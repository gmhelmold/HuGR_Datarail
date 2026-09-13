//! Durability + O(1)-RAM proofs for the write-ahead-log substrate.
//!
//! These are the falsifiable gates behind `DURABLE-LOG.md`: AC-6 conformance, power-loss recovery (every
//! fsync'd cofre survives a "crash"), torn-tail truncation, and the RAM-flat invariant (RSS does not grow with
//! stored volume).

use std::sync::atomic::{AtomicU64, Ordering};

use datarail_core::Substrate;
use datarail_rail::testsupport::cofre_seq;
use datarail_substrate_wal::{DurableLog, WalConfig};

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("datarail-wal-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// AC-6: the WAL substrate satisfies the shared conformance harness (send→recv-in-order→ack→drained).
#[test]
fn ac6_wal_passes_substrate_conformance() {
    let dir = temp_dir("conf");
    datarail_rail::substrate_conformance(|| DurableLog::open(&dir).expect("open wal"));
}

/// Power-loss durability: write N cofres + fsync (`flush`), DROP the handle (simulating a crash with no
/// in-RAM state surviving), reopen a fresh `DurableLog` on the same dir, and drain — every cofre must come back,
/// in order, byte-identical. This is the "acks=all ⇒ on stable storage" guarantee.
#[test]
fn power_loss_recovery_zero_loss() {
    const N: u64 = 2000;
    let dir = temp_dir("recover");
    {
        let mut log = DurableLog::open(&dir).expect("open");
        for seq in 0..N {
            log.send(&cofre_seq(seq)).expect("send");
        }
        log.flush().expect("fsync"); // durability point
        drop(log); // "crash": the only state that survives is what's on disk
    }
    // A brand-new process-equivalent opens the same dir and drains it.
    let mut reopened = DurableLog::open(&dir).expect("reopen");
    let mut got = Vec::new();
    while let Some(c) = reopened.recv().expect("recv") {
        let id = c.etiqueta.cofre_id;
        got.push(c.etiqueta.seq);
        reopened.ack(id).expect("ack");
    }
    assert_eq!(
        got.len(),
        usize::try_from(N).unwrap(),
        "every fsync'd cofre must survive the crash"
    );
    assert_eq!(
        got,
        (0..N).collect::<Vec<_>>(),
        "recovered cofres must be in seq order, 0-loss/0-dup"
    );
}

/// A torn write (power-loss mid-append) must be truncated to the last intact frame; earlier cofres survive.
#[test]
fn torn_tail_is_truncated_prior_intact() {
    const N: u64 = 50;
    let dir = temp_dir("torn");
    {
        let mut log = DurableLog::open(&dir).expect("open");
        for seq in 0..N {
            log.send(&cofre_seq(seq)).expect("send");
        }
        log.flush().expect("fsync");
    }
    // Simulate a torn write: append a partial/garbage frame to the active segment file.
    let seg = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "seg"))
        .expect("a segment file");
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        // a plausible-looking length prefix followed by truncated bytes (no valid CRC) = a torn tail
        std::io::Write::write_all(&mut f, &1024u32.to_be_bytes()).unwrap();
        std::io::Write::write_all(&mut f, &[0xABu8; 300]).unwrap();
        f.sync_data().unwrap();
    }
    let mut reopened = DurableLog::open(&dir).expect("reopen after torn write");
    let mut got = Vec::new();
    while let Some(c) = reopened.recv().expect("recv") {
        let id = c.etiqueta.cofre_id;
        got.push(c.etiqueta.seq);
        reopened.ack(id).expect("ack");
    }
    assert_eq!(
        got,
        (0..N).collect::<Vec<_>>(),
        "torn tail dropped; all intact cofres recovered exactly"
    );
}

/// Round-trip with rotation: a small segment size forces many segments; send→recv→ack still 0-loss, and
/// fully-acked segments are GC'd (disk does not retain everything).
#[test]
fn rotation_and_gc_zero_loss() {
    const N: u64 = 1000;
    let dir = temp_dir("rotate");
    let cfg = WalConfig {
        flush_bytes: 4096,
        flush_micros: 1,
        segment_bytes: 16 * 1024,
    };
    let mut log = DurableLog::open_with(&dir, cfg).expect("open");
    for seq in 0..N {
        log.send(&cofre_seq(seq)).expect("send");
    }
    log.flush().expect("flush");
    let mut got = Vec::new();
    while let Some(c) = log.recv().expect("recv") {
        let id = c.etiqueta.cofre_id;
        got.push(c.etiqueta.seq);
        log.ack(id).expect("ack");
    }
    assert_eq!(
        got,
        (0..N).collect::<Vec<_>>(),
        "0-loss across many rotated segments"
    );
    // After draining + acking everything, GC should have deleted the early segments.
    let remaining = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "seg"))
        .count();
    assert!(
        remaining <= 2,
        "fully-acked segments must be GC'd (found {remaining} seg files)"
    );
}

/// THE masterpiece gate (de-rigged after the durability audit): RSS must not grow with TOTAL volume across the
/// FULL send→recv→ack cycle. The previous version only `send`-ed, so it never exercised the read/ack path (which
/// is where the `inflight`/`seg_inflight` maps live) — the audit correctly called that gate rigged. This drives
/// the whole pipeline with in-flight bounded to ~1 (ack right after recv) and asserts RSS stays flat as total
/// stored+drained volume grows. (The SEPARATE cost of a large UN-acked backlog is asserted in the next test —
/// honestly O(in-flight), not O(1).)
#[test]
fn ram_flat_across_full_send_recv_ack_cycle() {
    const N: u64 = 60_000;
    let Some(rss0) = rss_kb() else {
        eprintln!("skip: /proc not available (non-Linux)");
        return;
    };
    let dir = temp_dir("ramflat");
    // bigger flush threshold so the test isn't dominated by per-record fsyncs
    let cfg = WalConfig {
        flush_bytes: 1 << 20,
        flush_micros: 200_000,
        segment_bytes: 4 << 20,
    };
    let mut log = DurableLog::open_with(&dir, cfg).expect("open");
    let cofre = cofre_seq(0);
    let mut peak = rss0;
    for i in 0..N {
        log.send(&cofre).expect("send");
        // drain+ack so in-flight stays ~1 — proves total-volume independence, not just write-side.
        if let Some(c) = log.recv().expect("recv") {
            log.ack(c.etiqueta.cofre_id).expect("ack");
        }
        if i % 10_000 == 0 {
            if let Some(r) = rss_kb() {
                peak = peak.max(r);
            }
        }
    }
    let after = rss_kb().unwrap_or(rss0);
    eprintln!("full-cycle {N} cofres; RSS {rss0}→{after} KB (peak {peak})");
    assert!(
        after < rss0 + 32 * 1024 && peak < rss0 + 32 * 1024,
        "RSS must stay flat across the full cycle (after {after}, peak {peak}, baseline {rss0} — grew {} KB)",
        after.saturating_sub(rss0)
    );
}

/// HONEST counter-gate: a large UN-acked delivered backlog costs O(in-flight) RAM (the ack-bookkeeping maps),
/// NOT O(1) and NOT O(total). The audit caught us claiming "independent of in-flight backlog" — it is not. This
/// asserts the cost is BOUNDED by the in-flight window and RECLAIMED on ack (so it's not a leak).
#[test]
fn unacked_backlog_ram_is_bounded_by_inflight_and_reclaimed_on_ack() {
    // A clear un-acked backlog. Kept modest because each distinct cofre is a real seal (crypto); the O(in-flight)
    // -and-reclaimed invariant holds at any N — we assert the map count, not RSS, so a huge N buys nothing.
    const N: u64 = 500;
    let rss0 = rss_kb(); // informational only (Some on Linux, None elsewhere) — the invariant below is RSS-free
    let dir = temp_dir("backlog");
    let cfg = WalConfig {
        flush_bytes: 1 << 20,
        flush_micros: 200_000,
        segment_bytes: 4 << 20,
    };
    let mut log = DurableLog::open_with(&dir, cfg).expect("open");
    // DISTINCT cofres → the in-flight map (keyed by cofre_id) genuinely holds one entry per delivered-un-acked
    // cofre. (A single repeated cofre would collapse to one map entry and prove nothing about the backlog cost.)
    for seq in 0..N {
        log.send(&cofre_seq(seq)).expect("send");
    }
    log.flush().expect("flush");
    // Deliver everything WITHOUT acking → the in-flight map holds N entries.
    let mut ids = Vec::new();
    while let Some(c) = log.recv().expect("recv") {
        ids.push(c.etiqueta.cofre_id);
    }
    assert_eq!(ids.len(), usize::try_from(N).unwrap(), "all delivered");
    // The un-acked backlog holds O(in-flight) bookkeeping (one entry per delivered-un-acked cofre).
    assert_eq!(
        log.inflight_len(),
        usize::try_from(N).unwrap(),
        "the backlog is tracked, O(in-flight)"
    );
    let backlog_rss = rss_kb();
    // Now ack everything → the bookkeeping must be RECLAIMED.
    for id in &ids {
        log.ack(*id).expect("ack");
    }
    let after_ack = rss_kb();
    // Assert the REAL invariant at the data-structure level (allocator-independent, runs on every platform): the
    // in-flight map is released. RSS reclaim is NOT asserted — glibc malloc keeps freed pages in its arenas, so RSS
    // need not drop on Linux even though the bookkeeping is gone (that exact false failure showed up on CI). RSS is
    // an informational print: the honest claim is O(in-flight)-and-reclaimed, proven by the count returning to 0.
    assert_eq!(
        log.inflight_len(),
        0,
        "acking the full backlog reclaims ALL in-flight bookkeeping — not a leak"
    );
    if let (Some(r0), Some(rb), Some(ra)) = (rss0, backlog_rss, after_ack) {
        eprintln!("backlog RSS: rss0 {r0} → un-acked {rb} → acked {ra} KB (reclaim allocator-dependent; invariant proven by inflight_len)");
    }
}

/// REGRESSION GATE for the audit's total-loss bug: a lost cursor checkpoint combined with GC of early segments
/// must NOT lose the un-acked tail. recv must skip forward over the GC'd/missing segments and recover them.
#[test]
fn lost_cursor_plus_gc_still_recovers_unacked_tail() {
    const N: u64 = 1200;
    let dir = temp_dir("lostcursor");
    let cfg = WalConfig {
        flush_bytes: 2048,
        flush_micros: 1,
        segment_bytes: 8 * 1024,
    };
    {
        let mut log = DurableLog::open_with(&dir, cfg).expect("open");
        for seq in 0..N {
            log.send(&cofre_seq(seq)).expect("send");
        }
        log.flush().expect("flush");
        // ack the first half → GC deletes the early segments
        for _ in 0..(N / 2) {
            let c = log.recv().expect("recv").expect("some");
            log.ack(c.etiqueta.cofre_id).expect("ack");
        }
    }
    // Simulate a LOST cursor checkpoint (crash before the cursor rename was durable) while early segments are GC'd.
    let _ = std::fs::remove_file(dir.join("cursor"));
    let mut reopened = DurableLog::open_with(&dir, cfg).expect("reopen");
    let mut got = Vec::new();
    while let Some(c) = reopened.recv().expect("recv") {
        let id = c.etiqueta.cofre_id;
        got.push(c.etiqueta.seq);
        reopened.ack(id).expect("ack");
    }
    // The un-acked tail (the second half) MUST be recovered — not 0 (the bug). Duplicates of the first half are
    // fine (at-least-once → deduped downstream); the requirement is no LOSS of the un-acked tail.
    for seq in (N / 2)..N {
        assert!(
            got.contains(&seq),
            "un-acked cofre seq {seq} was LOST after lost-cursor+GC (the total-loss bug)"
        );
    }
}

/// REGRESSION GATE: a corrupt frame in a SEALED (non-active) segment must ERROR, not silently skip it plus the
/// rest of the segment (the audit's "lost 13 not 1" finding).
#[test]
fn corrupt_interior_frame_in_sealed_segment_errors() {
    const N: u64 = 400;
    let dir = temp_dir("corrupt");
    let cfg = WalConfig {
        flush_bytes: 2048,
        flush_micros: 1,
        segment_bytes: 8 * 1024,
    };
    {
        let mut log = DurableLog::open_with(&dir, cfg).expect("open");
        for seq in 0..N {
            log.send(&cofre_seq(seq)).expect("send");
        }
        log.flush().expect("flush");
    }
    // Corrupt a byte well inside the FIRST (sealed, non-active) segment.
    let mut segs: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "seg"))
        .collect();
    segs.sort();
    let first = &segs[0];
    let mut data = std::fs::read(first).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF; // flip a byte inside a committed frame
    std::fs::write(first, &data).unwrap();

    let mut reopened = DurableLog::open_with(&dir, cfg).expect("reopen");
    // Draining must hit the corruption and ERROR (not silently skip the rest of the sealed segment).
    let mut errored = false;
    loop {
        match reopened.recv() {
            Ok(Some(c)) => {
                let _ = reopened.ack(c.etiqueta.cofre_id);
            }
            Ok(None) => break,
            Err(_) => {
                errored = true;
                break;
            }
        }
    }
    assert!(
        errored,
        "corruption inside a sealed segment must surface as an error, not be silently swallowed"
    );
}

/// Audit CRITICAL regression: `recv` advances the read cursor on DELIVERY, so a crash after delivering-but-not-
/// acking some cofres — and acking/checkpointing a LATER one — must RE-DELIVER the un-acked ones on restart, never
/// skip them. Resuming from the persisted ACK FLOOR (not the advanced read cursor) is what guarantees at-least-once.
#[test]
fn delivered_but_unacked_records_are_redelivered_after_a_crash() {
    const N: u64 = 10;
    let dir = temp_dir("unacked-redeliver");
    let acked_seq;
    {
        let mut log = DurableLog::open(&dir).expect("open");
        for seq in 0..N {
            log.send(&cofre_seq(seq)).expect("send");
        }
        log.flush().expect("flush");
        // Deliver 6, then ack ONLY the 6th (a partial / out-of-order ack) → the first 5 are delivered-but-un-acked.
        let mut delivered = Vec::new();
        for _ in 0..6 {
            delivered.push(log.recv().expect("recv").expect("a cofre"));
        }
        let last = delivered.last().expect("6 delivered");
        acked_seq = last.etiqueta.seq;
        log.ack(last.etiqueta.cofre_id).expect("ack the 6th only");
        // DROP here = crash. The 5 delivered-but-un-acked cofres MUST remain re-deliverable.
    }
    let mut reopened = DurableLog::open(&dir).expect("reopen");
    let mut got = std::collections::BTreeSet::new();
    while let Some(c) = reopened.recv().expect("recv") {
        got.insert(c.etiqueta.seq);
        reopened.ack(c.etiqueta.cofre_id).expect("ack");
    }
    // At-least-once: every record NOT durably acked before the crash is re-delivered (none lost). The single acked
    // record may or may not reappear (a harmless duplicate either way) — only loss of an UN-acked record is a bug.
    for seq in 0..N {
        if seq == acked_seq {
            continue;
        }
        assert!(
            got.contains(&seq),
            "un-acked record {seq} was LOST across the crash (recovered {got:?})"
        );
    }
}

fn rss_kb() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = s.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4) // 4 KiB pages → KB
}
