//! **Use case 4 — Decoupled / temporal, offline destination (store-and-forward)** over the object-store.
//!
//! Source and destination are NEVER online together; they rendezvous only through the durable bucket. The
//! assault is **DEST-OFFLINE-THEN-DRAIN under a backlog, then a full REPLAY**:
//!
//! 1. the source ships a large backlog while **no destination is reading** (the bucket fills up);
//! 2. later a fresh destination drains the **whole backlog**, delivering every record exactly once, in order;
//! 3. then the source **re-ships the same range** (an at-least-once source after a crash) and a fresh
//!    destination drains it again — every record comes back `Duplicate`, **0 re-commit** at the sink.
//!
//! This is the temporal-decoupling guarantee: durability across an offline window + effectively-once across a
//! replay, both end-to-end through a provider-blind store.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use datarail_core::{Cofre, Disposition, Substrate};
use datarail_stress::{conforming_record, record_key, Rig, Tally};
use datarail_substrate_objectstore::ObjectStoreSubstrate;

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn temp_bucket() -> PathBuf {
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("datarail-stress-snf-{}-{n}", std::process::id()))
}

/// DEST-OFFLINE-THEN-DRAIN + REPLAY: backlog drains exactly once in order; a full replay is all-Duplicate.
#[test]
fn uc4_offline_backlog_drains_once_then_replay_is_all_duplicate() {
    // The object-store `recv` re-scans the bucket each call (O(n) per GET ⇒ O(n²) to drain); 400 keeps the
    // assault a real backlog while bounding that quadratic scan to a couple of seconds.
    const N: usize = 400;

    let dir = temp_bucket();
    let mut rig = Rig::new();
    let mut tally = Tally::new();

    // Board N authentic cofres up front (kept so we can re-ship the identical bytes on replay).
    let cofres: Vec<Cofre> = (0..N)
        .map(|i| {
            let rec = conforming_record(i);
            let rk = record_key(i);
            rig.source.board(&[rec.as_slice()], &rk).expect("board")
        })
        .collect();

    // --- Phase 1: ship the whole backlog while the destination is OFFLINE (nothing reads). ---
    {
        let mut src_store = ObjectStoreSubstrate::open(&dir).expect("open source store");
        for c in &cofres {
            src_store.send(c).expect("PUT to backlog");
        }
    } // source store dropped — the backlog persists durably in the bucket with no reader.

    // --- Phase 2: a FRESH destination drains the whole backlog in seq order, exactly once. ---
    {
        let mut dst_store = ObjectStoreSubstrate::open(&dir).expect("reopen as dest");
        drain_backlog(
            &mut dst_store,
            &mut rig,
            &mut tally,
            N,
            Disposition::Delivered,
            "backlog delivery",
        );
        assert!(
            dst_store.recv().expect("drain").is_none(),
            "bucket fully drained + GC'd after the backlog"
        );
    }

    let after_drain = rig.dest.sink().len();
    assert_eq!(
        after_drain, N,
        "0-loss: the entire offline backlog was delivered"
    );
    let committed_snapshot: Vec<Vec<u8>> = rig.dest.sink().committed().to_vec();
    for (i, rec) in committed_snapshot.iter().enumerate() {
        assert_eq!(
            rec.as_slice(),
            conforming_record(i).as_slice(),
            "backlog record {i} out of order"
        );
    }

    // --- Phase 3: the source RE-SHIPS the identical range (at-least-once after a crash); a fresh dest drains
    //     it again. Every record is a benign Duplicate — the sink does not grow (0 re-commit). ---
    {
        let mut src_again = ObjectStoreSubstrate::open(&dir).expect("reopen source for replay");
        for c in &cofres {
            src_again.send(c).expect("re-PUT identical cofre");
        }
    }
    {
        let mut dst_again = ObjectStoreSubstrate::open(&dir).expect("reopen dest for replay");
        drain_backlog(
            &mut dst_again,
            &mut rig,
            &mut tally,
            N,
            Disposition::Duplicate,
            "replay dedup",
        );
    }

    // 0-dup at the sink: the full replay committed nothing new.
    assert_eq!(
        rig.dest.sink().len(),
        after_drain,
        "replay re-committed records (0-dup violation)"
    );
    assert!(
        rig.dest.dead_letters().is_empty(),
        "all cofres authentic — nothing dead-lettered (0-leak)"
    );
    assert_eq!(
        tally.delivered, N as u64,
        "exactly N first-time deliveries (the backlog)"
    );
    assert_eq!(
        tally.duplicate, N as u64,
        "exactly N duplicates (the replay)"
    );
    assert_eq!(tally.lost, 0);
    println!(
        "{} (backlog=N={N}, replay=N={N})",
        tally.report("uc4 store-and-forward")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn drain_backlog(
    store: &mut ObjectStoreSubstrate,
    rig: &mut Rig,
    tally: &mut Tally,
    count: usize,
    expected: Disposition,
    label: &str,
) {
    for _ in 0..count {
        let cofre = store
            .recv()
            .expect("GET object")
            .expect("backlogged object");
        let disposition = rig.dest.offload(&cofre).expect("offload");
        tally.observe(disposition);
        assert_eq!(disposition, expected, "{label}");
        store.ack(cofre.etiqueta.cofre_id).expect("ack + GC");
    }
}
