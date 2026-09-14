//! **Use case 3 — Cross-org / cross-cloud regulated transfer (the MFT corner)** over the **untrusted**
//! `ObjectStoreSubstrate` (a filesystem-backed, provider-blind holding pen).
//!
//! The store is assumed HOSTILE: a compromised bucket operator can inject anything. The assault writes, *into
//! the bucket directory*, alongside legit sealed cofres:
//!
//! - (a) **forged / garbage files** — random bytes that are not a cofre at all;
//! - (b) **tampered cofres** — a legit cofre with one byte flipped (payload corruption);
//! - (c) **oversized files** — larger than [`MAX_COFRE_WIRE_LEN`], a memory-exhaustion attempt.
//!
//! Two defensive layers must hold so that **0 forged bytes reach the sink, 0 panics, 0 leak**:
//! 1. the **substrate's parse-before-verify** (`decode` + the AUDIT-03 size guard) rejects garbage / oversized /
//!    structurally-broken objects — they never even become a `Cofre`;
//! 2. the **terminal's verify** dead-letters (reason-coded) any cofre that decodes but fails the seal (a
//!    payload-tampered cofre ⇒ `CofreIdMismatch`).
//!
//! Only the authentic, untampered cofres are delivered — exactly once, in seq order.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use datarail_core::{Substrate, MAX_COFRE_WIRE_LEN};
use datarail_stress::{conforming_record, record_key, tampered_wire_bytes, Rig, Tally};
use datarail_substrate_objectstore::ObjectStoreSubstrate;

static UNIQ: AtomicU64 = AtomicU64::new(0);

/// A unique per-test temp bucket (no tempfile dep — matches the substrate crate's own test convention).
fn temp_bucket() -> PathBuf {
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "datarail-stress-objstore-{}-{n}",
        std::process::id()
    ))
}

/// Recursively collect every `*.cofre` object under `dir`, sorted (so legit objects come back in seq order).
fn sorted_cofre_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(dir, &mut out);
    out.sort();
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("cofre") {
            out.push(path);
        }
    }
}

/// (a)+(b)+(c) UNTRUSTED-STORE ASSAULT: legit cofres mixed with forged/garbage, tampered, and oversized files.
/// Only the legit cofres deliver (exactly once, in order); every bad object is rejected — 0 forged delivered.
#[test]
fn uc3_untrusted_store_delivers_only_legit_rejects_every_injection() {
    const LEGIT: usize = 300;

    let dir = temp_bucket();
    let mut rig = Rig::new();
    let mut tally = Tally::new();

    // --- PUT the legit cofres through the real substrate (correct seq-keyed layout), remembering their ids. ---
    let mut legit_payloads = Vec::with_capacity(LEGIT);
    {
        let mut store = ObjectStoreSubstrate::open(&dir).expect("open bucket (source)");
        for i in 0..LEGIT {
            let rec = conforming_record(i);
            let rk = record_key(i);
            let cofre = rig
                .source
                .board(&[rec.as_slice()], &rk)
                .expect("board legit");
            legit_payloads.push(rec);
            store.send(&cofre).expect("PUT legit");
        }
    } // source store dropped — only the bucket persists.

    // --- INJECT the assault objects straight into the bucket directory (a hostile operator). ---
    let assault_dir = dir
        .join("ffffffffffffffffffffffffffffffff")
        .join("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    std::fs::create_dir_all(&assault_dir).expect("mk assault dir");

    // (a) forged / garbage: bytes that are not a cofre (bad magic) → `decode` fails at the substrate layer.
    let mut garbage_files = 0usize;
    for j in 0..50u8 {
        let path = assault_dir.join(format!("{j:020}.cofre"));
        // 256 bytes that are NOT a cofre (the first 4 bytes are not the `DRLC` magic) — pure u8 arithmetic.
        let junk: Vec<u8> = (0..=u8::MAX).map(|b| b ^ j).collect();
        std::fs::write(&path, &junk).expect("write garbage");
        garbage_files += 1;
    }

    // (b) tampered cofres: real cofres with one byte flipped → some fail `decode` (structure), the rest decode
    // but fail `verify` (CofreIdMismatch) → reason-coded dead-letter at the terminal layer.
    let mut tampered_files = 0usize;
    for j in 0..50usize {
        let rec = conforming_record(1_000_000 + j); // distinct from legit so a leak would be detectable.
        let rk = record_key(1_000_000 + j);
        let cofre = rig
            .source
            .board(&[rec.as_slice()], &rk)
            .expect("board to-tamper");
        // Flip a byte in the carga region (offset chosen well past the fixed header) so it decodes but fails
        // verify — the worst case for the assault (a structurally-perfect, content-tampered cofre).
        let bytes = tampered_wire_bytes(&cofre, 200);
        let path = assault_dir.join(format!("{:020}.cofre", 100 + j));
        std::fs::write(&path, &bytes).expect("write tampered");
        tampered_files += 1;
    }

    // (c) oversized: a file just over MAX_COFRE_WIRE_LEN → the substrate's AUDIT-03 size guard refuses it.
    let oversized_path = assault_dir.join("00000000000000000999.cofre");
    write_oversized(&oversized_path);
    let oversized_files = 1usize;

    let substrate_rejected = deliver_untrusted_objects(&dir, &mut rig, &mut tally);

    // --- 0-loss / 0-dup / 0-leak assertions. ---
    let committed = rig.dest.sink().committed();
    assert_eq!(
        committed.len(),
        LEGIT,
        "exactly the legit records delivered (0 forged delivered, 0-loss)"
    );
    assert_eq!(
        committed,
        legit_payloads.as_slice(),
        "legit records delivered exactly once, in seq order"
    );

    let dead = rig.dest.dead_letters();
    assert!(
        !dead.is_empty(),
        "payload-tampered cofres must be reason-coded onto the dead-letter siding"
    );
    assert_tampered_rejected(committed, dead, tampered_files);

    assert_eq!(
        tally.delivered, LEGIT as u64,
        "delivered count == legit count"
    );
    assert_eq!(
        tally.dead_lettered,
        tally_dead(&rig),
        "every dead-letter is accounted for"
    );
    let bad_total = (garbage_files + tampered_files + oversized_files) as u64;
    assert_eq!(
        substrate_rejected + tally.dead_lettered,
        bad_total,
        "every injected bad object was rejected — at the substrate (decode/size) or the terminal (dead-letter)"
    );

    println!(
        "{} (legit={LEGIT}, garbage={garbage_files}, tampered={tampered_files}, oversized={oversized_files}, \
         substrate-rejected={substrate_rejected})",
        tally.report("uc3 untrusted-store")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn assert_tampered_rejected(
    committed: &[Vec<u8>],
    dead: &datarail_terminal::DeadLetterSiding,
    tampered_files: usize,
) {
    for entry in dead.entries() {
        assert_ne!(entry.cofre.etiqueta.cofre_id, [0u8; 32]);
        assert!(matches!(
            entry.reason,
            datarail_terminal::DeadLetterReason::SealFailed(_)
        ));
    }
    for j in 0..tampered_files {
        let leaked = conforming_record(1_000_000 + j);
        assert!(!committed.contains(&leaked), "tampered payload leaked");
    }
}

fn deliver_untrusted_objects(dir: &Path, rig: &mut Rig, tally: &mut Tally) -> u64 {
    let mut rejected = 0u64;
    for path in sorted_cofre_files(dir) {
        let meta = std::fs::metadata(&path).expect("stat object");
        if meta.len() > MAX_COFRE_WIRE_LEN as u64 {
            rejected += 1;
            continue;
        }
        match datarail_cofre::decode(&std::fs::read(&path).expect("read object")) {
            Err(_) => rejected += 1,
            Ok(cofre) => tally.observe(rig.dest.offload(&cofre).expect("offload")),
        }
    }
    rejected
}

/// The substrate's OWN defensive bounds (AUDIT-03 F3): drive `ObjectStoreSubstrate::recv` over a bucket holding
/// one oversized object and one garbage object and assert it returns `InvalidData` rather than panicking or
/// exhausting memory. (Complements the end-to-end test above, which applies the same guard in the driver.)
#[test]
fn uc3_substrate_recv_rejects_oversized_and_garbage_with_invaliddata() {
    let dir = temp_bucket();
    let sub_dir = dir
        .join("00000000000000000000000000000000")
        .join("00000000000000000000000000000000");
    std::fs::create_dir_all(&sub_dir).expect("mk dir");

    // One oversized object: recv must error InvalidData (size guard), not read 64+ MiB into memory.
    write_oversized(&sub_dir.join("00000000000000000001.cofre"));
    let mut store = ObjectStoreSubstrate::open(&dir).expect("open");
    let err = store
        .recv()
        .expect_err("oversized object must be refused by recv");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "oversized ⇒ InvalidData (no unbounded read)"
    );

    // Replace it with garbage: recv must error InvalidData (decode failure), never yield a bogus cofre.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&sub_dir).expect("mk dir 2");
    std::fs::write(
        sub_dir.join("00000000000000000001.cofre"),
        b"not-a-cofre-at-all",
    )
    .expect("write garbage");
    let mut store2 = ObjectStoreSubstrate::open(&dir).expect("open 2");
    let err2 = store2
        .recv()
        .expect_err("garbage object must be refused by recv");
    assert_eq!(
        err2.kind(),
        std::io::ErrorKind::InvalidData,
        "garbage ⇒ InvalidData (parse-before-verify)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The destination's current dead-letter count (read back for the accounting assertion).
fn tally_dead(rig: &Rig) -> u64 {
    rig.dest.dead_letters().len() as u64
}

/// Write a file one byte larger than [`MAX_COFRE_WIRE_LEN`] (the oversized assault). Uses a sparse-friendly
/// single trailing-byte write so the test does not actually materialize 64 MiB of zeros on disk where the OS
/// supports holes; the substrate only ever reads its *metadata length*, never the body, before refusing it.
fn write_oversized(path: &Path) {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::File::create(path).expect("create oversized");
    // Seek past the cap and write one byte: the file's reported length exceeds MAX_COFRE_WIRE_LEN.
    f.seek(SeekFrom::Start(MAX_COFRE_WIRE_LEN as u64 + 1))
        .expect("seek");
    f.write_all(&[0u8]).expect("write tail byte");
    f.flush().expect("flush");
}
