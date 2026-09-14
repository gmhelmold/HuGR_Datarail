//! **Use case 2 — Cross-container, same host (the service-mesh corner)** over the lock-free `ShmemRing`.
//!
//! Two containers on one box sharing a memory mapping: a µs SPSC hop. The assault is **BACKPRESSURE
//! SATURATION** — a producer faster than the consumer keeps the ring *full*, so `send` repeatedly returns
//! `WouldBlock` (the back-pressure signal). The rail must NEVER drop a record under back-pressure: the producer
//! waits, the consumer drains, and across tens of thousands of wraparound cycles every record arrives exactly
//! once, in order.
//!
//! The ring is deliberately tiny (room for only a couple of frames) so a high record count drives the
//! monotonic cursors far past the ring length — exercising the wrap-split copy thousands of times.

use datarail_core::Substrate;
use datarail_stress::{conforming_record, record_key, Rig, Tally};
use datarail_substrate_shmem::ShmemRing;

/// BACKPRESSURE SATURATION — a fast producer floods a tiny ring; back-pressure is honored (no loss), wraparound
/// is correct across many cycles, and every record is committed exactly once in order.
#[test]
fn uc2_backpressure_saturation_no_loss_correct_wraparound() {
    const RECORDS: usize = 1_000; // one record per cofre ⇒ 1 000 frames forced through a ~2-frame ring.

    let mut rig = Rig::new();
    let mut tally = Tally::new();

    // Pre-seal every cofre so the hot loop only does ring I/O + offload (the assault is the ring, not sealing).
    let cofres: Vec<_> = (0..RECORDS)
        .map(|i| {
            let rec = conforming_record(i);
            let rk = record_key(i);
            rig.source.board(&[rec.as_slice()], &rk).expect("board")
        })
        .collect();

    // Size the ring to hold only ~2 frames so the producer is forced into back-pressure almost immediately and
    // the cursors wrap tens of thousands of times.
    let one_frame = 4 + datarail_cofre::encode(&cofres[0]).len();
    let mut shmem = ShmemRing::anon(one_frame * 2 + 16).expect("tiny anon ring");

    // Single-threaded, producer-biased interleave: try to send the next cofre; while the ring is FULL
    // (`WouldBlock`), drain one frame to the destination and retry — so the ring stays saturated but nothing is
    // dropped. This is exactly the back-pressure contract: refusal, never loss.
    let mut send_idx = 0usize;
    let mut backpressure_hits = 0u64;
    while send_idx < RECORDS {
        match shmem.send(&cofres[send_idx]) {
            Ok(()) => send_idx += 1,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                backpressure_hits += 1;
                // The consumer makes room: drain exactly one frame (must be present — the ring is full).
                let c = shmem
                    .recv()
                    .expect("recv under back-pressure")
                    .expect("a full ring has a frame");
                let disp = rig.dest.offload(&c).expect("offload");
                tally.observe(disp);
                shmem.ack(c.etiqueta.cofre_id).expect("ack");
            }
            Err(e) => panic!("unexpected ring send error (not back-pressure): {e}"),
        }
    }

    // Drain whatever remains in the ring after the last send.
    while let Some(c) = shmem.recv().expect("final drain recv") {
        let disp = rig.dest.offload(&c).expect("offload");
        tally.observe(disp);
        shmem.ack(c.etiqueta.cofre_id).expect("ack");
    }

    // 0-loss / 0-dup / 0-leak: every record committed exactly once, in order, despite relentless saturation.
    let committed = rig.dest.sink().committed();
    assert_eq!(
        committed.len(),
        RECORDS,
        "no record lost under back-pressure saturation (0-loss)"
    );
    assert!(
        rig.dest.dead_letters().is_empty(),
        "nothing dead-lettered: every frame decoded + verified"
    );
    for (i, rec) in committed.iter().enumerate() {
        assert_eq!(
            rec.as_slice(),
            conforming_record(i).as_slice(),
            "frame {i} out of order across a wrap"
        );
    }
    assert_eq!(
        tally.delivered, RECORDS as u64,
        "every record delivered exactly once"
    );
    assert_eq!(
        tally.duplicate, 0,
        "no duplicate: each frame offloaded once"
    );
    assert!(
        backpressure_hits > 0,
        "the assault must actually hit back-pressure (else the ring was too big to be a real saturation test)"
    );
    println!(
        "{} (records={RECORDS}, ring≈2 frames, back-pressure hits={backpressure_hits})",
        tally.report("uc2 shmem-backpressure")
    );
}
