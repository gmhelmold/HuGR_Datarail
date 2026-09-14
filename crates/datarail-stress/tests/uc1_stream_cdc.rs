//! **Use case 1 — Stream / CDC (the Kafka corner)** over the in-process loopback and a real TCP socket.
//!
//! The change-data-capture / event-stream shape: a firehose of small records boarded into batched cofres,
//! shipped over the rail, offloaded exactly once **in order**. Three violent assaults, each asserting the rail
//! HOLDS at 0-loss / 0-dup / 0-leak:
//!
//! - (a) **VOLUME STORM** — 100 000+ tiny records batched into cofres over loopback; every conforming record is
//!   committed exactly once, in boarding order.
//! - (b) **TINY-RECORD OVERHEAD STORM** — one record per cofre at high count over a *real TCP loopback socket*
//!   (the per-cofre-overhead worst case); we prove it stays correct, not that it is fast.
//! - (c) **DUPLICATE FLOOD** — re-offload the SAME cofres 10× through one destination; every replay yields
//!   `Duplicate` and the sink grows by exactly 0 on each pass (the once-gate's reject-below + dedup).

use datarail_core::{Cofre, Disposition, Substrate};
use datarail_rail::{LoopbackSubstrate, TcpSubstrate};
use datarail_stress::{conforming_record, record_key, Rig, Tally};

/// (a) VOLUME STORM — 100k+ tiny records, batched, over the loopback. Exactly-once + in-order at the sink.
#[test]
fn uc1a_volume_storm_100k_records_committed_exactly_once_in_order() {
    const RECORDS: usize = 120_000;
    const BATCH: usize = 400; // 300 cofres of 400 records each — the batched-CDC shape (the volume is the records).

    let mut rig = Rig::new();
    let mut link = LoopbackSubstrate::new();
    let mut tally = Tally::new();

    // Board the firehose into batched cofres (distinct record_key per cofre ⇒ distinct idempotency key + seq).
    let mut boarded_cofres = 0u64;
    let mut next = 0usize;
    while next < RECORDS {
        let end = (next + BATCH).min(RECORDS);
        let batch: Vec<Vec<u8>> = (next..end).map(conforming_record).collect();
        let refs: Vec<&[u8]> = batch.iter().map(Vec::as_slice).collect();
        let rk = record_key(next); // the first index keys the whole batch (distinct per cofre).
        let cofre = rig.source.board(&refs, &rk).expect("board batch");
        link.send(&cofre).expect("send");
        boarded_cofres += 1;
        next = end;
    }

    // Ship + offload every cofre once.
    while let Some(c) = link.recv().expect("recv") {
        let disp = rig.dest.offload(&c).expect("offload");
        tally.observe(disp);
        link.ack(c.etiqueta.cofre_id).expect("ack");
    }

    // 0-loss / 0-dup / 0-leak: every record committed exactly once, in boarding order.
    let committed = rig.dest.sink().committed();
    assert_eq!(
        committed.len(),
        RECORDS,
        "every conforming record committed exactly once (0-loss/0-dup)"
    );
    assert!(
        rig.dest.dead_letters().is_empty(),
        "nothing dead-lettered (0-leak): all records were authentic"
    );
    for (i, rec) in committed.iter().enumerate() {
        assert_eq!(
            rec.as_slice(),
            conforming_record(i).as_slice(),
            "record {i} out of order"
        );
    }
    assert_eq!(
        tally.delivered, boarded_cofres,
        "every cofre delivered exactly once"
    );
    assert_eq!(tally.duplicate, 0, "no duplicate under a single pass");
    assert_eq!(tally.dead_lettered, 0, "no dead-letter under a single pass");
    println!(
        "{} (records={RECORDS}, cofres={boarded_cofres})",
        tally.report("uc1a volume-storm")
    );
}

/// (b) TINY-RECORD OVERHEAD STORM — one record per cofre at high count over a **real TCP loopback socket**.
/// This is the per-cofre-overhead worst case; we prove correctness (exactly-once, in order), not speed.
#[test]
fn uc1b_tiny_record_overhead_storm_over_real_tcp_is_correct() {
    const RECORDS: usize = 700; // 1 record == 1 cofre == 1 framed wire message; the overhead worst case.

    let mut rig = Rig::new();
    let mut link = TcpSubstrate::loopback_pair().expect("tcp loopback pair");
    let mut tally = Tally::new();

    // INTERLEAVE send + drain so the single-process kernel socket buffer never deadlocks (a flood that is sent
    // up-front with no reader would block `write_all` once the OS send buffer fills). Send one cofre, then drain
    // everything currently readable; repeat. This still exercises 1-record-per-frame over a real socket.
    let mut sent = 0u64;
    let mut got = 0u64;
    for i in 0..RECORDS {
        let rec = conforming_record(i);
        let rk = record_key(i);
        let cofre = rig
            .source
            .board(&[rec.as_slice()], &rk)
            .expect("board 1-record cofre");
        link.send(&cofre).expect("send over tcp");
        sent += 1;
        while let Some(c) = link.recv().expect("recv over tcp") {
            let disp = rig.dest.offload(&c).expect("offload");
            tally.observe(disp);
            link.ack(c.etiqueta.cofre_id).expect("ack");
            got += 1;
        }
    }
    // Final drain: anything still in flight after the last send.
    while got < sent {
        if let Some(c) = link.recv().expect("recv over tcp (final)") {
            let disp = rig.dest.offload(&c).expect("offload");
            tally.observe(disp);
            link.ack(c.etiqueta.cofre_id).expect("ack");
            got += 1;
        }
    }

    let committed = rig.dest.sink().committed();
    assert_eq!(
        committed.len(),
        RECORDS,
        "every 1-record cofre committed exactly once over real TCP"
    );
    assert!(
        rig.dest.dead_letters().is_empty(),
        "nothing dead-lettered: every cofre survived TCP byte-for-byte"
    );
    for (i, rec) in committed.iter().enumerate() {
        assert_eq!(
            rec.as_slice(),
            conforming_record(i).as_slice(),
            "record {i} out of order over TCP"
        );
    }
    assert_eq!(tally.delivered, sent, "every cofre delivered exactly once");
    assert_eq!(tally.duplicate, 0);
    assert_eq!(tally.dead_lettered, 0);
    println!(
        "{} (records=cofres={RECORDS}, real-tcp)",
        tally.report("uc1b tiny-record-overhead")
    );
}

/// (c) DUPLICATE FLOOD — re-offload the SAME cofres 10× through one destination. Every replay is a `Duplicate`
/// and the sink grows by exactly 0 on each pass: the effectively-once gate (reject-below + dedup) holds.
#[test]
fn uc1c_duplicate_flood_replays_are_all_duplicate_sink_grows_by_zero() {
    const N: usize = 200; // distinct cofres
    const REPLAYS: usize = 10; // times to re-offload the WHOLE set after the first pass (2 000 replayed offloads)

    let mut rig = Rig::new();
    let mut tally = Tally::new();

    // Build N distinct, authentic cofres (kept so we can replay the EXACT same bytes).
    let cofres: Vec<Cofre> = (0..N)
        .map(|i| {
            let rec = conforming_record(i);
            let rk = record_key(i);
            rig.source.board(&[rec.as_slice()], &rk).expect("board")
        })
        .collect();

    // First pass: all Delivered, sink == N, in order.
    for c in &cofres {
        let disp = rig.dest.offload(c).expect("offload (first pass)");
        tally.observe(disp);
        assert_eq!(
            disp,
            Disposition::Delivered,
            "first delivery of a distinct cofre"
        );
    }
    let baseline = rig.dest.sink().len();
    assert_eq!(
        baseline, N,
        "first pass committed every distinct record exactly once"
    );

    // DUPLICATE FLOOD: replay the SAME cofres REPLAYS times. Each must be Duplicate; the sink must not grow.
    for pass in 0..REPLAYS {
        for c in &cofres {
            let disp = rig.dest.offload(c).expect("offload (replay)");
            tally.observe(disp);
            assert_eq!(
                disp,
                Disposition::Duplicate,
                "replayed cofre must dedup to Duplicate"
            );
        }
        assert_eq!(
            rig.dest.sink().len(),
            baseline,
            "sink grew on replay pass {pass} — the once-gate let a duplicate through (0-dup violation)"
        );
    }

    assert!(
        rig.dest.dead_letters().is_empty(),
        "duplicates are dropped, never dead-lettered"
    );
    assert_eq!(tally.delivered, N as u64, "exactly N first-time deliveries");
    assert_eq!(
        tally.duplicate,
        (N * REPLAYS) as u64,
        "exactly N*REPLAYS duplicates across the flood"
    );
    assert_eq!(tally.lost, 0);
    println!(
        "{} (distinct={N}, replays={REPLAYS})",
        tally.report("uc1c duplicate-flood")
    );
}
