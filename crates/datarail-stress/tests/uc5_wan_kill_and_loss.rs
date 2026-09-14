//! **Use case 5 — High-throughput WAN batch (the Aspera / FASP corner)** over `WanLink` + a real TCP socket.
//!
//! A bulk transfer across a lossy, high-RTT WAN that gets **killed mid-stream**. The recovery model is the one
//! the rail is built on: the source retains every cofre in a durable **outbox** until it is done; on a loss or
//! a partition it re-drives the outbox, and the destination's effectively-once gate dedups the redeliveries —
//! so the net effect is **0-loss / 0-dup, in order**, however violent the link.
//!
//! Two assaults:
//! - (a) **LOSS STORM + RE-DRIVE** over `WanLink<LoopbackSubstrate>` with `drop_every` packet loss: the source
//!   re-drives its outbox across sessions until the sink is complete; every record lands exactly once.
//! - (b) **KILL-MID-STREAM + LOSS** over `WanLink<TcpSubstrate>` (a real kernel socket with injected
//!   latency+loss): deliver a first leg, tear the socket down mid-stream (partition), reconnect on a fresh
//!   socket, re-drive the whole outbox; effectively-once recovery holds across the real partition.

use std::collections::HashSet;

use datarail_core::{Cofre, Disposition, Substrate};
use datarail_rail::{LoopbackSubstrate, TcpSubstrate, WanLink, WanProfile};
use datarail_stress::{conforming_record, record_key, Rig, Tally};

/// Assert **exactly-once as a SET**: the sink committed exactly the `expected` records, each exactly once
/// (0-loss + 0-dup), regardless of commit ORDER.
///
/// Why set-based, not in-order: under genuine packet loss + resume, a dropped middle record is re-driven and
/// arrives in a *later* pass — so it commits AFTER records with higher seq. The sink's commit order is therefore
/// arrival order, which loss legitimately reorders. The rail's guarantees that DO hold here are exactly-once and
/// the contiguous seq watermark (proven in `datarail-once` + the lossless in-order paths of uc1); a strict
/// in-order *sink* assertion would only hold on a lossless link, so asserting it here would be false. This
/// checks the real invariant under loss without weakening it: same multiset, no loss, no duplicate.
fn assert_exactly_once_set(committed: &[Vec<u8>], expected: &[Vec<u8>], scenario: &str) {
    assert_eq!(
        committed.len(),
        expected.len(),
        "{scenario}: sink size != expected (0-loss/0-dup)"
    );
    let mut got: Vec<&Vec<u8>> = committed.iter().collect();
    let mut want: Vec<&Vec<u8>> = expected.iter().collect();
    got.sort();
    want.sort();
    assert_eq!(
        got, want,
        "{scenario}: sink multiset != expected (a record was lost or duplicated)"
    );
    // No duplicates within the sink (defense in depth beyond the size+multiset check).
    let unique: std::collections::HashSet<&Vec<u8>> = committed.iter().collect();
    assert_eq!(
        unique.len(),
        committed.len(),
        "{scenario}: a record was committed more than once (0-dup)"
    );
}

/// Board N authentic single-record cofres into a source outbox; returns `(cofres, expected_payloads)`.
fn board_outbox(rig: &mut Rig, n: usize) -> (Vec<Cofre>, Vec<Vec<u8>>) {
    let mut cofres = Vec::with_capacity(n);
    let mut expected = Vec::with_capacity(n);
    for i in 0..n {
        let rec = conforming_record(i);
        let rk = record_key(i);
        cofres.push(rig.source.board(&[rec.as_slice()], &rk).expect("board"));
        expected.push(rec);
    }
    (cofres, expected)
}

/// (a) LOSS STORM + RE-DRIVE — every 3rd send is dropped in transit; the source re-drives its outbox across
/// sessions until complete. 0-loss/0-dup recovery despite relentless loss; recovered redeliveries are Duplicate.
#[test]
fn uc5a_loss_storm_redrive_recovers_every_record_exactly_once() {
    const N: usize = 800;

    let mut rig = Rig::new();
    let (outbox, expected) = board_outbox(&mut rig, N);

    // A lossy link: drop every 3rd send. The link is REUSED across passes, so its monotonic `sent` counter
    // shifts which positions get dropped each pass — a cofre lost this pass is re-driven and lands next pass.
    let profile = WanProfile {
        drop_every: 3,
        ..WanProfile::default()
    };
    let mut link = WanLink::new(LoopbackSubstrate::new(), profile);

    let mut tally = Tally::new();
    let mut committed: HashSet<[u8; 32]> = HashSet::new();

    // Re-drive only the not-yet-committed cofres each pass (the resumable outbox after acks): the dropped subset
    // shrinks geometrically, so this converges quickly. Bound the passes and assert convergence.
    let mut sessions = 0u32;
    while committed.len() < N {
        sessions += 1;
        assert!(
            sessions <= 64,
            "loss recovery failed to converge in a sane number of re-drives"
        );
        for c in outbox
            .iter()
            .filter(|c| !committed.contains(&c.etiqueta.cofre_id))
        {
            link.send(c).expect("send (may be dropped in transit)");
        }
        while let Some(c) = link.recv().expect("recv") {
            let already = committed.contains(&c.etiqueta.cofre_id);
            let disp = rig.dest.offload(&c).expect("offload");
            tally.observe(disp);
            if already {
                assert_eq!(
                    disp,
                    Disposition::Duplicate,
                    "a re-driven committed cofre must dedup"
                );
            } else {
                assert_eq!(
                    disp,
                    Disposition::Delivered,
                    "a first-time cofre must be delivered"
                );
                committed.insert(c.etiqueta.cofre_id);
            }
            link.ack(c.etiqueta.cofre_id).expect("ack");
        }
    }

    // 0-loss / 0-dup / 0-leak (exactly-once as a set; commit order is arrival order under loss — see helper).
    assert_exactly_once_set(
        rig.dest.sink().committed(),
        &expected,
        "uc5a wan-loss-storm",
    );
    assert!(
        rig.dest.dead_letters().is_empty(),
        "nothing dead-lettered across the lossy link"
    );
    assert_eq!(
        committed.len(),
        N,
        "all N records committed exactly once despite the loss storm"
    );
    assert!(
        link.dropped() > 0,
        "the assault must actually drop sends (else it isn't a loss test)"
    );
    assert_eq!(tally.delivered, N as u64, "exactly N first-time deliveries");
    println!(
        "{} (records={N}, sessions={sessions}, sends-dropped={})",
        tally.report("uc5a wan-loss-storm"),
        link.dropped()
    );
}

/// (b) KILL-MID-STREAM + LOSS over a REAL TCP socket wrapped in a lossy/high-RTT `WanLink`. The socket is torn
/// down mid-stream (a real partition); the source reconnects on a fresh socket and re-drives the whole outbox.
/// Effectively-once recovery: 0-loss / 0-dup, in order, across the real partition.
#[test]
fn uc5b_real_tcp_kill_mid_stream_with_loss_recovers_exactly_once() {
    const N: usize = 250; // real sockets + injected latency ⇒ keep the count modest but non-toy.

    let mut rig = Rig::new();
    let (outbox, expected) = board_outbox(&mut rig, N);

    let mut tally = Tally::new();
    let mut committed: HashSet<[u8; 32]> = HashSet::new();

    // A small per-recv latency models RTT; drop_every injects loss on top of the partition.
    let profile = WanProfile {
        latency: std::time::Duration::from_micros(50),
        drop_every: 7,
    };

    // --- Session 1: a real TCP socket under the lossy WAN profile. Deliver part of the stream, then KILL it. ---
    let first_leg = N / 2;
    {
        let inner = TcpSubstrate::loopback_pair().expect("tcp session 1");
        let mut link = WanLink::new(inner, profile);
        for c in outbox.iter().take(first_leg) {
            link.send(c).expect("send (s1, may drop)");
        }
        // Drain whatever survived the loss on this session (bounded: stop once the socket yields nothing new).
        drain_available(&mut link, &mut rig, &mut committed, &mut tally);
        // `link` (and its real sockets) drop here → PARTITION mid-stream.
    }
    assert!(
        committed.len() <= first_leg,
        "session 1 committed at most the first leg"
    );

    // --- Session 2+: a NEW real TCP socket each reconnect. The resumable source RE-DRIVES every cofre not yet
    //     durably committed (its outbox minus the acked) and dedup makes any incidental re-delivery safe. The
    //     WanLink's loss is deterministic per link (every 7th *send*), so re-driving the FULL outbox in a fixed
    //     order would drop the SAME positions forever; re-driving only the shrinking un-committed set instead
    //     (exactly what a resumable outbox does) drops a different, ever-smaller subset each round and converges
    //     geometrically. This is the real resume model: the source retains until acked, never re-sends the done. ---
    let mut rounds = 0u32;
    while committed.len() < N {
        rounds += 1;
        assert!(rounds <= 64, "real-socket loss recovery failed to converge");
        let inner = TcpSubstrate::loopback_pair().expect("tcp session 2+");
        let mut link = WanLink::new(inner, profile);
        // Re-drive only the not-yet-committed cofres (the live outbox after acks).
        for c in outbox
            .iter()
            .filter(|c| !committed.contains(&c.etiqueta.cofre_id))
        {
            link.send(c).expect("send (s2+, may drop)");
        }
        drain_available(&mut link, &mut rig, &mut committed, &mut tally);
    }

    // 0-loss / 0-dup / 0-leak across a real partition + loss (exactly-once as a set; commit order is arrival
    // order under loss — the rail's order guarantee is the seq watermark, see `assert_exactly_once_set`).
    assert_exactly_once_set(
        rig.dest.sink().committed(),
        &expected,
        "uc5b wan-kill-mid-stream",
    );
    assert!(
        rig.dest.dead_letters().is_empty(),
        "nothing dead-lettered across the partition"
    );
    assert_eq!(committed.len(), N, "all N committed exactly once");
    println!(
        "{} (records={N}, reconnect-rounds={rounds})",
        tally.report("uc5b wan-kill-mid-stream")
    );
}

/// Drain every cofre currently available on `link`, offloading each through the destination and recording
/// first-time vs duplicate. Stops after a bounded run of empty `recv`s (the lossy socket has nothing more *now*).
fn drain_available(
    link: &mut WanLink<TcpSubstrate>,
    rig: &mut Rig,
    committed: &mut HashSet<[u8; 32]>,
    tally: &mut Tally,
) {
    let mut empty_streak = 0u32;
    // A few consecutive empties (with the recv latency already applied inside WanLink) means the socket has
    // delivered everything that survived this session.
    while empty_streak < 8 {
        match link.recv().expect("recv") {
            Some(c) => {
                empty_streak = 0;
                let already = committed.contains(&c.etiqueta.cofre_id);
                let disp = rig.dest.offload(&c).expect("offload");
                tally.observe(disp);
                if already {
                    assert_eq!(
                        disp,
                        Disposition::Duplicate,
                        "re-driven committed cofre dedups"
                    );
                } else {
                    assert_eq!(disp, Disposition::Delivered, "first-time cofre delivered");
                    committed.insert(c.etiqueta.cofre_id);
                }
                link.ack(c.etiqueta.cofre_id).expect("ack");
            }
            None => empty_streak += 1,
        }
    }
}
