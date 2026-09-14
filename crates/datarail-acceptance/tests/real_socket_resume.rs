//! AC-8 (real-socket upgrade) — resume across a **real TCP partition**. The in-memory `ResumableSubstrate`
//! proves the resume *cursor* logic (`ac8_resume.rs`); this proves the **effectively-once** guarantee holds
//! when the transport is a real kernel socket that genuinely **dies mid-stream** and is replaced by a new
//! connection over which the source **re-drives** its outbox. Redeliveries are deduped by the gate inside the
//! terminal, so the net effect at the sink is **0-loss / 0-duplicate**, in order.
//!
//! The source retains every cofre until it is durably done (the outbox); on partition it cannot be certain
//! what the destination received, so on reconnect it conservatively re-drives the whole outbox — and dedup
//! makes that safe (already-committed cofres come back as `Duplicate`, never re-committed). That is the real
//! AC-8 claim over a real transport.

use std::collections::HashSet;

use datarail_core::{AeadAlg, Cofre, Disposition, Substrate};
use datarail_crypto::{verifying_key, x25519_public};
use datarail_rail::TcpSubstrate;
use datarail_terminal::{ContentContract, DestTerminal, SourceTerminal, TerminalConfig};

const SOURCE_SEED: [u8; 32] = [11; 32];
const DEST_SEED: [u8; 32] = [22; 32];
const DEST_X_SECRET: [u8; 32] = [5; 32];
const ROUTE: [u8; 16] = [1; 16];
const STREAM: [u8; 16] = [2; 16];
const TENANT: [u8; 32] = [6; 32];

fn config() -> TerminalConfig {
    TerminalConfig {
        route_id: ROUTE,
        stream_id: STREAM,
        aead_alg: AeadAlg::Gcmsiv256,
        dest_x25519_pk: x25519_public(&DEST_X_SECRET),
        tenant_secret: TENANT,
    }
}

fn contract() -> ContentContract {
    ContentContract::new(1024, b"evt:".to_vec())
}

/// Receive + offload exactly `count` cofres over `link`, recording each committed `cofre_id`. Already-committed
/// cofres (re-driven after the partition) must dedup to `Duplicate`; fresh ones must be `Delivered`.
fn drain_offload(
    link: &mut TcpSubstrate,
    dest: &mut DestTerminal,
    committed: &mut HashSet<[u8; 32]>,
    count: usize,
) {
    let mut got = 0;
    while got < count {
        if let Some(c) = link.recv().expect("recv") {
            let already = committed.contains(&c.etiqueta.cofre_id);
            let disp = dest.offload(&c).expect("offload");
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
                    "a fresh cofre must be delivered"
                );
                committed.insert(c.etiqueta.cofre_id);
            }
            link.ack(c.etiqueta.cofre_id).expect("ack");
            got += 1;
        }
    }
}

#[test]
fn ac8_real_tcp_partition_then_resume_delivers_each_record_exactly_once() {
    const N: usize = 10;
    const FIRST_LEG: usize = N / 2;

    let source_vk = verifying_key(&SOURCE_SEED);
    let mut source = SourceTerminal::new(config(), contract(), SOURCE_SEED);
    let mut dest = DestTerminal::new(config(), contract(), source_vk, DEST_SEED, DEST_X_SECRET);

    // Board N distinct cofres into the source outbox (retained until durably done — resume re-drives from here).
    let mut outbox: Vec<Cofre> = Vec::new();
    let mut expected: Vec<Vec<u8>> = Vec::new();
    for i in 0..N {
        let payload = format!("evt:rec-{i:02}");
        let rk = format!("key-{i}");
        let cofre = source
            .board(&[payload.as_bytes()], rk.as_bytes())
            .expect("board");
        outbox.push(cofre);
        expected.push(payload.into_bytes());
    }

    let mut committed: HashSet<[u8; 32]> = HashSet::new();

    // --- Session 1 over a REAL TCP socket: deliver + commit the first leg, then the link DIES mid-stream. ---
    {
        let mut link = TcpSubstrate::loopback_pair().expect("tcp session 1");
        for cofre in outbox.iter().take(FIRST_LEG) {
            link.send(cofre).expect("send (s1)");
        }
        drain_offload(&mut link, &mut dest, &mut committed, FIRST_LEG);
        // `link` drops here → the real kernel sockets are torn down → PARTITION.
    }
    assert_eq!(
        committed.len(),
        FIRST_LEG,
        "first leg committed before the partition"
    );

    // --- Session 2 over a NEW real TCP socket: the source RE-DRIVES the whole outbox; the already-committed
    //     cofres dedup to Duplicate, the rest are Delivered. ---
    {
        let mut link = TcpSubstrate::loopback_pair().expect("tcp session 2");
        for cofre in &outbox {
            link.send(cofre).expect("send (s2)");
        }
        drain_offload(&mut link, &mut dest, &mut committed, N);
    }

    // 0-loss + 0-duplicate: every record committed exactly once, in order, across a real socket partition.
    assert_eq!(
        dest.sink().committed(),
        expected.as_slice(),
        "each record delivered exactly once, in order, across a real TCP partition + resume"
    );
    assert!(
        dest.dead_letters().is_empty(),
        "nothing dead-lettered across the partition"
    );
    assert_eq!(committed.len(), N, "all N records committed exactly once");
}
