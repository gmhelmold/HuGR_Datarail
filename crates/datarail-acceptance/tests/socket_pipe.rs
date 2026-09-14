//! v1.1 — the vertical slice over a **real cross-process transport** (Unix domain socket). Proves the whole
//! pipe — board → seal → kernel socket → verify → offload → Delivered — works *unchanged* when the in-memory
//! substrate is swapped for a real one (the substrate is polymorphic; the terminals don't know the difference).
//! Unix-only.

#![cfg(unix)]

use datarail_core::{AeadAlg, Disposition, Substrate};
use datarail_crypto::{verifying_key, x25519_public};
use datarail_rail::SocketSubstrate;
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

#[test]
fn board_over_unix_socket_then_offload_delivers() {
    let source_vk = verifying_key(&SOURCE_SEED);
    let mut source = SourceTerminal::new(config(), contract(), SOURCE_SEED);
    let mut dest = DestTerminal::new(config(), contract(), source_vk, DEST_SEED, DEST_X_SECRET);
    let mut rail = SocketSubstrate::pair().expect("unix socket pair");

    // Board a conforming batch and push the sealed cofre across the kernel socket.
    let recs: [&[u8]; 2] = [b"evt:over-the-wire", b"evt:cross-process"];
    let cofre = source.board(&recs, b"sock-1").expect("board");
    rail.send(&cofre).expect("send over uds");

    // Pull it back off the wire (buffered non-blocking recv returns Some once the full frame has arrived).
    let received = loop {
        if let Some(c) = rail.recv().expect("recv") {
            break c;
        }
    };
    assert_eq!(
        received, cofre,
        "the cofre survived the kernel transport byte-for-byte"
    );

    // Offload behaves exactly as over the in-memory rail: verify → open → admit → commit, exactly once.
    assert_eq!(
        dest.offload(&received).expect("offload"),
        Disposition::Delivered
    );
    rail.ack(received.etiqueta.cofre_id).expect("ack");
    assert_eq!(
        dest.sink().committed().to_vec(),
        vec![b"evt:over-the-wire".to_vec(), b"evt:cross-process".to_vec()],
        "both records committed once, intact, across a real cross-process transport"
    );
    assert!(dest.dead_letters().is_empty());
}
