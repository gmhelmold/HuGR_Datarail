//! P5 (roadmap) — the vertical slice over **real substrate hops**, not in-memory. The roadmap's P5 demanded the
//! first slice traverse real hops (it named shmem-hop + QUIC-hop); the two SPEC-named real substrates we have
//! are **QUIC** (cross-host) and the **object-store** (cross-cloud, temporally decoupled). Each test drives the
//! WHOLE pipe — board → seal → real hop → verify → open → admit → commit → **Delivered** — and shows it works
//! *unchanged* when the in-memory substrate is swapped for a real one (the substrate is polymorphic; the
//! terminals do not know the difference). (shmem-hop is owner-blocked, `BUILD_LOG` §6 #24.)

use datarail_core::{AeadAlg, Disposition, Substrate};
use datarail_crypto::{verifying_key, x25519_public};
use datarail_substrate_objectstore::ObjectStoreSubstrate;
use datarail_substrate_quic::QuicSubstrate;
use datarail_substrate_shmem::ShmemRing;
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

fn source() -> SourceTerminal {
    SourceTerminal::new(config(), contract(), SOURCE_SEED)
}

fn dest() -> DestTerminal {
    DestTerminal::new(
        config(),
        contract(),
        verifying_key(&SOURCE_SEED),
        DEST_SEED,
        DEST_X_SECRET,
    )
}

#[test]
fn vertical_slice_over_quic_hop_delivers() {
    let mut src = source();
    let mut dst = dest();
    let mut rail = QuicSubstrate::dev_loopback_pair().expect("quic loopback");

    let recs: [&[u8]; 2] = [b"evt:over-quic", b"evt:cross-host"];
    let cofre = src.board(&recs, b"quic-1").expect("board");
    rail.send(&cofre).expect("send over quic");

    let received = loop {
        if let Some(c) = rail.recv().expect("recv") {
            break c;
        }
    };
    assert_eq!(
        received, cofre,
        "the cofre survived the QUIC transport byte-for-byte"
    );
    assert_eq!(
        dst.offload(&received).expect("offload"),
        Disposition::Delivered
    );
    rail.ack(received.etiqueta.cofre_id).expect("ack");
    assert_eq!(
        dst.sink().committed().to_vec(),
        vec![b"evt:over-quic".to_vec(), b"evt:cross-host".to_vec()],
        "both records committed once, intact, across a real QUIC hop"
    );
    assert!(dst.dead_letters().is_empty());
}

#[test]
fn vertical_slice_over_shmem_hop_delivers() {
    let mut src = source();
    let mut dst = dest();
    let mut rail = ShmemRing::pair().expect("shmem ring");

    let recs: [&[u8]; 2] = [b"evt:over-shmem", b"evt:same-host"];
    let cofre = src.board(&recs, b"shmem-1").expect("board");
    rail.send(&cofre).expect("send over shmem");

    let received = loop {
        if let Some(c) = rail.recv().expect("recv") {
            break c;
        }
    };
    assert_eq!(
        received, cofre,
        "the cofre survived the shared-memory ring byte-for-byte"
    );
    assert_eq!(
        dst.offload(&received).expect("offload"),
        Disposition::Delivered
    );
    rail.ack(received.etiqueta.cofre_id).expect("ack");
    assert_eq!(
        dst.sink().committed().to_vec(),
        vec![b"evt:over-shmem".to_vec(), b"evt:same-host".to_vec()],
        "both records committed once, intact, across a real shared-memory hop"
    );
    assert!(dst.dead_letters().is_empty());
}

#[test]
fn vertical_slice_over_object_store_hop_delivers_decoupled() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static UNIQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "datarail-p5-objstore-{}-{}",
        std::process::id(),
        UNIQ.fetch_add(1, Ordering::Relaxed)
    ));

    let mut src = source();
    let recs: [&[u8]; 2] = [b"evt:stored", b"evt:later"];
    let cofre = src.board(&recs, b"obj-1").expect("board");

    // The source PUTs to the store and then goes away — the destination is offline at send time (temporal
    // decoupling, the object-store substrate's whole reason to exist).
    {
        let mut store = ObjectStoreSubstrate::open(&dir).expect("open source store");
        store.send(&cofre).expect("PUT");
    }

    // Later, a SEPARATE destination opens the same bucket, GETs, and offloads to Delivered.
    let mut dst = dest();
    let mut store = ObjectStoreSubstrate::open(&dir).expect("reopen dest store");
    let received = loop {
        if let Some(c) = store.recv().expect("GET") {
            break c;
        }
    };
    assert_eq!(
        received, cofre,
        "the cofre survived the object-store hop byte-for-byte"
    );
    assert_eq!(
        dst.offload(&received).expect("offload"),
        Disposition::Delivered
    );
    store.ack(received.etiqueta.cofre_id).expect("ack + GC");
    assert_eq!(
        dst.sink().committed().to_vec(),
        vec![b"evt:stored".to_vec(), b"evt:later".to_vec()],
        "records committed once, intact, across a decoupled object-store hop"
    );
    assert!(dst.dead_letters().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
