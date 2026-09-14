//! MF-4 — the first vertical slice. A sealed cofre boards at the source terminal, rides the loopback rail, is
//! verified and offloaded exactly once at the destination (with an offline-verifiable manifest receipt); a
//! replay of the same cofre is deduped to a no-op; and a tampered cofre is dead-lettered, never delivered.
//!
//! This is the end-to-end proof that the whole pipe moves data — exactly once, tamper-rejected, provable.

use datarail_core::{AeadAlg, Disposition, Substrate};
use datarail_crypto::{verifying_key, x25519_public};
use datarail_manifest::{sign_ack, verify_delivery, DeliveryProof, ManifestLog};
use datarail_rail::LoopbackSubstrate;
use datarail_terminal::{ContentContract, DestTerminal, SourceTerminal, TerminalConfig};

const SOURCE_SEED: [u8; 32] = [11; 32];
const DEST_SEED: [u8; 32] = [22; 32];
const ROUTE: [u8; 16] = [1; 16];
const STREAM: [u8; 16] = [2; 16];
const DEST_X_SECRET: [u8; 32] = [5; 32];
const TENANT: [u8; 32] = [6; 32];
const EPOCH: u64 = 1;
const TS: u64 = 1_700_000_000;

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
    // A simple offloading/onboarding contract: records start with "evt:" and are <= 1 KiB.
    ContentContract::new(1024, b"evt:".to_vec())
}

#[test]
fn mf4_board_rail_offload_exactly_once_and_dead_letter() {
    let source_vk = verifying_key(&SOURCE_SEED);
    let dest_vk = verifying_key(&DEST_SEED);
    let mut source = SourceTerminal::new(config(), contract(), SOURCE_SEED);
    let mut dest = DestTerminal::new(config(), contract(), source_vk, DEST_SEED, DEST_X_SECRET);
    let mut rail = LoopbackSubstrate::new();

    // ---- Board a conforming batch → sealed cofre. ----
    let records: [&[u8]; 2] = [b"evt:alpha", b"evt:bravo"];
    let cofre = source
        .board(&records, b"order-42")
        .expect("conforming batch boards");

    // ---- Ride the (dumb, header-only) loopback rail. ----
    rail.send(&cofre).expect("send");
    let received = rail
        .recv()
        .expect("recv ok")
        .expect("a cofre is on the rail");
    assert_eq!(received, cofre, "the rail moved the cofre byte-for-byte");

    // ---- Offload: verify → open → contract → admit → commit, exactly once. ----
    assert_eq!(
        dest.offload(&received).expect("offload"),
        Disposition::Delivered
    );
    rail.ack(received.etiqueta.cofre_id).expect("ack");
    assert_eq!(
        dest.sink().committed().to_vec(),
        vec![b"evt:alpha".to_vec(), b"evt:bravo".to_vec()],
        "both records committed once"
    );
    assert!(dest.dead_letters().is_empty(), "nothing dead-lettered");

    // ---- Provable delivery receipt: the delivered cofre's leaf sits in a signed tree; the bundle verifies
    //      offline with zero trust in the pipe (BLK-8 cofre_id recompute included). ----
    let mut log = ManifestLog::new();
    log.append(
        &cofre.etiqueta.cofre_id,
        &ROUTE,
        &STREAM,
        cofre.etiqueta.seq,
        EPOCH,
    );
    let sth = log.sign_sth(&SOURCE_SEED, TS);
    let proof = log.inclusion_proof(0).expect("inclusion proof");
    let ack = sign_ack(
        &DEST_SEED,
        cofre.etiqueta.cofre_id,
        ROUTE,
        STREAM,
        cofre.etiqueta.seq,
        sth.root,
        EPOCH,
    );
    verify_delivery(&DeliveryProof {
        carga: &cofre.carga,
        route_id: &ROUTE,
        stream_id: &STREAM,
        seq: cofre.etiqueta.seq,
        epoch: EPOCH,
        proof: &proof,
        sth: &sth,
        source_vk: &source_vk,
        ack: &ack,
        dest_vk: &dest_vk,
    })
    .expect("delivery proof verifies offline");

    // ---- Exactly-once: replay the SAME cofre → Duplicate, sink unchanged. ----
    assert_eq!(
        dest.offload(&cofre).expect("replay"),
        Disposition::Duplicate,
        "a replayed cofre is deduped"
    );
    assert_eq!(
        dest.sink().committed().len(),
        2,
        "no re-commit on replay (exactly-once)"
    );

    // ---- Dead-letter: a tampered cofre → siding, never delivered. ----
    let mut tampered = cofre.clone();
    tampered.carga[0] ^= 0x01;
    assert_eq!(
        dest.offload(&tampered).expect("tampered offload"),
        Disposition::DeadLettered,
        "a tampered cofre is dead-lettered"
    );
    assert_eq!(
        dest.sink().committed().len(),
        2,
        "a tampered cofre never commits"
    );
    assert_eq!(
        dest.dead_letters().len(),
        1,
        "tampered cofre is on the siding"
    );
}
