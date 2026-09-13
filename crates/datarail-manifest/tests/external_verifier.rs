//! External-consumer shape test: receipt verification needs only `datarail_manifest`'s public API.

use datarail_manifest::{
    leaf_hash, sign_ack, verify_receipt, DeliveryReceipt, DestAck, InclusionProof, ManifestError,
    ManifestLog, OwnedDeliveryReceipt, SignedTreeHead,
};

const SOURCE_SEED: [u8; 32] = [11; 32];
const SOURCE_VK: [u8; 32] = [
    102, 190, 126, 51, 44, 122, 69, 51, 50, 189, 157, 10, 127, 125, 176, 85, 245, 197, 239, 26, 6,
    173, 166, 109, 152, 179, 159, 182, 129, 12, 71, 58,
];
const DEST_SEED: [u8; 32] = [22; 32];
const DEST_VK: [u8; 32] = [
    81, 28, 52, 161, 162, 203, 82, 29, 241, 107, 178, 70, 184, 222, 142, 121, 151, 206, 35, 92,
    126, 118, 178, 42, 61, 117, 3, 162, 72, 25, 221, 138,
];
const COFRE_ID: [u8; 32] = [
    83, 120, 6, 90, 35, 122, 150, 130, 24, 29, 52, 177, 118, 235, 137, 76, 9, 10, 27, 62, 226, 221,
    175, 181, 25, 17, 233, 133, 235, 207, 184, 164,
];
const CARGA: &[u8] = b"external payload";
const ROUTE: [u8; 16] = [1; 16];
const STREAM: [u8; 16] = [2; 16];
const WRONG_COORDINATE: [u8; 16] = [8; 16];
const SEQ: u64 = 4;
const EPOCH: u64 = 7;

fn fixture() -> (InclusionProof, SignedTreeHead, DestAck) {
    let leaf = leaf_hash(&COFRE_ID, &ROUTE, &STREAM, SEQ, EPOCH);
    let mut log = ManifestLog::new();
    log.append_leaf(leaf);
    log.append_leaf([9; 32]);
    let sth = log.sign_sth(&SOURCE_SEED, 1_700_000_000);
    let proof = log.inclusion_proof(0).expect("proof");
    let ack = sign_ack(&DEST_SEED, COFRE_ID, ROUTE, STREAM, SEQ, sth.root, EPOCH);
    (proof, sth, ack)
}

fn receipt<'a>(
    proof: &'a InclusionProof,
    sth: &'a SignedTreeHead,
    ack: &'a DestAck,
) -> DeliveryReceipt<'a> {
    DeliveryReceipt {
        carga: CARGA,
        route_id: &ROUTE,
        stream_id: &STREAM,
        seq: SEQ,
        epoch: EPOCH,
        proof,
        sth,
        source_vk: &SOURCE_VK,
        ack,
        dest_vk: &DEST_VK,
    }
}

#[test]
fn external_consumer_verifies_receipt_offline() {
    let (proof, sth, ack) = fixture();
    verify_receipt(&receipt(&proof, &sth, &ack)).expect("valid receipt");
}

#[test]
fn external_consumer_verifies_owned_typed_receipt() {
    let (proof, sth, ack) = fixture();
    OwnedDeliveryReceipt {
        carga: CARGA.to_vec(),
        route_id: ROUTE,
        stream_id: STREAM,
        seq: SEQ,
        epoch: EPOCH,
        proof,
        sth,
        source_vk: SOURCE_VK,
        ack,
        dest_vk: DEST_VK,
    }
    .verify()
    .expect("valid owned receipt");
}

#[test]
fn external_consumer_rejects_route_stream_seq_root_signature_and_tampering() {
    let (proof, sth, ack) = fixture();
    let receipt = receipt(&proof, &sth, &ack);

    let mut wrong_route = receipt;
    wrong_route.route_id = &WRONG_COORDINATE;
    assert!(verify_receipt(&wrong_route).is_err());

    let mut wrong_stream = receipt;
    wrong_stream.stream_id = &WRONG_COORDINATE;
    assert!(verify_receipt(&wrong_stream).is_err());

    let mut wrong_seq = receipt;
    wrong_seq.seq += 1;
    assert!(verify_receipt(&wrong_seq).is_err());

    let mut wrong_root = sth;
    wrong_root.root[0] ^= 1;
    let wrong_root_receipt = DeliveryReceipt {
        sth: &wrong_root,
        ..receipt
    };
    assert_eq!(
        verify_receipt(&wrong_root_receipt),
        Err(ManifestError::BadSth)
    );

    let mut wrong_signature = sth;
    wrong_signature.sig[0] ^= 1;
    let wrong_signature_receipt = DeliveryReceipt {
        sth: &wrong_signature,
        ..receipt
    };
    assert_eq!(
        verify_receipt(&wrong_signature_receipt),
        Err(ManifestError::BadSth)
    );

    let mut tampered_path = proof.clone();
    tampered_path.path[0].sibling[0] ^= 1;
    let tampered_receipt = DeliveryReceipt {
        proof: &tampered_path,
        ..receipt
    };
    assert_eq!(
        verify_receipt(&tampered_receipt),
        Err(ManifestError::BadInclusion)
    );

    let mut tampered_ack = ack;
    tampered_ack.dest_sig[0] ^= 1;
    let tampered_ack_receipt = DeliveryReceipt {
        ack: &tampered_ack,
        ..receipt
    };
    assert_eq!(
        verify_receipt(&tampered_ack_receipt),
        Err(ManifestError::BadAckSig)
    );

    let mut tampered_payload = receipt;
    tampered_payload.carga = b"external payload tampered";
    assert_eq!(
        verify_receipt(&tampered_payload),
        Err(ManifestError::CofreIdMismatch)
    );

    let mut wrong_metadata = proof.clone();
    wrong_metadata.tree_size += 1;
    let wrong_metadata_receipt = DeliveryReceipt {
        proof: &wrong_metadata,
        ..receipt
    };
    assert_eq!(
        verify_receipt(&wrong_metadata_receipt),
        Err(ManifestError::BadInclusion)
    );
}
