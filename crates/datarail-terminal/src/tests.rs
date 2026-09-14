//! AC-9 (content-contract refusals, both sides) + exactly-once integration proofs for the terminals.

use super::{
    ContentContract, DeadLetterReason, DestTerminal, SourceTerminal, TerminalConfig, TerminalError,
};
use datarail_cofre::CofreError;
use datarail_core::{AeadAlg, Disposition};
use datarail_crypto::{verifying_key, x25519_public};

const SOURCE_SEED: [u8; 32] = [11u8; 32];
const DEST_SEED: [u8; 32] = [22u8; 32];
const EVIL_SEED: [u8; 32] = [99u8; 32];
const ROUTE: [u8; 16] = [1u8; 16];
const STREAM: [u8; 16] = [2u8; 16];
const DEST_X_SECRET: [u8; 32] = [33u8; 32];
const TENANT: [u8; 32] = [5u8; 32];

const PREFIX: &[u8] = b"OK:";
const MAX_LEN: usize = 64;

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
    ContentContract::new(MAX_LEN, PREFIX.to_vec())
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

// ---- ContentContract unit behaviour ----------------------------------------------------------------------

#[test]
fn contract_validate_rules() {
    let c = contract();
    assert!(c.validate(b"OK:hello"));
    assert!(!c.validate(b""), "empty is rejected");
    assert!(!c.validate(b"NO:hello"), "wrong prefix is rejected");
    let too_long = [b'x'; MAX_LEN + 1];
    assert!(!c.validate(&too_long), "over max_record_len is rejected");
    assert!(c.validate(PREFIX), "exactly the prefix, at min len, is ok");
}

#[test]
fn same_rules_same_fingerprint() {
    // Two terminals configured with the same rules must agree on the schema id; different rules differ.
    assert_eq!(contract().fingerprint, contract().fingerprint);
    assert_ne!(
        contract().fingerprint,
        ContentContract::new(MAX_LEN, b"OTHER:".to_vec()).fingerprint
    );
    assert_ne!(
        contract().fingerprint,
        ContentContract::new(MAX_LEN + 1, PREFIX.to_vec()).fingerprint
    );
}

// ---- Happy path: a conforming batch boards and offloads, records land in the sink -------------------------

#[test]
fn round_trip_delivers_records() {
    let mut src = source();
    let mut dst = dest();
    let recs: [&[u8]; 2] = [b"OK:alpha", b"OK:beta"];
    let cofre = src.board(&recs, b"record-key-1").expect("board");
    assert_eq!(
        dst.offload(&cofre).expect("offload"),
        Disposition::Delivered
    );
    assert_eq!(
        dst.sink().committed(),
        &[b"OK:alpha".to_vec(), b"OK:beta".to_vec()]
    );
    assert!(dst.dead_letters().is_empty());
    assert_eq!(src.next_seq(), 1);
}

// ---- AC-9 (a): onboarding refuses a contract-violating record — NEVER boards -----------------------------

#[test]
fn ac9_board_refuses_contract_violating_record() {
    let mut src = source();
    // One good, one bad (wrong prefix) record: the whole batch must be refused.
    let recs: [&[u8]; 2] = [b"OK:good", b"BAD:nope"];
    assert_eq!(
        src.board(&recs, b"rk"),
        Err(TerminalError::ContractViolation)
    );
    // It never boarded: the sequence did not advance.
    assert_eq!(src.next_seq(), 0);

    // An empty record is likewise refused.
    let recs2: [&[u8]; 1] = [b""];
    assert_eq!(
        src.board(&recs2, b"rk"),
        Err(TerminalError::ContractViolation)
    );
    assert_eq!(src.next_seq(), 0);
}

#[test]
fn dead_letter_siding_is_bounded_under_a_flood() {
    // A hostile producer flooding contract-violating cofres must NOT grow the siding without bound (a long-running
    // destination would OOM). Past the retention cap the OLDEST is evicted (counted, not retained); the all-time
    // total is preserved. Boards under a permissive source, dead-letters at the strict dest (fingerprint mismatch).
    let permissive = ContentContract::new(MAX_LEN, Vec::new());
    let mut src = SourceTerminal::new(config(), permissive, SOURCE_SEED);
    let mut dst = dest();
    let cap = super::MAX_DEAD_LETTERS_RETAINED;
    let n = cap + 100;
    for i in 0..n {
        let rk = format!("flood-{i}");
        let rec = format!("NO-PREFIX-{i}");
        let recs: [&[u8]; 1] = [rec.as_bytes()];
        let cofre = src.board(&recs, rk.as_bytes()).expect("board");
        assert_eq!(
            dst.offload(&cofre).expect("offload"),
            Disposition::DeadLettered
        );
    }
    assert_eq!(dst.dead_letters().len(), cap, "retained count is capped");
    assert_eq!(
        dst.dead_letters().dropped(),
        100,
        "older diversions evicted + counted"
    );
    assert_eq!(
        dst.dead_letters().total(),
        u64::try_from(n).unwrap(),
        "all-time total preserved"
    );
    assert!(
        dst.sink().is_empty(),
        "no dead-lettered cofre is ever committed"
    );
}

// ---- AC-9 (b): offload of contract-violating records ⇒ dead-lettered, NOT committed ----------------------

#[test]
fn ac9_offload_dead_letters_contract_violation_not_committed() {
    // The *source* enforces a permissive contract (boards anything non-empty); the *dest* enforces the
    // strict PREFIX contract — so a record that boards can still violate the offloading contract (AC-9).
    let permissive = ContentContract::new(MAX_LEN, Vec::new());
    let mut src = SourceTerminal::new(config(), permissive, SOURCE_SEED);
    let mut dst = dest(); // strict PREFIX contract

    let recs: [&[u8]; 1] = [b"NO-PREFIX-here"]; // boards under permissive, violates strict dest contract
    let cofre = src
        .board(&recs, b"rk")
        .expect("boards under permissive contract");

    // The dest's contract_fp differs from the cofre's, so the *fingerprint* check fires first (still AC-9:
    // a managed schema event, dead-lettered, never committed).
    let disp = dst.offload(&cofre).expect("offload");
    assert_eq!(disp, Disposition::DeadLettered);
    assert!(dst.sink().is_empty(), "nothing committed");
    assert_eq!(dst.dead_letters().len(), 1);
    assert_eq!(
        dst.dead_letters().entries()[0].reason,
        DeadLetterReason::ContractFingerprintMismatch
    );
}

#[test]
fn ac9_offload_dead_letters_post_decrypt_record_violation() {
    // Isolate step (5) — the *record* re-validation — from the (4) fingerprint check. Honestly-configured
    // terminals with the same rules share a fingerprint, so a record that boards also passes at the dest. To
    // exercise the post-decrypt record check directly, the dest pins a STRICTER rule (PREFIX b"OK:STRICT:")
    // but advertises the *source's* fingerprint, so the fingerprint gate passes and the record-validation
    // gate is the one that fires.
    let mut src = source(); // boards b"OK:..." records
    let mut dst_strict = ContentContract::new(MAX_LEN, b"OK:STRICT:".to_vec());
    dst_strict.fingerprint = contract().fingerprint; // align fp so step (4) passes, step (5) is reached
    let mut dst = DestTerminal::new(
        config(),
        dst_strict,
        verifying_key(&SOURCE_SEED),
        DEST_SEED,
        DEST_X_SECRET,
    );

    let recs: [&[u8]; 1] = [b"OK:loose"]; // valid at source, fails the dest's stricter prefix
    let cofre = src.board(&recs, b"rk").expect("board");
    let disp = dst.offload(&cofre).expect("offload");
    assert_eq!(disp, Disposition::DeadLettered);
    assert!(
        dst.sink().is_empty(),
        "contract-violating records are NOT committed"
    );
    assert_eq!(
        dst.dead_letters().entries()[0].reason,
        DeadLetterReason::ContractViolation
    );
}

// ---- AC-9 (c): wrong contract_fp ⇒ dead-lettered ---------------------------------------------------------

#[test]
fn ac9_wrong_contract_fingerprint_dead_lettered() {
    // Source stamps one schema; dest pins a *different* schema version => managed drift, dead-lettered.
    let src_contract = ContentContract::new(MAX_LEN, PREFIX.to_vec());
    let dst_contract = ContentContract::new(MAX_LEN, b"V2:".to_vec()); // different fingerprint
    let mut src = SourceTerminal::new(config(), src_contract, SOURCE_SEED);
    let mut dst = DestTerminal::new(
        config(),
        dst_contract,
        verifying_key(&SOURCE_SEED),
        DEST_SEED,
        DEST_X_SECRET,
    );

    let recs: [&[u8]; 1] = [b"OK:payload"];
    let cofre = src.board(&recs, b"rk").expect("board");
    assert_eq!(
        dst.offload(&cofre).expect("offload"),
        Disposition::DeadLettered
    );
    assert!(dst.sink().is_empty());
    assert_eq!(
        dst.dead_letters().entries()[0].reason,
        DeadLetterReason::ContractFingerprintMismatch
    );
}

// ---- AC-9 (d): tampered / forged cofre ⇒ dead-lettered --------------------------------------------------

#[test]
fn ac9_tampered_carga_dead_lettered() {
    let mut src = source();
    let mut dst = dest();
    let recs: [&[u8]; 1] = [b"OK:payload"];
    let mut cofre = src.board(&recs, b"rk").expect("board");
    // Flip a ciphertext byte: the lacre covers etiqueta ⊗ carga, so verify() fails (cofre_id mismatch).
    cofre.carga[0] ^= 0x01;
    let disp = dst.offload(&cofre).expect("offload");
    assert_eq!(disp, Disposition::DeadLettered);
    assert!(dst.sink().is_empty());
    assert!(matches!(
        dst.dead_letters().entries()[0].reason,
        DeadLetterReason::SealFailed(_)
    ));
}

#[test]
fn ac9_forged_cofre_wrong_signer_dead_lettered() {
    // A cofre sealed by an impostor key, verified against the pinned source key, is rejected (BLK-4, AC-3).
    let mut evil = SourceTerminal::new(config(), contract(), EVIL_SEED);
    let mut dst = dest(); // pins verifying_key(SOURCE_SEED)
    let recs: [&[u8]; 1] = [b"OK:payload"];
    let cofre = evil.board(&recs, b"rk").expect("board");
    let disp = dst.offload(&cofre).expect("offload");
    assert_eq!(disp, Disposition::DeadLettered);
    assert!(dst.sink().is_empty());
    assert_eq!(
        dst.dead_letters().entries()[0].reason,
        DeadLetterReason::SealFailed(CofreError::SignerMismatch)
    );
}

#[test]
fn ac9_tampered_etiqueta_seq_dead_lettered() {
    // Mutating an authenticated header field breaks the lacre (INV-SEAL-COMPLETE) => dead-letter.
    let mut src = source();
    let mut dst = dest();
    let recs: [&[u8]; 1] = [b"OK:payload"];
    let mut cofre = src.board(&recs, b"rk").expect("board");
    cofre.etiqueta.seq ^= 0x01;
    let disp = dst.offload(&cofre).expect("offload");
    assert_eq!(disp, Disposition::DeadLettered);
    assert!(dst.sink().is_empty());
    assert!(matches!(
        dst.dead_letters().entries()[0].reason,
        DeadLetterReason::SealFailed(_)
    ));
}

// ---- Exactly-once mini-proof: the SAME cofre offloaded twice ---------------------------------------------

#[test]
fn exactly_once_same_cofre_twice() {
    let mut src = source();
    let mut dst = dest();
    let recs: [&[u8]; 2] = [b"OK:one", b"OK:two"];
    let cofre = src.board(&recs, b"record-key-A").expect("board");

    // First offload: Delivered, records committed once.
    assert_eq!(
        dst.offload(&cofre).expect("offload 1"),
        Disposition::Delivered
    );
    assert_eq!(dst.sink().len(), 2);
    assert_eq!(
        dst.sink().committed(),
        &[b"OK:one".to_vec(), b"OK:two".to_vec()]
    );

    // Second offload of the identical cofre: Duplicate, sink UNCHANGED (no re-commit).
    assert_eq!(
        dst.offload(&cofre).expect("offload 2"),
        Disposition::Duplicate
    );
    assert_eq!(dst.sink().len(), 2, "duplicate must not re-commit");
    assert_eq!(
        dst.sink().committed(),
        &[b"OK:one".to_vec(), b"OK:two".to_vec()]
    );
    assert!(dst.dead_letters().is_empty());
}

#[test]
fn distinct_record_keys_are_both_delivered() {
    // Two genuinely distinct cofres (different record-key => different idempotency_key, advancing seq) both
    // commit — exactly-once is per-record, not "deliver only one ever".
    let mut src = source();
    let mut dst = dest();
    let c0 = src.board(&[b"OK:zero"], b"rk-0").expect("board 0");
    let c1 = src.board(&[b"OK:one"], b"rk-1").expect("board 1");
    assert_eq!(dst.offload(&c0).expect("off 0"), Disposition::Delivered);
    assert_eq!(dst.offload(&c1).expect("off 1"), Disposition::Delivered);
    assert_eq!(dst.sink().len(), 2);
}

// ---- A4 sealed-sender: the fine-grained sender rides ENCRYPTED inside the carga (SPEC-02 A4 / 03 MAJ-4) ----
mod sealed_sender {
    use super::{config, contract, DEST_SEED, DEST_X_SECRET, SOURCE_SEED};
    use crate::{
        issue_sender_cert, DeadLetterReason, DestTerminal, SenderCredential, SourceTerminal,
    };
    use datarail_core::Disposition;
    use datarail_crypto::verifying_key;

    const ISSUER_SEED: [u8; 32] = [70u8; 32];
    const SENDER_SEED: [u8; 32] = [71u8; 32];
    const SENDER_ID: [u8; 32] = [0xABu8; 32];
    const EPOCH: u64 = 7;

    /// A source configured with a valid issuer-signed sealed-sender credential.
    fn sealed_source() -> SourceTerminal {
        let sender_vk = verifying_key(&SENDER_SEED);
        let issuer_sig = issue_sender_cert(&ISSUER_SEED, &SENDER_ID, &sender_vk, EPOCH);
        SourceTerminal::new(config(), contract(), SOURCE_SEED).with_sender(SenderCredential::new(
            SENDER_ID,
            SENDER_SEED,
            EPOCH,
            issuer_sig,
        ))
    }

    fn dest_with_issuer(issuer_vk: [u8; 32]) -> DestTerminal {
        DestTerminal::new(
            config(),
            contract(),
            verifying_key(&SOURCE_SEED),
            DEST_SEED,
            DEST_X_SECRET,
        )
        .with_sender_issuer(issuer_vk)
    }

    #[test]
    fn sealed_sender_round_trips_and_dest_validates_the_sender() {
        let mut src = sealed_source();
        let mut dst = dest_with_issuer(verifying_key(&ISSUER_SEED));
        let cofre = src.board(&[b"OK:hello"], b"rk").expect("board");
        assert!(
            cofre.etiqueta.sender_present,
            "header flags the sealed sender"
        );

        assert_eq!(
            dst.offload(&cofre).expect("offload"),
            Disposition::Delivered
        );
        assert_eq!(dst.sink().committed(), &[b"OK:hello".to_vec()]);
        assert_eq!(
            dst.last_sender_id(),
            Some(SENDER_ID),
            "the dest validated + exposed the sender id"
        );
        assert!(dst.dead_letters().is_empty());
    }

    #[test]
    fn sealed_sender_below_min_epoch_is_dead_lettered() {
        // audit S-2: once the dest pins a higher epoch floor (a key rotation / revocation), a cert minted at the
        // old EPOCH must stop being honored — even though the issuer signature is still valid.
        let mut src = sealed_source();
        let mut dst =
            dest_with_issuer(verifying_key(&ISSUER_SEED)).with_min_sender_epoch(EPOCH + 1);
        let cofre = src.board(&[b"OK:hello"], b"rk").expect("board");
        assert_eq!(
            dst.offload(&cofre).expect("offload"),
            Disposition::DeadLettered
        );
        assert!(
            dst.last_sender_id().is_none(),
            "a below-floor sender is never accepted"
        );
        // At exactly the floor the same sender is accepted again.
        let mut at_floor =
            dest_with_issuer(verifying_key(&ISSUER_SEED)).with_min_sender_epoch(EPOCH);
        let cofre2 = src.board(&[b"OK:world"], b"rk2").expect("board");
        assert_eq!(
            at_floor.offload(&cofre2).expect("offload"),
            Disposition::Delivered
        );
        assert_eq!(at_floor.last_sender_id(), Some(SENDER_ID));
    }

    #[test]
    fn the_rail_never_sees_the_sender_id_in_cleartext() {
        // INV-OPAQUE-CARGO for the sender: the plaintext sender_id must appear NOWHERE on the wire — it rides
        // inside the AEAD-encrypted carga, so its raw bytes cannot occur in the encoded cofre.
        let mut src = sealed_source();
        let cofre = src.board(&[b"OK:secret-sender"], b"rk").expect("board");
        let wire = datarail_cofre::encode(&cofre);
        let appears = wire.windows(SENDER_ID.len()).any(|w| w == SENDER_ID);
        assert!(
            !appears,
            "the sender_id bytes must not be observable in the cleartext wire cofre"
        );
    }

    #[test]
    fn sealed_sender_with_no_issuer_pinned_is_dead_lettered() {
        // A dest that did not pin an issuer cannot validate the claimed sender → dead-letter, never deliver.
        let mut src = sealed_source();
        let mut dst = DestTerminal::new(
            config(),
            contract(),
            verifying_key(&SOURCE_SEED),
            DEST_SEED,
            DEST_X_SECRET,
        ); // no with_sender_issuer
        let cofre = src.board(&[b"OK:hello"], b"rk").expect("board");
        assert_eq!(
            dst.offload(&cofre).expect("offload"),
            Disposition::DeadLettered
        );
        assert!(dst.sink().is_empty());
        assert_eq!(
            dst.dead_letters().entries()[0].reason,
            DeadLetterReason::SenderCertInvalid
        );
    }

    #[test]
    fn forged_issuer_is_dead_lettered() {
        // The cert is validated against the WRONG issuer key (an impostor authority) → fails → dead-letter.
        let mut src = sealed_source();
        let mut dst = dest_with_issuer(verifying_key(&[88u8; 32])); // not the real issuer
        let cofre = src.board(&[b"OK:hello"], b"rk").expect("board");
        assert_eq!(
            dst.offload(&cofre).expect("offload"),
            Disposition::DeadLettered
        );
        assert!(dst.sink().is_empty());
        assert_eq!(
            dst.dead_letters().entries()[0].reason,
            DeadLetterReason::SenderCertInvalid
        );
        assert_eq!(dst.last_sender_id(), None);
    }

    #[test]
    fn a_cert_minted_for_a_different_sender_key_is_rejected() {
        // The issuer signs sender_id↔sender_vk; if the credential's signing seed does not match the vk the
        // issuer vouched for, the per-cofre sender binding is signed by the wrong key → validation fails.
        let real_vk = verifying_key(&SENDER_SEED);
        let issuer_sig = issue_sender_cert(&ISSUER_SEED, &SENDER_ID, &real_vk, EPOCH);
        // Credential carries a DIFFERENT signing seed than the one the issuer vouched for.
        let mut src = SourceTerminal::new(config(), contract(), SOURCE_SEED).with_sender(
            SenderCredential::new(SENDER_ID, [0x55u8; 32], EPOCH, issuer_sig),
        );
        let mut dst = dest_with_issuer(verifying_key(&ISSUER_SEED));
        let cofre = src.board(&[b"OK:hello"], b"rk").expect("board");
        assert_eq!(
            dst.offload(&cofre).expect("offload"),
            Disposition::DeadLettered
        );
        assert_eq!(
            dst.dead_letters().entries()[0].reason,
            DeadLetterReason::SenderCertInvalid
        );
    }

    #[test]
    fn non_sealed_sender_still_works_unchanged() {
        // A plain source (no credential) produces sender_present=false; a plain dest delivers as before.
        let mut src = SourceTerminal::new(config(), contract(), SOURCE_SEED);
        let mut dst = DestTerminal::new(
            config(),
            contract(),
            verifying_key(&SOURCE_SEED),
            DEST_SEED,
            DEST_X_SECRET,
        );
        let cofre = src.board(&[b"OK:plain"], b"rk").expect("board");
        assert!(!cofre.etiqueta.sender_present);
        assert_eq!(
            dst.offload(&cofre).expect("offload"),
            Disposition::Delivered
        );
        assert_eq!(dst.last_sender_id(), None);
    }
}

// ---- AC-9 (proptest): the SPEC-11 *named* proof method — randomized conforming/violating cases, both sides --
mod prop {
    use super::{contract, dest, source, Disposition, TerminalError, MAX_LEN, PREFIX};
    use proptest::prelude::*;
    use proptest::sample::Index;

    /// A record that always satisfies `contract()`: `PREFIX` followed by an arbitrary tail, total ≤ `MAX_LEN`.
    fn conforming_record() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..=(MAX_LEN - PREFIX.len())).prop_map(|tail| {
            let mut rec = PREFIX.to_vec();
            rec.extend_from_slice(&tail);
            rec
        })
    }

    proptest! {
        /// Source onboarding (AC-9a): the terminal boards a batch **iff every record conforms**; a batch with
        /// any violating record is refused and the sequence never advances (it never boards).
        #[test]
        fn source_boards_iff_all_records_conform(
            recs in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..80), 1..6)
        ) {
            let mut src = source();
            let all_conform = recs.iter().all(|r| contract().validate(r));
            let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
            let res = src.board(&refs, b"rk");
            if all_conform {
                prop_assert!(res.is_ok(), "a fully-conforming batch must board");
                prop_assert_eq!(src.next_seq(), 1);
            } else {
                prop_assert_eq!(res, Err(TerminalError::ContractViolation));
                prop_assert_eq!(src.next_seq(), 0, "a violating batch must never board");
            }
        }

        /// Dest offloading happy path (AC-9b): any honestly-boarded conforming batch Delivers and commits
        /// exactly those records, with no dead-letters.
        #[test]
        fn conforming_batch_round_trips_and_commits(
            recs in proptest::collection::vec(conforming_record(), 1..6)
        ) {
            let mut src = source();
            let mut dst = dest();
            let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
            let cofre = src.board(&refs, b"rk").expect("a conforming batch boards");
            prop_assert_eq!(dst.offload(&cofre).expect("offload"), Disposition::Delivered);
            prop_assert_eq!(dst.sink().committed(), &recs[..]);
            prop_assert!(dst.dead_letters().is_empty());
        }

        /// Dest tamper rejection (AC-9d / AC-2 at the terminal): flipping **any** single ciphertext byte breaks
        /// the seal, so the cofre is dead-lettered and nothing is committed — for every conforming batch and
        /// every byte position.
        #[test]
        fn any_carga_byte_flip_is_dead_lettered(
            recs in proptest::collection::vec(conforming_record(), 1..4),
            at in any::<Index>(),
        ) {
            let mut src = source();
            let mut dst = dest();
            let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
            let mut cofre = src.board(&refs, b"rk").expect("board");
            let i = at.index(cofre.carga.len());
            cofre.carga[i] ^= 0x01;
            prop_assert_eq!(dst.offload(&cofre).expect("offload"), Disposition::DeadLettered);
            prop_assert!(dst.sink().is_empty(), "a tampered cofre commits nothing");
        }
    }
}

// ---- CSPRNG (per-thread forward-secure DRBG) sanity — AUDIT-04 perf fix must not weaken randomness ----

#[test]
fn drbg_outputs_are_distinct_across_many_draws() {
    use std::collections::HashSet;
    // Every 32-byte output must be unique across a large run (a repeat would betray a broken PRF/entropy mix).
    let n = 70_000usize;
    let mut seen = HashSet::with_capacity(n);
    for _ in 0..n {
        let r = super::random_32().expect("drbg draw");
        assert!(
            seen.insert(r),
            "DRBG produced a repeated 32-byte output — randomness is broken"
        );
        assert_ne!(r, [0u8; 32], "DRBG must not emit all-zeros");
    }
}

#[test]
fn reserved_sequences_are_contiguous_within_each_partition() {
    let mut src = source();
    let mut next = [0_u64; 4];
    for i in 0_u64..1_000 {
        let partition = usize::try_from(i % 4).expect("partition fits usize");
        let count = i % 7 + 1;
        let start = src.reserve_seqs(u64::try_from(partition).expect("partition fits u64"), count);
        assert_eq!(start, next[partition]);
        next[partition] += count;
    }
}

#[test]
fn drbg_backed_board_still_seals_and_offloads_round_trip() {
    // The ephemeral key + nonce now come from the DRBG; a full board→offload must still verify + deliver,
    // proving the DRBG-produced key material yields valid seals (not just distinct bytes).
    let contract = ContentContract::new(4096, Vec::new());
    let cfg = TerminalConfig {
        route_id: ROUTE,
        stream_id: STREAM,
        aead_alg: AeadAlg::Gcmsiv256,
        dest_x25519_pk: x25519_public(&DEST_X_SECRET),
        tenant_secret: [6u8; 32],
    };
    let mut src = SourceTerminal::new(cfg.clone(), contract.clone(), SOURCE_SEED);
    let src_vk = verifying_key(&SOURCE_SEED);
    let mut dst = DestTerminal::new(cfg, contract, src_vk, DEST_SEED, DEST_X_SECRET);
    let recs: Vec<&[u8]> = vec![
        b"alpha".as_slice(),
        b"bravo".as_slice(),
        b"charlie".as_slice(),
    ];
    for i in 0u64..200 {
        let cofre = src.board(&recs, &i.to_le_bytes()).expect("board");
        // distinct ephemeral pubkey per cofre (fresh DRBG draw) — no key reuse across cofres
        assert_ne!(cofre.etiqueta.eph_pk, [0u8; 32]);
        assert_eq!(
            dst.offload(&cofre).expect("offload"),
            Disposition::Delivered
        );
    }
    assert_eq!(dst.sink().committed().len(), 200 * recs.len());
}

#[test]
fn drbg_identical_state_clones_diverge_every_draw() {
    // AUDIT-05: a VM-snapshot / CRIU / paused-VM clone preserves the PID *and* the DRBG state byte-for-byte —
    // the exact case the old PID-based reseed gate missed. Construct two DRBGs with the IDENTICAL seed (a perfect
    // clone) and assert their draws DIFFER every time: because each draw mixes fresh OS entropy, the clones can
    // never replay an identical (eph_secret, nonce) → no catastrophic (data_key, nonce) re-pair under plain GCM.
    let seed = super::os_seed_32().expect("seed");
    let mut original = super::Drbg { seed };
    let mut clone = super::Drbg { seed }; // byte-identical clone — same seed, same (preserved) PID
    let mut observed = std::collections::HashSet::new();
    for _ in 0..1000 {
        let from_original = original.next_32().expect("original draw");
        let from_clone = clone.next_32().expect("clone draw");
        assert_ne!(
            from_original, from_clone,
            "identical-state clones must diverge every draw (snapshot immunity)"
        );
        assert!(
            observed.insert(from_original) && observed.insert(from_clone),
            "no repeated output across clones"
        );
    }
}
