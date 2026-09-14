//! **Cross-cutting — FORGERY FLOOD.** Mix N authentic cofres with N forged ones (sealed by a *wrong signer*
//! the destination does not pin) and pour the interleaved flood into one destination.
//!
//! The pinned-key check (`INV-TAMPER-REJECT`, BLK-4) must hold under volume: **exactly the N authentic records
//! are delivered**, **every forged cofre is dead-lettered** (reason `SealFailed(SignerMismatch)`), and the sink
//! **never** contains a forged payload — 0 forged delivered, 0 panic, 0 leak.
//!
//! The forged cofres are *structurally valid* (boarded through a forger terminal with the same route/contract,
//! signed under a different Ed25519 seed) so this exercises the real signature-pin rejection, not a mere decode
//! failure — and their payloads are deliberately distinct from the authentic ones so any leak is detectable.

use datarail_core::Disposition;
use datarail_stress::{conforming_record, forger_source, record_key, Rig, Tally};
use datarail_terminal::{DeadLetterReason, SourceTerminal};

/// A forged payload for index `i` — distinct from any authentic payload, so a leak into the sink is detectable.
fn forged_payload(i: usize) -> Vec<u8> {
    format!("evt:FORGED-{i:08}").into_bytes()
}

/// FORGERY FLOOD — N legit + N forged, interleaved. Exactly the legit N delivered; all forged dead-lettered.
#[test]
fn forgery_flood_delivers_only_authentic_dead_letters_every_forgery() {
    const N: usize = 900; // N authentic + N forged == 1 800 cofres poured into one dest.

    let mut rig = Rig::new();
    let mut forger: SourceTerminal = forger_source(); // same route/contract, WRONG signing seed.
    let mut tally = Tally::new();

    let mut authentic_payloads: Vec<Vec<u8>> = Vec::with_capacity(N);
    let mut forged_set: Vec<Vec<u8>> = Vec::with_capacity(N);

    // Interleave the flood: for each i, offload one authentic cofre then one forged cofre.
    for i in 0..N {
        // Authentic: boarded through the real source (pinned key) ⇒ must be Delivered.
        let rec = conforming_record(i);
        let rk = record_key(i);
        let good = rig
            .source
            .board(&[rec.as_slice()], &rk)
            .expect("board authentic");
        authentic_payloads.push(rec);
        let disp_good = rig.dest.offload(&good).expect("offload authentic");
        tally.observe(disp_good);
        assert_eq!(
            disp_good,
            Disposition::Delivered,
            "authentic cofre must be delivered"
        );

        // Forged: boarded through the forger (wrong signer) with a DISTINCT payload ⇒ must be dead-lettered.
        let fpay = forged_payload(i);
        let frk = record_key(10_000_000 + i);
        let bad = forger
            .board(&[fpay.as_slice()], &frk)
            .expect("board forged (structurally valid)");
        forged_set.push(fpay);
        let disp_bad = rig.dest.offload(&bad).expect("offload forged");
        tally.observe(disp_bad);
        assert_eq!(
            disp_bad,
            Disposition::DeadLettered,
            "forged cofre must be dead-lettered, never delivered"
        );
    }

    // --- 0 forged delivered / 0-leak / exactly-N authentic. ---
    let committed = rig.dest.sink().committed();
    assert_eq!(
        committed.len(),
        N,
        "exactly the N authentic records delivered (0 forged delivered)"
    );
    assert_eq!(
        committed,
        authentic_payloads.as_slice(),
        "authentic records delivered exactly once, in order"
    );

    // The sink must NEVER contain a forged payload.
    for fpay in &forged_set {
        assert!(
            !committed.contains(fpay),
            "a forged payload reached the sink (0-leak violation)"
        );
    }

    // Every forgery is reason-coded as a signer-pin failure on the dead-letter siding.
    let dead = rig.dest.dead_letters();
    assert_eq!(dead.len(), N, "every forged cofre was dead-lettered");
    for entry in dead.entries() {
        assert!(
            matches!(
                entry.reason,
                DeadLetterReason::SealFailed(datarail_cofre::CofreError::SignerMismatch)
            ),
            "forgery dead-lettered for the wrong reason (expected SignerMismatch): {:?}",
            entry.reason
        );
    }

    assert_eq!(tally.delivered, N as u64, "exactly N delivered");
    assert_eq!(tally.dead_lettered, N as u64, "exactly N dead-lettered");
    assert_eq!(tally.duplicate, 0, "no duplicates in the flood");
    assert_eq!(tally.lost, 0, "0-loss: every authentic record landed");
    println!(
        "{} (authentic={N}, forged={N}, total={})",
        tally.report("forgery-flood"),
        2 * N
    );
}
