//! AC-10 fairness **rig** (SPEC-11). The rig runs every engine over the **same** workload and enforces the
//! core anti-cheat — **byte-equal delivery *before* timing**: an engine that delivers anything other than the
//! exact input (dropped, reordered, mangled, or "optimised" by skipping work) is disqualified *before* any
//! number is reported, so you can never win the benchmark by cheating correctness.
//!
//! The **real competitor engines** (Kafka / Fivetran / an MFT / …) are external infrastructure (task #20) — not
//! buildable here. What *is* the tech lead's to build, and is built here, is the **rig + methodology**: the
//! `MoverEngine` trait, datarail as an engine, an idealised pass-through baseline, the byte-equal gate, and the
//! anti-cheat checklist. When real engines arrive they implement `MoverEngine` and drop straight in.

use datarail_core::{AeadAlg, Disposition, Substrate};
use datarail_crypto::{verifying_key, x25519_public};
use datarail_rail::LoopbackSubstrate;
use datarail_terminal::{ContentContract, DestTerminal, SourceTerminal, TerminalConfig};

/// A data-mover under test: ship a workload end-to-end and return what was **delivered**, in order.
pub trait MoverEngine {
    /// Engine name (for the report).
    fn name(&self) -> &'static str;
    /// Ship `records` end-to-end; return the delivered records (must equal the input for a correct engine).
    fn ship(&mut self, records: &[Vec<u8>]) -> Vec<Vec<u8>>;
}

/// datarail itself as an engine: board → sealed cofre → (in-process substrate) → offload → committed records.
/// A fresh source/dest/substrate per `ship` (cold start — no cross-run caching, an anti-cheat requirement).
pub struct DatarailEngine;

const SRC_SEED: [u8; 32] = [11; 32];
const DST_SEED: [u8; 32] = [22; 32];
const DST_X: [u8; 32] = [5; 32];

fn config() -> TerminalConfig {
    TerminalConfig {
        route_id: [1; 16],
        stream_id: [2; 16],
        aead_alg: AeadAlg::Gcmsiv256,
        dest_x25519_pk: x25519_public(&DST_X),
        tenant_secret: [6; 32],
    }
}

fn contract() -> ContentContract {
    ContentContract::new(4096, b"evt:".to_vec())
}

impl MoverEngine for DatarailEngine {
    fn name(&self) -> &'static str {
        "datarail (sealed, effectively-once)"
    }

    fn ship(&mut self, records: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut src = SourceTerminal::new(config(), contract(), SRC_SEED);
        let mut dst = DestTerminal::new(
            config(),
            contract(),
            verifying_key(&SRC_SEED),
            DST_SEED,
            DST_X,
        );
        let mut rail = LoopbackSubstrate::new();
        let refs: Vec<&[u8]> = records.iter().map(Vec::as_slice).collect();
        let cofre = src
            .board(&refs, b"fairness-1")
            .expect("board conforming workload");
        rail.send(&cofre).expect("send");
        let received = rail.recv().expect("recv").expect("a cofre");
        assert_eq!(
            dst.offload(&received).expect("offload"),
            Disposition::Delivered
        );
        dst.sink().committed().to_vec()
    }
}

/// An idealised zero-overhead baseline: an in-memory pass-through (no sealing, no proof, no dedup). It is the
/// floor any *real* mover is measured against — never a winner on guarantees, only on raw copy speed.
pub struct PassthroughEngine;

impl MoverEngine for PassthroughEngine {
    fn name(&self) -> &'static str {
        "passthrough baseline (in-memory copy)"
    }

    fn ship(&mut self, records: &[Vec<u8>]) -> Vec<Vec<u8>> {
        records.to_vec()
    }
}

/// The anti-cheat gate: every engine must deliver **byte-equal** to `workload`. Returns the names of any
/// engines that failed (empty ⇒ all correct, timing may proceed). Cold-starts each engine (fresh `ship`).
#[must_use]
pub fn byte_equal_failures(
    engines: &mut [&mut dyn MoverEngine],
    workload: &[Vec<u8>],
) -> Vec<&'static str> {
    let mut failed = Vec::new();
    for engine in engines.iter_mut() {
        if engine.ship(workload).as_slice() != workload {
            failed.push(engine.name());
        }
    }
    failed
}

/// A conforming workload of `n` records (`evt:` prefix, distinct payloads) for the rig.
#[must_use]
pub fn workload(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("evt:record-{i:05}").into_bytes())
        .collect()
}

/// Print the fairness-rig status for the bench binary (DIRECTIONAL; the real bake-off needs external engines).
pub fn report() {
    println!(
        "\nAC-10 fairness rig (byte-equal-before-timing; real competitor engines = external, #20):"
    );
    let work = workload(64);
    let mut datarail = DatarailEngine;
    let mut baseline = PassthroughEngine;
    let mut engines: [&mut dyn MoverEngine; 2] = [&mut datarail, &mut baseline];
    let failures = byte_equal_failures(&mut engines, &work);
    if failures.is_empty() {
        println!("  byte-equal gate: PASS (datarail + baseline both deliver the workload exactly)");
    } else {
        println!("  byte-equal gate: FAIL for {failures:?} — timing withheld (anti-cheat)");
    }
    println!(
        "  (datarail adds sealing + delivery proof + effectively-once over the raw-copy baseline;"
    );
    println!(
        "   the fair comparison vs Kafka/MFT/Fivetran per corner needs those real engines — #20.)"
    );
}

#[cfg(test)]
mod tests {
    use super::{byte_equal_failures, workload, DatarailEngine, MoverEngine, PassthroughEngine};

    #[test]
    fn datarail_and_baseline_pass_the_byte_equal_gate() {
        let work = workload(32);
        let mut datarail = DatarailEngine;
        let mut baseline = PassthroughEngine;
        let mut engines: [&mut dyn MoverEngine; 2] = [&mut datarail, &mut baseline];
        let failures = byte_equal_failures(&mut engines, &work);
        assert!(
            failures.is_empty(),
            "correct engines deliver byte-equal: {failures:?}"
        );
    }

    #[test]
    fn a_cheating_engine_is_disqualified_before_timing() {
        // An engine that drops a record (or otherwise "optimises" correctness away) must FAIL the gate — the
        // anti-cheat: you cannot win on speed by delivering wrong output.
        struct DropsLast;
        impl MoverEngine for DropsLast {
            fn name(&self) -> &'static str {
                "cheater (drops the last record)"
            }
            fn ship(&mut self, records: &[Vec<u8>]) -> Vec<Vec<u8>> {
                let mut out = records.to_vec();
                out.pop();
                out
            }
        }
        let work = workload(8);
        let mut cheat = DropsLast;
        let mut engines: [&mut dyn MoverEngine; 1] = [&mut cheat];
        let failures = byte_equal_failures(&mut engines, &work);
        assert_eq!(
            failures,
            vec!["cheater (drops the last record)"],
            "the gate disqualifies a wrong engine"
        );
    }
}
