# Work Package Plan: WP-01 — Per-Partition Locking (Kill the Last Throughput Serializer)

**Status:** ❌ REJECTED — Superseded by `WP-01-PER-PARTITION-LOCKING-CHECKLIST.md`  
**Baseline:** `v0.1.0` (SHA: `3cc5bb9`)  
**Owner:** TechLead  
**Review Date:** 2026-09-10  
**Adversarial Review:** FAILED — 5 fatal flaws, 8 hidden couplings, 7 missing tasks

> **This plan is NOT executable.** See `WP-01-PER-PARTITION-LOCKING-CHECKLIST.md` for the corrected redesign with all fixes.

---

## 1. AXIOMS (Non-Negotiable Principles)

| Axiom | Description | Enforcement |
|---|---|---|
| **A1 — Single Writer Per Partition** | Each `(topic, partition)` log is mutated by exactly one logical writer at a time. No cross-partition serialization. | Mutex-per-partition; seq-reservation stays partition-local. |
| **A2 — Seq-Reservation Invariance** | `SourceTerminal::reserve_seqs` must allocate contiguous, non-overlapping ranges within each partition. Partition namespaces are independent by design. | Unit test (1000 reservations). |
| **A3 — Txn Epoch Fencing Preserved** | Transactional buffers keyed by `(producer_id, epoch, topic, partition)` must never allow stale-epoch commit. | Existing regression test `txn_commit_flushes_only_the_matching_epoch_dropping_stale` must pass unchanged. |
| **A4 — Offsets Store Isolation** | Consumer-group offsets (`FileOffsets`) remain globally consistent; no partition-lock coupling. | `kafka_groups_wire` test unchanged. |
| **A5 — Zero Behavioral Regression** | All existing wire/durability tests pass without modification. | `cargo test --workspace --release` green. |
| **A6 — Positive Scaling Measured** | Two producers on two partitions **exceed** single-producer throughput (not just match). | Interleaved A/B benchmark committed to `docs/BENCH-INDEPENDENT-2026-07-01.md`. |

---

## 2. COMPLETENESS CRITERIA (Definition of "Done" for the WP)

The WP is **complete** iff **ALL** hold:

| Criterion | Verification Method |
|---|---|
| **C1 — Code compiles** | `cargo build --release -p datarail-cli` |
| **C2 — Clippy pedantic clean** | `cargo clippy --workspace --all-targets -- -D warnings` |
| **C3 — All workspace tests pass** | `cargo test --workspace --release` (including integration: `kill9_crash`, `kafka_broker_wire`, `kafka_rebalance_wire`, `kafka_txn_wire`, `kafka_multipartition_wire`, `kafka_groups_wire`, `two_process`) |
| **C4 — New regression test added** | `per_partition_scaling` test in `crates/datarail-cli/tests/` proving positive scaling |
| **C5 — Benchmark evidence committed** | Interleaved A/B run (same host, same minute) showing `throughput_2partitions > throughput_1partition`; results appended to `docs/BENCH-INDEPENDENT-2026-07-01.md` |
| **C6 — No new unsafe** | `forbid(unsafe_code)` workspace charter holds |
| **C7 — Documentation updated** | `README.md` "Known limitations" reflects resolution; `CHANGELOG.md` entry for `v0.1.1` |

**Incomplete if any single criterion fails.** No partial credit.

---

## 3. SUCCESS CRITERIA (Outcome Metrics)

| Metric | Target | Measurement |
|---|---|---|
| **Throughput scaling** | 2 producers × 2 partitions ≥ 1.5× single-producer throughput | `kafka_broker_wire` style harness + `datarail_bench` loadgen; interleaved A/B |
| **Latency p99** | No regression vs baseline (single partition) | `datarail_bench` loadgen, same workload |
| **Memory** | ≤ baseline + 10% (no per-partition metadata bloat) | RSS tracking in bench |
| **Lock contention** | `Mutex` wait time < 5% of produce path | `perf` / `tokio-console` if available |
| **Test runtime** | No >20% increase in CI suite time | GitHub Actions timing |

---

## 4. DEFINITION OF DONE (DoD) — TechLead Verify Checklist (V1)

Each task in this WP must pass **all** before merge:

| Level | Check | Pass Condition |
|---|---|---|
| **L0 — Sanity** | Cold-check: commit exists, parent is baseline, no merge commits | `git log --oneline -1` |
| **L1 — Compile** | `cargo build --release -p datarail-cli` + all crates | Zero errors |
| **L2 — Lint** | `cargo clippy --workspace --all-targets -- -D warnings` | Zero warnings |
| **L3 — Unit tests** | All crate unit tests green | `cargo test --workspace --lib` |
| **L4 — Integration tests** | All `datarail-cli` integration tests green | `cargo test -p datarail-cli --release --test '*'` |
| **L5 — New test** | `per_partition_scaling` test passes | Added + green |
| **L6 — Benchmark** | A/B interleaved run committed to bench doc | PR to `docs/BENCH-INDEPENDENT-2026-07-01.md` |
| **L7 — Risk** | No new `unsafe`, no `#[allow]` on clippy, no `--no-verify` | Audit |
| **L8 — Docs** | `README.md`, `CHANGELOG.md` updated | Diff shows entries |

**Merge gate:** TechLead signs off on **all L0–L8**. No self-waiver.

---

## 5. INVARIANTS (Must Hold Throughout Execution)

| Invariant | Scope | Violation → Action |
|---|---|---|
| **I1 — Partition Isolation** | No code path acquires locks for >1 partition simultaneously | STOP → redesign |
| **I2 — Seq Uniqueness** | `reserve_seqs` never returns overlapping ranges across partitions | STOP → fix reservation logic |
| **I3 — Txn Atomicity** | `commit_txn` flushes only matching epoch; stale-epoch dropped | STOP → revert to working state |
| **I4 — Offsets Durability** | `OffsetCommit`/`OffsetFetch` fsync-before-ack unchanged | STOP → restore `FileOffsets` path |
| **I5 — No Global Lock** | Zero `Mutex<BrokerInner>` in hot path (produce/fetch/commit_txn) | STOP → remove it |
| **I6 — Deadlock Freedom** | Lock ordering: partition lock → offsets lock → txn lock (never reverse) | STOP → enforce ordering |

---

## 6. QUALITY STANDARDS (Engineering Bar)

| Standard | Enforcement |
|---|---|
| **Rust 2021, edition 2021, rust-version 1.90** | Workspace manifest |
| **Clippy `deny(all + pedantic)`** | CI gate |
| **`forbid(unsafe_code)`** | Compile-time (shmem waiver only) |
| **Conventional commits** | `fix(kafka):`, `perf(kafka):`, `test(kafka):` |
| **Regression test per fix** | Mandatory (techlead-verify L5) |
| **Real-wire tests over mocks** | `kafka_*_wire.rs` style; spawn real broker |
| **Honest claims** | Numbers from interleaved A/B; label manual vs automated |
| **Zero external dep creep** | No new crates without techlead approval |

---

## 7. WORK PACKAGE BREAKDOWN (Atomic, Disjoint, Sequential)

| Task | ID | Owner Files | Description | Depends On | Sweet-Spot Check |
|---|---|---|---|---|---|
| **T1** | `wp1-t1-scaffold` | `crates/datarail-cli/src/main.rs` | Define new `PartitionLockMap` type; extract per-partition state from `BrokerInner` | — | 1 file, ~50 LOC |
| **T2** | `wp1-t2-produce-path` | `crates/datarail-cli/src/main.rs` | Refactor `produce_into` → acquire partition lock only; move seal + append under partition lock | T1 | 1 file, ~80 LOC |
| **T3** | `wp1-t3-fetch-path` | `crates/datarail-cli/src/main.rs` | Refactor `fetch` → acquire partition lock only; un-seal under partition lock | T1 | 1 file, ~60 LOC |
| **T4** | `wp1-t4-bounds-path` | `crates/datarail-cli/src/main.rs` | Refactor `bounds` → partition lock only | T1 | 1 file, ~20 LOC |
| **T5** | `wp1-t5-txn-buffers` | `crates/datarail-cli/src/main.rs` | Refactor `buffer_txn`/`commit_txn`/`abort_txn` → per-partition txn buffers; epoch fencing preserved | T1 | 1 file, ~100 LOC |
| **T6** | `wp1-t6-offsets-store` | `crates/datarail-cli/src/main.rs` | Verify `commit_offset`/`fetch_offset` use `FileOffsets` directly (no partition lock coupling) | T1 | 1 file, ~30 LOC |
| **T7** | `wp1-t7-seq-reservation` | `crates/datarail-cli/src/main.rs` | Ensure `reserve_seqs` called under partition lock; preserve partition-local sequence namespaces | T2 | 1 file, ~20 LOC |
| **T8** | `wp1-t8-regression-test` | `crates/datarail-cli/tests/per_partition_scaling.rs` | New integration test: 2 producers × 2 partitions, measure positive scaling | T2–T7 | New file, ~150 LOC |
| **T9** | `wp1-t9-benchmark` | `docs/BENCH-INDEPENDENT-2026-07-01.md` | Run interleaved A/B (1 vs 2 partitions); append results | T8 green | Manual + doc |
| **T10** | `wp1-t10-docs` | `README.md`, `CHANGELOG.md` | Update "Known limitations" (remove global lock), add v0.1.1 entry | All green | 2 files |

**Total: 10 tasks, ~530 LOC changed + 150 LOC new test + bench doc.**

---

## 8. DEPENDENCY DAG & EXECUTION ORDER

```
T1 (scaffold)
  ├─→ T2 (produce)
  ├─→ T3 (fetch)
  ├─→ T4 (bounds)
  ├─→ T5 (txn buffers)
  ├─→ T6 (offsets)
  └─→ T7 (seq reservation)
        ↓
     T8 (regression test) → T9 (bench) → T10 (docs)
```

**Sequential execution required** — all tasks mutate `BrokerInner` / `KafkaBrokerStore` in `main.rs`. No disjoint file slices possible. Single agent, ordered.

---

## 9. CONFLICT MAP (Single File Mutant)

| File | Tasks Touching | Conflict Type | Resolution |
|---|---|---|---|
| `crates/datarail-cli/src/main.rs` | T1–T7 | **Sequential mutex** — all edit same struct/impl | Enforced order T1→T7; each task applies patch to fresh baseline |
| `crates/datarail-cli/tests/per_partition_scaling.rs` | T8 | New file | No conflict |
| `docs/BENCH-INDEPENDENT-2026-07-01.md` | T9 | Append-only | No conflict |
| `README.md`, `CHANGELOG.md` | T10 | Append-only | No conflict |

**No parallel fan-out possible.** The `Mutex<BrokerInner>` refactor is a single atomic mutation surface.

---

## 10. RISK ASSESSMENT & MITIGATION

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **R1 — Deadlock** (partition lock + offsets lock + txn lock ordering) | MEDIUM | HIGH (broker hang) | Enforce lock ordering: partition → offsets → txn; add `lock_order` test |
| **R2 — Seq collision** (overlap within one partition) | LOW | HIGH (data corruption) | Partition-local reservation test; cross-partition equal seqs are intentional |
| **R3 — Txn regression** (stale-epoch commit) | LOW | HIGH (correctness) | Existing test `txn_commit_flushes_only_the_matching_epoch_dropping_stale` is gate |
| **R4 — Performance regression** (lock overhead > gain) | LOW | MEDIUM | Benchmark after T2; if negative, STOP |
| **R5 — Test flakiness** (timing-dependent scaling test) | MEDIUM | MEDIUM | Run test 3× in CI; require 2/3 positive scaling |

**Hard stop triggers:** R1 or R2 or R3 failure → revert to baseline, re-plan.

---

## 11. RETURN SHAPE (What Each Task Produces)

Each task `T1–T7` returns a **compact card** (no transcript dump):

```
TASK: wp1-t{X}-{name}
STATUS: DONE | BLOCKED (reason)
FILES: [exact paths changed]
DIFF_STAT: +N/-M lines
TESTS_ADDED: [names] | NONE
TESTS_PASSED: cargo test -p datarail-cli --release --bin datarail <relevant> → OK
RISK_FLAGS: [none | deadlock-risk | seq-collision-risk | txn-regression-risk]
NEXT: wp1-t{X+1} | REVERT
```

Task `T8` returns:
```
TEST: per_partition_scaling
SCENARIO: 2 producers × 2 partitions, 10k msg each, 1KB
RESULT: p1_throughput=X MB/s, p2_throughput=Y MB/s, ratio=Y/X=Z
PASS: Z > 1.5
```

Task `T9` returns bench doc PR URL.

---

## 12. MERGE ORDER & SEAL

Since sequential, merge is linear: `T1 → T2 → ... → T10` as **single PR** (or stacked PRs if GitHub supports). Each task commits to a **feature branch** `wp1-per-partition-locking`.

**SEAL per task (techlead-loop):**
1. Verify L0–L8 on task commit
2. Run full workspace test suite
3. Tag task commit `wp1-t{X}-done`
4. Next task bases on it

**Final SEAL:** Single PR `wp1-per-partition-locking` → TechLead review → merge to `main` → tag `v0.1.1`.

---

## 13. CALIBRATION NOTES (For Future Waves)

| Learning | Application |
|---|---|
| Single-file hot-path refactor = sequential only | Don't attempt parallel on `BrokerInner` mutants |
| Property test for seq uniqueness caught 2 bugs in prior audit | Keep 1000-seed gate |
| Interleaved A/B on same host/minute = only trustworthy ratio | Document host state (CPU freq, thermal) in bench |
| `Mutex` → `RwLock` for read-heavy paths (fetch/bounds) | Consider for T3/T4 if contention shows |

---

## 14. AUTHORIZATION

This plan is **frozen**. Execution begins on TechLead `GO` signal.

```
TECHLEAD SIGN-OFF: ______________________________________
HUMAN OWNER WAIVER (if any): ____________________________
BASELINE SHA: 3cc5bb9ede3a9d7cffa9da516e3268473605cec7
PLAN VERSION: 1.0
DATE: 2026-09-10
```

---

**Next action:** Await `GO` to start `T1` (scaffold `PartitionLockMap`).
