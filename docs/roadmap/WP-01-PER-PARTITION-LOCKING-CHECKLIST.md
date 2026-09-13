# WP-01 Per-Partition Locking — ADVERSARIAL FIX CHECKLIST

**Status:** IMPLEMENTATION COMPLETE — release evidence and crash-atomic txn remain open
**Baseline:** `v0.1.0` (SHA: `3cc5bb9`)  
**Owner:** TechLead  
**Review Date:** 2026-09-12

---

## 🔴 FATAL FLAWS — Must Fix Before Any Code Change

### F1: `SourceTerminal::reserve_seqs` is GLOBAL ✅ **DONE**
- [x] **Root cause:** `reserve_seqs` in `datarail-terminal` crate takes no partition arg — single global counter
- [x] **Fix applied:** Option A — Added `reserve_seqs(partition_id, count)` to `SourceTerminal` with `HashMap<u64, u64>` per-partition seq space
- [x] **Gate:** All existing tests pass; `kill9_crash`, `kafka_multipartition_wire`, `kafka_txn_wire` green
- [x] **Owner:** Self (same workspace)

### F2: `DestTerminal::open` is SHARED ❌ **FALSE POSITIVE**
- [x] **Root cause:** Single `dst` field in `BrokerInner`; `open()` mutates DRBG state
- [x] **Reality:** `open(&self)` is thread-safe; DRBG only used in `SourceTerminal::board_at` (thread-local). No mutation in `open`.
- [x] **Verdict:** No fix needed.

### F3: `commit_txn` is CROSS-PARTITION
- [x] **Root cause:** `commit_txn` flushes enrolled partitions sequentially; a crash can expose a partial commit
- [x] **Fix required:** Add durable intent/commit protocol; lock ordering is already implemented
  - [x] Design lock ordering: deterministic partition order (e.g., sorted by `(topic, partition)`)
  - [x] Implement lock acquisition in order, release in reverse
  - [x] Verify no deadlock with reverse-order `commit_txn` + concurrent `produce` + `fetch`
  - [x] Preserve epoch fencing: stale-epoch dropped, matching epoch flushed; stale `EndTxn` completion fenced
  - [x] Restore unlanded buffer after pre-append commit failure
- [x] **Gate:** transaction wire test + reverse-order and 10k-op stress pass
- [x] **Risk:** HIGH — single-node crash/offset atomicity backed by process and journal-write fault matrix; Kafka marker/LSO remains out of scope

### F4: `FileOffsets` is SINGLE GLOBAL
- [ ] **Root cause:** One `Option<FileOffsets>` in `BrokerInner`; currently under global mutex
- [ ] **Fix required:** Extract `FileOffsets` into its own `Arc<RwLock<FileOffsets>>`
  - [ ] Change `commit_offset`/`fetch_offset` to take `&self` (not `&mut self`)
  - [ ] Verify `FileOffsets` is `Send + Sync` (check `datarail-offsets` crate)
  - [ ] Add dedicated lock for offsets store
- [ ] **Gate:** `kafka_groups_wire` test passes unchanged

### F5: `seal_batch` takes SHARED `&SourceTerminal` ❌ **FALSE POSITIVE**
- [x] **Root cause:** `seal_batch(&self.src, ...)` passes shared ref to parallel threads
- [x] **Reality:** `board_at(&self, ...)` is thread-safe; uses thread-local DRBG (`random_32()`), no shared mutable state.
- [x] **Verdict:** No fix needed.

---

## 🟡 HIDDEN COUPLINGS — Must Address in Redesign

| # | Coupling | Location | Fix Required |
|---|----------|----------|--------------|
| HC1 | `SourceTerminal` global seq counter | `datarail-terminal` crate | ✅ **F1 fix covers** — MT-1 done |
| HC2 | `DestTerminal` DRBG state | `datarail-terminal` crate | ❌ **FALSE POSITIVE** — no DRBG in `open` |
| HC3 | `commit_txn` cross-partition flush | `main.rs:1266-1277` | F3 fix covers |
| HC4 | `buffer_txn` reads partition log len | `main.rs` | ✅ Partition write lock |
| HC5 | `partition_log` lazy init race | `main.rs` | ✅ Partition-locked init |
| HC6 | `logs` HashMap lazy init | `main.rs` | ✅ Per-partition lock for map access |
| HC7 | `onboarding` contract (read-only) | `main.rs:1041` | No fix needed — immutable |
| HC8 | `data_dir` (read-only) | `main.rs:1045` | No fix needed — immutable |

---

## 🟢 MISSING TASKS — Add to Work Package Breakdown

### Terminal Refactor Tasks (datarail-terminal crate)
- [x] **MT-1** `SourceTerminal::reserve_seqs(partition_id, count)` — per-partition seq space (DONE)
- [ ] **MT-2** `DestTerminal::open` thread-safe (internal lock or per-thread DRBG) — **NOT NEEDED** (F2 false positive, `open` is already thread-safe)
- [x] **MT-3** Verify `SourceTerminal::board_at` thread-safe with shared ref — **DONE** (F5 false positive, `board_at` uses thread-local DRBG, no shared state)
- [x] **MT-4** Add `partition_id` to `board_at`/`board` for per-partition DRBG isolation — **NOT NEEDED** (DRBG is already thread-local)

### Core Locking Tasks (main.rs)
- [x] **CT-1** Design `PartitionLockMap` type (per-partition `RwLock<PartitionState>`)
- [x] **CT-2** Define `PartitionState` struct (what moves from `BrokerInner` per partition)
- [x] **CT-3** Field migration map: global vs per-partition (see below)
- [x] **CT-4** `produce_into` under partition write lock
- [x] **CT-5** `fetch` under partition read lock (`RwLock`)
- [x] **CT-6** `bounds` under partition read lock
- [x] **CT-7** `buffer_txn` under partition write lock
- [x] **CT-8** `commit_txn` with multi-partition lock ordering (deterministic)
- [x] **CT-9** `abort_txn` under partition write lock(s)
- [x] **CT-10** Extract `FileOffsets` → `Arc<RwLock<FileOffsets>>` + `&self` methods
- [x] **CT-11** Fix `partition_log` lazy init under partition lock
- [x] **CT-12** `seal_batch` thread-safety audit + fix if needed

### Field Migration Map (CT-3 Detail)

| Field | Current | New Location | Notes |
|-------|---------|--------------|-------|
| `src: SourceTerminal` | `BrokerInner` (global) | **Per-partition** or keep global with per-partition seq | MT-1/MT-2 |
| `dst: DestTerminal` | `BrokerInner` (global) | **Per-partition** or make `open` thread-safe | MT-2 |
| `onboarding: ContentContract` | `BrokerInner` (global) | **Global** (immutable) | No change |
| `logs: HashMap<(String,i32), SealedPartitionLog>` | `BrokerInner` (global) | **Per-partition** in `PartitionState` | CT-1 |
| `data_dir: PathBuf` | `BrokerInner` (global) | **Global** (immutable) | No change |
| `offsets: Option<FileOffsets>` | `BrokerInner` (global) | **Global** `Arc<RwLock<FileOffsets>>` | CT-10 |
| `txn_buffers: HashMap<...>` | `BrokerInner` (global) | **Per-partition** in `PartitionState` | CT-7/CT-8 |

### Test & Benchmark Tasks
- [x] **TB-1** Build multi-producer multi-partition correctness harness
- [ ] **TB-2** Build `datarail_bench` binary for throughput measurement (or extend existing)
- [x] **TB-3** Add `per_partition_scaling` integration test (2 producers × 2 partitions; correctness only)
- [x] **TB-4** Add reverse-order deadlock stress test for `commit_txn` + concurrent produce/fetch
- [ ] **TB-5** Add lock contention benchmark (if `perf` available)
- [x] **TB-6** Sequence reservation test: contiguous/non-overlapping ranges within each partition

### Documentation & Rollback Tasks
- [x] **DR-1** Add compile-time feature flag `per_partition_locking` to toggle old/new builds
- [ ] **DR-2** Staging branch strategy (not single PR) for incremental verification
- [x] **DR-3** Rollback procedure documented; per-task git tags still pending
- [x] **DR-4** Update `README.md` "Known limitations" with local-only scaling status
- [ ] **DR-5** `CHANGELOG.md` entry for `v0.1.1` (unreleased draft until gates pass)

---

## 📊 MEASUREMENT INFRASTRUCTURE — Must Build Before Success Criteria

| Metric | Infrastructure Needed | Status |
|--------|----------------------|--------|
| Throughput scaling | Multi-producer benchmark harness | ⚠️ Local harness exists; independent evidence missing |
| Lock contention < 5% | `perf` integration or `tokio-console` | ❌ Missing |
| Memory ≤ +10% | RSS tracking in bench | ❌ Missing |
| Positive scaling measured | Interleaved A/B harness | ⚠️ Local samples 1.154x–1.684x; high variance, not independent |
| Test runtime ≤ +20% | CI timing baseline | ⚠️ Baseline exists |

---

## 🔄 ROLLBACK SAFETY — Must Have Before Starting

- [x] **RB-1** Feature flag `per_partition_locking` (compile-time) to toggle implementations
- [ ] **RB-2** Git tag after each task: `wp1-t{X}-checkpoint`
- [ ] **RB-3** Staging branch `wp1-per-partition-locking` (not single PR)
- [ ] **RB-4** CI gate per task (compile + relevant tests)
- [x] **RB-5** Documented revert procedure in `docs/roadmap/WP-01-ROLLBACK.md`

---

## 🎯 SUCCESS CRITERIA — Redefine with Measurable Gates

| Criterion | New Measurable Target | Gate |
|-----------|----------------------|------|
| **Throughput scaling** | 2 producers × 2 partitions ≥ 1.5× single-partition baseline with 95% CI | TB-2 + independent A/B |
| **Latency p99** | No regression vs baseline (p99 diff < 5%) | TB-2 |
| **Memory** | RSS ≤ baseline + 10% (measured in bench) | TB-2 |
| **No deadlock** | 10k concurrent ops stress test passes | TB-4 |
| **All existing tests pass** | `cargo test --workspace --release` green | CT-1..CT-12 |
| **New regression test** | `per_partition_scaling` passes in CI | TB-3 |
| **Bench evidence** | Local A/B recorded separately; independent product benchmark remains required | DR-4 |

---

## 📋 EXECUTION ORDER (Revised Dependency DAG)

```
PHASE 0: Terminal Refactor (prerequisite)
  MT-1 → MT-2 → MT-3 → MT-4
       ↓
PHASE 1: Core Scaffold
  CT-1 (PartitionLockMap) → CT-2 (PartitionState) → CT-3 (Field Migration Map)
       ↓
PHASE 2: Path Refactors (sequential, same file)
  CT-4 (produce) → CT-5 (fetch) → CT-6 (bounds) → CT-7 (buffer_txn)
       ↓
PHASE 3: Complex Paths
  CT-8 (commit_txn multi-lock) → CT-9 (abort_txn) → CT-10 (FileOffsets) → CT-11 (partition_log init)
       ↓
PHASE 4: Audit
  CT-12 (seal_batch audit)
       ↓
PHASE 5: Tests & Benchmarks
  TB-1 → TB-2 → TB-3 → TB-4 → TB-5 → TB-6
       ↓
PHASE 6: Rollback & Docs
  DR-1 → DR-2 → DR-3 → DR-4 → DR-5
```

---

### Phase 0 Gate (Terminal Refactor) ✅ **COMPLETE**
- [x] MT-1 compiles, `reserve_seqs(partition_id, count)` works
- [ ] MT-2 compiles, concurrent `open` passes stress test — **NOT NEEDED** (F2 false positive)
- [x] MT-3 audit complete (board_at thread-safe — uses thread-local DRBG)
- [x] MT-4 DRBG per-partition isolation verified — **NOT NEEDED** (DRBG already thread-local)

### Phase 1 Gate (Scaffold)
- [x] CT-1 `PartitionLockMap` type defined + exercised by integration tests
- [x] CT-2 `PartitionState` struct defined with all per-partition fields
- [x] CT-3 Field migration map reviewed and implemented

### Phase 2 Gate (Path Refactors)
- [x] Each CT-4..CT-7 compiles + relevant tests pass
- [x] No clippy regressions
- [x] `kafka_broker_wire` test passes

### Phase 3 Gate (Complex Paths)
- [x] CT-8 `commit_txn` reverse-order + 10k-op lock stress passes
- [x] CT-10 `FileOffsets` extracted + `kafka_groups_wire` passes
- [x] CT-11 `partition_log` init race fixed

### Phase 4 Gate (Audit)
- [x] CT-12 `seal_batch` audit complete + round-trip test passes

### Phase 5 Gate (Tests & Benchmarks)
- [x] TB-1 harness runs 2 producers × 2 partitions
- [ ] TB-2 dedicated bench binary produces throughput numbers; ignored local harness exists
- [x] TB-3 `per_partition_scaling` test passes locally in default and rollback builds
- [x] TB-4 reverse-order + 10k-op deadlock stress passes
- [x] TB-6 per-partition sequence reservation test passes

### Phase 6 Gate (Rollback & Docs)
- [x] DR-1 feature flag works (old/new toggle)
- [ ] DR-2 staging branch merged via stacked PRs
- [ ] DR-5 `v0.1.1` tagged

---

## 🚫 HARD STOP TRIGGERS (Any = Full Revert)

| Trigger | Action |
|---------|--------|
| Any Phase 0 task fails | STOP — terminal refactor blocked |
| CT-8 deadlock detected | STOP — redesign commit protocol |
| Any existing integration test fails | STOP — revert to last checkpoint |
| Throughput regression > 10% | STOP — investigate before continue |
| `datarail-terminal` crate owner unavailable | STOP — cannot proceed without MT-1/MT-2 |

---

## 📝 TRACKING

| Item | Status | Notes |
|------|--------|-------|
| Adversarial review completed | ✅ | 2026-09-10 |
| Checklist created | ✅ | This file |
| Phase 0 started | ✅ | Self-executed (same workspace) |
| Phase 0 complete | ✅ | MT-1 done; MT-2/MT-4 not needed (false positives) |
| Phase 1 complete | ✅ | Implementation complete; full WP gate remains open |
| Phase 2 complete | ✅ | Paths compile and wire tests pass |
| Phase 3 complete | ⚠️ | Locking/stress pass; durable txn atomicity open |
| Phase 4 complete | ✅ | Seal audit and round-trip test pass |
| Phase 5 complete | ⚠️ | Correctness/stress/local A/B pass; independent/p99/RSS evidence open |
| Phase 6 complete | ⬜ | |
| `v0.1.1` released | ⬜ | |

---

## 📌 CLOSED ISSUE — ReplayLog Seek After Corruption

- `ReplayLog::replay_from` now resets framing when crossing segment boundaries.
- Regression covers prior-segment corruption plus exact seek into later intact data.
- `SealedPartitionLog::read_sealed_from` uses replay cursor again; no direct-read workaround remains.

---

**Next Action:** Execute canonical backlog in `docs/roadmap/ISSUES.md`; run
`.github/workflows/durability-linux.yml` on a runner exposing `dm-flakey`, then collect physical power-loss evidence.
