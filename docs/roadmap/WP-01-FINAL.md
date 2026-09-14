# WP-01 — FINAL STATE (v0.1.1 Ready)

**Commit:** `d0895c1`
**Baseline:** `3cc5bb9` (v0.1.0)
**Date:** 2026-09-10

**Superseded:** canonical status is `docs/roadmap/ISSUES.md`; follow-up commits `183e9e0` and `78acd59` landed after
this snapshot.

---

## FASE 0: COMPLETE ✅

- `SourceTerminal::reserve_seqs(partition_id: u64, n: u64)` — per-partition seq space (`HashMap<u64,u64>`)
- `KafkaBrokerStore`: `RwLock` per-partition (`PartitionLockMap`), `Arc<RwLock<FileOffsets>>` for offsets
- `produce_into`: uses `with_write_partition`, `reserve_seqs(partition_id, ...)`
- Clippy workspace clean (`deny(all+pedantic)`)

---

## BUG REAL: REPLAYLOG (`replay_from` seek) CLOSED

- `ReplayLog::refill` now clears stale partial-frame bytes before opening the next segment.
- Regression covers prior corruption plus exact seek into later intact data.
- `SealedPartitionLog::read_sealed_from` uses corrected `ReplayLog::replay_from`; no direct-read workaround remains.

---

## TEST STATUS

| Teste | Status | Notas |
|-------|--------|-------|
| `kill9_crash` | ✅ PASS | SIGKILL 4 rounds, todos offsets exatos |
| `kafka_broker_wire` | ✅ PASS | Real broker, produce/fetch/restart |
| `kafka_txn_wire` | ✅ PASS | Commit atomico 2 particoes |
| `kafka_groups_wire` | ✅ PASS | OffsetCommit/Fetch restart |
| `kafka_multipartition_wire` | ✅ PASS | 3 particoes |
| `kafka_replay_wire` | ✅ PASS | Replay + grow |
| `two_process` | ✅ PASS | TCP + Noise_KK |
| `fetch_halts_loud` | ✅ PASS | Corruption remains loud; offsets do not renumber |
| `fasp_s2` | ❌ IGNORED | FASP timeout flakiness CI |

---

## NEXT PHASE (HISTORICAL)

**Fase 1 (CT-1..CT-12): `PartitionLockMap` + `PartitionState` + per-partition `RwLock` para `produce`, `fetch`, `txn_buffers`**
- Blocked by replaylog bug fix (storage-layer real fix required)
- Checklist frozen: `docs/roadmap/WP-01-PER-PARTITION-LOCKING-CHECKLIST.md` (245 linhas, gates L0-L8)
- Plan superseded: `WP-01-PER-PARTITION-LOCKING.md` (REJECTED, adversarial audit found 5 fatal flaws)

---

**DECISAO SUPERSEDED:**
A: Continuar Fase 1 (scaffold `PartitionLockMap` — replaylog bug nao bloqueia locking)
B: Fixar replaylog primeiro (redesign `replay_from` seek — storage-layer fix)
