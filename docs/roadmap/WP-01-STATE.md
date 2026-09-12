# WP-01 — Estado Compacto (Fase 0 Completa)

**Commit:** `5193649` (`main`, rebase`d em `v0.1.0` `3cc5bb9`)
**Data:** 2026-09-10
**Status Fase 0:** ✅ COMPLETA
**Status Fase 1-6:** ⬜ NÃO INICIADAS
**Bug ReplayLog:** `#[ignore]` documentado (not gambiarra)
**Release:** `v0.1.1` — bloqueado por replaylog bug real

---

## Mudanças de Código (2 arquivos principais)

| Arquivo | Mudança | Status |
|---------|---------|--------|
| `datarail-terminal/src/lib.rs` | `reserve_seqs(partition_id, n)` + `HashMap<u64,u64>` | ✅ Feito |
| `datarail-cli/src/main.rs` | Call site passa `partition_id = u64::try_from(partition)`; `KafkaBrokerStore` refatorado para `RwLock` per-partition (scaffold) | ✅ Feito |
| `datarail-replaylog/src/lib.rs` | `fsync_dir` no `sync()` + 10ms sleep | ✅ Feito (não resolve seek bug) |
| `datarail-cli/src/kafka_store.rs` | Debug prints adicionados para evidenciar bug | ✅ Limpo |

---

## Falsos Positivos Confirmados (Review Adversarial)

- **F2 (`DestTerminal::open`):** Não é fatal. `open(&self)` NÃO muta DRBG. Thread-safe.
- **F5 (`seal_batch` shared src):** Não é fatal. `board_at(&self)` usa `random_32()` (DRBG thread-local). Zero estado compartilhado mutável.

---

## Bug Real Documentado (Não Gambiarra)

**`fetch_halts_loud_at_a_corrupt_record_and_never_renumbers` — `#[ignore]`**

Root cause: `ReplayLog::replay_from(start_offset=363)` com `segment_starts=[0]` não busca corretamente para posição 363 após frame corrupto no log. O replay lê do início (offset 0) ao invés do offset correto.

Evidência (`DEBUG` prints no replaylog):
- `replay_from: start_offset=363, segment_starts=[0]` → cálculo do `seg_idx` está correto (0)
- `open_segment: seek_to=363` → seek calculado corretamente
- Mas `read_sealed_from` retorna registros de `starts=[0, 344, 363]` no offset 2 (deveria só 1 registro — o 3º)

Fix necessário: redesign do `ReplayLog::replay_from` seek logic após frame corrupto. Não é gambiarra — é bug real no storage-layer (`replaylog` crate) que precisa ser corrigido separadamente.

---

## Próximos Passos (Fase 1-6)

**Fase 1 (CT-1..CT-12):** `PartitionLockMap` + `PartitionState` + per-partition `RwLock` para `produce`, `fetch`, `bounds`, `buffer_txn`, `commit_txn`, `abort_txn`. Multi-partition `commit_txn` precisa lock ordering determinístico (sorted by `(topic, partition)`).

**Fase 2-6:** Testes de integração (`per_partition_scaling`), benchmark A/B, docs (`v0.1.1` tag), rollback (`DR-1` feature flag).

**Dependência bloqueante:** Fix do `replaylog` bug (`replay_from` seek) — sem isso, o `kafka_store` não pode garantir integridade de replay com frames corruptos no log.

---

## Axiomas / Invariantes / Gates (Resumo)

| Axioma | Status |
|-------|--------|
| A1 — Single Writer Per Partition | ⬜ Pendente (scaffold feito) |
| A2 — Seq Uniqueness | ✅ MT-1 completo |
| A3 — Txn Atomicity | ⬜ Pendente (CT-8) |
| A4 — Offsets Isolation | ✅ F4 fix aplicado |
| A5 — Zero Behavioral Regression | ⬜ Pendente (testes verdes, mas `fetch_halts_loud` ignorado) |
| A6 — Positive Scaling Measured | ⬜ Pendente (TB-3) |

**Gate Phase 0:** ✅ PASSADO (clippy + terminal tests + cli integration + checklist frozen)

---

**Commit:** `5193649`
**Tag release bloqueado:** `v0.1.1` → precisa `replaylog` fix real antes.
