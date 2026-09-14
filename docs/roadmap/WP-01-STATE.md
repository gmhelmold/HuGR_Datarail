# WP-01 — Estado Compacto (Fase 1 em revisão)

**Base:** `v0.1.0` (`3cc5bb9`); current branch `test/durability-linux-evidence`
**Data:** 2026-09-10
**Status Fase 0:** ✅ COMPLETA
**Status Fase 1:** ⚠️ locking implementado; evidência independente e power-loss físico pendentes
**Bug ReplayLog:** corrigido em `ReplayLog`, teste de corrupção ativo
**Release:** `v0.1.1` — bloqueado por evidência WP1 e `DUR-01` físico

---

## Mudanças de Código (2 arquivos principais)

| Arquivo | Mudança | Status |
|---------|---------|--------|
| `datarail-terminal/src/lib.rs` | `reserve_seqs(partition_id, n)` + `HashMap<u64,u64>` | ✅ Feito |
| `datarail-cli/src/main.rs` | Call site passa `partition_id = u64::try_from(partition)`; `KafkaBrokerStore` refatorado para `RwLock` per-partition (scaffold) | ✅ Feito |
| `datarail-replaylog/src/lib.rs` | `fsync_dir` no `sync()` + correção de framing ao trocar segmento | ✅ Feito |
| `datarail-cli/src/kafka_store.rs` | `read_sealed_from` usa `ReplayLog::replay_from` corrigido | ✅ Feito |

---

## Falsos Positivos Confirmados (Review Adversarial)

- **F2 (`DestTerminal::open`):** Não é fatal. `open(&self)` NÃO muta DRBG. Thread-safe.
- **F5 (`seal_batch` shared src):** Não é fatal. `board_at(&self)` usa `random_32()` (DRBG thread-local). Zero estado compartilhado mutável.

---

## Bug Real Documentado (Não Gambiarra)

**`fetch_halts_loud_at_a_corrupt_record_and_never_renumbers`**

Root cause: `ReplayLog::replay_from(start_offset=363)` com `segment_starts=[0]` não busca corretamente para posição 363 após frame corrupto no log. O replay lê do início (offset 0) ao invés do offset correto.

Evidência (`DEBUG` prints no replaylog):
- `replay_from: start_offset=363, segment_starts=[0]` → cálculo do `seg_idx` está correto (0)
- `open_segment: seek_to=363` → seek calculado corretamente
- Mas `read_sealed_from` retorna registros de `starts=[0, 344, 363]` no offset 2 (deveria só 1 registro — o 3º)

Correção: `ReplayLog::refill` limpa bytes de frame parcial antes de abrir o segmento seguinte. Regressão cobre seek
exato em dados íntegros depois de corrupção anterior.

---

## Próximos Passos (Fase 1-6)

**Fase 1:** `PartitionLockMap` + `PartitionState` implementados; abort, retry de commit, lazy-init, sequência por
partição e fencing de epoch corrigidos; buffer não-lançado é restaurado após falha de commit. Stress de 10k ops passa.
Atomicidade crash cross-partition single-node agora coberta por fault matrix e cortes de escrita do journal.

**Próximos:** seguir backlog canônico em `docs/roadmap/ISSUES.md`; primeiro `DUR-01` e evidência WP1.

**Dependências bloqueantes:** power-loss evidence e WP1 release evidence. `STOR-01` core e `TXN-01` single-node estão
fechados; `DUR-01` ainda exige fsync/rename reorder + directory-entry-loss harness.

---

## Axiomas / Invariantes / Gates (Resumo)

| Axioma | Status |
|-------|--------|
| A1 — Single Writer Per Partition | ✅ Lock por partição; sequência reservada por partição |
| A2 — Seq Uniqueness | ✅ Contiguous/non-overlapping per-partition ranges tested; namespaces intentionally independent |
| A3 — Txn Atomicity | ✅ Single-node cross-partition commit + offsets cobertos por fault matrix e recovery determinístico |
| A4 — Offsets Isolation | ✅ F4 fix applied (separate `OffsetsStore` lock) |
| A5 — Zero Behavioral Regression | ✅ Testes + mutation probe + stress de 10k ops verdes |
| A6 — Positive Scaling Measured | ⚠️ Local default samples 1.154x–1.684x; independent/CI/RSS evidence pending |

**Gate Phase 0:** ✅ PASSADO (clippy + terminal tests + cli integration + checklist frozen)

**Gate Phase 1:** ⬜ NÃO PASSADO (correções e evidência pendentes)

---

**Commit:** working tree (revisão em andamento)
**Tag release:** `v0.1.1` bloqueado até gates passarem
