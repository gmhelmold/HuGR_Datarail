# KAFKA-TXN-DESIGN — transactional producer EOS (bounded buffer model)

> **STATUS: BUILT + SINGLE-NODE CRASH-ATOMIC (2026-09-13).** `datarail kafka-broker` serves the transactional producer
> APIs (`InitProducerId(transactional_id)` with epoch fencing, `AddPartitionsToTxn`, `AddOffsetsToTxn`,
> `TxnOffsetCommit`, `EndTxn`) on the **buffer-until-commit** model: a transactional batch is FENCED against the
> coordinator (`produce_check`: epoch + partition-claim) then BUFFERED (keyed by `(producer_id, epoch, topic,
> partition)`), invisible until successful `EndTxn(commit)` flushes each enrolled partition to the durable sealed log
> in deterministic order under the durable transaction journal /
> `EndTxn(abort)` discards it. PROVEN: `txn.rs` unit tests (epoch fencing, one-txn-per-partition, produce_check,
> commit/abort) + `kafka_txn_wire.rs` (full binary: buffered→invisible; successful commit→visible across 2 partitions;
> abort→hidden; **a stale-epoch zombie is NEVER committed**) + the store epoch-scoped-commit regression.
> **AUDITED (`CORE-AUDIT.md` §Kafka-TXN): a brutal 4-Opus pass found 3 EOS breaks (unfenced produce / re-init
> orphan / swallowed commit failure) — surfaced and retryable; a confirming re-audit verified them + found 1
> TOCTOU (the `produce_check`/`buffer_txn` two-lock seam) — FIXED (epoch in the buffer key).** The codec is
> parse-safe + charter-clean; provider-blind holds (buffered plaintext is sealed before it ever hits disk).
> **HONEST SCOPE:** correct for **one producer per partition during a txn** (concurrent same-partition → retriable
> `CONCURRENT_TRANSACTIONS`); `read_uncommitted` behaves like `read_committed`; unresolved journal intents roll back
> during startup recovery; single-node cross-partition crash atomicity is backed by the fault matrix and journal-write
> cuts. This is not Kafka's faithful marker/LSO model or multi-node transaction coordination.
> The faithful marker/LSO model (marker semantics, concurrent same-partition txns + a true `read_uncommitted`) is
> tracked future work.
>
> **(build history below — Q1–Q4 RATIFIED BY THE TECHLEAD.)**
> The owner re-armed the autonomous loop rather than answer Q1–Q4, so per the standing "decide+execute, don't ask
> which-option" directive I ratify them with the recommendations below and build incrementally (each step green +
> the whole tier audited before any exactly-once claim is made — the delicate semantics are managed by the audit,
> not by deferring). RATIFICATIONS: **Q1 = (a)** control COMMIT/ABORT markers are stored as a distinct **un-sealed
> control record** (they carry no secret payload — pure txn-control metadata, like offsets/etiqueta already are →
> provider-blind preserved). **Q2 = (a)** `read_committed` is **edge-filtered** by us (we are the authoritative
> coordinator → return only committed records + a correct LSO + an empty aborted-list; wire-compatible with a
> `read_committed` client, and we never ship aborted plaintext). **Q3 = abort-on-restart** for in-memory pre-prepare
> state; durable participant intents now recover from the transaction journal. The single-node crash proof is backed
> by the process and journal-write fault matrix; Kafka marker/LSO fidelity remains open.
> **Q4 = IN SCOPE, build now.** Build order: TxnCoordinator (state machine + epoch fencing, unit-tested) → codec →
> serve wiring → store markers + LSO → `read_committed` Fetch → wire test → brutal audit.
>
> **(original frozen design below.)**
> Historical proposal: the idempotent producer EOS (per-partition exactly-once within a session) is already shipped + proven
> (`KAFKA-EOS-DESIGN.md`). This proposed TRANSACTIONAL tier adds atomic multi-partition writes + consumer-offsets-in-
> the-transaction + `read_committed` consumers. It is the **hardest** Kafka feature (a transaction coordinator with
> epoch fencing, two-phase-commit control markers in the durable log, and `read_committed` isolation), so it is
> frozen as a design first — and because it raises **provider-blind design questions only the owner should rule on**
> (below), it is explicitly held for ratification rather than built unattended.

## Why this is held for the owner (the rigor-compact reason)
Transactional EOS semantics are unforgiving: a subtly-wrong abort/commit boundary silently breaks exactly-once —
the exact failure the owner most wants to avoid. And it forces a **provider-blind** decision (how control markers
live in a sealed store) that is a product call, not a mechanical one. Shipping it half-right unattended would be a
claim larger than its proof. So: design now, ratify + build with the owner in the loop.

## Protocol surface (what a transactional producer drives)
- **`InitProducerId` (22) WITH a `transactional_id`** — today we hand out a bare `producer_id` (idempotent). The
  transactional path must: look up/create the txn state for `transactional_id`, **bump the producer epoch** (fencing
  any prior incarnation), abort any in-flight txn from a previous epoch, and return `(producer_id, epoch)`.
- **`AddPartitionsToTxn` (24)** — register the `(topic, partition)`s a txn will write to (so the coordinator knows
  where to write commit/abort markers at `EndTxn`).
- **`AddOffsetsToTxn` (25)** + **`TxnOffsetCommit` (28)** — fold consumer-group offset commits INTO the txn
  (consume-process-produce atomicity) — they become visible only on commit.
- **`EndTxn` (26)** — commit or abort: write a **control batch** (COMMIT/ABORT marker) to every registered
  partition; on commit, the txn's records + offsets become visible.
- **Fetch `read_committed`** — a `read_committed` consumer must receive only committed records: the Fetch response
  carries the **Last Stable Offset (LSO)** and the **aborted-transactions list**; the consumer (or we) filter out
  aborted records. (`read_uncommitted` consumers — the current behavior — see everything.)

## Coordinator state (extends the group `coordinator.rs` pattern)
A `TxnCoordinator` keyed by `transactional_id`: `{ producer_id, epoch, state: Empty|Ongoing|PrepareCommit|
PrepareAbort|CompleteCommit|CompleteAbort, partitions: Set<(topic,partition)>, pending_offsets }`, behind a Mutex.
Epoch fencing: a Produce/EndTxn at a stale epoch is rejected (`INVALID_PRODUCER_EPOCH`). Like the group coordinator,
txn state is runtime (a crash aborts in-flight txns) UNLESS we persist it — see open question Q3.

## OPEN QUESTIONS for the owner (ratify before build)
- **Q1 — provider-blind control markers.** Kafka writes COMMIT/ABORT control batches into the partition log. In
  datarail the log holds **sealed cofres**. Options: (a) store markers as a distinct un-sealed control record type
  (markers carry no payload, only txn metadata — arguably fine to leave un-sealed); (b) seal the markers too
  (uniform, but they have no secret payload). Recommendation: **(a)** — markers are metadata, not cargo; keep them
  out of the sealed path. Owner ruling needed (it touches the provider-blind invariant's surface).
- **Q2 — `read_committed` filtering locus.** Filter aborted records (a) at our Fetch edge (we hold the txn state →
  return only committed records + a correct LSO), or (b) the Kafka-faithful way (return everything + LSO + aborted
  list, let the client filter). (a) is simpler + keeps us authoritative; (b) is wire-faithful. Recommendation:
  **(b)** for drop-in fidelity, **(a)** acceptable as a first cut. Owner ruling.
- **Q3 — durability of txn state.** Persist `TxnCoordinator` state (like `FileOffsets`) so a broker restart
  resumes in-flight txns, or accept "a broker restart aborts in-flight txns" (simpler, and a producer retries)?
  Recommendation: **accept abort-on-restart** for v1 of this tier (documented), persist later.
- **Q4 — scope.** Is the transactional tier even in scope for v1, or post-v1? The idempotent tier already gives
  per-partition exactly-once (the common case). This is the niche atomic-multi-partition / consume-transform-
  produce case. Owner call on priority.

## Honest scope / non-goals (proposed)
- Target the non-flexible versions of each API where possible; single-node coordinator.
- v1 of this tier: abort-on-broker-restart (Q3); `read_committed` filtering per the Q2 ruling.
- NOT: cross-broker txn coordination, exactly-once across a multi-node cluster.

## Steps 5–6 design decision (the delicate isolation core) — DECIDED 2026-06-28, SCOPE CORRECTED 2026-09-12
First decided as the full marker/LSO model; **revised to buffer-until-commit after a deeper analysis of the
implementation surface.** The rigor compact (correctness paramount; never ship subtly-wrong EOS) drove the change:
- **Full marker / LSO model (revised away).** Faithful Kafka — interleaved durable records + un-sealed COMMIT/ABORT
  markers, a durable per-partition txn-range journal, restart recovery rebuilding ranges, LSO computation, and
  `read_committed` edge-filtering. **But** that is ~5 delicate, interlocking pieces (durable per-record txn metadata,
  resolution journal, recovery, LSO, fetch filtering) — a large correctness surface where an UNATTENDED build is
  too likely to introduce a subtle exactly-once bug. Tracked as a future enhancement (it alone enables concurrent
  same-partition txns + a faithful `read_uncommitted`).
- **Buffer-until-commit (CHOSEN).** Hold a transaction's records in memory (per `producer_id`/partition); flush them
  to the durable sealed log only on `EndTxn(commit)`, **discard on abort**. The durable log then holds only records
  from successful or partially completed commits. Aborted records never become durable, but a crash during a
  cross-partition flush can leave some committed records and lose the rest. No markers, no LSO, no journal, no
  recovery surgery, no storage-format change, `Fetch` unchanged. Proven guarantees: pre-commit invisibility,
  post-success visibility, abort invisibility, epoch fencing, and retry preservation for unlanded buffers.
- **HONEST SCOPE (the trade-off, documented not hidden):** correct when **each partition has a single concurrent
  producer during an open txn**. Concurrent writers to a partition mid-txn would conflict on provisional offsets →
  rejected with a retriable `CONCURRENT_TRANSACTIONS` (the producer retries after the first commits), enforced by
  the coordinator claiming a partition for one open txn at a time. `read_uncommitted` behaves like `read_committed`
  (stricter, safe). For a single-node broker this is a reasonable, honest limitation; the faithful marker model
  lifts it later.
- **Implementation shape:** `KafkaBroker` gains `buffer_txn(producer_id, topic, partition, records) -> base` +
  `commit_txn(producer_id, partitions)` + `abort_txn(producer_id, partitions)` (default no-ops); the produce path
  routes a transactional batch (attributes bit `0x10`, carried on `EosCoord.transactional`) to `buffer_txn`; the
  coordinator claims partitions (one open txn each) and `EndTxn` drives commit/abort. `Fetch` is unchanged.

## Build plan (once ratified — each step tested + audited, like every prior increment)
1. **This doc + owner ratification of Q1–Q4.**
2. `txn.rs`: the `TxnCoordinator` state machine + epoch fencing (unit-tested, no wire).
3. Codec: `InitProducerId` (transactional_id), `AddPartitionsToTxn`, `AddOffsetsToTxn`, `TxnOffsetCommit`,
   `EndTxn` + control-batch (marker) build/parse; ApiVersions advertises them.
4. `serve_broker` wiring; the marker write per Q1; the txn-aware produce (epoch fence) + EndTxn.
5. `read_committed` Fetch (LSO + aborted list / edge-filter per Q2).
6. **Wire test:** a transactional producer writes to 2 partitions + commits → a `read_committed` consumer sees
   both after successful `EndTxn`; an aborted txn → the consumer sees neither.
7. **Brutal adversarial audit** (epoch-fencing races, abort/commit boundary correctness, the provider-blind
   marker decision, `read_committed` leak of aborted records).
