# Kafka Transaction Durability Contract

**Status:** foundation implemented; crash matrix and fault-injection proof pending.
**Scope:** single-node `datarail kafka-broker`; cross-partition records plus transactional offsets.

## Problem

Current path journals `Prepare`, flushes enrolled partition logs, applies offsets, then journals `Commit`. Recovery
rolls back an unresolved intent or verifies/reapplies a committed one. The wire test and local restart tests do not
prove crash atomicity; fault injection remains required.

## Required Invariants

- A transaction is either fully durable (all enrolled records and offsets) or fully absent after recovery.
- Records remain invisible to fetch until commit state is durable.
- An intent without commit is rolled back, including already-applied offsets.
- A durable commit without all participant data is a recovery error, never an implicit success.
- Stale `(producer_id, epoch)` cannot prepare, commit, abort, or recover a newer epoch.
- Journal, logs, and offset snapshots contain no plaintext cargo.
- Recovery completes before the broker accepts connections.
- Torn journal tails are ignored only after CRC validation; malformed committed state fails closed.

## Journal Format

Journal path: `<data-dir>/txn-journal.log`. Append-only, length-framed, CRC-32C protected records:

```text
magic:u32 | version:u16 | kind:u8 | payload_len:u32 | payload | crc32c:u32
```

`Prepare` payload contains `txn_id`, `transactional_id`, `producer_id`, `epoch`, every participant's topic,
partition, pre-commit byte end, pre-commit logical length, and every staged offset's before/after state.

`Commit` payload contains `txn_id`, a digest of the matching `Prepare`, every participant's post-commit byte/logical
end, and the staged offset after-values. Recovery uses these post-boundaries to prove every participant completed.

`Abort` payload contains `txn_id` and a digest of the matching `Prepare`.

Unknown versions, duplicate conflicting IDs, digest mismatches, and impossible positions fail closed. Journal
compaction is separate work and must preserve the last state for every unresolved transaction.

## Storage Contracts Required Before TXN Implementation

- `ReplayLog::truncate_to(byte_end)` removes later frames/segments, truncates the target segment, fsyncs the file and
  directory, and reopens the active handle with a matching `end_offset`.
- `SealedPartitionLog::truncate_to(byte_end, logical_len)` rebuilds its `starts` index and validates the result.
- `FileOffsets::restore_many(snapshot)` restores old values atomically through temp-file, fsync, rename, and directory
  fsync. `commit_many(values)` applies all after-values with the same durability boundary.
- All recovery methods are called while no broker listener exists and no reader can hold an old file handle.

## Commit Protocol

1. Acquire the transaction gate for exclusive visibility, then participant write locks in sorted `(topic, partition)`
   order.
2. Snapshot participant byte/logical ends and offset before-values.
3. Append and fsync `Prepare`.
4. Seal/append every buffered participant and fsync every participant log.
5. Apply and fsync all staged offsets through `commit_many`.
6. Append and fsync `Commit`.
7. Drop buffers, release locks, and answer `EndTxn` success.

The transaction gate also protects fetch visibility and offset reads. Normal non-transactional partition operations keep
their per-partition locks; the gate is held only for the transaction boundary, not for ordinary produce.

## Recovery Protocol

1. Open and scan the journal with bounded frame parsing and CRC validation.
2. For each `Prepare` without matching `Commit`/`Abort`, truncate every participant to its recorded pre-commit end and
   restore every offset before-value.
3. For each `Commit`, verify every participant reaches at least the recorded post-commit boundary; then reapply all
   offset after-values idempotently. Missing participant data is a hard recovery error.
4. For `Abort`, ensure participant data is at pre-commit boundaries and restore before-values.
5. Only after recovery succeeds, open the broker listener.

## Fault Matrix

Fault injection must stop the process after each of these points and restart on the same data directory:

- before and after `Prepare` append;
- after each participant append and fsync;
- after the last participant fsync;
- after each offset write and fsync;
- before and after `Commit` append and fsync;
- after recovery truncation and offset restore.

Expected result: all records plus all offsets, or no records plus old offsets. Retry of the same transaction is
idempotent. A successful wire test without this matrix is not a crash-atomicity proof.

The unit test injects panics at these boundaries and reopens the data directory after unwinding. The real-binary
`kafka_txn_wire` harness now aborts and restarts the process at each post-fsync boundary (points 1 through 5), proving
record and staged-offset all-or-none recovery there. It does not cover ambiguous `fsync`/partial-journal-write outcomes.

## Explicit Non-Goals

- Multi-node transaction coordination.
- Kafka-faithful marker/LSO semantics.
- Concurrent transactions on one partition.
- Release claim before external fault-injection evidence.
