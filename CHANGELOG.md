# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Transaction Durability Foundation
- Durable CRC-32C transaction journal with `Prepare`, `Commit`, and `Abort` records
- Cross-partition transaction gate, participant rollback, offset snapshot/restore, and startup recovery
- Restart tests for committed records/offsets and unresolved intent rollback
- Deterministic in-process fault-point test covers main boundaries; process-level restart proof remains open

### Fixed — ReplayLog Corruption Handling
- **`read_sealed_from` now bypasses buggy `ReplayLog::replay_from` seek mechanism** — reads directly from segment files with manual seek + CRC-32C validation
- Corrupt frames (oversize length or CRC mismatch) now halt replay cleanly, matching `ReplayLog` semantics
- `fetch_halts_loud_at_a_corrupt_record_and_never_renumbers` test un-ignored and passing

### Added — Per-Partition Locking (WP-01 Phase 1 In Review)
- `PartitionLockMap` + `PartitionState` — per-partition `RwLock` eliminates global throughput serializer
- `produce_into`, `fetch`, `bounds`, `buffer_txn`, `commit_txn`, `abort_txn` all use per-partition locks
- `commit_txn` uses deterministic lock ordering (sort by `(topic, partition)`); reverse-order lock stress passes
- `FileOffsets` extracted to dedicated `Arc<RwLock<FileOffsets>>` — decoupled from partition locks
- `partition_log` lazy init fixed under partition lock (no global mutex race)
- `EndTxn` completion now carries `(producer_id, epoch)` — stale completions cannot reset newer transaction epochs
- Failed txn sealing restores unlanded buffers for retry; cross-partition crash atomicity remains explicitly unsupported
- Added ignored 10k-operation contention stress (default and rollback builds pass)
- Added per-partition sequence reservation regression test (1,000 reservations)
- `BatchTooLarge` now maps to non-retriable Kafka `MESSAGE_TOO_LARGE` (10), not storage error 56

### Changed — `abort_txn` Semantics
- Now uses per-partition locks with deterministic ordering (was global map lock)
- Only aborts specified partitions (was all partitions)
- Matches `commit_txn` lock ordering for consistency

### Changed — Known Limitations
- Per-partition lock scaffolding is present; throughput scaling remains unmeasured pending Phase 2 A/B evidence
- Cross-partition transaction commit is lock-ordered but not crash-atomic; Phase 1 remains blocked on failure-path evidence

## [0.1.0] - 2026-09-10

### Added — Rail Mode (Zero-Knowledge)
- `datarail run` — native sealed pipeline: file/HTTP sources → sealed rail → file/Postgres/webhook sinks
- `datarail send` / `datarail recv` — cross-process sealed transfer over TCP (loopback or cross-host)
- `datarail pair` — SPAKE2 short-code pairing + Noise_KK identity exchange (local rehearsal + remote)
- `datarail keygen` — Ed25519 signing identity + Noise_KK static keypairs
- Content contracts at onboarding/offloading (prefix, max length) with dead-lettering
- Effectively-once delivery within a process run (dedup on source key)
- Substrates: Loopback (in-process), TCP, POSIX Shared Memory, Object Store (S3-compatible FS), QUIC (dev cert)
- FASP delay-based congestion control with WAN/netem harness
- Merkle delivery proof (`datarail-manifest`) with `bao` chunk-resume — offline verifiable

### Added — Broker Mode (Provider-Blind Storage)
- `datarail kafka-broker` — bidirectional Kafka drop-in: unmodified producer writes, unmodified consumer reads back
- Sealed on produce, un-sealed on fetch — **on-disk log is ciphertext-only** (provider-blind)
- Durable sealed partition log (`SealedPartitionLog` over `ReplayLog`) with fsync-before-ack
- Restart survival verified: SIGKILL harness (4 rounds, every acked record at exact offset)
- Multi-partition (independent logs + offset spaces)
- Consumer groups: JoinGroup/SyncGroup/Heartbeat/LeaveGroup/OffsetCommit/OffsetFetch (durable)
- Transactional producers: buffered until EndTxn, successful commit visible, abort hidden, epoch-fenced; cross-partition crash atomicity unsupported
- TLS (server), mTLS (client cert), SASL/PLAIN auth — all CI-gated vs real librdkafka (kcat)
- Compressed producer batches (gzip/lz4/zstd/snappy, feature-gated) — decompress + seal
- CRC-32C validation on produce, correct CRC-32C on fetch (real consumers accept)

### Added — Kafka Ingest → Postgres
- `datarail kafka-ingest` — unmodified Kafka producer → sealed rail → Postgres/webhook/file
- **Exactly-once for idempotent producers**: dedup watermark keyed on `(producer_id, partition, sequence)` lands in same PG transaction as records
- At-least-once for non-idempotent producers (Kafka parity)

### Added — Exactly-Once Into Postgres (Tier A)
- `datarail run --source-file --sink-postgres` — append-ordered sources (file/replay/inline)
- Watermark stored transactionally in DB; replay/grow never double-lands
- `--at-least-once` opts out to plain COPY path

### Added — Connectors
- Hand-rolled Postgres wire protocol (zero dependencies) with **SCRAM-SHA-256** (RFC 7677 vectors tested)
- HTTP source (GET → newline-delimited records)
- Webhook sink (POST batches)
- File source/sink (line-delimited)

### Added — Replication Tier (Library Code, Not Wired Into CLI)
*Designed-ahead, fully tested, not exposed in the shipped binary — single-node is the honest scope for v0.1.0*
- `datarail-erasure` — RS(k,m) Reed-Solomon over GF(256), exhaustive C(k+m,m) loss pattern gates
- `datarail-blobstore` — `BlobStore` trait + `MemBlob` + `FsBlob` (percent-encode, temp-file+rename+fsync)
- `datarail-netblob` — TCP server/client for `BlobStore` (remote cold tier)
- `datarail-replication` — `ErasureStore` over any `BlobStore` (survives any m shard loss)
- `datarail-replicated-topic` — `Topic` + `ErasureStore` = produce→log+shard, reconstruct from shards
- `datarail-tieredlog` — Hot segment local, cold segments offloaded to `BlobStore`, local evicted (O(1 segment) disk)
- `datarail-keyrouter` — Consistent hashing, even spread, 0-reshuffle, churn ~1/N

### Added — Verification & Quality
- Workspace: `deny(all + pedantic)`, `forbid(unsafe_code)` (one waiver: `datarail-substrate-shmem`, 2 audited sites)
- CI gates: clippy + full test suite on every push
- Functional CI against real librdkafka: produce/consume/group/TLS/mTLS/SASL/compression
- Adversarial self-audit trail: `docs/design/ADVERSARIAL-AUDIT.md`, `docs/design/LASTRO-MATRIX.md`
- Independent benchmark reproduced by separate auditor: `docs/BENCH-INDEPENDENT-2026-07-01.md`

### Known Limitations (Honest Scope)
- **Single-node** — no replication, failover, or cross-node coordination
- **Per-partition broker locking** — implementation and local stress are present; independent scaling/p99/RSS evidence remains open (WP1-01)
- **Transactions not crash-atomic** — in-memory coordinator, durable txn log is future work (Issue #4)
- **Broker restarts at-least-once** for non-idempotent producers (dedup index not wired, Issue #6)
- **QUIC substrate** — dev cert only, client accepts any server cert (Issue #8)
- **No real key management** — `rail.toml` carries inline demo seeds (Issue #7)
- **Self-audited, not third-party audited** — "fuzz" = property tests, "chaos" = in-process fault injection

### Measured (Independent Benchmark, Real Binary)
| Metric | Value | Rigor |
|---|---|---|
| Cold start (median) | 3.0 ms | n=30, CI automated |
| Idle RSS | 3.3 MB | Independent auditor |
| Peak RSS (50k msg) | 9 MB | Independent auditor |
| Integrity | 50k produced → 50k consumed, zero loss, disk ciphertext-only | Auditor reproduced |
| Throughput/partition | ~6 MB/s (~6k msg/s) | First fix 2026-07-02, parallel seal ~2.5× |
| RAM vs Kafka (fsync) | ~72× less | OMB Run 12, n=3 manual dispatches |

[0.1.0]: https://github.com/HumanGuardrail/HuGR_Datarail/releases/tag/v0.1.0
