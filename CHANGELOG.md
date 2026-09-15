# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-15

### Added — Storage Primitives (WP-01)
- `ReplayLog`: corruption-aware replay + safe truncation/reopen (`replay_from`, `truncate_to`)
- `FileOffsets`: partial-tail repair, batch snapshot/restore, compaction-safe watermark
- `DurableLog` (WAL): fail-closed on ambiguous `fsync`/`dir-fsync`, poison after ambiguous write, ack preservation on failed dir-fsync
- Standalone WAL durability probe (`datarail-substrate-wal` example) for fault-injection evidence
- `Terminal`: per-partition sequence allocation, streaming landed-state drain

### Added — Kafka Broker Hardening
- `GroupCoordinator`: member registration extracted, rebalance semantics preserved, generation bump + deadline management
- Wire layer: record parsing hardened, bounded reads, compression rejection, CRC-32C validation
- Groups/SASL: request validation tightened, auth paths verified
- Transactional wire dispatch: `TxnCoordinator` API aligned with serve loop, stale `finish_txn` rejected, `MESSAGE_TOO_LARGE` (10) error mapping, handler extraction for clippy compliance

### Added — Transport Security
- Crypto: AEAD round-trip, HMAC determinism, X25519 key-wrap
- Identity: Noise_KK handshake, SPAKE2 pairing, impostor rejection
- Rail: FASP bounded retry loop (CI stability), oversized-frame rejection gate (AUDIT-03 F1)

### Added — Spec / Compatibility
- Spec: external key references (`env:`, `file:`) with malformed-fail-closed
- QUIC: server cert verification (wrong-CA/hostname rejection), dev/prod API split
- Manifest: standalone receipt verifier (`verify_receipt`), tree-size binding, external verifier test
- Compat matrix: real-client harness (Java, franz-go, kafka-python, Sarama, librdkafka 2.x)

### Added — Connectors / Substrates / Bench
- Connectors: HTTP source hardening, SCRAM-SHA-256 RFC 7677 vectors, Postgres/webhook sink hardening
- Acceptance: blobstore, erasure, keyrouter, netblob, replication, shmem, objectstore, tieredlog, topic substrates
- Bench/stress: broker restart survival, Fuzz 13 adversarial tests, Once persist/dedup, Stress UC1-5, System chaos/e2e, OMB shim roundtrip, Bench fairness

### Added — Docs / Roadmap
- Durability design updates (`DURABLE-LOG.md`, `KAFKA-TXN-DURABILITY.md`)
- Manifest verifier design (`MANIFEST-VERIFIER.md`)
- WP-01 roadmap artifacts: checklist (F1-F4), rejected locking plan, rollback, state, local bench, final snapshot
- Linux `dm-flakey` evidence workflow + `durability-device-mapper.sh` script

### Fixed
- `ReplayLog` recovery seek after corruption
- `FileOffsets` partial-tail truncation on reopen
- WAL: ambiguous `fsync` → fail-closed, poison propagation, ack restoration
- `Terminal`: per-partition sequence allocation, streaming drain
- Kafka coordinator: stale epoch fence, member registration
- Wire: CRC-32C validation, bounded reads, compression rejection
- Transaction: stale `finish_txn` rejection, error code 10 mapping
- Terminal: oversized frame rejection
- Connectors: SCRAM-SHA-256 vectors, Postgres sink hardening

### Known Limitations (Honest Scope)
- **Single-node** — no replication, failover, or cross-node coordination
- **Global broker lock** — per-batch seal parallelized (~2.5×), but `Mutex<BrokerInner>` serializes across partitions
- **Transactions not crash-atomic** — in-memory coordinator, durable txn log is future work
- **Broker restarts at-least-once** for non-idempotent producers (dedup index not wired)
- **QUIC substrate** — dev cert only, client accepts any server cert
- **No real key management** — `rail.toml` carries inline demo seeds
- **Self-audited, not third-party audited** — "fuzz" = property tests, "chaos" = in-process fault injection
- **DUR-01 physical evidence** — `dm-flakey` evidence pending self-hosted Linux runner

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
- Transactional producers: buffered until EndTxn, commit visible atomically, abort hidden, epoch-fenced
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
- **Global broker lock** — per-batch seal parallelized (~2.5×), but `Mutex<BrokerInner>` serializes across partitions (Issue #1)
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
