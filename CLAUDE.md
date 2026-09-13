# CLAUDE.md — working context for this repo

Read this first. It is the handoff so any Claude session (Claude Code, Cowork, etc.) starts oriented. The
source of truth is always the code + `docs/`; this file is the map and the conventions.

## What this is

**Datarail** — an end-to-end-sealed data rail (rail mode) and a Kafka-wire-compatible broker with
provider-blind storage (broker mode). Rust, 34 crates, single-node prototype. Positioned as a **portfolio /
capability-demonstration** project, not a product for sale — the honest verdict is that the "cheaper Kafka"
market is already won by S3-native players and E2E-encrypted streaming has weak market pull; the value here is
the engineering + the disciplined, self-audited process.

**Two trust models — never conflate them:**
- **Rail mode** (`datarail send/recv/run`): endpoints hold keys and seal; the pipe/storage see only ciphertext.
  This is the genuine zero-knowledge mode.
- **Broker mode** (`datarail kafka-broker`/`kafka-ingest`): the broker process holds all keys, seals on
  produce, un-seals on fetch. On-disk log is ciphertext-only = **provider-blind storage**, NOT zero-knowledge.

## The prime directive: honesty of claims

This repo's whole credibility rests on claims matching reality. Before writing any number or capability claim:
- Product numbers come from `docs/BENCH-INDEPENDENT-2026-07-01.md` (the real `kafka-broker` binary). The older
  `~72×` RAM / throughput-"tie" figures are **shim** measurements (`datarail-omb-shim`), a different object —
  always label them as such; never present them as broker properties.
- Vocabulary discipline: "self-audited" (not third-party audited); "property tests" (not coverage-guided
  fuzzing); "in-process fault injection" (not distributed chaos); "exactly-once" only for the idempotent-
  producer / append-ordered-Postgres paths (broker is at-least-once across restarts).
- If you soften or change a claim, update it everywhere (README, `docs/`, blog, SECURITY.md) in the same pass —
  drift between docs is the failure mode we keep fighting. `docs/design/LASTRO-MATRIX.md` grades every load-
  bearing number; `docs/design/ADVERSARIAL-AUDIT.md` records corrections.

## Layout

- `crates/datarail-kafka/` — Kafka wire protocol + broker serve loop (`serve.rs`, `produce.rs`, `codec.rs`,
  `consume.rs`, `groups.rs`, `coordinator.rs`, `txn.rs`).
- `crates/datarail-cli/` — the `datarail` binary; `main.rs` has `KafkaBrokerStore` (the global-`Mutex` broker,
  `produce_into`, the parallel `seal_batch`); `kafka_store.rs` is the durable sealed log. Integration tests in
  `tests/` (incl. `kill9_crash.rs`, `acks_wire.rs`, the `kafka_*_wire.rs` set).
- `crates/datarail-terminal/` — seal/open (`board`, `board_at`, `reserve_seqs`), the DRBG (reseed-on-fork /
  CRIU-snapshot safe), content contracts.
- `crates/datarail-connectors/` — hand-rolled HTTP + Postgres driver (now with SCRAM-SHA-256, RFC 7677-tested).
- `crates/datarail-manifest/` — the Merkle delivery proof (the extractable wedge; see blog 03).
- Designed-ahead but **NOT wired into the CLI**: `datarail-broker`, `-replicated-topic`, `-replication`,
  `-erasure`, `-tieredlog`, `-blobstore`, `-netblob`, `-keyrouter`. Single-node is a hard truth today.
- `docs/` — `PRODUCT.md`, `design/` (SPECs, audits, KAFKA-*.md), `blog/`, `roadmap/ISSUES.md`, the bench doc.
- `SECURITY.md`, `scripts/demo.sh` (the 60-second provider-blind proof), `docs/blog/demo.cast`.

## Conventions

- **Rust:** edition 2021, rust-version 1.90. Workspace lints: clippy `deny(all + pedantic)`,
  `forbid(unsafe_code)` (one waiver: `datarail-substrate-shmem`, two audited `unsafe` sites). Write pedantic-
  clean code (inline format args, `#[must_use]`, `# Errors` docs on public fallible fns). No new external deps
  without a strong reason — the project prides itself on a tiny dependency surface.
- **Commits:** conventional prefixes (`fix(kafka):`, `perf(...)`, `docs:`, `test(...)`, `chore:`). Bodies
  explain the *why* and cite the audit finding / bench when relevant. Keep the honest, specific voice.
- **Tests:** every fix ships a regression test. Prefer real-wire / real-binary tests over mocks where feasible
  (the `kafka_*_wire.rs` and `kill9_crash.rs` tests spawn the actual broker). Batch builders must stamp a real
  CRC-32C (`datarail_kafka::produce::crc32c`) — the broker validates it on produce.
- **Docs vocabulary is Portuguese by design:** cofre (sealed vault), etiqueta (envelope/header), lacre
  (signature seal), carga (ciphertext payload), lastro (reproducible evidence for a claim).

## Build / test notes (important for a fresh environment)

- `cargo build --release -p datarail-cli` builds the broker. `cargo test --release -p <crate>` for tests.
  Use `--release` — some suites are slow in debug, and it reuses the release cache.
- Live-service tests (`postgres_live.rs`, `kafka_eos_live.rs`) are `#[ignore]`d and need a real Postgres /
  docker harness — env-gated, not run in normal CI.
- CI (`.github/workflows/`) runs clippy + tests on push, plus functional smokes against **real librdkafka**
  (kcat) for the broker, TLS, mTLS, SASL, compression. Benchmark workflows are `workflow_dispatch`-only.
- Benchmarks on shared/cloud hosts drift a lot between sessions (~4.5× observed). Never compare absolute
  numbers across sessions — always interleave an A/B in the same run and report the ratio.

## What's next (canonical backlog: `docs/roadmap/ISSUES.md`)

1. **WP1 evidence/release decision** — implementation and local stress are done; independent A/B, p99/RSS, CI-scale
   evidence, and `v0.1.1` release gates remain.
2. **ReplayLog + power-loss durability** — core seek fix, persistent idempotent dedup, Docker cut harness, and manual
   Linux `dm-flakey` workflow landed; physical power-loss evidence remains.
3. **Durable transaction protocol** — journal/recovery/offset atomicity foundation, process-level kill-during-commit,
   and partial/complete journal-write proof landed; scope remains single-node.
4. **Real Kafka clients + key refs** — compatibility harness and env/file refs landed; run Java, franz-go, kafka-python,
   Sarama, librdkafka 2.x, real-client transactions, and add KMS integration.
5. **Security/architecture** — verified QUIC, standalone Merkle verifier, and owned receipt boundary landed; external crypto review, replication
   decision, verifier CLI/typed boundary, real FASP transport, and owner/external queue remain.

## Owner-reserved files

`docs/PRODUCT.md` and `docs/WORKING_BACKWARDS.md` are owner-reserved product-intent docs — change only with the
owner's sign-off (they carry STOP-THE-LINE notes). `docs/PLANO-PORTFOLIO.md` is gitignored scaffolding (a
behind-the-scenes plan) — do not surface it publicly.
