# Backlog Canonico

Fonte unica para trabalho aberto. Revisado em 2026-09-12. Documentos antigos podem citar numeros ou planos
superados; este arquivo define status atual. `Done` nao e backlog ativo.

## P0 - correctness and ship blockers

### TXN-01 - Make cross-partition `EndTxn` crash-atomic
**Legacy:** Issue #4 · `docs/design/KAFKA-TXN-DESIGN.md`

**Status:** open. Durable `Prepare`/`Commit` journal, partition rollback, startup recovery, offset snapshots, and a
transaction visibility gate now exist. In-process and real-binary restart tests cover five post-fsync boundaries, but
ambiguous journal-write handling and full all-or-none proof under those ambiguous outcomes remain open; do not claim
crash atomicity yet.

**Do:** finish process-level crash tests and ambiguous journal-write handling against
[`KAFKA-TXN-DURABILITY.md`](../design/KAFKA-TXN-DURABILITY.md). Keep control metadata provider-blind. Do not claim
Kafka EOS until kill-during-commit proves all-or-none.

**Acceptance:** injected crash at every commit boundary leaves either all enrolled records and offsets visible or none;
recovery is deterministic; stale epoch cannot finish a newer transaction.

### DUR-01 - Prove power-loss durability
**Legacy:** Issue #2

**Status:** open. `kill9_crash.rs` proves SIGKILL survival, not fsync reordering or directory-entry loss.

**Do:** FUSE, `dm-flakey`, CharybdeFS, or equivalent fault-injection harness that can cut/reorder fsync and rename.

**Acceptance:** reproducible local or CI harness fails without dir-fsync ordering and passes with it; every acked record
survives the injected cut.

### STOR-01 - Fix `ReplayLog::replay_from` seek after corruption
**Legacy:** WP-01 checklist remaining issue

**Status:** closed. Core seek fix landed, direct-read workaround removed, and storage/fetch regressions pass.

**Do:** none; retain corruption regression coverage.

**Acceptance:** arbitrary valid record offsets after corrupt frames return exact suffixes; no renumbering; existing
corruption tests remain green.

## P1 - product correctness and compatibility

### WP1-01 - Close per-partition locking evidence and release gates
**Legacy:** Issue #1 · WP-01

**Status:** implementation done; evidence incomplete. Per-partition locks, rollback build, deterministic multi-lock
ordering, 10k contention stress, sequence reservation test, and local A/B harness exist. Local ratios ranged
`1.154x-1.684x`; no independent product benchmark, 95% CI, RSS, or dedicated benchmark binary exists.

**Do:** run independent/interleaved product A/B; collect p99, RSS, CI timing; decide whether to ship `v0.1.1`.

**Acceptance:** default build meets agreed throughput/p99/RSS gates on documented hardware; rollback remains green;
staging/tag/CI evidence is recorded; no claim exceeds evidence.

### COMPAT-01 - Run real Kafka client conformance matrix
**Legacy:** Issue #3 · `docs/design/KAFKA-COMPAT.md`

**Status:** open. Preparation landed: `scripts/kafka-compat-matrix.sh` validates a fail-closed matrix and provides
the real-broker adapter contract. Real coverage remains limited to kcat/librdkafka 1.7.1 and an independent
librdkafka 1.8.0 run. Missing: Apache Kafka Java, franz-go, kafka-python, Sarama, librdkafka 2.x, and real-client
transactional EOS.

**Acceptance:** each client row has a real pass/fail result for produce, fetch, groups, security, compression, and
transactions where supported.

### DEDUP-01 - Persist broker restart deduplication
**Legacy:** Issue #6

**Status:** implemented for idempotent producers. Persistent per-partition sequence metadata survives broker restart;
non-idempotent producers remain at-least-once.

**Acceptance:** produce, restart, retry sequence lands each record once at stable offsets; scope remains distinct from
rail-mode and Postgres exactly-once claims.

## P1 - security and trust boundary

### KEY-01 - Replace inline demo secrets with key references
**Legacy:** Issue #7

**Status:** partial. `env:` and `file:` key refs work and demo inline seeds remain; KMS path is absent.

**Acceptance:** env/file/KMS handle references boot rail and broker without raw secret material in config; errors fail
closed and secret lifetime is documented.

### QUIC-01 - Verify real QUIC server certificates
**Legacy:** Issue #8

**Status:** implemented. Production `connect` verifies caller CA and hostname; embedded cert and accept-any behavior
remain explicit dev/test paths.

**Acceptance:** CA/hostname verification rejects wrong-cert MITM; dev certificate path requires explicit opt-in.

### CRYPTO-01 - Obtain external review of crypto composition
**Legacy:** Issue #9

**Status:** open. Primitive crates and construction have self-audit only.

**Acceptance:** external review covers X25519 wrap, AEAD/AAD, Ed25519 lacre, DRBG snapshot/fork behavior, and key
zeroization; findings and remediation are published.

## P2 - architecture and extraction

### REPL-01 - Decide replication scope: wire it or cut it
**Legacy:** Issue #11

**Status:** open decision. Replication, erasure, routed topics, tiered log, and related crates are tested libraries,
not wired into the CLI. Single-node is current truth.

**Acceptance:** either a real multi-node leader/replication/failover path reaches the binary, or docs explicitly scope
the project as single-node/embedded and remove unfulfilled product language.

### MAN-01 - Extract Merkle delivery receipt crate
**Legacy:** Issue #10

**Status:** closed via typed boundary. Public standalone verifier API now includes owned `OwnedDeliveryReceipt` plus
external-consumer tests/docs; verifier CLI and serialization remain intentionally absent because SPEC 04 defines no
wire format.

**Acceptance:** external consumer verifies owned receipt offline without importing CLI internals; no CLI or wire-format
claim is made.

### NET-01 - Wire FASP delay controller into real lossy transport

**Status:** parked. The algorithm is proven in seeded simulation; production TCP path does not use FASP over UDP.

**Acceptance:** real UDP transport with authenticated peer/session handling, loss/latency test, and no claim based on
simulation alone.

## External and owner queue

### EXT-01 - AC-10 real competitor bake-off
**Legacy:** Issue #20

**Status:** external resource. Fairness rig/methodology can be maintained here; actual competitor binaries and suitable
infrastructure are not in this repository.

**Acceptance:** real engine binaries, byte-equal workload, documented environment, and reproducible results.

### OWNER-01 - Reconcile CAST/MF-0 ratification status

**Status:** owner/documentation gate. `DECOMPOSITION.md` says MF-0 ratified, while `00-CONSTITUTION.md`,
`adr/0001-adopt-cast.md`, and product-intent docs still say pending. Resolve status before another product-scope
freeze. Owner-reserved product docs remain untouched here.

**Acceptance:** one signed decision record is authoritative; dependent docs agree; no implementation claim depends on
an unresolved product decision.

## Parked, not active defects

- Kafka-faithful marker/LSO model and true `read_uncommitted`; current safe scope is buffer-until-commit with
  `read_uncommitted == read_committed`.
- RFC-3161 TSA anchoring; explicitly out of v1 delivery path.
- FASP real transport integration; tracked as `NET-01`.
- CI p99/RSS/lock-contention measurement; part of `WP1-01`, not a product number yet.

## Closed in current worktree

- `BatchTooLarge` -> Kafka `MESSAGE_TOO_LARGE` `10`; regression covered.
- Per-partition locking implementation, rollback feature, lock-order stress, and sequence-range test.
- Transaction epoch fencing, stale completion rejection, failed-buffer restoration.
- Replay corruption active mitigation and loud fetch behavior.
- Contract violation -> non-retriable `INVALID_RECORD` `87`.

## Dependency order

1. `WP1-01` evidence/release decision and `DUR-01` power-loss semantics.
2. `DUR-01` power-loss harness.
3. `TXN-01` durable transaction protocol and crash test.
4. `DEDUP-01` restart deduplication.
5. `COMPAT-01` real-client matrix.
6. `KEY-01` and `QUIC-01` security hardening.
7. `REPL-01`, `MAN-01`, `NET-01`, `CRYPTO-01`, and `EXT-01` by leverage/resources.
