# KAFKA-COMPAT — the Kafka wire-protocol ingest bridge (scope, limits, security posture)

> **The pitch:** point an existing, **unmodified** Kafka producer at datarail; every record it sends is sealed
> into a provider-blind cofre and landed via any datarail `Sink`. *Your Kafka producers, now provider-blind,
> no code change.* This doc is the HONEST scope: exactly what is implemented, what is not, and the
> precise security boundary — so no one over-claims.

## What is implemented (`datarail-kafka`, zero-dependency)
datarail presents itself as a **single-broker, single-partition-per-topic** Kafka-compatible **ingest** endpoint.

| API | key | versions | notes |
|---|---|---|---|
| `ApiVersions` | 18 | v0–v3 | responds in the client's version (flexible body for v3; response header always v0 per KIP-482) |
| `Metadata` | 3 | v0–v1 | advertises this process as broker `node 0` (`--advertised HOST:port`), the leader of every requested topic's single partition |
| `Produce` | 0 | v0–v7 | parses the request envelope + the records blob (incl. the idempotent producer's `producer_id`/`base_sequence`) |
| `Fetch` | 1 | v0–v4 | CONSUME side (`kafka-broker` mode): returns un-sealed records as a v2 `RecordBatch` with a correct `CRC-32C` (`KAFKA-FETCH-DESIGN.md`) |
| `ListOffsets` | 2 | v0–v2 | earliest/latest logical offsets for a consumer (`kafka-broker` mode) |
| `OffsetCommit` | 8 | v0–v2 | durably commit a consumer group's offset (`kafka-broker` mode, `KAFKA-GROUPS-DESIGN.md`) |
| `OffsetFetch` | 9 | v0–v2 | read a consumer group's committed offset (`kafka-broker` mode) |
| `FindCoordinator` | 10 | v0–v2 | names this broker the group coordinator (single-node, `kafka-broker` mode) |
| `AddPartitionsToTxn` | 24 | v0–v1 | enroll partitions in a transaction (`kafka-broker` mode, `KAFKA-TXN-DESIGN.md`) |
| `AddOffsetsToTxn` | 25 | v0–v1 | fold a consumer group's offsets into a transaction (`kafka-broker` mode) |
| `EndTxn` | 26 | v0–v1 | commit/abort a transaction (`kafka-broker` mode) |
| `TxnOffsetCommit` | 28 | v0–v1 | stage offsets to commit atomically at `EndTxn` (`kafka-broker` mode) |
| `InitProducerId` | 22 | v0–v1 | grants a `producer_id` so a client can `enable.idempotence=true` → exactly-once ingest (`KAFKA-EOS-DESIGN.md`) |

**Record formats:** both the modern **v2 `RecordBatch`** AND the legacy **v0/v1 `MessageSet`** are parsed
(librdkafka emits legacy magic-0 on a fallback path — this was caught by live-testing against real `kcat`, not
assumed). **Uncompressed only.**

**Proven against the REAL Kafka client (not just our wire tests).** `kafka-broker-librdkafka.yml` (CI) drives
`datarail kafka-broker` with kcat (= librdkafka 1.7.1): a real producer + a real simple consumer + a real
`subscribe()` CONSUMER GROUP all round-trip, and the on-disk store is asserted ciphertext-only (provider-blind).
This caught a genuine compat bug our hand-rolled tests could not — only a real client negotiates **Fetch v4** + the
group path: we encoded `aborted_transactions` and an empty record-set as null (`-1`); librdkafka rejects `-1`
("Protocol parse failure for Fetch v4" / "invalid MessageSetSize -1"). Fixed to empty (`0`), as a real broker
sends (regression: `fetch_response_v4_empty_partition_uses_zero_not_null`). The rebalance / JoinGroup / SyncGroup
path was already librdkafka-compatible (the real group joined + was assigned cleanly).

**Flow:** `datarail kafka-ingest <rail.toml> --advertised HOST --sink-…` runs the endpoint; each produced batch's
record values stream into the normal rail (`board` → **seal** → substrate → `offload` → `Sink`). Produced offsets
are tracked per `(topic, partition)` and returned in the Produce response.

**Delivery guarantee:** **exactly-once** into a transactional sink (Postgres) for an **idempotent producer**
(`enable.idempotence=true`) — datarail honors `InitProducerId` and keys dedup on the producer's stable
`(producer_id, partition, sequence)`, stored transactionally in the sink, so a producer retry / ingest restart
never double-lands (`KAFKA-EOS-DESIGN.md`). A **non-idempotent** producer is **at-least-once** (Kafka's own
default). Honest scope: exactly-once is *within an idempotent producer session*; cross-session (transactional)
EOS is a further increment.

**Verified:** `kafka-ingest.yml` (CI) runs a real `kcat`/librdkafka producer → datarail → sealed rail → a Postgres
service container, asserting the sealed rows land; plus the EOS gate — a duplicated idempotent `Produce` through
the real binary lands exactly once (3 rows, not 6). Continuously gated, not a one-off (`LASTRO-MATRIX`).

## What is NOT implemented (honest limits — do not claim these)
- **Consumer side EXISTS now** (`kafka-broker` mode: `Fetch`, `ListOffsets`) — an unmodified consumer reads back,
  un-sealed at the edge, from a provider-blind (sealed) store. The store is **durable on disk** (increment 2:
  `kafka_store::SealedPartitionLog` over `datarail-replaylog`, `fsync`-before-ack, contiguous logical offset) and
  **survives a restart** (proven by a broker-kill+restart wire test). **Durable consumer offsets EXIST now**
  (increment 3: `OffsetCommit`/`OffsetFetch`/`FindCoordinator`, fsync-before-ack via `FileOffsets`) — a consumer's
  committed offset survives its own restart AND a broker restart. **Multi-partition** (increment 4a): `--partitions
  N` → Metadata advertises N partitions, each an INDEPENDENT durable log + offset space (proven by
  `kafka_multipartition_wire.rs`). **Automatic group rebalance** (increment 4b): a single-node coordinator serves
  `JoinGroup`/`SyncGroup`/`Heartbeat`/`LeaveGroup`, so a `subscribe()` consumer group auto-assigns partitions
  (proven by `kafka_rebalance_wire.rs`; concurrency audit pending). **Honest limits:** group membership is runtime
  state (not persisted across a broker restart — committed OFFSETS are); server-side assignment / KIP-848,
  static membership, cooperative-incremental rebalance are out of scope; offset-stable across a clean crash +
  failed batch, with silent mid-history disk-rot renumbering a known retained-log limit (CRC-detected; tracked).
- **COMPRESSION EXISTS now** (`--features compression`, `KAFKA-COMPRESSION-DESIGN.md`): a producer with
  `compression.type=gzip|lz4|zstd|snappy` works — the broker decompresses the batch, seals each record, and a
  consumer reads them back uncompressed. Proven against real librdkafka (kcat) over all four codecs in CI
  (`kafka-broker-compression.yml`). The codecs are pure-Rust decompress-only crates behind the feature (default
  binary stays dependency-light + rejects compressed). Snappy accepts Kafka's xerial/snappy-java framing OR raw/
  frame snappy (librdkafka's variant). Each decompression is bounded (16 MiB zip-bomb cap).
- **TRANSACTIONAL producer EXISTS now** (`kafka-broker` mode, `KAFKA-TXN-DESIGN.md`): `InitProducerId` with a
  `transactional.id` (epoch fencing), `AddPartitionsToTxn`/`AddOffsetsToTxn`/`TxnOffsetCommit`/`EndTxn`, on a
  buffer-until-commit model — a txn's records are buffered (invisible) until `EndTxn(commit)` makes them visible
  atomically across partitions (offsets too) / `EndTxn(abort)` discards them; a stale-epoch zombie is fenced
  (proven by `kafka_txn_wire.rs`; AUDITED, `CORE-AUDIT.md` §Kafka-TXN). **Honest scope:** correct for one producer
  per partition during a txn (concurrent → retriable `CONCURRENT_TRANSACTIONS`); `read_uncommitted` behaves like
  `read_committed`; abort-on-restart. The idempotent producer (`enable.idempotence=true`) remains supported for
  per-partition exactly-once. The faithful marker/LSO model (concurrent same-partition txns + a true
  `read_uncommitted`) is tracked future work.
- **TLS on the Kafka hop EXISTS now** (server-side termination, `--features tls`: `--tls --tls-cert --tls-key`,
  `KAFKA-TLS-DESIGN.md`) — encrypts hop (1). **SASL/PLAIN auth EXISTS now** (`--sasl-user`/`--sasl-pass`,
  `KAFKA-SASL-DESIGN.md`): a client must authenticate (`SaslHandshake` → `SaslAuthenticate`, mechanism `PLAIN`)
  before any other API; proven against real librdkafka (`kafka-broker-sasl.yml`). Pair `--sasl-*` with `--tls` for
  `SASL_SSL` (PLAIN sends the password in the clear). **mTLS / client-cert auth EXISTS now** (`--tls-client-ca <pem>`,
  `KAFKA-MTLS-DESIGN.md`): the broker requires + verifies a client cert chaining to that CA (the cert-based
  alternative to SASL) — proven against real librdkafka (`kafka-broker-mtls.yml`). **No SCRAM/GSSAPI yet** (single
  credential, PLAIN only); **no cert→identity ACL** yet (mTLS authenticates the client, it does not authorize per
  topic). See the security posture below.
- **Single partition per topic, single broker.** No real partitioning/replication on the Kafka-facing side — the
  durability/replication is datarail's own (the rail + substrate), not Kafka-style partition replicas.

## Security posture — READ THIS, it is the boundary that must not be over-claimed
datarail's core guarantee is **provider-blind**: the rail, the cheap/untrusted pipe, and the storage/sink-side
infrastructure never see plaintext. With Kafka ingest, the trust boundary is:

```
[Kafka producer] --(1) Kafka wire (plaintext, or TLS with --tls)-->  [datarail kafka-ingest]  --(2) SEALED cofre-->  [rail → storage → sink]
```

- **Hop (2) — the rail and everything downstream — is sealed and provider-blind.** This is the moat and it holds:
  the cheap pipe, any intermediate, and the storage provider see only ciphertext.
- **Hop (1) — the producer → datarail link — is PLAINTEXT by default, or TLS-encrypted with `--tls`**
  (`--features tls`, `KAFKA-TLS-DESIGN.md`). With TLS it is encrypted-in-transit and datarail is server-authenticated
  (proven against real librdkafka over TLS in CI). It is still **NOT end-to-end sealed from the producer** — TLS
  terminates at datarail's edge, where the record is plaintext only for as long as it takes to seal it into a cofre
  (the moat). For a fully end-to-end-sealed source, use datarail's native sealed terminals, not Kafka ingest.
- **Honest framing:** TLS closes the on-the-wire exposure of hop (1) (a passive tap sees ciphertext); it is
  transport security + server auth, NOT the same as datarail's end-to-end sealing. Cert trust + client auth (mTLS)
  are the operator's to configure; SASL is a further axis (tracked).

## Roadmap (next arcs, in rough value order)
1. ✅ **`Fetch` consumer side — DONE** (2026-06-27, `kafka-broker` mode, `KAFKA-FETCH-DESIGN.md`): datarail is a
   bidirectional Kafka drop-in (produce AND consume), un-sealing on read. Next within this line: **durable store**
   (datarail-topic backing) + **consumer groups** + **multi-partition**.
2. ✅ **TLS on the Kafka hop — DONE** (2026-06-28, `--features tls`, `KAFKA-TLS-DESIGN.md`): server-side TLS
   termination (`--tls --tls-cert --tls-key`) encrypts hop (1); proven against real librdkafka over TLS in CI
   (`kafka-broker-tls.yml`). ✅ **mTLS / client-cert — DONE** (`--tls-client-ca`, `KAFKA-MTLS-DESIGN.md`). ✅ **SASL/
   PLAIN — DONE** (`--sasl-user/--sasl-pass`, `KAFKA-SASL-DESIGN.md`). Next: SCRAM; cert/identity → ACL.
3. ✅ **Compression — DONE** (2026-06-28, `--features compression`, `KAFKA-COMPRESSION-DESIGN.md`): gzip/lz4/zstd/
   snappy decompression on produce, proven vs real librdkafka in CI. Re-compression on Fetch (bandwidth) is tracked.
4. ✅ **Idempotent producer (`InitProducerId`) → exactly-once from idempotent producers — DONE** (2026-06-27,
   `KAFKA-EOS-DESIGN.md`). Next within this line: **transactional** producer (cross-session EOS via a stable
   `transactional.id`).

## Reproducible client matrix harness

Preparation only. The harness does not turn wire-test coverage into client evidence. Matrix source:
`scripts/kafka-compat-matrix.tsv`.

```text
./scripts/kafka-compat-matrix.sh --check
./scripts/kafka-compat-matrix.test.sh
```

Run requires the real release broker and an executable client adapter:

```text
cargo build --release -p datarail-cli
./scripts/kafka-compat-matrix.sh --run CLIENT_ID \
  --broker-bin ./target/release/datarail --adapter ./compat-adapter
```

Adapter contract: accept `--broker HOST:PORT`, `--topic NAME`, and `--data-dir DIR`; exercise the client against
that real `datarail kafka-broker`; print exactly one `DATARAIL_COMPAT_VERSION=<exact version>` line and exactly one
`DATARAIL_COMPAT_RESULT=PASS` or `DATARAIL_COMPAT_RESULT=FAIL` line. Known-version rows must include their expected
version. Missing tool/adapter records `UNAVAILABLE` and exits nonzero. Missing, contradictory, malformed, or
versionless output records `UNKNOWN` and exits nonzero. No absent client can become `PASS`.

Common broker command used by every adapter:

```text
./target/release/datarail kafka-broker examples/rail.toml \
  --listen 127.0.0.1:19092 --advertised 127.0.0.1 \
  --data-dir "$DATA_DIR" --partitions 1
```

Client-specific version and wire commands. These are reproducible run recipes, not evidence until an adapter emits
the result marker and its output is retained with the version output.

| Client | Capture exact version | Produce/fetch/group command |
|---|---|---|
| Apache Kafka Java | `$KAFKA_HOME/bin/kafka-topics.sh --version` | `$KAFKA_HOME/bin/kafka-console-producer.sh --bootstrap-server 127.0.0.1:19092 --topic compat-java`; then `kafka-console-consumer.sh --bootstrap-server 127.0.0.1:19092 --topic compat-java --from-beginning --group compat-java` |
| franz-go | `go list -m -f '{{.Version}}' github.com/twmb/franz-go` | `go run "$FRANZ_GO_ADAPTER" --broker 127.0.0.1:19092 --topic compat-franz-go` |
| kafka-python | `python3 -c 'import kafka; print(kafka.__version__)'` | `python3 "$KAFKA_PYTHON_ADAPTER" --broker 127.0.0.1:19092 --topic compat-python` |
| Sarama | `go list -m -f '{{.Version}}' github.com/IBM/sarama` | `go run "$SARAMA_ADAPTER" --broker 127.0.0.1:19092 --topic compat-sarama` |
| librdkafka 2.x | `kcat -V`; require reported librdkafka major `2` | `printf 'evt:1\\nevt:2\\n' \| kcat -P -b 127.0.0.1:19092 -t compat-rdkafka-2`; then `kcat -C -b 127.0.0.1:19092 -t compat-rdkafka-2 -o beginning -e` |
| Transactional EOS | client-specific command plus exact version capture | client adapter must run transactional produce, consumer-group offset commit, restart/retry, then emit marker; wire test alone is not real-client evidence |

`franz-go`, kafka-python, Sarama, and transactional rows have no adapter in this repository. They remain
`UNTESTED`; commands above intentionally use operator-supplied adapter paths. Java and librdkafka 2.x likewise remain
untested until their exact client distributions are captured. Do not replace `UNTESTED` with `PASS` after a missing-tool
run.

## Tested client matrix (honest)

Every row below reflects something that was actually exercised against the real binary, either in CI or during the independent audit. Nothing here is inferred from wire-test coverage alone.

| Client | Version | Produce | Simple consume | Consumer group | TLS | mTLS | SASL/PLAIN | Compression | Transactions | Where | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| kcat (librdkafka) | 1.7.1 (edenhill/kcat docker image) | yes | yes | yes (subscribe + rebalance) | yes | yes | yes | yes (gzip, lz4, snappy, zstd) | not exercised in this workflow | CI: `kafka-broker-librdkafka.yml`, `kafka-broker-tls.yml`, `kafka-broker-mtls.yml`, `kafka-broker-sasl.yml`, `kafka-broker-compression.yml` | passing |
| kafkacat (librdkafka) | 1.6.0 / librdkafka 1.8.0 (Ubuntu 22.04 package) | yes | yes | not exercised | not exercised | not exercised | not exercised | not exercised | not exercised | independent bench (`docs/BENCH-INDEPENDENT-2026-07-01.md`) | passing; 1.8.0 found the INVALID\_RECORD bug (fixed same day) |
| datarail wire tests (hand-rolled) | — | yes (all API versions in scope) | yes | yes (JoinGroup/SyncGroup/Heartbeat/LeaveGroup paths) | — | — | — | — | yes (commit/abort/epoch-fencing) | CI: `ci.yml` | self-referential; a real client is always the definitive test |

**NOT yet tested** — no CI workflow and no independent run has driven these against the real binary:

- Apache Kafka Java client (any version)
- franz-go
- kafka-python
- Sarama (Go)
- librdkafka 2.x (only 1.7.1 in CI; 1.8.0 in the independent bench — 2.x API negotiation differences are untested)
- Any client exercising transactional producers end-to-end (the wire path is tested by the hand-rolled suite, not a real client)

A conformance run against the above clients is tracked but not yet scheduled.

## Why this is still a big deal even produce-only + seal-on-ingest
The expensive, untrusted, always-on part of a Kafka deployment is the **broker cluster + its storage**. datarail
replaces exactly that with a single-node, provider-blind rail (single-digit-MB RSS — 3.3 MB idle / 9 MB peak,
independently measured; the older `~70×` figure is a *shim* comparison, a different object — see the README
"Measured" note) — while the producer keeps its existing
Kafka client. The first hop being trusted-network is the same assumption most in-datacenter Kafka deployments
already make (PLAINTEXT or mTLS between app and broker); datarail adds provider-blindness for everything after.
