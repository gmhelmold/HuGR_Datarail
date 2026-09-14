# Security

## Reporting a vulnerability

Email **gustavomalleths@gmail.com**. There is no bug bounty. Response is best-effort; critical issues
will be acknowledged as quickly as possible. Please include enough detail to reproduce the issue —
affected component, Rust toolchain version, and a minimal reproducer if practical.

## Threat model

The project operates in two modes with different trust models. They must not be conflated.

### What the design defends against

**Rail mode** (`datarail send / recv / run`): the endpoints — and only the endpoints — hold the
keys and perform the seal. Every carrier in between (TCP socket, QUIC stream, shared-memory segment,
S3 object store) sees only opaque ciphertext. A passive tap on any transport hop cannot recover
payload content or sender identity. An active storage-layer attacker who can read and rewrite objects
gets ciphertext and cannot produce valid forgeries: each cofre carries an Ed25519 lacre (signature)
and an AEAD tag, both verified at the destination. Replay of old cofres is blocked by a per-route
sequence counter and a dedup index keyed on the idempotency token. Sender authenticity is provable
offline: the Merkle delivery receipt plus the signed lacre lets a third party verify that a specific
sender produced a specific record, without trusting any intermediary.

**Broker mode** (`datarail kafka-broker` / `kafka-ingest`): the broker process holds all keys and
seals on produce / un-seals on fetch. The value of this mode is **provider-blind storage**: the
on-disk log is always ciphertext; a storage-layer adversary who steals the disk, snapshots the
volume, or reads the files through a storage-provider API gets sealed cofres, not plaintext records.
The optional Kafka-hop security (`--tls`, `--tls-client-ca` for mTLS, `--sasl-user` for SASL/PLAIN)
encrypts and authenticates the producer-to-broker link.

### What the design does NOT defend against

- **Compromised endpoint.** A process that controls the terminal (the sealing or unsealing end in
  rail mode, or the broker process in broker mode) can read plaintext. The seal lives at the edge;
  the edge must be trusted.
- **Compromised broker process (broker mode specifically).** The broker holds all keys. Any attacker
  who gains code execution inside the broker process can read everything. Disk-theft protection is
  the goal; process-compromise protection is not.
- **Traffic analysis and metadata on the QUIC substrate.** The QUIC substrate ships with dev-only
  embedded certificates and a client that accepts any server certificate. An active on-path attacker
  can terminate the TLS 1.3 handshake and observe all QUIC transport metadata — route/stream IDs,
  sequence numbers, frame timing, connection teardown patterns. Payload confidentiality and integrity
  still hold end-to-end (the cofre is AEAD-sealed before it reaches the transport), but metadata is
  exposed. The QUIC substrate is dev/test only.
- **Side channels.** Timing, cache, and power side channels are not in scope. The primitives used
  (AES-NI, constant-time scalar multiplication from the dalek suite) reduce obvious timing exposure
  but no formal side-channel analysis has been done.
- **Denial of service beyond the DoS cookie's scope.** The rail implements a stateless DoS cookie
  that gates connection setup, but sustained high-rate packet flooding, resource exhaustion on the
  broker's single global lock, and amplification attacks are not defended against.
- **Supply-chain attacks.** Dependencies are pinned in `Cargo.lock` and sourced from crates.io.
  Compromise of an upstream crate or the Rust toolchain is out of scope.

## Crypto inventory

All primitives are provided by vetted crates. **The composition — how these primitives are wired
together in the cofre format, the key hierarchy, and the delivery proof — has had no third-party
cryptographic review. It is self-audited only.** See
[`docs/design/ADVERSARIAL-AUDIT.md`](docs/design/ADVERSARIAL-AUDIT.md) for the adversarial
self-audit on record.

| Construction | Primitive | Crate |
|---|---|---|
| Per-cofre key-wrap (KEM) | X25519 ECDH → HKDF-SHA256 → AEAD-wrap | `x25519-dalek` |
| AEAD (default) | AES-256-GCM-SIV (nonce-misuse-resistant) | `aes-gcm-siv` |
| AEAD (alternate, opt-in) | ChaCha20-Poly1305 | `chacha20poly1305` |
| Signature (lacre · STH · ack · cert · ticket) | Ed25519, domain-separated per role | `ed25519-dalek` |
| Hash (cofre\_id · contract\_fp · Merkle) | BLAKE3-256 | `blake3` |
| Transport identity / mutual auth | Noise\_KK | `snow` |
| Pairing / short-code key agreement | SPAKE2 | `spake2` |
| Constant-time comparison | — | `subtle` |
| Secret zeroing | — | `zeroize` |

## Secrets handling

The `examples/rail.toml` file carries raw, all-repeated-byte keys by design — they are demo fixtures
committed to the public repository and must never be used in production. Real deployments should
reference keys through an external store; the spec supports `env:` and `file:` key-reference values in
`[keys]` for exactly this reason. KMS references are not implemented.

Long-term secrets (route identity keypairs, tenant secrets) are wrapped in types that implement
`zeroize::Zeroize` and are dropped with `zeroize-on-drop` so they are overwritten in memory before
the allocator reclaims them. Per-cofre ephemeral data keys are fresh CSPRNG draws; they are wrapped
into the cofre and not retained after sealing.
