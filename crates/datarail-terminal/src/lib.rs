//! `datarail-terminal` — the onboarding / offloading terminals (SPEC `06-terminal-protocol.md`,
//! Capability D / AC-2,3,9). A terminal is **our mechanism running in the user's trust zone**: it holds the
//! keys, sees plaintext, and enforces the **user's content contract** (`INV-CONTRACT-SPLIT` — content
//! contract here, envelope contract at the rail).
//!
//! This crate wires the whole flow end-to-end against the **frozen** seam (`docs/design/FOOTER-FREEZE.md`):
//! it transcribes [`datarail_cofre::seal`] / [`datarail_cofre::verify`], the [`datarail_crypto`] primitives,
//! and the [`datarail_once`] admission gate; it does **not** redesign any of them.
//!
//! - **Onboarding** ([`SourceTerminal::board`]): enforce the content contract on every record (a failing
//!   record **never boards**, AC-9 boarding side), frame the conforming records into a `RECORD_BATCH`,
//!   AEAD-seal them into a [`Cofre`], and Ed25519-sign it.
//! - **Offloading** ([`DestTerminal::offload`]): parse-before-verify the seal against the **pinned** source
//!   key, check the `contract_fp`, AEAD-open, re-validate every record against the offloading contract, then
//!   take the [`datarail_once`] admission decision and commit exactly once to the sink. Any seal/contract
//!   failure is routed to a reason-coded **dead-letter** siding (AC-9 offload side), never delivered.
//!
//! ## Key-wrap & v1 notes
//!
//! - **Per-cofre X25519 key-wrap (SPEC A5 / `03`).** `board` generates a fresh ephemeral X25519 key and seals
//!   a fresh per-cofre data key to the route's destination public key ([`datarail_crypto::seal_key`]); the
//!   `eph_pk` rides in the etiqueta and only the holder of the destination secret re-derives the key
//!   ([`datarail_crypto::open_key`]). Forward-secure (the ephemeral is discarded) and provider-blind.
//! - **AEAD AAD binds the header (AUDIT-02 F5).** The AEAD's associated data is every *seal-time-final*
//!   etiqueta field — all except `cofre_id` / `signer_key_id`, which [`datarail_cofre::seal`] stamps *after*
//!   the carga exists (the ordering cycle that blocks binding the whole etiqueta). This is defense in depth
//!   atop the outer `lacre`, which already binds `etiqueta ⊗ carga` (`INV-SEAL-COMPLETE`). See [`aead_aad`].

#![forbid(unsafe_code)]

use datarail_core::{AeadAlg, Cofre, Disposition, Etiqueta};
use datarail_cofre::CofreError;
use datarail_crypto::{aead_open, aead_seal, blake3_256, hmac_blake3, open_key, seal_key, AeadError};
use datarail_once::Once;
use std::collections::HashMap;
use zeroize::Zeroize as _;

/// Build the AEAD associated data: every **seal-time-final** etiqueta field — all of them *except* `cofre_id`
/// and `signer_key_id`, which [`datarail_cofre::seal`] stamps *after* the carga exists (the ordering cycle
/// that blocks binding the whole etiqueta). **AUDIT-02 F5:** this binds the AEAD to the header — defense in
/// depth atop the outer `lacre`, which already covers `etiqueta ⊗ carga`. `board` and `offload` recompute it
/// identically (the excluded fields are zero at seal time and verifier-recomputed at open time).
fn aead_aad(e: &Etiqueta) -> Vec<u8> {
    let aead_tag: u8 = match e.aead_alg {
        AeadAlg::Gcmsiv256 => 1,
        AeadAlg::ChaCha20Poly1305 => 2,
        AeadAlg::Gcm256 => 3,
    };
    let mut aad = Vec::with_capacity(16 + 16 + 8 + 32 + 32 + 1 + 12 + 32 + 1 + 8);
    aad.extend_from_slice(&e.route_id);
    aad.extend_from_slice(&e.stream_id);
    aad.extend_from_slice(&e.seq.to_le_bytes());
    aad.extend_from_slice(&e.idempotency_key);
    aad.extend_from_slice(&e.contract_fp);
    aad.push(aead_tag);
    aad.extend_from_slice(&e.nonce);
    aad.extend_from_slice(&e.eph_pk);
    aad.push(u8::from(e.sender_present));
    aad.extend_from_slice(&e.ts.to_le_bytes());
    aad
}

/// Read 32 bytes of OS entropy (`/dev/urandom`, zero-dep) through a **per-thread persistent fd**.
///
/// The DRBG below mixes fresh OS bytes into every draw (AUDIT-05 clone/snapshot immunity), so this runs twice
/// per cofre — and the previous implementation `open()`ed `/dev/urandom` on every call, which put an
/// open/read/close (dentry + fd-table churn) on the hot seal path and measurably *contended* once the seal was
/// parallelized across cores (2026-07-01 bench). Keeping one open fd per thread removes the open/close while
/// preserving the security property exactly: each `read` still returns fresh kernel CSPRNG output, and a
/// restored VM-snapshot / CRIU clone reading through a restored fd still gets DIFFERENT bytes per clone — the
/// freshness comes from the kernel pool at read time, not from the fd. On a read error the fd is dropped so
/// the next call reopens rather than wedging the thread on a dead handle.
fn os_seed_32() -> Result<[u8; 32], TerminalError> {
    use std::io::Read as _;
    thread_local! {
        static URANDOM: core::cell::RefCell<Option<std::fs::File>> = const { core::cell::RefCell::new(None) };
    }
    URANDOM.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(std::fs::File::open("/dev/urandom").map_err(|_| TerminalError::Entropy)?);
        }
        let mut buf = [0u8; 32];
        let ok = slot.as_mut().is_some_and(|file| file.read_exact(&mut buf).is_ok());
        if ok {
            Ok(buf)
        } else {
            *slot = None; // reopen on the next call instead of wedging on a dead fd
            Err(TerminalError::Entropy)
        }
    })
}

/// Draws between fresh OS reseeds (prediction resistance / recovery from a state compromise).
/// A per-thread, **forward-secure** CSPRNG for per-cofre ephemeral keys + nonces.
///
/// Construction: a BLAKE3-keyed-PRF over a secret ratcheting seed that **mixes fresh OS entropy into every
/// draw**. Each draw reads 32 fresh OS bytes and emits `out = PRF(seed, os_fresh)`, then ratchets the seed via
/// `seed = PRF(seed, "ratchet")`. Clone/snapshot immunity (AUDIT-05 fix): because every draw depends on fresh OS
/// entropy obtained AFTER any fork / VM-snapshot-restore / CRIU / paused-VM clone, two clones that preserve the
/// PID and the DRBG state still draw DIFFERENT OS bytes and never re-emit an identical `(eph_secret, nonce)` —
/// the prior design keyed clone-detection on the PID, which is invariant across snapshot-restore, so that hole
/// is now closed by construction, not by detection. Forward secrecy: the ratcheting seed means a state
/// compromise cannot recover already-used (zeroized) keys. The per-draw OS read is negligible beside the
/// per-cofre X25519/Ed25519 work, and the secret seed is defense-in-depth if the OS RNG momentarily degrades.
struct Drbg {
    seed: [u8; 32],
}

impl Drbg {
    fn seeded() -> Result<Self, TerminalError> {
        Ok(Self { seed: os_seed_32()? })
    }

    fn next_32(&mut self) -> Result<[u8; 32], TerminalError> {
        // Fresh OS entropy on EVERY draw ⇒ a snapshot/clone (PID + DRBG state preserved) cannot replay key
        // material: each restored clone reads different OS bytes here. The ratchet keeps forward secrecy.
        let fresh = os_seed_32()?;
        let out = hmac_blake3(&self.seed, &fresh);
        self.seed = hmac_blake3(&self.seed, b"datarail-drbg-ratchet-v1");
        Ok(out)
    }
}

thread_local! {
    static DRBG: core::cell::RefCell<Option<Drbg>> = const { core::cell::RefCell::new(None) };
}

/// 32 fresh cryptographically-random bytes for a per-cofre ephemeral key / nonce, from the per-thread CSPRNG
/// (seeded lazily from the OS on first use). Replaces the old per-call `/dev/urandom` open.
fn random_32() -> Result<[u8; 32], TerminalError> {
    DRBG.with(|cell| {
        let mut g = cell.borrow_mut();
        if g.is_none() {
            *g = Some(Drbg::seeded()?);
        }
        g.as_mut().expect("seeded just above").next_32()
    })
}

// ----------------------------------------------------------------------------------------------------------
// Content contract — a real, simple stand-in for schema / required-fields (D4: declarative policy).
// ----------------------------------------------------------------------------------------------------------

/// A content contract: the user's declarative validation policy for a single record (SPEC 06, D4).
///
/// This is a deliberately simple but *real* stand-in for a schema / required-fields rule set: a record is
/// valid iff it is non-empty, no longer than [`max_record_len`](Self::max_record_len), and begins with
/// [`required_prefix`](Self::required_prefix). The [`fingerprint`](Self::fingerprint) is what the destination
/// pins as the expected schema version — a mismatch is a *managed* schema-drift event (dead-letter), never
/// silent corruption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentContract {
    /// `BLAKE3` fingerprint identifying this contract / schema version (stamped into the etiqueta's
    /// `contract_fp` and checked at offload).
    pub fingerprint: [u8; 32],
    /// Maximum permitted length of a single record, in bytes.
    pub max_record_len: usize,
    /// Bytes every conforming record must start with (a minimal "required fields" stand-in).
    pub required_prefix: Vec<u8>,
}

impl ContentContract {
    /// Build a contract whose [`fingerprint`](Self::fingerprint) is derived deterministically from its rules,
    /// so two terminals configured with the same rules agree on the same schema id.
    ///
    /// The fingerprint commits to `max_record_len ‖ required_prefix` under [`blake3_256`].
    #[must_use]
    pub fn new(max_record_len: usize, required_prefix: Vec<u8>) -> Self {
        let mut preimage = Vec::with_capacity(8 + required_prefix.len());
        preimage.extend_from_slice(&(max_record_len as u64).to_le_bytes());
        preimage.extend_from_slice(&required_prefix);
        Self {
            fingerprint: blake3_256(&preimage),
            max_record_len,
            required_prefix,
        }
    }

    /// Validate one record against this contract: non-empty, `len <= max_record_len`, and starting with
    /// [`required_prefix`](Self::required_prefix).
    #[must_use]
    pub fn validate(&self, record: &[u8]) -> bool {
        !record.is_empty()
            && record.len() <= self.max_record_len
            && record.starts_with(&self.required_prefix)
    }
}

// ----------------------------------------------------------------------------------------------------------
// RECORD_BATCH framing — length-prefixed: u32 count, then per-record (u32 len ‖ bytes).
// ----------------------------------------------------------------------------------------------------------

/// Encode records into a length-prefixed `RECORD_BATCH`: `u32 count`, then for each record `u32 len ‖ bytes`
/// (little-endian). This is the plaintext that gets AEAD-sealed into the cofre's `carga`.
fn frame_batch(records: &[&[u8]]) -> Result<Vec<u8>, TerminalError> {
    let count = u32::try_from(records.len()).map_err(|_| TerminalError::BatchTooLarge)?;
    let total: usize = records.iter().map(|r| 4 + r.len()).sum();
    let mut buf = Vec::with_capacity(4 + total);
    buf.extend_from_slice(&count.to_le_bytes());
    for record in records {
        let len = u32::try_from(record.len()).map_err(|_| TerminalError::BatchTooLarge)?;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(record);
    }
    Ok(buf)
}

/// Decode a `RECORD_BATCH` produced by [`frame_batch`] back into its records. Every declared length is
/// bound-checked against the remaining buffer (a malformed batch is a [`TerminalError::MalformedBatch`], which
/// the caller turns into a dead-letter — never a panic).
fn unframe_batch(bytes: &[u8]) -> Result<Vec<Vec<u8>>, TerminalError> {
    let mut pos = 0usize;
    let count_bytes = bytes
        .get(pos..pos + 4)
        .ok_or(TerminalError::MalformedBatch)?;
    let count = u32::from_le_bytes(count_bytes.try_into().map_err(|_| TerminalError::MalformedBatch)?);
    pos += 4;
    // Cap the speculative pre-allocation: each record needs ≥4 header bytes, so a legitimate `count` cannot
    // exceed `bytes.len() / 4`. Prevents a malformed-but-authenticated batch (a buggy/compromised source) from
    // requesting a huge `Vec` allocation before the per-record bound checks run (AUDIT-02 parse-lens finding).
    let mut records = Vec::with_capacity((count as usize).min(bytes.len() / 4));
    for _ in 0..count {
        let len_bytes = bytes
            .get(pos..pos + 4)
            .ok_or(TerminalError::MalformedBatch)?;
        let len = u32::from_le_bytes(len_bytes.try_into().map_err(|_| TerminalError::MalformedBatch)?)
            as usize;
        pos += 4;
        let end = pos.checked_add(len).ok_or(TerminalError::MalformedBatch)?;
        let record = bytes.get(pos..end).ok_or(TerminalError::MalformedBatch)?;
        records.push(record.to_vec());
        pos = end;
    }
    if pos != bytes.len() {
        return Err(TerminalError::MalformedBatch);
    }
    Ok(records)
}

// ----------------------------------------------------------------------------------------------------------
// Sealed-sender (SPEC-02 A4 / 03 MAJ-4) — the fine-grained sender identity rides ENCRYPTED inside the carga,
// so the rail never sees it; only the destination, after AEAD-open, validates it.
// ----------------------------------------------------------------------------------------------------------

/// Fixed on-wire `SENDER_CERT` length: `sender_id(32) ‖ sender_vk(32) ‖ epoch(8) ‖ issuer_sig(64) ‖
/// sender_sig(64)`.
const SENDER_CERT_LEN: usize = 32 + 32 + 8 + 64 + 64;

/// Issue a long-lived sender certificate: the **route authority** (issuer) vouches that `sender_id` owns
/// `sender_vk` for `epoch` — `Ed25519(ctx::CERT, issuer_seed, sender_id ‖ sender_vk ‖ epoch_le)`. Signed once,
/// offline (SPEC 03 MAJ-4: issuer-signed, **not** self-signed); the destination pins the issuer's verifying key.
#[must_use]
pub fn issue_sender_cert(
    issuer_seed: &[u8; 32],
    sender_id: &[u8; 32],
    sender_vk: &[u8; 32],
    epoch: u64,
) -> [u8; 64] {
    datarail_crypto::sign_domain(datarail_crypto::ctx::CERT, issuer_seed, &cert_identity_msg(sender_id, sender_vk, epoch))
}

/// The issuer-signed preimage: `sender_id ‖ sender_vk ‖ epoch_le`.
fn cert_identity_msg(sender_id: &[u8; 32], sender_vk: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(72);
    m.extend_from_slice(sender_id);
    m.extend_from_slice(sender_vk);
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

/// The per-cofre preimage the sender signs: `eph_pk ‖ epoch_le` — binds the cert to **this** cofre (via its
/// unique ephemeral key) without the circular dependency a literal `cofre_id` binding would have
/// (`cofre_id = BLAKE3(carga)`, and the cert is *inside* the carga). See AUDIT-03 / FOOTER-FREEZE.
fn cert_binding_msg(eph_pk: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(40);
    m.extend_from_slice(eph_pk);
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

/// A source terminal's sealed-sender credential: the sender's secret signing identity plus the issuer's
/// vouching certificate. The sender signs a fresh per-cofre binding over `eph_pk` at board time.
#[derive(Clone)]
pub struct SenderCredential {
    /// The sender principal id (issuer-asserted; dest-visible after open).
    pub sender_id: [u8; 32],
    /// The sender's Ed25519 signing seed (per-cofre binding; **secret**).
    sender_seed: [u8; 32],
    /// Epoch the issuer cert was minted for (freshness / revocation window).
    pub epoch: u64,
    /// The issuer's signature vouching `sender_id ↔ sender_vk @ epoch`.
    pub issuer_sig: [u8; 64],
}

impl SenderCredential {
    /// Build a credential from the sender's signing seed, its id, and a pre-issued `issuer_sig` (from
    /// [`issue_sender_cert`] over the matching `sender_id`/`sender_vk`/`epoch`).
    #[must_use]
    pub fn new(sender_id: [u8; 32], sender_seed: [u8; 32], epoch: u64, issuer_sig: [u8; 64]) -> Self {
        Self { sender_id, sender_seed, epoch, issuer_sig }
    }

    /// Encode the wire `SENDER_CERT` for a cofre with ephemeral key `eph_pk`: appends the per-cofre
    /// `sender_sig = Ed25519(ctx::CERT, sender_seed, eph_pk ‖ epoch_le)`.
    fn encode(&self, eph_pk: &[u8; 32]) -> Vec<u8> {
        let sender_vk = datarail_crypto::verifying_key(&self.sender_seed);
        let sender_sig = datarail_crypto::sign_domain(
            datarail_crypto::ctx::CERT,
            &self.sender_seed,
            &cert_binding_msg(eph_pk, self.epoch),
        );
        let mut out = Vec::with_capacity(SENDER_CERT_LEN);
        out.extend_from_slice(&self.sender_id);
        out.extend_from_slice(&sender_vk);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.issuer_sig);
        out.extend_from_slice(&sender_sig);
        out
    }
}

/// Redacting `Debug` (never print the sender signing seed).
/// Wipe the sealed-sender Ed25519 `sender_seed` on drop (defense-in-depth — complements the redacting `Debug`).
impl Drop for SenderCredential {
    fn drop(&mut self) {
        self.sender_seed.zeroize();
    }
}

impl core::fmt::Debug for SenderCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SenderCredential")
            .field("sender_id", &self.sender_id)
            .field("sender_seed", &"<redacted>")
            .field("epoch", &self.epoch)
            .field("issuer_sig", &self.issuer_sig)
            .finish()
    }
}

/// Validate a wire `SENDER_CERT` at the destination against the pinned issuer key and this cofre's `eph_pk`.
/// Returns the authenticated `sender_id` on success. Both signatures must hold: the **issuer** vouches for the
/// sender's identity↔key, and the **sender** authorized this specific cofre (via `eph_pk`).
fn validate_sender_cert(
    bytes: &[u8],
    eph_pk: &[u8; 32],
    pinned_issuer_vk: &[u8; 32],
    min_epoch: u64,
) -> Option<[u8; 32]> {
    if bytes.len() != SENDER_CERT_LEN {
        return None;
    }
    let sender_id: [u8; 32] = bytes[0..32].try_into().ok()?;
    let sender_vk: [u8; 32] = bytes[32..64].try_into().ok()?;
    let epoch = u64::from_le_bytes(bytes[64..72].try_into().ok()?);
    // Revocation floor (audit S-2): reject a cert minted before the accepted epoch — without this a rotated/
    // revoked sender's old (validly-issued) cert would be honored forever.
    if epoch < min_epoch {
        return None;
    }
    let issuer_sig: [u8; 64] = bytes[72..136].try_into().ok()?;
    let sender_sig: [u8; 64] = bytes[136..200].try_into().ok()?;

    // (a) the issuer vouches for sender_id ↔ sender_vk @ epoch (route authority, not self-signed).
    if !datarail_crypto::verify_domain(
        datarail_crypto::ctx::CERT,
        pinned_issuer_vk,
        &cert_identity_msg(&sender_id, &sender_vk, epoch),
        &issuer_sig,
    ) {
        return None;
    }
    // (b) the sender authorized THIS cofre (binding over its unique eph_pk).
    if !datarail_crypto::verify_domain(
        datarail_crypto::ctx::CERT,
        &sender_vk,
        &cert_binding_msg(eph_pk, epoch),
        &sender_sig,
    ) {
        return None;
    }
    Some(sender_id)
}

// ----------------------------------------------------------------------------------------------------------
// Errors.
// ----------------------------------------------------------------------------------------------------------

/// An error from a terminal operation.
///
/// Note the split (SPEC 06): a content-contract violation **at onboarding** is an *error* ([`board`] never
/// produces a cofre), whereas a content/seal failure **at offloading** is a [`Disposition::DeadLettered`]
/// (the cofre is preserved on the siding), not an error. [`MalformedBatch`](Self::MalformedBatch) is reserved
/// for an internal framing inconsistency.
///
/// [`board`]: SourceTerminal::board
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalError {
    /// A record violated the onboarding content contract — the batch **never boards** (AC-9, boarding side).
    ContractViolation,
    /// Sealing the batch failed at the AEAD layer (e.g. a bad key length).
    Seal,
    /// A `RECORD_BATCH` could not be framed (more than `u32::MAX` records, or a record longer than `u32::MAX`).
    BatchTooLarge,
    /// A decoded `RECORD_BATCH` was internally inconsistent (truncated / trailing bytes).
    MalformedBatch,
    /// OS entropy for the per-cofre ephemeral key could not be read.
    Entropy,
}

impl core::fmt::Display for TerminalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::ContractViolation => "record violates the onboarding content contract (never boards)",
            Self::Seal => "AEAD seal failed",
            Self::BatchTooLarge => "record batch exceeds framing limits",
            Self::MalformedBatch => "record batch is malformed",
            Self::Entropy => "could not read OS entropy for the per-cofre key",
        };
        f.write_str(s)
    }
}

impl core::error::Error for TerminalError {}

impl From<AeadError> for TerminalError {
    fn from(_: AeadError) -> Self {
        Self::Seal
    }
}

// ----------------------------------------------------------------------------------------------------------
// Dead-letter siding + sink.
// ----------------------------------------------------------------------------------------------------------

/// Why a cofre was diverted to the offloading dead-letter siding (D3 — reason-coded, preserved, never
/// delivered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadLetterReason {
    /// The seal failed parse-before-verify against the pinned source key (`INV-TAMPER-REJECT`, AC-2/3).
    SealFailed(CofreError),
    /// The cofre is addressed to a different route/stream than this terminal serves.
    RouteMismatch,
    /// The cofre's `contract_fp` did not match the destination's expected schema (AC-9 — managed drift).
    ContractFingerprintMismatch,
    /// The AEAD-open failed (tamper / wrong key / nonce), so the payload could not be read.
    OpenFailed,
    /// The cofre's `eph_pk` is a low-order / non-contributory X25519 point, so the per-cofre key-wrap could not
    /// safely derive a key (S-3 defense-in-depth, RFC 7748 §6.1) — the cofre is rejected before AEAD-open.
    KeyWrapInvalid,
    /// The decrypted `RECORD_BATCH` was malformed (truncated / trailing bytes).
    MalformedBatch,
    /// A decrypted record violated the offloading content contract (AC-9, offload side).
    ContractViolation,
    /// A sealed-sender cofre's `SENDER_CERT` failed validation (bad issuer/sender signature, wrong epoch
    /// binding, malformed, or no issuer key pinned at the destination) — SPEC-02 A4 / 03 MAJ-4.
    SenderCertInvalid,
}

impl core::fmt::Display for DeadLetterReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SealFailed(e) => write!(f, "seal verification failed: {e}"),
            Self::RouteMismatch => f.write_str("cofre addressed to a different route/stream"),
            Self::ContractFingerprintMismatch => f.write_str("contract fingerprint mismatch (schema drift)"),
            Self::OpenFailed => f.write_str("AEAD open failed (tamper/wrong key)"),
            Self::KeyWrapInvalid => f.write_str("key-wrap invalid (low-order/non-contributory eph_pk)"),
            Self::MalformedBatch => f.write_str("decrypted record batch is malformed"),
            Self::ContractViolation => f.write_str("decrypted record violates offloading contract"),
            Self::SenderCertInvalid => f.write_str("sealed-sender certificate failed validation"),
        }
    }
}

/// One entry on the dead-letter siding: the preserved cofre plus the reason it was diverted (D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetter {
    /// The full cofre, preserved verbatim (never dropped, never delivered).
    pub cofre: Cofre,
    /// The reason-code for the diversion.
    pub reason: DeadLetterReason,
}

/// Max dead-letters RETAINED in memory. Past this, the OLDEST is evicted (its count kept in `dropped`) so a
/// hostile producer flooding contract-violating cofres cannot grow the siding without bound (a long-running
/// destination must not OOM on diverted cofres). 1024 is ample for inspection; the all-time total is preserved.
const MAX_DEAD_LETTERS_RETAINED: usize = 1024;

/// A cofre opened to its plaintext: the records and the validated sealed-sender id (if any). The read-only
/// result of [`DestTerminal::open_records`], shared by `offload` (which then dedups + commits) and `open`.
type OpenedRecords = (Vec<Vec<u8>>, Option<[u8; 32]>);

/// The offloading dead-letter siding: a reason-coded list of diverted cofres (D3), **bounded** to the most
/// recent [`MAX_DEAD_LETTERS_RETAINED`] (older ones are counted in `dropped`, not retained).
#[derive(Debug, Default, Clone)]
pub struct DeadLetterSiding {
    entries: Vec<DeadLetter>,
    dropped: u64,
}

impl DeadLetterSiding {
    /// A fresh, empty siding.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of diverted cofres CURRENTLY RETAINED on the siding (≤ [`MAX_DEAD_LETTERS_RETAINED`]).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the siding currently retains no cofres.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Count of older diverted cofres evicted to keep the siding bounded (not retained).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// All-time count of diverted cofres (retained + evicted).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.dropped.saturating_add(u64::try_from(self.entries.len()).unwrap_or(u64::MAX))
    }

    /// The diverted entries currently retained, in arrival order (oldest first).
    #[must_use]
    pub fn entries(&self) -> &[DeadLetter] {
        &self.entries
    }

    /// Divert a cofre to the siding with its reason-code, evicting the oldest if at the retention cap.
    fn push(&mut self, cofre: Cofre, reason: DeadLetterReason) {
        if self.entries.len() >= MAX_DEAD_LETTERS_RETAINED {
            self.entries.remove(0); // evict oldest (bounded flood; O(n) only past the cap)
            self.dropped = self.dropped.saturating_add(1);
        }
        self.entries.push(DeadLetter { cofre, reason });
    }
}

/// A trivial in-memory sink: the records committed (delivered exactly once) at the destination.
#[derive(Debug, Default, Clone)]
pub struct Sink {
    committed: Vec<Vec<u8>>,
}

impl Sink {
    /// A fresh, empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of records committed so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.committed.len()
    }

    /// Whether the sink holds no committed records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty()
    }

    /// The committed records, in commit order.
    #[must_use]
    pub fn committed(&self) -> &[Vec<u8>] {
        &self.committed
    }

    /// Drain and return all committed records, leaving the sink empty. Lets a consumer that forwards delivered
    /// records downstream (e.g. a relay) reclaim memory instead of retaining every record for the process
    /// lifetime — without this an unbounded stream grows the sink until OOM.
    #[must_use]
    pub fn take_committed(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.committed)
    }

    /// Commit a batch of records (idempotency is decided upstream by [`datarail_once`]).
    fn commit(&mut self, records: Vec<Vec<u8>>) {
        self.committed.extend(records);
    }
}

// ----------------------------------------------------------------------------------------------------------
// Shared route configuration (the v1 key simplification lives here).
// ----------------------------------------------------------------------------------------------------------

/// The static, shared parameters for one A→B route, held by **both** terminals.
///
/// Bundling the route parameters in one struct (rather than passing loose `[u8; _]` arguments) keeps the
/// terminal constructors within the Craft Charter without an `#[allow]`.
#[derive(Clone)]
pub struct TerminalConfig {
    /// Fixed A→B route id (copied into every etiqueta).
    pub route_id: [u8; 16],
    /// Ordering domain (copied into every etiqueta; drives the [`datarail_once`] gate keyed per stream).
    pub stream_id: [u8; 16],
    /// AEAD algorithm for the carga (default [`AeadAlg::Gcmsiv256`]).
    pub aead_alg: AeadAlg,
    /// The route **destination's X25519 public key**. `board` seals a fresh per-cofre data key to it; only the
    /// destination terminal (holding the matching secret) can open it — provider-blind and forward-secure.
    pub dest_x25519_pk: [u8; 32],
    /// Per-tenant secret keying the idempotency MAC `HMAC(tenant_secret, record_key)`.
    pub tenant_secret: [u8; 32],
}

/// Redacting `Debug` (AUDIT-02): never print the `tenant_secret` MAC key. Public route params are shown.
/// Wipe the `tenant_secret` (HMAC key for idempotency-key derivation) on drop — every clone wipes its own copy.
impl Drop for TerminalConfig {
    fn drop(&mut self) {
        self.tenant_secret.zeroize();
    }
}

impl core::fmt::Debug for TerminalConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TerminalConfig")
            .field("route_id", &self.route_id)
            .field("stream_id", &self.stream_id)
            .field("aead_alg", &self.aead_alg)
            .field("dest_x25519_pk", &self.dest_x25519_pk)
            .field("tenant_secret", &"<redacted>")
            .finish()
    }
}

// ----------------------------------------------------------------------------------------------------------
// Source terminal — onboarding.
// ----------------------------------------------------------------------------------------------------------

/// The **onboarding** (source) terminal: enforces the content contract, frames a `RECORD_BATCH`, and seals it
/// into a signed [`Cofre`] (SPEC 06, boarding side).
///
/// Holds the route config, the onboarding [`ContentContract`], the Ed25519 source signing seed, and the
/// monotonic per-stream `seq`. A contract-violating record makes [`board`](Self::board) return
/// [`TerminalError::ContractViolation`] — it **never boards** (AC-9).
#[derive(Clone)]
pub struct SourceTerminal {
    config: TerminalConfig,
    contract: ContentContract,
    /// Ed25519 source signing seed (the route's pinned identity).
    source_seed: [u8; 32],
    /// Monotonic per-stream sequence counter (legacy, used by `board`/`next_seq`).
    seq: u64,
    /// Per-partition sequence counters for parallel sealing ([`reserve_seqs`] with `partition_id`).
    seq_per_partition: HashMap<u64, u64>,
    /// Optional sealed-sender credential (SPEC-02 A4). When set, `board` rides an issuer-signed `SENDER_CERT`
    /// **inside** the encrypted carga and sets `sender_present`; when `None`, cofres carry no sender identity.
    sender: Option<SenderCredential>,
}

/// Redacting `Debug` (AUDIT-02): never print the Ed25519 `source_seed`.
/// Wipe the Ed25519 `source_seed` (the route's signing identity) on drop (defense-in-depth).
impl Drop for SourceTerminal {
    fn drop(&mut self) {
        self.source_seed.zeroize();
    }
}

impl core::fmt::Debug for SourceTerminal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SourceTerminal")
            .field("config", &self.config)
            .field("contract", &self.contract)
            .field("source_seed", &"<redacted>")
            .field("seq", &self.seq)
            .field("seq_per_partition", &self.seq_per_partition)
            .field("sender", &self.sender)
            .finish()
    }
}

impl SourceTerminal {
    /// Build a source terminal for a route with its onboarding `contract` and Ed25519 `source_seed`.
    #[must_use]
    pub fn new(config: TerminalConfig, contract: ContentContract, source_seed: [u8; 32]) -> Self {
        Self {
            config,
            contract,
            source_seed,
            seq: 0,
            seq_per_partition: HashMap::new(),
            sender: None,
        }
    }

    /// Enable **sealed-sender** (SPEC-02 A4): every subsequent [`board`](Self::board) rides the issuer-signed
    /// `SENDER_CERT` encrypted inside the carga, hidden from the rail. Builder-style; returns `self`.
    #[must_use]
    pub fn with_sender(mut self, sender: SenderCredential) -> Self {
        self.sender = Some(sender);
        self
    }

    /// The next sequence number this terminal will assign (the count of cofres boarded so far).
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.seq
    }

    /// **Onboard** a batch of records into a sealed cofre (SPEC 06, boarding side).
    ///
    /// Steps: validate **every** record against the onboarding contract (any failure ⇒
    /// [`TerminalError::ContractViolation`], and the batch never boards — AC-9); frame the records into a
    /// `RECORD_BATCH`; seal a fresh per-cofre data key to the dest's X25519 key, then AEAD-seal the batch;
    /// stamp the etiqueta (including `idempotency_key = HMAC(tenant_secret, record_key)` and the contract
    /// fingerprint); [`datarail_cofre::seal`] it under the source seed; bump `seq`; return the cofre.
    ///
    /// # Errors
    /// - [`TerminalError::ContractViolation`] if any record fails the onboarding contract (never boards).
    /// - [`TerminalError::BatchTooLarge`] if the batch exceeds the `u32` framing limits.
    /// - [`TerminalError::Seal`] if the AEAD seal fails (e.g. a bad key length).
    pub fn board(&mut self, records: &[&[u8]], record_key: &[u8]) -> Result<Cofre, TerminalError> {
        let cofre = self.board_at(records, record_key, self.seq)?;
        self.seq += 1;
        Ok(cofre)
    }

    /// Reserve `n` consecutive sequence numbers for a given `partition_id` and return the first — for
    /// callers that seal a batch of cofres **in parallel** with explicit per-cofre seqs
    /// ([`board_at`](Self::board_at)). The reservation is what keeps parallel sealing seq-unique:
    /// the counter is bumped once, up front, under whatever lock the caller already holds, and
    /// each worker stamps `start + i` (order-preserving, no duplicates). Saturates at `u64::MAX`
    /// rather than wrapping.
    ///
    /// Each partition has its own independent sequence space, so sequences from different
    /// partitions never collide.
    ///
    /// # Panics
    /// Never panics. The `entry(...).or_insert(0)` ensures the key exists, and the subsequent
    /// `get_mut` is guaranteed to succeed.
    #[must_use]
    pub fn reserve_seqs(&mut self, partition_id: u64, n: u64) -> u64 {
        let start = *self.seq_per_partition.entry(partition_id).or_insert(0);
        let entry = self.seq_per_partition.get_mut(&partition_id).unwrap();
        *entry = entry.saturating_add(n);
        start
    }

    /// [`board`](Self::board) with an explicit, caller-assigned sequence number and **no internal state
    /// change** (`&self`): the parallel-seal building block. Callers MUST assign each cofre a distinct `seq`
    /// (use [`reserve_seqs`](Self::reserve_seqs)) — the per-cofre data key is freshly drawn per call from the
    /// per-thread CSPRNG, so cryptographic safety never depends on `seq`, but a duplicated seq would confuse
    /// downstream effectively-once accounting.
    ///
    /// # Errors
    /// - [`TerminalError::ContractViolation`] if any record fails the onboarding contract (never boards).
    /// - [`TerminalError::BatchTooLarge`] if the batch exceeds the `u32` framing limits.
    /// - [`TerminalError::Seal`] if the AEAD seal fails (e.g. a bad key length).
    pub fn board_at(&self, records: &[&[u8]], record_key: &[u8], seq: u64) -> Result<Cofre, TerminalError> {
        // (1) Enforce the content contract on EVERY record — a single failure means the batch never boards.
        if !records.iter().all(|r| self.contract.validate(r)) {
            return Err(TerminalError::ContractViolation);
        }

        // (2) Frame the conforming records into a length-prefixed RECORD_BATCH.
        let batch = frame_batch(records)?;

        // (3) Idempotency key: HMAC(tenant_secret, record_key) — the sole effectively-once dedup key.
        let idempotency_key = hmac_blake3(&self.config.tenant_secret, record_key);

        // (4) Per-cofre key-wrap (SPEC A5/03): a fresh ephemeral X25519 key seals a fresh data key to the
        // route's destination public key — only the dest can re-derive it (provider-blind, forward-secure).
        let mut eph_secret = random_32()?;
        let Some((eph_pk, mut data_key)) = seal_key(&self.config.dest_x25519_pk, &eph_secret) else {
            eph_secret.zeroize();
            return Err(TerminalError::Seal); // a low-order dest_x25519_pk is a route misconfiguration (S-3)
        };
        eph_secret.zeroize(); // forward secrecy: wipe the ephemeral secret immediately (AUDIT-02 F4).

        // (5) Sealed-sender (SPEC-02 A4): if a credential is configured, prepend the issuer-signed SENDER_CERT
        // (bound to this cofre's eph_pk) ahead of the RECORD_BATCH — it rides ENCRYPTED, invisible to the rail.
        let (inner, sender_present) = match &self.sender {
            Some(cred) => {
                let mut inner = cred.encode(&eph_pk);
                inner.extend_from_slice(&batch);
                (inner, true)
            }
            None => (batch, false),
        };

        // (6) Build the etiqueta (cofre_id/signer_key_id are stamped by `seal`), then AEAD-seal INNER under the
        // per-cofre data key with a fresh random nonce and the header bound as AAD (AUDIT-02 F5).
        let nonce = Self::fresh_nonce()?;
        let etiqueta = Etiqueta {
            route_id: self.config.route_id,
            stream_id: self.config.stream_id,
            seq,
            cofre_id: [0u8; 32],
            idempotency_key,
            contract_fp: self.contract.fingerprint,
            aead_alg: self.config.aead_alg,
            nonce,
            signer_key_id: [0u8; 32],
            eph_pk,
            sender_present,
            ts: 0, // informational only; never trusted (SPEC-02). A real wall-clock stamp is a deployment concern.
        };
        let carga = aead_seal(self.config.aead_alg, &data_key, &nonce, &aead_aad(&etiqueta), &inner)?;
        data_key.zeroize(); // the per-cofre data key is consumed; wipe it (AUDIT-02 F4).

        // (6) Seal (Ed25519 over etiqueta ⊗ carga). (The per-stream sequence is advanced by the caller —
        // `board` bumps by one; a parallel sealer reserves its whole range up front via `reserve_seqs`.)
        let cofre = datarail_cofre::seal(etiqueta, carga, &self.source_seed);
        Ok(cofre)
    }

    /// Draw a fresh 12-byte nonce from the per-thread CSPRNG. Nonce reuse is precluded primarily by the
    /// **fresh per-cofre data key** (one message per key). Fork/snapshot safety is provided by the DRBG's
    /// **reseed-on-fork gate** ([`Drbg::next_32`] reseeds when the PID changes) — NOT by this nonce being random,
    /// since a forked DRBG would replay both the key draw and the nonce draw identically without that gate
    /// (AUDIT-04 corrected the prior claim that seq-decoupling alone gave fork safety).
    fn fresh_nonce() -> Result<[u8; 12], TerminalError> {
        let r = random_32()?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&r[..12]);
        Ok(nonce)
    }
}

// ----------------------------------------------------------------------------------------------------------
// Destination terminal — offloading.
// ----------------------------------------------------------------------------------------------------------

/// The **offloading** (destination) terminal: verifies the seal, checks the contract, opens the payload,
/// re-validates every record, and commits exactly once (SPEC 06, offload side).
///
/// Owns the route config, the offloading [`ContentContract`], the **pinned** source verifying key, the
/// [`datarail_once`] admission gate, the [`Sink`], and the [`DeadLetterSiding`]. Any seal/contract failure is
/// reason-coded onto the siding and reported as [`Disposition::DeadLettered`] — never delivered (AC-9).
pub struct DestTerminal {
    config: TerminalConfig,
    contract: ContentContract,
    /// The route-pinned source Ed25519 verifying key (BLK-4).
    pinned_source_vk: [u8; 32],
    /// This destination's X25519 secret — unwraps the per-cofre data key from the cofre's `eph_pk`.
    dest_x25519_secret: [u8; 32],
    /// Optional pinned **issuer** verifying key for sealed-sender (SPEC-02 A4). A cofre with `sender_present`
    /// is validated against this; if `None`, such a cofre is dead-lettered (can't validate the claimed sender).
    sender_issuer_vk: Option<[u8; 32]>,
    /// Minimum acceptable sealed-sender cert `epoch` (audit S-2): a cert with `epoch < min_sender_epoch` is
    /// rejected, giving revocation a real floor. Default `0` accepts any epoch (backward-compatible); raise it
    /// after a key rotation so a revoked sender's old-epoch cert stops being honored.
    min_sender_epoch: u64,
    /// The `sender_id` validated on the most recent `Delivered` sealed-sender cofre (observability; dest-only).
    last_sender_id: Option<[u8; 32]>,
    once: Once,
    sink: Sink,
    dead_letters: DeadLetterSiding,
}

/// Redacting `Debug` (AUDIT-02): never print the destination X25519 secret (the `Once` gate redacts its own
/// signing seed).
/// Wipe this destination's X25519 secret — the per-cofre data-key unwrap key whose compromise breaks
/// provider-blindness for the whole route — on drop (defense-in-depth; the moat key must not linger in freed
/// heap / a core dump / swap). The nested `config`/`once` zeroize their own secrets via their own `Drop`.
impl Drop for DestTerminal {
    fn drop(&mut self) {
        self.dest_x25519_secret.zeroize();
    }
}

impl core::fmt::Debug for DestTerminal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DestTerminal")
            .field("config", &self.config)
            .field("contract", &self.contract)
            .field("pinned_source_vk", &self.pinned_source_vk)
            .field("dest_x25519_secret", &"<redacted>")
            .field("sender_issuer_vk", &self.sender_issuer_vk)
            .field("min_sender_epoch", &self.min_sender_epoch)
            .field("last_sender_id", &self.last_sender_id)
            .field("once", &self.once)
            .field("sink", &self.sink)
            .field("dead_letters", &self.dead_letters)
            .finish()
    }
}

impl DestTerminal {
    /// Build a destination terminal for a route with its offloading `contract`, the **pinned** source
    /// verifying key, and a [`datarail_once`] gate signing watermarks under `dest_seed`.
    #[must_use]
    pub fn new(
        config: TerminalConfig,
        contract: ContentContract,
        pinned_source_vk: [u8; 32],
        dest_seed: [u8; 32],
        dest_x25519_secret: [u8; 32],
    ) -> Self {
        Self {
            config,
            contract,
            pinned_source_vk,
            dest_x25519_secret,
            sender_issuer_vk: None,
            min_sender_epoch: 0,
            last_sender_id: None,
            once: Once::new(dest_seed),
            sink: Sink::new(),
            dead_letters: DeadLetterSiding::new(),
        }
    }

    /// Set the minimum acceptable sealed-sender cert `epoch` (audit S-2): a `sender_present` cofre whose cert
    /// `epoch < min` is dead-lettered, so a rotated/revoked sender's old-epoch cert is no longer honored. Builder.
    #[must_use]
    pub fn with_min_sender_epoch(mut self, min_epoch: u64) -> Self {
        self.min_sender_epoch = min_epoch;
        self
    }

    /// Pin the sealed-sender **issuer** verifying key (SPEC-02 A4): cofres with `sender_present` are validated
    /// against it; a valid cert's `sender_id` is exposed via [`last_sender_id`](Self::last_sender_id). Without
    /// this, a `sender_present` cofre is dead-lettered (the claimed sender cannot be validated). Builder-style.
    #[must_use]
    pub fn with_sender_issuer(mut self, issuer_vk: [u8; 32]) -> Self {
        self.sender_issuer_vk = Some(issuer_vk);
        self
    }

    /// The `sender_id` validated on the most recent `Delivered` sealed-sender cofre, if any (dest-only — the
    /// rail never sees it).
    #[must_use]
    pub fn last_sender_id(&self) -> Option<[u8; 32]> {
        self.last_sender_id
    }

    /// The destination's commit sink (records delivered exactly once).
    #[must_use]
    pub fn sink(&self) -> &Sink {
        &self.sink
    }

    /// Mutable access to the commit sink — for a relay that drains delivered records downstream (see
    /// [`Sink::take_committed`]) so the sink does not grow unbounded over a long stream.
    pub fn sink_mut(&mut self) -> &mut Sink {
        &mut self.sink
    }

    /// The reason-coded dead-letter siding.
    #[must_use]
    pub fn dead_letters(&self) -> &DeadLetterSiding {
        &self.dead_letters
    }

    /// **Offload** a received cofre (SPEC 06, offload side).
    ///
    /// Order (the offloading pipeline): parse-before-verify the seal against the pinned source key (fail ⇒
    /// dead-letter); check `contract_fp` against the expected schema (fail ⇒ dead-letter, managed drift);
    /// AEAD-open and un-frame the `RECORD_BATCH` (fail ⇒ dead-letter); re-validate every record against the
    /// offloading contract (any fail ⇒ dead-letter); take the [`datarail_once`] admission decision —
    /// [`Disposition::Duplicate`] ⇒ drop, no commit; [`Disposition::Delivered`] ⇒ commit the records to the
    /// sink.
    ///
    /// # Errors
    /// This function does not currently return an error: every rejection is a
    /// [`Disposition::DeadLettered`] on the siding (a preserved, reason-coded event, not a failure), and a
    /// dedup drop is a [`Disposition::Duplicate`]. The `Result` matches the [`datarail_core::Terminal`] seam
    /// and reserves room for a future fallible sink commit.
    pub fn offload(&mut self, cofre: &Cofre) -> Result<Disposition, TerminalError> {
        // Verify + open (the read-only core); a rejection becomes a reason-coded dead-letter.
        let (records, sender_id) = match self.open_records(cofre) {
            Ok(rs) => rs,
            Err(reason) => {
                self.dead_letters.push(cofre.clone(), reason);
                return Ok(Disposition::DeadLettered);
            }
        };

        // (7) Effectively-once admission, then commit-on-Delivered only (exactly-once at the sink).
        match self.once.admit(
            cofre.etiqueta.stream_id,
            cofre.etiqueta.seq,
            cofre.etiqueta.idempotency_key,
        ) {
            Disposition::Delivered => {
                self.sink.commit(records);
                self.last_sender_id = sender_id; // expose the validated sender (dest-only) on delivery.
                Ok(Disposition::Delivered)
            }
            // A duplicate is dropped without committing; DeadLettered cannot come from the once gate.
            other => Ok(other),
        }
    }

    /// Verify + open a received cofre to its plaintext records WITHOUT the dedup / commit / dead-letter side
    /// effects — the read-only core shared by [`DestTerminal::offload`] and [`DestTerminal::open`]. Returns the
    /// records and the validated sender id, or the [`DeadLetterReason`] that rejects the cofre. Steps mirror the
    /// offloading pipeline: verify lacre → route binding → schema → key-wrap + AEAD-open → sealed-sender split →
    /// un-frame → re-validate every record against the offloading contract.
    fn open_records(&self, cofre: &Cofre) -> Result<OpenedRecords, DeadLetterReason> {
        // (1) Parse-before-verify: verify the lacre against the route-pinned source key (BLK-4/7, AC-2/3).
        if let Err(e) = datarail_cofre::verify(cofre, &self.pinned_source_vk) {
            return Err(DeadLetterReason::SealFailed(e));
        }
        // (2) Route binding: the cofre must be addressed to THIS terminal's route + stream.
        if cofre.etiqueta.route_id != self.config.route_id
            || cofre.etiqueta.stream_id != self.config.stream_id
        {
            return Err(DeadLetterReason::RouteMismatch);
        }
        // (3) Schema check: the cofre's claimed contract_fp must match this destination's expected contract.
        if cofre.etiqueta.contract_fp != self.contract.fingerprint {
            return Err(DeadLetterReason::ContractFingerprintMismatch);
        }
        // (4) Re-derive the per-cofre data key from the authenticated eph_pk, then AEAD-open with the header
        // bound as AAD (AUDIT-02 F5). S-3: a low-order eph_pk fails closed (no key derived).
        let Some(mut data_key) = open_key(&self.dest_x25519_secret, &cofre.etiqueta.eph_pk) else {
            return Err(DeadLetterReason::KeyWrapInvalid);
        };
        let opened = aead_open(
            cofre.etiqueta.aead_alg,
            &data_key,
            &cofre.etiqueta.nonce,
            &aead_aad(&cofre.etiqueta),
            &cofre.carga,
        );
        data_key.zeroize(); // wipe the re-derived per-cofre key (AUDIT-02 F4).
        let Ok(batch) = opened else {
            return Err(DeadLetterReason::OpenFailed);
        };

        // (5) Sealed-sender (SPEC-02 A4): if the header says a SENDER_CERT rides inside, split + validate it.
        let (record_bytes, sender_id): (&[u8], Option<[u8; 32]>) = if cofre.etiqueta.sender_present {
            let Some(issuer_vk) = self.sender_issuer_vk else {
                return Err(DeadLetterReason::SenderCertInvalid);
            };
            if batch.len() < SENDER_CERT_LEN {
                return Err(DeadLetterReason::SenderCertInvalid);
            }
            let (cert, rest) = batch.split_at(SENDER_CERT_LEN);
            match validate_sender_cert(cert, &cofre.etiqueta.eph_pk, &issuer_vk, self.min_sender_epoch) {
                Some(sid) => (rest, Some(sid)),
                None => return Err(DeadLetterReason::SenderCertInvalid),
            }
        } else {
            (&batch, None)
        };

        // (6) Un-frame the RECORD_BATCH, then re-validate EVERY record against the offloading contract (AC-9).
        let Ok(records) = unframe_batch(record_bytes) else {
            return Err(DeadLetterReason::MalformedBatch);
        };
        if !records.iter().all(|r| self.contract.validate(r)) {
            return Err(DeadLetterReason::ContractViolation);
        }
        Ok((records, sender_id))
    }

    /// Verify + open a received cofre to its plaintext records — the read-only path a CONSUMER edge (e.g. the
    /// Kafka `Fetch` broker) uses to return records WITHOUT the dedup/commit of [`DestTerminal::offload`].
    /// Re-opening the same cofre is idempotent (no dedup state is touched), so a consumer may re-fetch an offset.
    /// Returns `None` if the cofre is rejected (bad seal / wrong route / wrong schema / bad key-wrap / contract
    /// violation) — a forged or cross-route cofre never opens. Provider-blindness is preserved: only the holder
    /// of the dest key (this terminal) can open; the stored ciphertext reveals nothing.
    #[must_use]
    pub fn open(&self, cofre: &Cofre) -> Option<Vec<Vec<u8>>> {
        self.open_records(cofre).ok().map(|(records, _sender)| records)
    }
}

#[cfg(test)]
mod tests;
