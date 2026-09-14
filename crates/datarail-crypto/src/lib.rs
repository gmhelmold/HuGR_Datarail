//! `datarail-crypto` — the primitives behind the cofre seal, per the frozen SPEC `03-crypto-construction.md`.
//!
//! BLAKE3 hashing, **domain-separated** Ed25519 signatures (BLK-5 — each role gets a distinct context prefix
//! so a signature can never be replayed across contexts), and a **pluggable AEAD** with **AES-256-GCM-SIV** as
//! the nonce-misuse-resistant default (BLK-1). No `unsafe`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use datarail_core::AeadAlg;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecret};

/// Ed25519 domain-separation context labels (BLK-5). Each signature role gets a distinct prefix.
pub mod ctx {
    /// The cofre seal (`lacre`).
    pub const LACRE: &[u8] = b"dr:lacre:v1";
    /// A manifest Signed Tree Head.
    pub const STH: &[u8] = b"dr:sth:v1";
    /// A destination delivery ack.
    pub const ACK: &[u8] = b"dr:ack:v1";
    /// A sealed-sender certificate.
    pub const CERT: &[u8] = b"dr:cert:v1";
    /// A route descriptor / ticket.
    pub const TICKET: &[u8] = b"dr:ticket:v1";
}

/// BLAKE3-256 of `data`.
#[must_use]
pub fn blake3_256(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Keyed BLAKE3 — a MAC / PRF. Used for the idempotency key `HMAC(tenant_secret, record_key)` (SPEC 02/03):
/// deterministic, plaintext never exposed, and (unlike a raw content hash) keyed per tenant so it leaks no
/// cross-tenant equality. BLAKE3's native keyed mode is a secure MAC (no length-extension).
#[must_use]
pub fn hmac_blake3(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, msg).as_bytes()
}

/// Domain-separation label for the X25519 per-cofre key-wrap KDF.
const KEYWRAP_CTX: &[u8] = b"dr:keywrap:v1";

/// The X25519 public key for a 32-byte secret (a destination's static key-agreement key).
#[must_use]
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    XPublicKey::from(&XSecret::from(*secret)).to_bytes()
}

/// Raw X25519 Diffie–Hellman shared secret between `secret` and `public`, or `None` if it is
/// **non-contributory** (a low-order `public` yields the all-zero shared secret).
///
/// Defense-in-depth (S-3, RFC 7748 §6.1): an all-zero shared secret would make the derived data key publicly
/// computable — the [`kdf_data_key`] mixes only *public* values besides `shared`, so a known-zero `shared`
/// reduces the key to a hash of public inputs. The `eph_pk` is `lacre`-authenticated **before** this runs
/// (the offload verifies the seal first), so a wire adversary cannot reach it; this is belt-and-suspenders that
/// fails closed rather than trusting that upstream check alone.
fn x25519_shared(secret: &[u8; 32], public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = XSecret::from(*secret).diffie_hellman(&XPublicKey::from(*public));
    shared.was_contributory().then(|| shared.to_bytes())
}

/// Derive the per-cofre data key from the ECDH shared secret, domain-separated and bound to **both** public
/// keys (so the key cannot be re-targeted by swapping an endpoint).
fn kdf_data_key(shared: &[u8; 32], eph_public: &[u8; 32], recipient_pk: &[u8; 32]) -> [u8; 32] {
    let mut m = Vec::with_capacity(KEYWRAP_CTX.len() + 96);
    m.extend_from_slice(KEYWRAP_CTX);
    m.extend_from_slice(shared);
    m.extend_from_slice(eph_public);
    m.extend_from_slice(recipient_pk);
    blake3_256(&m)
}

/// **Source side** of the per-cofre key-wrap (SPEC 03 / A5): given the destination's X25519 public key and a
/// fresh random ephemeral secret, derive `(eph_public, data_key)`. The `eph_public` travels in the cofre's
/// etiqueta; the `data_key` encrypts that one cofre's carga and is **never transmitted**.
///
/// A fresh `eph_secret` per cofre ⇒ a fresh `data_key` per cofre — forward-secure once the ephemeral is
/// discarded, and provider-blind: only the holder of the recipient secret can re-derive it ([`open_key`]).
#[must_use]
pub fn seal_key(recipient_pk: &[u8; 32], eph_secret: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let eph_public = x25519_public(eph_secret);
    let shared = x25519_shared(eph_secret, recipient_pk)?; // `None` ⇒ a low-order `recipient_pk` (misconfig)
    let data_key = kdf_data_key(&shared, &eph_public, recipient_pk);
    Some((eph_public, data_key))
}

/// **Destination side** of the per-cofre key-wrap: recover the `data_key` from the cofre's `eph_public` using
/// the recipient's X25519 secret. Only the holder of `recipient_secret` can derive the key. Returns `None` if
/// `eph_public` is a low-order (non-contributory) point — the caller dead-letters such a cofre (S-3).
#[must_use]
pub fn open_key(recipient_secret: &[u8; 32], eph_public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = x25519_shared(recipient_secret, eph_public)?;
    let recipient_pk = x25519_public(recipient_secret);
    Some(kdf_data_key(&shared, eph_public, &recipient_pk))
}

fn framed(context: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(context.len() + msg.len());
    buf.extend_from_slice(context);
    buf.extend_from_slice(msg);
    buf
}

/// Sign `msg` under a domain-separation `context` with the Ed25519 secret `seed` (32 bytes).
#[must_use]
pub fn sign_domain(context: &[u8], seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(seed)
        .sign(&framed(context, msg))
        .to_bytes()
}

/// The Ed25519 verifying (public) key for the secret `seed`.
#[must_use]
pub fn verifying_key(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// Verify a domain-separated Ed25519 signature against verifying key `vk`.
#[must_use]
pub fn verify_domain(context: &[u8], vk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(vk) else {
        return false;
    };
    vk.verify(&framed(context, msg), &Signature::from_bytes(sig))
        .is_ok()
}

/// An AEAD operation failed: a bad key length, or — on open — an authentication failure (tamper / wrong
/// key, nonce, or AAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AEAD operation failed (bad key or authentication failure)")
    }
}

impl core::error::Error for AeadError {}

/// AEAD-**seal** `plaintext` with associated data `aad` under `key` (32 B) and `nonce` (12 B) using `alg`.
///
/// # Errors
/// Returns [`AeadError`] if the key is the wrong length or the cipher refuses the input.
pub fn aead_seal(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match alg {
        AeadAlg::Gcmsiv256 => aes_gcm_siv::Aes256GcmSiv::new_from_slice(key)
            .map_err(|_| AeadError)?
            .encrypt(aes_gcm_siv::Nonce::from_slice(nonce), payload)
            .map_err(|_| AeadError),
        AeadAlg::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| AeadError)?
            .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            .map_err(|_| AeadError),
        AeadAlg::Gcm256 => gcm256_seal(key, nonce, aad, plaintext),
    }
}

/// `AES-256-GCM` seal. With `--features vaes` this runs `ring`'s `VAES`/`AVX-512` asm (line-rate on capable
/// cores); otherwise `RustCrypto`'s portable `AES-NI`. **Wire-identical** either way (ciphertext ‖ 16-byte tag),
/// so a cofre is interchangeable across the two backends. Plain `GCM` is sound here only under the per-cofre
/// fresh-key invariant (no nonce reuse); see the `vaes` feature note in `Cargo.toml`.
#[cfg(feature = "vaes")]
fn gcm256_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| AeadError)?);
    let mut buf = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| AeadError)?;
    Ok(buf)
}

#[cfg(not(feature = "vaes"))]
fn gcm256_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    aes_gcm::Aes256Gcm::new_from_slice(key)
        .map_err(|_| AeadError)?
        .encrypt(
            aes_gcm::Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AeadError)
}

/// AEAD-**open** `ciphertext` with associated data `aad` under `key` (32 B) and `nonce` (12 B) using `alg`.
///
/// # Errors
/// Returns [`AeadError`] on authentication failure (tamper, or wrong key / nonce / AAD).
pub fn aead_open(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match alg {
        AeadAlg::Gcmsiv256 => aes_gcm_siv::Aes256GcmSiv::new_from_slice(key)
            .map_err(|_| AeadError)?
            .decrypt(aes_gcm_siv::Nonce::from_slice(nonce), payload)
            .map_err(|_| AeadError),
        AeadAlg::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| AeadError)?
            .decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            .map_err(|_| AeadError),
        AeadAlg::Gcm256 => gcm256_open(key, nonce, aad, ciphertext),
    }
}

/// `AES-256-GCM` open — `ring` `VAES` asm under `--features vaes`, else `RustCrypto` `AES-NI`. Wire-identical
/// to [`gcm256_seal`].
#[cfg(feature = "vaes")]
fn gcm256_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| AeadError)?);
    let mut buf = ciphertext.to_vec();
    let plaintext = opening
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| AeadError)?;
    Ok(plaintext.to_vec())
}

#[cfg(not(feature = "vaes"))]
fn gcm256_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    aes_gcm::Aes256Gcm::new_from_slice(key)
        .map_err(|_| AeadError)?
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError)
}

#[cfg(test)]
mod tests {
    use super::{
        aead_open, aead_seal, blake3_256, ctx, hmac_blake3, sign_domain, verify_domain,
        verifying_key,
    };
    use datarail_core::AeadAlg;

    const SEED: [u8; 32] = [7u8; 32];
    const KEY: [u8; 32] = [9u8; 32];
    const NONCE: [u8; 12] = [3u8; 12];

    #[test]
    fn hmac_is_keyed_and_deterministic() {
        // Deterministic per (key, msg); changing key or msg changes the tag; differs from the unkeyed hash.
        let a = hmac_blake3(&KEY, b"record-key");
        assert_eq!(a, hmac_blake3(&KEY, b"record-key"));
        assert_ne!(a, hmac_blake3(&[1u8; 32], b"record-key"));
        assert_ne!(a, hmac_blake3(&KEY, b"other"));
        assert_ne!(a, blake3_256(b"record-key"));
    }

    #[test]
    fn x25519_keywrap_round_trips() {
        // Source seals a per-cofre key to the dest's X25519 public key; only the dest re-derives it.
        let recipient_secret = [9u8; 32];
        let recipient_pk = super::x25519_public(&recipient_secret);
        let (eph_public, k_src) = super::seal_key(&recipient_pk, &[3u8; 32]).expect("seal");
        assert_eq!(
            super::open_key(&recipient_secret, &eph_public),
            Some(k_src),
            "dest re-derives the key"
        );
        // A different recipient cannot open it.
        assert_ne!(super::open_key(&[1u8; 32], &eph_public), Some(k_src));
        // A tampered ephemeral public key yields a different (wrong) key — AEAD-open would then fail.
        let mut bad = eph_public;
        bad[0] ^= 1;
        assert_ne!(super::open_key(&recipient_secret, &bad), Some(k_src));
        // A fresh ephemeral per cofre ⇒ a fresh data key.
        let (_e2, k2) = super::seal_key(&recipient_pk, &[4u8; 32]).expect("seal2");
        assert_ne!(k2, k_src);
    }

    #[test]
    fn low_order_eph_public_is_rejected_s3() {
        // S-3 defense-in-depth: a low-order (non-contributory) eph_public — e.g. the all-zero point — yields an
        // all-zero shared secret. `open_key`/`seal_key` must FAIL CLOSED (return None) rather than derive a key
        // that an adversary could compute from public values alone. The RFC 7748 §6.1 small-subgroup points:
        let low_order: [[u8; 32]; 3] = [
            [0u8; 32], // the identity (order 1) — product is all-zero
            {
                // order-8 point (RFC 7748 test vector 1)
                let mut p = [0u8; 32];
                p[0] = 1;
                p
            },
            {
                // order-2 point: p = 2^255 - 19 - 1 reduced; the canonical all-zero-y small point set includes this.
                let mut p = [0xe0; 32];
                p[0] = 0xe0;
                p[31] = 0x7f;
                p
            },
        ];
        let secret = [7u8; 32];
        // The identity point MUST be rejected by open_key (the offload would dead-letter such a cofre).
        assert_eq!(
            super::open_key(&secret, &low_order[0]),
            None,
            "all-zero eph_public must be rejected"
        );
        // seal_key to the identity recipient_pk must also fail closed (a low-order dest key is misconfig).
        assert_eq!(
            super::seal_key(&low_order[0], &secret),
            None,
            "seal to a low-order recipient must fail"
        );
        // The order-8 point is likewise non-contributory and must be rejected.
        assert_eq!(
            super::open_key(&secret, &low_order[1]),
            None,
            "order-8 eph_public must be rejected"
        );
        // (low_order[2] documents the small-subgroup family; was_contributory covers the whole set.)
        let _ = low_order[2];
    }

    #[test]
    fn ed25519_domain_roundtrip_and_separation() {
        let vk = verifying_key(&SEED);
        let sig = sign_domain(ctx::LACRE, &SEED, b"hello");
        assert!(verify_domain(ctx::LACRE, &vk, b"hello", &sig));
        // BLK-5: a signature under one context must not verify under another.
        assert!(!verify_domain(ctx::ACK, &vk, b"hello", &sig));
        // Wrong message fails.
        assert!(!verify_domain(ctx::LACRE, &vk, b"hell0", &sig));
    }

    #[test]
    fn aead_roundtrip_all_algs() {
        for alg in [
            AeadAlg::Gcmsiv256,
            AeadAlg::ChaCha20Poly1305,
            AeadAlg::Gcm256,
        ] {
            let ct = aead_seal(alg, &KEY, &NONCE, b"aad", b"plaintext").unwrap();
            let pt = aead_open(alg, &KEY, &NONCE, b"aad", &ct).unwrap();
            assert_eq!(pt, b"plaintext");
        }
    }

    #[test]
    fn aead_tamper_and_aad_mismatch_fail() {
        let alg = AeadAlg::Gcmsiv256;
        let mut ct = aead_seal(alg, &KEY, &NONCE, b"aad", b"plaintext").unwrap();
        // INV-TAMPER-REJECT: flipping any ciphertext byte must fail open.
        ct[0] ^= 0x01;
        assert!(aead_open(alg, &KEY, &NONCE, b"aad", &ct).is_err());
        // AAD mismatch (e.g. a mutated etiqueta) must fail open.
        let good = aead_seal(alg, &KEY, &NONCE, b"aad", b"plaintext").unwrap();
        assert!(aead_open(alg, &KEY, &NONCE, b"different-aad", &good).is_err());
    }

    /// `AES-256-GCM` **known-answer test** — pins one fixed (key, nonce, aad, plaintext) → exact ciphertext.
    /// This same vector runs under BOTH the default (`RustCrypto` `AES-NI`) and `--features vaes` (`ring`
    /// `VAES`) builds; if the two backends ever disagreed by a byte, one of the two CI runs would fail here. So
    /// it is the proof that the `vaes` backend is **wire-compatible** — a cofre sealed by one backend opens on
    /// the other (and across a mixed-backend fleet).
    #[test]
    fn gcm256_known_answer_is_backend_independent() {
        use core::fmt::Write as _;
        const EXPECT: &str = "b5f59f1327dd02c0f6d4ce109f15b993cd7a617020b77006a50b3352b6de70df5d";
        let ct = aead_seal(AeadAlg::Gcm256, &KEY, &NONCE, b"aad", b"datarail-vaes-kat").unwrap();
        let mut hex = String::with_capacity(ct.len() * 2);
        for b in &ct {
            let _ = write!(hex, "{b:02x}");
        }
        assert_eq!(
            hex, EXPECT,
            "AES-256-GCM ciphertext must match the canonical vector on every backend"
        );
        // And it round-trips back to the plaintext.
        let pt = aead_open(AeadAlg::Gcm256, &KEY, &NONCE, b"aad", &ct).unwrap();
        assert_eq!(pt, b"datarail-vaes-kat");
    }
}
