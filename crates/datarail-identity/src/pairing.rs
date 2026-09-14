//! **F3** — PAKE short-code bootstrap (SPEC `08` + the three MAJ-5 hardenings).
//!
//! Two endpoints that do not yet know each other's pinned static key bootstrap trust from a short,
//! out-of-band code (read aloud, scanned, etc.). The code is turned into a shared secret with the [`spake2`]
//! balanced PAKE — the SPEC **forbids** rolling our own PAKE (croc `CVE-2021-31603`), so we drive `spake2`
//! and never touch the elliptic-curve math.
//!
//! ## Why a key-confirmation step is mandatory (and not hand-rolled crypto)
//!
//! Bare SPAKE2 derives a key but performs **no key confirmation**: `Spake2::finish` returns `Ok` with a key
//! whether or not the password matched — a wrong code (or a mismatched bound identity) simply yields a
//! *different* key on each side, never an error. So "detect a failed attempt" — the precondition for the
//! attempt-cap and burn hardening — does not exist until we add an explicit confirmation exchange. We add the
//! standard one (as croc / Magic Wormhole do): each side derives a tag with a domain-separated **SHA-256**
//! over the SPAKE2 transcript and the shared key, sends it, and verifies the peer's tag in **constant time**
//! ([`subtle`]). This is a textbook KDF/MAC construction over vetted primitives — not a bespoke PAKE.
//!
//! On top of the PAKE this module implements all three MAJ-5 hardenings:
//!
//! 1. **High-entropy single-use code.** [`ShortCode::generate`] reads `128` bits from `/dev/urandom`
//!    (zero-dep entropy, like the rest of the repo). The code is consumed by exactly one [`Pairing`].
//! 2. **Hard attempt-cap with burn-on-fail.** A [`Pairing`] is a small state machine with a strict cap on
//!    failed confirmations ([`Pairing::MAX_ATTEMPTS`]). Reaching it **burns** the code: every later call
//!    errors with [`PairingError::Burned`] and pairing must restart with a *fresh* code.
//! 3. **Identity binding into the transcript.** Both endpoints' static public keys are bound into the PAKE as
//!    its `id_a` / `id_b` identity inputs **and** folded into the confirmation transcript. Success therefore
//!    proves *which two identities* paired; a man-in-the-middle that substitutes its own static key changes
//!    the bound identities, the derived keys diverge, and confirmation fails.
//!
//! ## Message flow (two short round-trips)
//!
//! ```text
//!   Initiator                                    Responder
//!   ---------                                    ---------
//!   start(code, pk_i, pk_r) -- pake_i -------->  start(code, pk_i, pk_r)
//!                           <-------- pake_r --  (returns its own pake msg)
//!   derive(pake_r) -> tag_i -- tag_i -------->   derive(pake_i) -> tag_r
//!                           <--------- tag_r --
//!   confirm(tag_r) -> key                        confirm(tag_i) -> key
//! ```
//!
//! Both sides obtain the **same** key iff the code matches *and* the bound identities match.
//!
//! ## Usage
//!
//! ```
//! use datarail_identity::pairing::{Pairing, ShortCode};
//!
//! # fn main() -> Result<(), datarail_identity::pairing::PairingError> {
//! let code = ShortCode::generate()?;            // one party mints it and reads it to the other
//! let pk_i = [1u8; 32];                          // each endpoint's static public key
//! let pk_r = [2u8; 32];
//!
//! let (mut init, pake_i) = Pairing::start_initiator(&code, pk_i, pk_r)?;
//! let (mut resp, pake_r) = Pairing::start_responder(&code, pk_i, pk_r)?;
//!
//! let tag_i = init.derive(&pake_r)?;             // exchange PAKE messages, then confirmation tags
//! let tag_r = resp.derive(&pake_i)?;
//!
//! let key_i = init.confirm(&tag_r)?;
//! let key_r = resp.confirm(&tag_i)?;
//! assert_eq!(key_i, key_r);                       // shared secret established
//! # Ok(())
//! # }
//! ```

use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::io::Read as _;
use subtle::ConstantTimeEq as _;

/// Domain-separation label for the bound identities fed into SPAKE2.
const ID_CTX: &[u8] = b"dr:pairing:id:v1";

/// Domain-separation label for the key-confirmation tag derivation.
const CONFIRM_CTX: &[u8] = b"dr:pairing:confirm:v1";

/// Number of random bytes in a [`ShortCode`] (`128` bits of entropy).
pub const SHORT_CODE_LEN: usize = 16;

/// Length of an endpoint static public key bound into the PAKE, in bytes (X25519).
pub const STATIC_PUBLIC_LEN: usize = 32;

/// Length of a key-confirmation tag (SHA-256 output), in bytes.
pub const CONFIRM_TAG_LEN: usize = 32;

/// Errors from the pairing bootstrap (F3).
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairingError {
    /// OS entropy (`/dev/urandom`) could not be read to mint a fresh code.
    Entropy,
    /// A method was called in the wrong order (e.g. [`Pairing::confirm`] before [`Pairing::derive`], or
    /// [`Pairing::derive`] twice).
    WrongState,
    /// The peer's SPAKE2 message was malformed (wrong length / bad side tag / corrupt element).
    BadPeerMessage,
    /// The peer's confirmation tag did not match: a wrong code or mismatched bound identities. The remaining
    /// failed-attempt budget after this failure is reported (`0` = the code is now burned).
    ConfirmFailed {
        /// Failed-attempt budget still available after this failure (`0` = the code is now burned).
        attempts_remaining: u32,
    },
    /// The code has been **burned** by reaching [`Pairing::MAX_ATTEMPTS`]; pairing must restart with a fresh
    /// [`ShortCode`].
    Burned,
}

impl core::fmt::Display for PairingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Entropy => f.write_str("failed to read OS entropy for a pairing code"),
            Self::WrongState => f.write_str("pairing method called out of order"),
            Self::BadPeerMessage => f.write_str("peer PAKE message was malformed"),
            Self::ConfirmFailed { attempts_remaining } => write!(
                f,
                "pairing confirmation failed ({attempts_remaining} attempt(s) left before burn)"
            ),
            Self::Burned => f.write_str("pairing code burned; restart with a fresh code"),
        }
    }
}

impl std::error::Error for PairingError {}

/// A high-entropy, single-use pairing code (hardening #1).
///
/// Minted from `/dev/urandom`. Because the entropy is full (`128` bits) the attempt-cap in [`Pairing`] is
/// belt-and-suspenders rather than the sole defense, but MAJ-5 requires both. Treat the bytes as secret and
/// drop the value promptly after use.
#[derive(Clone)]
pub struct ShortCode {
    bytes: [u8; SHORT_CODE_LEN],
}

impl ShortCode {
    /// Mint a fresh single-use code from `/dev/urandom`.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Entropy`] if the OS entropy source cannot be opened or read.
    pub fn generate() -> Result<Self, PairingError> {
        let mut file = std::fs::File::open("/dev/urandom").map_err(|_| PairingError::Entropy)?;
        let mut bytes = [0u8; SHORT_CODE_LEN];
        file.read_exact(&mut bytes)
            .map_err(|_| PairingError::Entropy)?;
        Ok(Self { bytes })
    }

    /// Construct a code from caller-supplied bytes (e.g. one a user transcribed out-of-band).
    #[must_use]
    pub fn from_bytes(bytes: [u8; SHORT_CODE_LEN]) -> Self {
        Self { bytes }
    }

    /// The raw code bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHORT_CODE_LEN] {
        &self.bytes
    }
}

impl core::fmt::Debug for ShortCode {
    /// Never prints the secret bytes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShortCode(<redacted>)")
    }
}

/// The shared secret produced by a successful pairing (`32` bytes).
pub type PairingOutcome = [u8; 32];

/// Which end of the pairing a [`Pairing`] is. SPAKE2 requires the two sides to be asymmetric (`A` confirms
/// against a `B` message and vice-versa), so we fix the initiator as `A` and the responder as `B`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Initiator,
    Responder,
}

/// Internal lifecycle of a [`Pairing`].
enum Phase {
    /// PAKE started; awaiting the peer's PAKE message via [`Pairing::derive`].
    Started(Box<Spake2<Ed25519Group>>),
    /// Key derived; awaiting the peer's confirmation tag via [`Pairing::confirm`]. Holds our derived key and
    /// the tag we expect from the peer.
    Deriving {
        our_key: [u8; 32],
        expected_peer_tag: [u8; CONFIRM_TAG_LEN],
    },
    /// Confirmed: the shared secret was produced.
    Done,
    /// Burned: the attempt-cap was reached.
    Burned,
}

/// A single pairing session's state machine (hardenings #2 + #3).
///
/// One [`Pairing`] corresponds to one [`ShortCode`] on one endpoint. Drive it: [`start_initiator`] /
/// [`start_responder`] -> [`derive`] -> [`confirm`]. A failed [`confirm`] counts against
/// [`MAX_ATTEMPTS`](Self::MAX_ATTEMPTS); reaching the cap **burns** the code and all further calls return
/// [`PairingError::Burned`].
///
/// [`start_initiator`]: Self::start_initiator
/// [`start_responder`]: Self::start_responder
/// [`derive`]: Self::derive
/// [`confirm`]: Self::confirm
pub struct Pairing {
    phase: Phase,
    side: Side,
    /// Identity transcript bound into both the PAKE and the confirmation tags (hardening #3).
    bound: Vec<u8>,
    failures: u32,
}

impl Pairing {
    /// Maximum number of failed confirmations before the code is burned (hardening #2).
    pub const MAX_ATTEMPTS: u32 = 3;

    /// Start the **initiator** side. `initiator_pk` / `responder_pk` are the two endpoints' static public
    /// keys; both are bound into the PAKE transcript (hardening #3). Returns the pairing state and the
    /// outbound PAKE message to hand to the responder.
    ///
    /// # Errors
    ///
    /// Infallible today; returns `Result` for API symmetry and forward-compatibility.
    pub fn start_initiator(
        code: &ShortCode,
        initiator_pk: [u8; STATIC_PUBLIC_LEN],
        responder_pk: [u8; STATIC_PUBLIC_LEN],
    ) -> Result<(Self, Vec<u8>), PairingError> {
        Ok(Self::start(
            code,
            initiator_pk,
            responder_pk,
            Side::Initiator,
        ))
    }

    /// Start the **responder** side. Arguments mirror [`start_initiator`](Self::start_initiator) — both sides
    /// pass the keys in the *same* `(initiator_pk, responder_pk)` order so the bound identities match.
    ///
    /// # Errors
    ///
    /// Infallible today; returns `Result` for API symmetry and forward-compatibility.
    pub fn start_responder(
        code: &ShortCode,
        initiator_pk: [u8; STATIC_PUBLIC_LEN],
        responder_pk: [u8; STATIC_PUBLIC_LEN],
    ) -> Result<(Self, Vec<u8>), PairingError> {
        Ok(Self::start(
            code,
            initiator_pk,
            responder_pk,
            Side::Responder,
        ))
    }

    fn start(
        code: &ShortCode,
        initiator_pk: [u8; STATIC_PUBLIC_LEN],
        responder_pk: [u8; STATIC_PUBLIC_LEN],
        side: Side,
    ) -> (Self, Vec<u8>) {
        let password = Password::new(code.as_bytes());
        // Bind both static keys, role-tagged and domain-separated, into the SPAKE2 identities AND keep the
        // concatenation as the confirmation transcript.
        let id_a = bound_identity_bytes(b"i", &initiator_pk);
        let id_b = bound_identity_bytes(b"r", &responder_pk);
        let mut bound = Vec::with_capacity(id_a.len() + id_b.len());
        bound.extend_from_slice(&id_a);
        bound.extend_from_slice(&id_b);

        let (spake, outbound) = match side {
            Side::Initiator => Spake2::<Ed25519Group>::start_a(
                &password,
                &Identity::new(&id_a),
                &Identity::new(&id_b),
            ),
            Side::Responder => Spake2::<Ed25519Group>::start_b(
                &password,
                &Identity::new(&id_a),
                &Identity::new(&id_b),
            ),
        };
        let pairing = Self {
            phase: Phase::Started(Box::new(spake)),
            side,
            bound,
            failures: 0,
        };
        (pairing, outbound)
    }

    /// Process the peer's PAKE message, derive the (unconfirmed) shared key, and return **our** confirmation
    /// tag to send to the peer.
    ///
    /// This step always succeeds for a well-formed peer message — SPAKE2 yields a key regardless of whether
    /// the code matched. Whether the key is the *right* one is decided later, in [`confirm`](Self::confirm).
    ///
    /// # Errors
    ///
    /// - [`PairingError::Burned`] if the code is already burned.
    /// - [`PairingError::WrongState`] if called more than once or after [`confirm`](Self::confirm).
    /// - [`PairingError::BadPeerMessage`] if the peer's PAKE message is malformed.
    pub fn derive(&mut self, peer_pake_msg: &[u8]) -> Result<[u8; CONFIRM_TAG_LEN], PairingError> {
        let spake = match core::mem::replace(&mut self.phase, Phase::Burned) {
            Phase::Started(spake) => *spake,
            Phase::Burned => return Err(PairingError::Burned),
            other => {
                // Restore and reject: derive is only valid once, from Started.
                self.phase = other;
                return Err(PairingError::WrongState);
            }
        };
        let key_vec = spake
            .finish(peer_pake_msg)
            .map_err(|_| PairingError::BadPeerMessage)?;
        let our_key = to_key32(&key_vec).ok_or(PairingError::BadPeerMessage)?;

        // Our tag confirms our key under our role; the peer expects the complementary role's tag.
        let our_tag = confirm_tag(self.side, &self.bound, &our_key);
        let expected_peer_tag = confirm_tag(self.side.peer(), &self.bound, &our_key);

        self.phase = Phase::Deriving {
            our_key,
            expected_peer_tag,
        };
        Ok(our_tag)
    }

    /// Verify the peer's confirmation tag and, on success, return the shared secret.
    ///
    /// A wrong code or mismatched bound identity makes the two sides derive different keys, so the peer's tag
    /// will not match ours: the failure is counted, and the [`MAX_ATTEMPTS`](Self::MAX_ATTEMPTS)-th failure
    /// burns the code.
    ///
    /// # Errors
    ///
    /// - [`PairingError::Burned`] if the code is already burned.
    /// - [`PairingError::WrongState`] if called before [`derive`](Self::derive) or after success.
    /// - [`PairingError::ConfirmFailed`] on a tag mismatch (carrying the remaining budget); the cap-th
    ///   failure reports `attempts_remaining == 0` and burns the code.
    pub fn confirm(&mut self, peer_tag: &[u8]) -> Result<PairingOutcome, PairingError> {
        let (our_key, expected_peer_tag) = match &self.phase {
            Phase::Deriving {
                our_key,
                expected_peer_tag,
            } => (*our_key, *expected_peer_tag),
            Phase::Burned => return Err(PairingError::Burned),
            Phase::Started(_) | Phase::Done => return Err(PairingError::WrongState),
        };

        if bool::from(expected_peer_tag.ct_eq(peer_tag)) {
            self.phase = Phase::Done;
            Ok(our_key)
        } else {
            self.register_failure()
        }
    }

    /// Count a failed confirmation; burn on reaching the cap.
    fn register_failure(&mut self) -> Result<PairingOutcome, PairingError> {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= Self::MAX_ATTEMPTS {
            self.phase = Phase::Burned;
            return Err(PairingError::ConfirmFailed {
                attempts_remaining: 0,
            });
        }
        // Stay in `Deriving`: the same key is still held, so the caller may retry `confirm` with another tag
        // (e.g. a fresh peer message exchanged out of band) without re-running the PAKE.
        Err(PairingError::ConfirmFailed {
            attempts_remaining: Self::MAX_ATTEMPTS - self.failures,
        })
    }

    /// Whether the code has been burned (cap reached).
    #[must_use]
    pub fn is_burned(&self) -> bool {
        matches!(self.phase, Phase::Burned)
    }

    /// Whether this pairing already produced a shared secret.
    #[must_use]
    pub fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done)
    }

    /// Failed-confirmation budget still remaining before the code burns.
    #[must_use]
    pub fn attempts_remaining(&self) -> u32 {
        Self::MAX_ATTEMPTS.saturating_sub(self.failures)
    }
}

impl Side {
    /// The complementary side.
    fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }

    /// A stable byte tag for the role, mixed into confirmation tags.
    fn tag_byte(self) -> u8 {
        match self {
            Self::Initiator => b'i',
            Self::Responder => b'r',
        }
    }
}

/// Build the role-tagged, domain-separated identity bytes binding an endpoint's static public key
/// (hardening #3). Identical inputs on both sides -> identical bytes -> identical derived key.
fn bound_identity_bytes(role_tag: &[u8], static_pk: &[u8; STATIC_PUBLIC_LEN]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ID_CTX.len() + 1 + role_tag.len() + STATIC_PUBLIC_LEN);
    buf.extend_from_slice(ID_CTX);
    buf.push(b':');
    buf.extend_from_slice(role_tag);
    buf.extend_from_slice(static_pk);
    buf
}

/// Derive a key-confirmation tag for `side` over the bound-identity transcript and the SPAKE2 shared key,
/// domain-separated. (A standard KDF-as-MAC: `SHA-256(ctx || side || bound || key)`.)
fn confirm_tag(side: Side, bound: &[u8], key: &[u8; 32]) -> [u8; CONFIRM_TAG_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(CONFIRM_CTX);
    hasher.update([side.tag_byte()]);
    hasher.update((bound.len() as u64).to_le_bytes());
    hasher.update(bound);
    hasher.update(key);
    hasher.finalize().into()
}

/// Convert SPAKE2's `Vec<u8>` key into a fixed `[u8; 32]`, or `None` if the length is unexpected.
fn to_key32(key: &[u8]) -> Option<[u8; 32]> {
    let arr: [u8; 32] = key.try_into().ok()?;
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::{Pairing, PairingError, ShortCode};

    const PK_I: [u8; 32] = [0x11; 32];
    const PK_R: [u8; 32] = [0x22; 32];

    // Test (a): same code + matching bound identities on both sides -> identical shared secret.
    #[test]
    fn matching_code_and_identities_agree() {
        let code = ShortCode::generate().unwrap();

        let (mut init, pake_i) = Pairing::start_initiator(&code, PK_I, PK_R).unwrap();
        let (mut resp, pake_r) = Pairing::start_responder(&code, PK_I, PK_R).unwrap();
        let tag_i = init.derive(&pake_r).unwrap();
        let tag_r = resp.derive(&pake_i).unwrap();

        let key_i = init.confirm(&tag_r).expect("initiator should confirm");
        let key_r = resp.confirm(&tag_i).expect("responder should confirm");

        assert_eq!(
            key_i, key_r,
            "matching code+identities must yield one secret"
        );
        assert_ne!(key_i, [0u8; 32]);
        assert!(init.is_done() && resp.is_done());
    }

    // The generated code is full-entropy: two mints differ with overwhelming probability.
    #[test]
    fn generated_codes_are_random() {
        let a = ShortCode::generate().unwrap();
        let b = ShortCode::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    // Test (b): a wrong code fails confirmation, and after MAX_ATTEMPTS failures the code is BURNED — every
    // later call errors with `Burned`.
    #[test]
    fn wrong_code_fails_then_burns() {
        let real = ShortCode::from_bytes([0xAB; 16]);
        let wrong = ShortCode::from_bytes([0xCD; 16]);

        // Honest peer derives its tag from the REAL code; matching identities.
        let (mut peer, peer_pake) = Pairing::start_responder(&real, PK_I, PK_R).unwrap();

        // Our side holds the WRONG code.
        let (mut ours, our_pake) = Pairing::start_initiator(&wrong, PK_I, PK_R).unwrap();

        // Both derive (always succeeds); keys differ -> tags differ.
        let peer_tag = peer.derive(&our_pake).unwrap();
        let _our_tag = ours.derive(&peer_pake).unwrap();

        // Failure 1 of MAX_ATTEMPTS (=3): two left.
        assert_eq!(
            ours.confirm(&peer_tag).unwrap_err(),
            PairingError::ConfirmFailed {
                attempts_remaining: 2
            }
        );
        assert!(!ours.is_burned());

        // Failure 2: one left.
        assert_eq!(
            ours.confirm(&peer_tag).unwrap_err(),
            PairingError::ConfirmFailed {
                attempts_remaining: 1
            }
        );
        assert!(!ours.is_burned());

        // Failure 3: budget hits zero and the code burns.
        assert_eq!(
            ours.confirm(&peer_tag).unwrap_err(),
            PairingError::ConfirmFailed {
                attempts_remaining: 0
            }
        );
        assert!(ours.is_burned());

        // Subsequent attempts error with `Burned`; even a (hypothetically) correct tag cannot revive it.
        assert_eq!(ours.confirm(&peer_tag).unwrap_err(), PairingError::Burned);
        assert_eq!(ours.attempts_remaining(), 0);
        // `derive` after burn is also rejected.
        assert_eq!(ours.derive(&peer_pake).unwrap_err(), PairingError::Burned);
    }

    // Test (c): same code but MISMATCHED bound identities (a MITM substitutes a static key) -> the derived
    // keys diverge and confirmation fails. This is the identity-binding hardening in action.
    #[test]
    fn mismatched_bound_identities_fail() {
        let code = ShortCode::from_bytes([0x42; 16]);
        let attacker_pk = [0x99; 32];

        // Initiator binds (PK_I, PK_R); responder was tricked into binding (PK_I, attacker_pk).
        let (mut init, pake_i) = Pairing::start_initiator(&code, PK_I, PK_R).unwrap();
        let (mut resp, pake_r) = Pairing::start_responder(&code, PK_I, attacker_pk).unwrap();

        let _tag_i = init.derive(&pake_r).unwrap();
        let tag_r = resp.derive(&pake_i).unwrap();

        let r = init.confirm(&tag_r);
        assert!(
            matches!(r, Err(PairingError::ConfirmFailed { .. })),
            "mismatched bound identities must fail confirmation, got {r:?}"
        );
        assert!(!init.is_done());
    }

    // State-machine guards: confirm-before-derive and double-derive are rejected.
    #[test]
    fn out_of_order_calls_are_rejected() {
        let code = ShortCode::from_bytes([0x01; 16]);
        let (mut init, _pake_i) = Pairing::start_initiator(&code, PK_I, PK_R).unwrap();
        // confirm before derive
        assert_eq!(
            init.confirm(&[0u8; 32]).unwrap_err(),
            PairingError::WrongState
        );

        let (_resp, pake_r) = Pairing::start_responder(&code, PK_I, PK_R).unwrap();
        init.derive(&pake_r).unwrap();
        // derive twice
        assert_eq!(init.derive(&pake_r).unwrap_err(), PairingError::WrongState);
    }

    // A malformed peer PAKE message is rejected cleanly (not a panic).
    #[test]
    fn malformed_peer_message_is_rejected() {
        let code = ShortCode::from_bytes([0x07; 16]);
        let (mut init, _pake_i) = Pairing::start_initiator(&code, PK_I, PK_R).unwrap();
        assert_eq!(
            init.derive(b"too-short").unwrap_err(),
            PairingError::BadPeerMessage
        );
    }
}
