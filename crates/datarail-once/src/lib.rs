//! `datarail-once` — effectively-once (SPEC `05-effectively-once.md`): a bounded dedup index, a signed
//! monotonic low-watermark with **reject-below**, and crash/retry/partition safety.
//!
//! The destination's admission decision (transcribed from SPEC 05 / BLK-6):
//! 1. **Reject-below, not merely lookup (BLK-6):** keep a *signed monotonic low-watermark per stream* and
//!    refuse to re-commit any arriving `seq` *below* it outright — a below-watermark `seq` is already durably
//!    committed, so admitting it would risk a GC-vs-replay double-commit. It is reported as a benign
//!    [`Disposition::Duplicate`] (drop + re-ack), never re-committed. (`DeadLettered` is the terminal's domain
//!    — seal/contract failure, before this gate.)
//! 2. **Dedup:** an arriving `idempotency_key` already in the dedup index ⇒ [`Disposition::Duplicate`]
//!    (idempotent drop + re-ack).
//! 3. Otherwise **commit**: record the key, return [`Disposition::Delivered`], and advance the contiguous
//!    low-watermark across every already-delivered `seq`.
//!
//! GC of the dedup index lags the **dest watermark — NOT a source checkpoint** (BLK-6): a key is GC-eligible
//! only once the dest watermark has advanced past its `seq`, so no still-replayable `seq` can fall through a
//! GC'd slot.
//!
//! AC-4 (*"acked at boarding ⇒ offloaded exactly once"*) is proven by the **deterministic simulation test**
//! (`tests/ac4_dst.rs`): a seeded, fault-injecting in-memory pipe (drop / reorder / duplicate / kill-and-
//! respawn) over N seeds, asserting **0 acked-loss and 0 duplicate** committed at the sink.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use datarail_core::Disposition;
use datarail_crypto::{sign_domain, verify_domain};

pub mod persist;
pub use persist::FileOnce;

/// A per-stream durable checkpoint: `(stream, low_watermark, above-watermark (seq, key) entries)` — see
/// [`Once::checkpoints`] / [`FileOnce`].
pub type StreamCheckpoint = ([u8; 16], u64, Vec<(u64, [u8; 32])>);

/// Domain-separation label for a signed low-watermark token (BLK-5 style; local to this crate — the frozen
/// `datarail_crypto::ctx` has no watermark role).
const WM_CTX: &[u8] = b"dr:once:wm:v1";

/// Per-stream effectively-once state: the dedup index, the contiguous low-watermark, and the set of
/// delivered-but-not-yet-contiguous `seq`s used to advance it.
//
// TODO(MAJ-2, SPEC 05 §"Dedup index"): for v1 the dedup index is an in-RAM `HashSet<[u8;32]>`. The SPEC
// calls for a **bloom-filter prefilter (in-RAM, fast negative) fronting an on-disk authoritative map**, with
// dead-letter + sealed gap-skip on bloom/map overflow. That bounded, persisted index is a later optimization;
// the membership *semantics* below are the contract it must preserve.
#[derive(Debug, Default)]
struct StreamState {
    /// Authoritative dedup membership, keyed by `idempotency_key` (BLK: the *sole* dedup key).
    seen: HashSet<[u8; 32]>,
    /// `seq` → `idempotency_key` for every delivered record at or above the GC floor (lets GC drop keys from
    /// `seen` as the watermark advances past their `seq`).
    delivered_keys: HashMap<u64, [u8; 32]>,
    /// Delivered `seq`s strictly **above** `low_watermark` (the reorder horizon), used to advance the
    /// contiguous floor as gaps fill.
    ahead: HashSet<u64>,
    /// Monotonic contiguous low-watermark: every `seq < low_watermark` is durably committed. An arriving
    /// `seq < low_watermark` is rejected (BLK-6).
    low_watermark: u64,
    /// The GC floor: keys for `seq < gc_floor` have been compacted out of `seen`. Lags `low_watermark` by
    /// `gc_lag` (BLK-6: bound to the **dest watermark**, never a source checkpoint).
    gc_floor: u64,
}

/// The effectively-once admission gate for one destination: a dedup index + signed monotonic low-watermark
/// **per `stream_id`**.
///
/// Construct with [`Once::new`], drive with [`Once::admit`]. The watermark is signed with the destination's
/// Ed25519 `seed`; expose it to peers via [`Once::signed_watermark`] (verify with [`verify_watermark`]).
pub struct Once {
    streams: HashMap<[u8; 16], StreamState>,
    /// Ed25519 secret for signing watermark tokens.
    seed: [u8; 32],
    /// How far the dedup-GC floor trails the dest low-watermark (BLK-6). This is a **dedup-retention /
    /// re-ack-cost** knob, **not** a correctness knob: GC is keyed off the *contiguous* low-watermark, and
    /// reject-below (evaluated *before* the dedup lookup) catches any replay of a GC'd `seq` — so exactly-once
    /// holds for **any** `gc_lag` (including 0). A larger lag just keeps keys longer, so at-least-once
    /// redeliveries are reported `Duplicate` rather than harmlessly re-admitted. (AUDIT-02 correctness note.)
    gc_lag: u64,
}

/// Wipe the Ed25519 watermark-signing `seed` from memory when the gate is dropped (defense-in-depth: a
/// long-lived secret should not linger in freed heap / a core dump / swap — complements the redacting `Debug`).
impl Drop for Once {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.seed);
    }
}

/// Redacting `Debug` (AUDIT-02): never print the Ed25519 watermark-signing `seed`.
impl core::fmt::Debug for Once {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Once")
            .field("streams", &self.streams)
            .field("seed", &"<redacted>")
            .field("gc_lag", &self.gc_lag)
            .finish()
    }
}

/// Default GC lag — how far the dedup-GC floor trails the dest low-watermark (BLK-6).
///
/// Sized to comfortably exceed a bounded reorder window + replay horizon for v1.
pub const DEFAULT_GC_LAG: u64 = 1024;

/// Max parked (above-watermark) seqs before the reorder horizon seals the lowest gap (audit D-5). A permanently
/// missing `seq` must not pin the watermark forever and grow the dedup index without bound; past this horizon the
/// gap is sealed (the watermark advances across the missing `seq`, which is thereafter reject-below'd). This is a
/// deliberate availability-over-completeness bound for a stuck gap; it is far above any real reorder window.
pub const MAX_REORDER_HORIZON: usize = 1 << 20;

impl Once {
    /// Create an admission gate signing watermark tokens under the destination Ed25519 `seed`, with the
    /// [`DEFAULT_GC_LAG`].
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self::with_gc_lag(seed, DEFAULT_GC_LAG)
    }

    /// As [`Once::new`], but with an explicit GC lag (a dedup-retention knob — correct for **any** value; see
    /// the [`gc_lag`](Self#structfield.gc_lag) field doc). A smaller lag bounds the dedup index and exercises
    /// the GC path; the AC-4 DST uses a small lag deliberately.
    #[must_use]
    pub fn with_gc_lag(seed: [u8; 32], gc_lag: u64) -> Self {
        Self {
            streams: HashMap::new(),
            seed,
            gc_lag,
        }
    }

    /// Admit a received record for `stream` at sequence `seq` with dedup key `idempotency_key`, returning the
    /// [`Disposition`] the destination should act on. **Pure decision + state update; no I/O.**
    ///
    /// Order of checks (SPEC 05 / BLK-6). The once gate only ever decides Delivered vs Duplicate — it has no
    /// failure mode (`DeadLettered` is the terminal's domain: seal/contract failure, *before* this gate):
    /// - `seq` **below** the stream's monotonic low-watermark ⇒ [`Disposition::Duplicate`] (reject-below; the
    ///   `seq` is already durably committed — a benign already-delivered redelivery: drop + re-ack, never
    ///   re-commit). Fires *before* the dedup lookup, so it holds even if the key was GC'd (BLK-6).
    /// - `idempotency_key` already seen ⇒ [`Disposition::Duplicate`] (a redelivery of a `seq` still at/above
    ///   the watermark — a parked, not-yet-contiguous one).
    /// - otherwise ⇒ [`Disposition::Delivered`]: the key is recorded and the contiguous low-watermark is
    ///   advanced across every already-delivered `seq`.
    pub fn admit(&mut self, stream: [u8; 16], seq: u64, idempotency_key: [u8; 32]) -> Disposition {
        let gc_lag = self.gc_lag;
        let st = self.streams.entry(stream).or_default();

        // (1) Reject-below the monotonic low-watermark (BLK-6) — *before* any dedup lookup, so it holds even
        // if the key was GC'd. A below-watermark seq is already durably committed: a benign already-delivered
        // redelivery -> Duplicate (drop + re-ack, never re-commit). DeadLettered is the terminal's domain
        // (seal/contract failure, before this gate); the once gate only ever sees verified cofres.
        if seq < st.low_watermark {
            return Disposition::Duplicate;
        }

        // (2) Dedup on the sole key. At/above the watermark we may still have seen this exact key (an
        // at-least-once redelivery of a not-yet-contiguous seq).
        if st.seen.contains(&idempotency_key) {
            return Disposition::Duplicate;
        }

        // (2b) Seq-level dedup above the watermark (audit HIGH): a seq is committed ONCE regardless of key.
        // Without this, a redelivery of an already-delivered (but not-yet-contiguous) seq carrying a *different*
        // idempotency_key would slip past (2) and be Delivered twice. `delivered_keys` is never GC'd above the
        // watermark (gc_floor < low_watermark <= seq), so this check is reliable for any at/above-watermark seq.
        if st.delivered_keys.contains_key(&seq) {
            return Disposition::Duplicate;
        }

        // (3) Commit: record the key, then advance the contiguous floor.
        st.seen.insert(idempotency_key);
        st.delivered_keys.insert(seq, idempotency_key);
        if seq == st.low_watermark {
            st.low_watermark += 1;
            // Drain any contiguous run that earlier arrived out of order.
            while st.ahead.remove(&st.low_watermark) {
                st.low_watermark += 1;
            }
        } else {
            // seq > low_watermark: a gap remains; park it on the reorder horizon.
            st.ahead.insert(seq);
            // (3b) Bound the reorder horizon (audit D-5): a permanently-missing seq must not pin the watermark
            // and grow `ahead`/`seen` without bound. Past the horizon, seal the lowest gap — advance the
            // watermark across the missing seq (sealed-skip; it is thereafter reject-below'd) and drain any now-
            // contiguous parked run. Availability-over-completeness for a stuck gap; never triggers in normal
            // reorder. (The subsequent GC step then trims `seen` as the watermark moves.)
            while st.ahead.len() > MAX_REORDER_HORIZON {
                st.low_watermark += 1;
                while st.ahead.remove(&st.low_watermark) {
                    st.low_watermark += 1;
                }
            }
        }

        // (4) GC the dedup index up to a floor that LAGS the dest watermark (BLK-6) — never a source
        // checkpoint. Keys are dropped only once the dest watermark has advanced past their seq + gc_lag.
        let new_floor = st.low_watermark.saturating_sub(gc_lag);
        while st.gc_floor < new_floor {
            if let Some(k) = st.delivered_keys.remove(&st.gc_floor) {
                st.seen.remove(&k);
            }
            st.gc_floor += 1;
        }

        Disposition::Delivered
    }

    /// The current contiguous low-watermark for `stream` (every `seq <` it is committed). `0` if unseen.
    #[must_use]
    pub fn low_watermark(&self, stream: [u8; 16]) -> u64 {
        self.streams.get(&stream).map_or(0, |s| s.low_watermark)
    }

    /// The current dedup-GC floor for `stream` — keys for `seq <` it have been compacted out (BLK-6). `0` if
    /// unseen.
    #[must_use]
    pub fn gc_floor(&self, stream: [u8; 16]) -> u64 {
        self.streams.get(&stream).map_or(0, |s| s.gc_floor)
    }

    /// A **signed** low-watermark token for `stream`: the Ed25519 signature over `stream ‖ watermark` under
    /// this destination's seed, domain-separated by `WM_CTX`. Peers verify it with [`verify_watermark`].
    ///
    /// Returns the `(watermark, signature)` pair; the watermark is the same value as [`Once::low_watermark`].
    #[must_use]
    pub fn signed_watermark(&self, stream: [u8; 16]) -> (u64, [u8; 64]) {
        let wm = self.low_watermark(stream);
        let sig = sign_domain(WM_CTX, &self.seed, &watermark_msg(stream, wm));
        (wm, sig)
    }

    /// Per-stream durable checkpoints for a persistent dedup index ([`crate::FileOnce`]): for each known stream,
    /// `(stream, low_watermark, above-watermark (seq, key) entries)`. Replaying a checkpoint's watermark then its
    /// entries reconstructs the stream's state exactly — the basis for log compaction.
    #[must_use]
    pub fn checkpoints(&self) -> Vec<StreamCheckpoint> {
        self.streams
            .iter()
            .map(|(stream, st)| {
                let mut entries: Vec<(u64, [u8; 32])> = st
                    .delivered_keys
                    .iter()
                    .filter(|(seq, _)| **seq >= st.low_watermark)
                    .map(|(seq, key)| (*seq, *key))
                    .collect();
                entries.sort_unstable_by_key(|(seq, _)| *seq);
                (*stream, st.low_watermark, entries)
            })
            .collect()
    }

    /// Restore a `stream`'s contiguous low-watermark from a durable checkpoint (used by [`crate::FileOnce`] on
    /// open, before any live traffic). Idempotent and monotonic — only advances. The above-watermark keys are
    /// re-supplied by replaying the checkpoint's `(seq, key)` entries through [`Once::admit`].
    pub fn restore_watermark(&mut self, stream: [u8; 16], watermark: u64) {
        let gc_lag = self.gc_lag;
        let st = self.streams.entry(stream).or_default();
        if watermark > st.low_watermark {
            st.low_watermark = watermark;
            st.gc_floor = watermark.saturating_sub(gc_lag);
            st.ahead.retain(|seq| *seq >= watermark);
            st.delivered_keys.retain(|seq, _| *seq >= st.gc_floor);
            // `seen` is rebuilt from the replayed entries; drop anything now below the floor is unnecessary here
            // because restore runs at open before traffic, but keep `seen` consistent with `delivered_keys`:
            let live: std::collections::HashSet<[u8; 32]> =
                st.delivered_keys.values().copied().collect();
            st.seen.retain(|k| live.contains(k));
        }
    }
}

/// The signed message body for a watermark token: `stream_id ‖ watermark` (little-endian).
fn watermark_msg(stream: [u8; 16], watermark: u64) -> [u8; 24] {
    let mut m = [0u8; 24];
    m[..16].copy_from_slice(&stream);
    m[16..].copy_from_slice(&watermark.to_le_bytes());
    m
}

/// Verify a signed low-watermark token (from [`Once::signed_watermark`]) against the destination's verifying
/// key `vk`.
#[must_use]
pub fn verify_watermark(vk: &[u8; 32], stream: [u8; 16], watermark: u64, sig: &[u8; 64]) -> bool {
    verify_domain(WM_CTX, vk, &watermark_msg(stream, watermark), sig)
}

#[cfg(test)]
mod tests {
    use super::{verify_watermark, Once, DEFAULT_GC_LAG};
    use datarail_core::Disposition;
    use datarail_crypto::verifying_key;

    const SEED: [u8; 32] = [13u8; 32];
    const S: [u8; 16] = [1u8; 16];

    fn key(n: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&n.to_le_bytes());
        k
    }

    #[test]
    fn first_delivery_then_redelivery_is_dropped() {
        let mut o = Once::new(SEED);
        assert_eq!(o.admit(S, 0, key(0)), Disposition::Delivered);
        // Redelivery of seq 0: the watermark has advanced past it, so reject-below (BLK-6) fires before the
        // dedup lookup. It's a benign already-delivered redelivery -> Duplicate (drop + re-ack, never re-commit).
        assert_eq!(o.admit(S, 0, key(0)), Disposition::Duplicate);
    }

    #[test]
    fn redelivery_at_or_above_watermark_is_a_duplicate() {
        let mut o = Once::new(SEED);
        // Park seq 3 above the watermark (gap at 0..3 keeps the watermark at 0).
        assert_eq!(o.admit(S, 3, key(3)), Disposition::Delivered);
        assert_eq!(o.low_watermark(S), 0);
        // Redelivery of the still-at/above-watermark seq is caught by the dedup index -> Duplicate.
        assert_eq!(o.admit(S, 3, key(3)), Disposition::Duplicate);
    }

    #[test]
    fn reject_below_watermark_is_not_a_lookup() {
        let mut o = Once::new(SEED);
        // Deliver 0,1,2 contiguously; watermark advances to 3.
        for n in 0..3u64 {
            assert_eq!(o.admit(S, n, key(n)), Disposition::Delivered);
        }
        assert_eq!(o.low_watermark(S), 3);
        // BLK-6: a seq below the watermark is never re-committed — even with a brand-new, never-seen key —
        // and is reported as a benign already-delivered Duplicate (drop + re-ack).
        assert_eq!(o.admit(S, 1, key(999)), Disposition::Duplicate);
        // And a below-watermark replay of a key that was GC'd would otherwise look "new" — still not re-committed.
        assert_eq!(o.admit(S, 0, key(0)), Disposition::Duplicate);
    }

    #[test]
    fn same_seq_above_watermark_with_a_different_key_is_a_duplicate() {
        // audit HIGH: a redelivery of an already-delivered (not-yet-contiguous) seq carrying a *different*
        // idempotency_key must NOT be committed twice — a seq is committed once regardless of key. Keep the
        // watermark pinned with a gap at 0, deliver seq 5, then re-present seq 5 under a regenerated key.
        let mut o = Once::new(SEED);
        assert_eq!(o.admit(S, 5, key(5)), Disposition::Delivered);
        assert_eq!(
            o.low_watermark(S),
            0,
            "the gap at 0 pins the watermark; seq 5 is merely parked"
        );
        assert_eq!(
            o.admit(S, 5, key(999)),
            Disposition::Duplicate,
            "same seq, new key -> committed once"
        );
    }

    #[test]
    fn out_of_order_then_gap_fill_advances_watermark() {
        let mut o = Once::new(SEED);
        // 0 arrives, then 2 (gap at 1): watermark only reaches 1.
        assert_eq!(o.admit(S, 0, key(0)), Disposition::Delivered);
        assert_eq!(o.admit(S, 2, key(2)), Disposition::Delivered);
        assert_eq!(o.low_watermark(S), 1);
        // 1 fills the gap: watermark jumps past the parked 2 -> 3.
        assert_eq!(o.admit(S, 1, key(1)), Disposition::Delivered);
        assert_eq!(o.low_watermark(S), 3);
    }

    #[test]
    fn duplicate_of_a_parked_ahead_seq_is_caught() {
        let mut o = Once::new(SEED);
        assert_eq!(o.admit(S, 0, key(0)), Disposition::Delivered);
        assert_eq!(o.admit(S, 5, key(5)), Disposition::Delivered); // parked ahead
                                                                   // Redelivery of the parked seq's key is a duplicate, not a re-delivery.
        assert_eq!(o.admit(S, 5, key(5)), Disposition::Duplicate);
    }

    #[test]
    fn gc_floor_lags_the_dest_watermark() {
        let lag = 4u64;
        let mut o = Once::with_gc_lag(SEED, lag);
        for n in 0..10u64 {
            assert_eq!(o.admit(S, n, key(n)), Disposition::Delivered);
        }
        assert_eq!(o.low_watermark(S), 10);
        // GC floor trails the dest watermark by exactly `lag` (BLK-6), never a source checkpoint.
        assert_eq!(o.gc_floor(S), 10 - lag);
        // A key at seq below the GC floor was compacted out; replaying it below-watermark is still not
        // re-committed (reject-below is what makes GC safe) — reported as Duplicate.
        assert_eq!(o.admit(S, 0, key(0)), Disposition::Duplicate);
    }

    #[test]
    fn streams_are_independent() {
        let mut o = Once::new(SEED);
        let s2 = [2u8; 16];
        assert_eq!(o.admit(S, 0, key(0)), Disposition::Delivered);
        // Same seq+key on a *different* stream is a fresh delivery.
        assert_eq!(o.admit(s2, 0, key(0)), Disposition::Delivered);
        assert_eq!(o.low_watermark(S), 1);
        assert_eq!(o.low_watermark(s2), 1);
    }

    #[test]
    fn signed_watermark_roundtrips_and_rejects_tamper() {
        let mut o = Once::new(SEED);
        for n in 0..5u64 {
            o.admit(S, n, key(n));
        }
        let vk = verifying_key(&SEED);
        let (wm, sig) = o.signed_watermark(S);
        assert_eq!(wm, 5);
        assert!(verify_watermark(&vk, S, wm, &sig));
        // A bumped watermark claim does not verify against the signed value.
        assert!(!verify_watermark(&vk, S, wm + 1, &sig));
        // A different stream does not verify.
        assert!(!verify_watermark(&vk, [9u8; 16], wm, &sig));
    }

    #[test]
    fn default_gc_lag_is_exposed() {
        assert_eq!(DEFAULT_GC_LAG, 1024);
    }
}
