//! AC-4 — **effectively-once under fault, proven by Deterministic Simulation Testing (DST)**.
//!
//! SPEC `05-effectively-once.md`: *"Acked at boarding ⇒ offloaded exactly once"* under crash / retry /
//! partition. We drive the [`Once`] admission gate from a source that delivers **at-least-once** across a
//! seeded, fault-injecting in-memory pipe and assert, at the sink, the two AC-4 invariants:
//!
//! - **0 acked-loss**: every source record that the source saw acked is committed at the sink.
//! - **0 duplicate**: no `seq` is committed at the sink more than once.
//!
//! Faults injected on the dumb pipe (the crash matrix of SPEC 05): **drop**, **reorder**, **duplicate**, and
//! **kill-and-respawn** (the ephemeral rail dies mid-flight → re-spawn resends from the last un-acked `seq`).
//!
//! Determinism: a self-contained **`SplitMix64`** PRNG seeds every fault decision — **no `rand` crate**. The
//! whole run is a pure function of the seed, so a failing seed reproduces exactly.

use std::collections::{HashMap, VecDeque};

use datarail_core::Disposition;
use datarail_once::Once;

/// Self-contained `SplitMix64` (public-domain algorithm). Deterministic; **no external crate**.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, n)` (n > 0).
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// Uniform `usize` in `[0, n)` (n > 0) — for indexing in-flight buffers without a lossy cast.
    fn below_usize(&mut self, n: usize) -> usize {
        // `next_u64() % n` fits in `usize` because the result is `< n` and `n: usize`.
        usize::try_from(self.next_u64() % (n as u64)).unwrap_or(0)
    }

    /// True with probability `pct/100`.
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

/// A frame in flight: the source's record plus the dedup key. (We model the cofre as just what the gate
/// needs — `stream`, `seq`, `idempotency_key` — per SPEC's `(cofre, seq, idempotency_key)`.)
#[derive(Clone, Copy)]
struct Frame {
    stream: [u8; 16],
    seq: u64,
    key: [u8; 32],
}

/// A **cumulative** ack flowing back to the source: "for this `stream`, every `seq < up_to` is durably
/// accounted for at the dest." `up_to` is the dest's signed low-watermark (SPEC 05) — it advances only when
/// the contiguous prefix is committed-or-rejected, which is what makes a cumulative ack sound under
/// out-of-order delivery.
#[derive(Clone, Copy)]
struct Ack {
    stream: [u8; 16],
    up_to: u64,
}

/// The dedup key for a record. Deterministic and unique per `(stream, seq)` — stands in for
/// `HMAC(tenant_secret, record_key)`.
fn key_of(stream: [u8; 16], seq: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(&stream);
    k[16..24].copy_from_slice(&seq.to_le_bytes());
    k
}

/// One source stream with a durable WAL: re-sends from the last un-acked `seq` (at-least-once).
struct Source {
    stream: [u8; 16],
    total: u64,
    /// Lowest `seq` not yet acked by the dest = the WAL replay point. Records `< acked` are dest-acked.
    acked: u64,
}

impl Source {
    /// All un-acked frames currently eligible for (re)transmission: the in-flight window `[acked, total)`,
    /// bounded so the pipe never grows without end. Returns an iterator (no per-tick allocation).
    fn outstanding(&self) -> impl Iterator<Item = Frame> + '_ {
        (self.acked..self.total).map(|seq| Frame {
            stream: self.stream,
            seq,
            key: key_of(self.stream, seq),
        })
    }

    fn on_ack(&mut self, ack: Ack) {
        // Cumulative ack against the dest watermark: advance the WAL replay point. (Acks themselves may be
        // reordered/duplicated; a stale ack at/below `acked` is simply ignored.)
        if ack.up_to > self.acked {
            self.acked = ack.up_to;
        }
    }

    fn done(&self) -> bool {
        self.acked >= self.total
    }
}

/// The destination: the [`Once`] gate + a commit-counting sink + the acks it owes the source.
struct Dest {
    once: Once,
    /// seq -> number of times committed at the sink (must end == 1 for every acked seq; AC-4 invariant).
    commits: HashMap<([u8; 16], u64), u32>,
    /// Acks to flush back to the source (sent for Delivered, Duplicate, AND DeadLettered/below-watermark —
    /// all three mean "durably accounted for", so re-ack and let the source advance its WAL).
    out_acks: VecDeque<Ack>,
}

impl Dest {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            // AUDIT-02: a small gc_lag (< PER_STREAM = 8) so the dedup-GC path actually fires mid-run under
            // fault injection — proving exactly-once across the GC-vs-replay interleave, not just with GC idle.
            once: Once::with_gc_lag(seed, 3),
            commits: HashMap::new(),
            out_acks: VecDeque::new(),
        }
    }

    fn receive(&mut self, f: Frame) {
        // Only `Delivered` touches the sink; `Duplicate` / `DeadLettered` are idempotent drops. In every
        // case the dest then re-acks its *current* cumulative low-watermark — the value the source uses to
        // advance its WAL. (The signed form of this watermark is exercised once per stream in
        // `signed_watermark_matches_low_watermark`, tying the cheap ack value to the real signed-token API.)
        if let Disposition::Delivered = self.once.admit(f.stream, f.seq, f.key) {
            *self.commits.entry((f.stream, f.seq)).or_insert(0) += 1;
        }
        self.out_acks.push_back(Ack {
            stream: f.stream,
            up_to: self.once.low_watermark(f.stream),
        });
    }
}

/// Run one fully-deterministic fault-injected simulation for `seed`. Returns the per-`(stream,seq)` commit
/// counts and the set of `(stream,seq)` the source ultimately saw acked.
fn run_once(seed: u64, streams: u64, per_stream: u64) -> (HashMap<([u8; 16], u64), u32>, u64) {
    let mut rng = SplitMix64::new(seed);

    let mut sources: Vec<Source> = (0..streams)
        .map(|i| Source {
            stream: stream_id(i),
            total: per_stream,
            acked: 0,
        })
        .collect();

    let mut dest = Dest::new([0xABu8; 32]);

    // In-flight queues across the dumb pipe (both directions can drop/reorder/dup).
    let mut wire: VecDeque<Frame> = VecDeque::new();
    let mut ack_wire: VecDeque<Ack> = VecDeque::new();

    // Bound the run: generous vs. the work to do, but finite so a livelock fails loudly. With a drain-each-
    // tick dest, quiescence needs only ~O(records) ticks even under heavy drop+kill; this cap is far above.
    let max_ticks = (streams * per_stream + 1) * 50 + 500;
    let mut ticks = 0u64;

    while !sources.iter().all(Source::done) {
        ticks += 1;
        assert!(
            ticks < max_ticks,
            "seed {seed}: did not quiesce (livelock?)"
        );

        // --- Source step: (re)transmit each source's un-acked window (at-least-once), so even under heavy
        // drop a copy eventually gets through. Per-frame DROP and DUPLICATE faults are injected here.
        for src in &sources {
            for f in src.outstanding() {
                if rng.chance(30) {
                    continue; // DROP on the forward path.
                }
                wire.push_back(f);
                if rng.chance(20) {
                    wire.push_back(f); // DUPLICATE on the forward path.
                }
            }
        }

        // --- Pipe REORDER: occasionally rotate the in-flight frames so delivery order != send order.
        if wire.len() > 1 && rng.chance(40) {
            let r = rng.below_usize(wire.len());
            wire.rotate_left(r);
        }

        // --- KILL-AND-RESPAWN: the ephemeral rail dies mid-flight; everything in flight is lost. The source
        // is untouched (its WAL survives) and will resend from the last un-acked seq; the dest's dedup index
        // + watermark survive (the durability anchors are NOT in the rail).
        if rng.chance(8) {
            wire.clear();
            ack_wire.clear();
        }

        // --- Dest step: deliver the currently in-flight frames to the gate (drain — the gate is a pure,
        // cheap decision and its dedup + reject-below are exactly what must absorb the reorder/dup above).
        while let Some(f) = wire.pop_front() {
            dest.receive(f);
        }

        // --- Acks flow back across the pipe (also lossy/dup), then to the matching source.
        while let Some(a) = dest.out_acks.pop_front() {
            if rng.chance(25) {
                continue; // DROP the ack -> source will resend -> dedup/reject-below must absorb it.
            }
            ack_wire.push_back(a);
            if rng.chance(15) {
                ack_wire.push_back(a); // DUPLICATE the ack.
            }
        }
        if ack_wire.len() > 1 && rng.chance(30) {
            let r = rng.below_usize(ack_wire.len());
            ack_wire.rotate_left(r); // REORDER acks.
        }
        while let Some(a) = ack_wire.pop_front() {
            if let Some(src) = source_for(&mut sources, a.stream) {
                src.on_ack(a);
            }
        }
    }

    let acked_total = sources.iter().map(|s| s.acked).sum();
    (dest.commits, acked_total)
}

fn stream_id(i: u64) -> [u8; 16] {
    let mut s = [0u8; 16];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

/// Recover the [`Source`] for a `stream` via the deterministic `stream_id` mapping (the low 8 bytes are the
/// stream index) — O(1), no linear scan.
fn source_for(sources: &mut [Source], stream: [u8; 16]) -> Option<&mut Source> {
    let mut idx = [0u8; 8];
    idx.copy_from_slice(&stream[..8]);
    let i = usize::try_from(u64::from_le_bytes(idx)).ok()?;
    sources.get_mut(i)
}

#[test]
fn ac4_effectively_once_over_1000_seeds() {
    const SEEDS: u64 = 1000;
    const STREAMS: u64 = 3;
    const PER_STREAM: u64 = 8;

    for seed in 0..SEEDS {
        let (commits, acked_total) = run_once(seed, STREAMS, PER_STREAM);

        // INVARIANT 1 — 0 duplicate: no (stream, seq) committed at the sink more than once.
        for (&(stream, seq), &n) in &commits {
            assert_eq!(
                n, 1,
                "seed {seed}: stream {stream:?} seq {seq} committed {n}x (duplicate at sink)"
            );
        }

        // INVARIANT 2 — 0 acked-loss: every record the source saw acked is committed exactly once. The run
        // only quiesces when every source has acked all `PER_STREAM` records, so the acked set is the full
        // [0, PER_STREAM) per stream; each must appear exactly once in the sink.
        assert_eq!(
            acked_total,
            STREAMS * PER_STREAM,
            "seed {seed}: not all records acked at quiescence"
        );
        for s in 0..STREAMS {
            let stream = stream_id(s);
            for seq in 0..PER_STREAM {
                assert_eq!(
                    commits.get(&(stream, seq)).copied(),
                    Some(1),
                    "seed {seed}: acked stream {stream:?} seq {seq} NOT committed exactly once (acked-loss)"
                );
            }
        }
        // The sink holds exactly the acked set — nothing extra committed.
        assert_eq!(
            u64::try_from(commits.len()).unwrap(),
            STREAMS * PER_STREAM,
            "seed {seed}: sink committed records outside the acked set"
        );
    }
}

/// The cumulative ack value the DST harness uses (`Once::low_watermark`) is exactly the value carried by the
/// **signed** watermark token (`Once::signed_watermark`), and that token verifies — tying the harness's cheap
/// ack to the real signed-watermark API exercised in production (SPEC 05).
#[test]
fn signed_watermark_matches_low_watermark() {
    use datarail_crypto::verifying_key;
    let seed = [0xABu8; 32];
    let mut once = Once::new(seed);
    let stream = stream_id(0);
    for n in 0..6u64 {
        once.admit(stream, n, key_of(stream, n));
    }
    let (signed_wm, sig) = once.signed_watermark(stream);
    assert_eq!(signed_wm, once.low_watermark(stream));
    assert!(datarail_once::verify_watermark(
        &verifying_key(&seed),
        stream,
        signed_wm,
        &sig
    ));
}
