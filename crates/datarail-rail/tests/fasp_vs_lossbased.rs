//! AC-8 (FASP physics): **delay-based congestion control sustains throughput under loss where loss-based
//! TCP collapses.**
//!
//! datarail's [`DelayController`](datarail_rail::congestion::DelayController) is FASP-style — it reacts to
//! *queueing delay* (RTT inflation above the learned base RTT) and **deliberately ignores packet loss**
//! (loss is repaired by retransmission / `bao` resume, never by cutting the rate). Loss-based TCP-Reno
//! instead treats *every loss event* as congestion and multiplicatively halves its window (AIMD
//! multiplicative-decrease). On a high-RTT path with non-trivial loss, Reno's window is dragged down toward
//! its minimum and goodput collapses; the delay-based window stays near the path's bandwidth-delay product
//! (BDP) equilibrium and goodput holds.
//!
//! This integration test drives **both** controllers over the **same** deterministic, seeded link model
//! (one shared loss schedule + one shared RTT/queue model per loss rate) across a sweep of loss rates
//! (5 %, 15 %, 30 %) and asserts:
//!
//! 1. at every tested loss rate the delay-based controller sustains *materially* higher effective goodput
//!    than the loss-based one;
//! 2. the **gap widens monotonically** as loss rises — i.e. loss-based collapses with loss while delay-based
//!    does not.
//!
//! The loss-based AIMD model lives here as a **reference baseline** (TCP-Reno behaviour), not production code.
//! No RNG crate: a tiny `SplitMix64` PRNG seeded per run keeps the loss schedule deterministic and reproducible.

use std::time::Duration;

use datarail_rail::congestion::DelayController;

/// A deterministic `SplitMix64` PRNG — gives a reproducible loss schedule with zero dependencies.
///
/// (We only need a uniform stream in `[0, 1)`; `SplitMix64` is the standard tiny, well-distributed choice.)
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Next raw `u64` in the stream.
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Next `f64` uniformly in `[0, 1)` (top 32 bits / 2^32).
    fn next_unit(&mut self) -> f64 {
        // Take the high 32 bits (best-distributed) and scale by 2^32. After `>> 32` the value is provably
        // `<= u32::MAX`, so `try_from` never fails; 32 bits fits `u32` exactly so the widening to `f64`
        // (`f64::from`) is lossless — ample resolution for a loss schedule, and clippy-clean (no `as`).
        let bits = u32::try_from(self.next_u64() >> 32).unwrap_or(u32::MAX);
        f64::from(bits) * (1.0 / 4_294_967_296.0)
    }
}

/// A loss-based AIMD congestion window — the **TCP-Reno reference baseline** (this test only).
///
/// Additive-increase per congestion-free RTT round (`+1` window), multiplicative-decrease on **every loss
/// event** (`window *= 0.5`, the Reno halving). This is the behaviour datarail's delay-based controller is
/// designed to beat under loss: Reno cannot tell a *lossy* link from a *congested* one, so loss alone drags
/// its window down.
struct AimdController {
    window: f64,
    min_window: f64,
    max_window: f64,
}

impl AimdController {
    fn new(init_window: f64, min_window: f64, max_window: f64) -> Self {
        Self {
            window: init_window.clamp(min_window, max_window),
            min_window,
            max_window,
        }
    }

    fn window(&self) -> f64 {
        self.window
    }

    /// One congestion-free RTT round: additive increase.
    fn on_clean_rtt(&mut self) {
        self.window = (self.window + 1.0).min(self.max_window);
    }

    /// A loss event: multiplicative decrease (Reno halving). **This is the only difference that matters** —
    /// the delay-based controller does nothing on loss.
    fn on_loss(&mut self) {
        self.window = (self.window * 0.5).max(self.min_window);
    }
}

/// Outcome of simulating one controller over the link: the goodput (delivered cofres per RTT round) and the
/// time-averaged window, both averaged over the measured rounds.
#[derive(Debug, Clone, Copy)]
struct SimResult {
    /// Mean delivered cofres per RTT round (the effective goodput).
    goodput: f64,
    /// Mean congestion window over the run (the rate the controller chose to run at).
    avg_window: f64,
}

/// Shared link model parameters. Both controllers see the **same** values so the only variable is the
/// control law.
#[derive(Debug, Clone, Copy)]
struct Link {
    /// Learned base (uncongested) RTT of the path.
    base_rtt: Duration,
    /// Bandwidth-delay product, in cofres: the window at which the pipe is exactly full. Below it the queue
    /// is empty (RTT == base); above it the queue (and RTT) grows linearly.
    bdp: f64,
    /// Extra queueing delay per cofre of window held **above** the BDP (models a bottleneck buffer filling).
    queue_per_excess_cofre: Duration,
    /// Number of RTT rounds to simulate (after a warm-up).
    rounds: u32,
    /// Rounds of warm-up (let each controller reach its operating point) before measuring.
    warmup: u32,
}

impl Link {
    /// The RTT a sender observes when running at `window` cofres outstanding: base RTT while the window is
    /// within the BDP, plus a linear queueing term once it exceeds the BDP (standard bottleneck-queue model).
    fn rtt_at(&self, window: f64) -> Duration {
        let excess = (window - self.bdp).max(0.0);
        // Each cofre of window held above the BDP adds `queue_per_excess_cofre` of delay. Compute in f64
        // seconds (no integer cast) then back to a `Duration`, so the queue grows smoothly with the excess.
        let queue = Duration::from_secs_f64(self.queue_per_excess_cofre.as_secs_f64() * excess);
        self.base_rtt.saturating_add(queue)
    }
}

/// Draw the per-RTT-round loss outcome for an integer window of `in_flight` cofres against the shared
/// schedule in `rng`: returns `(delivered, lost)`. Counting uses an `f64` accumulator (no `f64 as u32`
/// cast) — `in_flight` is the floored, `[1, 4*BDP]`-clamped window, so the loop count is small and exact.
fn draw_round(in_flight: f64, loss_rate: f64, rng: &mut SplitMix64) -> (u32, u32) {
    let mut delivered = 0u32;
    let mut lost = 0u32;
    let mut sent = 0.0_f64;
    while sent < in_flight {
        if rng.next_unit() < loss_rate {
            lost += 1;
        } else {
            delivered += 1;
        }
        sent += 1.0;
    }
    (delivered, lost)
}

/// Average a goodput / window sum over the measured (post-warm-up) rounds.
fn finish(goodput_sum: f64, window_sum: f64, rounds: u32) -> SimResult {
    let rounds = f64::from(rounds);
    SimResult {
        goodput: goodput_sum / rounds,
        avg_window: window_sum / rounds,
    }
}

/// Simulate the **delay-based** [`DelayController`] over `link` against the shared loss schedule produced by
/// `rng`. Per RTT round: deliver the in-window cofres, apply the round's losses (observed only — the
/// controller does **not** back off on them), then feed the round's measured RTT so the window tracks the
/// queue. Goodput counts only the cofres that were *not* lost that round.
fn simulate_delay_based(link: &Link, loss_rate: f64, rng: &mut SplitMix64) -> SimResult {
    // Init at one cofre; queue threshold a small fraction of base RTT (a shallow standing queue is "congested").
    let queue_threshold = link.base_rtt / 8;
    let mut cc = DelayController::new(1.0, 1.0, 4.0 * link.bdp, queue_threshold);
    // Prime the base-RTT estimate with one clean (empty-queue) sample so "queue" is measured against truth.
    cc.on_rtt_sample(link.base_rtt);

    let mut goodput_sum = 0.0;
    let mut window_sum = 0.0;
    let total = link.warmup + link.rounds;
    for round in 0..total {
        let window = cc.window();
        let in_flight = window.floor().max(1.0);
        // Apply this round's losses against the SHARED schedule; delay-based observes but does not react.
        let (delivered, lost) = draw_round(in_flight, loss_rate, rng);
        for _ in 0..lost {
            cc.on_loss(); // observed-only (FASP physics): the window is NOT cut.
        }
        // Feed the RTT the sender experienced at this window so the delay signal drives the window.
        cc.on_rtt_sample(link.rtt_at(window));
        if round >= link.warmup {
            goodput_sum += f64::from(delivered);
            window_sum += window;
        }
    }
    finish(goodput_sum, window_sum, link.rounds)
}

/// Simulate the **loss-based** AIMD reference over the SAME `link` and SAME loss schedule. Per RTT round:
/// deliver the in-window cofres; if **any** were lost, multiplicatively decrease (one Reno halving per lossy
/// round); otherwise additively increase. Goodput counts the cofres that were not lost.
fn simulate_loss_based(link: &Link, loss_rate: f64, rng: &mut SplitMix64) -> SimResult {
    let mut cc = AimdController::new(1.0, 1.0, 4.0 * link.bdp);

    let mut goodput_sum = 0.0;
    let mut window_sum = 0.0;
    let total = link.warmup + link.rounds;
    for round in 0..total {
        let window = cc.window();
        let in_flight = window.floor().max(1.0);
        let (delivered, lost) = draw_round(in_flight, loss_rate, rng);
        // Reno: one congestion reaction per lossy RTT (halve); else additive-increase.
        if lost > 0 {
            cc.on_loss();
        } else {
            cc.on_clean_rtt();
        }
        if round >= link.warmup {
            goodput_sum += f64::from(delivered);
            window_sum += window;
        }
    }
    finish(goodput_sum, window_sum, link.rounds)
}

/// The shared high-RTT, deep-pipe link used by every sweep point: a 100 ms base RTT path whose pipe holds
/// 64 cofres (a fat long-distance link — exactly where Reno's loss-sensitivity hurts and FASP shines).
fn wan_link() -> Link {
    Link {
        base_rtt: Duration::from_millis(100),
        bdp: 64.0,
        queue_per_excess_cofre: Duration::from_micros(500),
        rounds: 4000,
        warmup: 400,
    }
}

/// Run BOTH controllers over the SAME link and the SAME seeded loss process at `loss_rate`. Each controller
/// gets its own PRNG seeded identically (same `seed`), so both face a loss process with identical statistics
/// and the whole experiment is deterministic / reproducible. The two then *consume* that stream at their own
/// rate — a smaller window draws fewer per-round outcomes — but that divergence is itself a consequence of the
/// control law, which is exactly the variable under test. (Seeding per controller, rather than sharing one
/// stream, keeps each run independently reproducible.)
fn head_to_head(loss_rate: f64, seed: u64) -> (SimResult, SimResult) {
    let link = wan_link();
    let mut rng_delay = SplitMix64::new(seed);
    let mut rng_loss = SplitMix64::new(seed);
    let delay = simulate_delay_based(&link, loss_rate, &mut rng_delay);
    let loss = simulate_loss_based(&link, loss_rate, &mut rng_loss);
    (delay, loss)
}

#[test]
fn fasp_delay_cc_holds_throughput_where_loss_based_collapses() {
    // Loss-rate sweep. At each point the FASP/delay controller must sustain MATERIALLY higher goodput than
    // the loss-based (Reno) baseline, and the advantage must WIDEN as loss rises.
    const SEED: u64 = 0x0DA7_A4A1_F45D_5EED; // fixed: deterministic, reproducible.
    let loss_rates = [0.05, 0.15, 0.30];

    let mut ratios = Vec::new();
    println!(
        "\nFASP delay-based vs loss-based AIMD (TCP-Reno) over a 100ms / 64-cofre BDP WAN link:"
    );
    println!(
        "  {:>6}  {:>14}  {:>14}  {:>10}",
        "loss", "delay-goodput", "loss-goodput", "ratio"
    );
    for &loss_rate in &loss_rates {
        let (delay, loss) = head_to_head(loss_rate, SEED);
        // Goodput ratio (how many times more the delay controller sustains). Guard the denominator.
        let ratio = delay.goodput / loss.goodput.max(1e-9);
        println!(
            "  {:>5.0}%  {:>10.2} c/rt  {:>10.2} c/rt  {ratio:>9.2}x   (windows: delay {:.1} vs loss {:.1})",
            loss_rate * 100.0,
            delay.goodput,
            loss.goodput,
            delay.avg_window,
            loss.avg_window,
        );

        // (1) At THIS loss rate the delay-based controller sustains materially higher goodput. We require a
        //     clear margin (>= 1.5x) rather than a hair, so this asserts a real, not marginal, advantage.
        assert!(
            delay.goodput > loss.goodput * 1.5,
            "at {:.0}% loss the FASP delay controller must sustain materially higher goodput \
             (delay {:.2} c/rt vs loss-based {:.2} c/rt)",
            loss_rate * 100.0,
            delay.goodput,
            loss.goodput,
        );
        ratios.push(ratio);
    }

    // (2) The advantage WIDENS as loss rises: each successive loss rate yields a strictly larger ratio. This
    //     is the collapse signature — loss-based goodput falls off with loss while delay-based holds, so the
    //     delay/loss ratio grows monotonically.
    for pair in ratios.windows(2) {
        assert!(
            pair[1] > pair[0],
            "the FASP advantage must WIDEN as loss increases (ratios so far: {ratios:?})"
        );
    }

    // (3) Sanity on the absolute physics: the loss-based window must have COLLAPSED at the worst loss rate
    //     (well below the BDP it would reach loss-free), proving the baseline genuinely falls over — the
    //     comparison is not won by an under-powered baseline.
    let (delay_worst, loss_worst) = head_to_head(0.30, SEED);
    assert!(
        loss_worst.avg_window < 0.5 * wan_link().bdp,
        "loss-based AIMD must collapse well below BDP at 30% loss (avg window {:.1}, BDP {:.0})",
        loss_worst.avg_window,
        wan_link().bdp,
    );
    assert!(
        delay_worst.avg_window > loss_worst.avg_window,
        "delay-based must run a larger window than the collapsed loss-based one at 30% loss"
    );
}

#[test]
fn delay_based_window_is_loss_invariant_while_loss_based_is_not() {
    // A tighter, isolated proof of the mechanism behind the throughput gap: hand BOTH controllers the SAME
    // sequence of pure loss events (no intervening RTT samples, so the delay controller's only stimulus is
    // loss). The delay-based window must be COMPLETELY UNCHANGED — `on_loss` does not touch the window by
    // design; the loss-based window is halved by each event and collapses toward its floor. This isolates the
    // single mechanism ("ignore loss, react only to RTT") that produces the throughput advantage above.
    const SEED: u64 = 0xFEED_F00D_DEAD_BEEF;
    let link = wan_link();
    let queue_threshold = link.base_rtt / 8;

    let mut delay = DelayController::new(link.bdp, 1.0, 4.0 * link.bdp, queue_threshold);
    delay.on_rtt_sample(link.base_rtt); // learn the base RTT once (a clean, empty-queue sample).
    let delay_window_before = delay.window();
    let mut loss = AimdController::new(link.bdp, 1.0, 4.0 * link.bdp);

    // Deliver the same loss schedule to both; the delay controller receives ONLY loss events here.
    let mut rng = SplitMix64::new(SEED);
    let mut loss_events = 0u64;
    for _ in 0..2000 {
        if rng.next_unit() < 0.30 {
            delay.on_loss(); // ignored by design — window must not move.
            loss.on_loss(); // Reno halving.
            loss_events += 1;
        }
    }

    assert!(
        loss_events > 0,
        "the seeded schedule must produce loss events"
    );
    assert!(
        (delay.window() - delay_window_before).abs() < f64::EPSILON,
        "delay-based window must be invariant to loss (was {delay_window_before}, now {} after {loss_events} losses)",
        delay.window()
    );
    assert!(
        loss.window() < delay.window(),
        "loss-based window must be dragged below the loss-invariant delay-based window by {loss_events} losses \
         (loss {:.2} vs delay {:.2})",
        loss.window(),
        delay.window()
    );
    // It collapses all the way to the floor under sustained loss (the Reno failure mode).
    assert!(
        (loss.window() - 1.0).abs() < f64::EPSILON,
        "sustained loss drives the loss-based window to its floor (window {:.2})",
        loss.window()
    );
    assert_eq!(
        delay.losses(),
        loss_events,
        "the delay controller counts losses for visibility even though it does not act on them"
    );
}
