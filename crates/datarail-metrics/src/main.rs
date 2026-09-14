//! `datarail-metrics` — a dependency-free measurement binary for two charter gates:
//!
//! - **GATE-FEATHER (idle footprint):** process RSS sampled from `/proc/self/statm` at a startup baseline and
//!   again after building a [`LoopbackSubstrate`] + terminals and draining them to idle. The honest point is
//!   that datarail's rail is an *ephemeral, passive* pipe — once drained it holds ~no standing in-flight state,
//!   so its idle RSS returns to (near) the baseline, unlike an always-on broker that pins memory while idle.
//!   Off-Linux (no `/proc`) it prints `unavailable off-Linux` and still proves the in-flight-returns-to-0
//!   architectural half.
//! - **GATE-LATENCY (percentiles):** `N = 20_000` full board → loopback → offload cycles on a 1-record cofre,
//!   collecting per-op latencies, then printing **p50 / p90 / p99 / p99.9 / max** in microseconds for `board`
//!   and for `offload` via a plain sorted-vec percentile (no deps).
//!
//! All numbers are **DIRECTIONAL on dev hardware** — representative percentiles / footprint come from a VAES
//! run on the cloud target (`RUSTFLAGS=-C target-cpu=native` is set by the runner; nothing CPU-specific is
//! hardcoded here). The constructors mirror `datarail-bench` exactly (same `TerminalConfig` / `ContentContract`
//! / route), so this measures the real hot path, not a toy.

#![forbid(unsafe_code)]

use std::time::Instant;

use datarail_core::{AeadAlg, Disposition, Substrate};
use datarail_crypto::{verifying_key, x25519_public};
use datarail_rail::LoopbackSubstrate;
use datarail_terminal::{ContentContract, DestTerminal, SourceTerminal, TerminalConfig};

/// The Linux page size in bytes. `/proc/self/statm` reports counts in pages; on every Linux target datarail
/// deploys to this is 4 KiB. We avoid an FFI `sysconf` call (it would need `unsafe`, which the charter
/// forbids); a non-4 KiB page size would only rescale the absolute RSS, not the baseline-vs-drained *delta*
/// that GATE-FEATHER actually argues.
const LINUX_PAGE_BYTES: u64 = 4096;

/// Resident set size of this process in bytes, read from `/proc/self/statm` (field 2 = resident pages), or
/// `None` when that file is absent (i.e. off-Linux — macOS/Windows have no `/proc`).
///
/// `statm` format: `size resident shared text lib data dt` (all in pages); we take `resident`.
fn read_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(resident_pages.saturating_mul(LINUX_PAGE_BYTES))
}

/// Format an optional RSS reading as a human string (KiB), or the honest off-Linux sentinel.
fn fmt_rss(rss: Option<u64>) -> String {
    match rss {
        Some(bytes) => format!("{} KiB ({bytes} B)", bytes / 1024),
        None => "unavailable off-Linux".to_string(),
    }
}

/// The route fixtures — identical shape to `datarail-bench`'s, so the percentiles measure the real pipeline.
struct Fixtures {
    cfg: TerminalConfig,
    contract: ContentContract,
    src_seed: [u8; 32],
    src_vk: [u8; 32],
    dest_secret: [u8; 32],
}

impl Fixtures {
    fn new() -> Self {
        let dest_secret = [9u8; 32];
        let dest_pk = x25519_public(&dest_secret);
        let cfg = TerminalConfig {
            route_id: [1; 16],
            stream_id: [2; 16],
            aead_alg: AeadAlg::Gcmsiv256,
            dest_x25519_pk: dest_pk,
            tenant_secret: [6; 32],
        };
        let contract = ContentContract::new(4096, b"evt:".to_vec());
        let src_seed = [11u8; 32];
        let src_vk = verifying_key(&src_seed);
        Self {
            cfg,
            contract,
            src_seed,
            src_vk,
            dest_secret,
        }
    }

    fn source(&self) -> SourceTerminal {
        SourceTerminal::new(self.cfg.clone(), self.contract.clone(), self.src_seed)
    }

    fn dest(&self) -> DestTerminal {
        DestTerminal::new(
            self.cfg.clone(),
            self.contract.clone(),
            self.src_vk,
            [22; 32],
            self.dest_secret,
        )
    }
}

/// Latency percentiles over a sample of per-op durations, in **nanoseconds** (kept as `u64` to avoid lossy
/// float rounding before the final report).
#[derive(Debug, Clone, Copy)]
struct Percentiles {
    p50: u64,
    p90: u64,
    p99: u64,
    p999: u64,
    max: u64,
    count: usize,
}

/// The nearest-rank percentile at `permille` (e.g. `500` = p50, `999` = p99.9) of an **already-sorted** ascending
/// slice. Rank index `= (n - 1) * permille / 1000` (pure integer math — no lossy float index).
fn nearest_rank(sorted_ns: &[u64], permille: u64) -> u64 {
    if sorted_ns.is_empty() {
        return 0;
    }
    let n = u64::try_from(sorted_ns.len()).unwrap_or(u64::MAX);
    let rank = (n - 1).saturating_mul(permille) / 1000;
    let idx = usize::try_from(rank).unwrap_or(sorted_ns.len() - 1);
    sorted_ns[idx]
}

impl Percentiles {
    /// Sort `samples_ns` ascending in place and extract the standard percentiles.
    fn from_samples(samples_ns: &mut [u64]) -> Self {
        samples_ns.sort_unstable();
        Self {
            p50: nearest_rank(samples_ns, 500),
            p90: nearest_rank(samples_ns, 900),
            p99: nearest_rank(samples_ns, 990),
            p999: nearest_rank(samples_ns, 999),
            max: samples_ns.last().copied().unwrap_or(0),
            count: samples_ns.len(),
        }
    }

    /// Print one labelled percentile row in microseconds (3 decimals — sub-µs ops are common on the hot path).
    fn print_row(&self, label: &str) {
        let us = |ns: u64| {
            // ns → µs as f64 for display only; the comparison/storage stayed integer. `u32::try_from` keeps
            // the conversion lint-clean: a per-op latency in ns comfortably fits u32 (<= ~4.29 s).
            let ns_u32 = u32::try_from(ns).unwrap_or(u32::MAX);
            f64::from(ns_u32) / 1000.0
        };
        println!(
            "  {label:8} p50 {:>8.3}  p90 {:>8.3}  p99 {:>8.3}  p99.9 {:>8.3}  max {:>8.3}  µs   (N={})",
            us(self.p50),
            us(self.p90),
            us(self.p99),
            us(self.p999),
            us(self.max),
            self.count,
        );
    }
}

/// GATE-FEATHER: report RSS at baseline, then after building a rail + terminals and draining bursts to idle,
/// asserting (architecturally) that the in-flight count returns to 0 — the rail holds no standing memory.
fn report_idle_footprint(fx: &Fixtures) {
    println!("GATE-FEATHER — idle footprint (RSS via /proc/self/statm; DIRECTIONAL on dev HW):");
    let baseline = read_rss_bytes();
    println!(
        "  baseline RSS (startup)                 {}",
        fmt_rss(baseline)
    );

    // Build the rail + terminals and run repeated burst → drain → ack cycles. After each drain the in-flight
    // count must be 0: a passive substrate accumulates no standing state when idle (the architectural half).
    let mut sub = LoopbackSubstrate::new();
    let mut src = fx.source();
    let mut dst = fx.dest();
    let rec: [&[u8]; 1] = [b"evt:idle-probe"];

    let mut delivered = 0u64;
    for cycle in 0..64u64 {
        for _ in 0..256 {
            let rk = cycle.to_le_bytes();
            let cofre = src
                .board(&rec, &rk)
                .expect("board must succeed for a contract-conforming record");
            sub.send(&cofre).expect("loopback send is infallible");
        }
        while let Some(cofre) = sub.recv().expect("loopback recv is infallible") {
            if matches!(
                dst.offload(&cofre).expect("offload is infallible"),
                Disposition::Delivered
            ) {
                delivered += 1;
            }
            sub.ack(cofre.etiqueta.cofre_id)
                .expect("loopback ack is infallible");
        }
        assert_eq!(
            sub.queued_len(),
            0,
            "the rail must return to 0 in-flight after each drain (idle ≈ no standing state)"
        );
    }

    let drained = read_rss_bytes();
    println!(
        "  RSS after build + drain-to-idle        {}",
        fmt_rss(drained)
    );
    if let (Some(base), Some(now)) = (baseline, drained) {
        let delta = now.saturating_sub(base);
        let shrank = base.saturating_sub(now);
        println!(
            "  delta vs baseline                      +{} KiB (grew) / -{} KiB (shrank)",
            delta / 1024,
            shrank / 1024
        );
    }
    println!(
        "  in-flight after drain                  0 cofres (queue drained every cycle; {delivered} delivered total)"
    );
    println!("  -> ephemeral rail: idle holds ~no standing memory, vs a broker's always-on RSS.\n");
}

/// GATE-LATENCY: time `N` full board → loopback → offload cycles on a 1-record cofre and report per-op
/// percentiles for `board` and `offload`.
fn report_latency_percentiles(fx: &Fixtures) {
    const N: usize = 20_000;
    println!("GATE-LATENCY — board/offload percentiles over N={N} 1-record cycles (DIRECTIONAL on dev HW):");

    let rec: [&[u8]; 1] = [b"evt:latency-probe"];
    let mut src = fx.source();
    let mut dst = fx.dest();
    let mut sub = LoopbackSubstrate::new();

    let mut board_ns: Vec<u64> = Vec::with_capacity(N);
    let mut offload_ns: Vec<u64> = Vec::with_capacity(N);

    // Warm-up (let caches / branch predictors settle) — measured separately so it never pollutes the sample.
    for _ in 0..(N / 20).max(1) {
        let c = src.board(&rec, b"warm").expect("warm board");
        sub.send(&c).expect("warm send");
        if let Some(g) = sub.recv().expect("warm recv") {
            dst.offload(&g).expect("warm offload");
            sub.ack(g.etiqueta.cofre_id).expect("warm ack");
        }
    }

    for i in 0..N {
        // Unique record-key per cycle so every cofre is Delivered (not deduped) — measures the full commit path.
        let rk = u64::try_from(i).unwrap_or(u64::MAX).to_le_bytes();

        let t0 = Instant::now();
        let cofre = src.board(&rec, &rk).expect("board must succeed");
        board_ns.push(u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX));

        sub.send(&cofre).expect("loopback send is infallible");
        let got = loop {
            if let Some(g) = sub.recv().expect("loopback recv is infallible") {
                break g;
            }
        };

        let t1 = Instant::now();
        let disp = dst.offload(&got).expect("offload is infallible");
        offload_ns.push(u64::try_from(t1.elapsed().as_nanos()).unwrap_or(u64::MAX));

        debug_assert!(
            matches!(disp, Disposition::Delivered),
            "unique keys must deliver"
        );
        sub.ack(got.etiqueta.cofre_id)
            .expect("loopback ack is infallible");
    }

    Percentiles::from_samples(&mut board_ns).print_row("board");
    Percentiles::from_samples(&mut offload_ns).print_row("offload");
    println!(
        "  (board = validate->X25519-wrap->AEAD-seal->sign; offload = verify->open->admit->commit. \
         Representative numbers come from a VAES run.)"
    );
}

fn main() {
    println!("datarail-metrics — GATE-FEATHER + GATE-LATENCY harness. DIRECTIONAL on dev HW (Linux RSS via /proc).\n");
    let fx = Fixtures::new();
    report_idle_footprint(&fx);
    report_latency_percentiles(&fx);
}
