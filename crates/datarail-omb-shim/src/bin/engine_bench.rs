//! `datarail-engine-bench` — datarail's PURE sealed-engine throughput, no sockets, no driver.
//!
//! The OMB client capped datarail at 658 MB/s; a native TCP loadgen lifted it to ~1.4 GB/s — but both still
//! pay socket + driver overhead, and on a co-located box the driver steals cores from the engine. This bench
//! removes ALL of that: N threads, each running datarail's REAL sealed datapath in a tight loop —
//! `board` (AEAD-seal + sign + per-cofre key-wrap, batched) → in-process handoff → `offload`
//! (verify → open → admit → commit) → drain — on 1 KB records. It reports the aggregate records/s + MB/s,
//! i.e. **datarail's sealed engine ceiling on this hardware**, the number the pipe + driver can only approach.
//!
//! Usage: `datarail-engine-bench [threads] [msg_size] [batch] [measure_secs]`
//! (defaults: all-cores 1024 128 20). Build with `--features vaes` for the warp (AES-256-GCM) seal path.
//! NOT a product component — a measurement tool.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use datarail_core::{AeadAlg, Disposition};
use datarail_crypto::{verifying_key, x25519_public};
use datarail_terminal::{ContentContract, DestTerminal, SourceTerminal, TerminalConfig};

const ROUTE_ID: [u8; 16] = [1u8; 16];
const STREAM_ID: [u8; 16] = [2u8; 16];
const SRC_SEED: [u8; 32] = [11u8; 32];
const DEST_SEED: [u8; 32] = [22u8; 32];
const DEST_X25519_SECRET: [u8; 32] = [9u8; 32];
const TENANT_SECRET: [u8; 32] = [6u8; 32];

fn term_config() -> TerminalConfig {
    TerminalConfig {
        route_id: ROUTE_ID,
        stream_id: STREAM_ID,
        #[cfg(feature = "vaes")]
        aead_alg: AeadAlg::Gcm256,
        #[cfg(not(feature = "vaes"))]
        aead_alg: AeadAlg::Gcmsiv256,
        dest_x25519_pk: x25519_public(&DEST_X25519_SECRET),
        tenant_secret: TENANT_SECRET,
    }
}

/// One worker: board+offload `batch`-record cofres of `msg_size` in a tight loop until `stop`, counting records.
fn worker(msg_size: usize, batch: usize, delivered: &Arc<AtomicU64>, stop: &Arc<AtomicBool>) {
    let cfg = term_config();
    let contract = ContentContract::new(msg_size + 8, Vec::new());
    let src_vk = verifying_key(&SRC_SEED);
    let mut src = SourceTerminal::new(cfg.clone(), contract.clone(), SRC_SEED);
    let mut dst = DestTerminal::new(cfg, contract, src_vk, DEST_SEED, DEST_X25519_SECRET);
    let payload = vec![0x78u8; msg_size];
    let recs: Vec<&[u8]> = (0..batch).map(|_| payload.as_slice()).collect();
    let mut seq: u64 = 0;
    let mut pending: u64 = 0;
    let batch_u64 = batch as u64;
    while !stop.load(Ordering::Relaxed) {
        let key = seq.to_le_bytes();
        seq += 1;
        let Ok(cofre) = src.board(&recs, &key) else {
            continue;
        };
        if let Ok(Disposition::Delivered) = dst.offload(&cofre) {
            let _ = dst.sink_mut().take_committed(); // drain so the sink does not grow
            pending += batch_u64;
            if pending >= 8192 {
                delivered.fetch_add(pending, Ordering::Relaxed);
                pending = 0;
            }
        }
    }
    delivered.fetch_add(pending, Ordering::Relaxed);
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let threads: usize = a
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get));
    let msg_size: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(1024);
    let batch: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(128);
    let measure_secs: u64 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
    let warp = cfg!(feature = "vaes");
    println!("datarail-engine-bench: threads={threads} msg_size={msg_size} batch={batch} measure={measure_secs}s warp(vaes)={warp}");

    let delivered = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for _ in 0..threads {
        let (d, s) = (Arc::clone(&delivered), Arc::clone(&stop));
        handles.push(thread::spawn(move || worker(msg_size, batch, &d, &s)));
    }

    thread::sleep(Duration::from_secs(3)); // warm up
    let start = delivered.load(Ordering::Relaxed);
    let t0 = Instant::now();
    thread::sleep(Duration::from_secs(measure_secs));
    let end = delivered.load(Ordering::Relaxed);
    stop.store(true, Ordering::Relaxed);

    let msgs = u128::from(end - start);
    let micros = t0.elapsed().as_micros().max(1);
    let per_s = msgs.saturating_mul(1_000_000) / micros;
    let mb_s = msgs.saturating_mul(u128::try_from(msg_size).unwrap_or(0)) / micros;
    println!("RESULT threads={threads} msg_size={msg_size} : {per_s} msg/s  {mb_s} MB/s  (sealed engine, no sockets)");
    for h in handles {
        let _ = h.join();
    }
}
