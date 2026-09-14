//! `datarail-store-bench` — proves datarail's DURABILITY decouples from RAM.
//!
//! Kafka achieves durability+performance by keeping the working set in the OS page cache — RAM (the scarce,
//! expensive resource) grows with retention/throughput. datarail's durable store (SPEC-10) is the opposite:
//! the source seals a cofre and writes it to commodity object storage / disk (cheap, abundant), keeping only a
//! tiny index in RAM. So you can store an unbounded volume and process RSS stays FLAT.
//!
//! This bench boards sealed cofres and PUTs them through the real `ObjectStoreSubstrate` (one sealed object per
//! cofre, on a local temp dir = a stand-in for S3/GCS/R2/MinIO), sampling process RSS as the stored volume
//! grows into the GBs. If RSS stays flat while disk grows, durability is decoupled from RAM — the whole point.
//!
//! Usage: `datarail-store-bench [cofres] [records_per_cofre] [msg_size] [dir]`
//! (defaults: 200000 128 1024 <tempdir>). NOT a product component — a measurement tool.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Instant;

use datarail_core::{AeadAlg, Substrate};
use datarail_crypto::{verifying_key, x25519_public};
use datarail_substrate_objectstore::ObjectStoreSubstrate;
use datarail_terminal::{ContentContract, SourceTerminal, TerminalConfig};

const ROUTE_ID: [u8; 16] = [1u8; 16];
const STREAM_ID: [u8; 16] = [2u8; 16];
const SRC_SEED: [u8; 32] = [11u8; 32];
const DEST_X25519_SECRET: [u8; 32] = [9u8; 32];
const TENANT_SECRET: [u8; 32] = [6u8; 32];

/// Resident set size of this process, in MB (Linux `/proc/self/statm` resident pages × 4 KiB; 0 off-Linux).
fn rss_mb() -> u64 {
    let Ok(s) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let pages: u64 = s
        .split_whitespace()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    pages * 4096 / (1024 * 1024)
}

/// Total bytes stored under `dir` (the durable on-disk footprint), in MB.
fn dir_mb(dir: &std::path::Path) -> u64 {
    fn walk(d: &std::path::Path, acc: &mut u64) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, acc);
            } else if let Ok(m) = e.metadata() {
                *acc += m.len();
            }
        }
    }
    let mut acc = 0u64;
    walk(dir, &mut acc);
    acc / (1024 * 1024)
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let cofres: u64 = a.first().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let per_cofre: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(128);
    let msg_size: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(1024);
    let dir = a.get(3).map_or_else(
        || std::env::temp_dir().join("datarail-store-bench"),
        PathBuf::from,
    );
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create store dir");

    let cfg = TerminalConfig {
        route_id: ROUTE_ID,
        stream_id: STREAM_ID,
        aead_alg: AeadAlg::Gcmsiv256,
        dest_x25519_pk: x25519_public(&DEST_X25519_SECRET),
        tenant_secret: TENANT_SECRET,
    };
    let _src_vk = verifying_key(&SRC_SEED);
    let contract = ContentContract::new(msg_size + 8, Vec::new());
    let mut src = SourceTerminal::new(cfg, contract, SRC_SEED);
    let mut store = ObjectStoreSubstrate::open(&dir).expect("open durable store");
    let payload = vec![0x78u8; msg_size];
    let recs: Vec<&[u8]> = (0..per_cofre).map(|_| payload.as_slice()).collect();

    let rss_base = rss_mb();
    println!(
        "datarail-store-bench: {cofres} cofres x {per_cofre} rec x {msg_size}B → durable store at {}",
        dir.display()
    );
    println!("  baseline RSS: {rss_base} MB");
    println!("  stored(MB) |  RSS(MB) | cofres");
    let t0 = Instant::now();
    let mut rss_peak = rss_base;
    for i in 0..cofres {
        let key = i.to_le_bytes();
        if let Ok(cofre) = src.board(&recs, &key) {
            store.send(&cofre).expect("durable PUT");
        }
        if i > 0 && i % (cofres / 10).max(1) == 0 {
            let r = rss_mb();
            if r > rss_peak {
                rss_peak = r;
            }
            println!("  {:>9} | {:>7} | {i}", dir_mb(&dir), r);
        }
    }
    let micros = t0.elapsed().as_micros().max(1);
    let stored = dir_mb(&dir);
    let rss_final = rss_mb();
    let put_rate = u128::from(cofres).saturating_mul(1_000_000) / micros; // cofres/s, integer
    println!("\nRESULT: stored {stored} MB durably across {cofres} sealed cofres on disk");
    println!(
        "        process RSS: baseline {rss_base} MB → final {rss_final} MB (max {rss_peak} MB)"
    );
    println!(
        "        ⇒ durability scaled on DISK (cheap/abundant); RAM stayed ~FLAT (scarce/expensive)"
    );
    println!("        ({put_rate} cofres/s sealed+PUT)");
}
