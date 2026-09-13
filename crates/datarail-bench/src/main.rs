//! `datarail-bench` — directional latency/throughput micro-benchmarks on **dev hardware**.
//!
//! These are **NOT a GATE-WARP result**: GATE-WARP requires representative VAES hardware this machine is not.
//! The numbers are **DIRECTIONAL** — they sanity-check the hot path and informally bound GATE-LATENCY /
//! GATE-FEATHER. Zero external deps (a `std::time::Instant` harness — Charter *leveza*). See
//! `docs/design/BENCH-01.md` for a recorded run with honest labels.

#![forbid(unsafe_code)]

use std::hint::black_box;
use std::time::Instant;

use datarail_cofre::{decode, encode};
use datarail_core::{AeadAlg, Cofre, Substrate};
use datarail_crypto::{
    aead_open, aead_seal, blake3_256, open_key, seal_key, verifying_key, x25519_public,
};
use datarail_rail::{LoopbackSubstrate, TcpSubstrate};
use datarail_terminal::{ContentContract, DestTerminal, SourceTerminal, TerminalConfig};

mod fairness;

/// Time `f` over `iters` iterations (after a warm-up) and print nanoseconds per op.
fn lat(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = t.elapsed().as_nanos() / u128::from(iters.max(1));
    println!("  {name:38} {ns:>9} ns/op   ({iters} iters)");
}

/// Time `f` (processing `bytes` each call) and print throughput in MB/s (integer: bytes/µs == MB/s).
fn tput(name: &str, iters: u32, bytes: usize, mut f: impl FnMut()) {
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let total = u64::try_from(bytes)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::from(iters));
    let micros = u64::try_from(t.elapsed().as_micros())
        .unwrap_or(u64::MAX)
        .max(1);
    println!(
        "  {name:38} {:>6} MB/s   ({iters} iters x {bytes} B)",
        total / micros
    );
}

/// Round-trip `n` cofres through a substrate (send → drain, **interleaved** so a real socket's bounded buffer
/// cannot deadlock) and print ns/cofre + cofres/s. DIRECTIONAL: loopback is in-process; tcp is a real kernel
/// hop on `127.0.0.1` (not a WAN — a WAN link adds `WanLink`'s latency per hop).
fn roundtrip<S: Substrate>(name: &str, mut sub: S, cofre: &Cofre, n: u32) {
    for _ in 0..(n / 10).max(1) {
        sub.send(cofre).ok();
        while sub.recv().ok().flatten().is_none() {}
    }
    let t = Instant::now();
    for _ in 0..n {
        sub.send(cofre).ok();
        while sub.recv().ok().flatten().is_none() {}
    }
    let elapsed = t.elapsed();
    let per = elapsed.as_nanos() / u128::from(n.max(1));
    let cps = f64::from(n) / elapsed.as_secs_f64().max(1e-9);
    println!("  {name:38} {per:>9} ns/cofre  (~{cps:.0} cofres/s, {n} cofres)");
}

fn main() {
    println!("datarail-bench — DIRECTIONAL on dev hardware; NOT GATE-WARP (needs representative VAES HW).\n");

    // ---- crypto throughput (64 KiB blocks) ----
    let buf = vec![0x5au8; 65_536];
    let key = [7u8; 32];
    let nonce = [3u8; 12];
    println!("crypto throughput (64 KiB blocks):");
    tput("blake3_256", 5000, buf.len(), || {
        black_box(blake3_256(black_box(&buf)));
    });
    tput("aes-256-gcm-siv seal", 3000, buf.len(), || {
        black_box(aead_seal(AeadAlg::Gcmsiv256, &key, &nonce, &[], black_box(&buf)).unwrap());
    });
    let ct = aead_seal(AeadAlg::Gcmsiv256, &key, &nonce, &[], &buf).unwrap();
    tput("aes-256-gcm-siv open", 3000, buf.len(), || {
        black_box(aead_open(AeadAlg::Gcmsiv256, &key, &nonce, &[], black_box(&ct)).unwrap());
    });
    // Single-pass AES-256-GCM (AeadAlg::Gcm256). With `--features vaes` this is ring's VAES asm (line-rate);
    // default is RustCrypto AES-NI. Sound here under the per-cofre fresh-key invariant (no nonce reuse).
    let backend = if cfg!(feature = "vaes") {
        "ring/VAES"
    } else {
        "RustCrypto/AES-NI"
    };
    tput(
        &format!("aes-256-gcm   seal [{backend}]"),
        3000,
        buf.len(),
        || {
            black_box(aead_seal(AeadAlg::Gcm256, &key, &nonce, &[], black_box(&buf)).unwrap());
        },
    );
    let ctg = aead_seal(AeadAlg::Gcm256, &key, &nonce, &[], &buf).unwrap();
    tput(
        &format!("aes-256-gcm   open [{backend}]"),
        3000,
        buf.len(),
        || {
            black_box(aead_open(AeadAlg::Gcm256, &key, &nonce, &[], black_box(&ctg)).unwrap());
        },
    );

    // ---- key-wrap + wire-codec latency ----
    println!("\nkey-wrap + wire-codec latency:");
    let dest_secret = [9u8; 32];
    let dest_pk = x25519_public(&dest_secret);
    lat("x25519 seal_key (source)", 20_000, || {
        black_box(seal_key(black_box(&dest_pk), &[3u8; 32]));
    });
    let Some((eph, _k)) = seal_key(&dest_pk, &[3u8; 32]) else {
        eprintln!("bench: seal_key returned None for a valid key — skipping key-wrap bench");
        return;
    };
    lat("x25519 open_key (dest)", 20_000, || {
        black_box(open_key(black_box(&dest_secret), black_box(&eph)));
    });

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
    let rec: [&[u8]; 1] = [b"evt:benchmark-payload"];
    let cofre = {
        let mut s = SourceTerminal::new(cfg.clone(), contract.clone(), src_seed);
        s.board(&rec, b"rk").unwrap()
    };
    let wire = encode(&cofre);
    lat("cofre encode", 50_000, || {
        black_box(encode(black_box(&cofre)));
    });
    lat("cofre decode", 50_000, || {
        black_box(decode(black_box(&wire)).unwrap());
    });

    // ---- terminal end-to-end (one record, including the X25519 wrap + OS entropy) ----
    println!("\nterminal end-to-end (1 record, incl. X25519 wrap + entropy):");
    lat("board (validate->wrap->seal)", 2000, || {
        let mut s = SourceTerminal::new(cfg.clone(), contract.clone(), src_seed);
        black_box(s.board(black_box(&rec), b"rk").unwrap());
    });
    lat("offload (verify->open->admit->commit)", 2000, || {
        let mut d = DestTerminal::new(cfg.clone(), contract.clone(), src_vk, [22; 32], dest_secret);
        black_box(d.offload(black_box(&cofre)).unwrap());
    });

    // ---- substrate round-trip (real transports; DIRECTIONAL, loopback only — NOT a WAN measurement) ----
    println!("\nsubstrate round-trip (send+drain interleaved; DIRECTIONAL on loopback):");
    roundtrip(
        "in-process LoopbackSubstrate",
        LoopbackSubstrate::new(),
        &cofre,
        20_000,
    );
    if let Ok(tcp) = TcpSubstrate::loopback_pair() {
        roundtrip("TCP loopback (real kernel hop)", tcp, &cofre, 5_000);
    }
    println!("  (a real WAN adds WanLink latency x hop + loss; AC-8 resume + dedup recover drops — see tests.)");

    head_to_head(&cfg, &contract, src_seed, src_vk, dest_secret);

    fairness::report();
}

/// HEAD-TO-HEAD: datarail moving the SAME workload Kafka was measured on (256 B records), batched + SEALED,
/// through the full board → loopback → offload pipe. Kafka (2 vCPU, 256 B, acks=1, PLAINTEXT) measured
/// 90,661 rec/s / 22 MB/s; datarail seals every record AND is provider-blind. Apples-to-apples on record size;
/// batching amortizes the per-cofre X25519 wrap (SPEC: batch-many-records-per-cofre).
fn head_to_head(
    cfg: &TerminalConfig,
    contract: &ContentContract,
    src_seed: [u8; 32],
    src_vk: [u8; 32],
    dest_secret: [u8; 32],
) {
    const REC: usize = 256;
    const PER_COFRE: usize = 1024;
    println!("\nhead-to-head workload (256 B records, 1024/cofre, full board->loopback->offload, SEALED):");
    let mut payload = b"evt:".to_vec();
    payload.resize(REC, b'x');
    let recs: Vec<&[u8]> = (0..PER_COFRE).map(|_| payload.as_slice()).collect();
    let iters: u32 = 1000;
    let mut s = SourceTerminal::new(cfg.clone(), contract.clone(), src_seed);
    let mut d = DestTerminal::new(cfg.clone(), contract.clone(), src_vk, [22; 32], dest_secret);
    let mut sub = LoopbackSubstrate::new();
    for _ in 0..(iters / 10).max(1) {
        let c = s.board(&recs, b"warm").unwrap();
        sub.send(&c).unwrap();
        while sub.recv().ok().flatten().is_none() {}
    }
    let t = Instant::now();
    for i in 0..iters {
        let rk = u64::from(i).to_le_bytes(); // unique per cofre ⇒ Delivered (not deduped)
        let c = s.board(&recs, &rk).unwrap();
        sub.send(&c).unwrap();
        loop {
            if let Some(g) = sub.recv().ok().flatten() {
                black_box(d.offload(&g).unwrap());
                sub.ack(g.etiqueta.cofre_id).ok();
                break;
            }
        }
    }
    let micros = u64::try_from(t.elapsed().as_micros())
        .unwrap_or(u64::MAX)
        .max(1);
    let total = u64::from(iters).saturating_mul(u64::try_from(PER_COFRE).unwrap_or(1));
    let recs_per_s = total.saturating_mul(1_000_000) / micros;
    let mb_per_s = total.saturating_mul(u64::try_from(REC).unwrap_or(1)) / micros;
    println!("  datarail SEALED: {recs_per_s:>10} rec/s  ({mb_per_s} MB/s)   [Kafka ref 2vCPU: 90,661 rec/s / 22 MB/s, PLAINTEXT]");
}
