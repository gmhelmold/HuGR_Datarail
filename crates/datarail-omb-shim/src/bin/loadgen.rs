//! `datarail-loadgen` — a native, minimal-overhead TCP load generator for the datarail OMB shim.
//!
//! WHY THIS EXISTS: the OMB Java `LocalWorker` provably could not saturate datarail's sealed shim — three
//! independent shim optimizations (hot-path, flusher consolidation, full async rewrite) each moved the OMB
//! aggregate ~0 %, which localized that ~620–660 MB/s ceiling to the *measurement client*, not datarail. To
//! find datarail's TRUE sealed throughput we need a driver that is not itself the bottleneck. This is it: per
//! topic it blasts pre-built `[u32 len][u64 ts][payload]` frames in bulk (one `write_all` per many messages,
//! no per-message future/histogram), drains acks in bulk, and counts delivered frames on the egress side. The
//! shim's bounded ingress queue self-throttles the producer to the shim's real rate, so the measured egress
//! delivery rate IS datarail's sustained sealed throughput on the hardware.
//!
//! It speaks the frozen `docs/design/OMB-PROTOCOL.md` wire format, so it exercises the EXACT same sealed
//! datapath the OMB benchmark does (board → seal → relay → offload → open → deliver) over real localhost TCP.
//!
//! Usage: `datarail-loadgen [topics] [msg_size] [warmup_secs] [measure_secs] [ingress_addr] [egress_addr]`
//! (all positional, all optional; defaults: 16 4096 5 20 127.0.0.1:7701 127.0.0.1:7702).
//! NOT a product component — a measurement tool (same status as the rest of this adapter crate).

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Per-message frame header on the wire: `[u32 payload_len][u64 publish_ts]`.
const FRAME_HEADER: usize = 12;
/// Producer batches this many identical frames into one buffer and writes them with a single `write_all`.
const FRAMES_PER_WRITE: usize = 1024;
/// Egress read chunk; large so frame-counting costs few syscalls.
const READ_CHUNK: usize = 1 << 18;

/// Parsed positional args with the documented defaults.
struct Args {
    topics: usize,
    msg_size: usize,
    warmup_secs: u64,
    measure_secs: u64,
    ingress_addr: String,
    egress_addr: String,
}

fn parse_args() -> Args {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let get_usize = |i: usize, d: usize| a.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    let get_u64 = |i: usize, d: u64| a.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    let get_str = |i: usize, d: &str| a.get(i).cloned().unwrap_or_else(|| d.to_owned());
    Args {
        topics: get_usize(0, 16),
        msg_size: get_usize(1, 4096),
        warmup_secs: get_u64(2, 5),
        measure_secs: get_u64(3, 20),
        ingress_addr: get_str(4, "127.0.0.1:7701"),
        egress_addr: get_str(5, "127.0.0.1:7702"),
    }
}

/// Build the length-prefixed `[u16 len][bytes]` header the shim reads first on each connection.
fn topic_header(topic: &str, sub: Option<&str>) -> Vec<u8> {
    let mut h = Vec::new();
    let t = topic.as_bytes();
    h.extend_from_slice(&u16::try_from(t.len()).unwrap_or(0).to_be_bytes());
    h.extend_from_slice(t);
    if let Some(s) = sub {
        let s = s.as_bytes();
        h.extend_from_slice(&u16::try_from(s.len()).unwrap_or(0).to_be_bytes());
        h.extend_from_slice(s);
    }
    h
}

/// Producer: stream pre-built frames as fast as the shim will accept (its bounded queue self-throttles us).
fn run_producer(
    addr: &str,
    topic: &str,
    msg_size: usize,
    stop: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    let mut sock = TcpStream::connect(addr)?;
    sock.set_nodelay(true)?;
    sock.write_all(&topic_header(topic, None))?;

    // Drain acks on a side handle so the shim's ack writes never block (which would stall its ingress).
    let ack_sock = sock.try_clone()?;
    let ack_stop = Arc::clone(stop);
    let ack_thread = thread::spawn(move || drain(ack_sock, &ack_stop));

    // One reusable buffer of FRAMES_PER_WRITE identical frames: [u32 len][u64 ts=0][payload of 0x78].
    let frame_len = FRAME_HEADER + msg_size;
    let mut batch = vec![0u8; frame_len * FRAMES_PER_WRITE];
    for i in 0..FRAMES_PER_WRITE {
        let off = i * frame_len;
        batch[off..off + 4].copy_from_slice(&u32::try_from(msg_size).unwrap_or(0).to_be_bytes());
        // ts stays 0 (loadgen measures throughput, not latency); payload stays 0x00 — content is opaque to the seal.
        for b in &mut batch[off + FRAME_HEADER..off + frame_len] {
            *b = 0x78;
        }
    }
    while !stop.load(Ordering::Relaxed) {
        sock.write_all(&batch)?;
    }
    drop(sock);
    let _ = ack_thread.join();
    Ok(())
}

/// Read-and-discard until `stop` (used to drain the ack stream so the shim never blocks writing acks).
fn drain(mut sock: TcpStream, stop: &Arc<AtomicBool>) {
    let mut buf = vec![0u8; READ_CHUNK];
    while !stop.load(Ordering::Relaxed) {
        match sock.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// Consumer: read delivered frames in bulk, count complete ones into `delivered` (no payload copy — just walk
/// the `[u32 len]` prefixes). Returns when `stop` is set or the socket closes.
fn run_consumer(
    addr: &str,
    topic: &str,
    delivered: &Arc<AtomicU64>,
    stop: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    let mut sock = TcpStream::connect(addr)?;
    sock.set_nodelay(true)?;
    sock.write_all(&topic_header(topic, Some("s")))?;

    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK * 2);
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut pending: u64 = 0; // counted-but-not-yet-published, flushed to the atomic in batches
    while !stop.load(Ordering::Relaxed) {
        let n = match sock.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        // Walk complete `[u32 len][u64 ts][payload]` frames; keep any partial tail.
        let mut pos = 0usize;
        while buf.len() - pos >= FRAME_HEADER {
            let len = usize::try_from(u32::from_be_bytes([
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
            ]))
            .unwrap_or(usize::MAX);
            let total = FRAME_HEADER.saturating_add(len);
            if buf.len() - pos < total {
                break;
            }
            pos += total;
            pending += 1;
            if pending >= 4096 {
                delivered.fetch_add(pending, Ordering::Relaxed);
                pending = 0;
            }
        }
        buf.drain(..pos);
    }
    delivered.fetch_add(pending, Ordering::Relaxed);
    Ok(())
}

fn main() {
    let args = parse_args();
    println!(
        "datarail-loadgen: topics={} msg_size={} warmup={}s measure={}s ingress={} egress={}",
        args.topics,
        args.msg_size,
        args.warmup_secs,
        args.measure_secs,
        args.ingress_addr,
        args.egress_addr
    );
    let delivered = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for i in 0..args.topics {
        let topic = format!("t{i}");
        // Consumer first so it is subscribed before the producer floods (the shim fans out to live subscribers).
        let (caddr, ctopic, cdel, cstop) = (
            args.egress_addr.clone(),
            topic.clone(),
            Arc::clone(&delivered),
            Arc::clone(&stop),
        );
        handles.push(thread::spawn(move || {
            if let Err(e) = run_consumer(&caddr, &ctopic, &cdel, &cstop) {
                eprintln!("consumer {ctopic}: {e}");
            }
        }));
    }
    thread::sleep(Duration::from_millis(300)); // let consumers register
    for i in 0..args.topics {
        let topic = format!("t{i}");
        let (paddr, ptopic, psize, pstop) = (
            args.ingress_addr.clone(),
            topic,
            args.msg_size,
            Arc::clone(&stop),
        );
        handles.push(thread::spawn(move || {
            if let Err(e) = run_producer(&paddr, &ptopic, psize, &pstop) {
                eprintln!("producer {ptopic}: {e}");
            }
        }));
    }

    // Warm up, then measure the delivered delta over the window. Integer math only (matches datarail-bench's
    // `tput`: bytes/µs == MB/s) — no float casts, no `#[allow]`.
    thread::sleep(Duration::from_secs(args.warmup_secs));
    let start_count = delivered.load(Ordering::Relaxed);
    let t0 = Instant::now();
    thread::sleep(Duration::from_secs(args.measure_secs));
    let end_count = delivered.load(Ordering::Relaxed);
    stop.store(true, Ordering::Relaxed);

    let msgs = u128::from(end_count - start_count);
    let micros = t0.elapsed().as_micros().max(1);
    let per_s = msgs.saturating_mul(1_000_000) / micros;
    let msg_size = u128::try_from(args.msg_size).unwrap_or(0);
    let mb_s = msgs.saturating_mul(msg_size) / micros; // bytes/µs == MB/s
    println!(
        "RESULT topics={} msg_size={} : {per_s} msg/s  {mb_s} MB/s  (delivered {msgs} in {micros} us)",
        args.topics, args.msg_size
    );
    for h in handles {
        let _ = h.join();
    }
}
