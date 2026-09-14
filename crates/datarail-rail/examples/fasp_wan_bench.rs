//! S3 goodput bench (FASP-UDP-TRANSPORT.md): move bytes A→B over `FaspLink` (UDP, our delay-based controller)
//! and over kernel TCP, on the same loopback, for a FIXED DURATION (iperf-style — the only sane way to measure
//! goodput under loss, where a fixed-byte transfer over a collapsed link would take ~forever). Run it under
//! `tc netem` (applied externally on `lo`) so a real kernel injects loss + delay equally on both — turning the
//! sim's 16–42× into a real-socket number, whatever it is. Prints `fasp_mbps=… tcp_mbps=… ratio=…`.
//!
//! Usage: `cargo run --release --example fasp_wan_bench -p datarail-rail -- [seconds]`

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use datarail_rail::reliable_udp::{FaspCfg, FaspLink, MAX_FASP_PAYLOAD};

fn loopback() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

/// Goodput in MB/s (decimal megabytes), converting the byte count losslessly via `u32` (the MB count is tiny).
fn mbps(bytes: u64, secs: f64) -> f64 {
    let mb = f64::from(u32::try_from(bytes / 1_000_000).unwrap_or(u32::MAX));
    if secs > 0.0 {
        mb / secs
    } else {
        0.0
    }
}

/// Push messages over a real UDP `FaspLink` for `secs`, then drain in-flight; return MB/s of bytes *delivered*.
fn bench_fasp(secs: u64) -> f64 {
    let cfg = FaspCfg {
        max_inflight: 8192,
        max_window: 8192.0,
        init_window: 64.0,
        min_window: 8.0,
        rto: Duration::from_millis(120),
        queue_threshold: Duration::from_millis(10),
        recv_window: 8192, // ≥ max_inflight so the receiver accepts the full in-flight window
        send_timeout: Duration::from_secs(60),
        loss_sim_drop_every: 0, // real loss comes from tc netem, not the simulator
    };
    let mut a = FaspLink::bind(loopback(), cfg).expect("bind a");
    let mut b = FaspLink::bind(loopback(), cfg).expect("bind b");
    let a_addr = a.local_addr().expect("a addr");
    let b_addr = b.local_addr().expect("b addr");
    a.set_peer(b_addr);
    b.set_peer(a_addr);

    let delivered = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let rx = {
        let delivered = Arc::clone(&delivered);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let mut local = 0u64;
            while !stop.load(Ordering::Relaxed) {
                while b.recv().expect("recv").is_some() {
                    local += 1;
                }
            }
            for _ in 0..200 {
                while b.recv().expect("recv").is_some() {
                    local += 1;
                }
                thread::sleep(Duration::from_millis(1));
            }
            delivered.store(local, Ordering::Relaxed);
        })
    };

    let payload = [0u8; MAX_FASP_PAYLOAD];
    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    while Instant::now() < deadline {
        a.send(&payload).expect("send");
    }
    // Drain in-flight so the delivered count reflects work actually completed.
    let drain_end = Instant::now() + Duration::from_millis(800);
    while Instant::now() < drain_end {
        a.pump().expect("pump");
    }
    let elapsed = start.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    rx.join().expect("rx join");
    mbps(
        delivered.load(Ordering::Relaxed) * MAX_FASP_PAYLOAD as u64,
        elapsed,
    )
}

/// Push bytes over kernel TCP on the same loopback for `secs`; return MB/s of bytes *received* (timing starts
/// after `connect`, so the comparison is goodput, not the TCP handshake).
fn bench_tcp(secs: u64) -> f64 {
    let listener = TcpListener::bind(loopback()).expect("tcp bind");
    let addr = listener.local_addr().expect("tcp addr");
    let received = Arc::new(AtomicU64::new(0));
    let acc = {
        let received = Arc::clone(&received);
        thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut sink = vec![0u8; 1 << 16];
            let mut got = 0u64;
            loop {
                match s.read(&mut sink) {
                    Ok(n) if n > 0 => got += n as u64,
                    _ => break, // EOF (Ok(0)) or error → done
                }
            }
            received.store(got, Ordering::Relaxed);
        })
    };
    let mut c = TcpStream::connect(addr).expect("connect");
    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    let buf = vec![0u8; 1 << 16];
    while Instant::now() < deadline {
        if c.write(&buf).is_err() {
            break;
        }
    }
    c.flush().ok();
    c.shutdown(std::net::Shutdown::Write).ok();
    acc.join().expect("acc join");
    mbps(
        received.load(Ordering::Relaxed),
        start.elapsed().as_secs_f64(),
    )
}

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let fasp = bench_fasp(secs);
    let tcp = bench_tcp(secs);
    let ratio = if tcp > 0.0 { fasp / tcp } else { 0.0 };
    println!("fasp_mbps={fasp:.2} tcp_mbps={tcp:.2} ratio={ratio:.2}");
}
