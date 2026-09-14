//! Integration test for `datarail-omb-shim`: spawn the real binary on ephemeral ports, connect a producer and
//! a consumer over raw TCP exactly as the frozen `OMB-PROTOCOL.md` wire format prescribes, publish
//! `N = 1000 × 256 B` messages each carrying an embedded `publish_ts`, and assert the consumer receives **all
//! 1000**, with **byte-identical payloads**, **preserved `publish_ts`**, and **0 loss / 0 duplicate**.
//!
//! This drives the shim end-to-end through its full sealed datapath (board → in-process handoff → offload →
//! fan-out) — no shim internals are stubbed. The shim is launched as a subprocess (the binary under test) so
//! the test exercises the exact `main` wiring an OMB run would.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Number of messages the producer publishes.
const N: usize = 1000;
/// Payload size in bytes (the OMB head-to-head workload size).
const PAYLOAD_LEN: usize = 256;
/// Topic + subscription names used for the round-trip.
const TOPIC: &str = "bench-topic";
const SUB: &str = "sub-0";

/// A spawned shim subprocess; killed on drop so a failed assertion never leaks the child.
struct Shim {
    child: Child,
    ingress_addr: String,
    egress_addr: String,
}

impl Drop for Shim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the shim binary with `:0` (OS-assigned) ports and parse its announce line for the bound addresses.
fn spawn_shim() -> Shim {
    // Write a tiny config selecting ephemeral ports; loopback substrate (the default) is the in-process path.
    let dir = std::env::temp_dir().join(format!("omb-shim-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("shim.toml");
    std::fs::write(
        &cfg_path,
        "ingress_addr = \"127.0.0.1:0\"\negress_addr = \"127.0.0.1:0\"\nsubstrate = \"loopback\"\n",
    )
    .expect("write config");

    let bin = env!("CARGO_BIN_EXE_datarail-omb-shim");
    let mut child = Command::new(bin)
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn shim binary");

    // Read the single announce line: `DATARAIL-OMB-SHIM ingress=ADDR egress=ADDR substrate=...`. Cargo has
    // already built the binary before this test runs, so the child starts in milliseconds; a blocking
    // line-read is correct (no manual timeout that could trip under build/load contention).
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read announce line");
    assert!(n > 0, "shim exited before announcing its bound ports");
    let (ingress_addr, egress_addr) = parse_announce(line.trim_end());
    Shim {
        child,
        ingress_addr,
        egress_addr,
    }
}

/// Parse `DATARAIL-OMB-SHIM ingress=ADDR egress=ADDR substrate=...` into `(ingress_addr, egress_addr)`.
fn parse_announce(line: &str) -> (String, String) {
    let mut ingress = None;
    let mut egress = None;
    for tok in line.split_whitespace() {
        if let Some(a) = tok.strip_prefix("ingress=") {
            ingress = Some(a.to_owned());
        } else if let Some(a) = tok.strip_prefix("egress=") {
            egress = Some(a.to_owned());
        }
    }
    (
        ingress.unwrap_or_else(|| panic!("no ingress= in announce: {line:?}")),
        egress.unwrap_or_else(|| panic!("no egress= in announce: {line:?}")),
    )
}

/// Connect to `addr`, retrying briefly while the shim's accept loop comes up.
fn connect(addr: &str) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => return s,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "could not connect to {addr}: {e}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Write a `[u16 len][bytes]` big-endian length-prefixed field.
fn write_len_prefixed(stream: &mut TcpStream, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("field fits u16");
    stream.write_all(&len.to_be_bytes()).expect("write len");
    stream.write_all(bytes).expect("write field");
}

/// The expected payload for message `i`: 256 bytes whose first 4 bytes encode `i` (so every message differs).
fn payload_for(i: usize) -> Vec<u8> {
    let mut p = vec![0u8; PAYLOAD_LEN];
    p[0..4].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
    // Fill the tail with a position-dependent pattern so a swapped/duplicated payload is detectable.
    for (j, b) in p.iter_mut().enumerate().skip(4) {
        *b = u8::try_from((i + j) % 251).unwrap();
    }
    p
}

/// The publish timestamp embedded for message `i` (a deterministic but distinct, non-trivial value).
fn ts_for(i: usize) -> u64 {
    1_700_000_000_000 + i as u64
}

#[test]
fn roundtrip_1000_messages_zero_loss_zero_dup_ts_preserved() {
    let shim = spawn_shim();

    // 1) Connect the CONSUMER first and send its egress header, so its subscriber is registered before any
    //    message is published (fan-out only reaches already-registered subscribers).
    let mut consumer = connect(&shim.egress_addr);
    write_len_prefixed(&mut consumer, TOPIC.as_bytes());
    write_len_prefixed(&mut consumer, SUB.as_bytes());
    consumer.flush().expect("flush consumer header");
    // Give the egress thread a beat to register the subscriber channel on the (lazily created) topic.
    std::thread::sleep(Duration::from_millis(150));

    // 2) Connect the PRODUCER, send its ingress header, then pipeline all N frames.
    let mut producer = connect(&shim.ingress_addr);
    write_len_prefixed(&mut producer, TOPIC.as_bytes());

    // Spawn a reader for the consumer side BEFORE publishing, so a small egress buffer can never wedge the run.
    let consumer_handle = std::thread::spawn(move || drain_consumer(&mut consumer));

    // Pipeline the frames: [u32 payload_len][u64 publish_ts][payload].
    for i in 0..N {
        let payload = payload_for(i);
        let mut frame = Vec::with_capacity(12 + payload.len());
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&ts_for(i).to_be_bytes());
        frame.extend_from_slice(&payload);
        producer.write_all(&frame).expect("write frame");
    }
    producer.flush().expect("flush frames");

    // 3) Read the ack stream: exactly N monotonic-from-0 acks, in order.
    let acks = read_acks(&mut producer, N);
    assert_eq!(acks.len(), N, "expected {N} acks");
    for (i, seq) in acks.iter().enumerate() {
        assert_eq!(
            *seq, i as u64,
            "ack {i} should be monotonic seq {i}, got {seq}"
        );
    }

    // 4) Collect delivered frames from the consumer thread.
    let delivered = consumer_handle.join().expect("consumer thread");

    // ---- ASSERTIONS: all N, byte-identical, ts preserved, 0 loss / 0 dup. ----
    assert_eq!(
        delivered.len(),
        N,
        "consumer must receive all {N} messages (0 loss)"
    );

    // Every message index must appear exactly once (0 dup), with the right payload and ts.
    let mut seen = vec![0u32; N];
    for (payload, ts) in &delivered {
        assert_eq!(payload.len(), PAYLOAD_LEN, "payload length preserved");
        let idx = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        assert!(idx < N, "decoded index {idx} out of range");
        assert_eq!(payload, &payload_for(idx), "payload {idx} byte-identical");
        assert_eq!(*ts, ts_for(idx), "publish_ts {idx} preserved");
        seen[idx] += 1;
    }
    for (idx, count) in seen.iter().enumerate() {
        assert_eq!(
            *count, 1,
            "message {idx} delivered exactly once (got {count}) — 0 loss / 0 dup"
        );
    }
}

/// Read exactly `count` `[u64 seq]` big-endian acks from the producer socket.
fn read_acks(stream: &mut TcpStream, count: usize) -> Vec<u64> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set ack read timeout");
    let mut acks = Vec::with_capacity(count);
    let mut buf = [0u8; 8];
    for _ in 0..count {
        read_exact(stream, &mut buf).expect("read ack");
        acks.push(u64::from_be_bytes(buf));
    }
    acks
}

/// Drain delivered `[u32 payload_len][u64 publish_ts][payload]` frames from the consumer socket until `N` have
/// arrived (or a read timeout fires — a wedge surfaces as a short result the assertions catch).
fn drain_consumer(stream: &mut TcpStream) -> Vec<(Vec<u8>, u64)> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set consumer read timeout");
    let mut out = Vec::with_capacity(N);
    let mut hdr = [0u8; 12];
    while out.len() < N {
        if read_exact(stream, &mut hdr).is_err() {
            break; // timeout / close: return what we have; the test asserts on the count.
        }
        let payload_len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let ts = u64::from_be_bytes([
            hdr[4], hdr[5], hdr[6], hdr[7], hdr[8], hdr[9], hdr[10], hdr[11],
        ]);
        let mut payload = vec![0u8; payload_len];
        if read_exact(stream, &mut payload).is_err() {
            break;
        }
        out.push((payload, ts));
    }
    out
}

/// Fill `buf` exactly, tolerating short reads but surfacing EOF/timeout as an error.
fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
