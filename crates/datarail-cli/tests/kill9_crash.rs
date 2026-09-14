//! The hard-crash durability harness the README promised: spawn the real `datarail kafka-broker` binary,
//! produce acked batches over the real Kafka wire, **SIGKILL the process** (no shutdown path of any kind),
//! restart it on the same data dir, and assert that EVERY acked record is fetchable at its exact acked
//! offset, across several kill/restart rounds — including one kill fired with a produce still in flight
//! (that batch is allowed to be absent or fully present, never torn, and must not disturb acked offsets).
//!
//! This is a stronger claim than the store-reopen tests: the broker gets no `Drop`, no flush, no atexit —
//! `kill -9` semantics. It is still NOT a power-loss test (the kernel's page cache survives the process),
//! so fsync ordering bugs that only a power cut exposes remain out of scope — documented in the README.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use datarail_kafka::codec::{Reader, Writer};
use datarail_kafka::produce::parse_record_batch;

const PORT: u16 = 19_297;

fn req_header(api_key: i16, api_version: i16, correlation_id: i32) -> Writer {
    let mut w = Writer::new();
    w.int16(api_key);
    w.int16(api_version);
    w.int32(correlation_id);
    w.nullable_string(Some("kill9-crash"));
    w
}

/// A non-idempotent v2 `RecordBatch` blob carrying `values` (`producer_id` = -1), with the real CRC-32C
/// stamped (the broker validates it on produce).
fn record_batch(values: &[&[u8]]) -> Vec<u8> {
    let mut recs = Writer::new();
    for (i, v) in values.iter().enumerate() {
        let mut r = Writer::new();
        r.int8(0);
        r.varlong(0);
        r.varint(i32::try_from(i).unwrap());
        r.varint(-1);
        r.varint(i32::try_from(v.len()).unwrap());
        r.raw(v);
        r.varint(0);
        let body = r.into_bytes();
        recs.varint(i32::try_from(body.len()).unwrap());
        recs.raw(&body);
    }
    let records = recs.into_bytes();
    let mut b = Writer::new();
    b.int32(0);
    b.int8(2);
    b.uint32(0); // crc placeholder — the real CRC-32C is stamped below
    b.int16(0);
    b.int32(i32::try_from(values.len().saturating_sub(1)).unwrap());
    b.int64(0);
    b.int64(0);
    b.int64(-1);
    b.int16(-1);
    b.int32(-1);
    b.int32(i32::try_from(values.len()).unwrap());
    b.raw(&records);
    let mut after = b.into_bytes();
    let crc = datarail_kafka::produce::crc32c(&after[9..]);
    after[5..9].copy_from_slice(&crc.to_be_bytes());
    let mut full = Writer::new();
    full.int64(0);
    full.int32(i32::try_from(after.len()).unwrap());
    full.raw(&after);
    full.into_bytes()
}

fn produce_req(correlation_id: i32, topic: &str, values: &[&[u8]]) -> Vec<u8> {
    let batch = record_batch(values);
    let mut w = req_header(0, 7, correlation_id);
    w.nullable_string(None);
    w.int16(1); // acks=1 — the ack is the durability contract this harness holds the broker to
    w.int32(30_000);
    w.int32(1);
    w.string(topic);
    w.int32(1);
    w.int32(0);
    w.bytes(&batch);
    Writer::frame(&w.into_bytes())
}

/// Parse a Produce v7 response payload → (`base_offset`, `error_code`) of its single topic/partition.
fn produce_ack(resp: &[u8]) -> (i64, i16) {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    let topic_count = r.int32().unwrap();
    assert_eq!(topic_count, 1);
    let _name = r.string().unwrap();
    let part_count = r.int32().unwrap();
    assert_eq!(part_count, 1);
    let _partition = r.int32().unwrap();
    let error = r.int16().unwrap();
    let base = r.int64().unwrap();
    (base, error)
}

fn fetch_req(correlation_id: i32, topic: &str, fetch_offset: i64) -> Vec<u8> {
    let mut w = req_header(1, 4, correlation_id);
    w.int32(-1);
    w.int32(100);
    w.int32(1);
    w.int32(1_048_576);
    w.int8(0);
    w.int32(1);
    w.string(topic);
    w.int32(1);
    w.int32(0);
    w.int64(fetch_offset);
    w.int32(1_048_576);
    Writer::frame(&w.into_bytes())
}

fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).expect("read length");
    let n = u32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).expect("read body");
    body
}

/// Parse a Fetch v4 response payload → the plaintext values of its single topic/partition record-set.
fn fetch_values(resp: &[u8]) -> Vec<Vec<u8>> {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    let _throttle = r.int32().unwrap();
    let topic_count = r.int32().unwrap();
    assert_eq!(topic_count, 1);
    let _name = r.string().unwrap();
    let part_count = r.int32().unwrap();
    assert_eq!(part_count, 1);
    let _partition = r.int32().unwrap();
    let error = r.int16().unwrap();
    assert_eq!(error, 0, "fetch after restart must be clean (error NONE)");
    let _high_wm = r.int64().unwrap();
    let _last_stable = r.int64().unwrap();
    let _aborted = r.int32().unwrap();
    match r.nullable_bytes().unwrap() {
        None => Vec::new(),
        Some(blob) => {
            parse_record_batch(&blob)
                .expect("parse fetched batch")
                .values
        }
    }
}

struct Daemon(Child);
impl Daemon {
    /// SIGKILL — no shutdown handler, no flush, no Drop runs inside the broker.
    fn kill9(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill9();
    }
}

fn spawn_broker(rail: &std::path::Path, data_dir: &std::path::Path) -> (Daemon, TcpStream) {
    let child = Command::new(env!("CARGO_BIN_EXE_datarail"))
        .args([
            "kafka-broker",
            rail.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{PORT}"),
            "--data-dir",
            data_dir.to_str().unwrap(),
        ])
        .spawn()
        .expect("spawn datarail kafka-broker");
    let daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    let stream = loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", PORT)) {
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "kafka-broker never started listening"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    (daemon, stream)
}

const ROUNDS: usize = 4;
const BATCHES_PER_ROUND: usize = 3;

#[test]
fn every_acked_record_survives_repeated_kill_minus_9() {
    let rail = std::env::temp_dir().join(format!("kill9-{}.toml", std::process::id()));
    std::fs::write(
        &rail,
        "[route]\n\
         route_id = \"0x07070707070707070707070707070707\"\n\
         stream_id = \"0x08080808080808080808080808080808\"\n\
         aead = \"gcm-siv-256\"\n\
         guarantee = \"exactly-once\"\n\
         [onboarding]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
         [offloading]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
         [keys]\n\
         source_seed = \"0x5555555555555555555555555555555555555555555555555555555555555555\"\n\
         dest_seed = \"0x5555555555555555555555555555555555555555555555555555555555555555\"\n\
         dest_x25519_secret = \"0x5555555555555555555555555555555555555555555555555555555555555555\"\n\
         tenant_secret = \"0x5555555555555555555555555555555555555555555555555555555555555555\"\n",
    )
    .unwrap();

    // Ledger of the harness's contract: every value the broker ACKED, at its acked offset.
    let mut acked: Vec<(i64, Vec<u8>)> = Vec::new();
    let mut corr = 0i32;

    let data_dir = std::env::temp_dir().join(format!("kill9-data-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);

    for round in 0..ROUNDS {
        let (mut daemon, mut stream) = spawn_broker(&rail, &data_dir);

        // (a) Produce a few acked batches this round.
        for batch in 0..BATCHES_PER_ROUND {
            let values: Vec<Vec<u8>> = (0..3)
                .map(|i| format!("evt:r{round}-b{batch}-i{i}").into_bytes())
                .collect();
            let refs: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
            corr += 1;
            stream
                .write_all(&produce_req(corr, "crash", &refs))
                .unwrap();
            let (base, error) = produce_ack(&read_frame(&mut stream));
            assert_eq!(
                error, 0,
                "produce must ack clean (round {round} batch {batch})"
            );
            for (i, v) in values.into_iter().enumerate() {
                acked.push((base + i64::try_from(i).unwrap(), v));
            }
        }

        // (b) Fire one more produce and SIGKILL with it IN FLIGHT (response never read). That batch is
        // Schrödinger's batch: it may or may not have landed durably before the kill — both are correct for
        // acks=1 — but it must never be torn and must never disturb the acked ledger's offsets.
        corr += 1;
        let inflight = produce_req(corr, "crash", &[format!("evt:inflight-{round}").as_bytes()]);
        let _ = stream.write_all(&inflight);
        daemon.kill9();

        // (c) Restart on the same data dir; every acked record must be at its exact acked offset.
        let (daemon, mut stream) = spawn_broker(&rail, &data_dir);
        corr += 1;
        stream.write_all(&fetch_req(corr, "crash", 0)).unwrap();
        let fetched = fetch_values(&read_frame(&mut stream));
        for (offset, value) in &acked {
            let at = usize::try_from(*offset).unwrap();
            assert!(
                at < fetched.len(),
                "acked offset {offset} missing after kill -9 (round {round}: {} fetched, {} acked)",
                fetched.len(),
                acked.len()
            );
            assert_eq!(
                &fetched[at], value,
                "acked record at offset {offset} corrupted after kill -9 (round {round})"
            );
        }
        // The Schrödinger batch may add records past the acked ledger; anything present must be readable
        // (fetch_values already asserts a clean, decodable log) — and the count can exceed by at most the
        // in-flight batches so far.
        assert!(
            fetched.len() >= acked.len() && fetched.len() <= acked.len() + ROUNDS,
            "round {round}: fetched {} outside [acked={}, acked+{ROUNDS}]",
            fetched.len(),
            acked.len()
        );
        // If the in-flight batch DID land, adopt it into the ledger so later rounds assert against it too.
        for (i, v) in fetched.iter().enumerate().skip(acked.len()) {
            acked.push((i64::try_from(i).unwrap(), v.clone()));
        }
        drop(daemon); // clean kill between rounds (Drop = kill9)
    }

    let _ = std::fs::remove_dir_all(&data_dir);
    let _ = std::fs::remove_file(&rail);
}
