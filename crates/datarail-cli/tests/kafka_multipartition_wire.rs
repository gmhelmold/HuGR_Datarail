//! FULL-CHAIN multi-partition proof: spawn the real `datarail kafka-broker --partitions 3`, assert `Metadata`
//! advertises 3 partitions, then produce to a NON-ZERO partition and fetch it back independently (each partition
//! has its own offset space). Proves the broker is genuinely multi-partition (`KAFKA-GROUPS-DESIGN.md` increment 4
//! foundation). Runs in normal CI (durable on-disk store under a temp dir, TCP loopback).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use datarail_kafka::codec::{Reader, Writer};
use datarail_kafka::produce::parse_record_batch;

const PORT: u16 = 19_095;

fn req_header(api_key: i16, api_version: i16, correlation_id: i32) -> Writer {
    let mut w = Writer::new();
    w.int16(api_key);
    w.int16(api_version);
    w.int32(correlation_id);
    w.nullable_string(Some("mp-wire"));
    w
}

/// A non-idempotent v2 `RecordBatch` blob carrying `values`.
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
    b.uint32(0);
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
    // Stamp the real CRC-32C (the broker VALIDATES it on produce since 2026-07-02): the 4-byte crc
    // field sits at after[5..9] and covers attributes..end = after[9..].
    let crc = datarail_kafka::produce::crc32c(&after[9..]);
    after[5..9].copy_from_slice(&crc.to_be_bytes());
    let mut full = Writer::new();
    full.int64(0);
    full.int32(i32::try_from(after.len()).unwrap());
    full.raw(&after);
    full.into_bytes()
}

fn metadata_req(correlation_id: i32, topic: &str) -> Vec<u8> {
    let mut w = req_header(3, 1, correlation_id);
    w.int32(1); // 1 topic
    w.string(topic);
    Writer::frame(&w.into_bytes())
}

fn produce_req(correlation_id: i32, topic: &str, partition: i32, values: &[&[u8]]) -> Vec<u8> {
    let batch = record_batch(values);
    let mut w = req_header(0, 7, correlation_id);
    w.nullable_string(None);
    w.int16(-1);
    w.int32(30_000);
    w.int32(1);
    w.string(topic);
    w.int32(1);
    w.int32(partition);
    w.bytes(&batch);
    Writer::frame(&w.into_bytes())
}

fn fetch_req(correlation_id: i32, topic: &str, partition: i32, fetch_offset: i64) -> Vec<u8> {
    let mut w = req_header(1, 4, correlation_id);
    w.int32(-1);
    w.int32(100);
    w.int32(1);
    w.int32(1_048_576);
    w.int8(0);
    w.int32(1);
    w.string(topic);
    w.int32(1);
    w.int32(partition);
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

/// Parse a `Metadata` v1 response → the number of partitions advertised for its single topic.
fn metadata_partition_count(resp: &[u8]) -> i32 {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    let broker_count = r.int32().unwrap();
    for _ in 0..broker_count {
        let _node = r.int32().unwrap();
        let _host = r.string().unwrap();
        let _port = r.int32().unwrap();
        let _rack = r.nullable_string().unwrap(); // v1
    }
    let _controller = r.int32().unwrap(); // v1
    let topic_count = r.int32().unwrap();
    assert_eq!(topic_count, 1, "one topic");
    let _err = r.int16().unwrap();
    let _name = r.string().unwrap();
    let _is_internal = r.int8().unwrap(); // v1
    r.int32().unwrap() // partition array length
}

/// Parse a Fetch v4 response → the plaintext values from its single topic/partition record-set.
fn fetch_values(resp: &[u8]) -> Vec<Vec<u8>> {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    let _throttle = r.int32().unwrap();
    assert_eq!(r.int32().unwrap(), 1);
    let _name = r.string().unwrap();
    assert_eq!(r.int32().unwrap(), 1);
    let _partition = r.int32().unwrap();
    assert_eq!(r.int16().unwrap(), 0, "fetch error NONE");
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
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn broker_advertises_and_serves_multiple_partitions_independently() {
    let rail = std::env::temp_dir().join(format!("kafka-mp-{}.toml", std::process::id()));
    std::fs::write(
        &rail,
        "[route]\n\
         route_id = \"0x03030303030303030303030303030303\"\n\
         stream_id = \"0x04040404040404040404040404040404\"\n\
         aead = \"gcm-siv-256\"\n\
         guarantee = \"exactly-once\"\n\
         [onboarding]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
         [offloading]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
         [keys]\n\
         source_seed = \"0x2222222222222222222222222222222222222222222222222222222222222222\"\n\
         dest_seed = \"0x2222222222222222222222222222222222222222222222222222222222222222\"\n\
         dest_x25519_secret = \"0x2222222222222222222222222222222222222222222222222222222222222222\"\n\
         tenant_secret = \"0x2222222222222222222222222222222222222222222222222222222222222222\"\n",
    )
    .expect("write rail.toml");
    let data_dir = std::env::temp_dir().join(format!("kafka-mp-data-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);

    let child = Command::new(env!("CARGO_BIN_EXE_datarail"))
        .args([
            "kafka-broker",
            rail.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{PORT}"),
            "--advertised",
            "127.0.0.1",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--partitions",
            "3",
        ])
        .spawn()
        .expect("spawn datarail kafka-broker");
    let _daemon = Daemon(child);

    let mut stream = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", PORT)) {
                break s;
            }
            assert!(Instant::now() < deadline, "broker never started");
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Metadata advertises 3 partitions for the topic.
    stream.write_all(&metadata_req(1, "events")).unwrap();
    assert_eq!(
        metadata_partition_count(&read_frame(&mut stream)),
        3,
        "broker advertises 3 partitions"
    );

    // Produce to partition 2 ONLY.
    stream
        .write_all(&produce_req(2, "events", 2, &[b"evt:p2a", b"evt:p2b"]))
        .unwrap();
    let _ = read_frame(&mut stream);

    // Fetch partition 2 → the two records; partition 0 is an independent (empty) offset space.
    stream.write_all(&fetch_req(3, "events", 2, 0)).unwrap();
    assert_eq!(
        fetch_values(&read_frame(&mut stream)),
        vec![b"evt:p2a".to_vec(), b"evt:p2b".to_vec()]
    );
    stream.write_all(&fetch_req(4, "events", 0, 0)).unwrap();
    assert!(
        fetch_values(&read_frame(&mut stream)).is_empty(),
        "partition 0 is independent and empty"
    );

    // Produce to partition 0 → it has its OWN offset 0 (not continuing partition 2's).
    stream
        .write_all(&produce_req(5, "events", 0, &[b"evt:p0a"]))
        .unwrap();
    let _ = read_frame(&mut stream);
    stream.write_all(&fetch_req(6, "events", 0, 0)).unwrap();
    assert_eq!(
        fetch_values(&read_frame(&mut stream)),
        vec![b"evt:p0a".to_vec()],
        "partition 0 offset space is its own"
    );

    let _ = std::fs::remove_file(&rail);
    let _ = std::fs::remove_dir_all(&data_dir);
}
