//! FULL-CHAIN bidirectional proof: spawn the real `datarail kafka-broker` binary, PRODUCE records over the Kafka
//! wire, then FETCH them back — getting the original plaintext, having stored only sealed cofres. No external
//! deps (durable on-disk store under a temp dir, TCP loopback) so this runs in normal CI. Proves `serve_broker` +
//! the CLI durable sealed store + the Fetch/ListOffsets wire end-to-end (see `KAFKA-FETCH-DESIGN.md`). The second
//! phase KILLS the broker and restarts it on the SAME data dir — proving records survive a real process restart
//! (increment 2 durability), the moat over an in-memory store.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use datarail_kafka::codec::{Reader, Writer};
use datarail_kafka::produce::parse_record_batch;

fn req_header(api_key: i16, api_version: i16, correlation_id: i32) -> Writer {
    let mut w = Writer::new();
    w.int16(api_key);
    w.int16(api_version);
    w.int32(correlation_id);
    w.nullable_string(Some("broker-wire"));
    w
}

fn record_batch_with_coord(
    values: &[&[u8]],
    producer_id: i64,
    producer_epoch: i16,
    base_sequence: i32,
) -> Vec<u8> {
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
    b.int64(producer_id);
    b.int16(producer_epoch);
    b.int32(base_sequence);
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

fn idempotent_produce_req(
    correlation_id: i32,
    topic: &str,
    values: &[&[u8]],
    producer_id: i64,
    producer_epoch: i16,
    base_sequence: i32,
) -> Vec<u8> {
    let batch = record_batch_with_coord(values, producer_id, producer_epoch, base_sequence);
    let mut w = req_header(0, 7, correlation_id);
    w.nullable_string(None);
    w.int16(-1);
    w.int32(30_000);
    w.int32(1);
    w.string(topic);
    w.int32(1);
    w.int32(0);
    w.bytes(&batch);
    Writer::frame(&w.into_bytes())
}

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
    w.int32(-1); // replica_id
    w.int32(100); // max_wait_ms
    w.int32(1); // min_bytes
    w.int32(1_048_576); // max_bytes (v3+)
    w.int8(0); // isolation_level (v4+)
    w.int32(1); // 1 topic
    w.string(topic);
    w.int32(1); // 1 partition
    w.int32(0); // partition 0
    w.int64(fetch_offset);
    w.int32(1_048_576); // partition max_bytes
    Writer::frame(&w.into_bytes())
}

fn list_offsets_req(correlation_id: i32, topic: &str) -> Vec<u8> {
    let mut w = req_header(2, 1, correlation_id);
    w.int32(-1); // replica_id
    w.int32(1);
    w.string(topic);
    w.int32(1);
    w.int32(0); // partition
    w.int64(-1); // latest
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

/// Parse a Fetch v4 response payload → the plaintext values from its single topic/partition record-set.
fn fetch_values(resp: &[u8]) -> Vec<Vec<u8>> {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    let _throttle = r.int32().unwrap(); // v1+
    let topic_count = r.int32().unwrap();
    assert_eq!(topic_count, 1);
    let _name = r.string().unwrap();
    let part_count = r.int32().unwrap();
    assert_eq!(part_count, 1);
    let _partition = r.int32().unwrap();
    let error = r.int16().unwrap();
    assert_eq!(error, 0, "fetch error_code must be NONE");
    let _high_wm = r.int64().unwrap();
    let _last_stable = r.int64().unwrap(); // v4+
    let _aborted = r.int32().unwrap(); // v4+ null array (-1)
    let record_set = r.nullable_bytes().unwrap();
    match record_set {
        None => Vec::new(),
        Some(blob) => {
            parse_record_batch(&blob)
                .expect("parse fetched batch")
                .values
        }
    }
}

/// Parse a `ListOffsets` v1 response payload → the latest offset for its single topic/partition.
fn list_offset_latest(resp: &[u8]) -> i64 {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    let topic_count = r.int32().unwrap();
    assert_eq!(topic_count, 1);
    let _name = r.string().unwrap();
    let _pc = r.int32().unwrap();
    let _partition = r.int32().unwrap();
    let _error = r.int16().unwrap();
    let _timestamp = r.int64().unwrap(); // v1
    r.int64().unwrap() // offset
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `datarail kafka-broker` on `port` over `data_dir`, and return the daemon + a connected stream once it is
/// listening. (Killing the returned `Daemon` and calling this again with the same `data_dir` simulates a restart.)
fn spawn_broker(
    rail: &std::path::Path,
    data_dir: &std::path::Path,
    port: u16,
) -> (Daemon, TcpStream) {
    let child = Command::new(env!("CARGO_BIN_EXE_datarail"))
        .args([
            "kafka-broker",
            rail.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--data-dir",
            data_dir.to_str().unwrap(),
        ])
        .spawn()
        .expect("spawn datarail kafka-broker");
    let mut daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    let stream = loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            break s;
        }
        if let Ok(Some(status)) = daemon.0.try_wait() {
            panic!("kafka-broker exited before listening: {status}");
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

#[test]
fn produce_then_fetch_round_trips_and_survives_a_broker_restart() {
    let rail = std::env::temp_dir().join(format!("kafka-broker-{}.toml", std::process::id()));
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
    let data_dir = std::env::temp_dir().join(format!("kafka-broker-data-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let reservation = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a loopback port");
    let port = reservation
        .local_addr()
        .expect("read reserved loopback port")
        .port();
    drop(reservation);

    // ---- PHASE 1: produce + fetch through a live broker ----
    {
        let (_daemon, mut stream) = spawn_broker(&rail, &data_dir, port);

        // PRODUCE 3 records (sealed + durably stored by the broker).
        stream
            .write_all(&idempotent_produce_req(
                1,
                "events",
                &[b"evt:m0", b"evt:m1", b"evt:m2"],
                41,
                2,
                0,
            ))
            .unwrap();
        let _ = read_frame(&mut stream);

        // FETCH from offset 0 → the original plaintext back (un-sealed at the edge).
        stream.write_all(&fetch_req(2, "events", 0)).unwrap();
        let resp = read_frame(&mut stream);
        let values = fetch_values(&resp);
        assert_eq!(
            values,
            vec![b"evt:m0".to_vec(), b"evt:m1".to_vec(), b"evt:m2".to_vec()],
            "a consumer fetches back exactly what was produced (provider-blind bidirectional Kafka)"
        );

        // FETCH a suffix (offset 1) → m1, m2.
        stream.write_all(&fetch_req(3, "events", 1)).unwrap();
        let resp = read_frame(&mut stream);
        assert_eq!(
            fetch_values(&resp),
            vec![b"evt:m1".to_vec(), b"evt:m2".to_vec()]
        );

        // LISTOFFSETS latest → 3.
        stream.write_all(&list_offsets_req(4, "events")).unwrap();
        let resp = read_frame(&mut stream);
        assert_eq!(list_offset_latest(&resp), 3, "latest offset = record count");
        // _daemon dropped here → the broker process is killed (simulating a crash/restart).
    }

    // The on-disk data dir holds only ciphertext — a snapshot of the killed broker's storage reveals no plaintext.
    let on_disk = read_all_under(&data_dir);
    assert!(!on_disk.is_empty(), "the durable log persisted to disk");
    assert!(
        !contains(&on_disk, b"evt:m0")
            && !contains(&on_disk, b"evt:m1")
            && !contains(&on_disk, b"evt:m2"),
        "on-disk bytes are sealed ciphertext, never plaintext (provider-blind across restart)"
    );

    exercise_idempotent_restart(&rail, &data_dir, port);

    let _ = std::fs::remove_file(&rail);
    let _ = std::fs::remove_dir_all(&data_dir);
}

fn exercise_idempotent_restart(rail: &std::path::Path, data_dir: &std::path::Path, port: u16) {
    let (_daemon, mut stream) = spawn_broker(rail, data_dir, port);
    stream
        .write_all(&idempotent_produce_req(
            5,
            "events",
            &[b"evt:m0", b"evt:m1", b"evt:m2"],
            41,
            2,
            0,
        ))
        .unwrap();
    let (base, error) = produce_ack(&read_frame(&mut stream));
    assert_eq!(error, 0, "retry of committed sequence must ack cleanly");
    assert_eq!(base, 0, "retry must return original stable base offset");
    stream
        .write_all(&idempotent_produce_req(6, "events", &[b"evt:m3"], 41, 2, 3))
        .unwrap();
    let (base, error) = produce_ack(&read_frame(&mut stream));
    assert_eq!(error, 0);
    assert_eq!(base, 3, "new sequence appends at stable next offset");
    stream.write_all(&list_offsets_req(7, "events")).unwrap();
    assert_eq!(list_offset_latest(&read_frame(&mut stream)), 4);
    stream.write_all(&fetch_req(8, "events", 0)).unwrap();
    assert_eq!(
        fetch_values(&read_frame(&mut stream)),
        vec![
            b"evt:m0".to_vec(),
            b"evt:m1".to_vec(),
            b"evt:m2".to_vec(),
            b"evt:m3".to_vec(),
        ]
    );
    stream.write_all(&fetch_req(9, "events", 3)).unwrap();
    assert_eq!(
        fetch_values(&read_frame(&mut stream)),
        vec![b"evt:m3".to_vec()]
    );
}

/// Recursively read+concatenate every file under `dir` (for the on-disk provider-blind check).
fn read_all_under(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(read_all_under(&path));
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.extend(bytes);
            }
        }
    }
    out
}

/// True if `haystack` contains `needle` as a contiguous subslice.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
