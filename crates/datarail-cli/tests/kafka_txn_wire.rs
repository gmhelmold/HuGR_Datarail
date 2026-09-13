//! FULL-CHAIN transactional-EOS proof: spawn the real `datarail kafka-broker` and drive a TRANSACTIONAL producer
//! through `InitProducerId`(`transactional_id`) → `AddPartitionsToTxn` → (transactional) Produce → `EndTxn`. Asserts:
//! buffered records are INVISIBLE before commit; a successful COMMIT makes them visible across two partitions; an
//! ABORT discards them (never visible). `KAFKA-TXN-DESIGN.md` (buffer-until-commit model). Runs in normal CI.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use datarail_kafka::codec::{Reader, Writer};
use datarail_kafka::produce::parse_record_batch;

static BROKER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    listener.local_addr().expect("read ephemeral port").port()
}

fn req_header(api_key: i16, api_version: i16, correlation_id: i32) -> Writer {
    let mut w = Writer::new();
    w.int16(api_key);
    w.int16(api_version);
    w.int32(correlation_id);
    w.nullable_string(Some("txn-wire"));
    w
}

fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).expect("read length");
    let n = u32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).expect("read body");
    body
}

/// A TRANSACTIONAL v2 `RecordBatch`: attributes bit `0x10` set, carrying `(producer_id, epoch, base_sequence)`.
fn txn_record_batch(values: &[&[u8]], producer_id: i64, epoch: i16, base_sequence: i32) -> Vec<u8> {
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
    b.int32(0); // partition_leader_epoch
    b.int8(2); // magic v2
    b.uint32(0); // crc placeholder — the real CRC-32C is stamped below
    b.int16(0x10); // attributes: bit 4 = transactional, uncompressed
    b.int32(i32::try_from(values.len().saturating_sub(1)).unwrap());
    b.int64(0);
    b.int64(0);
    b.int64(producer_id);
    b.int16(epoch);
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

fn init_producer_id_req(correlation_id: i32, transactional_id: &str) -> Vec<u8> {
    let mut w = req_header(22, 1, correlation_id);
    w.nullable_string(Some(transactional_id));
    w.int32(60_000); // transaction_timeout_ms
    Writer::frame(&w.into_bytes())
}

/// Parse an `InitProducerId` v1 response → (`producer_id`, epoch).
fn init_producer_id(resp: &[u8]) -> (i64, i16) {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    let _throttle = r.int32().unwrap();
    assert_eq!(r.int16().unwrap(), 0, "InitProducerId error NONE");
    let pid = r.int64().unwrap();
    let epoch = r.int16().unwrap();
    (pid, epoch)
}

fn add_partitions_req(
    correlation_id: i32,
    tid: &str,
    pid: i64,
    epoch: i16,
    topic: &str,
    partitions: &[i32],
) -> Vec<u8> {
    let mut w = req_header(24, 1, correlation_id);
    w.string(tid);
    w.int64(pid);
    w.int16(epoch);
    w.int32(1); // 1 topic
    w.string(topic);
    w.int32(i32::try_from(partitions.len()).unwrap());
    for &p in partitions {
        w.int32(p);
    }
    Writer::frame(&w.into_bytes())
}

fn produce_txn_req(
    correlation_id: i32,
    topic: &str,
    partition: i32,
    pid: i64,
    epoch: i16,
    values: &[&[u8]],
) -> Vec<u8> {
    let batch = txn_record_batch(values, pid, epoch, 0);
    let mut w = req_header(0, 7, correlation_id);
    w.nullable_string(Some("tx-1")); // transactional_id on the Produce request (v3+)
    w.int16(-1);
    w.int32(30_000);
    w.int32(1);
    w.string(topic);
    w.int32(1);
    w.int32(partition);
    w.bytes(&batch);
    Writer::frame(&w.into_bytes())
}

fn end_txn_req(correlation_id: i32, tid: &str, pid: i64, epoch: i16, committed: bool) -> Vec<u8> {
    let mut w = req_header(26, 1, correlation_id);
    w.string(tid);
    w.int64(pid);
    w.int16(epoch);
    w.int8(i8::from(committed));
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

fn spawn_fault_broker(
    rail: &std::path::Path,
    data_dir: &std::path::Path,
    port: u16,
    fault_point: Option<u8>,
) -> (Daemon, TcpStream) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_datarail"));
    command.args([
        "kafka-broker",
        rail.to_str().unwrap(),
        "--listen",
        &format!("127.0.0.1:{port}"),
        "--advertised",
        "127.0.0.1",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--partitions",
        "2",
    ]);
    if let Some(point) = fault_point {
        command
            .env("DATARAIL_TXN_FAULT_POINT", point.to_string())
            .env("DATARAIL_TXN_FAULT_ABORT", "1");
    }
    let child = command.spawn().expect("spawn datarail kafka-broker");
    let mut daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    let stream = loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            break s;
        }
        if let Ok(Some(status)) = daemon.0.try_wait() {
            panic!("kafka-broker exited before listening: {status}");
        }
        assert!(Instant::now() < deadline, "broker never started");
        std::thread::sleep(Duration::from_millis(100));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    (daemon, stream)
}

fn write_fault_rail(point: u8) -> (std::path::PathBuf, std::path::PathBuf) {
    let rail = std::env::temp_dir().join(format!("kafka-txn-fault-{point}-{}.toml", std::process::id()));
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
    .expect("write fault rail");
    let data_dir = std::env::temp_dir().join(format!("kafka-txn-fault-data-{point}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    (rail, data_dir)
}

fn drive_faulted_commit(stream: &mut TcpStream) {
    stream.write_all(&init_producer_id_req(1, "tx-1")).unwrap();
    let (pid, epoch) = init_producer_id(&read_frame(stream));
    stream
        .write_all(&add_partitions_req(
            2,
            "tx-1",
            pid,
            epoch,
            "events",
            &[0, 1],
        ))
        .unwrap();
    let _ = read_frame(stream);
    for (correlation_id, partition, values) in [
        (3, 0, vec![b"evt:fault-0".as_slice()]),
        (4, 1, vec![b"evt:fault-1".as_slice()]),
    ] {
        stream
            .write_all(&produce_txn_req(
                correlation_id,
                "events",
                partition,
                pid,
                epoch,
                &values,
            ))
            .unwrap();
        let _ = read_frame(stream);
    }
    stream
        .write_all(&end_txn_req(5, "tx-1", pid, epoch, true))
        .unwrap();
    let mut byte = [0u8; 1];
    let _ = stream.read(&mut byte);
}

#[test]
fn process_crash_at_each_transaction_boundary_recovers_all_or_none() {
    let _lock = BROKER_TEST_LOCK.lock().unwrap();
    for point in 1..=5 {
        let (rail, data_dir) = write_fault_rail(point);
        let port = free_port();
        let (mut daemon, mut stream) = spawn_fault_broker(&rail, &data_dir, port, Some(point));
        drive_faulted_commit(&mut stream);
        let status = daemon.0.wait().expect("wait for injected transaction crash");
        assert!(!status.success(), "fault point {point} did not stop broker");

        let (_daemon, mut stream) = spawn_fault_broker(&rail, &data_dir, port, None);
        for partition in 0..2 {
            stream
                .write_all(&fetch_req(10 + partition, "events", partition, 0))
                .unwrap();
            let values = fetch_values(&read_frame(&mut stream));
            if point == 5 {
                assert_eq!(values, vec![format!("evt:fault-{partition}").into_bytes()]);
            } else {
                assert!(values.is_empty(), "fault point {point} left committed data");
            }
        }
        let _ = std::fs::remove_file(&rail);
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}

#[test]
fn transactional_commit_is_visible_after_success_and_abort_is_hidden() {
    let _lock = BROKER_TEST_LOCK.lock().unwrap();
    let port = free_port();
    let rail = std::env::temp_dir().join(format!("kafka-txn-{}.toml", std::process::id()));
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
    let data_dir = std::env::temp_dir().join(format!("kafka-txn-data-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);

    let (_daemon, mut stream) = spawn_fault_broker(&rail, &data_dir, port, None);

    let _ = commit_transaction(&mut stream);
    abort_and_fence_transaction(&mut stream);

    let _ = std::fs::remove_file(&rail);
    let _ = std::fs::remove_dir_all(&data_dir);
}

fn commit_transaction(stream: &mut TcpStream) -> (i64, i16) {
    stream.write_all(&init_producer_id_req(1, "tx-1")).unwrap();
    let (pid, epoch) = init_producer_id(&read_frame(stream));
    stream
        .write_all(&add_partitions_req(
            2,
            "tx-1",
            pid,
            epoch,
            "events",
            &[0, 1],
        ))
        .unwrap();
    let _ = read_frame(stream);
    for (correlation_id, partition, values) in [
        (3, 0, vec![b"evt:p0a".as_slice(), b"evt:p0b".as_slice()]),
        (4, 1, vec![b"evt:p1a".as_slice()]),
    ] {
        stream
            .write_all(&produce_txn_req(
                correlation_id,
                "events",
                partition,
                pid,
                epoch,
                &values,
            ))
            .unwrap();
        let _ = read_frame(stream);
    }
    for (correlation_id, partition) in [(5, 0), (6, 1)] {
        stream
            .write_all(&fetch_req(correlation_id, "events", partition, 0))
            .unwrap();
        assert!(
            fetch_values(&read_frame(stream)).is_empty(),
            "buffered record became visible"
        );
    }
    stream
        .write_all(&end_txn_req(7, "tx-1", pid, epoch, true))
        .unwrap();
    let _ = read_frame(stream);
    stream.write_all(&fetch_req(8, "events", 0, 0)).unwrap();
    assert_eq!(
        fetch_values(&read_frame(stream)),
        vec![b"evt:p0a".to_vec(), b"evt:p0b".to_vec()]
    );
    stream.write_all(&fetch_req(9, "events", 1, 0)).unwrap();
    assert_eq!(fetch_values(&read_frame(stream)), vec![b"evt:p1a".to_vec()]);
    (pid, epoch)
}

fn abort_and_fence_transaction(stream: &mut TcpStream) {
    stream.write_all(&init_producer_id_req(10, "tx-1")).unwrap();
    let (pid2, epoch2) = init_producer_id(&read_frame(stream));
    stream
        .write_all(&add_partitions_req(
            11,
            "tx-1",
            pid2,
            epoch2,
            "events",
            &[0],
        ))
        .unwrap();
    let _ = read_frame(stream);
    stream
        .write_all(&produce_txn_req(
            12,
            "events",
            0,
            pid2,
            epoch2,
            &[b"evt:doomed"],
        ))
        .unwrap();
    let _ = read_frame(stream);
    stream
        .write_all(&end_txn_req(13, "tx-1", pid2, epoch2, false))
        .unwrap();
    let _ = read_frame(stream);
    stream.write_all(&fetch_req(14, "events", 0, 0)).unwrap();
    assert_eq!(
        fetch_values(&read_frame(stream)),
        vec![b"evt:p0a".to_vec(), b"evt:p0b".to_vec()]
    );

    stream.write_all(&init_producer_id_req(15, "tx-1")).unwrap();
    let (pid3, epoch3) = init_producer_id(&read_frame(stream));
    stream
        .write_all(&add_partitions_req(
            16,
            "tx-1",
            pid3,
            epoch3,
            "events",
            &[0],
        ))
        .unwrap();
    let _ = read_frame(stream);
    stream
        .write_all(&produce_txn_req(
            17,
            "events",
            0,
            pid3,
            epoch3,
            &[b"evt:legit"],
        ))
        .unwrap();
    let _ = read_frame(stream);
    stream
        .write_all(&produce_txn_req(
            18,
            "events",
            0,
            pid2,
            epoch2,
            &[b"evt:zombie"],
        ))
        .unwrap();
    let _ = read_frame(stream);
    stream
        .write_all(&end_txn_req(19, "tx-1", pid3, epoch3, true))
        .unwrap();
    let _ = read_frame(stream);
    stream.write_all(&fetch_req(20, "events", 0, 0)).unwrap();
    let got = fetch_values(&read_frame(stream));
    assert!(got.contains(&b"evt:legit".to_vec()));
    assert!(!got.contains(&b"evt:zombie".to_vec()));
}
