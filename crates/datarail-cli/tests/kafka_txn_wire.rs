//! FULL-CHAIN transactional-EOS proof: spawn the real `datarail kafka-broker` and drive a TRANSACTIONAL producer
//! through `InitProducerId`(`transactional_id`) → `AddPartitionsToTxn` → (transactional) Produce → `EndTxn`. Asserts:
//! buffered records are INVISIBLE before commit; a successful COMMIT makes them visible across two partitions; an
//! ABORT discards them (never visible). `KAFKA-TXN-DESIGN.md` (buffer-until-commit model). Runs in normal CI.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use datarail_kafka::codec::{Reader, Writer};
use datarail_kafka::produce::parse_record_batch;

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

#[test]
fn transactional_commit_is_visible_after_success_and_abort_is_hidden() {
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

    let child = Command::new(env!("CARGO_BIN_EXE_datarail"))
        .args([
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
        ])
        .spawn()
        .expect("spawn datarail kafka-broker");
    let _daemon = Daemon(child);
    let mut stream = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                break s;
            }
            assert!(Instant::now() < deadline, "broker never started");
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // --- a transactional producer, COMMIT path ---
    stream.write_all(&init_producer_id_req(1, "tx-1")).unwrap();
    let (pid, epoch) = init_producer_id(&read_frame(&mut stream));

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
    let _ = read_frame(&mut stream);

    // Produce transactional batches to BOTH partitions (buffered, not yet visible).
    stream
        .write_all(&produce_txn_req(
            3,
            "events",
            0,
            pid,
            epoch,
            &[b"evt:p0a", b"evt:p0b"],
        ))
        .unwrap();
    let _ = read_frame(&mut stream);
    stream
        .write_all(&produce_txn_req(4, "events", 1, pid, epoch, &[b"evt:p1a"]))
        .unwrap();
    let _ = read_frame(&mut stream);

    // Before commit: BOTH partitions are EMPTY (records buffered, invisible).
    stream.write_all(&fetch_req(5, "events", 0, 0)).unwrap();
    assert!(
        fetch_values(&read_frame(&mut stream)).is_empty(),
        "p0 invisible before commit"
    );
    stream.write_all(&fetch_req(6, "events", 1, 0)).unwrap();
    assert!(
        fetch_values(&read_frame(&mut stream)).is_empty(),
        "p1 invisible before commit"
    );

    // Successful COMMIT → both partitions become visible after the flush returns.
    stream
        .write_all(&end_txn_req(7, "tx-1", pid, epoch, true))
        .unwrap();
    let _ = read_frame(&mut stream);
    stream.write_all(&fetch_req(8, "events", 0, 0)).unwrap();
    assert_eq!(
        fetch_values(&read_frame(&mut stream)),
        vec![b"evt:p0a".to_vec(), b"evt:p0b".to_vec()],
        "p0 visible after commit"
    );
    stream.write_all(&fetch_req(9, "events", 1, 0)).unwrap();
    assert_eq!(
        fetch_values(&read_frame(&mut stream)),
        vec![b"evt:p1a".to_vec()],
        "p1 visible after commit"
    );

    // --- a second transaction, ABORT path (re-init bumps the epoch) ---
    stream.write_all(&init_producer_id_req(10, "tx-1")).unwrap();
    let (pid2, epoch2) = init_producer_id(&read_frame(&mut stream));
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
    let _ = read_frame(&mut stream);
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
    let _ = read_frame(&mut stream);
    // ABORT → the doomed record is discarded.
    stream
        .write_all(&end_txn_req(13, "tx-1", pid2, epoch2, false))
        .unwrap();
    let _ = read_frame(&mut stream);
    // p0 still shows ONLY the committed records — the aborted one never appears.
    stream.write_all(&fetch_req(14, "events", 0, 0)).unwrap();
    assert_eq!(
        fetch_values(&read_frame(&mut stream)),
        vec![b"evt:p0a".to_vec(), b"evt:p0b".to_vec()],
        "aborted record is never visible"
    );

    // --- ZOMBIE FENCE (audit CRITICAL): a stale-epoch Produce must NOT be committed ---
    stream.write_all(&init_producer_id_req(15, "tx-1")).unwrap();
    let (pid3, epoch3) = init_producer_id(&read_frame(&mut stream)); // epoch bumped again; pid2/epoch2 now fenced
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
    let _ = read_frame(&mut stream);
    // A legit record at the CURRENT epoch.
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
    let _ = read_frame(&mut stream);
    // A ZOMBIE record at the OLD (fenced) epoch — must be rejected, never buffered.
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
    let _ = read_frame(&mut stream);
    stream
        .write_all(&end_txn_req(19, "tx-1", pid3, epoch3, true))
        .unwrap();
    let _ = read_frame(&mut stream);
    stream.write_all(&fetch_req(20, "events", 0, 0)).unwrap();
    let got = fetch_values(&read_frame(&mut stream));
    assert!(
        got.contains(&b"evt:legit".to_vec()),
        "the current-epoch record committed"
    );
    assert!(
        !got.contains(&b"evt:zombie".to_vec()),
        "the fenced stale-epoch record was NEVER committed"
    );

    let _ = std::fs::remove_file(&rail);
    let _ = std::fs::remove_dir_all(&data_dir);
}
