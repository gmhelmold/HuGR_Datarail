//! FULL-CHAIN consumer-offset proof: spawn the real `datarail kafka-broker` binary and drive `FindCoordinator`,
//! `OffsetCommit`, and `OffsetFetch` over the Kafka wire. Asserts the broker (a) names itself the coordinator,
//! (b) durably commits a group's offset, and (c) returns it after a REAL broker restart on the same `--data-dir`
//! — the consumer-group durable-offset feature (`KAFKA-GROUPS-DESIGN.md` increment 3). Runs in normal CI.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use datarail_kafka::codec::{Reader, Writer};

const PORT: u16 = 19_094;

fn req_header(api_key: i16, api_version: i16, correlation_id: i32) -> Writer {
    let mut w = Writer::new();
    w.int16(api_key);
    w.int16(api_version);
    w.int32(correlation_id);
    w.nullable_string(Some("groups-wire"));
    w
}

fn find_coordinator_req(correlation_id: i32, group: &str) -> Vec<u8> {
    let mut w = req_header(10, 1, correlation_id);
    w.string(group);
    w.int8(0); // key_type = GROUP
    Writer::frame(&w.into_bytes())
}

fn offset_commit_req(
    correlation_id: i32,
    group: &str,
    topic: &str,
    partition: i32,
    offset: i64,
) -> Vec<u8> {
    let mut w = req_header(8, 2, correlation_id);
    w.string(group);
    w.int32(-1); // generation_id (v1+)
    w.string(""); // member_id (v1+)
    w.int64(-1); // retention_time_ms (v2+)
    w.int32(1); // 1 topic
    w.string(topic);
    w.int32(1); // 1 partition
    w.int32(partition);
    w.int64(offset);
    w.nullable_string(None); // metadata
    Writer::frame(&w.into_bytes())
}

fn offset_fetch_req(correlation_id: i32, group: &str, topic: &str, partition: i32) -> Vec<u8> {
    let mut w = req_header(9, 2, correlation_id);
    w.string(group);
    w.int32(1); // 1 topic
    w.string(topic);
    w.int32(1); // 1 partition
    w.int32(partition);
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

/// Parse a `FindCoordinator` v1 response → (`node_id`, host, port).
fn coordinator(resp: &[u8]) -> (i32, String, i32) {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    let _throttle = r.int32().unwrap();
    assert_eq!(r.int16().unwrap(), 0, "FindCoordinator error_code NONE");
    let _err_msg = r.nullable_string().unwrap();
    let node = r.int32().unwrap();
    let host = r.string().unwrap();
    let port = r.int32().unwrap();
    (node, host, port)
}

/// Parse an `OffsetCommit` v2 response → the single partition's `error_code`.
fn commit_error(resp: &[u8]) -> i16 {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    assert_eq!(r.int32().unwrap(), 1, "1 topic");
    let _name = r.string().unwrap();
    assert_eq!(r.int32().unwrap(), 1, "1 partition");
    let _partition = r.int32().unwrap();
    r.int16().unwrap()
}

/// Parse an `OffsetFetch` v2 response → the single partition's committed offset.
fn fetched_offset(resp: &[u8]) -> i64 {
    let mut r = Reader::new(resp);
    let _corr = r.int32().unwrap();
    assert_eq!(r.int32().unwrap(), 1, "1 topic");
    let _name = r.string().unwrap();
    assert_eq!(r.int32().unwrap(), 1, "1 partition");
    let _partition = r.int32().unwrap();
    let offset = r.int64().unwrap();
    let _metadata = r.nullable_string().unwrap();
    assert_eq!(r.int16().unwrap(), 0, "partition error NONE");
    assert_eq!(r.int16().unwrap(), 0, "top-level error NONE (v2)");
    offset
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_broker(rail: &std::path::Path, data_dir: &std::path::Path) -> (Daemon, TcpStream) {
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

#[test]
fn offset_commit_fetch_round_trips_and_survives_a_broker_restart() {
    let rail = std::env::temp_dir().join(format!("kafka-groups-{}.toml", std::process::id()));
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
    let data_dir = std::env::temp_dir().join(format!("kafka-groups-data-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);

    // ---- PHASE 1: coordinator + commit + fetch through a live broker ----
    {
        let (_daemon, mut stream) = spawn_broker(&rail, &data_dir);

        // FindCoordinator → THIS broker (node 0, advertised host/port).
        stream
            .write_all(&find_coordinator_req(1, "analytics"))
            .unwrap();
        let (node, host, port) = coordinator(&read_frame(&mut stream));
        assert_eq!(
            node, 0,
            "single-node: the broker is its own group coordinator"
        );
        assert_eq!((host.as_str(), port), ("127.0.0.1", i32::from(PORT)));

        // OffsetFetch before any commit → -1 (no committed offset).
        stream
            .write_all(&offset_fetch_req(2, "analytics", "events", 0))
            .unwrap();
        assert_eq!(
            fetched_offset(&read_frame(&mut stream)),
            -1,
            "no committed offset yet"
        );

        // OffsetCommit offset 7 → NONE.
        stream
            .write_all(&offset_commit_req(3, "analytics", "events", 0, 7))
            .unwrap();
        assert_eq!(
            commit_error(&read_frame(&mut stream)),
            0,
            "commit acked NONE (durable)"
        );

        // OffsetFetch → 7.
        stream
            .write_all(&offset_fetch_req(4, "analytics", "events", 0))
            .unwrap();
        assert_eq!(
            fetched_offset(&read_frame(&mut stream)),
            7,
            "committed offset read back"
        );

        // A DIFFERENT group is isolated (no cross-group leakage).
        stream
            .write_all(&offset_fetch_req(5, "other-group", "events", 0))
            .unwrap();
        assert_eq!(
            fetched_offset(&read_frame(&mut stream)),
            -1,
            "another group has its own (empty) offset"
        );
        // _daemon dropped → broker killed.
    }

    // ---- PHASE 2: restart on the SAME data dir → the committed offset is recovered ----
    {
        let (_daemon, mut stream) = spawn_broker(&rail, &data_dir);
        stream
            .write_all(&offset_fetch_req(6, "analytics", "events", 0))
            .unwrap();
        assert_eq!(
            fetched_offset(&read_frame(&mut stream)),
            7,
            "committed offset survived a real broker restart (durable consumer offsets)"
        );
    }

    let _ = std::fs::remove_file(&rail);
    let _ = std::fs::remove_dir_all(&data_dir);
}
