//! FULL-CHAIN end-to-end exactly-once: spawn the real `datarail kafka-ingest` binary against a live Postgres,
//! drive it with an idempotent producer handshake (`InitProducerId`) + a `Produce` batch sent TWICE (a faithful
//! retry), and assert the records land EXACTLY ONCE in Postgres. `#[ignore]` — needs a live Postgres (env
//! `DATARAIL_PG_*`) + `psql` on PATH; run in the docker verification harness.
//!
//! This exercises the whole product path no unit/wire test covers in one process: serve (grant `producer_id`) ->
//! channel (`EosCoord`) -> the CLI's per-batch EOS routing -> `ship_batch_seq` -> `commit_at_seq` (Tier A) -> rows.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use datarail_kafka::codec::Writer;

const PORT: u16 = 19_092;
const TABLE: &str = "datarail_kafka_eos";

fn pg_env(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_owned())
}

fn psql(sql: &str) -> std::process::Output {
    Command::new("psql")
        .args([
            "-h",
            &pg_env("DATARAIL_PG_HOST", "127.0.0.1"),
            "-p",
            &pg_env("DATARAIL_PG_PORT", "5432"),
            "-U",
            &pg_env("DATARAIL_PG_USER", "postgres"),
            "-d",
            &pg_env("DATARAIL_PG_DB", "postgres"),
            "-tA",
            "-c",
            sql,
        ])
        .output()
        .expect("psql")
}

fn psql_scalar(sql: &str) -> String {
    String::from_utf8_lossy(&psql(sql).stdout).trim().to_owned()
}

fn req_header(api_key: i16, api_version: i16, correlation_id: i32) -> Writer {
    let mut w = Writer::new();
    w.int16(api_key);
    w.int16(api_version);
    w.int32(correlation_id);
    w.nullable_string(Some("eos-e2e"));
    w
}

fn init_producer_id_req(correlation_id: i32) -> Vec<u8> {
    let mut w = req_header(22, 1, correlation_id);
    w.nullable_string(None);
    w.int32(60_000);
    w.int64(-1);
    w.int16(-1);
    Writer::frame(&w.into_bytes())
}

fn idempotent_batch(producer_id: i64, base_sequence: i32, values: &[&[u8]]) -> Vec<u8> {
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
    b.int16(0);
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

fn produce_req(
    correlation_id: i32,
    topic: &str,
    producer_id: i64,
    base_sequence: i32,
    values: &[&[u8]],
) -> Vec<u8> {
    let batch = idempotent_batch(producer_id, base_sequence, values);
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

fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).expect("read length");
    let n = u32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).expect("read body");
    body
}

/// Parse the per-partition error code from a single-topic/single-partition Produce response payload (after the
/// frame length): a 4-byte correlation id, a 4-byte topic-array count, the topic name (2-byte length + bytes), a
/// 4-byte partition-array count, the 4-byte partition, then the 2-byte error code. The caller passes the name length.
fn produce_error_code(resp: &[u8], topic_len: usize) -> i16 {
    let off = 4 + 4 + 2 + topic_len + 4 + 4;
    i16::from_be_bytes([resp[off], resp[off + 1]])
}

/// Kill the spawned daemon on drop so a failed assert never leaks the process / port.
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "needs a live Postgres (DATARAIL_PG_*) + psql; run in the docker verification harness"]
fn idempotent_produce_retry_lands_exactly_once_through_the_kafka_ingest_binary() {
    // Clean slate: the table + the EOS watermark for this run's producer substream.
    let _ = psql(&format!("DROP TABLE IF EXISTS {TABLE}"));
    let _ = psql(&format!("CREATE TABLE {TABLE} (data text)"));
    let _ = psql("CREATE TABLE IF NOT EXISTS datarail_watermark (stream bytea PRIMARY KEY, seq bigint NOT NULL)");
    // route_id of the sample rail is 0x0101...; the producer_id granted by a FRESH daemon is 1. Clear any stale wm.
    let _ = psql("DELETE FROM datarail_watermark");

    let rail = std::env::temp_dir().join(format!("kafka-eos-{}.toml", std::process::id()));
    std::fs::write(
        &rail,
        "[route]\n\
         route_id = \"0x01010101010101010101010101010101\"\n\
         stream_id = \"0x02020202020202020202020202020202\"\n\
         aead = \"gcm-siv-256\"\n\
         guarantee = \"exactly-once\"\n\
         [onboarding]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
         [offloading]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
         [keys]\n\
         source_seed = \"0x1111111111111111111111111111111111111111111111111111111111111111\"\n\
         dest_seed = \"0x1111111111111111111111111111111111111111111111111111111111111111\"\n\
         dest_x25519_secret = \"0x1111111111111111111111111111111111111111111111111111111111111111\"\n\
         tenant_secret = \"0x1111111111111111111111111111111111111111111111111111111111111111\"\n",
    )
    .expect("write rail.toml");

    let conn = format!(
        "host={},port={},user={},db={},table={TABLE},column=data",
        pg_env("DATARAIL_PG_HOST", "127.0.0.1"),
        pg_env("DATARAIL_PG_PORT", "5432"),
        pg_env("DATARAIL_PG_USER", "postgres"),
        pg_env("DATARAIL_PG_DB", "postgres"),
    );
    let child = Command::new(env!("CARGO_BIN_EXE_datarail"))
        .args([
            "kafka-ingest",
            rail.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{PORT}"),
            "--sink-postgres",
            &conn,
        ])
        .spawn()
        .expect("spawn datarail kafka-ingest");
    let _daemon = Daemon(child);

    // Connect (the daemon may still be binding).
    let mut stream = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", PORT)) {
                break s;
            }
            assert!(
                Instant::now() < deadline,
                "kafka-ingest never started listening"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Handshake: InitProducerId → producer_id.
    stream.write_all(&init_producer_id_req(1)).unwrap();
    let resp = read_frame(&mut stream);
    let pid = i64::from_be_bytes([
        resp[10], resp[11], resp[12], resp[13], resp[14], resp[15], resp[16], resp[17],
    ]);
    assert!(pid >= 0, "granted producer_id");

    // Produce an idempotent batch [0,3), then RETRY the identical batch (same pid+sequence).
    stream
        .write_all(&produce_req(
            2,
            "events",
            pid,
            0,
            &[b"evt:k0", b"evt:k1", b"evt:k2"],
        ))
        .unwrap();
    let _ = read_frame(&mut stream);
    stream
        .write_all(&produce_req(
            3,
            "events",
            pid,
            0,
            &[b"evt:k0", b"evt:k1", b"evt:k2"],
        ))
        .unwrap();
    let _ = read_frame(&mut stream);

    // Poll: exactly 3 rows must land despite the retry (the watermark in Postgres no-ops the second send).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut rows = String::new();
    while Instant::now() < deadline {
        rows = psql_scalar(&format!("SELECT count(*) FROM {TABLE}"));
        if rows == "3" {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        rows, "3",
        "idempotent retry must land exactly once (3 rows), not 6"
    );

    // ---- audit A/E: ack-after-durable — a sink failure must NOT be a false NONE ack, and the daemon must survive.
    // Drop the data table out from under the ingest: the next produce's land fails inside commit_at_seq.
    let _ = psql(&format!("DROP TABLE {TABLE}"));
    stream
        .write_all(&produce_req(4, "events", pid, 3, &[b"evt:k3", b"evt:k4"]))
        .unwrap();
    let resp = read_frame(&mut stream);
    let code = produce_error_code(&resp, "events".len());
    assert_ne!(
        code, 0,
        "a failed durable land must return a retriable error, never a false NONE ack (audit A)"
    );

    // The daemon must still be serving (audit E: one sink failure must not tear down ingest). Recreate the table
    // and produce a fresh range — it must succeed (error_code 0) and land, proving the loop survived.
    let _ = psql(&format!("CREATE TABLE {TABLE} (data text)"));
    stream
        .write_all(&produce_req(
            5,
            "events",
            pid,
            10,
            &[b"evt:k10", b"evt:k11"],
        ))
        .unwrap();
    let resp2 = read_frame(&mut stream);
    assert_eq!(
        produce_error_code(&resp2, "events".len()),
        0,
        "the daemon must keep serving after a sink error (audit E)"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut after = String::new();
    while Instant::now() < deadline {
        after = psql_scalar(&format!("SELECT count(*) FROM {TABLE}"));
        if after == "2" {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        after, "2",
        "after recovery the daemon lands the new batch (2 rows in the recreated table)"
    );

    let _ = std::fs::remove_file(&rail);
}
