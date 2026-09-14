//! End-to-end WIRE test of the exactly-once ingest path through the real `serve` loop over a real TCP socket:
//! an idempotent producer's handshake (`InitProducerId`) + a `Produce` batch sent TWICE (a retry). Proves the
//! broker grants a `producer_id` and surfaces the SAME stable `EosCoord` on both sends — the coordinate the sink
//! then dedups on (the `commit_at_seq` op, proven idempotent in the `postgres_live` integration test).
//! Together: end-to-end exactly-once.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use datarail_kafka::codec::Writer;
use datarail_kafka::serve::serve;

/// A non-flexible Kafka request header (v1): key, version, correlation id, and a client id.
fn req_header(api_key: i16, api_version: i16, correlation_id: i32) -> Writer {
    let mut w = Writer::new();
    w.int16(api_key);
    w.int16(api_version);
    w.int32(correlation_id);
    w.nullable_string(Some("eos-test"));
    w
}

/// An `InitProducerId` v1 request (null transactional id, a timeout, and a fresh producer).
fn init_producer_id_req(correlation_id: i32) -> Vec<u8> {
    let mut w = req_header(22, 1, correlation_id);
    w.nullable_string(None); // transactional_id
    w.int32(60_000); // transaction_timeout_ms
    w.int64(-1); // producer_id (fresh)
    w.int16(-1); // producer_epoch
    Writer::frame(&w.into_bytes())
}

/// An idempotent v2 `RecordBatch` blob carrying `values` under `(producer_id, base_sequence)`.
fn idempotent_batch(producer_id: i64, base_sequence: i32, values: &[&[u8]]) -> Vec<u8> {
    let mut recs = Writer::new();
    for (i, v) in values.iter().enumerate() {
        let mut r = Writer::new();
        r.int8(0);
        r.varlong(0);
        r.varint(i32::try_from(i).unwrap());
        r.varint(-1); // null key
        r.varint(i32::try_from(v.len()).unwrap());
        r.raw(v);
        r.varint(0); // header count
        let body = r.into_bytes();
        recs.varint(i32::try_from(body.len()).unwrap());
        recs.raw(&body);
    }
    let records = recs.into_bytes();
    let mut b = Writer::new();
    b.int32(0); // partition_leader_epoch
    b.int8(2); // magic
    b.uint32(0); // crc placeholder — stamped with the real CRC-32C below (the broker validates it on produce)
    b.int16(0); // attributes (uncompressed)
    b.int32(i32::try_from(values.len().saturating_sub(1)).unwrap());
    b.int64(0);
    b.int64(0);
    b.int64(producer_id);
    b.int16(0); // producer epoch
    b.int32(base_sequence);
    b.int32(i32::try_from(values.len()).unwrap());
    b.raw(&records);
    let mut after = b.into_bytes();
    // The broker now VALIDATES the v2 CRC-32C on produce (over `attributes..end`). `after` is
    // `partition_leader_epoch(4) magic(1) crc(4) attributes..records`, so the covered range starts at offset 9
    // and the 4-byte crc field sits at `after[5..9]` — stamp the real CRC there, else the batch is CORRUPT.
    let crc = datarail_kafka::produce::crc32c(&after[9..]);
    after[5..9].copy_from_slice(&crc.to_be_bytes());
    let mut full = Writer::new();
    full.int64(0); // base offset
    full.int32(i32::try_from(after.len()).unwrap());
    full.raw(&after);
    full.into_bytes()
}

/// A `Produce` v7 request to `topic`/partition 0 with one idempotent batch.
fn produce_req(
    correlation_id: i32,
    topic: &str,
    producer_id: i64,
    base_sequence: i32,
    values: &[&[u8]],
) -> Vec<u8> {
    let batch = idempotent_batch(producer_id, base_sequence, values);
    let mut w = req_header(0, 7, correlation_id);
    w.nullable_string(None); // transactional_id (v3+)
    w.int16(-1); // acks = all (idempotent)
    w.int32(30_000); // timeout
    w.int32(1); // 1 topic
    w.string(topic);
    w.int32(1); // 1 partition
    w.int32(0); // partition 0
    w.bytes(&batch); // records as NULLABLE_BYTES
    Writer::frame(&w.into_bytes())
}

/// Read one length-framed response and return its payload (after the 4-byte length).
fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).expect("read length");
    let n = u32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).expect("read body");
    body
}

#[test]
fn idempotent_producer_handshake_and_retry_surface_a_stable_eos_coord() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    let conn: std::sync::Arc<dyn datarail_kafka::serve::ConnWrap> =
        std::sync::Arc::new(datarail_kafka::serve::PlainConn);
    std::thread::spawn(move || {
        let _ = serve(&listener, "127.0.0.1", addr.port().into(), tx, &conn);
    });

    // The integration layer: drain produced batches and ACK each (ack-after-durable) so `serve` can respond to
    // the producer. Collect the coords on a side channel for the assertions.
    let (coord_tx, coord_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for b in rx {
            let _ = coord_tx.send((b.topic.clone(), b.partition, b.values.clone(), b.eos));
            let _ = b.done.send(Ok(())); // signal durable land so the producer is acked
        }
    });

    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // 1) InitProducerId → the broker grants a producer_id (response: corr, throttle, error, producer_id, epoch).
    stream
        .write_all(&init_producer_id_req(1))
        .expect("send init");
    let resp = read_frame(&mut stream);
    // payload: correlation_id(4) throttle(4) error(2) producer_id(8) epoch(2)
    assert!(resp.len() >= 20, "init response too short: {}", resp.len());
    let error = i16::from_be_bytes([resp[8], resp[9]]);
    assert_eq!(error, 0, "InitProducerId error_code must be NONE");
    let pid = i64::from_be_bytes([
        resp[10], resp[11], resp[12], resp[13], resp[14], resp[15], resp[16], resp[17],
    ]);
    assert!(pid >= 0, "granted producer_id must be >= 0, got {pid}");

    // 2) Produce an idempotent batch [0,3), then RETRY the identical batch (same pid+base_sequence).
    stream
        .write_all(&produce_req(2, "events", pid, 0, &[b"e:a", b"e:b", b"e:c"]))
        .expect("produce");
    let _ = read_frame(&mut stream);
    stream
        .write_all(&produce_req(3, "events", pid, 0, &[b"e:a", b"e:b", b"e:c"]))
        .expect("produce retry");
    let _ = read_frame(&mut stream);

    // 3) Both sends surface on the channel with the SAME stable EOS coordinate — what the sink dedups on.
    let (t1, p1, v1, e1) = coord_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("first batch");
    let (_t2, _p2, _v2, e2) = coord_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("retry batch");
    assert_eq!(t1, "events");
    assert_eq!(p1, 0);
    assert_eq!(v1, vec![b"e:a".to_vec(), b"e:b".to_vec(), b"e:c".to_vec()]);
    let c1 = e1.expect("first batch must carry an EOS coord");
    let c2 = e2.expect("retry batch must carry an EOS coord");
    assert_eq!(c1.producer_id, pid);
    assert_eq!(c1.base_sequence, 0);
    assert_eq!(c1.count, 3, "sequence range [0,3)");
    // The retry carries the IDENTICAL coordinate → the sink's commit_at_seq no-ops it (exactly-once).
    assert_eq!(
        c1, c2,
        "an idempotent retry must present the same (producer_id, base_sequence, count)"
    );
}
