//! WIRE test of Kafka `acks=0` (fire-and-forget) semantics through the real `serve` loop over a real TCP
//! socket. A produce with `acks=0` must still land its records durably, but the broker writes NO response frame
//! (a response would shift the client's correlation-id stream by one, desynchronizing every subsequent reply).
//! The connection keeps serving: a follow-up request on the SAME socket still gets its response with the right
//! correlation id. This locks in the two invariants together.

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
    w.nullable_string(Some("acks-test"));
    w
}

/// A minimal uncompressed v2 `RecordBatch` (non-idempotent) carrying `values`, with a CORRECT CRC-32C so the
/// broker's produce-time CRC gate accepts it. Built by the crate's own `build_record_batch` (the fetch builder),
/// which stamps a valid CRC over `attributes..records` — exactly the range the parser validates.
fn record_batch(values: &[&[u8]]) -> Vec<u8> {
    let owned: Vec<Vec<u8>> = values.iter().map(|v| v.to_vec()).collect();
    datarail_kafka::produce::build_record_batch(0, &owned)
}

/// A `Produce` v7 request to `topic`/partition 0 with the given `acks` and one v2 batch.
fn produce_req(correlation_id: i32, topic: &str, acks: i16, values: &[&[u8]]) -> Vec<u8> {
    let batch = record_batch(values);
    let mut w = req_header(0, 7, correlation_id);
    w.nullable_string(None); // transactional_id (v3+)
    w.int16(acks); // acks
    w.int32(30_000); // timeout
    w.int32(1); // 1 topic
    w.string(topic);
    w.int32(1); // 1 partition
    w.int32(0); // partition 0
    w.bytes(&batch); // records as NULLABLE_BYTES
    Writer::frame(&w.into_bytes())
}

/// A `Metadata` v0 request naming one topic — a simple follow-up whose response we can correlate.
fn metadata_req(correlation_id: i32, topic: &str) -> Vec<u8> {
    let mut w = req_header(3, 0, correlation_id);
    w.int32(1); // 1 topic
    w.string(topic);
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
fn acks_zero_lands_records_but_sends_no_response_and_connection_keeps_serving() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    let conn: std::sync::Arc<dyn datarail_kafka::serve::ConnWrap> =
        std::sync::Arc::new(datarail_kafka::serve::PlainConn);
    std::thread::spawn(move || {
        let _ = serve(&listener, "127.0.0.1", addr.port().into(), tx, &conn);
    });

    // Integration layer: capture the landed values on a side channel and ack durable so `serve` proceeds.
    let (land_tx, land_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for b in rx {
            let _ = land_tx.send((b.topic.clone(), b.partition, b.values.clone()));
            let _ = b.done.send(Ok(())); // signal durable land
        }
    });

    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // 1) acks=0 produce: the records must LAND (arrive on the channel), and NO response frame must be written.
    stream
        .write_all(&produce_req(1, "events", 0, &[b"a0:x", b"a0:y"]))
        .expect("send acks=0 produce");
    let (topic, partition, values) = land_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("records must land");
    assert_eq!(topic, "events");
    assert_eq!(partition, 0);
    assert_eq!(
        values,
        vec![b"a0:x".to_vec(), b"a0:y".to_vec()],
        "acks=0 still lands records durably"
    );

    // 2) There must be NO response bytes for the acks=0 produce. Give the broker a moment to (not) reply, then a
    // short read window: reading a length prefix must TIME OUT (no data), proving nothing was written.
    std::thread::sleep(Duration::from_millis(150));
    stream
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let mut probe = [0u8; 1];
    match stream.read(&mut probe) {
        Ok(0) => panic!("connection closed after acks=0 produce — it must keep serving"),
        Ok(n) => {
            panic!("acks=0 produce must write NO response, but {n} byte(s) arrived: {probe:?}")
        }
        Err(e) => {
            let k = e.kind();
            assert!(
                k == std::io::ErrorKind::WouldBlock || k == std::io::ErrorKind::TimedOut,
                "expected a read timeout (no response bytes), got {k:?}"
            );
        }
    }

    // 3) The SAME connection keeps serving: a follow-up Metadata request gets its response with the right
    // correlation id (the acks=0 produce did NOT consume a response slot / shift the stream).
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(&metadata_req(99, "events"))
        .expect("send metadata");
    let resp = read_frame(&mut stream);
    assert!(resp.len() >= 4, "metadata response too short");
    let corr = i32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]);
    assert_eq!(
        corr, 99,
        "the follow-up response must carry ITS own correlation id (stream not desynchronized)"
    );

    // 4) And an acks=1 produce on the same connection DOES get a response (contrast with acks=0).
    stream
        .write_all(&produce_req(100, "events", 1, &[b"a1:z"]))
        .expect("send acks=1 produce");
    let (_t, _p, v) = land_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("acks=1 records land too");
    assert_eq!(v, vec![b"a1:z".to_vec()]);
    let resp = read_frame(&mut stream);
    let corr = i32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]);
    assert_eq!(
        corr, 100,
        "acks=1 produce IS answered, with its correlation id"
    );
}
