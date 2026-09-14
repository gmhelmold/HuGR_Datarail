//! `datarail-kafka-serve` — run the Kafka ingest endpoint and print each received record value. Proves an
//! UNMODIFIED Kafka producer can send to datarail. Usage: `datarail-kafka-serve [listen_addr] [advertised_host]`.
//! (`advertised_host` is what the client must reach us at — e.g. `host.docker.internal` for a containerized client.)
#![forbid(unsafe_code)]

use std::net::TcpListener;
use std::sync::mpsc;

use datarail_kafka::serve::serve;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let listen = args.get(1).map_or("0.0.0.0:9092", String::as_str);
    let advertised = args.get(2).map_or("127.0.0.1", String::as_str);
    let port: i32 = listen
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9092);

    let listener = TcpListener::bind(listen)?;
    println!("datarail-kafka ingest on {listen} (advertised {advertised}:{port})");
    let (tx, rx) = mpsc::channel::<datarail_kafka::serve::ProducedBatch>();
    std::thread::spawn(move || {
        for b in rx {
            let seq = b.eos.map_or_else(
                || "-".to_owned(),
                |e| format!("pid={} seq={}", e.producer_id, e.base_sequence),
            );
            for v in &b.values {
                println!(
                    "RECV topic={} partition={} [{seq}] value={}",
                    b.topic,
                    b.partition,
                    String::from_utf8_lossy(v.as_slice())
                );
            }
            let _ = b.done.send(Ok(())); // this demo "lands" by printing; ack so the producer is acked
        }
    });
    let conn: std::sync::Arc<dyn datarail_kafka::serve::ConnWrap> =
        std::sync::Arc::new(datarail_kafka::serve::PlainConn);
    serve(&listener, advertised, port, tx, &conn)
}
