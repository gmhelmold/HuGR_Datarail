//! Multi-producer/multi-partition wire harness for WP-01.
//!
//! This is a correctness gate, not a throughput claim. It proves concurrent producers can write distinct
//! partitions without loss, offset collision, cross-partition routing, or malformed acknowledgements. Throughput
//! and confidence intervals belong in a dedicated benchmark, not in a timing-sensitive CI assertion.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use datarail_kafka::codec::{Reader, Writer};
use datarail_kafka::produce::parse_record_batch;

const RECORD_COUNT: usize = 200;
const BATCH_SIZE: usize = 20;
const RECORD_SIZE: usize = 512;

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    listener.local_addr().expect("read ephemeral port").port()
}

fn rail_text() -> &'static str {
    "[route]\n\
     route_id = \"0x03030303030303030303030303030303\"\n\
     stream_id = \"0x04040404040404040404040404040404\"\n\
     aead = \"gcm-siv-256\"\n\
     guarantee = \"exactly-once\"\n\
     [onboarding]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
     [offloading]\nmax_record_len = 1024\nrequired_prefix = \"evt:\"\n\
     [keys]\n\
     source_seed = \"0x3333333333333333333333333333333333333333333333333333333333333333\"\n\
     dest_seed = \"0x3333333333333333333333333333333333333333333333333333333333333333\"\n\
     dest_x25519_secret = \"0x3333333333333333333333333333333333333333333333333333333333333333\"\n\
     tenant_secret = \"0x3333333333333333333333333333333333333333333333333333333333333333\"\n"
}

fn req_header(api_key: i16, api_version: i16, correlation_id: i32) -> Writer {
    let mut w = Writer::new();
    w.int16(api_key);
    w.int16(api_version);
    w.int32(correlation_id);
    w.nullable_string(Some("partition-scale"));
    w
}

fn record_batch(values: &[&[u8]]) -> Vec<u8> {
    let mut records = Writer::new();
    for (index, value) in values.iter().enumerate() {
        let mut record = Writer::new();
        record.int8(0);
        record.varlong(0);
        record.varint(i32::try_from(index).expect("record index fits i32"));
        record.varint(-1);
        record.varint(i32::try_from(value.len()).expect("record length fits i32"));
        record.raw(value);
        record.varint(0);
        let body = record.into_bytes();
        records.varint(i32::try_from(body.len()).expect("record body fits i32"));
        records.raw(&body);
    }

    let encoded_records = records.into_bytes();
    let mut batch = Writer::new();
    batch.int32(0);
    batch.int8(2);
    batch.uint32(0);
    batch.int16(0);
    batch.int32(i32::try_from(values.len().saturating_sub(1)).expect("last offset fits i32"));
    batch.int64(0);
    batch.int64(0);
    batch.int64(-1);
    batch.int16(-1);
    batch.int32(-1);
    batch.int32(i32::try_from(values.len()).expect("record count fits i32"));
    batch.raw(&encoded_records);

    let mut body = batch.into_bytes();
    let crc = datarail_kafka::produce::crc32c(&body[9..]);
    body[5..9].copy_from_slice(&crc.to_be_bytes());

    let mut blob = Writer::new();
    blob.int64(0);
    blob.int32(i32::try_from(body.len()).expect("batch length fits i32"));
    blob.raw(&body);
    blob.into_bytes()
}

fn produce_request(correlation_id: i32, partition: i32, values: &[&[u8]]) -> Vec<u8> {
    let mut request = req_header(0, 7, correlation_id);
    request.nullable_string(None);
    request.int16(1);
    request.int32(30_000);
    request.int32(1);
    request.string("events");
    request.int32(1);
    request.int32(partition);
    request.bytes(&record_batch(values));
    Writer::frame(&request.into_bytes())
}

fn fetch_request(correlation_id: i32, partition: i32) -> Vec<u8> {
    let mut request = req_header(1, 4, correlation_id);
    request.int32(-1);
    request.int32(100);
    request.int32(1);
    request.int32(64 * 1024 * 1024);
    request.int8(0);
    request.int32(1);
    request.string("events");
    request.int32(1);
    request.int32(partition);
    request.int64(0);
    request.int32(64 * 1024 * 1024);
    Writer::frame(&request.into_bytes())
}

fn metadata_request(correlation_id: i32) -> Vec<u8> {
    let mut request = req_header(3, 1, correlation_id);
    request.int32(1);
    request.string("events");
    Writer::frame(&request.into_bytes())
}

fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .expect("read response length");
    let size = u32::from_be_bytes(length) as usize;
    let mut body = vec![0u8; size];
    stream.read_exact(&mut body).expect("read response body");
    body
}

fn produce_ack(
    response: &[u8],
    expected_correlation: i32,
    expected_partition: i32,
    expected_base: i64,
) {
    let mut reader = Reader::new(response);
    assert_eq!(reader.int32().unwrap(), expected_correlation);
    assert_eq!(reader.int32().unwrap(), 1);
    assert_eq!(reader.string().unwrap(), "events");
    assert_eq!(reader.int32().unwrap(), 1);
    assert_eq!(reader.int32().unwrap(), expected_partition);
    assert_eq!(reader.int16().unwrap(), 0, "produce ACK error must be NONE");
    assert_eq!(
        reader.int64().unwrap(),
        expected_base,
        "produce ACK base offset"
    );
}

struct ProducerTiming {
    elapsed: Duration,
    batch_latencies: Vec<Duration>,
}

struct CaseTiming {
    elapsed: Duration,
    p99: Duration,
}

fn p99(samples: &[Duration]) -> Duration {
    assert!(
        !samples.is_empty(),
        "benchmark must record at least one batch"
    );
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = (sorted.len() * 99).div_ceil(100).saturating_sub(1);
    sorted[rank]
}

fn fetched_values(response: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = Reader::new(response);
    let _correlation = reader.int32().unwrap();
    let _throttle = reader.int32().unwrap();
    assert_eq!(reader.int32().unwrap(), 1);
    assert_eq!(reader.string().unwrap(), "events");
    assert_eq!(reader.int32().unwrap(), 1);
    let _partition = reader.int32().unwrap();
    assert_eq!(reader.int16().unwrap(), 0, "fetch error must be NONE");
    let _high_watermark = reader.int64().unwrap();
    let _last_stable = reader.int64().unwrap();
    let _aborted = reader.int32().unwrap();
    match reader.nullable_bytes().unwrap() {
        Some(blob) => {
            parse_record_batch(&blob)
                .expect("parse fetched batch")
                .values
        }
        None => Vec::new(),
    }
}

fn metadata_partition_count(response: &[u8]) -> i32 {
    let mut reader = Reader::new(response);
    let _correlation = reader.int32().unwrap();
    let brokers = reader.int32().unwrap();
    for _ in 0..brokers {
        let _node = reader.int32().unwrap();
        let _host = reader.string().unwrap();
        let _port = reader.int32().unwrap();
        let _rack = reader.nullable_string().unwrap();
    }
    let _controller = reader.int32().unwrap();
    assert_eq!(reader.int32().unwrap(), 1);
    assert_eq!(reader.int16().unwrap(), 0);
    assert_eq!(reader.string().unwrap(), "events");
    let _internal = reader.int8().unwrap();
    reader.int32().unwrap()
}

struct Daemon {
    child: Child,
    rail: PathBuf,
    data_dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.rail);
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn spawn_broker(port: u16) -> (Daemon, TcpStream) {
    let pid = std::process::id();
    let rail = std::env::temp_dir().join(format!("kafka-scale-{pid}-{port}.toml"));
    let data_dir = std::env::temp_dir().join(format!("kafka-scale-data-{pid}-{port}"));
    std::fs::write(&rail, rail_text()).expect("write rail spec");
    let _ = std::fs::remove_dir_all(&data_dir);

    let child = Command::new(env!("CARGO_BIN_EXE_datarail"))
        .args([
            "kafka-broker",
            rail.to_str().expect("rail path is UTF-8"),
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--data-dir",
            data_dir.to_str().expect("data path is UTF-8"),
            "--partitions",
            "2",
        ])
        .spawn()
        .expect("spawn datarail kafka-broker");
    let mut daemon = Daemon {
        child,
        rail,
        data_dir,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let stream = loop {
        if let Some(status) = daemon.child.try_wait().expect("poll broker") {
            panic!("broker exited before readiness: {status}");
        }
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            break stream;
        }
        assert!(Instant::now() < deadline, "broker never became ready");
        thread::sleep(Duration::from_millis(50));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .expect("set write timeout");
    (daemon, stream)
}

fn producer_worker(
    partition: i32,
    producer_id: usize,
    port: u16,
    start: &Arc<Barrier>,
) -> Result<ProducerTiming, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;

    let prefix = format!("evt:p{producer_id}:");
    let mut record = vec![b'x'; RECORD_SIZE];
    record[..prefix.len()].copy_from_slice(prefix.as_bytes());
    let record_ref = record.as_slice();

    start.wait();
    let began = Instant::now();
    let mut batch_latencies = Vec::new();
    for batch_start in (0..RECORD_COUNT).step_by(BATCH_SIZE) {
        let batch_began = Instant::now();
        let count = BATCH_SIZE.min(RECORD_COUNT - batch_start);
        let values = vec![record_ref; count];
        let correlation =
            i32::try_from(producer_id * 10_000 + batch_start).map_err(|error| error.to_string())?;
        stream
            .write_all(&produce_request(correlation, partition, &values))
            .map_err(|error| error.to_string())?;
        let response = read_frame(&mut stream);
        let expected_base = i64::try_from(batch_start).map_err(|error| error.to_string())?;
        produce_ack(&response, correlation, partition, expected_base);
        batch_latencies.push(batch_began.elapsed());
    }
    Ok(ProducerTiming {
        elapsed: began.elapsed(),
        batch_latencies,
    })
}

fn timed_case(parallel: bool) -> CaseTiming {
    let port = free_port();
    let (_daemon, _control) = spawn_broker(port);
    if parallel {
        let start = Arc::new(Barrier::new(3));
        let start_zero = Arc::clone(&start);
        let worker_zero = thread::spawn(move || producer_worker(0, 0, port, &start_zero));
        let start_one = Arc::clone(&start);
        let worker_one = thread::spawn(move || producer_worker(1, 1, port, &start_one));
        start.wait();
        let timing_zero = worker_zero
            .join()
            .expect("partition 0 producer panicked")
            .expect("partition 0 failed");
        let timing_one = worker_one
            .join()
            .expect("partition 1 producer panicked")
            .expect("partition 1 failed");
        let elapsed = timing_zero.elapsed.max(timing_one.elapsed);
        let mut latencies = timing_zero.batch_latencies;
        latencies.extend(timing_one.batch_latencies);
        CaseTiming {
            elapsed,
            p99: p99(&latencies),
        }
    } else {
        let start = Arc::new(Barrier::new(2));
        let worker = {
            let start = Arc::clone(&start);
            thread::spawn(move || producer_worker(0, 0, port, &start))
        };
        start.wait();
        let timing = worker
            .join()
            .expect("serial producer panicked")
            .expect("serial producer failed");
        CaseTiming {
            elapsed: timing.elapsed,
            p99: p99(&timing.batch_latencies),
        }
    }
}

#[test]
fn per_partition_scaling_two_producers_two_partitions() {
    let port = free_port();
    let (_daemon, mut control) = spawn_broker(port);

    control
        .write_all(&metadata_request(1))
        .expect("write metadata request");
    assert_eq!(metadata_partition_count(&read_frame(&mut control)), 2);

    let start = Arc::new(Barrier::new(3));
    let start_zero = Arc::clone(&start);
    let worker_zero = thread::spawn(move || producer_worker(0, 0, port, &start_zero));
    let start_one = Arc::clone(&start);
    let worker_one = thread::spawn(move || producer_worker(1, 1, port, &start_one));
    start.wait();

    let elapsed_zero = worker_zero
        .join()
        .expect("partition 0 producer did not panic")
        .expect("partition 0 producer failed");
    let elapsed_one = worker_one
        .join()
        .expect("partition 1 producer did not panic")
        .expect("partition 1 producer failed");
    eprintln!(
        "concurrent producer durations: p0={:?}, p1={:?}",
        elapsed_zero.elapsed, elapsed_one.elapsed
    );

    for partition in 0..2 {
        control
            .write_all(&fetch_request(100 + partition, partition))
            .expect("write fetch request");
        let values = fetched_values(&read_frame(&mut control));
        assert_eq!(
            values.len(),
            RECORD_COUNT,
            "partition {partition} record count"
        );
        let expected_prefix = format!("evt:p{partition}:");
        assert!(values
            .iter()
            .all(|value| value.starts_with(expected_prefix.as_bytes())));
        assert!(values.iter().all(|value| value.len() == RECORD_SIZE));
    }
}

/// Local A/B only. Interleaves serial and parallel brokers from this same build; output is evidence, not a CI gate.
#[test]
#[ignore = "manual local benchmark; not a correctness gate"]
fn per_partition_scaling_interleaved_benchmark() {
    let runs = [false, true, false, true];
    let mut serial = Vec::new();
    let mut parallel = Vec::new();
    for is_parallel in runs {
        let timing = timed_case(is_parallel);
        let records = if is_parallel {
            RECORD_COUNT * 2
        } else {
            RECORD_COUNT
        };
        let throughput =
            f64::from(u32::try_from(records).expect("benchmark record count fits u32"))
                / timing.elapsed.as_secs_f64();
        println!(
            "case={} records={} elapsed_ms={:.3} p99_ms={:.3} records_per_s={:.0}",
            if is_parallel {
                "parallel-2p"
            } else {
                "serial-1p"
            },
            records,
            timing.elapsed.as_secs_f64() * 1000.0,
            timing.p99.as_secs_f64() * 1000.0,
            throughput
        );
        if is_parallel {
            parallel.push(throughput);
        } else {
            serial.push(throughput);
        }
    }
    let serial_mean = serial.iter().sum::<f64>()
        / f64::from(u32::try_from(serial.len()).expect("benchmark run count fits u32"));
    let parallel_mean = parallel.iter().sum::<f64>()
        / f64::from(u32::try_from(parallel.len()).expect("benchmark run count fits u32"));
    println!(
        "interleaved_ratio_parallel_over_serial={:.3}",
        parallel_mean / serial_mean
    );
}
