//! The Kafka ingest serve loop: accept TCP, read length-framed requests, dispatch `ApiVersions` / `Metadata` /
//! `Produce`, write length-framed responses, and emit each produced batch's record VALUES over an `mpsc` channel
//! (the integration layer seals them and lands them via a datarail `Sink`). Dependency-free: this crate speaks
//! only the wire protocol; it never sees datarail keys or cofres.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::codec::{Reader, Writer};
use crate::consume::{
    fetch_response, list_offsets_response, parse_fetch, parse_list_offsets, FetchPartitionResult,
    FetchTopicResult, ListOffsetResult, ListOffsetTopicResult, API_FETCH, API_LIST_OFFSETS,
};
use crate::coordinator::GroupCoordinator;
use crate::groups::{
    find_coordinator_response, heartbeat_response, join_group_response, leave_group_response,
    offset_commit_response, offset_fetch_response, parse_find_coordinator, parse_heartbeat,
    parse_join_group, parse_leave_group, parse_offset_commit, parse_offset_fetch, parse_sync_group,
    sync_group_response, JoinGroupResponse, OffsetCommitPartitionResult, OffsetCommitTopicResult,
    OffsetFetchPartitionResult, OffsetFetchTopicResult, API_FIND_COORDINATOR, API_HEARTBEAT,
    API_JOIN_GROUP, API_LEAVE_GROUP, API_OFFSET_COMMIT, API_OFFSET_FETCH, API_SYNC_GROUP,
};
use crate::handlers::{
    api_versions_response, init_producer_id_response, metadata_response, parse_metadata_topics,
    API_INIT_PRODUCER_ID, API_METADATA, API_PRODUCE, API_VERSIONS,
};
use crate::produce::{
    build_record_batch, parse_produce, produce_response, EosCoord, ProducedRequest,
};
use crate::txn::{
    add_partitions_response, init_producer_id_response as txn_init_producer_id_response,
    parse_add_offsets, parse_add_partitions, parse_end_txn, parse_init_producer_id,
    parse_txn_offset_commit, throttle_error_response, TxnCoordinator, API_ADD_OFFSETS_TO_TXN,
    API_ADD_PARTITIONS_TO_TXN, API_END_TXN, API_TXN_OFFSET_COMMIT,
};

/// A connection stream the serve loop reads length-framed requests from and writes responses to. Implemented for
/// `TcpStream` (plaintext) and — via the CLI's `tls` feature — a rustls TLS stream, so `datarail-kafka` stays
/// dependency-free and transport-agnostic (`KAFKA-TLS-DESIGN.md`): crypto lives in the CLI, not this wire crate.
pub trait ReadWrite: Read + Write {}
impl<T: Read + Write + ?Sized> ReadWrite for T {}

/// Turns a freshly-accepted plaintext `TcpStream` into the stream a connection handler uses. [`PlainConn`] is the
/// identity (no TLS); the CLI supplies a rustls-wrapping impl behind its `tls` feature. This is the seam that keeps
/// TLS out of the zero-dep wire crate while letting it terminate TLS at the edge.
pub trait ConnWrap: Send + Sync {
    /// Identity, or a completed TLS handshake, over the accepted socket.
    ///
    /// # Errors
    /// A TLS handshake failure — the serve loop then drops the connection.
    fn wrap(&self, stream: TcpStream) -> io::Result<Box<dyn ReadWrite + Send>>;
}

/// A configured SASL/PLAIN credential (`KAFKA-SASL-DESIGN.md`). When `serve_broker` is given `Some`, a client must
/// authenticate (`SaslHandshake` → `SaslAuthenticate`) before any other API; `None` means SASL is off (as today).
#[derive(Clone)]
pub struct SaslCreds {
    /// The expected username.
    pub user: String,
    /// The expected password (checked constant-time; PLAIN sends it in the clear, so pair with TLS).
    pub pass: String,
}

/// Plaintext transport: the accepted socket IS the stream, unchanged (no dependency, the default).
pub struct PlainConn;

impl ConnWrap for PlainConn {
    fn wrap(&self, stream: TcpStream) -> io::Result<Box<dyn ReadWrite + Send>> {
        Ok(Box::new(stream))
    }
}

/// A produced batch handed to the integration layer for **durable** landing. The producer is **not acked until
/// `done` reports the landing result** (ack-after-durable — audit A: a broker that acks before the record is
/// durable loses acked records on a crash, and an idempotent producer never resends an acked batch). `done`
/// carries `Ok(())` on a durable land or `Err(e)` on a failure; the error's [`io::ErrorKind`] classifies the
/// failure so the serve loop can pick the RIGHT wire code (`InvalidData` ⇒ permanent rejection / non-retriable
/// 87; anything else ⇒ retriable 56) — never a false ack. The `EosCoord` (when present) carries the idempotent
/// producer's stable sequence range — the basis for exactly-once ingest (`KAFKA-EOS-DESIGN.md`); `None` ⇒
/// at-least-once.
pub struct ProducedBatch {
    /// Topic the batch was produced to.
    pub topic: String,
    /// Partition index.
    pub partition: i32,
    /// Record value payloads, in order.
    pub values: Vec<Vec<u8>>,
    /// The idempotent-producer EOS coordinate, if present.
    pub eos: Option<EosCoord>,
    /// The integration layer signals the durable-landing result here; the serve loop acks only after it arrives.
    /// The error KIND distinguishes a permanent rejection (`InvalidData`) from a transient failure (everything
    /// else) so the produce response carries a non-retriable vs retriable code accordingly.
    pub done: Sender<io::Result<()>>,
}

/// Max bytes in a single framed request — a hostile peer cannot make us allocate a giant buffer.
const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Max concurrent connections — bounds thread/FD/memory under a connection flood (audit K2).
const MAX_CONNECTIONS: usize = 256;
/// Per-socket read/write deadline — a stalled/slowloris peer errors out instead of pinning a thread (audit K2).
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Max distinct `(topic, partition)` offset entries retained — bounds the global map so a hostile producer
/// cannot mint unbounded permanent keys (audit K1). Beyond this, a new key simply restarts at offset 0.
const MAX_OFFSET_KEYS: usize = 100_000;

struct Shared {
    offsets: Mutex<HashMap<(String, i32), i64>>,
    tx: Sender<ProducedBatch>,
    host: String,
    port: i32,
    /// Monotonic source of `producer_id`s handed out by `InitProducerId` — each idempotent producer gets a
    /// distinct id, so distinct producers form distinct exactly-once substreams in the sink.
    next_producer_id: AtomicI64,
}

/// Serve Kafka ingest on `listener`, advertising this broker as `advertised_host:advertised_port` (the address a
/// client must be able to reach us at). Produced record values are sent on `tx`. Blocks, one thread per connection.
///
/// # Errors
/// [`io::Error`] if accepting a connection fails.
pub fn serve(
    listener: &TcpListener,
    advertised_host: &str,
    advertised_port: i32,
    tx: Sender<ProducedBatch>,
    conn_wrap: &Arc<dyn ConnWrap>,
) -> io::Result<()> {
    let shared = Arc::new(Shared {
        offsets: Mutex::new(HashMap::new()),
        tx,
        host: advertised_host.to_owned(),
        port: advertised_port,
        next_producer_id: AtomicI64::new(1),
    });
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = stream?;
        // Bound concurrency: refuse (and immediately drop) connections past the cap rather than spawn unboundedly.
        if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            drop(stream);
            continue;
        }
        // A stalled peer must not pin a thread forever — fail its blocking reads/writes after a deadline.
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        active.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::clone(&shared);
        let active = Arc::clone(&active);
        let conn_wrap = Arc::clone(conn_wrap);
        std::thread::spawn(move || {
            // Wrap the raw socket (identity for plaintext, a TLS handshake otherwise) before handling; a failed
            // handshake just drops the connection.
            if let Ok(mut s) = conn_wrap.wrap(stream) {
                let _ = handle_connection(&mut *s, &shared);
            }
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

/// Whether the REQUEST header for `(api_key, version)` is flexible (KIP-482 tagged fields present).
fn request_is_flexible(api_key: i16, version: i16) -> bool {
    match api_key {
        API_VERSIONS => version >= 3,
        API_METADATA | API_PRODUCE => version >= 9,
        _ => false,
    }
}

/// Read one length-framed request (`INT32` length prefix + payload), or `None` at a clean EOF.
fn read_frame<R: Read>(stream: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = i32::from_be_bytes(len_buf);
    let n = usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative frame length"))?;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn handle_connection<S: Read + Write>(mut stream: S, shared: &Shared) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut stream)? {
        let mut reader = Reader::new(&frame);
        let api_key = reader.int16()?;
        let api_version = reader.int16()?;
        let correlation_id = reader.int32()?;
        let _client_id = reader.nullable_string()?;
        if request_is_flexible(api_key, api_version) {
            reader.skip_tagged_fields()?;
        }

        // `None` means silent acks=0 produce; every other request yields `Some(bytes)`.
        let response: Option<Vec<u8>> = match api_key {
            API_VERSIONS => Some(api_versions_response(api_version, correlation_id)),
            API_METADATA => {
                let topics = parse_metadata_topics(&mut reader)?;
                // Ingest merges all partitions into one sink, so a single partition is advertised here.
                Some(metadata_response(
                    api_version,
                    correlation_id,
                    &shared.host,
                    shared.port,
                    &topics,
                    1,
                ))
            }
            API_PRODUCE => handle_ingest_produce(&mut reader, api_version, correlation_id, shared)?,
            API_INIT_PRODUCER_ID => {
                // Hand out a fresh producer_id so the client can enable idempotence; the request body
                // (transactional_id / timeout) needs no parsing — each producer just needs a distinct id.
                let pid = shared.next_producer_id.fetch_add(1, Ordering::Relaxed);
                Some(init_producer_id_response(correlation_id, pid))
            }
            other => {
                return Err(io::Error::other(format!(
                    "unsupported Kafka api_key {other}"
                )));
            }
        };

        // Suppress the write entirely for a silent request (acks=0 produce); the read loop keeps serving the
        // next framed request on the same connection.
        if let Some(bytes) = response {
            stream.write_all(&Writer::frame(&bytes))?;
            stream.flush()?;
        }
    }
    Ok(())
}

fn handle_ingest_produce(
    reader: &mut Reader<'_>,
    api_version: i16,
    correlation_id: i32,
    shared: &Shared,
) -> io::Result<Option<Vec<u8>>> {
    let ProducedRequest { acks, topics } = parse_produce(reader, api_version)?;
    let mut codes: HashMap<(String, i32), i16> = HashMap::new();
    for topic in &topics {
        for partition in &topic.partitions {
            if partition.values.is_empty() {
                continue;
            }
            let (done, done_rx) = std::sync::mpsc::channel();
            let sent = shared.tx.send(ProducedBatch {
                topic: topic.name.clone(),
                partition: partition.partition,
                values: partition.values.clone(),
                eos: partition.eos,
                done,
            });
            let code = match sent {
                Err(_) => {
                    eprintln!(
                        "kafka: ingest land unreachable (retriable) topic={} partition={}",
                        topic.name, partition.partition
                    );
                    56
                }
                Ok(()) => match done_rx.recv() {
                    Ok(Ok(())) => 0,
                    Ok(Err(error)) => produce_error_code(&topic.name, partition.partition, &error),
                    Err(error) => {
                        eprintln!(
                            "kafka: ingest land result lost (retriable) topic={} partition={} error={error}",
                            topic.name, partition.partition
                        );
                        56
                    }
                },
            };
            codes.insert((topic.name.clone(), partition.partition), code);
        }
    }
    let mut offsets = shared
        .offsets
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let response = produce_response(
        api_version,
        correlation_id,
        &topics,
        &mut |name, partition, count| {
            let key = (name.to_owned(), partition);
            let base = *offsets.get(&key).unwrap_or(&0);
            let code = codes.get(&key).copied().unwrap_or(0);
            if code == 0 && (offsets.contains_key(&key) || offsets.len() < MAX_OFFSET_KEYS) {
                offsets.insert(
                    key,
                    base.saturating_add(i64::try_from(count).unwrap_or(i64::MAX)),
                );
            }
            (base, code)
        },
    );
    Ok((acks != 0).then_some(response))
}

/// The CONSUME-side broker backend (see `KAFKA-FETCH-DESIGN.md`). The `kafka-broker` mode wires this to a sealed
/// store: `produce` seals + stores the cofre, `fetch` un-seals at the edge. Shared across connection threads.
pub trait KafkaBroker: Send + Sync {
    /// Seal + store a produced batch for `(topic, partition)`; return the logical base offset assigned.
    ///
    /// # Errors
    /// Propagates a seal/store error (the producer then gets a retriable code, never a false ack).
    fn produce(&self, topic: &str, partition: i32, records: &[Vec<u8>]) -> io::Result<i64>;

    /// Un-seal + return the plaintext records for `(topic, partition)` from `offset`, bounded by `max_bytes`.
    ///
    /// # Errors
    /// Propagates a read/open error.
    fn fetch(
        &self,
        topic: &str,
        partition: i32,
        offset: i64,
        max_bytes: i32,
    ) -> io::Result<Vec<Vec<u8>>>;

    /// The logical `(earliest, latest)` offsets for `(topic, partition)` (latest = the next offset to be written).
    fn bounds(&self, topic: &str, partition: i32) -> (i64, i64);

    /// BUFFER a transactional batch for `(producer_id, epoch)` on `(topic, partition)` — held until `EndTxn`, NOT
    /// yet durable/visible (`KAFKA-TXN-DESIGN.md`). The EPOCH is part of the buffer key so a stale-epoch record
    /// that slips in via the `produce_check`/`buffer_txn` two-lock window can NEVER be flushed by a newer
    /// incarnation's commit (audit TOCTOU). Returns the provisional base offset (log end + already-buffered).
    /// Default: falls back to a plain `produce` (a non-txn-aware broker simply lands it immediately).
    ///
    /// # Errors
    /// Propagates a seal/store error.
    fn buffer_txn(
        &self,
        _producer_id: i64,
        _epoch: i16,
        topic: &str,
        partition: i32,
        records: &[Vec<u8>],
    ) -> io::Result<i64> {
        self.produce(topic, partition, records)
    }

    /// COMMIT `(producer_id, epoch)`'s buffered records on `partitions` — flush ONLY this exact epoch's buffers to
    /// the durable sealed log (now visible), and DROP any older-epoch buffers for the same producer (stale
    /// stragglers from a re-init race → never committed). Default: no-op.
    ///
    /// # Errors
    /// Propagates a seal/store error (the producer then retries the `EndTxn`).
    fn commit_txn(
        &self,
        _producer_id: i64,
        _epoch: i16,
        _partitions: &[(String, i32)],
    ) -> io::Result<()> {
        Ok(())
    }

    /// COMMIT a transaction and its staged consumer offsets under one broker-specific durability boundary when
    /// supported. The default preserves compatibility for stores that only implement the older partition method.
    ///
    /// # Errors
    /// Propagates a seal, store, or offset durability error.
    fn commit_txn_with_offsets(
        &self,
        _transactional_id: &str,
        producer_id: i64,
        epoch: i16,
        partitions: &[(String, i32)],
        group: Option<&str>,
        offsets: &[(String, i32, i64)],
    ) -> io::Result<()> {
        self.commit_txn(producer_id, epoch, partitions)?;
        if let Some(group) = group {
            for (topic, partition, offset) in offsets {
                self.commit_offset(group, topic, *partition, *offset)?;
            }
        }
        Ok(())
    }

    /// ABORT — discard every buffer for `producer_id` at epoch `<=` the given one (this incarnation + any stale
    /// older one). Default: no-op.
    fn abort_txn(&self, _producer_id: i64, _epoch: i16, _partitions: &[(String, i32)]) {}

    /// Durably commit a consumer group's offset for `(topic, partition)` (`OffsetCommit`). Default: no-op — a
    /// broker that does not persist consumer offsets (acked as NONE; the consumer simply gains no durability).
    ///
    /// # Errors
    /// Propagates a durable-store error (the consumer then gets a retriable code, never a false success).
    fn commit_offset(
        &self,
        _group: &str,
        _topic: &str,
        _partition: i32,
        _offset: i64,
    ) -> io::Result<()> {
        Ok(())
    }

    /// The last durably-committed offset for `(group, topic, partition)`, or `None` if none (`OffsetFetch`).
    /// Default: `None`.
    ///
    /// # Errors
    /// Propagates a durable-store read error.
    fn fetch_offset(&self, _group: &str, _topic: &str, _partition: i32) -> io::Result<Option<i64>> {
        Ok(None)
    }
}

/// Serve the bidirectional `datarail kafka-broker` on `listener`: `Produce` (seal+store), `Fetch` (un-seal+return),
/// `ListOffsets`, plus `Metadata`/`ApiVersions`/`InitProducerId`. Blocks; one bounded thread per connection (like
/// [`serve`]). The storage holds only sealed cofres — un-sealing happens here, at the serving edge.
///
/// # Errors
/// [`io::Error`] if accepting a connection fails.
pub fn serve_broker<B: KafkaBroker + 'static>(
    listener: &TcpListener,
    advertised_host: &str,
    advertised_port: i32,
    partitions: i32,
    broker: &Arc<B>,
    conn_wrap: &Arc<dyn ConnWrap>,
    creds: Option<SaslCreds>,
) -> io::Result<()> {
    let host = advertised_host.to_owned();
    let next_producer_id = Arc::new(AtomicI64::new(1));
    let coordinator = Arc::new(GroupCoordinator::with_defaults());
    // Transactional producer ids live in a distinct high range so they never collide with the idempotent
    // allocator's (which counts up from 1).
    let txn_coordinator = Arc::new(TxnCoordinator::new(1 << 40));
    let creds = creds.map(Arc::new); // shared across connection threads; None = SASL off (today's behavior)
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = stream?;
        if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            drop(stream);
            continue;
        }
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        active.fetch_add(1, Ordering::Relaxed);
        let broker = Arc::clone(broker);
        let host = host.clone();
        let pid = Arc::clone(&next_producer_id);
        let coord = Arc::clone(&coordinator);
        let txn = Arc::clone(&txn_coordinator);
        let active = Arc::clone(&active);
        let conn_wrap = Arc::clone(conn_wrap);
        let creds = creds.clone();
        std::thread::spawn(move || {
            let ctx = BrokerCtx {
                host: &host,
                port: advertised_port,
                partitions,
                next_producer_id: &pid,
            };
            // Wrap the raw socket (identity for plaintext, a TLS handshake otherwise) before serving.
            if let Ok(mut s) = conn_wrap.wrap(stream) {
                let _ = handle_broker_connection(
                    &mut *s,
                    broker.as_ref(),
                    &ctx,
                    &coord,
                    &txn,
                    creds.as_deref(),
                );
            }
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

/// Per-connection broker context (bundled so the connection handler stays within the argument cap).
struct BrokerCtx<'a> {
    host: &'a str,
    port: i32,
    partitions: i32,
    next_producer_id: &'a AtomicI64,
}

fn handle_broker_connection<S: Read + Write, B: KafkaBroker>(
    mut stream: S,
    broker: &B,
    ctx: &BrokerCtx<'_>,
    coordinator: &GroupCoordinator,
    txn: &TxnCoordinator,
    creds: Option<&SaslCreds>,
) -> io::Result<()> {
    let mut authenticated = creds.is_none();
    while let Some(frame) = read_frame(&mut stream)? {
        let mut reader = Reader::new(&frame);
        let api_key = reader.int16()?;
        let api_version = reader.int16()?;
        let correlation_id = reader.int32()?;
        let _client_id = reader.nullable_string()?;
        if request_is_flexible(api_key, api_version) {
            reader.skip_tagged_fields()?;
        }
        match handle_sasl(
            api_key,
            api_version,
            correlation_id,
            &mut reader,
            creds,
            &mut authenticated,
        )? {
            SaslOutcome::Reply(r) => {
                stream.write_all(&Writer::frame(&r))?;
                stream.flush()?;
                continue;
            }
            SaslOutcome::CloseAfter(r) => {
                stream.write_all(&Writer::frame(&r))?;
                stream.flush()?;
                return Ok(());
            }
            SaslOutcome::Pass => {}
        }
        if !authenticated && api_key != API_VERSIONS {
            return Ok(());
        }
        let bctx = BrokerReqCtx {
            broker,
            ctx,
            coordinator,
            txn,
        };
        let (response, suppress) =
            handle_broker_request(api_key, api_version, correlation_id, &mut reader, &bctx)?;
        if !suppress {
            stream.write_all(&Writer::frame(&response))?;
            stream.flush()?;
        }
    }
    Ok(())
}

/// Handle a single broker request (post-SASL), returning the response bytes and whether to suppress the write
/// (true only for acks=0 produce).
struct BrokerReqCtx<'a, B: KafkaBroker> {
    broker: &'a B,
    ctx: &'a BrokerCtx<'a>,
    coordinator: &'a GroupCoordinator,
    txn: &'a TxnCoordinator,
}

fn handle_broker_request<B: KafkaBroker>(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    reader: &mut Reader<'_>,
    bctx: &BrokerReqCtx<'_, B>,
) -> io::Result<(Vec<u8>, bool)> {
    let mut suppress_response = false;
    let response = match api_key {
        API_VERSIONS => api_versions_response(api_version, correlation_id),
        API_METADATA => {
            let topics = parse_metadata_topics(reader)?;
            metadata_response(
                api_version,
                correlation_id,
                bctx.ctx.host,
                bctx.ctx.port,
                &topics,
                bctx.ctx.partitions,
            )
        }
        API_INIT_PRODUCER_ID => {
            if let Some(tid) = parse_init_producer_id(reader)? {
                let (pid, epoch) = bctx.txn.init_producer_id(&tid);
                bctx.broker.abort_txn(pid, epoch, &[]);
                txn_init_producer_id_response(correlation_id, pid, epoch)
            } else {
                let pid = bctx.ctx.next_producer_id.fetch_add(1, Ordering::Relaxed);
                init_producer_id_response(correlation_id, pid)
            }
        }
        API_PRODUCE => {
            let ProducedRequest { acks, topics } = parse_produce(reader, api_version)?;
            let results = produce_results(bctx.broker, bctx.txn, &topics);
            suppress_response = acks == 0;
            produce_response(
                api_version,
                correlation_id,
                &topics,
                &mut |name, part, _count| {
                    results
                        .get(&(name.to_owned(), part))
                        .copied()
                        .unwrap_or((0, 0))
                },
            )
        }
        API_FETCH => {
            let topics = parse_fetch(reader, api_version)?;
            let out = fetch_results(bctx.broker, &topics);
            fetch_response(api_version, correlation_id, &out)
        }
        API_LIST_OFFSETS => handle_list_offsets(reader, api_version, correlation_id, bctx.broker)?,
        API_FIND_COORDINATOR => {
            let _group = parse_find_coordinator(reader, api_version)?;
            find_coordinator_response(api_version, correlation_id, 0, bctx.ctx.host, bctx.ctx.port)
        }
        API_OFFSET_COMMIT => {
            let req = parse_offset_commit(reader, api_version)?;
            let out = offset_commit_results(bctx.broker, &req);
            offset_commit_response(correlation_id, &out)
        }
        API_OFFSET_FETCH => {
            let req = parse_offset_fetch(reader, api_version)?;
            let out = offset_fetch_results(bctx.broker, &req);
            offset_fetch_response(api_version, correlation_id, &out)
        }
        other => {
            if let Some(resp) =
                dispatch_group_api(other, api_version, correlation_id, reader, bctx.coordinator)?
            {
                resp
            } else if let Some(resp) = dispatch_txn_api(
                other,
                api_version,
                correlation_id,
                reader,
                bctx.txn,
                bctx.broker,
            )? {
                resp
            } else {
                return Err(io::Error::other(format!(
                    "unsupported Kafka api_key {other}"
                )));
            }
        }
    };
    Ok((response, suppress_response))
}

fn handle_list_offsets<B: KafkaBroker>(
    reader: &mut Reader<'_>,
    api_version: i16,
    correlation_id: i32,
    broker: &B,
) -> io::Result<Vec<u8>> {
    let topics = parse_list_offsets(reader, api_version)?;
    let out = topics
        .iter()
        .map(|topic| ListOffsetTopicResult {
            name: topic.name.clone(),
            partitions: topic
                .partitions
                .iter()
                .map(|partition| {
                    let (earliest, latest) = broker.bounds(&topic.name, partition.partition);
                    ListOffsetResult {
                        partition: partition.partition,
                        offset: if partition.timestamp == -2 {
                            earliest
                        } else {
                            latest
                        },
                    }
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    Ok(list_offsets_response(api_version, correlation_id, &out))
}

/// What the SASL pre-stage decided for a request: send a reply and keep going, send a reply then close (failed
/// auth), or it was not a SASL request (proceed to the normal dispatch).
enum SaslOutcome {
    Reply(Vec<u8>),
    CloseAfter(Vec<u8>),
    Pass,
}

/// Handle the SASL handshake/auth APIs (`KAFKA-SASL-DESIGN.md`). For `SaslHandshake` it negotiates the mechanism;
/// for `SaslAuthenticate` it verifies the PLAIN credential (constant-time) and flips `authenticated`. Any other API
/// returns `Pass`. With no configured credential, an auth attempt is accepted (SASL is off).
fn handle_sasl(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    reader: &mut Reader<'_>,
    creds: Option<&SaslCreds>,
    authenticated: &mut bool,
) -> io::Result<SaslOutcome> {
    if api_key == crate::sasl::API_SASL_HANDSHAKE {
        let mechanism = crate::sasl::parse_sasl_handshake(reader)?;
        let code = if mechanism == crate::sasl::PLAIN {
            0
        } else {
            crate::sasl::UNSUPPORTED_SASL_MECHANISM
        };
        return Ok(SaslOutcome::Reply(crate::sasl::sasl_handshake_response(
            correlation_id,
            code,
            &[crate::sasl::PLAIN],
        )));
    }
    if api_key == crate::sasl::API_SASL_AUTHENTICATE {
        let token = crate::sasl::parse_sasl_authenticate(reader, api_version)?;
        let ok = creds.is_none_or(|c| crate::sasl::verify_plain(&token, &c.user, &c.pass));
        let resp = |code, msg| {
            crate::sasl::sasl_authenticate_response(correlation_id, api_version, code, msg, &[], 0)
        };
        if ok {
            *authenticated = true;
            return Ok(SaslOutcome::Reply(resp(0, None)));
        }
        return Ok(SaslOutcome::CloseAfter(resp(
            crate::sasl::SASL_AUTHENTICATION_FAILED,
            Some("authentication failed"),
        )));
    }
    Ok(SaslOutcome::Pass)
}

/// Handle the consumer-group REBALANCE APIs (JoinGroup/SyncGroup/Heartbeat/LeaveGroup) against the coordinator.
/// Returns `None` if `api_key` is not one of them (so the caller can fall through to the unsupported-key error).
fn dispatch_group_api(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    reader: &mut Reader,
    coordinator: &GroupCoordinator,
) -> io::Result<Option<Vec<u8>>> {
    let resp = match api_key {
        API_JOIN_GROUP => {
            let req = parse_join_group(reader, api_version)?;
            let protocols: Vec<(String, Vec<u8>)> = req
                .protocols
                .into_iter()
                .map(|p| (p.name, p.metadata))
                .collect();
            let o = coordinator.join(
                &req.group_id,
                &req.member_id,
                req.session_timeout_ms,
                req.rebalance_timeout_ms,
                &req.protocol_type,
                &protocols,
            );
            let resp = JoinGroupResponse {
                error_code: o.error_code,
                generation: o.generation,
                protocol: o.protocol,
                leader: o.leader,
                member_id: o.member_id,
                members: o.members,
            };
            join_group_response(api_version, correlation_id, &resp)
        }
        API_SYNC_GROUP => {
            let req = parse_sync_group(reader, api_version)?;
            let assignments: Vec<(String, Vec<u8>)> = req
                .assignments
                .into_iter()
                .map(|a| (a.member_id, a.assignment))
                .collect();
            let o = coordinator.sync(
                &req.group_id,
                &req.member_id,
                req.generation_id,
                &assignments,
            );
            sync_group_response(api_version, correlation_id, o.error_code, &o.assignment)
        }
        API_HEARTBEAT => {
            let req = parse_heartbeat(reader, api_version)?;
            let code = coordinator.heartbeat(&req.group_id, &req.member_id, req.generation_id);
            heartbeat_response(api_version, correlation_id, code)
        }
        API_LEAVE_GROUP => {
            let (group_id, member_id) = parse_leave_group(reader, api_version)?;
            let code = coordinator.leave(&group_id, &member_id);
            leave_group_response(api_version, correlation_id, code)
        }
        _ => return Ok(None),
    };
    Ok(Some(resp))
}

/// Handle the TRANSACTIONAL producer APIs (AddPartitionsToTxn/AddOffsetsToTxn/TxnOffsetCommit/EndTxn) against the
/// txn coordinator. Returns `None` if `api_key` is not one of them. On `EndTxn(commit)`, the broker owns one
/// durability boundary for participant logs plus staged consumer offsets when its store supports it.
fn dispatch_txn_api<B: KafkaBroker>(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    reader: &mut Reader,
    txn: &TxnCoordinator,
    broker: &B,
) -> io::Result<Option<Vec<u8>>> {
    let resp = match api_key {
        API_ADD_PARTITIONS_TO_TXN => {
            let req = parse_add_partitions(reader, api_version)?;
            let parts: Vec<(String, i32)> = req
                .topics
                .iter()
                .flat_map(|(t, ps)| ps.iter().map(move |&p| (t.clone(), p)))
                .collect();
            let code =
                txn.add_partitions(&req.transactional_id, req.producer_id, req.epoch, &parts);
            add_partitions_response(correlation_id, &req.topics, code)
        }
        API_ADD_OFFSETS_TO_TXN => {
            let (tid, pid, epoch, group) = parse_add_offsets(reader, api_version)?;
            let code = txn.add_offsets(&tid, pid, epoch, &group);
            throttle_error_response(correlation_id, code)
        }
        API_TXN_OFFSET_COMMIT => {
            let req = parse_txn_offset_commit(reader, api_version)?;
            let code = txn.stage_offsets(
                &req.transactional_id,
                req.producer_id,
                req.epoch,
                &req.offsets,
            );
            txn_offset_commit_response(correlation_id, &req.topics, code)
        }
        API_END_TXN => {
            let (tid, pid, epoch, committed) = parse_end_txn(reader, api_version)?;
            // PREPARE: validate against the OPEN txn (no reset yet — so a failed flush can be retried).
            let out = txn.end_txn(&tid, pid, epoch, committed);
            let code = if out.error_code != 0 {
                out.error_code
            } else if out.committed {
                // COMMIT: flush the buffered records to the durable log, then the staged offsets. On ANY failure,
                // return a RETRIABLE code and do NOT finish the txn — the producer retries EndTxn; the flush
                // re-runs (already-flushed buffers are gone → harmless) until it fully succeeds (audit: a swallowed
                // mid-flush error was acked as a successful atomic commit, silently losing committed records).
                // (A permanent contract violation can NOT surface here: it is rejected at BUFFER time with
                // non-retriable INVALID_RECORD 87 on its own ProduceResponse — see `KafkaBrokerStore::buffer_txn` —
                // so by construction a commit-time failure is transient and 56 is the honest answer.)
                if broker
                    .commit_txn_with_offsets(
                        &tid,
                        pid,
                        epoch,
                        &out.partitions,
                        out.group.as_deref(),
                        &out.offsets,
                    )
                    .is_err()
                {
                    56
                } else {
                    txn.finish_txn(&tid, pid, epoch);
                    0
                }
            } else {
                // ABORT: discard the buffered records — they never become durable/visible.
                broker.abort_txn(pid, epoch, &out.partitions);
                txn.finish_txn(&tid, pid, epoch);
                0
            };
            throttle_error_response(correlation_id, code)
        }
        _ => return Ok(None),
    };
    Ok(Some(resp))
}

/// Build a `TxnOffsetCommit` response mirroring the topics/partitions with a per-partition error code.
fn txn_offset_commit_response(
    correlation_id: i32,
    topics: &[(String, Vec<i32>)],
    error_code: i16,
) -> Vec<u8> {
    // Same wire shape as AddPartitionsToTxn's response body (throttle + topics[name, partitions[idx, error]]).
    add_partitions_response(correlation_id, topics, error_code)
}

/// Seal + store each produced partition batch BEFORE acking, returning `(base_offset, error_code)` per
/// `(topic, partition)`. A TRANSACTIONAL batch is FENCED against the coordinator (stale epoch / un-claimed
/// partition → rejected, never buffered) then BUFFERED until `EndTxn`; a plain/idempotent batch lands durably now.
fn produce_results<B: KafkaBroker>(
    broker: &B,
    txn: &TxnCoordinator,
    topics: &[crate::produce::ProducedTopic],
) -> HashMap<(String, i32), (i64, i16)> {
    let mut results: HashMap<(String, i32), (i64, i16)> = HashMap::new();
    for t in topics {
        for p in &t.partitions {
            // A batch rejected at PARSE time (today: CORRUPT_MESSAGE 2 on a v2 CRC mismatch) is NEVER landed —
            // skip the store entirely so no record from a corrupt batch is persisted. `produce_response` reports
            // the parse code directly (it reads `part.error_code` before consulting these results).
            if p.error_code.is_some() {
                continue;
            }
            let outcome = if let Some(eos) = p.eos.filter(|e| e.transactional) {
                let code =
                    txn.produce_check(eos.producer_id, eos.producer_epoch, &t.name, p.partition);
                if code == 0 {
                    match broker.buffer_txn(
                        eos.producer_id,
                        eos.producer_epoch,
                        &t.name,
                        p.partition,
                        &p.values,
                    ) {
                        Ok(base) => (base, 0i16),
                        Err(e) => (-1, produce_error_code(&t.name, p.partition, &e)),
                    }
                } else {
                    (-1, code)
                }
            } else {
                match broker.produce(&t.name, p.partition, &p.values) {
                    Ok(base) => (base, 0i16),
                    Err(e) => (-1, produce_error_code(&t.name, p.partition, &e)),
                }
            };
            results.insert((t.name.clone(), p.partition), outcome);
        }
    }
    results
}

/// Map a produce/buffer failure for `(topic, partition)` to its Kafka error code, and LOG the real error to
/// stderr (broker-side visibility — otherwise the detail is swallowed and a stuck producer looks silent).
///
/// - `InvalidData` ⇒ **87 = `INVALID_RECORD` (non-retriable)**: a PERMANENT rejection (e.g. a content-contract
///   violation — the record can never land). It MUST NOT be retried; a retriable code would make librdkafka
///   re-send the identical, still-rejected batch every ~100ms forever (a silent hot loop).
/// - anything else ⇒ **56 = `KAFKA_STORAGE_ERROR` (retriable)**: a transient store/seal failure, so the producer
///   retries rather than treating the records as durably stored — never a false NONE ack (audit A).
fn produce_error_code(topic: &str, partition: i32, e: &io::Error) -> i16 {
    if e.kind() == io::ErrorKind::InvalidData {
        eprintln!(
            "kafka: produce rejected (non-retriable) topic={topic} partition={partition} error={e}"
        );
        87
    } else if e.kind() == io::ErrorKind::InvalidInput {
        eprintln!(
            "kafka: produce rejected (message too large) topic={topic} partition={partition} error={e}"
        );
        10
    } else {
        eprintln!(
            "kafka: produce failed (retriable) topic={topic} partition={partition} error={e}"
        );
        56
    }
}

/// Resolve a parsed `Fetch` request against the broker: un-seal each partition's records at the edge into a v2
/// `RecordBatch` (or empty), carrying the high-watermark; a read/open error maps to `OFFSET_OUT_OF_RANGE` (1).
fn fetch_results<B: KafkaBroker>(
    broker: &B,
    topics: &[crate::consume::FetchTopic],
) -> Vec<FetchTopicResult> {
    let mut out = Vec::with_capacity(topics.len());
    for t in topics {
        let mut parts = Vec::with_capacity(t.partitions.len());
        for p in &t.partitions {
            let (_, latest) = broker.bounds(&t.name, p.partition);
            let (error_code, records) =
                match broker.fetch(&t.name, p.partition, p.fetch_offset, p.max_bytes) {
                    Ok(values) if values.is_empty() => (0, Vec::new()),
                    Ok(values) => (0, build_record_batch(p.fetch_offset, &values)),
                    // InvalidData = the store's record at this offset is unreadable (corruption) → CORRUPT_MESSAGE
                    // (2), so the consumer surfaces it instead of silently spinning; anything else keeps the
                    // OFFSET_OUT_OF_RANGE (1) mapping.
                    Err(e) => {
                        eprintln!(
                            "kafka: fetch failed topic={} partition={} offset={} error={e}",
                            t.name, p.partition, p.fetch_offset
                        );
                        (
                            if e.kind() == io::ErrorKind::InvalidData {
                                2
                            } else {
                                1
                            },
                            Vec::new(),
                        )
                    }
                };
            parts.push(FetchPartitionResult {
                partition: p.partition,
                error_code,
                high_watermark: latest,
                records,
            });
        }
        out.push(FetchTopicResult {
            name: t.name.clone(),
            partitions: parts,
        });
    }
    out
}

/// Durably commit a parsed `OffsetCommit` request, per `(topic, partition)`, BEFORE the response is sent. Each
/// partition carries its OWN error: 0 = NONE on a durable commit, else a retriable code (16) so the consumer
/// re-commits THAT partition — a failure on one never masks another's success, and never a false NONE.
fn offset_commit_results<B: KafkaBroker>(
    broker: &B,
    req: &crate::groups::OffsetCommitRequest,
) -> Vec<OffsetCommitTopicResult> {
    let mut out = Vec::with_capacity(req.topics.len());
    for t in &req.topics {
        let mut parts = Vec::with_capacity(t.partitions.len());
        for p in &t.partitions {
            let error_code =
                match broker.commit_offset(&req.group_id, &t.name, p.partition, p.offset) {
                    Ok(()) => 0,
                    Err(_) => 16, // COORDINATOR_NOT_AVAILABLE-class: retriable, never a false success
                };
            parts.push(OffsetCommitPartitionResult {
                partition: p.partition,
                error_code,
            });
        }
        out.push(OffsetCommitTopicResult {
            name: t.name.clone(),
            partitions: parts,
        });
    }
    out
}

/// Resolve a parsed `OffsetFetch` request against the broker's durable offset store. `-1` ("no committed offset",
/// the Kafka sentinel) on absence OR a store read error — the consumer then falls back to `auto.offset.reset`
/// rather than resuming at a wrong position.
fn offset_fetch_results<B: KafkaBroker>(
    broker: &B,
    req: &crate::groups::OffsetFetchRequest,
) -> Vec<OffsetFetchTopicResult> {
    let mut out = Vec::with_capacity(req.topics.len());
    for t in &req.topics {
        let mut parts = Vec::with_capacity(t.partitions.len());
        for &partition in &t.partitions {
            let offset = broker
                .fetch_offset(&req.group_id, &t.name, partition)
                .ok()
                .flatten()
                .unwrap_or(-1);
            parts.push(OffsetFetchPartitionResult { partition, offset });
        }
        out.push(OffsetFetchTopicResult {
            name: t.name.clone(),
            partitions: parts,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{produce_results, KafkaBroker};
    use crate::produce::{ProducedPartition, ProducedTopic};
    use crate::txn::TxnCoordinator;

    /// A minimal `KafkaBroker` whose `produce` always fails with a caller-chosen `io::Error`. Everything else is
    /// the trait default; only the produce error path is under test (the `(base, code)` mapping in `produce_results`).
    struct FailingBroker {
        kind: io::ErrorKind,
    }

    impl KafkaBroker for FailingBroker {
        fn produce(&self, _topic: &str, _partition: i32, _records: &[Vec<u8>]) -> io::Result<i64> {
            Err(io::Error::new(self.kind, "forced produce failure for test"))
        }
        fn fetch(
            &self,
            _topic: &str,
            _partition: i32,
            _offset: i64,
            _max_bytes: i32,
        ) -> io::Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }
        fn bounds(&self, _topic: &str, _partition: i32) -> (i64, i64) {
            (0, 0)
        }
    }

    /// A single non-transactional produced topic (one partition, one record) — the plain `produce` arm.
    fn one_partition_batch() -> Vec<ProducedTopic> {
        vec![ProducedTopic {
            name: "events".to_owned(),
            partitions: vec![ProducedPartition {
                partition: 0,
                values: vec![b"evt:x".to_vec()],
                eos: None,
                error_code: None,
            }],
        }]
    }

    /// A CONTRACT VIOLATION (surfaced as `InvalidData`) is a PERMANENT rejection → non-retriable `INVALID_RECORD`
    /// (87). Regression: a retriable code here makes librdkafka re-send the still-rejected batch forever.
    #[test]
    fn produce_invalid_data_maps_to_non_retriable_87() {
        let broker = FailingBroker {
            kind: io::ErrorKind::InvalidData,
        };
        let txn = TxnCoordinator::new(1000);
        let results = produce_results(&broker, &txn, &one_partition_batch());
        let (base, code) = results[&("events".to_owned(), 0)];
        assert_eq!(
            code, 87,
            "InvalidData must map to INVALID_RECORD (87, non-retriable)"
        );
        assert_eq!(base, -1, "a rejected batch reports no base offset");
    }

    /// A framing overflow is permanent → `MESSAGE_TOO_LARGE` (10), not retriable storage error 56.
    #[test]
    fn produce_invalid_input_maps_to_message_too_large_10() {
        let broker = FailingBroker {
            kind: io::ErrorKind::InvalidInput,
        };
        let txn = TxnCoordinator::new(1000);
        let results = produce_results(&broker, &txn, &one_partition_batch());
        let (base, code) = results[&("events".to_owned(), 0)];
        assert_eq!(code, 10, "InvalidInput must map to MESSAGE_TOO_LARGE (10)");
        assert_eq!(base, -1, "a rejected batch reports no base offset");
    }

    /// A transient store/seal failure (any non-`InvalidData` kind) → retriable `KAFKA_STORAGE_ERROR` (56): the
    /// producer retries rather than treating the records as durably stored (never a false ack). Locks in the
    /// retriable path so a future refactor cannot silently promote a transient failure to a permanent reject.
    #[test]
    fn produce_other_error_stays_retriable_56() {
        let broker = FailingBroker {
            kind: io::ErrorKind::Other,
        };
        let txn = TxnCoordinator::new(1000);
        let results = produce_results(&broker, &txn, &one_partition_batch());
        let (base, code) = results[&("events".to_owned(), 0)];
        assert_eq!(
            code, 56,
            "a non-InvalidData error stays KAFKA_STORAGE_ERROR (56, retriable)"
        );
        assert_eq!(base, -1, "a failed batch reports no base offset");
    }
}
