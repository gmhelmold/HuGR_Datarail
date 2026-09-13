//! CLI-owned broker dispatch. Keeps idempotent produce coordinates at the storage seam without changing the shared
//! wire crate's compatibility trait.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use datarail_kafka::codec::{Reader, Writer};
use datarail_kafka::consume::{
    fetch_response, list_offsets_response, parse_fetch, parse_list_offsets, FetchPartitionResult,
    FetchTopicResult, ListOffsetResult, ListOffsetTopicResult, API_FETCH, API_LIST_OFFSETS,
};
use datarail_kafka::coordinator::GroupCoordinator;
use datarail_kafka::groups::{
    find_coordinator_response, heartbeat_response, join_group_response, leave_group_response,
    offset_commit_response, offset_fetch_response, parse_find_coordinator, parse_heartbeat,
    parse_join_group, parse_leave_group, parse_offset_commit, parse_offset_fetch, parse_sync_group,
    sync_group_response, JoinGroupResponse, OffsetCommitPartitionResult, OffsetCommitTopicResult,
    OffsetFetchPartitionResult, OffsetFetchTopicResult, API_FIND_COORDINATOR, API_HEARTBEAT,
    API_JOIN_GROUP, API_LEAVE_GROUP, API_OFFSET_COMMIT, API_OFFSET_FETCH, API_SYNC_GROUP,
};
use datarail_kafka::handlers::{
    api_versions_response, init_producer_id_response, metadata_response, parse_metadata_topics,
    API_INIT_PRODUCER_ID, API_METADATA, API_PRODUCE, API_VERSIONS,
};
use datarail_kafka::produce::{
    build_record_batch, parse_produce, produce_response, ProducedRequest,
};
use datarail_kafka::serve::{ConnWrap, KafkaBroker, SaslCreds};
use datarail_kafka::txn::{
    add_partitions_response, init_producer_id_response as txn_init_producer_id_response,
    parse_add_offsets, parse_add_partitions, parse_end_txn, parse_init_producer_id,
    parse_txn_offset_commit, throttle_error_response, TxnCoordinator, API_ADD_OFFSETS_TO_TXN,
    API_ADD_PARTITIONS_TO_TXN, API_END_TXN, API_TXN_OFFSET_COMMIT,
};

pub(crate) use datarail_kafka::produce::EosCoord;

pub(crate) trait IdempotentBroker: KafkaBroker {
    fn produce_idempotent(
        &self,
        topic: &str,
        partition: i32,
        records: &[Vec<u8>],
        coord: EosCoord,
    ) -> io::Result<i64>;
}

struct BrokerContext<'a> {
    host: &'a str,
    port: i32,
    partitions: i32,
    next_producer_id: &'a AtomicI64,
    coordinator: &'a GroupCoordinator,
    txn: &'a TxnCoordinator,
}

const MAX_FRAME: usize = 16 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 256;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Serve broker APIs while retaining `EosCoord` for non-transactional idempotent produce.
pub(crate) fn serve_broker<B: IdempotentBroker + 'static>(
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
    let txn_coordinator = Arc::new(TxnCoordinator::new(1 << 40));
    let creds = creds.map(Arc::new);
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
        let coordinator = Arc::clone(&coordinator);
        let txn = Arc::clone(&txn_coordinator);
        let active = Arc::clone(&active);
        let conn_wrap = Arc::clone(conn_wrap);
        let creds = creds.clone();
        std::thread::spawn(move || {
            let context = BrokerContext {
                host: &host,
                port: advertised_port,
                partitions,
                next_producer_id: &pid,
                coordinator: &coordinator,
                txn: &txn,
            };
            if let Ok(mut stream) = conn_wrap.wrap(stream) {
                let _ =
                    handle_connection(&mut *stream, broker.as_ref(), &context, creds.as_deref());
            }
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

fn read_frame<R: Read + ?Sized>(stream: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let n = usize::try_from(i32::from_be_bytes(len))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative frame length"))?;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut frame = vec![0u8; n];
    stream.read_exact(&mut frame)?;
    Ok(Some(frame))
}

fn request_is_flexible(api_key: i16, version: i16) -> bool {
    match api_key {
        API_VERSIONS => version >= 3,
        API_METADATA | API_PRODUCE => version >= 9,
        _ => false,
    }
}

fn handle_connection<S: Read + Write + ?Sized, B: IdempotentBroker>(
    stream: &mut S,
    broker: &B,
    context: &BrokerContext<'_>,
    creds: Option<&SaslCreds>,
) -> io::Result<()> {
    let mut authenticated = creds.is_none();
    while let Some(frame) = read_frame(stream)? {
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
            SaslOutcome::Reply(response) => {
                stream.write_all(&Writer::frame(&response))?;
                stream.flush()?;
                continue;
            }
            SaslOutcome::CloseAfter(response) => {
                stream.write_all(&Writer::frame(&response))?;
                stream.flush()?;
                return Ok(());
            }
            SaslOutcome::Pass => {}
        }
        if !authenticated && api_key != API_VERSIONS {
            return Ok(());
        }
        let (response, suppress) = handle_request(
            api_key,
            api_version,
            correlation_id,
            &mut reader,
            broker,
            context,
        )?;
        if !suppress {
            stream.write_all(&Writer::frame(&response))?;
            stream.flush()?;
        }
    }
    Ok(())
}

fn handle_request<B: IdempotentBroker>(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    reader: &mut Reader<'_>,
    broker: &B,
    context: &BrokerContext<'_>,
) -> io::Result<(Vec<u8>, bool)> {
    let mut suppress = false;
    let response = match api_key {
        API_VERSIONS => api_versions_response(api_version, correlation_id),
        API_METADATA => metadata_response(
            api_version,
            correlation_id,
            context.host,
            context.port,
            &parse_metadata_topics(reader)?,
            context.partitions,
        ),
        API_INIT_PRODUCER_ID => {
            if let Some(tid) = parse_init_producer_id(reader)? {
                let (pid, epoch) = context.txn.init_producer_id(&tid);
                broker.abort_txn(pid, epoch, &[]);
                txn_init_producer_id_response(correlation_id, pid, epoch)
            } else {
                init_producer_id_response(
                    correlation_id,
                    context.next_producer_id.fetch_add(1, Ordering::Relaxed),
                )
            }
        }
        API_PRODUCE => {
            let ProducedRequest { acks, topics } = parse_produce(reader, api_version)?;
            let results = produce_results(broker, context.txn, &topics);
            suppress = acks == 0;
            produce_response(
                api_version,
                correlation_id,
                &topics,
                &mut |name, partition, _| {
                    results
                        .get(&(name.to_owned(), partition))
                        .copied()
                        .unwrap_or((0, 0))
                },
            )
        }
        API_FETCH => fetch_response(
            api_version,
            correlation_id,
            &fetch_results(broker, &parse_fetch(reader, api_version)?),
        ),
        API_LIST_OFFSETS => handle_list_offsets(reader, api_version, correlation_id, broker)?,
        API_FIND_COORDINATOR => {
            let _ = parse_find_coordinator(reader, api_version)?;
            find_coordinator_response(api_version, correlation_id, 0, context.host, context.port)
        }
        API_OFFSET_COMMIT => {
            let req = parse_offset_commit(reader, api_version)?;
            offset_commit_response(correlation_id, &offset_commit_results(broker, &req))
        }
        API_OFFSET_FETCH => {
            let req = parse_offset_fetch(reader, api_version)?;
            offset_fetch_response(
                api_version,
                correlation_id,
                &offset_fetch_results(broker, &req),
            )
        }
        other => {
            if let Some(response) = dispatch_group(
                other,
                api_version,
                correlation_id,
                reader,
                context.coordinator,
            )? {
                response
            } else if let Some(response) = dispatch_txn(
                other,
                api_version,
                correlation_id,
                reader,
                context.txn,
                broker,
            )? {
                response
            } else {
                return Err(io::Error::other(format!(
                    "unsupported Kafka api_key {other}"
                )));
            }
        }
    };
    Ok((response, suppress))
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
                .map(|part| {
                    let (earliest, latest) = broker.bounds(&topic.name, part.partition);
                    ListOffsetResult {
                        partition: part.partition,
                        offset: if part.timestamp == -2 {
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

enum SaslOutcome {
    Reply(Vec<u8>),
    CloseAfter(Vec<u8>),
    Pass,
}

fn handle_sasl(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    reader: &mut Reader<'_>,
    creds: Option<&SaslCreds>,
    authenticated: &mut bool,
) -> io::Result<SaslOutcome> {
    if api_key == datarail_kafka::sasl::API_SASL_HANDSHAKE {
        let mechanism = datarail_kafka::sasl::parse_sasl_handshake(reader)?;
        let code = if mechanism == datarail_kafka::sasl::PLAIN {
            0
        } else {
            datarail_kafka::sasl::UNSUPPORTED_SASL_MECHANISM
        };
        return Ok(SaslOutcome::Reply(
            datarail_kafka::sasl::sasl_handshake_response(
                correlation_id,
                code,
                &[datarail_kafka::sasl::PLAIN],
            ),
        ));
    }
    if api_key == datarail_kafka::sasl::API_SASL_AUTHENTICATE {
        let token = datarail_kafka::sasl::parse_sasl_authenticate(reader, api_version)?;
        let ok = creds.is_none_or(|creds| {
            datarail_kafka::sasl::verify_plain(&token, &creds.user, &creds.pass)
        });
        let response = |code, message| {
            datarail_kafka::sasl::sasl_authenticate_response(
                correlation_id,
                api_version,
                code,
                message,
                &[],
                0,
            )
        };
        if ok {
            *authenticated = true;
            return Ok(SaslOutcome::Reply(response(0, None)));
        }
        return Ok(SaslOutcome::CloseAfter(response(
            datarail_kafka::sasl::SASL_AUTHENTICATION_FAILED,
            Some("authentication failed"),
        )));
    }
    Ok(SaslOutcome::Pass)
}

fn produce_results<B: IdempotentBroker>(
    broker: &B,
    txn: &TxnCoordinator,
    topics: &[datarail_kafka::produce::ProducedTopic],
) -> HashMap<(String, i32), (i64, i16)> {
    let mut results = HashMap::new();
    for topic in topics {
        for part in &topic.partitions {
            if part.error_code.is_some() {
                continue;
            }
            let outcome = if let Some(eos) = part.eos.filter(|eos| eos.transactional) {
                let code = txn.produce_check(
                    eos.producer_id,
                    eos.producer_epoch,
                    &topic.name,
                    part.partition,
                );
                if code == 0 {
                    match broker.buffer_txn(
                        eos.producer_id,
                        eos.producer_epoch,
                        &topic.name,
                        part.partition,
                        &part.values,
                    ) {
                        Ok(base) => (base, 0),
                        Err(error) => (-1, produce_error_code(&topic.name, part.partition, &error)),
                    }
                } else {
                    (-1, code)
                }
            } else if let Some(eos) = part.eos {
                match broker.produce_idempotent(&topic.name, part.partition, &part.values, eos) {
                    Ok(base) => (base, 0),
                    Err(error) => (-1, produce_error_code(&topic.name, part.partition, &error)),
                }
            } else {
                match broker.produce(&topic.name, part.partition, &part.values) {
                    Ok(base) => (base, 0),
                    Err(error) => (-1, produce_error_code(&topic.name, part.partition, &error)),
                }
            };
            results.insert((topic.name.clone(), part.partition), outcome);
        }
    }
    results
}

fn produce_error_code(topic: &str, partition: i32, error: &io::Error) -> i16 {
    let (code, label) = match error.kind() {
        io::ErrorKind::InvalidData => (87, "rejected (non-retriable)"),
        io::ErrorKind::InvalidInput => (10, "rejected (message too large)"),
        _ => (56, "failed (retriable)"),
    };
    eprintln!("kafka: produce {label} topic={topic} partition={partition} error={error}");
    code
}

fn fetch_results<B: KafkaBroker>(
    broker: &B,
    topics: &[datarail_kafka::consume::FetchTopic],
) -> Vec<FetchTopicResult> {
    topics
        .iter()
        .map(|topic| FetchTopicResult {
            name: topic.name.clone(),
            partitions: topic
                .partitions
                .iter()
                .map(|part| {
                    let (_, latest) = broker.bounds(&topic.name, part.partition);
                    let (error_code, records) = match broker.fetch(
                        &topic.name,
                        part.partition,
                        part.fetch_offset,
                        part.max_bytes,
                    ) {
                        Ok(values) if values.is_empty() => (0, Vec::new()),
                        Ok(values) => (0, build_record_batch(part.fetch_offset, &values)),
                        Err(error) => (
                            if error.kind() == io::ErrorKind::InvalidData {
                                2
                            } else {
                                1
                            },
                            Vec::new(),
                        ),
                    };
                    FetchPartitionResult {
                        partition: part.partition,
                        error_code,
                        high_watermark: latest,
                        records,
                    }
                })
                .collect(),
        })
        .collect()
}

fn dispatch_group(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    reader: &mut Reader<'_>,
    coordinator: &GroupCoordinator,
) -> io::Result<Option<Vec<u8>>> {
    let response = match api_key {
        API_JOIN_GROUP => {
            let req = parse_join_group(reader, api_version)?;
            let protocols: Vec<(String, Vec<u8>)> = req
                .protocols
                .into_iter()
                .map(|p| (p.name, p.metadata))
                .collect();
            let out = coordinator.join(
                &req.group_id,
                &req.member_id,
                req.session_timeout_ms,
                req.rebalance_timeout_ms,
                &req.protocol_type,
                &protocols,
            );
            Some(join_group_response(
                api_version,
                correlation_id,
                &JoinGroupResponse {
                    error_code: out.error_code,
                    generation: out.generation,
                    protocol: out.protocol,
                    leader: out.leader,
                    member_id: out.member_id,
                    members: out.members,
                },
            ))
        }
        API_SYNC_GROUP => {
            let req = parse_sync_group(reader, api_version)?;
            let assignments: Vec<(String, Vec<u8>)> = req
                .assignments
                .into_iter()
                .map(|a| (a.member_id, a.assignment))
                .collect();
            let out = coordinator.sync(
                &req.group_id,
                &req.member_id,
                req.generation_id,
                &assignments,
            );
            Some(sync_group_response(
                api_version,
                correlation_id,
                out.error_code,
                &out.assignment,
            ))
        }
        API_HEARTBEAT => {
            let req = parse_heartbeat(reader, api_version)?;
            Some(heartbeat_response(
                api_version,
                correlation_id,
                coordinator.heartbeat(&req.group_id, &req.member_id, req.generation_id),
            ))
        }
        API_LEAVE_GROUP => {
            let (group, member) = parse_leave_group(reader, api_version)?;
            Some(leave_group_response(
                api_version,
                correlation_id,
                coordinator.leave(&group, &member),
            ))
        }
        _ => None,
    };
    Ok(response)
}

fn dispatch_txn<B: KafkaBroker>(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    reader: &mut Reader<'_>,
    txn: &TxnCoordinator,
    broker: &B,
) -> io::Result<Option<Vec<u8>>> {
    let response = match api_key {
        API_ADD_PARTITIONS_TO_TXN => {
            let req = parse_add_partitions(reader, api_version)?;
            let parts: Vec<(String, i32)> = req
                .topics
                .iter()
                .flat_map(|(topic, partitions)| {
                    partitions
                        .iter()
                        .map(move |&partition| (topic.clone(), partition))
                })
                .collect();
            Some(add_partitions_response(
                correlation_id,
                &req.topics,
                txn.add_partitions(&req.transactional_id, req.producer_id, req.epoch, &parts),
            ))
        }
        API_ADD_OFFSETS_TO_TXN => {
            let (tid, pid, epoch, group) = parse_add_offsets(reader, api_version)?;
            Some(throttle_error_response(
                correlation_id,
                txn.add_offsets(&tid, pid, epoch, &group),
            ))
        }
        API_TXN_OFFSET_COMMIT => {
            let req = parse_txn_offset_commit(reader, api_version)?;
            let code = txn.stage_offsets(
                &req.transactional_id,
                req.producer_id,
                req.epoch,
                &req.offsets,
            );
            Some(add_partitions_response(correlation_id, &req.topics, code))
        }
        API_END_TXN => {
            let (tid, pid, epoch, committed) = parse_end_txn(reader, api_version)?;
            let out = txn.end_txn(&tid, pid, epoch, committed);
            let code = if out.error_code != 0 {
                out.error_code
            } else if out.committed {
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
                broker.abort_txn(pid, epoch, &out.partitions);
                txn.finish_txn(&tid, pid, epoch);
                0
            };
            Some(throttle_error_response(correlation_id, code))
        }
        _ => None,
    };
    Ok(response)
}

fn offset_commit_results<B: KafkaBroker>(
    broker: &B,
    req: &datarail_kafka::groups::OffsetCommitRequest,
) -> Vec<OffsetCommitTopicResult> {
    req.topics
        .iter()
        .map(|topic| OffsetCommitTopicResult {
            name: topic.name.clone(),
            partitions: topic
                .partitions
                .iter()
                .map(|part| OffsetCommitPartitionResult {
                    partition: part.partition,
                    error_code: if broker
                        .commit_offset(&req.group_id, &topic.name, part.partition, part.offset)
                        .is_ok()
                    {
                        0
                    } else {
                        16
                    },
                })
                .collect(),
        })
        .collect()
}

fn offset_fetch_results<B: KafkaBroker>(
    broker: &B,
    req: &datarail_kafka::groups::OffsetFetchRequest,
) -> Vec<OffsetFetchTopicResult> {
    req.topics
        .iter()
        .map(|topic| OffsetFetchTopicResult {
            name: topic.name.clone(),
            partitions: topic
                .partitions
                .iter()
                .map(|&partition| OffsetFetchPartitionResult {
                    partition,
                    offset: broker
                        .fetch_offset(&req.group_id, &topic.name, partition)
                        .ok()
                        .flatten()
                        .unwrap_or(-1),
                })
                .collect(),
        })
        .collect()
}
