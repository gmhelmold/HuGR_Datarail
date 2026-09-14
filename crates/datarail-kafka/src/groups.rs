//! The consumer-group OFFSET side of the Kafka wire protocol: `FindCoordinator` (API 10), `OffsetCommit`
//! (API 8), and `OffsetFetch` (API 9). These let a consumer durably store its committed offset per
//! `(group, topic, partition)` broker-side, so its progress survives a restart (Kafka's `__consumer_offsets`).
//! See `KAFKA-GROUPS-DESIGN.md`. We target non-flexible encodings: `FindCoordinator` v0–v2, `OffsetCommit` v0–v2,
//! `OffsetFetch` v0–v2 (no KIP-482 tagged fields), advertised via `ApiVersions` so a client negotiates down.

use std::io;

use crate::codec::{write_response_header, Reader, Writer};

/// `OffsetCommit` API key.
pub const API_OFFSET_COMMIT: i16 = 8;
/// `OffsetFetch` API key.
pub const API_OFFSET_FETCH: i16 = 9;
/// `FindCoordinator` API key.
pub const API_FIND_COORDINATOR: i16 = 10;
/// `JoinGroup` API key.
pub const API_JOIN_GROUP: i16 = 11;
/// `Heartbeat` API key.
pub const API_HEARTBEAT: i16 = 12;
/// `LeaveGroup` API key.
pub const API_LEAVE_GROUP: i16 = 13;
/// `SyncGroup` API key.
pub const API_SYNC_GROUP: i16 = 14;

/// Smallest possible wire size of a topic array entry: a `string` length (2) + a partition-count `int32` (4).
const MIN_TOPIC_BYTES: usize = 6;
/// Smallest possible wire size of a partition array entry: at least the partition `int32` (4) read first.
const MIN_PARTITION_BYTES: usize = 4;

// ---- FindCoordinator (10) ----

/// Parse a `FindCoordinator` request body at `version`; returns the coordinator key (the group id). We answer
/// `self` regardless, but parsing keeps the frame consumed and validated.
///
/// # Errors
/// [`io::Error`] if the body is malformed / truncated.
pub fn parse_find_coordinator(reader: &mut Reader, version: i16) -> io::Result<String> {
    let key = reader.string()?;
    if version >= 1 {
        let _key_type = reader.int8()?;
    }
    Ok(key)
}

/// Build a `FindCoordinator` response naming THIS broker as the coordinator (single-node: node 0). `error_code`
/// is `NONE` (0). Version-gated: v1+ prepends `throttle_time_ms` and inserts a null `error_message`.
#[must_use]
pub fn find_coordinator_response(
    version: i16,
    correlation_id: i32,
    node_id: i32,
    host: &str,
    port: i32,
) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    if version >= 1 {
        w.int32(0); // throttle_time_ms
    }
    w.int16(0); // error_code = NONE
    if version >= 1 {
        w.nullable_string(None); // error_message
    }
    w.int32(node_id);
    w.string(host);
    w.int32(port);
    w.into_bytes()
}

// ---- OffsetCommit (8) ----

/// One partition's committed offset in an `OffsetCommit` request.
#[derive(Debug, Clone)]
pub struct OffsetCommitPartition {
    /// Partition index.
    pub partition: i32,
    /// The offset the consumer is committing (its next-to-read position).
    pub offset: i64,
}

/// A topic and the partitions a consumer is committing offsets for.
#[derive(Debug, Clone)]
pub struct OffsetCommitTopic {
    /// Topic name.
    pub name: String,
    /// Partitions committed.
    pub partitions: Vec<OffsetCommitPartition>,
}

/// A parsed `OffsetCommit` request: the consumer group and the per-topic/partition offsets to durably commit.
#[derive(Debug, Clone)]
pub struct OffsetCommitRequest {
    /// Consumer group id.
    pub group_id: String,
    /// Topics + partitions + offsets being committed.
    pub topics: Vec<OffsetCommitTopic>,
}

/// Parse an `OffsetCommit` request body at `version` (v0–v2). Version-gated fields (generation/member, retention,
/// the v1-only per-partition timestamp) are consumed but not used — we durably store only `(group → offset)`.
///
/// # Errors
/// [`io::Error`] if the body is malformed / truncated.
pub fn parse_offset_commit(reader: &mut Reader, version: i16) -> io::Result<OffsetCommitRequest> {
    let group_id = reader.string()?;
    if version >= 1 {
        let _generation_id = reader.int32()?;
        let _member_id = reader.string()?;
    }
    if version >= 2 {
        let _retention_time_ms = reader.int64()?;
    }
    let topic_count = reader.int32()?;
    let tc = reader.bounded_count(topic_count, MIN_TOPIC_BYTES);
    let mut topics = Vec::new();
    for _ in 0..tc {
        let name = reader.string()?;
        let part_count = reader.int32()?;
        let pc = reader.bounded_count(part_count, MIN_PARTITION_BYTES);
        let mut partitions = Vec::new();
        for _ in 0..pc {
            let partition = reader.int32()?;
            let offset = reader.int64()?;
            if version == 1 {
                let _timestamp = reader.int64()?;
            }
            let _metadata = reader.nullable_string()?;
            partitions.push(OffsetCommitPartition { partition, offset });
        }
        topics.push(OffsetCommitTopic { name, partitions });
    }
    Ok(OffsetCommitRequest { group_id, topics })
}

/// One partition's `OffsetCommit` outcome: its index and a PER-PARTITION `error_code` (0 = NONE on a durable
/// success, else a retriable code so the consumer re-commits that partition rather than assuming success).
#[derive(Debug, Clone)]
pub struct OffsetCommitPartitionResult {
    /// Partition index.
    pub partition: i32,
    /// Per-partition error code (0 = NONE).
    pub error_code: i16,
}

/// A topic's `OffsetCommit` outcomes.
#[derive(Debug, Clone)]
pub struct OffsetCommitTopicResult {
    /// Topic name.
    pub name: String,
    /// Per-partition outcomes.
    pub partitions: Vec<OffsetCommitPartitionResult>,
}

/// Build an `OffsetCommit` response mirroring the committed topics/partitions, each carrying its OWN `error_code`
/// (Kafka reports per-partition status — a failure on one partition must not mask another's success).
#[must_use]
pub fn offset_commit_response(correlation_id: i32, topics: &[OffsetCommitTopicResult]) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    w.int32(i32::try_from(topics.len()).unwrap_or(0));
    for t in topics {
        w.string(&t.name);
        w.int32(i32::try_from(t.partitions.len()).unwrap_or(0));
        for p in &t.partitions {
            w.int32(p.partition);
            w.int16(p.error_code);
        }
    }
    w.into_bytes()
}

// ---- OffsetFetch (9) ----

/// A topic and the partitions a consumer wants its committed offsets for.
#[derive(Debug, Clone)]
pub struct OffsetFetchTopic {
    /// Topic name.
    pub name: String,
    /// Partition indices requested.
    pub partitions: Vec<i32>,
}

/// A parsed `OffsetFetch` request: the consumer group and which topic/partitions to look up.
#[derive(Debug, Clone)]
pub struct OffsetFetchRequest {
    /// Consumer group id.
    pub group_id: String,
    /// Topics + partitions to fetch committed offsets for.
    pub topics: Vec<OffsetFetchTopic>,
}

/// Parse an `OffsetFetch` request body at `version` (v0–v2). A null topics array (v2+, count `< 0`) is treated as
/// "no explicit topics" (empty) — we do not enumerate all groups' topics in this increment.
///
/// # Errors
/// [`io::Error`] if the body is malformed / truncated.
pub fn parse_offset_fetch(reader: &mut Reader, _version: i16) -> io::Result<OffsetFetchRequest> {
    let group_id = reader.string()?;
    let topic_count = reader.int32()?;
    let tc = reader.bounded_count(topic_count, MIN_TOPIC_BYTES);
    let mut topics = Vec::new();
    for _ in 0..tc {
        let name = reader.string()?;
        let part_count = reader.int32()?;
        let pc = reader.bounded_count(part_count, MIN_PARTITION_BYTES);
        let mut partitions = Vec::new();
        for _ in 0..pc {
            partitions.push(reader.int32()?);
        }
        topics.push(OffsetFetchTopic { name, partitions });
    }
    Ok(OffsetFetchRequest { group_id, topics })
}

/// One partition's resolved committed offset (`offset` = `-1` for "no committed offset", Kafka's sentinel).
#[derive(Debug, Clone)]
pub struct OffsetFetchPartitionResult {
    /// Partition index.
    pub partition: i32,
    /// The last committed offset, or `-1` if none has ever been committed for this `(group, topic, partition)`.
    pub offset: i64,
}

/// A topic's resolved committed offsets.
#[derive(Debug, Clone)]
pub struct OffsetFetchTopicResult {
    /// Topic name.
    pub name: String,
    /// Per-partition resolved offsets.
    pub partitions: Vec<OffsetFetchPartitionResult>,
}

/// Build an `OffsetFetch` response at `version`. Each partition carries its committed offset (or `-1`), null
/// metadata, and `error_code` 0. v2+ appends a top-level `error_code` (0 = NONE).
#[must_use]
pub fn offset_fetch_response(
    version: i16,
    correlation_id: i32,
    topics: &[OffsetFetchTopicResult],
) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    w.int32(i32::try_from(topics.len()).unwrap_or(0));
    for t in topics {
        w.string(&t.name);
        w.int32(i32::try_from(t.partitions.len()).unwrap_or(0));
        for p in &t.partitions {
            w.int32(p.partition);
            w.int64(p.offset);
            w.nullable_string(None); // metadata
            w.int16(0); // partition error_code = NONE
        }
    }
    if version >= 2 {
        w.int16(0); // top-level error_code = NONE
    }
    w.into_bytes()
}

// ---- JoinGroup (11) ----

/// A `(protocol_name, metadata)` a member advertises in `JoinGroup`.
#[derive(Debug, Clone)]
pub struct JoinProtocol {
    /// Assignor protocol name (e.g. `range`).
    pub name: String,
    /// Opaque subscription metadata (consumed by the leader's assignor).
    pub metadata: Vec<u8>,
}

/// A parsed `JoinGroup` request (v1–v4; group-instance-id v5+ is out of scope).
#[derive(Debug, Clone)]
pub struct JoinGroupRequest {
    /// Consumer group id.
    pub group_id: String,
    /// Session timeout (ms) — liveness window.
    pub session_timeout_ms: i32,
    /// Rebalance timeout (ms) — how long the member will wait for the rebalance.
    pub rebalance_timeout_ms: i32,
    /// The member id (empty on a first join → the coordinator assigns one).
    pub member_id: String,
    /// `protocol_type` (e.g. `consumer`).
    pub protocol_type: String,
    /// The assignor protocols the member supports.
    pub protocols: Vec<JoinProtocol>,
}

/// Parse a `JoinGroup` request body at `version` (v1–v4).
///
/// # Errors
/// [`io::Error`] if malformed / truncated.
pub fn parse_join_group(reader: &mut Reader, version: i16) -> io::Result<JoinGroupRequest> {
    let group_id = reader.string()?;
    let session_timeout_ms = reader.int32()?;
    let rebalance_timeout_ms = if version >= 1 {
        reader.int32()?
    } else {
        session_timeout_ms
    };
    let member_id = reader.string()?;
    let protocol_type = reader.string()?;
    let proto_count = reader.int32()?;
    let pc = reader.bounded_count(proto_count, MIN_TOPIC_BYTES); // each ≥ name(2) + bytes-len(4)
    let mut protocols = Vec::new();
    for _ in 0..pc {
        let name = reader.string()?;
        let metadata = reader.bytes()?;
        protocols.push(JoinProtocol { name, metadata });
    }
    Ok(JoinGroupRequest {
        group_id,
        session_timeout_ms,
        rebalance_timeout_ms,
        member_id,
        protocol_type,
        protocols,
    })
}

/// The fields of a `JoinGroup` response (bundled so the builder stays within the argument cap).
#[derive(Debug, Clone)]
pub struct JoinGroupResponse {
    /// Error code (0 = NONE).
    pub error_code: i16,
    /// Assigned generation.
    pub generation: i32,
    /// Selected assignor protocol name.
    pub protocol: String,
    /// Leader member id.
    pub leader: String,
    /// This member's id.
    pub member_id: String,
    /// `(member_id, metadata)` for the LEADER; empty for followers.
    pub members: Vec<(String, Vec<u8>)>,
}

/// Build a `JoinGroup` response (v1–v4) from [`JoinGroupResponse`].
#[must_use]
pub fn join_group_response(version: i16, correlation_id: i32, r: &JoinGroupResponse) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    if version >= 2 {
        w.int32(0); // throttle_time_ms
    }
    w.int16(r.error_code);
    w.int32(r.generation);
    w.string(&r.protocol);
    w.string(&r.leader);
    w.string(&r.member_id);
    w.int32(i32::try_from(r.members.len()).unwrap_or(0));
    for (mid, meta) in &r.members {
        w.string(mid);
        w.bytes(meta);
    }
    w.into_bytes()
}

// ---- SyncGroup (14) ----

/// One member's assignment in a leader's `SyncGroup` request.
#[derive(Debug, Clone)]
pub struct SyncAssignment {
    /// The member to assign.
    pub member_id: String,
    /// Opaque assignment bytes (produced by the leader's assignor).
    pub assignment: Vec<u8>,
}

/// A parsed `SyncGroup` request (v0–v2; group-instance-id v3+ is out of scope).
#[derive(Debug, Clone)]
pub struct SyncGroupRequest {
    /// Consumer group id.
    pub group_id: String,
    /// The generation the member believes it is in.
    pub generation_id: i32,
    /// The member id.
    pub member_id: String,
    /// Assignments — non-empty only from the leader.
    pub assignments: Vec<SyncAssignment>,
}

/// Parse a `SyncGroup` request body at `version` (v0–v2).
///
/// # Errors
/// [`io::Error`] if malformed / truncated.
pub fn parse_sync_group(reader: &mut Reader, _version: i16) -> io::Result<SyncGroupRequest> {
    let group_id = reader.string()?;
    let generation_id = reader.int32()?;
    let member_id = reader.string()?;
    let count = reader.int32()?;
    let n = reader.bounded_count(count, MIN_TOPIC_BYTES); // each ≥ member-id(2) + bytes-len(4)
    let mut assignments = Vec::new();
    for _ in 0..n {
        let member_id = reader.string()?;
        let assignment = reader.bytes()?;
        assignments.push(SyncAssignment {
            member_id,
            assignment,
        });
    }
    Ok(SyncGroupRequest {
        group_id,
        generation_id,
        member_id,
        assignments,
    })
}

/// Build a `SyncGroup` response (v0–v2) carrying this member's assignment bytes.
#[must_use]
pub fn sync_group_response(
    version: i16,
    correlation_id: i32,
    error_code: i16,
    assignment: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    if version >= 1 {
        w.int32(0); // throttle_time_ms
    }
    w.int16(error_code);
    w.bytes(assignment);
    w.into_bytes()
}

// ---- Heartbeat (12) ----

/// A parsed `Heartbeat` request (v0–v2).
#[derive(Debug, Clone)]
pub struct HeartbeatRequest {
    /// Consumer group id.
    pub group_id: String,
    /// The member's generation.
    pub generation_id: i32,
    /// The member id.
    pub member_id: String,
}

/// Parse a `Heartbeat` request body at `version` (v0–v2).
///
/// # Errors
/// [`io::Error`] if malformed / truncated.
pub fn parse_heartbeat(reader: &mut Reader, _version: i16) -> io::Result<HeartbeatRequest> {
    let group_id = reader.string()?;
    let generation_id = reader.int32()?;
    let member_id = reader.string()?;
    Ok(HeartbeatRequest {
        group_id,
        generation_id,
        member_id,
    })
}

/// Build a `Heartbeat` response (v0–v2).
#[must_use]
pub fn heartbeat_response(version: i16, correlation_id: i32, error_code: i16) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    if version >= 1 {
        w.int32(0); // throttle_time_ms
    }
    w.int16(error_code);
    w.into_bytes()
}

// ---- LeaveGroup (12) ----

/// Parse a `LeaveGroup` request body at `version` (v0–v2): `(group_id, member_id)`.
///
/// # Errors
/// [`io::Error`] if malformed / truncated.
pub fn parse_leave_group(reader: &mut Reader, _version: i16) -> io::Result<(String, String)> {
    let group_id = reader.string()?;
    let member_id = reader.string()?;
    Ok((group_id, member_id))
}

/// Build a `LeaveGroup` response (v0–v2).
#[must_use]
pub fn leave_group_response(version: i16, correlation_id: i32, error_code: i16) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    if version >= 1 {
        w.int32(0); // throttle_time_ms
    }
    w.int16(error_code);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::{
        find_coordinator_response, offset_commit_response, offset_fetch_response,
        parse_find_coordinator, parse_offset_commit, parse_offset_fetch,
        OffsetCommitPartitionResult, OffsetCommitTopicResult, OffsetFetchPartitionResult,
        OffsetFetchTopicResult,
    };
    use crate::codec::{Reader, Writer};

    /// Build an `OffsetCommit` v2 request body (after the request header) for one topic/partition.
    fn commit_body(group: &str, topic: &str, partition: i32, offset: i64) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(group);
        w.int32(5); // generation_id (v1+)
        w.string("member-1"); // member_id (v1+)
        w.int64(-1); // retention_time_ms (v2+)
        w.int32(1); // 1 topic
        w.string(topic);
        w.int32(1); // 1 partition
        w.int32(partition);
        w.int64(offset);
        w.nullable_string(None); // metadata
        w.into_bytes()
    }

    #[test]
    fn offset_commit_v2_round_trips() {
        let body = commit_body("grp", "events", 0, 42);
        let mut r = Reader::new(&body);
        let req = parse_offset_commit(&mut r, 2).unwrap();
        assert_eq!(req.group_id, "grp");
        assert_eq!(req.topics.len(), 1);
        assert_eq!(req.topics[0].name, "events");
        assert_eq!(req.topics[0].partitions[0].partition, 0);
        assert_eq!(req.topics[0].partitions[0].offset, 42);
        // The response mirrors the topic/partition with a per-partition NONE error.
        let results = vec![OffsetCommitTopicResult {
            name: "events".to_owned(),
            partitions: vec![OffsetCommitPartitionResult {
                partition: 0,
                error_code: 0,
            }],
        }];
        let resp = offset_commit_response(7, &results);
        let mut rr = Reader::new(&resp);
        assert_eq!(rr.int32().unwrap(), 7, "correlation id echoed");
        assert_eq!(rr.int32().unwrap(), 1, "1 topic");
        assert_eq!(rr.string().unwrap(), "events");
        assert_eq!(rr.int32().unwrap(), 1, "1 partition");
        assert_eq!(rr.int32().unwrap(), 0, "partition 0");
        assert_eq!(rr.int16().unwrap(), 0, "error NONE");
    }

    #[test]
    fn offset_fetch_v2_round_trips_and_carries_offset() {
        let mut w = Writer::new();
        w.string("grp");
        w.int32(1);
        w.string("events");
        w.int32(1);
        w.int32(0);
        let body = w.into_bytes();
        let mut r = Reader::new(&body);
        let req = parse_offset_fetch(&mut r, 2).unwrap();
        assert_eq!(req.group_id, "grp");
        assert_eq!(req.topics[0].partitions, vec![0]);

        let results = vec![OffsetFetchTopicResult {
            name: "events".to_owned(),
            partitions: vec![OffsetFetchPartitionResult {
                partition: 0,
                offset: 42,
            }],
        }];
        let resp = offset_fetch_response(2, 9, &results);
        let mut rr = Reader::new(&resp);
        assert_eq!(rr.int32().unwrap(), 9);
        assert_eq!(rr.int32().unwrap(), 1);
        assert_eq!(rr.string().unwrap(), "events");
        assert_eq!(rr.int32().unwrap(), 1);
        assert_eq!(rr.int32().unwrap(), 0, "partition");
        assert_eq!(rr.int64().unwrap(), 42, "committed offset");
        assert_eq!(rr.nullable_string().unwrap(), None, "null metadata");
        assert_eq!(rr.int16().unwrap(), 0, "partition error NONE");
        assert_eq!(rr.int16().unwrap(), 0, "top-level error NONE (v2)");
    }

    #[test]
    fn find_coordinator_v1_answers_self() {
        let mut w = Writer::new();
        w.string("grp");
        w.int8(0); // key_type (v1+)
        let body = w.into_bytes();
        let mut r = Reader::new(&body);
        assert_eq!(parse_find_coordinator(&mut r, 1).unwrap(), "grp");

        let resp = find_coordinator_response(1, 3, 0, "broker.local", 9092);
        let mut rr = Reader::new(&resp);
        assert_eq!(rr.int32().unwrap(), 3, "correlation");
        assert_eq!(rr.int32().unwrap(), 0, "throttle (v1)");
        assert_eq!(rr.int16().unwrap(), 0, "error NONE");
        assert_eq!(
            rr.nullable_string().unwrap(),
            None,
            "error_message null (v1)"
        );
        assert_eq!(rr.int32().unwrap(), 0, "node 0 = self");
        assert_eq!(rr.string().unwrap(), "broker.local");
        assert_eq!(rr.int32().unwrap(), 9092);
    }

    #[test]
    fn malformed_offset_commit_does_not_panic_or_overalloc() {
        // A huge topic count followed by a LOT of filler must bound the materialized count to remaining /
        // min-entry, never `with_capacity(i32::MAX)` (which can even abort) nor build billions of structs.
        let mut w = Writer::new();
        w.string("grp");
        w.int32(5);
        w.string("member");
        w.int64(-1);
        w.int32(i32::MAX); // lying topic count
        w.raw(&vec![0u8; 64 * 1024]); // 64 KiB of zero filler (would-be entries)
        let body = w.into_bytes();
        let mut r = Reader::new(&body);
        // bounded_count caps topics at remaining / MIN_TOPIC_BYTES (≈ 10 K), and the Vec grows on demand — the
        // parse returns Ok/Err well within memory, never panics / aborts / over-allocs.
        let _ = parse_offset_commit(&mut r, 2);
    }
}
