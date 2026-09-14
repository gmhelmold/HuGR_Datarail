//! Kafka request handlers for the APIs a producer needs: `ApiVersions` (18), `Metadata` (3). The advertised
//! version ranges are chosen so a real client negotiates to encodings we implement cleanly; `ApiVersions` itself
//! must answer the client's first (highest) request, so both the classic (v0) and flexible (v3) response bodies
//! are produced. (The `ApiVersions` *response header* is always v0 — a KIP-482 special case.)

use std::io;

use crate::codec::{write_response_header, Reader, Writer};

/// Kafka API keys this broker speaks.
pub const API_PRODUCE: i16 = 0;
/// `Metadata` API key.
pub const API_METADATA: i16 = 3;
/// `ApiVersions` API key.
pub const API_VERSIONS: i16 = 18;
/// `InitProducerId` API key — a client enabling idempotence calls this first to obtain a `producer_id` before it
/// can stamp `(producer_id, base_sequence)` on its record batches (the basis for exactly-once ingest).
pub const API_INIT_PRODUCER_ID: i16 = 22;

/// One advertised API range.
struct ApiRange {
    key: i16,
    min: i16,
    max: i16,
}

/// What this broker supports. A client picks, for each API, a version in `[min, max]` it also supports.
/// `InitProducerId` is advertised at v0/v1 only (non-flexible) — enough for an idempotent (non-transactional)
/// producer. `Fetch`/`ListOffsets` are the CONSUME side (only the `kafka-broker` mode serves them; advertising
/// them is harmless for ingest-only producers). All are non-flexible versions (no KIP-482 tagged fields).
const SUPPORTED: [ApiRange; 19] = [
    ApiRange {
        key: API_PRODUCE,
        min: 0,
        max: 7,
    },
    ApiRange {
        key: crate::consume::API_FETCH,
        min: 0,
        max: 4,
    },
    ApiRange {
        key: crate::consume::API_LIST_OFFSETS,
        min: 0,
        max: 2,
    },
    ApiRange {
        key: API_METADATA,
        min: 0,
        max: 1,
    },
    ApiRange {
        key: API_VERSIONS,
        min: 0,
        max: 3,
    },
    ApiRange {
        key: API_INIT_PRODUCER_ID,
        min: 0,
        max: 1,
    },
    // Consumer-group OFFSET side (kafka-broker mode): durable committed offsets (`KAFKA-GROUPS-DESIGN.md`).
    ApiRange {
        key: crate::groups::API_OFFSET_COMMIT,
        min: 0,
        max: 2,
    },
    ApiRange {
        key: crate::groups::API_OFFSET_FETCH,
        min: 0,
        max: 2,
    },
    ApiRange {
        key: crate::groups::API_FIND_COORDINATOR,
        min: 0,
        max: 2,
    },
    // Consumer-group REBALANCE (kafka-broker mode): automatic assignment (`KAFKA-REBALANCE-DESIGN.md`).
    // Non-flexible version caps (group-instance-id / KIP-482 tagged fields are out of scope).
    ApiRange {
        key: crate::groups::API_JOIN_GROUP,
        min: 1,
        max: 4,
    },
    ApiRange {
        key: crate::groups::API_HEARTBEAT,
        min: 0,
        max: 2,
    },
    ApiRange {
        key: crate::groups::API_LEAVE_GROUP,
        min: 0,
        max: 2,
    },
    ApiRange {
        key: crate::groups::API_SYNC_GROUP,
        min: 0,
        max: 2,
    },
    // Transactional producer (kafka-broker mode): `KAFKA-TXN-DESIGN.md`. Non-flexible caps.
    ApiRange {
        key: crate::txn::API_ADD_PARTITIONS_TO_TXN,
        min: 0,
        max: 1,
    },
    ApiRange {
        key: crate::txn::API_ADD_OFFSETS_TO_TXN,
        min: 0,
        max: 1,
    },
    ApiRange {
        key: crate::txn::API_END_TXN,
        min: 0,
        max: 1,
    },
    ApiRange {
        key: crate::txn::API_TXN_OFFSET_COMMIT,
        min: 0,
        max: 1,
    },
    // SASL/PLAIN authentication (kafka-broker mode, `KAFKA-SASL-DESIGN.md`). Advertised so a SASL client negotiates;
    // only enforced when the broker is started with a credential.
    ApiRange {
        key: crate::sasl::API_SASL_HANDSHAKE,
        min: 0,
        max: 1,
    },
    ApiRange {
        key: crate::sasl::API_SASL_AUTHENTICATE,
        min: 0,
        max: 1,
    },
];

/// Build the full `InitProducerId` response (response header v0 + body v0) granting `producer_id` with epoch 0.
/// The producer then stamps this `producer_id` (and an incrementing `base_sequence`) on its idempotent batches.
#[must_use]
pub fn init_producer_id_response(correlation_id: i32, producer_id: i64) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false); // v0/v1 InitProducerId response header is v0
    w.int32(0); // throttle_time_ms
    w.int16(0); // error_code = NONE
    w.int64(producer_id);
    w.int16(0); // producer_epoch (fresh)
    w.into_bytes()
}

/// Build the full `ApiVersions` response (response header + body) for a request of `req_version`. The response
/// header is always v0; the body is flexible (compact + tagged fields) when `req_version >= 3`.
#[must_use]
pub fn api_versions_response(req_version: i16, correlation_id: i32) -> Vec<u8> {
    let flexible = req_version >= 3;
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false); // ApiVersions response header is ALWAYS v0
    w.int16(0); // error_code = NONE
    if flexible {
        // COMPACT_ARRAY: unsigned varint (len + 1)
        let n = u32::try_from(SUPPORTED.len()).unwrap_or(0);
        w.unsigned_varint(n + 1);
        for a in &SUPPORTED {
            w.int16(a.key);
            w.int16(a.min);
            w.int16(a.max);
            w.empty_tagged_fields(); // per-element tagged fields
        }
        w.int32(0); // throttle_time_ms
        w.empty_tagged_fields(); // top-level tagged fields
    } else {
        let n = i32::try_from(SUPPORTED.len()).unwrap_or(0);
        w.int32(n);
        for a in &SUPPORTED {
            w.int16(a.key);
            w.int16(a.min);
            w.int16(a.max);
        }
        if req_version >= 1 {
            w.int32(0); // throttle_time_ms (added in v1)
        }
    }
    w.into_bytes()
}

/// Parse the topic names a `Metadata` request asks about (v0/v1, non-flexible). A null/empty array means
/// "all topics"; we echo back whatever the client names (we are a single logical broker for any topic).
///
/// # Errors
/// [`io::Error`] if the request body is malformed.
pub fn parse_metadata_topics(reader: &mut Reader) -> io::Result<Vec<String>> {
    let count = reader.int32()?;
    if count <= 0 {
        return Ok(Vec::new()); // null (-1) or empty (0) ⇒ all topics
    }
    // Bound by remaining bytes (each topic name is ≥2 bytes) so a huge count can't drive an over-allocation.
    let n = usize::try_from(count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad topic count"))?
        .min(reader.remaining().len());
    let mut topics = Vec::with_capacity(n);
    for _ in 0..n {
        topics.push(reader.string()?);
    }
    Ok(topics)
}

/// Build the full `Metadata` response (response header v0 + body) for `req_version` (0 or 1). Advertises this
/// process as the single broker `node 0` at `host:port`, and each requested topic as `partitions` partitions
/// (indices `0..partitions`), all led by us. `partitions` is clamped to `>= 1`.
#[must_use]
pub fn metadata_response(
    req_version: i16,
    correlation_id: i32,
    host: &str,
    port: i32,
    topics: &[String],
    partitions: i32,
) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);

    // brokers: ARRAY of { node_id INT32, host STRING, port INT32, [rack NULLABLE_STRING (v1+)] }
    w.int32(1);
    w.int32(0); // node_id 0
    w.string(host);
    w.int32(port);
    if req_version >= 1 {
        w.nullable_string(None); // rack
    }

    if req_version >= 1 {
        w.int32(0); // controller_id = node 0
    }

    // topics: ARRAY of { error_code INT16, name STRING, [is_internal BOOL (v1+)], partitions ARRAY }
    let names: Vec<&String> = if topics.is_empty() {
        Vec::new()
    } else {
        topics.iter().collect()
    };
    let count = i32::try_from(names.len()).unwrap_or(0);
    w.int32(count);
    for name in names {
        w.int16(0); // error_code NONE
        w.string(name);
        if req_version >= 1 {
            w.int8(0); // is_internal = false
        }
        // partitions: ARRAY of { error_code INT16, partition INT32, leader INT32, replicas ARRAY<INT32>, isr ARRAY<INT32> }
        let n = partitions.max(1);
        w.int32(n);
        for p in 0..n {
            w.int16(0); // error_code
            w.int32(p); // partition_index
            w.int32(0); // leader = node 0
            w.int32(1);
            w.int32(0); // replicas = [0]
            w.int32(1);
            w.int32(0); // isr = [0]
        }
    }
    w.into_bytes()
}
