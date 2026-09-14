//! The `Produce` (API 0) request: parse the request envelope + the v2 `RecordBatch` blob, extract each record's
//! value bytes (the payload a datarail terminal will seal), and build the response. Compressed batches are
//! decompressed when the `compression` feature is on (`KAFKA-COMPRESSION-DESIGN.md`); otherwise a clear error.

use std::io;

use crate::codec::{write_response_header, Reader, Writer};

/// Cap on a single batch's DECOMPRESSED records size (a zip-bomb guard: a small compressed batch from an untrusted
/// producer cannot expand to exhaust memory). Matches the serve-layer max frame.
#[cfg(feature = "compression")]
const MAX_DECOMPRESSED: usize = 16 * 1024 * 1024;

/// The idempotent-producer identity of a single v2 `RecordBatch` — the stable, retry-invariant coordinate
/// datarail keys exactly-once on (see `KAFKA-EOS-DESIGN.md`). Present only for a SINGLE idempotent v2 batch
/// (`producer_id >= 0`); absent for legacy / multi-batch / non-idempotent producers (→ at-least-once).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EosCoord {
    /// The broker-assigned idempotent producer id (stable across retries within a producer session).
    pub producer_id: i64,
    /// The producer epoch (bumped on producer restart / fencing).
    pub producer_epoch: i16,
    /// The sequence of this batch's first record.
    pub base_sequence: i32,
    /// The number of records in the batch — the range is `[base_sequence, base_sequence + count)`.
    pub count: i32,
    /// Whether the batch is TRANSACTIONAL (v2 attributes bit `0x10`) — its records are buffered until `EndTxn`
    /// (`KAFKA-TXN-DESIGN.md`), not visible until commit.
    pub transactional: bool,
}

/// The result of parsing a partition's records blob: the extracted value payloads, plus the exactly-once
/// coordinate when the blob is a single idempotent v2 batch.
#[derive(Debug, Clone)]
pub struct ParsedRecords {
    /// Record value payloads, in order (null-value records are skipped, but still consume a sequence).
    pub values: Vec<Vec<u8>>,
    /// The exactly-once coordinate, or `None` if this blob is not EOS-eligible (legacy / multi-batch / non-idempotent).
    pub eos: Option<EosCoord>,
}

/// Why parsing a partition's records blob failed. The two kinds are handled DIFFERENTLY by the caller:
/// - [`ParseError::Corrupt`] — a v2 `RecordBatch` whose CRC-32C did not match: the data is corrupt on the wire.
///   This is a PER-PARTITION failure (Kafka `CORRUPT_MESSAGE`, error code 2) — no record from the batch is
///   stored, but the connection keeps serving and other partitions are unaffected.
/// - [`ParseError::Malformed`] — the blob is structurally broken (truncated, bad magic, over-long length): the
///   frame cannot be trusted at all, so the caller propagates it and closes the connection (today's behavior).
#[derive(Debug)]
pub enum ParseError {
    /// A v2 batch CRC-32C mismatch — reject the batch with `CORRUPT_MESSAGE` (2), keep the connection alive.
    Corrupt,
    /// A structurally malformed blob — propagate as an [`io::Error`] and close the connection.
    Malformed(io::Error),
}

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        ParseError::Malformed(e)
    }
}

/// A produced partition: its index, the record VALUES extracted from the batch, and (when present) the
/// idempotent-producer EOS coordinate for exactly-once dedup.
#[derive(Debug, Clone)]
pub struct ProducedPartition {
    /// Partition index.
    pub partition: i32,
    /// Record value payloads, in order.
    pub values: Vec<Vec<u8>>,
    /// The idempotent-producer EOS coordinate, if this partition carried a single idempotent v2 batch.
    pub eos: Option<EosCoord>,
    /// A NON-ZERO Kafka error code set at PARSE time for THIS partition alone (`None` ⇒ the batch parsed
    /// cleanly). Today this is `Some(2)` = `CORRUPT_MESSAGE` when the v2 `RecordBatch` CRC-32C fails: the batch
    /// is rejected without storing any record, but only THAT partition errors — the connection keeps serving and
    /// other partitions/topics in the same request are unaffected.
    pub error_code: Option<i16>,
}

/// A produced topic: its name and the partitions in this request.
#[derive(Debug, Clone)]
pub struct ProducedTopic {
    /// Topic name.
    pub name: String,
    /// Partitions produced to.
    pub partitions: Vec<ProducedPartition>,
}

/// A parsed `Produce` request: the `acks` setting plus the produced topics. `acks == 0` is a FIRE-AND-FORGET
/// produce — Kafka semantics require the broker to write **no response frame** at all (a response would
/// desynchronize the client's correlation-id stream). The records are still landed durably; only the response
/// is suppressed. `acks == 1` (leader) / `-1` (all) get a normal response.
#[derive(Debug, Clone)]
pub struct ProducedRequest {
    /// The producer's `acks` setting: `0` = no response expected, `1` = leader ack, `-1` = all-replica ack.
    pub acks: i16,
    /// The topics (and their partitions) produced in this request.
    pub topics: Vec<ProducedTopic>,
}

/// Take a varint-length-prefixed byte run from `reader` (`-1` ⇒ `None`/absent), returning the bytes.
fn take_varint_bytes(reader: &mut Reader) -> io::Result<Option<Vec<u8>>> {
    let len = reader.varint()?;
    if len < 0 {
        return Ok(None);
    }
    let n = usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad varint length"))?;
    Ok(Some(reader.take(n)?.to_vec()))
}

/// CRC-32C (Castagnoli, reflected) — the checksum a Kafka v2 `RecordBatch` carries and that real consumers
/// VALIDATE on `Fetch`. Hand-rolled (zero-dep, like the `MD5` in the Postgres sink). Bitwise reflected form with
/// polynomial `0x82F6_3B78` (the reflection of `0x1EDC_6F41`).
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Build one uncompressed v2 `RecordBatch` (non-idempotent: `producer_id = -1`) carrying `values`, with a CORRECT
/// `CRC-32C` so a real Kafka consumer accepts it on `Fetch`. `base_offset` is the logical offset of the first
/// record. Null keys, no headers, `CreateTime` timestamps 0 (informational). The inverse of [`parse_record_batch`].
#[must_use]
pub fn build_record_batch(base_offset: i64, values: &[Vec<u8>]) -> Vec<u8> {
    let mut recs = Writer::new();
    for (i, v) in values.iter().enumerate() {
        let mut r = Writer::new();
        r.int8(0); // attributes
        r.varlong(0); // timestamp delta
        r.varint(i32::try_from(i).unwrap_or(i32::MAX)); // offset delta
        r.varint(-1); // null key
        r.varint(i32::try_from(v.len()).unwrap_or(i32::MAX));
        r.raw(v);
        r.varint(0); // header count
        let body = r.into_bytes();
        recs.varint(i32::try_from(body.len()).unwrap_or(i32::MAX));
        recs.raw(&body);
    }
    let records = recs.into_bytes();

    // Everything the CRC covers: from `attributes` to the end of the records.
    let mut after_crc = Writer::new();
    after_crc.int16(0); // attributes (uncompressed, CreateTime)
    after_crc.int32(i32::try_from(values.len().saturating_sub(1)).unwrap_or(i32::MAX)); // last_offset_delta
    after_crc.int64(0); // base_timestamp
    after_crc.int64(0); // max_timestamp
    after_crc.int64(-1); // producer_id (non-idempotent)
    after_crc.int16(-1); // producer_epoch
    after_crc.int32(-1); // base_sequence
    after_crc.int32(i32::try_from(values.len()).unwrap_or(i32::MAX)); // record count
    after_crc.raw(&records);
    let after = after_crc.into_bytes();
    let crc = crc32c(&after);

    // partition_leader_epoch + magic + crc + (attributes..records) = the batch length covers all of this.
    let mut tail = Writer::new();
    tail.int32(-1); // partition_leader_epoch
    tail.int8(2); // magic
    tail.uint32(crc);
    tail.raw(&after);
    let tail_bytes = tail.into_bytes();

    let mut full = Writer::new();
    full.int64(base_offset);
    full.int32(i32::try_from(tail_bytes.len()).unwrap_or(i32::MAX)); // batch_length
    full.raw(&tail_bytes);
    full.into_bytes()
}

/// Parse a producer's records blob into the record VALUE payloads. Handles BOTH the v2 `RecordBatch` (magic 2,
/// modern clients) and the legacy `MessageSet` (magic 0/1, older clients and some librdkafka fallbacks) — they
/// share a layout up to the magic byte at offset 16 (`int64`, `int32`, 4 bytes, then magic), so we read that far
/// and dispatch. Uncompressed only unless the `compression` feature is on. Every v2 batch's CRC-32C is validated
/// (over the wire bytes `attributes..end`, before any decompression); a mismatch is a [`ParseError::Corrupt`].
///
/// # Errors
/// [`ParseError::Corrupt`] on a v2 CRC mismatch (reject the batch, keep serving); [`ParseError::Malformed`] on a
/// structurally broken blob, an unsupported magic byte, or a compressed entry with the feature off.
pub fn parse_record_batch(blob: &[u8]) -> Result<ParsedRecords, ParseError> {
    let mut reader = Reader::new(blob);
    let mut values = Vec::new();
    let mut batches = 0u32;
    let mut first_coord: Option<EosCoord> = None;
    while !reader.is_empty() {
        let _offset = reader.int64()?; // baseOffset (v2) / offset (legacy)
        let length = reader.int32()?; // batchLength (v2) / messageSize (legacy)
                                      // batchLength counts from HERE (partitionLeaderEpoch) to the end of the batch's records.
        let batch_end = reader
            .position()
            .saturating_add(usize::try_from(length).unwrap_or(0));
        let _crc_or_epoch = reader.uint32()?; // partitionLeaderEpoch (v2) / crc (legacy)
        let magic = reader.int8()?;
        match magic {
            2 => {
                let coord = parse_v2_records(blob, &mut reader, batch_end, &mut values)?;
                if batches == 0 {
                    first_coord = coord;
                }
            }
            0 | 1 => parse_legacy_message(&mut reader, magic, &mut values)?,
            other => {
                return Err(ParseError::Malformed(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported record magic {other}"),
                )));
            }
        }
        batches += 1;
    }
    // Exactly-once is keyed on a SINGLE idempotent v2 batch's stable sequence range. A multi-batch blob, a legacy
    // MessageSet, or a non-idempotent batch (producer_id < 0) has no such stable identity → not EOS-eligible.
    let eos = if batches == 1 { first_coord } else { None };
    Ok(ParsedRecords { values, eos })
}

/// Parse the v2 `RecordBatch` fields after the magic byte, pushing each record's value. Returns the
/// idempotent-producer [`EosCoord`] when the batch carries one (`producer_id >= 0` and `base_sequence >= 0`).
///
/// VALIDATES the batch's `CRC-32C` before touching any record: the v2 CRC covers the WIRE bytes from `attributes`
/// (the byte right after the 4-byte crc field) to the end of the batch (`batch_end`) — for a COMPRESSED batch
/// that is the compressed records blob, so the check runs BEFORE decompression, exactly as a real broker does.
/// On mismatch we reject with `CORRUPT_MESSAGE` semantics (error code 2 at the produce layer): an `InvalidData`
/// error, so no record from a corrupt batch is ever stored. `blob` is the full partition records blob (the CRC
/// range is sliced from it by absolute position).
fn parse_v2_records(
    blob: &[u8],
    reader: &mut Reader,
    batch_end: usize,
    values: &mut Vec<Vec<u8>>,
) -> Result<Option<EosCoord>, ParseError> {
    let stored_crc = reader.uint32()?;
    // The CRC covers `attributes..batch_end`: `attributes` starts at the current cursor (right after the crc
    // field), and `batch_end` is the batch's end computed by the caller from `batchLength`. Both are absolute
    // positions into `blob`. A malformed `batch_end` (past the buffer) is clamped so the slice never panics.
    let crc_start = reader.position();
    let crc_end = batch_end.min(blob.len());
    let covered = blob.get(crc_start..crc_end).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "record batch length runs past the buffer",
        )
    })?;
    let computed = crc32c(covered);
    if computed != stored_crc {
        // CORRUPT_MESSAGE (Kafka error code 2): the batch is corrupt on the wire. Fail the whole batch — no
        // record from it is parsed or stored — and surface the mismatch on stderr for broker-side visibility.
        // Validated over the WIRE bytes (still compressed for a compressed batch) BEFORE any decompression.
        eprintln!("kafka: produce record batch CRC mismatch (corrupt): stored={stored_crc:#010x} computed={computed:#010x}");
        return Err(ParseError::Corrupt);
    }
    let attributes = reader.int16()?;
    let codec = u8::try_from(attributes & 0x07).unwrap_or(0); // bits 0-2: 0=none, 1=gzip, 2=snappy, 3=lz4, 4=zstd
    let transactional = attributes & 0x10 != 0; // v2 attributes bit 4 = transactional batch
    let _last_offset_delta = reader.int32()?;
    let _base_timestamp = reader.int64()?;
    let _max_timestamp = reader.int64()?;
    let producer_id = reader.int64()?;
    let producer_epoch = reader.int16()?;
    let base_sequence = reader.int32()?;
    let record_count = reader.int32()?;
    let n = usize::try_from(record_count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad record count"))?;
    if codec == 0 {
        // Uncompressed: the records follow inline; the varint-framed loop self-terminates after `n` records.
        parse_records_into(reader, n, values)?;
    } else {
        // Compressed: the records section (from here to batch_end) is one compressed blob. Decompress it
        // (feature-gated, bounded) and parse the records from the decompressed bytes.
        #[cfg(feature = "compression")]
        {
            let blob_len = batch_end.saturating_sub(reader.position());
            let blob = reader.take(blob_len)?;
            let decompressed = crate::compress::decompress(codec, blob, MAX_DECOMPRESSED)?;
            let mut inner = Reader::new(&decompressed);
            parse_records_into(&mut inner, n, values)?;
        }
        #[cfg(not(feature = "compression"))]
        {
            let _ = batch_end;
            return Err(ParseError::Malformed(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed batches not supported",
            )));
        }
    }
    // An idempotent producer stamps producer_id >= 0 + a real base_sequence; a non-idempotent one sends -1.
    let eos = (producer_id >= 0 && base_sequence >= 0).then_some(EosCoord {
        producer_id,
        producer_epoch,
        base_sequence,
        count: record_count,
        transactional,
    });
    Ok(eos)
}

/// Parse `n` v2 records (varint-framed) from `reader`, pushing each non-null value. Shared by the uncompressed
/// path (reads inline) and the compressed path (reads from the decompressed blob).
fn parse_records_into(reader: &mut Reader, n: usize, values: &mut Vec<Vec<u8>>) -> io::Result<()> {
    for _ in 0..n {
        let _length = reader.varint()?;
        let _attributes = reader.int8()?;
        let _timestamp_delta = reader.varlong()?;
        let _offset_delta = reader.varint()?;
        let _key = take_varint_bytes(reader)?;
        if let Some(value) = take_varint_bytes(reader)? {
            values.push(value);
        }
        let header_count = reader.varint()?;
        let hc = usize::try_from(header_count.max(0)).unwrap_or(0);
        for _ in 0..hc {
            let _hk = take_varint_bytes(reader)?;
            let _hv = take_varint_bytes(reader)?;
        }
    }
    Ok(())
}

/// Parse one legacy `MessageSet` message (magic 0/1) after the magic byte, pushing its value. The crc and the
/// preceding `int64` offset + `int32` size were already consumed by the caller; key/value are classic `INT32`-
/// length `BYTES`.
///
/// NOTE: legacy v0/v1 messages DO carry a per-message CRC (the `int32` the caller consumed as `_crc_or_epoch`),
/// but it is a CRC-32 over the IEEE polynomial — a DIFFERENT algorithm from the CRC-32C the codec implements and
/// that v2 batches use. Validating it would need a second, distinct CRC just for a legacy fallback path; that is
/// not worth the code, so legacy CRCs are intentionally left unvalidated (only v2 batches are CRC-checked).
fn parse_legacy_message(
    reader: &mut Reader,
    magic: i8,
    values: &mut Vec<Vec<u8>>,
) -> io::Result<()> {
    let attributes = reader.int8()?;
    if attributes & 0x07 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed messages not supported",
        ));
    }
    if magic >= 1 {
        let _timestamp = reader.int64()?;
    }
    let _key = reader.nullable_bytes()?;
    if let Some(value) = reader.nullable_bytes()? {
        values.push(value);
    }
    Ok(())
}

/// Parse a `Produce` request body (after the request header) at `version`, returning the `acks` setting and the
/// produced topics. `acks == 0` signals a fire-and-forget produce: the caller must still land the records but
/// write NO response frame (see [`ProducedRequest`]).
///
/// A per-partition v2 CRC-32C mismatch does NOT fail the whole request — that partition alone carries
/// `error_code = Some(2)` (`CORRUPT_MESSAGE`) with no values, and parsing continues. A STRUCTURALLY malformed
/// blob still errors out (the frame is untrustworthy → close the connection).
///
/// # Errors
/// [`io::Error`] if the request envelope or an embedded batch is structurally malformed (not a mere CRC failure).
pub fn parse_produce(reader: &mut Reader, version: i16) -> io::Result<ProducedRequest> {
    if version >= 3 {
        let _transactional_id = reader.nullable_string()?;
    }
    let acks = reader.int16()?;
    let _timeout_ms = reader.int32()?;
    let topic_count = reader.int32()?;
    // Bound the count by the bytes actually remaining (each element is ≥1 byte): a small frame cannot claim
    // billions of topics/partitions and drive an over-allocation (audit K3). A genuine over-claim then fails
    // fast when the per-element reads run out of buffer.
    let tc = reader.bounded_count(topic_count, 6); // 6 = min topic entry (string len 2 + partition count 4)
    let mut topics = Vec::new();
    for _ in 0..tc {
        let name = reader.string()?;
        let part_count = reader.int32()?;
        let pc = reader.bounded_count(part_count, 4); // 4 = min partition entry (the int32 partition)
        let mut partitions = Vec::new();
        for _ in 0..pc {
            let partition = reader.int32()?;
            let (values, eos, error_code) = match reader.nullable_bytes()? {
                Some(blob) => match parse_record_batch(&blob) {
                    Ok(parsed) => (parsed.values, parsed.eos, None),
                    // A CRC mismatch is a PER-PARTITION CORRUPT_MESSAGE (2): drop the batch (no values stored),
                    // flag only this partition, and keep parsing the rest of the request + serving the connection.
                    Err(ParseError::Corrupt) => (Vec::new(), None, Some(2)),
                    // A structurally malformed blob poisons the frame — propagate and close the connection.
                    Err(ParseError::Malformed(e)) => return Err(e),
                },
                None => (Vec::new(), None, None),
            };
            partitions.push(ProducedPartition {
                partition,
                values,
                eos,
                error_code,
            });
        }
        topics.push(ProducedTopic { name, partitions });
    }
    Ok(ProducedRequest { acks, topics })
}

/// Build the full `Produce` response (header v0 + body) at `version`. `outcome_for` yields, per
/// `(topic, partition)`, the `(base_offset, error_code)` — the offset of that batch's first record and the
/// DURABLE landing result (`0` = NONE only once the records are committed; non-zero ⇒ retriable).
#[must_use]
pub fn produce_response(
    version: i16,
    correlation_id: i32,
    topics: &[ProducedTopic],
    outcome_for: &mut dyn FnMut(&str, i32, usize) -> (i64, i16),
) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false); // Produce response header is v0 for versions ≤ 8

    let count = i32::try_from(topics.len()).unwrap_or(0);
    w.int32(count);
    for topic in topics {
        w.string(&topic.name);
        let pcount = i32::try_from(topic.partitions.len()).unwrap_or(0);
        w.int32(pcount);
        for part in &topic.partitions {
            // A PARSE-time per-partition error (today: CORRUPT_MESSAGE 2 on a v2 CRC mismatch) short-circuits the
            // landing path entirely — the batch was never stored, so we report the parse code with a -1 base
            // offset and never invoke `outcome_for`. Otherwise `outcome_for` returns (base_offset, error_code) —
            // the error_code reflects the DURABLE landing result (0 = NONE only after the records are durably
            // committed; non-zero ⇒ retriable, audit A).
            let (base, error_code) = match part.error_code {
                Some(code) => (-1, code),
                None => outcome_for(&topic.name, part.partition, part.values.len()),
            };
            w.int32(part.partition);
            w.int16(error_code);
            w.int64(base); // base_offset
            if version >= 2 {
                w.int64(-1); // log_append_time = -1 (CreateTime)
            }
            if version >= 5 {
                w.int64(0); // log_start_offset
            }
        }
    }
    if version >= 1 {
        w.int32(0); // throttle_time_ms
    }
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::{parse_produce, parse_record_batch, ParseError};
    use crate::codec::Writer;

    /// Stamp the CORRECT CRC-32C into a v2 batch body `after` (the bytes after `base_offset` + `batch_length`,
    /// i.e. `partition_leader_epoch(4) magic(1) crc(4) attributes..records`). The CRC covers `attributes..end`,
    /// which begins at offset 9 of `after`; the 4-byte crc field sits at `after[5..9]`. Now that the parser
    /// VALIDATES the CRC, every hand-built v2 test batch must carry a real one.
    fn fix_v2_crc(after: &mut [u8]) {
        let crc = super::crc32c(&after[9..]);
        after[5..9].copy_from_slice(&crc.to_be_bytes());
    }

    /// Build a minimal uncompressed v2 `RecordBatch` carrying the given values (null keys, no headers).
    fn record_batch(values: &[&[u8]]) -> Vec<u8> {
        let mut recs = Writer::new();
        for (i, v) in values.iter().enumerate() {
            let mut r = Writer::new();
            r.int8(0); // attributes
            r.varlong(0); // timestamp delta
            r.varint(i32::try_from(i).unwrap()); // offset delta
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
        b.uint32(0); // crc (not validated on parse)
        b.int16(0); // attributes (uncompressed)
        b.int32(i32::try_from(values.len().saturating_sub(1)).unwrap()); // last_offset_delta
        b.int64(0); // base ts
        b.int64(0); // max ts
        b.int64(-1); // producer id
        b.int16(-1); // producer epoch
        b.int32(-1); // base sequence
        b.int32(i32::try_from(values.len()).unwrap()); // record count
        b.raw(&records);
        let mut after = b.into_bytes();
        fix_v2_crc(&mut after);

        let mut full = Writer::new();
        full.int64(0); // base offset
        full.int32(i32::try_from(after.len()).unwrap()); // batch length
        full.raw(&after);
        full.into_bytes()
    }

    /// Build a legacy v0 `MessageSet` (magic 0) carrying one null-key value — the format librdkafka sent live.
    fn legacy_messageset(value: &[u8]) -> Vec<u8> {
        let mut msg = Writer::new();
        msg.uint32(0); // crc (not validated)
        msg.int8(0); // magic 0
        msg.int8(0); // attributes (uncompressed)
        msg.int32(-1); // null key
        msg.int32(i32::try_from(value.len()).unwrap());
        msg.raw(value);
        let body = msg.into_bytes();
        let mut set = Writer::new();
        set.int64(0); // offset
        set.int32(i32::try_from(body.len()).unwrap()); // message size
        set.raw(&body);
        set.into_bytes()
    }

    #[test]
    fn over_claimed_count_does_not_over_allocate() {
        // topic_count = i32::MAX with no topic bytes: the remaining-bytes bound keeps allocation tiny (audit K3).
        // Before the bound, `Vec::with_capacity(i32::MAX as usize)` aborts the process.
        let mut req = Writer::new();
        req.nullable_string(None);
        req.int16(1);
        req.int32(0);
        req.int32(i32::MAX);
        let bytes = req.into_bytes();
        let mut reader = crate::codec::Reader::new(&bytes);
        let req = parse_produce(&mut reader, 7).expect("bounded parse, no over-alloc");
        assert!(
            req.topics.len() < 1024,
            "count must be bounded by remaining bytes, got {}",
            req.topics.len()
        );
    }

    /// Build a v2 `RecordBatch` with an explicit idempotent-producer identity (`producer_id` / `base_sequence`).
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
        b.int16(0); // producer epoch
        b.int32(base_sequence);
        b.int32(i32::try_from(values.len()).unwrap());
        b.raw(&records);
        let mut after = b.into_bytes();
        fix_v2_crc(&mut after);
        let mut full = Writer::new();
        full.int64(0);
        full.int32(i32::try_from(after.len()).unwrap());
        full.raw(&after);
        full.into_bytes()
    }

    #[test]
    fn legacy_messageset_value_extracted() {
        let blob = legacy_messageset(b"evt:legacy");
        let parsed = parse_record_batch(&blob).expect("parse legacy");
        assert_eq!(parsed.values, vec![b"evt:legacy".to_vec()]);
        assert_eq!(
            parsed.eos, None,
            "legacy MessageSet has no idempotent identity"
        );
    }

    #[test]
    fn record_batch_values_extracted() {
        let blob = record_batch(&[b"evt:one", b"evt:two", b"evt:three"]);
        let parsed = parse_record_batch(&blob).expect("parse");
        assert_eq!(
            parsed.values,
            vec![
                b"evt:one".to_vec(),
                b"evt:two".to_vec(),
                b"evt:three".to_vec()
            ]
        );
        // The reference helper uses producer_id = -1 (non-idempotent) → no EOS coord.
        assert_eq!(parsed.eos, None);
    }

    #[test]
    fn crc32c_known_answer() {
        // The canonical CRC-32C check value for the ASCII string "123456789".
        assert_eq!(super::crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(super::crc32c(b""), 0);
    }

    #[test]
    fn built_record_batch_round_trips_through_the_parser() {
        // build_record_batch is the inverse of parse_record_batch: a consumer-facing batch we build must parse
        // back to the same values (and a real consumer accepts it because the CRC-32C is correct).
        let values = vec![b"evt:x".to_vec(), b"evt:y".to_vec(), b"evt:z".to_vec()];
        let blob = super::build_record_batch(0, &values);
        let parsed = parse_record_batch(&blob).expect("parse our own batch");
        assert_eq!(parsed.values, values);
        // And the embedded CRC matches a recompute over the covered range (attributes..records).
        // Layout: base_offset(8) batch_len(4) ple(4) magic(1) crc(4) then the covered bytes.
        let crc_stored = u32::from_be_bytes([blob[17], blob[18], blob[19], blob[20]]);
        assert_eq!(
            crc_stored,
            super::crc32c(&blob[21..]),
            "stored CRC-32C covers attributes..records"
        );
    }

    #[test]
    fn idempotent_batch_surfaces_the_eos_coordinate() {
        let blob = idempotent_batch(7, 100, &[b"evt:a", b"evt:b", b"evt:c"]);
        let parsed = parse_record_batch(&blob).expect("parse idempotent");
        assert_eq!(parsed.values.len(), 3);
        let eos = parsed
            .eos
            .expect("an idempotent batch must surface its coordinate");
        assert_eq!(eos.producer_id, 7);
        assert_eq!(eos.base_sequence, 100);
        assert_eq!(eos.count, 3, "the sequence range is [100, 103)");
    }

    #[test]
    fn two_batches_in_one_blob_are_not_eos_eligible() {
        // A multi-batch blob has no single stable sequence range → no EOS coord (falls back to at-least-once).
        let mut blob = idempotent_batch(7, 0, &[b"evt:a"]);
        blob.extend_from_slice(&idempotent_batch(7, 1, &[b"evt:b"]));
        let parsed = parse_record_batch(&blob).expect("parse two batches");
        assert_eq!(parsed.values, vec![b"evt:a".to_vec(), b"evt:b".to_vec()]);
        assert_eq!(parsed.eos, None);
    }

    #[test]
    fn produce_v7_request_round_trips_records() {
        let batch = record_batch(&[b"evt:a", b"evt:b"]);
        let mut req = Writer::new();
        req.nullable_string(None); // transactional_id (v3+)
        req.int16(1); // acks
        req.int32(1000); // timeout
        req.int32(1); // 1 topic
        req.string("events");
        req.int32(1); // 1 partition
        req.int32(0); // partition 0
        req.bytes(&batch); // records as NULLABLE_BYTES (int32 len + bytes)
        let bytes = req.into_bytes();

        let mut reader = crate::codec::Reader::new(&bytes);
        let parsed = parse_produce(&mut reader, 7).expect("parse produce");
        assert_eq!(
            parsed.acks, 1,
            "acks is parsed and threaded out of parse_produce"
        );
        assert_eq!(parsed.topics.len(), 1);
        assert_eq!(parsed.topics[0].name, "events");
        assert_eq!(
            parsed.topics[0].partitions[0].values,
            vec![b"evt:a".to_vec(), b"evt:b".to_vec()]
        );
        assert_eq!(
            parsed.topics[0].partitions[0].error_code, None,
            "a valid CRC → no parse error"
        );
    }

    #[test]
    fn compressed_batch_is_rejected() {
        // Start from a VALID uncompressed batch (correct CRC), then flip the gzip codec bit in `attributes` and
        // re-stamp the CRC so the batch passes the CRC gate and actually reaches the compression path. Without
        // the `compression` feature that is "compressed batches not supported"; with it, the still-uncompressed
        // body fails to gzip-decompress — either way, an error (never a false accept).
        let mut blob = record_batch(&[b"evt:a"]);
        // Layout: base_offset(8) batch_len(4) ple(4) magic(1) crc(4) attributes(2) ...; attributes at [21..23].
        blob[21..23].copy_from_slice(&1i16.to_be_bytes()); // attributes: gzip codec bit
        let crc = super::crc32c(&blob[21..]);
        blob[17..21].copy_from_slice(&crc.to_be_bytes()); // re-stamp CRC over the mutated body
        assert!(parse_record_batch(&blob).is_err());
    }

    #[test]
    fn v2_batch_with_flipped_records_byte_is_corrupt_and_stores_nothing() {
        // A valid v2 batch parses to its values; flipping ONE byte in the records section makes the stored CRC no
        // longer match the recomputed CRC over `attributes..end` → ParseError::Corrupt (produce error code 2),
        // and NO record is extracted. This is the record-batch CRC guard on the produce path.
        let good = record_batch(&[b"evt:one", b"evt:two"]);
        assert_eq!(
            parse_record_batch(&good).expect("valid CRC parses").values,
            vec![b"evt:one".to_vec(), b"evt:two".to_vec()],
        );
        let mut bad = good.clone();
        // Flip a byte deep in the records section (well past the 61-byte v2 header) — a value payload byte.
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        match parse_record_batch(&bad) {
            Err(ParseError::Corrupt) => {}
            other => panic!("a flipped records byte must be ParseError::Corrupt, got {other:?}"),
        }
    }

    /// gzip a byte slice (test helper — the `compression-gzip` feature pulls flate2).
    #[cfg(feature = "compression-gzip")]
    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("gz write");
        enc.finish().expect("gz finish")
    }

    #[test]
    #[cfg(feature = "compression-gzip")]
    fn parse_gzip_compressed_v2_batch_decompresses_and_yields_values() {
        // Reuse the proven uncompressed builder, then GZIP its records section (header is 61 bytes; attributes at
        // [21..23]; batchLength at [8..12] counts from offset 12) and re-frame as a gzip (codec 1) batch.
        let values = vec![
            b"evt:gz-a".to_vec(),
            b"evt:gz-b".to_vec(),
            b"evt:gz-c".to_vec(),
        ];
        let plain = super::build_record_batch(0, &values);
        let compressed = gzip(&plain[61..]);
        let mut out = plain[..61].to_vec();
        out[21..23].copy_from_slice(&1i16.to_be_bytes()); // attributes: gzip codec
        out.extend_from_slice(&compressed);
        let batch_len = i32::try_from(out.len() - 12).expect("len");
        out[8..12].copy_from_slice(&batch_len.to_be_bytes());
        // The CRC covers the WIRE bytes `attributes..end` (the COMPRESSED body) — re-stamp it after reframing so
        // the parser's CRC gate (which runs BEFORE decompression) accepts the batch.
        let crc = super::crc32c(&out[21..]);
        out[17..21].copy_from_slice(&crc.to_be_bytes());

        let parsed = parse_record_batch(&out).expect("gzip batch parses");
        assert_eq!(
            parsed.values, values,
            "gzip records were decompressed + parsed in order"
        );
    }

    #[test]
    #[cfg(feature = "compression-gzip")]
    fn gzip_decompress_rejects_a_zip_bomb_past_the_cap() {
        let big = vec![0u8; 1 << 20]; // 1 MiB of zeros → tiny gzip, expands past a small cap
        let compressed = gzip(&big);
        let err =
            crate::compress::decompress(1, &compressed, 1024).expect_err("must reject over-cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Re-frame a plain (uncompressed) v2 batch as a compressed one: set the attributes codec + swap in the
    /// compressed records blob + fix batchLength. Header is 61 bytes; attributes at [21..23]; batchLength at [8..12].
    #[cfg(any(
        feature = "compression-lz4",
        feature = "compression-zstd",
        feature = "compression-snappy"
    ))]
    fn reframe_compressed(plain: &[u8], codec: i16, compressed: &[u8]) -> Vec<u8> {
        let mut out = plain[..61].to_vec();
        out[21..23].copy_from_slice(&codec.to_be_bytes());
        out.extend_from_slice(compressed);
        let batch_len = i32::try_from(out.len() - 12).expect("len");
        out[8..12].copy_from_slice(&batch_len.to_be_bytes());
        // The v2 CRC covers the WIRE bytes `attributes..end` (the COMPRESSED body); re-stamp it after reframing
        // so the parser's CRC gate (which runs BEFORE decompression) accepts the batch.
        let crc = super::crc32c(&out[21..]);
        out[17..21].copy_from_slice(&crc.to_be_bytes());
        out
    }

    #[test]
    #[cfg(feature = "compression-lz4")]
    fn parse_lz4_frame_compressed_v2_batch() {
        use std::io::Write as _;
        let values = vec![b"evt:lz-a".to_vec(), b"evt:lz-b".to_vec()];
        let plain = super::build_record_batch(0, &values);
        let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
        enc.write_all(&plain[61..]).expect("lz4 write");
        let compressed = enc.finish().expect("lz4 finish");
        let out = reframe_compressed(&plain, 3, &compressed);
        assert_eq!(
            parse_record_batch(&out).expect("lz4 batch parses").values,
            values
        );
    }

    #[test]
    #[cfg(feature = "compression-zstd")]
    fn parse_zstd_compressed_v2_batch() {
        // Hand-build a valid zstd frame with a single RAW block (no encoder dep): magic + frame-header
        // (single-segment, 1-byte content size) + block-header ((len<<3)|last|raw) + the raw records bytes.
        let values = vec![b"evt:zs-a".to_vec(), b"evt:zs-b".to_vec()];
        let plain = super::build_record_batch(0, &values);
        let records = &plain[61..];
        assert!(
            records.len() < 256,
            "test payload fits a 1-byte content size"
        );
        let mut zstd = vec![0x28, 0xB5, 0x2F, 0xFD]; // zstd magic
        zstd.push(0x20); // FHD: single-segment → 1-byte Frame_Content_Size, no checksum/dict
        zstd.push(u8::try_from(records.len()).expect("fits")); // content size
        let block_header = (u32::try_from(records.len()).expect("fits") << 3) | 1; // raw block (type 0), last
        zstd.extend_from_slice(&block_header.to_le_bytes()[..3]);
        zstd.extend_from_slice(records);
        let out = reframe_compressed(&plain, 4, &zstd);
        assert_eq!(
            parse_record_batch(&out).expect("zstd batch parses").values,
            values
        );
    }

    #[test]
    #[cfg(feature = "compression-snappy")]
    fn parse_snappy_xerial_compressed_v2_batch() {
        // Kafka snappy = xerial/snappy-java framing: magic + version + compat-version + [block_len][raw-snappy block].
        let values = vec![b"evt:sn-a".to_vec(), b"evt:sn-b".to_vec()];
        let plain = super::build_record_batch(0, &values);
        let block = snap::raw::Encoder::new()
            .compress_vec(&plain[61..])
            .expect("snappy compress");
        let mut xerial = vec![0x82u8, b'S', b'N', b'A', b'P', b'P', b'Y', 0x00];
        xerial.extend_from_slice(&1i32.to_be_bytes()); // version
        xerial.extend_from_slice(&1i32.to_be_bytes()); // compatible version
        xerial.extend_from_slice(&i32::try_from(block.len()).expect("len").to_be_bytes());
        xerial.extend_from_slice(&block);
        let out = reframe_compressed(&plain, 2, &xerial);
        assert_eq!(
            parse_record_batch(&out)
                .expect("snappy batch parses")
                .values,
            values
        );
    }

    #[test]
    #[cfg(feature = "compression-snappy")]
    fn parse_raw_snappy_block_v2_batch() {
        // Some producers send a single RAW snappy block (no xerial framing) — unsnappy must accept that too.
        let values = vec![b"evt:raw-a".to_vec(), b"evt:raw-b".to_vec()];
        let plain = super::build_record_batch(0, &values);
        let raw = snap::raw::Encoder::new()
            .compress_vec(&plain[61..])
            .expect("snappy compress");
        let out = reframe_compressed(&plain, 2, &raw);
        assert_eq!(
            parse_record_batch(&out)
                .expect("raw snappy batch parses")
                .values,
            values
        );
    }
}
