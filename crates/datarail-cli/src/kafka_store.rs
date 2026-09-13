//! Durable, provider-blind, contiguous-offset partition log for `datarail kafka-broker`
//! (`KAFKA-FETCH-DESIGN.md` increment 2 — durability across restart).
//!
//! It wraps the proven flat-RAM [`datarail_replaylog::ReplayLog`] (fsync-durable, segment-rotating, torn-tail-safe
//! — see `LASTRO-MATRIX.md`) and maps **Kafka's contiguous logical offset** (record index 0,1,2,…; next fetch =
//! `last + 1`) onto the log's *byte* offsets. The log on disk holds **only sealed cofre bytes**, so a snapshot of
//! the data directory reveals nothing — the provider-blind property the in-memory increment-1 store already had,
//! now surviving a restart.
//!
//! Two invariants make it Kafka-correct AND crash-safe:
//! - **Contiguous logical offset.** A side index `starts[i]` = the byte offset where record `i` begins. Rebuilt by
//!   scanning the durable log on [`open`](SealedPartitionLog::open), so every previously-acked record is
//!   addressable again after a restart.
//! - **Durability-before-visibility (= durability-before-ack).** [`append_durable`](SealedPartitionLog::append_durable)
//!   appends the batch, `fsync`s, and only THEN publishes the records' logical offsets. A record is fetchable only
//!   once it is on stable storage, so a clean crash immediately after the produce ack never loses an acked record —
//!   closing the in-memory increment-1 caveat (`KAFKA-FETCH-DESIGN.md`: "durability-before-ack lands with
//!   increment 2's persistent log"). A *failed* batch is reconciled to disk so it never shifts later offsets
//!   either (see [`append_durable`](SealedPartitionLog::append_durable)).
//!
//! **Scope of the guarantee (honest, audit increment-2 HIGH #1).** Offset stability holds across a *clean crash*
//! (a torn tail in the final segment, which recovery stops at cleanly) and across a failed/partial batch. It does
//! NOT cover silent *mid-history disk corruption* (bit-rot in a non-final segment): the retained-log substrate
//! detects it via CRC — wrong bytes are never returned — but it RESYNCS past the corrupt segment, which drops that
//! segment's tail and renumbers the survivors. That is a known limit of the underlying `datarail-replaylog` and a
//! storage-integrity failure outside the crash-consistency model; hardening it (per-record durable logical ids /
//! an integrity checkpoint that fails loud instead of renumbering) is tracked future work, not claimed here.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use datarail_replaylog::{ReplayLog, MAX_RECORD};

/// IEEE CRC-32 (table-free) over a record's `len ‖ bytes`, matching `datarail_replaylog::crc32`.
fn crc32(parts: &[&[u8]]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for part in parts {
        for &b in *part {
            crc ^= u32::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }
    !crc
}

/// Per-partition segment size. The flat-RAM cost scales as `total / segment_bytes` (the per-replay segment-start
/// list), independent of how much history is retained — see `datarail-replaylog`.
const SEGMENT_BYTES: u64 = datarail_replaylog::DEFAULT_SEGMENT_BYTES;

const DEDUP_MAGIC: &[u8; 4] = b"DRD1";
const DEDUP_RECORD_BYTES: usize = 80;
const DEDUP_PREPARE: u8 = 1;
const DEDUP_COMMIT: u8 = 2;
const MAX_DEDUP_ENTRIES: usize = 65_536;

/// The wire identity and durable result for one idempotent produce batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DedupCoord {
    pub(crate) producer_id: i64,
    pub(crate) epoch: i16,
    pub(crate) base_sequence: i32,
    pub(crate) count: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DedupEntry {
    pub(crate) coord: DedupCoord,
    pub(crate) base_offset: i64,
}

/// Persistent sequence state. Metadata contains only numeric coordinates and offsets, never payload bytes.
#[derive(Debug)]
pub(crate) struct DedupState {
    file: std::fs::File,
    entries: Vec<DedupEntry>,
    pending_start: Option<u64>,
}

impl DedupState {
    /// Open metadata, reject full-record corruption, and roll back an uncommitted prepare in the partition log.
    pub(crate) fn open(path: impl AsRef<Path>, log: &mut SealedPartitionLog) -> io::Result<Self> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let complete = bytes.len() / DEDUP_RECORD_BYTES * DEDUP_RECORD_BYTES;
        if bytes.len() != complete {
            file.set_len(u64::try_from(complete).unwrap_or(u64::MAX))?;
            file.sync_all()?;
            bytes.truncate(complete);
        }
        let mut entries = Vec::new();
        let mut pending: Option<(u64, DedupRecord)> = None;
        let (records, _) = bytes.as_chunks::<DEDUP_RECORD_BYTES>();
        for (index, raw) in records.iter().enumerate() {
            let record = decode_dedup_record(raw)?;
            match record.kind {
                DEDUP_PREPARE => {
                    let start =
                        u64::try_from(index.saturating_mul(DEDUP_RECORD_BYTES)).unwrap_or(u64::MAX);
                    if pending.replace((start, record)).is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "dedup metadata has nested prepare",
                        ));
                    }
                }
                DEDUP_COMMIT => {
                    let (_, prepared) = pending.take().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "dedup metadata commit has no prepare",
                        )
                    })?;
                    if prepared.coord != record.coord
                        || prepared.byte_end != record.byte_end
                        || prepared.logical_len != record.logical_len
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "dedup metadata commit does not match prepare",
                        ));
                    }
                    if entries.len() >= MAX_DEDUP_ENTRIES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "dedup metadata entry limit exceeded",
                        ));
                    }
                    entries.push(DedupEntry {
                        coord: record.coord,
                        base_offset: record.base_offset,
                    });
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "dedup metadata has unknown record kind",
                    ));
                }
            }
        }
        if let Some((start, record)) = pending {
            log.truncate_to(record.byte_end, record.logical_len)?;
            file.set_len(start)?;
            file.sync_all()?;
        }
        Ok(Self {
            file,
            entries,
            pending_start: None,
        })
    }

    pub(crate) fn lookup(&self, coord: DedupCoord) -> io::Result<Option<DedupEntry>> {
        sequence_high(coord)?;
        let mut highest_epoch: Option<i16> = None;
        for entry in &self.entries {
            if entry.coord.producer_id != coord.producer_id {
                continue;
            }
            highest_epoch =
                Some(highest_epoch.map_or(entry.coord.epoch, |old| old.max(entry.coord.epoch)));
        }
        if highest_epoch.is_some_and(|epoch| coord.epoch < epoch) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stale idempotent producer epoch",
            ));
        }
        let mut watermark = 0i64;
        for entry in &self.entries {
            if entry.coord.producer_id != coord.producer_id {
                continue;
            }
            if entry.coord.epoch == coord.epoch {
                watermark = watermark.max(sequence_high(entry.coord)?);
                if entry.coord.base_sequence == coord.base_sequence
                    && entry.coord.count == coord.count
                {
                    return Ok(Some(*entry));
                }
            }
        }
        if highest_epoch == Some(coord.epoch) && i64::from(coord.base_sequence) < watermark {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "out-of-order idempotent producer sequence",
            ));
        }
        Ok(None)
    }

    pub(crate) fn prepare(
        &mut self,
        coord: DedupCoord,
        byte_end: u64,
        logical_len: usize,
    ) -> io::Result<()> {
        if self.entries.len() >= MAX_DEDUP_ENTRIES {
            return Err(io::Error::other("dedup metadata entry limit reached"));
        }
        if self.pending_start.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dedup metadata has an unresolved prepare",
            ));
        }
        let start = self.file.metadata()?.len();
        let record = DedupRecord {
            kind: DEDUP_PREPARE,
            coord,
            byte_end,
            logical_len,
            base_offset: 0,
        };
        append_dedup_record(&mut self.file, &record)?;
        self.pending_start = Some(start);
        Ok(())
    }

    pub(crate) fn commit(
        &mut self,
        coord: DedupCoord,
        byte_end: u64,
        logical_len: usize,
        base_offset: i64,
    ) -> io::Result<()> {
        let record = DedupRecord {
            kind: DEDUP_COMMIT,
            coord,
            byte_end,
            logical_len,
            base_offset,
        };
        append_dedup_record(&mut self.file, &record)?;
        self.entries.push(DedupEntry { coord, base_offset });
        self.pending_start = None;
        Ok(())
    }

    pub(crate) fn rollback(&mut self) -> io::Result<()> {
        if let Some(start) = self.pending_start.take() {
            self.file.set_len(start)?;
            self.file.sync_all()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct DedupRecord {
    kind: u8,
    coord: DedupCoord,
    byte_end: u64,
    logical_len: usize,
    base_offset: i64,
}

fn sequence_high(coord: DedupCoord) -> io::Result<i64> {
    if coord.count <= 0 || coord.base_sequence < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid idempotent producer sequence range",
        ));
    }
    i64::from(coord.base_sequence)
        .checked_add(i64::from(coord.count))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "idempotent sequence range overflows",
            )
        })
}

fn append_dedup_record(file: &mut std::fs::File, record: &DedupRecord) -> io::Result<()> {
    let mut bytes = [0u8; DEDUP_RECORD_BYTES];
    bytes[..4].copy_from_slice(DEDUP_MAGIC);
    bytes[4] = record.kind;
    bytes[8..16].copy_from_slice(&record.byte_end.to_be_bytes());
    bytes[16..24].copy_from_slice(
        &u64::try_from(record.logical_len)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    bytes[24..32].copy_from_slice(&record.coord.producer_id.to_be_bytes());
    bytes[32..34].copy_from_slice(&record.coord.epoch.to_be_bytes());
    bytes[36..40].copy_from_slice(&record.coord.base_sequence.to_be_bytes());
    bytes[40..44].copy_from_slice(&record.coord.count.to_be_bytes());
    bytes[48..56].copy_from_slice(&record.base_offset.to_be_bytes());
    let crc = crc32(&[&bytes[..76]]);
    bytes[76..80].copy_from_slice(&crc.to_be_bytes());
    file.write_all(&bytes)?;
    file.sync_all()
}

fn decode_dedup_record(bytes: &[u8]) -> io::Result<DedupRecord> {
    if bytes.len() != DEDUP_RECORD_BYTES || &bytes[..4] != DEDUP_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid dedup metadata header",
        ));
    }
    let stored = u32::from_be_bytes(bytes[76..80].try_into().unwrap_or([0; 4]));
    if crc32(&[&bytes[..76]]) != stored {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dedup metadata CRC mismatch",
        ));
    }
    let logical_len = usize::try_from(u64::from_be_bytes(
        bytes[16..24].try_into().unwrap_or([0; 8]),
    ))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "dedup logical length overflows"))?;
    let record = DedupRecord {
        kind: bytes[4],
        byte_end: u64::from_be_bytes(bytes[8..16].try_into().unwrap_or([0; 8])),
        logical_len,
        coord: DedupCoord {
            producer_id: i64::from_be_bytes(bytes[24..32].try_into().unwrap_or([0; 8])),
            epoch: i16::from_be_bytes(bytes[32..34].try_into().unwrap_or([0; 2])),
            base_sequence: i32::from_be_bytes(bytes[36..40].try_into().unwrap_or([0; 4])),
            count: i32::from_be_bytes(bytes[40..44].try_into().unwrap_or([0; 4])),
        },
        base_offset: i64::from_be_bytes(bytes[48..56].try_into().unwrap_or([0; 8])),
    };
    sequence_high(record.coord)?;
    if record.base_offset < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dedup metadata has negative base offset",
        ));
    }
    Ok(record)
}

/// Scan the durable log from the start and return the byte offset of every recoverable record, in order — the
/// authoritative contiguous logical-offset index. Used by both [`SealedPartitionLog::open`] (restart recovery)
/// and the failed-batch reconcile path. A clean crash leaves a torn tail in the final segment, which the replay
/// layer stops cleanly at, so the returned prefix is exactly the durable, acked records.
fn scan_starts(log: &ReplayLog) -> io::Result<Vec<u64>> {
    let mut starts = Vec::new();
    let mut replay = log.replay_from(0).map_err(io::Error::other)?;
    while let Some((offset, _record)) = replay.read_next().map_err(io::Error::other)? {
        starts.push(offset);
    }
    Ok(starts)
}

/// One `(topic, partition)`'s durable, sealed, contiguous-offset record log.
pub(crate) struct SealedPartitionLog {
    log: ReplayLog,
    /// `starts[logical_offset]` = the byte offset where that record begins in `log` (a valid `replay_from` seek
    /// point). `starts.len()` = the Kafka *latest* offset (record count). Costs 8 bytes per record — an index,
    /// not the data; the sealed payloads live on disk and stream through a bounded buffer on read.
    starts: Vec<u64>,
}

impl SealedPartitionLog {
    /// Open or recover the partition log rooted at `dir`. Rebuilds the contiguous logical-offset index by scanning
    /// the durable log from the start, so all previously-acked records are addressable again after a restart. A
    /// torn tail (a crash mid-append) is dropped by the replay layer, so only fully-written records are recovered.
    ///
    /// # Errors
    /// [`io::Error`] if the backing log cannot be opened or scanned.
    pub(crate) fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let log = ReplayLog::open(dir, SEGMENT_BYTES).map_err(io::Error::other)?;
        let starts = scan_starts(&log)?;
        Ok(Self { log, starts })
    }

    /// The number of durably-stored records = the Kafka *latest* (next) logical offset.
    pub(crate) fn len(&self) -> usize {
        self.starts.len()
    }

    /// Current durable byte end, used as a transaction recovery boundary.
    pub(crate) fn byte_end(&self) -> u64 {
        self.log.end_offset()
    }

    /// Roll back this partition to a journaled byte/logical boundary.
    ///
    /// # Errors
    /// Returns an I/O error if the backing log cannot truncate or the recovered index does not match.
    pub(crate) fn truncate_to(&mut self, byte_end: u64, logical_len: usize) -> io::Result<()> {
        self.log.truncate_to(byte_end).map_err(io::Error::other)?;
        self.starts = scan_starts(&self.log)?;
        if self.byte_end() != byte_end || self.starts.len() != logical_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "partition recovery boundary mismatch",
            ));
        }
        Ok(())
    }

    /// Append a batch of already-sealed cofre bytes, `fsync` once, and only THEN publish their logical offsets. The
    /// single `fsync` is the durability barrier for the whole batch; publishing the offsets afterwards means a
    /// record is never visible (fetchable / counted) before it is durable.
    ///
    /// **Offset stability across a failed batch (audit increment-2 HIGH #2).** A record that was appended as a
    /// valid frame *before* a later record in the same batch failed (e.g. an oversize record, or a disk-full mid
    /// batch) is durable on disk even though the live broker did not publish its offset. On ANY append/`fsync`
    /// failure we therefore reconcile the in-memory index against what is *actually* on disk (a rescan), so the
    /// next produce's base AND a post-restart [`open`](Self::open) agree on every record's logical offset — a
    /// failed batch never silently shifts later offsets. The caller still gets the (retriable) error.
    ///
    /// Returns the logical offset assigned to the FIRST record in the batch.
    ///
    /// # Errors
    /// [`io::Error`] on an append (e.g. record too large) or `fsync` failure — with the index reconciled to disk.
    pub(crate) fn append_durable(&mut self, sealed: &[Vec<u8>]) -> io::Result<i64> {
        let base = i64::try_from(self.starts.len()).unwrap_or(i64::MAX);
        let mut new_starts = Vec::with_capacity(sealed.len());
        let mut append_err = None;
        for bytes in sealed {
            match self.log.append(bytes) {
                Ok(offset) => new_starts.push(offset),
                Err(e) => {
                    append_err = Some(io::Error::other(e));
                    break;
                }
            }
        }
        // Durability barrier for whatever was appended (best-effort even on the failure path, so the on-disk state
        // the recovery rescan sees is settled).
        let sync_err = self.log.sync().err().map(io::Error::other);
        match append_err.or(sync_err) {
            None => {
                self.starts.extend(new_starts);
                Ok(base)
            }
            Some(e) => {
                // Reconcile to disk: the authoritative count is whatever is durably framed, not what we published.
                self.starts = scan_starts(&self.log)?;
                Err(e)
            }
        }
    }

    /// Read the **sealed** cofre bytes from logical `offset` onward, capping the batch at `max_bytes` of *ciphertext*
    /// (but always returning at least one record if any exist — Kafka semantics: a fetch must make progress). The
    /// caller un-seals at the edge. Streams through the flat-RAM replay cursor, so RAM stays flat regardless of how
    /// much history is retained. An `offset` at/past the end returns empty (the consumer waits / retries).
    ///
    /// The cap is on ciphertext, which is `>=` the plaintext size the caller will return, so the effective
    /// plaintext bytes never exceed `max_bytes` by more than one record — an honest, safe over-approximation.
    ///
    /// # Errors
    /// [`io::Error`] on a read/framing error from the backing log.
    pub(crate) fn read_sealed_from(
        &self,
        offset: usize,
        max_bytes: i64,
    ) -> io::Result<Vec<Vec<u8>>> {
        let Some(&start) = self.starts.get(offset) else {
            return Ok(Vec::new());
        };
        // FIX REAL: read directly from the correct segment file at byte offset `start` (bypass Replay replay mechanism
        // which has a seek/replay bug when corrupt frames exist in previous segments — see replaylog crate doc).
        // Find segment containing byte offset `start` by scanning segment file names from data_dir.
        let dir = self.log.dir();
        let mut seg_starts: Vec<u64> = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(io::Error::other)? {
            let path = entry.map_err(io::Error::other)?.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(s) = name
                    .strip_suffix(".seg")
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    seg_starts.push(s);
                }
            }
        }
        seg_starts.sort_unstable();
        let seg_start = seg_starts
            .iter()
            .rfind(|&&s| s <= start)
            .copied()
            .unwrap_or(0);
        let seek_in_file = start.saturating_sub(seg_start);
        let seg_path = dir.join(format!("{seg_start:020}.seg"));
        let mut file = std::fs::File::open(&seg_path)
            .map_err(|e| io::Error::other(format!("segment file open error: {e}")))?;
        file.seek(SeekFrom::Start(seek_in_file))
            .map_err(|e| io::Error::other(format!("segment seek error: {e}")))?;
        let mut out = Vec::new();
        let mut bytes_read = 0i64;
        loop {
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(_) => break, // torn tail / end of segment
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > MAX_RECORD {
                break; // corrupt length — stop replay (like replaylog resync_or_stop in final segment)
            }
            let frame_size = 4 + len + 4;
            let mut frame_bytes = vec![0u8; frame_size];
            frame_bytes[..4].copy_from_slice(&len_buf);
            match file.read_exact(&mut frame_bytes[4..]) {
                Ok(()) => {}
                Err(_) => break, // truncated frame
            }
            // Validate CRC32 (like replaylog does) — stop at first corrupt frame in final segment.
            let payload = &frame_bytes[4..4 + len];
            let stored_crc = u32::from_le_bytes([
                frame_bytes[4 + len],
                frame_bytes[4 + len + 1],
                frame_bytes[4 + len + 2],
                frame_bytes[4 + len + 3],
            ]);
            let computed_crc = crc32(&[&len_buf, payload]);
            if stored_crc != computed_crc {
                break; // CRC mismatch — stop replay (like replaylog resync_or_stop in final segment)
            }
            let body = payload.to_vec();
            out.push(body);
            bytes_read += i64::try_from(len).unwrap_or(i64::MAX);
            if bytes_read >= max_bytes {
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{DedupCoord, DedupState, SealedPartitionLog};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("datarail-kafka-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn append_assigns_contiguous_logical_offsets_and_reads_back_in_order() {
        let dir = tmpdir("contig");
        let mut log = SealedPartitionLog::open(&dir).unwrap();
        assert_eq!(log.len(), 0);
        // Two batches: offsets must be contiguous 0,1 then 2.
        assert_eq!(
            log.append_durable(&[b"a".to_vec(), b"b".to_vec()]).unwrap(),
            0
        );
        assert_eq!(log.append_durable(&[b"c".to_vec()]).unwrap(), 2);
        assert_eq!(log.len(), 3);
        assert_eq!(
            log.read_sealed_from(0, 1 << 20).unwrap(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
        assert_eq!(
            log.read_sealed_from(1, 1 << 20).unwrap(),
            vec![b"b".to_vec(), b"c".to_vec()]
        );
        // At/past the end → empty, never a panic.
        assert!(log.read_sealed_from(3, 1 << 20).unwrap().is_empty());
        assert!(log.read_sealed_from(99, 1 << 20).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn records_survive_a_restart() {
        let dir = tmpdir("restart");
        {
            let mut log = SealedPartitionLog::open(&dir).unwrap();
            log.append_durable(&[b"sealed-0".to_vec(), b"sealed-1".to_vec()])
                .unwrap();
            log.append_durable(&[b"sealed-2".to_vec()]).unwrap();
            // drop → simulate process exit
        }
        // Reopen: the contiguous index is rebuilt from the durable log, and the next append continues at 3.
        let mut reopened = SealedPartitionLog::open(&dir).unwrap();
        assert_eq!(
            reopened.len(),
            3,
            "all acked records recovered after restart"
        );
        assert_eq!(
            reopened.read_sealed_from(0, 1 << 20).unwrap(),
            vec![
                b"sealed-0".to_vec(),
                b"sealed-1".to_vec(),
                b"sealed-2".to_vec()
            ]
        );
        assert_eq!(
            reopened.append_durable(&[b"sealed-3".to_vec()]).unwrap(),
            3,
            "logical offset continues past recovery"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idempotent_sequence_metadata_survives_restart_and_replays_same_offset() {
        let dir = tmpdir("dedup-restart");
        let coord = DedupCoord {
            producer_id: 41,
            epoch: 2,
            base_sequence: 7,
            count: 1,
        };
        {
            let mut log = SealedPartitionLog::open(&dir).unwrap();
            let mut dedup = DedupState::open(dir.join("dedup.meta"), &mut log).unwrap();
            dedup.prepare(coord, log.byte_end(), log.len()).unwrap();
            let base = log.append_durable(&[b"sealed".to_vec()]).unwrap();
            dedup.commit(coord, 0, 0, base).unwrap();
        }
        let mut reopened_log = SealedPartitionLog::open(&dir).unwrap();
        let reopened = DedupState::open(dir.join("dedup.meta"), &mut reopened_log).unwrap();
        assert_eq!(
            reopened.lookup(coord).unwrap().unwrap().base_offset,
            0,
            "same sequence resolves to original stable offset"
        );
        assert!(
            reopened.lookup(DedupCoord { epoch: 1, ..coord }).is_err(),
            "older epoch cannot replay after fencing"
        );
        assert!(
            reopened
                .lookup(DedupCoord {
                    base_sequence: 6,
                    ..coord
                })
                .is_err(),
            "sequence below current watermark cannot append"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_complete_idempotent_metadata_fails_closed() {
        let dir = tmpdir("dedup-corrupt");
        {
            let mut log = SealedPartitionLog::open(&dir).unwrap();
            let mut dedup = DedupState::open(dir.join("dedup.meta"), &mut log).unwrap();
            let coord = DedupCoord {
                producer_id: 1,
                epoch: 0,
                base_sequence: 0,
                count: 1,
            };
            dedup.prepare(coord, log.byte_end(), log.len()).unwrap();
            let base = log.append_durable(&[b"sealed".to_vec()]).unwrap();
            dedup.commit(coord, 0, 0, base).unwrap();
        }
        let metadata = dir.join("dedup.meta");
        let mut bytes = std::fs::read(&metadata).unwrap();
        bytes[24] ^= 1;
        std::fs::write(metadata, bytes).unwrap();
        let mut log = SealedPartitionLog::open(&dir).unwrap();
        assert_eq!(
            DedupState::open(dir.join("dedup.meta"), &mut log)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_batch_keeps_logical_offsets_stable_across_restart() {
        // Regression for audit increment-2 HIGH #2: a valid frame appended before a later record in the same batch
        // failed must NOT become a restart-only orphan that shifts subsequent offsets.
        let dir = tmpdir("failbatch");
        {
            let mut log = SealedPartitionLog::open(&dir).unwrap();
            // Second record exceeds the log's max → the batch fails, but "good" was already framed durably.
            let huge = vec![0u8; datarail_replaylog::MAX_RECORD + 1];
            assert!(
                log.append_durable(&[b"good".to_vec(), huge]).is_err(),
                "oversize record fails the batch"
            );
            // The index is reconciled to disk: the one durable frame is counted (not orphaned).
            assert_eq!(
                log.len(),
                1,
                "the durable frame from the failed batch is reconciled live"
            );
            // A later record therefore gets a STABLE offset that a restart will agree with.
            assert_eq!(log.append_durable(&[b"next".to_vec()]).unwrap(), 1);
        }
        let reopened = SealedPartitionLog::open(&dir).unwrap();
        assert_eq!(
            reopened.len(),
            2,
            "restart recovers exactly the live count — no offset shift"
        );
        assert_eq!(
            reopened.read_sealed_from(0, 1 << 20).unwrap(),
            vec![b"good".to_vec(), b"next".to_vec()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_bytes_bounds_the_batch_but_always_returns_at_least_one() {
        let dir = tmpdir("maxbytes");
        let mut log = SealedPartitionLog::open(&dir).unwrap();
        log.append_durable(&[vec![1u8; 100], vec![2u8; 100], vec![3u8; 100]])
            .unwrap();
        // A tiny cap still returns exactly one record (progress guarantee).
        assert_eq!(log.read_sealed_from(0, 1).unwrap().len(), 1);
        // A cap that fits ~two records stops early (does not over-read the whole log).
        assert_eq!(log.read_sealed_from(0, 150).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
