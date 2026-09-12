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

use std::io;
use std::path::Path;

use datarail_replaylog::ReplayLog;

/// Per-partition segment size. The flat-RAM cost scales as `total / segment_bytes` (the per-replay segment-start
/// list), independent of how much history is retained — see `datarail-replaylog`.
const SEGMENT_BYTES: u64 = datarail_replaylog::DEFAULT_SEGMENT_BYTES;

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
    pub(crate) fn read_sealed_from(&self, offset: usize, max_bytes: i64) -> io::Result<Vec<Vec<u8>>> {
        let Some(&start) = self.starts.get(offset) else {
            return Ok(Vec::new());
        };
        let mut replay = self.log.replay_from(start).map_err(io::Error::other)?;
        let mut out = Vec::new();
        let mut bytes = 0i64;
        while let Some((_offset, record)) = replay.read_next().map_err(io::Error::other)? {
            bytes = bytes.saturating_add(i64::try_from(record.len()).unwrap_or(i64::MAX));
            out.push(record);
            if bytes >= max_bytes {
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::SealedPartitionLog;

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
        assert_eq!(log.append_durable(&[b"a".to_vec(), b"b".to_vec()]).unwrap(), 0);
        assert_eq!(log.append_durable(&[b"c".to_vec()]).unwrap(), 2);
        assert_eq!(log.len(), 3);
        assert_eq!(log.read_sealed_from(0, 1 << 20).unwrap(), vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(log.read_sealed_from(1, 1 << 20).unwrap(), vec![b"b".to_vec(), b"c".to_vec()]);
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
            log.append_durable(&[b"sealed-0".to_vec(), b"sealed-1".to_vec()]).unwrap();
            log.append_durable(&[b"sealed-2".to_vec()]).unwrap();
            // drop → simulate process exit
        }
        // Reopen: the contiguous index is rebuilt from the durable log, and the next append continues at 3.
        let mut reopened = SealedPartitionLog::open(&dir).unwrap();
        assert_eq!(reopened.len(), 3, "all acked records recovered after restart");
        assert_eq!(
            reopened.read_sealed_from(0, 1 << 20).unwrap(),
            vec![b"sealed-0".to_vec(), b"sealed-1".to_vec(), b"sealed-2".to_vec()]
        );
        assert_eq!(reopened.append_durable(&[b"sealed-3".to_vec()]).unwrap(), 3, "logical offset continues past recovery");
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
            assert!(log.append_durable(&[b"good".to_vec(), huge]).is_err(), "oversize record fails the batch");
            // The index is reconciled to disk: the one durable frame is counted (not orphaned).
            assert_eq!(log.len(), 1, "the durable frame from the failed batch is reconciled live");
            // A later record therefore gets a STABLE offset that a restart will agree with.
            assert_eq!(log.append_durable(&[b"next".to_vec()]).unwrap(), 1);
        }
        let reopened = SealedPartitionLog::open(&dir).unwrap();
        assert_eq!(reopened.len(), 2, "restart recovers exactly the live count — no offset shift");
        assert_eq!(reopened.read_sealed_from(0, 1 << 20).unwrap(), vec![b"good".to_vec(), b"next".to_vec()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_bytes_bounds_the_batch_but_always_returns_at_least_one() {
        let dir = tmpdir("maxbytes");
        let mut log = SealedPartitionLog::open(&dir).unwrap();
        log.append_durable(&[vec![1u8; 100], vec![2u8; 100], vec![3u8; 100]]).unwrap();
        // A tiny cap still returns exactly one record (progress guarantee).
        assert_eq!(log.read_sealed_from(0, 1).unwrap().len(), 1);
        // A cap that fits ~two records stops early (does not over-read the whole log).
        assert_eq!(log.read_sealed_from(0, 150).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
