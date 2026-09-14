//! The single-node Kafka **transaction coordinator** (`KAFKA-TXN-DESIGN.md`): the state behind a transactional
//! producer — `InitProducerId(transactional_id)` (epoch fencing), `AddPartitionsToTxn`, `AddOffsetsToTxn`,
//! `TxnOffsetCommit`, `EndTxn`. It tracks, per `transactional_id`, the `(producer_id, epoch)` and the partitions +
//! staged offsets enrolled in the CURRENT transaction, so `EndTxn` can tell the serve layer where to write
//! COMMIT/ABORT markers and which offsets to durably commit. Runtime state (a broker restart aborts in-flight
//! txns — ratified Q3); durable txn state is later.
//!
//! **Epoch fencing (the crux).** `InitProducerId` on an existing `transactional_id` bumps the producer epoch,
//! fencing any prior incarnation: a Produce / `AddPartitions` / `EndTxn` carrying a stale epoch is rejected with
//! `INVALID_PRODUCER_EPOCH`, so a zombie producer from a previous session can never commit into a new one's txn.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, PoisonError};

use crate::codec::{write_response_header, Reader, Writer};

/// `AddPartitionsToTxn` API key.
pub const API_ADD_PARTITIONS_TO_TXN: i16 = 24;
/// `AddOffsetsToTxn` API key.
pub const API_ADD_OFFSETS_TO_TXN: i16 = 25;
/// `EndTxn` API key.
pub const API_END_TXN: i16 = 26;
/// `TxnOffsetCommit` API key.
pub const API_TXN_OFFSET_COMMIT: i16 = 28;

/// Smallest possible wire size of a topic array entry: a `string` length (2) + a partition-count `int32` (4).
const MIN_TOPIC_BYTES: usize = 6;
/// Smallest possible wire size of a partition array entry: at least an `int32`.
const MIN_PARTITION_BYTES: usize = 4;

/// NONE.
pub const NONE: i16 = 0;
/// `INVALID_PRODUCER_EPOCH` — the request's `(producer_id, epoch)` is fenced by a newer incarnation.
pub const INVALID_PRODUCER_EPOCH: i16 = 47;
/// `INVALID_TXN_STATE` — the operation is not valid in the txn's current state (e.g. `EndTxn` with no open txn).
pub const INVALID_TXN_STATE: i16 = 48;
/// `CONCURRENT_TRANSACTIONS` (retriable) — a partition is already claimed by another open txn; the producer must
/// retry after the holder commits/aborts. Enforces one open txn per partition (the buffer-model scope).
pub const CONCURRENT_TRANSACTIONS: i16 = 51;

/// Per-`transactional_id` coordinator state.
struct TxnState {
    producer_id: i64,
    epoch: i16,
    /// True between the first `AddPartitionsToTxn`/`AddOffsetsToTxn` and `EndTxn` (a txn is open).
    ongoing: bool,
    /// Partitions enrolled in the current txn (where COMMIT/ABORT markers must be written at `EndTxn`).
    partitions: BTreeSet<(String, i32)>,
    /// The consumer group whose offsets this txn commits (if any), and the staged `(topic, partition, offset)`s —
    /// applied durably only on `EndTxn(commit)`.
    group: Option<String>,
    staged_offsets: Vec<(String, i32, i64)>,
}

impl TxnState {
    fn new(producer_id: i64) -> Self {
        Self {
            producer_id,
            epoch: 0,
            ongoing: false,
            partitions: BTreeSet::new(),
            group: None,
            staged_offsets: Vec::new(),
        }
    }

    fn reset_txn(&mut self) {
        self.ongoing = false;
        self.partitions.clear();
        self.group = None;
        self.staged_offsets.clear();
    }
}

/// The result of `EndTxn`: the partitions needing a COMMIT/ABORT marker, plus (on commit) the offsets to durably
/// apply (`group`, `(topic, partition, offset)`).
pub struct EndTxnOutcome {
    /// Error code (0 = NONE).
    pub error_code: i16,
    /// Whether the txn committed (vs aborted) — the marker kind to write.
    pub committed: bool,
    /// Partitions to write the marker to.
    pub partitions: Vec<(String, i32)>,
    /// On commit: the consumer group + offsets to durably commit (empty on abort).
    pub group: Option<String>,
    /// On commit: `(topic, partition, offset)` to durably commit (empty on abort).
    pub offsets: Vec<(String, i32, i64)>,
}

/// The mutable shared state, behind one `Mutex`: per-id txn state + the global partition-claim table + the
/// `producer_id → transactional_id` reverse index (the Produce path carries only the `producer_id`).
#[derive(Default)]
struct TxnInner {
    txns: HashMap<String, TxnState>,
    /// Which `transactional_id` currently holds each `(topic, partition)` (one open txn per partition).
    claimed: HashMap<(String, i32), String>,
    /// `producer_id → transactional_id` — lets the Produce path fence a batch against the coordinator.
    by_producer: HashMap<i64, String>,
}

impl TxnInner {
    /// Release every partition claim held by `transactional_id` (on `EndTxn` or on re-init/fence).
    fn release_claims(&mut self, transactional_id: &str) {
        self.claimed.retain(|_, holder| holder != transactional_id);
    }
}

/// The single-node transaction coordinator.
pub struct TxnCoordinator {
    inner: Mutex<TxnInner>,
    /// Allocates `producer_id`s for transactional producers.
    next_producer_id: AtomicI64,
}

impl TxnCoordinator {
    /// A coordinator allocating `producer_id`s from `first_producer_id` upward (kept distinct from the idempotent
    /// allocator's range by the caller).
    #[must_use]
    pub fn new(first_producer_id: i64) -> Self {
        Self {
            inner: Mutex::new(TxnInner::default()),
            next_producer_id: AtomicI64::new(first_producer_id),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TxnInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `InitProducerId` for a `transactional_id`: assign a `producer_id` (new id for a new txn id) and BUMP the
    /// epoch (fencing any prior incarnation), aborting any in-flight txn from the old epoch. Returns
    /// `(producer_id, epoch)`.
    pub fn init_producer_id(&self, transactional_id: &str) -> (i64, i16) {
        let mut g = self.lock();
        if let Some(st) = g.txns.get_mut(transactional_id) {
            // Bump the epoch to fence the prior incarnation; on i16 overflow, mint a fresh producer_id at epoch 0.
            if let Some(next) = st.epoch.checked_add(1) {
                st.epoch = next;
            } else {
                st.producer_id = self.next_producer_id.fetch_add(1, Ordering::Relaxed);
                st.epoch = 0;
            }
            st.reset_txn(); // any in-flight txn of the old epoch is implicitly aborted
            let out = (st.producer_id, st.epoch);
            g.release_claims(transactional_id); // its old txn aborts → free its partitions
            g.by_producer.insert(out.0, transactional_id.to_owned()); // pid is reused; keep the index current
            out
        } else {
            let pid = self.next_producer_id.fetch_add(1, Ordering::Relaxed);
            let st = TxnState::new(pid);
            let out = (st.producer_id, st.epoch);
            g.txns.insert(transactional_id.to_owned(), st);
            g.by_producer.insert(pid, transactional_id.to_owned());
            out
        }
    }

    /// FENCE a transactional Produce batch (the Produce path carries only `(producer_id, epoch)` + the partition):
    /// returns `NONE` only if `(producer_id, epoch)` is the CURRENT incarnation AND the partition is in its OPEN
    /// txn — else `INVALID_PRODUCER_EPOCH` (a zombie / unknown producer) or `INVALID_TXN_STATE` (no open txn, or the
    /// partition was never `AddPartitionsToTxn`'d). This is what stops a stale-epoch zombie or an unclaimed-partition
    /// write from ever being buffered (audit: the Produce path was unfenced).
    #[must_use]
    pub fn produce_check(&self, producer_id: i64, epoch: i16, topic: &str, partition: i32) -> i16 {
        let g = self.lock();
        let Some(tid) = g.by_producer.get(&producer_id) else {
            return INVALID_PRODUCER_EPOCH;
        };
        let Some(st) = g.txns.get(tid) else {
            return INVALID_PRODUCER_EPOCH;
        };
        if st.producer_id != producer_id || st.epoch != epoch {
            return INVALID_PRODUCER_EPOCH; // fenced by a newer incarnation
        }
        if !st.ongoing || !st.partitions.contains(&(topic.to_owned(), partition)) {
            return INVALID_TXN_STATE; // no open txn, or this partition was not AddPartitionsToTxn'd
        }
        NONE
    }

    /// Verify `(producer_id, epoch)` against the current incarnation; `Ok(())` or an error code.
    fn fence(st: &TxnState, producer_id: i64, epoch: i16) -> i16 {
        if st.producer_id == producer_id && st.epoch == epoch {
            NONE
        } else {
            INVALID_PRODUCER_EPOCH
        }
    }

    /// `AddPartitionsToTxn`: enroll partitions in the current txn (opening it). Returns an error code.
    pub fn add_partitions(
        &self,
        transactional_id: &str,
        producer_id: i64,
        epoch: i16,
        partitions: &[(String, i32)],
    ) -> i16 {
        let mut g = self.lock();
        let TxnInner { txns, claimed, .. } = &mut *g;
        let Some(st) = txns.get_mut(transactional_id) else {
            return INVALID_PRODUCER_EPOCH;
        };
        let code = Self::fence(st, producer_id, epoch);
        if code != NONE {
            return code;
        }
        // One open txn per partition: if ANY requested partition is already claimed by a DIFFERENT txn, reject the
        // whole request (claim nothing) with a retriable CONCURRENT_TRANSACTIONS — the producer retries later.
        if partitions.iter().any(|p| {
            claimed
                .get(p)
                .is_some_and(|holder| holder.as_str() != transactional_id)
        }) {
            return CONCURRENT_TRANSACTIONS;
        }
        st.ongoing = true;
        for p in partitions {
            claimed.insert(p.clone(), transactional_id.to_owned());
            st.partitions.insert(p.clone());
        }
        NONE
    }

    /// `AddOffsetsToTxn`: record that this txn will commit offsets for `group` (opening it). Returns an error code.
    pub fn add_offsets(
        &self,
        transactional_id: &str,
        producer_id: i64,
        epoch: i16,
        group: &str,
    ) -> i16 {
        let mut g = self.lock();
        let Some(st) = g.txns.get_mut(transactional_id) else {
            return INVALID_PRODUCER_EPOCH;
        };
        let code = Self::fence(st, producer_id, epoch);
        if code != NONE {
            return code;
        }
        st.ongoing = true;
        st.group = Some(group.to_owned());
        NONE
    }

    /// `TxnOffsetCommit`: stage `(topic, partition, offset)`s to commit atomically at `EndTxn(commit)`.
    pub fn stage_offsets(
        &self,
        transactional_id: &str,
        producer_id: i64,
        epoch: i16,
        offsets: &[(String, i32, i64)],
    ) -> i16 {
        let mut g = self.lock();
        let Some(st) = g.txns.get_mut(transactional_id) else {
            return INVALID_PRODUCER_EPOCH;
        };
        let code = Self::fence(st, producer_id, epoch);
        if code != NONE {
            return code;
        }
        st.staged_offsets.extend_from_slice(offsets);
        NONE
    }

    /// `EndTxn` PREPARE: validate `(producer_id, epoch)` against an OPEN txn and return the partitions to flush +
    /// (on commit) the staged offsets — WITHOUT resetting. The caller flushes/discards the buffers durably and, only
    /// on success, calls [`finish_txn`](Self::finish_txn). Keeping the txn open until the durable flush succeeds is
    /// what lets a failed commit be RETRIED (audit: a swallowed mid-flush error must not be acked as success).
    pub fn end_txn(
        &self,
        transactional_id: &str,
        producer_id: i64,
        epoch: i16,
        commit: bool,
    ) -> EndTxnOutcome {
        let mut g = self.lock();
        let Some(st) = g.txns.get_mut(transactional_id) else {
            return EndTxnOutcome {
                error_code: INVALID_PRODUCER_EPOCH,
                committed: commit,
                partitions: Vec::new(),
                group: None,
                offsets: Vec::new(),
            };
        };
        let code = Self::fence(st, producer_id, epoch);
        if code != NONE {
            return EndTxnOutcome {
                error_code: code,
                committed: commit,
                partitions: Vec::new(),
                group: None,
                offsets: Vec::new(),
            };
        }
        if !st.ongoing {
            return EndTxnOutcome {
                error_code: INVALID_TXN_STATE,
                committed: commit,
                partitions: Vec::new(),
                group: None,
                offsets: Vec::new(),
            };
        }
        let partitions: Vec<(String, i32)> = st.partitions.iter().cloned().collect();
        let (group, offsets) = if commit {
            (st.group.clone(), st.staged_offsets.clone())
        } else {
            (None, Vec::new())
        };
        EndTxnOutcome {
            error_code: NONE,
            committed: commit,
            partitions,
            group,
            offsets,
        }
    }

    /// Finalize a resolved txn — reset its state (ready for the next) and free its partition claims. Called by the
    /// serve layer ONLY after the durable flush (commit) / discard (abort) succeeded. A stale completion cannot reset
    /// a newer producer epoch.
    pub fn finish_txn(&self, transactional_id: &str, producer_id: i64, epoch: i16) {
        let mut g = self.lock();
        if let Some(st) = g.txns.get_mut(transactional_id) {
            if st.producer_id == producer_id && st.epoch == epoch {
                st.reset_txn();
                g.release_claims(transactional_id);
            }
        }
    }
}

// ---- wire codec (non-flexible versions; flexible/tagged-field versions out of scope) ----

fn bounded(count: i32, reader: &Reader, min_entry: usize) -> usize {
    reader.bounded_count(count, min_entry)
}

/// Parse an `InitProducerId` request body (v0–v1): returns the `transactional_id` (`None` ⇒ a bare idempotent
/// producer, not transactional). The `transaction_timeout_ms` is consumed but unused.
///
/// # Errors
/// [`io::Error`] if malformed.
pub fn parse_init_producer_id(reader: &mut Reader) -> io::Result<Option<String>> {
    let transactional_id = reader.nullable_string()?;
    let _transaction_timeout_ms = reader.int32()?;
    Ok(transactional_id)
}

/// Build an `InitProducerId` response (v0–v1) — same shape as the idempotent grant, with the assigned epoch.
#[must_use]
pub fn init_producer_id_response(correlation_id: i32, producer_id: i64, epoch: i16) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    w.int32(0); // throttle_time_ms
    w.int16(NONE); // error_code
    w.int64(producer_id);
    w.int16(epoch);
    w.into_bytes()
}

/// A parsed `(transactional_id, producer_id, epoch)` prefix shared by the txn APIs.
struct TxnHeader {
    transactional_id: String,
    producer_id: i64,
    epoch: i16,
}

fn parse_txn_header(reader: &mut Reader) -> io::Result<TxnHeader> {
    let transactional_id = reader.string()?;
    let producer_id = reader.int64()?;
    let epoch = reader.int16()?;
    Ok(TxnHeader {
        transactional_id,
        producer_id,
        epoch,
    })
}

/// A parsed `AddPartitionsToTxn` request.
#[derive(Debug, Clone)]
pub struct AddPartitionsRequest {
    /// Transactional id.
    pub transactional_id: String,
    /// Producer id.
    pub producer_id: i64,
    /// Producer epoch.
    pub epoch: i16,
    /// `(topic, partitions)` to enroll.
    pub topics: Vec<(String, Vec<i32>)>,
}

/// Parse `AddPartitionsToTxn` (v0–v1).
///
/// # Errors
/// [`io::Error`] if malformed.
pub fn parse_add_partitions(
    reader: &mut Reader,
    _version: i16,
) -> io::Result<AddPartitionsRequest> {
    let h = parse_txn_header(reader)?;
    let tc = bounded(reader.int32()?, reader, MIN_TOPIC_BYTES);
    let mut topics = Vec::new();
    for _ in 0..tc {
        let name = reader.string()?;
        let pc = bounded(reader.int32()?, reader, MIN_PARTITION_BYTES);
        let mut parts = Vec::new();
        for _ in 0..pc {
            parts.push(reader.int32()?);
        }
        topics.push((name, parts));
    }
    Ok(AddPartitionsRequest {
        transactional_id: h.transactional_id,
        producer_id: h.producer_id,
        epoch: h.epoch,
        topics,
    })
}

/// Build an `AddPartitionsToTxn` response mirroring the topics/partitions, each with `error_code`.
#[must_use]
pub fn add_partitions_response(
    correlation_id: i32,
    topics: &[(String, Vec<i32>)],
    error_code: i16,
) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    w.int32(0); // throttle_time_ms
    w.int32(i32::try_from(topics.len()).unwrap_or(0));
    for (name, parts) in topics {
        w.string(name);
        w.int32(i32::try_from(parts.len()).unwrap_or(0));
        for &p in parts {
            w.int32(p);
            w.int16(error_code);
        }
    }
    w.into_bytes()
}

/// Parse `AddOffsetsToTxn` (v0–v1) → `(transactional_id, producer_id, epoch, group_id)`.
///
/// # Errors
/// [`io::Error`] if malformed.
pub fn parse_add_offsets(
    reader: &mut Reader,
    _version: i16,
) -> io::Result<(String, i64, i16, String)> {
    let h = parse_txn_header(reader)?;
    let group_id = reader.string()?;
    Ok((h.transactional_id, h.producer_id, h.epoch, group_id))
}

/// Build a simple throttle+error txn response (`AddOffsetsToTxn` / `EndTxn`).
#[must_use]
pub fn throttle_error_response(correlation_id: i32, error_code: i16) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    w.int32(0); // throttle_time_ms
    w.int16(error_code);
    w.into_bytes()
}

/// A parsed `TxnOffsetCommit` request.
#[derive(Debug, Clone)]
pub struct TxnOffsetCommitRequest {
    /// Transactional id.
    pub transactional_id: String,
    /// Consumer group whose offsets the txn commits.
    pub group_id: String,
    /// Producer id.
    pub producer_id: i64,
    /// Producer epoch.
    pub epoch: i16,
    /// `(topic, partition, committed_offset)` to stage.
    pub offsets: Vec<(String, i32, i64)>,
    /// Echo of the topic/partition structure (for the response).
    pub topics: Vec<(String, Vec<i32>)>,
}

/// Parse `TxnOffsetCommit` (v0–v1).
///
/// # Errors
/// [`io::Error`] if malformed.
pub fn parse_txn_offset_commit(
    reader: &mut Reader,
    _version: i16,
) -> io::Result<TxnOffsetCommitRequest> {
    let transactional_id = reader.string()?;
    let group_id = reader.string()?;
    let producer_id = reader.int64()?;
    let epoch = reader.int16()?;
    let tc = bounded(reader.int32()?, reader, MIN_TOPIC_BYTES);
    let mut offsets = Vec::new();
    let mut topics = Vec::new();
    for _ in 0..tc {
        let name = reader.string()?;
        let pc = bounded(reader.int32()?, reader, MIN_PARTITION_BYTES);
        let mut parts = Vec::new();
        for _ in 0..pc {
            let partition = reader.int32()?;
            let committed_offset = reader.int64()?;
            let _metadata = reader.nullable_string()?;
            offsets.push((name.clone(), partition, committed_offset));
            parts.push(partition);
        }
        topics.push((name, parts));
    }
    Ok(TxnOffsetCommitRequest {
        transactional_id,
        group_id,
        producer_id,
        epoch,
        offsets,
        topics,
    })
}

/// Parse `EndTxn` (v0–v1) → `(transactional_id, producer_id, epoch, committed)`.
///
/// # Errors
/// [`io::Error`] if malformed.
pub fn parse_end_txn(reader: &mut Reader, _version: i16) -> io::Result<(String, i64, i16, bool)> {
    let h = parse_txn_header(reader)?;
    let committed = reader.int8()? != 0;
    Ok((h.transactional_id, h.producer_id, h.epoch, committed))
}

#[cfg(test)]
mod tests {
    use super::{
        add_partitions_response, init_producer_id_response, parse_add_offsets,
        parse_add_partitions, parse_end_txn, parse_init_producer_id, parse_txn_offset_commit,
        throttle_error_response, TxnCoordinator, CONCURRENT_TRANSACTIONS, INVALID_PRODUCER_EPOCH,
        INVALID_TXN_STATE, NONE,
    };
    use crate::codec::{Reader, Writer};

    #[test]
    fn one_open_txn_per_partition_is_enforced() {
        let c = TxnCoordinator::new(1000);
        let (pa, ea) = c.init_producer_id("tx-A");
        let (pb, eb) = c.init_producer_id("tx-B");
        // A claims events:0.
        assert_eq!(
            c.add_partitions("tx-A", pa, ea, &[("events".to_owned(), 0)]),
            NONE
        );
        // B cannot claim the same partition while A's txn is open → retriable CONCURRENT_TRANSACTIONS.
        assert_eq!(
            c.add_partitions("tx-B", pb, eb, &[("events".to_owned(), 0)]),
            CONCURRENT_TRANSACTIONS,
            "a second open txn on the same partition is rejected"
        );
        // B CAN claim a different partition.
        assert_eq!(
            c.add_partitions("tx-B", pb, eb, &[("events".to_owned(), 1)]),
            NONE
        );
        // After A finishes, B can claim events:0 (claims free on finish_txn, not the prepare).
        assert_eq!(c.end_txn("tx-A", pa, ea, true).error_code, NONE);
        c.finish_txn("tx-A", pa, ea);
        assert_eq!(
            c.add_partitions("tx-B", pb, eb, &[("events".to_owned(), 0)]),
            NONE,
            "the partition frees on finish_txn"
        );
    }

    #[test]
    fn init_bumps_epoch_and_fences_the_prior_incarnation() {
        let c = TxnCoordinator::new(1000);
        let (pid1, ep1) = c.init_producer_id("tx-A");
        assert_eq!(ep1, 0);
        // A second InitProducerId for the same id keeps the producer_id but bumps the epoch.
        let (pid2, ep2) = c.init_producer_id("tx-A");
        assert_eq!(pid2, pid1, "same transactional_id keeps its producer_id");
        assert_eq!(ep2, 1, "epoch bumped — the prior incarnation is fenced");
        // The OLD epoch is now fenced.
        assert_eq!(
            c.add_partitions("tx-A", pid1, ep1, &[("t".to_owned(), 0)]),
            INVALID_PRODUCER_EPOCH,
            "a zombie at the old epoch is rejected"
        );
        // The new epoch works.
        assert_eq!(
            c.add_partitions("tx-A", pid2, ep2, &[("t".to_owned(), 0)]),
            NONE
        );
    }

    #[test]
    fn stale_finish_cannot_reset_new_epoch() {
        let c = TxnCoordinator::new(1000);
        let (old_pid, old_epoch) = c.init_producer_id("tx-A");
        assert_eq!(
            c.add_partitions("tx-A", old_pid, old_epoch, &[("t".to_owned(), 0)]),
            NONE
        );
        assert_eq!(c.end_txn("tx-A", old_pid, old_epoch, true).error_code, NONE);

        let (new_pid, new_epoch) = c.init_producer_id("tx-A");
        assert_eq!(new_pid, old_pid);
        assert_eq!(new_epoch, old_epoch + 1);
        assert_eq!(
            c.add_partitions("tx-A", new_pid, new_epoch, &[("t".to_owned(), 1)]),
            NONE
        );

        c.finish_txn("tx-A", old_pid, old_epoch);
        assert_eq!(c.produce_check(new_pid, new_epoch, "t", 1), NONE);
        assert_eq!(c.end_txn("tx-A", new_pid, new_epoch, true).error_code, NONE);
    }

    #[test]
    fn distinct_transactional_ids_get_distinct_producer_ids() {
        let c = TxnCoordinator::new(1000);
        let (pa, _) = c.init_producer_id("tx-A");
        let (pb, _) = c.init_producer_id("tx-B");
        assert_ne!(pa, pb);
    }

    #[test]
    fn commit_returns_partitions_and_staged_offsets_then_resets() {
        let c = TxnCoordinator::new(1000);
        let (pid, ep) = c.init_producer_id("tx-A");
        assert_eq!(
            c.add_partitions(
                "tx-A",
                pid,
                ep,
                &[("events".to_owned(), 0), ("events".to_owned(), 1)]
            ),
            NONE
        );
        assert_eq!(c.add_offsets("tx-A", pid, ep, "grp"), NONE);
        assert_eq!(
            c.stage_offsets("tx-A", pid, ep, &[("src".to_owned(), 0, 42)]),
            NONE
        );
        let out = c.end_txn("tx-A", pid, ep, true);
        assert_eq!(out.error_code, NONE);
        assert!(out.committed);
        assert_eq!(
            out.partitions.len(),
            2,
            "both enrolled partitions get a COMMIT marker"
        );
        assert_eq!(out.group.as_deref(), Some("grp"));
        assert_eq!(
            out.offsets,
            vec![("src".to_owned(), 0, 42)],
            "staged offsets committed atomically"
        );
        // EndTxn (prepare) does NOT reset — the txn stays open so a failed durable flush can be retried; a re-prepare
        // still validates.
        assert_eq!(
            c.end_txn("tx-A", pid, ep, true).error_code,
            NONE,
            "re-prepare is valid until finish"
        );
        // finish_txn resets it — a subsequent EndTxn has no open txn → INVALID_TXN_STATE.
        c.finish_txn("tx-A", pid, ep);
        assert_eq!(
            c.end_txn("tx-A", pid, ep, true).error_code,
            INVALID_TXN_STATE
        );
    }

    #[test]
    fn produce_check_fences_zombies_and_unclaimed_partitions() {
        let c = TxnCoordinator::new(1000);
        let (pid, ep) = c.init_producer_id("tx-A");
        c.add_partitions("tx-A", pid, ep, &[("events".to_owned(), 0)]);
        // A claimed partition at the current epoch → allowed.
        assert_eq!(c.produce_check(pid, ep, "events", 0), NONE);
        // An UNCLAIMED partition → rejected (it was never AddPartitionsToTxn'd).
        assert_eq!(c.produce_check(pid, ep, "events", 1), INVALID_TXN_STATE);
        // A STALE epoch (zombie) → fenced.
        assert_eq!(
            c.produce_check(pid, ep - 1, "events", 0),
            INVALID_PRODUCER_EPOCH
        );
        // After a re-init bumps the epoch, the old epoch is fenced on the produce path too.
        let (pid2, ep2) = c.init_producer_id("tx-A");
        assert_eq!(pid2, pid);
        assert_eq!(
            c.produce_check(pid, ep, "events", 0),
            INVALID_PRODUCER_EPOCH,
            "old epoch fenced after re-init"
        );
        // The new incarnation must re-claim before producing.
        assert_eq!(
            c.produce_check(pid2, ep2, "events", 0),
            INVALID_TXN_STATE,
            "must AddPartitions again"
        );
        c.add_partitions("tx-A", pid2, ep2, &[("events".to_owned(), 0)]);
        assert_eq!(c.produce_check(pid2, ep2, "events", 0), NONE);
        // An unknown producer id → fenced.
        assert_eq!(c.produce_check(999, 0, "events", 0), INVALID_PRODUCER_EPOCH);
    }

    #[test]
    fn txn_codec_round_trips_and_bounds_garbage() {
        // InitProducerId with a transactional_id.
        let mut w = Writer::new();
        w.nullable_string(Some("tx-A"));
        w.int32(60_000);
        let body = w.into_bytes();
        let mut r = Reader::new(&body);
        assert_eq!(
            parse_init_producer_id(&mut r).unwrap().as_deref(),
            Some("tx-A")
        );
        let resp = init_producer_id_response(7, 1000, 3);
        let mut rr = Reader::new(&resp);
        assert_eq!(rr.int32().unwrap(), 7); // corr
        assert_eq!(rr.int32().unwrap(), 0); // throttle
        assert_eq!(rr.int16().unwrap(), 0); // error
        assert_eq!(rr.int64().unwrap(), 1000); // producer_id
        assert_eq!(rr.int16().unwrap(), 3); // epoch

        // AddPartitionsToTxn round-trip.
        let mut w = Writer::new();
        w.string("tx-A");
        w.int64(1000);
        w.int16(3);
        w.int32(1); // 1 topic
        w.string("events");
        w.int32(2); // 2 partitions
        w.int32(0);
        w.int32(1);
        let body = w.into_bytes();
        let mut r = Reader::new(&body);
        let req = parse_add_partitions(&mut r, 1).unwrap();
        assert_eq!(req.transactional_id, "tx-A");
        assert_eq!(req.producer_id, 1000);
        assert_eq!(req.topics, vec![("events".to_owned(), vec![0, 1])]);
        let _ = add_partitions_response(7, &req.topics, NONE);

        // AddOffsetsToTxn + EndTxn.
        let mut w = Writer::new();
        w.string("tx-A");
        w.int64(1000);
        w.int16(3);
        w.string("grp");
        let body = w.into_bytes();
        let mut r = Reader::new(&body);
        assert_eq!(
            parse_add_offsets(&mut r, 1).unwrap(),
            ("tx-A".to_owned(), 1000, 3, "grp".to_owned())
        );
        let _ = throttle_error_response(7, NONE);

        let mut w = Writer::new();
        w.string("tx-A");
        w.int64(1000);
        w.int16(3);
        w.int8(1); // committed
        let body = w.into_bytes();
        let mut r = Reader::new(&body);
        assert_eq!(
            parse_end_txn(&mut r, 1).unwrap(),
            ("tx-A".to_owned(), 1000, 3, true)
        );

        // TxnOffsetCommit round-trip.
        let mut w = Writer::new();
        w.string("tx-A");
        w.string("grp");
        w.int64(1000);
        w.int16(3);
        w.int32(1);
        w.string("src");
        w.int32(1);
        w.int32(0);
        w.int64(42);
        w.nullable_string(None);
        let body = w.into_bytes();
        let mut r = Reader::new(&body);
        let toc = parse_txn_offset_commit(&mut r, 1).unwrap();
        assert_eq!(toc.offsets, vec![("src".to_owned(), 0, 42)]);

        // A lying topic count + filler must not panic / over-allocate.
        let mut w = Writer::new();
        w.string("tx");
        w.int64(1);
        w.int16(0);
        w.int32(i32::MAX);
        w.raw(&vec![0u8; 4096]);
        let body = w.into_bytes();
        let mut r = Reader::new(&body);
        let _ = parse_add_partitions(&mut r, 1);
    }

    #[test]
    fn abort_writes_markers_but_commits_no_offsets() {
        let c = TxnCoordinator::new(1000);
        let (pid, ep) = c.init_producer_id("tx-A");
        c.add_partitions("tx-A", pid, ep, &[("events".to_owned(), 0)]);
        c.stage_offsets("tx-A", pid, ep, &[("src".to_owned(), 0, 7)]);
        let out = c.end_txn("tx-A", pid, ep, false);
        assert_eq!(out.error_code, NONE);
        assert!(!out.committed);
        assert_eq!(
            out.partitions.len(),
            1,
            "the partition still gets an ABORT marker"
        );
        assert!(out.offsets.is_empty(), "an aborted txn commits NO offsets");
        assert!(out.group.is_none());
    }
}
