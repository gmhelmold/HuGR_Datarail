//! `datarail-topic` — the **integration layer**: it composes two independently-proven components —
//! [`datarail_replaylog`] (a retained, durable, flat-RAM replay log) and [`datarail_keyrouter`] (rendezvous key
//! routing) — into Kafka's *core* behaviour, built the leaner way.
//!
//! What it demonstrates, end to end:
//! - **Durable multi-consumer log** — many [`Group`]s read the same topic, each at its **own** offset, so they
//!   replay history independently. (Kafka's defining feature.)
//! - **Consumer groups with dynamic parallelism, no partitions** — within a group, each record is dispatched to
//!   the member that owns its key by rendezvous hashing. Parallelism = member count, changed any time.
//! - **No stop-the-world rebalance** — a member joining/leaving only changes routing for *future* records and
//!   only for ~1/N of keys; already-dispatched work and other members are untouched (monotonicity, proven in
//!   `datarail-keyrouter`).
//! - **Replay / rewind** — [`Group::seek`] rewinds a group to any offset; history is retained, so it re-dispatches.
//!
//! **Honest scope (integration milestone, not a finished broker).** This is the single-node *mechanism*: group
//! offsets are in-memory (durable offset commit — Kafka's `__consumer_offsets` — is future), there is no network
//! protocol or wire compatibility, the cold tier is the local filesystem (S3 GET-swap is future), and shard
//! placement / replication across nodes is future. It proves the proven components *compose* into the right
//! behaviour at flat RAM; it does not claim to be a drop-in Kafka cluster.

#![forbid(unsafe_code)]

use std::path::Path;

use datarail_keyrouter::Router;
use datarail_replaylog::{Replay, ReplayError, ReplayLog};

/// What can go wrong.
#[derive(Debug)]
pub enum TopicError {
    /// An error from the underlying retained log.
    Log(ReplayError),
    /// A stored record's framing was corrupt (truncated key length).
    Corrupt,
    /// The group has no members to route to (add one and retry — no record is consumed).
    NoMembers,
}

impl std::fmt::Display for TopicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Log(e) => write!(f, "topic log: {e}"),
            Self::Corrupt => f.write_str("topic record framing corrupt"),
            Self::NoMembers => f.write_str("topic group has no members to route to"),
        }
    }
}

impl std::error::Error for TopicError {}

impl From<ReplayError> for TopicError {
    fn from(e: ReplayError) -> Self {
        Self::Log(e)
    }
}

/// One dispatched record: which group **member** owns it (by key), its log `offset`, and the `key`/`payload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatched {
    /// The member id (from the group's [`Router`]) that owns this record's key.
    pub member: u64,
    /// The record's durable log offset (a valid [`Group::seek`] point).
    pub offset: u64,
    /// The record key (routing + ordering unit).
    pub key: Vec<u8>,
    /// The record payload.
    pub payload: Vec<u8>,
}

/// A durable, retained topic: an append-only [`ReplayLog`] of `(key, payload)` records.
pub struct Topic {
    log: ReplayLog,
}

impl Topic {
    /// Open (or create) a topic backed by a retained log in `dir`.
    ///
    /// # Errors
    /// [`TopicError::Log`] on a filesystem error.
    pub fn open(dir: impl AsRef<Path>, segment_bytes: u64) -> Result<Self, TopicError> {
        Ok(Self {
            log: ReplayLog::open(dir, segment_bytes)?,
        })
    }

    /// Append one `(key, payload)` record; returns its durable offset.
    ///
    /// # Errors
    /// [`TopicError::Log`] if the record exceeds the log's maximum or a write fails.
    pub fn produce(&mut self, key: &[u8], payload: &[u8]) -> Result<u64, TopicError> {
        // Record framing: [u32 key_len][key][payload].
        let key_len = u32::try_from(key.len()).map_err(|_| TopicError::Corrupt)?;
        let mut rec = Vec::with_capacity(4 + key.len() + payload.len());
        rec.extend_from_slice(&key_len.to_le_bytes());
        rec.extend_from_slice(key);
        rec.extend_from_slice(payload);
        Ok(self.log.append(&rec)?)
    }

    /// fsync the topic so produced records survive a power loss.
    ///
    /// # Errors
    /// [`TopicError::Log`] on an fsync error.
    pub fn sync(&mut self) -> Result<(), TopicError> {
        Ok(self.log.sync()?)
    }

    /// The current end offset (where the next produce will land).
    #[must_use]
    pub fn end_offset(&self) -> u64 {
        self.log.end_offset()
    }

    /// Dispatch the next record to its owning group member, advancing the group's cursor. Returns `None` at the
    /// end of the currently-retained log. Each call routes one record's key through the group's *current*
    /// membership — so a mid-stream join/leave affects only records dispatched after it.
    ///
    /// # Errors
    /// [`TopicError`] on a read or framing error.
    pub fn dispatch_next(&self, group: &mut Group) -> Result<Option<Dispatched>, TopicError> {
        // WP10 audit [HIGH] fix: fail BEFORE consuming a record if there is no one to route it to. Otherwise the
        // cursor/reader would advance past a record that was never dispatched → silent loss when a member rejoins.
        if group.router.is_empty() {
            return Err(TopicError::NoMembers);
        }
        // (Re)create the streaming reader at the group's cursor — picks up records produced since last time.
        if group.replay.is_none() {
            group.replay = Some(self.log.replay_from(group.cursor)?);
        }
        let reader = group.replay.as_mut().ok_or(TopicError::Corrupt)?;
        let Some((offset, rec)) = reader.read_next()? else {
            // Caught up. Drop the snapshot so a later call re-reads any newly-produced records.
            group.replay = None;
            return Ok(None);
        };
        let (key, payload) = split_record(&rec).ok_or(TopicError::Corrupt)?;
        // Advance the cursor to just past this record (its frame is 8 overhead + body).
        group.cursor = offset + 8 + rec.len() as u64;
        let member = group.router.route(key).ok_or(TopicError::Corrupt)?;
        Ok(Some(Dispatched {
            member,
            offset,
            key: key.to_vec(),
            payload: payload.to_vec(),
        }))
    }
}

/// Split a stored record `[u32 key_len][key][payload]` into `(key, payload)`.
fn split_record(rec: &[u8]) -> Option<(&[u8], &[u8])> {
    if rec.len() < 4 {
        return None;
    }
    let key_len = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]) as usize;
    let body = rec.get(4..)?;
    if key_len > body.len() {
        return None;
    }
    Some((&body[..key_len], &body[key_len..]))
}

/// A consumer group: a set of members (over which keys are rendezvous-routed) plus its **own** offset cursor
/// into the topic. Different groups have independent cursors → independent replay of the same durable history.
pub struct Group {
    router: Router,
    cursor: u64,
    replay: Option<Replay>,
}

impl Group {
    /// A group starting at offset 0 with the given member ids.
    #[must_use]
    pub fn new(members: &[u64]) -> Self {
        Self {
            router: Router::from_nodes(members),
            cursor: 0,
            replay: None,
        }
    }

    /// Add a member. Future records route through the larger set; already-dispatched records are untouched (no
    /// stop-the-world rebalance — only ~1/N of *future* keys shift, onto the new member).
    pub fn add_member(&mut self, id: u64) -> bool {
        self.router.add_node(id)
    }

    /// Remove a member. Future records owned by it route to their failover owner; everyone else is undisturbed.
    pub fn remove_member(&mut self, id: u64) -> bool {
        self.router.remove_node(id)
    }

    /// The group's current members.
    #[must_use]
    pub fn members(&self) -> &[u64] {
        self.router.nodes()
    }

    /// The group's current offset.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.cursor
    }

    /// Rewind (or fast-forward) the group to `offset` — replay retained history from any point.
    pub fn seek(&mut self, offset: u64) {
        self.cursor = offset;
        self.replay = None; // force the reader to be recreated at the new offset
    }
}

#[cfg(test)]
mod tests {
    use super::{Group, Topic};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("datarail-topic-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn drain_all(topic: &Topic, g: &mut Group) -> Vec<super::Dispatched> {
        let mut out = Vec::new();
        while let Some(d) = topic.dispatch_next(g).expect("dispatch") {
            out.push(d);
        }
        out
    }

    fn key_of(i: u32) -> Vec<u8> {
        format!("key-{}", i % 500).into_bytes() // 500 distinct keys
    }

    /// Integration: two consumer GROUPS replay the SAME durable history INDEPENDENTLY (each its own offset).
    #[test]
    fn two_groups_replay_the_same_history_independently() {
        let dir = tmpdir("multigroup");
        let mut topic = Topic::open(&dir, 1 << 16).expect("open");
        for i in 0..3000u32 {
            topic
                .produce(&key_of(i), format!("val-{i}").as_bytes())
                .expect("produce");
        }
        topic.sync().expect("sync");

        let mut a = Group::new(&[1, 2, 3]);
        let got_a = drain_all(&topic, &mut a);
        // Group B starts fresh at offset 0 — history was retained, so it sees everything too.
        let mut b = Group::new(&[7, 8]);
        let got_b = drain_all(&topic, &mut b);

        assert_eq!(got_a.len(), 3000, "group A did not see all records");
        assert_eq!(
            got_b.len(),
            3000,
            "group B did not independently replay all records"
        );
        // Same payloads, in the same log order, regardless of group membership.
        let pa: Vec<&Vec<u8>> = got_a.iter().map(|d| &d.payload).collect();
        let pb: Vec<&Vec<u8>> = got_b.iter().map(|d| &d.payload).collect();
        assert_eq!(pa, pb);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Integration: within a group, every record goes to its key's owner; union = all; per-key order preserved.
    #[test]
    fn in_group_distribution_covers_all_and_preserves_per_key_order() {
        use std::collections::HashMap;
        let dir = tmpdir("dist");
        let mut topic = Topic::open(&dir, 1 << 16).expect("open");
        for i in 0..4000u32 {
            topic
                .produce(&key_of(i), format!("{i}").as_bytes())
                .expect("produce");
        }
        topic.sync().expect("sync");

        let mut g = Group::new(&[10, 11, 12, 13]);
        let got = drain_all(&topic, &mut g);
        assert_eq!(got.len(), 4000);

        // Each key always landed on exactly one member; per-key the payloads are in produce order.
        let mut owner: HashMap<Vec<u8>, u64> = HashMap::new();
        let mut last_seq: HashMap<Vec<u8>, i64> = HashMap::new();
        for d in &got {
            let o = owner.entry(d.key.clone()).or_insert(d.member);
            assert_eq!(
                *o, d.member,
                "key routed to two different members (order broken)"
            );
            let seq: i64 = String::from_utf8_lossy(&d.payload).parse().expect("num");
            let prev = last_seq.entry(d.key.clone()).or_insert(-1);
            assert!(seq > *prev, "per-key order violated");
            *prev = seq;
        }
        // All 4 members got work (parallelism is real, no idle partitions).
        let members: std::collections::HashSet<u64> = got.iter().map(|d| d.member).collect();
        assert_eq!(members.len(), 4, "not all members received work");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Integration: a member joins MID-STREAM — already-dispatched work is untouched, only later records can use
    /// the new member, and the other members keep their keys. No global stall.
    #[test]
    fn member_joining_mid_stream_does_not_reshuffle_dispatched_work() {
        let dir = tmpdir("join");
        let mut topic = Topic::open(&dir, 1 << 16).expect("open");
        for i in 0..2000u32 {
            topic
                .produce(&key_of(i), format!("{i}").as_bytes())
                .expect("produce");
        }
        topic.sync().expect("sync");

        let mut g = Group::new(&[1, 2, 3]);
        // Dispatch the first half with 3 members.
        let mut first = Vec::new();
        for _ in 0..1000 {
            first.push(topic.dispatch_next(&mut g).expect("d").expect("some"));
        }
        // A 4th member joins mid-stream.
        assert!(g.add_member(4));
        let mut second = Vec::new();
        while let Some(d) = topic.dispatch_next(&mut g).expect("d") {
            second.push(d);
        }
        assert_eq!(
            first.len() + second.len(),
            2000,
            "lost records across the join"
        );
        // The new member can only appear AFTER the join (never retroactively).
        assert!(
            first.iter().all(|d| d.member != 4),
            "new member got pre-join work — that's a reshuffle"
        );
        assert!(
            second.iter().any(|d| d.member == 4),
            "new member never received post-join work"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Integration: a group can REWIND and replay retained history (Kafka's reprocess-from-offset).
    #[test]
    fn group_can_rewind_and_replay_history() {
        let dir = tmpdir("rewind");
        let mut topic = Topic::open(&dir, 1 << 16).expect("open");
        let mut offsets = Vec::new();
        for i in 0..1000u32 {
            offsets.push(
                topic
                    .produce(&key_of(i), format!("{i}").as_bytes())
                    .expect("produce"),
            );
        }
        topic.sync().expect("sync");

        let mut g = Group::new(&[1, 2]);
        let first = drain_all(&topic, &mut g);
        assert_eq!(first.len(), 1000);
        // Rewind to the 600th record and replay the tail.
        g.seek(offsets[600]);
        let replayed = drain_all(&topic, &mut g);
        assert_eq!(
            replayed.len(),
            400,
            "rewind+replay did not re-yield the retained tail"
        );
        assert_eq!(replayed[0].offset, offsets[600]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WP10 audit [HIGH] regression: a group drained to zero members must NOT consume a record — it errors, and
    /// after a member rejoins the record is still dispatched (no silent loss).
    #[test]
    fn dispatch_to_an_empty_group_consumes_nothing_then_recovers() {
        let dir = tmpdir("nomembers");
        let mut topic = Topic::open(&dir, 1 << 16).expect("open");
        for i in 0..50u32 {
            topic
                .produce(&key_of(i), format!("{i}").as_bytes())
                .expect("produce");
        }
        topic.sync().expect("sync");

        let mut g = Group::new(&[1]);
        // Drain a few, then the only member leaves → group is empty.
        for _ in 0..10 {
            topic.dispatch_next(&mut g).expect("d").expect("some");
        }
        assert!(g.remove_member(1));
        match topic.dispatch_next(&mut g) {
            Err(super::TopicError::NoMembers) => {}
            other => panic!("expected NoMembers, got {other:?}"),
        }
        // A member rejoins; the 11th record (never consumed) must be the next one dispatched.
        assert!(g.add_member(2));
        let rest = drain_all(&topic, &mut g);
        assert_eq!(
            rest.len(),
            40,
            "records were lost across the empty-group window"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
