//! The single-node Kafka consumer-group **coordinator** (`KAFKA-REBALANCE-DESIGN.md`, increment 4b): the state
//! machine behind `JoinGroup`/`SyncGroup`/`Heartbeat`/`LeaveGroup` that assigns partitions to group members
//! automatically. It is broker-side **protocol** state (independent of the sealed store), shared across connection
//! threads via one `Mutex` + a `Condvar`. Membership is runtime state (not persisted — like Kafka's
//! coordinator-side group state); durable committed OFFSETS persist separately (`KAFKA-GROUPS-DESIGN.md`).
//!
//! **Concurrency model (the crux).** `JoinGroup` parks the connection thread until the join window closes (a fixed
//! initial rebalance delay, exactly like Kafka's `group.initial.rebalance.delay.ms`); a follower's `SyncGroup`
//! parks until the leader submits assignments. Every park is a bounded `wait_timeout`, so progress is guaranteed
//! even with no notification — no permanent park, no deadlock (one lock, no nesting, predicates re-checked under
//! the lock after each wake). The assignment bytes are opaque (the client leader computed them); we only route.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

// Kafka error codes used by the group protocol.
/// NONE.
pub const NONE: i16 = 0;
/// `ILLEGAL_GENERATION` — the request's generation does not match the group's.
pub const ILLEGAL_GENERATION: i16 = 22;
/// `UNKNOWN_MEMBER_ID` — the member is not (or no longer) part of the group.
pub const UNKNOWN_MEMBER_ID: i16 = 25;
/// `REBALANCE_IN_PROGRESS` — a rebalance started; the member must rejoin.
pub const REBALANCE_IN_PROGRESS: i16 = 27;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum GroupState {
    Empty,
    PreparingRebalance,
    CompletingRebalance,
    Stable,
}

struct Member {
    /// The member's `JoinGroup` protocol metadata (subscription) — the leader needs every member's.
    subscription: Vec<u8>,
    /// Assignor protocol names the member supports (for selecting a common protocol).
    protocols: Vec<String>,
    /// The assignment the leader gave this member (set by the leader's `SyncGroup`), returned to it.
    assignment: Option<Vec<u8>>,
    last_heartbeat: Instant,
    session_timeout: Duration,
    /// How long the member is willing to wait for a rebalance (its advertised `rebalance_timeout_ms`); bounds how
    /// long it parks in `SyncGroup` for the leader's assignments (audit 4b LOW: was a fixed coordinator timeout).
    rebalance_timeout: Duration,
}

struct Group {
    state: GroupState,
    generation: i32,
    protocol_type: String,
    protocol: Option<String>,
    leader: Option<String>,
    members: BTreeMap<String, Member>,
    /// When the open join window closes (`PreparingRebalance` → `CompletingRebalance`).
    deadline: Option<Instant>,
    /// Monotonic per-group counter for generated member ids.
    member_seq: u64,
}

impl Group {
    fn new() -> Self {
        Self {
            state: GroupState::Empty,
            generation: 0,
            protocol_type: String::new(),
            protocol: None,
            leader: None,
            members: BTreeMap::new(),
            deadline: None,
            member_seq: 0,
        }
    }

    /// Evict members whose session has expired (no heartbeat within `session_timeout`); if that empties the group
    /// or removes the leader mid-flight, reflect it. Returns true if anything was removed.
    fn expire_stale(&mut self, now: Instant) -> bool {
        let before = self.members.len();
        self.members
            .retain(|_, m| now.duration_since(m.last_heartbeat) < m.session_timeout);
        let removed = self.members.len() != before;
        if removed {
            if self.members.is_empty() {
                self.state = GroupState::Empty;
                self.leader = None;
            } else if self
                .leader
                .as_ref()
                .is_some_and(|l| !self.members.contains_key(l))
            {
                self.leader = self.members.keys().next().cloned();
            }
        }
        removed
    }

    /// Choose an assignor protocol supported by EVERY member (Kafka requires a common protocol); falls back to the
    /// first member's first protocol. Deterministic (ordered by the first member's preference).
    fn select_protocol(&self) -> Option<String> {
        let first = self.members.values().next()?;
        for name in &first.protocols {
            if self
                .members
                .values()
                .all(|m| m.protocols.iter().any(|p| p == name))
            {
                return Some(name.clone());
            }
        }
        first.protocols.first().cloned()
    }
}

/// One member's `JoinGroup` outcome.
pub struct JoinOutcome {
    /// Error code (0 = NONE).
    pub error_code: i16,
    /// The assigned generation.
    pub generation: i32,
    /// The selected assignor protocol name.
    pub protocol: String,
    /// The leader member id.
    pub leader: String,
    /// This member's id (newly assigned if the request's was empty).
    pub member_id: String,
    /// For the LEADER: every member's `(member_id, subscription)`; empty for followers.
    pub members: Vec<(String, Vec<u8>)>,
}

/// One member's `SyncGroup` outcome.
pub struct SyncOutcome {
    /// Error code (0 = NONE).
    pub error_code: i16,
    /// This member's assignment bytes (opaque; produced by the leader).
    pub assignment: Vec<u8>,
}

/// The shared group coordinator. One per broker, behind an `Arc`.
pub struct GroupCoordinator {
    groups: Mutex<HashMap<String, Group>>,
    cond: Condvar,
    /// The join window length (Kafka's `group.initial.rebalance.delay.ms`); all joiners within it share a
    /// generation. Configurable so tests can use a short window.
    rebalance_delay: Duration,
    /// How long a follower's `SyncGroup` parks for the leader's assignments before returning a retry.
    sync_timeout: Duration,
}

impl GroupCoordinator {
    /// A coordinator with explicit timings.
    #[must_use]
    pub fn new(rebalance_delay: Duration, sync_timeout: Duration) -> Self {
        Self {
            groups: Mutex::new(HashMap::new()),
            cond: Condvar::new(),
            rebalance_delay,
            sync_timeout,
        }
    }

    /// A coordinator with Kafka-like defaults (3 s initial rebalance delay, 30 s sync wait).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(3), Duration::from_secs(30))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Group>> {
        self.groups.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `JoinGroup`: register (or refresh) a member and BLOCK until the join window closes, then return the
    /// finalized generation/leader/protocol (the leader also gets the member list). A brand-new member id is
    /// generated when `member_id` is empty.
    pub fn join(
        &self,
        group: &str,
        member_id: &str,
        session_timeout_ms: i32,
        rebalance_timeout_ms: i32,
        protocol_type: &str,
        protocols: &[(String, Vec<u8>)],
    ) -> JoinOutcome {
        let mut guard = self.lock();
        let now = Instant::now();
        let delay = self.rebalance_delay;
        let mid = {
            let g = guard.entry(group.to_owned()).or_insert_with(Group::new);
            g.expire_stale(now);
            let mid = if member_id.is_empty() {
                g.member_seq += 1;
                format!("datarail-{group}-{}", g.member_seq)
            } else {
                member_id.to_owned()
            };
            let session = Duration::from_millis(
                u64::try_from(session_timeout_ms)
                    .unwrap_or(30_000)
                    .clamp(1, 3_600_000),
            );
            let rebalance = Duration::from_millis(
                u64::try_from(rebalance_timeout_ms)
                    .unwrap_or(30_000)
                    .clamp(1, 3_600_000),
            );
            let (proto_names, subscription) = split_protocols(protocols);
            g.members.insert(
                mid.clone(),
                Member {
                    subscription,
                    protocols: proto_names,
                    assignment: None,
                    last_heartbeat: now,
                    session_timeout: session,
                    rebalance_timeout: rebalance,
                },
            );
            if !protocol_type.is_empty() {
                protocol_type.clone_into(&mut g.protocol_type);
            }
            // Start a new rebalance window unless one is already open (PreparingRebalance). A join during
            // CompletingRebalance (a member arriving after the window closed but before the leader synced) or
            // Stable must RESTART the rebalance — otherwise the late member joins a finalized generation and never
            // gets an assignment. (Kafka semantics: any join outside an open window re-opens it.)
            if !matches!(g.state, GroupState::PreparingRebalance) {
                g.state = GroupState::PreparingRebalance;
                g.generation = g.generation.checked_add(1).unwrap_or(1); // stay positive — never wrap to the -1 "unknown" sentinel (audit 4b LOW)
                g.deadline = Some(now + delay);
                // a new rebalance invalidates prior assignments
                for m in g.members.values_mut() {
                    m.assignment = None;
                }
            }
            mid
        };
        self.cond.notify_all();

        // Park until the join window closes (CompletingRebalance/Stable), or close it ourselves at the deadline.
        loop {
            let now = Instant::now();
            let (done, wait) = {
                let Some(g) = guard.get_mut(group) else {
                    return unknown_join(mid);
                };
                match g.state {
                    GroupState::CompletingRebalance | GroupState::Stable => (true, Duration::ZERO),
                    _ => {
                        if g.deadline.is_some_and(|dl| now >= dl) {
                            // Close the window: finalize this generation.
                            g.state = GroupState::CompletingRebalance;
                            g.leader = g.members.keys().next().cloned();
                            g.protocol = g.select_protocol();
                            (true, Duration::ZERO)
                        } else {
                            let wait = g
                                .deadline
                                .map_or(delay, |dl| dl.saturating_duration_since(now));
                            (false, wait)
                        }
                    }
                }
            };
            if done {
                self.cond.notify_all();
                break;
            }
            guard = self
                .cond
                .wait_timeout(guard, wait)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }

        let Some(g) = guard.get(group) else {
            return unknown_join(mid);
        };
        let is_leader = g.leader.as_deref() == Some(mid.as_str());
        let members = if is_leader {
            g.members
                .iter()
                .map(|(id, m)| (id.clone(), m.subscription.clone()))
                .collect()
        } else {
            Vec::new()
        };
        JoinOutcome {
            error_code: NONE,
            generation: g.generation,
            protocol: g.protocol.clone().unwrap_or_default(),
            leader: g.leader.clone().unwrap_or_default(),
            member_id: mid,
            members,
        }
    }

    /// `SyncGroup`: the leader carries `assignments` (`member_id` → bytes); store them and go `Stable`. A follower
    /// passes empty assignments and PARKS until its assignment is set (or `sync_timeout`).
    pub fn sync(
        &self,
        group: &str,
        member_id: &str,
        generation: i32,
        assignments: &[(String, Vec<u8>)],
    ) -> SyncOutcome {
        let mut guard = self.lock();
        let park_for = {
            let Some(g) = guard.get_mut(group) else {
                return SyncOutcome {
                    error_code: UNKNOWN_MEMBER_ID,
                    assignment: Vec::new(),
                };
            };
            if !g.members.contains_key(member_id) {
                return SyncOutcome {
                    error_code: UNKNOWN_MEMBER_ID,
                    assignment: Vec::new(),
                };
            }
            if g.generation != generation {
                return SyncOutcome {
                    error_code: ILLEGAL_GENERATION,
                    assignment: Vec::new(),
                };
            }
            // ONLY the leader's assignments are authoritative (audit 4b MEDIUM): a non-leader's `SyncGroup` must
            // not be able to drive the group to Stable or inject assignment bytes for other members. A follower's
            // assignments (if any) are ignored — it then parks for the leader's like a normal follower.
            if !assignments.is_empty() && g.leader.as_deref() == Some(member_id) {
                for (mid, bytes) in assignments {
                    if let Some(m) = g.members.get_mut(mid) {
                        m.assignment = Some(bytes.clone());
                    }
                }
                g.state = GroupState::Stable;
                g.deadline = None;
                self.cond.notify_all();
            }
            // Park bound = this member's OWN advertised rebalance timeout (already clamped to ≤1h at join), so a
            // client that declared a long patience for a slow leader is honored and they time out together — not
            // a fixed coordinator timeout that could give up early (audit 4b LOW).
            g.members
                .get(member_id)
                .map_or(self.sync_timeout, |m| m.rebalance_timeout)
        };

        let deadline = Instant::now() + park_for;
        loop {
            let now = Instant::now();
            let outcome = {
                let Some(g) = guard.get(group) else {
                    return SyncOutcome {
                        error_code: UNKNOWN_MEMBER_ID,
                        assignment: Vec::new(),
                    };
                };
                if g.generation != generation {
                    Some(SyncOutcome {
                        error_code: REBALANCE_IN_PROGRESS,
                        assignment: Vec::new(),
                    })
                } else if let Some(m) = g.members.get(member_id) {
                    if let Some(a) = &m.assignment {
                        Some(SyncOutcome {
                            error_code: NONE,
                            assignment: a.clone(),
                        })
                    } else if g.state == GroupState::Stable {
                        // Stable but the leader assigned us nothing → empty assignment.
                        Some(SyncOutcome {
                            error_code: NONE,
                            assignment: Vec::new(),
                        })
                    } else {
                        None
                    }
                } else {
                    Some(SyncOutcome {
                        error_code: UNKNOWN_MEMBER_ID,
                        assignment: Vec::new(),
                    })
                }
            };
            if let Some(o) = outcome {
                return o;
            }
            if now >= deadline {
                return SyncOutcome {
                    error_code: REBALANCE_IN_PROGRESS,
                    assignment: Vec::new(),
                };
            }
            guard = self
                .cond
                .wait_timeout(guard, deadline.saturating_duration_since(now))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// `Heartbeat`: refresh liveness; return NONE if `Stable` at the member's generation, `REBALANCE_IN_PROGRESS`
    /// if a rebalance is open, `ILLEGAL_GENERATION`/`UNKNOWN_MEMBER_ID` otherwise.
    pub fn heartbeat(&self, group: &str, member_id: &str, generation: i32) -> i16 {
        let mut guard = self.lock();
        let now = Instant::now();
        let Some(g) = guard.get_mut(group) else {
            return UNKNOWN_MEMBER_ID;
        };
        g.expire_stale(now);
        let Some(m) = g.members.get_mut(member_id) else {
            return UNKNOWN_MEMBER_ID;
        };
        m.last_heartbeat = now;
        if g.generation != generation {
            return ILLEGAL_GENERATION;
        }
        match g.state {
            GroupState::Stable => NONE,
            GroupState::PreparingRebalance | GroupState::CompletingRebalance => {
                REBALANCE_IN_PROGRESS
            }
            GroupState::Empty => UNKNOWN_MEMBER_ID,
        }
    }

    /// `LeaveGroup`: remove a member and trigger a rebalance for the rest (or empty the group).
    pub fn leave(&self, group: &str, member_id: &str) -> i16 {
        let mut guard = self.lock();
        let now = Instant::now();
        let Some(g) = guard.get_mut(group) else {
            return UNKNOWN_MEMBER_ID;
        };
        if g.members.remove(member_id).is_none() {
            return UNKNOWN_MEMBER_ID;
        }
        if g.members.is_empty() {
            g.state = GroupState::Empty;
            g.leader = None;
            g.deadline = None;
        } else {
            g.state = GroupState::PreparingRebalance;
            g.generation = g.generation.checked_add(1).unwrap_or(1); // stay positive — never wrap to the -1 "unknown" sentinel (audit 4b LOW)
            g.deadline = Some(now + self.rebalance_delay);
            if g.leader.as_deref() == Some(member_id) {
                g.leader = g.members.keys().next().cloned();
            }
            for m in g.members.values_mut() {
                m.assignment = None;
            }
        }
        self.cond.notify_all();
        NONE
    }
}

/// Split a member's advertised `(protocol_name, metadata)` list into the names (for protocol selection) and the
/// chosen subscription metadata (the first protocol's — what the leader needs). Empty if none.
fn split_protocols(protocols: &[(String, Vec<u8>)]) -> (Vec<String>, Vec<u8>) {
    let names = protocols.iter().map(|(n, _)| n.clone()).collect();
    let subscription = protocols
        .first()
        .map(|(_, m)| m.clone())
        .unwrap_or_default();
    (names, subscription)
}

fn unknown_join(member_id: String) -> JoinOutcome {
    JoinOutcome {
        error_code: UNKNOWN_MEMBER_ID,
        generation: -1,
        protocol: String::new(),
        leader: String::new(),
        member_id,
        members: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{GroupCoordinator, NONE};
    use std::sync::Arc;
    use std::time::Duration;

    fn fast() -> GroupCoordinator {
        // Short windows so tests are quick.
        GroupCoordinator::new(Duration::from_millis(150), Duration::from_secs(2))
    }

    fn proto() -> Vec<(String, Vec<u8>)> {
        vec![("range".to_owned(), b"sub".to_vec())]
    }

    #[test]
    fn single_member_joins_becomes_leader_syncs_and_heartbeats_stable() {
        let c = fast();
        let j = c.join("g", "", 30_000, 30_000, "consumer", &proto());
        assert_eq!(j.error_code, NONE);
        assert_eq!(j.leader, j.member_id, "the sole member is the leader");
        assert_eq!(j.members.len(), 1, "leader sees the full member list");
        assert_eq!(j.protocol, "range");
        // Leader assigns itself.
        let s = c.sync(
            "g",
            &j.member_id,
            j.generation,
            &[(j.member_id.clone(), b"assign-0".to_vec())],
        );
        assert_eq!(s.error_code, NONE);
        assert_eq!(s.assignment, b"assign-0");
        // Heartbeat at the live generation → NONE (stable).
        assert_eq!(c.heartbeat("g", &j.member_id, j.generation), NONE);
        // Stale generation → not NONE.
        assert_ne!(c.heartbeat("g", &j.member_id, j.generation - 1), NONE);
    }

    #[test]
    fn two_members_join_one_generation_leader_assigns_both() {
        let c = Arc::new(fast());
        let c2 = Arc::clone(&c);
        let h = std::thread::spawn(move || c2.join("g", "", 30_000, 30_000, "consumer", &proto()));
        // Slight stagger, both within the 150 ms window.
        std::thread::sleep(Duration::from_millis(20));
        let a = c.join("g", "", 30_000, 30_000, "consumer", &proto());
        let b = h.join().expect("thread");
        assert_eq!(
            a.generation, b.generation,
            "both joiners share one generation"
        );
        assert_eq!(a.leader, b.leader, "agree on the leader");
        // Exactly one is the leader and sees both members.
        let (leader, follower) = if a.member_id == a.leader {
            (a, b)
        } else {
            (b, a)
        };
        assert_eq!(leader.members.len(), 2, "leader sees both members");
        assert!(follower.members.is_empty(), "follower gets no member list");
        // Leader assigns disjoint work to both; follower's SyncGroup (empty) parks until then.
        let lid = leader.member_id.clone();
        let fid = follower.member_id.clone();
        let gen = leader.generation;
        let cc = Arc::clone(&c);
        let fh = std::thread::spawn(move || cc.sync("g", &fid, gen, &[]));
        std::thread::sleep(Duration::from_millis(20));
        let ls = c.sync(
            "g",
            &lid,
            gen,
            &[
                (lid.clone(), b"L".to_vec()),
                (follower.member_id.clone(), b"F".to_vec()),
            ],
        );
        let fs = fh.join().expect("thread");
        assert_eq!(ls.assignment, b"L");
        assert_eq!(
            fs.assignment, b"F",
            "follower received the leader's assignment after parking"
        );
    }

    #[test]
    fn only_the_leader_can_submit_assignments() {
        // Audit 4b MEDIUM regression: a FOLLOWER's SyncGroup assignments must be IGNORED — it cannot drive the
        // group Stable nor inject assignment bytes; only the leader's are authoritative.
        let c = Arc::new(fast());
        let c2 = Arc::clone(&c);
        let h = std::thread::spawn(move || c2.join("g", "", 30_000, 30_000, "consumer", &proto()));
        std::thread::sleep(Duration::from_millis(20));
        let a = c.join("g", "", 30_000, 30_000, "consumer", &proto());
        let b = h.join().expect("thread");
        let gen = a.generation;
        let (leader_id, follower_id) = if a.member_id == a.leader {
            (a.member_id, b.member_id)
        } else {
            (b.member_id, a.member_id)
        };

        // The follower tries to inject assignments for everyone — these must be ignored, so it parks for the
        // leader's real sync (run in a thread).
        let cc = Arc::clone(&c);
        let (fid, lid) = (follower_id.clone(), leader_id.clone());
        let fh = std::thread::spawn(move || {
            cc.sync(
                "g",
                &fid,
                gen,
                &[
                    (fid.clone(), b"INJECTED-F".to_vec()),
                    (lid, b"INJECTED-L".to_vec()),
                ],
            )
        });
        std::thread::sleep(Duration::from_millis(40));
        // The leader's legit sync is authoritative.
        let ls = c.sync(
            "g",
            &leader_id,
            gen,
            &[
                (leader_id.clone(), b"L".to_vec()),
                (follower_id.clone(), b"F".to_vec()),
            ],
        );
        let fs = fh.join().expect("thread");
        assert_eq!(ls.assignment, b"L", "leader gets its own assignment");
        assert_eq!(
            fs.assignment, b"F",
            "follower gets the LEADER's assignment, not its injected bytes"
        );
        assert_ne!(
            fs.assignment, b"INJECTED-F",
            "the follower's self-injected assignment was rejected"
        );
    }

    #[test]
    fn leaving_triggers_a_rebalance_for_the_rest() {
        let c = Arc::new(fast());
        // Two members in ONE generation (join concurrently within the window).
        let c2 = Arc::clone(&c);
        let h = std::thread::spawn(move || c2.join("g", "", 30_000, 30_000, "consumer", &proto()));
        std::thread::sleep(Duration::from_millis(20));
        let a = c.join("g", "", 30_000, 30_000, "consumer", &proto());
        let b = h.join().expect("thread");
        let gen = a.generation;
        assert_eq!(a.generation, b.generation);
        // Stabilize: the leader assigns both.
        let leader = a.leader.clone();
        c.sync(
            "g",
            &leader,
            gen,
            &[
                (a.member_id.clone(), b"A".to_vec()),
                (b.member_id.clone(), b"B".to_vec()),
            ],
        );
        assert_eq!(
            c.heartbeat("g", &a.member_id, gen),
            NONE,
            "stable before the leave"
        );
        // One leaves; the survivor must be told to rejoin (NOT NONE). leave() bumps the generation immediately, so
        // a heartbeat at the OLD generation returns ILLEGAL_GENERATION (a new-generation HB would be
        // REBALANCE_IN_PROGRESS) — either way, not stable.
        assert_eq!(c.leave("g", &a.member_id), NONE);
        assert_ne!(
            c.heartbeat("g", &b.member_id, gen),
            NONE,
            "survivor told to rejoin (not stable)"
        );
    }
}
