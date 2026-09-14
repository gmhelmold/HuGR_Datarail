//! `datarail-keyrouter` — **rendezvous (highest-random-weight) key routing**, the single mechanism that answers
//! two of Kafka's wastes at once.
//!
//! **Ledger #5 — partition count.** Kafka fixes the partition count up front; it caps parallelism, can't shrink,
//! and each partition costs files + RAM + a leader. Here there are **no partitions**: a key is routed to a
//! consumer by `argmax_node hash(key, node)`. Parallelism is simply the number of consumers — change it any time.
//! Same key → same consumer (per-key order preserved); the load spreads ~evenly with zero configuration.
//!
//! **Ledger #6 — rebalance hell.** Kafka's consumer-group rebalance is stop-the-world: a join/leave can reshuffle
//! *every* assignment. Rendezvous hashing is **monotonic**: adding a node moves a key only if the new node
//! out-weighs its current owner (so keys move *only to* the new node, never between two existing nodes); removing
//! a node remaps *only* the keys it owned (everyone else is untouched). Expected churn on a membership change is
//! ~`1/N` of keys — provably minimal, no global barrier.
//!
//! Pure, `#![forbid(unsafe_code)]`, zero-dependency, O(N) per route (N = consumer count, typically small).

#![forbid(unsafe_code)]

/// 64-bit avalanche mix (splitmix64/murmur3 finalizer) — turns a counter/id into a well-distributed value.
#[must_use]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^= x >> 33;
    x
}

/// FNV-1a 64-bit hash of a key's bytes.
#[must_use]
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The rendezvous weight of `(key_hash, node)`: independent across nodes, deterministic, well-spread.
#[must_use]
fn weight(key_hash: u64, node: u64) -> u64 {
    mix64(key_hash ^ mix64(node))
}

/// A set of consumer nodes (each a caller-assigned stable `u64` id) over which keys are routed by rendezvous
/// hashing. No partition count, no coordinator — membership is just this list.
#[derive(Debug, Clone, Default)]
pub struct Router {
    nodes: Vec<u64>,
}

impl Router {
    /// An empty router (no nodes — every route returns `None`).
    #[must_use]
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Build from an initial node set (duplicates are collapsed).
    #[must_use]
    pub fn from_nodes(nodes: &[u64]) -> Self {
        let mut r = Self::new();
        for &n in nodes {
            r.add_node(n);
        }
        r
    }

    /// Add a consumer node. Returns `false` if it was already present.
    pub fn add_node(&mut self, id: u64) -> bool {
        if self.nodes.contains(&id) {
            return false;
        }
        self.nodes.push(id);
        true
    }

    /// Remove a consumer node. Returns `false` if it was not present.
    pub fn remove_node(&mut self, id: u64) -> bool {
        if let Some(i) = self.nodes.iter().position(|&n| n == id) {
            self.nodes.remove(i);
            true
        } else {
            false
        }
    }

    /// The current consumer nodes.
    #[must_use]
    pub fn nodes(&self) -> &[u64] {
        &self.nodes
    }

    /// The number of consumers — this *is* the parallelism (no separate partition count).
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether there are no consumers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Route a pre-hashed key to its owning consumer (the highest-weight node). `None` if there are no nodes.
    /// Ties (astronomically unlikely) break toward the smaller node id for determinism.
    #[must_use]
    pub fn route_keyhash(&self, key_hash: u64) -> Option<u64> {
        let mut best: Option<(u64, u64)> = None; // (weight, node)
        for &node in &self.nodes {
            let w = weight(key_hash, node);
            // Highest weight wins; on a (distinct-id ⇒ impossible) tie, the smaller id — matching the doc and
            // `rank_keyhash` so the `rank[0] == route` invariant holds even under hypothetical duplicate ids.
            let better = match best {
                None => true,
                Some((bw, bn)) => w > bw || (w == bw && node < bn),
            };
            if better {
                best = Some((w, node));
            }
        }
        best.map(|(_, n)| n)
    }

    /// Route a key (by its bytes) to its owning consumer. Same key → same consumer for a given membership.
    #[must_use]
    pub fn route(&self, key: &[u8]) -> Option<u64> {
        self.route_keyhash(fnv1a(key))
    }

    /// The full preference ranking of nodes for a key, highest-weight first. The 2nd entry is the failover owner
    /// if the 1st leaves — useful for graceful handoff. Allocates; `route` is the hot path.
    #[must_use]
    pub fn rank_keyhash(&self, key_hash: u64) -> Vec<u64> {
        let mut ranked: Vec<u64> = self.nodes.clone();
        ranked.sort_by(|&a, &b| {
            let (wa, wb) = (weight(key_hash, a), weight(key_hash, b));
            // Highest weight first; tie-break by id for determinism.
            wb.cmp(&wa).then(a.cmp(&b))
        });
        ranked
    }
}

#[cfg(test)]
mod tests {
    use super::{fnv1a, Router};

    /// A spread of distinct key hashes (counter → avalanche) for the statistical gates.
    fn keys(n: u64) -> Vec<u64> {
        (0..n)
            .map(|i| super::mix64(i.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1)))
            .collect()
    }

    #[test]
    fn route_is_deterministic_and_key_order_is_preserved() {
        let r = Router::from_nodes(&[10, 20, 30, 40]);
        for &k in &keys(5000) {
            let a = r.route_keyhash(k);
            let b = r.route_keyhash(k);
            assert_eq!(a, b, "same key routed to two different nodes");
            assert!(a.is_some());
        }
        // The byte API agrees with itself too.
        assert_eq!(r.route(b"order-key-42"), r.route(b"order-key-42"));
    }

    #[test]
    fn empty_router_routes_nowhere() {
        let r = Router::new();
        assert!(r.is_empty());
        assert_eq!(r.route_keyhash(123), None);
        assert_eq!(r.route(b"x"), None);
    }

    /// Ledger #5: parallelism = node count, with NO partition config, and load spreads ~evenly.
    #[test]
    fn load_spreads_evenly_so_parallelism_scales_with_nodes() {
        let n_nodes = 8u64;
        let r = Router::from_nodes(&(0..n_nodes).collect::<Vec<_>>());
        let ks = keys(80_000);
        let mut counts = vec![0u64; usize::try_from(n_nodes).expect("fits")];
        for &k in &ks {
            let node = r.route_keyhash(k).expect("node");
            counts[usize::try_from(node).expect("fits")] += 1;
        }
        let ideal = ks.len() as u64 / n_nodes; // 10_000
        for (node, &c) in counts.iter().enumerate() {
            // Within ±10% of an even split — no hot partitions, no manual partition count.
            let lo = ideal - ideal / 10;
            let hi = ideal + ideal / 10;
            assert!(
                c >= lo && c <= hi,
                "node {node} got {c}, expected ~{ideal} (±10%)"
            );
        }
    }

    /// Ledger #6: adding a node is MONOTONIC — keys move ONLY to the new node, never between existing nodes, and
    /// the churn is ~K/(N+1). No stop-the-world reshuffle.
    #[test]
    fn adding_a_node_moves_keys_only_to_it_and_churn_is_minimal() {
        let mut r = Router::from_nodes(&[1, 2, 3, 4, 5]); // N=5
        let ks = keys(60_000);
        let before: Vec<u64> = ks.iter().map(|&k| r.route_keyhash(k).expect("n")).collect();
        let new_node = 99u64;
        r.add_node(new_node);
        let after: Vec<u64> = ks.iter().map(|&k| r.route_keyhash(k).expect("n")).collect();

        let mut moved = 0u64;
        for (b, a) in before.iter().zip(after.iter()) {
            if a != b {
                moved += 1;
                // The ONLY allowed move is onto the new node (monotonicity — no reshuffle among the old 5).
                assert_eq!(
                    *a, new_node,
                    "a key moved between two pre-existing nodes — that's a reshuffle"
                );
            }
        }
        // Expected churn ≈ K/(N+1) = 60000/6 = 10000. Allow a generous statistical band (0.12–0.21 of 60000).
        assert!(
            (7_200..=12_600).contains(&moved),
            "churn {moved}/60000 not ~1/(N+1)≈10000"
        );
    }

    /// Ledger #6: removing a node remaps ONLY the keys it owned — every other key keeps its node. No barrier.
    #[test]
    fn removing_a_node_only_remaps_its_own_keys() {
        let mut r = Router::from_nodes(&[1, 2, 3, 4, 5]);
        let ks = keys(60_000);
        let before: Vec<u64> = ks.iter().map(|&k| r.route_keyhash(k).expect("n")).collect();
        let victim = 3u64;
        r.remove_node(victim);
        let after: Vec<u64> = ks.iter().map(|&k| r.route_keyhash(k).expect("n")).collect();

        for (b, a) in before.iter().zip(after.iter()) {
            if *b == victim {
                assert_ne!(*a, victim, "key still routed to a removed node");
            } else {
                // A key NOT owned by the victim must be completely undisturbed.
                assert_eq!(
                    *a, *b,
                    "removing a node disturbed an unrelated key — that's a reshuffle"
                );
            }
        }
    }

    #[test]
    fn rank_lists_the_failover_owner_second() {
        let r = Router::from_nodes(&[7, 8, 9, 10]);
        let k = fnv1a(b"some-key");
        let ranked = r.rank_keyhash(k);
        assert_eq!(ranked.len(), 4);
        assert_eq!(
            Some(ranked[0]),
            r.route_keyhash(k),
            "rank[0] must equal route"
        );
        // After the owner leaves, the key must land on the previous rank[1].
        let mut r2 = r.clone();
        r2.remove_node(ranked[0]);
        assert_eq!(
            r2.route_keyhash(k),
            Some(ranked[1]),
            "failover did not go to rank[1]"
        );
    }
}
