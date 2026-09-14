//! `datarail-manifest` — provable delivery (SPEC `04-manifest.md`, AC-5): a per-route append-only Merkle
//! log, a **Signed Tree Head (STH)**, offline-verifiable **inclusion proofs**, and a destination **ack**.
//!
//! The chain of evidence is *"Cofre X was delivered"* = `{leaf, inclusion_proof → root, STH, dest_ack}`,
//! verifiable **offline without trusting the pipe** (zero trust in the rail):
//!
//! - **Leaf** (BLK-8) commits to route/stream/position + identity so a proof cannot be replayed onto another
//!   route or sequence: `leaf = BLAKE3(cofre_id ‖ route_id ‖ stream_id ‖ seq ‖ epoch)`. The leaf does **not**
//!   bind the STH-root — that would be circular, since leaves feed the root the STH signs; the `dest_ack`
//!   binds `STH-root` instead.
//! - **STH** is the source identity's Ed25519 signature over `root ‖ tree_size ‖ ts` under [`ctx::STH`].
//! - **Inclusion proof** is a Merkle authentication path; [`verify_inclusion`] re-derives the root from the
//!   leaf + path and checks it equals the STH root.
//! - **`dest_ack`** commits to `route_id ‖ stream_id ‖ seq ‖ STH-root ‖ epoch` (BLK-8) signed under
//!   [`ctx::ACK`] by the destination key; [`verify_ack`] checks the signature against the **pinned** dest
//!   key, that its position matches the leaf, that its `STH-root` matches the inclusion-proof root, and that
//!   the verifier-recomputed `cofre_id` binding matches.
//!
//! **Tree construction.** An RFC-6962 / Sigstore-style binary Merkle tree (the SPEC's stolen pattern). The
//! leaf hash is exactly the SPEC value above; interior nodes are domain-separated with a `0x01` prefix
//! (`node = BLAKE3(0x01 ‖ left ‖ right)`) so a leaf can never be confused with an interior node
//! (second-preimage resistance). An unpaired right node at any level is promoted unchanged.
//!
//! std only; all crypto goes through [`datarail_crypto`] (`blake3_256`, `sign_domain` / `verify_domain`).
//! No `unsafe`.

use datarail_crypto::{blake3_256, ctx, sign_domain, verify_domain};

/// Interior-node domain tag — keeps interior nodes disjoint from leaves (RFC-6962 §2.1).
const NODE_TAG: u8 = 0x01;

/// Hash an interior Merkle node from its two children (domain-separated, BLK-8 style).
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = NODE_TAG;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    blake3_256(&buf)
}

/// Compute the canonical leaf for a cofre's position in a route's manifest (BLK-8).
///
/// `leaf = BLAKE3(cofre_id ‖ route_id ‖ stream_id ‖ seq ‖ epoch)` — binds identity to route/stream/position
/// so an inclusion proof cannot be replayed onto another route or sequence. (Per SPEC the leaf does **not**
/// bind the STH-root; the `dest_ack` does.)
#[must_use]
pub fn leaf_hash(
    cofre_id: &[u8; 32],
    route_id: &[u8; 16],
    stream_id: &[u8; 16],
    seq: u64,
    epoch: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 16 + 16 + 8 + 8);
    buf.extend_from_slice(cofre_id);
    buf.extend_from_slice(route_id);
    buf.extend_from_slice(stream_id);
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&epoch.to_le_bytes());
    blake3_256(&buf)
}

/// One step of a Merkle authentication path: a sibling hash and which side it sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    /// The sibling node's hash at this level.
    pub sibling: [u8; 32],
    /// `true` if the sibling is the **right** child (so our running hash is the left input).
    pub sibling_is_right: bool,
}

/// A Merkle inclusion proof: the leaf's index, the tree size it was proven against, and the sibling path
/// from the leaf up to (but excluding) the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Zero-based index of the proven leaf.
    pub index: usize,
    /// The number of leaves in the tree this proof was generated against.
    pub tree_size: usize,
    /// Sibling steps, leaf-to-root order.
    pub path: Vec<ProofStep>,
}

/// A Signed Tree Head — the source identity's Ed25519 commitment to the whole log at a point in time.
///
/// `sig = sign_domain(ctx::STH, seed, root ‖ tree_size_le ‖ ts_le)` ([`ctx::STH`]). Cut on a pinned cadence,
/// decoupled from the per-cofre ack (MAJ-1). TSA anchoring of the STH is asynchronous and off the delivery
/// path (not modeled here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// Merkle root over all leaves in the log.
    pub root: [u8; 32],
    /// Number of leaves committed.
    pub tree_size: u64,
    /// Source-asserted timestamp (an *upper* bound once TSA-anchored; opaque here).
    pub ts: u64,
    /// Ed25519 signature over `root ‖ tree_size_le ‖ ts_le` under [`ctx::STH`].
    pub sig: [u8; 64],
}

/// A destination delivery ack bound to a route/stream/position **and** the STH-root it was issued against.
///
/// `dest_sig = sign_domain(ctx::ACK, dest_seed, route_id ‖ stream_id ‖ seq_le ‖ sth_root ‖ epoch_le)`
/// ([`ctx::ACK`], BLK-8) — so the ack cannot be lifted onto a different route/stream/position, nor replayed
/// against a different tree state. `cofre_id` is carried for the verifier's content-address recomputation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestAck {
    /// Content-address identity of the delivered cofre (verifier re-derives + checks this, BLK-8).
    pub cofre_id: [u8; 32],
    /// Route the cofre travelled.
    pub route_id: [u8; 16],
    /// Stream (ordering domain) within the route.
    pub stream_id: [u8; 16],
    /// Per-stream sequence position.
    pub seq: u64,
    /// The STH-root the ack is bound to.
    pub sth_root: [u8; 32],
    /// Manifest epoch.
    pub epoch: u64,
    /// Ed25519 signature by the destination key under [`ctx::ACK`].
    pub dest_sig: [u8; 64],
}

/// A per-route append-only Merkle log (SPEC 04). Leaves are appended in delivery order; the root and STHs
/// are derived on demand. Persistence (source-terminal-local, optional store mirror) is out of scope.
#[derive(Debug, Clone, Default)]
pub struct ManifestLog {
    leaves: Vec<[u8; 32]>,
}

impl ManifestLog {
    /// A fresh, empty log.
    #[must_use]
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Number of leaves appended so far (the tree size).
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the log has no leaves.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The leaf hashes in append order.
    #[must_use]
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Append a pre-computed `leaf` and return its zero-based index.
    pub fn append_leaf(&mut self, leaf: [u8; 32]) -> usize {
        let idx = self.leaves.len();
        self.leaves.push(leaf);
        idx
    }

    /// Compute and append the leaf for a cofre at `(route_id, stream_id, seq, epoch)`; returns its index.
    pub fn append(
        &mut self,
        cofre_id: &[u8; 32],
        route_id: &[u8; 16],
        stream_id: &[u8; 16],
        seq: u64,
        epoch: u64,
    ) -> usize {
        let leaf = leaf_hash(cofre_id, route_id, stream_id, seq, epoch);
        self.append_leaf(leaf)
    }

    /// The current Merkle root over all appended leaves.
    ///
    /// The empty tree's root is `BLAKE3("")` (a fixed, well-defined sentinel, per RFC-6962's empty-tree
    /// convention adapted to BLAKE3).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        merkle_root(&self.leaves)
    }

    /// Build a Merkle inclusion proof for the leaf at `index` against the current tree.
    ///
    /// # Errors
    /// Returns [`ManifestError::IndexOutOfRange`] if `index >= len()`.
    pub fn inclusion_proof(&self, index: usize) -> Result<InclusionProof, ManifestError> {
        if index >= self.leaves.len() {
            return Err(ManifestError::IndexOutOfRange);
        }
        let mut path = Vec::new();
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        let mut idx = index;
        while level.len() > 1 {
            // Sibling within the pair; an unpaired last node (even index == last) is promoted, no step.
            if idx.is_multiple_of(2) {
                if idx + 1 < level.len() {
                    path.push(ProofStep {
                        sibling: level[idx + 1],
                        sibling_is_right: true,
                    });
                }
            } else {
                path.push(ProofStep {
                    sibling: level[idx - 1],
                    sibling_is_right: false,
                });
            }
            level = next_level(&level);
            idx /= 2;
        }
        Ok(InclusionProof {
            index,
            tree_size: self.leaves.len(),
            path,
        })
    }

    /// Cut a [`SignedTreeHead`] over the current root with the source identity `seed` and timestamp `ts`.
    #[must_use]
    pub fn sign_sth(&self, seed: &[u8; 32], ts: u64) -> SignedTreeHead {
        let root = self.root();
        let tree_size = self.leaves.len() as u64;
        let sig = sign_domain(ctx::STH, seed, &sth_signing_bytes(&root, tree_size, ts));
        SignedTreeHead {
            root,
            tree_size,
            ts,
            sig,
        }
    }
}

/// The canonical signed preimage for an STH: `root ‖ tree_size_le ‖ ts_le`.
fn sth_signing_bytes(root: &[u8; 32], tree_size: u64, ts: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 8 + 8);
    buf.extend_from_slice(root);
    buf.extend_from_slice(&tree_size.to_le_bytes());
    buf.extend_from_slice(&ts.to_le_bytes());
    buf
}

/// The canonical signed preimage for a `dest_ack`: `route_id ‖ stream_id ‖ seq_le ‖ sth_root ‖ epoch_le`.
fn ack_signing_bytes(
    route_id: &[u8; 16],
    stream_id: &[u8; 16],
    seq: u64,
    sth_root: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 16 + 8 + 32 + 8);
    buf.extend_from_slice(route_id);
    buf.extend_from_slice(stream_id);
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(sth_root);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf
}

/// Reduce one Merkle level to the next: pair up siblings, promote an unpaired last node.
fn next_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut up = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        if i + 1 < level.len() {
            up.push(hash_node(&level[i], &level[i + 1]));
            i += 2;
        } else {
            up.push(level[i]);
            i += 1;
        }
    }
    up
}

/// Compute a Merkle root over `leaves` (RFC-6962 promotion of unpaired nodes; empty → `BLAKE3("")`).
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return blake3_256(&[]);
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// Re-derive a Merkle root from a `leaf` and its authentication `path` (independent of any tree state).
#[must_use]
pub fn root_from_path(leaf: &[u8; 32], path: &[ProofStep]) -> [u8; 32] {
    let mut acc = *leaf;
    for step in path {
        acc = if step.sibling_is_right {
            hash_node(&acc, &step.sibling)
        } else {
            hash_node(&step.sibling, &acc)
        };
    }
    acc
}

/// Verify a Merkle inclusion proof: the `leaf` + `proof.path` must re-derive `expected_root`.
///
/// This is the offline auditor's check — it trusts nothing but the leaf, the path, and the root taken from a
/// (separately signature-verified) STH.
#[must_use]
pub fn verify_inclusion(leaf: &[u8; 32], proof: &InclusionProof, expected_root: &[u8; 32]) -> bool {
    proof.index < proof.tree_size && root_from_path(leaf, &proof.path) == *expected_root
}

/// Verify a [`SignedTreeHead`] signature against the pinned source verifying key.
#[must_use]
pub fn verify_sth(sth: &SignedTreeHead, source_vk: &[u8; 32]) -> bool {
    verify_domain(
        ctx::STH,
        source_vk,
        &sth_signing_bytes(&sth.root, sth.tree_size, sth.ts),
        &sth.sig,
    )
}

/// Issue a [`DestAck`] from the destination identity `dest_seed`, bound to position + STH-root (BLK-8).
#[must_use]
pub fn sign_ack(
    dest_seed: &[u8; 32],
    cofre_id: [u8; 32],
    route_id: [u8; 16],
    stream_id: [u8; 16],
    seq: u64,
    sth_root: [u8; 32],
    epoch: u64,
) -> DestAck {
    let dest_sig = sign_domain(
        ctx::ACK,
        dest_seed,
        &ack_signing_bytes(&route_id, &stream_id, seq, &sth_root, epoch),
    );
    DestAck {
        cofre_id,
        route_id,
        stream_id,
        seq,
        sth_root,
        epoch,
        dest_sig,
    }
}

/// Why a delivery proof failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    /// A requested leaf index is `>=` the tree size.
    IndexOutOfRange,
    /// The inclusion proof's leaf does not re-derive the STH root.
    BadInclusion,
    /// The STH signature does not verify against the pinned source key.
    BadSth,
    /// The ack signature does not verify against the pinned destination key.
    BadAckSig,
    /// The ack's `route_id ‖ stream_id ‖ seq ‖ epoch` does not match the proven leaf.
    AckPositionMismatch,
    /// The ack's bound `STH-root` does not match the inclusion-proof / STH root.
    AckRootMismatch,
    /// The verifier-recomputed `cofre_id` binding does not match the ack (BLK-8).
    CofreIdMismatch,
}

impl core::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::IndexOutOfRange => "leaf index out of range",
            Self::BadInclusion => "inclusion proof does not match STH root",
            Self::BadSth => "STH signature invalid",
            Self::BadAckSig => "dest_ack signature invalid",
            Self::AckPositionMismatch => "dest_ack route/stream/seq/epoch != leaf",
            Self::AckRootMismatch => "dest_ack STH-root != inclusion-proof root",
            Self::CofreIdMismatch => "recomputed cofre_id != dest_ack",
        };
        f.write_str(s)
    }
}

impl core::error::Error for ManifestError {}

/// Verify a destination ack on its own: signature, then position/root binding against the proven leaf
/// coordinates. (Use [`verify_delivery`] for the full `{inclusion, STH, ack}` check.)
///
/// # Errors
/// Returns [`ManifestError::BadAckSig`] if the destination signature is invalid,
/// [`ManifestError::AckPositionMismatch`] if `route_id ‖ stream_id ‖ seq ‖ epoch` disagree, or
/// [`ManifestError::AckRootMismatch`] if the ack's bound `STH-root` differs from `expected_root`.
pub fn verify_ack(
    ack: &DestAck,
    dest_vk: &[u8; 32],
    route_id: &[u8; 16],
    stream_id: &[u8; 16],
    seq: u64,
    epoch: u64,
    expected_root: &[u8; 32],
) -> Result<(), ManifestError> {
    if !verify_domain(
        ctx::ACK,
        dest_vk,
        &ack_signing_bytes(&ack.route_id, &ack.stream_id, ack.seq, &ack.sth_root, ack.epoch),
        &ack.dest_sig,
    ) {
        return Err(ManifestError::BadAckSig);
    }
    if ack.route_id != *route_id
        || ack.stream_id != *stream_id
        || ack.seq != seq
        || ack.epoch != epoch
    {
        return Err(ManifestError::AckPositionMismatch);
    }
    if ack.sth_root != *expected_root {
        return Err(ManifestError::AckRootMismatch);
    }
    Ok(())
}

/// The bundle of evidence a verifier checks for *"this cofre was delivered, exactly once, intact"* (AC-5).
///
/// Bundling the inputs (rather than a 10-argument call) keeps the verifier entry point within the Craft
/// Charter without an `#[allow]`.
#[derive(Debug, Clone, Copy)]
pub struct DeliveryProof<'a> {
    /// The delivered cofre's payload bytes — the verifier re-derives `cofre_id = BLAKE3(carga)` (BLK-8).
    pub carga: &'a [u8],
    /// Claimed route.
    pub route_id: &'a [u8; 16],
    /// Claimed stream (ordering domain).
    pub stream_id: &'a [u8; 16],
    /// Claimed per-stream sequence.
    pub seq: u64,
    /// Claimed manifest epoch.
    pub epoch: u64,
    /// The Merkle inclusion proof.
    pub proof: &'a InclusionProof,
    /// The Signed Tree Head the proof is checked against.
    pub sth: &'a SignedTreeHead,
    /// The pinned source verifying key (for the STH).
    pub source_vk: &'a [u8; 32],
    /// The destination ack.
    pub ack: &'a DestAck,
    /// The pinned destination verifying key (for the ack).
    pub dest_vk: &'a [u8; 32],
}

/// Public name for an offline delivery receipt.
pub type DeliveryReceipt<'a> = DeliveryProof<'a>;

/// The full offline delivery proof for *"this cofre was delivered, exactly once, intact"* (AC-5).
///
/// Given the delivered cofre's `carga` (so the verifier can re-derive the content-address `cofre_id`, BLK-8)
/// and its claimed coordinates, this checks the complete `{inclusion proof, STH, dest_ack}` bundle with
/// **zero trust in the pipe**:
///
/// 1. recompute `cofre_id = BLAKE3(carga)` and the leaf, and confirm it matches the ack's `cofre_id`;
/// 2. the STH signature verifies under the pinned source key;
/// 3. the inclusion proof re-derives the STH root from the leaf;
/// 4. the ack verifies under the pinned dest key and its position + bound `STH-root` match.
///
/// # Errors
/// Returns the corresponding [`ManifestError`] variant for whichever check fails first
/// ([`ManifestError::CofreIdMismatch`], [`ManifestError::BadSth`], [`ManifestError::BadInclusion`], or an
/// ack error from [`verify_ack`]).
pub fn verify_receipt(p: &DeliveryReceipt<'_>) -> Result<(), ManifestError> {
    // (1) Content-address recomputation (BLK-8): the verifier trusts the bytes, not the claim.
    let cofre_id = blake3_256(p.carga);
    if cofre_id != p.ack.cofre_id {
        return Err(ManifestError::CofreIdMismatch);
    }
    let leaf = leaf_hash(&cofre_id, p.route_id, p.stream_id, p.seq, p.epoch);
    // (2) STH signed by the source identity.
    if !verify_sth(p.sth, p.source_vk) {
        return Err(ManifestError::BadSth);
    }
    let Ok(proof_tree_size) = u64::try_from(p.proof.tree_size) else {
        return Err(ManifestError::BadInclusion);
    };
    if proof_tree_size != p.sth.tree_size {
        return Err(ManifestError::BadInclusion);
    }
    // (3) leaf ∈ tree, against the STH's root.
    if !verify_inclusion(&leaf, p.proof, &p.sth.root) {
        return Err(ManifestError::BadInclusion);
    }
    // (4) ack signed by dest, position matches the leaf, and its bound STH-root matches the proof root.
    verify_ack(p.ack, p.dest_vk, p.route_id, p.stream_id, p.seq, p.epoch, &p.sth.root)
}

/// Verify an offline delivery proof using its original API name.
///
/// # Errors
/// Returns the corresponding [`ManifestError`] from [`verify_receipt`].
pub fn verify_delivery(p: &DeliveryProof<'_>) -> Result<(), ManifestError> {
    verify_receipt(p)
}

/// E4 — BLAKE3 verified-streaming **chunk resume** (SPEC 07), built on this crate's Merkle tree.
///
/// A large cofre's `carga` is split into fixed-size chunks; each chunk is an **index-bound** Merkle leaf and
/// the tree root is the authenticated commitment (the *same* machinery as the 04 manifest receipt root). A
/// receiver verifies every chunk against the root via its inclusion proof, tracks received chunks in a
/// bitfield, and on resume requests **only the missing** chunks — authenticating each incrementally, so a dead
/// rail can re-spawn and safely complete from a partial/untrusted source. A tampered chunk (or one replayed at
/// the wrong index, or from a different payload's tree) fails authentication and is rejected.
pub mod bao {
    use datarail_crypto::blake3_256;

    use super::{verify_inclusion, InclusionProof, ManifestLog};

    /// Default chunk size (64 KiB) — bounded by the SPEC-02 max-cofre-size; a payload below this is one chunk.
    pub const CHUNK_SIZE: usize = 64 * 1024;

    /// Domain tag separating chunk leaves from the manifest's cofre leaves.
    const CHUNK_LEAF_CTX: &[u8] = b"dr:bao:chunk:v1";

    /// The index-bound leaf for chunk `index` of `total`: binds content **and** position **and** the chunk
    /// count, so a chunk cannot be replayed at a different index, count, or payload tree.
    #[must_use]
    pub fn chunk_leaf(index: usize, total: usize, bytes: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(CHUNK_LEAF_CTX.len() + 16 + bytes.len());
        buf.extend_from_slice(CHUNK_LEAF_CTX);
        buf.extend_from_slice(&(index as u64).to_le_bytes());
        buf.extend_from_slice(&(total as u64).to_le_bytes());
        buf.extend_from_slice(bytes);
        blake3_256(&buf)
    }

    /// One authenticated chunk on the wire: its index, bytes, and inclusion proof against the root.
    #[derive(Debug, Clone)]
    pub struct ChunkPiece {
        /// Zero-based chunk index.
        pub index: usize,
        /// The chunk's bytes.
        pub bytes: Vec<u8>,
        /// Inclusion proof of this chunk's index-bound leaf against the committed root.
        pub proof: InclusionProof,
    }

    /// A commitment to a chunked payload: the Merkle `root`, the `total` chunk count, and the authenticated
    /// `pieces` ready to stream.
    #[derive(Debug, Clone)]
    pub struct Committed {
        /// BLAKE3 Merkle root over the index-bound chunk leaves (the authenticated commitment).
        pub root: [u8; 32],
        /// Number of chunks.
        pub total: usize,
        /// Every chunk + its inclusion proof, in index order.
        pub pieces: Vec<ChunkPiece>,
    }

    /// Why a chunk was rejected by [`ChunkReceiver::accept`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BaoError {
        /// The chunk's index is `>= total`.
        IndexOutOfRange,
        /// The wire `index` disagrees with the proof's bound index.
        ProofIndexMismatch,
        /// The leaf + proof did not re-derive the trusted root (tampered / wrong index / wrong payload).
        Unauthenticated,
        /// [`ChunkReceiver::reassemble`] was called before every chunk had arrived.
        Incomplete,
    }

    impl core::fmt::Display for BaoError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let s = match self {
                Self::IndexOutOfRange => "chunk index out of range",
                Self::ProofIndexMismatch => "chunk index disagrees with its proof",
                Self::Unauthenticated => "chunk failed authentication against the root",
                Self::Incomplete => "cannot reassemble: chunks still missing",
            };
            f.write_str(s)
        }
    }

    impl core::error::Error for BaoError {}

    /// Split `data` into chunks of `chunk_size` (min 1) and commit them to a BLAKE3 Merkle root. An empty
    /// payload yields a single empty chunk so the tree (and round-trip) is well-defined.
    #[must_use]
    pub fn split_and_commit(data: &[u8], chunk_size: usize) -> Committed {
        let mut chunks: Vec<&[u8]> = data.chunks(chunk_size.max(1)).collect();
        if chunks.is_empty() {
            chunks.push(data); // empty payload → one empty chunk
        }
        let total = chunks.len();
        let mut log = ManifestLog::new();
        for (i, c) in chunks.iter().enumerate() {
            log.append_leaf(chunk_leaf(i, total, c));
        }
        let root = log.root();
        let mut pieces = Vec::with_capacity(total);
        for (i, c) in chunks.iter().enumerate() {
            // `i < total == leaf count`, so the proof is infallible here; skip-on-Err avoids an unwrap.
            if let Ok(proof) = log.inclusion_proof(i) {
                pieces.push(ChunkPiece {
                    index: i,
                    bytes: (*c).to_vec(),
                    proof,
                });
            }
        }
        Committed { root, total, pieces }
    }

    /// A resumable chunk receiver: the trusted `root` + `total`, a received-chunk bitfield, and the reassembly
    /// buffer. Every chunk is authenticated against the root before it is stored.
    #[derive(Debug, Clone)]
    pub struct ChunkReceiver {
        root: [u8; 32],
        total: usize,
        slots: Vec<Option<Vec<u8>>>,
    }

    impl ChunkReceiver {
        /// A fresh receiver for a payload of `total` chunks committed to `root`.
        #[must_use]
        pub fn new(root: [u8; 32], total: usize) -> Self {
            Self {
                root,
                total,
                slots: vec![None; total],
            }
        }

        /// Accept a chunk iff its index-bound leaf + inclusion proof re-derive the trusted root. Idempotent: a
        /// re-accepted chunk simply overwrites its (identical, already-verified) slot.
        ///
        /// # Errors
        /// [`BaoError::IndexOutOfRange`], [`BaoError::ProofIndexMismatch`], or [`BaoError::Unauthenticated`].
        pub fn accept(&mut self, piece: &ChunkPiece) -> Result<(), BaoError> {
            if piece.index >= self.total {
                return Err(BaoError::IndexOutOfRange);
            }
            if piece.proof.index != piece.index {
                return Err(BaoError::ProofIndexMismatch);
            }
            let leaf = chunk_leaf(piece.index, self.total, &piece.bytes);
            if !verify_inclusion(&leaf, &piece.proof, &self.root) {
                return Err(BaoError::Unauthenticated);
            }
            self.slots[piece.index] = Some(piece.bytes.clone());
            Ok(())
        }

        /// Whether chunk `index` has been received and authenticated.
        #[must_use]
        pub fn has(&self, index: usize) -> bool {
            self.slots.get(index).is_some_and(Option::is_some)
        }

        /// The indices still missing — the resume request set.
        #[must_use]
        pub fn missing(&self) -> Vec<usize> {
            (0..self.total).filter(|&i| self.slots[i].is_none()).collect()
        }

        /// Whether every chunk has arrived.
        #[must_use]
        pub fn is_complete(&self) -> bool {
            self.slots.iter().all(Option::is_some)
        }

        /// Reassemble the original bytes once every chunk has been authenticated.
        ///
        /// # Errors
        /// [`BaoError::Incomplete`] if any chunk is still missing.
        pub fn reassemble(&self) -> Result<Vec<u8>, BaoError> {
            if !self.is_complete() {
                return Err(BaoError::Incomplete);
            }
            let mut out = Vec::new();
            for bytes in self.slots.iter().flatten() {
                out.extend_from_slice(bytes);
            }
            Ok(out)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{split_and_commit, BaoError, ChunkReceiver};

        /// Deterministic payload of `n` bytes.
        fn payload(n: usize) -> Vec<u8> {
            (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect()
        }

        #[test]
        fn round_trip_all_chunks_reassemble() {
            let data = payload(200); // 13 chunks at size 16
            let c = split_and_commit(&data, 16);
            assert_eq!(c.total, 13);
            let mut rx = ChunkReceiver::new(c.root, c.total);
            for piece in &c.pieces {
                rx.accept(piece).expect("authentic chunk accepted");
            }
            assert!(rx.is_complete());
            assert_eq!(rx.reassemble().expect("complete"), data);
        }

        #[test]
        fn partial_then_resume_reassembles() {
            // A dead rail received only the even chunks; on resume it requests exactly the missing (odd) ones.
            let data = payload(200);
            let c = split_and_commit(&data, 16);
            let mut rx = ChunkReceiver::new(c.root, c.total);

            for piece in c.pieces.iter().filter(|p| p.index % 2 == 0) {
                rx.accept(piece).expect("even chunk");
            }
            assert!(!rx.is_complete());
            let missing = rx.missing();
            assert!(missing.iter().all(|i| i % 2 == 1), "only odd chunks remain: {missing:?}");
            assert_eq!(rx.reassemble(), Err(BaoError::Incomplete));

            // Resume: deliver exactly the missing chunks.
            for &i in &missing {
                rx.accept(&c.pieces[i]).expect("resumed chunk");
            }
            assert!(rx.is_complete());
            assert_eq!(rx.reassemble().expect("complete"), data, "partial + resume reassembles the original");
        }

        #[test]
        fn tampered_chunk_is_rejected() {
            let data = payload(100);
            let c = split_and_commit(&data, 16);
            let mut rx = ChunkReceiver::new(c.root, c.total);
            let mut bad = c.pieces[2].clone();
            bad.bytes[0] ^= 0x01; // flip one byte
            assert_eq!(rx.accept(&bad), Err(BaoError::Unauthenticated), "a tampered chunk is rejected");
            assert!(!rx.has(2));
        }

        #[test]
        fn chunk_replayed_at_wrong_index_is_rejected() {
            let data = payload(100);
            let c = split_and_commit(&data, 16);
            let mut rx = ChunkReceiver::new(c.root, c.total);

            // Same bytes+proof but a lying wire index → caught by the index/proof cross-check.
            let mut relabelled = c.pieces[2].clone();
            relabelled.index = 3;
            assert_eq!(rx.accept(&relabelled), Err(BaoError::ProofIndexMismatch));

            // Another chunk's bytes presented under index 2's identity → leaf mismatch → unauthenticated.
            let mut swapped = c.pieces[2].clone();
            swapped.bytes = c.pieces[3].bytes.clone();
            assert_eq!(rx.accept(&swapped), Err(BaoError::Unauthenticated));
        }

        #[test]
        fn chunk_from_a_different_payload_is_unauthenticated() {
            let c1 = split_and_commit(&payload(100), 16);
            let c2 = split_and_commit(&payload(100), 16); // identical bytes here…
            let c3 = split_and_commit(b"a totally different payload entirely", 16);
            // Same content ⇒ same root (content-addressed), so c2's piece verifies against c1's root…
            let mut rx = ChunkReceiver::new(c1.root, c1.total);
            assert_eq!(rx.accept(&c2.pieces[0]), Ok(()));
            // …but a piece from a genuinely different payload does not.
            let mut rx3 = ChunkReceiver::new(c1.root, c1.total);
            assert_eq!(rx3.accept(&c3.pieces[0]), Err(BaoError::Unauthenticated));
        }

        #[test]
        fn empty_payload_round_trips() {
            let c = split_and_commit(&[], 16);
            assert_eq!(c.total, 1, "empty payload is one empty chunk");
            let mut rx = ChunkReceiver::new(c.root, c.total);
            rx.accept(&c.pieces[0]).expect("empty chunk");
            assert_eq!(rx.reassemble().expect("complete"), Vec::<u8>::new());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        leaf_hash, merkle_root, root_from_path, sign_ack, verify_ack, verify_delivery,
        verify_inclusion, verify_sth, DeliveryProof, DestAck, ManifestError, ManifestLog, ProofStep,
        SignedTreeHead,
    };
    use datarail_crypto::{blake3_256, ctx, verify_domain, verifying_key};

    const SOURCE_SEED: [u8; 32] = [11u8; 32];
    const DEST_SEED: [u8; 32] = [22u8; 32];
    const EVIL_SEED: [u8; 32] = [99u8; 32];
    const ROUTE: [u8; 16] = [1u8; 16];
    const STREAM: [u8; 16] = [2u8; 16];
    const EPOCH: u64 = 7;
    const TS: u64 = 1_700_000_000;

    /// Distinct payloads so each leaf's `cofre_id = BLAKE3(carga)` differs.
    fn cargas(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("carga-{i}").into_bytes()).collect()
    }

    fn build_log(cargas: &[Vec<u8>]) -> ManifestLog {
        let mut log = ManifestLog::new();
        for (i, c) in cargas.iter().enumerate() {
            let cofre_id = blake3_256(c);
            log.append(&cofre_id, &ROUTE, &STREAM, i as u64, EPOCH);
        }
        log
    }

    // ---- Independent re-derivation (the "differential" reference, AC-5) ----------------------------------

    /// One independently-coded reduction of a Merkle level (shares no code with `super::next_level`):
    /// hashes each pair under the `0x01` node tag and promotes an unpaired tail.
    fn indep_reduce(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut up = Vec::new();
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut buf = Vec::with_capacity(65);
                buf.push(0x01);
                buf.extend_from_slice(&level[i]);
                buf.extend_from_slice(&level[i + 1]);
                up.push(blake3_256(&buf));
                i += 2;
            } else {
                up.push(level[i]);
                i += 1;
            }
        }
        up
    }

    /// A from-scratch Merkle root that shares no code path with [`ManifestLog`]'s builder. If both agree on
    /// every tree size, the production reducer is corroborated independently (the AC-5 differential ref).
    fn independent_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return blake3_256(&[]);
        }
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            level = indep_reduce(&level);
        }
        level[0]
    }

    #[test]
    fn root_matches_independent_rederivation() {
        // Differential: the production root equals an independently-coded root, for every size 0..=16.
        for n in 0..=16 {
            let cs = cargas(n);
            let log = build_log(&cs);
            assert_eq!(
                log.root(),
                independent_root(log.leaves()),
                "root mismatch at n={n}"
            );
        }
    }

    #[test]
    fn leaf_hash_is_spec_formula() {
        // BLK-8: leaf = BLAKE3(cofre_id ‖ route_id ‖ stream_id ‖ seq_le ‖ epoch_le), independently composed.
        let cofre_id = blake3_256(b"carga-0");
        let mut expect = Vec::new();
        expect.extend_from_slice(&cofre_id);
        expect.extend_from_slice(&ROUTE);
        expect.extend_from_slice(&STREAM);
        expect.extend_from_slice(&5u64.to_le_bytes());
        expect.extend_from_slice(&EPOCH.to_le_bytes());
        assert_eq!(
            leaf_hash(&cofre_id, &ROUTE, &STREAM, 5, EPOCH),
            blake3_256(&expect)
        );
    }

    // ---- AC-5: a valid {inclusion, STH, ack} is independently confirmed -----------------------------------

    #[test]
    fn ac5_valid_bundle_is_accepted_at_every_index() {
        let cs = cargas(11); // odd size → exercises odd-tail promotion in paths
        let log = build_log(&cs);
        let sth = log.sign_sth(&SOURCE_SEED, TS);
        let source_vk = verifying_key(&SOURCE_SEED);
        let dest_vk = verifying_key(&DEST_SEED);

        // STH is signed by the source identity (independent check via the crypto verifier under ctx::STH).
        assert!(verify_sth(&sth, &source_vk));

        for (i, c) in cs.iter().enumerate() {
            let seq = i as u64;
            let cofre_id = blake3_256(c);
            let leaf = leaf_hash(&cofre_id, &ROUTE, &STREAM, seq, EPOCH);
            let proof = log.inclusion_proof(i).expect("proof");

            // Independent re-derivation confirms the inclusion proof: rebuild the root from leaf+path and
            // compare to the STH root — sharing nothing with the prover's level-walk except the node hash.
            assert_eq!(root_from_path(&leaf, &proof.path), sth.root, "idx {i}");
            assert!(verify_inclusion(&leaf, &proof, &sth.root));

            let ack = sign_ack(&DEST_SEED, cofre_id, ROUTE, STREAM, seq, sth.root, EPOCH);
            // Independent ack check: re-build the exact ctx::ACK preimage and verify the raw signature.
            let mut ack_msg = Vec::new();
            ack_msg.extend_from_slice(&ROUTE);
            ack_msg.extend_from_slice(&STREAM);
            ack_msg.extend_from_slice(&seq.to_le_bytes());
            ack_msg.extend_from_slice(&sth.root);
            ack_msg.extend_from_slice(&EPOCH.to_le_bytes());
            assert!(verify_domain(ctx::ACK, &dest_vk, &ack_msg, &ack.dest_sig));

            // Full offline bundle accepts.
            run(c, seq, &proof, &sth, &source_vk, &ack, &dest_vk).expect("valid delivery proof");
        }
    }

    #[test]
    fn ac5_single_leaf_tree() {
        // Edge: a 1-leaf log has an empty path and root == leaf.
        let cs = cargas(1);
        let log = build_log(&cs);
        let sth = log.sign_sth(&SOURCE_SEED, TS);
        let cofre_id = blake3_256(&cs[0]);
        let leaf = leaf_hash(&cofre_id, &ROUTE, &STREAM, 0, EPOCH);
        let proof = log.inclusion_proof(0).expect("proof");
        assert!(proof.path.is_empty());
        assert_eq!(sth.root, leaf);
        let ack = sign_ack(&DEST_SEED, cofre_id, ROUTE, STREAM, 0, sth.root, EPOCH);
        run(
            &cs[0],
            0,
            &proof,
            &sth,
            &verifying_key(&SOURCE_SEED),
            &ack,
            &verifying_key(&DEST_SEED),
        )
        .expect("single-leaf delivery proof");
    }

    // ---- AC-5: tampering with leaf / path / root / ack is REJECTED ----------------------------------------

    /// A fully-valid bundle for index 3 of a 9-leaf log, returned with all the pieces to tamper.
    fn valid_fixture() -> (
        Vec<u8>,            // carga
        u64,                // seq
        super::InclusionProof,
        SignedTreeHead,
        [u8; 32],           // source_vk
        DestAck,
        [u8; 32],           // dest_vk
    ) {
        let cs = cargas(9);
        let log = build_log(&cs);
        let sth = log.sign_sth(&SOURCE_SEED, TS);
        let idx = 3usize;
        let seq = idx as u64;
        let cofre_id = blake3_256(&cs[idx]);
        let proof = log.inclusion_proof(idx).expect("proof");
        let ack = sign_ack(&DEST_SEED, cofre_id, ROUTE, STREAM, seq, sth.root, EPOCH);
        (
            cs[idx].clone(),
            seq,
            proof,
            sth,
            verifying_key(&SOURCE_SEED),
            ack,
            verifying_key(&DEST_SEED),
        )
    }

    fn run(
        carga: &[u8],
        seq: u64,
        proof: &super::InclusionProof,
        sth: &SignedTreeHead,
        svk: &[u8; 32],
        ack: &DestAck,
        dvk: &[u8; 32],
    ) -> Result<(), ManifestError> {
        verify_delivery(&DeliveryProof {
            carga,
            route_id: &ROUTE,
            stream_id: &STREAM,
            seq,
            epoch: EPOCH,
            proof,
            sth,
            source_vk: svk,
            ack,
            dest_vk: dvk,
        })
    }

    #[test]
    fn ac5_tampered_leaf_rejected() {
        // (a) Tamper the delivered bytes so the leaf changes. Keep the ack's cofre_id consistent with the
        //     new bytes so we isolate the *inclusion* failure (not the BLK-8 content-address check).
        let (carga, seq, proof, sth, svk, mut ack, dvk) = valid_fixture();
        let mut bad = carga.clone();
        bad[0] ^= 0x01;
        ack.cofre_id = blake3_256(&bad);
        ack.dest_sig = sign_ack(&DEST_SEED, ack.cofre_id, ROUTE, STREAM, seq, sth.root, EPOCH).dest_sig;
        assert_eq!(
            run(&bad, seq, &proof, &sth, &svk, &ack, &dvk),
            Err(ManifestError::BadInclusion)
        );

        // (b) The genuine leaf, but claimed at the wrong sequence position, is not in the tree at that path.
        //     The recomputed leaf for seq+1 differs from the leaf proof.path was built for → BadInclusion.
        let (carga2, _seq2, proof2, sth2, svk2, _ack2, dvk2) = valid_fixture();
        let wrong_seq = (proof2.index as u64) + 1;
        let ack2 = sign_ack(
            &DEST_SEED,
            blake3_256(&carga2),
            ROUTE,
            STREAM,
            wrong_seq,
            sth2.root,
            EPOCH,
        );
        assert_eq!(
            run(&carga2, wrong_seq, &proof2, &sth2, &svk2, &ack2, &dvk2),
            Err(ManifestError::BadInclusion)
        );
    }

    #[test]
    fn ac5_tampered_path_rejected() {
        let (carga, seq, mut proof, sth, svk, ack, dvk) = valid_fixture();
        // Flip a bit in a sibling hash → root re-derivation diverges.
        proof.path[0].sibling[0] ^= 0x01;
        assert_eq!(
            run(&carga, seq, &proof, &sth, &svk, &ack, &dvk),
            Err(ManifestError::BadInclusion)
        );
        // Flip a sibling's side bit → wrong concatenation order → wrong root.
        let (carga2, seq2, mut proof2, sth2, svk2, ack2, dvk2) = valid_fixture();
        proof2.path[0].sibling_is_right = !proof2.path[0].sibling_is_right;
        assert_eq!(
            run(&carga2, seq2, &proof2, &sth2, &svk2, &ack2, &dvk2),
            Err(ManifestError::BadInclusion)
        );
        // Drop a step from the path → too-short path → wrong root.
        let (carga3, seq3, mut proof3, sth3, svk3, ack3, dvk3) = valid_fixture();
        proof3.path.pop();
        assert_eq!(
            run(&carga3, seq3, &proof3, &sth3, &svk3, &ack3, &dvk3),
            Err(ManifestError::BadInclusion)
        );
    }

    #[test]
    fn ac5_tampered_root_rejected() {
        // A forged STH root (re-signed by the source over the *wrong* root) still fails inclusion, because
        // the leaf+path re-derive the true root, not the forged one.
        let (carga, seq, proof, mut sth, svk, mut ack, dvk) = valid_fixture();
        let mut forged_root = sth.root;
        forged_root[0] ^= 0x01;
        // Re-sign so the STH signature itself is valid — isolate the inclusion check.
        let resigned = {
            let log = build_log(&cargas(9));
            // borrow the signing helper indirectly: sign a fresh STH with a manually-set root
            let mut s = log.sign_sth(&SOURCE_SEED, TS);
            s.root = forged_root;
            // re-sign over the forged root
            super::SignedTreeHead {
                sig: datarail_crypto::sign_domain(
                    ctx::STH,
                    &SOURCE_SEED,
                    &{
                        let mut b = Vec::new();
                        b.extend_from_slice(&forged_root);
                        b.extend_from_slice(&s.tree_size.to_le_bytes());
                        b.extend_from_slice(&s.ts.to_le_bytes());
                        b
                    },
                ),
                ..s
            }
        };
        sth = resigned;
        ack.sth_root = forged_root; // keep ack consistent so we hit BadInclusion, not AckRootMismatch
        assert!(verify_sth(&sth, &svk)); // the forged STH is genuinely signed
        assert_eq!(
            run(&carga, seq, &proof, &sth, &svk, &ack, &dvk),
            Err(ManifestError::BadInclusion)
        );
    }

    #[test]
    fn ac5_unsigned_or_wrongly_signed_sth_rejected() {
        let (carga, seq, proof, mut sth, svk, ack, dvk) = valid_fixture();
        // STH signed by an impostor source key → BadSth under the pinned source vk.
        sth.sig = {
            let mut b = Vec::new();
            b.extend_from_slice(&sth.root);
            b.extend_from_slice(&sth.tree_size.to_le_bytes());
            b.extend_from_slice(&sth.ts.to_le_bytes());
            datarail_crypto::sign_domain(ctx::STH, &EVIL_SEED, &b)
        };
        assert_eq!(
            run(&carga, seq, &proof, &sth, &svk, &ack, &dvk),
            Err(ManifestError::BadSth)
        );
    }

    #[test]
    fn ac5_tampered_ack_rejected() {
        // (a) ack signed by an impostor dest key.
        let (carga, seq, proof, sth, svk, _ack, dvk) = valid_fixture();
        let cofre_id = blake3_256(&carga);
        let evil_ack = sign_ack(&EVIL_SEED, cofre_id, ROUTE, STREAM, seq, sth.root, EPOCH);
        assert_eq!(
            run(&carga, seq, &proof, &sth, &svk, &evil_ack, &dvk),
            Err(ManifestError::BadAckSig)
        );

        // (b) ack lifted onto a different route → position mismatch (signature stays valid for its own msg).
        let (carga_b, seq_b, proof_b, sth_b, svk_b, _a_b, dvk_b) = valid_fixture();
        let ack_b = sign_ack(&DEST_SEED, blake3_256(&carga_b), [0xAA; 16], STREAM, seq_b, sth_b.root, EPOCH);
        assert_eq!(
            run(&carga_b, seq_b, &proof_b, &sth_b, &svk_b, &ack_b, &dvk_b),
            Err(ManifestError::AckPositionMismatch)
        );

        // (c) ack bound to a stale STH-root → root mismatch.
        let (carga_c, seq_c, proof_c, sth_c, svk_c, _a, dvk_c) = valid_fixture();
        let mut stale_root = sth_c.root;
        stale_root[0] ^= 0x01;
        let ack_c = sign_ack(&DEST_SEED, blake3_256(&carga_c), ROUTE, STREAM, seq_c, stale_root, EPOCH);
        assert_eq!(
            run(&carga_c, seq_c, &proof_c, &sth_c, &svk_c, &ack_c, &dvk_c),
            Err(ManifestError::AckRootMismatch)
        );

        // (d) BLK-8: delivered bytes don't match the ack's content-address → CofreIdMismatch.
        let (carga_d, seq_d, proof_d, sth_d, svk_d, ack_d, dvk_d) = valid_fixture();
        let mut other = carga_d.clone();
        other.extend_from_slice(b"-tampered");
        assert_eq!(
            run(&other, seq_d, &proof_d, &sth_d, &svk_d, &ack_d, &dvk_d),
            Err(ManifestError::CofreIdMismatch)
        );
    }

    #[test]
    fn ack_position_and_root_binding_standalone() {
        let cs = cargas(4);
        let log = build_log(&cs);
        let sth = log.sign_sth(&SOURCE_SEED, TS);
        let dvk = verifying_key(&DEST_SEED);
        let cofre_id = blake3_256(&cs[2]);
        let ack = sign_ack(&DEST_SEED, cofre_id, ROUTE, STREAM, 2, sth.root, EPOCH);
        verify_ack(&ack, &dvk, &ROUTE, &STREAM, 2, EPOCH, &sth.root).expect("ack ok");
        // wrong seq
        assert_eq!(
            verify_ack(&ack, &dvk, &ROUTE, &STREAM, 3, EPOCH, &sth.root),
            Err(ManifestError::AckPositionMismatch)
        );
        // wrong epoch
        assert_eq!(
            verify_ack(&ack, &dvk, &ROUTE, &STREAM, 2, EPOCH + 1, &sth.root),
            Err(ManifestError::AckPositionMismatch)
        );
    }

    #[test]
    fn empty_and_index_errors() {
        let log = ManifestLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert_eq!(log.root(), blake3_256(&[]));
        assert_eq!(
            log.inclusion_proof(0).unwrap_err(),
            ManifestError::IndexOutOfRange
        );
        let mut log = log;
        log.append(&blake3_256(b"x"), &ROUTE, &STREAM, 0, EPOCH);
        assert_eq!(
            log.inclusion_proof(1).unwrap_err(),
            ManifestError::IndexOutOfRange
        );
    }

    #[test]
    fn sth_separation_from_ack_context() {
        // BLK-5: an STH preimage signed under ctx::STH must not verify under ctx::ACK and vice-versa.
        let log = build_log(&cargas(3));
        let sth = log.sign_sth(&SOURCE_SEED, TS);
        let svk = verifying_key(&SOURCE_SEED);
        let mut msg = Vec::new();
        msg.extend_from_slice(&sth.root);
        msg.extend_from_slice(&sth.tree_size.to_le_bytes());
        msg.extend_from_slice(&sth.ts.to_le_bytes());
        assert!(verify_domain(ctx::STH, &svk, &msg, &sth.sig));
        assert!(!verify_domain(ctx::ACK, &svk, &msg, &sth.sig));
    }

    #[test]
    fn proof_step_and_helpers_are_consistent() {
        // root_from_path on an empty path is the leaf itself; merkle_root of one leaf is that leaf.
        let leaf = leaf_hash(&blake3_256(b"x"), &ROUTE, &STREAM, 0, EPOCH);
        assert_eq!(root_from_path(&leaf, &[]), leaf);
        assert_eq!(merkle_root(&[leaf]), leaf);
        // a single right-sibling step composes the documented way.
        let sib = [9u8; 32];
        let step = ProofStep {
            sibling: sib,
            sibling_is_right: true,
        };
        assert_eq!(root_from_path(&leaf, &[step]), super::hash_node(&leaf, &sib));
    }
}
