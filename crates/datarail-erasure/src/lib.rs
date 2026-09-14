//! `datarail-erasure` — a minimal **systematic Reed-Solomon erasure codec** over GF(2⁸), built so datarail can
//! offer Kafka-grade fault tolerance at a fraction of the write cost.
//!
//! **The point (ledger #3).** Kafka survives 2 node losses by **replication factor 3** — it writes every byte
//! **3×** (and ships 2× extra over the network). Reed-Solomon survives the *same* 2 losses with `m = 2` parity
//! shards over `k` data shards: storage is `(k+m)/k`. At `k = 4, m = 2` that is **1.5×**, not 3× — **half the
//! storage and bandwidth for the same durability.** This crate is the codec that makes that real and *proven*
//! (encode → lose any `m` shards → reconstruct byte-for-byte), with an exhaustive gate.
//!
//! **Honest scope.** This is the *codec* — the math that lets datarail match RF=3 durability at 1.5× overhead.
//! It is `#![forbid(unsafe_code)]`, zero-dependency, and exhaustively gated. Wiring it to **distributed shard
//! placement** across nodes/object-stores (so the 1.5× is realized end-to-end) is a separate, later layer; this
//! crate proves the encoding is correct and MDS, not that datarail already runs erasure-coded across a cluster.
//!
//! Construction: a **Cauchy** parity matrix over GF(2⁸) (primitive polynomial `0x11D`). Cauchy matrices are MDS
//! — *every* square submatrix is invertible — so the systematic `(k+m, k)` code reconstructs the `k` data shards
//! from **any** `k` of the `k+m` shards.

/// GF(2⁸) exp/log tables (generator 2, primitive polynomial `x⁸+x⁴+x³+x²+1` = `0x11D`), built at compile time.
const TABLES: ([u8; 256], [u8; 256]) = {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x: u8 = 1;
    let mut i: u8 = 0;
    while i < 255 {
        exp[i as usize] = x;
        log[x as usize] = i;
        // Multiply x by the generator (2) in GF(2⁸): left shift, and on carry-out reduce by 0x11D (low 8 bits).
        let carry = x & 0x80;
        x <<= 1;
        if carry != 0 {
            x ^= 0x1D;
        }
        i += 1;
    }
    (exp, log)
};
const EXP: [u8; 256] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

/// GF(2⁸) multiply.
#[must_use]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let s = LOG[a as usize] as usize + LOG[b as usize] as usize;
    EXP[s % 255]
}

/// GF(2⁸) multiplicative inverse. `a` must be non-zero (callers guarantee it — Cauchy never forms `x^y == 0`,
/// and `invert` only inverts non-zero pivots). The `debug_assert` documents that contract (WP7 audit hardening).
#[must_use]
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "gf_inv(0) is undefined");
    EXP[(255 - LOG[a as usize] as usize) % 255]
}

/// What can go wrong building or using the codec.
#[derive(Debug, PartialEq, Eq)]
pub enum ErasureError {
    /// `k`/`m` out of range (need `k ≥ 1`, `m ≥ 1`, `k + m ≤ 255`).
    BadParams,
    /// Wrong number of data shards passed to [`Rs::encode`] (expected `k`).
    WrongShardCount,
    /// Shards passed in were not all the same length.
    RaggedShards,
    /// Fewer than `k` surviving shards given to [`Rs::reconstruct`] — recovery is impossible.
    NotEnoughShards,
    /// A survivor referenced a shard index ≥ `k + m`, or two survivors shared an index.
    BadShardIndex,
}

impl core::fmt::Display for ErasureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::BadParams => "k/m out of range (need k>=1, m>=1, k+m<=255)",
            Self::WrongShardCount => "wrong number of data shards (expected k)",
            Self::RaggedShards => "shards are not all the same length",
            Self::NotEnoughShards => "fewer than k surviving shards — cannot reconstruct",
            Self::BadShardIndex => "shard index out of range or duplicated",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ErasureError {}

/// A systematic `(k + m, k)` Reed-Solomon erasure codec: `k` data shards, `m` parity shards, tolerates the loss
/// of any `m` shards.
#[derive(Debug, Clone)]
pub struct Rs {
    k: usize,
    m: usize,
    /// `m × k` Cauchy parity matrix (row `i` produces parity shard `i`).
    cauchy: Vec<Vec<u8>>,
}

impl Rs {
    /// Build a codec with `k` data + `m` parity shards.
    ///
    /// # Errors
    /// [`ErasureError::BadParams`] if `k < 1`, `m < 1`, or `k + m > 255`.
    pub fn new(k: usize, m: usize) -> Result<Self, ErasureError> {
        if k < 1 || m < 1 || k + m > 255 {
            return Err(ErasureError::BadParams);
        }
        // Cauchy entry C[i][j] = 1 / (x_i ⊕ y_j) with the disjoint point sets x_i = i (0..m), y_j = m+j (0..k).
        // Disjoint ⇒ x_i ⊕ y_j ≠ 0; Cauchy ⇒ every square submatrix is invertible (MDS).
        let mut cauchy = Vec::with_capacity(m);
        for i in 0..m {
            let mut row = Vec::with_capacity(k);
            for j in 0..k {
                let x = u8::try_from(i).map_err(|_| ErasureError::BadParams)?;
                let y = u8::try_from(m + j).map_err(|_| ErasureError::BadParams)?;
                row.push(gf_inv(x ^ y));
            }
            cauchy.push(row);
        }
        Ok(Self { k, m, cauchy })
    }

    /// Number of data shards.
    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    /// Number of parity shards (= the number of simultaneous losses tolerated).
    #[must_use]
    pub fn m(&self) -> usize {
        self.m
    }

    /// Storage (and write-bandwidth) overhead vs the raw data: `(k + m) / k`. Compare to replication's `RF`
    /// (e.g. RF=3) for the same `m`-failure tolerance.
    #[must_use]
    pub fn storage_overhead(&self) -> f64 {
        let total = u32::try_from(self.k + self.m).unwrap_or(u32::MAX);
        let data = u32::try_from(self.k).unwrap_or(1);
        f64::from(total) / f64::from(data)
    }

    /// Encode `data` (exactly `k` equal-length shards) into `m` parity shards (systematic: the data shards are
    /// themselves the first `k` code shards and are returned unchanged by the caller).
    ///
    /// # Errors
    /// [`ErasureError::WrongShardCount`] if `data.len() != k`; [`ErasureError::RaggedShards`] if the shards
    /// differ in length.
    pub fn encode(&self, data: &[&[u8]]) -> Result<Vec<Vec<u8>>, ErasureError> {
        if data.len() != self.k {
            return Err(ErasureError::WrongShardCount);
        }
        let len = data.first().map_or(0, |s| s.len());
        if data.iter().any(|s| s.len() != len) {
            return Err(ErasureError::RaggedShards);
        }
        let mut parity = vec![vec![0u8; len]; self.m];
        for (prow, crow) in parity.iter_mut().zip(self.cauchy.iter()) {
            for (shard, &c) in data.iter().zip(crow.iter()) {
                if c == 0 {
                    continue;
                }
                for (p, &d) in prow.iter_mut().zip(shard.iter()) {
                    *p ^= gf_mul(c, d);
                }
            }
        }
        Ok(parity)
    }

    /// The encoding-matrix row that produces code shard `idx`: a unit vector for a data shard (`idx < k`) or the
    /// Cauchy row for a parity shard (`k ≤ idx < k+m`).
    fn code_row(&self, idx: usize) -> Vec<u8> {
        if idx < self.k {
            let mut row = vec![0u8; self.k];
            row[idx] = 1;
            row
        } else {
            self.cauchy[idx - self.k].clone()
        }
    }

    /// Reconstruct the `k` data shards from **any** `k` (or more) surviving shards, each given as
    /// `(code_index, bytes)` where `code_index ∈ [0, k+m)` (`< k` = data shard, `≥ k` = parity shard).
    ///
    /// # Errors
    /// [`ErasureError::NotEnoughShards`] if fewer than `k` survivors; [`ErasureError::BadShardIndex`] if an index
    /// is out of range or duplicated; [`ErasureError::RaggedShards`] if survivors differ in length.
    pub fn reconstruct(&self, survivors: &[(usize, &[u8])]) -> Result<Vec<Vec<u8>>, ErasureError> {
        if survivors.len() < self.k {
            return Err(ErasureError::NotEnoughShards);
        }
        let chosen = &survivors[..self.k];
        let len = chosen.first().map_or(0, |(_, b)| b.len());
        let mut seen = vec![false; self.k + self.m];
        for &(idx, b) in chosen {
            if idx >= self.k + self.m || seen[idx] {
                return Err(ErasureError::BadShardIndex);
            }
            seen[idx] = true;
            if b.len() != len {
                return Err(ErasureError::RaggedShards);
            }
        }
        // Build the k×k matrix mapping the k original data shards → the chosen survivors, then invert it.
        let matrix: Vec<Vec<u8>> = chosen.iter().map(|&(idx, _)| self.code_row(idx)).collect();
        let inv = invert(matrix).ok_or(ErasureError::BadShardIndex)?;
        // data[j] = Σ_r inv[j][r] · survivor_r  (over each byte position).
        let mut data = vec![vec![0u8; len]; self.k];
        for (j, out) in data.iter_mut().enumerate() {
            for (r, &(_, bytes)) in chosen.iter().enumerate() {
                let coeff = inv[j][r];
                if coeff == 0 {
                    continue;
                }
                for (o, &s) in out.iter_mut().zip(bytes.iter()) {
                    *o ^= gf_mul(coeff, s);
                }
            }
        }
        Ok(data)
    }
}

/// Invert a square GF(2⁸) matrix by Gauss-Jordan elimination on `[matrix | I]`. Returns `None` if singular.
fn invert(mut matrix: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let n = matrix.len();
    let mut inv: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let mut row = vec![0u8; n];
            row[i] = 1;
            row
        })
        .collect();
    for col in 0..n {
        // Find a pivot row at or below `col` with a non-zero entry in `col`.
        let pivot = (col..n).find(|&r| matrix[r][col] != 0)?;
        matrix.swap(col, pivot);
        inv.swap(col, pivot);
        // Normalize the pivot row so matrix[col][col] == 1.
        let p_inv = gf_inv(matrix[col][col]);
        for c in 0..n {
            matrix[col][c] = gf_mul(matrix[col][c], p_inv);
            inv[col][c] = gf_mul(inv[col][c], p_inv);
        }
        // Eliminate `col` from every other row.
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = matrix[r][col];
            if factor == 0 {
                continue;
            }
            for c in 0..n {
                matrix[r][c] ^= gf_mul(factor, matrix[col][c]);
                inv[r][c] ^= gf_mul(factor, inv[col][c]);
            }
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::{gf_inv, gf_mul, ErasureError, Rs};

    /// Visit every `m`-element subset of `0..total` (the loss patterns).
    fn for_each_subset(
        start: usize,
        depth: usize,
        total: usize,
        lost: &mut Vec<usize>,
        hit: &mut dyn FnMut(&[usize]),
    ) {
        if depth == lost.len() {
            hit(lost);
            return;
        }
        for x in start..total {
            lost[depth] = x;
            for_each_subset(x + 1, depth + 1, total, lost, hit);
        }
    }

    #[test]
    fn gf_field_axioms_hold() {
        // 0 annihilates; 1 is identity; every non-zero element has an inverse.
        for a in 0u8..=255 {
            assert_eq!(gf_mul(a, 0), 0);
            assert_eq!(gf_mul(a, 1), a);
            if a != 0 {
                assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a}");
            }
        }
    }

    /// The headline gate: encode k data shards, then for EVERY way to lose `m` of the `k+m` shards, reconstruct
    /// the original data byte-for-byte. Exhaustive over all C(k+m, m) loss patterns.
    fn exhaustive_recovery(k: usize, m: usize, len: usize) {
        let rs = Rs::new(k, m).expect("params");
        // Deterministic but varied shard data (low byte of each index → no usize→u8 cast).
        let data: Vec<Vec<u8>> = (0..k)
            .map(|j| {
                let jb = j.to_le_bytes()[0];
                (0..len)
                    .map(|b| {
                        jb.wrapping_mul(31)
                            .wrapping_add(b.to_le_bytes()[0].wrapping_mul(17))
                    })
                    .collect()
            })
            .collect();
        let data_refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let parity = rs.encode(&data_refs).expect("encode");

        // All k+m code shards, indexed: 0..k data, k..k+m parity.
        let mut all: Vec<(usize, Vec<u8>)> = Vec::new();
        for (j, d) in data.iter().enumerate() {
            all.push((j, d.clone()));
        }
        for (i, p) in parity.iter().enumerate() {
            all.push((k + i, p.clone()));
        }

        let total = k + m;
        // Iterate every subset of `m` indices to delete (so `k` survive).
        let mut lost = vec![0usize; m];
        let mut count = 0usize;
        for_each_subset(0, 0, total, &mut lost, &mut |lost_set: &[usize]| {
            let survivors: Vec<(usize, &[u8])> = all
                .iter()
                .filter(|(idx, _)| !lost_set.contains(idx))
                .map(|(idx, bytes)| (*idx, bytes.as_slice()))
                .collect();
            let recovered = rs.reconstruct(&survivors).expect("reconstruct");
            assert_eq!(
                recovered, data,
                "recovery failed losing shards {lost_set:?}"
            );
            count += 1;
        });
        // Sanity: we actually exercised C(total, m) patterns.
        assert!(count > 0, "no loss patterns tested");
    }

    #[test]
    fn rs_4_2_recovers_from_every_double_loss() {
        // RF=3-equivalent: survives any 2 losses, at 1.5× storage instead of 3×.
        exhaustive_recovery(4, 2, 64);
    }

    #[test]
    fn rs_6_3_recovers_from_every_triple_loss() {
        exhaustive_recovery(6, 3, 50);
    }

    #[test]
    fn rs_10_4_recovers_from_every_quadruple_loss() {
        exhaustive_recovery(10, 4, 33);
    }

    #[test]
    fn storage_overhead_is_1_5x_for_rf3_equivalence() {
        let rs = Rs::new(4, 2).expect("params");
        assert!((rs.storage_overhead() - 1.5).abs() < 1e-9);
        // …vs replication's 3× for the same 2-failure tolerance: a 2× write/storage saving.
    }

    #[test]
    fn bad_params_and_shapes_are_rejected() {
        assert_eq!(Rs::new(0, 2).unwrap_err(), ErasureError::BadParams);
        assert_eq!(Rs::new(4, 0).unwrap_err(), ErasureError::BadParams);
        assert_eq!(Rs::new(200, 200).unwrap_err(), ErasureError::BadParams);
        let rs = Rs::new(3, 2).expect("params");
        let two: Vec<&[u8]> = vec![&[1, 2], &[3, 4]];
        assert_eq!(rs.encode(&two).unwrap_err(), ErasureError::WrongShardCount);
        let ragged: Vec<&[u8]> = vec![&[1, 2], &[3], &[4, 5]];
        assert_eq!(rs.encode(&ragged).unwrap_err(), ErasureError::RaggedShards);
        let too_few: Vec<(usize, &[u8])> = vec![(0, &[1, 2])];
        assert_eq!(
            rs.reconstruct(&too_few).unwrap_err(),
            ErasureError::NotEnoughShards
        );
    }
}
