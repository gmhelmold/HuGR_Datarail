//! `datarail-replication` — FROZEN API (frozen by the lead); WP3 implements the bodies + gates.
//! Erasure-codes each record into `k` data + `m` parity shards over a [`BlobStore`], tolerating `m` lost shards
//! (Kafka-grade 2-failure durability at 1.5x storage, not RF=3's 3x).
#![forbid(unsafe_code)]
use datarail_blobstore::BlobStore;
use datarail_erasure::Rs;
use std::io::{Error, ErrorKind};

/// An erasure-coded replicated store over any [`BlobStore`].
///
/// Each record is split into `k` equal-length data shards (the last zero-padded) and encoded into `m` parity
/// shards. All `k + m` shards live at blob keys `<id>/<i>` (`i` in `0..k+m`); the original byte length is stored
/// at `<id>/len` so [`ErasureStore::get`] can strip the padding. Any `k` of the `k + m` shards reconstruct the
/// record byte-for-byte, so losing any `m` shards is survivable.
pub struct ErasureStore<B: BlobStore> {
    blob: B,
    rs: Rs,
    k: usize,
    m: usize,
}

impl<B: BlobStore> ErasureStore<B> {
    /// Build over `blob` with `k` data + `m` parity shards.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidInput`] if `k`/`m` are out of range (need `k >= 1`, `m >= 1`, `k + m <= 255`).
    pub fn new(blob: B, k: usize, m: usize) -> Result<Self, Error> {
        let rs = Rs::new(k, m).map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
        Ok(Self { blob, rs, k, m })
    }

    /// Borrow the backing blob store (lets callers/tests inspect the underlying shards).
    #[must_use]
    pub fn blob(&self) -> &B {
        &self.blob
    }

    /// Blob key for shard `i` of record `id`.
    fn shard_key(id: &str, i: usize) -> String {
        format!("{id}/{i}")
    }

    /// Blob key holding the original (un-padded) byte length of record `id`.
    fn len_key(id: &str) -> String {
        format!("{id}/len")
    }

    /// Store `data` under `id` as `k` data + `m` parity shards (keys `<id>/0..<id>/{k+m-1}`), plus the original
    /// length at `<id>/len`.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidData`] if the data is too large to record its length; otherwise any backend write
    /// failure, or an encoder error mapped to [`ErrorKind::InvalidData`].
    pub fn put(&mut self, id: &str, data: &[u8]) -> Result<(), Error> {
        // Equal-length shards; pad the tail with zeros. `max(1)` keeps empty records well-formed (no chunks(0)).
        let shard_len = data.len().div_ceil(self.k).max(1);
        let mut padded = vec![0u8; shard_len * self.k];
        padded[..data.len()].copy_from_slice(data);
        let shards: Vec<&[u8]> = padded.chunks(shard_len).collect();

        let parity = self
            .rs
            .encode(&shards)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        for (i, shard) in shards.iter().enumerate() {
            self.blob.put(&Self::shard_key(id, i), shard)?;
        }
        for (j, p) in parity.iter().enumerate() {
            self.blob.put(&Self::shard_key(id, self.k + j), p)?;
        }

        let len = u64::try_from(data.len()).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        self.blob.put(&Self::len_key(id), &len.to_le_bytes())?;
        Ok(())
    }

    /// Reconstruct `data` for `id` from any `k` surviving shards.
    ///
    /// Returns `Ok(None)` if the record is absent (no length header) or fewer than `k` shards survive (more than
    /// `m` were lost) — never wrong bytes.
    ///
    /// # Errors
    /// Backend read failure, a corrupt length header, or an encoder reconstruction error mapped to
    /// [`ErrorKind::InvalidData`].
    pub fn get(&self, id: &str) -> Result<Option<Vec<u8>>, Error> {
        let Some(len_bytes) = self.blob.get(&Self::len_key(id))? else {
            return Ok(None);
        };
        let len_arr = <[u8; 8]>::try_from(len_bytes.as_slice())
            .map_err(|_| Error::new(ErrorKind::InvalidData, "corrupt length header"))?;
        let orig_len = usize::try_from(u64::from_le_bytes(len_arr))
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        // Gather whichever of the k+m shards still exist.
        let mut survivors: Vec<(usize, Vec<u8>)> = Vec::with_capacity(self.k + self.m);
        for i in 0..self.k + self.m {
            if let Some(bytes) = self.blob.get(&Self::shard_key(id, i))? {
                survivors.push((i, bytes));
            }
        }
        if survivors.len() < self.k {
            return Ok(None);
        }

        let refs: Vec<(usize, &[u8])> = survivors.iter().map(|(i, b)| (*i, b.as_slice())).collect();
        let data_shards = self
            .rs
            .reconstruct(&refs)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        let mut out = Vec::with_capacity(data_shards.iter().map(Vec::len).sum());
        for shard in &data_shards {
            out.extend_from_slice(shard);
        }
        out.truncate(orig_len);
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::ErasureStore;
    use datarail_blobstore::{BlobStore, MemBlob};

    const K: usize = 4;
    const M: usize = 2;

    fn store() -> ErasureStore<MemBlob> {
        ErasureStore::new(MemBlob::new(), K, M).expect("valid k/m")
    }

    /// Visit every `depth`-element subset of `0..total`.
    fn for_each_subset(
        start: usize,
        depth: usize,
        pick: &mut Vec<usize>,
        total: usize,
        hit: &mut dyn FnMut(&[usize]),
    ) {
        if depth == pick.len() {
            hit(pick);
            return;
        }
        for x in start..total {
            pick[depth] = x;
            for_each_subset(x + 1, depth + 1, pick, total, hit);
        }
    }

    #[test]
    fn roundtrip_exact_without_loss() {
        let mut s = store();
        let data = b"the rail moves data in sealed vaults".to_vec();
        s.put("rec", &data).expect("put");
        assert_eq!(s.get("rec").expect("get"), Some(data));
    }

    #[test]
    fn missing_record_is_none() {
        let s = store();
        assert_eq!(s.get("nope").expect("get"), None);
    }

    #[test]
    fn recovers_from_every_double_loss() {
        // The headline gate: lose ANY m=2 of the k+m shards, still get the exact original bytes.
        let data: Vec<u8> = (0..1000u32).map(|i| i.to_le_bytes()[0]).collect();
        let total = K + M;
        let mut pick = vec![0usize; M];
        let mut patterns = 0usize;
        for_each_subset(0, 0, &mut pick, total, &mut |lost: &[usize]| {
            let mut s = store();
            s.put("rec", &data).expect("put");
            for &i in lost {
                assert!(s
                    .blob
                    .delete(&ErasureStore::<MemBlob>::shard_key("rec", i))
                    .expect("delete"));
            }
            assert_eq!(
                s.get("rec").expect("get"),
                Some(data.clone()),
                "losing {lost:?}"
            );
            patterns += 1;
        });
        assert_eq!(patterns, 15, "C(6,2) loss patterns");
    }

    #[test]
    fn losing_m_plus_one_shards_returns_none_not_wrong_data() {
        let data = b"durability is a measured number".to_vec();
        let total = K + M;
        let mut pick = vec![0usize; M + 1];
        for_each_subset(0, 0, &mut pick, total, &mut |lost: &[usize]| {
            let mut s = store();
            s.put("rec", &data).expect("put");
            for &i in lost {
                s.blob
                    .delete(&ErasureStore::<MemBlob>::shard_key("rec", i))
                    .expect("delete");
            }
            // Fewer than k survive: must be None, never silently-wrong bytes.
            assert_eq!(s.get("rec").expect("get"), None, "losing {lost:?}");
        });
    }

    #[test]
    fn length_not_divisible_by_k_roundtrips() {
        // 4 data shards; lengths spanning every residue mod k, padded correctly.
        for len in 0..=37usize {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 251).expect("fits"))
                .collect();
            let mut s = store();
            s.put("rec", &data).expect("put");
            // Drop 2 shards too, to prove padding survives reconstruction.
            s.blob
                .delete(&ErasureStore::<MemBlob>::shard_key("rec", 1))
                .expect("delete");
            s.blob
                .delete(&ErasureStore::<MemBlob>::shard_key("rec", K + 1))
                .expect("delete");
            assert_eq!(s.get("rec").expect("get"), Some(data), "len {len}");
        }
    }

    #[test]
    fn empty_and_short_data() {
        let mut s = store();
        s.put("empty", b"").expect("put");
        assert_eq!(s.get("empty").expect("get"), Some(Vec::new()));

        let mut s2 = store();
        s2.put("short", b"hi").expect("put"); // shorter than k bytes
                                              // survive a double loss on the short record too
        s2.blob
            .delete(&ErasureStore::<MemBlob>::shard_key("short", 0))
            .expect("delete");
        s2.blob
            .delete(&ErasureStore::<MemBlob>::shard_key("short", 3))
            .expect("delete");
        assert_eq!(s2.get("short").expect("get"), Some(b"hi".to_vec()));
    }

    #[test]
    fn bad_params_rejected() {
        assert!(ErasureStore::new(MemBlob::new(), 0, 2).is_err());
        assert!(ErasureStore::new(MemBlob::new(), 4, 0).is_err());
    }

    #[test]
    fn blob_accessor_is_live() {
        let mut s = store();
        s.put("rec", b"x").expect("put");
        // k+m shard keys + the len key.
        assert_eq!(s.blob().list("rec/").expect("list").len(), K + M + 1);
    }
}
