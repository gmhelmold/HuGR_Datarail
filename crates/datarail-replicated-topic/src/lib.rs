//! `datarail-replicated-topic` — FROZEN API (frozen by the lead); WP2 implements the bodies + gates.
//! Composes a [`datarail_topic::Topic`] (durable retained log) with a `datarail_replication::ErasureStore`
//! (erasure-coded shards over a [`BlobStore`]): every produced record is appended to the log AND sharded into
//! k+m blobs keyed by its offset, so a record survives the loss of any `m` shards — node-loss durability at 1.5x.
#![forbid(unsafe_code)]
use datarail_blobstore::BlobStore;
use datarail_replication::ErasureStore;
use datarail_topic::Topic;
use std::io::{Error, ErrorKind};

/// A decoded record: `(key, payload)`.
pub type Record = (Vec<u8>, Vec<u8>);

/// Default retained-log segment size (bytes) for the composed [`Topic`].
const SEGMENT_BYTES: u64 = 1 << 20;

/// Frame a record as `[u32 key_len][key][payload]` for shard storage.
///
/// # Errors
/// [`ErrorKind::InvalidInput`] if `key` is longer than [`u32::MAX`].
fn frame(key: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
    let key_len = u32::try_from(key.len()).map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
    let mut framed = Vec::with_capacity(4 + key.len() + payload.len());
    framed.extend_from_slice(&key_len.to_le_bytes());
    framed.extend_from_slice(key);
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// Split a framed record `[u32 key_len][key][payload]` back into `(key, payload)`.
fn unframe(framed: &[u8]) -> Option<Record> {
    let len_bytes: [u8; 4] = framed.get(..4)?.try_into().ok()?;
    let key_len = u32::from_le_bytes(len_bytes) as usize;
    let body = framed.get(4..)?;
    let key = body.get(..key_len)?;
    let payload = body.get(key_len..)?;
    Some((key.to_vec(), payload.to_vec()))
}

/// A topic with erasure-coded node-loss durability over a [`BlobStore`].
pub struct ReplicatedTopic<B: BlobStore> {
    topic: Topic,
    erasure: ErasureStore<B>,
}

impl<B: BlobStore> ReplicatedTopic<B> {
    /// Open at `dir` with the shard store `blob` and `k`+`m` erasure parameters.
    ///
    /// # Errors
    /// Filesystem error opening the log, or [`ErrorKind::InvalidInput`] if `k`/`m` are out of range.
    pub fn open(dir: &std::path::Path, blob: B, k: usize, m: usize) -> Result<Self, Error> {
        let topic = Topic::open(dir, SEGMENT_BYTES).map_err(Error::other)?;
        let erasure = ErasureStore::new(blob, k, m)?;
        Ok(Self { topic, erasure })
    }

    /// Borrow the shard store (lets callers/tests inspect the underlying shards).
    #[must_use]
    pub fn blob(&self) -> &B {
        self.erasure.blob()
    }

    /// Produce a record: append it to the durable log AND erasure-shard it under its offset. Returns the offset.
    ///
    /// The log is fsynced and the record is sharded into `k + m` blobs keyed by `<offset>/<i>`, so the record
    /// survives losing any `m` of its shards.
    ///
    /// # Errors
    /// Filesystem/codec error from the log, or [`ErrorKind::InvalidInput`] if `key` exceeds [`u32::MAX`].
    pub fn produce(&mut self, key: &[u8], payload: &[u8]) -> Result<u64, Error> {
        let offset = self.topic.produce(key, payload).map_err(Error::other)?;
        self.topic.sync().map_err(Error::other)?;
        let framed = frame(key, payload)?;
        self.erasure.put(&offset.to_string(), &framed)?;
        Ok(offset)
    }

    /// Reconstruct a record by its offset from its erasure shards (works even after losing any `m`).
    ///
    /// Returns `Ok(None)` for an unknown offset or when more than `m` shards are lost — never wrong bytes.
    ///
    /// # Errors
    /// Backend read failure, or [`ErrorKind::InvalidData`] if a shard's framing is corrupt.
    pub fn reconstruct(&self, offset: u64) -> Result<Option<Record>, Error> {
        let Some(framed) = self.erasure.get(&offset.to_string())? else {
            return Ok(None);
        };
        let record = unframe(&framed)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "corrupt record framing"))?;
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests {
    use super::ReplicatedTopic;
    use datarail_blobstore::{BlobStore, MemBlob};
    use std::sync::atomic::{AtomicU64, Ordering};

    const K: usize = 4;
    const M: usize = 2;

    static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "datarail-replicated-topic-{tag}-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn open(dir: &std::path::Path) -> ReplicatedTopic<MemBlob> {
        ReplicatedTopic::open(dir, MemBlob::new(), K, M).expect("open")
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

    /// Copy every blob out of `src` (read via the mandated `&B` accessor) into a fresh `MemBlob`, OMITTING the
    /// shard keys in `drop_keys` — i.e. simulate the loss of those shards. Returns the lossy store.
    fn store_missing(src: &ReplicatedTopic<MemBlob>, drop_keys: &[String]) -> MemBlob {
        let mut lossy = MemBlob::new();
        for key in src.blob().list("").expect("list") {
            if drop_keys.contains(&key) {
                continue;
            }
            let bytes = src.blob().get(&key).expect("get").expect("present");
            lossy.put(&key, &bytes).expect("put");
        }
        lossy
    }

    /// Normal roundtrip: produce several records, reconstruct each exactly.
    #[test]
    fn produce_then_reconstruct_roundtrip() {
        let dir = tmpdir("roundtrip");
        let mut rt = open(&dir);
        let records: Vec<(Vec<u8>, Vec<u8>)> = (0..20u32)
            .map(|i| {
                (
                    format!("key-{i}").into_bytes(),
                    format!("payload-value-{i}").into_bytes(),
                )
            })
            .collect();
        let mut offsets = Vec::new();
        for (k, v) in &records {
            offsets.push(rt.produce(k, v).expect("produce"));
        }
        for (off, (k, v)) in offsets.iter().zip(&records) {
            assert_eq!(
                rt.reconstruct(*off).expect("reconstruct"),
                Some((k.clone(), v.clone()))
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Headline gate: produce several records; for ONE, drop ANY `m` of its `<offset>/<i>` shard blobs and confirm
    /// `reconstruct` still returns the EXACT original `(key, payload)`. Every distinct m-subset is exercised.
    ///
    /// `ErasureStore` only lends the store as `&B`, and `MemBlob::delete` needs `&mut`, so shard loss is staged by
    /// reconstructing over a copy of the live store (read through `.blob()`) that is missing the chosen `m` shards —
    /// driving the real `reconstruct` path, the property the gate asserts.
    #[test]
    fn reconstruct_survives_every_m_shard_loss() {
        let dir = tmpdir("mloss-src");
        let mut rt = open(&dir);
        // Produce several records; target the middle one.
        rt.produce(b"decoy-a", b"alpha").expect("produce");
        let key = b"the-durable-key".to_vec();
        let payload = b"a record that must survive node loss".to_vec();
        let off = rt.produce(&key, &payload).expect("produce");
        rt.produce(b"decoy-b", b"beta").expect("produce");

        let id = off.to_string();
        let total = K + M;
        let mut pick = vec![0usize; M];
        let mut patterns = 0usize;
        for_each_subset(0, 0, &mut pick, total, &mut |lost: &[usize]| {
            let drop_keys: Vec<String> = lost.iter().map(|i| format!("{id}/{i}")).collect();
            let lossy = store_missing(&rt, &drop_keys);
            let degraded_dir = tmpdir("mloss-degraded");
            let degraded =
                ReplicatedTopic::open(&degraded_dir, lossy, K, M).expect("open degraded");
            assert_eq!(
                degraded.reconstruct(off).expect("reconstruct"),
                Some((key.clone(), payload.clone())),
                "losing shards {lost:?}"
            );
            patterns += 1;
            let _ = std::fs::remove_dir_all(&degraded_dir);
        });
        assert_eq!(patterns, 15, "C(6,2) loss patterns");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reconstruct of an unknown offset returns None.
    #[test]
    fn reconstruct_unknown_offset_is_none() {
        let dir = tmpdir("unknown");
        let mut rt = open(&dir);
        rt.produce(b"k", b"v").expect("produce");
        assert_eq!(rt.reconstruct(999_999).expect("reconstruct"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
