//! `datarail-substrate-objectstore` — the SPEC `10` / `07` **object-store (S3) substrate**: a dumb,
//! provider-blind durable holding pen for temporal decoupling (the destination is offline) or fan-out
//! buffering. The source PUTs sealed cofres keyed by `<route_id>/<stream_id>/<seq>`; the destination GETs them
//! in `seq` order and deletes each post-ack (GC). The store sees **only ciphertext** (`INV-OPAQUE-CARGO`) and
//! holds **no keys** (`INV-DUMB-PIPE`) — a breach of the bucket yields useless bytes.
//!
//! This crate ships a **filesystem-backed** implementation (a `bucket` is a directory, an object is a file):
//! it fully exercises the store semantics — keyed idempotent PUT, ordered GET, delete-post-ack — and passes
//! the same [`substrate_conformance`](datarail_rail::substrate_conformance) harness as every other substrate
//! (`INV-SUBSTRATE-POLYMORPHIC`). A real S3/GCS/R2 backend is the *same* trait with the PUT/GET/DELETE verbs
//! pointed at a bucket API behind a credential-gated adapter — not a redesign (the cofre is already sealed, so
//! the object client adds no crypto). Keeping this substrate in its own crate keeps the std-only rail core
//! dependency-free.
//!
//! **Durability decoupled from RAM** (the audit's WP5 answer). Delivery dedup is a **forward read cursor**, the
//! way `datarail-substrate-wal` does it: a per-stream monotonic `seq` watermark — a record is deliverable iff
//! its `seq` is past its stream's cursor; `recv` advances the cursor, `ack` GCs the object. The cursor map is
//! O(number of live streams), NOT O(stored volume); the ack→object map is O(the in-flight, delivered-but-un-acked
//! window) and is reclaimed on ack. There is **no in-RAM id-set that grows with total stored volume** (the prior
//! unbounded `HashSet<PathBuf>` + cumulative ack log was the leak the adversarial audit flagged).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use datarail_core::{Cofre, Substrate};

/// A provider-blind object-store [`Substrate`], filesystem-backed (the reference for the `s3` substrate).
///
/// Layout per SPEC `10`: `<bucket>/<route_id>/<stream_id>/<seq>.cofre`, one sealed cofre per object.
/// [`send`](Substrate::send) PUTs (atomically: write-temp-then-rename; re-PUT of the same `seq` is a no-op);
/// [`recv`](Substrate::recv) GETs the lowest `(route, stream, seq)` object whose `seq` is past its stream's read
/// cursor (seq order within a stream); [`ack`](Substrate::ack) deletes the object (GC). The store never decrypts,
/// validates, or orders content — those are the terminal's and the rail-protocol's jobs.
///
/// **Bookkeeping is bounded** (see crate docs): the read cursor is O(live streams) and the ack map is
/// O(in-flight window) — neither grows with total stored volume.
///
/// v1 note: `recv` still scans the bucket each call (`O(n)` in stored objects) — correct and simple for bounded
/// holding pens; the RAM, not the scan, was the audit's target. A production driver would also keep the scan
/// cursor on disk (this one keeps the dedup cursor in RAM, so a reopened instance redelivers the un-acked
/// objects still on disk — exactly the at-least-once + downstream-dedup model the rail already relies on).
#[derive(Debug)]
pub struct ObjectStoreSubstrate {
    bucket: PathBuf,
    /// Forward read cursor: stream directory (`<bucket>/<route>/<stream>`) → highest `seq` delivered from it.
    /// An object is already-delivered iff its `seq <= cursor[stream]`. Bounded by the number of live streams
    /// (NOT total stored volume) — the O(1)-on-volume replacement for the prior unbounded `delivered` set.
    cursors: HashMap<PathBuf, u64>,
    /// `cofre_id` → object key, so `ack` can delete exactly the right object. Bounded by the in-flight,
    /// delivered-but-un-acked window: every `recv` inserts one entry, every `ack` removes it (O(in-flight),
    /// reclaimed on ack — not O(total)).
    by_id: HashMap<[u8; 32], PathBuf>,
}

impl ObjectStoreSubstrate {
    /// Open a bucket rooted at `bucket`, creating the directory if it does not exist.
    ///
    /// # Errors
    /// [`std::io::Error`] if the bucket directory cannot be created.
    pub fn open(bucket: impl Into<PathBuf>) -> std::io::Result<Self> {
        let bucket = bucket.into();
        std::fs::create_dir_all(&bucket)?;
        Ok(Self {
            bucket,
            cursors: HashMap::new(),
            by_id: HashMap::new(),
        })
    }

    /// Total live bookkeeping entries: the read cursor (O(live streams)) plus the in-flight ack map
    /// (O(delivered-but-un-acked window)). Neither term grows with total stored/acked volume — this is the
    /// accessor the WP5 bound-gate asserts stays bounded across a large send→recv→ack cycle.
    #[must_use]
    pub fn bookkeeping_len(&self) -> usize {
        self.cursors.len() + self.by_id.len()
    }

    /// The object key for a cofre: `<bucket>/<route_id>/<stream_id>/<seq>.cofre` (SPEC 10). `seq` is
    /// zero-padded so lexicographic key order equals numeric seq order.
    fn object_path(&self, cofre: &Cofre) -> PathBuf {
        let e = &cofre.etiqueta;
        self.bucket
            .join(hex16(&e.route_id))
            .join(hex16(&e.stream_id))
            .join(format!("{:020}.cofre", e.seq))
    }

    /// Every stored object key, sorted — `(route, stream, seq)` order (seq order within a stream).
    fn sorted_objects(&self) -> std::io::Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        collect_cofres(&self.bucket, &mut out)?;
        out.sort();
        Ok(out)
    }
}

impl Substrate for ObjectStoreSubstrate {
    type Error = std::io::Error;

    /// PUT the sealed cofre at its `seq`-keyed object path, atomically (write a temp sibling, then rename).
    /// Idempotent: re-PUT of the same `seq` overwrites identical bytes — a no-op in effect.
    ///
    /// # Errors
    /// [`std::io::Error`] on a directory-create, write, or rename failure.
    fn send(&mut self, cofre: &Cofre) -> Result<(), Self::Error> {
        let path = self.object_path(cofre);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = datarail_cofre::encode(cofre);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// GET the lowest-keyed object whose `seq` is past its stream's read cursor (seq order within a stream);
    /// `None` when the bucket holds nothing new. The object's `(stream, seq)` coordinates live in its PATH (the
    /// store wrote `<route>/<stream>/<seq>.cofre`), so an already-delivered object is skipped from the cursor
    /// **without reading it** — no per-object RAM is retained. Decodes the wire bytes to return the cofre but
    /// never inspects `carga` (`INV-OPAQUE-CARGO`).
    ///
    /// **Precondition (WP7 audit C3):** the high-watermark cursor assumes a stream's objects ARRIVE in `seq`
    /// order (the in-order source the rail provides). A `seq` that appears in the bucket *after* a higher `seq`
    /// from the same stream was already delivered is treated as already-seen and skipped — fine for the in-order
    /// rail, but callers feeding a stream out of order must not rely on the late-lower-seq being delivered.
    ///
    /// # Errors
    /// [`std::io::Error`] on a read failure (a non-`seq` filename is skipped, not an error — WP7 H1), or
    /// `InvalidData` if a stored object exceeds the max size or its bytes fail to decode.
    fn recv(&mut self) -> Result<Option<Cofre>, Self::Error> {
        for path in self.sorted_objects()? {
            // WP7 audit H1 fix: a `*.cofre` whose name isn't a store seq was never written by this store — SKIP
            // it, don't abort the whole `recv`. Erroring let one crafted filename from a hostile storage operator
            // make every legit cofre behind it undeliverable (a one-file DoS).
            let Ok(seq) = parse_seq(&path) else { continue };
            let stream_dir = path.parent().map(Path::to_path_buf);
            // Forward-cursor dedup: a record is deliverable iff its seq is past its stream's monotonic cursor.
            // Cheap (path-only) skip of already-delivered objects — no read, no retained id.
            if stream_dir
                .as_ref()
                .is_some_and(|dir| self.cursors.get(dir).is_some_and(|&c| seq <= c))
            {
                continue;
            }
            // Bound the read (AUDIT-03 F3): refuse an object larger than one max cofre, so a malicious storage
            // operator cannot force an unbounded read.
            if std::fs::metadata(&path)?.len() > datarail_core::MAX_COFRE_WIRE_LEN as u64 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "stored object exceeds the maximum cofre size",
                ));
            }
            let bytes = std::fs::read(&path)?;
            let cofre = datarail_cofre::decode(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            // Advance the cursor (O(live streams)) and record the ack mapping (O(in-flight), reclaimed on ack).
            if let Some(dir) = stream_dir {
                self.cursors.insert(dir, seq);
            }
            self.by_id.insert(cofre.etiqueta.cofre_id, path);
            return Ok(Some(cofre));
        }
        Ok(None)
    }

    /// Record an acknowledgement and GC the object (delete-post-ack, SPEC 10). A missing object is fine — ack
    /// is idempotent and the object may already have been collected. Reclaims the cofre's in-flight ack entry,
    /// keeping that map bounded by the un-acked window.
    ///
    /// # Errors
    /// [`std::io::Error`] on a delete failure other than "not found".
    fn ack(&mut self, cofre_id: [u8; 32]) -> Result<(), Self::Error> {
        if let Some(path) = self.by_id.remove(&cofre_id) {
            let stream_dir = path.parent().map(Path::to_path_buf);
            if let Err(e) = std::fs::remove_file(&path) {
                // A missing object is fine (already collected / idempotent ack); anything else propagates.
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e);
                }
            }
            // WP7 audit C1/C2 fix: when a stream's last object is acked+GC'd, drop its cursor entry (and the now-
            // empty dir). This makes `cursors` genuinely O(LIVE streams) — not O(every stream ever seen) — and
            // lets a later reuse of the same stream id start fresh instead of silently skipping its low seqs.
            if let Some(dir) = stream_dir {
                if stream_drained(&dir) {
                    self.cursors.remove(&dir);
                    let _ = std::fs::remove_dir(&dir);
                }
            }
        }
        Ok(())
    }
}

/// Whether a stream directory has no remaining `*.cofre` objects (its delivered history is fully GC'd).
fn stream_drained(dir: &Path) -> bool {
    match std::fs::read_dir(dir) {
        Ok(entries) => !entries
            .flatten()
            .any(|e| e.path().extension().is_some_and(|x| x == "cofre")),
        Err(_) => false,
    }
}

/// Parse the `seq` encoded in an object's filename (`{seq:020}.cofre`). A `*.cofre` whose name is not a store
/// `seq` was never written by this store — reject it defensively (parse-before-verify) rather than guess.
fn parse_seq(path: &Path) -> std::io::Result<u64> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stored object name is not a valid seq key",
            )
        })
}

/// Lowercase-hex a 16-byte id for use as a filesystem-safe path segment.
fn hex16(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for &b in bytes {
        s.push(char::from(HEX[(b >> 4) as usize]));
        s.push(char::from(HEX[(b & 0x0f) as usize]));
    }
    s
}

/// Recursively collect every `*.cofre` object path under `dir` (a non-directory or missing path yields none).
fn collect_cofres(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_cofres(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("cofre") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ObjectStoreSubstrate;
    use datarail_core::Substrate;
    use datarail_rail::{substrate_conformance, testsupport};
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    /// A unique, per-test temp bucket path (no tempfile dep — `forbid(unsafe)` + leveza).
    fn temp_bucket() -> std::path::PathBuf {
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("datarail-objstore-{}-{n}", std::process::id()))
    }

    #[test]
    fn ac6_objectstore_passes_substrate_conformance() {
        // The SAME AC-6 flow over a real on-disk, provider-blind object store: seq-keyed PUT → ordered GET → ack.
        let dir = temp_bucket();
        substrate_conformance(|| ObjectStoreSubstrate::open(&dir).expect("open bucket"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decoupled_source_puts_then_a_separate_dest_drains_in_seq_order() {
        // The store's reason to exist: SOURCE and DEST are never online together — they rendezvous only via
        // the bucket. Source PUTs a batch and goes away; a SEPARATE dest instance later drains it in seq order
        // and GCs each object on ack.
        let dir = temp_bucket();
        {
            let mut src = ObjectStoreSubstrate::open(&dir).expect("open source");
            for seq in 0..4 {
                src.send(&testsupport::cofre_seq(seq)).expect("PUT");
            }
        } // source dropped — only the bucket persists

        let mut dst = ObjectStoreSubstrate::open(&dir).expect("reopen as dest");
        for seq in 0..4 {
            let got = dst.recv().expect("GET").expect("a cofre is present");
            assert_eq!(
                got,
                testsupport::cofre_seq(seq),
                "objects delivered in seq order, byte-for-byte"
            );
            dst.ack(got.etiqueta.cofre_id).expect("ack + GC");
        }
        assert!(
            dst.recv().expect("drain").is_none(),
            "bucket fully drained after GC"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reput_same_seq_is_idempotent() {
        // SPEC 10: the seq is the key → a re-PUT is a no-op (at-least-once sources don't duplicate objects).
        let dir = temp_bucket();
        let mut store = ObjectStoreSubstrate::open(&dir).expect("open");
        let cofre = testsupport::cofre_seq(7);
        store.send(&cofre).expect("PUT 1");
        store.send(&cofre).expect("PUT 2 (idempotent)");

        let got = store.recv().expect("GET").expect("one cofre");
        assert_eq!(got, cofre);
        assert!(
            store.recv().expect("drain").is_none(),
            "re-PUT produced exactly one object, not two"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delivered_object_is_not_redelivered_before_ack() {
        // The cursor dedups WITHOUT an ack: a delivered-but-un-acked object must not be handed out twice, and
        // the next un-delivered seq must follow it (forward-only, in seq order).
        let dir = temp_bucket();
        let mut store = ObjectStoreSubstrate::open(&dir).expect("open");
        store.send(&testsupport::cofre_seq(0)).expect("PUT 0");
        store.send(&testsupport::cofre_seq(1)).expect("PUT 1");

        let a = store.recv().expect("GET 0").expect("cofre 0");
        assert_eq!(a, testsupport::cofre_seq(0));
        // Without acking a, recv must advance to seq 1 (not redeliver seq 0).
        let b = store.recv().expect("GET 1").expect("cofre 1");
        assert_eq!(b, testsupport::cofre_seq(1));
        assert!(
            store.recv().expect("drain").is_none(),
            "both delivered, none redelivered"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WP5 BOUND-GATE (deterministic, cross-platform): the live bookkeeping must stay bounded by
    /// (live streams) + (in-flight window), INDEPENDENT of total stored/acked volume. Drive a large
    /// send→recv→ack cycle on a single stream with in-flight pinned to ~1 and assert `bookkeeping_len()`
    /// never exceeds a small constant — the direct refutation of the audit's unbounded-`HashSet` finding.
    #[test]
    fn bookkeeping_stays_bounded_across_a_large_cycle() {
        const N: u64 = 5_000;
        let dir = temp_bucket();
        let mut store = ObjectStoreSubstrate::open(&dir).expect("open");
        for seq in 0..N {
            store.send(&testsupport::cofre_seq(seq)).expect("PUT");
            let got = store.recv().expect("GET").expect("a cofre");
            // 1 stream cursor + 1 in-flight (delivered, not yet acked).
            assert!(
                store.bookkeeping_len() <= 2,
                "bookkeeping must stay bounded by streams+in-flight at seq {seq}, got {}",
                store.bookkeeping_len()
            );
            store.ack(got.etiqueta.cofre_id).expect("ack + GC");
            // After ack the in-flight entry is reclaimed: only the stream cursor remains.
            assert!(
                store.bookkeeping_len() <= 1,
                "ack must reclaim the in-flight entry at seq {seq}, got {}",
                store.bookkeeping_len()
            );
        }
        // WP7 audit C1 fix: a FULLY-DRAINED stream reclaims its cursor too — bookkeeping returns to ZERO, not a
        // lingering per-stream entry. This is the truly-O(live-streams) bound (drained ≠ live), and it refutes the
        // audit's "cursors never removed" finding directly.
        assert_eq!(
            store.bookkeeping_len(),
            0,
            "drained stream ⇒ cursor GC'd too (O(LIVE streams), not lifetime)"
        );
        assert!(
            store.recv().expect("drain").is_none(),
            "bucket fully drained"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// HONEST counter-gate (mirrors the WAL's): a large UN-acked delivered backlog costs O(in-flight) — the ack
    /// map holds one entry per delivered-but-un-acked object — and is RECLAIMED on ack (so it is bounded, not a
    /// leak). The cursor stays O(1) per stream throughout.
    #[test]
    fn unacked_backlog_is_o_inflight_and_reclaimed_on_ack() {
        // Kept modest: every `recv` rescans the (un-GC'd) backlog, so this gate is O(N²) by design — N is
        // sized to prove the O(in-flight) shape, not to stress the scan (the RAM bound is the point here).
        const N: u64 = 600;
        let dir = temp_bucket();
        let mut store = ObjectStoreSubstrate::open(&dir).expect("open");
        for seq in 0..N {
            store.send(&testsupport::cofre_seq(seq)).expect("PUT");
        }
        // Deliver everything WITHOUT acking → the ack map holds N entries (the honest in-flight cost).
        let mut ids = Vec::new();
        while let Some(c) = store.recv().expect("recv") {
            ids.push(c.etiqueta.cofre_id);
        }
        assert_eq!(
            ids.len(),
            usize::try_from(N).expect("fits"),
            "all delivered"
        );
        // 1 stream cursor + N in-flight.
        assert_eq!(
            store.bookkeeping_len(),
            1 + ids.len(),
            "backlog ⇒ O(in-flight) bookkeeping"
        );
        // Ack everything → the in-flight map is released, and the now-fully-drained stream reclaims its cursor
        // too (WP7 audit C1 fix), so bookkeeping returns to ZERO — O(LIVE streams), and there are none left.
        for id in &ids {
            store.ack(*id).expect("ack");
        }
        assert_eq!(
            store.bookkeeping_len(),
            0,
            "ack reclaims in-flight AND the drained stream's cursor"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WP5 RAM gate (Linux-only via `/proc/self/statm`, skipped elsewhere): RSS must stay flat across a full
    /// send→recv→ack cycle whose total volume dwarfs the buffers — durability decoupled from RAM, measured.
    #[test]
    fn ram_flat_across_full_send_recv_ack_cycle() {
        const N: u64 = 40_000;
        let Some(rss0) = rss_kb() else {
            eprintln!("skip: /proc not available (non-Linux)");
            return;
        };
        let dir = temp_bucket();
        let mut store = ObjectStoreSubstrate::open(&dir).expect("open");
        let mut peak = rss0;
        for seq in 0..N {
            store.send(&testsupport::cofre_seq(seq)).expect("PUT");
            if let Some(c) = store.recv().expect("recv") {
                store.ack(c.etiqueta.cofre_id).expect("ack");
            }
            if seq % 8_000 == 0 {
                if let Some(r) = rss_kb() {
                    peak = peak.max(r);
                }
            }
        }
        let after = rss_kb().unwrap_or(rss0);
        eprintln!("full-cycle {N} cofres; RSS {rss0}→{after} KB (peak {peak})");
        assert!(
            after < rss0 + 32 * 1024 && peak < rss0 + 32 * 1024,
            "RSS must stay flat across the full cycle (after {after}, peak {peak}, baseline {rss0})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Resident set size of this process in KB (Linux `/proc/self/statm` resident pages × 4 KiB), or `None`
    /// off-Linux so the RAM gate self-skips.
    fn rss_kb() -> Option<u64> {
        let s = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = s.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4)
    }
}
