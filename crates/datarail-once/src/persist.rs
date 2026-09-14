//! `FileOnce` — a crash-safe **persistent** dedup index: the in-memory [`Once`] gate backed by an fsync'd,
//! append-only log that is replayed on open. This closes audit D-3 for **non-transactional** sinks (Tier C in
//! `docs/design/EXACTLY-ONCE-DESIGN.md`): a destination restart no longer FORGETS the dedup state and re-admits
//! a flood of redeliveries — the watermark + above-watermark keys survive. (For a *transactional* sink the
//! stronger Tier-A `TxnSink` stores the watermark atomically in the sink itself; `FileOnce` is the durable dedup
//! for sinks that cannot.)
//!
//! Log format: append-only records `[tag][body][crc4]`, `crc4 = BLAKE3(tag‖body)[..4]`. Two record kinds:
//! - `D` delivered: `stream(16) ‖ seq(8 LE) ‖ key(32)` — replayed through [`Once::admit`].
//! - `W` checkpoint: `stream(16) ‖ watermark(8 LE)` — replayed through [`Once::restore_watermark`].
//!
//! Replay stops at the first short/CRC-mismatched record (a torn tail from a crash mid-append) — priors intact.
//! Compaction rewrites the log as one `W` per stream + the above-watermark `D`s, bounding its size; it is durable
//! (tmp + fsync + rename + dir-fsync, the `FileOffsets` pattern the audit confirmed safe).

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use datarail_core::Disposition;
use datarail_crypto::blake3_256;

use crate::Once;

const TAG_DELIVERED: u8 = b'D';
const TAG_CHECKPOINT: u8 = b'W';
const D_BODY: usize = 16 + 8 + 32; // stream + seq + key
const W_BODY: usize = 16 + 8; // stream + watermark
const CRC: usize = 4;
const LOG_NAME: &str = "once.log";
const TMP_NAME: &str = "once.log.tmp";
/// Compact once the live log holds this many more records than the reconstructed state would need.
const COMPACT_EVERY: u64 = 1 << 16;

/// A persistent, crash-safe effectively-once gate (the durable counterpart of [`Once`]).
#[derive(Debug)]
pub struct FileOnce {
    once: Once,
    log: File,
    dir: PathBuf,
    appended: u64,
}

/// 4-byte BLAKE3 checksum over a record's `tag‖body`.
fn crc4(bytes: &[u8]) -> [u8; 4] {
    let h = blake3_256(bytes);
    [h[0], h[1], h[2], h[3]]
}

/// fsync a directory so a create/rename within it is durable across power loss (D-6 lesson).
fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn encode(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(1 + body.len() + CRC);
    rec.push(tag);
    rec.extend_from_slice(body);
    let crc = crc4(&rec);
    rec.extend_from_slice(&crc);
    rec
}

fn delivered_body(stream: &[u8; 16], seq: u64, key: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(D_BODY);
    b.extend_from_slice(stream);
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(key);
    b
}

fn checkpoint_body(stream: &[u8; 16], watermark: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(W_BODY);
    b.extend_from_slice(stream);
    b.extend_from_slice(&watermark.to_le_bytes());
    b
}

impl FileOnce {
    /// Open (creating if absent) a persistent dedup gate in `dir`, signing watermarks under `seed`, replaying the
    /// durable log to reconstruct the [`Once`] state.
    ///
    /// # Errors
    /// The directory/log cannot be created or read.
    pub fn open(dir: impl AsRef<Path>, seed: [u8; 32]) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let _ = std::fs::remove_file(dir.join(TMP_NAME)); // a leftover tmp = crash before a compaction rename
        let path = dir.join(LOG_NAME);

        let mut once = Once::new(seed);
        let appended = {
            let mut buf = Vec::new();
            OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open(&path)?
                .read_to_end(&mut buf)?;
            replay(&buf, &mut once)
        };
        let log = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        fsync_dir(&dir)?;
        Ok(Self {
            once,
            log,
            dir,
            appended,
        })
    }

    /// Admit a record durably: decide via the in-memory gate, and on `Delivered` append a fsync'd `D` record so a
    /// restart will not re-admit a redelivery. Compacts the log periodically to bound its size.
    ///
    /// # Errors
    /// An I/O error appending or compacting the log.
    pub fn admit(&mut self, stream: [u8; 16], seq: u64, key: [u8; 32]) -> io::Result<Disposition> {
        let disposition = self.once.admit(stream, seq, key);
        if disposition == Disposition::Delivered {
            let rec = encode(TAG_DELIVERED, &delivered_body(&stream, seq, &key));
            self.log.write_all(&rec)?;
            self.log.sync_all()?; // durable BEFORE the caller acts on Delivered (no "decided but forgotten")
            self.appended += 1;
            if self.appended >= COMPACT_EVERY {
                self.compact()?;
            }
        }
        Ok(disposition)
    }

    /// The contiguous low-watermark for `stream` (delegates to the in-memory gate).
    #[must_use]
    pub fn low_watermark(&self, stream: [u8; 16]) -> u64 {
        self.once.low_watermark(stream)
    }

    /// Rewrite the log as a minimal snapshot (one `W` checkpoint + the above-watermark `D`s per stream), durably
    /// (tmp + fsync + rename + dir-fsync), then reopen the live handle.
    fn compact(&mut self) -> io::Result<()> {
        let tmp_path = self.dir.join(TMP_NAME);
        let live_path = self.dir.join(LOG_NAME);
        let mut written = 0u64;
        {
            let mut tmp = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            let mut snapshot = Vec::new();
            for (stream, watermark, entries) in self.once.checkpoints() {
                snapshot.extend_from_slice(&encode(
                    TAG_CHECKPOINT,
                    &checkpoint_body(&stream, watermark),
                ));
                written += 1;
                for (seq, key) in entries {
                    snapshot.extend_from_slice(&encode(
                        TAG_DELIVERED,
                        &delivered_body(&stream, seq, &key),
                    ));
                    written += 1;
                }
            }
            tmp.write_all(&snapshot)?;
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, &live_path)?;
        self.log = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&live_path)?;
        fsync_dir(&self.dir)?;
        self.appended = written;
        Ok(())
    }
}

/// Replay a log buffer into `once`, returning the number of intact records applied. Stops at the first short or
/// CRC-mismatched record (a torn tail) — defensive, never panics on arbitrary bytes.
fn replay(buf: &[u8], once: &mut Once) -> u64 {
    let mut pos = 0usize;
    let mut applied = 0u64;
    while let Some(&tag) = buf.get(pos) {
        let body_len = match tag {
            TAG_DELIVERED => D_BODY,
            TAG_CHECKPOINT => W_BODY,
            _ => break, // unknown tag = corruption; stop
        };
        let Some(crc_start) = pos.checked_add(1).and_then(|p| p.checked_add(body_len)) else {
            break;
        };
        let Some(rec_end) = crc_start.checked_add(CRC) else {
            break;
        };
        if rec_end > buf.len() {
            break; // torn tail
        }
        let Some(framed) = buf.get(pos..crc_start) else {
            break;
        };
        let Some(stored) = buf.get(crc_start..rec_end) else {
            break;
        };
        if stored != crc4(framed) {
            break; // corrupt / torn record
        }
        let Some(body) = buf.get(pos + 1..crc_start) else {
            break;
        };
        let Some(stream) = body.get(0..16).and_then(|b| <[u8; 16]>::try_from(b).ok()) else {
            break;
        };
        match tag {
            TAG_DELIVERED => {
                let seq = body
                    .get(16..24)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map(u64::from_le_bytes);
                let key = body.get(24..56).and_then(|b| <[u8; 32]>::try_from(b).ok());
                let (Some(seq), Some(key)) = (seq, key) else {
                    break;
                };
                let _ = once.admit(stream, seq, key);
            }
            TAG_CHECKPOINT => {
                let Some(wm) = body
                    .get(16..24)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map(u64::from_le_bytes)
                else {
                    break;
                };
                once.restore_watermark(stream, wm);
            }
            _ => break,
        }
        applied += 1;
        pos = rec_end;
    }
    applied
}

#[cfg(test)]
mod tests {
    use super::FileOnce;
    use datarail_core::Disposition;

    const SEED: [u8; 32] = [9u8; 32];
    const S: [u8; 16] = [1u8; 16];

    fn key(n: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&n.to_le_bytes());
        k
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("datarail-fileonce-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn dedup_survives_a_restart() {
        let dir = tmp("restart");
        {
            let mut o = FileOnce::open(&dir, SEED).expect("open");
            for n in 0..5u64 {
                assert_eq!(
                    o.admit(S, n, key(n)).expect("admit"),
                    Disposition::Delivered
                );
            }
        }
        // "Crash" + restart: a fresh FileOnce over the same dir must REMEMBER the dedup state (no flood).
        let mut o = FileOnce::open(&dir, SEED).expect("reopen");
        assert_eq!(
            o.low_watermark(S),
            5,
            "watermark recovered from the durable log"
        );
        for n in 0..5u64 {
            assert_eq!(
                o.admit(S, n, key(n)).expect("replay"),
                Disposition::Duplicate,
                "redelivery dropped"
            );
        }
        assert_eq!(
            o.admit(S, 5, key(5)).expect("new"),
            Disposition::Delivered,
            "genuinely new still delivered"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn above_watermark_keys_survive_a_restart() {
        let dir = tmp("gap");
        {
            let mut o = FileOnce::open(&dir, SEED).expect("open");
            // Gap at 0: deliver 5 (parked above the watermark).
            assert_eq!(
                o.admit(S, 5, key(5)).expect("admit"),
                Disposition::Delivered
            );
            assert_eq!(o.low_watermark(S), 0);
        }
        let mut o = FileOnce::open(&dir, SEED).expect("reopen");
        // The parked, above-watermark seq 5 must still be deduped after the restart.
        assert_eq!(
            o.admit(S, 5, key(5)).expect("replay"),
            Disposition::Duplicate
        );
        assert_eq!(
            o.admit(S, 5, key(999)).expect("replay-diff-key"),
            Disposition::Duplicate
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_torn_tail_is_truncated_not_fatal() {
        let dir = tmp("torn");
        {
            let mut o = FileOnce::open(&dir, SEED).expect("open");
            for n in 0..3u64 {
                let _ = o.admit(S, n, key(n)).expect("admit");
            }
        }
        // Corrupt the tail (simulate a crash mid-append): append garbage bytes.
        let path = dir.join("once.log");
        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend_from_slice(&[0xFFu8; 7]); // a short/garbage trailing record
        std::fs::write(&path, &bytes).expect("write");
        // Reopen must recover the 3 intact records and ignore the torn tail (no panic).
        let mut o = FileOnce::open(&dir, SEED).expect("reopen torn");
        assert_eq!(
            o.low_watermark(S),
            3,
            "intact prefix recovered, torn tail dropped"
        );
        assert_eq!(o.admit(S, 0, key(0)).expect("dup"), Disposition::Duplicate);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
