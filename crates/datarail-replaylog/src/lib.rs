//! `datarail-replaylog` — a segmented, **retained**, durable append-only log that serves **replay from an
//! arbitrary offset at flat RAM**.
//!
//! **The point (ledger #2).** Kafka's killer feature is the durable, re-readable log: many consumers replay
//! history from any offset. Kafka pays for it by holding the hot set in the OS **page cache**, so its RAM bill
//! grows with retention + throughput. This log does the opposite: history lives on disk (cheap, abundant) and a
//! reader streams it through a **fixed, bounded buffer**, so **RAM stays flat no matter how much history is
//! retained**. Unlike `datarail-substrate-wal` (drain + GC-on-ack — history is *gone* once acked), this log
//! **retains** segments, so `replay_from(offset)` is repeatable and seekable — the actual Kafka-replay semantics.
//!
//! **Honest scope.** Single-node, on-disk tiered storage with a streaming reader. The cold tier here is the local
//! filesystem; pointing the segment reads at S3/object-store (so "disk" becomes "cheap object storage") is the
//! same code with the GET verb swapped, and is future. Multi-consumer offset *coordination* (consumer groups) is
//! also future — this proves the storage + replay + flat-RAM property, not a full broker.
//!
//! Memory profile: a reader holds `O(read_buffer + one record)`; the writer holds `O(1)`. The only structure that
//! scales with volume is the per-replay sorted list of segment start-offsets — `O(total / segment_bytes)`, i.e.
//! a handful of `u64`s per (default 8 MiB) segment, negligible vs the retained bytes. Stated plainly, not hidden.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Default segment size: rotate to a new file once the active one reaches this many bytes.
pub const DEFAULT_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;
/// Reader refill chunk — the reader pulls at most this much from a segment at a time (the flat-RAM bound, plus
/// at most one record that straddles a chunk boundary).
const REFILL_CHUNK: usize = 64 * 1024;

/// IEEE CRC-32 (table-free) over a record's `len ‖ bytes`, detecting torn writes.
fn crc32(parts: &[&[u8]]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for part in parts {
        for &b in *part {
            crc ^= u32::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }
    !crc
}

/// What can go wrong.
#[derive(Debug)]
pub enum ReplayError {
    /// Underlying filesystem error.
    Io(std::io::Error),
    /// `replay_from` was given an offset past the end of the log, or not at a record boundary.
    BadOffset(u64),
    /// A record exceeded the configured maximum.
    TooLarge(usize),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "replaylog io: {e}"),
            Self::BadOffset(o) => write!(f, "replaylog offset {o} is past the end or mis-aligned"),
            Self::TooLarge(n) => write!(f, "replaylog record {n} bytes exceeds the maximum"),
        }
    }
}

impl std::error::Error for ReplayError {}

impl From<std::io::Error> for ReplayError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Largest single record (frame body) the log accepts — a parse-safety bound for recovery/replay.
pub const MAX_RECORD: usize = 64 * 1024 * 1024;
const FRAME_OVERHEAD: u64 = 8; // [u32 len] + [u32 crc]

/// A segmented, retained, durable append-only log.
pub struct ReplayLog {
    dir: PathBuf,
    segment_bytes: u64,
    /// Logical byte offset where the active segment begins.
    active_start: u64,
    /// The next logical offset to write (= end of the log).
    write_offset: u64,
    active: File,
}

fn seg_name(start: u64) -> String {
    format!("{start:020}.seg")
}

fn seg_start(path: &Path) -> Option<u64> {
    path.file_name()?
        .to_str()?
        .strip_suffix(".seg")?
        .parse()
        .ok()
}

/// fsync the directory itself so a newly-created entry (a segment file) survives a power loss — an fsync of
/// the file persists its *bytes*, not its *directory entry* (same technique as `datarail-offsets::fsync_dir`).
/// Without this, a record acked right after a rotation could vanish with its whole segment on power loss.
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// All segment start-offsets in `dir`, sorted ascending.
fn segment_starts(dir: &Path) -> Result<Vec<u64>, ReplayError> {
    let mut starts = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if let Some(s) = seg_start(&path) {
            starts.push(s);
        }
    }
    starts.sort_unstable();
    Ok(starts)
}

impl ReplayLog {
    /// Open (or create) a log in `dir` with the given segment size. Recovers `write_offset` by scanning valid
    /// frames in the last segment and truncating any torn tail.
    ///
    /// # Errors
    /// [`ReplayError::Io`] on a filesystem error.
    pub fn open(dir: impl AsRef<Path>, segment_bytes: u64) -> Result<Self, ReplayError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let starts = segment_starts(&dir)?;
        let active_start = starts.last().copied().unwrap_or(0);
        let path = dir.join(seg_name(active_start));
        // Recover the valid length of the active segment (scan frames; stop at a torn/short tail).
        let valid_len = scan_valid_len(&path)?;
        let active = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        active.set_len(valid_len)?; // drop any torn tail
                                    // Persist the directory entries we may have just created (the log dir + the first segment): without a
                                    // dir fsync, a power loss could erase the dentries of a log whose records were already acked durable.
        fsync_dir(&dir)?;
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            fsync_dir(parent)?;
        }
        let mut active = active;
        active.seek(SeekFrom::Start(valid_len))?;
        Ok(Self {
            dir,
            segment_bytes: segment_bytes.max(1024),
            active_start,
            write_offset: active_start + valid_len,
            active,
        })
    }

    /// The current end of the log (the offset the next append will return).
    #[must_use]
    pub fn end_offset(&self) -> u64 {
        self.write_offset
    }

    /// The directory path where segment files are stored.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Append one record, returning its logical offset (a valid `replay_from` seek point). Rotates to a new
    /// segment first if the active one is full. The record is **retained** — never deleted by reads.
    ///
    /// # Errors
    /// [`ReplayError::TooLarge`] if the record exceeds [`MAX_RECORD`]; [`ReplayError::Io`] on a write error.
    pub fn append(&mut self, record: &[u8]) -> Result<u64, ReplayError> {
        if record.len() > MAX_RECORD {
            return Err(ReplayError::TooLarge(record.len()));
        }
        if self.write_offset - self.active_start >= self.segment_bytes {
            self.rotate()?;
        }
        let offset = self.write_offset;
        let len = u32::try_from(record.len()).map_err(|_| ReplayError::TooLarge(record.len()))?;
        let len_bytes = len.to_le_bytes();
        let crc = crc32(&[&len_bytes, record]).to_le_bytes();
        self.active.write_all(&len_bytes)?;
        self.active.write_all(record)?;
        self.active.write_all(&crc)?;
        self.write_offset += FRAME_OVERHEAD + u64::from(len);
        Ok(offset)
    }

    /// Flush + fsync the active segment so appended records survive a power loss.
    ///
    /// # Errors
    /// [`ReplayError::Io`] on a flush/fsync error.
    pub fn sync(&mut self) -> Result<(), ReplayError> {
        self.active.flush()?;
        self.active.sync_all()?;
        // Persist the directory entry so new file handles see the latest data.
        fsync_dir(&self.dir)?;
        Ok(())
    }

    /// Truncate the retained log to a previously returned record boundary.
    ///
    /// Removes every later segment, truncates the target segment when needed, and reopens the active handle at the
    /// new end. Intended for transaction recovery before the broker accepts connections; callers must exclude readers.
    ///
    /// # Errors
    /// [`ReplayError::BadOffset`] if `end_offset` is past the current end or not a valid frame boundary; filesystem
    /// failures are returned as [`ReplayError::Io`].
    pub fn truncate_to(&mut self, end_offset: u64) -> Result<(), ReplayError> {
        if end_offset > self.write_offset {
            return Err(ReplayError::BadOffset(end_offset));
        }
        if end_offset == self.write_offset {
            return Ok(());
        }

        let starts = segment_starts(&self.dir)?;
        let target_index = starts
            .partition_point(|&start| start <= end_offset)
            .saturating_sub(1);
        let target_start = starts.get(target_index).copied().unwrap_or(0);
        let target_path = self.dir.join(seg_name(target_start));
        let relative = end_offset.saturating_sub(target_start);
        if !is_frame_boundary(&target_path, relative)? {
            return Err(ReplayError::BadOffset(end_offset));
        }

        self.active.flush()?;
        self.active.sync_all()?;
        let active = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&target_path)?;
        drop(std::mem::replace(&mut self.active, active));

        for &start in starts.iter().skip(target_index + 1) {
            std::fs::remove_file(self.dir.join(seg_name(start)))?;
        }
        self.active.set_len(relative)?;
        self.active.seek(SeekFrom::Start(relative))?;
        self.active_start = target_start;
        self.write_offset = end_offset;
        fsync_dir(&self.dir)?;
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), ReplayError> {
        self.active.flush()?;
        self.active.sync_all()?;
        self.active_start = self.write_offset;
        self.active = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(self.dir.join(seg_name(self.active_start)))?;
        // Persist the new segment's directory entry NOW, before any record lands in it: the caller's
        // fsync-before-ack (`sync`) only covers the file's bytes — without this dir fsync, a power loss after
        // an ack could erase the freshly-rotated segment together with every record acked into it.
        fsync_dir(&self.dir)?;
        Ok(())
    }

    /// Start replaying from `start_offset`. The returned [`Replay`] streams records through a bounded buffer —
    /// RAM stays flat regardless of how much history is retained.
    ///
    /// **Precondition (WP8 audit honesty):** `start_offset` MUST be a record boundary — a value returned by
    /// [`append`](Self::append), or `0`, or [`end_offset`](Self::end_offset). Only `> end` is *validated*
    /// (→ `BadOffset`); a mis-aligned in-range offset is a caller error that yields an empty/garbage replay, not
    /// an error. **Corruption resync:** a bad `len` or CRC failure in a *non-final* segment (disk rot mid-history)
    /// no longer ends the replay — the reader SKIPS to the start of the next segment and continues, so later
    /// intact segments stay reachable (records never straddle segments, so every segment boundary is a frame
    /// boundary; at most the corrupt segment's remaining records are lost, never later ones). Corruption is still
    /// detected — wrong bytes are never returned. Only a torn tail in the *final* segment stops the replay (clean
    /// truncation), exactly as before.
    ///
    /// # Errors
    /// [`ReplayError::BadOffset`] if `start_offset` is past the end; [`ReplayError::Io`] on a filesystem error.
    pub fn replay_from(&self, start_offset: u64) -> Result<Replay, ReplayError> {
        if start_offset > self.write_offset {
            return Err(ReplayError::BadOffset(start_offset));
        }
        let starts = segment_starts(&self.dir)?;
        let seg_idx = starts
            .partition_point(|&s| s <= start_offset)
            .saturating_sub(1);
        Replay::open(
            self.dir.clone(),
            starts,
            seg_idx,
            start_offset,
            self.write_offset,
        )
    }
}

/// Read every valid frame in a segment file; return the byte length up to (but excluding) the first torn/short
/// frame — the recoverable length.
fn scan_valid_len(path: &Path) -> Result<u64, ReplayError> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut pos = 0usize;
    loop {
        if pos + 4 > bytes.len() {
            break;
        }
        let len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        if len > MAX_RECORD {
            break;
        }
        let end = pos + 4 + len + 4;
        if end > bytes.len() {
            break;
        }
        let stored = u32::from_le_bytes([
            bytes[end - 4],
            bytes[end - 3],
            bytes[end - 2],
            bytes[end - 1],
        ]);
        if stored != crc32(&[&bytes[pos..pos + 4], &bytes[pos + 4..pos + 4 + len]]) {
            break;
        }
        pos = end;
    }
    Ok(pos as u64)
}

fn is_frame_boundary(path: &Path, target: u64) -> Result<bool, ReplayError> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let target = usize::try_from(target).map_err(|_| ReplayError::BadOffset(target))?;
    if target > bytes.len() {
        return Ok(false);
    }
    let mut pos = 0usize;
    while pos < target {
        let Some(len_bytes) = bytes.get(pos..pos + 4) else {
            return Ok(false);
        };
        let len = u32::from_le_bytes(
            len_bytes
                .try_into()
                .map_err(|_| ReplayError::BadOffset(target as u64))?,
        ) as usize;
        let Some(end) = pos.checked_add(4 + len + 4) else {
            return Ok(false);
        };
        if end > target || end > bytes.len() {
            return Ok(false);
        }
        let stored = u32::from_le_bytes(
            bytes[end - 4..end]
                .try_into()
                .map_err(|_| ReplayError::BadOffset(target as u64))?,
        );
        if stored != crc32(&[&bytes[pos..pos + 4], &bytes[pos + 4..pos + 4 + len]]) {
            return Ok(false);
        }
        pos = end;
    }
    Ok(pos == target)
}

/// A streaming, flat-RAM replay cursor over the retained log. Yields `(offset, record)` in order.
pub struct Replay {
    dir: PathBuf,
    starts: Vec<u64>,
    seg_idx: usize,
    file: Option<File>,
    /// Logical offset of `buf[0]`.
    buf_base: u64,
    buf: Vec<u8>,
    cursor: usize, // consumed bytes within buf
    end: u64,
}

impl Replay {
    fn open(
        dir: PathBuf,
        starts: Vec<u64>,
        seg_idx: usize,
        start_offset: u64,
        end: u64,
    ) -> Result<Self, ReplayError> {
        let mut r = Self {
            dir,
            starts,
            seg_idx,
            file: None,
            buf_base: start_offset,
            buf: Vec::new(),
            cursor: 0,
            end,
        };
        r.open_segment(start_offset)?;
        Ok(r)
    }

    fn open_segment(&mut self, at_offset: u64) -> Result<(), ReplayError> {
        let Some(&seg) = self.starts.get(self.seg_idx) else {
            self.file = None;
            return Ok(());
        };
        let mut f = File::open(self.dir.join(seg_name(seg)))?;
        let seek_pos = at_offset.saturating_sub(seg);
        f.seek(SeekFrom::Start(seek_pos))?;
        self.file = Some(f);
        self.buf.clear();
        self.cursor = 0;
        self.buf_base = at_offset;
        Ok(())
    }

    /// Bytes currently held in the read buffer — the flat-RAM witness. Bounded by `REFILL_CHUNK + one record`,
    /// **independent of total retained volume**. A gate asserts this never grows with the log size.
    #[must_use]
    pub fn bytes_buffered(&self) -> usize {
        self.buf.len() - self.cursor
    }

    /// Compact consumed bytes out of `buf`, then pull one `REFILL_CHUNK` from the current segment (advancing to
    /// the next segment at EOF). Returns false when no more bytes are available anywhere.
    fn refill(&mut self) -> Result<bool, ReplayError> {
        if self.cursor > 0 {
            self.buf.drain(..self.cursor);
            self.buf_base += self.cursor as u64;
            self.cursor = 0;
        }
        loop {
            // Take the file out so we can borrow `self.buf` to read into it (disjoint fields, no stack array).
            let Some(mut file) = self.file.take() else {
                return Ok(false);
            };
            let old = self.buf.len();
            self.buf.resize(old + REFILL_CHUNK, 0);
            let n = file.read(&mut self.buf[old..])?;
            self.buf.truncate(old + n);
            if n > 0 {
                self.file = Some(file);
                return Ok(true);
            }
            // Current segment exhausted (file dropped) → advance to the next one.
            self.seg_idx += 1;
            let Some(next) = self.starts.get(self.seg_idx).copied() else {
                return Ok(false);
            };
            self.open_segment_keep_buf(next)?;
        }
    }

    fn open_segment_keep_buf(&mut self, seg: u64) -> Result<(), ReplayError> {
        // Open the next segment at its start without clearing the partial-frame bytes still in `buf`.
        self.file = Some(File::open(self.dir.join(seg_name(seg)))?);
        Ok(())
    }

    /// A bad frame (oversize `len` or CRC mismatch) was found at logical offset `bad_off`. If a *later* segment
    /// exists, RESYNC: drop the corrupt segment and reopen the reader at the next segment's start (segment
    /// boundaries are frame boundaries, so this loses at most the corrupt segment's remaining records, never
    /// later ones). Returns `Ok(true)` if resynced (caller should keep reading), `Ok(false)` if `bad_off` is in
    /// the final segment (a torn tail — the caller stops with `Ok(None)`).
    fn resync_or_stop(&mut self, bad_off: u64) -> Result<bool, ReplayError> {
        // First segment-start strictly greater than `bad_off` = the start of the next intact segment.
        let next = self.starts.partition_point(|&s| s <= bad_off);
        let Some(&start) = self.starts.get(next) else {
            return Ok(false); // corruption is in the final segment → clean truncation
        };
        self.seg_idx = next;
        self.open_segment(start)?;
        Ok(true)
    }

    /// The next record, or `None` at the end of the retained log. (Not the `Iterator` trait: this is fallible,
    /// returning `Result<Option<…>>`.)
    ///
    /// # Errors
    /// [`ReplayError::Io`] on a read error; a torn/corrupt tail surfaces as the end of the readable log.
    pub fn read_next(&mut self) -> Result<Option<(u64, Vec<u8>)>, ReplayError> {
        loop {
            let avail = self.buf.len() - self.cursor;
            if avail < 4 {
                if self.buf_base + self.cursor as u64 >= self.end || !self.refill()? {
                    return Ok(None);
                }
                continue;
            }
            let p = self.cursor;
            let len = u32::from_le_bytes([
                self.buf[p],
                self.buf[p + 1],
                self.buf[p + 2],
                self.buf[p + 3],
            ]) as usize;
            if len > MAX_RECORD {
                // Corruption: resync to the next segment if one exists, else (final segment) stop — a torn tail.
                if self.resync_or_stop(self.buf_base + self.cursor as u64)? {
                    continue;
                }
                return Ok(None);
            }
            let frame = 4 + len + 4;
            if self.buf.len() - self.cursor < frame {
                if !self.refill()? {
                    return Ok(None);
                }
                continue;
            }
            let offset = self.buf_base + self.cursor as u64;
            // WP8 audit [LOW] fix: never emit a record at/after the snapshot end (a concurrent committed append to
            // the active segment must not leak into a reader created before it).
            if offset >= self.end {
                return Ok(None);
            }
            let body = &self.buf[p + 4..p + 4 + len];
            let stored = u32::from_le_bytes([
                self.buf[p + 4 + len],
                self.buf[p + 4 + len + 1],
                self.buf[p + 4 + len + 2],
                self.buf[p + 4 + len + 3],
            ]);
            if stored != crc32(&[&self.buf[p..p + 4], body]) {
                // Corruption: resync to the next segment if one exists, else (final segment) stop — a torn tail.
                if self.resync_or_stop(offset)? {
                    continue;
                }
                return Ok(None);
            }
            let record = body.to_vec();
            self.cursor += frame;
            return Ok(Some((offset, record)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplayError, ReplayLog, MAX_RECORD, REFILL_CHUNK};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("datarail-replaylog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn drain(log: &ReplayLog, from: u64) -> Vec<(u64, Vec<u8>)> {
        let mut r = log.replay_from(from).expect("replay_from");
        let mut out = Vec::new();
        while let Some(rec) = r.read_next().expect("read_next") {
            out.push(rec);
        }
        out
    }

    #[test]
    fn append_then_replay_from_zero_returns_everything_in_order() {
        let dir = tmpdir("roundtrip");
        let mut log = ReplayLog::open(&dir, 4096).expect("open"); // small segments → many of them
        let mut offsets = Vec::new();
        for i in 0u32..1000 {
            let rec = format!("record-{i}").into_bytes();
            offsets.push((log.append(&rec).expect("append"), rec));
        }
        log.sync().expect("sync");
        let got = drain(&log, 0);
        assert_eq!(got.len(), 1000);
        for (i, (off, rec)) in got.iter().enumerate() {
            assert_eq!(*off, offsets[i].0, "offset mismatch at {i}");
            assert_eq!(*rec, offsets[i].1, "record mismatch at {i}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_from_an_arbitrary_offset_starts_exactly_there() {
        let dir = tmpdir("seek");
        let mut log = ReplayLog::open(&dir, 4096).expect("open");
        let mut offsets = Vec::new();
        for i in 0u32..500 {
            let rec = format!("r{i}").into_bytes();
            offsets.push(log.append(&rec).expect("append"));
        }
        log.sync().expect("sync");
        // Seek to the 321st record's offset → replay must start exactly there.
        let mid = offsets[321];
        let got = drain(&log, mid);
        assert_eq!(got.len(), 500 - 321);
        assert_eq!(got[0].0, mid);
        assert_eq!(got[0].1, b"r321");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_is_repeatable_history_is_retained_not_consumed() {
        let dir = tmpdir("retain");
        let mut log = ReplayLog::open(&dir, 4096).expect("open");
        for i in 0u32..300 {
            log.append(format!("x{i}").as_bytes()).expect("append");
        }
        log.sync().expect("sync");
        let first = drain(&log, 0);
        let second = drain(&log, 0); // read AGAIN — Kafka-style; unlike the WAL, nothing was consumed/GC'd
        assert_eq!(
            first, second,
            "replay was not repeatable — history was not retained"
        );
        assert_eq!(first.len(), 300);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopen_recovers_end_offset_and_full_replay() {
        let dir = tmpdir("recover");
        let mut tail = Vec::new();
        {
            let mut log = ReplayLog::open(&dir, 4096).expect("open");
            for i in 0u32..400 {
                let rec = format!("rec{i}").into_bytes();
                log.append(&rec).expect("append");
                tail.push(rec);
            }
            log.sync().expect("sync");
        }
        // Reopen a fresh handle → must recover the end and replay all retained history.
        let log = ReplayLog::open(&dir, 4096).expect("reopen");
        let got = drain(&log, 0);
        assert_eq!(got.len(), 400, "reopen lost history");
        assert_eq!(got.last().unwrap().1, *tail.last().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_to_boundary_removes_later_segments_and_survives_reopen() {
        let dir = tmpdir("truncate");
        let mut log = ReplayLog::open(&dir, 1024).expect("open");
        let mut offsets = Vec::new();
        for i in 0u32..100 {
            offsets.push(
                log.append(format!("record-{i}").as_bytes())
                    .expect("append"),
            );
        }
        log.sync().expect("sync");

        let keep_before = offsets[37];
        assert!(matches!(
            log.truncate_to(keep_before + 1),
            Err(ReplayError::BadOffset(_))
        ));
        log.truncate_to(keep_before)
            .expect("truncate at record boundary");
        assert_eq!(drain(&log, 0).len(), 37);
        log.append(b"replacement").expect("append after truncate");
        log.sync().expect("sync replacement");

        let reopened = ReplayLog::open(&dir, 1024).expect("reopen");
        let got = drain(&reopened, 0);
        assert_eq!(got.len(), 38);
        assert_eq!(got[36].1, b"record-36");
        assert_eq!(got[37].1, b"replacement");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ledger #2 gate: replay a retained volume MANY times the read buffer, and prove the in-RAM read buffer
    /// stays bounded by `REFILL_CHUNK + one record` the whole way — RAM flat, independent of total volume.
    #[test]
    fn ram_flat_replaying_a_volume_far_larger_than_the_buffer() {
        let dir = tmpdir("flatram");
        let mut log = ReplayLog::open(&dir, 1 << 20).expect("open"); // 1 MiB segments
        let rec = vec![0xABu8; 1024]; // 1 KiB records
                                      // ~40 MiB of retained history — ~640× the 64 KiB read buffer.
        let target = 40 * 1024 * 1024u64;
        while log.end_offset() < target {
            log.append(&rec).expect("append");
        }
        log.sync().expect("sync");
        let total = log.end_offset();

        let mut r = log.replay_from(0).expect("replay");
        let bound = REFILL_CHUNK + 1024 + 64; // chunk + one record + framing slack
        let mut count = 0u64;
        let mut peak = 0usize;
        while let Some((_off, _rec)) = r.read_next().expect("read_next") {
            peak = peak.max(r.bytes_buffered());
            count += 1;
            assert!(
                r.bytes_buffered() <= bound,
                "read buffer grew with volume: {} > {bound}",
                r.bytes_buffered()
            );
        }
        assert!(
            count >= 30_000,
            "did not replay the full volume ({count} records)"
        );
        // The witness: peak buffered RAM is O(read buffer), NOT O(total retained volume).
        assert!(
            peak <= bound,
            "peak {peak} exceeded the flat-RAM bound {bound}"
        );
        assert!(
            total >= 40 * 1024 * 1024,
            "sanity: retained volume was large ({total} bytes)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WP4 gate: corruption in the MIDDLE of a non-final segment must RESYNC — the replay skips the corrupt
    /// segment's remaining records but still reaches and yields the records in the later intact segments.
    #[test]
    fn corruption_in_a_non_final_segment_resyncs_to_later_segments() {
        let dir = tmpdir("resync");
        let n = 2000u32;
        let mut log = ReplayLog::open(&dir, 4096).expect("open"); // small segments → many of them
        for i in 0..n {
            log.append(format!("resync-record-{i:05}").as_bytes())
                .expect("append");
        }
        log.sync().expect("sync");

        // Collect the segment files, sorted by start offset.
        let mut segs: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("seg"))
            .collect();
        segs.sort();
        assert!(
            segs.len() >= 3,
            "test needs >=3 segments, got {}",
            segs.len()
        );

        // Corrupt a body byte in the MIDDLE of a non-final segment so its CRC fails.
        let victim = &segs[segs.len() / 2];
        let mut bytes = std::fs::read(victim).expect("read seg");
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(victim, &bytes).expect("write seg");

        // Replay from 0 must resync past the corrupt segment and still deliver the later intact segments.
        let got = drain(&log, 0);
        let expected_last = format!("resync-record-{:05}", n - 1).into_bytes();
        assert_eq!(
            got.last().expect("replay yielded nothing").1,
            expected_last,
            "later intact segments were unreachable — resync did not happen"
        );
        // The corrupt segment's tail is dropped, so we never deliver all n records, but we DO reach the end.
        assert!(
            got.len() < n as usize,
            "expected to lose the corrupt segment's tail"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A torn tail in the FINAL segment still truncates cleanly (no resync target → stop), unchanged behavior.
    #[test]
    fn corruption_in_the_final_segment_truncates_cleanly() {
        let dir = tmpdir("torntail");
        let n = 2000u32;
        let mut log = ReplayLog::open(&dir, 4096).expect("open");
        for i in 0..n {
            log.append(format!("tail-record-{i:05}").as_bytes())
                .expect("append");
        }
        log.sync().expect("sync");

        let mut segs: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("seg"))
            .collect();
        segs.sort();
        assert!(
            segs.len() >= 3,
            "test needs >=3 segments, got {}",
            segs.len()
        );

        // Corrupt a body byte in the MIDDLE of the FINAL segment → no later segment → clean truncation.
        let victim = segs.last().expect("final segment");
        let mut bytes = std::fs::read(victim).expect("read seg");
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(victim, &bytes).expect("write seg");

        let got = drain(&log, 0);
        // Some records survive (everything before the torn tail), but not all — and no error/panic.
        assert!(
            !got.is_empty(),
            "clean records before the tear should still replay"
        );
        assert!(
            got.len() < n as usize,
            "the torn tail should have been truncated"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversize_record_is_rejected() {
        let dir = tmpdir("toobig");
        let mut log = ReplayLog::open(&dir, 4096).expect("open");
        let huge = vec![0u8; MAX_RECORD + 1];
        assert!(log.append(&huge).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
