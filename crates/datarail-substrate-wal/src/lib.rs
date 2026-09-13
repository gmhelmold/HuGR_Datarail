//! `datarail-substrate-wal` — a **fsync-durable, O(1)-RAM** write-ahead-log [`Substrate`].
//!
//! Durability without the RAM tax. Kafka couples durability to memory (it keeps its hot log working set in the
//! OS page cache + a multi-GB JVM heap, so RSS grows with retention/throughput). A write-ahead log does not:
//! durability is **sequential append + fsync**, whose process-RAM cost is a single fixed write buffer; reading
//! back is a sequential scan with a single fixed read buffer. The OS page cache that holds recent pages is
//! *reclaimable kernel memory, not our RSS*. So this substrate gives **power-loss durability (Kafka `acks=all`
//! equivalent) at a flat ~couple-MiB RSS, independent of stored volume** (store 1 TB across 10^9 cofres in the
//! same RAM as 1 MB). Full design: `docs/design/DURABLE-LOG.md`.
//!
//! - **Group-commit fsync** (the warp-speed lever): `send` appends framed cofres into a fixed buffer; one
//!   `sync_data()` durably commits a whole batch (flush on `flush_bytes` OR `flush_micros`). The durability
//!   point is the fsync, so the producer's ack means *on stable storage*, not *enqueued*.
//! - **O(1) read cursor**: a record is deliverable iff its offset ≥ the committed read cursor; the cursor is the
//!   dedup state — **no in-RAM id-set** (the demo object-store's unbounded `HashSet` was the audit's flaw).
//! - **Crash recovery**: each frame is CRC-guarded; on open, a torn tail (power-loss mid-append) is truncated to
//!   the last intact frame. Every fsync'd cofre survives; a half-written one (never acked) is dropped.
//! - **GC**: a fully-read, fully-acked segment file is deleted; disk is bounded by the un-acked window, RAM is
//!   not affected.
//!
//! Zero external dependencies (Charter *leveza*); `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

#[cfg(test)]
use std::cell::Cell;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use datarail_core::{Cofre, Substrate, MAX_COFRE_WIRE_LEN};

/// Frame overhead on disk: a 4-byte big-endian length prefix + a 4-byte big-endian CRC-32 suffix.
const FRAME_OVERHEAD: usize = 8;

#[cfg(test)]
thread_local! {
    static FAIL_DIR_FSYNC: Cell<bool> = const { Cell::new(false) };
    static FAIL_SEGMENT_SYNC: Cell<bool> = const { Cell::new(false) };
}

/// Tunables for the log (all have warp-but-safe defaults).
#[derive(Debug, Clone, Copy)]
pub struct WalConfig {
    /// Flush+fsync once the write buffer reaches this many bytes. Default 1 MiB (group commit).
    pub flush_bytes: usize,
    /// Flush+fsync at least this often even if the buffer is not full. Default 1000 µs.
    pub flush_micros: u64,
    /// Roll to a new segment file once the active one exceeds this. Default 256 MiB.
    pub segment_bytes: u64,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            flush_bytes: 1 << 20,
            flush_micros: 1000,
            segment_bytes: 256 << 20,
        }
    }
}

/// Errors from the durable log.
#[derive(Debug)]
pub enum WalError {
    /// Underlying filesystem I/O failure.
    Io(std::io::Error),
    /// A framed record on disk is corrupt (bad length or CRC) past the recoverable tail.
    Corrupt(String),
    /// A cofre failed to encode/decode at the wire boundary.
    Codec(String),
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "wal io: {e}"),
            Self::Corrupt(m) => write!(f, "wal corrupt: {m}"),
            Self::Codec(m) => write!(f, "wal codec: {m}"),
        }
    }
}

impl std::error::Error for WalError {}

impl From<std::io::Error> for WalError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// IEEE CRC-32 (reflected), table generated at compile time — torn-write detection on recovery. Zero deps.
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
};

/// CRC-32 over two concatenated slices (the frame's length prefix and its body), one pass.
fn crc32_2(a: &[u8], b: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &x in a.iter().chain(b) {
        c = CRC32_TABLE[((c ^ u32::from(x)) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// A durably-stored, O(1)-RAM write-ahead-log substrate (see crate docs + `DURABLE-LOG.md`).
pub struct DurableLog {
    dir: PathBuf,
    cfg: WalConfig,
    // ---- write side (RAM: one fixed buffer) ----
    active: File,
    active_id: u64,
    write_off: u64,
    buf: Vec<u8>,
    last_flush: Instant,
    // ---- read side (RAM: one fixed cursor + a reused scratch buffer) ----
    read_id: u64,
    read_off: u64,
    read_file: Option<File>,
    // ---- ack / GC (RAM: bounded by the in-flight, delivered-but-un-acked window — NOT total volume) ----
    inflight: HashMap<[u8; 32], u64>, // cofre_id → segment id it was delivered from
    seg_inflight: HashMap<u64, u64>,  // segment id → count of delivered-un-acked cofres in it
    poisoned: bool,
}

impl DurableLog {
    /// Open (or create) a durable log at `dir` with the default config.
    ///
    /// # Errors
    /// [`WalError::Io`] on filesystem failure; [`WalError::Corrupt`] if a segment is damaged beyond the
    /// recoverable (torn-tail) case.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, WalError> {
        Self::open_with(dir, WalConfig::default())
    }

    /// Open with an explicit [`WalConfig`].
    ///
    /// # Errors
    /// As [`DurableLog::open`].
    pub fn open_with(dir: impl AsRef<Path>, cfg: WalConfig) -> Result<Self, WalError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        // Resume reads from the persisted ACK FLOOR — the (segment, offset) below which everything is delivered
        // AND acked — NOT the advanced read cursor. The read cursor moves on DELIVERY (`recv`), so a crash after
        // delivering-but-not-acking a cofre, then acking/checkpointing a LATER one, would leave the persisted read
        // cursor past records that were never acked → those would be skipped on restart and silently LOST,
        // breaking at-least-once (audit CRITICAL). The ack floor is never past an un-acked record, so resuming
        // there RE-DELIVERS every delivered-but-un-acked cofre; already-acked records re-read from the floor's
        // segment are harmless duplicates that downstream effectively-once dedup absorbs.
        let (_read_id, _read_off, ack_id, ack_off) = load_cursor(&dir);
        let active_id = highest_segment(&dir)?.unwrap_or(1);
        let path = seg_path(&dir, active_id);
        let mut active = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        fsync_dir(&dir)?; // the active segment's dir-entry must be durable
                          // Recovery: scan the active segment, truncate any torn tail to the last intact frame.
        let write_off = recover_segment_end(&mut active)?;
        active.set_len(write_off)?;
        active.seek(SeekFrom::Start(write_off))?;
        Ok(Self {
            dir,
            cfg,
            active,
            active_id,
            write_off,
            buf: Vec::with_capacity(cfg.flush_bytes + (MAX_COFRE_WIRE_LEN / 64).min(1 << 20)),
            last_flush: Instant::now(),
            read_id: ack_id.max(1),
            read_off: ack_off,
            read_file: None,
            inflight: HashMap::new(),
            seg_inflight: HashMap::new(),
            poisoned: false,
        })
    }

    /// Frame and buffer a cofre; flush+fsync if the byte or time threshold is hit. Buffer is reused (no growth).
    fn append(&mut self, cofre: &Cofre) -> Result<(), WalError> {
        let bytes = datarail_cofre::encode(cofre);
        if bytes.len() > MAX_COFRE_WIRE_LEN {
            return Err(WalError::Codec("cofre exceeds MAX_COFRE_WIRE_LEN".into()));
        }
        let len = u32::try_from(bytes.len()).map_err(|_| WalError::Codec("len overflow".into()))?;
        // CRC covers the length prefix AND the body (per DURABLE-LOG.md) — so a corrupted *length* is caught.
        let lenb = len.to_be_bytes();
        let crc = crc32_2(&lenb, &bytes);
        self.buf.extend_from_slice(&lenb);
        self.buf.extend_from_slice(&bytes);
        self.buf.extend_from_slice(&crc.to_be_bytes());
        if self.buf.len() >= self.cfg.flush_bytes
            || self.last_flush.elapsed() >= Duration::from_micros(self.cfg.flush_micros)
        {
            self.flush()?;
        }
        Ok(())
    }

    /// Group-commit: write the buffer to the active segment and **fsync** (the durability point), then clear the
    /// buffer (capacity retained) and rotate the segment if it has grown past `segment_bytes`.
    ///
    /// # Errors
    /// [`WalError::Io`] on write/fsync failure.
    pub fn flush(&mut self) -> Result<(), WalError> {
        if self.poisoned {
            return Err(
                std::io::Error::other("wal is poisoned after a prior write failure").into(),
            );
        }
        if !self.buf.is_empty() {
            if let Err(error) = self.active.write_all(&self.buf) {
                self.poisoned = true;
                self.buf.clear();
                return Err(error.into());
            }
            // sync_all (not sync_data) so the inode metadata is durable too. NOTE: std `fsync` flushes to the
            // device but does NOT issue a drive-cache barrier on macOS (needs F_FULLFSYNC, unavailable in safe
            // std) — true power-loss durability holds on Linux/ext4/xfs with write barriers, not on the macOS
            // dev box or a no-barrier container FS. See DURABLE-LOG.md "durability boundary".
            #[cfg(test)]
            let sync_result = if FAIL_SEGMENT_SYNC.with(Cell::get) {
                Err(std::io::Error::from_raw_os_error(5))
            } else {
                self.active.sync_all()
            };
            #[cfg(not(test))]
            let sync_result = self.active.sync_all();
            if let Err(error) = sync_result {
                self.poisoned = true;
                self.buf.clear();
                return Err(error.into());
            }
            self.write_off += self.buf.len() as u64;
            self.buf.clear();
            if self.write_off >= self.cfg.segment_bytes {
                if let Err(error) = self.rotate() {
                    self.poisoned = true;
                    return Err(error);
                }
            }
        }
        self.last_flush = Instant::now();
        Ok(())
    }

    /// Number of delivered-but-un-acked cofres currently tracked in the in-flight bookkeeping. The ack-cost
    /// invariant (`DURABLE-LOG.md`): this grows with the un-acked backlog and returns to 0 once everything is
    /// acked — the bookkeeping is RECLAIMED, not leaked. (Asserted at the data-structure level because RSS reclaim
    /// is allocator-dependent: glibc malloc retains freed pages in its arenas, so RSS need not drop on Linux.)
    #[must_use]
    pub fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    /// Start a fresh segment file. The new file's dir-entry is made durable by fsync'ing the directory, so a
    /// power-loss can't leave fsync'd segment data unreachable because its name never hit the directory.
    fn rotate(&mut self) -> Result<(), WalError> {
        self.active_id += 1;
        let path = seg_path(&self.dir, self.active_id);
        let active = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        fsync_dir(&self.dir)?;
        self.active = active;
        self.write_off = 0;
        Ok(())
    }

    /// Persist the read/ack cursors durably (write-tmp + fsync + rename + **dir fsync** = a truly atomic,
    /// crash-safe checkpoint — without the directory fsync the rename itself can be lost on power-loss, which is
    /// what caused the GC-vs-lost-cursor total-loss bug).
    fn checkpoint(&mut self) -> Result<(), WalError> {
        let ack_floor = self.ack_floor();
        let tmp = self.dir.join("cursor.tmp");
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        let mut rec = Vec::with_capacity(32);
        rec.extend_from_slice(&self.read_id.to_be_bytes());
        rec.extend_from_slice(&self.read_off.to_be_bytes());
        rec.extend_from_slice(&ack_floor.0.to_be_bytes());
        rec.extend_from_slice(&ack_floor.1.to_be_bytes());
        f.write_all(&rec)?;
        f.sync_all()?;
        std::fs::rename(&tmp, self.dir.join("cursor"))?;
        fsync_dir(&self.dir)?;
        Ok(())
    }

    /// The (segment, offset) below which everything is delivered AND acked — the GC floor.
    fn ack_floor(&self) -> (u64, u64) {
        // Conservative: the oldest segment that still has an in-flight (un-acked) cofre bounds GC; if none,
        // the read cursor is the floor (all delivered are acked).
        let oldest = self
            .seg_inflight
            .iter()
            .filter(|(_, &n)| n > 0)
            .map(|(&s, _)| s)
            .min();
        oldest.map_or((self.read_id, self.read_off), |s| (s, 0))
    }

    /// Open `read_id`'s segment for reading, seeking to `read_off`. Returns false if that segment doesn't exist.
    fn ensure_read_file(&mut self) -> Result<bool, WalError> {
        if self.read_file.is_none() {
            let path = seg_path(&self.dir, self.read_id);
            match OpenOptions::new().read(true).open(&path) {
                Ok(mut f) => {
                    f.seek(SeekFrom::Start(self.read_off))?;
                    self.read_file = Some(f);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    }
}

impl Substrate for DurableLog {
    type Error = WalError;

    fn send(&mut self, cofre: &Cofre) -> Result<(), WalError> {
        self.append(cofre)
    }

    fn recv(&mut self) -> Result<Option<Cofre>, WalError> {
        loop {
            // Make sure anything buffered is durable before it can be read (read-your-writes within a process).
            if self.read_id == self.active_id
                && self.read_off >= self.write_off
                && !self.buf.is_empty()
            {
                self.flush()?;
            }
            if !self.ensure_read_file()? {
                // The segment at `read_id` is missing (GC'd, or a lost cursor pointed below the live range).
                // Skip FORWARD to the next segment rather than stopping — returning None here would permanently
                // hide every surviving un-acked cofre in later segments (the GC+lost-cursor total-loss bug).
                if self.read_id < self.active_id {
                    self.read_id += 1;
                    self.read_off = 0;
                    continue;
                }
                return Ok(None);
            }
            let frame = read_frame(
                self.read_file.as_mut().expect("read_file set above"),
                self.read_id == self.active_id,
            )?;
            match frame {
                FrameRead::Cofre { bytes, advance } => {
                    let cofre = datarail_cofre::decode(&bytes)
                        .map_err(|e| WalError::Codec(e.to_string()))?;
                    self.read_off += advance;
                    let id = cofre.etiqueta.cofre_id;
                    self.inflight.insert(id, self.read_id);
                    *self.seg_inflight.entry(self.read_id).or_insert(0) += 1;
                    return Ok(Some(cofre));
                }
                FrameRead::Eof => {
                    // End of this segment. If a higher segment exists, roll the read cursor forward; else done.
                    if self.read_id < self.active_id {
                        self.read_id += 1;
                        self.read_off = 0;
                        self.read_file = None;
                        continue;
                    }
                    return Ok(None);
                }
            }
        }
    }

    fn ack(&mut self, cofre_id: [u8; 32]) -> Result<(), WalError> {
        let removed = if let Some(seg) = self.inflight.remove(&cofre_id) {
            if let Some(n) = self.seg_inflight.get_mut(&seg) {
                *n = n.saturating_sub(1);
            }
            Some(seg)
        } else {
            None
        };
        // CRASH-SAFE GC ORDER: durably checkpoint the advanced cursor FIRST, THEN delete segments. If we deleted
        // first and crashed before the cursor was durable, recovery would point at a deleted segment — the
        // total-loss bug. (recv's skip-forward is the additional safety net if a delete still races a stale
        // cursor.) The dir fsync in checkpoint() makes the cursor rename itself durable.
        if let Err(error) = self.checkpoint() {
            // A failed directory fsync means caller has no durable ack. Restore in-memory bookkeeping so a retry
            // cannot silently skip the cofre after a transient persistence failure.
            if let Some(seg) = removed {
                self.inflight.insert(cofre_id, seg);
                *self.seg_inflight.entry(seg).or_insert(0) += 1;
            }
            return Err(error);
        }
        let floor = self.ack_floor().0;
        let mut s = 1u64;
        let mut deleted = false;
        while s < floor && s < self.read_id {
            let p = seg_path(&self.dir, s);
            if p.exists() {
                std::fs::remove_file(&p).ok();
                deleted = true;
            }
            self.seg_inflight.remove(&s);
            s += 1;
        }
        if deleted {
            fsync_dir(&self.dir)?; // make the unlinks durable
        }
        Ok(())
    }
}

impl Drop for DurableLog {
    fn drop(&mut self) {
        if self.poisoned {
            return;
        }
        let _ = self.flush();
        let _ = self.checkpoint();
    }
}

// ---- free helpers (no growing state) ----

fn seg_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:012}.seg"))
}

/// fsync a directory so a create/rename/unlink of its entries is durable (Unix semantics). Some filesystems
/// return `EINVAL` for a directory fsync — that unsupported operation is tolerated. Other sync failures are
/// real durability errors and must reach the caller.
fn fsync_dir(dir: &Path) -> Result<(), WalError> {
    #[cfg(test)]
    if FAIL_DIR_FSYNC.with(Cell::get) {
        return Err(std::io::Error::from_raw_os_error(5).into());
    }
    fsync_dir_with(dir, File::sync_all)
}

fn fsync_dir_with<F>(dir: &Path, sync: F) -> Result<(), WalError>
where
    F: FnOnce(&File) -> std::io::Result<()>,
{
    match File::open(dir) {
        Ok(f) => {
            match sync(&f) {
                Ok(()) => Ok(()),
                // POSIX directory fsync is unavailable on some supported filesystems (notably macOS APIs).
                Err(error) if error.raw_os_error() == Some(22) => Ok(()),
                Err(error) => Err(error.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Highest existing segment id in `dir` (none ⇒ fresh log).
fn highest_segment(dir: &Path) -> Result<Option<u64>, WalError> {
    let mut max: Option<u64> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".seg") {
            if let Ok(id) = stem.parse::<u64>() {
                max = Some(max.map_or(id, |m| m.max(id)));
            }
        }
    }
    Ok(max)
}

/// Read the persisted cursor (`read_id`, `read_off`, `ack_id`, `ack_off`); defaults to `(1,0,1,0)` if absent or
/// short (a fresh log). Infallible — an unreadable cursor simply means "start from the beginning."
fn load_cursor(dir: &Path) -> (u64, u64, u64, u64) {
    let path = dir.join("cursor");
    match std::fs::read(&path) {
        Ok(b) if b.len() >= 32 => {
            let g = |i: usize| u64::from_be_bytes(b[i..i + 8].try_into().unwrap_or([0; 8]));
            (g(0), g(8), g(16), g(24))
        }
        Ok(_) | Err(_) => (1, 0, 1, 0),
    }
}

/// Scan the **active** segment from the start, returning the byte offset just past the last intact (CRC-valid)
/// frame. A torn tail (interrupted write) stops the scan — those bytes are truncated by the caller. `active=true`
/// because only the segment being written may legitimately have a torn tail.
fn recover_segment_end(file: &mut File) -> Result<u64, WalError> {
    file.seek(SeekFrom::Start(0))?;
    let mut off = 0u64;
    loop {
        match read_frame(file, true)? {
            FrameRead::Cofre { advance, .. } => off += advance,
            FrameRead::Eof => return Ok(off),
        }
    }
}

enum FrameRead {
    Cofre { bytes: Vec<u8>, advance: u64 },
    Eof,
}

/// Read one `[u32 len][bytes][u32 crc]` frame; the CRC covers `len‖bytes`.
///
/// `active` distinguishes the segment currently being appended (where a partial/torn tail is EXPECTED — a power
/// loss mid-write — and is reported as `Eof` so the caller truncates) from a SEALED segment (which must be
/// internally complete: a short read or CRC mismatch there is real **corruption** and is returned as an error,
/// NOT silently skipped — silently skipping a corrupt interior frame would drop every intact cofre after it).
fn read_frame(file: &mut File, active: bool) -> Result<FrameRead, WalError> {
    let corrupt = |what: &str| -> Result<FrameRead, WalError> {
        if active {
            Ok(FrameRead::Eof) // torn tail of the live segment — truncate
        } else {
            Err(WalError::Corrupt(format!("sealed segment: {what}")))
        }
    };
    let mut lenb = [0u8; 4];
    match file.read_exact(&mut lenb) {
        Ok(()) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(FrameRead::Eof), // clean EOF
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(lenb) as usize;
    if len == 0 || len > MAX_COFRE_WIRE_LEN {
        return corrupt("invalid frame length");
    }
    let mut bytes = vec![0u8; len];
    if file.read_exact(&mut bytes).is_err() {
        return corrupt("truncated body");
    }
    let mut crcb = [0u8; 4];
    if file.read_exact(&mut crcb).is_err() {
        return corrupt("truncated crc");
    }
    if u32::from_be_bytes(crcb) != crc32_2(&lenb, &bytes) {
        return corrupt("crc mismatch");
    }
    let advance = (FRAME_OVERHEAD + len) as u64;
    Ok(FrameRead::Cofre { bytes, advance })
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicU64, Ordering};

    use datarail_core::Substrate;
    use datarail_rail::testsupport::cofre_seq;

    use super::{fsync_dir_with, DurableLog, WalError, FAIL_DIR_FSYNC, FAIL_SEGMENT_SYNC};

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let id = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "datarail-wal-fsync-dir-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test directory");
        dir
    }

    #[test]
    fn directory_sync_tolerates_only_unsupported_einval() {
        let dir = temp_dir();
        let unsupported = io::Error::from_raw_os_error(22);
        assert!(fsync_dir_with(&dir, |_| Err(unsupported)).is_ok());

        let real_failure = io::Error::from_raw_os_error(5);
        assert!(matches!(
            fsync_dir_with(&dir, |_| Err(real_failure)),
            Err(WalError::Io(_))
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_directory_sync_does_not_consume_ack() {
        let dir = temp_dir();
        let mut log = DurableLog::open(&dir).expect("open test log");
        log.send(&cofre_seq(0)).expect("send");
        log.flush().expect("flush");
        let cofre = log.recv().expect("recv").expect("record");

        FAIL_DIR_FSYNC.with(|failed| failed.set(true));
        assert!(log.ack(cofre.etiqueta.cofre_id).is_err());
        assert_eq!(
            log.inflight_len(),
            1,
            "failed dir fsync must preserve retryable ack state"
        );
        FAIL_DIR_FSYNC.with(|failed| failed.set(false));
        log.ack(cofre.etiqueta.cofre_id).expect("retry ack");
        drop(log);

        let mut reopened = DurableLog::open(&dir).expect("reopen test log");
        assert!(reopened.recv().expect("recv after durable ack").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_segment_sync_poisoned_log_cannot_duplicate_buffer() {
        let dir = temp_dir();
        let cfg = super::WalConfig {
            flush_bytes: 1 << 20,
            flush_micros: u64::MAX,
            segment_bytes: 1 << 20,
        };
        let mut log = DurableLog::open_with(&dir, cfg).expect("open test log");
        log.send(&cofre_seq(0)).expect("buffer");
        FAIL_SEGMENT_SYNC.with(|failed| failed.set(true));
        assert!(log.flush().is_err());
        FAIL_SEGMENT_SYNC.with(|failed| failed.set(false));
        assert!(
            log.flush().is_err(),
            "failed log must not retry an ambiguous buffer"
        );
        drop(log);

        let mut reopened = DurableLog::open_with(&dir, cfg).expect("reopen test log");
        let cofre = reopened.recv().expect("recv").expect("durable frame");
        assert_eq!(cofre.etiqueta.seq, 0);
        reopened.ack(cofre.etiqueta.cofre_id).expect("ack");
        assert!(reopened.recv().expect("drain").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
