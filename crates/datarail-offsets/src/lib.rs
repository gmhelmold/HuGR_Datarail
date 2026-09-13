//! `datarail-offsets` — FROZEN CONTRACT (frozen by the lead): durable group-offset commits. `MemOffsets` is the working
//! reference (dependents test against it); `FileOffsets` (crash-safe, fsync'd) is implemented by WP1.
#![forbid(unsafe_code)]
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Where consumer groups durably record how far they've consumed.
pub trait OffsetStore {
    /// Durably commit `group`'s offset (survives restart).
    /// # Errors
    /// Backend write/fsync failure.
    fn commit(&mut self, group: &str, offset: u64) -> Result<(), std::io::Error>;
    /// The last committed offset for `group`, or `None`.
    fn fetch(&self, group: &str) -> Option<u64>;
    /// All known group names.
    fn groups(&self) -> Vec<String>;
}

/// The working in-memory reference — frozen by the lead so dependents (WP4) can test immediately.
#[derive(Debug, Default)]
pub struct MemOffsets {
    map: BTreeMap<String, u64>,
}
impl MemOffsets {
    /// A new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}
impl OffsetStore for MemOffsets {
    fn commit(&mut self, group: &str, offset: u64) -> Result<(), std::io::Error> {
        self.map.insert(group.to_owned(), offset);
        Ok(())
    }
    fn fetch(&self, group: &str) -> Option<u64> {
        self.map.get(group).copied()
    }
    fn groups(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }
}

/// Name of the append-only commit log inside the store directory.
const LOG_NAME: &str = "offsets.log";
/// Name of the temp file a compaction snapshot is written to before the
/// atomic rename. A stale copy (a crash mid-compaction) is removed on open.
const TMP_NAME: &str = "offsets.log.tmp";
/// A compaction is never triggered below this many physical records — it keeps
/// small logs (the common case) from paying any rewrite cost.
const COMPACT_MIN_RECORDS: usize = 1024;
/// Above the minimum, compact once the log holds more than this many physical
/// records per live group. This bounds on-disk size to O(groups): a single
/// group committed a million times compacts back to one record long before the
/// log can grow large.
const COMPACT_GROWTH_FACTOR: usize = 4;

/// Bitwise CRC-32 (IEEE 802.3, reflected) over `bytes` — a std-only integrity
/// check so a torn write at the log tail is detected on recovery.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A crash-safe, fsync'd, durable [`OffsetStore`] backed by an append-only
/// commit log.
///
/// Each [`commit`](OffsetStore::commit) appends a length-prefixed,
/// CRC-checked record `[group_len: u32][group][offset: u64][crc: u32]`
/// (all integers little-endian) and fsyncs the file before returning, so a
/// committed offset survives a process restart or crash. On [`open`](Self::open)
/// the log is replayed start-to-finish and the last record per group wins; a
/// torn or corrupt tail record is discarded, leaving every prior commit intact.
///
/// ## Bounded size via compaction
/// Because the log is append-only and last-write-wins, a group committed N
/// times leaves N records though only the last matters. To keep on-disk size
/// O(groups) rather than O(commits), once the log holds more than
/// [`COMPACT_GROWTH_FACTOR`] physical records per live group (and at least
/// [`COMPACT_MIN_RECORDS`]) it is *compacted*: a snapshot of one record per
/// group (the current offset) is written to a temp file, fsync'd, and
/// atomically renamed over the live log (with a directory fsync so the rename
/// is durable). Recovery is unaffected — a crash mid-compaction leaves either
/// the intact old log or the intact new snapshot, never a torn mix, because the
/// rename is atomic. A stale temp file from such a crash is removed on `open`.
#[derive(Debug)]
pub struct FileOffsets {
    file: File,
    map: BTreeMap<String, u64>,
    dir: PathBuf,
    /// Count of physical records in the live log (drives the compaction trigger).
    records: usize,
}

/// A prior value for one group, used by a durable transaction recovery path. `None` means the group did not exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffsetSnapshot {
    /// Consumer-group key.
    pub group: String,
    /// Previously committed value, if any.
    pub offset: Option<u64>,
}

/// fsync a directory so a `create`/`rename` within it is durable across a power loss (the file's own data fsync
/// does NOT guarantee its directory entry is persisted). Unix-targeted; the project runs on macOS/Linux.
fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

impl FileOffsets {
    /// Open (creating if absent) the durable offset store in directory `dir`,
    /// recovering the latest committed offset for every group.
    ///
    /// # Errors
    /// The directory cannot be created, the log cannot be opened, or an I/O
    /// error occurs while reading the log during recovery.
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        // A leftover temp file means a crash before a compaction's rename; the
        // live log is authoritative, so drop the partial snapshot.
        let _ = std::fs::remove_file(dir.join(TMP_NAME));
        let path: PathBuf = dir.join(LOG_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let (map, records) = Self::replay(&mut file)?;
        // Make the log's directory entry durable: a first-ever create must survive a power loss, else a
        // committed offset whose file data fsync'd could vanish with the lost create (audit D-6).
        fsync_dir(&dir)?;
        Ok(Self {
            file,
            map,
            dir,
            records,
        })
    }

    /// Capture current values for groups that may be changed by one transaction.
    #[must_use]
    pub fn snapshot(&self, groups: &[String]) -> Vec<OffsetSnapshot> {
        groups
            .iter()
            .map(|group| OffsetSnapshot {
                group: group.clone(),
                offset: self.map.get(group).copied(),
            })
            .collect()
    }

    /// Durably apply several group offsets under one file fsync boundary.
    ///
    /// # Errors
    /// Returns an I/O or encoding error. On failure the in-memory map is unchanged; recovery can restore the prior
    /// snapshot if a prefix reached disk.
    pub fn commit_many(&mut self, values: &[(String, u64)]) -> io::Result<()> {
        let mut encoded = Vec::new();
        for (group, offset) in values {
            encoded.extend_from_slice(&Self::encode_record(group, *offset)?);
        }
        self.file.write_all(&encoded)?;
        self.file.sync_all()?;
        for (group, offset) in values {
            self.map.insert(group.clone(), *offset);
        }
        self.records += values.len();
        self.maybe_compact()
    }

    /// Restore a captured group snapshot through an atomic compacted replacement.
    ///
    /// # Errors
    /// Returns an I/O or encoding error. The caller must fail closed if restoration does not complete.
    pub fn restore_many(&mut self, snapshots: &[OffsetSnapshot]) -> io::Result<()> {
        let mut restored = self.map.clone();
        for snapshot in snapshots {
            match snapshot.offset {
                Some(offset) => {
                    restored.insert(snapshot.group.clone(), offset);
                }
                None => {
                    restored.remove(&snapshot.group);
                }
            }
        }
        self.rewrite_map(&restored)
    }

    /// Read the whole log and fold it into the latest-offset-per-group map,
    /// stopping at the first incomplete or CRC-mismatched record (a torn tail).
    /// Also returns the number of intact physical records replayed.
    fn replay(file: &mut File) -> io::Result<(BTreeMap<String, u64>, usize)> {
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let mut map = BTreeMap::new();
        let mut pos = 0usize;
        let mut records = 0usize;
        while let Some((group, offset, next)) = Self::parse_record(&buf, pos) {
            map.insert(group, offset);
            pos = next;
            records += 1;
        }
        Ok((map, records))
    }

    /// Encode one length-prefixed, CRC-checked record for `group`/`offset`.
    ///
    /// # Errors
    /// The group name exceeds `u32::MAX` bytes.
    fn encode_record(group: &str, offset: u64) -> io::Result<Vec<u8>> {
        let group_len = u32::try_from(group.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "group name too long"))?;
        let mut record = Vec::with_capacity(group.len() + 16);
        record.extend_from_slice(&group_len.to_le_bytes());
        record.extend_from_slice(group.as_bytes());
        record.extend_from_slice(&offset.to_le_bytes());
        let crc = crc32(&record);
        record.extend_from_slice(&crc.to_le_bytes());
        Ok(record)
    }

    /// Compact the log if it has grown past the trigger
    /// ([`COMPACT_MIN_RECORDS`] records and more than [`COMPACT_GROWTH_FACTOR`]
    /// records per live group), bounding on-disk size to O(groups).
    fn maybe_compact(&mut self) -> io::Result<()> {
        let live = self.map.len().max(1);
        if self.records < COMPACT_MIN_RECORDS || self.records <= COMPACT_GROWTH_FACTOR * live {
            return Ok(());
        }
        self.compact()
    }

    /// Rewrite the log as one record per group via temp-file + fsync + atomic
    /// rename, then continue appending to the fresh file. Crash-safe: until the
    /// rename completes the old log is untouched, and the rename is atomic, so
    /// recovery always sees exactly one intact file.
    fn compact(&mut self) -> io::Result<()> {
        self.rewrite_map(&self.map.clone())
    }

    fn rewrite_map(&mut self, map: &BTreeMap<String, u64>) -> io::Result<()> {
        let tmp_path = self.dir.join(TMP_NAME);
        let live_path = self.dir.join(LOG_NAME);
        {
            let mut tmp = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            let mut snapshot = Vec::new();
            for (group, &offset) in map {
                snapshot.extend_from_slice(&Self::encode_record(group, offset)?);
            }
            tmp.write_all(&snapshot)?;
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, &live_path)?;
        // WP5 audit F1 fix: reopen the live handle + reset the counter IMMEDIATELY after the rename (the old
        // handle now points at the unlinked inode). The directory fsync is a durability nicety done AFTER, and is
        // best-effort — if it errored before the reopen, a subsequent `commit` would write to the dead inode and
        // be silently lost on the next open.
        self.file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&live_path)?;
        self.records = map.len();
        // fsync the directory so the rename itself is durable across a power loss. Done AFTER the reopen (a
        // pre-reopen error would strand `self.file` on the dead inode); propagated now (audit D-6) so a caller
        // learns the rename may not be durable rather than silently assuming it is.
        fsync_dir(&self.dir)?;
        self.map.clone_from(map);
        Ok(())
    }

    /// Parse one record starting at `pos`, returning the group, offset, and the
    /// offset just past it, or `None` if the bytes are incomplete/corrupt.
    fn parse_record(buf: &[u8], pos: usize) -> Option<(String, u64, usize)> {
        let len_end = pos.checked_add(4)?;
        let len_bytes: [u8; 4] = buf.get(pos..len_end)?.try_into().ok()?;
        let group_len = u32::from_le_bytes(len_bytes) as usize;
        let group_end = len_end.checked_add(group_len)?;
        let group_bytes = buf.get(len_end..group_end)?;
        let offset_end = group_end.checked_add(8)?;
        let offset_bytes: [u8; 8] = buf.get(group_end..offset_end)?.try_into().ok()?;
        let crc_end = offset_end.checked_add(4)?;
        let crc_bytes: [u8; 4] = buf.get(offset_end..crc_end)?.try_into().ok()?;
        let stored_crc = u32::from_le_bytes(crc_bytes);
        if crc32(buf.get(pos..offset_end)?) != stored_crc {
            return None;
        }
        let group = String::from_utf8(group_bytes.to_vec()).ok()?;
        let offset = u64::from_le_bytes(offset_bytes);
        Some((group, offset, crc_end))
    }
}

impl OffsetStore for FileOffsets {
    fn commit(&mut self, group: &str, offset: u64) -> Result<(), std::io::Error> {
        let record = Self::encode_record(group, offset)?;
        self.file.write_all(&record)?;
        self.file.sync_all()?;
        self.map.insert(group.to_owned(), offset);
        self.records += 1;
        self.maybe_compact()
    }
    fn fetch(&self, group: &str) -> Option<u64> {
        self.map.get(group).copied()
    }
    fn groups(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{FileOffsets, OffsetSnapshot, OffsetStore};
    use std::path::PathBuf;

    /// A unique, auto-cleaned temp dir per test.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            p.push(format!(
                "datarail-offsets-{}-{}-{nanos}",
                std::process::id(),
                tag
            ));
            std::fs::create_dir_all(&p).expect("create temp dir");
            Self(p)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn commit_fetch_roundtrip() {
        let tmp = TmpDir::new("roundtrip");
        let mut store = FileOffsets::open(&tmp.0).expect("open");
        store.commit("g", 42).expect("commit");
        assert_eq!(store.fetch("g"), Some(42));
    }

    #[test]
    fn durable_across_reopen() {
        let tmp = TmpDir::new("durable");
        {
            let mut store = FileOffsets::open(&tmp.0).expect("open");
            store.commit("alpha", 1).expect("commit");
            store.commit("beta", 22).expect("commit");
            store.commit("gamma", 333).expect("commit");
        }
        let store = FileOffsets::open(&tmp.0).expect("reopen");
        assert_eq!(store.fetch("alpha"), Some(1));
        assert_eq!(store.fetch("beta"), Some(22));
        assert_eq!(store.fetch("gamma"), Some(333));
    }

    #[test]
    fn batch_offsets_snapshot_and_restore_survive_reopen() {
        let tmp = TmpDir::new("batch");
        let mut store = FileOffsets::open(&tmp.0).expect("open");
        store.commit("g", 7).expect("seed");
        let groups = vec!["g".to_owned(), "new".to_owned()];
        let before = store.snapshot(&groups);
        assert_eq!(
            before,
            vec![
                OffsetSnapshot {
                    group: "g".to_owned(),
                    offset: Some(7)
                },
                OffsetSnapshot {
                    group: "new".to_owned(),
                    offset: None
                },
            ]
        );

        store
            .commit_many(&[("g".to_owned(), 8), ("new".to_owned(), 9)])
            .expect("batch commit");
        assert_eq!(store.fetch("g"), Some(8));
        assert_eq!(store.fetch("new"), Some(9));
        store.restore_many(&before).expect("restore snapshot");
        assert_eq!(store.fetch("g"), Some(7));
        assert_eq!(store.fetch("new"), None);

        let reopened = FileOffsets::open(&tmp.0).expect("reopen");
        assert_eq!(reopened.fetch("g"), Some(7));
        assert_eq!(reopened.fetch("new"), None);
    }

    #[test]
    fn last_write_wins() {
        let tmp = TmpDir::new("lww");
        {
            let mut store = FileOffsets::open(&tmp.0).expect("open");
            store.commit("g", 1).expect("commit");
            store.commit("g", 2).expect("commit");
            store.commit("g", 999).expect("commit");
        }
        let store = FileOffsets::open(&tmp.0).expect("reopen");
        assert_eq!(store.fetch("g"), Some(999));
    }

    #[test]
    fn groups_isolated() {
        let tmp = TmpDir::new("iso");
        let mut store = FileOffsets::open(&tmp.0).expect("open");
        store.commit("a", 5).expect("commit");
        store.commit("b", 7).expect("commit");
        assert_eq!(store.fetch("a"), Some(5));
        assert_eq!(store.fetch("b"), Some(7));
        let mut g = store.groups();
        g.sort();
        assert_eq!(g, vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn unknown_group_is_none() {
        let tmp = TmpDir::new("unknown");
        let store = FileOffsets::open(&tmp.0).expect("open");
        assert_eq!(store.fetch("nope"), None);
    }

    /// Current on-disk size of the live log.
    fn log_size(dir: &std::path::Path) -> u64 {
        std::fs::metadata(dir.join("offsets.log")).map_or(0, |m| m.len())
    }

    #[test]
    fn compaction_bounds_disk_size_one_group() {
        // The same group committed far past the compaction trigger
        // (COMPACT_MIN_RECORDS = 1024) so ≥2 compactions occur; the final count
        // lands just past a compaction boundary, leaving a tiny live log. Each
        // commit fsyncs, so the count is kept modest while still O(commits)
        // would balloon the file (~40 KB) absent compaction.
        let tmp = TmpDir::new("compact-bound");
        let mut store = FileOffsets::open(&tmp.0).expect("open");
        for i in 0..2_100u64 {
            store.commit("g", i).expect("commit");
        }
        // One group, last-write-wins: the log must stay O(groups), not O(commits).
        assert!(
            log_size(&tmp.0) < 4096,
            "log not compacted: {}",
            log_size(&tmp.0)
        );
        assert_eq!(store.fetch("g"), Some(2_099));
    }

    #[test]
    fn durable_across_compaction() {
        let tmp = TmpDir::new("compact-durable");
        let mut expected = std::collections::BTreeMap::new();
        {
            let mut store = FileOffsets::open(&tmp.0).expect("open");
            // Enough commits across several groups to trigger ≥1 compaction.
            for i in 0..2_100u64 {
                let g = format!("group-{}", i % 8);
                store.commit(&g, i).expect("commit");
                expected.insert(g, i);
            }
        }
        // Reopen from disk: every group's latest offset must be recovered.
        let store = FileOffsets::open(&tmp.0).expect("reopen");
        for (g, want) in &expected {
            assert_eq!(store.fetch(g), Some(*want));
        }
    }

    #[test]
    fn commits_after_compaction_still_correct() {
        let tmp = TmpDir::new("compact-then-more");
        let mut store = FileOffsets::open(&tmp.0).expect("open");
        for i in 0..1_100u64 {
            store.commit("x", i).expect("commit"); // crosses the compaction trigger
        }
        // Append more, including a new group, after the rewrite.
        store.commit("x", 123_456).expect("commit");
        store.commit("y", 7).expect("commit");
        assert_eq!(store.fetch("x"), Some(123_456));
        assert_eq!(store.fetch("y"), Some(7));
        drop(store);
        let store = FileOffsets::open(&tmp.0).expect("reopen");
        assert_eq!(store.fetch("x"), Some(123_456));
        assert_eq!(store.fetch("y"), Some(7));
    }
}
