//! `datarail-blobstore` — FROZEN CONTRACT (frozen by the lead): the cold-tier blob seam. `MemBlob` is the working
//! reference (dependents test against it); `FsBlob` is implemented by WP2.
#![forbid(unsafe_code)]
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A content-addressed-ish blob store: opaque keys → bytes. The seam that lets the cold tier be local FS today
/// and S3/GCS tomorrow (same trait, GET/PUT/LIST/DELETE verbs).
pub trait BlobStore {
    /// Store/overwrite `key` with `bytes`.
    /// # Errors
    /// Backend write failure.
    fn put(&mut self, key: &str, bytes: &[u8]) -> Result<(), std::io::Error>;
    /// Fetch `key`, or `None` if absent.
    /// # Errors
    /// Backend read failure.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, std::io::Error>;
    /// All keys with the given prefix, sorted.
    /// # Errors
    /// Backend list failure.
    fn list(&self, prefix: &str) -> Result<Vec<String>, std::io::Error>;
    /// Delete `key`; returns whether it existed.
    /// # Errors
    /// Backend delete failure.
    fn delete(&mut self, key: &str) -> Result<bool, std::io::Error>;
}

/// The working in-memory reference implementation — frozen by the lead so dependents (WP3) can test immediately.
#[derive(Debug, Default)]
pub struct MemBlob {
    map: BTreeMap<String, Vec<u8>>,
}
impl MemBlob {
    /// A new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}
impl BlobStore for MemBlob {
    fn put(&mut self, key: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
        self.map.insert(key.to_owned(), bytes.to_vec());
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, std::io::Error> {
        Ok(self.map.get(key).cloned())
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>, std::io::Error> {
        Ok(self
            .map
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    fn delete(&mut self, key: &str) -> Result<bool, std::io::Error> {
        Ok(self.map.remove(key).is_some())
    }
}

/// Process-global counter feeding unique temp-file names for atomic writes.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Percent-encode `key` into a single, flat, path-safe filename.
///
/// Only the unreserved set `[A-Za-z0-9_-]` passes through verbatim; every other
/// byte becomes `%XX` (uppercase hex). Because `/`, `.` and every separator are
/// escaped, the result is always a single path component that can never traverse
/// out of the store root — this is the security boundary, not a sanity check.
fn encode_key(key: &str) -> String {
    // Constant 'B' marker prefix (WP6 audit fix): guarantees the encoded name is never EMPTY (so an empty key
    // maps to "B", not the root dir itself) and never starts with '.' (so it can never collide with a `.tmp.*`
    // temp file). 'B' is in the verbatim alphanumeric set, so decode just strips one leading 'B'.
    let mut out = String::with_capacity(key.len() + 1);
    out.push('B');
    for &b in key.as_bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(hex_digit(b >> 4)));
            out.push(char::from(hex_digit(b & 0x0f)));
        }
    }
    out
}

/// Map a nibble (0..=15) to its uppercase ASCII hex digit.
fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'A' + (nibble - 10),
    }
}

/// Parse a single ASCII hex digit back into its nibble value, or `None` if invalid.
fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode a filename produced by [`encode_key`] back into the original key.
///
/// Returns `None` for any name that is not a valid encoding (e.g. transient
/// temp files), so callers can skip non-blob entries safely.
fn decode_key(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    // Must start with the 'B' marker written by `encode_key`; anything else (temp files, foreign files) is not
    // one of our blobs → None (so `list` skips it).
    let bytes = bytes.strip_prefix(b"B")?;
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let hi = hex_value(*bytes.get(i + 1)?)?;
            let lo = hex_value(*bytes.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            out.push(b);
            i += 1;
        } else {
            return None;
        }
    }
    String::from_utf8(out).ok()
}

/// A local-filesystem [`BlobStore`]: each key is percent-encoded into one flat
/// filename under `root`, and writes are made crash-atomic via temp-file + rename.
#[derive(Debug, Clone)]
pub struct FsBlob {
    root: PathBuf,
}

impl FsBlob {
    /// Open (creating if needed) a filesystem blob store rooted at `root`.
    ///
    /// # Errors
    /// If `root` cannot be created or is not a directory.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, io::Error> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Absolute path of the blob backing `key`.
    fn path_for(&self, key: &str) -> PathBuf {
        self.root.join(encode_key(key))
    }

    /// A unique temp-file path within the root (same filesystem ⇒ atomic rename).
    fn tmp_path(&self) -> PathBuf {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        self.root
            .join(format!(".tmp.{}.{nanos}.{seq}", std::process::id()))
    }
}

impl BlobStore for FsBlob {
    fn put(&mut self, key: &str, bytes: &[u8]) -> Result<(), io::Error> {
        let tmp = self.tmp_path();
        fs::write(&tmp, bytes)?;
        // WP6 audit fix: fsync the bytes BEFORE the rename so a power loss can't leave a present-but-empty blob
        // (power-durable, not merely crash-atomic — matching the rest of this codebase's durability bar).
        fs::File::open(&tmp)?.sync_all()?;
        if let Err(e) = fs::rename(&tmp, self.path_for(key)) {
            drop(fs::remove_file(&tmp));
            return Err(e);
        }
        // fsync the directory so the rename itself is durable.
        if let Ok(dir) = fs::File::open(&self.root) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, io::Error> {
        match fs::read(self.path_for(key)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, io::Error> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(key) = decode_key(name) else {
                continue;
            };
            if key.starts_with(prefix) {
                out.push(key);
            }
        }
        out.sort();
        Ok(out)
    }

    fn delete(&mut self, key: &str) -> Result<bool, io::Error> {
        match fs::remove_file(self.path_for(key)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BlobStore, FsBlob, MemBlob};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    /// A unique temp directory that removes itself on drop.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let mut p = std::env::temp_dir();
            p.push(format!(
                "datarail-fsblob-{}-{tag}-{seq}",
                std::process::id()
            ));
            Self(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn roundtrip_including_slash_keys() {
        let dir = TmpDir::new("roundtrip");
        let mut fs_blob = FsBlob::open(dir.path()).unwrap();
        let cases: &[(&str, &[u8])] = &[
            ("flat", b"value-a"),
            ("nested/key/with/slashes", b"value-b"),
            ("weird .%+=key", b"value-c"),
            ("empty", b""),
        ];
        for (k, v) in cases {
            fs_blob.put(k, v).unwrap();
            assert_eq!(fs_blob.get(k).unwrap().as_deref(), Some(*v));
        }
        // Keys from list round-trip back through get.
        for k in fs_blob.list("").unwrap() {
            assert!(fs_blob.get(&k).unwrap().is_some());
        }
    }

    #[test]
    fn conformance_mem_vs_fs() {
        let dir = TmpDir::new("conformance");
        let mut mem = MemBlob::new();
        let mut fsb = FsBlob::open(dir.path()).unwrap();

        let ops: &[(&str, &[u8])] = &[
            ("a/1", b"one"),
            ("a/2", b"two"),
            ("b/1", b"three"),
            ("a/1", b"one-overwritten"),
            ("c", b""),
        ];
        for (k, v) in ops {
            assert_eq!(mem.put(k, v).is_ok(), fsb.put(k, v).is_ok());
            assert_eq!(mem.get(k).unwrap(), fsb.get(k).unwrap());
        }
        for prefix in ["", "a", "a/", "b", "z"] {
            assert_eq!(mem.list(prefix).unwrap(), fsb.list(prefix).unwrap());
        }
        for k in ["a/1", "a/2", "missing"] {
            assert_eq!(mem.delete(k).unwrap(), fsb.delete(k).unwrap());
            assert_eq!(mem.get(k).unwrap(), fsb.get(k).unwrap());
        }
        assert_eq!(mem.list("").unwrap(), fsb.list("").unwrap());
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = TmpDir::new("persist");
        {
            let mut fsb = FsBlob::open(dir.path()).unwrap();
            fsb.put("durable/key", b"survives").unwrap();
        }
        let reopened = FsBlob::open(dir.path()).unwrap();
        assert_eq!(
            reopened.get("durable/key").unwrap().as_deref(),
            Some(&b"survives"[..])
        );
    }

    #[test]
    fn list_by_prefix_sorted() {
        let dir = TmpDir::new("list");
        let mut fsb = FsBlob::open(dir.path()).unwrap();
        for k in ["p/c", "p/a", "p/b", "q/a"] {
            fsb.put(k, b"x").unwrap();
        }
        assert_eq!(fsb.list("p/").unwrap(), vec!["p/a", "p/b", "p/c"]);
        assert_eq!(fsb.list("q/").unwrap(), vec!["q/a"]);
        assert!(fsb.list("z").unwrap().is_empty());
    }

    #[test]
    fn delete_semantics() {
        let dir = TmpDir::new("delete");
        let mut fsb = FsBlob::open(dir.path()).unwrap();
        fsb.put("k", b"v").unwrap();
        assert!(fsb.delete("k").unwrap());
        assert!(!fsb.delete("k").unwrap());
        assert_eq!(fsb.get("k").unwrap(), None);
    }

    #[test]
    fn path_traversal_cannot_escape_root() {
        let parent = TmpDir::new("traversal-parent");
        std::fs::create_dir_all(parent.path()).unwrap();
        let root = parent.path().join("store");
        let mut fsb = FsBlob::open(&root).unwrap();

        let evil_key = "../evil";
        fsb.put(evil_key, b"pwned").unwrap();

        // The sibling path the naive key would resolve to must NOT exist.
        let escaped = parent.path().join("evil");
        assert!(!escaped.exists(), "key escaped the store root");
        // It is stored safely inside root and round-trips.
        assert_eq!(fsb.get(evil_key).unwrap().as_deref(), Some(&b"pwned"[..]));
        assert_eq!(fsb.list("").unwrap(), vec![evil_key.to_owned()]);
    }
}
