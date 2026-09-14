//! `datarail-netblob` — FROZEN API (frozen by the lead); WP3 implements the bodies + gates.
//! Serves any [`datarail_blobstore::BlobStore`] over a TCP socket, and provides `NetBlob` — a client that
//! implements `BlobStore` by round-tripping put/get/list/delete to that server (the cold tier, made remote).
//!
//! # Wire protocol
//! Every message is a length-prefixed frame: a little-endian `u32` byte count followed by exactly that many
//! body bytes. The first body byte is an op tag (requests) or a status byte (responses: `0` = ok, `1` = error
//! with a UTF-8 message). Strings and byte blobs are carried either as a `u32`-prefixed field or as the
//! frame remainder. Framing makes the codec robust to partial reads (every multi-byte read is `read_exact`).
#![forbid(unsafe_code)]
use datarail_blobstore::BlobStore;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// Request op tag: store/overwrite a key. Body: `[tag][u32 key_len][key][value..]`.
/// Max concurrent connections — bounds thread/FD/memory under a connection flood (audit MED).
const MAX_CONNECTIONS: usize = 256;

const OP_PUT: u8 = 1;
/// Request op tag: fetch a key. Body: `[tag][key..]`.
const OP_GET: u8 = 2;
/// Request op tag: list keys by prefix. Body: `[tag][prefix..]`.
const OP_LIST: u8 = 3;
/// Request op tag: delete a key. Body: `[tag][key..]`.
const OP_DELETE: u8 = 4;

/// Response status byte: the op succeeded; op-specific payload follows.
const STATUS_OK: u8 = 0;
/// Response status byte: the op failed; a UTF-8 error message follows.
const STATUS_ERR: u8 = 1;

/// A client `BlobStore` that forwards every op to a remote [`serve`] endpoint over TCP.
pub struct NetBlob {
    addr: SocketAddr,
}

impl NetBlob {
    /// Connect to a blob server at `addr`.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
    /// The server address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Open a fresh connection, send `body` as one frame, and return the response frame body.
    ///
    /// # Errors
    /// Connect/IO failure, or a closed connection with no response.
    fn round_trip(&self, body: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect(self.addr)?;
        write_frame(&mut stream, body)?;
        match read_frame(&mut stream)? {
            Some(resp) => Ok(resp),
            None => Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "server closed without responding",
            )),
        }
    }
}

impl BlobStore for NetBlob {
    fn put(&mut self, key: &str, bytes: &[u8]) -> io::Result<()> {
        let mut body = Vec::with_capacity(5 + key.len() + bytes.len());
        body.push(OP_PUT);
        body.extend_from_slice(&len_u32(key.len())?.to_le_bytes());
        body.extend_from_slice(key.as_bytes());
        body.extend_from_slice(bytes);
        let resp = self.round_trip(&body)?;
        ok_payload(&resp).map(|_| ())
    }

    fn get(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let mut body = Vec::with_capacity(1 + key.len());
        body.push(OP_GET);
        body.extend_from_slice(key.as_bytes());
        let resp = self.round_trip(&body)?;
        let mut reader = Reader::new(ok_payload(&resp)?);
        if reader.u8()? == 0 {
            Ok(None)
        } else {
            Ok(Some(reader.rest().to_vec()))
        }
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        let mut body = Vec::with_capacity(1 + prefix.len());
        body.push(OP_LIST);
        body.extend_from_slice(prefix.as_bytes());
        let resp = self.round_trip(&body)?;
        let mut reader = Reader::new(ok_payload(&resp)?);
        let count = reader.u32()?;
        let mut out = Vec::new();
        for _ in 0..count {
            let len = usize_of(reader.u32()?);
            let raw = reader.take(len)?;
            let s = std::str::from_utf8(raw).map_err(|_| {
                io::Error::new(ErrorKind::InvalidData, "non-utf8 key in list response")
            })?;
            out.push(s.to_owned());
        }
        Ok(out)
    }

    fn delete(&mut self, key: &str) -> io::Result<bool> {
        let mut body = Vec::with_capacity(1 + key.len());
        body.push(OP_DELETE);
        body.extend_from_slice(key.as_bytes());
        let resp = self.round_trip(&body)?;
        let mut reader = Reader::new(ok_payload(&resp)?);
        Ok(reader.u8()? != 0)
    }
}

/// Serve `store` on a fresh loopback TCP listener; returns the bound address.
///
/// Binds `127.0.0.1:0`, then spawns a detached thread running the accept loop. The store is moved behind an
/// `Arc<Mutex<_>>` and a thread is spawned per connection, so concurrent clients are serialized at the store
/// (correctness over throughput). Each connection reads framed ops until the peer closes.
///
/// # Errors
/// If binding the listener or reading its local address fails.
pub fn serve<B: BlobStore + Send + 'static>(store: B) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let addr = listener.local_addr()?;
    let store = Arc::new(Mutex::new(store));
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(stream) = incoming else { continue };
            // Bound concurrency (audit MED): a connection FLOOD must not spawn unbounded threads/FDs. Drop new
            // connections past the cap rather than spawn. (Slowloris is separately bounded by the read timeout.)
            if active.load(std::sync::atomic::Ordering::Relaxed) >= MAX_CONNECTIONS {
                drop(stream);
                continue;
            }
            // WP4 audit M1 fix: a read timeout so a stalled/slow-loris client cannot park its connection thread
            // forever (thread/FD exhaustion). A legit op completes well within this.
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
            active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let store = Arc::clone(&store);
            let active = Arc::clone(&active);
            std::thread::spawn(move || {
                // A connection-level IO error simply ends that connection; the server keeps serving.
                let _ = serve_connection(&stream, &store);
                active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    Ok(addr)
}

/// Handle one connection: read op frames and apply each to `store`, writing a response frame per op.
///
/// # Errors
/// Propagates the first IO error (which terminates this connection only).
fn serve_connection<B: BlobStore>(mut stream: &TcpStream, store: &Mutex<B>) -> io::Result<()> {
    while let Some(body) = read_frame(&mut stream)? {
        let response = handle_op(&body, store);
        write_frame(&mut stream, &response)?;
    }
    Ok(())
}

/// Apply one request body to `store`, returning the response body (never fails: store/parse errors are
/// encoded as a `STATUS_ERR` frame so the client surfaces them as an `io::Error`).
fn handle_op<B: BlobStore>(body: &[u8], store: &Mutex<B>) -> Vec<u8> {
    match apply(body, store) {
        Ok(payload) => payload,
        Err(e) => {
            let msg = e.to_string();
            let mut out = Vec::with_capacity(1 + msg.len());
            out.push(STATUS_ERR);
            out.extend_from_slice(msg.as_bytes());
            out
        }
    }
}

/// Parse + execute one request body, producing an ok-prefixed (`STATUS_OK`) response payload.
///
/// # Errors
/// Malformed frame, a poisoned store lock, or a backend failure.
fn apply<B: BlobStore>(body: &[u8], store: &Mutex<B>) -> io::Result<Vec<u8>> {
    let mut reader = Reader::new(body);
    let tag = reader.u8()?;
    match tag {
        OP_PUT => {
            let key_len = usize_of(reader.u32()?);
            let key = reader.take_str(key_len)?.to_owned();
            let value = reader.rest().to_vec();
            lock(store)?.put(&key, &value)?;
            Ok(vec![STATUS_OK])
        }
        OP_GET => {
            let key = reader.rest_str()?.to_owned();
            let value = lock(store)?.get(&key)?;
            let mut out = vec![STATUS_OK];
            match value {
                Some(bytes) => {
                    out.push(1);
                    out.extend_from_slice(&bytes);
                }
                None => out.push(0),
            }
            Ok(out)
        }
        OP_LIST => {
            let prefix = reader.rest_str()?.to_owned();
            let keys = lock(store)?.list(&prefix)?;
            let mut out = vec![STATUS_OK];
            out.extend_from_slice(&len_u32(keys.len())?.to_le_bytes());
            for k in keys {
                out.extend_from_slice(&len_u32(k.len())?.to_le_bytes());
                out.extend_from_slice(k.as_bytes());
            }
            Ok(out)
        }
        OP_DELETE => {
            let key = reader.rest_str()?.to_owned();
            let existed = lock(store)?.delete(&key)?;
            Ok(vec![STATUS_OK, u8::from(existed)])
        }
        other => Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("unknown op tag {other}"),
        )),
    }
}

/// Lock `store`, mapping poisoning to an `io::Error` (no `unwrap`).
///
/// # Errors
/// If the mutex is poisoned by a panicking handler.
fn lock<B: BlobStore>(store: &Mutex<B>) -> io::Result<std::sync::MutexGuard<'_, B>> {
    store
        .lock()
        .map_err(|_| io::Error::other("store lock poisoned"))
}

/// Write `body` as a length-prefixed frame and flush.
///
/// # Errors
/// If the body exceeds `u32::MAX`, or on any write/flush failure.
fn write_frame(stream: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let len = len_u32(body.len())?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Read one length-prefixed frame, or `None` on a clean end-of-stream before any byte of the next frame.
///
/// # Errors
/// On a truncated frame (partial length or body) or any underlying read failure.
fn read_frame(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = usize_of(u32::from_le_bytes(len_buf));
    // WP4 audit CRITICAL C1 fix: reject an over-large advertised length BEFORE allocating, so a hostile 4-byte
    // prefix can't make us commit gigabytes of zeroed RAM (an OOM/DoS with no body bytes sent).
    if len > MAX_FRAME {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "netblob frame exceeds the maximum size",
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Largest accepted frame body (one blob op + a generous blob value). Caps `read_frame`'s pre-allocation so a
/// lying length prefix cannot exhaust memory.
const MAX_FRAME: usize = 256 * 1024 * 1024;

/// Convert a length to `u32`, erroring if it does not fit a frame field.
///
/// # Errors
/// If `n` exceeds `u32::MAX`.
fn len_u32(n: usize) -> io::Result<u32> {
    u32::try_from(n).map_err(|_| io::Error::new(ErrorKind::InvalidInput, "frame field exceeds u32"))
}

/// Widen a wire `u32` length to `usize` (lossless on every supported target).
fn usize_of(n: u32) -> usize {
    n as usize
}

/// Check a response frame's status byte, returning the ok payload (everything after the status byte).
///
/// # Errors
/// On an empty frame or a `STATUS_ERR` frame (whose message is surfaced).
fn ok_payload(resp: &[u8]) -> io::Result<&[u8]> {
    match resp.split_first() {
        Some((&STATUS_OK, payload)) => Ok(payload),
        Some((&STATUS_ERR, msg)) => {
            Err(io::Error::other(String::from_utf8_lossy(msg).into_owned()))
        }
        _ => Err(io::Error::new(
            ErrorKind::InvalidData,
            "empty or malformed response frame",
        )),
    }
}

/// A bounds-checked forward reader over a request/response body.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Wrap `buf`.
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Take the next `n` bytes, advancing the cursor.
    ///
    /// # Errors
    /// If fewer than `n` bytes remain.
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "frame body truncated",
            ));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// Take the next `n` bytes as UTF-8.
    ///
    /// # Errors
    /// If too few bytes remain or they are not valid UTF-8.
    fn take_str(&mut self, n: usize) -> io::Result<&'a str> {
        let raw = self.take(n)?;
        std::str::from_utf8(raw)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "non-utf8 string field"))
    }

    /// Take one byte.
    ///
    /// # Errors
    /// If the buffer is empty.
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Take a little-endian `u32`.
    ///
    /// # Errors
    /// If fewer than four bytes remain.
    fn u32(&mut self) -> io::Result<u32> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "short u32 field"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Consume the remaining bytes.
    fn rest(self) -> &'a [u8] {
        self.buf
    }

    /// Consume the remaining bytes as UTF-8.
    ///
    /// # Errors
    /// If the remainder is not valid UTF-8.
    fn rest_str(self) -> io::Result<&'a str> {
        std::str::from_utf8(self.buf)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "non-utf8 string field"))
    }
}

#[cfg(test)]
mod tests {
    use super::{serve, NetBlob};
    use datarail_blobstore::{BlobStore, MemBlob};

    #[test]
    fn remote_roundtrip_over_loopback() {
        let addr = serve(MemBlob::new()).unwrap();
        let mut client = NetBlob::new(addr);

        let cases: &[(&str, &[u8])] = &[
            ("flat", b"value-a"),
            ("nested/key/with/slashes", b"value-b"),
            ("empty", b""),
            ("a/1", b"one"),
            ("a/2", b"two"),
            ("b/1", b"three"),
        ];

        // Put then exact get round-trip.
        for (k, v) in cases {
            client.put(k, v).unwrap();
            assert_eq!(client.get(k).unwrap().as_deref(), Some(*v));
        }

        // Overwrite is visible remotely.
        client.put("a/1", b"one-overwritten").unwrap();
        assert_eq!(
            client.get("a/1").unwrap().as_deref(),
            Some(&b"one-overwritten"[..])
        );

        // List by prefix, sorted (MemBlob/BTreeMap order).
        assert_eq!(client.list("a/").unwrap(), vec!["a/1", "a/2"]);
        assert_eq!(
            client.list("nested/").unwrap(),
            vec!["nested/key/with/slashes"]
        );
        assert!(client.list("zzz").unwrap().is_empty());

        // Absent key is None, not an error.
        assert_eq!(client.get("missing").unwrap(), None);

        // Delete semantics, then confirm get -> None.
        assert!(client.delete("flat").unwrap());
        assert!(!client.delete("flat").unwrap());
        assert_eq!(client.get("flat").unwrap(), None);
    }

    #[test]
    fn concurrent_clients_share_one_store() {
        let addr = serve(MemBlob::new()).unwrap();
        let mut writer = NetBlob::new(addr);
        writer.put("shared", b"written-by-one").unwrap();

        // A second, independent client connection sees the same store.
        let reader = NetBlob::new(addr);
        assert_eq!(
            reader.get("shared").unwrap().as_deref(),
            Some(&b"written-by-one"[..])
        );
    }
}
