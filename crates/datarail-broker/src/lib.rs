//! `datarail-broker` — FROZEN API (frozen by the lead); WP4 implements the bodies + gates.
//! A minimal length-prefixed request/response protocol exposing a [`datarail_topic`] over a byte stream
//! (TCP/loopback), with durable group offsets via [`datarail_offsets`].
#![forbid(unsafe_code)]

/// A client request over the wire (WP4: define the on-wire encoding; this enum is the frozen shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Append a record.
    Produce {
        /// Routing/order key.
        key: Vec<u8>,
        /// Payload bytes.
        payload: Vec<u8>,
    },
    /// Dispatch the next record for a group member.
    Poll {
        /// Consumer group name.
        group: String,
    },
    /// Durably commit a group's offset.
    Commit {
        /// Consumer group name.
        group: String,
        /// Offset to commit.
        offset: u64,
    },
}

/// A server response (WP4: frozen shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Produce accepted at this offset.
    Produced(u64),
    /// A dispatched record, or `None` at the tail.
    Record(Option<(u64, Vec<u8>, Vec<u8>)>),
    /// Commit acknowledged.
    Committed,
    /// An error string.
    Err(String),
}

use std::collections::BTreeMap;

use datarail_offsets::OffsetStore;
use datarail_topic::{Group, Topic};

// ---- Wire framing -----------------------------------------------------------
//
// Every frame is `[u32 len][body][u32 crc]`, all little-endian, matching the codebase style
// (see `datarail-replaylog`): `len` is the body length and `crc` is the IEEE CRC-32 over `len ‖ body`.
// The body is a single tag byte followed by the variant's fields. Variable-length byte runs are written
// length-prefixed (`[u32 len][bytes]`); a single trailing run (a payload) consumes the rest of the body.

// Request body tags.
const TAG_PRODUCE: u8 = 0x01;
const TAG_POLL: u8 = 0x02;
const TAG_COMMIT: u8 = 0x03;

// Response body tags.
const TAG_PRODUCED: u8 = 0x10;
const TAG_RECORD_SOME: u8 = 0x11;
const TAG_RECORD_NONE: u8 = 0x12;
const TAG_COMMITTED: u8 = 0x13;
const TAG_ERR: u8 = 0x14;

/// IEEE CRC-32 (table-free) over the concatenation of `parts` — the same polynomial the durable log uses.
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

/// Wrap a body in the `[u32 len][body][u32 crc]` frame.
fn frame(body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let len_bytes = len.to_le_bytes();
    let crc = crc32(&[&len_bytes, body]).to_le_bytes();
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(body);
    out.extend_from_slice(&crc);
    out
}

/// Validate a frame and return its body, or `None` if the length or CRC do not check out.
fn unframe(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 8 {
        return None;
    }
    let len = u32::from_le_bytes(frame.get(0..4)?.try_into().ok()?);
    let body_len = usize::try_from(len).ok()?;
    let crc_start = 4usize.checked_add(body_len)?;
    let frame_end = crc_start.checked_add(4)?;
    if frame.len() != frame_end {
        return None;
    }
    let len_bytes = frame.get(0..4)?;
    let body = frame.get(4..crc_start)?;
    let stored = u32::from_le_bytes(frame.get(crc_start..frame_end)?.try_into().ok()?);
    if stored != crc32(&[len_bytes, body]) {
        return None;
    }
    Some(body)
}

/// Append a length-prefixed (`[u32 len][bytes]`) byte run to `buf`.
fn put_slice(buf: &mut Vec<u8>, s: &[u8]) {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(s);
}

/// A bounds-checked, never-panicking cursor over a frame body.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_u32(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        let v = u32::from_le_bytes(self.buf.get(self.pos..end)?.try_into().ok()?);
        self.pos = end;
        Some(v)
    }

    fn read_u64(&mut self) -> Option<u64> {
        let end = self.pos.checked_add(8)?;
        let v = u64::from_le_bytes(self.buf.get(self.pos..end)?.try_into().ok()?);
        self.pos = end;
        Some(v)
    }

    fn read_slice(&mut self) -> Option<Vec<u8>> {
        let len = usize::try_from(self.read_u32()?).ok()?;
        let end = self.pos.checked_add(len)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s.to_vec())
    }

    fn read_string(&mut self) -> Option<String> {
        String::from_utf8(self.read_slice()?).ok()
    }

    fn read_rest(&mut self) -> Vec<u8> {
        let rest = self.buf.get(self.pos..).unwrap_or(&[]).to_vec();
        self.pos = self.buf.len();
        rest
    }

    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Encode a [`Request`] to wire bytes (length-prefixed, CRC-tailed).
#[must_use]
pub fn encode_request(req: &Request) -> Vec<u8> {
    let mut body = Vec::new();
    match req {
        Request::Produce { key, payload } => {
            body.push(TAG_PRODUCE);
            put_slice(&mut body, key);
            body.extend_from_slice(payload);
        }
        Request::Poll { group } => {
            body.push(TAG_POLL);
            put_slice(&mut body, group.as_bytes());
        }
        Request::Commit { group, offset } => {
            body.push(TAG_COMMIT);
            put_slice(&mut body, group.as_bytes());
            body.extend_from_slice(&offset.to_le_bytes());
        }
    }
    frame(&body)
}

/// Decode a [`Request`] from a complete frame; `None` on a malformed frame, bad CRC, or trailing bytes.
#[must_use]
pub fn decode_request(frame: &[u8]) -> Option<Request> {
    let body = unframe(frame)?;
    let mut r = Reader::new(body);
    let req = match r.read_u8()? {
        TAG_PRODUCE => {
            let key = r.read_slice()?;
            let payload = r.read_rest();
            Request::Produce { key, payload }
        }
        TAG_POLL => {
            let group = r.read_string()?;
            if !r.done() {
                return None;
            }
            Request::Poll { group }
        }
        TAG_COMMIT => {
            let group = r.read_string()?;
            let offset = r.read_u64()?;
            if !r.done() {
                return None;
            }
            Request::Commit { group, offset }
        }
        _ => return None,
    };
    Some(req)
}

/// Encode a [`Response`] to wire bytes (length-prefixed, CRC-tailed).
#[must_use]
pub fn encode_response(resp: &Response) -> Vec<u8> {
    let mut body = Vec::new();
    match resp {
        Response::Produced(offset) => {
            body.push(TAG_PRODUCED);
            body.extend_from_slice(&offset.to_le_bytes());
        }
        Response::Record(Some((offset, key, payload))) => {
            body.push(TAG_RECORD_SOME);
            body.extend_from_slice(&offset.to_le_bytes());
            put_slice(&mut body, key);
            body.extend_from_slice(payload);
        }
        Response::Record(None) => body.push(TAG_RECORD_NONE),
        Response::Committed => body.push(TAG_COMMITTED),
        Response::Err(msg) => {
            body.push(TAG_ERR);
            put_slice(&mut body, msg.as_bytes());
        }
    }
    frame(&body)
}

/// Decode a [`Response`] from a complete frame; `None` on a malformed frame, bad CRC, or trailing bytes.
#[must_use]
pub fn decode_response(frame: &[u8]) -> Option<Response> {
    let body = unframe(frame)?;
    let mut r = Reader::new(body);
    let resp = match r.read_u8()? {
        TAG_PRODUCED => {
            let offset = r.read_u64()?;
            if !r.done() {
                return None;
            }
            Response::Produced(offset)
        }
        TAG_RECORD_SOME => {
            let offset = r.read_u64()?;
            let key = r.read_slice()?;
            let payload = r.read_rest();
            Response::Record(Some((offset, key, payload)))
        }
        TAG_RECORD_NONE => {
            if !r.done() {
                return None;
            }
            Response::Record(None)
        }
        TAG_COMMITTED => {
            if !r.done() {
                return None;
            }
            Response::Committed
        }
        TAG_ERR => {
            let msg = r.read_string()?;
            if !r.done() {
                return None;
            }
            Response::Err(msg)
        }
        _ => return None,
    };
    Some(resp)
}

/// A minimal in-process broker: a durable [`Topic`] plus an [`OffsetStore`] and one [`Group`] per consumer
/// group name. [`Server::handle`] turns a decoded [`Request`] into a [`Response`]; wiring it to a `TcpStream`
/// accept-loop (decode a frame, `handle`, encode the reply) is the thin remaining layer.
pub struct Server<O: OffsetStore> {
    topic: Topic,
    offsets: O,
    groups: BTreeMap<String, Group>,
}

impl<O: OffsetStore> Server<O> {
    /// Build a server over an open `topic` and an offset store.
    #[must_use]
    pub fn new(topic: Topic, offsets: O) -> Self {
        Self {
            topic,
            offsets,
            groups: BTreeMap::new(),
        }
    }

    /// Borrow the injected offset store (e.g. to read back a committed offset).
    #[must_use]
    pub fn offsets(&self) -> &O {
        &self.offsets
    }

    /// Apply one request and produce its response. Internal errors are mapped to [`Response::Err`].
    ///
    /// - `Produce` appends to the topic and replies [`Response::Produced`] with the durable offset.
    /// - `Poll` dispatches the next record for the named group (creating a default group on first use),
    ///   replying [`Response::Record`] (`Some` with the record, or `None` at the tail).
    /// - `Commit` durably records the group's offset and replies [`Response::Committed`].
    pub fn handle(&mut self, req: Request) -> Response {
        match req {
            Request::Produce { key, payload } => match self.topic.produce(&key, &payload) {
                // DURABILITY-BEFORE-ACK (audit CRITICAL #1/#2): fsync the topic before acking. Otherwise an
                // acked record lives only in the page cache and a power loss silently loses it — and, worse, the
                // fsync'd committed offset could then outlive the un-synced record and wedge the consumer group.
                // (A group-commit batching the fsync across concurrent produces is the future throughput win.)
                Ok(offset) => match self.topic.sync() {
                    Ok(()) => Response::Produced(offset),
                    Err(e) => Response::Err(e.to_string()),
                },
                Err(e) => Response::Err(e.to_string()),
            },
            Request::Poll { group } => {
                // RESUME from the durable committed offset on first use of a group (restart-safe): after a broker
                // restart, a group resumes where it last committed, not from offset 0.
                if !self.groups.contains_key(&group) {
                    let start = self.offsets.fetch(&group).unwrap_or(0);
                    let mut g = Group::new(&[0]);
                    g.seek(start);
                    self.groups.insert(group.clone(), g);
                }
                let Some(g) = self.groups.get_mut(&group) else {
                    return Response::Err("group state vanished".to_owned());
                };
                match self.topic.dispatch_next(g) {
                    // WP2 audit CRITICAL fix: the offset returned is the group's RESUME point — the cursor AFTER
                    // this record (`g.position()`), i.e. the value to `Commit` once this record is processed.
                    // Committing it and resuming `seek`s to the NEXT record, so a restart never re-delivers the
                    // last record (the prior code returned the record's own start offset → guaranteed dup on
                    // every restart).
                    Ok(Some(d)) => Response::Record(Some((g.position(), d.key, d.payload))),
                    Ok(None) => Response::Record(None),
                    Err(e) => Response::Err(e.to_string()),
                }
            }
            Request::Commit { group, offset } => {
                // Reject a commit past the durable topic tail (audit LOW #7): otherwise a buggy/hostile client
                // can persist an offset that, on resume, seeks past the end and wedges the group forever.
                if offset > self.topic.end_offset() {
                    return Response::Err("commit offset is past the topic tail".to_owned());
                }
                match self.offsets.commit(&group, offset) {
                    Ok(()) => Response::Committed,
                    Err(e) => Response::Err(e.to_string()),
                }
            }
        }
    }
}

// ---- TCP transport ----------------------------------------------------------
//
// The wire format above is reused verbatim: every exchange is one request frame in, one response frame
// out, over a plain `TcpStream`. Frames are read robustly (4-byte length, then the body and CRC tail),
// so partial reads on the socket are handled by `read_exact`.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};

/// A dispatched record as seen by a client: `(offset, key, payload)`.
pub type ClientRecord = (u64, Vec<u8>, Vec<u8>);

/// Upper bound on a single frame body, guarding the read path against a hostile/garbled length prefix.
const MAX_FRAME_BODY: usize = 1 << 26; // 64 MiB

/// Read one complete `[u32 len][body][u32 crc]` frame from `stream`.
///
/// Returns `Ok(None)` on a clean end-of-stream before any byte of a frame is read, and `Ok(Some(frame))`
/// with the full reconstructed frame bytes otherwise. Partial reads are absorbed by `read_exact`.
///
/// # Errors
/// [`io::Error`] on a socket failure, on a truncated frame (EOF mid-frame), or when the advertised body
/// length exceeds [`MAX_FRAME_BODY`].
fn read_frame(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    match stream.read(&mut len_bytes[..1]) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    stream.read_exact(&mut len_bytes[1..])?;
    let body_len = usize::try_from(u32::from_le_bytes(len_bytes)).unwrap_or(usize::MAX);
    if body_len > MAX_FRAME_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame body length too large",
        ));
    }
    let mut frame = Vec::with_capacity(8 + body_len);
    frame.extend_from_slice(&len_bytes);
    frame.resize(8 + body_len, 0);
    stream.read_exact(&mut frame[4..])?;
    Ok(Some(frame))
}

/// Serve a [`Server`] over TCP at `addr`, returning the actually-bound [`SocketAddr`].
///
/// Binds a [`TcpListener`], then spawns a background thread running the accept loop. Each accepted
/// connection is handled on its own thread: request frames are decoded with [`decode_request`], applied
/// via [`Server::handle`] under a shared lock, and the [`Response`] is written back as a frame. The
/// server runs until the process exits or the listener is dropped; bind `127.0.0.1:0` to get an
/// OS-assigned port from the returned address.
///
/// # Errors
/// [`io::Error`] if the address cannot be resolved or the listener cannot bind.
pub fn serve<O>(server: Server<O>, addr: impl ToSocketAddrs) -> io::Result<SocketAddr>
where
    O: OffsetStore + Send + 'static,
{
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    let shared = Arc::new(Mutex::new(server));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let server = Arc::clone(&shared);
            std::thread::spawn(move || {
                let _ = serve_conn(&server, stream);
            });
        }
    });
    Ok(local)
}

/// Drive one connection to completion: read frames, handle each, write the reply frame.
///
/// # Errors
/// [`io::Error`] on a socket failure. A malformed request frame ends the connection cleanly.
fn serve_conn<O: OffsetStore>(server: &Mutex<Server<O>>, mut stream: TcpStream) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut stream)? {
        let Some(req) = decode_request(&frame) else {
            break;
        };
        let resp = match server.lock() {
            Ok(mut guard) => guard.handle(req),
            Err(_) => Response::Err("server lock poisoned".to_owned()),
        };
        stream.write_all(&encode_response(&resp))?;
        stream.flush()?;
    }
    Ok(())
}

/// A TCP client for a broker served by [`serve`]: each call sends one request frame and reads one
/// response frame back over the owned [`TcpStream`].
pub struct Client {
    stream: TcpStream,
}

impl Client {
    /// Connect to a broker at `addr`.
    ///
    /// # Errors
    /// [`io::Error`] if the address cannot be resolved or the connection fails.
    pub fn connect(addr: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self {
            stream: TcpStream::connect(addr)?,
        })
    }

    /// Send one request and read its response, validating the frame round-trip.
    ///
    /// # Errors
    /// [`io::Error`] on a socket failure or if the peer closes the stream before replying, and
    /// [`io::ErrorKind::InvalidData`] if the reply frame is malformed.
    fn round_trip(&mut self, req: &Request) -> io::Result<Response> {
        self.stream.write_all(&encode_request(req))?;
        self.stream.flush()?;
        let frame = read_frame(&mut self.stream)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no response frame"))?;
        decode_response(&frame)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed response frame"))
    }

    /// Produce a record, returning its durable offset.
    ///
    /// # Errors
    /// [`io::Error`] on a transport failure or if the server replies with an error.
    pub fn produce(&mut self, key: &[u8], payload: &[u8]) -> io::Result<u64> {
        match self.round_trip(&Request::Produce {
            key: key.to_vec(),
            payload: payload.to_vec(),
        })? {
            Response::Produced(offset) => Ok(offset),
            Response::Err(msg) => Err(io::Error::other(msg)),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected reply: {other:?}"),
            )),
        }
    }

    /// Poll the next record for `group`, or `None` at the tail.
    ///
    /// # Errors
    /// [`io::Error`] on a transport failure or if the server replies with an error.
    pub fn poll(&mut self, group: &str) -> io::Result<Option<ClientRecord>> {
        match self.round_trip(&Request::Poll {
            group: group.to_owned(),
        })? {
            Response::Record(rec) => Ok(rec),
            Response::Err(msg) => Err(io::Error::other(msg)),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected reply: {other:?}"),
            )),
        }
    }

    /// Durably commit `offset` for `group`.
    ///
    /// # Errors
    /// [`io::Error`] on a transport failure or if the server replies with an error.
    pub fn commit(&mut self, group: &str, offset: u64) -> io::Result<()> {
        match self.round_trip(&Request::Commit {
            group: group.to_owned(),
            offset,
        })? {
            Response::Committed => Ok(()),
            Response::Err(msg) => Err(io::Error::other(msg)),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected reply: {other:?}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_request, decode_response, encode_request, encode_response, serve, Client, Request,
        Response, Server,
    };
    use datarail_offsets::{FileOffsets, MemOffsets, OffsetStore};
    use datarail_topic::Topic;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("datarail-broker-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Gate 1: every `Request` variant survives encode -> decode exactly.
    #[test]
    fn request_round_trips_all_variants() {
        let cases = [
            Request::Produce {
                key: b"k".to_vec(),
                payload: b"hello world".to_vec(),
            },
            Request::Produce {
                key: Vec::new(),
                payload: Vec::new(),
            },
            Request::Poll {
                group: "g1".to_owned(),
            },
            Request::Poll {
                group: String::new(),
            },
            Request::Commit {
                group: "orders".to_owned(),
                offset: 0,
            },
            Request::Commit {
                group: "orders".to_owned(),
                offset: u64::MAX,
            },
        ];
        for c in &cases {
            let bytes = encode_request(c);
            let back = decode_request(&bytes).expect("decode request");
            assert_eq!(&back, c, "request did not round-trip: {c:?}");
        }
    }

    /// Gate 1: every `Response` variant survives encode -> decode exactly.
    #[test]
    fn response_round_trips_all_variants() {
        let cases = [
            Response::Produced(0),
            Response::Produced(u64::MAX),
            Response::Record(Some((7, b"key".to_vec(), b"payload".to_vec()))),
            Response::Record(Some((0, Vec::new(), Vec::new()))),
            Response::Record(None),
            Response::Committed,
            Response::Err("boom".to_owned()),
            Response::Err(String::new()),
        ];
        for c in &cases {
            let bytes = encode_response(c);
            let back = decode_response(&bytes).expect("decode response");
            assert_eq!(&back, c, "response did not round-trip: {c:?}");
        }
    }

    /// A bit-flip in the frame must fail the CRC and decode to `None`.
    #[test]
    fn corrupt_frame_rejected() {
        let mut bytes = encode_request(&Request::Poll {
            group: "g".to_owned(),
        });
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(
            decode_request(&bytes).is_none(),
            "corrupt frame must not decode"
        );
        assert!(decode_request(&[]).is_none(), "empty input must not decode");
    }

    /// Gates 2 + 3: produce/produce/poll/poll/commit through `Server`, then read the offset back from the store.
    #[test]
    fn server_produce_poll_commit_sequence() {
        let dir = tmpdir("seq");
        let topic = Topic::open(&dir, 1 << 16).expect("open topic");
        let mut server = Server::new(topic, MemOffsets::new());

        // Two produces — offsets must be assigned and increasing.
        let o0 = match server.handle(Request::Produce {
            key: b"a".to_vec(),
            payload: b"v0".to_vec(),
        }) {
            Response::Produced(o) => o,
            other => panic!("expected Produced, got {other:?}"),
        };
        let o1 = match server.handle(Request::Produce {
            key: b"b".to_vec(),
            payload: b"v1".to_vec(),
        }) {
            Response::Produced(o) => o,
            other => panic!("expected Produced, got {other:?}"),
        };
        assert!(o1 > o0, "produced offsets must increase ({o0} -> {o1})");

        // Two polls — records come back in produce order (key+payload); the returned offset is the RESUME point
        // (the cursor AFTER the record), so resume-after-record-0 equals the START of record 1 (o1).
        let resume0 = match server.handle(Request::Poll {
            group: "g".to_owned(),
        }) {
            Response::Record(Some((off, k, p))) => {
                assert_eq!((k, p), (b"a".to_vec(), b"v0".to_vec()));
                off
            }
            other => panic!("expected a record, got {other:?}"),
        };
        assert_eq!(
            resume0, o1,
            "resume point after record 0 must be the start of record 1"
        );
        let resume1 = match server.handle(Request::Poll {
            group: "g".to_owned(),
        }) {
            Response::Record(Some((off, k, p))) => {
                assert_eq!((k, p), (b"b".to_vec(), b"v1".to_vec()));
                off
            }
            other => panic!("expected a record, got {other:?}"),
        };
        assert!(resume1 > resume0, "resume offsets must increase");

        // Tail — no more records.
        assert_eq!(
            server.handle(Request::Poll {
                group: "g".to_owned()
            }),
            Response::Record(None)
        );

        // Commit the last resume point; it is durable in the injected store.
        assert_eq!(
            server.handle(Request::Commit {
                group: "g".to_owned(),
                offset: resume1
            }),
            Response::Committed
        );
        assert_eq!(
            server.offsets().fetch("g"),
            Some(resume1),
            "committed offset not retrievable"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Gate (WP1): full produce/poll/commit cycle over a REAL TCP socket on `127.0.0.1:0`.
    #[test]
    fn end_to_end_over_tcp_socket() {
        let dir = tmpdir("tcp");
        let topic = Topic::open(&dir, 1 << 16).expect("open topic");
        let server = Server::new(topic, MemOffsets::new());
        let addr = serve(server, "127.0.0.1:0").expect("serve");

        let mut client = Client::connect(addr).expect("connect");

        // Produce 100 records over the wire; offsets must be assigned and strictly increasing.
        let mut produced = Vec::with_capacity(100);
        for i in 0u32..100 {
            let key = i.to_le_bytes().to_vec();
            let payload = format!("payload-{i}").into_bytes();
            let offset = client.produce(&key, &payload).expect("produce");
            if let Some(prev) = produced.last() {
                let (po, _, _): &(u64, Vec<u8>, Vec<u8>) = prev;
                assert!(offset > *po, "offsets must increase ({po} -> {offset})");
            }
            produced.push((offset, key, payload));
        }

        // Poll them all back for group "g" — same order, same key + payload (the returned offset is the resume
        // point, not the record's own start, so we match on key/payload).
        for expected in &produced {
            let got = client.poll("g").expect("poll").expect("record present");
            assert_eq!(
                (&got.1, &got.2),
                (&expected.1, &expected.2),
                "polled record key/payload mismatch"
            );
        }
        // Tail: nothing left.
        assert_eq!(client.poll("g").expect("poll tail"), None);

        // Commit the last offset; the ack returns Ok and the offset is durable in the store.
        let last_offset = produced.last().expect("at least one record").0;
        client.commit("g", last_offset).expect("commit acked");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WP2 audit CRITICAL regression: commit the RESUME offset, RESTART (a fresh `Server` over the same durable
    /// topic + offset store), and the group resumes at the next record — the last consumed record is NOT
    /// re-delivered (the prior code re-delivered it on every restart).
    #[test]
    fn restart_resumes_without_redelivering_the_last_record() {
        const N: usize = 100;
        const HALF: usize = 50;
        let tdir = tmpdir("resume-topic");
        let odir = tmpdir("resume-offsets");

        // Phase 1: produce N, consume HALF, commit the HALF-th poll's RESUME offset.
        let mut resume = 0u64;
        {
            let topic = Topic::open(&tdir, 1 << 16).expect("topic");
            let mut server = Server::new(topic, FileOffsets::open(&odir).expect("offsets"));
            for i in 0..N {
                let r = server.handle(Request::Produce {
                    key: Vec::new(),
                    payload: format!("v{i}").into_bytes(),
                });
                assert!(matches!(r, Response::Produced(_)), "produce failed: {r:?}");
            }
            for _ in 0..HALF {
                resume = match server.handle(Request::Poll {
                    group: "g".to_owned(),
                }) {
                    Response::Record(Some((off, _, _))) => off,
                    other => panic!("expected a record, got {other:?}"),
                };
            }
            assert_eq!(
                server.handle(Request::Commit {
                    group: "g".to_owned(),
                    offset: resume
                }),
                Response::Committed
            );
        }

        // Phase 2: restart over the SAME durable state; resume must start exactly at record HALF.
        let topic2 = Topic::open(&tdir, 1 << 16).expect("reopen topic");
        let mut server2 = Server::new(topic2, FileOffsets::open(&odir).expect("reopen offsets"));
        let mut got = Vec::new();
        while let Response::Record(Some((_, _, payload))) = server2.handle(Request::Poll {
            group: "g".to_owned(),
        }) {
            got.push(payload);
        }
        assert_eq!(
            got.len(),
            N - HALF,
            "wrong count on resume — re-delivery or loss"
        );
        assert_eq!(
            got[0],
            format!("v{HALF}").into_bytes(),
            "first resumed record must be v{HALF}, not a re-delivery"
        );

        let _ = std::fs::remove_dir_all(&tdir);
        let _ = std::fs::remove_dir_all(&odir);
    }
}
