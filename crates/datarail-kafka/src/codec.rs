//! Apache Kafka wire-protocol primitive codec — the broker-side reader, writer and
//! request/response headers.
//!
//! Kafka encodes integers big-endian. Two families of variable-length types exist: the
//! classic forms and the KIP-482 "flexible/compact" forms used by newer api versions; both
//! are implemented here. Every short read is reported as an [`std::io::Error`] — the reader
//! never panics, and any length pulled from the buffer is validated against the remaining
//! bytes before a single byte is allocated or taken.

use std::io;

/// A defensive cursor over a borrowed byte slice.
///
/// All reads are bounds-checked; a short read yields an [`io::ErrorKind::UnexpectedEof`] and
/// malformed data yields an [`io::ErrorKind::InvalidData`], never a panic.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader positioned at the start of `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn invalid(msg: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, msg)
    }

    fn eof(msg: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::UnexpectedEof, msg)
    }

    /// Borrows the next `n` bytes, advancing the cursor.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::UnexpectedEof`] if fewer than `n` bytes remain. The length is
    /// validated against the remaining buffer before anything is taken.
    pub fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Self::eof("length overflow"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| Self::eof("short read"))?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let slice = self.take(N)?;
        <[u8; N]>::try_from(slice).map_err(|_| Self::eof("short read"))
    }

    fn read_byte(&mut self) -> io::Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// Returns the bytes not yet consumed without advancing the cursor.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// The current read cursor (bytes consumed so far). Used to bound a length-counted region — e.g. a compressed
    /// records blob whose size is `batch_end - position()` (`KAFKA-COMPRESSION-DESIGN.md`).
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bound an array element count read from the wire to the number of elements that could PHYSICALLY remain
    /// (`remaining_bytes / min_entry_bytes`), and never negative. A lying length prefix therefore can neither
    /// drive a giant `Vec::with_capacity` (which could even abort on allocation failure) nor an over-long loop —
    /// the materialized count is bounded by the frame size, not by the attacker's number. `min_entry_bytes` MUST
    /// be a true lower bound on the bytes each loop iteration consumes before pushing (e.g. 4 for an `int32`
    /// partition, 6 for a `string`+`int32` topic), so a valid request is never under-counted.
    #[must_use]
    pub fn bounded_count(&self, count: i32, min_entry_bytes: usize) -> usize {
        let by_bytes = self.remaining().len() / min_entry_bytes.max(1);
        usize::try_from(count.max(0)).unwrap_or(0).min(by_bytes)
    }

    /// Returns `true` when no bytes remain to be read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Reads a signed 8-bit integer.
    ///
    /// # Errors
    /// Returns an error if no byte remains.
    pub fn int8(&mut self) -> io::Result<i8> {
        Ok(i8::from_be_bytes(self.array::<1>()?))
    }

    /// Reads a big-endian signed 16-bit integer.
    ///
    /// # Errors
    /// Returns an error if fewer than two bytes remain.
    pub fn int16(&mut self) -> io::Result<i16> {
        Ok(i16::from_be_bytes(self.array::<2>()?))
    }

    /// Reads a big-endian signed 32-bit integer.
    ///
    /// # Errors
    /// Returns an error if fewer than four bytes remain.
    pub fn int32(&mut self) -> io::Result<i32> {
        Ok(i32::from_be_bytes(self.array::<4>()?))
    }

    /// Reads a big-endian signed 64-bit integer.
    ///
    /// # Errors
    /// Returns an error if fewer than eight bytes remain.
    pub fn int64(&mut self) -> io::Result<i64> {
        Ok(i64::from_be_bytes(self.array::<8>()?))
    }

    /// Reads a big-endian unsigned 32-bit integer.
    ///
    /// # Errors
    /// Returns an error if fewer than four bytes remain.
    pub fn uint32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn unsigned_varint_u64(&mut self, max_bytes: u32) -> io::Result<u64> {
        let mut result: u64 = 0;
        for i in 0..max_bytes {
            let byte = self.read_byte()?;
            result |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(Self::invalid("variable-length integer is overlong"))
    }

    /// Reads an unsigned `LEB128` variable-length integer (max five bytes).
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::InvalidData`] if the encoding is overlong (a sixth
    /// continuation byte) or overflows a [`u32`], or [`io::ErrorKind::UnexpectedEof`] on a
    /// short read.
    pub fn unsigned_varint(&mut self) -> io::Result<u32> {
        let value = self.unsigned_varint_u64(5)?;
        u32::try_from(value).map_err(|_| Self::invalid("unsigned varint overflows u32"))
    }

    /// Reads a zig-zag encoded signed 32-bit variable-length integer.
    ///
    /// # Errors
    /// Returns an error if the underlying unsigned varint is malformed or truncated.
    pub fn varint(&mut self) -> io::Result<i32> {
        let v = self.unsigned_varint()?;
        let zz = (v >> 1) ^ 0u32.wrapping_sub(v & 1);
        Ok(i32::from_ne_bytes(zz.to_ne_bytes()))
    }

    /// Reads a zig-zag encoded signed 64-bit variable-length integer (max ten bytes).
    ///
    /// # Errors
    /// Returns an error if the encoding is overlong or truncated.
    pub fn varlong(&mut self) -> io::Result<i64> {
        let v = self.unsigned_varint_u64(10)?;
        let zz = (v >> 1) ^ 0u64.wrapping_sub(v & 1);
        Ok(i64::from_ne_bytes(zz.to_ne_bytes()))
    }

    fn read_utf8(&mut self, len: usize) -> io::Result<String> {
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Self::invalid("invalid utf-8 string"))
    }

    /// Reads a classic non-null string (`INT16` length then that many `utf-8` bytes).
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::InvalidData`] if the length is negative (an unexpected null
    /// string) or the bytes are not valid `utf-8`, or on a short read.
    pub fn string(&mut self) -> io::Result<String> {
        let n = self.int16()?;
        let len = usize::try_from(n).map_err(|_| Self::invalid("unexpected null string"))?;
        self.read_utf8(len)
    }

    /// Reads a classic nullable string; an `INT16` length of `-1` decodes to `None`.
    ///
    /// # Errors
    /// Returns an error on a length below `-1`, invalid `utf-8`, or a short read.
    pub fn nullable_string(&mut self) -> io::Result<Option<String>> {
        let n = self.int16()?;
        if n == -1 {
            return Ok(None);
        }
        let len = usize::try_from(n).map_err(|_| Self::invalid("invalid string length"))?;
        Ok(Some(self.read_utf8(len)?))
    }

    fn compact_len(&mut self) -> io::Result<Option<usize>> {
        let v = self.unsigned_varint()?;
        if v == 0 {
            return Ok(None);
        }
        let len = usize::try_from(v - 1).map_err(|_| Self::invalid("compact length overflow"))?;
        Ok(Some(len))
    }

    /// Reads a compact (KIP-482) non-null string; the length is an unsigned varint of `len + 1`.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::InvalidData`] if the encoded length is `0` (an unexpected
    /// null string) or the bytes are not valid `utf-8`, or on a short read.
    pub fn compact_string(&mut self) -> io::Result<String> {
        match self.compact_len()? {
            None => Err(Self::invalid("unexpected null compact string")),
            Some(len) => self.read_utf8(len),
        }
    }

    /// Reads a compact nullable string; an encoded length of `0` decodes to `None`.
    ///
    /// # Errors
    /// Returns an error on invalid `utf-8` or a short read.
    pub fn compact_nullable_string(&mut self) -> io::Result<Option<String>> {
        match self.compact_len()? {
            None => Ok(None),
            Some(len) => Ok(Some(self.read_utf8(len)?)),
        }
    }

    /// Reads a classic non-null byte array (`INT32` length then that many bytes).
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::InvalidData`] if the length is negative, or on a short read.
    pub fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.int32()?;
        let len = usize::try_from(n).map_err(|_| Self::invalid("unexpected null bytes"))?;
        Ok(self.take(len)?.to_vec())
    }

    /// Reads a classic nullable byte array; an `INT32` length of `-1` decodes to `None`.
    ///
    /// # Errors
    /// Returns an error on a length below `-1` or a short read.
    pub fn nullable_bytes(&mut self) -> io::Result<Option<Vec<u8>>> {
        let n = self.int32()?;
        if n == -1 {
            return Ok(None);
        }
        let len = usize::try_from(n).map_err(|_| Self::invalid("invalid bytes length"))?;
        Ok(Some(self.take(len)?.to_vec()))
    }

    /// Reads a compact (KIP-482) non-null byte array; the length is `len + 1`.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::InvalidData`] if the encoded length is `0`, or on a short read.
    pub fn compact_bytes(&mut self) -> io::Result<Vec<u8>> {
        match self.compact_len()? {
            None => Err(Self::invalid("unexpected null compact bytes")),
            Some(len) => Ok(self.take(len)?.to_vec()),
        }
    }

    /// Reads a compact nullable byte array; an encoded length of `0` decodes to `None`.
    ///
    /// # Errors
    /// Returns an error on a short read.
    pub fn compact_nullable_bytes(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.compact_len()? {
            None => Ok(None),
            Some(len) => Ok(Some(self.take(len)?.to_vec())),
        }
    }

    /// Skips the tagged-fields section of a flexible-version message.
    ///
    /// Reads an unsigned-varint count, then for each entry an unsigned-varint tag, an
    /// unsigned-varint size, and that many skipped bytes.
    ///
    /// # Errors
    /// Returns an error if any varint is malformed or a declared size runs past the buffer.
    pub fn skip_tagged_fields(&mut self) -> io::Result<()> {
        let count = self.unsigned_varint()?;
        for _ in 0..count {
            let _tag = self.unsigned_varint()?;
            let size = self.unsigned_varint()?;
            let n =
                usize::try_from(size).map_err(|_| Self::invalid("tagged field size overflow"))?;
            self.take(n)?;
        }
        Ok(())
    }
}

/// A growable big-endian Kafka encoder backed by a [`Vec<u8>`].
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Creates an empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes the writer and returns the accumulated bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` when nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Appends raw bytes verbatim.
    pub fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Writes a signed 8-bit integer.
    pub fn int8(&mut self, v: i8) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Writes a big-endian signed 16-bit integer.
    pub fn int16(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Writes a big-endian signed 32-bit integer.
    pub fn int32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Writes a big-endian signed 64-bit integer.
    pub fn int64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Writes a big-endian unsigned 32-bit integer.
    pub fn uint32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Writes an unsigned `LEB128` variable-length integer.
    pub fn unsigned_varint(&mut self, mut v: u32) {
        while v >= 0x80 {
            self.buf.push((v & 0x7f).to_le_bytes()[0] | 0x80);
            v >>= 7;
        }
        self.buf.push(v.to_le_bytes()[0]);
    }

    fn unsigned_varlong(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.buf.push((v & 0x7f).to_le_bytes()[0] | 0x80);
            v >>= 7;
        }
        self.buf.push(v.to_le_bytes()[0]);
    }

    /// Writes a zig-zag encoded signed 32-bit variable-length integer.
    pub fn varint(&mut self, n: i32) {
        let zz = (n << 1) ^ (n >> 31);
        self.unsigned_varint(u32::from_ne_bytes(zz.to_ne_bytes()));
    }

    /// Writes a zig-zag encoded signed 64-bit variable-length integer.
    pub fn varlong(&mut self, n: i64) {
        let zz = (n << 1) ^ (n >> 63);
        self.unsigned_varlong(u64::from_ne_bytes(zz.to_ne_bytes()));
    }

    /// Writes a classic non-null string (`INT16` length then `utf-8` bytes).
    pub fn string(&mut self, s: &str) {
        let n = i16::try_from(s.len()).unwrap_or(i16::MAX);
        self.int16(n);
        self.raw(s.as_bytes());
    }

    /// Writes a classic nullable string; `None` encodes as an `INT16` length of `-1`.
    pub fn nullable_string(&mut self, s: Option<&str>) {
        match s {
            None => self.int16(-1),
            Some(s) => self.string(s),
        }
    }

    /// Writes a compact (KIP-482) non-null string with a `len + 1` unsigned-varint length.
    pub fn compact_string(&mut self, s: &str) {
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        self.unsigned_varint(len.saturating_add(1));
        self.raw(s.as_bytes());
    }

    /// Writes a compact nullable string; `None` encodes as an unsigned-varint `0`.
    pub fn compact_nullable_string(&mut self, s: Option<&str>) {
        match s {
            None => self.unsigned_varint(0),
            Some(s) => self.compact_string(s),
        }
    }

    /// Writes a classic non-null byte array (`INT32` length then bytes).
    pub fn bytes(&mut self, b: &[u8]) {
        let n = i32::try_from(b.len()).unwrap_or(i32::MAX);
        self.int32(n);
        self.raw(b);
    }

    /// Writes a compact (KIP-482) non-null byte array with a `len + 1` unsigned-varint length.
    pub fn compact_bytes(&mut self, b: &[u8]) {
        let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
        self.unsigned_varint(len.saturating_add(1));
        self.raw(b);
    }

    /// Writes an empty tagged-fields section (a single unsigned-varint `0`).
    pub fn empty_tagged_fields(&mut self) {
        self.unsigned_varint(0);
    }

    /// Prefixes `payload` with its big-endian `INT32` length — the Kafka on-the-wire framing.
    #[must_use]
    pub fn frame(payload: &[u8]) -> Vec<u8> {
        let n = i32::try_from(payload.len()).unwrap_or(i32::MAX);
        let mut out = Vec::with_capacity(payload.len().saturating_add(4));
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }
}

/// A parsed Kafka request header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    /// The request api key.
    pub api_key: i16,
    /// The request api version.
    pub api_version: i16,
    /// The client-supplied correlation id echoed back in the response.
    pub correlation_id: i32,
    /// The optional client id (a classic nullable string even in flexible versions).
    pub client_id: Option<String>,
}

impl RequestHeader {
    /// Parses a request header from `reader`.
    ///
    /// The `client_id` is always a classic nullable string, even in flexible versions
    /// (a KIP-482 detail); `flexible` only controls whether a trailing tagged-fields section
    /// is consumed. The caller decides `flexible` from the api key and version.
    ///
    /// # Errors
    /// Returns an error on a short read, an invalid string, or malformed tagged fields.
    pub fn parse(reader: &mut Reader, flexible: bool) -> io::Result<RequestHeader> {
        let api_key = reader.int16()?;
        let api_version = reader.int16()?;
        let correlation_id = reader.int32()?;
        let client_id = reader.nullable_string()?;
        if flexible {
            reader.skip_tagged_fields()?;
        }
        Ok(RequestHeader {
            api_key,
            api_version,
            correlation_id,
            client_id,
        })
    }
}

/// Writes a response header: the `correlation_id`, then for flexible versions an empty
/// tagged-fields section.
pub fn write_response_header(w: &mut Writer, correlation_id: i32, flexible: bool) {
    w.int32(correlation_id);
    if flexible {
        w.empty_tagged_fields();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_varint_known_vectors() {
        for (value, expected) in [
            (0u32, vec![0x00u8]),
            (1, vec![0x01]),
            (300, vec![0xAC, 0x02]),
        ] {
            let mut w = Writer::new();
            w.unsigned_varint(value);
            assert_eq!(w.clone().into_bytes(), expected, "encode {value}");
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.unsigned_varint().unwrap(), value, "decode {value}");
            assert!(r.is_empty());
        }
    }

    #[test]
    fn varint_zigzag_known_vectors() {
        for (value, expected) in [(0i32, 0u32), (-1, 1), (1, 2), (-2, 3)] {
            let mut w = Writer::new();
            w.varint(value);
            let mut probe = Writer::new();
            probe.unsigned_varint(expected);
            assert_eq!(w.clone().into_bytes(), probe.into_bytes(), "encode {value}");
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.varint().unwrap(), value, "decode {value}");
        }
    }

    #[test]
    fn varint_roundtrip_extremes() {
        for v in [i32::MIN, -1_234_567, -1, 0, 1, 987_654, i32::MAX] {
            let mut w = Writer::new();
            w.varint(v);
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.varint().unwrap(), v);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn varlong_roundtrip_extremes() {
        for v in [i64::MIN, -1, 0, 1, 9_000_000_000_000, i64::MAX] {
            let mut w = Writer::new();
            w.varlong(v);
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.varlong().unwrap(), v);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn fixed_int_roundtrips() {
        let mut w = Writer::new();
        w.int8(-5);
        w.int16(-300);
        w.int32(-70000);
        w.int64(-5_000_000_000);
        w.uint32(0xDEAD_BEEF);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.int8().unwrap(), -5);
        assert_eq!(r.int16().unwrap(), -300);
        assert_eq!(r.int32().unwrap(), -70000);
        assert_eq!(r.int64().unwrap(), -5_000_000_000);
        assert_eq!(r.uint32().unwrap(), 0xDEAD_BEEF);
        assert!(r.is_empty());
    }

    #[test]
    fn string_roundtrip() {
        let mut w = Writer::new();
        w.string("hello");
        w.nullable_string(Some("world"));
        w.nullable_string(None);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.string().unwrap(), "hello");
        assert_eq!(r.nullable_string().unwrap(), Some("world".to_string()));
        assert_eq!(r.nullable_string().unwrap(), None);
        assert!(r.is_empty());
    }

    #[test]
    fn compact_string_length_is_len_plus_one() {
        let mut w = Writer::new();
        w.compact_string("abc");
        let bytes = w.into_bytes();
        assert_eq!(bytes[0], 0x04, "compact length must be len + 1");
        assert_eq!(&bytes[1..], b"abc");

        let mut r = Reader::new(&bytes);
        assert_eq!(r.compact_string().unwrap(), "abc");
        assert!(r.is_empty());
    }

    #[test]
    fn compact_string_roundtrip_with_nulls() {
        let mut w = Writer::new();
        w.compact_string("xyz");
        w.compact_nullable_string(Some("q"));
        w.compact_nullable_string(None);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.compact_string().unwrap(), "xyz");
        assert_eq!(r.compact_nullable_string().unwrap(), Some("q".to_string()));
        assert_eq!(r.compact_nullable_string().unwrap(), None);
        assert!(r.is_empty());
    }

    #[test]
    fn compact_string_zero_is_null_error() {
        let bytes = [0x00u8];
        let mut r = Reader::new(&bytes);
        assert_eq!(
            r.compact_string().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn bytes_roundtrip_with_nulls() {
        let mut w = Writer::new();
        w.bytes(&[1, 2, 3]);
        w.compact_bytes(&[9, 8]);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.bytes().unwrap(), vec![1, 2, 3]);
        assert_eq!(r.compact_bytes().unwrap(), vec![9, 8]);
        assert!(r.is_empty());
    }

    #[test]
    fn nullable_bytes_null_roundtrip() {
        // Hand-built: INT32 = -1 → None; then INT32 = 2, two bytes.
        let mut w = Writer::new();
        w.int32(-1);
        w.int32(2);
        w.raw(&[0xAA, 0xBB]);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.nullable_bytes().unwrap(), None);
        assert_eq!(r.nullable_bytes().unwrap(), Some(vec![0xAA, 0xBB]));
        assert!(r.is_empty());
    }

    #[test]
    fn compact_nullable_bytes_roundtrip() {
        let mut w = Writer::new();
        w.unsigned_varint(0); // null
        w.unsigned_varint(3); // len 2 + 1
        w.raw(&[7, 7]);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.compact_nullable_bytes().unwrap(), None);
        assert_eq!(r.compact_nullable_bytes().unwrap(), Some(vec![7, 7]));
        assert!(r.is_empty());
    }

    #[test]
    fn frame_prefixes_int32_length() {
        let payload = [1u8, 2, 3, 4, 5];
        let framed = Writer::frame(&payload);
        assert_eq!(&framed[0..4], &5i32.to_be_bytes());
        assert_eq!(&framed[4..], &payload);
    }

    #[test]
    fn request_header_classic() {
        // api_key=18, api_version=0, correlation_id=7, client_id="kafka-cli"
        let mut w = Writer::new();
        w.int16(18);
        w.int16(0);
        w.int32(7);
        w.nullable_string(Some("kafka-cli"));
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let h = RequestHeader::parse(&mut r, false).unwrap();
        assert_eq!(
            h,
            RequestHeader {
                api_key: 18,
                api_version: 0,
                correlation_id: 7,
                client_id: Some("kafka-cli".to_string()),
            }
        );
        assert!(r.is_empty());
    }

    #[test]
    fn request_header_flexible_with_tagged_fields() {
        // Flexible header: client_id is STILL a classic nullable string, then tagged fields.
        let mut w = Writer::new();
        w.int16(3); // Metadata
        w.int16(12); // a flexible version
        w.int32(42);
        w.nullable_string(Some("app"));
        // tagged fields: count=1, tag=0, size=2, two bytes
        w.unsigned_varint(1);
        w.unsigned_varint(0);
        w.unsigned_varint(2);
        w.raw(&[0xCA, 0xFE]);
        // a trailing marker to prove tagged fields were consumed exactly
        w.int8(99);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let h = RequestHeader::parse(&mut r, true).unwrap();
        assert_eq!(h.api_key, 3);
        assert_eq!(h.api_version, 12);
        assert_eq!(h.correlation_id, 42);
        assert_eq!(h.client_id, Some("app".to_string()));
        assert_eq!(r.int8().unwrap(), 99, "tagged fields must be fully skipped");
        assert!(r.is_empty());
    }

    #[test]
    fn request_header_null_client_id() {
        let mut w = Writer::new();
        w.int16(1);
        w.int16(0);
        w.int32(0);
        w.nullable_string(None);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let h = RequestHeader::parse(&mut r, false).unwrap();
        assert_eq!(h.client_id, None);
    }

    #[test]
    fn response_header_classic_and_flexible() {
        let mut classic = Writer::new();
        write_response_header(&mut classic, 1234, false);
        assert_eq!(classic.into_bytes(), 1234i32.to_be_bytes());

        let mut flexible = Writer::new();
        write_response_header(&mut flexible, 1234, true);
        let bytes = flexible.into_bytes();
        assert_eq!(&bytes[0..4], &1234i32.to_be_bytes());
        assert_eq!(bytes[4], 0x00, "flexible adds an empty tagged-fields byte");
    }

    #[test]
    fn defensive_truncated_reads_error_never_panic() {
        // Empty buffer: every fixed reader must error.
        let empty: [u8; 0] = [];
        let mut r = Reader::new(&empty);
        assert!(r.int8().is_err());
        let mut r = Reader::new(&empty);
        assert!(r.int16().is_err());
        let mut r = Reader::new(&empty);
        assert!(r.int32().is_err());
        let mut r = Reader::new(&empty);
        assert!(r.int64().is_err());
        let mut r = Reader::new(&empty);
        assert!(r.uint32().is_err());
        let mut r = Reader::new(&empty);
        assert!(r.unsigned_varint().is_err());
        let mut r = Reader::new(&empty);
        assert!(r.varint().is_err());
        let mut r = Reader::new(&empty);
        assert!(r.varlong().is_err());
        let mut r = Reader::new(&empty);
        assert!(r.string().is_err());
        let mut r = Reader::new(&empty);
        assert!(r.bytes().is_err());

        // Length header present but body truncated.
        let mut w = Writer::new();
        w.int16(10); // claims 10 bytes
        w.raw(&[1, 2]); // only 2 present
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.string().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn overlong_unsigned_varint_errors() {
        // Six continuation bytes — overlong.
        let bytes = [0x80u8, 0x80, 0x80, 0x80, 0x80, 0x01];
        let mut r = Reader::new(&bytes);
        assert_eq!(
            r.unsigned_varint().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn unsigned_varint_overflowing_u32_errors() {
        // Five bytes whose value exceeds u32::MAX.
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x7F];
        let mut r = Reader::new(&bytes);
        assert_eq!(
            r.unsigned_varint().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn huge_length_short_buffer_errors_without_alloc() {
        // INT32 length of 1 GiB but only a few bytes follow: must error, never allocate.
        let mut w = Writer::new();
        w.int32(1 << 30);
        w.raw(&[1, 2, 3]);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.bytes().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);

        // Same for a compact byte array with a huge unsigned-varint length.
        let mut w = Writer::new();
        w.unsigned_varint(0xFFFF_FFFF); // ~4 GiB len + 1
        w.raw(&[1, 2, 3]);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert!(r.compact_bytes().is_err());
    }

    #[test]
    fn null_string_via_negative_length_errors() {
        let mut w = Writer::new();
        w.int16(-1);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.string().unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn remaining_and_take() {
        let data = [1u8, 2, 3, 4];
        let mut r = Reader::new(&data);
        assert_eq!(r.take(2).unwrap(), &[1, 2]);
        assert_eq!(r.remaining(), &[3, 4]);
        assert!(r.take(99).is_err());
    }
}
