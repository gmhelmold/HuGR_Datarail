//! Decompression of compressed Kafka producer batches (feature `compression`, `KAFKA-COMPRESSION-DESIGN.md`).
//!
//! Decompress-only, pure-Rust codecs. A compressed v2 `RecordBatch` has an uncompressed header followed by a
//! compressed records blob (codec = `attributes & 0x07`); we decompress the blob and parse the records from it, so
//! they become normal sealed cofres. Every decompression is **bounded** by `max` (a zip-bomb guard): a small
//! compressed batch from an untrusted producer cannot expand to exhaust memory.

use std::io;

/// Decompress a compressed records blob. `codec` is the Kafka attributes codec id (1 = gzip, 2 = snappy, 3 = lz4,
/// 4 = zstd). At most `max` decompressed bytes are produced; anything larger is rejected.
///
/// # Errors
/// [`io::Error`] if the codec is unsupported (not compiled in) or the stream is malformed / exceeds `max`.
pub fn decompress(codec: u8, input: &[u8], max: usize) -> io::Result<Vec<u8>> {
    match codec {
        #[cfg(feature = "compression-gzip")]
        1 => gunzip(input, max),
        #[cfg(feature = "compression-lz4")]
        3 => unlz4(input, max),
        #[cfg(feature = "compression-zstd")]
        4 => unzstd(input, max),
        #[cfg(feature = "compression-snappy")]
        2 => unsnappy(input, max),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported compression codec {other}"),
        )),
    }
}

/// Read a decompressing reader to completion, bounded at `max` bytes (the shared zip-bomb guard).
#[cfg(any(
    feature = "compression-lz4",
    feature = "compression-zstd",
    feature = "compression-snappy"
))]
fn read_capped(mut r: impl std::io::Read, max: usize) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    let cap = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut out = Vec::new();
    r.by_ref().take(cap).read_to_end(&mut out)?;
    if out.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed batch exceeds the size cap",
        ));
    }
    Ok(out)
}

/// lz4 (Kafka codec 3) — the LZ4 **frame** format (not raw block) via `lz4_flex`, capped at `max`.
#[cfg(feature = "compression-lz4")]
fn unlz4(input: &[u8], max: usize) -> io::Result<Vec<u8>> {
    read_capped(lz4_flex::frame::FrameDecoder::new(input), max)
}

/// zstd (Kafka codec 4) — a standard zstd frame via the pure-Rust `ruzstd` decoder, capped at `max`.
#[cfg(feature = "compression-zstd")]
fn unzstd(input: &[u8], max: usize) -> io::Result<Vec<u8>> {
    let dec = ruzstd::decoding::StreamingDecoder::new(input)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    read_capped(dec, max)
}

/// snappy (Kafka codec 2) — Kafka wraps snappy in the **xerial / snappy-java** block framing, NOT a raw or
/// standard-snappy-frame stream: an 8-byte magic `\x82SNAPPY\x00`, two big-endian `int32` version words, then a
/// run of `[int32 block_len][raw-snappy block]` chunks. We parse the framing and decode each block with `snap`.
#[cfg(feature = "compression-snappy")]
fn unsnappy(input: &[u8], max: usize) -> io::Result<Vec<u8>> {
    const XERIAL_MAGIC: [u8; 8] = [0x82, b'S', b'N', b'A', b'P', b'P', b'Y', 0x00];
    let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
    // Detect the actual snappy variant a producer sent (librdkafka may use any): xerial/snappy-java framing,
    // the standard snappy frame stream (starts 0xFF), or a single raw snappy block. Be liberal in what we accept.
    if input.get(..8) == Some(&XERIAL_MAGIC[..]) {
        return unsnappy_xerial(input, max);
    }
    if input.first() == Some(&0xFF) {
        return read_capped(snap::read::FrameDecoder::new(input), max);
    }
    let decoded = snap::raw::Decoder::new()
        .decompress_vec(input)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if decoded.len() > max {
        return Err(bad("decompressed batch exceeds the size cap"));
    }
    Ok(decoded)
}

/// Decode the xerial / snappy-java framing: magic + version words + a run of `[int32 len][raw-snappy block]`.
#[cfg(feature = "compression-snappy")]
fn unsnappy_xerial(input: &[u8], max: usize) -> io::Result<Vec<u8>> {
    let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
    // 8-byte magic + int32 version + int32 compatible-version = a 16-byte header; then framed blocks.
    let mut pos = 16usize;
    let mut out = Vec::new();
    let mut dec = snap::raw::Decoder::new();
    while pos < input.len() {
        let len_end = pos
            .checked_add(4)
            .ok_or_else(|| bad("block length overflow"))?;
        let len_bytes: [u8; 4] = input
            .get(pos..len_end)
            .ok_or_else(|| bad("truncated snappy block length"))?
            .try_into()
            .map_err(|_| bad("bad block length"))?;
        let block_len = usize::try_from(u32::from_be_bytes(len_bytes)).unwrap_or(usize::MAX);
        let block_end = len_end
            .checked_add(block_len)
            .ok_or_else(|| bad("block overflow"))?;
        let block = input
            .get(len_end..block_end)
            .ok_or_else(|| bad("truncated snappy block"))?;
        pos = block_end;
        let decoded = dec
            .decompress_vec(block)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if out.len().saturating_add(decoded.len()) > max {
            return Err(bad("decompressed batch exceeds the size cap"));
        }
        out.extend_from_slice(&decoded);
    }
    Ok(out)
}

/// gzip (Kafka codec 1) — a standard gzip stream via flate2's pure-Rust backend, capped at `max` bytes.
#[cfg(feature = "compression-gzip")]
fn gunzip(input: &[u8], max: usize) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    // Read at most max+1 bytes so an over-cap stream is detected without materializing the whole thing.
    let cap = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(input)
        .take(cap)
        .read_to_end(&mut out)?;
    if out.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed batch exceeds the size cap",
        ));
    }
    Ok(out)
}
