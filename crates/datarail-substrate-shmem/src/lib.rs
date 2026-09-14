//! `datarail-substrate-shmem` — the SPEC-07 **shmem** substrate: a lock-free single-producer/single-consumer
//! byte ring over shared memory, for **µs same-host hops** (two containers on one box sharing a mapping). The
//! ring carries length-prefixed sealed cofres; the substrate holds **no keys** and does no cofre crypto
//! (`INV-DUMB-PIPE`) and never inspects `carga` (`INV-OPAQUE-CARGO`). It passes the same
//! [`substrate_conformance`](datarail_rail::substrate_conformance) harness as every other substrate.
//!
//! ## The single audited `unsafe` (owner-delegated WAIVER, 2026-06-22)
//!
//! A *lock-free* cross-process ring requires atomic cursors living **inside** the shared mapping, which Rust
//! can only express with `unsafe` (forming `&AtomicUsize` over mapped bytes). The whole workspace stays
//! `forbid(unsafe)`; this crate alone is `deny(unsafe)` with a single `#[allow(unsafe_code)]` site
//! ([`ShmemRing::cell`]) — plus the file-backed `map_mut` (memmap2 marks file mapping `unsafe`). `memmap2`
//! encapsulates the mmap; the ring **data** bytes are accessed only through safe slices. See `AUDIT-03.md`.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use datarail_core::{Cofre, Substrate, MAX_COFRE_WIRE_LEN};

/// Byte offset of the producer cursor (monotonic) within the header.
const WRITE_OFF: usize = 0;
/// Byte offset of the consumer cursor (monotonic) within the header.
const READ_OFF: usize = 8;
/// Reserved header bytes (holds the two cursors; padded to a cache line, keeps the data region aligned).
const HEADER_LEN: usize = 64;
/// Default data-region size (4 MiB) — a same-host ring for typical batched cofres; huge cofres go via QUIC/S3.
pub const DEFAULT_RING: usize = 4 * 1024 * 1024;

/// A lock-free SPSC byte-ring [`Substrate`] over a shared memory mapping (SPEC-07 shmem).
///
/// [`pair`](Self::pair) / [`anon`](Self::anon) use a private anonymous mapping (single object — conformance +
/// same-process). [`create`](Self::create) / [`open`](Self::open) use a file-backed `MAP_SHARED` mapping so two
/// **independent processes** can share the ring (the real same-host cross-container hop).
pub struct ShmemRing {
    map: memmap2::MmapMut,
    capacity: usize,
    acked: Vec<[u8; 32]>,
}

impl ShmemRing {
    /// A fresh ring over a private anonymous mapping of `DEFAULT_RING` bytes (single object).
    ///
    /// # Errors
    /// [`io::Error`] if the anonymous mapping cannot be created.
    pub fn pair() -> io::Result<Self> {
        Self::anon(DEFAULT_RING)
    }

    /// A fresh ring over a private anonymous mapping with `ring_bytes` of data capacity (single object).
    ///
    /// # Errors
    /// [`io::Error`] if the anonymous mapping cannot be created.
    pub fn anon(ring_bytes: usize) -> io::Result<Self> {
        // `map_anon` is safe (no file aliasing) and zero-filled, so both cursors start at 0.
        let map = memmap2::MmapMut::map_anon(HEADER_LEN + ring_bytes)?;
        Ok(Self {
            map,
            capacity: ring_bytes,
            acked: Vec::new(),
        })
    }

    /// Create (or truncate) a file-backed shared ring at `path` with `ring_bytes` of data capacity — the
    /// **producer** side of a cross-process hop. The peer joins with [`open`](Self::open).
    ///
    /// # Errors
    /// [`io::Error`] if the file cannot be created/sized or mapped.
    pub fn create(path: impl AsRef<Path>, ring_bytes: usize) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let total = u64::try_from(HEADER_LEN + ring_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ring size overflow"))?;
        file.set_len(total)?; // zero-fills ⇒ both cursors start at 0
        Ok(Self {
            map: map_file(&file)?,
            capacity: ring_bytes,
            acked: Vec::new(),
        })
    }

    /// Join an existing file-backed shared ring at `path` — the **consumer** side of a cross-process hop.
    ///
    /// # Errors
    /// [`io::Error`] if the file cannot be opened or mapped, or is smaller than the header.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let map = map_file(&file)?;
        if map.len() <= HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ring file smaller than header",
            ));
        }
        let capacity = map.len() - HEADER_LEN;
        Ok(Self {
            map,
            capacity,
            acked: Vec::new(),
        })
    }

    /// The `cofre_id`s acked so far, in ack order.
    #[must_use]
    pub fn acked(&self) -> &[[u8; 32]] {
        &self.acked
    }

    /// Borrow the monotonic cursor stored at `offset` (`WRITE_OFF` or `READ_OFF`) as a shared-memory atomic.
    // WAIVER (owner-delegated, 2026-06-22): the single audited unsafe site. Both allows are intrinsic to sound
    // shared-memory atomics — `unsafe_code` forms the atomic over the mapping, and `cast_ptr_alignment` because
    // the page-aligned mmap base makes the `u8 → AtomicUsize` cast aligned (proven in SAFETY). Scoped to here.
    #[allow(unsafe_code, clippy::cast_ptr_alignment)]
    fn cell(&self, offset: usize) -> &AtomicUsize {
        debug_assert!(offset + 8 <= HEADER_LEN && offset.is_multiple_of(8));
        // SAFETY: `offset` (0 or 8) is 8-aligned and inside the reserved `HEADER_LEN`-byte header, and the
        // mmap base is page-aligned, so the cast is aligned and in-bounds. These two cells are accessed ONLY
        // through atomic ops (never aliased as plain memory), and the ring DATA region (`>= HEADER_LEN`) never
        // overlaps the header — so this is a sound single-producer/single-consumer atomic protocol over the
        // shared mapping. The returned reference is bounded to `&self`, which owns the mapping.
        unsafe { &*(self.map.as_ptr().add(offset).cast::<AtomicUsize>()) }
    }

    /// Copy `src` into the ring data region starting at monotonic position `pos` (wrapping the circular buffer).
    fn write_ring(&mut self, pos: usize, src: &[u8]) {
        let start = HEADER_LEN + (pos % self.capacity);
        let first = src.len().min(self.map.len() - start);
        self.map[start..start + first].copy_from_slice(&src[..first]);
        if first < src.len() {
            self.map[HEADER_LEN..HEADER_LEN + (src.len() - first)].copy_from_slice(&src[first..]);
        }
    }

    /// Copy `dst.len()` bytes out of the ring data region starting at monotonic position `pos` (wrapping).
    fn read_ring(&self, pos: usize, dst: &mut [u8]) {
        let start = HEADER_LEN + (pos % self.capacity);
        let first = dst.len().min(self.map.len() - start);
        dst[..first].copy_from_slice(&self.map[start..start + first]);
        if first < dst.len() {
            let rest = dst.len() - first;
            dst[first..].copy_from_slice(&self.map[HEADER_LEN..HEADER_LEN + rest]);
        }
    }
}

/// Memory-map a file read/write, `MAP_SHARED` (so independent processes mapping the same file share the ring).
#[allow(unsafe_code)]
fn map_file(file: &std::fs::File) -> io::Result<memmap2::MmapMut> {
    // SAFETY: `map_mut` is `unsafe` because the mapped file could be mutated out from under a `&[u8]`. Here
    // the file is our own ring file, sized once; every read/write of the data region is synchronized by the
    // header cursors' acquire/release, and the cursors are atomics — so concurrent access via the shared
    // mapping is the intended SPSC protocol, not UB.
    unsafe { memmap2::MmapMut::map_mut(file) }
}

impl Substrate for ShmemRing {
    type Error = io::Error;

    /// Append a length-prefixed cofre frame to the ring (single producer); errors if the frame exceeds the
    /// cap or the ring is full (back-pressure — the consumer must drain).
    ///
    /// # Errors
    /// [`io::Error`] if the cofre exceeds [`MAX_COFRE_WIRE_LEN`], is larger than the ring, or the ring is full.
    fn send(&mut self, cofre: &Cofre) -> Result<(), Self::Error> {
        let bytes = datarail_cofre::encode(cofre);
        if bytes.len() > MAX_COFRE_WIRE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cofre exceeds the maximum wire size",
            ));
        }
        let len = u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cofre exceeds u32 frame"))?;
        let total = 4 + bytes.len();
        if total > self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame larger than the ring",
            ));
        }
        let read = self.cell(READ_OFF).load(Ordering::Acquire); // consumer progress — PEER-CONTROLLABLE
        let write = self.cell(WRITE_OFF).load(Ordering::Relaxed); // our own
                                                                  // The consumer's `read` cursor lives in the shared segment and is untrusted (a hostile/corrupt same-host
                                                                  // consumer): `write - read` must not underflow (`read > write` → usize wraparound → a bogus "free" that
                                                                  // bypasses back-pressure and publishes a corrupt cursor), mirroring the guard in `recv`. Both subtractions
                                                                  // are checked.
        let Some(used) = write.checked_sub(read) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupt shmem ring cursors (read > write)",
            ));
        };
        let Some(free) = self.capacity.checked_sub(used) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupt shmem ring cursors (used > capacity)",
            ));
        };
        if total > free {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "shmem ring full (back-pressure)",
            ));
        }
        // `write` also lives in the shared segment; guard the advance against a corrupted cursor (checked_add).
        let Some(next_write) = write.checked_add(total) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupt shmem ring cursor (write overflow)",
            ));
        };
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&bytes);
        self.write_ring(write, &frame);
        // Publish: the Release pairs with the consumer's Acquire load of WRITE, so the bytes happen-before.
        self.cell(WRITE_OFF).store(next_write, Ordering::Release);
        Ok(())
    }

    /// Pop the next complete cofre frame from the ring (single consumer); `None` until a full frame is present.
    /// Routes from the bytes only — never inspects the plaintext.
    ///
    /// # Errors
    /// [`io::Error`] `InvalidData` if a framed cofre fails to decode or declares a length over the cap.
    fn recv(&mut self) -> Result<Option<Cofre>, Self::Error> {
        let write = self.cell(WRITE_OFF).load(Ordering::Acquire); // producer progress
        let read = self.cell(READ_OFF).load(Ordering::Relaxed); // our own
                                                                // The cursors live in the shared segment and are PEER-CONTROLLABLE (a hostile/corrupt same-host writer):
                                                                // treat them as untrusted. `write - read` must not underflow (audit: `read > write` → usize wraparound to
                                                                // a huge `avail` that bypasses every gate below), so use a checked subtraction.
        let Some(avail) = write.checked_sub(read) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupt shmem ring cursors (read > write)",
            ));
        };
        if avail < 4 {
            return Ok(None);
        }
        let mut len_bytes = [0u8; 4];
        self.read_ring(read, &mut len_bytes);
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_COFRE_WIRE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ring frame exceeds the maximum cofre size",
            ));
        }
        let total = 4 + len;
        // Cap the frame against the ACTUAL ring capacity (the `send` side does this; `recv` must too, or a
        // peer-declared `len > capacity` drives `read_ring` past the mapping → OOB slice panic). audit CRITICAL.
        if total > self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ring frame exceeds the ring capacity",
            ));
        }
        if avail < total {
            return Ok(None); // frame not fully written yet
        }
        let mut frame = vec![0u8; len];
        self.read_ring(read + 4, &mut frame);
        let cofre = datarail_cofre::decode(&frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        // Release the space: the Release pairs with the producer's Acquire load of READ.
        self.cell(READ_OFF).store(read + total, Ordering::Release);
        Ok(Some(cofre))
    }

    /// Record an acknowledgement (header-only; the payload is never consulted).
    ///
    /// # Errors
    /// Never returns an error — recording is in-memory; the `Result` satisfies the [`Substrate`] contract.
    fn ack(&mut self, cofre_id: [u8; 32]) -> Result<(), Self::Error> {
        self.acked.push(cofre_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ShmemRing;
    use datarail_core::Substrate;
    use datarail_rail::{substrate_conformance, testsupport};
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> std::path::PathBuf {
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("datarail-shmem-{}-{n}.ring", std::process::id()))
    }

    #[test]
    fn recv_rejects_a_hostile_oversized_frame_without_panicking() {
        // audit CRITICAL: the ring cursors + length are PEER-CONTROLLABLE. A len that is <= MAX_COFRE_WIRE_LEN but
        // far exceeds the ring capacity must ERROR, not drive read_ring past the mapping (OOB slice panic).
        let mut ring = ShmemRing::anon(64).expect("anon"); // 64-byte capacity
        let len: u32 = 60_000;
        ring.write_ring(0, &len.to_le_bytes());
        ring.cell(super::WRITE_OFF)
            .store(4 + usize::try_from(len).unwrap(), Ordering::Release);
        ring.cell(super::READ_OFF).store(0, Ordering::Release);
        assert!(
            ring.recv().is_err(),
            "an oversized hostile frame must error, not panic"
        );
    }

    #[test]
    fn recv_rejects_corrupt_cursors_with_read_past_write() {
        // `write - read` must not underflow when a corrupt/hostile peer sets read > write (audit CRITICAL).
        let mut ring = ShmemRing::anon(64).expect("anon");
        ring.cell(super::READ_OFF).store(100, Ordering::Release);
        ring.cell(super::WRITE_OFF).store(0, Ordering::Release);
        assert!(
            ring.recv().is_err(),
            "corrupt cursors (read > write) must error, not underflow"
        );
    }

    #[test]
    fn ac6_shmem_passes_substrate_conformance() {
        // The SAME AC-6 flow over a real shared-memory ring (anonymous mapping) — INV-SUBSTRATE-POLYMORPHIC
        // now holds over the lock-free SPSC ring too.
        substrate_conformance(|| ShmemRing::pair().expect("anon ring"));
    }

    #[test]
    fn cross_mapping_producer_and_consumer_share_the_ring() {
        // The shmem reason to exist: two INDEPENDENT mappings of the same file share the ring via the in-mapping
        // atomic cursors (this is exactly the cross-process / cross-container same-host hop, in one test proc).
        let path = temp_path();
        let mut producer = ShmemRing::create(&path, 64 * 1024).expect("create");
        let mut consumer = ShmemRing::open(&path).expect("open");

        let sent = testsupport::cofre_seq(7);
        producer.send(&sent).expect("send");
        let got = loop {
            if let Some(c) = consumer.recv().expect("recv") {
                break c;
            }
        };
        assert_eq!(
            got, sent,
            "the cofre crossed two independent mappings via shared memory, byte-for-byte"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ring_full_applies_back_pressure() {
        // A ring just big enough for one frame: a second un-drained send is refused (WouldBlock), not silently
        // dropped — the producer must wait for the consumer.
        let cofre = testsupport::cofre_seq(0);
        let one = 4 + datarail_cofre::encode(&cofre).len();
        let mut ring = ShmemRing::anon(one + one / 2).expect("anon"); // room for ~1.5 frames
        ring.send(&cofre).expect("first send fits");
        let err = ring
            .send(&cofre)
            .expect_err("second send must hit back-pressure");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn wraparound_preserves_frames() {
        // Capacity holds ~1 frame; alternating send/recv drives the monotonic cursors past the ring length,
        // exercising the wrap split. Every frame must reassemble byte-for-byte.
        let frame = 4 + datarail_cofre::encode(&testsupport::cofre_seq(0)).len();
        let mut ring = ShmemRing::anon(frame * 2 + 8).expect("anon");
        for seq in 0..8 {
            let c = testsupport::cofre_seq(seq);
            ring.send(&c).expect("send");
            let got = ring.recv().expect("recv").expect("a cofre");
            assert_eq!(got, c, "frame {seq} survived the ring wrap");
            ring.ack(got.etiqueta.cofre_id).expect("ack");
        }
    }
}
