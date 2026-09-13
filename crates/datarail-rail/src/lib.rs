//! `datarail-rail` — the ephemeral, substrate-polymorphic transport (SPEC `07-rail-substrate.md`): it moves
//! cofres using only the authenticated header + seal (`INV-OPAQUE-CARGO`), never the payload.
//!
//! This crate provides the first concrete [`Substrate`] — an in-process [`LoopbackSubstrate`] — plus the
//! reusable [`substrate_conformance`] harness (AC-6) that every later substrate (shmem / QUIC / object-store)
//! must also pass. The loopback is the reference oracle: a `VecDeque<Cofre>` queue whose `send` enqueues,
//! `recv` dequeues in FIFO order, and `ack` records the acknowledged `cofre_id`s — routing and acking from
//! the [`Etiqueta`](datarail_core::Etiqueta) alone, **never** reading [`Cofre::carga`](datarail_core::Cofre).

#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};

use datarail_core::{Cofre, Substrate};

/// An in-process, single-queue [`Substrate`] — the reference loopback used as the conformance oracle.
///
/// `send` enqueues a clone of the cofre at the back of a `VecDeque`; `recv` pops the front (FIFO, preserving
/// per-stream order); `ack` appends the acked `cofre_id` to an audit log. It is a pure header-driven pipe:
/// it inspects only the routing fields it is given (`cofre_id` for acking) and **never** reads `carga`
/// (`INV-OPAQUE-CARGO`) — the metamorphic proof in this crate's tests pins that property.
///
/// It holds no keys and performs no crypto (`INV-DUMB-PIPE`); verification/sealing live in the terminal.
#[derive(Debug, Default, Clone)]
pub struct LoopbackSubstrate {
    queue: VecDeque<Cofre>,
    acked: Vec<[u8; 32]>,
}

impl LoopbackSubstrate {
    /// Create an empty loopback substrate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cofres currently queued (sent but not yet received).
    #[must_use]
    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }

    /// The `cofre_id`s acked so far, in ack order. Used by tests to observe ack behavior.
    #[must_use]
    pub fn acked(&self) -> &[[u8; 32]] {
        &self.acked
    }
}

/// The loopback substrate cannot fail: it is a pure in-memory queue with no transport to break.
///
/// It is an inhabited-but-unconstructable error type (no public constructor) so the [`Substrate`] contract is
/// honoured without ever yielding an `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackError {}

impl core::fmt::Display for LoopbackError {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {}
    }
}

impl core::error::Error for LoopbackError {}

impl Substrate for LoopbackSubstrate {
    type Error = LoopbackError;

    /// Enqueue a clone of the sealed cofre at the back of the queue.
    ///
    /// Routes by header only: the bytes of `cofre.carga` are copied verbatim and never inspected
    /// (`INV-OPAQUE-CARGO`).
    ///
    /// # Errors
    /// Never returns an error — [`LoopbackError`] is uninhabited; the signature satisfies the [`Substrate`]
    /// contract.
    fn send(&mut self, cofre: &Cofre) -> Result<(), Self::Error> {
        self.queue.push_back(cofre.clone());
        Ok(())
    }

    /// Pop and return the next cofre in FIFO order, or `None` when the queue is empty.
    ///
    /// # Errors
    /// Never returns an error — see [`LoopbackError`].
    fn recv(&mut self) -> Result<Option<Cofre>, Self::Error> {
        Ok(self.queue.pop_front())
    }

    /// Record an acknowledgement for `cofre_id` (header-only; the payload is never consulted).
    ///
    /// # Errors
    /// Never returns an error — see [`LoopbackError`].
    fn ack(&mut self, cofre_id: [u8; 32]) -> Result<(), Self::Error> {
        self.acked.push(cofre_id);
        Ok(())
    }
}

/// AC-6 substrate-parity harness: the one acceptance flow every [`Substrate`] must pass.
///
/// Given a factory that builds a fresh substrate, this drives the canonical lifecycle — **send N → recv N in
/// FIFO order → ack each** — and asserts:
///
/// 1. every `recv` after a `send` yields a cofre, in send order, byte-for-byte equal to what was sent;
/// 2. the queue is drained (the `N+1`-th `recv` is `None`);
/// 3. each received cofre can be acked (by its `etiqueta.cofre_id`) without error.
///
/// [`LoopbackSubstrate`] passes it; later substrates (shmem / QUIC / S3) plug into the *same* function so the
/// suite is identical across substrates (`INV-SUBSTRATE-POLYMORPHIC`).
///
/// # Panics
/// Panics (as a test assertion) if any step deviates from the contract above, or if the substrate's `send` /
/// `recv` / `ack` returns an error.
pub fn substrate_conformance<S, E>(make: impl Fn() -> S)
where
    S: Substrate<Error = E>,
    E: core::fmt::Debug,
{
    const N: u64 = 8;

    let mut sub = make();
    let sent: Vec<Cofre> = (0..N).map(testsupport::cofre_seq).collect();

    for cofre in &sent {
        sub.send(cofre).expect("send must succeed");
    }

    for (i, expected) in sent.iter().enumerate() {
        let mut attempts = 0;
        let got = loop {
            if let Some(got) = sub.recv().expect("recv must succeed") {
                break got;
            }
            attempts += 1;
            assert!(
                attempts < 1_000,
                "recv #{i} returned None for 1 second after a cofre was sent"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        assert_eq!(
            &got, expected,
            "recv #{i} must return the sent cofre in order"
        );
        sub.ack(got.etiqueta.cofre_id).expect("ack must succeed");
    }

    assert!(
        sub.recv().expect("recv must succeed").is_none(),
        "queue must be drained after N recvs"
    );
}

/// A substrate that models a **resumable** link across a network partition (AC-8).
///
/// Every cofre handed to [`send`](Substrate::send) is retained in a source-side outbox until it is acked;
/// [`recv`](Substrate::recv) delivers forward from a cursor. [`partition`](Self::partition) severs the link
/// (delivery yields `None`); [`resume`](Self::resume) reconnects and rewinds the cursor to the **first
/// un-acked** cofre, so the source re-drives the stream from the last durable position. Redeliveries are
/// deduped downstream by the `datarail-once` gate, so the net effect across a partition is **0-loss /
/// 0-duplicate** at the sink (proven end-to-end in `datarail-acceptance`'s AC-8 test).
///
/// Like [`LoopbackSubstrate`] it holds no keys and reads only the header (`INV-DUMB-PIPE` / `INV-OPAQUE-CARGO`)
/// and cannot fail (its `Error` is the uninhabited [`LoopbackError`]).
#[derive(Debug, Default, Clone)]
pub struct ResumableSubstrate {
    /// Every cofre sent, retained until acked (the resend buffer).
    outbox: Vec<Cofre>,
    /// `cofre_id`s the destination has acknowledged.
    acked: HashSet<[u8; 32]>,
    /// Index of the next cofre `recv` will deliver.
    cursor: usize,
    /// While `true`, `recv` delivers nothing (the link is severed).
    partitioned: bool,
}

impl ResumableSubstrate {
    /// A fresh, connected, empty resumable substrate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sever the link: until [`resume`](Self::resume), `recv` yields `None` (in-flight cofres are "lost").
    pub fn partition(&mut self) {
        self.partitioned = true;
    }

    /// Reconnect and resume from the last durable (acked) position: rewind the delivery cursor to the first
    /// un-acked cofre, so every sent-but-unacked cofre is re-driven.
    pub fn resume(&mut self) {
        self.partitioned = false;
        self.cursor = self
            .outbox
            .iter()
            .position(|c| !self.acked.contains(&c.etiqueta.cofre_id))
            .unwrap_or(self.outbox.len());
    }

    /// Number of cofres sent but not yet acked.
    #[must_use]
    pub fn inflight(&self) -> usize {
        self.outbox.len() - self.acked.len().min(self.outbox.len())
    }
}

impl Substrate for ResumableSubstrate {
    type Error = LoopbackError;

    /// Retain a clone of the cofre in the resend buffer.
    ///
    /// # Errors
    /// Never returns an error — [`LoopbackError`] is uninhabited.
    fn send(&mut self, cofre: &Cofre) -> Result<(), Self::Error> {
        self.outbox.push(cofre.clone());
        Ok(())
    }

    /// Deliver the next cofre from the cursor, or `None` while partitioned / drained.
    ///
    /// # Errors
    /// Never returns an error — see [`LoopbackError`].
    fn recv(&mut self) -> Result<Option<Cofre>, Self::Error> {
        if self.partitioned {
            return Ok(None);
        }
        if let Some(cofre) = self.outbox.get(self.cursor) {
            self.cursor += 1;
            Ok(Some(cofre.clone()))
        } else {
            Ok(None)
        }
    }

    /// Record an acknowledgement (header-only); acked cofres are not re-driven on [`resume`](Self::resume).
    ///
    /// # Errors
    /// Never returns an error — see [`LoopbackError`].
    fn ack(&mut self, cofre_id: [u8; 32]) -> Result<(), Self::Error> {
        self.acked.insert(cofre_id);
        Ok(())
    }
}

/// The shared core behind every **real byte-stream** [`Substrate`] (cross-process / cross-host): a duplex
/// transport `S` (anything `Read + Write` — a kernel socket, a TCP connection, later a QUIC stream).
///
/// Cofres are serialized with the canonical wire codec ([`encode`](datarail_cofre::encode) /
/// [`decode`](datarail_cofre::decode)), `u32`-length-prefixed, and moved over a transport that sees **only
/// opaque bytes** (`INV-OPAQUE-CARGO`) and holds **no keys** (`INV-DUMB-PIPE`). The very same
/// [`substrate_conformance`] harness passes over an in-memory queue, a Unix pipe, and a TCP connection
/// unchanged — `INV-SUBSTRATE-POLYMORPHIC` demonstrated identically across all of them.
///
/// `send` writes a framed cofre to the write half (`tx`); `recv` drains the read half (`rx`) into a buffer
/// and decodes one complete frame (returning `None` until a full frame has arrived). The read half is made
/// *non-immediately-blocking* by the concrete constructor — non-blocking for the separate-fd pair cases
/// ([`SocketSubstrate::pair`] / [`TcpSubstrate::loopback_pair`]) or a short read-timeout for the shared-fd
/// duplex cases ([`TcpSubstrate::connect`] / [`TcpSubstrate::accept`], where the write half must stay
/// blocking) — so `recv` returns promptly on an empty transport.
///
/// v1 note: a single connection with kernel-buffered sends — fine for bounded batches; a production substrate
/// would interleave send/recv or size the socket buffer to avoid back-pressure on huge bursts.
#[derive(Debug)]
pub struct StreamSubstrate<S> {
    tx: S,
    rx: S,
    buf: Vec<u8>,
    acked: Vec<[u8; 32]>,
}

impl<S> StreamSubstrate<S> {
    /// The `cofre_id`s acked so far, in ack order.
    #[must_use]
    pub fn acked(&self) -> &[[u8; 32]] {
        &self.acked
    }
}

impl<S: std::io::Read + std::io::Write> Substrate for StreamSubstrate<S> {
    type Error = std::io::Error;

    /// Serialize the cofre (wire codec) and write a `u32`-length-prefixed frame to the write half.
    ///
    /// # Errors
    /// [`std::io::Error`] on a write failure, or if the encoded cofre exceeds [`MAX_COFRE_WIRE_LEN`]
    /// ([`datarail_core::MAX_COFRE_WIRE_LEN`]) — the same cap the receiver enforces.
    fn send(&mut self, cofre: &Cofre) -> Result<(), Self::Error> {
        let bytes = datarail_cofre::encode(cofre);
        if bytes.len() > datarail_core::MAX_COFRE_WIRE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cofre exceeds the maximum wire size",
            ));
        }
        let len = u32::try_from(bytes.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "cofre exceeds u32 frame")
        })?;
        self.tx.write_all(&len.to_le_bytes())?;
        self.tx.write_all(&bytes)?;
        Ok(())
    }

    /// Drain whatever is readable into the buffer, then decode one complete length-prefixed frame if present
    /// (`None` until a full frame has arrived). Routes from the bytes only — never inspects the plaintext.
    ///
    /// # Errors
    /// [`std::io::Error`] on a read failure, or `InvalidData` if a framed cofre fails to decode (corrupt pipe).
    fn recv(&mut self) -> Result<Option<Cofre>, Self::Error> {
        let mut tmp = [0u8; 8192];
        loop {
            match self.rx.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    self.buf.extend_from_slice(&tmp[..n]);
                    // Bound buffering (AUDIT-03 F1): a peer cannot make us hold more than one max-size frame,
                    // so a huge declared length or an endless dribble can't exhaust memory.
                    if self.buf.len() > datarail_core::MAX_COFRE_WIRE_LEN + 4 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "stream frame exceeds the maximum cofre size",
                        ));
                    }
                }
                // WouldBlock (non-blocking fd) and TimedOut (read-timeout fd) both mean "no more right now".
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&self.buf[..4]);
        let len = u32::from_le_bytes(len_bytes) as usize;
        // Reject an over-large declared frame up front (AUDIT-03 F1), before waiting to buffer its body.
        if len > datarail_core::MAX_COFRE_WIRE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stream frame length exceeds the maximum cofre size",
            ));
        }
        if self.buf.len() < 4 + len {
            return Ok(None); // frame not fully arrived yet
        }
        let frame = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        let cofre = datarail_cofre::decode(&frame)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
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

/// A **cross-process** [`Substrate`] over a connected Unix-domain-socket pair (same host — the first rung of
/// the cross-container ladder). A [`StreamSubstrate`] over [`UnixStream`](std::os::unix::net::UnixStream).
#[cfg(unix)]
pub type SocketSubstrate = StreamSubstrate<std::os::unix::net::UnixStream>;

#[cfg(unix)]
impl StreamSubstrate<std::os::unix::net::UnixStream> {
    /// Build a substrate over a fresh connected socket pair: bytes written by `send` (to `tx`) are read by
    /// `recv` (from `rx`). The read end is set non-blocking so `recv` can return `None` on an empty pipe.
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] if the socket pair cannot be created or set non-blocking.
    pub fn pair() -> std::io::Result<Self> {
        let (tx, rx) = std::os::unix::net::UnixStream::pair()?;
        rx.set_nonblocking(true)?;
        Ok(Self {
            tx,
            rx,
            buf: Vec::new(),
            acked: Vec::new(),
        })
    }
}

/// A **cross-host** [`Substrate`] over a TCP connection — the cross-cluster rung of the ladder, and the
/// literal **TCP baseline** the AC-8 WAN benchmark measures against. A [`StreamSubstrate`] over
/// [`TcpStream`](std::net::TcpStream).
///
/// The cofre is already sealed, so TCP is used purely as a dumb byte pipe — **no TLS is needed for
/// confidentiality** (`INV-OPAQUE-CARGO` already holds; this validates the DERP-style blind relay). Two
/// constructor shapes: [`loopback_pair`](Self::loopback_pair) holds both ends locally (conformance + same-host
/// hops); [`connect`](Self::connect) / [`accept`](Self::accept) hold a single duplex endpoint each, for a real
/// two-process / two-host transfer.
pub type TcpSubstrate = StreamSubstrate<std::net::TcpStream>;

impl StreamSubstrate<std::net::TcpStream> {
    /// A same-object loopback pair over `127.0.0.1` (both ends held locally): `send` writes the client end,
    /// `recv` reads the accepted server end. Used by the conformance harness and same-host hops; the two ends
    /// are *separate* sockets, so the read end can be set non-blocking without affecting writes.
    ///
    /// # Errors
    /// [`std::io::Error`] if binding, connecting, accepting, or socket configuration fails.
    pub fn loopback_pair() -> std::io::Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let tx = std::net::TcpStream::connect(addr)?;
        tx.set_nodelay(true)?;
        let (rx, _peer) = listener.accept()?;
        rx.set_nonblocking(true)?;
        Ok(Self {
            tx,
            rx,
            buf: Vec::new(),
            acked: Vec::new(),
        })
    }

    /// Connect to a remote rail endpoint (the cross-host **source** side): one duplex connection where `send`
    /// writes and `recv` reads the same socket. The read half is given a short read-timeout (rather than
    /// non-blocking, which — sharing the file description with the write half — would make writes fail) so
    /// `recv` returns promptly when the peer has sent nothing, while `send` stays blocking.
    ///
    /// # Errors
    /// [`std::io::Error`] on connect / clone / socket-configuration failure.
    pub fn connect(addr: impl std::net::ToSocketAddrs) -> std::io::Result<Self> {
        let tx = std::net::TcpStream::connect(addr)?;
        tx.set_nodelay(true)?;
        let rx = tx.try_clone()?;
        rx.set_read_timeout(Some(std::time::Duration::from_millis(50)))?;
        Ok(Self {
            tx,
            rx,
            buf: Vec::new(),
            acked: Vec::new(),
        })
    }

    /// Accept one connection from `listener` (the cross-host **destination** side). Same single-duplex,
    /// read-timeout shape as [`connect`](Self::connect).
    ///
    /// # Errors
    /// [`std::io::Error`] on accept / clone / socket-configuration failure.
    pub fn accept(listener: &std::net::TcpListener) -> std::io::Result<Self> {
        let (tx, _peer) = listener.accept()?;
        Self::from_stream(tx)
    }

    /// Build a destination-side substrate from an **already-accepted** [`TcpStream`](std::net::TcpStream).
    /// Same single-duplex, short-read-timeout shape as [`accept`](Self::accept) — use this when the caller does
    /// its own bounded/non-blocking accept (e.g. a `recv` daemon that must not block forever).
    ///
    /// # Errors
    /// [`std::io::Error`] on clone / socket-configuration failure.
    pub fn from_stream(tx: std::net::TcpStream) -> std::io::Result<Self> {
        tx.set_nodelay(true)?;
        let rx = tx.try_clone()?;
        rx.set_read_timeout(Some(std::time::Duration::from_millis(50)))?;
        Ok(Self {
            tx,
            rx,
            buf: Vec::new(),
            acked: Vec::new(),
        })
    }
}

/// A WAN-condition profile for [`WanLink`] — the SPEC-11 AC-8 "lossy / high-RTT link" knobs.
///
/// Deterministic (no RNG) so tests and benchmarks reproduce exactly: `latency` is added before each `recv`
/// returns (models per-hop RTT), and every `drop_every`-th `send` is silently lost (models packet loss —
/// `0` disables drops). Reordering is intentionally omitted: datarail's substrates are ordered byte streams
/// (TCP / QUIC), and AC-8 specifies *lossy / high-RTT*, not reordering.
#[derive(Debug, Clone, Copy, Default)]
pub struct WanProfile {
    /// Latency added before each `recv` returns a cofre (zero = none).
    pub latency: std::time::Duration,
    /// Drop every Nth `send` (lost in transit); `0` disables drops.
    pub drop_every: u32,
}

/// A WAN-condition decorator over any inner [`Substrate`] (AC-8 harness): injects extra latency and packet
/// loss to exercise resume + dedup and to bound throughput on a lossy / high-RTT link, **without changing the
/// inner substrate**. Std-only, deterministic. A dropped `send` never reaches the inner substrate, so the
/// effectively-once gate + source re-drive (resume) must recover it — exactly what AC-8 tests.
///
/// With the default ([`WanProfile::default`]) profile it is a transparent pass-through and satisfies
/// [`substrate_conformance`] unchanged.
#[derive(Debug)]
pub struct WanLink<S> {
    inner: S,
    profile: WanProfile,
    sent: u64,
    dropped: u64,
}

impl<S> WanLink<S> {
    /// Wrap `inner` with the given WAN `profile`.
    #[must_use]
    pub fn new(inner: S, profile: WanProfile) -> Self {
        Self {
            inner,
            profile,
            sent: 0,
            dropped: 0,
        }
    }

    /// How many `send`s this link has dropped so far (lost in the simulated WAN).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Borrow the inner substrate.
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: Substrate> Substrate for WanLink<S> {
    type Error = S::Error;

    /// Forward the cofre to the inner substrate, unless this is a `drop_every`-th send (then it is silently
    /// lost in transit — the source must re-drive it on resume).
    ///
    /// # Errors
    /// Propagates the inner substrate's error.
    fn send(&mut self, cofre: &Cofre) -> Result<(), Self::Error> {
        self.sent += 1;
        if self.profile.drop_every != 0
            && self.sent.is_multiple_of(u64::from(self.profile.drop_every))
        {
            self.dropped += 1;
            return Ok(());
        }
        self.inner.send(cofre)
    }

    /// Sleep for the profile's latency (modelling RTT), then delegate to the inner substrate.
    ///
    /// # Errors
    /// Propagates the inner substrate's error.
    fn recv(&mut self) -> Result<Option<Cofre>, Self::Error> {
        if !self.profile.latency.is_zero() {
            std::thread::sleep(self.profile.latency);
        }
        self.inner.recv()
    }

    /// Delegate the acknowledgement to the inner substrate (header-only).
    ///
    /// # Errors
    /// Propagates the inner substrate's error.
    fn ack(&mut self, cofre_id: [u8; 32]) -> Result<(), Self::Error> {
        self.inner.ack(cofre_id)
    }
}

/// E3 — FASP-style **delay-based** congestion control (SPEC 07): a sender-side rate window that reacts to
/// measured **queueing delay** (RTT inflation above the path's base RTT), *not* to packet loss. A large
/// transfer over a lossy / high-RTT WAN therefore does not collapse the way loss-based TCP does — loss is
/// recovered by retransmission (`bao` resume, E4), never by cutting the rate. Pure state machine: feed it RTT
/// samples and (observed-only) loss events; it owns no I/O.
pub mod reliable_udp;

pub mod congestion {
    use std::time::Duration;

    /// A delay-based congestion-window controller (TCP-Vegas / BBR-like).
    #[derive(Debug, Clone)]
    pub struct DelayController {
        base_rtt: Duration,
        window: f64,
        min_window: f64,
        max_window: f64,
        increase: f64,
        decrease: f64,
        queue_threshold: Duration,
        losses: u64,
    }

    impl DelayController {
        /// A controller starting at `init_window` (clamped to `[min_window, max_window]`), treating queueing
        /// delay above `queue_threshold` as congestion. `base_rtt` starts at the maximum and is pulled down by
        /// observed samples (the learned uncongested path delay).
        #[must_use]
        pub fn new(
            init_window: f64,
            min_window: f64,
            max_window: f64,
            queue_threshold: Duration,
        ) -> Self {
            Self {
                base_rtt: Duration::MAX,
                window: init_window.clamp(min_window, max_window),
                min_window,
                max_window,
                increase: 1.0,
                decrease: 0.85,
                queue_threshold,
                losses: 0,
            }
        }

        /// The current congestion window (cofres the sender may keep outstanding).
        #[must_use]
        pub fn window(&self) -> f64 {
            self.window
        }

        /// The learned base (uncongested) RTT.
        #[must_use]
        pub fn base_rtt(&self) -> Duration {
            self.base_rtt
        }

        /// Observed losses so far — recorded for visibility but **deliberately not acted on** (see [`on_loss`]).
        ///
        /// [`on_loss`]: Self::on_loss
        #[must_use]
        pub fn losses(&self) -> u64 {
            self.losses
        }

        /// Feed one RTT sample: learn the base RTT, then **additively grow** the window while the queue is
        /// shallow and **multiplicatively shrink** it once queueing delay exceeds the threshold (the
        /// delay-based congestion signal).
        pub fn on_rtt_sample(&mut self, rtt: Duration) {
            if rtt < self.base_rtt {
                self.base_rtt = rtt;
            }
            let queue = rtt.saturating_sub(self.base_rtt);
            if queue > self.queue_threshold {
                self.window = (self.window * self.decrease).max(self.min_window);
            } else {
                self.window = (self.window + self.increase).min(self.max_window);
            }
        }

        /// Record a packet loss. **Delay-based control does not treat loss as congestion** — the rate window is
        /// left unchanged (the lost cofre/chunk is recovered by retransmission / `bao` resume, E4). This is the
        /// FASP physics that decouples throughput from loss; loss-based TCP would halve here. The loss is
        /// counted for observability only.
        pub fn on_loss(&mut self) {
            self.losses += 1;
        }
    }
}

/// E5 — stateless **proof-of-IP cookie** denial-of-service defense (SPEC 07; `WireGuard` `mac1`/`mac2` style). A scale-to-zero
/// rail endpoint must not allocate per-connection state for a *spoofed* flood: on an unauthenticated
/// initiation it returns a stateless cookie `HMAC(secret, client_addr ‖ epoch)` and allocates **nothing**, and
/// only proceeds once the initiator **echoes a valid cookie** — which a source lying about its address cannot
/// produce. The secret never leaves the endpoint; bumping `epoch` expires outstanding cookies. This is
/// connection *admission*, separate from the dumb substrate (it touches no cofre, holds no cofre key).
pub mod admission {
    use datarail_crypto::hmac_blake3;

    /// A stateless cookie gate: an endpoint secret bound to the current epoch.
    #[derive(Clone)]
    pub struct CookieGate {
        secret: [u8; 32],
        epoch: u64,
    }

    // Manual `Debug` that **redacts the secret** (AUDIT-03 F2) — a derived `Debug` would print the endpoint
    // key, the same leak AUDIT-02 closed for the terminal secrets.
    impl core::fmt::Debug for CookieGate {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("CookieGate")
                .field("secret", &"<redacted>")
                .field("epoch", &self.epoch)
                .finish()
        }
    }

    impl CookieGate {
        /// A gate keyed by `secret` at `epoch` (bump the epoch to rotate / expire outstanding cookies).
        #[must_use]
        pub fn new(secret: [u8; 32], epoch: u64) -> Self {
            Self { secret, epoch }
        }

        /// Issue a stateless cookie for `client_addr` = `HMAC(secret, addr ‖ epoch_le)`. Allocates no state.
        #[must_use]
        pub fn issue(&self, client_addr: &[u8]) -> [u8; 32] {
            hmac_blake3(&self.secret, &cookie_preimage(client_addr, self.epoch))
        }

        /// Constant-time check that `cookie` is the one this gate would issue for `client_addr` at this epoch.
        /// A spoofed source (wrong `client_addr`), a forged cookie, the wrong secret, or an expired epoch all
        /// fail — so connection state is allocated only after a genuine round-trip to the claimed address.
        #[must_use]
        pub fn verify(&self, client_addr: &[u8], cookie: &[u8; 32]) -> bool {
            ct_eq(&self.issue(client_addr), cookie)
        }
    }

    /// The cookie preimage: `client_addr ‖ epoch_le`.
    fn cookie_preimage(client_addr: &[u8], epoch: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(client_addr.len() + 8);
        buf.extend_from_slice(client_addr);
        buf.extend_from_slice(&epoch.to_le_bytes());
        buf
    }

    /// Constant-time equality for two 32-byte tags — folds over all bytes with no early return, so it leaks no
    /// timing oracle on the MAC.
    fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
        a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
    }
}

/// Shared cofre fixtures — `pub` so downstream substrate crates can reuse them in the same harness.
pub mod testsupport {
    use datarail_cofre::seal;
    use datarail_core::{AeadAlg, Cofre, Etiqueta};

    /// A deterministic signing seed for fixtures (test-only; not a real key).
    pub const FIXTURE_SEED: [u8; 32] = [7u8; 32];

    /// Build a fully-populated etiqueta with a given `seq` and all routing fields fixed.
    ///
    /// `cofre_id` / `signer_key_id` are placeholders overwritten by [`seal`].
    #[must_use]
    pub fn etiqueta_seq(seq: u64) -> Etiqueta {
        Etiqueta {
            route_id: [1; 16],
            stream_id: [2; 16],
            seq,
            cofre_id: [0; 32],
            idempotency_key: [4; 32],
            contract_fp: [5; 32],
            aead_alg: AeadAlg::Gcmsiv256,
            nonce: [6; 12],
            signer_key_id: [0; 32],
            eph_pk: [7; 32],
            sender_present: false,
            ts: 0,
        }
    }

    /// A validly-sealed cofre for sequence `seq`, with a distinct payload per `seq`.
    #[must_use]
    pub fn cofre_seq(seq: u64) -> Cofre {
        let carga = format!("opaque-ciphertext-{seq:03}").into_bytes();
        seal(etiqueta_seq(seq), carga, &FIXTURE_SEED)
    }
}

#[cfg(test)]
mod tests {
    use super::testsupport::{etiqueta_seq, FIXTURE_SEED};
    use super::{substrate_conformance, LoopbackSubstrate, ResumableSubstrate};
    use datarail_cofre::{seal, verify};
    use datarail_core::{Cofre, Substrate};
    use datarail_crypto::verifying_key;

    #[test]
    fn ac6_loopback_passes_substrate_conformance() {
        // The reference substrate satisfies the polymorphic acceptance flow (AC-6).
        substrate_conformance(LoopbackSubstrate::new);
    }

    #[test]
    fn ac6_resumable_passes_substrate_conformance() {
        // The resumable substrate (with no partition) satisfies the same polymorphic flow.
        substrate_conformance(ResumableSubstrate::new);
    }

    #[cfg(unix)]
    #[test]
    fn ac6_socket_passes_substrate_conformance() {
        // The SAME AC-6 flow, now over a REAL cross-process kernel transport (Unix domain socket) — the wire
        // codec round-trips through the kernel and the polymorphic harness is satisfied unchanged.
        substrate_conformance(|| super::SocketSubstrate::pair().expect("unix socket pair"));
    }

    #[test]
    fn ac6_tcp_passes_substrate_conformance() {
        // The SAME AC-6 flow over a REAL cross-host transport (TCP, loopback) — INV-SUBSTRATE-POLYMORPHIC now
        // holds over a network socket too, not only a kernel pipe. This substrate is the AC-8 TCP baseline.
        substrate_conformance(|| super::TcpSubstrate::loopback_pair().expect("tcp loopback pair"));
    }

    #[test]
    fn tcp_cross_endpoint_transfers_cofre_byte_for_byte() {
        // A genuine TWO-ENDPOINT transfer (separate connect + accept across threads, as a cross-host hop would
        // be): a cofre sealed at the source survives the TCP transport byte-for-byte at the destination.
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let sent = super::testsupport::cofre_seq(42);
        let expected = sent.clone();

        let server = std::thread::spawn(move || {
            let mut dst = super::TcpSubstrate::accept(&listener).expect("accept");
            loop {
                if let Some(c) = dst.recv().expect("recv") {
                    dst.ack(c.etiqueta.cofre_id).expect("ack");
                    return c;
                }
            }
        });

        let mut src = super::TcpSubstrate::connect(addr).expect("connect");
        src.send(&sent).expect("send");
        let got = server.join().expect("server thread");
        assert_eq!(
            got, expected,
            "cofre survived a real cross-endpoint TCP transport byte-for-byte"
        );
    }

    #[test]
    fn ac6_wanlink_default_profile_is_transparent() {
        // A benign (default) WAN profile is a pure pass-through, so the decorator satisfies the SAME AC-6
        // conformance flow — proving it neither corrupts nor reorders the stream.
        substrate_conformance(|| {
            super::WanLink::new(LoopbackSubstrate::new(), super::WanProfile::default())
        });
    }

    #[test]
    fn wanlink_drops_every_nth_send() {
        // drop_every=2 over a lossless loopback: sends #2 and #4 are lost in transit, so only #1 and #3 arrive.
        let profile = super::WanProfile {
            drop_every: 2,
            ..super::WanProfile::default()
        };
        let mut link = super::WanLink::new(LoopbackSubstrate::new(), profile);
        for seq in 0..4 {
            link.send(&super::testsupport::cofre_seq(seq)).unwrap();
        }
        assert_eq!(link.dropped(), 2, "every 2nd send was dropped");
        let a = link.recv().unwrap().expect("first survivor");
        let b = link.recv().unwrap().expect("second survivor");
        assert_eq!(
            link.recv().unwrap(),
            None,
            "only the un-dropped cofres arrive"
        );
        assert_eq!(a.etiqueta.seq, 0, "send #1 (seq 0) survived");
        assert_eq!(
            b.etiqueta.seq, 2,
            "send #3 (seq 2) survived; #2 and #4 were dropped"
        );
    }

    #[test]
    fn wanlink_adds_recv_latency() {
        let profile = super::WanProfile {
            latency: std::time::Duration::from_millis(20),
            ..super::WanProfile::default()
        };
        let mut link = super::WanLink::new(LoopbackSubstrate::new(), profile);
        link.send(&super::testsupport::cofre_seq(0)).unwrap();
        let t = std::time::Instant::now();
        let _ = link.recv().unwrap();
        assert!(
            t.elapsed() >= std::time::Duration::from_millis(20),
            "recv waited out the simulated WAN latency"
        );
    }

    // ---- E3 delay-based congestion control ------------------------------------------------------------------

    #[test]
    fn cc_backs_off_under_queue_buildup() {
        use super::congestion::DelayController;
        use std::time::Duration;
        let mut cc = DelayController::new(20.0, 1.0, 100.0, Duration::from_millis(5));
        cc.on_rtt_sample(Duration::from_millis(10)); // learn base RTT = 10 ms (queue 0 → grow)
        let before = cc.window();
        cc.on_rtt_sample(Duration::from_millis(50)); // queue = 40 ms > 5 ms threshold → back off
        assert!(
            cc.window() < before,
            "delay-based CC shrinks the window on queue build-up"
        );
    }

    #[test]
    fn cc_ignores_loss_unlike_loss_based_tcp() {
        use super::congestion::DelayController;
        use std::time::Duration;
        let mut cc = DelayController::new(20.0, 1.0, 100.0, Duration::from_millis(5));
        let w = cc.window();
        cc.on_loss();
        cc.on_loss();
        cc.on_loss();
        assert!(
            (cc.window() - w).abs() < f64::EPSILON,
            "loss must NOT cut the rate (FASP physics)"
        );
        assert_eq!(
            cc.losses(),
            3,
            "losses observed for visibility, not acted on"
        );
    }

    #[test]
    fn cc_grows_while_uncongested_and_clamps_to_max() {
        use super::congestion::DelayController;
        use std::time::Duration;
        let mut cc = DelayController::new(1.0, 1.0, 5.0, Duration::from_millis(5));
        for _ in 0..20 {
            cc.on_rtt_sample(Duration::from_millis(10)); // always uncongested → additive increase
        }
        assert!(
            (cc.window() - 5.0).abs() < f64::EPSILON,
            "window grows but clamps at max_window"
        );
    }

    // ---- E5 DoS proof-of-IP cookie --------------------------------------------------------------------------

    #[test]
    fn cookie_valid_admits_spoofed_and_forged_rejected() {
        use super::admission::CookieGate;
        let gate = CookieGate::new([7u8; 32], 1);
        let real = b"203.0.113.7:51000";
        let cookie = gate.issue(real);
        assert!(
            gate.verify(real, &cookie),
            "a genuine round-trip cookie admits"
        );
        assert!(
            !gate.verify(b"198.51.100.9:40000", &cookie),
            "a spoofed source address fails"
        );
        assert!(!gate.verify(real, &[0u8; 32]), "a forged cookie fails");
    }

    #[test]
    fn cookie_rotates_on_epoch_and_secret() {
        use super::admission::CookieGate;
        let addr = b"203.0.113.7:51000";
        let cookie = CookieGate::new([7u8; 32], 1).issue(addr);
        assert!(
            !CookieGate::new([7u8; 32], 2).verify(addr, &cookie),
            "an epoch bump expires the cookie"
        );
        assert!(
            !CookieGate::new([9u8; 32], 1).verify(addr, &cookie),
            "a different secret rejects it"
        );
    }

    // ---- GATE-FEATHER: an idle ephemeral substrate holds no standing in-flight state -----------------------

    #[test]
    fn gate_feather_idle_substrate_retains_nothing() {
        // An in-process ephemeral substrate is a passive struct — no spawned thread, fd, or timer — so when
        // there is no work it holds no standing resource. Concretely: across repeated burst→drain→ack cycles
        // the in-flight count returns to 0 every time (no accumulation of standing state when idle). This is
        // the architectural half of GATE-FEATHER; a real serverless substrate's idle RSS is a deployment
        // measurement (DIRECTIONAL/PENDING).
        let mut loopback = LoopbackSubstrate::new();
        for _ in 0..5 {
            for seq in 0..8 {
                loopback.send(&super::testsupport::cofre_seq(seq)).unwrap();
            }
            while let Some(c) = loopback.recv().unwrap() {
                loopback.ack(c.etiqueta.cofre_id).unwrap();
            }
            assert_eq!(
                loopback.queued_len(),
                0,
                "nothing retained in-flight once drained (idle ≈ 0)"
            );
        }

        let mut resumable = ResumableSubstrate::new();
        for seq in 0..8 {
            resumable.send(&super::testsupport::cofre_seq(seq)).unwrap();
        }
        while let Some(c) = resumable.recv().unwrap() {
            resumable.ack(c.etiqueta.cofre_id).unwrap();
        }
        assert_eq!(
            resumable.inflight(),
            0,
            "all acked ⇒ no standing in-flight state when idle"
        );
    }

    // ---- AUDIT-03 F1: a malicious oversized frame length is rejected, not buffered toward 4 GiB -----------

    #[test]
    fn oversized_frame_length_is_rejected() {
        use std::io::Write as _;
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Attacker: connect raw and declare a ~4 GiB frame, then dribble a little body.
        let mut attacker = TcpStream::connect(addr).expect("connect");
        attacker
            .write_all(&u32::MAX.to_le_bytes())
            .expect("write len");
        attacker.write_all(&[0u8; 1024]).expect("write body");
        attacker.flush().expect("flush");

        let mut sub = super::TcpSubstrate::accept(&listener).expect("accept");
        let err = loop {
            match sub.recv() {
                Ok(None) => {} // still waiting for bytes to arrive; the loop re-iterates
                Ok(Some(_)) => panic!("an oversized frame must never decode"),
                Err(e) => break e,
            }
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidData,
            "the substrate rejects an over-large declared frame instead of exhausting memory"
        );
        drop(attacker);
    }

    #[test]
    fn resumable_partition_then_resume_redelivers_unacked() {
        let mut sub = ResumableSubstrate::new();
        let a = super::testsupport::cofre_seq(0);
        let b = super::testsupport::cofre_seq(1);
        let c = super::testsupport::cofre_seq(2);
        sub.send(&a).unwrap();
        sub.send(&b).unwrap();
        sub.send(&c).unwrap();

        // Deliver + ack `a`; deliver `b` but do NOT ack it (its ack is "lost").
        assert_eq!(sub.recv().unwrap().as_ref(), Some(&a));
        sub.ack(a.etiqueta.cofre_id).unwrap();
        assert_eq!(sub.recv().unwrap().as_ref(), Some(&b));
        assert_eq!(sub.inflight(), 2, "b and c are unacked");

        // Partition: nothing is delivered.
        sub.partition();
        assert_eq!(sub.recv().unwrap(), None);

        // Resume: re-drive from the first un-acked (`b`), then the never-delivered `c`, then drain.
        sub.resume();
        assert_eq!(
            sub.recv().unwrap().as_ref(),
            Some(&b),
            "unacked b is redelivered"
        );
        assert_eq!(sub.recv().unwrap().as_ref(), Some(&c));
        assert_eq!(sub.recv().unwrap(), None);
    }

    #[test]
    fn send_recv_is_fifo_and_ack_is_logged() {
        let mut sub = LoopbackSubstrate::new();
        let a = super::testsupport::cofre_seq(0);
        let b = super::testsupport::cofre_seq(1);
        sub.send(&a).unwrap();
        sub.send(&b).unwrap();
        assert_eq!(sub.queued_len(), 2);

        assert_eq!(sub.recv().unwrap().as_ref(), Some(&a));
        assert_eq!(sub.recv().unwrap().as_ref(), Some(&b));
        assert_eq!(sub.recv().unwrap(), None);

        sub.ack(a.etiqueta.cofre_id).unwrap();
        sub.ack(b.etiqueta.cofre_id).unwrap();
        assert_eq!(sub.acked(), &[a.etiqueta.cofre_id, b.etiqueta.cofre_id]);
    }

    /// Drive the full send→recv→ack lifecycle and distill the substrate's *decision structure* — the
    /// routing choices it makes — into a comparable trace.
    ///
    /// The substrate routes/acks from the [`Etiqueta`](datarail_core::Etiqueta) alone, so the opacity claim
    /// is that this *structure* is independent of the payload bytes. We deliberately do NOT record the
    /// absolute `cofre_id`/`lacre` here: those are payload-derived (`cofre_id = BLAKE3(carga)`,
    /// `lacre` signs over carga), so when two payloads legitimately differ they differ too — comparing them
    /// would conflate "carga was read" with "the cofre carries a different content-id". Instead we record:
    /// receive order/count, the routing fields the substrate may use, whether each recv'd cofre is echoed
    /// byte-for-byte (the pipe is faithful), whether each ack records exactly the handed-in id, and drain.
    fn observe(cofres: &[Cofre]) -> Trace {
        let mut sub = LoopbackSubstrate::new();
        for c in cofres {
            sub.send(c).unwrap();
        }
        let mut steps = Vec::new();
        let mut idx = 0usize;
        while let Some(got) = sub.recv().unwrap() {
            sub.ack(got.etiqueta.cofre_id).unwrap();
            steps.push(RecvStep {
                position: idx,
                // The header routing fields the substrate is allowed to read…
                route_id: got.etiqueta.route_id,
                stream_id: got.etiqueta.stream_id,
                seq: got.etiqueta.seq,
                // …the pipe is faithful: what came out equals what went in, byte-for-byte.
                echoed_input_verbatim: cofres.get(idx) == Some(&got),
                // …and the ack records exactly the id it was handed (header-driven, not carga-driven).
                acked_handed_in_id: sub.acked().last() == Some(&got.etiqueta.cofre_id),
            });
            idx += 1;
        }
        Trace {
            steps,
            ack_count: sub.acked().len(),
            drained: sub.recv().unwrap().is_none(),
        }
    }

    /// One observed routing decision: position, the header fields the substrate may use, and two opacity
    /// invariants (faithful echo + handed-in-id ack) — all computable without reading `carga`.
    #[derive(Debug, PartialEq, Eq)]
    struct RecvStep {
        position: usize,
        route_id: [u8; 16],
        stream_id: [u8; 16],
        seq: u64,
        echoed_input_verbatim: bool,
        acked_handed_in_id: bool,
    }

    /// The substrate's observable decision structure over a flow. Independent of `carga` by the opacity
    /// claim — that independence is exactly what the AC-1 metamorphic test asserts.
    #[derive(Debug, PartialEq, Eq)]
    struct Trace {
        steps: Vec<RecvStep>,
        ack_count: usize,
        drained: bool,
    }

    #[test]
    fn ac1_metamorphic_opacity_payload_swap_is_unobservable() {
        // AC-1 (metamorphic opacity): take a sealed cofre; build a SECOND one identical except its `carga`
        // is replaced by ANOTHER validly-sealed ciphertext of EQUAL LENGTH (re-sealed via datarail-cofre).
        // The substrate routes/acks on the header alone, so its observable send/recv/ack behavior must be
        // IDENTICAL for the two flows — i.e. independent of the payload bytes (INV-OPAQUE-CARGO).
        let etq = etiqueta_seq(99);

        let carga_x = b"AAAAAAAAAAAAAAAA".to_vec();
        let carga_y = b"ZQ7k-3p!9xLm_w2#".to_vec(); // different bytes…
        assert_eq!(
            carga_x.len(),
            carga_y.len(),
            "metamorphic precondition: equal length"
        );

        // Two validly-sealed cofres with the SAME routing/header inputs, differing only in payload bytes.
        let cofre_x = seal(etq.clone(), carga_x.clone(), &FIXTURE_SEED);
        let cofre_y = seal(etq, carga_y.clone(), &FIXTURE_SEED);

        // Sanity: both are genuinely valid cofres (the swap is a re-seal, not a forgery)…
        let vk = verifying_key(&FIXTURE_SEED);
        verify(&cofre_x, &vk).expect("cofre_x is validly sealed");
        verify(&cofre_y, &vk).expect("cofre_y is validly sealed");
        // …and they really do differ only in the payload-derived parts (carga + its BLAKE3 id + the seal).
        assert_ne!(cofre_x.carga, cofre_y.carga);
        assert_eq!(cofre_x.carga.len(), cofre_y.carga.len());

        // The metamorphic relation: identical observable substrate behavior for the two flows.
        let trace_x = observe(std::slice::from_ref(&cofre_x));
        let trace_y = observe(std::slice::from_ref(&cofre_y));
        assert_eq!(
            trace_x, trace_y,
            "substrate behavior must be independent of the opaque payload bytes (INV-OPAQUE-CARGO)"
        );

        // And a stronger control: swapping carga UNDER A FIXED header (forcing cofre_id/lacre identical to
        // cofre_x) leaves the substrate's behavior bit-identical, proving carga is never read.
        let cofre_y_fixed_header = Cofre {
            etiqueta: cofre_x.etiqueta.clone(),
            carga: carga_y,
            lacre: cofre_x.lacre,
        };
        assert_eq!(
            observe(std::slice::from_ref(&cofre_x)),
            observe(std::slice::from_ref(&cofre_y_fixed_header)),
            "with header fields held fixed, payload bytes are invisible to the substrate"
        );
    }
}
