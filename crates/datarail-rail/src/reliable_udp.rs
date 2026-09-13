//! `reliable_udp` — a minimal **reliable, ordered datagram mover over UDP**, paced by the delay-based
//! [`DelayController`](crate::congestion::DelayController) (FASP physics: a lost datagram is recovered by
//! retransmission and **never** shrinks the congestion window — only measured RTT/queue growth does).
//!
//! This is the transport that wires the FASP *algorithm* to a *real* socket, so the WAN moat can be measured
//! over a real lossy link (`tc netem`) instead of only an in-process simulation. See the design contract in
//! `docs/design/FASP-UDP-TRANSPORT.md`.
//!
//! **Scope (S1–S4):** reliable framing, ACKs, in-order reassembly, retransmit-on-timeout, RTT samples feeding
//! the controller, loss recovery (S2), the real `tc netem` benchmark vs kernel TCP (S3), and the adversarial
//! audit (S4 — `docs/design/AUDIT-FASP.md`): receive-window flow control (bounded memory both sides), a `send`
//! liveness deadline (no infinite block), and an off-peer source-drop (off-path spoof resistance). The exactly-
//! once core is independently verified. The WAN *claim* stays DIRECTIONAL (loopback `netem`, n=2, modest
//! absolute throughput) — no PROVEN until a real-WAN field number.
//!
//! The mover carries **opaque bytes** (each `send` is one ≤[`MAX_FASP_PAYLOAD`] message delivered intact and in
//! order); the cofre is already sealed above this layer, so this is a dumb, confidential-by-construction pipe.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::congestion::DelayController;

/// Frame kinds on the wire.
const KIND_DATA: u8 = 1;
const KIND_ACK: u8 = 2;
/// Fixed header: `[seq:u64][kind:u8][len:u32]`, followed by `len` payload bytes and a trailing `[crc:u32]`.
const HEADER_LEN: usize = 8 + 1 + 4;
const CRC_LEN: usize = 4;
/// Largest per-message payload — kept well under a typical path MTU so a DATA frame is one un-fragmented IP
/// datagram (header + payload + crc ≤ ~1217 bytes).
pub const MAX_FASP_PAYLOAD: usize = 1200;
/// Receive scratch buffer — comfortably larger than any single frame (and any coalesced ACK datagram).
const DGRAM_BUF: usize = 2048;
/// On-the-wire length of one ACK frame (header + empty payload + crc): used to pack many ACKs into one datagram.
const ACK_FRAME_LEN: usize = HEADER_LEN + CRC_LEN;
/// Budget for a single coalesced-ACK datagram. Kept ≤ [`MAX_FASP_PAYLOAD`] so a packed-ACK datagram, like a
/// DATA frame, stays a single un-fragmented IP datagram on a typical path.
const ACK_DGRAM_BUDGET: usize = MAX_FASP_PAYLOAD;
/// Flush queued ACKs once this many accumulate during a single `pump` drain — one datagram's worth — so the ACK
/// buffer stays O(1) even under a sustained/duplicate DATA flood (WP6 audit HIGH fix).
const ACK_FLUSH_THRESHOLD: usize = ACK_DGRAM_BUDGET / ACK_FRAME_LEN;

/// Tuning for a [`FaspLink`].
#[derive(Debug, Clone, Copy)]
pub struct FaspCfg {
    /// Hard cap on un-acked messages in flight (bounds memory — `INV-FASP-BOUNDED`). S2 will additionally pace
    /// to `floor(window)`; S1 uses this integer cap so memory is bounded without a float→int conversion.
    pub max_inflight: usize,
    /// Retransmit timeout: a frame un-acked for longer than this is resent (and counted as a loss).
    pub rto: Duration,
    /// Initial congestion window handed to the [`DelayController`].
    pub init_window: f64,
    /// Minimum congestion window.
    pub min_window: f64,
    /// Maximum congestion window.
    pub max_window: f64,
    /// Queueing-delay threshold above which the controller treats the path as congested.
    pub queue_threshold: Duration,
    /// **Receive-window flow control (S4 fix F1/F1b):** the receiver buffers at most this many messages ahead of
    /// the lowest un-consumed one. A DATA frame whose `seq` falls outside `[base, base+recv_window)` is dropped
    /// and **not** acknowledged, so the sender retransmits it once the window slides — bounding the reorder +
    /// ready buffers to O(`recv_window`) (`INV-FASP-BOUNDED` on the *receive* side too, not just send). Set ≥
    /// `max_inflight`.
    pub recv_window: usize,
    /// **Send liveness deadline (S4 fix F3):** if `send` cannot make room within this long (the peer stopped
    /// acknowledging / vanished), it returns a `TimedOut` error instead of blocking forever.
    pub send_timeout: Duration,
    /// **Test/bench loss simulator** (0 = off): deterministically drop every Nth outgoing datagram before it
    /// hits the wire, to exercise loss recovery without a real network. Mirrors the established
    /// [`WanProfile`](crate::WanProfile)`::drop_every` pattern; the *real* loss number comes from `tc netem` (S3).
    pub loss_sim_drop_every: u32,
}

impl Default for FaspCfg {
    fn default() -> Self {
        Self {
            max_inflight: 64,
            rto: Duration::from_millis(50),
            init_window: 16.0,
            min_window: 1.0,
            max_window: 1024.0,
            queue_threshold: Duration::from_millis(5),
            recv_window: 8192,
            send_timeout: Duration::from_secs(30),
            loss_sim_drop_every: 0,
        }
    }
}

/// Observable counters for a [`FaspLink`].
#[derive(Debug, Clone, Copy)]
pub struct FaspStats {
    /// Messages delivered in order to the application.
    pub delivered: u64,
    /// Original (first-time) DATA frames sent.
    pub sent: u64,
    /// Retransmitted DATA frames.
    pub retransmits: u64,
    /// Current congestion window.
    pub window: f64,
    /// Learned base (uncongested) RTT.
    pub base_rtt: Duration,
    /// Losses inferred by the controller (timeout-driven).
    pub losses: u64,
}

/// What can go wrong moving bytes over a [`FaspLink`].
#[derive(Debug)]
pub enum FaspError {
    /// Underlying socket error.
    Io(std::io::Error),
    /// A `send` payload exceeded [`MAX_FASP_PAYLOAD`].
    TooLarge(usize),
}

impl fmt::Display for FaspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "fasp io: {e}"),
            Self::TooLarge(n) => write!(
                f,
                "fasp message {n} bytes exceeds the {MAX_FASP_PAYLOAD}-byte limit"
            ),
        }
    }
}

impl std::error::Error for FaspError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::TooLarge(_) => None,
        }
    }
}

impl From<std::io::Error> for FaspError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// IEEE CRC-32 over `bytes` (same polynomial as the WAL framing). Computed lazily without a static table to keep
/// the module self-contained; the input is one small datagram, so the cost is negligible.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// An un-acked, in-flight message awaiting its ACK.
struct InFlight {
    frame: Vec<u8>,
    sent_at: Instant,
    last_tx: Instant,
    /// Whether this frame has been retransmitted — if so, its ACK is **not** used as an RTT sample (Karn's
    /// algorithm: a retransmitted frame's ACK is ambiguous as to which transmission it answers, so sampling it
    /// would feed the controller a spuriously inflated RTT and collapse the window under loss).
    retransmitted: bool,
}

/// A reliable, ordered datagram mover over a connected UDP socket pair, paced by a [`DelayController`].
pub struct FaspLink {
    sock: UdpSocket,
    peer: Option<SocketAddr>,
    cfg: FaspCfg,
    cc: DelayController,
    // Send side.
    next_seq: u64,
    inflight: BTreeMap<u64, InFlight>,
    sent: u64,
    retransmits: u64,
    tx_count: u64,
    /// Seqs awaiting acknowledgement, accumulated across one `pump` drain and flushed as a few coalesced
    /// datagrams (many ACK frames per datagram) instead of one tiny datagram per DATA frame — amortizing the
    /// per-datagram syscall on both the receiver's send and the sender's recv. Drained every flush, so it is
    /// bounded by the datagrams processed in a single `pump` (`INV-FASP-BOUNDED` holds).
    pending_acks: Vec<u64>,
    // Receive side.
    next_deliver: u64,
    reorder: BTreeMap<u64, Vec<u8>>,
    ready: std::collections::VecDeque<Vec<u8>>,
    delivered: u64,
}

impl FaspLink {
    /// Bind a UDP socket at `local` with the given tuning; the peer is set later with [`set_peer`](Self::set_peer)
    /// (or use [`connect`](Self::connect) to do both at once). Binding first lets two endpoints discover each
    /// other's ephemeral ports before pointing at one another.
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] if the socket cannot be bound or set non-blocking.
    pub fn bind(local: SocketAddr, cfg: FaspCfg) -> Result<Self, FaspError> {
        let sock = UdpSocket::bind(local)?;
        sock.set_nonblocking(true)?;
        let cc = DelayController::new(
            cfg.init_window,
            cfg.min_window,
            cfg.max_window,
            cfg.queue_threshold,
        );
        Ok(Self {
            sock,
            peer: None,
            cfg,
            cc,
            next_seq: 0,
            inflight: BTreeMap::new(),
            sent: 0,
            retransmits: 0,
            tx_count: 0,
            pending_acks: Vec::new(),
            next_deliver: 0,
            reorder: BTreeMap::new(),
            ready: std::collections::VecDeque::new(),
            delivered: 0,
        })
    }

    /// Bind at `local` and target `peer` in one call.
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] if the socket cannot be bound or set non-blocking.
    pub fn connect(local: SocketAddr, peer: SocketAddr, cfg: FaspCfg) -> Result<Self, FaspError> {
        let mut link = Self::bind(local, cfg)?;
        link.set_peer(peer);
        Ok(link)
    }

    /// Point this link at its peer (the destination for `send`/retransmit).
    pub fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = Some(peer);
    }

    fn peer(&self) -> Result<SocketAddr, FaspError> {
        self.peer.ok_or_else(|| {
            FaspError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "fasp peer unset",
            ))
        })
    }

    /// Put one datagram on the wire, honoring the test/bench loss simulator: every Nth send is silently
    /// dropped (as a real lossy path would), which retransmission then recovers.
    fn wire_send(&mut self, frame: &[u8], addr: SocketAddr) -> Result<(), FaspError> {
        self.tx_count += 1;
        let drop_every = u64::from(self.cfg.loss_sim_drop_every);
        if drop_every != 0 && self.tx_count.is_multiple_of(drop_every) {
            return Ok(()); // simulated egress loss
        }
        self.sock.send_to(frame, addr)?;
        Ok(())
    }

    /// The local address the socket bound to (useful when `local` requested an ephemeral port).
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] if the local address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, FaspError> {
        Ok(self.sock.local_addr()?)
    }

    /// Reliably enqueue one ≤[`MAX_FASP_PAYLOAD`] message for in-order delivery to the peer. Blocks (pumping the
    /// socket) while the in-flight window is full, up to [`FaspCfg::send_timeout`] — after which it errors rather
    /// than blocking forever (S4 fix F3: a vanished/withholding peer must not wedge the caller). The caller is
    /// expected to also pump the peer.
    ///
    /// # Errors
    /// [`FaspError::TooLarge`] if the payload exceeds the limit; [`FaspError::Io`] on a socket error or if the
    /// in-flight window cannot drain within `send_timeout` (`TimedOut` — the peer is not acknowledging).
    pub fn send(&mut self, payload: &[u8]) -> Result<(), FaspError> {
        if payload.len() > MAX_FASP_PAYLOAD {
            return Err(FaspError::TooLarge(payload.len()));
        }
        // Pace to the FASP window (soft, rate control) AND max_inflight (hard, memory bound): drain ACKs /
        // retransmit until there is room — but give up after send_timeout so a dead peer can't wedge us forever.
        let block_deadline = Instant::now() + self.cfg.send_timeout;
        while !self.can_send() {
            self.pump()?;
            if !self.can_send() {
                if Instant::now() >= block_deadline {
                    return Err(FaspError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "fasp send blocked: in-flight window will not drain (peer not acknowledging)",
                    )));
                }
                std::thread::sleep(Duration::from_micros(50));
            }
        }
        let peer = self.peer()?;
        let seq = self.next_seq;
        self.next_seq += 1;
        let frame = encode_frame(seq, KIND_DATA, payload);
        self.wire_send(&frame, peer)?;
        let now = Instant::now();
        self.inflight.insert(
            seq,
            InFlight {
                frame,
                sent_at: now,
                last_tx: now,
                retransmitted: false,
            },
        );
        self.sent += 1;
        Ok(())
    }

    /// Pump the socket once (process all pending datagrams) then deliver the next in-order message if ready.
    ///
    /// # Errors
    /// [`FaspError::Io`] on a socket error other than "would block".
    pub fn recv(&mut self) -> Result<Option<Vec<u8>>, FaspError> {
        self.pump()?;
        Ok(self.ready.pop_front())
    }

    /// Drain every pending datagram, ACK/deliver DATA, retire acknowledged in-flight (feeding an RTT sample), and
    /// retransmit anything past its RTO (counting it as a loss — which, per FASP physics, does not cut the
    /// window).
    ///
    /// # Errors
    /// [`FaspError::Io`] on a socket error other than "would block".
    pub fn pump(&mut self) -> Result<(), FaspError> {
        let mut buf = [0u8; DGRAM_BUF];
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => self.on_datagram(&buf[..n], from),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(FaspError::Io(e)),
            }
            // WP6 audit HIGH fix: flush ACKs INCREMENTALLY once a datagram's worth has accumulated, so a sustained
            // (or duplicate) DATA flood cannot grow `pending_acks` without bound during a long drain — restoring
            // INV-FASP-BOUNDED on the ACK buffer too (it was previously flushed only after the whole drain).
            if self.pending_acks.len() >= ACK_FLUSH_THRESHOLD {
                self.flush_acks()?;
            }
        }
        self.flush_acks()?;
        self.retransmit_due()?;
        Ok(())
    }

    /// Send every ACK accumulated during this `pump`'s drain, packed into as few datagrams as fit under
    /// [`ACK_DGRAM_BUDGET`] — one `send_to` for up to ~70 ACKs instead of one per frame. A dropped coalesced
    /// datagram is harmless: the un-acked DATA simply retransmits on RTO and is re-ACKed, so reliability and
    /// exactly-once are unchanged.
    fn flush_acks(&mut self) -> Result<(), FaspError> {
        if self.pending_acks.is_empty() {
            return Ok(());
        }
        let acks = std::mem::take(&mut self.pending_acks);
        let Some(peer) = self.peer else {
            return Ok(()); // no peer to ACK (acks already drained, bound restored)
        };
        let mut dgram: Vec<u8> = Vec::with_capacity(ACK_DGRAM_BUDGET);
        for seq in acks {
            if !dgram.is_empty() && dgram.len() + ACK_FRAME_LEN > ACK_DGRAM_BUDGET {
                self.wire_send(&dgram, peer)?;
                dgram.clear();
            }
            encode_frame_into(&mut dgram, seq, KIND_ACK, &[]);
        }
        if !dgram.is_empty() {
            self.wire_send(&dgram, peer)?;
        }
        Ok(())
    }

    fn on_datagram(&mut self, dgram: &[u8], from: SocketAddr) {
        // S4 fix F4: once we know our peer, drop datagrams from any other source. CRC is an error-detector, not a
        // MAC, so off-path UDP spoofing could otherwise forge an ACK (silent loss) or inject DATA. This defeats
        // blind off-path spoofing cheaply; on-path integrity comes from the sealed cofre layer above.
        if let Some(peer) = self.peer {
            if from != peer {
                return;
            }
        }
        // A datagram carries one or more concatenated frames (DATA is sent one-per-datagram; ACKs are coalesced
        // many-per-datagram). Parse frame by frame; on the first malformed/corrupt frame drop the remainder —
        // reliability recovers the lost frames via retransmit, exactly as a whole-datagram drop would.
        let mut off = 0;
        while off < dgram.len() {
            let Some((seq, kind, payload, consumed)) = decode_frame_at(&dgram[off..]) else {
                return;
            };
            off += consumed;
            match kind {
                KIND_DATA => {
                    // S4 fix F1/F1b: receive-window flow control. `base` is the lowest un-consumed seq (front of
                    // the ready queue); a frame outside [base, base+recv_window) is dropped WITHOUT an ACK, so the
                    // sender retransmits once the window slides. This bounds reorder + ready to O(recv_window)
                    // regardless of a hostile peer's seqs — INV-FASP-BOUNDED on the receive side.
                    let base = self.next_deliver - self.ready.len() as u64;
                    if seq >= base.saturating_add(self.cfg.recv_window as u64) {
                        continue;
                    }
                    // Always ACK an in-window frame (even a duplicate) so the sender can retire it and stop
                    // resending; the ACK is queued and flushed (coalesced) at the end of this pump.
                    self.pending_acks.push(seq);
                    if seq >= self.next_deliver && !self.reorder.contains_key(&seq) {
                        self.reorder.insert(seq, payload.to_vec());
                        while let Some(bytes) = self.reorder.remove(&self.next_deliver) {
                            self.ready.push_back(bytes);
                            self.delivered += 1;
                            self.next_deliver += 1;
                        }
                    }
                }
                KIND_ACK => {
                    if let Some(f) = self.inflight.remove(&seq) {
                        if !f.retransmitted {
                            self.cc.on_rtt_sample(f.sent_at.elapsed());
                        }
                    }
                }
                _ => {} // unknown kind → ignore
            }
        }
    }

    fn retransmit_due(&mut self) -> Result<(), FaspError> {
        let Some(peer) = self.peer else { return Ok(()) };
        let now = Instant::now();
        let due: Vec<u64> = self
            .inflight
            .iter()
            .filter(|(_, f)| now.duration_since(f.last_tx) >= self.cfg.rto)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in due {
            if let Some(f) = self.inflight.get_mut(&seq) {
                let frame = f.frame.clone();
                f.last_tx = now;
                f.retransmitted = true;
                self.wire_send(&frame, peer)?;
                self.retransmits += 1;
                self.cc.on_loss();
            }
        }
        Ok(())
    }

    /// Snapshot of the observable counters.
    #[must_use]
    pub fn stats(&self) -> FaspStats {
        FaspStats {
            delivered: self.delivered,
            sent: self.sent,
            retransmits: self.retransmits,
            window: self.cc.window(),
            base_rtt: self.cc.base_rtt(),
            losses: self.cc.losses(),
        }
    }

    /// Count of messages still un-acked in flight.
    #[must_use]
    pub fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    /// Total messages buffered on the receive side (out-of-order `reorder` + delivered-but-un-consumed `ready`).
    /// Bounded by [`FaspCfg::recv_window`] (S4 fix F1/F1b) — exposed so callers/gates can assert that bound.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.reorder.len() + self.ready.len()
    }

    /// May a new message go out now? Gated by the FASP congestion window (rate control — loss never shrinks it,
    /// RTT growth does) and the hard `max_inflight` memory bound. The in-flight count is converted to `f64`
    /// losslessly via `u32` (it never approaches `u32::MAX` in practice) so no float→int cast is needed.
    fn can_send(&self) -> bool {
        if self.inflight.len() >= self.cfg.max_inflight {
            return false;
        }
        let inflight = f64::from(u32::try_from(self.inflight.len()).unwrap_or(u32::MAX));
        inflight < self.cc.window()
    }
}

/// Encode `[seq][kind][len][payload][crc]` (little-endian). `payload.len()` is always ≤ [`MAX_FASP_PAYLOAD`]
/// (enforced by callers), so the `len` field fits a `u32`.
fn encode_frame(seq: u64, kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(HEADER_LEN + payload.len() + CRC_LEN);
    encode_frame_into(&mut f, seq, kind, payload);
    f
}

/// Append one `[seq][kind][len][payload][crc]` frame to `buf` (the CRC covers only this frame's bytes), so several
/// frames can be packed into one datagram. `payload.len()` is always ≤ [`MAX_FASP_PAYLOAD`] (enforced by callers),
/// so the `len` field fits a `u32`.
fn encode_frame_into(buf: &mut Vec<u8>, seq: u64, kind: u8, payload: &[u8]) {
    let start = buf.len();
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.push(kind);
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    let crc = crc32(&buf[start..]);
    buf.extend_from_slice(&crc.to_le_bytes());
}

/// Decode + verify the frame at the front of `dgram`, returning `(seq, kind, payload, bytes_consumed)` so the
/// caller can advance to the next frame in a coalesced datagram. Returns `None` on any malformed/corrupt or
/// truncated frame (length mismatch, bad CRC, oversize payload) — the caller treats that as a drop, which
/// retransmission recovers.
fn decode_frame_at(dgram: &[u8]) -> Option<(u64, u8, &[u8], usize)> {
    if dgram.len() < HEADER_LEN + CRC_LEN {
        return None;
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&dgram[9..13]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FASP_PAYLOAD {
        return None; // a peer trying to push a larger-than-spec payload (S4 fix F8)
    }
    let body_len = HEADER_LEN + len;
    let frame_len = body_len + CRC_LEN;
    if dgram.len() < frame_len {
        return None; // truncated: the declared payload runs past the datagram
    }
    let mut crc_bytes = [0u8; 4];
    crc_bytes.copy_from_slice(&dgram[body_len..frame_len]);
    if u32::from_le_bytes(crc_bytes) != crc32(&dgram[..body_len]) {
        return None;
    }
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&dgram[..8]);
    let seq = u64::from_le_bytes(seq_bytes);
    let kind = dgram[8];
    Some((seq, kind, &dgram[HEADER_LEN..body_len], frame_len))
}

#[cfg(test)]
mod s4_gates {
    //! S4 adversarial-audit regression gates: every CRITICAL/HIGH finding from the [`FaspLink`] audit, fixed at
    //! the root and pinned here so it can never silently regress.
    use super::{encode_frame, FaspCfg, FaspError, FaspLink, KIND_DATA};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::time::Duration;

    fn loopback() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    #[test]
    fn f1_reorder_buffer_is_bounded_by_recv_window_under_hostile_gap_seqs() {
        let cfg = FaspCfg {
            recv_window: 256,
            ..FaspCfg::default()
        };
        let mut b = FaspLink::bind(loopback(), cfg).expect("bind b");
        let b_addr = b.local_addr().expect("b addr");
        let attacker = UdpSocket::bind(loopback()).expect("attacker bind");
        b.set_peer(attacker.local_addr().expect("atk addr")); // pass the F4 source-check; isolate F1
                                                              // Flood seqs 1..10000 but never seq 0 → a permanent gap → all want to sit in `reorder`. Pre-fix this
                                                              // grew unbounded (OOM); post-fix only [base, base+recv_window) is accepted.
        for seq in 1u64..10_000 {
            let f = encode_frame(seq, KIND_DATA, &[7, 7, 7]);
            attacker.send_to(&f, b_addr).expect("atk send");
        }
        for _ in 0..50 {
            b.pump().expect("pump");
        }
        assert!(
            b.buffered_len() <= cfg.recv_window,
            "reorder unbounded: buffered {} > recv_window {}",
            b.buffered_len(),
            cfg.recv_window
        );
    }

    #[test]
    fn f4_datagram_from_a_non_peer_source_is_dropped() {
        let mut b = FaspLink::bind(loopback(), FaspCfg::default()).expect("bind b");
        let b_addr = b.local_addr().expect("b addr");
        // b's peer is some OTHER address; a forged-but-valid DATA from a different source must be ignored.
        b.set_peer(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)));
        let spoofer = UdpSocket::bind(loopback()).expect("spoofer bind");
        let f = encode_frame(0, KIND_DATA, &[1, 2, 3]);
        spoofer.send_to(&f, b_addr).expect("spoof send");
        for _ in 0..20 {
            b.pump().expect("pump");
        }
        assert_eq!(b.buffered_len(), 0, "off-peer forged DATA was accepted");
        assert!(
            b.recv().expect("recv").is_none(),
            "off-peer forged DATA was delivered"
        );
    }

    #[test]
    fn f3_send_times_out_instead_of_blocking_forever_when_peer_never_acks() {
        let cfg = FaspCfg {
            max_inflight: 4,
            init_window: 4.0,
            send_timeout: Duration::from_millis(200),
            ..FaspCfg::default()
        };
        let mut a = FaspLink::bind(loopback(), cfg).expect("bind a");
        // A real bound socket that NEVER pumps/ACKs → A's window fills and can never drain.
        let dead = UdpSocket::bind(loopback()).expect("dead bind");
        a.set_peer(dead.local_addr().expect("dead addr"));
        let mut err = None;
        for _ in 0..100 {
            if let Err(e) = a.send(&[9]) {
                err = Some(e);
                break;
            }
        }
        match err {
            Some(FaspError::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "wrong error kind");
            }
            other => panic!("send did not time out; got {other:?}"),
        }
    }
}
