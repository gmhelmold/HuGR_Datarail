//! A **`Noise_KK`-protected substrate hop** — SPEC-08 F2 applied to the rail.
//!
//! [`NoiseSubstrate`] wraps a connected [`TcpStream`]: at construction it runs the `Noise_KK` handshake
//! (mutual static authentication + a forward-secret session, [`crate::noise`]), then tunnels each
//! already-sealed [`Cofre`] through the Noise transport. The cofre is sealed end-to-end independently — Noise
//! is **defense in depth on the wire**, and it buys two things the bare seal does not:
//!
//! 1. **Mutual endpoint authentication at the transport** — an unauthenticated peer cannot even establish the
//!    channel (the handshake fails against an impostor static key).
//! 2. **On-wire confidentiality of the cleartext etiqueta** — the routing metadata a bare-TCP observer would
//!    otherwise see (`signer_key_id`, `contract_fp`, `idempotency_key`) is encrypted, mitigating the SPEC-03
//!    "metadata residual" on the network path.
//!
//! It implements the same [`Substrate`] trait as every other transport (`type Error = io::Error`), so the
//! terminals do not know the difference.
//!
//! v1 scope: one cofre per Noise message (snow's 64 KiB-per-message limit); a cofre whose wire encoding
//! exceeds that is rejected (chunking a large cofre across Noise messages is a future extension — the `bao`
//! chunk machinery in `datarail-manifest` is the natural basis).

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use datarail_core::{Cofre, Substrate};

use crate::noise::{KkSession, NoiseError, StaticKeypair, Transport};

/// `snow`'s per-message ciphertext limit (the Noise spec's `65535`).
const MAX_NOISE_FRAME: usize = 65535;
/// `ChaChaPoly` AEAD tag overhead inside a Noise transport message.
const NOISE_TAG: usize = 16;
/// How long the handshake may take before giving up (so construction never hangs forever).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Short read-timeout for the transport phase so [`recv`](Substrate::recv) returns promptly when idle.
const RECV_TIMEOUT: Duration = Duration::from_millis(50);

/// Map a [`NoiseError`] to an [`io::Error`](std::io::Error) for the [`Substrate`] contract.
fn noise_io(e: &NoiseError) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// A [`Substrate`] that carries sealed cofres through a `Noise_KK` channel over a TCP connection.
pub struct NoiseSubstrate {
    tx: TcpStream,
    rx: TcpStream,
    transport: Transport,
    buf: Vec<u8>,
    acked: Vec<[u8; 32]>,
}

impl NoiseSubstrate {
    /// Establish the **initiator** side over `stream`: `local` is this endpoint's static keypair and
    /// `peer_static` is the pinned responder static public key. Runs the handshake, then returns the ready
    /// substrate.
    ///
    /// # Errors
    /// [`io::Error`](std::io::Error) on a socket failure or if the `Noise_KK` handshake fails (e.g. the peer
    /// presents the wrong pinned static key).
    pub fn initiator(
        stream: TcpStream,
        local: &StaticKeypair,
        peer_static: [u8; 32],
    ) -> std::io::Result<Self> {
        Self::establish(stream, local, peer_static, true)
    }

    /// Establish the **responder** side over `stream`. Mirror of [`initiator`](Self::initiator).
    ///
    /// # Errors
    /// [`io::Error`](std::io::Error) on a socket failure or a handshake authentication failure.
    pub fn responder(
        stream: TcpStream,
        local: &StaticKeypair,
        peer_static: [u8; 32],
    ) -> std::io::Result<Self> {
        Self::establish(stream, local, peer_static, false)
    }

    fn establish(
        stream: TcpStream,
        local: &StaticKeypair,
        peer_static: [u8; 32],
        initiator: bool,
    ) -> std::io::Result<Self> {
        stream.set_nodelay(true)?;
        let mut tx = stream;
        let mut rx = tx.try_clone()?;
        rx.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?; // blocking-ish reads during the handshake

        let mut session = if initiator {
            KkSession::initiator(local, peer_static).map_err(|e| noise_io(&e))?
        } else {
            KkSession::responder(local, peer_static).map_err(|e| noise_io(&e))?
        };

        // KK is a two-message handshake: the initiator sends first, the responder replies.
        if initiator {
            let m1 = session.write_handshake(&[]).map_err(|e| noise_io(&e))?;
            write_framed(&mut tx, &m1)?;
            let m2 = read_framed(&mut rx)?;
            session.read_handshake(&m2).map_err(|e| noise_io(&e))?;
        } else {
            let m1 = read_framed(&mut rx)?;
            session.read_handshake(&m1).map_err(|e| noise_io(&e))?;
            let m2 = session.write_handshake(&[]).map_err(|e| noise_io(&e))?;
            write_framed(&mut tx, &m2)?;
        }

        let transport = session.into_transport().map_err(|e| noise_io(&e))?;
        rx.set_read_timeout(Some(RECV_TIMEOUT))?;
        Ok(Self {
            tx,
            rx,
            transport,
            buf: Vec::new(),
            acked: Vec::new(),
        })
    }

    /// The `cofre_id`s acked so far, in ack order.
    #[must_use]
    pub fn acked(&self) -> &[[u8; 32]] {
        &self.acked
    }
}

impl Substrate for NoiseSubstrate {
    type Error = std::io::Error;

    /// Encrypt the wire-encoded cofre through the Noise transport and write a `u32`-length-prefixed frame.
    ///
    /// # Errors
    /// [`io::Error`](std::io::Error) on a write failure, a Noise failure, or if the cofre is too large for one
    /// Noise message.
    fn send(&mut self, cofre: &Cofre) -> Result<(), Self::Error> {
        let bytes = datarail_cofre::encode(cofre);
        if bytes.len() > MAX_NOISE_FRAME - NOISE_TAG {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cofre exceeds one Noise message (64 KiB)",
            ));
        }
        let ct = self.transport.encrypt(&bytes).map_err(|e| noise_io(&e))?;
        write_framed(&mut self.tx, &ct)
    }

    /// Drain whatever is readable, decode one complete length-prefixed Noise frame, decrypt it, and decode the
    /// cofre (`None` until a full frame has arrived). Never inspects the plaintext (`INV-OPAQUE-CARGO`).
    ///
    /// # Errors
    /// [`io::Error`](std::io::Error) on a read failure, an over-large frame, a Noise decrypt failure, or a
    /// cofre decode failure.
    fn recv(&mut self) -> Result<Option<Cofre>, Self::Error> {
        let mut tmp = [0u8; 8192];
        loop {
            match self.rx.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    self.buf.extend_from_slice(&tmp[..n]);
                    if self.buf.len() > MAX_NOISE_FRAME + 4 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "noise frame exceeds the maximum size",
                        ));
                    }
                }
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
        if len > MAX_NOISE_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "noise frame length exceeds the maximum size",
            ));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let frame = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        let plaintext = self.transport.decrypt(&frame).map_err(|e| noise_io(&e))?;
        let cofre = datarail_cofre::decode(&plaintext)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Some(cofre))
    }

    /// Record an acknowledgement (header-only).
    ///
    /// # Errors
    /// Never returns an error — recording is in-memory; the `Result` satisfies the [`Substrate`] contract.
    fn ack(&mut self, cofre_id: [u8; 32]) -> Result<(), Self::Error> {
        self.acked.push(cofre_id);
        Ok(())
    }
}

/// Write a `u32`-length-prefixed frame.
fn write_framed(tx: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame exceeds u32"))?;
    tx.write_all(&len.to_le_bytes())?;
    tx.write_all(bytes)?;
    tx.flush()
}

/// Read one `u32`-length-prefixed frame, blocking up to [`HANDSHAKE_TIMEOUT`] (handshake phase only).
fn read_framed(rx: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut hdr = [0u8; 4];
    read_exact_deadline(rx, &mut hdr, deadline)?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len > MAX_NOISE_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized handshake frame",
        ));
    }
    let mut body = vec![0u8; len];
    read_exact_deadline(rx, &mut body, deadline)?;
    Ok(body)
}

/// Fill `buf` exactly, tolerating short reads / timeouts until `deadline`.
fn read_exact_deadline(
    rx: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match rx.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed during handshake",
                ))
            }
            Ok(n) => filled += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "handshake read timed out",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::NoiseSubstrate;
    use crate::noise::StaticKeypair;
    use datarail_core::{AeadAlg, Cofre, Etiqueta, Substrate};
    use std::net::{TcpListener, TcpStream};

    /// A small validly-sealed cofre fixture.
    fn sample_cofre() -> Cofre {
        let etiqueta = Etiqueta {
            route_id: [1; 16],
            stream_id: [2; 16],
            seq: 3,
            cofre_id: [0; 32],
            idempotency_key: [4; 32],
            contract_fp: [5; 32],
            aead_alg: AeadAlg::Gcmsiv256,
            nonce: [6; 12],
            signer_key_id: [0; 32],
            eph_pk: [7; 32],
            sender_present: false,
            ts: 0,
        };
        datarail_cofre::seal(etiqueta, b"opaque-sealed-ciphertext".to_vec(), &[9u8; 32])
    }

    #[test]
    fn noise_hop_round_trips_a_sealed_cofre_over_real_tcp() {
        let a = StaticKeypair::generate().expect("keypair a");
        let b = StaticKeypair::generate().expect("keypair b");
        let a_pub = a.public();
        let b_pub = b.public();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let cofre = sample_cofre();
        let expected = cofre.clone();

        // Responder accepts, establishes the Noise channel pinning the initiator's static, and receives.
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().expect("accept");
            let mut dst = NoiseSubstrate::responder(s, &b, a_pub).expect("responder handshake");
            loop {
                if let Some(c) = dst.recv().expect("recv") {
                    return c;
                }
            }
        });

        let cs = TcpStream::connect(addr).expect("connect");
        let mut src = NoiseSubstrate::initiator(cs, &a, b_pub).expect("initiator handshake");
        src.send(&cofre).expect("send through noise channel");
        let got = server.join().expect("server thread");

        assert_eq!(
            got, expected,
            "the sealed cofre survived the Noise_KK channel byte-for-byte"
        );
    }

    #[test]
    fn responder_pinning_an_impostor_initiator_fails_the_handshake() {
        let a = StaticKeypair::generate().expect("a");
        let b = StaticKeypair::generate().expect("b");
        let impostor = StaticKeypair::generate().expect("impostor");
        let b_pub = b.public();
        let impostor_pub = impostor.public();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Responder pins the IMPOSTOR as the initiator → the real initiator's handshake must not authenticate.
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().expect("accept");
            NoiseSubstrate::responder(s, &b, impostor_pub).is_err()
        });

        let cs = TcpStream::connect(addr).expect("connect");
        // The initiator may error here, or succeed locally while the responder rejects — either way the
        // responder side must report failure (mutual auth held).
        let _ = NoiseSubstrate::initiator(cs, &a, b_pub);
        assert!(
            server.join().expect("server thread"),
            "responder must reject an impostor-pinned peer"
        );
    }
}
