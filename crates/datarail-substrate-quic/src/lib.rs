//! `datarail-substrate-quic` — the SPEC-07 QUIC **cross-host** substrate.
//!
//! QUIC carries opaque sealed cofres and provides streams / flow-control / NAT traversal. The **seal — not
//! TLS — provides confidentiality** (`INV-OPAQUE-CARGO`): the cofre is already AEAD-sealed before it touches
//! the wire, so the QUIC transport is a *blind relay* (the DERP pattern, SPEC 07). Consequently the client
//! deliberately **does not verify the server certificate** — authenticity/secrecy ride on the cofre's seal
//! (Ed25519 + per-cofre key-wrap), never on the transport's TLS. The dev cert embedded here exists only to
//! satisfy QUIC's mandatory TLS 1.3 handshake; it secures nothing and is not a secret.
//!
//! The substrate owns a Tokio runtime and drives quinn's async API via `block_on` behind the synchronous
//! [`Substrate`] trait. Each connection carries **one ordered uni-directional stream** of length-prefixed
//! cofres — a single QUIC stream is a reliable ordered byte channel, so framing + delivery order match the
//! TCP substrate exactly, and the shared [`substrate_conformance`](datarail_rail::substrate_conformance)
//! harness passes unchanged (`INV-SUBSTRATE-POLYMORPHIC`). The substrate holds **no keys** and does **no
//! crypto on the cofre** (`INV-DUMB-PIPE`). quinn uses the `ring` backend; this crate quarantines the heavy
//! QUIC dependency tree out of the std-only rail core (Charter *leveza*).
//!
//! ## Security: DEV-ONLY transport identity
//!
//! **This substrate must not be used where transport-layer authentication matters.**
//!
//! - **Public, committed cert/key.** `src/dev_cert.der` and `src/dev_key.der` are baked in via
//!   `include_bytes!` and are the *only* server identity this substrate presents. Both files are committed
//!   to the public repository, so the private key is not secret in any meaningful sense.
//!
//! - **Client accepts any server certificate.** `AcceptAnyServerCert` skips all certificate validation.
//!   There is no hostname check, no chain verification, and no revocation check.
//!
//! - **Active MITM can terminate the QUIC/TLS hop.** Because the server key is public and the client
//!   performs no certificate verification, an active on-path attacker can impersonate the server, terminate
//!   the TLS 1.3 handshake, and observe all QUIC transport metadata — route/stream IDs, sequence numbers,
//!   frame timing, and connection teardown patterns. The attacker can also drop or replay individual QUIC
//!   frames at will.
//!
//! - **Payload confidentiality and integrity still hold end-to-end.** Cofres are AEAD-sealed (ephemeral
//!   X25519 per-cofre key-wrap → AEAD) and Ed25519-signed before they reach this substrate
//!   (`INV-OPAQUE-CARGO`). An attacker who terminates
//!   the transport layer sees only opaque ciphertext and cannot forge or silently modify cofre payloads.
//!   This is the DERP blind-relay property (SPEC 07): the transport is deliberately untrusted.
//!
//! - **Production use requires real certs and real verification.** Deployments that need transport-layer
//!   peer authentication must replace the embedded cert/key pair with certificates issued by a trusted CA
//!   and must replace `AcceptAnyServerCert` with a verifier that validates the certificate chain and server
//!   identity. Until that is done, this substrate provides QUIC framing and flow control only — it provides
//!   no transport-layer security guarantees whatsoever.

#![forbid(unsafe_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use datarail_core::{Cofre, Substrate};

/// Dev transport cert + PKCS#8 P-256 key — **not a secret** (the seal, not TLS, secures the cofre). Embedded
/// to satisfy QUIC's mandatory TLS 1.3 handshake only.
const DEV_CERT_DER: &[u8] = include_bytes!("dev_cert.der");
const DEV_KEY_DER: &[u8] = include_bytes!("dev_key.der");
/// Application-layer protocol negotiation token; client and server must agree (QUIC requires ALPN).
const ALPN: &[u8] = b"datarail-quic-v1";
/// Per-step await budget so `recv` returns `None` promptly on an idle/empty transport instead of blocking.
const STEP_TIMEOUT: Duration = Duration::from_millis(500);

/// A loopback bind address on an ephemeral port (`127.0.0.1:0`).
fn loopback_any() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// The `ring` crypto provider (cc+perl present; avoids aws-lc-rs's nasm requirement).
fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client cert verifier that accepts **any** server certificate.
///
/// This is intentional and safe in this design: the cofre is sealed end-to-end (AEAD + Ed25519 + per-cofre
/// key-wrap), so transport TLS provides neither confidentiality nor authenticity here — QUIC is a blind relay
/// (SPEC 07, DERP pattern). Verifying the transport cert would add nothing the seal does not already give.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build the quinn server config (TLS 1.3, ALPN, dev cert) over the `ring` provider.
fn server_config() -> io::Result<quinn::ServerConfig> {
    let cert = rustls::pki_types::CertificateDer::from(DEV_CERT_DER.to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        DEV_KEY_DER.to_vec(),
    ));
    let mut crypto = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(io::Error::other)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qsc =
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(io::Error::other)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(qsc)))
}

/// Build the quinn client config (TLS 1.3, ALPN, blind-relay cert acceptance) over the `ring` provider.
fn client_config() -> io::Result<quinn::ClientConfig> {
    let provider = ring_provider();
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qcc =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(io::Error::other)?;
    Ok(quinn::ClientConfig::new(Arc::new(qcc)))
}

/// A **cross-host** [`Substrate`] over a QUIC connection (quinn). One ordered uni-stream of length-prefixed
/// cofres per connection. Three shapes: [`loopback_pair`](Self::loopback_pair) holds both ends locally
/// (conformance + same-host); [`connect`](Self::connect) is the source (send) side; [`server`](Self::server)
/// is the destination (recv) side — together a real two-host transfer.
pub struct QuicSubstrate {
    rt: tokio::runtime::Runtime,
    /// Server endpoint (destination side) — kept for lazy connection-accept in `recv` and to stay alive.
    server_ep: Option<quinn::Endpoint>,
    /// Client endpoint (source side) — kept alive so quinn's driver keeps the connection healthy.
    client_ep: Option<quinn::Endpoint>,
    send_conn: Option<quinn::Connection>,
    send_stream: Option<quinn::SendStream>,
    recv_conn: Option<quinn::Connection>,
    recv_stream: Option<quinn::RecvStream>,
    rxbuf: Vec<u8>,
    acked: Vec<[u8; 32]>,
}

impl QuicSubstrate {
    /// A same-object loopback pair over `127.0.0.1`: both endpoints + both connection directions held locally,
    /// so `send` (client → server uni stream) is received by `recv`. Used by the conformance harness and
    /// same-host hops.
    ///
    /// # Errors
    /// [`io::Error`] if the runtime, endpoints, TLS config, or the QUIC handshake fail.
    pub fn loopback_pair() -> io::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (server_ep, client_ep, send_conn, recv_conn) = rt.block_on(async {
            let server_ep = quinn::Endpoint::server(server_config()?, loopback_any())?;
            let server_addr = server_ep.local_addr()?;
            let mut client_ep = quinn::Endpoint::client(loopback_any())?;
            client_ep.set_default_client_config(client_config()?);
            // Accept on a spawned task so the client handshake and the server accept progress concurrently
            // (a bidirectional handshake deadlocks if either side is awaited to completion first).
            let accept_ep = server_ep.clone();
            let accept_task = tokio::spawn(async move { accept_one(&accept_ep).await });
            let send_conn = client_ep
                .connect(server_addr, "datarail")
                .map_err(io::Error::other)?
                .await
                .map_err(io::Error::other)?;
            let recv_conn = accept_task.await.map_err(io::Error::other)??;
            Ok::<_, io::Error>((server_ep, client_ep, send_conn, recv_conn))
        })?;
        Ok(Self {
            rt,
            server_ep: Some(server_ep),
            client_ep: Some(client_ep),
            send_conn: Some(send_conn),
            send_stream: None,
            recv_conn: Some(recv_conn),
            recv_stream: None,
            rxbuf: Vec::new(),
            acked: Vec::new(),
        })
    }

    /// The **source** (send) side: connect to a remote rail endpoint at `addr`.
    ///
    /// # Errors
    /// [`io::Error`] if the runtime, client endpoint, TLS config, or the QUIC handshake fail.
    pub fn connect(addr: SocketAddr) -> io::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (client_ep, send_conn) = rt.block_on(async {
            let mut client_ep = quinn::Endpoint::client(loopback_any())?;
            client_ep.set_default_client_config(client_config()?);
            let send_conn = client_ep
                .connect(addr, "datarail")
                .map_err(io::Error::other)?
                .await
                .map_err(io::Error::other)?;
            Ok::<_, io::Error>((client_ep, send_conn))
        })?;
        Ok(Self {
            rt,
            server_ep: None,
            client_ep: Some(client_ep),
            send_conn: Some(send_conn),
            send_stream: None,
            recv_conn: None,
            recv_stream: None,
            rxbuf: Vec::new(),
            acked: Vec::new(),
        })
    }

    /// The **destination** (recv) side: bind a server endpoint at `bind` (use port 0 for an ephemeral port;
    /// read it back with [`local_addr`](Self::local_addr)). The inbound connection + stream are accepted
    /// lazily on the first [`recv`](Substrate::recv).
    ///
    /// # Errors
    /// [`io::Error`] if the runtime, server endpoint, or TLS config fail.
    pub fn server(bind: SocketAddr) -> io::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let server_ep = rt.block_on(async { quinn::Endpoint::server(server_config()?, bind) })?;
        Ok(Self {
            rt,
            server_ep: Some(server_ep),
            client_ep: None,
            send_conn: None,
            send_stream: None,
            recv_conn: None,
            recv_stream: None,
            rxbuf: Vec::new(),
            acked: Vec::new(),
        })
    }

    /// The local socket address of whichever endpoint this substrate holds (the bound address for a
    /// [`server`](Self::server), so a source can be pointed at it).
    ///
    /// # Errors
    /// [`io::Error`] if no endpoint is held or the address cannot be read.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        if let Some(ep) = &self.server_ep {
            return ep.local_addr();
        }
        if let Some(ep) = &self.client_ep {
            return ep.local_addr();
        }
        Err(io::Error::other("no endpoint"))
    }

    /// The `cofre_id`s acked so far, in ack order.
    #[must_use]
    pub fn acked(&self) -> &[[u8; 32]] {
        &self.acked
    }
}

/// Accept exactly one inbound connection on `ep`, completing its handshake.
async fn accept_one(ep: &quinn::Endpoint) -> io::Result<quinn::Connection> {
    let incoming = ep
        .accept()
        .await
        .ok_or_else(|| io::Error::other("endpoint closed before a connection arrived"))?;
    incoming
        .accept()
        .map_err(io::Error::other)?
        .await
        .map_err(io::Error::other)
}

/// Open (lazily) the single uni send stream and write one length-prefixed cofre frame to it.
async fn send_frame(
    conn: &quinn::Connection,
    stream: &mut Option<quinn::SendStream>,
    bytes: &[u8],
) -> io::Result<()> {
    if bytes.len() > datarail_core::MAX_COFRE_WIRE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cofre exceeds the maximum wire size",
        ));
    }
    if stream.is_none() {
        *stream = Some(conn.open_uni().await.map_err(io::Error::other)?);
    }
    let Some(s) = stream.as_mut() else {
        return Err(io::Error::other("send stream unavailable"));
    };
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cofre exceeds u32 frame"))?;
    s.write_all(&len.to_le_bytes())
        .await
        .map_err(io::Error::other)?;
    s.write_all(bytes).await.map_err(io::Error::other)?;
    Ok(())
}

/// Drive one step toward receiving: lazily accept the inbound connection (server side) and the uni stream,
/// then read one chunk into `buf`. Returns `true` iff bytes were appended (so the caller can retry decode).
async fn fill_buf(
    server_ep: Option<&quinn::Endpoint>,
    recv_conn: &mut Option<quinn::Connection>,
    recv_stream: &mut Option<quinn::RecvStream>,
    buf: &mut Vec<u8>,
) -> io::Result<bool> {
    if recv_conn.is_none() {
        let Some(ep) = server_ep else {
            return Ok(false); // no recv side (e.g. a source-only `connect` substrate)
        };
        match tokio::time::timeout(STEP_TIMEOUT, accept_one(ep)).await {
            Ok(Ok(conn)) => *recv_conn = Some(conn),
            _ => return Ok(false),
        }
    }
    if recv_stream.is_none() {
        let Some(conn) = recv_conn.as_ref() else {
            return Ok(false);
        };
        match tokio::time::timeout(STEP_TIMEOUT, conn.accept_uni()).await {
            Ok(Ok(s)) => *recv_stream = Some(s),
            _ => return Ok(false),
        }
    }
    let Some(s) = recv_stream.as_mut() else {
        return Ok(false);
    };
    let mut tmp = [0u8; 16384];
    match tokio::time::timeout(STEP_TIMEOUT, s.read(&mut tmp)).await {
        Ok(Ok(Some(n))) if n > 0 => {
            buf.extend_from_slice(&tmp[..n]);
            // Bound buffering (AUDIT-03 F1): never hold more than one max-size frame.
            if buf.len() > datarail_core::MAX_COFRE_WIRE_LEN + 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream frame exceeds the maximum cofre size",
                ));
            }
            Ok(true)
        }
        Ok(Err(e)) => Err(io::Error::other(e)),
        _ => Ok(false),
    }
}

/// Decode one complete length-prefixed cofre from the front of `buf`, or `None` if a full frame has not yet
/// arrived. Routes from the bytes only — never inspects the plaintext.
fn decode_frame(buf: &mut Vec<u8>) -> io::Result<Option<Cofre>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[..4]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    // Reject an over-large declared frame up front (AUDIT-03 F1).
    if len > datarail_core::MAX_COFRE_WIRE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stream frame length exceeds the maximum cofre size",
        ));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let frame = buf[4..4 + len].to_vec();
    buf.drain(..4 + len);
    let cofre = datarail_cofre::decode(&frame)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(Some(cofre))
}

impl Substrate for QuicSubstrate {
    type Error = io::Error;

    /// Serialize the cofre (wire codec) and write a `u32`-length-prefixed frame to the uni send stream.
    ///
    /// # Errors
    /// [`io::Error`] if this substrate has no send side, the cofre exceeds a `u32` frame, or the write fails.
    fn send(&mut self, cofre: &Cofre) -> Result<(), Self::Error> {
        let conn = self.send_conn.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "this QUIC substrate has no send side",
            )
        })?;
        let bytes = datarail_cofre::encode(cofre);
        self.rt
            .block_on(send_frame(&conn, &mut self.send_stream, &bytes))
    }

    /// Return the next complete cofre, reading from the uni stream as needed; `None` once the transport is
    /// idle/empty (no full frame within the step budget). Never inspects `carga` (`INV-OPAQUE-CARGO`).
    ///
    /// # Errors
    /// [`io::Error`] on a read failure, or `InvalidData` if a framed cofre fails to decode.
    fn recv(&mut self) -> Result<Option<Cofre>, Self::Error> {
        loop {
            if let Some(cofre) = decode_frame(&mut self.rxbuf)? {
                return Ok(Some(cofre));
            }
            let progressed = self.rt.block_on(fill_buf(
                self.server_ep.as_ref(),
                &mut self.recv_conn,
                &mut self.recv_stream,
                &mut self.rxbuf,
            ))?;
            if !progressed {
                return Ok(None);
            }
        }
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
    use super::QuicSubstrate;
    use datarail_core::Substrate;
    use datarail_rail::{substrate_conformance, testsupport};
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn ac6_quic_passes_substrate_conformance() {
        // The SAME AC-6 flow over a REAL QUIC connection (loopback) — INV-SUBSTRATE-POLYMORPHIC now holds over
        // quinn too. The single ordered uni stream preserves the FIFO the harness asserts.
        substrate_conformance(|| QuicSubstrate::loopback_pair().expect("quic loopback pair"));
    }

    #[test]
    fn quic_two_endpoint_transfers_cofre_byte_for_byte() {
        // A genuine TWO-ENDPOINT transfer (separate server + client across threads, as a cross-host hop would
        // be): a cofre sealed at the source survives the QUIC transport byte-for-byte at the destination.
        let mut dst = QuicSubstrate::server(super::loopback_any()).expect("bind server");
        let addr = dst.local_addr().expect("server addr");
        let sent = testsupport::cofre_seq(7);
        let expected = sent.clone();

        // Keep the source alive (its runtime drives transmission) until the dest has the cofre.
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let src = thread::spawn(move || {
            let mut src = QuicSubstrate::connect(addr).expect("connect");
            src.send(&sent).expect("send");
            let _ = done_rx.recv(); // hold the connection open until main signals receipt
        });

        let got = loop {
            if let Some(c) = dst.recv().expect("recv") {
                dst.ack(c.etiqueta.cofre_id).expect("ack");
                break c;
            }
        };
        let _ = done_tx.send(());
        src.join().expect("source thread");

        assert_eq!(
            got, expected,
            "cofre survived a real cross-endpoint QUIC transport byte-for-byte"
        );
    }
}
