//! TLS termination for the Kafka hop (behind the `tls` feature, `KAFKA-TLS-DESIGN.md`).
//!
//! Wraps each accepted `TcpStream` in a synchronous rustls server handshake so `datarail kafka-ingest` /
//! `kafka-broker` can serve over TLS, while `datarail-kafka` itself stays dependency-free and transport-agnostic
//! (it sees only the [`ConnWrap`] seam). Server-side termination only — one-way auth (datarail presents a cert);
//! mTLS / client-cert is a tracked follow-up. The crypto provider is `ring`, consistent with the QUIC substrate.

use std::fs::File;
use std::io::{self, BufReader};
use std::net::TcpStream;
use std::sync::Arc;

use datarail_kafka::serve::{ConnWrap, ReadWrite};
use rustls::ServerConfig;

/// A [`ConnWrap`] that terminates TLS: each accepted socket completes a rustls handshake (lazily, on first I/O)
/// before the Kafka wire protocol is spoken over it.
pub struct TlsConn {
    config: Arc<ServerConfig>,
}

impl TlsConn {
    /// Build a server-side TLS terminator from a PEM cert chain + a PEM private key (PKCS#8 or RSA). When
    /// `client_ca` is `Some`, **mutual TLS** is required: the client must present a certificate chaining to that CA
    /// PEM, else the handshake fails (`KAFKA-MTLS-DESIGN.md`). `None` is one-way TLS (the server is authenticated).
    ///
    /// # Errors
    /// [`io::Error`] if a file can't be read, the PEM is malformed, no private key is present, the client-CA has no
    /// usable roots, or the cert/key pair is rejected by rustls.
    pub fn from_pem(
        cert_path: &str,
        key_path: &str,
        client_ca: Option<String>,
    ) -> io::Result<Self> {
        let bad =
            |e: &dyn std::fmt::Display| io::Error::new(io::ErrorKind::InvalidData, e.to_string());
        let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert_path)?))
            .collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no certificate in the cert PEM",
            ));
        }
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key_path)?))?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "no private key in the key PEM")
            })?;
        // Explicit ring provider + safe default protocol versions (TLS 1.3/1.2) — no reliance on a process-global
        // default provider being installed.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let base = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| bad(&e))?;
        let with_verifier = if let Some(ca_path) = client_ca {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(&ca_path)?))
                .collect::<Result<Vec<_>, _>>()?
            {
                roots.add(cert).map_err(|e| bad(&e))?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .map_err(|e| bad(&e))?;
            base.with_client_cert_verifier(verifier)
        } else {
            base.with_no_client_auth()
        };
        let config = with_verifier
            .with_single_cert(certs, key)
            .map_err(|e| bad(&e))?;
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

impl ConnWrap for TlsConn {
    fn wrap(&self, stream: TcpStream) -> io::Result<Box<dyn ReadWrite + Send>> {
        let conn = rustls::ServerConnection::new(Arc::clone(&self.config))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        // StreamOwned: Read + Write; the TLS handshake runs on the first read/write the serve loop performs.
        Ok(Box::new(rustls::StreamOwned::new(conn, stream)))
    }
}
