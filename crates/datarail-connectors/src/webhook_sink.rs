//! `WebhookSink` — POST each committed batch to an HTTP endpoint as newline-delimited records (NDJSON-style),
//! over `std::net::TcpStream`, zero-dependency. The offloading terminal calls `commit` only after verify → open
//! → contract → dedup, so the endpoint receives exactly the records to deliver. Pairs with [`crate::HttpSource`]:
//! one datarail rail can move data from any HTTP API to any HTTP webhook, sealed end-to-end in between.

use std::io::{self, Read as _, Write as _};
use std::net::TcpStream;

/// Hard cap on the endpoint's response we will buffer — a malicious endpoint cannot OOM us.
const MAX_WEBHOOK_RESPONSE: u64 = 8 * 1024 * 1024;

/// An HTTP webhook sink: each `commit` POSTs the batch (records joined by `\n`) to the configured URL.
#[derive(Debug, Clone)]
pub struct WebhookSink {
    host: String,
    port: u16,
    path: String,
}

impl WebhookSink {
    /// Build a sink that POSTs to `url` (`http://host[:port]/path`; HTTP only, no TLS).
    ///
    /// # Errors
    /// [`io::Error`] (`InvalidInput`) if the URL is not a well-formed `http://` URL.
    pub fn post(url: &str) -> io::Result<Self> {
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "webhook url must start with http://",
            )
        })?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "webhook url has no host",
            ));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port = p.parse::<u16>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "webhook url has a bad port")
                })?;
                (h.to_owned(), port)
            }
            None => (authority.to_owned(), 80),
        };
        Ok(Self {
            host,
            port,
            path: path.to_owned(),
        })
    }

    /// Build the request body: records joined by `\n` with a trailing `\n` (NDJSON-style), empty if no records.
    fn body(records: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        for record in records {
            buf.extend_from_slice(record);
            buf.push(b'\n');
        }
        buf
    }
}

impl crate::Sink for WebhookSink {
    fn commit(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let body = Self::body(records);
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))?;
        let header = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.host,
            body.len()
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(&body)?;
        stream.flush()?;

        // Bound the response read: a malicious/compromised endpoint cannot OOM us by streaming forever.
        let mut response = Vec::new();
        std::io::Read::take(&mut stream, MAX_WEBHOOK_RESPONSE).read_to_end(&mut response)?;
        let status = parse_status(&response)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(io::Error::other(format!("webhook returned HTTP {status}")))
        }
    }
}

/// Parse the numeric status code from an HTTP response's status line (`HTTP/1.1 <code> ...`).
fn parse_status(response: &[u8]) -> io::Result<u16> {
    let line_end = response
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(response.len());
    let line = std::str::from_utf8(&response[..line_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 status line"))?;
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no status code in response"))
}

#[cfg(test)]
mod tests {
    use super::WebhookSink;
    use crate::Sink as _;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    #[test]
    fn malformed_url_rejected() {
        assert!(WebhookSink::post("ftp://x/y").is_err());
        assert!(WebhookSink::post("http://").is_err());
        assert!(WebhookSink::post("http://h:notaport/").is_err());
    }

    #[test]
    fn body_is_ndjson() {
        let b = WebhookSink::body(&[b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(b, b"a\nb\n");
        assert!(WebhookSink::body(&[]).is_empty());
    }

    #[test]
    fn posts_batch_and_reads_2xx() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            // The request (header + body) may arrive across several TCP reads — accumulate until the body's end.
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = sock.read(&mut buf).expect("read");
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.ends_with(b"evt:one\nevt:two\n") {
                    break;
                }
            }
            sock.write_all(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .expect("respond");
            String::from_utf8_lossy(&req).to_string()
        });
        let mut sink = WebhookSink::post(&format!("http://{addr}/ingest")).expect("sink");
        sink.commit(&[b"evt:one".to_vec(), b"evt:two".to_vec()])
            .expect("commit");
        let req = handle.join().expect("join");
        assert!(req.starts_with("POST /ingest HTTP/1.1"), "request: {req}");
        assert!(
            req.contains("Content-Length: 16"),
            "ndjson body length wrong: {req}"
        );
        assert!(req.ends_with("evt:one\nevt:two\n"), "body: {req}");
    }

    #[test]
    fn non_2xx_is_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });
        let mut sink = WebhookSink::post(&format!("http://{addr}/x")).expect("sink");
        assert!(sink.commit(&[b"evt:x".to_vec()]).is_err());
    }

    #[test]
    fn empty_batch_is_noop() {
        // No server: an empty commit must not even open a connection.
        let mut sink = WebhookSink::post("http://127.0.0.1:1/none").expect("sink");
        assert!(sink.commit(&[]).is_ok());
    }
}
