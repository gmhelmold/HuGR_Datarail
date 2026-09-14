//! An HTTP/1.1 source connector (std only, no TLS): one GET fetch = one batch, then drained — the network
//! sibling of [`crate::LineFileSource`]. It parses a `http://host[:port]/path` URL, opens a [`TcpStream`],
//! sends a `Connection: close` GET, reads the full response, decodes the body (`Content-Length`, chunked, or
//! read-to-EOF), and yields each non-empty LF-delimited line as one record. Zero dependencies: the terminal
//! still enforces the content contract and seals — this connector stays datarail-agnostic.

use std::io::{self, Read as _, Write as _};
use std::net::TcpStream;

/// A source that fetches records once over HTTP/1.1 and yields them as a single batch, then drains.
#[derive(Debug)]
pub struct HttpSource {
    batch: Option<Vec<Vec<u8>>>,
}

impl HttpSource {
    /// Fetch `url` (a `http://host[:port]/path` address — HTTP only, no TLS) and stage its body as one batch
    /// of line-records (each non-empty LF-delimited line is one record; a trailing CR is stripped).
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] if the URL is malformed; [`io::ErrorKind::InvalidData`] on a non-2xx
    /// status or a malformed response; otherwise the underlying connect/read [`io::Error`].
    pub fn get(url: &str) -> io::Result<Self> {
        let target = Target::parse(url)?;
        let body = fetch(&target)?;
        let batch: Vec<Vec<u8>> = body
            .split(|&b| b == b'\n')
            .map(strip_cr)
            .filter(|line| !line.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
        Ok(Self { batch: Some(batch) })
    }
}

impl crate::Source for HttpSource {
    fn next_batch(&mut self) -> io::Result<Option<Vec<Vec<u8>>>> {
        Ok(self.batch.take())
    }
}

/// Drop a single trailing carriage return so a CRLF-delimited body splits cleanly.
fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((&b'\r', rest)) => rest,
        _ => line,
    }
}

/// A parsed HTTP target: where to connect and what to request.
#[derive(Debug)]
struct Target {
    host: String,
    port: u16,
    path: String,
}

impl Target {
    /// Parse `http://host[:port]/path`. HTTP only; default port 80; empty path becomes `/`.
    fn parse(url: &str) -> io::Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| invalid_input("url must start with http://"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => {
                let (a, p) = rest.split_at(i);
                (a, p.to_owned())
            }
            None => (rest, "/".to_owned()),
        };
        if authority.is_empty() {
            return Err(invalid_input("url has no host"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| invalid_input("url has an invalid port"))?;
                (h, port)
            }
            None => (authority, 80),
        };
        if host.is_empty() {
            return Err(invalid_input("url has no host"));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            path,
        })
    }
}

/// Hard cap on a server response we will buffer — a malicious or compromised endpoint (the hop is plaintext)
/// cannot OOM us by streaming forever or lying about `Content-Length`.
const MAX_HTTP_RESPONSE: u64 = 64 * 1024 * 1024;

/// Connect, send the GET, read the full response (capped), and return the decoded body bytes.
fn fetch(target: &Target) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect((target.host.as_str(), target.port))?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target.path, target.host
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = Vec::new();
    std::io::Read::take(&mut stream, MAX_HTTP_RESPONSE).read_to_end(&mut response)?;
    if u64::try_from(response.len()).unwrap_or(u64::MAX) >= MAX_HTTP_RESPONSE {
        return Err(invalid_data("HTTP response exceeds the 64 MiB cap"));
    }

    let split = find_subslice(&response, b"\r\n\r\n")
        .ok_or_else(|| invalid_data("response has no header terminator"))?;
    let headers = response.get(..split).unwrap_or(&[]);
    let body_start = split + 4;
    let body = response.get(body_start..).unwrap_or(&[]);

    let header_text =
        std::str::from_utf8(headers).map_err(|_| invalid_data("response headers are not utf-8"))?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| invalid_data("response has no status line"))?;
    check_status(status)?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| invalid_data("invalid content-length"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
    }

    if chunked {
        decode_chunked(body)
    } else if let Some(len) = content_length {
        if len > body.len() {
            return Err(invalid_data(
                "HTTP response truncated: body shorter than Content-Length",
            ));
        }
        Ok(body.get(..len).unwrap_or(&[]).to_vec())
    } else {
        Ok(body.to_vec())
    }
}

/// Accept only a `2xx` status from an `HTTP/1.x <code> <reason>` status line.
fn check_status(status_line: &str) -> io::Result<()> {
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| invalid_data("malformed status line"))?;
    let code: u16 = code
        .parse()
        .map_err(|_| invalid_data("non-numeric status code"))?;
    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(invalid_data(format!("http status {code}")))
    }
}

/// Decode an HTTP/1.1 `Transfer-Encoding: chunked` body into its raw bytes.
fn decode_chunked(mut body: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find_subslice(body, b"\r\n")
            .ok_or_else(|| invalid_data("chunked body missing size line"))?;
        let size_field = body.get(..line_end).unwrap_or(&[]);
        // A chunk size may carry `;ext` extensions — keep only the hex size token.
        let size_hex = size_field.split(|&b| b == b';').next().unwrap_or(&[]);
        let size_str = std::str::from_utf8(size_hex)
            .map_err(|_| invalid_data("chunk size is not utf-8"))?
            .trim();
        let size =
            usize::from_str_radix(size_str, 16).map_err(|_| invalid_data("invalid chunk size"))?;
        let data_start = line_end + 2;
        if size == 0 {
            break;
        }
        let data_end = data_start
            .checked_add(size)
            .ok_or_else(|| invalid_data("chunk size overflow"))?;
        let chunk = body
            .get(data_start..data_end)
            .ok_or_else(|| invalid_data("chunk truncated"))?;
        out.extend_from_slice(chunk);
        // Skip the chunk's trailing CRLF.
        body = body
            .get(data_end + 2..)
            .ok_or_else(|| invalid_data("chunk missing trailing crlf"))?;
    }
    Ok(out)
}

/// Index of the first occurrence of `needle` in `haystack`, if any.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn invalid_data(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[cfg(test)]
mod tests {
    use super::HttpSource;
    use crate::Source as _;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    /// Spin a one-shot server that writes `response` and return its `http://127.0.0.1:<port>/` URL.
    fn serve_once(response: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response);
                let _ = stream.flush();
            }
        });
        format!("http://127.0.0.1:{port}/")
    }

    fn drain(url: &str) -> Vec<Vec<u8>> {
        let mut src = HttpSource::get(url).expect("get");
        let batch = src.next_batch().expect("next").expect("some batch");
        assert!(
            src.next_batch().expect("drained").is_none(),
            "drains after one batch"
        );
        batch
    }

    #[test]
    fn connection_close_three_lines() {
        let url = serve_once(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nevt:a\nevt:b\nevt:c\n");
        assert_eq!(
            drain(&url),
            vec![b"evt:a".to_vec(), b"evt:b".to_vec(), b"evt:c".to_vec()]
        );
    }

    #[test]
    fn content_length_body() {
        // Body is "one\ntwo\n" = 8 bytes; trailing junk after the length must be ignored.
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\none\ntwo\nIGNORED",
        );
        assert_eq!(drain(&url), vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[test]
    fn content_length_overrun_is_an_error_not_a_silent_truncation() {
        // Server claims 100 bytes but sends fewer: a short read must ERROR, not silently return a partial batch
        // (audit F4 — a MITM on the plaintext hop could otherwise drop trailing records undetected).
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nevt:a\n",
        );
        assert!(
            HttpSource::get(&url).is_err(),
            "truncated body shorter than Content-Length must error"
        );
    }

    #[test]
    fn crlf_body_strips_cr() {
        let url = serve_once(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nx:1\r\nx:2\r\n");
        assert_eq!(drain(&url), vec![b"x:1".to_vec(), b"x:2".to_vec()]);
    }

    #[test]
    fn chunked_two_records() {
        // Two chunks: "rec:1\n" (6 = 0x6) and "rec:2\n" (6 = 0x6), then a 0 terminator.
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nrec:1\n\r\n6\r\nrec:2\n\r\n0\r\n\r\n",
        );
        assert_eq!(drain(&url), vec![b"rec:1".to_vec(), b"rec:2".to_vec()]);
    }

    #[test]
    fn non_2xx_is_error() {
        let url =
            serve_once(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let err = HttpSource::get(&url).expect_err("404 must error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn malformed_url_is_invalid_input() {
        let err = HttpSource::get("ftp://example.com/").expect_err("non-http must error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
