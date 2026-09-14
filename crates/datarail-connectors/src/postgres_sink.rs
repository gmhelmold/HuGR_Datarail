//! A zero-dependency `PostgreSQL` sink: a hand-rolled implementation of the frontend/backend wire
//! protocol version 3 over a plain [`std::net::TcpStream`]. Each delivered record lands as **one row**
//! in a target table's single column via the `COPY ... FROM STDIN` sub-protocol (text format).
//!
//! Scope and honesty:
//! - Auth supported: trust ([`AuthenticationOk`]), cleartext password, `MD5` password (the `MD5` digest is
//!   hand-rolled here, RFC 1321), and **`SCRAM-SHA-256`** (`SASL`, RFC 5802 / RFC 7677 — the default on
//!   `PostgreSQL` 14+). The `SCRAM` crypto (`HMAC-SHA-256`, `PBKDF2`) is hand-rolled on top of `sha2`; the
//!   full exchange, including mandatory `ServerSignature` verification, lives in [`scram`].
//! - Channel binding: this driver has **no `TLS`**, so it advertises the plain `SCRAM-SHA-256` mechanism
//!   with a `gs2` header of `n,,` (no channel binding). If the server offers *only* `SCRAM-SHA-256-PLUS`
//!   (channel binding required), authentication fails with a clear error rather than silently downgrading.
//! - `SASLprep` (RFC 4013): ASCII passwords need no preparation and are used verbatim. A non-ASCII password
//!   is rejected with a clear error rather than risk a silent mis-prep that would compute the wrong proof.
//! - No `TLS`: the connection is plaintext. A real deployment must tunnel this over a secure transport.
//! - Records are raw bytes landing into a **text** column. Bytes are escaped per the `COPY` text format
//!   (backslash, tab, newline, carriage-return); no further encoding is applied.
//!
//! [`AuthenticationOk`]: https://www.postgresql.org/docs/current/protocol-message-formats.html

use std::io::{self, Read, Write};
use std::net::TcpStream;

/// Protocol version 3.0 magic, sent in the startup message (`0x0003_0000`).
const PROTOCOL_V3: i32 = 196_608;

/// Hard cap on a single backend message body we are willing to allocate (defensive: the length is
/// attacker-influenced). 64 MiB is far beyond any control message this client expects.
const MAX_BACKEND_MSG: usize = 64 * 1024 * 1024;

/// Connection + landing configuration for a [`PostgresSink`].
///
/// `table` and `column` are operator-supplied identifiers (not untrusted record data); they are still
/// validated to reject a double-quote or NUL so they cannot break the generated `COPY` command.
#[derive(Debug, Clone)]
pub struct PgConfig {
    /// Server host (name or address).
    pub host: String,
    /// Server port (`PostgreSQL` default is 5432).
    pub port: u16,
    /// Role to authenticate as.
    pub user: String,
    /// Optional password (required only if the server requests cleartext or `MD5` auth).
    pub password: Option<String>,
    /// Target database name.
    pub dbname: String,
    /// Target table identifier.
    pub table: String,
    /// Target column identifier (each record lands as one value here).
    pub column: String,
}

impl PgConfig {
    /// A configuration with the default port (5432) and no password. Set [`PgConfig::password`] and
    /// [`PgConfig::port`] afterwards if needed.
    #[must_use]
    pub fn new(host: String, user: String, dbname: String, table: String, column: String) -> Self {
        Self {
            host,
            port: 5432,
            user,
            password: None,
            dbname,
            table,
            column,
        }
    }
}

/// A `PostgreSQL` sink speaking protocol v3 over a plaintext TCP connection. Construct with
/// [`PostgresSink::connect`]; commit batches via the [`crate::Sink`] trait.
#[derive(Debug)]
pub struct PostgresSink {
    stream: TcpStream,
    table: String,
    column: String,
}

impl PostgresSink {
    /// Connect, authenticate, and ready the sink for `COPY` batches.
    ///
    /// Performs the startup handshake, handles the authentication request (trust / cleartext / `MD5` /
    /// `SCRAM-SHA-256`), and drains until the server is `ReadyForQuery`.
    ///
    /// # Errors
    /// Returns [`io::Error`] if the TCP connection fails, an identifier is invalid, the backend reports
    /// an error, a malformed message is received, `SCRAM` authentication fails (bad password or a
    /// `ServerSignature` mismatch), or the requested auth method is unsupported (e.g. `SCRAM-SHA-256-PLUS`
    /// channel binding, which this plaintext driver cannot satisfy).
    pub fn connect(cfg: PgConfig) -> io::Result<Self> {
        validate_ident(&cfg.table)?;
        validate_ident(&cfg.column)?;

        let mut stream = TcpStream::connect((cfg.host.as_str(), cfg.port))?;
        let startup = startup_bytes(&cfg.user, &cfg.dbname)?;
        stream.write_all(&startup)?;
        authenticate(&mut stream, &cfg)?;

        Ok(Self {
            stream,
            table: cfg.table,
            column: cfg.column,
        })
    }

    /// Land `records` via `COPY <table>(<column>) FROM STDIN` (text format). Caller guarantees non-empty + NUL-free.
    fn copy_in(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        let mut query =
            format!("COPY \"{}\" (\"{}\") FROM STDIN", self.table, self.column).into_bytes();
        query.push(0); // simple Query is a NUL-terminated C string
        send(&mut self.stream, b'Q', &query)?;
        // Wait for CopyInResponse ('G'). On an error, DRAIN to ReadyForQuery ('Z') before returning — the wire
        // protocol guarantees a 'Z' follows every 'E', and leaving it unread desyncs every later query (audit C1).
        let mut err: Option<io::Error> = None;
        let mut ready_for_data = false;
        loop {
            let (tag, body) = read_msg(&mut self.stream)?;
            match tag {
                b'G' => {
                    ready_for_data = true;
                    break; // server is ready; the closing 'Z' arrives after CopyDone (drained below)
                }
                b'E' if err.is_none() => err = Some(backend_error(&body)),
                b'Z' => break, // error path fully drained, or an unexpected ready
                _ => {}
            }
        }
        if let Some(e) = err {
            return Err(e); // 'E' then 'Z' consumed — the connection is realigned
        }
        if !ready_for_data {
            return Err(invalid("server was not ready to accept COPY-IN data"));
        }
        for record in records {
            let mut frame = escape_copy(record);
            frame.push(b'\n'); // row terminator
            send(&mut self.stream, b'd', &frame)?;
        }
        send(&mut self.stream, b'c', &[])?; // CopyDone
                                            // Drain to ReadyForQuery ('Z'), capturing any ErrorResponse (do not early-return — see above).
        let mut err: Option<io::Error> = None;
        loop {
            let (tag, body) = read_msg(&mut self.stream)?;
            match tag {
                b'Z' => break,
                b'E' if err.is_none() => err = Some(backend_error(&body)),
                _ => {} // CommandComplete ('C') and informational messages
            }
        }
        if let Some(e) = err {
            return Err(e);
        }
        Ok(())
    }

    /// The transaction body for `commit_at` (between `BEGIN` and `COMMIT`/`ROLLBACK`): read the current watermark
    /// under a row lock; land only the records past the stored watermark; advance the watermark.
    ///
    /// `watermark` is the cumulative count of records landed for this stream **through the end of `records`**, so
    /// `records` covers the half-open landed-count interval `(watermark - records.len(), watermark]`. When the
    /// stored watermark falls inside that interval — a **partial overlap**, reachable when a replayed source has
    /// grown and re-presents a *larger* batch (e.g. a whole file read as one batch) — only the suffix past the
    /// stored watermark is landed. Re-presenting an identical or smaller prefix is a clean no-op. This is what
    /// makes the land idempotent at record granularity, not merely batch granularity.
    fn txn_body(
        &mut self,
        stream_hex: &str,
        lock_key: i64,
        watermark: i64,
        records: &[Vec<u8>],
    ) -> io::Result<()> {
        // Serialize concurrent commit_at on the same stream — `SELECT … FOR UPDATE` locks NO row when the
        // watermark row does not exist yet, so two first-batches would both land (audit C2). A transaction-scoped
        // advisory lock has no such gap; it is released on COMMIT/ROLLBACK.
        query_simple(
            &mut self.stream,
            &format!("SELECT pg_advisory_xact_lock({lock_key})"),
        )?;
        let current = read_watermark(&mut self.stream, stream_hex, true)?; // FOR UPDATE
        if current.is_some_and(|c| c >= watermark) {
            return Ok(()); // already fully landed (idempotent replay) — the COMMIT makes it a clean no-op
        }
        // `base` = the landed-count BEFORE `records`. The stored watermark, when present and above `base`, marks
        // how many of `records` already landed; land only the rest. (`base >= 0` because watermark is cumulative
        // and `records` is a suffix of it; `already` is clamped into `[0, records.len())` since `current < watermark`.)
        let len_i64 = i64::try_from(records.len())
            .map_err(|_| invalid("batch too large to land atomically"))?;
        let base = watermark - len_i64;
        let already = usize::try_from(current.map_or(0, |c| (c - base).max(0))).unwrap_or(0);
        let to_land = records.get(already..).unwrap_or(&[]);
        if !to_land.is_empty() {
            self.copy_in(to_land)?;
        }
        let upsert = format!(
            "INSERT INTO datarail_watermark (stream, seq) VALUES ('\\x{stream_hex}', {watermark}) \
             ON CONFLICT (stream) DO UPDATE SET seq = EXCLUDED.seq"
        );
        query_simple(&mut self.stream, &upsert)?;
        Ok(())
    }

    /// The transaction body for `commit_at_seq` (the Kafka-EOS sequence model): treat the batch as a WHOLE unit.
    /// If the stored watermark is at or beyond `watermark`, the batch already landed (a retry / replay) → no-op;
    /// otherwise land ALL `records` and set the watermark to `watermark`. No partial-suffix landing — the source
    /// guarantees whole-batch, in-order presentation, so the stored watermark is always a clean batch boundary
    /// (`KAFKA-EOS-DESIGN.md`).
    fn txn_body_seq(
        &mut self,
        stream_hex: &str,
        lock_key: i64,
        watermark: i64,
        records: &[Vec<u8>],
    ) -> io::Result<()> {
        query_simple(
            &mut self.stream,
            &format!("SELECT pg_advisory_xact_lock({lock_key})"),
        )?;
        let current = read_watermark(&mut self.stream, stream_hex, true)?; // FOR UPDATE
        if current.is_some_and(|c| c >= watermark) {
            return Ok(()); // already processed (idempotent retry / replay) — clean no-op on COMMIT
        }
        if !records.is_empty() {
            self.copy_in(records)?;
        }
        let upsert = format!(
            "INSERT INTO datarail_watermark (stream, seq) VALUES ('\\x{stream_hex}', {watermark}) \
             ON CONFLICT (stream) DO UPDATE SET seq = EXCLUDED.seq"
        );
        query_simple(&mut self.stream, &upsert)?;
        Ok(())
    }
}

/// Create the watermark table if absent (idempotent). The dedup watermark lives in the sink's own DB.
fn ensure_watermark_table(stream: &mut (impl Read + Write)) -> io::Result<()> {
    query_simple(stream, "CREATE TABLE IF NOT EXISTS datarail_watermark (stream bytea PRIMARY KEY, seq bigint NOT NULL)")
        .map(|_| ())
}

/// Read the current watermark seq for `stream_hex`: `Some(seq)` if the row exists, `None` if absent — the two
/// must NOT collapse (a `0` watermark is a real, distinct value; treating "absent" as `0` silently loses the
/// first batch / re-lands, audit H3/M4). A present-but-unparsable value is a hard error. `stream_hex` is a hex
/// string (no injection); the seq is an integer. `for_update` locks the row inside a transaction.
fn read_watermark(
    stream: &mut (impl Read + Write),
    stream_hex: &str,
    for_update: bool,
) -> io::Result<Option<i64>> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let sql = format!("SELECT seq FROM datarail_watermark WHERE stream = '\\x{stream_hex}'{lock}");
    match query_simple(stream, &sql)? {
        None => Ok(None),
        Some(bytes) => {
            let text =
                std::str::from_utf8(&bytes).map_err(|_| invalid("non-utf8 watermark value"))?;
            let seq = text
                .trim()
                .parse::<i64>()
                .map_err(|_| invalid("unparsable watermark value"))?;
            Ok(Some(seq))
        }
    }
}

/// A transaction-scoped advisory-lock key derived from the stream bytes — serializes concurrent `commit_at` on
/// the same stream even when its watermark row does not exist yet (a `SELECT … FOR UPDATE` locks no missing row).
fn lock_key_for(stream: &[u8]) -> i64 {
    let h = md5(stream);
    i64::from_le_bytes(
        h.get(0..8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .unwrap_or([0u8; 8]),
    )
}

/// Run a simple `Query`, draining to `ReadyForQuery`. Returns the first field of the first `DataRow` (if any) —
/// used both for value-less statements (`BEGIN`/`COMMIT`/DDL/`INSERT`) and single-scalar `SELECT`s. Defensive
/// against short/garbage backend messages; an `ErrorResponse` becomes an `io::Error`.
fn query_simple(stream: &mut (impl Read + Write), sql: &str) -> io::Result<Option<Vec<u8>>> {
    let mut q = sql.as_bytes().to_vec();
    q.push(0); // NUL-terminated C string
    send(stream, b'Q', &q)?;
    let mut first: Option<Vec<u8>> = None;
    let mut saw_row = false;
    let mut err: Option<io::Error> = None;
    // ALWAYS drain to ReadyForQuery ('Z') — the protocol guarantees one terminates every query, and leaving it
    // unread (e.g. early-returning on 'E') desyncs every later query/COPY on this connection (audit C1).
    loop {
        let (tag, body) = read_msg(stream)?;
        match tag {
            b'D' if !saw_row => {
                saw_row = true;
                first = parse_first_field(&body);
                if first.is_none() && err.is_none() {
                    // A DataRow was present but unparsable — fail loud, never silently look like "no row" (audit M4).
                    err = Some(invalid("malformed DataRow from backend"));
                }
            }
            b'E' if err.is_none() => err = Some(backend_error(&body)),
            b'Z' => break, // ReadyForQuery — connection realigned
            _ => {} // RowDescription 'T', CommandComplete 'C', NoticeResponse, extra DataRows, etc.
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok(first),
    }
}

/// Parse the first field of a `DataRow` body: `int16 field-count`, then per field `[int32 len][bytes]` (`len -1`
/// = NULL → empty). Returns `None` if the body is too short to hold the declared first field (a malformed row).
fn parse_first_field(body: &[u8]) -> Option<Vec<u8>> {
    let nfields = body
        .get(0..2)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(i16::from_be_bytes)?;
    if nfields < 1 {
        return Some(Vec::new()); // a row with zero fields → treat as empty
    }
    let len = body
        .get(2..6)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(i32::from_be_bytes)?;
    if len < 0 {
        return Some(Vec::new()); // NULL field
    }
    let n = usize::try_from(len).ok()?;
    body.get(6..6 + n).map(<[u8]>::to_vec)
}

impl crate::Sink for PostgresSink {
    /// Land each record as one row in the configured `table(column)` using `COPY ... FROM STDIN`
    /// (text format). Records are raw bytes escaped per the `COPY` text format; they land into a text
    /// column. An empty batch is a no-op.
    fn commit(&mut self, records: &[Vec<u8>]) -> io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        // The COPY text format cannot represent a NUL byte; reject up front with a clear error rather than
        // letting a single crafted record fail mid-COPY (which would also leave the connection mid-stream).
        if records.iter().any(|r| r.contains(&0)) {
            return Err(invalid(
                "record contains a NUL byte, which the Postgres text COPY format cannot carry",
            ));
        }
        self.copy_in(records)
    }
}

impl crate::TxnSink for PostgresSink {
    /// Tier-A exactly-once (see `EXACTLY-ONCE-DESIGN.md`): land `records` AND advance the watermark for `stream`
    /// in ONE Postgres transaction. Idempotent — a replayed batch (`watermark <= stored`) is a committed no-op.
    fn commit_at(&mut self, records: &[Vec<u8>], stream: &[u8], watermark: u64) -> io::Result<()> {
        if records.iter().any(|r| r.contains(&0)) {
            return Err(invalid(
                "record contains a NUL byte, which the Postgres text COPY format cannot carry",
            ));
        }
        let stream_hex = hex(stream);
        let wm = i64::try_from(watermark).map_err(|_| invalid("watermark exceeds i64::MAX"))?;
        let lock_key = lock_key_for(stream);
        ensure_watermark_table(&mut self.stream)?;
        query_simple(&mut self.stream, "BEGIN")?;
        // Run the transaction body; on ANY error roll back so the connection is reusable (not stuck in a failed txn).
        match self.txn_body(&stream_hex, lock_key, wm, records) {
            Ok(()) => query_simple(&mut self.stream, "COMMIT").map(|_| ()),
            Err(e) => {
                let _ = query_simple(&mut self.stream, "ROLLBACK"); // best-effort; query_simple now drains to 'Z'
                Err(e)
            }
        }
    }

    /// Kafka-EOS sequence model (see `KAFKA-EOS-DESIGN.md`): land `records` + advance the per-substream watermark
    /// to `watermark` (the producer's `base_sequence + count`) in ONE transaction; a replayed/retried batch
    /// (`watermark <= stored`) is a committed no-op. Whole-batch atomic — no partial-suffix landing.
    fn commit_at_seq(
        &mut self,
        records: &[Vec<u8>],
        stream: &[u8],
        watermark: u64,
    ) -> io::Result<()> {
        if records.iter().any(|r| r.contains(&0)) {
            return Err(invalid(
                "record contains a NUL byte, which the Postgres text COPY format cannot carry",
            ));
        }
        let stream_hex = hex(stream);
        let wm = i64::try_from(watermark).map_err(|_| invalid("watermark exceeds i64::MAX"))?;
        let lock_key = lock_key_for(stream);
        ensure_watermark_table(&mut self.stream)?;
        query_simple(&mut self.stream, "BEGIN")?;
        match self.txn_body_seq(&stream_hex, lock_key, wm, records) {
            Ok(()) => query_simple(&mut self.stream, "COMMIT").map(|_| ()),
            Err(e) => {
                let _ = query_simple(&mut self.stream, "ROLLBACK"); // best-effort; query_simple drains to 'Z'
                Err(e)
            }
        }
    }

    fn resume_watermark(&mut self, stream: &[u8]) -> io::Result<u64> {
        ensure_watermark_table(&mut self.stream)?;
        let cur = read_watermark(&mut self.stream, &hex(stream), false)?;
        Ok(cur.and_then(|c| u64::try_from(c).ok()).unwrap_or(0))
    }
}

// ---------------------------------------------------------------------------------------------------
// Message framing (pure, unit-testable)
// ---------------------------------------------------------------------------------------------------

/// Build the v3 `StartupMessage` bytes: Int32 length, Int32 protocol, then `user`/`database` parameters.
fn startup_bytes(user: &str, dbname: &str) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
    payload.extend_from_slice(b"user\0");
    payload.extend_from_slice(user.as_bytes());
    payload.push(0);
    payload.extend_from_slice(b"database\0");
    payload.extend_from_slice(dbname.as_bytes());
    payload.push(0);
    payload.push(0); // end of parameter list

    let total = i32::try_from(payload.len() + 4).map_err(|_| too_large())?;
    let mut buf = Vec::with_capacity(payload.len() + 4);
    buf.extend_from_slice(&total.to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Build a tagged frontend message: 1-byte tag, Int32 length (covers length + body), then body.
fn frame_bytes(tag: u8, body: &[u8]) -> io::Result<Vec<u8>> {
    let total = i32::try_from(body.len() + 4).map_err(|_| too_large())?;
    let mut buf = Vec::with_capacity(body.len() + 5);
    buf.push(tag);
    buf.extend_from_slice(&total.to_be_bytes());
    buf.extend_from_slice(body);
    Ok(buf)
}

/// Write one tagged frontend message to the stream.
fn send(stream: &mut impl Write, tag: u8, body: &[u8]) -> io::Result<()> {
    stream.write_all(&frame_bytes(tag, body)?)
}

/// Read one backend message: 1-byte tag, Int32 length, then `length - 4` body bytes. Defensive against
/// short/garbage headers and absurd lengths.
fn read_msg(stream: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let tag = header[0];
    let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if len < 4 {
        return Err(invalid("backend message length below minimum"));
    }
    let body_len = usize::try_from(len - 4).map_err(|_| invalid("negative backend body length"))?;
    if body_len > MAX_BACKEND_MSG {
        return Err(invalid("backend message exceeds maximum allowed size"));
    }
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body)?;
    Ok((tag, body))
}

/// Read a big-endian `i32` at `offset` from a backend body, defensively.
fn read_be_i32(body: &[u8], offset: usize) -> io::Result<i32> {
    let slice = body
        .get(offset..offset + 4)
        .ok_or_else(|| invalid("backend message too short for a 32-bit field"))?;
    let arr: [u8; 4] = slice.try_into().unwrap_or([0; 4]);
    Ok(i32::from_be_bytes(arr))
}

// ---------------------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------------------

/// Drive the authentication exchange until `ReadyForQuery` ('Z').
fn authenticate(stream: &mut (impl Read + Write), cfg: &PgConfig) -> io::Result<()> {
    loop {
        let (tag, body) = read_msg(stream)?;
        match tag {
            b'R' => {
                let code = read_be_i32(&body, 0)?;
                match code {
                    0 => {} // AuthenticationOk — proceed
                    3 => {
                        // AuthenticationCleartextPassword
                        let pw = require_password(cfg)?;
                        let mut msg = pw.as_bytes().to_vec();
                        msg.push(0);
                        send(stream, b'p', &msg)?;
                    }
                    5 => {
                        // AuthenticationMD5Password: body[4..8] is the 4-byte salt
                        let salt = body
                            .get(4..8)
                            .ok_or_else(|| invalid("MD5 authentication request missing salt"))?;
                        let pw = require_password(cfg)?;
                        let mut msg = pg_md5(&cfg.user, pw, salt).into_bytes();
                        msg.push(0);
                        send(stream, b'p', &msg)?;
                    }
                    10 => {
                        // AuthenticationSASL: body[4..] is a NUL-separated list of mechanism names, terminated by an
                        // extra empty string. Drive the SCRAM-SHA-256 exchange (which reads its own SASLContinue /
                        // SASLFinal 'R' messages) and then fall back into this loop for AuthenticationOk + 'Z'.
                        let mechanisms = body.get(4..).unwrap_or(&[]);
                        scram::authenticate_sasl(stream, cfg, mechanisms)?;
                    }
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            format!("unsupported authentication request {other}"),
                        ));
                    }
                }
            }
            b'E' => return Err(backend_error(&body)),
            b'Z' => return Ok(()),
            _ => {} // ParameterStatus, BackendKeyData, NoticeResponse, … — ignore
        }
    }
}

/// Fetch the configured password or fail with a clear error.
fn require_password(cfg: &PgConfig) -> io::Result<&str> {
    cfg.password.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server requested a password but none was configured",
        )
    })
}

/// The `PostgreSQL` `MD5` password response: `"md5" + hex(md5(hex(md5(password + user)) + salt))`.
fn pg_md5(user: &str, password: &str, salt: &[u8]) -> String {
    let mut inner = password.as_bytes().to_vec();
    inner.extend_from_slice(user.as_bytes());
    let inner_hex = hex(&md5(&inner));

    let mut outer = inner_hex.into_bytes();
    outer.extend_from_slice(salt);
    let outer_hex = hex(&md5(&outer));

    format!("md5{outer_hex}")
}

// ---------------------------------------------------------------------------------------------------
// SCRAM-SHA-256 client authentication (RFC 5802 / RFC 7677)
// ---------------------------------------------------------------------------------------------------

/// `SCRAM-SHA-256` (RFC 5802 salted-challenge-response, RFC 7677 SHA-256 profile) as the PG frontend.
///
/// The exchange over PG's SASL sub-protocol (each step is a backend `'R'` / frontend `'p'` message):
/// 1. Backend `AuthenticationSASL` (already consumed by [`super::authenticate`]) offers a mechanism list.
/// 2. We send `SASLInitialResponse` with `client-first-message` `n,,n=,r=<clientnonce>` (gs2 header `n,,`
///    = no channel binding; the `n=` username is empty because PG binds SCRAM to the startup user).
/// 3. Backend `AuthenticationSASLContinue` (code 11) with `server-first-message`: `r=<nonce>,s=<salt>,i=<i>`.
/// 4. We send `SASLResponse` with `client-final-message`: `c=biws,r=<full nonce>,p=<ClientProof>`.
/// 5. Backend `AuthenticationSASLFinal` (code 12) with `v=<ServerSignature>` — we MUST verify it (mutual
///    authentication); a mismatch aborts even though the backend accepted our proof.
///
/// All crypto (`HMAC-SHA-256`, `PBKDF2-HMAC-SHA-256`, base64) is hand-rolled here on top of `sha2`'s bare
/// SHA-256; see the RFC references inline.
mod scram {
    use super::{invalid, read_be_i32, read_msg, require_password, send};
    use sha2::{Digest, Sha256};
    use std::io::{self, Read, Write};

    /// SHA-256 output size (bytes) and the HMAC block size.
    const HASH_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;

    /// Lower bound on the PBKDF2 iteration count we accept. PG's default is 4096 (RFC 7677 §4 also uses 4096);
    /// a server asking for `i < 1` is malformed.
    const MIN_ITERATIONS: u32 = 1;
    /// Upper bound on the iteration count — the server dictates `i`, and PBKDF2 does `i` HMAC rounds, so an
    /// absurd `i` is a cheap `DoS` the server could inflict on the client. Cap it well above any real config.
    const MAX_ITERATIONS: u32 = 1_000_000;

    /// Drive the full `SCRAM-SHA-256` exchange. `mechanisms` is the NUL-separated mechanism list from the
    /// `AuthenticationSASL` message body (after the 4-byte auth code). Returns once the backend has sent
    /// `AuthenticationSASLFinal` and we have verified the `ServerSignature`.
    ///
    /// # Errors
    /// Fails if no supported mechanism is offered (e.g. only channel-binding `SCRAM-SHA-256-PLUS`), the
    /// password is missing or non-ASCII, any backend message is malformed or out of sequence, or the
    /// `ServerSignature` does not verify (which would mean the server does not know the password).
    pub(super) fn authenticate_sasl(
        stream: &mut (impl Read + Write),
        cfg: &super::PgConfig,
        mechanisms: &[u8],
    ) -> io::Result<()> {
        require_plain_scram(mechanisms)?;
        // SASLprep (RFC 4013): ASCII passwords are their own normal form, so we use them verbatim. A non-ASCII
        // password would need full SASLprep (NFKC + prohibited-code-point checks); rather than risk computing a
        // proof the server will reject in a confusing way, reject up front with a clear error.
        let password = require_password(cfg)?;
        if !password.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SCRAM-SHA-256 with a non-ASCII password is unsupported (SASLprep not implemented)",
            ));
        }

        // --- client-first-message (sent inside a SASLInitialResponse) ---
        let client_nonce = make_nonce()?;
        // gs2 header `n,,` = no channel binding, no authzid. client-first-message-bare = `n=,r=<nonce>`
        // (empty username — PG ignores the SCRAM username and uses the startup `user`).
        let client_first_bare = format!("n=,r={client_nonce}");
        let client_first = format!("n,,{client_first_bare}");
        // The PG SASLInitialResponse 'p' body is: mechanism name (NUL-terminated) + Int32 length of the SASL
        // initial-response data + the data itself. (Later SASLResponse 'p' messages carry the raw data alone.)
        send(
            stream,
            b'p',
            &sasl_initial_response(client_first.as_bytes()),
        )?;

        // --- server-first-message (AuthenticationSASLContinue, code 11) ---
        let server_first_bytes = read_sasl_message(stream, 11)?;
        let server_first = std::str::from_utf8(&server_first_bytes)
            .map_err(|_| invalid("SCRAM server-first-message is not valid UTF-8"))?;
        let ServerFirst {
            nonce,
            salt,
            iterations,
        } = parse_server_first(server_first, &client_nonce)?;

        // --- client-final-message ---
        // channel-binding `c=biws` is base64("n,,") — restates the gs2 header, proving it was not tampered with.
        let gs2_header_b64 = base64_encode(b"n,,");
        let client_final_without_proof = format!("c={gs2_header_b64},r={nonce}");
        // AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof  (RFC 5802 §3).
        let auth_message =
            format!("{client_first_bare},{server_first},{client_final_without_proof}");

        let salted = pbkdf2_hmac_sha256(password.as_bytes(), &salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        // ClientProof = ClientKey XOR ClientSignature.
        let mut client_proof = client_key;
        for (p, s) in client_proof.iter_mut().zip(client_signature.iter()) {
            *p ^= *s;
        }
        let proof_b64 = base64_encode(&client_proof);
        let client_final = format!("{client_final_without_proof},p={proof_b64}");
        send(stream, b'p', client_final.as_bytes())?;

        // --- server-final-message (AuthenticationSASLFinal, code 12): verify ServerSignature (mutual auth) ---
        let server_final_bytes = read_sasl_message(stream, 12)?;
        let server_final = std::str::from_utf8(&server_final_bytes)
            .map_err(|_| invalid("SCRAM server-final-message is not valid UTF-8"))?;
        let server_signature_b64 = parse_server_final(server_final)?;
        let expected = base64_decode(&server_signature_b64)
            .ok_or_else(|| invalid("SCRAM ServerSignature is not valid base64"))?;

        let server_key = hmac_sha256(&salted, b"Server Key");
        let our_signature = hmac_sha256(&server_key, auth_message.as_bytes());
        if !constant_time_eq(&expected, &our_signature) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SCRAM ServerSignature mismatch — the server failed mutual authentication",
            ));
        }
        Ok(())
    }

    /// A parsed `server-first-message`: the combined (client+server) nonce, decoded salt, and iteration count.
    struct ServerFirst {
        nonce: String,
        salt: Vec<u8>,
        iterations: u32,
    }

    /// Reject unless the mechanism list contains the plain `SCRAM-SHA-256` mechanism. We do NOT accept
    /// `SCRAM-SHA-256-PLUS` — that requires TLS channel binding this plaintext driver cannot provide.
    fn require_plain_scram(mechanisms: &[u8]) -> io::Result<()> {
        // The list is NUL-separated, terminated by an extra empty element.
        let offered = mechanisms.split(|&b| b == 0).any(|m| m == b"SCRAM-SHA-256");
        if offered {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "server does not offer SCRAM-SHA-256 (only channel-binding SCRAM-SHA-256-PLUS?), \
                 which this plaintext driver cannot satisfy",
            ))
        }
    }

    /// Read a backend `'R'` message and require it to be an `Authentication*` of the given SASL `code`
    /// (11 = `SASLContinue`, 12 = `SASLFinal`), returning the SASL payload (body after the 4-byte code). An
    /// `ErrorResponse` ('E') becomes the backend error; anything else is a protocol violation.
    fn read_sasl_message(stream: &mut impl Read, code: i32) -> io::Result<Vec<u8>> {
        let (tag, body) = read_msg(stream)?;
        match tag {
            b'R' => {
                if read_be_i32(&body, 0)? != code {
                    return Err(invalid(
                        "unexpected authentication message during SCRAM exchange",
                    ));
                }
                Ok(body.get(4..).unwrap_or(&[]).to_vec())
            }
            b'E' => Err(super::backend_error(&body)),
            _ => Err(invalid("unexpected message during SCRAM exchange")),
        }
    }

    /// Parse a `server-first-message` (`r=<nonce>,s=<salt-b64>,i=<iterations>`), validating that the server
    /// nonce starts with our client nonce (RFC 5802 §5.1 — otherwise the server is not the one we challenged)
    /// and that the iteration count is within `[MIN_ITERATIONS, MAX_ITERATIONS]`.
    fn parse_server_first(msg: &str, client_nonce: &str) -> io::Result<ServerFirst> {
        let mut nonce: Option<&str> = None;
        let mut salt_b64: Option<&str> = None;
        let mut iters: Option<&str> = None;
        for attr in msg.split(',') {
            match attr.as_bytes().first() {
                Some(b'r') => nonce = attr.get(2..),
                Some(b's') => salt_b64 = attr.get(2..),
                Some(b'i') => iters = attr.get(2..),
                // 'm' (mandatory extension) would appear before 'r'; RFC 5802 requires clients to fail on it.
                Some(b'm') => {
                    return Err(invalid(
                        "SCRAM server requested an unsupported mandatory extension",
                    ))
                }
                _ => {}
            }
        }
        let nonce = nonce.ok_or_else(|| invalid("SCRAM server-first-message missing nonce"))?;
        if !nonce.starts_with(client_nonce) || nonce.len() == client_nonce.len() {
            // The full nonce MUST be our client nonce with the server's part appended; a prefix mismatch (or
            // no server part at all) means we are not talking to the server we challenged. Abort.
            return Err(invalid(
                "SCRAM server nonce does not extend the client nonce",
            ));
        }
        let salt_b64 =
            salt_b64.ok_or_else(|| invalid("SCRAM server-first-message missing salt"))?;
        let salt =
            base64_decode(salt_b64).ok_or_else(|| invalid("SCRAM salt is not valid base64"))?;
        let iters =
            iters.ok_or_else(|| invalid("SCRAM server-first-message missing iteration count"))?;
        let iterations: u32 = iters
            .parse()
            .map_err(|_| invalid("SCRAM iteration count is not a number"))?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(invalid(
                "SCRAM iteration count is out of the accepted range",
            ));
        }
        Ok(ServerFirst {
            nonce: nonce.to_owned(),
            salt,
            iterations,
        })
    }

    /// Parse a `server-final-message`. Success form: `v=<ServerSignature-b64>`. An error form `e=<reason>`
    /// (RFC 5802 §5.1) is surfaced as a clear auth failure.
    fn parse_server_final(msg: &str) -> io::Result<String> {
        for attr in msg.split(',') {
            if let Some(v) = attr.strip_prefix("v=") {
                return Ok(v.to_owned());
            }
            if let Some(e) = attr.strip_prefix("e=") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("SCRAM authentication failed: {e}"),
                ));
            }
        }
        Err(invalid(
            "SCRAM server-final-message missing ServerSignature",
        ))
    }

    /// Build the body of a PG `SASLInitialResponse` frontend message (sent under tag `'p'`):
    /// the mechanism name as a NUL-terminated C string, then an `Int32` length of the SASL initial-response
    /// data, then that data. We always use the plain `SCRAM-SHA-256` mechanism (channel binding rejected above).
    fn sasl_initial_response(client_first: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(client_first.len() + 24);
        body.extend_from_slice(b"SCRAM-SHA-256");
        body.push(0); // NUL terminator for the mechanism name
                      // The length is bounded by the small client-first-message; the cast is safe for any real message and
                      // clamps a pathological one to i32::MAX rather than emitting a bogus negative length.
        let len = i32::try_from(client_first.len()).unwrap_or(i32::MAX);
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(client_first);
        body
    }

    /// Generate a printable client nonce from OS entropy. Follows the workspace pattern of reading
    /// `/dev/urandom` directly (zero-dep). The bytes are base64-encoded so the nonce is printable and, per
    /// RFC 5802, contains no comma (base64's alphabet `A-Za-z0-9+/=` is comma-free).
    fn make_nonce() -> io::Result<String> {
        use std::fs::File;
        let mut buf = [0u8; 18]; // 18 bytes -> 24 base64 chars, ~144 bits of entropy
        let mut file = File::open("/dev/urandom")?;
        file.read_exact(&mut buf)?;
        Ok(base64_encode(&buf))
    }

    /// Constant-time byte-slice equality — fold the XOR of every byte pair so timing does not leak *where* a
    /// mismatch is (matters for the `ServerSignature` compare). Unequal lengths are unequal. (The workspace
    /// uses the `subtle` crate elsewhere; this ~10-line fold avoids adding it to this crate.)
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    /// Plain SHA-256 via `sha2`.
    fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// `HMAC-SHA-256` (RFC 2104), hand-rolled: `H((key' XOR opad) || H((key' XOR ipad) || message))`, where
    /// `key'` is the key padded/hashed to the 64-byte block size, `ipad`/`opad` are `0x36`/`0x5c` repeated.
    fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HASH_LEN] {
        // Keys longer than the block are first hashed down (RFC 2104 §2).
        let mut block = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            block[..HASH_LEN].copy_from_slice(&sha256(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        let mut inner = Sha256::new();
        let ipad: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
        inner.update(&ipad);
        inner.update(message);
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        let opad: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
        outer.update(&opad);
        outer.update(inner_hash);
        outer.finalize().into()
    }

    /// `PBKDF2-HMAC-SHA-256` (RFC 2898 §5.2) for `SCRAM`'s `SaltedPassword`. SCRAM always uses `dkLen == HASH_LEN`
    /// (one output block), so this computes exactly `U_1 = HMAC(pw, salt || INT(1))`, then
    /// `U_c = HMAC(pw, U_{c-1})`, XOR-folding all `iterations` blocks into the result.
    fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; HASH_LEN] {
        // U_1 = HMAC(password, salt || INT_32_BE(1))  — block index 1, the only block SCRAM needs.
        let mut salted = salt.to_vec();
        salted.extend_from_slice(&1u32.to_be_bytes());
        let mut u = hmac_sha256(password, &salted);
        let mut result = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for (r, x) in result.iter_mut().zip(u.iter()) {
                *r ^= *x;
            }
        }
        result
    }

    /// Standard base64 alphabet (RFC 4648 §4).
    const B64_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Encode `data` as standard base64 with `=` padding (RFC 4648 §4).
    fn base64_encode(data: &[u8]) -> String {
        let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
            out.push(B64_ALPHABET[(n >> 18) as usize & 0x3f]);
            out.push(B64_ALPHABET[(n >> 12) as usize & 0x3f]);
            out.push(if chunk.len() > 1 {
                B64_ALPHABET[(n >> 6) as usize & 0x3f]
            } else {
                b'='
            });
            out.push(if chunk.len() > 2 {
                B64_ALPHABET[n as usize & 0x3f]
            } else {
                b'='
            });
        }
        // Every output byte is ASCII from the alphabet or '=' — UTF-8 by construction.
        String::from_utf8(out).unwrap_or_default()
    }

    /// Decode standard base64 (RFC 4648 §4) with optional `=` padding. Returns `None` on any invalid input
    /// (non-alphabet byte, or a length that is not a valid base64 stream).
    fn base64_decode(s: &str) -> Option<Vec<u8>> {
        // Strip trailing '=' padding; the remaining length determines the byte count.
        let bytes = s.as_bytes();
        let unpadded = bytes.iter().take_while(|&&b| b != b'=').count();
        // Everything after the first '=' must be '=' only.
        if bytes[unpadded..].iter().any(|&b| b != b'=') {
            return None;
        }
        let symbols = &bytes[..unpadded];
        if symbols.len() % 4 == 1 {
            return None; // 1 leftover base64 char cannot encode any bytes
        }
        let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
        for chunk in symbols.chunks(4) {
            let mut acc = 0u32;
            for &c in chunk {
                acc = (acc << 6) | u32::from(b64_value(c)?);
            }
            // Left-align the accumulated bits for a short final chunk.
            acc <<= 6 * (4 - chunk.len());
            match chunk.len() {
                4 => {
                    out.push(u8::try_from((acc >> 16) & 0xFF).unwrap());
                    out.push(u8::try_from((acc >> 8) & 0xFF).unwrap());
                    out.push(u8::try_from(acc & 0xFF).unwrap());
                }
                3 => {
                    out.push(u8::try_from((acc >> 16) & 0xFF).unwrap());
                    out.push(u8::try_from((acc >> 8) & 0xFF).unwrap());
                }
                2 => out.push(u8::try_from((acc >> 16) & 0xFF).unwrap()),
                _ => return None,
            }
        }
        Some(out)
    }

    /// Map one base64 symbol to its 6-bit value, or `None` if it is not in the alphabet.
    fn b64_value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            base64_decode, base64_encode, constant_time_eq, hmac_sha256, parse_server_final,
            parse_server_first, pbkdf2_hmac_sha256, require_plain_scram, sasl_initial_response,
            sha256,
        };
        use std::fmt::Write;

        // RFC 7677 §3 worked example: user="user", password="pencil", client nonce "rOprNGfwEbeRWgbNEkqO",
        // server-appended nonce so full nonce "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
        // salt "W22ZaJ0SNY7soEsUEjb6gQ==" (base64), i=4096.
        const RFC7677_PASSWORD: &[u8] = b"pencil";
        const RFC7677_SALT_B64: &str = "W22ZaJ0SNY7soEsUEjb6gQ==";
        const RFC7677_ITERATIONS: u32 = 4096;
        const RFC7677_CLIENT_FIRST_BARE: &str = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        const RFC7677_SERVER_FIRST: &str =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        const RFC7677_CLIENT_FINAL_NO_PROOF: &str =
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";

        /// Lowercase hex helper for asserting against the RFC's hex-quoted intermediate values.
        fn hex(bytes: &[u8]) -> String {
            let mut s = String::with_capacity(bytes.len() * 2);
            for &b in bytes {
                write!(&mut s, "{b:02x}").unwrap();
            }
            s
        }

        #[test]
        fn base64_round_trips() {
            for input in [
                &b""[..],
                b"f",
                b"fo",
                b"foo",
                b"foob",
                b"fooba",
                b"foobar",
                &[0u8, 255, 1, 254, 128],
            ] {
                let encoded = base64_encode(input);
                let decoded = base64_decode(&encoded).expect("decode");
                assert_eq!(decoded, input, "round trip failed for {input:?}");
            }
        }

        #[test]
        fn base64_known_vectors() {
            // RFC 4648 §10 test vectors.
            assert_eq!(base64_encode(b""), "");
            assert_eq!(base64_encode(b"f"), "Zg==");
            assert_eq!(base64_encode(b"fo"), "Zm8=");
            assert_eq!(base64_encode(b"foo"), "Zm9v");
            assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
            assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
            assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
            assert_eq!(base64_decode("Zm9vYmFy").expect("decode"), b"foobar");
        }

        #[test]
        fn base64_rejects_garbage() {
            assert!(
                base64_decode("****").is_none(),
                "non-alphabet bytes rejected"
            );
            assert!(
                base64_decode("A").is_none(),
                "a single leftover char cannot decode"
            );
            assert!(
                base64_decode("Zm9vYg=x").is_none(),
                "non-'=' after the first pad byte rejected"
            );
            assert!(
                base64_decode("Zg=x").is_none(),
                "data after padding rejected"
            );
            // Lax padding (2 symbols with no explicit '=') still decodes to the 1 byte it encodes.
            assert_eq!(base64_decode("Zg").expect("lax"), b"f");
        }

        #[test]
        fn hmac_sha256_rfc4231_case2() {
            // RFC 4231 §4.3 test case 2: key="Jefe", data="what do ya want for nothing?".
            let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
            assert_eq!(
                hex(&mac),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
            );
        }

        #[test]
        fn hmac_sha256_rfc4231_case1() {
            // RFC 4231 §4.2 test case 1: key = 0x0b * 20, data = "Hi There".
            let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
            assert_eq!(
                hex(&mac),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
            );
        }

        #[test]
        fn pbkdf2_hmac_sha256_rfc7677_salted_password() {
            // RFC 7677 §3: SaltedPassword := Hi("pencil", <salt>, 4096). The 32-byte SaltedPassword hex below
            // is the standard value for this vector (independently reproducible via `hashlib.pbkdf2_hmac`).
            let salt = base64_decode(RFC7677_SALT_B64).expect("salt");
            let salted = pbkdf2_hmac_sha256(RFC7677_PASSWORD, &salt, RFC7677_ITERATIONS);
            assert_eq!(
                hex(&salted),
                "c4a49510323ab4f952cac1fa99441939e78ea74d6be81ddf7096e87513dc615d"
            );
        }

        #[test]
        fn scram_full_computation_matches_rfc7677() {
            // The complete RFC 7677 §3 chain: SaltedPassword -> ClientKey -> StoredKey -> ClientSignature ->
            // ClientProof, and ServerKey -> ServerSignature. Exact hex values are from the RFC.
            let salt = base64_decode(RFC7677_SALT_B64).expect("salt");
            let salted = pbkdf2_hmac_sha256(RFC7677_PASSWORD, &salt, RFC7677_ITERATIONS);

            let client_key = hmac_sha256(&salted, b"Client Key");
            let stored_key = sha256(&client_key);
            assert_eq!(
                hex(&client_key),
                "a60fc923d67e8644a92d16b96eda5ef4656b0c725c484374be25535576996e8b"
            );
            assert_eq!(
                hex(&stored_key),
                "586e5df283e6dceb5c3e791d8b8528ec191e664045ce971792e2e6b5bb13e2a6"
            );
            let auth_message = format!(
                "{RFC7677_CLIENT_FIRST_BARE},{RFC7677_SERVER_FIRST},{RFC7677_CLIENT_FINAL_NO_PROOF}"
            );
            let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
            let mut client_proof = client_key;
            for (p, s) in client_proof.iter_mut().zip(client_signature.iter()) {
                *p ^= *s;
            }
            let server_key = hmac_sha256(&salted, b"Server Key");
            let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());

            // Base64 values quoted directly in RFC 7677 §3.
            assert_eq!(
                super::base64_encode(&client_proof),
                "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
            );
            assert_eq!(
                super::base64_encode(&server_signature),
                "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
            );
        }

        #[test]
        fn parse_server_first_rejects_nonce_prefix_mismatch() {
            // The full server nonce MUST begin with our client nonce; a server whose nonce does not extend ours
            // is rejected (RFC 5802 §5.1).
            let msg = "r=SOMEOTHERNONCExyz,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
            assert!(parse_server_first(msg, "rOprNGfwEbeRWgbNEkqO").is_err());
            // A nonce that equals the client nonce (no server part) is also rejected.
            let msg2 = "r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
            assert!(parse_server_first(msg2, "rOprNGfwEbeRWgbNEkqO").is_err());
        }

        #[test]
        fn parse_server_first_accepts_and_extracts() {
            let parsed =
                parse_server_first(RFC7677_SERVER_FIRST, "rOprNGfwEbeRWgbNEkqO").expect("parse");
            assert_eq!(
                parsed.nonce,
                "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
            );
            assert_eq!(parsed.iterations, 4096);
            assert_eq!(super::base64_encode(&parsed.salt), RFC7677_SALT_B64);
        }

        #[test]
        fn parse_server_first_bounds_iteration_count() {
            // i must be within [1, 1_000_000]; a zero or absurd count is rejected (DoS bound).
            let too_low = "r=rOprNGfwEbeRWgbNEkqOxx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0";
            assert!(parse_server_first(too_low, "rOprNGfwEbeRWgbNEkqO").is_err());
            let too_high = "r=rOprNGfwEbeRWgbNEkqOxx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=2000000";
            assert!(parse_server_first(too_high, "rOprNGfwEbeRWgbNEkqO").is_err());
        }

        #[test]
        fn parse_server_final_extracts_signature_and_surfaces_errors() {
            assert_eq!(
                parse_server_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=").expect("v"),
                "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
            );
            assert!(parse_server_final("e=invalid-proof").is_err());
            assert!(parse_server_final("x=nothing").is_err());
        }

        #[test]
        fn sasl_initial_response_frames_mechanism_and_length() {
            // Body = "SCRAM-SHA-256\0" + Int32(len) + client-first.
            let client_first = b"n,,n=,r=abc";
            let got = sasl_initial_response(client_first);
            let mut want = b"SCRAM-SHA-256\0".to_vec();
            want.extend_from_slice(&i32::try_from(client_first.len()).unwrap().to_be_bytes());
            want.extend_from_slice(client_first);
            assert_eq!(got, want);
        }

        #[test]
        fn require_plain_scram_rejects_plus_only() {
            // NUL-separated list terminated by an empty element (as PG frames it).
            let plus_only = b"SCRAM-SHA-256-PLUS\0\0";
            assert!(
                require_plain_scram(plus_only).is_err(),
                "PLUS-only must be rejected (no TLS binding)"
            );
            let with_plain = b"SCRAM-SHA-256\0\0";
            assert!(require_plain_scram(with_plain).is_ok());
            let both = b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0";
            assert!(
                require_plain_scram(both).is_ok(),
                "plain offered alongside PLUS is accepted"
            );
        }

        #[test]
        fn constant_time_eq_matches_semantics() {
            assert!(constant_time_eq(b"abc", b"abc"));
            assert!(!constant_time_eq(b"abc", b"abd"));
            assert!(!constant_time_eq(b"abc", b"ab"));
            assert!(constant_time_eq(b"", b""));
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// COPY text-format escaping
// ---------------------------------------------------------------------------------------------------

/// Escape a record for the `COPY` text format (backslash, tab, newline, carriage-return).
fn escape_copy(record: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(record.len());
    for &byte in record {
        match byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------
// Identifier validation + error helpers
// ---------------------------------------------------------------------------------------------------

/// Reject an empty identifier or one containing a double-quote or NUL.
fn validate_ident(ident: &str) -> io::Result<()> {
    if ident.is_empty() {
        return Err(invalid("identifier must not be empty"));
    }
    if ident.bytes().any(|b| b == b'"' || b == 0) {
        return Err(invalid("identifier must not contain a double-quote or NUL"));
    }
    Ok(())
}

/// Parse an `ErrorResponse` body into an [`io::Error`], extracting the human-readable fields.
fn backend_error(body: &[u8]) -> io::Error {
    io::Error::other(error_message(body))
}

/// Extract a readable message from an `ErrorResponse`/`NoticeResponse` body (a series of
/// type-byte + C-string fields, terminated by a zero type byte).
fn error_message(body: &[u8]) -> String {
    let mut rest = body;
    let mut severity: Option<String> = None;
    let mut code: Option<String> = None;
    let mut message: Option<String> = None;

    while let Some((&ftype, after)) = rest.split_first() {
        if ftype == 0 {
            break;
        }
        let end = after.iter().position(|&b| b == 0).unwrap_or(after.len());
        let (value, tail) = after.split_at(end);
        let text = String::from_utf8_lossy(value).into_owned();
        match ftype {
            b'S' => severity = Some(text),
            b'C' => code = Some(text),
            b'M' => message = Some(text),
            _ => {}
        }
        rest = tail.get(1..).unwrap_or(&[]); // skip the field's NUL terminator
    }

    match (severity, message, code) {
        (Some(sev), Some(msg), Some(sqlstate)) => format!("{sev}: {msg} (SQLSTATE {sqlstate})"),
        (Some(sev), Some(msg), None) => format!("{sev}: {msg}"),
        (_, Some(msg), _) => msg,
        _ => "unknown postgres error response".to_owned(),
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "message too large to frame")
}

// ---------------------------------------------------------------------------------------------------
// Hand-rolled MD5 (RFC 1321), zero-dependency
// ---------------------------------------------------------------------------------------------------

/// Per-round left-rotate amounts.
const MD5_SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// Per-round additive constants: `floor(2^32 * abs(sin(i + 1)))`.
const MD5_K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// Compute the 16-byte MD5 digest of `input`.
fn md5(input: &[u8]) -> [u8; 16] {
    // Pad: append 0x80, then zeros to 56 mod 64, then the 64-bit little-endian bit length.
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xefcd_ab89;
    let mut h2: u32 = 0x98ba_dcfe;
    let mut h3: u32 = 0x1032_5476;

    for chunk in msg.as_chunks::<64>().0 {
        let mut words = [0u32; 16];
        for (word, bytes) in words.iter_mut().zip(chunk.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }

        let mut aa = h0;
        let mut bb = h1;
        let mut cc = h2;
        let mut dd = h3;

        for round in 0..64 {
            let (mut mix, word_idx) = if round < 16 {
                ((bb & cc) | (!bb & dd), round)
            } else if round < 32 {
                ((dd & bb) | (!dd & cc), (5 * round + 1) % 16)
            } else if round < 48 {
                (bb ^ cc ^ dd, (3 * round + 5) % 16)
            } else {
                (cc ^ (bb | !dd), (7 * round) % 16)
            };
            let kval = MD5_K.get(round).copied().unwrap_or(0);
            let shift = MD5_SHIFTS.get(round).copied().unwrap_or(0);
            let wval = words.get(word_idx).copied().unwrap_or(0);

            mix = mix.wrapping_add(aa).wrapping_add(kval).wrapping_add(wval);
            aa = dd;
            dd = cc;
            cc = bb;
            bb = bb.wrapping_add(mix.rotate_left(shift));
        }

        h0 = h0.wrapping_add(aa);
        h1 = h1.wrapping_add(bb);
        h2 = h2.wrapping_add(cc);
        h3 = h3.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    for (dst, val) in out.as_chunks_mut::<4>().0.iter_mut().zip([h0, h1, h2, h3]) {
        dst.copy_from_slice(&val.to_le_bytes());
    }
    out
}

/// Lowercase hex encoding of `bytes`.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS.get(usize::from(b >> 4)).copied().unwrap_or(b'?'));
        out.push(DIGITS.get(usize::from(b & 0x0f)).copied().unwrap_or(b'?'));
    }
    String::from_utf8(out).unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        escape_copy, frame_bytes, hex, md5, pg_md5, read_msg, startup_bytes, validate_ident,
    };
    use std::io::Cursor;

    #[test]
    fn md5_known_answers() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        // A multi-block input (> 64 bytes) exercises the chunk loop and padding.
        assert_eq!(
            hex(&md5(
                b"The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs."
            )),
            "f4188739a916382a9b8b684dea92ac8d",
        );
    }

    #[test]
    fn pg_md5_full_digest_matches_reference() {
        // Reference computed independently: user="alice", password="secret", salt=01 02 03 04.
        let digest = pg_md5("alice", "secret", &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(digest, "md598a0412b9c31436fc53776e863350083");
    }

    #[test]
    fn startup_message_exact_bytes() {
        let got = startup_bytes("u", "d").expect("startup");
        let mut want = Vec::new();
        want.extend_from_slice(&27i32.to_be_bytes()); // total length
        want.extend_from_slice(&196_608i32.to_be_bytes()); // protocol
        want.extend_from_slice(b"user\0u\0database\0d\0\0");
        assert_eq!(got, want);
    }

    #[test]
    fn copy_data_frame_exact_bytes() {
        // record "ab" -> escaped "ab" + row terminator '\n' = 3 body bytes; total = 7.
        let mut body = escape_copy(b"ab");
        body.push(b'\n');
        let got = frame_bytes(b'd', &body).expect("frame");
        assert_eq!(got, vec![b'd', 0, 0, 0, 7, b'a', b'b', b'\n']);
    }

    #[test]
    fn copy_text_escaping() {
        // tab, newline, backslash, carriage-return each get a backslash escape.
        let got = escape_copy(b"a\tb\nc\\d\re");
        assert_eq!(got, b"a\\tb\\nc\\\\d\\re".to_vec());
    }

    #[test]
    fn read_msg_rejects_truncated_header() {
        // Only 3 bytes: cannot even read the 5-byte header -> Err, not panic.
        let mut cur = Cursor::new(vec![b'X', 0, 0]);
        assert!(read_msg(&mut cur).is_err());
    }

    #[test]
    fn read_msg_rejects_undersized_length() {
        // Valid 5-byte header but length field < 4 -> Err.
        let mut cur = Cursor::new(vec![b'E', 0, 0, 0, 3]);
        assert!(read_msg(&mut cur).is_err());
    }

    #[test]
    fn read_msg_parses_well_formed_message() {
        // tag 'C', length 6 (covers length + 2 body bytes), body "ok".
        let mut cur = Cursor::new(vec![b'C', 0, 0, 0, 6, b'o', b'k']);
        let (tag, body) = read_msg(&mut cur).expect("read");
        assert_eq!(tag, b'C');
        assert_eq!(body, b"ok".to_vec());
    }

    #[test]
    fn validate_ident_rejects_quote_and_nul() {
        assert!(validate_ident("events").is_ok());
        assert!(validate_ident("bad\"name").is_err());
        assert!(validate_ident("bad\0name").is_err());
        assert!(validate_ident("").is_err());
    }
}
