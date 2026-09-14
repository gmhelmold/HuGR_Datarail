//! SASL/PLAIN authentication codec (`KAFKA-SASL-DESIGN.md`): `SaslHandshake` (17) negotiates the mechanism and
//! `SaslAuthenticate` (36) carries the SASL token (the KIP-152 wrapped form modern librdkafka uses). Pure wire —
//! zero-dependency like the rest of the crate; the credential check is a hand-rolled CONSTANT-TIME compare (no
//! `subtle` dep, `forbid(unsafe)`).

use std::io;

use crate::codec::{write_response_header, Reader, Writer};

/// `SaslHandshake` API key.
pub const API_SASL_HANDSHAKE: i16 = 17;
/// `SaslAuthenticate` API key.
pub const API_SASL_AUTHENTICATE: i16 = 36;

/// The requested mechanism is not one we support (we only offer `PLAIN`).
pub const UNSUPPORTED_SASL_MECHANISM: i16 = 33;
/// A request arrived in the wrong SASL state (e.g. a normal API before authenticating).
pub const ILLEGAL_SASL_STATE: i16 = 35;
/// The supplied credential did not verify.
pub const SASL_AUTHENTICATION_FAILED: i16 = 58;

/// The only mechanism we support in v1.
pub const PLAIN: &str = "PLAIN";

/// Parse a `SaslHandshake` request body (after the request header): a single `mechanism` STRING.
///
/// # Errors
/// [`io::Error`] if the body is malformed / truncated.
pub fn parse_sasl_handshake(reader: &mut Reader) -> io::Result<String> {
    reader.string()
}

/// Build a `SaslHandshake` response (v0/v1 share the body): `error_code` + the `enabled_mechanisms` STRING array.
#[must_use]
pub fn sasl_handshake_response(
    correlation_id: i32,
    error_code: i16,
    mechanisms: &[&str],
) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    w.int16(error_code);
    w.int32(i32::try_from(mechanisms.len()).unwrap_or(0));
    for m in mechanisms {
        w.string(m);
    }
    w.into_bytes()
}

/// Parse a `SaslAuthenticate` request body at `version`: the opaque `auth_bytes` (the SASL token).
///
/// # Errors
/// [`io::Error`] if the body is malformed / truncated.
pub fn parse_sasl_authenticate(reader: &mut Reader, _version: i16) -> io::Result<Vec<u8>> {
    reader.bytes()
}

/// Build a `SaslAuthenticate` response: `error_code` + `error_message` (nullable) + `auth_bytes` + (v1)
/// `session_lifetime_ms`.
#[must_use]
pub fn sasl_authenticate_response(
    correlation_id: i32,
    version: i16,
    error_code: i16,
    error_message: Option<&str>,
    auth_bytes: &[u8],
    session_lifetime_ms: i64,
) -> Vec<u8> {
    let mut w = Writer::new();
    write_response_header(&mut w, correlation_id, false);
    w.int16(error_code);
    w.nullable_string(error_message);
    w.bytes(auth_bytes);
    if version >= 1 {
        w.int64(session_lifetime_ms);
    }
    w.into_bytes()
}

/// Verify a SASL/PLAIN token (RFC 4616: `authzid \0 authcid \0 passwd`) against the configured credential, in
/// constant time. Returns `true` only if BOTH the username and the password match.
#[must_use]
pub fn verify_plain(auth_bytes: &[u8], user: &str, pass: &str) -> bool {
    // PLAIN = authzid NUL authcid NUL passwd. `splitn(3)` keeps any trailing bytes (incl. NULs) in the password.
    let mut parts = auth_bytes.splitn(3, |&b| b == 0);
    let _authzid = parts.next();
    let (Some(authcid), Some(passwd)) = (parts.next(), parts.next()) else {
        return false;
    };
    // Bitwise-AND (NOT `&&`) so both compares always run — no short-circuit on the username mismatch.
    ct_eq(authcid, user.as_bytes()) & ct_eq(passwd, pass.as_bytes())
}

/// Constant-time byte-slice equality (XOR-accumulate). A length mismatch returns `false` immediately (it leaks only
/// the length, never the content); equal-length inputs are compared without an early-out.
#[must_use]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{
        parse_sasl_authenticate, parse_sasl_handshake, sasl_authenticate_response,
        sasl_handshake_response, verify_plain, PLAIN,
    };
    use crate::codec::{Reader, Writer};

    #[test]
    fn handshake_round_trips_and_advertises_plain() {
        let mut req = Writer::new();
        req.string("PLAIN");
        let req = req.into_bytes();
        let mut r = Reader::new(&req);
        assert_eq!(parse_sasl_handshake(&mut r).unwrap(), "PLAIN");
        let resp = sasl_handshake_response(7, 0, &[PLAIN]);
        let mut rr = Reader::new(&resp);
        assert_eq!(rr.int32().unwrap(), 7); // correlation_id
        assert_eq!(rr.int16().unwrap(), 0); // error_code
        assert_eq!(rr.int32().unwrap(), 1); // one mechanism
        assert_eq!(rr.string().unwrap(), "PLAIN");
    }

    #[test]
    fn authenticate_parses_token_and_response_builds_v1() {
        let mut req = Writer::new();
        req.bytes(b"\0alice\0s3cret");
        let req = req.into_bytes();
        let mut r = Reader::new(&req);
        let token = parse_sasl_authenticate(&mut r, 1).unwrap();
        assert_eq!(token, b"\0alice\0s3cret");
        let resp = sasl_authenticate_response(9, 1, 0, None, &[], 3_600_000);
        let mut rr = Reader::new(&resp);
        assert_eq!(rr.int32().unwrap(), 9); // correlation_id
        assert_eq!(rr.int16().unwrap(), 0); // error_code
        assert_eq!(rr.nullable_string().unwrap(), None); // error_message
        assert_eq!(rr.bytes().unwrap(), Vec::<u8>::new()); // auth_bytes
        assert_eq!(rr.int64().unwrap(), 3_600_000); // session_lifetime_ms (v1)
    }

    #[test]
    fn verify_plain_accepts_correct_and_rejects_wrong() {
        assert!(
            verify_plain(b"\0alice\0s3cret", "alice", "s3cret"),
            "correct credential"
        );
        assert!(
            !verify_plain(b"\0alice\0WRONG", "alice", "s3cret"),
            "wrong password"
        );
        assert!(
            !verify_plain(b"\0bob\0s3cret", "alice", "s3cret"),
            "wrong username"
        );
        assert!(
            !verify_plain(b"\0alice", "alice", "s3cret"),
            "malformed (missing password field)"
        );
        assert!(
            !verify_plain(b"nonulls", "alice", "s3cret"),
            "malformed (no NUL separators)"
        );
        // An authzid present (some clients set it) still works — we ignore it.
        assert!(
            verify_plain(b"alice\0alice\0s3cret", "alice", "s3cret"),
            "authzid ignored"
        );
    }
}
