//! `datarail-spec` — the declarative route configuration (SPEC `09-spec-cli.md`).
//!
//! A datarail deployment is described by a `rail.toml`: a fixed A→B route, its onboarding/offloading content
//! contracts, the guarantee, and the key material references. This crate parses that file into typed config
//! and builds the runtime objects ([`TerminalConfig`], [`ContentContract`]) the terminals consume.
//!
//! ## The dialect (deliberately a minimal TOML subset — Charter *leveza*)
//!
//! Rather than depend on `serde` + `toml` (a dozen transitive crates) to parse our own small, fixed schema,
//! `datarail-spec` parses a documented **subset** of TOML with zero dependencies:
//! `[section]` headers, `key = value`, where a value is a `"quoted string"`, an integer, or `true`/`false`;
//! `#` starts a comment (except inside a string). No arrays, inline tables, multiline strings, or datetimes —
//! the schema needs none. Byte fields are written as `"0x…"` hex strings.
//!
//! ```toml
//! [route]
//! route_id   = "0x0101010101010101010101010101010101"  # 16 bytes
//! stream_id  = "0x02020202020202020202020202020202"      # 16 bytes
//! aead       = "gcm-siv-256"                              # gcm-siv-256 | chacha20-poly1305 | gcm-256
//! guarantee  = "exactly-once"
//!
//! [onboarding]
//! max_record_len = 1024
//! required_prefix = "evt:"     # a plain string, or "0x…" hex
//!
//! [offloading]
//! max_record_len = 1024
//! required_prefix = "evt:"
//!
//! [keys]                       # v1: inline hex for a local demo (prod: a key-ref / KMS handle)
//! source_seed    = "0x…32 bytes…"
//! dest_seed      = "0x…32 bytes…"
//! route_data_key = "0x…32 bytes…"
//! tenant_secret  = "0x…32 bytes…"
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use datarail_core::AeadAlg;
use datarail_crypto::x25519_public;
use datarail_terminal::{ContentContract, TerminalConfig};

/// A scalar value in the `rail.toml` dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// A `"quoted string"`.
    Str(String),
    /// An integer literal.
    Int(i64),
    /// `true` / `false`.
    Bool(bool),
}

/// The parsed key/value map, keyed by `(section, key)`.
type RawMap = BTreeMap<(String, String), Value>;

/// Why a `rail.toml` failed to parse or validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// A malformed line (bad header, missing `=`, or an unparseable value).
    Syntax {
        /// 1-based line number.
        line: usize,
        /// What was expected.
        msg: &'static str,
    },
    /// The same `(section, key)` was set twice.
    Duplicate {
        /// 1-based line number of the second occurrence.
        line: usize,
        /// The duplicated key.
        key: String,
    },
    /// A required key was absent.
    Missing {
        /// The section the key was expected in.
        section: &'static str,
        /// The missing key.
        key: &'static str,
    },
    /// A key held the wrong scalar type.
    BadType {
        /// The section.
        section: &'static str,
        /// The key.
        key: &'static str,
        /// The expected type.
        want: &'static str,
    },
    /// A `"0x…"` hex field decoded to the wrong number of bytes.
    BadHexLen {
        /// The key.
        key: &'static str,
        /// The expected byte length.
        want: usize,
        /// The actual byte length.
        got: usize,
    },
    /// A `"0x…"` hex field was not valid hex.
    BadHex {
        /// The key.
        key: &'static str,
    },
    /// The `aead` value was not a recognized algorithm.
    UnknownAead(String),
    /// A numeric field was out of its valid range (e.g. `max_record_len <= 0`).
    OutOfRange {
        /// The key.
        key: &'static str,
    },
}

impl core::fmt::Display for SpecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Syntax { line, msg } => write!(f, "line {line}: {msg}"),
            Self::Duplicate { line, key } => write!(f, "line {line}: duplicate key `{key}`"),
            Self::Missing { section, key } => write!(f, "missing key `{key}` in [{section}]"),
            Self::BadType { section, key, want } => write!(f, "[{section}].{key} must be a {want}"),
            Self::BadHexLen { key, want, got } => {
                write!(f, "`{key}` must be {want} bytes of hex, got {got}")
            }
            Self::BadHex { key } => write!(f, "`{key}` is not valid hex"),
            Self::UnknownAead(s) => write!(f, "unknown aead `{s}`"),
            Self::OutOfRange { key } => write!(f, "`{key}` is out of range"),
        }
    }
}

impl core::error::Error for SpecError {}

/// Strip a trailing `#` comment, ignoring `#` inside a quoted string.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (idx, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..idx],
            _ => {}
        }
    }
    line
}

/// Parse one scalar value.
fn parse_value(s: &str, line: usize) -> Result<Value, SpecError> {
    if let Some(inner) = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        return Ok(Value::Str(inner.to_owned()));
    }
    match s {
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        _ => s.parse::<i64>().map_or(
            Err(SpecError::Syntax {
                line,
                msg: "value must be a quoted string, integer, or boolean",
            }),
            |n| Ok(Value::Int(n)),
        ),
    }
}

/// Parse the dialect into a `(section, key) -> value` map.
fn parse_raw(src: &str) -> Result<RawMap, SpecError> {
    let mut map = RawMap::new();
    let mut section: Option<String> = None;
    for (i, raw) in src.lines().enumerate() {
        let line_no = i + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest.strip_suffix(']').ok_or(SpecError::Syntax {
                line: line_no,
                msg: "unterminated section header",
            })?;
            section = Some(name.trim().to_owned());
            continue;
        }
        let (key, val) = line.split_once('=').ok_or(SpecError::Syntax {
            line: line_no,
            msg: "expected `key = value`",
        })?;
        let section_name = section.clone().ok_or(SpecError::Syntax {
            line: line_no,
            msg: "key outside any [section]",
        })?;
        let key = key.trim().to_owned();
        let value = parse_value(val.trim(), line_no)?;
        if map.insert((section_name, key.clone()), value).is_some() {
            return Err(SpecError::Duplicate { line: line_no, key });
        }
    }
    Ok(map)
}

/// Decode an ASCII hex string (no `0x` prefix) into bytes.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

// ----------------------------------------------------------------------------------------------------------
// Typed extraction helpers.
// ----------------------------------------------------------------------------------------------------------

fn get<'a>(
    map: &'a RawMap,
    section: &'static str,
    key: &'static str,
) -> Result<&'a Value, SpecError> {
    map.get(&(section.to_owned(), key.to_owned()))
        .ok_or(SpecError::Missing { section, key })
}

fn get_str<'a>(
    map: &'a RawMap,
    section: &'static str,
    key: &'static str,
) -> Result<&'a str, SpecError> {
    match get(map, section, key)? {
        Value::Str(s) => Ok(s),
        _ => Err(SpecError::BadType {
            section,
            key,
            want: "string",
        }),
    }
}

fn get_int(map: &RawMap, section: &'static str, key: &'static str) -> Result<i64, SpecError> {
    match get(map, section, key)? {
        Value::Int(n) => Ok(*n),
        _ => Err(SpecError::BadType {
            section,
            key,
            want: "integer",
        }),
    }
}

fn get_bytes<const N: usize>(
    map: &RawMap,
    section: &'static str,
    key: &'static str,
) -> Result<[u8; N], SpecError> {
    let s = get_str(map, section, key)?;
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = from_hex(hex).ok_or(SpecError::BadHex { key })?;
    let got = bytes.len();
    bytes
        .try_into()
        .map_err(|_| SpecError::BadHexLen { key, want: N, got })
}

/// Bytes for a content prefix: a plain `"string"` becomes its UTF-8 bytes; a `"0x…"` value is decoded as hex.
fn get_prefix(
    map: &RawMap,
    section: &'static str,
    key: &'static str,
) -> Result<Vec<u8>, SpecError> {
    let s = get_str(map, section, key)?;
    if let Some(hex) = s.strip_prefix("0x") {
        from_hex(hex).ok_or(SpecError::BadHex { key })
    } else {
        Ok(s.as_bytes().to_vec())
    }
}

// ----------------------------------------------------------------------------------------------------------
// Typed spec.
// ----------------------------------------------------------------------------------------------------------

/// The `[route]` section: the fixed A→B identity, the AEAD, and the declared guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    /// 16-byte route id.
    pub route_id: [u8; 16],
    /// 16-byte stream (ordering domain) id.
    pub stream_id: [u8; 16],
    /// The AEAD algorithm for the carga.
    pub aead: AeadAlg,
    /// The declared delivery guarantee (informational in v1; the code path is always effectively-once).
    pub guarantee: String,
    /// The substrate the rail moves cofres over: `auto`/`loopback` · `tcp` · `shmem` · `s3`/`object-store` ·
    /// `quic` (SPEC-09). Absent ⇒ `loopback` (so a `rail.toml` without the field stays valid).
    pub substrate: String,
}

/// An `[onboarding]` / `[offloading]` content contract section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractSpec {
    /// Maximum record length, in bytes.
    pub max_record_len: usize,
    /// The required record prefix.
    pub required_prefix: Vec<u8>,
}

/// The `[keys]` section. v1 inlines the secrets as hex for a local demo; production carries key-refs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysSpec {
    /// Ed25519 source signing seed.
    pub source_seed: [u8; 32],
    /// Ed25519 destination signing seed (watermarks / acks).
    pub dest_seed: [u8; 32],
    /// The route destination's X25519 **secret**. (v1 demo carries it inline so one `rail.toml` builds both
    /// terminals; production would carry only the *public* key on the source side.) `terminal_config` derives
    /// the public key the source seals each per-cofre data key to.
    pub dest_x25519_secret: [u8; 32],
    /// Per-tenant secret keying the idempotency MAC.
    pub tenant_secret: [u8; 32],
}

/// A fully parsed, validated `rail.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailSpec {
    /// The route section.
    pub route: RouteSpec,
    /// The onboarding (source) content contract.
    pub onboarding: ContractSpec,
    /// The offloading (destination) content contract.
    pub offloading: ContractSpec,
    /// The key material.
    pub keys: KeysSpec,
}

fn contract_spec(map: &RawMap, section: &'static str) -> Result<ContractSpec, SpecError> {
    let raw = get_int(map, section, "max_record_len")?;
    let max_record_len =
        usize::try_from(raw)
            .ok()
            .filter(|&n| n > 0)
            .ok_or(SpecError::OutOfRange {
                key: "max_record_len",
            })?;
    Ok(ContractSpec {
        max_record_len,
        required_prefix: get_prefix(map, section, "required_prefix")?,
    })
}

impl RailSpec {
    /// Parse and validate a `rail.toml` source string.
    ///
    /// # Errors
    /// Returns a [`SpecError`] for any syntax problem, a missing/duplicate/mistyped key, a bad-length or
    /// non-hex byte field, an unknown `aead`, or an out-of-range numeric field.
    pub fn parse(src: &str) -> Result<Self, SpecError> {
        let map = parse_raw(src)?;

        let aead = match get_str(&map, "route", "aead")? {
            "gcm-siv-256" => AeadAlg::Gcmsiv256,
            "chacha20-poly1305" => AeadAlg::ChaCha20Poly1305,
            "gcm-256" => AeadAlg::Gcm256,
            other => return Err(SpecError::UnknownAead(other.to_owned())),
        };

        let route = RouteSpec {
            route_id: get_bytes::<16>(&map, "route", "route_id")?,
            stream_id: get_bytes::<16>(&map, "route", "stream_id")?,
            aead,
            guarantee: get_str(&map, "route", "guarantee")?.to_owned(),
            // Optional: absent ⇒ "loopback" (backward-compatible with specs predating the substrate field).
            substrate: get_str(&map, "route", "substrate")
                .map_or_else(|_| "loopback".to_owned(), str::to_owned),
        };

        let keys = KeysSpec {
            source_seed: get_bytes::<32>(&map, "keys", "source_seed")?,
            dest_seed: get_bytes::<32>(&map, "keys", "dest_seed")?,
            dest_x25519_secret: get_bytes::<32>(&map, "keys", "dest_x25519_secret")?,
            tenant_secret: get_bytes::<32>(&map, "keys", "tenant_secret")?,
        };

        Ok(Self {
            route,
            onboarding: contract_spec(&map, "onboarding")?,
            offloading: contract_spec(&map, "offloading")?,
            keys,
        })
    }

    /// Build the shared [`TerminalConfig`] both terminals are constructed from.
    #[must_use]
    pub fn terminal_config(&self) -> TerminalConfig {
        TerminalConfig {
            route_id: self.route.route_id,
            stream_id: self.route.stream_id,
            aead_alg: self.route.aead,
            dest_x25519_pk: x25519_public(&self.keys.dest_x25519_secret),
            tenant_secret: self.keys.tenant_secret,
        }
    }

    /// The onboarding (source) [`ContentContract`].
    #[must_use]
    pub fn onboarding_contract(&self) -> ContentContract {
        ContentContract::new(
            self.onboarding.max_record_len,
            self.onboarding.required_prefix.clone(),
        )
    }

    /// The offloading (destination) [`ContentContract`].
    #[must_use]
    pub fn offloading_contract(&self) -> ContentContract {
        ContentContract::new(
            self.offloading.max_record_len,
            self.offloading.required_prefix.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{from_hex, RailSpec, SpecError};
    use datarail_core::AeadAlg;

    const SEED32: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    fn sample() -> String {
        format!(
            "# a route\n\
             [route]\n\
             route_id = \"0x01010101010101010101010101010101\"  # 16 bytes\n\
             stream_id = \"0x02020202020202020202020202020202\"\n\
             aead = \"gcm-siv-256\"\n\
             guarantee = \"exactly-once\"\n\
             \n\
             [onboarding]\n\
             max_record_len = 1024\n\
             required_prefix = \"evt:\"\n\
             \n\
             [offloading]\n\
             max_record_len = 1024\n\
             required_prefix = \"evt:\"\n\
             \n\
             [keys]\n\
             source_seed = \"{SEED32}\"\n\
             dest_seed = \"{SEED32}\"\n\
             dest_x25519_secret = \"{SEED32}\"\n\
             tenant_secret = \"{SEED32}\"\n"
        )
    }

    #[test]
    fn parses_a_valid_rail_toml() {
        let spec = RailSpec::parse(&sample()).expect("valid");
        assert_eq!(spec.route.route_id, [1u8; 16]);
        assert_eq!(spec.route.stream_id, [2u8; 16]);
        assert_eq!(spec.route.aead, AeadAlg::Gcmsiv256);
        assert_eq!(spec.route.guarantee, "exactly-once");
        assert_eq!(spec.onboarding.max_record_len, 1024);
        assert_eq!(spec.onboarding.required_prefix, b"evt:");
        assert_eq!(spec.keys.source_seed, [0x11u8; 32]);
    }

    #[test]
    fn builds_runtime_config_with_matching_contract_fingerprints() {
        // Onboarding and offloading share rules ⇒ the source's stamped contract_fp matches the dest's check.
        let spec = RailSpec::parse(&sample()).expect("valid");
        let cfg = spec.terminal_config();
        assert_eq!(cfg.route_id, [1u8; 16]);
        assert_eq!(cfg.aead_alg, AeadAlg::Gcmsiv256);
        assert_eq!(
            spec.onboarding_contract().fingerprint,
            spec.offloading_contract().fingerprint
        );
    }

    #[test]
    fn hex_prefix_for_required_prefix_is_decoded() {
        let src = sample().replace(
            "required_prefix = \"evt:\"",
            "required_prefix = \"0xdeadbeef\"",
        );
        let spec = RailSpec::parse(&src).expect("valid");
        assert_eq!(
            spec.onboarding.required_prefix,
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn missing_key_is_rejected() {
        let src = sample().replace("aead = \"gcm-siv-256\"\n", "");
        assert_eq!(
            RailSpec::parse(&src),
            Err(SpecError::Missing {
                section: "route",
                key: "aead"
            })
        );
    }

    #[test]
    fn bad_hex_length_is_rejected() {
        let src = sample().replace(
            "route_id = \"0x01010101010101010101010101010101\"",
            "route_id = \"0x0101\"",
        );
        assert_eq!(
            RailSpec::parse(&src),
            Err(SpecError::BadHexLen {
                key: "route_id",
                want: 16,
                got: 2
            })
        );
    }

    #[test]
    fn unknown_aead_is_rejected() {
        let src = sample().replace("aead = \"gcm-siv-256\"", "aead = \"rot13\"");
        assert_eq!(
            RailSpec::parse(&src),
            Err(SpecError::UnknownAead("rot13".to_owned()))
        );
    }

    #[test]
    fn wrong_type_is_rejected() {
        let src = sample().replace("max_record_len = 1024", "max_record_len = \"big\"");
        assert_eq!(
            RailSpec::parse(&src),
            Err(SpecError::BadType {
                section: "onboarding",
                key: "max_record_len",
                want: "integer"
            })
        );
    }

    #[test]
    fn non_positive_max_record_len_is_rejected() {
        let src = sample().replace("max_record_len = 1024", "max_record_len = 0");
        assert_eq!(
            RailSpec::parse(&src),
            Err(SpecError::OutOfRange {
                key: "max_record_len"
            })
        );
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let src = sample().replace(
            "guarantee = \"exactly-once\"\n",
            "guarantee = \"exactly-once\"\nguarantee = \"at-least-once\"\n",
        );
        assert!(matches!(
            RailSpec::parse(&src),
            Err(SpecError::Duplicate { .. })
        ));
    }

    #[test]
    fn syntax_error_is_rejected() {
        assert!(matches!(
            RailSpec::parse("[route]\nthis line has no equals\n"),
            Err(SpecError::Syntax { line: 2, .. })
        ));
    }

    #[test]
    fn comment_inside_string_is_preserved() {
        assert_eq!(from_hex("deadBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(from_hex("0d0"), None); // odd length
        assert_eq!(from_hex("zz"), None); // non-hex
    }
}
