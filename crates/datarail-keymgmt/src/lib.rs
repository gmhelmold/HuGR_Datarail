//! Key Management Provider Abstraction
//!
//! Provides a unified interface for resolving cryptographic key material from
//! external sources (age, SSH agent, env, file, KMS) without embedding secrets
//! in configuration files.

#![forbid(unsafe_code)]

use std::io;
use std::path::Path;

use thiserror::Error;

/// A cryptographic key identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        KeyId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Error type for key provider operations.
#[derive(Debug, Error)]
pub enum KeyProviderError {
    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Provider unavailable: {0}")]
    Unavailable(String),

    #[error("Invalid key material: {0}")]
    InvalidMaterial(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Unsupported scheme: {0}")]
    UnsupportedScheme(String),
}

/// Result type for key provider operations.
pub type Result<T> = std::result::Result<T, KeyProviderError>;

/// A resolved cryptographic key (32 bytes for Ed25519/X25519 seeds, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKey {
    /// The raw key material (exactly 32 bytes for Ed25519/X25519 seeds).
    pub material: [u8; 32],

    /// Optional metadata about the key source.
    pub metadata: KeyMetadata,
}

/// Metadata about a resolved key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyMetadata {
    /// Human-readable description of the key source.
    pub source: String,

    /// Optional key version/rotation identifier.
    pub version: Option<String>,

    /// Key creation timestamp (Unix epoch seconds).
    pub created_at: Option<u64>,

    /// Optional key expiration timestamp (Unix epoch seconds).
    pub expires_at: Option<u64>,
}

/// Trait for resolving cryptographic key material from external sources.
///
/// Implementations should be thread-safe and cacheable. The CLI/spec uses this
/// trait to resolve key references without embedding secrets in configuration.
pub trait KeyProvider: Send + Sync {
    /// Resolve a key by its logical identifier.
    ///
    /// Returns the 32-byte key material and optional metadata.
    fn resolve(&self, key_id: &KeyId) -> Result<ResolvedKey>;

    /// List all available key identifiers.
    ///
    /// Used for validation and autocomplete.
    fn list_keys(&self) -> Vec<KeyId>;

    /// Check if a key exists without resolving it.
    fn has_key(&self, key_id: &KeyId) -> bool;

    /// Get the provider's human-readable name.
    fn name(&self) -> &'static str;
}

/// A key reference specification (scheme + locator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    /// The scheme (e.g., "env", "file", "age", "ssh-agent", "aws-kms").
    pub scheme: String,

    /// The locator within the scheme (e.g., env var name, file path, key ID).
    pub locator: String,
}

impl KeyRef {
    /// Parse a key reference string like `env:VAR_NAME` or `file:/path/to/key`.
    pub fn parse(s: &str) -> Option<Self> {
        let (scheme, locator) = s.split_once(':')?;
        Some(KeyRef {
            scheme: scheme.to_owned(),
            locator: locator.to_owned(),
        })
    }
}

/// Multi-provider key resolver that chains multiple providers.
///
/// Tries providers in order until one succeeds. Used by the CLI to resolve
/// keys from multiple sources with fallback.
#[derive(Default)]
pub struct KeyResolver {
    providers: Vec<Box<dyn KeyProvider>>,
}

impl KeyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a provider to the chain (later providers are tried first).
    pub fn add_provider(&mut self, provider: Box<dyn KeyProvider>) {
        self.providers.push(provider);
    }

    /// Resolve a key by trying providers in reverse order (last added first).
    pub fn resolve(&self, key_id: &KeyId) -> Result<ResolvedKey> {
        for provider in self.providers.iter().rev() {
            if provider.has_key(key_id) {
                return provider.resolve(key_id);
            }
        }
        Err(KeyProviderError::NotFound(key_id.0.clone()))
    }

    /// List all available keys from all providers.
    pub fn list_keys(&self) -> Vec<KeyId> {
        let mut keys = Vec::new();
        for provider in &self.providers {
            keys.extend(provider.list_keys());
        }
        keys
    }
}

impl KeyProvider for KeyResolver {
    fn resolve(&self, key_id: &KeyId) -> Result<ResolvedKey> {
        self.resolve(key_id)
    }

    fn list_keys(&self) -> Vec<KeyId> {
        self.list_keys()
    }

    fn has_key(&self, key_id: &KeyId) -> bool {
        self.providers.iter().any(|p| p.has_key(key_id))
    }

    fn name(&self) -> &'static str {
        "KeyResolver"
    }
}

/// Environment variable key provider.
///
/// Resolves keys from environment variables. The key ID is used as the
/// environment variable name (e.g., `DATARAIL_SOURCE_SEED`).
pub struct EnvKeyProvider {
    prefix: String,
}

impl EnvKeyProvider {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }
}

impl KeyProvider for EnvKeyProvider {
    fn resolve(&self, key_id: &KeyId) -> Result<ResolvedKey> {
        let var_name = format!("{}{}", self.prefix, key_id.as_str().to_uppercase());
        let value = std::env::var(&var_name)
            .map_err(|_| KeyProviderError::NotFound(var_name.clone()))?;

        let material = decode_hex(&value)
            .map_err(|e| KeyProviderError::InvalidMaterial(e.to_string()))?;

        Ok(ResolvedKey {
            material,
            metadata: KeyMetadata {
                source: format!("env:{}", var_name),
                ..Default::default()
            },
        })
    }

    fn list_keys(&self) -> Vec<KeyId> {
        std::env::vars()
            .filter_map(|(k, _)| k.strip_prefix(&self.prefix).map(KeyId::new))
            .collect()
    }

    fn has_key(&self, key_id: &KeyId) -> bool {
        let var_name = format!("{}{}", self.prefix, key_id.as_str().to_uppercase());
        std::env::var(&var_name).is_ok()
    }

    fn name(&self) -> &'static str {
        "EnvKeyProvider"
    }
}

/// File-based key provider.
///
/// Reads key material from files. The key ID is used as a relative path
/// under a configured base directory, or as an absolute path.
pub struct FileKeyProvider {
    base_dir: std::path::PathBuf,
}

impl FileKeyProvider {
    pub fn new(base_dir: impl AsRef<std::path::Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_owned(),
        }
    }

    fn resolve_path(&self, key_id: &KeyId) -> std::path::PathBuf {
        let path = std::path::Path::new(key_id.as_str());
        if path.is_absolute() {
            path.to_owned()
        } else {
            self.base_dir.join(path)
        }
    }
}

impl KeyProvider for FileKeyProvider {
    fn resolve(&self, key_id: &KeyId) -> Result<ResolvedKey> {
        let path = self.resolve_path(key_id);
        let content = std::fs::read_to_string(&path)
            .map_err(|e| KeyProviderError::Unavailable(format!("{}: {}", path.display(), e)))?;

        let trimmed = content.trim();
        let material = decode_hex(trimmed)
            .map_err(|e| KeyProviderError::InvalidMaterial(e.to_string()))?;

        Ok(ResolvedKey {
            material,
            metadata: KeyMetadata {
                source: format!("file:{}", path.display()),
                ..Default::default()
            },
        })
    }

    fn list_keys(&self) -> Vec<KeyId> {
        let mut keys = Vec::new();
        if self.base_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&self.base_dir) {
                for entry in entries.flatten() {
                    if let Some(s) = entry.path().file_name().and_then(|s| s.to_str()) {
                        keys.push(KeyId::new(s.to_owned()));
                    }
                }
            }
        }
        keys
    }

    fn has_key(&self, key_id: &KeyId) -> bool {
        self.resolve_path(key_id).exists()
    }

    fn name(&self) -> &'static str {
        "FileKeyProvider"
    }
}

#[cfg(feature = "age")]
pub mod age_provider {
    use super::*;

    /// Age-encrypted key provider.
    ///
    /// Resolves keys from age-encrypted files. The file contains an age-encrypted
    /// 32-byte key, decrypted using the recipient's identity (passphrase or SSH key).
    pub struct AgeKeyProvider {
        identity: age::scrypt::Identity,
        base_dir: std::path::PathBuf,
    }

    impl AgeKeyProvider {
        pub fn new(identity: age::scrypt::Identity, base_dir: impl AsRef<std::path::Path>) -> Self {
            Self {
                identity,
                base_dir: base_dir.as_ref().to_owned(),
            }
        }
    }

    impl KeyProvider for AgeKeyProvider {
        fn resolve(&self, key_id: &KeyId) -> Result<ResolvedKey> {
            let path = std::path::Path::new(key_id.as_str());
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                self.base_dir.join(path)
            };

            let encrypted = std::fs::read(&path)
                .map_err(|e| KeyProviderError::Unavailable(format!("{}: {}", path.display(), e)))?;

            let decryptor = age::Decryptor::new(&*encrypted)
                .map_err(|e| KeyProviderError::Provider(format!("age decrypt failed: {e}")))?;

            let mut decrypted = Vec::new();
            let mut reader = decryptor
                .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
                .map_err(|e| KeyProviderError::Provider(format!("age decrypt failed: {e}")))?;

            std::io::Read::read_to_end(&mut reader, &mut decrypted)
                .map_err(|e| KeyProviderError::Provider(format!("age read failed: {e}")))?;

            if decrypted.len() != 32 {
                return Err(KeyProviderError::InvalidMaterial(
                    "age-decrypted key must be exactly 32 bytes".into(),
                ));
            }

            let mut material = [0u8; 32];
            material.copy_from_slice(&decrypted);

            Ok(ResolvedKey {
                material,
                metadata: KeyMetadata {
                    source: format!("age:{}", path.display()),
                    ..Default::default()
                },
            })
        }

        fn list_keys(&self) -> Vec<KeyId> {
            let mut keys = Vec::new();
            if self.base_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&self.base_dir) {
                    for entry in entries.flatten() {
                        if let Some(s) = entry.path().file_name().and_then(|s| s.to_str()) {
                            if s.ends_with(".age") || s.ends_with(".enc") {
                                keys.push(KeyId::new(s.to_owned()));
                            }
                        }
                    }
                }
            }
            keys
        }

        fn has_key(&self, key_id: &KeyId) -> bool {
            let path = std::path::Path::new(key_id.as_str());
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                self.base_dir.join(path)
            };
            path.exists()
        }

        fn name(&self) -> &'static str {
            "AgeKeyProvider"
        }
    }
}

#[cfg(feature = "ssh-agent")]
pub mod ssh_agent_provider {
    use super::*;

    /// SSH agent key provider (stub - requires ssh-agent crate API fix).
    ///
    /// Resolves X25519/Ed25519 keys from a running SSH agent via the
    /// SSH_AUTH_SOCK socket. The key ID corresponds to the key fingerprint
    /// or comment in the agent.
    pub struct SshAgentKeyProvider {
        socket_path: Option<std::path::PathBuf>,
    }

    impl SshAgentKeyProvider {
        pub fn new(socket_path: Option<impl AsRef<std::path::Path>>) -> Self {
            Self {
                socket_path: socket_path.map(|p| p.as_ref().to_owned()),
            }
        }
    }

    impl KeyProvider for SshAgentKeyProvider {
        fn resolve(&self, _key_id: &KeyId) -> Result<ResolvedKey> {
            Err(KeyProviderError::UnsupportedScheme(
                "SSH agent support requires ssh-agent crate API fix".into()
            ))
        }

        fn list_keys(&self) -> Vec<KeyId> {
            Vec::new()
        }

        fn has_key(&self, _key_id: &KeyId) -> bool {
            false
        }

        fn name(&self) -> &'static str {
            "SshAgentKeyProvider"
        }
    }
}

/// Utility: decode hex string to 32-byte array.
fn decode_hex(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return Err(KeyProviderError::InvalidMaterial(
            "hex string must be 64 characters (32 bytes)".into(),
        ));
    }
    let bytes = hex::decode(s).map_err(|e| KeyProviderError::InvalidMaterial(e.to_string()))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_provider() {
        std::env::set_var("DATARAIL_TEST_KEY", "aa".repeat(32));
        let provider = EnvKeyProvider::new("DATARAIL_");
        let key = provider.resolve(&KeyId::new("TEST_KEY")).unwrap();
        assert_eq!(key.material, [0xaa; 32]);
        assert!(provider.has_key(&KeyId::new("TEST_KEY")));
        std::env::remove_var("DATARAIL_TEST_KEY");
    }

    #[test]
    fn test_file_provider() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_key");
        std::fs::write(&path, "aa".repeat(32)).unwrap();

        let provider = FileKeyProvider::new(dir.path());
        let key = provider.resolve(&KeyId::new("test_key")).unwrap();
        assert_eq!(key.material, [0xaa; 32]);
        assert!(provider.has_key(&KeyId::new("test_key")));
    }

    #[test]
    fn test_resolver_chain() {
        let mut resolver = KeyResolver::new();
        let mut env = EnvKeyProvider::new("DATARAIL_");
        std::env::set_var("DATARAIL_KEY1", "aa".repeat(32));
        resolver.add_provider(Box::new(env));

        let key = resolver.resolve(&KeyId::new("KEY1")).unwrap();
        assert_eq!(key.material, [0xaa; 32]);
        std::env::remove_var("DATARAIL_KEY1");
    }
}