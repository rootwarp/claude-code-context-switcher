//! Domain types: `Context`, `AuthMode`, `SecretRef`, `Fingerprint`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::errors::Error;
use crate::secret::Secret;

/// A stored authentication context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    /// Unique name for this context (e.g. `"personal"`, `"work"`).
    pub name: String,
    /// Whether this context uses OAuth or a raw API key.
    pub auth_mode: AuthMode,
    /// Identity metadata for display and matching.
    pub identity: IdentityMetadata,
    /// SHA-256 fingerprint of the credential.
    pub fingerprint: Fingerprint,
    /// When this context was first captured.
    pub created_at: DateTime<Utc>,
    /// Where the secret material for this context is stored.
    pub secret_ref: SecretRef,
}

/// Whether this context uses Claude Code OAuth or a raw API key.
///
/// Serializes to/from the arch §4 YAML schema:
/// - `OAuth`  → `oauth` (plain string)
/// - `ApiKey` → `api_key: { base_url: <url|null> }` (nested map)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "AuthModeWire", try_from = "AuthModeWire")]
pub enum AuthMode {
    /// Claude Code OAuth — credential lives in the `Claude Code-credentials` Keychain item.
    OAuth,
    /// Raw API key, optionally with a custom base URL for gateway users.
    ApiKey {
        /// Optional override for `ANTHROPIC_BASE_URL`.
        base_url: Option<Url>,
    },
}

// ---- wire types for arch §4 YAML format ----

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum AuthModeWire {
    Simple(String),
    ApiKey { api_key: ApiKeyBody },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ApiKeyBody {
    base_url: Option<Url>,
}

impl From<AuthMode> for AuthModeWire {
    fn from(m: AuthMode) -> Self {
        match m {
            AuthMode::OAuth => Self::Simple("oauth".into()),
            AuthMode::ApiKey { base_url } => Self::ApiKey {
                api_key: ApiKeyBody { base_url },
            },
        }
    }
}

impl TryFrom<AuthModeWire> for AuthMode {
    type Error = String;
    fn try_from(w: AuthModeWire) -> Result<Self, Self::Error> {
        match w {
            AuthModeWire::Simple(s) if s == "oauth" => Ok(Self::OAuth),
            AuthModeWire::Simple(s) => Err(format!("unknown auth_mode variant: {s}")),
            AuthModeWire::ApiKey { api_key } => Ok(Self::ApiKey {
                base_url: api_key.base_url,
            }),
        }
    }
}

/// Identity metadata stored alongside a context for display and matching.
///
/// For OAuth contexts, `user_id`, `account_uuid`, and `email_hint` are populated.
/// For API-key contexts, only `label` is used.
/// All fields are optional and omitted from YAML when absent.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IdentityMetadata {
    /// Hex user ID from `~/.claude.json` (OAuth only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Account UUID from the OAuth blob (OAuth only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_uuid: Option<String>,
    /// Redacted email hint for display (OAuth only; not used for matching).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_hint: Option<String>,
    /// Human-readable label (API-key contexts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Where the secret material for a context is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretRef {
    /// API key stored inline in `contexts.yaml`.  Discouraged — prefer `Keychain`.
    Plaintext {
        /// The API key value.
        value: Secret<String>,
    },
    /// API key stored in a cctx-owned Keychain generic-password item.
    Keychain {
        /// Keychain service name (e.g. `"cctx-context-work"`).
        service: String,
        /// Keychain account name (typically `$USER`).
        account: String,
    },
    /// OAuth — blob lives in the Claude Code-credentials Keychain item.
    ClaudeCodeKeychain,
}

/// SHA-256 fingerprint identifying a credential context.
///
/// Serializes to/from a 64-character lowercase hex string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    /// Stub fingerprint for API-key contexts: SHA-256 of the key bytes.
    ///
    /// The real OAuth recipe (`SHA-256(userID || ":" || SHA-256(accessToken)[:16])`)
    /// lands in issue 3.4.
    #[must_use]
    pub fn from_api_key(key: &crate::secret::Secret<String>) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(key.expose().as_bytes());
        let bytes: [u8; 32] = h.finalize().into();
        Self(bytes)
    }

    /// Encode as a 64-character lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        self.0.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// Parse a 64-character hex string (lowercase or uppercase).
    ///
    /// # Errors
    ///
    /// Returns [`Error::FingerprintParseError`] when the input is not exactly
    /// 64 valid hex characters.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        if s.len() != 64 {
            return Err(Error::FingerprintParseError {
                msg: format!("expected 64 hex chars, got {}", s.len()),
            });
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0]).ok_or_else(|| Error::FingerprintParseError {
                msg: format!("invalid hex char '{}'", char::from(chunk[0])),
            })?;
            let lo = hex_nibble(chunk[1]).ok_or_else(|| Error::FingerprintParseError {
                msg: format!("invalid hex char '{}'", char::from(chunk[1])),
            })?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn fixed_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 18, 2, 14, 5).unwrap()
    }

    fn oauth_context() -> Context {
        Context {
            name: "personal".to_string(),
            auth_mode: AuthMode::OAuth,
            identity: IdentityMetadata {
                user_id: Some("f3a9abc".to_string()),
                account_uuid: Some("8c2edef".to_string()),
                email_hint: Some("a***@example.com".to_string()),
                label: None,
            },
            fingerprint: Fingerprint([0x3b; 32]),
            created_at: fixed_ts(),
            secret_ref: SecretRef::ClaudeCodeKeychain,
        }
    }

    fn api_key_context(base_url: Option<Url>) -> Context {
        Context {
            name: "console-key".to_string(),
            auth_mode: AuthMode::ApiKey { base_url },
            identity: IdentityMetadata {
                label: Some("Console key (personal)".to_string()),
                ..Default::default()
            },
            fingerprint: Fingerprint([0xc1; 32]),
            created_at: fixed_ts(),
            secret_ref: SecretRef::Keychain {
                service: "cctx-context-console-key".to_string(),
                account: "joonkyo".to_string(),
            },
        }
    }

    #[test]
    fn serde_roundtrip_oauth_context() {
        let ctx = oauth_context();
        let yaml = serde_yaml_ng::to_string(&ctx).unwrap();
        // Verify arch §4 plain-string format (no YAML tags)
        assert!(
            yaml.contains("auth_mode: oauth"),
            "expected plain 'oauth', got: {yaml}"
        );
        assert!(!yaml.contains("!oauth"), "must not emit YAML tag: {yaml}");
        let back: Context = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(ctx, back);
    }

    #[test]
    fn serde_roundtrip_api_key_context() {
        let url = Url::parse("https://gateway.example/v1").unwrap();
        let ctx = api_key_context(Some(url));
        let yaml = serde_yaml_ng::to_string(&ctx).unwrap();
        // Verify arch §4 nested-map format (no YAML tags)
        assert!(
            yaml.contains("api_key:"),
            "expected nested map, got: {yaml}"
        );
        assert!(!yaml.contains("!api_key"), "must not emit YAML tag: {yaml}");
        let back: Context = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(ctx, back);
    }

    #[test]
    fn serde_roundtrip_api_key_no_base_url() {
        let ctx = api_key_context(None);
        let yaml = serde_yaml_ng::to_string(&ctx).unwrap();
        assert!(
            yaml.contains("api_key:"),
            "expected nested map, got: {yaml}"
        );
        assert!(!yaml.contains("!api_key"), "must not emit YAML tag: {yaml}");
        let back: Context = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(ctx, back);
    }

    #[test]
    fn fingerprint_hex_roundtrip() {
        let fp = Fingerprint([0u8; 32]);
        let hex = fp.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "0".repeat(64));
        let back = Fingerprint::from_hex(&hex).unwrap();
        assert_eq!(fp, back);

        // Non-trivial byte pattern
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let fp2 = Fingerprint(bytes);
        let hex2 = fp2.to_hex();
        assert_eq!(
            hex2,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        let back2 = Fingerprint::from_hex(&hex2).unwrap();
        assert_eq!(fp2, back2);
    }

    #[test]
    fn fingerprint_from_hex_rejects_short() {
        let err = Fingerprint::from_hex("abc").unwrap_err();
        assert!(err.to_string().contains("expected 64"));
    }

    #[test]
    fn fingerprint_from_hex_rejects_invalid_chars() {
        let bad = "zz".repeat(32);
        assert!(Fingerprint::from_hex(&bad).is_err());
    }

    #[test]
    fn fingerprint_hex_encoding() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        bytes[30] = 0xbe;
        bytes[31] = 0xef;
        let fp = Fingerprint(bytes);
        let hex = fp.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("dead"), "expected dead prefix: {hex}");
        assert!(hex.ends_with("beef"), "expected beef suffix: {hex}");
    }

    #[test]
    fn roundtrip_plaintext_variant() {
        // AC: load fixture YAML, parse to Context, serialize back, assert equality
        let fixture = include_str!("../tests/fixtures/context-plaintext.yaml");
        let ctx: Context = serde_yaml_ng::from_str(fixture).unwrap();
        assert!(matches!(ctx.secret_ref, SecretRef::Plaintext { .. }));
        let reserialized = serde_yaml_ng::to_string(&ctx).unwrap();
        let back: Context = serde_yaml_ng::from_str(&reserialized).unwrap();
        assert_eq!(ctx, back);
    }

    #[test]
    fn roundtrip_keychain_variant() {
        // AC: load fixture YAML, parse to Context, serialize back, assert equality
        let fixture = include_str!("../tests/fixtures/context-keychain.yaml");
        let ctx: Context = serde_yaml_ng::from_str(fixture).unwrap();
        assert!(matches!(ctx.secret_ref, SecretRef::Keychain { .. }));
        let reserialized = serde_yaml_ng::to_string(&ctx).unwrap();
        let back: Context = serde_yaml_ng::from_str(&reserialized).unwrap();
        assert_eq!(ctx, back);
    }

    #[test]
    fn roundtrip_claude_code_keychain_variant() {
        // AC: load fixture YAML, parse to Context, serialize back, assert equality
        let fixture = include_str!("../tests/fixtures/context-claude_code_keychain.yaml");
        let ctx: Context = serde_yaml_ng::from_str(fixture).unwrap();
        assert_eq!(ctx.secret_ref, SecretRef::ClaudeCodeKeychain);
        let reserialized = serde_yaml_ng::to_string(&ctx).unwrap();
        let back: Context = serde_yaml_ng::from_str(&reserialized).unwrap();
        assert_eq!(ctx, back);
    }

    #[test]
    fn secret_ref_plaintext_serializes_value_inline() {
        let sr = SecretRef::Plaintext {
            value: Secret::new("k".to_string()),
        };
        let yaml = serde_yaml_ng::to_string(&sr).unwrap();
        // Must roundtrip the literal key — NOT redacted
        assert!(yaml.contains('k'), "value must be present in YAML: {yaml}");
        let back: SecretRef = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(sr, back);
    }

    #[test]
    fn secret_ref_keychain_serializes_shape() {
        let sr = SecretRef::Keychain {
            service: "cctx-context-x".to_string(),
            account: "joonkyo".to_string(),
        };
        let yaml = serde_yaml_ng::to_string(&sr).unwrap();
        assert!(yaml.contains("kind: keychain"), "missing kind tag: {yaml}");
        assert!(yaml.contains("cctx-context-x"), "missing service: {yaml}");
        assert!(yaml.contains("joonkyo"), "missing account: {yaml}");
    }

    #[test]
    fn load_plaintext_fixture() {
        let yaml = include_str!("../tests/fixtures/context-plaintext.yaml");
        let ctx: Context = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(ctx.name, "bootstrap-demo");
        assert!(matches!(ctx.secret_ref, SecretRef::Plaintext { .. }));
    }

    #[test]
    fn load_keychain_fixture() {
        let yaml = include_str!("../tests/fixtures/context-keychain.yaml");
        let ctx: Context = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(ctx.name, "console-key");
        assert!(matches!(ctx.secret_ref, SecretRef::Keychain { .. }));
    }

    #[test]
    fn load_claude_code_keychain_fixture() {
        let yaml = include_str!("../tests/fixtures/context-claude_code_keychain.yaml");
        let ctx: Context = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(ctx.name, "personal");
        assert_eq!(ctx.secret_ref, SecretRef::ClaudeCodeKeychain);
    }

    #[test]
    fn fingerprint_from_api_key_is_stable() {
        let key = crate::secret::Secret::new("sk-ant-stable-key".to_string());
        let fp1 = Fingerprint::from_api_key(&key);
        let fp2 = Fingerprint::from_api_key(&key);
        assert_eq!(fp1, fp2, "same key must produce same fingerprint");
        assert_eq!(fp1.to_hex().len(), 64, "fingerprint must be 64 hex chars");
    }

    #[test]
    fn fingerprint_from_api_key_differs_for_different_keys() {
        let key_a = crate::secret::Secret::new("sk-ant-key-a".to_string());
        let key_b = crate::secret::Secret::new("sk-ant-key-b".to_string());
        let fp_a = Fingerprint::from_api_key(&key_a);
        let fp_b = Fingerprint::from_api_key(&key_b);
        assert_ne!(
            fp_a, fp_b,
            "different keys must produce different fingerprints"
        );
    }
}
