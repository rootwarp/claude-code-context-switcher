//! Read/write `~/.claude.json`, `~/.claude/settings.json`; detect `.credentials.json` fallback.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::errors::Error;
use crate::fs_atomic::write_atomic_0600;
use crate::secret::Secret;

// ── ~/.claude.json types ────────────────────────────────────────────────────

/// Dual-form parser for `expiresAt` (research 01 §1, issue #19274).
///
/// Accepts either a millisecond-since-epoch integer or an ISO-8601 string.
/// Write-back preserves whatever form was read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ExpiresAt {
    Millis(i64),
    Iso(String),
}

/// The `claudeAiOauth` payload stored in the Keychain blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeAiOauth {
    #[serde(rename = "accessToken")]
    pub access_token: Secret<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Secret<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: ExpiresAt,
}

/// Wrapper matching the Keychain blob's top-level shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeychainBlobEnvelope {
    #[serde(rename = "claudeAiOauth")]
    pub claude_ai_oauth: ClaudeAiOauth,
}

/// Non-secret identity block stored in `~/.claude.json` under `oauthAccount`.
///
/// Per research 01 §2. The `#[serde(flatten)]` captures all fields Claude Code
/// may add across versions, ensuring round-trip fidelity without a hardcoded list.
// `serde_json::Map<String, Value>` implements `PartialEq` but not `Eq` (Value contains f64).
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuthAccount {
    #[serde(rename = "accountUuid")]
    pub account_uuid: String,
    #[serde(rename = "emailAddress")]
    pub email_address: String,
    #[serde(rename = "organizationUuid")]
    pub organization_uuid: Option<String>,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

/// Parsed view of `~/.claude.json`.
///
/// `oauth_account` and `user_id` are the only fields cctx writes;
/// `preserved` holds every other top-level key opaquely for round-trip.
#[derive(Debug, Clone)]
pub struct ClaudeDotJson {
    pub oauth_account: Option<OAuthAccount>,
    pub user_id: Option<String>,
    pub preserved: Map<String, Value>,
}

/// Load `~/.claude.json`. If the file is missing, returns an empty state.
///
/// # Errors
///
/// `ClaudeStateParseError` if the file exists but is not valid JSON.
pub fn load_claude_dot_json(path: &Path) -> Result<ClaudeDotJson, Error> {
    if !path.exists() {
        return Ok(ClaudeDotJson {
            oauth_account: None,
            user_id: None,
            preserved: Map::new(),
        });
    }
    let raw = std::fs::read(path)?;
    let mut root: Map<String, Value> = serde_json::from_slice(&raw)
        .map_err(|e| Error::ClaudeStateParseError { msg: e.to_string() })?;

    let oauth_account = root
        .remove("oauthAccount")
        .and_then(|v| serde_json::from_value(v).ok());

    let user_id = root
        .remove("userID")
        .and_then(|v| v.as_str().map(String::from));

    Ok(ClaudeDotJson {
        oauth_account,
        user_id,
        preserved: root,
    })
}

/// Merge an incoming identity into `~/.claude.json` atomically (mode 0600 on unix).
///
/// Writes `oauthAccount` and `userID` at the top level. Every other top-level key
/// (`projects`, `tipsHistory`, `numStartups`, migration flags, unknown future keys, etc.)
/// is preserved verbatim from the existing file.
///
/// # Errors
///
/// `ClaudeStateParseError`, `ConfigWriteFailed`.
pub fn merge_and_save_claude_dot_json(
    path: &Path,
    incoming_oauth_account: &OAuthAccount,
    incoming_user_id: String,
) -> Result<(), Error> {
    let current = load_claude_dot_json(path)?;

    let mut out: Map<String, Value> = current.preserved;

    out.insert(
        "oauthAccount".to_string(),
        serde_json::to_value(incoming_oauth_account)?,
    );
    out.insert("userID".to_string(), Value::String(incoming_user_id));

    let bytes = serde_json::to_vec_pretty(&Value::Object(out))?;
    write_atomic_0600(path, &bytes)?;
    Ok(())
}

/// Lightweight indicator of which auth mode is being applied.
///
/// Avoids pulling `context::AuthMode` into this module.
#[derive(Clone, Copy)]
pub enum AuthModeHint {
    /// OAuth context — strip all `CLAUDE_CODE_*` keys from the env block.
    OAuth,
    /// API-key context — only minimal set (`ANTHROPIC_*`) written; unknown keys pass through.
    ApiKey,
}

/// Resolve the Claude Code state directory.
///
/// `CLAUDE_CONFIG_DIR` overrides `$HOME/.claude` (research doc §3).
///
/// # Errors
///
/// Returns `Error::Io` if `HOME` is not set and `CLAUDE_CONFIG_DIR` is also absent.
pub fn resolve_claude_dir() -> Result<PathBuf, Error> {
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME environment variable not set",
        ))
    })?;
    Ok(PathBuf::from(home).join(".claude"))
}

/// Return the path to `settings.json` inside the Claude state directory.
///
/// # Errors
///
/// Propagates errors from [`resolve_claude_dir`].
pub fn resolve_settings_path() -> Result<PathBuf, Error> {
    Ok(resolve_claude_dir()?.join("settings.json"))
}

/// Load `settings.json` as an opaque JSON value.
///
/// Returns an empty object `{}` when the file does not exist.
///
/// # Errors
///
/// - `SettingsParseError` if the file exists but is not valid JSON.
/// - `Io` for other I/O failures.
pub fn load_settings(path: &Path) -> Result<Value, Error> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let raw = std::fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|e| Error::SettingsParseError { msg: e.to_string() })
}

/// Read back the active API key (or auth token) from `settings.json`.
///
/// `path` must be the path to `settings.json` itself (not the parent directory).
/// Returns `None` when the file is absent, has no `env` block, or neither
/// `ANTHROPIC_API_KEY` nor `ANTHROPIC_AUTH_TOKEN` is set.
///
/// # Errors
///
/// Returns `SettingsParseError` if the file exists but is malformed JSON.
pub fn load_settings_api_key(path: &Path) -> Result<Option<Secret<String>>, Error> {
    let v = load_settings(path)?;
    let env = v.get("env").and_then(Value::as_object);
    if let Some(env) = env {
        if let Some(k) = env.get("ANTHROPIC_API_KEY").and_then(Value::as_str) {
            return Ok(Some(Secret::new(k.to_string())));
        }
        if let Some(k) = env.get("ANTHROPIC_AUTH_TOKEN").and_then(Value::as_str) {
            return Ok(Some(Secret::new(k.to_string())));
        }
    }
    Ok(None)
}

/// Read `ANTHROPIC_BASE_URL` from `settings.json`'s env block, if set.
///
/// `path` must be the path to `settings.json` itself (not the parent directory).
/// Returns `None` when the file is absent, has no `env` block, or the key is absent.
///
/// # Errors
///
/// Returns `SettingsParseError` if the file is malformed or the URL value cannot
/// be parsed as a valid URL.
pub fn load_settings_base_url(path: &Path) -> Result<Option<url::Url>, Error> {
    let v = load_settings(path)?;
    let env = v.get("env").and_then(Value::as_object);
    if let Some(env) = env {
        if let Some(s) = env.get("ANTHROPIC_BASE_URL").and_then(Value::as_str) {
            let u = url::Url::parse(s).map_err(|e| Error::SettingsParseError {
                msg: format!("invalid ANTHROPIC_BASE_URL '{s}': {e}"),
            })?;
            return Ok(Some(u));
        }
    }
    Ok(None)
}

/// Write the `env` block of `settings.json` atomically, applying forbidden-key guards.
///
/// `env_patch` maps env-var name → `Option<Secret<String>>`:
///
/// - `Some(value)` → set the key to that value.
/// - `None` → remove the key if present.
///
/// Forbidden-key rules:
///
/// - `CLAUDE_CODE_OAUTH_TOKEN` is **always** refused (returns `SettingsForbiddenKey`).
/// - In `OAuth` auth mode: every `CLAUDE_CODE_*` key is stripped silently
///   (arch §2, issue #49659 — env keys can break Keychain OAuth retrieval).
/// - In `ApiKey` auth mode: no additional restrictions; all keys pass through.
///
/// All non-`env` top-level keys in the existing `settings.json` are preserved verbatim.
///
/// # Errors
///
/// - `SettingsParseError` if the existing file is malformed.
/// - `SettingsForbiddenKey` if the caller tries to write `CLAUDE_CODE_OAUTH_TOKEN`.
/// - `Io` / `Json` for I/O or serialization failures.
pub fn save_settings_env(
    path: &Path,
    env_patch: BTreeMap<String, Option<Secret<String>>>,
    auth_mode_hint: AuthModeHint,
) -> Result<(), Error> {
    save_settings_env_inner(path, env_patch, auth_mode_hint).map(|_| ())
}

/// Variant of [`save_settings_env`] that also returns the bytes written to disk.
///
/// The returned `Vec<u8>` is the exact buffer passed to [`write_atomic_0600`],
/// suitable for post-apply byte-comparison in `switch_engine::verify_apply`.
///
/// # Errors
///
/// Same error conditions as [`save_settings_env`].
pub fn save_settings_env_returning_bytes(
    path: &Path,
    env_patch: BTreeMap<String, Option<Secret<String>>>,
    auth_mode_hint: AuthModeHint,
) -> Result<Vec<u8>, Error> {
    save_settings_env_inner(path, env_patch, auth_mode_hint)
}

fn save_settings_env_inner(
    path: &Path,
    env_patch: BTreeMap<String, Option<Secret<String>>>,
    auth_mode_hint: AuthModeHint,
) -> Result<Vec<u8>, Error> {
    // Guard: CLAUDE_CODE_OAUTH_TOKEN is unconditionally forbidden (#37512).
    if env_patch.contains_key("CLAUDE_CODE_OAUTH_TOKEN") {
        return Err(Error::SettingsForbiddenKey {
            key: "CLAUDE_CODE_OAUTH_TOKEN".to_string(),
        });
    }

    // Load existing settings (empty object if absent).
    let mut root = load_settings(path)?;

    let obj = root
        .as_object_mut()
        .ok_or_else(|| Error::SettingsParseError {
            msg: "settings.json root is not a JSON object".to_string(),
        })?;

    // Ensure the `env` key exists and is an object.
    let env = obj
        .entry("env")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| Error::SettingsParseError {
            msg: "settings.json .env is not a JSON object".to_string(),
        })?;

    // Apply the patch.
    for (k, v_opt) in env_patch {
        match v_opt {
            Some(secret) => {
                env.insert(k, Value::String(secret.expose().clone()));
            }
            None => {
                env.remove(&k);
            }
        }
    }

    // Strip forbidden keys after merge, per auth mode.
    match auth_mode_hint {
        AuthModeHint::OAuth => {
            // Remove all CLAUDE_CODE_* keys — they can break Keychain OAuth retrieval (#49659).
            let to_remove: Vec<String> = env
                .keys()
                .filter(|k| k.starts_with("CLAUDE_CODE_"))
                .cloned()
                .collect();
            for k in to_remove {
                env.remove(&k);
            }
        }
        AuthModeHint::ApiKey => {
            // No additional stripping for API-key mode.
        }
    }

    let bytes = serde_json::to_vec_pretty(&root)?;
    write_atomic_0600(path, &bytes)?;
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::similar_names)] // `path`/`patch` are intentional distinct names in test helpers
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    fn write_json(path: &Path, json: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, json).unwrap();
    }

    fn read_value(path: &Path) -> Value {
        let raw = fs::read_to_string(path).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    // ── test 1 ──────────────────────────────────────────────────────────────
    #[test]
    fn save_settings_env_creates_file_if_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");

        let mut patch = BTreeMap::new();
        patch.insert(
            "ANTHROPIC_API_KEY".to_string(),
            Some(Secret::new("sk-ant-test".to_string())),
        );
        save_settings_env(&path, patch, AuthModeHint::ApiKey).unwrap();

        assert!(path.exists());
        let v = read_value(&path);
        assert_eq!(v["env"]["ANTHROPIC_API_KEY"], "sk-ant-test");
    }

    // ── test 2 ──────────────────────────────────────────────────────────────
    #[test]
    fn save_settings_env_preserves_non_env_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        write_json(&path, r#"{"foo": 1, "env": {"OLD": "v"}}"#);

        let mut patch = BTreeMap::new();
        patch.insert("NEW".to_string(), Some(Secret::new("v".to_string())));
        save_settings_env(&path, patch, AuthModeHint::ApiKey).unwrap();

        let v = read_value(&path);
        assert_eq!(v["foo"], 1);
        assert_eq!(v["env"]["OLD"], "v");
        assert_eq!(v["env"]["NEW"], "v");
    }

    // ── test 3 ──────────────────────────────────────────────────────────────
    #[test]
    fn save_settings_env_unsets_when_value_is_none() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        write_json(&path, r#"{"env": {"A": "v"}}"#);

        let mut patch = BTreeMap::new();
        patch.insert("A".to_string(), None);
        save_settings_env(&path, patch, AuthModeHint::ApiKey).unwrap();

        let v = read_value(&path);
        assert!(v["env"].as_object().unwrap().is_empty());
    }

    // ── test 4 ──────────────────────────────────────────────────────────────
    #[test]
    fn save_settings_env_refuses_claude_code_oauth_token_always() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");

        for hint in [AuthModeHint::ApiKey, AuthModeHint::OAuth] {
            let mut patch = BTreeMap::new();
            patch.insert(
                "CLAUDE_CODE_OAUTH_TOKEN".to_string(),
                Some(Secret::new("tok".to_string())),
            );
            let err = save_settings_env(&path, patch, hint).unwrap_err();
            assert!(
                matches!(err, Error::SettingsForbiddenKey { ref key } if key == "CLAUDE_CODE_OAUTH_TOKEN"),
                "expected SettingsForbiddenKey, got: {err}"
            );
        }
    }

    // ── test 5 ──────────────────────────────────────────────────────────────
    #[test]
    fn save_settings_env_strips_claude_code_keys_for_oauth() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");

        let mut patch = BTreeMap::new();
        patch.insert(
            "CLAUDE_CODE_DISABLE_SOMETHING".to_string(),
            Some(Secret::new("1".to_string())),
        );
        patch.insert(
            "ANTHROPIC_API_KEY".to_string(),
            Some(Secret::new("key".to_string())),
        );
        save_settings_env(&path, patch, AuthModeHint::OAuth).unwrap();

        let v = read_value(&path);
        assert!(
            v["env"].get("CLAUDE_CODE_DISABLE_SOMETHING").is_none(),
            "CLAUDE_CODE_* must be stripped in OAuth mode"
        );
        assert_eq!(v["env"]["ANTHROPIC_API_KEY"], "key");
    }

    // ── test 6 ──────────────────────────────────────────────────────────────
    #[test]
    fn save_settings_env_apikey_mode_passes_through_unknown_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");

        let mut patch = BTreeMap::new();
        patch.insert(
            "ANTHROPIC_API_KEY".to_string(),
            Some(Secret::new("x".to_string())),
        );
        patch.insert(
            "SOMETHING_ELSE".to_string(),
            Some(Secret::new("y".to_string())),
        );
        save_settings_env(&path, patch, AuthModeHint::ApiKey).unwrap();

        let v = read_value(&path);
        assert_eq!(v["env"]["ANTHROPIC_API_KEY"], "x");
        assert_eq!(v["env"]["SOMETHING_ELSE"], "y");
    }

    // ── test 7 ──────────────────────────────────────────────────────────────
    #[cfg(unix)]
    #[test]
    fn save_settings_env_writes_mode_0600_on_unix() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");

        let patch = BTreeMap::new();
        save_settings_env(&path, patch, AuthModeHint::ApiKey).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    // ── test 8 ──────────────────────────────────────────────────────────────
    #[test]
    fn save_settings_env_pretty_prints_2_space_indent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");

        let mut patch = BTreeMap::new();
        patch.insert(
            "ANTHROPIC_API_KEY".to_string(),
            Some(Secret::new("k".to_string())),
        );
        save_settings_env(&path, patch, AuthModeHint::ApiKey).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("  \"env\":"),
            "expected 2-space indent for env key, got:\n{raw}"
        );
        assert!(
            raw.contains("    \"ANTHROPIC_API_KEY\":"),
            "expected 4-space indent for inner key, got:\n{raw}"
        );
    }

    // ── tests: load_settings_api_key ─────────────────────────────────────────

    #[test]
    fn load_settings_api_key_absent_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        // File does not exist → Ok(None)
        let result = load_settings_api_key(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_settings_api_key_no_env_block() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        write_json(&path, r#"{"foo": 1}"#);
        let result = load_settings_api_key(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_settings_api_key_present() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        write_json(&path, r#"{"env": {"ANTHROPIC_API_KEY": "sk-test-key"}}"#);
        let result = load_settings_api_key(&path).unwrap();
        assert_eq!(result.unwrap().expose(), "sk-test-key");
    }

    // ── tests: load_settings_base_url ────────────────────────────────────────

    #[test]
    fn load_settings_base_url_present() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        write_json(
            &path,
            r#"{"env": {"ANTHROPIC_BASE_URL": "https://gateway.example/v1"}}"#,
        );
        let result = load_settings_base_url(&path).unwrap();
        assert_eq!(result.unwrap().as_str(), "https://gateway.example/v1");
    }

    #[test]
    fn load_settings_base_url_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        write_json(&path, r#"{"env": {"ANTHROPIC_API_KEY": "k"}}"#);
        let result = load_settings_base_url(&path).unwrap();
        assert!(result.is_none());
    }

    // ── tests 9 + 10: resolve_claude_dir (sequential to avoid env-var race) ──
    #[test]
    fn resolve_claude_dir_env_override_and_default() {
        const KEY: &str = "CLAUDE_CONFIG_DIR";
        let dir = TempDir::new().unwrap();
        let expected = dir.path().to_path_buf();

        // -- test 9: env override --
        let prev = std::env::var_os(KEY);
        std::env::set_var(KEY, &expected);
        let with_override = resolve_claude_dir().unwrap();
        // restore before assertion so default test runs correctly
        match prev {
            Some(v) => std::env::set_var(KEY, v),
            None => std::env::remove_var(KEY),
        }
        assert_eq!(with_override, expected);

        // -- test 10: default (only when KEY is unset) --
        if std::env::var_os(KEY).is_none() {
            let default = resolve_claude_dir().unwrap();
            assert!(
                default.to_string_lossy().ends_with("/.claude"),
                "expected path ending in /.claude, got: {}",
                default.display()
            );
        }
    }

    // ── claude.json tests ────────────────────────────────────────────────────

    fn sample_oauth_account() -> OAuthAccount {
        OAuthAccount {
            account_uuid: "aaaaaaaa-0000-0000-0000-000000000001".to_string(),
            email_address: "test@example.com".to_string(),
            organization_uuid: Some("bbbbbbbb-0000-0000-0000-000000000002".to_string()),
            other: Map::new(),
        }
    }

    // ── test 11 ─────────────────────────────────────────────────────────────
    #[test]
    fn load_missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        let result = load_claude_dot_json(&path).unwrap();
        assert!(result.oauth_account.is_none());
        assert!(result.user_id.is_none());
        assert!(result.preserved.is_empty());
    }

    // ── test 12 ─────────────────────────────────────────────────────────────
    #[test]
    fn load_preserves_unknown_top_level_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        write_json(&path, r#"{"foo": 1, "bar": {"nested": true}}"#);
        let result = load_claude_dot_json(&path).unwrap();
        assert_eq!(result.preserved["foo"], 1);
        assert_eq!(result.preserved["bar"]["nested"], true);
    }

    // ── test 13 ─────────────────────────────────────────────────────────────
    #[test]
    fn load_parses_oauth_account() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        write_json(
            &path,
            r#"{"oauthAccount": {"accountUuid": "u1", "emailAddress": "a@b.com", "organizationUuid": null}}"#,
        );
        let result = load_claude_dot_json(&path).unwrap();
        let oa = result.oauth_account.unwrap();
        assert_eq!(oa.account_uuid, "u1");
        assert_eq!(oa.email_address, "a@b.com");
    }

    // ── test 14 ─────────────────────────────────────────────────────────────
    #[test]
    fn load_parses_user_id_string() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        write_json(&path, r#"{"userID": "deadbeefcafe"}"#);
        let result = load_claude_dot_json(&path).unwrap();
        assert_eq!(result.user_id.unwrap(), "deadbeefcafe");
    }

    // ── test 15 ─────────────────────────────────────────────────────────────
    #[test]
    fn merge_preserves_existing_preserved_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        write_json(&path, r#"{"projects": {}, "numStartups": 5}"#);
        merge_and_save_claude_dot_json(&path, &sample_oauth_account(), "uid1".to_string()).unwrap();
        let v = read_value(&path);
        assert_eq!(v["projects"], serde_json::json!({}));
        assert_eq!(v["numStartups"], 5);
    }

    // ── test 16 ─────────────────────────────────────────────────────────────
    #[test]
    fn merge_overwrites_existing_oauth_account() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        write_json(
            &path,
            r#"{"oauthAccount": {"accountUuid": "old", "emailAddress": "old@example.com", "organizationUuid": null}, "userID": "old-uid"}"#,
        );
        let new_oa = OAuthAccount {
            account_uuid: "new".to_string(),
            email_address: "new@example.com".to_string(),
            organization_uuid: None,
            other: Map::new(),
        };
        merge_and_save_claude_dot_json(&path, &new_oa, "new-uid".to_string()).unwrap();
        let v = read_value(&path);
        assert_eq!(v["oauthAccount"]["emailAddress"], "new@example.com");
        assert_eq!(v["userID"], "new-uid");
    }

    // ── test 17 ─────────────────────────────────────────────────────────────
    #[test]
    fn merge_sets_user_id_top_level() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        merge_and_save_claude_dot_json(&path, &sample_oauth_account(), "uid42".to_string())
            .unwrap();
        let v = read_value(&path);
        assert_eq!(v["userID"], "uid42");
    }

    // ── test 18 ─────────────────────────────────────────────────────────────
    #[cfg(unix)]
    #[test]
    fn merge_writes_file_mode_0600_on_unix() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        merge_and_save_claude_dot_json(&path, &sample_oauth_account(), "uid".to_string()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    // ── test 19 ─────────────────────────────────────────────────────────────
    #[test]
    fn merge_handles_missing_file_by_creating_fresh() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        assert!(!path.exists());
        merge_and_save_claude_dot_json(&path, &sample_oauth_account(), "fresh-uid".to_string())
            .unwrap();
        assert!(path.exists());
        let v = read_value(&path);
        assert!(v.get("oauthAccount").is_some());
        assert_eq!(v["userID"], "fresh-uid");
        // No extra keys beyond oauthAccount and userID
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 2);
    }

    // ── test 20 ─────────────────────────────────────────────────────────────
    #[test]
    fn merge_preserves_pretty_2space_indent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        merge_and_save_claude_dot_json(&path, &sample_oauth_account(), "uid".to_string()).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("  \"oauthAccount\":"),
            "expected 2-space indent, got:\n{raw}"
        );
    }

    // ── test 21 ─────────────────────────────────────────────────────────────
    #[test]
    fn expires_at_parses_millis_integer() {
        let json = r#"{"expiresAt": 1800000000000}"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        let expires: ExpiresAt = serde_json::from_value(parsed["expiresAt"].clone()).unwrap();
        assert!(matches!(expires, ExpiresAt::Millis(1_800_000_000_000)));
    }

    // ── test 22 ─────────────────────────────────────────────────────────────
    #[test]
    fn expires_at_parses_iso_string() {
        let json = r#"{"expiresAt": "2027-02-18T07:00:00.000Z"}"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        let expires: ExpiresAt = serde_json::from_value(parsed["expiresAt"].clone()).unwrap();
        assert!(matches!(expires, ExpiresAt::Iso(_)));
        if let ExpiresAt::Iso(s) = expires {
            assert_eq!(s, "2027-02-18T07:00:00.000Z");
        }
    }

    // ── test 23 ─────────────────────────────────────────────────────────────
    #[test]
    fn expires_at_roundtrip_preserves_form() {
        // Millis form
        let millis = ExpiresAt::Millis(1_800_000_000_000_i64);
        let serialized = serde_json::to_string(&millis).unwrap();
        let deserialized: ExpiresAt = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, ExpiresAt::Millis(1_800_000_000_000)));

        // ISO form
        let iso = ExpiresAt::Iso("2027-02-18T07:00:00.000Z".to_string());
        let serialized = serde_json::to_string(&iso).unwrap();
        let deserialized: ExpiresAt = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, ExpiresAt::Iso(_)));
        if let ExpiresAt::Iso(s) = deserialized {
            assert_eq!(s, "2027-02-18T07:00:00.000Z");
        }
    }

    // ── test 24 ─────────────────────────────────────────────────────────────
    #[test]
    fn oauth_account_camelcase_serde_roundtrip() {
        let account = OAuthAccount {
            account_uuid: "test-uuid".to_string(),
            email_address: "user@example.com".to_string(),
            organization_uuid: Some("org-uuid".to_string()),
            other: Map::new(),
        };
        let json = serde_json::to_string(&account).unwrap();
        let deserialized: OAuthAccount = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, account);
        // Verify camelCase key names in output
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("accountUuid").is_some(), "expected accountUuid key");
        assert!(v.get("emailAddress").is_some(), "expected emailAddress key");
        assert!(
            v.get("organizationUuid").is_some(),
            "expected organizationUuid key"
        );
    }
}
