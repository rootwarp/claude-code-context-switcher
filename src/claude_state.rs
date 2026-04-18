//! Read/write `~/.claude.json`, `~/.claude/settings.json`; detect `.credentials.json` fallback.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::errors::Error;
use crate::fs_atomic::write_atomic_0600;
use crate::secret::Secret;

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
/// Returns `None` when neither `ANTHROPIC_API_KEY` nor `ANTHROPIC_AUTH_TOKEN` is set.
///
/// # Errors
///
/// Propagates `SettingsParseError` or `Io` from [`load_settings`].
pub fn load_settings_api_key(claude_dir: &Path) -> Result<Option<Secret<String>>, Error> {
    let path = claude_dir.join("settings.json");
    let v = load_settings(&path)?;
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

/// Write the `env` block of `settings.json` atomically, applying forbidden-key guards.
///
/// `env_patch` maps env-var name → `Option<Secret<String>>`:
/// - `Some(value)` → set the key to that value.
/// - `None` → remove the key if present.
///
/// Forbidden-key rules:
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
    Ok(())
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
}
