//! Load/save `~/.config/cctx/contexts.yaml` atomically.

use std::path::PathBuf;

use etcetera::base_strategy::{choose_base_strategy, BaseStrategy};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::errors::Error;
use crate::fs_atomic::write_atomic_0600;

/// Resolved paths for all cctx-managed files.
pub struct ConfigPaths {
    pub config_dir: PathBuf,
    pub contexts_file: PathBuf,
    pub backups_dir: PathBuf,
    pub journal_file: PathBuf,
    pub lock_file: PathBuf,
}

/// The top-level `contexts.yaml` document.
// `PartialEq` only — `Context` contains `IdentityMetadata.oauth_account` which has no `Eq`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ContextsFile {
    pub version: u32,
    pub contexts: IndexMap<String, Context>,
}

/// Resolve the paths for all cctx-managed files.
///
/// If `CCTX_HOME` is set, it is used as `config_dir` directly (test override,
/// arch §9).  Otherwise `etcetera::choose_base_strategy()` determines the XDG
/// config directory and `cctx/` is appended.
///
/// # Errors
///
/// Returns [`Error::EtceteraStrategyFailed`] when no base strategy can be
/// determined (typically on platforms with no `HOME`).
pub fn resolve_paths() -> Result<ConfigPaths, Error> {
    let config_dir = if let Some(home) = std::env::var_os("CCTX_HOME") {
        PathBuf::from(home)
    } else {
        choose_base_strategy()
            .map(|s| s.config_dir().join("cctx"))
            .map_err(|e| Error::EtceteraStrategyFailed { msg: e.to_string() })?
    };

    Ok(ConfigPaths {
        contexts_file: config_dir.join("contexts.yaml"),
        backups_dir: config_dir.join("backups"),
        journal_file: config_dir.join("journal.log"),
        lock_file: config_dir.join(".lock"),
        config_dir,
    })
}

/// Load `contexts.yaml` from disk.
///
/// If the file does not exist, returns an empty [`ContextsFile`] with
/// `version: 1` rather than an error — a missing file is treated as
/// "no contexts yet".
///
/// # Errors
///
/// Returns [`Error::ContextsParseError`] when the file exists but cannot be
/// parsed.  Returns [`Error::Io`] on other read failures.
pub fn load(paths: &ConfigPaths) -> Result<ContextsFile, Error> {
    if !paths.contexts_file.exists() {
        return Ok(ContextsFile {
            version: 1,
            contexts: IndexMap::new(),
        });
    }

    let raw =
        std::fs::read_to_string(&paths.contexts_file).map_err(|e| Error::ConfigWriteFailed {
            path: paths.contexts_file.clone(),
            source: e,
        })?;

    serde_yaml_ng::from_str(&raw).map_err(|e| Error::ContextsParseError {
        path: paths.contexts_file.clone(),
        msg: e.to_string(),
    })
}

/// Save `contexts.yaml` atomically with mode `0o600`.
///
/// Creates `config_dir` (and parents) with mode `0o700` on Unix if absent.
///
/// # Errors
///
/// Returns [`Error::ConfigDirCreateFailed`] if the directory cannot be created,
/// or [`Error::ConfigWriteFailed`] on write failure.
pub fn save(paths: &ConfigPaths, c: &ContextsFile) -> Result<(), Error> {
    ensure_config_dir(&paths.config_dir)?;

    let yaml = serde_yaml_ng::to_string(c).map_err(|e| Error::ContextsParseError {
        path: paths.contexts_file.clone(),
        msg: e.to_string(),
    })?;

    write_atomic_0600(&paths.contexts_file, yaml.as_bytes())
}

fn ensure_config_dir(dir: &std::path::Path) -> Result<(), Error> {
    std::fs::create_dir_all(dir).map_err(|e| Error::ConfigDirCreateFailed {
        path: dir.to_owned(),
        source: e,
    })?;

    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, Permissions::from_mode(0o700)).map_err(|e| {
            Error::ConfigDirCreateFailed {
                path: dir.to_owned(),
                source: e,
            }
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{AuthMode, Context, Fingerprint, IdentityMetadata, SecretRef};
    use crate::secret::Secret;
    use chrono::TimeZone as _;
    use tempfile::tempdir;

    fn fixed_ts() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 4, 18, 2, 14, 5).unwrap()
    }

    fn oauth_ctx(name: &str) -> Context {
        Context {
            name: name.to_string(),
            auth_mode: AuthMode::OAuth,
            identity: IdentityMetadata {
                user_id: Some("f3a9abc".to_string()),
                account_uuid: Some("8c2edef".to_string()),
                email_hint: Some("a***@example.com".to_string()),
                label: None,
                oauth_account: None,
            },
            fingerprint: Fingerprint([0x3b; 32]),
            created_at: fixed_ts(),
            secret_ref: SecretRef::ClaudeCodeKeychain,
        }
    }

    fn api_key_ctx(name: &str, key: &str) -> Context {
        Context {
            name: name.to_string(),
            auth_mode: AuthMode::ApiKey { base_url: None },
            identity: IdentityMetadata {
                label: Some(format!("{name} label")),
                ..Default::default()
            },
            fingerprint: Fingerprint([0xc1; 32]),
            created_at: fixed_ts(),
            secret_ref: SecretRef::Plaintext {
                value: Secret::new(key.to_string()),
            },
        }
    }

    fn paths_in(dir: &std::path::Path) -> ConfigPaths {
        let cctx_dir = dir.join("cctx");
        ConfigPaths {
            contexts_file: cctx_dir.join("contexts.yaml"),
            backups_dir: cctx_dir.join("backups"),
            journal_file: cctx_dir.join("journal.log"),
            lock_file: cctx_dir.join(".lock"),
            config_dir: cctx_dir,
        }
    }

    #[test]
    fn resolve_paths_uses_cctx_home_override() {
        let dir = tempdir().unwrap();
        let tmp_path = dir.path().to_str().unwrap().to_string();
        // Isolate env mutation to this test using a local scope
        let old = std::env::var_os("CCTX_HOME");
        std::env::set_var("CCTX_HOME", &tmp_path);
        let result = resolve_paths();
        match old {
            Some(v) => std::env::set_var("CCTX_HOME", v),
            None => std::env::remove_var("CCTX_HOME"),
        }
        let paths = result.unwrap();
        assert_eq!(paths.config_dir, dir.path());
        assert_eq!(paths.contexts_file, dir.path().join("contexts.yaml"));
    }

    #[test]
    fn resolve_paths_default_contains_cctx() {
        let old = std::env::var_os("CCTX_HOME");
        std::env::remove_var("CCTX_HOME");
        let result = resolve_paths();
        if let Some(v) = old {
            std::env::set_var("CCTX_HOME", v);
        }
        let paths = result.unwrap();
        assert!(
            paths.config_dir.ends_with("cctx"),
            "config_dir should end with 'cctx', got: {}",
            paths.config_dir.display()
        );
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempdir().unwrap();
        let paths = paths_in(dir.path());
        // cctx/ dir doesn't exist, contexts.yaml doesn't exist
        let cf = load(&paths).unwrap();
        assert_eq!(cf.version, 1);
        assert!(cf.contexts.is_empty());
    }

    #[test]
    fn load_parse_error_reports_path() {
        let dir = tempdir().unwrap();
        let paths = paths_in(dir.path());
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(&paths.contexts_file, b": invalid: yaml: {\n").unwrap();
        let err = load(&paths).unwrap_err();
        match err {
            Error::ContextsParseError { path, .. } => {
                assert_eq!(path, paths.contexts_file);
            }
            other => panic!("expected ContextsParseError, got {other:?}"),
        }
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempdir().unwrap();
        let paths = paths_in(dir.path());

        let mut contexts = IndexMap::new();
        contexts.insert("personal".to_string(), oauth_ctx("personal"));
        contexts.insert("work".to_string(), api_key_ctx("work", "sk-ant-work"));
        let cf = ContextsFile {
            version: 1,
            contexts,
        };

        save(&paths, &cf).unwrap();
        let loaded = load(&paths).unwrap();

        assert_eq!(loaded.version, 1);
        let keys: Vec<_> = loaded.contexts.keys().cloned().collect();
        assert_eq!(
            keys,
            vec!["personal", "work"],
            "insertion order must be preserved"
        );
        assert_eq!(loaded, cf);
    }

    #[cfg(unix)]
    #[test]
    fn save_is_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let paths = paths_in(dir.path());
        let cf = ContextsFile {
            version: 1,
            contexts: IndexMap::new(),
        };
        save(&paths, &cf).unwrap();
        let mode = std::fs::metadata(&paths.contexts_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }

    #[test]
    fn save_creates_config_dir() {
        let dir = tempdir().unwrap();
        let paths = paths_in(dir.path());
        assert!(!paths.config_dir.exists());
        let cf = ContextsFile {
            version: 1,
            contexts: IndexMap::new(),
        };
        save(&paths, &cf).unwrap();
        assert!(paths.config_dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_config_dir_with_mode_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let paths = paths_in(dir.path());
        let cf = ContextsFile {
            version: 1,
            contexts: IndexMap::new(),
        };
        save(&paths, &cf).unwrap();
        let mode = std::fs::metadata(&paths.config_dir)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "expected 0700, got {:o}", mode & 0o777);
    }

    #[test]
    fn save_writes_full_contents() {
        let dir = tempdir().unwrap();
        let paths = paths_in(dir.path());
        let cf = ContextsFile {
            version: 1,
            contexts: IndexMap::new(),
        };
        save(&paths, &cf).unwrap();
        let on_disk = std::fs::read_to_string(&paths.contexts_file).unwrap();
        assert!(
            on_disk.contains("version: 1"),
            "should contain version field: {on_disk}"
        );
    }

    #[test]
    fn load_contexts_minimal_fixture_preserves_order() {
        let yaml = include_str!("../tests/fixtures/contexts-minimal.yaml");
        let cf: ContextsFile = serde_yaml_ng::from_str(yaml).unwrap();
        let keys: Vec<_> = cf.contexts.keys().cloned().collect();
        assert_eq!(keys, vec!["personal", "work", "console-key"]);
    }
}
