//! Orchestrate plan→snapshot→apply→verify→commit across the three stores.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::backup;
use crate::claude_state::{self, AuthModeHint};
use crate::config::{ConfigPaths, ContextsFile};
use crate::context::{AuthMode, Context, Fingerprint, SecretRef};
use crate::errors::Error;
use crate::journal::{self, EntryId, Intent, Journal, Op, PlannedOp, Store};
use crate::secret::Secret;

// ─── Public types ─────────────────────────────────────────────────────────────

/// All runtime handles the engine needs to interact with credential stores.
pub struct Stores<'a> {
    pub backend: &'a dyn crate::credential_backend::CredentialBackend,
    /// e.g. "Claude Code-credentials"
    pub keychain_service: &'a str,
    /// e.g. $USER
    pub keychain_account: &'a str,
    /// Path to `~/.claude.json` (outside `~/.claude/`).
    pub claude_dot_json_path: &'a Path,
    /// Path to `~/.claude/settings.json`.
    pub settings_json_path: &'a Path,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SwitchOutcome {
    Applied { from: Option<String>, to: String },
    NoOp { reason: NoOpReason },
    RolledBack { cause: String },
}

#[derive(Debug, PartialEq, Eq)]
pub enum NoOpReason {
    AlreadyActive,
    NoContextsConfigured,
    ContextNotFound,
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Phase-2 scope: API-key only (plaintext `SecretRef`).
/// OAuth + Keychain-backed API keys land in issue 3.5.
///
/// # Errors
///
/// Returns `Error::Unimplemented` for non-API-key contexts.
/// Returns `Error::SnapshotWriteFailed` when the pre-apply snapshot cannot be written.
/// Returns `Error::RollbackFailed` when rollback itself fails after an apply/verify error.
/// Other variants propagate from `journal`, `claude_state`, and `backup` modules.
pub fn execute_switch(
    current: &ContextsFile,
    target_name: &str,
    stores: &Stores<'_>,
    journal: &mut Journal,
    paths: &ConfigPaths,
) -> Result<SwitchOutcome, Error> {
    // ── Phase 1: Plan ─────────────────────────────────────────────────────────
    let Some(target) = current.contexts.get(target_name) else {
        return Ok(SwitchOutcome::NoOp {
            reason: NoOpReason::ContextNotFound,
        });
    };

    // Idempotency guard via fingerprint.
    let live_fp = compute_live_fingerprint(stores.settings_json_path)?;
    if live_fp.as_ref() == Some(&target.fingerprint) {
        return Ok(SwitchOutcome::NoOp {
            reason: NoOpReason::AlreadyActive,
        });
    }

    // For 2.4 scope, only API-key plaintext is supported.
    match (&target.auth_mode, &target.secret_ref) {
        (AuthMode::ApiKey { .. }, SecretRef::Plaintext { .. }) => {}
        (AuthMode::OAuth, _) | (AuthMode::ApiKey { .. }, SecretRef::ClaudeCodeKeychain) => {
            return Err(Error::Unimplemented {
                what: "OAuth switch lands in issue 3.5",
            });
        }
        (AuthMode::ApiKey { .. }, SecretRef::Keychain { .. }) => {
            return Err(Error::Unimplemented {
                what: "Keychain-backed API key switch lands in issue 3.5",
            });
        }
    }

    let planned_ops = vec![PlannedOp {
        store: Store::Settings,
        op: Op::Write,
    }];
    // Phase 3 stub points; 3.5 will add ClaudeDotJson and Keychain ops here.

    // Derive "from" context name by matching live fingerprint to known contexts.
    let from = live_fp.as_ref().and_then(|fp| {
        current
            .contexts
            .iter()
            .find(|(_, ctx)| &ctx.fingerprint == fp)
            .map(|(name, _)| name.clone())
    });

    // Ensure backups dir exists (0700).
    std::fs::create_dir_all(&paths.backups_dir)
        .map_err(|e| Error::SnapshotWriteFailed { source: e })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ =
            std::fs::set_permissions(&paths.backups_dir, std::fs::Permissions::from_mode(0o700));
    }

    let snapshot_filename = format!(
        "{}.json",
        chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S%.3fZ")
    );
    let snapshot_path = paths.backups_dir.join(&snapshot_filename);

    let entry_id = journal.append(
        Intent::Switch,
        from.clone(),
        Some(target_name.to_string()),
        planned_ops,
        snapshot_path.clone(),
    )?;

    // ── Phase 2: Snapshot ─────────────────────────────────────────────────────
    let snap = match backup::capture_snapshot(
        stores.backend,
        stores.keychain_service,
        stores.keychain_account,
        stores.claude_dot_json_path,
        stores.settings_json_path,
        &snapshot_path,
    ) {
        Ok(s) => s,
        Err(e) => {
            let _ = journal.mark_failed(entry_id, &e.to_string());
            return Err(Error::SnapshotWriteFailed {
                source: std::io::Error::other(e.to_string()),
            });
        }
    };

    // ── Phase 3: Apply ────────────────────────────────────────────────────────
    // Step 1: settings.json write.
    let apply_result = apply_settings(target, stores.settings_json_path);
    // Step 2: ~/.claude.json merge — 2.4 scope: NO-OP for API-key targets.
    // TODO(3.7): wires claude.json merge for OAuth here.
    // Step 3: Keychain — 2.4 scope: no Keychain write for API-key targets.
    // TODO(3.5): wires Keychain write for OAuth / Keychain-backed API keys here.

    if let Err(apply_err) = apply_result {
        return rollback_and_report(
            entry_id,
            apply_err.to_string(),
            &snap,
            stores,
            journal,
            snapshot_path,
        );
    }

    // ── Phase 4: Verify ───────────────────────────────────────────────────────
    // Verify settings.json write.
    if let Err(verify_err) = verify_settings(target, stores.settings_json_path) {
        return rollback_and_report(
            entry_id,
            verify_err.to_string(),
            &snap,
            stores,
            journal,
            snapshot_path,
        );
    }
    // 2.4 scope: no claude.json verify; no Keychain verify.

    // ── Phase 5: Commit ───────────────────────────────────────────────────────
    journal.mark_completed(entry_id)?;
    Ok(SwitchOutcome::Applied {
        from,
        to: target_name.to_string(),
    })
}

// ─── Private helpers ──────────────────────────────────────────────────────────

fn rollback_and_report(
    entry_id: EntryId,
    cause: String,
    snap: &backup::Snapshot,
    stores: &Stores<'_>,
    journal: &mut Journal,
    snapshot_path: PathBuf,
) -> Result<SwitchOutcome, Error> {
    let rb = backup::restore_snapshot(
        snap,
        stores.backend,
        stores.keychain_service,
        stores.keychain_account,
        stores.claude_dot_json_path,
        stores.settings_json_path,
    );
    match rb {
        Ok(()) => {
            let _ = journal.mark_failed(entry_id, &cause);
            Ok(SwitchOutcome::RolledBack { cause })
        }
        Err(rb_err) => {
            eprintln!(
                "cctx: ROLLBACK FAILED — manual recovery required. \
                 Snapshot at: {path}. Rollback error: {rb_err}",
                path = snapshot_path.display()
            );
            let _ = journal.mark_failed(entry_id, "rollback failed");
            Err(Error::RollbackFailed {
                attempted_stores: vec![Store::Settings],
                path: snapshot_path,
            })
        }
    }
}

/// Compute the fingerprint of the currently-live API key, if any.
fn compute_live_fingerprint(settings_path: &Path) -> Result<Option<Fingerprint>, Error> {
    claude_state::load_settings_api_key(settings_path)
        .map(|opt| opt.map(|key| Fingerprint::from_api_key(&key)))
}

/// Build the settings env patch for an API-key context (same logic as 1.5's `handle_switch`).
fn build_settings_patch(
    target: &Context,
) -> Result<BTreeMap<String, Option<Secret<String>>>, Error> {
    let (AuthMode::ApiKey { base_url }, SecretRef::Plaintext { value: key }) =
        (&target.auth_mode, &target.secret_ref)
    else {
        return Err(Error::Unimplemented {
            what: "non-plaintext API key patch not supported in 2.4",
        });
    };

    let mut patch: BTreeMap<String, Option<Secret<String>>> = BTreeMap::new();
    patch.insert("ANTHROPIC_API_KEY".to_string(), Some(key.clone()));
    patch.insert("ANTHROPIC_AUTH_TOKEN".to_string(), None);
    if let Some(url) = base_url {
        patch.insert(
            "ANTHROPIC_BASE_URL".to_string(),
            Some(Secret::new(url.to_string())),
        );
    } else {
        patch.insert("ANTHROPIC_BASE_URL".to_string(), None);
    }
    Ok(patch)
}

/// Apply the settings.json write for an API-key context.
fn apply_settings(target: &Context, settings_path: &Path) -> Result<(), Error> {
    let patch = build_settings_patch(target)?;
    claude_state::save_settings_env(settings_path, patch, AuthModeHint::ApiKey)
}

/// Verify that settings.json reflects the planned write by re-reading and comparing.
fn verify_settings(target: &Context, settings_path: &Path) -> Result<(), Error> {
    let patch = build_settings_patch(target)?;
    let settings = claude_state::load_settings(settings_path)?;
    for (k, v_opt) in &patch {
        let got = settings
            .get("env")
            .and_then(|e| e.get(k))
            .and_then(|x| x.as_str());
        match v_opt {
            Some(expected) => {
                if got != Some(expected.expose().as_str()) {
                    return Err(Error::VerifyFailed {
                        which_store: journal::Store::Settings,
                    });
                }
            }
            None => {
                if got.is_some() {
                    return Err(Error::VerifyFailed {
                        which_store: journal::Store::Settings,
                    });
                }
            }
        }
    }
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContextsFile;
    use crate::context::{AuthMode, Context, Fingerprint, IdentityMetadata};
    use crate::credential_backend::InMemoryBackend;
    use crate::journal::{EntryStatus, Journal};
    use crate::secret::Secret;
    use indexmap::IndexMap;
    use tempfile::TempDir;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_api_key_context(name: &str, api_key: &str) -> Context {
        let key = Secret::new(api_key.to_string());
        let fp = Fingerprint::from_api_key(&key);
        Context {
            name: name.to_string(),
            auth_mode: AuthMode::ApiKey { base_url: None },
            identity: IdentityMetadata::default(),
            fingerprint: fp,
            created_at: chrono::Utc::now(),
            secret_ref: SecretRef::Plaintext { value: key },
        }
    }

    fn make_oauth_context(name: &str) -> Context {
        Context {
            name: name.to_string(),
            auth_mode: AuthMode::OAuth,
            identity: IdentityMetadata::default(),
            fingerprint: Fingerprint([0xABu8; 32]),
            created_at: chrono::Utc::now(),
            secret_ref: SecretRef::ClaudeCodeKeychain,
        }
    }

    fn contexts_file_with(contexts: Vec<Context>) -> ContextsFile {
        let mut map = IndexMap::new();
        for ctx in contexts {
            map.insert(ctx.name.clone(), ctx);
        }
        ContextsFile {
            version: 1,
            contexts: map,
        }
    }

    struct TestEnv {
        _cctx_dir: TempDir,
        _claude_dir: TempDir,
        pub paths: ConfigPaths,
        pub settings_path: PathBuf,
        pub claude_dot_json_path: PathBuf,
    }

    fn setup_test_env() -> TestEnv {
        let cctx_dir = TempDir::new().unwrap();
        let claude_dir = TempDir::new().unwrap();
        let paths = ConfigPaths {
            backups_dir: cctx_dir.path().join("backups"),
            journal_file: cctx_dir.path().join("journal.log"),
            lock_file: cctx_dir.path().join(".lock"),
            contexts_file: cctx_dir.path().join("contexts.yaml"),
            config_dir: cctx_dir.path().to_path_buf(),
        };
        let settings_path = claude_dir.path().join("settings.json");
        let claude_dot_json_path = claude_dir.path().join(".claude.json");
        TestEnv {
            _cctx_dir: cctx_dir,
            _claude_dir: claude_dir,
            paths,
            settings_path,
            claude_dot_json_path,
        }
    }

    fn write_settings_with_key(path: &Path, api_key: &str) {
        let json = format!(r#"{{"env":{{"ANTHROPIC_API_KEY":"{api_key}"}}}}"#);
        std::fs::write(path, json).unwrap();
    }

    fn make_stores<'a>(backend: &'a InMemoryBackend, env: &'a TestEnv) -> Stores<'a> {
        Stores {
            backend,
            keychain_service: "test-svc",
            keychain_account: "test-acc",
            claude_dot_json_path: &env.claude_dot_json_path,
            settings_json_path: &env.settings_path,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn already_active_returns_noop() {
        let env = setup_test_env();
        let api_key = "sk-ant-already-active";
        write_settings_with_key(&env.settings_path, api_key);

        let ctx = make_api_key_context("work", api_key);
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert_eq!(
            outcome,
            SwitchOutcome::NoOp {
                reason: NoOpReason::AlreadyActive
            }
        );
    }

    #[test]
    fn unknown_target_returns_context_not_found() {
        let env = setup_test_env();
        let cf = contexts_file_with(vec![
            make_api_key_context("a", "sk-ant-a"),
            make_api_key_context("b", "sk-ant-b"),
        ]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "c", &stores, &mut journal, &env.paths).unwrap();
        assert_eq!(
            outcome,
            SwitchOutcome::NoOp {
                reason: NoOpReason::ContextNotFound
            }
        );
    }

    #[test]
    fn applies_api_key_switch_end_to_end() {
        let env = setup_test_env();
        let ctx_a = make_api_key_context("work", "sk-ant-key-work");
        let cf = contexts_file_with(vec![ctx_a]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert!(
            matches!(outcome, SwitchOutcome::Applied { ref to, .. } if to == "work"),
            "expected Applied, got {outcome:?}"
        );

        let settings = claude_state::load_settings(&env.settings_path).unwrap();
        assert_eq!(
            settings["env"]["ANTHROPIC_API_KEY"], "sk-ant-key-work",
            "settings.json must contain the new API key"
        );

        let all = journal.read_all().unwrap();
        assert_eq!(all.len(), 1);
        assert!(
            matches!(all[0].status, EntryStatus::Completed { .. }),
            "journal entry must be Completed"
        );
    }

    #[test]
    fn oauth_target_returns_unimplemented() {
        let env = setup_test_env();
        let cf = contexts_file_with(vec![make_oauth_context("personal")]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let err = execute_switch(&cf, "personal", &stores, &mut journal, &env.paths).unwrap_err();
        assert!(
            matches!(err, Error::Unimplemented { .. }),
            "expected Unimplemented, got {err:?}"
        );
    }

    #[test]
    fn journal_records_pending_then_completed_on_success() {
        let env = setup_test_env();
        let ctx = make_api_key_context("work", "sk-ant-journal-test");
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert!(matches!(outcome, SwitchOutcome::Applied { .. }));

        let uncommitted = journal.find_uncommitted().unwrap();
        assert!(
            uncommitted.is_empty(),
            "no uncommitted entries after success"
        );
    }

    #[test]
    fn snapshot_taken_before_apply() {
        let env = setup_test_env();
        let ctx = make_api_key_context("work", "sk-ant-snap-test");
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();

        let backups: Vec<_> = std::fs::read_dir(&env.paths.backups_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(backups.len(), 1, "exactly one snapshot file should exist");
        assert!(
            backups[0].file_name().to_string_lossy().ends_with(".json"),
            "snapshot file should be .json"
        );
    }

    #[test]
    fn idempotent_second_invocation_is_noop() {
        let env = setup_test_env();
        let ctx = make_api_key_context("work", "sk-ant-idempotent");
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let first = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert!(matches!(first, SwitchOutcome::Applied { .. }));

        let second = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert_eq!(
            second,
            SwitchOutcome::NoOp {
                reason: NoOpReason::AlreadyActive
            }
        );

        // Only one snapshot should exist (second call returned NoOp before snapshot).
        let backups: Vec<_> = std::fs::read_dir(&env.paths.backups_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(backups.len(), 1, "only one snapshot from the first switch");
    }

    #[test]
    fn from_field_is_none_when_no_prior_key() {
        let env = setup_test_env();
        let ctx = make_api_key_context("work", "sk-ant-fresh");
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert!(
            matches!(outcome, SwitchOutcome::Applied { from: None, .. }),
            "from must be None when no prior context active"
        );
    }
}
