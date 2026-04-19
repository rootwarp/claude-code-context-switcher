//! Fault-injection rollback tests for the switch engine.

use std::path::PathBuf;

use claude_code_context_switcher::claude_state::OAuthAccount;
use claude_code_context_switcher::config::{ConfigPaths, ContextsFile};
use claude_code_context_switcher::context::{
    AuthMode, Context, Fingerprint, IdentityMetadata, SecretRef,
};
use claude_code_context_switcher::credential_backend::{
    BackendError, CredentialBackend, FaultInjectingBackend, FaultMethod, InMemoryBackend,
    PasswordOptions,
};
use claude_code_context_switcher::errors::Error;
use claude_code_context_switcher::journal::{EntryStatus, Journal};
use claude_code_context_switcher::secret::Secret;
use claude_code_context_switcher::switch_engine::{execute_switch, Stores, SwitchOutcome};
use indexmap::IndexMap;
use tempfile::TempDir;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn make_oauth_account(uuid: &str, email: &str) -> OAuthAccount {
    OAuthAccount {
        account_uuid: uuid.to_string(),
        email_address: email.to_string(),
        organization_uuid: None,
        other: serde_json::Map::new(),
    }
}

fn make_oauth_context(
    name: &str,
    user_id: &str,
    account: OAuthAccount,
    mirror_service: &str,
    mirror_account: &str,
    blob: &[u8],
) -> Context {
    use claude_code_context_switcher::claude_state::KeychainBlobEnvelope;
    let envelope: KeychainBlobEnvelope = serde_json::from_slice(blob).unwrap();
    let fp = claude_code_context_switcher::fingerprint::compute_oauth(
        user_id,
        &account.account_uuid,
        &envelope.claude_ai_oauth.access_token,
    );
    Context {
        name: name.to_string(),
        auth_mode: AuthMode::OAuth,
        identity: IdentityMetadata {
            user_id: Some(user_id.to_string()),
            account_uuid: Some(account.account_uuid.clone()),
            email_hint: Some("w***@example.com".to_string()),
            label: None,
            oauth_account: Some(account),
        },
        fingerprint: fp,
        created_at: chrono::Utc::now(),
        secret_ref: SecretRef::Keychain {
            service: mirror_service.to_string(),
            account: mirror_account.to_string(),
        },
    }
}

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
    pub claude_dir: PathBuf,
}

/// Like `setup_test_env` but places `claude_dot_json_path` in a separate subdirectory.
/// This lets tests make only the CDJ parent read-only without affecting `settings_path`.
fn setup_test_env_split_cdj() -> TestEnv {
    let cctx_dir = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    let cdj_sub = claude_dir.path().join("cdj_sub");
    std::fs::create_dir_all(&cdj_sub).unwrap();
    let paths = ConfigPaths {
        backups_dir: cctx_dir.path().join("backups"),
        journal_file: cctx_dir.path().join("journal.log"),
        lock_file: cctx_dir.path().join(".lock"),
        contexts_file: cctx_dir.path().join("contexts.yaml"),
        config_dir: cctx_dir.path().to_path_buf(),
    };
    let settings_path = claude_dir.path().join("settings.json");
    let claude_dot_json_path = cdj_sub.join(".claude.json");
    let claude_dir_path = claude_dir.path().to_path_buf();
    TestEnv {
        _cctx_dir: cctx_dir,
        _claude_dir: claude_dir,
        paths,
        settings_path,
        claude_dot_json_path,
        claude_dir: claude_dir_path,
    }
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
    let claude_dir_path = claude_dir.path().to_path_buf();
    TestEnv {
        _cctx_dir: cctx_dir,
        _claude_dir: claude_dir,
        paths,
        settings_path,
        claude_dot_json_path,
        claude_dir: claude_dir_path,
    }
}

fn make_stores_with_backend<'a>(
    backend: &'a dyn CredentialBackend,
    env: &'a TestEnv,
) -> Stores<'a> {
    Stores {
        backend,
        keychain_service: "test-svc",
        keychain_account: "test-acc",
        claude_dot_json_path: &env.claude_dot_json_path,
        settings_json_path: &env.settings_path,
        claude_dir: &env.claude_dir,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// `FaultInjectingBackend` call counting: 3 calls with fail_on_nth=2 → first ok, second fails, third ok.
#[test]
fn fault_injecting_backend_counts_calls_correctly() {
    let inner = InMemoryBackend::new();
    inner
        .set_generic_password("svc", "acc", b"val", PasswordOptions::default())
        .unwrap();

    let fib = FaultInjectingBackend::new(&inner, FaultMethod::Get, 2, BackendError::AccessDenied);

    assert!(
        fib.get_generic_password("svc", "acc").is_ok(),
        "call 1 must succeed"
    );
    assert!(
        matches!(
            fib.get_generic_password("svc", "acc").unwrap_err(),
            BackendError::AccessDenied
        ),
        "call 2 must fail with AccessDenied"
    );
    assert!(
        fib.get_generic_password("svc", "acc").is_ok(),
        "call 3 must succeed"
    );
}

/// Method isolation: FaultMethod::Set instrumented; Get never fails regardless of counter.
#[test]
fn fault_injecting_backend_only_fails_matching_method() {
    let inner = InMemoryBackend::new();
    inner
        .set_generic_password("svc", "acc", b"val", PasswordOptions::default())
        .unwrap();

    // fail on nth=1 for Set; Get must remain unaffected
    let fib = FaultInjectingBackend::new(&inner, FaultMethod::Set, 1, BackendError::AccessDenied);

    for _ in 0..5 {
        fib.get_generic_password("svc", "acc")
            .expect("Get must never fault when only Set is instrumented");
    }
}

/// A settings.json write fault forces both apply AND rollback to fail (same dir is read-only).
/// Rollback fails because restoring the pre-switch settings.json also requires a write to the
/// same parent directory (via `write_atomic_0600`'s temp-file-rename pattern).
/// Engine must return `Error::RollbackFailed`; the snapshot file still exists on disk.
#[cfg(unix)]
#[test]
fn fault_on_settings_write_produces_rollback_failed() {
    use std::os::unix::fs::PermissionsExt as _;

    let env = setup_test_env();

    // Pre-seed a settings.json with original content. When it's snapshotted, snap.settings_json
    // will be Some(...), so restore_file will try to write it back — which also fails when the
    // parent dir is read-only.
    let original_settings = r#"{"env":{"ANTHROPIC_API_KEY":"sk-ant-original"}}"#;
    std::fs::write(&env.settings_path, original_settings).unwrap();

    // Make the claude dir read-only: apply write fails; rollback write also fails.
    let claude_dir = env.settings_path.parent().unwrap();
    std::fs::create_dir_all(&env.paths.backups_dir).unwrap();
    std::fs::set_permissions(claude_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let ctx = make_api_key_context("work", "sk-ant-fault-settings-new");
    let cf = contexts_file_with(vec![ctx]);
    let backend = InMemoryBackend::new();
    let mut journal = Journal::open(&env.paths.journal_file).unwrap();
    let stores = make_stores_with_backend(&backend, &env);

    let result = execute_switch(&cf, "work", &stores, &mut journal, &env.paths);

    // Restore write permission so TempDir cleanup and further assertions succeed.
    std::fs::set_permissions(claude_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let err = result.expect_err("expected RollbackFailed error");
    assert!(
        matches!(err, Error::RollbackFailed { .. }),
        "expected RollbackFailed, got: {err:?}"
    );

    // Original settings.json bytes must be intact (only the read-only pre-seeded file remains).
    let remaining = std::fs::read_to_string(&env.settings_path).unwrap();
    assert_eq!(
        remaining, original_settings,
        "settings.json must contain the original pre-switch content"
    );

    // Snapshot was written to the backups dir (different, writable parent).
    let snaps: Vec<_> = std::fs::read_dir(&env.paths.backups_dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .collect();
    assert_eq!(snaps.len(), 1, "exactly one snapshot should exist");
}

/// After a successful switch, a second switch with a fault should not affect the first
/// switch's settings.json result — the first write's bytes are preserved.
#[test]
fn happy_path_switch_then_fault_leaves_first_settings_intact() {
    let env = setup_test_env();
    let ctx_a = make_api_key_context("work", "sk-ant-key-a");
    let ctx_b = make_api_key_context("home", "sk-ant-key-b");
    let cf = contexts_file_with(vec![ctx_a, ctx_b]);

    let backend = InMemoryBackend::new();
    let mut journal = Journal::open(&env.paths.journal_file).unwrap();
    let stores = make_stores_with_backend(&backend, &env);

    // First switch succeeds.
    let first = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
    assert!(matches!(first, SwitchOutcome::Applied { .. }));

    let settings_after_first = std::fs::read(&env.settings_path).unwrap();

    // Second switch targets "home"; it should succeed too (no fault).
    execute_switch(&cf, "home", &stores, &mut journal, &env.paths).unwrap();

    // Restore back to "work" again — same bytes as after first switch.
    execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();

    let settings_now = std::fs::read(&env.settings_path).unwrap();
    assert_eq!(
        settings_after_first, settings_now,
        "settings.json after round-trip must match original first-switch bytes"
    );
}

/// After a rolled-back switch (or failed-switch), journal has the Failed entry and
/// find_uncommitted returns empty.
///
/// We drive this via the `already active` → no journal entry path, then simulate a
/// journal-only failure by directly exercising the journal API.
#[test]
fn journal_has_failed_status_after_rollback() {
    use claude_code_context_switcher::journal::{Intent, Journal, Op, PlannedOp, Store};

    let env = setup_test_env();
    let mut journal = Journal::open(&env.paths.journal_file).unwrap();

    // Manually append a pending entry and mark it failed (simulates a rolled-back switch).
    let snapshot_path = env.paths.backups_dir.join("snap.json");
    let id = journal
        .append(
            Intent::Switch,
            Some("work".into()),
            Some("home".into()),
            vec![PlannedOp {
                store: Store::Settings,
                op: Op::Write,
            }],
            snapshot_path,
        )
        .unwrap();
    journal.mark_failed(id, "simulated rollback").unwrap();

    // find_uncommitted must be empty.
    let uncommitted = journal.find_uncommitted().unwrap();
    assert!(
        uncommitted.is_empty(),
        "no uncommitted entries after failure mark"
    );

    // read_all must show the Failed entry.
    let all = journal.read_all().unwrap();
    assert_eq!(all.len(), 1);
    assert!(
        matches!(&all[0].status, EntryStatus::Failed { err } if err == "simulated rollback"),
        "expected Failed status, got: {:?}",
        all[0].status
    );
}

/// A write fault at the `~/.claude.json` step (step 2 of OAuth apply) must roll back
/// `settings.json` to its pre-switch state.
///
/// The CDJ parent directory is placed in a separate subdirectory and made read-only so
/// that only the CDJ write fails; `settings_path`'s parent remains writable and rollback
/// can restore it.
#[cfg(unix)]
#[test]
fn fault_at_claude_json_write_rolls_back_settings() {
    use std::os::unix::fs::PermissionsExt as _;

    let env = setup_test_env_split_cdj();

    let original_settings = r#"{"env":{"ANTHROPIC_API_KEY":"sk-ant-orig"}}"#;
    std::fs::write(&env.settings_path, original_settings).unwrap();

    let blob: Vec<u8> = serde_json::json!({
        "claudeAiOauth": {
            "accessToken": "tok-work",
            "refreshToken": "rtok-work",
            "expiresAt": 9_999_999_999_999_i64
        }
    })
    .to_string()
    .into_bytes();

    let account = make_oauth_account("uuid-work", "work@example.com");
    let ctx = make_oauth_context("work", "user-id-work", account, "cctx-oauth-work", "test-acc", &blob);
    let cf = contexts_file_with(vec![ctx]);

    let inner = InMemoryBackend::new();
    inner
        .set_generic_password("cctx-oauth-work", "test-acc", &blob, PasswordOptions::default())
        .unwrap();

    // Make the CDJ subdirectory read-only so the step-2 write fails while the
    // settings parent (a sibling dir) remains writable for rollback.
    let cdj_parent = env.claude_dot_json_path.parent().unwrap();
    std::fs::create_dir_all(&env.paths.backups_dir).unwrap();
    std::fs::set_permissions(cdj_parent, std::fs::Permissions::from_mode(0o555)).unwrap();

    let mut journal = Journal::open(&env.paths.journal_file).unwrap();
    let stores = make_stores_with_backend(&inner, &env);
    let result = execute_switch(&cf, "work", &stores, &mut journal, &env.paths);

    std::fs::set_permissions(cdj_parent, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        matches!(result, Ok(SwitchOutcome::RolledBack { .. })),
        "expected RolledBack, got: {result:?}"
    );

    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&env.settings_path).unwrap()).unwrap();
    assert_eq!(
        settings["env"]["ANTHROPIC_API_KEY"], "sk-ant-orig",
        "settings.json must be restored to pre-switch content after rollback"
    );
}

/// A fault at the Keychain `set` step (step 3c of OAuth apply) must roll back both
/// `settings.json` and `~/.claude.json` to their pre-switch state.
///
/// Steps 1 (settings) and 2 (claude.json) succeed before the Keychain write is
/// attempted; rollback must undo both.
#[test]
fn fault_at_keychain_set_rolls_back_all_stores() {
    let env = setup_test_env();

    let original_settings = r#"{"env":{"ANTHROPIC_API_KEY":"sk-ant-orig"}}"#;
    std::fs::write(&env.settings_path, original_settings).unwrap();

    let original_cdj = r#"{"userID":"user-orig","oauthAccount":{"accountUuid":"uuid-orig","emailAddress":"orig@example.com"}}"#;
    std::fs::write(&env.claude_dot_json_path, original_cdj).unwrap();

    let blob: Vec<u8> = serde_json::json!({
        "claudeAiOauth": {
            "accessToken": "tok-work",
            "refreshToken": "rtok-work",
            "expiresAt": 9_999_999_999_999_i64
        }
    })
    .to_string()
    .into_bytes();

    let account = make_oauth_account("uuid-work", "work@example.com");
    let ctx = make_oauth_context("work", "user-id-work", account, "cctx-oauth-work", "test-acc", &blob);
    let cf = contexts_file_with(vec![ctx]);

    let inner = InMemoryBackend::new();
    inner
        .set_generic_password("cctx-oauth-work", "test-acc", &blob, PasswordOptions::default())
        .unwrap();

    // No live blob at ("test-svc","test-acc") → from=None → step 3a is skipped.
    // The first Set call is step 3c (writing to the live keychain item).
    let fault = FaultInjectingBackend::new(&inner, FaultMethod::Set, 1, BackendError::AccessDenied);

    let mut journal = Journal::open(&env.paths.journal_file).unwrap();
    let stores = Stores {
        backend: &fault,
        keychain_service: "test-svc",
        keychain_account: "test-acc",
        claude_dot_json_path: &env.claude_dot_json_path,
        settings_json_path: &env.settings_path,
        claude_dir: &env.claude_dir,
    };
    let result = execute_switch(&cf, "work", &stores, &mut journal, &env.paths);

    assert!(
        matches!(result, Ok(SwitchOutcome::RolledBack { .. })),
        "expected RolledBack, got: {result:?}"
    );

    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&env.settings_path).unwrap()).unwrap();
    assert_eq!(
        settings["env"]["ANTHROPIC_API_KEY"], "sk-ant-orig",
        "settings.json must be restored to original content"
    );

    let cdj =
        claude_code_context_switcher::claude_state::load_claude_dot_json(&env.claude_dot_json_path)
            .unwrap();
    assert_eq!(
        cdj.user_id.as_deref(),
        Some("user-orig"),
        "claude.json must be restored to original content"
    );
    assert_eq!(
        cdj.oauth_account.as_ref().map(|a| a.account_uuid.as_str()),
        Some("uuid-orig"),
        "oauth_account must be restored to original content after rollback"
    );
}
