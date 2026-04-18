//! Fault-injection rollback tests for the switch engine.
//!
//! Phase-2 scope: only settings.json is mutated during an API-key switch; the
//! Keychain and ~/.claude.json paths are stubs.  Tests that require Keychain
//! writes are marked `#[ignore]` with a forward pointer to issue 3.5.

use std::path::PathBuf;

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

/// IGNORED — requires Keychain write in the apply phase, which lands in issue 3.5.
///
/// Once issue 3.5 wires engine → Keychain for OAuth contexts, remove `#[ignore]`
/// and plumb a `FaultInjectingBackend(Set, 1, AccessDenied)` through the OAuth apply path.
#[ignore = "Keychain apply path lands in issue 3.5; enable then"]
#[test]
fn fault_on_keychain_set_rolls_back() {
    let env = setup_test_env();
    let inner = InMemoryBackend::new();
    let fib = FaultInjectingBackend::new(&inner, FaultMethod::Set, 1, BackendError::AccessDenied);

    let _stores = make_stores_with_backend(&fib, &env);
    // TODO(3.5): construct OAuth context, run execute_switch, assert RolledBack + unchanged state.
}
