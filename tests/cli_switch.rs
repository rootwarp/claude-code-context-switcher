//! Integration tests for `cctx <name>` / `cctx switch <name>` handler (issue 1.5).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// A plaintext API-key context fixture (no base_url).
const PLAINTEXT_CONTEXTS_YAML: &str = r#"version: 1
contexts:
  console-key:
    name: console-key
    auth_mode:
      api_key:
        base_url: null
    identity:
      label: "Console API key"
    fingerprint: "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-ant-console-key-value"
  personal:
    name: personal
    auth_mode: oauth
    identity:
      label: "Personal OAuth"
    fingerprint: "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: claude_code_keychain
"#;

fn setup_dirs() -> (TempDir, TempDir) {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    (cctx_home, claude_dir)
}

fn write_contexts(cctx_home: &TempDir, yaml: &str) {
    fs::write(cctx_home.path().join("contexts.yaml"), yaml).unwrap();
}

fn write_settings(claude_dir: &TempDir, json: &str) {
    fs::write(claude_dir.path().join("settings.json"), json).unwrap();
}

fn cctx(cctx_home: &TempDir, claude_dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cctx").unwrap();
    cmd.env("CCTX_HOME", cctx_home.path());
    cmd.env("CLAUDE_CONFIG_DIR", claude_dir.path());
    cmd
}

fn read_settings(claude_dir: &TempDir) -> serde_json::Value {
    let raw = fs::read_to_string(claude_dir.path().join("settings.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

// ── test 1 ─────────────────────────────────────────────────────────────────
#[test]
fn cctx_switch_apikey_plaintext_writes_env() {
    let (cctx_home, claude_dir) = setup_dirs();
    write_contexts(&cctx_home, PLAINTEXT_CONTEXTS_YAML);

    cctx(&cctx_home, &claude_dir)
        .arg("console-key")
        .assert()
        .success()
        .stderr(predicate::str::contains("switched to console-key"));

    let settings = read_settings(&claude_dir);
    assert_eq!(
        settings["env"]["ANTHROPIC_API_KEY"],
        "sk-ant-console-key-value"
    );
    assert!(
        settings["env"].get("ANTHROPIC_AUTH_TOKEN").is_none()
            || settings["env"]["ANTHROPIC_AUTH_TOKEN"].is_null(),
        "ANTHROPIC_AUTH_TOKEN must be absent"
    );
}

// ── test 2 ─────────────────────────────────────────────────────────────────
#[test]
fn cctx_switch_subcommand_same_as_positional() {
    let (cctx_home, claude_dir) = setup_dirs();
    write_contexts(&cctx_home, PLAINTEXT_CONTEXTS_YAML);

    cctx(&cctx_home, &claude_dir)
        .args(["switch", "console-key"])
        .assert()
        .success()
        .stderr(predicate::str::contains("switched to console-key"));

    let settings = read_settings(&claude_dir);
    assert_eq!(
        settings["env"]["ANTHROPIC_API_KEY"],
        "sk-ant-console-key-value"
    );
}

// ── test 3 ─────────────────────────────────────────────────────────────────
#[test]
fn cctx_switch_unknown_context_exits_nonzero() {
    let (cctx_home, claude_dir) = setup_dirs();
    write_contexts(&cctx_home, PLAINTEXT_CONTEXTS_YAML);

    cctx(&cctx_home, &claude_dir)
        .arg("does-not-exist")
        .assert()
        .failure()
        .stderr(predicate::str::contains("context not found"));
}

// ── test 4 ─────────────────────────────────────────────────────────────────
#[test]
fn cctx_switch_oauth_context_with_claude_code_keychain_ref_fails_with_context_corrupt() {
    // The `personal` context in the fixture has `secret_ref: claude_code_keychain`.
    // Since there is no live Keychain item (InMemory backend, no item seeded), the
    // engine cannot locate the source blob and returns ContextCorrupt.
    let (cctx_home, claude_dir) = setup_dirs();
    write_contexts(&cctx_home, PLAINTEXT_CONTEXTS_YAML);

    cctx(&cctx_home, &claude_dir)
        .arg("personal")
        .assert()
        .failure()
        .stderr(predicate::str::contains("corrupt or incomplete"));
}

// ── test 4b ────────────────────────────────────────────────────────────────
/// OAuth switch integration test against the real macOS Keychain.
///
/// Gated behind `#[cfg(feature = "real-keychain")]` and `#[ignore]` so it never
/// runs in CI.  Enable with:
///   CCTX_REAL_KEYCHAIN=1 cargo test --features real-keychain -- --ignored
#[cfg(feature = "real-keychain")]
#[ignore]
#[test]
fn cctx_switch_oauth_real_keychain_end_to_end() {
    // Verify that `CCTX_REAL_KEYCHAIN` env var is set so the test is intentional.
    if std::env::var("CCTX_REAL_KEYCHAIN").is_err() {
        panic!("set CCTX_REAL_KEYCHAIN=1 to run real-keychain tests");
    }

    // This test is a scaffold for 3.8 release-gate manual testing.
    // Full implementation requires two real OAuth accounts on the dev laptop.
    // The test is intentionally left as a panic-placeholder until the release gate.
    todo!(
        "implement full OAuth real-keychain end-to-end test for 3.8 release gate: \
         pre-seed two contexts in real Keychain, cctx switch, verify claude next launch \
         picks up the selected identity"
    );
}

// ── test 5 ─────────────────────────────────────────────────────────────────
#[test]
fn cctx_switch_preserves_unrelated_settings_keys() {
    let (cctx_home, claude_dir) = setup_dirs();
    write_contexts(&cctx_home, PLAINTEXT_CONTEXTS_YAML);
    write_settings(
        &claude_dir,
        r#"{"foo": 1, "env": {"BAR": "x", "ANTHROPIC_AUTH_TOKEN": "old-token"}}"#,
    );

    cctx(&cctx_home, &claude_dir)
        .arg("console-key")
        .assert()
        .success();

    let settings = read_settings(&claude_dir);
    assert_eq!(
        settings["foo"], 1,
        "non-env top-level key must be preserved"
    );
    assert_eq!(
        settings["env"]["BAR"], "x",
        "unrelated env var must be preserved"
    );
    assert_eq!(
        settings["env"]["ANTHROPIC_API_KEY"],
        "sk-ant-console-key-value"
    );
    // ANTHROPIC_AUTH_TOKEN was explicitly cleared by the switch.
    assert!(
        settings["env"]
            .get("ANTHROPIC_AUTH_TOKEN")
            .map_or(true, |v| v.is_null()),
        "ANTHROPIC_AUTH_TOKEN must be cleared"
    );
}

// ── test 6 ─────────────────────────────────────────────────────────────────
#[test]
fn cctx_switch_creates_backup_file_in_backups_dir() {
    let (cctx_home, claude_dir) = setup_dirs();
    write_contexts(&cctx_home, PLAINTEXT_CONTEXTS_YAML);

    cctx(&cctx_home, &claude_dir)
        .arg("console-key")
        .assert()
        .success();

    let backups_dir = cctx_home.path().join("backups");
    assert!(backups_dir.exists(), "backups dir must be created");
    let entries: Vec<_> = fs::read_dir(&backups_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1, "exactly one backup file after switch");
    assert!(
        entries[0].file_name().to_string_lossy().ends_with(".json"),
        "backup file should end in .json"
    );
}

// ── test 7 ─────────────────────────────────────────────────────────────────
/// Switch between two contexts produces two backups total.
#[test]
fn cctx_switch_between_two_contexts_produces_two_backups() {
    // Build a contexts YAML with two plaintext API-key contexts whose fingerprints
    // match the actual SHA-256 of their stored keys (required for idempotency guard).
    let yaml = r#"version: 1
contexts:
  ctx-a:
    name: ctx-a
    auth_mode:
      api_key:
        base_url: null
    identity:
      label: "Context A"
    fingerprint: "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-ant-ctx-a-key"
  ctx-b:
    name: ctx-b
    auth_mode:
      api_key:
        base_url: null
    identity:
      label: "Context B"
    fingerprint: "b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-ant-ctx-b-key"
"#;
    let (cctx_home, claude_dir) = setup_dirs();
    fs::write(cctx_home.path().join("contexts.yaml"), yaml).unwrap();

    cctx(&cctx_home, &claude_dir)
        .arg("ctx-a")
        .assert()
        .success();

    cctx(&cctx_home, &claude_dir)
        .arg("ctx-b")
        .assert()
        .success();

    let backups_dir = cctx_home.path().join("backups");
    let entries: Vec<_> = fs::read_dir(&backups_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 2, "two backups: one per switch");
}
