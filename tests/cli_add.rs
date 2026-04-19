//! Integration tests for `cctx add <name>` handler (issues 1.6, 3.6).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn cctx(cctx_home: &TempDir, claude_dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cctx").unwrap();
    cmd.env("CCTX_HOME", cctx_home.path());
    cmd.env("CLAUDE_CONFIG_DIR", claude_dir.path());
    cmd.env("CCTX_TEST_IN_MEMORY_KEYCHAIN", "1");
    cmd
}

fn write_settings(claude_dir: &TempDir, json: &str) {
    fs::write(claude_dir.path().join("settings.json"), json).unwrap();
}

fn write_contexts(cctx_home: &TempDir, yaml: &str) {
    fs::write(cctx_home.path().join("contexts.yaml"), yaml).unwrap();
}

fn load_contexts_yaml(cctx_home: &TempDir) -> serde_yaml_ng::Value {
    let raw = fs::read_to_string(cctx_home.path().join("contexts.yaml")).unwrap();
    serde_yaml_ng::from_str(&raw).unwrap()
}

/// Build a test dir layout where CLAUDE_CONFIG_DIR = root/.claude and
/// ~/.claude.json = root/.claude.json (matching the real directory structure).
///
/// Returns (root TempDir, claude_dir path = root/.claude).
fn setup_nested_claude_dir() -> (TempDir, std::path::PathBuf) {
    let root = TempDir::new().unwrap();
    let claude_inner = root.path().join(".claude");
    fs::create_dir_all(&claude_inner).unwrap();
    (root, claude_inner)
}

// ── test 1 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_add_captures_apikey_from_settings() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    write_settings(&claude_dir, r#"{"env":{"ANTHROPIC_API_KEY":"sk-test"}}"#);

    cctx(&cctx_home, &claude_dir)
        .args(["add", "personal"])
        .assert()
        .success()
        .stderr(predicate::str::contains("captured personal"));

    let doc = load_contexts_yaml(&cctx_home);
    let ctx = &doc["contexts"]["personal"];
    // auth_mode must serialize as the nested api_key map
    assert!(
        ctx["auth_mode"]["api_key"].is_mapping(),
        "expected api_key nested map, got: {:?}",
        ctx["auth_mode"]
    );
    // secret_ref: keychain (key written to cctx-owned keychain item in InMemory backend)
    assert_eq!(
        ctx["secret_ref"]["kind"].as_str().unwrap(),
        "keychain",
        "expected kind: keychain, got: {:?}",
        ctx["secret_ref"]
    );
    assert!(
        ctx["secret_ref"]["service"]
            .as_str()
            .unwrap()
            .contains("cctx-context-personal"),
        "expected cctx-context-personal service, got: {:?}",
        ctx["secret_ref"]["service"]
    );
}

// ── test 2 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_add_duplicate_errors() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    write_settings(&claude_dir, r#"{"env":{"ANTHROPIC_API_KEY":"sk-test"}}"#);

    // First add succeeds
    cctx(&cctx_home, &claude_dir)
        .args(["add", "personal"])
        .assert()
        .success();

    // Second add fails with "already exists"
    cctx(&cctx_home, &claude_dir)
        .args(["add", "personal"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

// ── test 3 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_add_no_identity_errors_with_hint() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    // settings.json with no env block, no OAuth in keychain (InMemory starts empty)
    write_settings(&claude_dir, r#"{"foo": 1}"#);

    cctx(&cctx_home, &claude_dir)
        .args(["add", "x"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("claude /login"));
}

// ── test 4 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_add_oauth_flag_errors_with_phase_6_message() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();

    cctx(&cctx_home, &claude_dir)
        .args(["add", "x", "--oauth"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("P1"));
}

// ── test 5 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_add_preserves_existing_contexts_order() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    write_settings(&claude_dir, r#"{"env":{"ANTHROPIC_API_KEY":"sk-m-key"}}"#);

    // Pre-seed contexts.yaml with a and z
    write_contexts(
        &cctx_home,
        r#"version: 1
contexts:
  a:
    name: a
    auth_mode:
      api_key:
        base_url: null
    identity: {}
    fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-a"
  z:
    name: z
    auth_mode:
      api_key:
        base_url: null
    identity: {}
    fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-z"
"#,
    );

    // Add m — should be appended after a and z
    cctx(&cctx_home, &claude_dir)
        .args(["add", "m"])
        .assert()
        .success();

    // cctx list should print a, z, m in that order
    let output = cctx(&cctx_home, &claude_dir)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    let names: Vec<&str> = stdout.lines().map(str::trim).collect();
    assert_eq!(names, vec!["a", "z", "m"], "order must be a, z, m");
}

// ── test 6 ──────────────────────────────────────────────────────────────────
/// OAuth capture: pre-seed InMemory backend via CCTX_TEST_KEYCHAIN_BLOB and write
/// a matching ~/.claude.json. Asserts exit 0, success message, and YAML shape.
#[test]
fn add_captures_oauth_from_live_keychain() {
    let cctx_home = TempDir::new().unwrap();
    let (claude_root, claude_inner) = setup_nested_claude_dir();

    // Write settings.json inside .claude/
    fs::write(
        claude_inner.join("settings.json"),
        r#"{"env":{}}"#,
    )
    .unwrap();

    // Write ~/.claude.json at the root level (parent of .claude/)
    let claude_dot_json = r#"{
  "oauthAccount": {
    "accountUuid": "aaaaaaaa-1111-1111-1111-000000000001",
    "emailAddress": "testuser@example.com",
    "organizationUuid": null
  },
  "userID": "deadbeefcafe0001deadbeefcafe0001deadbeefcafe0001deadbeefcafe0001"
}"#;
    fs::write(claude_root.path().join(".claude.json"), claude_dot_json).unwrap();

    // Keychain blob JSON (KeychainBlobEnvelope)
    let blob_json = r#"{"claudeAiOauth":{"accessToken":"test-access-token-v1","refreshToken":"test-refresh-token-v1","expiresAt":1800000000000}}"#;

    let mut cmd = Command::cargo_bin("cctx").unwrap();
    cmd.env("CCTX_HOME", cctx_home.path());
    cmd.env("CLAUDE_CONFIG_DIR", &claude_inner);
    cmd.env("CCTX_TEST_IN_MEMORY_KEYCHAIN", "1");
    cmd.env("CCTX_TEST_KEYCHAIN_BLOB", blob_json);
    cmd.args(["add", "test-ctx"]);

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("captured test-ctx as OAuth context"));

    let doc = load_contexts_yaml(&cctx_home);
    let ctx = &doc["contexts"]["test-ctx"];

    assert_eq!(
        ctx["auth_mode"].as_str().unwrap(),
        "oauth",
        "expected auth_mode: oauth, got: {:?}",
        ctx["auth_mode"]
    );
    assert_eq!(
        ctx["secret_ref"]["kind"].as_str().unwrap(),
        "claude_code_keychain",
        "expected kind: claude_code_keychain, got: {:?}",
        ctx["secret_ref"]
    );
    assert_eq!(
        ctx["identity"]["account_uuid"].as_str().unwrap(),
        "aaaaaaaa-1111-1111-1111-000000000001"
    );
    assert!(
        ctx["identity"]["email_hint"].as_str().unwrap().contains("**"),
        "email_hint should be redacted"
    );
}

// ── test 7 ──────────────────────────────────────────────────────────────────
/// API-key capture when no OAuth in Keychain: context must use SecretRef::Keychain.
#[test]
fn add_captures_api_key_to_keychain_when_no_oauth() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    // API key present, no CCTX_TEST_KEYCHAIN_BLOB → InMemory backend has no OAuth
    write_settings(
        &claude_dir,
        r#"{"env":{"ANTHROPIC_API_KEY":"sk-ant-api-key-test"}}"#,
    );

    cctx(&cctx_home, &claude_dir)
        .args(["add", "key-ctx"])
        .assert()
        .success()
        .stderr(predicate::str::contains("captured key-ctx as API-key context"));

    let doc = load_contexts_yaml(&cctx_home);
    let ctx = &doc["contexts"]["key-ctx"];

    assert!(
        ctx["auth_mode"]["api_key"].is_mapping(),
        "expected api_key nested map"
    );
    assert_eq!(
        ctx["secret_ref"]["kind"].as_str().unwrap(),
        "keychain",
        "expected kind: keychain (InMemory backend write succeeds), got: {:?}",
        ctx["secret_ref"]
    );
    assert!(
        ctx["secret_ref"]["service"]
            .as_str()
            .unwrap()
            .starts_with("cctx-context-"),
        "service should be cctx-context-key-ctx"
    );
}
