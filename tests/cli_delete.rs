//! Integration tests for `cctx delete <name>` handler (issue 1.7).

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

fn write_contexts(cctx_home: &TempDir, yaml: &str) {
    fs::write(cctx_home.path().join("contexts.yaml"), yaml).unwrap();
}

fn write_settings(claude_dir: &TempDir, json: &str) {
    fs::write(claude_dir.path().join("settings.json"), json).unwrap();
}

fn load_contexts_yaml(cctx_home: &TempDir) -> serde_yaml_ng::Value {
    let raw = fs::read_to_string(cctx_home.path().join("contexts.yaml")).unwrap();
    serde_yaml_ng::from_str(&raw).unwrap()
}

/// Three-context fixture with distinct fingerprints. None match a live settings.json key
/// so delete can proceed without --force.
const THREE_CONTEXTS_YAML: &str = r#"version: 1
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
  b:
    name: b
    auth_mode:
      api_key:
        base_url: null
    identity: {}
    fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-b"
  c:
    name: c
    auth_mode:
      api_key:
        base_url: null
    identity: {}
    fingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-c"
"#;

/// Compute the SHA-256 fingerprint for a given API key (mirrors Fingerprint::from_api_key).
fn sha256_hex(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    format!("{:x}", h.finalize())
}

fn active_context_yaml(name: &str, api_key: &str) -> String {
    let fp = sha256_hex(api_key);
    format!(
        r#"version: 1
contexts:
  {name}:
    name: {name}
    auth_mode:
      api_key:
        base_url: null
    identity: {{}}
    fingerprint: "{fp}"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "{api_key}"
"#
    )
}

// ── test 1 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_delete_removes_context_from_yaml() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    write_contexts(&cctx_home, THREE_CONTEXTS_YAML);
    // settings.json has no API key so the active-context guard is a no-op
    write_settings(&claude_dir, r#"{}"#);

    cctx(&cctx_home, &claude_dir)
        .args(["delete", "b"])
        .assert()
        .success()
        .stderr(predicate::str::contains("deleted b"));

    let doc = load_contexts_yaml(&cctx_home);
    assert!(doc["contexts"]["a"].is_mapping(), "a must remain");
    assert!(
        doc["contexts"]["b"].is_null() || !doc["contexts"]["b"].is_mapping(),
        "b must be gone"
    );
    assert!(doc["contexts"]["c"].is_mapping(), "c must remain");
}

// ── test 2 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_delete_missing_context_exits_nonzero() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    write_contexts(&cctx_home, THREE_CONTEXTS_YAML);

    cctx(&cctx_home, &claude_dir)
        .args(["delete", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("context not found: nope"));
}

// ── test 3 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_delete_active_refuses_without_force() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();

    let api_key = "sk-ant-active-key-test-3";
    write_contexts(&cctx_home, &active_context_yaml("p", api_key));
    write_settings(
        &claude_dir,
        &format!(r#"{{"env":{{"ANTHROPIC_API_KEY":"{api_key}"}}}}"#),
    );

    cctx(&cctx_home, &claude_dir)
        .args(["delete", "p"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
}

// ── test 4 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_delete_active_proceeds_with_force() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();

    let api_key = "sk-ant-active-key-test-4";
    write_contexts(&cctx_home, &active_context_yaml("p", api_key));
    write_settings(
        &claude_dir,
        &format!(r#"{{"env":{{"ANTHROPIC_API_KEY":"{api_key}"}}}}"#),
    );

    cctx(&cctx_home, &claude_dir)
        .args(["delete", "p", "--force"])
        .assert()
        .success()
        .stderr(predicate::str::contains("deleted p"));

    let doc = load_contexts_yaml(&cctx_home);
    assert!(
        !doc["contexts"]["p"].is_mapping(),
        "p must be removed after --force delete"
    );
}

// ── test 5 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_delete_preserves_insertion_order() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();

    let yaml = r#"version: 1
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
  b:
    name: b
    auth_mode:
      api_key:
        base_url: null
    identity: {}
    fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-b"
  c:
    name: c
    auth_mode:
      api_key:
        base_url: null
    identity: {}
    fingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-c"
  d:
    name: d
    auth_mode:
      api_key:
        base_url: null
    identity: {}
    fingerprint: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-d"
"#;

    write_contexts(&cctx_home, yaml);
    write_settings(&claude_dir, r#"{}"#);

    cctx(&cctx_home, &claude_dir)
        .args(["delete", "b"])
        .assert()
        .success();

    // cctx list should print a, c, d in that order
    let output = cctx(&cctx_home, &claude_dir)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    let names: Vec<&str> = stdout.lines().map(str::trim).collect();
    assert_eq!(
        names,
        vec!["a", "c", "d"],
        "order must be a, c, d after deleting b"
    );
}

// ── test 6 ──────────────────────────────────────────────────────────────────
#[test]
fn cctx_delete_last_context_works() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();

    let yaml = r#"version: 1
contexts:
  only:
    name: only
    auth_mode:
      api_key:
        base_url: null
    identity: {}
    fingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: plaintext
      value: "sk-only"
"#;
    write_contexts(&cctx_home, yaml);
    write_settings(&claude_dir, r#"{}"#);

    cctx(&cctx_home, &claude_dir)
        .args(["delete", "only"])
        .assert()
        .success()
        .stderr(predicate::str::contains("deleted only"));

    let doc = load_contexts_yaml(&cctx_home);
    assert_eq!(doc["version"].as_u64().unwrap(), 1);
    // contexts map should be empty (null in YAML when serialized as {})
    let contexts = &doc["contexts"];
    assert!(
        contexts.is_null() || contexts.as_mapping().map(|m| m.is_empty()).unwrap_or(false),
        "contexts must be empty after deleting the last entry, got: {contexts:?}"
    );
}
