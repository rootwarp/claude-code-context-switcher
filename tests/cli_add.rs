//! Integration tests for `cctx add <name>` handler (issue 1.6).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn cctx(cctx_home: &TempDir, claude_dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cctx").unwrap();
    cmd.env("CCTX_HOME", cctx_home.path());
    cmd.env("CLAUDE_CONFIG_DIR", claude_dir.path());
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
    // secret_ref must be plaintext with the value intact
    assert_eq!(
        ctx["secret_ref"]["kind"].as_str().unwrap(),
        "plaintext",
        "expected kind: plaintext"
    );
    assert_eq!(
        ctx["secret_ref"]["value"].as_str().unwrap(),
        "sk-test",
        "expected value sk-test"
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
fn cctx_add_no_apikey_errors_with_hint() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    // settings.json with no env block
    write_settings(&claude_dir, r#"{"foo": 1}"#);

    cctx(&cctx_home, &claude_dir)
        .args(["add", "x"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("claude /login").and(predicate::str::contains("Phase 3")));
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
