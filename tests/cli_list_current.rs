//! Integration tests for `cctx` list and `cctx -c` / `cctx current` handlers.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn cctx(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cctx").unwrap();
    cmd.env("CCTX_HOME", home.path());
    cmd
}

fn write_contexts(home: &TempDir, yaml: &str) {
    fs::write(home.path().join("contexts.yaml"), yaml).unwrap();
}

const MINIMAL_FIXTURE: &str = include_str!("fixtures/contexts-minimal.yaml");

#[test]
fn cctx_on_empty_config_prints_hint() {
    let home = TempDir::new().unwrap();
    // No contexts.yaml at all — config::load returns empty ContextsFile.
    cctx(&home)
        .assert()
        .success()
        .stderr(predicate::str::contains("no contexts configured"));
}

#[test]
fn cctx_lists_configured_contexts_one_per_line() {
    let home = TempDir::new().unwrap();
    write_contexts(&home, MINIMAL_FIXTURE);
    let output = cctx(&home).assert().success().get_output().stdout.clone();
    let stdout = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 lines, got: {stdout:?}");
    assert!(
        lines[0].trim_start().starts_with("personal"),
        "line 0: {}",
        lines[0]
    );
    assert!(
        lines[1].trim_start().starts_with("work"),
        "line 1: {}",
        lines[1]
    );
    assert!(
        lines[2].trim_start().starts_with("console-key"),
        "line 2: {}",
        lines[2]
    );
}

#[test]
fn cctx_preserves_insertion_order() {
    let home = TempDir::new().unwrap();
    // Deliberate non-alphabetical order: a, z, m
    let yaml = r#"version: 1
contexts:
  alpha:
    name: alpha
    auth_mode: oauth
    identity: {}
    fingerprint: "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: claude_code_keychain
  zeta:
    name: zeta
    auth_mode: oauth
    identity: {}
    fingerprint: "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: claude_code_keychain
  mu:
    name: mu
    auth_mode: oauth
    identity: {}
    fingerprint: "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
    created_at: "2026-04-18T02:14:05Z"
    secret_ref:
      kind: claude_code_keychain
"#;
    write_contexts(&home, yaml);
    let output = cctx(&home).assert().success().get_output().stdout.clone();
    let stdout = String::from_utf8(output).unwrap();
    let names: Vec<&str> = stdout.lines().map(str::trim).collect();
    assert_eq!(
        names,
        vec!["alpha", "zeta", "mu"],
        "insertion order must be preserved"
    );
}

#[test]
fn cctx_dash_c_exits_3_with_phase3_message() {
    let home = TempDir::new().unwrap();
    cctx(&home)
        .arg("-c")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("Phase 3"));
}

#[test]
fn cctx_current_subcommand_exits_3_with_phase3_message() {
    let home = TempDir::new().unwrap();
    cctx(&home)
        .arg("current")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("Phase 3"));
}

#[test]
fn cctx_list_with_corrupt_yaml_exits_4() {
    let home = TempDir::new().unwrap();
    write_contexts(&home, ": invalid: yaml: {\n");
    cctx(&home)
        .assert()
        .code(4)
        .stderr(predicate::str::contains("parse").or(predicate::str::contains("error")));
}
