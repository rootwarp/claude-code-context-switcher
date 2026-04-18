//! Integration tests for `cctx doctor` subcommand and crash-detection on startup (issue 2.5).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

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
"#;

fn setup_dirs() -> (TempDir, TempDir) {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    (cctx_home, claude_dir)
}

fn cctx(cctx_home: &TempDir, claude_dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cctx").unwrap();
    cmd.env("CCTX_HOME", cctx_home.path());
    cmd.env("CLAUDE_CONFIG_DIR", claude_dir.path());
    cmd
}

/// Write a pending journal Init record.
///
/// The `status` field uses serde internally-tagged enum: it serializes as
/// `{"status":"pending"}` (an object), not a bare string.
fn write_pending_journal_entry(cctx_home: &TempDir, snap_path: &str) {
    let escaped = snap_path.replace('\\', "\\\\");
    let line = format!(
        r#"{{"kind":"init","id":1,"intent":"switch","from":null,"to":"console-key","timestamp":"2026-04-19T00:00:00Z","planned_ops":[{{"store":"settings","op":"write"}}],"snapshot_path":"{escaped}","status":{{"status":"pending"}}}}"#
    );
    fs::write(cctx_home.path().join("journal.log"), format!("{line}\n")).unwrap();
}

// ── doctor dry-run tests ─────────────────────────────────────────────────────

#[test]
fn cctx_doctor_dry_run_clean_exits_0() {
    let (cctx_home, claude_dir) = setup_dirs();

    cctx(&cctx_home, &claude_dir)
        .args(["doctor", "--dry-run"])
        .assert()
        .success()
        .stderr(predicate::str::contains("clean"));
}

#[test]
fn cctx_doctor_no_flag_defaults_to_dry_run_exits_0_when_clean() {
    let (cctx_home, claude_dir) = setup_dirs();

    cctx(&cctx_home, &claude_dir)
        .arg("doctor")
        .assert()
        .success();
}

#[test]
fn cctx_doctor_dry_run_dirty_exits_5() {
    let (cctx_home, claude_dir) = setup_dirs();
    let snap_path = cctx_home.path().join("snap.json");
    write_pending_journal_entry(&cctx_home, snap_path.to_str().unwrap());

    cctx(&cctx_home, &claude_dir)
        .args(["doctor", "--dry-run"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("1"));
}

#[test]
fn cctx_doctor_dry_run_dirty_stderr_shows_entry_count() {
    let (cctx_home, claude_dir) = setup_dirs();
    let snap_path = cctx_home.path().join("snap.json");
    write_pending_journal_entry(&cctx_home, snap_path.to_str().unwrap());

    let output = cctx(&cctx_home, &claude_dir)
        .args(["doctor", "--dry-run"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("uncommitted") || stderr.contains("partial"),
        "expected 'uncommitted' or 'partial' in stderr: {stderr}"
    );
}

// ── crash detection: mutating commands refuse ─────────────────────────────────

#[test]
fn cctx_switch_with_dirty_journal_refuses() {
    let (cctx_home, claude_dir) = setup_dirs();
    fs::write(
        cctx_home.path().join("contexts.yaml"),
        PLAINTEXT_CONTEXTS_YAML,
    )
    .unwrap();
    let snap_path = cctx_home.path().join("snap.json");
    write_pending_journal_entry(&cctx_home, snap_path.to_str().unwrap());

    cctx(&cctx_home, &claude_dir)
        .args(["console-key"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("doctor"));
}

#[test]
fn cctx_switch_subcommand_with_dirty_journal_refuses() {
    let (cctx_home, claude_dir) = setup_dirs();
    fs::write(
        cctx_home.path().join("contexts.yaml"),
        PLAINTEXT_CONTEXTS_YAML,
    )
    .unwrap();
    let snap_path = cctx_home.path().join("snap.json");
    write_pending_journal_entry(&cctx_home, snap_path.to_str().unwrap());

    cctx(&cctx_home, &claude_dir)
        .args(["switch", "console-key"])
        .assert()
        .code(5);
}

// ── crash detection: read-only commands warn and continue ─────────────────────

#[test]
fn cctx_list_with_dirty_journal_warns_but_lists() {
    let (cctx_home, claude_dir) = setup_dirs();
    fs::write(
        cctx_home.path().join("contexts.yaml"),
        PLAINTEXT_CONTEXTS_YAML,
    )
    .unwrap();
    let snap_path = cctx_home.path().join("snap.json");
    write_pending_journal_entry(&cctx_home, snap_path.to_str().unwrap());

    cctx(&cctx_home, &claude_dir)
        .assert()
        .success()
        .stderr(predicate::str::contains("warning"))
        .stdout(predicate::str::contains("console-key"));
}
