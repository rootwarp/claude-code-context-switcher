//! Integration tests verifying exit-code taxonomy (issue 4.4).

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

// Plaintext API-key context whose fingerprint is SHA-256("sk-ant-noop-key-value").
// Fingerprint computed: df624dad618899e79fb4107b4d4371d76cd43fdb8d0ba56f065ff17418319be1
const NOOP_CONTEXTS_YAML: &str = r#"version: 1
contexts:
  noop-ctx:
    name: noop-ctx
    auth_mode:
      api_key:
        base_url: null
    identity:
      label: "noop test context"
    fingerprint: "df624dad618899e79fb4107b4d4371d76cd43fdb8d0ba56f065ff17418319be1"
    created_at: "2026-04-19T00:00:00Z"
    secret_ref:
      kind: plaintext
      value: "sk-ant-noop-key-value"
"#;

const SWITCH_CONTEXTS_YAML: &str = r#"version: 1
contexts:
  test-ctx:
    name: test-ctx
    auth_mode:
      api_key:
        base_url: null
    identity:
      label: "test context"
    fingerprint: "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
    created_at: "2026-04-19T00:00:00Z"
    secret_ref:
      kind: plaintext
      value: "sk-ant-test-context-key"
"#;

fn cctx(cctx_home: &TempDir, claude_dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cctx").unwrap();
    cmd.env("CCTX_HOME", cctx_home.path());
    cmd.env("CLAUDE_CONFIG_DIR", claude_dir.path());
    cmd.env("CCTX_TEST_IN_MEMORY_KEYCHAIN", "1");
    cmd
}

fn write_pending_journal_entry(cctx_home: &TempDir, snap_path: &str) {
    let escaped = snap_path.replace('\\', "\\\\");
    let line = format!(
        r#"{{"kind":"init","id":1,"intent":"switch","from":null,"to":"test-ctx","timestamp":"2026-04-19T00:00:00Z","planned_ops":[{{"store":"settings","op":"write"}}],"snapshot_path":"{escaped}","status":{{"status":"pending"}}}}"#
    );
    fs::write(cctx_home.path().join("journal.log"), format!("{line}\n")).unwrap();
}

// ── context not found → exit 3 ───────────────────────────────────────────────

#[test]
fn context_not_found_exits_3() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    fs::write(
        cctx_home.path().join("contexts.yaml"),
        SWITCH_CONTEXTS_YAML,
    )
    .unwrap();

    cctx(&cctx_home, &claude_dir)
        .args(["switch", "nosuchcontext"])
        .assert()
        .code(3);
}

// ── corrupted YAML → exit 4 ──────────────────────────────────────────────────

#[test]
fn config_corruption_exits_4() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    fs::write(
        cctx_home.path().join("contexts.yaml"),
        b": [\x00invalid yaml\x01",
    )
    .unwrap();

    cctx(&cctx_home, &claude_dir).assert().code(4);
}

// ── partial state in journal → exit 5 ────────────────────────────────────────

#[test]
fn partially_applied_exits_5() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    fs::write(
        cctx_home.path().join("contexts.yaml"),
        SWITCH_CONTEXTS_YAML,
    )
    .unwrap();
    let snap_path = cctx_home.path().join("snap.json");
    write_pending_journal_entry(&cctx_home, snap_path.to_str().unwrap());

    cctx(&cctx_home, &claude_dir)
        .args(["switch", "test-ctx"])
        .assert()
        .code(5);
}

// ── success → exit 0 ─────────────────────────────────────────────────────────

#[test]
fn success_exits_0() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    fs::write(
        cctx_home.path().join("contexts.yaml"),
        SWITCH_CONTEXTS_YAML,
    )
    .unwrap();

    cctx(&cctx_home, &claude_dir)
        .args(["switch", "test-ctx"])
        .assert()
        .success();
}

// ── noop → exit 0 ────────────────────────────────────────────────────────────

#[test]
fn noop_exits_0() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    fs::write(
        cctx_home.path().join("contexts.yaml"),
        NOOP_CONTEXTS_YAML,
    )
    .unwrap();

    // Prime settings.json with the matching API key so the fingerprint matches.
    fs::write(
        claude_dir.path().join("settings.json"),
        r#"{"env":{"ANTHROPIC_API_KEY":"sk-ant-noop-key-value"}}"#,
    )
    .unwrap();

    // Switch to already-active context → AlreadyActive NoOp → exit 0.
    cctx(&cctx_home, &claude_dir)
        .args(["switch", "noop-ctx"])
        .assert()
        .success();
}
