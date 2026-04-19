//! Integration tests for `.credentials.json` fallback detection and refusal (issue 3.3).
//!
//! Tests 6–11 from the spec.  The mutating-command refusal (tests 6–9) only fires on macOS
//! because `detect_credentials_json_fallback` returns `Absent` unconditionally on other
//! platforms — skip those tests on non-macOS.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

const CONTEXTS_YAML: &str = r#"version: 1
contexts:
  work:
    name: work
    auth_mode:
      api_key:
        base_url: null
    identity:
      label: "Work"
    fingerprint: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    created_at: "2026-04-18T00:00:00Z"
    secret_ref:
      kind: plaintext
      value: "sk-ant-work-key"
  personal:
    name: personal
    auth_mode:
      api_key:
        base_url: null
    identity:
      label: "Personal"
    fingerprint: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
    created_at: "2026-04-18T00:00:00Z"
    secret_ref:
      kind: plaintext
      value: "sk-ant-personal-key"
"#;

fn setup() -> (TempDir, TempDir) {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();
    fs::write(cctx_home.path().join("contexts.yaml"), CONTEXTS_YAML).unwrap();
    (cctx_home, claude_dir)
}

fn seed_fallback(claude_dir: &TempDir) {
    fs::write(
        claude_dir.path().join(".credentials.json"),
        br#"{"claudeAiOauth":{"accessToken":"tok","refreshToken":"ref","expiresAt":0}}"#,
    )
    .unwrap();
}

fn cctx(cctx_home: &TempDir, claude_dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cctx").unwrap();
    cmd.env("CCTX_HOME", cctx_home.path());
    cmd.env("CLAUDE_CONFIG_DIR", claude_dir.path());
    cmd.env("CCTX_TEST_IN_MEMORY_KEYCHAIN", "1");
    cmd
}

// test 6: switch refuses with exit 4 when fallback present (macOS only)
#[cfg(target_os = "macos")]
#[test]
fn cctx_switch_refuses_when_fallback_present() {
    let (cctx_home, claude_dir) = setup();
    seed_fallback(&claude_dir);

    let cred_path = claude_dir.path().join(".credentials.json");
    cctx(&cctx_home, &claude_dir)
        .arg("work")
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("refusing to switch"))
        .stderr(predicate::str::contains(
            cred_path.to_string_lossy().as_ref(),
        ));
}

// test 7: add refuses with exit 4 when fallback present (macOS only)
#[cfg(target_os = "macos")]
#[test]
fn cctx_add_refuses_when_fallback_present() {
    let (cctx_home, claude_dir) = setup();
    seed_fallback(&claude_dir);
    // Write a settings.json so add doesn't fail on missing API key before reaching detection.
    fs::write(
        claude_dir.path().join("settings.json"),
        r#"{"env":{"ANTHROPIC_API_KEY":"sk-ant-test"}}"#,
    )
    .unwrap();

    cctx(&cctx_home, &claude_dir)
        .args(["add", "newctx"])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("refusing to switch"));
}

// test 8: delete refuses with exit 4 when fallback present (macOS only)
#[cfg(target_os = "macos")]
#[test]
fn cctx_delete_refuses_when_fallback_present() {
    let (cctx_home, claude_dir) = setup();
    seed_fallback(&claude_dir);

    cctx(&cctx_home, &claude_dir)
        .args(["delete", "work"])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("refusing to switch"));
}

// test 9: list warns but continues with exit 0 when fallback present (macOS only)
#[cfg(target_os = "macos")]
#[test]
fn cctx_list_warns_but_continues_when_fallback_present() {
    let (cctx_home, claude_dir) = setup();
    seed_fallback(&claude_dir);

    cctx(&cctx_home, &claude_dir)
        .assert()
        .success()
        .code(0)
        .stdout(predicate::str::contains("work"))
        .stdout(predicate::str::contains("personal"))
        .stderr(predicate::str::contains(".credentials.json"));
}

// test 10: cctx -c emits warning then exits with code 3 (not-implemented) when fallback present
// When .credentials.json fallback is present, detection is unavailable → warn + print "(unmanaged)" + exit 0.
#[cfg(target_os = "macos")]
#[test]
fn cctx_current_warns_and_prints_unmanaged_when_fallback_present() {
    let (cctx_home, claude_dir) = setup();
    seed_fallback(&claude_dir);

    cctx(&cctx_home, &claude_dir)
        .arg("-c")
        .assert()
        .success()
        .code(0)
        .stderr(predicate::str::contains(".credentials.json"))
        .stdout(predicate::str::contains("(unmanaged)"));
}

// test 11: doctor proceeds when fallback present and reports it (macOS only)
#[cfg(target_os = "macos")]
#[test]
fn cctx_doctor_proceeds_when_fallback_present() {
    let (cctx_home, claude_dir) = setup();
    seed_fallback(&claude_dir);

    // Doctor should not refuse; it runs and reports the fallback in its output.
    // Journal is clean so exit 0.
    cctx(&cctx_home, &claude_dir)
        .args(["doctor", "--dry-run"])
        .assert()
        .success()
        .code(0)
        .stderr(predicate::str::contains(".credentials.json"));
}
