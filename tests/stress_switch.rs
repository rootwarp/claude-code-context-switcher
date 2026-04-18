//! Stress tests: 20 back-to-back switches, idempotency, journal consistency.

use assert_cmd::Command;
use claude_code_context_switcher::context::Fingerprint;
use claude_code_context_switcher::secret::Secret;
use std::fs;
use tempfile::TempDir;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn cctx(cctx_home: &TempDir, claude_dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cctx").unwrap();
    cmd.env("CCTX_HOME", cctx_home.path());
    cmd.env("CLAUDE_CONFIG_DIR", claude_dir.path());
    cmd
}

/// Build a two-context YAML with fingerprints that are correct SHA-256 of the keys.
fn two_context_yaml() -> String {
    let key_a = Secret::new("sk-ant-stress-ctx-a".to_string());
    let key_b = Secret::new("sk-ant-stress-ctx-b".to_string());
    let fp_a = Fingerprint::from_api_key(&key_a).to_hex();
    let fp_b = Fingerprint::from_api_key(&key_b).to_hex();
    format!(
        r#"version: 1
contexts:
  ctx-a:
    name: ctx-a
    auth_mode:
      api_key:
        base_url: null
    identity:
      label: "Context A"
    fingerprint: "{fp_a}"
    created_at: "2026-04-18T00:00:00Z"
    secret_ref:
      kind: plaintext
      value: "sk-ant-stress-ctx-a"
  ctx-b:
    name: ctx-b
    auth_mode:
      api_key:
        base_url: null
    identity:
      label: "Context B"
    fingerprint: "{fp_b}"
    created_at: "2026-04-18T00:00:00Z"
    secret_ref:
      kind: plaintext
      value: "sk-ant-stress-ctx-b"
"#
    )
}

/// Count journal Init records in journal.log.
fn count_journal_records(cctx_home: &TempDir) -> (usize, usize) {
    let path = cctx_home.path().join("journal.log");
    if !path.exists() {
        return (0, 0);
    }
    let content = fs::read_to_string(&path).unwrap();
    let mut inits = 0usize;
    let mut updates = 0usize;
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.contains(r#""kind":"init""#) {
            inits += 1;
        } else if t.contains(r#""kind":"update""#) {
            updates += 1;
        }
    }
    (inits, updates)
}

fn count_snapshot_files(cctx_home: &TempDir) -> usize {
    let backups = cctx_home.path().join("backups");
    if !backups.exists() {
        return 0;
    }
    fs::read_dir(&backups)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .count()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// 20 alternating switches between two API-key contexts.
///
/// Post-conditions:
/// - settings.json has the last-switched-to context's key (ctx-b, iteration 19).
/// - journal.log has exactly 20 Init records and 20 Update (completed) records.
/// - backups/ has exactly 20 snapshot files (nanosecond timestamps prevent collision).
#[test]
fn stress_20_back_to_back_switches_between_two_contexts() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();

    fs::write(cctx_home.path().join("contexts.yaml"), two_context_yaml()).unwrap();

    for i in 0..20u32 {
        let target = if i % 2 == 0 { "ctx-a" } else { "ctx-b" };
        cctx(&cctx_home, &claude_dir).arg(target).assert().success();
    }

    // i=0 → ctx-a, i=1 → ctx-b, …, i=18 → ctx-a, i=19 → ctx-b.
    // Final target is ctx-b (odd).
    let settings_raw = fs::read_to_string(claude_dir.path().join("settings.json")).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&settings_raw).unwrap();
    assert_eq!(
        settings["env"]["ANTHROPIC_API_KEY"], "sk-ant-stress-ctx-b",
        "last switch was to ctx-b; settings must reflect that"
    );

    // Journal: 20 Init + 20 Update records.
    let (inits, updates) = count_journal_records(&cctx_home);
    assert_eq!(inits, 20, "expected 20 Init records, got {inits}");
    assert_eq!(updates, 20, "expected 20 Update records, got {updates}");

    // Snapshots: exactly 20 files (no collisions with nanosecond-precision filenames).
    let snaps = count_snapshot_files(&cctx_home);
    assert_eq!(snaps, 20, "expected 20 snapshot files, got {snaps}");
}

/// 21st switch to the same context is a no-op (AlreadyActive).
///
/// Per arch §5 Phase 1, AlreadyActive short-circuits before journal.append,
/// so the journal must still have exactly 20 Init records after 21 invocations.
#[test]
fn stress_idempotent_no_op_after_20_switches() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();

    fs::write(cctx_home.path().join("contexts.yaml"), two_context_yaml()).unwrap();

    // 20 alternating switches.
    for i in 0..20u32 {
        let target = if i % 2 == 0 { "ctx-a" } else { "ctx-b" };
        cctx(&cctx_home, &claude_dir).arg(target).assert().success();
    }

    // Final state is ctx-b. One more switch to ctx-b → AlreadyActive (exit 0).
    cctx(&cctx_home, &claude_dir)
        .arg("ctx-b")
        .assert()
        .success();

    // Journal must still have exactly 20 Init records — the 21st call never appended.
    let (inits, _) = count_journal_records(&cctx_home);
    assert_eq!(
        inits, 20,
        "21st same-target switch must not append a journal entry; got {inits} Init records"
    );
}

/// After 5 switches, a manually-appended corrupt journal line causes `find_uncommitted`
/// to reject the log.  A subsequent mutating command (cctx switch) must fail with a
/// journal-corrupt-style error rather than proceeding blindly.
#[test]
fn stress_corrupted_journal_line_is_rejected() {
    let cctx_home = TempDir::new().unwrap();
    let claude_dir = TempDir::new().unwrap();

    fs::write(cctx_home.path().join("contexts.yaml"), two_context_yaml()).unwrap();

    // 5 clean switches.
    for i in 0..5u32 {
        let target = if i % 2 == 0 { "ctx-a" } else { "ctx-b" };
        cctx(&cctx_home, &claude_dir).arg(target).assert().success();
    }

    // Append a corrupt line to the journal.
    let journal_path = cctx_home.path().join("journal.log");
    let mut content = fs::read_to_string(&journal_path).unwrap();
    content.push_str("not-valid-json\n");
    fs::write(&journal_path, content).unwrap();

    // A subsequent switch must fail — corrupt journal blocks mutation.
    // The engine calls find_uncommitted() on startup which returns JournalCorrupt.
    // The CLI converts that to a non-zero exit.
    cctx(&cctx_home, &claude_dir)
        .arg("ctx-a")
        .assert()
        .failure();
}
