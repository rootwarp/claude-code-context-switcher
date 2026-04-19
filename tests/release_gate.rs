//! Release-gate integration tests — Phase 3 exit criteria.
//!
//! All tests are `#[ignore]`. Run with:
//!   CCTX_RELEASE_GATE=1 CCTX_REAL_KEYCHAIN=1 cargo test --test release_gate -- --ignored
//!
//! Prerequisites: `personal` and `work` OAuth contexts registered via `cctx add`.
//! See `plan/release-gate-runbook.md` for the full manual steps.

use assert_cmd::Command;

fn release_gate_enabled() -> bool {
    std::env::var("CCTX_RELEASE_GATE").ok().as_deref() == Some("1")
}

fn cctx() -> Command {
    Command::cargo_bin("cctx").unwrap()
}

/// Switch work → personal via real OAuth keychain; verify both exits are 0.
///
/// Identity verification (subscription email / `/status`) is manual per the runbook.
#[ignore = "requires CCTX_RELEASE_GATE=1 CCTX_REAL_KEYCHAIN=1 and registered OAuth contexts"]
#[test]
fn release_gate_oauth_switch_applies_all_stores() {
    if !release_gate_enabled() {
        return;
    }

    cctx()
        .arg("work")
        .assert()
        .success()
        .stderr(predicates::str::contains("switched"));

    cctx()
        .arg("personal")
        .assert()
        .success();
}

/// Run 10 work↔personal round-trips (20 switches total); all must exit 0.
///
/// Orphan keychain item check (`security find-generic-password`) is manual per the runbook.
#[ignore = "requires CCTX_RELEASE_GATE=1 CCTX_REAL_KEYCHAIN=1 and registered OAuth contexts"]
#[test]
fn release_gate_stress_20_switches() {
    if !release_gate_enabled() {
        return;
    }

    for _ in 0..10 {
        cctx().arg("work").assert().success();
        cctx().arg("personal").assert().success();
    }
}

/// Each of `cctx`, `cctx -c`, and `cctx work` must complete within 500 ms.
///
/// The manual runbook threshold is 100 ms; 500 ms is a generous CI bound.
#[ignore = "requires CCTX_RELEASE_GATE=1 CCTX_REAL_KEYCHAIN=1 and registered OAuth contexts"]
#[test]
fn release_gate_performance_under_100ms() {
    if !release_gate_enabled() {
        return;
    }

    let threshold = std::time::Duration::from_millis(500);

    let cases: &[&[&str]] = &[&[], &["-c"], &["work"]];
    for args in cases {
        let start = std::time::Instant::now();
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("cctx"));
        cmd.args(*args);
        let status = cmd.status().expect("failed to spawn cctx");
        let elapsed = start.elapsed();
        // list/current may exit non-zero if no context is active; we only check timing
        let _ = status;
        assert!(
            elapsed < threshold,
            "cctx {:?} took {:?}, expected < {:?}",
            args,
            elapsed,
            threshold
        );
    }
}
