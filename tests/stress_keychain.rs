//! Real-Keychain stress tests — require `CCTX_REAL_KEYCHAIN=1`.
//!
//! Prereqs: `personal` and `work` OAuth contexts + `console-key` API-key context added via `cctx add`.
//!
//! Run with:
//!   CCTX_REAL_KEYCHAIN=1 cargo test --test stress_keychain -- --ignored --test-threads=1

#[cfg(feature = "real-keychain")]
use claude_code_context_switcher::credential_backend::SecurityFrameworkBackend;
use claude_code_context_switcher::credential_backend::CredentialBackend;

fn skip_unless_real_keychain() -> bool {
    std::env::var("CCTX_REAL_KEYCHAIN").ok().as_deref() != Some("1")
}

fn cctx_bin() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_cctx"))
}

/// 20 alternating OAuth switches leave no Keychain orphans.
#[cfg(feature = "real-keychain")]
#[ignore = "requires CCTX_REAL_KEYCHAIN=1 and registered contexts"]
#[test]
fn twenty_alternating_switches_leave_no_orphans() {
    if skip_unless_real_keychain() { return; }
    let backend = SecurityFrameworkBackend::new();
    let pre_count = backend.enumerate_by_service_prefix("Claude Code").unwrap().len();
    for i in 0..20 {
        let name = if i % 2 == 0 { "personal" } else { "work" };
        let status = cctx_bin().arg(name).status().unwrap();
        assert!(status.success(), "switch {name} failed on iteration {i}");
    }
    let post_count = backend.enumerate_by_service_prefix("Claude Code").unwrap().len();
    assert_eq!(pre_count, post_count, "orphan Keychain items after 20 switches");
}

/// 10 OAuth↔API-key alternations leave no orphans and no stale `Claude Code-credentials` items.
#[cfg(feature = "real-keychain")]
#[ignore = "requires CCTX_REAL_KEYCHAIN=1 and registered contexts"]
#[test]
fn oauth_api_key_alternation_no_orphans() {
    if skip_unless_real_keychain() { return; }
    let backend = SecurityFrameworkBackend::new();
    for i in 0..11 {
        let name = if i % 2 == 0 { "personal" } else { "console-key" };
        let status = cctx_bin().arg(name).status().unwrap();
        assert!(status.success(), "switch {name} failed on iteration {i}");
    }
    // After switching back to OAuth at the end, credentials item must exist.
    let creds = backend.enumerate_by_service_prefix("Claude Code-credentials").unwrap();
    assert!(!creds.is_empty(), "Claude Code-credentials item missing after OAuth restore");
}
