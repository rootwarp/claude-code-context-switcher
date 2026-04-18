#![cfg(feature = "real-keychain")]
//! Integration tests for `SecurityFrameworkBackend`.
//!
//! All tests are gated behind `#[ignore]` and the `CCTX_REAL_KEYCHAIN`
//! environment variable, so they never run in CI unless explicitly opted in:
//!
//! ```
//! CCTX_REAL_KEYCHAIN=1 cargo test --features real-keychain -- --ignored
//! ```
//!
//! Tests use a per-process service prefix (`cctx-test-<pid>`) to avoid
//! colliding with real Claude Code or other cctx items. Teardown purges all
//! items matching that prefix in both a RAII guard (per-test) and a
//! best-effort cleanup at test start.

use claude_code_context_switcher::credential_backend::{
    BackendError, CredentialBackend, PasswordOptions, SecurityFrameworkBackend,
};

fn skip_unless_real_keychain() -> bool {
    std::env::var("CCTX_REAL_KEYCHAIN").ok().as_deref() != Some("1")
}

fn test_service(suffix: &str) -> String {
    format!("cctx-test-{}-{suffix}", std::process::id())
}

fn test_prefix() -> String {
    format!("cctx-test-{}-", std::process::id())
}

fn default_account() -> String {
    std::env::var("USER").unwrap_or_else(|_| "testuser".into())
}

/// Deletes all items matching the per-process test prefix. Silently ignores
/// `NotFound` so this is safe to call unconditionally.
fn purge_test_items(backend: &SecurityFrameworkBackend) {
    let prefix = test_prefix();
    if let Ok(items) = backend.enumerate_by_service_prefix(&prefix) {
        for item in items {
            let _ = backend.delete_generic_password(&item.service, &item.account);
        }
    }
}

struct TeardownGuard<'a> {
    backend: &'a SecurityFrameworkBackend,
}

impl Drop for TeardownGuard<'_> {
    fn drop(&mut self) {
        purge_test_items(self.backend);
    }
}

#[test]
#[ignore]
fn set_then_get_returns_password() {
    if skip_unless_real_keychain() {
        return;
    }
    let backend = SecurityFrameworkBackend::new();
    purge_test_items(&backend);
    let _guard = TeardownGuard { backend: &backend };

    let svc = test_service("set-get");
    let acc = default_account();
    let pw = b"correct-horse-battery-staple";

    backend
        .set_generic_password(&svc, &acc, pw, PasswordOptions::default())
        .expect("set should succeed");

    let got = backend
        .get_generic_password(&svc, &acc)
        .expect("get should succeed");
    assert_eq!(got.expose().as_slice(), pw);
}

#[test]
#[ignore]
fn set_duplicate_without_update_errors() {
    if skip_unless_real_keychain() {
        return;
    }
    let backend = SecurityFrameworkBackend::new();
    purge_test_items(&backend);
    let _guard = TeardownGuard { backend: &backend };

    let svc = test_service("dup");
    let acc = default_account();

    backend
        .set_generic_password(&svc, &acc, b"first", PasswordOptions::default())
        .expect("first set should succeed");

    let err = backend
        .set_generic_password(&svc, &acc, b"second", PasswordOptions::default())
        .expect_err("second set without update_if_exists should fail");
    assert!(matches!(err, BackendError::DuplicateItem));

    // Original value is preserved.
    let got = backend.get_generic_password(&svc, &acc).unwrap();
    assert_eq!(got.expose().as_slice(), b"first");
}

#[test]
#[ignore]
fn delete_removes_item() {
    if skip_unless_real_keychain() {
        return;
    }
    let backend = SecurityFrameworkBackend::new();
    purge_test_items(&backend);
    let _guard = TeardownGuard { backend: &backend };

    let svc = test_service("delete");
    let acc = default_account();

    backend
        .set_generic_password(&svc, &acc, b"temp", PasswordOptions::default())
        .expect("set should succeed");
    backend
        .delete_generic_password(&svc, &acc)
        .expect("delete should succeed");

    let err = backend
        .get_generic_password(&svc, &acc)
        .expect_err("get after delete should fail");
    assert!(matches!(err, BackendError::NotFound));
}

#[test]
#[ignore]
fn enumerate_by_service_prefix_finds_matching_items() {
    if skip_unless_real_keychain() {
        return;
    }
    let backend = SecurityFrameworkBackend::new();
    purge_test_items(&backend);
    let _guard = TeardownGuard { backend: &backend };

    let acc = default_account();
    let services = [
        test_service("enum-abc-1"),
        test_service("enum-abc-2"),
        test_service("enum-abc-3"),
    ];
    for svc in &services {
        backend
            .set_generic_password(svc, &acc, b"pw", PasswordOptions::default())
            .expect("set should succeed");
    }

    let prefix = test_prefix();
    let found = backend
        .enumerate_by_service_prefix(&prefix)
        .expect("enumerate should succeed");

    // All three test items should be found (no others with this pid prefix).
    assert_eq!(found.len(), 3, "expected 3 items, got: {found:?}");
    for item in &found {
        assert!(item.service.starts_with(&prefix));
    }
    // Results should be sorted.
    let svcs: Vec<_> = found.iter().map(|h| &h.service).collect();
    let mut sorted = svcs.clone();
    sorted.sort();
    assert_eq!(svcs, sorted, "results should be sorted by service");
}

#[test]
#[ignore]
fn get_missing_returns_not_found() {
    if skip_unless_real_keychain() {
        return;
    }
    let backend = SecurityFrameworkBackend::new();
    // Use an ephemeral service name that almost certainly doesn't exist.
    let svc = format!("cctx-test-nonexistent-{}", std::process::id());
    let acc = default_account();

    let err = backend
        .get_generic_password(&svc, &acc)
        .expect_err("get of missing item should fail");
    assert!(matches!(err, BackendError::NotFound));
}
