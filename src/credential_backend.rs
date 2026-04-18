//! Trait + impls for Keychain CRUD and prefix enumeration.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::secret::Secret;

type Store = Mutex<HashMap<(String, String), (Vec<u8>, PasswordOptions)>>;

/// Keychain CRUD and prefix-enumeration abstraction.
///
/// All implementors must be `Send + Sync` so they can be shared across async
/// tasks or passed to `std::thread::spawn`.
pub trait CredentialBackend: Send + Sync {
    /// Fetch a password stored under `(service, account)`.
    ///
    /// # Errors
    /// Returns [`BackendError::NotFound`] when no item matches, or a
    /// platform-specific error if the keychain cannot be accessed.
    fn get_generic_password(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Secret<Vec<u8>>, BackendError>;

    /// Store a password under `(service, account)`.
    ///
    /// **Signature note:** the password is `&[u8]`, not `Secret<&[u8]>`.
    /// Callers typically hold a `Secret<Vec<u8>>` from `get_generic_password`
    /// and call `.expose()` before passing it here; `Secret<&[u8]>` would
    /// require a separate lifetime and is ergonomically awkward.  If a future
    /// review requires the wrapped form, swap the parameter.
    ///
    /// # Errors
    /// Returns [`BackendError::DuplicateItem`] when the item already exists and
    /// `opts.update_if_exists` is `false`.  Platform errors are propagated as
    /// [`BackendError::Platform`].
    fn set_generic_password(
        &self,
        service: &str,
        account: &str,
        password: &[u8],
        opts: PasswordOptions,
    ) -> Result<(), BackendError>;

    /// Remove a password stored under `(service, account)`.
    ///
    /// # Errors
    /// Returns [`BackendError::NotFound`] when no item matches.
    fn delete_generic_password(&self, service: &str, account: &str) -> Result<(), BackendError>;

    /// List all items whose service name starts with `prefix`, sorted by
    /// `(service, account)`.
    ///
    /// # Errors
    /// Returns a platform-specific error if the keychain cannot be accessed.
    fn enumerate_by_service_prefix(&self, prefix: &str) -> Result<Vec<ItemHandle>, BackendError>;

    /// Read-back verification helper.
    ///
    /// Default: fetch the stored value and compare byte-for-byte.
    ///
    /// # Errors
    /// Returns [`BackendError::VerifyMismatch`] when the stored bytes differ
    /// from `expected`.  Any error from [`Self::get_generic_password`] is
    /// propagated unchanged.
    fn verify_password(
        &self,
        service: &str,
        account: &str,
        expected: &[u8],
    ) -> Result<(), BackendError> {
        let got = self.get_generic_password(service, account)?;
        if got.expose().as_slice() == expected {
            Ok(())
        } else {
            Err(BackendError::VerifyMismatch)
        }
    }
}

/// Options controlling how an item is stored.
#[derive(Debug, Clone, Default)]
pub struct PasswordOptions {
    /// Human-readable label shown in the platform keychain UI.
    pub label: Option<String>,
    /// Access-control policy for the stored item.
    pub access_control: AccessControl,
    /// If `true`, overwrite an existing `(service, account)` pair; otherwise
    /// return [`BackendError::DuplicateItem`].
    pub update_if_exists: bool,
}

/// Access-control policy applied when writing a keychain item.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AccessControl {
    /// `kSecAccessControlAllowApplicationPassword` — the cctx-owned item default.
    #[default]
    ApplicationPassword,
    /// No explicit ACL; delegate to the platform keychain default.
    None,
}

/// Lightweight descriptor returned by [`CredentialBackend::enumerate_by_service_prefix`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemHandle {
    /// Keychain service name.
    pub service: String,
    /// Keychain account name.
    pub account: String,
    /// Human-readable label, if one was stored.
    pub label: Option<String>,
}

/// Errors that a [`CredentialBackend`] implementation can return.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("keychain item not found")]
    NotFound,
    #[error("keychain access denied")]
    AccessDenied,
    #[error("keychain item already exists")]
    DuplicateItem,
    #[error("verify mismatch — written value differs from expected")]
    VerifyMismatch,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("platform error: {0}")]
    Platform(String),
}

// ─── InMemoryBackend ─────────────────────────────────────────────────────────

/// In-process, thread-safe keychain backed by a `HashMap`.
///
/// Always compiled (no `cfg` gate).  Used by all Phase-2 tests and the
/// Phase-2 engine integration.
#[derive(Debug, Default)]
pub struct InMemoryBackend {
    items: Store,
}

impl InMemoryBackend {
    /// Create an empty backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of items currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// `true` when no items are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CredentialBackend for InMemoryBackend {
    fn get_generic_password(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Secret<Vec<u8>>, BackendError> {
        let map = self
            .items
            .lock()
            .map_err(|_| BackendError::Platform("poisoned mutex".into()))?;
        map.get(&(service.to_string(), account.to_string()))
            .map(|(v, _)| Secret::new(v.clone()))
            .ok_or(BackendError::NotFound)
    }

    fn set_generic_password(
        &self,
        service: &str,
        account: &str,
        password: &[u8],
        opts: PasswordOptions,
    ) -> Result<(), BackendError> {
        let key = (service.to_string(), account.to_string());
        {
            let mut map = self
                .items
                .lock()
                .map_err(|_| BackendError::Platform("poisoned mutex".into()))?;
            if map.contains_key(&key) && !opts.update_if_exists {
                return Err(BackendError::DuplicateItem);
            }
            map.insert(key, (password.to_vec(), opts));
        }
        Ok(())
    }

    fn delete_generic_password(&self, service: &str, account: &str) -> Result<(), BackendError> {
        let result = {
            let mut map = self
                .items
                .lock()
                .map_err(|_| BackendError::Platform("poisoned mutex".into()))?;
            map.remove(&(service.to_string(), account.to_string()))
                .map(|_| ())
                .ok_or(BackendError::NotFound)
        };
        result
    }

    fn enumerate_by_service_prefix(&self, prefix: &str) -> Result<Vec<ItemHandle>, BackendError> {
        let mut out: Vec<ItemHandle> = {
            let map = self
                .items
                .lock()
                .map_err(|_| BackendError::Platform("poisoned mutex".into()))?;
            map.iter()
                .filter(|((s, _), _)| s.starts_with(prefix))
                .map(|((s, a), (_, opts))| ItemHandle {
                    service: s.clone(),
                    account: a.clone(),
                    label: opts.label.clone(),
                })
                .collect()
        };
        out.sort_by(|a, b| (&a.service, &a.account).cmp(&(&b.service, &b.account)));
        Ok(out)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn default_opts() -> PasswordOptions {
        PasswordOptions::default()
    }

    fn update_opts() -> PasswordOptions {
        PasswordOptions {
            update_if_exists: true,
            ..Default::default()
        }
    }

    #[test]
    fn set_then_get_returns_password() {
        let b = InMemoryBackend::new();
        b.set_generic_password("svc", "acc", b"hunter2", default_opts())
            .unwrap();
        let v = b.get_generic_password("svc", "acc").unwrap();
        assert_eq!(v.expose().as_slice(), b"hunter2");
    }

    #[test]
    fn get_missing_returns_not_found() {
        let b = InMemoryBackend::new();
        let err = b.get_generic_password("svc", "missing").unwrap_err();
        assert!(matches!(err, BackendError::NotFound));
    }

    #[test]
    fn set_duplicate_without_update_errors() {
        let b = InMemoryBackend::new();
        b.set_generic_password("svc", "acc", b"first", default_opts())
            .unwrap();
        let err = b
            .set_generic_password("svc", "acc", b"second", default_opts())
            .unwrap_err();
        assert!(matches!(err, BackendError::DuplicateItem));
        let v = b.get_generic_password("svc", "acc").unwrap();
        assert_eq!(v.expose().as_slice(), b"first");
    }

    #[test]
    fn set_with_update_if_exists_overwrites() {
        let b = InMemoryBackend::new();
        b.set_generic_password("svc", "acc", b"first", default_opts())
            .unwrap();
        b.set_generic_password("svc", "acc", b"second", update_opts())
            .unwrap();
        let v = b.get_generic_password("svc", "acc").unwrap();
        assert_eq!(v.expose().as_slice(), b"second");
    }

    #[test]
    fn delete_removes_item() {
        let b = InMemoryBackend::new();
        b.set_generic_password("svc", "acc", b"pw", default_opts())
            .unwrap();
        b.delete_generic_password("svc", "acc").unwrap();
        let err = b.get_generic_password("svc", "acc").unwrap_err();
        assert!(matches!(err, BackendError::NotFound));
    }

    #[test]
    fn delete_missing_returns_not_found() {
        let b = InMemoryBackend::new();
        let err = b.delete_generic_password("svc", "ghost").unwrap_err();
        assert!(matches!(err, BackendError::NotFound));
    }

    #[test]
    fn enumerate_by_service_prefix_filters_and_sorts() {
        let b = InMemoryBackend::new();
        b.set_generic_password("cctx-context-b", "user", b"pw", default_opts())
            .unwrap();
        b.set_generic_password("cctx-context-a", "user", b"pw", default_opts())
            .unwrap();
        b.set_generic_password("other-svc-x", "user", b"pw", default_opts())
            .unwrap();

        let all = b.enumerate_by_service_prefix("cctx-context-").unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].service, "cctx-context-a");
        assert_eq!(all[1].service, "cctx-context-b");

        let one = b.enumerate_by_service_prefix("cctx-context-a").unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].service, "cctx-context-a");
    }

    #[test]
    fn enumerate_empty_returns_empty_vec() {
        let b = InMemoryBackend::new();
        let result = b.enumerate_by_service_prefix("cctx-context-").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn verify_password_succeeds_on_match() {
        let b = InMemoryBackend::new();
        b.set_generic_password("svc", "acc", b"correct", default_opts())
            .unwrap();
        b.verify_password("svc", "acc", b"correct").unwrap();
    }

    #[test]
    fn verify_password_fails_on_mismatch() {
        let b = InMemoryBackend::new();
        b.set_generic_password("svc", "acc", b"correct", default_opts())
            .unwrap();
        let err = b.verify_password("svc", "acc", b"wrong").unwrap_err();
        assert!(matches!(err, BackendError::VerifyMismatch));
    }

    #[test]
    fn verify_password_missing_item_propagates_not_found() {
        let b = InMemoryBackend::new();
        let err = b.verify_password("svc", "ghost", b"pw").unwrap_err();
        assert!(matches!(err, BackendError::NotFound));
    }

    #[test]
    fn backend_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryBackend>();
    }

    #[test]
    fn concurrent_set_and_get_threadsafe() {
        let backend = Arc::new(InMemoryBackend::new());
        let writer = Arc::clone(&backend);

        let handle = std::thread::spawn(move || {
            for i in 0..10u8 {
                writer
                    .set_generic_password("svc", &format!("acc-{i}"), &[i], default_opts())
                    .unwrap();
            }
        });

        handle.join().unwrap();

        assert_eq!(backend.len(), 10);
        for i in 0..10u8 {
            let v = backend
                .get_generic_password("svc", &format!("acc-{i}"))
                .unwrap();
            assert_eq!(v.expose().as_slice(), &[i]);
        }
    }
}
