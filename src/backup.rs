//! Timestamped snapshot files at `~/.config/cctx/backups/*.json` mode 0600.
//!
//! The keychain blob is stored on-disk as a hex string (field `keychain_blob_hex`)
//! rather than base64 to avoid pulling in a new dependency.  Both encode arbitrary
//! bytes in a JSON-safe, human-skimmable way; hex was chosen for zero-dep simplicity.

use std::fs;
use std::io;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::credential_backend::{BackendError, CredentialBackend, PasswordOptions};
use crate::errors::Error;
use crate::fs_atomic::write_atomic_0600;
use crate::secret::Secret;

// ─── Hex helpers ─────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, Error> {
    if !s.is_ascii() {
        return Err(Error::SnapshotInvalidHex {
            msg: "non-ASCII character in hex string".to_owned(),
        });
    }
    if s.len() % 2 != 0 {
        return Err(Error::SnapshotInvalidHex {
            msg: format!("odd-length hex string ({} chars)", s.len()),
        });
    }
    s.as_bytes()
        .chunks(2)
        .enumerate()
        .map(|(i, pair)| {
            // SAFETY: is_ascii check above ensures both bytes are ASCII and
            // from_str_radix is infallible for valid hex digits.
            let nibbles = std::str::from_utf8(pair).map_err(|e| Error::SnapshotInvalidHex {
                msg: format!("at byte {}: {e}", i * 2),
            })?;
            u8::from_str_radix(nibbles, 16).map_err(|e| Error::SnapshotInvalidHex {
                msg: format!("at offset {}: {e}", i * 2),
            })
        })
        .collect()
}

// ─── Public types ─────────────────────────────────────────────────────────────

/// In-memory snapshot of the three credential stores at a point in time.
#[derive(Debug)]
pub struct Snapshot {
    /// Raw bytes of the Claude Code keychain item, or `None` if no item existed.
    pub keychain_blob: Option<Secret<Vec<u8>>>,
    /// Parsed contents of `~/.claude.json`, or `None` if the file did not exist.
    pub claude_dot_json: Option<serde_json::Value>,
    /// Parsed contents of `~/.claude/settings.json`, or `None` if the file did not exist.
    pub settings_json: Option<serde_json::Value>,
    /// UTC instant at which the snapshot was captured.
    pub taken_at: DateTime<Utc>,
}

/// On-disk JSON representation of a [`Snapshot`].
///
/// The keychain blob is stored as a lowercase hex string in `keychain_blob_hex`
/// so that arbitrary bytes survive JSON round-trips without a base64 dependency.
/// The field is wrapped in `Secret` so the in-memory copy is zeroized on drop.
#[derive(Debug, Serialize, Deserialize)]
struct SnapshotOnDisk {
    taken_at: DateTime<Utc>,
    /// Lowercase hex encoding of the raw keychain blob, or `null` when no item existed.
    keychain_blob_hex: Option<Secret<String>>,
    claude_dot_json: Option<serde_json::Value>,
    settings_json: Option<serde_json::Value>,
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Capture the current state of all three credential stores and persist to disk.
///
/// # Arguments
///
/// * `backend` — keychain backend to query for the credential blob.
/// * `keychain_service` — service name used to locate the keychain item.
/// * `keychain_account` — account name used to locate the keychain item.
/// * `claude_dot_json_path` — path to `~/.claude.json` (home-relative, outside `claude_dir`).
/// * `settings_json_path` — path to `~/.claude/settings.json`.
/// * `out_path` — destination path for the snapshot JSON file (parent must exist).
///
/// # Errors
///
/// Returns an error if the keychain read fails with something other than
/// [`BackendError::NotFound`], or if any file I/O fails.
pub fn capture_snapshot(
    backend: &dyn CredentialBackend,
    keychain_service: &str,
    keychain_account: &str,
    claude_dot_json_path: &Path,
    settings_json_path: &Path,
    out_path: &Path,
) -> Result<Snapshot, Error> {
    let keychain_blob = match backend.get_generic_password(keychain_service, keychain_account) {
        Ok(blob) => Some(blob),
        Err(BackendError::NotFound) => None,
        Err(e) => return Err(Error::KeychainBackend { source: e }),
    };

    let claude_dot_json = read_optional_json(claude_dot_json_path)?;
    let settings_json = read_optional_json(settings_json_path)?;

    let snap = Snapshot {
        keychain_blob,
        claude_dot_json,
        settings_json,
        taken_at: Utc::now(),
    };

    let on_disk = snapshot_to_disk(&snap);
    let bytes = serde_json::to_vec_pretty(&on_disk).map_err(|e| Error::SnapshotParseError {
        path: out_path.to_owned(),
        msg: e.to_string(),
    })?;
    write_atomic_0600(out_path, &bytes).map_err(extract_snapshot_write_err)?;

    Ok(snap)
}

/// Restore all three credential stores to the state captured in `snap`.
///
/// Each store is restored independently; if one fails the error is returned
/// immediately and the remaining stores are not touched.  The caller (the
/// switch engine) is responsible for deciding rollback ordering.
///
/// # Arguments
///
/// * `snap` — snapshot produced by [`capture_snapshot`] or [`load_snapshot`].
/// * `backend` — keychain backend to write or delete the credential blob.
/// * `keychain_service` — service name for the keychain item.
/// * `keychain_account` — account name for the keychain item.
/// * `claude_dot_json_path` — path to `~/.claude.json`.
/// * `settings_json_path` — path to `~/.claude/settings.json`.
///
/// # Errors
///
/// Returns an error if any store write or delete fails.
pub fn restore_snapshot(
    snap: &Snapshot,
    backend: &dyn CredentialBackend,
    keychain_service: &str,
    keychain_account: &str,
    claude_dot_json_path: &Path,
    settings_json_path: &Path,
) -> Result<(), Error> {
    match &snap.keychain_blob {
        Some(blob) => {
            backend.set_generic_password(
                keychain_service,
                keychain_account,
                blob.expose(),
                PasswordOptions {
                    update_if_exists: true,
                    ..Default::default()
                },
            )?;
        }
        None => match backend.delete_generic_password(keychain_service, keychain_account) {
            Ok(()) | Err(BackendError::NotFound) => {}
            Err(e) => return Err(Error::KeychainBackend { source: e }),
        },
    }

    restore_file(claude_dot_json_path, snap.claude_dot_json.as_ref())?;
    restore_file(settings_json_path, snap.settings_json.as_ref())?;

    Ok(())
}

/// Load a snapshot from disk (for `doctor` / rollback-after-crash).
///
/// # Errors
///
/// Returns [`Error::SnapshotReadFailed`] if the file cannot be read,
/// [`Error::SnapshotParseError`] if the JSON is malformed,
/// and [`Error::SnapshotInvalidHex`] if the keychain blob hex is corrupt.
pub fn load_snapshot(path: &Path) -> Result<Snapshot, Error> {
    let bytes = fs::read(path).map_err(|e| Error::SnapshotReadFailed { source: e })?;
    let on_disk: SnapshotOnDisk =
        serde_json::from_slice(&bytes).map_err(|e| Error::SnapshotParseError {
            path: path.to_owned(),
            msg: e.to_string(),
        })?;
    snapshot_from_disk(on_disk)
}

// ─── Private helpers ──────────────────────────────────────────────────────────

fn snapshot_to_disk(snap: &Snapshot) -> SnapshotOnDisk {
    SnapshotOnDisk {
        taken_at: snap.taken_at,
        keychain_blob_hex: snap
            .keychain_blob
            .as_ref()
            .map(|s| Secret::new(hex_encode(s.expose()))),
        claude_dot_json: snap.claude_dot_json.clone(),
        settings_json: snap.settings_json.clone(),
    }
}

fn snapshot_from_disk(on_disk: SnapshotOnDisk) -> Result<Snapshot, Error> {
    let keychain_blob = on_disk
        .keychain_blob_hex
        .map(|hex| hex_decode(hex.expose()).map(Secret::new))
        .transpose()?;
    Ok(Snapshot {
        keychain_blob,
        claude_dot_json: on_disk.claude_dot_json,
        settings_json: on_disk.settings_json,
        taken_at: on_disk.taken_at,
    })
}

fn read_optional_json(path: &Path) -> Result<Option<serde_json::Value>, Error> {
    match fs::read(path) {
        Ok(bytes) => {
            let value = serde_json::from_slice(&bytes).map_err(|e| Error::SnapshotParseError {
                path: path.to_owned(),
                msg: e.to_string(),
            })?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::SnapshotReadFailed { source: e }),
    }
}

fn restore_file(path: &Path, value: Option<&serde_json::Value>) -> Result<(), Error> {
    match value {
        Some(v) => {
            let bytes = serde_json::to_vec_pretty(v).map_err(|e| Error::SnapshotParseError {
                path: path.to_owned(),
                msg: e.to_string(),
            })?;
            write_atomic_0600(path, &bytes).map_err(extract_snapshot_write_err)
        }
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::SnapshotWriteFailed { source: e }),
        },
    }
}

fn extract_snapshot_write_err(e: Error) -> Error {
    match e {
        Error::ConfigWriteFailed { source, .. } => Error::SnapshotWriteFailed { source },
        other => Error::SnapshotWriteFailed {
            source: io::Error::other(other.to_string()),
        },
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_backend::InMemoryBackend;
    use serde_json::json;
    use tempfile::tempdir;

    const SVC: &str = "test-service";
    const ACC: &str = "test-account";

    fn make_backend_with_item(blob: &[u8]) -> InMemoryBackend {
        let b = InMemoryBackend::new();
        b.set_generic_password(SVC, ACC, blob, PasswordOptions::default())
            .unwrap();
        b
    }

    #[test]
    fn capture_writes_file_and_returns_snapshot() {
        let dir = tempdir().unwrap();
        let backend = make_backend_with_item(b"secret-bytes");
        let claude_json = dir.path().join("claude.json");
        let settings = dir.path().join("settings.json");
        fs::write(&claude_json, r#"{"userId":"u1"}"#).unwrap();
        fs::write(&settings, r#"{"theme":"dark"}"#).unwrap();
        let out = dir.path().join("snap.json");

        let snap = capture_snapshot(&backend, SVC, ACC, &claude_json, &settings, &out).unwrap();

        assert!(out.exists());
        assert_eq!(snap.keychain_blob.unwrap().expose(), b"secret-bytes");
        assert!(snap.claude_dot_json.is_some());
        assert!(snap.settings_json.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_file_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let backend = InMemoryBackend::new();
        let out = dir.path().join("snap.json");
        capture_snapshot(
            &backend,
            SVC,
            ACC,
            &dir.path().join("absent1.json"),
            &dir.path().join("absent2.json"),
            &out,
        )
        .unwrap();
        let mode = fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }

    #[test]
    fn capture_with_no_keychain_item_produces_none() {
        let dir = tempdir().unwrap();
        let backend = InMemoryBackend::new();
        let out = dir.path().join("snap.json");
        let snap = capture_snapshot(
            &backend,
            SVC,
            ACC,
            &dir.path().join("absent.json"),
            &dir.path().join("absent2.json"),
            &out,
        )
        .unwrap();
        assert!(snap.keychain_blob.is_none());
    }

    #[test]
    fn capture_with_missing_claude_dot_json_is_none() {
        let dir = tempdir().unwrap();
        let backend = InMemoryBackend::new();
        let out = dir.path().join("snap.json");
        let snap = capture_snapshot(
            &backend,
            SVC,
            ACC,
            &dir.path().join("does_not_exist.json"),
            &dir.path().join("also_absent.json"),
            &out,
        )
        .unwrap();
        assert!(snap.claude_dot_json.is_none());
    }

    #[test]
    fn capture_with_missing_settings_json_is_none() {
        let dir = tempdir().unwrap();
        let backend = InMemoryBackend::new();
        let claude_json = dir.path().join("claude.json");
        fs::write(&claude_json, r#"{"userId":"u1"}"#).unwrap();
        let out = dir.path().join("snap.json");
        let snap = capture_snapshot(
            &backend,
            SVC,
            ACC,
            &claude_json,
            &dir.path().join("absent_settings.json"),
            &out,
        )
        .unwrap();
        assert!(snap.settings_json.is_none());
    }

    #[test]
    fn restore_writes_keychain_blob_back() {
        let dir = tempdir().unwrap();
        let backend = make_backend_with_item(b"my-blob");
        let out = dir.path().join("snap.json");
        capture_snapshot(
            &backend,
            SVC,
            ACC,
            &dir.path().join("a.json"),
            &dir.path().join("b.json"),
            &out,
        )
        .unwrap();

        backend.delete_generic_password(SVC, ACC).unwrap();
        assert!(backend.get_generic_password(SVC, ACC).is_err());

        let snap = load_snapshot(&out).unwrap();
        restore_snapshot(
            &snap,
            &backend,
            SVC,
            ACC,
            &dir.path().join("a.json"),
            &dir.path().join("b.json"),
        )
        .unwrap();

        let restored = backend.get_generic_password(SVC, ACC).unwrap();
        assert_eq!(restored.expose(), b"my-blob");
    }

    #[test]
    fn restore_deletes_keychain_when_snapshot_none() {
        let dir = tempdir().unwrap();
        let backend = make_backend_with_item(b"existing");

        let snap = Snapshot {
            keychain_blob: None,
            claude_dot_json: None,
            settings_json: None,
            taken_at: Utc::now(),
        };
        restore_snapshot(
            &snap,
            &backend,
            SVC,
            ACC,
            &dir.path().join("a.json"),
            &dir.path().join("b.json"),
        )
        .unwrap();

        let err = backend.get_generic_password(SVC, ACC).unwrap_err();
        assert!(matches!(err, BackendError::NotFound));
    }

    #[test]
    fn restore_writes_claude_dot_json_bytes() {
        let dir = tempdir().unwrap();
        let backend = InMemoryBackend::new();
        let claude_json = dir.path().join("claude.json");
        let settings = dir.path().join("settings.json");
        fs::write(&claude_json, r#"{"userId":"original"}"#).unwrap();
        let out = dir.path().join("snap.json");

        let _snap = capture_snapshot(&backend, SVC, ACC, &claude_json, &settings, &out).unwrap();

        fs::write(&claude_json, r#"{"userId":"mutated"}"#).unwrap();

        let snap = load_snapshot(&out).unwrap();
        restore_snapshot(&snap, &backend, SVC, ACC, &claude_json, &settings).unwrap();

        let restored: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&claude_json).unwrap()).unwrap();
        assert_eq!(restored["userId"], json!("original"));
    }

    #[test]
    fn restore_is_idempotent() {
        let dir = tempdir().unwrap();
        let backend = make_backend_with_item(b"blob");
        let claude_json = dir.path().join("claude.json");
        let settings = dir.path().join("settings.json");
        fs::write(&claude_json, r#"{"userId":"u1"}"#).unwrap();
        fs::write(&settings, r#"{"theme":"light"}"#).unwrap();
        let out = dir.path().join("snap.json");

        capture_snapshot(&backend, SVC, ACC, &claude_json, &settings, &out).unwrap();
        let snap = load_snapshot(&out).unwrap();

        restore_snapshot(&snap, &backend, SVC, ACC, &claude_json, &settings).unwrap();
        restore_snapshot(&snap, &backend, SVC, ACC, &claude_json, &settings).unwrap();

        let blob = backend.get_generic_password(SVC, ACC).unwrap();
        assert_eq!(blob.expose(), b"blob");
        let cdj: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&claude_json).unwrap()).unwrap();
        assert_eq!(cdj["userId"], json!("u1"));
    }

    #[test]
    fn load_snapshot_roundtrips_hex_blob() {
        let dir = tempdir().unwrap();
        let non_utf8_blob: &[u8] = &[0x00, 0xff, 0x80, 0x42];
        let backend = InMemoryBackend::new();
        backend
            .set_generic_password(SVC, ACC, non_utf8_blob, PasswordOptions::default())
            .unwrap();
        let out = dir.path().join("snap.json");

        capture_snapshot(
            &backend,
            SVC,
            ACC,
            &dir.path().join("absent1.json"),
            &dir.path().join("absent2.json"),
            &out,
        )
        .unwrap();

        let snap = load_snapshot(&out).unwrap();
        assert_eq!(snap.keychain_blob.unwrap().expose(), non_utf8_blob);
    }

    #[test]
    fn load_snapshot_rejects_invalid_hex() {
        let dir = tempdir().unwrap();
        let bad_json = serde_json::json!({
            "taken_at": "2026-04-19T00:00:00Z",
            "keychain_blob_hex": "not-hex!!",
            "claude_dot_json": null,
            "settings_json": null
        });
        let path = dir.path().join("bad.json");
        fs::write(&path, serde_json::to_vec(&bad_json).unwrap()).unwrap();

        let err = load_snapshot(&path).unwrap_err();
        assert!(
            matches!(err, Error::SnapshotInvalidHex { .. }),
            "expected SnapshotInvalidHex, got: {err:?}"
        );
    }

    #[test]
    fn restore_with_none_claude_json_deletes_existing_file() {
        let dir = tempdir().unwrap();
        let backend = InMemoryBackend::new();
        let claude_json = dir.path().join("claude.json");
        let settings = dir.path().join("settings.json");
        fs::write(&claude_json, r#"{"userId":"u1"}"#).unwrap();

        let snap = Snapshot {
            keychain_blob: None,
            claude_dot_json: None,
            settings_json: None,
            taken_at: Utc::now(),
        };
        restore_snapshot(&snap, &backend, SVC, ACC, &claude_json, &settings).unwrap();
        assert!(
            !claude_json.exists(),
            "claude.json should have been deleted"
        );
    }

    #[test]
    fn load_snapshot_rejects_non_ascii_hex() {
        let dir = tempdir().unwrap();
        // "日日" is non-ASCII; 6 bytes but invalid hex
        let bad_json = serde_json::json!({
            "taken_at": "2026-04-19T00:00:00Z",
            "keychain_blob_hex": "日日",
            "claude_dot_json": null,
            "settings_json": null
        });
        let path = dir.path().join("non_ascii.json");
        fs::write(&path, serde_json::to_vec(&bad_json).unwrap()).unwrap();

        let err = load_snapshot(&path).unwrap_err();
        assert!(
            matches!(err, Error::SnapshotInvalidHex { .. }),
            "expected SnapshotInvalidHex, got: {err:?}"
        );
    }

    #[test]
    fn load_snapshot_with_corrupt_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt.json");
        fs::write(&path, b"not valid json {{{").unwrap();

        let err = load_snapshot(&path).unwrap_err();
        assert!(
            matches!(err, Error::SnapshotParseError { .. }),
            "expected SnapshotParseError, got: {err:?}"
        );
    }

    #[test]
    fn capture_with_invalid_json_path_returns_parse_error() {
        let dir = tempdir().unwrap();
        let backend = InMemoryBackend::new();
        let bad_claude_json = dir.path().join("bad_claude.json");
        fs::write(&bad_claude_json, b"not json!!!").unwrap();
        let out = dir.path().join("snap.json");

        let err = capture_snapshot(
            &backend,
            SVC,
            ACC,
            &bad_claude_json,
            &dir.path().join("absent_settings.json"),
            &out,
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::SnapshotParseError { .. }),
            "expected SnapshotParseError, got: {err:?}"
        );
    }
}
