//! Atomic write-temp-0600-rename helper shared across storage modules.

use std::fs::Permissions;
use std::io::Write as _;
use std::path::Path;

use tempfile::NamedTempFile;

use crate::errors::Error;

/// Write `bytes` to `target` atomically with mode `0o600` on Unix.
///
/// Uses a temp file in the same directory as `target`, fsyncs, then renames.
/// The parent directory must already exist; this function does not create it.
/// On non-Unix platforms the rename still happens but no explicit mode is set.
///
/// # Errors
///
/// Returns [`Error::ConfigWriteFailed`] on any I/O failure.
pub fn write_atomic_0600(target: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = target.parent().ok_or_else(|| Error::ConfigWriteFailed {
        path: target.to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no parent"),
    })?;

    let mut tmp = NamedTempFile::new_in(parent).map_err(|e| Error::ConfigWriteFailed {
        path: parent.to_owned(),
        source: e,
    })?;

    tmp.write_all(bytes).map_err(|e| Error::ConfigWriteFailed {
        path: target.to_owned(),
        source: e,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(Permissions::from_mode(0o600))
            .map_err(|e| Error::ConfigWriteFailed {
                path: target.to_owned(),
                source: e,
            })?;
    }

    tmp.as_file()
        .sync_all()
        .map_err(|e| Error::ConfigWriteFailed {
            path: target.to_owned(),
            source: e,
        })?;

    tmp.persist(target).map_err(|e| Error::ConfigWriteFailed {
        path: target.to_owned(),
        source: e.error,
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_then_read_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        write_atomic_0600(&path, b"hello world").unwrap();
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"hello world");
    }

    #[cfg(unix)]
    #[test]
    fn sets_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        write_atomic_0600(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }

    #[test]
    fn atomic_rename_overwrites_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("target.bin");
        std::fs::write(&path, b"old content").unwrap();
        write_atomic_0600(&path, b"new content").unwrap();
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"new content");
    }
}
