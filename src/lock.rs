//! `flock(2)` advisory lock on `~/.config/cctx/.lock` around every mutating command.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::errors::Error;

/// RAII guard: drops unlock.
#[derive(Debug)]
pub struct Guard {
    file: File,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// Acquire exclusive advisory lock on `lock_file_path`. Polls `try_lock_exclusive` every 50ms
/// up to `timeout`. Creates the lock file with mode 0600 if absent.
///
/// The effective timeout can be overridden by `CCTX_TEST_LOCK_TIMEOUT_MS` (milliseconds); this is
/// intended for tests that need deterministic concurrent-access outcomes.
///
/// # Errors
/// - `Error::ConcurrentAccess` — timeout elapsed; another cctx process holds the lock.
/// - `Error::ConfigWriteFailed` — lock file couldn't be created or opened.
pub fn acquire_exclusive(lock_file_path: &Path, timeout: Duration) -> Result<Guard, Error> {
    let timeout = std::env::var("CCTX_TEST_LOCK_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(timeout, Duration::from_millis);
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let file = opts
        .open(lock_file_path)
        .map_err(|e| Error::ConfigWriteFailed {
            path: lock_file_path.to_owned(),
            source: e,
        })?;

    let start = Instant::now();
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(Guard { file }),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() >= timeout {
                    return Err(Error::ConcurrentAccess);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(Error::ConfigWriteFailed {
                    path: lock_file_path.to_owned(),
                    source: e,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn acquire_on_fresh_file_succeeds() {
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join(".lock");
        let _guard = acquire_exclusive(&lock_path, Duration::from_millis(100)).unwrap();
        assert!(lock_path.exists());
    }

    #[test]
    fn second_acquire_blocks_then_times_out() {
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join(".lock");

        // Thread A acquires and holds the lock.
        let lock_path_a = lock_path.clone();
        let barrier = Arc::new(Barrier::new(2));
        let barrier_a = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            let _guard = acquire_exclusive(&lock_path_a, Duration::from_secs(5)).unwrap();
            barrier_a.wait(); // signal B that lock is held
            thread::sleep(Duration::from_millis(500)); // hold long enough for B to timeout
        });

        barrier.wait(); // wait for A to acquire lock

        // Thread B (us) tries with short timeout → ConcurrentAccess.
        let err = acquire_exclusive(&lock_path, Duration::from_millis(100)).unwrap_err();
        assert!(
            matches!(err, Error::ConcurrentAccess),
            "expected ConcurrentAccess, got: {err:?}"
        );

        handle.join().unwrap();
    }

    #[test]
    fn drop_guard_releases_lock() {
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join(".lock");

        {
            let _guard = acquire_exclusive(&lock_path, Duration::from_millis(100)).unwrap();
            // guard drops here
        }

        // Should succeed because guard was dropped.
        let _guard2 = acquire_exclusive(&lock_path, Duration::from_millis(100)).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn lock_file_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join(".lock");
        let _guard = acquire_exclusive(&lock_path, Duration::from_millis(100)).unwrap();
        let mode = std::fs::metadata(&lock_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }
}
