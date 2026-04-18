//! Inspect unfinished journal entries and finalize or rollback.

use crate::backup;
use crate::config::ConfigPaths;
use crate::errors::Error;
use crate::journal::{Journal, JournalEntry};
use crate::switch_engine::Stores;

/// Returns the Claude Code version this cctx build was pinned against.
#[must_use]
pub const fn pinned_claude_code_version() -> &'static str {
    crate::CLAUDE_CODE_PINNED_VERSION
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairMode {
    DryRun,
    Rollback,
    Commit,
}

#[derive(Debug)]
pub struct Report {
    pub uncommitted_entries: Vec<JournalEntry>,
    pub actions_taken: Vec<String>,
    pub mode: RepairMode,
}

/// Diagnose the cctx state and optionally repair.
///
/// - `DryRun`: report uncommitted entries, take no action.
/// - `Rollback`: for each uncommitted entry, restore from its snapshot file then mark Failed.
///   Requires `stores` to be `Some`.
/// - `Commit`: mark each uncommitted entry as Completed. No store mutation.
///
/// # Errors
///
/// Returns `Error::Unimplemented` if mode is `Rollback` and `stores` is `None`.
/// Returns journal/backup/keychain errors on I/O failure.
pub fn diagnose_and_repair(
    paths: &ConfigPaths,
    stores: Option<&Stores<'_>>,
    mode: RepairMode,
) -> Result<Report, Error> {
    let mut journal = Journal::open(&paths.journal_file)?;
    let uncommitted = journal.find_uncommitted()?;

    match mode {
        RepairMode::DryRun => Ok(Report {
            uncommitted_entries: uncommitted,
            actions_taken: vec![],
            mode,
        }),

        RepairMode::Commit => {
            let mut actions = Vec::new();
            for entry in &uncommitted {
                journal.mark_completed(entry.id)?;
                actions.push(format!("marked entry {} as Completed", entry.id));
            }
            Ok(Report {
                uncommitted_entries: uncommitted,
                actions_taken: actions,
                mode,
            })
        }

        RepairMode::Rollback => {
            let Some(stores) = stores else {
                return Err(Error::Unimplemented {
                    what: "Rollback requires stores; pass Some(&stores) to diagnose_and_repair",
                });
            };

            let mut actions = Vec::new();
            for entry in &uncommitted {
                let snap = backup::load_snapshot(&entry.snapshot_path)?;
                backup::restore_snapshot(
                    &snap,
                    stores.backend,
                    stores.keychain_service,
                    stores.keychain_account,
                    stores.claude_dot_json_path,
                    stores.settings_json_path,
                )?;
                journal.mark_failed(entry.id, "rolled back by doctor")?;
                actions.push(format!(
                    "rolled back entry {} from snapshot {}",
                    entry.id,
                    entry.snapshot_path.display()
                ));
            }
            Ok(Report {
                uncommitted_entries: uncommitted,
                actions_taken: actions,
                mode,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::capture_snapshot;
    use crate::config::ConfigPaths;
    use crate::credential_backend::{CredentialBackend, InMemoryBackend, PasswordOptions};
    use crate::journal::{Intent, Journal, Op, PlannedOp, Store};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_paths(dir: &std::path::Path) -> ConfigPaths {
        ConfigPaths {
            config_dir: dir.to_path_buf(),
            contexts_file: dir.join("contexts.yaml"),
            backups_dir: dir.join("backups"),
            journal_file: dir.join("journal.log"),
            lock_file: dir.join(".lock"),
        }
    }

    fn sample_planned_ops() -> Vec<PlannedOp> {
        vec![PlannedOp {
            store: Store::Settings,
            op: Op::Write,
        }]
    }

    #[test]
    fn dry_run_on_clean_journal_returns_empty_report() {
        let dir = tempdir().unwrap();
        let paths = make_paths(dir.path());

        let report = diagnose_and_repair(&paths, None, RepairMode::DryRun).unwrap();
        assert!(report.uncommitted_entries.is_empty());
        assert!(report.actions_taken.is_empty());
        assert_eq!(report.mode, RepairMode::DryRun);
    }

    #[test]
    fn dry_run_on_dirty_journal_lists_uncommitted_entries() {
        let dir = tempdir().unwrap();
        let paths = make_paths(dir.path());

        let mut j = Journal::open(&paths.journal_file).unwrap();
        j.append(
            Intent::Switch,
            None,
            Some("ctx1".to_string()),
            sample_planned_ops(),
            PathBuf::from("/snap/1"),
        )
        .unwrap();
        j.append(
            Intent::Add,
            None,
            Some("ctx2".to_string()),
            sample_planned_ops(),
            PathBuf::from("/snap/2"),
        )
        .unwrap();

        let report = diagnose_and_repair(&paths, None, RepairMode::DryRun).unwrap();
        assert_eq!(report.uncommitted_entries.len(), 2);
        assert!(report.actions_taken.is_empty());
    }

    #[test]
    fn commit_mode_marks_uncommitted_as_completed() {
        let dir = tempdir().unwrap();
        let paths = make_paths(dir.path());

        let mut j = Journal::open(&paths.journal_file).unwrap();
        j.append(
            Intent::Switch,
            None,
            Some("ctx1".to_string()),
            sample_planned_ops(),
            PathBuf::from("/snap/1"),
        )
        .unwrap();

        let report = diagnose_and_repair(&paths, None, RepairMode::Commit).unwrap();
        assert_eq!(report.uncommitted_entries.len(), 1);
        assert_eq!(report.actions_taken.len(), 1);

        // Re-open journal and verify no pending entries remain.
        let j2 = Journal::open(&paths.journal_file).unwrap();
        let still_pending = j2.find_uncommitted().unwrap();
        assert!(still_pending.is_empty(), "expected no pending after commit");
    }

    #[test]
    fn rollback_mode_restores_snapshot() {
        let dir = tempdir().unwrap();
        let paths = make_paths(dir.path());
        std::fs::create_dir_all(&paths.backups_dir).unwrap();

        let backend = InMemoryBackend::new();
        backend
            .set_generic_password("svc", "acc", b"original-blob", PasswordOptions::default())
            .unwrap();

        let settings_json = dir.path().join("settings.json");
        std::fs::write(&settings_json, r#"{"env":{"KEY":"original"}}"#).unwrap();
        let claude_dot_json = dir.path().join("claude.json");
        let snap_path = paths.backups_dir.join("snap_001.json");

        // Capture snapshot of initial state.
        capture_snapshot(
            &backend,
            "svc",
            "acc",
            &claude_dot_json,
            &settings_json,
            &snap_path,
        )
        .unwrap();

        // Mutate stores to simulate a partial apply.
        backend
            .set_generic_password(
                "svc",
                "acc",
                b"mutated-blob",
                PasswordOptions {
                    update_if_exists: true,
                    ..Default::default()
                },
            )
            .unwrap();
        std::fs::write(&settings_json, r#"{"env":{"KEY":"mutated"}}"#).unwrap();

        // Write a pending journal entry pointing to the snapshot.
        let mut j = Journal::open(&paths.journal_file).unwrap();
        j.append(
            Intent::Switch,
            None,
            Some("ctx".to_string()),
            sample_planned_ops(),
            snap_path,
        )
        .unwrap();

        let stores = Stores {
            backend: &backend,
            keychain_service: "svc",
            keychain_account: "acc",
            claude_dot_json_path: &claude_dot_json,
            settings_json_path: &settings_json,
            claude_dir: dir.path(),
        };

        let report = diagnose_and_repair(&paths, Some(&stores), RepairMode::Rollback).unwrap();
        assert_eq!(report.uncommitted_entries.len(), 1);
        assert_eq!(report.actions_taken.len(), 1);

        // Verify keychain was restored.
        let restored_blob = backend.get_generic_password("svc", "acc").unwrap();
        assert_eq!(restored_blob.expose(), b"original-blob");

        // Verify settings.json was restored.
        let restored_settings: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_json).unwrap()).unwrap();
        assert_eq!(
            restored_settings["env"]["KEY"],
            serde_json::json!("original")
        );

        // Verify journal now shows Failed.
        let j2 = Journal::open(&paths.journal_file).unwrap();
        let still_pending = j2.find_uncommitted().unwrap();
        assert!(
            still_pending.is_empty(),
            "should have no pending after rollback"
        );
    }

    #[test]
    fn rollback_without_stores_returns_error() {
        let dir = tempdir().unwrap();
        let paths = make_paths(dir.path());

        let mut j = Journal::open(&paths.journal_file).unwrap();
        j.append(
            Intent::Switch,
            None,
            None,
            sample_planned_ops(),
            PathBuf::from("/snap/1"),
        )
        .unwrap();

        let err = diagnose_and_repair(&paths, None, RepairMode::Rollback).unwrap_err();
        assert!(
            matches!(err, Error::Unimplemented { .. }),
            "expected Unimplemented, got: {err:?}"
        );
    }
}
