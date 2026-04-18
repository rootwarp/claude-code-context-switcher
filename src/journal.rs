//! Append-only WAL at `~/.config/cctx/journal.log`; crash-recovery log.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::errors::Error;

/// Monotonic entry ID allocated on append.
pub type EntryId = u64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Intent {
    #[serde(rename = "switch")]
    Switch,
    #[serde(rename = "add")]
    Add,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "rename")]
    Rename,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Store {
    Settings,
    ClaudeDotJson,
    Keychain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Write,
    Merge,
    Set,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedOp {
    pub store: Store,
    pub op: Op,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EntryStatus {
    Pending,
    Completed { committed_at: DateTime<Utc> },
    Failed { err: String },
}

/// A journal "record" as written to disk. Two flavors: an `Init` record carrying the full
/// plan, and an `Update` record that mutates a prior entry's status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalRecord {
    Init {
        id: EntryId,
        intent: Intent,
        from: Option<String>,
        to: Option<String>,
        timestamp: DateTime<Utc>,
        planned_ops: Vec<PlannedOp>,
        snapshot_path: PathBuf,
        status: EntryStatus,
    },
    Update {
        id: EntryId,
        status: EntryStatus,
    },
}

/// Folded view of the journal — one entry per ID, reflecting the latest known status.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub id: EntryId,
    pub intent: Intent,
    pub from: Option<String>,
    pub to: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub planned_ops: Vec<PlannedOp>,
    pub snapshot_path: PathBuf,
    pub status: EntryStatus,
}

pub struct Journal {
    path: PathBuf,
    next_id: EntryId,
}

impl Journal {
    /// Open (or create) the journal at `path`.
    ///
    /// Scans existing records (tolerating malformed lines) to determine `next_id`.
    ///
    /// # Errors
    /// Returns `Error::JournalWriteFailed` if the file cannot be created.
    pub fn open(path: &Path) -> Result<Self, Error> {
        if !path.exists() {
            create_journal_file(path)?;
            return Ok(Self {
                path: path.to_path_buf(),
                next_id: 1,
            });
        }

        let content =
            std::fs::read_to_string(path).map_err(|e| Error::JournalWriteFailed { source: e })?;
        let mut max_id: EntryId = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Tolerate malformed lines during open — strict parsing happens in read_all()
            if let Ok(JournalRecord::Init { id, .. }) =
                serde_json::from_str::<JournalRecord>(trimmed)
            {
                if id > max_id {
                    max_id = id;
                }
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            next_id: max_id + 1,
        })
    }

    /// Append a new Init record. Returns the assigned `EntryId`.
    ///
    /// # Errors
    /// Returns `Error::JournalWriteFailed` on I/O failure.
    pub fn append(
        &mut self,
        intent: Intent,
        from: Option<String>,
        to: Option<String>,
        planned_ops: Vec<PlannedOp>,
        snapshot_path: PathBuf,
    ) -> Result<EntryId, Error> {
        let id = self.next_id;
        let record = JournalRecord::Init {
            id,
            intent,
            from,
            to,
            timestamp: Utc::now(),
            planned_ops,
            snapshot_path,
            status: EntryStatus::Pending,
        };
        self.write_record(&record)?;
        self.next_id += 1;
        Ok(id)
    }

    /// Append an Update record marking an entry as Completed.
    ///
    /// # Errors
    /// Returns `Error::JournalEntryNotFound` if `id` has no corresponding Init record.
    /// Returns `Error::JournalWriteFailed` on I/O failure.
    pub fn mark_completed(&mut self, id: EntryId) -> Result<(), Error> {
        self.verify_id_exists(id)?;
        let record = JournalRecord::Update {
            id,
            status: EntryStatus::Completed {
                committed_at: Utc::now(),
            },
        };
        self.write_record(&record)
    }

    /// Append an Update record marking an entry as Failed.
    ///
    /// # Errors
    /// Returns `Error::JournalEntryNotFound` if `id` has no corresponding Init record.
    /// Returns `Error::JournalWriteFailed` on I/O failure.
    pub fn mark_failed(&mut self, id: EntryId, err: &str) -> Result<(), Error> {
        self.verify_id_exists(id)?;
        let record = JournalRecord::Update {
            id,
            status: EntryStatus::Failed {
                err: err.to_string(),
            },
        };
        self.write_record(&record)
    }

    /// Scan the journal, fold Init+Update pairs, return all entries whose latest status is Pending.
    ///
    /// # Errors
    /// Returns `Error::JournalCorrupt` on any malformed JSONL line.
    pub fn find_uncommitted(&self) -> Result<Vec<JournalEntry>, Error> {
        let all = self.read_all()?;
        Ok(all
            .into_iter()
            .filter(|e| matches!(e.status, EntryStatus::Pending))
            .collect())
    }

    /// Scan and return every entry (Init+Update folded), mostly for tests and `doctor`.
    ///
    /// # Errors
    /// Returns `Error::JournalCorrupt` on any malformed JSONL line.
    pub fn read_all(&self) -> Result<Vec<JournalEntry>, Error> {
        if !self.path.exists() {
            return Ok(vec![]);
        }

        let content = std::fs::read_to_string(&self.path)
            .map_err(|e| Error::JournalWriteFailed { source: e })?;

        let mut inits: HashMap<EntryId, JournalEntry> = HashMap::new();
        let mut order: Vec<EntryId> = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let record = serde_json::from_str::<JournalRecord>(trimmed).map_err(|e| {
                Error::JournalCorrupt {
                    path: self.path.clone(),
                    line: line_num,
                    msg: e.to_string(),
                }
            })?;

            match record {
                JournalRecord::Init {
                    id,
                    intent,
                    from,
                    to,
                    timestamp,
                    planned_ops,
                    snapshot_path,
                    status,
                } => {
                    order.push(id);
                    inits.insert(
                        id,
                        JournalEntry {
                            id,
                            intent,
                            from,
                            to,
                            timestamp,
                            planned_ops,
                            snapshot_path,
                            status,
                        },
                    );
                }
                JournalRecord::Update { id, status } => {
                    if let Some(entry) = inits.get_mut(&id) {
                        entry.status = status;
                    } else {
                        return Err(Error::JournalCorrupt {
                            path: self.path.clone(),
                            line: line_num,
                            msg: format!("Update record references unknown id={id}"),
                        });
                    }
                }
            }
        }

        Ok(order
            .into_iter()
            .filter_map(|id| inits.remove(&id))
            .collect())
    }

    fn verify_id_exists(&self, id: EntryId) -> Result<(), Error> {
        if !self.path.exists() {
            return Err(Error::JournalEntryNotFound { id });
        }
        let content = std::fs::read_to_string(&self.path)
            .map_err(|e| Error::JournalWriteFailed { source: e })?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(JournalRecord::Init { id: init_id, .. }) =
                serde_json::from_str::<JournalRecord>(trimmed)
            {
                if init_id == id {
                    return Ok(());
                }
            }
        }
        Err(Error::JournalEntryNotFound { id })
    }

    fn write_record(&self, record: &JournalRecord) -> Result<(), Error> {
        let mut line = serde_json::to_string(record).map_err(Error::Json)?;
        line.push('\n');

        let mut opts = OpenOptions::new();
        opts.create(true).append(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }

        let mut file = opts
            .open(&self.path)
            .map_err(|e| Error::JournalWriteFailed { source: e })?;
        file.write_all(line.as_bytes())
            .map_err(|e| Error::JournalWriteFailed { source: e })
    }
}

fn create_journal_file(path: &Path) -> Result<(), Error> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }

    opts.open(path)
        .map_err(|e| Error::JournalWriteFailed { source: e })?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_ops() -> Vec<PlannedOp> {
        vec![PlannedOp {
            store: Store::Settings,
            op: Op::Write,
        }]
    }

    #[test]
    fn open_missing_creates_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let j = Journal::open(&path).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert_eq!(j.next_id, 1);
    }

    #[test]
    fn append_returns_monotonic_ids() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let mut j = Journal::open(&path).unwrap();
        let id1 = j
            .append(
                Intent::Switch,
                None,
                None,
                sample_ops(),
                PathBuf::from("/snap/1"),
            )
            .unwrap();
        let id2 = j
            .append(
                Intent::Add,
                None,
                None,
                sample_ops(),
                PathBuf::from("/snap/2"),
            )
            .unwrap();
        let id3 = j
            .append(
                Intent::Delete,
                None,
                None,
                sample_ops(),
                PathBuf::from("/snap/3"),
            )
            .unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn append_then_mark_completed_folds_to_completed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let mut j = Journal::open(&path).unwrap();
        let id = j
            .append(
                Intent::Switch,
                None,
                None,
                sample_ops(),
                PathBuf::from("/snap/1"),
            )
            .unwrap();
        j.mark_completed(id).unwrap();
        let all = j.read_all().unwrap();
        assert_eq!(all.len(), 1);
        assert!(matches!(all[0].status, EntryStatus::Completed { .. }));
    }

    #[test]
    fn append_without_completion_stays_pending() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let mut j = Journal::open(&path).unwrap();
        j.append(
            Intent::Switch,
            None,
            None,
            sample_ops(),
            PathBuf::from("/snap/1"),
        )
        .unwrap();
        let uncommitted = j.find_uncommitted().unwrap();
        assert_eq!(uncommitted.len(), 1);
        assert_eq!(uncommitted[0].id, 1);
    }

    #[test]
    fn multiple_pending_entries_returned_by_find_uncommitted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let mut j = Journal::open(&path).unwrap();
        j.append(
            Intent::Switch,
            None,
            None,
            sample_ops(),
            PathBuf::from("/snap/1"),
        )
        .unwrap();
        let id2 = j
            .append(
                Intent::Add,
                None,
                None,
                sample_ops(),
                PathBuf::from("/snap/2"),
            )
            .unwrap();
        j.append(
            Intent::Delete,
            None,
            None,
            sample_ops(),
            PathBuf::from("/snap/3"),
        )
        .unwrap();
        j.mark_completed(id2).unwrap();
        let uncommitted = j.find_uncommitted().unwrap();
        assert_eq!(uncommitted.len(), 2);
        let ids: Vec<EntryId> = uncommitted.iter().map(|e| e.id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
        assert!(!ids.contains(&2));
    }

    #[test]
    fn mark_completed_unknown_id_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let mut j = Journal::open(&path).unwrap();
        let err = j.mark_completed(99).unwrap_err();
        assert!(matches!(err, Error::JournalEntryNotFound { id: 99 }));
    }

    #[test]
    fn mark_failed_records_error_message() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let mut j = Journal::open(&path).unwrap();
        let id = j
            .append(
                Intent::Switch,
                None,
                None,
                sample_ops(),
                PathBuf::from("/snap/1"),
            )
            .unwrap();
        j.mark_failed(id, "io fault").unwrap();
        let all = j.read_all().unwrap();
        assert_eq!(all.len(), 1);
        assert!(matches!(&all[0].status, EntryStatus::Failed { err } if err == "io fault"));
    }

    #[test]
    fn reopen_preserves_next_id() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        {
            let mut j = Journal::open(&path).unwrap();
            for _ in 0..5 {
                j.append(
                    Intent::Switch,
                    None,
                    None,
                    sample_ops(),
                    PathBuf::from("/snap"),
                )
                .unwrap();
            }
        }
        let mut j = Journal::open(&path).unwrap();
        let id = j
            .append(
                Intent::Switch,
                None,
                None,
                sample_ops(),
                PathBuf::from("/snap/6"),
            )
            .unwrap();
        assert_eq!(id, 6);
    }

    #[test]
    fn corrupt_line_errors_on_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        Journal::open(&path).unwrap();

        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(f, "not-json").unwrap();
        }

        let j = Journal::open(&path).unwrap();
        let err = j.find_uncommitted().unwrap_err();
        assert!(matches!(err, Error::JournalCorrupt { line: 1, .. }));
    }

    #[test]
    #[cfg(unix)]
    fn file_mode_is_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let mut j = Journal::open(&path).unwrap();
        j.append(
            Intent::Switch,
            None,
            None,
            sample_ops(),
            PathBuf::from("/snap/1"),
        )
        .unwrap();
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn concurrent_appends_preserve_order_on_append_only_fs() {
        use std::sync::{Arc, Mutex};

        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let j = Arc::new(Mutex::new(Journal::open(&path).unwrap()));

        let j1 = Arc::clone(&j);
        let path1 = path.clone();
        let t1 = std::thread::spawn(move || {
            for _ in 0..5 {
                j1.lock()
                    .unwrap()
                    .append(Intent::Switch, None, None, sample_ops(), path1.clone())
                    .unwrap();
            }
        });

        let j2 = Arc::clone(&j);
        let t2 = std::thread::spawn(move || {
            for _ in 0..5 {
                j2.lock()
                    .unwrap()
                    .append(Intent::Switch, None, None, sample_ops(), path.clone())
                    .unwrap();
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let all = j.lock().unwrap().read_all().unwrap();
        assert_eq!(all.len(), 10);

        let mut ids: Vec<EntryId> = all.iter().map(|e| e.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, (1u64..=10).collect::<Vec<_>>());
    }

    #[test]
    fn intent_serializes_lowercase() {
        let record = JournalRecord::Init {
            id: 1,
            intent: Intent::Switch,
            from: None,
            to: None,
            timestamp: Utc::now(),
            planned_ops: vec![],
            snapshot_path: PathBuf::from("/snap"),
            status: EntryStatus::Pending,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(
            json.contains(r#""switch""#),
            "expected lowercase intent in: {json}"
        );
        assert!(!json.contains(r#""Switch""#));
    }
}
