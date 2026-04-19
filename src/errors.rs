//! `thiserror` typed error taxonomy for the library layer.

use std::path::PathBuf;

/// `Error` covers every failure mode in cctx.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// `contexts.yaml` is absent or cannot be opened.
    #[error("contexts file not found: {path}")]
    ContextsFileMissing { path: PathBuf },

    /// A fingerprint hex string was malformed.
    #[error("invalid fingerprint: {msg}")]
    FingerprintParseError {
        /// Human-readable description of why parsing failed.
        msg: String,
    },

    /// Two fingerprints that should be equal differ.
    #[error("fingerprint mismatch: expected {expected}, actual {actual}")]
    FingerprintMismatch { expected: String, actual: String },

    /// `contexts.yaml` could not be parsed.
    #[error("failed to parse {path}: {msg}")]
    ContextsParseError { path: PathBuf, msg: String },

    /// An atomic config write failed.
    #[error("failed to write {path}: {source}")]
    ConfigWriteFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The config directory could not be created.
    #[error("failed to create config dir {path}: {source}")]
    ConfigDirCreateFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `etcetera` could not determine a base strategy for the platform.
    #[error("could not determine config directory: {msg}")]
    EtceteraStrategyFailed { msg: String },

    /// A context was not found by name.
    #[error("context not found: {name}")]
    ContextNotFound { name: String },

    /// A context already exists with this name.
    #[error("context already exists: {name}")]
    ContextAlreadyExists { name: String },

    /// `~/.claude/settings.json` could not be parsed.
    #[error("failed to parse ~/.claude/settings.json: {msg}")]
    SettingsParseError { msg: String },

    /// Caller attempted to write a forbidden env key into `settings.json`.
    #[error("refusing to write forbidden settings.json env key: {key}")]
    SettingsForbiddenKey { key: String },

    /// A JSON serialization/deserialization error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// `~/.claude.json` could not be parsed.
    #[error("failed to parse ~/.claude.json: {msg}")]
    ClaudeStateParseError { msg: String },

    /// A not-yet-implemented path (deferred to a later phase).
    #[error("not implemented in v1: {what}")]
    Unimplemented { what: &'static str },

    /// A generic I/O error not covered by a more specific variant.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A credential-backend error surfaced to upstream callers.
    #[error("keychain backend: {source}")]
    KeychainBackend {
        #[from]
        source: crate::credential_backend::BackendError,
    },

    /// OS denied access to the keychain service (user cancelled or ACL rejected).
    #[error("keychain access denied for service: {service}")]
    KeychainAccessDenied { service: String },

    /// A keychain item was expected but not found.
    #[error("keychain item not found: service={service}, account={account}")]
    KeychainItemMissing { service: String, account: String },

    /// A write to the keychain failed.
    #[error("keychain write failed: {source}")]
    KeychainWriteFailed {
        #[source]
        source: crate::credential_backend::BackendError,
    },

    /// The journal JSONL file contains a line that cannot be parsed.
    #[error("journal file corrupt at {path}:{line}: {msg}")]
    JournalCorrupt {
        path: PathBuf,
        line: usize,
        msg: String,
    },

    /// An `Update` record references an `EntryId` for which no `Init` record exists.
    #[error("journal entry not found: id={id}")]
    JournalEntryNotFound { id: u64 },

    /// A write to the journal file failed.
    #[error("journal write failed: {source}")]
    JournalWriteFailed {
        #[source]
        source: std::io::Error,
    },

    /// A snapshot file could not be written atomically.
    #[error("snapshot write failed: {source}")]
    SnapshotWriteFailed {
        #[source]
        source: std::io::Error,
    },

    /// A snapshot file could not be read.
    #[error("snapshot read failed: {source}")]
    SnapshotReadFailed {
        #[source]
        source: std::io::Error,
    },

    /// A snapshot file could not be parsed as valid JSON.
    #[error("snapshot parse failed at {path}: {msg}")]
    SnapshotParseError { path: PathBuf, msg: String },

    /// The hex-encoded keychain blob in a snapshot file is malformed.
    #[error("invalid hex in snapshot keychain blob: {msg}")]
    SnapshotInvalidHex { msg: String },

    /// Post-apply read-back didn't match the planned value for the given store.
    #[error("verify failed for store {which_store:?}")]
    VerifyFailed { which_store: crate::journal::Store },

    /// Rollback itself failed after a failed apply or verify.
    #[error("rollback failed after attempting {attempted_stores:?}; snapshot at {path}")]
    RollbackFailed {
        attempted_stores: Vec<crate::journal::Store>,
        path: PathBuf,
    },

    /// Another cctx process holds the advisory lock.
    #[error("another cctx process holds the lock")]
    ConcurrentAccess,

    /// A mutating command was refused because the journal has uncommitted entries.
    #[error(
        "partial state detected; run `cctx doctor` (journal_id={journal_id}, snapshot={snapshot_path:?})"
    )]
    PartiallyAppliedState {
        journal_id: u64,
        snapshot_path: PathBuf,
    },

    /// A mutating command was refused because `.credentials.json` exists, indicating
    /// Claude Code is bypassing the Keychain (research 05).  The long diagnostic message
    /// is rendered by the CLI layer; this one-liner is for error-chain display.
    #[error("claude.json in .credentials.json fallback mode; refusing to switch")]
    CredentialsJsonFallback { path: PathBuf },

    /// A stored context is missing required fields for the requested operation.
    #[error("context '{name}' is corrupt or incomplete: {detail}")]
    ContextCorrupt { name: String, detail: String },
}

impl Error {
    /// Map this error variant to a process exit code.
    ///
    /// | Code | Category |
    /// |------|----------|
    /// | 1    | Unexpected / unclassified |
    /// | 3    | Not found / not implemented |
    /// | 4    | Config / parse corruption |
    /// | 5    | Doctor-recoverable partial state |
    /// | 6    | Manual restore required |
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::ContextNotFound { .. }
            | Self::KeychainItemMissing { .. }
            | Self::Unimplemented { .. } => 3,
            Self::ContextsParseError { .. }
            | Self::ClaudeStateParseError { .. }
            | Self::SettingsParseError { .. }
            | Self::CredentialsJsonFallback { .. } => 4,
            Self::PartiallyAppliedState { .. }
            | Self::ConcurrentAccess
            | Self::VerifyFailed { .. } => 5,
            Self::RollbackFailed { .. } => 6,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_file_missing_message() {
        let e = Error::ContextsFileMissing {
            path: PathBuf::from("/home/user/.config/cctx/contexts.yaml"),
        };
        assert!(e.to_string().contains("contexts file not found"));
        assert!(e.to_string().contains("contexts.yaml"));
    }

    #[test]
    fn keychain_access_denied_message() {
        let e = Error::KeychainAccessDenied {
            service: "Claude Code-credentials".to_string(),
        };
        assert!(e.to_string().contains("keychain access denied"));
        assert!(e.to_string().contains("Claude Code-credentials"));
    }

    #[test]
    fn keychain_item_missing_message() {
        let e = Error::KeychainItemMissing {
            service: "cctx-oauth-work".to_string(),
            account: "alice".to_string(),
        };
        assert!(e.to_string().contains("keychain item not found"));
        assert!(e.to_string().contains("cctx-oauth-work"));
        assert!(e.to_string().contains("alice"));
    }

    #[test]
    fn keychain_write_failed_message() {
        use crate::credential_backend::BackendError;
        let e = Error::KeychainWriteFailed {
            source: BackendError::AccessDenied,
        };
        assert!(e.to_string().contains("keychain write failed"));
    }

    #[test]
    fn fingerprint_mismatch_message() {
        let e = Error::FingerprintMismatch {
            expected: "deadbeef".to_string(),
            actual: "cafebabe".to_string(),
        };
        assert!(e.to_string().contains("fingerprint mismatch"));
        assert!(e.to_string().contains("deadbeef"));
        assert!(e.to_string().contains("cafebabe"));
    }

    #[test]
    fn rollback_failed_exits_6() {
        let e = Error::RollbackFailed {
            attempted_stores: vec![],
            path: PathBuf::from("/tmp/snap.json"),
        };
        assert_eq!(e.exit_code(), 6);
    }

    #[test]
    fn context_not_found_exits_3() {
        let e = Error::ContextNotFound {
            name: "missing".to_string(),
        };
        assert_eq!(e.exit_code(), 3);
    }

    #[test]
    fn partially_applied_state_exits_5() {
        let e = Error::PartiallyAppliedState {
            journal_id: 1,
            snapshot_path: PathBuf::from("/tmp/snap.json"),
        };
        assert_eq!(e.exit_code(), 5);
    }

    #[test]
    fn credentials_json_fallback_exits_4() {
        let e = Error::CredentialsJsonFallback {
            path: PathBuf::from("/home/user/.credentials.json"),
        };
        assert_eq!(e.exit_code(), 4);
    }

    #[test]
    fn unimplemented_exits_3() {
        let e = Error::Unimplemented {
            what: "some feature",
        };
        assert_eq!(e.exit_code(), 3);
    }
}
