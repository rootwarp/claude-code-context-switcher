//! `thiserror` typed error taxonomy for the library layer.

use std::path::PathBuf;

/// Library-layer errors.
///
/// Only the variants needed by Phase-1 issues land here.  The full 17-variant
/// taxonomy (Phase 4) grows this enum incrementally.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// A fingerprint hex string was malformed.
    #[error("invalid fingerprint: {msg}")]
    FingerprintParseError {
        /// Human-readable description of why parsing failed.
        msg: String,
    },

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
}
