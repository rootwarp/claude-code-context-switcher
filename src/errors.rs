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

    /// A generic I/O error not covered by a more specific variant.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
