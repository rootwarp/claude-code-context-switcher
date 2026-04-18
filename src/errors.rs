//! `thiserror` typed error taxonomy for the library layer.

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
}
