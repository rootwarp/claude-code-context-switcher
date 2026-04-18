//! Inspect unfinished journal entries and finalize or rollback.

use crate::CLAUDE_CODE_PINNED_VERSION;

/// Returns the Claude Code version this cctx build was pinned against.
///
/// Real doctor implementation lands in Phase 2 / Phase 4; this exists so
/// the pinned-version constant has an intended consumer.
#[must_use]
pub const fn pinned_claude_code_version() -> &'static str {
    CLAUDE_CODE_PINNED_VERSION
}
