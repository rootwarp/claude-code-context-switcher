#![warn(clippy::pedantic, clippy::nursery)]

/// The Claude Code version this cctx build is known to interoperate with.
/// Issue 0.7 will set the real observed value from `claude --version`.
#[allow(dead_code)]
pub const CLAUDE_CODE_PINNED_VERSION: &str = "UNPINNED";

pub mod backup;
pub mod claude_state;
pub mod cli;
pub mod config;
pub mod context;
pub mod credential_backend;
pub mod doctor;
pub mod errors;
pub mod fingerprint;
pub mod fs_atomic;
pub mod interactive;
pub mod journal;
pub mod lock;
pub mod logging;
pub mod secret;
pub mod switch_engine;
