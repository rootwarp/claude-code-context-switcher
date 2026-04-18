#![warn(clippy::pedantic, clippy::nursery)]
// Secrets must never panic: .unwrap()/.expect()/panic!()/todo!()/unimplemented!()/
// unreachable!() can embed credential data in the panic message (all accept
// format_args). Override per-site with #[allow(...)] when necessary.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]
// Tests may use idiomatic .unwrap()/.expect()/#[should_panic]/todo!() without
// per-file overrides — the deny set above only targets production code paths.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable
    )
)]

/// The Claude Code version the Phase-0 research spikes and development observed.
///
/// cctx assumes `claude` is at least this version. Adopting a newer version
/// requires re-running the Phase-0 spikes (0.1 — keychain attrs, 0.2 — userID
/// rotation, 0.3 — .credentials.json fallback policy) and bumping this pin.
pub const CLAUDE_CODE_PINNED_VERSION: &str = "2.1.114";

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
