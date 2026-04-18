#![warn(clippy::pedantic, clippy::nursery)]
// Secrets must never panic: .unwrap()/.expect()/panic!()/todo!()/unimplemented!()
// can embed credential data in the panic message. Override per-site with
// #[allow(...)] when necessary (e.g. in tests or truly-infallible cases).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
// Tests may use idiomatic .unwrap()/.expect()/#[should_panic] without per-file
// overrides — the deny set above only targets production code paths.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]

/// The Claude Code version this cctx build is known to interoperate with.
/// Issue 0.7 will set the real observed value from `claude --version`.
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
