// Binary crate must carry its own deny set — lib.rs attrs do not propagate here.
// Same panic-protection policy as lib.rs (arch §7): secrets must never appear
// in panic messages. `todo`/`unimplemented`/`unreachable` also panic and
// accept format_args, so they belong in the same deny set.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]
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

use claude_code_context_switcher::cli;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
