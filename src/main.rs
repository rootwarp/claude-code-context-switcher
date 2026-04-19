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
use claude_code_context_switcher::errors::Error;

fn main() {
    match cli::run() {
        Ok(()) => {}
        Err(e) => {
            if let Some(Error::CredentialsJsonFallback { path }) = e.downcast_ref::<Error>() {
                eprintln!("{}", cli::format_credentials_json_fallback_help(path));
                std::process::exit(4); // was 5 — corrected to 4 (config corruption)
            }
            eprintln!("error: {e:#}");
            let code = e
                .downcast_ref::<Error>()
                .map(Error::exit_code)
                .unwrap_or(1);
            std::process::exit(code);
        }
    }
}
