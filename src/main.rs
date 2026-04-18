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
            // Check for CredentialsJsonFallback first — print the long help text and suppress
            // the short error line (the long message is self-describing).
            if let Some(Error::CredentialsJsonFallback { path }) = e.downcast_ref::<Error>() {
                eprintln!("{}", cli::format_credentials_json_fallback_help(path));
                std::process::exit(5);
            }

            eprintln!("error: {e:#}");
            let msg = format!("{e:#}");
            // Full exit-code taxonomy lands in issue 4.4; string-match bridge for now.
            let code = if msg.contains("not implemented") {
                3
            } else if msg.contains("partial state")
                || msg.contains("another cctx process")
                || msg.contains("fallback mode")
            {
                5
            } else {
                1
            };
            std::process::exit(code);
        }
    }
}
