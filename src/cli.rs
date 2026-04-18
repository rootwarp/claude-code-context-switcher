//! Parse argv via clap derive and dispatch to command handlers.

use clap::{ArgAction, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser, Debug)]
#[command(
    name = "cctx",
    version,
    about = "Switch Claude Code authentication identities",
    long_about = None,
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Command>,

    /// Positional shortcut for `cctx switch <name>`.
    pub name: Option<String>,

    /// Print the currently-active context name and exit.
    #[arg(short = 'c', long)]
    pub current: bool,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace).
    #[arg(short = 'v', long, action = ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Switch to a named context (same as `cctx <name>`).
    Switch { name: String },
    /// Print the currently-active context.
    Current,
    /// Capture the currently-active credentials as a new context.
    Add {
        name: String,
        /// Walk through `claude /login` and capture the new OAuth entry (P1; stub in v1).
        #[arg(long)]
        oauth: bool,
    },
    /// Delete a stored context.
    Delete {
        name: String,
        #[arg(long)]
        force: bool,
    },
    /// Rename a stored context (P1).
    Rename { old: String, new: String },
    /// Diagnose and optionally repair crash state.
    Doctor {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        rollback: bool,
        #[arg(long, conflicts_with_all = ["dry_run", "rollback"])]
        commit: bool,
    },
    /// Emit a shell completion script.
    Completions { shell: Shell },
}

#[must_use]
pub fn parse() -> Cli {
    Cli::parse()
}

/// Run the CLI, parsing argv and dispatching to the appropriate handler.
///
/// # Errors
///
/// Returns an error if argument parsing fails or a subcommand handler returns an error.
pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    dispatch(cli)
}

// Both lints fire because the body is a stub; real arms consuming `cli` land in 1.4–1.7.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
fn dispatch(cli: Cli) -> anyhow::Result<()> {
    // v1 stub dispatch — functional handlers land in issues 1.4–1.7.
    let _ = cli;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_no_args_is_list() {
        let cli = Cli::try_parse_from(["cctx"]).unwrap();
        assert!(cli.cmd.is_none());
        assert!(cli.name.is_none());
        assert!(!cli.current);
    }

    #[test]
    fn parse_dash_c_is_current() {
        let cli = Cli::try_parse_from(["cctx", "-c"]).unwrap();
        assert!(cli.current);
    }

    #[test]
    fn parse_positional_name_sets_name() {
        let cli = Cli::try_parse_from(["cctx", "personal"]).unwrap();
        assert_eq!(cli.name, Some("personal".to_string()));
        assert!(cli.cmd.is_none());
    }

    #[test]
    fn parse_switch_subcommand() {
        let cli = Cli::try_parse_from(["cctx", "switch", "personal"]).unwrap();
        assert!(matches!(cli.cmd, Some(Command::Switch { name }) if name == "personal"));
    }

    #[test]
    fn parse_add_with_oauth_flag() {
        let cli = Cli::try_parse_from(["cctx", "add", "x", "--oauth"]).unwrap();
        assert!(matches!(cli.cmd, Some(Command::Add { name, oauth: true }) if name == "x"));
    }

    #[test]
    fn parse_delete_with_force() {
        let cli = Cli::try_parse_from(["cctx", "delete", "x", "--force"]).unwrap();
        assert!(matches!(cli.cmd, Some(Command::Delete { name, force: true }) if name == "x"));
    }

    #[test]
    fn parse_verbose_counts() {
        let cli = Cli::try_parse_from(["cctx", "-v"]).unwrap();
        assert_eq!(cli.verbose, 1);
        let cli = Cli::try_parse_from(["cctx", "-vv"]).unwrap();
        assert_eq!(cli.verbose, 2);
        let cli = Cli::try_parse_from(["cctx", "-vvv"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn parse_doctor_dry_run() {
        let cli = Cli::try_parse_from(["cctx", "doctor", "--dry-run"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Command::Doctor {
                dry_run: true,
                rollback: false,
                commit: false
            })
        ));
    }

    #[test]
    fn parse_doctor_mutually_exclusive_flags() {
        let result = Cli::try_parse_from(["cctx", "doctor", "--dry-run", "--rollback"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_completions_zsh() {
        let cli = Cli::try_parse_from(["cctx", "completions", "zsh"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Command::Completions { shell: Shell::Zsh })
        ));
    }

    #[test]
    fn parse_rename() {
        let cli = Cli::try_parse_from(["cctx", "rename", "old", "new"]).unwrap();
        assert!(
            matches!(cli.cmd, Some(Command::Rename { old, new }) if old == "old" && new == "new")
        );
    }

    #[test]
    fn dispatch_returns_ok_for_all_variants() {
        let variants: Vec<Cli> = vec![
            Cli::try_parse_from(["cctx"]).unwrap(),
            Cli::try_parse_from(["cctx", "-c"]).unwrap(),
            Cli::try_parse_from(["cctx", "personal"]).unwrap(),
            Cli::try_parse_from(["cctx", "switch", "personal"]).unwrap(),
            Cli::try_parse_from(["cctx", "current"]).unwrap(),
            Cli::try_parse_from(["cctx", "add", "x"]).unwrap(),
            Cli::try_parse_from(["cctx", "add", "x", "--oauth"]).unwrap(),
            Cli::try_parse_from(["cctx", "delete", "x"]).unwrap(),
            Cli::try_parse_from(["cctx", "delete", "x", "--force"]).unwrap(),
            Cli::try_parse_from(["cctx", "rename", "a", "b"]).unwrap(),
            Cli::try_parse_from(["cctx", "doctor"]).unwrap(),
            Cli::try_parse_from(["cctx", "doctor", "--dry-run"]).unwrap(),
            Cli::try_parse_from(["cctx", "completions", "zsh"]).unwrap(),
        ];
        for cli in variants {
            assert!(dispatch(cli).is_ok());
        }
    }
}
