//! Parse argv via clap derive and dispatch to command handlers.

use clap::{ArgAction, Parser, Subcommand};
use clap_complete::Shell;

use crate::config::{self, ContextsFile};

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

/// Render context names for the list command.
///
/// Returns one formatted line per context. If `active_marker` matches a name,
/// that line is prefixed with `"* "`, others with `"  "`.
#[must_use]
pub fn render_list(cf: &ContextsFile, active_marker: Option<&str>) -> Vec<String> {
    cf.contexts
        .keys()
        .map(|name| {
            let marker = if active_marker == Some(name.as_str()) {
                "* "
            } else {
                "  "
            };
            format!("{marker}{name}")
        })
        .collect()
}

fn handle_list(active_marker: Option<&str>) -> anyhow::Result<()> {
    let paths = config::resolve_paths()?;
    let cf = config::load(&paths)?;
    if cf.contexts.is_empty() {
        eprintln!("no contexts configured. run `cctx add <name>` to create one.");
        return Ok(());
    }
    for line in render_list(&cf, active_marker) {
        println!("{line}");
    }
    Ok(())
}

/// Return an informative error for active-context detection.
///
/// Active-context detection requires fingerprinting which lands in Phase 3.
/// Exit code 3 is signalled by `main` when the error message contains "not implemented".
fn handle_current() -> anyhow::Result<()> {
    anyhow::bail!(
        "active-context detection not implemented until Phase 3 (fingerprint module). \
         Use `cctx list` to see configured contexts."
    );
}

#[allow(clippy::needless_pass_by_value)]
fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match (cli.cmd, cli.name, cli.current) {
        (None, None, false) => handle_list(None),
        (None, _, true) | (Some(Command::Current), _, _) => handle_current(),
        // Stubs for 1.5–1.7
        (Some(Command::Switch { .. }), _, _) | (None, Some(_), false) => {
            anyhow::bail!("switch not implemented yet (issue 1.5)")
        }
        (Some(Command::Add { oauth: true, .. }), _, _) => {
            eprintln!(
                "cctx add --oauth is not implemented in v1; \
                 see `claude /login` first, then `cctx add <name>`."
            );
            Ok(())
        }
        (Some(Command::Add { .. }), _, _) => {
            anyhow::bail!("add not implemented yet (issue 1.6)")
        }
        (Some(Command::Delete { .. }), _, _) => {
            anyhow::bail!("delete not implemented yet (issue 1.7)")
        }
        (
            Some(Command::Rename { .. } | Command::Doctor { .. } | Command::Completions { .. }),
            _,
            _,
        ) => {
            eprintln!("not implemented in v1");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use indexmap::IndexMap;

    use crate::config::ContextsFile;
    use crate::context::{AuthMode, Context, Fingerprint, IdentityMetadata, SecretRef};
    use crate::secret::Secret;

    fn make_contexts_file(names: &[&str]) -> ContextsFile {
        let mut contexts = IndexMap::new();
        for &name in names {
            contexts.insert(
                name.to_string(),
                Context {
                    name: name.to_string(),
                    auth_mode: AuthMode::ApiKey { base_url: None },
                    identity: IdentityMetadata::default(),
                    fingerprint: Fingerprint([0u8; 32]),
                    created_at: chrono::DateTime::UNIX_EPOCH,
                    secret_ref: SecretRef::Plaintext {
                        value: Secret::new("key".to_string()),
                    },
                },
            );
        }
        ContextsFile {
            version: 1,
            contexts,
        }
    }

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
    fn dispatch_ok_variants() {
        // Variants that should return Ok after 1.4 wiring (not current/switch/add/delete stubs).
        let ok_variants: Vec<Cli> = vec![
            Cli::try_parse_from(["cctx", "add", "x", "--oauth"]).unwrap(),
            Cli::try_parse_from(["cctx", "rename", "a", "b"]).unwrap(),
            Cli::try_parse_from(["cctx", "doctor"]).unwrap(),
            Cli::try_parse_from(["cctx", "doctor", "--dry-run"]).unwrap(),
            Cli::try_parse_from(["cctx", "completions", "zsh"]).unwrap(),
        ];
        for cli in ok_variants {
            assert!(dispatch(cli).is_ok());
        }
    }

    #[test]
    fn dispatch_current_variants_return_err() {
        let current_variants: Vec<Cli> = vec![
            Cli::try_parse_from(["cctx", "-c"]).unwrap(),
            Cli::try_parse_from(["cctx", "current"]).unwrap(),
        ];
        for cli in current_variants {
            let err = dispatch(cli).unwrap_err();
            assert!(
                err.to_string().contains("not implemented"),
                "expected 'not implemented' in error, got: {err}"
            );
        }
    }

    #[test]
    fn handle_current_returns_unimplemented_error() {
        let err = handle_current().unwrap_err();
        assert!(err.to_string().contains("Phase 3"));
        assert!(err.to_string().contains("not implemented"));
    }

    #[test]
    fn render_list_insertion_order_no_marker() {
        let cf = make_contexts_file(&["alpha", "zeta", "mu"]);
        let lines = render_list(&cf, None);
        assert_eq!(lines, vec!["  alpha", "  zeta", "  mu"]);
    }

    #[test]
    fn render_list_active_marker() {
        let cf = make_contexts_file(&["alpha", "zeta", "mu"]);
        let lines = render_list(&cf, Some("zeta"));
        assert_eq!(lines, vec!["  alpha", "* zeta", "  mu"]);
    }

    #[test]
    fn render_list_empty_contexts() {
        let cf = make_contexts_file(&[]);
        let lines = render_list(&cf, None);
        assert!(lines.is_empty());
    }
}
