//! Parse argv via clap derive and dispatch to command handlers.

use std::time::Duration;

use clap::{ArgAction, Parser, Subcommand};
use clap_complete::Shell;

use crate::claude_state;
use crate::config::{self, ContextsFile};
use crate::context::{self, AuthMode, Fingerprint, IdentityMetadata, SecretRef};
use crate::credential_backend::InMemoryBackend;
use crate::doctor::{self, RepairMode};
use crate::errors::Error;
use crate::journal::Journal;
use crate::lock;
use crate::switch_engine;

#[cfg(feature = "real-keychain")]
use crate::credential_backend::SecurityFrameworkBackend;

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

/// Build the long multi-line refusal message shown to the user when
/// `.credentials.json` fallback is detected (research 05 §2, verbatim).
#[must_use]
pub fn format_credentials_json_fallback_help(path: &std::path::Path) -> String {
    let p = path.display();
    // Inline the template without `\` continuation so leading spaces are preserved verbatim.
    format!("cctx: refusing to switch \u{2014} a credentials fallback file exists on this macOS\nmachine, which means Claude Code is NOT reading OAuth from the Keychain. cctx\nonly manages the Keychain-backed flow on macOS.\n\n  Fallback file: {p}\n\nThis usually means one of:\n  \u{2022} $CLAUDE_CONFIG_DIR is set, directing Claude Code to a custom root.\n  \u{2022} An SSH session with a locked Keychain forced Claude Code to the file\n    fallback.\n  \u{2022} A prior export of CLAUDE_CODE_OAUTH_TOKEN triggered upstream bug #37512,\n    which silently purges the Keychain entry on child-process exit.\n\nResolve by:\n  1. unset CLAUDE_CONFIG_DIR                                (if set)\n  2. rm {p}\n  3. claude /login                                          (repopulates Keychain)\n  4. retry cctx\n\nSee: https://github.com/anthropics/claude-code/issues/37512")
}

fn handle_list(active_marker: Option<&str>) -> anyhow::Result<()> {
    let paths = config::resolve_paths()?;
    ensure_config_dir(&paths)?;

    let pending = check_dirty_journal(&paths)?;
    if !pending.is_empty() {
        eprintln!(
            "warning: {} uncommitted journal entr{} detected; run `cctx doctor` to resolve",
            pending.len(),
            if pending.len() == 1 { "y" } else { "ies" }
        );
    }

    // Warn (do not refuse) when .credentials.json fallback is present.
    if let Ok(claude_dir) = claude_state::resolve_claude_dir() {
        if let claude_state::FallbackState::Present { path, .. } =
            claude_state::detect_credentials_json_fallback(&claude_dir)
        {
            eprintln!(
                "warning: .credentials.json exists at {} — active-context detection unavailable (run `cctx doctor`)",
                path.display()
            );
        }
    }

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
    // Warn (do not refuse) when .credentials.json fallback is present.
    if let Ok(claude_dir) = claude_state::resolve_claude_dir() {
        if let claude_state::FallbackState::Present { path, .. } =
            claude_state::detect_credentials_json_fallback(&claude_dir)
        {
            eprintln!(
                "warning: .credentials.json exists at {} — active-context detection unavailable (run `cctx doctor`)",
                path.display()
            );
        }
    }
    anyhow::bail!(
        "active-context detection not implemented until Phase 3 (fingerprint module). \
         Use `cctx list` to see configured contexts."
    );
}

fn current_user_short_name() -> String {
    std::env::var("USER").unwrap_or_else(|_| "default".to_string())
}

fn handle_switch(name: &str) -> anyhow::Result<()> {
    let paths = config::resolve_paths()?;
    ensure_config_dir(&paths)?;
    refuse_if_dirty(&paths)?;

    let _guard = lock::acquire_exclusive(&paths.lock_file, Duration::from_secs(5))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let cf = config::load(&paths)?;

    // Use real Keychain backend when compiled with the real-keychain feature.
    // Integration tests set CCTX_TEST_IN_MEMORY_KEYCHAIN=1 to force InMemoryBackend
    // and avoid SecurityAgent dialogs that would deadlock subprocess-based tests.
    let use_in_memory = std::env::var_os("CCTX_TEST_IN_MEMORY_KEYCHAIN").is_some();
    #[cfg(feature = "real-keychain")]
    let backend: Box<dyn crate::credential_backend::CredentialBackend> = if use_in_memory {
        Box::new(InMemoryBackend::new())
    } else {
        Box::new(SecurityFrameworkBackend::new())
    };
    #[cfg(not(feature = "real-keychain"))]
    let backend: Box<dyn crate::credential_backend::CredentialBackend> = {
        let _ = use_in_memory;
        Box::new(InMemoryBackend::new())
    };

    let settings_path = claude_state::resolve_settings_path()?;
    let claude_dir = claude_state::resolve_claude_dir()?;
    // ~/.claude.json lives at $HOME/.claude.json (OUTSIDE ~/.claude/).
    let claude_dot_json_path = claude_dir.parent().map_or_else(
        || claude_dir.join(".claude.json"),
        |h| h.join(".claude.json"),
    );

    let mut journal = Journal::open(&paths.journal_file)?;
    let stores = switch_engine::Stores {
        backend: &*backend,
        keychain_service: "Claude Code-credentials",
        keychain_account: &current_user_short_name(),
        claude_dot_json_path: &claude_dot_json_path,
        settings_json_path: &settings_path,
        claude_dir: &claude_dir,
    };

    match switch_engine::execute_switch(&cf, name, &stores, &mut journal, &paths)? {
        switch_engine::SwitchOutcome::Applied { from, to } => {
            match from {
                Some(f) => eprintln!("switched from {f} to {to}"),
                None => eprintln!("switched to {to}"),
            }
            Ok(())
        }
        switch_engine::SwitchOutcome::NoOp { reason } => match reason {
            switch_engine::NoOpReason::AlreadyActive => {
                eprintln!("already active: {name}");
                Ok(())
            }
            switch_engine::NoOpReason::ContextNotFound => {
                anyhow::bail!("context not found: {name}")
            }
            switch_engine::NoOpReason::NoContextsConfigured => {
                anyhow::bail!("no contexts configured")
            }
        },
        switch_engine::SwitchOutcome::RolledBack { cause } => {
            anyhow::bail!("switch failed and was rolled back: {cause}");
        }
    }
}

fn handle_delete(name: &str, force: bool) -> anyhow::Result<()> {
    // Refuse before any mutation if .credentials.json fallback is present.
    if let Ok(claude_dir) = claude_state::resolve_claude_dir() {
        if let claude_state::FallbackState::Present { path, .. } =
            claude_state::detect_credentials_json_fallback(&claude_dir)
        {
            return Err(Error::CredentialsJsonFallback { path }.into());
        }
    }

    // Capture env-dependent paths at entry before any blocking operations.
    let settings_path_for_guard = claude_state::resolve_settings_path().ok();
    let paths = config::resolve_paths()?;
    ensure_config_dir(&paths)?;
    refuse_if_dirty(&paths)?;

    let _guard = lock::acquire_exclusive(&paths.lock_file, Duration::from_secs(5))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut cf = config::load(&paths)?;

    if !cf.contexts.contains_key(name) {
        anyhow::bail!("context not found: {name}");
    }

    if !force {
        // Phase-1 heuristic: compare the live settings.json API-key fingerprint to this context.
        // Full active-detection (OAuth, ~/.claude.json) lands in Phase 3.
        if let Some(settings_path) = settings_path_for_guard.as_ref() {
            if let Ok(Some(live_key)) = claude_state::load_settings_api_key(settings_path) {
                let live_fp = Fingerprint::from_api_key(&live_key);
                if cf.contexts.get(name).map(|c| &c.fingerprint) == Some(&live_fp) {
                    anyhow::bail!(
                        "refusing to delete {name}: this context appears to be the currently-active \
                         identity. use --force to override."
                    );
                }
            }
        }
    }

    // Phase 3: sweep cctx-owned Keychain items here.
    // For Phase 1 this is a documented no-op stub.
    // TODO(phase-3): credential_backend::enumerate_by_service_prefix(&format!("cctx-context-{name}"))
    //                then delete each returned ItemHandle.

    cf.contexts.shift_remove(name);
    config::save(&paths, &cf)?;
    eprintln!("deleted {name}");
    Ok(())
}

fn handle_add(name: &str, oauth: bool) -> anyhow::Result<()> {
    if oauth {
        anyhow::bail!(
            "--oauth interactive add is P1 (issue 6.1); for now, log in manually with \
             `claude /login` then run `cctx add {name}` without --oauth"
        );
    }

    // Refuse before any mutation if .credentials.json fallback is present.
    if let Ok(claude_dir) = claude_state::resolve_claude_dir() {
        if let claude_state::FallbackState::Present { path, .. } =
            claude_state::detect_credentials_json_fallback(&claude_dir)
        {
            return Err(Error::CredentialsJsonFallback { path }.into());
        }
    }

    let paths = config::resolve_paths()?;
    ensure_config_dir(&paths)?;
    refuse_if_dirty(&paths)?;

    let _guard = lock::acquire_exclusive(&paths.lock_file, Duration::from_secs(5))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut cf = config::load(&paths)?;

    if cf.contexts.contains_key(name) {
        anyhow::bail!("context already exists: {name}. use `cctx delete {name}` first to replace.");
    }

    let settings_path = claude_state::resolve_settings_path()?;
    let api_key = claude_state::load_settings_api_key(&settings_path)?;

    match api_key {
        Some(key) => {
            let base_url = claude_state::load_settings_base_url(&settings_path)?;
            let fingerprint = Fingerprint::from_api_key(&key);
            let ctx = context::Context {
                name: name.to_string(),
                auth_mode: AuthMode::ApiKey { base_url },
                identity: IdentityMetadata {
                    label: Some(format!(
                        "API key captured {}",
                        chrono::Utc::now().format("%Y-%m-%d")
                    )),
                    ..Default::default()
                },
                fingerprint,
                created_at: chrono::Utc::now(),
                secret_ref: SecretRef::Plaintext { value: key },
            };
            cf.contexts.insert(name.to_string(), ctx);
            config::save(&paths, &cf)?;
            eprintln!("captured {name} as API-key context");
            Ok(())
        }
        None => {
            anyhow::bail!(
                "no active API-key identity found in ~/.claude/settings.json. \
                 Run `claude /login` first, then re-run `cctx add {name}`. \
                 OAuth capture lands in Phase 3."
            );
        }
    }
}

fn handle_rename() -> anyhow::Result<()> {
    // Refuse before any mutation if .credentials.json fallback is present.
    if let Ok(claude_dir) = claude_state::resolve_claude_dir() {
        if let claude_state::FallbackState::Present { path, .. } =
            claude_state::detect_credentials_json_fallback(&claude_dir)
        {
            return Err(Error::CredentialsJsonFallback { path }.into());
        }
    }
    eprintln!("not implemented in v1");
    Ok(())
}

fn handle_doctor(dry_run: bool, rollback: bool, commit: bool) -> anyhow::Result<()> {
    let mode = if dry_run {
        RepairMode::DryRun
    } else if rollback {
        RepairMode::Rollback
    } else if commit {
        RepairMode::Commit
    } else {
        // Default: dry-run when no flag specified.
        RepairMode::DryRun
    };

    let paths = config::resolve_paths()?;
    ensure_config_dir(&paths)?;

    let _guard = lock::acquire_exclusive(&paths.lock_file, Duration::from_secs(5))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // For DryRun/Commit we don't need stores; for Rollback we need them.
    // Phase 2: InMemoryBackend only.
    let backend = InMemoryBackend::new();
    let settings_path = claude_state::resolve_settings_path()?;
    let claude_dir = claude_state::resolve_claude_dir()?;
    let claude_dot_json_path = claude_dir.parent().map_or_else(
        || claude_dir.join(".claude.json"),
        |h| h.join(".claude.json"),
    );

    let stores = switch_engine::Stores {
        backend: &backend,
        keychain_service: "Claude Code-credentials",
        keychain_account: &current_user_short_name(),
        claude_dot_json_path: &claude_dot_json_path,
        settings_json_path: &settings_path,
        claude_dir: &claude_dir,
    };

    let stores_opt = if mode == RepairMode::Rollback {
        Some(&stores)
    } else {
        None
    };

    // Report fallback state as part of doctor output (never refuse).
    match claude_state::detect_credentials_json_fallback(&claude_dir) {
        claude_state::FallbackState::Present { path, size_bytes } => {
            eprintln!(
                "warning: .credentials.json fallback file detected at {} ({size_bytes} bytes) — \
                 Claude Code is NOT using Keychain. Run `cctx doctor` after removing it.",
                path.display()
            );
        }
        claude_state::FallbackState::Absent => {}
    }

    let report = doctor::diagnose_and_repair(&paths, stores_opt, mode)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if report.uncommitted_entries.is_empty() {
        eprintln!("journal is clean — no uncommitted entries");
    } else {
        eprintln!(
            "{} uncommitted entr{}:",
            report.uncommitted_entries.len(),
            if report.uncommitted_entries.len() == 1 {
                "y"
            } else {
                "ies"
            }
        );
        for entry in &report.uncommitted_entries {
            eprintln!(
                "  id={} intent={:?} snapshot={}",
                entry.id,
                entry.intent,
                entry.snapshot_path.display()
            );
        }
    }

    for action in &report.actions_taken {
        eprintln!("  action: {action}");
    }

    // Exit 5 if dirty in DryRun mode (caller checks exit code).
    if mode == RepairMode::DryRun && !report.uncommitted_entries.is_empty() {
        // Signal dirty state: return an error so main maps to exit 5.
        return Err(anyhow::anyhow!(
            "partial state detected: {} uncommitted entr{} — run `cctx doctor --rollback` or `cctx doctor --commit`",
            report.uncommitted_entries.len(),
            if report.uncommitted_entries.len() == 1 { "y" } else { "ies" }
        ));
    }

    Ok(())
}

/// Ensure the config directory exists (creates it if missing, mode 0700 on unix).
fn ensure_config_dir(paths: &config::ConfigPaths) -> anyhow::Result<()> {
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to create config dir {}: {e}",
            paths.config_dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&paths.config_dir, Permissions::from_mode(0o700))
            .map_err(|e| anyhow::anyhow!("failed to set config dir permissions: {e}"))?;
    }
    Ok(())
}

/// Check journal for uncommitted entries. Returns the list (may be empty).
fn check_dirty_journal(
    paths: &config::ConfigPaths,
) -> anyhow::Result<Vec<crate::journal::JournalEntry>> {
    let journal = Journal::open(&paths.journal_file)?;
    Ok(journal.find_uncommitted()?)
}

/// Refuse to proceed if there are uncommitted journal entries.
///
/// Prints a helpful message and returns `Error::PartiallyAppliedState` for the first
/// uncommitted entry found.
fn refuse_if_dirty(paths: &config::ConfigPaths) -> anyhow::Result<()> {
    let pending = check_dirty_journal(paths)?;
    if let Some(first) = pending.first() {
        let err = Error::PartiallyAppliedState {
            journal_id: first.id,
            snapshot_path: first.snapshot_path.clone(),
        };
        return Err(anyhow::anyhow!("{err}"));
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match (cli.cmd, cli.name, cli.current) {
        (None, None, false) => handle_list(None),
        (None, _, true) | (Some(Command::Current), _, _) => handle_current(),
        (Some(Command::Switch { name }), _, _) | (None, Some(name), false) => handle_switch(&name),
        (Some(Command::Add { name, oauth }), _, _) => handle_add(&name, oauth),
        (Some(Command::Delete { name, force }), _, _) => handle_delete(&name, force),
        (Some(Command::Rename { .. }), _, _) => handle_rename(),
        (
            Some(Command::Doctor {
                dry_run,
                rollback,
                commit,
            }),
            _,
            _,
        ) => handle_doctor(dry_run, rollback, commit),
        (Some(Command::Completions { shell }), _, _) => {
            use clap::CommandFactory as _;
            clap_complete::generate(shell, &mut Cli::command(), "cctx", &mut std::io::stdout());
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
    fn dispatch_add_oauth_returns_err_with_p1_message() {
        let cli = Cli::try_parse_from(["cctx", "add", "x", "--oauth"]).unwrap();
        let err = dispatch(cli).unwrap_err();
        assert!(
            err.to_string().contains("P1"),
            "expected P1 in error, got: {err}"
        );
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

    // ── handle_delete unit tests ──────────────────────────────────────────────

    fn make_contexts_file_with_key(name: &str, api_key: &str) -> ContextsFile {
        let key = Secret::new(api_key.to_string());
        let fp = Fingerprint::from_api_key(&key);
        let mut contexts = IndexMap::new();
        contexts.insert(
            name.to_string(),
            Context {
                name: name.to_string(),
                auth_mode: AuthMode::ApiKey { base_url: None },
                identity: IdentityMetadata::default(),
                fingerprint: fp,
                created_at: chrono::DateTime::UNIX_EPOCH,
                secret_ref: SecretRef::Plaintext { value: key },
            },
        );
        ContextsFile {
            version: 1,
            contexts,
        }
    }

    fn write_contexts_file(dir: &std::path::Path, cf: &ContextsFile) {
        let yaml = serde_yaml_ng::to_string(cf).unwrap();
        std::fs::write(dir.join("contexts.yaml"), yaml).unwrap();
    }

    fn write_settings_json(dir: &std::path::Path, api_key: &str) {
        let json = format!(r#"{{"env":{{"ANTHROPIC_API_KEY":"{api_key}"}}}}"#);
        std::fs::write(dir.join("settings.json"), json).unwrap();
    }

    #[test]
    fn handle_delete_unknown_context_errors() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cf = make_contexts_file(&["alpha"]);
        write_contexts_file(tmp.path(), &cf);
        std::env::set_var("CCTX_HOME", tmp.path());
        std::env::set_var("CLAUDE_CONFIG_DIR", tmp.path());

        let err = handle_delete("nosuch", false).unwrap_err();
        assert!(
            err.to_string().contains("context not found: nosuch"),
            "got: {err}"
        );
    }

    #[test]
    fn handle_delete_active_heuristic_blocks_without_force() {
        let cctx_tmp = tempfile::TempDir::new().unwrap();
        let claude_tmp = tempfile::TempDir::new().unwrap();

        let api_key = "sk-ant-unit-test-active-key";
        let cf = make_contexts_file_with_key("myctx", api_key);
        write_contexts_file(cctx_tmp.path(), &cf);
        write_settings_json(claude_tmp.path(), api_key);

        std::env::set_var("CCTX_HOME", cctx_tmp.path());
        std::env::set_var("CLAUDE_CONFIG_DIR", claude_tmp.path());

        let err = handle_delete("myctx", false).unwrap_err();
        assert!(
            err.to_string().contains("--force"),
            "expected --force mention, got: {err}"
        );
    }

    #[test]
    fn handle_delete_active_heuristic_bypassed_with_force() {
        let cctx_tmp = tempfile::TempDir::new().unwrap();
        let claude_tmp = tempfile::TempDir::new().unwrap();

        let api_key = "sk-ant-unit-test-force-key";
        let cf = make_contexts_file_with_key("myctx", api_key);
        write_contexts_file(cctx_tmp.path(), &cf);
        write_settings_json(claude_tmp.path(), api_key);

        std::env::set_var("CCTX_HOME", cctx_tmp.path());
        std::env::set_var("CLAUDE_CONFIG_DIR", claude_tmp.path());

        handle_delete("myctx", true).unwrap();

        // Verify context is gone
        std::env::set_var("CCTX_HOME", cctx_tmp.path());
        let paths = config::resolve_paths().unwrap();
        let loaded = config::load(&paths).unwrap();
        assert!(!loaded.contexts.contains_key("myctx"));
    }
}
