//! Parse argv via clap derive and dispatch to command handlers.

/// Entry point for the `cctx` binary.
///
/// # Errors
///
/// Returns an error if argument parsing or any subcommand handler fails.
// `missing_const_for_fn`: stub body is `Ok(())` which satisfies const, but the
// real implementation will not be const — allow rather than mislead the reader.
#[allow(clippy::missing_const_for_fn)]
pub fn run() -> anyhow::Result<()> {
    Ok(())
}
