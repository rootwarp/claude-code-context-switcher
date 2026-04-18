//! Orchestrate plan→snapshot→apply→verify→commit across the three stores.

use std::collections::BTreeMap;
use std::path::Path;

use crate::backup;
use crate::claude_state::{self, AuthModeHint};
use crate::config::{ConfigPaths, ContextsFile};
use crate::context::{AuthMode, Context, Fingerprint, SecretRef};
use crate::credential_backend::{BackendError, PasswordOptions};
use crate::errors::Error;
use crate::fingerprint as fp_mod;
use crate::journal::{self, EntryId, Intent, Journal, Op, PlannedOp, Store};
use crate::secret::Secret;

// ─── Public types ─────────────────────────────────────────────────────────────

/// All runtime handles the engine needs to interact with credential stores.
pub struct Stores<'a> {
    pub backend: &'a dyn crate::credential_backend::CredentialBackend,
    /// e.g. "Claude Code-credentials"
    pub keychain_service: &'a str,
    /// e.g. $USER
    pub keychain_account: &'a str,
    /// Path to `~/.claude.json` (outside `~/.claude/`).
    pub claude_dot_json_path: &'a Path,
    /// Path to `~/.claude/settings.json`.
    pub settings_json_path: &'a Path,
    /// `$CLAUDE_CONFIG_DIR` if set, else `$HOME/.claude`.  Used for fallback detection.
    pub claude_dir: &'a Path,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SwitchOutcome {
    Applied { from: Option<String>, to: String },
    NoOp { reason: NoOpReason },
    RolledBack { cause: String },
}

#[derive(Debug, PartialEq, Eq)]
pub enum NoOpReason {
    AlreadyActive,
    NoContextsConfigured,
    ContextNotFound,
}

// ─── Internal types ───────────────────────────────────────────────────────────

/// Carries the planned store tag and the exact bytes written during apply.
///
/// For `ClaudeDotJson`, `expected_bytes` encodes `{"oauthAccount":…,"userID":…}`.
/// For `Keychain`, `expected_bytes` is the blob written to `Claude Code-credentials`.
/// Empty `expected_bytes` is treated as a no-op in `verify_apply` (backward-compat).
pub(crate) struct PlannedApply {
    pub store: Store,
    pub expected_bytes: Vec<u8>,
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Execute a context switch across all three credential stores.
///
/// Supports:
/// - API-key (plaintext `SecretRef`) — settings.json only.
/// - OAuth (cctx-mirror `SecretRef::Keychain`) — all three stores + mirror management.
///
/// # Errors
///
/// Returns `Error::SnapshotWriteFailed` when the pre-apply snapshot cannot be written.
/// Returns `Error::RollbackFailed` when rollback itself fails after an apply/verify error.
/// Returns `Error::ContextCorrupt` when an OAuth context is missing required identity fields.
#[allow(clippy::too_many_lines)]
pub fn execute_switch(
    current: &ContextsFile,
    target_name: &str,
    stores: &Stores<'_>,
    journal: &mut Journal,
    paths: &ConfigPaths,
) -> Result<SwitchOutcome, Error> {
    // ── Phase 1: Plan ─────────────────────────────────────────────────────────

    // Refuse before any mutation if the .credentials.json fallback file exists.
    if let claude_state::FallbackState::Present { path, .. } =
        claude_state::detect_credentials_json_fallback(stores.claude_dir)
    {
        return Err(Error::CredentialsJsonFallback { path });
    }

    let Some(target) = current.contexts.get(target_name) else {
        return Ok(SwitchOutcome::NoOp {
            reason: NoOpReason::ContextNotFound,
        });
    };

    match (&target.auth_mode, &target.secret_ref) {
        (AuthMode::ApiKey { .. }, SecretRef::Plaintext { .. }) => {
            execute_api_key_switch(target, target_name, current, stores, journal, paths)
        }
        (AuthMode::OAuth, _) => {
            execute_oauth_switch(target, target_name, current, stores, journal, paths)
        }
        (AuthMode::ApiKey { .. }, SecretRef::Keychain { .. }) => Err(Error::Unimplemented {
            what: "Keychain-backed API key switch lands in a later issue",
        }),
        (AuthMode::ApiKey { .. }, SecretRef::ClaudeCodeKeychain) => Err(Error::Unimplemented {
            what: "API-key with ClaudeCodeKeychain ref is not a valid combination",
        }),
    }
}

// ─── API-key switch path ──────────────────────────────────────────────────────

fn execute_api_key_switch(
    target: &Context,
    target_name: &str,
    current: &ContextsFile,
    stores: &Stores<'_>,
    journal: &mut Journal,
    paths: &ConfigPaths,
) -> Result<SwitchOutcome, Error> {
    let live_fp = compute_live_api_key_fingerprint(stores.settings_json_path)?;
    if live_fp.as_ref() == Some(&target.fingerprint) {
        return Ok(SwitchOutcome::NoOp {
            reason: NoOpReason::AlreadyActive,
        });
    }

    let planned_ops = vec![PlannedOp {
        store: Store::Settings,
        op: Op::Write,
    }];

    let from = live_fp.as_ref().and_then(|fp| {
        current
            .contexts
            .iter()
            .find(|(_, ctx)| &ctx.fingerprint == fp)
            .map(|(name, _)| name.clone())
    });

    let (entry_id, snap, snapshot_path) = plan_and_snapshot(
        target_name,
        from.clone(),
        planned_ops,
        stores,
        journal,
        paths,
    )?;

    let written_bytes = match apply_settings(target, stores.settings_json_path) {
        Ok(b) => b,
        Err(e) => {
            return rollback_and_report(
                entry_id,
                e.to_string(),
                &snap,
                stores,
                journal,
                snapshot_path,
            );
        }
    };

    let plans = [PlannedApply {
        store: Store::Settings,
        expected_bytes: written_bytes,
    }];
    if let Err(verify_err) = verify_apply(&plans, stores) {
        return rollback_and_report(
            entry_id,
            verify_err.to_string(),
            &snap,
            stores,
            journal,
            snapshot_path,
        );
    }

    journal.mark_completed(entry_id)?;
    Ok(SwitchOutcome::Applied {
        from,
        to: target_name.to_string(),
    })
}

// ─── OAuth switch path ────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn execute_oauth_switch(
    target: &Context,
    target_name: &str,
    current: &ContextsFile,
    stores: &Stores<'_>,
    journal: &mut Journal,
    paths: &ConfigPaths,
) -> Result<SwitchOutcome, Error> {
    // Idempotency: compare live OAuth fingerprint to target's.
    let live_fp = compute_live_oauth_fingerprint(
        stores.backend,
        stores.keychain_service,
        stores.keychain_account,
        stores.claude_dot_json_path,
    )?;
    if live_fp.as_ref() == Some(&target.fingerprint) {
        return Ok(SwitchOutcome::NoOp {
            reason: NoOpReason::AlreadyActive,
        });
    }

    // Resolve the mirror (source) keychain coordinates for the target blob.
    let (target_mirror_service, target_mirror_account) = match &target.secret_ref {
        SecretRef::Keychain { service, account } => (service.clone(), account.clone()),
        SecretRef::ClaudeCodeKeychain => {
            // Live fp didn't match → can't locate source blob via ClaudeCodeKeychain.
            return Err(Error::ContextCorrupt {
                name: target_name.to_string(),
                detail: "SecretRef::ClaudeCodeKeychain but live fingerprint does not match; \
                         cannot locate source blob"
                    .to_string(),
            });
        }
        SecretRef::Plaintext { .. } => {
            return Err(Error::Unimplemented {
                what: "OAuth context with Plaintext SecretRef is not a valid combination",
            });
        }
    };

    // Validate required identity fields for claude.json merge.
    let oauth_account =
        target
            .identity
            .oauth_account
            .as_ref()
            .ok_or_else(|| Error::ContextCorrupt {
                name: target_name.to_string(),
                detail: "OAuth context missing identity fields: oauth_account".to_string(),
            })?;
    let user_id = target
        .identity
        .user_id
        .as_ref()
        .ok_or_else(|| Error::ContextCorrupt {
            name: target_name.to_string(),
            detail: "OAuth context missing identity fields: user_id".to_string(),
        })?;

    let planned_ops = vec![
        PlannedOp {
            store: Store::Settings,
            op: Op::Write,
        },
        PlannedOp {
            store: Store::ClaudeDotJson,
            op: Op::Write,
        },
        PlannedOp {
            store: Store::Keychain,
            op: Op::Write,
        },
    ];

    // Determine "from" by matching live OAuth fingerprint to a known context.
    let from = live_fp.as_ref().and_then(|fp| {
        current
            .contexts
            .iter()
            .find(|(_, ctx)| &ctx.fingerprint == fp)
            .map(|(name, _)| name.clone())
    });

    let (entry_id, snap, snapshot_path) = plan_and_snapshot(
        target_name,
        from.clone(),
        planned_ops,
        stores,
        journal,
        paths,
    )?;

    // ── Phase 3: Apply (strict order: settings → claude.json → keychain) ─────

    // Step 1: settings.json — strip CLAUDE_CODE_* keys, unset API-key vars.
    let settings_bytes = match apply_oauth_settings(stores.settings_json_path) {
        Ok(b) => b,
        Err(e) => {
            return rollback_and_report(
                entry_id,
                e.to_string(),
                &snap,
                stores,
                journal,
                snapshot_path,
            );
        }
    };

    // Step 2: ~/.claude.json merge.
    if let Err(e) = claude_state::merge_and_save_claude_dot_json(
        stores.claude_dot_json_path,
        oauth_account,
        user_id.clone(),
    ) {
        return rollback_and_report(
            entry_id,
            e.to_string(),
            &snap,
            stores,
            journal,
            snapshot_path,
        );
    }

    // Step 3: Keychain — save current live blob to previous context's mirror, then write target.

    // 3a. Save current live blob into previously-active context's mirror item.
    if let Some(prev_name) = &from {
        let mirror_service = format!("cctx-oauth-{prev_name}");
        if let Err(e) = save_live_blob_to_mirror(
            stores.backend,
            stores.keychain_service,
            stores.keychain_account,
            &mirror_service,
            stores.keychain_account,
        ) {
            return rollback_and_report(
                entry_id,
                e.to_string(),
                &snap,
                stores,
                journal,
                snapshot_path,
            );
        }
    }

    // 3b. Read target blob from its mirror item.
    let target_blob = match stores
        .backend
        .get_generic_password(&target_mirror_service, &target_mirror_account)
    {
        Ok(b) => b,
        Err(BackendError::NotFound) => {
            let detail = format!(
                "mirror blob not found at ({target_mirror_service}, {target_mirror_account})"
            );
            return rollback_and_report(
                entry_id,
                Error::ContextCorrupt {
                    name: target_name.to_string(),
                    detail,
                }
                .to_string(),
                &snap,
                stores,
                journal,
                snapshot_path,
            );
        }
        Err(e) => {
            return rollback_and_report(
                entry_id,
                Error::KeychainBackend { source: e }.to_string(),
                &snap,
                stores,
                journal,
                snapshot_path,
            );
        }
    };

    // 3c. Write target blob into live Claude Code-credentials.
    if let Err(e) = stores.backend.set_generic_password(
        stores.keychain_service,
        stores.keychain_account,
        target_blob.expose(),
        PasswordOptions {
            update_if_exists: true,
            ..Default::default()
        },
    ) {
        return rollback_and_report(
            entry_id,
            Error::KeychainBackend { source: e }.to_string(),
            &snap,
            stores,
            journal,
            snapshot_path,
        );
    }

    // ── Phase 4: Verify ───────────────────────────────────────────────────────
    let cdj_verify_bytes = match build_claude_dot_json_verify_bytes(oauth_account, user_id) {
        Ok(b) => b,
        Err(e) => {
            return rollback_and_report(
                entry_id,
                e.to_string(),
                &snap,
                stores,
                journal,
                snapshot_path,
            );
        }
    };

    let verify_plans = [
        PlannedApply {
            store: Store::Settings,
            expected_bytes: settings_bytes,
        },
        PlannedApply {
            store: Store::ClaudeDotJson,
            expected_bytes: cdj_verify_bytes,
        },
        PlannedApply {
            store: Store::Keychain,
            expected_bytes: target_blob.expose().clone(),
        },
    ];
    if let Err(verify_err) = verify_apply(&verify_plans, stores) {
        return rollback_and_report(
            entry_id,
            verify_err.to_string(),
            &snap,
            stores,
            journal,
            snapshot_path,
        );
    }

    // ── Phase 5: Commit ───────────────────────────────────────────────────────
    journal.mark_completed(entry_id)?;
    Ok(SwitchOutcome::Applied {
        from,
        to: target_name.to_string(),
    })
}

// ─── verify_apply ─────────────────────────────────────────────────────────────

/// Post-apply verification: re-read each store and compare to the planned value.
///
/// - `Settings`: byte-compare re-read file to the buffer written.
/// - `ClaudeDotJson`: re-read `oauthAccount` + `userID`, serialize, byte-compare.
///   Empty `expected_bytes` → no-op (backward-compat).
/// - `Keychain`: `verify_password` on the live item.
///   Empty `expected_bytes` → no-op (backward-compat).
pub(crate) fn verify_apply(planned: &[PlannedApply], stores: &Stores<'_>) -> Result<(), Error> {
    for plan in planned {
        match plan.store {
            Store::Settings => {
                let actual = std::fs::read(stores.settings_json_path).map_err(Error::Io)?;
                if actual != plan.expected_bytes {
                    return Err(Error::VerifyFailed {
                        which_store: journal::Store::Settings,
                    });
                }
            }
            Store::ClaudeDotJson => {
                if plan.expected_bytes.is_empty() {
                    continue;
                }
                let current = claude_state::load_claude_dot_json(stores.claude_dot_json_path)?;
                let actual_bytes = build_claude_dot_json_verify_bytes_from_loaded(&current)?;
                if actual_bytes != plan.expected_bytes {
                    return Err(Error::VerifyFailed {
                        which_store: journal::Store::ClaudeDotJson,
                    });
                }
            }
            Store::Keychain => {
                if plan.expected_bytes.is_empty() {
                    continue;
                }
                stores
                    .backend
                    .verify_password(
                        stores.keychain_service,
                        stores.keychain_account,
                        &plan.expected_bytes,
                    )
                    .map_err(|_| Error::VerifyFailed {
                        which_store: journal::Store::Keychain,
                    })?;
            }
        }
    }
    Ok(())
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Shared plan + snapshot boilerplate.
///
/// Returns `(entry_id, snapshot, snapshot_path)` so callers can thread the real
/// path into `rollback_and_report` for accurate `ROLLBACK FAILED` diagnostics.
fn plan_and_snapshot(
    target_name: &str,
    from: Option<String>,
    planned_ops: Vec<PlannedOp>,
    stores: &Stores<'_>,
    journal: &mut Journal,
    paths: &ConfigPaths,
) -> Result<(EntryId, backup::Snapshot, std::path::PathBuf), Error> {
    std::fs::create_dir_all(&paths.backups_dir)
        .map_err(|e| Error::SnapshotWriteFailed { source: e })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ =
            std::fs::set_permissions(&paths.backups_dir, std::fs::Permissions::from_mode(0o700));
    }

    let snapshot_filename = format!(
        "{}.json",
        chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S%.9fZ")
    );
    let snapshot_path = paths.backups_dir.join(&snapshot_filename);

    let entry_id = journal.append(
        Intent::Switch,
        from,
        Some(target_name.to_string()),
        planned_ops,
        snapshot_path.clone(),
    )?;

    let snap = match backup::capture_snapshot(
        stores.backend,
        stores.keychain_service,
        stores.keychain_account,
        stores.claude_dot_json_path,
        stores.settings_json_path,
        &snapshot_path,
    ) {
        Ok(s) => s,
        Err(e) => {
            let _ = journal.mark_failed(entry_id, &e.to_string());
            return Err(Error::SnapshotWriteFailed {
                source: std::io::Error::other(e.to_string()),
            });
        }
    };

    Ok((entry_id, snap, snapshot_path))
}

fn rollback_and_report(
    entry_id: EntryId,
    cause: String,
    snap: &backup::Snapshot,
    stores: &Stores<'_>,
    journal: &mut Journal,
    snapshot_path: std::path::PathBuf,
) -> Result<SwitchOutcome, Error> {
    let rb = backup::restore_snapshot(
        snap,
        stores.backend,
        stores.keychain_service,
        stores.keychain_account,
        stores.claude_dot_json_path,
        stores.settings_json_path,
    );
    match rb {
        Ok(()) => {
            let _ = journal.mark_failed(entry_id, &cause);
            Ok(SwitchOutcome::RolledBack { cause })
        }
        Err(rb_err) => {
            eprintln!(
                "cctx: ROLLBACK FAILED — manual recovery required. \
                 Snapshot at: {path}. Rollback error: {rb_err}",
                path = snapshot_path.display()
            );
            let _ = journal.mark_failed(entry_id, "rollback failed");
            Err(Error::RollbackFailed {
                attempted_stores: vec![Store::Keychain, Store::ClaudeDotJson, Store::Settings],
                path: snapshot_path,
            })
        }
    }
}

/// Compute the fingerprint of the currently-live API key, if any.
fn compute_live_api_key_fingerprint(settings_path: &Path) -> Result<Option<Fingerprint>, Error> {
    claude_state::load_settings_api_key(settings_path)
        .map(|opt| opt.map(|key| Fingerprint::from_api_key(&key)))
}

/// Compute the OAuth fingerprint from the live `Claude Code-credentials` blob + `~/.claude.json`.
///
/// Returns `None` if the Keychain item is absent, the blob is unparseable, or
/// `~/.claude.json` is missing `userID`/`accountUuid`.
fn compute_live_oauth_fingerprint(
    backend: &dyn crate::credential_backend::CredentialBackend,
    keychain_service: &str,
    keychain_account: &str,
    claude_dot_json_path: &Path,
) -> Result<Option<Fingerprint>, Error> {
    let blob = match backend.get_generic_password(keychain_service, keychain_account) {
        Ok(b) => b,
        Err(BackendError::NotFound) => return Ok(None),
        Err(e) => return Err(Error::KeychainBackend { source: e }),
    };

    let envelope: claude_state::KeychainBlobEnvelope = match serde_json::from_slice(blob.expose()) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };

    let cdj = claude_state::load_claude_dot_json(claude_dot_json_path)?;
    let (Some(user_id), Some(account_uuid)) = (
        cdj.user_id.as_deref(),
        cdj.oauth_account.as_ref().map(|a| a.account_uuid.as_str()),
    ) else {
        return Ok(None);
    };

    Ok(Some(fp_mod::compute_oauth(
        user_id,
        account_uuid,
        &envelope.claude_ai_oauth.access_token,
    )))
}

/// Build the settings.json env patch for an API-key context.
fn build_settings_patch(
    target: &Context,
) -> Result<BTreeMap<String, Option<Secret<String>>>, Error> {
    let (AuthMode::ApiKey { base_url }, SecretRef::Plaintext { value: key }) =
        (&target.auth_mode, &target.secret_ref)
    else {
        return Err(Error::Unimplemented {
            what: "non-plaintext API key patch not supported",
        });
    };

    let mut patch: BTreeMap<String, Option<Secret<String>>> = BTreeMap::new();
    patch.insert("ANTHROPIC_API_KEY".to_string(), Some(key.clone()));
    patch.insert("ANTHROPIC_AUTH_TOKEN".to_string(), None);
    if let Some(url) = base_url {
        patch.insert(
            "ANTHROPIC_BASE_URL".to_string(),
            Some(Secret::new(url.to_string())),
        );
    } else {
        patch.insert("ANTHROPIC_BASE_URL".to_string(), None);
    }
    Ok(patch)
}

fn apply_settings(target: &Context, settings_path: &Path) -> Result<Vec<u8>, Error> {
    let patch = build_settings_patch(target)?;
    claude_state::save_settings_env_returning_bytes(settings_path, patch, AuthModeHint::ApiKey)
}

/// Apply the settings.json write for an OAuth context.
///
/// Unsets `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, and
/// strips all `CLAUDE_CODE_*` keys (arch §2, issue #49659).
fn apply_oauth_settings(settings_path: &Path) -> Result<Vec<u8>, Error> {
    let mut patch: BTreeMap<String, Option<Secret<String>>> = BTreeMap::new();
    patch.insert("ANTHROPIC_API_KEY".to_string(), None);
    patch.insert("ANTHROPIC_AUTH_TOKEN".to_string(), None);
    patch.insert("ANTHROPIC_BASE_URL".to_string(), None);
    claude_state::save_settings_env_returning_bytes(settings_path, patch, AuthModeHint::OAuth)
}

/// Save the current live `Claude Code-credentials` blob into a cctx-owned mirror item.
///
/// Silently succeeds if the live blob is absent (first-ever switch, nothing to preserve).
fn save_live_blob_to_mirror(
    backend: &dyn crate::credential_backend::CredentialBackend,
    live_service: &str,
    live_account: &str,
    mirror_service: &str,
    mirror_account: &str,
) -> Result<(), Error> {
    let live_blob = match backend.get_generic_password(live_service, live_account) {
        Ok(b) => b,
        Err(BackendError::NotFound) => return Ok(()),
        Err(e) => return Err(Error::KeychainBackend { source: e }),
    };

    backend
        .set_generic_password(
            mirror_service,
            mirror_account,
            live_blob.expose(),
            PasswordOptions {
                update_if_exists: true,
                ..Default::default()
            },
        )
        .map_err(|e| Error::KeychainBackend { source: e })
}

/// Build the canonical JSON bytes used to verify `ClaudeDotJson` after merge.
///
/// Format: `{"oauthAccount":<account>,"userID":<user_id>}` (pretty-printed).
fn build_claude_dot_json_verify_bytes(
    oauth_account: &claude_state::OAuthAccount,
    user_id: &str,
) -> Result<Vec<u8>, Error> {
    let v = serde_json::json!({
        "oauthAccount": serde_json::to_value(oauth_account)?,
        "userID": user_id,
    });
    Ok(serde_json::to_vec_pretty(&v)?)
}

/// Same as above but reads from an already-loaded `ClaudeDotJson`.
fn build_claude_dot_json_verify_bytes_from_loaded(
    cdj: &claude_state::ClaudeDotJson,
) -> Result<Vec<u8>, Error> {
    let account = cdj.oauth_account.as_ref().ok_or(Error::VerifyFailed {
        which_store: Store::ClaudeDotJson,
    })?;
    let user_id = cdj.user_id.as_deref().ok_or(Error::VerifyFailed {
        which_store: Store::ClaudeDotJson,
    })?;
    build_claude_dot_json_verify_bytes(account, user_id)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claude_state::OAuthAccount;
    use crate::config::ContextsFile;
    use crate::context::{AuthMode, Context, Fingerprint, IdentityMetadata};
    use crate::credential_backend::{
        BackendError, CredentialBackend, FaultInjectingBackend, FaultMethod, InMemoryBackend,
    };
    use crate::journal::{EntryStatus, Journal};
    use crate::secret::Secret;
    use indexmap::IndexMap;
    use serde_json::Map;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_api_key_context(name: &str, api_key: &str) -> Context {
        let key = Secret::new(api_key.to_string());
        let fp = Fingerprint::from_api_key(&key);
        Context {
            name: name.to_string(),
            auth_mode: AuthMode::ApiKey { base_url: None },
            identity: IdentityMetadata::default(),
            fingerprint: fp,
            created_at: chrono::Utc::now(),
            secret_ref: SecretRef::Plaintext { value: key },
        }
    }

    fn make_oauth_account(uuid: &str, email: &str) -> OAuthAccount {
        OAuthAccount {
            account_uuid: uuid.to_string(),
            email_address: email.to_string(),
            organization_uuid: None,
            other: Map::new(),
        }
    }

    /// Build a test OAuth context + its keychain blob.
    fn make_oauth_context_with_blob(
        name: &str,
        user_id: &str,
        account: OAuthAccount,
        blob: &[u8],
    ) -> Context {
        let envelope: crate::claude_state::KeychainBlobEnvelope =
            serde_json::from_slice(blob).expect("test blob must be valid JSON");
        let fp = crate::fingerprint::compute_oauth(
            user_id,
            &account.account_uuid,
            &envelope.claude_ai_oauth.access_token,
        );
        Context {
            name: name.to_string(),
            auth_mode: AuthMode::OAuth,
            identity: IdentityMetadata {
                user_id: Some(user_id.to_string()),
                account_uuid: Some(account.account_uuid.clone()),
                email_hint: Some("t***@example.com".to_string()),
                label: None,
                oauth_account: Some(account),
            },
            fingerprint: fp,
            created_at: chrono::Utc::now(),
            secret_ref: SecretRef::Keychain {
                service: format!("cctx-oauth-{name}"),
                account: "testuser".to_string(),
            },
        }
    }

    /// Build a minimal valid Keychain blob JSON for the given access token.
    fn test_keychain_blob(access_token: &str) -> Vec<u8> {
        serde_json::json!({
            "claudeAiOauth": {
                "accessToken": access_token,
                "refreshToken": "refresh-token",
                "expiresAt": 9_999_999_999_i64
            }
        })
        .to_string()
        .into_bytes()
    }

    fn contexts_file_with(contexts: Vec<Context>) -> ContextsFile {
        let mut map = IndexMap::new();
        for ctx in contexts {
            map.insert(ctx.name.clone(), ctx);
        }
        ContextsFile {
            version: 1,
            contexts: map,
        }
    }

    struct TestEnv {
        _cctx_dir: TempDir,
        _claude_dir: TempDir,
        pub paths: ConfigPaths,
        pub settings_path: PathBuf,
        pub claude_dot_json_path: PathBuf,
        pub claude_dir: PathBuf,
    }

    fn setup_test_env() -> TestEnv {
        let cctx_dir = TempDir::new().unwrap();
        let claude_dir = TempDir::new().unwrap();
        let paths = ConfigPaths {
            backups_dir: cctx_dir.path().join("backups"),
            journal_file: cctx_dir.path().join("journal.log"),
            lock_file: cctx_dir.path().join(".lock"),
            contexts_file: cctx_dir.path().join("contexts.yaml"),
            config_dir: cctx_dir.path().to_path_buf(),
        };
        let settings_path = claude_dir.path().join("settings.json");
        let claude_dot_json_path = claude_dir.path().join(".claude.json");
        let claude_dir_path = claude_dir.path().to_path_buf();
        TestEnv {
            _cctx_dir: cctx_dir,
            _claude_dir: claude_dir,
            paths,
            settings_path,
            claude_dot_json_path,
            claude_dir: claude_dir_path,
        }
    }

    fn write_settings_with_key(path: &Path, api_key: &str) {
        let json = format!(r#"{{"env":{{"ANTHROPIC_API_KEY":"{api_key}"}}}}"#);
        std::fs::write(path, json).unwrap();
    }

    fn make_stores<'a>(backend: &'a InMemoryBackend, env: &'a TestEnv) -> Stores<'a> {
        Stores {
            backend,
            keychain_service: "Claude Code-credentials",
            keychain_account: "testuser",
            claude_dot_json_path: &env.claude_dot_json_path,
            settings_json_path: &env.settings_path,
            claude_dir: &env.claude_dir,
        }
    }

    fn seed_live_oauth_state(
        backend: &InMemoryBackend,
        env: &TestEnv,
        blob: &[u8],
        user_id: &str,
        account: &OAuthAccount,
    ) {
        backend
            .set_generic_password(
                "Claude Code-credentials",
                "testuser",
                blob,
                PasswordOptions::default(),
            )
            .unwrap();
        let cdj = serde_json::json!({
            "oauthAccount": serde_json::to_value(account).unwrap(),
            "userID": user_id,
        });
        std::fs::write(
            &env.claude_dot_json_path,
            serde_json::to_vec_pretty(&cdj).unwrap(),
        )
        .unwrap();
    }

    // ── API-key path (regression) ─────────────────────────────────────────────

    #[test]
    fn already_active_returns_noop() {
        let env = setup_test_env();
        let api_key = "sk-ant-already-active";
        write_settings_with_key(&env.settings_path, api_key);

        let ctx = make_api_key_context("work", api_key);
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert_eq!(
            outcome,
            SwitchOutcome::NoOp {
                reason: NoOpReason::AlreadyActive
            }
        );
    }

    #[test]
    fn unknown_target_returns_context_not_found() {
        let env = setup_test_env();
        let cf = contexts_file_with(vec![
            make_api_key_context("a", "sk-ant-a"),
            make_api_key_context("b", "sk-ant-b"),
        ]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "c", &stores, &mut journal, &env.paths).unwrap();
        assert_eq!(
            outcome,
            SwitchOutcome::NoOp {
                reason: NoOpReason::ContextNotFound
            }
        );
    }

    #[test]
    fn applies_api_key_switch_end_to_end() {
        let env = setup_test_env();
        let ctx_a = make_api_key_context("work", "sk-ant-key-work");
        let cf = contexts_file_with(vec![ctx_a]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert!(
            matches!(outcome, SwitchOutcome::Applied { ref to, .. } if to == "work"),
            "expected Applied, got {outcome:?}"
        );

        let settings = claude_state::load_settings(&env.settings_path).unwrap();
        assert_eq!(
            settings["env"]["ANTHROPIC_API_KEY"], "sk-ant-key-work",
            "settings.json must contain the new API key"
        );

        let all = journal.read_all().unwrap();
        assert_eq!(all.len(), 1);
        assert!(
            matches!(all[0].status, EntryStatus::Completed { .. }),
            "journal entry must be Completed"
        );
    }

    #[test]
    fn api_key_switch_still_works_end_to_end() {
        let env = setup_test_env();
        let ctx = make_api_key_context("personal", "sk-ant-regression-key");
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "personal", &stores, &mut journal, &env.paths).unwrap();
        assert!(matches!(outcome, SwitchOutcome::Applied { .. }));

        let settings = claude_state::load_settings(&env.settings_path).unwrap();
        assert_eq!(
            settings["env"]["ANTHROPIC_API_KEY"],
            "sk-ant-regression-key"
        );
        assert!(
            settings["env"]
                .get("ANTHROPIC_AUTH_TOKEN")
                .map_or(true, serde_json::Value::is_null),
            "ANTHROPIC_AUTH_TOKEN must be absent"
        );
    }

    #[test]
    fn journal_records_pending_then_completed_on_success() {
        let env = setup_test_env();
        let ctx = make_api_key_context("work", "sk-ant-journal-test");
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert!(matches!(outcome, SwitchOutcome::Applied { .. }));

        let uncommitted = journal.find_uncommitted().unwrap();
        assert!(
            uncommitted.is_empty(),
            "no uncommitted entries after success"
        );
    }

    #[test]
    fn snapshot_taken_before_apply() {
        let env = setup_test_env();
        let ctx = make_api_key_context("work", "sk-ant-snap-test");
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();

        let backups: Vec<_> = std::fs::read_dir(&env.paths.backups_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(backups.len(), 1, "exactly one snapshot file should exist");
        assert!(
            backups[0].file_name().to_string_lossy().ends_with(".json"),
            "snapshot file should be .json"
        );
    }

    #[test]
    fn idempotent_second_invocation_is_noop() {
        let env = setup_test_env();
        let ctx = make_api_key_context("work", "sk-ant-idempotent");
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let first = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert!(matches!(first, SwitchOutcome::Applied { .. }));

        let second = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert_eq!(
            second,
            SwitchOutcome::NoOp {
                reason: NoOpReason::AlreadyActive
            }
        );

        let backups: Vec<_> = std::fs::read_dir(&env.paths.backups_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(backups.len(), 1, "only one snapshot from the first switch");
    }

    #[test]
    fn from_field_is_none_when_no_prior_key() {
        let env = setup_test_env();
        let ctx = make_api_key_context("work", "sk-ant-fresh");
        let cf = contexts_file_with(vec![ctx]);

        let backend = InMemoryBackend::new();
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "work", &stores, &mut journal, &env.paths).unwrap();
        assert!(
            matches!(outcome, SwitchOutcome::Applied { from: None, .. }),
            "from must be None when no prior context active"
        );
    }

    // ── verify_apply unit tests ───────────────────────────────────────────────

    #[test]
    fn verify_apply_empty_plan_ok() {
        let env = setup_test_env();
        let backend = InMemoryBackend::new();
        let stores = make_stores(&backend, &env);
        verify_apply(&[], &stores).unwrap();
    }

    #[test]
    fn verify_apply_settings_match_ok() {
        let env = setup_test_env();
        let backend = InMemoryBackend::new();
        let stores = make_stores(&backend, &env);

        let content = b"{\"env\":{\"ANTHROPIC_API_KEY\":\"sk-ant-test\"}}";
        std::fs::write(&env.settings_path, content).unwrap();

        let plan = PlannedApply {
            store: Store::Settings,
            expected_bytes: content.to_vec(),
        };
        verify_apply(&[plan], &stores).unwrap();
    }

    #[test]
    fn verify_apply_settings_mismatch_errors() {
        let env = setup_test_env();
        let backend = InMemoryBackend::new();
        let stores = make_stores(&backend, &env);

        std::fs::write(
            &env.settings_path,
            b"{\"env\":{\"ANTHROPIC_API_KEY\":\"sk-ant-actual\"}}",
        )
        .unwrap();

        let plan = PlannedApply {
            store: Store::Settings,
            expected_bytes: b"{\"env\":{\"ANTHROPIC_API_KEY\":\"sk-ant-expected\"}}".to_vec(),
        };
        let err = verify_apply(&[plan], &stores).unwrap_err();
        assert!(
            matches!(
                err,
                Error::VerifyFailed {
                    which_store: Store::Settings
                }
            ),
            "expected VerifyFailed(Settings), got: {err:?}"
        );
    }

    #[test]
    fn verify_apply_keychain_empty_bytes_is_noop() {
        let env = setup_test_env();
        let backend = InMemoryBackend::new();
        let stores = make_stores(&backend, &env);
        let plan = PlannedApply {
            store: Store::Keychain,
            expected_bytes: vec![],
        };
        verify_apply(&[plan], &stores).unwrap();
    }

    #[test]
    fn verify_apply_claude_dot_json_empty_bytes_is_noop() {
        let env = setup_test_env();
        let backend = InMemoryBackend::new();
        let stores = make_stores(&backend, &env);
        let plan = PlannedApply {
            store: Store::ClaudeDotJson,
            expected_bytes: vec![],
        };
        verify_apply(&[plan], &stores).unwrap();
    }

    #[test]
    fn verify_apply_keychain_match_ok() {
        let env = setup_test_env();
        let backend = InMemoryBackend::new();
        backend
            .set_generic_password(
                "Claude Code-credentials",
                "testuser",
                b"blob-bytes",
                PasswordOptions::default(),
            )
            .unwrap();
        let stores = make_stores(&backend, &env);
        let plan = PlannedApply {
            store: Store::Keychain,
            expected_bytes: b"blob-bytes".to_vec(),
        };
        verify_apply(&[plan], &stores).unwrap();
    }

    #[test]
    fn verify_apply_keychain_mismatch_errors() {
        let env = setup_test_env();
        let backend = InMemoryBackend::new();
        backend
            .set_generic_password(
                "Claude Code-credentials",
                "testuser",
                b"actual-blob",
                PasswordOptions::default(),
            )
            .unwrap();
        let stores = make_stores(&backend, &env);
        let plan = PlannedApply {
            store: Store::Keychain,
            expected_bytes: b"expected-blob".to_vec(),
        };
        let err = verify_apply(&[plan], &stores).unwrap_err();
        assert!(
            matches!(
                err,
                Error::VerifyFailed {
                    which_store: Store::Keychain
                }
            ),
            "expected VerifyFailed(Keychain), got: {err:?}"
        );
    }

    // ── OAuth switch tests ────────────────────────────────────────────────────

    #[test]
    fn oauth_switch_via_in_memory_backend_end_to_end() {
        let env = setup_test_env();
        let backend = InMemoryBackend::new();

        let account = make_oauth_account("uuid-test-1234", "test@example.com");
        let blob = test_keychain_blob("access-token-target");
        let target_ctx = make_oauth_context_with_blob("personal", "user-id-123", account, &blob);

        // Pre-seed the mirror item.
        backend
            .set_generic_password(
                "cctx-oauth-personal",
                "testuser",
                &blob,
                PasswordOptions::default(),
            )
            .unwrap();

        let cf = contexts_file_with(vec![target_ctx]);
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "personal", &stores, &mut journal, &env.paths).unwrap();
        assert!(
            matches!(outcome, SwitchOutcome::Applied { ref to, .. } if to == "personal"),
            "expected Applied, got {outcome:?}"
        );

        // Live Keychain has the target blob.
        let live = backend
            .get_generic_password("Claude Code-credentials", "testuser")
            .unwrap();
        assert_eq!(live.expose(), blob.as_slice());

        // ~/.claude.json has merged oauthAccount + userID.
        let cdj = claude_state::load_claude_dot_json(&env.claude_dot_json_path).unwrap();
        assert_eq!(cdj.user_id.as_deref(), Some("user-id-123"));
        assert!(cdj.oauth_account.is_some());
        assert_eq!(cdj.oauth_account.unwrap().account_uuid, "uuid-test-1234");

        // settings.json has no API-key vars.
        let settings = claude_state::load_settings(&env.settings_path).unwrap();
        assert!(
            settings["env"]
                .get("ANTHROPIC_API_KEY")
                .map_or(true, serde_json::Value::is_null),
            "ANTHROPIC_API_KEY must be absent after OAuth switch"
        );

        // Journal completed.
        let all = journal.read_all().unwrap();
        assert_eq!(all.len(), 1);
        assert!(
            matches!(all[0].status, EntryStatus::Completed { .. }),
            "journal entry must be Completed"
        );
    }

    #[test]
    fn oauth_switch_saves_previous_context_blob_to_mirror() {
        // Verifies the "refreshed tokens survive switch-away" invariant from arch §2:
        // the live blob (with fresh tokens) is written to ctx-a's mirror BEFORE ctx-b's
        // blob goes live, so a later switch back to ctx-a picks up the refreshed tokens.
        let env = setup_test_env();
        let backend = InMemoryBackend::new();

        let account_a = make_oauth_account("uuid-a", "a@example.com");
        let account_b = make_oauth_account("uuid-b", "b@example.com");

        // ctx-a: two blobs with the SAME accessToken (same fingerprint) but different
        // refreshToken — simulates what happens after an hourly token refresh.
        let blob_a_stale = serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "token-ctx-a",
                "refreshToken": "stale-refresh",
                "expiresAt": 1000_i64
            }
        })
        .to_string()
        .into_bytes();
        let blob_a_fresh = serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "token-ctx-a",
                "refreshToken": "fresh-refresh",
                "expiresAt": 9_999_999_999_i64
            }
        })
        .to_string()
        .into_bytes();

        let blob_b = test_keychain_blob("token-context-b");

        // Build ctx-a using the stale blob to establish the fingerprint.
        let ctx_a =
            make_oauth_context_with_blob("ctx-a", "user-a", account_a.clone(), &blob_a_stale);
        let ctx_b = make_oauth_context_with_blob("ctx-b", "user-b", account_b, &blob_b);

        // Live keychain holds blob_a_fresh (refreshed since last cctx run).
        // claude.json has user-a + uuid-a so fingerprint matches ctx-a (same accessToken).
        seed_live_oauth_state(&backend, &env, &blob_a_fresh, "user-a", &account_a);

        // ctx-a's mirror holds the stale blob (pre-refresh).
        backend
            .set_generic_password(
                "cctx-oauth-ctx-a",
                "testuser",
                &blob_a_stale,
                PasswordOptions::default(),
            )
            .unwrap();
        // ctx-b mirror pre-seeded.
        backend
            .set_generic_password(
                "cctx-oauth-ctx-b",
                "testuser",
                &blob_b,
                PasswordOptions::default(),
            )
            .unwrap();

        let cf = contexts_file_with(vec![ctx_a, ctx_b]);
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "ctx-b", &stores, &mut journal, &env.paths).unwrap();
        assert!(
            matches!(outcome, SwitchOutcome::Applied { ref to, .. } if to == "ctx-b"),
            "expected Applied to ctx-b, got {outcome:?}"
        );

        // ctx-a's mirror must now hold blob_a_fresh (NOT the stale one).
        // This confirms that the live blob's refreshed tokens were preserved.
        let mirror_a = backend
            .get_generic_password("cctx-oauth-ctx-a", "testuser")
            .unwrap();
        assert_eq!(
            mirror_a.expose(),
            blob_a_fresh.as_slice(),
            "mirror for ctx-a must hold the FRESH live blob, not the stale one"
        );

        // ctx-b is now the live credential.
        let live = backend
            .get_generic_password("Claude Code-credentials", "testuser")
            .unwrap();
        assert_eq!(live.expose(), blob_b.as_slice());
    }

    #[test]
    fn oauth_switch_rolls_back_on_keychain_set_failure() {
        let env = setup_test_env();
        let inner = InMemoryBackend::new();

        let account = make_oauth_account("uuid-rb", "rb@example.com");
        let blob = test_keychain_blob("token-rollback");
        let target_ctx = make_oauth_context_with_blob("personal", "user-rb", account, &blob);

        // Pre-seed mirror.
        inner
            .set_generic_password(
                "cctx-oauth-personal",
                "testuser",
                &blob,
                PasswordOptions::default(),
            )
            .unwrap();
        // Pre-seed live keychain so snapshot captures it.
        let original_blob = b"original-live-blob";
        inner
            .set_generic_password(
                "Claude Code-credentials",
                "testuser",
                original_blob,
                PasswordOptions::default(),
            )
            .unwrap();
        std::fs::write(&env.settings_path, r#"{"env":{}}"#).unwrap();

        // First Set = save_live_blob_to_mirror (no previous context found, so skipped);
        // second Set = writing Claude Code-credentials (fail this one).
        // Since there's no previous context active (no claude.json), save_live_blob_to_mirror
        // for "from" is skipped. So the first Set on Claude Code-credentials is #1.
        let fault =
            FaultInjectingBackend::new(&inner, FaultMethod::Set, 1, BackendError::AccessDenied);

        let cf = contexts_file_with(vec![target_ctx]);
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = Stores {
            backend: &fault,
            keychain_service: "Claude Code-credentials",
            keychain_account: "testuser",
            claude_dot_json_path: &env.claude_dot_json_path,
            settings_json_path: &env.settings_path,
            claude_dir: &env.claude_dir,
        };

        let outcome = execute_switch(&cf, "personal", &stores, &mut journal, &env.paths).unwrap();
        assert!(
            matches!(outcome, SwitchOutcome::RolledBack { .. }),
            "expected RolledBack on keychain Set failure, got: {outcome:?}"
        );

        // After rollback, Claude Code-credentials must be restored.
        let restored = inner
            .get_generic_password("Claude Code-credentials", "testuser")
            .unwrap();
        assert_eq!(
            restored.expose(),
            original_blob,
            "rollback must restore original keychain blob"
        );
    }

    #[test]
    fn oauth_switch_idempotent_via_keychain_mirror() {
        // When the live OAuth fingerprint already matches the target, it's a NoOp.
        let env = setup_test_env();
        let backend = InMemoryBackend::new();

        let account = make_oauth_account("uuid-idem", "idem@example.com");
        let blob = test_keychain_blob("token-idem");
        let target_ctx =
            make_oauth_context_with_blob("personal", "user-idem", account.clone(), &blob);

        // Make the target already active.
        seed_live_oauth_state(&backend, &env, &blob, "user-idem", &account);
        // Also pre-seed the mirror (needed for non-idempotent path, but not used here).
        backend
            .set_generic_password(
                "cctx-oauth-personal",
                "testuser",
                &blob,
                PasswordOptions::default(),
            )
            .unwrap();

        let cf = contexts_file_with(vec![target_ctx]);
        let mut journal = Journal::open(&env.paths.journal_file).unwrap();
        let stores = make_stores(&backend, &env);

        let outcome = execute_switch(&cf, "personal", &stores, &mut journal, &env.paths).unwrap();
        assert_eq!(
            outcome,
            SwitchOutcome::NoOp {
                reason: NoOpReason::AlreadyActive
            }
        );
    }
}
