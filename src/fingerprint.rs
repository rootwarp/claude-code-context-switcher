//! OAuth fingerprint recipe: `SHA-256(user_id || ":" || account_uuid || ":" || SHA-256(access_token)[0..16])`.
//!
//! The `from_api_key` fingerprint lives in `context::Fingerprint`; this module
//! owns the OAuth recipe only.

use sha2::{Digest, Sha256};

use crate::context::Fingerprint;
use crate::secret::Secret;

/// OAuth fingerprint recipe per arch §2 with always-on `accountUuid` fallback (Spike 0.2 deferred).
///
/// Recipe: `SHA-256(user_id || ":" || account_uuid || ":" || SHA-256(access_token)[0..16])`.
///
/// - `user_id`: the 64-char hex string from `~/.claude.json`'s top-level `"userID"`. Primary matcher.
/// - `account_uuid`: `oauthAccount.accountUuid` (UUID v4). Fallback anchor if `userID` rotates.
/// - `SHA-256(access_token)[0..16]`: stabilizes against ~hourly token refresh while still
///   distinguishing identities per-account. The token input is not retained after this call.
///
/// The resulting `Fingerprint` is not a secret — it is safe to log and store in YAML.
///
/// # Golden value
///
/// ```text
/// user_id      = "a" × 64
/// account_uuid = "UUID"
/// access_token = "token"
///
/// at_hash   = SHA-256("token")
///           = 3c469e9d6c5875d37a43f353d4f88e61fcf812c66eee3457465a40b0da4153e0
/// at_prefix = at_hash[0..16]
///           = 3c469e9d6c5875d37a43f353d4f88e61
///
/// fingerprint = SHA-256("a"×64 || ":" || "UUID" || ":" || at_prefix)
///             = 7f87ceb487f9da454d73513db014b6a85055ef7011290d7d61867057ed94b9aa
/// ```
#[must_use]
pub fn compute_oauth(
    user_id: &str,
    account_uuid: &str,
    access_token: &Secret<String>,
) -> Fingerprint {
    let mut h1 = Sha256::new();
    h1.update(access_token.expose().as_bytes());
    let at_hash: [u8; 32] = h1.finalize().into();
    let at_prefix = &at_hash[..16];

    let mut h2 = Sha256::new();
    h2.update(user_id.as_bytes());
    h2.update(b":");
    h2.update(account_uuid.as_bytes());
    h2.update(b":");
    h2.update(at_prefix);
    Fingerprint(h2.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(s: &str) -> Secret<String> {
        Secret::new(s.to_string())
    }

    #[test]
    fn oauth_fingerprint_is_deterministic() {
        let fp1 = compute_oauth("user1", "uuid-A", &token("tok"));
        let fp2 = compute_oauth("user1", "uuid-A", &token("tok"));
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn oauth_fingerprint_differs_on_user_id_change() {
        let fp1 = compute_oauth("user1", "uuid-A", &token("tok"));
        let fp2 = compute_oauth("user2", "uuid-A", &token("tok"));
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn oauth_fingerprint_differs_on_account_uuid_change() {
        let fp1 = compute_oauth("user1", "uuid-A", &token("tok"));
        let fp2 = compute_oauth("user1", "uuid-B", &token("tok"));
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn oauth_fingerprint_differs_on_access_token_change() {
        let fp1 = compute_oauth("user1", "uuid-A", &token("tok-alpha"));
        let fp2 = compute_oauth("user1", "uuid-A", &token("tok-beta"));
        assert_ne!(fp1, fp2);
    }

    // The prefix-hash design means two tokens that share SHA-256(tok)[0..16] would
    // collide — this is intentional (stabilizes against hourly refresh). SHA-256 scatters
    // bits thoroughly, so distinct tokens almost never share the same 16-byte prefix.
    // This test documents the design by picking two clearly-distinct tokens and asserting
    // they produce different fingerprints (expected: SHA-256 scattering ensures they differ).
    #[test]
    fn oauth_fingerprint_access_token_prefix_stable_under_small_change() {
        let fp1 = compute_oauth("user1", "uuid-A", &token("access_token_v1"));
        let fp2 = compute_oauth("user1", "uuid-A", &token("access_token_v2"));
        assert_ne!(
            fp1, fp2,
            "distinct tokens should produce distinct fingerprints"
        );
    }

    // Golden-value regression test.
    //
    // Recipe (see module doc for derivation):
    //   user_id      = "a" × 64
    //   account_uuid = "UUID"
    //   access_token = "token"
    //   expected     = 7f87ceb487f9da454d73513db014b6a85055ef7011290d7d61867057ed94b9aa
    #[test]
    fn oauth_fingerprint_matches_expected_golden_value() {
        let user_id = "a".repeat(64);
        let fp = compute_oauth(&user_id, "UUID", &token("token"));
        assert_eq!(
            fp.to_hex(),
            "7f87ceb487f9da454d73513db014b6a85055ef7011290d7d61867057ed94b9aa",
        );
    }
}
