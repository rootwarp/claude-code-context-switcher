//! Golden-fixture integration tests for `claude_state::merge_and_save_claude_dot_json`.

use std::fs;
use tempfile::TempDir;

use claude_code_context_switcher::claude_state::{
    load_claude_dot_json, merge_and_save_claude_dot_json, OAuthAccount,
};
use serde_json::{Map, Value};

fn new_incoming_account() -> OAuthAccount {
    OAuthAccount {
        account_uuid: "cccccccc-3333-3333-3333-cccccccccccc".to_string(),
        email_address: "new-user@example.com".to_string(),
        organization_uuid: Some("dddddddd-4444-4444-4444-dddddddddddd".to_string()),
        other: {
            let mut m = Map::new();
            m.insert("hasExtraUsageEnabled".to_string(), Value::Bool(false));
            m.insert("billingType".to_string(), Value::String("free".to_string()));
            m.insert(
                "displayName".to_string(),
                Value::String("New User".to_string()),
            );
            m.insert(
                "organizationRole".to_string(),
                Value::String("member".to_string()),
            );
            m.insert("workspaceRole".to_string(), Value::Null);
            m.insert(
                "organizationName".to_string(),
                Value::String("New Org".to_string()),
            );
            m
        },
    }
}

/// Standard identity used by the golden-corpus parametric test.
fn merge_identity_account() -> OAuthAccount {
    OAuthAccount {
        account_uuid: "aaaa-bbbb-cccc-dddd".to_string(),
        email_address: "merged@test.example".to_string(),
        organization_uuid: Some("org-1234".to_string()),
        other: Map::new(),
    }
}

const MERGE_USER_ID: &str = "test-uid-merge";

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/claude_dot_json")
        .join(name)
}

/// Parametric golden-corpus test: for every `*.json` that has a `*.expected.json` sibling,
/// merge with the standard test identity and assert JSON-value equality (key-order agnostic).
#[test]
fn merge_golden_corpus() {
    let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/claude_dot_json");

    let mut pairs_tested = 0u32;

    let mut entries: Vec<_> = fs::read_dir(&fixture_dir)
        .expect("fixture dir must exist")
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy();
        if stem.ends_with(".expected") {
            continue;
        }
        let expected_path = fixture_dir.join(format!("{stem}.expected.json"));
        if !expected_path.exists() {
            continue;
        }

        let dir = TempDir::new().unwrap();
        let work = dir.path().join("state.json");
        fs::copy(&path, &work).unwrap();

        merge_and_save_claude_dot_json(&work, &merge_identity_account(), MERGE_USER_ID.to_string())
            .unwrap_or_else(|e| panic!("merge failed for {stem}: {e}"));

        let result: Value =
            serde_json::from_str(&fs::read_to_string(&work).unwrap()).unwrap();
        let expected: Value =
            serde_json::from_str(&fs::read_to_string(&expected_path).unwrap()).unwrap();

        assert_eq!(result, expected, "fixture '{stem}' did not match expected after merge");
        pairs_tested += 1;
    }

    assert!(pairs_tested >= 5, "expected at least 5 fixture pairs, found {pairs_tested}");
}

/// Preserved keys from the full-sample fixture are all present in the output.
#[test]
fn merge_preserves_projects_and_counters() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(".claude.json");
    fs::copy(fixture("full-sample.json"), &path).unwrap();

    merge_and_save_claude_dot_json(&path, &new_incoming_account(), "uid".to_string()).unwrap();

    let result: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert!(
        result.get("projects").is_some(),
        "projects must be preserved"
    );
    assert_eq!(result["numStartups"], 42, "numStartups must be preserved");
    assert_eq!(
        result["promptQueueUseCount"], 7,
        "promptQueueUseCount must be preserved"
    );
    assert!(
        result.get("tipsHistory").is_some(),
        "tipsHistory must be preserved"
    );
    assert!(
        result.get("cachedGrowthBookFeatures").is_some(),
        "cachedGrowthBookFeatures must be preserved"
    );
}

/// Unknown future top-level keys are preserved verbatim.
#[test]
fn merge_preserves_unknown_future_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(".claude.json");
    fs::copy(fixture("sample-unknown-keys.json"), &path).unwrap();

    merge_and_save_claude_dot_json(&path, &new_incoming_account(), "uid".to_string()).unwrap();

    let result: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        result["futureFeature"]["enabled"], true,
        "futureFeature must be preserved verbatim"
    );
    assert_eq!(result["futureFeature"]["config"]["threshold"], 42);
    assert_eq!(result["anotherUnknownKey"], "some-value");
    assert_eq!(result["numStartups"], 3);
}

/// Only oauthAccount and userID change; everything else stays identical.
#[test]
fn merge_updates_only_oauth_account_and_user_id() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(".claude.json");
    fs::copy(fixture("full-sample.json"), &path).unwrap();

    let original: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

    let new_uid = "newuid".to_string();
    merge_and_save_claude_dot_json(&path, &new_incoming_account(), new_uid.clone()).unwrap();

    let result: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

    // Identity fields changed
    assert_eq!(result["userID"], new_uid);
    assert_eq!(
        result["oauthAccount"]["emailAddress"],
        "new-user@example.com"
    );

    // All other keys unchanged
    for (key, original_value) in original.as_object().unwrap() {
        if key == "oauthAccount" || key == "userID" {
            continue;
        }
        assert_eq!(
            result.get(key),
            Some(original_value),
            "key '{key}' must be unchanged"
        );
    }
}

/// load_claude_dot_json on the minimal fixture parses correctly.
#[test]
fn load_minimal_fixture() {
    let state = load_claude_dot_json(&fixture("sample-minimal.json")).unwrap();
    assert_eq!(
        state.oauth_account.unwrap().email_address,
        "old@example.com"
    );
    assert_eq!(state.user_id.unwrap(), "old-user-id");
    assert!(state.preserved.is_empty());
}

/// ExpiresAt millis roundtrip via serde.
#[test]
fn expires_at_millis_roundtrip() {
    use claude_code_context_switcher::claude_state::ExpiresAt;
    let blob_json = r#"{"expiresAt": 1800000000000}"#;
    let v: Value = serde_json::from_str(blob_json).unwrap();
    let expires: ExpiresAt = serde_json::from_value(v["expiresAt"].clone()).unwrap();
    let re_serialized = serde_json::to_value(&expires).unwrap();
    assert_eq!(
        re_serialized, v["expiresAt"],
        "millis form must round-trip exactly"
    );
}

/// ExpiresAt ISO string roundtrip via serde.
#[test]
fn expires_at_iso_roundtrip() {
    use claude_code_context_switcher::claude_state::ExpiresAt;
    let blob_json = r#"{"expiresAt": "2027-02-18T07:00:00.000Z"}"#;
    let v: Value = serde_json::from_str(blob_json).unwrap();
    let expires: ExpiresAt = serde_json::from_value(v["expiresAt"].clone()).unwrap();
    let re_serialized = serde_json::to_value(&expires).unwrap();
    assert_eq!(
        re_serialized, v["expiresAt"],
        "ISO form must round-trip exactly"
    );
}
