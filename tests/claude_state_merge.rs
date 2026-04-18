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

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/claude_dot_json")
        .join(name)
}

/// Merge against the full-sample fixture and verify the result matches the expected fixture.
#[test]
fn merge_against_realistic_claude_dot_json_preserves_cachelist() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(".claude.json");

    // Seed the file with the realistic fixture
    fs::copy(fixture("full-sample.json"), &path).unwrap();

    let new_user_id =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
    merge_and_save_claude_dot_json(&path, &new_incoming_account(), new_user_id).unwrap();

    let result: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let expected: Value =
        serde_json::from_str(&fs::read_to_string(fixture("full-sample.expected.json")).unwrap())
            .unwrap();

    assert_eq!(
        result, expected,
        "merge output did not match expected fixture"
    );
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
