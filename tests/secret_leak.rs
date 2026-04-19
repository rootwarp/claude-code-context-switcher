//! Regression tests asserting that secrets never appear in formatted output,
//! panic messages, or CLI output (issue 4.5).

const SENTINEL: &str = "sk-ant-oat01-LEAKTEST-0123456789abcdef1234567890abcdef";

// ── Test 1 ───────────────────────────────────────────────────────────────────

#[test]
fn debug_does_not_leak() {
    let s = claude_code_context_switcher::secret::Secret::new(SENTINEL.to_string());
    assert!(!format!("{s:?}").contains(SENTINEL));
    assert_eq!(format!("{s:?}"), "Secret(***)");
}

// ── Test 2 ───────────────────────────────────────────────────────────────────

#[test]
fn display_does_not_leak() {
    let s = claude_code_context_switcher::secret::Secret::new(SENTINEL.to_string());
    assert!(!format!("{s}").contains(SENTINEL));
    assert_eq!(format!("{s}"), "***");
}

// ── Test 3 ───────────────────────────────────────────────────────────────────

#[test]
fn panic_scrub_strips_sk_ant() {
    use claude_code_context_switcher::logging::scrub_panic_message;
    let input = format!("thread 'main' panicked: {SENTINEL}");
    let out = scrub_panic_message(&input);
    assert!(!out.contains(SENTINEL), "sentinel leaked: {out}");
    assert!(out.contains("sk-ant-***"), "expected sk-ant-*** in: {out}");
}

// ── Test 4 ───────────────────────────────────────────────────────────────────

#[test]
fn panic_scrub_strips_bearer() {
    use claude_code_context_switcher::logging::scrub_panic_message;
    let bearer_token = "eyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef";
    let input = format!("error: Bearer {bearer_token}");
    let out = scrub_panic_message(&input);
    assert!(!out.contains(bearer_token));
    assert!(out.contains("Bearer ***"));
}

// ── Test 5 ───────────────────────────────────────────────────────────────────

#[test]
fn panic_scrub_strips_hex_run() {
    use claude_code_context_switcher::logging::scrub_panic_message;
    let hex = "0123456789abcdef0123456789abcdef"; // 32 chars
    let input = format!("debug value: {hex}");
    let out = scrub_panic_message(&input);
    assert!(!out.contains(hex));
    assert!(out.contains("<hex-redacted>"));
}

// ── Test 6 ───────────────────────────────────────────────────────────────────

#[test]
fn cli_add_verbosity_does_not_leak() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_dir = tmp.path().join("claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.json"),
        format!(r#"{{"env":{{"ANTHROPIC_API_KEY":"{SENTINEL}"}}}}"#),
    )
    .unwrap();
    let out = assert_cmd::Command::cargo_bin("cctx")
        .unwrap()
        .env("CCTX_HOME", tmp.path().join("cctx"))
        .env("CLAUDE_CONFIG_DIR", &claude_dir)
        .env("CCTX_TEST_IN_MEMORY_KEYCHAIN", "1")
        .args(["-vvv", "add", "sentinel-ctx"])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains(SENTINEL),
        "sentinel leaked in add output:\n{combined}"
    );
}
