use proptest::prelude::*;
use url::Url;

use claude_code_context_switcher::context::{AuthMode, Context, Fingerprint, IdentityMetadata, SecretRef};
use claude_code_context_switcher::secret::Secret;

fn arb_auth_mode() -> impl Strategy<Value = AuthMode> {
    prop_oneof![
        Just(AuthMode::OAuth),
        Just(AuthMode::ApiKey { base_url: None }),
        prop_oneof![
            Just(Some(Url::parse("https://api.anthropic.com").unwrap())),
            Just(Some(Url::parse("https://custom.example.com/v1").unwrap())),
        ]
        .prop_map(|u| AuthMode::ApiKey { base_url: u }),
    ]
}

fn arb_secret_ref() -> impl Strategy<Value = SecretRef> {
    prop_oneof![
        "[a-zA-Z][a-zA-Z0-9_-]{0,19}".prop_map(|s| SecretRef::Plaintext {
            value: Secret::new(s)
        }),
        (
            "[a-zA-Z][a-zA-Z0-9_-]{0,19}",
            "[a-zA-Z][a-zA-Z0-9_-]{0,19}"
        )
            .prop_map(|(s, a)| SecretRef::Keychain {
                service: s,
                account: a
            }),
        Just(SecretRef::ClaudeCodeKeychain),
    ]
}

fn arb_fingerprint() -> impl Strategy<Value = Fingerprint> {
    any::<[u8; 32]>().prop_map(Fingerprint)
}

fn arb_context() -> impl Strategy<Value = Context> {
    (
        "[a-zA-Z][a-zA-Z0-9_-]{0,19}",
        arb_auth_mode(),
        arb_secret_ref(),
        arb_fingerprint(),
    )
        .prop_map(|(name, auth_mode, secret_ref, fingerprint)| Context {
            name,
            auth_mode,
            secret_ref,
            fingerprint,
            identity: IdentityMetadata::default(),
            created_at: chrono::Utc::now(),
        })
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(256))]
    #[test]
    fn roundtrip_context_yaml(ctx in arb_context()) {
        let s = serde_yaml_ng::to_string(&ctx).unwrap();
        let back: Context = serde_yaml_ng::from_str(&s).unwrap();
        prop_assert_eq!(ctx.name, back.name);
        prop_assert_eq!(ctx.auth_mode, back.auth_mode);
        prop_assert_eq!(ctx.secret_ref, back.secret_ref);
        prop_assert_eq!(ctx.fingerprint, back.fingerprint);
    }
}
