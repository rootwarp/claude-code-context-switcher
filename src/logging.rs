//! `tracing_subscriber` init and a custom `Layer` that scrubs known-secret field names.

use std::sync::{LazyLock, OnceLock};

use regex::Regex;
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer};

/// Field names whose values must always be redacted before reaching the formatter.
const SCRUB_FIELDS: &[&str] = &[
    "access_token",
    "refresh_token",
    "api_key",
    "password",
    "anthropic_api_key",
    "anthropic_auth_token",
    "claude_code_oauth_token",
    "keychain_blob",
    "secret",
];

// Static compiled regexes — patterns are literal constants so `expect` cannot fail at runtime.
#[allow(clippy::expect_used)]
static RE_SK_ANT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{8,}").expect("static regex"));
#[allow(clippy::expect_used)]
static RE_BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Bearer [A-Za-z0-9._-]{8,}").expect("static regex"));
#[allow(clippy::expect_used)]
static RE_HEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Fa-f0-9]{32,}").expect("static regex"));

/// Build the default filter string for the given verbosity count.
fn default_filter(verbosity: u8) -> String {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    format!("cctx={level}")
}

/// Scrub known secret patterns from a panic message string.
#[must_use]
pub fn scrub_panic_message(s: &str) -> String {
    let s = RE_SK_ANT.replace_all(s, "sk-ant-***");
    let s = RE_BEARER.replace_all(&s, "Bearer ***");
    RE_HEX.replace_all(&s, "<hex-redacted>").into_owned()
}

/// Installs a scrubbing layer before the previous panic hook.
///
/// Secret-shaped strings are replaced in the panic message before forwarding
/// to the prior hook (which may print backtraces etc.).
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let raw = info.to_string();
        let clean = scrub_panic_message(&raw);
        eprintln!("{clean}");
        prev(info);
    }));
}

/// Detects tracing events where a known-secret field name carries an unredacted value.
///
/// Does NOT suppress or modify the event — emits a warning to stderr.
/// Prevention relies on callers wrapping secrets in `Secret<T>`.
pub struct SecretLeakCanary;

pub(crate) struct SecretFieldVisitor {
    pub(crate) found_leak: bool,
}

impl SecretFieldVisitor {
    pub(crate) fn check_str(&mut self, name: &str, value: &str) {
        if SCRUB_FIELDS.contains(&name) && !value.contains("***") {
            eprintln!("WARN [cctx] secret-field '{name}' appears unredacted in tracing event");
            self.found_leak = true;
        }
    }
}

impl tracing::field::Visit for SecretFieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.check_str(field.name(), value);
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if SCRUB_FIELDS.contains(&field.name()) {
            let rendered = format!("{value:?}");
            if !rendered.contains("***") {
                eprintln!(
                    "WARN [cctx] secret-field '{}' appears unredacted in tracing event",
                    field.name()
                );
                self.found_leak = true;
            }
        }
    }
}

impl<S: Subscriber> Layer<S> for SecretLeakCanary {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = SecretFieldVisitor { found_leak: false };
        event.record(&mut visitor);
    }
}

static INIT: OnceLock<()> = OnceLock::new();

/// Initialise the global `tracing` subscriber.
///
/// Verbosity mapping: 0→warn, 1→info, 2→debug, 3+→trace (on `cctx` target).
/// `RUST_LOG` overrides the constructed filter when set.
pub fn init(verbosity: u8) {
    INIT.get_or_init(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(default_filter(verbosity)));

        let fmt = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

        tracing_subscriber::registry()
            .with(SecretLeakCanary)
            .with(filter)
            .with(fmt)
            .try_init()
            .ok();

        install_panic_hook();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbosity_0_filter_is_warn() {
        assert!(default_filter(0).contains("warn"));
    }

    #[test]
    fn verbosity_1_filter_is_info() {
        assert!(default_filter(1).contains("info"));
    }

    #[test]
    fn verbosity_2_filter_is_debug() {
        assert!(default_filter(2).contains("debug"));
    }

    #[test]
    fn panic_hook_strips_sk_ant() {
        let input = "panicked at 'sk-ant-oat01-abc123def456ghi789jkl'";
        let output = scrub_panic_message(input);
        assert!(output.contains("sk-ant-***"), "output: {output}");
        assert!(
            !output.contains("sk-ant-oat01-abc123def456ghi789jkl"),
            "output: {output}"
        );
    }

    #[test]
    fn panic_hook_strips_bearer() {
        let input = "error: Bearer abc123def456ghi789jkl012";
        let output = scrub_panic_message(input);
        assert!(output.contains("Bearer ***"), "output: {output}");
        assert!(!output.contains("abc123def456ghi789jkl012"), "output: {output}");
    }

    #[test]
    fn panic_hook_strips_hex_run() {
        let input = "leaked: deadbeefcafebabe0123456789abcdef";
        let output = scrub_panic_message(input);
        assert!(output.contains("<hex-redacted>"), "output: {output}");
        assert!(
            !output.contains("deadbeefcafebabe0123456789abcdef"),
            "output: {output}"
        );
    }

    #[test]
    fn secret_field_visitor_warns_on_raw_value() {
        let mut visitor = SecretFieldVisitor { found_leak: false };
        visitor.check_str("access_token", "sk-ant-raw");
        assert!(visitor.found_leak);
    }

    #[test]
    fn secret_field_visitor_silent_for_redacted_value() {
        let mut visitor = SecretFieldVisitor { found_leak: false };
        visitor.check_str("access_token", "Secret(***)");
        assert!(!visitor.found_leak);
    }
}
