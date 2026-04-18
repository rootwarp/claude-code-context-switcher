//! `Secret<T>` newtype with redacted `Display`/`Debug`; memory-zeroize on drop.

use serde::{Deserialize, Serialize};

/// Wrapper that prevents secrets from leaking via `Debug`/`Display`.
///
/// `Debug` and `Display` always render `"***"`.
/// `Serialize`/`Deserialize` are transparent so YAML config can store and
/// reload keys verbatim.  Full `zeroize` on `Drop` lands in issue 4.1.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wrap a secret value.
    #[must_use]
    pub const fn new(v: T) -> Self {
        Self(v)
    }

    /// Expose the inner value for use within trusted code.
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Eq> Eq for Secret<T> {}

impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "***")
    }
}

impl<T> std::fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "***")
    }
}

impl<T: PartialEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("sk-ant-xyz".to_string());
        let dbg = format!("{s:?}");
        assert!(
            !dbg.contains("sk-ant"),
            "debug must not expose secret: {dbg}"
        );
        assert!(
            dbg.contains("***"),
            "debug must contain *** redaction: {dbg}"
        );
    }

    #[test]
    fn secret_display_is_redacted() {
        let s = Secret::new("sk-ant-xyz".to_string());
        let display = format!("{s}");
        assert!(!display.contains("sk-ant"));
        assert_eq!(display, "***");
    }

    #[test]
    fn secret_expose_returns_inner() {
        let s = Secret::new(42u32);
        assert_eq!(*s.expose(), 42);
    }

    #[test]
    fn secret_partial_eq() {
        let a = Secret::new("key".to_string());
        let b = Secret::new("key".to_string());
        let c = Secret::new("other".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn secret_serde_roundtrip() {
        let s = Secret::new("sk-ant-test".to_string());
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#""sk-ant-test""#);
        let back: Secret<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
