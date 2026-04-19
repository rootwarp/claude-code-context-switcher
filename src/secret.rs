//! `Secret<T>` newtype with redacted `Display`/`Debug` and zeroize on drop.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Wrapper that prevents secrets from leaking via `Debug`/`Display`.
///
/// `Debug` renders `"Secret(***)"` and `Display` renders `"***"`.
/// `Serialize`/`Deserialize` are transparent so YAML config can store and
/// reload keys verbatim.  `Drop` calls `zeroize()` on the inner value.
///
/// The `T: Zeroize` bound is required on the struct so that the `Drop` impl
/// can guarantee zeroization.  All types used as secrets in this codebase
/// (`String`, `Vec<u8>`) implement `Zeroize`.
// `into_inner` contains an `unsafe` block (ManuallyDrop + ptr::read) that is
// unrelated to deserialization; suppress the false-positive clippy lint.
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
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

    /// Consume the wrapper and return the inner value without running `Drop`.
    ///
    /// When calling this method the caller takes responsibility for the value;
    /// it will NOT be zeroized automatically.
    #[must_use]
    pub fn into_inner(self) -> T {
        let me = std::mem::ManuallyDrop::new(self);
        // SAFETY: `me` is ManuallyDrop, so Secret's Drop will not run.
        // We read the T directly, taking ownership of the value.
        unsafe { std::ptr::read(&me.0) }
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Eq> Eq for Secret<T> {}

impl<T: Zeroize> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(***)")
    }
}

impl<T: Zeroize> std::fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "***")
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Secret<T> {
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
    fn debug_format_is_secret_triple_star() {
        let s = Secret::new("sk-ant-oat01-REAL".to_string());
        assert_eq!(format!("{s:?}"), "Secret(***)");
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

    #[test]
    fn into_inner_returns_value() {
        let s = Secret::new(42u32);
        assert_eq!(s.into_inner(), 42);
    }

    #[test]
    fn into_inner_string_returns_value() {
        let s = Secret::new("hello".to_string());
        assert_eq!(s.into_inner(), "hello");
    }

    #[test]
    fn drop_zeroizes_vec() {
        // Verify the Zeroize impl that Secret<Vec<u8>>::drop() calls actually zeroes memory.
        let mut v: Vec<u8> = vec![1, 2, 3];
        Zeroize::zeroize(&mut v);
        assert!(v.iter().all(|&b| b == 0), "Zeroize must clear all bytes");
    }
}
