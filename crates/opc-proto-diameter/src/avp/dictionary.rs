//! Redaction-aware helpers for Diameter dictionary values.
//!
//! The [`Redacted`] wrapper lets typed AVP structs keep sensitive subscriber
//! identifiers available to code while preventing them from leaking through
//! `Debug` or `Display` output.

use std::fmt;
use std::hash::Hash;
use std::net::IpAddr;
use std::ops::Deref;

/// Wrapper that redacts its inner value from `Debug` and `Display`.
///
/// Equality, cloning, and hashing delegate to the inner type so the wrapper
/// can be used transparently in tests and business logic. Only the diagnostic
/// representations are replaced with a static placeholder.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Create a new redacted value.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Consume the wrapper and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl From<IpAddr> for Redacted<IpAddr> {
    fn from(value: IpAddr) -> Self {
        Self(value)
    }
}

impl<T> Deref for Redacted<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> AsRef<T> for Redacted<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl From<&str> for Redacted<String> {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for Redacted<String> {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<Vec<u8>> for Redacted<Vec<u8>> {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}
