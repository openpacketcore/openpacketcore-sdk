use std::fmt;

const REDACTED_MARKER: &str = "<redacted>";

/// Owns sensitive data while guaranteeing that `Debug` and `Display` stay
/// redacted.
///
/// This wrapper intentionally does not implement serde traits. Call sites must
/// make an explicit policy choice between serializing the inner value under an
/// authorized channel or emitting an explicit redacted marker.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap a value in a redacted container.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Access the inner value by reference.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Unwrap and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Map the inner value through a function.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Redacted<U> {
        Redacted::new(f(self.0))
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Redacted").field(&REDACTED_MARKER).finish()
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

/// Borrowed debug/display adapter for sensitive values that should never be formatted directly.
#[derive(Copy, Clone)]
pub struct RedactedDebug<'a, T: ?Sized>(&'a T);

impl<'a, T: ?Sized> RedactedDebug<'a, T> {
    /// Create a redacted debug adapter for a borrowed value.
    pub fn new(value: &'a T) -> Self {
        Self(value)
    }
}

impl<T: ?Sized> fmt::Debug for RedactedDebug<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RedactedDebug")
            .field(&REDACTED_MARKER)
            .finish()
    }
}

impl<T: ?Sized> fmt::Display for RedactedDebug<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

/// Wraps a borrowed value in a formatter that never renders the inner secret.
pub fn redact<T: ?Sized>(value: &T) -> RedactedDebug<'_, T> {
    RedactedDebug::new(value)
}

/// Convenience extension trait for converting owned values into `Redacted`.
pub trait IntoRedacted: Sized {
    /// Wrap this value in a `Redacted` container.
    fn redacted(self) -> Redacted<Self> {
        Redacted::new(self)
    }
}

impl<T> IntoRedacted for T {}
