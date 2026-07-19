//! Redaction-aware helpers for Diameter dictionary values.
//!
//! [`Redacted`] prevents diagnostic disclosure for values that do not require
//! a memory-lifetime contract. [`Sensitive`] additionally owns its value in
//! zeroizing storage, including every clone.

use std::fmt;
use std::hash::Hash;
use std::net::IpAddr;
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Wrapper that redacts its inner value from `Debug` and `Display`.
///
/// Equality, cloning, and hashing delegate to the inner type so the wrapper
/// can be used transparently in tests and business logic. Only the diagnostic
/// representations are replaced with a static placeholder. This type does not
/// zeroize its value; use [`Sensitive`] when retained ownership requires that
/// memory-lifetime contract.
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

/// Redacted owner that zeroizes its value when dropped.
///
/// Use this wrapper for retained subscriber identifiers, credentials, and
/// other owned Diameter values whose lifetime must carry an explicit erasure
/// contract. Every clone receives its own [`Zeroizing`] storage, so dropping
/// either the source or a clone zeroizes that allocation independently.
/// `Debug` and `Display` never expose the value.
///
/// Zeroization is best effort: it covers the wrapper's current allocation, but
/// cannot erase earlier allocator copies, wire buffers, swap, or transport
/// retransmission caches. Construct the value directly in this owner where
/// practical, and use [`Self::into_zeroizing`] when ownership must leave the
/// dictionary model without discarding the zeroize-on-drop contract.
#[derive(Clone, PartialEq, Eq)]
pub struct Sensitive<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> Sensitive<T> {
    /// Move an owned value into redacted zeroizing storage.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Adopt an existing zeroizing owner without copying its value.
    #[must_use]
    pub fn from_zeroizing(value: Zeroizing<T>) -> Self {
        Self(value)
    }

    /// Consume this wrapper without losing the zeroize-on-drop contract.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<T> {
        self.0
    }
}

impl<T: Zeroize> Deref for Sensitive<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> AsRef<T> for Sensitive<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl From<&str> for Sensitive<String> {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl From<String> for Sensitive<String> {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<Vec<u8>> for Sensitive<Vec<u8>> {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> From<Zeroizing<T>> for Sensitive<T> {
    fn from(value: Zeroizing<T>) -> Self {
        Self::from_zeroizing(value)
    }
}

impl<T> Hash for Sensitive<T>
where
    T: Hash + Zeroize,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T: Zeroize> Zeroize for Sensitive<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Sensitive<T> {}

impl<T: Zeroize> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}

impl<T: Zeroize> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}

#[cfg(test)]
mod tests {
    use super::Sensitive;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    #[derive(Clone)]
    struct ZeroizeProbe(Arc<AtomicUsize>);

    impl Zeroize for ZeroizeProbe {
        fn zeroize(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn sensitive_source_and_clone_zeroize_independently() {
        assert_zeroize_on_drop::<Sensitive<String>>();

        let zeroize_calls = Arc::new(AtomicUsize::new(0));
        let source = Sensitive::new(ZeroizeProbe(Arc::clone(&zeroize_calls)));
        let clone = source.clone();

        drop(clone);
        assert_eq!(zeroize_calls.load(Ordering::SeqCst), 1);
        drop(source);
        assert_eq!(zeroize_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn sensitive_string_is_redacted_and_explicitly_zeroizable() {
        let mut source = Sensitive::from("subscriber@example");
        let clone = source.clone();

        assert_eq!(format!("{source:?}"), "REDACTED");
        assert_eq!(source.to_string(), "REDACTED");
        source.zeroize();
        assert!(source.is_empty());
        assert_eq!(clone.as_ref(), "subscriber@example");
    }

    #[test]
    fn sensitive_adopts_existing_zeroizing_allocation_without_copying() {
        let existing = Zeroizing::new(String::from("subscriber@example"));
        let allocation = existing.as_ptr();

        let sensitive = Sensitive::from_zeroizing(existing);

        assert_eq!(sensitive.as_ptr(), allocation);
        assert_eq!(sensitive.as_ref(), "subscriber@example");
    }
}
