//! Immutable published rows. Captures own their containers and retain these
//! allocations by strong reference; no row exposes mutation after publication.
//! Serialization is transparent, preserving both native image wire versions.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Borrow;
use std::io;
use std::num::NonZeroU64;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// These numbers identify process-local publications, never persisted rows or
// authority. One issuer across all owners prevents equal values, cold opens
// and concurrent preparations from aliasing a captured logical revision.
// Exhaustion is permanent: no wrap, recycling, address reuse or owner reset.
struct RevisionIssuer(AtomicU64);

static REVISIONS: RevisionIssuer = RevisionIssuer(AtomicU64::new(1));

pub(super) fn issue_revision() -> io::Result<NonZeroU64> {
    REVISIONS.issue()
}

impl RevisionIssuer {
    fn issue(&self) -> io::Result<NonZeroU64> {
        let value = self
            .0
            // Only uniqueness is synchronized here. The existing Arc and
            // owner publication locks still synchronize the actual payload.
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1).filter(|_| value != 0)
            })
            .map_err(|_| super::invalid("native row revision exhausted"))?;
        NonZeroU64::new(value).ok_or_else(|| super::invalid("native row revision invalid"))
    }
}

/// Published values choose immutable ownership without changing revision
/// semantics. Receipt metadata fits in its already shared map entry; other
/// rows retain their original independent Arc. Every owner clone is bounded
/// and shares variable-sized bodies rather than copying them under State.
pub(crate) trait RowValue: Sized {
    type Owner: Clone + Borrow<Self>;

    fn new_owner(self) -> Self::Owner;
    fn owner_allocation_bytes() -> usize;
}

macro_rules! arc_values {
    ($($value:ty),+ $(,)?) => {
        $(impl RowValue for $value {
            type Owner = Arc<Self>;

            fn new_owner(self) -> Self::Owner {
                Arc::new(self)
            }

            fn owner_allocation_bytes() -> usize {
                // Include both atomic reference counts and conservatively
                // round header and value for either alignment.
                std::mem::size_of::<Self>()
                    + 2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
                    + 2 * (std::mem::align_of::<Self>()
                        + std::mem::align_of::<std::sync::atomic::AtomicUsize>())
            }
        })+
    };
}

arc_values!(
    super::NativeKeyState,
    super::NativeGenericReceipt,
    super::log::NativeLogEntry,
    super::roster::Row,
    super::roster::Partition,
);

impl RowValue for super::NativeReceipt {
    type Owner = Self;

    fn new_owner(self) -> Self::Owner {
        self
    }

    fn owner_allocation_bytes() -> usize {
        0
    }
}

#[cfg(test)]
arc_values!(Vec<u64>, u64);

pub(crate) struct SharedRow<T: RowValue> {
    value: T::Owner,
    // Logical publication identity is independent of its representation. A
    // checked relocation can release a resident payload while old captures
    // retain it, without pretending to be a new business mutation.
    revision: NonZeroU64,
}

impl<T: RowValue> SharedRow<T> {
    /// Charge the concrete owner before a relocation. Inline metadata is
    /// already charged by its containing preparation vectors.
    pub(super) fn relocated_allocation_bytes() -> usize {
        T::owner_allocation_bytes()
    }

    pub(super) fn new(value: T) -> io::Result<Self> {
        let revision = issue_revision()?;
        Ok(Self {
            value: value.new_owner(),
            revision,
        })
    }

    pub(super) fn ptr_eq(&self, other: &Self) -> bool {
        self.revision == other.revision
    }

    // Only the generation relocation publisher calls this after matching the
    // exact captured revision and complete, readback-verified replacement.
    pub(super) fn relocated(&self, value: T) -> Self {
        Self {
            value: value.new_owner(),
            revision: self.revision,
        }
    }

    // Process-only identity, never reused even after the last capture drops.
    // Never encoded on disk or interpreted as a persisted certificate.
    pub(super) fn revision(&self) -> u64 {
        self.revision.get()
    }
}

impl<T: RowValue> Clone for SharedRow<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            revision: self.revision,
        }
    }
}

impl<T: RowValue> Deref for SharedRow<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.borrow()
    }
}

impl<T: Serialize + RowValue> Serialize for SharedRow<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Borrow::<T>::borrow(&self.value).serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de> + RowValue> Deserialize<'de> for SharedRow<T> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        Self::new(T::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_shared_revisions_preserve_captures_and_relocation_but_separate_new_rows() {
        let original = SharedRow::new(vec![1u64, 2, 3]).unwrap();
        let captured = original.clone();
        let relocated = original.relocated((*original).clone());
        assert!(original.ptr_eq(&captured));
        assert!(original.ptr_eq(&relocated));
        assert!(!Arc::ptr_eq(&original.value, &relocated.value));
        let encoded = serde_json::to_vec(&original).unwrap();
        assert_eq!(encoded, serde_json::to_vec(&*original).unwrap());
        drop(original);
        for _ in 0..4096 {
            let replacement = SharedRow::new((*captured).clone()).unwrap();
            assert!(!captured.ptr_eq(&replacement));
            assert!(!relocated.ptr_eq(&replacement));
        }
        let reconstructed: SharedRow<Vec<u64>> = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(*reconstructed, *captured);
        assert!(!reconstructed.ptr_eq(&captured));
        assert_eq!(serde_json::to_vec(&relocated).unwrap(), encoded);
    }

    #[test]
    fn native_shared_revision_issuer_exhaustion_is_permanent_and_cannot_wrap() {
        // A local issuer exercises exhaustion without resetting or modifying
        // the production issuer used by other tests and live owners.
        let issuer = RevisionIssuer(AtomicU64::new(u64::MAX - 1));
        assert_eq!(issuer.issue().unwrap().get(), u64::MAX - 1);
        for _ in 0..8 {
            assert!(issuer.issue().is_err());
            assert_eq!(issuer.0.load(Ordering::Relaxed), u64::MAX);
        }
        assert!(RevisionIssuer(AtomicU64::new(0)).issue().is_err());
    }

    #[test]
    fn native_shared_revisions_do_not_alias_across_concurrent_owners() {
        let revisions = std::thread::scope(|scope| {
            let threads = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        (0..1024)
                            .map(|_| SharedRow::new(7u64).unwrap().revision())
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();
            threads
                .into_iter()
                .flat_map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(revisions.len(), 8192);
        assert_eq!(
            revisions
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            8192
        );
    }
}
