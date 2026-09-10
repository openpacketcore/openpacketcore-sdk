//! Immutable published rows. Captures own their containers and retain these
//! allocations by strong reference; no row exposes mutation after publication.
//! Serialization is transparent, preserving both native image wire versions.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::Deref;
use std::sync::Arc;

pub(crate) struct SharedRow<T> {
    value: Arc<T>,
    // Logical publication identity is independent of its representation. A
    // checked relocation can release a resident payload while old captures
    // retain it, without pretending to be a new business mutation.
    revision: Arc<()>,
}

impl<T> SharedRow<T> {
    /// A relocation allocates only a new value Arc and reuses the revision
    /// Arc. Include its two atomic reference counts and conservatively round
    /// both the header and value for either alignment, before allocating it.
    pub(super) fn relocated_allocation_bytes() -> usize {
        std::mem::size_of::<T>()
            + 2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
            + 2 * (std::mem::align_of::<T>()
                + std::mem::align_of::<std::sync::atomic::AtomicUsize>())
    }

    pub(super) fn new(value: T) -> Self {
        Self {
            value: Arc::new(value),
            revision: Arc::new(()),
        }
    }

    pub(super) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.revision, &other.revision)
    }

    // Only the generation relocation publisher calls this after matching the
    // exact captured revision and complete, readback-verified replacement.
    pub(super) fn relocated(&self, value: T) -> Self {
        Self {
            value: Arc::new(value),
            revision: Arc::clone(&self.revision),
        }
    }

    // Process-only identity while this strong reference remains alive. Never
    // encoded on disk or interpreted as a persisted revision/certificate.
    pub(super) fn address(&self) -> usize {
        Arc::as_ptr(&self.revision) as usize
    }
}

impl<T> Clone for SharedRow<T> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            revision: Arc::clone(&self.revision),
        }
    }
}

impl<T> Deref for SharedRow<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: Serialize> Serialize for SharedRow<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.as_ref().serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for SharedRow<T> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        T::deserialize(decoder).map(Self::new)
    }
}
