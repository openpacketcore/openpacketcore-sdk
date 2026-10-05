//! Process-local ownership of bounded configuration preparation buffers.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::ConfigCapacityError;

const PREPARATION_SLOTS: usize = 8;

/// Store-owned admission for eight simultaneous bounded preparations.
///
/// Keep the pool private to its destination and check [`Self::owns`] before
/// accepting transferred ownership. Slots do not establish a whole-operation
/// memory bound or replace admission for an accepted consensus proposal.
pub struct ConfigPreparationPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    available: AtomicUsize,
    _owner: Option<Arc<dyn Send + Sync>>,
}

// The opaque owner is only retained and dropped: the pool never accesses or
// exposes its state. Unwinding cannot reveal a partial owner mutation through
// this type, and slot accounting uses atomic transitions and RAII release.
impl std::panic::UnwindSafe for PoolInner {}
impl std::panic::RefUnwindSafe for PoolInner {}

impl ConfigPreparationPool {
    /// Create an independent pool containing exactly eight slots.
    pub fn bounded_v1() -> Self {
        Self::with_owner(None)
    }

    /// Create eight slots retaining an opaque destination lifetime owner.
    ///
    /// The owner survives until the pool and its last lease or envelope alias
    /// drop. Sharing an owner between pools does not merge their capacity or
    /// identity. The owner must not retain a reference back to this pool.
    pub fn bounded_v1_with_owner(owner: Arc<dyn Send + Sync>) -> Self {
        Self::with_owner(Some(owner))
    }

    fn with_owner(owner: Option<Arc<dyn Send + Sync>>) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                available: AtomicUsize::new(PREPARATION_SLOTS),
                _owner: owner,
            }),
        }
    }

    /// Reserve immediately without waiting for capacity or enqueuing a waiter.
    pub fn try_reserve(&self) -> Result<ConfigPreparationReservation, ConfigCapacityError> {
        let mut available = self.inner.available.load(Ordering::Acquire);
        loop {
            let next = available
                .checked_sub(1)
                .ok_or(ConfigCapacityError::ResourceAdmission)?;
            match self.inner.available.compare_exchange_weak(
                available,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => available = current,
            }
        }
        Ok(ConfigPreparationReservation {
            lease: Arc::new(ConfigPreparationLease {
                pool: Arc::clone(&self.inner),
                sealed: AtomicBool::new(false),
            }),
        })
    }

    /// Compare private pool allocation identity, never a caller-supplied ID.
    pub fn owns(&self, reservation: &ConfigPreparationReservation) -> bool {
        self.owns_lease(&reservation.lease)
    }

    pub(super) fn owns_lease(&self, lease: &ConfigPreparationLease) -> bool {
        Arc::ptr_eq(&self.inner, &lease.pool)
    }
}

impl std::fmt::Debug for ConfigPreparationPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfigPreparationPool(<redacted>)")
    }
}

/// Non-cloneable ownership consumed by reserved bounded encryption.
///
/// Cancellation and errors release ownership. Successful encryption transfers
/// it to the envelope and its one-shot claim. The slot is returned only after
/// the last envelope alias and transferred reservation drop. This value has no
/// serialized representation and cannot be reused for a second encryption.
pub struct ConfigPreparationReservation {
    pub(super) lease: Arc<ConfigPreparationLease>,
}

impl ConfigPreparationReservation {
    pub(super) fn begin_encryption(&self) -> Result<(), ConfigCapacityError> {
        self.lease
            .sealed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ConfigCapacityError::ResourceAdmission)?;
        Ok(())
    }
}

impl std::fmt::Debug for ConfigPreparationReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfigPreparationReservation(<redacted>)")
    }
}

pub(super) struct ConfigPreparationLease {
    pool: Arc<PoolInner>,
    sealed: AtomicBool,
}

impl Drop for ConfigPreparationLease {
    fn drop(&mut self) {
        self.pool.available.fetch_add(1, Ordering::Release);
    }
}
