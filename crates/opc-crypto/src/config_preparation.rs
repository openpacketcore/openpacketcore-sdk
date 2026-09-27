//! Process-local ownership of bounded configuration preparation buffers.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::ConfigCapacityError;

const PREPARATION_SLOTS: usize = 8;

/// Store-owned, nonwaiting admission for eight bounded preparations.
///
/// Each store must keep its own pool private and check [`Self::owns`] before
/// accepting a reservation. Constructing another pool does not grant capacity
/// in that store. These slots do not establish a per-operation memory bound or
/// replace the consensus engine's accepted-proposal admission.
pub struct ConfigPreparationPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    available: AtomicUsize,
}

impl ConfigPreparationPool {
    /// Construct the version-one pool with exactly eight preparation slots.
    pub fn bounded_v1() -> Self {
        Self {
            inner: Arc::new(PoolInner {
                available: AtomicUsize::new(PREPARATION_SLOTS),
            }),
        }
    }

    /// Reserve one slot immediately, without creating a waiting queue.
    pub fn try_reserve(&self) -> Result<ConfigPreparationReservation, ConfigCapacityError> {
        self.inner
            .available
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |available| {
                available.checked_sub(1)
            })
            .map_err(|_| ConfigCapacityError::ResourceAdmission)?;
        Ok(ConfigPreparationReservation {
            lease: Arc::new(ConfigPreparationLease {
                pool: Arc::clone(&self.inner),
                sealed: AtomicBool::new(false),
            }),
        })
    }

    /// Test private allocation identity, never a caller-supplied store ID.
    pub fn owns(&self, reservation: &ConfigPreparationReservation) -> bool {
        Arc::ptr_eq(&self.inner, &reservation.lease.pool)
    }
}

impl std::fmt::Debug for ConfigPreparationPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfigPreparationPool(<redacted>)")
    }
}

/// Non-cloneable preparation ownership, consumed by reserved encryption.
///
/// Envelope aliases share the same lease. Transferring its one-shot claim does
/// not release the slot while any envelope alias still retains its ciphertext.
/// This process-local value has no serialized representation.
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
