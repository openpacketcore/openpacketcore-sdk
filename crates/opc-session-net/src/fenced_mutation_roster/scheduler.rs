//! Bounded, fail-fast provider work admission shared by roster executors.
//!
//! The scheduler is deliberately not an async queue.  A caller supplies an
//! already-redacted exact tenant-and-scope digest and receives both permits at
//! once or a fixed busy result.  Per-scope gates keep one hot tenant from
//! consuming every process-wide provider slot.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard, Weak},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Opaque, precomputed exact tenant-and-scope scheduling key.
pub(crate) type ProviderSchedulingDigest = [u8; 32];

/// The registry is intentionally a fixed power-of-two shard set, not a
/// process-wide queue or mutex.
const PROVIDER_SCHEDULER_SHARDS: usize = 16;
/// No provider scheduler can outlive the durable live-roster capacity.
const MAX_PROVIDER_WORK: usize = opc_session_store::FENCED_MUTATION_ROSTER_MAX_LIVE_ROSTERS;

type ScopeRegistry = HashMap<ProviderSchedulingDigest, Weak<Semaphore>>;

/// Invalid fixed provider-work capacity supplied at process startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderWorkSchedulerConfigError {
    /// Zero provider-work capacity cannot admit any operation.
    ZeroCapacity,
    /// Provider-work capacity exceeds the fixed durable live-roster ceiling.
    CapacityExceedsLiveRosterLimit,
}

impl fmt::Display for ProviderWorkSchedulerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroCapacity => "provider work capacity is invalid",
            Self::CapacityExceedsLiveRosterLimit => "provider work capacity is invalid",
        })
    }
}

impl std::error::Error for ProviderWorkSchedulerConfigError {}

/// Fixed, non-diagnostic result when immediate provider-work admission fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderWorkSchedulerAcquireError {
    /// Either the global or exact-scope capacity is presently exhausted.
    Busy,
}

impl fmt::Display for ProviderWorkSchedulerAcquireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("provider work scheduler is busy")
    }
}

impl std::error::Error for ProviderWorkSchedulerAcquireError {}

/// Fixed-capacity, sharded admission for provider effects.
///
/// For global capacity greater than one, each exact scope receives at most
/// `ceil(global / 2)` permits.  Therefore a saturated scope leaves at least
/// one global permit for an unrelated scope.  All operations use synchronous
/// `try_acquire`; this type owns neither waiters nor worker tasks.
#[derive(Clone)]
pub(crate) struct ProviderWorkScheduler {
    global: Arc<Semaphore>,
    per_scope_capacity: usize,
    shards: [Arc<Mutex<ScopeRegistry>>; PROVIDER_SCHEDULER_SHARDS],
}

impl fmt::Debug for ProviderWorkScheduler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderWorkScheduler { redacted }")
    }
}

impl ProviderWorkScheduler {
    /// Create the fixed scheduler after validating the process-wide limit.
    pub(crate) fn new(max_in_flight: usize) -> Result<Self, ProviderWorkSchedulerConfigError> {
        if max_in_flight == 0 {
            return Err(ProviderWorkSchedulerConfigError::ZeroCapacity);
        }
        if max_in_flight > MAX_PROVIDER_WORK {
            return Err(ProviderWorkSchedulerConfigError::CapacityExceedsLiveRosterLimit);
        }

        Ok(Self {
            global: Arc::new(Semaphore::new(max_in_flight)),
            per_scope_capacity: max_in_flight.div_ceil(2),
            shards: std::array::from_fn(|_| Arc::new(Mutex::new(HashMap::new()))),
        })
    }

    /// Attempt to hold global and exact-scope capacity without waiting.
    pub(crate) fn try_acquire(
        &self,
        digest: ProviderSchedulingDigest,
    ) -> Result<ProviderWorkPermit, ProviderWorkSchedulerAcquireError> {
        // Take the global permit first.  A burst of distinct failed scopes can
        // therefore never grow the registry beyond the global work bound,
        // even transiently.
        let global_permit = Arc::clone(&self.global)
            .try_acquire_owned()
            .map_err(|_| ProviderWorkSchedulerAcquireError::Busy)?;
        let registry = Arc::clone(&self.shards[self.shard_index(&digest)]);
        let scope = {
            let mut entries = lock_registry(&registry);
            entries.retain(|_, weak| weak.strong_count() != 0);
            match entries.get(&digest).and_then(Weak::upgrade) {
                Some(existing) => existing,
                None => {
                    let scope = Arc::new(Semaphore::new(self.per_scope_capacity));
                    entries.insert(digest, Arc::downgrade(&scope));
                    scope
                }
            }
        };

        let scope_permit = match Arc::clone(&scope).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                drop(scope);
                drop(global_permit);
                remove_if_inactive(&registry, &digest);
                return Err(ProviderWorkSchedulerAcquireError::Busy);
            }
        };

        Ok(ProviderWorkPermit {
            scope_permit: Some(scope_permit),
            global_permit: Some(global_permit),
            digest,
            registry,
        })
    }

    fn shard_index(&self, digest: &ProviderSchedulingDigest) -> usize {
        usize::from(digest[0]) & (PROVIDER_SCHEDULER_SHARDS - 1)
    }

    #[cfg(test)]
    fn registry_entries(&self) -> usize {
        self.shards
            .iter()
            .map(|registry| {
                let mut entries = lock_registry(registry);
                entries.retain(|_, weak| weak.strong_count() != 0);
                entries.len()
            })
            .sum()
    }
}

/// RAII admission holding the exact-scope and process-wide provider permits.
pub(crate) struct ProviderWorkPermit {
    scope_permit: Option<OwnedSemaphorePermit>,
    global_permit: Option<OwnedSemaphorePermit>,
    digest: ProviderSchedulingDigest,
    registry: Arc<Mutex<ScopeRegistry>>,
}

impl fmt::Debug for ProviderWorkPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderWorkPermit { redacted }")
    }
}

impl Drop for ProviderWorkPermit {
    fn drop(&mut self) {
        self.global_permit.take();
        self.scope_permit.take();
        remove_if_inactive(&self.registry, &self.digest);
    }
}

fn lock_registry(registry: &Mutex<ScopeRegistry>) -> MutexGuard<'_, ScopeRegistry> {
    match registry.lock() {
        Ok(entries) => entries,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn remove_if_inactive(registry: &Mutex<ScopeRegistry>, digest: &ProviderSchedulingDigest) {
    let mut entries = lock_registry(registry);
    if entries
        .get(digest)
        .is_some_and(|weak| weak.strong_count() == 0)
    {
        entries.remove(digest);
    }
    entries.retain(|_, weak| weak.strong_count() != 0);
}

#[cfg(test)]
mod tests {
    use super::{
        ProviderWorkScheduler, ProviderWorkSchedulerAcquireError, ProviderWorkSchedulerConfigError,
        MAX_PROVIDER_WORK,
    };

    #[test]
    fn global_bound_is_never_exceeded() {
        let scheduler = ProviderWorkScheduler::new(4).expect("valid capacity");
        let _first = scheduler.try_acquire([1; 32]).expect("first permit");
        let _second = scheduler.try_acquire([2; 32]).expect("second permit");
        let _third = scheduler.try_acquire([3; 32]).expect("third permit");
        let _fourth = scheduler.try_acquire([4; 32]).expect("fourth permit");

        assert!(matches!(
            scheduler.try_acquire([5; 32]),
            Err(ProviderWorkSchedulerAcquireError::Busy)
        ));
    }

    #[test]
    fn same_scope_is_limited_to_half_rounded_up() {
        let scheduler = ProviderWorkScheduler::new(6).expect("valid capacity");
        let _first = scheduler.try_acquire([9; 32]).expect("first permit");
        let _second = scheduler.try_acquire([9; 32]).expect("second permit");
        let _third = scheduler.try_acquire([9; 32]).expect("third permit");

        assert!(matches!(
            scheduler.try_acquire([9; 32]),
            Err(ProviderWorkSchedulerAcquireError::Busy)
        ));
    }

    #[test]
    fn hot_scope_saturation_leaves_capacity_for_an_unrelated_scope() {
        let scheduler = ProviderWorkScheduler::new(4).expect("valid capacity");
        let _first = scheduler.try_acquire([10; 32]).expect("first permit");
        let _second = scheduler.try_acquire([10; 32]).expect("second permit");

        assert!(scheduler.try_acquire([11; 32]).is_ok());
    }

    #[test]
    fn clones_share_global_and_scope_limits() {
        let scheduler = ProviderWorkScheduler::new(2).expect("valid capacity");
        let clone = scheduler.clone();
        let _first = scheduler.try_acquire([12; 32]).expect("first permit");
        assert!(matches!(
            clone.try_acquire([12; 32]),
            Err(ProviderWorkSchedulerAcquireError::Busy)
        ));
        let _second = clone.try_acquire([13; 32]).expect("second permit");

        assert!(matches!(
            scheduler.try_acquire([14; 32]),
            Err(ProviderWorkSchedulerAcquireError::Busy)
        ));
    }

    #[test]
    fn dropping_a_permit_releases_scope_and_global_capacity() {
        let scheduler = ProviderWorkScheduler::new(1).expect("valid capacity");
        let permit = scheduler.try_acquire([15; 32]).expect("first permit");
        drop(permit);

        let replacement = scheduler.try_acquire([16; 32]).expect("replacement permit");
        assert_eq!(scheduler.registry_entries(), 1);
        drop(replacement);
        assert_eq!(scheduler.registry_entries(), 0);
    }

    #[test]
    fn inactive_registry_entries_are_removed_and_churn_remains_bounded() {
        let scheduler = ProviderWorkScheduler::new(2).expect("valid capacity");
        for value in 0_u8..=u8::MAX {
            let permit = scheduler
                .try_acquire([value; 32])
                .expect("sequential permit");
            drop(permit);
            assert_eq!(scheduler.registry_entries(), 0);
        }
    }

    #[test]
    fn shard_collision_does_not_alias_exact_scopes() {
        let scheduler = ProviderWorkScheduler::new(4).expect("valid capacity");
        let first_scope = [0; 32];
        let second_scope = [16; 32];
        assert_eq!(
            scheduler.shard_index(&first_scope),
            scheduler.shard_index(&second_scope)
        );

        let _a_one = scheduler.try_acquire(first_scope).expect("first scope");
        let _a_two = scheduler.try_acquire(first_scope).expect("first scope");
        let _b_one = scheduler.try_acquire(second_scope).expect("second scope");
        let _b_two = scheduler.try_acquire(second_scope).expect("second scope");
    }

    #[test]
    fn max_one_has_one_total_and_one_scope_slot() {
        let scheduler = ProviderWorkScheduler::new(1).expect("valid capacity");
        let permit = scheduler.try_acquire([17; 32]).expect("first permit");

        assert!(matches!(
            scheduler.try_acquire([18; 32]),
            Err(ProviderWorkSchedulerAcquireError::Busy)
        ));
        drop(permit);
        assert!(scheduler.try_acquire([17; 32]).is_ok());
    }

    #[test]
    fn invalid_capacity_is_rejected_without_panicking() {
        assert!(matches!(
            ProviderWorkScheduler::new(0),
            Err(ProviderWorkSchedulerConfigError::ZeroCapacity)
        ));
        assert!(matches!(
            ProviderWorkScheduler::new(MAX_PROVIDER_WORK + 1),
            Err(ProviderWorkSchedulerConfigError::CapacityExceedsLiveRosterLimit)
        ));
    }

    #[test]
    fn acquisition_is_immediate_and_returns_no_wait_handle() {
        let scheduler = ProviderWorkScheduler::new(1).expect("valid capacity");
        let _permit = scheduler.try_acquire([19; 32]).expect("first permit");

        assert!(matches!(
            scheduler.try_acquire([20; 32]),
            Err(ProviderWorkSchedulerAcquireError::Busy)
        ));
    }
}
