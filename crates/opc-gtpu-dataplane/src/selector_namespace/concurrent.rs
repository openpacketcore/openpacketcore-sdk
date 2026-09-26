//! Explicit concurrent composition of the existing protected lifecycle.

use super::observability::{observe_guard, ObservedGuard};
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, OwnedSemaphorePermit};

#[cfg(test)]
mod tests;

/// Experimental concurrent operations over one already-open protected namespace.
///
/// Clones share bounded SDK supervisors, conflict reservations and one durable
/// lease only while operations overlap. Each operation retains its original
/// fenced writes, exact readbacks and non-aborting result observer. Unrelated
/// backend effects may overlap; conflicting groups, PAAs and TEIDs may not.
/// This does not change the namespace's permanent-history capacity profile.
pub struct GtpuSessionSelectorConcurrentNamespace<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    authority: GtpuSessionSelectorNamespaceAuthority<B>,
    pool: Arc<LeasePool>,
}

impl<B> Clone for GtpuSessionSelectorConcurrentNamespace<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    fn clone(&self) -> Self {
        Self {
            authority: self.authority.clone(),
            pool: Arc::clone(&self.pool),
        }
    }
}

impl<B> fmt::Debug for GtpuSessionSelectorConcurrentNamespace<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorConcurrentNamespace(<redacted>)")
    }
}

impl<B> GtpuSessionSelectorNamespaceAuthority<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    /// Select the experimental concurrent composition for this opened namespace.
    ///
    /// Keep and clone the returned handle. Independently selected handles and
    /// legacy operations still exclude each other through the original durable
    /// worker gate; they cannot replace a live cohort's lease credential.
    pub fn concurrent_operations(&self) -> GtpuSessionSelectorConcurrentNamespace<B> {
        GtpuSessionSelectorConcurrentNamespace {
            authority: self.clone(),
            pool: Arc::new(LeasePool::default()),
        }
    }

    pub(super) async fn concurrent_transition(
        &self,
    ) -> Option<ObservedGuard<'static, tokio::sync::MutexGuard<'_, ()>>> {
        match self.concurrent_operation.as_ref() {
            Some(operation) => Some(
                observe_guard(
                    GtpuSelectorPhase::TransitionWait,
                    GtpuSelectorPhase::TransitionHold,
                    operation.shared.transition.lock(),
                )
                .await,
            ),
            None => None,
        }
    }

    pub(super) fn retain_concurrent_install(
        &self,
        admission: &GtpuSessionSelectorAdmission,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        if let Some(operation) = &self.concurrent_operation {
            operation.retain_install(admission)?;
        }
        Ok(())
    }
}

impl<B> GtpuSessionSelectorConcurrentNamespace<B>
where
    B: SessionBackend + SessionLeaseManager + Send + Sync + 'static,
{
    fn spawn<T, F, W>(
        &self,
        groups: Vec<GtpuSessionGroup>,
        work: W,
    ) -> GtpuSessionSelectorOperation<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, GtpuSessionSelectorCoordinatorError>> + Send + 'static,
        W: FnOnce(GtpuSessionSelectorNamespaceAuthority<B>) -> F + Send + 'static,
    {
        let authority = self.authority.clone();
        let pool = Arc::clone(&self.pool);
        spawn_selector_operation_with_gate(
            authority.storage_scope_commitment,
            GtpuSessionSelectorCoordinatorError::Backend,
            None,
            async move {
                // These are scheduling exclusions, never selector authority.
                // Their number is bounded by the admitted complete groups.
                let _conflicts = pool.reserve_groups(&groups).await?;
                let shared = pool.join(&authority).await?;
                let operation = Arc::new(ConcurrentOperation::new(Arc::clone(&shared)));
                let mut worker_authority = authority.clone();
                worker_authority.concurrent_operation = Some(Arc::clone(&operation));
                let result = work(worker_authority).await;
                let release = pool.leave(&authority, &shared).await;
                operation.settled();
                match result {
                    Err(error) => Err(error),
                    Ok(value) if release.is_ok() => Ok(value),
                    Ok(_) => Err(GtpuSessionSelectorCoordinatorError::Namespace),
                }
            },
        )
    }

    /// Reconcile one fresh complete group with the existing exact lifecycle.
    pub fn reconcile_fresh<D>(
        &self,
        backend: Arc<D>,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        self.spawn(vec![desired.clone()], |authority| async move {
            authority
                .reconcile_fresh_owned(backend.as_ref(), desired)
                .await
        })
    }

    /// Permanently seal one exact never-admitted group without a backend effect.
    pub fn seal_unadmitted<D>(
        &self,
        backend: Arc<D>,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorUnadmittedClaim>
    where
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        self.spawn(vec![desired.clone()], |authority| async move {
            authority
                .seal_unadmitted_owned(backend.as_ref(), desired)
                .await
        })
    }

    /// Reattach an exact retired single-bearer predecessor using a fresh TEID.
    ///
    /// The complete desired PAA reservation also excludes every eligible
    /// predecessor. The original protected source discovery, quiescence receipt
    /// and atomic one-successor transition remain mandatory.
    pub fn reconcile_reattached<D>(
        &self,
        backend: Arc<D>,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        self.spawn(vec![desired.clone()], |authority| async move {
            authority
                .reconcile_reattached_owned(backend.as_ref(), desired)
                .await
        })
    }

    /// Reconcile a marked child, reserving its exact parent and complete set.
    pub fn reconcile_bearer<D>(
        &self,
        backend: Arc<D>,
        parent_claim: GtpuSessionSelectorActiveClaim,
        parent: GtpuSessionGroup,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        self.spawn(
            vec![parent.clone(), desired.clone()],
            |authority| async move {
                authority
                    .reconcile_bearer_owned(backend.as_ref(), parent_claim, parent, desired)
                    .await
            },
        )
    }

    /// Recover exact Active authority without replaying an installation.
    pub fn recover_active<D>(
        &self,
        backend: Arc<D>,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        self.spawn(vec![desired.clone()], |authority| async move {
            authority
                .recover_active_owned(backend.as_ref(), desired)
                .await
        })
    }

    /// Recover retained Installing state using its original exact status rules.
    pub fn recover_install<D>(
        &self,
        backend: Arc<D>,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        self.spawn(vec![desired.clone()], |authority| async move {
            authority
                .recover_install_owned(backend.as_ref(), desired)
                .await
        })
    }

    /// Retire one exact Active group and durably acknowledge its exact absence.
    pub fn retire<D>(
        &self,
        backend: Arc<D>,
        active: GtpuSessionSelectorActiveClaim,
        expected: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorRetiredClaim>
    where
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        self.spawn(vec![expected.clone()], |authority| async move {
            authority
                .retire_owned(backend.as_ref(), active, expected)
                .await
        })
    }

    /// Recover the original retirement without replaying an ambiguous effect.
    pub fn recover_retiring<D>(
        &self,
        backend: Arc<D>,
        expected: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorRetiredClaim>
    where
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        self.spawn(vec![expected.clone()], |authority| async move {
            authority
                .recover_retiring_owned(backend.as_ref(), expected)
                .await
        })
    }

    /// Recover an exact terminal Retired claim and its backend quiescence state.
    pub fn recover_retired<D>(
        &self,
        backend: Arc<D>,
        expected: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorRetiredClaim>
    where
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        self.spawn(vec![expected.clone()], |authority| async move {
            authority
                .recover_retired_owned(backend.as_ref(), expected)
                .await
        })
    }
}

#[derive(Default)]
struct LeasePool {
    lifecycle: AsyncMutex<Option<(Arc<SharedLease>, usize)>>,
    conflicts: Mutex<BTreeMap<Vec<u8>, Weak<AsyncMutex<()>>>>,
}

struct AcquiringCohortGate(Option<OwnedSemaphorePermit>);

impl Drop for AcquiringCohortGate {
    fn drop(&mut self) {
        // An unexpectedly dropped acquire may already have replaced the
        // durable credential. Preserve exclusion until process recovery; the
        // enclosing supervisor retains its bounded slots on the same path.
        std::mem::forget(self.0.take());
    }
}

impl LeasePool {
    async fn reserve_groups(
        &self,
        groups: &[GtpuSessionGroup],
    ) -> Result<ObservedGuard<'static, Vec<OwnedMutexGuard<()>>>, GtpuSessionSelectorCoordinatorError>
    {
        if groups.is_empty() || groups.len() > 2 {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        }
        let mut keys = BTreeSet::new();
        for group in groups {
            let canonical = CanonicalClaim::from_group(group);
            if canonical.atoms.len() > SELECTOR_NAMESPACE_MAX_READBACK_ATOMS {
                return Err(GtpuSessionSelectorCoordinatorError::Namespace);
            }
            let mut identity = vec![b'G'];
            identity.extend_from_slice(&canonical.stable_device);
            identity.extend_from_slice(&canonical.group_id);
            keys.insert(identity);
            for atom in canonical.atoms {
                // A scoped mark is exclusive within its PAA. The PAA guard
                // covers that conflict and parent/child ordering; global mark
                // reservations remain enforced by each complete ledger CAS.
                if atom.first() != Some(&b'M') {
                    let mut identity = canonical.stable_device.to_vec();
                    identity.extend_from_slice(&atom);
                    keys.insert(identity);
                }
            }
        }
        let locks = {
            let mut registry = self
                .conflicts
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            registry.retain(|_, lock| lock.strong_count() != 0);
            keys.into_iter()
                .map(|key| {
                    if let Some(lock) = registry.get(&key).and_then(Weak::upgrade) {
                        lock
                    } else {
                        let lock = Arc::new(AsyncMutex::new(()));
                        registry.insert(key, Arc::downgrade(&lock));
                        lock
                    }
                })
                .collect::<Vec<_>>()
        };
        Ok(observe_guard(
            GtpuSelectorPhase::ConflictWait,
            GtpuSelectorPhase::ConflictHold,
            async move {
                let mut guards = Vec::with_capacity(locks.len());
                for lock in locks {
                    guards.push(lock.lock_owned().await);
                }
                guards
            },
        )
        .await)
    }

    async fn join<B>(
        &self,
        authority: &GtpuSessionSelectorNamespaceAuthority<B>,
    ) -> Result<Arc<SharedLease>, GtpuSessionSelectorCoordinatorError>
    where
        B: SessionBackend + SessionLeaseManager,
    {
        let mut state = observe_guard(
            GtpuSelectorPhase::CohortWait,
            GtpuSelectorPhase::CohortHold,
            self.lifecycle.lock(),
        )
        .await;
        if let Some((shared, members)) = state.as_mut() {
            if shared.abandoned.load(Ordering::Acquire) {
                return Err(GtpuSessionSelectorCoordinatorError::Namespace);
            }
            *members += 1;
            return Ok(Arc::clone(shared));
        }
        let worker = observe(
            GtpuSelectorPhase::WorkerWait,
            selector_namespace_worker(authority.storage_scope_commitment).acquire_owned(),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let mut acquiring = AcquiringCohortGate(Some(worker));
        let lease = authority.acquire_worker_lease_owned().await;
        let worker = acquiring
            .0
            .take()
            .ok_or(GtpuSessionSelectorCoordinatorError::Namespace)?;
        let lease = lease.map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let shared = Arc::new(SharedLease {
            lease: AsyncMutex::new(Some(lease)),
            transition: AsyncMutex::new(()),
            installing: Mutex::new(BTreeMap::new()),
            abandoned: AtomicBool::new(false),
            _worker: worker,
        });
        **state = Some((Arc::clone(&shared), 1));
        Ok(shared)
    }

    async fn leave<B>(
        &self,
        authority: &GtpuSessionSelectorNamespaceAuthority<B>,
        shared: &Arc<SharedLease>,
    ) -> Result<(), GtpuSessionSelectorNamespaceError>
    where
        B: SessionBackend + SessionLeaseManager,
    {
        let mut state = observe_guard(
            GtpuSelectorPhase::CohortWait,
            GtpuSelectorPhase::CohortHold,
            self.lifecycle.lock(),
        )
        .await;
        let Some((current, members)) = state.as_mut() else {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        };
        if !Arc::ptr_eq(current, shared)
            || *members == 0
            || shared.abandoned.load(Ordering::Acquire)
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        *members -= 1;
        if *members != 0 {
            return shared.check_current().await;
        }
        let lease = shared
            .credential()
            .await
            .take()
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let result = authority.release_worker_lease_owned(lease).await;
        **state = None;
        result
    }
}

pub(super) struct SharedLease {
    pub(super) lease: AsyncMutex<Option<SelectorWorkerLease>>,
    transition: AsyncMutex<()>,
    installing: Mutex<BTreeMap<[u8; 32], Arc<InFlightInstall>>>,
    abandoned: AtomicBool,
    _worker: OwnedSemaphorePermit,
}

impl SharedLease {
    pub(super) async fn credential(
        &self,
    ) -> ObservedGuard<'static, tokio::sync::MutexGuard<'_, Option<SelectorWorkerLease>>> {
        observe_guard(
            GtpuSelectorPhase::CredentialWait,
            GtpuSelectorPhase::CredentialHold,
            self.lease.lock(),
        )
        .await
    }

    pub(super) fn is_abandoned(&self) -> bool {
        self.abandoned.load(Ordering::Acquire)
    }

    pub(super) async fn check_current(&self) -> Result<(), GtpuSessionSelectorNamespaceError> {
        if self.is_abandoned() {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let mut lease = self.credential().await;
        let lease = lease
            .as_mut()
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let result = if self.is_abandoned() {
            Err(GtpuSessionSelectorNamespaceError::Indeterminate)
        } else {
            lease
                .timing
                .as_ref()
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)
                .and_then(|timing| timing.renewal_due().map(|_| ()))
        };
        if result.is_err() {
            lease.timing = None;
        }
        result
    }

    pub(super) fn attach_inventory(&self, inventory: &mut SelectorOperationStampInventory) {
        let installs = self
            .installing
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut digest = Sha256::new();
        digest.update(b"opc/gtpu-selector/concurrent-inventory/v1\0");
        digest.update(inventory.summary);
        for expected in &mut inventory.expectations {
            expected.in_flight = installs
                .get(&expected.group_fingerprint)
                .filter(|proof| proof.matches(expected))
                .cloned();
            digest.update([u8::from(expected.in_flight.is_some())]);
        }
        inventory.summary = digest.finalize().into();
    }
}

pub(super) struct ConcurrentOperation {
    pub(super) shared: Arc<SharedLease>,
    installs: Mutex<Vec<Arc<InFlightInstall>>>,
    settled: AtomicBool,
}

impl ConcurrentOperation {
    fn new(shared: Arc<SharedLease>) -> Self {
        Self {
            shared,
            installs: Mutex::new(Vec::new()),
            settled: AtomicBool::new(false),
        }
    }

    fn retain_install(
        &self,
        admission: &GtpuSessionSelectorAdmission,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        if admission.phase != SelectorAdmissionPhase::Installing || self.shared.is_abandoned() {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let proof = Arc::new(InFlightInstall {
            live: AtomicBool::new(true),
            group: admission.group_fingerprint,
            device: admission.device_fingerprint,
            selectors: admission.selector_set_fingerprint,
            desired: admission.desired_fingerprint,
            pending: SelectorOperationStampCoordinate {
                generation: admission.generation,
                nonce: admission.operation_nonce,
            },
            terminal: SelectorOperationStampCoordinate {
                generation: admission.terminal_generation,
                nonce: admission.terminal_operation_nonce,
            },
        });
        let mut installs = self
            .shared
            .installing
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if installs.contains_key(&proof.group)
            || installs.len() >= SELECTOR_NAMESPACE_MAX_SUPERVISORS_PER_NAMESPACE
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        installs.insert(proof.group, Arc::clone(&proof));
        self.installs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(proof);
        Ok(())
    }

    fn settled(&self) {
        self.settled.store(true, Ordering::Release);
        self.clear_installs();
    }

    fn clear_installs(&self) {
        let mut registry = self
            .shared
            .installing
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut owned = self
            .installs
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for proof in owned.drain(..) {
            proof.live.store(false, Ordering::Release);
            if registry
                .get(&proof.group)
                .is_some_and(|current| Arc::ptr_eq(current, &proof))
            {
                registry.remove(&proof.group);
            }
        }
    }
}

impl Drop for ConcurrentOperation {
    fn drop(&mut self) {
        if !self.settled.load(Ordering::Acquire) {
            // Unexpected worker destruction is not proof that an already
            // dispatched host effect settled. Retain the cohort's sole worker
            // gate and reject further use until process recovery.
            self.shared.abandoned.store(true, Ordering::Release);
            // The supervising task also retains its pre-admitted process and
            // namespace slots on abnormal destruction, bounding this retained
            // ownership even if the caller drops every public handle.
            std::mem::forget(Arc::clone(&self.shared));
        }
        self.clear_installs();
    }
}

pub(super) struct InFlightInstall {
    live: AtomicBool,
    group: [u8; 32],
    device: [u8; 32],
    selectors: [u8; 32],
    desired: [u8; 32],
    pending: SelectorOperationStampCoordinate,
    terminal: SelectorOperationStampCoordinate,
}

impl InFlightInstall {
    pub(super) fn matches(&self, expected: &SelectorOperationStampInventoryExpectation) -> bool {
        self.live.load(Ordering::Acquire)
            && self.group == expected.group_fingerprint
            && self.device == expected.device_fingerprint
            && self.selectors == expected.selector_set_fingerprint
            && self.desired == expected.desired_fingerprint
            && matches!(expected.lifecycle,
                SelectorOperationStampLifecycleExpectation::Installing { pending, terminal, .. }
                    if pending == self.pending && terminal == self.terminal)
    }
}
