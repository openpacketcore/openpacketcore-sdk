//! One execution's shared lane owner and bounded terminal-delivery state.

use super::*;
use crate::scope_authority::CommittedScopeAuthority;
use crate::scope_scheduler::{
    ScopeLane, ScopeLaneGuard, ScopeScheduler, ScopeSchedulerError, ScopeSchedulerKey,
    ScopeWorkClass, ScopeWorkReservation,
};
use crate::SessionConsumerIdentity;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, MutexGuard, OnceLock, Weak,
};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Notify, OnceCell};

mod reservation;
mod supervisor;
pub use reservation::{ScopeBatchBuildContext, ScopeBatchReservation};

fn scheduler_error(error: ScopeSchedulerError) -> ScopeBatchError {
    match error {
        ScopeSchedulerError::Closed => ScopeBatchError::Unavailable,
        ScopeSchedulerError::ScopeMismatch => ScopeBatchError::InvalidRequest,
        ScopeSchedulerError::SafetyControlOnDataLane => ScopeAuthorityError::Unauthorized.into(),
    }
}

/// Trusted authenticated access to one execution's scope service. The coordinator
/// alone owns the replay lane and resident reservation; adapters must not reserve
/// either again. Carry the supplied effective class through independent transport
/// capacity, outside canonical request bytes. A transport must authenticate the
/// peer and response; decoding a claim alone never proves committed application.
#[async_trait]
pub trait ScopeBatchPort: Send + Sync {
    /// Return authority and every lane from one backend snapshot after a full
    /// current-configuration read barrier. Never synthesize a missing ledger.
    async fn reopen(&self, class: ScopeWorkClass) -> Result<ScopeBatchReopen, ScopeBatchError>;
    /// Submit the unchanged exact request under the supplied effective class.
    /// An ambiguous response must remain OutcomeUnknown or Unavailable.
    async fn apply(
        &self,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError>;
    /// Race cancellation against apply for this complete original attempt.
    async fn cancel(
        &self,
        attempt: &ScopeBatchAttempt,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError>;
}

struct StoreBackend {
    store: ScopeBatchStore,
    authenticated: SessionConsumerIdentity,
}
#[async_trait]
impl ScopeBatchPort for StoreBackend {
    async fn reopen(&self, _class: ScopeWorkClass) -> Result<ScopeBatchReopen, ScopeBatchError> {
        // Untimed scope reads use the complete ReadIndex round, with no TTL or
        // Maintenance proposal. The caller already holds its running credit.
        self.store.reopen(&self.authenticated).await
    }
    async fn apply(
        &self,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        self.store
            .execute_classified(&self.authenticated, request, class)
            .await
    }
    async fn cancel(
        &self,
        attempt: &ScopeBatchAttempt,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        self.store
            .cancel_classified(&self.authenticated, attempt, class)
            .await
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

struct Control {
    cancelled: AtomicBool,
    changed: Notify,
    result: watch::Sender<Option<ScopeBatchCompletion>>,
    acknowledged: watch::Sender<bool>,
}
impl Control {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            changed: Notify::new(),
            result: watch::channel(None).0,
            acknowledged: watch::channel(false).0,
        })
    }
}

struct Slot {
    attempt: ScopeBatchAttempt,
    binding: [u8; 32],
    guard: Arc<ScopeLaneGuard>,
    control: Arc<Control>,
    request: Option<Arc<ScopeBatchRequest>>,
    terminal: Option<ScopeBatchCompletion>,
    last_error: Option<ScopeBatchError>,
    unresolved_since: Option<Instant>,
    // An explicit final scheduler close cannot unaccount accepted unknown bytes.
    // The owner must drain supervisors before final close. This is retained even
    // when no further running credit can be obtained from the closed scheduler.
    _retained_resident: Option<ScopeWorkReservation>,
    // Retain accepted work and unacknowledged results even if every original
    // caller disappears. Only exact ack breaks this bounded per-lane cycle.
    _owner: Arc<Inner>,
}

#[derive(Default)]
struct State {
    slots: [Option<Slot>; SCOPE_BATCH_LANES],
    ages: progress::CompletionAges,
    // Acknowledgement clears a local slot, not the last observed stored receipt.
    receipt_ids: [Option<[u8; 16]>; SCOPE_BATCH_LANES],
}

struct Inner {
    stamp: ScopeAuthorityStamp,
    scheduler: ScopeScheduler,
    key: ScopeSchedulerKey,
    lanes: [ScopeLane; SCOPE_BATCH_LANES],
    backend: Mutex<Arc<dyn ScopeBatchPort>>,
    state: Mutex<State>,
    ready: OnceCell<()>,
    changed: Notify,
}
impl Inner {
    fn backend(&self) -> Arc<dyn ScopeBatchPort> {
        Arc::clone(&lock(&self.backend))
    }
    async fn initialize(self: &Arc<Self>, cut: &ScopeBatchReopen) -> Result<(), ScopeBatchError> {
        let view = cut.check_stamp(&self.stamp)?;
        let mut state = State::default();
        for (index, lane) in view.lanes().iter().enumerate() {
            let Some(receipt) = lane.receipt().cloned() else {
                continue;
            };
            let completion = ScopeBatchCompletion::from_receipt(receipt)?;
            let attempt = completion.attempt.clone();
            state.receipt_ids[index] = Some(*attempt.request_id());
            let binding = attempt.key()?.binding_digest;
            let control = Control::new();
            control.result.send_replace(Some(completion.clone()));
            let class = if index == 7 {
                ScopeWorkClass::Emergency
            } else {
                ScopeWorkClass::Maintenance
            };
            let guard = Arc::new(
                self.lanes[index]
                    .acquire(class)
                    .await
                    .map_err(scheduler_error)?,
            );
            state
                .ages
                .observe(index as u8, binding, Instant::now())
                .map_err(|_| ScopeBatchError::FormatMismatch)?;
            state.slots[index] = Some(Slot {
                attempt,
                binding,
                guard,
                control,
                request: None,
                terminal: Some(completion),
                last_error: None,
                unresolved_since: None,
                _retained_resident: None,
                _owner: Arc::clone(self),
            });
        }
        *lock(&self.state) = state;
        Ok(())
    }
}

/// Shared producer for one admitted execution. Factories and reconnects for the
/// same complete stamp reuse its arbitration and pending work. Dropping a clone
/// or a submitted observer never acknowledges or abandons an accepted attempt.
#[derive(Clone)]
pub struct ScopeBatchCoordinator {
    inner: Arc<Inner>,
}

impl ScopeBatchCoordinator {
    /// Bind authenticated service access and one global scheduler to the current
    /// committed execution. Recovered receipts block their lanes until reconciled
    /// through `completions` and exact `ack`; opening grants no new authority.
    pub async fn open(
        store: ScopeBatchStore,
        authenticated: SessionConsumerIdentity,
        authority: &CommittedScopeAuthority,
        scheduler: ScopeScheduler,
    ) -> Result<Self, ScopeBatchError> {
        if store.namespace() != authority.stamp().namespace()
            || authority.stamp().execution().identity() != &authenticated
        {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        Self::open_port(
            Arc::new(StoreBackend {
                store,
                authenticated,
            }),
            authority,
            scheduler,
            ScopeWorkClass::Normal,
        )
        .await
    }

    /// Use an authenticated local or remote adapter with this same coordinator.
    /// `class` controls only the opening observation; each reservation supplies
    /// its own later class. Reconnection updates the port while retaining lanes,
    /// pending exact requests, original entitlements and unacknowledged results.
    /// The existing committed capability is checked, never created from the read.
    pub async fn open_port(
        port: Arc<dyn ScopeBatchPort>,
        authority: &CommittedScopeAuthority,
        scheduler: ScopeScheduler,
        class: ScopeWorkClass,
    ) -> Result<Self, ScopeBatchError> {
        Self::open_with_backend(authority.stamp().clone(), scheduler, port, class).await
    }

    pub(super) async fn open_with_backend(
        stamp: ScopeAuthorityStamp,
        scheduler: ScopeScheduler,
        backend: Arc<dyn ScopeBatchPort>,
        class: ScopeWorkClass,
    ) -> Result<Self, ScopeBatchError> {
        if class == ScopeWorkClass::SafetyControl {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        stamp.validate()?;
        let cut = backend.reopen(class).await?;
        cut.check_stamp(&stamp)?;
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope-batch/coordinator/v4\0");
        hash.update(postcard::to_allocvec(&stamp).map_err(|_| ScopeBatchError::InvalidRequest)?);
        let identity: [u8; 32] = hash.finalize().into();
        static REGISTRY: OnceLock<Mutex<HashMap<[u8; 32], Weak<Inner>>>> = OnceLock::new();
        let inner = {
            let mut registry = lock(REGISTRY.get_or_init(Mutex::default));
            registry.retain(|_, inner| inner.strong_count() != 0);
            if let Some(inner) = registry.get(&identity).and_then(Weak::upgrade) {
                inner
            } else {
                let key = crate::ConsensusSessionStore::scope_batch_scheduler_key(stamp.scope());
                let inner = Arc::new(Inner {
                    stamp,
                    scheduler,
                    key,
                    lanes: std::array::from_fn(|_| ScopeLane::new(key)),
                    backend: Mutex::new(Arc::clone(&backend)),
                    state: Mutex::new(State::default()),
                    ready: OnceCell::new(),
                    changed: Notify::new(),
                });
                registry.insert(identity, Arc::downgrade(&inner));
                inner
            }
        };
        *lock(&inner.backend) = backend;
        inner
            .ready
            .get_or_try_init(|| inner.initialize(&cut))
            .await?;
        Ok(Self { inner })
    }

    /// Read a bounded stream that redelivers terminal results until exact ack.
    pub fn completions(&self) -> ScopeBatchCompletions {
        ScopeBatchCompletions {
            inner: Arc::clone(&self.inner),
            cursor: 0,
        }
    }

    /// Acknowledge only after reconciling this exact terminal attempt's durable
    /// child/intent state. A stale, altered or still-pending attempt cannot release
    /// the lane. This operation is local and adds no consensus command.
    pub fn ack(&self, attempt: &ScopeBatchAttempt) -> bool {
        let removed = {
            let mut state = lock(&self.inner.state);
            let Some(slot) = state
                .slots
                .get(usize::from(attempt.lane()))
                .and_then(Option::as_ref)
            else {
                return false;
            };
            if slot.attempt != *attempt || slot.terminal.is_none() {
                return false;
            }
            let binding = slot.binding;
            if !state.ages.ack(attempt.lane(), &binding) {
                return false;
            }
            state.slots[usize::from(attempt.lane())].take()
        };
        if let Some(slot) = removed {
            slot.control.acknowledged.send_replace(true);
            drop(slot);
        }
        self.inner.changed.notify_waiters();
        true
    }

    /// Fixed-cardinality lane diagnostics. Ages measure local submission or
    /// terminal observation and never expire a result or authorize lane reuse.
    pub fn lane_status(&self) -> [ScopeBatchLaneStatus; SCOPE_BATCH_LANES] {
        let state = lock(&self.inner.state);
        let now = Instant::now();
        let ages = state.ages.ages(now);
        std::array::from_fn(|index| ScopeBatchLaneStatus {
            occupied: state.slots[index].is_some(),
            oldest_unacknowledged: ages[index],
            unresolved_for: state.slots[index]
                .as_ref()
                .and_then(|slot| slot.unresolved_since)
                .map(|since| now.saturating_duration_since(since)),
            last_error: state.slots[index]
                .as_ref()
                .and_then(|slot| slot.last_error.clone()),
        })
    }
}

/// Diagnostic per-lane observations without request or scope labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeBatchLaneStatus {
    /// Accepted work or a recovered terminal result still owns this lane.
    pub occupied: bool,
    /// Age since first local terminal observation; redelivery never resets it.
    pub oldest_unacknowledged: Option<Duration>,
    /// Age since local submission while no terminal result is known. This
    /// survives reconnection and also exposes permanent scheduler closure.
    pub unresolved_for: Option<Duration>,
    /// Latest unresolved local failure. This does not authorize lane reuse.
    pub last_error: Option<ScopeBatchError>,
}

/// Bounded at-least-once stream over the execution's eight retained results.
pub struct ScopeBatchCompletions {
    inner: Arc<Inner>,
    cursor: usize,
}
impl ScopeBatchCompletions {
    /// Wait for a terminal result, retaining it until exact acknowledgement.
    /// Dropping this stream neither clears results nor cancels supervisors.
    pub async fn next(&mut self) -> ScopeBatchCompletion {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = lock(&self.inner.state);
                for offset in 0..SCOPE_BATCH_LANES {
                    let index = (self.cursor + offset) % SCOPE_BATCH_LANES;
                    if let Some(result) = state.slots[index]
                        .as_ref()
                        .and_then(|slot| slot.terminal.clone())
                    {
                        self.cursor = (index + 1) % SCOPE_BATCH_LANES;
                        return result;
                    }
                }
            }
            changed.await;
        }
    }
}

/// An observer of supervised work. Dropping it detaches only the observer.
pub struct ScopeBatchHandle {
    attempt: ScopeBatchAttempt,
    control: Arc<Control>,
}
impl ScopeBatchHandle {
    /// Exact immutable submitted identity, retained by the supervisor too.
    pub const fn attempt(&self) -> &ScopeBatchAttempt {
        &self.attempt
    }
    /// Request cancellation; apply may already have won. Only the terminal
    /// completion says which result committed, and explicit ack is still required.
    pub fn cancel(&self) -> bool {
        if self.control.result.borrow().is_some() {
            return false;
        }
        self.control.cancelled.store(true, Ordering::Release);
        self.control.changed.notify_one();
        true
    }
    /// Wait for the exact terminal result, including after another observer's ack.
    pub async fn completion(&self) -> ScopeBatchCompletion {
        let mut result = self.control.result.subscribe();
        loop {
            if let Some(result) = result.borrow_and_update().clone() {
                return result;
            }
            result
                .changed()
                .await
                .expect("the handle retains the completion sender");
        }
    }
    async fn acknowledged(&self) {
        let mut acknowledged = self.control.acknowledged.subscribe();
        while !*acknowledged.borrow_and_update() {
            acknowledged
                .changed()
                .await
                .expect("the handle retains the acknowledgement sender");
        }
    }
}

impl fmt::Debug for ScopeBatchCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchCoordinator(<redacted>)")
    }
}
impl fmt::Debug for ScopeBatchCompletions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchCompletions(<redacted>)")
    }
}
impl fmt::Debug for ScopeBatchHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchHandle(<redacted>)")
    }
}
