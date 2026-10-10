//! Scope-aware backpressure and shared-lane arbitration (RFC 024).
//!
//! Capacity always waits. Each class has independent resident and running
//! credits; an unresolved operation keeps its resident entitlement between
//! bounded attempts. Reserve resident capacity before acquiring a shared replay
//! lane; the exclusive Emergency lane takes its lane first. Build only after
//! both grants and a running credit.
//! The service supervisor, not a cancellable observer, must own dispatched
//! permits through local attempt completion and lanes through exact resolution.
//! Scheduling never grants store authority or changes canonical request bytes.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

mod lane;
pub use lane::{ScopeLane, ScopeLaneGuard};

/// Processing class, chosen from an authenticated operation and session state.
/// Emergency is a whole-session property, never inferred from a bearer's ARP.
/// Unknown/unverified work uses its separate classification budget. MPS is not
/// yet classified; see RFC 024's explicit specification gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[non_exhaustive]
pub enum ScopeWorkClass {
    /// Authorized retirement, handoff and bounded control prerequisites.
    SafetyControl,
    /// Every procedure on a positively established emergency session.
    Emergency,
    /// Bounded classification or unverified emergency work.
    EmergencyClassification,
    /// Positively classified ordinary foreground work, including attaches.
    Normal,
    /// Bounded bulk recovery, scan and maintenance steps.
    Maintenance,
}

impl ScopeWorkClass {
    /// Explicit scheduling rank: lower values run first at a shared lane.
    /// This rank is independent of the class's stable serialized tag.
    pub const fn priority_rank(self) -> u8 {
        match self {
            Self::SafetyControl => 0,
            Self::Emergency => 10,
            Self::EmergencyClassification => 20,
            Self::Normal => 30,
            Self::Maintenance => 40,
        }
    }

    pub(crate) const ALL: [Self; 5] = [
        Self::SafetyControl,
        Self::Emergency,
        Self::EmergencyClassification,
        Self::Normal,
        Self::Maintenance,
    ];

    const fn index(self) -> usize {
        match self {
            Self::SafetyControl => 0,
            Self::Emergency => 1,
            Self::EmergencyClassification => 2,
            Self::Normal => 3,
            Self::Maintenance => 4,
        }
    }
}

impl Ord for ScopeWorkClass {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority_rank().cmp(&other.priority_rank())
    }
}

impl PartialOrd for ScopeWorkClass {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// These revision-6 tags are append-only, regardless of declaration or priority
// order. A future class can have a new tag and any explicit scheduling rank.
impl From<ScopeWorkClass> for u8 {
    fn from(class: ScopeWorkClass) -> Self {
        match class {
            ScopeWorkClass::SafetyControl => 0,
            ScopeWorkClass::Emergency => 1,
            ScopeWorkClass::EmergencyClassification => 2,
            ScopeWorkClass::Normal => 3,
            ScopeWorkClass::Maintenance => 4,
        }
    }
}

impl TryFrom<u8> for ScopeWorkClass {
    type Error = &'static str;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::SafetyControl),
            1 => Ok(Self::Emergency),
            2 => Ok(Self::EmergencyClassification),
            3 => Ok(Self::Normal),
            4 => Ok(Self::Maintenance),
            _ => Err("unknown scope work class tag"),
        }
    }
}

/// Opaque stable-scope key for fairness, not authentication or authority.
/// Derive it from the admitted scope; a different key per request defeats
/// fairness. Keys are process-local metadata and are never logged by this API.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopeSchedulerKey {
    bytes: [u8; 32],
    internal: bool,
}

impl ScopeSchedulerKey {
    /// Supply the stable scope's fixed-size, opaque identity/commitment.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            internal: false,
        }
    }

    // Aggregate store-internal work is not one tenant. This marker cannot be
    // constructed by a producer, even by supplying an all-zero public key.
    pub(crate) const INTERNAL: Self = Self {
        bytes: [0; 32],
        internal: true,
    };
}

impl fmt::Debug for ScopeSchedulerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeSchedulerKey(<redacted>)")
    }
}

/// Concurrent resource budgets, never a session or lifetime attach quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassBudget {
    /// Resident descriptors, including running and unresolved retry work.
    pub queued: usize,
    /// Simultaneously running bounded attempts/pages.
    pub running: usize,
}

/// Independent named pools. No class borrows another's resident capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScopeSchedulerBudgets {
    /// Authorized control operations.
    pub safety_control: ClassBudget,
    /// Established emergency sessions.
    pub emergency: ClassBudget,
    /// Unknown/unverified work, isolated from established emergencies.
    pub emergency_classification: ClassBudget,
    /// Ordinary foreground work.
    pub normal: ClassBudget,
    /// Bounded bulk recovery and housekeeping.
    pub maintenance: ClassBudget,
}

impl Default for ScopeSchedulerBudgets {
    fn default() -> Self {
        Self {
            safety_control: ClassBudget {
                queued: 8,
                running: 1,
            },
            emergency: ClassBudget {
                queued: 16,
                running: 2,
            },
            emergency_classification: ClassBudget {
                queued: 8,
                running: 1,
            },
            normal: ClassBudget {
                queued: 24,
                running: 8,
            },
            maintenance: ClassBudget {
                queued: 8,
                running: 1,
            },
        }
    }
}

impl ScopeSchedulerBudgets {
    /// Configure one named class while retaining defaults for future classes.
    pub fn with_budget(mut self, class: ScopeWorkClass, budget: ClassBudget) -> Self {
        match class {
            ScopeWorkClass::SafetyControl => self.safety_control = budget,
            ScopeWorkClass::Emergency => self.emergency = budget,
            ScopeWorkClass::EmergencyClassification => self.emergency_classification = budget,
            ScopeWorkClass::Normal => self.normal = budget,
            ScopeWorkClass::Maintenance => self.maintenance = budget,
        }
        self
    }

    /// Budget for one processing class.
    pub const fn class(&self, class: ScopeWorkClass) -> ClassBudget {
        match class {
            ScopeWorkClass::SafetyControl => self.safety_control,
            ScopeWorkClass::Emergency => self.emergency,
            ScopeWorkClass::EmergencyClassification => self.emergency_classification,
            ScopeWorkClass::Normal => self.normal,
            ScopeWorkClass::Maintenance => self.maintenance,
        }
    }
}

/// Invalid process-local resource configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// All resident and running pools must have positive capacity.
    #[error("scope scheduler capacity must be positive")]
    ZeroCapacity,
    /// Running descriptors also retain resident credits.
    #[error("resident capacity must cover running capacity")]
    ResidentBelowRunning,
    /// Capacity exceeds the synchronization primitive's supported limit.
    #[error("scope scheduler capacity exceeds supported limit")]
    CapacityTooLarge,
}

/// Explicit shutdown or invalid composition; saturation is never an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeSchedulerError {
    /// This invocation did not dispatch. A prior attempt may remain unknown.
    #[error("scope scheduler is closed")]
    Closed,
    /// A lane and its reservation must belong to the same admitted scope.
    #[error("scope scheduler lane belongs to another scope")]
    ScopeMismatch,
    /// Data lanes cannot carry authority control work or inherit its capacity.
    #[error("SafetyControl cannot use a data lane")]
    SafetyControlOnDataLane,
}

/// An undispatched start failure that retains the original resident entitlement.
/// Recover it for exact outcome resolution; dropping this error drops that
/// entitlement and must be an explicit decision by the supervising owner.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
#[must_use = "recover the retained reservation before abandoning unresolved work"]
pub struct ScopeWorkStartError {
    #[source]
    error: ScopeSchedulerError,
    reservation: ScopeWorkReservation,
}

impl ScopeWorkStartError {
    /// Reason this attempt did not dispatch.
    pub const fn error(&self) -> ScopeSchedulerError {
        self.error
    }

    /// Recover the same resident entitlement without reserving again.
    pub fn into_reservation(self) -> ScopeWorkReservation {
        self.reservation
    }
}

/// Observational counts for one class; no request or scope labels.
/// A concurrent snapshot is not a transaction and must not govern safety.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScopeClassSnapshot {
    /// Resident entitlements, including running and unresolved work.
    pub resident: usize,
    /// Running attempts charged to this effective class after inheritance.
    pub running: usize,
    /// Producers awaiting either a per-scope or global resident credit.
    pub reserve_waiting: usize,
    /// Ready attempts awaiting either a per-scope or global running credit.
    pub start_waiting: usize,
}

/// Aggregate fixed-cardinality snapshot without scope or request identities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScopeSchedulerSnapshot([ScopeClassSnapshot; 5]);

impl ScopeSchedulerSnapshot {
    /// Read the counters of one processing class.
    pub const fn class(&self, class: ScopeWorkClass) -> ScopeClassSnapshot {
        self.0[class.index()]
    }
}

#[derive(Default)]
struct Counters {
    resident: AtomicUsize,
    running: AtomicUsize,
    reserve_waiting: AtomicUsize,
    start_waiting: AtomicUsize,
}

#[derive(Clone, Copy)]
enum Counter {
    Resident,
    Running,
    ReserveWaiting,
    StartWaiting,
}

impl Counters {
    fn counter(&self, kind: Counter) -> &AtomicUsize {
        match kind {
            Counter::Resident => &self.resident,
            Counter::Running => &self.running,
            Counter::ReserveWaiting => &self.reserve_waiting,
            Counter::StartWaiting => &self.start_waiting,
        }
    }

    fn snapshot(&self) -> ScopeClassSnapshot {
        ScopeClassSnapshot {
            resident: self.resident.load(Ordering::Relaxed),
            running: self.running.load(Ordering::Relaxed),
            reserve_waiting: self.reserve_waiting.load(Ordering::Relaxed),
            start_waiting: self.start_waiting.load(Ordering::Relaxed),
        }
    }
}

struct Counted {
    counters: Arc<Counters>,
    kind: Counter,
}

impl Counted {
    fn new(counters: &Arc<Counters>, kind: Counter) -> Self {
        counters.counter(kind).fetch_add(1, Ordering::Relaxed);
        Self {
            counters: Arc::clone(counters),
            kind,
        }
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.counters
            .counter(self.kind)
            .fetch_sub(1, Ordering::Relaxed);
    }
}

struct ClassPool {
    resident: Arc<Semaphore>,
    running: Arc<Semaphore>,
    counters: Arc<Counters>,
}

struct Inner {
    budgets: ScopeSchedulerBudgets,
    classes: [ClassPool; 5],
    scopes: Mutex<BTreeMap<ScopeSchedulerKey, Weak<ScopePools>>>,
}

struct ScopePools {
    inner: Weak<Inner>,
    key: ScopeSchedulerKey,
    resident: [Arc<Semaphore>; 5],
    running: [Arc<Semaphore>; 5],
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Drop for ScopePools {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut registry = lock(&inner.scopes);
            // A concurrent caller can replace an expired Weak before this
            // destructor acquires the lock. Never remove its new registry entry.
            if registry
                .get(&self.key)
                .is_some_and(|entry| std::ptr::eq(entry.as_ptr(), self))
            {
                registry.remove(&self.key);
            }
        }
    }
}

impl Inner {
    fn scope(self: &Arc<Self>, key: ScopeSchedulerKey) -> Arc<ScopePools> {
        let mut registry = lock(&self.scopes);
        if let Some(scope) = registry.get(&key).and_then(Weak::upgrade) {
            return scope;
        }
        let cap = |budget: usize| {
            if key.internal {
                budget
            } else {
                budget.div_ceil(2)
            }
        };
        let scope = Arc::new(ScopePools {
            inner: Arc::downgrade(self),
            key,
            resident: std::array::from_fn(|i| {
                let semaphore = Arc::new(Semaphore::new(cap(self
                    .budgets
                    .class(ScopeWorkClass::ALL[i])
                    .queued)));
                if self.classes[i].resident.is_closed() {
                    semaphore.close();
                }
                semaphore
            }),
            running: std::array::from_fn(|i| {
                let semaphore = Arc::new(Semaphore::new(cap(self
                    .budgets
                    .class(ScopeWorkClass::ALL[i])
                    .running)));
                if self.classes[i].running.is_closed() {
                    semaphore.close();
                }
                semaphore
            }),
        });
        registry.insert(key, Arc::downgrade(&scope));
        scope
    }

    fn close(&self, final_close: bool) {
        for class in ScopeWorkClass::ALL {
            if final_close || class != ScopeWorkClass::SafetyControl {
                self.classes[class.index()].resident.close();
            }
            if final_close {
                self.classes[class.index()].running.close();
            }
        }
        // Never drop the last strong scope reference under the registry lock:
        // its destructor removes the expired registry entry using that lock.
        let scopes: Vec<_> = lock(&self.scopes)
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for scope in scopes {
            for class in ScopeWorkClass::ALL {
                if final_close || class != ScopeWorkClass::SafetyControl {
                    scope.resident[class.index()].close();
                }
                if final_close {
                    scope.running[class.index()].close();
                }
            }
        }
    }
}

/// Unique shutdown capability. Dropping it does not cancel accepted work or
/// implicitly close producer clones; shutdown must be explicit and supervised.
pub struct ScopeSchedulerOwner {
    inner: Arc<Inner>,
}

impl Default for ScopeSchedulerOwner {
    fn default() -> Self {
        Self::from_validated_budgets(ScopeSchedulerBudgets::default())
    }
}

impl ScopeSchedulerOwner {
    /// Validate resource bounds and create a fresh process-local scheduler.
    pub fn new(budgets: ScopeSchedulerBudgets) -> Result<Self, ConfigError> {
        for class in ScopeWorkClass::ALL {
            let budget = budgets.class(class);
            if budget.queued == 0 || budget.running == 0 {
                return Err(ConfigError::ZeroCapacity);
            }
            if budget.queued < budget.running {
                return Err(ConfigError::ResidentBelowRunning);
            }
            if budget.queued > Semaphore::MAX_PERMITS || budget.running > Semaphore::MAX_PERMITS {
                return Err(ConfigError::CapacityTooLarge);
            }
        }
        Ok(Self::from_validated_budgets(budgets))
    }

    fn from_validated_budgets(budgets: ScopeSchedulerBudgets) -> Self {
        Self {
            inner: Arc::new(Inner {
                budgets,
                classes: std::array::from_fn(|i| {
                    let budget = budgets.class(ScopeWorkClass::ALL[i]);
                    ClassPool {
                        resident: Arc::new(Semaphore::new(budget.queued)),
                        running: Arc::new(Semaphore::new(budget.running)),
                        counters: Arc::new(Counters::default()),
                    }
                }),
                scopes: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Clone a producer with no shutdown authority.
    pub fn scheduler(&self) -> ScopeScheduler {
        ScopeScheduler {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Stop new non-control reservations. Existing entitlements may finish or
    /// retry, and SafetyControl remains available for a final committed Close.
    pub fn quiesce(&self) {
        self.inner.close(false);
    }

    /// Wake all undispatched work. Running permits remain owned until their
    /// supervisors finish; this method neither cancels nor disproves effects.
    pub fn close(&self) {
        self.inner.close(true);
    }
}

/// Clonable producer sharing all class and scope budgets.
/// Producers have no shutdown capability:
/// ```compile_fail
/// use opc_session_store::scope_scheduler::{ScopeSchedulerOwner, ScopeSchedulerBudgets};
/// let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default()).unwrap();
/// owner.scheduler().close();
/// ```
#[derive(Clone)]
pub struct ScopeScheduler {
    inner: Arc<Inner>,
}

impl ScopeScheduler {
    #[cfg(test)]
    pub(crate) fn available_running(&self, class: ScopeWorkClass) -> usize {
        self.inner.classes[class.index()]
            .running
            .available_permits()
    }

    /// Wait before materializing a full request. Reserve before acquiring a
    /// shared replay lane; the exclusive Emergency lane acquires its lane first.
    /// Waiting callers need an upstream bound; they retain only fixed metadata.
    pub async fn reserve(
        &self,
        key: ScopeSchedulerKey,
        class: ScopeWorkClass,
    ) -> Result<ScopeWorkReservation, ScopeSchedulerError> {
        let scope = self.inner.scope(key);
        let pool = &self.inner.classes[class.index()];
        let _waiting = Counted::new(&pool.counters, Counter::ReserveWaiting);
        let scoped = Arc::clone(&scope.resident[class.index()])
            .acquire_owned()
            .await
            .map_err(|_| ScopeSchedulerError::Closed)?;
        let global = Arc::clone(&pool.resident)
            .acquire_owned()
            .await
            .map_err(|_| ScopeSchedulerError::Closed)?;
        Ok(ScopeWorkReservation {
            inner: Arc::clone(&self.inner),
            scope,
            class,
            _resident: Counted::new(&pool.counters, Counter::Resident),
            _scoped: scoped,
            _global: global,
        })
    }

    /// Read fixed-cardinality observational counts; these are not authority.
    pub fn snapshot(&self) -> ScopeSchedulerSnapshot {
        ScopeSchedulerSnapshot(std::array::from_fn(|i| {
            self.inner.classes[i].counters.snapshot()
        }))
    }
}

/// One affine resident entitlement, retained until the operation is resolved.
pub struct ScopeWorkReservation {
    _resident: Counted,
    _scoped: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
    inner: Arc<Inner>,
    class: ScopeWorkClass,
    // Drop the per-scope registry owner only after its permits are returned.
    scope: Arc<ScopePools>,
}

impl ScopeWorkReservation {
    /// Original resident class; inheritance never changes the retained bytes.
    pub const fn class(&self) -> ScopeWorkClass {
        self.class
    }

    /// Join this class's fair ready queue for one bounded local attempt.
    /// On failure the returned error retains this reservation.
    pub async fn start(self) -> Result<ScopeWorkPermit, ScopeWorkStartError> {
        let running = match self.acquire_running(self.class).await {
            Ok(running) => running,
            Err(error) => return Err(self.start_error(error)),
        };
        Ok(ScopeWorkPermit {
            reservation: self,
            running,
        })
    }

    /// Start a lane holder's bounded attempt, inheriting the highest trusted
    /// waiter while it waits for capacity. A running attempt is not preempted.
    /// SafetyControl never uses a data lane. Every failure returns this
    /// reservation in the error, including a mismatched scope.
    pub async fn start_in_lane(
        self,
        lane: &ScopeLaneGuard,
    ) -> Result<ScopeWorkPermit, ScopeWorkStartError> {
        if self.scope.key != lane.scope_key() {
            return Err(self.start_error(ScopeSchedulerError::ScopeMismatch));
        }
        if self.class == ScopeWorkClass::SafetyControl {
            return Err(self.start_error(ScopeSchedulerError::SafetyControlOnDataLane));
        }
        loop {
            let class = lane.effective_class(self.class);
            let running = tokio::select! {
                biased;
                _ = lane.wait_for_class_change(self.class, class) => continue,
                result = self.acquire_running(class) => result,
            };
            let running = match running {
                Ok(running) => running,
                Err(error) => return Err(self.start_error(error)),
            };
            return Ok(ScopeWorkPermit {
                reservation: self,
                running,
            });
        }
    }

    fn start_error(self, error: ScopeSchedulerError) -> ScopeWorkStartError {
        ScopeWorkStartError {
            error,
            reservation: self,
        }
    }

    async fn acquire_running(&self, class: ScopeWorkClass) -> Result<Running, ScopeSchedulerError> {
        let pool = &self.inner.classes[class.index()];
        let _waiting = Counted::new(&pool.counters, Counter::StartWaiting);
        let scoped = Arc::clone(&self.scope.running[class.index()])
            .acquire_owned()
            .await
            .map_err(|_| ScopeSchedulerError::Closed)?;
        let global = Arc::clone(&pool.running)
            .acquire_owned()
            .await
            .map_err(|_| ScopeSchedulerError::Closed)?;
        Ok(Running {
            class,
            _counted: Counted::new(&pool.counters, Counter::Running),
            _scoped: scoped,
            _global: global,
            _scope: Arc::clone(&self.scope),
        })
    }
}

struct Running {
    class: ScopeWorkClass,
    _counted: Counted,
    _scoped: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
    // Also pin the scope during permit destruction, independently of the
    // resident field's destruction order. A live credit never gets a new cap.
    _scope: Arc<ScopePools>,
}

/// One bounded running attempt. Keep this in the operation supervisor when an
/// observer cancels; drop only on definitive local completion, or retain the
/// resident entitlement with [`Self::finish_unknown`] for outcome resolution.
pub struct ScopeWorkPermit {
    reservation: ScopeWorkReservation,
    running: Running,
}

impl ScopeWorkPermit {
    /// Effective class charged for this running attempt.
    pub const fn class(&self) -> ScopeWorkClass {
        self.running.class
    }

    /// End the local attempt while retaining the unresolved operation's resident
    /// entitlement. The next attempt rejoins `start`, never `reserve`.
    pub fn finish_unknown(self) -> ScopeWorkReservation {
        drop(self.running);
        self.reservation
    }
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )+ };
}
redacted_debug!(
    ScopeSchedulerOwner,
    ScopeScheduler,
    ScopeWorkReservation,
    ScopeWorkPermit
);

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::poll;

    #[tokio::test]
    async fn running_credit_keeps_scope_cap_alive_during_permit_destruction() {
        let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default()).unwrap();
        let scheduler = owner.scheduler();
        let key = ScopeSchedulerKey::from_bytes([1; 32]);
        let permit = scheduler
            .reserve(key, ScopeWorkClass::Emergency)
            .await
            .unwrap()
            .start()
            .await
            .unwrap();
        // A concurrent reserve can race destruction between the resident and
        // running credit releases. It must find the same per-scope semaphore.
        let ScopeWorkPermit {
            reservation,
            running,
        } = permit;
        drop(reservation);
        let next = scheduler
            .reserve(key, ScopeWorkClass::Emergency)
            .await
            .unwrap();
        let mut next = Box::pin(next.start());
        assert!(
            poll!(&mut next).is_pending(),
            "an outstanding running credit still caps its scope"
        );
        drop(running);
        assert!(poll!(&mut next).is_ready());
    }
    #[tokio::test]
    async fn poisoned_registry_recovers_and_finished_scopes_are_reclaimed() {
        let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default()).unwrap();
        let scheduler = owner.scheduler();
        let inner = Arc::clone(&scheduler.inner);
        assert!(std::thread::spawn(move || {
            let _guard = inner.scopes.lock().unwrap();
            panic!("synthetic metadata lock poison");
        })
        .join()
        .is_err());
        for value in 1..=100 {
            let reservation = scheduler
                .reserve(
                    ScopeSchedulerKey::from_bytes([value; 32]),
                    ScopeWorkClass::Normal,
                )
                .await
                .unwrap();
            assert_eq!(lock(&scheduler.inner.scopes).len(), 1);
            drop(reservation.start().await.unwrap());
            assert!(lock(&scheduler.inner.scopes).is_empty());
        }
    }
}
