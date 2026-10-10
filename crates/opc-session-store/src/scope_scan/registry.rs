//! Node-wide ownership and invalidation of retained scope views.
//!
//! Pending requests own resident scheduler credits, never execution permits or backend
//! pins. Register every grant before delivering it, and retain weak lifecycle
//! controls until the actual workers have drained. All destructors, runtime
//! calls and waiter notifications run outside the registry lock.

use std::collections::HashMap;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use tokio::sync::{oneshot, Notify};

use super::activity::ViewInvalidation;
use super::admission::{
    AdmissionError, AdmissionQueue, AdmissionTicket, CaptureCost, RetentionLimits,
};
use super::runtime::{RetainedView, ViewControl, ViewError, WeakViewControl};
use crate::scope_scheduler::{ScopeSchedulerKey, ScopeWorkClass, ScopeWorkReservation};

#[derive(Debug, thiserror::Error)]
pub(crate) enum RegistryError {
    #[error("scope view ended: {0:?}")]
    Ended(ViewInvalidation),
    #[error("scope view admission failed: {0:?}")]
    Admission(AdmissionError),
    #[cfg(any(test, target_os = "linux"))]
    #[error("scope view reservation belongs to another registry or epoch")]
    InvalidReservation,
    #[error("scope view epoch is exhausted")]
    EpochExhausted,
    #[error("scope view replacement has not drained")]
    NotDrained,
    #[error(transparent)]
    Runtime(#[from] ViewError),
}

type Control<C> = ViewControl<C, RetentionLease<C>>;
type WeakControl<C> = WeakViewControl<C, RetentionLease<C>>;

pub(crate) type WalProbe = Arc<dyn Fn() -> BoxFuture<'static, Option<u64>> + Send + Sync>;

pub(crate) struct RegisteredView<C: Send + 'static> {
    pub(crate) runtime: RetainedView<C, RetentionLease<C>>,
    pub(crate) epoch: u64,
    pub(crate) reservation: Reservation<C>,
}

/// A cost-adjustment token, not a capture or an authority capability.
pub(crate) struct Reservation<C: Send + 'static> {
    registry: Weak<ViewRegistry<C>>,
    ticket: AdmissionTicket,
    epoch: u64,
}

impl<C: Send + 'static> Clone for Reservation<C> {
    fn clone(&self) -> Self {
        Self {
            registry: Weak::clone(&self.registry),
            ticket: self.ticket,
            epoch: self.epoch,
        }
    }
}

// The runtime declares capture destruction before this lease's destructor.
pub(crate) struct RetentionLease<C: Send + 'static> {
    registry: Arc<ViewRegistry<C>>,
    ticket: AdmissionTicket,
}

impl<C: Send + 'static> Drop for RetentionLease<C> {
    fn drop(&mut self) {
        lock(&self.registry.state).queue.release(self.ticket);
        self.registry.changed.notify_waiters();
        #[cfg(test)]
        {
            let hook = lock(&self.registry.after_release).take();
            if let Some(hook) = hook {
                hook();
            }
        }
        self.registry.drive();
    }
}

struct Pending<C: Send + 'static> {
    capture: C,
    resident: ScopeWorkReservation,
    sender: oneshot::Sender<Result<RegisteredView<C>, RegistryError>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Open,
    Replacing,
    Closed,
}

struct State<C: Send + 'static> {
    epoch: u64,
    mode: Mode,
    reason: ViewInvalidation,
    queue: AdmissionQueue<ScopeSchedulerKey, Pending<C>>,
    controls: HashMap<AdmissionTicket, WeakControl<C>>,
    wal_bytes: Option<u64>,
    driving: bool,
}

type RegistryMetrics = super::ScopeScanMetrics;

pub(crate) struct ViewRegistry<C: Send + 'static> {
    state: Mutex<State<C>>,
    wal_probe: Mutex<Option<WalProbe>>,
    idle_timeout: Duration,
    changed: Notify,
    cleanup_running: AtomicBool,
    #[cfg(test)]
    before_registration: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    after_release: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<C: Send + 'static> ViewRegistry<C> {
    pub(crate) fn new(
        limits: RetentionLimits,
        idle_timeout: Duration,
    ) -> Result<Arc<Self>, RegistryError> {
        if idle_timeout.is_zero() {
            return Err(ViewError::InvalidIdleTimeout.into());
        }
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                epoch: 1,
                mode: Mode::Open,
                reason: ViewInvalidation::BackendRestarted,
                queue: AdmissionQueue::new(limits),
                controls: HashMap::new(),
                wal_bytes: None,
                driving: false,
            }),
            idle_timeout,
            wal_probe: Mutex::new(None),
            changed: Notify::new(),
            cleanup_running: AtomicBool::new(false),
            #[cfg(test)]
            before_registration: Mutex::new(None),
            #[cfg(test)]
            after_release: Mutex::new(None),
        }))
    }

    /// `capture` is an empty backend slot. Only the admitted opening worker
    /// may acquire a root or transaction and populate it.
    pub(crate) async fn admit(
        self: &Arc<Self>,
        scope: ScopeSchedulerKey,
        cost: CaptureCost,
        capture: C,
        resident: ScopeWorkReservation,
    ) -> Result<RegisteredView<C>, RegistryError> {
        if resident.class() != ScopeWorkClass::Normal {
            return Err(ViewError::WrongClass.into());
        }
        let epoch = self.current_epoch().ok_or_else(|| self.ended())?;
        let mut refresh = pin!(self.refresh_wal());
        loop {
            let mut changed = pin!(self.changed.notified());
            changed.as_mut().enable();
            if !self.is_current(epoch) {
                return Err(self.ended());
            }
            tokio::select! {
                () = refresh.as_mut() => break,
                () = changed => {},
            }
        }
        let (sender, receiver) = oneshot::channel();
        let pending = Pending {
            capture,
            resident,
            sender,
        };
        let admitted = {
            let mut state = lock(&self.state);
            if state.mode != Mode::Open || state.epoch != epoch {
                Err((RegistryError::Ended(state.reason), pending))
            } else {
                state
                    .queue
                    .enqueue_retaining(scope, cost, pending)
                    .map_err(|(error, pending)| (RegistryError::Admission(error), pending))
            }
        };
        let ticket = match admitted {
            Ok(ticket) => ticket,
            Err((error, pending)) => {
                drop(pending);
                return Err(error);
            }
        };
        let mut waiting = Waiter {
            registry: Arc::clone(self),
            ticket: Some(ticket),
        };
        self.ensure_cleanup();
        self.drive();
        let result = receiver.await.map_err(|_| self.ended())?;
        waiting.ticket = None;
        let view = result?;
        if !self.is_current(view.epoch) {
            return Err(self.ended());
        }
        Ok(view)
    }

    pub(crate) fn current_epoch(&self) -> Option<u64> {
        let state = lock(&self.state);
        (state.mode == Mode::Open).then_some(state.epoch)
    }

    pub(crate) fn is_current(&self, epoch: u64) -> bool {
        let state = lock(&self.state);
        state.mode == Mode::Open && state.epoch == epoch
    }

    /// An epoch number alone does not identify a backend generation or node.
    pub(crate) fn owns(&self, reservation: &Reservation<C>) -> bool {
        std::ptr::eq(reservation.registry.as_ptr(), self)
    }

    fn ended(&self) -> RegistryError {
        RegistryError::Ended(lock(&self.state).reason)
    }

    fn controls(&self) -> Vec<Control<C>> {
        lock(&self.state)
            .controls
            .values()
            .filter_map(WeakViewControl::upgrade)
            .collect()
    }

    /// An inactive ticket can never become active again. Take that fact before
    /// querying the runtime, so a concurrent finish cannot make an old idle
    /// observation hide an accepted worker that is still returning scheduler credit.
    fn prune(&self) {
        let candidates = {
            let state = lock(&self.state);
            state
                .controls
                .iter()
                .filter(|(ticket, _)| !state.queue.is_active(**ticket))
                .map(|(ticket, control)| (*ticket, control.upgrade()))
                .collect::<Vec<_>>()
        };
        let drained = candidates
            .into_iter()
            .filter_map(|(ticket, control)| {
                control
                    .as_ref()
                    .is_none_or(ViewControl::is_drained)
                    .then_some(ticket)
            })
            .collect::<Vec<_>>();
        let mut state = lock(&self.state);
        for ticket in drained {
            state.controls.remove(&ticket);
        }
    }

    fn drive(self: &Arc<Self>) {
        self.prune();
        {
            let mut state = lock(&self.state);
            if state.driving {
                return;
            }
            state.driving = true;
        }
        loop {
            let next = {
                let mut state = lock(&self.state);
                let wal = state.wal_bytes;
                let next = (state.mode == Mode::Open)
                    .then(|| state.queue.admit_next(wal))
                    .flatten();
                match next {
                    Some(grant) => Some((grant, state.epoch)),
                    None => {
                        state.driving = false;
                        None
                    }
                }
            };
            let Some((grant, epoch)) = next else { return };
            let Pending {
                capture,
                resident,
                sender,
            } = grant.resident;
            let runtime = RetainedView::new(
                capture,
                RetentionLease {
                    registry: Arc::clone(self),
                    ticket: grant.ticket,
                },
                resident,
                self.idle_timeout,
                Instant::now(),
            );
            let result = match runtime {
                Err(error) => Err(error.into()),
                Ok(runtime) => {
                    #[cfg(test)]
                    {
                        let hook = lock(&self.before_registration).take();
                        if let Some(hook) = hook {
                            hook();
                        }
                    }
                    let error = {
                        let mut state = lock(&self.state);
                        if state.mode == Mode::Open && state.epoch == epoch {
                            state.controls.insert(grant.ticket, runtime.control());
                            None
                        } else {
                            Some(state.reason)
                        }
                    };
                    if let Some(reason) = error {
                        runtime.invalidate(reason);
                        Err(RegistryError::Ended(reason))
                    } else {
                        Ok(RegisteredView {
                            runtime,
                            epoch,
                            reservation: Reservation {
                                registry: Arc::downgrade(self),
                                ticket: grant.ticket,
                                epoch,
                            },
                        })
                    }
                }
            };
            // An unobserved grant is already registered. Failed delivery drops
            // its runtime here; release reenters only the guarded dispatcher.
            let _ = sender.send(result);
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn adjust_native_cost(
        &self,
        reservation: &Reservation<C>,
        bytes: u64,
    ) -> Result<bool, RegistryError> {
        if !std::ptr::eq(reservation.registry.as_ptr(), self) {
            return Err(RegistryError::InvalidReservation);
        }
        let mut state = lock(&self.state);
        if state.mode != Mode::Open || state.epoch != reservation.epoch {
            return Err(RegistryError::InvalidReservation);
        }
        state
            .queue
            .adjust_native_cost(reservation.ticket, bytes)
            .map_err(RegistryError::Admission)
    }

    pub(crate) fn observe_wal(self: &Arc<Self>, bytes: Option<u64>) {
        lock(&self.state).wal_bytes = bytes;
        self.drive();
    }

    pub(crate) fn set_wal_probe(self: &Arc<Self>, probe: WalProbe) {
        let previous = lock(&self.wal_probe).replace(probe);
        drop(previous);
        self.observe_wal(None);
    }

    async fn refresh_wal(self: &Arc<Self>) {
        let probe = lock(&self.wal_probe).clone();
        if let Some(probe) = probe {
            // The probe may inspect the live connection. Call it after both
            // registry locks have been released, and overwrite even with an
            // unknown result so a stale low sample cannot grant a reader.
            self.observe_wal(None);
            self.observe_wal(probe().await);
        }
    }

    pub(crate) fn metrics(&self) -> RegistryMetrics {
        let (metrics, retained_wal_bytes) = {
            let state = lock(&self.state);
            (state.queue.metrics(), state.wal_bytes)
        };
        let now = Instant::now();
        let oldest_idle_age = self
            .controls()
            .iter()
            .filter_map(|control| control.idle_age(now))
            .max();
        RegistryMetrics {
            active_views: metrics.active_views,
            waiting_views: metrics.waiting_views,
            native_bytes: metrics.native_bytes,
            sqlite_readers: metrics.sqlite_readers,
            retained_wal_bytes,
            oldest_idle_age,
        }
    }

    pub(crate) fn expire_idle(self: &Arc<Self>, now: Instant) {
        for control in self.controls() {
            control.expire_idle(now);
        }
        self.drive();
    }

    pub(crate) async fn close_and_drain(self: &Arc<Self>, reason: ViewInvalidation) {
        let (pending, controls) = {
            let mut state = lock(&self.state);
            state.mode = Mode::Closed;
            state.reason = reason;
            state.epoch = state.epoch.checked_add(1).unwrap_or(state.epoch);
            let pending = state.queue.drain_pending();
            let controls = state
                .controls
                .values()
                .filter_map(WeakViewControl::upgrade)
                .collect::<Vec<_>>();
            (pending, controls)
        };
        Self::invalidate(reason, pending, &controls);
        self.changed.notify_waiters();
        self.wait_drained(&controls).await;
    }

    async fn wait_drained(&self, controls: &[Control<C>]) {
        for control in controls {
            control.drain().await;
        }
        loop {
            let mut changed = pin!(self.changed.notified());
            changed.as_mut().enable();
            if lock(&self.state).queue.metrics().active_views == 0 {
                return;
            }
            changed.await;
        }
    }

    pub(crate) fn begin_replacement(
        self: &Arc<Self>,
        reason: ViewInvalidation,
    ) -> Result<Replacement<C>, RegistryError> {
        let (epoch, exhausted, pending, controls) = {
            let mut state = lock(&self.state);
            if state.mode != Mode::Open {
                return Err(RegistryError::Ended(state.reason));
            }
            let epoch = state.epoch.checked_add(1);
            state.mode = if epoch.is_some() {
                Mode::Replacing
            } else {
                Mode::Closed
            };
            state.epoch = epoch.unwrap_or(state.epoch);
            state.reason = reason;
            let pending = state.queue.drain_pending();
            let controls = state
                .controls
                .values()
                .filter_map(WeakViewControl::upgrade)
                .collect::<Vec<_>>();
            (state.epoch, epoch.is_none(), pending, controls)
        };
        Self::invalidate(reason, pending, &controls);
        self.changed.notify_waiters();
        if exhausted {
            return Err(RegistryError::EpochExhausted);
        }
        Ok(Replacement {
            registry: Arc::clone(self),
            epoch,
            controls,
            drained: AtomicBool::new(false),
            completed: false,
        })
    }

    fn invalidate(reason: ViewInvalidation, pending: Vec<Pending<C>>, controls: &[Control<C>]) {
        for Pending {
            capture,
            resident,
            sender,
        } in pending
        {
            drop(capture);
            drop(resident);
            let _ = sender.send(Err(RegistryError::Ended(reason)));
        }
        for control in controls {
            control.invalidate(reason);
        }
    }

    fn ensure_cleanup(self: &Arc<Self>) {
        if self.cleanup_running.swap(true, Ordering::AcqRel) {
            return;
        }
        let cleanup = Cleanup(Arc::downgrade(self));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            let mut pending: Option<BoxFuture<'static, Option<u64>>> = None;
            loop {
                tokio::select! {
                    bytes = async { pending.as_mut().expect("guarded probe").await },
                        if pending.is_some() => {
                        pending = None;
                        let Some(registry) = cleanup.0.upgrade() else {
                            return;
                        };
                        registry.observe_wal(bytes);
                    }
                    _ = tick.tick() => {
                        let Some(registry) = cleanup.0.upgrade() else {
                            return;
                        };
                        registry.expire_idle(Instant::now());
                        let should_probe = {
                            let state = lock(&registry.state);
                            if state.mode == Mode::Closed {
                                return;
                            }
                            let metrics = state.queue.metrics();
                            state.mode == Mode::Open
                                && (metrics.active_views != 0 || metrics.waiting_views != 0)
                        };
                        if !should_probe {
                            pending = None;
                        } else if pending.is_none() {
                            let probe = lock(&registry.wal_probe).clone();
                            if let Some(probe) = probe {
                                registry.observe_wal(None);
                                pending = Some(probe());
                            }
                        }
                        // A contended WAL probe cannot delay idle expiration or
                        // keep the registry alive across a writer-lock wait.
                    }
                }
            }
        });
    }
}

struct Waiter<C: Send + 'static> {
    registry: Arc<ViewRegistry<C>>,
    ticket: Option<AdmissionTicket>,
}

impl<C: Send + 'static> Drop for Waiter<C> {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket {
            let pending = lock(&self.registry.state).queue.take_pending(ticket);
            drop(pending);
            self.registry.drive();
        }
    }
}

struct Cleanup<C: Send + 'static>(Weak<ViewRegistry<C>>);

impl<C: Send + 'static> Drop for Cleanup<C> {
    fn drop(&mut self) {
        if let Some(registry) = self.0.upgrade() {
            registry.cleanup_running.store(false, Ordering::Release);
        }
    }
}

pub(crate) struct Replacement<C: Send + 'static> {
    registry: Arc<ViewRegistry<C>>,
    epoch: u64,
    controls: Vec<Control<C>>,
    drained: AtomicBool,
    completed: bool,
}

impl<C: Send + 'static> Replacement<C> {
    pub(crate) async fn drain(&self) {
        self.registry.wait_drained(&self.controls).await;
        self.drained.store(true, Ordering::Release);
    }

    pub(crate) fn complete(mut self) -> Result<(), RegistryError> {
        if !self.drained.load(Ordering::Acquire) {
            return Err(RegistryError::NotDrained);
        }
        {
            let mut state = lock(&self.registry.state);
            if state.mode != Mode::Replacing || state.epoch != self.epoch {
                return Err(RegistryError::Ended(state.reason));
            }
            state.mode = Mode::Open;
        }
        self.completed = true;
        self.registry.drive();
        Ok(())
    }
}

impl<C: Send + 'static> Drop for Replacement<C> {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = lock(&self.registry.state);
            if state.epoch == self.epoch {
                state.mode = Mode::Closed;
            }
        }
    }
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
