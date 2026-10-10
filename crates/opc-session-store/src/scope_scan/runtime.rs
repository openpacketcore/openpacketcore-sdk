//! Supervised ownership of a retained cut and its bounded page workers.
//!
//! The backend adapter supplies an already admitted cut and its retention
//! charge. It checks authority/epoch and acquires any short backend operation
//! permit inside the work closure. Closures must obey the page work bound and
//! cancellation signal, and must not let capture handles escape in a reply.

use std::collections::VecDeque;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, Notify};

use super::activity::{ActivityError, ViewActivity, ViewInvalidation, ViewState};
use crate::scope_scheduler::{ScopeWorkClass, ScopeWorkPermit, ScopeWorkReservation};

pub(crate) async fn run_local_guard(
    permit: ScopeWorkPermit,
    work: impl FnOnce(&ViewCancellation) -> Result<(), super::ScopeScanError> + Send + 'static,
) -> Result<(), super::ScopeScanError> {
    struct CancelOnDrop(ViewCancellation);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }

    let cancelled = ViewCancellation::default();
    let _cancel_on_drop = CancelOnDrop(cancelled.clone());
    // Cancellation ends observation immediately, but the actual blocking
    // worker owns execution and resident credit until its work has drained.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if cancelled.is_cancelled() {
            return Err(super::ScopeScanError::RestartRequired);
        }
        work(&cancelled)
    })
    .await
    .unwrap_or(Err(super::ScopeScanError::Unavailable))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ViewError {
    #[error("scope scan view ended: {0:?}")]
    Ended(ViewState),
    #[error("scope scan already has an accepted operation of this kind")]
    Busy,
    #[error("scope scan operation has the wrong scheduling class")]
    WrongClass,
    #[error("scope scan idle timeout must be positive")]
    InvalidIdleTimeout,
    #[error("scope scan scheduler is closed")]
    SchedulerClosed,
    #[error("scope scan worker panicked")]
    WorkerPanicked,
    #[error("scope scan resource ownership is inconsistent")]
    RuntimeInvariant,
}

#[derive(Clone, Default)]
pub(crate) struct ViewCancellation(Arc<Cancellation>);

#[derive(Default)]
struct Cancellation {
    cancelled: AtomicBool,
    changed: Notify,
}

impl ViewCancellation {
    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let mut changed = pin!(self.0.changed.notified());
            changed.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            changed.await;
        }
    }
}

/// Dropping an observer detaches it; it never aborts the actual worker.
#[derive(Debug)]
pub(crate) struct ViewOperation<R> {
    result: oneshot::Receiver<Result<R, ViewError>>,
}

impl<R> ViewOperation<R> {
    pub(crate) async fn result(self) -> Result<R, ViewError> {
        self.result.await.unwrap_or(Err(ViewError::WorkerPanicked))
    }
}

// Declaration order matters: destroy the capture before releasing its charge.
struct Captured<C, G> {
    value: C,
    _retention: G,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperationKind {
    Normal,
    Classification,
}

struct State<C, G> {
    activity: ViewActivity,
    capture: Option<Captured<C, G>>,
    resident: Option<ScopeWorkReservation>,
    normal_active: bool,
    classification_active: bool,
    // At most two distinct kinds are accepted. Keep both ready waiters in
    // arrival order even when the executor polls a later arrival first.
    capture_waiters: VecDeque<OperationKind>,
    // A concurrent drain must also wait for idle resource destructors.
    retiring_idle: bool,
}

struct Inner<C: Send + 'static, G: Send + 'static> {
    state: Mutex<State<C, G>>,
    cancellation: ViewCancellation,
    changed: Notify,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The registry/local handle owns retention. Workers hold only private Inner
/// references, so dropping this handle still revokes detached operations.
pub(crate) struct RetainedView<C: Send + 'static, G: Send + 'static> {
    inner: Arc<Inner<C, G>>,
}

/// Lifecycle control follows the private worker owner even after the outer
/// client handle is dropped. It cannot start work or obtain the capture.
pub(crate) struct WeakViewControl<C: Send + 'static, G: Send + 'static>(Weak<Inner<C, G>>);

pub(crate) struct ViewControl<C: Send + 'static, G: Send + 'static>(Arc<Inner<C, G>>);

impl<C: Send + 'static, G: Send + 'static> WeakViewControl<C, G> {
    pub(crate) fn upgrade(&self) -> Option<ViewControl<C, G>> {
        self.0.upgrade().map(ViewControl)
    }
}

impl<C: Send + 'static, G: Send + 'static> ViewControl<C, G> {
    pub(crate) fn invalidate(&self, reason: ViewInvalidation) {
        self.0.invalidate(reason);
    }

    pub(crate) fn expire_idle(&self, now: Instant) {
        self.0.retire_idle(now);
    }

    pub(crate) fn idle_age(&self, now: Instant) -> Option<Duration> {
        lock(&self.0.state).activity.idle_age(now)
    }

    pub(crate) fn is_drained(&self) -> bool {
        self.0.is_drained()
    }

    pub(crate) async fn drain(&self) {
        self.0.drain().await;
    }
}

impl<C: Send + 'static, G: Send + 'static> RetainedView<C, G> {
    pub(crate) fn new(
        capture: C,
        retention: G,
        resident: ScopeWorkReservation,
        idle_timeout: Duration,
        now: Instant,
    ) -> Result<Self, ViewError> {
        // Keep the destruction order even when constructor validation refuses
        // this capture. Independent argument drops would release G before C.
        let capture = Captured {
            value: capture,
            _retention: retention,
        };
        if resident.class() != ScopeWorkClass::Normal {
            return Err(ViewError::WrongClass);
        }
        let activity =
            ViewActivity::new(idle_timeout, now).map_err(|_| ViewError::InvalidIdleTimeout)?;
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    activity,
                    capture: Some(capture),
                    resident: Some(resident),
                    normal_active: false,
                    classification_active: false,
                    capture_waiters: VecDeque::with_capacity(2),
                    retiring_idle: false,
                }),
                cancellation: ViewCancellation::default(),
                changed: Notify::new(),
            }),
        })
    }

    pub(crate) fn start_normal<R: Send + 'static>(
        &self,
        work: impl FnOnce(&mut C, &ViewCancellation) -> R + Send + 'static,
    ) -> Result<ViewOperation<R>, ViewError> {
        self.start(OperationKind::Normal, None, work)
    }

    pub(crate) fn start_classification<R: Send + 'static>(
        &self,
        resident: ScopeWorkReservation,
        work: impl FnOnce(&mut C, &ViewCancellation) -> R + Send + 'static,
    ) -> Result<ViewOperation<R>, ViewError> {
        if resident.class() != ScopeWorkClass::EmergencyClassification {
            return Err(ViewError::WrongClass);
        }
        self.start(OperationKind::Classification, Some(resident), work)
    }

    fn start<R: Send + 'static>(
        &self,
        kind: OperationKind,
        supplied: Option<ScopeWorkReservation>,
        work: impl FnOnce(&mut C, &ViewCancellation) -> R + Send + 'static,
    ) -> Result<ViewOperation<R>, ViewError> {
        let accepted = self.inner.accept(kind, supplied);
        let (resident, accepted) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                self.expire_idle(Instant::now());
                return Err(error);
            }
        };
        let (sender, result) = oneshot::channel();
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let outcome = inner.run(kind, resident, accepted, work).await;
            let _ = sender.send(outcome);
        });
        Ok(ViewOperation { result })
    }

    pub(crate) fn invalidate(&self, reason: ViewInvalidation) {
        self.inner.invalidate(reason);
    }

    pub(crate) fn control(&self) -> WeakViewControl<C, G> {
        WeakViewControl(Arc::downgrade(&self.inner))
    }

    pub(crate) fn cancellation(&self) -> ViewCancellation {
        self.inner.cancellation.clone()
    }

    pub(crate) fn expire_idle(&self, now: Instant) -> ViewState {
        self.inner.retire_idle(now)
    }

    pub(crate) async fn close_and_drain(&self, reason: ViewInvalidation) {
        self.invalidate(reason);
        self.inner.drain().await;
    }
}

impl<C: Send + 'static, G: Send + 'static> Drop for RetainedView<C, G> {
    fn drop(&mut self) {
        self.invalidate(ViewInvalidation::Closed);
    }
}

// A dispatched worker owns this last field after its capture and running
// permit. Panic or supervisor/runtime cancellation therefore cannot report a
// drained operation while a detached blocking worker still uses the capture.
struct Accepted<C: Send + 'static, G: Send + 'static> {
    inner: Arc<Inner<C, G>>,
    kind: OperationKind,
    settled: bool,
}

impl<C: Send + 'static, G: Send + 'static> Accepted<C, G> {
    fn finish(mut self) {
        self.settled = true;
    }
}

impl<C: Send + 'static, G: Send + 'static> Drop for Accepted<C, G> {
    fn drop(&mut self) {
        if !self.settled {
            self.inner.invalidate(ViewInvalidation::Closed);
        }
        let failed = {
            let mut state = lock(&self.inner.state);
            let failed = state.activity.finish(Instant::now()).is_err();
            match self.kind {
                OperationKind::Normal => state.normal_active = false,
                OperationKind::Classification => state.classification_active = false,
            }
            failed
        };
        if failed {
            self.inner.invalidate(ViewInvalidation::Closed);
        }
        self.inner.changed.notify_waiters();
    }
}

// Field order guarantees capture -> charge -> execution -> activity release,
// including unwinding and a detached JoinHandle whose output is discarded.
struct WorkerLease<C: Send + 'static, G: Send + 'static> {
    capture: Captured<C, G>,
    permit: ScopeWorkPermit,
    accepted: Accepted<C, G>,
}

impl<C: Send + 'static, G: Send + 'static> Inner<C, G> {
    fn is_drained(&self) -> bool {
        let state = lock(&self.state);
        !state.normal_active && !state.classification_active && !state.retiring_idle
    }

    async fn drain(&self) {
        loop {
            let mut changed = pin!(self.changed.notified());
            changed.as_mut().enable();
            if self.is_drained() {
                return;
            }
            changed.await;
        }
    }

    fn accept(
        self: &Arc<Self>,
        kind: OperationKind,
        supplied: Option<ScopeWorkReservation>,
    ) -> Result<(ScopeWorkReservation, Accepted<C, G>), ViewError> {
        let mut state = lock(&self.state);
        let view_state = state.activity.state(Instant::now());
        if view_state != ViewState::Retained {
            return Err(ViewError::Ended(view_state));
        }
        let busy = match kind {
            OperationKind::Normal => state.normal_active,
            OperationKind::Classification => state.classification_active,
        };
        if busy {
            return Err(ViewError::Busy);
        }
        state.activity.begin(Instant::now()).map_err(|error| {
            if let ActivityError::Ended(state) = error {
                ViewError::Ended(state)
            } else {
                ViewError::Busy
            }
        })?;
        let resident = match kind {
            OperationKind::Normal => state.resident.take(),
            OperationKind::Classification => supplied,
        };
        let Some(resident) = resident else {
            let _ = state.activity.finish(Instant::now());
            state.activity.invalidate(ViewInvalidation::Closed);
            return Err(ViewError::RuntimeInvariant);
        };
        match kind {
            OperationKind::Normal => state.normal_active = true,
            OperationKind::Classification => state.classification_active = true,
        };
        Ok((
            resident,
            Accepted {
                inner: Arc::clone(self),
                kind,
                settled: false,
            },
        ))
    }

    fn invalidate(&self, reason: ViewInvalidation) {
        lock(&self.state).activity.invalidate(reason);
        self.retire_idle(Instant::now());
    }

    fn retire_idle(&self, now: Instant) -> ViewState {
        let (view_state, retired) = {
            let mut state = lock(&self.state);
            let view_state = state.activity.state(now);
            let retired = if view_state != ViewState::Retained {
                let capture = state.capture.take();
                let resident = state.resident.take();
                if capture.is_some() || resident.is_some() {
                    state.retiring_idle = true;
                    Some((capture, resident))
                } else {
                    None
                }
            } else {
                None
            };
            (view_state, retired)
        };
        if view_state != ViewState::Retained {
            self.cancellation.cancel();
        }
        if let Some(retired) = retired {
            drop(retired);
            lock(&self.state).retiring_idle = false;
            self.changed.notify_waiters();
        }
        view_state
    }

    fn ended(&self) -> ViewError {
        ViewError::Ended(lock(&self.state).activity.state(Instant::now()))
    }

    async fn take_capture(&self, kind: OperationKind) -> Result<Captured<C, G>, ViewError> {
        loop {
            let mut changed = pin!(self.changed.notified());
            changed.as_mut().enable();
            {
                let mut state = lock(&self.state);
                let view_state = state.activity.state(Instant::now());
                if view_state != ViewState::Retained {
                    return Err(ViewError::Ended(view_state));
                }
                if !state.capture_waiters.contains(&kind) {
                    state.capture_waiters.push_back(kind);
                }
                if state.capture_waiters.front() == Some(&kind) {
                    if let Some(capture) = state.capture.take() {
                        state.capture_waiters.pop_front();
                        return Ok(capture);
                    }
                }
            }
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return Err(self.ended()),
                _ = changed => {},
            }
        }
    }

    async fn run<R: Send + 'static>(
        self: Arc<Self>,
        kind: OperationKind,
        resident: ScopeWorkReservation,
        accepted: Accepted<C, G>,
        work: impl FnOnce(&mut C, &ViewCancellation) -> R + Send + 'static,
    ) -> Result<R, ViewError> {
        // A Normal attempt waiting for execution capacity cannot own the cut
        // that a separately admitted classification operation needs.
        let permit = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => {
                accepted.finish();
                return Err(self.ended());
            }
            result = resident.start() => match result {
                Ok(permit) => permit,
                Err(_) => {
                    self.invalidate(ViewInvalidation::Closed);
                    accepted.finish();
                    return Err(ViewError::SchedulerClosed);
                }
            },
        };
        let capture = match self.take_capture(kind).await {
            Ok(capture) => capture,
            Err(error) => {
                drop(permit);
                accepted.finish();
                return Err(error);
            }
        };
        let cancellation = self.cancellation.clone();
        let mut lease = WorkerLease {
            capture,
            permit,
            accepted,
        };
        // Never select cancellation against this join. The lease, including
        // its activity guard, moves into the blocking worker itself.
        let worker = tokio::task::spawn_blocking(move || {
            let reply = work(&mut lease.capture.value, &cancellation);
            (lease, reply)
        });
        let (lease, reply) = match worker.await {
            Ok(completed) => completed,
            Err(_) => {
                self.invalidate(ViewInvalidation::Closed);
                return Err(ViewError::WorkerPanicked);
            }
        };
        let WorkerLease {
            capture,
            permit,
            accepted,
        } = lease;
        let mut capture = Some(capture);
        let mut resident = match kind {
            OperationKind::Normal => Some(permit.finish_unknown()),
            OperationKind::Classification => {
                drop(permit);
                None
            }
        };
        let outcome = {
            let mut state = lock(&self.state);
            let view_state = state.activity.state(Instant::now());
            if view_state == ViewState::Retained {
                state.capture = capture.take();
                if matches!(kind, OperationKind::Normal) {
                    state.resident = resident.take();
                }
                Ok(reply)
            } else {
                Err(ViewError::Ended(view_state))
            }
        };
        // Invalidation may have happened while work was running. Complete
        // resource destruction before the activity guard signals drainage.
        drop(capture);
        drop(resident);
        accepted.finish();
        outcome
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "local_guard_tests.rs"]
mod local_guard_tests;
