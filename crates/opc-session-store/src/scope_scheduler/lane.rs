//! Class ordering only at a shared serialized resource, with bounded bypass.
use super::{lock, ScopeSchedulerError, ScopeSchedulerKey, ScopeWorkClass};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::sync::Notify;

const MAX_BYPASSES: usize = 8;

struct Waiter {
    token: Arc<()>,
    class: ScopeWorkClass,
    waker: Waker,
}

#[derive(Default)]
struct State {
    holder: Option<Arc<()>>,
    waiting: VecDeque<Waiter>,
    bypasses: usize,
}

impl State {
    fn dispatch(&mut self) -> Option<Waker> {
        if self.holder.is_some() {
            return None;
        }
        let index = if self.bypasses >= MAX_BYPASSES {
            if self.waiting.is_empty() {
                return None;
            }
            0
        } else {
            self.waiting
                .iter()
                .enumerate()
                .min_by_key(|(_, waiter)| waiter.class)?
                .0
        };
        self.bypasses = if index == 0 { 0 } else { self.bypasses + 1 };
        let waiter = self.waiting.remove(index)?;
        self.holder = Some(waiter.token);
        Some(waiter.waker)
    }

    fn is_holder(&self, token: &Arc<()>) -> bool {
        self.holder
            .as_ref()
            .is_some_and(|holder| Arc::ptr_eq(holder, token))
    }
}

struct Inner {
    key: ScopeSchedulerKey,
    state: Mutex<State>,
    changed: Notify,
}

impl Inner {
    fn release(&self, token: &Arc<()>) {
        let wake = {
            let mut state = lock(&self.state);
            if state.is_holder(token) {
                state.holder = None;
            } else if let Some(index) = state
                .waiting
                .iter()
                .position(|waiter| Arc::ptr_eq(&waiter.token, token))
            {
                state.waiting.remove(index);
            }
            if state.waiting.is_empty() {
                state.bypasses = 0;
            }
            state.dispatch()
        };
        self.changed.notify_waiters();
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

/// One scope's serialized data lane. Clone this arbiter rather than constructing
/// one per caller. It does not own the replay ledger: the lane integration must
/// keep its guard until the exact outcome is resolved, including across retries.
#[derive(Clone)]
pub struct ScopeLane {
    inner: Arc<Inner>,
}

impl ScopeLane {
    /// Construct a shared lane bound to one stable admitted scope.
    pub fn new(key: ScopeSchedulerKey) -> Self {
        Self {
            inner: Arc::new(Inner {
                key,
                state: Mutex::new(State::default()),
                changed: Notify::new(),
            }),
        }
    }

    /// Wait in class order, FIFO within class. The oldest waiter may be bypassed
    /// at most eight grants. Build/read the request only after this completes.
    /// SafetyControl is refused before joining the lane or its waiters.
    pub async fn acquire(
        &self,
        class: ScopeWorkClass,
    ) -> Result<ScopeLaneGuard, ScopeSchedulerError> {
        if class == ScopeWorkClass::SafetyControl {
            return Err(ScopeSchedulerError::SafetyControlOnDataLane);
        }
        Ok(Acquire {
            inner: Arc::clone(&self.inner),
            token: Arc::new(()),
            class,
            registered: false,
            finished: false,
        }
        .await)
    }
}

struct Acquire {
    inner: Arc<Inner>,
    token: Arc<()>,
    class: ScopeWorkClass,
    registered: bool,
    finished: bool,
}

impl Future for Acquire {
    type Output = ScopeLaneGuard;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let (granted, wake, changed) = {
            let mut state = lock(&this.inner.state);
            let changed = !this.registered;
            if !this.registered {
                state.waiting.push_back(Waiter {
                    token: Arc::clone(&this.token),
                    class: this.class,
                    waker: cx.waker().clone(),
                });
                this.registered = true;
            } else if let Some(waiter) = state
                .waiting
                .iter_mut()
                .find(|waiter| Arc::ptr_eq(&waiter.token, &this.token))
            {
                waiter.waker.clone_from(cx.waker());
            }
            let wake = state.dispatch();
            (state.is_holder(&this.token), wake, changed)
        };
        if changed {
            this.inner.changed.notify_waiters();
        }
        if let Some(waker) = wake {
            waker.wake();
        }
        if granted {
            this.finished = true;
            Poll::Ready(ScopeLaneGuard {
                inner: Arc::clone(&this.inner),
                token: Arc::clone(&this.token),
            })
        } else {
            Poll::Pending
        }
    }
}

impl Drop for Acquire {
    fn drop(&mut self) {
        if self.registered && !self.finished {
            self.inner.release(&self.token);
        }
    }
}

/// Affine lane ownership, retained through exact outcome resolution. Dropping
/// this guard releases the lane; cancelling a post-dispatch observer must not.
pub struct ScopeLaneGuard {
    inner: Arc<Inner>,
    token: Arc<()>,
}

impl ScopeLaneGuard {
    /// Highest of this attempt's original class and the trusted live waiters.
    /// The guard's acquisition class never raises an unrelated reservation.
    pub fn effective_class(&self, original: ScopeWorkClass) -> ScopeWorkClass {
        lock(&self.inner.state)
            .waiting
            .iter()
            .map(|waiter| waiter.class)
            .fold(original, ScopeWorkClass::min)
    }

    pub(super) fn scope_key(&self) -> ScopeSchedulerKey {
        self.inner.key
    }

    pub(super) async fn wait_for_class_change(
        &self,
        original: ScopeWorkClass,
        effective: ScopeWorkClass,
    ) {
        loop {
            // Register before reading the class so no change can be lost.
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.effective_class(original) != effective {
                return;
            }
            // Changes that leave priority unchanged must not cancel a running
            // semaphore acquisition and put its FIFO waiter back at the tail.
            changed.await;
        }
    }
}

impl Drop for ScopeLaneGuard {
    fn drop(&mut self) {
        self.inner.release(&self.token);
    }
}

impl fmt::Debug for ScopeLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeLane(<redacted>)")
    }
}
impl fmt::Debug for ScopeLaneGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeLaneGuard(<redacted>)")
    }
}
