//! Cooperative cancellation: a server drains backend work before releasing proof credit.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Notify;

/// Cancellation for one internal transport read. Carries no authority or admission credit.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct ScopeChildReadControl(Arc<Cancellation>);

#[derive(Debug, Default)]
struct Cancellation {
    cancelled: AtomicBool,
    changed: Notify,
}

impl ScopeChildReadControl {
    /// Revoke an in-flight read, including blocking backend work.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            changed.await;
        }
    }
}

pub(crate) struct CancelOnDrop(pub(crate) ScopeChildReadControl);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(any(test, feature = "test-control"))]
mod gates {
    use super::*;
    use std::sync::{Condvar, Mutex};

    /// Deterministic pause locations for qualification of the sole read cut.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ScopeChildReadStage {
        BeforeCapture,
        AfterCapture,
        BetweenKeys,
    }

    #[derive(Debug, Default)]
    pub(crate) struct PauseState {
        reached: AtomicBool,
        changed: Notify,
        released: Mutex<bool>,
        release: Condvar,
    }

    impl PauseState {
        pub(crate) fn pause(&self, check: &dyn Fn() -> std::io::Result<()>) -> std::io::Result<()> {
            self.reached.store(true, Ordering::Release);
            self.changed.notify_waiters();
            let mut released = self.released.lock().unwrap();
            while !*released {
                check()?;
                released = self
                    .release
                    .wait_timeout(released, std::time::Duration::from_millis(20))
                    .unwrap()
                    .0;
            }
            check()
        }
    }

    /// A single-use pause. Dropping it also releases a waiting test worker.
    #[derive(Debug)]
    pub struct ScopeChildReadPause(pub(crate) Arc<PauseState>);
    impl ScopeChildReadPause {
        /// Wait until the actual read reaches the selected boundary.
        pub async fn reached(&self) {
            loop {
                let changed = self.0.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.0.reached.load(Ordering::Acquire) {
                    return;
                }
                changed.await;
            }
        }
        /// Release the blocked operation.
        pub fn release(self) {
            drop(self);
        }
    }
    impl Drop for ScopeChildReadPause {
        fn drop(&mut self) {
            *self.0.released.lock().unwrap() = true;
            self.0.release.notify_all();
        }
    }
}
#[cfg(any(test, feature = "test-control"))]
pub(crate) use gates::PauseState;
#[cfg(any(test, feature = "test-control"))]
pub use gates::{ScopeChildReadPause, ScopeChildReadStage};
