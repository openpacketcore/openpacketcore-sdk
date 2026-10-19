//! Protocol time and passive observations for pressure-recovery fixtures.

use std::cell::RefCell;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, watch};

const RETRY_PACING: Duration = Duration::from_millis(100);

tokio::task_local! {
    static PACER: Pacer;
    static EVENTS: RefCell<Vec<Event>>;
}

#[derive(Clone)]
pub(super) struct Pacer(mpsc::UnboundedSender<Idle>);

struct Idle {
    active: Arc<AtomicBool>,
    cancelled: oneshot::Receiver<()>,
}

pub(super) struct IdleGuard {
    active: Arc<AtomicBool>,
    cancelled: Option<oneshot::Sender<()>>,
}

impl Drop for IdleGuard {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        if let Some(cancelled) = self.cancelled.take() {
            let _ = cancelled.send(());
        }
    }
}

impl Pacer {
    pub(super) fn idle(&self) -> IdleGuard {
        let active = Arc::new(AtomicBool::new(true));
        let (cancelled, receiver) = oneshot::channel();
        let _ = self.0.send(Idle {
            active: active.clone(),
            cancelled: receiver,
        });
        IdleGuard {
            active,
            cancelled: Some(cancelled),
        }
    }
}

pub(super) fn current_pacer() -> Option<Pacer> {
    PACER.try_with(Clone::clone).ok()
}

struct AbortPacer(tokio::task::JoinHandle<()>);

impl Drop for AbortPacer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Freeze only dispatched protocol deadlines. Retained owners still pace
/// retries against real time; Raft and storage keep their original runtime.
/// Advance only while a positive pressure acknowledgement has left the owner
/// idle. A route wake cancels that idle period before any new dispatch.
pub(crate) fn run<F>(
    physical_deadline: Instant,
    first_advance: Duration,
    operation: F,
) -> (impl Future<Output = F::Output>, watch::Receiver<bool>)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let real_runtime = tokio::runtime::Handle::current();
    let (advanced, probe) = watch::channel(false);
    let operation =
        crate::formation_clock::controlled_clock::run_before(physical_deadline, async move {
            let (sender, mut idle) = mpsc::unbounded_channel::<Idle>();
            let driver = AbortPacer(tokio::spawn(async move {
                let mut first = true;
                while let Some(mut idle) = idle.recv().await {
                    let physical_sleep = {
                        let _entered = real_runtime.enter();
                        tokio::time::sleep(RETRY_PACING)
                    };
                    tokio::select! {
                        biased;
                        _ = &mut idle.cancelled => continue,
                        () = physical_sleep => {},
                    }
                    if !idle.active.load(Ordering::Acquire) {
                        continue;
                    }
                    // This runtime is current-thread. advance changes its
                    // clock before yielding, so an owner cannot start another
                    // attempt between this idle check and the clock change.
                    tokio::time::advance(if first { first_advance } else { RETRY_PACING }).await;
                    if first {
                        advanced.send_replace(true);
                        first = false;
                    }
                }
            }));
            let result = PACER.scope(Pacer(sender), operation).await;
            drop(driver);
            result
        });
    (operation, probe)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    DeadlineExpired,
    ScopeBatchOutcomeUnknown,
    CheckpointResolved,
}

/// Observe the original call without adding a read, retry, or deadline.
#[cfg(target_os = "linux")]
pub(crate) async fn observe<F: Future>(operation: F) -> (F::Output, Vec<Event>) {
    EVENTS
        .scope(RefCell::new(Vec::new()), async {
            let result = operation.await;
            let events = EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()));
            (result, events)
        })
        .await
}

pub(crate) fn record(event: Event) {
    let _ = EVENTS.try_with(|events| events.borrow_mut().push(event));
}

#[tokio::test]
async fn route_wake_cancels_the_idle_clock_advance() {
    let real_runtime = tokio::runtime::Handle::current();
    let (operation, advanced) = run(
        Instant::now() + Duration::from_secs(3),
        Duration::from_millis(900),
        async move {
            let started = tokio::time::Instant::now();
            let idle = current_pacer().unwrap().idle();
            tokio::task::yield_now().await;
            drop(idle);
            // Model a route wake followed by an in-flight dispatch. Its
            // deadline must not receive the previous idle period's tick.
            let physical_sleep = {
                let _entered = real_runtime.enter();
                tokio::time::sleep(2 * RETRY_PACING)
            };
            physical_sleep.await;
            assert_eq!(started.elapsed(), Duration::ZERO);
        },
    );
    operation.await;
    assert!(!*advanced.borrow());
}
