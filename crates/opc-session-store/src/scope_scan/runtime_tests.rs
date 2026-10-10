use super::*;
use crate::scope_scheduler::{
    ClassBudget, ScopeScheduler, ScopeSchedulerBudgets, ScopeSchedulerKey, ScopeSchedulerOwner,
    ScopeWorkClass,
};
use futures_util::poll;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use tokio::sync::oneshot;

const NORMAL: ScopeWorkClass = ScopeWorkClass::Normal;
const CLASSIFY: ScopeWorkClass = ScopeWorkClass::EmergencyClassification;
const IDLE: Duration = Duration::from_secs(30);
const TIMEOUT: Duration = Duration::from_secs(5);
type Events = Arc<Mutex<Vec<&'static str>>>;

struct Capture {
    value: u32,
    events: Events,
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.events.lock().unwrap().push("capture");
    }
}

struct Retention(Events);

impl Drop for Retention {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("retention");
    }
}

async fn fixture() -> (
    ScopeSchedulerOwner,
    ScopeScheduler,
    RetainedView<Capture, Retention>,
    Events,
) {
    let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
        NORMAL,
        ClassBudget {
            queued: 4,
            running: 1,
        },
    ))
    .unwrap();
    let scheduler = owner.scheduler();
    let resident = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([1; 32]), NORMAL)
        .await
        .unwrap();
    let events = Events::default();
    let view = RetainedView::new(
        Capture {
            value: 0,
            events: Arc::clone(&events),
        },
        Retention(Arc::clone(&events)),
        resident,
        IDLE,
        Instant::now(),
    )
    .unwrap();
    (owner, scheduler, view, events)
}

struct ReleaseOnDrop(Option<mpsc::Sender<()>>);

impl ReleaseOnDrop {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.release();
    }
}

fn gate() -> (
    ReleaseOnDrop,
    mpsc::Receiver<()>,
    oneshot::Sender<()>,
    oneshot::Receiver<()>,
) {
    let (release, wait) = mpsc::channel();
    let (entered, started) = oneshot::channel();
    (ReleaseOnDrop(Some(release)), wait, entered, started)
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(TIMEOUT, async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("supervised work reached the expected state");
}

async fn result<R>(operation: ViewOperation<R>) -> Result<R, ViewError> {
    tokio::time::timeout(TIMEOUT, operation.result())
        .await
        .expect("bounded page completed")
}

#[tokio::test]
async fn pages_reuse_resident_credit_and_release_running_credit_between_pages() {
    let (_owner, scheduler, view, events) = fixture().await;
    for expected in 1..=2 {
        let during = scheduler.clone();
        let page = view
            .start_normal(move |capture, cancellation| {
                assert!(!cancellation.is_cancelled());
                assert_eq!(during.snapshot().class(NORMAL).running, 1);
                capture.value += 1;
                capture.value
            })
            .unwrap();
        assert_eq!(result(page).await, Ok(expected));
        let counts = scheduler.snapshot().class(NORMAL);
        assert_eq!((counts.resident, counts.running), (1, 0));
        assert!(events.lock().unwrap().is_empty());
    }
    view.close_and_drain(ViewInvalidation::Closed).await;
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
}

#[tokio::test]
async fn dropping_observer_keeps_actual_worker_capture_and_credit_until_drain() {
    let (_owner, scheduler, view, events) = fixture().await;
    let (mut release, wait, entered, started) = gate();
    let page = view
        .start_normal(move |_, cancellation| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
            assert!(cancellation.is_cancelled());
        })
        .unwrap();
    tokio::time::timeout(TIMEOUT, started)
        .await
        .unwrap()
        .unwrap();
    drop(page);
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 1);
    assert!(events.lock().unwrap().is_empty());
    let mut drain = Box::pin(view.close_and_drain(ViewInvalidation::SnapshotInstalled));
    assert!(poll!(&mut drain).is_pending());
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 1);
    assert!(events.lock().unwrap().is_empty());
    release.release();
    tokio::time::timeout(TIMEOUT, drain).await.unwrap();
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 0);
}

#[tokio::test]
async fn revocation_suppresses_a_late_reply_and_waits_for_real_worker_exit() {
    let (_owner, scheduler, view, events) = fixture().await;
    let (mut release, wait, entered, started) = gate();
    let page = view
        .start_normal(move |capture, cancellation| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
            assert!(cancellation.is_cancelled());
            capture.value
        })
        .unwrap();
    tokio::time::timeout(TIMEOUT, started)
        .await
        .unwrap()
        .unwrap();
    let reason = ViewInvalidation::ConfigurationChanged;
    view.invalidate(reason);
    assert_eq!(
        view.start_normal(|_, _| ()).unwrap_err(),
        ViewError::Ended(ViewState::Invalidated(reason)),
        "revocation takes precedence over an older operation's busy flag"
    );
    let mut drain = Box::pin(view.close_and_drain(reason));
    assert!(poll!(&mut drain).is_pending());
    assert!(events.lock().unwrap().is_empty());
    release.release();
    tokio::time::timeout(TIMEOUT, drain).await.unwrap();
    assert_eq!(
        result(page).await,
        Err(ViewError::Ended(ViewState::Invalidated(reason)))
    );
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 0);
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
}

#[tokio::test]
async fn revocation_cancels_a_capacity_wait_without_dispatching_or_waiting_for_client() {
    let (_owner, scheduler, view, events) = fixture().await;
    let blocker = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([2; 32]), NORMAL)
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let called = Arc::new(AtomicBool::new(false));
    let in_worker = Arc::clone(&called);
    let page = view
        .start_normal(move |_, _| in_worker.store(true, Ordering::SeqCst))
        .unwrap();
    wait_for(|| scheduler.snapshot().class(NORMAL).start_waiting == 1).await;
    let reason = ViewInvalidation::SnapshotInstalled;
    tokio::time::timeout(TIMEOUT, view.close_and_drain(reason))
        .await
        .expect("revocation cannot wait for unrelated capacity or a client");
    assert_eq!(
        result(page).await,
        Err(ViewError::Ended(ViewState::Invalidated(reason)))
    );
    assert!(!called.load(Ordering::SeqCst));
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 1);
    drop(blocker);
}

#[tokio::test]
async fn classification_uses_same_capture_while_normal_waits_for_execution_capacity() {
    let (_owner, scheduler, view, _events) = fixture().await;
    let blocker = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([2; 32]), NORMAL)
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let normal = view
        .start_normal(|capture, _| {
            capture.value += 1;
            capture.value
        })
        .unwrap();
    wait_for(|| scheduler.snapshot().class(NORMAL).start_waiting == 1).await;
    let resident = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([1; 32]), CLASSIFY)
        .await
        .unwrap();
    let during = scheduler.clone();
    let classification = view
        .start_classification(resident, move |capture, _| {
            assert_eq!(during.snapshot().class(CLASSIFY).running, 1);
            capture.value += 10;
            capture.value
        })
        .unwrap();
    assert_eq!(result(classification).await, Ok(10));
    assert_eq!(scheduler.snapshot().class(CLASSIFY).resident, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).start_waiting, 1);
    drop(blocker);
    assert_eq!(result(normal).await, Ok(11));
    view.close_and_drain(ViewInvalidation::Closed).await;
}

#[tokio::test]
async fn idle_expiry_drops_capture_before_retention_without_a_client_request() {
    let (_owner, scheduler, view, events) = fixture().await;
    assert_eq!(
        view.expire_idle(Instant::now() + IDLE),
        ViewState::IdleExpired
    );
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    assert_eq!(
        view.start_normal(|_, _| ()).unwrap_err(),
        ViewError::Ended(ViewState::IdleExpired)
    );
    view.close_and_drain(ViewInvalidation::Closed).await;
    assert_eq!(view.expire_idle(Instant::now()), ViewState::IdleExpired);
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
}

#[tokio::test]
async fn accepted_activity_survives_idle_limit_and_completion_starts_a_fresh_interval() {
    let (_owner, _scheduler, view, events) = fixture().await;
    let (mut release, wait, entered, started) = gate();
    let page = view
        .start_normal(move |_, _| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
        })
        .unwrap();
    tokio::time::timeout(TIMEOUT, started)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        view.expire_idle(Instant::now() + Duration::from_secs(3600)),
        ViewState::Retained
    );
    assert!(events.lock().unwrap().is_empty());
    release.release();
    result(page).await.unwrap();
    assert_eq!(
        view.expire_idle(Instant::now() + IDLE / 2),
        ViewState::Retained
    );
    assert_eq!(
        view.expire_idle(Instant::now() + IDLE),
        ViewState::IdleExpired
    );
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
}

#[tokio::test]
async fn worker_panic_terminates_view_and_drops_resources_before_drain_completes() {
    let (_owner, scheduler, view, events) = fixture().await;
    let page = view
        .start_normal::<()>(|_, _| panic!("injected page worker panic"))
        .unwrap();
    assert_eq!(result(page).await, Err(ViewError::WorkerPanicked));
    tokio::time::timeout(TIMEOUT, view.close_and_drain(ViewInvalidation::Closed))
        .await
        .unwrap();
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    assert_eq!(
        view.expire_idle(Instant::now()),
        ViewState::Invalidated(ViewInvalidation::Closed)
    );
}

#[tokio::test]
async fn wrong_class_and_duplicate_operations_cannot_expand_accepted_work() {
    let (_owner, scheduler, view, _events) = fixture().await;
    let wrong = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([1; 32]), NORMAL)
        .await
        .unwrap();
    assert_eq!(
        view.start_classification(wrong, |_, _| ()).unwrap_err(),
        ViewError::WrongClass
    );
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 1);
    let (mut release, wait, entered, started) = gate();
    let page = view
        .start_normal(move |_, _| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
        })
        .unwrap();
    tokio::time::timeout(TIMEOUT, started)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.start_normal(|_, _| ()).unwrap_err(), ViewError::Busy);
    let resident = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([1; 32]), CLASSIFY)
        .await
        .unwrap();
    let classification = view.start_classification(resident, |_, _| ()).unwrap();
    let duplicate = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([1; 32]), CLASSIFY)
        .await
        .unwrap();
    assert_eq!(
        view.start_classification(duplicate, |_, _| ()).unwrap_err(),
        ViewError::Busy
    );
    assert_eq!(scheduler.snapshot().class(CLASSIFY).resident, 1);
    release.release();
    result(page).await.unwrap();
    result(classification).await.unwrap();
    view.close_and_drain(ViewInvalidation::Closed).await;
}

#[tokio::test]
async fn dropping_view_revokes_detached_work_without_requiring_a_close_request() {
    let (_owner, scheduler, view, events) = fixture().await;
    let (mut release, wait, entered, started) = gate();
    let page = view
        .start_normal(move |_, cancellation| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
            assert!(cancellation.is_cancelled());
        })
        .unwrap();
    tokio::time::timeout(TIMEOUT, started)
        .await
        .unwrap()
        .unwrap();
    drop(view);
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 1);
    assert!(events.lock().unwrap().is_empty());
    release.release();
    assert_eq!(
        result(page).await,
        Err(ViewError::Ended(ViewState::Invalidated(
            ViewInvalidation::Closed
        )))
    );
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn scheduler_shutdown_releases_capture_and_never_dispatches_page() {
    let (owner, scheduler, view, events) = fixture().await;
    owner.close();
    let page = view
        .start_normal::<()>(|_, _| panic!("closed scheduler dispatched work"))
        .unwrap();
    assert_eq!(result(page).await, Err(ViewError::SchedulerClosed));
    view.close_and_drain(ViewInvalidation::Closed).await;
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn constructor_rejection_destroys_capture_before_releasing_its_charge() {
    let owner = ScopeSchedulerOwner::default();
    let scheduler = owner.scheduler();
    for (class, idle, expected) in [
        (NORMAL, Duration::ZERO, ViewError::InvalidIdleTimeout),
        (CLASSIFY, IDLE, ViewError::WrongClass),
    ] {
        let events = Events::default();
        let resident = scheduler
            .reserve(ScopeSchedulerKey::from_bytes([1; 32]), class)
            .await
            .unwrap();
        let outcome = RetainedView::new(
            Capture {
                value: 0,
                events: Arc::clone(&events),
            },
            Retention(Arc::clone(&events)),
            resident,
            idle,
            Instant::now(),
        );
        assert!(matches!(outcome, Err(error) if error == expected));
        assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
        assert_eq!(scheduler.snapshot().class(class).resident, 0);
    }
}

#[tokio::test]
async fn supervisor_cancellation_cannot_release_a_detached_blocking_workers_lease() {
    let (_owner, scheduler, view, events) = fixture().await;
    let (mut release, wait, entered, started) = gate();
    let inner = Arc::clone(&view.inner);
    let (resident, accepted) = inner.accept(OperationKind::Normal, None).unwrap();
    // Exercise runtime/supervisor teardown, not observer cancellation. The
    // public operation handle intentionally has no worker-abort capability.
    let supervisor = tokio::spawn(inner.run(
        OperationKind::Normal,
        resident,
        accepted,
        move |_, cancellation| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
            assert!(cancellation.is_cancelled());
        },
    ));
    tokio::time::timeout(TIMEOUT, started)
        .await
        .unwrap()
        .unwrap();
    supervisor.abort();
    assert!(supervisor.await.unwrap_err().is_cancelled());
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 1);
    assert!(events.lock().unwrap().is_empty());
    let mut drain = Box::pin(view.close_and_drain(ViewInvalidation::BackendRestarted));
    assert!(poll!(&mut drain).is_pending());
    release.release();
    tokio::time::timeout(TIMEOUT, drain).await.unwrap();
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn concurrent_drain_waits_for_idle_capture_destruction_and_admission_release() {
    struct SlowDrop {
        events: Events,
        entered: Option<oneshot::Sender<()>>,
        wait: mpsc::Receiver<()>,
    }
    impl Drop for SlowDrop {
        fn drop(&mut self) {
            self.entered.take().unwrap().send(()).unwrap();
            self.wait.recv_timeout(TIMEOUT).unwrap();
            self.events.lock().unwrap().push("capture");
        }
    }
    let owner = ScopeSchedulerOwner::default();
    let scheduler = owner.scheduler();
    let (mut release, wait, entered, started) = gate();
    let events = Events::default();
    let resident = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([1; 32]), NORMAL)
        .await
        .unwrap();
    let view = Arc::new(
        RetainedView::new(
            SlowDrop {
                events: Arc::clone(&events),
                entered: Some(entered),
                wait,
            },
            Retention(Arc::clone(&events)),
            resident,
            IDLE,
            Instant::now(),
        )
        .unwrap(),
    );
    let in_destructor = Arc::clone(&view);
    let invalidate = tokio::task::spawn_blocking(move || {
        in_destructor.invalidate(ViewInvalidation::SnapshotInstalled);
    });
    tokio::time::timeout(TIMEOUT, started)
        .await
        .unwrap()
        .unwrap();
    let mut drain = Box::pin(view.close_and_drain(ViewInvalidation::SnapshotInstalled));
    assert!(poll!(&mut drain).is_pending());
    assert!(events.lock().unwrap().is_empty());
    release.release();
    tokio::time::timeout(TIMEOUT, invalidate)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(TIMEOUT, drain).await.unwrap();
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn new_capture_users_cannot_overtake_an_already_waiting_operation() {
    let (_owner, _scheduler, view, events) = fixture().await;
    let inner = Arc::clone(&view.inner);
    let held = inner
        .take_capture(OperationKind::Classification)
        .await
        .unwrap();
    let mut waiting = Box::pin(inner.take_capture(OperationKind::Normal));
    assert!(poll!(&mut waiting).is_pending());

    // Finish the previous bounded capture access. Deliberately delay polling
    // its ready waiter, as an executor can, while a new lookup reaches the cut.
    lock(&inner.state).capture = Some(held);
    inner.changed.notify_waiters();
    let mut newcomer = Box::pin(inner.take_capture(OperationKind::Classification));
    assert!(
        poll!(&mut newcomer).is_pending(),
        "a new lookup must not steal the ready page's capture turn"
    );
    let held = tokio::time::timeout(TIMEOUT, waiting)
        .await
        .unwrap()
        .unwrap();
    lock(&inner.state).capture = Some(held);
    inner.changed.notify_waiters();
    let mut later_page = Box::pin(inner.take_capture(OperationKind::Normal));
    assert!(
        poll!(&mut later_page).is_pending(),
        "the earlier lookup's turn survives the preceding page's acquisition"
    );
    let held = tokio::time::timeout(TIMEOUT, newcomer)
        .await
        .unwrap()
        .unwrap();
    lock(&inner.state).capture = Some(held);
    inner.changed.notify_waiters();
    let held = tokio::time::timeout(TIMEOUT, later_page)
        .await
        .unwrap()
        .unwrap();
    lock(&inner.state).capture = Some(held);
    view.close_and_drain(ViewInvalidation::Closed).await;
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
}

#[tokio::test]
async fn inconsistent_local_credit_ownership_revokes_and_releases_the_view() {
    let (_owner, scheduler, view, events) = fixture().await;
    // Inject a local ownership fault. It must be a typed terminal failure,
    // never a panic that can leave admission charged or make a view reusable.
    drop(lock(&view.inner.state).resident.take());
    assert_eq!(
        view.start_normal(|_, _| ()).unwrap_err(),
        ViewError::RuntimeInvariant
    );
    assert_eq!(
        view.expire_idle(Instant::now()),
        ViewState::Invalidated(ViewInvalidation::Closed)
    );
    assert_eq!(*events.lock().unwrap(), ["capture", "retention"]);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    tokio::time::timeout(TIMEOUT, view.close_and_drain(ViewInvalidation::Closed))
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_start_retains_resident_credit_until_capture_and_charge_are_destroyed() {
    struct Witness {
        name: &'static str,
        scheduler: ScopeScheduler,
        events: Arc<Mutex<Vec<(&'static str, usize)>>>,
    }
    impl Drop for Witness {
        fn drop(&mut self) {
            self.events
                .lock()
                .unwrap()
                .push((self.name, self.scheduler.snapshot().class(NORMAL).resident));
        }
    }
    let owner = ScopeSchedulerOwner::default();
    let scheduler = owner.scheduler();
    let events = Arc::new(Mutex::new(Vec::new()));
    let witness = |name| Witness {
        name,
        scheduler: scheduler.clone(),
        events: Arc::clone(&events),
    };
    let resident = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([1; 32]), NORMAL)
        .await
        .unwrap();
    let view = RetainedView::new(
        witness("capture"),
        witness("retention"),
        resident,
        IDLE,
        Instant::now(),
    )
    .unwrap();
    owner.close();
    let page = view
        .start_normal::<()>(|_, _| panic!("closed scheduler dispatched"))
        .unwrap();
    assert_eq!(result(page).await, Err(ViewError::SchedulerClosed));
    view.close_and_drain(ViewInvalidation::Closed).await;
    assert_eq!(
        *events.lock().unwrap(),
        [("capture", 1), ("retention", 1)],
        "failed start must supervise its original resident credit through capture destruction"
    );
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}
