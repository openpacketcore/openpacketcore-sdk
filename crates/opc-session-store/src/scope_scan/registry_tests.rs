use super::*;
use crate::scope_scheduler::{
    ClassBudget, ScopeScheduler, ScopeSchedulerBudgets, ScopeSchedulerOwner, ScopeWorkClass,
};
use futures_util::poll;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use tokio::sync::oneshot;

const NORMAL: ScopeWorkClass = ScopeWorkClass::Normal;
const IDLE: Duration = Duration::from_secs(30);
const TIMEOUT: Duration = Duration::from_secs(5);
type Capture = Option<Pin>;

struct Pin(Arc<AtomicUsize>);

impl Pin {
    fn new(alive: &Arc<AtomicUsize>) -> Self {
        alive.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(alive))
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn key(value: u8) -> ScopeSchedulerKey {
    ScopeSchedulerKey::from_bytes([value; 32])
}

fn fixture(
    views: usize,
    native_bytes: u64,
) -> (
    ScopeSchedulerOwner,
    ScopeScheduler,
    Arc<ViewRegistry<Capture>>,
) {
    let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
        NORMAL,
        ClassBudget {
            queued: 16,
            running: 1,
        },
    ))
    .unwrap();
    let scheduler = owner.scheduler();
    let limits = RetentionLimits::new(views, views, native_bytes, 128).unwrap();
    let registry = ViewRegistry::new(limits, IDLE).unwrap();
    (owner, scheduler, registry)
}

async fn open(
    registry: &Arc<ViewRegistry<Capture>>,
    scheduler: &ScopeScheduler,
    scope: u8,
    cost: CaptureCost,
) -> RegisteredView<Capture> {
    registry
        .admit(
            key(scope),
            cost,
            None,
            scheduler.reserve(key(scope), NORMAL).await.unwrap(),
        )
        .await
        .unwrap()
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(TIMEOUT, future).await.unwrap()
}

struct Release(Option<mpsc::Sender<()>>);

impl Release {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.release();
    }
}

fn gate() -> (
    Release,
    mpsc::Receiver<()>,
    oneshot::Sender<()>,
    oneshot::Receiver<()>,
) {
    let (release, wait) = mpsc::channel();
    let (entered, started) = oneshot::channel();
    (Release(Some(release)), wait, entered, started)
}

#[tokio::test]
async fn retention_waits_without_taking_running_credit_or_evicting_a_view() {
    let (_owner, scheduler, registry) = fixture(4, 512);
    let running = scheduler
        .reserve(key(99), NORMAL)
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let mut views = Vec::new();
    for scope in 1..=4 {
        views.push(open(&registry, &scheduler, scope, CaptureCost::Native(64)).await);
    }
    let resident = scheduler.reserve(key(5), NORMAL).await.unwrap();
    let mut fifth = Box::pin(registry.admit(key(5), CaptureCost::Native(64), None, resident));
    assert!(poll!(fifth.as_mut()).is_pending(), "fifth view must wait");
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 1);
    assert!(views.iter().all(|view| registry.is_current(view.epoch)));
    assert_eq!(registry.metrics().active_views, 4);
    assert_eq!(registry.metrics().waiting_views, 1);
    drop(views.remove(0));
    let fifth = bounded(fifth).await.unwrap();
    assert_eq!(registry.metrics().active_views, 4);
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 1);
    drop((fifth, views, running));
    assert_eq!(registry.metrics().active_views, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn cancelling_a_waiter_releases_its_credit_and_preserves_the_next_waiter() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let first = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let mut cancelled = Box::pin(registry.admit(
        key(2),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    ));
    let mut next = Box::pin(registry.admit(
        key(3),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(3), NORMAL).await.unwrap(),
    ));
    assert!(poll!(cancelled.as_mut()).is_pending());
    assert!(poll!(next.as_mut()).is_pending());
    drop(cancelled);
    assert_eq!(registry.metrics().waiting_views, 1);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 2);
    drop(first);
    let next = bounded(next).await.unwrap();
    assert_eq!(registry.metrics().waiting_views, 0);
    drop(next);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn a_grant_is_registered_before_the_client_polls_its_ready_result() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let first = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let mut waiting = Box::pin(registry.admit(
        key(2),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    ));
    assert!(poll!(waiting.as_mut()).is_pending());
    drop(first);
    assert_eq!(registry.metrics().active_views, 1);
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    bounded(replacement.drain()).await;
    assert_eq!(registry.metrics().active_views, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    assert!(matches!(
        bounded(waiting).await,
        Err(RegistryError::Ended(ViewInvalidation::SnapshotInstalled))
    ));
    replacement.complete().unwrap();
}

#[tokio::test]
async fn replacement_invalidates_an_idle_pin_without_another_client_request() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let alive = Arc::new(AtomicUsize::new(0));
    let worker_alive = Arc::clone(&alive);
    bounded(
        view.runtime
            .start_normal(move |slot, _| *slot = Some(Pin::new(&worker_alive)))
            .unwrap()
            .result(),
    )
    .await
    .unwrap();
    let old_epoch = view.epoch;
    assert_eq!(alive.load(Ordering::SeqCst), 1);
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    bounded(replacement.drain()).await;
    assert_eq!(alive.load(Ordering::SeqCst), 0);
    assert!(!registry.is_current(old_epoch));
    assert!(view.runtime.start_normal(|_, _| ()).is_err());
    assert_eq!(registry.metrics().native_bytes, 0);
    replacement.complete().unwrap();
    let next = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    assert_ne!(next.epoch, old_epoch);
    assert!(registry.is_current(next.epoch));
    assert!(!registry.is_current(old_epoch));
}

#[tokio::test]
async fn replacement_drains_a_running_open_before_releasing_its_charge() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let alive = Arc::new(AtomicUsize::new(0));
    let worker_alive = Arc::clone(&alive);
    let (mut release, wait, entered, started) = gate();
    let operation = view
        .runtime
        .start_normal(move |slot, cancellation| {
            *slot = Some(Pin::new(&worker_alive));
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
            assert!(cancellation.is_cancelled());
            7
        })
        .unwrap();
    bounded(started).await.unwrap();
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    let mut drained = Box::pin(replacement.drain());
    assert!(
        poll!(drained.as_mut()).is_pending(),
        "real opening work must drain"
    );
    assert_eq!(alive.load(Ordering::SeqCst), 1);
    assert!(
        registry.adjust_native_cost(&view.reservation, 1).is_err(),
        "invalidated reservations cannot change charges"
    );
    assert_eq!(registry.metrics().native_bytes, 64);
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 1);
    release.release();
    assert!(matches!(
        bounded(operation.result()).await,
        Err(ViewError::Ended(_))
    ));
    bounded(drained).await;
    assert_eq!(alive.load(Ordering::SeqCst), 0);
    assert_eq!(registry.metrics().active_views, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    replacement.complete().unwrap();
}

#[tokio::test]
async fn dropping_the_outer_handle_does_not_hide_a_detached_worker_from_drain() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let (mut release, wait, entered, started) = gate();
    let operation = view
        .runtime
        .start_normal(move |_, cancellation| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
            assert!(cancellation.is_cancelled());
        })
        .unwrap();
    bounded(started).await.unwrap();
    drop((operation, view));
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    let mut drained = Box::pin(replacement.drain());
    assert!(
        poll!(drained.as_mut()).is_pending(),
        "outer drop cannot hide actual work"
    );
    release.release();
    bounded(drained).await;
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    replacement.complete().unwrap();
}

#[tokio::test]
async fn replacement_cancels_queued_work_without_waiting_for_normal_capacity() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let held = scheduler
        .reserve(key(99), NORMAL)
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let worker_calls = Arc::clone(&calls);
    let operation = view
        .runtime
        .start_normal(move |_, _| {
            worker_calls.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    bounded(replacement.drain()).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        bounded(operation.result()).await,
        Err(ViewError::Ended(_))
    ));
    assert_eq!(
        scheduler.snapshot().class(NORMAL).resident,
        1,
        "only the unrelated held permit remains"
    );
    assert_eq!(registry.metrics().active_views, 0);
    drop(held);
    replacement.complete().unwrap();
}

#[tokio::test]
async fn abandoned_replacement_cannot_reopen_or_revive_old_views() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let old = view.epoch;
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    bounded(replacement.drain()).await;
    drop(replacement);
    assert!(!registry.is_current(old));
    assert!(view.runtime.start_normal(|_, _| ()).is_err());
    let attempt = registry.admit(
        key(2),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    );
    assert!(bounded(attempt).await.is_err());
    assert_eq!(registry.metrics().active_views, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn actual_native_cost_growth_is_charged_or_refused_transactionally() {
    let (_owner, scheduler, registry) = fixture(3, 100);
    let first = open(&registry, &scheduler, 1, CaptureCost::Native(40)).await;
    let second = open(&registry, &scheduler, 2, CaptureCost::Native(40)).await;
    assert!(!registry.adjust_native_cost(&first.reservation, 70).unwrap());
    assert_eq!(registry.metrics().native_bytes, 80);
    assert!(registry.adjust_native_cost(&first.reservation, 60).unwrap());
    assert_eq!(registry.metrics().native_bytes, 100);
    assert!(registry
        .adjust_native_cost(&first.reservation, 101)
        .is_err());
    assert_eq!(registry.metrics().native_bytes, 100);
    drop(second);
    assert!(registry
        .adjust_native_cost(&first.reservation, 100)
        .unwrap());
    assert_eq!(registry.metrics().native_bytes, 100);
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    bounded(replacement.drain()).await;
    assert!(registry.adjust_native_cost(&first.reservation, 1).is_err());
    assert_eq!(registry.metrics().native_bytes, 0);
    replacement.complete().unwrap();
}

#[tokio::test]
async fn wal_pressure_blocks_new_readers_but_keeps_an_active_reader_usable() {
    let (_owner, scheduler, registry) = fixture(2, 100);
    registry.observe_wal(Some(127));
    let first = open(&registry, &scheduler, 1, CaptureCost::Sqlite).await;
    registry.observe_wal(Some(1024));
    let mut second = Box::pin(registry.admit(
        key(2),
        CaptureCost::Sqlite,
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    ));
    assert!(poll!(second.as_mut()).is_pending());
    assert_eq!(
        bounded(first.runtime.start_normal(|_, _| 9).unwrap().result()).await,
        Ok(9)
    );
    assert_eq!(registry.metrics().sqlite_readers, 1);
    assert_eq!(registry.metrics().retained_wal_bytes, Some(1024));
    drop(first);
    assert!(
        poll!(second.as_mut()).is_pending(),
        "pressure persists after the first view closes"
    );
    registry.observe_wal(None);
    assert!(
        poll!(second.as_mut()).is_pending(),
        "unknown WAL must not become zero"
    );
    registry.observe_wal(Some(127));
    let second = bounded(second).await.unwrap();
    assert_eq!(registry.metrics().sqlite_readers, 1);
    drop(second);
    assert_eq!(registry.metrics().sqlite_readers, 0);
}

#[tokio::test]
async fn cleanup_expires_idle_views_but_keeps_accepted_work_charged() {
    let (_owner, scheduler, registry) = fixture(2, 100);
    let idle = open(&registry, &scheduler, 1, CaptureCost::Native(40)).await;
    let active = open(&registry, &scheduler, 2, CaptureCost::Native(40)).await;
    let (mut release, wait, entered, started) = gate();
    let operation = active
        .runtime
        .start_normal(move |_, _| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
        })
        .unwrap();
    bounded(started).await.unwrap();
    registry.expire_idle(Instant::now() + Duration::from_secs(60));
    assert!(idle.runtime.start_normal(|_, _| ()).is_err());
    assert_eq!(registry.metrics().active_views, 1);
    assert_eq!(registry.metrics().native_bytes, 40);
    release.release();
    bounded(operation.result()).await.unwrap();
    assert_eq!(
        bounded(active.runtime.start_normal(|_, _| 1).unwrap().result()).await,
        Ok(1)
    );
    drop((idle, active));
    assert_eq!(registry.metrics().active_views, 0);
}
#[tokio::test]
async fn queued_scopes_rotate_and_preserve_each_scope_order() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let held = open(&registry, &scheduler, 0, CaptureCost::Native(64)).await;
    let mut a1 = Box::pin(registry.admit(
        key(1),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(1), NORMAL).await.unwrap(),
    ));
    let mut a2 = Box::pin(registry.admit(
        key(1),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(1), NORMAL).await.unwrap(),
    ));
    let mut b1 = Box::pin(registry.admit(
        key(2),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    ));
    assert!(poll!(a1.as_mut()).is_pending());
    assert!(poll!(a2.as_mut()).is_pending());
    assert!(poll!(b1.as_mut()).is_pending());
    drop(held);
    let first = bounded(a1).await.unwrap();
    assert!(poll!(a2.as_mut()).is_pending());
    assert!(poll!(b1.as_mut()).is_pending());
    drop(first);
    let second = bounded(b1).await.unwrap();
    assert!(poll!(a2.as_mut()).is_pending());
    drop(second);
    drop(bounded(a2).await.unwrap());
    assert_eq!(registry.metrics().active_views, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn a_cost_reservation_cannot_be_used_on_another_registry() {
    let (_owner, scheduler, registry) = fixture(1, 100);
    let other = ViewRegistry::new(RetentionLimits::new(1, 1, 100, 128).unwrap(), IDLE).unwrap();
    let first = open(&registry, &scheduler, 1, CaptureCost::Native(40)).await;
    let second = open(&other, &scheduler, 1, CaptureCost::Native(40)).await;
    assert!(registry.adjust_native_cost(&second.reservation, 1).is_err());
    assert_eq!(registry.metrics().native_bytes, 40);
    assert_eq!(other.metrics().native_bytes, 40);
    drop((first, second));
}

#[tokio::test]
async fn replacement_cannot_reopen_before_actual_work_has_drained() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let (mut release, wait, entered, started) = gate();
    let operation = view
        .runtime
        .start_normal(move |_, _| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
        })
        .unwrap();
    bounded(started).await.unwrap();
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    assert!(
        replacement.complete().is_err(),
        "drain is a precondition for reopening"
    );
    let attempt = registry.admit(
        key(2),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    );
    assert!(bounded(attempt).await.is_err());
    release.release();
    assert!(bounded(operation.result()).await.is_err());
    assert_eq!(registry.metrics().active_views, 0);
}

#[tokio::test]
async fn shutdown_drains_actual_workers_and_permanently_closes_admission() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let (mut release, wait, entered, started) = gate();
    let operation = view
        .runtime
        .start_normal(move |_, _| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
        })
        .unwrap();
    bounded(started).await.unwrap();
    let mut waiting = Box::pin(registry.admit(
        key(2),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    ));
    assert!(poll!(waiting.as_mut()).is_pending());
    let mut closing = Box::pin(registry.close_and_drain(ViewInvalidation::Closed));
    assert!(
        poll!(closing.as_mut()).is_pending(),
        "shutdown must await actual work"
    );
    assert!(bounded(waiting).await.is_err());
    assert_eq!(registry.metrics().native_bytes, 64);
    assert_eq!(scheduler.snapshot().class(NORMAL).running, 1);
    drop(closing); // Cancellation cannot reopen admission.
    let attempt = registry.admit(
        key(3),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(3), NORMAL).await.unwrap(),
    );
    assert!(bounded(attempt).await.is_err());
    release.release();
    assert!(bounded(operation.result()).await.is_err());
    bounded(registry.close_and_drain(ViewInvalidation::Closed)).await;
    assert_eq!(registry.metrics().active_views, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    assert!(registry
        .begin_replacement(ViewInvalidation::BackendRestarted)
        .is_err());
}

#[tokio::test]
async fn shutdown_wins_over_a_successful_snapshot_replacement() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    bounded(replacement.drain()).await;
    bounded(registry.close_and_drain(ViewInvalidation::Closed)).await;
    assert!(replacement.complete().is_err(), "shutdown must not reopen");
    assert!(!registry.is_current(view.epoch));
    let attempt = registry.admit(
        key(2),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    );
    assert!(bounded(attempt).await.is_err());
}

#[test]
fn cleanup_can_restart_after_its_tokio_runtime_is_dropped() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    for _ in 0..2 {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let view = runtime.block_on(async {
            let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
            tokio::task::yield_now().await;
            assert!(registry.cleanup_running.load(Ordering::Acquire));
            view
        });
        drop(view);
        drop(runtime);
        assert!(
            !registry.cleanup_running.load(Ordering::Acquire),
            "cleanup latched across runtime shutdown"
        );
    }
}

#[tokio::test]
async fn released_idle_handles_cannot_grow_registry_metadata() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let mut ended = Vec::new();
    for _ in 0..256 {
        let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
        view.runtime.invalidate(ViewInvalidation::Closed);
        ended.push(view);
        registry.expire_idle(Instant::now());
        assert!(
            lock(&registry.state).controls.is_empty(),
            "drained controls must be pruned"
        );
    }
    assert_eq!(registry.metrics().active_views, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn epoch_exhaustion_closes_and_releases_idle_resources() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let alive = Arc::new(AtomicUsize::new(0));
    let worker_alive = Arc::clone(&alive);
    bounded(
        view.runtime
            .start_normal(move |slot, _| *slot = Some(Pin::new(&worker_alive)))
            .unwrap()
            .result(),
    )
    .await
    .unwrap();
    lock(&registry.state).epoch = u64::MAX;
    assert!(matches!(
        registry.begin_replacement(ViewInvalidation::BackendRestarted),
        Err(RegistryError::EpochExhausted)
    ));
    assert_eq!(alive.load(Ordering::SeqCst), 0);
    assert_eq!(registry.metrics().active_views, 0);
    assert!(view.runtime.start_normal(|_, _| ()).is_err());
    let attempt = registry.admit(
        key(2),
        CaptureCost::Native(64),
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    );
    assert!(bounded(attempt).await.is_err());
}

#[tokio::test]
async fn replacement_drains_a_grant_still_being_registered() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let (mut release, wait, entered, started) = gate();
    *lock(&registry.before_registration) = Some(Box::new(move || {
        entered.send(()).unwrap();
        wait.recv_timeout(TIMEOUT).unwrap();
    }));
    let opener_registry = Arc::clone(&registry);
    let resident = scheduler.reserve(key(1), NORMAL).await.unwrap();
    let opener = tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(opener_registry.admit(
            key(1),
            CaptureCost::Native(64),
            None,
            resident,
        ))
    });
    bounded(started).await.unwrap();
    assert_eq!(registry.metrics().active_views, 1);
    assert!(lock(&registry.state).controls.is_empty());
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    let mut draining = Box::pin(replacement.drain());
    assert!(
        poll!(draining.as_mut()).is_pending(),
        "registration gap must remain charged"
    );
    release.release();
    assert!(matches!(
        bounded(opener).await.unwrap(),
        Err(RegistryError::Ended(ViewInvalidation::SnapshotInstalled))
    ));
    bounded(draining).await;
    assert_eq!(registry.metrics().active_views, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    replacement.complete().unwrap();
}

struct DropProbe {
    registry: Weak<ViewRegistry<DropProbe>>,
    dropped: Arc<AtomicUsize>,
    locked: Arc<AtomicBool>,
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            self.locked
                .fetch_or(registry.state.try_lock().is_err(), Ordering::SeqCst);
        }
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn rejected_cancelled_and_revoked_resources_drop_outside_the_registry_lock() {
    let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default()).unwrap();
    let scheduler = owner.scheduler();
    let registry = ViewRegistry::new(RetentionLimits::new(1, 1, 64, 128).unwrap(), IDLE).unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let locked = Arc::new(AtomicBool::new(false));
    let probe = || DropProbe {
        registry: Arc::downgrade(&registry),
        dropped: Arc::clone(&dropped),
        locked: Arc::clone(&locked),
    };
    for bytes in [0, 65] {
        assert!(registry
            .admit(
                key(1),
                CaptureCost::Native(bytes),
                probe(),
                scheduler.reserve(key(1), NORMAL).await.unwrap()
            )
            .await
            .is_err());
    }
    let first = registry
        .admit(
            key(1),
            CaptureCost::Native(64),
            probe(),
            scheduler.reserve(key(1), NORMAL).await.unwrap(),
        )
        .await
        .unwrap();
    let mut cancelled = Box::pin(registry.admit(
        key(2),
        CaptureCost::Native(64),
        probe(),
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    ));
    assert!(poll!(cancelled.as_mut()).is_pending());
    drop(cancelled);
    let mut waiting = Box::pin(registry.admit(
        key(3),
        CaptureCost::Native(64),
        probe(),
        scheduler.reserve(key(3), NORMAL).await.unwrap(),
    ));
    assert!(poll!(waiting.as_mut()).is_pending());
    bounded(registry.close_and_drain(ViewInvalidation::Closed)).await;
    assert!(bounded(waiting).await.is_err());
    assert!(registry
        .admit(
            key(4),
            CaptureCost::Native(64),
            probe(),
            scheduler.reserve(key(4), NORMAL).await.unwrap()
        )
        .await
        .is_err());
    drop(first);
    assert_eq!(dropped.load(Ordering::SeqCst), 6);
    assert!(
        !locked.load(Ordering::SeqCst),
        "resource destructor ran under registry lock"
    );
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
}

#[tokio::test]
async fn idle_metrics_exclude_queued_and_executing_activity() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let held = scheduler
        .reserve(key(2), NORMAL)
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    assert!(registry.metrics().oldest_idle_age.is_some());
    let (mut release, wait, entered, started) = gate();
    let operation = view
        .runtime
        .start_normal(move |_, _| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
        })
        .unwrap();
    assert_eq!(registry.metrics().oldest_idle_age, None);
    drop(held);
    bounded(started).await.unwrap();
    assert_eq!(registry.metrics().oldest_idle_age, None);
    release.release();
    bounded(operation.result()).await.unwrap();
    assert!(registry.metrics().oldest_idle_age.is_some());
    drop(view);
    assert_eq!(registry.metrics().oldest_idle_age, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_waits_for_s7_credit_after_capture_charge_is_released() {
    let (_owner, scheduler, registry) = fixture(1, 64);
    let view = open(&registry, &scheduler, 1, CaptureCost::Native(64)).await;
    let (mut release, wait, entered, started) = gate();
    let (mut release_charge, charge_wait, charge_entered, charge_started) = gate();
    *lock(&registry.after_release) = Some(Box::new(move || {
        charge_entered.send(()).unwrap();
        charge_wait.recv_timeout(TIMEOUT).unwrap();
    }));
    let operation = view
        .runtime
        .start_normal(move |_, _| {
            entered.send(()).unwrap();
            wait.recv_timeout(TIMEOUT).unwrap();
        })
        .unwrap();
    bounded(started).await.unwrap();
    drop(view);
    release.release();
    bounded(charge_started).await.unwrap();
    assert_eq!(registry.metrics().active_views, 0);
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 1);
    // Charge release is not enough to prune a detached worker's lifecycle
    // control. Replacement starts only after this cleanup opportunity.
    registry.expire_idle(Instant::now());
    let replacement = registry
        .begin_replacement(ViewInvalidation::SnapshotInstalled)
        .unwrap();
    let mut draining = Box::pin(replacement.drain());
    assert!(
        poll!(draining.as_mut()).is_pending(),
        "scheduler credit must drain after capture charge"
    );
    release_charge.release();
    assert!(bounded(operation.result()).await.is_err());
    bounded(draining).await;
    assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
    replacement.complete().unwrap();
}

#[tokio::test]
async fn native_cost_growth_cannot_wrap_the_total_reservation() {
    let (_owner, scheduler, registry) = fixture(2, u64::MAX);
    let first = open(&registry, &scheduler, 1, CaptureCost::Native(u64::MAX - 4)).await;
    let second = open(&registry, &scheduler, 2, CaptureCost::Native(4)).await;
    assert!(
        !registry
            .adjust_native_cost(&first.reservation, u64::MAX - 3)
            .unwrap(),
        "cost growth overflow must refuse without changing reservations"
    );
    assert_eq!(registry.metrics().native_bytes, u64::MAX);
    drop((first, second));
    assert_eq!(registry.metrics().native_bytes, 0);
}

#[tokio::test(start_paused = true)]
async fn wal_probe_wakes_queued_readers_without_client_activity() {
    let (_owner, scheduler, registry) = fixture(2, 100);
    let bytes = Arc::new(std::sync::atomic::AtomicU64::new(256));
    let observed = Arc::clone(&bytes);
    registry.observe_wal(Some(256));
    registry.set_wal_probe(Arc::new(move || {
        Box::pin(std::future::ready(Some(observed.load(Ordering::Acquire))))
    }));
    let mut waiting = Box::pin(registry.admit(
        key(1),
        CaptureCost::Sqlite,
        None,
        scheduler.reserve(key(1), NORMAL).await.unwrap(),
    ));
    assert!(poll!(waiting.as_mut()).is_pending());
    bytes.store(64, Ordering::Release);
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = tokio::time::timeout(TIMEOUT, waiting).await;
    assert!(
        result.is_ok(),
        "checkpoint relief must wake admission without a client operation"
    );
    let view = result.unwrap().unwrap();
    assert_eq!(registry.metrics().retained_wal_bytes, Some(64));
    drop(view);
}

#[tokio::test]
async fn wal_probe_failure_cannot_reuse_an_old_low_measurement() {
    let (_owner, scheduler, registry) = fixture(2, 100);
    registry.observe_wal(Some(64));
    registry.set_wal_probe(Arc::new(|| Box::pin(std::future::ready(None))));
    let mut waiting = Box::pin(registry.admit(
        key(1),
        CaptureCost::Sqlite,
        None,
        scheduler.reserve(key(1), NORMAL).await.unwrap(),
    ));
    assert!(
        poll!(waiting.as_mut()).is_pending(),
        "unknown WAL cannot admit using a stale low sample"
    );
    assert_eq!(registry.metrics().retained_wal_bytes, None);
}

#[tokio::test]
async fn wal_probe_runs_outside_registry_locks_before_admission() {
    let (_owner, scheduler, registry) = fixture(2, 100);
    let weak = Arc::downgrade(&registry);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    registry.observe_wal(Some(64));
    registry.set_wal_probe(Arc::new(move || {
        let registry = weak.upgrade().unwrap();
        assert!(
            registry.state.try_lock().is_ok(),
            "descriptor probe cannot hold the registry mutex"
        );
        assert!(
            registry.wal_probe.try_lock().is_ok(),
            "descriptor probe cannot hold its callback mutex"
        );
        counted.fetch_add(1, Ordering::AcqRel);
        Box::pin(std::future::ready(Some(64)))
    }));
    let view = open(&registry, &scheduler, 1, CaptureCost::Sqlite).await;
    assert!(
        calls.load(Ordering::Acquire) > 0,
        "admission must take a fresh descriptor sample"
    );
    drop(view);
}

#[tokio::test]
async fn wal_probe_rechecks_live_pressure_before_each_admission() {
    let (_owner, scheduler, registry) = fixture(2, 100);
    let bytes = Arc::new(std::sync::atomic::AtomicU64::new(64));
    let observed = Arc::clone(&bytes);
    registry.observe_wal(Some(64));
    registry.set_wal_probe(Arc::new(move || {
        Box::pin(std::future::ready(Some(observed.load(Ordering::Acquire))))
    }));
    let first = open(&registry, &scheduler, 1, CaptureCost::Sqlite).await;
    bytes.store(256, Ordering::Release);
    let mut second = Box::pin(registry.admit(
        key(2),
        CaptureCost::Sqlite,
        None,
        scheduler.reserve(key(2), NORMAL).await.unwrap(),
    ));
    assert!(
        poll!(second.as_mut()).is_pending(),
        "new admission must remeasure pressure before a periodic tick"
    );
    assert_eq!(registry.metrics().retained_wal_bytes, Some(256));
    assert_eq!(registry.metrics().sqlite_readers, 1);
    assert_eq!(
        bounded(first.runtime.start_normal(|_, _| 7).unwrap().result()).await,
        Ok(7)
    );
}

#[tokio::test]
async fn pending_wal_probe_does_not_block_idle_cleanup_or_retain_the_registry() {
    let owner = ScopeSchedulerOwner::default();
    let scheduler = owner.scheduler();
    let registry = ViewRegistry::new(Default::default(), Duration::from_secs(1)).unwrap();
    let idle = open(&registry, &scheduler, 1, CaptureCost::Native(40)).await;
    let alive = Arc::new(AtomicUsize::new(0));
    let held = Arc::clone(&alive);
    let started = Arc::new(Notify::new());
    let wake = Arc::clone(&started);
    registry.set_wal_probe(Arc::new(move || {
        let pin = Pin::new(&held);
        wake.notify_one();
        Box::pin(async move {
            let _pin = pin;
            std::future::pending().await
        })
    }));
    bounded(started.notified()).await;
    assert_eq!(alive.load(Ordering::Acquire), 1);
    bounded(async {
        loop {
            let changed = registry.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if registry.metrics().active_views == 0 {
                break;
            }
            changed.await;
        }
    })
    .await;
    assert!(idle.runtime.start_normal(|_, _| ()).is_err());
    assert_eq!(alive.load(Ordering::Acquire), 0);
    let weak = Arc::downgrade(&registry);
    drop((idle, registry));
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn wal_probe_wait_is_cancelled_by_close_or_replacement_without_writer_progress() {
    for replace in [false, true] {
        let (_owner, scheduler, registry) = fixture(2, 100);
        let alive = Arc::new(AtomicUsize::new(0));
        let held = Arc::clone(&alive);
        let started = Arc::new(Notify::new());
        let wake = Arc::clone(&started);
        registry.set_wal_probe(Arc::new(move || {
            let pin = Pin::new(&held);
            wake.notify_one();
            Box::pin(async move {
                let _pin = pin;
                std::future::pending().await
            })
        }));
        let resident = scheduler.reserve(key(1), NORMAL).await.unwrap();
        let waiting = tokio::spawn({
            let registry = Arc::clone(&registry);
            async move {
                registry
                    .admit(key(1), CaptureCost::Sqlite, None, resident)
                    .await
            }
        });
        bounded(started.notified()).await;
        assert_eq!(alive.load(Ordering::Acquire), 1);
        if replace {
            let replacement = registry
                .begin_replacement(ViewInvalidation::SnapshotInstalled)
                .unwrap();
            bounded(replacement.drain()).await;
            replacement.complete().unwrap();
        } else {
            bounded(registry.close_and_drain(ViewInvalidation::Closed)).await;
        }
        assert!(matches!(
            bounded(waiting).await.unwrap(),
            Err(RegistryError::Ended(_))
        ));
        assert_eq!(alive.load(Ordering::Acquire), 0);
        assert_eq!(scheduler.snapshot().class(NORMAL).resident, 0);
        assert_eq!(registry.metrics().active_views, 0);
    }
}
