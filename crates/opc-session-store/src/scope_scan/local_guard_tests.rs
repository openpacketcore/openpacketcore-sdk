//! Local stamp checks retain execution credit until their actual worker exits.
use super::*;
use crate::scope_scan::ScopeScanError;
use crate::scope_scheduler::{
    ClassBudget, ScopeScheduler, ScopeSchedulerBudgets, ScopeSchedulerKey, ScopeSchedulerOwner,
};
use std::sync::mpsc;

const WAIT: Duration = Duration::from_secs(5);

async fn setup(class: ScopeWorkClass) -> (ScopeSchedulerOwner, ScopeScheduler, ScopeWorkPermit) {
    let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
        class,
        ClassBudget {
            queued: 4,
            running: 1,
        },
    ))
    .unwrap();
    let scheduler = owner.scheduler();
    let permit = scheduler
        .reserve(ScopeSchedulerKey::from_bytes([1; 32]), class)
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    (owner, scheduler, permit)
}

struct Release(Option<mpsc::Sender<()>>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

#[tokio::test]
async fn local_guard_owns_its_fixed_class_credit_inside_the_actual_worker() {
    for class in [
        ScopeWorkClass::Normal,
        ScopeWorkClass::EmergencyClassification,
    ] {
        let (_owner, scheduler, permit) = setup(class).await;
        let during = scheduler.clone();
        let result = run_local_guard(permit, move |cancelled| {
            assert!(!cancelled.is_cancelled());
            let count = during.snapshot().class(class);
            assert_eq!((count.running, count.resident), (1, 1));
            Ok(())
        })
        .await;
        assert_eq!(
            result,
            Ok(()),
            "local validation executes under its trusted class"
        );
        let count = scheduler.snapshot().class(class);
        assert_eq!((count.running, count.resident), (0, 0));
    }
}

#[tokio::test]
async fn dropping_a_local_guard_signals_cancellation_but_retains_credit_until_worker_drain() {
    let class = ScopeWorkClass::Normal;
    let (_owner, scheduler, permit) = setup(class).await;
    let (entered, started) = oneshot::channel();
    let (release, wait) = mpsc::channel();
    let release = Release(Some(release));
    let during = scheduler.clone();
    let operation = tokio::spawn(run_local_guard(permit, move |cancelled| {
        let _ = entered.send(cancelled.clone());
        wait.recv_timeout(WAIT)
            .expect("test releases the blocking guard");
        assert!(cancelled.is_cancelled());
        assert_eq!(during.snapshot().class(class).running, 1);
        Ok(())
    }));
    let cancellation = tokio::time::timeout(WAIT, started)
        .await
        .unwrap()
        .expect("local guard starts its actual worker");
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    assert!(
        cancellation.is_cancelled(),
        "dropping the response future revokes accepted work"
    );
    let count = scheduler.snapshot().class(class);
    assert_eq!(
        (count.running, count.resident),
        (1, 1),
        "actual work still owns both credits"
    );
    drop(release);
    tokio::time::timeout(WAIT, async {
        while {
            let count = scheduler.snapshot().class(class);
            (count.running, count.resident) != (0, 0)
        } {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("blocking worker drains");
    let count = scheduler.snapshot().class(class);
    assert_eq!((count.running, count.resident), (0, 0));
}

#[tokio::test]
async fn local_guard_worker_panic_is_typed_and_releases_actual_execution_credit() {
    let class = ScopeWorkClass::Normal;
    let (_owner, scheduler, permit) = setup(class).await;
    let (entered, started) = oneshot::channel();
    let result = run_local_guard(permit, move |_| {
        let _ = entered.send(());
        panic!("deliberate local guard worker failure")
    })
    .await;
    started.await.expect("actual worker ran before its panic");
    assert_eq!(result, Err(ScopeScanError::Unavailable));
    let count = scheduler.snapshot().class(class);
    assert_eq!((count.running, count.resident), (0, 0));
}
