//! Clock controls for bounded operations and real fixture-event watchdogs.

use super::*;
use std::future::Future;

pub(super) use crate::formation_clock::controlled_clock::run;

/// A missing fixture event fails against real time. Advancing a protocol clock
/// must not pretend that the disk or another runtime has had time to publish.
pub(super) async fn watchdog<F: Future>(operation: F, message: &str) -> F::Output {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let mut watchdog =
        tokio::task::spawn_blocking(move || held.recv_timeout(Duration::from_secs(30)));
    let result = tokio::select! {
        biased;
        result = operation => Some(result),
        expired = &mut watchdog => {
            let _ = expired.expect("fixture watchdog task");
            None
        }
    };
    drop(release);
    match result {
        Some(result) => {
            let _ = watchdog.await.expect("retire fixture watchdog");
            result
        }
        None => panic!("{message}"),
    }
}

pub(super) async fn complete<F>(operation_timeout: Duration, operation: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    assert_eq!(operation_timeout, OPERATION_BOUND);
    run(async move {
        let started = tokio::time::Instant::now();
        let deadline = started + operation_timeout;
        let result = operation.await;
        assert!(
            tokio::time::Instant::now() < deadline,
            "functional operation must complete before its own deadline"
        );
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "functional completion needed no protocol timer"
        );
        result
    })
    .await
}

pub(super) async fn drain(
    store: &ConsensusSessionStore,
) -> Result<SessionPersistenceHealth, SessionPersistenceDrainError> {
    assert_eq!(store.inner.operation_timeout, OPERATION_BOUND);
    let started = std::time::Instant::now();
    let result = store.drain_async_persistence().await;
    if result.is_ok() {
        assert!(
            started.elapsed() < store.inner.operation_timeout,
            "successful fixture drain must retain its real-time operation bound"
        );
    }
    result
}

pub(super) async fn initialize(
    store: &ConsensusSessionStore,
) -> Result<(), ConsensusSessionStoreOpenError> {
    assert_eq!(store.inner.operation_timeout, OPERATION_BOUND);
    let started = std::time::Instant::now();
    let result = store.initialize_cluster().await;
    if result.is_ok() {
        assert!(
            started.elapsed() < store.inner.operation_timeout,
            "successful fixture initialization must retain its real-time operation bound"
        );
    }
    result
}
