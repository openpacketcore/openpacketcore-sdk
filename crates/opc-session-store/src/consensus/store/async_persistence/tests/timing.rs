//! Functional completion follows publication; deadline tests advance time explicitly.

use super::*;
use crate::consensus::snapshot::SnapshotArtifactGate;

struct Release(Arc<SnapshotArtifactGate>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[cfg(feature = "test-vfs")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_fixture_close_is_independent_of_the_callers_clock() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    fleet.start().await;
    let old = fleet.store(0).clone();
    let hold = old.hold_raft_shutdown_before_core_for_test();
    let (mut fleet, closed, completed_before_release) = crate::formation_clock::run(async move {
        let (closed, early) = {
            // Force close's first poll to wait on an in-flight handler lease.
            // Releasing it requires close to be polled again to start shutdown.
            let peer = Arc::clone(&fleet.peers[0]);
            let handler = peer.handler.read().await;
            let close = fleet.close_and_join_result(0);
            tokio::pin!(close);
            assert!(futures_util::poll!(close.as_mut()).is_pending());
            drop(handler);
            let gate = Arc::clone(&hold.gate);
            let entered = tokio::task::spawn_blocking(move || {
                gate.wait_until_entered(Duration::from_secs(30))
            });
            tokio::select! {
                entered = entered => assert!(entered.unwrap()),
                result = close.as_mut() => {
                    panic!("fixture cleanup completed before the shutdown gate: {result:?}");
                }
            }
            tokio::time::advance(OPERATION_BOUND + Duration::from_millis(1)).await;
            let early = futures_util::poll!(close.as_mut());
            drop(hold);
            match early {
                std::task::Poll::Ready(result) => (result, true),
                std::task::Poll::Pending => (close.await, false),
            }
        };
        // Even a failing case must join the accepted shutdown before its clock
        // runtime is dropped. A caller deadline never cancels that owner.
        old.shutdown_with_closed_proof(false).await.unwrap();
        drop(old);
        (fleet, closed, early)
    })
    .await;
    fleet.close_all().await;
    assert!(
        !completed_before_release,
        "fixture cleanup used the caller's deadline"
    );
    assert_eq!(closed, Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_drain_observes_publication_without_a_protocol_timer_tick() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let gate = Arc::new(SnapshotArtifactGate::new());
    let release = Release(Arc::clone(&gate));
    let held = Arc::clone(&gate);
    fleet
        .open_with_hook(
            0,
            SessionPersistenceMode::Async,
            Some(Arc::new(move || {
                held.block_if_armed_blocking();
                Ok(())
            })),
        )
        .await
        .unwrap();
    for index in [1, 2] {
        fleet
            .open(index, SessionPersistenceMode::Async)
            .await
            .unwrap();
    }
    fleet.form().await;
    let store = fleet.store(0).clone();
    clock::drain(&store).await.unwrap();
    gate.arm();
    let request = create_request(fleet.store(fleet.leader()), 1701, &provider()).await;
    let outcome = create(fleet.store(fleet.leader()), &request).await;
    assert_recorded(&store, &request, &outcome).await;
    let wal = Arc::clone(store.inner.private_wal.as_ref().unwrap());
    let cut = wal.request_async_persistence().unwrap();
    tokio::time::timeout(Duration::from_secs(30), gate.wait_started())
        .await
        .unwrap();
    let observed = crate::formation_clock::run(async move {
        let mut publication = wal.async_progress_for_test();
        {
            let held_drain = store.drain_async_persistence();
            tokio::pin!(held_drain);
            assert!(futures_util::poll!(held_drain.as_mut()).is_pending());
            tokio::time::advance(OPERATION_BOUND - Duration::from_millis(1)).await;
            assert!(futures_util::poll!(held_drain.as_mut()).is_pending());
            tokio::time::advance(Duration::from_millis(1)).await;
            assert_eq!(
                held_drain.await,
                Err(SessionPersistenceDrainError::DeadlineExceeded)
            );
        }
        let started = tokio::time::Instant::now();
        let drain = store.drain_async_persistence();
        tokio::pin!(drain);
        assert!(futures_util::poll!(drain.as_mut()).is_pending());
        gate.release();
        loop {
            publication.borrow_and_update();
            let progress = store.persistence_health().asynchronous.unwrap();
            if progress.completed_generation >= cut.0 && progress.completed_sequence >= cut.1 {
                break;
            }
            publication.changed().await.unwrap();
        }
        assert_eq!(started.elapsed(), Duration::ZERO);
        match futures_util::poll!(drain.as_mut()) {
            std::task::Poll::Ready(result) => Some(result),
            std::task::Poll::Pending => None,
        }
    })
    .await;
    drop(release);
    fleet.close_all().await;
    assert!(
        observed.is_some(),
        "published cut still waits for a timer tick"
    );
    assert!(observed.unwrap().is_ok());
}

#[tokio::test(start_paused = true)]
async fn functional_progress_wait_is_independent_of_the_callers_clock() {
    let (publication, observed) = tokio::sync::watch::channel(false);
    let current = observed.clone();
    let wait = AssertUnwindSafe(races::until(
        [observed],
        || *current.borrow(),
        "real publication is still deliberately held",
    ))
    .catch_unwind();
    tokio::pin!(wait);
    assert!(futures_util::poll!(wait.as_mut()).is_pending());
    tokio::time::advance(OPERATION_BOUND + Duration::from_millis(1)).await;
    let early = futures_util::poll!(wait.as_mut());
    publication.send_replace(true);
    let (result, completed_before_release) = match early {
        std::task::Poll::Ready(result) => (result, true),
        std::task::Poll::Pending => (wait.await, false),
    };
    assert!(
        result.is_ok(),
        "functional progress expired on the caller's clock"
    );
    assert!(!completed_before_release);
}
