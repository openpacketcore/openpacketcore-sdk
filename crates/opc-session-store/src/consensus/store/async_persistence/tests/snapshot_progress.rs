//! A complete snapshot can take many stall intervals while making real progress.

use super::*;
use crate::sqlite::consensus::wal::{owner::IoHookForTest, Point};

async fn slow_progressing_snapshot(mode: SessionPersistenceMode) {
    let mut fleet = Fleet::new(3);
    let enabled: Vec<_> = (0..3).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let progress: Vec<_> = (0..3).map(|_| Arc::new(AtomicU64::new(0))).collect();
    let result = AssertUnwindSafe(async {
        for index in 0..3 {
            let enabled = Arc::clone(&enabled[index]);
            let progress = Arc::clone(&progress[index]);
            let hook: IoHookForTest = Arc::new(move |point| {
                if point == Point::NativeSnapshotExportProgress
                    && enabled.load(Ordering::Acquire)
                {
                    progress.fetch_add(1, Ordering::AcqRel);
                    // Every call is another bounded unit of the real native
                    // export. Slow each unit without blocking its progress.
                    std::thread::sleep(Duration::from_millis(25));
                }
                Ok(())
            });
            fleet
                .open_with_all_hooks(index, mode, None, None, Some(hook))
                .await
                .unwrap();
        }
        fleet.form().await;
        let leader = fleet.leader();
        let store = fleet.store(leader);
        // Distinct receipts make the export visit actual rows. Replaying one
        // idempotent request would not grow the business-state projection.
        for _ in 0..32 {
            let mut command = repeated_command(store);
            command.request_id = SessionConsensusRequestId::new();
            let reply = propose(store, &command, tokio::time::Instant::now() + WAIT).await;
            assert!(
                matches!(&reply, ForwardMutationReply::Applied(response) if response.result.is_ok()),
                "seed a distinct retained receipt: {reply:?}"
            );
        }
        let interval = Duration::from_millis(500);
        store
            .inner
            .storage_shutdown
            .set_snapshot_limits_for_test(interval, Duration::from_secs(5));
        let cut = store.inner.raft.metrics().borrow().last_applied.unwrap();
        assert!(store.inner.raft.metrics().borrow().snapshot.is_none());
        enabled[leader].store(true, Ordering::Release);
        let started = tokio::time::Instant::now();
        store.inner.raft.trigger().snapshot().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let steps = progress[leader].load(Ordering::Acquire);
                let retries = store.inner.storage_shutdown.snapshot_retries_for_test();
                assert_eq!(
                    retries, 0,
                    "slow progressing snapshot restarted after {steps} completed export units"
                );
                if store
                    .inner
                    .raft
                    .metrics()
                    .borrow()
                    .snapshot
                    .is_some_and(|snapshot| snapshot.index >= cut.index)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the original slow, progressing build must publish its captured cut");
        assert!(started.elapsed() > interval);
        assert!(progress[leader].load(Ordering::Acquire) >= 32);
        assert_eq!(store.inner.storage_shutdown.snapshot_retries_for_test(), 0);
        assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
    })
    .catch_unwind()
    .await;
    for enabled in enabled {
        enabled.store(false, Ordering::Release);
    }
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_slow_progressing_snapshot_finishes_durable() {
    slow_progressing_snapshot(SessionPersistenceMode::Durable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_slow_progressing_snapshot_finishes_async() {
    slow_progressing_snapshot(SessionPersistenceMode::Async).await;
}
