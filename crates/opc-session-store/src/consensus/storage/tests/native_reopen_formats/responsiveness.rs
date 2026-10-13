//! A paused generation scan must leave a current-thread runtime available.

use super::*;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};

async fn large_generation(directory: &FixedRawReadStoreFixture, mode: SessionPersistenceMode) {
    let (backend, raft, wal, _) = native_log_retained_bound::open_engine(directory, mode).await;
    let profile = opc_consensus::DURABLE_OPENRAFT_PROFILE;
    for start in (0..16_384_u64).step_by(64) {
        let end = start + 64;
        let entries = (start..end)
            .map(|index| {
                if index == 0 {
                    fixed_initial_membership_entry()
                } else {
                    blank_entry(index)
                }
            })
            .collect();
        assert_eq!(
            raft.append_entries(AppendEntriesRequest {
                vote: Vote::new_committed(1, node_id()),
                prev_log_id: start.checked_sub(1).map(log_id),
                leader_commit: Some(log_id(end - 1)),
                entries,
            })
            .await
            .unwrap(),
            AppendEntriesResponse::Success
        );
        raft.wait(Some(Duration::from_secs(300)))
            .applied_index_at_least(Some(end - 1), "large generation applied")
            .await
            .unwrap();
        if end.is_multiple_of(profile.logs_per_snapshot) {
            // Finish each ordinary snapshot cycle before adding more rows.
            // In-flight snapshot construction must not outlive fixture setup
            // and contaminate the opener's no-write observation.
            raft.wait(Some(Duration::from_secs(300)))
                .metrics(
                    |metrics| {
                        metrics.snapshot == Some(log_id(end - 1))
                            && metrics.purged == Some(log_id(end - profile.retained_logs - 1))
                    },
                    "large generation snapshot and purge completed",
                )
                .await
                .unwrap();
        }
    }
    drop(close_engine(backend, raft, wal).await);
    let bytes: u64 = std::fs::read_dir(directory.path().join(format!("{DATABASE}.native-wal")))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "native")
        })
        .map(|entry| entry.metadata().unwrap().len())
        .sum();
    assert!(bytes >= 512 * 1024, "fixture must scan a large generation");
}

async fn responsive_preflight(expected_identity: SessionConsensusIdentity) {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let directory = FixedRawReadStoreFixture::new();
        large_generation(&directory, mode).await;
        let backend = SqliteSessionBackend::open(directory.path().join(DATABASE)).unwrap();
        let before = (
            namespace(directory.path()),
            namespace(directory.snapshot_path()),
            root_selection(&directory),
        );
        let checks = Arc::new(AtomicUsize::new(0));
        let checked = Arc::clone(&checks);
        let (entered, started) = tokio::sync::oneshot::channel();
        let entered = Mutex::new(Some(entered));
        let (release, wait) = mpsc::channel();
        let wait = Mutex::new(wait);
        backend
            .native_owner
            .as_ref()
            .unwrap()
            .set_preflight_hook_for_test(Arc::new(move || {
                // The first check precedes file open; the next two checks
                // straddle the first selected block read. Pause within the
                // scan, after some real I/O, without relying on its duration.
                if checked.fetch_add(1, Ordering::SeqCst) == 2 {
                    entered.lock().unwrap().take().unwrap().send(()).unwrap();
                    wait.lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(30))
                        .map_err(|_| std::io::Error::other("preflight scan release timed out"))?;
                }
                Ok(())
            }));
        let timer_ran = Arc::new(AtomicBool::new(false));
        let timer_flag = Arc::clone(&timer_ran);
        let timer = tokio::spawn(async move {
            started.await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
            timer_flag.store(true, Ordering::SeqCst);
            release.send(()).unwrap();
        });
        let snapshots_inspected = AtomicBool::new(false);
        let result = backend
            .native_persistence_preflight(expected_identity, |_| async {
                assert!(timer_ran.load(Ordering::SeqCst));
                // Observe the completed read-only scan before the admitted
                // scope-lookup path may query SQLite and open its WAL readers.
                assert_eq!(
                    (
                        namespace(directory.path()),
                        namespace(directory.snapshot_path()),
                        root_selection(&directory)
                    ),
                    before,
                    "compatibility inspection must not initialize storage"
                );
                snapshots_inspected.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;
        let progressed_during_scan = timer_ran.load(Ordering::SeqCst);
        timer.await.unwrap();
        assert!(
            progressed_during_scan,
            "a paused compatibility scan blocked the current-thread runtime"
        );
        assert!(checks.load(Ordering::SeqCst) > 3);
        assert!(snapshots_inspected.load(Ordering::SeqCst));
        assert_eq!(
            result,
            if expected_identity == identity(1) {
                Ok(Some(mode))
            } else {
                Err(SessionConsensusStorageError::IdentityMismatch)
            }
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_format_preflight_keeps_runtime_responsive_for_matching_scope() {
    responsive_preflight(identity(1)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn native_format_preflight_keeps_runtime_responsive_before_scope_lookup() {
    responsive_preflight(identity(2)).await;
}

fn cancellation_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
}

#[test]
fn native_format_preflight_cancels_running_scans() {
    cancellation_runtime().block_on(async {
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let directory = FixedRawReadStoreFixture::new();
            large_generation(&directory, mode).await;
            for expected in [identity(1), identity(2)] {
                let backend = SqliteSessionBackend::open(directory.path().join(DATABASE)).unwrap();
                let owner = backend.native_owner.as_ref().unwrap();
                let before = (
                    namespace(directory.path()),
                    namespace(directory.snapshot_path()),
                    root_selection(&directory),
                );
                let checks = Arc::new(AtomicUsize::new(0));
                let checked = Arc::clone(&checks);
                let (entered, started) = tokio::sync::oneshot::channel();
                let entered = Mutex::new(Some(entered));
                let (release, wait) = mpsc::channel();
                let wait = Mutex::new(wait);
                owner.set_preflight_hook_for_test(Arc::new(move || {
                    if checked.fetch_add(1, Ordering::SeqCst) == 2 {
                        entered.lock().unwrap().take().unwrap().send(()).unwrap();
                        wait.lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(30))
                            .map_err(|_| {
                                std::io::Error::other("preflight scan release timed out")
                            })?;
                    }
                    Ok(())
                }));
                let inspected = AtomicBool::new(false);
                let mut opening =
                    Box::pin(backend.native_persistence_preflight(expected, |_| async {
                        inspected.store(true, Ordering::SeqCst);
                        Ok(())
                    }));
                assert!(std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(opening.as_mut().poll(cx))
                })
                .await
                .is_pending());
                tokio::time::timeout(Duration::from_secs(30), started)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(Arc::strong_count(owner), 2);
                drop(opening);
                release.send(()).unwrap();
                // A single blocking worker makes this a completion barrier for
                // the scan, without waiting on host timing or a detached handle.
                tokio::task::spawn_blocking(|| ()).await.unwrap();
                assert_eq!(
                    checks.load(Ordering::SeqCst),
                    3,
                    "a dropped opener must stop the scan at its next check"
                );
                assert_eq!(Arc::strong_count(owner), 1);
                assert!(!inspected.load(Ordering::SeqCst));
                assert_eq!(
                    (
                        namespace(directory.path()),
                        namespace(directory.snapshot_path()),
                        root_selection(&directory)
                    ),
                    before
                );
            }
        }
    });
}

#[test]
fn native_format_preflight_cancels_queued_scans() {
    cancellation_runtime().block_on(async {
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let directory = FixedRawReadStoreFixture::new();
            large_generation(&directory, mode).await;
            for expected in [identity(1), identity(2)] {
                let backend = SqliteSessionBackend::open(directory.path().join(DATABASE)).unwrap();
                let owner = backend.native_owner.as_ref().unwrap();
                let checks = Arc::new(AtomicUsize::new(0));
                let checked = Arc::clone(&checks);
                owner.set_preflight_hook_for_test(Arc::new(move || {
                    checked.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }));
                let before = (
                    namespace(directory.path()),
                    namespace(directory.snapshot_path()),
                    root_selection(&directory),
                );
                let (entered, started) = tokio::sync::oneshot::channel();
                let (release, wait) = mpsc::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    entered.send(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(30)).unwrap();
                });
                started.await.unwrap();
                let inspected = AtomicBool::new(false);
                let mut opening =
                    Box::pin(backend.native_persistence_preflight(expected, |_| async {
                        inspected.store(true, Ordering::SeqCst);
                        Ok(())
                    }));
                assert!(std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(opening.as_mut().poll(cx))
                })
                .await
                .is_pending());
                assert_eq!(Arc::strong_count(owner), 2);
                drop(opening);
                let references_after_cancel = Arc::strong_count(owner);
                release.send(()).unwrap();
                blocker.await.unwrap();
                tokio::task::spawn_blocking(|| ()).await.unwrap();
                assert_eq!(
                    references_after_cancel, 1,
                    "cancelling queued work must release its owner before the worker becomes available"
                );
                assert_eq!(checks.load(Ordering::SeqCst), 0);
                assert_eq!(Arc::strong_count(owner), 1);
                assert!(!inspected.load(Ordering::SeqCst));
                assert_eq!(
                    (
                        namespace(directory.path()),
                        namespace(directory.snapshot_path()),
                        root_selection(&directory)
                    ),
                    before
                );
            }
        }
    });
}
