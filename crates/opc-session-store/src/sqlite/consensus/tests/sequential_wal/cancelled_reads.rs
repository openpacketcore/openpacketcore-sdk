//! A dropped read caller cannot cancel the owned cache-integrity cleanup.

use super::*;
use crate::sqlite::consensus::wal::integration::PrivateWalTest;
use crate::sqlite::SqliteStoreWorkKind;

struct GuardedReadFixture {
    backend: SqliteSessionBackend,
    wal: Arc<Wal>,
    source_path: std::path::PathBuf,
    pause: Arc<Pause>,
    armed: Arc<AtomicBool>,
    _core: SqliteConsensusCore,
    _directory: tempfile::TempDir,
}

impl GuardedReadFixture {
    fn new(runtime: &tokio::runtime::Runtime) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.sqlite");
        let mut backend = SqliteSessionBackend::open(&source_path).unwrap();
        let pause = Pause::new(Point::BeforeCutPublish);
        let armed = Arc::new(AtomicBool::new(false));
        let hook_armed = Arc::clone(&armed);
        let control = pause.control();
        let private = Arc::new(PrivateWalTest::with_snapshot_hook(
            directory.path().join("wal"),
            [0xB1; 32],
            Arc::new(move |point| {
                if hook_armed.load(Ordering::Acquire) {
                    (control.hook)(point)?;
                }
                Ok(())
            }),
        ));
        backend.private_wal_test = Some(Arc::clone(&private));
        let fixed_members = members(&[7, 8, 9]);
        let mut core = runtime
            .block_on(SqliteConsensusCore::initialize(
                &backend,
                directory.path().join("snapshots"),
                identity(),
                fixed_members.clone(),
                test_member_bindings(&fixed_members),
                ConsensusAuthorityProfile::FixedImmutable,
                FIXED_TEST_PLACEMENT_POLICY,
            ))
            .unwrap();
        // This fixture owns no production/background maintenance workload.
        if let Some(lane) = core.proactive_checkpoint_lane() {
            runtime.block_on(lane.shutdown());
        }
        if let Some(lane) = core.consensus_log_prune_lane() {
            runtime.block_on(lane.shutdown());
        }
        runtime.block_on(private.attach(&mut core)).unwrap();
        let wal = private.current().unwrap();
        let entries = vec![
            membership_entry_at(0, vec![fixed_members.clone()], fixed_members),
            acquire_entry(1, [0xB2; 16], "cancelled-read-owner"),
        ];
        wal.submit(append(&entries)).unwrap().wait().unwrap();
        wal.submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        {
            let conn = backend.conn.blocking_lock();
            wal.apply_committed(&conn, &core.caps, entries, ApplyControl::Normal)
                .unwrap();
            assert_eq!(wal.with_application_read(&conn, || 7).unwrap(), 7);
        }
        Self {
            backend,
            wal,
            source_path,
            pause,
            armed,
            _core: core,
            _directory: directory,
        }
    }

    fn pause_vote(&self) -> crate::sqlite::consensus::wal::Ticket {
        self.armed.store(true, Ordering::Release);
        let waiting = self
            .wal
            .submit(Operation::Vote(Vote::new_committed(3, node_id())))
            .unwrap();
        self.pause.entered();
        waiting
    }
}

#[test]
fn cancelled_private_cache_read_reconciles_before_releasing_its_owner() {
    for foreign_write in [false, true] {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let fixture = GuardedReadFixture::new(&runtime);
        let backend = &fixture.backend;
        let wal = &fixture.wal;
        let pause = &fixture.pause;
        let source_path = &fixture.source_path;
        let waiting = fixture.pause_vote();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_backend = backend.clone();
        runtime.block_on(async {
            let caller = tokio::spawn(async move {
                worker_backend
                    .run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
                        let count: i64 = conn
                            .query_row("SELECT COUNT(*) FROM session_records", [], |row| row.get(0))
                            .map_err(|_| {
                                crate::StoreError::BackendUnavailable("read unavailable".into())
                            })?;
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        Ok(count)
                    })
                    .await
            });
            tokio::time::timeout(Duration::from_secs(5), entered_rx)
                .await
                .unwrap()
                .unwrap();
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
            assert_eq!(
                backend.operation_workers.available_permits(),
                0,
                "a cancelled caller cannot release its live verification worker"
            );
            assert!(
                backend.conn.try_lock().is_err(),
                "the exact connection stays with the blocked read"
            );
            pause.release();
            tokio::time::sleep(Duration::from_millis(25)).await;
            assert!(
                matches!(waiting.try_recv(), Err(mpsc::TryRecvError::Empty)),
                "a waiting durability callback cannot overtake the held read guard"
            );
            if foreign_write {
                Connection::open(source_path)
                    .unwrap()
                    .execute_batch("CREATE TABLE foreign_cache_schema (value INTEGER)")
                    .unwrap();
            }
            release_tx.send(()).unwrap();
            let conn = tokio::time::timeout(Duration::from_secs(5), backend.conn.lock())
                .await
                .unwrap();
            assert!(conn.is_autocommit());
            drop(conn);
            tokio::time::timeout(Duration::from_secs(5), async {
                while backend.operation_workers.available_permits() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        });
        let readable = wal.vote().is_ok();
        if !foreign_write {
            assert!(
                readable,
                "cancelled read must complete cache validation before returning its owner"
            );
            assert_eq!(
                runtime
                    .block_on(
                        backend.run_store_sqlite_task(SqliteStoreWorkKind::Read, |conn| conn
                            .query_row("SELECT 9", [], |row| row.get::<_, i64>(0))
                            .map_err(|_| crate::StoreError::BackendUnavailable(
                                "read unavailable".into()
                            )),)
                    )
                    .unwrap(),
                9
            );
        }
        let acknowledged = waiting.wait().is_ok();
        let shutdown = wal.shutdown().is_ok();
        if foreign_write {
            assert!(
                !readable && !acknowledged && !shutdown,
                "cancellation cannot suppress a foreign-write fence or release a waiting callback"
            );
        } else {
            assert!(
                readable && acknowledged && shutdown,
                "cancelled read must complete cache validation before returning its owner"
            );
        }
    }
}

#[test]
fn queued_private_cache_read_cancellation_releases_admission_without_execution() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let fixture = GuardedReadFixture::new(&runtime);
    let executed = Arc::new(AtomicBool::new(false));
    let (released, connection_released) = runtime.block_on(async {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let saturator = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        started_rx.await.unwrap();
        let backend = fixture.backend.clone();
        let called = Arc::clone(&executed);
        let caller = tokio::spawn(async move {
            backend
                .run_store_sqlite_task(SqliteStoreWorkKind::Read, move |_| {
                    called.store(true, Ordering::Release);
                    Ok(())
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while fixture.backend.operation_workers.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let released = tokio::time::timeout(Duration::from_secs(1), async {
            while fixture.backend.operation_workers.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        let connection_released = fixture.backend.conn.try_lock().is_ok();
        release_tx.send(()).unwrap();
        saturator.await.unwrap();
        (released, connection_released)
    });
    assert!(
        released && connection_released,
        "queued cancellation must reclaim both owned resources"
    );
    assert!(
        !executed.load(Ordering::Acquire),
        "cancelled queued work must never execute"
    );
    assert!(runtime
        .block_on(
            fixture
                .backend
                .run_store_sqlite_task(SqliteStoreWorkKind::Read, |_| Ok(()))
        )
        .is_ok());
    fixture.wal.shutdown().unwrap();
}

#[test]
fn retained_cache_guard_deadline_fences_before_callback_without_sql_progress() {
    for expired_before_entry in [true, false] {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let fixture = GuardedReadFixture::new(&runtime);
        let waiting = fixture.pause_vote();
        let conn = fixture.backend.conn.blocking_lock();
        let deadline = if expired_before_entry {
            Instant::now()
        } else {
            Instant::now() + Duration::from_millis(100)
        };
        let entered = std::cell::Cell::new(false);
        let result = fixture
            .wal
            .with_retained_application_read(&conn, deadline, || {
                entered.set(true);
                fixture.pause.release();
                // No SQLite VM steps can enforce the deadline in this body.
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                );
                assert!(matches!(waiting.try_recv(), Err(mpsc::TryRecvError::Empty)));
                42
            });
        assert_eq!(entered.get(), !expired_before_entry);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        drop(conn);
        fixture.pause.release();
        assert!(
            waiting.wait().is_err(),
            "expiry must fence before the waiting callback"
        );
        assert!(fixture.wal.vote().is_err());
        assert!(fixture.wal.shutdown().is_err());
    }
}

#[test]
fn late_retained_read_handoff_rejects_the_result_without_fencing_validated_state() {
    use std::future::Future;
    use std::task::Poll;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = GuardedReadFixture::new(&runtime);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut read = Box::pin(fixture.backend.run_store_sqlite_task(
        SqliteStoreWorkKind::Read,
        move |_| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            Ok(42)
        },
    ));
    let started = Instant::now();
    runtime.block_on(std::future::poll_fn(|cx| {
        assert!(read.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    }));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    release_tx.send(()).unwrap();
    // The read body holds the WAL lock. Acquiring it here proves that clean
    // validation has finished while the async result remains deliberately unpolled.
    assert!(fixture.wal.vote().is_ok());
    assert!(started.elapsed() < crate::sqlite::SQLITE_OPERATION_MAX_WORK);
    std::thread::sleep(
        crate::sqlite::SQLITE_OPERATION_MAX_WORK.saturating_sub(started.elapsed())
            + Duration::from_millis(25),
    );
    assert!(
        runtime.block_on(read).is_err(),
        "a ready result cannot bypass its original deadline"
    );
    assert!(
        fixture.wal.vote().is_ok(),
        "late receiver scheduling cannot fence clean validated state"
    );
    assert!(runtime
        .block_on(
            fixture
                .backend
                .run_store_sqlite_task(SqliteStoreWorkKind::Read, |_| Ok(()))
        )
        .is_ok());
    fixture.wal.shutdown().unwrap();
}

#[test]
fn ordinary_and_acceptance_reads_remain_interruptible_and_reuse_clean_connections() {
    for acceptance_pool in [false, true] {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let backend = SqliteSessionBackend::open(directory.path().join("ordinary.sqlite")).unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (interrupted_tx, interrupted_rx) = tokio::sync::oneshot::channel();
        let worker_backend = backend.clone();
        runtime.block_on(async {
            let operation = move |conn: &Connection| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let result = conn.query_row(
                    "WITH RECURSIVE count(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM count WHERE x<100000000) SELECT sum(x) FROM count",
                    [], |row| row.get::<_, i64>(0));
                interrupted_tx.send(matches!(result.as_ref(),
                    Err(rusqlite::Error::SqliteFailure(error, _))
                        if error.code == rusqlite::ErrorCode::OperationInterrupted)).unwrap();
                result.map_err(|_| crate::StoreError::BackendUnavailable("read unavailable".into()))
            };
            let caller = tokio::spawn(async move {
                if acceptance_pool {
                    worker_backend.run_consensus_acceptance_read_task(operation).await
                } else {
                    worker_backend.run_store_sqlite_task(SqliteStoreWorkKind::Read, operation).await
                }
            });
            tokio::time::timeout(Duration::from_secs(1), entered_rx).await.unwrap().unwrap();
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
            release_tx.send(()).unwrap();
            assert!(tokio::time::timeout(Duration::from_secs(1), interrupted_rx)
                .await.unwrap().unwrap(), "ordinary caller cancellation must still interrupt SQL work");
            let (workers, expected) = if acceptance_pool {
                (&backend.consensus_acceptance_reader_pool.as_ref().unwrap().workers,
                 crate::sqlite::SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS)
            } else {
                (&backend.operation_workers, crate::sqlite::SQLITE_OPERATION_BLOCKING_WORKERS)
            };
            tokio::time::timeout(Duration::from_secs(1), async {
                while workers.available_permits() != expected {
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            // Cycle every acceptance lane, including the one just cancelled.
            for _ in 0..expected {
                let read = |conn: &Connection| conn.query_row("SELECT 17", [], |row| row.get::<_, i64>(0))
                    .map_err(|_| crate::StoreError::BackendUnavailable("read unavailable".into()));
                let result = if acceptance_pool {
                    backend.run_consensus_acceptance_read_task(read).await
                } else {
                    backend.run_store_sqlite_task(SqliteStoreWorkKind::Read, read).await
                };
                assert_eq!(result.unwrap(), 17);
            }
        });
    }
}
