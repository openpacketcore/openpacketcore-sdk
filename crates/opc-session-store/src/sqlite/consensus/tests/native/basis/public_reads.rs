use super::*;
use crate::restore::RestoreScanRequest;
use crate::sqlite::consensus::wal::integration::PrivateWalTest;

async fn backend(
    hook: Arc<dyn Fn(Point) -> io::Result<()> + Send + Sync>,
) -> (
    tempfile::TempDir,
    Arc<SqliteSessionBackend>,
    SqliteConsensusCore,
    Arc<Wal>,
) {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = SqliteSessionBackend::open(directory.path().join("backend.sqlite")).unwrap();
    let handle = Arc::new(PrivateWalTest::new_native_with_hook(
        directory.path().join("wal"),
        [0xB5; 32],
        hook,
    ));
    let mut core = SqliteConsensusCore::initialize_with_roster_attestation_root(
        &backend,
        directory.path().join("snapshots"),
        identity(),
        fixed_members(),
        test_member_bindings(&fixed_members()),
        ConsensusAuthorityProfile::FixedImmutable,
        FIXED_TEST_PLACEMENT_POLICY,
        None,
    )
    .await
    .unwrap();
    handle.attach(&mut core).await.unwrap();
    let wal = handle.current().unwrap();
    backend.private_wal_test = Some(handle);
    (directory, Arc::new(backend), core, wal)
}

#[tokio::test]
async fn sqlite_clock_frozen_setup_preserves_native_read_budget() {
    let (_directory, backend, core, wal) = backend(Arc::new(|_| Ok(()))).await;
    if let Some(lane) = core.proactive_checkpoint_lane() {
        lane.shutdown().await;
    }
    if let Some(lane) = core.consensus_log_prune_lane() {
        lane.shutdown().await;
    }
    tokio::time::pause();
    let frozen = tokio::time::Instant::now();
    std::thread::sleep(crate::sqlite::SQLITE_OPERATION_MAX_WORK + Duration::from_millis(20));
    assert_eq!(tokio::time::Instant::now(), frozen);
    let value = backend
        .native_read_task(|_, check| {
            check().map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
            Ok(7)
        })
        .await
        .expect("a fresh native read retains its frozen caller budget");
    assert_eq!(value, 7);
    assert_eq!(tokio::time::Instant::now(), frozen);
    tokio::time::resume();
    tokio::task::spawn_blocking(move || wal.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn sqlite_clock_advance_expires_native_read_without_polling_caller() {
    let (_directory, backend, core, wal) = backend(Arc::new(|_| Ok(()))).await;
    if let Some(lane) = core.proactive_checkpoint_lane() {
        lane.shutdown().await;
    }
    if let Some(lane) = core.consensus_log_prune_lane() {
        lane.shutdown().await;
    }
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    tokio::time::pause();
    let mut operation = std::pin::pin!(backend.native_read_task(move |_, check| {
        ready_tx.send(()).expect("native reader ready");
        release_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("native reader release");
        let result = check();
        result_tx
            .send(matches!(&result, Err(error) if error.kind() == io::ErrorKind::TimedOut))
            .expect("native deadline result");
        result.map_err(|error| StoreError::BackendUnavailable(error.to_string()))
    }));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(operation.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("native reader starts");
    tokio::time::advance(crate::sqlite::SQLITE_OPERATION_MAX_WORK).await;
    release_tx.send(()).expect("release expired native reader");
    let expired = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("native reader finishes");
    let result = operation.await;
    assert!(
        expired,
        "the native worker must check its caller's advanced clock"
    );
    assert!(result.is_err());
    tokio::time::resume();
    tokio::task::spawn_blocking(move || wal.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_public_dispatch_ignores_sql_lanes_and_rejects_retained_closed_owner() {
    let (_directory, backend, _core, wal) = backend(Arc::new(|_| Ok(()))).await;
    let request = fenced_transition_v2_request(0xB6, 1, "native-public-async");
    let entries = [formation(), activation(1, request.clone(), timestamp(1))];
    let writer = Arc::clone(&wal);
    tokio::task::spawn_blocking(move || {
        writer.submit(append(&entries)).unwrap().wait().unwrap();
        writer
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        writer.native_apply_committed(&entries).unwrap();
    })
    .await
    .unwrap();
    let _sql = backend.conn.lock().await;
    tokio::time::timeout(Duration::from_secs(1), async {
        assert!(backend
            .consensus_get_at(request.lease().key(), timestamp(2))
            .await
            .unwrap()
            .is_some());
        assert!(backend
            .consensus_observe_fenced_transition_at(request.lease().key(), timestamp(2))
            .await
            .is_ok());
        let page = backend
            .consensus_scan_restore_records_at(
                RestoreScanRequest::all(2),
                timestamp(2),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(page.loaded_count, 1);
        assert_eq!(
            backend
                .consensus_get_replication_log(0, 2)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            backend.consensus_max_replication_sequence().await.unwrap(),
            1
        );
        assert!(backend
            .consensus_fenced_transition_v2_history_is_activated(identity())
            .await
            .unwrap());
        assert!(backend.fixed_quorum_authority_is_exact_now(
            identity(),
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            FIXED_TEST_PLACEMENT_POLICY.unwrap()
        ));
    })
    .await
    .unwrap();
    let joined = Arc::clone(&wal);
    tokio::task::spawn_blocking(move || joined.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(
        wal.with_native_read(|state| Ok(state.applied()))
            .unwrap()
            .is_some(),
        "joined internal inspection remains available"
    );
    assert!(backend
        .consensus_get_at(request.lease().key(), timestamp(2))
        .await
        .is_err());
    assert!(backend.consensus_max_replication_sequence().await.is_err());
    assert!(backend
        .consensus_fenced_transition_activation_matches_scope(
            identity(),
            identity(),
            fixed_members()
        )
        .await
        .is_err());
    assert!(backend
        .consensus_protected_roster_profile_activation_matches_scope(
            identity(),
            identity(),
            fixed_members()
        )
        .await
        .is_err());
    assert!(backend
        .consensus_fenced_transition_v2_history_is_activated(identity())
        .await
        .is_err());
    assert!(backend
        .consensus_protected_roster_v2_history_is_activated(identity())
        .await
        .is_err());
    assert!(backend
        .consensus_fenced_transition_v2_history_state(identity(), identity())
        .await
        .is_err());
    assert!(!backend.fixed_quorum_authority_is_exact_now(
        identity(),
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY.unwrap()
    ));
    assert!(wal.native_fixed_scope_snapshot(identity()).is_err());
    assert!(backend
        .consensus_fenced_transition_v2_status(identity(), identity(), &request)
        .await
        .is_err());
}

#[tokio::test]
async fn native_consensus_restore_late_delivery_preserves_terminal_cursor_error() {
    struct CompletionWake(std::sync::mpsc::Sender<()>);
    impl futures_util::task::ArcWake for CompletionWake {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            let _ = arc_self.0.send(());
        }
    }

    let (_directory, backend, core, wal) = backend(Arc::new(|_| Ok(()))).await;
    let writer = Arc::clone(&wal);
    tokio::task::spawn_blocking(move || {
        let entries = [formation()];
        writer.submit(append(&entries)).unwrap().wait().unwrap();
        writer
            .submit(Operation::Committed(Some(log_id(0))))
            .unwrap()
            .wait()
            .unwrap();
        writer.native_apply_committed(&entries).unwrap();
    })
    .await
    .unwrap();
    if let Some(lane) = core.proactive_checkpoint_lane() {
        lane.shutdown().await;
    }
    if let Some(lane) = core.consensus_log_prune_lane() {
        lane.shutdown().await;
    }
    let request = RestoreScanRequest {
        cursor: Some(crate::restore::RestoreScanCursor::from_offset(1)),
        ..RestoreScanRequest::all(1)
    };
    assert_eq!(
        backend
            .consensus_scan_restore_records_at(
                request.clone(),
                timestamp(1),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await,
        Err(StoreError::RestoreScanCursorStale)
    );
    tokio::time::pause();
    let budget = Duration::from_secs(1);
    let deadline = tokio::time::Instant::now() + budget;
    let mut operation =
        Box::pin(backend.consensus_scan_restore_records_at(request, timestamp(1), deadline));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let waker = futures_util::task::waker(Arc::new(CompletionWake(ready_tx)));
    let mut context = std::task::Context::from_waker(&waker);
    assert!(std::future::Future::poll(operation.as_mut(), &mut context).is_pending());
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the completed native read wakes its caller");
    assert_eq!(backend.restore_scan_workers.available_permits(), 1);
    tokio::time::advance(budget).await;
    assert_eq!(
        operation.await,
        Err(StoreError::RestoreScanCursorStale),
        "a terminal scan result stays terminal when delivery crosses the deadline"
    );
    tokio::time::resume();
    tokio::task::spawn_blocking(move || wal.shutdown().unwrap())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_consensus_restore_deadline_while_waiting_for_worker_is_retryable() {
    let (_directory, backend, _core, wal) = backend(Arc::new(|_| Ok(()))).await;
    let held_permit = Arc::clone(&backend.restore_scan_workers)
        .acquire_owned()
        .await
        .unwrap();
    let result = backend
        .consensus_scan_restore_records_at(
            RestoreScanRequest::all(1),
            timestamp(1),
            tokio::time::Instant::now() + Duration::from_millis(25),
        )
        .await;
    assert_eq!(
        result,
        Err(StoreError::BackendUnavailable(
            "native session state is unavailable".into()
        ))
    );
    drop(held_permit);
    assert!(backend.native_read_task(|_, _| Ok(())).await.is_ok());
    tokio::task::spawn_blocking(move || wal.shutdown().unwrap())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_public_active_cancellation_and_restore_deadline_retire_without_fencing() {
    for deadline in [false, true] {
        let gate = Gate::new(Point::BeforeNativePublicRead, 1);
        let hook = Arc::clone(&gate);
        let (_directory, backend, _core, wal) =
            backend(Arc::new(move |point| hook.hook(point))).await;
        let workers = if deadline {
            Arc::clone(&backend.restore_scan_workers)
        } else {
            Arc::clone(&backend.operation_workers)
        };
        let available = workers.available_permits();
        let worker_backend = Arc::clone(&backend);
        let task = tokio::spawn(async move {
            if deadline {
                worker_backend
                    .consensus_scan_restore_records_at(
                        RestoreScanRequest::all(1),
                        timestamp(1),
                        tokio::time::Instant::now() + Duration::from_millis(100),
                    )
                    .await
                    .map(|_| ())
            } else {
                worker_backend.native_read_task(|_, _| Ok(())).await
            }
        });
        let entered = Arc::clone(&gate);
        tokio::task::spawn_blocking(move || entered.entered())
            .await
            .unwrap();
        assert_eq!(workers.available_permits(), available - 1);
        assert!(
            wal.native_public_scalar_read(|_| Ok(())).is_ok(),
            "detached work does not hold State"
        );
        if deadline {
            assert_eq!(
                task.await.unwrap(),
                Err(StoreError::BackendUnavailable(
                    "native session state is unavailable".into()
                ))
            );
        } else {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert_eq!(
            workers.available_permits(),
            available - 1,
            "active worker keeps its reservation until retirement"
        );
        gate.release();
        let retained_workers = Arc::clone(&workers);
        tokio::task::spawn_blocking(move || {
            until(|| retained_workers.available_permits() == available)
        })
        .await
        .unwrap();
        assert!(backend.native_read_task(|_, _| Ok(())).await.is_ok());
        let joined = Arc::clone(&wal);
        tokio::task::spawn_blocking(move || {
            joined.submit(Operation::Barrier).unwrap().wait().unwrap();
            joined.shutdown().unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_public_cancelled_admission_never_spawns_or_consumes_an_extra_worker() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hook_hits = Arc::clone(&hits);
    let (_directory, backend, _core, wal) = backend(Arc::new(move |point| {
        if point == Point::BeforeNativePublicRead {
            hook_hits.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }))
    .await;
    let available = backend.operation_workers.available_permits();
    let held = Arc::clone(&backend.operation_workers)
        .acquire_many_owned(available.try_into().unwrap())
        .await
        .unwrap();
    let mut waiting = Box::pin(backend.native_read_task(|_, _| Ok(())));
    let pending = std::future::poll_fn(|context| {
        std::task::Poll::Ready(std::future::Future::poll(waiting.as_mut(), context).is_pending())
    })
    .await;
    assert!(
        pending,
        "the same future has entered exhausted semaphore admission"
    );
    drop(waiting);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    drop(held);
    assert_eq!(backend.operation_workers.available_permits(), available);
    backend.native_read_task(|_, _| Ok(())).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    tokio::task::spawn_blocking(move || wal.shutdown())
        .await
        .unwrap()
        .unwrap();
}
