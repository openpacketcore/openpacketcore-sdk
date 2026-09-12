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
                Err(StoreError::RestoreScanWorkBudgetExceeded)
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
