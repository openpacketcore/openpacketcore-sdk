//! Real public quorum work while ordinary background writers and snapshot
//! publication are held. The hook changes I/O timing, never mode selection.

use super::*;
use crate::consensus::snapshot::SnapshotArtifactGate;

struct ReleaseWriters(Vec<Arc<SnapshotArtifactGate>>);

impl Drop for ReleaseWriters {
    fn drop(&mut self) {
        for gate in &self.0 {
            gate.release();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_public_v2_and_snapshot_work_continue_during_writer_stall() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let gates = (0..3)
        .map(|_| Arc::new(SnapshotArtifactGate::new()))
        .collect::<Vec<_>>();
    let release = ReleaseWriters(gates.clone());
    let result = AssertUnwindSafe(async {
        for (index, gate) in gates.iter().enumerate() {
            let gate = Arc::clone(gate);
            let hook: GenerationHook = Arc::new(move || {
                gate.block_if_armed_blocking();
                Ok(())
            });
            fleet
                .open_with_hook(index, SessionPersistenceMode::Async, Some(hook))
                .await
                .unwrap();
        }
        fleet.form().await;
        let leader = fleet.leader();
        let store = fleet.store(leader).clone();
        store.activate_fenced_transition_capability().await.unwrap();
        let provider = provider();
        let mut requests = Vec::new();
        for index in 1..=139 {
            requests.push(create_request(&store, index, &provider).await);
        }
        let first = create(&store, &requests[0]).await;
        for voter in fleet.stores.iter().flatten() {
            assert_recorded(voter, &requests[0], &first).await;
            voter.drain_async_persistence().await.unwrap();
        }
        let selected = (0..3)
            .map(|index| fleet.selector(index))
            .collect::<Vec<_>>();
        let completed = fleet
            .stores
            .iter()
            .flatten()
            .map(|voter| {
                voter
                    .persistence_health()
                    .asynchronous
                    .unwrap()
                    .completed_generation
            })
            .collect::<Vec<_>>();
        for gate in &gates {
            gate.arm();
        }
        let mut retained = vec![(requests[0].clone(), first)];
        retained.push((requests[1].clone(), create(&store, &requests[1]).await));
        tokio::time::timeout(
            Duration::from_secs(3),
            join_all(gates.iter().map(|gate| gate.wait_started())),
        )
        .await
        .expect("all ordinary native generation writers reached the I/O hold");
        let snapshots = fleet
            .stores
            .iter()
            .flatten()
            .map(|voter| voter.status().completed_snapshot_count)
            .collect::<Vec<_>>();
        for voter in fleet.stores.iter().flatten() {
            voter.inner.raft.trigger().snapshot().await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if fleet.stores.iter().flatten().all(|voter| {
                    voter
                        .inner
                        .private_wal
                        .as_ref()
                        .unwrap()
                        .native_snapshot_publication_pending_for_test()
                        .unwrap()
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("actual verified snapshots await the held persistence publication");
        let drain = {
            let store = store.clone();
            tokio::spawn(async move { store.drain_async_persistence().await })
        };
        // Complete seventeen real eight-item public batches while every
        // ordinary disk writer remains blocked in its captured generation.
        for batch in requests[2..138].chunks(8) {
            let started = tokio::time::Instant::now();
            let outcomes = store
                .fenced_transition_v2_batch(batch.to_vec())
                .await
                .unwrap();
            assert!(started.elapsed() < OPERATION_BOUND);
            assert_eq!(outcomes.len(), batch.len());
            for (request, outcome) in batch.iter().zip(outcomes) {
                let outcome = outcome.unwrap();
                assert!(outcome.matches_v2_request(request));
                assert_eq!(outcome.mutation(), FencedTransitionMutationResult::Created);
                assert_eq!(outcome.committed_generation(), Generation::new(1));
                retained.push((request.clone(), outcome));
            }
        }
        assert_eq!(
            drain.await.unwrap(),
            Err(SessionPersistenceDrainError::DeadlineExceeded)
        );
        let started = tokio::time::Instant::now();
        retained.push((requests[138].clone(), create(&store, &requests[138]).await));
        assert!(started.elapsed() < OPERATION_BOUND);
        for (index, voter) in fleet.stores.iter().flatten().enumerate() {
            let health = voter.persistence_health();
            let progress = health.asynchronous.unwrap();
            assert!(health.engine_running);
            assert_eq!(health.storage_state, SessionStorageState::Running);
            assert!(health.storage_failure.is_none() && progress.background_failure.is_none());
            assert_eq!(progress.completed_generation, completed[index]);
            assert!(progress.resident_generation > progress.completed_generation);
            assert!(progress.captured_generation.is_some());
            assert!(progress.lag_millis >= OPERATION_BOUND.as_millis() as u64);
            assert_eq!(fleet.selector(index), selected[index]);
            assert_eq!(voter.status().completed_snapshot_count, snapshots[index]);
            for (request, outcome) in &retained {
                assert_recorded(voter, request, outcome).await;
            }
        }
        for gate in &gates {
            gate.release();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if fleet
                    .stores
                    .iter()
                    .flatten()
                    .enumerate()
                    .all(|(index, voter)| {
                        voter.status().completed_snapshot_count > snapshots[index]
                    })
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all verified snapshot publications complete after writer release");
        for voter in fleet.stores.iter().flatten() {
            let health = voter.drain_async_persistence().await.unwrap();
            assert!(health.storage_failure.is_none());
            assert!(voter
                .probe_fixed_quorum_readiness()
                .await
                .traffic_authority()
                .is_granted());
            for (request, outcome) in &retained {
                assert_recorded(voter, request, outcome).await;
            }
        }
    })
    .catch_unwind()
    .await;
    drop(release);
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_public_background_error_preserves_results_and_reports_failed_drain() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let faults = (0..3)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect::<Vec<_>>();
    let result = AssertUnwindSafe(async {
        for (index, fault) in faults.iter().enumerate() {
            let fault = Arc::clone(fault);
            let hook: GenerationHook = Arc::new(move || {
                if fault.load(Ordering::Acquire) {
                    Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
                } else {
                    Ok(())
                }
            });
            fleet
                .open_with_hook(index, SessionPersistenceMode::Async, Some(hook))
                .await
                .unwrap();
        }
        fleet.form().await;
        let leader = fleet.leader();
        let follower = (leader + 1) % 3;
        let provider = provider();
        let first = create_request(fleet.store(leader), 1, &provider).await;
        let first_outcome = create(fleet.store(leader), &first).await;
        fleet
            .store(leader)
            .activate_fenced_transition_capability()
            .await
            .unwrap();
        // Prepare all public request authority before selecting the unchanged
        // completed prefix whose next background write will actually fail.
        let second = create_request(fleet.store(leader), 2, &provider).await;
        let third = create_request(fleet.store(leader), 3, &provider).await;
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &first_outcome).await;
        }
        for store in fleet.stores.iter().flatten() {
            store.drain_async_persistence().await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if fleet.stores.iter().flatten().all(|store| {
                    let progress = store.persistence_health().asynchronous.unwrap();
                    progress.captured_generation.is_none()
                        && progress.completed_generation == progress.resident_generation
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ordinary writers have completed all prior work");
        let selected = fleet.selector(follower);
        let completed = fleet
            .store(follower)
            .persistence_health()
            .asynchronous
            .unwrap()
            .completed_generation;
        faults[follower].store(true, Ordering::Release);
        let second_outcome = create(fleet.store(leader), &second).await;
        let failure = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(failure) = fleet
                    .store(follower)
                    .persistence_health()
                    .asynchronous
                    .unwrap()
                    .background_failure
                {
                    break failure;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the ordinary background writer reports its real ENOSPC");
        assert_eq!(
            failure.stage,
            crate::SessionStorageFailureStage::Persistence
        );
        assert_eq!(failure.kind, crate::SessionStorageFailureKind::StorageFull);
        assert_eq!(failure.os_error, Some(libc::ENOSPC));
        let started = tokio::time::Instant::now();
        let third_outcome = create(fleet.store(leader), &third).await;
        assert!(started.elapsed() < OPERATION_BOUND);
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &first_outcome).await;
            assert_recorded(store, &second, &second_outcome).await;
            assert_recorded(store, &third, &third_outcome).await;
        }
        let health = fleet.store(follower).persistence_health();
        let progress = health.asynchronous.unwrap();
        assert!(health.engine_running);
        assert_eq!(health.storage_state, SessionStorageState::Running);
        assert!(health.storage_failure.is_none());
        assert_eq!(progress.background_failure, Some(failure));
        assert!(progress.saturated);
        assert_eq!(progress.completed_generation, completed);
        assert!(progress.resident_generation > completed);
        assert!(progress.captured_generation.is_none());
        assert_eq!(fleet.selector(follower), selected);
        assert_eq!(
            fleet.store(follower).drain_async_persistence().await,
            Err(SessionPersistenceDrainError::Failed(failure))
        );
        assert!(fleet
            .store(follower)
            .probe_fixed_quorum_readiness()
            .await
            .traffic_authority()
            .is_granted());
        let leader_vote = fleet.store(leader).inner.raft.metrics().borrow().vote;
        let remembered = fleet
            .store(leader)
            .inner
            .raft
            .metrics()
            .borrow()
            .replication
            .as_ref()
            .unwrap()[&fleet.peers[follower].node]
            .unwrap();
        assert!(
            fleet.close_result(follower).await.is_err(),
            "shutdown reports the failed persistence drain after joining the owner"
        );
        assert_eq!(fleet.selector(follower), selected);
        fleet
            .open(follower, SessionPersistenceMode::Async)
            .await
            .unwrap();
        assert_eq!(
            fleet.store(follower).persistence_health().recovery,
            Some(SessionAsyncRecoveryState::AwaitingLiveQuorum)
        );
        assert!(!fleet.store(follower).status().admitted);
        assert!(
            fleet
                .store(follower)
                .inner
                .raft
                .metrics()
                .borrow()
                .last_log_index
                < Some(remembered.index),
            "the restarted follower lost a previously acknowledged tail"
        );
        let started_repair = tokio::time::Instant::now();
        let initialized = fleet.store(follower).initialize_cluster().await;
        for (role, store) in [("leader", fleet.store(leader)), ("cold", fleet.store(follower))] {
            let metrics = store.inner.raft.metrics();
            let metrics = metrics.borrow();
            eprintln!("async_failed_writer_rejoin role={role} elapsed_us={} result={initialized:?} health={:?} vote={:?} log={:?} applied={:?} snapshot={:?}", started_repair.elapsed().as_micros(), store.persistence_health(), metrics.vote, metrics.last_log_index, metrics.last_applied, metrics.snapshot);
        }
        initialized.unwrap();
        assert_eq!(
            fleet.store(leader).inner.raft.metrics().borrow().vote,
            leader_vote
        );
        assert_eq!(
            fleet.leader(),
            leader,
            "repair must not require another election"
        );
        assert!(fleet
            .store(follower)
            .inner
            .raft
            .metrics()
            .borrow()
            .snapshot
            .is_some_and(|last| last.index >= remembered.index));
        assert_recorded(fleet.store(follower), &first, &first_outcome).await;
        assert_recorded(fleet.store(follower), &second, &second_outcome).await;
        assert_recorded(fleet.store(follower), &third, &third_outcome).await;
        let recovered = fleet
            .store(follower)
            .drain_async_persistence()
            .await
            .unwrap();
        assert!(recovered.asynchronous.unwrap().background_failure.is_none());
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
