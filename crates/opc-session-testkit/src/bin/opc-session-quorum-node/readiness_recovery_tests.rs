//! Recovery must prove the unavailable operation under the retained authority.

use super::*;
use opc_session_testkit::ConsensusTestCluster;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClearBarrier {
    BeforeCheckpoint,
    AfterFailedProof,
    Never,
}

async fn readiness_recovery_case(clear: ClearBarrier) {
    let cluster = ConsensusTestCluster::start(3).await;
    let leader_id = cluster.store(0).status().leader_id.expect("elected leader");
    let leader = (0..3)
        .find(|index| cluster.store(*index).status().node_id == leader_id)
        .expect("leader belongs to the actual fixture");
    let follower = (leader + 1) % 3;
    let store = Arc::new(cluster.store(follower));
    assert_eq!(store.status().leader_id, Some(leader_id));
    assert_ne!(store.status().node_id, leader_id);

    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new(QUALIFICATION_KEY_ID).unwrap(),
            KeyPurpose::Session,
            TenantId::new(QUALIFICATION_TENANT).unwrap(),
            Zeroizing::new(QUALIFICATION_KEY_BYTES),
        )
        .unwrap();
    let protected = EncryptingSessionBackend::new(
        Arc::clone(&store),
        provider,
        "readiness-recovery-fixture".to_owned(),
    );
    let key = qualification_traffic_key(follower).unwrap();
    let owner = OwnerId::new(format!("rotation-traffic-owner-{follower}")).unwrap();
    // The complete checkpoint also has an acquisition lane. Read-only
    // recovery must retain this unused lane without changing its journal.
    let acquisition_directory = tempfile::tempdir().unwrap();
    let acquisition_database = acquisition_directory.path().join("replica.sqlite");
    let journal = traffic_acquire::Journal::open(
        &acquisition_database,
        traffic_acquire::Binding::new(
            store.consumer_scope().unwrap(),
            follower,
            key.clone(),
            owner.clone(),
            QUALIFICATION_TRAFFIC_TTL,
        ),
        QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS,
    )
    .unwrap();
    let journal_path = acquisition_database.with_extension("traffic-acquire-v1.json");
    let journal_before = fs::read(&journal_path).unwrap();
    let mut acquirer = traffic_acquire::Acquirer::from_store(journal, &store)
        .await
        .unwrap();
    let lease = protected
        .acquire(&key, owner.clone(), QUALIFICATION_TRAFFIC_TTL)
        .await
        .expect("acquire the one retained authority");
    let fence = lease.fence().get();
    let seed = 37;
    let expected = expected_traffic_record(&key, seed, 3, follower, 1, fence).unwrap();
    assert!(matches!(
        protected
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: expected.clone(),
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    ));

    cluster.set_ordinary_read_barrier_online(follower, leader, false);
    let readiness = store.probe_durable_readiness().await;
    assert!(
        !readiness.is_ready(),
        "the actual read-index path must fail"
    );
    let rejected_before = cluster.rejected_ordinary_read_barriers(follower, leader);
    assert!(
        rejected_before > 0,
        "the intended RPC fault must be consumed"
    );
    let exact = protected.get(&key).await.unwrap().unwrap();
    assert!(traffic_record_is_exact(&expected, &exact));
    assert_eq!(store.status().leader_id, Some(leader_id));
    assert_ne!(store.status().node_id, leader_id);

    let observation = QualificationTrafficObservation::new(seed, 3);
    observation.last_generation.store(1, Ordering::Release);
    observation
        .last_record_fence
        .store(fence, Ordering::Release);
    let mut consecutive = 0;
    assert!(observation.record_availability_interruption(&mut consecutive));
    let initial_failure = QualificationTrafficFailure::backend_unavailable(
        QualificationTrafficFailureCode::ReadinessUnavailable,
        QualificationTrafficFailureStage::ReadinessProbe,
    );
    if clear == ClearBarrier::BeforeCheckpoint {
        cluster.set_ordinary_read_barrier_online(follower, leader, true);
    }
    let recovery_started_at = tokio::time::Instant::now();
    let deadline = traffic_recovery_deadline(recovery_started_at, None);
    let mut retained = Some(lease);
    let mut observed_failed_proof = false;
    let result = {
        let checkpoint = reconcile_traffic_mutation_checkpoint(
            &protected,
            &store,
            &key,
            &owner,
            &mut retained,
            &mut acquirer,
            seed,
            3,
            follower,
            initial_failure,
            recovery_started_at,
            deadline,
            &mut consecutive,
            &observation,
        );
        tokio::pin!(checkpoint);
        if clear == ClearBarrier::AfterFailedProof {
            tokio::select! {
                result = &mut checkpoint => result,
                () = async {
                    while observation.availability_snapshot().interruptions == 1 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                } => {
                    observed_failed_proof = true;
                    cluster.set_ordinary_read_barrier_online(follower, leader, true);
                    checkpoint.await
                }
            }
        } else {
            checkpoint.await
        }
    };
    let snapshot = observation.availability_snapshot();
    let rejected_after = cluster.rejected_ordinary_read_barriers(follower, leader);
    let same_leader =
        store.status().leader_id == Some(leader_id) && store.status().node_id != leader_id;
    let retained = retained.expect("read-only recovery retains the original guard");
    let same_authority = lease_authority_is_preserved(
        &key,
        &owner,
        fence,
        retained.key(),
        retained.owner(),
        retained.fence().get(),
    );

    // Restore the real path and drain the fixture before evaluating the RED.
    cluster.set_ordinary_read_barrier_online(follower, leader, true);
    let cleared_readiness = store.probe_durable_readiness().await.is_ready();
    let final_record = protected.get(&key).await.unwrap().unwrap();
    let journal_unchanged = fs::read(&journal_path).unwrap() == journal_before;
    protected.release(retained).await.unwrap();
    drop(acquirer);
    drop(protected);
    drop(store);
    cluster.shutdown().await;

    assert!(
        journal_unchanged,
        "read-only recovery must not acquire authority"
    );

    assert!(
        same_leader,
        "the same real follower must exercise both paths"
    );
    assert!(
        cleared_readiness,
        "clearing the exact fault restores readiness"
    );
    assert!(same_authority);
    assert!(traffic_record_is_exact(&expected, &final_record));
    assert_eq!(snapshot.interruption_episodes, 1);
    assert_eq!(snapshot.recoveries, 0);
    if clear == ClearBarrier::BeforeCheckpoint {
        assert_eq!(result, Ok(()));
        assert_eq!(snapshot.interruptions, 1);
        assert_eq!(consecutive, 1);
    } else if clear == ClearBarrier::AfterFailedProof {
        assert!(
            observed_failed_proof,
            "the real failed reproof must be counted before recovery"
        );
        assert_eq!(result, Ok(()));
        assert!(rejected_after > rejected_before);
        assert!(snapshot.interruptions >= 2);
        assert_eq!(snapshot.interruptions, consecutive);
        assert_eq!(snapshot.max_consecutive_interruptions, consecutive);
    } else {
        assert!(
            result.is_err(),
            "an exact get must not certify recovery while ReadBarrier remains unavailable"
        );
        assert!(rejected_after > rejected_before);
        assert!(snapshot.interruptions > 1);
        assert_eq!(snapshot.interruptions, consecutive);
    }
}

#[tokio::test]
async fn readiness_checkpoint_rejects_still_unavailable_read_barrier_after_exact_get() {
    readiness_recovery_case(ClearBarrier::Never).await;
}

#[tokio::test]
async fn readiness_checkpoint_accepts_cleared_read_barrier_with_original_authority() {
    readiness_recovery_case(ClearBarrier::BeforeCheckpoint).await;
}

#[tokio::test]
async fn readiness_checkpoint_recovers_after_counting_a_real_failed_reproof() {
    readiness_recovery_case(ClearBarrier::AfterFailedProof).await;
}

#[tokio::test(start_paused = true)]
async fn readiness_reproof_uses_the_remaining_original_episode_deadline() {
    let started = tokio::time::Instant::now();
    let deadline = traffic_recovery_deadline(started, None);
    tokio::time::advance(Duration::from_secs(25)).await;
    let entered = Arc::new(Notify::new());
    let entered_probe = Arc::clone(&entered);
    let task = tokio::spawn(async move {
        let observation = QualificationTrafficObservation::new(37, 3);
        let mut consecutive = 0;
        assert!(observation.record_availability_interruption(&mut consecutive));
        let result = prove_traffic_readiness_recovery(
            || async {
                entered_probe.notify_one();
                std::future::pending::<bool>().await
            },
            started,
            deadline,
            &mut consecutive,
            &observation,
        )
        .await;
        (result, observation.availability_snapshot(), consecutive)
    });
    entered.notified().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let finished_at_deadline = task.is_finished();
    if !finished_at_deadline {
        task.abort();
    }
    let joined = task.await;
    assert!(
        finished_at_deadline,
        "a pending readiness proof must end at the original episode deadline"
    );
    let (result, snapshot, consecutive) = joined.unwrap();
    assert!(result.is_err());
    assert_eq!(tokio::time::Instant::now(), deadline);
    assert_eq!(snapshot.interruption_episodes, 1);
    assert_eq!(snapshot.interruptions, 2);
    assert_eq!(snapshot.recoveries, 0);
    assert_eq!(consecutive, 2);
}

#[tokio::test(start_paused = true)]
async fn readiness_reproof_does_not_admit_work_at_an_expired_deadline() {
    let started = tokio::time::Instant::now();
    let observation = QualificationTrafficObservation::new(37, 3);
    let mut consecutive = 0;
    assert!(observation.record_availability_interruption(&mut consecutive));
    let mut calls = 0;
    let result = prove_traffic_readiness_recovery(
        || {
            calls += 1;
            std::future::ready(true)
        },
        started,
        started,
        &mut consecutive,
        &observation,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls, 0);
    assert_eq!(consecutive, 1);
    assert_eq!(observation.availability_snapshot().interruptions, 1);
}

#[tokio::test(start_paused = true)]
async fn readiness_reproof_counts_the_completed_outcome_and_original_retry_delay() {
    let started = tokio::time::Instant::now();
    let deadline = traffic_recovery_deadline(started, None);
    let observation = QualificationTrafficObservation::new(37, 3);
    let mut consecutive = 0;
    assert!(observation.record_availability_interruption(&mut consecutive));
    let mut calls = 0;
    let result = prove_traffic_readiness_recovery(
        || {
            calls += 1;
            std::future::ready(calls == 2)
        },
        started,
        deadline,
        &mut consecutive,
        &observation,
    )
    .await;
    assert_eq!(result, Ok(()));
    assert_eq!(calls, 2);
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_millis(QUALIFICATION_TRAFFIC_AVAILABILITY_RETRY_MILLIS)
    );
    let snapshot = observation.availability_snapshot();
    assert_eq!(snapshot.interruption_episodes, 1);
    assert_eq!(snapshot.interruptions, 2);
    assert_eq!(snapshot.recoveries, 0);
    assert_eq!(snapshot.max_consecutive_interruptions, 2);
    assert_eq!(consecutive, 2);
}

#[tokio::test(start_paused = true)]
async fn readiness_reproof_rejects_a_ready_result_at_the_original_deadline() {
    let started = tokio::time::Instant::now();
    let deadline = traffic_recovery_deadline(started, None);
    let observation = QualificationTrafficObservation::new(37, 3);
    let mut consecutive = 0;
    assert!(observation.record_availability_interruption(&mut consecutive));
    let result = prove_traffic_readiness_recovery(
        || async {
            tokio::time::sleep_until(deadline).await;
            true
        },
        started,
        deadline,
        &mut consecutive,
        &observation,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(tokio::time::Instant::now(), deadline);
    assert_eq!(consecutive, 1);
    assert_eq!(observation.availability_snapshot().recoveries, 0);
}
