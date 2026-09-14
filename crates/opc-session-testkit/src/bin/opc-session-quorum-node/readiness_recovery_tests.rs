//! Recovery must prove the unavailable operation under the retained authority.

use super::*;
use opc_session_testkit::ConsensusTestCluster;

async fn readiness_recovery_case(clear_before_checkpoint: bool) {
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
    if clear_before_checkpoint {
        cluster.set_ordinary_read_barrier_online(follower, leader, true);
    }
    let recovery_started_at = tokio::time::Instant::now();
    let deadline = traffic_recovery_deadline(recovery_started_at, None);
    let mut retained = Some(lease);
    let result = reconcile_traffic_mutation_checkpoint(
        &protected,
        &key,
        &owner,
        &mut retained,
        seed,
        3,
        follower,
        initial_failure,
        recovery_started_at,
        deadline,
        &mut consecutive,
        &observation,
    )
    .await;
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
    protected.release(retained).await.unwrap();
    drop(protected);
    drop(store);
    cluster.shutdown().await;

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
    if clear_before_checkpoint {
        assert_eq!(result, Ok(()));
        assert_eq!(snapshot.interruptions, 1);
        assert_eq!(consecutive, 1);
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
    readiness_recovery_case(false).await;
}

#[tokio::test]
async fn readiness_checkpoint_accepts_cleared_read_barrier_with_original_authority() {
    readiness_recovery_case(true).await;
}
