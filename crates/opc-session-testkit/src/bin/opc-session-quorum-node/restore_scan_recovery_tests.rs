//! An exact get cannot certify availability of a separately failing scan.

use super::*;
use opc_session_store::test_support::{
    consensus_restore_scan_rejections_for_test, set_consensus_restore_scan_unavailable_for_test,
};
use opc_session_testkit::ConsensusTestCluster;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClearScan {
    BeforeCheckpoint,
    AfterFailedProof,
    Never,
}

async fn restore_scan_recovery_case(clear: ClearScan) {
    let cluster = ConsensusTestCluster::start(3).await;
    let store = Arc::new(cluster.store(0));
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
        "restore-scan-recovery-fixture".to_owned(),
    );
    let key = qualification_traffic_key(0).unwrap();
    let owner = OwnerId::new("rotation-traffic-owner-0").unwrap();
    let lease = protected
        .acquire(&key, owner.clone(), QUALIFICATION_TRAFFIC_TTL)
        .await
        .unwrap();
    let fence = lease.fence().get();
    let seed = 37;
    let expected = expected_traffic_record(&key, seed, 3, 0, 1, fence).unwrap();
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

    set_consensus_restore_scan_unavailable_for_test(&store, true);
    let error = protected
        .scan_restore_records(RestoreScanRequest::all(QUALIFICATION_TRAFFIC_RESTORE_LIMIT))
        .await
        .expect_err("the real scan dispatch must reach the armed fault");
    let initial_failure = QualificationTrafficFailure::store(
        QualificationTrafficFailureCode::RestoreScanRejected,
        QualificationTrafficFailureStage::RestoreScan,
        &error,
    );
    assert!(traffic_failure_is_recoverable(initial_failure));
    assert_eq!(consensus_restore_scan_rejections_for_test(&store), 1);
    let exact = protected.get(&key).await.unwrap().unwrap();
    assert!(traffic_record_is_exact(&expected, &exact));

    let observation = QualificationTrafficObservation::new(seed, 3);
    observation.last_generation.store(1, Ordering::Release);
    observation
        .last_record_fence
        .store(fence, Ordering::Release);
    let mut consecutive = 0;
    assert!(observation.record_availability_interruption(&mut consecutive));
    if clear == ClearScan::BeforeCheckpoint {
        set_consensus_restore_scan_unavailable_for_test(&store, false);
    }
    let started = tokio::time::Instant::now();
    let deadline = traffic_recovery_deadline(started, None);
    let mut retained = Some(lease);
    let mut observed_failed_proof = false;
    let result = {
        let checkpoint = reconcile_traffic_mutation_checkpoint(
            &protected,
            &store,
            &key,
            &owner,
            &mut retained,
            seed,
            3,
            0,
            initial_failure,
            started,
            deadline,
            &mut consecutive,
            &observation,
        );
        tokio::pin!(checkpoint);
        if clear == ClearScan::AfterFailedProof {
            tokio::select! {
                result = &mut checkpoint => result,
                () = async {
                    while observation.availability_snapshot().interruptions == 1 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                } => {
                    observed_failed_proof = true;
                    set_consensus_restore_scan_unavailable_for_test(&store, false);
                    checkpoint.await
                }
            }
        } else {
            checkpoint.await
        }
    };
    let availability = observation.availability_snapshot();
    let rejected = consensus_restore_scan_rejections_for_test(&store);
    let retained = retained.expect("read-only recovery retains the original guard");
    let same_authority = lease_authority_is_preserved(
        &key,
        &owner,
        fence,
        retained.key(),
        retained.owner(),
        retained.fence().get(),
    );

    set_consensus_restore_scan_unavailable_for_test(&store, false);
    let cleared_page = protected
        .scan_restore_records(RestoreScanRequest::all(QUALIFICATION_TRAFFIC_RESTORE_LIMIT))
        .await
        .unwrap();
    let final_record = protected.get(&key).await.unwrap().unwrap();
    protected.release(retained).await.unwrap();
    drop(protected);
    drop(store);
    cluster.shutdown().await;

    assert!(same_authority);
    assert!(traffic_record_is_exact(&expected, &final_record));
    assert!(cleared_page.complete);
    assert!(cleared_page.next_cursor.is_none());
    assert_eq!(cleared_page.loaded_count, 1);
    assert!(traffic_record_is_exact(&expected, &cleared_page.records[0]));
    assert_eq!(availability.interruption_episodes, 1);
    assert_eq!(availability.recoveries, 0);
    if clear == ClearScan::BeforeCheckpoint {
        assert_eq!(result, Ok(()));
        assert_eq!(rejected, 1);
        assert_eq!(consecutive, 1);
    } else if clear == ClearScan::AfterFailedProof {
        assert!(
            observed_failed_proof,
            "count the actual failed scan reproof"
        );
        assert_eq!(result, Ok(()));
        assert!(rejected > 1);
        assert_eq!(rejected, availability.interruptions);
        assert_eq!(availability.interruptions, consecutive);
    } else {
        assert!(
            result.is_err(),
            "an exact get must not certify recovery while the scan remains unavailable"
        );
        assert!(rejected > 1);
        assert_eq!(availability.interruptions, consecutive);
    }
}

#[tokio::test]
async fn restore_scan_checkpoint_rejects_still_unavailable_scan_after_exact_get() {
    restore_scan_recovery_case(ClearScan::Never).await;
}

#[tokio::test]
async fn restore_scan_checkpoint_accepts_cleared_scan_with_original_authority() {
    restore_scan_recovery_case(ClearScan::BeforeCheckpoint).await;
}

#[tokio::test]
async fn restore_scan_checkpoint_recovers_after_counting_real_failed_scan() {
    restore_scan_recovery_case(ClearScan::AfterFailedProof).await;
}
