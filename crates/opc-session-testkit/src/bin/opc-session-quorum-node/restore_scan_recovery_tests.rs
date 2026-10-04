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
    // Keep the real acquisition lane available to the complete checkpoint,
    // and prove that scan recovery does not mutate its retained custody.
    let acquisition_directory = tempfile::tempdir().unwrap();
    let acquisition_database = acquisition_directory.path().join("replica.sqlite");
    let journal = traffic_acquire::Journal::open(
        &acquisition_database,
        traffic_acquire::Binding::new(
            store.consumer_scope().unwrap(),
            0,
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
            &mut acquirer,
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

fn exact_restore_page() -> (StoredSessionRecord, opc_session_store::RestoreScanPage) {
    let key = qualification_traffic_key(0).unwrap();
    let expected = expected_traffic_record(&key, 37, 3, 0, 1, 1).unwrap();
    let mut page = opc_session_store::RestoreScanPage::new(vec![expected.clone()], 0, None);
    page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
    (expected, page)
}

#[tokio::test(start_paused = true)]
async fn restore_scan_reproof_preserves_every_page_validation() {
    let (expected, page) = exact_restore_page();
    let mut malformed = Vec::new();
    let mut incomplete = page.clone();
    incomplete.complete = false;
    malformed.push(incomplete);
    let mut continued = page.clone();
    continued.next_cursor = Some(opc_session_store::RestoreScanCursor::from_offset(1));
    malformed.push(continued);
    let mut legacy = page.clone();
    legacy.cursor_profile = RestoreScanCursorProfile::LegacyCompatibility;
    malformed.push(legacy);
    let mut wrong_count = page.clone();
    wrong_count.loaded_count += 1;
    malformed.push(wrong_count);
    let mut over_limit = page.clone();
    over_limit.records = vec![expected.clone(); QUALIFICATION_TRAFFIC_RESTORE_LIMIT + 1];
    over_limit.loaded_count = over_limit.records.len();
    malformed.push(over_limit);
    let mut wrong_record = page.clone();
    wrong_record.records[0].generation = Generation::new(2);
    malformed.push(wrong_record);

    for (index, page) in malformed.into_iter().enumerate() {
        let observation = QualificationTrafficObservation::new(37, 3);
        let mut consecutive = 0;
        assert!(observation.record_availability_interruption(&mut consecutive));
        let started = tokio::time::Instant::now();
        let result = prove_traffic_restore_scan_recovery(
            || std::future::ready(Ok(page.clone())),
            &expected,
            started,
            traffic_recovery_deadline(started, None),
            &mut consecutive,
            &observation,
        )
        .await;
        assert_eq!(
            result,
            Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::RestoreScanRejected,
                QualificationTrafficFailureStage::RestoreScan,
            )),
            "malformed page case {index} must be terminal"
        );
        assert_eq!(consecutive, 1);
        assert_eq!(observation.availability_snapshot().recoveries, 0);
        assert_eq!(tokio::time::Instant::now(), started);
    }
}

#[tokio::test(start_paused = true)]
async fn restore_scan_reproof_keeps_work_budget_errors_terminal() {
    let (expected, _) = exact_restore_page();
    let observation = QualificationTrafficObservation::new(37, 3);
    let mut consecutive = 0;
    assert!(observation.record_availability_interruption(&mut consecutive));
    let started = tokio::time::Instant::now();
    let mut calls = 0;
    let result = prove_traffic_restore_scan_recovery(
        || {
            calls += 1;
            std::future::ready(Err(StoreError::RestoreScanWorkBudgetExceeded))
        },
        &expected,
        started,
        traffic_recovery_deadline(started, None),
        &mut consecutive,
        &observation,
    )
    .await;
    assert_eq!(
        result,
        Err(QualificationTrafficFailure::store(
            QualificationTrafficFailureCode::RestoreScanRejected,
            QualificationTrafficFailureStage::RestoreScan,
            &StoreError::RestoreScanWorkBudgetExceeded,
        ))
    );
    assert_eq!(calls, 1);
    assert_eq!(consecutive, 1);
    assert_eq!(tokio::time::Instant::now(), started);
}

#[tokio::test(start_paused = true)]
async fn restore_scan_reproof_uses_remaining_original_deadline() {
    let started = tokio::time::Instant::now();
    let deadline = traffic_recovery_deadline(started, None);
    tokio::time::advance(Duration::from_secs(25)).await;
    let entered = Arc::new(Notify::new());
    let entered_scan = Arc::clone(&entered);
    let task = tokio::spawn(async move {
        let (expected, _) = exact_restore_page();
        let observation = QualificationTrafficObservation::new(37, 3);
        let mut consecutive = 0;
        assert!(observation.record_availability_interruption(&mut consecutive));
        let result = prove_traffic_restore_scan_recovery(
            || async {
                entered_scan.notify_one();
                std::future::pending().await
            },
            &expected,
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
    let finished = task.is_finished();
    if !finished {
        task.abort();
    }
    let joined = task.await;
    assert!(
        finished,
        "the scan observer must end at the original deadline"
    );
    let (result, availability, consecutive) = joined.unwrap();
    assert!(result.is_err());
    assert_eq!(tokio::time::Instant::now(), deadline);
    assert_eq!(availability.interruption_episodes, 1);
    assert_eq!(availability.interruptions, 2);
    assert_eq!(availability.recoveries, 0);
    assert_eq!(consecutive, 2);
}

#[tokio::test(start_paused = true)]
async fn restore_scan_reproof_does_not_admit_at_expired_deadline() {
    let (expected, page) = exact_restore_page();
    let started = tokio::time::Instant::now();
    let observation = QualificationTrafficObservation::new(37, 3);
    let mut consecutive = 0;
    assert!(observation.record_availability_interruption(&mut consecutive));
    let mut calls = 0;
    let result = prove_traffic_restore_scan_recovery(
        || {
            calls += 1;
            std::future::ready(Ok(page.clone()))
        },
        &expected,
        started,
        started,
        &mut consecutive,
        &observation,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls, 0);
    assert_eq!(consecutive, 1);
}

#[tokio::test(start_paused = true)]
async fn restore_scan_reproof_rejects_exact_page_observed_at_deadline() {
    let (expected, page) = exact_restore_page();
    let started = tokio::time::Instant::now();
    let deadline = traffic_recovery_deadline(started, None);
    let observation = QualificationTrafficObservation::new(37, 3);
    let mut consecutive = 0;
    assert!(observation.record_availability_interruption(&mut consecutive));
    let result = prove_traffic_restore_scan_recovery(
        || async {
            tokio::time::sleep_until(deadline).await;
            Ok(page.clone())
        },
        &expected,
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
