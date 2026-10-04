//! Planned handoff must retain native close, reopen and exact-outcome authority.

use super::*;

struct RetainedReplyHold(Arc<AcceptedClientWriteReceiverHoldForTest>);

impl Drop for RetainedReplyHold {
    fn drop(&mut self) {
        self.0.release.notify_one();
    }
}

async fn planned_native_retirement(stop_leader: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let original_leader = fleet.leader();
        let stopped = if stop_leader {
            original_leader
        } else {
            (original_leader + 1) % 3
        };
        let survivor = (0..3)
            .find(|index| *index != original_leader && *index != stopped)
            .unwrap();
        let term = fleet.store(original_leader).status().term;
        let keys = provider();
        // Normal consumer startup commits V1 independently of the V2 profile.
        // A read-only fence observation cannot create that certificate once
        // a voter is absent. Preserve the all-voter activation requirement.
        fleet
            .store(survivor)
            .activate_fenced_transition_capability()
            .await
            .unwrap();
        assert!(fleet
            .store(survivor)
            .activated_fenced_transition_scope_is_current()
            .await
            .unwrap());
        let request = create_request(fleet.store(survivor), 1, keys.as_ref()).await;
        let outcome = create(fleet.store(survivor), &request).await;
        fleet.ready().await;
        let close_proof = fleet
            .directory
            .path()
            .join(format!("node-{stopped}.sqlite.native-wal/ASYNC-CLOSED"));
        assert!(!close_proof.exists());

        // The fixture retains its original, stricter 800 ms operation bound.
        fleet.store(stopped).prepare_shutdown().await.unwrap();
        assert!(!fleet.store(stopped).status().admitted);
        assert!(
            fleet.store(stopped).inner.admitted.load(Ordering::Acquire),
            "retirement closes consumer admission while keeping engine authority for drain"
        );
        assert!(
            !close_proof.exists(),
            "preparation is not a storage drain certificate"
        );
        fleet.close_clean(stopped).await.unwrap();
        assert!(
            close_proof.is_file(),
            "actual shutdown publishes exact native close proof"
        );
        assert_recorded(fleet.store(survivor), &request, &outcome).await;
        let next = create_request(fleet.store(survivor), 2, keys.as_ref()).await;
        create(fleet.store(survivor), &next).await;
        let after = fleet.store(survivor).status();
        assert_eq!(after.term == term, !stop_leader);
        assert_ne!(after.leader_id, Some(fleet.peers[stopped].node));

        fleet
            .open(stopped, SessionPersistenceMode::Async)
            .await
            .unwrap();
        assert!(
            !close_proof.exists(),
            "ordinary opener consumes the one-use proof"
        );
        assert_eq!(
            fleet.store(stopped).persistence_health().recovery,
            Some(SessionAsyncRecoveryState::Active)
        );
        assert!(
            !fleet.store(stopped).inner.retirement.is_started(),
            "new incarnation starts with independent retirement authority"
        );
        assert!(
            !fleet.store(stopped).status().admitted,
            "close proof alone does not grant consumer admission"
        );
        fleet.store(stopped).initialize_cluster().await.unwrap();
        fleet.ready().await;
        assert_recorded(fleet.store(stopped), &request, &outcome).await;
        let fresh = create_request(fleet.store(stopped), 3, keys.as_ref()).await;
        create(fleet.store(stopped), &fresh).await;
    })
    .catch_unwind()
    .await;
    for index in 0..fleet.stores.len() {
        let _ = fleet.close_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn planned_native_leader_retirement_preserves_close_proof_and_reopen() {
    planned_native_retirement(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn planned_native_follower_retirement_preserves_close_proof_and_reopen() {
    planned_native_retirement(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retiring_native_voter_does_not_manufacture_missing_v1_activation() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let leader = fleet.leader();
        let stopped = (leader + 1) % 3;
        let survivor = (leader + 2) % 3;
        let keys = provider();
        let first = create_request(fleet.store(survivor), 41, keys.as_ref()).await;
        let outcome = create(fleet.store(survivor), &first).await;
        let next = create_request(fleet.store(survivor), 42, keys.as_ref()).await;
        assert!(!fleet
            .store(survivor)
            .activated_fenced_transition_scope_is_current()
            .await
            .unwrap());
        fleet.store(stopped).prepare_shutdown().await.unwrap();
        fleet.close_clean(stopped).await.unwrap();
        assert_recorded(fleet.store(survivor), &first, &outcome).await;
        assert_eq!(
            fleet
                .store(survivor)
                .observe_fenced_transition(next.lease().key())
                .await,
            Err(consensus_unavailable()),
            "V2 activation and handoff cannot certify an unproven V1 capability"
        );
        create(fleet.store(survivor), &next).await;
    })
    .catch_unwind()
    .await;
    for index in 0..fleet.stores.len() {
        let _ = fleet.close_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn planned_native_handoff_preserves_an_accepted_mutations_original_completion() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let leader = fleet.leader();
        let survivor = (leader + 1) % 3;
        let old = fleet.store(leader).clone();
        old.activate_fenced_transition_capability().await.unwrap();
        let keys = provider();
        let first = create_request(&old, 51, keys.as_ref()).await;
        create(&old, &first).await;
        let request = create_request(&old, 52, keys.as_ref()).await;
        let before = old.inner.raft.metrics().borrow().last_log_index.unwrap();
        let hold = RetainedReplyHold(Arc::new(AcceptedClientWriteReceiverHoldForTest::default()));
        old.inject_accepted_client_write_receiver_outcome(
            AcceptedClientWriteReceiverTestOutcome::HoldUntilReleased(Arc::clone(&hold.0)),
        );
        let pending = {
            let store = old.clone();
            let request = request.clone();
            tokio::spawn(async move { store.fenced_transition_v2_batch(vec![request]).await })
        };
        tokio::time::timeout(OPERATION_BOUND, hold.0.entered.notified())
            .await
            .unwrap();
        races::until(
            || {
                fleet.stores.iter().flatten().all(|store| {
                    store
                        .inner
                        .raft
                        .metrics()
                        .borrow()
                        .last_applied
                        .is_some_and(|log| log.index > before)
                })
            },
            "the original accepted mutation is applied before its response is released",
        )
        .await;
        // Returning the accepted receiver can precede publication of metrics.
        // Inspect the exact log count after the bounded applied observation.
        assert_eq!(
            old.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1)
        );
        assert!(!pending.is_finished());
        old.prepare_shutdown().await.unwrap();
        assert!(!old.status().admitted);
        assert!(
            !pending.is_finished(),
            "preparation neither cancels nor replaces the original receiver"
        );
        hold.0.release.notify_one();
        let outcome = tokio::time::timeout(OPERATION_BOUND, pending)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .remove(0)
            .unwrap();
        assert!(outcome.matches_v2_request(&request));
        assert_eq!(outcome.mutation(), FencedTransitionMutationResult::Created);
        drop(old);
        fleet.close_clean(leader).await.unwrap();
        assert_recorded(fleet.store(survivor), &request, &outcome).await;
    })
    .catch_unwind()
    .await;
    for index in 0..fleet.stores.len() {
        let _ = fleet.close_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
