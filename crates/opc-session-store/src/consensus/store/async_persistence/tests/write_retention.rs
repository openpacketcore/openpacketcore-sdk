//! Direct supported writes retain exact work across pressure-only attempts.

use super::*;
use crate::scope_authority::*;
use crate::scope_batch::{
    ScopeBatchLookup, ScopeBatchRequest, ScopeBatchStore, ScopeCounterMutation,
};

struct Admission {
    identity: SessionConsumerIdentity,
    scope: ScopeId,
    allowed: AtomicBool,
}

#[async_trait]
impl ScopeAuthorityAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        scope: &ScopeId,
        claim: Option<&ScopeExecution>,
        _: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        if !self.allowed.load(Ordering::Acquire)
            || authenticated != &self.identity
            || scope != &self.scope
            || claim.is_some_and(|claim| claim.identity() != authenticated)
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        Ok(ScopeAuthorityRole::Worker)
    }
}

async fn batch_fixture(
    store: &ConsensusSessionStore,
    class: ScopeWorkClass,
) -> (
    ScopeBatchStore,
    SessionConsumerIdentity,
    ScopeBatchRequest,
    Arc<Admission>,
) {
    store.activate_scope_profile().await.unwrap();
    let identity = SessionConsumerIdentity::new("spiffe://pressure.test/worker").unwrap();
    let scope = ScopeId::new(
        store.inner.storage_identity,
        TenantId::new("pressure-test").unwrap(),
        NetworkFunctionKind::new("test").unwrap(),
        [0x75; 32],
    )
    .unwrap();
    let admission = Arc::new(Admission {
        identity: identity.clone(),
        scope: scope.clone(),
        allowed: AtomicBool::new(true),
    });
    let execution = ScopeExecution::new(identity.clone(), 1, [1; 16], [2; 16], [3; 32]).unwrap();
    let authority =
        ScopeAuthorityStore::new(Arc::new(store.clone()), scope.clone(), admission.clone())
            .unwrap();
    let committed = authority
        .admit(
            &identity,
            &ScopeAuthorityRequest::new(
                scope,
                [0x71; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial { execution },
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let batches = ScopeBatchStore::new(
        Arc::new(store.clone()),
        committed.stamp().namespace().clone(),
        admission.clone(),
    )
    .unwrap();
    let request = ScopeBatchRequest::in_lane(
        committed.stamp(),
        [0x72; 16],
        if class == ScopeWorkClass::Emergency {
            7
        } else {
            0
        },
        1,
        vec![],
        vec![ScopeCounterMutation::new(0, 0, 7).unwrap()],
    )
    .unwrap();
    (batches, identity, request, admission)
}

async fn retained_batch(
    remote: bool,
    cancel_observer: bool,
    revoke: bool,
    handoff: bool,
    slow_reply: bool,
) {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let store = fleet.store(leader);
        let client = fleet.store(if remote { (leader + 1) % 3 } else { leader });
        let (batches, identity, request, admission) =
            batch_fixture(client, ScopeWorkClass::Normal).await;
        let gate = Arc::new(SnapshotArtifactGate::new());
        let mut hold = Some(store
            .inner
            .terminal_recovery_handoff_consumer
            .pause_snapshot_publication_for_test(gate.clone()));
        gate.arm();
        store.inner.raft.trigger().snapshot().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), gate.wait_started())
            .await
            .unwrap();
        let command = repeated_command(store);
        let through = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_applied
            .unwrap()
            .index
            + DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
            + DURABLE_OPENRAFT_PROFILE.retained_logs
            + 64;
        seed_to(&fleet, store, &command, through).await;
        let window = store.log_pressure_snapshot().retained_rows;
        store
            .inner
            .raft_handler
            .set_log_admission_window_for_test(window);
        let request_bytes = postcard::to_allocvec(&request).unwrap();
        let attempt = request.attempt().unwrap();
        let _slow_reply = slow_reply.then(|| SlowAcceptedReply::arm(&fleet));
        let service = batches.clone();
        let authenticated = identity.clone();
        let retained = request.clone();
        let (write, mut pressure_clock_advanced) = recovery_test_control::run(
            std::time::Instant::now() + OPERATION_BOUND
                + Duration::from_millis(100) + Duration::from_secs(10),
            OPERATION_BOUND + Duration::from_millis(100),
            async move {
                service.execute_classified(&authenticated, &retained, ScopeWorkClass::Normal).await
            },
        );
        let mut write = Box::pin(write);
        assert!(
            tokio::time::timeout(OPERATION_BOUND + Duration::from_millis(100), &mut write)
                .await
                .is_err(),
            "the same public write must remain owned after a pressure-only dispatch deadline"
        );
        assert_eq!(postcard::to_allocvec(&request).unwrap(), request_bytes);
        assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
        assert_eq!(store.log_pressure_snapshot().retained_rows, window);
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS,
            "pressure keeps no running proposal credit"
        );
        let recovery_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        tokio::time::timeout_at(
            recovery_deadline,
            pressure_clock_advanced.wait_for(|advanced| *advanced),
        ).await.expect("pressure owner crosses the original protocol deadline")
            .expect("pressure clock remains owned");
        if revoke {
            admission.allowed.store(false, Ordering::Release);
        }
        if cancel_observer {
            drop(write);
            drop(hold.take());
        } else {
            if !handoff {
                drop(hold.take());
            }
            let result = tokio::time::timeout_at(recovery_deadline, &mut write)
                .await
                .unwrap();
            if revoke {
                assert_eq!(
                    result,
                    Err(crate::scope_batch::ScopeBatchError::Scope(
                        ScopeAuthorityError::Unauthorized
                    ))
                );
                let checkpoint = store.scope_batch_checkpoint(request.scope()).await.unwrap();
                assert_eq!(
                    checkpoint.counters[0], 0,
                    "retry must recheck live service authority"
                );
                return;
            }
            let outcome = result.unwrap_or_else(|error| {
                panic!(
                    "retained write failed: {error}; pressure: {:?}; metrics: {:?}",
                    store.log_pressure_snapshot(),
                    store.inner.raft.metrics().borrow(),
                )
            });
            assert!(outcome.matches_request(&request));
            assert_eq!(outcome.counters()[0], 7);
            if handoff {
                assert_ne!(store.inner.raft.metrics().borrow().current_leader, Some(store.inner.local_node_id));
                assert_eq!(store.inner.raft.metrics().borrow().snapshot, None,
                    "the successor completes the retained write while the old snapshot is still held");
            }
            drop(hold.take());
        }
        let lookup_deadline = if cancel_observer {
            recovery_deadline
        } else {
            tokio::time::Instant::now() + Duration::from_secs(10)
        };
        tokio::time::timeout_at(lookup_deadline, async {
            loop {
                if let ScopeBatchLookup::Applied(outcome) =
                    batches.lookup(&identity, &attempt).await.unwrap()
                {
                    assert!(outcome.matches_request(&request));
                    assert_eq!(outcome.counters()[0], 7);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the retained exact request commits without another caller submission");
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_public_write_retains_local_request() {
    retained_batch(false, false, false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_public_write_retains_request_with_slow_reply() {
    retained_batch(false, false, false, false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_public_batch_deadline_resolves_committed_checkpoint() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let store = fleet.store(leader).clone();
        let (batches, identity, request, _) =
            batch_fixture(&store, ScopeWorkClass::Normal).await;
        let held = SlowAcceptedReply::hold(&fleet);
        let before = store.inner.raft.metrics().borrow().last_log_index.unwrap();
        clock::run(async move {
            let started = tokio::time::Instant::now();
            let mut write = Box::pin(recovery_test_control::observe(
                batches.execute_classified(&identity, &request, ScopeWorkClass::Normal),
            ));
            {
                let entered = held.holds[leader].entered.notified();
                tokio::pin!(entered);
                tokio::select! {
                    () = &mut entered => {},
                    result = &mut write => panic!("batch completed before its accepted reply was held: {result:?}"),
                }
            }
            // The real Raft runtime commits the command while its reply stays
            // held. The public operation must still observe its own deadline.
            let mut metrics = store.inner.raft.metrics();
            metrics.wait_for(|current| current.last_applied.is_some_and(|log| log.index > before))
                .await.unwrap();
            tokio::time::advance(OPERATION_BOUND - Duration::from_millis(1)).await;
            assert!(write.as_mut().now_or_never().is_none(), "the 800ms deadline has not fired at 799ms");
            tokio::time::advance(Duration::from_millis(1)).await;
            let (outcome, events) = write.await;
            assert_eq!(started.elapsed(), OPERATION_BOUND);
            assert_eq!(events, vec![
                recovery_test_control::Event::DeadlineExpired,
                recovery_test_control::Event::ScopeBatchOutcomeUnknown,
                recovery_test_control::Event::CheckpointResolved,
            ], "expiry returns unknown before the service resolves the committed checkpoint");
            let outcome = outcome.unwrap();
            assert!(outcome.matches_request(&request));
            assert_eq!(outcome.counters()[0], 7);
            assert_eq!(store.inner.raft.metrics().borrow().last_log_index, Some(before + 1),
                "checkpoint resolution must not replay the ambiguous mutation");
            drop(held);
        }).await;
    }).catch_unwind().await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_public_write_retains_forwarded_request() {
    retained_batch(true, false, false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_public_write_retains_cancelled_observer_request() {
    retained_batch(false, true, false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_public_write_rechecks_authority_after_pressure() {
    retained_batch(false, false, true, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_public_emergency_batch_uses_headroom() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let store = fleet.store(fleet.leader());
        let (batches, identity, request, _) = batch_fixture(store, ScopeWorkClass::Emergency).await;
        let gate = Arc::new(SnapshotArtifactGate::new());
        let hold = store
            .inner
            .terminal_recovery_handoff_consumer
            .pause_snapshot_publication_for_test(gate.clone());
        gate.arm();
        store.inner.raft.trigger().snapshot().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), gate.wait_started())
            .await
            .unwrap();
        let window = store.log_pressure_snapshot().retained_rows;
        store
            .inner
            .raft_handler
            .set_log_admission_window_for_test(window);
        let started = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(
            OPERATION_BOUND,
            batches.execute_classified(&identity, &request, ScopeWorkClass::Emergency),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(outcome.matches_request(&request));
        assert_eq!(outcome.counters()[0], 7);
        assert!(store.log_pressure_snapshot().retained_rows > window);
        tokio::time::sleep_until(started + OPERATION_BOUND + Duration::from_millis(100)).await;
        assert!(
            store.inner.raft.metrics().borrow().snapshot.is_none(),
            "the snapshot remains held beyond the dispatch budget"
        );
        assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
        drop(hold);
        let resolved = batches
            .lookup(&identity, &request.attempt().unwrap())
            .await
            .unwrap();
        assert!(
            matches!(resolved, ScopeBatchLookup::Applied(ref value) if value.as_ref() == &outcome)
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_public_v2_write_retains_exact_request() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let store = fleet.store(fleet.leader());
        let provider = provider();
        let initial = create_request(store, 71, &provider).await;
        store.fenced_transition_v2(initial).await.unwrap();
        let request = create_request(store, 72, &provider).await;
        let bytes = postcard::to_allocvec(&request).unwrap();
        let gate = Arc::new(SnapshotArtifactGate::new());
        let hold = store
            .inner
            .terminal_recovery_handoff_consumer
            .pause_snapshot_publication_for_test(gate.clone());
        gate.arm();
        store.inner.raft.trigger().snapshot().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), gate.wait_started())
            .await
            .unwrap();
        let through = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_applied
            .unwrap()
            .index
            + DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
            + DURABLE_OPENRAFT_PROFILE.retained_logs
            + 64;
        seed_to(&fleet, store, &repeated_command(store), through).await;
        let window = store.log_pressure_snapshot().retained_rows;
        store
            .inner
            .raft_handler
            .set_log_admission_window_for_test(window);
        let mut write = Box::pin(store.fenced_transition_v2(request.clone()));
        assert!(
            tokio::time::timeout(OPERATION_BOUND + Duration::from_millis(100), &mut write)
                .await
                .is_err(),
            "the direct V2 write retains its exact request across pressure attempts"
        );
        assert_eq!(postcard::to_allocvec(&request).unwrap(), bytes);
        assert_eq!(store.log_pressure_snapshot().retained_rows, window);
        drop(hold);
        let outcome = tokio::time::timeout(Duration::from_secs(10), &mut write)
            .await
            .unwrap()
            .unwrap();
        assert!(outcome.matches_v2_request(&request));
        assert_eq!(outcome.mutation(), FencedTransitionMutationResult::Created);
        assert_eq!(outcome.committed_generation(), Generation::new(1));
        assert_recorded(store, &request, &outcome).await;
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_review_public_write_retains_request_across_pressure_handoff() {
    retained_batch(false, false, false, true, false).await;
}
