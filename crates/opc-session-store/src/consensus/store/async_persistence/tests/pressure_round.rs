//! Pressure recovery retains only work accepted by a live engine.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_status_ticket_waits_for_capacity_with_its_original_deadline() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let store = fleet.store(fleet.leader());
        let scope = store.inner.storage_identity;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let baseline = store
            .fenced_transition_v2_status_logical_time_on_local_leader(
                scope,
                deadline,
                Arc::new(AtomicBool::new(false)),
            )
            .await;
        assert!(matches!(
            baseline,
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(_)
        ));
        store
            .inner
            .raft_handler
            .set_log_admission_window_for_test(1);
        let before = store.inner.raft.metrics().borrow().last_log_index;
        let frozen = Arc::new(AtomicBool::new(false));
        let mut ticket = Box::pin(
            store.fenced_transition_v2_status_logical_time_on_local_leader(
                scope,
                deadline,
                Arc::clone(&frozen),
            ),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut ticket)
                .await
                .is_err(),
            "a status ticket must wait for log capacity, not return Unavailable immediately"
        );
        assert!(!frozen.load(Ordering::Acquire));
        assert_eq!(store.inner.raft.metrics().borrow().last_log_index, before);
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS
        );
        store.inner.raft_handler.set_log_admission_window_for_test(
            crate::consensus::SESSION_CONSENSUS_LOG_HIGH_WATER_ROWS,
        );
        let reply = tokio::time::timeout_at(deadline, ticket).await.unwrap();
        assert!(matches!(
            reply,
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(_)
        ));
        assert!(frozen.load(Ordering::Acquire));
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_status_ticket_keeps_its_deadline_when_pressure_stays() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let store = fleet.store(fleet.leader());
        store
            .inner
            .raft_handler
            .set_log_admission_window_for_test(1);
        let before = store.inner.raft.metrics().borrow().last_log_index;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let reply = store
            .fenced_transition_v2_status_logical_time_on_local_leader(
                store.inner.storage_identity,
                deadline,
                Arc::new(AtomicBool::new(false)),
            )
            .await;
        assert!(matches!(
            reply,
            FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable
        ));
        assert!(tokio::time::Instant::now() >= deadline);
        assert_eq!(store.inner.raft.metrics().borrow().last_log_index, before);
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_failed_handoff_begin_keeps_no_target() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let store = fleet.store((leader + 1) % 3);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        store
            .require_application_traffic_authority_before(deadline)
            .await
            .unwrap();
        let original = store.inner.raft.metrics().borrow().vote;
        let mut target = None;
        let mut handoff = None;
        assert!(store
            .transfer_pressure_leadership_before(&mut target, &mut handoff, deadline)
            .await
            .is_err());
        assert!(handoff.is_none(), "a follower cannot begin a transfer");
        assert!(target.is_none(), "a failed begin owns no later transfer");
        assert_eq!(store.inner.raft.metrics().borrow().vote, original);
        assert_eq!(
            store.inner.raft.metrics().borrow().current_leader,
            Some(fleet.store(leader).inner.local_node_id)
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_retry_owner_stops_when_local_engine_stops() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let store = fleet.store((fleet.leader() + 1) % 3);
        let calls = Arc::new(AtomicU64::new(0));
        let attempt_calls = Arc::clone(&calls);
        let engine = store.inner.raft.clone();
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            store.own_pressure_retries(
                ScopeSchedulerKey::INTERNAL,
                ScopeWorkClass::Normal,
                tokio::time::Instant::now() + Duration::from_secs(10),
                move |_| {
                    let engine = engine.clone();
                    let calls = Arc::clone(&attempt_calls);
                    async move {
                        assert_eq!(
                            calls.fetch_add(1, Ordering::AcqRel),
                            0,
                            "a stopped local engine must not retry its stale remote route"
                        );
                        engine.shutdown().await.unwrap();
                        None::<()>
                    }
                },
            ),
        )
        .await
        .expect("stopping the engine retires its retry owner");
        assert!(matches!(outcome, Err(PressureRetryFailure::NotTransmitted)));
        assert_eq!(calls.load(Ordering::Acquire), 1);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
