//! Scheduling metadata protocol regressions.
use super::*;

#[tokio::test]
async fn log_admission_preflight_resident_deadline_preserves_diagnostic() {
    let directory = tempfile::tempdir().expect("preflight admission directory");
    let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
        .expect("preflight admission backend");
    let store = ConsensusSessionStore::open_with_clock(
        membership_tests::singleton_topology(),
        backend,
        directory.path().join("snapshots"),
        BTreeMap::new(),
        Arc::new(SystemClock),
        Duration::from_secs(5),
    )
    .await
    .expect("preflight admission store");
    let initializing_store = store.clone();
    crate::formation_clock::run(async move { initializing_store.initialize_cluster().await })
        .await
        .expect("initialize preflight admission leader");
    store
        .require_exact_membership_admission()
        .expect("preflight deadline fixture has admitted membership");
    let mut reservations = Vec::new();
    for _ in 0..crate::scope_scheduler::ScopeSchedulerBudgets::default()
        .maintenance
        .queued
    {
        reservations.push(
            store
                .inner
                .proposal_admission
                .reserve_for(ScopeSchedulerKey::INTERNAL, ScopeWorkClass::Maintenance)
                .await
                .expect("reserve maintenance resident capacity"),
        );
    }
    let before = store
        .inner
        .diagnostics
        .proposal_permit_deadline
        .load(Ordering::Relaxed);
    let reply = store
        .preflight_record_expiry_on_local_leader(
            Vec::new(),
            ForwardConsumerScope::Internal,
            store.inner.local_node_id,
            tokio::time::Instant::now() + Duration::from_millis(40),
        )
        .await;
    assert_eq!(reply, ForwardMutationReply::Unavailable);
    assert_eq!(
        store.inner.proposal_admission.available_permits(),
        SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS,
        "resident exhaustion does not consume an execution credit"
    );
    let after = store
        .inner
        .diagnostics
        .proposal_permit_deadline
        .load(Ordering::Relaxed);
    drop(reservations);
    store
        .shutdown()
        .await
        .expect("preflight admission shutdown");
    assert_eq!(
        after,
        before + 1,
        "preflight admission timeouts remain observable"
    );
}

#[tokio::test]
async fn log_admission_preflight_rejects_unadmitted_before_resident_wait() {
    let directory = tempfile::tempdir().expect("unadmitted preflight directory");
    let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
        .expect("unadmitted preflight backend");
    let store = ConsensusSessionStore::open_with_clock(
        membership_tests::singleton_topology(),
        backend,
        directory.path().join("snapshots"),
        BTreeMap::new(),
        Arc::new(SystemClock),
        Duration::from_secs(5),
    )
    .await
    .expect("unadmitted preflight store");
    assert!(store.require_exact_membership_admission().is_err());
    let mut reservations = Vec::new();
    for _ in 0..crate::scope_scheduler::ScopeSchedulerBudgets::default()
        .maintenance
        .queued
    {
        reservations.push(
            store
                .inner
                .proposal_admission
                .reserve_for(ScopeSchedulerKey::INTERNAL, ScopeWorkClass::Maintenance)
                .await
                .expect("reserve maintenance resident capacity"),
        );
    }
    let before = store
        .inner
        .diagnostics
        .proposal_permit_deadline
        .load(Ordering::Relaxed);
    let mut preflight = Box::pin(store.preflight_record_expiry_on_local_leader(
        Vec::new(),
        ForwardConsumerScope::Internal,
        store.inner.local_node_id,
        tokio::time::Instant::now() + Duration::from_secs(5),
    ));
    assert_eq!(
        futures_util::poll!(&mut preflight),
        std::task::Poll::Ready(ForwardMutationReply::Unavailable),
        "unadmitted membership rejects before waiting for resident capacity"
    );
    drop(preflight);
    assert_eq!(
        store
            .inner
            .diagnostics
            .proposal_permit_deadline
            .load(Ordering::Relaxed),
        before,
        "membership rejection is not an admission deadline"
    );
    assert_eq!(
        store.inner.proposal_admission.available_permits(),
        SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS,
        "unadmitted preflight does not consume an execution credit"
    );
    drop(reservations);
    store
        .shutdown()
        .await
        .expect("unadmitted preflight shutdown");
}

#[tokio::test]
async fn log_admission_leader_waits_without_running_credit() {
    let directory = tempfile::tempdir().expect("log admission directory");
    let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
        .expect("log admission backend");
    let store = ConsensusSessionStore::open_with_clock(
        membership_tests::singleton_topology(),
        backend,
        directory.path().join("snapshots"),
        BTreeMap::new(),
        Arc::new(SystemClock),
        Duration::from_secs(5),
    )
    .await
    .expect("log admission store");
    let initializing_store = store.clone();
    crate::formation_clock::run(async move { initializing_store.initialize_cluster().await })
        .await
        .expect("initialize log admission leader");
    let retained = store
        .inner
        .raft
        .metrics()
        .borrow()
        .last_log_index
        .expect("initialized log")
        + 1;
    store
        .inner
        .raft_handler
        .set_log_admission_window_for_test(retained);
    let reservation = store
        .inner
        .proposal_admission
        .reserve_for(ScopeSchedulerKey::INTERNAL, ScopeWorkClass::Normal)
        .await
        .expect("resident proposal reservation");
    let mut waiting = Box::pin(store.start_proposal_before(
        reservation,
        &SessionMutationIntent::AdvanceLogicalTime,
        tokio::time::Instant::now() + Duration::from_secs(5),
    ));
    assert!(
        futures_util::poll!(&mut waiting).is_pending(),
        "live retained-log pressure must hold a new leader proposal before execution"
    );
    assert_eq!(
        store.inner.proposal_admission.available_permits(),
        SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS,
        "waiting on log reclamation must not consume an execution credit"
    );
    let priority = store
        .inner
        .proposal_admission
        .reserve_for(ScopeSchedulerKey::INTERNAL, ScopeWorkClass::SafetyControl)
        .await
        .expect("priority reservation");
    let mut priority_waiting = Box::pin(store.start_proposal_before(
        priority,
        &SessionMutationIntent::PreflightScopeProfile,
        tokio::time::Instant::now() + Duration::from_secs(5),
    ));
    assert!(
        futures_util::poll!(&mut priority_waiting).is_pending(),
        "scheduling priority does not exempt ordinary growth from log backpressure"
    );
    assert_eq!(
        store.inner.proposal_admission.available_permits(),
        SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS,
        "priority growth also waits without consuming a running credit"
    );
    let emergency = store
        .inner
        .proposal_admission
        .reserve_for(ScopeSchedulerKey::INTERNAL, ScopeWorkClass::Emergency)
        .await
        .expect("verified emergency reservation");
    let emergency = tokio::time::timeout(
        Duration::from_millis(100),
        store.start_proposal_before(
            emergency,
            &SessionMutationIntent::AdvanceLogicalTime,
            tokio::time::Instant::now() + Duration::from_secs(5),
        ),
    )
    .await
    .expect("emergency admission must not wait behind the ordinary log window")
    .expect("emergency retains reserved admission headroom");
    assert_eq!(emergency.class(), ScopeWorkClass::Emergency);
    drop(emergency);
    let control = store
        .inner
        .proposal_admission
        .reserve_for(ScopeSchedulerKey::INTERNAL, ScopeWorkClass::SafetyControl)
        .await
        .expect("control reservation");
    let control = store
        .start_proposal_before(
            control,
            &SessionMutationIntent::AbortTopologyTransition {
                transition_id: [1; 16],
                request_digest: [2; 32],
            },
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("topology progress retains its reserved scheduler capacity");
    drop(control);
    drop(waiting);
    drop(priority_waiting);
    assert_eq!(
        store.inner.proposal_admission.available_permits(),
        SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS,
        "cancelling the waiting proposal releases its reservation"
    );
    store
        .shutdown()
        .await
        .expect("log admission leader shutdown");
}

#[test]
fn scope_scheduler_reserved_credits_are_additional_to_eight_ordinary_slots() {
    let budgets = crate::scope_scheduler::ScopeSchedulerBudgets::default();
    assert!(crate::scope_scheduler::ScopeSchedulerOwner::new(budgets).is_ok());
    assert_eq!(
        budgets.normal.running,
        opc_consensus::DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS
    );
    assert_eq!(SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS, 13);
    assert_eq!(
        StoreWorkAdmission::new().available_permits(),
        SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS
    );
}

#[test]
fn scope_scheduler_mutation_forward_requires_class_metadata() {
    // This independent old shape must never gain the new field through a
    // shared alias to the current struct (the original v711 mirror did).
    #[derive(Serialize)]
    struct OldMutation {
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
        required_consumer_scope: ForwardConsumerScope,
    }
    #[derive(Serialize)]
    enum OldForward {
        Mutation(OldMutation),
    }
    let old = encode_bounded(&OldForward::Mutation(OldMutation {
        request_id: SessionConsensusRequestId::from_bytes([1; 16]),
        intent: SessionMutationIntent::AdvanceLogicalTime,
        required_consumer_scope: ForwardConsumerScope::Internal,
    }))
    .unwrap();
    assert!(
        decode_bounded::<ForwardRequest>(&old).is_err(),
        "missing class metadata must fail closed"
    );
}

#[test]
fn scope_scheduler_forward_class_is_required_bounded_metadata_outside_intent() {
    let request = ForwardMutationRequest {
        request_id: SessionConsensusRequestId::from_bytes([1; 16]),
        intent: SessionMutationIntent::AdvanceLogicalTime,
        required_consumer_scope: ForwardConsumerScope::Internal,
        work_class: ForwardWorkClass::Inferred,
    };
    let encoded = encode_bounded(&ForwardRequest::Mutation(request.clone())).unwrap();
    assert!(decode_bounded::<FrozenV711ForwardRequest>(&encoded).is_err());
    assert!(decode_bounded::<ForwardRequest>(&encoded[..encoded.len() - 1]).is_err());
    let mut invalid = encoded.clone();
    *invalid.last_mut().unwrap() = 0x7F;
    assert!(decode_bounded::<ForwardRequest>(&invalid).is_err());
    let mut forged = request.clone();
    forged.work_class = ForwardWorkClass::Declared(ScopeWorkClass::SafetyControl);
    assert_eq!(
        forged.scheduling(),
        Err(StoreError::TopologyAuthorityRevoked)
    );
    forged.work_class = ForwardWorkClass::Declared(ScopeWorkClass::Emergency);
    assert_eq!(
        forged.scheduling(),
        Err(StoreError::TopologyAuthorityRevoked),
        "only own-scope batch ingress declares a data class"
    );
    assert_eq!(
        encode_bounded(&request.intent).unwrap(),
        encode_bounded(&forged.intent).unwrap()
    );
    assert_eq!(request.request_id, forged.request_id);
    assert_eq!(request.scheduling().unwrap().1, ScopeWorkClass::Normal);
}

#[test]
fn scope_scheduler_leader_refuses_declared_control_on_forwarded_child_batch() {
    use crate::scope_batch::{ScopeBatchCommand, ScopeBatchRequest};
    let admitted = crate::scope_authority::tests::admitted();
    let request = ForwardMutationRequest {
        request_id: SessionConsensusRequestId::from_bytes([3; 16]),
        intent: SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
            request: ScopeBatchRequest::new(
                admitted.view.stamp().unwrap(),
                [3; 16],
                0,
                vec![crate::scope_batch::tests::create(1, &[1])],
                vec![],
            )
            .unwrap(),
        })),
        required_consumer_scope: ForwardConsumerScope::Internal,
        work_class: ForwardWorkClass::Declared(ScopeWorkClass::SafetyControl),
    };
    let encoded = encode_bounded(&ForwardRequest::Mutation(request)).unwrap();
    let ForwardRequest::Mutation(mut forwarded) = decode_bounded(&encoded).unwrap() else {
        panic!("forwarded mutation");
    };
    assert_eq!(
        forwarded.scheduling(),
        Err(StoreError::TopologyAuthorityRevoked)
    );
    // This shape reaches the batch-specific arm. A generic non-batch rejection
    // would not prove that forged control is rejected at leader admission.
    forwarded.work_class = ForwardWorkClass::Declared(ScopeWorkClass::Emergency);
    assert_eq!(forwarded.scheduling().unwrap().1, ScopeWorkClass::Emergency);
}
