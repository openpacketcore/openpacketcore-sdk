mod continuity;
mod legacy_outcome_bytes;
#[cfg(unix)]
mod retained_opening;
mod target_outcome_bytes;

// SDK #797: one real configuration quorum; independent receipt and config readback.
use super::*;
use opc_persist::audit_authority::*;
use opc_persist::{
    ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
};

fn source_event(request: u8, outcome: ManagementAuditOutcomeCode) -> ManagementAuditEventRecord {
    ManagementAuditEventRecord::try_new(
        [request; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        "audit-tenant-canary",
        "audit-principal-canary",
        ManagementAuditTransportCode::Gnmi,
        ManagementAuditOperationCode::Update,
        outcome,
        (outcome == ManagementAuditOutcomeCode::Denied).then_some("denied"),
        ["/fixture:config/fixture:name"],
        Some("audit-transaction-canary"),
    )
    .unwrap()
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0xA9; 32]).unwrap()
}
fn caller() -> AuditCaller {
    AuditCaller::project(&privacy(), "audit-tenant-canary", "audit-principal-canary").unwrap()
}
fn applied(result: AuditAdmission) -> AuditOperationReceipt {
    match result {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected authoritative receipt: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn known_audited_commit_does_not_depend_on_a_second_read_quorum() {
    let cluster = ThreeNodeCluster::start().await;
    let leader = cluster.leader();
    let follower = (leader + 1) % 3;
    let store = cluster.stores[follower].clone();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(91, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 7), audit(tx)),
            Duration::from_secs(60),
        )
        .unwrap();
    let intent = applied(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
    );
    let wire = cluster.paths[&(follower, leader)].clone();
    wire.pause_forward_response.store(true, Ordering::Release);
    let submitted = prepared.clone();
    let actor = store.clone();
    let task = tokio::spawn(async move {
        actor
            .submit_audited_mutation(&submitted, &intent, caller())
            .await
    });
    tokio::time::timeout(
        Duration::from_secs(10),
        wire.forward_response_ready.notified(),
    )
    .await
    .unwrap();
    assert_eq!(
        cluster.stores[leader]
            .load_latest()
            .await
            .unwrap()
            .unwrap()
            .record
            .tx_id,
        tx,
        "the exact committed config is independently visible before its response"
    );
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].stall_family(ConsensusRpcFamily::ReadBarrier, true);
        }
    }
    wire.pause_forward_response.store(false, Ordering::Release);
    wire.release_forward_response.notify_one();
    let outcome = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].stall_family(ConsensusRpcFamily::ReadBarrier, false);
        }
    }
    let receipt = applied(outcome);
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(!receipt.terminal_recorded());
    assert_eq!(
        store
            .lookup_audit_operation(prepared.handle(), caller())
            .await
            .unwrap()
            .unwrap(),
        receipt
    );
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_audit_lost_intent_and_commit_acks_survive_leader_change() {
    let cluster = ThreeNodeCluster::start().await;
    let leader = cluster.leader();
    let follower = (leader + 1) % 3;
    let store = &cluster.stores[follower];
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(12, 4).unwrap())
        .await
        .unwrap();
    assert!(store.load_latest().await.unwrap().is_none());
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(1, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 7), audit(tx)),
            Duration::from_secs(300),
        )
        .unwrap();
    let recovered = PreparedAuditedMutation::decode(&prepared.encode().unwrap()).unwrap();
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(usize::MAX);
        }
    }
    assert!(matches!(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
        AuditAdmission::Unknown(_)
    ));
    assert!(
        store.load_latest().await.unwrap().is_none(),
        "intent never changes config"
    );
    let intent = store
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(intent.state(), AuditOperationState::Intent);
    assert!(matches!(
        store
            .submit_audited_mutation(&recovered, &intent, caller())
            .await,
        AuditAdmission::Unknown(_)
    ));
    let receipt = store
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(!receipt.terminal_recorded());
    assert_eq!(store.load_latest().await.unwrap().unwrap().record.tx_id, tx);
    let wrong = AuditCaller::project(&privacy(), "other-tenant", "audit-principal-canary").unwrap();
    assert_eq!(
        store
            .lookup_audit_operation(prepared.handle(), wrong)
            .await
            .unwrap_err(),
        AuditAuthorityError::BindingMismatch
    );

    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(0);
        }
    }
    cluster.isolate(leader);
    #[cfg(feature = "dangerous-test-hooks")]
    cluster.stores[follower]
        .trigger_election_for_test()
        .await
        .unwrap();
    tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
        loop {
            if cluster.stores[follower]
                .probe_durable_readiness()
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let replay = applied(
        store
            .submit_audited_mutation(&recovered, &intent, caller())
            .await,
    );
    assert_eq!(
        replay.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert_eq!(
        store.load_latest().await.unwrap().unwrap().record.version,
        ConfigVersion::new(1)
    );
    let finished = applied(
        store
            .finish_audit_operation(prepared.handle(), caller())
            .await,
    );
    assert!(finished.terminal_recorded());
    assert_eq!(
        applied(
            store
                .reject_audit_operation(prepared.handle(), caller())
                .await
        )
        .state(),
        AuditOperationState::Committed { version: 1 }
    );
    cluster.heal(leader);
    cluster.wait_ready().await;
    for voter in &cluster.stores {
        assert_eq!(
            voter
                .lookup_audit_operation(prepared.handle(), caller())
                .await
                .unwrap()
                .unwrap(),
            finished
        );
        assert_eq!(
            voter.load_latest().await.unwrap().unwrap().record.version,
            ConfigVersion::new(1)
        );
    }
    for path in cluster.paths.values() {
        for payload in path.captured_payloads.lock().unwrap().iter() {
            for canary in [
                b"audit-tenant-canary".as_slice(),
                b"audit-principal-canary",
                b"audit-transaction-canary",
            ] {
                assert!(!payload.windows(canary.len()).any(|window| window == canary));
            }
        }
    }
    cluster.shutdown().await;
}

#[tokio::test]
async fn replicated_audit_saturation_reserves_results_and_rejects_rebinding() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open_singleton(
        &dir.path().join("config.sqlite"),
        &dir.path().join("snapshots"),
    )
    .await;
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(3, 1).unwrap())
        .await
        .unwrap();
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(2, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 8), audit(tx)),
            Duration::from_secs(300),
        )
        .unwrap();
    let receipt = applied(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
    );
    let denied = store
        .prepare_audit_observation(
            &privacy(),
            &source_event(3, ManagementAuditOutcomeCode::Denied),
            Duration::from_secs(300),
        )
        .unwrap();
    assert!(matches!(
        store.admit_audit_operation(&denied, caller()).await,
        AuditAdmission::Rejected(AuditAuthorityError::Full)
    ));
    let other_tx = TxId::new();
    let other = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(2, ManagementAuditOutcomeCode::Intent),
            attested(commit(other_tx, None, 1, 9), audit(other_tx)),
            Duration::from_secs(300),
        )
        .unwrap();
    assert!(matches!(
        store.admit_audit_operation(other.handle(), caller()).await,
        AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
    ));
    assert!(matches!(
        store
            .submit_audited_mutation(&other, &receipt, caller())
            .await,
        AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
    ));
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&prepared.encode().unwrap()).unwrap();
    tampered["effect"]["Append"]["commit"]["record"]["version"] = serde_json::json!(2);
    let tampered =
        PreparedAuditedMutation::decode(&serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(matches!(
        store
            .submit_audited_mutation(&tampered, &receipt, caller())
            .await,
        AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
    ));
    assert!(store.load_latest().await.unwrap().is_none());
    let unaudited_tx = TxId::new();
    assert!(
        store
            .append_attested_commit(attested(
                commit(unaudited_tx, None, 1, 19),
                audit(unaudited_tx)
            ))
            .await
            .is_err(),
        "an active audit authority must reject the ordinary unaudited write API"
    );
    assert!(store.load_latest().await.unwrap().is_none());
    assert_eq!(
        applied(
            store
                .submit_audited_mutation(&prepared, &receipt, caller())
                .await
        )
        .state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(applied(
        store
            .finish_audit_operation(prepared.handle(), caller())
            .await
    )
    .terminal_recorded());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn replicated_audit_known_commit_pending_terminal_survives_retained_restart() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("retained.sqlite");
    let snapshots = dir.path().join("snapshots");
    let backend = SqliteBackend::provision_config_authority(
        retained_options(&database, topology(), 1),
        audit_key(),
    )
    .await
    .unwrap();
    let store = ConsensusConfigStore::open(topology(), backend, &snapshots, BTreeMap::new())
        .await
        .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(3, 1).unwrap())
        .await
        .unwrap();
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(4, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 10), audit(tx)),
            Duration::from_secs(300),
        )
        .unwrap();
    let intent = applied(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
    );
    let receipt = applied(
        store
            .submit_audited_mutation(&prepared, &intent, caller())
            .await,
    );
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 1 }
    );
    store.trigger_snapshot().await.unwrap();
    store.shutdown().await.unwrap();
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(
        retained_options(&database, topology(), 1),
        audit_key(),
    )
    .await
    .unwrap();
    let store = ConsensusConfigStore::open(topology(), backend, &snapshots, BTreeMap::new())
        .await
        .unwrap();
    store.initialize_cluster().await.unwrap();
    assert_eq!(
        store
            .lookup_audit_operation(prepared.handle(), caller())
            .await
            .unwrap()
            .unwrap(),
        receipt
    );
    let recovery = store.reconcile_audit_obligations(1).await.unwrap();
    assert_eq!(recovery.inspected, 1);
    assert_eq!(recovery.completed, 1);
    assert_eq!(recovery.pending, 0);
    assert_eq!(recovery.unknown, 0);
    assert!(store
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap()
        .terminal_recorded());
    assert_eq!(
        store
            .reconcile_audit_obligations(1)
            .await
            .unwrap()
            .inspected,
        0
    );
    assert_eq!(store.load_latest().await.unwrap().unwrap().record.tx_id, tx);
    store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_audit_cancellation_after_apply_and_terminal_reply_loss_are_recoverable() {
    let cluster = ThreeNodeCluster::start().await;
    let leader = cluster.leader();
    let follower = (leader + 1) % 3;
    let store = cluster.stores[follower].clone();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(5, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 11), audit(tx)),
            Duration::from_secs(300),
        )
        .unwrap();
    let intent = applied(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
    );
    let path = &cluster.paths[&(follower, leader)];
    path.pause_forward_response.store(true, Ordering::SeqCst);
    let submitting = store.clone();
    let pending = prepared.clone();
    let task = tokio::spawn(async move {
        submitting
            .submit_audited_mutation(&pending, &intent, caller())
            .await
    });
    // The peer handler has applied the proposal; no response reached the caller.
    tokio::time::timeout(
        CLUSTER_TRANSITION_TIMEOUT,
        path.forward_response_ready.notified(),
    )
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    path.pause_forward_response.store(false, Ordering::SeqCst);
    path.release_forward_response.notify_one();
    let receipt = store
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(!receipt.terminal_recorded());
    assert_eq!(
        cluster.stores[leader]
            .load_latest()
            .await
            .unwrap()
            .unwrap()
            .record
            .tx_id,
        tx
    );
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(usize::MAX);
        }
    }
    assert!(matches!(
        store
            .finish_audit_operation(prepared.handle(), caller())
            .await,
        AuditAdmission::Unknown(_)
    ));
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(0);
        }
    }
    let terminal = store
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        terminal.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(terminal.terminal_recorded());
    assert_eq!(
        applied(
            store
                .finish_audit_operation(prepared.handle(), caller())
                .await
        ),
        terminal
    );
    assert_eq!(
        store.load_latest().await.unwrap().unwrap().record.version,
        ConfigVersion::new(1)
    );
    cluster.shutdown().await;
}

#[tokio::test]
async fn replicated_audit_conflicting_base_is_rejected_atomically_and_recovery_is_fair() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open_singleton(
        &dir.path().join("config.sqlite"),
        &dir.path().join("snapshots"),
    )
    .await;
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(12, 4).unwrap())
        .await
        .unwrap();
    let waiting = store
        .prepare_audit_intent(
            &privacy(),
            &source_event(6, ManagementAuditOutcomeCode::Intent),
            ConfigVersion::new(0),
            b"standalone-pending-operation",
            Duration::from_secs(300),
        )
        .unwrap();
    applied(store.admit_audit_operation(&waiting, caller()).await);
    let tx = TxId::new();
    let first = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(7, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 12), audit(tx)),
            Duration::from_secs(300),
        )
        .unwrap();
    let other_tx = TxId::new();
    let conflicting = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(8, ManagementAuditOutcomeCode::Intent),
            attested(commit(other_tx, None, 1, 13), audit(other_tx)),
            Duration::from_secs(300),
        )
        .unwrap();
    let a = applied(store.admit_audit_operation(first.handle(), caller()).await);
    let b = applied(
        store
            .admit_audit_operation(conflicting.handle(), caller())
            .await,
    );
    assert_eq!(
        applied(store.submit_audited_mutation(&first, &a, caller()).await).state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert_eq!(
        applied(
            store
                .submit_audited_mutation(&conflicting, &b, caller())
                .await
        )
        .state(),
        AuditOperationState::Rejected
    );
    assert_eq!(store.load_latest().await.unwrap().unwrap().record.tx_id, tx);
    // The earlier live intent cannot monopolize a bounded recovery pass.
    assert_eq!(
        store
            .reconcile_audit_obligations(1)
            .await
            .unwrap()
            .completed,
        1
    );
    assert_eq!(
        store
            .reconcile_audit_obligations(1)
            .await
            .unwrap()
            .completed,
        1
    );
    let pending = store.reconcile_audit_obligations(1).await.unwrap();
    assert_eq!(pending.pending, 1);
    assert_eq!(pending.completed, 0);
    applied(store.reject_audit_operation(&waiting, caller()).await);
    assert_eq!(
        store
            .reconcile_audit_obligations(1)
            .await
            .unwrap()
            .completed,
        1
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn replicated_audit_observation_reply_loss_does_not_create_a_configuration_revision() {
    let cluster = ThreeNodeCluster::start().await;
    let follower = (cluster.leader() + 1) % 3;
    let store = &cluster.stores[follower];
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(3, 1).unwrap())
        .await
        .unwrap();
    let denied = store
        .prepare_audit_observation(
            &privacy(),
            &source_event(9, ManagementAuditOutcomeCode::Denied),
            Duration::from_secs(300),
        )
        .unwrap();
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(usize::MAX);
        }
    }
    assert!(matches!(
        store.admit_audit_operation(&denied, caller()).await,
        AuditAdmission::Unknown(_)
    ));
    let receipt = store
        .lookup_audit_operation(&denied, caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.state(),
        AuditOperationState::Observed {
            outcome: ManagementAuditOutcomeCode::Denied
        }
    );
    assert!(receipt.terminal_recorded());
    assert!(store.load_latest().await.unwrap().is_none());
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(0);
        }
    }
    assert_eq!(
        applied(store.admit_audit_operation(&denied, caller()).await),
        receipt
    );
    cluster.shutdown().await;
}

#[tokio::test]
async fn replicated_audit_fixed_expiry_rejects_delayed_config_and_recovers_an_abandoned_intent() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open_singleton(
        &dir.path().join("config.sqlite"),
        &dir.path().join("snapshots"),
    )
    .await;
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(9, 3).unwrap())
        .await
        .unwrap();
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(10, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 14), audit(tx)),
            Duration::from_secs(2),
        )
        .unwrap();
    let intent = applied(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
    );
    let abandoned = store
        .prepare_audit_intent(
            &privacy(),
            &source_event(11, ManagementAuditOutcomeCode::Intent),
            ConfigVersion::new(0),
            b"abandoned-operation",
            Duration::from_secs(2),
        )
        .unwrap();
    applied(store.admit_audit_operation(&abandoned, caller()).await);
    let absent = store
        .prepare_audit_intent(
            &privacy(),
            &source_event(12, ManagementAuditOutcomeCode::Intent),
            ConfigVersion::new(0),
            b"never-admitted-operation",
            Duration::from_secs(2),
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(
        applied(
            store
                .submit_audited_mutation(&prepared, &intent, caller())
                .await
        )
        .state(),
        AuditOperationState::Rejected
    );
    assert!(store.load_latest().await.unwrap().is_none());
    let recovery = store.reconcile_audit_obligations(3).await.unwrap();
    assert_eq!(recovery.completed, 2);
    assert_eq!(recovery.unknown, 0);
    assert_eq!(
        store
            .lookup_audit_operation(&absent, caller())
            .await
            .unwrap_err(),
        AuditAuthorityError::Expired
    );
    assert!(matches!(
        store.admit_audit_operation(&absent, caller()).await,
        AuditAdmission::Rejected(AuditAuthorityError::Expired)
    ));
    // A retry returns the closed receipt rather than re-admitting fresh work.
    assert_eq!(
        applied(
            store
                .admit_audit_operation(prepared.handle(), caller())
                .await
        )
        .state(),
        AuditOperationState::Rejected
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn replicated_audit_unfinished_terminal_protects_referenced_config_history() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open_singleton(
        &dir.path().join("config.sqlite"),
        &dir.path().join("snapshots"),
    )
    .await;
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(12, 4).unwrap())
        .await
        .unwrap();
    let mut transactions = Vec::new();
    let mut first = None;
    for version in 1..=4 {
        let tx = TxId::new();
        let parent = transactions.last().copied();
        let prepared = store
            .prepare_audited_commit(
                &privacy(),
                &source_event(20 + version as u8, ManagementAuditOutcomeCode::Intent),
                attested(commit(tx, parent, version, 15), audit(tx)),
                Duration::from_secs(300),
            )
            .unwrap();
        let receipt = applied(
            store
                .admit_audit_operation(prepared.handle(), caller())
                .await,
        );
        assert_eq!(
            applied(
                store
                    .submit_audited_mutation(&prepared, &receipt, caller())
                    .await
            )
            .state(),
            AuditOperationState::Committed { version }
        );
        if version == 1 {
            first = Some(prepared);
        } else {
            applied(
                store
                    .finish_audit_operation(prepared.handle(), caller())
                    .await,
            );
        }
        transactions.push(tx);
    }
    let decision = retention(transactions[3], 4, 3, 3, 1_048_576);
    let failure = store
        .retain_history_idempotent(
            ConfigConsensusRequestId::from_bytes([0xAF; 16]),
            decision.clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        failure.kind(),
        PersistErrorKind::ConfigHistoryProtected
    ));
    assert_eq!(
        store
            .load_since(ConfigVersion::new(0), 8)
            .await
            .unwrap()
            .len(),
        4
    );
    applied(
        store
            .finish_audit_operation(first.as_ref().unwrap().handle(), caller())
            .await,
    );
    store
        .retain_history_idempotent(ConfigConsensusRequestId::from_bytes([0xB0; 16]), decision)
        .await
        .unwrap();
    assert_eq!(
        store
            .load_since(ConfigVersion::new(2), 8)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        store
            .lookup_audit_operation(first.as_ref().unwrap().handle(), caller())
            .await
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Committed { version: 1 }
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn replicated_audit_missing_authority_row_cannot_be_reinitialized_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("config.sqlite");
    let snapshots = dir.path().join("snapshots");
    let backend = SqliteBackend::provision_config_authority(
        retained_options(&database, topology(), 1),
        audit_key(),
    )
    .await
    .unwrap();
    let store = ConsensusConfigStore::open(topology(), backend, &snapshots, BTreeMap::new())
        .await
        .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(3, 1).unwrap())
        .await
        .unwrap();
    let denied = store
        .prepare_audit_observation(
            &privacy(),
            &source_event(30, ManagementAuditOutcomeCode::Denied),
            Duration::from_secs(300),
        )
        .unwrap();
    applied(store.admit_audit_operation(&denied, caller()).await);
    store.shutdown().await.unwrap();
    drop(store);
    let sql = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(
        sql.execute("DELETE FROM config_raft_management_audit", [])
            .unwrap(),
        1
    );
    drop(sql);
    assert!(SqliteBackend::reopen_config_authority(
        retained_options(&database, topology(), 1),
        audit_key()
    )
    .await
    .is_err());
}
