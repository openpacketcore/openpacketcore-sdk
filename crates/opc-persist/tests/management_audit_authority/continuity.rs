use super::*;
use opc_persist::audit_authority::continuity::*;
use opc_persist::ConfigConsensusOpenError;

#[derive(Default)]
struct ExternalCheckpointFixture {
    value: StdMutex<Option<AuditCheckpoint>>,
    unavailable: AtomicBool,
    lose_next_ack: AtomicBool,
}

#[async_trait]
impl AuditCheckpointPort for ExternalCheckpointFixture {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        if self.unavailable.load(Ordering::Acquire) {
            return Err(AuditAuthorityError::Unavailable);
        }
        Ok(self.value.lock().unwrap().clone())
    }
    async fn compare_advance(
        &self,
        _: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        if self.unavailable.load(Ordering::Acquire) {
            return Err(AuditAuthorityError::Unavailable);
        }
        let mut current = self.value.lock().unwrap();
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        *current = Some(next);
        Ok(if self.lose_next_ack.swap(false, Ordering::AcqRel) {
            AuditCheckpointAdvance::Unknown
        } else {
            AuditCheckpointAdvance::Applied
        })
    }
}

fn keys(epochs: &[u64]) -> AuditKeyRing {
    AuditKeyRing::new(
        epochs
            .iter()
            .map(|epoch| AuditSigningKey::new(*epoch, [*epoch as u8 + 0x70; 32]).unwrap())
            .collect(),
    )
    .unwrap()
}
fn policy(external: Arc<ExternalCheckpointFixture>, epochs: &[u64]) -> AuditContinuityPolicy {
    AuditContinuityPolicy::new(keys(epochs), external, epochs[0], 1).unwrap()
}
async fn open(
    database: &std::path::Path,
    snapshots: &std::path::Path,
    external: Arc<ExternalCheckpointFixture>,
    epochs: &[u64],
    fresh: bool,
) -> Result<ConsensusConfigStore, ConfigConsensusOpenError> {
    let options = retained_options(database, topology(), 1);
    let backend = if fresh {
        SqliteBackend::provision_config_authority(options, audit_key()).await
    } else {
        SqliteBackend::reopen_config_authority(options, audit_key()).await
    }
    .unwrap();
    ConsensusConfigStore::open_with_audit_continuity(
        topology(),
        backend,
        snapshots,
        BTreeMap::new(),
        policy(external, epochs),
    )
    .await
}
fn verify_export(
    session: &AuditExportSession,
    identity: ConfigConsensusIdentity,
    epochs: &[u64],
) -> VerifiedAuditExport {
    let mut verify = AuditExportVerifier::new(
        Arc::new(keys(epochs)),
        session.manifest().clone(),
        identity,
        caller(),
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    let mut cursor = None;
    loop {
        let page = session.page(cursor.as_ref(), 1, caller()).unwrap();
        verify
            .accept(&AuditExportPage::decode(&page.encode().unwrap()).unwrap())
            .unwrap();
        cursor = page.next_cursor().cloned();
        if cursor.is_none() {
            break;
        }
    }
    verify.finish().unwrap()
}

#[tokio::test]
async fn automatic_mutation_checkpoint_never_grants_export_retention_authority() {
    let dir = tempfile::tempdir().unwrap();
    let external = Arc::new(ExternalCheckpointFixture::default());
    let store = open(
        &dir.path().join("authority.sqlite"),
        &dir.path().join("snapshots"),
        external.clone(),
        &[1, 2],
        true,
    )
    .await
    .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(94, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 7), audit(tx)),
            Duration::from_secs(3),
        )
        .unwrap();
    let intent = applied(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
    );
    let committed = applied(
        store
            .submit_audited_mutation(&prepared, &intent, caller())
            .await,
    );
    store
        .complete_required_audit_outcome(&committed, caller())
        .await
        .unwrap();
    assert_eq!(
        external.value.lock().unwrap().as_ref().unwrap().sequence(),
        3
    );
    tokio::time::sleep(Duration::from_millis(3100)).await;
    assert!(
        store.retain_audit_history_through(3).await.is_err(),
        "a mutation checkpoint is not proof of complete export"
    );
    assert_eq!(store.load_latest().await.unwrap().unwrap().record.tx_id, tx);
    let export = store
        .freeze_audit_export(caller(), 0, Duration::from_secs(60))
        .await
        .unwrap();
    let verified = verify_export(&export, topology().identity(), &[1, 2]);
    store
        .acknowledge_audit_export(&verified, caller())
        .await
        .unwrap();
    assert_eq!(
        external.value.lock().unwrap().as_ref().unwrap().sequence(),
        3,
        "equal-tail export acknowledgement cannot overwrite the external checkpoint"
    );
    store.retain_audit_history_through(3).await.unwrap();
    assert!(
        matches!(
            store
                .freeze_audit_export(caller(), 0, Duration::from_secs(60))
                .await,
            Err(AuditAuthorityError::Full)
        ),
        "frozen export still owns its one-slot capacity"
    );
    drop(export);
    assert!(matches!(
        store
            .freeze_audit_export(caller(), 0, Duration::from_secs(60))
            .await,
        Err(AuditAuthorityError::Pruned)
    ));
    assert_eq!(store.load_latest().await.unwrap().unwrap().record.tx_id, tx);
    store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_and_export_remain_one_history_across_ack_loss_and_leader_change() {
    let external = Arc::new(ExternalCheckpointFixture::default());
    let factory = || policy(external.clone(), &[1, 2]);
    let cluster = ThreeNodeCluster::build_with_audit_continuity(
        [[0x55; 32]; 3],
        FixtureStorage::Legacy,
        Some(&factory),
    )
    .await;
    let (a, b, c) = tokio::join!(
        cluster.stores[0].initialize_cluster(),
        cluster.stores[1].initialize_cluster(),
        cluster.stores[2].initialize_cluster()
    );
    a.unwrap();
    b.unwrap();
    c.unwrap();
    assert!(cluster.stores[0].probe_durable_readiness().await.is_err());
    cluster.stores[0]
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(12, 4).unwrap())
        .await
        .unwrap();
    cluster.wait_ready().await;
    let leader = cluster.leader();
    let follower = (leader + 1) % 3;
    let transition = cluster.stores[follower]
        .prepare_audit_key_transition(2)
        .await
        .unwrap();
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(usize::MAX);
        }
    }
    assert!(cluster.stores[follower]
        .activate_audit_key_transition(&transition)
        .await
        .is_err());
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(0);
        }
    }
    cluster.stores[follower]
        .activate_audit_key_transition(&transition)
        .await
        .unwrap();
    let observed = cluster.stores[follower]
        .prepare_audit_observation(
            &privacy(),
            &source_event(71, ManagementAuditOutcomeCode::Denied),
            Duration::from_secs(3),
        )
        .unwrap();
    applied(
        cluster.stores[follower]
            .admit_audit_operation(&observed, caller())
            .await,
    );
    let identity = cluster.identity;
    let export = cluster.stores[follower]
        .freeze_audit_export(caller(), 0, Duration::from_secs(60))
        .await
        .unwrap();
    let verified = verify_export(&export, identity, &[1, 2]);
    external.lose_next_ack.store(true, Ordering::Release);
    cluster.stores[follower]
        .acknowledge_audit_export(&verified, caller())
        .await
        .unwrap();
    assert_eq!(
        external.value.lock().unwrap().as_ref().unwrap().sequence(),
        2
    );
    drop(export);
    tokio::time::sleep(Duration::from_millis(3100)).await;
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(usize::MAX);
        }
    }
    assert!(cluster.stores[follower]
        .retain_audit_history_through(2)
        .await
        .is_err());
    for target in 0..3 {
        if target != follower {
            cluster.paths[&(follower, target)].drop_forward_responses(0);
        }
    }
    // The apply may already have removed the prefix. Exact retry reconciles it
    // without removing a later entry or requiring the lost transport response.
    cluster.stores[follower]
        .retain_audit_history_through(2)
        .await
        .unwrap();
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
    let export = cluster.stores[follower]
        .freeze_audit_export(caller(), 2, Duration::from_secs(60))
        .await
        .unwrap();
    verify_export(&export, identity, &[1, 2]);
    assert!(
        cluster.stores[follower]
            .load_latest()
            .await
            .unwrap()
            .is_none(),
        "standalone audit never changes config version"
    );
    cluster.heal(leader);
    cluster.wait_ready().await;
    cluster.shutdown().await;
}

#[tokio::test]
async fn checkpoint_outage_and_rollback_block_export_and_admission_without_reset() {
    let dir = tempfile::tempdir().unwrap();
    let external = Arc::new(ExternalCheckpointFixture::default());
    let database = dir.path().join("authority.sqlite");
    let snapshots = dir.path().join("snapshots");
    let store = open(&database, &snapshots, external.clone(), &[1, 2], true)
        .await
        .unwrap();
    store.initialize_cluster().await.unwrap();
    let tx = TxId::new();
    assert!(
        store
            .append_attested_commit(attested(commit(tx, None, 1, 7), audit(tx)))
            .await
            .is_err(),
        "the required profile forbids unaudited writes even before ledger provisioning"
    );
    assert!(store.load_latest().await.unwrap().is_none());
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let genesis = external.value.lock().unwrap().clone();
    let observation = store
        .prepare_audit_observation(
            &privacy(),
            &source_event(72, ManagementAuditOutcomeCode::Denied),
            Duration::from_secs(30),
        )
        .unwrap();
    applied(store.admit_audit_operation(&observation, caller()).await);
    let export = store
        .freeze_audit_export(caller(), 0, Duration::from_secs(60))
        .await
        .unwrap();
    let verified = verify_export(&export, topology().identity(), &[1, 2]);
    assert!(matches!(
        store
            .freeze_audit_export(caller(), 0, Duration::from_secs(60))
            .await,
        Err(AuditAuthorityError::Full)
    ));
    external.unavailable.store(true, Ordering::Release);
    assert!(store.probe_durable_readiness().await.is_err());
    assert!(store
        .acknowledge_audit_export(&verified, caller())
        .await
        .is_err());
    let next = store
        .prepare_audit_observation(
            &privacy(),
            &source_event(73, ManagementAuditOutcomeCode::Denied),
            Duration::from_secs(30),
        )
        .unwrap();
    assert!(matches!(
        store.admit_audit_operation(&next, caller()).await,
        AuditAdmission::Rejected(AuditAuthorityError::Unavailable)
    ));
    drop(export);
    assert!(matches!(
        store
            .freeze_audit_export(caller(), 0, Duration::from_secs(60))
            .await,
        Err(AuditAuthorityError::Unavailable)
    ));
    external.unavailable.store(false, Ordering::Release);
    store
        .acknowledge_audit_export(&verified, caller())
        .await
        .unwrap();
    let latest = external.value.lock().unwrap().clone();
    *external.value.lock().unwrap() = genesis;
    assert!(matches!(
        store
            .freeze_audit_export(caller(), 0, Duration::from_secs(60))
            .await,
        Err(AuditAuthorityError::RollbackDetected)
    ));
    *external.value.lock().unwrap() = latest;
    assert!(store
        .lookup_audit_operation(&next, caller())
        .await
        .unwrap()
        .is_none());
    store.shutdown().await.unwrap();
    drop(store);
    external.unavailable.store(true, Ordering::Release);
    assert!(matches!(
        open(&database, &snapshots, external.clone(), &[1, 2], false).await,
        Err(ConfigConsensusOpenError::AuditContinuityUnavailable)
    ));
    external.unavailable.store(false, Ordering::Release);
    let restored = open(&database, &snapshots, external, &[1, 2], false)
        .await
        .unwrap();
    restored.initialize_cluster().await.unwrap();
    restored.probe_durable_readiness().await.unwrap();
    restored.shutdown().await.unwrap();
}

#[tokio::test]
async fn acknowledged_expired_prefix_allows_key_retirement_but_never_handle_replay() {
    let dir = tempfile::tempdir().unwrap();
    let external = Arc::new(ExternalCheckpointFixture::default());
    let database = dir.path().join("authority.sqlite");
    let snapshots = dir.path().join("snapshots");
    let store = open(&database, &snapshots, external.clone(), &[1, 2], true)
        .await
        .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let observation = store
        .prepare_audit_observation(
            &privacy(),
            &source_event(74, ManagementAuditOutcomeCode::Denied),
            Duration::from_secs(2),
        )
        .unwrap();
    applied(store.admit_audit_operation(&observation, caller()).await);
    let transition = store.prepare_audit_key_transition(2).await.unwrap();
    store
        .activate_audit_key_transition(&transition)
        .await
        .unwrap();
    let export = store
        .freeze_audit_export(caller(), 0, Duration::from_secs(60))
        .await
        .unwrap();
    let verified = verify_export(&export, topology().identity(), &[1, 2]);
    assert!(store.retain_audit_history_through(2).await.is_err());
    store
        .acknowledge_audit_export(&verified, caller())
        .await
        .unwrap();
    assert!(matches!(
        store.retain_audit_history_through(2).await,
        Err(AuditAuthorityError::Full)
    ));
    tokio::time::sleep(Duration::from_millis(2100)).await;
    store.retain_audit_history_through(2).await.unwrap();
    verify_export(&export, topology().identity(), &[1, 2]); // pruning did not alter a frozen session
    drop(export);
    assert!(matches!(
        store
            .freeze_audit_export(caller(), 0, Duration::from_secs(60))
            .await,
        Err(AuditAuthorityError::Pruned)
    ));
    assert!(matches!(
        store
            .freeze_audit_export(caller(), 3, Duration::from_secs(60))
            .await,
        Err(AuditAuthorityError::InvalidInput)
    ));
    assert_eq!(
        store
            .lookup_audit_operation(&observation, caller())
            .await
            .unwrap_err(),
        AuditAuthorityError::Expired
    );
    store.shutdown().await.unwrap();
    drop(store);
    let store = open(&database, &snapshots, external, &[2], false)
        .await
        .unwrap();
    store.initialize_cluster().await.unwrap();
    store.probe_durable_readiness().await.unwrap();
    let export = store
        .freeze_audit_export(caller(), 2, Duration::from_secs(60))
        .await
        .unwrap();
    verify_export(&export, topology().identity(), &[2]);
    assert!(matches!(
        store.admit_audit_operation(&observation, caller()).await,
        AuditAdmission::Rejected(AuditAuthorityError::Expired)
    ));
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn backend_clone_cannot_omit_required_external_checkpoint_authority() {
    let dir = tempfile::tempdir().unwrap();
    let external = Arc::new(ExternalCheckpointFixture::default());
    let database = dir.path().join("authority.sqlite");
    let snapshots = dir.path().join("snapshots");
    let backend = SqliteBackend::provision_config_authority(
        retained_options(&database, topology(), 1),
        audit_key(),
    )
    .await
    .unwrap();
    let retained = backend.clone();
    let store = ConsensusConfigStore::open_with_audit_continuity(
        topology(),
        backend,
        &snapshots,
        BTreeMap::new(),
        policy(external.clone(), &[1, 2]),
    )
    .await
    .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    store.shutdown().await.unwrap();
    drop(store);
    external.unavailable.store(true, Ordering::Release);
    let reopened =
        ConsensusConfigStore::open(topology(), retained, &snapshots, BTreeMap::new()).await;
    let refused = matches!(
        &reopened,
        Err(ConfigConsensusOpenError::AuditContinuityUnavailable)
    );
    if let Ok(unprotected) = reopened {
        unprotected.shutdown().await.unwrap();
    }
    assert!(
        refused,
        "a retained keyring cannot replace the external rollback authority"
    );
}

#[tokio::test]
async fn coherent_database_rollback_and_missing_keys_are_refused_before_engine_start() {
    let dir = tempfile::tempdir().unwrap();
    let external = Arc::new(ExternalCheckpointFixture::default());
    let database = dir.path().join("authority.sqlite");
    let snapshots = dir.path().join("snapshots");
    let store = open(&database, &snapshots, external.clone(), &[1, 2], true)
        .await
        .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let saved = dir.path().join("coherent-old.sqlite");
    {
        let source = rusqlite::Connection::open(&database).unwrap();
        let mut destination = rusqlite::Connection::open(&saved).unwrap();
        rusqlite::backup::Backup::new(&source, &mut destination)
            .unwrap()
            .run_to_completion(64, Duration::from_millis(1), None)
            .unwrap();
    }
    let transition = store.prepare_audit_key_transition(2).await.unwrap();
    store
        .activate_audit_key_transition(&transition)
        .await
        .unwrap();
    let export = store
        .freeze_audit_export(caller(), 0, Duration::from_secs(60))
        .await
        .unwrap();
    let verified = verify_export(&export, topology().identity(), &[1, 2]);
    store
        .acknowledge_audit_export(&verified, caller())
        .await
        .unwrap();
    drop(export);
    store.shutdown().await.unwrap();
    drop(store);
    assert!(
        matches!(
            open(&database, &snapshots, external.clone(), &[2], false).await,
            Err(ConfigConsensusOpenError::AuditContinuityUnavailable)
        ),
        "old retained rows still need old keys"
    );
    let backend = SqliteBackend::reopen_config_authority(
        retained_options(&database, topology(), 1),
        audit_key(),
    )
    .await
    .unwrap();
    assert!(
        matches!(
            ConsensusConfigStore::open(topology(), backend, &snapshots, BTreeMap::new()).await,
            Err(ConfigConsensusOpenError::AuditContinuityUnavailable)
        ),
        "ordinary open is not a downgrade"
    );
    assert!(
        !database.with_extension("sqlite-wal").exists(),
        "all database owners are closed"
    );
    std::fs::copy(saved, &database).unwrap();
    assert!(
        matches!(
            open(&database, &snapshots, external, &[1, 2], false).await,
            Err(ConfigConsensusOpenError::AuditContinuityUnavailable)
        ),
        "coherent old database cannot erase the external high-water mark"
    );
}

#[tokio::test]
async fn checkpointed_intent_with_retained_commit_reopens_and_settles() {
    let dir = tempfile::tempdir().unwrap();
    let external = Arc::new(ExternalCheckpointFixture::default());
    let database = dir.path().join("authority.sqlite");
    let snapshots = dir.path().join("snapshots");
    let store = open(&database, &snapshots, external.clone(), &[1, 2], true)
        .await
        .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(93, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 7), audit(tx)),
            Duration::from_secs(60),
        )
        .unwrap();
    let intent = applied(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
    );
    let export = store
        .freeze_audit_export(caller(), 0, Duration::from_secs(60))
        .await
        .unwrap();
    let verified = verify_export(&export, topology().identity(), &[1, 2]);
    store
        .acknowledge_audit_export(&verified, caller())
        .await
        .unwrap();
    drop(export);
    let committed = applied(
        store
            .submit_audited_mutation(&prepared, &intent, caller())
            .await,
    );
    assert_eq!(
        committed.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(!committed.terminal_recorded());
    assert_eq!(
        external.value.lock().unwrap().as_ref().unwrap().sequence(),
        1
    );
    store.shutdown().await.unwrap();
    drop(store);

    // The same prefix checkpoint accompanies a retained committed outcome here.
    // Reopen must recover that exact outcome, not refuse every pending terminal.
    let reopened = open(&database, &snapshots, external, &[1, 2], false)
        .await
        .unwrap();
    reopened.initialize_cluster().await.unwrap();
    reopened.probe_durable_readiness().await.unwrap();
    assert_eq!(
        reopened.load_latest().await.unwrap().unwrap().record.tx_id,
        tx
    );
    let progress = reopened.reconcile_audit_obligations(2).await.unwrap();
    assert_eq!(
        (progress.completed, progress.pending, progress.unknown),
        (1, 0, 0)
    );
    let settled = reopened
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(settled.state(), committed.state());
    assert!(settled.terminal_recorded());
    assert_eq!(
        reopened
            .reconcile_audit_obligations(2)
            .await
            .unwrap()
            .inspected,
        0
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn checkpointed_intent_cannot_become_rejected_after_committed_suffix_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let external = Arc::new(ExternalCheckpointFixture::default());
    let database = dir.path().join("authority.sqlite");
    let snapshots = dir.path().join("snapshots");
    let store = open(&database, &snapshots, external.clone(), &[1, 2], true)
        .await
        .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(92, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 7), audit(tx)),
            Duration::from_secs(3),
        )
        .unwrap();
    let intent = applied(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
    );
    assert_eq!(intent.state(), AuditOperationState::Intent);

    // Exercise the strongest existing public composition: export, verify and
    // externally checkpoint this exact Intent before submitting its mutation.
    let export = store
        .freeze_audit_export(caller(), 0, Duration::from_secs(60))
        .await
        .unwrap();
    let verified = verify_export(&export, topology().identity(), &[1, 2]);
    store
        .acknowledge_audit_export(&verified, caller())
        .await
        .unwrap();
    drop(export);
    assert_eq!(
        external.value.lock().unwrap().as_ref().unwrap().sequence(),
        1
    );
    let saved = dir.path().join("checkpointed-intent.sqlite");
    {
        let source = rusqlite::Connection::open(&database).unwrap();
        let mut destination = rusqlite::Connection::open(&saved).unwrap();
        rusqlite::backup::Backup::new(&source, &mut destination)
            .unwrap()
            .run_to_completion(64, Duration::from_millis(1), None)
            .unwrap();
    }
    let committed = applied(
        store
            .submit_audited_mutation(&prepared, &intent, caller())
            .await,
    );
    assert_eq!(
        committed.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert_eq!(store.load_latest().await.unwrap().unwrap().record.tx_id, tx);
    assert!(!committed.terminal_recorded());
    assert_eq!(
        external.value.lock().unwrap().as_ref().unwrap().sequence(),
        1
    );
    store.shutdown().await.unwrap();
    drop(store);
    assert!(
        !database.with_extension("sqlite-wal").exists(),
        "all database owners are closed before this synthetic restore"
    );
    std::fs::copy(saved, &database).unwrap();

    // The external authority is unchanged and still reserves the earlier
    // Intent. Restoring its exact prefix is not proof of no configuration effect.
    let restored = match open(&database, &snapshots, external.clone(), &[1, 2], false).await {
        Ok(store) => store,
        Err(ConfigConsensusOpenError::AuditContinuityUnavailable) => return,
        Err(error) => panic!("unexpected retained-open error: {error:?}"),
    };
    restored.initialize_cluster().await.unwrap();
    if restored.probe_durable_readiness().await.is_err() {
        restored.shutdown().await.unwrap();
        return;
    }
    assert!(restored.load_latest().await.unwrap().is_none());
    let recovered = restored
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.state(), AuditOperationState::Intent);
    tokio::time::sleep(Duration::from_millis(3100)).await;
    let progress = restored.reconcile_audit_obligations(2).await.unwrap();
    let recovered = restored
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    let export = restored
        .freeze_audit_export(caller(), 0, Duration::from_secs(60))
        .await
        .unwrap();
    let verified = verify_export(&export, topology().identity(), &[1, 2]);
    restored
        .acknowledge_audit_export(&verified, caller())
        .await
        .unwrap();
    let checkpoint_sequence = external.value.lock().unwrap().as_ref().unwrap().sequence();
    restored.shutdown().await.unwrap();

    assert_ne!(
        recovered.state(),
        AuditOperationState::Rejected,
        "a checkpointed reservation cannot erase a known committed suffix: original_version=1, restored_version=0, terminal_recorded={}, completed={}, external_sequence={checkpoint_sequence}",
        recovered.terminal_recorded(),
        progress.completed
    );
}

#[tokio::test]
async fn target_recovery_refuses_legacy_profile_without_reinterpreting_running_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let external = Arc::new(ExternalCheckpointFixture::default());
    let store = open(
        &directory.path().join("authority.sqlite"),
        &directory.path().join("snapshots"),
        external.clone(),
        &[1, 2],
        true,
    )
    .await
    .unwrap();
    store.initialize_cluster().await.unwrap();
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let tx = TxId::new();
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &source_event(163, ManagementAuditOutcomeCode::Intent),
            attested(commit(tx, None, 1, 7), audit(tx)),
            Duration::from_secs(60),
        )
        .unwrap();
    let intent = applied(
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await,
    );
    let committed = applied(
        store
            .submit_audited_mutation(&prepared, &intent, caller())
            .await,
    );
    store
        .complete_required_audit_outcome(&committed, caller())
        .await
        .unwrap();
    let checkpoint = external.value.lock().unwrap().clone();
    assert_eq!(
        store
            .recover_netconf_target(prepared.handle(), caller())
            .await,
        Err(AuditAuthorityError::Unavailable)
    );
    assert_eq!(external.value.lock().unwrap().clone(), checkpoint);
    let after = store
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.state(), committed.state());
    assert!(after.terminal_recorded());
    assert_eq!(store.load_latest().await.unwrap().unwrap().record.tx_id, tx);
    store.shutdown().await.unwrap();
}
