//! Synthetic #796/#797 integration: actual ConfigBus, encryption, and three voters.
use super::*;
use opc_persist::audit_authority::{AuditLedgerLimits, AuditPrivacyKey};

mod checkpoint;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_bus_commit_has_a_recoverable_consensus_audit_outcome() {
    let cluster = ProjectionCluster::start().await;
    let authority = Arc::clone(&cluster.stores[cluster.leader()]);
    let privacy = Arc::new(AuditPrivacyKey::new([0x71; 32]).expect("projection key"));
    authority
        .initialize_audit_authority(
            privacy.as_ref(),
            AuditLedgerLimits::new(6, 2).expect("bounds"),
        )
        .await
        .expect("ledger");
    let source = Arc::new(EncryptingManagedDatastore::new(
        Arc::new(
            RaftManagedDatastore::<TestConfig>::new_audited_local_authority(
                Arc::clone(&authority),
                opc_config_bus_consensus::ConfigAuditPolicy::new(
                    privacy.clone(),
                    Duration::from_secs(60),
                )
                .expect("audit policy"),
            ),
        ),
        provider(),
    ));
    source
        .append_commit(projection_record(TxId::new(), None, 1, "revision-1"))
        .await
        .expect("bootstrap must enter the required audit authority");
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "initial".into(),
        },
        Arc::clone(&source),
    )
    .await
    .expect("encrypted bus");
    let request = CommitRequest::commit(
        RequestId::new(),
        principal(),
        TransportType::Gnmi,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        TestConfig {
            name: "revision-2".into(),
        },
        Vec::new(),
        Instant::now() + Duration::from_secs(5),
    )
    .with_base_version(ConfigVersion::new(1))
    .with_idempotency_key(
        opc_config_model::IdempotencyKey::new("audit-config-request").expect("key"),
    );
    let result = bus
        .submit(request.clone())
        .await
        .expect("known configuration commit");
    assert_eq!(result.new_version, Some(ConfigVersion::new(2)));
    assert_eq!(
        source
            .load_committed_latest()
            .await
            .expect("read")
            .expect("record")
            .tx_id,
        result.tx_id
    );
    // The caller has no retained handle and never submitted a terminal event.
    // Recovery discovers the committed obligations under the same authority.
    let progress = authority
        .reconcile_audit_obligations(2)
        .await
        .expect("recovery");
    assert_eq!(progress.completed, 2);
    assert_eq!(progress.pending, 0);
    assert_eq!(progress.unknown, 0);
    assert_eq!(
        authority
            .reconcile_audit_obligations(2)
            .await
            .expect("idempotent recovery")
            .inspected,
        0
    );
    let mut retry = request;
    retry.deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(
        bus.submit(retry).await.expect("reply-loss recovery"),
        result
    );
    assert_eq!(
        authority
            .reconcile_audit_obligations(2)
            .await
            .expect("no duplicate audit")
            .inspected,
        0
    );
    let error = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                principal(),
                TransportType::NetconfTls,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                TestConfig {
                    name: "must-not-apply".into(),
                },
                Vec::new(),
                Instant::now() + Duration::from_secs(5),
            )
            .with_base_version(ConfigVersion::new(2)),
        )
        .await
        .expect_err("full audit authority refuses mutation");
    assert_ne!(
        error.code,
        opc_config_model::CommitErrorCode::OutcomeUnknown
    );
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(
        source
            .load_committed_latest()
            .await
            .expect("read")
            .expect("record")
            .tx_id,
        result.tx_id
    );
    cluster.shutdown().await;
}

fn audited_source(
    store: Arc<ConsensusConfigStore>,
    privacy: Arc<AuditPrivacyKey>,
) -> Arc<EncryptingManagedDatastore<TestConfig, MemoryKeyProvider, RaftManagedDatastore<TestConfig>>>
{
    Arc::new(EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::new_audited_local_authority(
            store,
            opc_config_bus_consensus::ConfigAuditPolicy::new(privacy, Duration::from_secs(60))
                .expect("audit policy"),
        )),
        provider(),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_audit_rejects_wrong_projection_missing_context_and_follower_writes() {
    let cluster = ProjectionCluster::start().await;
    let leader = cluster.leader();
    let authority = Arc::clone(&cluster.stores[leader]);
    let privacy = Arc::new(AuditPrivacyKey::new([0x71; 32]).expect("key"));
    authority
        .initialize_audit_authority(
            privacy.as_ref(),
            AuditLedgerLimits::new(9, 3).expect("bounds"),
        )
        .await
        .expect("ledger");
    let wrong = audited_source(
        Arc::clone(&authority),
        Arc::new(AuditPrivacyKey::new([0x72; 32]).expect("wrong key")),
    );
    wrong
        .append_commit(projection_record(TxId::new(), None, 1, "wrong-projection"))
        .await
        .expect_err("projection mismatch cannot mutate configuration");
    let current = audited_source(Arc::clone(&authority), Arc::clone(&privacy));
    let mut missing = projection_record(TxId::new(), None, 1, "missing-context");
    missing.source = RequestSource::Northbound;
    let failure = current
        .append_commit(missing)
        .await
        .expect_err("Northbound context cannot be inferred");
    assert_eq!(failure.code, StoreErrorCode::Internal);
    let follower = audited_source(Arc::clone(&cluster.stores[(leader + 1) % 3]), privacy);
    follower
        .append_commit(projection_record(
            TxId::new(),
            None,
            1,
            "follower-must-not-forward",
        ))
        .await
        .expect_err("local-only audit admission cannot forward");
    assert!(authority
        .load_latest()
        .await
        .expect("quorum read")
        .is_none());
    assert_eq!(
        authority
            .reconcile_audit_obligations(3)
            .await
            .expect("no side effects")
            .inspected,
        0
    );
    current
        .append_commit(projection_record(
            TxId::new(),
            None,
            1,
            "valid-leader-write",
        ))
        .await
        .expect("healthy leader still has capacity");
    assert_eq!(
        authority
            .load_latest()
            .await
            .expect("read")
            .expect("head")
            .record
            .version,
        ConfigVersion::new(1)
    );
    assert_eq!(
        authority
            .reconcile_audit_obligations(3)
            .await
            .expect("obligation")
            .completed,
        1
    );
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirmed_commit_confirmation_and_cancellation_use_audited_atomic_successors() {
    let cluster = ProjectionCluster::start().await;
    let authority = Arc::clone(&cluster.stores[cluster.leader()]);
    let privacy = Arc::new(AuditPrivacyKey::new([0x71; 32]).expect("key"));
    authority
        .initialize_audit_authority(
            privacy.as_ref(),
            AuditLedgerLimits::new(30, 10).expect("bounds"),
        )
        .await
        .expect("ledger");
    let source = audited_source(Arc::clone(&authority), privacy);
    source
        .append_commit(projection_record(TxId::new(), None, 1, "revision-1"))
        .await
        .expect("bootstrap");
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "initial".into(),
        },
        Arc::clone(&source),
    )
    .await
    .expect("bus");
    let begin = |base, value: &str| {
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::NetconfTls,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: Duration::from_secs(60),
            },
            Instant::now() + Duration::from_secs(5),
            Some(TestConfig { name: value.into() }),
            Vec::new(),
        )
        .with_base_version(ConfigVersion::new(base))
    };
    bus.submit(begin(1, "confirmed-value"))
        .await
        .expect("pending");
    assert!(source
        .load_committed_latest()
        .await
        .expect("read")
        .expect("head")
        .confirmed_deadline
        .is_some());
    let confirm = CommitRequest::new(
        RequestId::new(),
        principal(),
        TransportType::Gnmi,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        CommitMode::Commit,
        Instant::now() + Duration::from_secs(5),
        None,
        Vec::new(),
    )
    .with_base_version(ConfigVersion::new(2));
    let confirmed = bus
        .submit(confirm)
        .await
        .expect("confirm exact pending commit");
    assert_eq!(confirmed.new_version, Some(ConfigVersion::new(3)));
    assert_eq!(bus.current_snapshot().config.name, "confirmed-value");
    assert!(source
        .load_committed_latest()
        .await
        .expect("read")
        .expect("head")
        .confirmed_deadline
        .is_none());
    bus.submit(begin(3, "cancelled-value"))
        .await
        .expect("second pending");
    let cancel = CommitRequest::cancel_confirmed(
        RequestId::new(),
        principal(),
        TransportType::NetconfSsh,
        RequestSource::Northbound,
        Vec::new(),
        Instant::now() + Duration::from_secs(5),
    )
    .with_base_version(ConfigVersion::new(4));
    let cancelled = bus
        .submit(cancel)
        .await
        .expect("cancel exact pending commit");
    assert_eq!(cancelled.new_version, Some(ConfigVersion::new(5)));
    assert_eq!(bus.current_snapshot().config.name, "confirmed-value");
    let retained = source
        .load_committed_latest()
        .await
        .expect("read")
        .expect("head");
    assert_eq!(retained.tx_id, cancelled.tx_id);
    assert!(retained.confirmed_deadline.is_none());
    let progress = authority
        .reconcile_audit_obligations(10)
        .await
        .expect("all outcomes retained");
    assert_eq!(progress.completed, 5);
    assert_eq!((progress.pending, progress.unknown), (0, 0));
    cluster.shutdown().await;
}
