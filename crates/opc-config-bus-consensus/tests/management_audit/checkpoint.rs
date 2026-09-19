use super::*;
use opc_persist::audit_authority::continuity::{
    AuditCheckpoint, AuditCheckpointAdvance, AuditCheckpointPort, AuditExportVerifier,
    AuditKeyRing, AuditSigningKey,
};
use opc_persist::audit_authority::{AuditAuthorityError, AuditCaller};
use std::sync::atomic::{AtomicU64, AtomicUsize};

// Synthetic separately owned monotonic authority, never a production provider.
#[derive(Default)]
pub(super) struct CheckpointFixture {
    value: std::sync::Mutex<Option<AuditCheckpoint>>,
    unavailable: AtomicBool,
    advance_unavailable: AtomicBool,
    advance_attempts: AtomicUsize,
    refuse_from_sequence: AtomicU64,
    lose_next_ack: AtomicBool,
}

#[async_trait::async_trait]
impl AuditCheckpointPort for CheckpointFixture {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        if self.unavailable.load(Ordering::Acquire) {
            return Err(AuditAuthorityError::Unavailable);
        }
        Ok(self.value.lock().expect("checkpoint lock").clone())
    }

    async fn compare_advance(
        &self,
        _: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        self.advance_attempts.fetch_add(1, Ordering::AcqRel);
        if self.unavailable.load(Ordering::Acquire)
            || self.advance_unavailable.load(Ordering::Acquire)
            || (self.refuse_from_sequence.load(Ordering::Acquire) != 0
                && next.sequence() >= self.refuse_from_sequence.load(Ordering::Acquire))
        {
            return Err(AuditAuthorityError::Unavailable);
        }
        let mut current = self.value.lock().expect("checkpoint lock");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_bus_required_continuity_refuses_checkpoint_outage_before_config_effect() {
    let checkpoints = Arc::new(CheckpointFixture::default());
    let cluster = ProjectionCluster::start_with_continuity(Some(checkpoints.clone())).await;
    let authority = Arc::clone(&cluster.stores[cluster.leader()]);
    let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).expect("privacy key"));
    authority
        .initialize_audit_authority(
            privacy.as_ref(),
            AuditLedgerLimits::new(9, 3).expect("bounds"),
        )
        .await
        .expect("initialize required checkpoint profile");
    cluster.wait_ready().await;
    let source = audited_source(Arc::clone(&authority), privacy);
    source
        .append_commit(projection_record(TxId::new(), None, 1, "revision-1"))
        .await
        .expect("audited bootstrap");
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "initial".into(),
        },
        Arc::clone(&source),
    )
    .await
    .expect("bus");
    checkpoints.unavailable.store(true, Ordering::Release);
    let request = || {
        CommitRequest::commit(
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
    };
    let refused = bus
        .submit(request())
        .await
        .expect_err("checkpoint unavailable");
    assert_ne!(
        refused.code,
        opc_config_model::CommitErrorCode::OutcomeUnknown
    );
    assert_eq!(bus.version(), ConfigVersion::new(1));
    let stored = source
        .load_committed_latest()
        .await
        .expect("local read")
        .expect("head");
    assert_eq!(stored.version, ConfigVersion::new(1));
    assert_eq!(stored.config.name, "revision-1");

    checkpoints.unavailable.store(false, Ordering::Release);
    checkpoints.lose_next_ack.store(true, Ordering::Release);
    let result = bus.submit(request()).await.expect("checkpoint restored");
    assert_eq!(result.new_version, Some(ConfigVersion::new(2)));
    assert_eq!(
        source
            .load_committed_latest()
            .await
            .expect("read")
            .expect("head")
            .tx_id,
        result.tx_id
    );
    let progress = authority
        .reconcile_audit_obligations(3)
        .await
        .expect("recovery");
    assert_eq!(progress.completed, 0);
    assert_eq!(checkpoints.sequence(), 6);
    assert_eq!((progress.pending, progress.unknown), (0, 0));
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_terminal_checkpoint_debt_fences_new_writes_until_exact_recovery() {
    let checkpoints = Arc::new(CheckpointFixture::default());
    let cluster = ProjectionCluster::start_with_continuity(Some(checkpoints.clone())).await;
    let authority = Arc::clone(&cluster.stores[cluster.leader()]);
    let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).expect("privacy key"));
    authority
        .initialize_audit_authority(privacy.as_ref(), AuditLedgerLimits::new(12, 4).unwrap())
        .await
        .unwrap();
    cluster.wait_ready().await;
    let source = audited_source(Arc::clone(&authority), privacy);
    source
        .append_commit(projection_record(TxId::new(), None, 1, "revision-1"))
        .await
        .unwrap();
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "initial".into(),
        },
        Arc::clone(&source),
    )
    .await
    .unwrap();
    assert_eq!(checkpoints.sequence(), 3);

    // Intent 4 can be independently reserved, but terminal 6 cannot. The
    // authoritative commit must remain truthful, with no new mutation admitted.
    checkpoints.refuse_from_sequence.store(6, Ordering::Release);
    let committed = bus.submit(next_checkpointed_request()).await.unwrap();
    assert_eq!(committed.new_version, Some(ConfigVersion::new(2)));
    assert_eq!(checkpoints.sequence(), 4);
    let next = || {
        CommitRequest::commit(
            RequestId::new(),
            principal(),
            TransportType::Gnmi,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig {
                name: "revision-3".into(),
            },
            Vec::new(),
            Instant::now() + Duration::from_secs(5),
        )
        .with_base_version(ConfigVersion::new(2))
    };
    let before = checkpoints.advance_attempts.load(Ordering::Acquire);
    assert!(bus.submit(next()).await.is_err());
    assert_eq!(checkpoints.advance_attempts.load(Ordering::Acquire), before);
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(
        source.load_committed_latest().await.unwrap().unwrap().tx_id,
        committed.tx_id
    );
    let pending = authority.reconcile_audit_obligations(4).await.unwrap();
    assert_eq!(
        (pending.completed, pending.pending, pending.unknown),
        (0, 0, 1)
    );

    checkpoints.refuse_from_sequence.store(0, Ordering::Release);
    let recovered = authority.reconcile_audit_obligations(4).await.unwrap();
    assert_eq!(
        (recovered.completed, recovered.pending, recovered.unknown),
        (1, 0, 0)
    );
    assert_eq!(checkpoints.sequence(), 6);
    assert_eq!(
        authority
            .reconcile_audit_obligations(4)
            .await
            .unwrap()
            .inspected,
        0
    );
    assert_eq!(
        source.load_committed_latest().await.unwrap().unwrap().tx_id,
        committed.tx_id
    );
    let successor = bus.submit(next()).await.unwrap();
    assert_eq!(successor.new_version, Some(ConfigVersion::new(3)));
    assert_eq!(checkpoints.sequence(), 9);
    cluster.shutdown().await;
}

impl CheckpointFixture {
    fn sequence(&self) -> u64 {
        self.value
            .lock()
            .expect("checkpoint lock")
            .as_ref()
            .expect("provisioned checkpoint")
            .sequence()
    }
}

async fn acknowledge_current_prefix(
    authority: &ConsensusConfigStore,
    privacy: &AuditPrivacyKey,
) -> Result<(), AuditAuthorityError> {
    let principal = principal();
    let recipient = AuditCaller::project(
        privacy,
        principal.tenant.as_str(),
        &opc_mgmt_audit::principal_descriptor(&principal),
    )?;
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("config-bus-projection-tests").expect("cluster ID"),
        ConfigConsensusConfigurationId::from_bytes([0x70; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let export = authority
        .freeze_audit_export(recipient, 0, Duration::from_secs(60))
        .await?;
    let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x91; 32])?])?;
    let mut verifier = AuditExportVerifier::new(
        Arc::new(keys),
        export.manifest().clone(),
        identity,
        recipient,
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )?;
    let mut cursor = None;
    loop {
        let page = export.page(cursor.as_ref(), 256, recipient)?;
        verifier.accept(&page)?;
        cursor = page.next_cursor().cloned();
        if cursor.is_none() {
            break;
        }
    }
    let verified = verifier.finish()?;
    authority
        .acknowledge_audit_export(&verified, recipient)
        .await
}

fn next_checkpointed_request() -> CommitRequest<TestConfig> {
    CommitRequest::commit(
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_checkpoint_advance_failure_forbids_config_effect() {
    let checkpoints = Arc::new(CheckpointFixture::default());
    let cluster = ProjectionCluster::start_with_continuity(Some(checkpoints.clone())).await;
    let authority = Arc::clone(&cluster.stores[cluster.leader()]);
    let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).expect("privacy key"));
    authority
        .initialize_audit_authority(
            privacy.as_ref(),
            AuditLedgerLimits::new(9, 3).expect("bounds"),
        )
        .await
        .expect("required checkpoint authority");
    cluster.wait_ready().await;
    let source = audited_source(Arc::clone(&authority), Arc::clone(&privacy));
    source
        .append_commit(projection_record(TxId::new(), None, 1, "revision-1"))
        .await
        .expect("bootstrap");
    assert_eq!(
        authority
            .reconcile_audit_obligations(3)
            .await
            .expect("bootstrap terminal already checkpointed")
            .completed,
        0
    );
    acknowledge_current_prefix(&authority, &privacy)
        .await
        .expect("externally checkpoint complete bootstrap history");
    assert_eq!(checkpoints.sequence(), 3);
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "initial".into(),
        },
        Arc::clone(&source),
    )
    .await
    .expect("bus");

    // Reading the old checkpoint remains possible, but no new intent can be
    // independently reserved outside the configuration restore domain.
    checkpoints
        .advance_unavailable
        .store(true, Ordering::Release);
    let before = checkpoints.advance_attempts.load(Ordering::Acquire);
    let result = bus.submit(next_checkpointed_request()).await;
    let stored = source
        .load_committed_latest()
        .await
        .expect("read durable result")
        .expect("head");
    let bus_revision = bus.version().get();
    let durable_revision = stored.version.get();
    let sequence = checkpoints.sequence();
    let attempted = checkpoints.advance_attempts.load(Ordering::Acquire) - before;
    cluster.shutdown().await;

    assert!(
        attempted > 0,
        "must attempt independent reservation before effect"
    );
    assert!(
        result.is_err() && bus_revision == 1 && durable_revision == 1,
        "checkpoint advance refusal must prevent configuration effect: success={}, bus_revision={bus_revision}, durable_revision={durable_revision}, external_sequence={sequence}, advance_attempts={attempted}",
        result.is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_checkpoint_terminal_precedes_healthy_commit_acknowledgement() {
    let checkpoints = Arc::new(CheckpointFixture::default());
    let cluster = ProjectionCluster::start_with_continuity(Some(checkpoints.clone())).await;
    let authority = Arc::clone(&cluster.stores[cluster.leader()]);
    let privacy = Arc::new(AuditPrivacyKey::new([0x81; 32]).expect("privacy key"));
    authority
        .initialize_audit_authority(
            privacy.as_ref(),
            AuditLedgerLimits::new(9, 3).expect("bounds"),
        )
        .await
        .expect("required checkpoint authority");
    cluster.wait_ready().await;
    let source = audited_source(Arc::clone(&authority), Arc::clone(&privacy));
    source
        .append_commit(projection_record(TxId::new(), None, 1, "revision-1"))
        .await
        .expect("bootstrap");
    assert_eq!(
        authority
            .reconcile_audit_obligations(3)
            .await
            .expect("bootstrap terminal already checkpointed")
            .completed,
        0
    );
    acknowledge_current_prefix(&authority, &privacy)
        .await
        .expect("checkpoint complete bootstrap history");
    assert_eq!(checkpoints.sequence(), 3);
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "initial".into(),
        },
        Arc::clone(&source),
    )
    .await
    .expect("bus");

    let result = bus
        .submit(next_checkpointed_request())
        .await
        .expect("known committed configuration");
    assert_eq!(result.new_version, Some(ConfigVersion::new(2)));
    assert_eq!(
        source
            .load_committed_latest()
            .await
            .expect("durable result")
            .expect("head")
            .tx_id,
        result.tx_id
    );
    let sequence_at_reply = checkpoints.sequence();
    let progress = authority
        .reconcile_audit_obligations(3)
        .await
        .expect("recover terminal obligations");
    let sequence_after_terminal = checkpoints.sequence();

    // Positive control: the same healthy provider and the existing public
    // export/verification/acknowledgement composition can advance to this tail.
    acknowledge_current_prefix(&authority, &privacy)
        .await
        .expect("explicit export checkpoint advance");
    assert_eq!(checkpoints.sequence(), 6);
    cluster.shutdown().await;

    assert!(
        sequence_at_reply >= 6 && progress.completed == 0,
        "healthy commit reply must follow the terminal checkpoint: external_sequence_at_reply={sequence_at_reply}, terminals_completed_after_reply={}, external_sequence_after_terminal={sequence_after_terminal}",
        progress.completed
    );
}
