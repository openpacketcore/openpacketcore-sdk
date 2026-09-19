use super::*;
use opc_persist::audit_authority::continuity::{
    AuditCheckpoint, AuditCheckpointAdvance, AuditCheckpointPort,
};
use opc_persist::audit_authority::AuditAuthorityError;

// Synthetic separately owned monotonic authority, never a production provider.
#[derive(Default)]
struct CheckpointFixture {
    value: std::sync::Mutex<Option<AuditCheckpoint>>,
    unavailable: AtomicBool,
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
        if self.unavailable.load(Ordering::Acquire) {
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
        Ok(AuditCheckpointAdvance::Applied)
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
    assert_eq!(progress.completed, 2);
    assert_eq!((progress.pending, progress.unknown), (0, 0));
    cluster.shutdown().await;
}
