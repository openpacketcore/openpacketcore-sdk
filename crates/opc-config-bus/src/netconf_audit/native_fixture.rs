//! Synthetic single-member authority. This never substitutes mock SDK ownership.
use opc_config_model::{RequestId, TrustedPrincipal};
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome};
use opc_persist::{
    audit_authority::{continuity::*, *},
    *,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Default)]
pub(super) struct Checkpoint {
    value: Mutex<Option<AuditCheckpoint>>,
    pub(super) unavailable: AtomicBool,
    pub(super) loads: AtomicUsize,
    pub(super) fail_completion: AtomicBool,
    pub(super) advances_since_arm: AtomicUsize,
    pub(super) pause: AtomicBool,
    pub(super) entered: tokio::sync::Notify,
    pub(super) release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl AuditCheckpointPort for Checkpoint {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        self.loads.fetch_add(1, Ordering::AcqRel);
        if self.pause.swap(false, Ordering::AcqRel) {
            self.entered.notify_one();
            self.release.notified().await;
        }
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
        // Submission checkpoints Intent before applying the effect; completion
        // then advances the terminal checkpoint. Fail only that second boundary.
        if self.fail_completion.load(Ordering::Acquire)
            && self.advances_since_arm.fetch_add(1, Ordering::AcqRel) >= 1
        {
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
        Ok(AuditCheckpointAdvance::Applied)
    }
}

pub(super) struct Fixture {
    pub(super) store: Arc<ConsensusConfigStore>,
    pub(super) device: NetconfDeviceOwner,
    pub(super) port: super::NetconfAuditStore,
    pub(super) caller: AuditCaller,
    pub(super) checkpoint: Arc<Checkpoint>,
    path: PathBuf,
}
impl Fixture {
    pub(super) async fn new(principal: &TrustedPrincipal) -> Self {
        let path = std::env::temp_dir().join(format!("opc-session-{}", RequestId::new()));
        std::fs::create_dir(&path).unwrap();
        let node = ConfigConsensusNodeId::new(1).unwrap();
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("synthetic-session").unwrap(),
            ConfigConsensusConfigurationId::from_bytes([0x42; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
        let binding = RetainedConfigBinding::new(topology.clone(), [0x31; 32], [0x61; 32])
            .unwrap()
            .with_profile(RetainedConfigProfile::NetconfTargetsV1);
        let backend = SqliteBackend::provision_config_authority(
            RetainedConfigOptions::new(
                path.join("authority.sqlite"),
                binding,
                RetainedConfigDurability::Ephemeral,
                64 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap(),
            AuditKey::new([0x55; 32]).unwrap(),
        )
        .await
        .unwrap();
        let checkpoint = Arc::new(Checkpoint::default());
        let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x71; 32]).unwrap()]).unwrap();
        let policy = AuditContinuityPolicy::new(keys, checkpoint.clone(), 1, 1).unwrap();
        let store = Arc::new(
            ConsensusConfigStore::open_with_audit_continuity(
                topology,
                backend,
                path.join("snapshots"),
                BTreeMap::new(),
                policy,
            )
            .await
            .expect("single-member retained target runtime must open with independent continuity"),
        );
        store.initialize_cluster().await.unwrap();
        let privacy = Arc::new(AuditPrivacyKey::new([0xa9; 32]).unwrap());
        store
            .initialize_audit_authority(privacy.as_ref(), AuditLedgerLimits::new(96, 32).unwrap())
            .await
            .unwrap();
        let caller = AuditCaller::project(
            privacy.as_ref(),
            principal.tenant.as_str(),
            &opc_mgmt_audit::principal_descriptor(principal),
        )
        .unwrap();
        let event = super::event::convert_event(&AuditEvent::new(
            RequestId::new(),
            principal,
            opc_config_model::TransportType::Internal,
            AuditOperation::Exec,
            AuditOutcome::Intent,
        ))
        .unwrap();
        let prepared = store
            .prepare_netconf_device(privacy.as_ref(), &event, Duration::from_secs(60))
            .await
            .unwrap();
        let intent = applied(
            store
                .admit_netconf_target_local(prepared.mutation(), caller)
                .await,
        );
        let known = applied(
            store
                .submit_netconf_target_local(prepared.mutation(), &intent, caller)
                .await,
        );
        store
            .complete_required_audit_outcome(&known, caller)
            .await
            .unwrap();
        let device = store
            .claim_netconf_device_owner(&prepared, &known, caller)
            .await
            .unwrap();
        let port = super::NetconfAuditStore::new(
            store.clone(),
            privacy,
            Duration::from_secs(60),
            device.clone(),
        )
        .await
        .unwrap()
        .with_provider(Arc::new(opc_key::MemoryKeyProvider::new()));
        Self {
            store,
            device,
            port,
            caller,
            checkpoint,
            path,
        }
    }
    pub(super) async fn close(self) {
        self.store.shutdown().await.unwrap();
        drop(self.store);
        std::fs::remove_dir_all(self.path).unwrap();
    }
}
fn applied(result: AuditAdmission) -> AuditOperationReceipt {
    match result {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected authenticated result: {other:?}"),
    }
}

struct SessionStore(super::NetconfAuditStore);
struct RefusingObservations;
impl opc_mgmt_audit::AuditSink for RefusingObservations {
    fn record(&self, _: &AuditEvent) -> Result<(), opc_mgmt_audit::AuditError> {
        Err(opc_mgmt_audit::AuditError::unavailable(
            "synthetic observation unavailable",
        ))
    }
}
#[async_trait::async_trait]
impl crate::ManagedDatastore<()> for SessionStore {
    fn required_netconf_audit_store(&self) -> Option<super::NetconfAuditStore> {
        Some(self.0.clone())
    }
    fn required_audit_observations(&self) -> Option<Arc<dyn opc_mgmt_audit::AuditSink>> {
        Some(Arc::new(RefusingObservations))
    }
    async fn load_latest(&self) -> Result<Option<crate::StoredConfig<()>>, crate::StoreError> {
        Ok(None)
    }
    async fn load_rollback(
        &self,
        _: opc_config_model::RollbackTarget,
    ) -> Result<crate::StoredConfig<()>, crate::StoreError> {
        Err(crate::StoreError::unavailable(
            "synthetic no running config",
        ))
    }
    async fn load_by_idempotency_key(
        &self,
        _: &opc_config_model::IdempotencyKey,
    ) -> Result<Option<crate::StoredConfig<()>>, crate::StoreError> {
        Ok(None)
    }
    async fn clear_recovery_required(&self, _: opc_types::TxId) -> Result<(), crate::StoreError> {
        Err(crate::StoreError::unavailable(
            "synthetic no running config",
        ))
    }
}
impl Fixture {
    pub(super) fn bus(&self, capacity: usize) -> crate::ConfigBus<()> {
        crate::ConfigBus::spawn(
            (),
            opc_types::ConfigVersion::new(0),
            None,
            Arc::new(SessionStore(self.port.clone())),
            capacity,
            crate::AuthorityMode::Authoritative,
            opc_alarm::SharedAlarmManager::default(),
            Arc::new(crate::AllowAllAuthorizer),
            Arc::new(opc_config_model::HotConfigImpactClassifier),
            None,
        )
    }
}
