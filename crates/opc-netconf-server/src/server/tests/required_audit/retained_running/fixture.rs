//! Real encryption and native retained authority; gates only delay real providers.
use super::*;
use opc_config_bus::{CommitWrite, NetconfAuditStore, StoreError};
use opc_config_model::{IdempotencyKey, RollbackTarget};
use opc_key::{KeyError, KeyHandle, KeyProvider};
use opc_persist::audit_authority::{
    AuditAdmission, AuditCaller, AuditOperationReceipt, NetconfDeviceOwner,
};
use opc_persist::{
    ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions, RetainedConfigProfile,
};
use opc_types::{TenantId, TxId};
use std::sync::atomic::AtomicUsize;
use tokio::sync::{Notify, Semaphore};

const LIFETIME: Duration = Duration::from_secs(60);

pub(super) struct Gate {
    armed: AtomicBool,
    entered: AtomicBool,
    changed: Notify,
    release: Semaphore,
}
impl Default for Gate {
    fn default() -> Self {
        Self {
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            changed: Notify::new(),
            release: Semaphore::new(0),
        }
    }
}
impl Gate {
    pub(super) fn arm(self: &Arc<Self>) -> ReleaseGate {
        assert!(!self.armed.swap(true, Ordering::AcqRel));
        self.entered.store(false, Ordering::Release);
        ReleaseGate(self.clone())
    }
    async fn hold(&self) {
        if self.armed.swap(false, Ordering::AcqRel) {
            self.entered.store(true, Ordering::Release);
            self.changed.notify_waiters();
            self.release.acquire().await.unwrap().forget();
        }
    }
    pub(super) async fn entered(&self) {
        loop {
            let notified = self.changed.notified();
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}
pub(super) struct ReleaseGate(Arc<Gate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release.add_permits(1);
    }
}

pub(super) struct Provider {
    inner: MemoryKeyProvider,
    pub(super) active: AtomicUsize,
    lookup: AtomicUsize,
    rotations: AtomicUsize,
    pub(super) fail_lookup: AtomicBool,
    pub(super) encrypt_gate: Arc<Gate>,
    pub(super) readback_gate: Arc<Gate>,
}

impl Provider {
    fn new() -> Self {
        let inner = MemoryKeyProvider::new();
        inner
            .insert_active_key(
                KeyId::new("synthetic-running-adapter-key").unwrap(),
                KeyPurpose::Config,
                principal().tenant,
                Zeroizing::new([0x36; 32]),
            )
            .unwrap();
        Self {
            inner,
            active: AtomicUsize::new(0),
            lookup: AtomicUsize::new(0),
            rotations: AtomicUsize::new(0),
            fail_lookup: AtomicBool::new(false),
            encrypt_gate: Arc::new(Gate::default()),
            readback_gate: Arc::new(Gate::default()),
        }
    }
    pub(super) fn calls(&self) -> usize {
        self.active.load(Ordering::Acquire)
            + self.lookup.load(Ordering::Acquire)
            + self.rotations.load(Ordering::Acquire)
    }
}

#[async_trait::async_trait]
impl KeyProvider for Provider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.active.fetch_add(1, Ordering::AcqRel);
        self.encrypt_gate.hold().await;
        self.inner.get_active_key(purpose, tenant).await
    }
    async fn get_key_by_id(&self, id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.lookup.fetch_add(1, Ordering::AcqRel);
        self.readback_gate.hold().await;
        if self.fail_lookup.load(Ordering::Acquire) {
            return Err(KeyError::Unavailable);
        }
        self.inner.get_key_by_id(id).await
    }
    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.rotations.fetch_add(1, Ordering::AcqRel);
        self.inner.rotate_key(purpose, tenant).await
    }
}

fn sdk_event(event: &AuditEvent) -> ManagementAuditEventRecord {
    let transport = match event.transport {
        TransportType::NetconfSsh => ManagementAuditTransportCode::NetconfSsh,
        TransportType::NetconfTls => ManagementAuditTransportCode::NetconfTls,
        TransportType::Internal => ManagementAuditTransportCode::Internal,
        _ => panic!("unexpected fixture transport"),
    };
    let operation = match event.operation {
        AuditOperation::Replace => ManagementAuditOperationCode::Replace,
        AuditOperation::Update => ManagementAuditOperationCode::Update,
        AuditOperation::Delete => ManagementAuditOperationCode::Delete,
        AuditOperation::Exec => ManagementAuditOperationCode::Exec,
        _ => panic!("unexpected fixture operation"),
    };
    ManagementAuditEventRecord::try_new(
        *event.request_id.as_uuid().as_bytes(),
        ManagementAuditInstant::try_new(
            event.occurred_at.utc_seconds(),
            event.occurred_at.nanosecond(),
            event.occurred_at.monotonic_sequence(),
            ManagementAuditTimeSourceCode::NodeClock,
        )
        .unwrap(),
        &event.tenant,
        &event.principal,
        transport,
        operation,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        std::iter::empty::<&str>(),
        event.tx_id.as_ref().map(|tx| tx.as_str()),
    )
    .unwrap()
}

fn applied(result: AuditAdmission) -> AuditOperationReceipt {
    match result {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected original SDK outcome: {other:?}"),
    }
}

#[derive(Default)]
pub(super) struct NativeCheckpoint {
    pub(super) inner: Checkpoints,
    pub(super) after_prepare: AtomicBool,
    remaining_loads: AtomicUsize,
    pub(super) observed_loads: AtomicUsize,
    pub(super) admission_gate: Arc<Gate>,
    pub(super) prepared_request: Mutex<Option<RequestId>>,
}
#[async_trait::async_trait]
impl AuditCheckpointPort for NativeCheckpoint {
    async fn load(
        &self,
        identity: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        if let Ok(previous) =
            self.remaining_loads
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
        {
            self.observed_loads.fetch_add(1, Ordering::AcqRel);
            if previous == 1 {
                self.admission_gate.hold().await;
            }
        }
        self.inner.load(identity).await
    }
    async fn compare_advance(
        &self,
        identity: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        self.inner.compare_advance(identity, expected, next).await
    }
}

type Encrypted = EncryptingManagedDatastore<DemoConfig, Provider, RaftManagedDatastore<DemoConfig>>;

// Delegates every effect/read to the actual encrypted adapter. The sole seam
// arms a provider barrier after genuine SDK attestation; it cannot forge one.
struct ObservedStore {
    inner: Arc<Encrypted>,
    checkpoint: Arc<NativeCheckpoint>,
}
#[async_trait::async_trait]
impl ManagedDatastore<DemoConfig> for ObservedStore {
    fn required_audit_observations(&self) -> Option<Arc<dyn AuditSink>> {
        self.inner.required_audit_observations()
    }
    fn required_netconf_audit_store(&self) -> Option<NetconfAuditStore> {
        self.inner.required_netconf_audit_store()
    }
    async fn prepare_netconf_running_commit(
        &self,
        commit: CommitWrite<DemoConfig>,
        principal: &TrustedPrincipal,
        event: &AuditEvent,
    ) -> Result<opc_persist::AttestedConfigCommit, StoreError> {
        let request_id = commit.record().request_id;
        let attested = self
            .inner
            .prepare_netconf_running_commit(commit, principal, event)
            .await?;
        *self.checkpoint.prepared_request.lock().unwrap() = request_id;
        if self.checkpoint.after_prepare.swap(false, Ordering::AcqRel) {
            // Exact native sequence after attestation: prepare target preflight,
            // admit target preflight, then read_audit_ledger inside native
            // admission. The last active-session enqueue guard follows load 3.
            // This is also exercised by the existing native guard-removal test.
            self.checkpoint.observed_loads.store(0, Ordering::Release);
            assert_eq!(self.checkpoint.remaining_loads.swap(3, Ordering::AcqRel), 0);
        }
        Ok(attested)
    }
    async fn load_latest(&self) -> Result<Option<StoredConfig<DemoConfig>>, StoreError> {
        self.inner.load_latest().await
    }
    async fn load_rollback(
        &self,
        target: RollbackTarget,
    ) -> Result<StoredConfig<DemoConfig>, StoreError> {
        self.inner.load_rollback(target).await
    }
    async fn load_by_idempotency_key(
        &self,
        key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<DemoConfig>>, StoreError> {
        self.inner.load_by_idempotency_key(key).await
    }
    async fn load_by_request_id(
        &self,
        request: RequestId,
    ) -> Result<Option<StoredConfig<DemoConfig>>, StoreError> {
        self.inner.load_by_request_id(request).await
    }
    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.inner.clear_recovery_required(tx_id).await
    }
}

pub(super) struct Fixture {
    directory: tempfile::TempDir,
    pub(super) store: Arc<ConsensusConfigStore>,
    pub(super) encrypted: Arc<Encrypted>,
    pub(super) provider: Arc<Provider>,
    pub(super) checkpoint: Arc<NativeCheckpoint>,
    device: NetconfDeviceOwner,
    pub(super) bus: Arc<ConfigBus<DemoConfig>>,
    pub(super) audit: RequiredNetconfAudit<DemoConfig>,
}
impl Fixture {
    pub(super) async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let node = ConfigConsensusNodeId::new(1).unwrap();
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0x31; 32]),
            ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
        let backend = SqliteBackend::provision_config_authority(
            RetainedConfigOptions::new(
                directory.path().join("authority.sqlite"),
                RetainedConfigBinding::new(topology.clone(), [0x33; 32], [0x34; 32])
                    .unwrap()
                    .with_profile(RetainedConfigProfile::NetconfTargetsV1),
                RetainedConfigDurability::Ephemeral,
                64 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap(),
            AuditKey::new([0x37; 32]).unwrap(),
        )
        .await
        .unwrap();
        let checkpoint = Arc::new(NativeCheckpoint::default());
        let policy = AuditContinuityPolicy::new(
            AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x38; 32]).unwrap()]).unwrap(),
            checkpoint.clone(),
            1,
            1,
        )
        .unwrap();
        let store = Arc::new(
            ConsensusConfigStore::open_with_audit_continuity(
                topology,
                backend,
                directory.path().join("snapshots"),
                BTreeMap::new(),
                policy,
            )
            .await
            .unwrap(),
        );
        store.initialize_cluster().await.unwrap();
        let privacy = Arc::new(AuditPrivacyKey::new([0x39; 32]).unwrap());
        store
            .initialize_audit_authority(privacy.as_ref(), AuditLedgerLimits::new(96, 32).unwrap())
            .await
            .unwrap();
        let caller = AuditCaller::project(
            privacy.as_ref(),
            principal().tenant.as_str(),
            &opc_mgmt_audit::principal_descriptor(&principal()),
        )
        .unwrap();
        let start = AuditEvent::new(
            RequestId::new(),
            &principal(),
            TransportType::Internal,
            AuditOperation::Exec,
            AuditOutcome::Intent,
        );
        let prepared = store
            .prepare_netconf_device(privacy.as_ref(), &sdk_event(&start), LIFETIME)
            .await
            .unwrap();
        let intent = applied(
            store
                .admit_netconf_target_local(prepared.mutation(), caller)
                .await,
        );
        let result = applied(
            store
                .submit_netconf_target_local(prepared.mutation(), &intent, caller)
                .await,
        );
        store
            .complete_required_audit_outcome(&result, caller)
            .await
            .unwrap();
        let device = store
            .claim_netconf_device_owner(&prepared, &result, caller)
            .await
            .unwrap();
        let raft = Arc::new(
            RaftManagedDatastore::new_audited_netconf_local_authority(
                store.clone(),
                ConfigAuditPolicy::new(privacy, LIFETIME).unwrap(),
                device.clone(),
            )
            .await
            .unwrap(),
        );
        let provider = Arc::new(Provider::new());
        let encrypted = Arc::new(
            EncryptingManagedDatastore::new(raft, provider.clone())
                .with_required_netconf_audit()
                .await
                .unwrap(),
        );
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "fixture-initial".into(),
                    secret: "synthetic-secret".into(),
                },
                Arc::new(ObservedStore {
                    inner: encrypted.clone(),
                    checkpoint: checkpoint.clone(),
                }),
            )
            .await
            .unwrap(),
        );
        let audit = bus.required_netconf_audit().unwrap();
        Self {
            directory,
            store,
            encrypted,
            provider,
            checkpoint,
            device,
            bus,
            audit,
        }
    }
    pub(super) fn server(&self, policy: NacmPolicy) -> Result<Arc<NativeServer>, ServerInitError> {
        unattached(Binding::new(self.bus.clone()), policy)
            .with_retained_running_audit(self.audit.clone())
            .map(Arc::new)
    }
    pub(super) async fn close(self) -> bool {
        let exit = self.audit.shutdown().await;
        drop(self.audit);
        drop(self.bus);
        drop(self.encrypted);
        drop(self.device);
        let stopped = self.store.shutdown().await.is_ok();
        drop(self.store);
        drop(self.directory);
        matches!(exit, Ok(NetconfWorkerExit::Drained)) && stopped
    }
}
