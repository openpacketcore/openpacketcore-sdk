#![cfg(feature = "required-netconf-audit")]
//! Ordinary Running worker tests over real retained SDK storage and encryption.
//! Faults stop provider readback/checkpoint/marker publication, never substitute
//! a mutation result. SQL is used only for exact persisted observations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore};

use opc_config_bus::{
    AuthorizationContext, AuthorizationError, CommitWrite, ConfigAuthorizer, ConfigBus,
    EncryptingManagedDatastore, ManagedDatastore, NetconfAppliedReceipt, NetconfLockDatastore,
    NetconfMutationResult, NetconfSession, NetconfWorkerExit, RequiredNetconfAudit, StoreError,
    StoredConfig,
};
use opc_config_bus_consensus::{ConfigAuditPolicy, RaftManagedDatastore};
use opc_config_model::{
    CommitErrorCode, CommitMode, CommitRequest, ConfigError, ConfigOperation, IdempotencyKey,
    OpcConfig, RequestId, RequestSource, RollbackTarget, TransportType, TrustedPrincipal,
    ValidationContext, ValidationError, WorkloadIdentity, YangPath,
};
use opc_key::{KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome};
use opc_persist::audit_authority::continuity::{
    AuditCheckpoint, AuditCheckpointAdvance, AuditCheckpointPort, AuditContinuityPolicy,
    AuditKeyRing, AuditSigningKey,
};
use opc_persist::audit_authority::{
    AuditAdmission, AuditAuthorityError, AuditCaller, AuditLedgerLimits, AuditOperationReceipt,
    AuditPrivacyKey, NetconfAppliedOutcome, NetconfDeviceOwner,
};
use opc_persist::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, ConfigStore, ConsensusConfigStore, ManagementAuditEventRecord,
    ManagementAuditInstant, ManagementAuditOperationCode, ManagementAuditOutcomeCode,
    ManagementAuditTimeSourceCode, ManagementAuditTransportCode, RetainedConfigBinding,
    RetainedConfigDurability, RetainedConfigOptions, RetainedConfigProfile, SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};
use serde::{Deserialize, Serialize};

const LIFETIME: Duration = Duration::from_secs(60);

#[path = "netconf_running_worker/patch_operation.rs"]
mod patch_operation;
#[path = "netconf_running_worker/revocation.rs"]
mod revocation;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Settings {
    label: String,
}

impl OpcConfig for Settings {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_bytes([0x35; 32])
    }
    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        Ok(if self == previous {
            Vec::new()
        } else {
            vec![self.label.clone()]
        })
    }
    fn changed_paths(
        &self,
        _: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        Ok(if deltas.is_empty() {
            Vec::new()
        } else {
            vec![YangPath::new("/synthetic:settings/label").unwrap()]
        })
    }
    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        self.label = delta;
        Ok(())
    }
    fn validate_syntax(&self) -> Result<(), ValidationError> {
        if self.label == "invalid" {
            Err(ValidationError::syntax("synthetic invalid config"))
        } else {
            Ok(())
        }
    }
    fn validate_semantics(&self, _: &ValidationContext<Self>) -> Result<(), ValidationError> {
        Ok(())
    }
}

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::User("synthetic-operator".into()),
        TenantId::new("synthetic-running-adapter").unwrap(),
    )
}

struct Provider {
    inner: MemoryKeyProvider,
    active: AtomicUsize,
    lookup: AtomicUsize,
    rotations: AtomicUsize,
    fail_lookup: AtomicBool,
    encrypt_gate: Arc<Gate>,
    readback_gate: Arc<Gate>,
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
    fn calls(&self) -> usize {
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

struct Checkpoint {
    current: Mutex<Option<AuditCheckpoint>>,
    database: std::path::PathBuf,
    fail_after_effect: AtomicBool,
    revocation: revocation::CheckpointControls,
}

#[async_trait::async_trait]
impl AuditCheckpointPort for Checkpoint {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        self.revocation.before_load().await;
        Ok(self.current.lock().unwrap().clone())
    }
    async fn compare_advance(
        &self,
        _: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        self.revocation.before_advance(&next).await?;
        if self.fail_after_effect.load(Ordering::Acquire) {
            let conn = rusqlite::Connection::open_with_flags(
                &self.database,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let count: u64 = conn
                .query_row("SELECT count(*) FROM config_history", [], |row| row.get(0))
                .unwrap();
            if count != 0 {
                return Err(AuditAuthorityError::Unavailable);
            }
        }
        let mut current = self.current.lock().unwrap();
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

type Encrypted = EncryptingManagedDatastore<Settings, Provider, RaftManagedDatastore<Settings>>;
type TableRows = Vec<Vec<rusqlite::types::Value>>;
type AuthorityRows = (Vec<TableRows>, Option<AuditCheckpoint>);

struct Fixture {
    directory: tempfile::TempDir,
    store: Arc<ConsensusConfigStore>,
    raft: Arc<RaftManagedDatastore<Settings>>,
    encrypted: Arc<Encrypted>,
    provider: Arc<Provider>,
    checkpoint: Arc<Checkpoint>,
    device: NetconfDeviceOwner,
}

impl Fixture {
    async fn new() -> Self {
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
        let checkpoint = Arc::new(Checkpoint {
            current: Mutex::new(None),
            database: directory.path().join("authority.sqlite"),
            fail_after_effect: AtomicBool::new(false),
            revocation: revocation::CheckpointControls::default(),
        });
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
                ConfigAuditPolicy::new(privacy.clone(), LIFETIME).unwrap(),
                device.clone(),
            )
            .await
            .unwrap(),
        );
        let provider = Arc::new(Provider::new());
        let encrypted = Arc::new(
            EncryptingManagedDatastore::new(raft.clone(), provider.clone())
                .with_required_netconf_audit()
                .await
                .unwrap(),
        );
        Self {
            directory,
            store,
            raft,
            encrypted,
            provider,
            checkpoint,
            device,
        }
    }

    fn rows(&self) -> AuthorityRows {
        let conn = rusqlite::Connection::open_with_flags(
            self.directory.path().join("authority.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        let tables = [
            "config_history",
            "config_raft_management_audit",
            "config_netconf_profile",
            "config_netconf_targets",
            "config_netconf_lifecycle",
        ];
        let rows = tables
            .into_iter()
            .map(|table| {
                let mut query = tx
                    .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
                    .unwrap();
                let columns = query.column_count();
                let selected = query
                    .query_map([], |row| {
                        (0..columns)
                            .map(|column| row.get(column))
                            .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                    })
                    .unwrap();
                selected.collect::<rusqlite::Result<Vec<_>>>().unwrap()
            })
            .collect();
        (rows, self.checkpoint.current.lock().unwrap().clone())
    }

    async fn close(self) {
        drop(self.encrypted);
        drop(self.raft);
        self.store.shutdown().await.unwrap();
        drop(self.store);
        drop(self.directory);
    }
}

struct Gate {
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
    fn arm(self: &Arc<Self>) -> ReleaseGate {
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
    async fn entered(&self) {
        loop {
            let notified = self.changed.notified();
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}
struct ReleaseGate(Arc<Gate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release.add_permits(1);
    }
}

#[derive(Default)]
struct Authorizer {
    deny: AtomicBool,
    calls: AtomicUsize,
}
#[async_trait::async_trait]
impl ConfigAuthorizer for Authorizer {
    async fn authorize(&self, context: &AuthorizationContext) -> Result<(), AuthorizationError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        assert_eq!(
            context.changed_paths,
            vec![YangPath::new("/synthetic:settings/label").unwrap()],
            "RUNNING_DERIVED_NACM_PATHS"
        );
        if self.deny.load(Ordering::Acquire) {
            Err(AuthorizationError::new("synthetic denial"))
        } else {
            Ok(())
        }
    }
}

// Publication faults alter marker completion or select a different real stored
// transaction for readback. Preparation delegates to the actual encrypted
// retained adapter; no callback supplies an effect or an SDK receipt.
struct PublicationStore {
    inner: Arc<Encrypted>,
    checkpoint: Arc<Checkpoint>,
    fail_marker: AtomicBool,
    wrong_readback: Mutex<Option<TxId>>,
}
#[async_trait::async_trait]
impl ManagedDatastore<Settings> for PublicationStore {
    fn required_audit_observations(&self) -> Option<Arc<dyn opc_mgmt_audit::AuditSink>> {
        self.inner.required_audit_observations()
    }
    fn required_netconf_audit_store(&self) -> Option<opc_config_bus::NetconfAuditStore> {
        self.inner.required_netconf_audit_store()
    }
    async fn prepare_netconf_running_commit(
        &self,
        commit: CommitWrite<Settings>,
        principal: &TrustedPrincipal,
        event: &AuditEvent,
    ) -> Result<opc_persist::AttestedConfigCommit, StoreError> {
        let attested = self
            .inner
            .prepare_netconf_running_commit(commit, principal, event)
            .await?;
        self.checkpoint
            .revocation
            .after_preparation(attested.record().tx_id);
        Ok(attested)
    }
    async fn load_latest(&self) -> Result<Option<StoredConfig<Settings>>, StoreError> {
        self.inner.load_latest().await
    }
    async fn load_rollback(
        &self,
        target: RollbackTarget,
    ) -> Result<StoredConfig<Settings>, StoreError> {
        let selected = *self.wrong_readback.lock().unwrap();
        self.inner
            .load_rollback(selected.map_or(target, RollbackTarget::TxId))
            .await
    }
    async fn load_by_idempotency_key(
        &self,
        key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<Settings>>, StoreError> {
        self.inner.load_by_idempotency_key(key).await
    }
    async fn load_by_request_id(
        &self,
        request: RequestId,
    ) -> Result<Option<StoredConfig<Settings>>, StoreError> {
        self.inner.load_by_request_id(request).await
    }
    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        if self.fail_marker.load(Ordering::Acquire) {
            return Err(StoreError::unavailable(
                "synthetic marker publication fault",
            ));
        }
        self.inner.clear_recovery_required(tx_id).await
    }
}

struct Worker {
    bus: ConfigBus<Settings>,
    audit: RequiredNetconfAudit<Settings>,
    authorizer: Arc<Authorizer>,
    publication: Arc<PublicationStore>,
}
impl Worker {
    async fn new(f: &Fixture) -> Self {
        let authorizer = Arc::new(Authorizer::default());
        let publication = Arc::new(PublicationStore {
            inner: f.encrypted.clone(),
            checkpoint: f.checkpoint.clone(),
            fail_marker: AtomicBool::new(false),
            wrong_readback: Mutex::new(None),
        });
        let bus = ConfigBus::new_with_authorizer(
            Settings {
                label: "initial".into(),
            },
            publication.clone(),
            authorizer.clone(),
        )
        .await
        .unwrap();
        let audit = bus.required_netconf_audit().unwrap();
        Self {
            bus,
            audit,
            authorizer,
            publication,
        }
    }
    async fn submit(
        &self,
        session: &NetconfSession,
        request: CommitRequest<Settings>,
    ) -> NetconfMutationResult {
        let event = request_event(&request);
        self.audit
            .replace_running(session, &principal(), request, event)
            .await
            .unwrap()
    }
    async fn close(self) {
        assert_eq!(
            self.audit.shutdown().await.unwrap(),
            NetconfWorkerExit::Drained,
            "RUNNING_CLEAN_DRAIN"
        );
    }
}
fn request(version: u64) -> CommitRequest<Settings> {
    let mut request = CommitRequest::commit(
        RequestId::new(),
        principal(),
        TransportType::NetconfSsh,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        Settings {
            label: format!("revision-{}", version + 1),
        },
        Vec::new(),
        Instant::now() + LIFETIME,
    );
    request.base_version = ConfigVersion::new(version);
    request
}
fn request_event(request: &CommitRequest<Settings>) -> AuditEvent {
    AuditEvent::new(
        request.request_id,
        &request.principal,
        request.transport,
        AuditOperation::Replace,
        AuditOutcome::Intent,
    )
}
fn known(result: NetconfMutationResult) -> NetconfAppliedReceipt {
    match result {
        NetconfMutationResult::Applied(receipt) => receipt,
        other => panic!("RUNNING_KNOWN_APPLIED: {other:?}"),
    }
}
fn refused(result: NetconfMutationResult, marker: &str) {
    assert!(
        matches!(result, NetconfMutationResult::Refused(_)),
        "{marker}: {result:?}"
    );
}
fn history_count(f: &Fixture) -> u64 {
    let conn = rusqlite::Connection::open_with_flags(
        f.directory.path().join("authority.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    conn.query_row("SELECT count(*) FROM config_history", [], |row| row.get(0))
        .unwrap()
}
async fn exact_readback(f: &Fixture, w: &Worker, receipt: &NetconfAppliedReceipt, label: &str) {
    assert!(!receipt.completion_pending());
    assert!(
        !receipt.publication_pending(),
        "RUNNING_PUBLICATION_COMPLETE"
    );
    let result = receipt
        .published_commit()
        .expect("RUNNING_COMMIT_ACK_AFTER_PUBLICATION");
    let NetconfAppliedOutcome::RunningReplaced {
        tx_id,
        running_version,
        plaintext_digest,
    } = receipt.outcome()
    else {
        panic!("RUNNING_EXACT_ACTION_RESULT");
    };
    assert_eq!(result.tx_id, tx_id);
    assert_eq!(
        result.new_version,
        Some(ConfigVersion::new(running_version))
    );
    let actual = f.store.load_latest().await.unwrap().unwrap();
    assert_eq!(actual.record.tx_id, tx_id);
    assert_eq!(actual.record.version.get(), running_version);
    assert_eq!(
        actual.record.plaintext_digest.as_slice(),
        plaintext_digest.as_slice()
    );
    assert!(!actual.record.encrypted_blob.is_empty());
    let decoded = f.encrypted.load_latest().await.unwrap().unwrap();
    assert!(!decoded.recovery_required, "RUNNING_DURABLE_MARKER_CLEAR");
    assert_eq!(decoded.tx_id, tx_id);
    assert_eq!(decoded.config.label, label);
    let published = w.bus.current_snapshot();
    assert_eq!(
        published.tx_id,
        Some(tx_id),
        "RUNNING_BUS_EXACT_TRANSACTION"
    );
    assert_eq!(published.version.get(), running_version);
    assert_eq!(
        published.config.as_ref(),
        &decoded.config,
        "RUNNING_BUS_EXACT_MODEL"
    );
}

#[tokio::test]
async fn running_worker_commits_empty_and_nonempty_exact_base_with_owner_lock() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let lock = AuditEvent::new(
        RequestId::new(),
        &principal(),
        TransportType::NetconfSsh,
        AuditOperation::Exec,
        AuditOutcome::Intent,
    );
    let locked = known(
        w.audit
            .acquire_lock(&owner, &principal(), lock, NetconfLockDatastore::Running)
            .await
            .unwrap(),
    );
    assert!(locked.lock_ready());
    assert!(locked.published_commit().is_none());
    for version in 0..2 {
        let request = request(version);
        let request_id = request.request_id;
        let receipt = known(w.submit(&owner, request).await);
        exact_readback(&f, &w, &receipt, &format!("revision-{}", version + 1)).await;
        let before = f.rows();
        let recovered = known(
            w.audit
                .recover(receipt.recovery_handle(), &principal())
                .await,
        );
        assert_eq!(
            recovered.published_commit().unwrap().tx_id,
            receipt.published_commit().unwrap().tx_id
        );
        let by_request = known(
            w.audit
                .recover_request(request_id, &principal())
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(by_request.outcome(), receipt.outcome());
        assert_eq!(f.rows(), before, "RUNNING_RECOVERY_NO_NEW_EFFECT");
        assert_eq!(history_count(&f), version + 1);
    }
    assert_eq!(
        f.provider.active.load(Ordering::Acquire),
        2,
        "RUNNING_ENCRYPT_ONCE_PER_ORIGINAL"
    );
    assert_eq!(w.authorizer.calls.load(Ordering::Acquire), 2);
    drop(owner);
    w.close().await;
    f.store
        .verify_netconf_device_owner(&f.device)
        .await
        .unwrap();
    f.close().await;
}

#[tokio::test]
async fn running_worker_refuses_bindings_and_foreign_session_before_provider_or_intent() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let other_worker = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let foreign = w.audit.open_session(&principal()).await.unwrap();
    let lock = AuditEvent::new(
        RequestId::new(),
        &principal(),
        TransportType::NetconfSsh,
        AuditOperation::Exec,
        AuditOutcome::Intent,
    );
    assert!(known(
        w.audit
            .acquire_lock(&owner, &principal(), lock, NetconfLockDatastore::Running)
            .await
            .unwrap()
    )
    .lock_ready());
    let before = f.rows();
    for case in [
        "principal",
        "event_principal",
        "tenant",
        "request",
        "transport",
        "operation",
        "mode",
        "base",
        "session",
        "worker",
    ] {
        let mut request = request(0);
        let mut authenticated = principal();
        let mut event = request_event(&request);
        match case {
            "principal" => {
                authenticated = TrustedPrincipal::new(
                    WorkloadIdentity::User("different-operator".into()),
                    principal().tenant,
                )
            }
            "event_principal" => event.principal = "different-operator".into(),
            "tenant" => event.tenant = "different-tenant".into(),
            "request" => event.request_id = RequestId::new(),
            "transport" => request.transport = TransportType::Internal,
            "operation" => request.operation = ConfigOperation::Patch,
            "mode" => {
                request.mode = CommitMode::CommitConfirmed {
                    timeout: Duration::from_secs(30),
                }
            }
            "base" => request.base_version = ConfigVersion::new(1),
            "session" | "worker" => {}
            _ => unreachable!(),
        }
        let result = if case == "worker" {
            other_worker
                .audit
                .replace_running(&owner, &authenticated, request, event)
                .await
        } else {
            w.audit
                .replace_running(
                    if case == "session" { &foreign } else { &owner },
                    &authenticated,
                    request,
                    event,
                )
                .await
        };
        match result {
            Ok(result) => refused(result, "RUNNING_BINDING_REFUSED"),
            Err(error) => assert_eq!(error.code, CommitErrorCode::AdmissionRejected),
        }
        assert_eq!(
            f.provider.calls(),
            0,
            "RUNNING_BINDING_BEFORE_PROVIDER: {case}"
        );
        assert_eq!(f.rows(), before, "RUNNING_BINDING_NO_INTENT: {case}");
    }
    drop(foreign);
    drop(owner);
    w.close().await;
    other_worker.close().await;
    f.close().await;
}

#[tokio::test]
async fn running_worker_authorizes_and_validates_before_encryption_or_intent() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let before = f.rows();
    w.authorizer.deny.store(true, Ordering::Release);
    let denied = w.submit(&owner, request(0)).await;
    assert!(
        matches!(denied, NetconfMutationResult::Refused(ref error) if error.code == CommitErrorCode::AuthorizationDenied),
        "RUNNING_NACM_BEFORE_ENCRYPTION"
    );
    w.authorizer.deny.store(false, Ordering::Release);
    let mut invalid = request(0);
    invalid.candidate.as_mut().unwrap().label = "invalid".into();
    refused(w.submit(&owner, invalid).await, "RUNNING_MODEL_VALIDATION");
    assert_eq!(f.provider.calls(), 0);
    assert_eq!(f.rows(), before, "RUNNING_POLICY_NO_INTENT");
    drop(owner);
    w.close().await;
    f.close().await;
}

#[tokio::test]
async fn running_worker_cancelled_reply_retains_original_and_recovers_exactly_once() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let request = request(0);
    let request_id = request.request_id;
    let event = request_event(&request);
    let authenticated = principal();
    let release = f.provider.encrypt_gate.arm();
    let mut call = Box::pin(
        w.audit
            .replace_running(&owner, &authenticated, request, event),
    );
    tokio::select! {
        _ = f.provider.encrypt_gate.entered() => {},
        reply = &mut call => panic!("encryption was not held: {reply:?}"),
        _ = tokio::time::sleep(Duration::from_secs(30)) => panic!("encryption gate did not enter"),
    }
    assert_eq!(history_count(&f), 0);
    drop(call); // caller cancellation must not cancel the worker's preparation.
    drop(release);
    let receipt = known(
        w.audit
            .recover_request(request_id, &principal())
            .await
            .unwrap()
            .expect("RUNNING_CANCELLED_ORIGINAL_RETAINED"),
    );
    exact_readback(&f, &w, &receipt, "revision-1").await;
    let before = f.rows();
    let wrong = TrustedPrincipal::new(
        WorkloadIdentity::User("unrelated-reader".into()),
        principal().tenant,
    );
    assert!(w
        .audit
        .recover_request(request_id, &wrong)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        w.audit.recover(receipt.recovery_handle(), &wrong).await,
        NetconfMutationResult::Unknown(_)
    ));
    let again = known(
        w.audit
            .recover(receipt.recovery_handle(), &principal())
            .await,
    );
    assert_eq!(again.outcome(), receipt.outcome());
    assert_eq!(history_count(&f), 1, "RUNNING_CANCELLED_ORIGINAL_ONCE");
    assert_eq!(f.provider.active.load(Ordering::Acquire), 1);
    assert_eq!(f.rows(), before);
    drop(owner);
    w.close().await;
    f.close().await;
}

#[tokio::test]
async fn running_worker_final_transport_drop_after_effect_preserves_publication_and_cleanup() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let request = request(0);
    let request_id = request.request_id;
    let event = request_event(&request);
    let authenticated = principal();
    let release = f.provider.readback_gate.arm();
    let mut call = Box::pin(
        w.audit
            .replace_running(&owner, &authenticated, request, event),
    );
    tokio::select! {
        _ = f.provider.readback_gate.entered() => {},
        reply = &mut call => panic!("publication readback was not held: {reply:?}"),
        _ = tokio::time::sleep(Duration::from_secs(30)) => panic!("readback gate did not enter"),
    }
    assert_eq!(history_count(&f), 1, "RUNNING_REAL_EFFECT_BEFORE_DROP");
    assert_eq!(w.bus.current_snapshot().version, ConfigVersion::INITIAL);
    drop(call);
    drop(owner);
    drop(release);
    let receipt = known(
        w.audit
            .recover_request(request_id, &principal())
            .await
            .unwrap()
            .unwrap(),
    );
    exact_readback(&f, &w, &receipt, "revision-1").await;
    assert_eq!(history_count(&f), 1);
    w.close().await;
    f.close().await;
}

#[tokio::test]
async fn running_worker_checkpoint_and_publication_debt_fence_then_recover_original() {
    for fault in ["checkpoint", "readback", "marker"] {
        let f = Fixture::new().await;
        let w = Worker::new(&f).await;
        let owner = w.audit.open_session(&principal()).await.unwrap();
        f.checkpoint
            .fail_after_effect
            .store(fault == "checkpoint", Ordering::Release);
        f.provider
            .fail_lookup
            .store(fault == "readback", Ordering::Release);
        w.publication
            .fail_marker
            .store(fault == "marker", Ordering::Release);
        let receipt = known(w.submit(&owner, request(0)).await);
        assert!(
            receipt.publication_pending(),
            "RUNNING_PUBLICATION_DEBT: {fault}"
        );
        assert!(
            receipt.published_commit().is_none(),
            "RUNNING_NO_SUCCESS_WITH_DEBT: {fault}"
        );
        assert_eq!(
            receipt.completion_pending(),
            fault == "checkpoint",
            "RUNNING_AUDIT_DEBT: {fault}"
        );
        assert_eq!(history_count(&f), 1, "RUNNING_KNOWN_COMMITTED_WITH_DEBT");
        let published = w.bus.current_snapshot();
        assert_eq!(
            published.version.get(),
            u64::from(fault == "marker"),
            "RUNNING_SNAPSHOT_MARKER_ORDER"
        );
        let next = w.submit(&owner, request(published.version.get())).await;
        assert!(
            matches!(next, NetconfMutationResult::Refused(ref error) if error.code == CommitErrorCode::RecoveryRequired),
            "RUNNING_DEBT_FENCES_MUTATION: {fault}"
        );
        assert_eq!(
            f.provider.active.load(Ordering::Acquire),
            1,
            "RUNNING_FENCE_BEFORE_REENCRYPTION"
        );
        f.checkpoint
            .fail_after_effect
            .store(false, Ordering::Release);
        f.provider.fail_lookup.store(false, Ordering::Release);
        w.publication.fail_marker.store(false, Ordering::Release);
        let recovered = known(
            w.audit
                .recover(receipt.recovery_handle(), &principal())
                .await,
        );
        assert_eq!(recovered.outcome(), receipt.outcome());
        exact_readback(&f, &w, &recovered, "revision-1").await;
        let next = known(w.submit(&owner, request(1)).await);
        exact_readback(&f, &w, &next, "revision-2").await;
        assert_eq!(f.provider.active.load(Ordering::Acquire), 2);
        drop(owner);
        w.close().await;
        f.close().await;
    }
}

#[tokio::test]
async fn running_worker_unresolved_publication_makes_drain_recovery_required() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    w.publication.fail_marker.store(true, Ordering::Release);
    let receipt = known(w.submit(&owner, request(0)).await);
    assert!(receipt.publication_pending());
    drop(owner);
    assert_eq!(
        w.audit.shutdown().await.unwrap(),
        NetconfWorkerExit::RecoveryRequired,
        "RUNNING_DEBT_DRAIN_REFUSAL"
    );
    assert_eq!(history_count(&f), 1);
    // A new worker cannot borrow publication acknowledgement from the old bus.
    let recovered_worker = Worker::new(&f).await;
    let restored = known(
        recovered_worker
            .audit
            .recover(receipt.recovery_handle(), &principal())
            .await,
    );
    exact_readback(&f, &recovered_worker, &restored, "revision-1").await;
    recovered_worker.close().await;
    drop(w);
    f.close().await;
}

#[tokio::test]
async fn running_worker_frozen_head_mismatch_refuses_before_provider() {
    let f = Fixture::new().await;
    let current = Worker::new(&f).await;
    let owner = current.audit.open_session(&principal()).await.unwrap();
    let applied = known(current.submit(&owner, request(0)).await);
    exact_readback(&f, &current, &applied, "revision-1").await;
    // A second genuine worker with a stale bootstrap projection shares the
    // store, not the first worker's session or publication acknowledgement.
    let stale = Worker::new(&f).await;
    let stale_owner = stale.audit.open_session(&principal()).await.unwrap();
    let before = f.rows();
    let calls = f.provider.calls();
    refused(
        stale.submit(&stale_owner, request(0)).await,
        "RUNNING_FROZEN_BASE_REFUSED",
    );
    assert_eq!(
        f.provider.calls(),
        calls,
        "RUNNING_FROZEN_HEAD_BEFORE_PROVIDER"
    );
    assert_eq!(f.rows(), before, "RUNNING_FROZEN_HEAD_NO_INTENT");
    assert_eq!(stale.bus.current_snapshot().version, ConfigVersion::INITIAL);
    // This detector isolates stale-base refusal. Drain one owner at a time so
    // concurrent cleanup admission is exercised by its own regression case.
    drop(stale_owner);
    stale.close().await;
    drop(owner);
    current.close().await;
    f.close().await;
}

#[tokio::test]
async fn running_worker_recovery_authenticates_exact_original_readback() {
    let f = Fixture::new().await;
    let w = Worker::new(&f).await;
    let owner = w.audit.open_session(&principal()).await.unwrap();
    let first = known(w.submit(&owner, request(0)).await);
    exact_readback(&f, &w, &first, "revision-1").await;
    let first_tx = first.published_commit().unwrap().tx_id;
    // Base read remains the genuine first transaction. After the second effect,
    // the publication port returns that same genuine, but wrong, original.
    *w.publication.wrong_readback.lock().unwrap() = Some(first_tx);
    let second = known(w.submit(&owner, request(1)).await);
    assert_eq!(history_count(&f), 2);
    assert!(
        second.publication_pending(),
        "RUNNING_EXACT_ORIGINAL_READBACK_AUTHENTICATION"
    );
    assert!(second.published_commit().is_none());
    assert_eq!(w.bus.current_snapshot().tx_id, Some(first_tx));
    let still_owed = known(
        w.audit
            .recover(second.recovery_handle(), &principal())
            .await,
    );
    assert!(still_owed.publication_pending());
    assert_eq!(still_owed.outcome(), second.outcome());
    *w.publication.wrong_readback.lock().unwrap() = None;
    let recovered = known(
        w.audit
            .recover(second.recovery_handle(), &principal())
            .await,
    );
    exact_readback(&f, &w, &recovered, "revision-2").await;
    assert_eq!(
        f.provider.active.load(Ordering::Acquire),
        2,
        "RUNNING_ORIGINAL_RECOVERY_NO_REENCRYPTION"
    );
    drop(owner);
    w.close().await;
    f.close().await;
}

#[tokio::test]
async fn running_worker_later_incarnation_keeps_known_result_and_publication_debt() {
    let f = Fixture::new().await;
    let original_worker = Worker::new(&f).await;
    let owner = original_worker
        .audit
        .open_session(&principal())
        .await
        .unwrap();
    let first = known(original_worker.submit(&owner, request(0)).await);
    let second = known(original_worker.submit(&owner, request(1)).await);
    exact_readback(&f, &original_worker, &second, "revision-2").await;

    let authorizer = Arc::new(Authorizer::default());
    let publication = Arc::new(PublicationStore {
        inner: f.encrypted.clone(),
        checkpoint: f.checkpoint.clone(),
        fail_marker: AtomicBool::new(false),
        wrong_readback: Mutex::new(None),
    });
    let bus = ConfigBus::restore_or_new_with_authorizer(
        Settings {
            label: "initial".into(),
        },
        publication.clone(),
        authorizer.clone(),
    )
    .await
    .unwrap();
    let audit = bus.required_netconf_audit().unwrap();
    let later = Worker {
        bus,
        audit,
        authorizer,
        publication,
    };
    let later_owner = later.audit.open_session(&principal()).await.unwrap();
    let before = later.bus.current_snapshot();
    assert_eq!(before.version.get(), 2);
    let recovered = known(
        later
            .audit
            .recover(first.recovery_handle(), &principal())
            .await,
    );
    assert_eq!(
        recovered.outcome(),
        first.outcome(),
        "RUNNING_LATER_PROJECTION_PRESERVES_KNOWN"
    );
    assert!(
        recovered.publication_pending(),
        "RUNNING_NO_FOREIGN_INCARNATION_ACK"
    );
    assert!(recovered.published_commit().is_none());
    let after = later.bus.current_snapshot();
    assert_eq!(
        after.tx_id, before.tx_id,
        "RUNNING_NO_PROJECTION_REGRESSION"
    );
    assert_eq!(after.version, before.version);
    assert_eq!(after.config.as_ref(), before.config.as_ref());
    let next = later.submit(&later_owner, request(2)).await;
    assert!(
        matches!(next, NetconfMutationResult::Refused(ref error) if error.code == CommitErrorCode::RecoveryRequired),
        "RUNNING_LATER_PROJECTION_RETAINS_DEBT"
    );
    assert_eq!(history_count(&f), 2);
    assert_eq!(f.provider.active.load(Ordering::Acquire), 2);
    // The original worker may still acknowledge its own historical publication.
    let original_ack = known(
        original_worker
            .audit
            .recover(first.recovery_handle(), &principal())
            .await,
    );
    assert_eq!(
        original_ack.published_commit().unwrap().tx_id,
        first.published_commit().unwrap().tx_id
    );
    drop(later_owner);
    assert_eq!(
        later.audit.shutdown().await.unwrap(),
        NetconfWorkerExit::RecoveryRequired
    );
    drop(later);
    drop(owner);
    original_worker.close().await;
    f.close().await;
}
