#![cfg(feature = "required-netconf-audit")]
//! Preparation-only attribution over a real retained single-member authority.
//! Provider counts observe the pre-encryption boundary; persisted rows and
//! decrypted SDK readback, not callbacks, determine whether an effect occurred.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_config_bus::{
    CommitWrite, ConfirmedCommitResolution, EncryptingManagedDatastore, InMemoryManagedDatastore,
    ManagedDatastore, SealedConfig, StoreErrorCode, StoredConfig, StoredRequestFingerprint,
    StoredRequestMode,
};
use opc_config_bus_consensus::{ConfigAuditPolicy, RaftManagedDatastore};
use opc_config_model::{
    ConfigError, ConfigOperation, IdempotencyKey, OpcConfig, RequestId, RequestSource,
    TransportType, TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity,
    YangPath,
};
use opc_key::{KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome};
use opc_persist::audit_authority::continuity::{
    AuditCheckpoint, AuditCheckpointAdvance, AuditCheckpointPort, AuditContinuityPolicy,
    AuditKeyRing, AuditSigningKey,
};
use opc_persist::audit_authority::{
    AuditAdmission, AuditAuthorityError, AuditCaller, AuditLedgerLimits, AuditOperationReceipt,
    AuditOperationState, AuditPrivacyKey, NetconfAppliedOutcome, NetconfDeviceOwner,
};
use opc_persist::{
    AuditKey, CommitSource, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, ConfigStore, ConsensusConfigStore, ManagementAuditEventRecord,
    ManagementAuditInstant, ManagementAuditOperationCode, ManagementAuditOutcomeCode,
    ManagementAuditTimeSourceCode, ManagementAuditTransportCode, RetainedConfigBinding,
    RetainedConfigDurability, RetainedConfigOptions, RetainedConfigProfile, SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use serde::{Deserialize, Serialize};

const LIFETIME: Duration = Duration::from_secs(60);

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
        Ok(())
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
        self.inner.get_active_key(purpose, tenant).await
    }
    async fn get_key_by_id(&self, id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.lookup.fetch_add(1, Ordering::AcqRel);
        self.inner.get_key_by_id(id).await
    }
    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.rotations.fetch_add(1, Ordering::AcqRel);
        self.inner.rotate_key(purpose, tenant).await
    }
}

#[derive(Default)]
struct Checkpoint(Mutex<Option<AuditCheckpoint>>);

#[async_trait::async_trait]
impl AuditCheckpointPort for Checkpoint {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn compare_advance(
        &self,
        _: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        let mut current = self.0.lock().unwrap();
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

fn audit_operation(operation: ConfigOperation) -> AuditOperation {
    match operation {
        ConfigOperation::Replace => AuditOperation::Replace,
        ConfigOperation::Patch => AuditOperation::Update,
        ConfigOperation::Delete => AuditOperation::Delete,
        ConfigOperation::Rollback => AuditOperation::Rollback,
    }
}

fn write(
    parent: Option<TxId>,
    version: u64,
    transport: TransportType,
    operation: ConfigOperation,
) -> StoredConfig<Settings> {
    let mut record = StoredConfig::new(
        TxId::new(),
        ConfigVersion::new(version),
        principal(),
        RequestSource::Northbound,
        Settings {
            label: format!("revision-{version}"),
        },
    );
    record.parent_tx_id = parent;
    record.request_id = Some(RequestId::new());
    record.idempotency_key =
        Some(IdempotencyKey::new(format!("synthetic-replay-{version}")).unwrap());
    record.request_fingerprint = Some(StoredRequestFingerprint {
        operation,
        mode: StoredRequestMode::Commit,
        transport,
        changed_paths: vec![YangPath::new("/synthetic:settings/label").unwrap()],
        base_version: Some(ConfigVersion::new(version - 1)),
    });
    record
}

fn event(record: &StoredConfig<Settings>) -> AuditEvent {
    let fingerprint = record.request_fingerprint.as_ref().unwrap();
    AuditEvent::new(
        record.request_id.unwrap(),
        &record.principal,
        fingerprint.transport,
        audit_operation(fingerprint.operation),
        AuditOutcome::Intent,
    )
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
    privacy: Arc<AuditPrivacyKey>,
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
        let checkpoint = Arc::new(Checkpoint::default());
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
            privacy,
            device,
        }
    }

    fn caller(&self) -> AuditCaller {
        AuditCaller::project(
            self.privacy.as_ref(),
            principal().tenant.as_str(),
            &opc_mgmt_audit::principal_descriptor(&principal()),
        )
        .unwrap()
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
        (rows, self.checkpoint.0.lock().unwrap().clone())
    }

    async fn close(self) {
        drop(self.encrypted);
        drop(self.raft);
        self.store.shutdown().await.unwrap();
        drop(self.store);
        drop(self.directory);
    }
}

#[tokio::test]
async fn mismatched_running_preparation_refuses_before_provider_and_intent() {
    let f = Fixture::new().await;
    let before = f.rows();
    for case in [
        "record-principal",
        "record-roles",
        "record-tenant",
        "authenticated-principal",
        "event-principal",
        "event-tenant",
        "request",
        "transport",
        "operation",
        "outcome",
        "transaction",
        "non-netconf",
        "non-northbound",
        "missing-context",
        "schema",
        "confirmed-deadline",
        "confirmed-mode",
        "rollback-operation",
        "resolution",
    ] {
        let mut record = write(None, 1, TransportType::NetconfSsh, ConfigOperation::Replace);
        let mut intent = event(&record);
        let mut authenticated = principal();
        let mut resolution = None;
        match case {
            "record-principal" => {
                record.principal.identity = WorkloadIdentity::User("synthetic-other".into())
            }
            "record-roles" => record.principal = record.principal.with_roles(["other-role"]),
            "record-tenant" => {
                record.principal.tenant = TenantId::new("synthetic-other-tenant").unwrap()
            }
            "authenticated-principal" => {
                authenticated.identity = WorkloadIdentity::User("synthetic-other".into())
            }
            "event-principal" => intent.principal = "user:synthetic-other".into(),
            "event-tenant" => intent.tenant = "synthetic-other-tenant".into(),
            "request" => intent.request_id = RequestId::new(),
            "transport" => intent.transport = TransportType::NetconfTls,
            "operation" => intent.operation = AuditOperation::Update,
            "outcome" => intent.outcome = AuditOutcome::Success,
            "transaction" => intent = intent.with_tx_id(TxId::new().to_string()).unwrap(),
            "non-netconf" => {
                record.request_fingerprint.as_mut().unwrap().transport = TransportType::Gnmi;
                intent.transport = TransportType::Gnmi;
            }
            "non-northbound" => record.source = RequestSource::Internal,
            "missing-context" => record.request_id = None,
            "schema" => record.schema_digest = SchemaDigest::from_bytes([0x44; 32]),
            "confirmed-deadline" => record.confirmed_deadline = Some(Timestamp::now_utc()),
            "confirmed-mode" => {
                record.request_fingerprint.as_mut().unwrap().mode =
                    StoredRequestMode::CommitConfirmed { timeout: LIFETIME }
            }
            "rollback-operation" => {
                record.request_fingerprint.as_mut().unwrap().operation = ConfigOperation::Rollback;
                intent.operation = AuditOperation::Rollback;
            }
            "resolution" => {
                let pending_tx_id = TxId::new();
                record.parent_tx_id = Some(pending_tx_id);
                resolution = Some(ConfirmedCommitResolution::Confirm { pending_tx_id });
            }
            _ => unreachable!(),
        }
        let commit = match resolution {
            Some(resolution) => CommitWrite::resolving(record, resolution).unwrap(),
            None => CommitWrite::new(record),
        };
        let result = f
            .encrypted
            .prepare_netconf_running_commit(commit, &authenticated, &intent)
            .await;
        assert_eq!(
            f.provider.calls(),
            0,
            "RUNNING_PREPARATION_NO_PROVIDER: {case}"
        );
        assert!(result.is_err(), "RUNNING_PREPARATION_ATTRIBUTION: {case}");
        assert_eq!(f.rows(), before, "RUNNING_PREPARATION_NO_INTENT: {case}");
        assert!(f.store.load_latest().await.unwrap().is_none());
    }
    f.close().await;
}

#[tokio::test]
async fn running_preparation_is_effect_free_and_original_sdk_apply_has_exact_readback() {
    let f = Fixture::new().await;
    let session = f
        .store
        .open_netconf_session(&f.device, f.caller())
        .await
        .unwrap();
    let mut parent = None;
    for (index, (transport, operation)) in [
        (TransportType::NetconfSsh, ConfigOperation::Replace),
        (TransportType::NetconfTls, ConfigOperation::Patch),
        (TransportType::NetconfSsh, ConfigOperation::Delete),
    ]
    .into_iter()
    .enumerate()
    {
        let version = index as u64 + 1;
        let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
        assert_eq!(frozen.tx_id(), parent);
        let record = write(parent, version, transport, operation);
        let intent = event(&record).with_tx_id(record.tx_id.to_string()).unwrap();
        let before = f.rows();
        let calls = f.provider.calls();
        // Explicitly exercise Arc's trait forwarding, including a trait object.
        let port: Arc<dyn ManagedDatastore<Settings>> = f.encrypted.clone();
        let attested = ManagedDatastore::prepare_netconf_running_commit(
            &port,
            CommitWrite::new(record.clone()),
            &principal(),
            &intent,
        )
        .await
        .unwrap();
        assert_eq!(
            f.provider.calls(),
            calls + 1,
            "RUNNING_PREPARATION_ENCRYPT_ONCE"
        );
        assert_eq!(f.rows(), before, "RUNNING_PREPARATION_ONLY");
        let exact = attested.record().clone();
        assert_eq!(
            exact.source,
            CommitSource::Netconf,
            "RUNNING_PREPARATION_SOURCE"
        );
        assert_eq!(exact.tx_id, record.tx_id);
        assert_eq!(exact.parent_tx_id, parent);
        assert_eq!(exact.version, record.version);
        assert_eq!(exact.schema_digest, record.schema_digest);
        assert_eq!(exact.plaintext_digest.len(), 32);
        assert!(!exact.encrypted_blob.is_empty());
        assert!(attested.confirmed_resolution().is_none());
        let prepared = f
            .store
            .prepare_netconf_running_replacement(
                &session,
                &frozen,
                attested,
                f.privacy.as_ref(),
                &sdk_event(&intent),
                LIFETIME,
            )
            .await
            .unwrap();
        assert_eq!(f.rows(), before, "RUNNING_SDK_PREPARATION_ONLY");
        let admitted = applied(
            f.store
                .admit_netconf_running_replacement_local(&session, &prepared, f.caller())
                .await,
        );
        assert_eq!(admitted.state(), AuditOperationState::Intent);
        let result = applied(
            f.store
                .submit_netconf_target_local(&prepared, &admitted, f.caller())
                .await,
        );
        assert!(
            matches!(result.state(), AuditOperationState::TargetV1(target)
            if matches!(target.outcome(), NetconfAppliedOutcome::RunningReplaced { tx_id, running_version, plaintext_digest }
                if tx_id == exact.tx_id && running_version == version && plaintext_digest.as_slice() == exact.plaintext_digest))
        );
        let recovered = f
            .store
            .recover_netconf_target(prepared.handle(), f.caller())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.encode().unwrap(), prepared.encode().unwrap());
        let repeated = applied(
            f.store
                .submit_netconf_target_local(&recovered, &admitted, f.caller())
                .await,
        );
        assert_eq!(repeated.state(), result.state());
        f.store
            .complete_required_audit_outcome(&result, f.caller())
            .await
            .unwrap();
        let settled = f
            .store
            .lookup_audit_operation(prepared.handle(), f.caller())
            .await
            .unwrap()
            .unwrap();
        assert!(settled.terminal_recorded());
        assert_eq!(
            f.provider.calls(),
            calls + 1,
            "RUNNING_ORIGINAL_NO_REENCRYPTION"
        );
        let actual = f.store.load_latest().await.unwrap().unwrap();
        assert_eq!(actual.record, exact, "RUNNING_ATTESTED_EXACT_RECORD");
        let decoded = f.encrypted.load_latest().await.unwrap().unwrap();
        assert_eq!(decoded.tx_id, record.tx_id);
        assert_eq!(decoded.version, record.version);
        assert_eq!(decoded.parent_tx_id, record.parent_tx_id);
        assert_eq!(decoded.principal, record.principal);
        assert_eq!(decoded.source, record.source);
        assert_eq!(
            decoded.config, record.config,
            "RUNNING_ADAPTER_DECRYPTED_READBACK"
        );
        assert_eq!(decoded.request_id, record.request_id);
        assert_eq!(decoded.request_fingerprint, record.request_fingerprint);
        assert_eq!(decoded.idempotency_key, record.idempotency_key);
        assert_eq!(
            decoded.plaintext_digest.unwrap().as_slice(),
            exact.plaintext_digest
        );
        let replay = f
            .encrypted
            .load_by_idempotency_key(record.idempotency_key.as_ref().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            replay.tx_id, record.tx_id,
            "RUNNING_ORIGINAL_REPLAY_BINDING"
        );
        assert_eq!(replay.config, record.config);
        let conn = rusqlite::Connection::open_with_flags(
            f.directory.path().join("authority.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let count: u64 = conn
            .query_row("SELECT count(*) FROM config_history", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, version, "RUNNING_ORIGINAL_APPLIED_ONCE");
        parent = Some(record.tx_id);
    }
    f.close().await;
}

#[tokio::test]
async fn running_preparation_requires_real_attached_netconf_authority() {
    let f = Fixture::new().await;
    let before = f.rows();
    let record = write(None, 1, TransportType::NetconfSsh, ConfigOperation::Replace);
    let intent = event(&record);
    let plaintext = InMemoryManagedDatastore::<Settings>::new();
    let plain = plaintext
        .prepare_netconf_running_commit(CommitWrite::new(record.clone()), &principal(), &intent)
        .await
        .unwrap_err();
    assert_eq!(plain.code, StoreErrorCode::Unavailable);
    assert!(plaintext.load_latest().await.unwrap().is_none());
    let unattached = EncryptingManagedDatastore::new(f.raft.clone(), f.provider.clone());
    let result = unattached
        .prepare_netconf_running_commit(CommitWrite::new(record.clone()), &principal(), &intent)
        .await;
    assert_eq!(f.provider.calls(), 0, "RUNNING_UNATTACHED_NO_PROVIDER");
    assert_eq!(result.unwrap_err().code, StoreErrorCode::Unavailable);
    let ordinary = Arc::new(RaftManagedDatastore::<Settings>::new(f.store.clone()));
    // An unattached sealed adapter must refuse before considering a claim.
    // This marker intentionally has no fresh AEAD authority.
    let sealed = record
        .clone()
        .with_config(SealedConfig::<Settings>::new(record.schema_digest));
    let rejected = ordinary
        .prepare_netconf_running_commit(CommitWrite::new(sealed), &principal(), &intent)
        .await
        .unwrap_err();
    assert_eq!(
        rejected.code,
        StoreErrorCode::Unavailable,
        "RUNNING_SEALED_UNSUPPORTED"
    );
    let without_netconf = EncryptingManagedDatastore::new(ordinary, f.provider.clone());
    assert!(without_netconf.with_required_netconf_audit().await.is_err());
    let candidate = EncryptingManagedDatastore::with_store_kind(
        f.raft.clone(),
        f.provider.clone(),
        "candidate",
    );
    assert!(candidate.with_required_netconf_audit().await.is_err());
    assert_eq!(f.provider.calls(), 0);
    assert_eq!(f.rows(), before, "RUNNING_UNSUPPORTED_NO_INTENT");
    assert!(f.store.load_latest().await.unwrap().is_none());
    f.close().await;
}
