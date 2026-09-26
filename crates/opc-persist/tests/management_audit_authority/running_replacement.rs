//! Synthetic native single-member tests of the session-bound Running contract.
//! The real SDK authority, encrypted history and independently retained checkpoint
//! are the observations; no mock Running datastore or callback is an effect oracle.

use super::*;
use crate::audit_authority::{continuity::*, *};
use crate::{
    AuditKey, ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions, RetainedConfigProfile,
};
use opc_key::{ConfigAad, EnvelopeAad};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use std::sync::Mutex;

const TENANT: &str = "synthetic-running";
const PRINCIPAL: &str = "spiffe://test.invalid/tenant/synthetic-running/operator";
const LIFETIME: Duration = Duration::from_secs(60);
const WAIT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Checkpoint {
    value: Mutex<Option<AuditCheckpoint>>,
    unavailable: AtomicBool,
    pause: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait]
impl AuditCheckpointPort for Checkpoint {
    async fn load(
        &self,
        _: super::super::ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        // Delay delivery of a real checkpoint observation, not the effect or
        // a fabricated SDK response. A concurrent advance cannot rewrite it.
        let observed = self.value.lock().unwrap().clone();
        if self.pause.swap(false, Ordering::AcqRel) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if self.unavailable.load(Ordering::Acquire) {
            return Err(AuditAuthorityError::Unavailable);
        }
        Ok(observed)
    }
    async fn compare_advance(
        &self,
        _: super::super::ConfigConsensusIdentity,
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
        Ok(AuditCheckpointAdvance::Applied)
    }
}
fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0x53; 32]).unwrap()
}
fn caller() -> AuditCaller {
    AuditCaller::project(&privacy(), TENANT, PRINCIPAL).unwrap()
}
fn event(
    request: u8,
    operation: ManagementAuditOperationCode,
    tx: Option<TxId>,
) -> ManagementAuditEventRecord {
    let tx = tx.map(|tx| tx.to_string());
    ManagementAuditEventRecord::try_new(
        [request; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        TENANT,
        PRINCIPAL,
        if request == 1 {
            ManagementAuditTransportCode::Internal
        } else {
            ManagementAuditTransportCode::NetconfSsh
        },
        operation,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/synthetic:configuration"],
        tx.as_deref(),
    )
    .unwrap()
}
fn applied(value: AuditAdmission) -> AuditOperationReceipt {
    match value {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected original authoritative result: {other:?}"),
    }
}
fn refused(value: AuditAdmission) {
    assert!(
        matches!(value, AuditAdmission::Rejected(_)),
        "RUNNING_REFUSAL: {value:?}"
    );
}
struct Fixture {
    store: ConsensusConfigStore,
    device: NetconfDeviceOwner,
    checkpoint: Arc<Checkpoint>,
    provider: opc_key::MemoryKeyProvider,
    dir: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let node = super::super::ConfigConsensusNodeId::new(1).unwrap();
        let identity = super::super::ConfigConsensusIdentity::new(
            super::super::ConfigConsensusClusterId::from_bytes([0x31; 32]),
            super::super::ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
            super::super::ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
        let backend = SqliteBackend::provision_config_authority(
            RetainedConfigOptions::new(
                dir.path().join("authority.sqlite"),
                RetainedConfigBinding::new(topology.clone(), [0x41; 32], [0x42; 32])
                    .unwrap()
                    .with_profile(RetainedConfigProfile::NetconfTargetsV1),
                RetainedConfigDurability::Ephemeral,
                64 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap(),
            AuditKey::new([0x51; 32]).unwrap(),
        )
        .await
        .unwrap();
        let checkpoint = Arc::new(Checkpoint::default());
        let policy = AuditContinuityPolicy::new(
            AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x52; 32]).unwrap()]).unwrap(),
            checkpoint.clone(),
            1,
            1,
        )
        .unwrap();
        let store = ConsensusConfigStore::open_with_audit_continuity(
            topology,
            backend,
            dir.path().join("snapshots"),
            BTreeMap::new(),
            policy,
        )
        .await
        .unwrap();
        store.initialize_cluster().await.unwrap();
        store
            .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(96, 32).unwrap())
            .await
            .unwrap();
        let prepared = store
            .prepare_netconf_device(
                &privacy(),
                &event(1, ManagementAuditOperationCode::Exec, None),
                LIFETIME,
            )
            .await
            .unwrap();
        let intent = applied(
            store
                .admit_netconf_target_local(prepared.mutation(), caller())
                .await,
        );
        let receipt = applied(
            store
                .submit_netconf_target_local(prepared.mutation(), &intent, caller())
                .await,
        );
        store
            .complete_required_audit_outcome(&receipt, caller())
            .await
            .unwrap();
        let device = store
            .claim_netconf_device_owner(&prepared, &receipt, caller())
            .await
            .unwrap();
        let provider = opc_key::MemoryKeyProvider::new();
        provider
            .insert_active_key(
                opc_key::KeyId::new("synthetic-running-key").unwrap(),
                opc_key::KeyPurpose::Config,
                TenantId::new(TENANT).unwrap(),
                zeroize::Zeroizing::new([0x61; 32]),
            )
            .unwrap();
        Self {
            store,
            device,
            checkpoint,
            provider,
            dir,
        }
    }
    async fn session(&self) -> NetconfSessionOwner {
        self.store
            .open_netconf_session(&self.device, caller())
            .await
            .unwrap()
    }
    async fn commit(
        &self,
        frozen: &NetconfRunningEditRead,
        plaintext: &[u8],
    ) -> AttestedConfigCommit {
        self.commit_at(
            frozen.tx_id(),
            frozen.running_base_version() + 1,
            plaintext,
            "running",
            TENANT,
        )
        .await
    }
    async fn commit_at(
        &self,
        parent: Option<TxId>,
        version: u64,
        plaintext: &[u8],
        store_kind: &str,
        tenant: &str,
    ) -> AttestedConfigCommit {
        let mut record = CommitRecord {
            tx_id: TxId::new(),
            parent_tx_id: parent,
            version: ConfigVersion::new(version),
            committed_at: Timestamp::now_utc(),
            principal: PRINCIPAL.to_owned(),
            source: crate::CommitSource::Netconf,
            schema_digest: SchemaDigest::from_bytes([0x62; 32]),
            plaintext_digest: Sha256::digest(plaintext).to_vec(),
            encrypted_blob: Vec::new(),
            rollback_point: false,
            confirmed_deadline: None,
        };
        let aad = EnvelopeAad::config(
            TenantId::new(tenant).unwrap(),
            version,
            ConfigAad::new(
                record.tx_id,
                parent,
                record.committed_at,
                &record.principal,
                record.schema_digest,
                store_kind,
            )
            .unwrap(),
        );
        let encrypted = opc_crypto::encrypt_attested_envelope(&self.provider, &aad, plaintext)
            .await
            .unwrap();
        record.encrypted_blob = encrypted.encoded().to_vec();
        AttestedConfigCommit::try_new(record, Vec::new(), encrypted.claim().unwrap()).unwrap()
    }
    async fn prepare(
        &self,
        session: &NetconfSessionOwner,
        frozen: &NetconfRunningEditRead,
        request: u8,
        plaintext: &[u8],
    ) -> crate::audit_authority::PreparedTargetMutation {
        let commit = self.commit(frozen, plaintext).await;
        let event = event(
            request,
            ManagementAuditOperationCode::Replace,
            Some(commit.record().tx_id),
        );
        self.store
            .prepare_netconf_running_replacement(
                session,
                frozen,
                commit,
                &privacy(),
                &event,
                LIFETIME,
            )
            .await
            .expect("RUNNING_PREPARATION: original attested replacement must prepare")
    }
    async fn apply(
        &self,
        session: &NetconfSessionOwner,
        prepared: &crate::audit_authority::PreparedTargetMutation,
    ) -> AuditOperationReceipt {
        let intent = applied(
            self.store
                .admit_netconf_running_replacement_local(session, prepared, caller())
                .await,
        );
        assert_eq!(intent.state(), AuditOperationState::Intent);
        applied(
            self.store
                .submit_netconf_target_local(prepared, &intent, caller())
                .await,
        )
    }
    async fn settle(&self, receipt: &AuditOperationReceipt) {
        self.store
            .complete_required_audit_outcome(receipt, caller())
            .await
            .unwrap();
    }
    async fn lock(&self, session: &NetconfSessionOwner, request: u8) -> NetconfLockLease {
        let prepared = self
            .store
            .prepare_netconf_lock_acquisition(
                session,
                NetconfLockDatastore::Running,
                &privacy(),
                &event(request, ManagementAuditOperationCode::Exec, None),
                LIFETIME,
            )
            .await
            .unwrap();
        let intent = applied(
            self.store
                .admit_netconf_target_local(prepared.mutation(), caller())
                .await,
        );
        let receipt = applied(
            self.store
                .submit_netconf_target_local(prepared.mutation(), &intent, caller())
                .await,
        );
        self.settle(&receipt).await;
        self.store
            .claim_netconf_lock_lease(&prepared, &receipt, caller())
            .await
            .unwrap()
    }
    async fn unlock(&self, session: &NetconfSessionOwner, lease: &NetconfLockLease, request: u8) {
        let prepared = self
            .store
            .prepare_netconf_lock_release(
                session,
                lease,
                &privacy(),
                &event(request, ManagementAuditOperationCode::Exec, None),
                LIFETIME,
            )
            .await
            .unwrap();
        let intent = applied(
            self.store
                .admit_netconf_target_local(prepared.mutation(), caller())
                .await,
        );
        let receipt = applied(
            self.store
                .submit_netconf_target_local(prepared.mutation(), &intent, caller())
                .await,
        );
        self.settle(&receipt).await;
    }
    async fn assert_head(&self, expected: &CommitRecord, plaintext: &[u8]) {
        let actual = self.store.load_latest().await.unwrap().unwrap();
        assert_eq!(&actual.record, expected, "RUNNING_EXACT_RECORD");
        let envelope =
            opc_crypto::CryptoEnvelopeRef::decode(&actual.record.encrypted_blob).unwrap();
        let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
        let decoded =
            opc_crypto::decrypt_envelope(&self.provider, &aad, &actual.record.encrypted_blob)
                .await
                .unwrap();
        assert_eq!(decoded.as_slice(), plaintext, "RUNNING_ENCRYPTED_READBACK");
    }
    async fn rows(&self) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        let conn = self.store.inner.backend.conn();
        let conn = conn.lock().await;
        [
            "config_history",
            "config_raft_management_audit",
            "config_netconf_profile",
            "config_netconf_targets",
            "config_netconf_lifecycle",
        ]
        .into_iter()
        .map(|table| {
            let mut query = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
                .unwrap();
            let columns = query.column_count();
            let rows = query
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                })
                .unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        })
        .collect()
    }
    async fn close(self) {
        self.store.shutdown().await.unwrap();
        drop(self.store);
        drop(self.dir);
    }

    async fn reopen(self) -> Self {
        let Self {
            store,
            device,
            checkpoint,
            provider,
            dir,
        } = self;
        let binding = store
            .inner
            .backend
            .retained_binding
            .as_ref()
            .unwrap()
            .clone();
        let topology = ConfigConsensusTopology::try_new(
            store.inner.identity,
            store.inner.local_node_id,
            BTreeSet::from([store.inner.local_node_id]),
        )
        .unwrap();
        store.shutdown().await.unwrap();
        drop(store);
        let backend = SqliteBackend::reopen_config_authority(
            RetainedConfigOptions::new(
                dir.path().join("authority.sqlite"),
                binding,
                RetainedConfigDurability::Ephemeral,
                64 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap(),
            AuditKey::new([0x51; 32]).unwrap(),
        )
        .await
        .unwrap();
        let policy = AuditContinuityPolicy::new(
            AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x52; 32]).unwrap()]).unwrap(),
            checkpoint.clone(),
            1,
            1,
        )
        .unwrap();
        let store = ConsensusConfigStore::open_with_audit_continuity(
            topology,
            backend,
            dir.path().join("snapshots"),
            BTreeMap::new(),
            policy,
        )
        .await
        .unwrap();
        store.initialize_cluster().await.unwrap();
        Self {
            store,
            device,
            checkpoint,
            provider,
            dir,
        }
    }
}
fn record(prepared: &crate::audit_authority::PreparedTargetMutation) -> &CommitRecord {
    &prepared
        .effect
        .encrypted_payload
        .as_ref()
        .unwrap()
        .running()
        .unwrap()
        .0
        .record
}
fn running_result(receipt: &AuditOperationReceipt) -> NetconfTargetResult {
    match receipt.state() {
        AuditOperationState::TargetV1(result) => result,
        other => panic!("not a target result: {other:?}"),
    }
}

#[tokio::test]
async fn running_replacement_empty_base_and_exact_lock_owner_persist_changed_content() {
    let f = Fixture::new().await;
    let owner = f.session().await;
    let foreign = f.session().await;
    let empty = f.store.read_netconf_running_edit(&owner).await.unwrap();
    assert_eq!(empty.tx_id(), None);
    assert_eq!(empty.running_base_version(), 0);
    assert!(empty.record().is_none());
    let first = f
        .prepare(&owner, &empty, 2, b"first running configuration")
        .await;
    let first_receipt = f.apply(&owner, &first).await;
    assert!(
        matches!(running_result(&first_receipt).outcome(), NetconfAppliedOutcome::RunningReplaced { tx_id, running_version: 1, plaintext_digest }
        if tx_id == record(&first).tx_id && plaintext_digest.as_slice() == record(&first).plaintext_digest)
    );
    f.assert_head(record(&first), b"first running configuration")
        .await;
    f.settle(&first_receipt).await;
    let lease = f.lock(&owner, 3).await;
    let before = f.rows().await;
    assert!(
        matches!(
            f.store.read_netconf_running_edit(&foreign).await,
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "RUNNING_FOREIGN_SESSION_LOCK"
    );
    assert_eq!(f.rows().await, before);
    let frozen = f.store.read_netconf_running_edit(&owner).await.unwrap();
    assert_eq!(frozen.record(), Some(record(&first)));
    let changed = f
        .prepare(&owner, &frozen, 4, b"changed content is not a copy")
        .await;
    let applied = f.apply(&owner, &changed).await;
    f.assert_head(record(&changed), b"changed content is not a copy")
        .await;
    f.settle(&applied).await;
    f.store
        .verify_netconf_lock_lease(&lease, caller())
        .await
        .unwrap();
    f.unlock(&owner, &lease, 5).await;
    assert!(f.store.read_netconf_running_edit(&foreign).await.is_ok());
    f.close().await;
}

#[tokio::test]
async fn running_replacement_stale_head_and_lock_are_refused_without_an_intent() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let stale = f.prepare(&session, &frozen, 2, b"stale").await;
    let first = f.prepare(&session, &frozen, 3, b"new head").await;
    let applied = f.apply(&session, &first).await;
    f.settle(&applied).await;
    let before = f.rows().await;
    refused(
        f.store
            .admit_netconf_running_replacement_local(&session, &stale, caller())
            .await,
    );
    let stale_commit = f.commit(&frozen, b"stale after head advance").await;
    assert!(
        f.store
            .prepare_netconf_running_replacement(
                &session,
                &frozen,
                stale_commit,
                &privacy(),
                &event(4, ManagementAuditOperationCode::Update, None),
                LIFETIME
            )
            .await
            .is_err(),
        "RUNNING_STALE_FROZEN_HEAD"
    );
    assert_eq!(f.rows().await, before);
    let current = f.store.read_netconf_running_edit(&session).await.unwrap();
    let before_lock = f
        .prepare(&session, &current, 5, b"old lock incarnation")
        .await;
    let lease = f.lock(&session, 6).await;
    f.unlock(&session, &lease, 7).await;
    let after_unlock = f.rows().await;
    refused(
        f.store
            .admit_netconf_running_replacement_local(&session, &before_lock, caller())
            .await,
    );
    assert_eq!(f.rows().await, after_unlock, "RUNNING_STALE_LOCK_NO_INTENT");
    f.assert_head(record(&first), b"new head").await;
    f.close().await;
}

#[tokio::test]
async fn running_replacement_requires_original_session_worker_and_authenticated_caller() {
    let f = Fixture::new().await;
    let other = Fixture::new().await;
    let session = f.session().await;
    let foreign = f.session().await;
    let wrong_worker = other.session().await;
    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let prepared = f.prepare(&session, &frozen, 2, b"bound original").await;
    let original =
        crate::audit_authority::PreparedTargetMutation::decode(&prepared.encode().unwrap())
            .unwrap();
    let before = f.rows().await;
    for actor in [&foreign, &wrong_worker] {
        refused(
            f.store
                .admit_netconf_running_replacement_local(actor, &original, caller())
                .await,
        );
        let commit = f.commit(&frozen, b"foreign actor").await;
        assert!(
            f.store
                .prepare_netconf_running_replacement(
                    actor,
                    &frozen,
                    commit,
                    &privacy(),
                    &event(3, ManagementAuditOperationCode::Replace, None),
                    LIFETIME
                )
                .await
                .is_err(),
            "RUNNING_FROZEN_SESSION"
        );
    }
    let wrong = AuditCaller::project(&privacy(), TENANT, "user:other").unwrap();
    refused(
        f.store
            .admit_netconf_running_replacement_local(&session, &original, wrong)
            .await,
    );
    refused(
        f.store
            .admit_netconf_target_local(&original, caller())
            .await,
    );
    assert_eq!(f.rows().await, before, "RUNNING_GENERIC_ADMISSION_BYPASS");
    session.invalidate();
    refused(
        f.store
            .admit_netconf_running_replacement_local(&session, &original, caller())
            .await,
    );
    refused(
        f.store
            .admit_netconf_target_local(&original, caller())
            .await,
    );
    assert!(f.store.read_netconf_running_edit(&session).await.is_err());
    assert_eq!(f.rows().await, before, "RUNNING_REVOKED_NO_INTENT");
    other.close().await;
    f.close().await;
}

#[tokio::test]
async fn running_replacement_revocation_during_preflight_is_definite_and_atomic() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let prepared = f
        .prepare(&session, &frozen, 2, b"revoked in preflight")
        .await;
    let before = f.rows().await;
    f.checkpoint.pause.store(true, Ordering::Release);
    let store = f.store.clone();
    let owner = session.clone();
    let original = prepared.clone();
    let pending = tokio::spawn(async move {
        store
            .admit_netconf_running_replacement_local(&owner, &original, caller())
            .await
    });
    tokio::time::timeout(WAIT, f.checkpoint.entered.notified())
        .await
        .unwrap();
    session.invalidate();
    f.checkpoint.release.notify_one();
    let result = tokio::time::timeout(WAIT, pending).await.unwrap().unwrap();
    assert!(
        matches!(
            result,
            AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
        ),
        "RUNNING_PREFLIGHT_REVOCATION: {result:?}"
    );
    assert_eq!(f.rows().await, before, "RUNNING_PREFLIGHT_NO_INTENT");
    f.close().await;
}

#[tokio::test]
async fn running_replacement_post_preflight_lock_change_retains_rejection_without_running_effect() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let prepared = f.prepare(&session, &frozen, 2, b"racing original").await;
    f.checkpoint.pause.store(true, Ordering::Release);
    let store = f.store.clone();
    let owner = session.clone();
    let original = prepared.clone();
    let pending = tokio::spawn(async move {
        store
            .admit_netconf_running_replacement_local(&owner, &original, caller())
            .await
    });
    tokio::time::timeout(WAIT, f.checkpoint.entered.notified())
        .await
        .unwrap();
    // The read-only target preflight has completed its transaction. While its
    // authentic checkpoint observation is in transit, another real command
    // changes the lock. No SDK callback or fabricated receipt drives this race.
    let lease = f.lock(&session, 3).await;
    let locked = f.rows().await;
    f.checkpoint.release.notify_one();
    let intent = applied(tokio::time::timeout(WAIT, pending).await.unwrap().unwrap());
    assert_eq!(intent.state(), AuditOperationState::Intent);
    let receipt = applied(
        f.store
            .submit_netconf_target_local(&prepared, &intent, caller())
            .await,
    );
    assert_eq!(
        receipt.state(),
        AuditOperationState::Rejected,
        "RUNNING_POST_PREFLIGHT_RACE_REJECTED"
    );
    assert!(!receipt.terminal_recorded());
    assert_eq!(
        f.store
            .lookup_audit_operation(prepared.handle(), caller())
            .await
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Rejected,
        "RUNNING_DURABLE_ORIGINAL_REJECTION"
    );
    let rejected = f.rows().await;
    assert_eq!(rejected[0], locked[0], "RUNNING_REJECTED_HISTORY_UNCHANGED");
    assert_eq!(
        rejected[2..],
        locked[2..],
        "RUNNING_REJECTED_TARGET_UNCHANGED"
    );
    assert!(f.store.load_latest().await.unwrap().is_none());
    f.store
        .verify_netconf_lock_lease(&lease, caller())
        .await
        .unwrap();
    f.settle(&receipt).await;
    f.unlock(&session, &lease, 4).await;
    f.close().await;
}

#[tokio::test]
async fn running_replacement_revocation_while_waiting_for_real_proposal_permit_never_enqueues() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let prepared = f
        .prepare(&session, &frozen, 2, b"revoked behind permit")
        .await;
    let before = f.rows().await;
    let held = f
        .store
        .inner
        .proposal_admission
        .clone()
        .acquire_many_owned(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS as u32)
        .await
        .unwrap();
    let request = derive_durable_request_id(
        f.store.inner.identity,
        b"netconf-target-intent",
        &prepared.handle.mac,
    );
    let command = ConfigMutationIntent::ManagementAudit(
        super::super::audit::AuditCommand::NetconfTarget(Box::new(
            super::super::audit_mutation::TargetAuditCommandV1::Admit(prepared),
        )),
    );
    {
        let pending =
            f.store
                .submit_request_on_local_leader_guarded(request, command, Some(&session));
        tokio::pin!(pending);
        tokio::select! { biased;
            _ = &mut pending => panic!("proposal bypassed its actual held permit"),
            _ = std::future::ready(()) => {}
        }
        session.invalidate();
        drop(held);
        assert!(
            matches!(
                tokio::time::timeout(WAIT, &mut pending).await.unwrap(),
                Err(LocalSubmissionError::BeforeEnqueue(
                    AuditAuthorityError::BindingMismatch
                ))
            ),
            "RUNNING_LAST_ENQUEUE_GUARD"
        );
    }
    assert_eq!(f.rows().await, before, "RUNNING_PERMIT_NO_INTENT");
    f.close().await;
}

#[tokio::test]
async fn running_replacement_original_survives_lost_reply_revocation_and_newer_head() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let active = f.session().await;
    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let prepared = f
        .prepare(&session, &frozen, 2, b"original before lost reply")
        .await;
    let encoded = prepared.encode().unwrap();
    let intent = applied(
        f.store
            .admit_netconf_running_replacement_local(&session, &prepared, caller())
            .await,
    );
    session.invalidate(); // An acknowledged original intent survives transport Drop.
    let store = f.store.clone();
    let original = prepared.clone();
    let (reply, receiver) = tokio::sync::oneshot::channel();
    drop(receiver);
    let lost = tokio::spawn(async move {
        let result = store
            .submit_netconf_target_local(&original, &intent, caller())
            .await;
        assert!(
            reply.send(result).is_err(),
            "the original caller no longer accepts a reply"
        );
    });
    tokio::time::timeout(WAIT, lost).await.unwrap().unwrap();
    let receipt = f
        .store
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    let expected = running_result(&receipt);
    assert!(!receipt.terminal_recorded());
    f.assert_head(record(&prepared), b"original before lost reply")
        .await;
    f.checkpoint.unavailable.store(true, Ordering::Release);
    assert!(f
        .store
        .complete_required_audit_outcome(&receipt, caller())
        .await
        .is_err());
    assert_eq!(
        applied(
            f.store
                .submit_netconf_target_local(&prepared, &receipt, caller())
                .await
        )
        .state(),
        receipt.state(),
        "RUNNING_KNOWN_RESULT_SURVIVES_DEBT"
    );
    f.checkpoint.unavailable.store(false, Ordering::Release);
    assert!(
        f.store.read_netconf_running_edit(&active).await.is_err(),
        "terminal debt did not fence a new frozen read"
    );
    f.settle(&receipt).await;
    let frozen = f.store.read_netconf_running_edit(&active).await.unwrap();
    let next = f
        .prepare(&active, &frozen, 3, b"newer independent head")
        .await;
    let next_receipt = f.apply(&active, &next).await;
    f.settle(&next_receipt).await;
    let restored = crate::audit_authority::PreparedTargetMutation::decode(&encoded).unwrap();
    let f = f.reopen().await;
    let recovered = f
        .store
        .recover_netconf_target(restored.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered, prepared, "RUNNING_ORIGINAL_RECOVERY");
    let retained = applied(
        f.store
            .admit_netconf_target_local(&recovered, caller())
            .await,
    );
    assert_eq!(
        running_result(&retained),
        expected,
        "RUNNING_RECOVERY_NOT_LATEST_HEAD"
    );
    assert_eq!(
        applied(
            f.store
                .submit_netconf_target_local(&recovered, &retained, caller())
                .await
        )
        .state(),
        retained.state()
    );
    f.assert_head(record(&next), b"newer independent head")
        .await;
    f.close().await;
}

#[tokio::test]
async fn running_replacement_outcome_authenticates_exact_action_transaction_version_and_digest() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let prepared = f
        .prepare(&session, &frozen, 2, b"authenticated outcome")
        .await;
    let mut altered = serde_json::to_value(&prepared).unwrap();
    altered["effect"]["lock"]["requester"] = serde_json::json!(vec![0x7f; 16]);
    let altered = crate::audit_authority::PreparedTargetMutation::decode(
        &serde_json::to_vec(&altered).unwrap(),
    )
    .unwrap();
    let before = f.rows().await;
    refused(
        f.store
            .admit_netconf_running_replacement_local(&session, &altered, caller())
            .await,
    );
    assert_eq!(f.rows().await, before);
    let receipt = f.apply(&session, &prepared).await;
    let result = running_result(&receipt);
    let expected = record(&prepared);
    let exact = NetconfAppliedOutcome::RunningReplaced {
        tx_id: expected.tx_id,
        running_version: expected.version.get(),
        plaintext_digest: expected.plaintext_digest.as_slice().try_into().unwrap(),
    };
    assert_eq!(result.outcome(), exact);
    for outcome in [
        NetconfAppliedOutcome::RunningReplaced {
            tx_id: TxId::new(),
            running_version: 1,
            plaintext_digest: expected.plaintext_digest.as_slice().try_into().unwrap(),
        },
        NetconfAppliedOutcome::RunningReplaced {
            tx_id: expected.tx_id,
            running_version: 2,
            plaintext_digest: expected.plaintext_digest.as_slice().try_into().unwrap(),
        },
        NetconfAppliedOutcome::RunningReplaced {
            tx_id: expected.tx_id,
            running_version: 1,
            plaintext_digest: [0x7e; 32],
        },
        NetconfAppliedOutcome::CopiedRunning { running_version: 1 },
    ] {
        let forged = NetconfTargetResult::new(
            f.store.inner.identity,
            result.profile_incarnation(),
            result.state_digest(),
            outcome,
        )
        .unwrap();
        assert_eq!(
            prepared.validate_result(forged),
            Err(AuditAuthorityError::BindingMismatch),
            "RUNNING_ORIGINAL_RESULT_BINDING"
        );
        // A valid MAC over a substituted outcome is still not this original's
        // result. Exercise the same exact-command response path as submission.
        let mut substituted = receipt.clone();
        substituted.state = AuditOperationState::TargetV1(forged);
        let proof = crate::audit_authority::receipt::AuthenticatedAuditReceipt::seal(
            f.store.inner.backend.audit_key(),
            &substituted,
        )
        .unwrap();
        let command = super::super::audit_mutation::TargetAuditCommandV1::Apply(prepared.clone());
        assert_eq!(
            command.read_back_receipt(
                &proof,
                f.store.inner.backend.audit_key(),
                f.store.inner.identity,
                caller()
            ),
            Err(AuditAuthorityError::BindingMismatch),
            "RUNNING_SIGNED_SUBSTITUTION_REFUSED"
        );
    }
    let bytes = opc_consensus::encode_bounded(&receipt.state()).unwrap();
    // Existing outer tag 4, identity 32+32+1, profile 16, state digest 32.
    assert_eq!(bytes[0], 4);
    assert_eq!(
        bytes[114], 8,
        "RunningReplaced must append after all eight original outcome variants"
    );
    assert_eq!(
        opc_consensus::decode_bounded::<AuditOperationState>(&bytes).unwrap(),
        receipt.state()
    );
    f.settle(&receipt).await;
    f.assert_head(record(&prepared), b"authenticated outcome")
        .await;
    f.close().await;
}

#[tokio::test]
async fn running_replacement_refuses_checkpoint_outage_and_invalid_original_metadata_atomically() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let before = f.rows().await;
    for (parent, version, kind) in [
        (Some(TxId::new()), 1, "running"),
        (None, 2, "running"),
        (None, 1, "candidate"),
    ] {
        let commit = f
            .commit_at(parent, version, b"invalid original", kind, TENANT)
            .await;
        assert!(f
            .store
            .prepare_netconf_running_replacement(
                &session,
                &frozen,
                commit,
                &privacy(),
                &event(2, ManagementAuditOperationCode::Replace, None),
                LIFETIME
            )
            .await
            .is_err());
    }
    let commit = f.commit(&frozen, b"wrong event transaction").await;
    assert!(f
        .store
        .prepare_netconf_running_replacement(
            &session,
            &frozen,
            commit,
            &privacy(),
            &event(3, ManagementAuditOperationCode::Replace, Some(TxId::new())),
            LIFETIME
        )
        .await
        .is_err());
    let commit = f.commit(&frozen, b"not an edit operation").await;
    assert!(f
        .store
        .prepare_netconf_running_replacement(
            &session,
            &frozen,
            commit,
            &privacy(),
            &event(4, ManagementAuditOperationCode::Exec, None),
            LIFETIME
        )
        .await
        .is_err());
    let foreign_principal = ManagementAuditEventRecord::try_new(
        [6; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        TENANT,
        "user:other",
        ManagementAuditTransportCode::NetconfSsh,
        ManagementAuditOperationCode::Replace,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/synthetic:configuration"],
        None::<&str>,
    )
    .unwrap();
    let commit = f.commit(&frozen, b"foreign event caller").await;
    assert!(f
        .store
        .prepare_netconf_running_replacement(
            &session,
            &frozen,
            commit,
            &privacy(),
            &foreign_principal,
            LIFETIME
        )
        .await
        .is_err());
    f.provider
        .insert_active_key(
            opc_key::KeyId::new("synthetic-other-tenant-key").unwrap(),
            opc_key::KeyPurpose::Config,
            TenantId::new("synthetic-other-tenant").unwrap(),
            zeroize::Zeroizing::new([0x63; 32]),
        )
        .unwrap();
    let commit = f
        .commit_at(
            None,
            1,
            b"other tenant",
            "running",
            "synthetic-other-tenant",
        )
        .await;
    assert!(f
        .store
        .prepare_netconf_running_replacement(
            &session,
            &frozen,
            commit,
            &privacy(),
            &event(7, ManagementAuditOperationCode::Replace, None),
            LIFETIME
        )
        .await
        .is_err());
    assert_eq!(
        f.rows().await,
        before,
        "RUNNING_INVALID_PREPARATION_NO_EFFECT"
    );
    let prepared = f.prepare(&session, &frozen, 5, b"checkpoint refused").await;
    f.checkpoint.unavailable.store(true, Ordering::Release);
    refused(
        f.store
            .admit_netconf_running_replacement_local(&session, &prepared, caller())
            .await,
    );
    f.checkpoint.unavailable.store(false, Ordering::Release);
    assert_eq!(f.rows().await, before, "RUNNING_ADMISSION_REFUSAL_ATOMIC");
    assert!(f.store.load_latest().await.unwrap().is_none());
    assert!(f
        .store
        .lookup_audit_operation(prepared.handle(), caller())
        .await
        .unwrap()
        .is_none());
    f.close().await;
}

#[tokio::test]
async fn running_replacement_fixed_expiry_and_confirmed_metadata_never_create_an_intent() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let before = f.rows().await;
    let commit = f.commit(&frozen, b"unavailable confirmed mode").await;
    let (mut pending_record, audit, _) = commit.into_parts();
    pending_record.confirmed_deadline = Some(Timestamp::now_utc());
    let aad = EnvelopeAad::config(
        TenantId::new(TENANT).unwrap(),
        1,
        ConfigAad::new(
            pending_record.tx_id,
            None,
            pending_record.committed_at,
            &pending_record.principal,
            pending_record.schema_digest,
            "running",
        )
        .unwrap(),
    );
    let encrypted =
        opc_crypto::encrypt_attested_envelope(&f.provider, &aad, b"unavailable confirmed mode")
            .await
            .unwrap();
    pending_record.encrypted_blob = encrypted.encoded().to_vec();
    let commit =
        AttestedConfigCommit::try_new(pending_record, audit, encrypted.claim().unwrap()).unwrap();
    assert!(
        f.store
            .prepare_netconf_running_replacement(
                &session,
                &frozen,
                commit,
                &privacy(),
                &event(2, ManagementAuditOperationCode::Replace, None),
                LIFETIME
            )
            .await
            .is_err(),
        "RUNNING_CONFIRMED_MODE_CLOSED"
    );
    let mut expired = f.prepare(&session, &frozen, 3, b"expired original").await;
    let now = f
        .store
        .inner
        .clock
        .now_utc()
        .as_offset_datetime()
        .unix_timestamp();
    expired.effect.expires_at = now - 1;
    let digest = expired
        .effect
        .digest(f.store.inner.backend.audit_key())
        .unwrap();
    let mut body = expired.handle.body.clone();
    body.issued_at = now - 61;
    body.expires_at = now - 1;
    body.binding = AuditOperationBinding::project(&privacy(), &body.event, 0, &digest).unwrap();
    body.mutation = Some(digest);
    expired.handle = AuditOperationHandle::issue(body, f.store.inner.backend.audit_key()).unwrap();
    let result = f
        .store
        .admit_netconf_running_replacement_local(&session, &expired, caller())
        .await;
    assert!(
        matches!(
            result,
            AuditAdmission::Rejected(AuditAuthorityError::Expired)
        ),
        "RUNNING_ORIGINAL_EXPIRY: {result:?}"
    );
    assert_eq!(f.rows().await, before, "RUNNING_EXPIRY_NO_INTENT");
    assert!(f.store.load_latest().await.unwrap().is_none());
    f.close().await;
}

impl Fixture {
    async fn confirmation_commit(
        &self,
        parent: TxId,
        version: u64,
        plaintext: &[u8],
        source: crate::CommitSource,
        deadline: Option<Timestamp>,
    ) -> AttestedConfigCommit {
        let original = self
            .commit_at(Some(parent), version, plaintext, "running", TENANT)
            .await;
        let (mut record, audit, _) = original.into_parts();
        record.source = source;
        record.confirmed_deadline = deadline;
        let envelope = opc_crypto::CryptoEnvelopeRef::decode(&record.encrypted_blob).unwrap();
        let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
        let encrypted = opc_crypto::encrypt_attested_envelope(&self.provider, &aad, plaintext)
            .await
            .unwrap();
        record.encrypted_blob = encrypted.encoded().to_vec();
        AttestedConfigCommit::try_new(record, audit, encrypted.claim().unwrap()).unwrap()
    }

    async fn apply_confirmation_target(
        &self,
        prepared: &crate::audit_authority::PreparedTargetMutation,
    ) -> AuditOperationReceipt {
        let intent = applied(
            self.store
                .admit_netconf_target_local(prepared, caller())
                .await,
        );
        assert_eq!(intent.state(), AuditOperationState::Intent);
        applied(
            self.store
                .submit_netconf_target_local(prepared, &intent, caller())
                .await,
        )
    }
}

#[tokio::test]
async fn running_replacement_after_settled_confirmation_rollback_uses_current_head() {
    let f = Fixture::new().await;
    let session = f.session().await;
    let original_plaintext = br#"{"revision":0}"#;
    let tentative_plaintext = br#"{"revision":1}"#;
    let next_plaintext = br#"{"revision":2}"#;

    let empty = f.store.read_netconf_running_edit(&session).await.unwrap();
    let original = f.prepare(&session, &empty, 2, original_plaintext).await;
    let original_receipt = f.apply(&session, &original).await;
    f.settle(&original_receipt).await;
    f.assert_head(record(&original), original_plaintext).await;

    let candidate = f
        .store
        .read_netconf_target(&session, NetconfLockDatastore::Candidate)
        .await
        .unwrap();
    let staged = f
        .store
        .prepare_netconf_target_replacement(
            &session,
            NetconfTargetReplacement::edit(
                &candidate,
                tentative_plaintext,
                record(&original).schema_digest,
                &f.provider,
            ),
            &privacy(),
            &event(3, ManagementAuditOperationCode::Update, None),
            LIFETIME,
        )
        .await
        .unwrap();
    let staged_receipt = f.apply_confirmation_target(&staged).await;
    assert!(matches!(
        running_result(&staged_receipt).outcome(),
        NetconfAppliedOutcome::Candidate { .. }
    ));
    f.settle(&staged_receipt).await;

    let promotion = f
        .store
        .read_netconf_candidate_promotion(&session)
        .await
        .unwrap();
    let deadline = Timestamp::now_utc()
        .add_seconds(LIFETIME.as_secs() as i64)
        .unwrap();
    let commit = f
        .confirmation_commit(
            record(&original).tx_id,
            2,
            tentative_plaintext,
            crate::CommitSource::Netconf,
            Some(deadline),
        )
        .await;
    let tentative_tx = commit.record().tx_id;
    let tentative = f
        .store
        .prepare_netconf_tentative_promotion(
            &session,
            NetconfTentativePromotion::new(&promotion, commit, &f.provider, None),
            &privacy(),
            &event(4, ManagementAuditOperationCode::Exec, Some(tentative_tx)),
            LIFETIME,
        )
        .await
        .unwrap();
    let tentative_receipt = f.apply_confirmation_target(&tentative).await;
    assert!(matches!(
        running_result(&tentative_receipt).outcome(),
        NetconfAppliedOutcome::Tentative {
            running_version: 2,
            ..
        }
    ));
    f.settle(&tentative_receipt).await;
    f.assert_head(record(&tentative), tentative_plaintext).await;

    // A genuinely pending confirmation must still fence an ordinary edit,
    // including after its own terminal and independent checkpoint have settled.
    let before_refusal = f.rows().await;
    assert!(
        matches!(
            f.store.read_netconf_running_edit(&session).await,
            Err(AuditAuthorityError::RecoveryRequired)
        ),
        "RUNNING_PENDING_CONFIRMATION_REFUSED"
    );
    assert_eq!(f.rows().await, before_refusal, "RUNNING_PENDING_NO_EFFECT");
    let pending = f
        .store
        .read_netconf_pending_confirmation(&session)
        .await
        .unwrap();
    assert_eq!(pending.tentative_transaction(), tentative_tx);
    assert!(!pending.has_staged_candidate());
    let rollback_plaintext = pending
        .rollback_configuration()
        .decrypt_configuration(&f.provider, &TenantId::new(TENANT).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rollback_plaintext.as_slice(), original_plaintext);
    let commit = f
        .confirmation_commit(
            pending.tentative_transaction(),
            pending.rollback_configuration().running_base_version() + 1,
            &rollback_plaintext,
            crate::CommitSource::CommitConfirmedRestore,
            None,
        )
        .await;
    let rollback_tx = commit.record().tx_id;
    let rollback = f
        .store
        .prepare_netconf_cancellation(
            &session,
            NetconfCancellation::new(&pending, commit, &f.provider, None),
            &privacy(),
            &event(5, ManagementAuditOperationCode::Exec, Some(rollback_tx)),
            LIFETIME,
        )
        .await
        .unwrap();
    let rollback_receipt = f.apply_confirmation_target(&rollback).await;
    assert!(matches!(
        running_result(&rollback_receipt).outcome(),
        NetconfAppliedOutcome::RolledBack { running_version: 3, pending: resolved }
            if resolved == pending.pending()
    ));
    f.settle(&rollback_receipt).await;
    f.assert_head(record(&rollback), original_plaintext).await;
    let settled = f
        .store
        .lookup_audit_operation(rollback.handle(), caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(settled.state(), rollback_receipt.state());
    assert!(settled.terminal_recorded(), "RUNNING_ROLLBACK_TERMINAL");
    assert!(
        f.checkpoint
            .value
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.sequence() >= settled.sequence),
        "RUNNING_ROLLBACK_CHECKPOINT"
    );

    // Observe real persisted history and lifecycle. No fixture SQL writes,
    // synthetic receipts or locally edited confirmation state create this case.
    {
        let conn = f.store.inner.backend.conn();
        let conn = conn.lock().await;
        let historical: (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT confirmed_deadline, confirmed_at FROM config_history WHERE tx_id = ?1",
                [tentative_tx.as_uuid().as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(historical, (Some(deadline.to_string()), None));
        let lifecycle: Vec<u8> = conn
            .query_row(
                "SELECT state_json FROM config_netconf_lifecycle WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let lifecycle: serde_json::Value = serde_json::from_slice(&lifecycle).unwrap();
        for field in [
            "pending_confirmation",
            "rollback_parent",
            "original_deadline",
        ] {
            assert_eq!(lifecycle.get(field), Some(&serde_json::Value::Null));
        }
    }

    let frozen = f
        .store
        .read_netconf_running_edit(&session)
        .await
        .expect("RUNNING_AFTER_SETTLED_ROLLBACK: historical tentative metadata must not fence the current ordinary head");
    assert_eq!(frozen.record(), Some(record(&rollback)));
    assert_eq!(frozen.tx_id(), Some(rollback_tx));
    assert_eq!(frozen.running_base_version(), 3);
    let next = f.prepare(&session, &frozen, 6, next_plaintext).await;
    let next_receipt = f.apply(&session, &next).await;
    assert!(matches!(
        running_result(&next_receipt).outcome(),
        NetconfAppliedOutcome::RunningReplaced { tx_id, running_version: 4, plaintext_digest }
            if tx_id == record(&next).tx_id
                && plaintext_digest.as_slice() == record(&next).plaintext_digest
    ));
    assert_eq!(record(&next).parent_tx_id, Some(rollback_tx));
    f.settle(&next_receipt).await;
    f.assert_head(record(&next), next_plaintext).await;
    f.close().await;
}
