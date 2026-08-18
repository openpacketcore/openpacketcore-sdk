use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use opc_config_model::{
    AuthStrength, RequestId, TransportType, TrustedPrincipal, WorkloadIdentity,
};
use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId, Membership};
use opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE;
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider,
    SessionAad, Zeroizing, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV_NONCE_LEN,
};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditOutcome, AuditSink};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use rusqlite::{params, types::Value, Connection};
use sha2::{Digest, Sha256};

use super::sqlite::{
    backup_and_reset_replica, prepare_test_workflow, seal_plan, RecoveryFailpoint, ResetInput,
};
use super::*;
use crate::capability::BackendCapabilities;
use crate::consensus::{
    SessionConsensusClusterId, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
    SessionRaftTypeConfig,
};
use crate::sqlite::consensus;
use crate::topology::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaTlsIdentity, ValidatedQuorumTopology,
};
use crate::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, EncryptingSessionBackend,
    Generation, OwnerId, ReplicationEntry, ReplicationOp, SessionBackend,
    SessionConsensusEntryDigest, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRequestId, SessionConsensusResponse, SessionConsensusRpcHandler,
    SessionConsensusWireRequest, SessionConsensusWireResponse, SessionKey, SessionKeyType,
    SessionLeaseManager, SqliteSessionBackend, StateClass, StateType, StoredSessionRecord,
    SystemClock, FENCED_TRANSITION_OUTCOME_RETENTION, FENCED_TRANSITION_SCHEMA_V1,
    REPLICATION_TX_ID_MAX_BYTES, SESSION_CONSENSUS_SCHEMA_VERSION,
};

const RECOVERY_CAMPAIGN_TRANSITION_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);

type V3ReceiptFixture = ([u8; 56], [u8; 32], [u8; 32], Vec<u8>, [u8; 32]);

type V3HistoryLifecycle = (
    Option<i64>,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    i64,
);

#[derive(Default)]
struct AllowRecovery;

impl RecoveryAuthorizer for AllowRecovery {
    fn authorize(
        &self,
        _principal: &TrustedPrincipal,
        _scope: RecoveryAuthorizationScope,
    ) -> Result<(), RecoveryAuthorizationDenied> {
        Ok(())
    }
}

struct DenyRecovery;

impl RecoveryAuthorizer for DenyRecovery {
    fn authorize(
        &self,
        _principal: &TrustedPrincipal,
        _scope: RecoveryAuthorizationScope,
    ) -> Result<(), RecoveryAuthorizationDenied> {
        Err(RecoveryAuthorizationDenied)
    }
}

#[derive(Default)]
struct CapturingAudit {
    events: Mutex<Vec<AuditEvent>>,
}

struct ToggleAudit {
    fail_success: Arc<AtomicBool>,
    events: Mutex<Vec<AuditEvent>>,
}

impl ToggleAudit {
    fn new(fail_success: Arc<AtomicBool>) -> Self {
        Self {
            fail_success,
            events: Mutex::new(Vec::new()),
        }
    }
}

impl AuditSink for ToggleAudit {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        if matches!(event.outcome, AuditOutcome::Success)
            && self.fail_success.load(Ordering::SeqCst)
        {
            return Err(AuditError::unavailable("injected recovery audit outage"));
        }
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
        Ok(())
    }
}

impl AuditSink for CapturingAudit {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
        Ok(())
    }
}

#[derive(Default)]
struct CapturingObserver {
    signals: Mutex<Vec<RecoverySignal>>,
}

impl RecoveryObserver for CapturingObserver {
    fn observe(&self, signal: RecoverySignal) {
        self.signals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(signal);
    }
}

fn integrity_key() -> RecoveryIntegrityKey {
    RecoveryIntegrityKey::new([0x71; 32]).expect("recovery integrity key")
}

fn context() -> RecoveryContext {
    RecoveryContext::new(
        TrustedPrincipal::new(
            WorkloadIdentity::Internal("offline-recovery-controller".to_string()),
            TenantId::from_static("system"),
        )
        .with_auth_strength(AuthStrength::LocalProcess),
        RequestId::new(),
        TransportType::Internal,
    )
    .expect("recovery context")
}

fn identity() -> SessionConsensusIdentity {
    SessionConsensusIdentity::new(
        SessionConsensusClusterId::new("operator-recovery-tests").expect("cluster"),
        SessionConsensusConfigurationId::from_bytes([0x39; 32]),
        SessionConsensusConfigurationEpoch::new(7).expect("configuration epoch"),
    )
}

fn replica_id(name: &str) -> ReplicaId {
    ReplicaId::new(name).expect("replica ID")
}

fn node_set(ids: &[ReplicaId]) -> BTreeSet<SessionConsensusNodeId> {
    node_set_for(identity(), ids)
}

fn node_set_for(
    identity: SessionConsensusIdentity,
    ids: &[ReplicaId],
) -> BTreeSet<SessionConsensusNodeId> {
    ids.iter()
        .map(|id| {
            opc_consensus::derive_node_id(identity.cluster_id(), id.as_str().as_bytes())
                .expect("derived node ID")
        })
        .collect()
}

#[derive(Clone)]
struct RecoveryLoopbackPeer {
    target: SessionConsensusNodeId,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
}

impl RecoveryLoopbackPeer {
    fn new(target: SessionConsensusNodeId) -> Self {
        Self {
            target,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }
}

impl fmt::Debug for RecoveryLoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryLoopbackPeer")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for RecoveryLoopbackPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
}

fn singleton_topology() -> (
    ValidatedQuorumTopology,
    SessionConsensusIdentity,
    SessionConsensusNodeId,
) {
    let replica_id = replica_id("recovery-finalize-singleton");
    let descriptor = QuorumReplicaDescriptor::new(
        replica_id.clone(),
        ReplicaEndpoint::new("recovery-finalize.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new("spiffe://test/session/recovery-finalize").expect("TLS identity"),
        ReplicaFailureDomain::new("recovery-finalize-zone").expect("failure domain"),
        ReplicaBackingIdentity::new("recovery-finalize-disk").expect("backing identity"),
    );
    let cluster = SessionConsensusClusterId::new("recovery-finalize-cluster").expect("cluster");
    let epoch = SessionConsensusConfigurationEpoch::new(1).expect("epoch");
    let configuration = opc_consensus::derive_configuration_id(
        cluster,
        epoch,
        &[descriptor.configuration_fingerprint()],
    );
    let identity = SessionConsensusIdentity::new(cluster, configuration, epoch);
    let topology = ValidatedQuorumTopology::try_new_consensus_lab_singleton(
        replica_id.clone(),
        vec![descriptor],
        identity,
    )
    .expect("singleton topology");
    let node = topology
        .consensus_node_id(&replica_id)
        .expect("singleton node ID");
    (topology, identity, node)
}

fn sealed_test_plan<A: RecoveryAuthorizer>(
    manager: &LegacyForkRecovery<A, CapturingAudit, CapturingObserver>,
    identity: SessionConsensusIdentity,
    node: SessionConsensusNodeId,
) -> RecoveryPlan {
    let body = RecoveryPlanBody {
        version: RECOVERY_PLAN_VERSION,
        identity,
        expected_members: BTreeSet::from([node]),
        basis: RecoveryDecisionBasis::VerifiedCommittedMajority,
        evidence: Vec::new(),
        source_token: RecoveryDigest::from_bytes([0x11; 32]),
        target_tokens: vec![RecoveryDigest::from_bytes([0x22; 32])],
        source_branch_digest: RecoveryDigest::from_bytes([0x33; 32]),
        next_recovery_epoch: 1,
        application_sequence_high_water: 0,
        watch_sequence_high_water: 0,
        watch_cursor_invalidation_floor: 0,
        fence_high_water: 0,
        credential_high_water: 0,
    };
    let encoded = serde_json::to_vec(&body).expect("encode test plan");
    let plan_digest = RecoveryDigest::from_bytes(Sha256::digest(&encoded).into());
    let seal = seal_plan(&manager.integrity_key, plan_digest, &encoded).expect("seal test plan");
    RecoveryPlan {
        body,
        plan_digest,
        seal,
    }
}

fn create_legacy_replica(root: &Path, id: ReplicaId, fence: u64) -> RecoveryReplica {
    let database = root.join(format!("{}.sqlite", id.as_str()));
    let snapshots = root.join(format!("{}-snapshots", id.as_str()));
    std::fs::create_dir(&snapshots).expect("snapshot directory");
    drop(SqliteSessionBackend::open(&database).expect("legacy SQLite backend"));
    let conn = Connection::open(&database).expect("open legacy database");
    conn.execute(
        "INSERT INTO key_fences (tenant, nf_kind, key_type, stable_id, fence) VALUES ('tenant-a', 'smf', 'pdu-session', ?1, ?2)",
        params![b"recovery-test-session".as_slice(), i64::try_from(fence).expect("fence")],
    )
    .expect("insert legacy fence");
    conn.execute(
        "UPDATE lease_globals SET val = ?1 WHERE key = 'next_fence'",
        [i64::try_from(fence + 1).expect("next fence")],
    )
    .expect("advance legacy fence global");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint legacy WAL");
    drop(conn);
    let backing = ReplicaBackingIdentity::new(format!("recovery-backing-{}", id.as_str()))
        .expect("recovery backing identity");
    RecoveryReplica::new_bound(id, backing, identity(), database, snapshots)
}

fn sealed_recovery_record(payload_len: usize) -> StoredSessionRecord {
    sealed_recovery_record_with_authority(
        SessionKey {
            tenant: TenantId::from_static("recovery-cap-tenant"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"recovery-cap-session")
                .try_into()
                .expect("valid stable ID"),
        },
        OwnerId::new("recovery-cap-owner").expect("owner"),
        crate::FenceToken::new(1),
        payload_len,
    )
}

fn sealed_recovery_record_with_authority(
    key: SessionKey,
    owner: OwnerId,
    fence: crate::FenceToken,
    payload_len: usize,
) -> StoredSessionRecord {
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("recovery-cap-state"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    let key_id = KeyId::new("recovery-cap-test-key").expect("key ID");
    let aad = EnvelopeAad::session(
        record.key.tenant.clone(),
        1,
        SessionAad::new(
            record.key.nf_kind.as_str(),
            "recovery-cap-keyed-session-digest",
            record.state_type.as_str(),
            record.generation.get(),
            record.fence.get(),
            "recovery-cap-test-backend",
        )
        .expect("session AAD"),
    );
    let envelope = |opaque_len| CryptoEnvelopeV1 {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_id: key_id.clone(),
        nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
        aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
        ciphertext_and_tag: {
            let mut ciphertext_and_tag = vec![0xA5; opaque_len];
            ciphertext_and_tag.extend_from_slice(&[0x5A; AEAD_TAG_LEN]);
            ciphertext_and_tag
        },
    };
    let envelope_overhead = envelope(0).encode().expect("empty envelope").len();
    let encoded = envelope(
        payload_len
            .checked_sub(envelope_overhead)
            .expect("payload length exceeds envelope overhead"),
    )
    .encode()
    .expect("sized envelope");
    assert_eq!(encoded.len(), payload_len);
    record.payload = EncryptedSessionPayload::try_envelope(encoded).expect("valid envelope");
    record
}

fn persist_valid_legacy_lease_record(conn: &Connection) {
    let template = sealed_recovery_record(64 * 1024);
    let lease = crate::sqlite::lease::acquire_sync(
        conn,
        &template.key,
        template.owner,
        Duration::from_secs(60),
        Timestamp::from_str("2026-07-12T00:00:01Z").expect("fixture timestamp"),
    )
    .expect("valid legacy lease fixture");
    let record = sealed_recovery_record_with_authority(
        lease.key().clone(),
        lease.owner().clone(),
        lease.fence(),
        64 * 1024,
    );
    crate::sqlite::ops::insert_or_replace_record_sync(conn, &record)
        .expect("persist lease-backed recovery record");
}

fn private_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("private temporary directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("set private temporary directory mode");
    }
    directory
}

fn file_digest(path: &Path) -> [u8; 32] {
    Sha256::digest(std::fs::read(path).expect("read database")).into()
}

fn assert_tree_does_not_contain(root: &Path, needle: &[u8]) {
    for entry in std::fs::read_dir(root).expect("read protected artifact tree") {
        let entry = entry.expect("protected artifact entry");
        let file_type = entry.file_type().expect("protected artifact type");
        if file_type.is_dir() {
            assert_tree_does_not_contain(&entry.path(), needle);
        } else if file_type.is_file() {
            let bytes = std::fs::read(entry.path()).expect("read protected artifact");
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "recovery artifact exposed protected plaintext"
            );
        }
    }
}

fn insert_legacy_empty_replication(replica: &RecoveryReplica, sequence: u64) {
    let timestamp = Timestamp::now_utc();
    let entry = ReplicationEntry {
        sequence,
        tx_id: format!("legacy-recovery-{sequence}")
            .try_into()
            .expect("valid transaction ID"),
        op: ReplicationOp::Batch { ops: Vec::new() },
        timestamp,
    };
    let conn = Connection::open(&replica.database_path).expect("open legacy replication fixture");
    conn.execute(
        "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![
            i64::try_from(sequence).expect("sequence"),
            entry.tx_id.as_str(),
            serde_json::to_string(&entry).expect("encode legacy replication fixture"),
            crate::sqlite::ops::format_rfc3339_normalized(timestamp),
        ],
    )
    .expect("insert legacy replication fixture");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint legacy replication fixture");
}

fn recovery<A: RecoveryAuthorizer>(
    authorizer: A,
) -> LegacyForkRecovery<A, CapturingAudit, CapturingObserver> {
    LegacyForkRecovery::new(
        authorizer,
        CapturingAudit::default(),
        CapturingObserver::default(),
        integrity_key(),
    )
}

#[test]
fn two_branch_legacy_dry_run_is_deterministic_redacted_and_non_mutating() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let first_id = replica_id("recovery-sensitive-replica-a");
    let second_id = replica_id("recovery-sensitive-replica-b");
    let third_id = replica_id("recovery-sensitive-replica-c");
    let ids = [first_id.clone(), second_id.clone(), third_id.clone()];
    let replicas = vec![
        create_legacy_replica(temp.path(), first_id.clone(), 11),
        create_legacy_replica(temp.path(), second_id.clone(), 29),
        create_legacy_replica(temp.path(), third_id.clone(), 29),
    ];
    for replica in &replicas {
        Connection::open(&replica.database_path)
            .expect("open pre-cursor legacy replica")
            .execute_batch(
                r#"
                DROP TABLE restore_scan_state;
                CREATE TABLE restore_scan_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                    revision INTEGER NOT NULL CHECK (revision >= 0)
                );
                "#,
            )
            .expect("install exact pre-cursor restore schema");
    }
    let before = replicas
        .iter()
        .map(|replica| file_digest(&replica.database_path))
        .collect::<Vec<_>>();
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &first_id,
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("legacy recovery plan");
    let repeated = manager
        .plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &first_id,
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("repeated legacy recovery plan");

    assert_eq!(plan, repeated);
    assert_eq!(plan.next_recovery_epoch(), 1);
    assert_eq!(plan.fence_high_water(), 29);
    assert_eq!(
        before,
        replicas
            .iter()
            .map(|replica| file_digest(&replica.database_path))
            .collect::<Vec<_>>()
    );
    let encoded = serde_json::to_string(&plan).expect("serialize redacted plan");
    assert!(!encoded.contains(first_id.as_str()));
    assert!(!encoded.contains(second_id.as_str()));
    assert!(!encoded.contains(third_id.as_str()));
    assert!(!encoded.contains(temp.path().to_str().expect("UTF-8 temp path")));
}

#[test]
fn planning_rejects_duplicate_backing_path_and_hardlink_votes() {
    fn assert_rejected(replicas: &[RecoveryReplica], ids: &[ReplicaId; 3]) {
        let manager = recovery(AllowRecovery);
        assert_eq!(
            manager.plan(
                &context(),
                identity(),
                node_set(ids),
                replicas,
                &ids[0],
                ids,
                RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
                RecoveryLimits::default(),
            ),
            Err(RecoveryError::InvalidRequest)
        );
    }

    let duplicate_backing_root = tempfile::tempdir().expect("duplicate backing root");
    let ids = [
        replica_id("physical-backing-a"),
        replica_id("physical-backing-b"),
        replica_id("physical-backing-c"),
    ];
    let mut duplicate_backing = vec![
        create_legacy_replica(duplicate_backing_root.path(), ids[0].clone(), 1),
        create_legacy_replica(duplicate_backing_root.path(), ids[1].clone(), 2),
        create_legacy_replica(duplicate_backing_root.path(), ids[2].clone(), 3),
    ];
    duplicate_backing[1].backing_identity = duplicate_backing[0].backing_identity.clone();
    assert_rejected(&duplicate_backing, &ids);

    let duplicate_path_root = tempfile::tempdir().expect("duplicate path root");
    let mut duplicate_path = vec![
        create_legacy_replica(duplicate_path_root.path(), ids[0].clone(), 1),
        create_legacy_replica(duplicate_path_root.path(), ids[1].clone(), 2),
        create_legacy_replica(duplicate_path_root.path(), ids[2].clone(), 3),
    ];
    duplicate_path[1].database_path = duplicate_path[0].database_path.clone();
    duplicate_path[1].snapshot_directory = duplicate_path[0].snapshot_directory.clone();
    assert_rejected(&duplicate_path, &ids);

    let hardlink_root = tempfile::tempdir().expect("hardlink root");
    let hardlinks = vec![
        create_legacy_replica(hardlink_root.path(), ids[0].clone(), 1),
        create_legacy_replica(hardlink_root.path(), ids[1].clone(), 2),
        create_legacy_replica(hardlink_root.path(), ids[2].clone(), 3),
    ];
    std::fs::remove_file(&hardlinks[1].database_path).expect("remove hardlink target");
    std::fs::hard_link(&hardlinks[0].database_path, &hardlinks[1].database_path)
        .expect("create database hardlink alias");
    assert_rejected(&hardlinks, &ids);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let symlink_root = tempfile::tempdir().expect("symlink root");
        let mut symlinked = vec![
            create_legacy_replica(symlink_root.path(), ids[0].clone(), 1),
            create_legacy_replica(symlink_root.path(), ids[1].clone(), 2),
            create_legacy_replica(symlink_root.path(), ids[2].clone(), 3),
        ];
        let alias = symlink_root.path().join("database-alias.sqlite");
        symlink(&symlinked[1].database_path, &alias).expect("create database symlink alias");
        symlinked[1].database_path = alias;
        assert_rejected(&symlinked, &ids);
    }
}

#[test]
fn recovery_replica_is_derived_from_validated_topology() {
    let (topology, admitted_identity, _) = singleton_topology();
    let admitted_member = topology.members()[0].clone();
    let replica = RecoveryReplica::from_topology(
        &topology,
        admitted_member.replica_id().clone(),
        "/private/recovery.sqlite",
        "/private/recovery-snapshots",
    )
    .expect("derive recovery input from admitted topology");
    assert_eq!(replica.replica_id(), admitted_member.replica_id());
    assert_eq!(
        replica.backing_identity(),
        admitted_member.backing_identity()
    );
    assert_eq!(replica.admitted_identity, admitted_identity);
    assert!(matches!(
        RecoveryReplica::from_topology(
            &topology,
            replica_id("not-an-admitted-member"),
            "/private/missing.sqlite",
            "/private/missing-snapshots",
        ),
        Err(RecoveryError::InvalidRequest)
    ));
}

#[test]
fn legacy_reset_requires_exact_confirmation_and_preserves_quarantine() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let first_id = replica_id("legacy-source-a");
    let second_id = replica_id("legacy-target-b");
    let third_id = replica_id("legacy-target-c");
    let ids = [first_id.clone(), second_id.clone(), third_id.clone()];
    let replicas = vec![
        create_legacy_replica(temp.path(), first_id.clone(), 17),
        create_legacy_replica(temp.path(), second_id.clone(), 43),
        create_legacy_replica(temp.path(), third_id.clone(), 67),
    ];
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &first_id,
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("legacy recovery plan");
    let weak = RecoveryConfirmation::legacy(&plan, "yes");
    assert_eq!(
        manager.execute(
            &context(),
            &plan,
            &weak,
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::ConfirmationRequired)
    );

    let confirmation = RecoveryConfirmation::legacy(
        &plan,
        RecoveryConfirmation::required_legacy_acknowledgement(),
    );
    let report = manager
        .execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        )
        .expect("execute legacy reset");
    assert_eq!(report.state(), RecoveryExecutionState::AwaitingEpochCommit);

    let mut restore_incarnations = BTreeSet::new();
    for replica in &replicas {
        let target = Connection::open(&replica.database_path).expect("open recovered target");
        let identity_rows: i64 = target
            .query_row("SELECT COUNT(*) FROM consensus_identity", [], |row| {
                row.get(0)
            })
            .expect("count consensus identity");
        let fence: i64 = target
            .query_row("SELECT fence FROM key_fences", [], |row| row.get(0))
            .expect("read recovered fence");
        let pending: i64 = target
            .query_row(
                "SELECT pending_epoch FROM consensus_operator_recovery",
                [],
                |row| row.get(0),
            )
            .expect("read pending recovery epoch");
        let objects = target
            .prepare(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
            )
            .expect("prepare exact converted schema")
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .expect("query exact converted schema")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect exact converted schema");
        assert_eq!(identity_rows, 1);
        assert_eq!(fence, 17);
        assert_eq!(pending, 1);
        let (restore_epoch, _, restore_key) =
            crate::sqlite::ops::read_restore_scan_state_sync(&target)
                .expect("read recovered restore incarnation");
        restore_incarnations.insert((restore_epoch, *restore_key));
        assert_eq!(objects.len(), 24);
        assert!(objects.iter().any(|(kind, name)| {
            kind == "table" && name == "consensus_fenced_transition_receipts"
        }));
        assert!(objects.iter().any(|(kind, name)| {
            kind == "table" && name == "consensus_fenced_transition_activation"
        }));
        assert!(objects.iter().any(|(kind, name)| {
            kind == "index" && name == "consensus_fenced_transition_receipts_due"
        }));
        assert!(objects.iter().all(|(kind, name)| {
            kind == "table"
                || (kind == "index" && name == "consensus_fenced_transition_receipts_due")
        }));
    }
    assert_eq!(restore_incarnations.len(), replicas.len());

    let workflow = backup
        .path()
        .join(format!("recovery-{}", plan.plan_digest()));
    let quarantine = Connection::open(
        workflow
            .join("targets")
            .join(
                replica_token(&manager.integrity_key, &second_id)
                    .expect("second replica token")
                    .to_hex(),
            )
            .join("target.sqlite"),
    )
    .expect("open integrity-protected quarantine database");
    let quarantined_fence: i64 = quarantine
        .query_row("SELECT fence FROM key_fences", [], |row| row.get(0))
        .expect("read quarantined fence");
    assert_eq!(quarantined_fence, 43);

    assert_eq!(
        manager
            .execute(
                &context(),
                &plan,
                &confirmation,
                &replicas,
                backup.path(),
                RecoveryLimits::default(),
            )
            .expect("idempotent resume")
            .state(),
        RecoveryExecutionState::AwaitingEpochCommit
    );
}

#[test]
fn audit_outage_after_reset_is_durably_journaled_and_resumable() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("audit-source-a"),
        replica_id("audit-target-b"),
        replica_id("audit-target-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 5),
        create_legacy_replica(temp.path(), ids[1].clone(), 9),
        create_legacy_replica(temp.path(), ids[2].clone(), 13),
    ];
    let fail_success = Arc::new(AtomicBool::new(false));
    let manager = LegacyForkRecovery::new(
        AllowRecovery,
        ToggleAudit::new(fail_success.clone()),
        CapturingObserver::default(),
        integrity_key(),
    );
    let plan = manager
        .plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &ids[0],
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("audit-pending plan");
    let confirmation = RecoveryConfirmation::legacy(
        &plan,
        RecoveryConfirmation::required_legacy_acknowledgement(),
    );
    fail_success.store(true, Ordering::SeqCst);
    assert_eq!(
        manager.execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::AuditUnavailable)
    );
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read durable audit-pending journal"),
        RecoveryExecutionState::AuditPending
    );
    for replica in &replicas {
        let latch = consensus::read_operator_recovery_latch_sync(&replica.database_path)
            .expect("read durable audit latch")
            .expect("audit outage must keep every voter latched");
        assert_eq!(latch.recovery_epoch, plan.next_recovery_epoch());
        assert_eq!(latch.plan_digest, plan.plan_digest().as_bytes());
        assert!(latch.audit_pending);
    }

    fail_success.store(false, Ordering::SeqCst);
    assert_eq!(
        manager
            .execute(
                &context(),
                &plan,
                &confirmation,
                &replicas,
                backup.path(),
                RecoveryLimits::default(),
            )
            .expect("resume after audit recovers")
            .state(),
        RecoveryExecutionState::AwaitingEpochCommit
    );
    for replica in &replicas {
        let latch = consensus::read_operator_recovery_latch_sync(&replica.database_path)
            .expect("read resumed audit latch")
            .expect("epoch commit still requires the fleet latch");
        assert!(!latch.audit_pending);
    }
}

#[tokio::test]
async fn changed_source_stale_target_and_corrupt_backup_fail_closed() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let first_id = replica_id("legacy-source-change-a");
    let second_id = replica_id("legacy-target-change-b");
    let third_id = replica_id("legacy-target-change-c");
    let ids = [first_id.clone(), second_id.clone(), third_id.clone()];
    let replicas = vec![
        create_legacy_replica(temp.path(), first_id.clone(), 5),
        create_legacy_replica(temp.path(), second_id.clone(), 9),
        create_legacy_replica(temp.path(), third_id.clone(), 13),
    ];
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &first_id,
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("legacy recovery plan");
    Connection::open(&replicas[0].database_path)
        .expect("open source")
        .execute_batch(
            "UPDATE key_fences SET fence = 6; UPDATE lease_globals SET val = 7 WHERE key = 'next_fence';",
        )
        .expect("change source coherently");
    let confirmation = RecoveryConfirmation::legacy(
        &plan,
        RecoveryConfirmation::required_legacy_acknowledgement(),
    );
    assert_eq!(
        manager.execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::SourceChanged)
    );
    let restarted_legacy =
        SqliteSessionBackend::open(&replicas[1].database_path).expect("restart latched legacy DB");
    assert_eq!(
        restarted_legacy.capabilities().await,
        BackendCapabilities::minimal(),
        "the sidecar latch must fence standalone capability claims after restart"
    );
    let probe_key = SessionKey {
        tenant: TenantId::from_static("tenant-a"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"latched-legacy-probe")
            .try_into()
            .expect("valid stable ID"),
    };
    assert!(matches!(
        restarted_legacy.get(&probe_key).await,
        Err(crate::StoreError::CapabilityNotSupported(_))
    ));
    drop(restarted_legacy);

    Connection::open(&replicas[0].database_path)
        .expect("restore source")
        .execute_batch(
            "UPDATE key_fences SET fence = 5; UPDATE lease_globals SET val = 6 WHERE key = 'next_fence';",
        )
        .expect("restore source coherently");
    manager
        .execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        )
        .expect("execute reset");
    let workflow = backup
        .path()
        .join(format!("recovery-{}", plan.plan_digest()));
    std::fs::write(
        workflow
            .join("targets")
            .join(
                replica_token(&manager.integrity_key, &second_id)
                    .expect("second replica token")
                    .to_hex(),
            )
            .join("target.sqlite"),
        b"corrupt",
    )
    .expect("corrupt quarantine backup");
    assert_eq!(
        manager.execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::BackupCorrupt)
    );
}

#[test]
fn authorization_denial_is_audited_and_does_not_inspect_mutably() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let first_id = replica_id("denied-source-a");
    let second_id = replica_id("denied-target-b");
    let third_id = replica_id("denied-target-c");
    let ids = [first_id.clone(), second_id.clone(), third_id.clone()];
    let replicas = vec![
        create_legacy_replica(temp.path(), first_id.clone(), 1),
        create_legacy_replica(temp.path(), second_id.clone(), 2),
        create_legacy_replica(temp.path(), third_id.clone(), 3),
    ];
    let before = file_digest(&replicas[1].database_path);
    let manager = recovery(DenyRecovery);
    assert_eq!(
        manager.plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &first_id,
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::AuthorizationDenied)
    );
    assert_eq!(before, file_digest(&replicas[1].database_path));
    let events = manager
        .audit
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(matches!(
        events.last().map(|event| event.outcome),
        Some(AuditOutcome::Denied(_))
    ));
}

#[test]
fn legacy_sequence_audit_rejects_hidden_domain_and_row_payload_mismatches() {
    for (case, stored_sequence, payload_sequence, stored_tx) in [
        ("zero", 0_i64, 1_u64, "sequence-test"),
        ("negative", -1_i64, 1_u64, "sequence-test"),
        ("gap", 2_i64, 2_u64, "sequence-test"),
        ("payload", 1_i64, 2_u64, "sequence-test"),
        ("transaction", 1_i64, 1_u64, "different-transaction"),
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let first_id = replica_id(&format!("sequence-source-{case}"));
        let second_id = replica_id(&format!("sequence-target-{case}"));
        let third_id = replica_id(&format!("sequence-target-c-{case}"));
        let ids = [first_id.clone(), second_id.clone(), third_id.clone()];
        let replicas = vec![
            create_legacy_replica(temp.path(), first_id.clone(), 3),
            create_legacy_replica(temp.path(), second_id.clone(), 4),
            create_legacy_replica(temp.path(), third_id.clone(), 5),
        ];
        let timestamp = Timestamp::now_utc();
        let entry = ReplicationEntry {
            sequence: payload_sequence,
            tx_id: "sequence-test".try_into().expect("valid transaction ID"),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp,
        };
        let conn = Connection::open(&replicas[0].database_path).expect("open sequence database");
        conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("disable check constraints for corruption fixture");
        conn.execute(
            "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![
                stored_sequence,
                stored_tx,
                serde_json::to_string(&entry).expect("encode replication entry"),
                crate::sqlite::ops::format_rfc3339_normalized(timestamp),
            ],
        )
        .expect("insert corrupt replication row");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint corruption fixture");
        drop(conn);

        let manager = recovery(AllowRecovery);
        assert_eq!(
            manager.plan(
                &context(),
                identity(),
                node_set(&ids),
                &replicas,
                &first_id,
                &ids,
                RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
                RecoveryLimits::default(),
            ),
            Err(RecoveryError::CorruptReplica),
            "case {case} must fail closed"
        );
    }
}

#[test]
fn legacy_recovery_rejects_unbounded_or_non_text_transaction_ids() {
    for (case, stored_tx_id) in [
        ("empty", Value::Text(String::new())),
        (
            "oversized",
            Value::Text("x".repeat(REPLICATION_TX_ID_MAX_BYTES + 1)),
        ),
        ("blob", Value::Blob(vec![b'x'])),
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let ids = [
            replica_id(&format!("tx-width-{case}-a")),
            replica_id(&format!("tx-width-{case}-b")),
            replica_id(&format!("tx-width-{case}-c")),
        ];
        let replicas = vec![
            create_legacy_replica(temp.path(), ids[0].clone(), 3),
            create_legacy_replica(temp.path(), ids[1].clone(), 4),
            create_legacy_replica(temp.path(), ids[2].clone(), 5),
        ];
        let timestamp = Timestamp::now_utc();
        let entry = ReplicationEntry {
            sequence: 1,
            tx_id: "valid-encoded-id".try_into().expect("valid transaction ID"),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp,
        };
        let conn = Connection::open(&replicas[0].database_path).expect("open legacy database");
        conn.execute_batch("PRAGMA ignore_check_constraints = ON")
            .expect("allow legacy-invalid fixture");
        conn.execute(
            "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) \
             VALUES (1, ?1, ?2, ?3)",
            params![
                stored_tx_id,
                serde_json::to_string(&entry).expect("entry JSON"),
                crate::sqlite::ops::format_rfc3339_normalized(timestamp),
            ],
        )
        .expect("insert invalid transaction ID fixture");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint invalid fixture");
        drop(conn);

        let manager = recovery(AllowRecovery);
        assert_eq!(
            manager.plan(
                &context(),
                identity(),
                node_set(&ids),
                &replicas,
                &ids[0],
                &ids,
                RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
                RecoveryLimits::default(),
            ),
            Err(RecoveryError::CorruptReplica),
            "case {case} must fail closed"
        );
    }
}

#[test]
fn campaign_preserves_fleet_maxima_and_preflights_sqlite_successors() {
    let temp = tempfile::tempdir().expect("maxima root");
    let backup = private_tempdir();
    let ids = [
        replica_id("maxima-a"),
        replica_id("maxima-b"),
        replica_id("maxima-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 19),
        create_legacy_replica(temp.path(), ids[2].clone(), 31),
    ];
    for sequence in 1..=1 {
        insert_legacy_empty_replication(&replicas[0], sequence);
    }
    for sequence in 1..=3 {
        insert_legacy_empty_replication(&replicas[1], sequence);
    }
    for sequence in 1..=5 {
        insert_legacy_empty_replication(&replicas[2], sequence);
    }
    for (replica, next_credential) in replicas.iter().zip([3_i64, 11, 23]) {
        Connection::open(&replica.database_path)
            .expect("open credential maximum")
            .execute(
                "UPDATE lease_globals SET val = ?1 WHERE key = 'next_credential_id'",
                [next_credential],
            )
            .expect("set credential maximum");
    }
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &ids[0],
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("maxima plan");
    assert_eq!(plan.application_sequence_high_water(), 5);
    assert_eq!(plan.watch_sequence_high_water(), 5);
    assert_eq!(plan.watch_cursor_invalidation_floor(), 5);
    assert_eq!(plan.fence_high_water(), 31);
    assert_eq!(plan.credential_high_water(), 22);
    let confirmation = RecoveryConfirmation::legacy(
        &plan,
        RecoveryConfirmation::required_legacy_acknowledgement(),
    );
    manager
        .execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        )
        .expect("execute maxima campaign");
    for replica in &replicas {
        let conn = Connection::open(&replica.database_path).expect("open converted maximum");
        let (application, watch): (i64, i64) = conn
            .query_row(
                "SELECT application_sequence, watch_sequence FROM consensus_machine WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read converted maxima");
        assert_eq!((application, watch), (5, 5));
        assert_eq!(
            consensus::read_operator_recovery_sync(&conn, identity())
                .expect("read converted recovery state")
                .watch_cursor_invalidation_floor,
            5
        );
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM session_replication_log", [], |row| {
                row.get(0)
            })
            .expect("count invalidated log");
        assert_eq!(rows, 0);
    }

    let overflow_temp = tempfile::tempdir().expect("overflow root");
    let overflow_backup = private_tempdir();
    let overflow_ids = [
        replica_id("overflow-a"),
        replica_id("overflow-b"),
        replica_id("overflow-c"),
    ];
    let overflow_replicas = vec![
        create_legacy_replica(overflow_temp.path(), overflow_ids[0].clone(), 1),
        create_legacy_replica(overflow_temp.path(), overflow_ids[1].clone(), 2),
        create_legacy_replica(overflow_temp.path(), overflow_ids[2].clone(), 3),
    ];
    Connection::open(&overflow_replicas[2].database_path)
        .expect("open exhausted fence")
        .execute("UPDATE key_fences SET fence = ?1", [i64::MAX])
        .expect("exhaust fence domain");
    assert_eq!(
        manager.plan(
            &context(),
            identity(),
            node_set(&overflow_ids),
            &overflow_replicas,
            &overflow_ids[0],
            &overflow_ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::CorruptReplica),
        "an exhausted fence with no representable allocator successor is corrupt",
    );
    assert!(
        std::fs::read_dir(overflow_backup.path())
            .expect("read untouched backup root")
            .next()
            .is_none(),
        "range exhaustion must fail before recovery artifacts"
    );
    for replica in &overflow_replicas {
        assert!(
            consensus::read_operator_recovery_latch_sync(&replica.database_path)
                .expect("read absent latch")
                .is_none(),
            "range exhaustion must fail before fleet latching"
        );
    }
}

#[test]
fn inspection_enforces_database_value_row_and_deadline_budgets() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("bounded-replica-a"),
        replica_id("bounded-replica-b"),
        replica_id("bounded-replica-c"),
    ];
    let replica = create_legacy_replica(temp.path(), ids[0].clone(), 3);
    let members = node_set(&ids);
    let key = integrity_key();
    let database_size = std::fs::metadata(&replica.database_path)
        .expect("database metadata")
        .len();

    for limits in [
        RecoveryLimits::try_new(database_size - 1, database_size, 1_000, 1_000)
            .expect("database bound"),
        RecoveryLimits::try_new(database_size * 2, database_size * 2, 1_000, 7)
            .expect("value bound"),
        RecoveryLimits::try_new(database_size * 2, database_size * 2, 2, 1_000).expect("row bound"),
        RecoveryLimits::try_new_with_work_budget(
            database_size * 2,
            database_size * 2,
            1_000,
            1_000,
            database_size * 8,
            Duration::from_nanos(1),
        )
        .expect("deadline bound"),
    ] {
        assert_eq!(
            inspect_replica(InspectionInput {
                key: &key,
                replica: &replica,
                identity: identity(),
                expected_members: &members,
                limits,
            }),
            Err(RecoveryError::WorkLimitExceeded)
        );
    }
}

#[test]
fn current_recovery_inspection_enforces_the_consensus_payload_cap() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("current-cap-replica-a"),
        replica_id("current-cap-replica-b"),
        replica_id("current-cap-replica-c"),
    ];
    let replica = create_legacy_replica(temp.path(), ids[0].clone(), 3);
    let members = node_set(&ids);
    claim_current_replica(
        &replica,
        &members,
        LogId::new(
            CommittedLeaderId::new(1, *members.iter().next().expect("member")),
            0,
        ),
    );
    append_current_blank_checkpoint(
        &replica,
        LogId::new(
            CommittedLeaderId::new(1, *members.iter().next().expect("member")),
            1,
        ),
    );
    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let oversized = sealed_recovery_record(1_048_577);
    crate::sqlite::ops::insert_or_replace_record_sync(&conn, &oversized)
        .expect("inject valid sealed record above the consensus cap");
    crate::sqlite::ops::insert_or_replace_fence_sync(&conn, &oversized.key, oversized.fence.get())
        .expect("persist the record fence");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint current replica");
    drop(conn);

    assert_eq!(
        inspect_replica(InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        }),
        Err(RecoveryError::CorruptReplica)
    );
}

#[test]
fn current_recovery_rejects_a_regressed_lease_allocator() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("current-allocator-replica-a"),
        replica_id("current-allocator-replica-b"),
        replica_id("current-allocator-replica-c"),
    ];
    let replica = create_legacy_replica(temp.path(), ids[0].clone(), 3);
    let members = node_set(&ids);
    claim_current_replica(
        &replica,
        &members,
        LogId::new(
            CommittedLeaderId::new(1, *members.iter().next().expect("member")),
            1,
        ),
    );
    let conn = Connection::open(&replica.database_path).expect("open current replica");
    conn.execute(
        "UPDATE lease_globals SET val = 3 WHERE key = 'next_fence'",
        [],
    )
    .expect("regress fence allocator");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint allocator mutation");
    drop(conn);

    assert_eq!(
        inspect_replica(InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        }),
        Err(RecoveryError::CorruptReplica)
    );
}

#[test]
fn legacy_recovery_rejects_a_regressed_lease_allocator() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("legacy-allocator-replica-a"),
        replica_id("legacy-allocator-replica-b"),
        replica_id("legacy-allocator-replica-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 3),
        create_legacy_replica(temp.path(), ids[1].clone(), 4),
        create_legacy_replica(temp.path(), ids[2].clone(), 5),
    ];
    let conn = Connection::open(&replicas[0].database_path).expect("open legacy replica");
    conn.execute(
        "UPDATE lease_globals SET val = 3 WHERE key = 'next_fence'",
        [],
    )
    .expect("regress fence allocator");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint allocator mutation");
    drop(conn);

    let manager = recovery(AllowRecovery);
    assert_eq!(
        manager.plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &ids[0],
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::CorruptReplica)
    );
}

#[test]
fn recovery_inspection_rejects_invalid_legacy_lease_semantics() {
    for (case, mutation) in [
        (
            "equal-fence-record-owner",
            "UPDATE session_records SET owner = 'different-valid-owner'",
        ),
        (
            "noncanonical-lease-timestamp",
            "UPDATE leases SET guard_expires_at = '2026-07-12T00:01:01Z'",
        ),
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let id = replica_id("legacy-semantic-replica");
        let replica = create_legacy_replica(temp.path(), id.clone(), 3);
        let conn = Connection::open(&replica.database_path).expect("open legacy replica");
        persist_valid_legacy_lease_record(&conn);
        conn.execute_batch(mutation).expect("mutate legacy fixture");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint legacy mutation");
        drop(conn);

        assert_eq!(
            inspect_replica(InspectionInput {
                key: &integrity_key(),
                replica: &replica,
                identity: identity(),
                expected_members: &node_set(&[id]),
                limits: RecoveryLimits::default(),
            }),
            Err(RecoveryError::CorruptReplica),
            "case {case}"
        );
    }
}

fn claim_current_replica(
    replica: &RecoveryReplica,
    members: &BTreeSet<SessionConsensusNodeId>,
    log_id: LogId<SessionConsensusNodeId>,
) {
    let conn = Connection::open(&replica.database_path).expect("open replica for claim");
    consensus::claim_legacy_checkpoint_sync(
        &conn,
        identity(),
        members,
        [0x55; 32],
        1,
        [0x66; 32],
        0,
        0,
    )
    .expect("claim legacy checkpoint");
    let membership = Membership::new(vec![members.clone()], members.clone());
    let entry: Entry<SessionRaftTypeConfig> = Entry {
        log_id,
        payload: EntryPayload::Membership(membership),
    };
    consensus::append_logs_sync(&conn, identity(), std::slice::from_ref(&entry))
        .expect("append membership entry");
    consensus::save_committed_sync(&conn, identity(), Some(log_id))
        .expect("save committed membership");
    consensus::apply_entries_sync(
        &conn,
        identity(),
        &BackendCapabilities::all_enabled(),
        vec![entry],
    )
    .expect("apply membership entry");
    assert_eq!(
        consensus::finalize_operator_recovery_sync(
            &conn,
            identity(),
            1,
            [0x66; 32],
            consensus::observed_fence_high_water_sync(&conn).expect("fence high-water"),
            consensus::observed_credential_high_water_sync(&conn).expect("credential high-water"),
        )
        .expect("finalize claimed current replica"),
        consensus::OperatorRecoveryApply::Applied
    );
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint current replica");
}

fn append_current_blank_checkpoint(
    replica: &RecoveryReplica,
    log_id: LogId<SessionConsensusNodeId>,
) {
    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let entry: Entry<SessionRaftTypeConfig> = Entry {
        log_id,
        payload: EntryPayload::Blank,
    };
    consensus::append_logs_sync(&conn, identity(), std::slice::from_ref(&entry))
        .expect("append current blank checkpoint");
    consensus::save_committed_sync(&conn, identity(), Some(log_id))
        .expect("commit current blank checkpoint");
    consensus::apply_entries_sync(
        &conn,
        identity(),
        &BackendCapabilities::all_enabled(),
        vec![entry],
    )
    .expect("apply current blank checkpoint");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint current blank checkpoint");
}

fn current_receipt_inspection_fixture(
    root: &Path,
) -> (RecoveryReplica, BTreeSet<SessionConsensusNodeId>) {
    std::fs::create_dir_all(root).expect("current recovery fixture root");
    let id = replica_id("receipt-inspection-replica");
    let replica = create_legacy_replica(root, id.clone(), 3);
    let members = node_set(&[id]);
    claim_current_replica(
        &replica,
        &members,
        LogId::new(
            CommittedLeaderId::new(1, *members.iter().next().expect("member")),
            0,
        ),
    );
    append_current_blank_checkpoint(
        &replica,
        LogId::new(
            CommittedLeaderId::new(1, *members.iter().next().expect("member")),
            1,
        ),
    );
    (replica, members)
}

fn activate_v3_history_fixture(
    replica: &RecoveryReplica,
    active_epoch: u64,
    retired_through_epoch: u64,
    current_bound_count: u64,
) {
    let conn = Connection::open(&replica.database_path).expect("open V3 fixture");
    conn.execute_batch(
        r#"
CREATE TABLE consensus_fenced_transition_v2_receipts (
    request_id BLOB NOT NULL PRIMARY KEY CHECK (length(request_id) = 56),
    history_epoch INTEGER NOT NULL CHECK (history_epoch > 0),
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    retained_until TEXT NOT NULL CHECK (octet_length(retained_until) = 30),
    binding_digest BLOB NOT NULL CHECK (length(binding_digest) = 32),
    response_json BLOB CHECK (response_json IS NULL OR length(response_json) BETWEEN 1 AND 17408),
    response_digest BLOB CHECK (response_digest IS NULL OR length(response_digest) = 32),
    CHECK ((response_json IS NULL AND response_digest IS NULL) OR (response_json IS NOT NULL AND response_digest IS NOT NULL)),
    UNIQUE (history_epoch, ordinal),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);
CREATE INDEX consensus_fenced_transition_v2_receipts_reclaim ON consensus_fenced_transition_v2_receipts (history_epoch, ordinal);
CREATE INDEX consensus_fenced_transition_v2_receipts_due ON consensus_fenced_transition_v2_receipts (retained_until, request_id) WHERE response_json IS NOT NULL;
CREATE TABLE consensus_fenced_transition_v2_activation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    storage_configuration_epoch INTEGER NOT NULL CHECK (storage_configuration_epoch > 0),
    scope_configuration_id BLOB NOT NULL CHECK (length(scope_configuration_id) = 32),
    scope_configuration_epoch INTEGER NOT NULL CHECK (scope_configuration_epoch > 0),
    voter_set_digest BLOB NOT NULL CHECK (length(voter_set_digest) = 32),
    profile_digest BLOB NOT NULL CHECK (length(profile_digest) = 32),
    FOREIGN KEY(storage_configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);
CREATE TABLE consensus_fenced_transition_v2_history (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    storage_configuration_epoch INTEGER NOT NULL CHECK (storage_configuration_epoch > 0),
    profile_digest BLOB NOT NULL CHECK (length(profile_digest) = 32),
    active_epoch INTEGER CHECK (active_epoch IS NULL OR active_epoch > 0),
    retired_through_epoch INTEGER NOT NULL CHECK (retired_through_epoch >= 0),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    current_bound_count INTEGER NOT NULL CHECK (current_bound_count BETWEEN 0 AND 131072),
    reclaim_epoch INTEGER CHECK (reclaim_epoch IS NULL OR reclaim_epoch > 0),
    reclaim_cursor_ordinal INTEGER CHECK (reclaim_cursor_ordinal IS NULL OR reclaim_cursor_ordinal >= 0),
    reclaim_remaining INTEGER CHECK (reclaim_remaining IS NULL OR reclaim_remaining >= 0),
    reclaimed_entries INTEGER NOT NULL DEFAULT 0 CHECK (reclaimed_entries >= 0),
    CHECK ((active_epoch IS NOT NULL AND active_epoch > retired_through_epoch AND reclaim_epoch IS NULL AND reclaim_cursor_ordinal IS NULL AND reclaim_remaining IS NULL) OR (active_epoch IS NULL AND reclaim_epoch IS NOT NULL AND reclaim_epoch = retired_through_epoch AND reclaim_cursor_ordinal IS NOT NULL AND reclaim_remaining IS NOT NULL AND current_bound_count = 0)),
    FOREIGN KEY(storage_configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);
"#,
    )
    .expect("install exact V3 schema");
    conn.execute(
        "UPDATE consensus_identity SET schema_version = ?1, fenced_transition_receipt_ledger_activated = 1 WHERE singleton = 1",
        [i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) + 2],
    )
    .expect("raise V3 fence");
    conn.execute(
        "INSERT INTO consensus_fenced_transition_v2_history (singleton, storage_configuration_epoch, profile_digest, active_epoch, retired_through_epoch, generation, current_bound_count, reclaim_epoch, reclaim_cursor_ordinal, reclaim_remaining, reclaimed_entries) VALUES (1, ?1, ?2, ?3, ?4, 0, ?5, NULL, NULL, NULL, 0)",
        params![
            i64::try_from(identity().configuration_epoch().get()).expect("epoch"),
            crate::fenced_transition::fenced_transition_v2_profile_digest().as_slice(),
            i64::try_from(active_epoch).expect("active epoch"),
            i64::try_from(retired_through_epoch).expect("retired epoch"),
            i64::try_from(current_bound_count).expect("count"),
        ],
    )
    .expect("insert V3 lifecycle singleton");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint V3 fixture");
}

fn insert_valid_v3_receipt_fixture(
    replica: &RecoveryReplica,
    history_epoch: u64,
    ordinal: u64,
) -> V3ReceiptFixture {
    let logical_time = receipt_inspection_timestamp();
    let retained_until =
        crate::checked_session_deadline(logical_time, FENCED_TRANSITION_OUTCOME_RETENTION)
            .expect("V3 receipt deadline");
    let retained_until = crate::sqlite::ops::format_rfc3339_normalized(retained_until);
    let mut request_id = [0xA1; 56];
    request_id[..8].copy_from_slice(&history_epoch.to_be_bytes());
    let payload_digest =
        consensus::fenced_transition_v2_payload_digest_for_request_id(identity(), request_id)
            .expect("V3 payload digest");
    let binding_digest = consensus::fenced_transition_v2_receipt_binding_digest(
        identity(),
        request_id,
        history_epoch,
        ordinal,
        payload_digest,
        &retained_until,
    )
    .expect("V3 receipt binding");
    let response = SessionConsensusResponse {
        result: Err(crate::StoreError::NotFound),
        sequence: 1,
        digest: Some(SessionConsensusEntryDigest::from_bytes([0xA3; 32])),
        logical_time: Some(logical_time),
        raft_log_index: 1,
    };
    let response_json =
        consensus::encode_fenced_transition_v2_response(&response).expect("encode V3 response");
    let response_digest =
        consensus::fenced_transition_v2_receipt_response_digest(binding_digest, &response_json)
            .expect("V3 response digest");
    let conn = Connection::open(&replica.database_path).expect("open V3 receipt fixture");
    conn.execute(
        "UPDATE consensus_machine SET application_sequence = 1, logical_time = ?1 WHERE singleton = 1",
        [crate::sqlite::ops::format_rfc3339_normalized(logical_time)],
    )
    .expect("advance V3 fixture machine");
    conn.execute(
        "INSERT INTO consensus_fenced_transition_v2_receipts (request_id, history_epoch, ordinal, configuration_epoch, payload_digest, retained_until, binding_digest, response_json, response_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            request_id.as_slice(),
            i64::try_from(history_epoch).expect("history epoch"),
            i64::try_from(ordinal).expect("ordinal"),
            i64::try_from(identity().configuration_epoch().get()).expect("configuration epoch"),
            payload_digest.as_slice(),
            retained_until,
            binding_digest.as_slice(),
            response_json.as_slice(),
            response_digest.as_slice(),
        ],
    )
    .expect("insert valid V3 receipt");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint V3 receipt fixture");
    (
        request_id,
        payload_digest,
        binding_digest,
        response_json,
        response_digest,
    )
}

fn inspect_current_fixture(
    replica: &RecoveryReplica,
    members: &BTreeSet<SessionConsensusNodeId>,
) -> Result<RecoveryReplicaEvidence, RecoveryError> {
    inspect_replica(InspectionInput {
        key: &integrity_key(),
        replica,
        identity: identity(),
        expected_members: members,
        limits: RecoveryLimits::default(),
    })
}

fn v3_history_lifecycle(replica: &RecoveryReplica) -> V3HistoryLifecycle {
    let conn = Connection::open(&replica.database_path).expect("open V3 lifecycle fixture");
    conn.query_row(
        "SELECT active_epoch, retired_through_epoch, current_bound_count, reclaim_epoch, reclaim_cursor_ordinal, reclaim_remaining, reclaimed_entries FROM consensus_fenced_transition_v2_history WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
    )
    .expect("read V3 lifecycle")
}

#[test]
fn current_recovery_inspection_accepts_populated_v3_history_and_reopen_preserves_branch() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (replica, members) = current_receipt_inspection_fixture(temp.path());
    activate_v3_history_fixture(&replica, 5, 4, 1);
    insert_valid_v3_receipt_fixture(&replica, 5, 1);

    let conn = Connection::open(&replica.database_path).expect("open V3 validation fixture");
    consensus::validate_fenced_transition_v2_receipts_sync(&conn, identity())
        .expect("validate populated V3 ledger");
    drop(conn);

    let lifecycle_before = v3_history_lifecycle(&replica);
    let before = inspect_current_fixture(&replica, &members).expect("inspect V3 replica");
    drop(SqliteSessionBackend::open(&replica.database_path).expect("reopen V3 replica"));
    let after = inspect_current_fixture(&replica, &members).expect("reinspect V3 replica");
    assert_eq!(before.branch_digest(), after.branch_digest());
    assert_eq!(
        lifecycle_before,
        v3_history_lifecycle(&replica),
        "inspection/reopen must neither synthesize nor advance V3 retirement",
    );
}

#[test]
fn current_recovery_v3_rejects_lifecycle_corruption_and_distinguishes_floor() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (valid, members) = current_receipt_inspection_fixture(&temp.path().join("valid"));
    activate_v3_history_fixture(&valid, 5, 4, 0);
    let valid_evidence = inspect_current_fixture(&valid, &members).expect("valid V3 inspection");

    let (higher_floor, higher_members) =
        current_receipt_inspection_fixture(&temp.path().join("higher-floor"));
    activate_v3_history_fixture(&higher_floor, 6, 5, 0);
    let higher_evidence =
        inspect_current_fixture(&higher_floor, &higher_members).expect("higher floor inspection");
    assert_ne!(
        valid_evidence.branch_digest(),
        higher_evidence.branch_digest()
    );

    for (label, sql) in [
        (
            "retired floor",
            "UPDATE consensus_fenced_transition_v2_history SET retired_through_epoch = 5",
        ),
        (
            "count mismatch",
            "UPDATE consensus_fenced_transition_v2_history SET current_bound_count = 1",
        ),
        (
            "reclaim cursor shape",
            "UPDATE consensus_fenced_transition_v2_history SET active_epoch = NULL, reclaim_epoch = 4, reclaim_cursor_ordinal = 2, reclaim_remaining = 1, current_bound_count = 0",
        ),
    ] {
        let (replica, case_members) =
            current_receipt_inspection_fixture(&temp.path().join(label));
        activate_v3_history_fixture(&replica, 5, 4, 0);
        let conn = Connection::open(&replica.database_path).expect("open corrupt V3 fixture");
        conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("allow lifecycle corruption");
        conn.execute_batch(sql).expect("inject lifecycle corruption");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint lifecycle corruption");
        drop(conn);
        assert_eq!(
            inspect_current_fixture(&replica, &case_members),
            Err(RecoveryError::CorruptReplica),
            "{label}",
        );
    }
}

#[test]
fn current_recovery_v3_rejects_profile_and_receipt_commitment_corruption() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (replica, members) = current_receipt_inspection_fixture(&temp.path().join("profile"));
    activate_v3_history_fixture(&replica, 5, 4, 0);
    let conn = Connection::open(&replica.database_path).expect("open V3 fixture");
    conn.execute(
        "UPDATE consensus_fenced_transition_v2_history SET profile_digest = ?1 WHERE singleton = 1",
        [[0xE1_u8; 32].as_slice()],
    )
    .expect("corrupt immutable V3 profile");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint corrupt profile");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&replica, &members),
        Err(RecoveryError::CorruptReplica)
    );

    for (label, column, value) in [
        ("payload", "payload_digest", vec![0xA2; 32]),
        ("binding", "binding_digest", vec![0xA4; 32]),
        ("response", "response_digest", vec![0xA5; 32]),
    ] {
        let (replica, members) = current_receipt_inspection_fixture(&temp.path().join(label));
        activate_v3_history_fixture(&replica, 5, 4, 1);
        insert_valid_v3_receipt_fixture(&replica, 5, 1);
        let conn = Connection::open(&replica.database_path).expect("open V3 receipt corruption");
        conn.execute(
            &format!("UPDATE consensus_fenced_transition_v2_receipts SET {column} = ?1"),
            [value],
        )
        .expect("corrupt V3 receipt commitment");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint V3 receipt corruption");
        drop(conn);
        assert_eq!(
            inspect_current_fixture(&replica, &members),
            Err(RecoveryError::CorruptReplica),
            "{label}",
        );
    }

    let (replica, members) = current_receipt_inspection_fixture(&temp.path().join("codec"));
    activate_v3_history_fixture(&replica, 5, 4, 1);
    let (_, _, binding_digest, _, _) = insert_valid_v3_receipt_fixture(&replica, 5, 1);
    let malformed_codec = b"not-a-v2-codec";
    let matching_digest =
        consensus::fenced_transition_v2_receipt_response_digest(binding_digest, malformed_codec)
            .expect("malformed codec digest");
    let conn = Connection::open(&replica.database_path).expect("open V3 codec corruption");
    conn.execute(
        "UPDATE consensus_fenced_transition_v2_receipts SET response_json = ?1, response_digest = ?2",
        params![malformed_codec.as_slice(), matching_digest.as_slice()],
    )
    .expect("inject self-consistent malformed V3 codec");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint V3 codec corruption");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&replica, &members),
        Err(RecoveryError::CorruptReplica)
    );
}

fn receipt_inspection_timestamp() -> Timestamp {
    Timestamp::from_str("2026-08-16T00:00:00Z").expect("fixed receipt timestamp")
}

fn fenced_receipt_binding_digest_for_recovery_fixture(
    request_id: SessionConsensusRequestId,
    payload_digest: [u8; 32],
    retained_until: &str,
) -> [u8; 32] {
    let encoded = serde_json::to_vec(&(
        FENCED_TRANSITION_SCHEMA_V1,
        identity(),
        request_id.as_bytes(),
        payload_digest,
        retained_until,
    ))
    .expect("encode fenced receipt binding");
    let mut hasher = Sha256::new();
    hasher.update(b"openpacketcore/session-consensus/fenced-transition-receipt-binding/v1\0");
    hasher.update(encoded);
    hasher.finalize().into()
}

fn fenced_receipt_response_digest_for_recovery_fixture(
    binding_digest: [u8; 32],
    response: &SessionConsensusResponse,
) -> [u8; 32] {
    let encoded = serde_json::to_vec(response).expect("encode fenced receipt response");
    let mut hasher = Sha256::new();
    hasher.update(b"openpacketcore/session-consensus/fenced-transition-receipt-response/v1\0");
    hasher.update(binding_digest);
    hasher.update(encoded);
    hasher.finalize().into()
}

fn activate_current_replica_for_recovery_fixture(
    replica: &RecoveryReplica,
    members: &BTreeSet<SessionConsensusNodeId>,
) -> (
    SessionConsensusRequestId,
    [u8; 32],
    Vec<u8>,
    [u8; 32],
    [u8; 32],
) {
    let logical_time = receipt_inspection_timestamp();
    let retained_until =
        crate::checked_session_deadline(logical_time, FENCED_TRANSITION_OUTCOME_RETENTION)
            .expect("fenced receipt retention deadline");
    let retained_until = crate::sqlite::ops::format_rfc3339_normalized(retained_until);
    let request_id = SessionConsensusRequestId::from_bytes([0xA1; 16]);
    let payload_digest = [0xA2; 32];
    let response = SessionConsensusResponse {
        result: Err(crate::StoreError::NotFound),
        sequence: 1,
        digest: Some(SessionConsensusEntryDigest::from_bytes([0xA3; 32])),
        logical_time: Some(logical_time),
        raft_log_index: 1,
    };
    let response_json = serde_json::to_vec(&response).expect("encode fenced receipt response");
    let binding_digest = fenced_receipt_binding_digest_for_recovery_fixture(
        request_id,
        payload_digest,
        &retained_until,
    );
    let response_digest =
        fenced_receipt_response_digest_for_recovery_fixture(binding_digest, &response);
    let voter_set_digest =
        crate::consensus::types::fenced_transition_voter_set_digest(identity(), members);
    let conn = Connection::open(&replica.database_path).expect("open activated current replica");
    conn.execute(
        "UPDATE consensus_identity SET schema_version = ?1, fenced_transition_receipt_ledger_activated = 1 WHERE singleton = 1",
        [i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) + 1],
    )
    .expect("activate fenced receipt ledger");
    conn.execute(
        "INSERT INTO consensus_fenced_transition_activation (singleton, storage_configuration_epoch, scope_configuration_id, scope_configuration_epoch, voter_set_digest) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            i64::try_from(identity().configuration_epoch().get()).expect("configuration epoch"),
            identity().configuration_id().as_bytes().as_slice(),
            i64::try_from(identity().configuration_epoch().get()).expect("scope epoch"),
            voter_set_digest.as_slice(),
        ],
    )
    .expect("insert exact activation certificate");
    conn.execute(
        "UPDATE consensus_machine SET application_sequence = 1, logical_time = ?1 WHERE singleton = 1",
        [crate::sqlite::ops::format_rfc3339_normalized(logical_time)],
    )
    .expect("advance machine for retained receipt");
    conn.execute(
        "INSERT INTO consensus_fenced_transition_receipts (request_id, configuration_epoch, payload_digest, retained_until, binding_digest, response_json, response_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            request_id.as_bytes().as_slice(),
            i64::try_from(identity().configuration_epoch().get()).expect("configuration epoch"),
            payload_digest.as_slice(),
            retained_until,
            binding_digest.as_slice(),
            response_json.as_slice(),
            response_digest.as_slice(),
        ],
    )
    .expect("insert valid retained fenced receipt");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint activated current replica");

    (
        request_id,
        payload_digest,
        response_json,
        binding_digest,
        response_digest,
    )
}

fn assert_activated_recovery_metadata(
    replica: &RecoveryReplica,
    members: &BTreeSet<SessionConsensusNodeId>,
    request_id: SessionConsensusRequestId,
    payload_digest: [u8; 32],
    response_json: &[u8],
    binding_digest: [u8; 32],
    response_digest: [u8; 32],
) {
    let conn = Connection::open(&replica.database_path).expect("open recovered activated replica");
    let (schema_version, activated): (i64, i64) = conn
        .query_row(
            "SELECT schema_version, fenced_transition_receipt_ledger_activated FROM consensus_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read activated schema fence");
    assert_eq!(
        schema_version,
        i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) + 1
    );
    assert_eq!(activated, 1);

    let certificate: (i64, Vec<u8>, i64, Vec<u8>) = conn
        .query_row(
            "SELECT storage_configuration_epoch, scope_configuration_id, scope_configuration_epoch, voter_set_digest FROM consensus_fenced_transition_activation WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read exact activation certificate");
    assert_eq!(
        certificate,
        (
            i64::try_from(identity().configuration_epoch().get()).expect("configuration epoch"),
            identity().configuration_id().as_bytes().to_vec(),
            i64::try_from(identity().configuration_epoch().get()).expect("scope epoch"),
            crate::consensus::types::fenced_transition_voter_set_digest(identity(), members)
                .to_vec(),
        )
    );

    let receipt: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT payload_digest, binding_digest, response_json, response_digest FROM consensus_fenced_transition_receipts WHERE request_id = ?1",
            [request_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read retained fenced receipt");
    assert_eq!(
        receipt,
        (
            payload_digest.to_vec(),
            binding_digest.to_vec(),
            response_json.to_vec(),
            response_digest.to_vec(),
        )
    );
}

fn insert_receipt_for_recovery_inspection(
    conn: &Connection,
    retained_until: Timestamp,
    response_json: Option<&[u8]>,
) {
    let response_digest = [0xA4_u8; 32];
    conn.execute(
        "INSERT INTO consensus_fenced_transition_receipts (request_id, configuration_epoch, payload_digest, retained_until, binding_digest, response_json, response_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            [0xA1_u8; 16].as_slice(),
            7_i64,
            [0xA2_u8; 32].as_slice(),
            crate::sqlite::ops::format_rfc3339_normalized(retained_until),
            [0xA3_u8; 32].as_slice(),
            response_json,
            response_json.map(|_| response_digest.as_slice()),
        ],
    )
    .expect("insert receipt fixture");
}

fn install_precommitment_fenced_receipt_table(conn: &Connection) {
    conn.execute_batch(
        r#"
        DROP TABLE consensus_fenced_transition_receipts;
        CREATE TABLE consensus_fenced_transition_receipts (
            request_id BLOB PRIMARY KEY,
            configuration_epoch INTEGER NOT NULL,
            payload_digest BLOB NOT NULL,
            retained_until TEXT NOT NULL,
            response_json BLOB
        );
        "#,
    )
    .expect("install pre-commitment receipt table");
}

#[test]
fn current_recovery_inspection_rejects_malformed_fenced_receipt_response_json() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (replica, members) = current_receipt_inspection_fixture(temp.path());
    let conn = Connection::open(&replica.database_path).expect("open current replica");
    insert_receipt_for_recovery_inspection(&conn, receipt_inspection_timestamp(), Some(b"{"));
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint receipt mutation");
    drop(conn);

    assert_eq!(
        inspect_replica(InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        }),
        Err(RecoveryError::CorruptReplica)
    );
}

#[test]
fn current_recovery_inspection_rejects_partial_receipt_commitment_schema() {
    for partial_column in ["binding_digest", "response_digest"] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let (replica, members) = current_receipt_inspection_fixture(temp.path());
        let conn = Connection::open(&replica.database_path).expect("open current replica");
        conn.execute_batch("DROP TABLE consensus_fenced_transition_receipts")
            .expect("remove canonical receipt table");
        let partial_schema = format!(
            "CREATE TABLE consensus_fenced_transition_receipts (request_id BLOB PRIMARY KEY, configuration_epoch INTEGER, payload_digest BLOB, retained_until TEXT, {partial_column} BLOB, response_json BLOB)"
        );
        conn.execute_batch(&partial_schema)
            .expect("install partial receipt schema");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint partial receipt schema");
        drop(conn);

        assert_eq!(
            inspect_replica(InspectionInput {
                key: &integrity_key(),
                replica: &replica,
                identity: identity(),
                expected_members: &members,
                limits: RecoveryLimits::default(),
            }),
            Err(RecoveryError::CorruptReplica),
            "{partial_column}",
        );
    }
}

#[test]
fn current_recovery_inspection_rejects_empty_and_populated_precommitment_receipt_table() {
    for populated in [false, true] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let (replica, members) = current_receipt_inspection_fixture(temp.path());
        let conn = Connection::open(&replica.database_path).expect("open current replica");
        install_precommitment_fenced_receipt_table(&conn);
        if populated {
            conn.execute(
                "INSERT INTO consensus_fenced_transition_receipts (request_id, configuration_epoch, payload_digest, retained_until, response_json) VALUES (?1, ?2, ?3, ?4, NULL)",
                params![
                    [0xA5_u8; 16].as_slice(),
                    7_i64,
                    [0xA6_u8; 32].as_slice(),
                    crate::sqlite::ops::format_rfc3339_normalized(receipt_inspection_timestamp()),
                ],
            )
            .expect("populate pre-commitment receipt table");
        }
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint pre-commitment receipt table");
        drop(conn);

        let inspected = inspect_replica(InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        });
        assert_eq!(
            inspected,
            Err(RecoveryError::CorruptReplica),
            "populated={populated}",
        );
    }
}

#[test]
fn current_recovery_inspection_rejects_premature_fenced_receipt_tombstone() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (replica, members) = current_receipt_inspection_fixture(temp.path());
    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let logical_time = receipt_inspection_timestamp();
    let retained_until =
        crate::checked_session_deadline(logical_time, crate::FENCED_TRANSITION_OUTCOME_RETENTION)
            .expect("receipt retention deadline");
    conn.execute(
        "UPDATE consensus_machine SET logical_time = ?1 WHERE singleton = 1",
        [crate::sqlite::ops::format_rfc3339_normalized(logical_time)],
    )
    .expect("set durable machine time");
    insert_receipt_for_recovery_inspection(&conn, retained_until, None);
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint receipt mutation");
    drop(conn);

    assert_eq!(
        inspect_replica(InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        }),
        Err(RecoveryError::CorruptReplica)
    );
}

#[test]
fn current_recovery_inspection_rejects_fenced_receipt_beyond_durable_floors() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (replica, members) = current_receipt_inspection_fixture(temp.path());
    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let logical_time = receipt_inspection_timestamp();
    let retained_until =
        crate::checked_session_deadline(logical_time, crate::FENCED_TRANSITION_OUTCOME_RETENTION)
            .expect("receipt retention deadline");
    let response = crate::SessionConsensusResponse {
        result: Err(crate::StoreError::NotFound),
        sequence: 1,
        digest: Some(crate::SessionConsensusEntryDigest::from_bytes([0xA3; 32])),
        logical_time: Some(logical_time),
        raft_log_index: 1,
    };
    let response_json = serde_json::to_vec(&response).expect("encode receipt response");
    insert_receipt_for_recovery_inspection(&conn, retained_until, Some(&response_json));
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint receipt mutation");
    drop(conn);

    assert_eq!(
        inspect_replica(InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        }),
        Err(RecoveryError::CorruptReplica)
    );
}

#[test]
fn current_recovery_inspection_accepts_pre_ledger_replica() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (replica, members) = current_receipt_inspection_fixture(temp.path());
    let conn = Connection::open(&replica.database_path).expect("open current replica");
    conn.execute_batch(
        "DROP TABLE consensus_fenced_transition_receipts;
         DROP TABLE consensus_fenced_transition_activation;
         ALTER TABLE consensus_identity
         DROP COLUMN fenced_transition_receipt_ledger_activated;
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .expect("restore the exact published #684 receipt shape");
    drop(conn);

    inspect_replica(InspectionInput {
        key: &integrity_key(),
        replica: &replica,
        identity: identity(),
        expected_members: &members,
        limits: RecoveryLimits::default(),
    })
    .expect("read-only inspection accepts a pre-ledger replica");
}

#[test]
fn current_recovery_inspection_normalizes_exact_pre_acquisition_lease_schema() {
    for active in [false, true] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let (replica, members) = current_receipt_inspection_fixture(temp.path());
        let conn = Connection::open(&replica.database_path).expect("open current replica");
        if active {
            let key = SessionKey {
                tenant: TenantId::from_static("recovery-pre-acquired-at"),
                nf_kind: NetworkFunctionKind::from_static("smf"),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"recovery-pre-acquired-at")
                    .try_into()
                    .expect("valid stable ID"),
            };
            crate::sqlite::lease::acquire_sync(
                &conn,
                &key,
                OwnerId::new("recovery-pre-acquired-at-owner").expect("owner"),
                Duration::from_secs(300),
                Timestamp::from_str("2027-01-01T00:00:00Z").expect("timestamp"),
            )
            .expect("insert active legacy lease");
        }
        conn.execute_batch(
            "ALTER TABLE leases DROP COLUMN acquired_at; PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .expect("form exact pre-acquisition schema");
        drop(conn);

        let inspected = inspect_replica(InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        })
        .expect("read-only inspection accepts exact pre-acquisition schema");

        drop(
            SqliteSessionBackend::open(&replica.database_path)
                .expect("writable migration adds non-authoritative marker"),
        );
        let migrated = inspect_replica(InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        })
        .expect("inspection accepts migrated schema");
        assert_eq!(
            inspected.branch_digest, migrated.branch_digest,
            "active={active}"
        );
        assert_eq!(
            inspected.logical_state_digest, migrated.logical_state_digest,
            "active={active}"
        );
    }
}

#[test]
fn current_recovery_plan_accepts_exact_pre_acquisition_lease_schema() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("pre-acquired-at-current-a"),
        replica_id("pre-acquired-at-current-b"),
        replica_id("pre-acquired-at-current-c"),
    ];
    let replicas = ids
        .iter()
        .cloned()
        .map(|id| create_legacy_replica(temp.path(), id, 7))
        .collect::<Vec<_>>();
    let members = node_set(&ids);
    let majority_log = LogId::new(
        CommittedLeaderId::new(1, *members.first().expect("member")),
        0,
    );
    let fork_log = LogId::new(
        CommittedLeaderId::new(2, *members.iter().nth(1).expect("fork leader")),
        0,
    );
    for (index, replica) in replicas.iter().enumerate() {
        claim_current_replica(
            replica,
            &members,
            if index == 2 { fork_log } else { majority_log },
        );
        Connection::open(&replica.database_path)
            .expect("open current replica")
            .execute_batch(
                "ALTER TABLE leases DROP COLUMN acquired_at; PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .expect("form exact pre-acquisition schema");
    }

    let _plan = recovery(AllowRecovery)
        .plan(
            &context(),
            identity(),
            members,
            &replicas,
            &ids[0],
            &ids[2..],
            RecoveryDecisionBasis::VerifiedCommittedMajority,
            RecoveryLimits::default(),
        )
        .expect("recovery plan accepts matching legacy lease schemas");
}

#[test]
fn planning_rejects_any_pending_recovery_workflow() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("pending-replica-a"),
        replica_id("pending-replica-b"),
        replica_id("pending-replica-c"),
    ];
    let replicas = ids
        .iter()
        .cloned()
        .map(|id| create_legacy_replica(temp.path(), id, 7))
        .collect::<Vec<_>>();
    let members = node_set(&ids);
    let leader = *members.iter().next().expect("leader");
    let log_id = LogId::new(CommittedLeaderId::new(3, leader), 0);
    for replica in &replicas {
        claim_current_replica(replica, &members, log_id);
    }
    let conn = Connection::open(&replicas[1].database_path).expect("open pending replica");
    consensus::mark_operator_recovery_pending_sync(&conn, identity(), 2, [0x91; 32])
        .expect("mark different recovery pending");
    drop(conn);

    let manager = recovery(AllowRecovery);
    assert_eq!(
        manager.plan(
            &context(),
            identity(),
            members,
            &replicas,
            &ids[0],
            &ids[2..],
            RecoveryDecisionBasis::VerifiedCommittedMajority,
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::RecoveryInProgress)
    );
}

#[test]
fn planning_rejects_untrusted_legacy_schema_objects() {
    for (suffix, sql) in [
        (
            "trigger",
            "CREATE TRIGGER hostile_trigger AFTER UPDATE ON key_fences BEGIN DELETE FROM leases; END;",
        ),
        (
            "view",
            "CREATE VIEW hostile_view AS SELECT * FROM session_records;",
        ),
        ("table", "CREATE TABLE hostile_table (secret BLOB);"),
    ] {
        let temp = tempfile::tempdir().expect("schema test root");
        let ids = [
            replica_id(&format!("schema-{suffix}-a")),
            replica_id(&format!("schema-{suffix}-b")),
            replica_id(&format!("schema-{suffix}-c")),
        ];
        let replicas = vec![
            create_legacy_replica(temp.path(), ids[0].clone(), 1),
            create_legacy_replica(temp.path(), ids[1].clone(), 2),
            create_legacy_replica(temp.path(), ids[2].clone(), 3),
        ];
        Connection::open(&replicas[1].database_path)
            .expect("open hostile schema")
            .execute_batch(sql)
            .expect("install hostile schema object");
        let manager = recovery(AllowRecovery);
        assert_eq!(
            manager.plan(
                &context(),
                identity(),
                node_set(&ids),
                &replicas,
                &ids[0],
                &ids,
                RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
                RecoveryLimits::default(),
            ),
            Err(RecoveryError::CorruptReplica),
            "untrusted {suffix} must fail closed"
        );
    }

    let temp = tempfile::tempdir().expect("restore schema test root");
    let ids = [
        replica_id("schema-restore-a"),
        replica_id("schema-restore-b"),
        replica_id("schema-restore-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 1),
        create_legacy_replica(temp.path(), ids[1].clone(), 2),
        create_legacy_replica(temp.path(), ids[2].clone(), 3),
    ];
    Connection::open(&replicas[1].database_path)
        .expect("open hostile restore schema")
        .execute_batch(
            r#"
            DROP TABLE restore_scan_state;
            CREATE TABLE restore_scan_state (
                singleton INTEGER PRIMARY KEY,
                epoch BLOB NOT NULL,
                revision INTEGER NOT NULL,
                cursor_key BLOB NOT NULL
            );
            "#,
        )
        .expect("install hostile same-name restore schema");
    let manager = recovery(AllowRecovery);
    assert_eq!(
        manager.plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &ids[0],
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::CorruptReplica)
    );

    let temp = tempfile::tempdir().expect("current schema test root");
    let ids = [
        replica_id("schema-current-a"),
        replica_id("schema-current-b"),
        replica_id("schema-current-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 1),
        create_legacy_replica(temp.path(), ids[1].clone(), 1),
        create_legacy_replica(temp.path(), ids[2].clone(), 2),
    ];
    let members = node_set(&ids);
    let log_id = LogId::new(
        CommittedLeaderId::new(1, *members.first().expect("node")),
        0,
    );
    for replica in &replicas {
        claim_current_replica(replica, &members, log_id);
    }
    Connection::open(&replicas[1].database_path)
        .expect("open current hostile schema")
        .execute_batch("CREATE VIEW hostile_current_view AS SELECT * FROM consensus_machine;")
        .expect("install current hostile view");
    let manager = recovery(AllowRecovery);
    assert_eq!(
        manager.plan(
            &context(),
            identity(),
            members,
            &replicas,
            &ids[0],
            &ids[2..],
            RecoveryDecisionBasis::VerifiedCommittedMajority,
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::CorruptReplica)
    );
}

#[test]
fn planning_rejects_current_tables_with_same_name_and_weakened_ddl() {
    for (suffix, replacement) in [
        (
            "type",
            r#"
            CREATE TABLE consensus_vote (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                term TEXT NOT NULL CHECK (term >= 0),
                node_id INTEGER CHECK (node_id > 0),
                vote_json BLOB NOT NULL,
                FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
            );
            "#,
        ),
        (
            "not-null",
            r#"
            CREATE TABLE consensus_vote (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                term INTEGER NOT NULL CHECK (term >= 0),
                node_id INTEGER CHECK (node_id > 0),
                vote_json BLOB,
                FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
            );
            "#,
        ),
        (
            "primary-key",
            r#"
            CREATE TABLE consensus_vote (
                singleton INTEGER NOT NULL CHECK (singleton = 1),
                configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                term INTEGER NOT NULL CHECK (term >= 0),
                node_id INTEGER CHECK (node_id > 0),
                vote_json BLOB NOT NULL,
                FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
            );
            "#,
        ),
        (
            "check",
            r#"
            CREATE TABLE consensus_vote (
                singleton INTEGER PRIMARY KEY,
                configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                term INTEGER NOT NULL CHECK (term >= 0),
                node_id INTEGER CHECK (node_id > 0),
                vote_json BLOB NOT NULL,
                FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
            );
            "#,
        ),
        (
            "foreign-key",
            r#"
            CREATE TABLE consensus_vote (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                term INTEGER NOT NULL CHECK (term >= 0),
                node_id INTEGER CHECK (node_id > 0),
                vote_json BLOB NOT NULL
            );
            "#,
        ),
        (
            "default",
            r#"
            CREATE TABLE consensus_vote (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                term INTEGER NOT NULL DEFAULT 0 CHECK (term >= 0),
                node_id INTEGER CHECK (node_id > 0),
                vote_json BLOB NOT NULL,
                FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
            );
            "#,
        ),
    ] {
        let temp = tempfile::tempdir().expect("current schema test root");
        let ids = [
            replica_id(&format!("weakened-{suffix}-a")),
            replica_id(&format!("weakened-{suffix}-b")),
            replica_id(&format!("weakened-{suffix}-c")),
        ];
        let replicas = vec![
            create_legacy_replica(temp.path(), ids[0].clone(), 1),
            create_legacy_replica(temp.path(), ids[1].clone(), 1),
            create_legacy_replica(temp.path(), ids[2].clone(), 2),
        ];
        let members = node_set(&ids);
        let log_id = LogId::new(
            CommittedLeaderId::new(1, *members.first().expect("node")),
            0,
        );
        for replica in &replicas {
            claim_current_replica(replica, &members, log_id);
        }
        Connection::open(&replicas[1].database_path)
            .expect("open weakened current schema")
            .execute_batch(&format!("DROP TABLE consensus_vote; {replacement}"))
            .expect("install same-name weakened current table");

        let manager = recovery(AllowRecovery);
        assert_eq!(
            manager.plan(
                &context(),
                identity(),
                members,
                &replicas,
                &ids[0],
                &ids[2..],
                RecoveryDecisionBasis::VerifiedCommittedMajority,
                RecoveryLimits::default(),
            ),
            Err(RecoveryError::CorruptReplica),
            "current same-name {suffix} weakening must fail closed"
        );
    }
}

#[test]
fn planning_accepts_the_supported_operator_recovery_cursor_migration() {
    let temp = tempfile::tempdir().expect("current migration test root");
    let ids = [
        replica_id("operator-migration-a"),
        replica_id("operator-migration-b"),
        replica_id("operator-migration-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 41),
    ];
    let members = node_set(&ids);
    let leader = *members.iter().next().expect("leader");
    let fork_leader = *members.iter().nth(1).expect("fork leader");
    let majority_log = LogId::new(CommittedLeaderId::new(3, leader), 0);
    let fork_log = LogId::new(CommittedLeaderId::new(4, fork_leader), 0);
    claim_current_replica(&replicas[0], &members, majority_log);
    claim_current_replica(&replicas[1], &members, majority_log);
    claim_current_replica(&replicas[2], &members, fork_log);

    for replica in &replicas {
        let conn = Connection::open(&replica.database_path).expect("open migrated replica");
        conn.execute_batch(
            r#"
            DROP TABLE consensus_operator_recovery;
            CREATE TABLE IF NOT EXISTS consensus_operator_recovery (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
                recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
                last_plan_digest BLOB NOT NULL CHECK (length(last_plan_digest) = 32),
                pending_epoch INTEGER CHECK (pending_epoch > recovery_epoch),
                pending_plan_digest BLOB CHECK (
                    pending_plan_digest IS NULL OR length(pending_plan_digest) = 32
                ),
                CHECK (
                    (pending_epoch IS NULL AND pending_plan_digest IS NULL)
                    OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL)
                ),
                FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
            );
            "#,
        )
        .expect("install pre-cursor operator recovery schema");
        conn.execute(
            "INSERT INTO consensus_operator_recovery (singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest) VALUES (1, ?1, 1, ?2, NULL, NULL)",
            params![
                i64::try_from(identity().configuration_epoch().get())
                    .expect("configuration epoch"),
                [0x66_u8; 32].as_slice(),
            ],
        )
        .expect("restore operator recovery state");
        consensus::ensure_operator_recovery_schema_sync(&conn, identity())
            .expect("migrate the operator recovery cursor floor");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint migrated replica");
    }

    let _plan = recovery(AllowRecovery)
        .plan(
            &context(),
            identity(),
            members,
            &replicas,
            &ids[0],
            &ids[2..],
            RecoveryDecisionBasis::VerifiedCommittedMajority,
            RecoveryLimits::default(),
        )
        .expect("the exact supported operator recovery migration remains recoverable");
}

#[tokio::test]
async fn three_way_current_fork_requires_and_uses_majority_committed_checkpoint() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("current-replica-a"),
        replica_id("current-replica-b"),
        replica_id("current-replica-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 41),
    ];
    let members = node_set(&ids);
    let leader = *members.iter().next().expect("first member");
    let fork_leader = *members.iter().nth(1).expect("second member");
    let majority_log = LogId::new(CommittedLeaderId::new(3, leader), 0);
    let fork_log = LogId::new(CommittedLeaderId::new(4, fork_leader), 0);
    claim_current_replica(&replicas[0], &members, majority_log);
    claim_current_replica(&replicas[1], &members, majority_log);
    claim_current_replica(&replicas[2], &members, fork_log);

    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            identity(),
            members,
            &replicas,
            &ids[0],
            &ids[2..],
            RecoveryDecisionBasis::VerifiedCommittedMajority,
            RecoveryLimits::default(),
        )
        .expect("majority-authoritative recovery plan");
    assert_eq!(
        plan.basis(),
        RecoveryDecisionBasis::VerifiedCommittedMajority
    );
    assert_eq!(
        plan.evidence()
            .iter()
            .filter(|evidence| evidence.branch_digest() == plan.source_branch_digest())
            .count(),
        2
    );
    let confirmation = RecoveryConfirmation::verified(&plan);
    let majority_before = [0_usize, 1]
        .into_iter()
        .map(|index| {
            inspect_replica(InspectionInput {
                key: &manager.integrity_key,
                replica: &replicas[index],
                identity: identity(),
                expected_members: &node_set(&ids),
                limits: RecoveryLimits::default(),
            })
            .expect("inspect majority before reset")
        })
        .collect::<Vec<_>>();
    manager
        .execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        )
        .expect("repair current-format minority fork");
    for replica in &replicas {
        let latch = consensus::read_operator_recovery_latch_sync(&replica.database_path)
            .expect("read current-format campaign latch")
            .expect("every voter, including untouched majority voters, must be latched");
        assert_eq!(latch.plan_digest, plan.plan_digest().as_bytes());
    }

    let majority_after = [0_usize, 1]
        .into_iter()
        .map(|index| {
            inspect_replica(InspectionInput {
                key: &manager.integrity_key,
                replica: &replicas[index],
                identity: identity(),
                expected_members: &node_set(&ids),
                limits: RecoveryLimits::default(),
            })
            .expect("inspect majority after reset")
        })
        .collect::<Vec<_>>();
    assert_eq!(majority_after, majority_before);

    let repaired = inspect_replica(InspectionInput {
        key: &manager.integrity_key,
        replica: &replicas[2],
        identity: identity(),
        expected_members: &node_set(&ids),
        limits: RecoveryLimits::default(),
    })
    .expect("inspect repaired target");
    assert_eq!(
        repaired.committed_index(),
        majority_before[0].committed_index()
    );
    assert_eq!(repaired.applied_index(), majority_before[0].applied_index());
    assert_eq!(
        repaired.local_head_index(),
        majority_before[0].local_head_index()
    );
    assert_eq!(
        repaired.pending_recovery_epoch(),
        Some(plan.next_recovery_epoch())
    );
    assert_eq!(repaired.pending_plan_digest(), Some(plan.plan_digest()));
    assert_eq!(repaired.fence_high_water(), 7);
    let recovered_backend =
        SqliteSessionBackend::open(&replicas[2].database_path).expect("open recovered target");
    assert!(recovered_backend
        .consensus_operator_recovery_pending(identity())
        .await
        .expect("read target recovery gate"));
}

#[tokio::test]
async fn activated_current_checkpoint_recovery_preserves_fenced_transition_evidence() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("activated-recovery-a"),
        replica_id("activated-recovery-b"),
        replica_id("activated-recovery-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 41),
    ];
    let members = node_set(&ids);
    let leader = *members.iter().next().expect("first member");
    let fork_leader = *members.iter().nth(1).expect("second member");
    let majority_log = LogId::new(CommittedLeaderId::new(3, leader), 0);
    let fork_log = LogId::new(CommittedLeaderId::new(4, fork_leader), 0);
    claim_current_replica(&replicas[0], &members, majority_log);
    claim_current_replica(&replicas[1], &members, majority_log);
    claim_current_replica(&replicas[2], &members, fork_log);
    let majority_blank = LogId::new(CommittedLeaderId::new(3, leader), 1);
    append_current_blank_checkpoint(&replicas[0], majority_blank);
    append_current_blank_checkpoint(&replicas[1], majority_blank);

    let expected_receipt = activate_current_replica_for_recovery_fixture(&replicas[0], &members);
    assert_eq!(
        expected_receipt,
        activate_current_replica_for_recovery_fixture(&replicas[1], &members),
        "the committed majority must carry identical activated evidence",
    );

    let manager = recovery(AllowRecovery);
    let majority_before = [0_usize, 1]
        .into_iter()
        .map(|index| {
            inspect_replica(InspectionInput {
                key: &manager.integrity_key,
                replica: &replicas[index],
                identity: identity(),
                expected_members: &members,
                limits: RecoveryLimits::default(),
            })
            .expect("activated majority replica remains recoverably inspectable")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        majority_before[0].branch_digest(),
        majority_before[1].branch_digest(),
        "the majority copies must be an identical recovery branch",
    );
    assert_eq!(
        majority_before[0].logical_state_digest, majority_before[1].logical_state_digest,
        "the majority copies must carry the same activated logical state",
    );
    for replica in &replicas[..2] {
        assert_activated_recovery_metadata(
            replica,
            &members,
            expected_receipt.0,
            expected_receipt.1,
            &expected_receipt.2,
            expected_receipt.3,
            expected_receipt.4,
        );
    }

    let plan = manager
        .plan(
            &context(),
            identity(),
            members.clone(),
            &replicas,
            &ids[0],
            &ids[2..],
            RecoveryDecisionBasis::VerifiedCommittedMajority,
            RecoveryLimits::default(),
        )
        .expect("activated majority checkpoint produces a recovery plan");
    assert_eq!(
        plan.source_branch_digest(),
        majority_before[0].branch_digest(),
        "recovery selected the activated committed majority",
    );

    manager
        .execute(
            &context(),
            &plan,
            &RecoveryConfirmation::verified(&plan),
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        )
        .expect("apply activated checkpoint recovery");

    for replica in &replicas {
        inspect_replica(InspectionInput {
            key: &manager.integrity_key,
            replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        })
        .expect("recovered activated replica must not be classified CorruptReplica");
        assert_activated_recovery_metadata(
            replica,
            &members,
            expected_receipt.0,
            expected_receipt.1,
            &expected_receipt.2,
            expected_receipt.3,
            expected_receipt.4,
        );
    }
}

#[test]
fn backup_and_snapshot_failpoints_resume_without_losing_quarantine() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let first_id = replica_id("failpoint-source-a");
    let second_id = replica_id("failpoint-target-b");
    let third_id = replica_id("failpoint-target-c");
    let ids = [first_id.clone(), second_id.clone(), third_id.clone()];
    let replicas = vec![
        create_legacy_replica(temp.path(), first_id.clone(), 13),
        create_legacy_replica(temp.path(), second_id.clone(), 31),
        create_legacy_replica(temp.path(), third_id.clone(), 47),
    ];
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &first_id,
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("legacy plan");
    for failpoint in [
        RecoveryFailpoint::AfterTargetBackupCopy,
        RecoveryFailpoint::AfterCheckpointCopy,
        RecoveryFailpoint::AfterBackup,
        RecoveryFailpoint::AfterStagedCopy,
        RecoveryFailpoint::AfterSnapshotInstall,
        RecoveryFailpoint::AfterDatabaseTemporaryPrepared,
        RecoveryFailpoint::AfterDatabaseInstall,
    ] {
        assert_eq!(
            backup_and_reset_replica(ResetInput {
                key: &manager.integrity_key,
                plan: &plan,
                source: &replicas[0],
                replicas: &replicas,
                targets: &replicas.iter().collect::<Vec<_>>(),
                backup_root: backup.path(),
                limits: RecoveryLimits::default(),
                failpoint: Some(failpoint),
            }),
            Err(RecoveryError::InjectedFailure),
            "workflow must stop at {failpoint:?}"
        );
    }
    assert_eq!(
        backup_and_reset_replica(ResetInput {
            key: &manager.integrity_key,
            plan: &plan,
            source: &replicas[0],
            replicas: &replicas,
            targets: &replicas.iter().collect::<Vec<_>>(),
            backup_root: backup.path(),
            limits: RecoveryLimits::default(),
            failpoint: None,
        })
        .expect("resume failpoint workflow"),
        RecoveryExecutionState::AwaitingEpochCommit
    );
    let restore_incarnations = replicas
        .iter()
        .map(|replica| {
            let conn =
                Connection::open(&replica.database_path).expect("open failpoint-recovered replica");
            let (epoch, _, key) = crate::sqlite::ops::read_restore_scan_state_sync(&conn)
                .expect("read failpoint-recovered restore incarnation");
            (epoch, *key)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(restore_incarnations.len(), replicas.len());
}

#[cfg(unix)]
#[test]
fn recovery_artifacts_reject_insecure_roots_symlinks_and_unsealed_staging_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("artifact-source-a"),
        replica_id("artifact-target-b"),
        replica_id("artifact-target-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 5),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 9),
    ];
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &ids[0],
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("artifact recovery plan");
    let confirmation = RecoveryConfirmation::legacy(
        &plan,
        RecoveryConfirmation::required_legacy_acknowledgement(),
    );

    let insecure = tempfile::tempdir().expect("insecure backup root");
    std::fs::set_permissions(insecure.path(), std::fs::Permissions::from_mode(0o755))
        .expect("set insecure root mode");
    assert_eq!(
        manager.execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            insecure.path(),
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::FileOperationFailed)
    );

    let symlink_parent = private_tempdir();
    let linked_root = symlink_parent.path().join("linked-root");
    let destination = private_tempdir();
    symlink(destination.path(), &linked_root).expect("create backup-root symlink");
    assert_eq!(
        manager.execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            &linked_root,
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::FileOperationFailed)
    );

    let backup = private_tempdir();
    let targets = replicas.iter().collect::<Vec<_>>();
    assert_eq!(
        backup_and_reset_replica(ResetInput {
            key: &manager.integrity_key,
            plan: &plan,
            source: &replicas[0],
            replicas: &replicas,
            targets: &targets,
            backup_root: backup.path(),
            limits: RecoveryLimits::default(),
            failpoint: Some(RecoveryFailpoint::AfterBackup),
        }),
        Err(RecoveryError::InjectedFailure)
    );
    let staged = backup
        .path()
        .join(format!("recovery-{}", plan.plan_digest()))
        .join("staged.sqlite");
    std::fs::write(&staged, b"unsealed staging artifact").expect("precreate staged artifact");
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
        .expect("set staged artifact mode");
    assert_eq!(
        backup_and_reset_replica(ResetInput {
            key: &manager.integrity_key,
            plan: &plan,
            source: &replicas[0],
            replicas: &replicas,
            targets: &targets,
            backup_root: backup.path(),
            limits: RecoveryLimits::default(),
            failpoint: None,
        }),
        Err(RecoveryError::FileOperationFailed)
    );
}

#[tokio::test]
async fn legacy_log_tail_is_quarantined_cleared_and_old_cursors_fail_closed() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("legacy-log-source-a"),
        replica_id("legacy-log-target-b"),
        replica_id("legacy-log-target-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 19),
        create_legacy_replica(temp.path(), ids[2].clone(), 31),
    ];
    // This entry is structurally valid but has no provable relationship to
    // the explicitly selected checkpoint state. It is provenance only.
    insert_legacy_empty_replication(&replicas[0], 1);
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            identity(),
            node_set(&ids),
            &replicas,
            &ids[0],
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("legacy log recovery plan");
    manager
        .execute(
            &context(),
            &plan,
            &RecoveryConfirmation::legacy(
                &plan,
                RecoveryConfirmation::required_legacy_acknowledgement(),
            ),
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        )
        .expect("execute legacy log recovery");

    for replica in &replicas {
        let conn = Connection::open(&replica.database_path).expect("open recovered replica");
        let log_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM session_replication_log", [], |row| {
                row.get(0)
            })
            .expect("count cleared legacy log");
        let state = consensus::read_operator_recovery_sync(&conn, identity())
            .expect("read recovery cursor state");
        assert_eq!(log_rows, 0);
        assert_eq!(state.watch_cursor_invalidation_floor, 1);
        drop(conn);

        let backend =
            SqliteSessionBackend::open(&replica.database_path).expect("open recovered backend");
        assert_eq!(
            backend
                .consensus_max_replication_sequence()
                .await
                .expect("read preserved application high-water"),
            1
        );
        assert!(matches!(
            backend.consensus_get_replication_log(1, 16).await,
            Err(crate::StoreError::ReplicationLogCursorCompacted { resume_from: 2 })
        ));
    }

    insert_legacy_empty_replication(&replicas[0], 2);
    let advanced = Connection::open(&replicas[0].database_path).expect("open advanced replica");
    advanced
        .execute(
            "UPDATE consensus_machine SET watch_sequence = 2 WHERE singleton = 1",
            [],
        )
        .expect("advance recovered watch sequence");
    consensus::validate_sealed_state_sync(&advanced)
        .expect("post-recovery journal may continue above invalidation floor");
    drop(advanced);
    assert_eq!(
        inspect_replica(InspectionInput {
            key: &manager.integrity_key,
            replica: &replicas[0],
            identity: identity(),
            expected_members: &node_set(&ids),
            limits: RecoveryLimits::default(),
        })
        .expect("inspect advanced recovered replica")
        .watch_cursor_invalidation_floor(),
        1
    );

    let workflow = backup
        .path()
        .join(format!("recovery-{}", plan.plan_digest()));
    let quarantine = Connection::open(
        workflow
            .join("targets")
            .join(
                replica_token(&manager.integrity_key, &ids[0])
                    .expect("source replica token")
                    .to_hex(),
            )
            .join("target.sqlite"),
    )
    .expect("open source quarantine");
    let quarantined_rows: i64 = quarantine
        .query_row("SELECT COUNT(*) FROM session_replication_log", [], |row| {
            row.get(0)
        })
        .expect("count quarantined legacy log");
    assert_eq!(quarantined_rows, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovered_legacy_voter_set_forms_openraft_and_finalizes_as_one_campaign() {
    let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("campaign-replica-a"),
        replica_id("campaign-replica-b"),
        replica_id("campaign-replica-c"),
    ];
    let mut replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 11),
        create_legacy_replica(temp.path(), ids[1].clone(), 23),
        create_legacy_replica(temp.path(), ids[2].clone(), 37),
    ];
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("legacy-recovery-payload-key").expect("payload key ID"),
            KeyPurpose::Session,
            TenantId::from_static("tenant-a"),
            Zeroizing::new([0x5a; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("install payload key");
    let protected = EncryptingSessionBackend::new(
        Arc::new(
            SqliteSessionBackend::open(&replicas[0].database_path)
                .expect("open legacy protected source"),
        ),
        provider.clone(),
        "legacy-recovery-campaign",
    );
    let protected_key = SessionKey {
        tenant: TenantId::from_static("tenant-a"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"legacy-protected-session")
            .try_into()
            .expect("valid stable ID"),
    };
    let protected_lease = protected
        .acquire(
            &protected_key,
            OwnerId::new("legacy-recovery-owner").expect("protected owner"),
            Duration::from_secs(300),
        )
        .await
        .expect("protected legacy lease");
    assert_eq!(
        protected
            .compare_and_set(CompareAndSet {
                key: protected_key.clone(),
                lease: protected_lease.clone(),
                expected_generation: None,
                new_record: StoredSessionRecord {
                    key: protected_key.clone(),
                    generation: Generation::new(1),
                    owner: protected_lease.owner().clone(),
                    fence: protected_lease.fence(),
                    state_class: StateClass::AuthoritativeSession,
                    state_type: StateType::new("legacy-protected-context")
                        .expect("protected state type"),
                    expires_at: None,
                    payload: EncryptedSessionPayload::new(Bytes::from_static(
                        b"legacy-recovery-plaintext-canary",
                    )),
                },
            })
            .await
            .expect("write protected legacy state"),
        CompareAndSetResult::Success
    );
    drop(protected);
    Connection::open(&replicas[0].database_path)
        .expect("checkpoint protected source")
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint protected source WAL");
    let descriptors = ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            QuorumReplicaDescriptor::new(
                id.clone(),
                ReplicaEndpoint::new(format!("campaign-{index}.invalid"), 7443)
                    .expect("campaign endpoint"),
                ReplicaTlsIdentity::new(format!("spiffe://test/session/campaign-{index}"))
                    .expect("campaign TLS identity"),
                ReplicaFailureDomain::new(format!("campaign-zone-{index}"))
                    .expect("campaign failure domain"),
                ReplicaBackingIdentity::new(format!("campaign-disk-{index}"))
                    .expect("campaign backing identity"),
            )
        })
        .collect::<Vec<_>>();
    let cluster = SessionConsensusClusterId::new("legacy-recovery-campaign").expect("cluster");
    let epoch = SessionConsensusConfigurationEpoch::new(1).expect("epoch");
    let configuration = opc_consensus::derive_configuration_id(
        cluster,
        epoch,
        &descriptors
            .iter()
            .map(QuorumReplicaDescriptor::configuration_fingerprint)
            .collect::<Vec<_>>(),
    );
    let campaign_identity = SessionConsensusIdentity::new(cluster, configuration, epoch);
    for replica in &mut replicas {
        replica.admitted_identity = campaign_identity;
    }
    let members = node_set_for(campaign_identity, &ids);
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            campaign_identity,
            members,
            &replicas,
            &ids[0],
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("whole-fleet campaign plan");
    let confirmation = RecoveryConfirmation::legacy(
        &plan,
        RecoveryConfirmation::required_legacy_acknowledgement(),
    );
    manager
        .execute(
            &context(),
            &plan,
            &confirmation,
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        )
        .expect("install whole-fleet campaign checkpoint");
    let plaintext_canary = b"legacy-recovery-plaintext-canary";
    for replica in &replicas {
        let database = std::fs::read(&replica.database_path).expect("read recovered database");
        assert!(!database
            .windows(plaintext_canary.len())
            .any(|window| window == plaintext_canary));
    }
    assert_tree_does_not_contain(backup.path(), plaintext_canary);

    let topologies = ids
        .iter()
        .map(|id| {
            ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                id.clone(),
                descriptors.clone(),
                campaign_identity,
            ))
            .expect("campaign topology")
        })
        .collect::<Vec<_>>();
    let node_ids = topologies
        .iter()
        .map(|topology| {
            topology
                .local_consensus_node_id()
                .expect("campaign node ID")
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..ids.len() {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(RecoveryLoopbackPeer::new(node_id)),
                );
            }
        }
    }
    let backends = replicas
        .iter()
        .map(|replica| {
            SqliteSessionBackend::open(&replica.database_path).expect("campaign backend")
        })
        .collect::<Vec<_>>();
    let mut stores = Vec::new();
    for index in 0..ids.len() {
        let peers = (0..ids.len())
            .filter(|target| *target != index)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(index, target))
                    .expect("campaign peer path")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        stores.push(
            ConsensusSessionStore::open_with_clock(
                topologies[index].clone(),
                backends[index].clone(),
                replicas[index].snapshot_directory.clone(),
                peers,
                Arc::new(SystemClock),
                Duration::from_millis(750),
            )
            .await
            .expect("open recovered campaign node"),
        );
    }
    for ((_, target), path) in &paths {
        path.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize recovered campaign membership");
    }

    // Campaign finalization and readiness share one bounded window that admits
    // a split-vote resampling plus a complete profiled operation.
    let deadline = Instant::now() + RECOVERY_CAMPAIGN_TRANSITION_TIMEOUT;
    let report = loop {
        let mut completed = None;
        for store in &stores {
            match manager
                .finalize(
                    &context(),
                    store,
                    &plan,
                    &confirmation,
                    &replicas,
                    backup.path(),
                )
                .await
            {
                Ok(report) => {
                    completed = Some(report);
                    break;
                }
                Err(RecoveryError::ConsensusUnavailable) => {}
                Err(error) => panic!("campaign finalization failed: {error}"),
            }
        }
        if let Some(report) = completed {
            break report;
        }
        assert!(
            Instant::now() < deadline,
            "campaign recovery finalization did not converge"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(report.state(), RecoveryExecutionState::Rejoined);

    for store in &stores {
        let report = loop {
            let report = store.probe_durable_readiness().await;
            if report.is_ready() {
                break report;
            }
            assert!(
                Instant::now() < deadline,
                "campaign member did not clear recovery readiness fence"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert!(report.is_ready());
    }

    let recovered = EncryptingSessionBackend::new(
        Arc::new(stores[0].clone()),
        provider,
        "legacy-recovery-campaign",
    );
    let recovered_record = recovered
        .get(&protected_key)
        .await
        .expect("read recovered protected state")
        .expect("recovered protected record");
    assert_eq!(
        recovered_record.payload.as_bytes(),
        b"legacy-recovery-plaintext-canary"
    );
    let finalized_inodes = replicas
        .iter()
        .map(|replica| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(&replica.database_path)
                    .expect("stat finalized voter")
                    .ino()
            }
            #[cfg(not(unix))]
            {
                std::fs::metadata(&replica.database_path)
                    .expect("stat finalized voter")
                    .len()
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        manager
            .execute(
                &context(),
                &plan,
                &confirmation,
                &replicas,
                backup.path(),
                RecoveryLimits::default(),
            )
            .expect("completed execute retry")
            .state(),
        RecoveryExecutionState::Rejoined
    );
    for store in &stores {
        assert!(
            store.probe_durable_readiness().await.is_ready(),
            "a completed execute retry must not recreate the fleet recovery latch"
        );
    }
    assert_eq!(
        manager
            .finalize(
                &context(),
                &stores[0],
                &plan,
                &confirmation,
                &replicas,
                backup.path(),
            )
            .await
            .expect("completed finalize retry")
            .state(),
        RecoveryExecutionState::Rejoined
    );
    let retried_inodes = replicas
        .iter()
        .map(|replica| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(&replica.database_path)
                    .expect("stat retried voter")
                    .ino()
            }
            #[cfg(not(unix))]
            {
                std::fs::metadata(&replica.database_path)
                    .expect("stat retried voter")
                    .len()
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(retried_inodes, finalized_inodes);
}

#[tokio::test]
async fn recovery_epoch_is_durable_idempotent_and_invalidates_old_credentials() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let database = temp.path().join("epoch.sqlite");
    let backend = SqliteSessionBackend::open(&database).expect("SQLite backend");
    let key = SessionKey {
        tenant: TenantId::from_static("recovery-epoch-tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"recovery-epoch-session")
            .try_into()
            .expect("valid stable ID"),
    };
    let guard = backend
        .acquire(
            &key,
            OwnerId::new("pre-recovery-owner").expect("owner"),
            Duration::from_secs(300),
        )
        .await
        .expect("pre-recovery lease");
    drop(backend);

    let ids = [replica_id("epoch-a"), replica_id("epoch-b")];
    let members = node_set(&ids);
    let conn = Connection::open(&database).expect("open recovery database");
    consensus::claim_legacy_checkpoint_sync(
        &conn,
        identity(),
        &members,
        [0x21; 32],
        1,
        [0x31; 32],
        0,
        0,
    )
    .expect("claim legacy state");
    let fence_high = consensus::observed_fence_high_water_sync(&conn).expect("fence high-water");
    let credential_high =
        consensus::observed_credential_high_water_sync(&conn).expect("credential high-water");
    assert_eq!(
        consensus::finalize_operator_recovery_sync(
            &conn,
            identity(),
            1,
            [0x31; 32],
            fence_high,
            credential_high,
        )
        .expect("finalize recovery"),
        consensus::OperatorRecoveryApply::Applied
    );
    assert_eq!(
        consensus::finalize_operator_recovery_sync(
            &conn,
            identity(),
            1,
            [0x31; 32],
            fence_high,
            credential_high,
        )
        .expect("idempotent finalize"),
        consensus::OperatorRecoveryApply::Idempotent
    );
    assert_eq!(
        consensus::finalize_operator_recovery_sync(
            &conn,
            identity(),
            1,
            [0x32; 32],
            fence_high,
            credential_high,
        )
        .expect("conflicting same-epoch finalize"),
        consensus::OperatorRecoveryApply::Rejected
    );
    let active: i64 = conn
        .query_row("SELECT active FROM leases", [], |row| row.get(0))
        .expect("read lease state");
    assert_eq!(active, 0);
    assert!(matches!(
        crate::sqlite::lease::renew_sync(
            &conn,
            &guard,
            Duration::from_secs(300),
            Timestamp::now_utc(),
        ),
        Err(crate::LeaseError::StaleFence | crate::LeaseError::NotFound)
    ));
    drop(conn);

    let restarted = Connection::open(&database).expect("restart recovery database");
    let state = consensus::read_operator_recovery_sync(&restarted, identity())
        .expect("read durable recovery state after restart");
    assert_eq!(state.recovery_epoch, 1);
    assert_eq!(state.last_plan_digest, [0x31; 32]);
    assert!(state.pending_epoch.is_none());
    assert!(state.pending_plan_digest.is_none());
    assert_eq!(
        consensus::observed_fence_high_water_sync(&restarted).expect("restarted fence high-water"),
        fence_high
    );
    assert_eq!(
        consensus::observed_credential_high_water_sync(&restarted)
            .expect("restarted credential high-water"),
        credential_high
    );
}

#[tokio::test]
async fn finalization_failpoints_resume_before_after_epoch_and_rejoin() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let database = temp.path().join("finalize.sqlite");
    let snapshots = temp.path().join("snapshots");
    let (topology, store_identity, node) = singleton_topology();
    let backend = SqliteSessionBackend::open(&database).expect("SQLite backend");
    let store = ConsensusSessionStore::open(topology, backend, &snapshots, BTreeMap::new())
        .await
        .expect("open singleton store");
    store
        .initialize_cluster()
        .await
        .expect("initialize singleton cluster");
    let manager = recovery(AllowRecovery);
    let wrong_plan = sealed_test_plan(&manager, identity(), node);
    let wrong_confirmation = RecoveryConfirmation::verified(&wrong_plan);
    prepare_test_workflow(
        &manager.integrity_key,
        &wrong_plan,
        backup.path(),
        RecoveryExecutionState::AwaitingEpochCommit,
    )
    .expect("prepare wrong-cluster workflow");
    assert_eq!(
        manager
            .finalize(
                &context(),
                &store,
                &wrong_plan,
                &wrong_confirmation,
                &[],
                backup.path(),
            )
            .await,
        Err(RecoveryError::WrongCluster)
    );
    let plan = sealed_test_plan(&manager, store_identity, node);
    let confirmation = RecoveryConfirmation::verified(&plan);
    prepare_test_workflow(
        &manager.integrity_key,
        &plan,
        backup.path(),
        RecoveryExecutionState::AwaitingEpochCommit,
    )
    .expect("prepare awaiting workflow");

    assert_eq!(
        manager
            .finalize_with_failpoint(
                &context(),
                &store,
                &plan,
                &confirmation,
                &[],
                backup.path(),
                RecoveryFinalizeFailpoint::BeforeEpochCommit,
            )
            .await,
        Err(RecoveryError::InjectedFailure)
    );
    let before = Connection::open(&database).expect("open before-epoch database");
    assert_eq!(
        consensus::read_operator_recovery_sync(&before, store_identity)
            .expect("read before-epoch state")
            .recovery_epoch,
        0
    );
    drop(before);

    // Regression: the locally authorized recovery control must remain a raw
    // control intent; wrapping it as application authority revokes it in the
    // state machine before this durable epoch commit can occur.
    assert_eq!(
        manager
            .finalize_with_failpoint(
                &context(),
                &store,
                &plan,
                &confirmation,
                &[],
                backup.path(),
                RecoveryFinalizeFailpoint::AfterEpochCommit,
            )
            .await,
        Err(RecoveryError::InjectedFailure)
    );
    let after = Connection::open(&database).expect("open after-epoch database");
    assert_eq!(
        consensus::read_operator_recovery_sync(&after, store_identity)
            .expect("read after-epoch state")
            .recovery_epoch,
        1
    );
    drop(after);
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("resume after committed epoch"),
        RecoveryExecutionState::AwaitingEpochCommit
    );

    assert_eq!(
        manager
            .finalize_with_failpoint(
                &context(),
                &store,
                &plan,
                &confirmation,
                &[],
                backup.path(),
                RecoveryFinalizeFailpoint::BeforeRejoinBarrier,
            )
            .await,
        Err(RecoveryError::InjectedFailure)
    );
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("resume before rejoin barrier"),
        RecoveryExecutionState::EpochCommitted
    );

    assert_eq!(
        manager
            .finalize_with_failpoint(
                &context(),
                &store,
                &plan,
                &confirmation,
                &[],
                backup.path(),
                RecoveryFinalizeFailpoint::AfterRejoinBarrier,
            )
            .await,
        Err(RecoveryError::InjectedFailure)
    );
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("resume after rejoin barrier"),
        RecoveryExecutionState::EpochCommitted
    );

    let completed = manager
        .finalize(&context(), &store, &plan, &confirmation, &[], backup.path())
        .await
        .expect("resume finalization to rejoin");
    assert_eq!(completed.state(), RecoveryExecutionState::Rejoined);
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read completed workflow"),
        RecoveryExecutionState::Rejoined
    );
}
