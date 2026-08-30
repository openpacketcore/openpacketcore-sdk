use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
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
    serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
#[cfg(feature = "test-control")]
use opc_key::{KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditOutcome, AuditSink};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use rusqlite::{params, types::Value, Connection};
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
use super::sqlite::{
    acquire_finalization_pins, classify_finalization_pins,
    clear_target_database_after_identity_admission_hook,
    install_legacy_classification_before_proof_hook,
    install_target_database_after_identity_admission_hook, legacy_finalization_predecessor,
};
use super::sqlite::{
    backup_and_reset_replica, clear_pinned_inspection_path_swap_hooks,
    database_promotion_temporary_path_for_test, fail_next_promotion_after_rename,
    hash_current_checkpoint_for_test, inspect_replica_with_descriptor_snapshot_proof_for_test,
    install_pinned_inspection_path_swap_hooks, install_target_backup_snapshot_directory_sync_hook,
    planned_fleet_inspection_count, prepare_test_workflow_with_current_snapshot,
    promotion_cleanup_journals_are_empty_for_test, reset_planned_fleet_inspection_count, seal_plan,
    snapshot_promotion_temporary_path_for_test, RecoveryFailpoint, ResetInput,
};
use super::*;
use crate::capability::BackendCapabilities;
use crate::consensus::storage::ConsensusAuthorityProfile;
use crate::consensus::{
    SessionConsensusClusterId, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
    SessionRaftTypeConfig, SessionTopologyMemberBinding,
};
use crate::sqlite::consensus;
use crate::topology::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaTlsIdentity, ValidatedQuorumTopology,
};
#[cfg(feature = "test-control")]
use crate::{CompareAndSet, CompareAndSetResult, EncryptingSessionBackend};
use crate::{
    EncryptedSessionPayload, FenceToken, Generation, OwnerId, ReplicationEntry, ReplicationOp,
    SessionBackend, SessionConsensusCommand, SessionConsensusEntryDigest, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRequestId, SessionConsensusResponse,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionKey, SessionKeyType, SessionLeaseManager, SessionMutationIntent, SqliteSessionBackend,
    StateClass, StateType, StoredSessionRecord, SystemClock,
    FENCED_MUTATION_ROSTER_MAX_LIVE_ROSTERS, FENCED_TRANSITION_OUTCOME_RETENTION,
    FENCED_TRANSITION_SCHEMA_V1, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
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

fn topology_member_bindings(
    topology: &ValidatedQuorumTopology,
) -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding> {
    const ENDPOINT_DOMAIN: &[u8] = b"openpacketcore/session-store/topology-endpoint-binding/v1\0";
    const TLS_DOMAIN: &[u8] = b"openpacketcore/session-store/topology-tls-binding/v1\0";
    const BACKING_DOMAIN: &[u8] = b"openpacketcore/session-store/topology-backing-binding/v1\0";

    topology
        .members()
        .iter()
        .filter_map(|descriptor| {
            let node_id = topology.consensus_node_id(descriptor.replica_id())?;
            let mut endpoint = Sha256::new();
            endpoint.update(ENDPOINT_DOMAIN);
            endpoint.update(Sha256::digest(descriptor.endpoint().host().as_bytes()));
            endpoint.update(descriptor.endpoint().port().to_be_bytes());
            let mut tls = Sha256::new();
            tls.update(TLS_DOMAIN);
            tls.update(Sha256::digest(
                descriptor.tls_identity().as_str().as_bytes(),
            ));
            let mut backing = Sha256::new();
            backing.update(BACKING_DOMAIN);
            backing.update(descriptor.backing_identity().fingerprint());
            Some((
                node_id,
                SessionTopologyMemberBinding::new(
                    descriptor.configuration_fingerprint(),
                    endpoint.finalize().into(),
                    tls.finalize().into(),
                    backing.finalize().into(),
                ),
            ))
        })
        .collect()
}

fn sealed_test_plan<A: RecoveryAuthorizer>(
    manager: &LegacyForkRecovery<A, CapturingAudit, CapturingObserver>,
    identity: SessionConsensusIdentity,
    node: SessionConsensusNodeId,
    source: RecoveryReplicaEvidence,
) -> RecoveryPlan {
    let source_token = source.replica_token;
    let source_branch_digest = source.branch_digest;
    let source_authority_profile = source.authority_profile;
    let source_fixed_placement_policy = source.fixed_placement_policy;
    let source_protected_roster_digest = source.protected_roster_digest;
    let body = RecoveryPlanBody {
        version: RECOVERY_PLAN_VERSION,
        identity,
        expected_members: BTreeSet::from([node]),
        basis: RecoveryDecisionBasis::VerifiedCommittedMajority,
        evidence: vec![source],
        source_token,
        target_tokens: vec![source_token],
        source_branch_digest,
        source_authority_profile,
        source_fixed_placement_policy,
        source_protected_roster_digest,
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

#[cfg(feature = "test-control")]
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
        assert_eq!(objects.len(), 33);
        assert!(objects.iter().any(|(kind, name)| {
            kind == "table" && name == "consensus_fenced_transition_receipts"
        }));
        assert!(objects.iter().any(|(kind, name)| {
            kind == "table" && name == "consensus_fenced_transition_activation"
        }));
        assert!(objects.iter().any(|(kind, name)| {
            kind == "index" && name == "consensus_fenced_transition_receipts_due"
        }));
        for (kind, name) in [
            ("table", "consensus_protected_roster_rows"),
            ("table", "consensus_protected_roster_floors"),
            ("table", "consensus_protected_roster_retirement_cursors"),
            ("table", "consensus_protected_roster_witness"),
            ("table", "consensus_protected_roster_business"),
            ("table", "consensus_protected_roster_admissions"),
            ("index", "consensus_protected_roster_reclaim_due"),
            ("index", "consensus_protected_roster_partition_epoch"),
            ("index", "consensus_protected_roster_terminal_sequence"),
        ] {
            assert!(objects.iter().any(
                |(observed_kind, observed_name)| observed_kind == kind && observed_name == name
            ));
        }
        assert!(objects.iter().all(|(kind, name)| {
            kind == "table"
                || (kind == "index"
                    && matches!(
                        name.as_str(),
                        "consensus_fenced_transition_receipts_due"
                            | "consensus_protected_roster_reclaim_due"
                            | "consensus_protected_roster_partition_epoch"
                            | "consensus_protected_roster_terminal_sequence"
                    ))
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
            0,
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

fn append_current_membership_checkpoint(
    replica: &RecoveryReplica,
    log_id: LogId<SessionConsensusNodeId>,
    members: &BTreeSet<SessionConsensusNodeId>,
) {
    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let entry: Entry<SessionRaftTypeConfig> = Entry {
        log_id,
        // Repeating a valid uniform membership is deliberately permitted by
        // the ordinary scope validator. This lets the causal lineage tests
        // distinguish stale authority from an invalid membership shape.
        payload: EntryPayload::Membership(Membership::new(vec![members.clone()], members.clone())),
    };
    consensus::append_logs_sync(&conn, identity(), std::slice::from_ref(&entry))
        .expect("append current membership checkpoint");
    consensus::save_committed_sync(&conn, identity(), Some(log_id))
        .expect("commit current membership checkpoint");
    consensus::apply_entries_sync(
        &conn,
        identity(),
        &BackendCapabilities::all_enabled(),
        vec![entry],
    )
    .expect("apply current membership checkpoint");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint current membership checkpoint");
}

fn terminalize_current_replica_for_normal_backend_open(replica: &RecoveryReplica) {
    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let recovery = consensus::read_operator_recovery_sync(&conn, identity())
        .expect("read finalized current recovery state");
    assert!(
        recovery.recovery_epoch > 0 && recovery.pending_epoch.is_none(),
        "normal reopen fixture requires a finalized recovery epoch",
    );
    let latch = consensus::OperatorRecoveryLatch {
        identity: identity(),
        recovery_epoch: recovery.recovery_epoch,
        plan_digest: recovery.last_plan_digest,
        audit_pending: false,
    };
    let database_file = File::open(&replica.database_path).expect("open current database pin");
    consensus::ensure_operator_recovery_latch_sync(&replica.database_path, latch)
        .expect("publish current normal-reopen latch");
    consensus::terminalize_operator_recovery_latch_sync(
        &replica.database_path,
        latch,
        &database_file,
        None,
    )
    .expect("terminalize current normal-reopen latch");
}

fn install_dynamic_current_snapshot_fixture(
    replica: &RecoveryReplica,
    last_log_id: LogId<SessionConsensusNodeId>,
    file_name: &str,
    snapshot_id: &str,
    payload: &[u8],
) -> Vec<u8> {
    install_dynamic_current_snapshot_fixture_for_identity(
        replica,
        identity(),
        last_log_id,
        file_name,
        snapshot_id,
        payload,
    )
}

fn install_dynamic_current_snapshot_fixture_for_identity(
    replica: &RecoveryReplica,
    storage_identity: SessionConsensusIdentity,
    last_log_id: LogId<SessionConsensusNodeId>,
    file_name: &str,
    snapshot_id: &str,
    payload: &[u8],
) -> Vec<u8> {
    let checksum: [u8; 32] = Sha256::digest(payload).into();
    let mut bytes = payload.to_vec();
    bytes.extend_from_slice(b"OPCSNP01");
    bytes.extend_from_slice(
        &u64::try_from(payload.len())
            .expect("snapshot payload length")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&checksum);
    std::fs::write(replica.snapshot_directory.join(file_name), &bytes)
        .expect("write current snapshot fixture");
    let conn = Connection::open(&replica.database_path).expect("open current snapshot fixture");
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(last_log_id),
        last_membership: consensus::read_membership_sync(&conn, storage_identity)
            .expect("read current snapshot membership"),
        snapshot_id: snapshot_id.to_owned(),
    };
    consensus::save_current_snapshot_sync(
        &conn,
        storage_identity,
        &meta,
        file_name,
        checksum,
        u64::try_from(bytes.len()).expect("snapshot fixture length"),
    )
    .expect("persist current snapshot fixture metadata");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint current snapshot fixture");
    bytes
}

fn install_current_purge_floor(conn: &Connection, floor: &LogId<SessionConsensusNodeId>) {
    conn.execute(
        "INSERT OR REPLACE INTO consensus_purged (singleton, configuration_epoch, term, log_index, log_id_json) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            i64::try_from(identity().configuration_epoch().get()).expect("configuration epoch"),
            i64::try_from(floor.leader_id.term).expect("floor term"),
            i64::try_from(floor.index).expect("floor index"),
            serde_json::to_vec(floor).expect("encode purge floor"),
        ],
    )
    .expect("persist exact purge floor");
}

fn pad_current_log_entry(conn: &Connection, index: u64, minimum_bytes: usize) {
    let mut entry: Vec<u8> = conn
        .query_row(
            "SELECT entry_json FROM consensus_log WHERE log_index = ?1",
            [i64::try_from(index).expect("log index")],
            |row| row.get(0),
        )
        .expect("read valid log entry");
    entry.resize(minimum_bytes, b' ');
    conn.execute(
        "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = ?2",
        params![entry, i64::try_from(index).expect("log index")],
    )
    .expect("pad valid log entry");
}

fn bounded_current_recovery_limits(replica: &RecoveryReplica) -> RecoveryLimits {
    let database_bytes = std::fs::metadata(&replica.database_path)
        .expect("database metadata")
        .len();
    RecoveryLimits::try_new(
        database_bytes.checked_mul(2).expect("database bound"),
        database_bytes.checked_mul(2).expect("snapshot bound"),
        1_000,
        64 * 1024,
    )
    .expect("bounded recovery limits")
}

#[test]
fn current_recovery_capacity_masks_retained_purged_prefix() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let id = replica_id("retained-purged-prefix");
    let replica = create_legacy_replica(temp.path(), id.clone(), 3);
    let members = node_set(&[id]);
    let leader = *members.iter().next().expect("member");
    let floor = LogId::new(CommittedLeaderId::new(1, leader), 0);
    claim_current_replica(&replica, &members, floor);
    let applied = LogId::new(CommittedLeaderId::new(1, leader), 1);
    append_current_blank_checkpoint(&replica, applied);
    // A purge marker carries only a LogId.  The snapshot's exact
    // last-membership payload is the needed durable attestation for the
    // compacted membership row; otherwise this would be intentionally
    // rejected as unauthenticated membership authority before capacity is
    // considered.
    install_dynamic_current_snapshot_fixture(
        &replica,
        applied,
        "snapshot-00000000-0000-4000-8000-0000000000c8.opc",
        "retained-purged-prefix-capacity",
        b"purged-prefix membership attestation",
    );

    let conn = Connection::open(&replica.database_path).expect("open current replica");
    install_current_purge_floor(&conn, &floor);
    pad_current_log_entry(&conn, floor.index, 128 * 1024);
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint retained prefix");
    drop(conn);

    let limits = bounded_current_recovery_limits(&replica);
    let before = inspect_replica(InspectionInput {
        key: &integrity_key(),
        replica: &replica,
        identity: identity(),
        expected_members: &members,
        limits,
    })
    .expect("retained purged prefix does not consume logical recovery capacity");

    let conn = Connection::open(&replica.database_path).expect("open retained prefix");
    conn.execute("DELETE FROM consensus_log WHERE log_index <= ?1", [0])
        .expect("physically prune stale prefix");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint physical prune");
    drop(conn);

    let after = inspect_replica(InspectionInput {
        key: &integrity_key(),
        replica: &replica,
        identity: identity(),
        expected_members: &members,
        limits,
    })
    .expect("physically pruned replica remains recoverable");
    assert_eq!(before.branch_digest(), after.branch_digest());
    assert_eq!(before.logical_state_digest(), after.logical_state_digest());
    assert_eq!(before.committed_index(), after.committed_index());
    assert_eq!(before.applied_index(), after.applied_index());
    assert_eq!(before.local_head_index(), after.local_head_index());
}

#[test]
fn current_recovery_capacity_rejects_an_oversized_authoritative_suffix() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let id = replica_id("oversized-authoritative-suffix");
    let replica = create_legacy_replica(temp.path(), id.clone(), 3);
    let members = node_set(&[id]);
    let leader = *members.iter().next().expect("member");
    let floor = LogId::new(CommittedLeaderId::new(1, leader), 0);
    claim_current_replica(&replica, &members, floor);
    append_current_blank_checkpoint(&replica, LogId::new(CommittedLeaderId::new(1, leader), 1));

    let conn = Connection::open(&replica.database_path).expect("open current replica");
    install_current_purge_floor(&conn, &floor);
    pad_current_log_entry(&conn, 1, 128 * 1024);
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint oversized suffix");
    drop(conn);

    assert_eq!(
        inspect_replica(InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: bounded_current_recovery_limits(&replica),
        }),
        Err(RecoveryError::WorkLimitExceeded),
    );
}

#[test]
fn current_dynamic_inspection_rejects_retained_log_gaps_and_term_regression() {
    for case in ["missing-first", "missing-middle", "term-regression"] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let id = replica_id(&format!("dynamic-retained-{case}"));
        let replica = create_legacy_replica(temp.path(), id.clone(), 3);
        let members = node_set(&[id]);
        let leader = *members.iter().next().expect("leader");
        claim_current_replica(
            &replica,
            &members,
            LogId::new(CommittedLeaderId::new(3, leader), 0),
        );
        append_current_blank_checkpoint(&replica, LogId::new(CommittedLeaderId::new(3, leader), 1));
        if case != "term-regression" {
            append_current_blank_checkpoint(
                &replica,
                LogId::new(CommittedLeaderId::new(3, leader), 2),
            );
        }
        let conn = Connection::open(&replica.database_path).expect("open current replica");
        match case {
            "missing-first" => {
                conn.execute("DELETE FROM consensus_log WHERE log_index = 0", [])
                    .expect("remove first retained row");
            }
            "missing-middle" => {
                conn.execute("DELETE FROM consensus_log WHERE log_index = 1", [])
                    .expect("remove interior retained row");
            }
            "term-regression" => {
                // Build a valid suffix first: durable append correctly refuses
                // to create regressed Raft lineage.  Then forge every copy of
                // the terminal LogId so inspection reaches the retained-log
                // lineage check rather than rejecting a pointer/row mismatch.
                let regressed = LogId::new(CommittedLeaderId::new(2, leader), 1);
                let entry: Entry<SessionRaftTypeConfig> = Entry {
                    log_id: regressed,
                    payload: EntryPayload::Blank,
                };
                let encoded_entry = serde_json::to_vec(&entry).expect("encode regressed log");
                let encoded_log_id =
                    serde_json::to_vec(&regressed).expect("encode regressed pointer");
                let term = i64::try_from(regressed.leader_id.term).expect("regressed term");
                let index = i64::try_from(regressed.index).expect("regressed index");
                conn.execute(
                    "UPDATE consensus_log SET term = ?1, entry_json = ?2 WHERE log_index = ?3",
                    params![term, encoded_entry, index],
                )
                .expect("forge regressed retained row");
                for table in ["consensus_committed", "consensus_applied"] {
                    conn.execute(
                        &format!(
                            "UPDATE {table} SET term = ?1, log_index = ?2, log_id_json = ?3 WHERE singleton = 1"
                        ),
                        params![term, index, &encoded_log_id],
                    )
                    .expect("forge regressed terminal pointer");
                }
            }
            _ => unreachable!("known retained-log corruption case"),
        }
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint retained corruption");
        drop(conn);

        assert_eq!(
            inspect_current_fixture(&replica, &members),
            Err(RecoveryError::CorruptReplica),
            "dynamic current recovery must reject {case}",
        );
    }
}

#[test]
fn current_dynamic_inspection_rejects_spliced_or_uncovered_membership_log_ids() {
    for corruption in [
        "term-leader-splice",
        "beyond-applied",
        "retained-payload-splice",
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let id = replica_id(&format!("dynamic-membership-lineage-{corruption}"));
        let replica = create_legacy_replica(temp.path(), id.clone(), 3);
        let members = node_set(&[id]);
        let leader = *members.iter().next().expect("leader");
        claim_current_replica(
            &replica,
            &members,
            LogId::new(CommittedLeaderId::new(3, leader), 0),
        );
        let conn = Connection::open(&replica.database_path).expect("open current replica");
        let membership =
            consensus::read_membership_sync(&conn, identity()).expect("read persisted membership");
        let original = membership.log_id().expect("current membership LogId");
        let forged_log_id = match corruption {
            "term-leader-splice" => LogId::new(
                CommittedLeaderId::new(original.leader_id.term + 1, leader),
                original.index,
            ),
            "beyond-applied" => LogId::new(
                original.leader_id,
                original.index.checked_add(1).expect("test log index"),
            ),
            "retained-payload-splice" => original,
            _ => unreachable!("known membership lineage corruption"),
        };
        let forged_membership = if corruption == "retained-payload-splice" {
            // Preserve the voter universe so membership-scope validation does
            // not mask the lineage check. The stored joint configuration is
            // nevertheless a distinct (and valid) membership payload.
            Membership::new(vec![members.clone(), members.clone()], members.clone())
        } else {
            membership.membership().clone()
        };
        let forged =
            opc_consensus::engine::StoredMembership::new(Some(forged_log_id), forged_membership);
        conn.execute(
            "UPDATE consensus_membership SET membership_json = ?1 WHERE singleton = 1",
            [serde_json::to_vec(&forged).expect("encode forged membership")],
        )
        .expect("persist forged membership LogId");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint membership lineage corruption");
        drop(conn);

        assert_eq!(
            inspect_current_fixture(&replica, &members),
            Err(RecoveryError::CorruptReplica),
            "offline inspection must reject membership {corruption}",
        );
    }
}

#[test]
fn current_dynamic_inspection_requires_snapshot_membership_payload_to_match_retained_log() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let id = replica_id("dynamic-snapshot-membership-payload");
    let replica = create_legacy_replica(temp.path(), id.clone(), 3);
    let members = node_set(&[id]);
    let leader = *members.iter().next().expect("leader");
    let membership_log = LogId::new(CommittedLeaderId::new(3, leader), 0);
    claim_current_replica(&replica, &members, membership_log);
    install_dynamic_current_snapshot_fixture(
        &replica,
        membership_log,
        "snapshot-00000000-0000-4000-8000-0000000000b1.opc",
        "snapshot-membership-payload",
        b"snapshot membership payload lineage",
    );

    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let (encoded_meta, current_membership): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT meta_json, membership_json FROM consensus_snapshot JOIN consensus_membership ON consensus_membership.singleton = 1 WHERE consensus_snapshot.singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read snapshot and membership records");
    let mut meta: opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    > = serde_json::from_slice(&encoded_meta).expect("decode snapshot metadata");
    let persisted: opc_consensus::engine::StoredMembership<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    > = serde_json::from_slice(&current_membership).expect("decode persisted membership");
    meta.last_membership = opc_consensus::engine::StoredMembership::new(
        Some(membership_log),
        Membership::new(vec![members.clone(), members.clone()], members.clone()),
    );
    assert_ne!(meta.last_membership, persisted);
    conn.execute(
        "UPDATE consensus_snapshot SET meta_json = ?1 WHERE singleton = 1",
        [serde_json::to_vec(&meta).expect("encode forged snapshot metadata")],
    )
    .expect("persist forged snapshot membership");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint forged snapshot membership");
    drop(conn);

    assert_eq!(
        inspect_current_fixture(&replica, &members),
        Err(RecoveryError::CorruptReplica),
        "a retained membership row must bind the snapshot membership payload",
    );
}

#[test]
fn current_dynamic_inspection_accepts_compacted_membership_covered_by_snapshot() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let id = replica_id("dynamic-compacted-membership-snapshot");
    let replica = create_legacy_replica(temp.path(), id.clone(), 3);
    let members = node_set(&[id]);
    let leader = *members.iter().next().expect("leader");
    let membership_log = LogId::new(CommittedLeaderId::new(3, leader), 0);
    let applied_log = LogId::new(CommittedLeaderId::new(3, leader), 1);
    claim_current_replica(&replica, &members, membership_log);
    append_current_blank_checkpoint(&replica, applied_log);
    install_dynamic_current_snapshot_fixture(
        &replica,
        applied_log,
        "snapshot-00000000-0000-4000-8000-0000000000b2.opc",
        "compacted-membership-snapshot",
        b"compacted membership snapshot",
    );

    let conn = Connection::open(&replica.database_path).expect("open compacted replica");
    install_current_purge_floor(&conn, &applied_log);
    conn.execute("DELETE FROM consensus_log WHERE log_index <= ?1", [1_i64])
        .expect("remove snapshot-covered retained prefix");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint compacted membership fixture");
    drop(conn);

    inspect_current_fixture(&replica, &members)
        .expect("snapshot last_membership covers compacted persisted membership");
}

#[test]
fn current_dynamic_inspection_rejects_stale_latest_persisted_and_snapshot_membership() {
    for corruption in ["persisted", "snapshot"] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let id = replica_id(&format!("dynamic-stale-latest-membership-{corruption}"));
        let replica = create_legacy_replica(temp.path(), id.clone(), 3);
        let members = node_set(&[id]);
        let leader = *members.iter().next().expect("leader");
        let historical_log = LogId::new(CommittedLeaderId::new(3, leader), 0);
        let latest_log = LogId::new(CommittedLeaderId::new(3, leader), 2);
        claim_current_replica(&replica, &members, historical_log);
        append_current_blank_checkpoint(&replica, LogId::new(CommittedLeaderId::new(3, leader), 1));
        append_current_membership_checkpoint(&replica, latest_log, &members);
        if corruption == "snapshot" {
            install_dynamic_current_snapshot_fixture(
                &replica,
                latest_log,
                "snapshot-00000000-0000-4000-8000-0000000000bf.opc",
                "stale-latest-membership",
                b"stale snapshot membership lineage",
            );
        }

        let conn = Connection::open(&replica.database_path).expect("open current replica");
        let historical = opc_consensus::engine::StoredMembership::new(
            Some(historical_log),
            Membership::new(vec![members.clone()], members.clone()),
        );
        let latest = consensus::read_membership_sync(&conn, identity())
            .expect("read newest persisted membership");
        assert_ne!(historical, latest, "M0 and M1 have distinct LogIds");
        match corruption {
            "persisted" => {
                // This is still a valid historical membership under ordinary
                // scope rules; retained lineage must reject it as stale.
                conn.execute(
                    "UPDATE consensus_membership SET membership_json = ?1 WHERE singleton = 1",
                    [serde_json::to_vec(&historical).expect("encode stale membership")],
                )
                .expect("replace persisted membership with M0");
            }
            "snapshot" => {
                let encoded_meta: Vec<u8> = conn
                    .query_row(
                        "SELECT meta_json FROM consensus_snapshot WHERE singleton = 1",
                        [],
                        |row| row.get(0),
                    )
                    .expect("read installed snapshot metadata");
                let mut meta: opc_consensus::engine::SnapshotMeta<
                    SessionConsensusNodeId,
                    opc_consensus::engine::EmptyNode,
                > = serde_json::from_slice(&encoded_meta).expect("decode snapshot metadata");
                meta.last_membership = historical;
                conn.execute(
                    "UPDATE consensus_snapshot SET meta_json = ?1 WHERE singleton = 1",
                    [serde_json::to_vec(&meta).expect("encode stale snapshot membership")],
                )
                .expect("replace snapshot membership with M0");
            }
            _ => unreachable!("known stale membership corruption"),
        }
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint stale membership corruption");
        drop(conn);

        assert_eq!(
            inspect_current_fixture(&replica, &members),
            Err(RecoveryError::CorruptReplica),
            "offline inspection must reject stale {corruption} membership authority",
        );
    }
}

#[test]
fn current_dynamic_inspection_rejects_malformed_interior_retained_rows() {
    // Exercise the recovery entry point rather than the shared range helper:
    // the full inspection scan must decode and bind every physically retained
    // row, not only its first/last indexes. The second case remains valid
    // JSON but borrows a neighbouring entry's embedded LogId; the final case
    // is a structurally valid normal command for a foreign consensus
    // identity. Together they prove decoding, row-header and command binding
    // are all applied to the interior suffix.
    for corruption in [
        "invalid-json",
        "mismatched-embedded-log-id",
        "foreign-command-identity",
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let id = replica_id(&format!("dynamic-malformed-interior-{corruption}"));
        let replica = create_legacy_replica(temp.path(), id.clone(), 3);
        let members = node_set(&[id]);
        let leader = *members.iter().next().expect("leader");
        claim_current_replica(
            &replica,
            &members,
            LogId::new(CommittedLeaderId::new(3, leader), 0),
        );
        append_current_blank_checkpoint(&replica, LogId::new(CommittedLeaderId::new(3, leader), 1));
        append_current_blank_checkpoint(&replica, LogId::new(CommittedLeaderId::new(3, leader), 2));

        let conn = Connection::open(&replica.database_path).expect("open current replica");
        match corruption {
            "invalid-json" => {
                conn.execute(
                    "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 1",
                    params![b"{malformed-retained-entry".to_vec()],
                )
                .expect("corrupt interior retained entry encoding");
            }
            "mismatched-embedded-log-id" => {
                let neighbouring_entry: Vec<u8> = conn
                    .query_row(
                        "SELECT entry_json FROM consensus_log WHERE log_index = 0",
                        [],
                        |row| row.get(0),
                    )
                    .expect("read neighbouring retained entry");
                conn.execute(
                    "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 1",
                    params![neighbouring_entry],
                )
                .expect("misbind interior retained entry header");
            }
            "foreign-command-identity" => {
                let foreign_identity = SessionConsensusIdentity::new(
                    identity().cluster_id(),
                    SessionConsensusConfigurationId::from_bytes([0xA6; 32]),
                    SessionConsensusConfigurationEpoch::new(7).expect("configuration epoch"),
                );
                let foreign_command = Entry::<SessionRaftTypeConfig> {
                    log_id: LogId::new(CommittedLeaderId::new(3, leader), 1),
                    payload: EntryPayload::Normal(SessionConsensusCommand {
                        schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                        identity: foreign_identity,
                        request_id: SessionConsensusRequestId::from_bytes([0xA7; 16]),
                        logical_time: Timestamp::from_str("2026-08-01T00:00:00Z")
                            .expect("logical timestamp"),
                        intent: SessionMutationIntent::AdvanceLogicalTime,
                    }),
                };
                conn.execute(
                    "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 1",
                    params![serde_json::to_vec(&foreign_command).expect("encode foreign command")],
                )
                .expect("misbind interior retained command identity");
            }
            _ => unreachable!("known malformed retained-row case"),
        }
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint malformed retained row");
        drop(conn);

        assert_eq!(
            inspect_current_fixture(&replica, &members),
            Err(RecoveryError::CorruptReplica),
            "dynamic current recovery must reject {corruption}",
        );
    }
}

#[test]
fn current_recovery_scans_retained_prefix_below_snapshot_and_accepts_snapshot_boundary() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let id = replica_id("retained-prefix-with-current-snapshot");
    let replica = create_legacy_replica(temp.path(), id.clone(), 3);
    let members = node_set(&[id]);
    let leader = *members.iter().next().expect("leader");
    let first = LogId::new(CommittedLeaderId::new(3, leader), 0);
    claim_current_replica(&replica, &members, first);
    append_current_blank_checkpoint(&replica, LogId::new(CommittedLeaderId::new(3, leader), 1));
    append_current_blank_checkpoint(&replica, LogId::new(CommittedLeaderId::new(3, leader), 2));

    // A current snapshot is allowed to account for an absent *initial*
    // retained prefix, but it must not hide rows which still physically
    // exist below that boundary.  Give the fixture a normal dynamic snapshot
    // envelope without purging its 0..=2 log rows first.
    let payload = b"current recovery retained snapshot boundary";
    let checksum: [u8; 32] = Sha256::digest(payload).into();
    let file_name = "snapshot-00000000-0000-4000-8000-0000000000a1.opc";
    let mut snapshot = payload.to_vec();
    snapshot.extend_from_slice(b"OPCSNP01");
    snapshot.extend_from_slice(
        &u64::try_from(payload.len())
            .expect("snapshot payload length")
            .to_be_bytes(),
    );
    snapshot.extend_from_slice(&checksum);
    std::fs::write(replica.snapshot_directory.join(file_name), &snapshot)
        .expect("write current snapshot");

    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(LogId::new(CommittedLeaderId::new(3, leader), 2)),
        last_membership: consensus::read_membership_sync(&conn, identity())
            .expect("read current membership"),
        snapshot_id: "retained-prefix-current-snapshot".to_owned(),
    };
    consensus::save_current_snapshot_sync(
        &conn,
        identity(),
        &meta,
        file_name,
        checksum,
        u64::try_from(snapshot.len()).expect("snapshot length"),
    )
    .expect("persist current snapshot metadata");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint current snapshot metadata");
    drop(conn);

    append_current_blank_checkpoint(&replica, LogId::new(CommittedLeaderId::new(3, leader), 3));

    let conn = Connection::open(&replica.database_path).expect("open retained-prefix fixture");
    consensus::read_log_range_for_recovery_sync(&conn, identity(), 0, None, Some(16))
        .expect("all physical retained rows remain valid");
    drop(conn);
    inspect_current_fixture(&replica, &members)
        .expect("physical retained prefix below snapshot remains fully inspectable");

    // With no durable purge floor, the snapshot can justify precisely the
    // omitted initial index.  It cannot justify an interior hole, which is
    // covered by the gap test above.
    let conn = Connection::open(&replica.database_path).expect("reopen current replica");
    conn.execute("DELETE FROM consensus_log WHERE log_index <= 2", [])
        .expect("remove snapshot-covered initial rows");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint snapshot-covered prefix removal");
    drop(conn);
    inspect_current_fixture(&replica, &members)
        .expect("current snapshot covers exactly the omitted initial log row");

    // The snapshot is also the immediate retained predecessor in this shape.
    // A byte-valid row whose leader term regresses below that exact snapshot
    // must not become authoritative just because there is no purge record.
    let conn = Connection::open(&replica.database_path).expect("reopen snapshot boundary");
    let regressed: Entry<SessionRaftTypeConfig> = Entry {
        log_id: LogId::new(CommittedLeaderId::new(2, leader), 3),
        payload: EntryPayload::Blank,
    };
    conn.execute(
        "UPDATE consensus_log SET term = ?1, entry_json = ?2 WHERE log_index = 3",
        params![
            i64::try_from(regressed.log_id.leader_id.term).expect("test term"),
            serde_json::to_vec(&regressed).expect("encode regressed row"),
        ],
    )
    .expect("regress snapshot-boundary row term");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint regressed snapshot boundary");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&replica, &members),
        Err(RecoveryError::CorruptReplica),
        "the first snapshot-covered retained row must preserve leader order",
    );
}

#[test]
fn current_recovery_rejects_snapshot_ahead_of_applied_or_spliced_at_retained_index() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let id = replica_id("current-snapshot-lineage");
    let replica = create_legacy_replica(temp.path(), id.clone(), 3);
    let members = node_set(&[id]);
    let leader = *members.iter().next().expect("leader");
    let retained = LogId::new(CommittedLeaderId::new(3, leader), 0);
    claim_current_replica(&replica, &members, retained);

    let payload = b"current recovery snapshot lineage";
    let checksum: [u8; 32] = Sha256::digest(payload).into();
    let file_name = "snapshot-00000000-0000-4000-8000-0000000000a2.opc";
    let mut snapshot = payload.to_vec();
    snapshot.extend_from_slice(b"OPCSNP01");
    snapshot.extend_from_slice(
        &u64::try_from(payload.len())
            .expect("snapshot payload length")
            .to_be_bytes(),
    );
    snapshot.extend_from_slice(&checksum);
    std::fs::write(replica.snapshot_directory.join(file_name), &snapshot)
        .expect("write current snapshot");

    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let membership = consensus::read_membership_sync(&conn, identity()).expect("read membership");
    let valid_meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(retained),
        last_membership: membership.clone(),
        snapshot_id: "current-snapshot-lineage".to_owned(),
    };
    consensus::save_current_snapshot_sync(
        &conn,
        identity(),
        &valid_meta,
        file_name,
        checksum,
        u64::try_from(snapshot.len()).expect("snapshot length"),
    )
    .expect("persist valid snapshot metadata");

    let ahead = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(LogId::new(CommittedLeaderId::new(3, leader), 1)),
        last_membership: membership.clone(),
        snapshot_id: "current-snapshot-lineage".to_owned(),
    };
    conn.execute(
        "UPDATE consensus_snapshot SET meta_json = ?1 WHERE singleton = 1",
        [serde_json::to_vec(&ahead).expect("encode ahead snapshot metadata")],
    )
    .expect("inject ahead snapshot metadata");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint ahead snapshot corruption");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&replica, &members),
        Err(RecoveryError::CorruptReplica),
        "a snapshot beyond the exact applied LogId cannot become recovery evidence"
    );

    let conn = Connection::open(&replica.database_path).expect("reopen current replica");
    let spliced = LogId::new(CommittedLeaderId::new(4, leader), 0);
    let spliced_meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(spliced),
        last_membership: membership,
        snapshot_id: "current-snapshot-lineage".to_owned(),
    };
    conn.execute(
        "UPDATE consensus_snapshot SET meta_json = ?1 WHERE singleton = 1",
        [serde_json::to_vec(&spliced_meta).expect("encode spliced snapshot metadata")],
    )
    .expect("inject spliced snapshot metadata");
    conn.execute(
        "UPDATE consensus_committed SET term = ?1, log_index = ?2, log_id_json = ?3 WHERE singleton = 1",
        params![
            i64::try_from(spliced.leader_id.term).expect("test term fits SQLite"),
            i64::try_from(spliced.index).expect("test index fits SQLite"),
            serde_json::to_vec(&spliced).expect("encode spliced committed pointer"),
        ],
    )
    .expect("inject forged committed pointer");
    conn.execute(
        "UPDATE consensus_applied SET term = ?1, log_index = ?2, log_id_json = ?3 WHERE singleton = 1",
        params![
            i64::try_from(spliced.leader_id.term).expect("test term fits SQLite"),
            i64::try_from(spliced.index).expect("test index fits SQLite"),
            serde_json::to_vec(&spliced).expect("encode spliced applied pointer"),
        ],
    )
    .expect("align applied pointer with forged snapshot");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint snapshot splice corruption");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&replica, &members),
        Err(RecoveryError::CorruptReplica),
        "a physical retained row must equal the snapshot's complete LogId"
    );
}

#[test]
fn current_recovery_rejects_snapshot_purge_same_index_splice() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let id = replica_id("current-snapshot-purge-lineage");
    let replica = create_legacy_replica(temp.path(), id.clone(), 3);
    let members = node_set(&[id]);
    let leader = *members.iter().next().expect("leader");
    let committed = LogId::new(CommittedLeaderId::new(3, leader), 0);
    claim_current_replica(&replica, &members, committed);

    let payload = b"current recovery snapshot purge lineage";
    let checksum: [u8; 32] = Sha256::digest(payload).into();
    let file_name = "snapshot-00000000-0000-4000-8000-0000000000a3.opc";
    let mut snapshot = payload.to_vec();
    snapshot.extend_from_slice(b"OPCSNP01");
    snapshot.extend_from_slice(
        &u64::try_from(payload.len())
            .expect("snapshot payload length")
            .to_be_bytes(),
    );
    snapshot.extend_from_slice(&checksum);
    std::fs::write(replica.snapshot_directory.join(file_name), &snapshot)
        .expect("write current snapshot");

    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(committed),
        last_membership: consensus::read_membership_sync(&conn, identity())
            .expect("read applied membership"),
        snapshot_id: "current-snapshot-purge-lineage".to_owned(),
    };
    consensus::save_current_snapshot_sync(
        &conn,
        identity(),
        &meta,
        file_name,
        checksum,
        u64::try_from(snapshot.len()).expect("snapshot length"),
    )
    .expect("persist current snapshot metadata");
    let forged_purge = LogId::new(CommittedLeaderId::new(4, leader), committed.index);
    install_current_purge_floor(&conn, &forged_purge);
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint snapshot/purge splice");
    drop(conn);

    assert_eq!(
        inspect_current_fixture(&replica, &members),
        Err(RecoveryError::CorruptReplica),
        "offline recovery must reject a purge pointer that shares only the snapshot index",
    );
}

#[test]
fn compacted_finalization_lineage_rejects_lower_term_and_same_term_leader_forks() {
    let members = node_set(&[
        replica_id("compacted-finalization-certified-leader"),
        replica_id("compacted-finalization-fork-leader"),
    ]);
    let certified_leader = *members.iter().next().expect("certified leader");
    let fork_leader = *members.iter().nth(1).expect("fork leader");
    let finalized = LogId::new(CommittedLeaderId::new(5, certified_leader), 10);

    // Applied and committed progress on a later term remains a valid
    // descendant of the certified finalization. It cannot make a separately
    // persisted lower-term purge + snapshot lineage trustworthy.
    let committed = LogId::new(CommittedLeaderId::new(6, fork_leader), 12);
    let applied = LogId::new(CommittedLeaderId::new(6, fork_leader), 12);
    assert!(super::sqlite::full_log_id_not_after(&finalized, &committed));
    assert!(super::sqlite::full_log_id_not_after(&finalized, &applied));

    let lower_term_purged = LogId::new(CommittedLeaderId::new(4, certified_leader), 11);
    let lower_term_snapshot = LogId::new(CommittedLeaderId::new(4, certified_leader), 11);
    assert_eq!(
        super::sqlite::require_compacted_terminal_log_lineage(
            &finalized,
            Some(&lower_term_purged),
            &lower_term_snapshot,
        ),
        Err(RecoveryError::BackupCorrupt),
        "a term-5/index-10 finalization is not covered by term-4/index-11 compacted evidence",
    );

    // At an equal index, a different term is likewise a distinct full LogId;
    // it cannot replace the finalized record as compacted branch evidence.
    let same_index_newer_term = LogId::new(CommittedLeaderId::new(6, fork_leader), 10);
    assert_eq!(
        super::sqlite::require_compacted_terminal_log_lineage(
            &finalized,
            Some(&same_index_newer_term),
            &same_index_newer_term,
        ),
        Err(RecoveryError::BackupCorrupt),
        "same-index compacted evidence must equal the finalized full LogId",
    );

    let same_term_fork_purged = LogId::new(CommittedLeaderId::new(5, fork_leader), 11);
    let same_term_fork_snapshot = LogId::new(CommittedLeaderId::new(5, fork_leader), 11);
    // This SDK's OpenRaft profile uses `single-term-leader`: the durable
    // leader component is the term itself, so different node inputs at one
    // term canonicalize to the same leader ID. This is not an observable
    // full-LogId fork; genuine fork rejection remains in
    // `full_log_id_not_after` for formats that serialize leader identity.
    assert_eq!(
        finalized.leader_id, same_term_fork_purged.leader_id,
        "single-term-leader canonicalizes same-term leader inputs"
    );
    assert_eq!(
        super::sqlite::require_compacted_terminal_log_lineage(
            &finalized,
            Some(&same_term_fork_purged),
            &same_term_fork_snapshot,
        ),
        Ok(()),
        "a canonical same-term LogId is valid finalization lineage",
    );

    let authentic_purged = LogId::new(CommittedLeaderId::new(5, certified_leader), 11);
    let authentic_snapshot = LogId::new(CommittedLeaderId::new(6, fork_leader), 12);
    assert_eq!(
        super::sqlite::require_compacted_terminal_log_lineage(
            &finalized,
            Some(&authentic_purged),
            &authentic_snapshot,
        ),
        Ok(()),
        "same-leader same-term progress and later-term snapshot lineage are valid descendants",
    );
}

#[test]
fn current_recovery_rejects_marker_only_term_regression_after_purge() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let id = replica_id("current-marker-only-term-regression");
    let replica = create_legacy_replica(temp.path(), id.clone(), 3);
    let members = node_set(&[id]);
    let leader = *members.iter().next().expect("leader");
    let original = LogId::new(CommittedLeaderId::new(3, leader), 0);
    claim_current_replica(&replica, &members, original);

    let lower_term_marker = LogId::new(CommittedLeaderId::new(2, leader), 1);
    let payload = b"current recovery marker-only term regression";
    let checksum: [u8; 32] = Sha256::digest(payload).into();
    let file_name = "snapshot-00000000-0000-4000-8000-0000000000a4.opc";
    let mut snapshot = payload.to_vec();
    snapshot.extend_from_slice(b"OPCSNP01");
    snapshot.extend_from_slice(
        &u64::try_from(payload.len())
            .expect("snapshot payload length")
            .to_be_bytes(),
    );
    snapshot.extend_from_slice(&checksum);
    std::fs::write(replica.snapshot_directory.join(file_name), &snapshot)
        .expect("write current snapshot");

    let conn = Connection::open(&replica.database_path).expect("open current replica");
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(lower_term_marker),
        last_membership: consensus::read_membership_sync(&conn, identity())
            .expect("read applied membership"),
        snapshot_id: "current-marker-only-term-regression".to_owned(),
    };
    conn.execute(
        "INSERT OR REPLACE INTO consensus_snapshot (singleton, configuration_epoch, meta_json, file_name, checksum, byte_length) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            i64::try_from(identity().configuration_epoch().get()).expect("epoch"),
            serde_json::to_vec(&meta).expect("encode forged snapshot metadata"),
            file_name,
            checksum.to_vec(),
            i64::try_from(snapshot.len()).expect("snapshot length"),
        ],
    )
    .expect("install marker-only snapshot metadata");
    for table in ["consensus_committed", "consensus_applied"] {
        conn.execute(
            &format!(
                "UPDATE {table} SET term = ?1, log_index = ?2, log_id_json = ?3 WHERE singleton = 1"
            ),
            params![
                i64::try_from(lower_term_marker.leader_id.term).expect("marker term"),
                i64::try_from(lower_term_marker.index).expect("marker index"),
                serde_json::to_vec(&lower_term_marker).expect("encode marker pointer"),
            ],
        )
        .expect("replace durable marker pointer");
    }
    install_current_purge_floor(&conn, &original);
    conn.execute("DELETE FROM consensus_log", [])
        .expect("remove all retained rows between markers");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint marker-only lineage splice");
    drop(conn);

    assert_eq!(
        inspect_current_fixture(&replica, &members),
        Err(RecoveryError::CorruptReplica),
        "offline recovery must order purge and marker-only snapshot lineage by complete Raft term",
    );
}

#[test]
fn current_inspection_requires_exact_applied_and_committed_log_lineage() {
    for case in ["applied", "committed"] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let id = replica_id(&format!("pointer-lineage-{case}"));
        let replica = create_legacy_replica(temp.path(), id.clone(), 3);
        let members = node_set(&[id]);
        let leader = *members.iter().next().expect("leader");
        let first = LogId::new(CommittedLeaderId::new(3, leader), 0);
        claim_current_replica(&replica, &members, first);
        let second = LogId::new(CommittedLeaderId::new(3, leader), 1);
        if case == "applied" {
            append_current_blank_checkpoint(&replica, second);
        } else {
            let conn = Connection::open(&replica.database_path).expect("open current replica");
            consensus::append_logs_sync(
                &conn,
                identity(),
                &[Entry {
                    log_id: second,
                    payload: EntryPayload::Blank,
                }],
            )
            .expect("append unapplied retained row");
        }
        let conn = Connection::open(&replica.database_path).expect("reopen current replica");
        let forged = match case {
            // Keep applied and committed equal so the old index-only floor
            // predicate cannot reject before exact lineage is checked.
            "applied" => LogId::new(CommittedLeaderId::new(4, leader), 1),
            // Applied remains the authentic first row; a forged committed
            // term at the later index satisfies ordering but has no exact row.
            "committed" => LogId::new(CommittedLeaderId::new(4, leader), 1),
            _ => unreachable!("known pointer lineage case"),
        };
        let encoded = serde_json::to_vec(&forged).expect("encode forged pointer");
        let term = i64::try_from(forged.leader_id.term).expect("forged term");
        let index = i64::try_from(forged.index).expect("forged index");
        match case {
            "applied" => {
                for table in ["consensus_applied", "consensus_committed"] {
                    conn.execute(
                        &format!(
                            "UPDATE {table} SET term = ?1, log_index = ?2, log_id_json = ?3 WHERE singleton = 1"
                        ),
                        params![term, index, &encoded],
                    )
                    .expect("forge matching applied/committed pointer");
                }
            }
            "committed" => {
                conn.execute(
                    "UPDATE consensus_committed SET term = ?1, log_index = ?2, log_id_json = ?3 WHERE singleton = 1",
                    params![term, index, &encoded],
                )
                .expect("forge committed pointer");
            }
            _ => unreachable!("known pointer lineage case"),
        }
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint pointer corruption");
        drop(conn);

        assert_eq!(
            inspect_current_fixture(&replica, &members),
            Err(RecoveryError::CorruptReplica),
            "inspection must require exact {case} pointer lineage",
        );
    }
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
    active_epoch INTEGER NOT NULL CHECK (active_epoch > 0),
    retired_through_epoch INTEGER NOT NULL CHECK (retired_through_epoch >= 0),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    current_bound_count INTEGER NOT NULL CHECK (current_bound_count BETWEEN 0 AND 131072),
    reclaim_epoch INTEGER CHECK (reclaim_epoch IS NULL OR reclaim_epoch > 0),
    reclaim_cursor_ordinal INTEGER CHECK (reclaim_cursor_ordinal IS NULL OR reclaim_cursor_ordinal >= 0),
    reclaim_remaining INTEGER CHECK (reclaim_remaining IS NULL OR reclaim_remaining >= 0),
    reclaimed_entries INTEGER NOT NULL DEFAULT 0 CHECK (reclaimed_entries >= 0),
    CHECK ((reclaim_epoch IS NULL AND reclaim_cursor_ordinal IS NULL AND reclaim_remaining IS NULL AND active_epoch - retired_through_epoch BETWEEN 1 AND 8) OR (reclaim_epoch IS NOT NULL AND reclaim_epoch = retired_through_epoch AND reclaim_cursor_ordinal IS NOT NULL AND reclaim_remaining IS NOT NULL AND active_epoch - retired_through_epoch BETWEEN 1 AND 7)),
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
    insert_valid_v3_receipt_fixture_with_marker(replica, history_epoch, ordinal, 0xA1)
}

fn insert_valid_v3_receipt_fixture_with_marker(
    replica: &RecoveryReplica,
    history_epoch: u64,
    ordinal: u64,
    marker: u8,
) -> V3ReceiptFixture {
    let logical_time = receipt_inspection_timestamp();
    let retained_until =
        crate::checked_session_deadline(logical_time, FENCED_TRANSITION_OUTCOME_RETENTION)
            .expect("V3 receipt deadline");
    let retained_until = crate::sqlite::ops::format_rfc3339_normalized(retained_until);
    let mut request_id = [marker; 56];
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

fn insert_v3_tombstone_rows_in_epoch(
    replica: &RecoveryReplica,
    history_epoch: u64,
    first_ordinal: u64,
    count: usize,
) {
    let logical_time = receipt_inspection_timestamp();
    let retained_until =
        crate::checked_session_deadline(logical_time, FENCED_TRANSITION_OUTCOME_RETENTION)
            .expect("V3 tombstone deadline");
    let retained_until = crate::sqlite::ops::format_rfc3339_normalized(retained_until);
    let mut conn = Connection::open(&replica.database_path).expect("open V3 tombstone fixture");
    let transaction = conn.transaction().expect("begin V3 tombstone fixture");
    let mut insert = transaction
        .prepare(
            "INSERT INTO consensus_fenced_transition_v2_receipts (request_id, history_epoch, ordinal, configuration_epoch, payload_digest, retained_until, binding_digest, response_json, response_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL)",
        )
        .expect("prepare V3 tombstone insert");
    for offset in 0..count {
        let ordinal = first_ordinal
            .checked_add(u64::try_from(offset).expect("V3 tombstone offset"))
            .expect("V3 tombstone ordinal");
        let mut request_id = [0x54_u8; 56];
        request_id[..8].copy_from_slice(&history_epoch.to_be_bytes());
        request_id[48..].copy_from_slice(&ordinal.to_be_bytes());
        let payload_digest =
            consensus::fenced_transition_v2_payload_digest_for_request_id(identity(), request_id)
                .expect("V3 tombstone payload");
        let binding_digest = consensus::fenced_transition_v2_receipt_binding_digest(
            identity(),
            request_id,
            history_epoch,
            ordinal,
            payload_digest,
            &retained_until,
        )
        .expect("V3 tombstone binding");
        insert
            .execute(params![
                request_id.as_slice(),
                i64::try_from(history_epoch).expect("V3 tombstone history epoch"),
                i64::try_from(ordinal).expect("V3 tombstone ordinal"),
                i64::try_from(identity().configuration_epoch().get())
                    .expect("V3 tombstone configuration epoch"),
                payload_digest.as_slice(),
                retained_until.as_str(),
                binding_digest.as_slice(),
            ])
            .expect("insert V3 tombstone");
    }
    drop(insert);
    transaction.commit().expect("commit V3 tombstone fixture");
    conn.execute(
        "UPDATE consensus_machine SET logical_time = ?1 WHERE singleton = 1",
        [retained_until.as_str()],
    )
    .expect("advance V3 tombstone fixture clock");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint V3 tombstones");
}

fn begin_v3_reclaim_fixture(
    replica: &RecoveryReplica,
    reclaim_epoch: u64,
    cursor: u64,
    remaining: u64,
) {
    let conn = Connection::open(&replica.database_path).expect("open V3 reclaim fixture");
    conn.execute(
        "UPDATE consensus_fenced_transition_v2_history SET reclaim_epoch = ?1, reclaim_cursor_ordinal = ?2, reclaim_remaining = ?3 WHERE singleton = 1",
        params![
            i64::try_from(reclaim_epoch).expect("reclaim epoch"),
            i64::try_from(cursor).expect("reclaim cursor"),
            i64::try_from(remaining).expect("reclaim remaining"),
        ],
    )
    .expect("begin V3 reclaim");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint V3 reclaim");
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
    activate_v3_history_fixture(&replica, 3, 2, 1);
    let final_ordinal =
        u64::try_from(FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES).expect("V3 maximum ordinal");
    let reclaim_remaining = 1_024_u64;
    let reclaim_cursor = final_ordinal
        .checked_sub(reclaim_remaining)
        .expect("V3 reclaim cursor");
    insert_valid_v3_receipt_fixture_with_marker(&replica, 2, final_ordinal, 0xA2);
    insert_valid_v3_receipt_fixture_with_marker(&replica, 3, 1, 0xA3);
    insert_v3_tombstone_rows_in_epoch(
        &replica,
        2,
        reclaim_cursor
            .checked_add(1)
            .expect("V3 first retained ordinal"),
        usize::try_from(reclaim_remaining - 1).expect("V3 retained tombstone count"),
    );
    begin_v3_reclaim_fixture(&replica, 2, reclaim_cursor, reclaim_remaining);

    let conn = Connection::open(&replica.database_path).expect("open V3 validation fixture");
    consensus::validate_fenced_transition_v2_receipts_sync(&conn, identity())
        .expect("validate populated V3 ledger");
    drop(conn);

    let lifecycle_before = v3_history_lifecycle(&replica);
    let before = inspect_current_fixture(&replica, &members).expect("inspect V3 replica");
    // The fixture models a prior completed recovery. Runtime reopens require
    // its terminal tombstone; a missing sidecar is intentionally fail-closed
    // and is not a valid historical normal-start shape.
    terminalize_current_replica_for_normal_backend_open(&replica);
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
            "UPDATE consensus_fenced_transition_v2_history SET reclaim_epoch = 4, reclaim_cursor_ordinal = 2, reclaim_remaining = 1, current_bound_count = 0",
        ),
    ] {
        let (replica, case_members) = current_receipt_inspection_fixture(&temp.path().join(label));
        activate_v3_history_fixture(&replica, 5, 4, 0);
        let conn = Connection::open(&replica.database_path).expect("open corrupt V3 fixture");
        conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("allow lifecycle corruption");
        conn.execute_batch(sql)
            .expect("inject lifecycle corruption");
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
        "DROP INDEX consensus_protected_roster_terminal_sequence;
         DROP INDEX consensus_protected_roster_reclaim_due;
         DROP INDEX consensus_protected_roster_partition_epoch;
         DROP TABLE consensus_protected_roster_admissions;
         DROP TABLE consensus_protected_roster_business;
         DROP TABLE consensus_protected_roster_witness;
         DROP TABLE consensus_protected_roster_retirement_cursors;
         DROP TABLE consensus_protected_roster_floors;
         DROP TABLE consensus_protected_roster_rows;
         DROP TABLE consensus_fenced_transition_receipts;
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

fn activate_protected_roster_recovery_fixture(replica: &RecoveryReplica) {
    let conn = Connection::open(&replica.database_path).expect("open protected roster fixture");
    conn.execute(
        "UPDATE consensus_identity SET schema_version = ?1 WHERE singleton = 1",
        [i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) + 3],
    )
    .expect("activate protected roster format");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint protected roster activation");
}

fn production_protected_roster_v2_namespace_ddl() -> String {
    let root = tempfile::tempdir().expect("production V2 namespace root");
    let database = root.path().join("production-v2-namespace.sqlite");
    consensus::initialize_protected_roster_v2_recovery_fixture(
        &database,
        consensus::ProtectedRosterV2RecoveryFixtureState::Live,
    )
    .expect("materialize production V2 namespace");
    let conn = Connection::open(&database).expect("open production V2 namespace");
    let mut ddl = String::new();
    for name in [
        "consensus_protected_roster_v2_activation",
        "consensus_protected_roster_v2_admissions",
        "consensus_protected_roster_v2_reclaim_due",
        "consensus_protected_roster_v2_partition_epoch",
        "consensus_protected_roster_v2_terminal_sequence",
        "consensus_protected_roster_v2_absence_reservations",
    ] {
        let schema: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .expect("read production V2 namespace DDL");
        ddl.push_str(&schema);
        ddl.push_str(";\n");
    }
    ddl
}

fn activate_inactive_protected_roster_v2_recovery_fixture(replica: &RecoveryReplica) {
    // The inactive format-five state has no certificate row, but its namespace
    // must remain byte-for-byte the production DDL. Derive it from the sealed
    // production materializer so this recovery fixture cannot drift.
    let namespace_ddl = production_protected_roster_v2_namespace_ddl();
    let conn = Connection::open(&replica.database_path).expect("open protected roster V2 fixture");
    conn.execute_batch(&namespace_ddl)
        .expect("install production V2 namespace");
    conn.execute_batch(
        "UPDATE consensus_identity SET schema_version = 5 WHERE singleton = 1; \
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .expect("activate inactive protected roster V2 format");
    assert!(matches!(
        consensus::protected_roster_v2_recovery_layout_sync(&conn),
        Ok(consensus::ProtectedRosterV2RecoveryLayout::Inactive)
    ));
}

fn sealed_protected_roster_v2_recovery_fixture(
    root: &Path,
    state: consensus::ProtectedRosterV2RecoveryFixtureState,
) -> (
    RecoveryReplica,
    SessionConsensusIdentity,
    BTreeSet<SessionConsensusNodeId>,
) {
    std::fs::create_dir_all(root).expect("create sealed V2 recovery root");
    let replica_id = replica_id("sealed-v2-recovery");
    let database = root.join("sealed-v2-recovery.sqlite");
    let snapshots = root.join("sealed-v2-recovery-snapshots");
    std::fs::create_dir(&snapshots).expect("create sealed V2 recovery snapshots");
    let fixture = consensus::initialize_protected_roster_v2_recovery_fixture(&database, state)
        .expect("materialize sealed V2 recovery fixture");
    let conn = Connection::open(&database).expect("open sealed V2 recovery database");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint sealed V2 recovery fixture");
    drop(conn);
    let replica = RecoveryReplica::new_bound(
        replica_id,
        ReplicaBackingIdentity::new("sealed-v2-recovery-backing").expect("backing identity"),
        fixture.identity,
        database,
        snapshots,
    );
    (replica, fixture.identity, fixture.members)
}

fn inspect_sealed_protected_roster_v2_fixture(
    replica: &RecoveryReplica,
    fixture_identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
) -> Result<RecoveryReplicaEvidence, RecoveryError> {
    inspect_replica(InspectionInput {
        key: &integrity_key(),
        replica,
        identity: fixture_identity,
        expected_members: members,
        limits: RecoveryLimits::default(),
    })
}

#[test]
fn format5_protected_roster_v2_replica_is_recoverable() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (replica, members) = current_receipt_inspection_fixture(temp.path());
    let conn = Connection::open(&replica.database_path).expect("open inactive V2 checkpoint");
    let predecessor_digest =
        hash_current_checkpoint_for_test(&conn).expect("hash pre-cutover V2 checkpoint");
    drop(conn);
    inspect_current_fixture(&replica, &members)
        .expect("offline recovery accepts pre-cutover format");
    activate_inactive_protected_roster_v2_recovery_fixture(&replica);
    let conn = Connection::open(&replica.database_path).expect("open inactive V2 checkpoint");
    let inactive_digest =
        hash_current_checkpoint_for_test(&conn).expect("hash inactive post-cutover V2 checkpoint");
    assert_ne!(
        predecessor_digest, inactive_digest,
        "complete inactive V2 namespace commits to checkpoint"
    );
    drop(conn);

    inspect_current_fixture(&replica, &members)
        .expect("offline recovery accepts inactive format five");
}

#[test]
fn format5_protected_roster_v2_signed_q1_and_q2_replicas_are_recoverable() {
    let mut checkpoint_digests = Vec::new();
    for (name, state) in [
        (
            "live-q1",
            consensus::ProtectedRosterV2RecoveryFixtureState::Live,
        ),
        (
            "established-q2",
            consensus::ProtectedRosterV2RecoveryFixtureState::Established,
        ),
        (
            "aborted-q2",
            consensus::ProtectedRosterV2RecoveryFixtureState::Aborted,
        ),
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let (replica, fixture_identity, members) =
            sealed_protected_roster_v2_recovery_fixture(temp.path(), state);
        let conn = Connection::open(&replica.database_path).expect("open signed V2 checkpoint");
        let checkpoint = hash_current_checkpoint_for_test(&conn)
            .unwrap_or_else(|error| panic!("hash sealed {name} V2 checkpoint: {error:?}"));
        assert!(
            !checkpoint_digests.contains(&checkpoint),
            "signed {name} V2 durable state must have a distinct checkpoint digest"
        );
        checkpoint_digests.push(checkpoint);
        drop(conn);
        inspect_sealed_protected_roster_v2_fixture(&replica, fixture_identity, &members)
            .unwrap_or_else(|error| panic!("recover sealed {name} V2 state: {error:?}"));
    }
}

#[test]
fn format5_checkpoint_digest_commits_every_v2_durable_table() {
    for (name, mutation) in [
        (
            "activation",
            "UPDATE consensus_protected_roster_v2_activation SET voter_set_digest = zeroblob(32);",
        ),
        (
            "absence",
            "UPDATE consensus_protected_roster_v2_absence_reservations SET business_key = zeroblob(32);",
        ),
        (
            "admission",
            "UPDATE consensus_protected_roster_v2_admissions SET canonical_record = zeroblob(length(canonical_record));",
        ),
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let (replica, fixture_identity, members) = sealed_protected_roster_v2_recovery_fixture(
            temp.path(),
            consensus::ProtectedRosterV2RecoveryFixtureState::Live,
        );
        let conn = Connection::open(&replica.database_path).expect("open signed V2 checkpoint");
        hash_current_checkpoint_for_test(&conn).expect("hash valid V2 checkpoint");
        conn.execute_batch(mutation)
            .expect("tamper V2 checkpoint row");
        assert_eq!(
            hash_current_checkpoint_for_test(&conn),
            Err(RecoveryError::CorruptReplica),
            "{name} row must fail authenticated checkpoint hashing"
        );
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint V2 tamper");
        drop(conn);
        assert_eq!(
            inspect_sealed_protected_roster_v2_fixture(&replica, fixture_identity, &members),
            Err(RecoveryError::CorruptReplica),
            "{name} tamper is rejected before branch selection",
        );
    }
}

#[test]
fn format5_signed_v2_admission_and_terminal_evidence_tamper_is_corrupt() {
    for (name, state) in [
        (
            "q1-ingress-and-provenance",
            consensus::ProtectedRosterV2RecoveryFixtureState::Live,
        ),
        (
            "q2-terminal-proof-and-evidence",
            consensus::ProtectedRosterV2RecoveryFixtureState::Established,
        ),
        (
            "aborted-q2-terminal-proof-and-evidence",
            consensus::ProtectedRosterV2RecoveryFixtureState::Aborted,
        ),
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let (replica, fixture_identity, members) =
            sealed_protected_roster_v2_recovery_fixture(temp.path(), state);
        let conn = Connection::open(&replica.database_path).expect("open signed V2 tamper");
        conn.execute_batch(
            "UPDATE consensus_protected_roster_v2_admissions \
             SET canonical_record = zeroblob(length(canonical_record)); \
             PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .expect("tamper sealed V2 canonical evidence");
        drop(conn);
        assert_eq!(
            inspect_sealed_protected_roster_v2_fixture(&replica, fixture_identity, &members),
            Err(RecoveryError::CorruptReplica),
            "{name}",
        );
    }
}

#[test]
fn format5_signed_v2_create_journal_tamper_is_corrupt_before_branch_selection() {
    fn non_authoritative(record: &mut StoredSessionRecord) {
        record.state_class = StateClass::ReplicatedDr;
    }

    fn expiring(record: &mut StoredSessionRecord) {
        record.expires_at = Some(receipt_inspection_timestamp());
    }

    fn invalid_envelope(record: &mut StoredSessionRecord) {
        record.payload = EncryptedSessionPayload::new(b"not-an-envelope");
    }

    fn invalid_bound_aad(record: &mut StoredSessionRecord) {
        record.fence = FenceToken::new(record.fence.get().saturating_add(1));
    }

    for (name, mutate) in [
        (
            "non-authoritative",
            non_authoritative as fn(&mut StoredSessionRecord),
        ),
        ("expiry", expiring as fn(&mut StoredSessionRecord)),
        (
            "invalid-envelope",
            invalid_envelope as fn(&mut StoredSessionRecord),
        ),
        (
            "invalid-bound-aad",
            invalid_bound_aad as fn(&mut StoredSessionRecord),
        ),
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let (replica, fixture_identity, members) = sealed_protected_roster_v2_recovery_fixture(
            temp.path(),
            consensus::ProtectedRosterV2RecoveryFixtureState::Established,
        );
        let conn = Connection::open(&replica.database_path).expect("open signed V2 journal");
        let encoded: String = conn
            .query_row(
                "SELECT entry_json FROM session_replication_log WHERE sequence = 1",
                [],
                |row| row.get(0),
            )
            .expect("read V2 create journal");
        let mut entry: ReplicationEntry =
            serde_json::from_str(&encoded).expect("decode sealed V2 create journal");
        let ReplicationOp::ProtectedRosterEstablishedCreate { record, .. } = &mut entry.op else {
            panic!("the sealed V2 Established terminal writes a create journal entry");
        };
        mutate(record);
        conn.execute(
            "UPDATE session_replication_log SET entry_json = ?1 WHERE sequence = 1",
            [serde_json::to_string(&entry).expect("encode tampered V2 create journal")],
        )
        .expect("persist V2 create journal tamper");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint V2 create journal tamper");
        drop(conn);

        assert_eq!(
            inspect_sealed_protected_roster_v2_fixture(&replica, fixture_identity, &members),
            Err(RecoveryError::CorruptReplica),
            "{name} V2 create journal is rejected before branch selection",
        );
    }
}

#[test]
fn format5_protected_roster_v2_partial_or_extra_namespace_is_corrupt() {
    for (name, mutation) in [
        (
            "partial-admissions-table",
            "DROP TABLE consensus_protected_roster_v2_admissions;",
        ),
        (
            "missing-terminal-index",
            "DROP INDEX consensus_protected_roster_v2_terminal_sequence;",
        ),
        (
            "unknown-index",
            "CREATE INDEX consensus_protected_roster_v2_unknown ON consensus_protected_roster_v2_admissions(binding);",
        ),
        (
            "extra-table",
            "CREATE TABLE consensus_protected_roster_v2_extra (singleton INTEGER);",
        ),
    ] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let (replica, members) = current_receipt_inspection_fixture(&temp.path().join(name));
        activate_inactive_protected_roster_v2_recovery_fixture(&replica);
        let conn = Connection::open(&replica.database_path).expect("open V2 corruption fixture");
        conn.execute_batch(mutation)
            .expect("apply V2 namespace mutation");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint V2 namespace mutation");
        drop(conn);

        assert_eq!(
            inspect_current_fixture(&replica, &members),
            Err(RecoveryError::CorruptReplica),
            "{name}",
        );
    }
}

#[test]
fn current_recovery_roster_prepared_layout_is_rootless_predecessor_compatible() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (prepared, prepared_members) =
        current_receipt_inspection_fixture(&temp.path().join("prepared"));
    let prepared_before = inspect_current_fixture(&prepared, &prepared_members)
        .expect("inspect empty prepared roster layout");

    // This is the exact rootless predecessor: removing any one roster object
    // or only one root column is intentionally not a compatibility form.
    let (rootless, rootless_members) =
        current_receipt_inspection_fixture(&temp.path().join("rootless"));
    let conn = Connection::open(&rootless.database_path).expect("open rootless predecessor");
    conn.execute_batch(
        "DROP INDEX consensus_protected_roster_terminal_sequence;
         DROP INDEX consensus_protected_roster_reclaim_due;
         DROP INDEX consensus_protected_roster_partition_epoch;
         DROP TABLE consensus_protected_roster_admissions;
         DROP TABLE consensus_protected_roster_business;
         DROP TABLE consensus_protected_roster_witness;
         DROP TABLE consensus_protected_roster_retirement_cursors;
         DROP TABLE consensus_protected_roster_floors;
         DROP TABLE consensus_protected_roster_rows;
         ALTER TABLE consensus_identity DROP COLUMN roster_attestation_algorithm_version;
         ALTER TABLE consensus_identity DROP COLUMN roster_attestation_public_key;
         ALTER TABLE consensus_identity DROP COLUMN roster_attestation_root_id;
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .expect("form exact rootless predecessor");
    drop(conn);
    let rootless_before = inspect_current_fixture(&rootless, &rootless_members)
        .expect("inspect exact rootless predecessor");
    assert_eq!(
        prepared_before.branch_digest(),
        rootless_before.branch_digest(),
        "empty prepared and exact rootless roster layouts retain identical authority",
    );

    terminalize_current_replica_for_normal_backend_open(&prepared);
    drop(SqliteSessionBackend::open(&prepared.database_path).expect("reopen prepared roster"));
    let prepared_after =
        inspect_current_fixture(&prepared, &prepared_members).expect("reinspect prepared roster");
    assert_eq!(
        prepared_before.branch_digest(),
        prepared_after.branch_digest()
    );

    let (v3, v3_members) = current_receipt_inspection_fixture(&temp.path().join("v3-rootless"));
    activate_v3_history_fixture(&v3, 1, 0, 0);
    let conn = Connection::open(&v3.database_path).expect("open exact V3 predecessor");
    conn.execute_batch(
        "DROP INDEX consensus_protected_roster_terminal_sequence;
         DROP INDEX consensus_protected_roster_reclaim_due;
         DROP INDEX consensus_protected_roster_partition_epoch;
         DROP TABLE consensus_protected_roster_admissions;
         DROP TABLE consensus_protected_roster_business;
         DROP TABLE consensus_protected_roster_witness;
         DROP TABLE consensus_protected_roster_retirement_cursors;
         DROP TABLE consensus_protected_roster_floors;
         DROP TABLE consensus_protected_roster_rows;
         ALTER TABLE consensus_identity DROP COLUMN roster_attestation_algorithm_version;
         ALTER TABLE consensus_identity DROP COLUMN roster_attestation_public_key;
         ALTER TABLE consensus_identity DROP COLUMN roster_attestation_root_id;
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .expect("form exact rootless pre-roster V3 fixture");
    drop(conn);
    inspect_current_fixture(&v3, &v3_members)
        .expect("read-only recovery accepts the exact pre-roster V3 product");
}

#[test]
fn current_recovery_accepts_exact_root_then_marker_pre_roster_upgrade() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (replica, members) = current_receipt_inspection_fixture(temp.path());
    let expected = inspect_current_fixture(&replica, &members)
        .expect("inspect equivalent empty prepared roster");
    let conn = Connection::open(&replica.database_path).expect("open R2 upgrade fixture");
    conn.execute_batch(
        "DROP INDEX consensus_protected_roster_terminal_sequence;
         DROP INDEX consensus_protected_roster_reclaim_due;
         DROP INDEX consensus_protected_roster_partition_epoch;
         DROP TABLE consensus_protected_roster_admissions;
         DROP TABLE consensus_protected_roster_business;
         DROP TABLE consensus_protected_roster_witness;
         DROP TABLE consensus_protected_roster_retirement_cursors;
         DROP TABLE consensus_protected_roster_floors;
         DROP TABLE consensus_protected_roster_rows;
         ALTER TABLE consensus_identity DROP COLUMN roster_attestation_algorithm_version;
         ALTER TABLE consensus_identity DROP COLUMN roster_attestation_public_key;
         ALTER TABLE consensus_identity DROP COLUMN roster_attestation_root_id;
         ALTER TABLE consensus_identity DROP COLUMN fenced_transition_receipt_ledger_activated;
         ALTER TABLE consensus_identity ADD COLUMN roster_attestation_root_id BLOB CHECK (
             roster_attestation_root_id IS NULL OR length(roster_attestation_root_id) = 32
         );
         ALTER TABLE consensus_identity ADD COLUMN roster_attestation_public_key BLOB CHECK (
             roster_attestation_public_key IS NULL OR length(roster_attestation_public_key) = 33
         );
         ALTER TABLE consensus_identity ADD COLUMN roster_attestation_algorithm_version INTEGER CHECK (
             roster_attestation_algorithm_version IS NULL OR roster_attestation_algorithm_version = 1
         );
         ALTER TABLE consensus_identity ADD COLUMN fenced_transition_receipt_ledger_activated INTEGER NOT NULL DEFAULT 0 CHECK (
             fenced_transition_receipt_ledger_activated IN (0, 1)
         );
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .expect("form exact roots-then-marker pre-roster upgrade");
    drop(conn);

    let observed = inspect_current_fixture(&replica, &members)
        .expect("offline recovery accepts exact roots-then-marker upgrade");
    assert_eq!(expected.branch_digest(), observed.branch_digest());
    assert_eq!(
        expected.logical_state_digest(),
        observed.logical_state_digest()
    );
}

#[test]
fn current_recovery_accepts_only_the_activated_protected_roster_format() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (valid, valid_members) = current_receipt_inspection_fixture(&temp.path().join("valid"));
    activate_protected_roster_recovery_fixture(&valid);
    inspect_current_fixture(&valid, &valid_members).expect("format-four roster is recoverable");

    let (missing_marker, missing_marker_members) =
        current_receipt_inspection_fixture(&temp.path().join("missing-marker"));
    activate_protected_roster_recovery_fixture(&missing_marker);
    let conn =
        Connection::open(&missing_marker.database_path).expect("open missing marker fixture");
    conn.execute_batch(
        "ALTER TABLE consensus_identity
         DROP COLUMN fenced_transition_receipt_ledger_activated;
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .expect("remove required receipt marker");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&missing_marker, &missing_marker_members),
        Err(RecoveryError::CorruptReplica),
    );

    let (partial_v2, partial_v2_members) =
        current_receipt_inspection_fixture(&temp.path().join("partial-v2"));
    activate_protected_roster_recovery_fixture(&partial_v2);
    let conn = Connection::open(&partial_v2.database_path).expect("open partial V2 fixture");
    conn.execute_batch(
        "CREATE TABLE consensus_fenced_transition_v2_receipts (singleton INTEGER);
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .expect("install partial V2 namespace");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&partial_v2, &partial_v2_members),
        Err(RecoveryError::CorruptReplica),
    );

    let (future, future_members) = current_receipt_inspection_fixture(&temp.path().join("future"));
    activate_protected_roster_recovery_fixture(&future);
    let conn = Connection::open(&future.database_path).expect("open future format fixture");
    conn.execute(
        "UPDATE consensus_identity SET schema_version = ?1 WHERE singleton = 1",
        [i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) + 4],
    )
    .expect("write unknown roster format");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint unknown roster format");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&future, &future_members),
        Err(RecoveryError::CorruptReplica),
    );
}

#[test]
fn current_recovery_roster_namespace_and_preflight_fail_closed() {
    let temp = tempfile::tempdir().expect("temporary directory");

    let (partial, partial_members) =
        current_receipt_inspection_fixture(&temp.path().join("partial"));
    let conn = Connection::open(&partial.database_path).expect("open partial roster fixture");
    conn.execute_batch(
        "DROP TABLE consensus_protected_roster_witness; PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .expect("form partial roster namespace");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&partial, &partial_members),
        Err(RecoveryError::CorruptReplica),
    );

    let (partial_root, partial_root_members) =
        current_receipt_inspection_fixture(&temp.path().join("partial-root"));
    let conn = Connection::open(&partial_root.database_path).expect("open partial root fixture");
    conn.execute_batch(
        "ALTER TABLE consensus_identity DROP COLUMN roster_attestation_algorithm_version;
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .expect("form partial roster trust-root identity");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&partial_root, &partial_root_members),
        Err(RecoveryError::CorruptReplica),
    );

    let (corrupt, corrupt_members) =
        current_receipt_inspection_fixture(&temp.path().join("corrupt"));
    activate_protected_roster_recovery_fixture(&corrupt);
    let conn = Connection::open(&corrupt.database_path).expect("open corrupt roster fixture");
    conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .expect("allow corrupt protected row");
    conn.execute(
        "INSERT INTO consensus_protected_roster_rows (binding, configuration_epoch, partition, history_epoch, state, terminalized_at, terminal_sequence, canonical_record) VALUES (zeroblob(120), (SELECT configuration_epoch FROM consensus_identity WHERE singleton=1), zeroblob(64), 1, 1, NULL, NULL, X'00')",
        [],
    )
    .expect("insert corrupt protected row");
    conn.execute_batch("PRAGMA ignore_check_constraints = OFF; PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint corrupt protected row");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&corrupt, &corrupt_members),
        Err(RecoveryError::CorruptReplica),
    );

    let (oversized, oversized_members) =
        current_receipt_inspection_fixture(&temp.path().join("oversized"));
    activate_protected_roster_recovery_fixture(&oversized);
    let conn = Connection::open(&oversized.database_path).expect("open oversized roster fixture");
    conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .expect("allow oversized protected value");
    let (record_cap, _) = consensus::protected_roster_recovery_value_caps();
    let oversized_record = record_cap
        .checked_add(1)
        .expect("canonical protected record cap has a successor");
    conn.execute(
        "INSERT INTO consensus_protected_roster_rows (binding, configuration_epoch, partition, history_epoch, state, terminalized_at, terminal_sequence, canonical_record) VALUES (zeroblob(120), (SELECT configuration_epoch FROM consensus_identity WHERE singleton=1), zeroblob(64), 1, 1, NULL, NULL, zeroblob(?1))",
        [i64::try_from(oversized_record).expect("record cap fits SQLite integer")],
    )
    .expect("insert oversized protected record");
    conn.execute_batch("PRAGMA ignore_check_constraints = OFF; PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint oversized protected record");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&oversized, &oversized_members),
        Err(RecoveryError::CorruptReplica),
    );

    let (over_count, over_count_members) =
        current_receipt_inspection_fixture(&temp.path().join("over-count"));
    activate_protected_roster_recovery_fixture(&over_count);
    let conn = Connection::open(&over_count.database_path).expect("open over-count roster fixture");
    conn.execute_batch("PRAGMA foreign_keys = OFF;")
        .expect("disable fixture-only foreign keys");
    let too_many_business_rows = FENCED_MUTATION_ROSTER_MAX_LIVE_ROSTERS
        .checked_add(1)
        .expect("live protected business cap has a successor");
    conn.execute_batch(&format!(
        "WITH RECURSIVE sequence(value) AS (
             VALUES(1)
             UNION ALL
             SELECT value + 1 FROM sequence WHERE value < {too_many_business_rows}
         )
         INSERT INTO consensus_protected_roster_business (business_key, binding, configuration_epoch, generation, canonical_business)
         SELECT CAST(printf('%032d', value) AS BLOB),
                CAST(printf('%0120d', value) AS BLOB),
                1,
                1,
                X'00'
         FROM sequence;
         PRAGMA wal_checkpoint(TRUNCATE);",
    ))
    .expect("insert one row over live protected business cap");
    drop(conn);
    assert_eq!(
        inspect_current_fixture(&over_count, &over_count_members),
        Err(RecoveryError::CorruptReplica),
    );
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

        // This fixture models a completed operator recovery. Runtime reopening is
        // therefore permitted only through its terminal recovery handoff, rather
        // than through the planning-only absent-latch path used above.
        terminalize_current_replica_for_normal_backend_open(&replica);
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
    assert!(matches!(
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
    ));
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
    assert!(matches!(
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
    ));

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
    assert!(matches!(
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
    ));
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

#[test]
fn current_recovery_rejects_divergent_retained_prefix_even_with_a_current_snapshot() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("retained-prefix-source"),
        replica_id("retained-prefix-voter"),
        replica_id("retained-prefix-target"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 7),
    ];
    let members = node_set(&ids);
    let initial_leader = *members.iter().next().expect("initial leader");
    let second_leader = *members.iter().nth(1).expect("second leader");
    let third_leader = *members.iter().nth(2).expect("third leader");
    let initial = LogId::new(CommittedLeaderId::new(1, initial_leader), 0);
    for replica in &replicas {
        claim_current_replica(replica, &members, initial);
    }

    // All copies finish with the same logical state.  Their retained blank
    // prefixes are nonetheless distinct valid Raft histories.  Older branch
    // hashing looked only at the final committed row and would let source and
    // voter form a false majority here.
    let source_prefix = LogId::new(CommittedLeaderId::new(2, second_leader), 1);
    let voter_prefix = LogId::new(CommittedLeaderId::new(3, third_leader), 1);
    let target_prefix = LogId::new(CommittedLeaderId::new(4, initial_leader), 1);
    let shared_head = LogId::new(CommittedLeaderId::new(5, second_leader), 2);
    let target_head = LogId::new(CommittedLeaderId::new(6, third_leader), 2);
    append_current_blank_checkpoint(&replicas[0], source_prefix);
    append_current_blank_checkpoint(&replicas[0], shared_head);
    append_current_blank_checkpoint(&replicas[1], voter_prefix);
    append_current_blank_checkpoint(&replicas[1], shared_head);
    append_current_blank_checkpoint(&replicas[2], target_prefix);
    append_current_blank_checkpoint(&replicas[2], target_head);

    // A selected snapshot equal to a still-retained committed row is local
    // compaction state, not a replacement for the retained prefix.  Removing
    // it must leave the source's branch evidence unchanged.
    let file_name = "snapshot-00000000-0000-4000-8000-0000000000c1.opc";
    let payload = b"retained-prefix snapshot is not branch authority";
    let checksum: [u8; 32] = Sha256::digest(payload).into();
    let mut snapshot = payload.to_vec();
    snapshot.extend_from_slice(b"OPCSNP01");
    snapshot.extend_from_slice(
        &u64::try_from(payload.len())
            .expect("snapshot payload length")
            .to_be_bytes(),
    );
    snapshot.extend_from_slice(&checksum);
    std::fs::write(replicas[0].snapshot_directory.join(file_name), &snapshot)
        .expect("write source current snapshot");
    let conn = Connection::open(&replicas[0].database_path).expect("open source replica");
    let metadata = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(shared_head),
        last_membership: consensus::read_membership_sync(&conn, identity())
            .expect("read source membership"),
        snapshot_id: "retained-prefix-current-snapshot".to_owned(),
    };
    consensus::save_current_snapshot_sync(
        &conn,
        identity(),
        &metadata,
        file_name,
        checksum,
        u64::try_from(snapshot.len()).expect("snapshot length"),
    )
    .expect("persist source current snapshot metadata");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint source snapshot metadata");
    drop(conn);

    let manager = recovery(AllowRecovery);
    let source_with_snapshot = inspect_replica(InspectionInput {
        key: &manager.integrity_key,
        replica: &replicas[0],
        identity: identity(),
        expected_members: &members,
        limits: RecoveryLimits::default(),
    })
    .expect("inspect source with current retained snapshot");
    let conn = Connection::open(&replicas[0].database_path).expect("reopen source replica");
    conn.execute("DELETE FROM consensus_snapshot", [])
        .expect("remove non-authoritative source snapshot metadata");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint snapshot removal");
    drop(conn);
    std::fs::remove_file(replicas[0].snapshot_directory.join(file_name))
        .expect("remove non-authoritative source snapshot");
    let source_without_snapshot = inspect_replica(InspectionInput {
        key: &manager.integrity_key,
        replica: &replicas[0],
        identity: identity(),
        expected_members: &members,
        limits: RecoveryLimits::default(),
    })
    .expect("inspect source without local snapshot");
    assert_eq!(
        source_with_snapshot.branch_digest, source_without_snapshot.branch_digest,
        "a current snapshot cannot hide retained prefix evidence"
    );

    let voter = inspect_replica(InspectionInput {
        key: &manager.integrity_key,
        replica: &replicas[1],
        identity: identity(),
        expected_members: &members,
        limits: RecoveryLimits::default(),
    })
    .expect("inspect divergent retained-prefix voter");
    assert_eq!(
        source_without_snapshot.logical_state_digest, voter.logical_state_digest,
        "blank prefixes retain identical logical state"
    );
    assert_eq!(
        source_without_snapshot.committed_index,
        voter.committed_index
    );
    assert_ne!(
        source_without_snapshot.branch_digest, voter.branch_digest,
        "canonical retained prefixes must participate in majority equivalence"
    );
    assert!(
        matches!(
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
            Err(RecoveryError::InsufficientAuthority)
        ),
        "no source majority may be inferred from only the common final row"
    );
}

#[test]
fn current_recovery_does_not_copy_a_redundant_historical_source_snapshot() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("redundant-snapshot-source"),
        replica_id("redundant-snapshot-voter"),
        replica_id("redundant-snapshot-target"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 41),
    ];
    let manager = recovery(AllowRecovery);
    let members = node_set(&ids);
    let leader = *members.iter().next().expect("majority leader");
    let retained_snapshot_log = LogId::new(CommittedLeaderId::new(3, leader), 0);
    let committed = LogId::new(CommittedLeaderId::new(3, leader), 1);
    let fork = LogId::new(
        CommittedLeaderId::new(4, *members.iter().nth(1).expect("fork leader")),
        0,
    );
    for replica in &replicas[..2] {
        claim_current_replica(replica, &members, retained_snapshot_log);
        append_current_blank_checkpoint(replica, committed);
    }
    claim_current_replica(&replicas[2], &members, fork);
    // `claim_current_replica` is a schema fixture and records the synthetic
    // claim as an already-completed recovery. This case models an ordinary
    // current-format cluster that has not itself undergone recovery: a
    // missing sidecar is valid only with this exact zero recovery state.
    for replica in &replicas {
        let conn = Connection::open(&replica.database_path).expect("open current fixture");
        conn.execute(
            "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = ?1, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1",
            params![[0_u8; 32].as_slice()],
        )
        .expect("restore never-recovered current fixture");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint never-recovered current fixture");
    }

    // The source alone selects a perfectly valid snapshot at log 0 while the
    // exact committed log 1 is still retained on both majority voters.  The
    // snapshot does not participate in their branch digest, so it must not
    // become a fleet-wide recovery artifact merely because the source owns it.
    let payload = b"redundant historical source snapshot";
    let checksum: [u8; 32] = Sha256::digest(payload).into();
    let file_name = "snapshot-00000000-0000-4000-8000-0000000000b3.opc";
    let mut snapshot = payload.to_vec();
    snapshot.extend_from_slice(b"OPCSNP01");
    snapshot.extend_from_slice(
        &u64::try_from(payload.len())
            .expect("snapshot payload length")
            .to_be_bytes(),
    );
    snapshot.extend_from_slice(&checksum);
    std::fs::write(replicas[0].snapshot_directory.join(file_name), &snapshot)
        .expect("write redundant source snapshot");
    let conn = Connection::open(&replicas[0].database_path).expect("open source replica");
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(retained_snapshot_log),
        last_membership: consensus::read_membership_sync(&conn, identity())
            .expect("read source membership"),
        snapshot_id: "redundant-source-snapshot".to_owned(),
    };
    // Normal publication refuses a snapshot behind committed/applied. This
    // stopped-process fixture writes an otherwise valid historical selection
    // directly so recovery proves it never republishes bytes that its branch
    // digest does not cover.
    conn.execute(
        "INSERT INTO consensus_snapshot (singleton, configuration_epoch, meta_json, file_name, checksum, byte_length) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            i64::try_from(identity().configuration_epoch().get()).expect("configuration epoch"),
            serde_json::to_vec(&meta).expect("encode historical snapshot metadata"),
            file_name,
            checksum.as_slice(),
            i64::try_from(snapshot.len()).expect("snapshot length fits SQLite"),
        ],
    )
    .expect("inject valid historical source snapshot metadata");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint source snapshot metadata");
    drop(conn);

    let source_evidence = inspect_replica(InspectionInput {
        key: &manager.integrity_key,
        replica: &replicas[0],
        identity: identity(),
        expected_members: &members,
        limits: RecoveryLimits::default(),
    })
    .expect("inspect source with a source-local historical snapshot");
    let voter_evidence = inspect_replica(InspectionInput {
        key: &manager.integrity_key,
        replica: &replicas[1],
        identity: identity(),
        expected_members: &members,
        limits: RecoveryLimits::default(),
    })
    .expect("inspect voter without the source-local snapshot");
    assert_eq!(
        source_evidence.branch_digest, voter_evidence.branch_digest,
        "a snapshot below the physically retained commit is not branch evidence"
    );
    let target_evidence = inspect_replica(InspectionInput {
        key: &manager.integrity_key,
        replica: &replicas[2],
        identity: identity(),
        expected_members: &members,
        limits: RecoveryLimits::default(),
    })
    .expect("inspect divergent target");
    assert_eq!(source_evidence.committed_index, Some(committed.index));
    assert_eq!(source_evidence.applied_index, Some(committed.index));
    assert_eq!(voter_evidence.committed_index, Some(committed.index));
    assert_eq!(voter_evidence.applied_index, Some(committed.index));
    assert_ne!(target_evidence.branch_digest, source_evidence.branch_digest);
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
        .expect("physical committed majority accepts source-local snapshot");
    let targets = replicas[2..].iter().collect::<Vec<_>>();
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
        Err(RecoveryError::InjectedFailure),
        "the snapshot-bearing checkpoint must remain resumable before staging decides to omit it"
    );
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read source-local snapshot checkpoint workflow"),
        RecoveryExecutionState::BackupVerified
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
        .expect("recovery omits redundant source snapshot from staging");

    let target = Connection::open(&replicas[2].database_path).expect("open recovered target");
    assert!(
        consensus::read_current_snapshot_sync(&target, identity())
            .expect("read target selected snapshot")
            .is_none(),
        "the staged database must not select a snapshot not authenticated by the committed branch"
    );
    assert!(
        !replicas[2].snapshot_directory.join(file_name).exists(),
        "the target must not receive the source-local snapshot bytes"
    );
}

#[test]
fn current_recovery_carries_an_authoritative_snapshot_boundary_across_resume() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("snapshot-boundary-source"),
        replica_id("snapshot-boundary-voter"),
        replica_id("snapshot-boundary-target"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 41),
    ];
    let members = node_set(&ids);
    let leader = *members.iter().next().expect("boundary leader");
    let initial = LogId::new(CommittedLeaderId::new(3, leader), 0);
    let boundary = LogId::new(CommittedLeaderId::new(3, leader), 2);
    let committed = LogId::new(CommittedLeaderId::new(3, leader), 3);
    for replica in &replicas[..2] {
        claim_current_replica(replica, &members, initial);
        append_current_blank_checkpoint(replica, LogId::new(CommittedLeaderId::new(3, leader), 1));
        append_current_blank_checkpoint(replica, boundary);
        append_current_blank_checkpoint(replica, committed);
    }
    claim_current_replica(
        &replicas[2],
        &members,
        LogId::new(
            CommittedLeaderId::new(4, *members.iter().nth(1).expect("fork leader")),
            0,
        ),
    );
    for replica in &replicas {
        let conn = Connection::open(&replica.database_path).expect("open current fixture");
        conn.execute(
            "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = ?1, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1",
            params![[0_u8; 32].as_slice()],
        )
        .expect("restore never-recovered current fixture");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint never-recovered current fixture");
    }

    let file_name = "snapshot-00000000-0000-4000-8000-0000000000c1.opc";
    let source_bytes = install_dynamic_current_snapshot_fixture(
        &replicas[0],
        boundary,
        file_name,
        "authoritative-snapshot-boundary",
        b"authoritative no-purge boundary",
    );
    install_dynamic_current_snapshot_fixture(
        &replicas[1],
        boundary,
        file_name,
        "different-authoritative-snapshot-boundary",
        b"different valid boundary bytes",
    );
    for replica in &replicas[..2] {
        let conn = Connection::open(&replica.database_path).expect("open boundary fixture");
        conn.execute("DELETE FROM consensus_log WHERE log_index <= 2", [])
            .expect("remove snapshot-covered prefix");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint snapshot boundary fixture");
    }

    let manager = recovery(AllowRecovery);
    assert!(
        matches!(
            manager.plan(
                &context(),
                identity(),
                members.clone(),
                &replicas,
                &ids[0],
                &ids[2..],
                RecoveryDecisionBasis::VerifiedCommittedMajority,
                RecoveryLimits::default(),
            ),
            Err(RecoveryError::InsufficientAuthority)
        ),
        "a different boundary snapshot cannot authenticate the same suffix"
    );

    // Restore byte-identical metadata and bytes: the two source voters now
    // describe the same snapshot-boundary branch, not merely the same final
    // retained log row.
    install_dynamic_current_snapshot_fixture(
        &replicas[1],
        boundary,
        file_name,
        "authoritative-snapshot-boundary",
        b"authoritative no-purge boundary",
    );
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
        .expect("exact snapshot-boundary majority");
    let targets = replicas[2..].iter().collect::<Vec<_>>();
    // Force the selected target leaf through `Present`: its arbitrary prior
    // inode is authenticated in the workflow and must be removed only by the
    // post-promotion cleanup reconciliation.
    std::fs::write(
        replicas[2].snapshot_directory.join(file_name),
        b"displaced target snapshot",
    )
    .expect("seed displaced target snapshot");
    let snapshot_temporary =
        snapshot_promotion_temporary_path_for_test(&replicas[2], &plan, file_name)
            .expect("derive exact snapshot promotion temporary");
    let database_temporary = database_promotion_temporary_path_for_test(&replicas[2], &plan)
        .expect("derive exact database promotion temporary");
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
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read snapshot-boundary checkpoint workflow"),
        RecoveryExecutionState::BackupVerified
    );
    assert_eq!(
        backup_and_reset_replica(ResetInput {
            key: &manager.integrity_key,
            plan: &plan,
            source: &replicas[0],
            replicas: &replicas,
            targets: &targets,
            backup_root: backup.path(),
            limits: RecoveryLimits::default(),
            failpoint: Some(RecoveryFailpoint::AfterSnapshotPromotion),
        }),
        Err(RecoveryError::InjectedFailure),
        "snapshot exchange leaves its exact displaced inode journaled before cleanup"
    );
    assert!(
        snapshot_temporary.exists(),
        "the snapshot journaled temporary exists before its resume cleanup"
    );
    assert_eq!(
        backup_and_reset_replica(ResetInput {
            key: &manager.integrity_key,
            plan: &plan,
            source: &replicas[0],
            replicas: &replicas,
            targets: &targets,
            backup_root: backup.path(),
            limits: RecoveryLimits::default(),
            failpoint: Some(RecoveryFailpoint::AfterDatabasePromotion),
        }),
        Err(RecoveryError::InjectedFailure),
        "snapshot resume cleanup must complete before the database exchange boundary"
    );
    assert!(
        !snapshot_temporary.exists(),
        "snapshot resume removes its exact journaled displaced inode"
    );
    assert!(
        database_temporary.exists(),
        "database exchange leaves its exact displaced inode journaled before cleanup"
    );
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
        })
        .expect("resume snapshot-boundary recovery"),
        RecoveryExecutionState::AwaitingEpochCommit
    );
    assert!(
        !database_temporary.exists(),
        "database resume removes its exact journaled displaced inode"
    );
    assert!(
        promotion_cleanup_journals_are_empty_for_test(
            &manager.integrity_key,
            &plan,
            backup.path(),
        )
        .expect("read completed promotion workflow"),
        "only a durable cleanup may clear the workflow promotion journals"
    );
    let target = Connection::open(&replicas[2].database_path).expect("open recovered target");
    let selected = consensus::read_current_snapshot_sync(&target, identity())
        .expect("read recovered snapshot")
        .expect("snapshot boundary must remain selected");
    assert_eq!(selected.0.last_log_id, Some(boundary));
    assert_eq!(selected.1, file_name);
    assert_eq!(
        std::fs::read(replicas[2].snapshot_directory.join(file_name))
            .expect("read copied target boundary snapshot"),
        source_bytes
    );
    let rows = consensus::read_log_range_for_recovery_sync(&target, identity(), 3, None, Some(8))
        .expect("read retained boundary suffix");
    assert_eq!(rows.last().map(|entry| entry.log_id), Some(committed));
}

#[test]
fn current_recovery_rejects_divergent_retained_prefix_below_a_committed_snapshot_fallback() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("snapshot-fallback-source"),
        replica_id("snapshot-fallback-voter"),
        replica_id("snapshot-fallback-target"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 41),
    ];
    let members = node_set(&ids);
    let initial_leader = *members.iter().next().expect("initial leader");
    let source_prefix_leader = initial_leader;
    let voter_prefix_leader = *members.iter().nth(1).expect("voter prefix leader");
    let committed_leader = *members.iter().nth(2).expect("committed leader");
    let initial = LogId::new(CommittedLeaderId::new(1, initial_leader), 0);
    let source_prefix = LogId::new(CommittedLeaderId::new(2, source_prefix_leader), 1);
    // The single-term-leader profile serializes a leader as its term, so a
    // distinct node at one term is not a distinct durable LogId. Use a term
    // divergence to exercise the prefix hash with two valid, observable Raft
    // histories that converge at the same later committed row.
    let voter_prefix = LogId::new(CommittedLeaderId::new(3, voter_prefix_leader), 1);
    let committed = LogId::new(CommittedLeaderId::new(4, committed_leader), 2);
    claim_current_replica(&replicas[0], &members, initial);
    append_current_blank_checkpoint(&replicas[0], source_prefix);
    append_current_blank_checkpoint(&replicas[0], committed);
    claim_current_replica(&replicas[1], &members, initial);
    append_current_blank_checkpoint(&replicas[1], voter_prefix);
    append_current_blank_checkpoint(&replicas[1], committed);
    claim_current_replica(
        &replicas[2],
        &members,
        LogId::new(CommittedLeaderId::new(5, committed_leader), 0),
    );
    for replica in &replicas {
        let conn = Connection::open(&replica.database_path).expect("open current fixture");
        conn.execute(
            "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = ?1, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1",
            params![[0_u8; 32].as_slice()],
        )
        .expect("restore never-recovered current fixture");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint never-recovered current fixture");
    }
    let file_name = "snapshot-00000000-0000-4000-8000-0000000000c2.opc";
    for replica in &replicas[..2] {
        install_dynamic_current_snapshot_fixture(
            replica,
            committed,
            file_name,
            "committed-snapshot-fallback",
            b"exact shared committed fallback snapshot",
        );
        let conn = Connection::open(&replica.database_path).expect("open fallback fixture");
        conn.execute("DELETE FROM consensus_log WHERE log_index = 2", [])
            .expect("remove committed log row covered by snapshot");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint committed snapshot fallback fixture");
    }

    let manager = recovery(AllowRecovery);
    let source = inspect_current_fixture(&replicas[0], &members)
        .expect("inspect source committed-snapshot fallback");
    let voter = inspect_current_fixture(&replicas[1], &members)
        .expect("inspect voter committed-snapshot fallback");
    assert_eq!(source.logical_state_digest, voter.logical_state_digest);
    assert_ne!(
        source.branch_digest, voter.branch_digest,
        "the committed fallback hashes every still-retained prefix row"
    );
    assert!(
        matches!(
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
            Err(RecoveryError::InsufficientAuthority)
        ),
        "a shared snapshot at commit cannot hide divergent physical prefixes"
    );
}

#[test]
fn current_recovery_treats_snapshot_at_the_purge_floor_as_redundant() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("purge-snapshot-source"),
        replica_id("purge-snapshot-voter"),
        replica_id("purge-snapshot-target"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 41),
    ];
    let members = node_set(&ids);
    let leader = *members.iter().next().expect("purge leader");
    let purge_floor = LogId::new(CommittedLeaderId::new(3, leader), 0);
    let committed = LogId::new(CommittedLeaderId::new(4, leader), 1);
    for replica in &replicas[..2] {
        claim_current_replica(replica, &members, purge_floor);
    }
    claim_current_replica(
        &replicas[2],
        &members,
        LogId::new(
            CommittedLeaderId::new(5, *members.iter().nth(1).expect("fork leader")),
            0,
        ),
    );
    for replica in &replicas {
        let conn = Connection::open(&replica.database_path).expect("open current fixture");
        conn.execute(
            "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = ?1, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1",
            params![[0_u8; 32].as_slice()],
        )
        .expect("restore never-recovered current fixture");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint never-recovered current fixture");
    }
    let file_name = "snapshot-00000000-0000-4000-8000-0000000000c3.opc";
    install_dynamic_current_snapshot_fixture(
        &replicas[0],
        purge_floor,
        file_name,
        "purge-floor-redundant-snapshot",
        b"snapshot exactly at the durable purge floor",
    );
    for replica in &replicas[..2] {
        // This physically retained membership attests the post-purge state;
        // the source's selected snapshot can therefore remain a local,
        // digest-neutral historical artifact.
        append_current_membership_checkpoint(replica, committed, &members);
        let conn = Connection::open(&replica.database_path).expect("open purge fixture");
        install_current_purge_floor(&conn, &purge_floor);
        conn.execute("DELETE FROM consensus_log WHERE log_index = 0", [])
            .expect("remove purged committed row");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint purge-floor fixture");
    }
    let manager = recovery(AllowRecovery);
    let source = inspect_current_fixture(&replicas[0], &members).expect("inspect source");
    let voter = inspect_current_fixture(&replicas[1], &members).expect("inspect voter");
    assert_eq!(
        source.branch_digest, voter.branch_digest,
        "an exact purge marker owns the committed boundary before a selected snapshot"
    );
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
        .expect("purge-floor majority remains valid without a copied snapshot");
    manager
        .execute(
            &context(),
            &plan,
            &RecoveryConfirmation::verified(&plan),
            &replicas,
            backup.path(),
            RecoveryLimits::default(),
        )
        .expect("execute recovery with redundant purge-floor snapshot");
    let target = Connection::open(&replicas[2].database_path).expect("open recovered target");
    assert!(
        consensus::read_current_snapshot_sync(&target, identity())
            .expect("read recovered snapshot")
            .is_none(),
        "the selected source snapshot was redundant to the durable purge marker"
    );
}

#[test]
fn current_recovery_rejects_different_exact_purge_log_ids() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ids = [
        replica_id("purge-log-source"),
        replica_id("purge-log-voter"),
        replica_id("purge-log-target"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 41),
    ];
    let members = node_set(&ids);
    let source_leader = *members.iter().next().expect("source purge leader");
    let voter_leader = *members.iter().nth(1).expect("voter purge leader");
    let committed_leader = *members.iter().nth(2).expect("committed leader");
    let source_floor = LogId::new(CommittedLeaderId::new(1, source_leader), 0);
    let voter_floor = LogId::new(CommittedLeaderId::new(2, voter_leader), 0);
    let committed = LogId::new(CommittedLeaderId::new(3, committed_leader), 1);

    claim_current_replica(&replicas[0], &members, source_floor);
    append_current_blank_checkpoint(&replicas[0], committed);
    claim_current_replica(&replicas[1], &members, voter_floor);
    append_current_blank_checkpoint(&replicas[1], committed);
    claim_current_replica(
        &replicas[2],
        &members,
        LogId::new(CommittedLeaderId::new(4, committed_leader), 0),
    );

    for (index, (replica, floor)) in [(&replicas[0], source_floor), (&replicas[1], voter_floor)]
        .into_iter()
        .enumerate()
    {
        let snapshot_name = [
            "snapshot-00000000-0000-4000-8000-0000000000c5.opc",
            "snapshot-00000000-0000-4000-8000-0000000000c6.opc",
        ][index];
        install_dynamic_current_snapshot_fixture(
            replica,
            floor,
            snapshot_name,
            "purge-log-identity-snapshot",
            b"snapshot authenticates the compacted membership payload",
        );
        let conn = Connection::open(&replica.database_path).expect("open purge fixture");
        install_current_purge_floor(&conn, &floor);
        conn.execute("DELETE FROM consensus_log WHERE log_index = 0", [])
            .expect("remove physically purged floor");
        conn.execute(
            "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = ?1, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1",
            params![[0_u8; 32].as_slice()],
        )
        .expect("restore never-recovered current fixture");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint purge fixture");
    }
    let conn = Connection::open(&replicas[2].database_path).expect("open target fixture");
    conn.execute(
        "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = ?1, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1",
        params![[0_u8; 32].as_slice()],
    )
    .expect("restore never-recovered target fixture");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint target fixture");

    let source = inspect_current_fixture(&replicas[0], &members).expect("inspect source");
    let voter = inspect_current_fixture(&replicas[1], &members).expect("inspect voter");
    assert_eq!(source.logical_state_digest, voter.logical_state_digest);
    assert_ne!(
        source.branch_digest, voter.branch_digest,
        "the exact purge LogId is authenticated branch evidence, not only a suffix offset"
    );

    let manager = recovery(AllowRecovery);
    assert!(
        matches!(
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
            Err(RecoveryError::InsufficientAuthority)
        ),
        "replicas with different exact purge identities cannot form an authenticated majority"
    );
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
        RecoveryFailpoint::AfterCheckpointCopyBeforeVerification,
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

/// Once `DatabaseInstalled` is MACed into the workflow, a retry must keep the
/// execution lock's original database descriptor authoritative.  Replacing
/// the public name with byte-identical B after that identity admission must
/// fail at the post-predicate fence, not let B inherit A's workflow entry.
#[cfg(target_os = "linux")]
#[test]
fn database_installed_retry_rejects_byte_identical_public_replacement_after_identity_admission() {
    use std::os::fd::AsFd as _;

    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("installed-pin-source-a"),
        replica_id("installed-pin-target-b"),
        replica_id("installed-pin-target-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 13),
        create_legacy_replica(temp.path(), ids[1].clone(), 31),
        create_legacy_replica(temp.path(), ids[2].clone(), 47),
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
        .expect("legacy plan");
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
            failpoint: Some(RecoveryFailpoint::AfterDatabaseInstall),
        }),
        Err(RecoveryError::InjectedFailure),
        "leave the first installed target committed in the workflow"
    );
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read pre-swap workflow"),
        RecoveryExecutionState::BackupVerified
    );

    let original = File::open(&replicas[0].database_path).expect("open installed inode A");
    let identity_a = opc_fs_verity_sys::persistent_file_identity(original.as_fd())
        .expect("persistent identity A");
    let replacement = temp
        .path()
        .join("installed-byte-identical-replacement.sqlite");
    std::fs::copy(&replicas[0].database_path, &replacement).expect("copy A into independent B");
    let replacement_file = File::open(&replacement).expect("open replacement inode B");
    let identity_b = opc_fs_verity_sys::persistent_file_identity(replacement_file.as_fd())
        .expect("persistent identity B");
    assert!(
        identity_a != identity_b,
        "the causal replacement must be byte-identical but persistently distinct"
    );
    drop(replacement_file);

    let swapped = Arc::new(AtomicBool::new(false));
    let swapped_hook = Arc::clone(&swapped);
    let expected_target = replicas[0].database_path.clone();
    install_target_database_after_identity_admission_hook(move |public_database| {
        assert_eq!(public_database, expected_target);
        std::fs::rename(&replacement, public_database)
            .expect("replace public A with independently-created B");
        swapped_hook.store(true, Ordering::SeqCst);
    });
    let result = backup_and_reset_replica(ResetInput {
        key: &manager.integrity_key,
        plan: &plan,
        source: &replicas[0],
        replicas: &replicas,
        targets: &targets,
        backup_root: backup.path(),
        limits: RecoveryLimits::default(),
        failpoint: None,
    });
    clear_target_database_after_identity_admission_hook();

    assert!(
        swapped.load(Ordering::SeqCst),
        "identity-admission seam fired"
    );
    assert_eq!(
        result,
        Err(RecoveryError::BackupCorrupt),
        "the retained A pin must reject public B before any workflow transition"
    );
    let public_b = File::open(&replicas[0].database_path).expect("open public replacement B");
    assert!(
        opc_fs_verity_sys::persistent_file_identity(public_b.as_fd())
            .expect("persistent public B identity")
            == identity_b,
        "the public name remains B; rejection cannot depend on restoring A"
    );
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read rejected workflow"),
        RecoveryExecutionState::BackupVerified,
        "the rejected retry must not advance the workflow"
    );
}

/// The final recovery predicates must read the same WAL snapshot as the
/// evidence they refine. X is valid evidence with no F marker; after that
/// inspection a writer commits Y that supplies the marker shape but drops the
/// protected-roster witness. X and Y fail distinct complete predicates.
#[test]
fn pinned_inspection_keeps_terminal_predicate_on_the_x_wal_snapshot() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (replica, members) = current_receipt_inspection_fixture(temp.path());
    inspect_current_fixture(&replica, &members).expect("X is semantically valid evidence");

    let writer_ran = Arc::new(AtomicBool::new(false));
    let writer_ran_hook = Arc::clone(&writer_ran);
    install_pinned_inspection_path_swap_hooks(
        |_| {},
        move |database| {
            let writer = Connection::open(database).expect("open concurrent WAL writer");
            writer
                .execute_batch(
                    "BEGIN IMMEDIATE;
                     UPDATE consensus_operator_recovery
                     SET recovery_v2_activated = 1,
                         finalize_log_id_json = X'31',
                         finalize_entry_json = X'31'
                     WHERE singleton = 1;
                     DROP TABLE consensus_protected_roster_witness;
                     COMMIT;",
                )
                .expect("commit Y marker/witness mutation into WAL");
            writer_ran_hook.store(true, Ordering::SeqCst);
        },
    );
    let observed_x = Arc::new(Mutex::new(None::<(bool, bool)>));
    let observed_x_proof = Arc::clone(&observed_x);
    let result = inspect_replica_with_descriptor_snapshot_proof_for_test(
        InspectionInput {
            key: &integrity_key(),
            replica: &replica,
            identity: identity(),
            expected_members: &members,
            limits: RecoveryLimits::default(),
        },
        move |_evidence, conn| {
            let strict_f_marker: bool = conn
                .query_row(
                    "SELECT finalize_log_id_json IS NOT NULL AND finalize_entry_json IS NOT NULL
                     FROM consensus_operator_recovery WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            let protected_roster_witness: bool = conn
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM sqlite_schema
                         WHERE type = 'table' AND name = 'consensus_protected_roster_witness'
                     )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            *observed_x_proof
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some((strict_f_marker, protected_roster_witness));
            if !strict_f_marker {
                return Err(RecoveryError::BackupCorrupt);
            }
            if !protected_roster_witness {
                return Err(RecoveryError::CorruptReplica);
            }
            Ok(())
        },
    );
    clear_pinned_inspection_path_swap_hooks();

    assert!(
        writer_ran.load(Ordering::SeqCst),
        "Y writer committed after X evidence"
    );
    assert_eq!(
        result,
        Err(RecoveryError::BackupCorrupt),
        "the retained transaction must continue the X predicate and reject X for its absent F marker"
    );
    assert_eq!(
        *observed_x
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        Some((false, true)),
        "the proof closure observed X: no F marker, but an intact protected roster witness"
    );

    let y = Connection::open(&replica.database_path).expect("open committed Y");
    let y_marker: bool = y
        .query_row(
            "SELECT finalize_log_id_json IS NOT NULL AND finalize_entry_json IS NOT NULL
             FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read Y marker");
    let y_witness: bool = y
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema
                 WHERE type = 'table' AND name = 'consensus_protected_roster_witness'
             )",
            [],
            |row| row.get(0),
        )
        .expect("read Y witness absence");
    assert_eq!(
        (y_marker, y_witness),
        (true, false),
        "Y restores the F-marker shape but independently fails its protected-roster predicate"
    );
    drop(y);
    assert_eq!(
        inspect_current_fixture(&replica, &members),
        Err(RecoveryError::CorruptReplica),
        "a standalone inspection of Y rejects the dropped protected-roster witness"
    );
}

/// The legacy capsule is captured from X.  Before classification can start, a
/// same-inode WAL writer installs Y with a canonical-but-different baseline
/// Membership while retaining the same resulting membership scope and all
/// installed-state evidence.  Classification must reject Y rather than
/// combining X's physical authority with Y's semantic predicate.
#[cfg(target_os = "linux")]
#[test]
fn legacy_finalization_classification_rejects_x_to_y_bootstrap_membership_rewrite() {
    use std::os::fd::AsFd as _;

    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("legacy-classification-wal-a"),
        replica_id("legacy-classification-wal-b"),
        replica_id("legacy-classification-wal-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 17),
        create_legacy_replica(temp.path(), ids[1].clone(), 31),
        create_legacy_replica(temp.path(), ids[2].clone(), 47),
    ];
    let expected_members = node_set(&ids);
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            identity(),
            expected_members.clone(),
            &replicas,
            &ids[0],
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("legacy classification plan");
    let confirmation = RecoveryConfirmation::legacy(
        &plan,
        RecoveryConfirmation::required_legacy_acknowledgement(),
    );
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
            .expect("install legacy classification fixture")
            .state(),
        RecoveryExecutionState::AwaitingEpochCommit
    );
    // A live OpenRaft cluster would establish this shared initial Membership
    // before finalization. This unit fixture has no live election, so create
    // its exact installed baseline directly on every already-reset target.
    let baseline_log_id = LogId::new(
        CommittedLeaderId::new(
            1,
            *expected_members
                .iter()
                .next()
                .expect("legacy classification leader"),
        ),
        0,
    );
    let baseline = Entry::<SessionRaftTypeConfig> {
        log_id: baseline_log_id,
        payload: EntryPayload::Membership(Membership::new(
            vec![expected_members.clone()],
            expected_members.clone(),
        )),
    };
    for replica in &replicas {
        let conn = Connection::open(&replica.database_path).expect("open installed legacy target");
        consensus::append_logs_sync(&conn, identity(), std::slice::from_ref(&baseline))
            .expect("append installed baseline Membership");
        consensus::save_committed_sync(&conn, identity(), Some(baseline_log_id))
            .expect("commit installed baseline Membership");
        consensus::apply_entries_sync(
            &conn,
            identity(),
            &BackendCapabilities::all_enabled(),
            vec![baseline.clone()],
        )
        .expect("apply installed baseline Membership");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint installed baseline Membership");
    }

    let mut pins = acquire_finalization_pins(
        &manager.integrity_key,
        &plan,
        &replicas,
        backup.path(),
        RecoveryLimits::default(),
    )
    .expect("pin installed legacy target");
    let predecessor = legacy_finalization_predecessor(
        &manager.integrity_key,
        &plan,
        &mut pins,
        backup.path(),
        RecoveryLimits::default(),
    )
    .expect("capture exact legacy predecessor")
    .expect("legacy plan captures predecessor");
    let legacy_bootstrap = predecessor
        .legacy_bootstrap_membership
        .as_ref()
        .expect("captured legacy Membership");
    let baseline_digest = legacy_bootstrap.digest;
    let baseline_log_id = legacy_bootstrap.log_id;
    assert_eq!(
        classify_finalization_pins(
            &manager.integrity_key,
            &plan,
            &mut pins,
            RecoveryLimits::default(),
        ),
        Ok(FinalizationTransitionState::AllInstalled),
        "X is a complete installed-state classification before the causal WAL rewrite"
    );
    let database = replicas[0].database_path.clone();
    let database_before = File::open(&database).expect("open X database descriptor");
    let inode_before = opc_fs_verity_sys::persistent_file_identity(database_before.as_fd())
        .expect("read X persistent database identity");
    drop(database_before);

    let writer_ran = Arc::new(AtomicBool::new(false));
    let writer_ran_hook = Arc::clone(&writer_ran);
    install_legacy_classification_before_proof_hook(move || {
        let writer = Connection::open(&database).expect("open same-inode Y WAL writer");
        writer
            .execute_batch("PRAGMA journal_mode = WAL; BEGIN IMMEDIATE;")
            .expect("begin Y WAL transaction");
        let rewritten = Entry::<SessionRaftTypeConfig> {
            log_id: baseline_log_id,
            // The duplicate uniform configuration is semantically equivalent
            // to X for the current scope, but its canonical Membership bytes
            // deliberately produce a different authenticated digest.
            payload: EntryPayload::Membership(Membership::new(
                vec![expected_members.clone(), expected_members.clone()],
                expected_members.clone(),
            )),
        };
        writer
            .execute(
                "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = ?2",
                params![
                    serde_json::to_vec(&rewritten).expect("encode rewritten Y Membership"),
                    i64::try_from(baseline_log_id.index).expect("baseline log index"),
                ],
            )
            .expect("replace exact baseline Membership in Y");
        writer
            .execute_batch("COMMIT;")
            .expect("commit Y WAL rewrite");
        writer_ran_hook.store(true, Ordering::SeqCst);
    });

    assert_eq!(
        classify_finalization_pins(
            &manager.integrity_key,
            &plan,
            &mut pins,
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::BackupCorrupt),
        "one classifier snapshot must reject Y's replacement baseline"
    );
    assert!(writer_ran.load(Ordering::SeqCst), "causal Y writer ran");

    let database_after = File::open(&replicas[0].database_path).expect("open Y database");
    assert_eq!(
        opc_fs_verity_sys::persistent_file_identity(database_after.as_fd())
            .expect("read Y persistent database identity"),
        inode_before,
        "the adversary wrote the pinned inode through WAL rather than replacing its pathname"
    );
    drop(database_after);
    let y = Connection::open(&replicas[0].database_path).expect("open Y database connection");
    let y_digest = consensus::operator_recovery_v2_bootstrap_membership_digest_sync(
        &y,
        identity(),
        &baseline_log_id,
    )
    .expect("read Y Membership digest");
    assert_ne!(
        RecoveryDigest::from_bytes(y_digest),
        baseline_digest,
        "Y retains a valid membership scope but changes the exact capsule payload"
    );
    drop(y);
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read rejected legacy workflow"),
        RecoveryExecutionState::AwaitingEpochCommit,
        "rejected classification cannot advance the workflow"
    );
}

#[test]
fn target_backup_semantic_inspection_uses_the_held_copy_pin() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("pinned-inspection-source"),
        replica_id("pinned-inspection-target-b"),
        replica_id("pinned-inspection-target-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 13),
        create_legacy_replica(temp.path(), ids[1].clone(), 31),
        create_legacy_replica(temp.path(), ids[2].clone(), 47),
    ];
    let semantic_standin = create_legacy_replica(
        temp.path(),
        replica_id("pinned-inspection-semantic-standin"),
        99,
    );
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
        .expect("legacy plan");

    // `ensure_target_backup` has already copied and pinned A when this hook
    // makes its pathname name the independently valid but semantically
    // divergent B.  The after hook restores A before the mandatory path-to-pin
    // fence.  A pathname-based inspection would bless B and return StalePlan;
    // descriptor-backed inspection reads A and reaches the injected boundary.
    let displaced = Arc::new(Mutex::new(None::<std::path::PathBuf>));
    let hook_armed = Arc::new(AtomicBool::new(true));
    let before_displaced = Arc::clone(&displaced);
    let after_displaced = Arc::clone(&displaced);
    let before_hook_armed = Arc::clone(&hook_armed);
    let standin_database = semantic_standin.database_path.clone();
    install_pinned_inspection_path_swap_hooks(
        move |backup_database| {
            if !before_hook_armed.swap(false, Ordering::SeqCst) {
                return;
            }
            let original = backup_database.with_extension("pinned-inspection-original");
            std::fs::rename(backup_database, &original).expect("detach pinned backup pathname");
            std::fs::copy(&standin_database, backup_database)
                .expect("substitute independently valid backup database");
            *before_displaced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(original);
        },
        move |backup_database| {
            let Some(original) = after_displaced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            else {
                return;
            };
            std::fs::remove_file(backup_database).expect("remove stand-in backup database");
            std::fs::rename(original, backup_database).expect("restore pinned backup pathname");
        },
    );
    let targets = replicas.iter().collect::<Vec<_>>();
    let result = backup_and_reset_replica(ResetInput {
        key: &manager.integrity_key,
        plan: &plan,
        source: &replicas[0],
        replicas: &replicas,
        targets: &targets,
        backup_root: backup.path(),
        limits: RecoveryLimits::default(),
        failpoint: Some(RecoveryFailpoint::AfterTargetBackupCopy),
    });
    clear_pinned_inspection_path_swap_hooks();
    assert_eq!(
        result,
        Err(RecoveryError::InjectedFailure),
        "semantic inspection must read the held copied inode, not the swapped pathname"
    );
    assert!(
        displaced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none(),
        "the pathname was restored before the exact-inode path fence"
    );
}

#[test]
fn checkpoint_semantic_inspection_uses_the_held_copy_pin() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("pinned-checkpoint-source"),
        replica_id("pinned-checkpoint-target-b"),
        replica_id("pinned-checkpoint-target-c"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 13),
        create_legacy_replica(temp.path(), ids[1].clone(), 31),
        create_legacy_replica(temp.path(), ids[2].clone(), 47),
    ];
    let semantic_standin = create_legacy_replica(
        temp.path(),
        replica_id("pinned-checkpoint-semantic-standin"),
        99,
    );
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
        .expect("legacy plan");

    // Target backups are inspected first. Leave those paths alone and swap
    // only `checkpoint/source.sqlite`, after its copy is pinned and its SQLite
    // connection has been opened. A former pathname inspection would observe
    // B here and reject the selected source; descriptor inspection observes
    // the copied source A, then the exact-inode fence sees A restored.
    let displaced = Arc::new(Mutex::new(None::<std::path::PathBuf>));
    let hook_armed = Arc::new(AtomicBool::new(true));
    let before_displaced = Arc::clone(&displaced);
    let after_displaced = Arc::clone(&displaced);
    let checkpoint_hook_ran = Arc::new(AtomicBool::new(false));
    let before_hook_ran = Arc::clone(&checkpoint_hook_ran);
    let before_hook_armed = Arc::clone(&hook_armed);
    let standin_database = semantic_standin.database_path.clone();
    install_pinned_inspection_path_swap_hooks(
        move |checkpoint_database| {
            if checkpoint_database
                .file_name()
                .and_then(|name| name.to_str())
                != Some("source.sqlite")
            {
                return;
            }
            if !before_hook_armed.swap(false, Ordering::SeqCst) {
                return;
            }
            let original = checkpoint_database.with_extension("pinned-inspection-original");
            std::fs::rename(checkpoint_database, &original)
                .expect("detach pinned checkpoint pathname");
            std::fs::copy(&standin_database, checkpoint_database)
                .expect("substitute independently valid checkpoint database");
            *before_displaced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(original);
            before_hook_ran.store(true, Ordering::SeqCst);
        },
        move |checkpoint_database| {
            if checkpoint_database
                .file_name()
                .and_then(|name| name.to_str())
                != Some("source.sqlite")
            {
                return;
            }
            let Some(original) = after_displaced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            else {
                return;
            };
            std::fs::remove_file(checkpoint_database).expect("remove stand-in checkpoint database");
            std::fs::rename(original, checkpoint_database)
                .expect("restore pinned checkpoint pathname");
        },
    );
    let targets = replicas.iter().collect::<Vec<_>>();
    let result = backup_and_reset_replica(ResetInput {
        key: &manager.integrity_key,
        plan: &plan,
        source: &replicas[0],
        replicas: &replicas,
        targets: &targets,
        backup_root: backup.path(),
        limits: RecoveryLimits::default(),
        failpoint: Some(RecoveryFailpoint::AfterCheckpointCopy),
    });
    clear_pinned_inspection_path_swap_hooks();
    assert_eq!(
        result,
        Err(RecoveryError::InjectedFailure),
        "checkpoint semantic inspection must read the held copied inode"
    );
    assert!(
        checkpoint_hook_ran.load(Ordering::SeqCst),
        "the checkpoint semantic inspection swap must actually execute"
    );
    assert!(
        displaced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none(),
        "the checkpoint pathname was restored before the exact-inode path fence"
    );
}

#[test]
fn checkpoint_copy_crash_before_verified_evidence_reproves_and_resumes() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let first_id = replica_id("checkpoint-crash-source-a");
    let second_id = replica_id("checkpoint-crash-target-b");
    let third_id = replica_id("checkpoint-crash-target-c");
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
    let targets = replicas.iter().collect::<Vec<_>>();

    reset_planned_fleet_inspection_count();
    assert_eq!(
        backup_and_reset_replica(ResetInput {
            key: &manager.integrity_key,
            plan: &plan,
            source: &replicas[0],
            replicas: &replicas,
            targets: &targets,
            backup_root: backup.path(),
            limits: RecoveryLimits::default(),
            failpoint: Some(RecoveryFailpoint::AfterCheckpointCopyBeforeVerification),
        }),
        Err(RecoveryError::InjectedFailure)
    );
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("the copy-only workflow remains structurally readable"),
        RecoveryExecutionState::Planned
    );
    assert_eq!(
        planned_fleet_inspection_count(),
        1,
        "the first proof precedes the intentionally unpublished checkpoint evidence"
    );

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
        })
        .expect("resume copy-only checkpoint workflow"),
        RecoveryExecutionState::AwaitingEpochCommit
    );
    assert!(
        planned_fleet_inspection_count() >= 3,
        "resume must prove the fleet before and after recreating the checkpoint"
    );
}

#[test]
fn snapshot_checkpoint_after_backup_crash_keeps_checkpoint_and_staging_shapes_distinct() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("snapshot-backup-crash-source"),
        replica_id("snapshot-backup-crash-voter"),
        replica_id("snapshot-backup-crash-target"),
    ];
    let replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 7),
        create_legacy_replica(temp.path(), ids[1].clone(), 7),
        create_legacy_replica(temp.path(), ids[2].clone(), 41),
    ];
    let members = node_set(&ids);
    let leader = *members.iter().next().expect("majority leader");
    let source_log = LogId::new(CommittedLeaderId::new(3, leader), 0);
    let target_log = LogId::new(
        CommittedLeaderId::new(4, *members.iter().nth(1).expect("fork leader")),
        0,
    );
    claim_current_replica(&replicas[0], &members, source_log);
    claim_current_replica(&replicas[1], &members, source_log);
    claim_current_replica(&replicas[2], &members, target_log);
    for replica in &replicas {
        let conn = Connection::open(&replica.database_path).expect("open current fixture");
        conn.execute(
            "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = ?1, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1",
            params![[0_u8; 32].as_slice()],
        )
        .expect("restore never-recovered current fixture");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint never-recovered fixture");
    }

    let payload = b"snapshot-bearing checkpoint crash fixture";
    let checksum: [u8; 32] = Sha256::digest(payload).into();
    let file_name = "snapshot-00000000-0000-4000-8000-0000000000ca.opc";
    let mut bytes = payload.to_vec();
    bytes.extend_from_slice(b"OPCSNP01");
    bytes.extend_from_slice(
        &u64::try_from(payload.len())
            .expect("snapshot payload length")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&checksum);
    std::fs::write(replicas[0].snapshot_directory.join(file_name), &bytes)
        .expect("write source snapshot");
    let conn = Connection::open(&replicas[0].database_path).expect("open source replica");
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: Some(source_log),
        last_membership: consensus::read_membership_sync(&conn, identity())
            .expect("read source membership"),
        snapshot_id: "snapshot-backup-crash".to_owned(),
    };
    consensus::save_current_snapshot_sync(
        &conn,
        identity(),
        &meta,
        file_name,
        checksum,
        u64::try_from(bytes.len()).expect("snapshot length"),
    )
    .expect("persist source snapshot metadata");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint source snapshot metadata");
    drop(conn);

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
        .expect("snapshot-bearing current plan");
    let targets = replicas[2..].iter().collect::<Vec<_>>();
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
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("snapshot-bearing backup record is structurally valid"),
        RecoveryExecutionState::BackupVerified
    );
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
        })
        .expect("resume snapshot-bearing workflow"),
        RecoveryExecutionState::AwaitingEpochCommit
    );
}

#[test]
fn target_backup_snapshot_directory_sync_precedes_verified_manifest() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let first_id = replica_id("backup-sync-source");
    let second_id = replica_id("backup-sync-target");
    let third_id = replica_id("backup-sync-third");
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

    let observed_sync_boundary = Arc::new(AtomicBool::new(false));
    let observed_by_hook = Arc::clone(&observed_sync_boundary);
    install_target_backup_snapshot_directory_sync_hook(move |snapshot_directory| {
        assert!(
            snapshot_directory.is_dir(),
            "nested snapshots directory exists"
        );
        assert!(
            !snapshot_directory
                .parent()
                .expect("backup parent")
                .join("backup-manifest.json")
                .exists(),
            "the manifest cannot precede nested snapshots directory durability"
        );
        observed_by_hook.store(true, Ordering::SeqCst);
        true // deterministically model an fsync failure at this boundary.
    });

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
        }),
        Err(RecoveryError::FileOperationFailed),
        "a failed nested directory fsync must abort before verification"
    );
    assert!(
        observed_sync_boundary.load(Ordering::SeqCst),
        "the backup path exercised the nested directory sync boundary"
    );

    fn contains_backup_manifest(path: &Path) -> bool {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => return false,
        };
        entries.filter_map(Result::ok).any(|entry| {
            let path = entry.path();
            path.file_name()
                .is_some_and(|name| name == "backup-manifest.json")
                || path.is_dir() && contains_backup_manifest(&path)
        })
    }

    assert!(
        !contains_backup_manifest(backup.path()),
        "Verified evidence must never publish without a synced nested snapshot directory"
    );
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read interrupted workflow"),
        RecoveryExecutionState::Planned,
        "the outer workflow must remain before its verified transition"
    );
}

#[test]
fn database_promotion_resume_syncs_the_promoted_parent_before_installing() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let first_id = replica_id("rename-sync-source");
    let second_id = replica_id("rename-sync-target");
    let third_id = replica_id("rename-sync-third");
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
    let database_temporary = database_promotion_temporary_path_for_test(&replicas[0], &plan)
        .expect("derive exact database promotion temporary");

    // This is intentionally earlier than AfterDatabaseInstall: it leaves the
    // authenticated temporary identity in the workflow while the promoted
    // target name exists but its parent has not been fsynced by this process.
    fail_next_promotion_after_rename();
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
        }),
        Err(RecoveryError::InjectedFailure),
        "test seam stopped between rename and parent-directory fsync"
    );
    assert!(
        database_temporary.exists(),
        "the pre-sync exchange retains its exact displaced database inode"
    );

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
        .expect("resume renamed target after syncing its parent"),
        RecoveryExecutionState::AwaitingEpochCommit,
        "resume must not treat a merely renamed target as installed until its parent is synced"
    );
    assert!(
        !database_temporary.exists(),
        "the completed database promotion must remove its exact displaced inode"
    );
    assert!(
        promotion_cleanup_journals_are_empty_for_test(
            &manager.integrity_key,
            &plan,
            backup.path(),
        )
        .expect("read resumed promotion workflow"),
        "only a durable cleanup may clear the database promotion journal"
    );
}

#[test]
fn database_promotion_resume_rejects_a_same_byte_displaced_inode() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let first_id = replica_id("disposition-source");
    let second_id = replica_id("disposition-target");
    let third_id = replica_id("disposition-third");
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

    assert_eq!(
        backup_and_reset_replica(ResetInput {
            key: &manager.integrity_key,
            plan: &plan,
            source: &replicas[0],
            replicas: &replicas,
            targets: &replicas.iter().collect::<Vec<_>>(),
            backup_root: backup.path(),
            limits: RecoveryLimits::default(),
            failpoint: Some(RecoveryFailpoint::AfterDatabaseTemporaryPrepared),
        }),
        Err(RecoveryError::InjectedFailure),
        "the prepared temporary and its destination disposition are journaled before exchange"
    );
    let replacement = temp.path().join("same-byte-database-replacement.sqlite");
    std::fs::copy(&replicas[0].database_path, &replacement)
        .expect("copy exact displaced database bytes");
    std::fs::rename(&replacement, &replicas[0].database_path)
        .expect("replace the journaled public database inode");

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
        }),
        Err(RecoveryError::BackupCorrupt),
        "resume must reject a same-byte replacement instead of promoting over it"
    );
    assert_ne!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read halted workflow"),
        RecoveryExecutionState::AwaitingEpochCommit,
        "the rejected retry must not advance the recovery workflow"
    );
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

#[cfg(feature = "test-control")]
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
    let (finalized_index, report) = loop {
        let mut completed = None;
        for (index, store) in stores.iter().enumerate() {
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
                    completed = Some((index, report));
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

    // The one manager that returned has consumed only its own terminal
    // handoff.  Observe the remaining sidecars directly through their exact
    // database descriptors: do not call B/C readiness, because that public
    // boundary would itself consume the pending handoff we need to prove.
    let expected_latch = consensus::OperatorRecoveryLatch {
        identity: campaign_identity,
        recovery_epoch: plan.next_recovery_epoch(),
        plan_digest: plan.plan_digest().as_bytes(),
        audit_pending: false,
    };
    let latch_phase = |index: usize| {
        let database = File::open(&replicas[index].database_path)
            .expect("open campaign database descriptor for latch phase");
        consensus::operator_recovery_latch_phase_sync(
            &replicas[index].database_path,
            expected_latch,
            &database,
            None,
        )
        .expect("classify descriptor-bound campaign latch")
    };
    for index in 0..replicas.len() {
        assert_eq!(
            latch_phase(index),
            if index == finalized_index {
                consensus::OperatorRecoveryLatchPhase::Consumed
            } else {
                consensus::OperatorRecoveryLatchPhase::PendingHandoff
            },
            "only the manager which returned may consume its handoff"
        );
    }
    let finalized_conn =
        Connection::open(&replicas[finalized_index].database_path).expect("open finalized voter");
    let finalize_log_id =
        consensus::read_operator_recovery_sync(&finalized_conn, campaign_identity)
            .expect("read finalized campaign recovery state")
            .finalize_log_id
            .expect("read exact finalized campaign log ID");
    drop(finalized_conn);

    // A consumed live voter may now admit a real application operation.  Its
    // pending peers must replicate and apply that ordinary command while
    // remaining readiness-closed; the fleet classifier must therefore use
    // the one historical proof regime only after this consumption boundary.
    let post_recovery = EncryptingSessionBackend::new(
        Arc::new(stores[finalized_index].clone()),
        provider.clone(),
        "legacy-recovery-campaign",
    );
    let post_recovery_key = SessionKey {
        tenant: TenantId::from_static("tenant-a"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"legacy-post-recovery-canary")
            .try_into()
            .expect("valid post-recovery stable ID"),
    };
    let post_recovery_lease = post_recovery
        .acquire(
            &post_recovery_key,
            OwnerId::new("legacy-post-recovery-owner").expect("post-recovery owner"),
            Duration::from_secs(300),
        )
        .await
        .expect("acquire fresh post-recovery lease through consumed voter");
    assert_eq!(
        post_recovery
            .compare_and_set(CompareAndSet {
                key: post_recovery_key.clone(),
                lease: post_recovery_lease.clone(),
                expected_generation: None,
                new_record: StoredSessionRecord {
                    key: post_recovery_key.clone(),
                    generation: Generation::new(1),
                    owner: post_recovery_lease.owner().clone(),
                    fence: post_recovery_lease.fence(),
                    state_class: StateClass::AuthoritativeSession,
                    state_type: StateType::new("legacy-post-recovery-context")
                        .expect("post-recovery state type"),
                    expires_at: None,
                    payload: EncryptedSessionPayload::new(Bytes::from_static(
                        b"legacy-post-recovery-plaintext-canary",
                    )),
                },
            })
            .await
            .expect("commit post-recovery normal canary"),
        CompareAndSetResult::Success
    );
    let source_canary = crate::sqlite::ops::get_raw_sync(
        &Connection::open(&replicas[finalized_index].database_path)
            .expect("open consumed voter durable canary"),
        &post_recovery_key,
    )
    .expect("read consumed voter durable canary")
    .expect("post-recovery canary on consumed voter");
    assert_eq!(
        post_recovery
            .get(&post_recovery_key)
            .await
            .expect("decrypt consumed-voter post-recovery canary")
            .expect("decrypted consumed-voter post-recovery canary")
            .payload
            .as_bytes(),
        b"legacy-post-recovery-plaintext-canary"
    );
    let recovery_application_sequence = plan
        .application_sequence_high_water()
        .checked_add(1)
        .expect("recovery application sequence");
    for (index, replica) in replicas.iter().enumerate() {
        if index == finalized_index {
            continue;
        }
        loop {
            let conn =
                Connection::open(&replica.database_path).expect("open pending voter durable state");
            let applied = consensus::read_applied_sync(&conn, campaign_identity)
                .expect("read pending voter applied log");
            let application_sequence: i64 = conn
                .query_row(
                    "SELECT application_sequence FROM consensus_machine WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("read pending voter application sequence");
            drop(conn);
            let direct = crate::sqlite::ops::get_raw_sync(
                &Connection::open(&replica.database_path)
                    .expect("open pending voter raw durable canary"),
                &post_recovery_key,
            )
            .expect("read pending voter durable canary directly");
            if applied.is_some_and(|applied| applied.index > finalize_log_id.index)
                && u64::try_from(application_sequence).ok() > Some(recovery_application_sequence)
                && direct
                    .as_ref()
                    .is_some_and(|record| record == &source_canary)
                && latch_phase(index) == consensus::OperatorRecoveryLatchPhase::PendingHandoff
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "pending voter did not durably apply the post-recovery canary"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    // Capture the deterministic recovery certificate and outcome after every
    // voter has applied the canary. Sequential B/C finalization retries must
    // only consume their local handoffs, never issue another V2 proposal.
    let recovery_request_id: [u8; 16] = plan.plan_digest().as_bytes()[..16]
        .try_into()
        .expect("recovery plan digest contains deterministic request ID");
    let v2_evidence = replicas
        .iter()
        .map(|replica| {
            let conn = Connection::open(&replica.database_path)
                .expect("open voter for deterministic V2 evidence");
            let certificate: (Vec<u8>, Vec<u8>) = conn
                .query_row(
                    "SELECT finalize_log_id_json, finalize_entry_json FROM consensus_operator_recovery WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("read exact V2 certificate");
            let outcome: (Vec<u8>, Vec<u8>) = conn
                .query_row(
                    "SELECT payload_digest, response_json FROM consensus_request_outcomes WHERE request_id = ?1",
                    [recovery_request_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("read exact deterministic V2 outcome");
            let outcome_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM consensus_request_outcomes WHERE request_id = ?1",
                    [recovery_request_id.as_slice()],
                    |row| row.get(0),
                )
                .expect("count deterministic V2 outcomes");
            assert_eq!(outcome_count, 1, "exactly one V2 outcome per voter");
            (certificate, outcome)
        })
        .collect::<Vec<_>>();

    // Drive the production OpenRaft snapshot and purge paths on the one
    // already-consumed voter while B/C remain PendingHandoff.  The exact V2
    // certificate and request outcome must survive after the recovery marker
    // itself is no longer physically retained, because B/C still need the
    // fleet-level historical proof to consume their handoffs without a second
    // V2 proposal.
    crate::consensus::store::test_support::trigger_consensus_snapshot_for_test(
        &stores[finalized_index],
    )
    .await
    .expect("capture actual post-recovery OpenRaft snapshot");
    let snapshot_deadline = Instant::now() + RECOVERY_CAMPAIGN_TRANSITION_TIMEOUT;
    loop {
        match crate::consensus::store::test_support::trigger_consensus_log_purge_through_for_test(
            &stores[finalized_index],
            finalize_log_id.index,
        )
        .await
        {
            Ok(()) => break,
            // `snapshot()` completes after scheduling the engine snapshot;
            // wait only for that already-requested snapshot to reach local
            // metrics before asking the engine to purge through it.
            Err(error) if error == "test consensus purge is not covered by a local snapshot" => {
                assert!(
                    Instant::now() < snapshot_deadline,
                    "actual post-recovery OpenRaft snapshot did not cover recovery finalization: {:?}",
                    crate::consensus::store::test_support::consensus_local_durable_progress_for_test(
                        &stores[finalized_index]
                    )
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => panic!("trigger actual post-recovery OpenRaft purge: {error}"),
        }
    }
    crate::consensus::store::test_support::wait_for_consensus_log_purge_beyond_for_test(
        &stores[finalized_index],
        finalize_log_id.index.saturating_sub(1),
    )
    .await
    .expect("purge actual post-recovery OpenRaft log beyond recovery finalization");
    let snapshot_purged_conn = Connection::open(&replicas[finalized_index].database_path)
        .expect("open consumed voter after snapshot and purge");
    let snapshot = consensus::read_current_snapshot_sync(&snapshot_purged_conn, campaign_identity)
        .expect("read actual persisted snapshot metadata")
        .expect("actual post-recovery snapshot metadata");
    let snapshot_log_id = snapshot.0.last_log_id.expect("actual snapshot cut log ID");
    assert!(
        super::sqlite::full_log_id_not_after(&finalize_log_id, &snapshot_log_id),
        "actual snapshot cut must be a full-LogId descendant of the recovery finalization"
    );
    let purged_log_id = consensus::read_purged_sync(&snapshot_purged_conn, campaign_identity)
        .expect("read actual persisted purge floor")
        .expect("actual post-recovery purge floor");
    assert!(
        super::sqlite::full_log_id_not_after(&finalize_log_id, &purged_log_id),
        "actual purge must be a full-LogId descendant of the recovery finalization"
    );
    let marker_count: i64 = snapshot_purged_conn
        .query_row(
            "SELECT COUNT(*) FROM consensus_log WHERE log_index = ?1",
            [i64::try_from(finalize_log_id.index).expect("finalize log index fits SQLite")],
            |row| row.get(0),
        )
        .expect("count physically retained recovery marker");
    assert_eq!(
        marker_count, 0,
        "actual purge must remove the historical recovery marker row"
    );
    let snapshot_certificate: (Vec<u8>, Vec<u8>) = snapshot_purged_conn
        .query_row(
            "SELECT finalize_log_id_json, finalize_entry_json FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read V2 certificate after marker purge");
    let snapshot_outcome: (Vec<u8>, Vec<u8>) = snapshot_purged_conn
        .query_row(
            "SELECT payload_digest, response_json FROM consensus_request_outcomes WHERE request_id = ?1",
        [recovery_request_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read V2 outcome after marker purge");
    let snapshot_outcome_count: i64 = snapshot_purged_conn
        .query_row(
            "SELECT COUNT(*) FROM consensus_request_outcomes WHERE request_id = ?1",
            [recovery_request_id.as_slice()],
            |row| row.get(0),
        )
        .expect("count V2 outcomes after marker purge");
    assert_eq!(
        (snapshot_certificate, snapshot_outcome),
        v2_evidence[finalized_index],
        "snapshot and purge must preserve the exact V2 certificate and outcome"
    );
    assert_eq!(
        snapshot_outcome_count, 1,
        "snapshot and purge must preserve exactly one V2 outcome"
    );
    drop(snapshot_purged_conn);

    // A duplicated request ID could be absorbed by `consensus_request_outcomes`
    // after a new log proposal has already been appended. Record the exact
    // retained V2 rows on B/C, not only the singleton outcome, before and
    // after each sequential handoff retry.
    let retained_v2_log_entries = |replica: &RecoveryReplica| {
        let conn = Connection::open(&replica.database_path)
            .expect("open pending voter for exact retained V2 log evidence");
        let mut statement = conn
            .prepare("SELECT log_index, entry_json FROM consensus_log ORDER BY log_index ASC")
            .expect("prepare retained consensus log scan");
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .expect("scan retained consensus log rows");
        let mut exact_v2 = Vec::new();
        for row in rows {
            let (index, encoded) = row.expect("decode retained consensus log row");
            let entry: Entry<SessionRaftTypeConfig> =
                serde_json::from_slice(&encoded).expect("decode retained consensus log entry");
            if matches!(
                entry.payload,
                EntryPayload::Normal(SessionConsensusCommand {
                    intent: SessionMutationIntent::FinalizeOperatorRecoveryV2(_),
                    ..
                })
            ) {
                exact_v2.push((index, encoded));
            }
        }
        exact_v2
    };
    let request_outcome_count = |replica: &RecoveryReplica| {
        let conn = Connection::open(&replica.database_path)
            .expect("open pending voter for V2 outcome count");
        conn.query_row(
            "SELECT COUNT(*) FROM consensus_request_outcomes WHERE request_id = ?1",
            [recovery_request_id.as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .expect("count deterministic V2 outcomes on pending voter")
    };
    let retained_v2_before_retries = replicas
        .iter()
        .map(retained_v2_log_entries)
        .collect::<Vec<_>>();

    for (index, store) in stores.iter().enumerate().take(replicas.len()) {
        if index == finalized_index {
            continue;
        }
        let exact_v2_before_retry = retained_v2_log_entries(&replicas[index]);
        let outcome_count_before_retry = request_outcome_count(&replicas[index]);
        assert_eq!(
            exact_v2_before_retry, retained_v2_before_retries[index],
            "B/C retained V2 evidence changed before its sequential retry"
        );
        assert_eq!(
            outcome_count_before_retry, 1,
            "B/C begins each sequential retry with exactly one V2 outcome"
        );
        assert_eq!(
            manager
                .finalize(
                    &context(),
                    store,
                    &plan,
                    &confirmation,
                    &replicas,
                    backup.path(),
                )
                .await
                .expect("sequential pending-voter finalization retry")
                .state(),
            RecoveryExecutionState::Rejoined
        );
        assert_eq!(
            latch_phase(index),
            consensus::OperatorRecoveryLatchPhase::Consumed,
            "sequential retry must consume only its own handoff"
        );
        assert_eq!(
            retained_v2_log_entries(&replicas[index]),
            exact_v2_before_retry,
            "sequential retry must not append a second exact V2 log proposal"
        );
        assert_eq!(
            request_outcome_count(&replicas[index]),
            outcome_count_before_retry,
            "request-ID dedup must not mask a second V2 proposal on sequential retry"
        );
    }
    let v2_evidence_after = replicas
        .iter()
        .map(|replica| {
            let conn = Connection::open(&replica.database_path)
                .expect("open voter after sequential terminal retries");
            let certificate: (Vec<u8>, Vec<u8>) = conn
                .query_row(
                    "SELECT finalize_log_id_json, finalize_entry_json FROM consensus_operator_recovery WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("re-read exact V2 certificate");
            let outcome: (Vec<u8>, Vec<u8>) = conn
                .query_row(
                    "SELECT payload_digest, response_json FROM consensus_request_outcomes WHERE request_id = ?1",
                    [recovery_request_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("re-read exact deterministic V2 outcome");
            (certificate, outcome)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        v2_evidence_after, v2_evidence,
        "terminal retries must preserve the one deterministic V2 certificate and outcome"
    );

    for store in &stores {
        let report = loop {
            let report = store.probe_durable_readiness().await;
            if report.is_ready() {
                break report;
            }
            assert!(
                Instant::now() < deadline,
                "campaign member did not clear recovery readiness fence: {report:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert!(report.is_ready());
    }
    for (index, replica) in replicas.iter().enumerate() {
        assert_eq!(
            latch_phase(index),
            consensus::OperatorRecoveryLatchPhase::Consumed,
            "every terminal handoff must be consumed before readiness is open"
        );
        let direct = crate::sqlite::ops::get_raw_sync(
            &Connection::open(&replica.database_path)
                .expect("open consumed voter raw durable canary"),
            &post_recovery_key,
        )
        .expect("read consumed voter durable canary directly")
        .expect("post-recovery canary on every consumed voter");
        assert_eq!(
            direct, source_canary,
            "every consumed voter must retain the exact replicated canary row"
        );
    }

    let recovered = EncryptingSessionBackend::new(
        Arc::new(stores[0].clone()),
        provider.clone(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_proof_without_a_consumed_voter_keeps_pending_suffix_strict() {
    let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
    let temp = tempfile::tempdir().expect("temporary directory");
    let backup = private_tempdir();
    let ids = [
        replica_id("strict-terminal-replica-a"),
        replica_id("strict-terminal-replica-b"),
        replica_id("strict-terminal-replica-c"),
    ];
    let mut replicas = vec![
        create_legacy_replica(temp.path(), ids[0].clone(), 11),
        create_legacy_replica(temp.path(), ids[1].clone(), 23),
        create_legacy_replica(temp.path(), ids[2].clone(), 37),
    ];
    let descriptors = ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            QuorumReplicaDescriptor::new(
                id.clone(),
                ReplicaEndpoint::new(format!("strict-terminal-{index}.invalid"), 7443)
                    .expect("strict terminal endpoint"),
                ReplicaTlsIdentity::new(format!("spiffe://test/session/strict-terminal-{index}"))
                    .expect("strict terminal TLS identity"),
                ReplicaFailureDomain::new(format!("strict-terminal-zone-{index}"))
                    .expect("strict terminal failure domain"),
                ReplicaBackingIdentity::new(format!("strict-terminal-disk-{index}"))
                    .expect("strict terminal backing identity"),
            )
        })
        .collect::<Vec<_>>();
    let cluster =
        SessionConsensusClusterId::new("strict-terminal-recovery-campaign").expect("cluster");
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
    let manager = recovery(AllowRecovery);
    let plan = manager
        .plan(
            &context(),
            campaign_identity,
            node_set_for(campaign_identity, &ids),
            &replicas,
            &ids[0],
            &ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("strict-terminal whole-fleet plan");
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
        .expect("install strict-terminal campaign checkpoint");

    let topologies = ids
        .iter()
        .map(|id| {
            ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                id.clone(),
                descriptors.clone(),
                campaign_identity,
            ))
            .expect("strict-terminal topology")
        })
        .collect::<Vec<_>>();
    let node_ids = topologies
        .iter()
        .map(|topology| {
            topology
                .local_consensus_node_id()
                .expect("strict-terminal node ID")
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
            SqliteSessionBackend::open(&replica.database_path)
                .expect("strict-terminal campaign backend")
        })
        .collect::<Vec<_>>();
    let mut stores = Vec::new();
    for index in 0..ids.len() {
        let peers = (0..ids.len())
            .filter(|target| *target != index)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(index, target))
                    .expect("strict-terminal peer path")
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
            .expect("open strict-terminal campaign node"),
        );
    }
    for ((_, target), path) in &paths {
        path.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize strict-terminal campaign membership");
    }

    let deadline = Instant::now() + RECOVERY_CAMPAIGN_TRANSITION_TIMEOUT;
    loop {
        let mut interrupted = false;
        for store in &stores {
            match manager
                .finalize_with_failpoint(
                    &context(),
                    store,
                    &plan,
                    &confirmation,
                    &replicas,
                    backup.path(),
                    RecoveryFinalizeFailpoint::AfterTerminalizingSidecars(1),
                )
                .await
            {
                Err(RecoveryError::InjectedFailure) => {
                    interrupted = true;
                    break;
                }
                Err(RecoveryError::ConsensusUnavailable) => {}
                result => panic!("unexpected strict-terminal initial result: {result:?}"),
            }
        }
        if interrupted {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "strict-terminal campaign did not reach the publication failpoint"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let expected_latch = consensus::OperatorRecoveryLatch {
        identity: campaign_identity,
        recovery_epoch: plan.next_recovery_epoch(),
        plan_digest: plan.plan_digest().as_bytes(),
        audit_pending: false,
    };
    let latch_phase = |index: usize| {
        let database = File::open(&replicas[index].database_path)
            .expect("open strict-terminal descriptor for latch phase");
        consensus::operator_recovery_latch_phase_sync(
            &replicas[index].database_path,
            expected_latch,
            &database,
            None,
        )
        .expect("classify strict-terminal descriptor-bound latch")
    };
    assert_eq!(
        latch_phase(0),
        consensus::OperatorRecoveryLatchPhase::PendingHandoff
    );
    assert_eq!(
        latch_phase(1),
        consensus::OperatorRecoveryLatchPhase::Active
    );
    assert_eq!(
        latch_phase(2),
        consensus::OperatorRecoveryLatchPhase::Active
    );
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read strict-terminal workflow"),
        RecoveryExecutionState::Rejoined,
        "the common terminal proof is durably recorded before publication"
    );

    // With proof + Pending/Active and no suffix, retry reaches the same
    // publication seam again. This proves that the zero-Consumed fleet is
    // strict but resumable, rather than being rejected merely because proof
    // publication was interrupted.
    assert_eq!(
        manager
            .finalize_with_failpoint(
                &context(),
                &stores[0],
                &plan,
                &confirmation,
                &replicas,
                backup.path(),
                RecoveryFinalizeFailpoint::AfterTerminalizingSidecars(1),
            )
            .await,
        Err(RecoveryError::InjectedFailure)
    );
    assert_eq!(
        latch_phase(0),
        consensus::OperatorRecoveryLatchPhase::PendingHandoff
    );
    assert_eq!(
        latch_phase(1),
        consensus::OperatorRecoveryLatchPhase::Active
    );
    assert_eq!(
        latch_phase(2),
        consensus::OperatorRecoveryLatchPhase::Active
    );

    // PendingHandoff is the closed public-ingress state. Do not probe it
    // through a public store API here: that API deliberately owns terminal
    // handoff consumption. Instead, bypass that boundary only through the
    // internal state-machine seam to model a syntactically valid later Normal
    // that a crash/corruption could leave on the pending replica. The exact
    // V2 recovery proof must reject this strict suffix on finalization retry.
    let pending_conn = Connection::open(&replicas[0].database_path)
        .expect("open pending voter for internal Normal injection");
    let finalize_log_id = consensus::read_operator_recovery_sync(&pending_conn, campaign_identity)
        .expect("read pending voter recovery state")
        .finalize_log_id
        .expect("read pending voter finalization LogId");
    let injected = Entry::<SessionRaftTypeConfig> {
        log_id: LogId::new(
            finalize_log_id.leader_id,
            finalize_log_id.index.saturating_add(1),
        ),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: campaign_identity,
            request_id: SessionConsensusRequestId::from_bytes([0xC1; 16]),
            logical_time: Timestamp::now_utc(),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        }),
    };
    consensus::append_logs_sync(
        &pending_conn,
        campaign_identity,
        std::slice::from_ref(&injected),
    )
    .expect("append syntactically valid pending-voter Normal");
    consensus::apply_entries_sync(
        &pending_conn,
        campaign_identity,
        &BackendCapabilities::all_enabled(),
        vec![injected],
    )
    .expect("apply syntactically valid pending-voter Normal through internal seam");
    drop(pending_conn);

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
            .await,
        Err(RecoveryError::BackupCorrupt)
    );
    assert_eq!(
        latch_phase(0),
        consensus::OperatorRecoveryLatchPhase::PendingHandoff,
        "corrupt strict retry must not release the pending voter"
    );
    assert_eq!(
        latch_phase(1),
        consensus::OperatorRecoveryLatchPhase::Active,
        "corrupt strict retry must not release the active voter"
    );
    assert_eq!(
        latch_phase(2),
        consensus::OperatorRecoveryLatchPhase::Active,
        "corrupt strict retry must not release any active voter"
    );
    let recovery_request_id = plan.plan_digest().as_bytes()[..16].to_vec();
    for replica in &replicas {
        let conn = Connection::open(&replica.database_path)
            .expect("open strict-terminal voter after rejected retry");
        let outcome_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM consensus_request_outcomes WHERE request_id = ?1",
                [recovery_request_id.as_slice()],
                |row| row.get(0),
            )
            .expect("count strict-terminal V2 outcomes");
        assert_eq!(
            outcome_count, 1,
            "corrupt retry must not propose a second deterministic V2 command"
        );
    }
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
    let recovery_replica = RecoveryReplica::from_topology(
        &topology,
        replica_id("recovery-finalize-singleton"),
        database.clone(),
        snapshots.clone(),
    )
    .expect("bind singleton recovery replica");
    let backend = SqliteSessionBackend::open(&database).expect("SQLite backend");
    let store = ConsensusSessionStore::open(topology.clone(), backend, &snapshots, BTreeMap::new())
        .await
        .expect("open singleton store");
    store
        .initialize_cluster()
        .await
        .expect("initialize singleton cluster");
    let snapshot_last_log = {
        let conn = Connection::open(&database).expect("open initialized singleton database");
        consensus::read_applied_sync(&conn, store_identity)
            .expect("read initialized applied LogId")
            .expect("initialized singleton has an applied membership LogId")
    };
    let snapshot_name = "snapshot-00000000-0000-4000-8000-00000000f1a1.opc";
    let snapshot_bytes = install_dynamic_current_snapshot_fixture_for_identity(
        &recovery_replica,
        store_identity,
        snapshot_last_log,
        snapshot_name,
        "recovery-finalize-terminal-snapshot",
        b"recovery finalization terminal snapshot envelope",
    );
    let manager = recovery(AllowRecovery);
    let expected_members = BTreeSet::from([node]);
    let source_evidence = inspect_replica(InspectionInput {
        key: &manager.integrity_key,
        replica: &recovery_replica,
        identity: store_identity,
        expected_members: &expected_members,
        limits: RecoveryLimits::default(),
    })
    .expect("inspect singleton recovery replica");
    let replicas = std::slice::from_ref(&recovery_replica);
    let wrong_plan = sealed_test_plan(&manager, identity(), node, source_evidence.clone());
    let wrong_confirmation = RecoveryConfirmation::verified(&wrong_plan);
    assert_eq!(
        manager
            .finalize(
                &context(),
                &store,
                &wrong_plan,
                &wrong_confirmation,
                replicas,
                backup.path(),
            )
            .await,
        Err(RecoveryError::WrongCluster)
    );
    let plan = sealed_test_plan(&manager, store_identity, node, source_evidence);
    let confirmation = RecoveryConfirmation::verified(&plan);
    // A unit fixture cannot elect a live Openraft leader after an offline
    // replacement, so make the exact pending intent and descriptor-bound
    // workflow durable directly.  The finalization path still pins, checks,
    // commits, revalidates and terminalizes this real database.
    let pending = Connection::open(&database).expect("open pending recovery database");
    consensus::mark_operator_recovery_pending_sync(
        &pending,
        store_identity,
        plan.next_recovery_epoch(),
        plan.plan_digest().as_bytes(),
    )
    .expect("persist pending recovery intent");
    drop(pending);
    prepare_test_workflow_with_current_snapshot(
        &manager.integrity_key,
        &plan,
        backup.path(),
        RecoveryExecutionState::AwaitingEpochCommit,
        &recovery_replica,
    )
    .expect("prepare descriptor-bound awaiting workflow");

    assert_eq!(
        manager
            .finalize_with_failpoint(
                &context(),
                &store,
                &plan,
                &confirmation,
                replicas,
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
                replicas,
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
                replicas,
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
                replicas,
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
        .finalize(
            &context(),
            &store,
            &plan,
            &confirmation,
            replicas,
            backup.path(),
        )
        .await
        .expect("resume finalization to rejoin");
    assert_eq!(completed.state(), RecoveryExecutionState::Rejoined);
    assert_eq!(
        resume_execution_state(&manager.integrity_key, &plan, backup.path())
            .expect("read completed workflow"),
        RecoveryExecutionState::Rejoined
    );
    drop(store);

    // Successful local finalization has already consumed its durable terminal
    // sidecar. The consumed tombstone intentionally has no snapshot locator:
    // normal snapshot publication (and even a temporary selected-file change)
    // cannot turn an idempotent local recovery retry back into Pending.
    let snapshot_path = snapshots.join(snapshot_name);
    std::fs::write(&snapshot_path, b"tampered terminal snapshot")
        .expect("tamper selected terminal snapshot");
    assert!(
        SqliteSessionBackend::open(&database).is_ok(),
        "a consumed terminal must not retain a mutable snapshot locator"
    );
    std::fs::write(&snapshot_path, &snapshot_bytes).expect("restore exact terminal snapshot");

    // This is the production backend/core restart boundary after local
    // consumption. It remains open without fabricating a second pending
    // handoff; snapshot envelope handoff validation is exercised by the
    // dedicated pending-terminal storage tests.
    let reopened = SqliteSessionBackend::open(&database)
        .expect("backend classifies the restored consumed terminal");
    let core = consensus::SqliteConsensusCore::initialize(
        &reopened,
        snapshots.clone(),
        store_identity,
        expected_members,
        topology_member_bindings(&topology),
        ConsensusAuthorityProfile::Dynamic,
        None,
    )
    .await
    .expect("initialize core after consumed terminal");
    assert!(
        !core.terminal_recovery_handoff_pending_for_test(),
        "a consumed terminal must not recreate a pending handoff"
    );
    drop(core);
    drop(reopened);

    // The terminal sidecar is bound to the descriptor finalization held.  A
    // same-byte pathname replacement after the terminal transition must not
    // inherit the removed-ready state on a later process restart.
    let replacement = temp.path().join("finalize-replacement.sqlite");
    std::fs::copy(&database, &replacement).expect("copy byte-identical replacement database");
    std::fs::rename(&replacement, &database).expect("swap database after terminal latch write");
    assert!(
        SqliteSessionBackend::open(&database).is_err(),
        "terminal latch must fail closed when its database pathname is substituted"
    );
}
