use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use opc_config_model::{
    AuthStrength, RequestId, TransportType, TrustedPrincipal, WorkloadIdentity,
};
use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId, Membership};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditOutcome, AuditSink};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use rusqlite::{params, Connection};
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
    Generation, OwnerId, ReplicationEntry, ReplicationOp, SessionBackend, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRpcHandler, SessionConsensusWireRequest,
    SessionConsensusWireResponse, SessionKey, SessionKeyType, SessionLeaseManager,
    SqliteSessionBackend, StateClass, StateType, StoredSessionRecord, SystemClock,
};

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
        tx_id: format!("legacy-recovery-{sequence}"),
        op: ReplicationOp::Batch { ops: Vec::new() },
        timestamp,
    };
    let conn = Connection::open(&replica.database_path).expect("open legacy replication fixture");
    conn.execute(
        "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![
            i64::try_from(sequence).expect("sequence"),
            entry.tx_id,
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
        assert_eq!(objects.len(), 17);
        assert!(objects.iter().all(|(kind, _)| kind == "table"));
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
        .execute("UPDATE key_fences SET fence = 6", [])
        .expect("change source");
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
        stable_id: Bytes::from_static(b"latched-legacy-probe"),
    };
    assert!(matches!(
        restarted_legacy.get(&probe_key).await,
        Err(crate::StoreError::CapabilityNotSupported(_))
    ));
    drop(restarted_legacy);

    Connection::open(&replicas[0].database_path)
        .expect("restore source")
        .execute("UPDATE key_fences SET fence = 5", [])
        .expect("restore source");
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
            tx_id: "sequence-test".to_string(),
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
    let overflow_plan = manager
        .plan(
            &context(),
            identity(),
            node_set(&overflow_ids),
            &overflow_replicas,
            &overflow_ids[0],
            &overflow_ids,
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint,
            RecoveryLimits::default(),
        )
        .expect("overflow plan remains inspectable");
    let overflow_confirmation = RecoveryConfirmation::legacy(
        &overflow_plan,
        RecoveryConfirmation::required_legacy_acknowledgement(),
    );
    assert_eq!(
        manager.execute(
            &context(),
            &overflow_plan,
            &overflow_confirmation,
            &overflow_replicas,
            overflow_backup.path(),
            RecoveryLimits::default(),
        ),
        Err(RecoveryError::WorkLimitExceeded)
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
    consensus::append_logs_sync(&conn, identity(), members, std::slice::from_ref(&entry))
        .expect("append membership entry");
    consensus::save_committed_sync(&conn, identity(), Some(log_id))
        .expect("save committed membership");
    consensus::apply_entries_sync(
        &conn,
        identity(),
        members,
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
        ("view", "CREATE VIEW hostile_view AS SELECT * FROM session_records;"),
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
            Err(crate::StoreError::BackendUnavailable(_))
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
        stable_id: Bytes::from_static(b"legacy-protected-session"),
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

    let deadline = Instant::now() + Duration::from_secs(12);
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
        assert!(Instant::now() < deadline, "campaign did not elect a leader");
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
        stable_id: Bytes::from_static(b"recovery-epoch-session"),
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
