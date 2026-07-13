use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hmac::Mac;
use opc_consensus::engine::LogId;
use rusqlite::backup::Backup;
use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    plan_mac, RecoveryDecisionBasis, RecoveryDigest, RecoveryError, RecoveryExecutionState,
    RecoveryIntegrityKey, RecoveryLimits, RecoveryPlan, RecoveryReplica, RecoveryReplicaEvidence,
    RecoveryReplicaFormat,
};
use crate::consensus::{
    SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId, SessionConsensusIdentity,
    SessionConsensusNodeId, SESSION_CONSENSUS_SCHEMA_VERSION,
};
use crate::sqlite::{consensus, ops};
use crate::ReplicationEntry;

const PATH_MAX_BYTES: usize = 4_096;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_millis(100);
const SNAPSHOT_FOOTER_MAGIC: &[u8; 8] = b"OPCSNP01";
const SNAPSHOT_FOOTER_BYTES: u64 = 8 + 8 + 32;
const PLAN_MAC_DOMAIN: &[u8] = b"openpacketcore/session-recovery/plan-seal/v1\0";
const WORKFLOW_MAC_DOMAIN: &[u8] = b"openpacketcore/session-recovery/workflow/v1\0";
const BACKUP_MAC_DOMAIN: &[u8] = b"openpacketcore/session-recovery/backup/v1\0";
const CURRENT_BRANCH_DOMAIN: &[u8] = b"openpacketcore/session-recovery/current-branch/v1\0";
const LEGACY_BRANCH_DOMAIN: &[u8] = b"openpacketcore/session-recovery/legacy-branch/v1\0";
const PATH_BINDING_DOMAIN: &[u8] = b"openpacketcore/session-recovery/path-binding/v1\0";
const FILE_IDENTITY_DOMAIN: &[u8] = b"openpacketcore/session-recovery/file-identity/v1\0";
const LOGICAL_STATE_DOMAIN: &[u8] = b"openpacketcore/session-recovery/logical-state/v1\0";
const FILE_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-recovery/file/v1\0";
const WORKFLOW_VERSION: u16 = 2;
const MAX_CURRENT_SCHEMA_OBJECTS: usize = 17;
const MAX_SCHEMA_SQL_BYTES: usize = 16_384;

pub(super) struct InspectionInput<'a> {
    pub(super) key: &'a RecoveryIntegrityKey,
    pub(super) replica: &'a RecoveryReplica,
    pub(super) identity: SessionConsensusIdentity,
    pub(super) expected_members: &'a BTreeSet<SessionConsensusNodeId>,
    pub(super) limits: RecoveryLimits,
}

pub(super) struct ResetInput<'a> {
    pub(super) key: &'a RecoveryIntegrityKey,
    pub(super) plan: &'a RecoveryPlan,
    pub(super) source: &'a RecoveryReplica,
    pub(super) replicas: &'a [RecoveryReplica],
    pub(super) targets: &'a [&'a RecoveryReplica],
    pub(super) backup_root: &'a Path,
    pub(super) limits: RecoveryLimits,
    #[cfg(test)]
    pub(super) failpoint: Option<RecoveryFailpoint>,
}

#[cfg(test)]
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecoveryFailpoint {
    AfterTargetBackupCopy,
    AfterCheckpointCopy,
    AfterBackup,
    AfterStagedCopy,
    AfterSnapshotInstall,
    AfterDatabaseTemporaryPrepared,
    AfterDatabaseInstall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkflowRecord {
    version: u16,
    plan_digest: RecoveryDigest,
    source_branch_digest: RecoveryDigest,
    target_tokens: Vec<RecoveryDigest>,
    state: RecoveryExecutionState,
    audit_resume_state: Option<RecoveryExecutionState>,
    rejoin_proven: bool,
    checkpoint_database_digest: Option<RecoveryDigest>,
    checkpoint_snapshot_digest: Option<RecoveryDigest>,
    staged_database_digest: Option<RecoveryDigest>,
    source_snapshot_name: Option<String>,
    checkpoint_progress: FileProgress,
    staged_progress: FileProgress,
    target_backups: BTreeMap<String, FileProgress>,
    target_installs: BTreeMap<String, TargetInstallState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FileProgress {
    Pending,
    Copying,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TargetInstallState {
    Pending,
    SnapshotCopying,
    SnapshotInstalled,
    DatabaseCopying,
    DatabaseInstalled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedWorkflowRecord {
    record: WorkflowRecord,
    mac: RecoveryDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupFileEvidence {
    role: String,
    byte_length: u64,
    digest: RecoveryDigest,
    original_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupManifestBody {
    version: u16,
    plan_digest: RecoveryDigest,
    target_token: RecoveryDigest,
    files: Vec<BackupFileEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedBackupManifest {
    body: BackupManifestBody,
    mac: RecoveryDigest,
}

struct CanonicalReplicaPaths {
    database: PathBuf,
    snapshots: PathBuf,
}

struct InspectionBudget {
    limits: RecoveryLimits,
    started: Instant,
    rows: u64,
    value_bytes: u64,
}

#[cfg(unix)]
struct ReplicaExecutionLock {
    path: PathBuf,
    _file: nix::fcntl::Flock<File>,
    device: u64,
    inode: u64,
}

impl InspectionBudget {
    fn new(limits: RecoveryLimits) -> Self {
        Self {
            limits,
            started: Instant::now(),
            rows: 0,
            value_bytes: 0,
        }
    }

    fn check(&self) -> Result<(), RecoveryError> {
        if self.started.elapsed() >= self.limits.max_duration() {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        Ok(())
    }

    fn consume_row(&mut self) -> Result<(), RecoveryError> {
        self.check()?;
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if self.rows > self.limits.max_rows() {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        Ok(())
    }

    fn consume_value(&mut self, length: usize) -> Result<(), RecoveryError> {
        self.check()?;
        let length = u64::try_from(length).map_err(|_| RecoveryError::WorkLimitExceeded)?;
        if length > self.limits.max_value_bytes() {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        self.value_bytes = self
            .value_bytes
            .checked_add(length)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if self.value_bytes > self.limits.max_total_value_bytes() {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        Ok(())
    }
}

fn inspection_sql_error(error: rusqlite::Error, budget: &InspectionBudget) -> RecoveryError {
    if budget.started.elapsed() >= budget.limits.max_duration()
        || matches!(
            error,
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ffi::ErrorCode::OperationInterrupted,
                    ..
                },
                _
            )
        )
    {
        RecoveryError::WorkLimitExceeded
    } else {
        RecoveryError::CorruptReplica
    }
}

pub(super) fn seal_plan(
    key: &RecoveryIntegrityKey,
    plan_digest: RecoveryDigest,
    encoded: &[u8],
) -> Result<RecoveryDigest, RecoveryError> {
    Ok(RecoveryDigest::from_bytes(plan_mac(
        key,
        PLAN_MAC_DOMAIN,
        &[&plan_digest.as_bytes(), encoded],
    )?))
}

pub(super) fn verify_plan_seal(
    key: &RecoveryIntegrityKey,
    plan_digest: RecoveryDigest,
    encoded: &[u8],
    seal: RecoveryDigest,
) -> Result<(), RecoveryError> {
    let mut verifier = hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| RecoveryError::StalePlan)?;
    verifier.update(PLAN_MAC_DOMAIN);
    for part in [&plan_digest.as_bytes()[..], encoded] {
        verifier.update(
            &u64::try_from(part.len())
                .map_err(|_| RecoveryError::StalePlan)?
                .to_be_bytes(),
        );
        verifier.update(part);
    }
    verifier
        .verify_slice(&seal.as_bytes())
        .map_err(|_| RecoveryError::StalePlan)?;
    Ok(())
}

pub(super) fn inspect_replica(
    input: InspectionInput<'_>,
) -> Result<RecoveryReplicaEvidence, RecoveryError> {
    let mut budget = InspectionBudget::new(input.limits);
    let paths = canonical_replica_paths(input.replica, false)?;
    let path_binding = recovery_path_binding(input.key, &paths)?;
    let metadata = fs::metadata(&paths.database).map_err(|_| RecoveryError::DatabaseUnavailable)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > input.limits.max_database_bytes()
    {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    let file_identity = recovery_file_identity(input.key, &metadata)?;
    let conn = open_read_only(&paths.database)?;
    let started = budget.started;
    let max_duration = input.limits.max_duration();
    conn.progress_handler(1_000, Some(move || started.elapsed() >= max_duration));
    validate_database_snapshot(&conn, &budget)?;
    if table_exists(&conn, "consensus_identity")? {
        inspect_current(
            input,
            &conn,
            paths,
            path_binding,
            file_identity,
            &mut budget,
        )
    } else {
        inspect_legacy(input, &conn, path_binding, file_identity, &mut budget)
    }
}

pub(super) fn replica_has_recovery_latch(
    replica: &RecoveryReplica,
    identity: SessionConsensusIdentity,
) -> Result<bool, RecoveryError> {
    let paths = canonical_replica_paths(replica, false)?;
    match consensus::read_operator_recovery_latch_sync(&paths.database)
        .map_err(|_| RecoveryError::CorruptReplica)?
    {
        Some(latch) if latch.identity == identity => Ok(true),
        Some(_) => Err(RecoveryError::WrongCluster),
        None => Ok(false),
    }
}

fn inspect_current(
    input: InspectionInput<'_>,
    conn: &Connection,
    paths: CanonicalReplicaPaths,
    path_binding: RecoveryDigest,
    file_identity: RecoveryDigest,
    budget: &mut InspectionBudget,
) -> Result<RecoveryReplicaEvidence, RecoveryError> {
    budget.check()?;
    preflight_current_tables(conn, budget)?;
    validate_exact_recovery_schema(conn, false)?;
    let (schema_version, cluster, configuration, epoch): (i64, Vec<u8>, Vec<u8>, i64) = conn
        .query_row(
            "SELECT schema_version, cluster_id, configuration_id, configuration_epoch FROM consensus_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if schema_version != i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) {
        return Err(RecoveryError::CorruptReplica);
    }
    let cluster: [u8; 32] = cluster
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let configuration: [u8; 32] = configuration
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let epoch = u64::try_from(epoch)
        .ok()
        .and_then(|value| SessionConsensusConfigurationEpoch::new(value).ok())
        .ok_or(RecoveryError::CorruptReplica)?;
    let stored_identity = SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::from_bytes(cluster),
        SessionConsensusConfigurationId::from_bytes(configuration),
        epoch,
    );
    if stored_identity != input.identity {
        return Err(RecoveryError::WrongCluster);
    }
    consensus::read_membership_sync(conn, stored_identity, input.expected_members)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    validate_sealed_records(conn, budget)?;
    let committed = consensus::read_committed_sync(conn, stored_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let applied = consensus::read_applied_sync(conn, stored_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let purged = consensus::read_purged_sync(conn, stored_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let last_log = consensus::last_log_sync(conn, stored_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    validate_log_floors(
        committed.as_ref(),
        applied.as_ref(),
        purged.as_ref(),
        last_log.as_ref(),
    )?;
    let recovery = consensus::read_operator_recovery_sync(conn, stored_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let replication_head = validate_replication_sequence_domain(
        conn,
        budget,
        recovery.watch_cursor_invalidation_floor,
    )?;
    let (application_sequence, watch_sequence): (i64, i64) = conn
        .query_row(
            "SELECT application_sequence, watch_sequence FROM consensus_machine WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let application_sequence =
        u64::try_from(application_sequence).map_err(|_| RecoveryError::CorruptReplica)?;
    let watch_sequence =
        u64::try_from(watch_sequence).map_err(|_| RecoveryError::CorruptReplica)?;
    if watch_sequence != replication_head {
        return Err(RecoveryError::CorruptReplica);
    }
    let branch_digest = committed_branch_digest(
        conn,
        stored_identity,
        input.expected_members,
        committed.as_ref(),
        &paths.snapshots,
        budget,
        recovery.recovery_epoch,
        recovery.pending_epoch,
        recovery.pending_plan_digest,
        recovery.watch_cursor_invalidation_floor,
    )?;
    let fence_high_water = consensus::observed_fence_high_water_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let credential_high_water = consensus::observed_credential_high_water_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let logical_state_digest = hash_logical_state(conn, budget)?;
    budget.check()?;
    Ok(RecoveryReplicaEvidence {
        replica_token: super::replica_token(input.key, &input.replica.replica_id)?,
        backing_identity: RecoveryDigest::from_bytes(input.replica.backing_identity.fingerprint()),
        path_binding,
        file_identity,
        format: RecoveryReplicaFormat::Openraft,
        cluster_digest: Some(RecoveryDigest::from_bytes(cluster)),
        configuration_digest: Some(RecoveryDigest::from_bytes(configuration)),
        configuration_epoch: Some(epoch.get()),
        recovery_epoch: recovery.recovery_epoch,
        pending_recovery_epoch: recovery.pending_epoch,
        pending_plan_digest: recovery.pending_plan_digest.map(RecoveryDigest::from_bytes),
        watch_cursor_invalidation_floor: recovery.watch_cursor_invalidation_floor,
        application_sequence,
        watch_sequence,
        committed_index: committed.as_ref().map(|log_id| log_id.index),
        applied_index: applied.as_ref().map(|log_id| log_id.index),
        local_head_index: last_log.as_ref().map(|log_id| log_id.index),
        branch_digest,
        fence_high_water,
        credential_high_water,
        logical_state_digest,
    })
}

fn preflight_current_tables(
    conn: &Connection,
    budget: &InspectionBudget,
) -> Result<(), RecoveryError> {
    let mut total_bytes = 0_u64;
    for query in [
        "SELECT COUNT(*), COALESCE(MAX(MAX(length(cluster_id), length(configuration_id))), 0), COALESCE(SUM(length(cluster_id) + length(configuration_id)), 0) FROM consensus_identity",
        "SELECT COUNT(*), COALESCE(MAX(length(membership_json)), 0), COALESCE(SUM(length(membership_json)), 0) FROM consensus_membership",
        "SELECT COUNT(*), COALESCE(MAX(length(vote_json)), 0), COALESCE(SUM(length(vote_json)), 0) FROM consensus_vote",
        "SELECT COUNT(*), COALESCE(MAX(length(log_id_json)), 0), COALESCE(SUM(length(log_id_json)), 0) FROM consensus_committed",
        "SELECT COUNT(*), COALESCE(MAX(length(log_id_json)), 0), COALESCE(SUM(length(log_id_json)), 0) FROM consensus_purged",
        "SELECT COUNT(*), COALESCE(MAX(length(entry_json)), 0), COALESCE(SUM(length(entry_json)), 0) FROM consensus_log",
        "SELECT COUNT(*), COALESCE(MAX(length(log_id_json)), 0), COALESCE(SUM(length(log_id_json)), 0) FROM consensus_applied",
        "SELECT COUNT(*), COALESCE(MAX(MAX(length(meta_json), length(file_name), length(checksum))), 0), COALESCE(SUM(length(meta_json) + length(file_name) + length(checksum)), 0) FROM consensus_snapshot",
        "SELECT COUNT(*), COALESCE(MAX(MAX(length(request_id), length(payload_digest), length(response_json))), 0), COALESCE(SUM(length(request_id) + length(payload_digest) + length(response_json)), 0) FROM consensus_request_outcomes",
    ] {
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(query, [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| inspection_sql_error(error, budget))?;
        let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
        let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
        let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
        total_bytes = total_bytes
            .checked_add(total)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if count > budget.limits.max_rows()
            || maximum > budget.limits.max_value_bytes()
            || total_bytes > budget.limits.max_total_value_bytes()
        {
            return Err(RecoveryError::WorkLimitExceeded);
        }
    }
    if table_exists(conn, "consensus_operator_recovery")? {
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(MAX(length(last_plan_digest), COALESCE(length(pending_plan_digest), 0))), 0), COALESCE(SUM(length(last_plan_digest) + COALESCE(length(pending_plan_digest), 0)), 0) FROM consensus_operator_recovery",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| inspection_sql_error(error, budget))?;
        let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
        let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
        let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
        total_bytes = total_bytes
            .checked_add(total)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if count > budget.limits.max_rows()
            || maximum > budget.limits.max_value_bytes()
            || total_bytes > budget.limits.max_total_value_bytes()
        {
            return Err(RecoveryError::WorkLimitExceeded);
        }
    }
    Ok(())
}

fn validate_log_floors(
    committed: Option<&LogId<SessionConsensusNodeId>>,
    applied: Option<&LogId<SessionConsensusNodeId>>,
    purged: Option<&LogId<SessionConsensusNodeId>>,
    last_log: Option<&LogId<SessionConsensusNodeId>>,
) -> Result<(), RecoveryError> {
    if let (Some(applied), Some(committed)) = (applied, committed) {
        if applied.index > committed.index
            || (applied.index == committed.index && applied != committed)
        {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    if applied.is_some() && committed.is_none() {
        return Err(RecoveryError::CorruptReplica);
    }
    if let (Some(purged), Some(applied)) = (purged, applied) {
        if purged.index > applied.index || (purged.index == applied.index && purged != applied) {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    if let (Some(committed), Some(last_log)) = (committed, last_log) {
        if last_log.index < committed.index {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn committed_branch_digest(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    committed: Option<&LogId<SessionConsensusNodeId>>,
    snapshot_dir: &Path,
    budget: &mut InspectionBudget,
    recovery_epoch: u64,
    pending_epoch: Option<u64>,
    pending_plan_digest: Option<[u8; 32]>,
    watch_cursor_invalidation_floor: u64,
) -> Result<RecoveryDigest, RecoveryError> {
    let mut hasher = Sha256::new();
    hasher.update(CURRENT_BRANCH_DOMAIN);
    hasher.update(identity.cluster_id().as_bytes());
    hasher.update(identity.configuration_id().as_bytes());
    hasher.update(identity.configuration_epoch().get().to_be_bytes());
    hasher.update(recovery_epoch.to_be_bytes());
    hasher.update(watch_cursor_invalidation_floor.to_be_bytes());
    match (pending_epoch, pending_plan_digest) {
        (Some(epoch), Some(digest)) => {
            hasher.update([1]);
            hasher.update(epoch.to_be_bytes());
            hasher.update(digest);
        }
        (None, None) => hasher.update([0]),
        _ => return Err(RecoveryError::CorruptReplica),
    }
    let Some(committed) = committed else {
        hasher.update([0]);
        hash_current_checkpoint(conn, budget, &mut hasher)?;
        return Ok(RecoveryDigest::from_bytes(hasher.finalize().into()));
    };
    hasher.update([1]);
    feed_json(&mut hasher, committed)?;
    let end = committed
        .index
        .checked_add(1)
        .ok_or(RecoveryError::CorruptReplica)?;
    let entries = consensus::read_log_range_sync(
        conn,
        identity,
        expected_members,
        committed.index,
        Some(end),
        Some(1),
    )
    .map_err(|_| RecoveryError::CorruptReplica)?;
    if let Some(entry) = entries.first() {
        if entry.log_id != *committed {
            return Err(RecoveryError::CorruptReplica);
        }
        hasher.update([1]);
        feed_json(&mut hasher, entry)?;
        hash_current_checkpoint(conn, budget, &mut hasher)?;
        return Ok(RecoveryDigest::from_bytes(hasher.finalize().into()));
    }
    let snapshot = consensus::read_current_snapshot_sync(conn, identity, expected_members)
        .map_err(|_| RecoveryError::CorruptReplica)?
        .ok_or(RecoveryError::CorruptReplica)?;
    if snapshot.0.last_log_id.as_ref() != Some(committed) {
        return Err(RecoveryError::CorruptReplica);
    }
    let snapshot_path = snapshot_dir.join(&snapshot.1);
    let observed = verify_snapshot_file(
        &snapshot_path,
        budget.limits.max_snapshot_bytes(),
        Some(budget),
    )?;
    if observed.0 != snapshot.2 || observed.1 != snapshot.3 {
        return Err(RecoveryError::CorruptReplica);
    }
    hasher.update([2]);
    hasher.update(snapshot.2);
    hasher.update(snapshot.3.to_be_bytes());
    feed_json(&mut hasher, &snapshot.0)?;
    hash_current_checkpoint(conn, budget, &mut hasher)?;
    Ok(RecoveryDigest::from_bytes(hasher.finalize().into()))
}

fn hash_current_checkpoint(
    conn: &Connection,
    budget: &mut InspectionBudget,
    hasher: &mut Sha256,
) -> Result<(), RecoveryError> {
    for query in [
        "SELECT * FROM session_records ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM leases ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM key_fences ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM lease_globals ORDER BY key",
        "SELECT * FROM session_replication_log ORDER BY sequence",
        "SELECT * FROM consensus_machine ORDER BY singleton",
        "SELECT * FROM consensus_membership ORDER BY singleton",
        "SELECT * FROM consensus_applied ORDER BY singleton",
        "SELECT * FROM consensus_request_outcomes ORDER BY request_id",
    ] {
        hasher.update(
            u64::try_from(query.len())
                .map_err(|_| RecoveryError::WorkLimitExceeded)?
                .to_be_bytes(),
        );
        hasher.update(query.as_bytes());
        hash_query_rows(conn, query, budget, hasher)?;
    }
    Ok(())
}

fn inspect_legacy(
    input: InspectionInput<'_>,
    conn: &Connection,
    path_binding: RecoveryDigest,
    file_identity: RecoveryDigest,
    budget: &mut InspectionBudget,
) -> Result<RecoveryReplicaEvidence, RecoveryError> {
    validate_legacy_schema(conn)?;
    validate_sealed_records(conn, budget)?;
    validate_replication_sequence_domain(conn, budget, 0)?;
    let branch_digest = hash_legacy_state(conn, budget)?;
    let fence_high_water = consensus::observed_fence_high_water_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let credential_high_water = consensus::observed_credential_high_water_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let logical_state_digest = hash_logical_state(conn, budget)?;
    budget.check()?;
    let local_head_index: Option<i64> = conn
        .query_row(
            "SELECT MAX(sequence) FROM session_replication_log",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let local_head_index = local_head_index
        .map(u64::try_from)
        .transpose()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let sequence_high_water = local_head_index.unwrap_or(0);
    Ok(RecoveryReplicaEvidence {
        replica_token: super::replica_token(input.key, &input.replica.replica_id)?,
        backing_identity: RecoveryDigest::from_bytes(input.replica.backing_identity.fingerprint()),
        path_binding,
        file_identity,
        format: RecoveryReplicaFormat::LegacyUnproven,
        cluster_digest: None,
        configuration_digest: None,
        configuration_epoch: None,
        recovery_epoch: 0,
        pending_recovery_epoch: None,
        pending_plan_digest: None,
        watch_cursor_invalidation_floor: 0,
        application_sequence: sequence_high_water,
        watch_sequence: sequence_high_water,
        committed_index: None,
        applied_index: None,
        local_head_index,
        branch_digest,
        fence_high_water,
        credential_high_water,
        logical_state_digest,
    })
}

fn validate_legacy_schema(conn: &Connection) -> Result<(), RecoveryError> {
    for (table, expected) in [
        (
            "session_records",
            &[
                "tenant",
                "nf_kind",
                "key_type",
                "stable_id",
                "generation",
                "owner",
                "fence",
                "state_class",
                "state_type",
                "expires_at",
                "payload",
                "encoding",
            ][..],
        ),
        (
            "leases",
            &[
                "tenant",
                "nf_kind",
                "key_type",
                "stable_id",
                "active",
                "credential_id",
                "owner",
                "fence",
                "expires_at_unix_ms",
                "guard_expires_at",
            ][..],
        ),
        (
            "key_fences",
            &["tenant", "nf_kind", "key_type", "stable_id", "fence"][..],
        ),
        ("lease_globals", &["key", "val"][..]),
        (
            "session_replication_log",
            &["sequence", "tx_id", "entry_json", "timestamp"][..],
        ),
    ] {
        let mut statement = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|_| RecoveryError::CorruptReplica)?;
        let observed = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|_| RecoveryError::CorruptReplica)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RecoveryError::CorruptReplica)?;
        if observed != expected {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    let has_restore_scan_state = validate_restore_scan_schema_if_present(conn)?;
    let mut expected = BTreeSet::from([
        "key_fences".to_string(),
        "lease_globals".to_string(),
        "leases".to_string(),
        "session_records".to_string(),
        "session_replication_log".to_string(),
    ]);
    if has_restore_scan_state {
        expected.insert("restore_scan_state".to_string());
    }
    let mut statement = conn
        .prepare(
            "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| RecoveryError::CorruptReplica)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if objects.len() != expected.len()
        || objects
            .iter()
            .any(|(kind, name)| kind != "table" || !expected.contains(name))
    {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(())
}

fn validate_restore_scan_schema_if_present(conn: &Connection) -> Result<bool, RecoveryError> {
    if !table_exists(conn, "restore_scan_state")? {
        return Ok(false);
    }
    let mut statement = conn
        .prepare("PRAGMA table_info(restore_scan_state)")
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let observed = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|_| RecoveryError::CorruptReplica)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let legacy = vec![
        (
            0,
            "singleton".to_string(),
            "INTEGER".to_string(),
            0,
            None,
            1,
        ),
        (1, "epoch".to_string(), "BLOB".to_string(), 1, None, 0),
        (2, "revision".to_string(), "INTEGER".to_string(), 1, None, 0),
    ];
    let mut migrated = legacy.clone();
    migrated.push((3, "cursor_key".to_string(), "BLOB".to_string(), 0, None, 0));
    let mut current = legacy.clone();
    current.push((3, "cursor_key".to_string(), "BLOB".to_string(), 1, None, 0));
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'restore_scan_state'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let normalized_sql = normalize_schema_sql(&sql);
    let expected_sql = if observed == legacy {
        normalize_schema_sql(
            r#"
            CREATE TABLE restore_scan_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                revision INTEGER NOT NULL CHECK (revision >= 0)
            )
            "#,
        )
    } else if observed == migrated {
        normalize_schema_sql(
            r#"
            CREATE TABLE restore_scan_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                revision INTEGER NOT NULL CHECK (revision >= 0),
                cursor_key BLOB CHECK (
                    cursor_key IS NULL OR length(cursor_key) = 32
                )
            )
            "#,
        )
    } else if observed == current {
        normalize_schema_sql(
            r#"
            CREATE TABLE restore_scan_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                revision INTEGER NOT NULL CHECK (revision >= 0),
                cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32)
            )
            "#,
        )
    } else {
        return Err(RecoveryError::CorruptReplica);
    };
    if normalized_sql != expected_sql {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(true)
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_ascii_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn ensure_restore_scan_metadata(conn: &Connection) -> Result<(), RecoveryError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS restore_scan_state (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            epoch BLOB NOT NULL CHECK (length(epoch) = 16),
            revision INTEGER NOT NULL CHECK (revision >= 0)
        );
        "#,
    )
    .map_err(|_| RecoveryError::FileOperationFailed)?;
    ops::initialize_restore_scan_metadata_sync(conn).map_err(|_| RecoveryError::FileOperationFailed)
}

fn validate_exact_recovery_schema(
    conn: &Connection,
    require_recovery_table: bool,
) -> Result<(), RecoveryError> {
    let has_restore_scan_state = validate_restore_scan_schema_if_present(conn)?;
    let canonical = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    consensus::install_recovery_validation_schema_sync(&canonical, false)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let mut expected = recovery_schema_manifest(&canonical)?;

    let canonical_operator = expected
        .remove("consensus_operator_recovery")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    expected
        .remove("restore_scan_state")
        .ok_or(RecoveryError::DatabaseUnavailable)?;

    canonical
        .execute_batch("DROP TABLE consensus_operator_recovery")
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    consensus::install_recovery_validation_schema_sync(&canonical, true)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let add_on_operator = schema_object_sql(&canonical, "consensus_operator_recovery")?
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    canonical
        .execute_batch("DROP TABLE consensus_operator_recovery")
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    consensus::install_migrated_operator_recovery_validation_schema_sync(&canonical)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let migrated_operator = schema_object_sql(&canonical, "consensus_operator_recovery")?
        .ok_or(RecoveryError::DatabaseUnavailable)?;

    let mut observed = recovery_schema_manifest(conn)?;
    match observed.remove("restore_scan_state") {
        Some(_) if has_restore_scan_state => {}
        None if has_restore_scan_state => return Err(RecoveryError::CorruptReplica),
        None => {}
        Some(_) => return Err(RecoveryError::CorruptReplica),
    }
    match observed.remove("consensus_operator_recovery") {
        Some(sql)
            if sql == canonical_operator || sql == add_on_operator || sql == migrated_operator => {}
        Some(_) => return Err(RecoveryError::CorruptReplica),
        None if require_recovery_table => return Err(RecoveryError::CorruptReplica),
        None => {}
    }
    if observed != expected {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(())
}

fn recovery_schema_manifest(conn: &Connection) -> Result<BTreeMap<String, String>, RecoveryError> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut rows = statement
        .query([])
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut manifest = BTreeMap::new();
    while let Some(row) = rows.next().map_err(|_| RecoveryError::CorruptReplica)? {
        if manifest.len() >= MAX_CURRENT_SCHEMA_OBJECTS {
            return Err(RecoveryError::CorruptReplica);
        }
        let kind = row
            .get::<_, String>(0)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        let name = row
            .get::<_, String>(1)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        let sql = row
            .get::<_, Option<String>>(2)
            .map_err(|_| RecoveryError::CorruptReplica)?
            .ok_or(RecoveryError::CorruptReplica)?;
        if kind != "table"
            || name.len() > MAX_SCHEMA_SQL_BYTES
            || sql.len() > MAX_SCHEMA_SQL_BYTES
            || manifest.insert(name, normalize_schema_sql(&sql)).is_some()
        {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    Ok(manifest)
}

fn schema_object_sql(conn: &Connection, name: &str) -> Result<Option<String>, RecoveryError> {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map(|sql| sql.map(|sql| normalize_schema_sql(&sql)))
    .map_err(|_| RecoveryError::CorruptReplica)
}

fn hash_legacy_state(
    conn: &Connection,
    budget: &mut InspectionBudget,
) -> Result<RecoveryDigest, RecoveryError> {
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_BRANCH_DOMAIN);
    for query in [
        "SELECT * FROM session_records ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM leases ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM key_fences ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM lease_globals ORDER BY key",
        "SELECT * FROM session_replication_log ORDER BY sequence",
    ] {
        hasher.update(
            u64::try_from(query.len())
                .map_err(|_| RecoveryError::WorkLimitExceeded)?
                .to_be_bytes(),
        );
        hasher.update(query.as_bytes());
        hash_query_rows(conn, query, budget, &mut hasher)?;
    }
    Ok(RecoveryDigest::from_bytes(hasher.finalize().into()))
}

fn hash_logical_state(
    conn: &Connection,
    budget: &mut InspectionBudget,
) -> Result<RecoveryDigest, RecoveryError> {
    let mut hasher = Sha256::new();
    hasher.update(LOGICAL_STATE_DOMAIN);
    for query in [
        "SELECT * FROM session_records ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM leases ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM key_fences ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM lease_globals ORDER BY key",
    ] {
        hasher.update(
            u64::try_from(query.len())
                .map_err(|_| RecoveryError::WorkLimitExceeded)?
                .to_be_bytes(),
        );
        hasher.update(query.as_bytes());
        hash_query_rows(conn, query, budget, &mut hasher)?;
    }
    Ok(RecoveryDigest::from_bytes(hasher.finalize().into()))
}

fn validate_sealed_records(
    conn: &Connection,
    budget: &mut InspectionBudget,
) -> Result<(), RecoveryError> {
    let (count, max_value, total_value): (i64, i64, i64) = conn
        .query_row(
            r#"
            SELECT COUNT(*),
                   COALESCE(MAX(MAX(length(stable_id), length(payload))), 0),
                   COALESCE(SUM(
                       length(tenant) + length(nf_kind) + length(key_type) +
                       length(stable_id) + length(owner) + length(state_class) +
                       length(state_type) + COALESCE(length(expires_at), 0) +
                       length(payload)
                   ), 0)
            FROM session_records
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| inspection_sql_error(error, budget))?;
    let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
    let max_value = u64::try_from(max_value).map_err(|_| RecoveryError::CorruptReplica)?;
    let total_value = u64::try_from(total_value).map_err(|_| RecoveryError::CorruptReplica)?;
    if count > budget.limits.max_rows()
        || max_value > budget.limits.max_value_bytes()
        || total_value > budget.limits.max_total_value_bytes()
    {
        return Err(RecoveryError::WorkLimitExceeded);
    }

    let mut statement = conn
        .prepare(
            r#"
            SELECT tenant, nf_kind, key_type, stable_id, generation, owner,
                   fence, state_class, state_type, expires_at, payload, encoding
            FROM session_records
            ORDER BY tenant, nf_kind, key_type, stable_id
            "#,
        )
        .map_err(|error| inspection_sql_error(error, budget))?;
    let mut rows = statement
        .query([])
        .map_err(|error| inspection_sql_error(error, budget))?;
    while let Some(row) = rows
        .next()
        .map_err(|error| inspection_sql_error(error, budget))?
    {
        budget.consume_row()?;
        for column in [0_usize, 1, 2, 3, 5, 7, 8, 9, 10] {
            match row
                .get_ref(column)
                .map_err(|error| inspection_sql_error(error, budget))?
            {
                ValueRef::Null if column == 9 => {}
                ValueRef::Text(value) | ValueRef::Blob(value) => {
                    budget.consume_value(value.len())?
                }
                _ => return Err(RecoveryError::CorruptReplica),
            }
        }
        let record = crate::sqlite::ops::stored_record_from_row(
            row.get(0).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(1).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(2).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(3).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(4).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(5).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(6).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(7).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(8).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(9).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(10).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(11).map_err(|_| RecoveryError::CorruptReplica)?,
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
        if record.payload.encoding() != crate::SessionPayloadEncoding::EnvelopeV1 {
            return Err(RecoveryError::CorruptReplica);
        }
        record
            .payload
            .validate_envelope_for_record(&record)
            .map_err(|_| RecoveryError::CorruptReplica)?;
    }
    Ok(())
}

fn validate_replication_sequence_domain(
    conn: &Connection,
    budget: &mut InspectionBudget,
    invalidation_floor: u64,
) -> Result<u64, RecoveryError> {
    let (minimum, maximum, count, max_value, total_value): (
        Option<i64>,
        Option<i64>,
        i64,
        i64,
        i64,
    ) = conn
        .query_row(
            r#"
            SELECT MIN(sequence), MAX(sequence), COUNT(*),
                   COALESCE(MAX(MAX(length(tx_id), length(entry_json), length(timestamp))), 0),
                   COALESCE(SUM(length(tx_id) + length(entry_json) + length(timestamp)), 0)
            FROM session_replication_log
            "#,
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|error| inspection_sql_error(error, budget))?;
    let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
    let max_value = u64::try_from(max_value).map_err(|_| RecoveryError::CorruptReplica)?;
    let total_value = u64::try_from(total_value).map_err(|_| RecoveryError::CorruptReplica)?;
    if count > budget.limits.max_rows()
        || max_value > budget.limits.max_value_bytes()
        || total_value > budget.limits.max_total_value_bytes()
    {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    if count == 0 {
        if minimum.is_some() || maximum.is_some() {
            return Err(RecoveryError::CorruptReplica);
        }
        return Ok(invalidation_floor);
    }
    let minimum = minimum
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(RecoveryError::CorruptReplica)?;
    let maximum = maximum
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(RecoveryError::CorruptReplica)?;
    let expected_minimum = invalidation_floor
        .checked_add(1)
        .ok_or(RecoveryError::CorruptReplica)?;
    let expected_maximum = invalidation_floor
        .checked_add(count)
        .ok_or(RecoveryError::CorruptReplica)?;
    if minimum != expected_minimum || maximum != expected_maximum {
        return Err(RecoveryError::CorruptReplica);
    }

    let mut statement = conn
        .prepare(
            "SELECT sequence, tx_id, entry_json, timestamp FROM session_replication_log ORDER BY sequence",
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut rows = statement
        .query([])
        .map_err(|error| inspection_sql_error(error, budget))?;
    let mut expected = expected_minimum;
    while let Some(row) = rows
        .next()
        .map_err(|error| inspection_sql_error(error, budget))?
    {
        budget.consume_row()?;
        for column in [1_usize, 2, 3] {
            match row
                .get_ref(column)
                .map_err(|error| inspection_sql_error(error, budget))?
            {
                ValueRef::Text(value) => budget.consume_value(value.len())?,
                _ => return Err(RecoveryError::CorruptReplica),
            }
        }
        let stored_sequence: i64 = row.get(0).map_err(|_| RecoveryError::CorruptReplica)?;
        let tx_id: String = row.get(1).map_err(|_| RecoveryError::CorruptReplica)?;
        let encoded: String = row.get(2).map_err(|_| RecoveryError::CorruptReplica)?;
        let timestamp: String = row.get(3).map_err(|_| RecoveryError::CorruptReplica)?;
        let stored_sequence =
            u64::try_from(stored_sequence).map_err(|_| RecoveryError::CorruptReplica)?;
        let entry: ReplicationEntry =
            serde_json::from_str(&encoded).map_err(|_| RecoveryError::CorruptReplica)?;
        let entry = entry
            .into_validated()
            .map_err(|_| RecoveryError::CorruptReplica)?;
        consensus::validate_sealed_replication_op(&entry.op)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        if stored_sequence != expected
            || entry.sequence != stored_sequence
            || entry.tx_id != tx_id
            || crate::sqlite::ops::format_rfc3339_normalized(entry.timestamp) != timestamp
        {
            return Err(RecoveryError::CorruptReplica);
        }
        expected = expected
            .checked_add(1)
            .ok_or(RecoveryError::CorruptReplica)?;
    }
    if expected.checked_sub(1) != Some(expected_maximum) {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(expected_maximum)
}

fn hash_query_rows(
    conn: &Connection,
    query: &str,
    budget: &mut InspectionBudget,
    hasher: &mut Sha256,
) -> Result<(), RecoveryError> {
    let mut statement = conn
        .prepare(query)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let columns = statement.column_count();
    let mut rows = statement
        .query([])
        .map_err(|error| inspection_sql_error(error, budget))?;
    while let Some(row) = rows
        .next()
        .map_err(|error| inspection_sql_error(error, budget))?
    {
        budget.consume_row()?;
        hasher.update([0xff]);
        for column in 0..columns {
            match row
                .get_ref(column)
                .map_err(|_| RecoveryError::CorruptReplica)?
            {
                ValueRef::Null => hasher.update([0]),
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hasher.update(value.to_be_bytes());
                }
                ValueRef::Real(_) => return Err(RecoveryError::CorruptReplica),
                ValueRef::Text(value) => {
                    feed_bounded_value(hasher, 2, value, budget)?;
                }
                ValueRef::Blob(value) => {
                    feed_bounded_value(hasher, 3, value, budget)?;
                }
            }
        }
    }
    Ok(())
}

fn feed_bounded_value(
    hasher: &mut Sha256,
    kind: u8,
    value: &[u8],
    budget: &mut InspectionBudget,
) -> Result<(), RecoveryError> {
    let length = u64::try_from(value.len()).map_err(|_| RecoveryError::WorkLimitExceeded)?;
    budget.consume_value(value.len())?;
    hasher.update([kind]);
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

pub(super) fn backup_and_reset_replica(
    input: ResetInput<'_>,
) -> Result<RecoveryExecutionState, RecoveryError> {
    preflight_plan_high_waters(input.plan)?;
    let mut supplied = input
        .replicas
        .iter()
        .map(|replica| super::replica_token(input.key, &replica.replica_id))
        .collect::<Result<Vec<_>, _>>()?;
    supplied.sort_unstable();
    let planned = input
        .plan
        .body
        .evidence
        .iter()
        .map(RecoveryReplicaEvidence::replica_token)
        .collect::<Vec<_>>();
    let mut supplied_targets = input
        .targets
        .iter()
        .map(|replica| super::replica_token(input.key, &replica.replica_id))
        .collect::<Result<Vec<_>, _>>()?;
    supplied_targets.sort_unstable();
    if supplied != planned
        || supplied.windows(2).any(|pair| pair[0] == pair[1])
        || supplied_targets != input.plan.body.target_tokens
    {
        return Err(RecoveryError::StalePlan);
    }
    let execution_locks = acquire_fleet_execution_locks(input.key, input.plan, input.replicas)?;
    let workflow_dir = workflow_directory(input.backup_root, input.plan, true)?;
    let mut workflow =
        read_workflow(input.key, input.plan, &workflow_dir)?.unwrap_or(WorkflowRecord {
            version: WORKFLOW_VERSION,
            plan_digest: input.plan.plan_digest,
            source_branch_digest: input.plan.body.source_branch_digest,
            target_tokens: input.plan.body.target_tokens.clone(),
            state: RecoveryExecutionState::Planned,
            audit_resume_state: None,
            rejoin_proven: false,
            checkpoint_database_digest: None,
            checkpoint_snapshot_digest: None,
            staged_database_digest: None,
            source_snapshot_name: None,
            checkpoint_progress: FileProgress::Pending,
            staged_progress: FileProgress::Pending,
            target_backups: input
                .plan
                .body
                .target_tokens
                .iter()
                .map(|token| (token.to_hex(), FileProgress::Pending))
                .collect(),
            target_installs: input
                .plan
                .body
                .target_tokens
                .iter()
                .copied()
                .map(|token| (token.to_hex(), TargetInstallState::Pending))
                .collect(),
        });
    validate_workflow_shape(input.plan, &workflow)?;
    // A completed execute retry must remain read-only with respect to the
    // fleet latch. Finalization has already cleared it on the successful path,
    // and recreating it here would regress every voter back to not-ready. If a
    // prior finalization crashed before clearing an existing latch, only a
    // finalize retry is authorized to remove it.
    if workflow.state != RecoveryExecutionState::Rejoined {
        ensure_fleet_latches(input.key, input.plan, input.replicas)?;
    }
    let checkpoint_replica = if workflow.checkpoint_database_digest.is_some() {
        for target in input.targets {
            verify_target_backup(input.key, input.plan, target, &workflow_dir)?;
        }
        verify_checkpoint(
            input.key,
            input.plan,
            input.source,
            &workflow_dir,
            &workflow,
            input.limits,
        )?
    } else {
        if workflow.state != RecoveryExecutionState::Planned {
            return Err(RecoveryError::BackupCorrupt);
        }
        // Re-prove the entire bound fleet, majority, and global high-waters in
        // one pass immediately before the first backup or target mutation.
        inspect_planned_fleet(&input)?;

        for target in input.targets {
            let token = super::replica_token(input.key, &target.replica_id)?.to_hex();
            let progress = workflow
                .target_backups
                .get(&token)
                .copied()
                .ok_or(RecoveryError::BackupCorrupt)?;
            if progress != FileProgress::Verified {
                if progress == FileProgress::Pending {
                    workflow
                        .target_backups
                        .insert(token.clone(), FileProgress::Copying);
                    write_workflow(input.key, &workflow_dir, &workflow)?;
                }
                ensure_target_backup(
                    input.key,
                    input.plan,
                    target,
                    &workflow_dir,
                    input.limits,
                    true,
                )?;
                #[cfg(test)]
                if input.failpoint == Some(RecoveryFailpoint::AfterTargetBackupCopy) {
                    return Err(RecoveryError::InjectedFailure);
                }
                workflow
                    .target_backups
                    .insert(token, FileProgress::Verified);
                write_workflow(input.key, &workflow_dir, &workflow)?;
            } else {
                verify_target_backup(input.key, input.plan, target, &workflow_dir)?;
            }
        }
        if workflow.checkpoint_progress == FileProgress::Pending {
            workflow.checkpoint_progress = FileProgress::Copying;
            write_workflow(input.key, &workflow_dir, &workflow)?;
        }
        let checkpoint = create_checkpoint(
            input.key,
            input.plan,
            input.source,
            &workflow_dir,
            input.limits,
            workflow.checkpoint_progress == FileProgress::Copying,
        )?;
        #[cfg(test)]
        if input.failpoint == Some(RecoveryFailpoint::AfterCheckpointCopy) {
            return Err(RecoveryError::InjectedFailure);
        }
        workflow.checkpoint_progress = FileProgress::Verified;
        write_workflow(input.key, &workflow_dir, &workflow)?;
        // A target may have changed while the sequential quarantine copies
        // were being made. Re-prove every live file once more after every
        // backup/checkpoint and before the first destructive installation.
        inspect_planned_fleet(&input)?;
        workflow.checkpoint_database_digest = Some(checkpoint.database_digest);
        workflow.checkpoint_snapshot_digest = checkpoint.snapshot_digest;
        workflow.source_snapshot_name = checkpoint.snapshot_name;
        transition_record_state(&mut workflow, RecoveryExecutionState::BackupVerified)?;
        write_workflow(input.key, &workflow_dir, &workflow)?;
        checkpoint.replica
    };

    #[cfg(test)]
    if input.failpoint == Some(RecoveryFailpoint::AfterBackup) {
        return Err(RecoveryError::InjectedFailure);
    }

    let staged = workflow_dir.join("staged.sqlite");
    let staged_snapshot = workflow_dir.join("staged-snapshot.opc");
    let source_snapshot_name = if let Some(expected) = workflow.staged_database_digest {
        if digest_file(&staged, input.limits.max_database_bytes())?.0 != expected {
            return Err(RecoveryError::BackupCorrupt);
        }
        verify_staged_source(
            input.key,
            input.plan,
            &checkpoint_replica,
            &staged,
            &staged_snapshot,
            workflow.source_snapshot_name.as_deref(),
            input.limits,
        )?;
        workflow.source_snapshot_name.clone()
    } else {
        if workflow.staged_progress == FileProgress::Pending {
            require_path_absent(&staged)?;
            require_path_absent(&staged_snapshot)?;
            workflow.staged_progress = FileProgress::Copying;
            write_workflow(input.key, &workflow_dir, &workflow)?;
        }
        if workflow.staged_progress != FileProgress::Copying {
            return Err(RecoveryError::BackupCorrupt);
        }
        remove_regular_file_if_present(&staged)?;
        remove_regular_file_if_present(&staged_snapshot)?;
        let source_snapshot_name = stage_source(
            input.key,
            input.plan,
            &checkpoint_replica,
            &staged,
            &staged_snapshot,
            input.limits,
        )?;
        #[cfg(test)]
        if input.failpoint == Some(RecoveryFailpoint::AfterStagedCopy) {
            return Err(RecoveryError::InjectedFailure);
        }
        let staged_digest = digest_file(&staged, input.limits.max_database_bytes())?.0;
        workflow.staged_database_digest = Some(staged_digest);
        workflow.staged_progress = FileProgress::Verified;
        workflow.source_snapshot_name = source_snapshot_name.clone();
        write_workflow(input.key, &workflow_dir, &workflow)?;
        source_snapshot_name
    };

    for target in input.targets {
        let target_token = super::replica_token(input.key, &target.replica_id)?;
        let progress = workflow
            .target_installs
            .get(&target_token.to_hex())
            .copied()
            .ok_or(RecoveryError::BackupCorrupt)?;
        if progress < TargetInstallState::DatabaseInstalled {
            revalidate_execution_lock(&execution_locks, &target.database_path)?;
        }
        if progress < TargetInstallState::SnapshotInstalled {
            if progress == TargetInstallState::Pending {
                require_snapshot_install_temporary_absent(target, source_snapshot_name.as_deref())?;
                workflow
                    .target_installs
                    .insert(target_token.to_hex(), TargetInstallState::SnapshotCopying);
                write_workflow(input.key, &workflow_dir, &workflow)?;
            }
            if verify_installed_snapshot(
                target,
                source_snapshot_name.as_deref(),
                &staged_snapshot,
                input.limits,
            )
            .is_err()
            {
                install_staged_snapshot(
                    target,
                    source_snapshot_name.as_deref(),
                    &staged_snapshot,
                    input.limits,
                    true,
                )?;
            }
            #[cfg(test)]
            if input
                .targets
                .first()
                .is_some_and(|first| std::ptr::eq(*first, *target))
                && input.failpoint == Some(RecoveryFailpoint::AfterSnapshotInstall)
            {
                return Err(RecoveryError::InjectedFailure);
            }
            workflow
                .target_installs
                .insert(target_token.to_hex(), TargetInstallState::SnapshotInstalled);
            write_workflow(input.key, &workflow_dir, &workflow)?;
        } else {
            verify_installed_snapshot(
                target,
                source_snapshot_name.as_deref(),
                &staged_snapshot,
                input.limits,
            )?;
        }
        let progress = workflow
            .target_installs
            .get(&target_token.to_hex())
            .copied()
            .ok_or(RecoveryError::BackupCorrupt)?;
        if progress < TargetInstallState::DatabaseInstalled {
            if progress == TargetInstallState::SnapshotInstalled {
                require_database_install_temporary_absent(target, input.plan)?;
                workflow
                    .target_installs
                    .insert(target_token.to_hex(), TargetInstallState::DatabaseCopying);
                write_workflow(input.key, &workflow_dir, &workflow)?;
            }
            if target_matches_staged_recovery(input.key, input.plan, target, &staged, input.limits)?
            {
                workflow
                    .target_installs
                    .insert(target_token.to_hex(), TargetInstallState::DatabaseInstalled);
                write_workflow(input.key, &workflow_dir, &workflow)?;
            } else {
                install_staged_database(
                    target,
                    &staged,
                    input.plan,
                    true,
                    #[cfg(test)]
                    input.failpoint,
                )?;
                verify_target_installed(input.key, input.plan, target, input.limits)?;
                #[cfg(test)]
                if input
                    .targets
                    .first()
                    .is_some_and(|first| std::ptr::eq(*first, *target))
                    && input.failpoint == Some(RecoveryFailpoint::AfterDatabaseInstall)
                {
                    return Err(RecoveryError::InjectedFailure);
                }
                workflow
                    .target_installs
                    .insert(target_token.to_hex(), TargetInstallState::DatabaseInstalled);
                write_workflow(input.key, &workflow_dir, &workflow)?;
            }
        } else {
            let finalized = matches!(
                workflow.state,
                RecoveryExecutionState::EpochCommitted | RecoveryExecutionState::Rejoined
            ) || (workflow.state == RecoveryExecutionState::AuditPending
                && workflow.audit_resume_state.is_some_and(|state| {
                    matches!(
                        state,
                        RecoveryExecutionState::EpochCommitted | RecoveryExecutionState::Rejoined
                    )
                }));
            if finalized {
                verify_target_finalized(input.key, input.plan, target, input.limits)?;
            } else if !target_matches_staged_recovery(
                input.key,
                input.plan,
                target,
                &staged,
                input.limits,
            )? {
                return Err(RecoveryError::BackupCorrupt);
            }
        }
    }
    if workflow.state != RecoveryExecutionState::BackupVerified {
        return Ok(workflow.state);
    }
    transition_record_state(&mut workflow, RecoveryExecutionState::AwaitingEpochCommit)?;
    write_workflow(input.key, &workflow_dir, &workflow)?;
    Ok(workflow.state)
}

fn expected_latch(plan: &RecoveryPlan, audit_pending: bool) -> consensus::OperatorRecoveryLatch {
    consensus::OperatorRecoveryLatch {
        identity: plan.body.identity,
        recovery_epoch: plan.body.next_recovery_epoch,
        plan_digest: plan.plan_digest.as_bytes(),
        audit_pending,
    }
}

fn validate_bound_replica_path(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replica: &RecoveryReplica,
) -> Result<CanonicalReplicaPaths, RecoveryError> {
    let token = super::replica_token(key, &replica.replica_id)?;
    let planned = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == token)
        .ok_or(RecoveryError::StalePlan)?;
    if planned.backing_identity
        != RecoveryDigest::from_bytes(replica.backing_identity.fingerprint())
    {
        return Err(RecoveryError::StalePlan);
    }
    let paths = canonical_replica_paths(replica, false)?;
    if recovery_path_binding(key, &paths)? != planned.path_binding {
        return Err(RecoveryError::StalePlan);
    }
    Ok(paths)
}

#[cfg(unix)]
fn acquire_fleet_execution_locks(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &[RecoveryReplica],
) -> Result<Vec<ReplicaExecutionLock>, RecoveryError> {
    use std::os::unix::fs::MetadataExt;

    validate_fleet_replica_set(key, plan, replicas)?;
    let mut locks = Vec::with_capacity(replicas.len());
    for replica in replicas {
        let paths = validate_bound_replica_path(key, plan, replica)?;
        let file =
            open_regular_read(&paths.database).map_err(|_| RecoveryError::FileOperationFailed)?;
        let metadata = file
            .metadata()
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        let file = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        locks.push(ReplicaExecutionLock {
            path: paths.database,
            _file: file,
            device: metadata.dev(),
            inode: metadata.ino(),
        });
    }
    Ok(locks)
}

#[cfg(not(unix))]
fn acquire_fleet_execution_locks(
    _key: &RecoveryIntegrityKey,
    _plan: &RecoveryPlan,
    _replicas: &[RecoveryReplica],
) -> Result<Vec<()>, RecoveryError> {
    Err(RecoveryError::InvalidRequest)
}

#[cfg(unix)]
fn revalidate_execution_lock(
    locks: &[ReplicaExecutionLock],
    path: &Path,
) -> Result<(), RecoveryError> {
    use std::os::unix::fs::MetadataExt;
    let canonical = fs::canonicalize(path).map_err(|_| RecoveryError::SourceChanged)?;
    let lock = locks
        .iter()
        .find(|lock| lock.path == canonical)
        .ok_or(RecoveryError::SourceChanged)?;
    let observed = open_regular_read(&canonical).map_err(|_| RecoveryError::SourceChanged)?;
    let metadata = observed
        .metadata()
        .map_err(|_| RecoveryError::SourceChanged)?;
    if metadata.dev() != lock.device || metadata.ino() != lock.inode {
        return Err(RecoveryError::SourceChanged);
    }
    Ok(())
}

#[cfg(not(unix))]
fn revalidate_execution_lock(_locks: &[()], _path: &Path) -> Result<(), RecoveryError> {
    Err(RecoveryError::InvalidRequest)
}

fn ensure_fleet_latches(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &[RecoveryReplica],
) -> Result<(), RecoveryError> {
    validate_fleet_replica_set(key, plan, replicas)?;
    let expected = expected_latch(plan, false);
    for replica in replicas {
        let paths = validate_bound_replica_path(key, plan, replica)?;
        consensus::ensure_operator_recovery_latch_sync(&paths.database, expected)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    Ok(())
}

pub(super) fn set_fleet_latches_audit_pending(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &[RecoveryReplica],
    audit_pending: bool,
) -> Result<(), RecoveryError> {
    validate_fleet_replica_set(key, plan, replicas)?;
    let expected = expected_latch(plan, audit_pending);
    for replica in replicas {
        let paths = validate_bound_replica_path(key, plan, replica)?;
        consensus::set_operator_recovery_latch_audit_pending_sync(
            &paths.database,
            expected,
            audit_pending,
        )
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    opc_redaction::metrics::METRICS
        .session_operator_recovery_audit_pending
        .store(
            i64::from(audit_pending),
            std::sync::atomic::Ordering::Relaxed,
        );
    Ok(())
}

pub(super) fn clear_fleet_latches(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &[RecoveryReplica],
) -> Result<(), RecoveryError> {
    validate_fleet_replica_set(key, plan, replicas)?;
    let expected = expected_latch(plan, false);
    for replica in replicas {
        let paths = validate_bound_replica_path(key, plan, replica)?;
        consensus::clear_operator_recovery_latch_sync(&paths.database, expected)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    opc_redaction::metrics::METRICS
        .session_operator_recovery_audit_pending
        .store(0, std::sync::atomic::Ordering::Relaxed);
    opc_redaction::metrics::METRICS
        .session_operator_recovery_required
        .store(0, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

fn validate_fleet_replica_set(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &[RecoveryReplica],
) -> Result<(), RecoveryError> {
    let observed = replicas
        .iter()
        .map(|replica| super::replica_token(key, &replica.replica_id))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = plan
        .body
        .evidence
        .iter()
        .map(RecoveryReplicaEvidence::replica_token)
        .collect::<BTreeSet<_>>();
    if observed != expected || replicas.len() != expected.len() {
        return Err(RecoveryError::StalePlan);
    }
    Ok(())
}

fn checked_sqlite_high_water(value: u64) -> Result<i64, RecoveryError> {
    i64::try_from(value).map_err(|_| RecoveryError::WorkLimitExceeded)
}

fn preflight_successor(value: u64) -> Result<(), RecoveryError> {
    let successor = value
        .checked_add(1)
        .ok_or(RecoveryError::WorkLimitExceeded)?;
    checked_sqlite_high_water(successor).map(|_| ())
}

fn preflight_plan_high_waters(plan: &RecoveryPlan) -> Result<(), RecoveryError> {
    for value in [
        plan.body.next_recovery_epoch,
        plan.body.application_sequence_high_water,
        plan.body.watch_sequence_high_water,
        plan.body.watch_cursor_invalidation_floor,
        plan.body.fence_high_water,
        plan.body.credential_high_water,
    ] {
        preflight_successor(value)?;
    }
    Ok(())
}

fn inspect_planned_fleet(input: &ResetInput<'_>) -> Result<(), RecoveryError> {
    let mut observed = input
        .replicas
        .iter()
        .map(|replica| {
            inspect_replica(InspectionInput {
                key: input.key,
                replica,
                identity: input.plan.body.identity,
                expected_members: &input.plan.body.expected_members,
                limits: input.limits,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    observed.sort_by_key(RecoveryReplicaEvidence::replica_token);
    if observed == input.plan.body.evidence {
        return Ok(());
    }
    let source_token = super::replica_token(input.key, &input.source.replica_id)?;
    let observed_source = observed
        .iter()
        .find(|item| item.replica_token == source_token);
    let planned_source = input
        .plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == source_token);
    if observed_source != planned_source {
        return Err(RecoveryError::SourceChanged);
    }
    Err(RecoveryError::StalePlan)
}

struct CheckpointBundle {
    replica: RecoveryReplica,
    database_digest: RecoveryDigest,
    snapshot_digest: Option<RecoveryDigest>,
    snapshot_name: Option<String>,
}

fn target_backup_directory(
    workflow_dir: &Path,
    token: RecoveryDigest,
    create: bool,
) -> Result<PathBuf, RecoveryError> {
    let targets = workflow_dir.join("targets");
    if create {
        create_private_directory(&targets)?;
    }
    let directory = targets.join(token.to_hex());
    if create {
        create_private_directory(&directory)?;
    } else {
        validate_private_directory(&directory)?;
    }
    Ok(directory)
}

fn ensure_target_backup(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    workflow_dir: &Path,
    limits: RecoveryLimits,
    resume_partial: bool,
) -> Result<SealedBackupManifest, RecoveryError> {
    let target_token = super::replica_token(key, &target.replica_id)?;
    if !plan.body.target_tokens.contains(&target_token) {
        return Err(RecoveryError::StalePlan);
    }
    let target_path = workflow_dir.join("targets").join(target_token.to_hex());
    let target_path_preexisted = fs::symlink_metadata(&target_path).is_ok();
    let backup_dir = target_backup_directory(workflow_dir, target_token, true)?;
    if backup_dir.join("backup-manifest.json").exists() {
        return read_and_verify_backup_manifest(key, plan, target_token, &backup_dir);
    }
    if target_path_preexisted {
        if !resume_partial {
            return Err(RecoveryError::FileOperationFailed);
        }
        clean_partial_target_backup(&backup_dir)?;
    }
    if fs::read_dir(&backup_dir)
        .map_err(|_| RecoveryError::FileOperationFailed)?
        .next()
        .is_some()
    {
        return Err(RecoveryError::FileOperationFailed);
    }
    let paths = canonical_replica_paths(target, false)?;
    let backup_database = backup_dir.join("target.sqlite");
    sqlite_backup(
        &paths.database,
        &backup_database,
        limits.max_database_bytes(),
    )?;

    let backup_snapshots = backup_dir.join("snapshots");
    create_private_directory(&backup_snapshots)?;
    let mut files = Vec::new();
    if let Some(snapshot) = current_snapshot_reference(
        &paths.database,
        plan.body.identity,
        &plan.body.expected_members,
        &paths.snapshots,
        limits,
    )? {
        let destination = backup_snapshots.join(&snapshot.file_name);
        copy_file_bounded(&snapshot.path, &destination, limits.max_snapshot_bytes())?;
        let (digest, length) = digest_file(&destination, limits.max_snapshot_bytes())?;
        files.push(BackupFileEvidence {
            role: "snapshot".to_string(),
            byte_length: length,
            digest,
            original_name: Some(snapshot.file_name),
        });
    }
    let backed_up_replica = RecoveryReplica::new_bound(
        target.replica_id.clone(),
        target.backing_identity.clone(),
        target.admitted_identity,
        backup_database.clone(),
        backup_snapshots,
    );
    let backed_up_evidence = inspect_replica(InspectionInput {
        key,
        replica: &backed_up_replica,
        identity: plan.body.identity,
        expected_members: &plan.body.expected_members,
        limits,
    })?;
    let planned_target = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == target_token)
        .ok_or(RecoveryError::StalePlan)?;
    if !same_checkpoint(&backed_up_evidence, planned_target) {
        return Err(RecoveryError::StalePlan);
    }
    let (database_digest, database_length) =
        digest_file(&backup_database, limits.max_database_bytes())?;
    files.insert(
        0,
        BackupFileEvidence {
            role: "database".to_string(),
            byte_length: database_length,
            digest: database_digest,
            original_name: None,
        },
    );
    let body = BackupManifestBody {
        version: WORKFLOW_VERSION,
        plan_digest: plan.plan_digest,
        target_token,
        files,
    };
    let encoded = serde_json::to_vec(&body).map_err(|_| RecoveryError::FileOperationFailed)?;
    let mac = RecoveryDigest::from_bytes(plan_mac(key, BACKUP_MAC_DOMAIN, &[&encoded])?);
    let manifest = SealedBackupManifest { body, mac };
    atomic_write_json(&backup_dir.join("backup-manifest.json"), &manifest)?;
    let verified = read_and_verify_backup_manifest(key, plan, target_token, &backup_dir)?;
    sync_directory(&backup_dir)?;
    Ok(verified)
}

fn verify_target_backup(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    workflow_dir: &Path,
) -> Result<(), RecoveryError> {
    let target_token = super::replica_token(key, &target.replica_id)?;
    let directory = target_backup_directory(workflow_dir, target_token, false)?;
    read_and_verify_backup_manifest(key, plan, target_token, &directory).map(|_| ())
}

fn clean_partial_target_backup(directory: &Path) -> Result<(), RecoveryError> {
    let mut inspected = 0;
    remove_private_tree(directory, 0, &mut inspected)?;
    create_private_directory(directory)
}

fn clean_partial_checkpoint(directory: &Path) -> Result<(), RecoveryError> {
    let mut inspected = 0;
    remove_private_tree(directory, 0, &mut inspected)?;
    Ok(())
}

fn remove_private_tree(
    path: &Path,
    depth: usize,
    inspected: &mut usize,
) -> Result<(), RecoveryError> {
    if depth > 3 || *inspected > 32 {
        return Err(RecoveryError::FileOperationFailed);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| RecoveryError::FileOperationFailed)?;
    if metadata.file_type().is_symlink() {
        return Err(RecoveryError::FileOperationFailed);
    }
    if metadata.is_file() {
        validate_private_file(path).map_err(|_| RecoveryError::FileOperationFailed)?;
        return fs::remove_file(path).map_err(|_| RecoveryError::FileOperationFailed);
    }
    validate_private_directory(path)?;
    for entry in fs::read_dir(path).map_err(|_| RecoveryError::FileOperationFailed)? {
        let entry = entry.map_err(|_| RecoveryError::FileOperationFailed)?;
        *inspected = inspected
            .checked_add(1)
            .ok_or(RecoveryError::FileOperationFailed)?;
        remove_private_tree(&entry.path(), depth + 1, inspected)?;
    }
    fs::remove_dir(path).map_err(|_| RecoveryError::FileOperationFailed)
}

fn read_and_verify_backup_manifest(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target_token: RecoveryDigest,
    backup_dir: &Path,
) -> Result<SealedBackupManifest, RecoveryError> {
    let manifest: SealedBackupManifest =
        read_bounded_json(&backup_dir.join("backup-manifest.json"), 64 * 1024)?;
    if manifest.body.version != WORKFLOW_VERSION
        || manifest.body.plan_digest != plan.plan_digest
        || manifest.body.target_token != target_token
        || !plan.body.target_tokens.contains(&target_token)
        || manifest.body.files.is_empty()
        || manifest.body.files.len() > 2
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let encoded = serde_json::to_vec(&manifest.body).map_err(|_| RecoveryError::BackupCorrupt)?;
    verify_mac(key, BACKUP_MAC_DOMAIN, &[&encoded], manifest.mac)?;
    if manifest
        .body
        .files
        .iter()
        .filter(|file| file.role == "database" && file.original_name.is_none())
        .count()
        != 1
        || manifest
            .body
            .files
            .iter()
            .filter(|file| file.role == "snapshot" && file.original_name.is_some())
            .count()
            > 1
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    for evidence in &manifest.body.files {
        let path = match evidence.role.as_str() {
            "database" => backup_dir.join("target.sqlite"),
            "snapshot" => {
                let name = evidence
                    .original_name
                    .as_deref()
                    .ok_or(RecoveryError::BackupCorrupt)?;
                validate_snapshot_name(name).map_err(|_| RecoveryError::BackupCorrupt)?;
                backup_dir.join("snapshots").join(name)
            }
            _ => return Err(RecoveryError::BackupCorrupt),
        };
        let (digest, length) = digest_file(&path, evidence.byte_length)?;
        if digest != evidence.digest || length != evidence.byte_length {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    Ok(manifest)
}

fn create_checkpoint(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    source: &RecoveryReplica,
    workflow_dir: &Path,
    limits: RecoveryLimits,
    resume_partial: bool,
) -> Result<CheckpointBundle, RecoveryError> {
    let checkpoint_dir = workflow_dir.join("checkpoint");
    if fs::symlink_metadata(&checkpoint_dir).is_ok() {
        if !resume_partial {
            return Err(RecoveryError::FileOperationFailed);
        }
        clean_partial_checkpoint(&checkpoint_dir)?;
    }
    create_private_directory(&checkpoint_dir)?;
    if fs::read_dir(&checkpoint_dir)
        .map_err(|_| RecoveryError::FileOperationFailed)?
        .next()
        .is_some()
    {
        return Err(RecoveryError::FileOperationFailed);
    }
    let source_paths = canonical_replica_paths(source, false)?;
    let database = checkpoint_dir.join("source.sqlite");
    let snapshots = checkpoint_dir.join("snapshots");
    create_private_directory(&snapshots)?;
    sqlite_backup(
        &source_paths.database,
        &database,
        limits.max_database_bytes(),
    )?;
    let snapshot = current_snapshot_reference(
        &source_paths.database,
        plan.body.identity,
        &plan.body.expected_members,
        &source_paths.snapshots,
        limits,
    )?;
    let (snapshot_name, snapshot_digest) = if let Some(snapshot) = snapshot {
        let destination = snapshots.join(&snapshot.file_name);
        copy_file_bounded(&snapshot.path, &destination, limits.max_snapshot_bytes())?;
        let digest = digest_file(&destination, limits.max_snapshot_bytes())?.0;
        (Some(snapshot.file_name), Some(digest))
    } else {
        (None, None)
    };
    let replica = RecoveryReplica::new_bound(
        source.replica_id.clone(),
        source.backing_identity.clone(),
        source.admitted_identity,
        &database,
        &snapshots,
    );
    let evidence = inspect_replica(InspectionInput {
        key,
        replica: &replica,
        identity: plan.body.identity,
        expected_members: &plan.body.expected_members,
        limits,
    })?;
    let planned = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if !same_checkpoint(&evidence, planned) {
        return Err(RecoveryError::SourceChanged);
    }
    let database_digest = digest_file(&database, limits.max_database_bytes())?.0;
    sync_directory(&snapshots)?;
    sync_directory(&checkpoint_dir)?;
    Ok(CheckpointBundle {
        replica,
        database_digest,
        snapshot_digest,
        snapshot_name,
    })
}

fn verify_checkpoint(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    source: &RecoveryReplica,
    workflow_dir: &Path,
    workflow: &WorkflowRecord,
    limits: RecoveryLimits,
) -> Result<RecoveryReplica, RecoveryError> {
    let checkpoint_dir = workflow_dir.join("checkpoint");
    validate_private_directory(&checkpoint_dir)?;
    let database = checkpoint_dir.join("source.sqlite");
    let snapshots = checkpoint_dir.join("snapshots");
    validate_private_directory(&snapshots)?;
    let database_digest = digest_file(&database, limits.max_database_bytes())?.0;
    if Some(database_digest) != workflow.checkpoint_database_digest {
        return Err(RecoveryError::BackupCorrupt);
    }
    match (
        workflow.source_snapshot_name.as_deref(),
        workflow.checkpoint_snapshot_digest,
    ) {
        (Some(name), Some(expected)) => {
            validate_snapshot_name(name)?;
            if digest_file(&snapshots.join(name), limits.max_snapshot_bytes())?.0 != expected {
                return Err(RecoveryError::BackupCorrupt);
            }
        }
        (None, None) => {}
        _ => return Err(RecoveryError::BackupCorrupt),
    }
    let replica = RecoveryReplica::new_bound(
        source.replica_id.clone(),
        source.backing_identity.clone(),
        source.admitted_identity,
        &database,
        &snapshots,
    );
    let evidence = inspect_replica(InspectionInput {
        key,
        replica: &replica,
        identity: plan.body.identity,
        expected_members: &plan.body.expected_members,
        limits,
    })?;
    let planned = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if !same_checkpoint(&evidence, planned) {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(replica)
}

fn stage_source(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    source: &RecoveryReplica,
    staged: &Path,
    staged_snapshot: &Path,
    limits: RecoveryLimits,
) -> Result<Option<String>, RecoveryError> {
    let paths = canonical_replica_paths(source, false)?;
    match plan.body.basis {
        RecoveryDecisionBasis::VerifiedCommittedMajority => {
            sqlite_backup(&paths.database, staged, limits.max_database_bytes())?;
        }
        RecoveryDecisionBasis::ExplicitLegacyCheckpoint => {
            convert_legacy_checkpoint(&paths.database, staged, limits)?;
        }
    }
    let staged_replica = RecoveryReplica::new_bound(
        source.replica_id.clone(),
        source.backing_identity.clone(),
        source.admitted_identity,
        staged.to_path_buf(),
        paths.snapshots.clone(),
    );
    let staged_evidence = inspect_replica(InspectionInput {
        key,
        replica: &staged_replica,
        identity: plan.body.identity,
        expected_members: &plan.body.expected_members,
        limits,
    })?;
    let planned_source = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if !same_checkpoint(&staged_evidence, planned_source) {
        return Err(RecoveryError::SourceChanged);
    }
    let mut conn = open_read_write(staged)?;
    ensure_restore_scan_metadata(&conn)?;
    match plan.body.basis {
        RecoveryDecisionBasis::VerifiedCommittedMajority => {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| RecoveryError::FileOperationFailed)?;
            let committed: Option<i64> = tx
                .query_row(
                    "SELECT log_index FROM consensus_committed WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| RecoveryError::CorruptReplica)?;
            match committed {
                Some(committed) => {
                    tx.execute(
                        "DELETE FROM consensus_log WHERE log_index > ?1",
                        [committed],
                    )
                    .map_err(|_| RecoveryError::FileOperationFailed)?;
                }
                None => {
                    tx.execute("DELETE FROM consensus_log", [])
                        .map_err(|_| RecoveryError::FileOperationFailed)?;
                }
            }
            tx.execute("DELETE FROM consensus_vote", [])
                .map_err(|_| RecoveryError::FileOperationFailed)?;
            consensus::mark_operator_recovery_pending_sync(
                &tx,
                plan.body.identity,
                plan.body.next_recovery_epoch,
                plan.plan_digest.as_bytes(),
            )
            .map_err(|_| RecoveryError::CorruptReplica)?;
            tx.execute("DELETE FROM session_replication_log", [])
                .map_err(|_| RecoveryError::FileOperationFailed)?;
            tx.execute(
                "UPDATE consensus_machine SET application_sequence = ?1, watch_sequence = ?2 WHERE singleton = 1",
                rusqlite::params![
                    checked_sqlite_high_water(plan.body.application_sequence_high_water)?,
                    checked_sqlite_high_water(plan.body.watch_cursor_invalidation_floor)?,
                ],
            )
            .map_err(|_| RecoveryError::FileOperationFailed)?;
            tx.execute(
                "UPDATE consensus_operator_recovery SET watch_cursor_invalidation_floor = ?1 WHERE singleton = 1",
                [checked_sqlite_high_water(
                    plan.body.watch_cursor_invalidation_floor,
                )?],
            )
            .map_err(|_| RecoveryError::FileOperationFailed)?;
            tx.commit()
                .map_err(|_| RecoveryError::FileOperationFailed)?;
        }
        RecoveryDecisionBasis::ExplicitLegacyCheckpoint => {
            consensus::claim_legacy_checkpoint_sync(
                &conn,
                plan.body.identity,
                &plan.body.expected_members,
                plan.body.source_branch_digest.as_bytes(),
                plan.body.next_recovery_epoch,
                plan.plan_digest.as_bytes(),
                plan.body.application_sequence_high_water,
                plan.body.watch_cursor_invalidation_floor,
            )
            .map_err(|_| RecoveryError::CorruptReplica)?;
            validate_exact_recovery_schema(&conn, true)?;
        }
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;")
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(conn);
    open_regular_read(staged)
        .and_then(|file| file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)?;

    let snapshot = current_snapshot_reference(
        staged,
        plan.body.identity,
        &plan.body.expected_members,
        &paths.snapshots,
        limits,
    )?;
    let source_snapshot_name = if let Some(snapshot) = snapshot {
        copy_file_bounded(&snapshot.path, staged_snapshot, limits.max_snapshot_bytes())?;
        Some(snapshot.file_name)
    } else {
        None
    };
    verify_staged_source(
        key,
        plan,
        source,
        staged,
        staged_snapshot,
        source_snapshot_name.as_deref(),
        limits,
    )?;
    Ok(source_snapshot_name)
}

fn convert_legacy_checkpoint(
    source: &Path,
    destination: &Path,
    limits: RecoveryLimits,
) -> Result<(), RecoveryError> {
    let source_conn = open_read_only(source)?;
    let mut source_budget = InspectionBudget::new(limits);
    validate_database_snapshot(&source_conn, &source_budget)?;
    validate_legacy_schema(&source_conn)?;
    validate_sealed_records(&source_conn, &mut source_budget)?;
    validate_replication_sequence_domain(&source_conn, &mut source_budget, 0)?;
    let before = hash_legacy_state(&source_conn, &mut source_budget)?;

    drop(private_create_new(destination)?);
    drop(
        crate::sqlite::SqliteSessionBackend::open(destination)
            .map_err(|_| RecoveryError::FileOperationFailed)?,
    );
    let mut destination_conn = open_read_write(destination)?;
    let tx = destination_conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    for table in [
        "session_records",
        "leases",
        "key_fences",
        "lease_globals",
        "session_replication_log",
    ] {
        tx.execute(&format!("DELETE FROM {table}"), [])
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    for (table, columns, column_count) in [
        (
            "session_records",
            "tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, state_type, expires_at, payload, encoding",
            12,
        ),
        (
            "leases",
            "tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at",
            10,
        ),
        (
            "key_fences",
            "tenant, nf_kind, key_type, stable_id, fence",
            5,
        ),
        ("lease_globals", "key, val", 2),
        (
            "session_replication_log",
            "sequence, tx_id, entry_json, timestamp",
            4,
        ),
    ] {
        copy_exact_table(&source_conn, &tx, table, columns, column_count)?;
    }
    tx.commit()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;")
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(destination_conn);

    let destination_conn = open_read_only(destination)?;
    validate_legacy_schema(&destination_conn)?;
    let mut destination_budget = InspectionBudget::new(limits);
    let after = hash_legacy_state(&destination_conn, &mut destination_budget)?;
    if before != after {
        return Err(RecoveryError::SourceChanged);
    }
    open_regular_read(destination)
        .and_then(|file| file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)
}

fn copy_exact_table(
    source: &Connection,
    destination: &rusqlite::Transaction<'_>,
    table: &str,
    columns: &str,
    column_count: usize,
) -> Result<(), RecoveryError> {
    let mut statement = source
        .prepare(&format!("SELECT {columns} FROM {table}"))
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut rows = statement
        .query([])
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let placeholders = (1..=column_count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let insert = format!("INSERT INTO {table} ({columns}) VALUES ({placeholders})");
    while let Some(row) = rows.next().map_err(|_| RecoveryError::CorruptReplica)? {
        let values = (0..column_count)
            .map(|column| row.get::<_, Value>(column))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RecoveryError::CorruptReplica)?;
        destination
            .execute(&insert, rusqlite::params_from_iter(values.iter()))
            .map_err(|_| RecoveryError::CorruptReplica)?;
    }
    Ok(())
}

fn verify_staged_source(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    checkpoint: &RecoveryReplica,
    staged: &Path,
    staged_snapshot: &Path,
    source_snapshot_name: Option<&str>,
    limits: RecoveryLimits,
) -> Result<(), RecoveryError> {
    let checkpoint_paths = canonical_replica_paths(checkpoint, false)?;
    let staged_replica = RecoveryReplica::new_bound(
        checkpoint.replica_id.clone(),
        checkpoint.backing_identity.clone(),
        checkpoint.admitted_identity,
        staged.to_path_buf(),
        checkpoint_paths.snapshots,
    );
    let evidence = inspect_replica(InspectionInput {
        key,
        replica: &staged_replica,
        identity: plan.body.identity,
        expected_members: &plan.body.expected_members,
        limits,
    })?;
    let planned_source = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if evidence.pending_recovery_epoch != Some(plan.body.next_recovery_epoch)
        || evidence.pending_plan_digest != Some(plan.plan_digest)
        || evidence.application_sequence != plan.body.application_sequence_high_water
        || evidence.watch_sequence != plan.body.watch_cursor_invalidation_floor
        || evidence.watch_cursor_invalidation_floor != plan.body.watch_cursor_invalidation_floor
        || evidence.fence_high_water > plan.body.fence_high_water
        || evidence.credential_high_water > plan.body.credential_high_water
        || evidence.logical_state_digest != planned_source.logical_state_digest
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    match source_snapshot_name {
        Some(name) => {
            validate_snapshot_name(name)?;
            let reference = current_snapshot_reference(
                staged,
                plan.body.identity,
                &plan.body.expected_members,
                &checkpoint.snapshot_directory,
                limits,
            )?
            .ok_or(RecoveryError::BackupCorrupt)?;
            if reference.file_name != name {
                return Err(RecoveryError::BackupCorrupt);
            }
            let (expected_checksum, expected_length) =
                verify_snapshot_file(&reference.path, limits.max_snapshot_bytes(), None)?;
            let (staged_checksum, staged_length) =
                verify_snapshot_file(staged_snapshot, limits.max_snapshot_bytes(), None)?;
            if expected_checksum != staged_checksum || expected_length != staged_length {
                return Err(RecoveryError::BackupCorrupt);
            }
        }
        None => require_path_absent(staged_snapshot)?,
    }
    Ok(())
}

fn same_checkpoint(observed: &RecoveryReplicaEvidence, planned: &RecoveryReplicaEvidence) -> bool {
    observed.replica_token == planned.replica_token
        && observed.backing_identity == planned.backing_identity
        && observed.format == planned.format
        && observed.cluster_digest == planned.cluster_digest
        && observed.configuration_digest == planned.configuration_digest
        && observed.configuration_epoch == planned.configuration_epoch
        && observed.recovery_epoch == planned.recovery_epoch
        && observed.pending_recovery_epoch == planned.pending_recovery_epoch
        && observed.pending_plan_digest == planned.pending_plan_digest
        && observed.watch_cursor_invalidation_floor == planned.watch_cursor_invalidation_floor
        && observed.application_sequence == planned.application_sequence
        && observed.watch_sequence == planned.watch_sequence
        && observed.committed_index == planned.committed_index
        && observed.applied_index == planned.applied_index
        && observed.local_head_index == planned.local_head_index
        && observed.branch_digest == planned.branch_digest
        && observed.fence_high_water == planned.fence_high_water
        && observed.credential_high_water == planned.credential_high_water
        && observed.logical_state_digest == planned.logical_state_digest
}

fn install_staged_snapshot(
    target: &RecoveryReplica,
    file_name: Option<&str>,
    staged_snapshot: &Path,
    limits: RecoveryLimits,
    resume_partial: bool,
) -> Result<(), RecoveryError> {
    let Some(file_name) = file_name else {
        return Ok(());
    };
    validate_snapshot_name(file_name)?;
    let paths = canonical_replica_paths(target, false)?;
    let temporary = paths.snapshots.join(format!("recovery-{file_name}.part"));
    if resume_partial {
        remove_regular_file_if_present(&temporary)?;
    } else {
        require_path_absent(&temporary)?;
    }
    copy_file_bounded(staged_snapshot, &temporary, limits.max_snapshot_bytes())?;
    fs::rename(&temporary, paths.snapshots.join(file_name))
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    sync_directory(&paths.snapshots)
}

fn require_snapshot_install_temporary_absent(
    target: &RecoveryReplica,
    file_name: Option<&str>,
) -> Result<(), RecoveryError> {
    let Some(file_name) = file_name else {
        return Ok(());
    };
    validate_snapshot_name(file_name)?;
    let paths = canonical_replica_paths(target, false)?;
    require_path_absent(&paths.snapshots.join(format!("recovery-{file_name}.part")))
}

fn verify_installed_snapshot(
    target: &RecoveryReplica,
    file_name: Option<&str>,
    staged_snapshot: &Path,
    limits: RecoveryLimits,
) -> Result<(), RecoveryError> {
    let Some(file_name) = file_name else {
        return Ok(());
    };
    validate_snapshot_name(file_name)?;
    let paths = canonical_replica_paths(target, false)?;
    let expected = verify_snapshot_file(staged_snapshot, limits.max_snapshot_bytes(), None)?;
    let observed = verify_snapshot_file(
        &paths.snapshots.join(file_name),
        limits.max_snapshot_bytes(),
        None,
    )?;
    if observed != expected {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

fn target_matches_staged_recovery(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    staged: &Path,
    limits: RecoveryLimits,
) -> Result<bool, RecoveryError> {
    if verify_target_installed(key, plan, target, limits).is_err() {
        return Ok(false);
    }
    let target = open_read_only(&canonical_replica_paths(target, false)?.database)?;
    let staged = open_read_only(staged)?;
    let (target_epoch, _, target_key) =
        ops::read_restore_scan_state_sync(&target).map_err(|_| RecoveryError::CorruptReplica)?;
    let (staged_epoch, _, staged_key) =
        ops::read_restore_scan_state_sync(&staged).map_err(|_| RecoveryError::CorruptReplica)?;
    Ok(target_epoch != staged_epoch && *target_key != *staged_key)
}

fn verify_target_installed(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    limits: RecoveryLimits,
) -> Result<(), RecoveryError> {
    let evidence = inspect_replica(InspectionInput {
        key,
        replica: target,
        identity: plan.body.identity,
        expected_members: &plan.body.expected_members,
        limits,
    })?;
    let planned_source = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if evidence.pending_recovery_epoch != Some(plan.body.next_recovery_epoch)
        || evidence.pending_plan_digest != Some(plan.plan_digest)
        || evidence.application_sequence != plan.body.application_sequence_high_water
        || evidence.watch_sequence != plan.body.watch_cursor_invalidation_floor
        || evidence.watch_cursor_invalidation_floor != plan.body.watch_cursor_invalidation_floor
        || evidence.logical_state_digest != planned_source.logical_state_digest
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

fn verify_target_finalized(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    limits: RecoveryLimits,
) -> Result<(), RecoveryError> {
    let evidence = inspect_replica(InspectionInput {
        key,
        replica: target,
        identity: plan.body.identity,
        expected_members: &plan.body.expected_members,
        limits,
    })?;
    if evidence.recovery_epoch != plan.body.next_recovery_epoch
        || evidence.pending_recovery_epoch.is_some()
        || evidence.pending_plan_digest.is_some()
        || evidence.application_sequence < plan.body.application_sequence_high_water
        || evidence.watch_sequence < plan.body.watch_cursor_invalidation_floor
        || evidence.watch_cursor_invalidation_floor < plan.body.watch_cursor_invalidation_floor
        || evidence.fence_high_water < plan.body.fence_high_water
        || evidence.credential_high_water < plan.body.credential_high_water
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

fn install_staged_database(
    target: &RecoveryReplica,
    staged: &Path,
    plan: &RecoveryPlan,
    resume_partial: bool,
    #[cfg(test)] failpoint: Option<RecoveryFailpoint>,
) -> Result<(), RecoveryError> {
    let paths = canonical_replica_paths(target, false)?;
    let parent = paths
        .database
        .parent()
        .ok_or(RecoveryError::InvalidRequest)?;
    let temporary = parent.join(format!(
        ".opc-recovery-{}.sqlite",
        &plan.plan_digest.to_hex()[..16]
    ));
    if resume_partial {
        remove_regular_file_if_present(&temporary)?;
    } else {
        require_path_absent(&temporary)?;
    }
    copy_file_bounded(
        staged,
        &temporary,
        fs::metadata(staged)
            .map_err(|_| RecoveryError::FileOperationFailed)?
            .len(),
    )?;
    let conn = open_read_write(&temporary)?;
    ops::rotate_restore_scan_incarnation_sync(&conn)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(conn);
    open_regular_read(&temporary)
        .and_then(|file| file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    #[cfg(test)]
    if failpoint == Some(RecoveryFailpoint::AfterDatabaseTemporaryPrepared) {
        return Err(RecoveryError::InjectedFailure);
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = paths.database.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        remove_regular_file_if_present(&sidecar)?;
    }
    fs::rename(&temporary, &paths.database).map_err(|_| RecoveryError::FileOperationFailed)?;
    sync_directory(parent)
}

fn require_database_install_temporary_absent(
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
) -> Result<(), RecoveryError> {
    let paths = canonical_replica_paths(target, false)?;
    let parent = paths
        .database
        .parent()
        .ok_or(RecoveryError::InvalidRequest)?;
    require_path_absent(&parent.join(format!(
        ".opc-recovery-{}.sqlite",
        &plan.plan_digest.to_hex()[..16]
    )))
}

pub(super) fn resume_execution_state(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<RecoveryExecutionState, RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    read_workflow(key, plan, &directory)?
        .map(|record| record.state)
        .ok_or(RecoveryError::StalePlan)
}

pub(super) fn resume_audit_state(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<Option<RecoveryExecutionState>, RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    let record = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    Ok(record.audit_resume_state)
}

pub(super) fn record_epoch_committed(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<(), RecoveryError> {
    transition_workflow(
        key,
        plan,
        backup_root,
        RecoveryExecutionState::EpochCommitted,
    )
}

pub(super) fn record_rejoined(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<(), RecoveryError> {
    transition_workflow(key, plan, backup_root, RecoveryExecutionState::Rejoined)
}

pub(super) fn record_rejoin_proven(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<(), RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    let mut record = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    if !matches!(
        record.state,
        RecoveryExecutionState::EpochCommitted | RecoveryExecutionState::AuditPending
    ) {
        return Err(RecoveryError::StalePlan);
    }
    record.rejoin_proven = true;
    write_workflow(key, &directory, &record)
}

pub(super) fn record_audit_pending(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<(), RecoveryError> {
    transition_workflow(key, plan, backup_root, RecoveryExecutionState::AuditPending)
}

pub(super) fn transition_after_audit(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
    resume: RecoveryExecutionState,
) -> Result<(), RecoveryError> {
    transition_workflow(key, plan, backup_root, resume)
}

#[cfg(test)]
pub(super) fn prepare_test_workflow(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
    state: RecoveryExecutionState,
) -> Result<(), RecoveryError> {
    let directory = workflow_directory(backup_root, plan, true)?;
    write_workflow(
        key,
        &directory,
        &WorkflowRecord {
            version: WORKFLOW_VERSION,
            plan_digest: plan.plan_digest,
            source_branch_digest: plan.body.source_branch_digest,
            target_tokens: plan.body.target_tokens.clone(),
            state,
            audit_resume_state: (state == RecoveryExecutionState::AuditPending)
                .then_some(RecoveryExecutionState::AwaitingEpochCommit),
            rejoin_proven: state == RecoveryExecutionState::Rejoined,
            checkpoint_database_digest: None,
            checkpoint_snapshot_digest: None,
            staged_database_digest: None,
            source_snapshot_name: None,
            checkpoint_progress: FileProgress::Pending,
            staged_progress: FileProgress::Pending,
            target_backups: plan
                .body
                .target_tokens
                .iter()
                .map(|token| (token.to_hex(), FileProgress::Pending))
                .collect(),
            target_installs: plan
                .body
                .target_tokens
                .iter()
                .copied()
                .map(|token| {
                    let progress = if matches!(
                        state,
                        RecoveryExecutionState::AwaitingEpochCommit
                            | RecoveryExecutionState::EpochCommitted
                            | RecoveryExecutionState::Rejoined
                            | RecoveryExecutionState::AuditPending
                    ) {
                        TargetInstallState::DatabaseInstalled
                    } else {
                        TargetInstallState::Pending
                    };
                    (token.to_hex(), progress)
                })
                .collect(),
        },
    )
}

fn transition_workflow(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
    state: RecoveryExecutionState,
) -> Result<(), RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    let mut record = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    transition_record_state(&mut record, state)?;
    write_workflow(key, &directory, &record)
}

fn transition_record_state(
    record: &mut WorkflowRecord,
    next: RecoveryExecutionState,
) -> Result<(), RecoveryError> {
    if record.state == next {
        return Ok(());
    }
    if record.state == RecoveryExecutionState::AuditPending {
        if record.audit_resume_state != Some(next) {
            return Err(RecoveryError::StalePlan);
        }
        record.state = next;
        record.audit_resume_state = None;
        return Ok(());
    }
    if next == RecoveryExecutionState::AuditPending {
        record.audit_resume_state = Some(record.state);
        record.state = next;
        return Ok(());
    }
    let allowed = matches!(
        (record.state, next),
        (
            RecoveryExecutionState::Planned,
            RecoveryExecutionState::BackupVerified
        ) | (
            RecoveryExecutionState::BackupVerified,
            RecoveryExecutionState::AwaitingEpochCommit
        ) | (
            RecoveryExecutionState::AwaitingEpochCommit,
            RecoveryExecutionState::EpochCommitted
        ) | (
            RecoveryExecutionState::EpochCommitted,
            RecoveryExecutionState::Rejoined
        )
    );
    if !allowed {
        return Err(RecoveryError::StalePlan);
    }
    if next == RecoveryExecutionState::Rejoined && !record.rejoin_proven {
        return Err(RecoveryError::StalePlan);
    }
    record.state = next;
    Ok(())
}

fn validate_workflow_shape(
    plan: &RecoveryPlan,
    record: &WorkflowRecord,
) -> Result<(), RecoveryError> {
    let expected_targets = plan
        .body
        .target_tokens
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let observed_targets = record
        .target_installs
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed_backups = record
        .target_backups
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if expected_targets != observed_targets
        || expected_targets != observed_backups
        || (record.state == RecoveryExecutionState::AuditPending)
            != record.audit_resume_state.is_some()
        || record
            .audit_resume_state
            .is_some_and(|state| state == RecoveryExecutionState::AuditPending)
        || record.rejoin_proven
            && !matches!(
                record.state,
                RecoveryExecutionState::EpochCommitted
                    | RecoveryExecutionState::Rejoined
                    | RecoveryExecutionState::AuditPending
            )
        || record.checkpoint_database_digest.is_some()
            != (record.checkpoint_progress == FileProgress::Verified)
        || record.staged_database_digest.is_some()
            != (record.staged_progress == FileProgress::Verified)
        || matches!(
            record.state,
            RecoveryExecutionState::AwaitingEpochCommit
                | RecoveryExecutionState::EpochCommitted
                | RecoveryExecutionState::Rejoined
                | RecoveryExecutionState::AuditPending
        ) && record
            .target_installs
            .values()
            .any(|state| *state != TargetInstallState::DatabaseInstalled)
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

fn workflow_directory(
    backup_root: &Path,
    plan: &RecoveryPlan,
    create: bool,
) -> Result<PathBuf, RecoveryError> {
    validate_path_text(backup_root)?;
    if create {
        create_private_directory(backup_root)?;
    } else {
        validate_private_directory(backup_root)?;
    }
    let root = fs::canonicalize(backup_root).map_err(|_| RecoveryError::FileOperationFailed)?;
    validate_private_directory(&root)?;
    let directory = root.join(format!("recovery-{}", plan.plan_digest));
    if create {
        create_private_directory(&directory)?;
    } else {
        validate_private_directory(&directory)?;
    }
    Ok(directory)
}

fn create_private_directory(path: &Path) -> Result<(), RecoveryError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(path)
                .map_err(|_| RecoveryError::FileOperationFailed)?;
            set_private_directory_permissions(path)?;
            validate_private_directory(path)
        }
        Err(_) => Err(RecoveryError::FileOperationFailed),
    }
}

fn validate_private_directory(path: &Path) -> Result<(), RecoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RecoveryError::FileOperationFailed)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(RecoveryError::FileOperationFailed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(RecoveryError::FileOperationFailed);
        }
    }
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> Result<(), RecoveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    Ok(())
}

fn validate_private_file(path: &Path) -> Result<fs::Metadata, RecoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RecoveryError::BackupCorrupt)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(RecoveryError::BackupCorrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    Ok(metadata)
}

fn private_create_new(path: &Path) -> Result<File, RecoveryError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    Ok(file)
}

fn read_workflow(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    directory: &Path,
) -> Result<Option<WorkflowRecord>, RecoveryError> {
    let path = directory.join("workflow.json");
    if !path.exists() {
        return Ok(None);
    }
    let sealed: SealedWorkflowRecord = read_bounded_json(&path, 64 * 1024)?;
    let encoded = serde_json::to_vec(&sealed.record).map_err(|_| RecoveryError::BackupCorrupt)?;
    verify_mac(key, WORKFLOW_MAC_DOMAIN, &[&encoded], sealed.mac)?;
    if sealed.record.version != WORKFLOW_VERSION
        || sealed.record.plan_digest != plan.plan_digest
        || sealed.record.source_branch_digest != plan.body.source_branch_digest
        || sealed.record.target_tokens != plan.body.target_tokens
    {
        return Err(RecoveryError::StalePlan);
    }
    validate_workflow_shape(plan, &sealed.record)?;
    Ok(Some(sealed.record))
}

fn write_workflow(
    key: &RecoveryIntegrityKey,
    directory: &Path,
    record: &WorkflowRecord,
) -> Result<(), RecoveryError> {
    let encoded = serde_json::to_vec(record).map_err(|_| RecoveryError::FileOperationFailed)?;
    let mac = RecoveryDigest::from_bytes(plan_mac(key, WORKFLOW_MAC_DOMAIN, &[&encoded])?);
    atomic_write_json(
        &directory.join("workflow.json"),
        &SealedWorkflowRecord {
            record: record.clone(),
            mac,
        },
    )?;
    sync_directory(directory)
}

struct SnapshotReference {
    file_name: String,
    path: PathBuf,
}

fn current_snapshot_reference(
    database: &Path,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    snapshot_dir: &Path,
    limits: RecoveryLimits,
) -> Result<Option<SnapshotReference>, RecoveryError> {
    let conn = open_read_only(database)?;
    if !table_exists(&conn, "consensus_identity")? {
        return Ok(None);
    }
    let snapshot = consensus::read_current_snapshot_sync(&conn, identity, expected_members)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let Some((_, file_name, expected_checksum, expected_length)) = snapshot else {
        return Ok(None);
    };
    validate_snapshot_name(&file_name)?;
    let path = snapshot_dir.join(&file_name);
    let (checksum, length) = verify_snapshot_file(&path, limits.max_snapshot_bytes(), None)?;
    if checksum != expected_checksum || length != expected_length {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(Some(SnapshotReference { file_name, path }))
}

fn verify_snapshot_file(
    path: &Path,
    max_bytes: u64,
    budget: Option<&InspectionBudget>,
) -> Result<([u8; 32], u64), RecoveryError> {
    if let Some(budget) = budget {
        budget.check()?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| RecoveryError::CorruptReplica)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() <= SNAPSHOT_FOOTER_BYTES
        || metadata.len() > max_bytes
    {
        return Err(RecoveryError::CorruptReplica);
    }
    let mut file = open_regular_read(path).map_err(|_| RecoveryError::CorruptReplica)?;
    let total = metadata.len();
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::End(
        -i64::try_from(SNAPSHOT_FOOTER_BYTES).map_err(|_| RecoveryError::CorruptReplica)?,
    ))
    .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut footer = [0_u8; SNAPSHOT_FOOTER_BYTES as usize];
    file.read_exact(&mut footer)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if &footer[..8] != SNAPSHOT_FOOTER_MAGIC {
        return Err(RecoveryError::CorruptReplica);
    }
    let length = u64::from_be_bytes(
        footer[8..16]
            .try_into()
            .map_err(|_| RecoveryError::CorruptReplica)?,
    );
    let expected: [u8; 32] = footer[16..]
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if length == 0 || length.checked_add(SNAPSHOT_FOOTER_BYTES) != Some(total) {
        return Err(RecoveryError::CorruptReplica);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut limited = file.take(length);
    let mut hasher = Sha256::new();
    let copied = hash_reader(&mut limited, &mut hasher, length, budget)?;
    let actual: [u8; 32] = hasher.finalize().into();
    if copied != length || actual != expected {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok((actual, total))
}

fn canonical_replica_paths(
    replica: &RecoveryReplica,
    allow_missing: bool,
) -> Result<CanonicalReplicaPaths, RecoveryError> {
    validate_path_text(&replica.database_path)?;
    validate_path_text(&replica.snapshot_directory)?;
    match fs::symlink_metadata(&replica.database_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            return Err(RecoveryError::InvalidRequest);
        }
        Ok(_) => {}
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(RecoveryError::DatabaseUnavailable),
    }
    let raw_snapshot_metadata = fs::symlink_metadata(&replica.snapshot_directory)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    if raw_snapshot_metadata.file_type().is_symlink() || !raw_snapshot_metadata.file_type().is_dir()
    {
        return Err(RecoveryError::InvalidRequest);
    }
    let database = if allow_missing {
        replica.database_path.clone()
    } else {
        fs::canonicalize(&replica.database_path).map_err(|_| RecoveryError::DatabaseUnavailable)?
    };
    let snapshots = fs::canonicalize(&replica.snapshot_directory)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let database_metadata =
        fs::symlink_metadata(&database).map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let snapshot_metadata =
        fs::symlink_metadata(&snapshots).map_err(|_| RecoveryError::DatabaseUnavailable)?;
    if database_metadata.file_type().is_symlink()
        || (!allow_missing && !database_metadata.file_type().is_file())
        || snapshot_metadata.file_type().is_symlink()
        || !snapshot_metadata.file_type().is_dir()
    {
        return Err(RecoveryError::InvalidRequest);
    }
    Ok(CanonicalReplicaPaths {
        database,
        snapshots,
    })
}

fn recovery_path_binding(
    key: &RecoveryIntegrityKey,
    paths: &CanonicalReplicaPaths,
) -> Result<RecoveryDigest, RecoveryError> {
    let database = paths
        .database
        .to_str()
        .ok_or(RecoveryError::InvalidRequest)?;
    let snapshots = paths
        .snapshots
        .to_str()
        .ok_or(RecoveryError::InvalidRequest)?;
    Ok(RecoveryDigest::from_bytes(plan_mac(
        key,
        PATH_BINDING_DOMAIN,
        &[database.as_bytes(), snapshots.as_bytes()],
    )?))
}

fn recovery_file_identity(
    key: &RecoveryIntegrityKey,
    metadata: &fs::Metadata,
) -> Result<RecoveryDigest, RecoveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(RecoveryDigest::from_bytes(plan_mac(
            key,
            FILE_IDENTITY_DOMAIN,
            &[&metadata.dev().to_be_bytes(), &metadata.ino().to_be_bytes()],
        )?))
    }
    #[cfg(not(unix))]
    {
        let _ = (key, metadata);
        Err(RecoveryError::InvalidRequest)
    }
}

fn validate_path_text(path: &Path) -> Result<(), RecoveryError> {
    let value = path.to_str().ok_or(RecoveryError::InvalidRequest)?;
    if value.is_empty() || value.len() > PATH_MAX_BYTES || value.chars().any(char::is_control) {
        return Err(RecoveryError::InvalidRequest);
    }
    Ok(())
}

fn open_read_only(path: &Path) -> Result<Connection, RecoveryError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    conn.execute_batch(
        "PRAGMA query_only = ON; PRAGMA trusted_schema = OFF; BEGIN DEFERRED TRANSACTION;",
    )
    .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    Ok(conn)
}

fn open_read_write(path: &Path) -> Result<Connection, RecoveryError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| RecoveryError::FileOperationFailed)?;
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    Ok(conn)
}

fn validate_database_snapshot(
    conn: &Connection,
    budget: &InspectionBudget,
) -> Result<(), RecoveryError> {
    budget.check()?;
    let result: String = conn
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|error| inspection_sql_error(error, budget))?;
    budget.check()?;
    if result != "ok" {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, RecoveryError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
    .map_err(|_| RecoveryError::CorruptReplica)
}

fn sqlite_backup(source: &Path, destination: &Path, max: u64) -> Result<(), RecoveryError> {
    let source_metadata = fs::metadata(source).map_err(|_| RecoveryError::FileOperationFailed)?;
    if source_metadata.len() == 0 || source_metadata.len() > max {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    let source = open_read_only(source)?;
    drop(private_create_new(destination)?);
    let mut destination_conn = Connection::open_with_flags(
        destination,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| RecoveryError::FileOperationFailed)?;
    {
        let backup = Backup::new(&source, &mut destination_conn)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        backup
            .run_to_completion(128, Duration::ZERO, None)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    destination_conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;")
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(destination_conn);
    let metadata = fs::metadata(destination).map_err(|_| RecoveryError::FileOperationFailed)?;
    if metadata.len() == 0 || metadata.len() > max {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    open_regular_read(destination)
        .and_then(|file| file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)
}

fn copy_file_bounded(source: &Path, destination: &Path, max: u64) -> Result<(), RecoveryError> {
    let source_metadata =
        fs::symlink_metadata(source).map_err(|_| RecoveryError::FileOperationFailed)?;
    if !source_metadata.file_type().is_file()
        || source_metadata.file_type().is_symlink()
        || source_metadata.len() == 0
        || source_metadata.len() > max
    {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    let mut source_file =
        open_regular_read(source).map_err(|_| RecoveryError::FileOperationFailed)?;
    let mut destination_file = private_create_new(destination)?;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let read = source_file
            .read(&mut buffer)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| RecoveryError::WorkLimitExceeded)?)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if copied > max {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        destination_file
            .write_all(&buffer[..read])
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    if copied != source_metadata.len() {
        return Err(RecoveryError::SourceChanged);
    }
    destination_file
        .flush()
        .and_then(|_| destination_file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)
}

fn digest_file(path: &Path, max: u64) -> Result<(RecoveryDigest, u64), RecoveryError> {
    let metadata = validate_private_file(path)?;
    if metadata.len() == 0 || metadata.len() > max {
        return Err(RecoveryError::BackupCorrupt);
    }
    let mut file = open_regular_read(path).map_err(|_| RecoveryError::BackupCorrupt)?;
    let mut hasher = Sha256::new();
    hasher.update(FILE_DIGEST_DOMAIN);
    let length = hash_reader(&mut file, &mut hasher, max, None)?;
    if length != metadata.len() {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok((RecoveryDigest::from_bytes(hasher.finalize().into()), length))
}

fn hash_reader(
    reader: &mut impl Read,
    hasher: &mut Sha256,
    max: u64,
    budget: Option<&InspectionBudget>,
) -> Result<u64, RecoveryError> {
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        if let Some(budget) = budget {
            budget.check()?;
        }
        let read = reader
            .read(&mut buffer)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| RecoveryError::WorkLimitExceeded)?)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if total > max {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(total)
}

fn validate_snapshot_name(name: &str) -> Result<(), RecoveryError> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(())
}

fn feed_json<T: Serialize>(hasher: &mut Sha256, value: &T) -> Result<(), RecoveryError> {
    let encoded = serde_json::to_vec(value).map_err(|_| RecoveryError::CorruptReplica)?;
    hasher.update(
        u64::try_from(encoded.len())
            .map_err(|_| RecoveryError::WorkLimitExceeded)?
            .to_be_bytes(),
    );
    hasher.update(encoded);
    Ok(())
}

fn verify_mac(
    key: &RecoveryIntegrityKey,
    domain: &[u8],
    parts: &[&[u8]],
    observed: RecoveryDigest,
) -> Result<(), RecoveryError> {
    let mut verifier = hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    verifier.update(domain);
    for part in parts {
        verifier.update(
            &u64::try_from(part.len())
                .map_err(|_| RecoveryError::BackupCorrupt)?
                .to_be_bytes(),
        );
        verifier.update(part);
    }
    verifier
        .verify_slice(&observed.as_bytes())
        .map_err(|_| RecoveryError::BackupCorrupt)
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), RecoveryError> {
    let parent = path.parent().ok_or(RecoveryError::FileOperationFailed)?;
    let temporary = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(RecoveryError::FileOperationFailed)?
    ));
    remove_regular_file_if_present(&temporary)?;
    let encoded = serde_json::to_vec(value).map_err(|_| RecoveryError::FileOperationFailed)?;
    let mut file = private_create_new(&temporary)?;
    file.write_all(&encoded)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(file);
    fs::rename(&temporary, path).map_err(|_| RecoveryError::FileOperationFailed)?;
    sync_directory(parent)
}

fn read_bounded_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    max: u64,
) -> Result<T, RecoveryError> {
    let metadata = validate_private_file(path)?;
    if metadata.len() == 0 || metadata.len() > max {
        return Err(RecoveryError::BackupCorrupt);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| RecoveryError::BackupCorrupt)?,
    );
    open_regular_read(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    serde_json::from_slice(&bytes).map_err(|_| RecoveryError::BackupCorrupt)
}

fn remove_regular_file_if_present(path: &Path) -> Result<(), RecoveryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(RecoveryError::FileOperationFailed);
            }
            fs::remove_file(path).map_err(|_| RecoveryError::FileOperationFailed)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RecoveryError::FileOperationFailed),
    }
}

fn require_path_absent(path: &Path) -> Result<(), RecoveryError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(RecoveryError::FileOperationFailed),
    }
}

fn sync_directory(path: &Path) -> Result<(), RecoveryError> {
    open_directory(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)
}

fn open_regular_read(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY);
    }
    options.open(path)
}
