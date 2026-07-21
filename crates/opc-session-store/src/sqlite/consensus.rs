//! Fail-closed SQLite persistence for the Openraft session state machine.
//!
//! This module contains synchronous transaction primitives. The Openraft
//! adapter in `consensus::storage` owns async locking and maps these coarse,
//! redaction-safe failures into Openraft storage errors.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use opc_consensus::engine::{Entry, EntryPayload, LogId, StoredMembership, Vote};
use opc_consensus::{AppendEntriesBatchAccumulator, AppendEntriesBatchDecision};
use opc_types::Timestamp;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::backend::{
    CompareAndSetResult, ReplicationEntry, ReplicationOp, ReplicationTxId,
    REPLICATION_TX_ID_MAX_BYTES, REPLICATION_TX_ID_MIN_BYTES,
};
use crate::capability::BackendCapabilities;
use crate::consensus::storage::SessionConsensusStorageError;
use crate::consensus::types::{
    SessionConsensusCommand, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
    SessionConsensusEntryDigest, SessionConsensusIdentity, SessionConsensusNodeId,
    SessionConsensusRequestId, SessionConsensusResponse, SessionMutationIntent,
    SessionMutationOutcome, SessionTopologyMemberBinding, SESSION_CONSENSUS_SCHEMA_VERSION,
};
use crate::consensus::SessionRaftTypeConfig;
use crate::error::{LeaseError, StoreError};
use crate::record::SessionPayloadEncoding;

use super::{lease, ops, SqliteSessionBackend};

const CONSENSUS_LOG_ENTRY_MAX_BYTES: usize = 16 * 1024 * 1024;
const MEMBERSHIP_SCOPE_MEMBERS_MAX_BYTES: usize = 1_024;
const MEMBERSHIP_SCOPE_BINDINGS_MAX_BYTES: usize = 32 * 1_024;
const MEMBERSHIP_HISTORY_MAX_ENTRIES: usize = 4_096;
const MEMBERSHIP_TRANSITION_ID_BYTES: usize = 16;
const OUTCOME_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/outcome-payload/v1\0";
const OPERATOR_RECOVERY_LATCH_MAGIC: &[u8; 8] = b"OPCRL001";
const OPERATOR_RECOVERY_LATCH_BYTES: usize = 8 + 32 + 32 + 8 + 8 + 32 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OperatorRecoveryLatch {
    pub(crate) identity: SessionConsensusIdentity,
    pub(crate) recovery_epoch: u64,
    pub(crate) plan_digest: [u8; 32],
    pub(crate) audit_pending: bool,
}

pub(crate) fn operator_recovery_latch_path(database: &Path) -> io::Result<PathBuf> {
    let name = database
        .file_name()
        .ok_or_else(|| invalid_data("session recovery database path has no file name"))?;
    let mut latch_name = name.to_os_string();
    latch_name.push(".opc-recovery-latch");
    Ok(database.with_file_name(latch_name))
}

fn encode_operator_recovery_latch(
    latch: OperatorRecoveryLatch,
) -> [u8; OPERATOR_RECOVERY_LATCH_BYTES] {
    let mut encoded = [0_u8; OPERATOR_RECOVERY_LATCH_BYTES];
    encoded[..8].copy_from_slice(OPERATOR_RECOVERY_LATCH_MAGIC);
    encoded[8..40].copy_from_slice(latch.identity.cluster_id().as_bytes());
    encoded[40..72].copy_from_slice(latch.identity.configuration_id().as_bytes());
    encoded[72..80].copy_from_slice(&latch.identity.configuration_epoch().get().to_be_bytes());
    encoded[80..88].copy_from_slice(&latch.recovery_epoch.to_be_bytes());
    encoded[88..120].copy_from_slice(&latch.plan_digest);
    encoded[120] = u8::from(latch.audit_pending);
    encoded
}

fn decode_operator_recovery_latch(
    encoded: &[u8; OPERATOR_RECOVERY_LATCH_BYTES],
) -> io::Result<OperatorRecoveryLatch> {
    if &encoded[..8] != OPERATOR_RECOVERY_LATCH_MAGIC || encoded[120] > 1 {
        return Err(invalid_data("session operator recovery latch is invalid"));
    }
    let cluster = encoded[8..40]
        .try_into()
        .map_err(|_| invalid_data("session operator recovery latch is invalid"))?;
    let configuration = encoded[40..72]
        .try_into()
        .map_err(|_| invalid_data("session operator recovery latch is invalid"))?;
    let configuration_epoch = u64::from_be_bytes(
        encoded[72..80]
            .try_into()
            .map_err(|_| invalid_data("session operator recovery latch is invalid"))?,
    );
    let recovery_epoch = u64::from_be_bytes(
        encoded[80..88]
            .try_into()
            .map_err(|_| invalid_data("session operator recovery latch is invalid"))?,
    );
    let plan_digest = encoded[88..120]
        .try_into()
        .map_err(|_| invalid_data("session operator recovery latch is invalid"))?;
    if recovery_epoch == 0 || plan_digest == [0; 32] {
        return Err(invalid_data("session operator recovery latch is invalid"));
    }
    let epoch = SessionConsensusConfigurationEpoch::new(configuration_epoch)
        .map_err(|_| invalid_data("session operator recovery latch is invalid"))?;
    Ok(OperatorRecoveryLatch {
        identity: SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::from_bytes(cluster),
            SessionConsensusConfigurationId::from_bytes(configuration),
            epoch,
        ),
        recovery_epoch,
        plan_digest,
        audit_pending: encoded[120] == 1,
    })
}

fn open_latch_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

pub(crate) fn read_operator_recovery_latch_sync(
    database: &Path,
) -> io::Result<Option<OperatorRecoveryLatch>> {
    let path = operator_recovery_latch_path(database)?;
    let mut file = match open_latch_read(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != OPERATOR_RECOVERY_LATCH_BYTES as u64 {
        return Err(invalid_data("session operator recovery latch is invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid_data(
                "session operator recovery latch permissions are invalid",
            ));
        }
    }
    let mut encoded = [0_u8; OPERATOR_RECOVERY_LATCH_BYTES];
    file.read_exact(&mut encoded)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(invalid_data("session operator recovery latch is oversized"));
    }
    decode_operator_recovery_latch(&encoded).map(Some)
}

fn write_latch_file(path: &Path, latch: OperatorRecoveryLatch, create_new: bool) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(!create_new)
        .create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    file.write_all(&encode_operator_recovery_latch(latch))?;
    file.flush()?;
    file.sync_all()?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| invalid_data("session recovery latch has no parent"))?,
    )?
    .sync_all()
}

pub(crate) fn ensure_operator_recovery_latch_sync(
    database: &Path,
    expected: OperatorRecoveryLatch,
) -> io::Result<()> {
    match read_operator_recovery_latch_sync(database)? {
        Some(observed)
            if observed == expected
                || (observed
                    == OperatorRecoveryLatch {
                        audit_pending: !expected.audit_pending,
                        ..expected
                    }) =>
        {
            Ok(())
        }
        Some(_) => Err(invalid_data(
            "a different session operator recovery latch is active",
        )),
        None => write_latch_file(&operator_recovery_latch_path(database)?, expected, true),
    }
}

pub(crate) fn set_operator_recovery_latch_audit_pending_sync(
    database: &Path,
    expected: OperatorRecoveryLatch,
    audit_pending: bool,
) -> io::Result<()> {
    let observed = read_operator_recovery_latch_sync(database)?
        .ok_or_else(|| invalid_data("session operator recovery latch is missing"))?;
    if observed.identity != expected.identity
        || observed.recovery_epoch != expected.recovery_epoch
        || observed.plan_digest != expected.plan_digest
    {
        return Err(invalid_data(
            "session operator recovery latch does not match",
        ));
    }
    let path = operator_recovery_latch_path(database)?;
    let temporary = path.with_extension("opc-recovery-latch.tmp");
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    write_latch_file(
        &temporary,
        OperatorRecoveryLatch {
            audit_pending,
            ..observed
        },
        true,
    )?;
    std::fs::rename(&temporary, &path)?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| invalid_data("session recovery latch has no parent"))?,
    )?
    .sync_all()
}

pub(crate) fn clear_operator_recovery_latch_sync(
    database: &Path,
    expected: OperatorRecoveryLatch,
) -> io::Result<()> {
    let Some(observed) = read_operator_recovery_latch_sync(database)? else {
        return Ok(());
    };
    if observed.identity != expected.identity
        || observed.recovery_epoch != expected.recovery_epoch
        || observed.plan_digest != expected.plan_digest
        || observed.audit_pending
    {
        return Err(invalid_data(
            "session operator recovery latch cannot be cleared",
        ));
    }
    let path = operator_recovery_latch_path(database)?;
    std::fs::remove_file(&path)?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| invalid_data("session recovery latch has no parent"))?,
    )?
    .sync_all()
}

type ConsensusAppliedMembership = (
    Option<LogId<SessionConsensusNodeId>>,
    StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
);

/// Exact durable identity history admitted for one bounded membership change.
///
/// The original `consensus_identity` row remains the immutable database
/// incarnation used by the legacy foreign-key columns. This scope is the
/// authoritative membership epoch. Keeping those concepts separate lets old
/// log entries retain their exact command identity until Openraft has
/// snapshotted and purged them instead of rewriting authenticated history.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MembershipValidationScope {
    pub(crate) current_identity: SessionConsensusIdentity,
    pub(crate) current_members: BTreeSet<SessionConsensusNodeId>,
    pub(crate) current_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    pub(crate) application_authority_epoch: SessionConsensusConfigurationEpoch,
    pub(crate) application_authority_members: BTreeSet<SessionConsensusNodeId>,
    pub(crate) predecessor: Option<MembershipPredecessorScope>,
    pub(crate) history: Vec<MembershipPredecessorScope>,
    pub(crate) pending: Option<PendingMembershipScope>,
    pub(crate) terminal: Option<TerminalMembershipTransition>,
}

impl fmt::Debug for MembershipValidationScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MembershipValidationScope")
            .field(
                "current_epoch",
                &self.current_identity.configuration_epoch(),
            )
            .field("current_member_count", &self.current_members.len())
            .field("current_binding_count", &self.current_bindings.len())
            .field("authority_epoch", &self.application_authority_epoch)
            .field(
                "authority_member_count",
                &self.application_authority_members.len(),
            )
            .field(
                "predecessor_epoch",
                &self
                    .predecessor
                    .as_ref()
                    .map(|scope| scope.identity.configuration_epoch()),
            )
            .field("history_depth", &self.history.len())
            .field(
                "pending_epoch",
                &self
                    .pending
                    .as_ref()
                    .map(|scope| scope.desired_identity.configuration_epoch()),
            )
            .field(
                "terminal_outcome",
                &self.terminal.as_ref().map(|terminal| terminal.outcome),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MembershipPredecessorScope {
    pub(crate) transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    pub(crate) transition_digest: [u8; 32],
    pub(crate) identity: SessionConsensusIdentity,
    pub(crate) members: BTreeSet<SessionConsensusNodeId>,
    pub(crate) transition_start_log_index: u64,
    pub(crate) cutover_log_index: u64,
}

impl fmt::Debug for MembershipPredecessorScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MembershipPredecessorScope")
            .field("transition_id", &"<redacted>")
            .field("transition_digest", &"<redacted>")
            .field("epoch", &self.identity.configuration_epoch())
            .field("member_count", &self.members.len())
            .field(
                "transition_start_log_index",
                &self.transition_start_log_index,
            )
            .field("cutover_log_index", &self.cutover_log_index)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PendingMembershipScope {
    pub(crate) transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    pub(crate) transition_digest: [u8; 32],
    pub(crate) desired_identity: SessionConsensusIdentity,
    pub(crate) desired_members: BTreeSet<SessionConsensusNodeId>,
    pub(crate) desired_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    pub(crate) transition_start_log_index: u64,
    pub(crate) learners_ready_log_index: Option<u64>,
    pub(crate) joint_membership_log_index: Option<u64>,
    pub(crate) uniform_membership_log_index: Option<u64>,
}

impl fmt::Debug for PendingMembershipScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingMembershipScope")
            .field("transition_id", &"<redacted>")
            .field("transition_digest", &"<redacted>")
            .field(
                "desired_epoch",
                &self.desired_identity.configuration_epoch(),
            )
            .field("desired_member_count", &self.desired_members.len())
            .field("desired_binding_count", &self.desired_bindings.len())
            .field(
                "transition_start_log_index",
                &self.transition_start_log_index,
            )
            .field("learners_ready_log_index", &self.learners_ready_log_index)
            .field(
                "joint_membership_log_index",
                &self.joint_membership_log_index,
            )
            .field(
                "uniform_membership_log_index",
                &self.uniform_membership_log_index,
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalMembershipOutcome {
    Aborted,
    Promoted,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TerminalMembershipTransition {
    pub(crate) transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    pub(crate) transition_digest: [u8; 32],
    pub(crate) outcome: TerminalMembershipOutcome,
    pub(crate) transition_start_log_index: u64,
    pub(crate) learners_ready_log_index: Option<u64>,
    pub(crate) joint_membership_log_index: Option<u64>,
    pub(crate) uniform_membership_log_index: Option<u64>,
    pub(crate) cutover_log_index: Option<u64>,
    pub(crate) finalization_log_index: Option<u64>,
}

impl fmt::Debug for TerminalMembershipTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalMembershipTransition")
            .field("transition_id", &"<redacted>")
            .field("transition_digest", &"<redacted>")
            .field("outcome", &self.outcome)
            .field(
                "transition_start_log_index",
                &self.transition_start_log_index,
            )
            .field("learners_ready_log_index", &self.learners_ready_log_index)
            .field(
                "joint_membership_log_index",
                &self.joint_membership_log_index,
            )
            .field(
                "uniform_membership_log_index",
                &self.uniform_membership_log_index,
            )
            .field("cutover_log_index", &self.cutover_log_index)
            .field("finalization_log_index", &self.finalization_log_index)
            .finish()
    }
}

/// Restart-safe progress for one exact membership transition.
///
/// Identifiers and digests are accepted as lookup keys and deliberately not
/// returned or formatted, keeping status reporting redaction-safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MembershipTransitionEvidence {
    pub(crate) outcome: Option<TerminalMembershipOutcome>,
    pub(crate) transition_start_log_index: u64,
    pub(crate) learners_ready_log_index: Option<u64>,
    pub(crate) joint_membership_log_index: Option<u64>,
    pub(crate) uniform_membership_log_index: Option<u64>,
    pub(crate) cutover_log_index: Option<u64>,
    pub(crate) finalization_log_index: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MembershipScopeMutation {
    Applied,
    Idempotent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MembershipScopeMutationError {
    InvalidScope,
    ConflictingTransition,
    CompactionRequired,
    TransitionNotQuiescent,
    BackendUnavailable,
    CorruptState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DroppedMembershipPredecessor {
    /// Snapshot metadata invalidated by the compaction proof. The caller owns
    /// redaction-safe deletion of the SDK-controlled file after commit.
    pub(crate) invalidated_snapshot_file: Option<String>,
}

impl fmt::Display for MembershipScopeMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidScope => "session consensus membership scope is invalid",
            Self::ConflictingTransition => {
                "a different session consensus membership transition is active"
            }
            Self::CompactionRequired => {
                "session consensus membership history requires snapshot compaction"
            }
            Self::TransitionNotQuiescent => {
                "session consensus membership transition is not quiescent"
            }
            Self::BackendUnavailable => "session consensus membership storage is unavailable",
            Self::CorruptState => "session consensus membership storage is corrupt",
        })
    }
}

impl std::error::Error for MembershipScopeMutationError {}

fn membership_scope_error(error: MembershipScopeMutationError) -> io::Error {
    match error {
        MembershipScopeMutationError::BackendUnavailable => {
            io::Error::other("session consensus membership storage is unavailable")
        }
        MembershipScopeMutationError::InvalidScope
        | MembershipScopeMutationError::ConflictingTransition
        | MembershipScopeMutationError::CompactionRequired
        | MembershipScopeMutationError::TransitionNotQuiescent
        | MembershipScopeMutationError::CorruptState => {
            invalid_data("session consensus membership storage is inconsistent")
        }
    }
}

const CONSENSUS_SCHEMA: &str = r#"
CREATE TABLE consensus_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    cluster_id BLOB NOT NULL CHECK (length(cluster_id) = 32),
    configuration_id BLOB NOT NULL CHECK (length(configuration_id) = 32),
    configuration_epoch INTEGER NOT NULL UNIQUE CHECK (configuration_epoch > 0)
);

CREATE TABLE consensus_membership_scope (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    storage_configuration_epoch INTEGER NOT NULL CHECK (storage_configuration_epoch > 0),
    current_configuration_id BLOB NOT NULL CHECK (length(current_configuration_id) = 32),
    current_configuration_epoch INTEGER NOT NULL CHECK (current_configuration_epoch > 0),
    current_members_json BLOB NOT NULL CHECK (
        length(current_members_json) BETWEEN 2 AND 1024
    ),
    current_bindings_json BLOB NOT NULL CHECK (
        length(current_bindings_json) BETWEEN 2 AND 32768
    ),
    application_authority_epoch INTEGER NOT NULL CHECK (
        application_authority_epoch > 0
    ),
    application_authority_members_json BLOB NOT NULL CHECK (
        length(application_authority_members_json) BETWEEN 2 AND 1024
    ),
    predecessor_configuration_id BLOB CHECK (
        predecessor_configuration_id IS NULL OR length(predecessor_configuration_id) = 32
    ),
    predecessor_transition_id BLOB CHECK (
        predecessor_transition_id IS NULL OR length(predecessor_transition_id) = 16
    ),
    predecessor_transition_digest BLOB CHECK (
        predecessor_transition_digest IS NULL OR length(predecessor_transition_digest) = 32
    ),
    predecessor_configuration_epoch INTEGER,
    predecessor_members_json BLOB CHECK (
        predecessor_members_json IS NULL
        OR length(predecessor_members_json) BETWEEN 2 AND 1024
    ),
    predecessor_transition_start_index INTEGER CHECK (
        predecessor_transition_start_index IS NULL
        OR predecessor_transition_start_index >= 0
    ),
    predecessor_cutover_index INTEGER CHECK (
        predecessor_cutover_index IS NULL OR predecessor_cutover_index >= 0
    ),
    pending_transition_id BLOB CHECK (
        pending_transition_id IS NULL OR length(pending_transition_id) = 16
    ),
    pending_transition_digest BLOB CHECK (
        pending_transition_digest IS NULL OR length(pending_transition_digest) = 32
    ),
    desired_configuration_id BLOB CHECK (
        desired_configuration_id IS NULL OR length(desired_configuration_id) = 32
    ),
    desired_configuration_epoch INTEGER,
    desired_members_json BLOB CHECK (
        desired_members_json IS NULL OR length(desired_members_json) BETWEEN 2 AND 1024
    ),
    desired_bindings_json BLOB CHECK (
        desired_bindings_json IS NULL OR length(desired_bindings_json) BETWEEN 2 AND 32768
    ),
    pending_transition_start_index INTEGER CHECK (
        pending_transition_start_index IS NULL OR pending_transition_start_index >= 0
    ),
    pending_learners_ready_index INTEGER CHECK (
        pending_learners_ready_index IS NULL OR pending_learners_ready_index >= 0
    ),
    pending_joint_membership_index INTEGER CHECK (
        pending_joint_membership_index IS NULL OR pending_joint_membership_index >= 0
    ),
    pending_uniform_membership_index INTEGER CHECK (
        pending_uniform_membership_index IS NULL OR pending_uniform_membership_index >= 0
    ),
    terminal_transition_id BLOB CHECK (
        terminal_transition_id IS NULL OR length(terminal_transition_id) = 16
    ),
    terminal_transition_digest BLOB CHECK (
        terminal_transition_digest IS NULL OR length(terminal_transition_digest) = 32
    ),
    terminal_transition_outcome INTEGER CHECK (
        terminal_transition_outcome IS NULL OR terminal_transition_outcome IN (1, 2)
    ),
    terminal_transition_start_index INTEGER CHECK (
        terminal_transition_start_index IS NULL OR terminal_transition_start_index >= 0
    ),
    terminal_learners_ready_index INTEGER CHECK (
        terminal_learners_ready_index IS NULL OR terminal_learners_ready_index >= 0
    ),
    terminal_joint_membership_index INTEGER CHECK (
        terminal_joint_membership_index IS NULL OR terminal_joint_membership_index >= 0
    ),
    terminal_uniform_membership_index INTEGER CHECK (
        terminal_uniform_membership_index IS NULL OR terminal_uniform_membership_index >= 0
    ),
    terminal_cutover_index INTEGER CHECK (
        terminal_cutover_index IS NULL OR terminal_cutover_index >= 0
    ),
    terminal_finalization_index INTEGER CHECK (
        terminal_finalization_index IS NULL OR terminal_finalization_index >= 0
    ),
    CHECK (
        (predecessor_configuration_id IS NULL
         AND predecessor_transition_id IS NULL
         AND predecessor_transition_digest IS NULL
         AND predecessor_configuration_epoch IS NULL
         AND predecessor_members_json IS NULL
         AND predecessor_transition_start_index IS NULL
         AND predecessor_cutover_index IS NULL)
        OR
        (predecessor_configuration_id IS NOT NULL
         AND predecessor_transition_id IS NOT NULL
         AND predecessor_transition_digest IS NOT NULL
         AND predecessor_configuration_epoch IS NOT NULL
         AND predecessor_members_json IS NOT NULL
         AND predecessor_transition_start_index IS NOT NULL
         AND predecessor_cutover_index IS NOT NULL
         AND predecessor_configuration_epoch < current_configuration_epoch
         AND predecessor_transition_start_index <= predecessor_cutover_index)
    ),
    CHECK (
        application_authority_epoch = current_configuration_epoch
        OR application_authority_epoch = desired_configuration_epoch
    ),
    CHECK (
        (pending_transition_id IS NULL
         AND pending_transition_digest IS NULL
         AND desired_configuration_id IS NULL
         AND desired_configuration_epoch IS NULL
         AND desired_members_json IS NULL
         AND desired_bindings_json IS NULL
         AND pending_transition_start_index IS NULL
         AND pending_learners_ready_index IS NULL
         AND pending_joint_membership_index IS NULL
         AND pending_uniform_membership_index IS NULL)
        OR
        (pending_transition_id IS NOT NULL
         AND pending_transition_digest IS NOT NULL
         AND desired_configuration_id IS NOT NULL
         AND desired_configuration_epoch IS NOT NULL
         AND desired_members_json IS NOT NULL
         AND desired_bindings_json IS NOT NULL
         AND pending_transition_start_index IS NOT NULL
         AND desired_configuration_epoch = current_configuration_epoch + 1
         AND desired_configuration_id != current_configuration_id
         AND (pending_learners_ready_index IS NULL
              OR pending_learners_ready_index > pending_transition_start_index)
         AND (pending_joint_membership_index IS NULL
              OR (pending_learners_ready_index IS NOT NULL
                  AND pending_joint_membership_index > pending_learners_ready_index))
         AND (pending_uniform_membership_index IS NULL
              OR (pending_joint_membership_index IS NOT NULL
                  AND pending_uniform_membership_index > pending_joint_membership_index)))
    ),
    CHECK (
        (terminal_transition_id IS NULL
         AND terminal_transition_digest IS NULL
         AND terminal_transition_outcome IS NULL
         AND terminal_transition_start_index IS NULL
         AND terminal_learners_ready_index IS NULL
         AND terminal_joint_membership_index IS NULL
         AND terminal_uniform_membership_index IS NULL
         AND terminal_cutover_index IS NULL
         AND terminal_finalization_index IS NULL)
        OR
        (terminal_transition_id IS NOT NULL
         AND terminal_transition_digest IS NOT NULL
         AND terminal_transition_outcome IS NOT NULL
         AND terminal_transition_start_index IS NOT NULL
         AND (terminal_learners_ready_index IS NULL
              OR terminal_learners_ready_index > terminal_transition_start_index)
         AND (terminal_joint_membership_index IS NULL
              OR (terminal_learners_ready_index IS NOT NULL
                  AND terminal_joint_membership_index > terminal_learners_ready_index))
         AND (terminal_uniform_membership_index IS NULL
              OR (terminal_joint_membership_index IS NOT NULL
                  AND terminal_uniform_membership_index > terminal_joint_membership_index))
         AND ((terminal_transition_outcome = 1
               AND terminal_joint_membership_index IS NULL
               AND terminal_uniform_membership_index IS NULL
               AND terminal_cutover_index IS NULL
               AND terminal_finalization_index IS NULL)
              OR (terminal_transition_outcome = 2
                  AND terminal_uniform_membership_index IS NOT NULL
                  AND terminal_cutover_index IS NOT NULL
                  AND terminal_cutover_index >= terminal_uniform_membership_index
                  AND (terminal_finalization_index IS NULL
                       OR terminal_finalization_index > terminal_cutover_index))))
    ),
    FOREIGN KEY(storage_configuration_epoch)
        REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_membership_history (
    configuration_epoch INTEGER PRIMARY KEY CHECK (configuration_epoch > 0),
    storage_configuration_epoch INTEGER NOT NULL CHECK (storage_configuration_epoch > 0),
    configuration_id BLOB NOT NULL CHECK (length(configuration_id) = 32),
    members_json BLOB NOT NULL CHECK (length(members_json) BETWEEN 2 AND 1024),
    transition_id BLOB NOT NULL CHECK (length(transition_id) = 16),
    transition_digest BLOB NOT NULL CHECK (length(transition_digest) = 32),
    transition_start_index INTEGER NOT NULL CHECK (transition_start_index >= 0),
    cutover_index INTEGER NOT NULL CHECK (
        cutover_index >= transition_start_index
    ),
    FOREIGN KEY(storage_configuration_epoch)
        REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_vote (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    node_id INTEGER CHECK (node_id > 0),
    vote_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_committed (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    log_index INTEGER NOT NULL CHECK (log_index >= 0),
    log_id_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_purged (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    log_index INTEGER NOT NULL CHECK (log_index >= 0),
    log_id_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_log (
    log_index INTEGER PRIMARY KEY CHECK (log_index >= 0),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    entry_json BLOB NOT NULL CHECK (length(entry_json) > 0),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_applied (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    log_index INTEGER NOT NULL CHECK (log_index >= 0),
    log_id_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_membership (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    membership_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_machine (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    application_sequence INTEGER NOT NULL CHECK (application_sequence >= 0),
    last_digest BLOB NOT NULL CHECK (length(last_digest) = 32),
    logical_time TEXT,
    watch_sequence INTEGER NOT NULL CHECK (watch_sequence >= 0),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_request_outcomes (
    request_id BLOB PRIMARY KEY CHECK (length(request_id) = 16),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    response_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_snapshot (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    meta_json BLOB NOT NULL,
    file_name TEXT NOT NULL CHECK (length(file_name) > 0),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_operator_recovery (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    last_plan_digest BLOB NOT NULL CHECK (length(last_plan_digest) = 32),
    pending_epoch INTEGER CHECK (pending_epoch > recovery_epoch),
    pending_plan_digest BLOB CHECK (
        pending_plan_digest IS NULL OR length(pending_plan_digest) = 32
    ),
    watch_cursor_invalidation_floor INTEGER NOT NULL CHECK (watch_cursor_invalidation_floor >= 0),
    CHECK (
        (pending_epoch IS NULL AND pending_plan_digest IS NULL)
        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL)
    ),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);
"#;

/// Install the exact consensus DDL used by production into an empty schema.
///
/// Recovery uses this only to derive a canonical, bounded schema manifest. A
/// boolean selects the supported add-on form created when an older current
/// database first gains the operator-recovery table.
pub(crate) fn install_recovery_validation_schema_sync(
    conn: &Connection,
    operator_recovery_add_on: bool,
) -> io::Result<()> {
    if operator_recovery_add_on {
        conn.execute_batch(OPERATOR_RECOVERY_SCHEMA)
            .map_err(db_error)?;
    } else {
        conn.execute_batch(CONSENSUS_SCHEMA).map_err(db_error)?;
    }
    Ok(())
}

/// Reproduce the supported pre-cursor operator-recovery schema migration.
///
/// SQLite records `ALTER TABLE ... ADD COLUMN` by appending the column to the
/// original `sqlite_master.sql` text, so its canonical DDL is distinct from a
/// table created directly at the current version. Recovery must recognize the
/// result without weakening validation to column-name checks.
pub(crate) fn install_migrated_operator_recovery_validation_schema_sync(
    conn: &Connection,
) -> io::Result<()> {
    conn.execute_batch(PRE_CURSOR_OPERATOR_RECOVERY_SCHEMA)
        .map_err(db_error)?;
    conn.execute_batch(OPERATOR_RECOVERY_CURSOR_MIGRATION)
        .map_err(db_error)
}

/// Shared persistence resources used by the log store, state machine, and
/// snapshot builder. One async mutex serializes every vote/log/state write.
#[derive(Clone)]
pub(crate) struct SqliteConsensusCore {
    pub(crate) conn: Arc<tokio::sync::Mutex<Connection>>,
    /// Immutable database-incarnation identity used by legacy foreign keys.
    /// The active topology identity lives in `consensus_membership_scope`.
    pub(crate) storage_identity: SessionConsensusIdentity,
    pub(crate) snapshot_dir: Arc<PathBuf>,
    pub(crate) caps: BackendCapabilities,
    pub(crate) snapshot_gate: Arc<tokio::sync::Mutex<()>>,
    pub(crate) applied_progress: tokio::sync::watch::Sender<Option<LogId<SessionConsensusNodeId>>>,
    pub(crate) watchers: Arc<tokio::sync::Mutex<Vec<crate::replication_watch::ReplicationWatcher>>>,
    #[cfg(test)]
    pub(crate) apply_gate: Arc<tokio::sync::Semaphore>,
}

impl SqliteConsensusCore {
    pub(crate) async fn initialize(
        backend: &SqliteSessionBackend,
        snapshot_dir: PathBuf,
        identity: SessionConsensusIdentity,
        expected_members: BTreeSet<SessionConsensusNodeId>,
        expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    ) -> Result<Self, SessionConsensusStorageError> {
        Self::initialize_inner(
            backend,
            snapshot_dir,
            identity,
            expected_members,
            expected_bindings,
            None,
            None,
        )
        .await
    }

    pub(crate) async fn initialize_with_pending(
        backend: &SqliteSessionBackend,
        snapshot_dir: PathBuf,
        storage_identity: SessionConsensusIdentity,
        current_identity: SessionConsensusIdentity,
        current_members: BTreeSet<SessionConsensusNodeId>,
        current_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        pending: PendingMembershipBootstrap<'_>,
    ) -> Result<Self, SessionConsensusStorageError> {
        Self::initialize_inner(
            backend,
            snapshot_dir,
            current_identity,
            current_members,
            current_bindings,
            Some(storage_identity),
            Some(pending),
        )
        .await
    }

    async fn initialize_inner(
        backend: &SqliteSessionBackend,
        snapshot_dir: PathBuf,
        identity: SessionConsensusIdentity,
        expected_members: BTreeSet<SessionConsensusNodeId>,
        expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        required_storage_identity: Option<SessionConsensusIdentity>,
        pending: Option<PendingMembershipBootstrap<'_>>,
    ) -> Result<Self, SessionConsensusStorageError> {
        validate_member_set(&expected_members, false)
            .map_err(|_| SessionConsensusStorageError::InvalidIdentity)?;
        validate_member_bindings(&expected_members, &expected_bindings)
            .map_err(|_| SessionConsensusStorageError::InvalidIdentity)?;
        tokio::fs::create_dir_all(&snapshot_dir)
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        let canonical_snapshot_dir = tokio::fs::canonicalize(&snapshot_dir)
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;

        let (storage_identity, applied) = {
            let conn = backend.conn.lock().await;
            let storage_identity = initialize_schema_with_storage_anchor_and_pending_and_bindings(
                &conn,
                required_storage_identity,
                identity,
                &expected_members,
                &expected_bindings,
                pending,
            )?;
            let applied = read_applied_sync(&conn, storage_identity)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?;
            (storage_identity, applied)
        };
        let (applied_progress, _) = tokio::sync::watch::channel(applied);

        Ok(Self {
            conn: Arc::clone(&backend.conn),
            storage_identity,
            snapshot_dir: Arc::new(canonical_snapshot_dir),
            caps: backend.caps,
            snapshot_gate: Arc::new(tokio::sync::Mutex::new(())),
            applied_progress,
            watchers: Arc::clone(&backend.watchers),
            #[cfg(test)]
            apply_gate: Arc::clone(&backend.consensus_apply_gate),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PendingMembershipBootstrap<'a> {
    pub(crate) transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    pub(crate) transition_digest: [u8; 32],
    pub(crate) desired_identity: SessionConsensusIdentity,
    pub(crate) desired_members: &'a BTreeSet<SessionConsensusNodeId>,
    pub(crate) desired_bindings: &'a BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
}

fn initialize_schema_with_bindings(
    conn: &Connection,
    requested_identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    initialize_schema_with_pending_and_bindings(
        conn,
        requested_identity,
        expected_members,
        expected_bindings,
        None,
    )
}

fn initialize_schema_with_pending_and_bindings(
    conn: &Connection,
    requested_identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    pending: Option<PendingMembershipBootstrap<'_>>,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    initialize_schema_with_storage_anchor_and_pending_and_bindings(
        conn,
        None,
        requested_identity,
        expected_members,
        expected_bindings,
        pending,
    )
}

fn initialize_schema_with_storage_anchor_and_pending_and_bindings(
    conn: &Connection,
    required_storage_identity: Option<SessionConsensusIdentity>,
    requested_identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    pending: Option<PendingMembershipBootstrap<'_>>,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    if let Some(storage_identity) = required_storage_identity {
        let same_incarnation = storage_identity.cluster_id() == requested_identity.cluster_id()
            && storage_identity.configuration_epoch() <= requested_identity.configuration_epoch()
            && (storage_identity.configuration_epoch() != requested_identity.configuration_epoch()
                || storage_identity.configuration_id() == requested_identity.configuration_id());
        if !same_incarnation {
            return Err(SessionConsensusStorageError::InvalidIdentity);
        }
    }
    // The immediate transaction is the durable authority hand-off fence. A
    // standalone operation on another SQLite connection either finishes
    // before this claim (and is included in the legacy-state check) or starts
    // after the consensus identity commits and fails closed.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let identity_table_exists = table_exists(&tx, "consensus_identity")
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;

    if !identity_table_exists {
        if legacy_authority_is_nonempty(&tx)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        {
            return Err(SessionConsensusStorageError::RecoveryRequired);
        }
        tx.execute_batch(CONSENSUS_SCHEMA)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        let storage_identity = required_storage_identity.unwrap_or(requested_identity);
        let epoch = checked_positive_i64(storage_identity.configuration_epoch().get())
            .map_err(|_| SessionConsensusStorageError::InvalidIdentity)?;
        tx.execute(
            "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
                storage_identity.cluster_id().as_bytes().as_slice(),
                storage_identity.configuration_id().as_bytes().as_slice(),
                epoch,
            ],
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        tx.execute(
            "INSERT INTO consensus_membership (singleton, configuration_epoch, membership_json) VALUES (1, ?1, ?2)",
            params![epoch, encode_json(&StoredMembership::<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>::default()).map_err(|_| SessionConsensusStorageError::BackendUnavailable)?],
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        tx.execute(
            "INSERT INTO consensus_machine (singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence) VALUES (1, ?1, 0, ?2, NULL, 0)",
            params![epoch, SessionConsensusEntryDigest::GENESIS.as_bytes().as_slice()],
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    }

    let storage_identity = read_storage_identity_sync(&tx)?;
    if required_storage_identity.is_some_and(|required| required != storage_identity) {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }
    if storage_identity.cluster_id() != requested_identity.cluster_id() {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }
    ensure_operator_recovery_schema_sync(&tx, storage_identity)
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    ensure_membership_scope_schema_sync(
        &tx,
        storage_identity,
        requested_identity,
        expected_members,
        expected_bindings,
    )
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    if identity_table_exists {
        validate_existing_schema(&tx, storage_identity)?;
    }

    let scope = read_membership_scope_sync(&tx, storage_identity)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    if scope.current_identity != requested_identity
        || scope.current_members != *expected_members
        || scope.current_bindings != *expected_bindings
    {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }
    if let Some(pending) = pending {
        let transition_start = last_log_sync(&tx, storage_identity)
            .map_err(|_| SessionConsensusStorageError::CorruptState)?
            .map(|log_id| {
                log_id
                    .index
                    .checked_add(1)
                    .ok_or(SessionConsensusStorageError::InvalidIdentity)
            })
            .transpose()?
            .unwrap_or(0);
        stage_membership_scope_in_tx(
            &tx,
            storage_identity,
            pending.transition_id,
            pending.transition_digest,
            pending.desired_identity,
            pending.desired_members,
            pending.desired_bindings,
            transition_start,
        )
        .map_err(|error| match error {
            MembershipScopeMutationError::BackendUnavailable => {
                SessionConsensusStorageError::BackendUnavailable
            }
            MembershipScopeMutationError::InvalidScope => {
                SessionConsensusStorageError::InvalidIdentity
            }
            MembershipScopeMutationError::ConflictingTransition
            | MembershipScopeMutationError::CompactionRequired
            | MembershipScopeMutationError::TransitionNotQuiescent
            | MembershipScopeMutationError::CorruptState => {
                SessionConsensusStorageError::CorruptState
            }
        })?;
    }
    validate_persisted_membership_sync(&tx, storage_identity)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;

    tx.commit()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    Ok(storage_identity)
}

#[cfg(test)]
fn test_member_bindings(
    members: &BTreeSet<SessionConsensusNodeId>,
) -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding> {
    members
        .iter()
        .copied()
        .map(|node| {
            let mut descriptor = [0x11; 32];
            descriptor[..8].copy_from_slice(&node.get().to_be_bytes());
            let mut endpoint = [0x22; 32];
            endpoint[..8].copy_from_slice(&node.get().to_be_bytes());
            let mut tls = [0x33; 32];
            tls[..8].copy_from_slice(&node.get().to_be_bytes());
            let mut backing = [0x44; 32];
            backing[..8].copy_from_slice(&node.get().to_be_bytes());
            (
                node,
                SessionTopologyMemberBinding::new(descriptor, endpoint, tls, backing),
            )
        })
        .collect()
}

#[cfg(test)]
fn initialize_schema(
    conn: &Connection,
    requested_identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    initialize_schema_with_bindings(
        conn,
        requested_identity,
        expected_members,
        &test_member_bindings(expected_members),
    )
}

#[cfg(test)]
fn initialize_schema_with_pending(
    conn: &Connection,
    requested_identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    pending: Option<PendingMembershipBootstrap<'_>>,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    initialize_schema_with_pending_and_bindings(
        conn,
        requested_identity,
        expected_members,
        &test_member_bindings(expected_members),
        pending,
    )
}

#[cfg(test)]
fn initialize_schema_with_storage_anchor_and_pending(
    conn: &Connection,
    required_storage_identity: Option<SessionConsensusIdentity>,
    requested_identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    pending: Option<PendingMembershipBootstrap<'_>>,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    initialize_schema_with_storage_anchor_and_pending_and_bindings(
        conn,
        required_storage_identity,
        requested_identity,
        expected_members,
        &test_member_bindings(expected_members),
        pending,
    )
}

fn table_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
    )
}

pub(crate) fn read_storage_identity_sync(
    conn: &Connection,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    let row = conn
        .query_row(
            "SELECT schema_version, cluster_id, configuration_id, configuration_epoch FROM consensus_identity WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        .ok_or(SessionConsensusStorageError::CorruptState)?;
    let (schema, cluster, configuration, epoch) = row;
    if schema != i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) {
        return Err(SessionConsensusStorageError::SchemaVersionMismatch);
    }
    let cluster: [u8; 32] = cluster
        .try_into()
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    let configuration: [u8; 32] = configuration
        .try_into()
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    let epoch = checked_positive_u64(epoch)
        .ok()
        .and_then(|value| SessionConsensusConfigurationEpoch::new(value).ok())
        .ok_or(SessionConsensusStorageError::CorruptState)?;
    Ok(SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::from_bytes(cluster),
        SessionConsensusConfigurationId::from_bytes(configuration),
        epoch,
    ))
}

fn install_membership_scope_schema_sync(conn: &Connection) -> io::Result<()> {
    if table_exists(conn, "consensus_membership_scope").map_err(db_error)? {
        return Ok(());
    }
    // Derive the migration DDL from the same hard-coded production schema so
    // a legacy upgrade cannot drift from fresh-database constraints.
    let canonical = Connection::open_in_memory().map_err(db_error)?;
    canonical
        .execute_batch(CONSENSUS_SCHEMA)
        .map_err(db_error)?;
    let ddl: String = canonical
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'consensus_membership_scope'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    conn.execute_batch(&ddl).map_err(db_error)
}

fn install_membership_history_schema_sync(conn: &Connection) -> io::Result<()> {
    if table_exists(conn, "consensus_membership_history").map_err(db_error)? {
        return Ok(());
    }
    let canonical = Connection::open_in_memory().map_err(db_error)?;
    canonical
        .execute_batch(CONSENSUS_SCHEMA)
        .map_err(db_error)?;
    let ddl: String = canonical
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'consensus_membership_history'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    conn.execute_batch(&ddl).map_err(db_error)
}

fn encode_members(
    members: &BTreeSet<SessionConsensusNodeId>,
    transition: bool,
) -> io::Result<Vec<u8>> {
    validate_member_set(members, transition)?;
    let encoded = encode_json(members)?;
    if encoded.len() < 2 || encoded.len() > MEMBERSHIP_SCOPE_MEMBERS_MAX_BYTES {
        return Err(invalid_data(
            "session consensus membership scope exceeds storage bounds",
        ));
    }
    Ok(encoded)
}

fn validate_member_set(
    members: &BTreeSet<SessionConsensusNodeId>,
    transition: bool,
) -> io::Result<()> {
    let count = members.len();
    let bounded = count > 0 && count <= crate::topology::QUORUM_TOPOLOGY_MAX_MEMBERS;
    let valid_transition = count >= 3 && !count.is_multiple_of(2);
    if !bounded || (transition && !valid_transition) {
        return Err(invalid_data(
            "session consensus membership scope has invalid cardinality",
        ));
    }
    for node in members {
        checked_positive_i64(node.get())?;
    }
    Ok(())
}

fn decode_members(
    encoded: Vec<u8>,
    transition: bool,
) -> io::Result<BTreeSet<SessionConsensusNodeId>> {
    if encoded.len() < 2 || encoded.len() > MEMBERSHIP_SCOPE_MEMBERS_MAX_BYTES {
        return Err(invalid_data(
            "session consensus membership scope exceeds storage bounds",
        ));
    }
    let members = decode_json(&encoded)?;
    validate_member_set(&members, transition)?;
    Ok(members)
}

fn validate_member_bindings(
    members: &BTreeSet<SessionConsensusNodeId>,
    bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
) -> io::Result<()> {
    if bindings.keys().copied().collect::<BTreeSet<_>>() != *members {
        return Err(invalid_data(
            "session consensus topology binding keys do not match membership",
        ));
    }
    let unique = |values: Vec<[u8; 32]>| {
        values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
    };
    if !unique(
        bindings
            .values()
            .map(|binding| binding.descriptor())
            .collect(),
    ) || !unique(
        bindings
            .values()
            .map(|binding| binding.endpoint())
            .collect(),
    ) || !unique(
        bindings
            .values()
            .map(|binding| binding.tls_identity())
            .collect(),
    ) || !unique(
        bindings
            .values()
            .map(|binding| binding.backing_identity())
            .collect(),
    ) {
        return Err(invalid_data(
            "session consensus topology bindings are not unique",
        ));
    }
    Ok(())
}

fn validate_transition_bindings(
    current_members: &BTreeSet<SessionConsensusNodeId>,
    current_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
    desired_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
) -> io::Result<()> {
    validate_member_bindings(current_members, current_bindings)?;
    validate_member_bindings(desired_members, desired_bindings)?;
    for retained in current_members.intersection(desired_members) {
        if current_bindings.get(retained) != desired_bindings.get(retained) {
            return Err(invalid_data(
                "session consensus retained topology binding changed",
            ));
        }
    }
    for added in desired_members.difference(current_members) {
        let binding = desired_bindings
            .get(added)
            .ok_or_else(|| invalid_data("session consensus added topology binding is missing"))?;
        if current_bindings.iter().any(|(node_id, current)| {
            node_id != added
                && (current.descriptor() == binding.descriptor()
                    || current.endpoint() == binding.endpoint()
                    || current.tls_identity() == binding.tls_identity()
                    || current.backing_identity() == binding.backing_identity())
        }) {
            return Err(invalid_data(
                "session consensus added topology binding reuses an admitted identity",
            ));
        }
    }
    Ok(())
}

fn encode_bindings(
    members: &BTreeSet<SessionConsensusNodeId>,
    bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
) -> io::Result<Vec<u8>> {
    validate_member_bindings(members, bindings)?;
    let encoded = encode_json(
        &bindings
            .iter()
            .map(|(node, binding)| (*node, *binding))
            .collect::<Vec<_>>(),
    )?;
    if encoded.len() < 2 || encoded.len() > MEMBERSHIP_SCOPE_BINDINGS_MAX_BYTES {
        return Err(invalid_data(
            "session consensus topology bindings exceed storage bounds",
        ));
    }
    Ok(encoded)
}

fn decode_bindings(
    encoded: Vec<u8>,
    members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>> {
    if encoded.len() < 2 || encoded.len() > MEMBERSHIP_SCOPE_BINDINGS_MAX_BYTES {
        return Err(invalid_data(
            "session consensus topology bindings exceed storage bounds",
        ));
    }
    let entries: Vec<(SessionConsensusNodeId, SessionTopologyMemberBinding)> =
        decode_json(&encoded)?;
    let entry_count = entries.len();
    let bindings = entries.into_iter().collect::<BTreeMap<_, _>>();
    if bindings.len() != entry_count {
        return Err(invalid_data(
            "session consensus topology binding contains duplicate member IDs",
        ));
    }
    validate_member_bindings(members, &bindings)?;
    Ok(bindings)
}

fn exact_successor_epoch(
    current: SessionConsensusIdentity,
    desired: SessionConsensusIdentity,
) -> bool {
    current.cluster_id() == desired.cluster_id()
        && current.configuration_id() != desired.configuration_id()
        && current
            .configuration_epoch()
            .get()
            .checked_add(1)
            .is_some_and(|next| next == desired.configuration_epoch().get())
}

fn ensure_membership_scope_schema_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    requested_current_identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
) -> io::Result<()> {
    validate_member_set(expected_members, false)?;
    if !expected_bindings.is_empty() {
        validate_member_bindings(expected_members, expected_bindings)?;
    }
    install_membership_history_schema_sync(conn)?;
    if storage_identity.cluster_id() != requested_current_identity.cluster_id()
        || storage_identity.configuration_epoch().get()
            > requested_current_identity.configuration_epoch().get()
        || (storage_identity.configuration_epoch()
            == requested_current_identity.configuration_epoch()
            && storage_identity.configuration_id() != requested_current_identity.configuration_id())
    {
        return Err(invalid_data(
            "session consensus storage and current identity lineage is invalid",
        ));
    }
    let existed = table_exists(conn, "consensus_membership_scope").map_err(db_error)?;
    if !existed {
        // A legacy database may be upgraded only when its old fixed validator
        // proves the caller-supplied set. This prevents migration from blessing
        // a caller-invented topology.
        let membership = read_membership_unchecked_sync(conn, storage_identity)?;
        if is_pristine_membership(&membership) {
            if read_applied_sync(conn, storage_identity)?.is_some() {
                return Err(invalid_data(
                    "session consensus applied state has pristine membership",
                ));
            }
            // Only a pristine database may be provisioned directly at an
            // active epoch newer than its immutable storage incarnation. A
            // legacy database without this table never performed a dynamic
            // transition and therefore cannot assert such a lineage.
            if existed || requested_current_identity != storage_identity {
                return Err(invalid_data(
                    "legacy session consensus membership scope cannot skip epochs",
                ));
            }
        } else {
            validate_uniform_membership(&membership, expected_members)?;
            if requested_current_identity != storage_identity {
                return Err(invalid_data(
                    "legacy session consensus membership identity is inconsistent",
                ));
            }
        }
        install_membership_scope_schema_sync(conn)?;
    }
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM consensus_membership_scope",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if rows == 0 {
        let encoded_bindings = if expected_bindings.is_empty() {
            encode_json(&Vec::<(SessionConsensusNodeId, SessionTopologyMemberBinding)>::new())?
        } else {
            encode_bindings(expected_members, expected_bindings)?
        };
        conn.execute(
            "INSERT INTO consensus_membership_scope (singleton, storage_configuration_epoch, current_configuration_id, current_configuration_epoch, current_members_json, current_bindings_json, application_authority_epoch, application_authority_members_json) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?3, ?4)",
            params![
                epoch_i64(storage_identity)?,
                requested_current_identity.configuration_id().as_bytes().as_slice(),
                checked_positive_i64(requested_current_identity.configuration_epoch().get())?,
                encode_members(expected_members, false)?,
                encoded_bindings,
            ],
        )
        .map_err(db_error)?;
    } else if rows != 1 {
        return Err(invalid_data(
            "session consensus membership scope row count is invalid",
        ));
    }
    if expected_bindings.is_empty() {
        return Ok(());
    }
    conn.execute(
        "UPDATE consensus_membership_scope SET current_bindings_json = ?1 WHERE singleton = 1 AND current_bindings_json = ?2 AND current_configuration_id = ?3 AND current_configuration_epoch = ?4 AND current_members_json = ?5 AND predecessor_configuration_id IS NULL AND pending_transition_id IS NULL AND terminal_transition_id IS NULL",
        params![
            encode_bindings(expected_members, expected_bindings)?,
            b"[]".as_slice(),
            requested_current_identity.configuration_id().as_bytes().as_slice(),
            checked_positive_i64(requested_current_identity.configuration_epoch().get())?,
            encode_members(expected_members, false)?,
        ],
    )
    .map_err(db_error)?;
    read_membership_scope_sync(conn, storage_identity).map(|_| ())
}

type MembershipScopeRow = (
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Vec<u8>,
    Option<Vec<u8>>,
);

fn read_membership_history_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> io::Result<Vec<MembershipPredecessorScope>> {
    if !table_exists(conn, "consensus_membership_history").map_err(db_error)? {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT storage_configuration_epoch, configuration_id, configuration_epoch, members_json, transition_id, transition_digest, transition_start_index, cutover_index FROM consensus_membership_history ORDER BY configuration_epoch ASC",
        )
        .map_err(db_error)?;
    let mut rows = statement.query([]).map_err(db_error)?;
    let mut history = Vec::new();
    while let Some(row) = rows.next().map_err(db_error)? {
        if history.len() >= MEMBERSHIP_HISTORY_MAX_ENTRIES {
            return Err(invalid_data(
                "session consensus membership history exceeds storage bounds",
            ));
        }
        let stored_epoch: i64 = row.get(0).map_err(db_error)?;
        validate_epoch(stored_epoch, storage_identity)?;
        let configuration: Vec<u8> = row.get(1).map_err(db_error)?;
        let configuration: [u8; 32] = configuration
            .try_into()
            .map_err(|_| invalid_data("session consensus history configuration ID is invalid"))?;
        let epoch: i64 = row.get(2).map_err(db_error)?;
        let epoch = SessionConsensusConfigurationEpoch::new(checked_positive_u64(epoch)?)
            .map_err(|_| invalid_data("session consensus history epoch is invalid"))?;
        let members: Vec<u8> = row.get(3).map_err(db_error)?;
        let transition_id: Vec<u8> = row.get(4).map_err(db_error)?;
        let transition_id = transition_id
            .try_into()
            .map_err(|_| invalid_data("session consensus history transition ID is invalid"))?;
        let transition_digest: Vec<u8> = row.get(5).map_err(db_error)?;
        let transition_digest = transition_digest
            .try_into()
            .map_err(|_| invalid_data("session consensus history digest is invalid"))?;
        let start: i64 = row.get(6).map_err(db_error)?;
        let cutover: i64 = row.get(7).map_err(db_error)?;
        let start = checked_u64(start)?;
        let cutover = checked_u64(cutover)?;
        if start > cutover {
            return Err(invalid_data(
                "session consensus history log range is invalid",
            ));
        }
        history.push(MembershipPredecessorScope {
            transition_id,
            transition_digest,
            identity: SessionConsensusIdentity::new(
                storage_identity.cluster_id(),
                SessionConsensusConfigurationId::from_bytes(configuration),
                epoch,
            ),
            members: decode_members(members, true)?,
            transition_start_log_index: start,
            cutover_log_index: cutover,
        });
    }
    Ok(history)
}

fn validate_membership_history_chain(
    history: &[MembershipPredecessorScope],
    predecessor: Option<&MembershipPredecessorScope>,
    current_identity: SessionConsensusIdentity,
) -> io::Result<()> {
    if history.is_empty() && predecessor.is_none() {
        return Ok(());
    }
    let mut entries = history.iter().chain(predecessor);
    let mut previous = entries
        .next()
        .ok_or_else(|| invalid_data("session consensus membership history is empty"))?;
    for next in entries {
        if !exact_successor_epoch(previous.identity, next.identity)
            || previous.cutover_log_index >= next.transition_start_log_index
        {
            return Err(invalid_data(
                "session consensus membership history lineage is inconsistent",
            ));
        }
        previous = next;
    }
    if !exact_successor_epoch(previous.identity, current_identity) {
        return Err(invalid_data(
            "session consensus membership history does not reach the current epoch",
        ));
    }
    Ok(())
}

pub(crate) fn read_membership_scope_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> io::Result<MembershipValidationScope> {
    if !table_exists(conn, "consensus_membership_scope").map_err(db_error)? {
        let membership = read_membership_unchecked_sync(conn, storage_identity)?;
        if is_pristine_membership(&membership) {
            return Err(invalid_data(
                "legacy session consensus membership scope is pristine",
            ));
        }
        let configs = membership.membership().get_joint_config();
        let members = configs
            .first()
            .filter(|_| configs.len() == 1)
            .cloned()
            .ok_or_else(|| invalid_data("legacy session consensus membership is not uniform"))?;
        validate_uniform_membership(&membership, &members)?;
        return Ok(MembershipValidationScope {
            current_identity: storage_identity,
            current_members: members.clone(),
            current_bindings: BTreeMap::new(),
            application_authority_epoch: storage_identity.configuration_epoch(),
            application_authority_members: members,
            predecessor: None,
            history: Vec::new(),
            pending: None,
            terminal: None,
        });
    }
    let row: MembershipScopeRow = conn
        .query_row(
            "SELECT storage_configuration_epoch, current_configuration_id, current_configuration_epoch, current_members_json, application_authority_epoch, application_authority_members_json, predecessor_configuration_id, predecessor_transition_id, predecessor_transition_digest, predecessor_configuration_epoch, predecessor_members_json, predecessor_transition_start_index, predecessor_cutover_index, pending_transition_id, pending_transition_digest, desired_configuration_id, desired_configuration_epoch, desired_members_json, pending_transition_start_index, pending_joint_membership_index, pending_uniform_membership_index, terminal_transition_id, terminal_transition_digest, terminal_transition_outcome, terminal_transition_start_index, terminal_joint_membership_index, terminal_uniform_membership_index, terminal_cutover_index, terminal_finalization_index, pending_learners_ready_index, terminal_learners_ready_index, current_bindings_json, desired_bindings_json FROM consensus_membership_scope WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                    row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?, row.get(14)?,
                    row.get(15)?, row.get(16)?, row.get(17)?, row.get(18)?, row.get(19)?,
                    row.get(20)?, row.get(21)?, row.get(22)?, row.get(23)?, row.get(24)?,
                    row.get(25)?, row.get(26)?, row.get(27)?, row.get(28)?, row.get(29)?,
                    row.get(30)?, row.get(31)?, row.get(32)?,
                ))
            },
        )
        .map_err(db_error)?;
    validate_epoch(row.0, storage_identity)?;
    let current_configuration: [u8; 32] = row
        .1
        .try_into()
        .map_err(|_| invalid_data("session consensus current configuration ID is invalid"))?;
    let current_epoch = SessionConsensusConfigurationEpoch::new(checked_positive_u64(row.2)?)
        .map_err(|_| invalid_data("session consensus current configuration epoch is invalid"))?;
    let current_identity = SessionConsensusIdentity::new(
        storage_identity.cluster_id(),
        SessionConsensusConfigurationId::from_bytes(current_configuration),
        current_epoch,
    );
    let current_members = decode_members(row.3, false)?;
    let current_bindings = decode_bindings(row.31, &current_members)?;
    let desired_bindings_encoded = row.32.clone();

    let application_authority_epoch =
        SessionConsensusConfigurationEpoch::new(checked_positive_u64(row.4)?)
            .map_err(|_| invalid_data("session consensus authority epoch is invalid"))?;
    let application_authority_members = decode_members(row.5, false)?;

    let predecessor = match (row.6, row.7, row.8, row.9, row.10, row.11, row.12) {
        (None, None, None, None, None, None, None) => None,
        (
            Some(configuration),
            Some(transition_id),
            Some(transition_digest),
            Some(epoch),
            Some(members),
            Some(start),
            Some(cutover),
        ) => {
            let configuration: [u8; 32] = configuration.try_into().map_err(|_| {
                invalid_data("session consensus predecessor configuration ID is invalid")
            })?;
            let epoch = SessionConsensusConfigurationEpoch::new(checked_positive_u64(epoch)?)
                .map_err(|_| {
                    invalid_data("session consensus predecessor configuration epoch is invalid")
                })?;
            let identity = SessionConsensusIdentity::new(
                storage_identity.cluster_id(),
                SessionConsensusConfigurationId::from_bytes(configuration),
                epoch,
            );
            let start = checked_u64(start)?;
            let cutover = checked_u64(cutover)?;
            let transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES] =
                transition_id.try_into().map_err(|_| {
                    invalid_data("session consensus predecessor transition ID is invalid")
                })?;
            let transition_digest: [u8; 32] = transition_digest.try_into().map_err(|_| {
                invalid_data("session consensus predecessor transition digest is invalid")
            })?;
            if !exact_successor_epoch(identity, current_identity) || start > cutover {
                return Err(invalid_data(
                    "session consensus predecessor scope is inconsistent",
                ));
            }
            Some(MembershipPredecessorScope {
                transition_id,
                transition_digest,
                identity,
                members: decode_members(members, true)?,
                transition_start_log_index: start,
                cutover_log_index: cutover,
            })
        }
        _ => {
            return Err(invalid_data(
                "session consensus predecessor scope is incomplete",
            ));
        }
    };

    let pending = match (
        row.13, row.14, row.15, row.16, row.17, row.18, row.19, row.20,
    ) {
        (None, None, None, None, None, None, None, None) => {
            if desired_bindings_encoded.is_some() {
                return Err(invalid_data(
                    "session consensus desired topology bindings have no transition",
                ));
            }
            None
        }
        (
            Some(transition_id),
            Some(transition_digest),
            Some(configuration),
            Some(epoch),
            Some(members),
            Some(start),
            joint,
            uniform,
        ) => {
            let transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES] = transition_id
                .try_into()
                .map_err(|_| invalid_data("session consensus transition ID is invalid"))?;
            let transition_digest: [u8; 32] = transition_digest
                .try_into()
                .map_err(|_| invalid_data("session consensus transition digest is invalid"))?;
            let configuration: [u8; 32] = configuration.try_into().map_err(|_| {
                invalid_data("session consensus desired configuration ID is invalid")
            })?;
            let epoch = SessionConsensusConfigurationEpoch::new(checked_positive_u64(epoch)?)
                .map_err(|_| {
                    invalid_data("session consensus desired configuration epoch is invalid")
                })?;
            let desired_identity = SessionConsensusIdentity::new(
                storage_identity.cluster_id(),
                SessionConsensusConfigurationId::from_bytes(configuration),
                epoch,
            );
            let start = checked_u64(start)?;
            let learners_ready = row.29.map(checked_u64).transpose()?;
            let joint = joint.map(checked_u64).transpose()?;
            let uniform = uniform.map(checked_u64).transpose()?;
            if !exact_successor_epoch(current_identity, desired_identity)
                || learners_ready.is_some_and(|index| index <= start)
                || joint.is_some_and(|index| {
                    learners_ready.is_none_or(|learners_ready| index <= learners_ready)
                })
                || uniform.is_some_and(|index| joint.is_none_or(|joint| index <= joint))
            {
                return Err(invalid_data(
                    "session consensus pending membership scope is inconsistent",
                ));
            }
            let desired_members = decode_members(members, true)?;
            let desired_bindings = decode_bindings(
                desired_bindings_encoded.ok_or_else(|| {
                    invalid_data("session consensus desired topology bindings are missing")
                })?,
                &desired_members,
            )?;
            validate_transition_bindings(
                &current_members,
                &current_bindings,
                &desired_members,
                &desired_bindings,
            )?;
            Some(PendingMembershipScope {
                transition_id,
                transition_digest,
                desired_identity,
                desired_members,
                desired_bindings,
                transition_start_log_index: start,
                learners_ready_log_index: learners_ready,
                joint_membership_log_index: joint,
                uniform_membership_log_index: uniform,
            })
        }
        _ => {
            return Err(invalid_data(
                "session consensus pending membership scope is incomplete",
            ));
        }
    };

    let terminal = match (row.21, row.22, row.23, row.24) {
        (None, None, None, None) => {
            if row.25.is_some()
                || row.26.is_some()
                || row.27.is_some()
                || row.28.is_some()
                || row.30.is_some()
            {
                return Err(invalid_data(
                    "session consensus terminal transition scope is incomplete",
                ));
            }
            None
        }
        (Some(transition_id), Some(transition_digest), Some(outcome), Some(start)) => {
            let transition_id = transition_id
                .try_into()
                .map_err(|_| invalid_data("session consensus terminal transition ID is invalid"))?;
            let transition_digest = transition_digest.try_into().map_err(|_| {
                invalid_data("session consensus terminal transition digest is invalid")
            })?;
            let outcome = match outcome {
                1 => TerminalMembershipOutcome::Aborted,
                2 => TerminalMembershipOutcome::Promoted,
                _ => {
                    return Err(invalid_data(
                        "session consensus terminal transition outcome is invalid",
                    ));
                }
            };
            let start = checked_u64(start)?;
            let learners_ready = row.30.map(checked_u64).transpose()?;
            let joint = row.25.map(checked_u64).transpose()?;
            let uniform = row.26.map(checked_u64).transpose()?;
            let cutover = row.27.map(checked_u64).transpose()?;
            let finalization = row.28.map(checked_u64).transpose()?;
            if learners_ready.is_some_and(|index| index <= start)
                || joint.is_some_and(|index| {
                    learners_ready.is_none_or(|learners_ready| index <= learners_ready)
                })
                || uniform.is_some_and(|index| joint.is_none_or(|joint| index <= joint))
                || match outcome {
                    TerminalMembershipOutcome::Aborted => {
                        joint.is_some()
                            || uniform.is_some()
                            || cutover.is_some()
                            || finalization.is_some()
                    }
                    TerminalMembershipOutcome::Promoted => {
                        uniform
                            .zip(cutover)
                            .is_none_or(|(uniform, cutover)| cutover < uniform)
                            || finalization
                                .is_some_and(|index| cutover.is_none_or(|cutover| index <= cutover))
                    }
                }
            {
                return Err(invalid_data(
                    "session consensus terminal transition scope is inconsistent",
                ));
            }
            Some(TerminalMembershipTransition {
                transition_id,
                transition_digest,
                outcome,
                transition_start_log_index: start,
                learners_ready_log_index: learners_ready,
                joint_membership_log_index: joint,
                uniform_membership_log_index: uniform,
                cutover_log_index: cutover,
                finalization_log_index: finalization,
            })
        }
        _ => {
            return Err(invalid_data(
                "session consensus terminal transition scope is incomplete",
            ));
        }
    };

    let authority_is_current = application_authority_epoch
        == current_identity.configuration_epoch()
        && application_authority_members == current_members;
    let authority_is_desired = pending.as_ref().is_some_and(|pending| {
        application_authority_epoch == pending.desired_identity.configuration_epoch()
            && application_authority_members == pending.desired_members
    });
    if !authority_is_current && !authority_is_desired {
        return Err(invalid_data(
            "session consensus application authority scope is inconsistent",
        ));
    }
    if let Some(predecessor) = &predecessor {
        let terminal_matches = terminal.as_ref().is_some_and(|terminal| {
            terminal.transition_id == predecessor.transition_id
                && terminal.transition_digest == predecessor.transition_digest
                && terminal.outcome == TerminalMembershipOutcome::Promoted
                && terminal.transition_start_log_index == predecessor.transition_start_log_index
                && terminal.cutover_log_index == Some(predecessor.cutover_log_index)
        });
        if !terminal_matches {
            return Err(invalid_data(
                "session consensus predecessor evidence is inconsistent",
            ));
        }
    }

    let history = read_membership_history_sync(conn, storage_identity)?;
    validate_membership_history_chain(&history, predecessor.as_ref(), current_identity)?;

    Ok(MembershipValidationScope {
        current_identity,
        current_members,
        current_bindings,
        application_authority_epoch,
        application_authority_members,
        predecessor,
        history,
        pending,
        terminal,
    })
}

fn membership_transaction(
    conn: &Connection,
) -> Result<Transaction<'_>, MembershipScopeMutationError> {
    Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)
}

fn read_scope_for_mutation(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> Result<MembershipValidationScope, MembershipScopeMutationError> {
    read_membership_scope_sync(conn, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)
}

pub(crate) fn stage_membership_scope_sync_with_bindings(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
    desired_identity: SessionConsensusIdentity,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
    desired_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let tx = membership_transaction(conn)?;
    let transition_start = last_log_sync(&tx, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?
        .map(|log_id| {
            log_id
                .index
                .checked_add(1)
                .ok_or(MembershipScopeMutationError::InvalidScope)
        })
        .transpose()?
        .unwrap_or(0);
    let result = stage_membership_scope_in_tx(
        &tx,
        storage_identity,
        transition_id,
        transition_digest,
        desired_identity,
        desired_members,
        desired_bindings,
        transition_start,
    )?;
    tx.commit()
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    Ok(result)
}

#[cfg(test)]
fn stage_membership_scope_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
    desired_identity: SessionConsensusIdentity,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    stage_membership_scope_sync_with_bindings(
        conn,
        storage_identity,
        transition_id,
        transition_digest,
        desired_identity,
        desired_members,
        &test_member_bindings(desired_members),
    )
}

pub(crate) fn stage_membership_scope_in_tx(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
    desired_identity: SessionConsensusIdentity,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
    desired_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    transition_start: u64,
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    if validate_member_set(desired_members, true).is_err() {
        return Err(MembershipScopeMutationError::InvalidScope);
    }
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    if !exact_successor_epoch(scope.current_identity, desired_identity)
        || validate_member_set(&scope.current_members, true).is_err()
        || (scope.predecessor.is_some() && scope.history.len() >= MEMBERSHIP_HISTORY_MAX_ENTRIES)
        || validate_transition_bindings(
            &scope.current_members,
            &scope.current_bindings,
            desired_members,
            desired_bindings,
        )
        .is_err()
    {
        return Err(MembershipScopeMutationError::InvalidScope);
    }
    if let Some(terminal) = &scope.terminal {
        if terminal.transition_id == transition_id {
            return if terminal.transition_digest == transition_digest {
                Ok(MembershipScopeMutation::Idempotent)
            } else {
                Err(MembershipScopeMutationError::ConflictingTransition)
            };
        }
    }
    if let Some(pending) = scope.pending {
        if pending.transition_id == transition_id
            && pending.transition_digest == transition_digest
            && pending.desired_identity == desired_identity
            && pending.desired_members == *desired_members
            && pending.desired_bindings == *desired_bindings
        {
            if pending.transition_start_log_index == transition_start
                || pending.transition_start_log_index != 0
            {
                return Ok(MembershipScopeMutation::Idempotent);
            }
            let candidate_can_adopt_exact_start = pending.transition_start_log_index == 0
                && transition_start > 0
                && pending.learners_ready_log_index.is_none()
                && pending.joint_membership_log_index.is_none()
                && pending.uniform_membership_log_index.is_none()
                && scope.application_authority_epoch
                    == scope.current_identity.configuration_epoch()
                && scope.application_authority_members == scope.current_members;
            if candidate_can_adopt_exact_start {
                let changed = conn
                    .execute(
                        "UPDATE consensus_membership_scope SET pending_transition_start_index = ?1 WHERE singleton = 1 AND pending_transition_id = ?2 AND pending_transition_digest = ?3 AND pending_transition_start_index = 0 AND pending_learners_ready_index IS NULL AND pending_joint_membership_index IS NULL AND pending_uniform_membership_index IS NULL",
                        params![
                            checked_i64(transition_start)
                                .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                            transition_id.as_slice(),
                            transition_digest.as_slice(),
                        ],
                    )
                    .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
                if changed != 1 {
                    return Err(MembershipScopeMutationError::ConflictingTransition);
                }
                read_scope_for_mutation(conn, storage_identity)?;
                return Ok(MembershipScopeMutation::Applied);
            }
        }
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    let changed = conn
        .execute(
            "UPDATE consensus_membership_scope SET pending_transition_id = ?1, pending_transition_digest = ?2, desired_configuration_id = ?3, desired_configuration_epoch = ?4, desired_members_json = ?5, desired_bindings_json = ?6, pending_transition_start_index = ?7 WHERE singleton = 1 AND storage_configuration_epoch = ?8",
            params![
                transition_id.as_slice(),
                transition_digest.as_slice(),
                desired_identity.configuration_id().as_bytes().as_slice(),
                checked_positive_i64(desired_identity.configuration_epoch().get())
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                encode_members(desired_members, true)
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                encode_bindings(desired_members, desired_bindings)
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                checked_i64(transition_start)
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                epoch_i64(storage_identity)
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
            ],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if changed != 1 {
        return Err(MembershipScopeMutationError::CorruptState);
    }
    read_scope_for_mutation(conn, storage_identity)?;
    Ok(MembershipScopeMutation::Applied)
}

pub(crate) fn read_membership_transition_evidence_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
) -> Result<Option<MembershipTransitionEvidence>, MembershipScopeMutationError> {
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    if let Some(pending) = &scope.pending {
        if pending.transition_id == transition_id {
            if pending.transition_digest != transition_digest {
                return Err(MembershipScopeMutationError::ConflictingTransition);
            }
            return Ok(Some(MembershipTransitionEvidence {
                outcome: None,
                transition_start_log_index: pending.transition_start_log_index,
                learners_ready_log_index: pending.learners_ready_log_index,
                joint_membership_log_index: pending.joint_membership_log_index,
                uniform_membership_log_index: pending.uniform_membership_log_index,
                cutover_log_index: None,
                finalization_log_index: None,
            }));
        }
    }
    if let Some(terminal) = &scope.terminal {
        if terminal.transition_id == transition_id {
            if terminal.transition_digest != transition_digest {
                return Err(MembershipScopeMutationError::ConflictingTransition);
            }
            return Ok(Some(MembershipTransitionEvidence {
                outcome: Some(terminal.outcome),
                transition_start_log_index: terminal.transition_start_log_index,
                learners_ready_log_index: terminal.learners_ready_log_index,
                joint_membership_log_index: terminal.joint_membership_log_index,
                uniform_membership_log_index: terminal.uniform_membership_log_index,
                cutover_log_index: terminal.cutover_log_index,
                finalization_log_index: terminal.finalization_log_index,
            }));
        }
    }
    Ok(None)
}

impl SqliteSessionBackend {
    pub(crate) async fn consensus_membership_scope_snapshot(
        &self,
        storage_identity: SessionConsensusIdentity,
    ) -> Result<
        (
            MembershipValidationScope,
            StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
        ),
        MembershipScopeMutationError,
    > {
        let conn = self.conn.lock().await;
        let scope = read_scope_for_mutation(&conn, storage_identity)?;
        let membership = read_membership_sync(&conn, storage_identity)
            .map_err(|_| MembershipScopeMutationError::CorruptState)?;
        Ok((scope, membership))
    }

    /// Atomically read the durable transition scope, exact evidence, and
    /// applied Openraft membership under the backend's single SQLite lock.
    pub(crate) async fn consensus_membership_transition_snapshot(
        &self,
        storage_identity: SessionConsensusIdentity,
        transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
        transition_digest: [u8; 32],
    ) -> Result<
        (
            MembershipValidationScope,
            Option<MembershipTransitionEvidence>,
            StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
        ),
        MembershipScopeMutationError,
    > {
        let conn = self.conn.lock().await;
        let scope = read_scope_for_mutation(&conn, storage_identity)?;
        let evidence = read_membership_transition_evidence_sync(
            &conn,
            storage_identity,
            transition_id,
            transition_digest,
        )?;
        let membership = read_membership_sync(&conn, storage_identity)
            .map_err(|_| MembershipScopeMutationError::CorruptState)?;
        Ok((scope, evidence, membership))
    }
}

fn record_membership_transition_evidence_in_tx(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> io::Result<()> {
    let scope = read_membership_scope_sync(conn, storage_identity)?;
    let Some(pending) = scope.pending else {
        return Ok(());
    };
    let log_index = membership
        .log_id()
        .ok_or_else(|| invalid_data("session consensus membership log identity is missing"))?
        .index;
    let shape = classify_transition_membership(
        membership,
        &scope.current_members,
        &pending.desired_members,
    )?;
    let (column, existing) = match shape {
        MembershipShape::CurrentUniform | MembershipShape::LearnersCatchingUp => return Ok(()),
        MembershipShape::Joint => (
            "pending_joint_membership_index",
            pending.joint_membership_log_index,
        ),
        MembershipShape::DesiredUniform => {
            let joint = pending.joint_membership_log_index.ok_or_else(|| {
                invalid_data("session consensus uniform membership preceded joint membership")
            })?;
            if log_index <= joint {
                return Err(invalid_data(
                    "session consensus membership transition evidence regressed",
                ));
            }
            (
                "pending_uniform_membership_index",
                pending.uniform_membership_log_index,
            )
        }
    };
    if matches!(
        shape,
        MembershipShape::Joint | MembershipShape::DesiredUniform
    ) && pending.learners_ready_log_index.is_none()
    {
        return Err(invalid_data(
            "session consensus membership changed before learners were durably ready",
        ));
    }
    if existing == Some(log_index) {
        return Ok(());
    }
    if existing.is_some() || log_index <= pending.transition_start_log_index {
        return Err(invalid_data(
            "session consensus membership transition evidence conflicts",
        ));
    }
    let changed = conn
        .execute(
            &format!(
                "UPDATE consensus_membership_scope SET {column} = ?1 WHERE singleton = 1 AND pending_transition_id = ?2 AND pending_transition_digest = ?3 AND {column} IS NULL"
            ),
            params![
                checked_i64(log_index)?,
                pending.transition_id.as_slice(),
                pending.transition_digest.as_slice(),
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data(
            "session consensus membership transition evidence conflicts",
        ));
    }
    read_membership_scope_sync(conn, storage_identity).map(|_| ())
}

/// Persist the committed proof that every added learner reached the
/// coordinator's catch-up barrier before authority fencing or joint consensus.
pub(crate) fn mark_membership_learners_ready_in_tx(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
    learners_ready_log_index: u64,
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    let pending = scope
        .pending
        .as_ref()
        .ok_or(MembershipScopeMutationError::ConflictingTransition)?;
    if pending.transition_id != transition_id || pending.transition_digest != transition_digest {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    if pending.learners_ready_log_index == Some(learners_ready_log_index) {
        return Ok(MembershipScopeMutation::Idempotent);
    }
    if pending.learners_ready_log_index.is_some()
        || learners_ready_log_index <= pending.transition_start_log_index
        || pending.joint_membership_log_index.is_some()
        || pending.uniform_membership_log_index.is_some()
    {
        return Err(MembershipScopeMutationError::InvalidScope);
    }
    let membership = read_membership_unchecked_sync(conn, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    if validate_all_added_learners_present(
        &membership,
        &scope.current_members,
        &pending.desired_members,
    )
    .is_err()
    {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    let changed = conn
        .execute(
            "UPDATE consensus_membership_scope SET pending_learners_ready_index = ?1 WHERE singleton = 1 AND pending_transition_id = ?2 AND pending_transition_digest = ?3 AND pending_learners_ready_index IS NULL AND pending_joint_membership_index IS NULL AND pending_uniform_membership_index IS NULL",
            params![
                checked_i64(learners_ready_log_index)
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                transition_id.as_slice(),
                transition_digest.as_slice(),
            ],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if changed != 1 {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    read_scope_for_mutation(conn, storage_identity)?;
    Ok(MembershipScopeMutation::Applied)
}

pub(crate) fn fence_application_authority_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let tx = membership_transaction(conn)?;
    let result =
        fence_application_authority_in_tx(&tx, storage_identity, transition_id, transition_digest)?;
    tx.commit()
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    Ok(result)
}

pub(crate) fn fence_application_authority_in_tx(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    let pending = scope
        .pending
        .as_ref()
        .ok_or(MembershipScopeMutationError::ConflictingTransition)?;
    if pending.transition_id != transition_id || pending.transition_digest != transition_digest {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    if pending.learners_ready_log_index.is_none() {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    if scope.application_authority_epoch == pending.desired_identity.configuration_epoch()
        && scope.application_authority_members == pending.desired_members
    {
        return Ok(MembershipScopeMutation::Idempotent);
    }
    let membership = read_membership_unchecked_sync(conn, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    if !matches!(
        classify_transition_membership(
            &membership,
            &scope.current_members,
            &pending.desired_members,
        ),
        Ok(MembershipShape::CurrentUniform | MembershipShape::LearnersCatchingUp)
    ) {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    let changed = conn
        .execute(
            "UPDATE consensus_membership_scope SET application_authority_epoch = desired_configuration_epoch, application_authority_members_json = desired_members_json WHERE singleton = 1 AND pending_transition_id = ?1 AND pending_transition_digest = ?2",
            params![transition_id.as_slice(), transition_digest.as_slice()],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if changed != 1 {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    read_scope_for_mutation(conn, storage_identity)?;
    Ok(MembershipScopeMutation::Applied)
}

pub(crate) fn validate_application_authority_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    origin: SessionConsensusNodeId,
    authority_identity: SessionConsensusIdentity,
) -> io::Result<()> {
    let scope = read_membership_scope_sync(conn, storage_identity)?;
    let durable_authority_identity = if scope.application_authority_epoch
        == scope.current_identity.configuration_epoch()
    {
        Some(scope.current_identity)
    } else {
        scope.pending.as_ref().and_then(|pending| {
            (scope.application_authority_epoch == pending.desired_identity.configuration_epoch())
                .then_some(pending.desired_identity)
        })
    };
    if durable_authority_identity != Some(authority_identity)
        || !scope.application_authority_members.contains(&origin)
    {
        return Err(invalid_data(
            "session consensus application origin is not authoritative",
        ));
    }
    Ok(())
}

pub(crate) fn abort_membership_scope_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let tx = membership_transaction(conn)?;
    let result = restore_and_abort_membership_scope_in_tx(
        &tx,
        storage_identity,
        transition_id,
        transition_digest,
    )?;
    tx.commit()
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    Ok(result)
}

pub(crate) fn restore_and_abort_membership_scope_in_tx(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    let Some(pending) = scope.pending.as_ref() else {
        return match scope.terminal {
            Some(terminal)
                if terminal.transition_id == transition_id
                    && terminal.transition_digest == transition_digest
                    && terminal.outcome == TerminalMembershipOutcome::Aborted =>
            {
                Ok(MembershipScopeMutation::Idempotent)
            }
            _ => Err(MembershipScopeMutationError::ConflictingTransition),
        };
    };
    if pending.transition_id != transition_id || pending.transition_digest != transition_digest {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    if pending.joint_membership_log_index.is_some()
        || pending.uniform_membership_log_index.is_some()
    {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    let membership = read_membership_unchecked_sync(conn, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    if validate_uniform_membership(&membership, &scope.current_members).is_err() {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    let changed = conn
        .execute(
            "UPDATE consensus_membership_scope SET application_authority_epoch = current_configuration_epoch, application_authority_members_json = current_members_json, terminal_transition_id = ?1, terminal_transition_digest = ?2, terminal_transition_outcome = 1, terminal_transition_start_index = pending_transition_start_index, terminal_learners_ready_index = pending_learners_ready_index, terminal_joint_membership_index = pending_joint_membership_index, terminal_uniform_membership_index = pending_uniform_membership_index, terminal_cutover_index = NULL, terminal_finalization_index = NULL, pending_transition_id = NULL, pending_transition_digest = NULL, desired_configuration_id = NULL, desired_configuration_epoch = NULL, desired_members_json = NULL, desired_bindings_json = NULL, pending_transition_start_index = NULL, pending_learners_ready_index = NULL, pending_joint_membership_index = NULL, pending_uniform_membership_index = NULL WHERE singleton = 1 AND pending_transition_id = ?1 AND pending_transition_digest = ?2",
            params![transition_id.as_slice(), transition_digest.as_slice()],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if changed != 1 {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    read_scope_for_mutation(conn, storage_identity)?;
    Ok(MembershipScopeMutation::Applied)
}

pub(crate) fn promote_membership_scope_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let tx = membership_transaction(conn)?;
    let membership = read_membership_unchecked_sync(&tx, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    let cutover_log_index = membership
        .log_id()
        .ok_or(MembershipScopeMutationError::TransitionNotQuiescent)?
        .index;
    let result = promote_membership_scope_at_in_tx(
        &tx,
        storage_identity,
        transition_id,
        transition_digest,
        cutover_log_index,
    )?;
    tx.commit()
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    Ok(result)
}

fn promote_membership_scope_at_in_tx(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
    cutover_log_index: u64,
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    if scope.predecessor.is_some() && scope.history.len() >= MEMBERSHIP_HISTORY_MAX_ENTRIES {
        return Err(MembershipScopeMutationError::CompactionRequired);
    }
    let Some(pending) = scope.pending.as_ref() else {
        return match scope.terminal {
            Some(terminal)
                if terminal.transition_id == transition_id
                    && terminal.transition_digest == transition_digest
                    && terminal.outcome == TerminalMembershipOutcome::Promoted =>
            {
                Ok(MembershipScopeMutation::Idempotent)
            }
            _ => Err(MembershipScopeMutationError::ConflictingTransition),
        };
    };
    if pending.transition_id != transition_id || pending.transition_digest != transition_digest {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    if scope.application_authority_epoch != pending.desired_identity.configuration_epoch()
        || scope.application_authority_members != pending.desired_members
    {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    let membership = read_membership_unchecked_sync(conn, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    if !matches!(
        classify_transition_membership(
            &membership,
            &scope.current_members,
            &pending.desired_members,
        ),
        Ok(MembershipShape::DesiredUniform)
    ) {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    if membership.log_id().map(|log_id| log_id.index) != Some(cutover_log_index)
        || pending.uniform_membership_log_index != Some(cutover_log_index)
    {
        return Err(MembershipScopeMutationError::CorruptState);
    }
    if let Some(predecessor) = &scope.predecessor {
        conn.execute(
            "INSERT INTO consensus_membership_history (configuration_epoch, storage_configuration_epoch, configuration_id, members_json, transition_id, transition_digest, transition_start_index, cutover_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                checked_positive_i64(predecessor.identity.configuration_epoch().get())
                    .map_err(|_| MembershipScopeMutationError::CorruptState)?,
                epoch_i64(storage_identity)
                    .map_err(|_| MembershipScopeMutationError::CorruptState)?,
                predecessor.identity.configuration_id().as_bytes().as_slice(),
                encode_members(&predecessor.members, true)
                    .map_err(|_| MembershipScopeMutationError::CorruptState)?,
                predecessor.transition_id.as_slice(),
                predecessor.transition_digest.as_slice(),
                checked_i64(predecessor.transition_start_log_index)
                    .map_err(|_| MembershipScopeMutationError::CorruptState)?,
                checked_i64(predecessor.cutover_log_index)
                    .map_err(|_| MembershipScopeMutationError::CorruptState)?,
            ],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    }
    let changed = conn
        .execute(
            "UPDATE consensus_membership_scope SET predecessor_configuration_id = current_configuration_id, predecessor_transition_id = pending_transition_id, predecessor_transition_digest = pending_transition_digest, predecessor_configuration_epoch = current_configuration_epoch, predecessor_members_json = current_members_json, predecessor_transition_start_index = pending_transition_start_index, predecessor_cutover_index = ?1, current_configuration_id = desired_configuration_id, current_configuration_epoch = desired_configuration_epoch, current_members_json = desired_members_json, current_bindings_json = desired_bindings_json, terminal_transition_id = ?2, terminal_transition_digest = ?3, terminal_transition_outcome = 2, terminal_transition_start_index = pending_transition_start_index, terminal_learners_ready_index = pending_learners_ready_index, terminal_joint_membership_index = pending_joint_membership_index, terminal_uniform_membership_index = pending_uniform_membership_index, terminal_cutover_index = ?1, terminal_finalization_index = NULL, pending_transition_id = NULL, pending_transition_digest = NULL, desired_configuration_id = NULL, desired_configuration_epoch = NULL, desired_members_json = NULL, desired_bindings_json = NULL, pending_transition_start_index = NULL, pending_learners_ready_index = NULL, pending_joint_membership_index = NULL, pending_uniform_membership_index = NULL WHERE singleton = 1 AND pending_transition_id = ?2 AND pending_transition_digest = ?3",
            params![
                checked_i64(cutover_log_index)
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                transition_id.as_slice(),
                transition_digest.as_slice(),
            ],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if changed != 1 {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    read_scope_for_mutation(conn, storage_identity)?;
    Ok(MembershipScopeMutation::Applied)
}

pub(crate) fn promote_membership_scope_if_quiescent_in_tx(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> Result<Option<MembershipScopeMutation>, MembershipScopeMutationError> {
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    let Some(pending) = scope.pending else {
        return Ok(None);
    };
    let membership = read_membership_unchecked_sync(conn, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    let Some(cutover_log_index) = membership.log_id().map(|log_id| log_id.index) else {
        return Ok(None);
    };
    match promote_membership_scope_at_in_tx(
        conn,
        storage_identity,
        pending.transition_id,
        pending.transition_digest,
        cutover_log_index,
    ) {
        Ok(result) => Ok(Some(result)),
        Err(MembershipScopeMutationError::TransitionNotQuiescent) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Record the exact committed `FinalizeTopologyTransition` command index.
///
/// This is intentionally a state-machine-apply operation. The coordinator must
/// never infer completion from leader-local control flow: every surviving
/// member observes the same durable index before re-admitting application
/// traffic.
pub(crate) fn finalize_membership_transition_in_tx(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
    finalization_log_index: u64,
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    if scope.pending.is_some() {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    let terminal = scope
        .terminal
        .as_ref()
        .ok_or(MembershipScopeMutationError::ConflictingTransition)?;
    if terminal.transition_id != transition_id
        || terminal.transition_digest != transition_digest
        || terminal.outcome != TerminalMembershipOutcome::Promoted
    {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    if terminal.finalization_log_index == Some(finalization_log_index) {
        return Ok(MembershipScopeMutation::Idempotent);
    }
    if terminal.finalization_log_index.is_some()
        || terminal
            .cutover_log_index
            .is_none_or(|cutover| finalization_log_index <= cutover)
    {
        return Err(MembershipScopeMutationError::InvalidScope);
    }
    let changed = conn
        .execute(
            "UPDATE consensus_membership_scope SET terminal_finalization_index = ?1 WHERE singleton = 1 AND terminal_transition_id = ?2 AND terminal_transition_digest = ?3 AND terminal_transition_outcome = 2 AND terminal_finalization_index IS NULL AND terminal_cutover_index < ?1",
            params![
                checked_i64(finalization_log_index)
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                transition_id.as_slice(),
                transition_digest.as_slice(),
            ],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if changed != 1 {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    read_scope_for_mutation(conn, storage_identity)?;
    Ok(MembershipScopeMutation::Applied)
}

pub(crate) fn drop_compacted_membership_predecessor_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> Result<DroppedMembershipPredecessor, MembershipScopeMutationError> {
    let tx = membership_transaction(conn)?;
    let scope = read_scope_for_mutation(&tx, storage_identity)?;
    if scope.pending.is_some() {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    let Some(predecessor) = scope.predecessor.as_ref() else {
        return Ok(DroppedMembershipPredecessor {
            invalidated_snapshot_file: None,
        });
    };
    let purged = read_purged_sync(&tx, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    if purged.is_none_or(|log_id| log_id.index < predecessor.cutover_log_index) {
        return Err(MembershipScopeMutationError::CompactionRequired);
    }
    let retained_before_or_at_cutover: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM consensus_log WHERE log_index <= ?1)",
            [checked_i64(predecessor.cutover_log_index)
                .map_err(|_| MembershipScopeMutationError::CorruptState)?],
            |row| row.get(0),
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if retained_before_or_at_cutover {
        return Err(MembershipScopeMutationError::CompactionRequired);
    }
    let snapshot = read_current_snapshot_sync(&tx, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    let Some((meta, _, _, _)) = snapshot else {
        return Err(MembershipScopeMutationError::CompactionRequired);
    };
    if meta
        .last_log_id
        .is_none_or(|log_id| log_id.index < predecessor.cutover_log_index)
    {
        return Err(MembershipScopeMutationError::CompactionRequired);
    }
    if scope.history.len() >= MEMBERSHIP_HISTORY_MAX_ENTRIES {
        return Err(MembershipScopeMutationError::CompactionRequired);
    }
    tx.execute(
        "INSERT INTO consensus_membership_history (configuration_epoch, storage_configuration_epoch, configuration_id, members_json, transition_id, transition_digest, transition_start_index, cutover_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            checked_positive_i64(predecessor.identity.configuration_epoch().get())
                .map_err(|_| MembershipScopeMutationError::CorruptState)?,
            epoch_i64(storage_identity).map_err(|_| MembershipScopeMutationError::CorruptState)?,
            predecessor.identity.configuration_id().as_bytes().as_slice(),
            encode_members(&predecessor.members, true)
                .map_err(|_| MembershipScopeMutationError::CorruptState)?,
            predecessor.transition_id.as_slice(),
            predecessor.transition_digest.as_slice(),
            checked_i64(predecessor.transition_start_log_index)
                .map_err(|_| MembershipScopeMutationError::CorruptState)?,
            checked_i64(predecessor.cutover_log_index)
                .map_err(|_| MembershipScopeMutationError::CorruptState)?,
        ],
    )
    .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    let changed = tx
        .execute(
            "UPDATE consensus_membership_scope SET predecessor_configuration_id = NULL, predecessor_transition_id = NULL, predecessor_transition_digest = NULL, predecessor_configuration_epoch = NULL, predecessor_members_json = NULL, predecessor_transition_start_index = NULL, predecessor_cutover_index = NULL WHERE singleton = 1",
            [],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if changed != 1 {
        return Err(MembershipScopeMutationError::CorruptState);
    }
    read_scope_for_mutation(&tx, storage_identity)?;
    tx.commit()
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    Ok(DroppedMembershipPredecessor {
        invalidated_snapshot_file: None,
    })
}

fn legacy_authority_is_nonempty(conn: &Connection) -> rusqlite::Result<bool> {
    for table in [
        "session_records",
        "leases",
        "key_fences",
        "session_replication_log",
    ] {
        if table_exists(conn, table)? {
            let sql = format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)");
            if conn.query_row(&sql, [], |row| row.get::<_, bool>(0))? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn validate_existing_schema(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> Result<(), SessionConsensusStorageError> {
    for table in [
        "consensus_identity",
        "consensus_membership_scope",
        "consensus_membership_history",
        "consensus_vote",
        "consensus_committed",
        "consensus_purged",
        "consensus_log",
        "consensus_applied",
        "consensus_membership",
        "consensus_machine",
        "consensus_request_outcomes",
        "consensus_snapshot",
        "consensus_operator_recovery",
    ] {
        if !table_exists(conn, table)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        {
            return Err(SessionConsensusStorageError::CorruptState);
        }
    }

    if read_storage_identity_sync(conn)? != storage_identity {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }

    let machine_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM consensus_machine", [], |row| {
            row.get(0)
        })
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let membership_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM consensus_membership", [], |row| {
            row.get(0)
        })
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    if machine_rows != 1 || membership_rows != 1 {
        return Err(SessionConsensusStorageError::CorruptState);
    }
    validate_persisted_membership_sync(conn, storage_identity)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    Ok(())
}

const OPERATOR_RECOVERY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS consensus_operator_recovery (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    last_plan_digest BLOB NOT NULL CHECK (length(last_plan_digest) = 32),
    pending_epoch INTEGER CHECK (pending_epoch > recovery_epoch),
    pending_plan_digest BLOB CHECK (
        pending_plan_digest IS NULL OR length(pending_plan_digest) = 32
    ),
    watch_cursor_invalidation_floor INTEGER NOT NULL DEFAULT 0 CHECK (watch_cursor_invalidation_floor >= 0),
    CHECK (
        (pending_epoch IS NULL AND pending_plan_digest IS NULL)
        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL)
    ),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);
"#;

const PRE_CURSOR_OPERATOR_RECOVERY_SCHEMA: &str = r#"
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
"#;

const OPERATOR_RECOVERY_CURSOR_MIGRATION: &str =
    "ALTER TABLE consensus_operator_recovery ADD COLUMN watch_cursor_invalidation_floor INTEGER NOT NULL DEFAULT 0 CHECK (watch_cursor_invalidation_floor >= 0);";

pub(crate) fn ensure_operator_recovery_schema_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    conn.execute_batch(OPERATOR_RECOVERY_SCHEMA)
        .map_err(db_error)?;
    let has_cursor_floor: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_operator_recovery') WHERE name = 'watch_cursor_invalidation_floor')",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if !has_cursor_floor {
        conn.execute_batch(OPERATOR_RECOVERY_CURSOR_MIGRATION)
            .map_err(db_error)?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO consensus_operator_recovery (singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor) VALUES (1, ?1, 0, ?2, NULL, NULL, 0)",
        params![epoch_i64(identity)?, [0_u8; 32].as_slice()],
    )
    .map_err(db_error)?;
    let (stored_epoch, rows): (i64, i64) = conn
        .query_row(
            "SELECT configuration_epoch, (SELECT COUNT(*) FROM consensus_operator_recovery) FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db_error)?;
    validate_epoch(stored_epoch, identity)?;
    if rows != 1 {
        return Err(invalid_data(
            "session consensus operator recovery state is invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OperatorRecoveryState {
    pub(crate) recovery_epoch: u64,
    pub(crate) last_plan_digest: [u8; 32],
    pub(crate) pending_epoch: Option<u64>,
    pub(crate) pending_plan_digest: Option<[u8; 32]>,
    pub(crate) watch_cursor_invalidation_floor: u64,
}

type StoredOperatorRecoveryRow = (i64, i64, Vec<u8>, Option<i64>, Option<Vec<u8>>, i64);

pub(crate) fn read_operator_recovery_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<OperatorRecoveryState> {
    if !table_exists(conn, "consensus_operator_recovery").map_err(db_error)? {
        return Ok(OperatorRecoveryState {
            recovery_epoch: 0,
            last_plan_digest: [0; 32],
            pending_epoch: None,
            pending_plan_digest: None,
            watch_cursor_invalidation_floor: 0,
        });
    }
    let row: StoredOperatorRecoveryRow = if operator_recovery_cursor_column_exists(conn)? {
        conn.query_row(
            "SELECT configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .map_err(db_error)?
    } else {
        let legacy: (i64, i64, Vec<u8>, Option<i64>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest FROM consensus_operator_recovery WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .map_err(db_error)?;
        (legacy.0, legacy.1, legacy.2, legacy.3, legacy.4, 0)
    };
    let (stored_epoch, recovery_epoch, last_digest, pending_epoch, pending_digest, cursor_floor) =
        row;
    validate_epoch(stored_epoch, identity)?;
    let recovery_epoch = checked_u64(recovery_epoch)?;
    let last_plan_digest = last_digest
        .try_into()
        .map_err(|_| invalid_data("session consensus recovery plan digest has invalid length"))?;
    let pending_epoch = pending_epoch.map(checked_positive_u64).transpose()?;
    let pending_plan_digest = pending_digest
        .map(|value| {
            value.try_into().map_err(|_| {
                invalid_data("session consensus pending recovery digest has invalid length")
            })
        })
        .transpose()?;
    if pending_epoch.is_some() != pending_plan_digest.is_some()
        || pending_epoch.is_some_and(|pending| pending <= recovery_epoch)
    {
        return Err(invalid_data(
            "session consensus pending recovery state is invalid",
        ));
    }
    Ok(OperatorRecoveryState {
        recovery_epoch,
        last_plan_digest,
        pending_epoch,
        pending_plan_digest,
        watch_cursor_invalidation_floor: checked_u64(cursor_floor)?,
    })
}

pub(crate) fn read_watch_cursor_invalidation_floor_sync(conn: &Connection) -> io::Result<u64> {
    if !table_exists(conn, "consensus_operator_recovery").map_err(db_error)?
        || !operator_recovery_cursor_column_exists(conn)?
    {
        return Ok(0);
    }
    let floor: i64 = conn
        .query_row(
            "SELECT watch_cursor_invalidation_floor FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    checked_u64(floor)
}

fn operator_recovery_cursor_column_exists(conn: &Connection) -> io::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_operator_recovery') WHERE name = 'watch_cursor_invalidation_floor')",
        [],
        |row| row.get(0),
    )
    .map_err(db_error)
}

pub(crate) fn mark_operator_recovery_pending_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    pending_epoch: u64,
    plan_digest: [u8; 32],
) -> io::Result<()> {
    ensure_operator_recovery_schema_sync(conn, identity)?;
    let current = read_operator_recovery_sync(conn, identity)?;
    match (current.pending_epoch, current.pending_plan_digest) {
        (Some(epoch), Some(digest)) if epoch == pending_epoch && digest == plan_digest => {
            return Ok(());
        }
        (Some(_), Some(_)) => {
            return Err(invalid_data(
                "a different session operator recovery workflow is already pending",
            ));
        }
        (None, None) => {}
        _ => {
            return Err(invalid_data(
                "session operator recovery pending state is incomplete",
            ));
        }
    }
    if pending_epoch <= current.recovery_epoch {
        return Err(invalid_data(
            "session consensus pending recovery epoch did not advance",
        ));
    }
    conn.execute(
        "UPDATE consensus_operator_recovery SET pending_epoch = ?1, pending_plan_digest = ?2 WHERE singleton = 1 AND configuration_epoch = ?3",
        params![
            checked_positive_i64(pending_epoch)?,
            plan_digest.as_slice(),
            epoch_i64(identity)?,
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorRecoveryApply {
    Applied,
    Idempotent,
    Rejected,
}

pub(crate) fn finalize_operator_recovery_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    recovery_epoch: u64,
    plan_digest: [u8; 32],
    fence_high_water: u64,
    credential_high_water: u64,
) -> io::Result<OperatorRecoveryApply> {
    ensure_operator_recovery_schema_sync(conn, identity)?;
    let current = read_operator_recovery_sync(conn, identity)?;
    if let (Some(pending_epoch), Some(pending_digest)) =
        (current.pending_epoch, current.pending_plan_digest)
    {
        if pending_epoch != recovery_epoch || pending_digest != plan_digest {
            return Ok(OperatorRecoveryApply::Rejected);
        }
    }
    if current.recovery_epoch == recovery_epoch {
        return Ok(if current.last_plan_digest == plan_digest {
            OperatorRecoveryApply::Idempotent
        } else {
            OperatorRecoveryApply::Rejected
        });
    }
    if recovery_epoch <= current.recovery_epoch {
        return Ok(OperatorRecoveryApply::Rejected);
    }

    let observed_fence = observed_fence_high_water_sync(conn)?;
    let observed_credential = observed_credential_high_water_sync(conn)?;
    if fence_high_water < observed_fence || credential_high_water < observed_credential {
        return Ok(OperatorRecoveryApply::Rejected);
    }
    let next_fence = fence_high_water
        .checked_add(1)
        .ok_or_else(|| invalid_data("session recovery fence high-water exhausted"))?;
    let next_credential = credential_high_water
        .checked_add(1)
        .ok_or_else(|| invalid_data("session recovery credential high-water exhausted"))?;

    conn.execute("UPDATE leases SET active = 0", [])
        .map_err(db_error)?;
    conn.execute(
        "UPDATE lease_globals SET val = ?1 WHERE key = 'next_fence'",
        [checked_positive_i64(next_fence)?],
    )
    .map_err(db_error)?;
    conn.execute(
        "UPDATE lease_globals SET val = ?1 WHERE key = 'next_credential_id'",
        [checked_positive_i64(next_credential)?],
    )
    .map_err(db_error)?;
    let changed = conn
        .execute(
            "UPDATE consensus_operator_recovery SET recovery_epoch = ?1, last_plan_digest = ?2, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1 AND configuration_epoch = ?3",
            params![
                checked_positive_i64(recovery_epoch)?,
                plan_digest.as_slice(),
                epoch_i64(identity)?,
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data(
            "session consensus recovery state was not updated",
        ));
    }
    Ok(OperatorRecoveryApply::Applied)
}

pub(crate) fn observed_fence_high_water_sync(conn: &Connection) -> io::Result<u64> {
    let mut high = 0_u64;
    for sql in [
        "SELECT MAX(fence) FROM session_records",
        "SELECT MAX(fence) FROM leases",
        "SELECT MAX(fence) FROM key_fences",
    ] {
        let value: Option<i64> = conn
            .query_row(sql, [], |row| row.get(0))
            .map_err(db_error)?;
        if let Some(value) = value {
            high = high.max(checked_u64(value)?);
        }
    }
    let next: i64 = conn
        .query_row(
            "SELECT val FROM lease_globals WHERE key = 'next_fence'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let next = checked_positive_u64(next)?;
    Ok(high.max(next.saturating_sub(1)))
}

pub(crate) fn observed_credential_high_water_sync(conn: &Connection) -> io::Result<u64> {
    let mut high = conn
        .query_row("SELECT MAX(credential_id) FROM leases", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .map_err(db_error)?
        .map(checked_u64)
        .transpose()?
        .unwrap_or(0);
    let next: i64 = conn
        .query_row(
            "SELECT val FROM lease_globals WHERE key = 'next_credential_id'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let next = checked_positive_u64(next)?;
    high = high.max(next.saturating_sub(1));
    Ok(high)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn claim_legacy_checkpoint_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    checkpoint_digest: [u8; 32],
    pending_recovery_epoch: u64,
    plan_digest: [u8; 32],
    application_sequence_high_water: u64,
    watch_cursor_invalidation_floor: u64,
) -> io::Result<()> {
    validate_member_set(expected_members, false)?;
    if table_exists(conn, "consensus_identity").map_err(db_error)? {
        return Err(invalid_data(
            "session recovery checkpoint is already consensus-owned",
        ));
    }
    validate_sealed_state_sync(conn)?;
    let logical_time: Option<String> = conn
        .query_row(
            "SELECT timestamp FROM session_replication_log ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    if let Some(value) = &logical_time {
        Timestamp::from_str(value)
            .map_err(|_| invalid_data("legacy checkpoint logical time is invalid"))?;
    }

    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    tx.execute_batch(CONSENSUS_SCHEMA).map_err(db_error)?;
    let epoch = epoch_i64(identity)?;
    tx.execute(
        "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
            identity.cluster_id().as_bytes().as_slice(),
            identity.configuration_id().as_bytes().as_slice(),
            epoch,
        ],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO consensus_membership (singleton, configuration_epoch, membership_json) VALUES (1, ?1, ?2)",
        params![
            epoch,
            encode_json(&StoredMembership::<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>::default())?,
        ],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO consensus_machine (singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            epoch,
            checked_i64(application_sequence_high_water)?,
            checkpoint_digest.as_slice(),
            logical_time,
            checked_i64(watch_cursor_invalidation_floor)?,
        ],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO consensus_operator_recovery (singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor) VALUES (1, ?1, 0, ?2, ?3, ?4, ?5)",
        params![
            epoch,
            [0_u8; 32].as_slice(),
            checked_positive_i64(pending_recovery_epoch)?,
            plan_digest.as_slice(),
            checked_i64(watch_cursor_invalidation_floor)?,
        ],
    )
    .map_err(db_error)?;
    ensure_membership_scope_schema_sync(
        &tx,
        identity,
        identity,
        expected_members,
        &BTreeMap::new(),
    )?;
    tx.execute("DELETE FROM session_replication_log", [])
        .map_err(db_error)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn checked_i64(value: u64) -> io::Result<i64> {
    i64::try_from(value).map_err(|_| invalid_data("session consensus integer exceeds SQLite range"))
}

pub(crate) fn checked_positive_i64(value: u64) -> io::Result<i64> {
    if value == 0 {
        return Err(invalid_data("session consensus integer must be positive"));
    }
    checked_i64(value)
}

pub(crate) fn checked_u64(value: i64) -> io::Result<u64> {
    u64::try_from(value).map_err(|_| invalid_data("negative session consensus integer"))
}

pub(crate) fn checked_positive_u64(value: i64) -> io::Result<u64> {
    let value = checked_u64(value)?;
    if value == 0 {
        return Err(invalid_data("session consensus integer must be positive"));
    }
    Ok(value)
}

pub(crate) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn db_error(_: rusqlite::Error) -> io::Error {
    io::Error::other("session consensus SQLite operation failed")
}

fn encode_json<T: serde::Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid_data("session consensus encoding failed"))
}

fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(|_| invalid_data("session consensus decoding failed"))
}

fn epoch_i64(identity: SessionConsensusIdentity) -> io::Result<i64> {
    checked_positive_i64(identity.configuration_epoch().get())
}

fn validate_epoch(stored: i64, identity: SessionConsensusIdentity) -> io::Result<()> {
    if checked_positive_u64(stored)? != identity.configuration_epoch().get() {
        return Err(invalid_data(
            "session consensus configuration epoch mismatch",
        ));
    }
    Ok(())
}

fn validate_log_id(log_id: &LogId<SessionConsensusNodeId>) -> io::Result<(i64, i64)> {
    let term = checked_i64(log_id.leader_id.term)?;
    let index = checked_i64(log_id.index)?;
    Ok((term, index))
}

pub(crate) fn validate_command_for_log(
    command: &SessionConsensusCommand,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    if command.schema_version != SESSION_CONSENSUS_SCHEMA_VERSION {
        return Err(invalid_data("unsupported session consensus command schema"));
    }
    if command.identity != identity {
        return Err(invalid_data("session consensus command identity mismatch"));
    }
    if let SessionMutationIntent::FinalizeOperatorRecovery {
        recovery_epoch,
        plan_digest,
        fence_high_water,
        credential_high_water,
    } = &command.intent
    {
        if *recovery_epoch == 0
            || plan_digest.iter().all(|byte| *byte == 0)
            || *fence_high_water == u64::MAX
            || *credential_high_water == u64::MAX
        {
            return Err(invalid_data(
                "session consensus operator recovery command is invalid",
            ));
        }
    }
    let semantic_intent = match &command.intent {
        SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
        intent => intent,
    };
    if let SessionMutationIntent::CompareAndSet(op) = semantic_intent {
        crate::ttl::validate_stored_record_expiry_at(&op.new_record, command.logical_time)
            .map_err(|_| invalid_data("session consensus record expiry is invalid"))?;
        if op.new_record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
            return Err(invalid_data(
                "session consensus requires a sealed record payload",
            ));
        }
        op.new_record
            .payload
            .validate_envelope_for_record(&op.new_record)
            .map_err(|_| invalid_data("session consensus record envelope is invalid"))?;
    }
    Ok(())
}

fn validate_entry_for_membership_scope(
    entry: &Entry<SessionRaftTypeConfig>,
    storage_identity: SessionConsensusIdentity,
    scope: &MembershipValidationScope,
) -> io::Result<()> {
    match &entry.payload {
        EntryPayload::Normal(command) => validate_command_for_log(command, storage_identity),
        EntryPayload::Membership(membership) => validate_membership_for_log(
            &StoredMembership::new(Some(entry.log_id), membership.clone()),
            scope,
            entry.log_id.index,
        ),
        EntryPayload::Blank => Ok(()),
    }
}

struct MembershipLogProjection {
    scope: MembershipValidationScope,
    membership: StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    projected_requests: BTreeMap<[u8; 16], [u8; 32]>,
}

impl MembershipLogProjection {
    fn load(conn: &Connection, storage_identity: SessionConsensusIdentity) -> io::Result<Self> {
        Ok(Self {
            scope: read_membership_scope_sync(conn, storage_identity)?,
            membership: read_membership_sync(conn, storage_identity)?,
            projected_requests: BTreeMap::new(),
        })
    }

    fn project(
        &mut self,
        conn: &Connection,
        entry: &Entry<SessionRaftTypeConfig>,
        storage_identity: SessionConsensusIdentity,
    ) -> io::Result<()> {
        validate_entry_for_membership_scope(entry, storage_identity, &self.scope)?;
        match &entry.payload {
            EntryPayload::Blank => Ok(()),
            EntryPayload::Membership(membership) => {
                let stored = StoredMembership::new(Some(entry.log_id), membership.clone());
                let mut promote = false;
                if let Some(pending) = self.scope.pending.as_mut() {
                    match classify_transition_membership(
                        &stored,
                        &self.scope.current_members,
                        &pending.desired_members,
                    )? {
                        MembershipShape::Joint => {
                            if pending.learners_ready_log_index.is_none()
                                || pending.joint_membership_log_index.is_some()
                                || entry.log_id.index <= pending.transition_start_log_index
                            {
                                return Err(invalid_data(
                                    "projected session consensus joint evidence conflicts",
                                ));
                            }
                            pending.joint_membership_log_index = Some(entry.log_id.index);
                        }
                        MembershipShape::DesiredUniform => {
                            if pending
                                .joint_membership_log_index
                                .is_none_or(|joint| entry.log_id.index <= joint)
                                || pending.uniform_membership_log_index.is_some()
                            {
                                return Err(invalid_data(
                                    "projected session consensus uniform evidence conflicts",
                                ));
                            }
                            pending.uniform_membership_log_index = Some(entry.log_id.index);
                            promote = true;
                        }
                        MembershipShape::CurrentUniform | MembershipShape::LearnersCatchingUp => {}
                    }
                }
                self.membership = stored;
                if promote {
                    self.promote_at(entry.log_id.index)?;
                }
                Ok(())
            }
            EntryPayload::Normal(command) => {
                let digest = payload_digest(command)?;
                let request_id = *command.request_id.as_bytes();
                if let Some(projected) = self.projected_requests.get(&request_id) {
                    return if projected == &digest {
                        Ok(())
                    } else {
                        Err(invalid_data(
                            "projected session consensus request ID was reused",
                        ))
                    };
                }
                if let Some((persisted, _)) =
                    read_outcome_sync(conn, storage_identity, command.request_id)?
                {
                    if persisted != digest {
                        return Err(invalid_data(
                            "persisted session consensus request ID was reused",
                        ));
                    }
                    self.projected_requests.insert(request_id, digest);
                    return Ok(());
                }
                self.projected_requests.insert(request_id, digest);
                self.project_intent(&command.intent, entry.log_id.index)
            }
        }
    }

    fn promote_at(&mut self, cutover_log_index: u64) -> io::Result<()> {
        let pending = self.scope.pending.take().ok_or_else(|| {
            invalid_data("projected session consensus promotion has no transition")
        })?;
        if self.scope.application_authority_epoch != pending.desired_identity.configuration_epoch()
            || self.scope.application_authority_members != pending.desired_members
            || pending.learners_ready_log_index.is_none()
            || pending.joint_membership_log_index.is_none()
            || pending.uniform_membership_log_index != Some(cutover_log_index)
        {
            self.scope.pending = Some(pending);
            return Err(invalid_data(
                "projected session consensus promotion evidence is incomplete",
            ));
        }
        if let Some(predecessor) = self.scope.predecessor.take() {
            if self.scope.history.len() >= MEMBERSHIP_HISTORY_MAX_ENTRIES {
                self.scope.predecessor = Some(predecessor);
                self.scope.pending = Some(pending);
                return Err(invalid_data(
                    "projected session consensus membership history is full",
                ));
            }
            self.scope.history.push(predecessor);
        }
        let predecessor = MembershipPredecessorScope {
            transition_id: pending.transition_id,
            transition_digest: pending.transition_digest,
            identity: self.scope.current_identity,
            members: self.scope.current_members.clone(),
            transition_start_log_index: pending.transition_start_log_index,
            cutover_log_index,
        };
        self.scope.current_identity = pending.desired_identity;
        self.scope.current_members = pending.desired_members;
        self.scope.current_bindings = pending.desired_bindings;
        self.scope.predecessor = Some(predecessor);
        self.scope.terminal = Some(TerminalMembershipTransition {
            transition_id: pending.transition_id,
            transition_digest: pending.transition_digest,
            outcome: TerminalMembershipOutcome::Promoted,
            transition_start_log_index: pending.transition_start_log_index,
            learners_ready_log_index: pending.learners_ready_log_index,
            joint_membership_log_index: pending.joint_membership_log_index,
            uniform_membership_log_index: pending.uniform_membership_log_index,
            cutover_log_index: Some(cutover_log_index),
            finalization_log_index: None,
        });
        Ok(())
    }

    fn project_intent(&mut self, intent: &SessionMutationIntent, log_index: u64) -> io::Result<()> {
        match intent {
            SessionMutationIntent::PrepareTopologyTransition {
                transition_id,
                request_digest,
                desired_identity,
                desired_members,
                desired_bindings,
            } => {
                validate_member_set(desired_members, true)?;
                validate_transition_bindings(
                    &self.scope.current_members,
                    &self.scope.current_bindings,
                    desired_members,
                    desired_bindings,
                )?;
                if let Some(pending) = self.scope.pending.as_mut() {
                    let exact = pending.transition_id == *transition_id
                        && pending.transition_digest == *request_digest
                        && pending.desired_identity == *desired_identity
                        && pending.desired_members == *desired_members
                        && pending.desired_bindings == *desired_bindings;
                    if !exact {
                        return Err(invalid_data(
                            "projected session consensus transition conflicts",
                        ));
                    }
                    if pending.transition_start_log_index == 0
                        && pending.learners_ready_log_index.is_none()
                        && pending.joint_membership_log_index.is_none()
                        && pending.uniform_membership_log_index.is_none()
                    {
                        pending.transition_start_log_index = log_index;
                    } else if pending.transition_start_log_index != log_index {
                        return Err(invalid_data(
                            "projected session consensus transition start conflicts",
                        ));
                    }
                    return Ok(());
                }
                if !exact_successor_epoch(self.scope.current_identity, *desired_identity)
                    || (self.scope.predecessor.is_some()
                        && self.scope.history.len() >= MEMBERSHIP_HISTORY_MAX_ENTRIES)
                    || self.scope.terminal.as_ref().is_some_and(|terminal| {
                        terminal.transition_id == *transition_id
                            && terminal.transition_digest != *request_digest
                    })
                {
                    return Err(invalid_data(
                        "projected session consensus successor scope is invalid",
                    ));
                }
                self.scope.pending = Some(PendingMembershipScope {
                    transition_id: *transition_id,
                    transition_digest: *request_digest,
                    desired_identity: *desired_identity,
                    desired_members: desired_members.clone(),
                    desired_bindings: desired_bindings.clone(),
                    transition_start_log_index: log_index,
                    learners_ready_log_index: None,
                    joint_membership_log_index: None,
                    uniform_membership_log_index: None,
                });
                Ok(())
            }
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id,
                request_digest,
            } => {
                let pending = self.scope.pending.as_mut().ok_or_else(|| {
                    invalid_data("projected session consensus transition is missing")
                })?;
                if pending.transition_id != *transition_id
                    || pending.transition_digest != *request_digest
                    || pending.learners_ready_log_index.is_some()
                    || log_index <= pending.transition_start_log_index
                    || validate_all_added_learners_present(
                        &self.membership,
                        &self.scope.current_members,
                        &pending.desired_members,
                    )
                    .is_err()
                {
                    return Err(invalid_data(
                        "projected session consensus learner readiness conflicts",
                    ));
                }
                pending.learners_ready_log_index = Some(log_index);
                Ok(())
            }
            SessionMutationIntent::FenceTopologyAuthority {
                transition_id,
                request_digest,
            } => {
                let pending = self.scope.pending.as_ref().ok_or_else(|| {
                    invalid_data("projected session consensus transition is missing")
                })?;
                if pending.transition_id != *transition_id
                    || pending.transition_digest != *request_digest
                    || pending.learners_ready_log_index.is_none()
                {
                    return Err(invalid_data(
                        "projected session consensus authority fence conflicts",
                    ));
                }
                self.scope.application_authority_epoch =
                    pending.desired_identity.configuration_epoch();
                self.scope.application_authority_members = pending.desired_members.clone();
                Ok(())
            }
            SessionMutationIntent::AbortTopologyTransition {
                transition_id,
                request_digest,
            } => {
                let pending = self.scope.pending.take().ok_or_else(|| {
                    invalid_data("projected session consensus transition is missing")
                })?;
                if pending.transition_id != *transition_id
                    || pending.transition_digest != *request_digest
                    || pending.joint_membership_log_index.is_some()
                    || pending.uniform_membership_log_index.is_some()
                    || validate_uniform_membership(&self.membership, &self.scope.current_members)
                        .is_err()
                {
                    self.scope.pending = Some(pending);
                    return Err(invalid_data("projected session consensus abort is invalid"));
                }
                self.scope.application_authority_epoch =
                    self.scope.current_identity.configuration_epoch();
                self.scope.application_authority_members = self.scope.current_members.clone();
                self.scope.terminal = Some(TerminalMembershipTransition {
                    transition_id: pending.transition_id,
                    transition_digest: pending.transition_digest,
                    outcome: TerminalMembershipOutcome::Aborted,
                    transition_start_log_index: pending.transition_start_log_index,
                    learners_ready_log_index: pending.learners_ready_log_index,
                    joint_membership_log_index: None,
                    uniform_membership_log_index: None,
                    cutover_log_index: None,
                    finalization_log_index: None,
                });
                Ok(())
            }
            SessionMutationIntent::FinalizeTopologyTransition {
                transition_id,
                request_digest,
            } => {
                let terminal = self.scope.terminal.as_mut().ok_or_else(|| {
                    invalid_data("projected session consensus terminal transition is missing")
                })?;
                if terminal.transition_id != *transition_id
                    || terminal.transition_digest != *request_digest
                    || terminal.outcome != TerminalMembershipOutcome::Promoted
                    || terminal.finalization_log_index.is_some()
                    || terminal
                        .cutover_log_index
                        .is_none_or(|cutover| log_index <= cutover)
                {
                    return Err(invalid_data(
                        "projected session consensus finalization conflicts",
                    ));
                }
                terminal.finalization_log_index = Some(log_index);
                Ok(())
            }
            SessionMutationIntent::AdvanceLogicalTime
            | SessionMutationIntent::CompareAndSet(_)
            | SessionMutationIntent::DeleteFenced(_)
            | SessionMutationIntent::RefreshTtl { .. }
            | SessionMutationIntent::AcquireLease { .. }
            | SessionMutationIntent::RenewLease { .. }
            | SessionMutationIntent::ReleaseLease(_)
            | SessionMutationIntent::FinalizeOperatorRecovery { .. }
            | SessionMutationIntent::Authorized { .. } => Ok(()),
        }
    }
}

fn replay_unapplied_log_prefix_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    before: u64,
    projection: &mut MembershipLogProjection,
) -> io::Result<Option<u64>> {
    let applied = read_applied_sync(conn, storage_identity)?.map(|log_id| log_id.index);
    let first = applied
        .map(|index| {
            index
                .checked_add(1)
                .ok_or_else(|| invalid_data("session consensus applied index exhausted"))
        })
        .transpose()?
        .unwrap_or(0);
    let target = last_log_sync(conn, storage_identity)?
        .map(|log_id| {
            log_id
                .index
                .checked_add(1)
                .ok_or_else(|| invalid_data("session consensus log index exhausted"))
        })
        .transpose()?
        .unwrap_or(0)
        .min(before);
    if first >= target {
        return Ok(applied);
    }
    let mut statement = conn
        .prepare(
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index ASC",
        )
        .map_err(db_error)?;
    let mut rows = statement
        .query(params![checked_i64(first)?, checked_i64(target)?])
        .map_err(db_error)?;
    let mut expected = first;
    while let Some(row) = rows.next().map_err(db_error)? {
        let epoch: i64 = row.get(0).map_err(db_error)?;
        let term: i64 = row.get(1).map_err(db_error)?;
        let index: i64 = row.get(2).map_err(db_error)?;
        let encoded: Vec<u8> = row.get(3).map_err(db_error)?;
        validate_epoch(epoch, storage_identity)?;
        let entry: Entry<SessionRaftTypeConfig> = decode_json(&encoded)?;
        if entry.log_id.index != expected
            || checked_u64(index)? != expected
            || checked_u64(term)? != entry.log_id.leader_id.term
        {
            return Err(invalid_data(
                "persisted session consensus unapplied log projection is not contiguous",
            ));
        }
        projection.project(conn, &entry, storage_identity)?;
        expected = expected
            .checked_add(1)
            .ok_or_else(|| invalid_data("session consensus log index exhausted"))?;
    }
    if expected != target {
        return Err(invalid_data(
            "persisted session consensus unapplied log projection has a hole",
        ));
    }
    Ok(applied)
}

pub(crate) fn read_vote_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<Vote<SessionConsensusNodeId>>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, term, node_id, vote_json FROM consensus_vote WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, Vec<u8>>(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, term, node_id, encoded)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    let vote: Vote<SessionConsensusNodeId> = decode_json(&encoded)?;
    if checked_u64(term)? != vote.leader_id.term {
        return Err(invalid_data(
            "persisted session consensus vote term mismatch",
        ));
    }
    match (node_id, vote.leader_id.voted_for()) {
        (Some(stored), Some(voted_for)) if checked_positive_u64(stored)? == voted_for.get() => {}
        (None, None) => {}
        _ => {
            return Err(invalid_data(
                "persisted session consensus vote node mismatch",
            ))
        }
    }
    Ok(Some(vote))
}

pub(crate) fn save_vote_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    vote: &Vote<SessionConsensusNodeId>,
) -> io::Result<()> {
    if let Some(current) = read_vote_sync(conn, identity)? {
        if vote.partial_cmp(&current) != Some(std::cmp::Ordering::Greater) && vote != &current {
            return Err(invalid_data("session consensus vote did not advance"));
        }
    }
    let epoch = epoch_i64(identity)?;
    let term = checked_i64(vote.leader_id.term)?;
    let node_id = vote
        .leader_id
        .voted_for()
        .map(|node| checked_positive_i64(node.get()))
        .transpose()?;
    let encoded = encode_json(vote)?;
    conn.execute(
        "INSERT OR REPLACE INTO consensus_vote (singleton, configuration_epoch, term, node_id, vote_json) VALUES (1, ?1, ?2, ?3, ?4)",
        params![epoch, term, node_id, encoded],
    )
    .map_err(db_error)?;
    Ok(())
}

fn read_log_pointer(
    conn: &Connection,
    table: &'static str,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    let sql = format!(
        "SELECT configuration_epoch, term, log_index, log_id_json FROM {table} WHERE singleton = 1"
    );
    let row = conn
        .query_row(&sql, [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .optional()
        .map_err(db_error)?;
    let Some((epoch, term, index, encoded)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    let log_id: LogId<SessionConsensusNodeId> = decode_json(&encoded)?;
    if checked_u64(term)? != log_id.leader_id.term || checked_u64(index)? != log_id.index {
        return Err(invalid_data(
            "persisted session consensus log pointer mismatch",
        ));
    }
    Ok(Some(log_id))
}

fn save_log_pointer(
    tx: &Transaction<'_>,
    table: &'static str,
    identity: SessionConsensusIdentity,
    log_id: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let (term, index) = validate_log_id(log_id)?;
    let sql = format!(
        "INSERT OR REPLACE INTO {table} (singleton, configuration_epoch, term, log_index, log_id_json) VALUES (1, ?1, ?2, ?3, ?4)"
    );
    tx.execute(
        &sql,
        params![epoch_i64(identity)?, term, index, encode_json(log_id)?],
    )
    .map_err(db_error)?;
    Ok(())
}

pub(crate) fn read_committed_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    read_log_pointer(conn, "consensus_committed", identity)
}

pub(crate) fn save_committed_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    committed: Option<LogId<SessionConsensusNodeId>>,
) -> io::Result<()> {
    let Some(committed) = committed else {
        if read_committed_sync(conn, identity)?.is_some() {
            return Err(invalid_data(
                "session consensus committed index cannot be cleared",
            ));
        }
        return Ok(());
    };
    if let Some(current) = read_committed_sync(conn, identity)? {
        if committed.index < current.index
            || (committed.index == current.index && committed != current)
        {
            return Err(invalid_data("session consensus committed index regressed"));
        }
    }
    let tx = conn.unchecked_transaction().map_err(db_error)?;
    save_log_pointer(&tx, "consensus_committed", identity, &committed)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn read_purged_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    read_log_pointer(conn, "consensus_purged", identity)
}

pub(crate) fn last_log_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log ORDER BY log_index DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, term, index, encoded)) = row else {
        return read_purged_sync(conn, identity);
    };
    validate_epoch(epoch, identity)?;
    let entry: Entry<SessionRaftTypeConfig> = decode_json(&encoded)?;
    if checked_u64(term)? != entry.log_id.leader_id.term
        || checked_u64(index)? != entry.log_id.index
    {
        return Err(invalid_data("persisted session consensus log row mismatch"));
    }
    Ok(Some(entry.log_id))
}

pub(crate) fn read_log_range_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    start: u64,
    end: Option<u64>,
    limit: Option<usize>,
) -> io::Result<Vec<Entry<SessionRaftTypeConfig>>> {
    read_log_range_with_batch_sync(conn, identity, start, end, limit, false)
}

pub(crate) fn read_limited_log_range_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    start: u64,
    end: u64,
    limit: usize,
) -> io::Result<Vec<Entry<SessionRaftTypeConfig>>> {
    let entries =
        read_log_range_with_batch_sync(conn, identity, start, Some(end), Some(limit), true)?;
    let purged = read_purged_sync(conn, identity)?;
    let expected_start = match purged {
        Some(purged) if start <= purged.index => purged.index.checked_add(1),
        _ => Some(start),
    };
    if let Some(expected_start) = expected_start {
        let range_can_contain_expected = expected_start < end;
        if range_can_contain_expected {
            if let Some(first) = entries.first() {
                if first.log_id.index != expected_start {
                    return Err(invalid_data(
                        "persisted session consensus log contains a hole",
                    ));
                }
            } else {
                let later_exists: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM consensus_log WHERE log_index > ?1 AND log_index < ?2)",
                        params![checked_i64(expected_start)?, checked_i64(end)?],
                        |row| row.get(0),
                    )
                    .map_err(db_error)?;
                if later_exists {
                    return Err(invalid_data(
                        "persisted session consensus log contains a hole",
                    ));
                }
            }
        }
    }
    Ok(entries)
}

fn read_log_range_with_batch_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    start: u64,
    end: Option<u64>,
    limit: Option<usize>,
    append_entries_batch: bool,
) -> io::Result<Vec<Entry<SessionRaftTypeConfig>>> {
    let start_u64 = start;
    let start = checked_i64(start)?;
    let end = end.map(checked_i64).transpose()?;
    let limit = limit
        .map(|value| {
            i64::try_from(value)
                .map_err(|_| invalid_data("session consensus log limit exceeds SQLite range"))
        })
        .transpose()?;
    let mut projection = MembershipLogProjection::load(conn, identity)?;
    let applied_index =
        replay_unapplied_log_prefix_sync(conn, identity, start_u64, &mut projection)?;
    let mut entries = Vec::new();
    let sql = match (end, limit) {
        (Some(_), Some(_)) => "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index ASC LIMIT ?3",
        (Some(_), None) => "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index ASC",
        (None, Some(_)) => "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 ORDER BY log_index ASC LIMIT ?3",
        (None, None) => "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 ORDER BY log_index ASC",
    };
    let mut stmt = conn.prepare(sql).map_err(db_error)?;
    let mut rows = match (end, limit) {
        (Some(end), Some(limit)) => stmt.query(params![start, end, limit]),
        (Some(end), None) => stmt.query(params![start, end]),
        (None, Some(limit)) => stmt.query(params![start, limit]),
        (None, None) => stmt.query(params![start]),
    }
    .map_err(db_error)?;
    let mut batch = append_entries_batch.then(AppendEntriesBatchAccumulator::new);
    while let Some(row) = rows.next().map_err(db_error)? {
        let epoch: i64 = row.get(0).map_err(db_error)?;
        let term: i64 = row.get(1).map_err(db_error)?;
        let index: i64 = row.get(2).map_err(db_error)?;
        let encoded: Vec<u8> = row.get(3).map_err(db_error)?;
        validate_epoch(epoch, identity)?;
        let entry: Entry<SessionRaftTypeConfig> = decode_json(&encoded)?;
        if checked_u64(term)? != entry.log_id.leader_id.term
            || checked_u64(index)? != entry.log_id.index
        {
            return Err(invalid_data("persisted session consensus log row mismatch"));
        }
        if applied_index.is_none_or(|applied| entry.log_id.index > applied) {
            projection.project(conn, &entry, identity)?;
        } else {
            validate_entry_for_membership_scope(&entry, identity, &projection.scope)?;
        }
        let decision = batch
            .as_mut()
            .map(|batch| {
                batch
                    .consider(&entry)
                    .map_err(|_| invalid_data("session consensus log entry cannot be sized"))
            })
            .transpose()?;
        match decision {
            Some(AppendEntriesBatchDecision::Include) | None => entries.push(entry),
            Some(AppendEntriesBatchDecision::IncludeAndStop) => {
                entries.push(entry);
                break;
            }
            Some(AppendEntriesBatchDecision::StopBefore) => break,
        }
    }
    for pair in entries.windows(2) {
        if pair[1].log_id.index != pair[0].log_id.index.saturating_add(1) {
            return Err(invalid_data(
                "persisted session consensus log contains a hole",
            ));
        }
    }
    Ok(entries)
}

pub(crate) fn append_logs_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    let mut projection = MembershipLogProjection::load(&tx, identity)?;
    let expected = last_log_sync(&tx, identity)?
        .map(|log| {
            log.index
                .checked_add(1)
                .ok_or_else(|| invalid_data("session consensus log index exhausted"))
        })
        .transpose()?
        .unwrap_or(0);
    if entries[0].log_id.index != expected {
        return Err(invalid_data(
            "session consensus log append would create a hole",
        ));
    }
    replay_unapplied_log_prefix_sync(&tx, identity, expected, &mut projection)?;
    for (offset, entry) in entries.iter().enumerate() {
        let offset = u64::try_from(offset)
            .map_err(|_| invalid_data("session consensus log batch exceeds integer range"))?;
        if entry.log_id.index
            != expected
                .checked_add(offset)
                .ok_or_else(|| invalid_data("session consensus log index exhausted"))?
        {
            return Err(invalid_data(
                "session consensus log batch is not contiguous",
            ));
        }
        projection.project(&tx, entry, identity)?;
    }

    for entry in entries {
        let (term, index) = validate_log_id(&entry.log_id)?;
        let encoded = encode_json(entry)?;
        if encoded.len() > CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(invalid_data(
                "session consensus log entry exceeds storage limit",
            ));
        }
        tx.execute(
            "INSERT INTO consensus_log (log_index, configuration_epoch, term, entry_json) VALUES (?1, ?2, ?3, ?4)",
            params![index, epoch_i64(identity)?, term, encoded],
        )
        .map_err(db_error)?;
    }
    tx.commit().map_err(db_error)
}

pub(crate) fn truncate_logs_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    since: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let (_, index) = validate_log_id(since)?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    if let Some(committed) = read_committed_sync(&tx, identity)? {
        if since.index <= committed.index {
            return Err(invalid_data(
                "session consensus truncate crosses committed log",
            ));
        }
    }
    if let Some(applied) = read_applied_sync(&tx, identity)? {
        if since.index <= applied.index {
            return Err(invalid_data(
                "session consensus truncate crosses applied log",
            ));
        }
    }
    if let Some(purged) = read_purged_sync(&tx, identity)? {
        if since.index <= purged.index {
            return Err(invalid_data(
                "session consensus truncate crosses purged log",
            ));
        }
    }
    tx.execute("DELETE FROM consensus_log WHERE log_index >= ?1", [index])
        .map_err(db_error)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn purge_logs_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    through: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let (_, index) = validate_log_id(through)?;
    if let Some(current) = read_purged_sync(conn, identity)? {
        if through.index < current.index || (through.index == current.index && through != &current)
        {
            return Err(invalid_data("session consensus purged index regressed"));
        }
    }
    let applied = read_applied_sync(conn, identity)?
        .ok_or_else(|| invalid_data("session consensus cannot purge unapplied logs"))?;
    if through.index > applied.index {
        return Err(invalid_data(
            "session consensus cannot purge unapplied logs",
        ));
    }
    let tx = conn.unchecked_transaction().map_err(db_error)?;
    tx.execute("DELETE FROM consensus_log WHERE log_index <= ?1", [index])
        .map_err(db_error)?;
    save_log_pointer(&tx, "consensus_purged", identity, through)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn read_applied_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    read_log_pointer(conn, "consensus_applied", identity)
}

fn is_pristine_membership(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> bool {
    membership.log_id().is_none()
        && membership.membership().get_joint_config().is_empty()
        && membership.nodes().next().is_none()
}

fn validate_uniform_membership(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    validate_member_set(expected_members, false)?;
    let config = membership.membership().get_joint_config();
    let nodes = membership
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    if config.len() != 1
        || config.first() != Some(expected_members)
        || nodes != *expected_members
        || membership.membership().learner_ids().next().is_some()
    {
        return Err(invalid_data(
            "session consensus membership does not match admitted topology",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MembershipShape {
    CurrentUniform,
    LearnersCatchingUp,
    Joint,
    DesiredUniform,
}

fn classify_transition_membership(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    current_members: &BTreeSet<SessionConsensusNodeId>,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<MembershipShape> {
    validate_member_set(current_members, true)?;
    validate_member_set(desired_members, true)?;
    let configs = membership.membership().get_joint_config();
    let nodes = membership
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    let learners = membership
        .membership()
        .learner_ids()
        .collect::<BTreeSet<_>>();
    let union = current_members
        .union(desired_members)
        .copied()
        .collect::<BTreeSet<_>>();

    if configs.len() == 1 && configs.first() == Some(current_members) {
        if nodes == *current_members && learners.is_empty() {
            return Ok(MembershipShape::CurrentUniform);
        }
        let expected_learners = nodes
            .difference(current_members)
            .copied()
            .collect::<BTreeSet<_>>();
        if nodes.is_superset(current_members)
            && nodes.is_subset(&union)
            && !expected_learners.is_empty()
            && learners == expected_learners
            && expected_learners.is_subset(desired_members)
        {
            return Ok(MembershipShape::LearnersCatchingUp);
        }
    }

    if configs.len() == 2
        && configs.iter().any(|config| config == current_members)
        && configs.iter().any(|config| config == desired_members)
        && current_members != desired_members
        && nodes == union
        && learners.is_empty()
    {
        return Ok(MembershipShape::Joint);
    }

    if configs.len() == 1
        && configs.first() == Some(desired_members)
        && nodes == *desired_members
        && learners.is_empty()
    {
        return Ok(MembershipShape::DesiredUniform);
    }

    Err(invalid_data(
        "session consensus membership is outside the admitted transition",
    ))
}

fn validate_all_added_learners_present(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    current_members: &BTreeSet<SessionConsensusNodeId>,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    let additions = desired_members
        .difference(current_members)
        .copied()
        .collect::<BTreeSet<_>>();
    if additions.is_empty() {
        return validate_uniform_membership(membership, current_members);
    }
    let expected_nodes = current_members
        .union(&additions)
        .copied()
        .collect::<BTreeSet<_>>();
    let configs = membership.membership().get_joint_config();
    let nodes = membership
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    let learners = membership
        .membership()
        .learner_ids()
        .collect::<BTreeSet<_>>();
    if configs.len() != 1
        || configs.first() != Some(current_members)
        || nodes != expected_nodes
        || learners != additions
    {
        return Err(invalid_data(
            "session consensus added learners are not completely admitted",
        ));
    }
    Ok(())
}

fn validate_membership_for_log(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    scope: &MembershipValidationScope,
    log_index: u64,
) -> io::Result<()> {
    validate_membership_ids(membership)?;
    let predecessors = scope
        .history
        .iter()
        .chain(scope.predecessor.iter())
        .collect::<Vec<_>>();
    for (offset, predecessor) in predecessors.iter().enumerate() {
        let successor_members = predecessors
            .get(offset + 1)
            .map_or(&scope.current_members, |next| &next.members);
        if log_index < predecessor.transition_start_log_index {
            return validate_uniform_membership(membership, &predecessor.members);
        }
        if log_index <= predecessor.cutover_log_index {
            classify_transition_membership(membership, &predecessor.members, successor_members)?;
            return Ok(());
        }
    }
    if let Some(pending) = &scope.pending {
        let shape = classify_transition_membership(
            membership,
            &scope.current_members,
            &pending.desired_members,
        )?;
        if matches!(
            shape,
            MembershipShape::Joint | MembershipShape::DesiredUniform
        ) && (pending.learners_ready_log_index.is_none()
            || scope.application_authority_epoch != pending.desired_identity.configuration_epoch()
            || scope.application_authority_members != pending.desired_members)
        {
            return Err(invalid_data(
                "session consensus joint membership preceded durable learner readiness or its authority fence",
            ));
        }
        if log_index < pending.transition_start_log_index
            && shape != MembershipShape::CurrentUniform
        {
            return Err(invalid_data(
                "session consensus membership transition predates its durable scope",
            ));
        }
        return Ok(());
    }
    validate_uniform_membership(membership, &scope.current_members)
}

fn validate_persisted_membership_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> io::Result<()> {
    let applied = read_applied_sync(conn, storage_identity)?;
    let membership = read_membership_unchecked_sync(conn, storage_identity)?;
    if is_pristine_membership(&membership) {
        if applied.is_none() {
            return Ok(());
        }
        return Err(invalid_data(
            "session consensus applied state has pristine membership",
        ));
    }
    let scope = read_membership_scope_sync(conn, storage_identity)?;
    let log_index = membership
        .log_id()
        .ok_or_else(|| invalid_data("session consensus membership log identity is missing"))?
        .index;
    validate_membership_for_log(&membership, &scope, log_index)
}

fn read_membership_unchecked_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>> {
    let (epoch, encoded): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT configuration_epoch, membership_json FROM consensus_membership WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    decode_json(&encoded)
}

pub(crate) fn read_membership_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> io::Result<StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>> {
    let membership = read_membership_unchecked_sync(conn, storage_identity)?;
    if is_pristine_membership(&membership) && read_applied_sync(conn, storage_identity)?.is_none() {
        return Ok(membership);
    }
    let scope = read_membership_scope_sync(conn, storage_identity)?;
    let log_index = membership
        .log_id()
        .ok_or_else(|| invalid_data("session consensus membership log identity is missing"))?
        .index;
    validate_membership_for_log(&membership, &scope, log_index)?;
    Ok(membership)
}

fn payload_digest(command: &SessionConsensusCommand) -> io::Result<[u8; 32]> {
    // Idempotency binds caller-owned semantics, not leader-owned sequence,
    // predecessor, or logical-time metadata. A retry after a committed
    // response is lost will be proposed by a new leader with new metadata but
    // must still recover the original durable outcome.
    let semantic_intent = match &command.intent {
        SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
        intent => intent,
    };
    let encoded = encode_json(&(command.schema_version, command.identity, semantic_intent))?;
    let mut hasher = Sha256::new();
    hasher.update(OUTCOME_DIGEST_DOMAIN);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn lease_error_to_store(error: LeaseError) -> StoreError {
    match error {
        LeaseError::AlreadyHeld => StoreError::LeaseHeld,
        LeaseError::Expired => StoreError::LeaseExpired,
        LeaseError::StaleFence => StoreError::StaleFence,
        LeaseError::NotFound => StoreError::NotFound,
        LeaseError::InvalidSessionTtl => StoreError::InvalidSessionTtl,
        LeaseError::OperationOutcomeUnavailable => StoreError::BackendOperationOutcomeUnavailable,
        LeaseError::Backend(_) => {
            StoreError::BackendUnavailable("session consensus lease application failed".into())
        }
    }
}

/// Whether a state-machine rejection is a deterministic result of the
/// committed command and previously committed state.
///
/// Backend capability, persistence, serialization, crypto, and restore/log
/// errors describe a node-local fault or corrupt/incompatible state rather than
/// a caller-visible command outcome. Persisting one of those errors would let a
/// faulty replica advance its applied/application state while healthy replicas
/// apply the mutation, permanently diverging the deterministic state machine.
fn is_deterministic_intent_rejection(error: &StoreError) -> bool {
    match error {
        StoreError::NotFound
        | StoreError::StaleFence
        | StoreError::CasConflict
        | StoreError::InvalidKey(_)
        | StoreError::TopologyAuthorityRevoked
        | StoreError::InvalidSessionTtl
        | StoreError::InvalidRecordExpiry
        | StoreError::LeaseHeld
        | StoreError::LeaseExpired
        | StoreError::PayloadTooLarge { .. } => true,
        StoreError::CapabilityNotSupported(_)
        | StoreError::CasIdempotencyConflict
        | StoreError::CasIdempotencyOutcomeUnavailable
        | StoreError::BackendOperationOutcomeUnavailable
        | StoreError::BackendUnavailable(_)
        | StoreError::InvalidReplicationSequence
        | StoreError::InvalidReplicationLogRange
        | StoreError::ReplicationLogPageTooLarge { .. }
        | StoreError::ReplicationLogCursorCompacted { .. }
        | StoreError::ReplicationWatchCatchUpRequired
        | StoreError::ReplicationOperationLimitExceeded
        | StoreError::RecordExpiryPreflightLimitExceeded
        | StoreError::Crypto(_)
        | StoreError::Serialization(_)
        | StoreError::InvalidRestoreScanRequest(_)
        | StoreError::InvalidRestoreScanResponse(_)
        | StoreError::RestoreScanPageTooLarge { .. }
        | StoreError::RestoreScanCursorStale
        | StoreError::RestoreScanWorkBudgetExceeded
        | StoreError::RestoreScanResponseTooLarge { .. } => false,
    }
}

fn state_machine_intent_fault() -> io::Error {
    io::Error::other("session consensus state-machine operation failed")
}

#[derive(Debug)]
pub(crate) struct AppliedBatch {
    pub(crate) responses: Vec<SessionConsensusResponse>,
    pub(crate) notifications: Vec<ReplicationEntry>,
}

fn read_machine_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<(u64, SessionConsensusEntryDigest, Option<Timestamp>, u64)> {
    let (epoch, sequence, digest, logical_time, watch_sequence): (
        i64,
        i64,
        Vec<u8>,
        Option<String>,
        i64,
    ) = conn
        .query_row(
            "SELECT configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence FROM consensus_machine WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| invalid_data("persisted session consensus digest has invalid length"))?;
    let logical_time = logical_time
        .map(|value| {
            Timestamp::from_str(&value)
                .map_err(|_| invalid_data("persisted session consensus logical time is invalid"))
        })
        .transpose()?;
    Ok((
        checked_u64(sequence)?,
        SessionConsensusEntryDigest::from_bytes(digest),
        logical_time,
        checked_u64(watch_sequence)?,
    ))
}

#[cfg(test)]
pub(crate) fn proposal_state_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<(u64, SessionConsensusEntryDigest, Option<Timestamp>)> {
    let (sequence, digest, logical_time, _) = read_machine_sync(conn, identity)?;
    Ok((sequence, digest, logical_time))
}

pub(crate) fn logical_time_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<Timestamp>> {
    read_machine_sync(conn, identity).map(|(_, _, logical_time, _)| logical_time)
}

fn read_outcome_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    request_id: SessionConsensusRequestId,
) -> io::Result<Option<([u8; 32], SessionConsensusResponse)>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, payload_digest, response_json FROM consensus_request_outcomes WHERE request_id = ?1",
            [request_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, digest, response)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    let digest = digest.try_into().map_err(|_| {
        invalid_data("persisted session consensus request digest has invalid length")
    })?;
    Ok(Some((digest, decode_json(&response)?)))
}

fn validate_membership_ids(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> io::Result<()> {
    if let Some(log_id) = membership.log_id() {
        validate_log_id(log_id)?;
    }
    for node_id in membership.voter_ids() {
        checked_positive_i64(node_id.get())?;
    }
    for (node_id, _) in membership.nodes() {
        checked_positive_i64(node_id.get())?;
    }
    Ok(())
}

fn store_membership_sync(
    tx: &Transaction<'_>,
    storage_identity: SessionConsensusIdentity,
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> io::Result<()> {
    validate_membership_ids(membership)?;
    let scope = read_membership_scope_sync(tx, storage_identity)?;
    let log_index = membership
        .log_id()
        .ok_or_else(|| invalid_data("session consensus membership log identity is missing"))?
        .index;
    validate_membership_for_log(membership, &scope, log_index)?;
    tx.execute(
        "UPDATE consensus_membership SET configuration_epoch = ?1, membership_json = ?2 WHERE singleton = 1",
        params![epoch_i64(storage_identity)?, encode_json(membership)?],
    )
    .map_err(db_error)?;
    Ok(())
}

fn execute_application_intent_sync(
    conn: &Connection,
    intent: &SessionMutationIntent,
    caps: &BackendCapabilities,
    logical_time: Timestamp,
) -> Result<(SessionMutationOutcome, Option<ReplicationOp>), StoreError> {
    match intent {
        SessionMutationIntent::AdvanceLogicalTime => Ok((SessionMutationOutcome::Unit, None)),
        SessionMutationIntent::CompareAndSet(op) => {
            if op.new_record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
                return Err(StoreError::Serialization(
                    "session consensus requires a sealed record payload".into(),
                ));
            }
            let result = ops::compare_and_set_sync(conn, op.as_ref().clone(), caps, logical_time)?;
            let replication = matches!(result, CompareAndSetResult::Success).then(|| {
                ReplicationOp::CompareAndSet {
                    key: op.key.clone(),
                    expected_generation: op.expected_generation,
                    credential_id: op.lease.credential_id(),
                    guard_expires_at: op.lease.expires_at(),
                    new_record: op.new_record.clone(),
                }
            });
            Ok((SessionMutationOutcome::CompareAndSet(result), replication))
        }
        SessionMutationIntent::DeleteFenced(guard) => {
            ops::delete_fenced_sync(conn, guard, caps, logical_time)?;
            Ok((
                SessionMutationOutcome::Unit,
                Some(ReplicationOp::DeleteFenced {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                }),
            ))
        }
        SessionMutationIntent::RefreshTtl { lease: guard, ttl } => {
            ops::refresh_ttl_sync(conn, guard, *ttl, caps, logical_time)?;
            let expires_at = crate::ttl::checked_session_deadline(logical_time, *ttl)?;
            Ok((
                SessionMutationOutcome::Unit,
                Some(ReplicationOp::RefreshTtl {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                    ttl: *ttl,
                    expires_at,
                }),
            ))
        }
        SessionMutationIntent::AcquireLease { key, owner, ttl } => {
            let guard = lease::acquire_sync(conn, key, owner.clone(), *ttl, logical_time)
                .map_err(lease_error_to_store)?;
            Ok((
                SessionMutationOutcome::Lease(guard.clone()),
                Some(ReplicationOp::AcquireLease {
                    key: key.clone(),
                    owner: owner.clone(),
                    fence: guard.fence(),
                    credential_id: guard.credential_id(),
                    ttl: *ttl,
                    expires_at: guard.expires_at(),
                }),
            ))
        }
        SessionMutationIntent::RenewLease { lease: guard, ttl } => {
            let renewed =
                lease::renew_sync(conn, guard, *ttl, logical_time).map_err(lease_error_to_store)?;
            Ok((
                SessionMutationOutcome::Lease(renewed.clone()),
                Some(ReplicationOp::RenewLease {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                    credential_id: guard.credential_id(),
                    ttl: *ttl,
                    expires_at: renewed.expires_at(),
                }),
            ))
        }
        SessionMutationIntent::ReleaseLease(guard) => {
            lease::release_sync(conn, guard.clone(), logical_time).map_err(lease_error_to_store)?;
            Ok((
                SessionMutationOutcome::Unit,
                Some(ReplicationOp::ReleaseLease {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                    credential_id: guard.credential_id(),
                }),
            ))
        }
        SessionMutationIntent::FinalizeOperatorRecovery {
            recovery_epoch,
            plan_digest,
            fence_high_water,
            credential_high_water,
        } => match finalize_operator_recovery_sync(
            conn,
            // The identity is validated before this function and all state
            // machine writes use the same fixed configuration epoch.
            read_identity_for_recovery_sync(conn)?,
            *recovery_epoch,
            *plan_digest,
            *fence_high_water,
            *credential_high_water,
        )
        .map_err(|_| {
            StoreError::BackendUnavailable("session consensus recovery application failed".into())
        })? {
            OperatorRecoveryApply::Applied | OperatorRecoveryApply::Idempotent => {
                Ok((SessionMutationOutcome::Unit, None))
            }
            OperatorRecoveryApply::Rejected => Err(StoreError::InvalidKey(
                "operator_recovery_epoch_rejected".into(),
            )),
        },
        SessionMutationIntent::PrepareTopologyTransition { .. }
        | SessionMutationIntent::MarkTopologyLearnersReady { .. }
        | SessionMutationIntent::FenceTopologyAuthority { .. }
        | SessionMutationIntent::AbortTopologyTransition { .. }
        | SessionMutationIntent::FinalizeTopologyTransition { .. }
        | SessionMutationIntent::Authorized { .. } => Err(StoreError::BackendUnavailable(
            "session consensus internal intent reached application executor".into(),
        )),
    }
}

fn membership_mutation_store_error(error: MembershipScopeMutationError) -> StoreError {
    match error {
        MembershipScopeMutationError::InvalidScope
        | MembershipScopeMutationError::ConflictingTransition
        | MembershipScopeMutationError::CompactionRequired
        | MembershipScopeMutationError::TransitionNotQuiescent => {
            StoreError::InvalidKey("topology_transition_rejected".into())
        }
        MembershipScopeMutationError::BackendUnavailable
        | MembershipScopeMutationError::CorruptState => {
            StoreError::BackendUnavailable("session topology state is unavailable".into())
        }
    }
}

fn untouched_initial_membership_scope(
    scope: &MembershipValidationScope,
    storage_identity: SessionConsensusIdentity,
) -> bool {
    let pending_is_only_provisional = scope.pending.as_ref().is_none_or(|pending| {
        pending.transition_start_log_index == 0
            && pending.learners_ready_log_index.is_none()
            && pending.joint_membership_log_index.is_none()
            && pending.uniform_membership_log_index.is_none()
    });
    scope.current_identity == storage_identity
        && scope.application_authority_epoch == storage_identity.configuration_epoch()
        && scope.application_authority_members == scope.current_members
        && scope.history.is_empty()
        && scope.predecessor.is_none()
        && pending_is_only_provisional
        && scope.terminal.is_none()
}

fn execute_intent_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    log_index: u64,
    intent: &SessionMutationIntent,
    caps: &BackendCapabilities,
    logical_time: Timestamp,
) -> Result<(SessionMutationOutcome, Option<ReplicationOp>), StoreError> {
    match intent {
        SessionMutationIntent::PrepareTopologyTransition {
            transition_id,
            request_digest,
            desired_identity,
            desired_members,
            desired_bindings,
        } => stage_membership_scope_in_tx(
            conn,
            storage_identity,
            *transition_id,
            *request_digest,
            *desired_identity,
            desired_members,
            desired_bindings,
            log_index,
        )
        .map_err(membership_mutation_store_error)
        .map(|_| (SessionMutationOutcome::Unit, None)),
        SessionMutationIntent::MarkTopologyLearnersReady {
            transition_id,
            request_digest,
        } => mark_membership_learners_ready_in_tx(
            conn,
            storage_identity,
            *transition_id,
            *request_digest,
            log_index,
        )
        .map_err(membership_mutation_store_error)
        .map(|_| (SessionMutationOutcome::Unit, None)),
        SessionMutationIntent::FenceTopologyAuthority {
            transition_id,
            request_digest,
        } => fence_application_authority_in_tx(
            conn,
            storage_identity,
            *transition_id,
            *request_digest,
        )
        .map_err(membership_mutation_store_error)
        .map(|_| (SessionMutationOutcome::Unit, None)),
        SessionMutationIntent::AbortTopologyTransition {
            transition_id,
            request_digest,
        } => restore_and_abort_membership_scope_in_tx(
            conn,
            storage_identity,
            *transition_id,
            *request_digest,
        )
        .map_err(membership_mutation_store_error)
        .map(|_| (SessionMutationOutcome::Unit, None)),
        SessionMutationIntent::FinalizeTopologyTransition {
            transition_id,
            request_digest,
        } => finalize_membership_transition_in_tx(
            conn,
            storage_identity,
            *transition_id,
            *request_digest,
            log_index,
        )
        .map_err(membership_mutation_store_error)
        .map(|_| (SessionMutationOutcome::Unit, None)),
        SessionMutationIntent::Authorized {
            origin,
            authority_identity,
            mutation,
        } => {
            if matches!(
                mutation.as_ref(),
                SessionMutationIntent::PrepareTopologyTransition { .. }
                    | SessionMutationIntent::MarkTopologyLearnersReady { .. }
                    | SessionMutationIntent::FenceTopologyAuthority { .. }
                    | SessionMutationIntent::AbortTopologyTransition { .. }
                    | SessionMutationIntent::FinalizeTopologyTransition { .. }
                    | SessionMutationIntent::FinalizeOperatorRecovery { .. }
                    | SessionMutationIntent::Authorized { .. }
            ) || validate_application_authority_sync(
                conn,
                storage_identity,
                *origin,
                *authority_identity,
            )
            .is_err()
            {
                return Err(StoreError::TopologyAuthorityRevoked);
            }
            execute_application_intent_sync(conn, mutation, caps, logical_time)
        }
        SessionMutationIntent::FinalizeOperatorRecovery { .. } => {
            execute_application_intent_sync(conn, intent, caps, logical_time)
        }
        legacy_application => {
            let scope = read_membership_scope_sync(conn, storage_identity).map_err(|_| {
                StoreError::BackendUnavailable("session topology state is unavailable".into())
            })?;
            if !untouched_initial_membership_scope(&scope, storage_identity) {
                return Err(StoreError::TopologyAuthorityRevoked);
            }
            execute_application_intent_sync(conn, legacy_application, caps, logical_time)
        }
    }
}

fn read_identity_for_recovery_sync(
    conn: &Connection,
) -> Result<SessionConsensusIdentity, StoreError> {
    let (cluster, configuration, epoch): (Vec<u8>, Vec<u8>, i64) = conn
        .query_row(
            "SELECT cluster_id, configuration_id, configuration_epoch FROM consensus_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| StoreError::BackendUnavailable(
            "session consensus recovery identity read failed".into(),
        ))?;
    let cluster: [u8; 32] = cluster.try_into().map_err(|_| {
        StoreError::BackendUnavailable("session consensus recovery identity is invalid".into())
    })?;
    let configuration: [u8; 32] = configuration.try_into().map_err(|_| {
        StoreError::BackendUnavailable("session consensus recovery identity is invalid".into())
    })?;
    let epoch = checked_positive_u64(epoch).map_err(|_| {
        StoreError::BackendUnavailable("session consensus recovery identity is invalid".into())
    })?;
    let epoch = crate::consensus::SessionConsensusConfigurationEpoch::new(epoch).map_err(|_| {
        StoreError::BackendUnavailable("session consensus recovery identity is invalid".into())
    })?;
    Ok(SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::from_bytes(cluster),
        crate::consensus::SessionConsensusConfigurationId::from_bytes(configuration),
        epoch,
    ))
}

fn store_replication_notification_sync(
    tx: &Transaction<'_>,
    identity: SessionConsensusIdentity,
    watch_sequence: u64,
    request_id: SessionConsensusRequestId,
    op: ReplicationOp,
    logical_time: Timestamp,
) -> io::Result<ReplicationEntry> {
    let entry = ReplicationEntry {
        sequence: watch_sequence,
        tx_id: ReplicationTxId::from_request_bytes(*request_id.as_bytes()),
        op,
        timestamp: logical_time,
    };
    entry
        .validate()
        .map_err(|_| invalid_data("committed session replication notification is invalid"))?;
    tx.execute(
        "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![
            checked_positive_i64(entry.sequence)?,
            entry.tx_id.as_str(),
            serde_json::to_string(&entry).map_err(|_| invalid_data("session replication notification encoding failed"))?,
            ops::format_rfc3339_normalized(entry.timestamp),
        ],
    )
    .map_err(db_error)?;
    let epoch = epoch_i64(identity)?;
    let changed = tx
        .execute(
            "UPDATE consensus_machine SET watch_sequence = ?1 WHERE singleton = 1 AND configuration_epoch = ?2",
            params![checked_i64(watch_sequence)?, epoch],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data("session consensus machine state is missing"));
    }
    Ok(entry)
}

pub(crate) fn apply_entries_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    caps: &BackendCapabilities,
    entries: Vec<Entry<SessionRaftTypeConfig>>,
) -> io::Result<AppliedBatch> {
    if entries.is_empty() {
        return Ok(AppliedBatch {
            responses: Vec::new(),
            notifications: Vec::new(),
        });
    }
    let mut tx =
        Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    let mut last_applied = read_applied_sync(&tx, identity)?;
    let mut machine = read_machine_sync(&tx, identity)?;
    let mut responses = Vec::with_capacity(entries.len());
    let mut notifications = Vec::new();

    for entry in entries {
        // A preceding application command in this same committed batch may
        // have staged, fenced, or aborted a transition. Validate each entry
        // against the scope visible at its exact apply position.
        let scope = read_membership_scope_sync(&tx, identity)?;
        validate_entry_for_membership_scope(&entry, identity, &scope)?;
        let expected_index = last_applied
            .as_ref()
            .map(|log_id| {
                log_id
                    .index
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("session consensus applied index exhausted"))
            })
            .transpose()?
            .unwrap_or(0);
        if entry.log_id.index != expected_index {
            return Err(invalid_data("session consensus apply is not contiguous"));
        }

        let response = match entry.payload {
            EntryPayload::Blank => SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::Unit),
                sequence: 0,
                digest: None,
                logical_time: None,
                raft_log_index: entry.log_id.index,
            },
            EntryPayload::Membership(membership) => {
                let stored = StoredMembership::new(Some(entry.log_id), membership);
                store_membership_sync(&tx, identity, &stored)?;
                record_membership_transition_evidence_in_tx(&tx, identity, &stored)?;
                promote_membership_scope_if_quiescent_in_tx(&tx, identity)
                    .map_err(membership_scope_error)?;
                SessionConsensusResponse {
                    result: Ok(SessionMutationOutcome::Unit),
                    sequence: 0,
                    digest: None,
                    logical_time: None,
                    raft_log_index: entry.log_id.index,
                }
            }
            EntryPayload::Normal(command) => {
                let digest = payload_digest(&command)?;
                if let Some((persisted_digest, persisted_response)) =
                    read_outcome_sync(&tx, identity, command.request_id)?
                {
                    if persisted_digest != digest {
                        return Err(invalid_data(
                            "session consensus request ID was reused with another payload",
                        ));
                    }
                    persisted_response
                } else {
                    let sequence = machine.0.checked_add(1).ok_or_else(|| {
                        invalid_data("session consensus application sequence exhausted")
                    })?;
                    let logical_time = machine.2.map_or(command.logical_time, |last_time| {
                        last_time.max(command.logical_time)
                    });
                    let command_digest = command
                        .calculate_applied_digest(sequence, machine.1, logical_time)
                        .map_err(|_| invalid_data("session consensus command digest failed"))?;

                    let (result, replication) = {
                        let mut savepoint = tx.savepoint().map_err(db_error)?;
                        match execute_intent_sync(
                            &savepoint,
                            identity,
                            entry.log_id.index,
                            &command.intent,
                            caps,
                            logical_time,
                        ) {
                            Ok((outcome, replication)) => {
                                savepoint.commit().map_err(db_error)?;
                                (Ok(outcome), replication)
                            }
                            Err(error) if is_deterministic_intent_rejection(&error) => {
                                savepoint.rollback().map_err(db_error)?;
                                (Err(error), None)
                            }
                            Err(_) => {
                                savepoint.rollback().map_err(db_error)?;
                                return Err(state_machine_intent_fault());
                            }
                        }
                    };

                    let response = SessionConsensusResponse {
                        result,
                        sequence,
                        digest: Some(command_digest),
                        logical_time: Some(logical_time),
                        raft_log_index: entry.log_id.index,
                    };
                    tx.execute(
                        "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, response_json) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            command.request_id.as_bytes().as_slice(),
                            epoch_i64(identity)?,
                            digest.as_slice(),
                            encode_json(&response)?,
                        ],
                    )
                    .map_err(db_error)?;
                    let changed = tx
                        .execute(
                            "UPDATE consensus_machine SET application_sequence = ?1, last_digest = ?2, logical_time = ?3 WHERE singleton = 1 AND configuration_epoch = ?4",
                            params![
                                checked_positive_i64(sequence)?,
                                command_digest.as_bytes().as_slice(),
                                ops::format_rfc3339_normalized(logical_time),
                                epoch_i64(identity)?,
                            ],
                        )
                        .map_err(db_error)?;
                    if changed != 1 {
                        return Err(invalid_data("session consensus machine state is missing"));
                    }
                    machine.0 = sequence;
                    machine.1 = command_digest;
                    machine.2 = Some(logical_time);
                    if let Some(replication) = replication {
                        machine.3 = machine.3.checked_add(1).ok_or_else(|| {
                            invalid_data("session consensus watch sequence exhausted")
                        })?;
                        notifications.push(store_replication_notification_sync(
                            &tx,
                            identity,
                            machine.3,
                            command.request_id,
                            replication,
                            logical_time,
                        )?);
                    }
                    response
                }
            }
        };

        save_log_pointer(&tx, "consensus_applied", identity, &entry.log_id)?;
        last_applied = Some(entry.log_id);
        responses.push(response);
    }

    validate_persisted_membership_sync(&tx, identity)?;
    tx.commit().map_err(db_error)?;
    Ok(AppliedBatch {
        responses,
        notifications,
    })
}

pub(crate) fn validate_sealed_state_sync(conn: &Connection) -> io::Result<()> {
    let invalid_stable_id = conn
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM session_records
                WHERE typeof(stable_id) != 'blob'
                   OR length(stable_id) NOT BETWEEN 1 AND 64
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(db_error)?;
    if invalid_stable_id {
        return Err(invalid_data(
            "session consensus snapshot stable identifier is invalid",
        ));
    }

    let mut record_stmt = conn
        .prepare(
            r#"
            SELECT tenant, nf_kind, key_type, stable_id, generation, owner,
                   fence, state_class, state_type, expires_at, payload, encoding
            FROM session_records
            "#,
        )
        .map_err(db_error)?;
    let records = record_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, i64>(11)?,
            ))
        })
        .map_err(db_error)?;
    for row in records {
        let (
            tenant,
            nf_kind,
            key_type,
            stable_id,
            generation,
            owner,
            fence,
            state_class,
            state_type,
            expires_at,
            payload,
            encoding,
        ) = row.map_err(db_error)?;
        let record = ops::stored_record_from_row(
            tenant,
            nf_kind,
            key_type,
            stable_id,
            generation,
            owner,
            fence,
            state_class,
            state_type,
            expires_at,
            payload,
            encoding,
        )
        .map_err(|_| invalid_data("session consensus snapshot record is invalid"))?;
        if record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
            return Err(invalid_data(
                "session consensus snapshot contains an unsealed record payload",
            ));
        }
        record
            .payload
            .validate_envelope_for_record(&record)
            .map_err(|_| invalid_data("session consensus snapshot envelope is invalid"))?;
    }

    let mut stmt = conn
        .prepare(
            r#"
            SELECT sequence,
                   CASE
                       WHEN typeof(tx_id) = 'text'
                        AND length(CAST(tx_id AS BLOB)) BETWEEN ?1 AND ?2
                       THEN tx_id
                   END,
                   entry_json
            FROM session_replication_log
            ORDER BY sequence ASC
            "#,
        )
        .map_err(db_error)?;
    let rows = stmt
        .query_map(
            params![REPLICATION_TX_ID_MIN_BYTES, REPLICATION_TX_ID_MAX_BYTES],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(db_error)?;
    let mut expected = read_watch_cursor_invalidation_floor_sync(conn)?
        .checked_add(1)
        .ok_or_else(|| invalid_data("session replication sequence exhausted"))?;
    for row in rows {
        let (stored_sequence, stored_tx_id, encoded) = row.map_err(db_error)?;
        let stored_sequence = checked_u64(stored_sequence)?;
        let stored_tx_id: ReplicationTxId = stored_tx_id
            .ok_or_else(|| invalid_data("persisted session replication transaction ID is invalid"))?
            .try_into()
            .map_err(|_| invalid_data("persisted session replication transaction ID is invalid"))?;
        let entry: ReplicationEntry = serde_json::from_str(&encoded)
            .map_err(|_| invalid_data("persisted session replication entry is invalid"))?;
        if stored_sequence != expected || entry.sequence != stored_sequence {
            return Err(invalid_data(
                "persisted session replication log is not contiguous",
            ));
        }
        if entry.tx_id != stored_tx_id {
            return Err(invalid_data(
                "persisted session replication transaction ID is inconsistent",
            ));
        }
        entry
            .validate()
            .map_err(|_| invalid_data("persisted session replication entry is invalid"))?;
        validate_sealed_replication_op(&entry.op)?;
        expected = expected
            .checked_add(1)
            .ok_or_else(|| invalid_data("session replication sequence exhausted"))?;
    }
    let observed_head = expected
        .checked_sub(1)
        .ok_or_else(|| invalid_data("session replication sequence underflow"))?;
    if table_exists(conn, "consensus_machine").map_err(db_error)? {
        let watch_sequence: i64 = conn
            .query_row(
                "SELECT watch_sequence FROM consensus_machine WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if checked_u64(watch_sequence)? != observed_head {
            return Err(invalid_data(
                "session replication cursor does not match the persisted log",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_sealed_replication_op(root: &ReplicationOp) -> io::Result<()> {
    let mut pending = vec![root];
    let mut visited = 0_usize;
    while let Some(op) = pending.pop() {
        visited = visited
            .checked_add(1)
            .ok_or_else(|| invalid_data("session replication operation count overflow"))?;
        if visited > crate::backend::MAX_REPLICATION_OPERATIONS_PER_ENTRY {
            return Err(invalid_data("session replication operation limit exceeded"));
        }
        match op {
            ReplicationOp::CompareAndSet { new_record, .. } => {
                if new_record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
                    return Err(invalid_data(
                        "session replication log contains an unsealed record payload",
                    ));
                }
                new_record
                    .payload
                    .validate_envelope_for_record(new_record)
                    .map_err(|_| {
                        invalid_data("session replication log contains an invalid envelope")
                    })?;
            }
            ReplicationOp::Batch { ops } => pending.extend(ops),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn build_snapshot_database_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    path: &std::path::Path,
) -> io::Result<ConsensusAppliedMembership> {
    validate_sealed_state_sync(conn)?;
    let applied = read_applied_sync(conn, identity)?;
    let membership = read_membership_sync(conn, identity)?;
    validate_membership_ids(&membership)?;

    let mut destination = Connection::open(path).map_err(db_error)?;
    {
        let backup = rusqlite::backup::Backup::new(conn, &mut destination).map_err(db_error)?;
        backup
            .run_to_completion(128, std::time::Duration::ZERO, None)
            .map_err(db_error)?;
    }
    destination
        .execute_batch(
            r#"
            DELETE FROM consensus_vote;
            DELETE FROM consensus_committed;
            DELETE FROM consensus_purged;
            DELETE FROM consensus_log;
            DELETE FROM consensus_snapshot;
            PRAGMA journal_mode = DELETE;
            VACUUM;
            "#,
        )
        .map_err(db_error)?;
    ops::rotate_restore_scan_epoch_sync(&destination)
        .map_err(|_| invalid_data("built session consensus snapshot restore metadata failed"))?;
    validate_existing_schema(&destination, identity)
        .map_err(|_| invalid_data("built session consensus snapshot failed validation"))?;
    validate_sealed_state_sync(&destination)?;
    Ok((applied, membership))
}

fn transition_start_is_compatible(local: u64, incoming: u64) -> bool {
    // A pristine candidate has no copy of the source log from which to derive
    // the prepare-entry index and records zero until it receives authoritative
    // state. Every non-zero locally observed index is exact and immutable.
    local == 0 || local == incoming
}

fn optional_transition_index_is_not_behind(local: Option<u64>, incoming: Option<u64>) -> bool {
    local.is_none() || local == incoming
}

fn pending_transition_is_not_behind(
    local: &PendingMembershipScope,
    incoming: &PendingMembershipScope,
) -> bool {
    local.transition_id == incoming.transition_id
        && local.transition_digest == incoming.transition_digest
        && local.desired_identity == incoming.desired_identity
        && local.desired_members == incoming.desired_members
        && transition_start_is_compatible(
            local.transition_start_log_index,
            incoming.transition_start_log_index,
        )
        && optional_transition_index_is_not_behind(
            local.learners_ready_log_index,
            incoming.learners_ready_log_index,
        )
        && optional_transition_index_is_not_behind(
            local.joint_membership_log_index,
            incoming.joint_membership_log_index,
        )
        && optional_transition_index_is_not_behind(
            local.uniform_membership_log_index,
            incoming.uniform_membership_log_index,
        )
}

fn terminal_matches_pending_progress(
    local: &PendingMembershipScope,
    terminal: &TerminalMembershipTransition,
) -> bool {
    local.transition_id == terminal.transition_id
        && local.transition_digest == terminal.transition_digest
        && transition_start_is_compatible(
            local.transition_start_log_index,
            terminal.transition_start_log_index,
        )
        && optional_transition_index_is_not_behind(
            local.learners_ready_log_index,
            terminal.learners_ready_log_index,
        )
        && optional_transition_index_is_not_behind(
            local.joint_membership_log_index,
            terminal.joint_membership_log_index,
        )
        && optional_transition_index_is_not_behind(
            local.uniform_membership_log_index,
            terminal.uniform_membership_log_index,
        )
}

fn finalized_terminal_is_not_behind(
    local: &TerminalMembershipTransition,
    incoming: &TerminalMembershipTransition,
) -> bool {
    local.transition_id == incoming.transition_id
        && local.transition_digest == incoming.transition_digest
        && local.outcome == incoming.outcome
        && local.transition_start_log_index == incoming.transition_start_log_index
        && local.learners_ready_log_index == incoming.learners_ready_log_index
        && local.joint_membership_log_index == incoming.joint_membership_log_index
        && local.uniform_membership_log_index == incoming.uniform_membership_log_index
        && local.cutover_log_index == incoming.cutover_log_index
        && (local.finalization_log_index.is_none()
            || local.finalization_log_index == incoming.finalization_log_index)
}

fn retained_lineage_is_not_behind(
    local_history: &[MembershipPredecessorScope],
    local_predecessor: Option<&MembershipPredecessorScope>,
    incoming_history: &[MembershipPredecessorScope],
    incoming_predecessor: Option<&MembershipPredecessorScope>,
) -> bool {
    let local_is_empty = local_history.is_empty() && local_predecessor.is_none();
    let incoming_is_compacted = incoming_history.is_empty() && incoming_predecessor.is_none();
    let exact_lineage = local_history
        .iter()
        .chain(local_predecessor)
        .eq(incoming_history.iter().chain(incoming_predecessor));
    local_is_empty || incoming_is_compacted || exact_lineage
}

fn incoming_lineage_contains_current_scope(
    local: &MembershipValidationScope,
    incoming: &MembershipValidationScope,
) -> bool {
    incoming
        .history
        .iter()
        .chain(incoming.predecessor.iter())
        .any(|predecessor| {
            predecessor.identity == local.current_identity
                && predecessor.members == local.current_members
        })
}

fn incoming_lineage_contains_pending_transition(
    local: &MembershipValidationScope,
    pending: &PendingMembershipScope,
    incoming: &MembershipValidationScope,
) -> bool {
    let lineage = incoming
        .history
        .iter()
        .chain(incoming.predecessor.iter())
        .collect::<Vec<_>>();
    lineage.iter().enumerate().any(|(offset, predecessor)| {
        let successor_identity = lineage
            .get(offset + 1)
            .map_or(incoming.current_identity, |next| next.identity);
        let successor_members = lineage
            .get(offset + 1)
            .map_or(&incoming.current_members, |next| &next.members);
        predecessor.identity == local.current_identity
            && predecessor.members == local.current_members
            && predecessor.transition_id == pending.transition_id
            && predecessor.transition_digest == pending.transition_digest
            && transition_start_is_compatible(
                pending.transition_start_log_index,
                predecessor.transition_start_log_index,
            )
            && successor_identity == pending.desired_identity
            && successor_members == &pending.desired_members
    })
}

fn validate_incoming_membership_scope(
    local: &MembershipValidationScope,
    incoming: &MembershipValidationScope,
) -> io::Result<()> {
    if local == incoming {
        return Ok(());
    }
    if local.current_identity.cluster_id() != incoming.current_identity.cluster_id() {
        return Err(invalid_data(
            "session consensus snapshot membership cluster mismatch",
        ));
    }

    if local.pending.is_none()
        && incoming.pending.is_none()
        && local.current_identity == incoming.current_identity
        && local.current_members == incoming.current_members
        && local.application_authority_epoch == incoming.application_authority_epoch
        && local.application_authority_members == incoming.application_authority_members
        && local
            .terminal
            .as_ref()
            .zip(incoming.terminal.as_ref())
            .is_some_and(|(local_terminal, incoming_terminal)| {
                finalized_terminal_is_not_behind(local_terminal, incoming_terminal)
            })
        && retained_lineage_is_not_behind(
            &local.history,
            local.predecessor.as_ref(),
            &incoming.history,
            incoming.predecessor.as_ref(),
        )
    {
        return Ok(());
    }

    if local.pending.is_none()
        && incoming.pending.is_some()
        && local.current_identity == incoming.current_identity
        && local.current_members == incoming.current_members
        && retained_lineage_is_not_behind(
            &local.history,
            local.predecessor.as_ref(),
            &incoming.history,
            incoming.predecessor.as_ref(),
        )
        && local
            .terminal
            .as_ref()
            .is_none_or(|terminal| incoming.terminal.as_ref() == Some(terminal))
    {
        return Ok(());
    }

    if local.pending.is_none()
        && incoming.current_identity.configuration_epoch()
            > local.current_identity.configuration_epoch()
        && incoming_lineage_contains_current_scope(local, incoming)
    {
        return Ok(());
    }

    if let Some(local_pending) = local.pending.as_ref() {
        if incoming.current_identity.configuration_epoch()
            > local.current_identity.configuration_epoch()
            && incoming_lineage_contains_pending_transition(local, local_pending, incoming)
        {
            return Ok(());
        }
    }

    let Some(local_pending) = local.pending.as_ref() else {
        return Err(invalid_data(
            "session consensus snapshot membership scope regressed or diverged",
        ));
    };
    if let Some(incoming_pending) = incoming.pending.as_ref() {
        let same_current = incoming.current_identity == local.current_identity
            && incoming.current_members == local.current_members
            && retained_lineage_is_not_behind(
                &local.history,
                local.predecessor.as_ref(),
                &incoming.history,
                incoming.predecessor.as_ref(),
            );
        let authority_not_behind = local.application_authority_epoch
            == local.current_identity.configuration_epoch()
            || (incoming.application_authority_epoch
                == local_pending.desired_identity.configuration_epoch()
                && incoming.application_authority_members == local_pending.desired_members);
        let retained_terminal_not_behind = local
            .terminal
            .as_ref()
            .is_none_or(|terminal| incoming.terminal.as_ref() == Some(terminal));
        if same_current
            && authority_not_behind
            && retained_terminal_not_behind
            && pending_transition_is_not_behind(local_pending, incoming_pending)
        {
            return Ok(());
        }
        return Err(invalid_data(
            "session consensus snapshot pending transition regressed or diverged",
        ));
    }

    let terminal = incoming.terminal.as_ref().ok_or_else(|| {
        invalid_data("session consensus snapshot lost pending transition evidence")
    })?;
    if !terminal_matches_pending_progress(local_pending, terminal) {
        return Err(invalid_data(
            "session consensus snapshot terminal transition diverged",
        ));
    }

    match terminal.outcome {
        TerminalMembershipOutcome::Aborted => {
            let restored = incoming.current_identity == local.current_identity
                && incoming.current_members == local.current_members
                && incoming.application_authority_epoch
                    == local.current_identity.configuration_epoch()
                && incoming.application_authority_members == local.current_members
                && incoming.predecessor.is_none()
                && terminal.cutover_log_index.is_none();
            if restored {
                Ok(())
            } else {
                Err(invalid_data(
                    "session consensus snapshot abort scope is inconsistent",
                ))
            }
        }
        TerminalMembershipOutcome::Promoted => {
            let predecessor_matches = incoming.predecessor.as_ref().is_some_and(|predecessor| {
                predecessor.transition_id == local_pending.transition_id
                    && predecessor.transition_digest == local_pending.transition_digest
                    && predecessor.identity == local.current_identity
                    && predecessor.members == local.current_members
                    && transition_start_is_compatible(
                        local_pending.transition_start_log_index,
                        predecessor.transition_start_log_index,
                    )
                    && terminal.cutover_log_index == Some(predecessor.cutover_log_index)
            });
            let promoted = incoming.current_identity == local_pending.desired_identity
                && incoming.current_members == local_pending.desired_members
                && incoming.application_authority_epoch
                    == local_pending.desired_identity.configuration_epoch()
                && incoming.application_authority_members == local_pending.desired_members
                && retained_lineage_is_not_behind(
                    &local.history,
                    local.predecessor.as_ref(),
                    &incoming.history,
                    None,
                )
                && predecessor_matches;
            if promoted {
                Ok(())
            } else {
                Err(invalid_data(
                    "session consensus snapshot promotion scope is inconsistent",
                ))
            }
        }
    }
}

fn validate_snapshot_database_sync(
    path: &std::path::Path,
    identity: SessionConsensusIdentity,
    expected_scope: &MembershipValidationScope,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
) -> io::Result<()> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(db_error)?;
    ensure_operator_recovery_schema_sync(&conn, identity)?;
    ensure_membership_scope_schema_sync(
        &conn,
        identity,
        expected_scope.current_identity,
        &expected_scope.current_members,
        &expected_scope.current_bindings,
    )?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(db_error)?;
    if integrity != "ok" {
        return Err(invalid_data(
            "session consensus snapshot integrity check failed",
        ));
    }
    validate_existing_schema(&conn, identity)
        .map_err(|_| invalid_data("session consensus snapshot identity is invalid"))?;
    let incoming_scope = read_membership_scope_sync(&conn, identity)?;
    validate_incoming_membership_scope(expected_scope, &incoming_scope)?;
    ops::read_restore_scan_state_sync(&conn)
        .map_err(|_| invalid_data("session consensus snapshot restore metadata is invalid"))?;
    validate_sealed_state_sync(&conn)?;
    let applied = read_applied_sync(&conn, identity)?;
    let membership = read_membership_sync(&conn, identity)?;
    if let Some(log_id) = meta.last_membership.log_id() {
        validate_membership_for_log(&meta.last_membership, &incoming_scope, log_id.index)?;
    } else if !is_pristine_membership(&meta.last_membership) {
        return Err(invalid_data(
            "session consensus snapshot membership log identity is missing",
        ));
    }
    if applied != meta.last_log_id || membership != meta.last_membership {
        return Err(invalid_data("session consensus snapshot metadata mismatch"));
    }
    for table in [
        "consensus_vote",
        "consensus_committed",
        "consensus_purged",
        "consensus_log",
        "consensus_snapshot",
    ] {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = conn
            .query_row(&sql, [], |row| row.get(0))
            .map_err(db_error)?;
        if count != 0 {
            return Err(invalid_data(
                "session consensus snapshot contains log-store authority",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn install_snapshot_database_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    snapshot_db_path: &std::path::Path,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    final_file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    let incoming_last_log_id = meta.last_log_id.as_ref();
    validate_snapshot_floor(conn, identity, incoming_last_log_id)?;
    let expected_scope = read_membership_scope_sync(conn, identity)?;
    validate_snapshot_database_sync(snapshot_db_path, identity, &expected_scope, meta)?;
    if final_file_name.is_empty()
        || final_file_name.contains('/')
        || final_file_name.contains('\\')
        || final_file_name == "."
        || final_file_name == ".."
    {
        return Err(invalid_data("invalid session consensus snapshot file name"));
    }
    let byte_length = checked_positive_i64(byte_length)?;
    let snapshot_path = snapshot_db_path
        .to_str()
        .ok_or_else(|| invalid_data("session consensus snapshot path is not UTF-8"))?;
    conn.execute("ATTACH DATABASE ?1 AS consensus_incoming", [snapshot_path])
        .map_err(db_error)?;

    let result = (|| {
        let tx = conn.unchecked_transaction().map_err(db_error)?;
        // Re-check under the same transaction that swaps the state image. A
        // second process must not be able to advance the durable floor between
        // validation and replacement even though deployment admission already
        // requires one writer per backing store.
        validate_snapshot_floor(&tx, identity, incoming_last_log_id)?;
        for (table, columns) in [
            (
                "session_records",
                "tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, state_type, expires_at, payload, encoding",
            ),
            (
                "leases",
                "tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at",
            ),
            (
                "key_fences",
                "tenant, nf_kind, key_type, stable_id, fence",
            ),
            ("lease_globals", "key, val"),
            (
                "session_replication_log",
                "sequence, tx_id, entry_json, timestamp",
            ),
            (
                "consensus_request_outcomes",
                "request_id, configuration_epoch, payload_digest, response_json",
            ),
            (
                "consensus_machine",
                "singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence",
            ),
            (
                "consensus_membership",
                "singleton, configuration_epoch, membership_json",
            ),
            (
                "consensus_membership_scope",
                "singleton, storage_configuration_epoch, current_configuration_id, current_configuration_epoch, current_members_json, current_bindings_json, application_authority_epoch, application_authority_members_json, predecessor_configuration_id, predecessor_transition_id, predecessor_transition_digest, predecessor_configuration_epoch, predecessor_members_json, predecessor_transition_start_index, predecessor_cutover_index, pending_transition_id, pending_transition_digest, desired_configuration_id, desired_configuration_epoch, desired_members_json, desired_bindings_json, pending_transition_start_index, pending_learners_ready_index, pending_joint_membership_index, pending_uniform_membership_index, terminal_transition_id, terminal_transition_digest, terminal_transition_outcome, terminal_transition_start_index, terminal_learners_ready_index, terminal_joint_membership_index, terminal_uniform_membership_index, terminal_cutover_index, terminal_finalization_index",
            ),
            (
                "consensus_membership_history",
                "configuration_epoch, storage_configuration_epoch, configuration_id, members_json, transition_id, transition_digest, transition_start_index, cutover_index",
            ),
            (
                "consensus_applied",
                "singleton, configuration_epoch, term, log_index, log_id_json",
            ),
            (
                "consensus_operator_recovery",
                "singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor",
            ),
            (
                "restore_scan_state",
                "singleton, epoch, revision, cursor_key",
            ),
        ] {
            tx.execute(&format!("DELETE FROM {table}"), [])
                .map_err(db_error)?;
            tx.execute(
                &format!(
                    "INSERT INTO {table} ({columns}) SELECT {columns} FROM consensus_incoming.{table}"
                ),
                [],
            )
            .map_err(db_error)?;
        }
        // Restore cursors are local evidence, not replicated state-machine
        // authority. Every snapshot destination gets a fresh incarnation so
        // two nodes installing the same coherent snapshot cannot consume one
        // another's continuation token.
        ops::rotate_restore_scan_incarnation_sync(&tx)
            .map_err(|_| invalid_data("installed session snapshot restore metadata failed"))?;
        tx.execute(
            "INSERT OR REPLACE INTO consensus_snapshot (singleton, configuration_epoch, meta_json, file_name, checksum, byte_length) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                epoch_i64(identity)?,
                encode_json(meta)?,
                final_file_name,
                checksum.as_slice(),
                byte_length,
            ],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)
    })();

    let detach = conn
        .execute("DETACH DATABASE consensus_incoming", [])
        .map_err(db_error);
    result.and(detach.map(|_| ()))
}

fn validate_snapshot_floor(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    incoming_last_log_id: Option<&LogId<SessionConsensusNodeId>>,
) -> io::Result<()> {
    for floor in [
        read_committed_sync(conn, identity)?,
        read_applied_sync(conn, identity)?,
    ] {
        let Some(floor) = floor else {
            continue;
        };
        let Some(incoming) = incoming_last_log_id else {
            return Err(invalid_data(
                "session consensus snapshot regresses durable state",
            ));
        };
        if incoming.index < floor.index || (incoming.index == floor.index && incoming != &floor) {
            return Err(invalid_data(
                "session consensus snapshot regresses durable state",
            ));
        }
    }
    Ok(())
}

pub(crate) fn save_current_snapshot_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    let scope = read_membership_scope_sync(conn, identity)?;
    if let Some(log_id) = meta.last_membership.log_id() {
        validate_membership_for_log(&meta.last_membership, &scope, log_id.index)?;
    } else if !is_pristine_membership(&meta.last_membership) {
        return Err(invalid_data(
            "session consensus snapshot membership log identity is missing",
        ));
    }
    let changed = conn
        .execute(
            "INSERT OR REPLACE INTO consensus_snapshot (singleton, configuration_epoch, meta_json, file_name, checksum, byte_length) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                epoch_i64(identity)?,
                encode_json(meta)?,
                file_name,
                checksum.as_slice(),
                checked_positive_i64(byte_length)?,
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data(
            "session consensus snapshot metadata was not saved",
        ));
    }
    Ok(())
}

pub(crate) type CurrentSnapshot = (
    opc_consensus::engine::SnapshotMeta<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    String,
    [u8; 32],
    u64,
);

pub(crate) fn read_current_snapshot_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<CurrentSnapshot>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, meta_json, file_name, checksum, byte_length FROM consensus_snapshot WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, encoded_meta, file_name, checksum, byte_length)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    if file_name.is_empty()
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name == "."
        || file_name == ".."
    {
        return Err(invalid_data(
            "persisted session consensus snapshot file name is invalid",
        ));
    }
    let checksum = checksum
        .try_into()
        .map_err(|_| invalid_data("persisted session consensus snapshot checksum is invalid"))?;
    let meta: opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    > = decode_json(&encoded_meta)?;
    let scope = read_membership_scope_sync(conn, identity)?;
    if let Some(log_id) = meta.last_membership.log_id() {
        validate_membership_for_log(&meta.last_membership, &scope, log_id.index)?;
    } else if !is_pristine_membership(&meta.last_membership) {
        return Err(invalid_data(
            "session consensus snapshot membership log identity is missing",
        ));
    }
    Ok(Some((
        meta,
        file_name,
        checksum,
        checked_positive_u64(byte_length)?,
    )))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId};
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    use super::*;
    use crate::model::{OwnerId, SessionKey, SessionKeyType};
    use crate::restore::{RestoreScanCursor, RestoreScanRequest, RestoreScanScope};

    fn identity() -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::new("state-machine-fault-tests")
                .expect("cluster ID"),
            crate::consensus::SessionConsensusConfigurationId::from_bytes([0x51; 32]),
            crate::consensus::SessionConsensusConfigurationEpoch::new(1)
                .expect("configuration epoch"),
        )
    }

    fn node_id() -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(7).expect("node ID")
    }

    fn expected_members() -> BTreeSet<SessionConsensusNodeId> {
        BTreeSet::from([node_id()])
    }

    fn member(value: u64) -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(value).expect("member ID")
    }

    fn stored_membership(
        configs: Vec<BTreeSet<SessionConsensusNodeId>>,
        nodes: BTreeSet<SessionConsensusNodeId>,
    ) -> StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode> {
        stored_membership_at(0, configs, nodes)
    }

    fn stored_membership_at(
        index: u64,
        configs: Vec<BTreeSet<SessionConsensusNodeId>>,
        nodes: BTreeSet<SessionConsensusNodeId>,
    ) -> StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode> {
        StoredMembership::new(
            Some(log_id(index)),
            opc_consensus::engine::Membership::new(configs, nodes),
        )
    }

    fn membership_entry_at(
        index: u64,
        configs: Vec<BTreeSet<SessionConsensusNodeId>>,
        nodes: BTreeSet<SessionConsensusNodeId>,
    ) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                configs, nodes,
            )),
        }
    }

    fn topology_entry_at(
        index: u64,
        request_byte: u8,
        intent: SessionMutationIntent,
    ) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: identity(),
                request_id: SessionConsensusRequestId::from_bytes([request_byte; 16]),
                logical_time: timestamp(u8::try_from(index).expect("test log index")),
                intent,
            }),
        }
    }

    fn identity_at(epoch: u64, configuration_byte: u8) -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            identity().cluster_id(),
            SessionConsensusConfigurationId::from_bytes([configuration_byte; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).expect("configuration epoch"),
        )
    }

    fn members(values: &[u64]) -> BTreeSet<SessionConsensusNodeId> {
        values.iter().copied().map(member).collect()
    }

    fn log_id(index: u64) -> LogId<SessionConsensusNodeId> {
        LogId::new(CommittedLeaderId::new(1, node_id()), index)
    }

    fn timestamp(second: u8) -> Timestamp {
        Timestamp::from_str(&format!("2026-07-12T00:00:{second:02}Z")).expect("timestamp")
    }

    fn key() -> crate::model::SessionKey {
        SessionKey {
            tenant: TenantId::from_static("state-machine-fault-tenant"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"state-machine-fault-session")
                .try_into()
                .expect("valid stable ID"),
        }
    }

    #[tokio::test]
    async fn sealed_snapshot_validation_rejects_invalid_stable_ids_first() {
        for stable_id in [Vec::new(), vec![0x5a_u8; crate::STABLE_ID_MAX_BYTES + 1]] {
            let backend = SqliteSessionBackend::in_memory().expect("backend");
            let conn = backend.conn.lock().await;
            conn.execute_batch("PRAGMA ignore_check_constraints = ON")
                .expect("allow corrupt snapshot fixture");
            conn.execute(
                r#"
                INSERT INTO session_records (
                    tenant, nf_kind, key_type, stable_id, generation, owner,
                    fence, state_class, state_type, expires_at, payload, encoding
                ) VALUES ('tenant-a', 'smf', 'pdu-session', ?1, 1, 'owner-a',
                          1, 'authoritative-session', 'state-a', NULL, X'', 0)
                "#,
                [stable_id],
            )
            .expect("inject invalid stable ID");

            let error = validate_sealed_state_sync(&conn)
                .expect_err("invalid stable ID must reject snapshot");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "session consensus snapshot stable identifier is invalid"
            );
        }
    }

    fn membership_entry() -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![expected_members()],
                expected_members(),
            )),
        }
    }

    fn blank_entry(index: u64) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Blank,
        }
    }

    async fn backend_with_blank_logs(last_index: u64) -> SqliteSessionBackend {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        {
            let conn = backend.conn.lock().await;
            initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
            let mut entries = vec![membership_entry()];
            entries.extend((1..=last_index).map(blank_entry));
            append_logs_sync(&conn, identity(), &entries).expect("append log fixtures");
        }
        backend
    }

    #[tokio::test]
    async fn limited_log_read_rejects_a_missing_leading_row() {
        let backend = backend_with_blank_logs(2).await;
        let conn = backend.conn.lock().await;
        conn.execute("DELETE FROM consensus_log WHERE log_index = 1", [])
            .expect("inject leading hole");

        let error = read_limited_log_range_sync(
            &conn,
            identity(),
            1,
            3,
            opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES,
        )
        .expect_err("missing leading row must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn limited_log_read_rejects_an_internal_hole() {
        let backend = backend_with_blank_logs(3).await;
        let conn = backend.conn.lock().await;
        conn.execute("DELETE FROM consensus_log WHERE log_index = 2", [])
            .expect("inject internal hole");

        let error = read_limited_log_range_sync(
            &conn,
            identity(),
            1,
            4,
            opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES,
        )
        .expect_err("internal hole must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn limited_log_read_crossing_purged_floor_starts_after_the_floor() {
        let backend = backend_with_blank_logs(3).await;
        let conn = backend.conn.lock().await;
        let applied = vec![
            membership_entry(),
            blank_entry(1),
            blank_entry(2),
            blank_entry(3),
        ];
        apply_entries_sync(&conn, identity(), &backend.caps, applied).expect("apply log fixtures");
        purge_logs_sync(&conn, identity(), &log_id(1)).expect("purge applied prefix");

        let entries = read_limited_log_range_sync(
            &conn,
            identity(),
            0,
            4,
            opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES,
        )
        .expect("range crosses purged floor");
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.log_id.index)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    fn acquire_entry(
        index: u64,
        request_id: [u8; 16],
        owner: &'static str,
    ) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: identity(),
                request_id: SessionConsensusRequestId::from_bytes(request_id),
                logical_time: timestamp(u8::try_from(index).expect("test index fits timestamp")),
                intent: SessionMutationIntent::AcquireLease {
                    key: key(),
                    owner: OwnerId::new(owner).expect("owner"),
                    ttl: Duration::from_secs(300),
                },
            }),
        }
    }

    #[test]
    fn only_deterministic_domain_rejections_are_committable() {
        for error in [
            StoreError::NotFound,
            StoreError::StaleFence,
            StoreError::CasConflict,
            StoreError::InvalidKey("SDK-owned validation reason".into()),
            StoreError::InvalidSessionTtl,
            StoreError::InvalidRecordExpiry,
            StoreError::LeaseHeld,
            StoreError::LeaseExpired,
            StoreError::PayloadTooLarge { actual: 2, max: 1 },
        ] {
            assert!(is_deterministic_intent_rejection(&error));
        }

        for error in [
            StoreError::BackendUnavailable("node-local detail".into()),
            StoreError::Serialization("corrupt local row".into()),
            StoreError::CapabilityNotSupported("local capability".into()),
            StoreError::Crypto("invalid persisted envelope".into()),
        ] {
            assert!(!is_deterministic_intent_rejection(&error));
        }
    }

    #[test]
    fn follower_log_admission_uses_command_time_for_record_expiry() {
        let logical_time = timestamp(1);
        let key = key();
        let owner = OwnerId::new("owner-a").expect("owner");
        let fence = crate::FenceToken::new(1);
        let lease = crate::LeaseGuard::new(
            key.clone(),
            owner.clone(),
            fence,
            logical_time,
            logical_time,
            1,
        );
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes([0x44; 16]),
            logical_time,
            intent: SessionMutationIntent::CompareAndSet(Box::new(crate::CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: crate::StoredSessionRecord {
                    key,
                    generation: crate::Generation::new(1),
                    owner,
                    fence,
                    state_class: crate::StateClass::AuthoritativeSession,
                    state_type: crate::StateType::from_static("state-machine-fault"),
                    expires_at: Some(
                        Timestamp::from_str("9999-12-31T23:59:59.999999999Z")
                            .expect("far-future timestamp"),
                    ),
                    payload: crate::EncryptedSessionPayload::new(b"payload"),
                },
            })),
        };

        let error = validate_command_for_log(&command, identity())
            .expect_err("follower log admission must reject the leader command");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session consensus record expiry is invalid"
        );
    }

    #[test]
    fn fixed_membership_rejects_subset_joint_and_learner_shapes() {
        let expected = BTreeSet::from([member(7), member(8), member(9)]);
        let exact = stored_membership(vec![expected.clone()], expected.clone());
        validate_uniform_membership(&exact, &expected).expect("exact membership");

        let subset = BTreeSet::from([member(7), member(8)]);
        assert!(validate_uniform_membership(
            &stored_membership(vec![subset.clone()], subset),
            &expected
        )
        .is_err());
        assert!(validate_uniform_membership(
            &stored_membership(
                vec![expected.clone(), BTreeSet::from([member(7), member(8)])],
                expected.clone(),
            ),
            &expected,
        )
        .is_err());
        let mut nodes_with_learner = expected.clone();
        nodes_with_learner.insert(member(10));
        assert!(validate_uniform_membership(
            &stored_membership(vec![expected.clone()], nodes_with_learner),
            &expected,
        )
        .is_err());
    }

    #[test]
    fn transition_membership_classifier_accepts_only_exact_bounded_shapes() {
        let current = members(&[7, 8, 9]);
        let desired = members(&[7, 8, 9, 10, 11]);
        let union = current.union(&desired).copied().collect::<BTreeSet<_>>();

        assert_eq!(
            MembershipShape::CurrentUniform,
            classify_transition_membership(
                &stored_membership(vec![current.clone()], current.clone()),
                &current,
                &desired,
            )
            .expect("current uniform")
        );
        assert_eq!(
            MembershipShape::LearnersCatchingUp,
            classify_transition_membership(
                &stored_membership(vec![current.clone()], union.clone()),
                &current,
                &desired,
            )
            .expect("desired additions are exact learners")
        );
        assert_eq!(
            MembershipShape::Joint,
            classify_transition_membership(
                &stored_membership(vec![current.clone(), desired.clone()], union.clone()),
                &current,
                &desired,
            )
            .expect("exact joint membership")
        );
        assert_eq!(
            MembershipShape::DesiredUniform,
            classify_transition_membership(
                &stored_membership(vec![desired.clone()], desired.clone()),
                &current,
                &desired,
            )
            .expect("desired uniform")
        );

        let mut invented = union;
        invented.insert(member(12));
        assert!(classify_transition_membership(
            &stored_membership(vec![current.clone()], invented),
            &current,
            &desired,
        )
        .is_err());
        assert!(classify_transition_membership(
            &stored_membership(vec![current.clone(), members(&[7, 8, 10])], desired.clone(),),
            &current,
            &desired,
        )
        .is_err());
    }

    #[tokio::test]
    async fn durable_membership_scope_completes_sequential_three_five_three() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let storage_identity = identity();
        let current = members(&[7, 8, 9]);
        let five = members(&[7, 8, 9, 10, 11]);
        let final_three = members(&[9, 10, 11]);
        let five_identity = identity_at(2, 0x52);
        let final_identity = identity_at(3, 0x53);
        let first_id = [0x11; MEMBERSHIP_TRANSITION_ID_BYTES];
        let first_digest = [0x21; 32];
        let second_id = [0x12; MEMBERSHIP_TRANSITION_ID_BYTES];
        let second_digest = [0x22; 32];

        initialize_schema(&conn, storage_identity, &current).expect("initialize current scope");
        let initial = membership_entry_at(0, vec![current.clone()], current.clone());
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&initial))
            .expect("append initial membership");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![initial])
            .expect("apply initial membership");

        assert_eq!(
            MembershipScopeMutation::Applied,
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                first_id,
                first_digest,
                five_identity,
                &five,
            )
            .expect("stage first transition")
        );
        assert_eq!(
            MembershipScopeMutation::Idempotent,
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                first_id,
                first_digest,
                five_identity,
                &five,
            )
            .expect("retry exact first transition")
        );
        assert_eq!(
            MembershipScopeMutationError::ConflictingTransition,
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                first_id,
                [0x31; 32],
                five_identity,
                &five,
            )
            .expect_err("same transition ID with another digest must conflict")
        );

        validate_application_authority_sync(&conn, storage_identity, member(7), storage_identity)
            .expect("current origin is initially authoritative");
        assert!(validate_application_authority_sync(
            &conn,
            storage_identity,
            member(10),
            five_identity,
        )
        .is_err());

        let learners = membership_entry_at(1, vec![current.clone()], five.clone());
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&learners))
            .expect("append learner membership");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![learners])
            .expect("apply learner membership");
        let ready = topology_entry_at(
            2,
            0x81,
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id: first_id,
                request_digest: first_digest,
            },
        );
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&ready))
            .expect("append learner readiness");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![ready])
            .expect("apply learner readiness");
        fence_application_authority_sync(&conn, storage_identity, first_id, first_digest)
            .expect("fence application authority");
        assert!(validate_application_authority_sync(
            &conn,
            storage_identity,
            member(7),
            storage_identity,
        )
        .is_err());
        validate_application_authority_sync(&conn, storage_identity, member(10), five_identity)
            .expect("new desired member is authoritative after fence");

        let joint = membership_entry_at(3, vec![current.clone(), five.clone()], five.clone());
        let uniform = membership_entry_at(4, vec![five.clone()], five.clone());
        append_logs_sync(&conn, storage_identity, &[joint.clone(), uniform.clone()])
            .expect("append joint and desired membership");
        save_committed_sync(&conn, storage_identity, Some(uniform.log_id))
            .expect("commit first transition");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![joint, uniform])
            .expect("apply and auto-promote first transition");

        let evidence = read_membership_transition_evidence_sync(
            &conn,
            storage_identity,
            first_id,
            first_digest,
        )
        .expect("read first transition evidence")
        .expect("first transition evidence");
        assert_eq!(Some(TerminalMembershipOutcome::Promoted), evidence.outcome);
        assert_eq!(1, evidence.transition_start_log_index);
        assert_eq!(Some(2), evidence.learners_ready_log_index);
        assert_eq!(Some(3), evidence.joint_membership_log_index);
        assert_eq!(Some(4), evidence.uniform_membership_log_index);
        assert_eq!(Some(4), evidence.cutover_log_index);
        assert_eq!(
            MembershipScopeMutation::Applied,
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                second_id,
                second_digest,
                final_identity,
                &final_three,
            )
            .expect("stage a second live transition without local compaction")
        );
        assert_eq!(
            storage_identity,
            initialize_schema(&conn, five_identity, &five)
                .expect("restart keeps pending second transition and immutable anchor")
        );
        let staged = read_membership_scope_sync(&conn, storage_identity).expect("staged scope");
        assert!(staged.predecessor.is_some());
        assert!(staged.pending.is_some());
        let transition_floor = blank_entry(5);
        append_logs_sync(
            &conn,
            storage_identity,
            std::slice::from_ref(&transition_floor),
        )
        .expect("append second transition floor");
        apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![transition_floor],
        )
        .expect("apply second transition floor");
        let ready = topology_entry_at(
            6,
            0x82,
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id: second_id,
                request_digest: second_digest,
            },
        );
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&ready))
            .expect("append second readiness");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![ready])
            .expect("apply second readiness");
        fence_application_authority_sync(&conn, storage_identity, second_id, second_digest)
            .expect("fence second authority");
        let joint = membership_entry_at(7, vec![five.clone(), final_three.clone()], five.clone());
        let uniform = membership_entry_at(8, vec![final_three.clone()], final_three.clone());
        append_logs_sync(&conn, storage_identity, &[joint.clone(), uniform.clone()])
            .expect("append second transition memberships");
        save_committed_sync(&conn, storage_identity, Some(uniform.log_id))
            .expect("commit second transition");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![joint, uniform])
            .expect("apply and auto-promote second transition");

        let scope = read_membership_scope_sync(&conn, storage_identity)
            .expect("read final membership scope");
        assert_eq!(final_identity, scope.current_identity);
        assert_eq!(final_three, scope.current_members);
        assert_eq!(1, scope.history.len());
        assert_eq!(storage_identity, scope.history[0].identity);
        assert_eq!(
            five_identity,
            scope.predecessor.as_ref().expect("latest").identity
        );
        assert_eq!(
            storage_identity,
            read_storage_identity_sync(&conn).expect("anchor")
        );
        let evidence = read_membership_transition_evidence_sync(
            &conn,
            storage_identity,
            second_id,
            second_digest,
        )
        .expect("read second transition evidence")
        .expect("second transition evidence");
        assert_eq!(Some(6), evidence.learners_ready_log_index);
        assert_eq!(Some(7), evidence.joint_membership_log_index);
        assert_eq!(Some(8), evidence.uniform_membership_log_index);
        assert_eq!(Some(8), evidence.cutover_log_index);

        let final_membership =
            read_membership_sync(&conn, storage_identity).expect("read final membership");
        let snapshot_meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: Some(log_id(8)),
            last_membership: final_membership,
            snapshot_id: "membership-transition-two".into(),
        };
        save_current_snapshot_sync(
            &conn,
            storage_identity,
            &snapshot_meta,
            "membership-transition-two.opc",
            [0x71; 32],
            1,
        )
        .expect("save compaction snapshot metadata");
        purge_logs_sync(&conn, storage_identity, &log_id(8)).expect("purge transition history");
        drop_compacted_membership_predecessor_sync(&conn, storage_identity)
            .expect("drop all compacted predecessor history");
        let compacted =
            read_membership_scope_sync(&conn, storage_identity).expect("compacted scope");
        assert!(compacted.predecessor.is_none());
        assert_eq!(2, compacted.history.len());
        assert!(read_current_snapshot_sync(&conn, storage_identity)
            .expect("retained snapshot")
            .is_some());
    }

    #[tokio::test]
    async fn pre_joint_abort_atomically_restores_authority_and_preserves_exact_evidence() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let storage_identity = identity();
        let current = members(&[7, 8, 9]);
        let desired = members(&[8, 9, 10]);
        let desired_identity = identity_at(2, 0x62);
        let transition_id = [0x41; MEMBERSHIP_TRANSITION_ID_BYTES];
        let transition_digest = [0x42; 32];
        initialize_schema(&conn, storage_identity, &current).expect("initialize scope");
        let initial = membership_entry_at(0, vec![current.clone()], current.clone());
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&initial))
            .expect("append current membership");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![initial])
            .expect("apply current membership");
        stage_membership_scope_sync(
            &conn,
            storage_identity,
            transition_id,
            transition_digest,
            desired_identity,
            &desired,
        )
        .expect("stage transition");
        let learners = membership_entry_at(
            1,
            vec![current.clone()],
            current.union(&desired).copied().collect(),
        );
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&learners))
            .expect("append learners");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![learners])
            .expect("apply learners");
        let ready = topology_entry_at(
            2,
            0x83,
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id,
                request_digest: transition_digest,
            },
        );
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&ready))
            .expect("append readiness");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![ready])
            .expect("apply readiness");
        fence_application_authority_sync(&conn, storage_identity, transition_id, transition_digest)
            .expect("fence authority");
        let restored = membership_entry_at(3, vec![current.clone()], current.clone());
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&restored))
            .expect("append restored membership");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![restored])
            .expect("apply restored membership");

        assert_eq!(
            MembershipScopeMutation::Applied,
            abort_membership_scope_sync(&conn, storage_identity, transition_id, transition_digest,)
                .expect("atomically abort")
        );
        assert_eq!(
            MembershipScopeMutation::Idempotent,
            abort_membership_scope_sync(&conn, storage_identity, transition_id, transition_digest,)
                .expect("retry abort")
        );
        validate_application_authority_sync(&conn, storage_identity, member(7), storage_identity)
            .expect("current authority restored with abort");
        assert!(validate_application_authority_sync(
            &conn,
            storage_identity,
            member(10),
            desired_identity,
        )
        .is_err());
        let scope = read_membership_scope_sync(&conn, storage_identity).expect("scope");
        assert!(scope.pending.is_none());
        let evidence = read_membership_transition_evidence_sync(
            &conn,
            storage_identity,
            transition_id,
            transition_digest,
        )
        .expect("read abort evidence")
        .expect("abort evidence");
        assert_eq!(Some(TerminalMembershipOutcome::Aborted), evidence.outcome);
        assert_eq!(None, evidence.joint_membership_log_index);
        assert_eq!(None, evidence.uniform_membership_log_index);
        assert_eq!(None, evidence.cutover_log_index);
    }

    #[tokio::test]
    async fn committed_joint_membership_cannot_be_relabelled_as_aborted() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let storage_identity = identity();
        let current = members(&[7, 8, 9]);
        let desired = members(&[8, 9, 10]);
        let desired_identity = identity_at(2, 0x63);
        let transition_id = [0x43; MEMBERSHIP_TRANSITION_ID_BYTES];
        let transition_digest = [0x44; 32];
        initialize_schema(&conn, storage_identity, &current).expect("initialize scope");
        let initial = membership_entry_at(0, vec![current.clone()], current.clone());
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&initial))
            .expect("append current membership");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![initial])
            .expect("apply current membership");
        stage_membership_scope_sync(
            &conn,
            storage_identity,
            transition_id,
            transition_digest,
            desired_identity,
            &desired,
        )
        .expect("stage transition");
        let union = current.union(&desired).copied().collect::<BTreeSet<_>>();
        let learners = membership_entry_at(1, vec![current.clone()], union.clone());
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&learners))
            .expect("append learners");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![learners])
            .expect("apply learners");
        let ready = topology_entry_at(
            2,
            0x84,
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id,
                request_digest: transition_digest,
            },
        );
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&ready))
            .expect("append readiness");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![ready])
            .expect("apply readiness");
        fence_application_authority_sync(&conn, storage_identity, transition_id, transition_digest)
            .expect("fence authority");

        let joint = membership_entry_at(3, vec![current.clone(), desired.clone()], union);
        let restored = membership_entry_at(4, vec![current.clone()], current.clone());
        append_logs_sync(&conn, storage_identity, &[joint.clone(), restored.clone()])
            .expect("append committed joint and later uniform membership");
        apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![joint, restored],
        )
        .expect("apply committed membership history");

        assert_eq!(
            MembershipScopeMutationError::TransitionNotQuiescent,
            abort_membership_scope_sync(&conn, storage_identity, transition_id, transition_digest,)
                .expect_err("committed joint state is an irreversible transition boundary")
        );
        let evidence = read_membership_transition_evidence_sync(
            &conn,
            storage_identity,
            transition_id,
            transition_digest,
        )
        .expect("read transition evidence")
        .expect("pending transition evidence");
        assert_eq!(None, evidence.outcome);
        assert_eq!(Some(3), evidence.joint_membership_log_index);
    }

    #[tokio::test]
    async fn candidate_accepts_only_forward_snapshot_progress_for_exact_successor() {
        let directory = tempfile::tempdir().expect("directory");
        let source_database = directory.path().join("source.sqlite");
        let snapshot_path = directory.path().join("membership-snapshot.sqlite");
        let storage_identity = identity();
        let current = members(&[7, 8, 9]);
        let desired = members(&[7, 8, 9, 10, 11]);
        let desired_bindings = test_member_bindings(&desired);
        let desired_identity = identity_at(2, 0x72);
        let transition_id = [0x51; MEMBERSHIP_TRANSITION_ID_BYTES];
        let transition_digest = [0x52; 32];
        let pending = PendingMembershipBootstrap {
            transition_id,
            transition_digest,
            desired_identity,
            desired_members: &desired,
            desired_bindings: &desired_bindings,
        };

        let source = SqliteSessionBackend::open(&source_database).expect("source backend");
        {
            let conn = source.conn.lock().await;
            assert_eq!(
                storage_identity,
                initialize_schema(&conn, storage_identity, &current)
                    .expect("initialize source scope")
            );
            let initial = membership_entry_at(0, vec![current.clone()], current.clone());
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&initial))
                .expect("append source membership");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![initial])
                .expect("apply source membership");
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                transition_id,
                transition_digest,
                desired_identity,
                &desired,
            )
            .expect("stage source transition after existing history");
            let learners = membership_entry_at(1, vec![current.clone()], desired.clone());
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&learners))
                .expect("append source learners");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![learners])
                .expect("apply source learners");
            let ready = topology_entry_at(
                2,
                0x85,
                SessionMutationIntent::MarkTopologyLearnersReady {
                    transition_id,
                    request_digest: transition_digest,
                },
            );
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&ready))
                .expect("append source readiness");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![ready])
                .expect("apply source readiness");
            fence_application_authority_sync(
                &conn,
                storage_identity,
                transition_id,
                transition_digest,
            )
            .expect("fence source authority");
            let joint =
                membership_entry_at(3, vec![current.clone(), desired.clone()], desired.clone());
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&joint))
                .expect("append source joint membership");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![joint])
                .expect("apply source joint membership");
        }
        drop(source);

        let reopened = SqliteSessionBackend::open(&source_database).expect("reopened backend");
        let (last_log_id, last_membership) = {
            let conn = reopened.conn.lock().await;
            assert_eq!(
                storage_identity,
                initialize_schema_with_pending(&conn, storage_identity, &current, Some(pending),)
                    .expect("restart exact pending scope")
            );
            assert_eq!(
                Some(MembershipTransitionEvidence {
                    outcome: None,
                    transition_start_log_index: 1,
                    learners_ready_log_index: Some(2),
                    joint_membership_log_index: Some(3),
                    uniform_membership_log_index: None,
                    cutover_log_index: None,
                    finalization_log_index: None,
                }),
                read_membership_transition_evidence_sync(
                    &conn,
                    storage_identity,
                    transition_id,
                    transition_digest,
                )
                .expect("read restarted transition")
            );
            build_snapshot_database_sync(&conn, storage_identity, &snapshot_path)
                .expect("build pending-scope snapshot")
        };
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "exact-pending-scope".into(),
        };
        let byte_length = std::fs::metadata(&snapshot_path)
            .expect("snapshot metadata")
            .len();

        let exact_target = SqliteSessionBackend::in_memory().expect("exact target");
        {
            let conn = exact_target.conn.lock().await;
            initialize_schema_with_storage_anchor_and_pending(
                &conn,
                Some(storage_identity),
                storage_identity,
                &current,
                Some(pending),
            )
            .expect("initialize exact target scope");
            assert_eq!(
                0,
                read_membership_scope_sync(&conn, storage_identity)
                    .expect("candidate scope")
                    .pending
                    .expect("candidate transition")
                    .transition_start_log_index,
                "a pristine candidate cannot invent the source prepare index"
            );
            install_snapshot_database_sync(
                &conn,
                storage_identity,
                &snapshot_path,
                &meta,
                "exact-pending-scope.opc",
                [0x81; 32],
                byte_length,
            )
            .expect("install exact pending-scope snapshot");
            let scope = read_membership_scope_sync(&conn, storage_identity)
                .expect("read installed exact scope");
            assert_eq!(
                desired_identity,
                scope.pending.as_ref().expect("pending").desired_identity
            );
            assert_eq!(
                Some(3),
                scope
                    .pending
                    .as_ref()
                    .expect("pending")
                    .joint_membership_log_index
            );
            assert_eq!(
                desired_identity.configuration_epoch(),
                scope.application_authority_epoch
            );
        }

        let other_desired = members(&[7, 8, 9, 10, 12]);
        let other_desired_bindings = test_member_bindings(&other_desired);
        let conflicting_target = SqliteSessionBackend::in_memory().expect("conflicting target");
        {
            let conn = conflicting_target.conn.lock().await;
            initialize_schema_with_pending(
                &conn,
                storage_identity,
                &current,
                Some(PendingMembershipBootstrap {
                    transition_id: [0x61; MEMBERSHIP_TRANSITION_ID_BYTES],
                    transition_digest: [0x62; 32],
                    desired_identity: identity_at(2, 0x73),
                    desired_members: &other_desired,
                    desired_bindings: &other_desired_bindings,
                }),
            )
            .expect("initialize conflicting target scope");
            let error = install_snapshot_database_sync(
                &conn,
                storage_identity,
                &snapshot_path,
                &meta,
                "conflicting-pending-scope.opc",
                [0x82; 32],
                byte_length,
            )
            .expect_err("snapshot for another exact successor must reject");
            assert_eq!(io::ErrorKind::InvalidData, error.kind());
        }
    }

    #[tokio::test]
    async fn epoch_two_candidate_preserves_genesis_anchor_and_installs_source_snapshot() {
        let directory = tempfile::tempdir().expect("directory");
        let source_database = directory.path().join("late-source.sqlite");
        let compaction_path = directory.path().join("late-compaction.sqlite");
        let snapshot_path = directory.path().join("late-source-snapshot.sqlite");
        let source = SqliteSessionBackend::open(&source_database).expect("source backend");
        let storage_identity = identity();
        let first_members = members(&[7, 8, 9]);
        let current_members = members(&[7, 8, 9, 10, 11]);
        let desired_members = members(&[8, 9, 11]);
        let current_identity = identity_at(2, 0x75);
        let desired_identity = identity_at(3, 0x76);
        let first_id = [0x71; MEMBERSHIP_TRANSITION_ID_BYTES];
        let first_digest = [0x72; 32];
        let second_id = [0x73; MEMBERSHIP_TRANSITION_ID_BYTES];
        let second_digest = [0x74; 32];

        let (snapshot_last_log, snapshot_membership) = {
            let conn = source.conn.lock().await;
            initialize_schema(&conn, storage_identity, &first_members).expect("initialize source");
            let initial =
                membership_entry_at(0, vec![first_members.clone()], first_members.clone());
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&initial))
                .expect("append initial membership");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![initial])
                .expect("apply initial membership");
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                first_id,
                first_digest,
                current_identity,
                &current_members,
            )
            .expect("stage first transition");
            let learners =
                membership_entry_at(1, vec![first_members.clone()], current_members.clone());
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&learners))
                .expect("append first learners");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![learners])
                .expect("apply first learners");
            let ready = topology_entry_at(
                2,
                0x86,
                SessionMutationIntent::MarkTopologyLearnersReady {
                    transition_id: first_id,
                    request_digest: first_digest,
                },
            );
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&ready))
                .expect("append first readiness");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![ready])
                .expect("apply first readiness");
            fence_application_authority_sync(&conn, storage_identity, first_id, first_digest)
                .expect("fence first transition");
            let joint = membership_entry_at(
                3,
                vec![first_members.clone(), current_members.clone()],
                current_members.clone(),
            );
            let uniform =
                membership_entry_at(4, vec![current_members.clone()], current_members.clone());
            append_logs_sync(&conn, storage_identity, &[joint.clone(), uniform.clone()])
                .expect("append first transition");
            save_committed_sync(&conn, storage_identity, Some(uniform.log_id))
                .expect("commit first transition");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![joint, uniform])
                .expect("promote first transition");

            let (compacted_log, compacted_membership) =
                build_snapshot_database_sync(&conn, storage_identity, &compaction_path)
                    .expect("build compaction snapshot");
            let compaction_meta = opc_consensus::engine::SnapshotMeta {
                last_log_id: compacted_log,
                last_membership: compacted_membership,
                snapshot_id: "late-candidate-compaction".into(),
            };
            save_current_snapshot_sync(
                &conn,
                storage_identity,
                &compaction_meta,
                "late-candidate-compaction.opc",
                [0x75; 32],
                1,
            )
            .expect("record compaction snapshot");
            purge_logs_sync(&conn, storage_identity, &log_id(4)).expect("purge first history");
            drop_compacted_membership_predecessor_sync(&conn, storage_identity)
                .expect("drop first predecessor");

            stage_membership_scope_sync(
                &conn,
                storage_identity,
                second_id,
                second_digest,
                desired_identity,
                &desired_members,
            )
            .expect("stage successor from epoch two");
            let transition_floor = blank_entry(5);
            append_logs_sync(
                &conn,
                storage_identity,
                std::slice::from_ref(&transition_floor),
            )
            .expect("append successor floor");
            apply_entries_sync(
                &conn,
                storage_identity,
                &source.caps,
                vec![transition_floor],
            )
            .expect("apply successor floor");
            let ready = topology_entry_at(
                6,
                0x87,
                SessionMutationIntent::MarkTopologyLearnersReady {
                    transition_id: second_id,
                    request_digest: second_digest,
                },
            );
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&ready))
                .expect("append successor readiness");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![ready])
                .expect("apply successor readiness");
            fence_application_authority_sync(&conn, storage_identity, second_id, second_digest)
                .expect("fence successor authority");
            build_snapshot_database_sync(&conn, storage_identity, &snapshot_path)
                .expect("build epoch-two source snapshot")
        };
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: snapshot_last_log,
            last_membership: snapshot_membership,
            snapshot_id: "late-candidate-source".into(),
        };
        let byte_length = std::fs::metadata(&snapshot_path)
            .expect("snapshot metadata")
            .len();

        let candidate = SqliteSessionBackend::in_memory().expect("candidate");
        let conn = candidate.conn.lock().await;
        let desired_bindings = test_member_bindings(&desired_members);
        initialize_schema_with_storage_anchor_and_pending(
            &conn,
            Some(storage_identity),
            current_identity,
            &current_members,
            Some(PendingMembershipBootstrap {
                transition_id: second_id,
                transition_digest: second_digest,
                desired_identity,
                desired_members: &desired_members,
                desired_bindings: &desired_bindings,
            }),
        )
        .expect("initialize late candidate with separate immutable anchor");
        assert_eq!(
            storage_identity,
            read_storage_identity_sync(&conn).expect("candidate anchor")
        );
        install_snapshot_database_sync(
            &conn,
            storage_identity,
            &snapshot_path,
            &meta,
            "late-candidate-source.opc",
            [0x76; 32],
            byte_length,
        )
        .expect("install exact epoch-two transition snapshot");
        let scope = read_membership_scope_sync(&conn, storage_identity).expect("installed scope");
        assert_eq!(current_identity, scope.current_identity);
        assert_eq!(
            desired_identity,
            scope.pending.expect("pending successor").desired_identity
        );
    }

    #[tokio::test]
    async fn membership_scope_accepts_zero_transition_bytes_and_rejects_corrupt_epoch() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let storage_identity = identity();
        let current = members(&[7, 8, 9]);
        let desired = members(&[7, 8, 9, 10, 11]);
        initialize_schema(&conn, storage_identity, &current).expect("initialize scope");
        stage_membership_scope_sync(
            &conn,
            storage_identity,
            [0; MEMBERSHIP_TRANSITION_ID_BYTES],
            [0; 32],
            identity_at(2, 0x74),
            &desired,
        )
        .expect("fixed-width all-zero values are valid exact identifiers");
        assert!(read_membership_transition_evidence_sync(
            &conn,
            storage_identity,
            [0; MEMBERSHIP_TRANSITION_ID_BYTES],
            [0; 32],
        )
        .expect("read exact all-zero identifiers")
        .is_some());
        conn.execute_batch("PRAGMA ignore_check_constraints = ON")
            .expect("allow corrupt fixture");
        conn.execute(
            "UPDATE consensus_membership_scope SET desired_configuration_epoch = 99",
            [],
        )
        .expect("inject invalid successor epoch");
        let error = read_membership_scope_sync(&conn, storage_identity)
            .expect_err("invented successor epoch must fail closed");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert_eq!(
            "session consensus pending membership scope is inconsistent",
            error.to_string()
        );
    }

    #[tokio::test]
    async fn reopening_rejects_mismatched_persisted_membership() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let expected = expected_members();
        initialize_schema(&conn, identity, &expected).expect("consensus schema");
        let unexpected = stored_membership(
            vec![BTreeSet::from([member(8)])],
            BTreeSet::from([member(8)]),
        );
        conn.execute(
            "UPDATE consensus_membership SET membership_json = ?1 WHERE singleton = 1",
            [encode_json(&unexpected).expect("membership encoding")],
        )
        .expect("inject persisted mismatch");
        assert_eq!(
            SessionConsensusStorageError::CorruptState,
            initialize_schema(&conn, identity, &expected)
                .expect_err("mismatched persisted membership must reject startup")
        );
    }

    #[tokio::test]
    async fn snapshot_metadata_mismatch_is_rejected_before_persistence() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let expected = expected_members();
        initialize_schema(&conn, identity, &expected).expect("consensus schema");
        let unexpected = stored_membership(
            vec![BTreeSet::from([member(8)])],
            BTreeSet::from([member(8)]),
        );
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: Some(log_id(0)),
            last_membership: unexpected,
            snapshot_id: "mismatched-membership".into(),
        };
        assert!(
            save_current_snapshot_sync(&conn, identity, &meta, "snapshot.opc", [0; 32], 1,)
                .is_err()
        );
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM consensus_snapshot", [], |row| {
                row.get(0)
            })
            .expect("snapshot count");
        assert_eq!(0, count);
    }

    #[tokio::test]
    async fn installed_snapshot_invalidates_source_cursor_and_first_page_restarts() {
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.lock().await;
        let identity = identity();
        let expected = expected_members();
        initialize_schema(&source_conn, identity, &expected).expect("source consensus schema");
        apply_entries_sync(
            &source_conn,
            identity,
            &source.caps,
            vec![membership_entry()],
        )
        .expect("apply admitted membership");
        let (source_epoch, source_revision, source_cursor_key) =
            ops::read_restore_scan_state_sync(&source_conn).expect("source cursor state");
        let scope = RestoreScanScope::all();
        let source_cursor = RestoreScanCursor::durable(
            &source_cursor_key,
            source_epoch,
            source_revision,
            timestamp(0),
            &scope,
            &key(),
            1,
        )
        .expect("source cursor");

        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("installed.sqlite");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity, &snapshot_path)
                .expect("build snapshot");
        drop(source_conn);
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "restore-cursor-incarnation".to_string(),
        };

        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.lock().await;
        initialize_schema(&target_conn, identity, &expected).expect("target consensus schema");
        let byte_length = std::fs::metadata(&snapshot_path)
            .expect("snapshot metadata")
            .len();
        install_snapshot_database_sync(
            &target_conn,
            identity,
            &snapshot_path,
            &meta,
            "installed.opc",
            [0x5a; 32],
            byte_length,
        )
        .expect("install snapshot");

        let stale = ops::scan_restore_records_sync(
            &target_conn,
            RestoreScanRequest {
                scope: scope.clone(),
                cursor: Some(source_cursor),
                limit: 1,
            },
            timestamp(1),
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now() + Duration::from_secs(5),
            false,
        )
        .expect_err("snapshot install creates a new cursor incarnation");
        assert_eq!(stale, StoreError::RestoreScanCursorStale);
        let first_page = ops::scan_restore_records_sync(
            &target_conn,
            RestoreScanRequest {
                scope,
                cursor: None,
                limit: 1,
            },
            timestamp(1),
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now() + Duration::from_secs(5),
            false,
        )
        .expect("restart from first page");
        assert!(first_page.complete);
        assert!(first_page.records.is_empty());

        let (target_epoch, target_revision, target_cursor_key) =
            ops::read_restore_scan_state_sync(&target_conn).expect("target cursor state");
        let target_cursor = RestoreScanCursor::durable(
            &target_cursor_key,
            target_epoch,
            target_revision,
            timestamp(1),
            &RestoreScanScope::all(),
            &key(),
            1,
        )
        .expect("target-local cursor");

        let second_target = SqliteSessionBackend::in_memory().expect("second target backend");
        let second_target_conn = second_target.conn.lock().await;
        initialize_schema(&second_target_conn, identity, &expected)
            .expect("second target consensus schema");
        install_snapshot_database_sync(
            &second_target_conn,
            identity,
            &snapshot_path,
            &meta,
            "installed-second.opc",
            [0x6b; 32],
            byte_length,
        )
        .expect("install same snapshot on second target");
        let (second_epoch, _, second_cursor_key) =
            ops::read_restore_scan_state_sync(&second_target_conn)
                .expect("second-target cursor state");
        assert_ne!(target_epoch, second_epoch);
        assert_ne!(*target_cursor_key, *second_cursor_key);
        let cross_node = ops::scan_restore_records_sync(
            &second_target_conn,
            RestoreScanRequest {
                scope: RestoreScanScope::all(),
                cursor: Some(target_cursor),
                limit: 1,
            },
            timestamp(1),
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now() + Duration::from_secs(5),
            false,
        )
        .expect_err("same snapshot still yields node-local cursor incarnations");
        assert_eq!(cross_node, StoreError::RestoreScanCursorStale);
    }

    #[tokio::test]
    async fn node_local_intent_fault_aborts_apply_without_advancing_state() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let expected_members = expected_members();
        initialize_schema(&conn, identity, &expected_members).expect("consensus schema");

        apply_entries_sync(&conn, identity, &backend.caps, vec![membership_entry()])
            .expect("initial membership entry");
        let baseline_applied = read_applied_sync(&conn, identity).expect("baseline applied");
        let baseline_machine = proposal_state_sync(&conn, identity).expect("baseline machine");
        let baseline_globals: Vec<(String, i64)> = conn
            .prepare("SELECT key, val FROM lease_globals ORDER BY key")
            .expect("prepare globals")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query globals")
            .collect::<rusqlite::Result<_>>()
            .expect("collect globals");

        // Fail after acquire has updated both lease-global allocators. The
        // trigger text is deliberately sensitive-looking so the assertion also
        // proves that the state-machine storage error remains coarse.
        conn.execute_batch(
            r#"
            CREATE TRIGGER fail_consensus_lease_insert
            BEFORE INSERT ON leases
            BEGIN
                SELECT RAISE(ABORT, 'node-local-secret-canary');
            END;
            "#,
        )
        .expect("install local SQLite fault");

        let request_id = [0xA5; 16];
        let error = apply_entries_sync(
            &conn,
            identity,
            &backend.caps,
            vec![acquire_entry(1, request_id, "fault-owner")],
        )
        .expect_err("node-local SQLite fault must fail Openraft apply");
        assert_eq!(io::ErrorKind::Other, error.kind());
        assert_eq!(
            "session consensus state-machine operation failed",
            error.to_string()
        );
        assert!(!error.to_string().contains("node-local-secret-canary"));

        assert_eq!(
            baseline_applied,
            read_applied_sync(&conn, identity).expect("applied after fault")
        );
        assert_eq!(
            baseline_machine,
            proposal_state_sync(&conn, identity).expect("machine after fault")
        );
        assert!(read_outcome_sync(
            &conn,
            identity,
            SessionConsensusRequestId::from_bytes(request_id)
        )
        .expect("outcome lookup")
        .is_none());
        for table in ["leases", "key_fences", "session_replication_log"] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("table count");
            assert_eq!(0, count, "{table} must remain unchanged");
        }
        let globals: Vec<(String, i64)> = conn
            .prepare("SELECT key, val FROM lease_globals ORDER BY key")
            .expect("prepare globals")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query globals")
            .collect::<rusqlite::Result<_>>()
            .expect("collect globals");
        assert_eq!(baseline_globals, globals);

        conn.execute("DROP TRIGGER fail_consensus_lease_insert", [])
            .expect("remove local fault");
        let recovered = apply_entries_sync(
            &conn,
            identity,
            &backend.caps,
            vec![acquire_entry(1, request_id, "fault-owner")],
        )
        .expect("same entry applies after local storage recovery");
        assert!(matches!(
            recovered.responses.as_slice(),
            [SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::Lease(_)),
                sequence: 1,
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn deterministic_lease_rejection_commits_as_an_outcome() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let expected_members = expected_members();
        initialize_schema(&conn, identity, &expected_members).expect("consensus schema");

        let rejected_id = [0xB2; 16];
        let applied = apply_entries_sync(
            &conn,
            identity,
            &backend.caps,
            vec![
                membership_entry(),
                acquire_entry(1, [0xB1; 16], "current-owner"),
                acquire_entry(2, rejected_id, "other-owner"),
            ],
        )
        .expect("deterministic rejection remains a committed response");

        assert!(matches!(
            applied.responses.as_slice(),
            [
                SessionConsensusResponse { result: Ok(_), .. },
                SessionConsensusResponse {
                    result: Ok(SessionMutationOutcome::Lease(_)),
                    sequence: 1,
                    ..
                },
                SessionConsensusResponse {
                    result: Err(StoreError::LeaseHeld),
                    sequence: 2,
                    ..
                }
            ]
        ));
        assert_eq!(Some(log_id(2)), read_applied_sync(&conn, identity).unwrap());
        assert_eq!(
            2,
            proposal_state_sync(&conn, identity)
                .expect("machine state")
                .0
        );
        assert!(matches!(
            read_outcome_sync(
                &conn,
                identity,
                SessionConsensusRequestId::from_bytes(rejected_id)
            )
            .expect("rejected outcome")
            .map(|(_, response)| response.result),
            Some(Err(StoreError::LeaseHeld))
        ));
    }
}
