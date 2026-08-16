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
use std::sync::Arc;

use opc_consensus::engine::{Entry, EntryPayload, LogId, Membership, StoredMembership, Vote};
use opc_consensus::{AppendEntriesBatchAccumulator, AppendEntriesBatchDecision};
use opc_types::Timestamp;
#[cfg(target_os = "linux")]
use rusqlite::OpenFlags;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::backend::{
    CompareAndSetResult, ReplicationEntry, ReplicationOp, ReplicationTxId,
    REPLICATION_TX_ID_MAX_BYTES, REPLICATION_TX_ID_MIN_BYTES,
};
use crate::capability::BackendCapabilities;
use crate::consensus::storage::{ConsensusAuthorityProfile, SessionConsensusStorageError};
use crate::consensus::types::{
    DurableSessionConsensusCommand, SessionConsensusCommand, SessionConsensusConfigurationEpoch,
    SessionConsensusConfigurationId, SessionConsensusEntryDigest, SessionConsensusIdentity,
    SessionConsensusNodeId, SessionConsensusRequestId, SessionConsensusResponse,
    SessionMutationIntent, SessionMutationOutcome, SessionTopologyMemberBinding,
    SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_CURRENT,
    SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY, SESSION_CONSENSUS_SCHEMA_VERSION,
};
use crate::consensus::SessionRaftTypeConfig;
use crate::error::{LeaseError, StoreError};
use crate::readiness::PlacementResiliencePolicy;
use crate::record::SessionPayloadEncoding;

#[cfg(test)]
use super::RestoreScanValidationProfile;
use super::{lease, ops, SqliteProvisionalProbeAdmission, SqliteSessionBackend};

const CONSENSUS_LOG_ENTRY_MAX_BYTES: usize = 16 * 1024 * 1024;
// The frozen base release admitted exactly one byte beyond its advertised
// consensus cap.  This is a retained-history exception, not a moving version
// of the live capability: keep both sides of the historic rejection explicit.
const BASE_ADMITTED_LEGACY_PAYLOAD_BYTES: usize = 1_048_577;
const BASE_ADVERTISED_LEGACY_PAYLOAD_MAX_BYTES: usize = 1_048_576;
const MEMBERSHIP_SCOPE_MEMBERS_MAX_BYTES: usize = 1_024;
const MEMBERSHIP_SCOPE_BINDINGS_MAX_BYTES: usize = 32 * 1_024;
const MEMBERSHIP_HISTORY_MAX_ENTRIES: usize = 4_096;
const MEMBERSHIP_TRANSITION_ID_BYTES: usize = 16;
const OUTCOME_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/outcome-payload/v1\0";
const OUTCOME_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/outcome-receipt/v2\0";
const OUTCOME_RECEIPT_VERSION: i64 = 2;
const OUTCOME_RECEIPT_CHAIN_GENESIS: [u8; 32] = [0; 32];
const COMMAND_ADMISSION_REVISION: i64 = 1;
const LEGACY_CONSENSUS_REQUEST_OUTCOMES_SCHEMA: &str = r#"CREATE TABLE consensus_request_outcomes (
    request_id BLOB PRIMARY KEY CHECK (length(request_id) = 16),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    response_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
)"#;
// The reviewed immediate predecessor predates the parallel receipt-chain
// head. Keep this DDL separate from the current machine table: recovery only
// accepts this exact frozen shape and must never manufacture receipt authority
// while classifying or converting it.
const IMMEDIATE_PREDECESSOR_CONSENSUS_MACHINE_SCHEMA: &str = r#"CREATE TABLE consensus_machine (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    application_sequence INTEGER NOT NULL CHECK (application_sequence >= 0),
    last_digest BLOB NOT NULL CHECK (length(last_digest) = 32),
    logical_time TEXT,
    watch_sequence INTEGER NOT NULL CHECK (watch_sequence >= 0),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
)"#;
// Receipt v2 was not released, but an in-progress authority image can carry
// this exact pre-receipt-chain manifest.  It is the only v2 shape that may be
// upgraded in place; accepting a merely similar collection of columns would
// turn an interrupted or foreign schema into a trusted recovery source.
const PRE_RECEIPT_CHAIN_CONSENSUS_REQUEST_OUTCOMES_SCHEMA: &str = r#"CREATE TABLE consensus_request_outcomes (
    request_id BLOB PRIMARY KEY CHECK (length(request_id) = 16),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    command_json BLOB NOT NULL CHECK (length(command_json) > 0),
    predecessor_sequence INTEGER NOT NULL CHECK (predecessor_sequence >= 0),
    predecessor_digest BLOB NOT NULL CHECK (length(predecessor_digest) = 32),
    predecessor_logical_time TEXT,
    raft_log_index INTEGER NOT NULL CHECK (raft_log_index >= 0),
    response_json BLOB NOT NULL,
    receipt_version INTEGER NOT NULL CHECK (receipt_version = 2),
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
)"#;
const RECEIPT_CHAIN_CONSENSUS_REQUEST_OUTCOMES_SCHEMA: &str = r#"CREATE TABLE consensus_request_outcomes (
    request_id BLOB PRIMARY KEY CHECK (length(request_id) = 16),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    command_json BLOB NOT NULL CHECK (length(command_json) > 0),
    predecessor_sequence INTEGER NOT NULL CHECK (predecessor_sequence >= 0),
    predecessor_digest BLOB NOT NULL CHECK (length(predecessor_digest) = 32),
    predecessor_logical_time TEXT,
    predecessor_receipt_digest BLOB NOT NULL CHECK (length(predecessor_receipt_digest) = 32),
    raft_log_index INTEGER NOT NULL CHECK (raft_log_index >= 0),
    response_json BLOB NOT NULL,
    receipt_version INTEGER NOT NULL CHECK (receipt_version = 2),
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);"#;
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

fn open_nofollow_read(path: &Path) -> io::Result<File> {
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
    let mut file = match open_nofollow_read(&path) {
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
    pub(crate) terminal_history: Vec<RetainedTerminalMembershipTransition>,
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
            .field("terminal_history_depth", &self.terminal_history.len())
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

/// Durable proof needed to retire learners after an abort decision.
///
/// The abort command is committed while the learners are still reachable, so
/// every learner can apply the same terminal decision. The exact learner set
/// is retained until a later committed cleanup step proves terminality: an
/// Openraft node-removal entry when learners exist, or the current-term cleanup
/// control entry when no learner was ever admitted.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AbortedMembershipCleanup {
    pub(crate) desired_identity: SessionConsensusIdentity,
    pub(crate) desired_members: BTreeSet<SessionConsensusNodeId>,
    pub(crate) desired_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    pub(crate) learners: BTreeSet<SessionConsensusNodeId>,
    pub(crate) decision_log_index: u64,
    pub(crate) cleanup_log_index: Option<u64>,
}

impl fmt::Debug for AbortedMembershipCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AbortedMembershipCleanup")
            .field(
                "desired_epoch",
                &self.desired_identity.configuration_epoch(),
            )
            .field("desired_member_count", &self.desired_members.len())
            .field("desired_binding_count", &self.desired_bindings.len())
            .field("learner_count", &self.learners.len())
            .field("decision_log_index", &self.decision_log_index)
            .field("cleanup_log_index", &self.cleanup_log_index)
            .finish()
    }
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
    pub(crate) abort_cleanup: Option<AbortedMembershipCleanup>,
}

/// Complete terminal transition evidence retained after the singleton
/// terminal slot advances to a later transition.
///
/// Unlike membership lineage, this record covers both promoted and aborted
/// outcomes and retains every index needed to answer an exact idempotent
/// status lookup after restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetainedTerminalMembershipTransition {
    pub(crate) transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    pub(crate) transition_digest: [u8; 32],
    pub(crate) outcome: TerminalMembershipOutcome,
    pub(crate) expected_member_count: usize,
    pub(crate) transition_start_log_index: u64,
    pub(crate) learners_ready_log_index: Option<u64>,
    pub(crate) joint_membership_log_index: Option<u64>,
    pub(crate) uniform_membership_log_index: Option<u64>,
    pub(crate) cutover_log_index: Option<u64>,
    pub(crate) finalization_log_index: Option<u64>,
    pub(crate) abort_decision_log_index: Option<u64>,
    pub(crate) abort_cleanup_log_index: Option<u64>,
}

impl RetainedTerminalMembershipTransition {
    fn evidence(self) -> MembershipTransitionEvidence {
        MembershipTransitionEvidence {
            outcome: Some(self.outcome),
            transition_start_log_index: self.transition_start_log_index,
            learners_ready_log_index: self.learners_ready_log_index,
            joint_membership_log_index: self.joint_membership_log_index,
            uniform_membership_log_index: self.uniform_membership_log_index,
            cutover_log_index: self.cutover_log_index,
            finalization_log_index: self.finalization_log_index,
            abort_decision_log_index: self.abort_decision_log_index,
            abort_cleanup_log_index: self.abort_cleanup_log_index,
        }
    }
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
            .field("abort_cleanup", &self.abort_cleanup)
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
    pub(crate) abort_decision_log_index: Option<u64>,
    pub(crate) abort_cleanup_log_index: Option<u64>,
}

fn retained_transition_digest(
    scope: &MembershipValidationScope,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
) -> io::Result<Option<[u8; 32]>> {
    let mut retained = None;
    for (candidate_id, candidate_digest) in scope
        .terminal
        .iter()
        .map(|terminal| (terminal.transition_id, terminal.transition_digest))
        .chain(
            scope
                .terminal_history
                .iter()
                .map(|terminal| (terminal.transition_id, terminal.transition_digest)),
        )
        .chain(
            scope
                .predecessor
                .iter()
                .map(|predecessor| (predecessor.transition_id, predecessor.transition_digest)),
        )
        .chain(
            scope
                .history
                .iter()
                .map(|predecessor| (predecessor.transition_id, predecessor.transition_digest)),
        )
    {
        if candidate_id != transition_id {
            continue;
        }
        if retained.is_some_and(|digest| digest != candidate_digest) {
            return Err(invalid_data(
                "session consensus transition ID history conflicts",
            ));
        }
        retained = Some(candidate_digest);
    }
    Ok(retained)
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

#[cfg(test)]
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
    configuration_epoch INTEGER NOT NULL UNIQUE CHECK (configuration_epoch > 0),
    authority_profile INTEGER NOT NULL DEFAULT 1 CHECK (authority_profile IN (1, 2)),
    fixed_placement_policy INTEGER CHECK (fixed_placement_policy IN (1, 2))
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
    terminal_desired_configuration_id BLOB CHECK (
        terminal_desired_configuration_id IS NULL
        OR length(terminal_desired_configuration_id) = 32
    ),
    terminal_desired_configuration_epoch INTEGER,
    terminal_desired_members_json BLOB CHECK (
        terminal_desired_members_json IS NULL
        OR length(terminal_desired_members_json) BETWEEN 2 AND 1024
    ),
    terminal_desired_bindings_json BLOB CHECK (
        terminal_desired_bindings_json IS NULL
        OR length(terminal_desired_bindings_json) BETWEEN 2 AND 32768
    ),
    terminal_abort_learners_json BLOB CHECK (
        terminal_abort_learners_json IS NULL
        OR length(terminal_abort_learners_json) BETWEEN 2 AND 1024
    ),
    terminal_abort_decision_index INTEGER CHECK (
        terminal_abort_decision_index IS NULL OR terminal_abort_decision_index >= 0
    ),
    terminal_abort_cleanup_membership_index INTEGER CHECK (
        terminal_abort_cleanup_membership_index IS NULL
        OR terminal_abort_cleanup_membership_index >= 0
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
         AND terminal_finalization_index IS NULL
         AND terminal_desired_configuration_id IS NULL
         AND terminal_desired_configuration_epoch IS NULL
         AND terminal_desired_members_json IS NULL
         AND terminal_desired_bindings_json IS NULL
         AND terminal_abort_learners_json IS NULL
         AND terminal_abort_decision_index IS NULL
         AND terminal_abort_cleanup_membership_index IS NULL)
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
               AND terminal_finalization_index IS NULL
               AND terminal_desired_configuration_id IS NOT NULL
               AND terminal_desired_configuration_epoch = current_configuration_epoch + 1
               AND terminal_desired_members_json IS NOT NULL
               AND terminal_desired_bindings_json IS NOT NULL
               AND terminal_abort_learners_json IS NOT NULL
               AND terminal_abort_decision_index IS NOT NULL
               AND terminal_abort_decision_index > terminal_transition_start_index
               AND (terminal_learners_ready_index IS NULL
                    OR terminal_abort_decision_index > terminal_learners_ready_index)
               AND (terminal_abort_cleanup_membership_index IS NULL
                    OR terminal_abort_cleanup_membership_index > terminal_abort_decision_index))
              OR (terminal_transition_outcome = 2
                  AND terminal_uniform_membership_index IS NOT NULL
                  AND terminal_cutover_index IS NOT NULL
                  AND terminal_cutover_index >= terminal_uniform_membership_index
                  AND (terminal_finalization_index IS NULL
                       OR terminal_finalization_index > terminal_cutover_index)
                  AND terminal_desired_configuration_id IS NULL
                  AND terminal_desired_configuration_epoch IS NULL
                  AND terminal_desired_members_json IS NULL
                  AND terminal_desired_bindings_json IS NULL
                  AND terminal_abort_learners_json IS NULL
                  AND terminal_abort_decision_index IS NULL
                  AND terminal_abort_cleanup_membership_index IS NULL)))
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

CREATE TABLE consensus_membership_terminal_history (
    transition_id BLOB PRIMARY KEY CHECK (length(transition_id) = 16),
    storage_configuration_epoch INTEGER NOT NULL CHECK (storage_configuration_epoch > 0),
    transition_digest BLOB NOT NULL CHECK (length(transition_digest) = 32),
    outcome INTEGER NOT NULL CHECK (outcome IN (1, 2)),
    expected_member_count INTEGER NOT NULL CHECK (expected_member_count > 0),
    transition_start_index INTEGER NOT NULL CHECK (transition_start_index >= 0),
    learners_ready_index INTEGER CHECK (
        learners_ready_index IS NULL OR learners_ready_index > transition_start_index
    ),
    joint_membership_index INTEGER CHECK (
        joint_membership_index IS NULL
        OR (learners_ready_index IS NOT NULL
            AND joint_membership_index > learners_ready_index)
    ),
    uniform_membership_index INTEGER CHECK (
        uniform_membership_index IS NULL
        OR (joint_membership_index IS NOT NULL
            AND uniform_membership_index > joint_membership_index)
    ),
    cutover_index INTEGER CHECK (
        cutover_index IS NULL
        OR (uniform_membership_index IS NOT NULL
            AND cutover_index >= uniform_membership_index)
    ),
    finalization_index INTEGER CHECK (
        finalization_index IS NULL
        OR (cutover_index IS NOT NULL AND finalization_index > cutover_index)
    ),
    abort_decision_index INTEGER CHECK (
        abort_decision_index IS NULL OR abort_decision_index > transition_start_index
    ),
    abort_cleanup_membership_index INTEGER CHECK (
        abort_cleanup_membership_index IS NULL
        OR (abort_decision_index IS NOT NULL
            AND abort_cleanup_membership_index > abort_decision_index)
    ),
    CHECK (
        (outcome = 1
         AND joint_membership_index IS NULL
         AND uniform_membership_index IS NULL
         AND cutover_index IS NULL
         AND finalization_index IS NULL
         AND abort_decision_index IS NOT NULL
         AND abort_cleanup_membership_index IS NOT NULL)
        OR
        (outcome = 2
         AND joint_membership_index IS NOT NULL
         AND uniform_membership_index IS NOT NULL
         AND cutover_index IS NOT NULL
         AND finalization_index IS NOT NULL
         AND abort_decision_index IS NULL
         AND abort_cleanup_membership_index IS NULL)
    ),
    FOREIGN KEY(storage_configuration_epoch)
        REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_candidate_bootstrap (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    storage_configuration_epoch INTEGER NOT NULL CHECK (storage_configuration_epoch > 0),
    local_candidate_node_id INTEGER NOT NULL CHECK (local_candidate_node_id > 0),
    transition_id BLOB NOT NULL CHECK (length(transition_id) = 16),
    transition_digest BLOB NOT NULL CHECK (length(transition_digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
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
    last_receipt_digest BLOB NOT NULL CHECK (length(last_receipt_digest) = 32),
    logical_time TEXT,
    watch_sequence INTEGER NOT NULL CHECK (watch_sequence >= 0),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_request_outcomes (
    request_id BLOB PRIMARY KEY CHECK (length(request_id) = 16),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    command_json BLOB NOT NULL CHECK (length(command_json) > 0),
    predecessor_sequence INTEGER NOT NULL CHECK (predecessor_sequence >= 0),
    predecessor_digest BLOB NOT NULL CHECK (length(predecessor_digest) = 32),
    predecessor_logical_time TEXT,
    predecessor_receipt_digest BLOB NOT NULL CHECK (length(predecessor_receipt_digest) = 32),
    raft_log_index INTEGER NOT NULL CHECK (raft_log_index >= 0),
    response_json BLOB NOT NULL,
    receipt_version INTEGER NOT NULL CHECK (receipt_version = 2),
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_command_admission (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    admission_revision INTEGER NOT NULL CHECK (admission_revision = 1),
    strict_activation_index INTEGER NOT NULL CHECK (strict_activation_index >= 0),
    cutover_committed INTEGER NOT NULL CHECK (cutover_committed IN (0, 1)),
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
    pending_fence_high_water INTEGER CHECK (pending_fence_high_water >= 0),
    pending_credential_high_water INTEGER CHECK (pending_credential_high_water >= 0),
    watch_cursor_invalidation_floor INTEGER NOT NULL CHECK (watch_cursor_invalidation_floor >= 0),
    CHECK (
        (pending_epoch IS NULL AND pending_plan_digest IS NULL
            AND pending_fence_high_water IS NULL AND pending_credential_high_water IS NULL)
        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL
            AND pending_fence_high_water IS NOT NULL AND pending_credential_high_water IS NOT NULL)
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

/// Install the one reviewed predecessor manifest used by the recovery-only
/// upgrade path. It differs from the current schema by the absence of command
/// admission, the parallel receipt-chain machine head, and the four-column,
/// pre-receipt outcome table.
///
/// Recovery derives this from production DDL instead of carrying a second
/// hand-maintained table inventory.  Callers use it only on an otherwise
/// empty canonical schema connection when qualifying a stopped replica.
pub(crate) fn install_immediate_predecessor_recovery_validation_schema_sync(
    conn: &Connection,
) -> io::Result<()> {
    conn.execute_batch(CONSENSUS_SCHEMA).map_err(db_error)?;
    conn.execute_batch(
        "DROP TABLE consensus_command_admission;
         DROP TABLE consensus_operator_recovery;
         DROP TABLE consensus_request_outcomes;
         DROP TABLE consensus_machine;",
    )
    .map_err(db_error)?;
    conn.execute_batch(IMMEDIATE_PREDECESSOR_CONSENSUS_MACHINE_SCHEMA)
        .map_err(db_error)?;
    conn.execute_batch(PRE_HIGH_WATER_OPERATOR_RECOVERY_SCHEMA)
        .map_err(db_error)?;
    conn.execute_batch(LEGACY_CONSENSUS_REQUEST_OUTCOMES_SCHEMA)
        .map_err(db_error)
}

/// Convert a current test fixture into the exact reviewed predecessor layout.
/// Production recovery never calls this: its manifest oracle above always
/// starts from an empty canonical connection.
#[cfg(test)]
pub(crate) fn downgrade_to_immediate_predecessor_fixture_sync(conn: &Connection) -> io::Result<()> {
    let machine: (i64, i64, i64, Vec<u8>, Option<String>, i64) = conn
        .query_row(
            "SELECT singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence FROM consensus_machine WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(db_error)?;
    let recovery: StoredOperatorRecoveryRow = conn
        .query_row(
            "SELECT configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, pending_fence_high_water, pending_credential_high_water, watch_cursor_invalidation_floor FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .map_err(db_error)?;
    if recovery.5.is_some() || recovery.6.is_some() {
        return Err(invalid_data(
            "a pending current recovery authority cannot model the immediate predecessor",
        ));
    }
    conn.execute_batch(
        "DROP TABLE consensus_command_admission;
         DROP TABLE consensus_operator_recovery;
         DROP TABLE consensus_request_outcomes;
         DROP TABLE consensus_machine;",
    )
    .map_err(db_error)?;
    conn.execute_batch(IMMEDIATE_PREDECESSOR_CONSENSUS_MACHINE_SCHEMA)
        .map_err(db_error)?;
    conn.execute(
        "INSERT INTO consensus_machine (singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![machine.0, machine.1, machine.2, machine.3, machine.4, machine.5],
    )
    .map_err(db_error)?;
    conn.execute_batch(PRE_HIGH_WATER_OPERATOR_RECOVERY_SCHEMA)
        .map_err(db_error)?;
    conn.execute(
        "INSERT INTO consensus_operator_recovery (singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![recovery.0, recovery.1, recovery.2, recovery.3, recovery.4, recovery.7],
    )
    .map_err(db_error)?;
    conn.execute_batch(LEGACY_CONSENSUS_REQUEST_OUTCOMES_SCHEMA)
        .map_err(db_error)
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
        .map_err(db_error)?;
    conn.execute_batch(OPERATOR_RECOVERY_HIGH_WATER_MIGRATION)
        .map_err(db_error)
}

/// Install the exact cursor-era recovery table, before pending high-waters
/// became part of the sealed operator-recovery authority.
pub(crate) fn install_cursor_migrated_operator_recovery_validation_schema_sync(
    conn: &Connection,
) -> io::Result<()> {
    conn.execute_batch(PRE_CURSOR_OPERATOR_RECOVERY_SCHEMA)
        .map_err(db_error)?;
    conn.execute_batch(OPERATOR_RECOVERY_CURSOR_MIGRATION)
        .map_err(db_error)
}

/// Install the exact direct-table layout produced by the immediately
/// preceding current schema.  It remains a recovery-only manifest oracle;
/// writable open migrates it at the reviewed high-water binding boundary.
pub(crate) fn install_pre_high_water_operator_recovery_validation_schema_sync(
    conn: &Connection,
) -> io::Result<()> {
    conn.execute_batch(PRE_HIGH_WATER_OPERATOR_RECOVERY_SCHEMA)
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
    pub(crate) authority_profile: ConsensusAuthorityProfile,
    pub(crate) fixed_placement_policy: Option<PlacementResiliencePolicy>,
    pub(crate) expected_members: BTreeSet<SessionConsensusNodeId>,
    pub(crate) expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    pub(crate) snapshot_dir: Arc<PathBuf>,
    pub(crate) caps: BackendCapabilities,
    pub(crate) snapshot_gate: Arc<tokio::sync::Mutex<()>>,
    pub(crate) applied_progress: tokio::sync::watch::Sender<Option<LogId<SessionConsensusNodeId>>>,
    pub(crate) watchers: Arc<tokio::sync::Mutex<Vec<crate::replication_watch::ReplicationWatcher>>>,
    pub(crate) consumer_watchers:
        Arc<tokio::sync::Mutex<Vec<crate::replication_watch::ConsumerReplicationWatcher>>>,
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
        authority_profile: ConsensusAuthorityProfile,
        fixed_placement_policy: Option<PlacementResiliencePolicy>,
    ) -> Result<Self, SessionConsensusStorageError> {
        Self::initialize_inner(
            backend,
            snapshot_dir,
            identity,
            expected_members,
            expected_bindings,
            None,
            None,
            authority_profile,
            fixed_placement_policy,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn initialize_with_pending(
        backend: &SqliteSessionBackend,
        snapshot_dir: PathBuf,
        storage_identity: SessionConsensusIdentity,
        current_identity: SessionConsensusIdentity,
        current_members: BTreeSet<SessionConsensusNodeId>,
        current_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        pending: PendingMembershipBootstrap<'_>,
        authority_profile: ConsensusAuthorityProfile,
        fixed_placement_policy: Option<PlacementResiliencePolicy>,
    ) -> Result<Self, SessionConsensusStorageError> {
        Self::initialize_inner(
            backend,
            snapshot_dir,
            current_identity,
            current_members,
            current_bindings,
            Some(storage_identity),
            Some(pending),
            authority_profile,
            fixed_placement_policy,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn initialize_inner(
        backend: &SqliteSessionBackend,
        snapshot_dir: PathBuf,
        identity: SessionConsensusIdentity,
        expected_members: BTreeSet<SessionConsensusNodeId>,
        expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        required_storage_identity: Option<SessionConsensusIdentity>,
        pending: Option<PendingMembershipBootstrap<'_>>,
        authority_profile: ConsensusAuthorityProfile,
        fixed_placement_policy: Option<PlacementResiliencePolicy>,
    ) -> Result<Self, SessionConsensusStorageError> {
        if !cfg!(target_os = "linux") && authority_profile == ConsensusAuthorityProfile::Dynamic {
            return Err(SessionConsensusStorageError::DynamicConsensusUnsupportedPlatform);
        }
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
            // Raw watch registration takes this registry before acquiring the
            // SQLite connection. Retain the same order for the complete
            // admission transition so a captured standalone watch cannot be
            // registered after consensus takes authority.
            let mut watchers = backend.watchers.lock().await;
            let conn = backend.conn.lock().await;
            let prior_admission = backend
                .begin_consensus_admission(&conn, &mut watchers)
                .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
            let initialized = initialize_schema_with_storage_anchor_and_pending_and_bindings(
                &conn,
                required_storage_identity,
                identity,
                &expected_members,
                &expected_bindings,
                pending,
                authority_profile,
                fixed_placement_policy,
            );
            let (storage_identity, applied) = match initialized {
                Ok(initialized) => initialized,
                Err(error) => {
                    backend
                        .finish_consensus_admission(&conn, prior_admission, false)
                        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
                    return Err(error);
                }
            };
            backend
                .finish_consensus_admission(&conn, prior_admission, true)
                .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
            (storage_identity, applied)
        };
        let (applied_progress, _) = tokio::sync::watch::channel(applied);

        Ok(Self {
            conn: Arc::clone(&backend.conn),
            storage_identity,
            authority_profile,
            fixed_placement_policy,
            expected_members,
            expected_bindings,
            snapshot_dir: Arc::new(canonical_snapshot_dir),
            // The core is shared by state-machine apply, snapshots, and
            // recovery/reopen paths. It must retain the consensus adapter's
            // advertised profile rather than SQLite's standalone ceiling.
            caps: backend.consensus_capabilities(),
            snapshot_gate: Arc::new(tokio::sync::Mutex::new(())),
            applied_progress,
            watchers: Arc::clone(&backend.watchers),
            consumer_watchers: Arc::clone(&backend.consumer_watchers),
            #[cfg(test)]
            apply_gate: Arc::clone(&backend.consensus_apply_gate),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PendingMembershipBootstrap<'a> {
    pub(crate) local_candidate_node_id: Option<SessionConsensusNodeId>,
    pub(crate) transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    pub(crate) transition_digest: [u8; 32],
    pub(crate) desired_identity: SessionConsensusIdentity,
    pub(crate) desired_members: &'a BTreeSet<SessionConsensusNodeId>,
    pub(crate) desired_bindings: &'a BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateBootstrapState {
    Active,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateBootstrapMarker {
    local_candidate_node_id: SessionConsensusNodeId,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
    state: CandidateBootstrapState,
}

type CandidateBootstrapRow = (i64, i64, Vec<u8>, Vec<u8>, i64);

fn read_candidate_bootstrap_marker_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> io::Result<Option<CandidateBootstrapMarker>> {
    if !table_exists(conn, "consensus_candidate_bootstrap").map_err(db_error)? {
        return Ok(None);
    }
    let row: Option<CandidateBootstrapRow> = conn
        .query_row(
            "SELECT storage_configuration_epoch, local_candidate_node_id, transition_id, transition_digest, state FROM consensus_candidate_bootstrap WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((storage_epoch, node_id, transition_id, transition_digest, state)) = row else {
        return Ok(None);
    };
    validate_epoch(storage_epoch, storage_identity)?;
    let node_id = SessionConsensusNodeId::new(checked_positive_u64(node_id)?)
        .map_err(|_| invalid_data("session consensus candidate node ID is invalid"))?;
    let transition_id = transition_id
        .try_into()
        .map_err(|_| invalid_data("session consensus candidate transition ID is invalid"))?;
    let transition_digest = transition_digest
        .try_into()
        .map_err(|_| invalid_data("session consensus candidate transition digest is invalid"))?;
    let state = match state {
        1 => CandidateBootstrapState::Active,
        2 => CandidateBootstrapState::Cancelled,
        _ => {
            return Err(invalid_data(
                "session consensus candidate bootstrap state is invalid",
            ));
        }
    };
    Ok(Some(CandidateBootstrapMarker {
        local_candidate_node_id: node_id,
        transition_id,
        transition_digest,
        state,
    }))
}

fn record_active_candidate_bootstrap_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    local_candidate_node_id: SessionConsensusNodeId,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
) -> Result<(), SessionConsensusStorageError> {
    if read_candidate_bootstrap_marker_sync(conn, storage_identity)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?
        .is_some_and(|marker| {
            marker.local_candidate_node_id != local_candidate_node_id
                || (marker.transition_id == transition_id
                    && (marker.transition_digest != transition_digest
                        || marker.state == CandidateBootstrapState::Cancelled))
        })
    {
        return Err(SessionConsensusStorageError::RecoveryRequired);
    }
    conn.execute(
        "INSERT INTO consensus_candidate_bootstrap (singleton, storage_configuration_epoch, local_candidate_node_id, transition_id, transition_digest, state) VALUES (1, ?1, ?2, ?3, ?4, 1) ON CONFLICT(singleton) DO UPDATE SET local_candidate_node_id = excluded.local_candidate_node_id, transition_id = excluded.transition_id, transition_digest = excluded.transition_digest, state = 1",
        params![
            epoch_i64(storage_identity)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?,
            checked_positive_i64(local_candidate_node_id.get())
                .map_err(|_| SessionConsensusStorageError::InvalidIdentity)?,
            transition_id.as_slice(),
            transition_digest.as_slice(),
        ],
    )
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    Ok(())
}

#[cfg(test)]
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

#[cfg(test)]
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
        ConsensusAuthorityProfile::Dynamic,
        None,
    )
    .map(|(storage_identity, _)| storage_identity)
}

#[cfg(test)]
fn initialize_schema_with_profile(
    conn: &Connection,
    requested_identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    authority_profile: ConsensusAuthorityProfile,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    initialize_schema_with_storage_anchor_and_pending_and_bindings(
        conn,
        None,
        requested_identity,
        expected_members,
        &test_member_bindings(expected_members),
        None,
        authority_profile,
        (authority_profile == ConsensusAuthorityProfile::FixedImmutable)
            .then_some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
    )
    .map(|(storage_identity, _)| storage_identity)
}

#[allow(clippy::too_many_arguments)]
fn initialize_schema_with_storage_anchor_and_pending_and_bindings(
    conn: &Connection,
    required_storage_identity: Option<SessionConsensusIdentity>,
    requested_identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    pending: Option<PendingMembershipBootstrap<'_>>,
    authority_profile: ConsensusAuthorityProfile,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
) -> Result<
    (
        SessionConsensusIdentity,
        Option<LogId<SessionConsensusNodeId>>,
    ),
    SessionConsensusStorageError,
> {
    if matches!(authority_profile, ConsensusAuthorityProfile::FixedImmutable)
        != fixed_placement_policy.is_some()
    {
        return Err(SessionConsensusStorageError::InvalidIdentity);
    }
    if let Some(storage_identity) = required_storage_identity {
        let same_incarnation = storage_identity.cluster_id() == requested_identity.cluster_id()
            && storage_identity.configuration_epoch() <= requested_identity.configuration_epoch()
            && (storage_identity.configuration_epoch() != requested_identity.configuration_epoch()
                || storage_identity.configuration_id() == requested_identity.configuration_id());
        if !same_incarnation {
            return Err(SessionConsensusStorageError::InvalidIdentity);
        }
    }
    // The exclusive transaction is the durable authority hand-off fence. A
    // standalone operation on another SQLite connection either finishes
    // before this claim (and is included in the legacy-state check) or starts
    // after the consensus identity commits and fails closed.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let identity_table_exists = table_exists(&tx, "consensus_identity")
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;

    let initial_schema = if !identity_table_exists {
        // A fresh raw backend released its constructor lock before consensus
        // configuration was known. Reclassify its complete local catalog
        // under this new EXCLUSIVE transaction so an empty extra object or
        // altered local DDL cannot cross that bounded continuation gap.
        super::validate_local_schema_for_fresh_consensus_claim(&tx)
            .map_err(|_| SessionConsensusStorageError::CorruptState)?;
        if consensus_schema_has_footprint(&tx)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        {
            // A database that already contains any consensus object is not a
            // fresh standalone store.  Never complete that footprint by
            // creating a new identity or singleton rows.
            return Err(SessionConsensusStorageError::CorruptState);
        }
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
            "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch, authority_profile, fixed_placement_policy) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
                storage_identity.cluster_id().as_bytes().as_slice(),
                storage_identity.configuration_id().as_bytes().as_slice(),
                epoch,
                authority_profile_i64(authority_profile),
                fixed_placement_policy.map(placement_policy_i64),
            ],
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        tx.execute(
            "INSERT INTO consensus_membership (singleton, configuration_epoch, membership_json) VALUES (1, ?1, ?2)",
            params![epoch, encode_json(&StoredMembership::<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>::default()).map_err(|_| SessionConsensusStorageError::BackendUnavailable)?],
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        tx.execute(
            "INSERT INTO consensus_machine (singleton, configuration_epoch, application_sequence, last_digest, last_receipt_digest, logical_time, watch_sequence) VALUES (1, ?1, 0, ?2, ?3, NULL, 0)",
            params![
                epoch,
                SessionConsensusEntryDigest::GENESIS.as_bytes().as_slice(),
                OUTCOME_RECEIPT_CHAIN_GENESIS.as_slice(),
            ],
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        ConsensusReopenSchema::Current
    } else {
        // Classification reads only SQLite's schema catalog. Persisted
        // authority is validated once below after reviewed migrations finish.
        classify_consensus_reopen_schema(&tx)?
    };

    // Capture these from the classified source before any initializer helper
    // can create a reviewed migration table.  A missing singleton in an
    // already-present authority table is corruption, not a reason to seed a
    // replacement row.  A fresh database has just installed the current DDL,
    // but its source still had no authority tables and may initialize them.
    let (
        source_operator_recovery_table_existed,
        source_command_admission_table_existed,
        source_membership_scope_table_existed,
    ) = if identity_table_exists {
        (
            table_exists(&tx, "consensus_operator_recovery")
                .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?,
            table_exists(&tx, "consensus_command_admission")
                .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?,
            table_exists(&tx, "consensus_membership_scope")
                .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?,
        )
    } else {
        (false, false, false)
    };

    // Preserve the pre-mutation manifest classification.  A complete frozen
    // base image may still add empty receipt provenance, but the sole
    // nonempty automatic migration is pinned to the exact reviewed immediate
    // predecessor rather than to any older or partial schema shape.
    let exact_immediate_predecessor = initial_schema == ConsensusReopenSchema::ImmediatePredecessor;
    let storage_identity = read_storage_identity_sync(&tx)?;
    ensure_consensus_authority_profile_sync(&tx, authority_profile, identity_table_exists)?;
    ensure_fixed_placement_policy_sync(&tx, authority_profile, fixed_placement_policy)?;
    if required_storage_identity.is_some_and(|required| required != storage_identity) {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable
        && storage_identity != requested_identity
    {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }
    if storage_identity.cluster_id() != requested_identity.cluster_id() {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }
    if storage_identity.configuration_epoch() > requested_identity.configuration_epoch()
        || (storage_identity.configuration_epoch() == requested_identity.configuration_epoch()
            && storage_identity.configuration_id() != requested_identity.configuration_id())
    {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }
    ensure_operator_recovery_schema_for_initializer_sync(
        &tx,
        storage_identity,
        !source_operator_recovery_table_existed,
    )
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    ensure_machine_receipt_chain_schema_sync(&tx, storage_identity)
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    ensure_command_admission_schema_sync(
        &tx,
        storage_identity,
        !source_command_admission_table_existed,
    )
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    ensure_outcome_receipt_schema_sync(&tx, storage_identity, exact_immediate_predecessor)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                // Old receipts lack the command/predecessor provenance that
                // v2 verifies. They require an operator recovery path rather
                // than being silently accepted or locally reconstructed.
                SessionConsensusStorageError::RecoveryRequired
            } else {
                SessionConsensusStorageError::BackendUnavailable
            }
        })?;
    ensure_membership_scope_schema_sync(
        &tx,
        storage_identity,
        requested_identity,
        expected_members,
        expected_bindings,
        !source_membership_scope_table_existed,
    )
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let expected_final_schema = initial_schema.expected_schema_after_initialization();
    let final_schema = classify_consensus_reopen_schema(&tx)?;
    if final_schema != expected_final_schema {
        return Err(SessionConsensusStorageError::CorruptState);
    }
    validate_existing_schema(&tx, storage_identity)?;

    let scope = read_membership_scope_sync(&tx, storage_identity)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    if scope.current_identity != requested_identity
        || scope.current_members != *expected_members
        || scope.current_bindings != *expected_bindings
    {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }
    if let Some(pending) = pending {
        let transition_start =
            if let Some(local_candidate_node_id) = pending.local_candidate_node_id {
                if scope.current_members.contains(&local_candidate_node_id)
                    || !pending.desired_members.contains(&local_candidate_node_id)
                {
                    return Err(SessionConsensusStorageError::InvalidIdentity);
                }
                let membership = read_membership_unchecked_sync(&tx, storage_identity)
                    .map_err(|_| SessionConsensusStorageError::CorruptState)?;
                let pristine_candidate = is_pristine_membership(&membership)
                    && read_applied_sync(&tx, storage_identity)
                        .map_err(|_| SessionConsensusStorageError::CorruptState)?
                        .is_none()
                    && scope.pending.is_none()
                    && scope.terminal.is_none();
                let exact_pending_candidate = scope.pending.as_ref().is_some_and(|existing| {
                    existing.transition_id == pending.transition_id
                        && existing.transition_digest == pending.transition_digest
                        && existing.desired_identity == pending.desired_identity
                        && existing.desired_members == *pending.desired_members
                        && existing.desired_bindings == *pending.desired_bindings
                });
                let durably_aborted_candidate = scope
                    .terminal
                    .as_ref()
                    .filter(|terminal| terminal.outcome == TerminalMembershipOutcome::Aborted)
                    .and_then(|terminal| {
                        (terminal.transition_id != pending.transition_id)
                            .then_some(terminal)
                            .and_then(|terminal| terminal.abort_cleanup.as_ref())
                    })
                    .is_some_and(|cleanup| cleanup.learners.contains(&local_candidate_node_id));
                let marker = read_candidate_bootstrap_marker_sync(&tx, storage_identity)
                    .map_err(|_| SessionConsensusStorageError::CorruptState)?;
                let marker_allows = marker.is_none_or(|marker| {
                    let same_node = marker.local_candidate_node_id == local_candidate_node_id;
                    let same_transition_id = marker.transition_id == pending.transition_id;
                    let exact = same_node
                        && same_transition_id
                        && marker.transition_digest == pending.transition_digest;
                    same_node
                        && match marker.state {
                            CandidateBootstrapState::Active => {
                                (exact && exact_pending_candidate)
                                    || (!same_transition_id && durably_aborted_candidate)
                            }
                            CandidateBootstrapState::Cancelled => !same_transition_id,
                        }
                });
                if (!pristine_candidate && !exact_pending_candidate && !durably_aborted_candidate)
                    || !marker_allows
                {
                    return Err(SessionConsensusStorageError::RecoveryRequired);
                }
                // A candidate has no authority to invent the source Prepare index.
                // Zero remains provisional until an exact committed Prepare entry
                // or authoritative snapshot supplies the real index.
                0
            } else {
                last_log_sync(&tx, storage_identity)
                    .map_err(|_| SessionConsensusStorageError::CorruptState)?
                    .map(|log_id| {
                        log_id
                            .index
                            .checked_add(1)
                            .ok_or(SessionConsensusStorageError::InvalidIdentity)
                    })
                    .transpose()?
                    .unwrap_or(0)
            };
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
        if let Some(local_candidate_node_id) = pending.local_candidate_node_id {
            record_active_candidate_bootstrap_sync(
                &tx,
                storage_identity,
                local_candidate_node_id,
                pending.transition_id,
                pending.transition_digest,
            )?;
        }
    }
    // Reopen is an admission boundary too: a pre-cap, recovered, or externally
    // modified database must not expose state that live consensus proposals
    // could not create under the retained profile.
    validate_sealed_state_sync(&tx).map_err(|_| SessionConsensusStorageError::CorruptState)?;
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable
        && !fixed_quorum_authority_is_exact_sync(
            &tx,
            storage_identity,
            expected_members,
            expected_bindings,
            fixed_placement_policy.ok_or(SessionConsensusStorageError::InvalidIdentity)?,
            true,
        )
        .map_err(|_| SessionConsensusStorageError::CorruptState)?
    {
        return Err(SessionConsensusStorageError::CorruptState);
    }
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable {
        validate_fixed_durable_state_sync(&tx, storage_identity, expected_members)
            .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    }

    let applied = read_applied_sync(&tx, storage_identity)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;

    tx.commit()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    Ok((storage_identity, applied))
}

fn authority_profile_i64(profile: ConsensusAuthorityProfile) -> i64 {
    match profile {
        ConsensusAuthorityProfile::Dynamic => 1,
        ConsensusAuthorityProfile::FixedImmutable => 2,
    }
}

fn authority_profile_from_i64(
    value: i64,
) -> Result<ConsensusAuthorityProfile, SessionConsensusStorageError> {
    match value {
        1 => Ok(ConsensusAuthorityProfile::Dynamic),
        2 => Ok(ConsensusAuthorityProfile::FixedImmutable),
        _ => Err(SessionConsensusStorageError::CorruptState),
    }
}

fn placement_policy_i64(policy: PlacementResiliencePolicy) -> i64 {
    match policy {
        PlacementResiliencePolicy::RequireIndependentFailureDomains => 1,
        PlacementResiliencePolicy::AllowReducedResilience => 2,
    }
}

fn placement_policy_from_i64(
    value: i64,
) -> Result<PlacementResiliencePolicy, SessionConsensusStorageError> {
    match value {
        1 => Ok(PlacementResiliencePolicy::RequireIndependentFailureDomains),
        2 => Ok(PlacementResiliencePolicy::AllowReducedResilience),
        _ => Err(SessionConsensusStorageError::CorruptState),
    }
}

fn fixed_placement_policy_column_exists(
    conn: &Connection,
) -> Result<bool, SessionConsensusStorageError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_identity') WHERE name = 'fixed_placement_policy')",
        [],
        |row| row.get(0),
    )
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)
}

fn ensure_fixed_placement_policy_sync(
    conn: &Connection,
    profile: ConsensusAuthorityProfile,
    expected: Option<PlacementResiliencePolicy>,
) -> Result<(), SessionConsensusStorageError> {
    if !fixed_placement_policy_column_exists(conn)? {
        if profile == ConsensusAuthorityProfile::FixedImmutable {
            return Err(SessionConsensusStorageError::IdentityMismatch);
        }
        conn.execute_batch(
            "ALTER TABLE consensus_identity ADD COLUMN fixed_placement_policy INTEGER CHECK (fixed_placement_policy IN (1, 2));",
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    }
    let stored: Option<i64> = conn
        .query_row(
            "SELECT fixed_placement_policy FROM consensus_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        .ok_or(SessionConsensusStorageError::CorruptState)?;
    match (profile, expected, stored) {
        (ConsensusAuthorityProfile::Dynamic, None, None) => Ok(()),
        (ConsensusAuthorityProfile::FixedImmutable, Some(expected), Some(stored))
            if placement_policy_from_i64(stored)? == expected =>
        {
            Ok(())
        }
        _ => Err(SessionConsensusStorageError::IdentityMismatch),
    }
}

fn read_fixed_placement_policy_sync(
    conn: &Connection,
) -> Result<Option<PlacementResiliencePolicy>, SessionConsensusStorageError> {
    if !fixed_placement_policy_column_exists(conn)? {
        return Err(SessionConsensusStorageError::CorruptState);
    }
    let stored: Option<i64> = conn
        .query_row(
            "SELECT fixed_placement_policy FROM consensus_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        .ok_or(SessionConsensusStorageError::CorruptState)?;
    stored.map(placement_policy_from_i64).transpose()
}

fn consensus_authority_profile_column_exists(
    conn: &Connection,
) -> Result<bool, SessionConsensusStorageError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_identity') WHERE name = 'authority_profile')",
        [],
        |row| row.get(0),
    )
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)
}

fn ensure_consensus_authority_profile_sync(
    conn: &Connection,
    expected: ConsensusAuthorityProfile,
    identity_table_existed: bool,
) -> Result<(), SessionConsensusStorageError> {
    if !consensus_authority_profile_column_exists(conn)? {
        if expected == ConsensusAuthorityProfile::FixedImmutable {
            return Err(SessionConsensusStorageError::IdentityMismatch);
        }
        conn.execute_batch(
            "ALTER TABLE consensus_identity ADD COLUMN authority_profile INTEGER CHECK (authority_profile IN (1, 2));",
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    }
    let stored: Option<i64> = conn
        .query_row(
            "SELECT authority_profile FROM consensus_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        .ok_or(SessionConsensusStorageError::CorruptState)?;
    match stored {
        Some(value) => {
            if authority_profile_from_i64(value)? == expected {
                Ok(())
            } else {
                Err(SessionConsensusStorageError::IdentityMismatch)
            }
        }
        None if !identity_table_existed => Err(SessionConsensusStorageError::CorruptState),
        None if expected == ConsensusAuthorityProfile::Dynamic => {
            conn.execute(
                "UPDATE consensus_identity SET authority_profile = ?1 WHERE singleton = 1 AND authority_profile IS NULL",
                [authority_profile_i64(ConsensusAuthorityProfile::Dynamic)],
            )
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
            Ok(())
        }
        None => Err(SessionConsensusStorageError::IdentityMismatch),
    }
}

fn read_consensus_authority_profile_sync(
    conn: &Connection,
) -> Result<ConsensusAuthorityProfile, SessionConsensusStorageError> {
    if !consensus_authority_profile_column_exists(conn)? {
        return Err(SessionConsensusStorageError::CorruptState);
    }
    let stored: Option<i64> = conn
        .query_row(
            "SELECT authority_profile FROM consensus_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        .ok_or(SessionConsensusStorageError::CorruptState)?;
    stored
        .map(authority_profile_from_i64)
        .transpose()?
        .ok_or(SessionConsensusStorageError::CorruptState)
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
        ConsensusAuthorityProfile::Dynamic,
        None,
    )
    .map(|(storage_identity, _)| storage_identity)
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

fn install_membership_terminal_history_schema_sync(conn: &Connection) -> io::Result<()> {
    if table_exists(conn, "consensus_membership_terminal_history").map_err(db_error)? {
        return Ok(());
    }
    let canonical = Connection::open_in_memory().map_err(db_error)?;
    canonical
        .execute_batch(CONSENSUS_SCHEMA)
        .map_err(db_error)?;
    let ddl: String = canonical
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'consensus_membership_terminal_history'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    conn.execute_batch(&ddl).map_err(db_error)
}

fn install_candidate_bootstrap_schema_sync(conn: &Connection) -> io::Result<()> {
    if table_exists(conn, "consensus_candidate_bootstrap").map_err(db_error)? {
        return Ok(());
    }
    let canonical = Connection::open_in_memory().map_err(db_error)?;
    canonical
        .execute_batch(CONSENSUS_SCHEMA)
        .map_err(db_error)?;
    let ddl: String = canonical
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'consensus_candidate_bootstrap'",
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

fn encode_node_subset(nodes: &BTreeSet<SessionConsensusNodeId>) -> io::Result<Vec<u8>> {
    if nodes.len() > crate::topology::QUORUM_TOPOLOGY_MAX_MEMBERS {
        return Err(invalid_data(
            "session consensus membership subset exceeds storage bounds",
        ));
    }
    for node in nodes {
        checked_positive_i64(node.get())?;
    }
    let encoded = encode_json(nodes)?;
    if encoded.len() < 2 || encoded.len() > MEMBERSHIP_SCOPE_MEMBERS_MAX_BYTES {
        return Err(invalid_data(
            "session consensus membership subset exceeds storage bounds",
        ));
    }
    Ok(encoded)
}

fn decode_node_subset(encoded: Vec<u8>) -> io::Result<BTreeSet<SessionConsensusNodeId>> {
    if encoded.len() < 2 || encoded.len() > MEMBERSHIP_SCOPE_MEMBERS_MAX_BYTES {
        return Err(invalid_data(
            "session consensus membership subset exceeds storage bounds",
        ));
    }
    let nodes = decode_json(&encoded)?;
    encode_node_subset(&nodes)?;
    Ok(nodes)
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

fn decode_current_bindings(
    encoded: Vec<u8>,
    members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>> {
    // Fixed-topology recovery checkpoints predate routable member bindings
    // and use exactly the canonical empty JSON array. A writable production
    // open replaces this sentinel atomically from the caller-validated
    // topology before any dynamic transition can be staged.
    if encoded == b"[]" {
        return Ok(BTreeMap::new());
    }
    decode_bindings(encoded, members)
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
    allow_missing_singleton_initialization: bool,
) -> io::Result<()> {
    validate_member_set(expected_members, false)?;
    if !expected_bindings.is_empty() {
        validate_member_bindings(expected_members, expected_bindings)?;
    }
    install_membership_history_schema_sync(conn)?;
    install_membership_terminal_history_schema_sync(conn)?;
    install_candidate_bootstrap_schema_sync(conn)?;
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
    let scope_table_exists = table_exists(conn, "consensus_membership_scope").map_err(db_error)?;
    if !scope_table_exists {
        if !allow_missing_singleton_initialization {
            return Err(invalid_data(
                "session consensus membership scope table disappeared during initialization",
            ));
        }
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
            if requested_current_identity != storage_identity {
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
        if !allow_missing_singleton_initialization {
            return Err(invalid_data(
                "session consensus membership scope singleton is missing",
            ));
        }
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
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
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

fn read_membership_terminal_history_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> io::Result<Vec<RetainedTerminalMembershipTransition>> {
    if !table_exists(conn, "consensus_membership_terminal_history").map_err(db_error)? {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT storage_configuration_epoch, transition_id, transition_digest, outcome, expected_member_count, transition_start_index, learners_ready_index, joint_membership_index, uniform_membership_index, cutover_index, finalization_index, abort_decision_index, abort_cleanup_membership_index FROM consensus_membership_terminal_history ORDER BY transition_start_index ASC, transition_id ASC",
        )
        .map_err(db_error)?;
    let mut rows = statement.query([]).map_err(db_error)?;
    let mut history = Vec::new();
    while let Some(row) = rows.next().map_err(db_error)? {
        if history.len() >= MEMBERSHIP_HISTORY_MAX_ENTRIES {
            return Err(invalid_data(
                "session consensus terminal history exceeds storage bounds",
            ));
        }
        let stored_epoch: i64 = row.get(0).map_err(db_error)?;
        validate_epoch(stored_epoch, storage_identity)?;
        let transition_id: Vec<u8> = row.get(1).map_err(db_error)?;
        let transition_id = transition_id
            .try_into()
            .map_err(|_| invalid_data("session consensus terminal history ID is invalid"))?;
        let transition_digest: Vec<u8> = row.get(2).map_err(db_error)?;
        let transition_digest = transition_digest
            .try_into()
            .map_err(|_| invalid_data("session consensus terminal history digest is invalid"))?;
        let outcome = match row.get::<_, i64>(3).map_err(db_error)? {
            1 => TerminalMembershipOutcome::Aborted,
            2 => TerminalMembershipOutcome::Promoted,
            _ => {
                return Err(invalid_data(
                    "session consensus terminal history outcome is invalid",
                ));
            }
        };
        let expected_member_count = usize::try_from(checked_positive_u64(
            row.get::<_, i64>(4).map_err(db_error)?,
        )?)
        .map_err(|_| invalid_data("session consensus terminal history member count is invalid"))?;
        if expected_member_count > crate::topology::QUORUM_TOPOLOGY_MAX_MEMBERS {
            return Err(invalid_data(
                "session consensus terminal history member count is invalid",
            ));
        }
        let transition_start_log_index = checked_u64(row.get(5).map_err(db_error)?)?;
        let learners_ready_log_index = row
            .get::<_, Option<i64>>(6)
            .map_err(db_error)?
            .map(checked_u64)
            .transpose()?;
        let joint_membership_log_index = row
            .get::<_, Option<i64>>(7)
            .map_err(db_error)?
            .map(checked_u64)
            .transpose()?;
        let uniform_membership_log_index = row
            .get::<_, Option<i64>>(8)
            .map_err(db_error)?
            .map(checked_u64)
            .transpose()?;
        let cutover_log_index = row
            .get::<_, Option<i64>>(9)
            .map_err(db_error)?
            .map(checked_u64)
            .transpose()?;
        let finalization_log_index = row
            .get::<_, Option<i64>>(10)
            .map_err(db_error)?
            .map(checked_u64)
            .transpose()?;
        let abort_decision_log_index = row
            .get::<_, Option<i64>>(11)
            .map_err(db_error)?
            .map(checked_u64)
            .transpose()?;
        let abort_cleanup_log_index = row
            .get::<_, Option<i64>>(12)
            .map_err(db_error)?
            .map(checked_u64)
            .transpose()?;

        let index_order_is_valid = learners_ready_log_index
            .is_none_or(|ready| ready > transition_start_log_index)
            && joint_membership_log_index
                .is_none_or(|joint| learners_ready_log_index.is_some_and(|ready| joint > ready))
            && uniform_membership_log_index.is_none_or(|uniform| {
                joint_membership_log_index.is_some_and(|joint| uniform > joint)
            });
        let outcome_is_valid = match outcome {
            TerminalMembershipOutcome::Aborted => {
                joint_membership_log_index.is_none()
                    && uniform_membership_log_index.is_none()
                    && cutover_log_index.is_none()
                    && finalization_log_index.is_none()
                    && abort_decision_log_index
                        .is_some_and(|decision| decision > transition_start_log_index)
                    && abort_cleanup_log_index.is_some_and(|cleanup| {
                        abort_decision_log_index.is_some_and(|decision| cleanup > decision)
                    })
            }
            TerminalMembershipOutcome::Promoted => {
                joint_membership_log_index.is_some()
                    && uniform_membership_log_index.is_some()
                    && cutover_log_index.is_some_and(|cutover| {
                        uniform_membership_log_index.is_some_and(|uniform| cutover >= uniform)
                    })
                    && finalization_log_index.is_some_and(|finalization| {
                        cutover_log_index.is_some_and(|cutover| finalization > cutover)
                    })
                    && abort_decision_log_index.is_none()
                    && abort_cleanup_log_index.is_none()
            }
        };
        if !index_order_is_valid || !outcome_is_valid {
            return Err(invalid_data(
                "session consensus terminal history evidence is inconsistent",
            ));
        }
        history.push(RetainedTerminalMembershipTransition {
            transition_id,
            transition_digest,
            outcome,
            expected_member_count,
            transition_start_log_index,
            learners_ready_log_index,
            joint_membership_log_index,
            uniform_membership_log_index,
            cutover_log_index,
            finalization_log_index,
            abort_decision_log_index,
            abort_cleanup_log_index,
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
            terminal_history: Vec::new(),
            pending: None,
            terminal: None,
        });
    }
    let row: MembershipScopeRow = conn
        .query_row(
            "SELECT storage_configuration_epoch, current_configuration_id, current_configuration_epoch, current_members_json, application_authority_epoch, application_authority_members_json, predecessor_configuration_id, predecessor_transition_id, predecessor_transition_digest, predecessor_configuration_epoch, predecessor_members_json, predecessor_transition_start_index, predecessor_cutover_index, pending_transition_id, pending_transition_digest, desired_configuration_id, desired_configuration_epoch, desired_members_json, pending_transition_start_index, pending_joint_membership_index, pending_uniform_membership_index, terminal_transition_id, terminal_transition_digest, terminal_transition_outcome, terminal_transition_start_index, terminal_joint_membership_index, terminal_uniform_membership_index, terminal_cutover_index, terminal_finalization_index, pending_learners_ready_index, terminal_learners_ready_index, current_bindings_json, desired_bindings_json, terminal_desired_configuration_id, terminal_desired_configuration_epoch, terminal_desired_members_json, terminal_desired_bindings_json, terminal_abort_learners_json, terminal_abort_decision_index, terminal_abort_cleanup_membership_index FROM consensus_membership_scope WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                    row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?, row.get(14)?,
                    row.get(15)?, row.get(16)?, row.get(17)?, row.get(18)?, row.get(19)?,
                    row.get(20)?, row.get(21)?, row.get(22)?, row.get(23)?, row.get(24)?,
                    row.get(25)?, row.get(26)?, row.get(27)?, row.get(28)?, row.get(29)?,
                    row.get(30)?, row.get(31)?, row.get(32)?, row.get(33)?, row.get(34)?,
                    row.get(35)?, row.get(36)?, row.get(37)?, row.get(38)?, row.get(39)?,
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
    let current_bindings = decode_current_bindings(row.31, &current_members)?;
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
                || row.33.is_some()
                || row.34.is_some()
                || row.35.is_some()
                || row.36.is_some()
                || row.37.is_some()
                || row.38.is_some()
                || row.39.is_some()
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
            let abort_cleanup = match outcome {
                TerminalMembershipOutcome::Aborted => {
                    let (
                        Some(configuration),
                        Some(epoch),
                        Some(members),
                        Some(bindings),
                        Some(learners),
                        Some(decision),
                    ) = (row.33, row.34, row.35, row.36, row.37, row.38)
                    else {
                        return Err(invalid_data(
                            "session consensus abort cleanup scope is incomplete",
                        ));
                    };
                    let configuration: [u8; 32] = configuration.try_into().map_err(|_| {
                        invalid_data(
                            "session consensus aborted desired configuration ID is invalid",
                        )
                    })?;
                    let epoch =
                        SessionConsensusConfigurationEpoch::new(checked_positive_u64(epoch)?)
                            .map_err(|_| {
                                invalid_data(
                            "session consensus aborted desired configuration epoch is invalid",
                        )
                            })?;
                    let desired_identity = SessionConsensusIdentity::new(
                        storage_identity.cluster_id(),
                        SessionConsensusConfigurationId::from_bytes(configuration),
                        epoch,
                    );
                    let desired_members = decode_members(members, true)?;
                    let desired_bindings = decode_bindings(bindings, &desired_members)?;
                    validate_transition_bindings(
                        &current_members,
                        &current_bindings,
                        &desired_members,
                        &desired_bindings,
                    )?;
                    let learners = decode_node_subset(learners)?;
                    let additions = desired_members
                        .difference(&current_members)
                        .copied()
                        .collect::<BTreeSet<_>>();
                    let decision = checked_u64(decision)?;
                    let cleanup = row.39.map(checked_u64).transpose()?;
                    if !exact_successor_epoch(current_identity, desired_identity)
                        || !learners.is_subset(&additions)
                        || decision <= start
                        || learners_ready.is_some_and(|ready| decision <= ready)
                        || cleanup.is_some_and(|cleanup| cleanup <= decision)
                    {
                        return Err(invalid_data(
                            "session consensus abort cleanup scope is inconsistent",
                        ));
                    }
                    Some(AbortedMembershipCleanup {
                        desired_identity,
                        desired_members,
                        desired_bindings,
                        learners,
                        decision_log_index: decision,
                        cleanup_log_index: cleanup,
                    })
                }
                TerminalMembershipOutcome::Promoted => {
                    if row.33.is_some()
                        || row.34.is_some()
                        || row.35.is_some()
                        || row.36.is_some()
                        || row.37.is_some()
                        || row.38.is_some()
                        || row.39.is_some()
                    {
                        return Err(invalid_data(
                            "session consensus promoted transition has abort cleanup scope",
                        ));
                    }
                    None
                }
            };
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
                abort_cleanup,
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
    let terminal_history = read_membership_terminal_history_sync(conn, storage_identity)?;
    if let Some(predecessor) = &predecessor {
        let current_terminal_matches = terminal.as_ref().is_some_and(|terminal| {
            terminal.transition_id == predecessor.transition_id
                && terminal.transition_digest == predecessor.transition_digest
                && terminal.outcome == TerminalMembershipOutcome::Promoted
                && terminal.transition_start_log_index == predecessor.transition_start_log_index
                && terminal.cutover_log_index == Some(predecessor.cutover_log_index)
        });
        let retained_terminal_matches = terminal_history.iter().any(|terminal| {
            terminal.transition_id == predecessor.transition_id
                && terminal.transition_digest == predecessor.transition_digest
                && terminal.outcome == TerminalMembershipOutcome::Promoted
                && terminal.expected_member_count == predecessor.members.len()
                && terminal.transition_start_log_index == predecessor.transition_start_log_index
                && terminal.cutover_log_index == Some(predecessor.cutover_log_index)
                && terminal.finalization_log_index.is_some()
        });
        if !current_terminal_matches && !retained_terminal_matches {
            return Err(invalid_data(
                "session consensus predecessor evidence is inconsistent",
            ));
        }
    }

    let history = read_membership_history_sync(conn, storage_identity)?;
    validate_membership_history_chain(&history, predecessor.as_ref(), current_identity)?;
    let scope = MembershipValidationScope {
        current_identity,
        current_members,
        current_bindings,
        application_authority_epoch,
        application_authority_members,
        predecessor,
        history,
        terminal_history,
        pending,
        terminal,
    };
    if let Some(pending) = scope.pending.as_ref() {
        if retained_transition_digest(&scope, pending.transition_id)?.is_some() {
            return Err(invalid_data(
                "session consensus pending transition reuses retained evidence",
            ));
        }
    }
    if let Some(current) = scope.terminal.as_ref() {
        if let Some(retained) = scope
            .terminal_history
            .iter()
            .find(|retained| retained.transition_id == current.transition_id)
        {
            let completed = completed_terminal_from_scope(&scope).map_err(|_| {
                invalid_data("session consensus current terminal history is incomplete")
            })?;
            if completed.as_ref() != Some(retained) {
                return Err(invalid_data(
                    "session consensus current terminal history conflicts",
                ));
            }
        }
    }
    for transition_id in scope
        .terminal_history
        .iter()
        .map(|terminal| terminal.transition_id)
        .chain(scope.terminal.iter().map(|terminal| terminal.transition_id))
        .chain(
            scope
                .predecessor
                .iter()
                .map(|predecessor| predecessor.transition_id),
        )
        .chain(
            scope
                .history
                .iter()
                .map(|predecessor| predecessor.transition_id),
        )
    {
        retained_transition_digest(&scope, transition_id)?;
    }
    Ok(scope)
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

fn completed_terminal_from_scope(
    scope: &MembershipValidationScope,
) -> Result<Option<RetainedTerminalMembershipTransition>, MembershipScopeMutationError> {
    let Some(terminal) = scope.terminal.as_ref() else {
        return Ok(None);
    };
    let (expected_member_count, abort_decision_log_index, abort_cleanup_log_index) =
        match terminal.outcome {
            TerminalMembershipOutcome::Aborted => {
                let cleanup = terminal
                    .abort_cleanup
                    .as_ref()
                    .ok_or(MembershipScopeMutationError::CorruptState)?;
                let cleanup_index = cleanup
                    .cleanup_log_index
                    .ok_or(MembershipScopeMutationError::TransitionNotQuiescent)?;
                (
                    scope.current_members.len(),
                    Some(cleanup.decision_log_index),
                    Some(cleanup_index),
                )
            }
            TerminalMembershipOutcome::Promoted => {
                if terminal.finalization_log_index.is_none() {
                    return Err(MembershipScopeMutationError::TransitionNotQuiescent);
                }
                let expected_member_count = scope
                    .predecessor
                    .iter()
                    .chain(scope.history.iter())
                    .find(|predecessor| {
                        predecessor.transition_id == terminal.transition_id
                            && predecessor.transition_digest == terminal.transition_digest
                    })
                    .map(|predecessor| predecessor.members.len())
                    .ok_or(MembershipScopeMutationError::CorruptState)?;
                (expected_member_count, None, None)
            }
        };
    Ok(Some(RetainedTerminalMembershipTransition {
        transition_id: terminal.transition_id,
        transition_digest: terminal.transition_digest,
        outcome: terminal.outcome,
        expected_member_count,
        transition_start_log_index: terminal.transition_start_log_index,
        learners_ready_log_index: terminal.learners_ready_log_index,
        joint_membership_log_index: terminal.joint_membership_log_index,
        uniform_membership_log_index: terminal.uniform_membership_log_index,
        cutover_log_index: terminal.cutover_log_index,
        finalization_log_index: terminal.finalization_log_index,
        abort_decision_log_index,
        abort_cleanup_log_index,
    }))
}

fn retain_completed_terminal_in_tx(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    scope: &MembershipValidationScope,
) -> Result<(), MembershipScopeMutationError> {
    let Some(retained) = completed_terminal_from_scope(scope)? else {
        return Ok(());
    };
    if let Some(existing) = scope
        .terminal_history
        .iter()
        .find(|existing| existing.transition_id == retained.transition_id)
    {
        return if existing == &retained {
            Ok(())
        } else {
            Err(MembershipScopeMutationError::CorruptState)
        };
    }
    if scope.terminal_history.len() >= MEMBERSHIP_HISTORY_MAX_ENTRIES {
        return Err(MembershipScopeMutationError::CompactionRequired);
    }
    let optional_index = |index: Option<u64>| {
        index
            .map(checked_i64)
            .transpose()
            .map_err(|_| MembershipScopeMutationError::CorruptState)
    };
    conn.execute(
        "INSERT INTO consensus_membership_terminal_history (transition_id, storage_configuration_epoch, transition_digest, outcome, expected_member_count, transition_start_index, learners_ready_index, joint_membership_index, uniform_membership_index, cutover_index, finalization_index, abort_decision_index, abort_cleanup_membership_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            retained.transition_id.as_slice(),
            epoch_i64(storage_identity)
                .map_err(|_| MembershipScopeMutationError::CorruptState)?,
            retained.transition_digest.as_slice(),
            match retained.outcome {
                TerminalMembershipOutcome::Aborted => 1_i64,
                TerminalMembershipOutcome::Promoted => 2_i64,
            },
            checked_positive_i64(
                u64::try_from(retained.expected_member_count)
                    .map_err(|_| MembershipScopeMutationError::CorruptState)?,
            )
            .map_err(|_| MembershipScopeMutationError::CorruptState)?,
            checked_i64(retained.transition_start_log_index)
                .map_err(|_| MembershipScopeMutationError::CorruptState)?,
            optional_index(retained.learners_ready_log_index)?,
            optional_index(retained.joint_membership_log_index)?,
            optional_index(retained.uniform_membership_log_index)?,
            optional_index(retained.cutover_log_index)?,
            optional_index(retained.finalization_log_index)?,
            optional_index(retained.abort_decision_log_index)?,
            optional_index(retained.abort_cleanup_log_index)?,
        ],
    )
    .map_err(|error| {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
            MembershipScopeMutationError::CorruptState
        } else {
            MembershipScopeMutationError::BackendUnavailable
        }
    })?;
    Ok(())
}

#[cfg(test)]
fn stage_membership_scope_sync_with_bindings(
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

#[allow(clippy::too_many_arguments)]
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
    if read_candidate_bootstrap_marker_sync(conn, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?
        .is_some_and(|marker| {
            marker.state == CandidateBootstrapState::Cancelled
                && marker.transition_id == transition_id
        })
    {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    if let Some(retained_digest) = retained_transition_digest(&scope, transition_id)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?
    {
        return if retained_digest == transition_digest {
            Ok(MembershipScopeMutation::Idempotent)
        } else {
            Err(MembershipScopeMutationError::ConflictingTransition)
        };
    }
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
    if let Some(pending) = scope.pending.as_ref() {
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
    retain_completed_terminal_in_tx(conn, storage_identity, &scope)?;
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
                abort_decision_log_index: None,
                abort_cleanup_log_index: None,
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
                abort_decision_log_index: terminal
                    .abort_cleanup
                    .as_ref()
                    .map(|cleanup| cleanup.decision_log_index),
                abort_cleanup_log_index: terminal
                    .abort_cleanup
                    .as_ref()
                    .and_then(|cleanup| cleanup.cleanup_log_index),
            }));
        }
    }
    if let Some(retained) = scope
        .terminal_history
        .iter()
        .find(|retained| retained.transition_id == transition_id)
    {
        if retained.transition_digest != transition_digest {
            return Err(MembershipScopeMutationError::ConflictingTransition);
        }
        return Ok(Some(retained.evidence()));
    }
    if let Some(retained_digest) = retained_transition_digest(&scope, transition_id)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?
    {
        if retained_digest != transition_digest {
            return Err(MembershipScopeMutationError::ConflictingTransition);
        }
        // Predecessor/history rows retain the exact request binding and
        // cutover, but not every joint/finalization index required to mint a
        // public terminal status. Exact historical lookup therefore remains
        // collision-safe without fabricating evidence.
        return Ok(None);
    }
    Ok(None)
}

impl SqliteSessionBackend {
    pub(crate) async fn provisional_consensus_candidate_is_cancelled(
        &self,
        storage_identity: SessionConsensusIdentity,
        local_candidate_node_id: SessionConsensusNodeId,
        transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
        transition_digest: [u8; 32],
    ) -> Result<bool, MembershipScopeMutationError> {
        if self.consensus_provisional_probe_admission().is_none() {
            return Err(MembershipScopeMutationError::BackendUnavailable);
        }
        let conn = self.conn.lock().await;
        match self.consensus_provisional_probe_admission() {
            Some(SqliteProvisionalProbeAdmission::PristineStandalone) => {
                // A brand-new membership candidate has no consensus marker to
                // query yet. Admit that ordering only for an exact standalone
                // catalog with no local authority or partial consensus
                // footprint; the initializer repeats the catalog check under
                // its EXCLUSIVE hand-off transaction before claiming it.
                super::validate_local_schema_for_fresh_consensus_claim(&conn)
                    .map_err(|_| MembershipScopeMutationError::CorruptState)?;
                if consensus_schema_has_footprint(&conn)
                    .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?
                    || legacy_authority_is_nonempty(&conn)
                        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?
                {
                    return Err(MembershipScopeMutationError::CorruptState);
                }
                return Ok(false);
            }
            Some(SqliteProvisionalProbeAdmission::ConsensusOwned) => {}
            None => return Err(MembershipScopeMutationError::BackendUnavailable),
        }
        let marker = read_candidate_bootstrap_marker_sync(&conn, storage_identity)
            .map_err(|_| MembershipScopeMutationError::CorruptState)?;
        Ok(marker.is_some_and(|marker| {
            marker.local_candidate_node_id == local_candidate_node_id
                && marker.transition_id == transition_id
                && marker.transition_digest == transition_digest
                && marker.state == CandidateBootstrapState::Cancelled
        }))
    }

    pub(crate) async fn cancel_provisional_consensus_candidate(
        &self,
        storage_identity: SessionConsensusIdentity,
        local_candidate_node_id: SessionConsensusNodeId,
        transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
        transition_digest: [u8; 32],
    ) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
        if !self.consensus_admission_is_ready() {
            return Err(MembershipScopeMutationError::BackendUnavailable);
        }
        let conn = self.conn.lock().await;
        if !self.consensus_admission_is_ready() {
            return Err(MembershipScopeMutationError::BackendUnavailable);
        }
        cancel_provisional_candidate_membership_scope_sync(
            &conn,
            storage_identity,
            local_candidate_node_id,
            transition_id,
            transition_digest,
        )
    }

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
        if !self.consensus_admission_is_ready() {
            return Err(MembershipScopeMutationError::BackendUnavailable);
        }
        let conn = self.conn.lock().await;
        if !self.consensus_admission_is_ready() {
            return Err(MembershipScopeMutationError::BackendUnavailable);
        }
        let scope = read_scope_for_mutation(&conn, storage_identity)?;
        let membership = read_membership_sync(&conn, storage_identity)
            .map_err(|_| MembershipScopeMutationError::CorruptState)?;
        Ok((scope, membership))
    }

    /// Atomically read fixed-quorum structural authority and applied Openraft
    /// membership under the backend's single SQLite lock.
    pub(crate) async fn fixed_quorum_scope_snapshot(
        &self,
        storage_identity: SessionConsensusIdentity,
    ) -> Result<
        (
            ConsensusAuthorityProfile,
            Option<PlacementResiliencePolicy>,
            MembershipValidationScope,
            StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
        ),
        MembershipScopeMutationError,
    > {
        if !self.consensus_admission_is_ready() {
            return Err(MembershipScopeMutationError::BackendUnavailable);
        }
        let conn = self.conn.lock().await;
        if !self.consensus_admission_is_ready() {
            return Err(MembershipScopeMutationError::BackendUnavailable);
        }
        let authority_profile = read_consensus_authority_profile_sync(&conn)
            .map_err(|_| MembershipScopeMutationError::CorruptState)?;
        let placement_policy = read_fixed_placement_policy_sync(&conn)
            .map_err(|_| MembershipScopeMutationError::CorruptState)?;
        let scope = read_scope_for_mutation(&conn, storage_identity)?;
        let membership = read_membership_sync(&conn, storage_identity)
            .map_err(|_| MembershipScopeMutationError::CorruptState)?;
        Ok((authority_profile, placement_policy, scope, membership))
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
        if !self.consensus_admission_is_ready() {
            return Err(MembershipScopeMutationError::BackendUnavailable);
        }
        let conn = self.conn.lock().await;
        if !self.consensus_admission_is_ready() {
            return Err(MembershipScopeMutationError::BackendUnavailable);
        }
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
    let log_index = membership
        .log_id()
        .ok_or_else(|| invalid_data("session consensus membership log identity is missing"))?
        .index;
    let Some(pending) = scope.pending else {
        if let Some(cleanup) = scope
            .terminal
            .as_ref()
            .filter(|terminal| terminal.outcome == TerminalMembershipOutcome::Aborted)
            .and_then(|terminal| terminal.abort_cleanup.as_ref())
        {
            if log_index <= cleanup.decision_log_index {
                return Ok(());
            }
            validate_uniform_membership(membership, &scope.current_members)?;
            if cleanup.cleanup_log_index == Some(log_index) {
                return Ok(());
            }
            if cleanup.cleanup_log_index.is_some() {
                return Err(invalid_data(
                    "session consensus abort cleanup membership evidence conflicts",
                ));
            }
            let changed = conn
                .execute(
                    "UPDATE consensus_membership_scope SET terminal_abort_cleanup_membership_index = ?1 WHERE singleton = 1 AND terminal_transition_outcome = 1 AND terminal_abort_decision_index < ?1 AND terminal_abort_cleanup_membership_index IS NULL",
                    params![checked_i64(log_index)?],
                )
                .map_err(db_error)?;
            if changed != 1 {
                return Err(invalid_data(
                    "session consensus abort cleanup membership evidence conflicts",
                ));
            }
            read_membership_scope_sync(conn, storage_identity)?;
        }
        return Ok(());
    };
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

#[cfg(test)]
fn fence_application_authority_sync(
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

#[cfg(test)]
fn abort_membership_scope_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
    abort_decision_log_index: u64,
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let tx = membership_transaction(conn)?;
    let result = restore_and_abort_membership_scope_in_tx(
        &tx,
        storage_identity,
        transition_id,
        transition_digest,
        abort_decision_log_index,
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
    abort_decision_log_index: u64,
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    let Some(pending) = scope.pending.as_ref() else {
        let cleanup = scope
            .terminal
            .as_ref()
            .filter(|terminal| {
                terminal.transition_id == transition_id
                    && terminal.transition_digest == transition_digest
                    && terminal.outcome == TerminalMembershipOutcome::Aborted
            })
            .and_then(|terminal| terminal.abort_cleanup.as_ref())
            .ok_or(MembershipScopeMutationError::ConflictingTransition)?;
        if abort_decision_log_index < cleanup.decision_log_index {
            return Err(MembershipScopeMutationError::ConflictingTransition);
        }
        if cleanup.learners.is_empty()
            && cleanup.cleanup_log_index.is_none()
            && abort_decision_log_index > cleanup.decision_log_index
        {
            let changed = conn
                .execute(
                    "UPDATE consensus_membership_scope SET terminal_abort_cleanup_membership_index = ?1 WHERE singleton = 1 AND terminal_transition_id = ?2 AND terminal_transition_digest = ?3 AND terminal_transition_outcome = 1 AND terminal_abort_learners_json = ?4 AND terminal_abort_decision_index < ?1 AND terminal_abort_cleanup_membership_index IS NULL",
                    params![
                        checked_i64(abort_decision_log_index)
                            .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                        transition_id.as_slice(),
                        transition_digest.as_slice(),
                        encode_node_subset(&BTreeSet::new())
                            .map_err(|_| MembershipScopeMutationError::CorruptState)?,
                    ],
                )
                .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
            if changed != 1 {
                return Err(MembershipScopeMutationError::ConflictingTransition);
            }
            read_scope_for_mutation(conn, storage_identity)?;
            return Ok(MembershipScopeMutation::Applied);
        }
        return Ok(MembershipScopeMutation::Idempotent);
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
    let learners = match abort_learners_from_membership(
        &membership,
        &scope.current_members,
        &pending.desired_members,
    ) {
        Ok(learners) => learners,
        Err(_) => return Err(MembershipScopeMutationError::TransitionNotQuiescent),
    };
    if abort_decision_log_index <= pending.transition_start_log_index
        || pending
            .learners_ready_log_index
            .is_some_and(|ready| abort_decision_log_index <= ready)
    {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    retain_completed_terminal_in_tx(conn, storage_identity, &scope)?;
    let changed = conn
        .execute(
            "UPDATE consensus_membership_scope SET application_authority_epoch = current_configuration_epoch, application_authority_members_json = current_members_json, terminal_transition_id = ?1, terminal_transition_digest = ?2, terminal_transition_outcome = 1, terminal_transition_start_index = pending_transition_start_index, terminal_learners_ready_index = pending_learners_ready_index, terminal_joint_membership_index = NULL, terminal_uniform_membership_index = NULL, terminal_cutover_index = NULL, terminal_finalization_index = NULL, terminal_desired_configuration_id = desired_configuration_id, terminal_desired_configuration_epoch = desired_configuration_epoch, terminal_desired_members_json = desired_members_json, terminal_desired_bindings_json = desired_bindings_json, terminal_abort_learners_json = ?3, terminal_abort_decision_index = ?4, terminal_abort_cleanup_membership_index = NULL, pending_transition_id = NULL, pending_transition_digest = NULL, desired_configuration_id = NULL, desired_configuration_epoch = NULL, desired_members_json = NULL, desired_bindings_json = NULL, pending_transition_start_index = NULL, pending_learners_ready_index = NULL, pending_joint_membership_index = NULL, pending_uniform_membership_index = NULL WHERE singleton = 1 AND pending_transition_id = ?1 AND pending_transition_digest = ?2",
            params![
                transition_id.as_slice(),
                transition_digest.as_slice(),
                encode_node_subset(&learners)
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                checked_i64(abort_decision_log_index)
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
            ],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if changed != 1 {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    conn.execute(
        "UPDATE consensus_candidate_bootstrap SET state = 2 WHERE singleton = 1 AND transition_id = ?1 AND transition_digest = ?2 AND state = 1",
        params![transition_id.as_slice(), transition_digest.as_slice()],
    )
    .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    read_scope_for_mutation(conn, storage_identity)?;
    Ok(MembershipScopeMutation::Applied)
}

/// Cancel a locally opened candidate that never entered Openraft membership.
///
/// This is deliberately not a replacement for the replicated abort command.
/// It accepts only the exact provisional bootstrap (`start = 0`) before any
/// committed transition evidence exists. A durable local tombstone makes
/// authenticated retries idempotent and prevents another request from
/// blindly clearing or replacing the candidate scope.
pub(crate) fn cancel_provisional_candidate_membership_scope_sync(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    local_candidate_node_id: SessionConsensusNodeId,
    transition_id: [u8; MEMBERSHIP_TRANSITION_ID_BYTES],
    transition_digest: [u8; 32],
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let tx = membership_transaction(conn)?;
    let marker = read_candidate_bootstrap_marker_sync(&tx, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?
        .ok_or(MembershipScopeMutationError::ConflictingTransition)?;
    let exact_marker = marker.local_candidate_node_id == local_candidate_node_id
        && marker.transition_id == transition_id
        && marker.transition_digest == transition_digest;
    if !exact_marker {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    if marker.state == CandidateBootstrapState::Cancelled {
        let scope = read_scope_for_mutation(&tx, storage_identity)?;
        if scope.pending.is_some() {
            return Err(MembershipScopeMutationError::CorruptState);
        }
        tx.commit()
            .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
        return Ok(MembershipScopeMutation::Idempotent);
    }

    let scope = read_scope_for_mutation(&tx, storage_identity)?;
    let pending = scope
        .pending
        .as_ref()
        .ok_or(MembershipScopeMutationError::ConflictingTransition)?;
    if pending.transition_id != transition_id
        || pending.transition_digest != transition_digest
        || pending.transition_start_log_index != 0
        || pending.learners_ready_log_index.is_some()
        || pending.joint_membership_log_index.is_some()
        || pending.uniform_membership_log_index.is_some()
        || scope.application_authority_epoch != scope.current_identity.configuration_epoch()
        || scope.application_authority_members != scope.current_members
    {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }

    let membership = read_membership_unchecked_sync(&tx, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    let pristine = is_pristine_membership(&membership)
        && read_applied_sync(&tx, storage_identity)
            .map_err(|_| MembershipScopeMutationError::CorruptState)?
            .is_none();
    let mut scope_without_provisional = scope.clone();
    scope_without_provisional.pending = None;
    let prior_abort_proves_local_reuse = scope_without_provisional
        .terminal
        .as_ref()
        .filter(|terminal| terminal.outcome == TerminalMembershipOutcome::Aborted)
        .and_then(|terminal| terminal.abort_cleanup.as_ref())
        .is_some_and(|cleanup| cleanup.learners.contains(&local_candidate_node_id));
    let prior_state_is_valid = membership.log_id().is_some_and(|log_id| {
        prior_abort_proves_local_reuse
            && validate_membership_for_log(&membership, &scope_without_provisional, log_id.index)
                .is_ok()
    });
    if !pristine && !prior_state_is_valid {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }

    let changed = tx
        .execute(
            "UPDATE consensus_membership_scope SET pending_transition_id = NULL, pending_transition_digest = NULL, desired_configuration_id = NULL, desired_configuration_epoch = NULL, desired_members_json = NULL, desired_bindings_json = NULL, pending_transition_start_index = NULL, pending_learners_ready_index = NULL, pending_joint_membership_index = NULL, pending_uniform_membership_index = NULL WHERE singleton = 1 AND pending_transition_id = ?1 AND pending_transition_digest = ?2 AND pending_transition_start_index = 0 AND pending_learners_ready_index IS NULL AND pending_joint_membership_index IS NULL AND pending_uniform_membership_index IS NULL",
            params![transition_id.as_slice(), transition_digest.as_slice()],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if changed != 1 {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    let marker_changed = tx
        .execute(
            "UPDATE consensus_candidate_bootstrap SET state = 2 WHERE singleton = 1 AND local_candidate_node_id = ?1 AND transition_id = ?2 AND transition_digest = ?3 AND state = 1",
            params![
                checked_positive_i64(local_candidate_node_id.get())
                    .map_err(|_| MembershipScopeMutationError::InvalidScope)?,
                transition_id.as_slice(),
                transition_digest.as_slice(),
            ],
        )
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    if marker_changed != 1 {
        return Err(MembershipScopeMutationError::ConflictingTransition);
    }
    read_scope_for_mutation(&tx, storage_identity)?;
    validate_persisted_membership_sync(&tx, storage_identity)
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    tx.commit()
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    Ok(MembershipScopeMutation::Applied)
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
    retain_completed_terminal_in_tx(conn, storage_identity, &scope)?;
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
            "UPDATE consensus_membership_scope SET predecessor_configuration_id = current_configuration_id, predecessor_transition_id = pending_transition_id, predecessor_transition_digest = pending_transition_digest, predecessor_configuration_epoch = current_configuration_epoch, predecessor_members_json = current_members_json, predecessor_transition_start_index = pending_transition_start_index, predecessor_cutover_index = ?1, current_configuration_id = desired_configuration_id, current_configuration_epoch = desired_configuration_epoch, current_members_json = desired_members_json, current_bindings_json = desired_bindings_json, terminal_transition_id = ?2, terminal_transition_digest = ?3, terminal_transition_outcome = 2, terminal_transition_start_index = pending_transition_start_index, terminal_learners_ready_index = pending_learners_ready_index, terminal_joint_membership_index = pending_joint_membership_index, terminal_uniform_membership_index = pending_uniform_membership_index, terminal_cutover_index = ?1, terminal_finalization_index = NULL, terminal_desired_configuration_id = NULL, terminal_desired_configuration_epoch = NULL, terminal_desired_members_json = NULL, terminal_desired_bindings_json = NULL, terminal_abort_learners_json = NULL, terminal_abort_decision_index = NULL, terminal_abort_cleanup_membership_index = NULL, pending_transition_id = NULL, pending_transition_digest = NULL, desired_configuration_id = NULL, desired_configuration_epoch = NULL, desired_members_json = NULL, desired_bindings_json = NULL, pending_transition_start_index = NULL, pending_learners_ready_index = NULL, pending_joint_membership_index = NULL, pending_uniform_membership_index = NULL WHERE singleton = 1 AND pending_transition_id = ?2 AND pending_transition_digest = ?3",
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
    conn.execute(
        "DELETE FROM consensus_candidate_bootstrap WHERE singleton = 1 AND transition_id = ?1 AND transition_digest = ?2",
        params![transition_id.as_slice(), transition_digest.as_slice()],
    )
    .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
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

#[cfg(test)]
fn drop_compacted_membership_predecessor_sync(
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

#[cfg(test)]
const CONSENSUS_BASE_TABLES: &[&str] = &[
    "consensus_identity",
    "consensus_vote",
    "consensus_committed",
    "consensus_purged",
    "consensus_log",
    "consensus_applied",
    "consensus_membership",
    "consensus_machine",
    "consensus_request_outcomes",
    "consensus_snapshot",
];

#[cfg(test)]
const CONSENSUS_UPGRADE_TABLES: &[&str] = &[
    "consensus_membership_scope",
    "consensus_membership_history",
    "consensus_membership_terminal_history",
    "consensus_candidate_bootstrap",
    "consensus_command_admission",
    "consensus_operator_recovery",
];

fn consensus_schema_has_footprint(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name GLOB 'consensus_*')",
        [],
        |row| row.get(0),
    )
}

fn consensus_schema_manifest(
    conn: &Connection,
) -> Result<BTreeMap<String, String>, SessionConsensusStorageError> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master WHERE name GLOB 'consensus_*' ORDER BY type, name",
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let mut rows = statement
        .query([])
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let mut manifest = BTreeMap::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
    {
        let kind: String = row
            .get(0)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        let name: String = row
            .get(1)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        let sql: Option<String> = row
            .get(2)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        let Some(sql) = sql else {
            return Err(SessionConsensusStorageError::CorruptState);
        };
        if kind != "table" || manifest.insert(name, sql).is_some() {
            return Err(SessionConsensusStorageError::CorruptState);
        }
    }
    Ok(manifest)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsensusReopenSchema {
    Current,
    HistoricalBase,
    OriginMainFixedMembership,
    ImmediatePredecessor,
    PreReceiptChain,
    OperatorRecoveryAddOn,
    OperatorRecoveryMigrated,
    OperatorRecoveryCursorMigrated,
    OperatorRecoveryPreHighWater,
    HistoricalBaseMigrated,
    ImmediatePredecessorMigrated,
    PreReceiptChainMigrated,
    OperatorRecoveryPreHighWaterMigrated,
}

impl ConsensusReopenSchema {
    /// Return the exact stored-DDL form produced by the reviewed initializer
    /// migration for this complete source manifest.  In particular, the
    /// recovery add-on already uses `OPERATOR_RECOVERY_SCHEMA`, so it has the
    /// pending high-water columns and remains in its add-on DDL form.
    fn expected_schema_after_initialization(self) -> Self {
        match self {
            Self::Current => Self::Current,
            Self::HistoricalBase => Self::HistoricalBaseMigrated,
            Self::OriginMainFixedMembership => Self::Current,
            Self::ImmediatePredecessor => Self::ImmediatePredecessorMigrated,
            Self::PreReceiptChain => Self::PreReceiptChainMigrated,
            Self::OperatorRecoveryAddOn => Self::OperatorRecoveryAddOn,
            Self::OperatorRecoveryMigrated => Self::OperatorRecoveryMigrated,
            Self::OperatorRecoveryCursorMigrated => Self::OperatorRecoveryMigrated,
            Self::OperatorRecoveryPreHighWater => Self::OperatorRecoveryPreHighWaterMigrated,
            Self::HistoricalBaseMigrated
            | Self::ImmediatePredecessorMigrated
            | Self::PreReceiptChainMigrated
            | Self::OperatorRecoveryPreHighWaterMigrated => self,
        }
    }
}

fn canonical_consensus_schema_manifest(
    install: impl FnOnce(&Connection) -> io::Result<()>,
) -> Result<BTreeMap<String, String>, SessionConsensusStorageError> {
    let canonical = SqliteSessionBackend::canonical_schema_connection()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    install(&canonical).map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    consensus_schema_manifest(&canonical)
}

fn install_current_consensus_schema(conn: &Connection) -> io::Result<()> {
    install_recovery_validation_schema_sync(conn, false)
}

fn replace_operator_recovery_schema(
    conn: &Connection,
    install: impl FnOnce(&Connection) -> io::Result<()>,
) -> io::Result<()> {
    conn.execute_batch("DROP TABLE consensus_operator_recovery;")
        .map_err(db_error)?;
    install(conn)
}

fn install_machine_receipt_chain_migration_schema(conn: &Connection) -> io::Result<()> {
    conn.execute_batch("DROP TABLE consensus_machine;")
        .map_err(db_error)?;
    conn.execute_batch(IMMEDIATE_PREDECESSOR_CONSENSUS_MACHINE_SCHEMA)
        .map_err(db_error)?;
    conn.execute_batch(
        "ALTER TABLE consensus_machine ADD COLUMN last_receipt_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' CHECK (length(last_receipt_digest) = 32);",
    )
    .map_err(db_error)
}

fn install_current_outcome_receipt_schema(conn: &Connection) -> io::Result<()> {
    conn.execute_batch("DROP TABLE consensus_request_outcomes;")
        .map_err(db_error)?;
    conn.execute_batch(RECEIPT_CHAIN_CONSENSUS_REQUEST_OUTCOMES_SCHEMA)
        .map_err(db_error)
}

fn install_operator_recovery_high_water_migration_schema(conn: &Connection) -> io::Result<()> {
    conn.execute_batch(OPERATOR_RECOVERY_HIGH_WATER_MIGRATION)
        .map_err(db_error)
}

fn install_consensus_reopen_schema(
    conn: &Connection,
    schema: ConsensusReopenSchema,
) -> io::Result<()> {
    if schema == ConsensusReopenSchema::ImmediatePredecessor {
        return install_immediate_predecessor_recovery_validation_schema_sync(conn);
    }
    install_current_consensus_schema(conn)?;
    match schema {
        ConsensusReopenSchema::Current => Ok(()),
        ConsensusReopenSchema::HistoricalBase => conn
            .execute_batch(
                "DROP TABLE consensus_membership_scope;
                 DROP TABLE consensus_membership_history;
                 DROP TABLE consensus_membership_terminal_history;
                 DROP TABLE consensus_candidate_bootstrap;
                 DROP TABLE consensus_command_admission;
                 DROP TABLE consensus_operator_recovery;
                 ALTER TABLE consensus_identity DROP COLUMN fixed_placement_policy;
                 ALTER TABLE consensus_identity DROP COLUMN authority_profile;",
            )
            .map_err(db_error),
        ConsensusReopenSchema::OriginMainFixedMembership => conn
            .execute_batch(
                "DROP TABLE consensus_candidate_bootstrap;
                 DROP TABLE consensus_membership_terminal_history;
                 DROP TABLE consensus_membership_history;
                 DROP TABLE consensus_membership_scope;",
            )
            .map_err(db_error),
        ConsensusReopenSchema::ImmediatePredecessor => unreachable!(),
        ConsensusReopenSchema::PreReceiptChain => conn
            .execute_batch(
                "DROP TABLE consensus_request_outcomes;
                 DROP TABLE consensus_machine;",
            )
            .map_err(db_error)
            .and_then(|()| {
                conn.execute_batch(IMMEDIATE_PREDECESSOR_CONSENSUS_MACHINE_SCHEMA)
                    .map_err(db_error)
            })
            .and_then(|()| {
                conn.execute_batch(PRE_RECEIPT_CHAIN_CONSENSUS_REQUEST_OUTCOMES_SCHEMA)
                    .map_err(db_error)
            }),
        ConsensusReopenSchema::OperatorRecoveryAddOn => {
            replace_operator_recovery_schema(conn, |conn| {
                install_recovery_validation_schema_sync(conn, true)
            })
        }
        ConsensusReopenSchema::OperatorRecoveryMigrated => {
            replace_operator_recovery_schema(conn, |conn| {
                install_migrated_operator_recovery_validation_schema_sync(conn)
            })
        }
        ConsensusReopenSchema::OperatorRecoveryCursorMigrated => {
            replace_operator_recovery_schema(conn, |conn| {
                install_cursor_migrated_operator_recovery_validation_schema_sync(conn)
            })
        }
        ConsensusReopenSchema::OperatorRecoveryPreHighWater => {
            replace_operator_recovery_schema(conn, |conn| {
                install_pre_high_water_operator_recovery_validation_schema_sync(conn)
            })
        }
        ConsensusReopenSchema::HistoricalBaseMigrated => {
            conn.execute_batch(
                "ALTER TABLE consensus_identity DROP COLUMN fixed_placement_policy;
                 ALTER TABLE consensus_identity DROP COLUMN authority_profile;
                 ALTER TABLE consensus_identity ADD COLUMN authority_profile INTEGER CHECK (authority_profile IN (1, 2));
                 ALTER TABLE consensus_identity ADD COLUMN fixed_placement_policy INTEGER CHECK (fixed_placement_policy IN (1, 2));",
            )
            .map_err(db_error)?;
            replace_operator_recovery_schema(conn, |conn| {
                install_recovery_validation_schema_sync(conn, true)
            })
        }
        ConsensusReopenSchema::ImmediatePredecessorMigrated => {
            install_machine_receipt_chain_migration_schema(conn)?;
            install_current_outcome_receipt_schema(conn)?;
            replace_operator_recovery_schema(conn, |conn| {
                install_pre_high_water_operator_recovery_validation_schema_sync(conn)
            })?;
            install_operator_recovery_high_water_migration_schema(conn)
        }
        ConsensusReopenSchema::PreReceiptChainMigrated => {
            install_machine_receipt_chain_migration_schema(conn)?;
            install_current_outcome_receipt_schema(conn)
        }
        ConsensusReopenSchema::OperatorRecoveryPreHighWaterMigrated => {
            replace_operator_recovery_schema(conn, |conn| {
                install_pre_high_water_operator_recovery_validation_schema_sync(conn)
            })?;
            install_operator_recovery_high_water_migration_schema(conn)
        }
    }
}

fn classify_consensus_reopen_schema(
    conn: &Connection,
) -> Result<ConsensusReopenSchema, SessionConsensusStorageError> {
    let observed = consensus_schema_manifest(conn)?;
    for schema in [
        ConsensusReopenSchema::Current,
        ConsensusReopenSchema::HistoricalBase,
        ConsensusReopenSchema::OriginMainFixedMembership,
        ConsensusReopenSchema::ImmediatePredecessor,
        ConsensusReopenSchema::PreReceiptChain,
        ConsensusReopenSchema::OperatorRecoveryAddOn,
        ConsensusReopenSchema::OperatorRecoveryMigrated,
        ConsensusReopenSchema::OperatorRecoveryCursorMigrated,
        ConsensusReopenSchema::OperatorRecoveryPreHighWater,
        ConsensusReopenSchema::HistoricalBaseMigrated,
        ConsensusReopenSchema::ImmediatePredecessorMigrated,
        ConsensusReopenSchema::PreReceiptChainMigrated,
        ConsensusReopenSchema::OperatorRecoveryPreHighWaterMigrated,
    ] {
        if observed
            == canonical_consensus_schema_manifest(|conn| {
                install_consensus_reopen_schema(conn, schema)
            })?
        {
            return Ok(schema);
        }
    }
    Err(SessionConsensusStorageError::CorruptState)
}

/// Recognize a complete, exact consensus-owned inventory without reading any
/// authority rowset. The consensus initializer validates persisted state and
/// performs only the reviewed migrations while holding the admission fence.
pub(super) fn validate_consensus_inventory_for_local_open(
    conn: &Connection,
) -> Result<bool, SessionConsensusStorageError> {
    let manifest = consensus_schema_manifest(conn)?;
    if manifest.is_empty() {
        return Ok(false);
    }
    classify_consensus_reopen_schema(conn)?;
    Ok(true)
}

#[cfg(test)]
fn is_immediate_predecessor_schema(
    conn: &Connection,
) -> Result<bool, SessionConsensusStorageError> {
    Ok(classify_consensus_reopen_schema(conn)? == ConsensusReopenSchema::ImmediatePredecessor)
}

fn validate_existing_schema(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> Result<(), SessionConsensusStorageError> {
    for table in [
        "consensus_identity",
        "consensus_membership_scope",
        "consensus_membership_history",
        "consensus_membership_terminal_history",
        "consensus_candidate_bootstrap",
        "consensus_vote",
        "consensus_committed",
        "consensus_purged",
        "consensus_log",
        "consensus_applied",
        "consensus_membership",
        "consensus_machine",
        "consensus_request_outcomes",
        "consensus_command_admission",
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

    super::validate_consensus_restore_scan_metadata_row(conn)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;

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
    read_command_admission_sync(conn, storage_identity)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    validate_all_outcomes_sync(conn, storage_identity)
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
    pending_fence_high_water INTEGER CHECK (pending_fence_high_water >= 0),
    pending_credential_high_water INTEGER CHECK (pending_credential_high_water >= 0),
    watch_cursor_invalidation_floor INTEGER NOT NULL DEFAULT 0 CHECK (watch_cursor_invalidation_floor >= 0),
    CHECK (
        (pending_epoch IS NULL AND pending_plan_digest IS NULL
            AND pending_fence_high_water IS NULL AND pending_credential_high_water IS NULL)
        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL
            AND pending_fence_high_water IS NOT NULL AND pending_credential_high_water IS NOT NULL)
    ),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);
"#;

const PRE_HIGH_WATER_OPERATOR_RECOVERY_SCHEMA: &str = r#"
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

const OPERATOR_RECOVERY_CURSOR_MIGRATION: &str = "ALTER TABLE consensus_operator_recovery ADD COLUMN watch_cursor_invalidation_floor INTEGER NOT NULL DEFAULT 0 CHECK (watch_cursor_invalidation_floor >= 0);";
const OPERATOR_RECOVERY_HIGH_WATER_MIGRATION: &str = "ALTER TABLE consensus_operator_recovery ADD COLUMN pending_fence_high_water INTEGER CHECK (pending_fence_high_water >= 0); ALTER TABLE consensus_operator_recovery ADD COLUMN pending_credential_high_water INTEGER CHECK (pending_credential_high_water >= 0);";

pub(crate) fn ensure_operator_recovery_schema_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    ensure_operator_recovery_schema_with_missing_singleton_initialization_sync(conn, identity, true)
}

fn ensure_operator_recovery_schema_for_initializer_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    allow_missing_singleton_initialization: bool,
) -> io::Result<()> {
    ensure_operator_recovery_schema_with_missing_singleton_initialization_sync(
        conn,
        identity,
        allow_missing_singleton_initialization,
    )
}

fn ensure_operator_recovery_schema_with_missing_singleton_initialization_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    allow_missing_singleton_initialization: bool,
) -> io::Result<()> {
    conn.execute_batch(OPERATOR_RECOVERY_SCHEMA)
        .map_err(db_error)?;
    if !operator_recovery_cursor_column_exists(conn)? {
        conn.execute_batch(OPERATOR_RECOVERY_CURSOR_MIGRATION)
            .map_err(db_error)?;
    }
    let (has_pending_fence, has_pending_credential) =
        operator_recovery_pending_high_water_columns(conn)?;
    if has_pending_fence != has_pending_credential {
        return Err(invalid_data(
            "session consensus operator recovery high-water binding is incomplete",
        ));
    }
    if !has_pending_fence {
        let pending: bool = conn
            .query_row(
                "SELECT pending_epoch IS NOT NULL OR pending_plan_digest IS NOT NULL FROM consensus_operator_recovery WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if pending {
            return Err(invalid_data(
                "session consensus pending recovery high-water binding is missing",
            ));
        }
        conn.execute_batch(OPERATOR_RECOVERY_HIGH_WATER_MIGRATION)
            .map_err(db_error)?;
    }
    if allow_missing_singleton_initialization {
        conn.execute(
            "INSERT OR IGNORE INTO consensus_operator_recovery (singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, pending_fence_high_water, pending_credential_high_water, watch_cursor_invalidation_floor) VALUES (1, ?1, 0, ?2, NULL, NULL, NULL, NULL, 0)",
            params![epoch_i64(identity)?, [0_u8; 32].as_slice()],
        )
        .map_err(db_error)?;
    }
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

/// Add the versioned receipt columns to pre-receipt databases.
///
/// A legacy row binds only the command digest, not the complete result.  The
/// sole automatic exception is a complete retained revision-zero chain whose
/// every result is independently re-derived as `PayloadTooLarge`: that
/// rejection is decided before any mutable lease, record, or fence lookup.
/// Every successful or state-dependent legacy result remains an
/// operator-recovery concern; it is never promoted into a v2 receipt.
fn ensure_machine_receipt_chain_schema_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    let present = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_machine') WHERE name = 'last_receipt_digest')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(db_error)?;
    if !present {
        // Receipt v2 was not released. A candidate image may lack this
        // parallel head, which is initialized only while its receipts are
        // rebuilt below inside the same opening transaction.
        conn.execute_batch(
            "ALTER TABLE consensus_machine ADD COLUMN last_receipt_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' CHECK (length(last_receipt_digest) = 32);",
        )
        .map_err(db_error)?;
    }
    let digest: Vec<u8> = conn
        .query_row(
            "SELECT last_receipt_digest FROM consensus_machine WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if digest.len() != OUTCOME_RECEIPT_CHAIN_GENESIS.len() {
        return Err(invalid_data(
            "session consensus receipt chain head is invalid",
        ));
    }
    validate_epoch(
        conn.query_row(
            "SELECT configuration_epoch FROM consensus_machine WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?,
        identity,
    )
}

fn ensure_outcome_receipt_schema_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    exact_immediate_predecessor: bool,
) -> io::Result<()> {
    let columns = [
        "receipt_version",
        "receipt_digest",
        "command_json",
        "predecessor_sequence",
        "predecessor_digest",
        "predecessor_logical_time",
        "raft_log_index",
    ];
    let present = columns
        .iter()
        .map(|column| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_request_outcomes') WHERE name = ?1)",
                [column],
                |row| row.get::<_, bool>(0),
            )
            .map_err(db_error)
        })
        .collect::<io::Result<Vec<_>>>()?;
    if present.iter().any(|present| *present) && present.iter().any(|present| !*present) {
        return Err(invalid_data(
            "session consensus outcome receipt schema is partial",
        ));
    }
    let receipt_chain_present = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_request_outcomes') WHERE name = 'predecessor_receipt_digest')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(db_error)?;
    if !present[0] {
        let legacy_schema: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'consensus_request_outcomes'",
                [],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if legacy_schema != LEGACY_CONSENSUS_REQUEST_OUTCOMES_SCHEMA {
            return Err(invalid_data(
                "session consensus legacy outcome receipt schema is invalid",
            ));
        }
        conn.execute_batch(&format!(
            "ALTER TABLE consensus_request_outcomes RENAME TO consensus_request_outcomes_legacy;\n{RECEIPT_CHAIN_CONSENSUS_REQUEST_OUTCOMES_SCHEMA}"
        ))
        .map_err(db_error)?;
        migrate_legacy_outcome_receipts_sync(conn, identity, exact_immediate_predecessor)?;
        conn.execute_batch("DROP TABLE consensus_request_outcomes_legacy;")
            .map_err(db_error)?;
    } else if !receipt_chain_present {
        migrate_current_outcome_receipt_chain_sync(conn, identity)?;
    }
    Ok(())
}

fn migrate_legacy_outcome_receipts_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    exact_immediate_predecessor: bool,
) -> io::Result<()> {
    let mut statement = conn
        .prepare(
            "SELECT request_id, configuration_epoch, payload_digest, response_json \
             FROM consensus_request_outcomes_legacy",
        )
        .map_err(db_error)?;
    let legacy = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    drop(statement);

    let (machine_sequence, machine_digest, _, machine_time, _) = read_machine_sync(conn, identity)?;
    if legacy.is_empty() {
        if machine_sequence != 0
            || machine_digest != SessionConsensusEntryDigest::GENESIS
            || machine_time.is_some()
        {
            return Err(invalid_data(
                "session consensus empty legacy outcome chain is invalid",
            ));
        }
        return Ok(());
    }

    if !exact_immediate_predecessor {
        return Err(invalid_data(
            "session consensus nonempty legacy outcomes require the exact reviewed predecessor",
        ));
    }

    // A migrated legacy chain must begin at the original genesis root.  A
    // non-pristine operator-recovery epoch has a different authority root and
    // belongs to the explicit recovery workflow instead.
    let recovery = read_operator_recovery_sync(conn, identity)?;
    if recovery.recovery_epoch != 0
        || recovery.last_plan_digest != [0; 32]
        || recovery.pending_epoch.is_some()
        || recovery.pending_plan_digest.is_some()
    {
        return Err(invalid_data(
            "session consensus legacy outcomes require operator recovery",
        ));
    }
    let applied = read_applied_sync(conn, identity)?.ok_or_else(|| {
        invalid_data("session consensus legacy outcomes are missing an applied log pointer")
    })?;
    validate_complete_legacy_log_retention_sync(conn, identity, applied.index)?;

    let mut outcomes = Vec::with_capacity(legacy.len());
    for (request_id, epoch, payload_digest, response) in legacy {
        validate_epoch(epoch, identity)?;
        let request_id: [u8; 16] = request_id
            .try_into()
            .map_err(|_| invalid_data("persisted session consensus request ID is invalid"))?;
        let payload_digest: [u8; 32] = payload_digest.try_into().map_err(|_| {
            invalid_data("persisted session consensus request digest has invalid length")
        })?;
        let response: SessionConsensusResponse = decode_json(&response)?;
        outcomes.push((
            SessionConsensusRequestId::from_bytes(request_id),
            payload_digest,
            response,
        ));
    }
    outcomes.sort_by_key(|(_, _, response)| response.sequence);
    if u64::try_from(outcomes.len())
        .map_err(|_| invalid_data("persisted session consensus outcomes exceed integer range"))?
        != machine_sequence
    {
        return Err(invalid_data(
            "session consensus legacy outcome chain is incomplete",
        ));
    }

    let mut predecessor_sequence = 0_u64;
    let mut predecessor_digest = SessionConsensusEntryDigest::GENESIS;
    let mut predecessor_receipt_digest = OUTCOME_RECEIPT_CHAIN_GENESIS;
    let mut predecessor_time: Option<Timestamp> = None;
    let mut previous_raft_log_index = None;
    for (request_id, stored_payload_digest, stored_response) in outcomes {
        let raft_log_index = stored_response.raft_log_index;
        if raft_log_index > applied.index
            || previous_raft_log_index.is_some_and(|previous| raft_log_index <= previous)
        {
            return Err(invalid_data(
                "session consensus legacy outcome chain is invalid",
            ));
        }
        let command = read_exact_retained_legacy_command_sync(conn, identity, raft_log_index)?;
        if command.admission_revision() != SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY
            || command.request_id != request_id
            || payload_digest(&command)? != stored_payload_digest
        {
            return Err(invalid_data(
                "session consensus legacy outcome does not match retained command",
            ));
        }

        let result = rederive_legacy_payload_too_large_result(&command, identity)?;
        let sequence = predecessor_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_data("session consensus sequence exhausted"))?;
        let logical_time = predecessor_time.map_or(command.logical_time, |previous| {
            previous.max(command.logical_time)
        });
        let digest = command
            .calculate_applied_result_digest(
                sequence,
                predecessor_digest,
                logical_time,
                raft_log_index,
                &result,
            )
            .map_err(|_| invalid_data("session consensus legacy command digest failed"))?;
        let response = SessionConsensusResponse {
            result,
            sequence,
            digest: Some(digest),
            logical_time: Some(logical_time),
            raft_log_index,
        };
        if stored_response != response {
            return Err(invalid_data(
                "session consensus legacy outcome is not independently reproducible",
            ));
        }
        let receipt = outcome_receipt_digest(OutcomeReceiptDigestInput {
            request_id: &request_id,
            configuration_epoch: identity.configuration_epoch().get(),
            semantic_command_digest: &stored_payload_digest,
            command: &command,
            predecessor_sequence,
            predecessor_digest: &predecessor_digest,
            predecessor_logical_time: predecessor_time,
            predecessor_receipt_digest: &predecessor_receipt_digest,
            raft_log_index,
            response: &response,
        })?;
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                request_id.as_bytes().as_slice(),
                epoch_i64(identity)?,
                stored_payload_digest.as_slice(),
                encode_json(&command)?,
                checked_i64(predecessor_sequence)?,
                predecessor_digest.as_bytes().as_slice(),
                predecessor_time.map(ops::format_rfc3339_normalized),
                predecessor_receipt_digest.as_slice(),
                checked_i64(raft_log_index)?,
                encode_json(&response)?,
                OUTCOME_RECEIPT_VERSION,
                receipt.as_slice(),
            ],
        )
        .map_err(db_error)?;
        predecessor_sequence = sequence;
        predecessor_digest = digest;
        predecessor_receipt_digest = receipt;
        predecessor_time = Some(logical_time);
        previous_raft_log_index = Some(raft_log_index);
    }
    if predecessor_sequence != machine_sequence
        || predecessor_digest != machine_digest
        || predecessor_time != machine_time
    {
        return Err(invalid_data(
            "session consensus legacy outcome chain head is invalid",
        ));
    }
    let changed = conn
        .execute(
            "UPDATE consensus_machine SET last_receipt_digest = ?1 WHERE singleton = 1 AND configuration_epoch = ?2 AND application_sequence = ?3",
            params![
                predecessor_receipt_digest.as_slice(),
                epoch_i64(identity)?,
                checked_i64(machine_sequence)?,
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data(
            "session consensus legacy machine state is missing",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct PreReceiptChainOutcome {
    request_id: SessionConsensusRequestId,
    payload_digest: [u8; 32],
    command: DurableSessionConsensusCommand,
    predecessor_sequence: u64,
    predecessor_digest: SessionConsensusEntryDigest,
    predecessor_logical_time: Option<Timestamp>,
    raft_log_index: u64,
    response: SessionConsensusResponse,
}

/// Upgrade the only unreleased v2 candidate layout into the result-bearing
/// parallel receipt chain.  The frozen application chain is verified as-is
/// and deliberately never rewritten: legacy-compatible peers retain its old
/// digest semantics.  Receipt links become the independently result-bound
/// authority from this point forward.
fn migrate_current_outcome_receipt_chain_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    let schema: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'consensus_request_outcomes'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if schema != PRE_RECEIPT_CHAIN_CONSENSUS_REQUEST_OUTCOMES_SCHEMA {
        return Err(invalid_data(
            "session consensus pre-receipt-chain outcome schema is invalid",
        ));
    }

    let admission = read_command_admission_sync(conn, identity)?;
    let recovery = read_operator_recovery_sync(conn, identity)?;
    let applied_index = read_applied_sync(conn, identity)?.map(|log_id| log_id.index);
    let (machine_sequence, machine_digest, machine_receipt_digest, machine_time, _) =
        read_machine_sync(conn, identity)?;
    if machine_receipt_digest != OUTCOME_RECEIPT_CHAIN_GENESIS {
        return Err(invalid_data(
            "session consensus pre-receipt-chain machine receipt head is invalid",
        ));
    }

    let mut statement = conn
        .prepare(
            "SELECT request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, raft_log_index, response_json, receipt_version, receipt_digest FROM consensus_request_outcomes",
        )
        .map_err(db_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Vec<u8>>(10)?,
            ))
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    drop(statement);

    let mut outcomes = Vec::with_capacity(rows.len());
    for (
        request_id,
        epoch,
        payload,
        command,
        predecessor_sequence,
        predecessor_digest,
        predecessor_time,
        raft_log_index,
        response,
        receipt_version,
        receipt_digest,
    ) in rows
    {
        validate_epoch(epoch, identity)?;
        if receipt_version != OUTCOME_RECEIPT_VERSION {
            return Err(invalid_data(
                "session consensus pre-receipt-chain receipt version is invalid",
            ));
        }
        let request_id = request_id
            .try_into()
            .map(SessionConsensusRequestId::from_bytes)
            .map_err(|_| invalid_data("persisted session consensus request ID is invalid"))?;
        let stored_payload_digest: [u8; 32] = payload.try_into().map_err(|_| {
            invalid_data("persisted session consensus request digest has invalid length")
        })?;
        let command: DurableSessionConsensusCommand = decode_json(&command)?;
        // Legacy application digests are command-only.  A candidate row with
        // revision zero therefore cannot prove its result and must take the
        // explicit recovery route instead of being blessed into receipt v2.
        if command.admission_revision() != SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_CURRENT
            || command.request_id != request_id
            || command.identity != identity
            || payload_digest(&command)? != stored_payload_digest
        {
            return Err(invalid_data(
                "session consensus pre-receipt-chain command is invalid",
            ));
        }
        let predecessor_sequence = checked_u64(predecessor_sequence)?;
        let predecessor_digest = SessionConsensusEntryDigest::from_bytes(
            predecessor_digest.try_into().map_err(|_| {
                invalid_data("persisted session consensus predecessor digest has invalid length")
            })?,
        );
        let predecessor_logical_time = predecessor_time
            .map(|value| {
                ops::parse_persisted_rfc3339_normalized(&value).map_err(|_| {
                    invalid_data("persisted session consensus predecessor logical time is invalid")
                })
            })
            .transpose()?;
        let raft_log_index = checked_u64(raft_log_index)?;
        let response: SessionConsensusResponse = decode_json(&response)?;
        validate_outcome_against_retained_log_sync(conn, identity, raft_log_index, &command)?;
        validate_persisted_command_admission(&command, identity, raft_log_index, admission)?;
        let effective_time = predecessor_logical_time.map_or(command.logical_time, |previous| {
            previous.max(command.logical_time)
        });
        if response.sequence
            != predecessor_sequence
                .checked_add(1)
                .ok_or_else(|| invalid_data("persisted session consensus sequence exhausted"))?
            || response.logical_time != Some(effective_time)
            || response.raft_log_index != raft_log_index
            || response.digest
                != Some(
                    command
                        .calculate_applied_result_digest(
                            response.sequence,
                            predecessor_digest,
                            effective_time,
                            raft_log_index,
                            &response.result,
                        )
                        .map_err(|_| {
                            invalid_data("persisted session consensus outcome digest is invalid")
                        })?,
                )
        {
            return Err(invalid_data(
                "session consensus pre-receipt-chain outcome metadata is invalid",
            ));
        }
        validate_response_for_command(&command, &response)?;
        if let Ok(outcome) = &response.result {
            validate_consensus_outcome_records(outcome).map_err(|_| {
                invalid_data("persisted session consensus outcome record is invalid")
            })?;
        }
        let receipt_digest: [u8; 32] = receipt_digest.try_into().map_err(|_| {
            invalid_data("persisted session consensus outcome receipt has invalid length")
        })?;
        if receipt_digest
            != outcome_receipt_digest_without_receipt_chain(
                OutcomeReceiptDigestWithoutChainInput {
                    request_id: &request_id,
                    configuration_epoch: identity.configuration_epoch().get(),
                    semantic_command_digest: &stored_payload_digest,
                    command: &command,
                    predecessor_sequence,
                    predecessor_digest: &predecessor_digest,
                    predecessor_logical_time,
                    raft_log_index,
                    response: &response,
                },
            )?
        {
            return Err(invalid_data(
                "session consensus pre-receipt-chain outcome receipt is invalid",
            ));
        }
        outcomes.push(PreReceiptChainOutcome {
            request_id,
            payload_digest: stored_payload_digest,
            command,
            predecessor_sequence,
            predecessor_digest,
            predecessor_logical_time,
            raft_log_index,
            response,
        });
    }

    outcomes.sort_by_key(|outcome| outcome.response.sequence);
    let recovery_root = outcome_chain_recovery_root(recovery);
    let (root_digest, root_time) = match outcomes.first() {
        Some(outcome)
            if outcome.predecessor_sequence == 0
                && outcome.predecessor_digest == SessionConsensusEntryDigest::GENESIS
                && outcome.predecessor_logical_time.is_none() =>
        {
            (SessionConsensusEntryDigest::GENESIS, None)
        }
        Some(outcome)
            if outcome.predecessor_sequence == 0
                && recovery_root == Some(*outcome.predecessor_digest.as_bytes()) =>
        {
            (outcome.predecessor_digest, outcome.predecessor_logical_time)
        }
        Some(_) => {
            return Err(invalid_data(
                "session consensus pre-receipt-chain outcome root is invalid",
            ));
        }
        None if machine_sequence == 0
            && machine_digest == SessionConsensusEntryDigest::GENESIS
            && machine_time.is_none() =>
        {
            (SessionConsensusEntryDigest::GENESIS, None)
        }
        None if machine_sequence == 0 && recovery_root == Some(*machine_digest.as_bytes()) => {
            (machine_digest, machine_time)
        }
        None => {
            return Err(invalid_data(
                "session consensus pre-receipt-chain empty outcome head is invalid",
            ));
        }
    };
    if u64::try_from(outcomes.len())
        .map_err(|_| invalid_data("persisted session consensus outcomes exceed integer range"))?
        != machine_sequence
    {
        return Err(invalid_data(
            "session consensus pre-receipt-chain outcome chain is incomplete",
        ));
    }
    let mut previous_raft_log_index = None;
    let mut found_cutover_receipt = false;
    for (position, outcome) in outcomes.iter().enumerate() {
        let expected_sequence = u64::try_from(position)
            .map_err(|_| invalid_data("persisted session consensus outcomes exceed integer range"))?
            .checked_add(1)
            .ok_or_else(|| invalid_data("persisted session consensus sequence exhausted"))?;
        let (expected_digest, expected_time) = if position == 0 {
            (root_digest, root_time)
        } else {
            let previous = &outcomes[position - 1].response;
            (
                previous.digest.ok_or_else(|| {
                    invalid_data("persisted session consensus outcome metadata is invalid")
                })?,
                previous.logical_time,
            )
        };
        if outcome.response.sequence != expected_sequence
            || outcome.predecessor_sequence != expected_sequence - 1
            || outcome.predecessor_digest != expected_digest
            || outcome.predecessor_logical_time != expected_time
            || previous_raft_log_index.is_some_and(|previous| outcome.raft_log_index <= previous)
            || applied_index.is_none_or(|applied| outcome.raft_log_index > applied)
        {
            return Err(invalid_data(
                "session consensus pre-receipt-chain outcome chain is invalid",
            ));
        }
        previous_raft_log_index = Some(outcome.raft_log_index);
        if admission.cutover_committed
            && outcome.request_id.as_bytes()
                == &crate::consensus::SESSION_CONSENSUS_COMMAND_ADMISSION_CUTOVER_REQUEST_ID
            && outcome.raft_log_index.checked_add(1) == Some(admission.strict_activation_index)
            && matches!(outcome.response.result, Ok(SessionMutationOutcome::Unit))
        {
            found_cutover_receipt = true;
        }
    }
    if let Some(last) = outcomes.last() {
        if last.response.digest != Some(machine_digest)
            || last.response.logical_time != machine_time
        {
            return Err(invalid_data(
                "session consensus pre-receipt-chain outcome head is invalid",
            ));
        }
    } else if machine_sequence != 0 || machine_digest != root_digest || machine_time != root_time {
        return Err(invalid_data(
            "session consensus pre-receipt-chain empty outcome head is invalid",
        ));
    }
    if admission.cutover_committed && !found_cutover_receipt {
        return Err(invalid_data(
            "session consensus pre-receipt-chain admission cutover receipt is missing",
        ));
    }

    conn.execute_batch(&format!(
        "ALTER TABLE consensus_request_outcomes RENAME TO consensus_request_outcomes_pre_receipt_chain;\n{RECEIPT_CHAIN_CONSENSUS_REQUEST_OUTCOMES_SCHEMA}"
    ))
    .map_err(db_error)?;
    let mut predecessor_receipt_digest = OUTCOME_RECEIPT_CHAIN_GENESIS;
    for outcome in outcomes {
        let receipt_digest = outcome_receipt_digest(OutcomeReceiptDigestInput {
            request_id: &outcome.request_id,
            configuration_epoch: identity.configuration_epoch().get(),
            semantic_command_digest: &outcome.payload_digest,
            command: &outcome.command,
            predecessor_sequence: outcome.predecessor_sequence,
            predecessor_digest: &outcome.predecessor_digest,
            predecessor_logical_time: outcome.predecessor_logical_time,
            predecessor_receipt_digest: &predecessor_receipt_digest,
            raft_log_index: outcome.raft_log_index,
            response: &outcome.response,
        })?;
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                outcome.request_id.as_bytes().as_slice(),
                epoch_i64(identity)?,
                outcome.payload_digest.as_slice(),
                encode_json(&outcome.command)?,
                checked_i64(outcome.predecessor_sequence)?,
                outcome.predecessor_digest.as_bytes().as_slice(),
                outcome.predecessor_logical_time.map(ops::format_rfc3339_normalized),
                predecessor_receipt_digest.as_slice(),
                checked_i64(outcome.raft_log_index)?,
                encode_json(&outcome.response)?,
                OUTCOME_RECEIPT_VERSION,
                receipt_digest.as_slice(),
            ],
        )
        .map_err(db_error)?;
        predecessor_receipt_digest = receipt_digest;
    }
    let changed = conn
        .execute(
            "UPDATE consensus_machine SET last_receipt_digest = ?1 WHERE singleton = 1 AND configuration_epoch = ?2 AND application_sequence = ?3",
            params![
                predecessor_receipt_digest.as_slice(),
                epoch_i64(identity)?,
                checked_i64(machine_sequence)?,
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data(
            "session consensus pre-receipt-chain machine state is missing",
        ));
    }
    conn.execute_batch("DROP TABLE consensus_request_outcomes_pre_receipt_chain;")
        .map_err(db_error)?;
    Ok(())
}

/// Complete retained history is required to qualify the one automatic legacy
/// upgrade path.  A compacted log leaves the old command-only cache unable to
/// prove what happened, even for a syntactically plausible rejection.
fn validate_complete_legacy_log_retention_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    applied_index: u64,
) -> io::Result<()> {
    if read_purged_sync(conn, identity)?.is_some() {
        return Err(invalid_data(
            "session consensus legacy outcomes require retained logs",
        ));
    }
    let mut statement = conn
        .prepare(
            "SELECT configuration_epoch, term, log_index, entry_json \
             FROM consensus_log WHERE log_index <= ?1 ORDER BY log_index ASC",
        )
        .map_err(db_error)?;
    let mut rows = statement
        .query([checked_i64(applied_index)?])
        .map_err(db_error)?;
    let mut expected_index = 0_u64;
    let mut saw_applied = false;
    while let Some(row) = rows.next().map_err(db_error)? {
        let epoch: i64 = row.get(0).map_err(db_error)?;
        let term: i64 = row.get(1).map_err(db_error)?;
        let index: i64 = row.get(2).map_err(db_error)?;
        let encoded: Vec<u8> = row.get(3).map_err(db_error)?;
        validate_epoch(epoch, identity)?;
        let index = checked_u64(index)?;
        let entry: Entry<SessionRaftTypeConfig> = decode_json(&encoded)?;
        if index != expected_index
            || entry.log_id.index != index
            || checked_u64(term)? != entry.log_id.leader_id.term
        {
            return Err(invalid_data(
                "persisted session consensus legacy log is not complete",
            ));
        }
        if index == applied_index {
            saw_applied = true;
            break;
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or_else(|| invalid_data("session consensus log index exhausted"))?;
    }
    if !saw_applied {
        return Err(invalid_data(
            "persisted session consensus legacy log is not complete",
        ));
    }
    Ok(())
}

/// Read the exact command at a retained legacy outcome index.  Unlike current
/// receipt validation, absence is not tolerated here because this function is
/// constructing the first result-bound receipt for the command.
fn read_exact_retained_legacy_command_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    raft_log_index: u64,
) -> io::Result<DurableSessionConsensusCommand> {
    let (epoch, term, index, encoded): (i64, i64, i64, Vec<u8>) = conn
        .query_row(
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index = ?1",
            [checked_i64(raft_log_index)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    let entry: Entry<SessionRaftTypeConfig> = decode_json(&encoded)?;
    if checked_u64(index)? != raft_log_index
        || entry.log_id.index != raft_log_index
        || checked_u64(term)? != entry.log_id.leader_id.term
    {
        return Err(invalid_data(
            "persisted session consensus legacy retained log row is invalid",
        ));
    }
    match entry.payload {
        // A missing `admission_revision` in the frozen JSON decodes to this
        // revision-zero command by design; serializing the v2 receipt writes
        // its explicit canonical value without changing the old chain digest.
        EntryPayload::Normal(command) => Ok(command),
        _ => Err(invalid_data(
            "persisted session consensus legacy outcome is not a normal log command",
        )),
    }
}

/// Independently derive the sole non-stateful legacy result that can be
/// migrated.  The ordinary command validator checks the frozen command shape
/// and envelope under legacy admission; the central record validator then
/// produces the exact current payload limit.  Structural CAS checks are all
/// earlier than the stateful lease/fence lookups in `compare_and_set_sync`.
fn rederive_legacy_payload_too_large_result(
    command: &DurableSessionConsensusCommand,
    identity: SessionConsensusIdentity,
) -> io::Result<Result<SessionMutationOutcome, StoreError>> {
    validate_command_for_log_with_cap(command, identity, false)?;
    let SessionMutationIntent::CompareAndSet(operation) = &command.intent else {
        return Err(invalid_data(
            "session consensus legacy outcome is not a payload rejection command",
        ));
    };
    if operation.lease.key() != &operation.key
        || operation.new_record.key != operation.key
        || operation.new_record.owner != *operation.lease.owner()
        || operation.new_record.fence != operation.lease.fence()
    {
        return Err(invalid_data(
            "session consensus legacy payload rejection command is invalid",
        ));
    }
    match super::validate_consensus_record(&operation.new_record) {
        Err(error) if is_base_admitted_legacy_payload_too_large(&error) => Ok(Err(error)),
        _ => Err(invalid_data(
            "session consensus legacy outcome is not an independently reproducible payload rejection",
        )),
    }
}

/// Ensure the durable admission state exists. Strict admission begins only
/// once the replicated cutover marker commits; that marker is the portable
/// proof followers and snapshots use to distinguish the retained legacy
/// prefix from current traffic.
fn install_command_admission_schema_sync(conn: &Connection) -> io::Result<()> {
    if table_exists(conn, "consensus_command_admission").map_err(db_error)? {
        return Ok(());
    }
    let canonical = SqliteSessionBackend::canonical_schema_connection()
        .map_err(|_| io::Error::other("session consensus canonical schema is unavailable"))?;
    install_recovery_validation_schema_sync(&canonical, false)?;
    let ddl: String = canonical
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'consensus_command_admission'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    conn.execute_batch(&ddl).map_err(db_error)
}

fn ensure_command_admission_schema_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    allow_missing_singleton_initialization: bool,
) -> io::Result<()> {
    let exists = table_exists(conn, "consensus_command_admission").map_err(db_error)?;
    if !exists {
        install_command_admission_schema_sync(conn)?;
    }
    if allow_missing_singleton_initialization {
        // Seed only a fresh database or an exact supported source manifest
        // whose complete inventory lacked this table. An existing authority
        // table with a deleted singleton must fail closed below.
        conn.execute(
            "INSERT INTO consensus_command_admission (singleton, configuration_epoch, admission_revision, strict_activation_index, cutover_committed) VALUES (1, ?1, ?2, ?3, 0)",
            params![
                epoch_i64(identity)?,
                COMMAND_ADMISSION_REVISION,
                0_i64,
            ],
        )
        .map_err(db_error)?;
    }
    read_command_admission_sync(conn, identity).map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OperatorRecoveryState {
    pub(crate) recovery_epoch: u64,
    pub(crate) last_plan_digest: [u8; 32],
    pub(crate) pending_epoch: Option<u64>,
    pub(crate) pending_plan_digest: Option<[u8; 32]>,
    pub(crate) pending_fence_high_water: Option<u64>,
    pub(crate) pending_credential_high_water: Option<u64>,
    pub(crate) watch_cursor_invalidation_floor: u64,
}

/// Return the sole plan digest that can root a receipt chain at sequence zero.
///
/// A first explicit legacy claim has no finalized recovery epoch, so its
/// pending plan is the fresh chain root. Once a recovery epoch is finalized,
/// a later verified-majority repair preserves that chain and its pending plan
/// only fences the repair; accepting that newer digest would permit a receipt
/// root rewrite without a command/result receipt.
fn outcome_chain_recovery_root(recovery: OperatorRecoveryState) -> Option<[u8; 32]> {
    if recovery.recovery_epoch > 0 {
        Some(recovery.last_plan_digest)
    } else {
        recovery.pending_plan_digest
    }
}

type StoredOperatorRecoveryRow = (
    i64,
    i64,
    Vec<u8>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    i64,
);

type LegacyOperatorRecoveryWithCursorRow = (i64, i64, Vec<u8>, Option<i64>, Option<Vec<u8>>, i64);

type MachineState = (
    u64,
    SessionConsensusEntryDigest,
    [u8; 32],
    Option<Timestamp>,
    u64,
);

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
            pending_fence_high_water: None,
            pending_credential_high_water: None,
            watch_cursor_invalidation_floor: 0,
        });
    }
    let row: StoredOperatorRecoveryRow = if operator_recovery_pending_high_water_columns(conn)?
        == (true, true)
    {
        conn.query_row(
            "SELECT configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, pending_fence_high_water, pending_credential_high_water, watch_cursor_invalidation_floor FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
        )
        .map_err(db_error)?
    } else {
        let (has_fence, has_credential) = operator_recovery_pending_high_water_columns(conn)?;
        if has_fence || has_credential {
            return Err(invalid_data(
                "session consensus operator recovery high-water binding is incomplete",
            ));
        }
        if operator_recovery_cursor_column_exists(conn)? {
            let legacy: LegacyOperatorRecoveryWithCursorRow = conn
                .query_row(
                    "SELECT configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor FROM consensus_operator_recovery WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
                )
                .map_err(db_error)?;
            (
                legacy.0, legacy.1, legacy.2, legacy.3, legacy.4, None, None, legacy.5,
            )
        } else {
            let legacy: (i64, i64, Vec<u8>, Option<i64>, Option<Vec<u8>>) = conn
                .query_row(
                    "SELECT configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest FROM consensus_operator_recovery WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .map_err(db_error)?;
            (
                legacy.0, legacy.1, legacy.2, legacy.3, legacy.4, None, None, 0,
            )
        }
    };
    let (
        stored_epoch,
        recovery_epoch,
        last_digest,
        pending_epoch,
        pending_digest,
        pending_fence,
        pending_credential,
        cursor_floor,
    ) = row;
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
    let pending_fence_high_water = pending_fence.map(checked_u64).transpose()?;
    let pending_credential_high_water = pending_credential.map(checked_u64).transpose()?;
    if (recovery_epoch == 0) != (last_plan_digest == [0; 32]) {
        return Err(invalid_data(
            "session consensus recovery authority state is invalid",
        ));
    }
    if pending_plan_digest.is_some_and(|digest| digest == [0; 32])
        || pending_epoch.is_some() != pending_plan_digest.is_some()
        || pending_epoch.is_some() != pending_fence_high_water.is_some()
        || pending_epoch.is_some() != pending_credential_high_water.is_some()
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
        pending_fence_high_water,
        pending_credential_high_water,
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

fn operator_recovery_pending_high_water_columns(conn: &Connection) -> io::Result<(bool, bool)> {
    let (fence, credential): (bool, bool) = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_operator_recovery') WHERE name = 'pending_fence_high_water'), EXISTS(SELECT 1 FROM pragma_table_info('consensus_operator_recovery') WHERE name = 'pending_credential_high_water')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db_error)?;
    Ok((fence, credential))
}

fn validate_nonzero_operator_recovery_plan_digest(plan_digest: [u8; 32]) -> io::Result<()> {
    if plan_digest == [0; 32] {
        return Err(invalid_data(
            "session consensus recovery plan digest must be nonzero",
        ));
    }
    Ok(())
}

pub(crate) fn mark_operator_recovery_pending_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    pending_epoch: u64,
    plan_digest: [u8; 32],
    fence_high_water: u64,
    credential_high_water: u64,
) -> io::Result<()> {
    validate_nonzero_operator_recovery_plan_digest(plan_digest)?;
    validate_operator_recovery_high_water(fence_high_water)?;
    validate_operator_recovery_high_water(credential_high_water)?;
    checked_positive_i64(pending_epoch)?;
    ensure_operator_recovery_schema_sync(conn, identity)?;
    let current = read_operator_recovery_sync(conn, identity)?;
    match (
        current.pending_epoch,
        current.pending_plan_digest,
        current.pending_fence_high_water,
        current.pending_credential_high_water,
    ) {
        (Some(epoch), Some(digest), Some(fence), Some(credential))
            if epoch == pending_epoch
                && digest == plan_digest
                && fence == fence_high_water
                && credential == credential_high_water =>
        {
            return Ok(());
        }
        (Some(_), Some(_), Some(_), Some(_)) => {
            return Err(invalid_data(
                "a different session operator recovery workflow is already pending",
            ));
        }
        (None, None, None, None) => {}
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
        "UPDATE consensus_operator_recovery SET pending_epoch = ?1, pending_plan_digest = ?2, pending_fence_high_water = ?3, pending_credential_high_water = ?4 WHERE singleton = 1 AND configuration_epoch = ?5",
        params![
            checked_positive_i64(pending_epoch)?,
            plan_digest.as_slice(),
            checked_i64(fence_high_water)?,
            checked_i64(credential_high_water)?,
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
    validate_nonzero_operator_recovery_plan_digest(plan_digest)?;
    validate_operator_recovery_high_water(fence_high_water)?;
    validate_operator_recovery_high_water(credential_high_water)?;
    checked_positive_i64(recovery_epoch)?;
    ensure_operator_recovery_schema_sync(conn, identity)?;
    let current = read_operator_recovery_sync(conn, identity)?;
    match (
        current.pending_epoch,
        current.pending_plan_digest,
        current.pending_fence_high_water,
        current.pending_credential_high_water,
    ) {
        (
            Some(pending_epoch),
            Some(pending_digest),
            Some(pending_fence),
            Some(pending_credential),
        ) => {
            if pending_epoch != recovery_epoch
                || pending_digest != plan_digest
                || pending_fence != fence_high_water
                || pending_credential != credential_high_water
            {
                return Ok(OperatorRecoveryApply::Rejected);
            }
        }
        (None, None, None, None) => {
            return Ok(
                if current.recovery_epoch == recovery_epoch
                    && current.last_plan_digest == plan_digest
                {
                    OperatorRecoveryApply::Idempotent
                } else {
                    OperatorRecoveryApply::Rejected
                },
            );
        }
        _ => {
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
            "UPDATE consensus_operator_recovery SET recovery_epoch = ?1, last_plan_digest = ?2, pending_epoch = NULL, pending_plan_digest = NULL, pending_fence_high_water = NULL, pending_credential_high_water = NULL WHERE singleton = 1 AND configuration_epoch = ?3",
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

/// A recovery high-water must leave one SQLite-positive allocator value for
/// the next lease or credential.  Checking this before Raft admission keeps a
/// malformed authenticated follower command from becoming a deterministic
/// state-machine fault later.
fn validate_operator_recovery_high_water(value: u64) -> io::Result<()> {
    if value >= i64::MAX as u64 {
        return Err(invalid_data(
            "session recovery high-water exhausts the SQLite allocator",
        ));
    }
    Ok(())
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

#[cfg(test)]
std::thread_local! {
    static LEGACY_CLAIM_AFTER_VALIDATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn install_legacy_claim_after_validation_hook(hook: impl FnOnce() + 'static) {
    LEGACY_CLAIM_AFTER_VALIDATION_HOOK.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "legacy claim test hook already installed"
        );
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_legacy_claim_after_validation_hook() {
    let hook = LEGACY_CLAIM_AFTER_VALIDATION_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn claim_legacy_checkpoint_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    recovery_root_digest: [u8; 32],
    pending_recovery_epoch: u64,
    plan_digest: [u8; 32],
    fence_high_water: u64,
    credential_high_water: u64,
    application_sequence_high_water: u64,
    watch_cursor_invalidation_floor: u64,
    recovery_root_time: Option<Timestamp>,
) -> io::Result<()> {
    validate_member_set(expected_members, false)?;
    validate_nonzero_operator_recovery_plan_digest(plan_digest)?;
    validate_operator_recovery_high_water(fence_high_water)?;
    validate_operator_recovery_high_water(credential_high_water)?;
    checked_positive_i64(pending_recovery_epoch)?;
    if recovery_root_digest == [0; 32] || recovery_root_digest != plan_digest {
        return Err(invalid_data(
            "session recovery receipt root is not bound to the operator plan",
        ));
    }
    // The caller already preflights this high-water with every other plan
    // value.  Keep the range check here too: a direct caller must not use a
    // narrowing conversion to turn an exhausted historical chain into a
    // plausible reset checkpoint.
    checked_i64(application_sequence_high_water)?;
    // Acquire write authority before inspecting the legacy checkpoint. Keeping
    // validation and ownership installation in one transaction prevents a
    // concurrent legacy writer from changing the admitted state between the
    // sealed-state preflight and the consensus fence.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    if table_exists(&tx, "consensus_identity").map_err(db_error)? {
        return Err(invalid_data(
            "session recovery checkpoint is already consensus-owned",
        ));
    }
    validate_sealed_state_sync(&tx)?;
    #[cfg(test)]
    run_legacy_claim_after_validation_hook();
    // A reviewed immediate predecessor already has a sealed machine clock.
    // Preserve that authoritative clock when the recovery coordinator supplied
    // it; a standalone legacy source has no such field, so it falls back to
    // the final validated replication event. The old replay cache is never
    // used as a time source.
    let logical_time = match recovery_root_time {
        Some(value) => Some(value),
        None => tx
            .query_row(
                "SELECT timestamp FROM session_replication_log ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(db_error)?
            .map(|value| {
                ops::parse_persisted_rfc3339_normalized(&value)
                    .map_err(|_| invalid_data("legacy checkpoint logical time is invalid"))
            })
            .transpose()?,
    };
    if let Some(reference) = logical_time {
        validate_record_expiry_bounds_at_sync(&tx, reference)?;
    } else {
        let finite_records: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM session_records WHERE expires_at IS NOT NULL)",
                [],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if finite_records {
            return Err(invalid_data(
                "legacy checkpoint finite record expiry has no replication time authority",
            ));
        }
    }

    tx.execute_batch(CONSENSUS_SCHEMA).map_err(db_error)?;
    let epoch = epoch_i64(identity)?;
    tx.execute(
        "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch, authority_profile) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
            identity.cluster_id().as_bytes().as_slice(),
            identity.configuration_id().as_bytes().as_slice(),
            epoch,
            authority_profile_i64(ConsensusAuthorityProfile::Dynamic),
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
        "INSERT INTO consensus_command_admission (singleton, configuration_epoch, admission_revision, strict_activation_index, cutover_committed) VALUES (1, ?1, ?2, 0, 0)",
        params![epoch, COMMAND_ADMISSION_REVISION],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO consensus_machine (singleton, configuration_epoch, application_sequence, last_digest, last_receipt_digest, logical_time, watch_sequence) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            epoch,
            0_i64,
            recovery_root_digest.as_slice(),
            OUTCOME_RECEIPT_CHAIN_GENESIS.as_slice(),
            logical_time.map(ops::format_rfc3339_normalized),
            checked_i64(watch_cursor_invalidation_floor)?,
        ],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO consensus_operator_recovery (singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, pending_fence_high_water, pending_credential_high_water, watch_cursor_invalidation_floor) VALUES (1, ?1, 0, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            epoch,
            [0_u8; 32].as_slice(),
            checked_positive_i64(pending_recovery_epoch)?,
            plan_digest.as_slice(),
            checked_i64(fence_high_water)?,
            checked_i64(credential_high_water)?,
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
        true,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandAdmission {
    strict_activation_index: u64,
    cutover_committed: bool,
}

fn read_command_admission_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<CommandAdmission> {
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM consensus_command_admission",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if rows != 1 {
        return Err(invalid_data(
            "session consensus command admission state is invalid",
        ));
    }
    let (epoch, revision, activation, cutover_committed): (i64, i64, i64, i64) = conn
        .query_row(
            "SELECT configuration_epoch, admission_revision, strict_activation_index, cutover_committed FROM consensus_command_admission WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    if revision != COMMAND_ADMISSION_REVISION {
        return Err(invalid_data(
            "session consensus command admission revision is invalid",
        ));
    }
    let strict_activation_index = checked_u64(activation)?;
    let cutover_committed = match cutover_committed {
        0 => false,
        1 => true,
        _ => {
            return Err(invalid_data(
                "session consensus command admission state is invalid",
            ));
        }
    };
    if (!cutover_committed && strict_activation_index != 0)
        || (cutover_committed && strict_activation_index == 0)
    {
        return Err(invalid_data(
            "session consensus command admission boundary is invalid",
        ));
    }
    Ok(CommandAdmission {
        strict_activation_index,
        cutover_committed,
    })
}

pub(crate) fn command_admission_cutover_committed_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<bool> {
    read_command_admission_sync(conn, identity).map(|admission| admission.cutover_committed)
}

fn validate_command_for_entry(
    command: &DurableSessionConsensusCommand,
    identity: SessionConsensusIdentity,
    log_index: u64,
    admission: CommandAdmission,
) -> io::Result<()> {
    let is_cutover = command.is_command_admission_cutover();
    if is_cutover {
        // The fixed SDK-internal request ID makes retries of the marker
        // idempotent.  The first marker establishes the boundary; later
        // strict-revision retries are ordinary duplicate commands and must
        // not move it.  This matters because callers cannot safely infer from
        // volatile routing state whether an earlier attempt committed.
        let boundary_matches = if admission.cutover_committed {
            log_index
                .checked_add(1)
                .is_some_and(|next| next >= admission.strict_activation_index)
        } else {
            admission.strict_activation_index == 0
        };
        if command.admission_revision() != SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_CURRENT
            || !boundary_matches
        {
            return Err(invalid_data(
                "session consensus command admission cutover is invalid",
            ));
        }
        return validate_command_for_log_with_cap(command, identity, true);
    }
    if !admission.cutover_committed {
        if command.admission_revision() != SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY {
            return Err(invalid_data(
                "session consensus command admission cutover is required",
            ));
        }
        return validate_command_for_log_with_cap(command, identity, false);
    }
    let marker_index = admission
        .strict_activation_index
        .checked_sub(1)
        .ok_or_else(|| invalid_data("session consensus command admission boundary is invalid"))?;
    match command.admission_revision() {
        SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY if log_index < marker_index => {
            validate_command_for_log_with_cap(command, identity, false)
        }
        SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_CURRENT
            if log_index >= admission.strict_activation_index =>
        {
            validate_command_for_log_with_cap(command, identity, true)
        }
        _ => Err(invalid_data(
            "session consensus command admission revision is unsupported",
        )),
    }
}

/// Validate a retained outcome's serialized command against the durable
/// cutover proof. Unlike live admission, a closed cutover still permits a
/// legacy command only when its original Raft position proves it belongs to
/// the legacy prefix.
fn validate_persisted_command_admission(
    command: &DurableSessionConsensusCommand,
    identity: SessionConsensusIdentity,
    raft_log_index: u64,
    admission: CommandAdmission,
) -> io::Result<()> {
    let is_cutover = command.is_command_admission_cutover();
    if is_cutover {
        if !admission.cutover_committed
            || command.admission_revision() != SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_CURRENT
            || raft_log_index.checked_add(1) != Some(admission.strict_activation_index)
        {
            return Err(invalid_data(
                "persisted session consensus admission cutover is invalid",
            ));
        }
        return validate_command_for_log_with_cap(command, identity, true);
    }
    if !admission.cutover_committed {
        if command.admission_revision() != SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY {
            return Err(invalid_data(
                "persisted session consensus admission cutover is required",
            ));
        }
        return validate_command_for_log_with_cap(command, identity, false);
    }
    let marker_index = admission
        .strict_activation_index
        .checked_sub(1)
        .ok_or_else(|| invalid_data("session consensus command admission boundary is invalid"))?;
    match command.admission_revision() {
        SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_LEGACY if raft_log_index < marker_index => {
            validate_command_for_log_with_cap(command, identity, false)
        }
        SESSION_CONSENSUS_COMMAND_ADMISSION_REVISION_CURRENT
            if raft_log_index >= admission.strict_activation_index =>
        {
            validate_command_for_log_with_cap(command, identity, true)
        }
        _ => Err(invalid_data(
            "persisted session consensus command admission is invalid",
        )),
    }
}

fn validate_command_for_log_with_cap(
    command: &DurableSessionConsensusCommand,
    identity: SessionConsensusIdentity,
    enforce_payload_cap: bool,
) -> io::Result<()> {
    if command.schema_version != SESSION_CONSENSUS_SCHEMA_VERSION {
        return Err(invalid_data("unsupported session consensus command schema"));
    }
    if command.identity != identity {
        return Err(invalid_data("session consensus command identity mismatch"));
    }
    let is_cutover = command.is_command_admission_cutover();
    let uses_cutover_request_id = command.request_id.as_bytes()
        == &crate::consensus::SESSION_CONSENSUS_COMMAND_ADMISSION_CUTOVER_REQUEST_ID;
    if is_cutover {
        if !uses_cutover_request_id {
            return Err(invalid_data(
                "session consensus command admission cutover is not canonical",
            ));
        }
    } else if uses_cutover_request_id {
        return Err(invalid_data(
            "session consensus command admission cutover request ID is reserved",
        ));
    }
    if let SessionMutationIntent::FinalizeOperatorRecovery {
        recovery_epoch,
        plan_digest,
        fence_high_water,
        credential_high_water,
    } = &command.intent
    {
        if *recovery_epoch == 0
            || *recovery_epoch > i64::MAX as u64
            || plan_digest.iter().all(|byte| *byte == 0)
            || *fence_high_water >= i64::MAX as u64
            || *credential_high_water >= i64::MAX as u64
        {
            return Err(invalid_data(
                "session consensus operator recovery command is invalid",
            ));
        }
    }
    let semantic_intent = match &command.intent {
        SessionMutationIntent::Authorized { mutation, .. } => {
            if matches!(
                mutation.as_ref(),
                SessionMutationIntent::FinalizeOperatorRecovery { .. }
                    | SessionMutationIntent::PrepareTopologyTransition { .. }
                    | SessionMutationIntent::MarkTopologyLearnersReady { .. }
                    | SessionMutationIntent::FenceTopologyAuthority { .. }
                    | SessionMutationIntent::AbortTopologyTransition { .. }
                    | SessionMutationIntent::FinalizeTopologyTransition { .. }
            ) {
                return Err(invalid_data(
                    "session consensus authorized control intent is invalid",
                ));
            }
            mutation.as_ref()
        }
        intent => intent,
    };
    if matches!(semantic_intent, SessionMutationIntent::Authorized { .. }) {
        return Err(invalid_data(
            "session consensus authorized intent nesting is invalid",
        ));
    }
    crate::consensus::types::validate_mutation_intent_profile(semantic_intent)
        .map_err(|_| invalid_data("session consensus mutation profile is invalid"))?;
    if let SessionMutationIntent::CompareAndSet(op) = semantic_intent {
        crate::ttl::validate_stored_record_expiry_at(&op.new_record, command.logical_time)
            .map_err(|_| invalid_data("session consensus record expiry is invalid"))?;
        match super::validate_consensus_record(&op.new_record) {
            Ok(()) => {}
            Err(error)
                if !enforce_payload_cap && is_base_admitted_legacy_payload_too_large(&error) =>
            {
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
            Err(StoreError::PayloadTooLarge { .. }) => {
                return Err(invalid_data(
                    "session consensus record payload exceeds the consensus limit",
                ));
            }
            Err(StoreError::Crypto(_))
                if op.new_record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 =>
            {
                return Err(invalid_data(
                    "session consensus requires a sealed record payload",
                ));
            }
            Err(_) => return Err(invalid_data("session consensus record envelope is invalid")),
        }
    }
    Ok(())
}

/// Whether a current cap rejection is the sole rejection that the frozen base
/// release could have committed.  Retained revision-zero log validation and
/// legacy receipt migration must make this same exact decision.
fn is_base_admitted_legacy_payload_too_large(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::PayloadTooLarge { actual, max }
            if *actual == BASE_ADMITTED_LEGACY_PAYLOAD_BYTES
                && *max == BASE_ADVERTISED_LEGACY_PAYLOAD_MAX_BYTES
    )
}

fn validate_entry_for_membership_scope(
    entry: &Entry<SessionRaftTypeConfig>,
    storage_identity: SessionConsensusIdentity,
    scope: &MembershipValidationScope,
    admission: CommandAdmission,
) -> io::Result<()> {
    match &entry.payload {
        EntryPayload::Normal(command) => {
            validate_command_for_entry(command, storage_identity, entry.log_id.index, admission)
        }
        EntryPayload::Membership(membership) => validate_membership_for_log(
            &StoredMembership::new(Some(entry.log_id), membership.clone()),
            scope,
            entry.log_id.index,
        ),
        EntryPayload::Blank => Ok(()),
    }
}

fn validate_entry_for_apply(
    entry: &Entry<SessionRaftTypeConfig>,
    storage_identity: SessionConsensusIdentity,
    scope: &MembershipValidationScope,
    admission: CommandAdmission,
) -> io::Result<()> {
    match &entry.payload {
        EntryPayload::Normal(command) => {
            validate_command_for_entry(command, storage_identity, entry.log_id.index, admission)
        }
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
    admission: CommandAdmission,
    membership: StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    projected_requests: BTreeMap<[u8; 16], [u8; 32]>,
    outcome_chain_validated: bool,
}

impl MembershipLogProjection {
    fn load(conn: &Connection, storage_identity: SessionConsensusIdentity) -> io::Result<Self> {
        Ok(Self {
            scope: read_membership_scope_sync(conn, storage_identity)?,
            admission: read_command_admission_sync(conn, storage_identity)?,
            membership: read_membership_sync(conn, storage_identity)?,
            projected_requests: BTreeMap::new(),
            outcome_chain_validated: false,
        })
    }

    fn read_validated_outcome(
        &mut self,
        conn: &Connection,
        storage_identity: SessionConsensusIdentity,
        request_id: SessionConsensusRequestId,
    ) -> io::Result<Option<([u8; 32], SessionConsensusResponse)>> {
        let outcome = read_outcome_sync(conn, storage_identity, request_id)?;
        if outcome.is_some() && !self.outcome_chain_validated {
            // A persisted row is about to influence follower projection.
            // Validate the complete result-bearing chain once in this append
            // transaction before allowing that row to suppress or bind the
            // command. Unique requests never consult persisted authority and
            // therefore avoid a quadratic full-history rescan.
            validate_all_outcomes_sync(conn, storage_identity)?;
            self.outcome_chain_validated = true;
        }
        Ok(outcome)
    }

    fn project(
        &mut self,
        conn: &Connection,
        entry: &Entry<SessionRaftTypeConfig>,
        storage_identity: SessionConsensusIdentity,
    ) -> io::Result<()> {
        validate_entry_for_membership_scope(entry, storage_identity, &self.scope, self.admission)?;
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
                } else if let Some(cleanup) = self
                    .scope
                    .terminal
                    .as_mut()
                    .filter(|terminal| terminal.outcome == TerminalMembershipOutcome::Aborted)
                    .and_then(|terminal| terminal.abort_cleanup.as_mut())
                {
                    if entry.log_id.index > cleanup.decision_log_index {
                        validate_uniform_membership(&stored, &self.scope.current_members)?;
                        if cleanup.cleanup_log_index.is_some() {
                            return Err(invalid_data(
                                "projected session consensus abort cleanup evidence conflicts",
                            ));
                        }
                        cleanup.cleanup_log_index = Some(entry.log_id.index);
                    }
                }
                self.membership = stored;
                if promote {
                    self.promote_at(entry.log_id.index)?;
                }
                Ok(())
            }
            EntryPayload::Normal(command) => {
                if command.is_command_admission_cutover() {
                    let digest = payload_digest(command)?;
                    let request_id = *command.request_id.as_bytes();
                    if !self.admission.cutover_committed {
                        self.admission.strict_activation_index =
                            entry.log_id.index.checked_add(1).ok_or_else(|| {
                                invalid_data(
                                    "session consensus admission activation index exhausted",
                                )
                            })?;
                        self.admission.cutover_committed = true;
                        self.projected_requests.insert(request_id, digest);
                    } else if self.projected_requests.get(&request_id) == Some(&digest) {
                        // A repeated marker in the same unapplied follower
                        // batch is bound to the first projected marker.
                    } else if let Some((persisted, response)) =
                        self.read_validated_outcome(conn, storage_identity, command.request_id)?
                    {
                        if persisted != digest
                            || !matches!(response.result, Ok(SessionMutationOutcome::Unit))
                        {
                            return Err(invalid_data(
                                "projected session consensus admission cutover receipt conflicts",
                            ));
                        }
                        self.projected_requests.insert(request_id, digest);
                    } else {
                        return Err(invalid_data(
                            "projected session consensus admission cutover receipt is missing",
                        ));
                    }
                    return Ok(());
                }
                let digest = payload_digest(command)?;
                let request_id = *command.request_id.as_bytes();
                if self.projected_requests.contains_key(&request_id) {
                    // A request-ID collision is a valid, deterministically
                    // rejected command. The state-machine apply path returns
                    // `CasIdempotencyConflict`; treating the log as corrupt
                    // here would instead turn untrusted caller reuse into a
                    // replica-fatal storage error.
                    return Ok(());
                }
                if let Some((persisted, _)) =
                    self.read_validated_outcome(conn, storage_identity, command.request_id)?
                {
                    if persisted != digest {
                        return Ok(());
                    }
                    self.projected_requests.insert(request_id, digest);
                    return Ok(());
                }
                self.projected_requests.insert(request_id, digest);
                self.project_intent(&command.intent, entry.log_id.index)
            }
        }
    }

    fn retain_current_terminal(&mut self) -> io::Result<()> {
        let retained = completed_terminal_from_scope(&self.scope).map_err(|error| match error {
            MembershipScopeMutationError::TransitionNotQuiescent => invalid_data(
                "projected session consensus prior terminal transition is not quiescent",
            ),
            _ => invalid_data("projected session consensus terminal evidence is invalid"),
        })?;
        let Some(retained) = retained else {
            return Ok(());
        };
        if let Some(existing) = self
            .scope
            .terminal_history
            .iter()
            .find(|existing| existing.transition_id == retained.transition_id)
        {
            return if existing == &retained {
                Ok(())
            } else {
                Err(invalid_data(
                    "projected session consensus terminal history conflicts",
                ))
            };
        }
        if self.scope.terminal_history.len() >= MEMBERSHIP_HISTORY_MAX_ENTRIES {
            return Err(invalid_data(
                "projected session consensus terminal history is full",
            ));
        }
        self.scope.terminal_history.push(retained);
        Ok(())
    }

    fn promote_at(&mut self, cutover_log_index: u64) -> io::Result<()> {
        self.retain_current_terminal()?;
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
            abort_cleanup: None,
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
                if let Some(retained_digest) =
                    retained_transition_digest(&self.scope, *transition_id)?
                {
                    return if retained_digest == *request_digest {
                        Ok(())
                    } else {
                        Err(invalid_data(
                            "projected session consensus transition ID was reused",
                        ))
                    };
                }
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
                {
                    return Err(invalid_data(
                        "projected session consensus successor scope is invalid",
                    ));
                }
                self.retain_current_terminal()?;
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
                if let Some(cleanup) = self
                    .scope
                    .terminal
                    .as_mut()
                    .filter(|terminal| {
                        terminal.transition_id == *transition_id
                            && terminal.transition_digest == *request_digest
                            && terminal.outcome == TerminalMembershipOutcome::Aborted
                    })
                    .and_then(|terminal| terminal.abort_cleanup.as_mut())
                {
                    if log_index < cleanup.decision_log_index {
                        return Err(invalid_data(
                            "projected session consensus abort evidence regressed",
                        ));
                    }
                    if cleanup.learners.is_empty()
                        && cleanup.cleanup_log_index.is_none()
                        && log_index > cleanup.decision_log_index
                    {
                        cleanup.cleanup_log_index = Some(log_index);
                    }
                    return Ok(());
                }
                self.retain_current_terminal()?;
                let pending = self.scope.pending.take().ok_or_else(|| {
                    invalid_data("projected session consensus transition is missing")
                })?;
                let learners = abort_learners_from_membership(
                    &self.membership,
                    &self.scope.current_members,
                    &pending.desired_members,
                );
                if pending.transition_id != *transition_id
                    || pending.transition_digest != *request_digest
                    || pending.joint_membership_log_index.is_some()
                    || pending.uniform_membership_log_index.is_some()
                    || log_index <= pending.transition_start_log_index
                    || pending
                        .learners_ready_log_index
                        .is_some_and(|ready| log_index <= ready)
                    || learners.is_err()
                {
                    self.scope.pending = Some(pending);
                    return Err(invalid_data("projected session consensus abort is invalid"));
                }
                self.scope.application_authority_epoch =
                    self.scope.current_identity.configuration_epoch();
                self.scope.application_authority_members = self.scope.current_members.clone();
                let learners = learners?;
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
                    abort_cleanup: Some(AbortedMembershipCleanup {
                        desired_identity: pending.desired_identity,
                        desired_members: pending.desired_members,
                        desired_bindings: pending.desired_bindings,
                        learners,
                        decision_log_index: log_index,
                        cleanup_log_index: None,
                    }),
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
            | SessionMutationIntent::BindConsumerRequest { .. }
            | SessionMutationIntent::ReadConsumerRecord { .. }
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
            ));
        }
    }
    Ok(Some(vote))
}

pub(crate) fn save_vote_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    vote: &Vote<SessionConsensusNodeId>,
) -> io::Result<()> {
    save_vote_in_tx(conn, identity, vote)
}

pub(crate) fn save_vote_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    vote: &Vote<SessionConsensusNodeId>,
) -> io::Result<()> {
    if authority_profile == ConsensusAuthorityProfile::Dynamic {
        return save_vote_sync(conn, identity, vote);
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    validate_durable_authority_for_raw_access(
        &tx,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
    )?;
    validate_fixed_vote_member(vote, expected_members)?;
    save_vote_in_tx(&tx, identity, vote)?;
    tx.commit().map_err(db_error)
}

fn save_vote_in_tx(
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
    let tx = conn.unchecked_transaction().map_err(db_error)?;
    save_committed_in_tx(&tx, identity, committed)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn save_committed_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    committed: Option<LogId<SessionConsensusNodeId>>,
) -> io::Result<()> {
    if authority_profile == ConsensusAuthorityProfile::Dynamic {
        return save_committed_sync(conn, identity, committed);
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    validate_durable_authority_for_raw_access(
        &tx,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
    )?;
    committed.as_ref().map(validate_fixed_log_id).transpose()?;
    save_committed_in_tx(&tx, identity, committed)?;
    tx.commit().map_err(db_error)
}

fn save_committed_in_tx(
    tx: &Transaction<'_>,
    identity: SessionConsensusIdentity,
    committed: Option<LogId<SessionConsensusNodeId>>,
) -> io::Result<()> {
    let Some(committed) = committed else {
        if read_committed_sync(tx, identity)?.is_some() {
            return Err(invalid_data(
                "session consensus committed index cannot be cleared",
            ));
        }
        return Ok(());
    };
    if let Some(current) = read_committed_sync(tx, identity)? {
        if committed.index < current.index
            || (committed.index == current.index && committed != current)
        {
            return Err(invalid_data("session consensus committed index regressed"));
        }
    }
    save_log_pointer(tx, "consensus_committed", identity, &committed)?;
    Ok(())
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
        (Some(_), Some(_)) => {
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index ASC LIMIT ?3"
        }
        (Some(_), None) => {
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index ASC"
        }
        (None, Some(_)) => {
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 ORDER BY log_index ASC LIMIT ?3"
        }
        (None, None) => {
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 ORDER BY log_index ASC"
        }
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
            validate_entry_for_membership_scope(
                &entry,
                identity,
                &projection.scope,
                projection.admission,
            )?;
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
    append_logs_in_tx(&tx, identity, entries)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn append_logs_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    if authority_profile == ConsensusAuthorityProfile::Dynamic {
        return append_logs_sync(conn, identity, entries);
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    validate_durable_authority_for_raw_access(
        &tx,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
    )?;
    for entry in entries {
        validate_fixed_log_id(&entry.log_id)?;
    }
    if entries
        .iter()
        .any(|entry| fixed_profile_entry_changes_topology(entry, expected_members))
    {
        return Err(invalid_data(
            "fixed session consensus authority rejects topology transitions",
        ));
    }
    append_logs_in_tx(&tx, identity, entries)?;
    tx.commit().map_err(db_error)
}

fn append_logs_in_tx(
    tx: &Transaction<'_>,
    identity: SessionConsensusIdentity,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> io::Result<()> {
    let mut projection = MembershipLogProjection::load(tx, identity)?;
    let expected = last_log_sync(tx, identity)?
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
    replay_unapplied_log_prefix_sync(tx, identity, expected, &mut projection)?;
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
        projection.project(tx, entry, identity)?;
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
    Ok(())
}

pub(crate) fn truncate_logs_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    since: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let (_, index) = validate_log_id(since)?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    truncate_logs_in_tx(&tx, identity, since, index)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn truncate_logs_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    since: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    if authority_profile == ConsensusAuthorityProfile::Dynamic {
        return truncate_logs_sync(conn, identity, since);
    }
    let (_, index) = validate_log_id(since)?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    validate_durable_authority_for_raw_access(
        &tx,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
    )?;
    validate_fixed_log_id(since)?;
    truncate_logs_in_tx(&tx, identity, since, index)?;
    tx.commit().map_err(db_error)
}

fn truncate_logs_in_tx(
    tx: &Transaction<'_>,
    identity: SessionConsensusIdentity,
    since: &LogId<SessionConsensusNodeId>,
    index: i64,
) -> io::Result<()> {
    if let Some(committed) = read_committed_sync(tx, identity)? {
        if since.index <= committed.index {
            return Err(invalid_data(
                "session consensus truncate crosses committed log",
            ));
        }
    }
    if let Some(applied) = read_applied_sync(tx, identity)? {
        if since.index <= applied.index {
            return Err(invalid_data(
                "session consensus truncate crosses applied log",
            ));
        }
    }
    if let Some(purged) = read_purged_sync(tx, identity)? {
        if since.index <= purged.index {
            return Err(invalid_data(
                "session consensus truncate crosses purged log",
            ));
        }
    }
    tx.execute("DELETE FROM consensus_log WHERE log_index >= ?1", [index])
        .map_err(db_error)?;
    Ok(())
}

pub(crate) fn purge_logs_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    through: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let (_, index) = validate_log_id(through)?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    purge_logs_in_tx(&tx, identity, through, index)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn purge_logs_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    through: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    if authority_profile == ConsensusAuthorityProfile::Dynamic {
        return purge_logs_sync(conn, identity, through);
    }
    let (_, index) = validate_log_id(through)?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    validate_durable_authority_for_raw_access(
        &tx,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
    )?;
    validate_fixed_log_id(through)?;
    purge_logs_in_tx(&tx, identity, through, index)?;
    tx.commit().map_err(db_error)
}

fn purge_logs_in_tx(
    tx: &Transaction<'_>,
    identity: SessionConsensusIdentity,
    through: &LogId<SessionConsensusNodeId>,
    index: i64,
) -> io::Result<()> {
    if let Some(current) = read_purged_sync(tx, identity)? {
        if through.index < current.index || (through.index == current.index && through != &current)
        {
            return Err(invalid_data("session consensus purged index regressed"));
        }
    }
    let applied = read_applied_sync(tx, identity)?
        .ok_or_else(|| invalid_data("session consensus cannot purge unapplied logs"))?;
    if through.index > applied.index {
        return Err(invalid_data(
            "session consensus cannot purge unapplied logs",
        ));
    }
    tx.execute("DELETE FROM consensus_log WHERE log_index <= ?1", [index])
        .map_err(db_error)?;
    save_log_pointer(tx, "consensus_purged", identity, through)?;
    Ok(())
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

fn abort_learners_from_membership(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    current_members: &BTreeSet<SessionConsensusNodeId>,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<BTreeSet<SessionConsensusNodeId>> {
    match classify_transition_membership(membership, current_members, desired_members)? {
        MembershipShape::CurrentUniform => Ok(BTreeSet::new()),
        MembershipShape::LearnersCatchingUp => Ok(membership
            .membership()
            .learner_ids()
            .collect::<BTreeSet<_>>()),
        MembershipShape::Joint | MembershipShape::DesiredUniform => Err(invalid_data(
            "session consensus abort followed an irreversible membership change",
        )),
    }
}

fn validate_aborted_membership_before_cleanup(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    current_members: &BTreeSet<SessionConsensusNodeId>,
    learners: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    let configs = membership.membership().get_joint_config();
    let nodes = membership
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    let stored_learners = membership
        .membership()
        .learner_ids()
        .collect::<BTreeSet<_>>();
    let expected_nodes = current_members
        .union(learners)
        .copied()
        .collect::<BTreeSet<_>>();
    if configs.len() != 1
        || configs.first() != Some(current_members)
        || nodes != expected_nodes
        || stored_learners != *learners
    {
        return Err(invalid_data(
            "session consensus membership does not match the durable abort decision",
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
    if let Some(cleanup) = scope
        .terminal
        .as_ref()
        .filter(|terminal| terminal.outcome == TerminalMembershipOutcome::Aborted)
        .and_then(|terminal| terminal.abort_cleanup.as_ref())
    {
        if log_index < cleanup.decision_log_index {
            return validate_aborted_membership_before_cleanup(
                membership,
                &scope.current_members,
                &cleanup.learners,
            );
        }
        if log_index == cleanup.decision_log_index {
            return Err(invalid_data(
                "session consensus membership collides with abort decision index",
            ));
        }
        validate_uniform_membership(membership, &scope.current_members)?;
        if cleanup
            .cleanup_log_index
            .is_some_and(|recorded| recorded != log_index)
        {
            return Err(invalid_data(
                "session consensus abort cleanup membership evidence conflicts",
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

fn payload_digest(command: &DurableSessionConsensusCommand) -> io::Result<[u8; 32]> {
    // Idempotency binds caller-owned semantics, not leader-owned sequence,
    // predecessor, or logical-time metadata. A retry after a committed
    // response is lost will be proposed by a new leader with new metadata but
    // must still recover the original durable outcome. The authenticated
    // origin may change across that retry, but its exact admitted topology
    // authority may not: carrying a request ID into a new epoch must conflict
    // instead of recovering an outcome authorized by the old epoch.
    let encoded = match &command.intent {
        SessionMutationIntent::Authorized {
            authority_identity,
            mutation,
            ..
        } => encode_json(&(
            command.schema_version,
            command.identity,
            authority_identity,
            mutation.as_ref(),
        ))?,
        intent => encode_json(&(command.schema_version, command.identity, intent))?,
    };
    let mut hasher = Sha256::new();
    hasher.update(OUTCOME_DIGEST_DOMAIN);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

/// Bind a durable idempotency receipt to the semantic command commitment and
/// the complete deterministic response, including all response metadata.
/// Caller-origin and proposal-time remain outside `payload_digest`, preserving
/// the established retry contract while preventing response swizzles.
struct OutcomeReceiptDigestInput<'a> {
    request_id: &'a SessionConsensusRequestId,
    configuration_epoch: u64,
    semantic_command_digest: &'a [u8; 32],
    command: &'a DurableSessionConsensusCommand,
    predecessor_sequence: u64,
    predecessor_digest: &'a SessionConsensusEntryDigest,
    predecessor_logical_time: Option<Timestamp>,
    predecessor_receipt_digest: &'a [u8; 32],
    raft_log_index: u64,
    response: &'a SessionConsensusResponse,
}

macro_rules! outcome_receipt_digest_input {
    (
        $request_id:expr, $configuration_epoch:expr, $semantic_command_digest:expr,
        $command:expr, $predecessor_sequence:expr, $predecessor_digest:expr,
        $predecessor_logical_time:expr, $predecessor_receipt_digest:expr,
        $raft_log_index:expr, $response:expr $(,)?
    ) => {
        outcome_receipt_digest(OutcomeReceiptDigestInput {
            request_id: &$request_id,
            configuration_epoch: $configuration_epoch,
            semantic_command_digest: &$semantic_command_digest,
            command: $command,
            predecessor_sequence: $predecessor_sequence,
            predecessor_digest: &$predecessor_digest,
            predecessor_logical_time: $predecessor_logical_time,
            predecessor_receipt_digest: &$predecessor_receipt_digest,
            raft_log_index: $raft_log_index,
            response: $response,
        })
    };
}

fn outcome_receipt_digest(input: OutcomeReceiptDigestInput<'_>) -> io::Result<[u8; 32]> {
    let encoded = encode_json(&(
        OUTCOME_RECEIPT_VERSION,
        input.request_id,
        input.configuration_epoch,
        input.semantic_command_digest,
        input.command,
        input.predecessor_sequence,
        input.predecessor_digest,
        input.predecessor_logical_time,
        input.predecessor_receipt_digest,
        input.raft_log_index,
        input.response,
    ))?;
    let mut hasher = Sha256::new();
    hasher.update(OUTCOME_RECEIPT_DIGEST_DOMAIN);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

/// Digest used only to verify the exact unpublished pre-chain candidate
/// manifest before rebuilding it.  New rows must always use
/// `outcome_receipt_digest`, which links the preceding result-bearing receipt.
struct OutcomeReceiptDigestWithoutChainInput<'a> {
    request_id: &'a SessionConsensusRequestId,
    configuration_epoch: u64,
    semantic_command_digest: &'a [u8; 32],
    command: &'a DurableSessionConsensusCommand,
    predecessor_sequence: u64,
    predecessor_digest: &'a SessionConsensusEntryDigest,
    predecessor_logical_time: Option<Timestamp>,
    raft_log_index: u64,
    response: &'a SessionConsensusResponse,
}

fn outcome_receipt_digest_without_receipt_chain(
    input: OutcomeReceiptDigestWithoutChainInput<'_>,
) -> io::Result<[u8; 32]> {
    let encoded = encode_json(&(
        OUTCOME_RECEIPT_VERSION,
        input.request_id,
        input.configuration_epoch,
        input.semantic_command_digest,
        input.command,
        input.predecessor_sequence,
        input.predecessor_digest,
        input.predecessor_logical_time,
        input.raft_log_index,
        input.response,
    ))?;
    let mut hasher = Sha256::new();
    hasher.update(OUTCOME_RECEIPT_DIGEST_DOMAIN);
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

pub(crate) fn read_machine_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<MachineState> {
    let (epoch, sequence, digest, receipt_digest, logical_time, watch_sequence): (
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<String>,
        i64,
    ) = conn
        .query_row(
            "SELECT configuration_epoch, application_sequence, last_digest, last_receipt_digest, logical_time, watch_sequence FROM consensus_machine WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| invalid_data("persisted session consensus digest has invalid length"))?;
    let logical_time = logical_time
        .map(|value| {
            ops::parse_persisted_rfc3339_normalized(&value)
                .map_err(|_| invalid_data("persisted session consensus logical time is invalid"))
        })
        .transpose()?;
    Ok((
        checked_u64(sequence)?,
        SessionConsensusEntryDigest::from_bytes(digest),
        receipt_digest.try_into().map_err(|_| {
            invalid_data("persisted session consensus receipt chain head is invalid")
        })?,
        logical_time,
        checked_u64(watch_sequence)?,
    ))
}

/// Read the frozen immediate-predecessor machine head without projecting a
/// receipt-chain head that this layout never persisted. Callers may use its
/// application and clock state only while converting the predecessor through
/// the explicit recovery boundary.
pub(crate) fn read_immediate_predecessor_machine_sync(
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
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| invalid_data("persisted predecessor consensus digest has invalid length"))?;
    let logical_time = logical_time
        .map(|value| {
            ops::parse_persisted_rfc3339_normalized(&value).map_err(|_| {
                invalid_data("persisted predecessor consensus logical time is invalid")
            })
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
    let (sequence, digest, _, logical_time, _) = read_machine_sync(conn, identity)?;
    Ok((sequence, digest, logical_time))
}

pub(crate) fn logical_time_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<Timestamp>> {
    read_machine_sync(conn, identity).map(|(_, _, _, logical_time, _)| logical_time)
}

pub(crate) fn validate_consensus_outcome_records(
    outcome: &SessionMutationOutcome,
) -> Result<(), StoreError> {
    match outcome {
        SessionMutationOutcome::ConsumerRecord(Some(record))
        | SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
            current: Some(record),
        }) => super::validate_consensus_record(record),
        SessionMutationOutcome::CompareAndSet(_)
        | SessionMutationOutcome::ConsumerRecord(None)
        | SessionMutationOutcome::Lease(_)
        | SessionMutationOutcome::Unit => Ok(()),
    }
}

/// Reject response families that are syntactically valid but cannot have been
/// produced by the retained command. This runs before idempotency replay and
/// while validating reopened or incoming snapshot state.
fn validate_response_for_command(
    command: &DurableSessionConsensusCommand,
    response: &SessionConsensusResponse,
) -> io::Result<()> {
    if response.sequence == 0 || response.digest.is_none() {
        return Err(invalid_data(
            "persisted session consensus outcome metadata is invalid",
        ));
    }
    let logical_time = response
        .logical_time
        .ok_or_else(|| invalid_data("persisted session consensus outcome metadata is invalid"))?;
    let authorized = matches!(&command.intent, SessionMutationIntent::Authorized { .. });
    let intent = match &command.intent {
        SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
        intent => intent,
    };
    match &response.result {
        Err(StoreError::TopologyAuthorityRevoked) if authorized => Ok(()),
        Err(error)
            if is_deterministic_intent_rejection(error)
                && response_error_matches_command(intent, error) =>
        {
            Ok(())
        }
        Err(_) => Err(invalid_data(
            "persisted session consensus outcome error is invalid",
        )),
        Ok(outcome) => {
            let matches = match (intent, outcome) {
                (
                    SessionMutationIntent::AdvanceLogicalTime
                    | SessionMutationIntent::BindConsumerRequest { .. }
                    | SessionMutationIntent::DeleteFenced(_)
                    | SessionMutationIntent::RefreshTtl { .. }
                    | SessionMutationIntent::ReleaseLease(_)
                    | SessionMutationIntent::FinalizeOperatorRecovery { .. }
                    | SessionMutationIntent::PrepareTopologyTransition { .. }
                    | SessionMutationIntent::MarkTopologyLearnersReady { .. }
                    | SessionMutationIntent::FenceTopologyAuthority { .. }
                    | SessionMutationIntent::AbortTopologyTransition { .. }
                    | SessionMutationIntent::FinalizeTopologyTransition { .. },
                    SessionMutationOutcome::Unit,
                ) => true,
                (
                    SessionMutationIntent::CompareAndSet(_),
                    SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success),
                ) => true,
                (
                    SessionMutationIntent::CompareAndSet(command),
                    SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
                        current,
                    }),
                ) => current
                    .as_ref()
                    .is_none_or(|record| record.key == command.key),
                (
                    SessionMutationIntent::AcquireLease { key, owner, ttl },
                    SessionMutationOutcome::Lease(lease),
                ) => {
                    lease.key() == key
                        && lease.owner() == owner
                        && lease.fence().get() > 0
                        && lease.credential_id() > 0
                        && lease.acquired_at() == logical_time
                        && crate::ttl::checked_session_deadline(logical_time, *ttl).ok()
                            == Some(lease.expires_at())
                }
                (
                    SessionMutationIntent::RenewLease {
                        lease: expected,
                        ttl,
                    },
                    SessionMutationOutcome::Lease(lease),
                ) => {
                    lease.key() == expected.key()
                        && lease.owner() == expected.owner()
                        && lease.fence() == expected.fence()
                        && lease.credential_id() == expected.credential_id()
                        && lease.acquired_at() == expected.acquired_at()
                        && crate::ttl::checked_session_deadline(logical_time, *ttl).ok()
                            == Some(lease.expires_at())
                }
                (
                    SessionMutationIntent::ReadConsumerRecord { key },
                    SessionMutationOutcome::ConsumerRecord(record),
                ) => record.as_ref().is_none_or(|record| &record.key == key),
                _ => false,
            };
            matches.then_some(()).ok_or_else(|| {
                invalid_data("persisted session consensus outcome does not match command")
            })
        }
    }
}

/// Constrain deterministic error outcomes to intent families. This prevents a
/// syntactically valid error from another command family from suppressing
/// execution during duplicate replay, while retaining historical outcomes
/// whose exact cause depends on predecessor state.
fn response_error_matches_command(intent: &SessionMutationIntent, error: &StoreError) -> bool {
    match intent {
        SessionMutationIntent::AdvanceLogicalTime
        | SessionMutationIntent::BindConsumerRequest { .. } => false,
        SessionMutationIntent::ReadConsumerRecord { .. } => {
            matches!(error, StoreError::PayloadTooLarge { .. })
        }
        SessionMutationIntent::CompareAndSet(_) => matches!(
            error,
            StoreError::StaleFence
                | StoreError::LeaseExpired
                | StoreError::InvalidKey(_)
                | StoreError::InvalidRecordExpiry
                | StoreError::PayloadTooLarge { .. }
        ),
        SessionMutationIntent::DeleteFenced(_) => {
            matches!(error, StoreError::StaleFence | StoreError::LeaseExpired)
        }
        SessionMutationIntent::RefreshTtl { .. } => matches!(
            error,
            StoreError::StaleFence
                | StoreError::LeaseExpired
                | StoreError::NotFound
                | StoreError::InvalidSessionTtl
        ),
        SessionMutationIntent::AcquireLease { .. } => {
            matches!(error, StoreError::LeaseHeld | StoreError::InvalidSessionTtl)
        }
        SessionMutationIntent::RenewLease { .. } => matches!(
            error,
            StoreError::LeaseHeld
                | StoreError::LeaseExpired
                | StoreError::StaleFence
                | StoreError::NotFound
                | StoreError::InvalidSessionTtl
        ),
        SessionMutationIntent::ReleaseLease(_) => matches!(
            error,
            StoreError::LeaseHeld
                | StoreError::LeaseExpired
                | StoreError::StaleFence
                | StoreError::NotFound
        ),
        SessionMutationIntent::FinalizeOperatorRecovery { .. } => matches!(
            error,
            StoreError::InvalidKey(reason) if reason == "operator_recovery_epoch_rejected"
        ),
        SessionMutationIntent::PrepareTopologyTransition { .. }
        | SessionMutationIntent::MarkTopologyLearnersReady { .. }
        | SessionMutationIntent::FenceTopologyAuthority { .. }
        | SessionMutationIntent::AbortTopologyTransition { .. }
        | SessionMutationIntent::FinalizeTopologyTransition { .. } => matches!(
            error,
            StoreError::InvalidKey(reason) if reason == "topology_transition_rejected"
        ),
        SessionMutationIntent::Authorized { .. } => false,
    }
}

/// A self-consistent receipt is not allowed to contradict the immutable Raft
/// command while that command is still retained. Compacted snapshots may no
/// longer carry the corresponding log row, so absence alone is not evidence
/// that can reconstruct or reject the receipt.
fn validate_outcome_against_retained_log_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    raft_log_index: u64,
    command: &DurableSessionConsensusCommand,
) -> io::Result<()> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index = ?1",
            [checked_i64(raft_log_index)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, term, index, encoded)) = row else {
        return Ok(());
    };
    validate_epoch(epoch, identity)?;
    let entry: Entry<SessionRaftTypeConfig> = decode_json(&encoded)?;
    if checked_u64(term)? != entry.log_id.leader_id.term
        || checked_u64(index)? != entry.log_id.index
        || entry.log_id.index != raft_log_index
    {
        return Err(invalid_data(
            "persisted session consensus outcome retained log row is invalid",
        ));
    }
    match entry.payload {
        EntryPayload::Normal(retained) if retained == *command => Ok(()),
        _ => Err(invalid_data(
            "persisted session consensus outcome contradicts retained command",
        )),
    }
}

fn read_outcome_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    request_id: SessionConsensusRequestId,
) -> io::Result<Option<([u8; 32], SessionConsensusResponse)>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest FROM consensus_request_outcomes WHERE request_id = ?1",
            [request_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    let Some((
        epoch,
        digest,
        command,
        predecessor_sequence,
        predecessor_digest,
        predecessor_logical_time,
        predecessor_receipt_digest,
        raft_log_index,
        response,
        receipt_version,
        receipt_digest,
    )) = row
    else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    if receipt_version != OUTCOME_RECEIPT_VERSION {
        return Err(invalid_data(
            "persisted session consensus outcome receipt version is invalid",
        ));
    }
    let digest = digest.try_into().map_err(|_| {
        invalid_data("persisted session consensus request digest has invalid length")
    })?;
    let command: DurableSessionConsensusCommand = decode_json(&command)?;
    if command.request_id != request_id
        || command.identity != identity
        || payload_digest(&command)? != digest
    {
        return Err(invalid_data(
            "persisted session consensus outcome command is invalid",
        ));
    }
    let response: SessionConsensusResponse = decode_json(&response)?;
    let predecessor_sequence = checked_u64(predecessor_sequence)?;
    let predecessor_digest =
        SessionConsensusEntryDigest::from_bytes(predecessor_digest.try_into().map_err(|_| {
            invalid_data("persisted session consensus predecessor digest has invalid length")
        })?);
    let predecessor_logical_time = predecessor_logical_time
        .map(|value| {
            ops::parse_persisted_rfc3339_normalized(&value).map_err(|_| {
                invalid_data("persisted session consensus predecessor logical time is invalid")
            })
        })
        .transpose()?;
    let predecessor_receipt_digest: [u8; 32] =
        predecessor_receipt_digest.try_into().map_err(|_| {
            invalid_data(
                "persisted session consensus predecessor receipt digest has invalid length",
            )
        })?;
    let raft_log_index = checked_u64(raft_log_index)?;
    validate_outcome_against_retained_log_sync(conn, identity, raft_log_index, &command)?;
    validate_persisted_command_admission(
        &command,
        identity,
        raft_log_index,
        read_command_admission_sync(conn, identity)?,
    )?;
    let effective_time = predecessor_logical_time.map_or(command.logical_time, |previous| {
        previous.max(command.logical_time)
    });
    if response.sequence
        != predecessor_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_data("persisted session consensus sequence exhausted"))?
        || response.logical_time != Some(effective_time)
        || response.raft_log_index != raft_log_index
        || response.digest
            != Some(
                command
                    .calculate_applied_result_digest(
                        response.sequence,
                        predecessor_digest,
                        effective_time,
                        raft_log_index,
                        &response.result,
                    )
                    .map_err(|_| {
                        invalid_data("persisted session consensus outcome digest is invalid")
                    })?,
            )
    {
        return Err(invalid_data(
            "persisted session consensus outcome metadata is invalid",
        ));
    }
    validate_response_for_command(&command, &response)?;
    if let Ok(outcome) = &response.result {
        validate_consensus_outcome_records(outcome)
            .map_err(|_| invalid_data("persisted session consensus outcome record is invalid"))?;
    }
    let receipt_digest: [u8; 32] = receipt_digest.try_into().map_err(|_| {
        invalid_data("persisted session consensus outcome receipt digest has invalid length")
    })?;
    if receipt_digest
        != outcome_receipt_digest_input!(
            request_id,
            checked_positive_u64(epoch)?,
            digest,
            &command,
            predecessor_sequence,
            predecessor_digest,
            predecessor_logical_time,
            predecessor_receipt_digest,
            raft_log_index,
            &response,
        )?
    {
        return Err(invalid_data(
            "persisted session consensus outcome receipt is invalid",
        ));
    }
    Ok(Some((digest, response)))
}

fn validate_all_outcomes_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    let admission = read_command_admission_sync(conn, identity)?;
    let recovery = read_operator_recovery_sync(conn, identity)?;
    let applied_index = read_applied_sync(conn, identity)?.map(|log_id| log_id.index);
    let mut statement = conn
        .prepare("SELECT request_id FROM consensus_request_outcomes")
        .map_err(db_error)?;
    let request_ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    drop(statement);
    let mut responses = Vec::with_capacity(request_ids.len());
    for request_id in request_ids {
        let request_id = request_id
            .try_into()
            .map(SessionConsensusRequestId::from_bytes)
            .map_err(|_| invalid_data("persisted session consensus request ID is invalid"))?;
        if let Some((_, response)) = read_outcome_sync(conn, identity, request_id)? {
            let (
                predecessor_sequence,
                predecessor_digest,
                predecessor_logical_time,
                predecessor_receipt_digest,
                receipt_digest,
            ): (i64, Vec<u8>, Option<String>, Vec<u8>, Vec<u8>) = conn
                .query_row(
                    "SELECT predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, receipt_digest FROM consensus_request_outcomes WHERE request_id = ?1",
                    [request_id.as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .map_err(db_error)?;
            let predecessor_digest = SessionConsensusEntryDigest::from_bytes(
                predecessor_digest.try_into().map_err(|_| {
                    invalid_data(
                        "persisted session consensus predecessor digest has invalid length",
                    )
                })?,
            );
            let predecessor_logical_time = predecessor_logical_time
                .map(|value| {
                    ops::parse_persisted_rfc3339_normalized(&value).map_err(|_| {
                        invalid_data(
                            "persisted session consensus predecessor logical time is invalid",
                        )
                    })
                })
                .transpose()?;
            let predecessor_receipt_digest: [u8; 32] =
                predecessor_receipt_digest.try_into().map_err(|_| {
                    invalid_data(
                        "persisted session consensus predecessor receipt digest has invalid length",
                    )
                })?;
            let receipt_digest = receipt_digest.try_into().map_err(|_| {
                invalid_data(
                    "persisted session consensus outcome receipt digest has invalid length",
                )
            })?;
            responses.push((
                request_id,
                response,
                checked_u64(predecessor_sequence)?,
                predecessor_digest,
                predecessor_logical_time,
                predecessor_receipt_digest,
                receipt_digest,
            ));
        }
    }
    responses.sort_by_key(|(_, response, ..)| response.sequence);
    let (machine_sequence, machine_digest, machine_receipt_digest, machine_time, _) =
        read_machine_sync(conn, identity)?;
    // An explicitly operator-authorized legacy reset does not synthesize a
    // command/result receipt for the discarded replay cache.  Its fresh
    // chain instead starts at sequence zero from the sealed recovery plan
    // digest. A later verified-majority repair leaves the existing receipt
    // root in the finalized plan; its pending plan is a recovery fence, not
    // a replacement receipt root. Every normal v2 chain starts at GENESIS.
    let recovery_root = outcome_chain_recovery_root(recovery);
    let (root_digest, root_time) = match responses.first() {
        Some((_, _, predecessor_sequence, predecessor_digest, predecessor_time, _, _))
            if *predecessor_sequence == 0
                && *predecessor_digest == SessionConsensusEntryDigest::GENESIS
                && predecessor_time.is_none() =>
        {
            (SessionConsensusEntryDigest::GENESIS, None)
        }
        Some((_, _, predecessor_sequence, predecessor_digest, predecessor_time, _, _))
            if *predecessor_sequence == 0
                && recovery_root == Some(*predecessor_digest.as_bytes()) =>
        {
            (*predecessor_digest, *predecessor_time)
        }
        Some(_) => {
            return Err(invalid_data(
                "persisted session consensus outcome root is invalid",
            ));
        }
        None if machine_sequence == 0
            && machine_digest == SessionConsensusEntryDigest::GENESIS
            && machine_time.is_none() =>
        {
            (SessionConsensusEntryDigest::GENESIS, None)
        }
        None if machine_sequence == 0 && recovery_root == Some(*machine_digest.as_bytes()) => {
            (machine_digest, machine_time)
        }
        None => {
            return Err(invalid_data(
                "persisted session consensus empty outcome chain head is invalid",
            ));
        }
    };
    if u64::try_from(responses.len())
        .map_err(|_| invalid_data("persisted session consensus outcomes exceed integer range"))?
        != machine_sequence
    {
        return Err(invalid_data(
            "persisted session consensus outcome chain is incomplete",
        ));
    }
    let mut previous_raft_log_index = None;
    let mut found_cutover_receipt = false;
    for (
        position,
        (
            request_id,
            response,
            predecessor_sequence,
            predecessor_digest,
            predecessor_time,
            predecessor_receipt_digest,
            _,
        ),
    ) in responses.iter().enumerate()
    {
        let expected_sequence = u64::try_from(position)
            .map_err(|_| invalid_data("persisted session consensus outcomes exceed integer range"))?
            .checked_add(1)
            .ok_or_else(|| invalid_data("persisted session consensus sequence exhausted"))?;
        let (expected_predecessor_digest, expected_predecessor_time, expected_receipt_digest) =
            if position == 0 {
                (root_digest, root_time, OUTCOME_RECEIPT_CHAIN_GENESIS)
            } else {
                let previous = &responses[position - 1].1;
                (
                    previous.digest.ok_or_else(|| {
                        invalid_data("persisted session consensus outcome metadata is invalid")
                    })?,
                    previous.logical_time,
                    responses[position - 1].6,
                )
            };
        if response.sequence != expected_sequence
            || *predecessor_sequence != expected_sequence - 1
            || *predecessor_digest != expected_predecessor_digest
            || *predecessor_time != expected_predecessor_time
            || *predecessor_receipt_digest != expected_receipt_digest
            || previous_raft_log_index.is_some_and(|previous| response.raft_log_index <= previous)
            || applied_index.is_none_or(|applied| response.raft_log_index > applied)
        {
            return Err(invalid_data(
                "persisted session consensus outcome chain is invalid",
            ));
        }
        previous_raft_log_index = Some(response.raft_log_index);
        if admission.cutover_committed
            && request_id.as_bytes()
                == &crate::consensus::SESSION_CONSENSUS_COMMAND_ADMISSION_CUTOVER_REQUEST_ID
            && response.raft_log_index.checked_add(1) == Some(admission.strict_activation_index)
            && matches!(response.result, Ok(SessionMutationOutcome::Unit))
        {
            found_cutover_receipt = true;
        }
    }
    if let Some((_, last, _, _, _, _, last_receipt_digest)) = responses.last() {
        if last.digest != Some(machine_digest) || last.logical_time != machine_time {
            return Err(invalid_data(
                "persisted session consensus outcome chain head is invalid",
            ));
        }
        if *last_receipt_digest != machine_receipt_digest {
            return Err(invalid_data(
                "persisted session consensus receipt chain head is invalid",
            ));
        }
    } else if machine_sequence != 0
        || machine_digest != root_digest
        || machine_receipt_digest != OUTCOME_RECEIPT_CHAIN_GENESIS
        || machine_time != root_time
    {
        return Err(invalid_data(
            "persisted session consensus empty outcome chain head is invalid",
        ));
    }
    if admission.cutover_committed && !found_cutover_receipt {
        return Err(invalid_data(
            "persisted session consensus admission cutover receipt is missing",
        ));
    }
    Ok(())
}

/// Validate the admission boundary and the complete command/outcome receipt
/// chain without mutating the database. Operator-recovery inspection uses the
/// same semantic authority as reopen and snapshot admission; hashing a
/// self-consistent but forged row is not sufficient evidence.
pub(crate) fn validate_recovery_receipts_and_admission_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    read_command_admission_sync(conn, identity)?;
    validate_all_outcomes_sync(conn, identity)
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
        SessionMutationIntent::AdvanceLogicalTime
        | SessionMutationIntent::BindConsumerRequest { .. } => {
            Ok((SessionMutationOutcome::Unit, None))
        }
        SessionMutationIntent::ReadConsumerRecord { key } => {
            let record = ops::get_sync(conn, key, logical_time)?;
            if let Some(record) = &record {
                super::validate_consensus_record(record)?;
            }
            Ok((SessionMutationOutcome::ConsumerRecord(record), None))
        }
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
            log_index,
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

#[cfg(test)]
pub(crate) fn apply_entries_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    caps: &BackendCapabilities,
    entries: Vec<Entry<SessionRaftTypeConfig>>,
) -> io::Result<AppliedBatch> {
    apply_entries_with_authority_sync(
        conn,
        identity,
        caps,
        ConsensusAuthorityProfile::Dynamic,
        &BTreeSet::new(),
        &BTreeMap::new(),
        None,
        entries,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_entries_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    caps: &BackendCapabilities,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
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
    let allows_initial_formation = last_applied.is_none()
        && entries.first().is_some_and(|entry| {
            matches!(
                &entry.payload,
                EntryPayload::Membership(membership)
                    if fixed_uniform_membership_matches(membership, expected_members)
            )
        });
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable
        && !fixed_quorum_authority_is_exact_sync(
            &tx,
            identity,
            expected_members,
            expected_bindings,
            fixed_placement_policy.ok_or_else(|| {
                invalid_data("session consensus fixed placement policy is missing")
            })?,
            allows_initial_formation,
        )?
    {
        return Err(invalid_data(
            "session consensus fixed authority is no longer exact",
        ));
    }
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable {
        for entry in &entries {
            validate_fixed_log_id(&entry.log_id)?;
        }
    }
    let mut machine = read_machine_sync(&tx, identity)?;
    let mut responses = Vec::with_capacity(entries.len());
    let mut notifications = Vec::new();
    let mut outcome_chain_validated = false;

    for entry in entries {
        if authority_profile == ConsensusAuthorityProfile::FixedImmutable
            && fixed_profile_entry_changes_topology(&entry, expected_members)
        {
            return Err(invalid_data(
                "fixed session consensus authority rejects topology transitions",
            ));
        }
        // A preceding application command in this same committed batch may
        // have staged, fenced, or aborted a transition. Validate each entry
        // against the scope visible at its exact apply position.
        let scope = read_membership_scope_sync(&tx, identity)?;
        let admission = read_command_admission_sync(&tx, identity)?;
        validate_entry_for_apply(&entry, identity, &scope, admission)?;
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
                let admission_cutover = command.is_command_admission_cutover();
                let digest = payload_digest(&command)?;
                let persisted_outcome = read_outcome_sync(&tx, identity, command.request_id)?;
                if persisted_outcome.is_some() && !outcome_chain_validated {
                    // This receipt is about to suppress a committed command.
                    // Validate the complete chain once in this apply
                    // transaction before trusting it. New request IDs do not
                    // consume persisted outcome authority and must not rescan
                    // the entire growing history on every application.
                    validate_all_outcomes_sync(&tx, identity)?;
                    outcome_chain_validated = true;
                }
                if let Some((persisted_digest, persisted_response)) = persisted_outcome {
                    if persisted_digest != digest {
                        // A caller can reuse an opaque durable request ID with
                        // another payload. That must be a closed domain
                        // conflict, never a storage fault that prevents the
                        // replicated log from applying.
                        SessionConsensusResponse {
                            result: Err(StoreError::CasIdempotencyConflict),
                            // This log entry is committed but intentionally
                            // has no application effect. Return the last
                            // committed state metadata so callers can prove
                            // it is a durable conflict rather than a local
                            // preproposal rejection.
                            sequence: machine.0,
                            digest: Some(machine.1),
                            logical_time: machine.3,
                            raft_log_index: entry.log_id.index,
                        }
                    } else {
                        persisted_response
                    }
                } else {
                    let sequence = machine.0.checked_add(1).ok_or_else(|| {
                        invalid_data("session consensus application sequence exhausted")
                    })?;
                    let logical_time = machine.3.map_or(command.logical_time, |last_time| {
                        last_time.max(command.logical_time)
                    });
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

                    let command_digest = command
                        .calculate_applied_result_digest(
                            sequence,
                            machine.1,
                            logical_time,
                            entry.log_id.index,
                            &result,
                        )
                        .map_err(|_| invalid_data("session consensus command digest failed"))?;

                    let response = SessionConsensusResponse {
                        result,
                        sequence,
                        digest: Some(command_digest),
                        logical_time: Some(logical_time),
                        raft_log_index: entry.log_id.index,
                    };
                    let receipt = outcome_receipt_digest_input!(
                        command.request_id,
                        identity.configuration_epoch().get(),
                        digest,
                        &command,
                        machine.0,
                        machine.1,
                        machine.3,
                        machine.2,
                        entry.log_id.index,
                        &response,
                    )?;
                    tx.execute(
                        "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                        params![
                            command.request_id.as_bytes().as_slice(),
                            epoch_i64(identity)?,
                            digest.as_slice(),
                            encode_json(&command)?,
                            checked_i64(machine.0)?,
                            machine.1.as_bytes().as_slice(),
                            machine.3.map(ops::format_rfc3339_normalized),
                            machine.2.as_slice(),
                            checked_i64(entry.log_id.index)?,
                            encode_json(&response)?,
                            OUTCOME_RECEIPT_VERSION,
                            receipt.as_slice(),
                        ],
                    )
                    .map_err(db_error)?;
                    if admission_cutover {
                        let changed = tx
                            .execute(
                                "UPDATE consensus_command_admission SET strict_activation_index = ?1, cutover_committed = 1 WHERE singleton = 1 AND configuration_epoch = ?2 AND admission_revision = ?3 AND cutover_committed = 0",
                                params![
                                    checked_i64(entry.log_id.index.checked_add(1).ok_or_else(|| invalid_data("session consensus admission activation index exhausted"))?)?,
                                    epoch_i64(identity)?,
                                    COMMAND_ADMISSION_REVISION,
                                ],
                            )
                            .map_err(db_error)?;
                        if changed != 1 {
                            return Err(invalid_data(
                                "session consensus command admission cutover is invalid",
                            ));
                        }
                    }
                    let changed = tx
                        .execute(
                            "UPDATE consensus_machine SET application_sequence = ?1, last_digest = ?2, last_receipt_digest = ?3, logical_time = ?4 WHERE singleton = 1 AND configuration_epoch = ?5",
                            params![
                                checked_positive_i64(sequence)?,
                                command_digest.as_bytes().as_slice(),
                                receipt.as_slice(),
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
                    machine.2 = receipt;
                    machine.3 = Some(logical_time);
                    if let Some(replication) = replication {
                        machine.4 = machine.4.checked_add(1).ok_or_else(|| {
                            invalid_data("session consensus watch sequence exhausted")
                        })?;
                        notifications.push(store_replication_notification_sync(
                            &tx,
                            identity,
                            machine.4,
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

    if authority_profile == ConsensusAuthorityProfile::FixedImmutable
        && !fixed_quorum_authority_is_exact_sync(
            &tx,
            identity,
            expected_members,
            expected_bindings,
            fixed_placement_policy.ok_or_else(|| {
                invalid_data("session consensus fixed placement policy is missing")
            })?,
            false,
        )?
    {
        return Err(invalid_data(
            "session consensus fixed authority changed while applying entries",
        ));
    }

    validate_persisted_membership_sync(&tx, identity)?;
    tx.commit().map_err(db_error)?;
    Ok(AppliedBatch {
        responses,
        notifications,
    })
}

pub(crate) fn fixed_quorum_authority_is_exact_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    expected_placement_policy: PlacementResiliencePolicy,
    allow_pristine_membership: bool,
) -> io::Result<bool> {
    if !matches!(expected_members.len(), 3 | 5)
        || validate_member_bindings(expected_members, expected_bindings).is_err()
    {
        return Ok(false);
    }
    if read_fixed_placement_policy_sync(conn)
        .map_err(|_| invalid_data("session consensus fixed placement policy is invalid"))?
        != Some(expected_placement_policy)
    {
        return Ok(false);
    }
    if read_consensus_authority_profile_sync(conn)
        .map_err(|_| invalid_data("session consensus fixed authority profile is invalid"))?
        != ConsensusAuthorityProfile::FixedImmutable
    {
        return Ok(false);
    }
    if read_storage_identity_sync(conn)
        .map_err(|_| invalid_data("session consensus fixed storage identity is invalid"))?
        != identity
    {
        return Ok(false);
    }
    let scope = read_scope_for_mutation(conn, identity)
        .map_err(|_| invalid_data("session consensus fixed scope is invalid"))?;
    let membership = read_membership_sync(conn, identity)?;
    let applied_membership_is_exact = membership.log_id().is_some()
        && fixed_uniform_membership_matches(membership.membership(), expected_members);
    Ok(scope.current_identity == identity
        && scope.current_members == *expected_members
        && scope.current_bindings == *expected_bindings
        && scope.application_authority_epoch == identity.configuration_epoch()
        && scope.application_authority_members == *expected_members
        && scope.pending.is_none()
        && scope.predecessor.is_none()
        && scope.history.is_empty()
        && scope.terminal_history.is_empty()
        && scope.terminal.is_none()
        && validate_fixed_live_durable_state_sync(conn, identity, expected_members).is_ok()
        && (applied_membership_is_exact
            || (allow_pristine_membership && membership.log_id().is_none())))
}

fn validate_fixed_vote_member(
    vote: &Vote<SessionConsensusNodeId>,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    if vote
        .leader_id
        .voted_for()
        .is_some_and(|node_id| !expected_members.contains(&node_id))
    {
        return Err(invalid_data(
            "session consensus fixed vote names a nonmember",
        ));
    }
    Ok(())
}

fn validate_fixed_log_id(log_id: &LogId<SessionConsensusNodeId>) -> io::Result<()> {
    // The pinned Openraft `single-term-leader` profile serializes committed
    // leader IDs as a term only. Its `LogId` therefore carries no recoverable
    // node identity to compare here; membership-bearing state and votes retain
    // their node IDs and are checked by the fixed-authority validators.
    validate_log_id(log_id).map(|_| ())
}

fn ensure_log_id_not_after(
    earlier: &LogId<SessionConsensusNodeId>,
    later: &LogId<SessionConsensusNodeId>,
    message: &'static str,
) -> io::Result<()> {
    if earlier.index > later.index {
        return Err(invalid_data(message));
    }
    if earlier.index == later.index && earlier != later {
        return Err(invalid_data(message));
    }
    Ok(())
}

fn validate_fixed_snapshot_metadata(
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    if let Some(last_log_id) = meta.last_log_id.as_ref() {
        validate_fixed_log_id(last_log_id)?;
    }
    if is_pristine_membership(&meta.last_membership) {
        if meta.last_log_id.is_some() {
            return Err(invalid_data(
                "session consensus fixed snapshot has pristine membership after a log",
            ));
        }
        return Ok(());
    }
    validate_uniform_membership(&meta.last_membership, expected_members)?;
    let membership_log_id = meta.last_membership.log_id().ok_or_else(|| {
        invalid_data("session consensus fixed snapshot membership log identity is missing")
    })?;
    validate_fixed_log_id(&membership_log_id)?;
    let last_log_id = meta.last_log_id.as_ref().ok_or_else(|| {
        invalid_data("session consensus fixed snapshot membership is beyond its last log")
    })?;
    ensure_log_id_not_after(
        &membership_log_id,
        last_log_id,
        "session consensus fixed snapshot membership is beyond its last log",
    )
}

fn validate_fixed_live_durable_state_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    if let Some(vote) = read_vote_sync(conn, identity)? {
        validate_fixed_vote_member(&vote, expected_members)?;
    }

    let committed = read_committed_sync(conn, identity)?;
    let purged = read_purged_sync(conn, identity)?;
    let applied = read_applied_sync(conn, identity)?;
    for log_id in [&committed, &purged, &applied].into_iter().flatten() {
        validate_fixed_log_id(log_id)?;
    }
    if let (Some(purged), Some(applied)) = (&purged, &applied) {
        ensure_log_id_not_after(
            purged,
            applied,
            "session consensus fixed purged pointer is beyond applied state",
        )?;
    }

    let membership = read_membership_sync(conn, identity)?;
    if !is_pristine_membership(&membership) {
        validate_uniform_membership(&membership, expected_members)?;
        let membership_log_id = membership.log_id().ok_or_else(|| {
            invalid_data("session consensus fixed membership log identity is missing")
        })?;
        validate_fixed_log_id(&membership_log_id)?;
        let applied = applied.as_ref().ok_or_else(|| {
            invalid_data("session consensus fixed membership is beyond applied state")
        })?;
        ensure_log_id_not_after(
            &membership_log_id,
            applied,
            "session consensus fixed membership is beyond applied state",
        )?;
    } else if applied.is_some() {
        return Err(invalid_data(
            "session consensus fixed applied state has pristine membership",
        ));
    }

    if let Some((meta, _, _, _)) = read_current_snapshot_sync(conn, identity)? {
        validate_fixed_snapshot_metadata(&meta, expected_members)?;
        match (meta.last_log_id.as_ref(), applied.as_ref()) {
            (Some(snapshot), Some(applied)) => ensure_log_id_not_after(
                snapshot,
                applied,
                "session consensus fixed snapshot is beyond applied state",
            )?,
            (Some(_), None) => {
                return Err(invalid_data(
                    "session consensus fixed snapshot is beyond applied state",
                ));
            }
            (None, _) => {}
        }
    }

    Ok(())
}

/// Deeply validate retained fixed-quorum state at startup/reopen. Live engine
/// admission uses [`validate_fixed_live_durable_state_sync`] so authenticated
/// heartbeats and ordinary writes remain bounded independently of retained log
/// length. Incoming entries are validated before their individual raw writes.
fn validate_fixed_durable_state_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    validate_fixed_live_durable_state_sync(conn, identity, expected_members)?;
    let mut statement = conn
        .prepare(
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log ORDER BY log_index ASC",
        )
        .map_err(db_error)?;
    let mut rows = statement.query([]).map_err(db_error)?;
    while let Some(row) = rows.next().map_err(db_error)? {
        let epoch: i64 = row.get(0).map_err(db_error)?;
        let term: i64 = row.get(1).map_err(db_error)?;
        let index: i64 = row.get(2).map_err(db_error)?;
        let encoded: Vec<u8> = row.get(3).map_err(db_error)?;
        validate_epoch(epoch, identity)?;
        let entry: Entry<SessionRaftTypeConfig> = decode_json(&encoded)?;
        validate_fixed_log_id(&entry.log_id)?;
        if checked_u64(term)? != entry.log_id.leader_id.term
            || checked_u64(index)? != entry.log_id.index
            || fixed_profile_entry_changes_topology(&entry, expected_members)
        {
            return Err(invalid_data("session consensus fixed log entry is invalid"));
        }
    }
    Ok(())
}

fn fixed_profile_entry_changes_topology(
    entry: &Entry<SessionRaftTypeConfig>,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> bool {
    match &entry.payload {
        EntryPayload::Membership(membership) => {
            !fixed_uniform_membership_matches(membership, expected_members)
        }
        EntryPayload::Normal(command) => fixed_profile_intent_changes_topology(&command.intent),
        EntryPayload::Blank => false,
    }
}

fn fixed_profile_intent_changes_topology(intent: &SessionMutationIntent) -> bool {
    match intent {
        SessionMutationIntent::PrepareTopologyTransition { .. }
        | SessionMutationIntent::MarkTopologyLearnersReady { .. }
        | SessionMutationIntent::FenceTopologyAuthority { .. }
        | SessionMutationIntent::AbortTopologyTransition { .. }
        | SessionMutationIntent::FinalizeTopologyTransition { .. } => true,
        SessionMutationIntent::Authorized { mutation, .. } => {
            fixed_profile_intent_changes_topology(mutation)
        }
        _ => false,
    }
}

/// Revalidate fixed-quorum authority inside a raw Openraft durable access.
///
/// The pristine exception is limited to the initial formation interval:
/// `read_membership_sync` rejects a pristine membership once any application
/// state exists, while the scope/profile checks bind that interval to the
/// configured immutable quorum.
fn validate_durable_authority_for_raw_access(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
) -> io::Result<()> {
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable
        && !fixed_quorum_authority_is_exact_sync(
            conn,
            identity,
            expected_members,
            expected_bindings,
            fixed_placement_policy.ok_or_else(|| {
                invalid_data("session consensus fixed placement policy is missing")
            })?,
            true,
        )?
    {
        return Err(invalid_data(
            "session consensus fixed authority is no longer exact",
        ));
    }
    Ok(())
}

/// Admit one raw Openraft metadata read against an exact fixed durable head.
///
/// Fixed stores acquire a SQLite read transaction before checking the durable
/// authority tuple, then perform the caller's entire read through that same
/// snapshot. This prevents a persisted profile, placement-policy, identity,
/// binding, scope, or applied-membership drift from racing between admission
/// and return. Dynamic stores retain their existing read path unchanged.
pub(crate) fn with_durable_authority_raw_read_sync<T>(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    read: impl FnOnce(&Connection) -> io::Result<T>,
) -> io::Result<T> {
    if authority_profile == ConsensusAuthorityProfile::Dynamic {
        return read(conn);
    }

    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Deferred).map_err(db_error)?;
    validate_durable_authority_for_raw_access(
        &tx,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
    )?;
    let value = read(&tx)?;
    tx.commit().map_err(db_error)?;
    Ok(value)
}

fn fixed_uniform_membership_matches(
    membership: &Membership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> bool {
    let nodes = membership
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    membership.get_joint_config().len() == 1
        && membership.get_joint_config().first() == Some(expected_members)
        && membership.learner_ids().next().is_none()
        && nodes == *expected_members
}

fn validate_record_expiry_bounds_at_sync(
    conn: &Connection,
    reference: Timestamp,
) -> io::Result<()> {
    let mut statement = conn
        .prepare("SELECT state_class, expires_at FROM session_records")
        .map_err(db_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(db_error)?;
    for row in rows {
        let (state_class, expires_at) = row.map_err(db_error)?;
        let state_class = match state_class.as_str() {
            "authoritative-session" => crate::model::StateClass::AuthoritativeSession,
            "dataplane-lookup" => crate::model::StateClass::DataplaneLookup,
            "replicated-dr" => crate::model::StateClass::ReplicatedDr,
            "telemetry-derived" => crate::model::StateClass::TelemetryDerived,
            "ephemeral-procedure" => crate::model::StateClass::EphemeralProcedure,
            _ => {
                return Err(invalid_data(
                    "session consensus snapshot state class is invalid",
                ));
            }
        };
        let expires_at = expires_at
            .map(|value| ops::parse_persisted_rfc3339_normalized(&value))
            .transpose()
            .map_err(|_| invalid_data("session consensus snapshot record expiry is invalid"))?;
        crate::ttl::validate_record_expiry_at(expires_at, state_class, reference)
            .map_err(|_| invalid_data("session consensus snapshot record expiry is invalid"))?;
    }
    Ok(())
}

pub(crate) fn validate_sealed_state_sync(conn: &Connection) -> io::Result<()> {
    // A consensus-owned state machine carries its immutable time authority in
    // the machine row.  Do not substitute a reopen-time clock here: doing so
    // would make identical durable state admit differently on different
    // nodes.  Legacy claim performs its corresponding validation against the
    // final persisted replication timestamp before installing this row.
    let consensus_machine_present = table_exists(conn, "consensus_machine").map_err(db_error)?;
    let expiry_reference = if consensus_machine_present {
        let logical_time: Option<String> = conn
            .query_row(
                "SELECT logical_time FROM consensus_machine WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        logical_time
            .map(|value| {
                ops::parse_persisted_rfc3339_normalized(&value).map_err(|_| {
                    invalid_data("persisted session consensus logical time is invalid")
                })
            })
            .transpose()?
    } else {
        None
    };
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
        super::validate_consensus_record(&record).map_err(|error| match error {
            StoreError::PayloadTooLarge { .. } => invalid_data(
                "session consensus snapshot record exceeds the consensus payload limit",
            ),
            StoreError::Crypto(_)
                if record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 =>
            {
                invalid_data("session consensus snapshot contains an unsealed record payload")
            }
            _ => invalid_data("session consensus snapshot envelope is invalid"),
        })?;
        crate::ttl::validate_stored_record_expiry_profile(&record)
            .map_err(|_| invalid_data("session consensus snapshot record expiry is invalid"))?;
        if let Some(reference) = expiry_reference {
            crate::ttl::validate_stored_record_expiry_at(&record, reference)
                .map_err(|_| invalid_data("session consensus snapshot record expiry is invalid"))?;
        } else if consensus_machine_present && record.expires_at.is_some() {
            return Err(invalid_data(
                "session consensus finite record expiry has no logical time authority",
            ));
        }
    }

    validate_lease_state_sync(conn)?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT sequence,
                   CASE
                       WHEN typeof(tx_id) = 'text'
                        AND length(CAST(tx_id AS BLOB)) BETWEEN ?1 AND ?2
                       THEN tx_id
                   END,
                   entry_json,
                   timestamp
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
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(db_error)?;
    let mut expected = read_watch_cursor_invalidation_floor_sync(conn)?
        .checked_add(1)
        .ok_or_else(|| invalid_data("session replication sequence exhausted"))?;
    for row in rows {
        let (stored_sequence, stored_tx_id, encoded, stored_timestamp) = row.map_err(db_error)?;
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
        let timestamp = ops::parse_persisted_rfc3339_normalized(&stored_timestamp)
            .map_err(|_| invalid_data("persisted session replication timestamp is invalid"))?;
        if entry.timestamp != timestamp {
            return Err(invalid_data(
                "persisted session replication timestamp is inconsistent",
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

pub(crate) fn validate_lease_state_sync(conn: &Connection) -> io::Result<()> {
    let invalid_lease_state = || invalid_data("session consensus snapshot lease state is invalid");
    let mut maximum_fence = 0_u64;
    let mut maximum_credential = 0_u64;

    let mut lease_stmt = conn
        .prepare(
            r#"
            SELECT tenant, nf_kind, key_type, stable_id, active, credential_id,
                   owner, fence, expires_at_unix_ms, guard_expires_at
            FROM leases
            "#,
        )
        .map_err(db_error)?;
    let leases = lease_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(db_error)?;
    for row in leases {
        let (
            tenant,
            nf_kind,
            key_type,
            stable_id,
            active,
            credential,
            owner,
            fence,
            expires_at_unix_ms,
            guard_expires_at,
        ) = row.map_err(db_error)?;
        ops::persisted_session_key(tenant, nf_kind, key_type, stable_id)
            .map_err(|_| invalid_lease_state())?;
        if !matches!(active, 0 | 1) {
            return Err(invalid_lease_state());
        }
        let credential = checked_positive_u64(credential).map_err(|_| invalid_lease_state())?;
        let fence = checked_positive_u64(fence).map_err(|_| invalid_lease_state())?;
        ops::persisted_owner_id(owner).map_err(|_| invalid_lease_state())?;
        let guard_expires_at = ops::parse_persisted_rfc3339_normalized(&guard_expires_at)
            .map_err(|_| invalid_lease_state())?;
        let guard_expires_at_unix_ms =
            ops::timestamp_unix_millis(guard_expires_at).map_err(|_| invalid_lease_state())?;
        if (active == 1 && expires_at_unix_ms != guard_expires_at_unix_ms)
            || (active == 0 && expires_at_unix_ms < guard_expires_at_unix_ms)
        {
            return Err(invalid_lease_state());
        }
        maximum_fence = maximum_fence.max(fence);
        maximum_credential = maximum_credential.max(credential);
    }

    let mut fence_stmt = conn
        .prepare("SELECT tenant, nf_kind, key_type, stable_id, fence FROM key_fences")
        .map_err(db_error)?;
    let fences = fence_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(db_error)?;
    for row in fences {
        let (tenant, nf_kind, key_type, stable_id, fence) = row.map_err(db_error)?;
        ops::persisted_session_key(tenant, nf_kind, key_type, stable_id)
            .map_err(|_| invalid_lease_state())?;
        maximum_fence =
            maximum_fence.max(checked_positive_u64(fence).map_err(|_| invalid_lease_state())?);
    }

    let stale_or_missing_fence = conn
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM session_records AS record
                LEFT JOIN key_fences AS fence
                  ON fence.tenant = record.tenant
                 AND fence.nf_kind = record.nf_kind
                 AND fence.key_type = record.key_type
                 AND fence.stable_id = record.stable_id
                WHERE fence.fence IS NULL OR fence.fence < record.fence
                UNION ALL
                SELECT 1
                FROM session_records AS record
                JOIN leases AS lease
                  ON lease.tenant = record.tenant
                 AND lease.nf_kind = record.nf_kind
                 AND lease.key_type = record.key_type
                 AND lease.stable_id = record.stable_id
                WHERE record.fence = lease.fence
                  AND record.owner != lease.owner
                UNION ALL
                SELECT 1
                FROM leases AS lease
                LEFT JOIN key_fences AS fence
                  ON fence.tenant = lease.tenant
                 AND fence.nf_kind = lease.nf_kind
                 AND fence.key_type = lease.key_type
                 AND fence.stable_id = lease.stable_id
                WHERE fence.fence IS NULL OR fence.fence != lease.fence
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(db_error)?;
    if stale_or_missing_fence {
        return Err(invalid_lease_state());
    }

    let mut next_fence = None;
    let mut next_credential = None;
    let mut globals_stmt = conn
        .prepare("SELECT key, val FROM lease_globals ORDER BY key")
        .map_err(db_error)?;
    let globals = globals_stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(db_error)?;
    for row in globals {
        let (key, value) = row.map_err(db_error)?;
        let value = checked_positive_u64(value).map_err(|_| invalid_lease_state())?;
        let slot = match key.as_str() {
            "next_fence" => &mut next_fence,
            "next_credential_id" => &mut next_credential,
            _ => return Err(invalid_lease_state()),
        };
        if slot.replace(value).is_some() {
            return Err(invalid_lease_state());
        }
    }
    if next_fence.is_none_or(|next| next <= maximum_fence)
        || next_credential.is_none_or(|next| next <= maximum_credential)
    {
        return Err(invalid_lease_state());
    }
    Ok(())
}

pub(crate) fn validate_sealed_replication_op(root: &ReplicationOp) -> io::Result<()> {
    super::replication::validate_replication_payloads(
        root,
        super::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
    )
    .map_err(|_| invalid_data("session replication log violates consensus admission"))?;
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
                super::validate_consensus_record(new_record).map_err(|_| {
                    invalid_data("session replication log contains an invalid envelope")
                })?;
            }
            ReplicationOp::Batch { ops } => pending.extend(ops),
            _ => {}
        }
    }
    Ok(())
}

/// Validate every durable source authority before copying a snapshot. In
/// particular, retained Raft entries are still available at this point to
/// bind each replay receipt to its immutable command; after compaction their
/// absence is intentionally not treated as reconstructible evidence.
fn validate_snapshot_source_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    validate_sealed_state_sync(conn)?;
    validate_recovery_receipts_and_admission_sync(conn, identity)
}

#[allow(dead_code)]
pub(crate) fn build_snapshot_database_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    path: &std::path::Path,
) -> io::Result<ConsensusAppliedMembership> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Deferred).map_err(db_error)?;
    validate_snapshot_source_sync(&tx, identity)?;
    let destination = create_pinned_snapshot_database(path)?;
    let (snapshot, _) = build_snapshot_database_from_pinned_sync(&tx, identity, destination)?;
    tx.commit().map_err(db_error)?;
    Ok(snapshot)
}

pub(crate) fn build_snapshot_database_pinned_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    path: &std::path::Path,
) -> io::Result<(
    ConsensusAppliedMembership,
    crate::consensus::snapshot::PinnedSqliteFile,
)> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Deferred).map_err(db_error)?;
    validate_durable_authority_for_raw_access(
        &tx,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
    )?;
    validate_snapshot_source_sync(&tx, identity)?;
    // Do not create even an empty snapshot artifact until the durable fixed
    // authority and retained-log receipt checks have succeeded under the
    // source read transaction.
    let destination = create_pinned_snapshot_database(path)?;
    let (snapshot, destination) =
        capture_and_finalize_validated_snapshot_database_sync(&tx, identity, destination)?;
    tx.commit().map_err(db_error)?;
    Ok((snapshot, destination))
}

#[allow(dead_code)]
pub(crate) fn build_snapshot_database_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    path: &std::path::Path,
) -> io::Result<ConsensusAppliedMembership> {
    if authority_profile == ConsensusAuthorityProfile::Dynamic {
        return build_snapshot_database_sync(conn, identity, path);
    }
    build_snapshot_database_pinned_with_authority_sync(
        conn,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
        path,
    )
    .map(|(snapshot, _)| snapshot)
}

fn build_snapshot_database_from_pinned_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    destination: crate::consensus::snapshot::PinnedSqliteFile,
) -> io::Result<(
    ConsensusAppliedMembership,
    crate::consensus::snapshot::PinnedSqliteFile,
)> {
    capture_and_finalize_validated_snapshot_database_sync(conn, identity, destination)
}

#[allow(dead_code)]
fn create_pinned_snapshot_database(
    path: &std::path::Path,
) -> io::Result<crate::consensus::snapshot::PinnedSqliteFile> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = OpenOptions::new();
        options
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        crate::consensus::snapshot::PinnedSqliteFile::from_file(
            options.open(path)?,
            path.to_path_buf(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "pinned SQLite snapshot binding requires Linux",
        ))
    }
}

fn refresh_pinned_snapshot_database(
    pinned: crate::consensus::snapshot::PinnedSqliteFile,
) -> io::Result<crate::consensus::snapshot::PinnedSqliteFile> {
    let path = pinned.path().to_path_buf();
    crate::consensus::snapshot::PinnedSqliteFile::from_file(pinned.into_file(), path)
}

#[cfg(target_os = "linux")]
fn matching_pinned_snapshot_descriptors(
    pinned: &crate::consensus::snapshot::PinnedSqliteFile,
) -> io::Result<BTreeSet<std::os::fd::RawFd>> {
    let mut descriptors = BTreeSet::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<std::os::fd::RawFd>().ok())
        else {
            continue;
        };
        match pinned.path_matches_identity(&entry.path()) {
            Ok(true) => {
                descriptors.insert(fd);
            }
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(descriptors)
}

#[cfg(not(target_os = "linux"))]
fn matching_pinned_snapshot_descriptors(
    _pinned: &crate::consensus::snapshot::PinnedSqliteFile,
) -> io::Result<BTreeSet<i32>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "pinned SQLite snapshot binding requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn pinned_snapshot_uri(
    pinned: &crate::consensus::snapshot::PinnedSqliteFile,
    read_only: bool,
) -> String {
    let mode = if read_only { "ro" } else { "rw" };
    format!(
        "file:/proc/self/fd/{}?mode={mode}&cache=private{}",
        pinned.raw_fd(),
        if read_only { "&immutable=1" } else { "" }
    )
}

#[cfg(not(target_os = "linux"))]
fn pinned_snapshot_uri(
    _pinned: &crate::consensus::snapshot::PinnedSqliteFile,
    _read_only: bool,
) -> String {
    String::new()
}

#[cfg(target_os = "linux")]
fn open_pinned_snapshot_database(
    pinned: &crate::consensus::snapshot::PinnedSqliteFile,
) -> io::Result<(Connection, BTreeSet<std::os::fd::RawFd>)> {
    pinned.verify_identity()?;
    let before = matching_pinned_snapshot_descriptors(pinned)?;
    let uri = pinned_snapshot_uri(pinned, false);
    let destination = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(db_error)?;
    destination
        .query_row("PRAGMA schema_version", [], |_| Ok(()))
        .map_err(db_error)?;
    let after = matching_pinned_snapshot_descriptors(pinned)?;
    let opened = after.difference(&before).copied().collect::<BTreeSet<_>>();
    if opened.len() != 1 {
        return Err(invalid_data(
            "SQLite did not retain exactly one pinned snapshot descriptor",
        ));
    }
    Ok((destination, opened))
}

#[cfg(not(target_os = "linux"))]
fn open_pinned_snapshot_database(
    _pinned: &crate::consensus::snapshot::PinnedSqliteFile,
) -> io::Result<(Connection, BTreeSet<i32>)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "pinned SQLite snapshot binding requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn verify_pinned_snapshot_descriptor(
    pinned: &crate::consensus::snapshot::PinnedSqliteFile,
    retained: &BTreeSet<std::os::fd::RawFd>,
) -> io::Result<()> {
    pinned.verify_identity()?;
    let observed = matching_pinned_snapshot_descriptors(pinned)?;
    if retained.is_empty() || !retained.is_subset(&observed) {
        return Err(invalid_data(
            "SQLite released the pinned snapshot descriptor",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_pinned_snapshot_descriptor(
    _pinned: &crate::consensus::snapshot::PinnedSqliteFile,
    _retained: &BTreeSet<i32>,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "pinned SQLite snapshot binding requires Linux",
    ))
}

/// Capture an already-validated source image while the caller holds the SQLite
/// transaction that admitted it. Validation and backup therefore observe the
/// same pinned source snapshot without repeating the complete source scan.
fn capture_and_finalize_validated_snapshot_database_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    mut pinned: crate::consensus::snapshot::PinnedSqliteFile,
) -> io::Result<(
    ConsensusAppliedMembership,
    crate::consensus::snapshot::PinnedSqliteFile,
)> {
    let applied = read_applied_sync(conn, identity)?;
    let membership = read_membership_sync(conn, identity)?;
    validate_membership_ids(&membership)?;

    let (mut destination, descriptor_fds) = open_pinned_snapshot_database(&pinned)?;
    destination
        .execute_batch("PRAGMA journal_mode = OFF;")
        .map_err(db_error)?;
    {
        let backup = rusqlite::backup::Backup::new(conn, &mut destination).map_err(db_error)?;
        backup
            .run_to_completion(128, std::time::Duration::ZERO, None)
            .map_err(db_error)?;
    }
    pinned = refresh_pinned_snapshot_database(pinned)?;
    verify_pinned_snapshot_descriptor(&pinned, &descriptor_fds)?;
    destination
        .execute_batch(
            r#"
            DELETE FROM consensus_vote;
            DELETE FROM consensus_committed;
            DELETE FROM consensus_purged;
            DELETE FROM consensus_log;
            DELETE FROM consensus_snapshot;
            PRAGMA journal_mode = OFF;
            VACUUM;
            "#,
        )
        .map_err(db_error)?;
    ops::rotate_restore_scan_epoch_sync(&destination)
        .map_err(|_| invalid_data("built session consensus snapshot restore metadata failed"))?;
    validate_existing_schema(&destination, identity)
        .map_err(|_| invalid_data("built session consensus snapshot failed validation"))?;
    // The source was validated while its retained log still existed. Recheck
    // the self-contained receipt/admission chain after compaction so the
    // copied snapshot cannot retain a damaged head or receipt link.
    validate_recovery_receipts_and_admission_sync(&destination, identity)
        .map_err(|_| invalid_data("built session consensus snapshot receipt validation failed"))?;
    validate_sealed_state_sync(&destination)?;
    pinned = refresh_pinned_snapshot_database(pinned)?;
    verify_pinned_snapshot_descriptor(&pinned, &descriptor_fds)?;
    drop(destination);
    Ok(((applied, membership), pinned))
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
        && local.desired_bindings == incoming.desired_bindings
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
    let abort_scope_matches = match terminal.outcome {
        TerminalMembershipOutcome::Aborted => {
            terminal.abort_cleanup.as_ref().is_some_and(|cleanup| {
                cleanup.desired_identity == local.desired_identity
                    && cleanup.desired_members == local.desired_members
                    && cleanup.desired_bindings == local.desired_bindings
            })
        }
        TerminalMembershipOutcome::Promoted => terminal.abort_cleanup.is_none(),
    };
    local.transition_id == terminal.transition_id
        && local.transition_digest == terminal.transition_digest
        && abort_scope_matches
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
    let abort_cleanup_is_not_behind = match (&local.abort_cleanup, &incoming.abort_cleanup) {
        (None, None) => true,
        (Some(local), Some(incoming)) => {
            local.desired_identity == incoming.desired_identity
                && local.desired_members == incoming.desired_members
                && local.desired_bindings == incoming.desired_bindings
                && local.learners == incoming.learners
                && local.decision_log_index == incoming.decision_log_index
                && (local.cleanup_log_index.is_none()
                    || local.cleanup_log_index == incoming.cleanup_log_index)
        }
        (None, Some(_)) | (Some(_), None) => false,
    };
    local.transition_id == incoming.transition_id
        && local.transition_digest == incoming.transition_digest
        && local.outcome == incoming.outcome
        && local.transition_start_log_index == incoming.transition_start_log_index
        && local.learners_ready_log_index == incoming.learners_ready_log_index
        && local.joint_membership_log_index == incoming.joint_membership_log_index
        && local.uniform_membership_log_index == incoming.uniform_membership_log_index
        && local.cutover_log_index == incoming.cutover_log_index
        && abort_cleanup_is_not_behind
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

fn retained_terminal_history_is_not_behind(
    local: &[RetainedTerminalMembershipTransition],
    incoming: &[RetainedTerminalMembershipTransition],
) -> bool {
    local.iter().all(|local_terminal| {
        incoming
            .iter()
            .any(|incoming_terminal| incoming_terminal == local_terminal)
    })
}

fn retained_terminal_state_is_not_behind(
    local: &MembershipValidationScope,
    incoming: &MembershipValidationScope,
) -> bool {
    let Some(local_terminal) = local.terminal.as_ref() else {
        return true;
    };
    if incoming.terminal.as_ref().is_some_and(|incoming_terminal| {
        finalized_terminal_is_not_behind(local_terminal, incoming_terminal)
    }) {
        return true;
    }
    completed_terminal_from_scope(local)
        .ok()
        .flatten()
        .is_some_and(|local_terminal| {
            incoming
                .terminal_history
                .iter()
                .any(|incoming_terminal| incoming_terminal == &local_terminal)
        })
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
    if !retained_terminal_history_is_not_behind(&local.terminal_history, &incoming.terminal_history)
        || !retained_terminal_state_is_not_behind(local, incoming)
    {
        return Err(invalid_data(
            "session consensus snapshot terminal history regressed or diverged",
        ));
    }

    if local.pending.is_none()
        && incoming.pending.is_none()
        && local.current_identity == incoming.current_identity
        && local.current_members == incoming.current_members
        && local.application_authority_epoch == incoming.application_authority_epoch
        && local.application_authority_members == incoming.application_authority_members
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
        if same_current
            && authority_not_behind
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

fn validate_fixed_immutable_membership_scope(
    storage_identity: SessionConsensusIdentity,
    expected: &MembershipValidationScope,
    incoming: &MembershipValidationScope,
) -> io::Result<()> {
    let exact_fixed_scope = incoming == expected
        && incoming.current_identity == storage_identity
        && matches!(incoming.current_members.len(), 3 | 5)
        && incoming.current_bindings.len() == incoming.current_members.len()
        && incoming
            .current_bindings
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            == incoming.current_members
        && incoming.application_authority_epoch == storage_identity.configuration_epoch()
        && incoming.application_authority_members == incoming.current_members
        && incoming.predecessor.is_none()
        && incoming.history.is_empty()
        && incoming.terminal_history.is_empty()
        && incoming.pending.is_none()
        && incoming.terminal.is_none();
    if exact_fixed_scope {
        Ok(())
    } else {
        Err(invalid_data(
            "fixed session consensus snapshot membership scope is not exact",
        ))
    }
}

/// Read-only tables that are shadowed temporarily while validating the
/// already-attached incoming snapshot. The names are constants controlled by
/// this adapter; no snapshot-supplied identifier is interpolated into SQL.
const ATTACHED_SNAPSHOT_VALIDATION_TABLES: &[&str] = &[
    "consensus_identity",
    "session_records",
    "leases",
    "key_fences",
    "lease_globals",
    "session_replication_log",
    "consensus_membership_scope",
    "consensus_membership_history",
    "consensus_membership_terminal_history",
    "consensus_candidate_bootstrap",
    "consensus_vote",
    "consensus_committed",
    "consensus_purged",
    "consensus_log",
    "consensus_applied",
    "consensus_membership",
    "consensus_machine",
    "consensus_request_outcomes",
    "consensus_command_admission",
    "consensus_snapshot",
    "consensus_operator_recovery",
    "restore_scan_state",
];

/// The only historical physical layouts admitted for Dynamic consensus.
///
/// The first is the released image from before authority-profile fields were
/// introduced. The second is that exact image after the two reviewed
/// `ALTER TABLE` migrations have run during a Dynamic reopen. Neither layout
/// can represent fixed authority, and no other DDL variation is accepted.
#[derive(Clone, Copy)]
enum SnapshotSchemaLayout {
    Current,
    LegacyDynamicWithoutProfile,
    LegacyDynamicMigratedProfile,
}

fn canonical_snapshot_schema_inventory_sync(
    layout: SnapshotSchemaLayout,
) -> io::Result<BTreeMap<String, String>> {
    // Build the manifest through the production schema constructors rather
    // than maintaining a second handwritten copy of the large table DDL.
    // `sqlite_schema.sql` preserves the CREATE/ALTER text, so this compares
    // the complete constraints and physical column layout, not just names.
    let canonical = SqliteSessionBackend::canonical_schema_connection()
        .map_err(|_| invalid_data("session consensus canonical snapshot schema is unavailable"))?;
    install_recovery_validation_schema_sync(&canonical, false)?;
    match layout {
        SnapshotSchemaLayout::Current => {}
        SnapshotSchemaLayout::LegacyDynamicWithoutProfile => canonical
            .execute_batch(
                "ALTER TABLE consensus_identity DROP COLUMN authority_profile;\
                 ALTER TABLE consensus_identity DROP COLUMN fixed_placement_policy;",
            )
            .map_err(db_error)?,
        SnapshotSchemaLayout::LegacyDynamicMigratedProfile => canonical
            .execute_batch(
                "ALTER TABLE consensus_identity DROP COLUMN authority_profile;\
                 ALTER TABLE consensus_identity DROP COLUMN fixed_placement_policy;\
                 ALTER TABLE consensus_identity ADD COLUMN authority_profile INTEGER CHECK (authority_profile IN (1, 2));\
                 ALTER TABLE consensus_identity ADD COLUMN fixed_placement_policy INTEGER CHECK (fixed_placement_policy IN (1, 2));",
            )
            .map_err(db_error)?,
    }

    let mut inventory = BTreeMap::new();
    for table in ATTACHED_SNAPSHOT_VALIDATION_TABLES {
        let ddl: String = canonical
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if inventory.insert((*table).to_owned(), ddl).is_some() {
            return Err(invalid_data(
                "session consensus canonical snapshot schema is duplicated",
            ));
        }
    }
    Ok(inventory)
}

/// The incoming image is an authority-bearing database, not a general SQLite
/// document. Admit only the exact allowlisted ordinary-table schema. In
/// particular, a same-column view is not a table: allowing one here would
/// make validation observe a query while the later copy could see different
/// results.
fn validate_snapshot_schema_inventory_sync(
    conn: &Connection,
    schema: &str,
    authority_profile: ConsensusAuthorityProfile,
) -> io::Result<()> {
    let sql = format!(
        "SELECT type, name, sql FROM {schema}.sqlite_schema \
         WHERE substr(name, 1, 7) != 'sqlite_' COLLATE NOCASE ORDER BY type, name"
    );
    let mut statement = conn.prepare(&sql).map_err(db_error)?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    let mut expected_layouts = vec![canonical_snapshot_schema_inventory_sync(
        SnapshotSchemaLayout::Current,
    )?];
    if authority_profile == ConsensusAuthorityProfile::Dynamic {
        expected_layouts.push(canonical_snapshot_schema_inventory_sync(
            SnapshotSchemaLayout::LegacyDynamicWithoutProfile,
        )?);
        expected_layouts.push(canonical_snapshot_schema_inventory_sync(
            SnapshotSchemaLayout::LegacyDynamicMigratedProfile,
        )?);
    }
    let schema_is_exact = expected_layouts.iter().any(|expected| {
        objects.len() == expected.len()
            && objects.iter().all(|(kind, name, ddl)| {
                kind == "table"
                    && ddl
                        .as_ref()
                        .is_some_and(|ddl| expected.get(name) == Some(ddl))
            })
    });
    if !schema_is_exact {
        return Err(invalid_data(
            "session consensus snapshot schema inventory is invalid",
        ));
    }
    Ok(())
}

/// Ordered source/destination manifests for every replicated snapshot table.
///
/// Keep these expressions identical for the copy and equality checks. SQLite
/// `SELECT *` is positional, so it would silently compare different logical
/// values if a compatible migration ever changed physical column order.
const SNAPSHOT_COPY_TABLE_MANIFESTS: &[(&str, &str)] = &[
    (
        "session_records",
        "tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, state_type, expires_at, payload, encoding",
    ),
    (
        "leases",
        "tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at",
    ),
    ("key_fences", "tenant, nf_kind, key_type, stable_id, fence"),
    ("lease_globals", "key, val"),
    (
        "session_replication_log",
        "sequence, tx_id, entry_json, timestamp",
    ),
    (
        "consensus_request_outcomes",
        "request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest",
    ),
    (
        "consensus_command_admission",
        "singleton, configuration_epoch, admission_revision, strict_activation_index, cutover_committed",
    ),
    (
        "consensus_machine",
        "singleton, configuration_epoch, application_sequence, last_digest, last_receipt_digest, logical_time, watch_sequence",
    ),
    (
        "consensus_membership",
        "singleton, configuration_epoch, membership_json",
    ),
    (
        "consensus_membership_scope",
        "singleton, storage_configuration_epoch, current_configuration_id, current_configuration_epoch, current_members_json, current_bindings_json, application_authority_epoch, application_authority_members_json, predecessor_configuration_id, predecessor_transition_id, predecessor_transition_digest, predecessor_configuration_epoch, predecessor_members_json, predecessor_transition_start_index, predecessor_cutover_index, pending_transition_id, pending_transition_digest, desired_configuration_id, desired_configuration_epoch, desired_members_json, desired_bindings_json, pending_transition_start_index, pending_learners_ready_index, pending_joint_membership_index, pending_uniform_membership_index, terminal_transition_id, terminal_transition_digest, terminal_transition_outcome, terminal_transition_start_index, terminal_learners_ready_index, terminal_joint_membership_index, terminal_uniform_membership_index, terminal_cutover_index, terminal_finalization_index, terminal_desired_configuration_id, terminal_desired_configuration_epoch, terminal_desired_members_json, terminal_desired_bindings_json, terminal_abort_learners_json, terminal_abort_decision_index, terminal_abort_cleanup_membership_index",
    ),
    (
        "consensus_membership_history",
        "configuration_epoch, storage_configuration_epoch, configuration_id, members_json, transition_id, transition_digest, transition_start_index, cutover_index",
    ),
    (
        "consensus_membership_terminal_history",
        "transition_id, storage_configuration_epoch, transition_digest, outcome, expected_member_count, transition_start_index, learners_ready_index, joint_membership_index, uniform_membership_index, cutover_index, finalization_index, abort_decision_index, abort_cleanup_membership_index",
    ),
    (
        "consensus_applied",
        "singleton, configuration_epoch, term, log_index, log_id_json",
    ),
    (
        "consensus_operator_recovery",
        "singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, pending_fence_high_water, pending_credential_high_water, watch_cursor_invalidation_floor",
    ),
    (
        "restore_scan_state",
        "singleton, epoch, revision, cursor_key",
    ),
];

fn validate_copied_snapshot_tables_match_sync(conn: &Connection) -> io::Result<()> {
    // This comparison happens after every copy but before local-only restore
    // metadata is rotated. `EXCEPT` gives set equality; the authoritative
    // tables all have primary keys, so it is also row equality.
    for (table, columns) in SNAPSHOT_COPY_TABLE_MANIFESTS {
        let sql = format!(
            "SELECT EXISTS(\
                SELECT 1 FROM (SELECT {columns} FROM main.{table} EXCEPT SELECT {columns} FROM consensus_incoming.{table}) \
                UNION ALL \
                SELECT 1 FROM (SELECT {columns} FROM consensus_incoming.{table} EXCEPT SELECT {columns} FROM main.{table})\
             )"
        );
        let differs: bool = conn
            .query_row(&sql, [], |row| row.get(0))
            .map_err(db_error)?;
        if differs {
            return Err(invalid_data(
                "session consensus copied snapshot tables do not match source",
            ));
        }
    }
    Ok(())
}

fn create_attached_snapshot_validation_views(conn: &Connection) -> io::Result<()> {
    for table in ATTACHED_SNAPSHOT_VALIDATION_TABLES {
        if let Err(error) = conn.execute(
            &format!("CREATE TEMP VIEW {table} AS SELECT * FROM consensus_incoming.{table}"),
            [],
        ) {
            let _ = drop_attached_snapshot_validation_views(conn);
            return Err(db_error(error));
        }
    }
    Ok(())
}

fn drop_attached_snapshot_validation_views(conn: &Connection) -> io::Result<()> {
    for table in ATTACHED_SNAPSHOT_VALIDATION_TABLES {
        conn.execute(&format!("DROP VIEW IF EXISTS temp.{table}"), [])
            .map_err(db_error)?;
    }
    Ok(())
}

/// Returns the authority profile stored by the exact attached snapshot.
///
/// Snapshots emitted before authority profiles were added have no column.
/// They are unambiguously legacy Dynamic snapshots; Fixed authority did not
/// exist in that durable format and must never infer its identity from it.
fn read_snapshot_authority_profile_sync(
    conn: &Connection,
) -> io::Result<Option<ConsensusAuthorityProfile>> {
    let has_column: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_identity') WHERE name = 'authority_profile')",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if !has_column {
        return Ok(None);
    }
    let stored: Option<i64> = conn
        .query_row(
            "SELECT authority_profile FROM consensus_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| invalid_data("session consensus snapshot authority profile is invalid"))?;
    stored
        .map(|value| {
            authority_profile_from_i64(value).map_err(|_| {
                invalid_data("session consensus snapshot authority profile is invalid")
            })
        })
        .transpose()
        .and_then(|value| {
            value.ok_or_else(|| {
                invalid_data("session consensus snapshot authority profile is invalid")
            })
        })
        .map(Some)
}

/// Whether validation is assessing the attached snapshot source or the
/// destination after its replicated state tables were copied.
///
/// The destination intentionally retains its Raft log-store authority; those
/// tables are deliberately absent from `SNAPSHOT_COPY_TABLE_MANIFESTS`. An
/// incoming snapshot, in contrast, must contain none of that authority.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SnapshotDatabaseValidationTarget {
    IncomingSource,
    InstalledDestination,
}

#[allow(clippy::too_many_arguments)]
fn validate_snapshot_database_sync(
    conn: &Connection,
    validated_schema: &str,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_scope: &MembershipValidationScope,
    fixed_expected_members: Option<&BTreeSet<SessionConsensusNodeId>>,
    fixed_expected_bindings: Option<
        &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    >,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    local_candidate_marker: Option<CandidateBootstrapMarker>,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    target: SnapshotDatabaseValidationTarget,
) -> io::Result<()> {
    let integrity_pragma = match validated_schema {
        "consensus_incoming" => "PRAGMA consensus_incoming.integrity_check",
        "main" => "PRAGMA main.integrity_check",
        _ => return Err(invalid_data("session consensus snapshot schema is invalid")),
    };
    let integrity: String = conn
        .query_row(integrity_pragma, [], |row| row.get(0))
        .map_err(db_error)?;
    if integrity != "ok" {
        return Err(invalid_data(
            "session consensus snapshot integrity check failed",
        ));
    }
    validate_existing_schema(conn, identity)
        .map_err(|_| invalid_data("session consensus snapshot identity is invalid"))?;
    match read_snapshot_authority_profile_sync(conn)? {
        Some(incoming_profile) if incoming_profile == authority_profile => {}
        None if authority_profile == ConsensusAuthorityProfile::Dynamic => {}
        Some(_) | None => {
            return Err(invalid_data(
                "session consensus snapshot authority profile is invalid",
            ));
        }
    }
    let incoming_scope = read_membership_scope_sync(conn, identity)?;
    if local_candidate_marker.is_some_and(|marker| {
        marker.state == CandidateBootstrapState::Cancelled
            && incoming_scope.pending.as_ref().is_some_and(|pending| {
                pending.transition_id == marker.transition_id
                    && pending.transition_digest == marker.transition_digest
            })
    }) {
        return Err(invalid_data(
            "session consensus snapshot attempted to revive a cancelled candidate",
        ));
    }
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable {
        let Some(fixed_placement_policy) = fixed_placement_policy else {
            return Err(invalid_data(
                "session consensus snapshot placement policy is invalid",
            ));
        };
        if read_fixed_placement_policy_sync(conn)
            .map_err(|_| invalid_data("session consensus snapshot placement policy is invalid"))?
            != Some(fixed_placement_policy)
        {
            return Err(invalid_data(
                "session consensus snapshot placement policy is invalid",
            ));
        }
        validate_fixed_immutable_membership_scope(identity, expected_scope, &incoming_scope)?;
        if let (Some(expected_members), Some(expected_bindings)) =
            (fixed_expected_members, fixed_expected_bindings)
        {
            if !fixed_quorum_authority_is_exact_sync(
                conn,
                identity,
                expected_members,
                expected_bindings,
                fixed_placement_policy,
                true,
            )? {
                return Err(invalid_data(
                    "session consensus snapshot fixed authority is not exact",
                ));
            }
        }
    } else {
        validate_incoming_membership_scope(expected_scope, &incoming_scope)?;
    }
    ops::read_restore_scan_state_sync(conn)
        .map_err(|_| invalid_data("session consensus snapshot restore metadata is invalid"))?;
    validate_sealed_state_sync(conn)?;
    let applied = read_applied_sync(conn, identity)?;
    let membership = read_membership_sync(conn, identity)?;
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable {
        validate_uniform_membership(&membership, &incoming_scope.current_members)?;
    }
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
    if target == SnapshotDatabaseValidationTarget::IncomingSource {
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
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotInstallOutcome {
    /// The replacement transaction committed and final-file ownership is now
    /// durable. Attachment cleanup is post-commit reconciliation only.
    Committed { incoming_detached: bool },
}

struct AttachedIncomingSnapshot<'a> {
    conn: &'a Connection,
    attached: bool,
}

impl<'a> AttachedIncomingSnapshot<'a> {
    fn new(conn: &'a Connection) -> Self {
        Self {
            conn,
            attached: true,
        }
    }

    fn detach(&mut self) -> io::Result<()> {
        self.conn
            .execute("DETACH DATABASE consensus_incoming", [])
            .map_err(db_error)?;
        self.attached = false;
        Ok(())
    }

    fn detach_after_commit(&mut self, force_failure: bool) -> io::Result<()> {
        if force_failure {
            return Err(io::Error::other(
                "forced session consensus incoming snapshot detach failure",
            ));
        }
        self.detach()
    }
}

impl Drop for AttachedIncomingSnapshot<'_> {
    fn drop(&mut self) {
        if self.attached {
            let _ = self.conn.execute("DETACH DATABASE consensus_incoming", []);
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
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
    install_snapshot_database_with_profile_sync(
        conn,
        identity,
        ConsensusAuthorityProfile::Dynamic,
        snapshot_db_path,
        meta,
        final_file_name,
        checksum,
        byte_length,
    )
}

#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn install_snapshot_database_with_profile_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    snapshot_db_path: &std::path::Path,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    final_file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    install_snapshot_database_with_authority_sync(
        conn,
        identity,
        authority_profile,
        None,
        None,
        (authority_profile == ConsensusAuthorityProfile::FixedImmutable)
            .then_some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
        snapshot_db_path,
        meta,
        final_file_name,
        checksum,
        byte_length,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn install_snapshot_database_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: Option<&BTreeSet<SessionConsensusNodeId>>,
    expected_bindings: Option<&BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    snapshot_db_path: &std::path::Path,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    final_file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    let pinned = crate::consensus::snapshot::PinnedSqliteFile::from_file(
        open_nofollow_read(snapshot_db_path)?,
        snapshot_db_path.to_path_buf(),
    )?;
    install_snapshot_database_from_pinned_with_authority_sync(
        conn,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
        pinned,
        None,
        meta,
        final_file_name,
        checksum,
        byte_length,
    )
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn install_snapshot_database_from_pinned_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: Option<&BTreeSet<SessionConsensusNodeId>>,
    expected_bindings: Option<&BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    pinned: crate::consensus::snapshot::PinnedSqliteFile,
    published_snapshot: Option<(&crate::consensus::snapshot::PinnedSqliteFile, &Path)>,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    final_file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<SnapshotInstallOutcome> {
    install_snapshot_database_from_pinned_with_authority_inner_sync(
        conn,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
        pinned,
        published_snapshot,
        meta,
        final_file_name,
        checksum,
        byte_length,
        false,
    )
}

/// Test-only post-commit cleanup fault. This is an explicit argument rather
/// than process-global state so concurrent store instances cannot affect one
/// another and production calls always use the normal path above.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn install_snapshot_database_from_pinned_with_forced_detach_failure_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: Option<&BTreeSet<SessionConsensusNodeId>>,
    expected_bindings: Option<&BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    pinned: crate::consensus::snapshot::PinnedSqliteFile,
    published_snapshot: Option<(&crate::consensus::snapshot::PinnedSqliteFile, &Path)>,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    final_file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<SnapshotInstallOutcome> {
    install_snapshot_database_from_pinned_with_authority_inner_sync(
        conn,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
        pinned,
        published_snapshot,
        meta,
        final_file_name,
        checksum,
        byte_length,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn install_snapshot_database_from_pinned_with_authority_inner_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: Option<&BTreeSet<SessionConsensusNodeId>>,
    expected_bindings: Option<&BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    mut pinned: crate::consensus::snapshot::PinnedSqliteFile,
    published_snapshot: Option<(&crate::consensus::snapshot::PinnedSqliteFile, &Path)>,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    final_file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
    force_detach_failure: bool,
) -> io::Result<SnapshotInstallOutcome> {
    let incoming_last_log_id = meta.last_log_id.as_ref();
    validate_snapshot_floor(conn, identity, incoming_last_log_id)?;
    let expected_scope = read_membership_scope_sync(conn, identity)?;
    let local_candidate_marker = read_candidate_bootstrap_marker_sync(conn, identity)?;
    if final_file_name.is_empty()
        || final_file_name.contains('/')
        || final_file_name.contains('\\')
        || final_file_name == "."
        || final_file_name == ".."
    {
        return Err(invalid_data("invalid session consensus snapshot file name"));
    }
    let byte_length = checked_positive_i64(byte_length)?;
    let stale_incoming: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_database_list WHERE name = 'consensus_incoming')",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if stale_incoming {
        // A prior post-commit detach is non-authoritative. Clear it before a
        // new pre-commit attachment so the shared connection remains retryable.
        conn.execute("DETACH DATABASE consensus_incoming", [])
            .map_err(db_error)?;
    }
    let before = matching_pinned_snapshot_descriptors(&pinned)?;
    let snapshot_uri = pinned_snapshot_uri(&pinned, true);
    conn.execute("ATTACH DATABASE ?1 AS consensus_incoming", [snapshot_uri])
        .map_err(db_error)?;
    let mut attachment = AttachedIncomingSnapshot::new(conn);
    conn.query_row(
        "SELECT 1 FROM consensus_incoming.sqlite_schema LIMIT 1",
        [],
        |_| Ok(()),
    )
    .map_err(db_error)?;
    let after = matching_pinned_snapshot_descriptors(&pinned)?;
    let retained_descriptors = after.difference(&before).copied().collect::<BTreeSet<_>>();
    if retained_descriptors.len() != 1 {
        return Err(invalid_data(
            "SQLite did not retain exactly one pinned incoming snapshot descriptor",
        ));
    }
    // The extracted source was sealed with no SDK-held writer. SQLite has now
    // retained an FD opened from the pinned source, so remove its only private
    // staging name before inspecting or copying any incoming bytes.
    pinned.remove_private_staging_path_after_attach()?;
    validate_snapshot_schema_inventory_sync(conn, "consensus_incoming", authority_profile)?;

    let result = (|| {
        let tx =
            Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
        // Re-check under the same transaction that swaps the state image. A
        // second process must not be able to advance the durable floor between
        // validation and replacement even though deployment admission already
        // requires one writer per backing store.
        validate_snapshot_floor(&tx, identity, incoming_last_log_id)?;
        if authority_profile == ConsensusAuthorityProfile::FixedImmutable {
            if let (Some(expected_members), Some(expected_bindings)) =
                (expected_members, expected_bindings)
            {
                // This is deliberately immediately before copying the incoming
                // tables. A drifted local fixed store must fail closed rather than
                // be repaired by an otherwise valid incoming snapshot.
                validate_durable_authority_for_raw_access(
                    &tx,
                    identity,
                    authority_profile,
                    expected_members,
                    expected_bindings,
                    fixed_placement_policy,
                )?;
            }
        }
        // ATTACH pins the incoming database handle before this transaction
        // begins. Shadowing only the fixed, adapter-controlled table names
        // lets the existing read-only validators inspect that exact attached
        // source under the transaction that will copy it. A pathname swap or
        // later writer therefore cannot substitute bytes after validation.
        create_attached_snapshot_validation_views(&tx)?;
        let validation = validate_snapshot_database_sync(
            &tx,
            "consensus_incoming",
            identity,
            authority_profile,
            &expected_scope,
            expected_members,
            expected_bindings,
            fixed_placement_policy,
            local_candidate_marker,
            meta,
            SnapshotDatabaseValidationTarget::IncomingSource,
        );
        let drop_views = drop_attached_snapshot_validation_views(&tx);
        if let Err(error) = validation {
            let _ = drop_views;
            return Err(error);
        }
        drop_views?;
        for (table, columns) in SNAPSHOT_COPY_TABLE_MANIFESTS {
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
        validate_copied_snapshot_tables_match_sync(&tx)?;
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
        validate_snapshot_schema_inventory_sync(&tx, "main", authority_profile)?;
        validate_snapshot_database_sync(
            &tx,
            "main",
            identity,
            authority_profile,
            &expected_scope,
            expected_members,
            expected_bindings,
            fixed_placement_policy,
            local_candidate_marker,
            meta,
            SnapshotDatabaseValidationTarget::InstalledDestination,
        )?;
        let installed = read_current_snapshot_sync(&tx, identity)?.ok_or_else(|| {
            invalid_data("installed session consensus snapshot metadata is missing")
        })?;
        if installed.0 != *meta
            || installed.1 != final_file_name
            || installed.2 != checksum
            || installed.3
                != u64::try_from(byte_length).map_err(|_| {
                    invalid_data("installed session consensus snapshot length is invalid")
                })?
        {
            return Err(invalid_data(
                "installed session consensus snapshot metadata is inconsistent",
            ));
        }
        verify_pinned_snapshot_descriptor(&pinned, &retained_descriptors)?;
        if let Some((published_snapshot, published_path)) = published_snapshot {
            if !published_snapshot.path_matches_identity(published_path)? {
                return Err(invalid_data(
                    "session consensus published snapshot was replaced",
                ));
            }
        }
        tx.commit().map_err(db_error)
    })();

    result?;
    // Commit transfers ownership of the final snapshot file. A failed detach
    // is cleanup reconciliation, never proof that the durable transaction
    // rolled back; Drop attempts it once more on scope exit.
    let incoming_detached = attachment.detach_after_commit(force_detach_failure).is_ok();
    Ok(SnapshotInstallOutcome::Committed { incoming_detached })
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

#[cfg(test)]
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
    save_current_snapshot_in_tx(conn, identity, meta, file_name, checksum, byte_length)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn save_current_snapshot_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    if authority_profile == ConsensusAuthorityProfile::Dynamic {
        return save_current_snapshot_sync(conn, identity, meta, file_name, checksum, byte_length);
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    validate_durable_authority_for_raw_access(
        &tx,
        identity,
        authority_profile,
        expected_members,
        expected_bindings,
        fixed_placement_policy,
    )?;
    validate_fixed_snapshot_metadata(meta, expected_members)?;
    if let Some(snapshot_log_id) = meta.last_log_id.as_ref() {
        let applied = read_applied_sync(&tx, identity)?.ok_or_else(|| {
            invalid_data("session consensus fixed snapshot is beyond applied state")
        })?;
        ensure_log_id_not_after(
            snapshot_log_id,
            &applied,
            "session consensus fixed snapshot is beyond applied state",
        )?;
    }
    save_current_snapshot_in_tx(&tx, identity, meta, file_name, checksum, byte_length)?;
    tx.commit().map_err(db_error)
}

/// Persist one published snapshot only while its final pathname still names
/// the descriptor that was sealed and verified by the caller.
///
/// Dynamic consensus uses this Linux descriptor fence too: profile choice
/// changes quorum authority, not the snapshot-file publication contract.
#[allow(clippy::too_many_arguments)]
pub(crate) fn save_current_snapshot_from_pinned_with_authority_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    authority_profile: ConsensusAuthorityProfile,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    expected_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    published_snapshot: (&crate::consensus::snapshot::PinnedSqliteFile, &Path),
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable {
        validate_durable_authority_for_raw_access(
            &tx,
            identity,
            authority_profile,
            expected_members,
            expected_bindings,
            fixed_placement_policy,
        )?;
        validate_fixed_snapshot_metadata(meta, expected_members)?;
        if let Some(snapshot_log_id) = meta.last_log_id.as_ref() {
            let applied = read_applied_sync(&tx, identity)?.ok_or_else(|| {
                invalid_data("session consensus fixed snapshot is beyond applied state")
            })?;
            ensure_log_id_not_after(
                snapshot_log_id,
                &applied,
                "session consensus fixed snapshot is beyond applied state",
            )?;
        }
    }
    save_current_snapshot_in_tx(&tx, identity, meta, file_name, checksum, byte_length)?;
    let (published_snapshot, published_path) = published_snapshot;
    published_snapshot.verify_identity()?;
    if !published_snapshot.path_matches_identity(published_path)? {
        return Err(invalid_data(
            "session consensus published snapshot was replaced",
        ));
    }
    tx.commit().map_err(db_error)
}

fn save_current_snapshot_in_tx(
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use futures_util::StreamExt;
    use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId};
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{
        serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
        AES_256_GCM_SIV_NONCE_LEN,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    use super::*;
    use crate::backend::SessionBackend;
    #[cfg(target_os = "linux")]
    use crate::consensus::snapshot::PinnedSqliteFile;
    use crate::model::{OwnerId, SessionKey, SessionKeyType};
    use crate::restore::{RestoreScanCursor, RestoreScanRequest, RestoreScanScope};

    const FIXED_TEST_PLACEMENT_POLICY: Option<PlacementResiliencePolicy> =
        Some(PlacementResiliencePolicy::RequireIndependentFailureDomains);

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

    /// These focused fixtures exercise the private post-admission read paths
    /// against deliberately malformed rows that could not pass the full
    /// initializer. Keep production admission exact while granting only the
    /// test backend the state a successfully initialized core would publish.
    fn admit_consensus_reads_for_test(backend: &SqliteSessionBackend) {
        backend.admission_state.store(
            super::super::SqliteAdmissionState::ConsensusReady as u8,
            Ordering::Release,
        );
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
            payload: EntryPayload::Normal(DurableSessionConsensusCommand::legacy(
                SessionConsensusCommand {
                    schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                    identity: identity(),
                    request_id: SessionConsensusRequestId::from_bytes([request_byte; 16]),
                    logical_time: timestamp(u8::try_from(index).expect("test log index")),
                    intent,
                },
            )),
        }
    }

    fn with_current_admission_revision(
        mut entry: Entry<SessionRaftTypeConfig>,
    ) -> Entry<SessionRaftTypeConfig> {
        let EntryPayload::Normal(command) = &mut entry.payload else {
            panic!("current-admission fixture must be a normal entry");
        };
        *command = DurableSessionConsensusCommand::current((**command).clone());
        entry
    }

    fn with_legacy_admission_revision(
        mut entry: Entry<SessionRaftTypeConfig>,
    ) -> Entry<SessionRaftTypeConfig> {
        let EntryPayload::Normal(command) = &mut entry.payload else {
            panic!("legacy-admission fixture must be a normal entry");
        };
        *command = DurableSessionConsensusCommand::legacy((**command).clone());
        entry
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
    async fn origin_main_fixed_membership_reopens_into_final_scope_without_rewriting_state() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let members = expected_members();
        initialize_schema(&conn, identity, &members).expect("initial consensus schema");

        let entries = vec![
            membership_entry(),
            acquire_entry(1, [0x91; 16], "owner-before-upgrade"),
        ];
        append_logs_sync(&conn, identity, &entries).expect("append pre-upgrade state");
        apply_entries_sync(&conn, identity, &backend.caps, entries)
            .expect("apply pre-upgrade state");
        let before: (Vec<u8>, Vec<u8>, i64, i64) = conn
            .query_row(
                "SELECT m.membership_json, a.log_id_json, machine.application_sequence, (SELECT COUNT(*) FROM leases) FROM consensus_membership AS m JOIN consensus_applied AS a ON a.singleton = m.singleton JOIN consensus_machine AS machine ON machine.singleton = m.singleton WHERE m.singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("capture pre-upgrade authority state");

        // These four tables do not exist on origin/main. Removing them from
        // an otherwise current fixture proves the production upgrade path
        // without admitting any unpublished intermediate schema shape.
        conn.execute_batch(
            "DROP TABLE consensus_candidate_bootstrap; DROP TABLE consensus_membership_terminal_history; DROP TABLE consensus_membership_history; DROP TABLE consensus_membership_scope;",
        )
        .expect("restore origin/main fixed-membership shape");
        let legacy_scope =
            read_membership_scope_sync(&conn, identity).expect("read origin/main fixed membership");
        assert_eq!(identity, legacy_scope.current_identity);
        assert_eq!(members, legacy_scope.current_members);
        assert!(legacy_scope.current_bindings.is_empty());

        initialize_schema(&conn, identity, &members).expect("upgrade fixed membership schema");
        let after: (Vec<u8>, Vec<u8>, i64, i64) = conn
            .query_row(
                "SELECT m.membership_json, a.log_id_json, machine.application_sequence, (SELECT COUNT(*) FROM leases) FROM consensus_membership AS m JOIN consensus_applied AS a ON a.singleton = m.singleton JOIN consensus_machine AS machine ON machine.singleton = m.singleton WHERE m.singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("capture upgraded authority state");
        assert_eq!(
            before, after,
            "upgrade must not rewrite consensus application state"
        );

        let upgraded_scope =
            read_membership_scope_sync(&conn, identity).expect("read upgraded membership scope");
        assert_eq!(identity, upgraded_scope.current_identity);
        assert_eq!(members, upgraded_scope.current_members);
        assert_eq!(
            test_member_bindings(&members),
            upgraded_scope.current_bindings
        );
        for table in [
            "consensus_membership_scope",
            "consensus_membership_history",
            "consensus_membership_terminal_history",
            "consensus_candidate_bootstrap",
        ] {
            assert!(table_exists(&conn, table).expect("read upgraded table shape"));
        }
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
            payload: EntryPayload::Normal(DurableSessionConsensusCommand::legacy(
                SessionConsensusCommand {
                    schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                    identity: identity(),
                    request_id: SessionConsensusRequestId::from_bytes(request_id),
                    logical_time: timestamp(
                        u8::try_from(index).expect("test index fits timestamp"),
                    ),
                    intent: SessionMutationIntent::AcquireLease {
                        key: key(),
                        owner: OwnerId::new(owner).expect("owner"),
                        ttl: Duration::from_secs(300),
                    },
                },
            )),
        }
    }

    fn sealed_payload_for_record(
        record: &crate::StoredSessionRecord,
        payload_len: usize,
    ) -> crate::EncryptedSessionPayload {
        let key_id = KeyId::new("consensus-cap-test-key").expect("key ID");
        let aad = EnvelopeAad::session(
            record.key.tenant.clone(),
            1,
            SessionAad::new(
                record.key.nf_kind.as_str(),
                "consensus-cap-test-keyed-session-digest",
                record.state_type.as_str(),
                record.generation.get(),
                record.fence.get(),
                "consensus-cap-test-backend",
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
        assert_eq!(payload_len, encoded.len());
        crate::EncryptedSessionPayload::try_envelope(encoded).expect("valid envelope")
    }

    fn sealed_record_for_key(
        record_key: SessionKey,
        payload_len: usize,
    ) -> crate::StoredSessionRecord {
        let mut record = crate::StoredSessionRecord {
            key: record_key,
            generation: crate::Generation::new(1),
            owner: OwnerId::new("consensus-cap-owner").expect("owner"),
            fence: crate::FenceToken::new(1),
            state_class: crate::StateClass::AuthoritativeSession,
            state_type: crate::StateType::from_static("consensus-cap-test"),
            expires_at: None,
            payload: crate::EncryptedSessionPayload::new([]),
        };
        record.payload = sealed_payload_for_record(&record, payload_len);
        record
    }

    fn persist_sealed_record_fixture(conn: &Connection, record: &crate::StoredSessionRecord) {
        ops::insert_or_replace_record_sync(conn, record).expect("persist sealed record fixture");
        ops::insert_or_replace_fence_sync(conn, &record.key, record.fence.get())
            .expect("persist sealed record fence");
        let next_fence = record
            .fence
            .get()
            .checked_add(1)
            .expect("fixture fence successor");
        conn.execute(
            "UPDATE lease_globals SET val = MAX(val, ?1) WHERE key = 'next_fence'",
            [i64::try_from(next_fence).expect("SQLite fixture fence")],
        )
        .expect("advance fixture fence allocator");
    }

    fn sealed_replication_cas(
        operation_key: SessionKey,
        record_key: SessionKey,
        payload_len: usize,
    ) -> ReplicationOp {
        ReplicationOp::CompareAndSet {
            key: operation_key,
            expected_generation: None,
            credential_id: 1,
            guard_expires_at: timestamp(1),
            new_record: sealed_record_for_key(record_key, payload_len),
        }
    }

    #[tokio::test]
    async fn sealed_consensus_state_enforces_the_consensus_payload_cap() {
        for (payload_len, accepted) in [(1_048_576, true), (1_048_577, false)] {
            let backend = SqliteSessionBackend::in_memory().expect("backend");
            let conn = backend.conn.lock().await;
            let record = sealed_record_for_key(key(), payload_len);
            persist_sealed_record_fixture(&conn, &record);

            let validation = validate_sealed_state_sync(&conn);
            if accepted {
                validation.expect("the exact consensus cap remains valid");
            } else {
                let error = validation.expect_err("one over the consensus cap must reject");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[tokio::test]
    async fn sealed_state_validation_rejects_malformed_legacy_lease_tables() {
        for (case, mutation) in [
            ("lease-key", "UPDATE leases SET tenant = 'INVALID'"),
            ("lease-active", "UPDATE leases SET active = 2"),
            ("lease-credential", "UPDATE leases SET credential_id = 0"),
            ("lease-owner", "UPDATE leases SET owner = ''"),
            (
                "lease-expiry",
                "UPDATE leases SET expires_at_unix_ms = expires_at_unix_ms + 1",
            ),
            (
                "lease-timestamp",
                "UPDATE leases SET guard_expires_at = 'not-a-timestamp'",
            ),
            ("fence-key", "UPDATE key_fences SET tenant = 'INVALID'"),
            ("fence-value", "UPDATE key_fences SET fence = 0"),
            ("missing-fence", "DELETE FROM key_fences"),
            (
                "advanced-fence",
                "UPDATE key_fences SET fence = 2; UPDATE lease_globals SET val = 3 WHERE key = 'next_fence'",
            ),
            (
                "stale-fence",
                "UPDATE leases SET fence = 2; UPDATE lease_globals SET val = 3 WHERE key = 'next_fence'",
            ),
            (
                "fence-allocator",
                "UPDATE lease_globals SET val = 1 WHERE key = 'next_fence'",
            ),
            (
                "credential-allocator",
                "UPDATE lease_globals SET val = 1 WHERE key = 'next_credential_id'",
            ),
            (
                "unknown-global",
                "INSERT INTO lease_globals (key, val) VALUES ('unexpected', 1)",
            ),
            (
                "missing-global",
                "DELETE FROM lease_globals WHERE key = 'next_fence'",
            ),
        ] {
            let backend = SqliteSessionBackend::in_memory().expect("backend");
            let conn = backend.conn.lock().await;
            lease::acquire_sync(
                &conn,
                &key(),
                OwnerId::new("legacy-lease-owner").expect("owner"),
                Duration::from_secs(60),
                timestamp(1),
            )
            .expect("valid lease fixture");
            conn.execute_batch(mutation).expect("mutate lease fixture");

            let error = validate_sealed_state_sync(&conn)
                .expect_err("malformed legacy lease state must reject");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "case {case}");
        }
    }

    #[tokio::test]
    async fn sealed_state_validation_accepts_released_legacy_lease() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let lease = lease::acquire_sync(
            &conn,
            &key(),
            OwnerId::new("released-legacy-owner").expect("owner"),
            Duration::from_secs(60),
            timestamp(1),
        )
        .expect("valid lease fixture");
        lease::release_sync(&conn, lease, timestamp(2)).expect("release lease fixture");

        validate_sealed_state_sync(&conn).expect("released legacy lease state remains valid");
    }

    #[tokio::test]
    async fn sealed_state_rejects_equal_fence_record_owner_mismatch_but_allows_stale_record() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let first = lease::acquire_sync(
            &conn,
            &key(),
            OwnerId::new("first-owner").expect("owner"),
            Duration::from_secs(60),
            timestamp(1),
        )
        .expect("first lease");

        let mut equal_fence = sealed_record_for_key(key(), 64 * 1024);
        equal_fence.owner = OwnerId::new("different-owner").expect("owner");
        equal_fence.fence = first.fence();
        persist_sealed_record_fixture(&conn, &equal_fence);
        assert_eq!(
            validate_sealed_state_sync(&conn)
                .expect_err("equal fence cannot belong to different owners")
                .kind(),
            io::ErrorKind::InvalidData
        );

        // Once ownership advances, the older record remains valid historical
        // state even though its owner differs from the active lease holder.
        let second = lease::acquire_sync(
            &conn,
            &key(),
            OwnerId::new("second-owner").expect("owner"),
            Duration::from_secs(60),
            Timestamp::from_str("2026-07-12T00:01:02Z").expect("successor lease timestamp"),
        )
        .expect("successor lease");
        assert!(equal_fence.fence < second.fence());
        validate_sealed_state_sync(&conn).expect("lower-fence historical record is valid");
    }

    #[tokio::test]
    async fn sealed_state_rejects_finite_expiry_without_machine_logical_time() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let mut record = sealed_record_for_key(key(), 64 * 1024);
        record.expires_at = Some(timestamp(30));
        record.payload = sealed_payload_for_record(&record, 64 * 1024);
        persist_sealed_record_fixture(&conn, &record);

        let error = validate_sealed_state_sync(&conn)
            .expect_err("finite record must have canonical machine time authority");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session consensus finite record expiry has no logical time authority"
        );
    }

    #[tokio::test]
    async fn live_consensus_get_revalidates_persisted_payload_authority() {
        let exact = SqliteSessionBackend::in_memory().expect("exact-cap backend");
        {
            let conn = exact.conn.lock().await;
            let record = sealed_record_for_key(key(), 1_048_576);
            persist_sealed_record_fixture(&conn, &record);
        }
        admit_consensus_reads_for_test(&exact);
        assert!(exact
            .consensus_get_at(&key(), timestamp(1))
            .await
            .expect("exact-cap consensus read")
            .is_some());

        let oversized = SqliteSessionBackend::in_memory().expect("oversized backend");
        {
            let conn = oversized.conn.lock().await;
            let record = sealed_record_for_key(key(), 1_048_577);
            persist_sealed_record_fixture(&conn, &record);
        }
        admit_consensus_reads_for_test(&oversized);
        assert_eq!(
            oversized
                .consensus_get_at(&key(), timestamp(1))
                .await
                .expect_err("live consensus read must reject one over its retained cap"),
            StoreError::PayloadTooLarge {
                actual: 1_048_577,
                max: 1_048_576,
            }
        );

        let unsealed = SqliteSessionBackend::in_memory().expect("unsealed backend");
        {
            let conn = unsealed.conn.lock().await;
            let mut record = sealed_record_for_key(key(), 64 * 1024);
            record.payload = crate::EncryptedSessionPayload::new(b"unsealed");
            persist_sealed_record_fixture(&conn, &record);
        }
        admit_consensus_reads_for_test(&unsealed);
        assert!(matches!(
            unsealed.consensus_get_at(&key(), timestamp(1)).await,
            Err(StoreError::Crypto(_))
        ));

        let mismatched = SqliteSessionBackend::in_memory().expect("AAD-mismatch backend");
        {
            let conn = mismatched.conn.lock().await;
            let mut record = sealed_record_for_key(key(), 64 * 1024);
            record.generation = crate::Generation::new(2);
            persist_sealed_record_fixture(&conn, &record);
        }
        admit_consensus_reads_for_test(&mismatched);
        assert!(matches!(
            mismatched.consensus_get_at(&key(), timestamp(1)).await,
            Err(StoreError::Crypto(_))
        ));
    }

    #[tokio::test]
    async fn committed_consumer_read_rejects_invalid_persisted_record() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        apply_entries_sync(&conn, identity(), &backend.caps, vec![membership_entry()])
            .expect("membership entry");
        let invalid = sealed_record_for_key(key(), 1_048_577);
        persist_sealed_record_fixture(&conn, &invalid);

        let applied = apply_entries_sync(
            &conn,
            identity(),
            &backend.caps,
            vec![topology_entry_at(
                1,
                0xD1,
                SessionMutationIntent::ReadConsumerRecord { key: key() },
            )],
        )
        .expect("invalid read is a deterministic rejection");
        assert!(matches!(
            applied.responses.as_slice(),
            [SessionConsensusResponse {
                result: Err(StoreError::PayloadTooLarge {
                    actual: 1_048_577,
                    max: 1_048_576,
                }),
                ..
            }]
        ));
    }

    #[test]
    fn replayed_consumer_outcome_rejects_invalid_serialized_record() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let request_id = SessionConsensusRequestId::from_bytes([0xD2; 16]);
        let mut response = SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::ConsumerRecord(Some(
                sealed_record_for_key(key(), 1_048_577),
            ))),
            sequence: 1,
            digest: Some(SessionConsensusEntryDigest::from_bytes([0xA2; 32])),
            logical_time: Some(timestamp(1)),
            raft_log_index: 1,
        };
        let command = DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id,
            logical_time: timestamp(1),
            intent: SessionMutationIntent::ReadConsumerRecord { key: key() },
        });
        response.digest = Some(
            command
                .calculate_applied_result_digest(
                    1,
                    SessionConsensusEntryDigest::GENESIS,
                    timestamp(1),
                    1,
                    &response.result,
                )
                .expect("response digest"),
        );
        let payload_digest = payload_digest(&command).expect("payload digest");
        let receipt = outcome_receipt_digest_input!(
            request_id,
            identity().configuration_epoch().get(),
            payload_digest,
            &command,
            0,
            SessionConsensusEntryDigest::GENESIS,
            None,
            OUTCOME_RECEIPT_CHAIN_GENESIS,
            1,
            &response,
        )
        .expect("receipt");
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                request_id.as_bytes().as_slice(),
                epoch_i64(identity()).expect("epoch"),
                payload_digest.as_slice(),
                encode_json(&command).expect("command encoding"),
                0_i64,
                SessionConsensusEntryDigest::GENESIS.as_bytes().as_slice(),
                Option::<String>::None,
                OUTCOME_RECEIPT_CHAIN_GENESIS.as_slice(),
                1_i64,
                encode_json(&response).expect("response encoding"),
                OUTCOME_RECEIPT_VERSION,
                receipt.as_slice(),
            ],
        )
        .expect("seed invalid replay outcome");

        let error = read_outcome_sync(&conn, identity(), request_id)
            .expect_err("invalid replayed consumer record must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "persisted session consensus outcome record is invalid"
        );
    }

    #[test]
    fn replayed_cas_conflict_rejects_invalid_serialized_record() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let request_id = SessionConsensusRequestId::from_bytes([0xD3; 16]);
        let mut response = SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::CompareAndSet(
                CompareAndSetResult::Conflict {
                    current: Some(sealed_record_for_key(key(), 1_048_577)),
                },
            )),
            sequence: 1,
            digest: Some(SessionConsensusEntryDigest::from_bytes([0xA3; 32])),
            logical_time: Some(timestamp(1)),
            raft_log_index: 1,
        };
        let new_record = sealed_record_for_key(key(), 64 * 1024);
        let lease = crate::LeaseGuard::new(
            new_record.key.clone(),
            new_record.owner.clone(),
            new_record.fence,
            timestamp(1),
            timestamp(2),
            1,
        );
        let command = DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id,
            logical_time: timestamp(1),
            intent: SessionMutationIntent::CompareAndSet(Box::new(crate::CompareAndSet {
                key: new_record.key.clone(),
                lease,
                expected_generation: None,
                new_record,
            })),
        });
        response.digest = Some(
            command
                .calculate_applied_result_digest(
                    1,
                    SessionConsensusEntryDigest::GENESIS,
                    timestamp(1),
                    1,
                    &response.result,
                )
                .expect("response digest"),
        );
        let payload_digest = payload_digest(&command).expect("payload digest");
        let receipt = outcome_receipt_digest_input!(
            request_id,
            identity().configuration_epoch().get(),
            payload_digest,
            &command,
            0,
            SessionConsensusEntryDigest::GENESIS,
            None,
            OUTCOME_RECEIPT_CHAIN_GENESIS,
            1,
            &response,
        )
        .expect("receipt");
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                request_id.as_bytes().as_slice(),
                epoch_i64(identity()).expect("epoch"),
                payload_digest.as_slice(),
                encode_json(&command).expect("command encoding"),
                0_i64,
                SessionConsensusEntryDigest::GENESIS.as_bytes().as_slice(),
                Option::<String>::None,
                OUTCOME_RECEIPT_CHAIN_GENESIS.as_slice(),
                1_i64,
                encode_json(&response).expect("response encoding"),
                OUTCOME_RECEIPT_VERSION,
                receipt.as_slice(),
            ],
        )
        .expect("seed invalid replay outcome");

        let error = read_outcome_sync(&conn, identity(), request_id)
            .expect_err("invalid replayed CAS conflict record must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "persisted session consensus outcome record is invalid"
        );
    }

    #[test]
    fn replayed_cas_outcome_rejects_valid_unit_response() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let request_id = SessionConsensusRequestId::from_bytes([0xD4; 16]);
        let new_record = sealed_record_for_key(key(), 64 * 1024);
        let lease = crate::LeaseGuard::new(
            new_record.key.clone(),
            new_record.owner.clone(),
            new_record.fence,
            timestamp(1),
            timestamp(2),
            1,
        );
        let command = DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id,
            logical_time: timestamp(1),
            intent: SessionMutationIntent::CompareAndSet(Box::new(crate::CompareAndSet {
                key: new_record.key.clone(),
                lease,
                expected_generation: None,
                new_record,
            })),
        });
        let mut response = SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::Unit),
            sequence: 1,
            digest: None,
            logical_time: Some(timestamp(1)),
            raft_log_index: 1,
        };
        response.digest = Some(
            command
                .calculate_applied_result_digest(
                    1,
                    SessionConsensusEntryDigest::GENESIS,
                    timestamp(1),
                    1,
                    &response.result,
                )
                .expect("response digest"),
        );
        let payload_digest = payload_digest(&command).expect("payload digest");
        let receipt = outcome_receipt_digest_input!(
            request_id,
            identity().configuration_epoch().get(),
            payload_digest,
            &command,
            0,
            SessionConsensusEntryDigest::GENESIS,
            None,
            OUTCOME_RECEIPT_CHAIN_GENESIS,
            1,
            &response,
        )
        .expect("receipt");
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                request_id.as_bytes().as_slice(),
                epoch_i64(identity()).expect("epoch"),
                payload_digest.as_slice(),
                encode_json(&command).expect("command encoding"),
                0_i64,
                SessionConsensusEntryDigest::GENESIS.as_bytes().as_slice(),
                Option::<String>::None,
                OUTCOME_RECEIPT_CHAIN_GENESIS.as_slice(),
                1_i64,
                encode_json(&response).expect("response encoding"),
                OUTCOME_RECEIPT_VERSION,
                receipt.as_slice(),
            ],
        )
        .expect("seed swizzled replay outcome");

        let error = read_outcome_sync(&conn, identity(), request_id)
            .expect_err("CAS receipt must reject a valid Unit response");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "persisted session consensus outcome does not match command"
        );
    }

    #[test]
    fn replayed_outcome_rejects_response_metadata_mutation() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let request_id = SessionConsensusRequestId::from_bytes([0xD5; 16]);
        let command = DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id,
            logical_time: timestamp(1),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        });
        let mut response = SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::Unit),
            sequence: 1,
            digest: None,
            logical_time: Some(timestamp(1)),
            raft_log_index: 1,
        };
        response.digest = Some(
            command
                .calculate_applied_result_digest(
                    1,
                    SessionConsensusEntryDigest::GENESIS,
                    timestamp(1),
                    1,
                    &response.result,
                )
                .expect("response digest"),
        );
        let payload_digest = payload_digest(&command).expect("payload digest");
        let receipt = outcome_receipt_digest_input!(
            request_id,
            identity().configuration_epoch().get(),
            payload_digest,
            &command,
            0,
            SessionConsensusEntryDigest::GENESIS,
            None,
            OUTCOME_RECEIPT_CHAIN_GENESIS,
            1,
            &response,
        )
        .expect("receipt");
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                request_id.as_bytes().as_slice(),
                epoch_i64(identity()).expect("epoch"),
                payload_digest.as_slice(),
                encode_json(&command).expect("command encoding"),
                0_i64,
                SessionConsensusEntryDigest::GENESIS.as_bytes().as_slice(),
                Option::<String>::None,
                OUTCOME_RECEIPT_CHAIN_GENESIS.as_slice(),
                1_i64,
                encode_json(&response).expect("response encoding"),
                OUTCOME_RECEIPT_VERSION,
                receipt.as_slice(),
            ],
        )
        .expect("seed replay outcome");

        response.raft_log_index = 2;
        conn.execute(
            "UPDATE consensus_request_outcomes SET response_json = ?1 WHERE request_id = ?2",
            params![
                encode_json(&response).expect("mutated response encoding"),
                request_id.as_bytes().as_slice(),
            ],
        )
        .expect("mutate replay response metadata");
        let error = read_outcome_sync(&conn, identity(), request_id)
            .expect_err("metadata mutation must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "persisted session consensus outcome metadata is invalid"
        );
    }

    #[test]
    fn empty_outcome_chain_requires_the_genesis_machine_head() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        conn.execute(
            "UPDATE consensus_machine SET last_digest = ?1 WHERE singleton = 1",
            [vec![0xA5_u8; 32]],
        )
        .expect("mutate empty-chain digest");
        let error = validate_all_outcomes_sync(&conn, identity())
            .expect_err("an empty chain cannot claim a non-genesis digest");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "persisted session consensus empty outcome chain head is invalid"
        );
        drop(conn);

        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        conn.execute(
            "UPDATE consensus_machine SET logical_time = ?1 WHERE singleton = 1",
            [ops::format_rfc3339_normalized(timestamp(1))],
        )
        .expect("mutate empty-chain logical time");
        let error = validate_all_outcomes_sync(&conn, identity())
            .expect_err("an empty chain cannot claim a logical time");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "persisted session consensus empty outcome chain head is invalid"
        );
    }

    #[test]
    fn committed_cutover_without_its_receipt_is_rejected_even_when_pristine() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        conn.execute(
            "UPDATE consensus_command_admission SET strict_activation_index = 1, cutover_committed = 1 WHERE singleton = 1",
            [],
        )
        .expect("forge receipt-free cutover authority");

        let error = validate_all_outcomes_sync(&conn, identity())
            .expect_err("receipt-free cutover authority must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "persisted session consensus admission cutover receipt is missing"
        );
    }

    #[test]
    fn operator_recovery_authority_rejects_ambiguous_zero_digests() {
        for (case, mutation) in [
            (
                "pristine-epoch-with-plan",
                "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = CAST(X'01' || zeroblob(31) AS BLOB) WHERE singleton = 1",
            ),
            (
                "recovered-epoch-without-plan",
                "UPDATE consensus_operator_recovery SET recovery_epoch = 1, last_plan_digest = zeroblob(32) WHERE singleton = 1",
            ),
            (
                "pending-workflow-without-plan",
                "UPDATE consensus_operator_recovery SET pending_epoch = 1, pending_plan_digest = zeroblob(32) WHERE singleton = 1",
            ),
        ] {
            let backend = SqliteSessionBackend::in_memory().expect("backend");
            let conn = backend.conn.blocking_lock();
            initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
            conn.execute_batch("PRAGMA ignore_check_constraints = ON")
                .expect("allow corrupt recovery fixture");
            conn.execute(mutation, [])
                .unwrap_or_else(|error| panic!("inject {case} recovery corruption: {error}"));

            let error = read_operator_recovery_sync(&conn, identity())
                .expect_err("ambiguous recovery authority must reject");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "case {case}");
            let error = validate_recovery_receipts_and_admission_sync(&conn, identity())
                .expect_err("persisted validation must reject ambiguous recovery authority");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "case {case}");
        }
    }

    #[test]
    fn operator_recovery_write_entrypoints_reject_zero_plan_digest_before_schema_writes() {
        let conn = Connection::open_in_memory().expect("connection");
        assert!(mark_operator_recovery_pending_sync(&conn, identity(), 1, [0; 32], 0, 0).is_err());
        assert!(finalize_operator_recovery_sync(&conn, identity(), 1, [0; 32], 0, 0).is_err());
        assert!(claim_legacy_checkpoint_sync(
            &conn,
            identity(),
            &expected_members(),
            [0x11; 32],
            1,
            [0; 32],
            0,
            0,
            0,
            0,
            None,
        )
        .is_err());
        assert!(
            !table_exists(&conn, "consensus_operator_recovery").expect("inspect schema"),
            "zero-digest entrypoints must not initialize recovery state"
        );
        assert!(
            !table_exists(&conn, "consensus_identity").expect("inspect schema"),
            "zero-digest claim must not install consensus ownership"
        );
    }

    #[test]
    fn raw_recovery_finalize_without_pending_authority_is_rejected_without_state_mutation() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let applied = apply_entries_sync(
            &conn,
            identity(),
            &backend.caps,
            vec![
                membership_entry(),
                acquire_entry(1, [0xA4; 16], "recovery-guard-owner"),
            ],
        )
        .expect("seed active recovery guard");
        assert!(matches!(
            applied.responses.as_slice(),
            [
                _,
                SessionConsensusResponse {
                    result: Ok(SessionMutationOutcome::Lease(_)),
                    ..
                }
            ]
        ));

        let recovery_before =
            read_operator_recovery_sync(&conn, identity()).expect("baseline recovery authority");
        let globals_before: Vec<(String, i64)> = conn
            .prepare("SELECT key, val FROM lease_globals ORDER BY key")
            .expect("prepare baseline allocators")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("scan baseline allocators")
            .collect::<Result<_, _>>()
            .expect("collect baseline allocators");
        let active_before: i64 = conn
            .query_row("SELECT COUNT(*) FROM leases WHERE active = 1", [], |row| {
                row.get(0)
            })
            .expect("baseline active leases");

        let forged = topology_entry_at(
            2,
            0xA5,
            SessionMutationIntent::FinalizeOperatorRecovery {
                recovery_epoch: 1,
                plan_digest: [0xA6; 32],
                fence_high_water: 100,
                credential_high_water: 100,
            },
        );
        let rejected = apply_entries_sync(&conn, identity(), &backend.caps, vec![forged])
            .expect("raw recovery command applies as a deterministic rejection");
        assert!(matches!(
            rejected.responses.as_slice(),
            [SessionConsensusResponse {
                result: Err(StoreError::InvalidKey(reason)),
                ..
            }] if reason == "operator_recovery_epoch_rejected"
        ));
        assert_eq!(
            read_operator_recovery_sync(&conn, identity()).expect("rejected recovery authority"),
            recovery_before
        );
        assert_eq!(
            conn.prepare("SELECT key, val FROM lease_globals ORDER BY key")
                .expect("prepare rejected allocators")
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .expect("scan rejected allocators")
                .collect::<Result<Vec<(String, i64)>, _>>()
                .expect("collect rejected allocators"),
            globals_before
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM leases WHERE active = 1", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("rejected active leases"),
            active_before
        );
    }

    #[test]
    fn operator_recovery_finalize_binds_the_pending_high_waters_exactly() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let digest = [0xC4; 32];
        mark_operator_recovery_pending_sync(&conn, identity(), 1, digest, 7, 9)
            .expect("stage exact recovery authority");
        let before = read_operator_recovery_sync(&conn, identity()).expect("pending authority");

        for (fence, credential) in [(6, 9), (8, 9), (7, 10)] {
            assert_eq!(
                finalize_operator_recovery_sync(&conn, identity(), 1, digest, fence, credential)
                    .expect("substituted high-water rejects"),
                OperatorRecoveryApply::Rejected
            );
            assert_eq!(
                read_operator_recovery_sync(&conn, identity()).expect("rejected authority"),
                before
            );
        }
        assert_eq!(
            finalize_operator_recovery_sync(&conn, identity(), 1, digest, 7, 9)
                .expect("exact high-water applies"),
            OperatorRecoveryApply::Applied
        );
        assert_eq!(
            finalize_operator_recovery_sync(&conn, identity(), 1, digest, 7, 9)
                .expect("exact finalized retry is idempotent"),
            OperatorRecoveryApply::Idempotent
        );
    }

    #[test]
    fn operator_recovery_high_water_boundary_is_rejected_before_log_admission() {
        let EntryPayload::Normal(command) = topology_entry_at(
            1,
            0xC5,
            SessionMutationIntent::FinalizeOperatorRecovery {
                recovery_epoch: 1,
                plan_digest: [0xC6; 32],
                fence_high_water: i64::MAX as u64,
                credential_high_water: 0,
            },
        )
        .payload
        else {
            unreachable!("test helper emits normal command");
        };
        assert!(validate_command_for_log_with_cap(&command, identity(), false).is_err());
    }

    #[test]
    fn coherent_receipt_rewrite_cannot_contradict_a_retained_command() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let request_id = SessionConsensusRequestId::from_bytes([0xD6; 16]);
        let original = DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id,
            logical_time: timestamp(1),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        });
        append_logs_sync(
            &conn,
            identity(),
            &[
                membership_entry(),
                Entry {
                    log_id: log_id(1),
                    payload: EntryPayload::Normal(original.clone()),
                },
            ],
        )
        .expect("retain original command");

        let mut forged = original.clone();
        forged.intent = SessionMutationIntent::BindConsumerRequest {
            request_commitment: [0x3C; 32],
        };
        let mut response = SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::Unit),
            sequence: 1,
            digest: None,
            logical_time: Some(timestamp(1)),
            raft_log_index: 1,
        };
        response.digest = Some(
            forged
                .calculate_applied_result_digest(
                    1,
                    SessionConsensusEntryDigest::GENESIS,
                    timestamp(1),
                    1,
                    &response.result,
                )
                .expect("forged result digest"),
        );
        let forged_payload_digest = payload_digest(&forged).expect("forged payload digest");
        let forged_receipt = outcome_receipt_digest_input!(
            request_id,
            identity().configuration_epoch().get(),
            forged_payload_digest,
            &forged,
            0,
            SessionConsensusEntryDigest::GENESIS,
            None,
            OUTCOME_RECEIPT_CHAIN_GENESIS,
            1,
            &response,
        )
        .expect("forged receipt digest");
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, command_json, predecessor_sequence, predecessor_digest, predecessor_logical_time, predecessor_receipt_digest, raft_log_index, response_json, receipt_version, receipt_digest) VALUES (?1, ?2, ?3, ?4, 0, ?5, NULL, ?6, 1, ?7, ?8, ?9)",
            params![
                request_id.as_bytes().as_slice(),
                epoch_i64(identity()).expect("epoch"),
                forged_payload_digest.as_slice(),
                encode_json(&forged).expect("forged command encoding"),
                SessionConsensusEntryDigest::GENESIS.as_bytes().as_slice(),
                OUTCOME_RECEIPT_CHAIN_GENESIS.as_slice(),
                encode_json(&response).expect("forged response encoding"),
                OUTCOME_RECEIPT_VERSION,
                forged_receipt.as_slice(),
            ],
        )
        .expect("seed internally coherent forged receipt");

        let error = read_outcome_sync(&conn, identity(), request_id)
            .expect_err("retained command must anchor receipt semantics");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "persisted session consensus outcome contradicts retained command"
        );
    }

    #[tokio::test]
    async fn historical_cas_conflict_preserves_the_admitted_outcome() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let applied = apply_entries_sync(
            &conn,
            identity(),
            &backend.caps,
            vec![
                membership_entry(),
                acquire_entry(1, [0xD4; 16], "consensus-cap-owner"),
            ],
        )
        .expect("membership and lease entries");
        let lease = match &applied.responses[1].result {
            Ok(SessionMutationOutcome::Lease(lease)) => lease.clone(),
            other => panic!("unexpected lease response: {other:?}"),
        };
        persist_sealed_record_fixture(&conn, &sealed_record_for_key(key(), 1_048_577));

        let applied = apply_entries_sync(
            &conn,
            identity(),
            &backend.caps,
            vec![with_legacy_admission_revision(capped_cas_entry(
                2,
                [0xD5; 16],
                lease,
                None,
                crate::Generation::new(2),
                64 * 1024,
            ))],
        )
        .expect("historical conflict remains deterministic");
        assert!(matches!(
            applied.responses.as_slice(),
            [SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::CompareAndSet(
                    CompareAndSetResult::Conflict {
                        current: Some(record),
                    },
                )),
                ..
            }] if record.payload.len() == 1_048_577
        ));
    }

    #[test]
    fn follower_log_admission_rejects_oversized_and_nested_authorized_records() {
        let lease = crate::LeaseGuard::new(
            key(),
            OwnerId::new("consensus-cap-owner").expect("owner"),
            crate::FenceToken::new(1),
            timestamp(1),
            timestamp(1),
            1,
        );
        let oversized = capped_cas_entry(
            1,
            [0xD3; 16],
            lease,
            None,
            crate::Generation::new(1),
            1_048_577,
        );
        let oversized_command = match oversized.payload {
            EntryPayload::Normal(command) => command,
            _ => panic!("oversized fixture is normal"),
        };
        let error = validate_command_for_log_with_cap(&oversized_command, identity(), true)
            .expect_err("one-over sealed record must not enter the log");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let nested = DurableSessionConsensusCommand::current(SessionConsensusCommand {
            intent: SessionMutationIntent::Authorized {
                origin: member(7),
                authority_identity: identity(),
                mutation: Box::new(SessionMutationIntent::Authorized {
                    origin: member(7),
                    authority_identity: identity(),
                    mutation: Box::new(oversized_command.intent.clone()),
                }),
            },
            ..(*oversized_command).clone()
        });
        let error = validate_command_for_log_with_cap(&nested, identity(), true)
            .expect_err("nested authorized intent must not enter the log");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session consensus authorized intent nesting is invalid"
        );

        let authorized_control = DurableSessionConsensusCommand::current(SessionConsensusCommand {
            request_id: SessionConsensusRequestId::from_bytes([0xD2; 16]),
            intent: SessionMutationIntent::Authorized {
                origin: member(7),
                authority_identity: identity(),
                mutation: Box::new(SessionMutationIntent::FinalizeOperatorRecovery {
                    recovery_epoch: 1,
                    plan_digest: [0xD1; 32],
                    fence_high_water: 1,
                    credential_high_water: 1,
                }),
            },
            ..(*oversized_command).clone()
        });
        let error = validate_command_for_log_with_cap(&authorized_control, identity(), true)
            .expect_err("authorized operator control must not enter the log");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session consensus authorized control intent is invalid"
        );
    }

    #[tokio::test]
    async fn follower_rejects_noncanonical_cutover_without_mutation_and_accepts_exact_retry() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        initialize_schema_with_storage_anchor_and_pending_and_bindings(
            &conn,
            None,
            identity(),
            &expected_members(),
            &test_member_bindings(&expected_members()),
            None,
            ConsensusAuthorityProfile::Dynamic,
            None,
        )
        .expect("production-shaped consensus schema");
        append_logs_sync(&conn, identity(), &[membership_entry()]).expect("membership log");
        apply_entries_sync(&conn, identity(), &backend.caps, vec![membership_entry()])
            .expect("membership apply");

        let marker = |index: u64, logical_time: Timestamp| -> Entry<SessionRaftTypeConfig> {
            Entry {
                log_id: log_id(index),
                payload: EntryPayload::Normal(DurableSessionConsensusCommand::current(
                    SessionConsensusCommand {
                    schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                    identity: identity(),
                    request_id: SessionConsensusRequestId::from_bytes(
                        crate::consensus::SESSION_CONSENSUS_COMMAND_ADMISSION_CUTOVER_REQUEST_ID,
                    ),
                    logical_time,
                    intent: SessionMutationIntent::AdvanceLogicalTime,
                },
                )),
            }
        };
        let canonical_time = crate::consensus::types::command_admission_cutover_logical_time();
        let EntryPayload::Normal(mut reserved_id) = marker(1, canonical_time).payload else {
            unreachable!("marker fixture is normal")
        };
        reserved_id.logical_time = timestamp(1);
        assert!(validate_command_for_log_with_cap(&reserved_id, identity(), true).is_err());
        reserved_id.logical_time = canonical_time;
        reserved_id.intent = SessionMutationIntent::Authorized {
            origin: node_id(),
            authority_identity: identity(),
            mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
        };
        assert!(validate_command_for_log_with_cap(&reserved_id, identity(), true).is_err());

        let baseline_machine = read_machine_sync(&conn, identity()).expect("baseline machine");
        let baseline_admission =
            read_command_admission_sync(&conn, identity()).expect("baseline admission");
        let baseline_log_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM consensus_log", [], |row| row.get(0))
            .expect("baseline log count");

        let noncanonical = marker(1, timestamp(1));
        assert!(append_logs_sync(&conn, identity(), &[noncanonical]).is_err());
        assert_eq!(
            read_machine_sync(&conn, identity()).expect("rejected machine"),
            baseline_machine
        );
        assert_eq!(
            read_command_admission_sync(&conn, identity()).expect("rejected admission"),
            baseline_admission
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| row
                .get::<_, i64>(0))
                .expect("rejected log count"),
            baseline_log_count
        );

        let canonical = marker(1, canonical_time);
        append_logs_sync(&conn, identity(), std::slice::from_ref(&canonical))
            .expect("canonical marker log");
        let first = apply_entries_sync(&conn, identity(), &backend.caps, vec![canonical])
            .expect("canonical marker apply");
        let retry = marker(2, canonical_time);
        append_logs_sync(&conn, identity(), std::slice::from_ref(&retry))
            .expect("canonical marker retry log");
        let repeated = apply_entries_sync(&conn, identity(), &backend.caps, vec![retry])
            .expect("canonical marker retry apply");
        assert_eq!(first.responses, repeated.responses);
        assert_eq!(
            read_command_admission_sync(&conn, identity())
                .expect("committed admission")
                .strict_activation_index,
            2
        );
    }

    #[tokio::test]
    async fn live_outcome_chain_swizzle_blocks_duplicate_projection_and_apply() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let members = expected_members();
        initialize_schema_with_storage_anchor_and_pending_and_bindings(
            &conn,
            None,
            identity(),
            &members,
            &test_member_bindings(&members),
            None,
            ConsensusAuthorityProfile::Dynamic,
            None,
        )
        .expect("production-shaped consensus schema");

        let membership = membership_entry();
        append_logs_sync(&conn, identity(), std::slice::from_ref(&membership))
            .expect("membership log");
        apply_entries_sync(&conn, identity(), &backend.caps, vec![membership])
            .expect("membership apply");

        let marker = Entry {
            log_id: log_id(1),
            payload: EntryPayload::Normal(DurableSessionConsensusCommand::current(
                SessionConsensusCommand {
                    schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                    identity: identity(),
                    request_id: SessionConsensusRequestId::from_bytes(
                        crate::consensus::SESSION_CONSENSUS_COMMAND_ADMISSION_CUTOVER_REQUEST_ID,
                    ),
                    logical_time: crate::consensus::types::command_admission_cutover_logical_time(),
                    intent: SessionMutationIntent::AdvanceLogicalTime,
                },
            )),
        };
        append_logs_sync(&conn, identity(), std::slice::from_ref(&marker))
            .expect("cutover marker log");
        apply_entries_sync(&conn, identity(), &backend.caps, vec![marker])
            .expect("cutover marker apply");

        let acquire =
            with_current_admission_revision(acquire_entry(2, [0xE1; 16], "outcome-chain-owner"));
        append_logs_sync(&conn, identity(), std::slice::from_ref(&acquire)).expect("lease log");
        let acquired = apply_entries_sync(&conn, identity(), &backend.caps, vec![acquire])
            .expect("lease apply");
        let lease = match acquired.responses.as_slice() {
            [SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::Lease(lease)),
                ..
            }] => lease.clone(),
            _ => panic!("lease fixture must return a lease"),
        };
        let predecessor = acquired.responses[0].clone();
        let predecessor_receipt = read_machine_sync(&conn, identity())
            .expect("lease receipt head")
            .2;

        let cas = with_current_admission_revision(capped_cas_entry(
            3,
            [0xE2; 16],
            lease,
            None,
            crate::Generation::new(1),
            64 * 1024,
        ));
        let EntryPayload::Normal(command) = &cas.payload else {
            panic!("CAS fixture is normal")
        };
        let command = command.clone();
        append_logs_sync(&conn, identity(), std::slice::from_ref(&cas)).expect("CAS log");
        let applied = apply_entries_sync(&conn, identity(), &backend.caps, vec![cas.clone()])
            .expect("CAS apply");
        let mut swizzled = match applied.responses.as_slice() {
            [response @ SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success)),
                ..
            }] => response.clone(),
            _ => panic!("CAS fixture must succeed"),
        };
        swizzled.result = Ok(SessionMutationOutcome::CompareAndSet(
            CompareAndSetResult::Conflict { current: None },
        ));
        let predecessor_digest = predecessor.digest.expect("lease response digest");
        let predecessor_time = predecessor.logical_time;
        swizzled.digest = Some(
            command
                .calculate_applied_result_digest(
                    swizzled.sequence,
                    predecessor_digest,
                    swizzled.logical_time.expect("CAS response logical time"),
                    swizzled.raft_log_index,
                    &swizzled.result,
                )
                .expect("swizzled result digest"),
        );
        let payload = payload_digest(&command).expect("CAS payload digest");
        let receipt = outcome_receipt_digest_input!(
            command.request_id,
            identity().configuration_epoch().get(),
            payload,
            &command,
            predecessor.sequence,
            predecessor_digest,
            predecessor_time,
            predecessor_receipt,
            swizzled.raft_log_index,
            &swizzled,
        )
        .expect("swizzled receipt digest");
        assert_eq!(
            1,
            conn.execute(
                "UPDATE consensus_request_outcomes SET response_json = ?1, receipt_digest = ?2 WHERE request_id = ?3",
                params![
                    encode_json(&swizzled).expect("encode swizzled response"),
                    receipt.as_slice(),
                    command.request_id.as_bytes().as_slice(),
                ],
            )
            .expect("rewrite only the CAS receipt"),
        );

        // A row-local replay lookup accepts the rewritten receipt: both
        // result and receipt digests were recomputed, and the retained CAS
        // command remains unchanged. Only the sealed chain head exposes it.
        assert_eq!(
            Some((payload, swizzled.clone())),
            read_outcome_sync(&conn, identity(), command.request_id)
                .expect("read locally valid rewritten receipt"),
        );
        let error = validate_all_outcomes_sync(&conn, identity())
            .expect_err("rewritten tail must disagree with the machine head");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let before = (
            conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("log count"),
            last_log_sync(&conn, identity()).expect("last log"),
            read_applied_sync(&conn, identity()).expect("applied pointer"),
            read_machine_sync(&conn, identity()).expect("machine state"),
            ops::get_sync(&conn, &key(), timestamp(4)).expect("CAS state"),
        );
        let mut duplicate = cas;
        duplicate.log_id = log_id(4);

        let error = append_logs_sync(&conn, identity(), std::slice::from_ref(&duplicate))
            .expect_err("follower projection must reject the broken receipt chain");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            before,
            (
                conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("unchanged log count"),
                last_log_sync(&conn, identity()).expect("unchanged last log"),
                read_applied_sync(&conn, identity()).expect("unchanged applied pointer"),
                read_machine_sync(&conn, identity()).expect("unchanged machine state"),
                ops::get_sync(&conn, &key(), timestamp(4)).expect("unchanged CAS state"),
            )
        );

        let error = apply_entries_sync(&conn, identity(), &backend.caps, vec![duplicate])
            .expect_err("duplicate application must reject the broken receipt chain");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            before,
            (
                conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("still unchanged log count"),
                last_log_sync(&conn, identity()).expect("still unchanged last log"),
                read_applied_sync(&conn, identity()).expect("still unchanged applied pointer"),
                read_machine_sync(&conn, identity()).expect("still unchanged machine state"),
                ops::get_sync(&conn, &key(), timestamp(4)).expect("still unchanged CAS state"),
            )
        );
    }

    #[test]
    fn follower_log_admission_rejects_current_and_legacy_cas_semantic_mismatches() {
        let lease = crate::LeaseGuard::new(
            key(),
            OwnerId::new("consensus-cap-owner").expect("owner"),
            crate::FenceToken::new(1),
            timestamp(1),
            timestamp(1),
            1,
        );
        let base = match capped_cas_entry(
            1,
            [0xD7; 16],
            lease,
            None,
            crate::Generation::new(1),
            64 * 1024,
        )
        .payload
        {
            EntryPayload::Normal(command) => command,
            _ => panic!("CAS fixture is normal"),
        };
        let mut alternate_key = key();
        alternate_key.stable_id = Bytes::from_static(b"other-state-machine-fault-session")
            .try_into()
            .expect("valid alternate stable ID");

        let mut key_mismatch = base.clone();
        let SessionMutationIntent::CompareAndSet(op) = &mut key_mismatch.intent else {
            panic!("CAS fixture intent changed")
        };
        op.key = alternate_key;

        let mut owner_mismatch = base.clone();
        let SessionMutationIntent::CompareAndSet(op) = &mut owner_mismatch.intent else {
            panic!("CAS fixture intent changed")
        };
        op.new_record.owner = OwnerId::new("other-consensus-cap-owner").expect("owner");

        let mut fence_mismatch = base;
        let SessionMutationIntent::CompareAndSet(op) = &mut fence_mismatch.intent else {
            panic!("CAS fixture intent changed")
        };
        op.new_record.fence = crate::FenceToken::new(2);

        for malformed in [key_mismatch, owner_mismatch, fence_mismatch] {
            for legacy in [false, true] {
                let command = if legacy {
                    DurableSessionConsensusCommand::legacy((*malformed).clone())
                } else {
                    DurableSessionConsensusCommand::current((*malformed).clone())
                };
                let error = validate_command_for_log_with_cap(&command, identity(), !legacy)
                    .expect_err("semantic mismatch must not enter a follower log");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    error.to_string(),
                    "session consensus mutation profile is invalid"
                );
            }
        }
    }

    #[tokio::test]
    async fn follower_log_admission_rejects_sqlite_unrepresentable_cas_before_append() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        initialize_schema(&conn, identity(), &expected_members()).expect("consensus schema");
        let lease = crate::LeaseGuard::new(
            key(),
            OwnerId::new("consensus-cap-owner").expect("owner"),
            crate::FenceToken::new(1),
            timestamp(1),
            timestamp(1),
            1,
        );
        let entry = with_legacy_admission_revision(capped_cas_entry(
            1,
            [0xDB; 16],
            lease,
            None,
            crate::Generation::new(u64::MAX),
            64 * 1024,
        ));
        append_logs_sync(&conn, identity(), &[membership_entry()])
            .expect("append initial follower membership entry");
        let baseline_log_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM consensus_log", [], |row| row.get(0))
            .expect("baseline log count");

        let error = append_logs_sync(&conn, identity(), &[entry])
            .expect_err("unrepresentable generation must not enter a follower log");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session consensus mutation profile is invalid"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| row
                .get::<_, i64>(0))
                .expect("rejected log count"),
            baseline_log_count
        );

        let desired_members = expected_members();
        let topology_entry = Entry {
            log_id: log_id(1),
            payload: EntryPayload::Normal(DurableSessionConsensusCommand::legacy(
                SessionConsensusCommand {
                    schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                    identity: identity(),
                    request_id: SessionConsensusRequestId::from_bytes([0xDC; 16]),
                    logical_time: timestamp(1),
                    intent: SessionMutationIntent::PrepareTopologyTransition {
                        transition_id: [0xDC; 16],
                        request_digest: [0xDD; 32],
                        desired_identity: identity_at(u64::MAX, 0xDE),
                        desired_bindings: test_member_bindings(&desired_members),
                        desired_members,
                    },
                },
            )),
        };
        let error = append_logs_sync(&conn, identity(), &[topology_entry])
            .expect_err("unrepresentable successor epoch must not enter a follower log");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| row
                .get::<_, i64>(0))
                .expect("topology rejection log count"),
            baseline_log_count
        );
    }

    #[test]
    fn follower_log_admission_rejects_current_and_legacy_out_of_profile_ttls() {
        let out_of_profile_ttl = Duration::from_secs(crate::ttl::MAX_SESSION_TTL.as_secs() + 1);
        let lease = crate::LeaseGuard::new(
            key(),
            OwnerId::new("consensus-cap-owner").expect("owner"),
            crate::FenceToken::new(1),
            timestamp(1),
            timestamp(1),
            1,
        );
        let intents = [
            SessionMutationIntent::AcquireLease {
                key: key(),
                owner: OwnerId::new("consensus-cap-owner").expect("owner"),
                ttl: out_of_profile_ttl,
            },
            SessionMutationIntent::RefreshTtl {
                lease: lease.clone(),
                ttl: out_of_profile_ttl,
            },
            SessionMutationIntent::RenewLease {
                lease,
                ttl: out_of_profile_ttl,
            },
        ];

        for intent in intents {
            for legacy in [false, true] {
                let command = if legacy {
                    DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
                        schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                        identity: identity(),
                        request_id: SessionConsensusRequestId::from_bytes([0xD8; 16]),
                        logical_time: timestamp(1),
                        intent: intent.clone(),
                    })
                } else {
                    DurableSessionConsensusCommand::current(SessionConsensusCommand {
                        schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                        identity: identity(),
                        request_id: SessionConsensusRequestId::from_bytes([0xD8; 16]),
                        logical_time: timestamp(1),
                        intent: intent.clone(),
                    })
                };
                let error = validate_command_for_log_with_cap(&command, identity(), !legacy)
                    .expect_err("out-of-profile TTL must not enter a follower log");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[test]
    fn follower_log_admission_rejects_current_and_legacy_forged_guards() {
        let forged = [
            SessionMutationIntent::DeleteFenced(crate::LeaseGuard::new(
                key(),
                OwnerId::new("consensus-cap-owner").expect("owner"),
                crate::FenceToken::new(0),
                timestamp(1),
                timestamp(1),
                1,
            )),
            SessionMutationIntent::RefreshTtl {
                lease: crate::LeaseGuard::new(
                    key(),
                    OwnerId::new("consensus-cap-owner").expect("owner"),
                    crate::FenceToken::new(1),
                    timestamp(2),
                    timestamp(1),
                    1,
                ),
                ttl: Duration::from_secs(1),
            },
            SessionMutationIntent::RenewLease {
                lease: crate::LeaseGuard::new(
                    key(),
                    OwnerId::new("consensus-cap-owner").expect("owner"),
                    crate::FenceToken::new(1),
                    timestamp(1),
                    timestamp(1),
                    0,
                ),
                ttl: Duration::from_secs(1),
            },
            SessionMutationIntent::DeleteFenced(crate::LeaseGuard::new(
                key(),
                OwnerId::new("consensus-cap-owner").expect("owner"),
                crate::FenceToken::new(u64::MAX),
                timestamp(1),
                timestamp(1),
                1,
            )),
            SessionMutationIntent::ReleaseLease(crate::LeaseGuard::new(
                key(),
                OwnerId::new("consensus-cap-owner").expect("owner"),
                crate::FenceToken::new(1),
                timestamp(1),
                timestamp(1),
                u64::MAX,
            )),
            SessionMutationIntent::ReleaseLease(crate::LeaseGuard::new(
                key(),
                OwnerId::new("consensus-cap-owner").expect("owner"),
                crate::FenceToken::new(1),
                timestamp(1),
                timestamp(1),
                0,
            )),
        ];

        for intent in forged {
            for legacy in [false, true] {
                let command = if legacy {
                    DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
                        schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                        identity: identity(),
                        request_id: SessionConsensusRequestId::from_bytes([0xD9; 16]),
                        logical_time: timestamp(1),
                        intent: intent.clone(),
                    })
                } else {
                    DurableSessionConsensusCommand::current(SessionConsensusCommand {
                        schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                        identity: identity(),
                        request_id: SessionConsensusRequestId::from_bytes([0xD9; 16]),
                        logical_time: timestamp(1),
                        intent: intent.clone(),
                    })
                };
                let error = validate_command_for_log_with_cap(&command, identity(), !legacy)
                    .expect_err("forged guard must not enter a follower log");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[test]
    fn legacy_follower_admission_tolerates_only_an_oversized_valid_record() {
        let lease = crate::LeaseGuard::new(
            key(),
            OwnerId::new("consensus-cap-owner").expect("owner"),
            crate::FenceToken::new(1),
            timestamp(1),
            timestamp(1),
            1,
        );
        let mut command = match capped_cas_entry(
            1,
            [0xDA; 16],
            lease,
            None,
            crate::Generation::new(1),
            1_048_577,
        )
        .payload
        {
            EntryPayload::Normal(command) => command,
            _ => panic!("CAS fixture is normal"),
        };
        command = DurableSessionConsensusCommand::legacy((*command).clone());
        validate_command_for_log_with_cap(&command, identity(), false)
            .expect("the historical exception accepts only the one-over valid payload");

        let SessionMutationIntent::CompareAndSet(op) = &mut command.intent else {
            panic!("CAS fixture intent changed")
        };
        let mut alternate_key = key();
        alternate_key.stable_id = Bytes::from_static(b"legacy-oversized-malformed-session")
            .try_into()
            .expect("valid alternate stable ID");
        op.key = alternate_key;
        // This fails only because follower admission invokes the shared
        // semantic validator before applying the legacy size exception.
        let error = validate_command_for_log_with_cap(&command, identity(), false)
            .expect_err("oversized and malformed legacy command must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session consensus mutation profile is invalid"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dynamic_snapshot_install_uses_pinned_source_after_path_replacement() {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let source_a =
            SqliteSessionBackend::open(directory.path().join("source-a.sqlite")).expect("source A");
        let source_b =
            SqliteSessionBackend::open(directory.path().join("source-b.sqlite")).expect("source B");
        let snapshot_a_path = directory.path().join("snapshot-a.sqlite");
        let snapshot_b_path = directory.path().join("snapshot-b.sqlite");
        let (meta, byte_length_a) = {
            let conn = source_a.conn.lock().await;
            initialize_schema(&conn, identity(), &expected_members()).expect("source A schema");
            let entries = vec![membership_entry(), acquire_entry(1, [0xD4; 16], "owner-a")];
            apply_entries_sync(&conn, identity(), &source_a.caps, entries).expect("source A state");
            let (last_log_id, last_membership) =
                build_snapshot_database_sync(&conn, identity(), &snapshot_a_path)
                    .expect("source A snapshot");
            let byte_length = std::fs::metadata(&snapshot_a_path)
                .expect("source A metadata")
                .len();
            (
                opc_consensus::engine::SnapshotMeta {
                    last_log_id,
                    last_membership,
                    snapshot_id: "pinned-dynamic-source".into(),
                },
                byte_length,
            )
        };
        {
            let conn = source_b.conn.lock().await;
            initialize_schema(&conn, identity(), &expected_members()).expect("source B schema");
            let entries = vec![membership_entry(), acquire_entry(1, [0xD5; 16], "owner-b")];
            apply_entries_sync(&conn, identity(), &source_b.caps, entries).expect("source B state");
            build_snapshot_database_sync(&conn, identity(), &snapshot_b_path)
                .expect("source B snapshot");
        }
        drop(source_a);
        drop(source_b);

        let pinned = crate::consensus::snapshot::PinnedSqliteFile::from_file(
            open_nofollow_read(&snapshot_a_path).expect("pin source A"),
            snapshot_a_path.clone(),
        )
        .expect("pinned source A");
        let displaced = directory.path().join("snapshot-a.displaced.sqlite");
        std::fs::rename(&snapshot_a_path, &displaced).expect("displace source A");
        std::fs::rename(&snapshot_b_path, &snapshot_a_path).expect("publish source B");

        let target = SqliteSessionBackend::in_memory().expect("target");
        let conn = target.conn.lock().await;
        initialize_schema(&conn, identity(), &expected_members()).expect("target schema");
        install_snapshot_database_from_pinned_with_authority_sync(
            &conn,
            identity(),
            ConsensusAuthorityProfile::Dynamic,
            None,
            None,
            None,
            pinned,
            None,
            &meta,
            "pinned-dynamic.opc",
            [0xD6; 32],
            byte_length_a,
        )
        .expect("pinned source A installs");
        let owner: String = conn
            .query_row("SELECT owner FROM leases", [], |row| row.get(0))
            .expect("installed lease");
        assert_eq!(owner, "owner-a");
    }

    #[tokio::test]
    async fn live_consensus_restore_scan_revalidates_persisted_payload_authority() {
        let exact = SqliteSessionBackend::in_memory().expect("exact-cap backend");
        {
            let conn = exact.conn.lock().await;
            let record = sealed_record_for_key(key(), 1_048_576);
            persist_sealed_record_fixture(&conn, &record);
        }
        admit_consensus_reads_for_test(&exact);
        let exact_page = exact
            .consensus_scan_restore_records_at(
                RestoreScanRequest::all(1),
                timestamp(1),
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect("exact-cap consensus restore page");
        assert_eq!(exact_page.records.len(), 1);

        let oversized = SqliteSessionBackend::in_memory().expect("oversized backend");
        {
            let conn = oversized.conn.lock().await;
            let record = sealed_record_for_key(key(), 1_048_577);
            persist_sealed_record_fixture(&conn, &record);
        }
        admit_consensus_reads_for_test(&oversized);
        assert_eq!(
            oversized
                .consensus_scan_restore_records_at(
                    RestoreScanRequest::all(1),
                    timestamp(1),
                    tokio::time::Instant::now() + Duration::from_secs(5),
                )
                .await
                .expect_err("consensus restore must reject one over its retained cap"),
            StoreError::PayloadTooLarge {
                actual: 1_048_577,
                max: 1_048_576,
            }
        );

        let invalid_aad = SqliteSessionBackend::in_memory().expect("AAD-mismatch backend");
        {
            let conn = invalid_aad.conn.lock().await;
            let mut record = sealed_record_for_key(key(), 64 * 1024);
            record.fence = crate::FenceToken::new(2);
            persist_sealed_record_fixture(&conn, &record);
        }
        admit_consensus_reads_for_test(&invalid_aad);
        assert!(matches!(
            invalid_aad
                .consensus_scan_restore_records_at(
                    RestoreScanRequest::all(1),
                    timestamp(1),
                    tokio::time::Instant::now() + Duration::from_secs(5),
                )
                .await,
            Err(StoreError::Crypto(_))
        ));
    }

    #[tokio::test]
    async fn snapshot_build_rejects_invalid_source_before_creating_an_artifact() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let members = expected_members();
        initialize_schema(&conn, identity, &members).expect("consensus schema");
        apply_entries_sync(
            &conn,
            identity,
            &backend.consensus_capabilities(),
            vec![membership_entry()],
        )
        .expect("apply membership");
        let oversized = sealed_record_for_key(key(), 1_048_577);
        persist_sealed_record_fixture(&conn, &oversized);
        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("must-not-exist.sqlite");

        let error = build_snapshot_database_sync(&conn, identity, &snapshot_path)
            .expect_err("invalid source must reject snapshot capture");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            !snapshot_path.exists(),
            "invalid source must not leave a snapshot artifact"
        );
    }

    #[test]
    fn snapshot_build_rejects_coherent_receipt_and_machine_head_rewrite_before_compaction() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        let identity = identity();
        initialize_schema(&conn, identity, &expected_members()).expect("consensus schema");
        let original = DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: SessionConsensusRequestId::from_bytes([0xB6; 16]),
            logical_time: timestamp(1),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        });
        let entries = vec![
            membership_entry(),
            Entry {
                log_id: log_id(1),
                payload: EntryPayload::Normal(original),
            },
        ];
        append_logs_sync(&conn, identity, &entries).expect("retain source commands");
        apply_entries_sync(&conn, identity, &backend.caps, entries).expect("apply source command");

        // Rewrite every mutable receipt/head field coherently, while keeping
        // the retained entry at index one as the independent authority.
        let forged = DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: SessionConsensusRequestId::from_bytes([0xB6; 16]),
            logical_time: timestamp(2),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        });
        let result: Result<SessionMutationOutcome, StoreError> = Ok(SessionMutationOutcome::Unit);
        let forged_digest = forged
            .calculate_applied_result_digest(
                1,
                SessionConsensusEntryDigest::GENESIS,
                timestamp(2),
                1,
                &result,
            )
            .expect("calculate forged response digest");
        let forged_response = SessionConsensusResponse {
            result,
            sequence: 1,
            digest: Some(forged_digest),
            logical_time: Some(timestamp(2)),
            raft_log_index: 1,
        };
        let forged_payload_digest = payload_digest(&forged).expect("calculate forged payload");
        let forged_receipt = outcome_receipt_digest_input!(
            forged.request_id,
            identity.configuration_epoch().get(),
            forged_payload_digest,
            &forged,
            0,
            SessionConsensusEntryDigest::GENESIS,
            None,
            OUTCOME_RECEIPT_CHAIN_GENESIS,
            1,
            &forged_response,
        )
        .expect("calculate forged receipt");
        conn.execute(
            "UPDATE consensus_request_outcomes SET payload_digest = ?1, command_json = ?2, response_json = ?3, receipt_digest = ?4 WHERE request_id = ?5",
            params![
                forged_payload_digest.as_slice(),
                encode_json(&forged).expect("encode forged command"),
                encode_json(&forged_response).expect("encode forged response"),
                forged_receipt.as_slice(),
                forged.request_id.as_bytes().as_slice(),
            ],
        )
        .expect("rewrite receipt row");
        conn.execute(
            "UPDATE consensus_machine SET last_digest = ?1, last_receipt_digest = ?2, logical_time = ?3 WHERE singleton = 1",
            params![
                forged_digest.as_bytes().as_slice(),
                forged_receipt.as_slice(),
                ops::format_rfc3339_normalized(timestamp(2)),
            ],
        )
        .expect("rewrite machine head");

        let error = validate_all_outcomes_sync(&conn, identity)
            .expect_err("retained log must reject the coherent forged chain");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("must-not-exist.sqlite");
        let error = build_snapshot_database_sync(&conn, identity, &snapshot_path)
            .expect_err("snapshot build must validate retained receipt authority first");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            !snapshot_path.exists(),
            "a rejected source must not reach snapshot construction or log compaction"
        );
    }

    #[tokio::test]
    async fn legacy_claim_rejects_a_record_above_the_consensus_cap() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let record = sealed_record_for_key(key(), 1_048_577);
        persist_sealed_record_fixture(&conn, &record);

        let error = claim_legacy_checkpoint_sync(
            &conn,
            identity(),
            &expected_members(),
            [0x31; 32],
            1,
            [0x31; 32],
            0,
            0,
            0,
            0,
            None,
        )
        .expect_err("legacy claim must not import an oversized consensus record");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!table_exists(&conn, "consensus_identity").expect("inspect ownership table"));
    }

    #[tokio::test]
    async fn legacy_claim_rejects_a_regressed_lease_allocator() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        lease::acquire_sync(
            &conn,
            &key(),
            OwnerId::new("legacy-claim-owner").expect("owner"),
            Duration::from_secs(60),
            timestamp(1),
        )
        .expect("valid lease fixture");
        conn.execute(
            "UPDATE lease_globals SET val = 1 WHERE key = 'next_fence'",
            [],
        )
        .expect("regress fence allocator");

        let error = claim_legacy_checkpoint_sync(
            &conn,
            identity(),
            &expected_members(),
            [0x35; 32],
            1,
            [0x35; 32],
            0,
            0,
            0,
            0,
            None,
        )
        .expect_err("legacy claim must reject a regressed lease allocator");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!table_exists(&conn, "consensus_identity").expect("inspect ownership table"));
    }

    #[test]
    fn legacy_claim_validation_and_ownership_fence_are_one_transaction() {
        let directory = tempfile::tempdir().expect("database directory");
        let database = directory.path().join("legacy-claim.sqlite");
        drop(SqliteSessionBackend::open(&database).expect("legacy backend"));
        let conn = Connection::open(&database).expect("claim connection");
        let concurrent_record = sealed_record_for_key(key(), 1_048_577);
        let concurrent_database = database.clone();
        install_legacy_claim_after_validation_hook(move || {
            let concurrent =
                Connection::open(&concurrent_database).expect("concurrent legacy writer");
            concurrent
                .busy_timeout(Duration::ZERO)
                .expect("disable concurrent writer wait");
            ops::insert_or_replace_record_sync(&concurrent, &concurrent_record)
                .expect_err("the claim transaction must already fence a concurrent legacy writer");
        });

        claim_legacy_checkpoint_sync(
            &conn,
            identity(),
            &expected_members(),
            [0x41; 32],
            1,
            [0x41; 32],
            0,
            0,
            0,
            0,
            None,
        )
        .expect("claim valid legacy checkpoint");

        let record_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM session_records", [], |row| row.get(0))
            .expect("count claimed records");
        assert_eq!(
            record_count, 0,
            "the fenced writer must not mutate the claim"
        );
        validate_sealed_state_sync(&conn).expect("claimed state remains valid");
    }

    #[test]
    fn sealed_replication_validation_enforces_the_consensus_payload_cap() {
        validate_sealed_replication_op(&sealed_replication_cas(key(), key(), 1_048_576))
            .expect("exact-cap key-bound replication remains valid");

        let oversized =
            validate_sealed_replication_op(&sealed_replication_cas(key(), key(), 1_048_577))
                .expect_err("persisted replication must reject one over the consensus cap");
        assert_eq!(oversized.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn sealed_replication_validation_binds_the_operation_and_record_keys() {
        let operation_key = key();
        let mut record_key = operation_key.clone();
        record_key.stable_id = Bytes::from_static(b"cross-key-persisted-record")
            .try_into()
            .expect("valid stable ID");
        let cross_key = validate_sealed_replication_op(&sealed_replication_cas(
            operation_key,
            record_key,
            64 * 1024,
        ))
        .expect_err("persisted replication must bind the operation and record keys");
        assert_eq!(cross_key.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn consensus_replication_read_revalidates_persisted_cas_authority() {
        let mut unsealed_record = sealed_record_for_key(key(), 64 * 1024);
        unsealed_record.payload = crate::EncryptedSessionPayload::new(b"unsealed".as_slice());
        for op in [
            sealed_replication_cas(key(), key(), 1_048_577),
            ReplicationOp::CompareAndSet {
                key: unsealed_record.key.clone(),
                expected_generation: None,
                credential_id: 1,
                guard_expires_at: timestamp(1),
                new_record: unsealed_record,
            },
            {
                let operation_key = key();
                let mut record_key = operation_key.clone();
                record_key.stable_id = Bytes::from_static(b"cross-key-consumer-record")
                    .try_into()
                    .expect("valid stable ID");
                sealed_replication_cas(operation_key, record_key, 64 * 1024)
            },
        ] {
            let backend = SqliteSessionBackend::in_memory().expect("backend");
            {
                let conn = backend.conn.lock().await;
                initialize_schema(&conn, identity(), &expected_members())
                    .expect("consensus schema");
                let entry = ReplicationEntry {
                    sequence: 1,
                    tx_id: "persisted-read"
                        .to_string()
                        .try_into()
                        .expect("transaction ID"),
                    op,
                    timestamp: timestamp(1),
                };
                conn.execute(
                    "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (1, ?1, ?2, ?3)",
                    params![
                        entry.tx_id.as_str(),
                        serde_json::to_string(&entry).expect("entry JSON"),
                        entry.timestamp.to_string(),
                    ],
                )
                .expect("inject persisted entry");
            }

            admit_consensus_reads_for_test(&backend);

            assert!(matches!(
                backend.consensus_get_replication_log(1, 1).await,
                Err(StoreError::BackendUnavailable(_))
            ));
        }
    }

    #[tokio::test]
    async fn fresh_consensus_claim_revalidates_complete_local_schema_under_its_lock() {
        for (case, mutation, retained_probe) in [
            (
                "empty extra table",
                "CREATE TABLE unreviewed_empty (value INTEGER NOT NULL);",
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'unreviewed_empty'",
            ),
            (
                "altered local DDL",
                "ALTER TABLE session_records ADD COLUMN unreviewed INTEGER;",
                "SELECT COUNT(*) FROM pragma_table_info('session_records') WHERE name = 'unreviewed'",
            ),
        ] {
            let directory = tempfile::tempdir().expect("database directory");
            let database = directory.path().join("session.sqlite");
            let backend = SqliteSessionBackend::open(&database).expect("fresh backend");
            let external = Connection::open(&database).expect("cooperating external connection");
            external
                .execute_batch(mutation)
                .unwrap_or_else(|error| panic!("apply {case} mutation: {error}"));
            drop(external);

            let members = expected_members();
            let error = match SqliteConsensusCore::initialize(
                &backend,
                directory.path().join("snapshots"),
                identity(),
                members.clone(),
                test_member_bindings(&members),
                ConsensusAuthorityProfile::Dynamic,
                None,
            )
            .await
            {
                Ok(_) => panic!("schema drift in the constructor-to-initializer gap must reject"),
                Err(error) => error,
            };
            assert_eq!(SessionConsensusStorageError::CorruptState, error, "{case}");

            let conn = backend.conn.lock().await;
            let identity_tables: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'consensus_identity'",
                    [],
                    |row| row.get(0),
                )
                .expect("inspect rejected consensus claim");
            assert_eq!(0, identity_tables, "{case} must not gain consensus authority");
            let retained: i64 = conn
                .query_row(retained_probe, [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("inspect retained {case} mutation: {error}"));
            assert_eq!(1, retained, "{case} must not be repaired or rewritten");
        }
    }

    #[tokio::test]
    async fn consensus_admission_releases_physical_writer_lock_after_wal_activation() {
        let directory = tempfile::tempdir().expect("database directory");
        let database = directory.path().join("session.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("fresh backend");
        let members = expected_members();
        let core = SqliteConsensusCore::initialize(
            &backend,
            directory.path().join("snapshots"),
            identity(),
            members.clone(),
            test_member_bindings(&members),
            ConsensusAuthorityProfile::Dynamic,
            None,
        )
        .await
        .expect("initialize consensus backend");

        let writer = Connection::open(&database).expect("open cooperating writer");
        writer
            .busy_timeout(Duration::ZERO)
            .expect("disable competing busy wait");
        writer
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
            .expect("cooperating writer enters after WAL activation");
        drop(core);
    }

    #[tokio::test]
    async fn consensus_admission_revokes_raw_watchers_without_breaking_consensus_watch() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let mut raw_watch = backend.watch(1).await.expect("standalone raw watch");
        let members = expected_members();
        let snapshot_dir = tempfile::tempdir().expect("snapshot directory");
        let _core = SqliteConsensusCore::initialize(
            &backend,
            snapshot_dir.path().join("snapshots"),
            identity(),
            members.clone(),
            test_member_bindings(&members),
            ConsensusAuthorityProfile::Dynamic,
            None,
        )
        .await
        .expect("initialize consensus backend");

        assert_eq!(
            backend.watchers.lock().await.len(),
            0,
            "consensus admission must drop every raw standalone watcher"
        );
        assert!(
            raw_watch.next().await.is_none(),
            "a revoked raw watcher must close before any consensus notification"
        );

        let consensus_watch = backend
            .consensus_watch(1)
            .await
            .expect("consensus watch remains available after raw revocation");
        assert_eq!(backend.watchers.lock().await.len(), 1);
        drop(consensus_watch);
    }

    #[tokio::test]
    async fn raw_watch_captured_before_consensus_admission_cannot_escape_registration() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let held_registration = Arc::clone(&backend.watch_registration_gate)
            .acquire_owned()
            .await
            .expect("hold registration gate");
        let watch_backend = backend.clone();
        let raw_watch = tokio::spawn(async move { watch_backend.watch(1).await });
        while !backend.watch_backlog_captured.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }

        let members = expected_members();
        let initialize_backend = backend.clone();
        let snapshot_dir = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = snapshot_dir.path().join("snapshots");
        let initialize = tokio::spawn(async move {
            SqliteConsensusCore::initialize(
                &initialize_backend,
                snapshot_path,
                identity(),
                members.clone(),
                test_member_bindings(&members),
                ConsensusAuthorityProfile::Dynamic,
                None,
            )
            .await
        });

        drop(held_registration);
        let raw_watch = raw_watch
            .await
            .expect("raw watch task must complete before admission finishes");
        let _core = initialize
            .await
            .expect("consensus initializer task")
            .expect("initialize consensus backend");

        assert_eq!(
            backend.watchers.lock().await.len(),
            0,
            "a captured raw watch must not survive the consensus fence"
        );
        match raw_watch {
            Ok(mut stream) => assert!(
                stream.next().await.is_none(),
                "a raw stream registered before the fence must be closed"
            ),
            Err(StoreError::CapabilityNotSupported(_)) => {}
            Err(error) => panic!("raw watch failed unexpectedly: {error}"),
        }
    }

    #[tokio::test]
    async fn consensus_reopen_rejects_persisted_state_above_its_retained_cap() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let members = expected_members();
        let bindings = test_member_bindings(&members);
        {
            let conn = backend.conn.lock().await;
            initialize_schema(&conn, identity(), &members).expect("consensus schema");
            let oversized = sealed_record_for_key(key(), 1_048_577);
            persist_sealed_record_fixture(&conn, &oversized);
        }
        let snapshots = tempfile::tempdir().expect("snapshot directory");

        let error = match SqliteConsensusCore::initialize(
            &backend,
            snapshots.path().join("snapshots"),
            identity(),
            members,
            bindings,
            ConsensusAuthorityProfile::Dynamic,
            None,
        )
        .await
        {
            Ok(_) => panic!("reopen must reject state above the retained consensus cap"),
            Err(error) => error,
        };
        assert_eq!(error, SessionConsensusStorageError::CorruptState);
    }

    #[tokio::test]
    async fn snapshot_install_rejects_an_oversized_record_without_target_mutation() {
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.lock().await;
        let identity = identity();
        let members = expected_members();
        initialize_schema(&source_conn, identity, &members).expect("source consensus schema");
        apply_entries_sync(
            &source_conn,
            identity,
            &source.consensus_capabilities(),
            vec![membership_entry()],
        )
        .expect("apply source membership");
        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("oversized.sqlite");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity, &snapshot_path)
                .expect("build source snapshot");
        drop(source_conn);

        let incoming = Connection::open(&snapshot_path).expect("open incoming snapshot");
        let oversized = sealed_record_for_key(key(), 1_048_577);
        persist_sealed_record_fixture(&incoming, &oversized);
        drop(incoming);

        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.lock().await;
        initialize_schema(&target_conn, identity, &members).expect("target consensus schema");
        let before_restore =
            ops::read_restore_scan_state_sync(&target_conn).expect("target restore state");
        let before_applied =
            read_applied_sync(&target_conn, identity).expect("target applied state");
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "oversized-record-rejected".to_string(),
        };

        let error = install_snapshot_database_sync(
            &target_conn,
            identity,
            &snapshot_path,
            &meta,
            "oversized.opc",
            [0x41; 32],
            std::fs::metadata(&snapshot_path)
                .expect("incoming metadata")
                .len(),
        )
        .expect_err("snapshot install must reject an oversized consensus record");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            before_restore,
            ops::read_restore_scan_state_sync(&target_conn).expect("unchanged restore state")
        );
        assert_eq!(
            before_applied,
            read_applied_sync(&target_conn, identity).expect("unchanged applied state")
        );
        let target_records: i64 = target_conn
            .query_row("SELECT COUNT(*) FROM session_records", [], |row| row.get(0))
            .expect("count target records");
        assert_eq!(target_records, 0);
    }

    #[test]
    fn snapshot_install_rejects_ambiguous_operator_recovery_digests() {
        for (case, mutation) in [
            (
                "pristine-epoch-with-plan",
                "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = CAST(X'01' || zeroblob(31) AS BLOB) WHERE singleton = 1",
            ),
            (
                "recovered-epoch-without-plan",
                "UPDATE consensus_operator_recovery SET recovery_epoch = 1, last_plan_digest = zeroblob(32) WHERE singleton = 1",
            ),
            (
                "pending-workflow-without-plan",
                "UPDATE consensus_operator_recovery SET pending_epoch = 1, pending_plan_digest = zeroblob(32) WHERE singleton = 1",
            ),
        ] {
            let source = SqliteSessionBackend::in_memory().expect("source backend");
            let source_conn = source.conn.blocking_lock();
            let identity = identity();
            let members = expected_members();
            initialize_schema(&source_conn, identity, &members).expect("source consensus schema");
            apply_entries_sync(
                &source_conn,
                identity,
                &source.consensus_capabilities(),
                vec![membership_entry()],
            )
            .expect("apply source membership");
            let directory = tempfile::tempdir().expect("snapshot directory");
            let snapshot_path = directory.path().join("ambiguous-recovery.sqlite");
            let (last_log_id, last_membership) =
                build_snapshot_database_sync(&source_conn, identity, &snapshot_path)
                    .expect("build source snapshot");
            drop(source_conn);

            let incoming = Connection::open(&snapshot_path).expect("open incoming snapshot");
            incoming
                .execute_batch("PRAGMA ignore_check_constraints = ON")
                .expect("allow corrupt recovery fixture");
            incoming
                .execute(mutation, [])
                .unwrap_or_else(|error| panic!("inject {case} recovery corruption: {error}"));
            drop(incoming);

            let target = SqliteSessionBackend::in_memory().expect("target backend");
            let target_conn = target.conn.blocking_lock();
            initialize_schema(&target_conn, identity, &members).expect("target consensus schema");
            let before =
                read_operator_recovery_sync(&target_conn, identity).expect("target recovery state");
            let meta = opc_consensus::engine::SnapshotMeta {
                last_log_id,
                last_membership,
                snapshot_id: format!("ambiguous-recovery-{case}"),
            };

            let error = install_snapshot_database_sync(
                &target_conn,
                identity,
                &snapshot_path,
                &meta,
                "ambiguous-recovery.opc",
                [0x41; 32],
                std::fs::metadata(&snapshot_path)
                    .expect("incoming metadata")
                    .len(),
            )
            .expect_err("ambiguous recovery state must reject snapshot installation");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "case {case}");
            assert_eq!(
                before,
                read_operator_recovery_sync(&target_conn, identity)
                    .expect("target recovery remains unchanged"),
                "case {case} must not alter target authority"
            );
        }
    }

    #[test]
    fn snapshot_install_rejects_required_name_view_and_detaches_before_same_connection_retry() {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let valid = directory.path().join("valid.sqlite");
        let malformed = directory.path().join("view.sqlite");
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.blocking_lock();
        let expected = expected_members();
        initialize_schema(&source_conn, identity(), &expected).expect("source schema");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity(), &valid).expect("build snapshot");
        drop(source_conn);
        std::fs::copy(&valid, &malformed).expect("copy malformed fixture");
        let malformed_conn = Connection::open(&malformed).expect("open malformed fixture");
        malformed_conn
            .execute_batch(
                "DROP TABLE leases; CREATE VIEW leases AS SELECT * FROM session_records;",
            )
            .expect("replace required table with same-column candidate view");
        drop(malformed_conn);

        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "view-rejection-retry".into(),
        };
        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.blocking_lock();
        initialize_schema(&target_conn, identity(), &expected).expect("target schema");
        let error = install_snapshot_database_sync(
            &target_conn,
            identity(),
            &malformed,
            &meta,
            "rejected-view.opc",
            [0xA1; 32],
            std::fs::metadata(&malformed)
                .expect("malformed metadata")
                .len(),
        )
        .expect_err("required-name view must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let attached: i64 = target_conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_database_list WHERE name = 'consensus_incoming'",
                [],
                |row| row.get(0),
            )
            .expect("inspect attachment cleanup");
        assert_eq!(0, attached);
        install_snapshot_database_sync(
            &target_conn,
            identity(),
            &valid,
            &meta,
            "accepted-after-view.opc",
            [0xA2; 32],
            std::fs::metadata(&valid).expect("valid metadata").len(),
        )
        .expect("same connection accepts a later valid snapshot");
    }

    #[test]
    fn snapshot_install_rejects_sql_like_wildcard_shaped_incoming_trigger() {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot = directory.path().join("trigger.sqlite");
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.blocking_lock();
        let expected = expected_members();
        initialize_schema(&source_conn, identity(), &expected).expect("source schema");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity(), &snapshot)
                .expect("build snapshot");
        drop(source_conn);
        let incoming = Connection::open(&snapshot).expect("open snapshot");
        incoming
            .execute_batch("CREATE TRIGGER sqlitex AFTER INSERT ON leases BEGIN SELECT 1; END;")
            .expect("add wildcard-shaped incoming trigger");
        drop(incoming);

        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.blocking_lock();
        initialize_schema(&target_conn, identity(), &expected).expect("target schema");
        let before = ops::read_restore_scan_state_sync(&target_conn).expect("target restore state");
        let error = install_snapshot_database_sync(
            &target_conn,
            identity(),
            &snapshot,
            &opc_consensus::engine::SnapshotMeta {
                last_log_id,
                last_membership,
                snapshot_id: "trigger-rejection".into(),
            },
            "rejected-trigger.opc",
            [0xA3; 32],
            std::fs::metadata(&snapshot)
                .expect("snapshot metadata")
                .len(),
        )
        .expect_err("wildcard-shaped incoming trigger must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            before,
            ops::read_restore_scan_state_sync(&target_conn).expect("target remains unchanged")
        );
        let attached: i64 = target_conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_database_list WHERE name = 'consensus_incoming'",
                [],
                |row| row.get(0),
            )
            .expect("inspect attachment cleanup");
        assert_eq!(0, attached);
    }

    #[test]
    fn snapshot_install_rejects_destination_trigger_before_commit() {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot = directory.path().join("destination-trigger.sqlite");
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.blocking_lock();
        let expected = expected_members();
        initialize_schema(&source_conn, identity(), &expected).expect("source schema");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity(), &snapshot)
                .expect("build snapshot");
        drop(source_conn);

        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.blocking_lock();
        initialize_schema(&target_conn, identity(), &expected).expect("target schema");
        target_conn
            .execute_batch(
                "CREATE TRIGGER destination_install_fault AFTER INSERT ON leases BEGIN SELECT 1; END;",
            )
            .expect("add destination trigger");
        let error = install_snapshot_database_sync(
            &target_conn,
            identity(),
            &snapshot,
            &opc_consensus::engine::SnapshotMeta {
                last_log_id,
                last_membership,
                snapshot_id: "destination-trigger-rejection".into(),
            },
            "destination-trigger.opc",
            [0xA4; 32],
            std::fs::metadata(&snapshot)
                .expect("snapshot metadata")
                .len(),
        )
        .expect_err("destination trigger must reject installation before commit");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let snapshots: i64 = target_conn
            .query_row("SELECT COUNT(*) FROM consensus_snapshot", [], |row| {
                row.get(0)
            })
            .expect("snapshot metadata count");
        assert_eq!(0, snapshots);
    }

    #[test]
    fn snapshot_install_rejects_altered_source_and_destination_table_ddl() {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let canonical = directory.path().join("canonical.sqlite");
        let altered = directory.path().join("altered.sqlite");
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.blocking_lock();
        let expected = expected_members();
        initialize_schema(&source_conn, identity(), &expected).expect("source schema");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity(), &canonical)
                .expect("build canonical snapshot");
        drop(source_conn);

        std::fs::copy(&canonical, &altered).expect("copy altered fixture");
        let altered_conn = Connection::open(&altered).expect("open altered fixture");
        altered_conn
            .execute_batch("ALTER TABLE leases ADD COLUMN untrusted_layout_marker INTEGER;")
            .expect("alter source table layout");
        drop(altered_conn);
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "altered-ddl-rejection".into(),
        };

        let source_target = SqliteSessionBackend::in_memory().expect("source target backend");
        let source_target_conn = source_target.conn.blocking_lock();
        initialize_schema(&source_target_conn, identity(), &expected)
            .expect("source target schema");
        let source_error = install_snapshot_database_sync(
            &source_target_conn,
            identity(),
            &altered,
            &meta,
            "altered-source.opc",
            [0xA5; 32],
            std::fs::metadata(&altered)
                .expect("altered source metadata")
                .len(),
        )
        .expect_err("same-name source table with altered DDL must reject");
        assert_eq!(io::ErrorKind::InvalidData, source_error.kind());

        let destination_target =
            SqliteSessionBackend::in_memory().expect("destination target backend");
        let destination_target_conn = destination_target.conn.blocking_lock();
        initialize_schema(&destination_target_conn, identity(), &expected)
            .expect("destination target schema");
        destination_target_conn
            .execute_batch("ALTER TABLE leases ADD COLUMN untrusted_layout_marker INTEGER;")
            .expect("alter destination table layout");
        let destination_error = install_snapshot_database_sync(
            &destination_target_conn,
            identity(),
            &canonical,
            &meta,
            "altered-destination.opc",
            [0xA6; 32],
            std::fs::metadata(&canonical)
                .expect("canonical source metadata")
                .len(),
        )
        .expect_err("same-name destination table with altered DDL must reject");
        assert_eq!(io::ErrorKind::InvalidData, destination_error.kind());
        let snapshots: i64 = destination_target_conn
            .query_row("SELECT COUNT(*) FROM consensus_snapshot", [], |row| {
                row.get(0)
            })
            .expect("read destination snapshot metadata");
        assert_eq!(0, snapshots, "destination mutation must roll back");
    }

    fn capped_cas_entry(
        index: u64,
        request_id: [u8; 16],
        lease: crate::LeaseGuard,
        expected_generation: Option<crate::Generation>,
        generation: crate::Generation,
        payload_len: usize,
    ) -> Entry<SessionRaftTypeConfig> {
        let key = key();
        let mut record = crate::StoredSessionRecord {
            key: key.clone(),
            generation,
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: crate::StateClass::AuthoritativeSession,
            state_type: crate::StateType::from_static("consensus-cap-test"),
            expires_at: None,
            payload: crate::EncryptedSessionPayload::new([]),
        };
        record.payload = sealed_payload_for_record(&record, payload_len);
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(DurableSessionConsensusCommand::current(
                SessionConsensusCommand {
                    schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                    identity: identity(),
                    request_id: SessionConsensusRequestId::from_bytes(request_id),
                    logical_time: timestamp(u8::try_from(index).expect("test index")),
                    intent: SessionMutationIntent::CompareAndSet(Box::new(crate::CompareAndSet {
                        key,
                        lease,
                        expected_generation,
                        new_record: record,
                    })),
                },
            )),
        }
    }

    #[tokio::test]
    async fn consensus_core_retains_the_capped_profile_and_rejects_live_reentry() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let snapshots = tempfile::tempdir().expect("snapshot directory");
        let members = expected_members();
        let bindings = test_member_bindings(&members);
        let advertised = backend.consensus_capabilities();
        let core = SqliteConsensusCore::initialize(
            &backend,
            snapshots.path().join("snapshots"),
            identity(),
            members.clone(),
            bindings.clone(),
            ConsensusAuthorityProfile::Dynamic,
            None,
        )
        .await
        .expect("initialize consensus core");
        assert_eq!(advertised, core.caps);
        assert_eq!(1_048_576, core.caps.max_value_bytes);

        let reentry_error = match SqliteConsensusCore::initialize(
            &backend,
            snapshots.path().join("snapshots"),
            identity(),
            members,
            bindings,
            ConsensusAuthorityProfile::Dynamic,
            None,
        )
        .await
        {
            Ok(_) => panic!("a live consensus backend cannot be initialized twice"),
            Err(error) => error,
        };
        assert_eq!(
            SessionConsensusStorageError::BackendUnavailable,
            reentry_error
        );

        let conn = core.conn.lock().await;
        let applied = apply_entries_sync(
            &conn,
            identity(),
            &core.caps,
            vec![
                membership_entry(),
                acquire_entry(1, [0xA1; 16], "consensus-cap-owner"),
            ],
        )
        .expect("apply membership and lease");
        let lease = match &applied.responses[1].result {
            Ok(SessionMutationOutcome::Lease(lease)) => lease.clone(),
            other => panic!("unexpected lease response: {other:?}"),
        };

        let exact = apply_entries_sync(
            &conn,
            identity(),
            &core.caps,
            vec![with_legacy_admission_revision(capped_cas_entry(
                2,
                [0xA2; 16],
                lease.clone(),
                None,
                crate::Generation::new(1),
                advertised.max_value_bytes,
            ))],
        )
        .expect("exact consensus cap applies");
        assert!(matches!(
            exact.responses.as_slice(),
            [SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::CompareAndSet(
                    CompareAndSetResult::Success
                )),
                ..
            }]
        ));
        let before_record: (i64, i64) = conn
            .query_row(
                "SELECT generation, length(payload) FROM session_records",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("exact-cap record");
        let (_, before_revision, _) =
            ops::read_restore_scan_state_sync(&conn).expect("restore revision");

        let rejected = apply_entries_sync(
            &conn,
            identity(),
            &core.caps,
            vec![with_legacy_admission_revision(capped_cas_entry(
                3,
                [0xA3; 16],
                lease,
                Some(crate::Generation::new(1)),
                crate::Generation::new(2),
                advertised.max_value_bytes + 1,
            ))],
        )
        .expect("oversized command returns a deterministic rejection");
        assert!(matches!(
            rejected.responses.as_slice(),
            [SessionConsensusResponse {
                result: Err(StoreError::PayloadTooLarge {
                    actual: 1_048_577,
                    max: 1_048_576,
                }),
                ..
            }]
        ));
        assert_eq!(
            before_record,
            conn.query_row(
                "SELECT generation, length(payload) FROM session_records",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("oversized command leaves record unchanged")
        );
        assert_eq!(
            before_revision,
            ops::read_restore_scan_state_sync(&conn)
                .expect("restore revision after rejection")
                .1
        );
    }

    fn authorized_acquire_entry(
        index: u64,
        request_id: [u8; 16],
        origin: SessionConsensusNodeId,
        authority_identity: SessionConsensusIdentity,
    ) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(DurableSessionConsensusCommand::legacy(
                SessionConsensusCommand {
                    schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                    identity: identity(),
                    request_id: SessionConsensusRequestId::from_bytes(request_id),
                    logical_time: timestamp(
                        u8::try_from(index).expect("test index fits timestamp"),
                    ),
                    intent: SessionMutationIntent::Authorized {
                        origin,
                        authority_identity,
                        mutation: Box::new(SessionMutationIntent::AcquireLease {
                            key: key(),
                            owner: OwnerId::new("authority-owner").expect("owner"),
                            ttl: Duration::from_secs(300),
                        }),
                    },
                },
            )),
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
        let command = DurableSessionConsensusCommand::current(SessionConsensusCommand {
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
        });

        let error = validate_command_for_log_with_cap(&command, identity(), true)
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
            MembershipScopeMutationError::TransitionNotQuiescent,
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                second_id,
                second_digest,
                final_identity,
                &final_three,
            )
            .expect_err("a finalizing transition must block its successor")
        );
        let finalize_first = topology_entry_at(
            5,
            0x8a,
            SessionMutationIntent::FinalizeTopologyTransition {
                transition_id: first_id,
                request_digest: first_digest,
            },
        );
        append_logs_sync(
            &conn,
            storage_identity,
            std::slice::from_ref(&finalize_first),
        )
        .expect("append first finalization");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![finalize_first])
            .expect("apply first finalization");
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
        assert_eq!(1, staged.terminal_history.len());
        let transition_floor = blank_entry(6);
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
            7,
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
        let joint = membership_entry_at(8, vec![five.clone(), final_three.clone()], five.clone());
        let uniform = membership_entry_at(9, vec![final_three.clone()], final_three.clone());
        append_logs_sync(&conn, storage_identity, &[joint.clone(), uniform.clone()])
            .expect("append second transition memberships");
        save_committed_sync(&conn, storage_identity, Some(uniform.log_id))
            .expect("commit second transition");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![joint, uniform])
            .expect("apply and auto-promote second transition");
        let finalize_second = topology_entry_at(
            10,
            0x8b,
            SessionMutationIntent::FinalizeTopologyTransition {
                transition_id: second_id,
                request_digest: second_digest,
            },
        );
        append_logs_sync(
            &conn,
            storage_identity,
            std::slice::from_ref(&finalize_second),
        )
        .expect("append second finalization");
        apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![finalize_second],
        )
        .expect("apply second finalization");

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
        assert_eq!(Some(7), evidence.learners_ready_log_index);
        assert_eq!(Some(8), evidence.joint_membership_log_index);
        assert_eq!(Some(9), evidence.uniform_membership_log_index);
        assert_eq!(Some(9), evidence.cutover_log_index);
        assert_eq!(Some(10), evidence.finalization_log_index);
        let first_retained = read_membership_transition_evidence_sync(
            &conn,
            storage_identity,
            first_id,
            first_digest,
        )
        .expect("read retained first transition")
        .expect("retained first transition evidence");
        assert_eq!(
            Some(TerminalMembershipOutcome::Promoted),
            first_retained.outcome
        );
        assert_eq!(Some(5), first_retained.finalization_log_index);

        let final_membership =
            read_membership_sync(&conn, storage_identity).expect("read final membership");
        let snapshot_meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: Some(log_id(10)),
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
        purge_logs_sync(&conn, storage_identity, &log_id(10)).expect("purge transition history");
        drop_compacted_membership_predecessor_sync(&conn, storage_identity)
            .expect("drop all compacted predecessor history");
        let compacted =
            read_membership_scope_sync(&conn, storage_identity).expect("compacted scope");
        assert!(compacted.predecessor.is_none());
        assert_eq!(2, compacted.history.len());
        assert!(read_current_snapshot_sync(&conn, storage_identity)
            .expect("retained snapshot")
            .is_some());

        assert_eq!(
            MembershipScopeMutationError::ConflictingTransition,
            read_membership_transition_evidence_sync(
                &conn,
                storage_identity,
                first_id,
                [0x31; 32],
            )
            .expect_err("retained transition ID with another digest must conflict")
        );
        let reused = topology_entry_at(
            11,
            0x89,
            SessionMutationIntent::PrepareTopologyTransition {
                transition_id: first_id,
                request_digest: [0x31; 32],
                desired_identity: identity_at(4, 0x54),
                desired_members: five.clone(),
                desired_bindings: test_member_bindings(&five),
            },
        );
        assert!(append_logs_sync(&conn, storage_identity, std::slice::from_ref(&reused)).is_err());
        let rejected = apply_entries_sync(&conn, storage_identity, &backend.caps, vec![reused])
            .expect("committed conflicting Prepare has a deterministic rejection");
        assert!(matches!(
            rejected.responses.as_slice(),
            [SessionConsensusResponse {
                result: Err(StoreError::InvalidKey(code)),
                ..
            }] if code == "topology_transition_rejected"
        ));
        assert!(read_membership_scope_sync(&conn, storage_identity)
            .expect("conflicting Prepare left scope intact")
            .pending
            .is_none());
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
        let abort = topology_entry_at(
            3,
            0x84,
            SessionMutationIntent::AbortTopologyTransition {
                transition_id,
                request_digest: transition_digest,
            },
        );
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&abort))
            .expect("append abort decision");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![abort])
            .expect("apply abort decision while learner remains reachable");
        assert_eq!(
            MembershipScopeMutation::Idempotent,
            abort_membership_scope_sync(
                &conn,
                storage_identity,
                transition_id,
                transition_digest,
                3,
            )
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
        let aborting_scope =
            read_membership_scope_sync(&conn, storage_identity).expect("aborting scope");
        assert!(aborting_scope.pending.is_none());
        let cleanup = aborting_scope
            .terminal
            .as_ref()
            .and_then(|terminal| terminal.abort_cleanup.as_ref())
            .expect("durable abort cleanup scope");
        assert_eq!(members(&[10]), cleanup.learners);
        assert_eq!(3, cleanup.decision_log_index);
        assert_eq!(None, cleanup.cleanup_log_index);
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
        assert_eq!(Some(3), evidence.abort_decision_log_index);
        assert_eq!(None, evidence.abort_cleanup_log_index);
        assert_eq!(
            MembershipScopeMutationError::TransitionNotQuiescent,
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                [0x43; MEMBERSHIP_TRANSITION_ID_BYTES],
                [0x44; 32],
                identity_at(2, 0x63),
                &desired,
            )
            .expect_err("an aborting transition must block its successor")
        );
        assert!(read_membership_scope_sync(&conn, storage_identity)
            .expect("rejected successor left abort scope intact")
            .pending
            .is_none());

        let restored = membership_entry_at(4, vec![current.clone()], current.clone());
        let current_term_abort = topology_entry_at(
            5,
            0x85,
            SessionMutationIntent::AbortTopologyTransition {
                transition_id,
                request_digest: transition_digest,
            },
        );
        append_logs_sync(
            &conn,
            storage_identity,
            &[restored.clone(), current_term_abort.clone()],
        )
        .expect("project cleanup followed by an exact current-term abort control");
        apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![restored, current_term_abort],
        )
        .expect("apply cleanup and exact current-term abort control");
        let evidence = read_membership_transition_evidence_sync(
            &conn,
            storage_identity,
            transition_id,
            transition_digest,
        )
        .expect("read cleanup evidence")
        .expect("cleanup evidence");
        assert_eq!(Some(3), evidence.abort_decision_log_index);
        assert_eq!(Some(4), evidence.abort_cleanup_log_index);
        let cleaned_scope =
            read_membership_scope_sync(&conn, storage_identity).expect("cleaned scope");
        validate_incoming_membership_scope(&aborting_scope, &cleaned_scope)
            .expect("cleanup snapshot progress is monotonic");
        assert!(validate_incoming_membership_scope(&cleaned_scope, &aborting_scope).is_err());
    }

    #[tokio::test]
    async fn retained_only_abort_accepts_exact_promoted_predecessor_history() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let storage_identity = identity();
        let initial_three = members(&[7, 8, 9]);
        let expanded_five = members(&[7, 8, 9, 10, 11]);
        let retained_three = members(&[7, 8, 9]);
        let expanded_identity = identity_at(2, 0x72);
        let retained_identity = identity_at(3, 0x73);
        let expand_id = [0x71; MEMBERSHIP_TRANSITION_ID_BYTES];
        let expand_digest = [0x72; 32];
        let remove_id = [0x73; MEMBERSHIP_TRANSITION_ID_BYTES];
        let remove_digest = [0x74; 32];

        initialize_schema(&conn, storage_identity, &initial_three).expect("initialize scope");
        let initial = membership_entry_at(0, vec![initial_three.clone()], initial_three.clone());
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&initial))
            .expect("append initial membership");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![initial])
            .expect("apply initial membership");

        stage_membership_scope_sync(
            &conn,
            storage_identity,
            expand_id,
            expand_digest,
            expanded_identity,
            &expanded_five,
        )
        .expect("stage expansion");
        let learners = membership_entry_at(1, vec![initial_three.clone()], expanded_five.clone());
        let ready = topology_entry_at(
            2,
            0xb1,
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id: expand_id,
                request_digest: expand_digest,
            },
        );
        append_logs_sync(&conn, storage_identity, &[learners.clone(), ready.clone()])
            .expect("append expansion learners and readiness");
        apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![learners, ready],
        )
        .expect("apply expansion learners and readiness");
        fence_application_authority_sync(&conn, storage_identity, expand_id, expand_digest)
            .expect("fence expansion authority");
        let joint = membership_entry_at(
            3,
            vec![initial_three.clone(), expanded_five.clone()],
            expanded_five.clone(),
        );
        let uniform = membership_entry_at(4, vec![expanded_five.clone()], expanded_five.clone());
        append_logs_sync(&conn, storage_identity, &[joint.clone(), uniform.clone()])
            .expect("append expansion membership");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![joint, uniform])
            .expect("apply expansion membership");
        let finalize = topology_entry_at(
            5,
            0xb2,
            SessionMutationIntent::FinalizeTopologyTransition {
                transition_id: expand_id,
                request_digest: expand_digest,
            },
        );
        append_logs_sync(&conn, storage_identity, std::slice::from_ref(&finalize))
            .expect("append expansion finalization");
        apply_entries_sync(&conn, storage_identity, &backend.caps, vec![finalize])
            .expect("apply expansion finalization");

        stage_membership_scope_sync(
            &conn,
            storage_identity,
            remove_id,
            remove_digest,
            retained_identity,
            &retained_three,
        )
        .expect("stage retained-only removal");
        let prepare = topology_entry_at(
            6,
            0xb3,
            SessionMutationIntent::PrepareTopologyTransition {
                transition_id: remove_id,
                request_digest: remove_digest,
                desired_identity: retained_identity,
                desired_members: retained_three.clone(),
                desired_bindings: test_member_bindings(&retained_three),
            },
        );
        let ready = topology_entry_at(
            7,
            0xb4,
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id: remove_id,
                request_digest: remove_digest,
            },
        );
        let abort = topology_entry_at(
            8,
            0xb5,
            SessionMutationIntent::AbortTopologyTransition {
                transition_id: remove_id,
                request_digest: remove_digest,
            },
        );
        let cleanup = topology_entry_at(
            9,
            0xb6,
            SessionMutationIntent::AbortTopologyTransition {
                transition_id: remove_id,
                request_digest: remove_digest,
            },
        );
        append_logs_sync(
            &conn,
            storage_identity,
            &[
                prepare.clone(),
                ready.clone(),
                abort.clone(),
                cleanup.clone(),
            ],
        )
        .expect("append retained-only abort controls");
        apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![prepare, ready, abort, cleanup],
        )
        .expect("apply retained-only abort without a membership entry");

        let scope = read_membership_scope_sync(&conn, storage_identity)
            .expect("exact retained promoted history validates the aborted successor");
        assert_eq!(expanded_identity, scope.current_identity);
        assert_eq!(expanded_five, scope.current_members);
        assert_eq!(1, scope.terminal_history.len());
        assert_eq!(expand_id, scope.terminal_history[0].transition_id);
        let terminal = scope.terminal.expect("retained-only abort terminal");
        let abort_cleanup = terminal.abort_cleanup.expect("retained-only cleanup proof");
        assert!(abort_cleanup.learners.is_empty());
        assert_eq!(8, abort_cleanup.decision_log_index);
        assert_eq!(Some(9), abort_cleanup.cleanup_log_index);
        assert_eq!(
            MembershipScopeMutation::Idempotent,
            abort_membership_scope_sync(&conn, storage_identity, remove_id, remove_digest, 9,)
                .expect("exact retained-only abort retry")
        );

        conn.execute(
            "UPDATE consensus_membership_terminal_history SET expected_member_count = 4 WHERE transition_id = ?1",
            params![expand_id.as_slice()],
        )
        .expect("corrupt retained promoted member count");
        assert!(
            read_membership_scope_sync(&conn, storage_identity).is_err(),
            "mismatched retained terminal evidence must not authorize the predecessor"
        );
    }

    #[tokio::test]
    async fn sequential_aborts_retain_exact_terminal_evidence_across_restart() {
        let directory = tempfile::tempdir().expect("directory");
        let database = directory.path().join("terminal-history.sqlite");
        let snapshot = directory.path().join("terminal-history-snapshot.sqlite");
        let regressed_snapshot = directory.path().join("terminal-history-regressed.sqlite");
        let storage_identity = identity();
        let current = members(&[7, 8, 9]);
        let first_desired = members(&[7, 8, 9, 10, 11]);
        let second_desired = members(&[7, 8, 9, 12, 13]);
        let first_id = [0xa1; MEMBERSHIP_TRANSITION_ID_BYTES];
        let first_digest = [0xb1; 32];
        let second_id = [0xa2; MEMBERSHIP_TRANSITION_ID_BYTES];
        let second_digest = [0xb2; 32];
        let first_identity = identity_at(2, 0xa1);
        let second_identity = identity_at(2, 0xa2);

        let backend = SqliteSessionBackend::open(&database).expect("backend");
        let (snapshot_last_log, snapshot_membership) = {
            let conn = backend.conn.lock().await;
            initialize_schema(&conn, storage_identity, &current).expect("initialize scope");
            let initial = membership_entry_at(0, vec![current.clone()], current.clone());
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&initial))
                .expect("append initial membership");
            apply_entries_sync(&conn, storage_identity, &backend.caps, vec![initial])
                .expect("apply initial membership");

            stage_membership_scope_sync(
                &conn,
                storage_identity,
                first_id,
                first_digest,
                first_identity,
                &first_desired,
            )
            .expect("stage first abort");
            let first_learners =
                membership_entry_at(1, vec![current.clone()], first_desired.clone());
            let first_abort = topology_entry_at(
                2,
                0xa3,
                SessionMutationIntent::AbortTopologyTransition {
                    transition_id: first_id,
                    request_digest: first_digest,
                },
            );
            let first_cleanup = membership_entry_at(3, vec![current.clone()], current.clone());
            append_logs_sync(
                &conn,
                storage_identity,
                &[
                    first_learners.clone(),
                    first_abort.clone(),
                    first_cleanup.clone(),
                ],
            )
            .expect("append first abort");
            apply_entries_sync(
                &conn,
                storage_identity,
                &backend.caps,
                vec![first_learners, first_abort, first_cleanup],
            )
            .expect("apply first abort");

            stage_membership_scope_sync(
                &conn,
                storage_identity,
                second_id,
                second_digest,
                second_identity,
                &second_desired,
            )
            .expect("stage second abort after exact first cleanup");
            let staged = read_membership_scope_sync(&conn, storage_identity)
                .expect("read staged second abort");
            assert_eq!(1, staged.terminal_history.len());
            assert_eq!(first_id, staged.terminal_history[0].transition_id);

            let second_learners =
                membership_entry_at(4, vec![current.clone()], second_desired.clone());
            let second_abort = topology_entry_at(
                5,
                0xa4,
                SessionMutationIntent::AbortTopologyTransition {
                    transition_id: second_id,
                    request_digest: second_digest,
                },
            );
            let second_cleanup = membership_entry_at(6, vec![current.clone()], current.clone());
            append_logs_sync(
                &conn,
                storage_identity,
                &[
                    second_learners.clone(),
                    second_abort.clone(),
                    second_cleanup.clone(),
                ],
            )
            .expect("append second abort");
            apply_entries_sync(
                &conn,
                storage_identity,
                &backend.caps,
                vec![second_learners, second_abort, second_cleanup],
            )
            .expect("apply second abort");
            build_snapshot_database_sync(&conn, storage_identity, &snapshot)
                .expect("build terminal-history snapshot")
        };
        drop(backend);

        let reopened = SqliteSessionBackend::open(&database).expect("reopen backend");
        let conn = reopened.conn.lock().await;
        initialize_schema(&conn, storage_identity, &current).expect("validate reopened scope");
        let first_evidence = read_membership_transition_evidence_sync(
            &conn,
            storage_identity,
            first_id,
            first_digest,
        )
        .expect("read retained first abort")
        .expect("retained first abort evidence");
        assert_eq!(
            Some(TerminalMembershipOutcome::Aborted),
            first_evidence.outcome
        );
        assert_eq!(Some(2), first_evidence.abort_decision_log_index);
        assert_eq!(Some(3), first_evidence.abort_cleanup_log_index);
        assert_eq!(
            MembershipScopeMutation::Idempotent,
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                first_id,
                first_digest,
                first_identity,
                &first_desired,
            )
            .expect("exact retained abort retry is idempotent")
        );
        assert_eq!(
            MembershipScopeMutationError::ConflictingTransition,
            read_membership_transition_evidence_sync(
                &conn,
                storage_identity,
                first_id,
                [0xc1; 32],
            )
            .expect_err("retained abort ID with another digest must conflict")
        );
        let scope = read_membership_scope_sync(&conn, storage_identity).expect("reopened scope");
        assert!(scope.pending.is_none());
        assert_eq!(1, scope.terminal_history.len());
        assert_eq!(
            second_id,
            scope
                .terminal
                .expect("current second terminal")
                .transition_id
        );

        let snapshot_meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: snapshot_last_log,
            last_membership: snapshot_membership,
            snapshot_id: "terminal-history".into(),
        };
        let snapshot_bytes = std::fs::metadata(&snapshot)
            .expect("snapshot metadata")
            .len();
        let target = SqliteSessionBackend::in_memory().expect("snapshot target");
        let target_conn = target.conn.lock().await;
        initialize_schema(&target_conn, storage_identity, &current)
            .expect("initialize snapshot target");
        install_snapshot_database_sync(
            &target_conn,
            storage_identity,
            &snapshot,
            &snapshot_meta,
            "terminal-history.opc",
            [0xd1; 32],
            snapshot_bytes,
        )
        .expect("install terminal-history snapshot");
        let installed = read_membership_transition_evidence_sync(
            &target_conn,
            storage_identity,
            first_id,
            first_digest,
        )
        .expect("read installed terminal history")
        .expect("installed terminal evidence");
        assert_eq!(Some(TerminalMembershipOutcome::Aborted), installed.outcome);
        assert_eq!(Some(3), installed.abort_cleanup_log_index);

        std::fs::copy(&snapshot, &regressed_snapshot).expect("copy regressed snapshot fixture");
        let regressed = Connection::open(&regressed_snapshot).expect("open regressed snapshot");
        regressed
            .execute("DELETE FROM consensus_membership_terminal_history", [])
            .expect("remove terminal history from regressed snapshot");
        drop(regressed);
        let regressed_bytes = std::fs::metadata(&regressed_snapshot)
            .expect("regressed snapshot metadata")
            .len();
        let error = install_snapshot_database_sync(
            &target_conn,
            storage_identity,
            &regressed_snapshot,
            &snapshot_meta,
            "terminal-history-regressed.opc",
            [0xd2; 32],
            regressed_bytes,
        )
        .expect_err("snapshot install must not discard retained terminal outcomes");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
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
            abort_membership_scope_sync(
                &conn,
                storage_identity,
                transition_id,
                transition_digest,
                5,
            )
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
    async fn pristine_standalone_candidate_probe_is_narrow_and_fail_closed() {
        let directory = tempfile::tempdir().expect("directory");
        let storage_identity = identity();
        let transition_id = [0x43; MEMBERSHIP_TRANSITION_ID_BYTES];
        let transition_digest = [0x44; 32];

        let pristine = SqliteSessionBackend::open(directory.path().join("pristine.sqlite"))
            .expect("open pristine candidate");
        assert_eq!(
            Ok(false),
            pristine
                .provisional_consensus_candidate_is_cancelled(
                    storage_identity,
                    member(10),
                    transition_id,
                    transition_digest,
                )
                .await
        );
        {
            let conn = pristine.conn.lock().await;
            conn.execute(
                "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (1, 'occupied', '{}', '1970-01-01T00:00:00Z')",
                [],
            )
            .expect("add standalone authority");
        }
        assert_eq!(
            Err(MembershipScopeMutationError::CorruptState),
            pristine
                .provisional_consensus_candidate_is_cancelled(
                    storage_identity,
                    member(10),
                    transition_id,
                    transition_digest,
                )
                .await
        );

        let partial = SqliteSessionBackend::open(directory.path().join("partial.sqlite"))
            .expect("open partial candidate");
        {
            let conn = partial.conn.lock().await;
            conn.execute_batch("CREATE TABLE consensus_partial (value INTEGER NOT NULL)")
                .expect("add partial consensus footprint");
        }
        assert_eq!(
            Err(MembershipScopeMutationError::CorruptState),
            partial
                .provisional_consensus_candidate_is_cancelled(
                    storage_identity,
                    member(10),
                    transition_id,
                    transition_digest,
                )
                .await
        );
    }

    #[tokio::test]
    async fn aborted_candidate_reuse_requires_exact_durable_abort_proof() {
        let directory = tempfile::tempdir().expect("directory");
        let database = directory.path().join("aborted-candidate.sqlite");
        let storage_identity = identity();
        let current = members(&[7, 8, 9]);
        let desired = members(&[7, 8, 9, 10, 11]);
        let desired_bindings = test_member_bindings(&desired);
        let aborted_identity = identity_at(2, 0x65);
        let aborted_id = [0x45; MEMBERSHIP_TRANSITION_ID_BYTES];
        let aborted_digest = [0x46; 32];

        let provisional = SqliteSessionBackend::in_memory().expect("provisional backend");
        {
            let conn = provisional.conn.lock().await;
            initialize_schema_with_pending(
                &conn,
                storage_identity,
                &current,
                Some(PendingMembershipBootstrap {
                    local_candidate_node_id: Some(member(10)),
                    transition_id: aborted_id,
                    transition_digest: aborted_digest,
                    desired_identity: aborted_identity,
                    desired_members: &desired,
                    desired_bindings: &desired_bindings,
                }),
            )
            .expect("open provisional candidate");
            assert_eq!(
                MembershipScopeMutation::Applied,
                cancel_provisional_candidate_membership_scope_sync(
                    &conn,
                    storage_identity,
                    member(10),
                    aborted_id,
                    aborted_digest,
                )
                .expect("cancel never-admitted candidate")
            );
            assert_eq!(
                MembershipScopeMutation::Idempotent,
                cancel_provisional_candidate_membership_scope_sync(
                    &conn,
                    storage_identity,
                    member(10),
                    aborted_id,
                    aborted_digest,
                )
                .expect("retry candidate cancellation")
            );
            assert!(read_membership_scope_sync(&conn, storage_identity)
                .expect("cancelled candidate scope")
                .pending
                .is_none());
            assert_eq!(
                MembershipScopeMutationError::ConflictingTransition,
                cancel_provisional_candidate_membership_scope_sync(
                    &conn,
                    storage_identity,
                    member(10),
                    [0x4b; MEMBERSHIP_TRANSITION_ID_BYTES],
                    aborted_digest,
                )
                .expect_err("another transition cannot reuse the cancellation tombstone")
            );
            assert_eq!(
                SessionConsensusStorageError::RecoveryRequired,
                initialize_schema_with_pending(
                    &conn,
                    storage_identity,
                    &current,
                    Some(PendingMembershipBootstrap {
                        local_candidate_node_id: Some(member(10)),
                        transition_id: aborted_id,
                        transition_digest: [0x4c; 32],
                        desired_identity: aborted_identity,
                        desired_members: &desired,
                        desired_bindings: &desired_bindings,
                    }),
                )
                .expect_err("a cancelled transition ID cannot be revived with another digest")
            );
            assert_eq!(
                Some(CandidateBootstrapMarker {
                    local_candidate_node_id: member(10),
                    transition_id: aborted_id,
                    transition_digest: aborted_digest,
                    state: CandidateBootstrapState::Cancelled,
                }),
                read_candidate_bootstrap_marker_sync(&conn, storage_identity)
                    .expect("cancelled marker remains durable")
            );
        }

        let backend = SqliteSessionBackend::open(&database).expect("backend");
        {
            let conn = backend.conn.lock().await;
            initialize_schema(&conn, storage_identity, &current).expect("initialize scope");
            let initial = membership_entry_at(0, vec![current.clone()], current.clone());
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&initial))
                .expect("append current membership");
            apply_entries_sync(&conn, storage_identity, &backend.caps, vec![initial])
                .expect("apply current membership");
            stage_membership_scope_sync(
                &conn,
                storage_identity,
                aborted_id,
                aborted_digest,
                aborted_identity,
                &desired,
            )
            .expect("stage transition");
            let learners = membership_entry_at(1, vec![current.clone()], desired.clone());
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&learners))
                .expect("append learners");
            apply_entries_sync(&conn, storage_identity, &backend.caps, vec![learners])
                .expect("apply learners");
            let abort = topology_entry_at(
                2,
                0x87,
                SessionMutationIntent::AbortTopologyTransition {
                    transition_id: aborted_id,
                    request_digest: aborted_digest,
                },
            );
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&abort))
                .expect("append abort");
            apply_entries_sync(&conn, storage_identity, &backend.caps, vec![abort])
                .expect("apply abort");
            let cleanup = membership_entry_at(3, vec![current.clone()], current.clone());
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&cleanup))
                .expect("append exact abort cleanup");
            apply_entries_sync(&conn, storage_identity, &backend.caps, vec![cleanup])
                .expect("apply exact abort cleanup");
        }
        drop(backend);

        let reopened = SqliteSessionBackend::open(&database).expect("reopen candidate");
        let conn = reopened.conn.lock().await;
        let same_aborted = PendingMembershipBootstrap {
            local_candidate_node_id: Some(member(10)),
            transition_id: aborted_id,
            transition_digest: aborted_digest,
            desired_identity: aborted_identity,
            desired_members: &desired,
            desired_bindings: &desired_bindings,
        };
        assert_eq!(
            SessionConsensusStorageError::RecoveryRequired,
            initialize_schema_with_pending(&conn, storage_identity, &current, Some(same_aborted),)
                .expect_err("an aborted transition cannot be reopened blindly")
        );

        let successor = PendingMembershipBootstrap {
            local_candidate_node_id: Some(member(10)),
            transition_id: [0x47; MEMBERSHIP_TRANSITION_ID_BYTES],
            transition_digest: [0x48; 32],
            desired_identity: identity_at(2, 0x66),
            desired_members: &desired,
            desired_bindings: &desired_bindings,
        };
        initialize_schema_with_pending(&conn, storage_identity, &current, Some(successor))
            .expect("durably aborted learner may stage a distinct successor");
        let scope = read_membership_scope_sync(&conn, storage_identity).expect("reused scope");
        assert_eq!(
            0,
            scope
                .pending
                .expect("new candidate transition")
                .transition_start_log_index
        );

        let unproven = SqliteSessionBackend::in_memory().expect("unproven backend");
        let unproven_conn = unproven.conn.lock().await;
        initialize_schema(&unproven_conn, storage_identity, &current)
            .expect("initialize unproven scope");
        let initial = membership_entry_at(0, vec![current.clone()], current.clone());
        append_logs_sync(
            &unproven_conn,
            storage_identity,
            std::slice::from_ref(&initial),
        )
        .expect("append unproven membership");
        apply_entries_sync(
            &unproven_conn,
            storage_identity,
            &unproven.caps,
            vec![initial],
        )
        .expect("apply unproven membership");
        assert_eq!(
            SessionConsensusStorageError::RecoveryRequired,
            initialize_schema_with_pending(
                &unproven_conn,
                storage_identity,
                &current,
                Some(PendingMembershipBootstrap {
                    local_candidate_node_id: Some(member(10)),
                    transition_id: [0x49; MEMBERSHIP_TRANSITION_ID_BYTES],
                    transition_digest: [0x4a; 32],
                    desired_identity: identity_at(2, 0x67),
                    desired_members: &desired,
                    desired_bindings: &desired_bindings,
                }),
            )
            .expect_err("candidate reuse without durable abort proof must fail closed")
        );
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
            local_candidate_node_id: Some(member(10)),
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
                    abort_decision_log_index: None,
                    abort_cleanup_log_index: None,
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
                    local_candidate_node_id: Some(member(10)),
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
            let finalize = topology_entry_at(
                5,
                0x88,
                SessionMutationIntent::FinalizeTopologyTransition {
                    transition_id: first_id,
                    request_digest: first_digest,
                },
            );
            append_logs_sync(&conn, storage_identity, std::slice::from_ref(&finalize))
                .expect("append first finalization");
            apply_entries_sync(&conn, storage_identity, &source.caps, vec![finalize])
                .expect("finalize first transition");

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
            purge_logs_sync(&conn, storage_identity, &log_id(5)).expect("purge first history");
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
            let transition_floor = blank_entry(6);
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
                7,
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
                local_candidate_node_id: None,
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
            RestoreScanValidationProfile::Consensus,
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
            RestoreScanValidationProfile::Consensus,
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
            RestoreScanValidationProfile::Consensus,
        )
        .expect_err("same snapshot still yields node-local cursor incarnations");
        assert_eq!(cross_node, StoreError::RestoreScanCursorStale);
    }

    #[tokio::test]
    async fn snapshot_install_rejects_source_log_authority_and_retains_destination_vote() {
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
        .expect("apply source membership");
        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("source.sqlite");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity, &snapshot_path)
                .expect("build source snapshot");
        drop(source_conn);
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "destination-vote-retained".into(),
        };

        let snapshot_conn = Connection::open(&snapshot_path).expect("open source snapshot");
        for table in [
            "consensus_vote",
            "consensus_committed",
            "consensus_purged",
            "consensus_log",
            "consensus_snapshot",
        ] {
            assert_eq!(
                0_i64,
                snapshot_conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .expect("read empty source-local authority table"),
                "incoming snapshot source must exclude {table}"
            );
        }
        drop(snapshot_conn);

        // Keep this target file-backed: snapshot ATTACH must remain compatible
        // with the portable live-WAL constructor while still binding the
        // incoming source through its Linux descriptor-pinned boundary.
        let target = SqliteSessionBackend::open(directory.path().join("target.sqlite"))
            .expect("file-backed target backend");
        let target_conn = target.conn.lock().await;
        initialize_schema(&target_conn, identity, &expected).expect("target consensus schema");
        save_vote_sync(&target_conn, identity, &Vote::new_committed(7, node_id()))
            .expect("persist target-local vote");
        let byte_length = std::fs::metadata(&snapshot_path)
            .expect("snapshot metadata")
            .len();
        install_snapshot_database_sync(
            &target_conn,
            identity,
            &snapshot_path,
            &meta,
            "destination-vote-retained.opc",
            [0x7e; 32],
            byte_length,
        )
        .expect("install valid incoming snapshot into target with local vote");
        assert_eq!(
            Some(Vote::new_committed(7, node_id())),
            read_vote_sync(&target_conn, identity).expect("read retained target-local vote")
        );
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
            .query_map([], |row| {
                Ok::<(String, i64), rusqlite::Error>((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                ))
            })
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
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
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

    #[tokio::test]
    async fn revoked_application_authority_commits_typed_no_effect_outcome() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let storage_identity = identity();
        let current = members(&[7, 8, 9]);
        let desired = members(&[7, 8, 9, 10, 11]);
        let desired_identity = identity_at(2, 0x5c);
        let transition_id = [0xB4; MEMBERSHIP_TRANSITION_ID_BYTES];
        let transition_digest = [0xC4; 32];
        initialize_schema(&conn, storage_identity, &current).expect("consensus schema");
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
        .expect("stage desired authority");
        let learners = membership_entry_at(1, vec![current], desired);
        let ready = topology_entry_at(
            2,
            0xB4,
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id,
                request_digest: transition_digest,
            },
        );
        append_logs_sync(&conn, storage_identity, &[learners.clone(), ready.clone()])
            .expect("append learner readiness");
        apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![learners, ready],
        )
        .expect("apply learner readiness");
        fence_application_authority_sync(&conn, storage_identity, transition_id, transition_digest)
            .expect("fence predecessor authority");

        let revoked = apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![authorized_acquire_entry(
                3,
                [0xB5; 16],
                node_id(),
                storage_identity,
            )],
        )
        .expect("commit deterministic authority rejection");
        assert!(matches!(
            revoked.responses.last(),
            Some(SessionConsensusResponse {
                result: Err(StoreError::TopologyAuthorityRevoked),
                ..
            })
        ));
        assert_eq!(
            0_i64,
            conn.query_row("SELECT COUNT(*) FROM leases", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("count unchanged leases")
        );
        assert_eq!(
            Some(log_id(3)),
            read_applied_sync(&conn, storage_identity).expect("rejection is durably applied")
        );
    }

    #[tokio::test]
    async fn idempotent_outcome_does_not_cross_topology_authority_epoch() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let storage_identity = identity();
        initialize_schema(&conn, storage_identity, &expected_members()).expect("consensus schema");

        let request_id = [0xB3; 16];
        let first = apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![
                membership_entry(),
                authorized_acquire_entry(1, request_id, node_id(), storage_identity),
            ],
        )
        .expect("current-authority request applies");
        assert!(matches!(
            first.responses.last(),
            Some(SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::Lease(_)),
                ..
            })
        ));

        let conflict = apply_entries_sync(
            &conn,
            storage_identity,
            &backend.caps,
            vec![authorized_acquire_entry(
                2,
                request_id,
                node_id(),
                identity_at(2, 0x5c),
            )],
        )
        .expect("a request-ID collision is a durable domain conflict");
        assert!(matches!(
            conflict.responses.last(),
            Some(SessionConsensusResponse {
                result: Err(StoreError::CasIdempotencyConflict),
                ..
            })
        ));
        assert_eq!(
            Some(log_id(2)),
            read_applied_sync(&conn, storage_identity)
                .expect("the closed conflict is durably applied")
        );
        assert_eq!(
            1_i64,
            conn.query_row("SELECT COUNT(*) FROM leases", [], |row| row
                .get::<_, i64>(0))
                .expect("count unchanged leases"),
            "the new authority epoch must not recover or repeat the old effect"
        );
    }

    #[tokio::test]
    async fn authority_profile_is_set_once_and_fixed_reopen_requires_exact_identity() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let members = members(&[7, 8, 9]);

        initialize_schema_with_profile(
            &conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed authority");
        assert_eq!(
            ConsensusAuthorityProfile::FixedImmutable,
            read_consensus_authority_profile_sync(&conn).expect("read fixed authority")
        );
        initialize_schema_with_profile(
            &conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("reopen same fixed authority");
        assert_eq!(
            SessionConsensusStorageError::IdentityMismatch,
            initialize_schema_with_profile(
                &conn,
                identity,
                &members,
                ConsensusAuthorityProfile::Dynamic,
            )
            .expect_err("dynamic authority must not claim a fixed database")
        );
        assert_eq!(
            SessionConsensusStorageError::IdentityMismatch,
            initialize_schema_with_profile(
                &conn,
                identity_at(2, 0x98),
                &members,
                ConsensusAuthorityProfile::FixedImmutable,
            )
            .expect_err("fixed authority must retain its exact storage identity")
        );
    }

    #[tokio::test]
    async fn fixed_raw_vote_rejects_durable_profile_drift() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let fixed_members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&fixed_members);
        initialize_schema_with_profile(
            &conn,
            identity,
            &fixed_members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed authority");
        conn.execute(
            "UPDATE consensus_identity SET authority_profile = ?1 WHERE singleton = 1",
            [authority_profile_i64(ConsensusAuthorityProfile::Dynamic)],
        )
        .expect("persist authority profile drift");

        let error = save_vote_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &Vote::new_committed(1, member(7)),
        )
        .expect_err("fixed raw vote must revalidate its durable authority");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert!(read_vote_sync(&conn, identity)
            .expect("read rejected vote")
            .is_none());
    }

    #[tokio::test]
    async fn fixed_raw_vote_rejects_nonmember_leader_id_without_mutation() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let fixed_members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&fixed_members);
        initialize_schema_with_profile(
            &conn,
            identity,
            &fixed_members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed authority");

        let error = save_vote_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &Vote::new_committed(1, member(10)),
        )
        .expect_err("fixed authority must reject a nonmember vote leader");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert!(read_vote_sync(&conn, identity)
            .expect("read rolled-back vote")
            .is_none());
    }

    #[tokio::test]
    async fn fixed_reopen_rejects_stopped_database_nonmember_vote_tamper() {
        let directory = tempfile::tempdir().expect("database directory");
        let database = directory.path().join("fixed-vote-tamper.sqlite");
        let identity = identity();
        let fixed_members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&fixed_members);

        let backend = SqliteSessionBackend::open(&database).expect("backend");
        let conn = backend.conn.lock().await;
        initialize_schema_with_profile(
            &conn,
            identity,
            &fixed_members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed authority");
        apply_entries_with_authority_sync(
            &conn,
            identity,
            &backend.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![membership_entry_at(
                0,
                vec![fixed_members.clone()],
                fixed_members.clone(),
            )],
        )
        .expect("form fixed quorum");
        save_vote_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &Vote::new_committed(1, member(7)),
        )
        .expect("persist member vote");
        drop(conn);
        drop(backend);

        let tampered = Connection::open(&database).expect("open stopped database");
        let nonmember_vote = Vote::new_committed(2, member(10));
        tampered
            .execute(
                "UPDATE consensus_vote SET term = ?1, node_id = ?2, vote_json = ?3 WHERE singleton = 1",
                params![2_i64, 10_i64, encode_json(&nonmember_vote).expect("encode tampered vote")],
            )
            .expect("tamper stopped database vote");
        drop(tampered);

        let reopened = SqliteSessionBackend::open(&database).expect("reopen backend");
        let conn = reopened.conn.lock().await;
        let error = initialize_schema_with_profile(
            &conn,
            identity,
            &fixed_members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect_err("fixed reopen must reject the tampered nonmember vote");
        assert_eq!(SessionConsensusStorageError::CorruptState, error);
    }

    #[tokio::test]
    async fn fixed_three_and_five_member_initial_formation_reopen_exactly() {
        for member_ids in [&[7_u64, 8, 9][..], &[7_u64, 8, 9, 10, 11][..]] {
            let directory = tempfile::tempdir().expect("fixed quorum directory");
            let database = directory.path().join("sessions.sqlite");
            let identity = identity();
            let members = members(member_ids);
            let bindings = test_member_bindings(&members);
            let backend = SqliteSessionBackend::open(&database).expect("fixed backend");
            let conn = backend.conn.lock().await;
            initialize_schema_with_profile(
                &conn,
                identity,
                &members,
                ConsensusAuthorityProfile::FixedImmutable,
            )
            .expect("initialize fixed authority");
            apply_entries_with_authority_sync(
                &conn,
                identity,
                &backend.caps,
                ConsensusAuthorityProfile::FixedImmutable,
                &members,
                &bindings,
                FIXED_TEST_PLACEMENT_POLICY,
                vec![membership_entry_at(
                    0,
                    vec![members.clone()],
                    members.clone(),
                )],
            )
            .expect("form fixed quorum");
            drop(conn);
            drop(backend);

            let reopened = SqliteSessionBackend::open(&database).expect("reopen fixed backend");
            let conn = reopened.conn.lock().await;
            initialize_schema_with_profile(
                &conn,
                identity,
                &members,
                ConsensusAuthorityProfile::FixedImmutable,
            )
            .expect("reopen fixed authority");
            assert!(fixed_quorum_authority_is_exact_sync(
                &conn,
                identity,
                &members,
                &bindings,
                PlacementResiliencePolicy::RequireIndependentFailureDomains,
                false,
            )
            .expect("read reopened fixed authority"));
        }
    }

    #[tokio::test]
    async fn fixed_apply_rejects_prepare_transition_without_scope_drift() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let fixed_members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&fixed_members);
        initialize_schema_with_profile(
            &conn,
            identity,
            &fixed_members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed authority");

        let desired_members = members(&[8, 9, 10]);
        let desired_bindings = test_member_bindings(&desired_members);
        let error = apply_entries_with_authority_sync(
            &conn,
            identity,
            &backend.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![
                membership_entry_at(0, vec![fixed_members.clone()], fixed_members.clone()),
                topology_entry_at(
                    1,
                    0x81,
                    SessionMutationIntent::PrepareTopologyTransition {
                        transition_id: [0x81; MEMBERSHIP_TRANSITION_ID_BYTES],
                        request_digest: [0x82; 32],
                        desired_identity: identity_at(2, 0x83),
                        desired_members,
                        desired_bindings,
                    },
                ),
            ],
        )
        .expect_err("fixed authority must reject committed topology preparation");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert!(read_applied_sync(&conn, identity)
            .expect("read rolled-back applied pointer")
            .is_none());
        let scope = read_membership_scope_sync(&conn, identity).expect("read rolled-back scope");
        assert!(scope.pending.is_none());
        assert_eq!(identity, scope.current_identity);
        assert_eq!(fixed_members, scope.current_members);
        assert!(read_membership_sync(&conn, identity)
            .expect("read rolled-back membership")
            .log_id()
            .is_none());
    }

    #[test]
    fn fixed_profile_recursively_classifies_every_transition_intent() {
        let transition_id = [0x84; MEMBERSHIP_TRANSITION_ID_BYTES];
        let request_digest = [0x85; 32];
        let desired_members = members(&[8, 9, 10]);
        let intents = [
            SessionMutationIntent::PrepareTopologyTransition {
                transition_id,
                request_digest,
                desired_identity: identity_at(2, 0x86),
                desired_members: desired_members.clone(),
                desired_bindings: test_member_bindings(&desired_members),
            },
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id,
                request_digest,
            },
            SessionMutationIntent::FenceTopologyAuthority {
                transition_id,
                request_digest,
            },
            SessionMutationIntent::AbortTopologyTransition {
                transition_id,
                request_digest,
            },
            SessionMutationIntent::FinalizeTopologyTransition {
                transition_id,
                request_digest,
            },
        ];
        for intent in intents {
            assert!(fixed_profile_intent_changes_topology(&intent));
            assert!(fixed_profile_intent_changes_topology(
                &SessionMutationIntent::Authorized {
                    origin: member(7),
                    authority_identity: identity(),
                    mutation: Box::new(intent),
                }
            ));
        }
        assert!(!fixed_profile_intent_changes_topology(
            &SessionMutationIntent::AdvanceLogicalTime
        ));
    }

    #[test]
    fn fixed_raw_log_append_rejects_nested_topology_transition_before_persistence() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.blocking_lock();
        let identity = identity();
        let fixed_members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&fixed_members);
        initialize_schema_with_profile(
            &conn,
            identity,
            &fixed_members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed authority");

        let desired_members = members(&[8, 9, 10]);
        let rejected = append_logs_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &[
                membership_entry_at(0, vec![fixed_members.clone()], fixed_members.clone()),
                topology_entry_at(
                    1,
                    0x87,
                    SessionMutationIntent::Authorized {
                        origin: member(7),
                        authority_identity: identity,
                        mutation: Box::new(SessionMutationIntent::PrepareTopologyTransition {
                            transition_id: [0x87; MEMBERSHIP_TRANSITION_ID_BYTES],
                            request_digest: [0x88; 32],
                            desired_identity: identity_at(2, 0x89),
                            desired_members: desired_members.clone(),
                            desired_bindings: test_member_bindings(&desired_members),
                        }),
                    },
                ),
            ],
        );
        assert_eq!(
            Err(io::ErrorKind::InvalidData),
            rejected.map_err(|error| error.kind())
        );
        assert_eq!(
            0_i64,
            conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("read rejected log count")
        );
    }

    #[tokio::test]
    async fn fixed_raw_writes_reject_profile_preserving_storage_identity_drift() {
        for drift in ["cluster_id", "configuration_id", "configuration_epoch"] {
            let backend = SqliteSessionBackend::in_memory().expect("backend");
            let conn = backend.conn.lock().await;
            let identity = identity();
            let members = members(&[7, 8, 9]);
            let bindings = test_member_bindings(&members);
            initialize_schema_with_profile(
                &conn,
                identity,
                &members,
                ConsensusAuthorityProfile::FixedImmutable,
            )
            .expect("initialize fixed authority");
            apply_entries_with_authority_sync(
                &conn,
                identity,
                &backend.caps,
                ConsensusAuthorityProfile::FixedImmutable,
                &members,
                &bindings,
                FIXED_TEST_PLACEMENT_POLICY,
                vec![membership_entry_at(
                    0,
                    vec![members.clone()],
                    members.clone(),
                )],
            )
            .expect("form fixed quorum");
            conn.execute_batch("PRAGMA foreign_keys = OFF")
                .expect("allow adversarial identity drift fixture");
            match drift {
                "cluster_id" => {
                    conn.execute(
                        "UPDATE consensus_identity SET cluster_id = ?1 WHERE singleton = 1",
                        [[0x91; 32].as_slice()],
                    )
                    .expect("persist cluster drift");
                }
                "configuration_id" => {
                    conn.execute(
                        "UPDATE consensus_identity SET configuration_id = ?1 WHERE singleton = 1",
                        [[0x92; 32].as_slice()],
                    )
                    .expect("persist configuration-ID drift");
                }
                "configuration_epoch" => {
                    conn.execute(
                        "UPDATE consensus_identity SET configuration_epoch = 2 WHERE singleton = 1",
                        [],
                    )
                    .expect("persist configuration-epoch drift");
                }
                _ => unreachable!("static identity drift fixture"),
            }
            conn.execute_batch("PRAGMA foreign_keys = ON")
                .expect("restore foreign-key checks");

            let vote = save_vote_with_authority_sync(
                &conn,
                identity,
                ConsensusAuthorityProfile::FixedImmutable,
                &members,
                &bindings,
                FIXED_TEST_PLACEMENT_POLICY,
                &Vote::new_committed(1, member(7)),
            )
            .expect_err("fixed vote must reject storage identity drift");
            assert_eq!(io::ErrorKind::InvalidData, vote.kind(), "{drift}");
            let append = append_logs_with_authority_sync(
                &conn,
                identity,
                ConsensusAuthorityProfile::FixedImmutable,
                &members,
                &bindings,
                FIXED_TEST_PLACEMENT_POLICY,
                &[blank_entry(1)],
            )
            .expect_err("fixed log append must reject storage identity drift");
            assert_eq!(io::ErrorKind::InvalidData, append.kind(), "{drift}");
            let apply = apply_entries_with_authority_sync(
                &conn,
                identity,
                &backend.caps,
                ConsensusAuthorityProfile::FixedImmutable,
                &members,
                &bindings,
                FIXED_TEST_PLACEMENT_POLICY,
                vec![blank_entry(1)],
            )
            .expect_err("fixed apply must reject storage identity drift");
            assert_eq!(io::ErrorKind::InvalidData, apply.kind(), "{drift}");
            let snapshot = save_current_snapshot_with_authority_sync(
                &conn,
                identity,
                ConsensusAuthorityProfile::FixedImmutable,
                &members,
                &bindings,
                FIXED_TEST_PLACEMENT_POLICY,
                &opc_consensus::engine::SnapshotMeta {
                    last_log_id: Some(log_id(0)),
                    last_membership: StoredMembership::new(
                        Some(log_id(0)),
                        opc_consensus::engine::Membership::new(
                            vec![members.clone()],
                            members.clone(),
                        ),
                    ),
                    snapshot_id: format!("fixed-identity-drift-{drift}"),
                },
                "fixed-identity-drift.opc",
                [0x93; 32],
                1,
            )
            .expect_err("fixed snapshot metadata must reject storage identity drift");
            assert_eq!(io::ErrorKind::InvalidData, snapshot.kind(), "{drift}");
            assert_eq!(
                0_i64,
                conn.query_row("SELECT COUNT(*) FROM consensus_vote", [], |row| row
                    .get::<_, i64>(0))
                    .expect("read rejected vote count"),
                "{drift}"
            );
            assert_eq!(
                0_i64,
                conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| row
                    .get::<_, i64>(0))
                    .expect("read rejected log count"),
                "{drift}"
            );
            assert_eq!(
                1_i64,
                conn.query_row("SELECT COUNT(*) FROM consensus_applied", [], |row| row
                    .get::<_, i64>(0))
                    .expect("read unchanged applied pointer count"),
                "{drift}"
            );
            assert_eq!(
                0_i64,
                conn.query_row("SELECT COUNT(*) FROM consensus_snapshot", [], |row| row
                    .get::<_, i64>(0))
                    .expect("read rejected snapshot metadata count"),
                "{drift}"
            );
        }
    }

    #[tokio::test]
    async fn fixed_raw_log_and_commit_reject_durable_scope_drift() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&members);
        initialize_schema_with_profile(
            &conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed authority");
        apply_entries_with_authority_sync(
            &conn,
            identity,
            &backend.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![membership_entry_at(
                0,
                vec![members.clone()],
                members.clone(),
            )],
        )
        .expect("form fixed quorum");
        conn.execute(
            "UPDATE consensus_membership_scope SET current_bindings_json = ?1 WHERE singleton = 1",
            [b"[]".as_slice()],
        )
        .expect("persist fixed scope drift");

        let append = append_logs_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &[topology_entry_at(
                1,
                0x71,
                SessionMutationIntent::AdvanceLogicalTime,
            )],
        )
        .expect_err("fixed raw log append must revalidate its durable authority");
        assert_eq!(io::ErrorKind::InvalidData, append.kind());
        let committed = save_committed_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            Some(log_id(0)),
        )
        .expect_err("fixed committed pointer must revalidate its durable authority");
        assert_eq!(io::ErrorKind::InvalidData, committed.kind());
        let snapshot_meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: Some(log_id(0)),
            last_membership: read_membership_sync(&conn, identity)
                .expect("read fixed membership before rejected snapshot save"),
            snapshot_id: "fixed-raw-drift".into(),
        };
        let snapshot = save_current_snapshot_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &snapshot_meta,
            "fixed-raw-drift.opc",
            [0x71; 32],
            1,
        )
        .expect_err("fixed snapshot metadata must revalidate its durable authority");
        assert_eq!(io::ErrorKind::InvalidData, snapshot.kind());
        assert_eq!(
            0_i64,
            conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("rejected log count")
        );
        assert!(read_committed_sync(&conn, identity)
            .expect("read rejected committed pointer")
            .is_none());
        assert!(read_current_snapshot_sync(&conn, identity)
            .expect("read rejected snapshot metadata")
            .is_none());
    }

    #[tokio::test]
    async fn fixed_snapshot_build_rejects_durable_authority_drift() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&members);
        initialize_schema_with_profile(
            &conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed authority");
        apply_entries_with_authority_sync(
            &conn,
            identity,
            &backend.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![membership_entry_at(
                0,
                vec![members.clone()],
                members.clone(),
            )],
        )
        .expect("form fixed quorum");
        conn.execute(
            "UPDATE consensus_membership_scope SET current_bindings_json = ?1 WHERE singleton = 1",
            [b"[]".as_slice()],
        )
        .expect("persist fixed scope drift");

        let directory = tempfile::tempdir().expect("snapshot directory");
        let path = directory.path().join("rejected-fixed-source.sqlite");
        let error = build_snapshot_database_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &path,
        )
        .expect_err("fixed snapshot build must revalidate durable authority");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert!(
            !path.exists(),
            "rejected snapshot build must not write an image"
        );
    }

    #[tokio::test]
    async fn fixed_snapshot_build_rejects_invalid_source_before_creating_an_artifact() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&members);
        initialize_schema_with_profile(
            &conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed authority");
        apply_entries_with_authority_sync(
            &conn,
            identity,
            &backend.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![membership_entry_at(
                0,
                vec![members.clone()],
                members.clone(),
            )],
        )
        .expect("form fixed quorum");
        let oversized = sealed_record_for_key(key(), 1_048_577);
        persist_sealed_record_fixture(&conn, &oversized);

        let directory = tempfile::tempdir().expect("snapshot directory");
        let path = directory.path().join("invalid-fixed-source.sqlite");
        let error = build_snapshot_database_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &path,
        )
        .expect_err("fixed snapshot build must reject invalid source state");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert!(
            !path.exists(),
            "invalid fixed source must not leave a snapshot artifact"
        );
    }

    #[tokio::test]
    async fn fixed_policy_drift_rejects_all_raw_writes_and_snapshot_paths_without_mutation() {
        let identity = identity();
        let members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&members);
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.lock().await;
        initialize_schema_with_profile(
            &source_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed source");
        apply_entries_with_authority_sync(
            &source_conn,
            identity,
            &source.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![membership_entry_at(
                0,
                vec![members.clone()],
                members.clone(),
            )],
        )
        .expect("form fixed source quorum");
        let directory = tempfile::tempdir().expect("snapshot directory");
        let source_snapshot_path = directory.path().join("fixed-source.sqlite");
        let (source_last_log_id, source_last_membership) =
            build_snapshot_database_with_authority_sync(
                &source_conn,
                identity,
                ConsensusAuthorityProfile::FixedImmutable,
                &members,
                &bindings,
                FIXED_TEST_PLACEMENT_POLICY,
                &source_snapshot_path,
            )
            .expect("build fixed source snapshot");
        drop(source_conn);

        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.lock().await;
        initialize_schema_with_profile(
            &target_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed target");
        apply_entries_with_authority_sync(
            &target_conn,
            identity,
            &target.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![membership_entry_at(
                0,
                vec![members.clone()],
                members.clone(),
            )],
        )
        .expect("form fixed target quorum");
        target_conn
            .execute(
                "UPDATE consensus_identity SET fixed_placement_policy = ?1 WHERE singleton = 1",
                [placement_policy_i64(
                    PlacementResiliencePolicy::AllowReducedResilience,
                )],
            )
            .expect("persist fixed placement policy drift");

        let vote = save_vote_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &Vote::new_committed(1, member(7)),
        )
        .expect_err("fixed vote must reject placement policy drift");
        assert_eq!(io::ErrorKind::InvalidData, vote.kind());
        let append = append_logs_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &[blank_entry(1)],
        )
        .expect_err("fixed append must reject placement policy drift");
        assert_eq!(io::ErrorKind::InvalidData, append.kind());
        let committed = save_committed_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            Some(log_id(0)),
        )
        .expect_err("fixed commit must reject placement policy drift");
        assert_eq!(io::ErrorKind::InvalidData, committed.kind());
        let truncate = truncate_logs_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &log_id(1),
        )
        .expect_err("fixed truncate must reject placement policy drift");
        assert_eq!(io::ErrorKind::InvalidData, truncate.kind());
        let purge = purge_logs_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &log_id(0),
        )
        .expect_err("fixed purge must reject placement policy drift");
        assert_eq!(io::ErrorKind::InvalidData, purge.kind());
        let apply = apply_entries_with_authority_sync(
            &target_conn,
            identity,
            &target.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![blank_entry(1)],
        )
        .expect_err("fixed apply must reject placement policy drift");
        assert_eq!(io::ErrorKind::InvalidData, apply.kind());

        let rejected_build_path = directory.path().join("rejected-fixed-source.sqlite");
        let build = build_snapshot_database_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &rejected_build_path,
        )
        .expect_err("fixed snapshot build must reject placement policy drift");
        assert_eq!(io::ErrorKind::InvalidData, build.kind());
        assert!(
            !rejected_build_path.exists(),
            "rejected snapshot build must not create an image"
        );
        let snapshot_meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: Some(log_id(0)),
            last_membership: read_membership_sync(&target_conn, identity)
                .expect("read fixed target membership"),
            snapshot_id: "fixed-policy-drift".into(),
        };
        let save = save_current_snapshot_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &snapshot_meta,
            "fixed-policy-drift.opc",
            [0x91; 32],
            1,
        )
        .expect_err("fixed snapshot save must reject placement policy drift");
        assert_eq!(io::ErrorKind::InvalidData, save.kind());
        let source_meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: source_last_log_id,
            last_membership: source_last_membership,
            snapshot_id: "fixed-policy-drift-install".into(),
        };
        let install = install_snapshot_database_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            Some(&members),
            Some(&bindings),
            FIXED_TEST_PLACEMENT_POLICY,
            &source_snapshot_path,
            &source_meta,
            "fixed-policy-drift-install.opc",
            [0x92; 32],
            std::fs::metadata(&source_snapshot_path)
                .expect("source snapshot metadata")
                .len(),
        )
        .expect_err("fixed snapshot install must reject local placement policy drift");
        assert_eq!(io::ErrorKind::InvalidData, install.kind());
        assert!(read_vote_sync(&target_conn, identity)
            .expect("read rejected vote")
            .is_none());
        assert!(read_committed_sync(&target_conn, identity)
            .expect("read rejected committed pointer")
            .is_none());
        assert_eq!(
            Some(log_id(0)),
            read_applied_sync(&target_conn, identity).expect("read unchanged applied pointer")
        );
        assert!(read_current_snapshot_sync(&target_conn, identity)
            .expect("read rejected snapshot metadata")
            .is_none());
        assert_eq!(
            Some(PlacementResiliencePolicy::AllowReducedResilience),
            read_fixed_placement_policy_sync(&target_conn)
                .expect("read retained fixed placement policy drift")
        );
    }

    #[tokio::test]
    async fn fixed_snapshot_install_rejects_local_authority_drift_without_repair() {
        let members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&members);
        let identity = identity();
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.lock().await;
        initialize_schema_with_profile(
            &source_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed source");
        apply_entries_with_authority_sync(
            &source_conn,
            identity,
            &source.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![membership_entry_at(
                0,
                vec![members.clone()],
                members.clone(),
            )],
        )
        .expect("form fixed source quorum");
        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("fixed-source.sqlite");
        let (last_log_id, last_membership) = build_snapshot_database_with_authority_sync(
            &source_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &snapshot_path,
        )
        .expect("build fixed source snapshot");
        drop(source_conn);
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "fixed-local-drift".into(),
        };

        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.lock().await;
        initialize_schema_with_profile(
            &target_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed target");
        target_conn
            .execute(
                "UPDATE consensus_membership_scope SET current_bindings_json = ?1 WHERE singleton = 1",
                [b"[]".as_slice()],
            )
            .expect("persist local fixed scope drift");

        let error = install_snapshot_database_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            Some(&members),
            Some(&bindings),
            Some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
            &snapshot_path,
            &meta,
            "fixed-local-drift.opc",
            [0x51; 32],
            std::fs::metadata(&snapshot_path)
                .expect("snapshot metadata")
                .len(),
        )
        .expect_err("fixed snapshot install must not repair local authority drift");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert!(read_applied_sync(&target_conn, identity)
            .expect("read unchanged target applied pointer")
            .is_none());
        assert_eq!(
            BTreeMap::new(),
            read_membership_scope_sync(&target_conn, identity)
                .expect("read retained local drift")
                .current_bindings
        );
    }

    #[tokio::test]
    async fn fixed_snapshot_install_rejects_replaced_incoming_source_before_copy() {
        let identity = identity();
        let members = members(&[7, 8, 9]);
        let bindings = test_member_bindings(&members);
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.lock().await;
        initialize_schema_with_profile(
            &source_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed source");
        apply_entries_with_authority_sync(
            &source_conn,
            identity,
            &source.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            vec![membership_entry_at(
                0,
                vec![members.clone()],
                members.clone(),
            )],
        )
        .expect("form fixed source quorum");
        let directory = tempfile::tempdir().expect("snapshot directory");
        let valid_path = directory.path().join("valid-source.sqlite");
        let (last_log_id, last_membership) = build_snapshot_database_with_authority_sync(
            &source_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            FIXED_TEST_PLACEMENT_POLICY,
            &valid_path,
        )
        .expect("build fixed source snapshot");
        drop(source_conn);
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "fixed-replaced-source".into(),
        };
        let replaced_path = directory.path().join("replaced-source.sqlite");
        std::fs::copy(&valid_path, &replaced_path).expect("stage replacement snapshot");
        let replaced = Connection::open(&replaced_path).expect("open replacement snapshot");
        replaced
            .execute(
                "UPDATE consensus_identity SET authority_profile = ?1 WHERE singleton = 1",
                [authority_profile_i64(ConsensusAuthorityProfile::Dynamic)],
            )
            .expect("replace source authority after valid image was produced");
        drop(replaced);

        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.lock().await;
        initialize_schema_with_profile(
            &target_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed target");
        #[cfg(unix)]
        {
            let symlink_path = directory.path().join("symlink-source.sqlite");
            std::os::unix::fs::symlink(&valid_path, &symlink_path)
                .expect("create incoming snapshot symlink");
            install_snapshot_database_with_authority_sync(
                &target_conn,
                identity,
                ConsensusAuthorityProfile::FixedImmutable,
                Some(&members),
                Some(&bindings),
                Some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
                &symlink_path,
                &meta,
                "symlink-source.opc",
                [0xa0; 32],
                std::fs::metadata(&valid_path)
                    .expect("valid source metadata")
                    .len(),
            )
            .expect_err("incoming snapshot helper must not follow a symlink");
            assert!(read_applied_sync(&target_conn, identity)
                .expect("read unchanged target after symlink rejection")
                .is_none());
        }
        let replaced_error = install_snapshot_database_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            Some(&members),
            Some(&bindings),
            Some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
            &replaced_path,
            &meta,
            "replaced-source.opc",
            [0xa1; 32],
            std::fs::metadata(&replaced_path)
                .expect("replacement metadata")
                .len(),
        )
        .expect_err("attached replacement source must be rejected before copy");
        assert_eq!(io::ErrorKind::InvalidData, replaced_error.kind());
        assert!(read_applied_sync(&target_conn, identity)
            .expect("read unchanged target after replacement rejection")
            .is_none());

        install_snapshot_database_with_authority_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            Some(&members),
            Some(&bindings),
            Some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
            &valid_path,
            &meta,
            "valid-source.opc",
            [0xa2; 32],
            std::fs::metadata(&valid_path)
                .expect("valid source metadata")
                .len(),
        )
        .expect("valid source installs after rejected replacement");
        assert_eq!(
            Some(log_id(0)),
            read_applied_sync(&target_conn, identity).expect("read installed target")
        );
    }

    #[tokio::test]
    async fn dynamic_authority_is_not_upgraded_to_fixed() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let members = expected_members();

        initialize_schema(&conn, identity, &members).expect("initialize dynamic authority");
        assert_eq!(
            ConsensusAuthorityProfile::Dynamic,
            read_consensus_authority_profile_sync(&conn).expect("read dynamic authority")
        );
        assert_eq!(
            SessionConsensusStorageError::IdentityMismatch,
            initialize_schema_with_profile(
                &conn,
                identity,
                &members,
                ConsensusAuthorityProfile::FixedImmutable,
            )
            .expect_err("fixed authority must not upgrade a dynamic database")
        );
    }

    #[tokio::test]
    async fn snapshots_preserve_and_require_the_authority_profile() {
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.lock().await;
        let identity = identity();
        let members = members(&[7, 8, 9]);
        initialize_schema_with_profile(
            &source_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed snapshot source");
        apply_entries_sync(
            &source_conn,
            identity,
            &source.caps,
            vec![membership_entry_at(
                0,
                vec![members.clone()],
                members.clone(),
            )],
        )
        .expect("apply fixed snapshot membership");
        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("fixed.sqlite");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity, &snapshot_path)
                .expect("build fixed snapshot");
        drop(source_conn);
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "fixed-authority-profile".into(),
        };
        let byte_length = std::fs::metadata(&snapshot_path)
            .expect("snapshot metadata")
            .len();

        let fixed_target = SqliteSessionBackend::in_memory().expect("fixed target");
        let fixed_conn = fixed_target.conn.lock().await;
        initialize_schema_with_profile(
            &fixed_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed target");
        let snapshot_conn = Connection::open(&snapshot_path).expect("open fixed snapshot");
        let incoming_scope =
            read_membership_scope_sync(&snapshot_conn, identity).expect("read snapshot scope");
        let expected_scope =
            read_membership_scope_sync(&fixed_conn, identity).expect("read target scope");
        assert_eq!(incoming_scope, expected_scope);
        validate_fixed_immutable_membership_scope(identity, &expected_scope, &incoming_scope)
            .expect("matching fixed scope is exact");
        drop(snapshot_conn);
        install_snapshot_database_with_profile_sync(
            &fixed_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &snapshot_path,
            &meta,
            "fixed-source.opc",
            [0x91; 32],
            byte_length,
        )
        .expect("install matching fixed snapshot");
        assert_eq!(
            ConsensusAuthorityProfile::FixedImmutable,
            read_consensus_authority_profile_sync(&fixed_conn)
                .expect("fixed target authority remains immutable")
        );
        drop(fixed_conn);

        let dynamic_target = SqliteSessionBackend::in_memory().expect("dynamic target");
        let dynamic_conn = dynamic_target.conn.lock().await;
        initialize_schema(&dynamic_conn, identity, &members).expect("initialize dynamic target");
        assert!(install_snapshot_database_with_profile_sync(
            &dynamic_conn,
            identity,
            ConsensusAuthorityProfile::Dynamic,
            &snapshot_path,
            &meta,
            "fixed-source.opc",
            [0x92; 32],
            byte_length,
        )
        .is_err());
        assert_eq!(
            ConsensusAuthorityProfile::Dynamic,
            read_consensus_authority_profile_sync(&dynamic_conn)
                .expect("failed snapshot cannot overwrite local authority")
        );
        drop(dynamic_conn);

        let tampered_snapshot = Connection::open(&snapshot_path).expect("open fixed snapshot");
        tampered_snapshot
            .execute(
                "UPDATE consensus_identity SET fixed_placement_policy = ?1 WHERE singleton = 1",
                [placement_policy_i64(
                    PlacementResiliencePolicy::AllowReducedResilience,
                )],
            )
            .expect("tamper fixed snapshot placement policy");
        drop(tampered_snapshot);

        let policy_target = SqliteSessionBackend::in_memory().expect("policy target");
        let policy_conn = policy_target.conn.lock().await;
        initialize_schema_with_profile(
            &policy_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed policy target");
        assert!(install_snapshot_database_with_profile_sync(
            &policy_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &snapshot_path,
            &meta,
            "fixed-policy-mismatch.opc",
            [0x93; 32],
            byte_length,
        )
        .is_err());
    }

    #[tokio::test]
    async fn legacy_dynamic_snapshot_without_authority_columns_installs() {
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.lock().await;
        let identity = identity();
        let dynamic_members = expected_members();
        initialize_schema(&source_conn, identity, &dynamic_members)
            .expect("initialize dynamic source");
        apply_entries_sync(
            &source_conn,
            identity,
            &source.caps,
            vec![membership_entry_at(
                0,
                vec![dynamic_members.clone()],
                dynamic_members.clone(),
            )],
        )
        .expect("apply source membership");
        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("legacy-dynamic.sqlite");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity, &snapshot_path)
                .expect("build dynamic snapshot");
        drop(source_conn);

        let legacy_snapshot = Connection::open(&snapshot_path).expect("open snapshot fixture");
        legacy_snapshot
            .execute_batch(
                "ALTER TABLE consensus_identity DROP COLUMN authority_profile;\
                 ALTER TABLE consensus_identity DROP COLUMN fixed_placement_policy;",
            )
            .expect("remove post-release authority columns");
        drop(legacy_snapshot);

        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.lock().await;
        initialize_schema(&target_conn, identity, &dynamic_members)
            .expect("initialize dynamic target");
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "legacy-dynamic-snapshot".into(),
        };
        install_snapshot_database_with_profile_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::Dynamic,
            &snapshot_path,
            &meta,
            "legacy-dynamic.opc",
            [0x94; 32],
            std::fs::metadata(&snapshot_path)
                .expect("legacy snapshot metadata")
                .len(),
        )
        .expect("released dynamic snapshot installs after upgrade");
        assert_eq!(
            Some(log_id(0)),
            read_applied_sync(&target_conn, identity).expect("read installed dynamic snapshot")
        );

        let fixed_target = SqliteSessionBackend::in_memory().expect("fixed target backend");
        let fixed_conn = fixed_target.conn.lock().await;
        let fixed_members = members(&[7, 8, 9]);
        initialize_schema_with_profile(
            &fixed_conn,
            identity,
            &fixed_members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed target");
        let error = install_snapshot_database_with_profile_sync(
            &fixed_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &snapshot_path,
            &meta,
            "legacy-dynamic-fixed.opc",
            [0x95; 32],
            std::fs::metadata(&snapshot_path)
                .expect("legacy snapshot metadata")
                .len(),
        )
        .expect_err("fixed authority must reject a legacy dynamic snapshot");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
    }

    #[tokio::test]
    async fn fixed_snapshot_rejects_persisted_binding_drift() {
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.lock().await;
        let identity = identity();
        let members = members(&[7, 8, 9]);
        initialize_schema_with_profile(
            &source_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed snapshot source");
        apply_entries_sync(
            &source_conn,
            identity,
            &source.caps,
            vec![membership_entry_at(
                0,
                vec![members.clone()],
                members.clone(),
            )],
        )
        .expect("apply fixed snapshot membership");
        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("drifted-fixed.sqlite");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity, &snapshot_path)
                .expect("build fixed snapshot");
        drop(source_conn);

        let snapshot_conn = Connection::open(&snapshot_path).expect("open fixed snapshot");
        let mut drifted_bindings = test_member_bindings(&members);
        drifted_bindings.insert(
            member(7),
            SessionTopologyMemberBinding::new([0x71; 32], [0x72; 32], [0x73; 32], [0x74; 32]),
        );
        snapshot_conn
            .execute(
                "UPDATE consensus_membership_scope SET current_bindings_json = ?1 WHERE singleton = 1",
                [encode_bindings(&members, &drifted_bindings).expect("encode drifted bindings")],
            )
            .expect("persist snapshot binding drift");
        drop(snapshot_conn);

        let target = SqliteSessionBackend::in_memory().expect("fixed target");
        let target_conn = target.conn.lock().await;
        initialize_schema_with_profile(
            &target_conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .expect("initialize fixed target");
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "fixed-binding-drift".into(),
        };
        let byte_length = std::fs::metadata(&snapshot_path)
            .expect("snapshot metadata")
            .len();
        let error = install_snapshot_database_with_profile_sync(
            &target_conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &snapshot_path,
            &meta,
            "drifted-fixed.opc",
            [0x75; 32],
            byte_length,
        )
        .expect_err("fixed snapshot binding drift must fail closed");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn procfd_snapshot_open_rejects_or_stays_on_pinned_inode_during_name_substitution() {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let path = directory.path().join("incoming.sqlite");
        let original = Connection::open(&path).expect("create original SQLite image");
        original
            .execute_batch(
                "CREATE TABLE original_only(value INTEGER); INSERT INTO original_only VALUES (7);",
            )
            .expect("populate original image");
        drop(original);
        let pinned = PinnedSqliteFile::from_file(
            File::open(&path).expect("open original descriptor"),
            path.clone(),
        )
        .expect("pin original descriptor");

        let displaced = directory.path().join("displaced.sqlite");
        let replacement = directory.path().join("replacement.sqlite");
        std::fs::rename(&path, &displaced).expect("displace A");
        let replacement_connection = Connection::open(&replacement).expect("create replacement B");
        replacement_connection
            .execute_batch("CREATE TABLE replacement_only(value INTEGER); INSERT INTO replacement_only VALUES (9);")
            .expect("populate replacement image");
        drop(replacement_connection);
        std::fs::rename(&replacement, &path).expect("publish B");
        std::fs::rename(&displaced, &replacement).expect("retain A for ABA restore");

        let opened = open_pinned_snapshot_database(&pinned);
        std::fs::rename(&replacement, &path).expect("restore A after SQLite proof");
        if let Ok((connection, retained)) = opened {
            let value: i64 = connection
                .query_row("SELECT value FROM original_only", [], |row| row.get(0))
                .expect("SQLite must consume A rather than B");
            assert_eq!(7, value);
            assert!(connection
                .query_row("SELECT value FROM replacement_only", [], |row| row
                    .get::<_, i64>(0))
                .is_err());
            verify_pinned_snapshot_descriptor(&pinned, &retained)
                .expect("retained descriptor must still be A before mutation");
        }
    }

    fn seed_file_backed_consensus(path: &std::path::Path) {
        let backend = SqliteSessionBackend::open(path).expect("fresh backend");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).expect("fresh consensus schema");
    }

    #[test]
    fn fresh_file_backed_production_initializer_seeds_uncommitted_admission() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("fresh-production.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("fresh backend");
        let conn = backend.conn.blocking_lock();
        let members = expected_members();
        let bindings = test_member_bindings(&members);
        initialize_schema_with_storage_anchor_and_pending_and_bindings(
            &conn,
            None,
            identity(),
            &members,
            &bindings,
            None,
            ConsensusAuthorityProfile::Dynamic,
            None,
        )
        .expect("fresh production consensus schema");
        let row: (i64, i64, i64, i64) = conn
            .query_row(
                "SELECT configuration_epoch, admission_revision, strict_activation_index, cutover_committed FROM consensus_command_admission WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read fresh admission row");
        assert_eq!(
            row,
            (
                epoch_i64(identity()).expect("identity epoch"),
                COMMAND_ADMISSION_REVISION,
                0,
                0,
            )
        );
    }

    type ConsensusSchemaEvidence = Vec<(String, String)>;
    type ConsensusTableCounts = Vec<(String, Option<i64>)>;

    fn consensus_reopen_evidence(
        path: &std::path::Path,
    ) -> (ConsensusSchemaEvidence, ConsensusTableCounts) {
        let conn = Connection::open(path).expect("inspect database");
        let schema = conn
            .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .expect("schema query")
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .expect("schema rows")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect schema");
        let counts = schema
            .iter()
            .map(|(table, _)| {
                let count = conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .ok();
                (table.clone(), count)
            })
            .collect();
        (schema, counts)
    }

    fn assert_file_backed_consensus_initializer_rejects_without_repair(
        path: &std::path::Path,
        case: &str,
    ) {
        let before = consensus_reopen_evidence(path);
        let backend = SqliteSessionBackend::open(path)
            .unwrap_or_else(|error| panic!("raw backend must admit {case}: {error}"));
        let conn = backend.conn.blocking_lock();
        assert!(
            initialize_schema(&conn, identity(), &expected_members()).is_err(),
            "consensus initializer must reject corrupt consensus row authority for {case}"
        );
        drop(conn);
        drop(backend);
        assert_eq!(
            consensus_reopen_evidence(path),
            before,
            "failed consensus initialization must not repair schema or singleton data for {case}"
        );
    }

    fn assert_file_backed_raw_reopen_rejects_without_repair(path: &std::path::Path, case: &str) {
        let before = consensus_reopen_evidence(path);
        assert!(
            SqliteSessionBackend::open(path).is_err(),
            "raw backend must reject an incomplete consensus schema inventory for {case}"
        );
        assert_eq!(
            consensus_reopen_evidence(path),
            before,
            "failed raw reopen must not repair schema or singleton data for {case}"
        );
    }

    #[test]
    fn file_backed_reopen_rejects_ambiguous_operator_recovery_digests_without_repair() {
        for (case, mutation) in [
            (
                "pristine-epoch-with-plan",
                "UPDATE consensus_operator_recovery SET recovery_epoch = 0, last_plan_digest = CAST(X'01' || zeroblob(31) AS BLOB) WHERE singleton = 1",
            ),
            (
                "recovered-epoch-without-plan",
                "UPDATE consensus_operator_recovery SET recovery_epoch = 1, last_plan_digest = zeroblob(32) WHERE singleton = 1",
            ),
            (
                "pending-workflow-without-plan",
                "UPDATE consensus_operator_recovery SET pending_epoch = 1, pending_plan_digest = zeroblob(32) WHERE singleton = 1",
            ),
        ] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join("consensus.sqlite");
            seed_file_backed_consensus(&path);
            let conn = Connection::open(&path).expect("mutate stopped database");
            conn.execute_batch("PRAGMA ignore_check_constraints = ON")
                .expect("allow corrupt recovery fixture");
            conn.execute(mutation, [])
                .unwrap_or_else(|error| panic!("inject {case} recovery corruption: {error}"));
            drop(conn);

            assert_file_backed_consensus_initializer_rejects_without_repair(&path, case);
        }
    }

    #[test]
    fn file_backed_reopen_never_repairs_missing_consensus_authority_evidence() {
        let mut schema_cases: Vec<(&str, String)> = CONSENSUS_BASE_TABLES
            .iter()
            .chain(CONSENSUS_UPGRADE_TABLES)
            .map(|table| (*table, format!("DROP TABLE {table}")))
            .collect();
        schema_cases.extend([
            (
                "authority-profile-column",
                "ALTER TABLE consensus_identity DROP COLUMN authority_profile".into(),
            ),
            (
                "placement-policy-column",
                "ALTER TABLE consensus_identity DROP COLUMN fixed_placement_policy".into(),
            ),
            (
                "recovery-cursor-column",
                "ALTER TABLE consensus_operator_recovery DROP COLUMN watch_cursor_invalidation_floor".into(),
            ),
            (
                "admission-column",
                "ALTER TABLE consensus_command_admission DROP COLUMN cutover_committed".into(),
            ),
        ]);
        for (case, mutation) in schema_cases {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join("consensus.sqlite");
            seed_file_backed_consensus(&path);
            let conn = Connection::open(&path).expect("mutate stopped database");
            conn.execute_batch("PRAGMA foreign_keys = OFF")
                .expect("allow malformed authority corruption fixture");
            conn.execute_batch(&mutation).unwrap_or_else(|error| {
                panic!("fixture mutation {case} must be supported: {error}")
            });
            drop(conn);
            assert_file_backed_raw_reopen_rejects_without_repair(&path, case);
        }

        for (case, mutation) in [
            ("identity-singleton", "DELETE FROM consensus_identity"),
            ("machine-singleton", "DELETE FROM consensus_machine"),
            ("membership-singleton", "DELETE FROM consensus_membership"),
            (
                "admission-singleton",
                "DELETE FROM consensus_command_admission",
            ),
            (
                "recovery-singleton",
                "DELETE FROM consensus_operator_recovery",
            ),
            ("scope-singleton", "DELETE FROM consensus_membership_scope"),
        ] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join("consensus.sqlite");
            seed_file_backed_consensus(&path);
            let conn = Connection::open(&path).expect("mutate stopped database");
            conn.execute_batch("PRAGMA foreign_keys = OFF")
                .expect("allow malformed authority corruption fixture");
            conn.execute_batch(mutation).unwrap_or_else(|error| {
                panic!("fixture mutation {case} must be supported: {error}")
            });
            drop(conn);

            let backend = SqliteSessionBackend::open(&path).unwrap_or_else(|error| {
                panic!("raw schema-only reopen must admit exact DDL with missing {case}: {error}")
            });
            drop(backend);
            assert_file_backed_consensus_initializer_rejects_without_repair(&path, case);
        }
    }

    #[test]
    fn file_backed_raw_reopen_rejects_exact_ddl_and_extra_object_mutations() {
        for (case, mutation) in [
            (
                "ddl-change",
                "ALTER TABLE consensus_vote ADD COLUMN unreviewed INTEGER;",
            ),
            (
                "extra-object",
                "CREATE VIEW consensus_unreviewed AS SELECT 1 AS value;",
            ),
        ] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join("consensus.sqlite");
            seed_file_backed_consensus(&path);
            let conn = Connection::open(&path).expect("open stopped database");
            conn.execute_batch(mutation)
                .unwrap_or_else(|error| panic!("install {case} schema mutation: {error}"));
            drop(conn);

            assert_file_backed_raw_reopen_rejects_without_repair(&path, case);
        }
    }

    #[test]
    fn file_backed_complete_frozen_base_schema_migrates() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("frozen-base.sqlite");
        seed_file_backed_consensus(&path);
        let conn = Connection::open(&path).expect("open stopped database");
        for table in CONSENSUS_UPGRADE_TABLES {
            conn.execute_batch(&format!("DROP TABLE {table}"))
                .expect("remove current add-on table");
        }
        conn.execute_batch(
            "ALTER TABLE consensus_identity DROP COLUMN fixed_placement_policy;
             ALTER TABLE consensus_identity DROP COLUMN authority_profile;",
        )
        .expect("restore frozen identity columns");
        drop(conn);

        let backend = SqliteSessionBackend::open(&path).expect("open frozen local database");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members())
            .expect("complete frozen base schema migrates");
        assert_eq!(
            classify_consensus_reopen_schema(&conn).expect("classify frozen-base migration output"),
            ConsensusReopenSchema::HistoricalBaseMigrated,
            "frozen-base migration must preserve its reviewed add-on recovery DDL",
        );
        drop(conn);
        drop(backend);

        let reopened = SqliteSessionBackend::open(&path)
            .expect("raw reopen admits the exact frozen-base migration output");
        let conn = reopened.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members())
            .expect("restart validates the frozen-base migration output");
    }

    #[test]
    fn file_backed_immediate_predecessor_without_receipt_head_classifies_and_migrates() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("immediate-predecessor.sqlite");
        seed_file_backed_consensus(&path);
        let conn = Connection::open(&path).expect("open stopped database");
        downgrade_to_immediate_predecessor_fixture_sync(&conn)
            .expect("install exact predecessor schema");
        let has_receipt_head: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_machine') WHERE name = 'last_receipt_digest')",
                [],
                |row| row.get(0),
            )
            .expect("inspect predecessor machine schema");
        assert!(
            !has_receipt_head,
            "the frozen predecessor did not persist a receipt-chain head"
        );
        assert!(
            is_immediate_predecessor_schema(&conn).expect("classify predecessor"),
            "fixture must model the exact reviewed predecessor manifest"
        );
        assert!(
            read_immediate_predecessor_machine_sync(&conn, identity()).is_ok(),
            "the predecessor-specific reader must not project absent receipt authority"
        );
        assert!(
            read_machine_sync(&conn, identity()).is_err(),
            "the current reader must not accept the predecessor machine layout"
        );
        drop(conn);

        let backend = SqliteSessionBackend::open(&path).expect("open predecessor database");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members())
            .expect("immediate predecessor schema migrates");
    }

    #[test]
    fn file_backed_pre_receipt_and_operator_recovery_variants_classify_and_migrate() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("pre-receipt.sqlite");
        seed_file_backed_consensus(&path);
        let conn = Connection::open(&path).expect("open stopped database");
        let machine: (i64, i64, i64, Vec<u8>, Option<String>, i64) = conn
            .query_row(
                "SELECT singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence FROM consensus_machine WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("read current machine row");
        conn.execute_batch(
            "DROP TABLE consensus_request_outcomes;
             DROP TABLE consensus_machine;",
        )
        .expect("remove receipt-chain tables");
        conn.execute_batch(IMMEDIATE_PREDECESSOR_CONSENSUS_MACHINE_SCHEMA)
            .expect("install pre-receipt machine schema");
        conn.execute_batch(PRE_RECEIPT_CHAIN_CONSENSUS_REQUEST_OUTCOMES_SCHEMA)
            .expect("install pre-receipt outcome schema");
        conn.execute(
            "INSERT INTO consensus_machine (singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![machine.0, machine.1, machine.2, machine.3, machine.4, machine.5],
        )
        .expect("restore pre-receipt machine row");
        drop(conn);

        let backend = SqliteSessionBackend::open(&path)
            .expect("raw open admits the exact pre-receipt inventory");
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members())
            .expect("pre-receipt inventory migrates");
        drop(conn);
        drop(backend);
        assert!(SqliteSessionBackend::open(&path).is_ok());

        for (case, schema) in [
            ("add-on", ConsensusReopenSchema::OperatorRecoveryAddOn),
            (
                "cursor-migrated",
                ConsensusReopenSchema::OperatorRecoveryCursorMigrated,
            ),
            (
                "pre-high-water",
                ConsensusReopenSchema::OperatorRecoveryPreHighWater,
            ),
            ("migrated", ConsensusReopenSchema::OperatorRecoveryMigrated),
        ] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join(format!("operator-{case}.sqlite"));
            seed_file_backed_consensus(&path);
            let conn = Connection::open(&path).expect("open stopped database");
            match schema {
                ConsensusReopenSchema::OperatorRecoveryAddOn => {
                    replace_operator_recovery_schema(&conn, |conn| {
                        install_recovery_validation_schema_sync(conn, true)
                    })
                }
                ConsensusReopenSchema::OperatorRecoveryCursorMigrated => {
                    replace_operator_recovery_schema(&conn, |conn| {
                        install_cursor_migrated_operator_recovery_validation_schema_sync(conn)
                    })
                }
                ConsensusReopenSchema::OperatorRecoveryPreHighWater => {
                    replace_operator_recovery_schema(&conn, |conn| {
                        install_pre_high_water_operator_recovery_validation_schema_sync(conn)
                    })
                }
                ConsensusReopenSchema::OperatorRecoveryMigrated => {
                    replace_operator_recovery_schema(&conn, |conn| {
                        install_migrated_operator_recovery_validation_schema_sync(conn)
                    })
                }
                _ => unreachable!(),
            }
            .unwrap_or_else(|error| panic!("install {case} recovery schema: {error}"));
            conn.execute(
                "INSERT INTO consensus_operator_recovery (singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor) VALUES (1, ?1, 0, ?2, NULL, NULL, 0)",
                params![
                    epoch_i64(identity()).expect("identity epoch"),
                    [0_u8; 32].as_slice(),
                ],
            )
            .unwrap_or_else(|error| panic!("seed {case} recovery singleton: {error}"));
            drop(conn);

            let backend = SqliteSessionBackend::open(&path)
                .unwrap_or_else(|error| panic!("raw open admits {case} schema: {error}"));
            let conn = backend.conn.blocking_lock();
            initialize_schema(&conn, identity(), &expected_members())
                .unwrap_or_else(|error| panic!("{case} recovery schema migrates: {error}"));
            assert_eq!(
                classify_consensus_reopen_schema(&conn).unwrap_or_else(|error| panic!(
                    "classify migrated {case} recovery schema: {error}"
                )),
                schema.expected_schema_after_initialization(),
                "initializer must produce the reviewed {case} recovery schema output",
            );
            drop(conn);
            drop(backend);
            assert!(
                SqliteSessionBackend::open(&path).is_ok(),
                "raw reopen admits migrated {case} recovery schema"
            );
        }
    }

    #[test]
    fn file_backed_hybrid_predecessor_schema_is_rejected_without_repair() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("hybrid-predecessor.sqlite");
        seed_file_backed_consensus(&path);
        let conn = Connection::open(&path).expect("open stopped database");
        conn.execute_batch(
            "DROP TABLE consensus_command_admission;
             DROP TABLE consensus_request_outcomes;",
        )
        .expect("remove current admission and receipt tables");
        conn.execute_batch(LEGACY_CONSENSUS_REQUEST_OUTCOMES_SCHEMA)
            .expect("install predecessor receipt table only");
        assert_eq!(
            classify_consensus_reopen_schema(&conn),
            Err(SessionConsensusStorageError::CorruptState),
            "a current high-water authority table cannot be mistaken for the predecessor"
        );
        drop(conn);

        assert_file_backed_raw_reopen_rejects_without_repair(&path, "hybrid-predecessor");
    }

    fn legacy_payload_too_large_entry() -> Entry<SessionRaftTypeConfig> {
        let legacy_lease = crate::LeaseGuard::new(
            key(),
            OwnerId::new("frozen-legacy-cap-owner").expect("owner"),
            crate::FenceToken::new(1),
            timestamp(1),
            timestamp(2),
            1,
        );
        let mut entry = capped_cas_entry(
            1,
            [0xE1; 16],
            legacy_lease,
            None,
            crate::Generation::new(1),
            1_048_577,
        );
        let EntryPayload::Normal(command) = &mut entry.payload else {
            unreachable!("capped CAS fixture is a normal command");
        };
        *command = DurableSessionConsensusCommand::legacy((**command).clone());
        entry
    }

    #[test]
    fn retained_legacy_payload_compatibility_is_one_over_only() {
        let exact_one_over = match legacy_payload_too_large_entry().payload {
            EntryPayload::Normal(command) => command,
            _ => panic!("legacy capped CAS fixture is normal"),
        };
        validate_command_for_log_with_cap(&exact_one_over, identity(), false)
            .expect("the frozen base one-over rejection remains readable");
        assert!(matches!(
            rederive_legacy_payload_too_large_result(&exact_one_over, identity()),
            Ok(Err(StoreError::PayloadTooLarge {
                actual: BASE_ADMITTED_LEGACY_PAYLOAD_BYTES,
                max: BASE_ADVERTISED_LEGACY_PAYLOAD_MAX_BYTES,
            }))
        ));

        for payload_len in [
            BASE_ADMITTED_LEGACY_PAYLOAD_BYTES + 1,
            BASE_ADMITTED_LEGACY_PAYLOAD_BYTES + 1_024,
        ] {
            let mut overage = exact_one_over.clone();
            let SessionMutationIntent::CompareAndSet(operation) = &mut overage.intent else {
                panic!("legacy capped CAS fixture intent changed");
            };
            let payload = sealed_payload_for_record(&operation.new_record, payload_len);
            operation.new_record.payload = payload;
            for validation in [
                validate_command_for_log_with_cap(&overage, identity(), false),
                rederive_legacy_payload_too_large_result(&overage, identity()).map(|_| ()),
            ] {
                let error = validation
                    .expect_err("legacy compatibility must reject every non-base overage");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }

        let nested = DurableSessionConsensusCommand::legacy(SessionConsensusCommand {
            intent: SessionMutationIntent::Authorized {
                origin: member(7),
                authority_identity: identity(),
                mutation: Box::new(SessionMutationIntent::Authorized {
                    origin: member(7),
                    authority_identity: identity(),
                    mutation: Box::new(exact_one_over.intent.clone()),
                }),
            },
            ..(*exact_one_over).clone()
        });
        let error = validate_command_for_log_with_cap(&nested, identity(), false)
            .expect_err("legacy compatibility must not admit nested follower commands");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session consensus authorized intent nesting is invalid"
        );
    }

    /// Make a file that is byte-for-byte shaped like the reviewed immediate
    /// predecessor where it matters: a four-column outcome table and a
    /// retained revision-zero command whose JSON predates the admission field.
    /// Its one outcome is the only legacy response the new migration may
    /// derive without looking at mutable state.
    fn seed_file_backed_frozen_legacy_payload_too_large(
        path: &std::path::Path,
    ) -> DurableSessionConsensusCommand {
        let backend = SqliteSessionBackend::open(path).expect("fresh backend");
        let caps = backend.consensus_capabilities();
        let (command, response) = {
            let conn = backend.conn.blocking_lock();
            let members = expected_members();
            let bindings = test_member_bindings(&members);
            initialize_schema_with_storage_anchor_and_pending_and_bindings(
                &conn,
                None,
                identity(),
                &members,
                &bindings,
                None,
                ConsensusAuthorityProfile::Dynamic,
                None,
            )
            .expect("fresh production consensus schema");
            let oversized = legacy_payload_too_large_entry();
            let command = match &oversized.payload {
                EntryPayload::Normal(command) => command.clone(),
                _ => unreachable!("capped CAS fixture is a normal command"),
            };
            let entries = vec![membership_entry(), oversized];
            append_logs_sync(&conn, identity(), &entries).expect("append retained legacy log");
            let applied = apply_entries_sync(&conn, identity(), &caps, entries)
                .expect("apply retained legacy payload rejection");
            assert!(matches!(
                applied.responses.as_slice(),
                [
                    _,
                    SessionConsensusResponse {
                        result: Err(StoreError::PayloadTooLarge {
                            actual: 1_048_577,
                            max: 1_048_576,
                        }),
                        ..
                    }
                ]
            ));
            (command, applied.responses[1].clone())
        };
        drop(backend);

        let conn = Connection::open(path).expect("open stopped legacy database");
        let mut frozen_entry: serde_json::Value = conn
            .query_row(
                "SELECT entry_json FROM consensus_log WHERE log_index = 1",
                [],
                |row| row.get(0),
            )
            .map(|encoded: Vec<u8>| {
                serde_json::from_slice(&encoded).expect("decode frozen legacy log entry")
            })
            .expect("read retained legacy log entry");
        frozen_entry
            .as_object_mut()
            .expect("entry JSON object")
            .get_mut("payload")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|payload| payload.get_mut("Normal"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("normal command JSON object")
            .remove("admission_revision")
            .expect("frozen command has admission revision before omission");
        conn.execute(
            "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 1",
            [serde_json::to_vec(&frozen_entry).expect("encode frozen legacy log entry")],
        )
        .expect("remove revision from retained legacy log");
        downgrade_to_immediate_predecessor_fixture_sync(&conn)
            .expect("install exact frozen predecessor schema");
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, response_json) VALUES (?1, ?2, ?3, ?4)",
            params![
                command.request_id.as_bytes(),
                epoch_i64(identity()).expect("identity epoch"),
                payload_digest(&command).expect("legacy payload digest").as_slice(),
                encode_json(&response).expect("encode frozen legacy response"),
            ],
        )
        .expect("seed frozen legacy outcome");
        assert!(
            is_immediate_predecessor_schema(&conn).expect("classify frozen predecessor"),
            "fixture must remain the exact immediate predecessor manifest"
        );
        command
    }

    fn assert_file_backed_legacy_outcome_requires_recovery_without_repair(path: &std::path::Path) {
        let before = consensus_reopen_evidence(path);
        let backend = SqliteSessionBackend::open(path).expect("open frozen local database");
        let conn = backend.conn.blocking_lock();
        assert_eq!(
            initialize_schema(&conn, identity(), &expected_members()),
            Err(SessionConsensusStorageError::RecoveryRequired),
            "unqualified legacy replay state must require operator recovery"
        );
        drop(conn);
        drop(backend);
        assert_eq!(
            consensus_reopen_evidence(path),
            before,
            "failed legacy migration must not publish a partial schema repair"
        );
    }

    #[test]
    fn file_backed_retained_legacy_payload_too_large_migrates_then_supports_duplicate_marker_and_follower(
    ) {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory
            .path()
            .join("frozen-retained-payload-too-large.sqlite");
        let legacy_command = seed_file_backed_frozen_legacy_payload_too_large(&path);

        let backend = SqliteSessionBackend::open(&path).expect("open frozen predecessor");
        let caps = backend.consensus_capabilities();
        {
            let conn = backend.conn.blocking_lock();
            initialize_schema(&conn, identity(), &expected_members())
                .expect("complete retained payload rejection migrates");
            let (_, migrated) = read_outcome_sync(&conn, identity(), legacy_command.request_id)
                .expect("read migrated receipt")
                .expect("migrated payload rejection receipt");
            assert!(matches!(
                migrated.result,
                Err(StoreError::PayloadTooLarge {
                    actual: 1_048_577,
                    max: 1_048_576,
                })
            ));
            assert_eq!(
                read_log_range_sync(&conn, identity(), 0, None, None)
                    .expect("read full retained prefix")
                    .iter()
                    .map(|entry| entry.log_id.index)
                    .collect::<Vec<_>>(),
                vec![0, 1],
            );
            assert_eq!(
                read_limited_log_range_sync(&conn, identity(), 0, 2, 1)
                    .expect("read limited retained prefix")
                    .iter()
                    .map(|entry| entry.log_id.index)
                    .collect::<Vec<_>>(),
                vec![0],
            );

            let duplicate = Entry {
                log_id: log_id(2),
                payload: EntryPayload::Normal(legacy_command.clone()),
            };
            append_logs_sync(&conn, identity(), std::slice::from_ref(&duplicate))
                .expect("follower appends duplicate legacy command");
            let duplicate_applied = apply_entries_sync(&conn, identity(), &caps, vec![duplicate])
                .expect("duplicate retained outcome applies idempotently");
            assert_eq!(
                duplicate_applied.responses.as_slice(),
                std::slice::from_ref(&migrated)
            );

            let marker = Entry {
                log_id: log_id(3),
                payload: EntryPayload::Normal(DurableSessionConsensusCommand::current(
                    SessionConsensusCommand {
                    schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                    identity: identity(),
                    request_id: SessionConsensusRequestId::from_bytes(
                        crate::consensus::SESSION_CONSENSUS_COMMAND_ADMISSION_CUTOVER_REQUEST_ID,
                    ),
                    logical_time: crate::consensus::types::command_admission_cutover_logical_time(),
                    intent: SessionMutationIntent::AdvanceLogicalTime,
                },
                )),
            };
            append_logs_sync(&conn, identity(), std::slice::from_ref(&marker))
                .expect("append current admission marker");
            apply_entries_sync(&conn, identity(), &caps, vec![marker])
                .expect("apply current admission marker");
            assert_eq!(
                read_command_admission_sync(&conn, identity())
                    .expect("read committed admission marker")
                    .strict_activation_index,
                4,
            );

            let follower = with_current_admission_revision(topology_entry_at(
                4,
                0xE4,
                SessionMutationIntent::AdvanceLogicalTime,
            ));
            append_logs_sync(&conn, identity(), std::slice::from_ref(&follower))
                .expect("follower appends current command after marker");
            let follower_applied = apply_entries_sync(&conn, identity(), &caps, vec![follower])
                .expect("follower applies current command after marker");
            assert!(matches!(
                follower_applied.responses.as_slice(),
                [SessionConsensusResponse {
                    result: Ok(SessionMutationOutcome::Unit),
                    sequence: 3,
                    raft_log_index: 4,
                    ..
                }]
            ));
        }
        drop(backend);

        let reopened = SqliteSessionBackend::open(&path).expect("restart migrated predecessor");
        let conn = reopened.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members())
            .expect("restart validates migrated receipt chain");
        assert!(
            read_command_admission_sync(&conn, identity())
                .expect("read restarted admission boundary")
                .cutover_committed
        );
    }

    #[test]
    fn file_backed_legacy_payload_too_large_migration_rejects_swizzled_or_compacted_history_without_repair(
    ) {
        for case in ["unit", "state-dependent-error", "missing-log"] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory
                .path()
                .join(format!("frozen-legacy-{case}.sqlite"));
            let command = seed_file_backed_frozen_legacy_payload_too_large(&path);
            let conn = Connection::open(&path).expect("open frozen predecessor");
            match case {
                "unit" | "state-dependent-error" => {
                    let result = if case == "unit" {
                        Ok(SessionMutationOutcome::Unit)
                    } else {
                        Err(StoreError::StaleFence)
                    };
                    let digest = command
                        .calculate_applied_result_digest(
                            1,
                            SessionConsensusEntryDigest::GENESIS,
                            timestamp(1),
                            1,
                            &result,
                        )
                        .expect("syntactically valid swizzled legacy digest");
                    let response = SessionConsensusResponse {
                        result,
                        sequence: 1,
                        digest: Some(digest),
                        logical_time: Some(timestamp(1)),
                        raft_log_index: 1,
                    };
                    conn.execute(
                        "UPDATE consensus_request_outcomes SET response_json = ?1",
                        [encode_json(&response).expect("encode swizzled legacy response")],
                    )
                    .expect("replace frozen legacy response");
                }
                "missing-log" => {
                    conn.execute("DELETE FROM consensus_log WHERE log_index = 1", [])
                        .expect("compact retained command log");
                }
                _ => unreachable!("enumerated legacy migration case"),
            }
            drop(conn);
            assert_file_backed_legacy_outcome_requires_recovery_without_repair(&path);
        }
    }

    #[test]
    fn file_backed_nonempty_immediate_predecessor_requires_operator_recovery() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory
            .path()
            .join("immediate-predecessor-outcome.sqlite");
        seed_file_backed_consensus(&path);
        let conn = Connection::open(&path).expect("open stopped database");
        append_logs_sync(&conn, identity(), &[membership_entry()])
            .expect("retain a predecessor command log");
        downgrade_to_immediate_predecessor_fixture_sync(&conn)
            .expect("install exact predecessor schema");
        // This response is syntactically valid, while the retained command log
        // is complete. It is still semantically untrusted: a legacy digest
        // binds only the command, so no retained log can prove the result was
        // actually produced by that command.
        let response = serde_json::to_vec(&SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::Unit),
            sequence: 1,
            digest: Some(SessionConsensusEntryDigest::from_bytes([0x93; 32])),
            logical_time: Some(timestamp(1)),
            raft_log_index: 0,
        })
        .expect("encode syntactically valid swizzled response");
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, response_json) VALUES (?1, 1, ?2, ?3)",
            params![[0x91_u8; 16].as_slice(), [0x92_u8; 32].as_slice(), response],
        )
        .expect("insert legacy replay outcome");
        drop(conn);

        let backend = SqliteSessionBackend::open(&path).expect("open predecessor database");
        let conn = backend.conn.blocking_lock();
        assert_eq!(
            initialize_schema(&conn, identity(), &expected_members()),
            Err(SessionConsensusStorageError::RecoveryRequired),
            "normal reopen must not promote a legacy replay result into a v2 receipt"
        );
    }
}
