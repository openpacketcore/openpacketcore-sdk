//! Explicit operator boundary for legacy or otherwise unprovable replica forks.
//!
//! Openraft remains the only runtime consensus authority. This module can
//! inspect drained, file-backed replicas and replace explicitly selected
//! replicas from one immutable checkpoint, but it never elects a branch, commits a
//! log entry, or serves a network protocol. Cluster-wide lease invalidation is
//! completed later by a normal Openraft client write.

mod sqlite;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use hmac::{Hmac, Mac};
use opc_config_model::{RequestId, TransportType, TrustedPrincipal};
use opc_consensus::engine::LogId;
use opc_mgmt_audit::{
    AuditEvent, AuditOperation, AuditOutcome, AuditReasonCode, AuditSink, AuditTxId, SchemaNodePath,
};
use opc_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::consensus::snapshot::{SNAPSHOT_DATABASE_MAX_BYTES, SNAPSHOT_ENVELOPE_MAX_BYTES};
use crate::consensus::storage::{LiveTerminalRecoveryHandoffGate, SessionConsensusStorageError};
use crate::consensus::{
    OperatorRecoveryCommitError, OperatorRecoveryCommitRequest, SessionConsensusIdentity,
    SessionConsensusNodeId, SessionConsensusRequestId,
};
use crate::topology::{
    ReplicaBackingIdentity, ReplicaId, ValidatedQuorumTopology, QUORUM_TOPOLOGY_MAX_MEMBERS,
};
use crate::ConsensusSessionStore;

use self::sqlite::{
    acquire_finalization_pins, backup_and_reset_replica, classify_finalization_pins,
    clear_fleet_latches_pinned, inspect_replica, legacy_finalization_predecessor,
    record_rejoined_with_terminal_proof, recovery_v2_intent_from_plan, replica_has_recovery_latch,
    resume_audit_state, resume_execution_state, revalidate_finalization_pins,
    revalidate_finalization_pins_after_terminal_consumed, seal_plan,
    set_fleet_latches_audit_pending, set_fleet_latches_audit_pending_pinned, verify_plan_seal,
    FinalizationTransitionState, InspectionInput, ResetInput,
};

const RECOVERY_PLAN_VERSION: u16 = 4;
const RECOVERY_PATH: &str = "/opc-session-store:legacy-recovery";
const LEGACY_ACKNOWLEDGEMENT: &str = "ACKNOWLEDGE-UNPROVEN-LEGACY-BRANCH-DISCARD";
const PRINCIPAL_DESCRIPTOR_MAX_BYTES: usize = 2_048;
/// Recovery walks selected SQLite values through several bounded validation
/// and digest passes. Keep this finite multiplier tied to the same accepted
/// physical extent instead of leaving a smaller stale logical-ledger limit.
const RECOVERY_DEFAULT_VALUE_SCAN_MULTIPLIER: u64 = 8;
const RECOVERY_DEFAULT_MAX_TOTAL_VALUE_BYTES: u64 =
    SNAPSHOT_DATABASE_MAX_BYTES * RECOVERY_DEFAULT_VALUE_SCAN_MULTIPLIER;
// These are protocol capacities, not caller-selected inspection policy. V2
// apply recomputes the invariant digest under these same bounds, so accepting
// a wider workflow here would create a deterministic finalization wedge.
const RECOVERY_V2_INVARIANT_PROTOCOL_MAX_ROWS: u64 = 10_000_000;
const RECOVERY_V2_INVARIANT_PROTOCOL_MAX_VALUE_BYTES: u64 = 16 * 1024 * 1024;
const RECOVERY_V2_INVARIANT_PROTOCOL_MAX_TOTAL_VALUE_BYTES: u64 =
    SNAPSHOT_DATABASE_MAX_BYTES * RECOVERY_DEFAULT_VALUE_SCAN_MULTIPLIER;

/// Purpose-separated integrity key for plans, workflow journals, and backups.
///
/// Key material is zeroized on drop and never enters a plan, backup, snapshot,
/// audit event, tracing field, or Openraft command.
#[derive(Clone)]
pub struct RecoveryIntegrityKey(Zeroizing<[u8; 32]>);

impl RecoveryIntegrityKey {
    /// Construct a non-zero recovery integrity key.
    pub fn new(mut bytes: [u8; 32]) -> Result<Self, RecoveryError> {
        if bytes.iter().all(|byte| *byte == 0) {
            bytes.zeroize();
            return Err(RecoveryError::InvalidRequest);
        }
        let key = Self(Zeroizing::new(bytes));
        bytes.zeroize();
        Ok(key)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RecoveryIntegrityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryIntegrityKey(<redacted>)")
    }
}

/// Fixed-width, redaction-safe digest used to bind recovery evidence.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecoveryDigest([u8; 32]);

impl RecoveryDigest {
    /// Reconstruct a digest from its fixed-width representation.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Fixed-width digest bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Lowercase hexadecimal representation for exact operator confirmation.
    pub fn to_hex(self) -> String {
        crate::hex::encode_lower(&self.0)
    }
}

/// Shared canonical V2 predecessor projection for consensus apply.  Its
/// implementation remains beside offline recovery inspection so both paths
/// use the identical row encoding and legacy-lease normalization.
pub(crate) fn recovery_v2_invariant_state_digest_for_apply(
    conn: &rusqlite::Connection,
) -> Result<[u8; 32], RecoveryError> {
    sqlite::recovery_v2_invariant_state_digest_for_apply(conn)
}

impl fmt::Debug for RecoveryDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecoveryDigest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for RecoveryDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Explicit administrative action subject to default-deny authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecoveryAction {
    /// Read-only inspection and deterministic plan construction.
    Inspect,
    /// Backup, quarantine, and reset an explicit target set.
    ResetReplicas,
    /// Commit cluster-wide recovery fencing through Openraft.
    Finalize,
}

/// Redaction-safe scope passed to the recovery authorizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryAuthorizationScope {
    action: RecoveryAction,
    plan_digest: Option<RecoveryDigest>,
    unproven_legacy_branch: bool,
    target_count: usize,
}

impl RecoveryAuthorizationScope {
    /// Requested action.
    pub const fn action(self) -> RecoveryAction {
        self.action
    }

    /// Exact plan digest for mutating actions.
    pub const fn plan_digest(self) -> Option<RecoveryDigest> {
        self.plan_digest
    }

    /// Whether the request discards an unproven legacy branch.
    pub const fn unproven_legacy_branch(self) -> bool {
        self.unproven_legacy_branch
    }

    /// Number of explicitly enumerated target replicas.
    pub const fn target_count(self) -> usize {
        self.target_count
    }
}

/// Payload-free authorization denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("operator recovery authorization denied")]
pub struct RecoveryAuthorizationDenied;

/// Default-deny policy port for privileged recovery operations.
pub trait RecoveryAuthorizer: Send + Sync {
    /// Authorize an already-authenticated management principal for one scope.
    fn authorize(
        &self,
        principal: &TrustedPrincipal,
        scope: RecoveryAuthorizationScope,
    ) -> Result<(), RecoveryAuthorizationDenied>;
}

/// Typed operator-recovery alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecoveryAlarm {
    /// A replica is fenced pending explicit operator recovery.
    RecoveryRequired,
    /// Recovery stopped because evidence or authority changed.
    RecoveryAborted,
    /// A recovery side effect completed but its success audit is pending.
    AuditPending,
}

impl RecoveryAlarm {
    /// Stable low-cardinality alarm code.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::RecoveryRequired => "operator_recovery_required",
            Self::RecoveryAborted => "operator_recovery_aborted",
            Self::AuditPending => "operator_recovery_audit_pending",
        }
    }
}

/// Durable workflow state suitable for readiness and metrics surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryExecutionState {
    /// A deterministic read-only plan exists; no replica state changed.
    Planned,
    /// The selected replica has a verified, integrity-protected backup.
    BackupVerified,
    /// The selected replica was reset and must not serve before finalization.
    AwaitingEpochCommit,
    /// Openraft committed the recovery epoch and credential/fence invalidation.
    EpochCommitted,
    /// A fresh Openraft readiness barrier completed after finalization.
    Rejoined,
    /// The mutation completed but a required success audit must be retried.
    AuditPending,
}

impl RecoveryExecutionState {
    /// Stable readiness/metric code.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::BackupVerified => "backup_verified",
            Self::AwaitingEpochCommit => "awaiting_epoch_commit",
            Self::EpochCommitted => "epoch_committed",
            Self::Rejoined => "rejoined",
            Self::AuditPending => "audit_pending",
        }
    }
}

/// Redaction-safe observation emitted at each durable workflow transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverySignal {
    state: RecoveryExecutionState,
    alarm: Option<RecoveryAlarm>,
}

impl RecoverySignal {
    /// Durable recovery state.
    pub const fn state(self) -> RecoveryExecutionState {
        self.state
    }

    /// Alarm to raise or clear at this transition.
    pub const fn alarm(self) -> Option<RecoveryAlarm> {
        self.alarm
    }
}

/// Observability port for readiness, metrics, and alarm adapters.
pub trait RecoveryObserver: Send + Sync {
    /// Publish one low-cardinality, identifier-free transition.
    fn observe(&self, signal: RecoverySignal);
}

/// Authenticated request context. Authentication is completed by the caller's
/// mTLS, SSH public-key, or trusted local management boundary before creation.
#[derive(Clone)]
pub struct RecoveryContext {
    principal: TrustedPrincipal,
    request_id: RequestId,
    transport: TransportType,
}

impl RecoveryContext {
    /// Bind an authenticated principal to a management correlation ID.
    pub fn new(
        principal: TrustedPrincipal,
        request_id: RequestId,
        transport: TransportType,
    ) -> Result<Self, RecoveryError> {
        let descriptor = opc_mgmt_audit::principal_descriptor(&principal);
        if descriptor.is_empty()
            || descriptor.len() > PRINCIPAL_DESCRIPTOR_MAX_BYTES
            || descriptor.chars().any(char::is_control)
        {
            return Err(RecoveryError::InvalidRequest);
        }
        Ok(Self {
            principal,
            request_id,
            transport,
        })
    }
}

impl fmt::Debug for RecoveryContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryContext(<redacted>)")
    }
}

/// One drained file-backed replica supplied to inspection and execution.
#[derive(Clone)]
pub struct RecoveryReplica {
    replica_id: ReplicaId,
    backing_identity: ReplicaBackingIdentity,
    admitted_identity: SessionConsensusIdentity,
    database_path: PathBuf,
    snapshot_directory: PathBuf,
}

impl RecoveryReplica {
    /// Build one replica input from an already validated consensus topology.
    ///
    /// The logical ID, opaque backing identity, and consensus configuration
    /// are copied from the admitted member; callers cannot substitute a
    /// recovery-only backing identity. Paths are canonicalized and bound into
    /// the plan during inspection; raw path text is never included in plan
    /// output.
    pub fn from_topology(
        topology: &ValidatedQuorumTopology,
        replica_id: ReplicaId,
        database_path: impl Into<PathBuf>,
        snapshot_directory: impl Into<PathBuf>,
    ) -> Result<Self, RecoveryError> {
        let admitted_identity = topology
            .consensus_identity()
            .ok_or(RecoveryError::InvalidRequest)?;
        let member = topology
            .members()
            .iter()
            .find(|member| member.replica_id() == &replica_id)
            .ok_or(RecoveryError::InvalidRequest)?;
        Ok(Self::new_bound(
            replica_id,
            member.backing_identity().clone(),
            admitted_identity,
            database_path,
            snapshot_directory,
        ))
    }

    fn new_bound(
        replica_id: ReplicaId,
        backing_identity: ReplicaBackingIdentity,
        admitted_identity: SessionConsensusIdentity,
        database_path: impl Into<PathBuf>,
        snapshot_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            replica_id,
            backing_identity,
            admitted_identity,
            database_path: database_path.into(),
            snapshot_directory: snapshot_directory.into(),
        }
    }

    /// Logical replica ID used to match later execution inputs.
    pub const fn replica_id(&self) -> &ReplicaId {
        &self.replica_id
    }

    /// Opaque physical backing identity admitted for this vote.
    pub const fn backing_identity(&self) -> &ReplicaBackingIdentity {
        &self.backing_identity
    }
}

impl fmt::Debug for RecoveryReplica {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryReplica(<redacted>)")
    }
}

/// Caller-approved inspection and backup work bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryLimits {
    max_database_bytes: u64,
    max_snapshot_bytes: u64,
    max_rows: u64,
    max_value_bytes: u64,
    max_total_value_bytes: u64,
    max_duration: Duration,
}

impl RecoveryLimits {
    /// Validate explicit non-zero bounds.
    pub fn try_new(
        max_database_bytes: u64,
        max_snapshot_bytes: u64,
        max_rows: u64,
        max_value_bytes: u64,
    ) -> Result<Self, RecoveryError> {
        if max_database_bytes == 0
            || max_database_bytes > SNAPSHOT_DATABASE_MAX_BYTES
            || max_snapshot_bytes == 0
            || max_snapshot_bytes > SNAPSHOT_ENVELOPE_MAX_BYTES
            || max_rows == 0
            || max_rows > RECOVERY_V2_INVARIANT_PROTOCOL_MAX_ROWS
            || max_value_bytes == 0
            || max_value_bytes > i64::MAX as u64
            || max_value_bytes > RECOVERY_V2_INVARIANT_PROTOCOL_MAX_VALUE_BYTES
        {
            return Err(RecoveryError::InvalidRequest);
        }
        let max_total_value_bytes = max_database_bytes
            .checked_mul(RECOVERY_DEFAULT_VALUE_SCAN_MULTIPLIER)
            .ok_or(RecoveryError::InvalidRequest)?;
        Ok(Self {
            max_database_bytes,
            max_snapshot_bytes,
            max_rows,
            max_value_bytes,
            max_total_value_bytes,
            max_duration: Duration::from_secs(30),
        })
    }

    /// Validate explicit bounds including cumulative read bytes and wall time.
    pub fn try_new_with_work_budget(
        max_database_bytes: u64,
        max_snapshot_bytes: u64,
        max_rows: u64,
        max_value_bytes: u64,
        max_total_value_bytes: u64,
        max_duration: Duration,
    ) -> Result<Self, RecoveryError> {
        let mut limits = Self::try_new(
            max_database_bytes,
            max_snapshot_bytes,
            max_rows,
            max_value_bytes,
        )?;
        // A caller may make recovery work stricter, but cannot detach its
        // cumulative scan allowance from the checked database extent admitted
        // above. This retains the finite physical-envelope policy for every
        // constructor, not only `Default`.
        if max_total_value_bytes == 0
            || max_total_value_bytes > limits.max_total_value_bytes
            || max_total_value_bytes > RECOVERY_V2_INVARIANT_PROTOCOL_MAX_TOTAL_VALUE_BYTES
            || max_duration.is_zero()
        {
            return Err(RecoveryError::InvalidRequest);
        }
        limits.max_total_value_bytes = max_total_value_bytes;
        limits.max_duration = max_duration;
        Ok(limits)
    }

    /// Maximum accepted SQLite file size.
    pub const fn max_database_bytes(self) -> u64 {
        self.max_database_bytes
    }

    /// Maximum accepted authoritative snapshot size.
    pub const fn max_snapshot_bytes(self) -> u64 {
        self.max_snapshot_bytes
    }

    /// Maximum rows hashed while deriving complete evidence.
    pub const fn max_rows(self) -> u64 {
        self.max_rows
    }

    /// Maximum bytes accepted from one persisted value.
    pub const fn max_value_bytes(self) -> u64 {
        self.max_value_bytes
    }

    /// Maximum cumulative persisted value bytes read during one inspection.
    pub const fn max_total_value_bytes(self) -> u64 {
        self.max_total_value_bytes
    }

    /// Maximum wall-clock duration of one replica inspection.
    pub const fn max_duration(self) -> Duration {
        self.max_duration
    }
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            max_database_bytes: SNAPSHOT_DATABASE_MAX_BYTES,
            max_snapshot_bytes: SNAPSHOT_ENVELOPE_MAX_BYTES,
            max_rows: 10_000_000,
            max_value_bytes: 16 * 1024 * 1024,
            max_total_value_bytes: RECOVERY_DEFAULT_MAX_TOTAL_VALUE_BYTES,
            max_duration: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
#[test]
fn default_recovery_limits_share_the_snapshot_physical_envelope() {
    let limits = RecoveryLimits::default();
    assert_eq!(limits.max_database_bytes(), SNAPSHOT_DATABASE_MAX_BYTES);
    assert_eq!(limits.max_snapshot_bytes(), SNAPSHOT_ENVELOPE_MAX_BYTES);
    assert_eq!(
        limits.max_total_value_bytes(),
        SNAPSHOT_DATABASE_MAX_BYTES * RECOVERY_DEFAULT_VALUE_SCAN_MULTIPLIER
    );
    assert_eq!(limits.max_duration(), Duration::from_secs(30));
    assert!(RecoveryLimits::try_new(
        SNAPSHOT_DATABASE_MAX_BYTES + 1,
        SNAPSHOT_ENVELOPE_MAX_BYTES,
        1,
        1,
    )
    .is_err());
    assert!(RecoveryLimits::try_new(
        SNAPSHOT_DATABASE_MAX_BYTES,
        SNAPSHOT_ENVELOPE_MAX_BYTES + 1,
        1,
        1,
    )
    .is_err());
    assert!(RecoveryLimits::try_new_with_work_budget(
        SNAPSHOT_DATABASE_MAX_BYTES,
        SNAPSHOT_ENVELOPE_MAX_BYTES,
        1,
        1,
        RECOVERY_DEFAULT_MAX_TOTAL_VALUE_BYTES + 1,
        Duration::from_secs(1),
    )
    .is_err());
    assert!(RecoveryLimits::try_new(
        SNAPSHOT_DATABASE_MAX_BYTES,
        SNAPSHOT_ENVELOPE_MAX_BYTES,
        RECOVERY_V2_INVARIANT_PROTOCOL_MAX_ROWS + 1,
        1,
    )
    .is_err());
    assert!(RecoveryLimits::try_new(
        SNAPSHOT_DATABASE_MAX_BYTES,
        SNAPSHOT_ENVELOPE_MAX_BYTES,
        1,
        RECOVERY_V2_INVARIANT_PROTOCOL_MAX_VALUE_BYTES + 1,
    )
    .is_err());
}

/// Persisted replica format found during inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryReplicaFormat {
    /// Current Openraft-owned SQLite state.
    Openraft,
    /// Pre-Openraft standalone/custom replication state with no commit proof.
    LegacyUnproven,
}

/// Persisted consensus authority model authenticated during offline recovery.
///
/// This deliberately does not deserialize an unknown value as a permissive
/// default.  Recovery must not infer whether an artifact needs immutable
/// fs-verity handling from its pathname or a target replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAuthorityProfile {
    /// The ordinary dynamic-membership authority model.
    Dynamic,
    /// The permanently fixed quorum authority model.
    FixedImmutable,
}

/// Persisted placement policy coupled to fixed recovery authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFixedPlacementPolicy {
    /// Independent failure domains are required for the resilience claim.
    RequireIndependentFailureDomains,
    /// An explicit reduced-resilience placement claim is permitted.
    AllowReducedResilience,
}

/// Redaction-safe evidence for one completely inspected replica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReplicaEvidence {
    replica_token: RecoveryDigest,
    backing_identity: RecoveryDigest,
    path_binding: RecoveryDigest,
    file_identity: RecoveryDigest,
    format: RecoveryReplicaFormat,
    cluster_digest: Option<RecoveryDigest>,
    configuration_digest: Option<RecoveryDigest>,
    configuration_epoch: Option<u64>,
    authority_profile: RecoveryAuthorityProfile,
    fixed_placement_policy: Option<RecoveryFixedPlacementPolicy>,
    /// Exact inode commitment for the snapshot selected by this replica's
    /// current checkpoint, when one exists.  It is distinct from the
    /// envelope checksum so byte-identical pathname replacement cannot cross
    /// plan → checkpoint handoff.
    current_snapshot_identity: Option<RecoveryDigest>,
    recovery_epoch: u64,
    /// Exact durable plan digest completed at `recovery_epoch`.  This is
    /// separate evidence from the epoch: a voter at the same epoch but with
    /// another campaign's plan must never inherit this campaign's terminal
    /// readiness record.
    last_plan_digest: RecoveryDigest,
    pending_recovery_epoch: Option<u64>,
    pending_plan_digest: Option<RecoveryDigest>,
    /// Exact V2 Raft identity that committed this recovery epoch.  This is
    /// separate from the current head: later ordinary commands may advance
    /// the head without weakening the proof of the recovery effect.
    finalize_log_id: Option<LogId<SessionConsensusNodeId>>,
    watch_cursor_invalidation_floor: u64,
    application_sequence: u64,
    /// Exact state-machine digest at the inspected predecessor.  This is
    /// deliberately distinct from the offline logical-state digest: V2 apply
    /// must reject a queued normal command even when its sequence remains
    /// below a fleet-wide recovery high-water.
    machine_last_digest: RecoveryDigest,
    /// Exact state-machine logical time at the inspected predecessor.
    machine_logical_time: Option<Timestamp>,
    watch_sequence: u64,
    /// Domain-separated commitment of the persisted identity, membership
    /// scope, authority policy, and protected-roster state.  It is carried
    /// into V2 so untouched voters cannot inherit a recovery command after a
    /// locally valid but different authority transition.
    authority_commitment: RecoveryDigest,
    /// Exact durable committed Raft identity. The legacy numeric projection
    /// remains for diagnostics, but never authorizes a plan transition.
    committed_log_id: Option<LogId<SessionConsensusNodeId>>,
    /// Canonical digest of the exact committed predecessor when that physical
    /// row is a retained Membership entry.  `None` is explicit evidence that
    /// inspection did not retain a Membership at this full LogId; V2 apply
    /// independently re-proves that absence against its own descriptors.
    predecessor_bootstrap_membership_digest: Option<RecoveryDigest>,
    /// Exact durable applied Raft identity.
    applied_log_id: Option<LogId<SessionConsensusNodeId>>,
    /// Exact physical local Raft head, including an unapplied suffix.
    local_head_log_id: Option<LogId<SessionConsensusNodeId>>,
    committed_index: Option<u64>,
    applied_index: Option<u64>,
    local_head_index: Option<u64>,
    branch_digest: RecoveryDigest,
    fence_high_water: u64,
    credential_high_water: u64,
    logical_state_digest: RecoveryDigest,
    /// Projection of logical state which excludes only V2's deliberate lease
    /// activation and allocator changes.  It binds the application, lease
    /// identity, and every other logical byte across finalization without
    /// treating V2's own transactional effects as corruption.
    recovery_v2_invariant_state_digest: RecoveryDigest,
    protected_roster_digest: RecoveryDigest,
}

/// Exact current-format predecessor captured only after a legacy fleet has
/// been bootstrapped under the retained finalization descriptors.  A legacy
/// recovery plan deliberately contains no OpenRaft predecessor; this MACed
/// workflow capsule makes the one admitted bootstrap state durable before a
/// V2 finalize entry can be proposed or retried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FinalizationPredecessorCapsule {
    pub(super) recovery_epoch: u64,
    pub(super) last_plan_digest: RecoveryDigest,
    pub(super) watch_cursor_invalidation_floor: u64,
    pub(super) baseline_log_id: LogId<SessionConsensusNodeId>,
    pub(super) application_sequence: u64,
    pub(super) machine_last_digest: RecoveryDigest,
    pub(super) machine_logical_time: Option<Timestamp>,
    pub(super) watch_sequence: u64,
    pub(super) authority_commitment: RecoveryDigest,
    pub(super) recovery_v2_invariant_state_digest: RecoveryDigest,
    /// Canonical JSON digest of the exact predecessor Membership payload when
    /// that row is retained. It binds the physical entry in addition to the
    /// scope covered by `authority_commitment`; this is not legacy-only.
    pub(super) bootstrap_membership_digest: Option<RecoveryDigest>,
    /// The fixed legacy bootstrap Membership may precede the V2 predecessor
    /// (OpenRaft normally follows it with a committed Blank).  Preserve that
    /// physical authority separately: it must not be overloaded into the V2
    /// predecessor commitment, whose `None` is meaningful for that Blank.
    #[serde(default)]
    pub(super) legacy_bootstrap_membership: Option<LegacyBootstrapMembershipCapsule>,
}

/// Exact legacy Membership retained as authority evidence when it is not the
/// immediate V2 predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LegacyBootstrapMembershipCapsule {
    pub(super) log_id: LogId<SessionConsensusNodeId>,
    pub(super) digest: RecoveryDigest,
}

impl RecoveryReplicaEvidence {
    /// Stable digest of the logical replica ID, not its raw text.
    pub const fn replica_token(&self) -> RecoveryDigest {
        self.replica_token
    }

    /// Persisted format.
    pub const fn format(&self) -> RecoveryReplicaFormat {
        self.format
    }

    /// Cluster identity digest for current-format replicas.
    pub const fn cluster_digest(&self) -> Option<RecoveryDigest> {
        self.cluster_digest
    }

    /// Configuration digest for current-format replicas.
    pub const fn configuration_digest(&self) -> Option<RecoveryDigest> {
        self.configuration_digest
    }

    /// Configuration epoch for current-format replicas.
    pub const fn configuration_epoch(&self) -> Option<u64> {
        self.configuration_epoch
    }

    /// Persisted authority profile for this inspected replica.
    pub const fn authority_profile(&self) -> RecoveryAuthorityProfile {
        self.authority_profile
    }

    /// Placement policy authenticated with fixed authority.
    pub const fn fixed_placement_policy(&self) -> Option<RecoveryFixedPlacementPolicy> {
        self.fixed_placement_policy
    }

    /// Exact inode commitment for the current snapshot selected during
    /// inspection.
    pub const fn current_snapshot_identity(&self) -> Option<RecoveryDigest> {
        self.current_snapshot_identity
    }

    /// Durable operator-recovery epoch.
    pub const fn recovery_epoch(&self) -> u64 {
        self.recovery_epoch
    }

    /// Exact durable plan digest completed at the observed recovery epoch.
    pub const fn last_plan_digest(&self) -> RecoveryDigest {
        self.last_plan_digest
    }

    /// Exact persisted V2 finalization log identity, when this replica has
    /// completed a current-format operator recovery epoch.
    pub const fn finalize_log_id(&self) -> Option<LogId<SessionConsensusNodeId>> {
        self.finalize_log_id
    }

    /// Pending recovery epoch left by an incomplete exact workflow.
    pub const fn pending_recovery_epoch(&self) -> Option<u64> {
        self.pending_recovery_epoch
    }

    /// Pending exact plan digest, when recovery is incomplete.
    pub const fn pending_plan_digest(&self) -> Option<RecoveryDigest> {
        self.pending_plan_digest
    }

    /// Highest pre-recovery application-journal cursor invalidated by reset.
    pub const fn watch_cursor_invalidation_floor(&self) -> u64 {
        self.watch_cursor_invalidation_floor
    }

    /// Highest committed application sequence observed on this replica.
    pub const fn application_sequence(&self) -> u64 {
        self.application_sequence
    }

    /// Exact state-machine digest at the inspected predecessor.
    pub const fn machine_last_digest(&self) -> RecoveryDigest {
        self.machine_last_digest
    }

    /// Exact state-machine logical time at the inspected predecessor.
    pub const fn machine_logical_time(&self) -> Option<Timestamp> {
        self.machine_logical_time
    }

    /// Highest application-journal/watch sequence observed on this replica.
    pub const fn watch_sequence(&self) -> u64 {
        self.watch_sequence
    }

    /// Exact durable authority/membership/roster commitment at the inspected
    /// predecessor.
    pub const fn authority_commitment(&self) -> RecoveryDigest {
        self.authority_commitment
    }

    /// Full committed Raft identity sealed into the plan.
    pub const fn committed_log_id(&self) -> Option<LogId<SessionConsensusNodeId>> {
        self.committed_log_id
    }

    /// Full applied Raft identity sealed into the plan.
    pub const fn applied_log_id(&self) -> Option<LogId<SessionConsensusNodeId>> {
        self.applied_log_id
    }

    /// Full physical local-log head sealed into the plan.
    pub const fn local_head_log_id(&self) -> Option<LogId<SessionConsensusNodeId>> {
        self.local_head_log_id
    }

    /// Persisted committed Openraft index, when present.
    pub const fn committed_index(&self) -> Option<u64> {
        self.committed_index
    }

    /// Persisted applied Openraft index, when present.
    pub const fn applied_index(&self) -> Option<u64> {
        self.applied_index
    }

    /// Local log head, including an uncommitted tail.
    pub const fn local_head_index(&self) -> Option<u64> {
        self.local_head_index
    }

    /// Complete branch/checkpoint fingerprint.
    pub const fn branch_digest(&self) -> RecoveryDigest {
        self.branch_digest
    }

    /// Highest allocated or persisted fence observed.
    pub const fn fence_high_water(&self) -> u64 {
        self.fence_high_water
    }

    /// Highest allocated or persisted credential ID observed.
    pub const fn credential_high_water(&self) -> u64 {
        self.credential_high_water
    }

    /// Exact logical session-state digest, independent from Raft metadata.
    pub const fn logical_state_digest(&self) -> RecoveryDigest {
        self.logical_state_digest
    }

    /// Canonical digest of the protected roster layout, verifier root, and
    /// activated roster projections.
    pub const fn protected_roster_digest(&self) -> RecoveryDigest {
        self.protected_roster_digest
    }

    fn has_valid_authority_descriptor(&self) -> bool {
        matches!(
            (self.authority_profile, self.fixed_placement_policy),
            (RecoveryAuthorityProfile::Dynamic, None)
                | (RecoveryAuthorityProfile::FixedImmutable, Some(_))
        )
    }
}

/// Evidence basis under which one source may be selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryDecisionBasis {
    /// A strict majority independently persisted the exact committed branch.
    VerifiedCommittedMajority,
    /// No durable commit proof exists; an operator explicitly chooses a branch.
    ExplicitLegacyCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryPlanBody {
    version: u16,
    #[serde(
        default = "crate::SnapshotIntegrityPolicy::legacy",
        skip_serializing_if = "crate::SnapshotIntegrityPolicy::is_legacy"
    )]
    snapshot_integrity: crate::SnapshotIntegrityPolicy,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
    basis: RecoveryDecisionBasis,
    evidence: Vec<RecoveryReplicaEvidence>,
    source_token: RecoveryDigest,
    target_tokens: Vec<RecoveryDigest>,
    source_branch_digest: RecoveryDigest,
    source_authority_profile: RecoveryAuthorityProfile,
    source_fixed_placement_policy: Option<RecoveryFixedPlacementPolicy>,
    source_protected_roster_digest: RecoveryDigest,
    next_recovery_epoch: u64,
    application_sequence_high_water: u64,
    watch_sequence_high_water: u64,
    watch_cursor_invalidation_floor: u64,
    fence_high_water: u64,
    credential_high_water: u64,
}

/// Deterministic, redaction-safe, integrity-sealed recovery dry-run.
#[must_use = "a recovery plan must be explicitly confirmed before execution"]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPlan {
    body: RecoveryPlanBody,
    plan_digest: RecoveryDigest,
    seal: RecoveryDigest,
}

impl fmt::Debug for RecoveryPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryPlan")
            .field("basis", &self.body.basis)
            .field("replicas", &self.body.evidence.len())
            .field("plan_digest", &self.plan_digest)
            .field("next_recovery_epoch", &self.body.next_recovery_epoch)
            .finish()
    }
}

impl RecoveryPlan {
    /// Snapshot integrity policy authenticated by this recovery plan.
    pub const fn snapshot_integrity_policy(&self) -> crate::SnapshotIntegrityPolicy {
        self.body.snapshot_integrity
    }

    /// Exact plan digest used for operator confirmation and idempotency.
    pub const fn plan_digest(&self) -> RecoveryDigest {
        self.plan_digest
    }

    /// Evidence basis.
    pub const fn basis(&self) -> RecoveryDecisionBasis {
        self.body.basis
    }

    /// Completely inspected, identifier-free replica evidence.
    pub fn evidence(&self) -> &[RecoveryReplicaEvidence] {
        &self.body.evidence
    }

    /// Selected source branch digest.
    pub const fn source_branch_digest(&self) -> RecoveryDigest {
        self.body.source_branch_digest
    }

    /// Recovery epoch that finalization must commit.
    pub const fn next_recovery_epoch(&self) -> u64 {
        self.body.next_recovery_epoch
    }

    /// Stable digest of the explicitly selected source replica ID.
    pub const fn source_token(&self) -> RecoveryDigest {
        self.body.source_token
    }

    /// Stable digests of every explicitly selected target replica ID.
    pub fn target_tokens(&self) -> &[RecoveryDigest] {
        &self.body.target_tokens
    }

    /// Highest fence preserved across every inspected replica.
    pub const fn fence_high_water(&self) -> u64 {
        self.body.fence_high_water
    }

    /// Highest credential ID preserved across every inspected replica.
    pub const fn credential_high_water(&self) -> u64 {
        self.body.credential_high_water
    }

    /// Highest application sequence preserved across the admitted fleet.
    pub const fn application_sequence_high_water(&self) -> u64 {
        self.body.application_sequence_high_water
    }

    /// Highest watch sequence preserved across the admitted fleet.
    pub const fn watch_sequence_high_water(&self) -> u64 {
        self.body.watch_sequence_high_water
    }

    /// Fleet-wide cursor invalidation floor installed by this campaign.
    pub const fn watch_cursor_invalidation_floor(&self) -> u64 {
        self.body.watch_cursor_invalidation_floor
    }
}

/// Exact operator acknowledgement bound to one plan and source branch.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryConfirmation {
    plan_digest: RecoveryDigest,
    source_branch_digest: RecoveryDigest,
    legacy_acknowledgement: Option<String>,
}

impl RecoveryConfirmation {
    /// Confirm a majority-proven reset.
    pub const fn verified(plan: &RecoveryPlan) -> Self {
        Self {
            plan_digest: plan.plan_digest,
            source_branch_digest: plan.body.source_branch_digest,
            legacy_acknowledgement: None,
        }
    }

    /// Confirm destructive selection of an unproven legacy checkpoint.
    ///
    /// `acknowledgement` must exactly equal the fixed phrase returned by
    /// [`Self::required_legacy_acknowledgement`]. The plan and branch digests
    /// are also checked, so a confirmation cannot be replayed onto another
    /// decision.
    pub fn legacy(plan: &RecoveryPlan, acknowledgement: impl Into<String>) -> Self {
        Self {
            plan_digest: plan.plan_digest,
            source_branch_digest: plan.body.source_branch_digest,
            legacy_acknowledgement: Some(acknowledgement.into()),
        }
    }

    /// Fixed checkpoint-discard acknowledgement phrase.
    pub const fn required_legacy_acknowledgement() -> &'static str {
        LEGACY_ACKNOWLEDGEMENT
    }
}

impl fmt::Debug for RecoveryConfirmation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryConfirmation(<redacted>)")
    }
}

/// Result of a reset/finalization step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryExecutionReport {
    plan_digest: RecoveryDigest,
    state: RecoveryExecutionState,
}

impl RecoveryExecutionReport {
    /// Exact plan being resumed.
    pub const fn plan_digest(self) -> RecoveryDigest {
        self.plan_digest
    }

    /// Durable workflow state.
    pub const fn state(self) -> RecoveryExecutionState {
        self.state
    }
}

/// Consume a terminal handoff through the already-open local core.  A storage
/// transport failure is retryable; every identity, descriptor, namespace, or
/// snapshot validation failure is evidence corruption and must stay
/// fail-closed rather than being retried as ordinary consensus lag.
fn map_live_terminal_recovery_handoff_error(error: SessionConsensusStorageError) -> RecoveryError {
    match error {
        SessionConsensusStorageError::SnapshotIntegrityUnavailable => {
            RecoveryError::FileOperationFailed
        }
        SessionConsensusStorageError::BackendUnavailable => RecoveryError::ConsensusUnavailable,
        SessionConsensusStorageError::UnsupportedPlatform
        | SessionConsensusStorageError::RecoveryRequired
        | SessionConsensusStorageError::IdentityMismatch
        | SessionConsensusStorageError::SchemaVersionMismatch
        | SessionConsensusStorageError::CorruptState
        | SessionConsensusStorageError::InvalidIdentity => RecoveryError::BackupCorrupt,
    }
}

async fn acquire_live_terminal_recovery_handoff_gate(
    store: &ConsensusSessionStore,
) -> Result<LiveTerminalRecoveryHandoffGate, RecoveryError> {
    store
        .acquire_live_operator_recovery_terminal_handoff_gate()
        .await
        .map_err(map_live_terminal_recovery_handoff_error)
}

async fn consume_live_terminal_recovery_handoff(
    store: &ConsensusSessionStore,
    gate: &LiveTerminalRecoveryHandoffGate,
) -> Result<(), RecoveryError> {
    store
        .consume_live_operator_recovery_terminal_handoff_with_gate(gate)
        .await
        .map_err(map_live_terminal_recovery_handoff_error)
}

/// Coarse, redaction-safe recovery failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RecoveryError {
    /// A bound, member set, path, or selection was invalid.
    #[error("operator recovery request is invalid")]
    InvalidRequest,
    /// The active authorization policy denied the action.
    #[error("operator recovery authorization denied")]
    AuthorizationDenied,
    /// The required durable audit trail was unavailable.
    #[error("operator recovery audit is unavailable")]
    AuditUnavailable,
    /// A database could not be opened or read within the supplied bounds.
    #[error("operator recovery database is unavailable")]
    DatabaseUnavailable,
    /// A replica or snapshot failed structural or cryptographic validation.
    #[error("operator recovery replica state is corrupt")]
    CorruptReplica,
    /// Persisted identity does not match the requested cluster/configuration.
    #[error("operator recovery cluster identity does not match")]
    WrongCluster,
    /// No strict majority proves the selected current-format branch.
    #[error("operator recovery has insufficient commit authority")]
    InsufficientAuthority,
    /// Complete evidence exceeded an explicit work or size budget.
    #[error("operator recovery inspection budget was exceeded")]
    WorkLimitExceeded,
    /// The plan no longer matches the supplied replica set.
    #[error("operator recovery plan is stale")]
    StalePlan,
    /// Another sealed recovery workflow is already pending on a replica.
    #[error("another operator recovery workflow is already pending")]
    RecoveryInProgress,
    /// The selected source head changed after dry-run.
    #[error("operator recovery source changed after planning")]
    SourceChanged,
    /// A backup or workflow journal failed integrity verification.
    #[error("operator recovery backup integrity check failed")]
    BackupCorrupt,
    /// Explicit destructive checkpoint confirmation was absent.
    #[error("operator recovery requires explicit checkpoint confirmation")]
    ConfirmationRequired,
    /// Confirmation did not bind the exact plan and branch.
    #[error("operator recovery confirmation does not match the plan")]
    ConfirmationMismatch,
    /// Backup, atomic publication, or durable journal I/O failed.
    #[error("operator recovery durable file operation failed")]
    FileOperationFailed,
    /// Openraft could not commit recovery fencing through the exact membership.
    #[error("operator recovery Openraft finalization failed")]
    ConsensusUnavailable,
    /// The committed state rejected a stale/conflicting recovery epoch.
    #[error("operator recovery epoch was rejected")]
    RecoveryEpochRejected,
    /// A qualification failpoint interrupted the resumable workflow.
    #[cfg(test)]
    #[error("operator recovery qualification failpoint")]
    InjectedFailure,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryFinalizeFailpoint {
    BeforeEpochCommit,
    AfterEpochCommit,
    BeforeRejoinBarrier,
    AfterRejoinBarrier,
    /// Interrupt publication after this many exact Active -> PendingHandoff
    /// sidecars have been durably terminalized.  This models a process loss
    /// in the sequential fleet publication loop without consuming any live
    /// handoff.
    AfterTerminalizingSidecars(usize),
}

#[cfg(test)]
impl RecoveryFinalizeFailpoint {
    fn terminalized_sidecars(self) -> Option<usize> {
        match self {
            Self::AfterTerminalizingSidecars(count) => Some(count),
            Self::BeforeEpochCommit
            | Self::AfterEpochCommit
            | Self::BeforeRejoinBarrier
            | Self::AfterRejoinBarrier => None,
        }
    }
}

/// Authorized coordinator for deterministic inspection and explicit recovery.
pub struct LegacyForkRecovery<A, S, O> {
    authorizer: A,
    audit: S,
    observer: O,
    integrity_key: RecoveryIntegrityKey,
    snapshot_integrity: crate::SnapshotIntegrityPolicy,
}

impl<A, S, O> fmt::Debug for LegacyForkRecovery<A, S, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyForkRecovery(<redacted>)")
    }
}

impl<A, S, O> LegacyForkRecovery<A, S, O>
where
    A: RecoveryAuthorizer,
    S: AuditSink,
    O: RecoveryObserver,
{
    /// Construct a recovery boundary. No allow-all authorizer or best-effort
    /// audit default is provided for this security-critical workflow.
    pub fn new(authorizer: A, audit: S, observer: O, integrity_key: RecoveryIntegrityKey) -> Self {
        Self {
            authorizer,
            audit,
            observer,
            integrity_key,
            snapshot_integrity: crate::SnapshotIntegrityPolicy::FsVerity,
        }
    }

    /// Select the fixed-quorum snapshot policy for this recovery campaign.
    ///
    /// The choice is authenticated in its plan and workflow and must agree
    /// when executing/resuming. The default preserves the legacy strict
    /// fs-verity contract. Portable reads retain the same descriptor, content,
    /// membership, and destructive-confirmation checks.
    pub fn with_snapshot_integrity(mut self, policy: crate::SnapshotIntegrityPolicy) -> Self {
        self.snapshot_integrity = policy;
        self
    }

    /// Inspect all drained replicas and produce a deterministic no-mutation plan.
    ///
    /// Current-format branch selection requires a strict majority with the
    /// exact same committed evidence. Legacy selection never infers authority;
    /// the returned plan remains unusable until the operator supplies the
    /// destructive acknowledgement at execution time.
    #[allow(clippy::too_many_arguments)]
    pub fn plan(
        &self,
        context: &RecoveryContext,
        identity: SessionConsensusIdentity,
        expected_members: BTreeSet<SessionConsensusNodeId>,
        replicas: &[RecoveryReplica],
        source: &ReplicaId,
        targets: &[ReplicaId],
        basis: RecoveryDecisionBasis,
        limits: RecoveryLimits,
    ) -> Result<RecoveryPlan, RecoveryError> {
        let scope = RecoveryAuthorizationScope {
            action: RecoveryAction::Inspect,
            plan_digest: None,
            unproven_legacy_branch: matches!(
                basis,
                RecoveryDecisionBasis::ExplicitLegacyCheckpoint
            ),
            target_count: targets.len(),
        };
        self.authorize_and_audit_intent(context, scope, None)?;
        let result = self.build_plan(
            identity,
            expected_members,
            replicas,
            source,
            targets,
            basis,
            limits,
        );
        match &result {
            Ok(plan) => {
                self.audit_plan_completion(context, plan)?;
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_required
                    .store(1, Ordering::Relaxed);
                self.observer.observe(RecoverySignal {
                    state: RecoveryExecutionState::Planned,
                    alarm: Some(RecoveryAlarm::RecoveryRequired),
                });
            }
            Err(_) => {
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_failures
                    .fetch_add(1, Ordering::Relaxed);
                self.audit_completion(context, None, false)?;
            }
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn build_plan(
        &self,
        identity: SessionConsensusIdentity,
        expected_members: BTreeSet<SessionConsensusNodeId>,
        replicas: &[RecoveryReplica],
        source: &ReplicaId,
        targets: &[ReplicaId],
        basis: RecoveryDecisionBasis,
        limits: RecoveryLimits,
    ) -> Result<RecoveryPlan, RecoveryError> {
        validate_member_inputs(identity, &expected_members, replicas, source, targets)?;
        if replicas
            .iter()
            .map(|replica| replica_has_recovery_latch(replica, identity))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .any(|active| active)
        {
            return Err(RecoveryError::RecoveryInProgress);
        }
        let mut evidence = replicas
            .iter()
            .map(|replica| {
                inspect_replica(InspectionInput {
                    key: &self.integrity_key,
                    replica,
                    identity,
                    expected_members: &expected_members,
                    limits,
                    snapshot_integrity: self.snapshot_integrity,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        evidence.sort_by_key(RecoveryReplicaEvidence::replica_token);
        let unique_backings = evidence
            .iter()
            .map(|item| item.backing_identity)
            .collect::<BTreeSet<_>>();
        let unique_paths = evidence
            .iter()
            .map(|item| item.path_binding)
            .collect::<BTreeSet<_>>();
        let unique_files = evidence
            .iter()
            .map(|item| item.file_identity)
            .collect::<BTreeSet<_>>();
        if unique_backings.len() != evidence.len()
            || unique_paths.len() != evidence.len()
            || unique_files.len() != evidence.len()
        {
            return Err(RecoveryError::InvalidRequest);
        }
        if evidence
            .iter()
            .any(|item| item.pending_recovery_epoch.is_some())
        {
            return Err(RecoveryError::RecoveryInProgress);
        }
        if evidence
            .iter()
            .any(|item| !item.has_valid_authority_descriptor())
        {
            return Err(RecoveryError::CorruptReplica);
        }
        let source_token = replica_token(&self.integrity_key, source)?;
        let mut target_tokens = targets
            .iter()
            .map(|target| replica_token(&self.integrity_key, target))
            .collect::<Result<Vec<_>, _>>()?;
        target_tokens.sort_unstable();
        let source_evidence = evidence
            .iter()
            .find(|item| item.replica_token == source_token)
            .ok_or(RecoveryError::InvalidRequest)?;
        let source_branch_digest = source_evidence.branch_digest;
        let source_authority_profile = source_evidence.authority_profile;
        let source_fixed_placement_policy = source_evidence.fixed_placement_policy;
        let source_protected_roster_digest = source_evidence.protected_roster_digest;

        match basis {
            RecoveryDecisionBasis::VerifiedCommittedMajority => {
                if source_evidence.format != RecoveryReplicaFormat::Openraft
                    || evidence.iter().any(|item| {
                        !target_tokens.contains(&item.replica_token)
                            && item.format != RecoveryReplicaFormat::Openraft
                    })
                {
                    return Err(RecoveryError::InsufficientAuthority);
                }
                if source_evidence.committed_log_id.is_none()
                    || source_evidence.applied_log_id != source_evidence.committed_log_id
                    || source_evidence.local_head_log_id != source_evidence.committed_log_id
                {
                    return Err(RecoveryError::InsufficientAuthority);
                }
                let agreeing = evidence
                    .iter()
                    .filter(|item| {
                        item.format == RecoveryReplicaFormat::Openraft
                            && item.applied_log_id == item.committed_log_id
                            && item.local_head_log_id == item.committed_log_id
                            && item.committed_log_id == source_evidence.committed_log_id
                            && item.branch_digest == source_evidence.branch_digest
                            && item.authority_profile == source_authority_profile
                            && item.fixed_placement_policy == source_fixed_placement_policy
                            && item.protected_roster_digest == source_protected_roster_digest
                    })
                    .count();
                let quorum = (expected_members.len() / 2) + 1;
                if agreeing < quorum || target_tokens.len() >= quorum {
                    return Err(RecoveryError::InsufficientAuthority);
                }
                if target_tokens.contains(&source_token)
                    || target_tokens.iter().any(|target| {
                        evidence
                            .iter()
                            .find(|item| item.replica_token == *target)
                            .is_none_or(|item| item.branch_digest == source_evidence.branch_digest)
                    })
                {
                    return Err(RecoveryError::InsufficientAuthority);
                }
                // Every voter left untouched by a verified-majority campaign
                // must start on the exact clean committed source branch.  The
                // finalization classifier may later permit its one exact
                // recovery command to replicate before state-machine apply;
                // accepting an arbitrary pre-existing tail here would make
                // that narrow transition proof indistinguishable from a
                // divergent durable branch.
                if evidence.iter().any(|item| {
                    !target_tokens.contains(&item.replica_token)
                        && (item.committed_log_id != source_evidence.committed_log_id
                            || item.applied_log_id != source_evidence.committed_log_id
                            || item.local_head_log_id != source_evidence.committed_log_id
                            || item.branch_digest != source_evidence.branch_digest
                            || item.recovery_v2_invariant_state_digest
                                != source_evidence.recovery_v2_invariant_state_digest)
                }) {
                    return Err(RecoveryError::InsufficientAuthority);
                }
            }
            RecoveryDecisionBasis::ExplicitLegacyCheckpoint => {
                if source_evidence.format != RecoveryReplicaFormat::LegacyUnproven
                    || evidence
                        .iter()
                        .any(|item| item.format != RecoveryReplicaFormat::LegacyUnproven)
                {
                    return Err(RecoveryError::InvalidRequest);
                }
                let all_tokens = evidence
                    .iter()
                    .map(RecoveryReplicaEvidence::replica_token)
                    .collect::<BTreeSet<_>>();
                if target_tokens.iter().copied().collect::<BTreeSet<_>>() != all_tokens {
                    return Err(RecoveryError::InvalidRequest);
                }
            }
        }

        let max_recovery_epoch = evidence
            .iter()
            .map(RecoveryReplicaEvidence::recovery_epoch)
            .max()
            .unwrap_or(0);
        let next_recovery_epoch = max_recovery_epoch
            .checked_add(1)
            .ok_or(RecoveryError::InvalidRequest)?;
        let application_sequence_high_water = evidence
            .iter()
            .map(RecoveryReplicaEvidence::application_sequence)
            .max()
            .unwrap_or(0);
        let watch_sequence_high_water = evidence
            .iter()
            .map(RecoveryReplicaEvidence::watch_sequence)
            .max()
            .unwrap_or(0);
        let watch_cursor_invalidation_floor = evidence
            .iter()
            .map(|item| {
                item.watch_cursor_invalidation_floor
                    .max(item.watch_sequence)
            })
            .max()
            .unwrap_or(0);
        let fence_high_water = evidence
            .iter()
            .map(RecoveryReplicaEvidence::fence_high_water)
            .max()
            .unwrap_or(0);
        let credential_high_water = evidence
            .iter()
            .map(RecoveryReplicaEvidence::credential_high_water)
            .max()
            .unwrap_or(0);
        let body = RecoveryPlanBody {
            version: RECOVERY_PLAN_VERSION,
            snapshot_integrity: self.snapshot_integrity,
            identity,
            expected_members,
            basis,
            evidence,
            source_token,
            target_tokens,
            source_branch_digest,
            source_authority_profile,
            source_fixed_placement_policy,
            source_protected_roster_digest,
            next_recovery_epoch,
            application_sequence_high_water,
            watch_sequence_high_water,
            watch_cursor_invalidation_floor,
            fence_high_water,
            credential_high_water,
        };
        let encoded = serde_json::to_vec(&body).map_err(|_| RecoveryError::InvalidRequest)?;
        let plan_digest = RecoveryDigest(Sha256::digest(&encoded).into());
        let seal = seal_plan(&self.integrity_key, plan_digest, &encoded)?;
        Ok(RecoveryPlan {
            body,
            plan_digest,
            seal,
        })
    }

    /// Back up and reset the exact selected target set, resuming idempotently after
    /// interruption. The cluster must remain drained until [`Self::finalize`]
    /// returns [`RecoveryExecutionState::Rejoined`].
    pub fn execute(
        &self,
        context: &RecoveryContext,
        plan: &RecoveryPlan,
        confirmation: &RecoveryConfirmation,
        replicas: &[RecoveryReplica],
        backup_root: impl AsRef<Path>,
        limits: RecoveryLimits,
    ) -> Result<RecoveryExecutionReport, RecoveryError> {
        verify_plan(&self.integrity_key, plan)?;
        if plan.body.snapshot_integrity != self.snapshot_integrity {
            return Err(RecoveryError::StalePlan);
        }
        validate_confirmation(plan, confirmation)?;
        let scope = RecoveryAuthorizationScope {
            action: RecoveryAction::ResetReplicas,
            plan_digest: Some(plan.plan_digest),
            unproven_legacy_branch: matches!(
                plan.body.basis,
                RecoveryDecisionBasis::ExplicitLegacyCheckpoint
            ),
            target_count: plan.body.target_tokens.len(),
        };
        self.authorize_and_audit_intent(context, scope, Some(plan))?;
        let source = find_replica(&self.integrity_key, replicas, plan.body.source_token)?;
        let targets = plan
            .body
            .target_tokens
            .iter()
            .map(|token| find_replica(&self.integrity_key, replicas, *token))
            .collect::<Result<Vec<_>, _>>()?;
        let report = backup_and_reset_replica(ResetInput {
            key: &self.integrity_key,
            plan,
            source,
            replicas,
            targets: &targets,
            backup_root: backup_root.as_ref(),
            limits,
            #[cfg(test)]
            failpoint: None,
        });
        match report {
            Ok(mut state) => {
                let mut audit_completed = false;
                if state == RecoveryExecutionState::AuditPending {
                    let resume =
                        resume_audit_state(&self.integrity_key, plan, backup_root.as_ref())?
                            .ok_or(RecoveryError::BackupCorrupt)?;
                    if let Err(error) = self.audit_plan_completion(context, plan) {
                        self.observer.observe(RecoverySignal {
                            state: RecoveryExecutionState::AuditPending,
                            alarm: Some(RecoveryAlarm::AuditPending),
                        });
                        return Err(error);
                    }
                    // Clear the durable sidecar audit bit before publishing
                    // the authenticated workflow transition.  Reversing
                    // these writes leaves a crash-resume image which claims
                    // `resume` while the fleet still requires a success
                    // audit, and terminalization must correctly reject it.
                    // Repeating the sidecar transition while the workflow is
                    // still `AuditPending` is idempotent.
                    set_fleet_latches_audit_pending(&self.integrity_key, plan, replicas, false)?;
                    sqlite::transition_after_audit(
                        &self.integrity_key,
                        plan,
                        backup_root.as_ref(),
                        resume,
                    )?;
                    state = resume;
                    audit_completed = true;
                } else if matches!(
                    state,
                    RecoveryExecutionState::EpochCommitted | RecoveryExecutionState::Rejoined
                ) {
                    return Ok(RecoveryExecutionReport {
                        plan_digest: plan.plan_digest,
                        state,
                    });
                }
                if !audit_completed {
                    if let Err(error) = self.audit_plan_completion(context, plan) {
                        sqlite::record_audit_pending(
                            &self.integrity_key,
                            plan,
                            backup_root.as_ref(),
                        )?;
                        set_fleet_latches_audit_pending(&self.integrity_key, plan, replicas, true)?;
                        self.observer.observe(RecoverySignal {
                            state: RecoveryExecutionState::AuditPending,
                            alarm: Some(RecoveryAlarm::AuditPending),
                        });
                        return Err(error);
                    }
                }
                self.observer.observe(RecoverySignal {
                    state,
                    alarm: Some(RecoveryAlarm::RecoveryRequired),
                });
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_required
                    .store(1, Ordering::Relaxed);
                Ok(RecoveryExecutionReport {
                    plan_digest: plan.plan_digest,
                    state,
                })
            }
            Err(error) => {
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_failures
                    .fetch_add(1, Ordering::Relaxed);
                self.observer.observe(RecoverySignal {
                    state: RecoveryExecutionState::Planned,
                    alarm: Some(RecoveryAlarm::RecoveryAborted),
                });
                let _ = self.audit_failure(context, Some(plan), error);
                Err(error)
            }
        }
    }

    /// Commit the recovery epoch and invalidate every pre-recovery lease through
    /// the current Openraft leader, then prove rejoin through an internal
    /// linearizable barrier while the public readiness latch remains closed.
    ///
    /// This call must be sent to the current leader's local admin boundary. The
    /// generic peer-forwarding RPC rejects recovery intents, so peer mTLS alone
    /// never grants operator-recovery authority. `replicas` must be the same
    /// complete fleet supplied to planning and execution; its local latches are
    /// cleared only after the required success audit is durable.
    pub async fn finalize(
        &self,
        context: &RecoveryContext,
        store: &ConsensusSessionStore,
        plan: &RecoveryPlan,
        confirmation: &RecoveryConfirmation,
        replicas: &[RecoveryReplica],
        backup_root: impl AsRef<Path>,
    ) -> Result<RecoveryExecutionReport, RecoveryError> {
        let result = self
            .finalize_inner(
                context,
                store,
                plan,
                confirmation,
                replicas,
                backup_root.as_ref(),
                #[cfg(test)]
                None,
            )
            .await;
        if let Err(error) = result {
            if !matches!(
                error,
                RecoveryError::AuthorizationDenied | RecoveryError::AuditUnavailable
            ) {
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_failures
                    .fetch_add(1, Ordering::Relaxed);
                self.observer.observe(RecoverySignal {
                    state: RecoveryExecutionState::AwaitingEpochCommit,
                    alarm: Some(RecoveryAlarm::RecoveryAborted),
                });
                let _ = self.audit_failure(context, Some(plan), error);
            }
        }
        result
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    async fn finalize_with_failpoint(
        &self,
        context: &RecoveryContext,
        store: &ConsensusSessionStore,
        plan: &RecoveryPlan,
        confirmation: &RecoveryConfirmation,
        replicas: &[RecoveryReplica],
        backup_root: &Path,
        failpoint: RecoveryFinalizeFailpoint,
    ) -> Result<RecoveryExecutionReport, RecoveryError> {
        self.finalize_inner(
            context,
            store,
            plan,
            confirmation,
            replicas,
            backup_root,
            Some(failpoint),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finalize_inner(
        &self,
        context: &RecoveryContext,
        store: &ConsensusSessionStore,
        plan: &RecoveryPlan,
        confirmation: &RecoveryConfirmation,
        replicas: &[RecoveryReplica],
        backup_root: &Path,
        #[cfg(test)] failpoint: Option<RecoveryFinalizeFailpoint>,
    ) -> Result<RecoveryExecutionReport, RecoveryError> {
        verify_plan(&self.integrity_key, plan)?;
        if plan.body.snapshot_integrity != self.snapshot_integrity
            || store
                .snapshot_integrity_policy()
                .is_some_and(|policy| policy != self.snapshot_integrity)
        {
            return Err(RecoveryError::StalePlan);
        }
        validate_confirmation(plan, confirmation)?;
        let scope = RecoveryAuthorizationScope {
            action: RecoveryAction::Finalize,
            plan_digest: Some(plan.plan_digest),
            unproven_legacy_branch: matches!(
                plan.body.basis,
                RecoveryDecisionBasis::ExplicitLegacyCheckpoint
            ),
            target_count: plan.body.target_tokens.len(),
        };
        self.authorize_and_audit_intent(context, scope, Some(plan))?;
        if store.recovery_identity() != plan.body.identity {
            return Err(RecoveryError::WrongCluster);
        }
        if store.recovery_members() != &plan.body.expected_members {
            return Err(RecoveryError::StalePlan);
        }
        let limits = sqlite::workflow_limits(&self.integrity_key, plan, backup_root)?;
        let current = resume_execution_state(&self.integrity_key, plan, backup_root)?;
        if !matches!(
            current,
            RecoveryExecutionState::AwaitingEpochCommit
                | RecoveryExecutionState::EpochCommitted
                | RecoveryExecutionState::Rejoined
                | RecoveryExecutionState::AuditPending
        ) {
            return Err(RecoveryError::StalePlan);
        }
        // Keep this core's admitted snapshot namespace frozen before pinning
        // the installed artifacts.  Otherwise a live publisher could advance
        // S1 to S2 between terminal-sidecar publication and descriptor-bound
        // handoff consumption, permanently wedging a correct recovery.
        let terminal_handoff_gate = acquire_live_terminal_recovery_handoff_gate(store).await?;
        // Keep the exact installed target inodes alive across the entire
        // finalization transaction.  The workflow commits each target's
        // database/snapshot inode; every irreversible boundary below proves
        // that the pathname still resolves to those same descriptors.
        let mut finalization_pins =
            acquire_finalization_pins(&self.integrity_key, plan, replicas, backup_root, limits)?;
        // Legacy plans predate OpenRaft and therefore cannot carry a durable
        // Raft predecessor.  Under the frozen descriptors, capture (or
        // re-prove) the sole canonical bootstrap predecessor and MAC it into
        // the workflow before any V2 proposal is possible.
        let legacy_predecessor = legacy_finalization_predecessor(
            &self.integrity_key,
            plan,
            &mut finalization_pins,
            backup_root,
            limits,
        )?;
        let mut current = current;
        if current == RecoveryExecutionState::AuditPending {
            let resume = resume_audit_state(&self.integrity_key, plan, backup_root)?
                .ok_or(RecoveryError::BackupCorrupt)?;
            revalidate_finalization_pins(
                &self.integrity_key,
                plan,
                &mut finalization_pins,
                limits,
                resume != RecoveryExecutionState::AwaitingEpochCommit,
            )?;
            self.audit_plan_completion(context, plan)?;
            // Clear the active latch's audit bit before advancing the
            // authenticated workflow out of AuditPending.  A process loss in
            // the opposite order would durably advertise Awaiting while
            // retaining an audit-pending sidecar; later terminalization then
            // quite correctly rejects that mismatch and wedges resume.
            // Repeating this operation while the workflow is still
            // AuditPending is idempotent and remains fenced by the held
            // finalization descriptors.
            set_fleet_latches_audit_pending_pinned(plan, &finalization_pins, false)?;
            revalidate_finalization_pins(
                &self.integrity_key,
                plan,
                &mut finalization_pins,
                limits,
                resume != RecoveryExecutionState::AwaitingEpochCommit,
            )?;
            sqlite::transition_after_audit(&self.integrity_key, plan, backup_root, resume)?;
            current = resume;
        }
        if current == RecoveryExecutionState::Rejoined {
            revalidate_finalization_pins(
                &self.integrity_key,
                plan,
                &mut finalization_pins,
                limits,
                true,
            )?;
            clear_fleet_latches_pinned(
                plan,
                &finalization_pins,
                #[cfg(test)]
                failpoint.and_then(RecoveryFinalizeFailpoint::terminalized_sidecars),
            )?;
            // PendingHandoff is still fenced.  Re-prove the strict suffix at
            // the actual release boundary, after publishing the terminal
            // sidecar but before the live core consumes it.
            revalidate_finalization_pins(
                &self.integrity_key,
                plan,
                &mut finalization_pins,
                limits,
                true,
            )?;
            // The live local core opened while the latch was Active, so it
            // cannot have captured the descriptor-bound terminal handoff.
            // Consume the newly published handoff through the retained
            // snapshot namespace before reporting this node rejoined.
            consume_live_terminal_recovery_handoff(store, &terminal_handoff_gate).await?;
            revalidate_finalization_pins_after_terminal_consumed(
                &self.integrity_key,
                plan,
                &mut finalization_pins,
                limits,
            )?;
            return Ok(RecoveryExecutionReport {
                plan_digest: plan.plan_digest,
                state: RecoveryExecutionState::Rejoined,
            });
        }
        #[cfg(test)]
        if failpoint == Some(RecoveryFinalizeFailpoint::BeforeEpochCommit) {
            return Err(RecoveryError::InjectedFailure);
        }
        if current == RecoveryExecutionState::AwaitingEpochCommit {
            // A crash after the leader durably commits the epoch but before
            // the workflow fsync intentionally leaves Awaiting in the
            // journal.  It is not safe to issue a fresh transition based on
            // that stale label.  First distinguish the only resumable case:
            // the exact held descriptors already satisfy every finalized
            // predicate.  Any other failed installed-state proof remains
            // fatal.
            match classify_finalization_pins(
                &self.integrity_key,
                plan,
                &mut finalization_pins,
                limits,
            )? {
                FinalizationTransitionState::AllInstalled => {}
                FinalizationTransitionState::AllFinalized => {
                    sqlite::record_epoch_committed(&self.integrity_key, plan, backup_root)?;
                    current = RecoveryExecutionState::EpochCommitted;
                }
                FinalizationTransitionState::ExactFinalizeInFlight => {
                    return Err(RecoveryError::ConsensusUnavailable);
                }
                // The leader may have committed immediately before a crash
                // while one follower has not applied it yet.  Every pinned
                // descriptor still passed either the exact installed or the
                // exact finalized predicate above; do not advance the
                // workflow, rejoin, or latch state until a later attempt
                // observes a complete finalized fleet.
                FinalizationTransitionState::MixedConverging => {
                    return Err(RecoveryError::ConsensusUnavailable);
                }
            }
        }
        if current == RecoveryExecutionState::AwaitingEpochCommit {
            store
                .commit_operator_recovery(OperatorRecoveryCommitRequest {
                    request_id: recovery_request_id(plan.plan_digest),
                    intent: recovery_v2_intent_from_plan(plan, legacy_predecessor.as_ref())?,
                })
                .await
                .map_err(|error| match error {
                    OperatorRecoveryCommitError::Rejected => RecoveryError::RecoveryEpochRejected,
                    OperatorRecoveryCommitError::NotLocalLeader
                    | OperatorRecoveryCommitError::Unavailable => {
                        RecoveryError::ConsensusUnavailable
                    }
                })?;
            match classify_finalization_pins(
                &self.integrity_key,
                plan,
                &mut finalization_pins,
                limits,
            )? {
                FinalizationTransitionState::AllFinalized => {}
                // A successful leader reply is not proof that every pinned
                // follower has applied the command.  Preserve the workflow
                // at Awaiting and require a full exact proof on retry.
                FinalizationTransitionState::MixedConverging => {
                    return Err(RecoveryError::ConsensusUnavailable);
                }
                // The local leader reported an applied epoch command, so a
                // fleet with no finalized descriptor is not an eventual
                // propagation state.
                FinalizationTransitionState::AllInstalled => {
                    return Err(RecoveryError::BackupCorrupt);
                }
                // The command is already durably committed but at least one
                // held state machine has not applied it. Re-proposing would
                // reuse the deterministic request ID with different command
                // timing bytes, so preserve Awaiting and let Raft apply
                // progress on a later retry.
                FinalizationTransitionState::ExactFinalizeInFlight => {
                    return Err(RecoveryError::ConsensusUnavailable);
                }
            }
            #[cfg(test)]
            if failpoint == Some(RecoveryFinalizeFailpoint::AfterEpochCommit) {
                return Err(RecoveryError::InjectedFailure);
            }
            opc_redaction::metrics::METRICS
                .session_operator_recovery_epoch
                .store(plan.body.next_recovery_epoch, Ordering::Relaxed);
            sqlite::record_epoch_committed(&self.integrity_key, plan, backup_root)?;
            revalidate_finalization_pins(
                &self.integrity_key,
                plan,
                &mut finalization_pins,
                limits,
                true,
            )?;
            self.observer.observe(RecoverySignal {
                state: RecoveryExecutionState::EpochCommitted,
                alarm: Some(RecoveryAlarm::RecoveryRequired),
            });
        }
        // An already-committed retry reaches the rejoin barrier without the
        // branch above, so prove its descriptors here as well.
        revalidate_finalization_pins(
            &self.integrity_key,
            plan,
            &mut finalization_pins,
            limits,
            true,
        )?;
        #[cfg(test)]
        if failpoint == Some(RecoveryFinalizeFailpoint::BeforeRejoinBarrier) {
            return Err(RecoveryError::InjectedFailure);
        }
        if !store
            .probe_operator_recovery_rejoin(
                plan.body.next_recovery_epoch,
                plan.plan_digest.as_bytes(),
            )
            .await
        {
            opc_redaction::metrics::METRICS
                .session_operator_recovery_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(RecoveryError::ConsensusUnavailable);
        }
        revalidate_finalization_pins(
            &self.integrity_key,
            plan,
            &mut finalization_pins,
            limits,
            true,
        )?;
        #[cfg(test)]
        if failpoint == Some(RecoveryFinalizeFailpoint::AfterRejoinBarrier) {
            return Err(RecoveryError::InjectedFailure);
        }
        sqlite::record_rejoin_proven(&self.integrity_key, plan, backup_root)?;
        revalidate_finalization_pins(
            &self.integrity_key,
            plan,
            &mut finalization_pins,
            limits,
            true,
        )?;
        if let Err(error) = self.audit_plan_completion(context, plan) {
            sqlite::record_audit_pending(&self.integrity_key, plan, backup_root)?;
            set_fleet_latches_audit_pending_pinned(plan, &finalization_pins, true)?;
            revalidate_finalization_pins(
                &self.integrity_key,
                plan,
                &mut finalization_pins,
                limits,
                true,
            )?;
            self.observer.observe(RecoverySignal {
                state: RecoveryExecutionState::AuditPending,
                alarm: Some(RecoveryAlarm::AuditPending),
            });
            return Err(error);
        }
        // Capture and HMAC-seal a common full-log-id terminal proof while all
        // voters still have the strict Active suffix, then atomically advance
        // the workflow to Rejoined before publishing any terminal sidecar.
        record_rejoined_with_terminal_proof(
            &self.integrity_key,
            plan,
            backup_root,
            &mut finalization_pins,
            limits,
        )?;
        revalidate_finalization_pins(
            &self.integrity_key,
            plan,
            &mut finalization_pins,
            limits,
            true,
        )?;
        clear_fleet_latches_pinned(
            plan,
            &finalization_pins,
            #[cfg(test)]
            failpoint.and_then(RecoveryFinalizeFailpoint::terminalized_sidecars),
        )?;
        // The strict pre-release proof must be the final observation before
        // Terminal(PendingHandoff) becomes Consumed and ordinary commands
        // are permitted again.
        revalidate_finalization_pins(
            &self.integrity_key,
            plan,
            &mut finalization_pins,
            limits,
            true,
        )?;
        // See the Rejoined-resume path above.  Terminal(PendingHandoff) is
        // intentionally not readiness-open until the already-admitted live
        // core consumes it through its retained snapshot descriptor.
        consume_live_terminal_recovery_handoff(store, &terminal_handoff_gate).await?;
        revalidate_finalization_pins_after_terminal_consumed(
            &self.integrity_key,
            plan,
            &mut finalization_pins,
            limits,
        )?;
        self.observer.observe(RecoverySignal {
            state: RecoveryExecutionState::Rejoined,
            alarm: None,
        });
        opc_redaction::metrics::METRICS
            .session_operator_recovery_required
            .store(0, Ordering::Relaxed);
        opc_redaction::metrics::METRICS
            .session_operator_recovery_rejoins
            .fetch_add(1, Ordering::Relaxed);
        Ok(RecoveryExecutionReport {
            plan_digest: plan.plan_digest,
            state: RecoveryExecutionState::Rejoined,
        })
    }

    fn authorize_and_audit_intent(
        &self,
        context: &RecoveryContext,
        scope: RecoveryAuthorizationScope,
        plan: Option<&RecoveryPlan>,
    ) -> Result<(), RecoveryError> {
        if self
            .authorizer
            .authorize(&context.principal, scope)
            .is_err()
        {
            opc_redaction::metrics::METRICS
                .session_operator_recovery_failures
                .fetch_add(1, Ordering::Relaxed);
            self.record_audit(
                context,
                plan,
                AuditOutcome::denied_code(AuditReasonCode::ACCESS_DENIED),
            )?;
            return Err(RecoveryError::AuthorizationDenied);
        }
        opc_redaction::metrics::METRICS
            .session_operator_recovery_attempts
            .fetch_add(1, Ordering::Relaxed);
        self.record_audit(context, plan, AuditOutcome::Intent)
    }

    fn audit_completion(
        &self,
        context: &RecoveryContext,
        plan: Option<&RecoveryPlan>,
        success: bool,
    ) -> Result<(), RecoveryError> {
        let outcome = if success {
            AuditOutcome::Success
        } else {
            AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED)
        };
        self.record_audit(context, plan, outcome)
    }

    fn audit_plan_completion(
        &self,
        context: &RecoveryContext,
        plan: &RecoveryPlan,
    ) -> Result<(), RecoveryError> {
        self.record_audit(context, Some(plan), AuditOutcome::Success)
    }

    fn audit_failure(
        &self,
        context: &RecoveryContext,
        plan: Option<&RecoveryPlan>,
        error: RecoveryError,
    ) -> Result<(), RecoveryError> {
        let reason = match error {
            RecoveryError::AuthorizationDenied => AuditReasonCode::ACCESS_DENIED,
            RecoveryError::WorkLimitExceeded => AuditReasonCode::TOO_BIG,
            RecoveryError::InvalidRequest
            | RecoveryError::ConfirmationRequired
            | RecoveryError::ConfirmationMismatch => AuditReasonCode::INVALID_VALUE,
            _ => AuditReasonCode::OPERATION_FAILED,
        };
        self.record_audit(context, plan, AuditOutcome::failed_code(reason))
    }

    fn record_audit(
        &self,
        context: &RecoveryContext,
        plan: Option<&RecoveryPlan>,
        outcome: AuditOutcome,
    ) -> Result<(), RecoveryError> {
        let path =
            SchemaNodePath::new(RECOVERY_PATH).map_err(|_| RecoveryError::AuditUnavailable)?;
        let mut event = AuditEvent::new(
            context.request_id,
            &context.principal,
            context.transport,
            AuditOperation::Exec,
            outcome,
        )
        .with_paths([path]);
        if let Some(plan) = plan {
            event.tx_id = Some(
                AuditTxId::new(plan.plan_digest.to_hex())
                    .map_err(|_| RecoveryError::AuditUnavailable)?,
            );
        }
        self.audit.record(&event).map_err(|_| {
            opc_redaction::metrics::METRICS
                .session_operator_recovery_failures
                .fetch_add(1, Ordering::Relaxed);
            RecoveryError::AuditUnavailable
        })
    }
}

fn validate_member_inputs(
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    replicas: &[RecoveryReplica],
    source: &ReplicaId,
    targets: &[ReplicaId],
) -> Result<(), RecoveryError> {
    if expected_members.len() < 3
        || expected_members.len().is_multiple_of(2)
        || expected_members.len() > QUORUM_TOPOLOGY_MAX_MEMBERS
        || replicas.len() != expected_members.len()
        || targets.is_empty()
        || targets.len() > replicas.len()
    {
        return Err(RecoveryError::InvalidRequest);
    }
    let mut replica_ids = BTreeSet::new();
    let mut derived_members = BTreeSet::new();
    for replica in replicas {
        if replica.admitted_identity != identity {
            return Err(RecoveryError::WrongCluster);
        }
        if !replica_ids.insert(replica.replica_id.clone()) {
            return Err(RecoveryError::InvalidRequest);
        }
        let node = opc_consensus::derive_node_id(
            identity.cluster_id(),
            replica.replica_id.as_str().as_bytes(),
        )
        .map_err(|_| RecoveryError::InvalidRequest)?;
        if !derived_members.insert(node) {
            return Err(RecoveryError::InvalidRequest);
        }
    }
    let selected_targets = targets.iter().collect::<BTreeSet<_>>();
    if selected_targets.len() != targets.len()
        || derived_members != *expected_members
        || !replica_ids.contains(source)
        || selected_targets
            .iter()
            .any(|target| !replica_ids.contains(*target))
    {
        return Err(RecoveryError::InvalidRequest);
    }
    Ok(())
}

fn validate_confirmation(
    plan: &RecoveryPlan,
    confirmation: &RecoveryConfirmation,
) -> Result<(), RecoveryError> {
    if confirmation.plan_digest != plan.plan_digest
        || confirmation.source_branch_digest != plan.body.source_branch_digest
    {
        return Err(RecoveryError::ConfirmationMismatch);
    }
    match plan.body.basis {
        RecoveryDecisionBasis::VerifiedCommittedMajority => {
            if confirmation.legacy_acknowledgement.is_some() {
                return Err(RecoveryError::ConfirmationMismatch);
            }
        }
        RecoveryDecisionBasis::ExplicitLegacyCheckpoint => {
            if confirmation.legacy_acknowledgement.as_deref() != Some(LEGACY_ACKNOWLEDGEMENT) {
                return Err(RecoveryError::ConfirmationRequired);
            }
        }
    }
    Ok(())
}

fn verify_plan(key: &RecoveryIntegrityKey, plan: &RecoveryPlan) -> Result<(), RecoveryError> {
    if plan.body.version != RECOVERY_PLAN_VERSION {
        return Err(RecoveryError::StalePlan);
    }
    if plan
        .body
        .evidence
        .iter()
        .any(|item| !item.has_valid_authority_descriptor())
    {
        return Err(RecoveryError::StalePlan);
    }
    let source = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if source.branch_digest != plan.body.source_branch_digest
        || source.authority_profile != plan.body.source_authority_profile
        || source.fixed_placement_policy != plan.body.source_fixed_placement_policy
        || source.protected_roster_digest != plan.body.source_protected_roster_digest
    {
        return Err(RecoveryError::StalePlan);
    }
    let encoded = serde_json::to_vec(&plan.body).map_err(|_| RecoveryError::StalePlan)?;
    let digest = RecoveryDigest(Sha256::digest(&encoded).into());
    if digest != plan.plan_digest {
        return Err(RecoveryError::StalePlan);
    }
    verify_plan_seal(key, plan.plan_digest, &encoded, plan.seal)
}

fn replica_token(
    key: &RecoveryIntegrityKey,
    replica_id: &ReplicaId,
) -> Result<RecoveryDigest, RecoveryError> {
    Ok(RecoveryDigest::from_bytes(plan_mac(
        key,
        b"openpacketcore/session-recovery/replica-token/v1\0",
        &[replica_id.as_str().as_bytes()],
    )?))
}

fn find_replica<'a>(
    key: &RecoveryIntegrityKey,
    replicas: &'a [RecoveryReplica],
    token: RecoveryDigest,
) -> Result<&'a RecoveryReplica, RecoveryError> {
    let mut found = None;
    for replica in replicas {
        if replica_token(key, &replica.replica_id)? == token && found.replace(replica).is_some() {
            return Err(RecoveryError::StalePlan);
        }
    }
    found.ok_or(RecoveryError::StalePlan)
}

fn recovery_request_id(digest: RecoveryDigest) -> SessionConsensusRequestId {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    SessionConsensusRequestId::from_bytes(bytes)
}

pub(crate) fn plan_mac(
    key: &RecoveryIntegrityKey,
    domain: &[u8],
    parts: &[&[u8]],
) -> Result<[u8; 32], RecoveryError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| RecoveryError::InvalidRequest)?;
    mac.update(domain);
    for part in parts {
        mac.update(
            &u64::try_from(part.len())
                .map_err(|_| RecoveryError::InvalidRequest)?
                .to_be_bytes(),
        );
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

impl From<crate::error::StoreError> for RecoveryError {
    fn from(_: crate::error::StoreError) -> Self {
        Self::ConsensusUnavailable
    }
}
