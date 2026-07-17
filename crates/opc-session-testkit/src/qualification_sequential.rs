//! Shared, bounded sequential lease/fence/CAS qualification workload.
//!
//! The multiprocess foundation proof and the deployed Kubernetes campaign use
//! this exact schedule and history encoder. Keeping the model here prevents
//! either harness from silently changing the frozen v1 evidence contract.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::qualification::{
    qualification_key_sha256, qualification_owner_sha256, qualification_value_sha256,
    QualificationNodeCommand, QualificationNodeErrorCode, QualificationNodeReply,
    QualificationSha256,
};

/// Frozen schema identifier for the sequential workload schedule.
pub const QUALIFICATION_SEQUENTIAL_SCHEDULE_SCHEMA_V1: &str = "opc-session-ha-schedule/v1";
/// Frozen schema identifier for the sequential workload history.
pub const QUALIFICATION_SEQUENTIAL_HISTORY_SCHEMA_V1: &str = "opc-session-ha-history/v1";
/// Number of invocations in the fixed lease/fence/CAS/read workload.
pub const QUALIFICATION_SEQUENTIAL_OPERATION_COUNT: usize = 15;
/// Lease duration used to prove expiry followed by a higher fencing token.
pub const QUALIFICATION_SHORT_LEASE_MILLIS: u64 = 1_200;
/// Lease duration used for the non-expiry portions of the bounded workload.
pub const QUALIFICATION_LONG_LEASE_MILLIS: u64 = 60_000;
/// Bounded delay between the short lease and its replacement acquisition.
pub const QUALIFICATION_LEASE_EXPIRY_WAIT: Duration = Duration::from_millis(1_600);

const QUALIFICATION_SEQUENTIAL_RUN_SCOPE_DOMAIN: &[u8] = b"opc-session-ha/sequential-run-scope/v1";
const QUALIFICATION_SEQUENTIAL_RUN_SCOPE_HEX_BYTES: usize = 16;

/// Domain-separated, redaction-safe namespace for one deployed schedule run.
///
/// The scope is deterministically derived from a caller-owned unique history
/// identifier. Only the digest token is embedded in durable keys, owners,
/// operation IDs, and the schedule ID; the source identifier is never exposed
/// by this type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct QualificationSequentialRunScope(String);

impl QualificationSequentialRunScope {
    /// Derive one bounded scope from a unique deployed campaign history ID.
    pub fn derive(history_id: &str) -> Result<Self, QualificationSequentialEvidenceError> {
        if history_id.is_empty()
            || history_id.len() > 128
            || !history_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(QualificationSequentialEvidenceError::RunScope);
        }
        let mut hasher = Sha256::new();
        hasher.update(QUALIFICATION_SEQUENTIAL_RUN_SCOPE_DOMAIN);
        hasher.update([0]);
        hasher.update(history_id.as_bytes());
        let digest = format!("{:x}", hasher.finalize());
        let retained_hex = QUALIFICATION_SEQUENTIAL_RUN_SCOPE_HEX_BYTES
            .checked_mul(2)
            .ok_or(QualificationSequentialEvidenceError::RunScope)?;
        let token = digest
            .get(..retained_hex)
            .ok_or(QualificationSequentialEvidenceError::RunScope)?;
        Ok(Self(token.to_owned()))
    }

    fn token(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for QualificationSequentialRunScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualificationSequentialRunScope(<sha256-prefix>)")
    }
}

/// One invocation in the frozen sequential qualification schedule.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationSequentialInvocation {
    /// Frozen schedule schema identifier.
    pub schema_version: String,
    /// Stable identifier for this topology's schedule.
    pub schedule_id: String,
    /// One-based invocation index.
    pub operation_index: usize,
    /// Exact number of invocations in the schedule.
    pub schedule_operation_count: usize,
    /// Stable operation handle used by later lease-dependent operations.
    pub operation_id: String,
    /// Topology-ordered process that must execute this invocation.
    pub process_id: String,
    /// Exact typed operation.
    pub operation: QualificationSequentialOperation,
}

impl fmt::Debug for QualificationSequentialInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationSequentialInvocation")
            .field("operation_index", &self.operation_index)
            .field("operation_id", &self.operation_id)
            .field("process_id", &self.process_id)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

impl QualificationSequentialInvocation {
    /// Return the zero-based member index encoded by this fixed schedule.
    pub fn member_index(&self) -> Result<usize, QualificationSequentialEvidenceError> {
        self.process_id
            .strip_prefix("node-")
            .and_then(|value| value.parse().ok())
            .ok_or(QualificationSequentialEvidenceError::Schedule)
    }

    /// Convert this schedule row into the exact existing node-control command.
    #[must_use]
    pub fn command(&self) -> QualificationNodeCommand {
        match &self.operation {
            QualificationSequentialOperation::LeaseAcquire {
                key,
                owner,
                ttl_millis,
            } => QualificationNodeCommand::Acquire {
                lease_handle: self.operation_id.clone(),
                stable_id: key.clone(),
                owner: owner.clone(),
                ttl_millis: *ttl_millis,
            },
            QualificationSequentialOperation::CompareAndSet {
                key,
                lease_operation_id,
                expected_generation,
                new_generation,
                value,
            } => QualificationNodeCommand::CompareAndSet {
                lease_handle: lease_operation_id.clone(),
                stable_id: key.clone(),
                expected_generation: *expected_generation,
                new_generation: *new_generation,
                value: value.clone(),
            },
            QualificationSequentialOperation::Read { key } => QualificationNodeCommand::Get {
                stable_id: key.clone(),
            },
            QualificationSequentialOperation::LeaseRelease {
                lease_operation_id, ..
            } => QualificationNodeCommand::Release {
                lease_handle: lease_operation_id.clone(),
            },
        }
    }
}

/// Operations admitted by the frozen sequential qualification schedule.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualificationSequentialOperation {
    /// Acquire one bounded lease and retain its fencing token.
    LeaseAcquire {
        /// Synthetic stable ID.
        key: String,
        /// Synthetic lease owner.
        owner: String,
        /// Requested lease lifetime.
        ttl_millis: u64,
    },
    /// Apply one generation-checked mutation under an earlier lease.
    CompareAndSet {
        /// Synthetic stable ID.
        key: String,
        /// Schedule operation that acquired the required lease.
        lease_operation_id: String,
        /// Required current generation, or absence for creation.
        expected_generation: Option<u64>,
        /// Proposed new generation.
        new_generation: u64,
        /// Synthetic qualification value.
        value: String,
    },
    /// Perform one linearizable durable read.
    Read {
        /// Synthetic stable ID.
        key: String,
    },
    /// Release the lease acquired by an earlier invocation.
    LeaseRelease {
        /// Synthetic stable ID.
        key: String,
        /// Schedule operation that acquired the lease.
        lease_operation_id: String,
    },
}

impl fmt::Debug for QualificationSequentialOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseAcquire { ttl_millis, .. } => formatter
                .debug_struct("LeaseAcquire")
                .field("ttl_millis", ttl_millis)
                .finish_non_exhaustive(),
            Self::CompareAndSet {
                expected_generation,
                new_generation,
                value,
                ..
            } => formatter
                .debug_struct("CompareAndSet")
                .field("expected_generation", expected_generation)
                .field("new_generation", new_generation)
                .field("value_bytes", &value.len())
                .finish_non_exhaustive(),
            Self::Read { .. } => formatter.write_str("Read(<synthetic-key>)"),
            Self::LeaseRelease { .. } => formatter.write_str("LeaseRelease(<synthetic-key>)"),
        }
    }
}

impl QualificationSequentialOperation {
    /// Borrow the synthetic stable ID used by this invocation.
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::LeaseAcquire { key, .. }
            | Self::CompareAndSet { key, .. }
            | Self::Read { key }
            | Self::LeaseRelease { key, .. } => key,
        }
    }
}

/// Build the exact 15-operation workload used by every sequential HA proof.
pub fn qualification_sequential_workload(
    member_count: usize,
) -> Result<Vec<QualificationSequentialInvocation>, QualificationSequentialEvidenceError> {
    build_qualification_sequential_workload(member_count, None, QUALIFICATION_LONG_LEASE_MILLIS)
}

/// Build one run-scoped deployed instance of the frozen v1 workload.
///
/// The semantic operation shape remains identical to
/// [`qualification_sequential_workload`], while every durable key, owner,
/// lease handle/operation ID, and schedule/history ID is isolated to `scope`.
/// `long_lease_ttl_millis` must fit both the session-store TTL contract and the
/// unchanged v1 schedule schema.
pub fn qualification_sequential_workload_for_run(
    member_count: usize,
    scope: &QualificationSequentialRunScope,
    long_lease_ttl_millis: u64,
) -> Result<Vec<QualificationSequentialInvocation>, QualificationSequentialEvidenceError> {
    let maximum_ttl_millis = u64::try_from(opc_session_store::MAX_SESSION_TTL.as_millis())
        .map_err(|_| QualificationSequentialEvidenceError::Ttl)?;
    if long_lease_ttl_millis == 0 || long_lease_ttl_millis > maximum_ttl_millis {
        return Err(QualificationSequentialEvidenceError::Ttl);
    }
    build_qualification_sequential_workload(member_count, Some(scope), long_lease_ttl_millis)
}

fn build_qualification_sequential_workload(
    member_count: usize,
    scope: Option<&QualificationSequentialRunScope>,
    long_lease_ttl_millis: u64,
) -> Result<Vec<QualificationSequentialInvocation>, QualificationSequentialEvidenceError> {
    if !matches!(member_count, 3 | 5) {
        return Err(QualificationSequentialEvidenceError::Topology);
    }
    let scoped = |label: &str| match scope {
        Some(scope) => format!("q143-{}-{label}", scope.token()),
        None => label.to_owned(),
    };
    let operation_id = |index: usize| match scope {
        Some(scope) => format!("q143-{}-op-{index}", scope.token()),
        None => format!("op-{index}"),
    };
    let schedule_id = match scope {
        Some(scope) => format!("session-ha-{member_count}-k8s-{}", scope.token()),
        None => format!("session-ha-{member_count}-process-foundation"),
    };
    let expiry_key = scoped("session-expiry");
    let session_key = scoped("session-a");
    let expiry_owner_a = scoped("owner-expiry-a");
    let expiry_owner_b = scoped("owner-expiry-b");
    let owner_a = scoped("owner-a");
    let owner_b = scoped("owner-b");
    let operations = vec![
        (
            1,
            QualificationSequentialOperation::LeaseAcquire {
                key: expiry_key.clone(),
                owner: expiry_owner_a,
                ttl_millis: QUALIFICATION_SHORT_LEASE_MILLIS,
            },
        ),
        (
            1,
            QualificationSequentialOperation::LeaseAcquire {
                key: expiry_key.clone(),
                owner: expiry_owner_b,
                ttl_millis: long_lease_ttl_millis,
            },
        ),
        (
            1,
            QualificationSequentialOperation::LeaseRelease {
                key: expiry_key,
                lease_operation_id: operation_id(2),
            },
        ),
        (
            1,
            QualificationSequentialOperation::LeaseAcquire {
                key: session_key.clone(),
                owner: owner_a,
                ttl_millis: long_lease_ttl_millis,
            },
        ),
        (
            1,
            QualificationSequentialOperation::CompareAndSet {
                key: session_key.clone(),
                lease_operation_id: operation_id(4),
                expected_generation: None,
                new_generation: 1,
                value: "qualification-value-1".to_owned(),
            },
        ),
        (
            2,
            QualificationSequentialOperation::Read {
                key: session_key.clone(),
            },
        ),
        (
            1,
            QualificationSequentialOperation::LeaseRelease {
                key: session_key.clone(),
                lease_operation_id: operation_id(4),
            },
        ),
        (
            1,
            QualificationSequentialOperation::LeaseAcquire {
                key: session_key.clone(),
                owner: owner_b,
                ttl_millis: long_lease_ttl_millis,
            },
        ),
        (
            1,
            QualificationSequentialOperation::CompareAndSet {
                key: session_key.clone(),
                lease_operation_id: operation_id(8),
                expected_generation: Some(1),
                new_generation: 2,
                value: "qualification-value-2".to_owned(),
            },
        ),
        (
            1,
            QualificationSequentialOperation::CompareAndSet {
                key: session_key.clone(),
                lease_operation_id: operation_id(4),
                expected_generation: Some(2),
                new_generation: 3,
                value: "qualification-stale-value".to_owned(),
            },
        ),
        (
            1,
            QualificationSequentialOperation::Read {
                key: session_key.clone(),
            },
        ),
        (
            1,
            QualificationSequentialOperation::CompareAndSet {
                key: session_key.clone(),
                lease_operation_id: operation_id(8),
                expected_generation: Some(2),
                new_generation: 3,
                value: "qualification-value-3".to_owned(),
            },
        ),
        (
            1,
            QualificationSequentialOperation::Read {
                key: session_key.clone(),
            },
        ),
        (
            1,
            QualificationSequentialOperation::LeaseRelease {
                key: session_key.clone(),
                lease_operation_id: operation_id(8),
            },
        ),
        (
            2,
            QualificationSequentialOperation::Read { key: session_key },
        ),
    ];
    let operation_count = operations.len();
    if operation_count != QUALIFICATION_SEQUENTIAL_OPERATION_COUNT {
        return Err(QualificationSequentialEvidenceError::Schedule);
    }
    let schedule = operations
        .into_iter()
        .enumerate()
        .map(
            |(offset, (member_index, operation))| QualificationSequentialInvocation {
                schema_version: QUALIFICATION_SEQUENTIAL_SCHEDULE_SCHEMA_V1.to_owned(),
                schedule_id: schedule_id.clone(),
                operation_index: offset + 1,
                schedule_operation_count: operation_count,
                operation_id: operation_id(offset + 1),
                process_id: format!("node-{member_index}"),
                operation,
            },
        )
        .collect::<Vec<_>>();
    if schedule.iter().any(|invocation| {
        invocation.schedule_id.is_empty()
            || invocation.schedule_id.len() > 128
            || invocation.operation_id.is_empty()
            || invocation.operation_id.len() > 64
            || invocation.command().validate().is_err()
    }) {
        return Err(QualificationSequentialEvidenceError::Schedule);
    }
    Ok(schedule)
}

/// One row in the frozen v1 sequential history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationSequentialHistoryRecord {
    /// Frozen history schema identifier.
    pub schema_version: String,
    /// SHA-256 of the exact JSON-lines schedule bytes.
    pub schedule_sha256: String,
    /// Schedule identifier shared by every history row.
    pub history_id: String,
    /// One-based position of this invocation in the schedule.
    pub operation_index: usize,
    /// Exact number of operations in the complete history.
    pub history_operation_count: usize,
    /// Schedule operation identifier.
    pub operation_id: String,
    /// Stable topology-ordered process identifier.
    pub process_id: String,
    /// Monotonic invocation start in campaign-relative nanoseconds.
    pub started_ns: u64,
    /// Monotonic invocation completion in campaign-relative nanoseconds.
    pub completed_ns: u64,
    /// Digest-only typed operation result.
    pub operation: QualificationSequentialHistoryOperation,
}

/// Typed v1 history operation, containing digests but no plaintext values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualificationSequentialHistoryOperation {
    /// One lease acquisition observation.
    LeaseAcquire {
        /// Domain-separated digest of the synthetic key.
        key_sha256: String,
        /// Domain-separated digest of the synthetic owner.
        owner_sha256: String,
        /// Closed acquisition outcome.
        outcome: QualificationSequentialLeaseOutcome,
        /// Positive fence only for a successful acquisition.
        fence: Option<u64>,
    },
    /// One fenced compare-and-set observation.
    CompareAndSet {
        /// Domain-separated digest of the synthetic key.
        key_sha256: String,
        /// Domain-separated digest of the lease owner.
        owner_sha256: String,
        /// Fence returned by the referenced lease acquisition.
        fence: u64,
        /// Generation required by the mutation, or absence for create.
        expected_generation: Option<u64>,
        /// Generation proposed by the mutation.
        new_generation: u64,
        /// Domain-separated digest of the synthetic value.
        value_sha256: String,
        /// Closed mutation outcome.
        outcome: QualificationSequentialCasOutcome,
    },
    /// One linearizable read observation.
    Read {
        /// Domain-separated digest of the synthetic key.
        key_sha256: String,
        /// Closed read outcome.
        outcome: QualificationSequentialReadOutcome,
        /// Digest-only record when the key was present.
        record: Option<QualificationSequentialReadRecord>,
    },
    /// One lease-release observation.
    LeaseRelease {
        /// Domain-separated digest of the synthetic key.
        key_sha256: String,
        /// Domain-separated digest of the lease owner.
        owner_sha256: String,
        /// Fence returned by the referenced acquisition.
        fence: u64,
        /// Closed release outcome.
        outcome: QualificationSequentialLeaseOutcome,
    },
}

/// Frozen lease-acquire/release history outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationSequentialLeaseOutcome {
    /// The lease operation completed as requested.
    Success,
    /// The backend rejected the lease operation.
    Rejected,
    /// The command was accepted but no classifiable terminal reply returned.
    Indeterminate,
    /// The backend explicitly reported temporary unavailability.
    Unavailable,
}

/// Frozen compare-and-set history outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationSequentialCasOutcome {
    /// The mutation committed at the proposed generation.
    Success,
    /// The expected generation did not match.
    Conflict,
    /// The lease/fence or mutation was rejected.
    Rejected,
    /// The command was accepted but no classifiable terminal reply returned.
    Indeterminate,
    /// The backend explicitly reported temporary unavailability.
    Unavailable,
}

/// Frozen read history outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationSequentialReadOutcome {
    /// A present or absent record was returned unambiguously.
    Success,
    /// No classifiable terminal read reply returned.
    Indeterminate,
    /// The backend explicitly reported temporary unavailability.
    Unavailable,
}

/// Digest-only record returned by one successful sequential read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationSequentialReadRecord {
    /// Durable record generation.
    pub generation: u64,
    /// Domain-separated owner digest.
    pub owner_sha256: String,
    /// Durable fencing token.
    pub fence: u64,
    /// Domain-separated value digest.
    pub value_sha256: String,
}

/// Result of admitting one typed reply into the sequential history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationSequentialObservation {
    /// Frozen v1 history row.
    pub history: QualificationSequentialHistoryRecord,
    /// Whether the reply exactly matched the next expected workload result.
    pub expected: bool,
}

#[derive(Clone)]
struct LeaseEvidence {
    owner: String,
    fence: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct RecordEvidence {
    generation: u64,
    owner_sha256: String,
    fence: u64,
    value_sha256: String,
}

/// Stateful encoder for the exact frozen v1 sequential history.
pub struct QualificationSequentialHistoryBuilder {
    schedule: Vec<QualificationSequentialInvocation>,
    schedule_sha256: String,
    history_id: String,
    operation_count: usize,
    next_operation_offset: usize,
    last_completed_ns: Option<u64>,
    leases: HashMap<String, LeaseEvidence>,
    maximum_fence_by_key: HashMap<String, u64>,
    records: HashMap<String, RecordEvidence>,
}

impl fmt::Debug for QualificationSequentialHistoryBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationSequentialHistoryBuilder")
            .field("operation_count", &self.operation_count)
            .field("recorded_operations", &self.next_operation_offset)
            .field("recorded_leases", &self.leases.len())
            .field("recorded_keys", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl QualificationSequentialHistoryBuilder {
    /// Construct a bounded history encoder bound to one exact schedule.
    pub fn new(
        schedule: &[QualificationSequentialInvocation],
    ) -> Result<Self, QualificationSequentialEvidenceError> {
        if schedule.len() != QUALIFICATION_SEQUENTIAL_OPERATION_COUNT {
            return Err(QualificationSequentialEvidenceError::Binding);
        }
        let first = schedule
            .first()
            .ok_or(QualificationSequentialEvidenceError::Binding)?;
        let history_id = first.schedule_id.clone();
        if history_id.is_empty() || history_id.len() > 128 {
            return Err(QualificationSequentialEvidenceError::Binding);
        }
        let mut operation_ids = HashSet::with_capacity(schedule.len());
        for (offset, invocation) in schedule.iter().enumerate() {
            if invocation.schema_version != QUALIFICATION_SEQUENTIAL_SCHEDULE_SCHEMA_V1
                || invocation.schedule_id != history_id
                || invocation.operation_index != offset + 1
                || invocation.schedule_operation_count != schedule.len()
                || invocation.operation_id.is_empty()
                || invocation.operation_id.len() > 128
                || !operation_ids.insert(invocation.operation_id.as_str())
                || invocation.command().validate().is_err()
            {
                return Err(QualificationSequentialEvidenceError::Binding);
            }
        }
        let schedule_bytes = encode_schedule(schedule)?;
        let schedule_sha256 = QualificationSha256::digest(&schedule_bytes)
            .as_str()
            .to_owned();
        Ok(Self {
            schedule: schedule.to_vec(),
            schedule_sha256,
            history_id,
            operation_count: schedule.len(),
            next_operation_offset: 0,
            last_completed_ns: None,
            leases: HashMap::new(),
            maximum_fence_by_key: HashMap::new(),
            records: HashMap::new(),
        })
    }

    /// Admit one completed command exactly once and produce its history row.
    pub fn observe(
        &mut self,
        scheduled: &QualificationSequentialInvocation,
        started_ns: u64,
        completed_ns: u64,
        reply: Option<&QualificationNodeReply>,
    ) -> Result<QualificationSequentialObservation, QualificationSequentialEvidenceError> {
        self.validate_invocation(scheduled, started_ns, completed_ns)?;
        let (operation, expected) = match &scheduled.operation {
            QualificationSequentialOperation::LeaseAcquire { key, owner, .. } => {
                self.observe_acquire(scheduled, key, owner, reply)
            }
            QualificationSequentialOperation::CompareAndSet {
                key,
                lease_operation_id,
                expected_generation,
                new_generation,
                value,
            } => self.observe_cas(
                scheduled,
                key,
                lease_operation_id,
                *expected_generation,
                *new_generation,
                value,
                reply,
            )?,
            QualificationSequentialOperation::Read { key } => self.observe_read(key, reply),
            QualificationSequentialOperation::LeaseRelease {
                key,
                lease_operation_id,
            } => self.observe_release(key, lease_operation_id, reply)?,
        };
        let observation = QualificationSequentialObservation {
            history: QualificationSequentialHistoryRecord {
                schema_version: QUALIFICATION_SEQUENTIAL_HISTORY_SCHEMA_V1.to_owned(),
                schedule_sha256: self.schedule_sha256.clone(),
                history_id: self.history_id.clone(),
                operation_index: scheduled.operation_index,
                history_operation_count: self.operation_count,
                operation_id: scheduled.operation_id.clone(),
                process_id: scheduled.process_id.clone(),
                started_ns,
                completed_ns,
                operation,
            },
            expected,
        };
        self.next_operation_offset = self
            .next_operation_offset
            .checked_add(1)
            .ok_or(QualificationSequentialEvidenceError::Schedule)?;
        self.last_completed_ns = Some(completed_ns);
        Ok(observation)
    }

    /// SHA-256 binding of the exact schedule instance owned by this builder.
    #[must_use]
    pub fn schedule_sha256(&self) -> &str {
        &self.schedule_sha256
    }

    /// Number of exact contiguous schedule operations already observed.
    #[must_use]
    pub const fn recorded_operation_count(&self) -> usize {
        self.next_operation_offset
    }

    /// Whether every exact schedule operation was observed once in order.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.next_operation_offset == self.operation_count
    }

    /// Next exact invocation required by this prefix, if it is incomplete.
    #[must_use]
    pub fn expected_next_invocation(&self) -> Option<&QualificationSequentialInvocation> {
        self.schedule.get(self.next_operation_offset)
    }

    fn validate_invocation(
        &self,
        scheduled: &QualificationSequentialInvocation,
        started_ns: u64,
        completed_ns: u64,
    ) -> Result<(), QualificationSequentialEvidenceError> {
        if self.schedule.get(self.next_operation_offset) != Some(scheduled)
            || completed_ns < started_ns
            || self
                .last_completed_ns
                .is_some_and(|previous| started_ns < previous)
        {
            return Err(QualificationSequentialEvidenceError::HistoryOrder);
        }
        Ok(())
    }

    fn observe_acquire(
        &mut self,
        scheduled: &QualificationSequentialInvocation,
        key: &str,
        owner: &str,
        reply: Option<&QualificationNodeReply>,
    ) -> (QualificationSequentialHistoryOperation, bool) {
        let key_sha256 = qualification_key_sha256(key);
        let owner_sha256 = qualification_owner_sha256(owner);
        let (outcome, fence, expected) = match reply {
            Some(QualificationNodeReply::LeaseAcquired { fence }) if *fence > 0 => {
                let previous = self.maximum_fence_by_key.get(key).copied().unwrap_or(0);
                let expected = *fence > previous;
                self.maximum_fence_by_key
                    .insert(key.to_owned(), previous.max(*fence));
                self.leases.insert(
                    scheduled.operation_id.clone(),
                    LeaseEvidence {
                        owner: owner.to_owned(),
                        fence: *fence,
                    },
                );
                (
                    QualificationSequentialLeaseOutcome::Success,
                    Some(*fence),
                    expected,
                )
            }
            Some(QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::LeaseRejected,
            }) => (QualificationSequentialLeaseOutcome::Rejected, None, false),
            Some(QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::BackendUnavailable,
            }) => (
                QualificationSequentialLeaseOutcome::Unavailable,
                None,
                false,
            ),
            _ => (
                QualificationSequentialLeaseOutcome::Indeterminate,
                None,
                false,
            ),
        };
        (
            QualificationSequentialHistoryOperation::LeaseAcquire {
                key_sha256,
                owner_sha256,
                outcome,
                fence,
            },
            expected,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_cas(
        &mut self,
        scheduled: &QualificationSequentialInvocation,
        key: &str,
        lease_operation_id: &str,
        expected_generation: Option<u64>,
        new_generation: u64,
        value: &str,
        reply: Option<&QualificationNodeReply>,
    ) -> Result<(QualificationSequentialHistoryOperation, bool), QualificationSequentialEvidenceError>
    {
        let lease = self
            .leases
            .get(lease_operation_id)
            .cloned()
            .ok_or(QualificationSequentialEvidenceError::LeaseEvidence)?;
        let outcome = match reply {
            Some(QualificationNodeReply::CompareAndSet {
                applied: true,
                current_generation: Some(current),
            }) if *current == new_generation => QualificationSequentialCasOutcome::Success,
            Some(QualificationNodeReply::CompareAndSet { applied: false, .. }) => {
                QualificationSequentialCasOutcome::Conflict
            }
            Some(QualificationNodeReply::Error {
                code:
                    QualificationNodeErrorCode::MutationRejected
                    | QualificationNodeErrorCode::LeaseRejected,
            }) => QualificationSequentialCasOutcome::Rejected,
            Some(QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::BackendUnavailable,
            }) => QualificationSequentialCasOutcome::Unavailable,
            _ => QualificationSequentialCasOutcome::Indeterminate,
        };
        let stale_rejection = scheduled.operation_index == 10
            && matches!(
                reply,
                Some(QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::MutationRejected
                })
            );
        let expected = if scheduled.operation_index == 10 {
            stale_rejection
        } else {
            outcome == QualificationSequentialCasOutcome::Success
        };
        if outcome == QualificationSequentialCasOutcome::Success {
            self.records.insert(
                key.to_owned(),
                RecordEvidence {
                    generation: new_generation,
                    owner_sha256: qualification_owner_sha256(&lease.owner),
                    fence: lease.fence,
                    value_sha256: qualification_value_sha256(value.as_bytes()),
                },
            );
        }
        Ok((
            QualificationSequentialHistoryOperation::CompareAndSet {
                key_sha256: qualification_key_sha256(key),
                owner_sha256: qualification_owner_sha256(&lease.owner),
                fence: lease.fence,
                expected_generation,
                new_generation,
                value_sha256: qualification_value_sha256(value.as_bytes()),
                outcome,
            },
            expected,
        ))
    }

    fn observe_read(
        &self,
        key: &str,
        reply: Option<&QualificationNodeReply>,
    ) -> (QualificationSequentialHistoryOperation, bool) {
        let (outcome, record) = match reply {
            Some(QualificationNodeReply::Record {
                present: true,
                generation: Some(generation),
                owner_sha256: Some(owner_sha256),
                fence: Some(fence),
                value_sha256: Some(value_sha256),
            }) if *generation > 0 && *fence > 0 => (
                QualificationSequentialReadOutcome::Success,
                Some(QualificationSequentialReadRecord {
                    generation: *generation,
                    owner_sha256: owner_sha256.clone(),
                    fence: *fence,
                    value_sha256: value_sha256.clone(),
                }),
            ),
            Some(QualificationNodeReply::Record {
                present: false,
                generation: None,
                owner_sha256: None,
                fence: None,
                value_sha256: None,
            }) => (QualificationSequentialReadOutcome::Success, None),
            Some(QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::BackendUnavailable,
            }) => (QualificationSequentialReadOutcome::Unavailable, None),
            _ => (QualificationSequentialReadOutcome::Indeterminate, None),
        };
        let observed = record.as_ref().map(|record| RecordEvidence {
            generation: record.generation,
            owner_sha256: record.owner_sha256.clone(),
            fence: record.fence,
            value_sha256: record.value_sha256.clone(),
        });
        let expected = outcome == QualificationSequentialReadOutcome::Success
            && observed.as_ref() == self.records.get(key);
        (
            QualificationSequentialHistoryOperation::Read {
                key_sha256: qualification_key_sha256(key),
                outcome,
                record,
            },
            expected,
        )
    }

    fn observe_release(
        &self,
        key: &str,
        lease_operation_id: &str,
        reply: Option<&QualificationNodeReply>,
    ) -> Result<(QualificationSequentialHistoryOperation, bool), QualificationSequentialEvidenceError>
    {
        let lease = self
            .leases
            .get(lease_operation_id)
            .ok_or(QualificationSequentialEvidenceError::LeaseEvidence)?;
        let outcome = match reply {
            Some(QualificationNodeReply::Released) => QualificationSequentialLeaseOutcome::Success,
            Some(QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::LeaseRejected,
            }) => QualificationSequentialLeaseOutcome::Rejected,
            Some(QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::BackendUnavailable,
            }) => QualificationSequentialLeaseOutcome::Unavailable,
            _ => QualificationSequentialLeaseOutcome::Indeterminate,
        };
        Ok((
            QualificationSequentialHistoryOperation::LeaseRelease {
                key_sha256: qualification_key_sha256(key),
                owner_sha256: qualification_owner_sha256(&lease.owner),
                fence: lease.fence,
                outcome,
            },
            outcome == QualificationSequentialLeaseOutcome::Success,
        ))
    }
}

/// Redaction-safe error from the fixed sequential evidence model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QualificationSequentialEvidenceError {
    /// Only three- and five-member production-shaped fleets are admitted.
    #[error("sequential qualification topology is invalid")]
    Topology,
    /// The internally fixed schedule envelope is inconsistent.
    #[error("sequential qualification schedule is invalid")]
    Schedule,
    /// Schedule digest, history ID, or operation count is invalid.
    #[error("sequential qualification evidence binding is invalid")]
    Binding,
    /// A lease-dependent row lacks a prior successful lease observation.
    #[error("sequential qualification lease evidence is unavailable")]
    LeaseEvidence,
    /// The deployed run-scope source is outside its closed bound or alphabet.
    #[error("sequential qualification run scope is invalid")]
    RunScope,
    /// The requested long lease TTL is outside the frozen v1/store bounds.
    #[error("sequential qualification lease TTL is invalid")]
    Ttl,
    /// A history observation was duplicated, reordered, or substituted.
    #[error("sequential qualification history order is invalid")]
    HistoryOrder,
}

fn encode_schedule(
    schedule: &[QualificationSequentialInvocation],
) -> Result<Vec<u8>, QualificationSequentialEvidenceError> {
    let mut encoded = Vec::new();
    for invocation in schedule {
        serde_json::to_writer(&mut encoded, invocation)
            .map_err(|_| QualificationSequentialEvidenceError::Binding)?;
        encoded.push(b'\n');
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn schedule_is_exactly_bounded_and_topology_stable() {
        for members in [3, 5] {
            let schedule = qualification_sequential_workload(members).expect("valid topology");
            assert_eq!(schedule.len(), QUALIFICATION_SEQUENTIAL_OPERATION_COUNT);
            assert!(schedule.iter().enumerate().all(|(offset, invocation)| {
                invocation.operation_index == offset + 1
                    && invocation.schedule_operation_count
                        == QUALIFICATION_SEQUENTIAL_OPERATION_COUNT
                    && invocation.member_index().is_ok_and(|index| index < members)
            }));
            assert_eq!(schedule[11].process_id, "node-1");
            assert_eq!(schedule[14].process_id, "node-2");
        }
        assert!(matches!(
            qualification_sequential_workload(1),
            Err(QualificationSequentialEvidenceError::Topology)
        ));
    }

    #[test]
    fn debug_never_exposes_synthetic_plaintext() {
        let schedule = qualification_sequential_workload(3).expect("schedule");
        let debug = format!("{:?}", schedule[4]);
        assert!(!debug.contains("session-a"));
        assert!(!debug.contains("owner-a"));
        assert!(!debug.contains("qualification-value-1"));
    }

    #[test]
    fn deployed_run_scopes_keep_one_semantic_shape_and_disjoint_durable_names() {
        let first_scope = QualificationSequentialRunScope::derive("campaign-a").expect("scope");
        let second_scope = QualificationSequentialRunScope::derive("campaign-b").expect("scope");
        assert_ne!(first_scope, second_scope);
        assert_eq!(
            first_scope,
            QualificationSequentialRunScope::derive("campaign-a").expect("stable scope")
        );
        let first = qualification_sequential_workload_for_run(5, &first_scope, 3_400_000)
            .expect("first schedule");
        let second = qualification_sequential_workload_for_run(5, &second_scope, 3_400_000)
            .expect("second schedule");
        assert_eq!(first.len(), QUALIFICATION_SEQUENTIAL_OPERATION_COUNT);
        assert_eq!(second.len(), QUALIFICATION_SEQUENTIAL_OPERATION_COUNT);
        assert_ne!(first[0].schedule_id, second[0].schedule_id);

        let mut first_keys = BTreeSet::new();
        let mut second_keys = BTreeSet::new();
        let mut first_handles = BTreeSet::new();
        let mut second_handles = BTreeSet::new();
        for (left, right) in first.iter().zip(&second) {
            assert_eq!(left.operation_index, right.operation_index);
            assert_eq!(left.process_id, right.process_id);
            assert_eq!(
                left.schedule_operation_count,
                right.schedule_operation_count
            );
            assert_ne!(left.operation_id, right.operation_id);
            assert!(left.operation_id.len() <= 64);
            assert!(right.operation_id.len() <= 64);
            assert!(left.command().validate().is_ok());
            assert!(right.command().validate().is_ok());
            first_keys.insert(left.operation.key().to_owned());
            second_keys.insert(right.operation.key().to_owned());
            first_handles.insert(left.operation_id.clone());
            second_handles.insert(right.operation_id.clone());
            match (&left.operation, &right.operation) {
                (
                    QualificationSequentialOperation::LeaseAcquire {
                        key: left_key,
                        owner: left_owner,
                        ttl_millis: left_ttl,
                    },
                    QualificationSequentialOperation::LeaseAcquire {
                        key: right_key,
                        owner: right_owner,
                        ttl_millis: right_ttl,
                    },
                ) => {
                    assert_ne!(left_key, right_key);
                    assert_ne!(left_owner, right_owner);
                    assert_eq!(left_ttl, right_ttl);
                }
                (
                    QualificationSequentialOperation::CompareAndSet {
                        expected_generation: left_expected,
                        new_generation: left_new,
                        value: left_value,
                        ..
                    },
                    QualificationSequentialOperation::CompareAndSet {
                        expected_generation: right_expected,
                        new_generation: right_new,
                        value: right_value,
                        ..
                    },
                ) => {
                    assert_eq!(left_expected, right_expected);
                    assert_eq!(left_new, right_new);
                    assert_eq!(left_value, right_value);
                }
                (
                    QualificationSequentialOperation::Read { .. },
                    QualificationSequentialOperation::Read { .. },
                )
                | (
                    QualificationSequentialOperation::LeaseRelease { .. },
                    QualificationSequentialOperation::LeaseRelease { .. },
                ) => {}
                _ => panic!("semantic operation shape changed across run scopes"),
            }
        }
        assert!(first_keys.is_disjoint(&second_keys));
        assert!(first_handles.is_disjoint(&second_handles));
    }

    #[test]
    fn history_builder_admits_only_the_exact_contiguous_schedule_prefix() {
        let schedule = qualification_sequential_workload(3).expect("schedule");
        let mut duplicate_ids = schedule.clone();
        duplicate_ids[1].operation_id = duplicate_ids[0].operation_id.clone();
        assert!(matches!(
            QualificationSequentialHistoryBuilder::new(&duplicate_ids),
            Err(QualificationSequentialEvidenceError::Binding)
        ));
        let mut builder = QualificationSequentialHistoryBuilder::new(&schedule).expect("builder");
        assert_eq!(builder.recorded_operation_count(), 0);
        assert_eq!(builder.expected_next_invocation(), schedule.first());
        assert!(!builder.is_complete());

        let first = builder
            .observe(
                &schedule[0],
                1,
                2,
                Some(&QualificationNodeReply::LeaseAcquired { fence: 1 }),
            )
            .expect("first observation");
        assert!(first.expected);
        assert_eq!(builder.recorded_operation_count(), 1);
        assert_eq!(builder.expected_next_invocation(), schedule.get(1));
        assert!(matches!(
            builder.observe(
                &schedule[0],
                3,
                4,
                Some(&QualificationNodeReply::LeaseAcquired { fence: 2 })
            ),
            Err(QualificationSequentialEvidenceError::HistoryOrder)
        ));
        assert!(matches!(
            builder.observe(&schedule[2], 3, 4, Some(&QualificationNodeReply::Released)),
            Err(QualificationSequentialEvidenceError::HistoryOrder)
        ));

        let mut substituted = schedule[1].clone();
        substituted.process_id = "node-2".to_owned();
        assert!(matches!(
            builder.observe(
                &substituted,
                3,
                4,
                Some(&QualificationNodeReply::LeaseAcquired { fence: 2 })
            ),
            Err(QualificationSequentialEvidenceError::HistoryOrder)
        ));
        assert_eq!(builder.recorded_operation_count(), 1);
    }
}
