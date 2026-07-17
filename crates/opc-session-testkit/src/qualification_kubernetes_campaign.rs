//! Bounded deployed-Kubernetes sequential-HA campaign for the experimental
//! session-HA candidate profile.
//!
//! This module drives the private same-binary control client merged for #143.
//! It does not implement consensus, infer readiness from a listener, grant
//! Kubernetes authority, or claim production qualification. It reuses the
//! frozen v1 lease/fence/CAS/read schedule and sends each mutation at most
//! once. Each unique history ID derives a domain-separated durable run scope;
//! the checked long lease covers the serialized subprocess envelope and a
//! shorter phase deadline preserves its margin. Process-local lease handles
//! are reclaimed once without replaying durable mutations. Artifact
//! persistence independently reconstructs the exact schedule, history prefix,
//! phases, and completion claims. A sample is ready only when the exact
//! rendered node and voter identities return a fresh, internally consistent
//! Openraft durable-barrier report. The external custom condition is an
//! AND-only evidence gate: kubelet
//! independently invokes the local UDS readiness client so readiness
//! self-expires on quorum loss, a hung probe, or process termination even if
//! an external condition becomes stale.
//! Every bounded campaign first resets all custom conditions, latches and
//! aborts on its first failure, and attempts a final all-false cleanup.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Cursor, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, Notify};

#[cfg(test)]
use crate::qualification::{qualification_owner_sha256, qualification_value_sha256};
use crate::qualification::{
    read_bounded_json_line, write_json_line, QualificationNodeCommand, QualificationNodeReply,
    QualificationReadinessCode, QualificationSha256, QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS,
    QUALIFICATION_MAX_CONTROL_LINE_BYTES, SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V4,
};
use crate::qualification_kubernetes::{
    is_kubernetes_dns_label, qualification_kubernetes_readiness_expectations,
    QualificationKubernetesReadinessExpectation, QUALIFICATION_KUBERNETES_CONTAINER_NAME,
    QUALIFICATION_KUBERNETES_CONTROL_SOCKET_PATH,
    QUALIFICATION_KUBERNETES_DURABLE_READINESS_CONDITION, QUALIFICATION_KUBERNETES_FLEET_NAME,
};
use crate::qualification_sequential::{
    qualification_sequential_workload_for_run, QualificationSequentialHistoryBuilder,
    QualificationSequentialHistoryRecord, QualificationSequentialInvocation,
    QualificationSequentialOperation, QualificationSequentialRunScope,
    QUALIFICATION_LEASE_EXPIRY_WAIT, QUALIFICATION_SEQUENTIAL_HISTORY_SCHEMA_V1,
    QUALIFICATION_SEQUENTIAL_OPERATION_COUNT, QUALIFICATION_SEQUENTIAL_SCHEDULE_SCHEMA_V1,
};

/// Schema identifier for the bounded command/reply transcript.
pub const QUALIFICATION_KUBERNETES_CAMPAIGN_TRANSCRIPT_SCHEMA: &str =
    "opc-session-kubernetes-campaign-transcript/v2";
/// Schema identifier used by each emitted readiness history fragment row.
pub const QUALIFICATION_CONCURRENT_HISTORY_SCHEMA_V3: &str = "opc-session-ha-concurrent-history/v3";
/// Schema identifier for the candidate-only probe-campaign summary.
pub const QUALIFICATION_KUBERNETES_CAMPAIGN_SUMMARY_SCHEMA: &str =
    "opc-session-kubernetes-campaign/v2";
/// Maximum probe samples emitted by one bounded runner invocation.
pub const QUALIFICATION_KUBERNETES_MAX_CAMPAIGN_SAMPLES: usize = 10_000;
/// Minimum supported gap between complete fleet probe rounds.
pub const QUALIFICATION_KUBERNETES_MIN_PROBE_INTERVAL: Duration = Duration::from_millis(250);
/// Maximum supported gap between complete fleet probe rounds.
pub const QUALIFICATION_KUBERNETES_MAX_PROBE_INTERVAL: Duration = Duration::from_secs(60);
/// Kubectl execution bound, including the node's internal response bound and a
/// fixed delivery allowance. A fixed one-second process-reaping allowance can
/// follow a forced termination.
pub const QUALIFICATION_KUBERNETES_COMMAND_TIMEOUT: Duration =
    Duration::from_millis(QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS + 5_000);

const KUBECTL_STDOUT_MAX_BYTES: usize = QUALIFICATION_MAX_CONTROL_LINE_BYTES;
const KUBECTL_STDERR_MAX_BYTES: usize = 4 * 1024;
const KUBECTL_REAP_TIMEOUT: Duration = Duration::from_secs(1);
const KUBECTL_PHASE_ABORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const KUBECTL_CALLS_PER_READINESS_MEMBER: usize = 2;
const LONG_LEASE_PROTECTED_SCHEDULE_TRANSITIONS: usize = 6;
const LONG_LEASE_MARGIN_KUBECTL_CALLS: usize = 2;
const CAMPAIGN_ARTIFACT_MAX_BYTES: usize = 32 * 1024 * 1024;
const CAMPAIGN_TRANSCRIPT_FILE: &str = "transcript.jsonl";
const CAMPAIGN_READINESS_HISTORY_FILE: &str = "readiness-v3-fragment.jsonl";
const CAMPAIGN_SEQUENTIAL_SCHEDULE_FILE: &str = "schedule-v1.jsonl";
const CAMPAIGN_SEQUENTIAL_HISTORY_FILE: &str = "history-v1.jsonl";
const CAMPAIGN_SUMMARY_FILE: &str = "summary.json";

/// Shared, asynchronously observable cancellation state for one campaign.
///
/// The notification closes the race between checking the atomic state and
/// awaiting a signal, while the atomic keeps synchronous boundary checks
/// cheap and deterministic.
#[derive(Debug, Default)]
pub struct QualificationKubernetesCampaignCancellation {
    cancelled: AtomicBool,
    notification: Notify,
}

impl QualificationKubernetesCampaignCancellation {
    /// Construct an active campaign cancellation handle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notification: Notify::const_new(),
        }
    }

    /// Request cancellation and wake every in-flight campaign operation.
    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.notification.notify_waiters();
        }
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notification.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Fixed, validated input for one deployed sequential-HA campaign.
#[derive(Clone, PartialEq, Eq)]
pub struct QualificationKubernetesCampaignConfig {
    /// Namespace containing the rendered qualification fleet.
    pub namespace: String,
    /// Exact supported three- or five-voter topology.
    pub member_count: usize,
    /// Number of complete fleet probe rounds.
    pub rounds: usize,
    /// Gap between complete fleet probe rounds.
    pub probe_interval: Duration,
    /// Unique bounded run nonce shared by emitted v3 readiness rows and used
    /// to derive the domain-separated sequential workload scope.
    ///
    /// A new value is required for every attempt, including retries after an
    /// ambiguous or cancelled campaign.
    pub history_id: String,
}

impl fmt::Debug for QualificationKubernetesCampaignConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationKubernetesCampaignConfig")
            .field("member_count", &self.member_count)
            .field("rounds", &self.rounds)
            .field("probe_interval", &self.probe_interval)
            .field("namespace", &"<redacted>")
            .field("history_id", &"<redacted>")
            .finish()
    }
}

impl QualificationKubernetesCampaignConfig {
    /// Validate every operator-controlled campaign input before executing a
    /// subprocess or contacting Kubernetes.
    pub fn validate(&self) -> Result<(), QualificationKubernetesCampaignConfigError> {
        if !matches!(self.member_count, 3 | 5) {
            return Err(QualificationKubernetesCampaignConfigError::InvalidTopology);
        }
        if !is_kubernetes_dns_label(&self.namespace) {
            return Err(QualificationKubernetesCampaignConfigError::InvalidNamespace);
        }
        qualification_kubernetes_readiness_expectations(self.member_count)
            .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidIdentityContract)?;
        let readiness_rounds = self
            .rounds
            .checked_add(QUALIFICATION_SEQUENTIAL_OPERATION_COUNT)
            .ok_or(QualificationKubernetesCampaignConfigError::InvalidRounds)?;
        let sample_count = readiness_rounds
            .checked_mul(self.member_count)
            .ok_or(QualificationKubernetesCampaignConfigError::InvalidRounds)?;
        if self.rounds == 0 || sample_count > QUALIFICATION_KUBERNETES_MAX_CAMPAIGN_SAMPLES {
            return Err(QualificationKubernetesCampaignConfigError::InvalidRounds);
        }
        if !(QUALIFICATION_KUBERNETES_MIN_PROBE_INTERVAL
            ..=QUALIFICATION_KUBERNETES_MAX_PROBE_INTERVAL)
            .contains(&self.probe_interval)
        {
            return Err(QualificationKubernetesCampaignConfigError::InvalidInterval);
        }
        if !is_bounded_identifier(&self.history_id) {
            return Err(QualificationKubernetesCampaignConfigError::InvalidHistoryId);
        }
        QualificationSequentialRunScope::derive(&self.history_id)
            .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidHistoryId)?;
        qualification_kubernetes_long_lease_ttl_millis(self.member_count)
            .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
        Ok(())
    }

    fn sample_count(&self) -> usize {
        self.rounds
            .saturating_add(QUALIFICATION_SEQUENTIAL_OPERATION_COUNT)
            .saturating_mul(self.member_count)
    }
}

fn qualification_kubernetes_long_lease_call_count(
    member_count: usize,
) -> Result<usize, QualificationKubernetesCampaignConfigError> {
    if !matches!(member_count, 3 | 5) {
        return Err(QualificationKubernetesCampaignConfigError::InvalidTopology);
    }
    let readiness_calls = member_count
        .checked_mul(KUBECTL_CALLS_PER_READINESS_MEMBER)
        .ok_or(QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
    readiness_calls
        .checked_add(1)
        .and_then(|calls| calls.checked_mul(LONG_LEASE_PROTECTED_SCHEDULE_TRANSITIONS))
        .ok_or(QualificationKubernetesCampaignConfigError::InvalidWorkload)
}

fn qualification_kubernetes_long_lease_ttl_millis(
    member_count: usize,
) -> Result<u64, QualificationKubernetesCampaignConfigError> {
    let protected_calls = qualification_kubernetes_long_lease_call_count(member_count)?;
    let admitted_calls = protected_calls
        .checked_add(LONG_LEASE_MARGIN_KUBECTL_CALLS)
        .ok_or(QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
    let timeout_millis = u64::try_from(QUALIFICATION_KUBERNETES_COMMAND_TIMEOUT.as_millis())
        .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
    let ttl_millis = u64::try_from(admitted_calls)
        .ok()
        .and_then(|calls| calls.checked_mul(timeout_millis))
        .ok_or(QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
    let maximum_millis = u64::try_from(opc_session_store::MAX_SESSION_TTL.as_millis())
        .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
    if ttl_millis == 0 || ttl_millis > maximum_millis {
        return Err(QualificationKubernetesCampaignConfigError::InvalidWorkload);
    }
    Ok(ttl_millis)
}

fn qualification_kubernetes_long_lease_phase_budget(
    member_count: usize,
) -> Result<Duration, QualificationKubernetesCampaignConfigError> {
    let admitted_calls = qualification_kubernetes_long_lease_call_count(member_count)?;
    QUALIFICATION_KUBERNETES_COMMAND_TIMEOUT
        .checked_mul(
            u32::try_from(admitted_calls)
                .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?,
        )
        .ok_or(QualificationKubernetesCampaignConfigError::InvalidWorkload)
}

/// Redaction-safe campaign configuration rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QualificationKubernetesCampaignConfigError {
    /// Only three- and five-voter topologies are supported.
    #[error("qualification Kubernetes campaign topology is invalid")]
    InvalidTopology,
    /// Namespace is not a canonical Kubernetes DNS label.
    #[error("qualification Kubernetes campaign namespace is invalid")]
    InvalidNamespace,
    /// Round count is zero, overflows, or exceeds the v3 history bound.
    #[error("qualification Kubernetes campaign rounds are invalid")]
    InvalidRounds,
    /// Probe interval is outside the bounded profile.
    #[error("qualification Kubernetes campaign interval is invalid")]
    InvalidInterval,
    /// History identifier is outside the closed identifier alphabet or bound.
    #[error("qualification Kubernetes campaign history identifier is invalid")]
    InvalidHistoryId,
    /// The fixed cluster/member names did not derive one exact voter set.
    #[error("qualification Kubernetes readiness identity contract is invalid")]
    InvalidIdentityContract,
    /// The internally fixed sequential workload could not be constructed or bound.
    #[error("qualification Kubernetes sequential workload is invalid")]
    InvalidWorkload,
}

/// Fixed error classes from the Kubernetes command boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum QualificationKubernetesPortError {
    /// The subprocess could not be started or its pipes failed.
    #[error("qualification Kubernetes command unavailable")]
    Unavailable,
    /// The complete subprocess deadline expired.
    #[error("qualification Kubernetes command timed out")]
    Timeout,
    /// Campaign cancellation terminated and reaped the subprocess.
    #[error("qualification Kubernetes command cancelled")]
    Cancelled,
    /// Output exceeded its pre-decode bound.
    #[error("qualification Kubernetes command output exceeded its bound")]
    OutputTooLarge,
    /// The subprocess failed or wrote an unexpected diagnostic.
    #[error("qualification Kubernetes command failed")]
    Failed,
    /// The same-binary client reply was absent, malformed, or duplicated.
    #[error("qualification Kubernetes control reply was invalid")]
    InvalidReply,
}

/// Kubernetes Pod condition status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QualificationKubernetesConditionStatus {
    /// The fresh durable barrier proved readiness.
    True,
    /// Readiness was not proven and traffic must remain gated.
    False,
}

/// One fixed-label custom Pod condition update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationKubernetesReadinessCondition {
    /// Exact readiness-gate condition type rendered on every member Pod.
    #[serde(rename = "type")]
    pub condition_type: String,
    /// `True` only after strict validation of a fresh durable barrier report.
    pub status: QualificationKubernetesConditionStatus,
    /// Fixed low-cardinality reason.
    pub reason: QualificationKubernetesReadinessReason,
    /// Fixed redaction-safe operator message.
    pub message: String,
}

impl QualificationKubernetesReadinessCondition {
    fn ready() -> Self {
        Self {
            condition_type: QUALIFICATION_KUBERNETES_DURABLE_READINESS_CONDITION.to_owned(),
            status: QualificationKubernetesConditionStatus::True,
            reason: QualificationKubernetesReadinessReason::DurableQuorumReady,
            message: "fresh durable quorum barrier passed".to_owned(),
        }
    }

    fn not_ready(reason: QualificationKubernetesReadinessReason) -> Self {
        Self {
            condition_type: QUALIFICATION_KUBERNETES_DURABLE_READINESS_CONDITION.to_owned(),
            status: QualificationKubernetesConditionStatus::False,
            reason,
            message: "fresh durable quorum barrier not proven".to_owned(),
        }
    }
}

/// Fixed readiness-condition reason inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QualificationKubernetesReadinessReason {
    /// A fresh durable quorum barrier passed every structural check.
    DurableQuorumReady,
    /// The node reported no durable quorum.
    DurableQuorumUnavailable,
    /// The node reported invalid configured topology.
    DurableTopologyInvalid,
    /// The node requires operator recovery.
    DurableRecoveryRequired,
    /// The local control client could not return a typed reply.
    ControlUnavailable,
    /// The typed reply contradicted the configured fleet contract.
    ProbeRejected,
    /// The bounded campaign is stopping and no longer maintains freshness.
    CampaignStopped,
}

/// Port used by the pure campaign state machine.
#[async_trait]
pub trait QualificationKubernetesCampaignPort: Send + Sync {
    /// Execute one typed command through the private same-binary control client.
    ///
    /// The adapter sends the command at most once. Callers must treat a
    /// missing reply to a mutating command as indeterminate and must never
    /// retry it within the campaign.
    async fn invoke_command(
        &self,
        namespace: &str,
        pod_name: &str,
        command: &QualificationNodeCommand,
        cancellation: &QualificationKubernetesCampaignCancellation,
    ) -> Result<QualificationNodeReply, QualificationKubernetesPortError>;

    /// Publish one custom condition through the Pod status subresource.
    async fn publish_readiness(
        &self,
        namespace: &str,
        pod_name: &str,
        condition: &QualificationKubernetesReadinessCondition,
        cancellation: &QualificationKubernetesCampaignCancellation,
    ) -> Result<(), QualificationKubernetesPortError>;
}

/// Clock/scheduler port used to make sampling order deterministic in tests.
#[async_trait]
pub trait QualificationKubernetesCampaignClock: Send + Sync {
    /// Monotonic nanoseconds elapsed in this campaign.
    fn elapsed_ns(&self) -> u64;
    /// Wait for the next complete fleet probe round.
    async fn sleep(&self, duration: Duration);
}

/// Production monotonic clock for the CLI campaign runner.
#[derive(Debug)]
pub struct QualificationKubernetesSystemClock {
    started: Instant,
}

impl QualificationKubernetesSystemClock {
    /// Start a fresh monotonic campaign clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Default for QualificationKubernetesSystemClock {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl QualificationKubernetesCampaignClock for QualificationKubernetesSystemClock {
    fn elapsed_ns(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Overall result of this bounded candidate-only sequential-HA campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationKubernetesCampaignStatus {
    /// Every sample proved strict durable readiness and cleanup completed.
    Passed,
    /// At least one sample or status update failed closed.
    Failed,
    /// Cancellation stopped the campaign and cleanup completed.
    Cancelled,
}

/// Action represented by one transcript record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationKubernetesCampaignAction {
    /// Initial all-member false publication before the first sample.
    Reset,
    /// One private control-client `Probe` followed by a status update.
    Probe,
    /// One scheduled lease, CAS, read, or release command without retry.
    SequentialOperation,
    /// One process-local lease-handle reclamation command without retry.
    LeaseHandleCleanup,
    /// Final fail-closed status cleanup without a node command.
    Cleanup,
}

/// Fixed outcome classification for one transcript record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationKubernetesCampaignRecordOutcome {
    /// Probe proved readiness and the condition was published.
    Ready,
    /// Probe completed but did not prove readiness.
    NotReady,
    /// Control execution failed before a valid reply was admitted.
    ControlUnavailable,
    /// A typed reply contradicted the configured fleet contract.
    InvalidReply,
    /// Cancellation arrived before this sample could authorize readiness.
    CampaignCancelled,
    /// Kubernetes rejected the condition update.
    ReadinessUpdateFailed,
    /// Final fail-closed cleanup was published.
    CleanupPublished,
    /// Final fail-closed cleanup could not be published.
    CleanupFailed,
    /// Initial fail-closed condition reset was published.
    ResetPublished,
    /// Initial fail-closed condition reset could not be published.
    ResetFailed,
    /// The scheduled operation returned its exact expected typed result.
    SequentialOperationAccepted,
    /// The stale-fence operation returned its exact expected rejection.
    SequentialOperationRejected,
    /// The operation did not return a result that can be safely classified.
    SequentialOperationIndeterminate,
    /// One process-local lease handle was conclusively reclaimed.
    LeaseHandleForgotten,
    /// Lease-handle cleanup had no classifiable terminal reply.
    LeaseHandleCleanupIndeterminate,
}

/// One deterministic, redaction-safe command/reply transcript row.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationKubernetesCampaignRecord {
    /// Exact transcript schema.
    pub schema_version: String,
    /// Zero-based complete fleet round.
    pub round: usize,
    /// Topology-ordered member index.
    pub member_index: usize,
    /// Stable generated Pod name, never a discovered address or identity.
    pub pod_name: String,
    /// Command or cleanup action.
    pub action: QualificationKubernetesCampaignAction,
    /// Monotonic operation interval.
    pub started_ns: u64,
    /// Monotonic operation interval.
    pub completed_ns: u64,
    /// Exact typed command, absent for cleanup.
    pub command: Option<QualificationNodeCommand>,
    /// Frozen schedule operation ID, present only for sequential operations.
    pub schedule_operation_id: Option<String>,
    /// Exact typed reply, admitted only after bounded decoding.
    pub reply: Option<QualificationNodeReply>,
    /// Fixed control-boundary error class, without subprocess diagnostics.
    pub control_error: Option<QualificationKubernetesPortError>,
    /// Fixed status-subresource error class, without Kubernetes diagnostics.
    pub readiness_update_error: Option<QualificationKubernetesPortError>,
    /// Published/attempted condition, or the last strict readiness context for
    /// a sequential operation.
    pub condition: QualificationKubernetesReadinessCondition,
    /// Fixed operation outcome.
    pub outcome: QualificationKubernetesCampaignRecordOutcome,
}

impl fmt::Debug for QualificationKubernetesCampaignRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationKubernetesCampaignRecord")
            .field("round", &self.round)
            .field("member_index", &self.member_index)
            .field("action", &self.action)
            .field("outcome", &self.outcome)
            .field("pod_name", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Readiness operation matching the existing concurrent-history v3 schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationKubernetesReadinessOperationV3 {
    /// Always `readiness`.
    pub kind: String,
    /// Per-process contiguous sequence beginning at one.
    pub sample_sequence: usize,
    /// This runner always expects a formed quorum.
    pub expected_quorum: bool,
    /// `ready` or `not_ready`.
    pub state: String,
    /// Authority is present only for a strictly ready sample.
    pub term: Option<u64>,
    /// Barrier commit index, present only for a strictly ready sample.
    pub commit_index: Option<u64>,
    /// Applied index, present only for a strictly ready sample.
    pub applied_index: Option<u64>,
}

/// One readiness-only fragment row matching the existing concurrent-history
/// v3 row schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationKubernetesReadinessHistoryV3 {
    /// Existing v3 concurrent-history schema identifier.
    pub schema_version: String,
    /// Caller-supplied bounded history identifier.
    pub history_id: String,
    /// Number of readiness rows in this fragment.
    pub history_operation_count: usize,
    /// Deterministic operation identifier.
    pub operation_id: String,
    /// Stable topology-ordered process identifier.
    pub process_id: String,
    /// Monotonic operation interval.
    pub started_ns: u64,
    /// Monotonic operation interval.
    pub completed_ns: u64,
    /// Readiness operation.
    pub operation: QualificationKubernetesReadinessOperationV3,
}

/// Complete in-memory artifacts from one bounded runner invocation.
#[derive(Debug, Clone)]
pub struct QualificationKubernetesCampaignOutcome {
    /// Candidate-only campaign status.
    status: QualificationKubernetesCampaignStatus,
    /// Number of complete fleet rounds.
    completed_rounds: usize,
    /// Whether every final false-condition update succeeded.
    cleanup_complete: bool,
    /// Whether every invoked acquisition handle was conclusively forgotten.
    lease_handle_cleanup_complete: bool,
    /// Ordered command/reply and cleanup transcript.
    transcript: Vec<QualificationKubernetesCampaignRecord>,
    /// Ordered readiness-only v3 history fragment.
    readiness_history: Vec<QualificationKubernetesReadinessHistoryV3>,
    /// Exact frozen v1 schedule executed by the deployed campaign.
    sequential_schedule: Vec<QualificationSequentialInvocation>,
    /// Ordered digest-only v1 results emitted for commands actually invoked.
    sequential_history: Vec<QualificationSequentialHistoryRecord>,
    /// Whether all 15 commands and their post-operation readiness samples
    /// completed with exact expected results.
    sequential_history_complete: bool,
}

impl QualificationKubernetesCampaignOutcome {
    /// Terminal status independently revalidated before artifact publication.
    #[must_use]
    pub const fn status(&self) -> QualificationKubernetesCampaignStatus {
        self.status
    }

    /// Number of configured fleet rounds completed successfully.
    #[must_use]
    pub const fn completed_rounds(&self) -> usize {
        self.completed_rounds
    }

    /// Whether final fail-closed Pod-condition cleanup completed.
    #[must_use]
    pub const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }

    /// Whether every invoked process-local lease handle was reclaimed.
    #[must_use]
    pub const fn lease_handle_cleanup_complete(&self) -> bool {
        self.lease_handle_cleanup_complete
    }

    /// Ordered, redaction-safe campaign transcript.
    #[must_use]
    pub fn transcript(&self) -> &[QualificationKubernetesCampaignRecord] {
        &self.transcript
    }

    /// Readiness-only concurrent-history fragment.
    #[must_use]
    pub fn readiness_history(&self) -> &[QualificationKubernetesReadinessHistoryV3] {
        &self.readiness_history
    }

    /// Exact deployed frozen-v1 schedule instance.
    #[must_use]
    pub fn sequential_schedule(&self) -> &[QualificationSequentialInvocation] {
        &self.sequential_schedule
    }

    /// Exact digest-only frozen-v1 history prefix.
    #[must_use]
    pub fn sequential_history(&self) -> &[QualificationSequentialHistoryRecord] {
        &self.sequential_history
    }

    /// Whether the exact sequential schedule and every post-operation sample completed.
    #[must_use]
    pub const fn sequential_history_complete(&self) -> bool {
        self.sequential_history_complete
    }
}

/// Run one bounded deployed sequential-HA campaign.
///
/// The campaign first proves a fresh all-member readiness baseline, then
/// executes the shared 15-operation lease/fence/CAS/read schedule exactly once
/// across its designated Pods. A complete all-member readiness sample follows
/// every operation. A missing mutation reply is recorded as indeterminate and
/// is never retried. The returned readiness rows remain only a fragment for the
/// existing v3 checker; batch, watch, and restore coverage remain separate.
pub async fn run_qualification_kubernetes_probe_campaign<P, C>(
    config: &QualificationKubernetesCampaignConfig,
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<QualificationKubernetesCampaignOutcome, QualificationKubernetesCampaignConfigError>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    config.validate()?;
    let expectations = qualification_kubernetes_readiness_expectations(config.member_count)
        .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidIdentityContract)?;
    let run_scope = QualificationSequentialRunScope::derive(&config.history_id)
        .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
    let long_lease_ttl_millis =
        qualification_kubernetes_long_lease_ttl_millis(config.member_count)?;
    let sequential_schedule = qualification_sequential_workload_for_run(
        config.member_count,
        &run_scope,
        long_lease_ttl_millis,
    )
    .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
    let schedule_bytes = encode_json_lines(&sequential_schedule)
        .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
    let schedule_sha256 = QualificationSha256::digest(&schedule_bytes);
    let mut sequential_history_builder =
        QualificationSequentialHistoryBuilder::new(&sequential_schedule)
            .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
    if sequential_history_builder.schedule_sha256() != schedule_sha256.as_str() {
        return Err(QualificationKubernetesCampaignConfigError::InvalidWorkload);
    }
    let mut transcript = Vec::with_capacity(
        config
            .sample_count()
            .saturating_add(QUALIFICATION_SEQUENTIAL_OPERATION_COUNT)
            .saturating_add(config.member_count.saturating_mul(2)),
    );
    let mut readiness_history = Vec::with_capacity(config.sample_count());
    let mut sequential_history = Vec::with_capacity(QUALIFICATION_SEQUENTIAL_OPERATION_COUNT);
    let mut status = QualificationKubernetesCampaignStatus::Passed;
    let mut completed_rounds = 0;
    let mut abort = !publish_fail_closed_conditions(
        config,
        port,
        clock,
        cancellation,
        0,
        FailClosedPhase::Reset,
        &mut transcript,
    )
    .await;
    if abort {
        status = if cancellation.is_cancelled() {
            QualificationKubernetesCampaignStatus::Cancelled
        } else {
            QualificationKubernetesCampaignStatus::Failed
        };
    }
    let mut last_started_ns = vec![None; config.member_count];
    let mut sample_sequences = vec![0usize; config.member_count];
    let mut sampling_round = 0usize;
    let mut last_sequential_completed_ns = None;
    let mut sequential_history_complete = false;
    let mut long_lease_deadline = None;

    if !abort {
        status = sample_readiness_round(
            config,
            port,
            clock,
            cancellation,
            &expectations,
            sampling_round,
            &mut sample_sequences,
            &mut last_started_ns,
            &mut transcript,
            &mut readiness_history,
            None,
        )
        .await;
        abort = status != QualificationKubernetesCampaignStatus::Passed;
        if !abort {
            completed_rounds = 1;
            sampling_round = sampling_round.saturating_add(1);
        }
    }

    if !abort {
        for scheduled in &sequential_schedule {
            if scheduled.operation_index == 2 {
                let slept = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => false,
                    () = clock.sleep(QUALIFICATION_LEASE_EXPIRY_WAIT) => true,
                };
                if !slept {
                    status = QualificationKubernetesCampaignStatus::Cancelled;
                    break;
                }
            }
            if cancellation.is_cancelled() {
                status = QualificationKubernetesCampaignStatus::Cancelled;
                break;
            }
            let member_index = scheduled
                .member_index()
                .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
            if member_index >= config.member_count {
                return Err(QualificationKubernetesCampaignConfigError::InvalidWorkload);
            }
            let pod_name = qualification_pod_name(member_index);
            let command = scheduled.command();
            let started_ns = monotonic_after(clock.elapsed_ns(), last_sequential_completed_ns);
            let reply = invoke_campaign_command(
                port,
                &config.namespace,
                &pod_name,
                &command,
                cancellation,
                long_lease_deadline,
            )
            .await;
            let completed_ns = clock.elapsed_ns().max(started_ns);
            last_sequential_completed_ns = Some(completed_ns);
            let control_error = reply.as_ref().err().copied();
            let observation = sequential_history_builder
                .observe(scheduled, started_ns, completed_ns, reply.as_ref().ok())
                .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidWorkload)?;
            let expected = observation.expected;
            sequential_history.push(observation.history);
            let cancelled = cancellation.is_cancelled()
                || matches!(
                    control_error,
                    Some(QualificationKubernetesPortError::Cancelled)
                );
            let record_outcome = if cancelled {
                QualificationKubernetesCampaignRecordOutcome::CampaignCancelled
            } else if !expected {
                QualificationKubernetesCampaignRecordOutcome::SequentialOperationIndeterminate
            } else if scheduled.operation_index == 10 {
                QualificationKubernetesCampaignRecordOutcome::SequentialOperationRejected
            } else {
                QualificationKubernetesCampaignRecordOutcome::SequentialOperationAccepted
            };
            transcript.push(QualificationKubernetesCampaignRecord {
                schema_version: QUALIFICATION_KUBERNETES_CAMPAIGN_TRANSCRIPT_SCHEMA.to_owned(),
                round: sampling_round,
                member_index,
                pod_name,
                action: QualificationKubernetesCampaignAction::SequentialOperation,
                started_ns,
                completed_ns,
                command: Some(command),
                schedule_operation_id: Some(scheduled.operation_id.clone()),
                reply: reply.ok(),
                control_error,
                readiness_update_error: None,
                condition: QualificationKubernetesReadinessCondition::ready(),
                outcome: record_outcome,
            });
            if cancelled {
                status = QualificationKubernetesCampaignStatus::Cancelled;
                break;
            }
            if !expected {
                status = QualificationKubernetesCampaignStatus::Failed;
                break;
            }
            if scheduled.operation_index == 8 {
                let budget = qualification_kubernetes_long_lease_phase_budget(config.member_count)?;
                long_lease_deadline = tokio::time::Instant::now().checked_add(budget);
                if long_lease_deadline.is_none() {
                    return Err(QualificationKubernetesCampaignConfigError::InvalidWorkload);
                }
            } else if scheduled.operation_index == 14 {
                long_lease_deadline = None;
            }

            status = sample_readiness_round(
                config,
                port,
                clock,
                cancellation,
                &expectations,
                sampling_round,
                &mut sample_sequences,
                &mut last_started_ns,
                &mut transcript,
                &mut readiness_history,
                long_lease_deadline,
            )
            .await;
            if status != QualificationKubernetesCampaignStatus::Passed {
                break;
            }
            sampling_round = sampling_round.saturating_add(1);
        }
        sequential_history_complete = status == QualificationKubernetesCampaignStatus::Passed
            && sequential_history.len() == sequential_schedule.len();
    }

    if status == QualificationKubernetesCampaignStatus::Passed {
        for configured_round in 1..config.rounds {
            let slept = tokio::select! {
                biased;
                () = cancellation.cancelled() => false,
                () = clock.sleep(config.probe_interval) => true,
            };
            if !slept {
                status = QualificationKubernetesCampaignStatus::Cancelled;
                break;
            }
            status = sample_readiness_round(
                config,
                port,
                clock,
                cancellation,
                &expectations,
                sampling_round,
                &mut sample_sequences,
                &mut last_started_ns,
                &mut transcript,
                &mut readiness_history,
                None,
            )
            .await;
            if status != QualificationKubernetesCampaignStatus::Passed {
                break;
            }
            completed_rounds = configured_round + 1;
            sampling_round = sampling_round.saturating_add(1);
        }
    }

    let history_operation_count = readiness_history.len();
    for record in &mut readiness_history {
        record.history_operation_count = history_operation_count;
    }

    let cleanup_cancellation = QualificationKubernetesCampaignCancellation::new();
    let lease_handle_cleanup_complete = cleanup_invoked_lease_handles(
        config,
        port,
        clock,
        &cleanup_cancellation,
        sampling_round,
        &sequential_schedule,
        sequential_history.len(),
        &mut transcript,
    )
    .await;
    if !lease_handle_cleanup_complete {
        status = QualificationKubernetesCampaignStatus::Failed;
    }
    let cleanup_complete = publish_fail_closed_conditions(
        config,
        port,
        clock,
        &cleanup_cancellation,
        sampling_round,
        FailClosedPhase::Cleanup,
        &mut transcript,
    )
    .await;
    if !cleanup_complete {
        status = QualificationKubernetesCampaignStatus::Failed;
    }

    Ok(QualificationKubernetesCampaignOutcome {
        status,
        completed_rounds,
        cleanup_complete,
        lease_handle_cleanup_complete,
        transcript,
        readiness_history,
        sequential_schedule,
        sequential_history,
        sequential_history_complete,
    })
}

#[allow(clippy::too_many_arguments)]
async fn cleanup_invoked_lease_handles<P, C>(
    config: &QualificationKubernetesCampaignConfig,
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
    round: usize,
    schedule: &[QualificationSequentialInvocation],
    invoked_operation_count: usize,
    transcript: &mut Vec<QualificationKubernetesCampaignRecord>,
) -> bool
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    let mut complete = true;
    for scheduled in schedule.iter().take(invoked_operation_count) {
        if !matches!(
            scheduled.operation,
            QualificationSequentialOperation::LeaseAcquire { .. }
        ) {
            continue;
        }
        let Ok(member_index) = scheduled.member_index() else {
            return false;
        };
        if member_index >= config.member_count {
            return false;
        }
        let pod_name = qualification_pod_name(member_index);
        let command = QualificationNodeCommand::ForgetLease {
            lease_handle: scheduled.operation_id.clone(),
        };
        let started_ns = clock.elapsed_ns();
        let Some(deadline) =
            tokio::time::Instant::now().checked_add(QUALIFICATION_KUBERNETES_COMMAND_TIMEOUT)
        else {
            return false;
        };
        let reply = invoke_campaign_command(
            port,
            &config.namespace,
            &pod_name,
            &command,
            cancellation,
            Some(deadline),
        )
        .await;
        let completed_ns = clock.elapsed_ns().max(started_ns);
        let control_error = reply.as_ref().err().copied();
        let forgotten = matches!(reply, Ok(QualificationNodeReply::LeaseHandleForgotten));
        complete &= forgotten;
        transcript.push(QualificationKubernetesCampaignRecord {
            schema_version: QUALIFICATION_KUBERNETES_CAMPAIGN_TRANSCRIPT_SCHEMA.to_owned(),
            round,
            member_index,
            pod_name,
            action: QualificationKubernetesCampaignAction::LeaseHandleCleanup,
            started_ns,
            completed_ns,
            command: Some(command),
            schedule_operation_id: Some(scheduled.operation_id.clone()),
            reply: reply.ok(),
            control_error,
            readiness_update_error: None,
            condition: QualificationKubernetesReadinessCondition::not_ready(
                QualificationKubernetesReadinessReason::CampaignStopped,
            ),
            outcome: if forgotten {
                QualificationKubernetesCampaignRecordOutcome::LeaseHandleForgotten
            } else {
                QualificationKubernetesCampaignRecordOutcome::LeaseHandleCleanupIndeterminate
            },
        });
    }
    complete
}

#[allow(clippy::too_many_arguments)]
async fn sample_readiness_round<P, C>(
    config: &QualificationKubernetesCampaignConfig,
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
    expectations: &[QualificationKubernetesReadinessExpectation],
    round: usize,
    sample_sequences: &mut [usize],
    last_started_ns: &mut [Option<u64>],
    transcript: &mut Vec<QualificationKubernetesCampaignRecord>,
    readiness_history: &mut Vec<QualificationKubernetesReadinessHistoryV3>,
    deadline: Option<tokio::time::Instant>,
) -> QualificationKubernetesCampaignStatus
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    for member_index in 0..config.member_count {
        if cancellation.is_cancelled() {
            return QualificationKubernetesCampaignStatus::Cancelled;
        }
        let Some(expectation) = expectations.get(member_index) else {
            return QualificationKubernetesCampaignStatus::Failed;
        };
        let Some(last_started) = last_started_ns.get_mut(member_index) else {
            return QualificationKubernetesCampaignStatus::Failed;
        };
        let Some(sample_sequence) = sample_sequences.get_mut(member_index) else {
            return QualificationKubernetesCampaignStatus::Failed;
        };
        let started_ns = monotonic_after(clock.elapsed_ns(), *last_started);
        *last_started = Some(started_ns);
        *sample_sequence = sample_sequence.saturating_add(1);
        let pod_name = qualification_pod_name(member_index);
        let command = QualificationNodeCommand::Probe;
        let reply = invoke_campaign_command(
            port,
            &config.namespace,
            &pod_name,
            &command,
            cancellation,
            deadline,
        )
        .await;
        let control_error = reply.as_ref().err().copied();
        let cancelled_after_probe = cancellation.is_cancelled()
            || matches!(
                control_error,
                Some(QualificationKubernetesPortError::Cancelled)
            );
        let mut classified = if cancelled_after_probe {
            not_ready_probe(
                QualificationKubernetesReadinessReason::CampaignStopped,
                QualificationKubernetesCampaignRecordOutcome::CampaignCancelled,
            )
        } else {
            classify_probe(reply.as_ref().ok(), expectation)
        };
        classified.history.sample_sequence = *sample_sequence;
        let mut record_outcome = classified.outcome;
        let condition_result = if cancelled_after_probe {
            None
        } else {
            Some(
                publish_campaign_readiness(
                    port,
                    &config.namespace,
                    &pod_name,
                    &classified.condition,
                    cancellation,
                    deadline,
                )
                .await,
            )
        };
        let readiness_update_error = condition_result
            .as_ref()
            .and_then(|result| result.as_ref().err().copied());
        let cancelled_during_publication = cancellation.is_cancelled()
            || matches!(
                readiness_update_error,
                Some(QualificationKubernetesPortError::Cancelled)
            );
        let status = if cancelled_after_probe || cancelled_during_publication {
            record_outcome = QualificationKubernetesCampaignRecordOutcome::CampaignCancelled;
            QualificationKubernetesCampaignStatus::Cancelled
        } else if condition_result.as_ref().is_some_and(Result::is_err) {
            record_outcome = QualificationKubernetesCampaignRecordOutcome::ReadinessUpdateFailed;
            QualificationKubernetesCampaignStatus::Failed
        } else if !classified.ready {
            QualificationKubernetesCampaignStatus::Failed
        } else {
            QualificationKubernetesCampaignStatus::Passed
        };
        let completed_ns = clock.elapsed_ns().max(started_ns);
        let retained_reply = reply.ok().and_then(|reply| {
            matches!(&reply, QualificationNodeReply::Readiness { .. }).then_some(reply)
        });
        transcript.push(QualificationKubernetesCampaignRecord {
            schema_version: QUALIFICATION_KUBERNETES_CAMPAIGN_TRANSCRIPT_SCHEMA.to_owned(),
            round,
            member_index,
            pod_name,
            action: QualificationKubernetesCampaignAction::Probe,
            started_ns,
            completed_ns,
            command: Some(command),
            schedule_operation_id: None,
            reply: retained_reply,
            control_error,
            readiness_update_error,
            condition: classified.condition,
            outcome: record_outcome,
        });
        readiness_history.push(QualificationKubernetesReadinessHistoryV3 {
            schema_version: QUALIFICATION_CONCURRENT_HISTORY_SCHEMA_V3.to_owned(),
            history_id: config.history_id.clone(),
            history_operation_count: 0,
            operation_id: format!("readiness-{}-{member_index}", *sample_sequence),
            process_id: format!("node-{member_index}"),
            started_ns,
            completed_ns,
            operation: classified.history,
        });
        if status != QualificationKubernetesCampaignStatus::Passed {
            return status;
        }
    }
    QualificationKubernetesCampaignStatus::Passed
}

async fn invoke_campaign_command<P>(
    port: &P,
    namespace: &str,
    pod_name: &str,
    command: &QualificationNodeCommand,
    cancellation: &QualificationKubernetesCampaignCancellation,
    deadline: Option<tokio::time::Instant>,
) -> Result<QualificationNodeReply, QualificationKubernetesPortError>
where
    P: QualificationKubernetesCampaignPort,
{
    let Some(deadline) = deadline else {
        return port
            .invoke_command(namespace, pod_name, command, cancellation)
            .await;
    };
    let phase_cancellation = QualificationKubernetesCampaignCancellation::new();
    let invocation = port.invoke_command(namespace, pod_name, command, &phase_cancellation);
    tokio::pin!(invocation);
    let terminal_error = tokio::select! {
        biased;
        () = cancellation.cancelled() => QualificationKubernetesPortError::Cancelled,
        result = &mut invocation => return result,
        () = tokio::time::sleep_until(deadline) => QualificationKubernetesPortError::Timeout,
    };
    phase_cancellation.cancel();
    let _ = tokio::time::timeout(KUBECTL_PHASE_ABORT_DRAIN_TIMEOUT, &mut invocation).await;
    Err(terminal_error)
}

async fn publish_campaign_readiness<P>(
    port: &P,
    namespace: &str,
    pod_name: &str,
    condition: &QualificationKubernetesReadinessCondition,
    cancellation: &QualificationKubernetesCampaignCancellation,
    deadline: Option<tokio::time::Instant>,
) -> Result<(), QualificationKubernetesPortError>
where
    P: QualificationKubernetesCampaignPort,
{
    let Some(deadline) = deadline else {
        return port
            .publish_readiness(namespace, pod_name, condition, cancellation)
            .await;
    };
    let phase_cancellation = QualificationKubernetesCampaignCancellation::new();
    let publication = port.publish_readiness(namespace, pod_name, condition, &phase_cancellation);
    tokio::pin!(publication);
    let terminal_error = tokio::select! {
        biased;
        () = cancellation.cancelled() => QualificationKubernetesPortError::Cancelled,
        result = &mut publication => return result,
        () = tokio::time::sleep_until(deadline) => QualificationKubernetesPortError::Timeout,
    };
    phase_cancellation.cancel();
    let _ = tokio::time::timeout(KUBECTL_PHASE_ABORT_DRAIN_TIMEOUT, &mut publication).await;
    Err(terminal_error)
}

#[derive(Clone, Copy)]
enum FailClosedPhase {
    Reset,
    Cleanup,
}

impl FailClosedPhase {
    const fn action(self) -> QualificationKubernetesCampaignAction {
        match self {
            Self::Reset => QualificationKubernetesCampaignAction::Reset,
            Self::Cleanup => QualificationKubernetesCampaignAction::Cleanup,
        }
    }

    const fn outcome(self, published: bool) -> QualificationKubernetesCampaignRecordOutcome {
        match (self, published) {
            (Self::Reset, true) => QualificationKubernetesCampaignRecordOutcome::ResetPublished,
            (Self::Reset, false) => QualificationKubernetesCampaignRecordOutcome::ResetFailed,
            (Self::Cleanup, true) => QualificationKubernetesCampaignRecordOutcome::CleanupPublished,
            (Self::Cleanup, false) => QualificationKubernetesCampaignRecordOutcome::CleanupFailed,
        }
    }
}

async fn publish_fail_closed_conditions<P, C>(
    config: &QualificationKubernetesCampaignConfig,
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
    round: usize,
    phase: FailClosedPhase,
    transcript: &mut Vec<QualificationKubernetesCampaignRecord>,
) -> bool
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    let mut complete = true;
    for member_index in 0..config.member_count {
        if matches!(phase, FailClosedPhase::Reset) && cancellation.is_cancelled() {
            return false;
        }
        let started_ns = clock.elapsed_ns();
        let pod_name = qualification_pod_name(member_index);
        let condition = QualificationKubernetesReadinessCondition::not_ready(
            QualificationKubernetesReadinessReason::CampaignStopped,
        );
        let publication = port
            .publish_readiness(&config.namespace, &pod_name, &condition, cancellation)
            .await;
        let readiness_update_error = publication.as_ref().err().copied();
        let published = publication.is_ok();
        complete &= published;
        transcript.push(QualificationKubernetesCampaignRecord {
            schema_version: QUALIFICATION_KUBERNETES_CAMPAIGN_TRANSCRIPT_SCHEMA.to_owned(),
            round,
            member_index,
            pod_name,
            action: phase.action(),
            started_ns,
            completed_ns: clock.elapsed_ns().max(started_ns),
            command: None,
            schedule_operation_id: None,
            reply: None,
            control_error: None,
            readiness_update_error,
            condition,
            outcome: phase.outcome(published),
        });
        if matches!(phase, FailClosedPhase::Reset)
            && (cancellation.is_cancelled()
                || matches!(
                    readiness_update_error,
                    Some(QualificationKubernetesPortError::Cancelled)
                ))
        {
            return false;
        }
    }
    complete
}

struct ClassifiedProbe {
    condition: QualificationKubernetesReadinessCondition,
    history: QualificationKubernetesReadinessOperationV3,
    outcome: QualificationKubernetesCampaignRecordOutcome,
    ready: bool,
}

fn classify_probe(
    reply: Option<&QualificationNodeReply>,
    expectation: &QualificationKubernetesReadinessExpectation,
) -> ClassifiedProbe {
    let member_count = expectation.voter_count();
    let required_quorum = expectation.required_quorum();
    let Some(reply) = reply else {
        return not_ready_probe(
            QualificationKubernetesReadinessReason::ControlUnavailable,
            QualificationKubernetesCampaignRecordOutcome::ControlUnavailable,
        );
    };
    let QualificationNodeReply::Readiness {
        ready,
        reason_code,
        node_id,
        term,
        leader_id,
        configured_voters,
        configured_voter_ids,
        fresh_reachable_voters,
        agreeing_voters,
        required_quorum: reported_quorum,
        committed_index,
        applied_index,
    } = reply
    else {
        return not_ready_probe(
            QualificationKubernetesReadinessReason::ProbeRejected,
            QualificationKubernetesCampaignRecordOutcome::InvalidReply,
        );
    };

    if expectation.accepts_ready_reply(reply) {
        return ClassifiedProbe {
            condition: QualificationKubernetesReadinessCondition::ready(),
            history: QualificationKubernetesReadinessOperationV3 {
                kind: "readiness".to_owned(),
                sample_sequence: 0,
                expected_quorum: true,
                state: "ready".to_owned(),
                term: Some(*term),
                commit_index: *committed_index,
                applied_index: *applied_index,
            },
            outcome: QualificationKubernetesCampaignRecordOutcome::Ready,
            ready: true,
        };
    }

    let valid_not_ready = !*ready
        && *reason_code != QualificationReadinessCode::Ready
        && *node_id == expectation.expected_node_id()
        && leader_id.is_none_or(|leader| expectation.contains_voter(leader))
        && *configured_voters == member_count
        && configured_voter_ids.as_deref() == Some(expectation.expected_voter_ids())
        && *reported_quorum == required_quorum
        && *fresh_reachable_voters <= member_count
        && *agreeing_voters <= *fresh_reachable_voters;
    if valid_not_ready {
        let reason = match reason_code {
            QualificationReadinessCode::NoQuorum => {
                QualificationKubernetesReadinessReason::DurableQuorumUnavailable
            }
            QualificationReadinessCode::TopologyInvalid => {
                QualificationKubernetesReadinessReason::DurableTopologyInvalid
            }
            QualificationReadinessCode::RecoveryRequired => {
                QualificationKubernetesReadinessReason::DurableRecoveryRequired
            }
            QualificationReadinessCode::Ready => {
                QualificationKubernetesReadinessReason::ProbeRejected
            }
        };
        return not_ready_probe(
            reason,
            QualificationKubernetesCampaignRecordOutcome::NotReady,
        );
    }

    not_ready_probe(
        QualificationKubernetesReadinessReason::ProbeRejected,
        QualificationKubernetesCampaignRecordOutcome::InvalidReply,
    )
}

fn not_ready_probe(
    reason: QualificationKubernetesReadinessReason,
    outcome: QualificationKubernetesCampaignRecordOutcome,
) -> ClassifiedProbe {
    ClassifiedProbe {
        condition: QualificationKubernetesReadinessCondition::not_ready(reason),
        history: QualificationKubernetesReadinessOperationV3 {
            kind: "readiness".to_owned(),
            sample_sequence: 0,
            expected_quorum: true,
            state: "not_ready".to_owned(),
            term: None,
            commit_index: None,
            applied_index: None,
        },
        outcome,
        ready: false,
    }
}

fn monotonic_after(candidate: u64, previous: Option<u64>) -> u64 {
    previous
        .and_then(|value| value.checked_add(1))
        .map_or(candidate, |minimum| candidate.max(minimum))
}

fn qualification_pod_name(member_index: usize) -> String {
    format!("{QUALIFICATION_KUBERNETES_FLEET_NAME}-{member_index}-0")
}

fn is_bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Production port that invokes `kubectl` directly without a shell.
#[derive(Clone)]
pub struct KubectlQualificationKubernetesCampaignPort {
    executable: OsString,
    command_timeout: Duration,
}

impl fmt::Debug for KubectlQualificationKubernetesCampaignPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubectlQualificationKubernetesCampaignPort")
            .field("executable", &"<redacted>")
            .field("command_timeout", &self.command_timeout)
            .finish()
    }
}

impl KubectlQualificationKubernetesCampaignPort {
    /// Construct the fixed production kubectl adapter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            executable: OsString::from("kubectl"),
            command_timeout: QUALIFICATION_KUBERNETES_COMMAND_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_executable(executable: OsString, command_timeout: Duration) -> Self {
        Self {
            executable,
            command_timeout,
        }
    }
}

impl Default for KubectlQualificationKubernetesCampaignPort {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl QualificationKubernetesCampaignPort for KubectlQualificationKubernetesCampaignPort {
    async fn invoke_command(
        &self,
        namespace: &str,
        pod_name: &str,
        command: &QualificationNodeCommand,
        cancellation: &QualificationKubernetesCampaignCancellation,
    ) -> Result<QualificationNodeReply, QualificationKubernetesPortError> {
        let mut input = Vec::new();
        write_json_line(&mut input, command)
            .map_err(|_| QualificationKubernetesPortError::Unavailable)?;
        let output = run_kubectl(
            &self.executable,
            &control_client_arguments(namespace, pod_name),
            &input,
            self.command_timeout,
            KUBECTL_STDOUT_MAX_BYTES,
            KUBECTL_STDERR_MAX_BYTES,
            cancellation,
        )
        .await?;
        if !output.stderr.is_empty() {
            return Err(QualificationKubernetesPortError::Failed);
        }
        let mut reader = BufReader::new(Cursor::new(output.stdout));
        let reply = read_bounded_json_line::<_, QualificationNodeReply>(&mut reader)
            .map_err(|_| QualificationKubernetesPortError::InvalidReply)?
            .ok_or(QualificationKubernetesPortError::InvalidReply)?;
        if read_bounded_json_line::<_, QualificationNodeReply>(&mut reader)
            .map_err(|_| QualificationKubernetesPortError::InvalidReply)?
            .is_some()
        {
            return Err(QualificationKubernetesPortError::InvalidReply);
        }
        Ok(reply)
    }

    async fn publish_readiness(
        &self,
        namespace: &str,
        pod_name: &str,
        condition: &QualificationKubernetesReadinessCondition,
        cancellation: &QualificationKubernetesCampaignCancellation,
    ) -> Result<(), QualificationKubernetesPortError> {
        let patch = serde_json::to_string(&json!({
            "status": { "conditions": [condition] },
        }))
        .map_err(|_| QualificationKubernetesPortError::Unavailable)?;
        let output = run_kubectl(
            &self.executable,
            &status_patch_arguments(namespace, pod_name, &patch),
            &[],
            self.command_timeout,
            4 * 1024,
            KUBECTL_STDERR_MAX_BYTES,
            cancellation,
        )
        .await?;
        if output.stderr.is_empty() {
            Ok(())
        } else {
            Err(QualificationKubernetesPortError::Failed)
        }
    }
}

fn control_client_arguments(namespace: &str, pod_name: &str) -> Vec<OsString> {
    [
        "--namespace",
        namespace,
        "exec",
        "-i",
        pod_name,
        "--container",
        QUALIFICATION_KUBERNETES_CONTAINER_NAME,
        "--",
        "opc-session-quorum-node",
        "--control-client",
        QUALIFICATION_KUBERNETES_CONTROL_SOCKET_PATH,
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn status_patch_arguments(namespace: &str, pod_name: &str, patch: &str) -> Vec<OsString> {
    [
        "--namespace",
        namespace,
        "patch",
        "pod",
        pod_name,
        "--subresource=status",
        "--type=strategic",
        "--patch",
        patch,
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

struct KubectlOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_kubectl(
    executable: &std::ffi::OsStr,
    arguments: &[OsString],
    stdin_bytes: &[u8],
    timeout: Duration,
    stdout_max_bytes: usize,
    stderr_max_bytes: usize,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<KubectlOutput, QualificationKubernetesPortError> {
    if cancellation.is_cancelled() {
        return Err(QualificationKubernetesPortError::Cancelled);
    }
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| QualificationKubernetesPortError::Unavailable)?;
    let deadline = tokio::time::Instant::now() + timeout;
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        terminate_child(&mut child).await;
        return Err(QualificationKubernetesPortError::Unavailable);
    };
    let (overflow_tx, mut overflow_rx) = mpsc::channel(1);
    let stdout_task = tokio::spawn(collect_bounded_stream(
        stdout,
        stdout_max_bytes,
        overflow_tx.clone(),
    ));
    let stderr_task = tokio::spawn(collect_bounded_stream(
        stderr,
        stderr_max_bytes,
        overflow_tx,
    ));

    let write_result = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            terminate_child(&mut child).await;
            abort_stream_tasks(stdout_task, stderr_task).await;
            return Err(QualificationKubernetesPortError::Cancelled);
        }
        result = tokio::time::timeout_at(deadline, async {
            stdin.write_all(stdin_bytes).await?;
            stdin.shutdown().await
        }) => result,
    };
    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            terminate_child(&mut child).await;
            abort_stream_tasks(stdout_task, stderr_task).await;
            return Err(QualificationKubernetesPortError::Unavailable);
        }
        Err(_) => {
            terminate_child(&mut child).await;
            abort_stream_tasks(stdout_task, stderr_task).await;
            return Err(QualificationKubernetesPortError::Timeout);
        }
    }

    enum Terminal {
        Exited(std::io::Result<std::process::ExitStatus>),
        Overflow,
        Timeout,
        Cancelled,
    }
    let terminal = {
        let wait = child.wait();
        tokio::pin!(wait);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Terminal::Cancelled,
            result = &mut wait => Terminal::Exited(result),
            Some(()) = overflow_rx.recv() => Terminal::Overflow,
            () = tokio::time::sleep_until(deadline) => Terminal::Timeout,
        }
    };
    let status = match terminal {
        Terminal::Exited(Ok(status)) => status,
        Terminal::Exited(Err(_)) => {
            terminate_child(&mut child).await;
            abort_stream_tasks(stdout_task, stderr_task).await;
            return Err(QualificationKubernetesPortError::Unavailable);
        }
        Terminal::Overflow => {
            terminate_child(&mut child).await;
            abort_stream_tasks(stdout_task, stderr_task).await;
            return Err(QualificationKubernetesPortError::OutputTooLarge);
        }
        Terminal::Timeout => {
            terminate_child(&mut child).await;
            abort_stream_tasks(stdout_task, stderr_task).await;
            return Err(QualificationKubernetesPortError::Timeout);
        }
        Terminal::Cancelled => {
            terminate_child(&mut child).await;
            abort_stream_tasks(stdout_task, stderr_task).await;
            return Err(QualificationKubernetesPortError::Cancelled);
        }
    };
    let (stdout, stderr) = tokio::join!(
        await_stream_task(stdout_task, deadline),
        await_stream_task(stderr_task, deadline)
    );
    let stdout = stdout?;
    let stderr = stderr?;
    if stdout.overflowed || stderr.overflowed {
        return Err(QualificationKubernetesPortError::OutputTooLarge);
    }
    if !status.success() {
        return Err(QualificationKubernetesPortError::Failed);
    }
    Ok(KubectlOutput {
        stdout: stdout.retained,
        stderr: stderr.retained,
    })
}

async fn terminate_child(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(KUBECTL_REAP_TIMEOUT, child.wait()).await;
}

async fn abort_stream_tasks(
    stdout: tokio::task::JoinHandle<std::io::Result<BoundedStream>>,
    stderr: tokio::task::JoinHandle<std::io::Result<BoundedStream>>,
) {
    stdout.abort();
    stderr.abort();
    let _ = stdout.await;
    let _ = stderr.await;
}

async fn await_stream_task(
    mut task: tokio::task::JoinHandle<std::io::Result<BoundedStream>>,
    deadline: tokio::time::Instant,
) -> Result<BoundedStream, QualificationKubernetesPortError> {
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(Ok(Ok(stream))) => Ok(stream),
        Ok(Ok(Err(_))) | Ok(Err(_)) => Err(QualificationKubernetesPortError::Unavailable),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(QualificationKubernetesPortError::Timeout)
        }
    }
}

struct BoundedStream {
    retained: Vec<u8>,
    overflowed: bool,
}

async fn collect_bounded_stream<R>(
    mut reader: R,
    maximum: usize,
    overflow: mpsc::Sender<()>,
) -> std::io::Result<BoundedStream>
where
    R: AsyncRead + Unpin,
{
    let mut retained = Vec::with_capacity(maximum.min(4 * 1024));
    let mut total = 0usize;
    let mut overflowed = false;
    let mut buffer = [0u8; 4 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        let remaining = maximum.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(remaining)]);
        if total > maximum && !overflowed {
            overflowed = true;
            let _ = overflow.try_send(());
        }
    }
    Ok(BoundedStream {
        retained,
        overflowed,
    })
}

#[derive(Clone, Copy)]
struct ValidatedCampaignOutcome {
    status: QualificationKubernetesCampaignStatus,
    completed_rounds: usize,
    cleanup_complete: bool,
    lease_handle_cleanup_complete: bool,
    sequential_history_complete: bool,
}

fn validate_campaign_outcome(
    config: &QualificationKubernetesCampaignConfig,
    outcome: &QualificationKubernetesCampaignOutcome,
) -> Result<ValidatedCampaignOutcome, QualificationKubernetesCampaignArtifactError> {
    let scope = QualificationSequentialRunScope::derive(&config.history_id)
        .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    let long_ttl = qualification_kubernetes_long_lease_ttl_millis(config.member_count)
        .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    let expected_schedule =
        qualification_sequential_workload_for_run(config.member_count, &scope, long_ttl)
            .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    if outcome.sequential_schedule != expected_schedule
        || outcome.sequential_history.len() > expected_schedule.len()
        || outcome.readiness_history.len() > config.sample_count()
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }

    let maximum_transcript_records = config
        .sample_count()
        .checked_add(QUALIFICATION_SEQUENTIAL_OPERATION_COUNT)
        .and_then(|count| count.checked_add(4))
        .and_then(|count| count.checked_add(config.member_count.checked_mul(2)?))
        .ok_or(QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    if outcome.transcript.len() > maximum_transcript_records {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    validate_transcript_envelopes(config, &outcome.transcript)?;

    let mut reset_end = 0usize;
    while outcome
        .transcript
        .get(reset_end)
        .is_some_and(|record| record.action == QualificationKubernetesCampaignAction::Reset)
    {
        reset_end = reset_end.saturating_add(1);
    }
    if reset_end > config.member_count
        || outcome.transcript[reset_end..]
            .iter()
            .any(|record| record.action == QualificationKubernetesCampaignAction::Reset)
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    let mut explicit_failure = false;
    for (member_index, record) in outcome.transcript[..reset_end].iter().enumerate() {
        validate_condition_only_record(
            config,
            record,
            member_index,
            QualificationKubernetesCampaignAction::Reset,
        )?;
        match record.outcome {
            QualificationKubernetesCampaignRecordOutcome::ResetPublished
                if record.readiness_update_error.is_none() => {}
            QualificationKubernetesCampaignRecordOutcome::ResetFailed
                if record.readiness_update_error.is_some() =>
            {
                explicit_failure = true
            }
            _ => return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome),
        }
    }
    let reset_complete = reset_end == config.member_count && !explicit_failure;

    let cleanup_start = outcome
        .transcript
        .len()
        .checked_sub(config.member_count)
        .ok_or(QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    let cleanup_records = &outcome.transcript[cleanup_start..];
    let mut cleanup_complete = true;
    for (member_index, record) in cleanup_records.iter().enumerate() {
        validate_condition_only_record(
            config,
            record,
            member_index,
            QualificationKubernetesCampaignAction::Cleanup,
        )?;
        match record.outcome {
            QualificationKubernetesCampaignRecordOutcome::CleanupPublished
                if record.readiness_update_error.is_none() => {}
            QualificationKubernetesCampaignRecordOutcome::CleanupFailed
                if record.readiness_update_error.is_some() =>
            {
                cleanup_complete = false
            }
            _ => return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome),
        }
    }
    if outcome.transcript[..cleanup_start]
        .iter()
        .any(|record| record.action == QualificationKubernetesCampaignAction::Cleanup)
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }

    let mut handle_cleanup_start = cleanup_start;
    while handle_cleanup_start > reset_end
        && outcome.transcript[handle_cleanup_start - 1].action
            == QualificationKubernetesCampaignAction::LeaseHandleCleanup
    {
        handle_cleanup_start -= 1;
    }
    if outcome.transcript[reset_end..handle_cleanup_start]
        .iter()
        .any(|record| record.action == QualificationKubernetesCampaignAction::LeaseHandleCleanup)
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }

    let middle = &outcome.transcript[reset_end..handle_cleanup_start];
    if !reset_complete && !middle.is_empty() {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    let mut builder = QualificationSequentialHistoryBuilder::new(&expected_schedule)
        .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    let mut history_offset = 0usize;
    let mut readiness_offset = 0usize;
    let mut readiness_sequences = vec![0usize; config.member_count];
    let mut cursor = 0usize;
    let mut completed_rounds = 0usize;
    let mut cancelled = false;

    if reset_complete && !middle.is_empty() {
        let group_start = cursor;
        let (next, full_ready) = validate_probe_group(
            config,
            middle,
            cursor,
            &outcome.readiness_history,
            &mut readiness_offset,
            &mut readiness_sequences,
        )?;
        cursor = next;
        if full_ready {
            completed_rounds = 1;
        } else {
            explicit_failure |= middle[group_start..cursor].iter().any(|record| {
                !matches!(
                    record.outcome,
                    QualificationKubernetesCampaignRecordOutcome::Ready
                        | QualificationKubernetesCampaignRecordOutcome::CampaignCancelled
                )
            });
            cancelled |= middle[group_start..cursor].iter().any(|record| {
                record.outcome == QualificationKubernetesCampaignRecordOutcome::CampaignCancelled
            }) || !explicit_failure;
            if cursor != middle.len() {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
        }
    } else if reset_complete || !explicit_failure {
        cancelled = true;
    }

    let mut sequential_post_sample_complete = false;
    while cursor < middle.len() && history_offset < expected_schedule.len() {
        let record = &middle[cursor];
        if record.action != QualificationKubernetesCampaignAction::SequentialOperation {
            break;
        }
        let scheduled = &expected_schedule[history_offset];
        let observation = validate_sequential_record(config, record, scheduled, &mut builder)?;
        let retained = outcome
            .sequential_history
            .get(history_offset)
            .ok_or(QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
        if retained != &observation.history {
            return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
        }
        history_offset += 1;
        cursor += 1;
        if record.outcome == QualificationKubernetesCampaignRecordOutcome::CampaignCancelled {
            cancelled = true;
            if cursor != middle.len() {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
            break;
        }
        if !observation.expected {
            explicit_failure = true;
            if cursor != middle.len() {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
            break;
        }
        let group_start = cursor;
        let (next, full_ready) = validate_probe_group(
            config,
            middle,
            cursor,
            &outcome.readiness_history,
            &mut readiness_offset,
            &mut readiness_sequences,
        )?;
        cursor = next;
        sequential_post_sample_complete = full_ready;
        if !full_ready {
            explicit_failure |= middle[group_start..cursor].iter().any(|record| {
                !matches!(
                    record.outcome,
                    QualificationKubernetesCampaignRecordOutcome::Ready
                        | QualificationKubernetesCampaignRecordOutcome::CampaignCancelled
                )
            });
            cancelled |= middle[group_start..cursor].iter().any(|record| {
                record.outcome == QualificationKubernetesCampaignRecordOutcome::CampaignCancelled
            }) || !explicit_failure;
            if cursor != middle.len() {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
            break;
        }
    }
    if history_offset != outcome.sequential_history.len() {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }

    let sequential_history_complete = builder.is_complete() && sequential_post_sample_complete;
    if sequential_history_complete {
        for _ in 1..config.rounds {
            if cursor == middle.len() {
                cancelled = true;
                break;
            }
            let group_start = cursor;
            let (next, full_ready) = validate_probe_group(
                config,
                middle,
                cursor,
                &outcome.readiness_history,
                &mut readiness_offset,
                &mut readiness_sequences,
            )?;
            cursor = next;
            if full_ready {
                completed_rounds = completed_rounds.saturating_add(1);
            } else {
                explicit_failure |= middle[group_start..cursor].iter().any(|record| {
                    !matches!(
                        record.outcome,
                        QualificationKubernetesCampaignRecordOutcome::Ready
                            | QualificationKubernetesCampaignRecordOutcome::CampaignCancelled
                    )
                });
                cancelled |= middle[group_start..cursor].iter().any(|record| {
                    record.outcome
                        == QualificationKubernetesCampaignRecordOutcome::CampaignCancelled
                }) || !explicit_failure;
                break;
            }
        }
    }
    if cursor != middle.len() || readiness_offset != outcome.readiness_history.len() {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }

    let invoked_acquisitions = expected_schedule
        .iter()
        .take(history_offset)
        .filter(|invocation| {
            matches!(
                invocation.operation,
                QualificationSequentialOperation::LeaseAcquire { .. }
            )
        })
        .collect::<Vec<_>>();
    let handle_cleanup_records = &outcome.transcript[handle_cleanup_start..cleanup_start];
    if handle_cleanup_records.len() != invoked_acquisitions.len() {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    let mut lease_handle_cleanup_complete = true;
    for (record, scheduled) in handle_cleanup_records.iter().zip(invoked_acquisitions) {
        let forgotten = validate_handle_cleanup_record(config, record, scheduled)?;
        lease_handle_cleanup_complete &= forgotten;
    }

    if outcome.cleanup_complete != cleanup_complete
        || outcome.lease_handle_cleanup_complete != lease_handle_cleanup_complete
        || outcome.sequential_history_complete != sequential_history_complete
        || outcome.completed_rounds != completed_rounds
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    let operational_complete = reset_complete
        && sequential_history_complete
        && completed_rounds == config.rounds
        && !explicit_failure
        && !cancelled;
    let status = if !cleanup_complete || !lease_handle_cleanup_complete || explicit_failure {
        QualificationKubernetesCampaignStatus::Failed
    } else if operational_complete {
        QualificationKubernetesCampaignStatus::Passed
    } else {
        QualificationKubernetesCampaignStatus::Cancelled
    };
    if outcome.status != status {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    Ok(ValidatedCampaignOutcome {
        status,
        completed_rounds,
        cleanup_complete,
        lease_handle_cleanup_complete,
        sequential_history_complete,
    })
}

fn validate_transcript_envelopes(
    config: &QualificationKubernetesCampaignConfig,
    transcript: &[QualificationKubernetesCampaignRecord],
) -> Result<(), QualificationKubernetesCampaignArtifactError> {
    let mut previous_round = 0usize;
    for record in transcript {
        if record.schema_version != QUALIFICATION_KUBERNETES_CAMPAIGN_TRANSCRIPT_SCHEMA
            || record.member_index >= config.member_count
            || record.pod_name != qualification_pod_name(record.member_index)
            || record.completed_ns < record.started_ns
            || record.round < previous_round
            || record.condition.condition_type
                != QUALIFICATION_KUBERNETES_DURABLE_READINESS_CONDITION
        {
            return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
        }
        previous_round = record.round;
    }
    Ok(())
}

fn validate_condition_only_record(
    config: &QualificationKubernetesCampaignConfig,
    record: &QualificationKubernetesCampaignRecord,
    member_index: usize,
    action: QualificationKubernetesCampaignAction,
) -> Result<(), QualificationKubernetesCampaignArtifactError> {
    if record.action != action
        || record.member_index != member_index
        || record.pod_name != qualification_pod_name(member_index)
        || record.command.is_some()
        || record.schedule_operation_id.is_some()
        || record.reply.is_some()
        || record.control_error.is_some()
        || record.condition
            != QualificationKubernetesReadinessCondition::not_ready(
                QualificationKubernetesReadinessReason::CampaignStopped,
            )
        || config.member_count == 0
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    Ok(())
}

fn validate_probe_group(
    config: &QualificationKubernetesCampaignConfig,
    records: &[QualificationKubernetesCampaignRecord],
    start: usize,
    readiness_history: &[QualificationKubernetesReadinessHistoryV3],
    readiness_offset: &mut usize,
    readiness_sequences: &mut [usize],
) -> Result<(usize, bool), QualificationKubernetesCampaignArtifactError> {
    let mut cursor = start;
    let mut member_index = 0usize;
    let mut full_ready = true;
    while member_index < config.member_count
        && records
            .get(cursor)
            .is_some_and(|record| record.action == QualificationKubernetesCampaignAction::Probe)
    {
        let history = readiness_history
            .get(*readiness_offset)
            .ok_or(QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
        let sequence = readiness_sequences
            .get_mut(member_index)
            .ok_or(QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
        *sequence = sequence
            .checked_add(1)
            .ok_or(QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
        validate_probe_record(
            config,
            &records[cursor],
            history,
            member_index,
            *sequence,
            readiness_history.len(),
        )?;
        full_ready &=
            records[cursor].outcome == QualificationKubernetesCampaignRecordOutcome::Ready;
        *readiness_offset = readiness_offset
            .checked_add(1)
            .ok_or(QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
        cursor += 1;
        member_index += 1;
    }
    Ok((cursor, member_index == config.member_count && full_ready))
}

fn validate_probe_record(
    config: &QualificationKubernetesCampaignConfig,
    record: &QualificationKubernetesCampaignRecord,
    history: &QualificationKubernetesReadinessHistoryV3,
    member_index: usize,
    expected_sequence: usize,
    history_operation_count: usize,
) -> Result<(), QualificationKubernetesCampaignArtifactError> {
    if record.action != QualificationKubernetesCampaignAction::Probe
        || record.member_index != member_index
        || !matches!(record.command, Some(QualificationNodeCommand::Probe))
        || record.schedule_operation_id.is_some()
        || history.schema_version != QUALIFICATION_CONCURRENT_HISTORY_SCHEMA_V3
        || history.history_id != config.history_id
        || history.history_operation_count != history_operation_count
        || history.process_id != format!("node-{member_index}")
        || history.started_ns != record.started_ns
        || history.completed_ns != record.completed_ns
        || history.operation.kind != "readiness"
        || !history.operation.expected_quorum
        || history.operation.sample_sequence != expected_sequence
        || history.operation_id
            != format!(
                "readiness-{}-{member_index}",
                history.operation.sample_sequence
            )
        || (record.reply.is_some() && record.control_error.is_some())
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    let expectations = qualification_kubernetes_readiness_expectations(config.member_count)
        .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    let expectation = expectations
        .get(member_index)
        .ok_or(QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    let ready_shape = history.operation.state == "ready"
        && history.operation.term.is_some()
        && history.operation.commit_index.is_some()
        && history.operation.applied_index.is_some()
        && record.condition.status == QualificationKubernetesConditionStatus::True;
    let not_ready_shape = history.operation.state == "not_ready"
        && history.operation.term.is_none()
        && history.operation.commit_index.is_none()
        && history.operation.applied_index.is_none()
        && record.condition.status == QualificationKubernetesConditionStatus::False;
    if !(ready_shape || not_ready_shape) {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    match record.outcome {
        QualificationKubernetesCampaignRecordOutcome::Ready => {
            let classified = classify_probe(record.reply.as_ref(), expectation);
            if classified.outcome != QualificationKubernetesCampaignRecordOutcome::Ready
                || !probe_binding_matches(classified, record, history, expected_sequence)
                || !ready_shape
                || record.control_error.is_some()
                || record.readiness_update_error.is_some()
            {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
        }
        QualificationKubernetesCampaignRecordOutcome::ReadinessUpdateFailed => {
            let classified = retained_probe_classification(record, expectation);
            if record.readiness_update_error.is_none()
                || classified.is_none_or(|classified| {
                    !probe_binding_matches(classified, record, history, expected_sequence)
                })
            {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
        }
        QualificationKubernetesCampaignRecordOutcome::NotReady => {
            let classified = record
                .reply
                .as_ref()
                .map(|reply| classify_probe(Some(reply), expectation));
            if record.control_error.is_some()
                || record.readiness_update_error.is_some()
                || classified.is_none_or(|classified| {
                    classified.outcome != QualificationKubernetesCampaignRecordOutcome::NotReady
                        || !probe_binding_matches(classified, record, history, expected_sequence)
                })
                || !not_ready_shape
            {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
        }
        QualificationKubernetesCampaignRecordOutcome::ControlUnavailable => {
            let classified = classify_probe(None, expectation);
            if record.reply.is_some()
                || record.control_error.is_none()
                || record.control_error == Some(QualificationKubernetesPortError::Cancelled)
                || record.readiness_update_error.is_some()
                || classified.outcome
                    != QualificationKubernetesCampaignRecordOutcome::ControlUnavailable
                || !probe_binding_matches(classified, record, history, expected_sequence)
                || !not_ready_shape
            {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
        }
        QualificationKubernetesCampaignRecordOutcome::InvalidReply => {
            let classified = retained_probe_classification(record, expectation);
            if record.control_error.is_some()
                || record.readiness_update_error.is_some()
                || classified.is_none_or(|classified| {
                    classified.outcome != QualificationKubernetesCampaignRecordOutcome::InvalidReply
                        || !probe_binding_matches(classified, record, history, expected_sequence)
                })
                || !not_ready_shape
            {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
        }
        QualificationKubernetesCampaignRecordOutcome::CampaignCancelled => {
            let stopped = not_ready_probe(
                QualificationKubernetesReadinessReason::CampaignStopped,
                QualificationKubernetesCampaignRecordOutcome::CampaignCancelled,
            );
            let binding_is_stopped = record.readiness_update_error.is_none()
                && probe_binding_matches(stopped, record, history, expected_sequence);
            let binding_is_classified = retained_probe_classification(record, expectation)
                .is_some_and(|classified| {
                    probe_binding_matches(classified, record, history, expected_sequence)
                });
            if !not_ready_shape && !ready_shape {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
            if !binding_is_stopped && !binding_is_classified {
                return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
            }
        }
        _ => return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome),
    }
    Ok(())
}

fn retained_probe_classification(
    record: &QualificationKubernetesCampaignRecord,
    expectation: &QualificationKubernetesReadinessExpectation,
) -> Option<ClassifiedProbe> {
    match (&record.reply, record.control_error) {
        (Some(reply), None) => Some(classify_probe(Some(reply), expectation)),
        (None, Some(error)) if error != QualificationKubernetesPortError::Cancelled => {
            Some(classify_probe(None, expectation))
        }
        (None, None) => Some(not_ready_probe(
            QualificationKubernetesReadinessReason::ProbeRejected,
            QualificationKubernetesCampaignRecordOutcome::InvalidReply,
        )),
        _ => None,
    }
}

fn probe_binding_matches(
    mut classified: ClassifiedProbe,
    record: &QualificationKubernetesCampaignRecord,
    history: &QualificationKubernetesReadinessHistoryV3,
    expected_sequence: usize,
) -> bool {
    classified.history.sample_sequence = expected_sequence;
    record.condition == classified.condition && history.operation == classified.history
}

fn validate_sequential_record(
    config: &QualificationKubernetesCampaignConfig,
    record: &QualificationKubernetesCampaignRecord,
    scheduled: &QualificationSequentialInvocation,
    builder: &mut QualificationSequentialHistoryBuilder,
) -> Result<
    crate::qualification_sequential::QualificationSequentialObservation,
    QualificationKubernetesCampaignArtifactError,
> {
    let member_index = scheduled
        .member_index()
        .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    let expected_command = scheduled.command();
    if record.action != QualificationKubernetesCampaignAction::SequentialOperation
        || record.member_index != member_index
        || record.pod_name != qualification_pod_name(member_index)
        || record.schedule_operation_id.as_deref() != Some(scheduled.operation_id.as_str())
        || record.readiness_update_error.is_some()
        || record.condition != QualificationKubernetesReadinessCondition::ready()
        || !record
            .command
            .as_ref()
            .is_some_and(|command| serialized_equal(command, &expected_command))
        || record.reply.is_some() == record.control_error.is_some()
        || config.member_count == 0
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    let observation = builder
        .observe(
            scheduled,
            record.started_ns,
            record.completed_ns,
            record.reply.as_ref(),
        )
        .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    let expected_outcome =
        if record.outcome == QualificationKubernetesCampaignRecordOutcome::CampaignCancelled {
            QualificationKubernetesCampaignRecordOutcome::CampaignCancelled
        } else if !observation.expected {
            QualificationKubernetesCampaignRecordOutcome::SequentialOperationIndeterminate
        } else if scheduled.operation_index == 10 {
            QualificationKubernetesCampaignRecordOutcome::SequentialOperationRejected
        } else {
            QualificationKubernetesCampaignRecordOutcome::SequentialOperationAccepted
        };
    if record.outcome != expected_outcome {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    Ok(observation)
}

fn validate_handle_cleanup_record(
    config: &QualificationKubernetesCampaignConfig,
    record: &QualificationKubernetesCampaignRecord,
    scheduled: &QualificationSequentialInvocation,
) -> Result<bool, QualificationKubernetesCampaignArtifactError> {
    let member_index = scheduled
        .member_index()
        .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidOutcome)?;
    let expected_command = QualificationNodeCommand::ForgetLease {
        lease_handle: scheduled.operation_id.clone(),
    };
    if record.action != QualificationKubernetesCampaignAction::LeaseHandleCleanup
        || record.member_index != member_index
        || record.pod_name != qualification_pod_name(member_index)
        || record.schedule_operation_id.as_deref() != Some(scheduled.operation_id.as_str())
        || record.readiness_update_error.is_some()
        || record.condition
            != QualificationKubernetesReadinessCondition::not_ready(
                QualificationKubernetesReadinessReason::CampaignStopped,
            )
        || !record
            .command
            .as_ref()
            .is_some_and(|command| serialized_equal(command, &expected_command))
        || record.reply.is_some() == record.control_error.is_some()
        || config.member_count == 0
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    let forgotten = matches!(
        record.reply,
        Some(QualificationNodeReply::LeaseHandleForgotten)
    ) && record.control_error.is_none();
    let expected_outcome = if forgotten {
        QualificationKubernetesCampaignRecordOutcome::LeaseHandleForgotten
    } else {
        QualificationKubernetesCampaignRecordOutcome::LeaseHandleCleanupIndeterminate
    };
    if record.outcome != expected_outcome {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome);
    }
    Ok(forgotten)
}

fn serialized_equal<T: Serialize>(left: &T, right: &T) -> bool {
    match (serde_json::to_vec(left), serde_json::to_vec(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Fixed candidate-only summary written beside the transcript and both
/// history artifacts.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationKubernetesCampaignSummary {
    /// Summary schema identifier.
    schema_version: String,
    /// This slice remains experimental.
    experimental: bool,
    /// This slice never claims complete production qualification.
    qualification_complete: bool,
    /// This slice never counts as production evidence by itself.
    counts_for_production: bool,
    /// Bounded probe-campaign outcome.
    status: QualificationKubernetesCampaignStatus,
    /// Configured voter count.
    topology_members: usize,
    /// Configured complete fleet rounds.
    rounds_planned: usize,
    /// Fully completed fleet rounds.
    rounds_completed: usize,
    /// Readiness samples retained in the fragment.
    readiness_samples: usize,
    /// Whether every final false-condition update succeeded.
    cleanup_complete: bool,
    /// Whether every invoked process-local lease handle was reclaimed.
    lease_handle_cleanup_complete: bool,
    /// Existing v3 history schema consumed by these readiness rows.
    readiness_history_schema: String,
    /// Digest of the exact bounded command/reply transcript bytes.
    transcript_sha256: QualificationSha256,
    /// Digest of the exact readiness-only v3 fragment bytes.
    readiness_history_sha256: QualificationSha256,
    /// This output intentionally lacks batch/watch/restore rows.
    concurrent_history_complete: bool,
    /// Frozen sequential schedule schema emitted beside this summary.
    sequential_schedule_schema: String,
    /// Frozen digest-only sequential history schema.
    sequential_history_schema: String,
    /// Exact fixed number of deployed operations planned.
    sequential_operations_planned: usize,
    /// Number of deployed operations actually invoked and recorded.
    sequential_operations_completed: usize,
    /// Digest of the exact frozen v1 schedule bytes.
    sequential_schedule_sha256: QualificationSha256,
    /// Digest of the exact emitted v1 history bytes.
    sequential_history_sha256: QualificationSha256,
    /// Whether every scheduled operation and its readiness sample completed.
    sequential_history_complete: bool,
    /// Complete fixed remaining #143 gate inventory.
    remaining_acceptance: Vec<String>,
}

impl QualificationKubernetesCampaignSummary {
    /// Revalidated terminal campaign status.
    #[must_use]
    pub const fn status(&self) -> QualificationKubernetesCampaignStatus {
        self.status
    }

    /// Whether the complete frozen v1 schedule and post-operation samples passed.
    #[must_use]
    pub const fn sequential_history_complete(&self) -> bool {
        self.sequential_history_complete
    }

    /// Digest of the exact persisted frozen v1 schedule bytes.
    #[must_use]
    pub const fn sequential_schedule_sha256(&self) -> &QualificationSha256 {
        &self.sequential_schedule_sha256
    }

    /// Digest of the exact persisted frozen v1 history bytes.
    #[must_use]
    pub const fn sequential_history_sha256(&self) -> &QualificationSha256 {
        &self.sequential_history_sha256
    }

    /// Construct an honest candidate-only summary from one completed run.
    #[must_use]
    fn from_validated_outcome(
        config: &QualificationKubernetesCampaignConfig,
        outcome: &QualificationKubernetesCampaignOutcome,
        validated: ValidatedCampaignOutcome,
        transcript_sha256: QualificationSha256,
        readiness_history_sha256: QualificationSha256,
        sequential_schedule_sha256: QualificationSha256,
        sequential_history_sha256: QualificationSha256,
    ) -> Self {
        Self {
            schema_version: QUALIFICATION_KUBERNETES_CAMPAIGN_SUMMARY_SCHEMA.to_owned(),
            experimental: true,
            qualification_complete: false,
            counts_for_production: false,
            status: validated.status,
            topology_members: config.member_count,
            rounds_planned: config.rounds,
            rounds_completed: validated.completed_rounds,
            readiness_samples: outcome.readiness_history.len(),
            cleanup_complete: validated.cleanup_complete,
            lease_handle_cleanup_complete: validated.lease_handle_cleanup_complete,
            readiness_history_schema: QUALIFICATION_CONCURRENT_HISTORY_SCHEMA_V3.to_owned(),
            transcript_sha256,
            readiness_history_sha256,
            concurrent_history_complete: false,
            sequential_schedule_schema: QUALIFICATION_SEQUENTIAL_SCHEDULE_SCHEMA_V1.to_owned(),
            sequential_history_schema: QUALIFICATION_SEQUENTIAL_HISTORY_SCHEMA_V1.to_owned(),
            sequential_operations_planned: QUALIFICATION_SEQUENTIAL_OPERATION_COUNT,
            sequential_operations_completed: outcome.sequential_history.len(),
            sequential_schedule_sha256,
            sequential_history_sha256,
            sequential_history_complete: validated.sequential_history_complete,
            remaining_acceptance: SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V4
                .iter()
                .map(|gate| (*gate).to_owned())
                .collect(),
        }
    }
}

/// Redaction-safe failure to encode or atomically publish campaign artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QualificationKubernetesCampaignArtifactError {
    /// The supplied campaign configuration did not satisfy its closed bounds.
    #[error("qualification Kubernetes campaign configuration is invalid")]
    InvalidCampaign,
    /// The in-memory outcome contradicted its canonical schedule or transcript.
    #[error("qualification Kubernetes campaign outcome is invalid")]
    InvalidOutcome,
    /// The destination was relative, non-canonical, or otherwise unsafe.
    #[error("qualification Kubernetes artifact destination is invalid")]
    InvalidDestination,
    /// The destination already exists and is never overwritten.
    #[error("qualification Kubernetes artifact destination already exists")]
    DestinationExists,
    /// Artifact serialization failed.
    #[error("qualification Kubernetes artifact encoding failed")]
    Encoding,
    /// The encoded artifact exceeded its fixed upper bound.
    #[error("qualification Kubernetes artifact exceeded its bound")]
    TooLarge,
    /// Private staging, durability, or atomic publication failed.
    #[error("qualification Kubernetes artifact publication failed")]
    Publication,
}

/// Atomically persist the bounded transcript, readiness fragment, frozen v1
/// schedule/history pair, and summary.
///
/// `output_directory` must be a new absolute direct child of an existing,
/// canonical directory. Existing paths are never replaced. Files are private
/// (`0600`) and the directory is private (`0700`) on Unix.
pub fn persist_qualification_kubernetes_campaign(
    output_directory: &Path,
    config: &QualificationKubernetesCampaignConfig,
    outcome: &QualificationKubernetesCampaignOutcome,
) -> Result<QualificationKubernetesCampaignSummary, QualificationKubernetesCampaignArtifactError> {
    config
        .validate()
        .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidCampaign)?;
    let validated = validate_campaign_outcome(config, outcome)?;
    let (parent, destination_name) = validate_artifact_destination(output_directory)?;
    let transcript = encode_json_lines(&outcome.transcript)?;
    let readiness_history = encode_json_lines(&outcome.readiness_history)?;
    let sequential_schedule = encode_json_lines(&outcome.sequential_schedule)?;
    let sequential_history = encode_json_lines(&outcome.sequential_history)?;
    let summary = QualificationKubernetesCampaignSummary::from_validated_outcome(
        config,
        outcome,
        validated,
        QualificationSha256::digest(&transcript),
        QualificationSha256::digest(&readiness_history),
        QualificationSha256::digest(&sequential_schedule),
        QualificationSha256::digest(&sequential_history),
    );
    let mut summary_bytes = serde_json::to_vec_pretty(&summary)
        .map_err(|_| QualificationKubernetesCampaignArtifactError::Encoding)?;
    summary_bytes.push(b'\n');
    if summary_bytes.len() > CAMPAIGN_ARTIFACT_MAX_BYTES {
        return Err(QualificationKubernetesCampaignArtifactError::TooLarge);
    }

    let staging = tempfile::Builder::new()
        .prefix(".opc-session-kubernetes-campaign-")
        .tempdir_in(&parent)
        .map_err(|_| QualificationKubernetesCampaignArtifactError::Publication)?;
    set_private_directory_permissions(staging.path())?;
    write_private_artifact(staging.path(), CAMPAIGN_TRANSCRIPT_FILE, &transcript)?;
    write_private_artifact(
        staging.path(),
        CAMPAIGN_READINESS_HISTORY_FILE,
        &readiness_history,
    )?;
    write_private_artifact(
        staging.path(),
        CAMPAIGN_SEQUENTIAL_SCHEDULE_FILE,
        &sequential_schedule,
    )?;
    write_private_artifact(
        staging.path(),
        CAMPAIGN_SEQUENTIAL_HISTORY_FILE,
        &sequential_history,
    )?;
    write_private_artifact(staging.path(), CAMPAIGN_SUMMARY_FILE, &summary_bytes)?;
    sync_directory(staging.path())?;
    publish_staging_directory(&parent, staging.path(), &destination_name)?;
    sync_directory(&parent)?;
    Ok(summary)
}

/// Validate the artifact destination before any Kubernetes operation begins.
///
/// Validation is repeated during atomic publication to close replacement
/// races. The destination is never created by this preflight check.
pub fn validate_qualification_kubernetes_campaign_artifact_destination(
    output_directory: &Path,
) -> Result<(), QualificationKubernetesCampaignArtifactError> {
    validate_artifact_destination(output_directory).map(|_| ())
}

fn validate_artifact_destination(
    output_directory: &Path,
) -> Result<(std::path::PathBuf, std::ffi::OsString), QualificationKubernetesCampaignArtifactError>
{
    if !output_directory.is_absolute()
        || output_directory
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidDestination);
    }
    let parent = output_directory
        .parent()
        .ok_or(QualificationKubernetesCampaignArtifactError::InvalidDestination)?;
    let destination_name = output_directory
        .file_name()
        .ok_or(QualificationKubernetesCampaignArtifactError::InvalidDestination)?
        .to_os_string();
    if !destination_name.to_str().is_some_and(is_bounded_identifier) {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidDestination);
    }
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| QualificationKubernetesCampaignArtifactError::InvalidDestination)?;
    if canonical_parent != parent {
        return Err(QualificationKubernetesCampaignArtifactError::InvalidDestination);
    }
    match fs::symlink_metadata(output_directory) {
        Ok(_) => Err(QualificationKubernetesCampaignArtifactError::DestinationExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok((canonical_parent, destination_name))
        }
        Err(_) => Err(QualificationKubernetesCampaignArtifactError::InvalidDestination),
    }
}

fn encode_json_lines<T: Serialize>(
    rows: &[T],
) -> Result<Vec<u8>, QualificationKubernetesCampaignArtifactError> {
    let mut encoded = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut encoded, row)
            .map_err(|_| QualificationKubernetesCampaignArtifactError::Encoding)?;
        encoded.push(b'\n');
        if encoded.len() > CAMPAIGN_ARTIFACT_MAX_BYTES {
            return Err(QualificationKubernetesCampaignArtifactError::TooLarge);
        }
    }
    Ok(encoded)
}

fn write_private_artifact(
    directory: &Path,
    name: &str,
    encoded: &[u8],
) -> Result<(), QualificationKubernetesCampaignArtifactError> {
    if encoded.len() > CAMPAIGN_ARTIFACT_MAX_BYTES {
        return Err(QualificationKubernetesCampaignArtifactError::TooLarge);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(directory.join(name))
        .map_err(|_| QualificationKubernetesCampaignArtifactError::Publication)?;
    file.write_all(encoded)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|_| QualificationKubernetesCampaignArtifactError::Publication)
}

fn set_private_directory_permissions(
    directory: &Path,
) -> Result<(), QualificationKubernetesCampaignArtifactError> {
    #[cfg(unix)]
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| QualificationKubernetesCampaignArtifactError::Publication)?;
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), QualificationKubernetesCampaignArtifactError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| QualificationKubernetesCampaignArtifactError::Publication)
}

#[cfg(unix)]
fn publish_staging_directory(
    parent: &Path,
    staging: &Path,
    destination_name: &std::ffi::OsStr,
) -> Result<(), QualificationKubernetesCampaignArtifactError> {
    use rustix::fs::{renameat_with, RenameFlags};

    let parent_descriptor = File::open(parent)
        .map_err(|_| QualificationKubernetesCampaignArtifactError::Publication)?;
    let staging_name = staging
        .file_name()
        .ok_or(QualificationKubernetesCampaignArtifactError::Publication)?;
    renameat_with(
        &parent_descriptor,
        staging_name,
        &parent_descriptor,
        destination_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists {
            QualificationKubernetesCampaignArtifactError::DestinationExists
        } else {
            QualificationKubernetesCampaignArtifactError::Publication
        }
    })
}

#[cfg(not(unix))]
fn publish_staging_directory(
    parent: &Path,
    staging: &Path,
    destination_name: &std::ffi::OsStr,
) -> Result<(), QualificationKubernetesCampaignArtifactError> {
    let destination = parent.join(destination_name);
    if destination.exists() {
        return Err(QualificationKubernetesCampaignArtifactError::DestinationExists);
    }
    fs::rename(staging, destination)
        .map_err(|_| QualificationKubernetesCampaignArtifactError::Publication)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;

    struct FakePort {
        replies: Mutex<VecDeque<Result<QualificationNodeReply, QualificationKubernetesPortError>>>,
        forget_replies:
            Mutex<VecDeque<Result<QualificationNodeReply, QualificationKubernetesPortError>>>,
        invoked_commands: Mutex<Vec<QualificationNodeCommand>>,
        invoked_pods: Mutex<Vec<String>>,
        published: Mutex<Vec<QualificationKubernetesReadinessCondition>>,
        fail_publish_at: Option<usize>,
        cancel_on_probe: Option<Arc<QualificationKubernetesCampaignCancellation>>,
    }

    impl FakePort {
        fn ready(config: &QualificationKubernetesCampaignConfig) -> Self {
            let expectations = qualification_kubernetes_readiness_expectations(config.member_count)
                .expect("fixed readiness expectations");
            let leader_id = expectations[0].expected_node_id();
            let readiness_replies = || {
                expectations
                    .iter()
                    .map(|expectation| Ok(ready_reply(expectation, leader_id)))
                    .collect::<Vec<_>>()
            };
            let mut replies = VecDeque::from(readiness_replies());
            for reply in sequential_replies(config) {
                replies.push_back(Ok(reply));
                replies.extend(readiness_replies());
            }
            for _ in 1..config.rounds {
                replies.extend(readiness_replies());
            }
            Self {
                replies: Mutex::new(replies),
                forget_replies: Mutex::new(VecDeque::new()),
                invoked_commands: Mutex::new(Vec::new()),
                invoked_pods: Mutex::new(Vec::new()),
                published: Mutex::new(Vec::new()),
                fail_publish_at: None,
                cancel_on_probe: None,
            }
        }
    }

    #[async_trait]
    impl QualificationKubernetesCampaignPort for FakePort {
        async fn invoke_command(
            &self,
            _namespace: &str,
            pod_name: &str,
            command: &QualificationNodeCommand,
            _cancellation: &QualificationKubernetesCampaignCancellation,
        ) -> Result<QualificationNodeReply, QualificationKubernetesPortError> {
            self.invoked_commands
                .lock()
                .expect("invoked command lock")
                .push(command.clone());
            self.invoked_pods
                .lock()
                .expect("invoked pod lock")
                .push(pod_name.to_owned());
            let reply = if matches!(command, QualificationNodeCommand::ForgetLease { .. }) {
                self.forget_replies
                    .lock()
                    .expect("forget reply lock")
                    .pop_front()
                    .unwrap_or(Ok(QualificationNodeReply::LeaseHandleForgotten))
            } else {
                self.replies
                    .lock()
                    .expect("reply lock")
                    .pop_front()
                    .unwrap_or(Err(QualificationKubernetesPortError::Unavailable))
            };
            if matches!(command, QualificationNodeCommand::Probe) {
                if let Some(cancellation) = &self.cancel_on_probe {
                    cancellation.cancel();
                }
            }
            reply
        }

        async fn publish_readiness(
            &self,
            _namespace: &str,
            _pod_name: &str,
            condition: &QualificationKubernetesReadinessCondition,
            cancellation: &QualificationKubernetesCampaignCancellation,
        ) -> Result<(), QualificationKubernetesPortError> {
            if cancellation.is_cancelled() {
                return Err(QualificationKubernetesPortError::Cancelled);
            }
            let mut published = self.published.lock().expect("published lock");
            let publication_index = published.len();
            published.push(condition.clone());
            if self.fail_publish_at == Some(publication_index) {
                Err(QualificationKubernetesPortError::Failed)
            } else {
                Ok(())
            }
        }
    }

    struct FakeClock {
        elapsed: std::sync::atomic::AtomicU64,
        cancel_on_sleep: Option<Arc<QualificationKubernetesCampaignCancellation>>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                elapsed: std::sync::atomic::AtomicU64::new(0),
                cancel_on_sleep: None,
            }
        }
    }

    #[async_trait]
    impl QualificationKubernetesCampaignClock for FakeClock {
        fn elapsed_ns(&self) -> u64 {
            self.elapsed.fetch_add(1, Ordering::Relaxed)
        }

        async fn sleep(&self, duration: Duration) {
            self.elapsed.fetch_add(
                u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            if let Some(cancellation) = &self.cancel_on_sleep {
                cancellation.cancel();
            }
        }
    }

    fn campaign_config(rounds: usize) -> QualificationKubernetesCampaignConfig {
        QualificationKubernetesCampaignConfig {
            namespace: "qualification".to_owned(),
            member_count: 3,
            rounds,
            probe_interval: Duration::from_secs(1),
            history_id: "candidate-history".to_owned(),
        }
    }

    fn readiness_expectation(
        member_count: usize,
        member_index: usize,
    ) -> QualificationKubernetesReadinessExpectation {
        qualification_kubernetes_readiness_expectations(member_count)
            .expect("fixed readiness expectations")[member_index]
            .clone()
    }

    fn ready_reply(
        expectation: &QualificationKubernetesReadinessExpectation,
        leader_id: u64,
    ) -> QualificationNodeReply {
        QualificationNodeReply::Readiness {
            ready: true,
            reason_code: QualificationReadinessCode::Ready,
            node_id: expectation.expected_node_id(),
            term: 2,
            leader_id: Some(leader_id),
            configured_voters: expectation.voter_count(),
            configured_voter_ids: Some(expectation.expected_voter_ids().to_vec()),
            fresh_reachable_voters: expectation.required_quorum(),
            agreeing_voters: expectation.required_quorum(),
            required_quorum: expectation.required_quorum(),
            committed_index: Some(7),
            applied_index: Some(7),
        }
    }

    fn sequential_replies(
        config: &QualificationKubernetesCampaignConfig,
    ) -> Vec<QualificationNodeReply> {
        let scope = QualificationSequentialRunScope::derive(&config.history_id)
            .expect("valid test run scope");
        let schedule = qualification_sequential_workload_for_run(
            config.member_count,
            &scope,
            qualification_kubernetes_long_lease_ttl_millis(config.member_count)
                .expect("valid test lease TTL"),
        )
        .expect("valid test schedule");
        let owner = |index: usize| match &schedule[index].operation {
            QualificationSequentialOperation::LeaseAcquire { owner, .. } => owner.clone(),
            _ => panic!("test schedule owner operation is fixed"),
        };
        let owner_a = qualification_owner_sha256(&owner(3));
        let owner_b = qualification_owner_sha256(&owner(7));
        let value_1 = qualification_value_sha256(b"qualification-value-1");
        let value_2 = qualification_value_sha256(b"qualification-value-2");
        let value_3 = qualification_value_sha256(b"qualification-value-3");
        vec![
            QualificationNodeReply::LeaseAcquired { fence: 10 },
            QualificationNodeReply::LeaseAcquired { fence: 11 },
            QualificationNodeReply::Released,
            QualificationNodeReply::LeaseAcquired { fence: 20 },
            QualificationNodeReply::CompareAndSet {
                applied: true,
                current_generation: Some(1),
            },
            QualificationNodeReply::Record {
                present: true,
                generation: Some(1),
                owner_sha256: Some(owner_a),
                fence: Some(20),
                value_sha256: Some(value_1),
            },
            QualificationNodeReply::Released,
            QualificationNodeReply::LeaseAcquired { fence: 21 },
            QualificationNodeReply::CompareAndSet {
                applied: true,
                current_generation: Some(2),
            },
            QualificationNodeReply::Error {
                code: crate::qualification::QualificationNodeErrorCode::MutationRejected,
            },
            QualificationNodeReply::Record {
                present: true,
                generation: Some(2),
                owner_sha256: Some(owner_b.clone()),
                fence: Some(21),
                value_sha256: Some(value_2),
            },
            QualificationNodeReply::CompareAndSet {
                applied: true,
                current_generation: Some(3),
            },
            QualificationNodeReply::Record {
                present: true,
                generation: Some(3),
                owner_sha256: Some(owner_b.clone()),
                fence: Some(21),
                value_sha256: Some(value_3.clone()),
            },
            QualificationNodeReply::Released,
            QualificationNodeReply::Record {
                present: true,
                generation: Some(3),
                owner_sha256: Some(owner_b),
                fence: Some(21),
                value_sha256: Some(value_3),
            },
        ]
    }

    #[cfg(unix)]
    fn write_fake_kubectl(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("fake kubectl directory");
        let executable = directory.path().join("kubectl");
        fs::write(&executable, format!("#!/bin/sh\nset -eu\n{body}\n"))
            .expect("write fake kubectl");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("make fake kubectl executable");
        (directory, executable)
    }

    #[cfg(unix)]
    fn appended_path(path: &Path, suffix: &str) -> std::path::PathBuf {
        let mut encoded = path.as_os_str().to_os_string();
        encoded.push(suffix);
        encoded.into()
    }

    #[test]
    fn kubectl_arguments_never_use_a_shell_or_network_control_port() {
        let control = control_client_arguments("qualification", "opc-session-ha-0-0");
        let values = control
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            vec![
                "--namespace",
                "qualification",
                "exec",
                "-i",
                "opc-session-ha-0-0",
                "--container",
                "session-quorum",
                "--",
                "opc-session-quorum-node",
                "--control-client",
                "/var/lib/opc-session-qualification/control/node.sock",
            ]
        );
        assert!(!values
            .iter()
            .any(|value| matches!(value.as_str(), "sh" | "bash")));
    }

    #[test]
    fn status_patch_targets_only_the_status_subresource_and_condition_type() {
        let condition = QualificationKubernetesReadinessCondition::ready();
        let patch = serde_json::to_string(&json!({
            "status": { "conditions": [&condition] },
        }))
        .expect("serialize patch");
        let arguments = status_patch_arguments("qualification", "opc-session-ha-0-0", &patch)
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(arguments.contains(&"--subresource=status".to_owned()));
        assert!(arguments.contains(&"--type=strategic".to_owned()));
        assert!(patch.contains(QUALIFICATION_KUBERNETES_DURABLE_READINESS_CONDITION));
        assert!(!patch.contains("certificate"));
        assert!(!patch.contains("identity"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn kubectl_timeout_kills_and_reaps_the_exact_process() {
        let (_directory, executable) = write_fake_kubectl(
            r#"printf '%s\n' "$$" > "${0}.pid"
exec sleep 30"#,
        );
        let cancellation = QualificationKubernetesCampaignCancellation::new();
        let result = run_kubectl(
            executable.as_os_str(),
            &[],
            &[],
            Duration::from_millis(250),
            1_024,
            1_024,
            &cancellation,
        )
        .await;
        assert!(matches!(
            result,
            Err(QualificationKubernetesPortError::Timeout)
        ));
        let pid = fs::read_to_string(appended_path(&executable, ".pid"))
            .expect("fake kubectl PID")
            .trim()
            .parse::<u32>()
            .expect("numeric fake kubectl PID");
        assert!(
            !std::path::PathBuf::from(format!("/proc/{pid}")).exists(),
            "timed-out kubectl must be reaped before return"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn kubectl_cancellation_kills_and_reaps_the_in_flight_process() {
        let (_directory, executable) = write_fake_kubectl(
            r#"printf '%s\n' "$$" > "${0}.pid"
exec sleep 30"#,
        );
        let pid_path = appended_path(&executable, ".pid");
        let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
        let task_cancellation = Arc::clone(&cancellation);
        let task_executable = executable.clone();
        let task = tokio::spawn(async move {
            run_kubectl(
                task_executable.as_os_str(),
                &[],
                &[],
                Duration::from_secs(30),
                1_024,
                1_024,
                task_cancellation.as_ref(),
            )
            .await
        });

        let pid_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !pid_path.exists() {
            assert!(
                tokio::time::Instant::now() < pid_deadline,
                "fake kubectl did not publish its PID"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("cancelled kubectl returned within its reap bound")
            .expect("join cancelled kubectl");
        assert!(matches!(
            result,
            Err(QualificationKubernetesPortError::Cancelled)
        ));
        let pid = fs::read_to_string(pid_path)
            .expect("fake kubectl PID")
            .trim()
            .parse::<u32>()
            .expect("numeric fake kubectl PID");
        assert!(
            !std::path::PathBuf::from(format!("/proc/{pid}")).exists(),
            "cancelled kubectl must be reaped before return"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn phase_deadline_cancels_and_reaps_the_exact_kubectl_process() {
        let (_directory, executable) = write_fake_kubectl(
            r#"printf '%s\n' "$$" > "${0}.pid"
exec sleep 30"#,
        );
        let pid_path = appended_path(&executable, ".pid");
        let port = KubectlQualificationKubernetesCampaignPort::with_executable(
            executable.into_os_string(),
            Duration::from_secs(30),
        );
        let cancellation = QualificationKubernetesCampaignCancellation::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let result = invoke_campaign_command(
            &port,
            "qualification",
            "opc-session-ha-0-0",
            &QualificationNodeCommand::Probe,
            &cancellation,
            Some(deadline),
        )
        .await;

        assert!(matches!(
            result,
            Err(QualificationKubernetesPortError::Timeout)
        ));
        let pid = fs::read_to_string(pid_path)
            .expect("fake kubectl PID")
            .trim()
            .parse::<u32>()
            .expect("numeric fake kubectl PID");
        assert!(
            !std::path::PathBuf::from(format!("/proc/{pid}")).exists(),
            "phase-deadline kubectl must be reaped before return"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kubectl_output_overflow_and_nonzero_exit_fail_closed() {
        let cancellation = QualificationKubernetesCampaignCancellation::new();
        let oversized = "x".repeat(2_049);
        let (_overflow_directory, overflow_executable) =
            write_fake_kubectl(&format!("printf '%s' '{oversized}'"));
        let overflow = run_kubectl(
            overflow_executable.as_os_str(),
            &[],
            &[],
            Duration::from_secs(2),
            2_048,
            1_024,
            &cancellation,
        )
        .await;
        assert!(matches!(
            overflow,
            Err(QualificationKubernetesPortError::OutputTooLarge)
        ));

        let (_failure_directory, failure_executable) = write_fake_kubectl("exit 9");
        let failure = run_kubectl(
            failure_executable.as_os_str(),
            &[],
            &[],
            Duration::from_secs(2),
            1_024,
            1_024,
            &cancellation,
        )
        .await;
        assert!(matches!(
            failure,
            Err(QualificationKubernetesPortError::Failed)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kubectl_probe_rejects_malformed_and_duplicate_replies() {
        let cancellation = QualificationKubernetesCampaignCancellation::new();
        let (_malformed_directory, malformed_executable) =
            write_fake_kubectl("IFS= read -r _\nprintf '%s\\n' 'not-json'");
        let malformed = KubectlQualificationKubernetesCampaignPort::with_executable(
            malformed_executable.into_os_string(),
            Duration::from_secs(2),
        )
        .invoke_command(
            "qualification",
            "opc-session-ha-0-0",
            &QualificationNodeCommand::Probe,
            &cancellation,
        )
        .await;
        assert!(matches!(
            malformed,
            Err(QualificationKubernetesPortError::InvalidReply)
        ));

        let (_duplicate_directory, duplicate_executable) = write_fake_kubectl(
            "IFS= read -r _\nprintf '%s\\n%s\\n' '{\"reply\":\"initialized\"}' '{\"reply\":\"initialized\"}'",
        );
        let duplicate = KubectlQualificationKubernetesCampaignPort::with_executable(
            duplicate_executable.into_os_string(),
            Duration::from_secs(2),
        )
        .invoke_command(
            "qualification",
            "opc-session-ha-0-0",
            &QualificationNodeCommand::Probe,
            &cancellation,
        )
        .await;
        assert!(matches!(
            duplicate,
            Err(QualificationKubernetesPortError::InvalidReply)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kubectl_control_adapter_forwards_one_typed_mutation_unchanged() {
        let (_directory, executable) = write_fake_kubectl(
            r#"IFS= read -r input
printf '%s\n' "$input" > "${0}.stdin"
printf '%s\n' '{"reply":"lease_acquired","fence":7}'"#,
        );
        let port = KubectlQualificationKubernetesCampaignPort::with_executable(
            executable.clone().into_os_string(),
            Duration::from_secs(2),
        );
        let command = QualificationNodeCommand::Acquire {
            lease_handle: "op-1".to_owned(),
            stable_id: "session-a".to_owned(),
            owner: "owner-a".to_owned(),
            ttl_millis: 60_000,
        };
        let reply = port
            .invoke_command(
                "qualification",
                "opc-session-ha-0-0",
                &command,
                &QualificationKubernetesCampaignCancellation::new(),
            )
            .await
            .expect("typed mutation reply");
        assert!(matches!(
            reply,
            QualificationNodeReply::LeaseAcquired { fence: 7 }
        ));
        let forwarded =
            fs::read(appended_path(&executable, ".stdin")).expect("captured control command");
        let expected = serde_json::to_vec(&command).expect("encode expected command");
        assert_eq!(forwarded, [expected, b"\n".to_vec()].concat());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kubectl_status_adapter_uses_only_the_status_subresource_command() {
        let (_directory, executable) = write_fake_kubectl(r#"printf '%s\n' "$@" > "${0}.args""#);
        let port = KubectlQualificationKubernetesCampaignPort::with_executable(
            executable.clone().into_os_string(),
            Duration::from_secs(2),
        );
        let debug = format!("{port:?}");
        assert!(!debug.contains(&executable.to_string_lossy().into_owned()));
        let condition = QualificationKubernetesReadinessCondition::ready();
        port.publish_readiness(
            "qualification",
            "opc-session-ha-0-0",
            &condition,
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("publish fake readiness");

        let patch = serde_json::to_string(&json!({
            "status": { "conditions": [&condition] },
        }))
        .expect("serialize expected patch");
        let expected = status_patch_arguments("qualification", "opc-session-ha-0-0", &patch)
            .into_iter()
            .map(|value| value.into_string().expect("UTF-8 test argument"))
            .collect::<Vec<_>>();
        let actual = fs::read_to_string(appended_path(&executable, ".args"))
            .expect("fake kubectl arguments")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(
            actual
                .iter()
                .filter(|argument| argument.as_str() == "--subresource=status")
                .count(),
            1
        );
        assert!(!actual.iter().any(|argument| argument.contains("exec")));
    }

    #[test]
    fn config_is_bounded_and_debug_redacts_operator_values() {
        let config = QualificationKubernetesCampaignConfig {
            namespace: "qualification".to_owned(),
            member_count: 3,
            rounds: 2,
            probe_interval: Duration::from_secs(1),
            history_id: "candidate-history".to_owned(),
        };
        assert_eq!(config.validate(), Ok(()));
        let debug = format!("{config:?}");
        assert!(!debug.contains("qualification"));
        assert!(!debug.contains("candidate-history"));

        let mut invalid = config.clone();
        invalid.rounds = 0;
        assert_eq!(
            invalid.validate(),
            Err(QualificationKubernetesCampaignConfigError::InvalidRounds)
        );
        invalid = config.clone();
        invalid.rounds = QUALIFICATION_KUBERNETES_MAX_CAMPAIGN_SAMPLES;
        assert_eq!(
            invalid.validate(),
            Err(QualificationKubernetesCampaignConfigError::InvalidRounds)
        );
        let mut exact_sample_bound = config.clone();
        exact_sample_bound.member_count = 5;
        exact_sample_bound.rounds = 1_985;
        assert_eq!(exact_sample_bound.validate(), Ok(()));
        exact_sample_bound.rounds = 1_986;
        assert_eq!(
            exact_sample_bound.validate(),
            Err(QualificationKubernetesCampaignConfigError::InvalidRounds)
        );
        invalid = config.clone();
        invalid.namespace = "Bad_Namespace".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(QualificationKubernetesCampaignConfigError::InvalidNamespace)
        );
        invalid = config;
        invalid.history_id = "secret/value".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(QualificationKubernetesCampaignConfigError::InvalidHistoryId)
        );
    }

    #[test]
    fn deployed_long_lease_covers_the_exact_admitted_kubectl_envelope() {
        assert_eq!(qualification_kubernetes_long_lease_call_count(3), Ok(42));
        assert_eq!(qualification_kubernetes_long_lease_call_count(5), Ok(66));
        let timeout_millis = u64::try_from(QUALIFICATION_KUBERNETES_COMMAND_TIMEOUT.as_millis())
            .expect("timeout fits u64");
        assert_eq!(timeout_millis, 50_000);
        for members in [3, 5] {
            let protected_calls =
                qualification_kubernetes_long_lease_call_count(members).expect("call count");
            let ttl = qualification_kubernetes_long_lease_ttl_millis(members).expect("lease TTL");
            let phase =
                qualification_kubernetes_long_lease_phase_budget(members).expect("phase budget");
            assert_eq!(
                ttl,
                u64::try_from(protected_calls + LONG_LEASE_MARGIN_KUBECTL_CALLS)
                    .expect("bounded calls")
                    * timeout_millis
            );
            assert_eq!(
                phase,
                QUALIFICATION_KUBERNETES_COMMAND_TIMEOUT
                    .checked_mul(u32::try_from(protected_calls).expect("bounded calls"))
                    .expect("bounded phase")
            );
            let ttl = Duration::from_millis(ttl);
            let margin = ttl.checked_sub(phase).expect("positive lease margin");
            assert_eq!(
                margin,
                QUALIFICATION_KUBERNETES_COMMAND_TIMEOUT
                    .checked_mul(
                        u32::try_from(LONG_LEASE_MARGIN_KUBECTL_CALLS)
                            .expect("bounded margin calls"),
                    )
                    .expect("bounded margin")
            );
            assert!(margin > KUBECTL_PHASE_ABORT_DRAIN_TIMEOUT);
            assert!(ttl <= opc_session_store::MAX_SESSION_TTL);

            let config = QualificationKubernetesCampaignConfig {
                member_count: members,
                ..campaign_config(1)
            };
            let scope =
                QualificationSequentialRunScope::derive(&config.history_id).expect("run scope");
            let schedule = qualification_sequential_workload_for_run(
                members,
                &scope,
                u64::try_from(ttl.as_millis()).expect("bounded TTL"),
            )
            .expect("scoped schedule");
            for (offset, invocation) in schedule.iter().enumerate() {
                if let QualificationSequentialOperation::LeaseAcquire { ttl_millis, .. } =
                    invocation.operation
                {
                    if offset == 0 {
                        assert_eq!(
                            ttl_millis,
                            crate::qualification_sequential::QUALIFICATION_SHORT_LEASE_MILLIS
                        );
                    } else {
                        assert_eq!(
                            ttl_millis,
                            u64::try_from(ttl.as_millis()).expect("bounded TTL")
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn readiness_requires_the_complete_fresh_barrier_contract() {
        let expectation = readiness_expectation(3, 0);
        let leader_id = expectation.expected_voter_ids()[1];
        let valid_ready = ready_reply(&expectation, leader_id);
        let ready = classify_probe(Some(&valid_ready), &expectation);
        assert!(ready.ready);
        assert_eq!(
            ready.condition.status,
            QualificationKubernetesConditionStatus::True
        );

        let mut zero_leader = ready_reply(&expectation, leader_id);
        if let QualificationNodeReply::Readiness { leader_id, .. } = &mut zero_leader {
            *leader_id = Some(0);
        }
        let rejected = classify_probe(Some(&zero_leader), &expectation);
        assert!(!rejected.ready);
        assert_eq!(rejected.history.term, None);

        let mut stale_apply = ready_reply(&expectation, leader_id);
        if let QualificationNodeReply::Readiness { applied_index, .. } = &mut stale_apply {
            *applied_index = Some(6);
        }
        let rejected = classify_probe(Some(&stale_apply), &expectation);
        assert!(!rejected.ready);
        assert_eq!(
            rejected.outcome,
            QualificationKubernetesCampaignRecordOutcome::InvalidReply
        );

        let no_quorum = QualificationNodeReply::Readiness {
            ready: false,
            reason_code: QualificationReadinessCode::NoQuorum,
            node_id: expectation.expected_node_id(),
            term: 2,
            leader_id: None,
            configured_voters: 3,
            configured_voter_ids: Some(expectation.expected_voter_ids().to_vec()),
            fresh_reachable_voters: 0,
            agreeing_voters: 0,
            required_quorum: 2,
            committed_index: None,
            applied_index: Some(5),
        };
        let unavailable = classify_probe(Some(&no_quorum), &expectation);
        assert!(!unavailable.ready);
        assert_eq!(
            unavailable.condition.reason,
            QualificationKubernetesReadinessReason::DurableQuorumUnavailable
        );
        assert_eq!(unavailable.history.applied_index, None);
    }

    #[tokio::test]
    async fn complete_campaign_publishes_only_fresh_readiness_then_clears_it() {
        let config = campaign_config(2);
        let port = FakePort::ready(&config);
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Passed
        );
        assert_eq!(outcome.completed_rounds, 2);
        assert!(outcome.cleanup_complete);
        assert!(outcome.lease_handle_cleanup_complete);
        assert!(outcome.sequential_history_complete);
        assert_eq!(outcome.sequential_history.len(), 15);
        assert_eq!(outcome.transcript.len(), 76);
        assert!(outcome
            .transcript
            .windows(2)
            .all(|rows| rows[0].round <= rows[1].round));
        assert_eq!(outcome.readiness_history.len(), 51);
        for (index, row) in outcome.readiness_history.iter().enumerate() {
            assert_eq!(row.history_operation_count, 51);
            assert_eq!(row.operation.sample_sequence, index / 3 + 1);
            assert_eq!(row.operation.state, "ready");
            assert_eq!(row.operation.term, Some(2));
        }
        let published = port.published.lock().expect("published lock");
        assert!(published[..3]
            .iter()
            .all(|condition| condition.status == QualificationKubernetesConditionStatus::False));
        assert!(published[3..54]
            .iter()
            .all(|condition| condition.status == QualificationKubernetesConditionStatus::True));
        assert!(published[54..]
            .iter()
            .all(|condition| condition.status == QualificationKubernetesConditionStatus::False));

        let commands = port.invoked_commands.lock().expect("command lock");
        let pods = port.invoked_pods.lock().expect("pod lock");
        let sequential_invocations = commands
            .iter()
            .zip(pods.iter())
            .filter(|(command, _)| {
                !matches!(
                    command,
                    QualificationNodeCommand::Probe | QualificationNodeCommand::ForgetLease { .. }
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(sequential_invocations.len(), 15);
        for ((actual_command, actual_pod), scheduled) in sequential_invocations
            .into_iter()
            .zip(outcome.sequential_schedule.iter())
        {
            assert_eq!(
                serde_json::to_value(actual_command).expect("actual command"),
                serde_json::to_value(scheduled.command()).expect("scheduled command")
            );
            assert_eq!(
                actual_pod,
                &qualification_pod_name(scheduled.member_index().expect("member index"))
            );
        }
    }

    #[tokio::test]
    async fn ambiguous_mutation_is_recorded_once_and_never_retried() {
        let config = campaign_config(1);
        let mut port = FakePort::ready(&config);
        *port
            .replies
            .get_mut()
            .expect("reply queue")
            .get_mut(3)
            .expect("first operation reply") = Err(QualificationKubernetesPortError::Timeout);
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Failed
        );
        assert!(!outcome.sequential_history_complete);
        assert_eq!(outcome.sequential_history.len(), 1);
        assert!(matches!(
            outcome.sequential_history[0].operation,
            crate::qualification_sequential::QualificationSequentialHistoryOperation::LeaseAcquire {
                outcome: crate::qualification_sequential::QualificationSequentialLeaseOutcome::Indeterminate,
                fence: None,
                ..
            }
        ));
        let commands = port.invoked_commands.lock().expect("command lock");
        assert_eq!(commands.len(), 5);
        assert!(matches!(
            commands[3],
            QualificationNodeCommand::Acquire { .. }
        ));
        assert_eq!(
            outcome
                .transcript
                .iter()
                .filter(|record| {
                    record.action == QualificationKubernetesCampaignAction::SequentialOperation
                })
                .count(),
            1
        );
        assert_eq!(
            outcome.transcript[6].outcome,
            QualificationKubernetesCampaignRecordOutcome::SequentialOperationIndeterminate
        );
        assert_eq!(
            outcome.transcript[6].control_error,
            Some(QualificationKubernetesPortError::Timeout)
        );
        assert!(matches!(
            commands[4],
            QualificationNodeCommand::ForgetLease { .. }
        ));
        assert!(validate_campaign_outcome(&config, &outcome).is_ok());
    }

    #[tokio::test]
    async fn ambiguous_handle_cleanup_is_recorded_once_and_never_retried() {
        let config = campaign_config(1);
        let port = FakePort::ready(&config);
        port.forget_replies
            .lock()
            .expect("forget reply lock")
            .push_back(Err(QualificationKubernetesPortError::Timeout));
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Failed
        );
        assert!(outcome.sequential_history_complete);
        assert!(!outcome.lease_handle_cleanup_complete);
        let expected_handles = outcome
            .sequential_schedule
            .iter()
            .filter(|scheduled| {
                matches!(
                    scheduled.operation,
                    QualificationSequentialOperation::LeaseAcquire { .. }
                )
            })
            .map(|scheduled| scheduled.operation_id.as_str())
            .collect::<Vec<_>>();
        let commands = port.invoked_commands.lock().expect("command lock");
        let actual_handles = commands
            .iter()
            .filter_map(|command| match command {
                QualificationNodeCommand::ForgetLease { lease_handle } => {
                    Some(lease_handle.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_handles, expected_handles);
        let cleanup = outcome
            .transcript
            .iter()
            .filter(|record| {
                record.action == QualificationKubernetesCampaignAction::LeaseHandleCleanup
            })
            .collect::<Vec<_>>();
        assert_eq!(cleanup.len(), expected_handles.len());
        assert_eq!(
            cleanup[0].outcome,
            QualificationKubernetesCampaignRecordOutcome::LeaseHandleCleanupIndeterminate
        );
        assert_eq!(
            cleanup[0].control_error,
            Some(QualificationKubernetesPortError::Timeout)
        );
        assert!(cleanup[1..].iter().all(|record| {
            record.outcome == QualificationKubernetesCampaignRecordOutcome::LeaseHandleForgotten
        }));
        assert!(validate_campaign_outcome(&config, &outcome).is_ok());
    }

    #[tokio::test]
    async fn contradictory_reply_fails_closed_without_authority_fields() {
        let config = campaign_config(1);
        let mut port = FakePort::ready(&config);
        let first_expectation = readiness_expectation(3, 0);
        let second_expectation = readiness_expectation(3, 1);
        let leader_id = first_expectation.expected_voter_ids()[0];
        port.replies = Mutex::new(VecDeque::from([
            Ok(QualificationNodeReply::Bound {
                node_index: 0,
                bind_addr: "127.0.0.1:7443".parse().expect("socket address"),
            }),
            Ok(ready_reply(&second_expectation, leader_id)),
            Ok(ready_reply(&first_expectation, leader_id)),
        ]));
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Failed
        );
        assert_eq!(outcome.readiness_history[0].operation.state, "not_ready");
        assert_eq!(outcome.readiness_history[0].operation.term, None);
        assert_eq!(outcome.readiness_history[0].operation.commit_index, None);
        assert_eq!(
            outcome.transcript[3].outcome,
            QualificationKubernetesCampaignRecordOutcome::InvalidReply
        );
        assert!(outcome.transcript[3].reply.is_none());
        assert_eq!(
            port.replies.lock().expect("reply lock").len(),
            2,
            "failure must latch before later ready replies can be published"
        );
        assert!(port
            .published
            .lock()
            .expect("published lock")
            .iter()
            .all(|condition| condition.status == QualificationKubernetesConditionStatus::False));
        assert!(validate_campaign_outcome(&config, &outcome).is_ok());
    }

    #[tokio::test]
    async fn cancellation_returns_partial_artifacts_and_clears_every_member() {
        let config = campaign_config(2);
        let port = FakePort::ready(&config);
        let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
        let clock = FakeClock {
            elapsed: std::sync::atomic::AtomicU64::new(0),
            cancel_on_sleep: Some(Arc::clone(&cancellation)),
        };
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &clock,
            cancellation.as_ref(),
        )
        .await
        .expect("valid campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Cancelled
        );
        assert_eq!(outcome.completed_rounds, 1);
        assert_eq!(outcome.readiness_history.len(), 6);
        assert_eq!(outcome.sequential_history.len(), 1);
        assert!(!outcome.sequential_history_complete);
        assert!(outcome.cleanup_complete);
        assert!(outcome.lease_handle_cleanup_complete);
        assert_eq!(port.published.lock().expect("published lock").len(), 12);
        assert!(validate_campaign_outcome(&config, &outcome).is_ok());
    }

    #[tokio::test]
    async fn status_update_failure_aborts_and_still_attempts_complete_cleanup() {
        let config = campaign_config(2);
        let expectation = readiness_expectation(3, 0);
        let leader_id = expectation.expected_voter_ids()[0];
        let port = FakePort {
            replies: Mutex::new(VecDeque::from([Ok(ready_reply(&expectation, leader_id))])),
            forget_replies: Mutex::new(VecDeque::new()),
            invoked_commands: Mutex::new(Vec::new()),
            invoked_pods: Mutex::new(Vec::new()),
            published: Mutex::new(Vec::new()),
            fail_publish_at: Some(3),
            cancel_on_probe: None,
        };
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Failed
        );
        assert_eq!(outcome.completed_rounds, 0);
        assert_eq!(outcome.transcript.len(), 7);
        assert!(outcome.cleanup_complete);
        assert_eq!(port.published.lock().expect("published lock").len(), 7);
        assert!(validate_campaign_outcome(&config, &outcome).is_ok());
    }

    #[tokio::test]
    async fn incomplete_initial_reset_never_invokes_or_publishes_a_ready_probe() {
        let config = campaign_config(2);
        let port = FakePort::ready(&config);
        let port = FakePort {
            fail_publish_at: Some(0),
            ..port
        };
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("bounded campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Failed
        );
        assert_eq!(outcome.completed_rounds, 0);
        assert!(outcome.readiness_history.is_empty());
        assert_eq!(outcome.transcript.len(), 6);
        assert_eq!(
            outcome.transcript[0].outcome,
            QualificationKubernetesCampaignRecordOutcome::ResetFailed
        );
        assert!(port
            .invoked_commands
            .lock()
            .expect("invoked command lock")
            .is_empty());
        assert!(port
            .published
            .lock()
            .expect("published lock")
            .iter()
            .all(|condition| condition.status == QualificationKubernetesConditionStatus::False));
        assert!(validate_campaign_outcome(&config, &outcome).is_ok());
    }

    #[tokio::test]
    async fn cancellation_during_probe_never_authorizes_its_ready_reply() {
        let config = campaign_config(1);
        let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
        let expectation = readiness_expectation(3, 0);
        let leader_id = expectation.expected_voter_ids()[0];
        let port = FakePort {
            replies: Mutex::new(VecDeque::from([Ok(ready_reply(&expectation, leader_id))])),
            forget_replies: Mutex::new(VecDeque::new()),
            invoked_commands: Mutex::new(Vec::new()),
            invoked_pods: Mutex::new(Vec::new()),
            published: Mutex::new(Vec::new()),
            fail_publish_at: None,
            cancel_on_probe: Some(Arc::clone(&cancellation)),
        };
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            cancellation.as_ref(),
        )
        .await
        .expect("valid campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Cancelled
        );
        assert_eq!(outcome.readiness_history.len(), 1);
        assert_eq!(outcome.readiness_history[0].operation.state, "not_ready");
        assert_eq!(
            outcome.transcript[3].outcome,
            QualificationKubernetesCampaignRecordOutcome::CampaignCancelled
        );
        assert_eq!(
            port.published.lock().expect("published lock")[3].status,
            QualificationKubernetesConditionStatus::False
        );
        assert!(validate_campaign_outcome(&config, &outcome).is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn artifacts_are_private_bound_and_atomically_non_overwriting() {
        let root = tempfile::tempdir().expect("artifact root");
        let canonical_root = fs::canonicalize(root.path()).expect("canonical root");
        let output = canonical_root.join("campaign-1");
        let config = campaign_config(1);
        let port = FakePort::ready(&config);
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign");
        let summary = persist_qualification_kubernetes_campaign(&output, &config, &outcome)
            .expect("persist campaign");

        assert_eq!(
            fs::metadata(&output)
                .expect("output metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let transcript = fs::read(output.join(CAMPAIGN_TRANSCRIPT_FILE)).expect("transcript");
        let history =
            fs::read(output.join(CAMPAIGN_READINESS_HISTORY_FILE)).expect("readiness history");
        let sequential_schedule =
            fs::read(output.join(CAMPAIGN_SEQUENTIAL_SCHEDULE_FILE)).expect("sequential schedule");
        let sequential_history =
            fs::read(output.join(CAMPAIGN_SEQUENTIAL_HISTORY_FILE)).expect("sequential history");
        assert_eq!(
            summary.transcript_sha256,
            QualificationSha256::digest(&transcript)
        );
        assert_eq!(
            summary.readiness_history_sha256,
            QualificationSha256::digest(&history)
        );
        assert_eq!(
            summary.sequential_schedule_sha256,
            QualificationSha256::digest(&sequential_schedule)
        );
        assert_eq!(
            summary.sequential_history_sha256,
            QualificationSha256::digest(&sequential_history)
        );
        assert!(summary.experimental);
        assert!(!summary.qualification_complete);
        assert!(!summary.counts_for_production);
        assert!(!summary.concurrent_history_complete);
        assert!(summary.sequential_history_complete);
        let checker =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check-session-ha-history.py");
        let checker_output = Command::new("python3")
            .arg(checker)
            .arg("--schedule")
            .arg(output.join(CAMPAIGN_SEQUENTIAL_SCHEDULE_FILE))
            .arg("--history")
            .arg(output.join(CAMPAIGN_SEQUENTIAL_HISTORY_FILE))
            .output()
            .await
            .expect("run independent sequential checker");
        assert!(checker_output.status.success());
        let checker_document: serde_json::Value = serde_json::from_slice(&checker_output.stdout)
            .expect("decode independent checker output");
        assert_eq!(checker_document["status"], "pass");
        assert_eq!(checker_document["operations_checked"], 15);
        for name in [
            CAMPAIGN_TRANSCRIPT_FILE,
            CAMPAIGN_READINESS_HISTORY_FILE,
            CAMPAIGN_SEQUENTIAL_SCHEDULE_FILE,
            CAMPAIGN_SEQUENTIAL_HISTORY_FILE,
            CAMPAIGN_SUMMARY_FILE,
        ] {
            assert_eq!(
                fs::metadata(output.join(name))
                    .expect("artifact metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(matches!(
            persist_qualification_kubernetes_campaign(&output, &config, &outcome),
            Err(QualificationKubernetesCampaignArtifactError::DestinationExists)
        ));
    }

    #[tokio::test]
    async fn persistence_rejects_forged_or_noncontiguous_outcomes_before_publication() {
        let root = tempfile::tempdir().expect("artifact root");
        let canonical_root = fs::canonicalize(root.path()).expect("canonical root");
        let config = campaign_config(1);
        let port = FakePort::ready(&config);
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign");
        assert!(validate_campaign_outcome(&config, &outcome).is_ok());

        let assert_rejected = |name: &str, forged: &QualificationKubernetesCampaignOutcome| {
            let destination = canonical_root.join(name);
            assert!(matches!(
                persist_qualification_kubernetes_campaign(&destination, &config, forged),
                Err(QualificationKubernetesCampaignArtifactError::InvalidOutcome)
            ));
            assert!(!destination.exists());
        };

        let mut empty_pass = outcome.clone();
        empty_pass.transcript.clear();
        empty_pass.readiness_history.clear();
        empty_pass.sequential_schedule.clear();
        empty_pass.sequential_history.clear();
        empty_pass.status = QualificationKubernetesCampaignStatus::Passed;
        empty_pass.completed_rounds = config.rounds;
        empty_pass.cleanup_complete = true;
        empty_pass.lease_handle_cleanup_complete = true;
        empty_pass.sequential_history_complete = true;
        assert_rejected("empty-pass", &empty_pass);

        let mut missing_schedule = outcome.clone();
        missing_schedule.sequential_schedule.pop();
        assert_rejected("missing-schedule", &missing_schedule);

        let mut reordered_schedule = outcome.clone();
        reordered_schedule.sequential_schedule.swap(0, 1);
        assert_rejected("reordered-schedule", &reordered_schedule);

        let mut duplicate_history = outcome.clone();
        duplicate_history.sequential_history[1] = duplicate_history.sequential_history[0].clone();
        assert_rejected("duplicate-history", &duplicate_history);

        let mut reordered_history = outcome.clone();
        reordered_history.sequential_history.swap(0, 1);
        assert_rejected("reordered-history", &reordered_history);

        let mut substituted_transcript = outcome.clone();
        let sequential = substituted_transcript
            .transcript
            .iter_mut()
            .find(|record| {
                record.action == QualificationKubernetesCampaignAction::SequentialOperation
            })
            .expect("sequential record");
        sequential.schedule_operation_id = Some("substituted-operation".to_owned());
        assert_rejected("substituted-transcript", &substituted_transcript);

        let mut duplicate_transcript = outcome.clone();
        let sequential_index = duplicate_transcript
            .transcript
            .iter()
            .position(|record| {
                record.action == QualificationKubernetesCampaignAction::SequentialOperation
            })
            .expect("sequential record");
        let duplicate = duplicate_transcript.transcript[sequential_index].clone();
        duplicate_transcript
            .transcript
            .insert(sequential_index + 1, duplicate);
        assert_rejected("duplicate-transcript", &duplicate_transcript);

        let mut missing_post_operation_sample = outcome.clone();
        missing_post_operation_sample
            .transcript
            .remove(sequential_index + 1);
        missing_post_operation_sample
            .readiness_history
            .remove(config.member_count);
        assert_rejected(
            "missing-post-operation-sample",
            &missing_post_operation_sample,
        );

        let mut mismatched_reply = outcome.clone();
        mismatched_reply.transcript[sequential_index].reply =
            Some(QualificationNodeReply::LeaseAcquired { fence: 999 });
        assert_rejected("mismatched-reply", &mismatched_reply);

        let mut forged_term = outcome.clone();
        let term = forged_term.readiness_history[0]
            .operation
            .term
            .expect("ready term");
        forged_term.readiness_history[0].operation.term = Some(term.wrapping_add(1));
        assert_rejected("forged-readiness-term", &forged_term);

        let mut forged_commit = outcome.clone();
        let commit = forged_commit.readiness_history[0]
            .operation
            .commit_index
            .expect("ready commit index");
        forged_commit.readiness_history[0].operation.commit_index = Some(commit.wrapping_add(1));
        assert_rejected("forged-readiness-commit", &forged_commit);

        let mut forged_applied = outcome.clone();
        let applied = forged_applied.readiness_history[0]
            .operation
            .applied_index
            .expect("ready applied index");
        forged_applied.readiness_history[0].operation.applied_index = Some(applied.wrapping_add(1));
        assert_rejected("forged-readiness-applied", &forged_applied);

        let mut forged_completion = outcome;
        forged_completion.sequential_history_complete = false;
        assert_rejected("forged-completion", &forged_completion);
    }
}
