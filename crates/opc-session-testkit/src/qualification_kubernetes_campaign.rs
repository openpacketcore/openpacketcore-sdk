//! Bounded deployed-Kubernetes readiness campaign for the experimental
//! session-HA candidate profile.
//!
//! This module drives the private same-binary control client merged for #143.
//! It does not implement consensus, infer readiness from a listener, grant
//! Kubernetes authority, or claim production qualification. A sample is ready
//! only when the exact rendered node and voter identities return a fresh,
//! internally consistent Openraft durable-barrier report. The external custom
//! condition is an AND-only evidence gate: kubelet independently invokes the
//! local UDS readiness client so readiness self-expires on quorum loss, a hung
//! probe, or process termination even if an external condition becomes stale.
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
use tokio::sync::mpsc;

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

/// Schema identifier for the bounded command/reply transcript.
pub const QUALIFICATION_KUBERNETES_CAMPAIGN_TRANSCRIPT_SCHEMA: &str =
    "opc-session-kubernetes-campaign-transcript/v1";
/// Schema identifier used by each emitted readiness history fragment row.
pub const QUALIFICATION_CONCURRENT_HISTORY_SCHEMA_V3: &str = "opc-session-ha-concurrent-history/v3";
/// Schema identifier for the candidate-only probe-campaign summary.
pub const QUALIFICATION_KUBERNETES_CAMPAIGN_SUMMARY_SCHEMA: &str =
    "opc-session-kubernetes-probe-campaign/v1";
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
const CAMPAIGN_ARTIFACT_MAX_BYTES: usize = 32 * 1024 * 1024;
const CAMPAIGN_TRANSCRIPT_FILE: &str = "transcript.jsonl";
const CAMPAIGN_READINESS_HISTORY_FILE: &str = "readiness-v3-fragment.jsonl";
const CAMPAIGN_SUMMARY_FILE: &str = "summary.json";

/// Fixed, validated input for one deployed readiness campaign.
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
    /// Bounded identifier shared by emitted v3 readiness rows.
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
        let sample_count = self
            .rounds
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
        Ok(())
    }

    fn sample_count(&self) -> usize {
        self.rounds.saturating_mul(self.member_count)
    }
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
    /// Execute one `Probe` through the private same-binary control client.
    async fn invoke_probe(
        &self,
        namespace: &str,
        pod_name: &str,
    ) -> Result<QualificationNodeReply, QualificationKubernetesPortError>;

    /// Publish one custom condition through the Pod status subresource.
    async fn publish_readiness(
        &self,
        namespace: &str,
        pod_name: &str,
        condition: &QualificationKubernetesReadinessCondition,
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

/// Overall result of this bounded candidate-only probe campaign.
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
    /// Exact typed reply, admitted only after bounded decoding.
    pub reply: Option<QualificationNodeReply>,
    /// Fixed control-boundary error class, without subprocess diagnostics.
    pub control_error: Option<QualificationKubernetesPortError>,
    /// Fixed status-subresource error class, without Kubernetes diagnostics.
    pub readiness_update_error: Option<QualificationKubernetesPortError>,
    /// Published or attempted condition.
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
    pub status: QualificationKubernetesCampaignStatus,
    /// Number of complete fleet rounds.
    pub completed_rounds: usize,
    /// Whether every final false-condition update succeeded.
    pub cleanup_complete: bool,
    /// Ordered command/reply and cleanup transcript.
    pub transcript: Vec<QualificationKubernetesCampaignRecord>,
    /// Ordered readiness-only v3 history fragment.
    pub readiness_history: Vec<QualificationKubernetesReadinessHistoryV3>,
}

/// Run one bounded deployed probe campaign.
///
/// The returned readiness rows are a fragment for the existing v3 checker. A
/// complete candidate must combine them with real batch, watch, and restore
/// rows and rewrite the full history count before invoking that checker.
pub async fn run_qualification_kubernetes_probe_campaign<P, C>(
    config: &QualificationKubernetesCampaignConfig,
    port: &P,
    clock: &C,
    cancelled: &AtomicBool,
) -> Result<QualificationKubernetesCampaignOutcome, QualificationKubernetesCampaignConfigError>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    config.validate()?;
    let expectations = qualification_kubernetes_readiness_expectations(config.member_count)
        .map_err(|_| QualificationKubernetesCampaignConfigError::InvalidIdentityContract)?;
    let mut transcript =
        Vec::with_capacity(config.sample_count() + config.member_count.saturating_mul(2));
    let mut readiness_history = Vec::with_capacity(config.sample_count());
    let mut status = QualificationKubernetesCampaignStatus::Passed;
    let mut completed_rounds = 0;
    let mut abort = !publish_fail_closed_conditions(
        config,
        port,
        clock,
        0,
        FailClosedPhase::Reset,
        &mut transcript,
    )
    .await;
    if abort {
        status = QualificationKubernetesCampaignStatus::Failed;
    }
    let mut last_started_ns = vec![None; config.member_count];

    for round in 0..config.rounds {
        if abort {
            break;
        }
        if cancelled.load(Ordering::Acquire) {
            status = QualificationKubernetesCampaignStatus::Cancelled;
            break;
        }
        for (member_index, (last_started_ns, expectation)) in
            last_started_ns.iter_mut().zip(&expectations).enumerate()
        {
            if cancelled.load(Ordering::Acquire) {
                status = QualificationKubernetesCampaignStatus::Cancelled;
                abort = true;
                break;
            }
            let started_ns = monotonic_after(clock.elapsed_ns(), *last_started_ns);
            *last_started_ns = Some(started_ns);
            let pod_name = qualification_pod_name(member_index);
            let reply = port.invoke_probe(&config.namespace, &pod_name).await;
            let control_error = reply.as_ref().err().copied();
            let cancelled_after_probe = cancelled.load(Ordering::Acquire);
            let mut classified = if cancelled_after_probe {
                not_ready_probe(
                    QualificationKubernetesReadinessReason::CampaignStopped,
                    QualificationKubernetesCampaignRecordOutcome::CampaignCancelled,
                )
            } else {
                classify_probe(reply.as_ref().ok(), expectation)
            };
            classified.history.sample_sequence = round + 1;
            let mut record_outcome = classified.outcome;
            let condition_result = port
                .publish_readiness(&config.namespace, &pod_name, &classified.condition)
                .await;
            let readiness_update_error = condition_result.as_ref().err().copied();
            if condition_result.is_err() {
                record_outcome =
                    QualificationKubernetesCampaignRecordOutcome::ReadinessUpdateFailed;
                status = QualificationKubernetesCampaignStatus::Failed;
                abort = true;
            } else if cancelled_after_probe {
                status = QualificationKubernetesCampaignStatus::Cancelled;
                abort = true;
            } else if !classified.ready {
                status = QualificationKubernetesCampaignStatus::Failed;
                abort = true;
            }
            if cancelled.load(Ordering::Acquire) {
                if status == QualificationKubernetesCampaignStatus::Passed {
                    status = QualificationKubernetesCampaignStatus::Cancelled;
                }
                abort = true;
            }
            let completed_ns = clock.elapsed_ns().max(started_ns);
            let retained_reply = reply.ok().and_then(|reply| {
                matches!(&reply, QualificationNodeReply::Readiness { .. }).then_some(reply)
            });
            transcript.push(QualificationKubernetesCampaignRecord {
                schema_version: QUALIFICATION_KUBERNETES_CAMPAIGN_TRANSCRIPT_SCHEMA.to_owned(),
                round,
                member_index,
                pod_name: pod_name.clone(),
                action: QualificationKubernetesCampaignAction::Probe,
                started_ns,
                completed_ns,
                command: Some(QualificationNodeCommand::Probe),
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
                operation_id: format!("readiness-{}-{}", round + 1, member_index),
                process_id: format!("node-{member_index}"),
                started_ns,
                completed_ns,
                operation: classified.history,
            });
            if abort {
                break;
            }
        }
        if abort {
            break;
        }
        completed_rounds = round + 1;
        if completed_rounds < config.rounds {
            clock.sleep(config.probe_interval).await;
        }
    }

    let history_operation_count = readiness_history.len();
    for record in &mut readiness_history {
        record.history_operation_count = history_operation_count;
    }

    let cleanup_complete = publish_fail_closed_conditions(
        config,
        port,
        clock,
        completed_rounds,
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
        transcript,
        readiness_history,
    })
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
        let started_ns = clock.elapsed_ns();
        let pod_name = qualification_pod_name(member_index);
        let condition = QualificationKubernetesReadinessCondition::not_ready(
            QualificationKubernetesReadinessReason::CampaignStopped,
        );
        let publication = port
            .publish_readiness(&config.namespace, &pod_name, &condition)
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
            reply: None,
            control_error: None,
            readiness_update_error,
            condition,
            outcome: phase.outcome(published),
        });
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
        && configured_voter_ids == expectation.expected_voter_ids()
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
    async fn invoke_probe(
        &self,
        namespace: &str,
        pod_name: &str,
    ) -> Result<QualificationNodeReply, QualificationKubernetesPortError> {
        let mut input = Vec::new();
        write_json_line(&mut input, &QualificationNodeCommand::Probe)
            .map_err(|_| QualificationKubernetesPortError::Unavailable)?;
        let output = run_kubectl(
            &self.executable,
            &control_client_arguments(namespace, pod_name),
            &input,
            self.command_timeout,
            KUBECTL_STDOUT_MAX_BYTES,
            KUBECTL_STDERR_MAX_BYTES,
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
) -> Result<KubectlOutput, QualificationKubernetesPortError> {
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

    let write_result = tokio::time::timeout_at(deadline, async {
        stdin.write_all(stdin_bytes).await?;
        stdin.shutdown().await
    })
    .await;
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
    }
    let terminal = {
        let wait = child.wait();
        tokio::pin!(wait);
        tokio::select! {
            result = &mut wait => Terminal::Exited(result),
            Some(()) = overflow_rx.recv() => Terminal::Overflow,
            () = tokio::time::sleep_until(deadline) => Terminal::Timeout,
        }
    };
    let status = match terminal {
        Terminal::Exited(Ok(status)) => status,
        Terminal::Exited(Err(_)) => {
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

/// Fixed candidate-only summary written beside the transcript and readiness
/// history fragment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationKubernetesCampaignSummary {
    /// Summary schema identifier.
    pub schema_version: String,
    /// This slice remains experimental.
    pub experimental: bool,
    /// This slice never claims complete production qualification.
    pub qualification_complete: bool,
    /// This slice never counts as production evidence by itself.
    pub counts_for_production: bool,
    /// Bounded probe-campaign outcome.
    pub status: QualificationKubernetesCampaignStatus,
    /// Configured voter count.
    pub topology_members: usize,
    /// Configured complete fleet rounds.
    pub rounds_planned: usize,
    /// Fully completed fleet rounds.
    pub rounds_completed: usize,
    /// Readiness samples retained in the fragment.
    pub readiness_samples: usize,
    /// Whether every final false-condition update succeeded.
    pub cleanup_complete: bool,
    /// Existing v3 history schema consumed by these readiness rows.
    pub readiness_history_schema: String,
    /// Digest of the exact bounded command/reply transcript bytes.
    pub transcript_sha256: QualificationSha256,
    /// Digest of the exact readiness-only v3 fragment bytes.
    pub readiness_history_sha256: QualificationSha256,
    /// This output intentionally lacks batch/watch/restore rows.
    pub concurrent_history_complete: bool,
    /// This slice does not produce the independent v1 workload history.
    pub sequential_history_complete: bool,
    /// Complete fixed remaining #143 gate inventory.
    pub remaining_acceptance: Vec<String>,
}

impl QualificationKubernetesCampaignSummary {
    /// Construct an honest candidate-only summary from one completed run.
    #[must_use]
    pub fn from_outcome(
        config: &QualificationKubernetesCampaignConfig,
        outcome: &QualificationKubernetesCampaignOutcome,
        transcript_sha256: QualificationSha256,
        readiness_history_sha256: QualificationSha256,
    ) -> Self {
        Self {
            schema_version: QUALIFICATION_KUBERNETES_CAMPAIGN_SUMMARY_SCHEMA.to_owned(),
            experimental: true,
            qualification_complete: false,
            counts_for_production: false,
            status: outcome.status,
            topology_members: config.member_count,
            rounds_planned: config.rounds,
            rounds_completed: outcome.completed_rounds,
            readiness_samples: outcome.readiness_history.len(),
            cleanup_complete: outcome.cleanup_complete,
            readiness_history_schema: QUALIFICATION_CONCURRENT_HISTORY_SCHEMA_V3.to_owned(),
            transcript_sha256,
            readiness_history_sha256,
            concurrent_history_complete: false,
            sequential_history_complete: false,
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

/// Atomically persist the bounded transcript, readiness fragment, and summary.
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
    let (parent, destination_name) = validate_artifact_destination(output_directory)?;
    let transcript = encode_json_lines(&outcome.transcript)?;
    let readiness_history = encode_json_lines(&outcome.readiness_history)?;
    let summary = QualificationKubernetesCampaignSummary::from_outcome(
        config,
        outcome,
        QualificationSha256::digest(&transcript),
        QualificationSha256::digest(&readiness_history),
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
        published: Mutex<Vec<QualificationKubernetesReadinessCondition>>,
        fail_publish_at: Option<usize>,
        cancel_on_probe: Option<Arc<AtomicBool>>,
    }

    impl FakePort {
        fn ready(rounds: usize, member_count: usize) -> Self {
            let expectations = qualification_kubernetes_readiness_expectations(member_count)
                .expect("fixed readiness expectations");
            let leader_id = expectations[0].expected_node_id();
            Self {
                replies: Mutex::new(
                    (0..rounds)
                        .flat_map(|_| {
                            expectations
                                .iter()
                                .map(|expectation| Ok(ready_reply(expectation, leader_id)))
                        })
                        .collect(),
                ),
                published: Mutex::new(Vec::new()),
                fail_publish_at: None,
                cancel_on_probe: None,
            }
        }
    }

    #[async_trait]
    impl QualificationKubernetesCampaignPort for FakePort {
        async fn invoke_probe(
            &self,
            _namespace: &str,
            _pod_name: &str,
        ) -> Result<QualificationNodeReply, QualificationKubernetesPortError> {
            let reply = self
                .replies
                .lock()
                .expect("reply lock")
                .pop_front()
                .unwrap_or(Err(QualificationKubernetesPortError::Unavailable));
            if let Some(cancelled) = &self.cancel_on_probe {
                cancelled.store(true, Ordering::Release);
            }
            reply
        }

        async fn publish_readiness(
            &self,
            _namespace: &str,
            _pod_name: &str,
            condition: &QualificationKubernetesReadinessCondition,
        ) -> Result<(), QualificationKubernetesPortError> {
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
        cancel_on_sleep: Option<Arc<AtomicBool>>,
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
            if let Some(cancelled) = &self.cancel_on_sleep {
                cancelled.store(true, Ordering::Release);
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
            configured_voter_ids: expectation.expected_voter_ids().to_vec(),
            fresh_reachable_voters: expectation.required_quorum(),
            agreeing_voters: expectation.required_quorum(),
            required_quorum: expectation.required_quorum(),
            committed_index: Some(7),
            applied_index: Some(7),
        }
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
        let result = run_kubectl(
            executable.as_os_str(),
            &[],
            &[],
            Duration::from_millis(250),
            1_024,
            1_024,
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

    #[cfg(unix)]
    #[tokio::test]
    async fn kubectl_output_overflow_and_nonzero_exit_fail_closed() {
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
        let (_malformed_directory, malformed_executable) =
            write_fake_kubectl("printf '%s\\n' 'not-json'");
        let malformed = KubectlQualificationKubernetesCampaignPort::with_executable(
            malformed_executable.into_os_string(),
            Duration::from_secs(2),
        )
        .invoke_probe("qualification", "opc-session-ha-0-0")
        .await;
        assert!(matches!(
            malformed,
            Err(QualificationKubernetesPortError::InvalidReply)
        ));

        let (_duplicate_directory, duplicate_executable) = write_fake_kubectl(
            "printf '%s\\n%s\\n' '{\"reply\":\"initialized\"}' '{\"reply\":\"initialized\"}'",
        );
        let duplicate = KubectlQualificationKubernetesCampaignPort::with_executable(
            duplicate_executable.into_os_string(),
            Duration::from_secs(2),
        )
        .invoke_probe("qualification", "opc-session-ha-0-0")
        .await;
        assert!(matches!(
            duplicate,
            Err(QualificationKubernetesPortError::InvalidReply)
        ));
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
        port.publish_readiness("qualification", "opc-session-ha-0-0", &condition)
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
            configured_voter_ids: expectation.expected_voter_ids().to_vec(),
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
        let port = FakePort::ready(2, 3);
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &AtomicBool::new(false),
        )
        .await
        .expect("valid campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Passed
        );
        assert_eq!(outcome.completed_rounds, 2);
        assert!(outcome.cleanup_complete);
        assert_eq!(outcome.transcript.len(), 12);
        assert_eq!(outcome.readiness_history.len(), 6);
        for (index, row) in outcome.readiness_history.iter().enumerate() {
            assert_eq!(row.history_operation_count, 6);
            assert_eq!(row.operation.sample_sequence, index / 3 + 1);
            assert_eq!(row.operation.state, "ready");
            assert_eq!(row.operation.term, Some(2));
        }
        let published = port.published.lock().expect("published lock");
        assert!(published[..3]
            .iter()
            .all(|condition| condition.status == QualificationKubernetesConditionStatus::False));
        assert!(published[3..9]
            .iter()
            .all(|condition| condition.status == QualificationKubernetesConditionStatus::True));
        assert!(published[9..]
            .iter()
            .all(|condition| condition.status == QualificationKubernetesConditionStatus::False));
    }

    #[tokio::test]
    async fn contradictory_reply_fails_closed_without_authority_fields() {
        let config = campaign_config(1);
        let mut port = FakePort::ready(1, 3);
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
            &AtomicBool::new(false),
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
    }

    #[tokio::test]
    async fn cancellation_returns_partial_artifacts_and_clears_every_member() {
        let config = campaign_config(2);
        let port = FakePort::ready(2, 3);
        let cancelled = Arc::new(AtomicBool::new(false));
        let clock = FakeClock {
            elapsed: std::sync::atomic::AtomicU64::new(0),
            cancel_on_sleep: Some(Arc::clone(&cancelled)),
        };
        let outcome =
            run_qualification_kubernetes_probe_campaign(&config, &port, &clock, cancelled.as_ref())
                .await
                .expect("valid campaign");

        assert_eq!(
            outcome.status,
            QualificationKubernetesCampaignStatus::Cancelled
        );
        assert_eq!(outcome.completed_rounds, 1);
        assert_eq!(outcome.readiness_history.len(), 3);
        assert!(outcome.cleanup_complete);
        assert_eq!(port.published.lock().expect("published lock").len(), 9);
    }

    #[tokio::test]
    async fn status_update_failure_aborts_and_still_attempts_complete_cleanup() {
        let config = campaign_config(2);
        let expectation = readiness_expectation(3, 0);
        let leader_id = expectation.expected_voter_ids()[0];
        let port = FakePort {
            replies: Mutex::new(VecDeque::from([Ok(ready_reply(&expectation, leader_id))])),
            published: Mutex::new(Vec::new()),
            fail_publish_at: Some(3),
            cancel_on_probe: None,
        };
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &AtomicBool::new(false),
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
    }

    #[tokio::test]
    async fn incomplete_initial_reset_never_invokes_or_publishes_a_ready_probe() {
        let config = campaign_config(2);
        let port = FakePort::ready(2, 3);
        let port = FakePort {
            fail_publish_at: Some(0),
            ..port
        };
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &AtomicBool::new(false),
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
        assert_eq!(
            port.replies.lock().expect("reply lock").len(),
            6,
            "failed reset must abort before any probe"
        );
        assert!(port
            .published
            .lock()
            .expect("published lock")
            .iter()
            .all(|condition| condition.status == QualificationKubernetesConditionStatus::False));
    }

    #[tokio::test]
    async fn cancellation_during_probe_never_authorizes_its_ready_reply() {
        let config = campaign_config(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let expectation = readiness_expectation(3, 0);
        let leader_id = expectation.expected_voter_ids()[0];
        let port = FakePort {
            replies: Mutex::new(VecDeque::from([Ok(ready_reply(&expectation, leader_id))])),
            published: Mutex::new(Vec::new()),
            fail_publish_at: None,
            cancel_on_probe: Some(Arc::clone(&cancelled)),
        };
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            cancelled.as_ref(),
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
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn artifacts_are_private_bound_and_atomically_non_overwriting() {
        let root = tempfile::tempdir().expect("artifact root");
        let canonical_root = fs::canonicalize(root.path()).expect("canonical root");
        let output = canonical_root.join("campaign-1");
        let config = campaign_config(1);
        let port = FakePort::ready(1, 3);
        let outcome = run_qualification_kubernetes_probe_campaign(
            &config,
            &port,
            &FakeClock::new(),
            &AtomicBool::new(false),
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
        assert_eq!(
            summary.transcript_sha256,
            QualificationSha256::digest(&transcript)
        );
        assert_eq!(
            summary.readiness_history_sha256,
            QualificationSha256::digest(&history)
        );
        for name in [
            CAMPAIGN_TRANSCRIPT_FILE,
            CAMPAIGN_READINESS_HISTORY_FILE,
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
}
