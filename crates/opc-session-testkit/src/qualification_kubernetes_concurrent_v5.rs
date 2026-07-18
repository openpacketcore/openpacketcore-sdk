//! Bounded deployed-Kubernetes adapter for the candidate v5 HA collector.
//!
//! The adapter drives the existing private same-binary control client through
//! [`QualificationKubernetesCampaignPort`]. It does not add a network control
//! plane, shell invocation, commit path, sequencer, or consensus mechanism.
//! Openraft and the protected session store remain the only authorities.
//!
//! A successful run uses a fresh history-derived namespace, pre-acquires two
//! leases, proves the namespace is empty, registers one real watch, executes
//! one partial-success protected batch, observes every voter before, during,
//! and after an all-member consensus-RPC fault, restores the terminal state,
//! and feeds only typed node replies into the pure v5 collector. The result is
//! still candidate evidence: this adapter does not bind an OCI image, release
//! manifest, platform inventory, or independent checker result.

use std::fmt;
use std::time::Duration;

use futures_util::future::join_all;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::qualification::{
    qualification_concurrent_state_type, qualification_key_bytes_sha256,
    qualification_owner_sha256, qualification_state_type_sha256, qualification_value_sha256,
    QualificationConcurrentBatchOutcome, QualificationConcurrentBatchSlot,
    QualificationConcurrentBatchSlotOutcome, QualificationConcurrentMutationSnapshot,
    QualificationConcurrentStateClass, QualificationConcurrentStateType,
    QualificationConcurrentSubscriptionId, QualificationConsensusRpcAvailability,
    QualificationNodeCommand, QualificationNodeReply, QualificationReadinessCode,
};
use crate::qualification_concurrent_v5::{
    QualificationConcurrentFaultScheduleV5Builder, QualificationConcurrentHistoryContractV5,
    QualificationConcurrentHistoryV5, QualificationConcurrentHistoryV5Builder,
    QualificationConcurrentLeaseBindingV5, QualificationConcurrentProcessV5,
    QualificationConcurrentV5Error, QualificationConcurrentWatchExpectationV5,
    QUALIFICATION_CONCURRENT_READINESS_V5_MAX_GAP_NS,
};
use crate::qualification_kubernetes::{
    is_kubernetes_dns_label, qualification_kubernetes_readiness_expectations,
    QualificationKubernetesReadinessExpectation, QUALIFICATION_KUBERNETES_FLEET_NAME,
};
use crate::qualification_kubernetes_campaign::{
    QualificationKubernetesCampaignCancellation, QualificationKubernetesCampaignClock,
    QualificationKubernetesCampaignPort, QualificationKubernetesPortError,
    QualificationKubernetesReadinessCondition, QualificationKubernetesReadinessReason,
};

/// Maximum elapsed campaign window retained in candidate v5 evidence.
///
/// Lease acquisition, namespace preflight, and fail-closed condition reset
/// happen before this window. Cleanup happens after it. Individual control
/// calls retain the lower fixed deadlines enforced by the kubectl adapter and
/// qualification node.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_MAX_DURATION: Duration =
    Duration::from_secs(8 * 60);

/// Lease lifetime used by the fixed deployed v5 workload.
///
/// Fifteen minutes covers two serialized pre-campaign acquisitions, one
/// restore preflight, the eight-minute retained campaign bound, and explicit
/// delivery margin. It remains far below the session-store one-year maximum.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_LEASE_TTL: Duration = Duration::from_secs(15 * 60);

/// Maximum time allowed for one all-voter readiness transition to converge.
///
/// The bound covers the observed Openraft reconnect lifecycle while remaining
/// below the frozen collector's sixty-second per-process readiness-gap bound,
/// including one bounded control operation on either side of the transition.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_TRANSITION_TIMEOUT: Duration =
    Duration::from_secs(35);

/// Cadence between complete all-voter transition samples.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_TRANSITION_CADENCE: Duration =
    Duration::from_secs(1);

const WORKLOAD_SCOPE_DOMAIN: &[u8] = b"opc-session-ha/kubernetes-concurrent-v5/v1";
const WORKLOAD_SCOPE_HEX_BYTES: usize = 16;
const WATCH_MEMBER_INDEX: usize = 1;
const RESTORE_MEMBER_INDEX: usize = 2;
const MAX_TRANSITION_ROUNDS: usize = 40;

/// Validated operator input for one deployed candidate v5 campaign.
#[derive(Clone, PartialEq, Eq)]
pub struct QualificationKubernetesConcurrentV5Config {
    /// Namespace containing the exact rendered qualification fleet.
    pub namespace: String,
    /// Exact supported three- or five-voter topology.
    pub member_count: usize,
    /// Unique bounded run nonce. Reusing one after any attempted run is not
    /// supported because an earlier ambiguous mutation may still be durable.
    pub history_id: String,
}

impl fmt::Debug for QualificationKubernetesConcurrentV5Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationKubernetesConcurrentV5Config")
            .field("member_count", &self.member_count)
            .field("namespace", &"<redacted>")
            .field("history_id", &"<redacted>")
            .finish()
    }
}

impl QualificationKubernetesConcurrentV5Config {
    /// Reject malformed operator input before invoking a subprocess.
    pub fn validate(&self) -> Result<(), QualificationKubernetesConcurrentV5ConfigError> {
        if !matches!(self.member_count, 3 | 5) {
            return Err(QualificationKubernetesConcurrentV5ConfigError::InvalidTopology);
        }
        if !is_kubernetes_dns_label(&self.namespace) {
            return Err(QualificationKubernetesConcurrentV5ConfigError::InvalidNamespace);
        }
        if self.history_id.is_empty()
            || self.history_id.len() > 128
            || !self
                .history_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(QualificationKubernetesConcurrentV5ConfigError::InvalidHistoryId);
        }
        qualification_kubernetes_readiness_expectations(self.member_count)
            .map_err(|_| QualificationKubernetesConcurrentV5ConfigError::InvalidIdentity)?;
        FixedWorkload::new(&self.history_id)
            .map_err(|_| QualificationKubernetesConcurrentV5ConfigError::InvalidWorkload)?;
        Ok(())
    }
}

/// Redaction-safe deployed v5 campaign configuration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QualificationKubernetesConcurrentV5ConfigError {
    /// Only three and five voters are admitted.
    #[error("qualification Kubernetes v5 topology is invalid")]
    InvalidTopology,
    /// The namespace is not a canonical Kubernetes DNS label.
    #[error("qualification Kubernetes v5 namespace is invalid")]
    InvalidNamespace,
    /// The history nonce is empty, oversized, or noncanonical.
    #[error("qualification Kubernetes v5 history identifier is invalid")]
    InvalidHistoryId,
    /// Stable Openraft identities could not be derived for the fleet.
    #[error("qualification Kubernetes v5 identity contract is invalid")]
    InvalidIdentity,
    /// The fixed isolated workload could not be constructed.
    #[error("qualification Kubernetes v5 workload is invalid")]
    InvalidWorkload,
}

/// Stable stage inventory for redaction-safe operational failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QualificationKubernetesConcurrentV5Stage {
    /// Clear the external readiness gate before doing work.
    ResetReadiness,
    /// Pre-acquire the fixed lease inventory.
    AcquireLeases,
    /// Prove the fresh history-derived restore scope is empty.
    InitialRestore,
    /// Collect the initial all-voter authority sample.
    InitialReadiness,
    /// Register the real retained watch.
    StartWatch,
    /// Dispatch the one at-most-once partial-success batch.
    Batch,
    /// Observe the committed batch before injecting a fault.
    PostBatchReadiness,
    /// Disable every qualification consensus RPC gate.
    IsolateFleet,
    /// Observe fail-closed readiness while isolated.
    IsolatedReadiness,
    /// Re-enable every qualification consensus RPC gate.
    RecoverFleet,
    /// Observe recovered durable authority.
    RecoveredReadiness,
    /// Consume the retained watch through the proven terminal head.
    FinishWatch,
    /// Scan the terminal history-derived restore scope.
    TerminalRestore,
    /// Validate and finalize the pure collector.
    Collect,
    /// Restore gates and drop process-local campaign state.
    Cleanup,
}

/// Stable, redaction-safe deployed campaign failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QualificationKubernetesConcurrentV5Failure {
    /// Cancellation stopped new campaign work.
    #[error("qualification Kubernetes v5 campaign was cancelled")]
    Cancelled,
    /// A bounded Kubernetes/control-client operation failed.
    #[error("qualification Kubernetes v5 control operation failed")]
    Port {
        /// Closed stage at which the operation failed.
        stage: QualificationKubernetesConcurrentV5Stage,
        /// Low-cardinality port failure.
        error: QualificationKubernetesPortError,
    },
    /// A typed reply did not match the exact requested operation.
    #[error("qualification Kubernetes v5 node reply was invalid")]
    Reply {
        /// Closed stage at which the reply was rejected.
        stage: QualificationKubernetesConcurrentV5Stage,
    },
    /// The monotonic campaign clock regressed or overflowed.
    #[error("qualification Kubernetes v5 campaign clock is invalid")]
    Clock,
    /// The campaign exceeded its fixed elapsed-time envelope.
    #[error("qualification Kubernetes v5 campaign exceeded its duration bound")]
    Deadline,
    /// A bounded readiness transition did not reach its required terminal
    /// state before the transition deadline.
    #[error("qualification Kubernetes v5 readiness transition did not converge")]
    TransitionTimeout {
        /// Closed transition stage that did not converge.
        stage: QualificationKubernetesConcurrentV5Stage,
    },
    /// The pure collector rejected the retained observations.
    #[error("qualification Kubernetes v5 collector rejected the campaign")]
    Collector(#[source] QualificationConcurrentV5Error),
    /// Cleanup could not conclusively restore every local control state.
    #[error("qualification Kubernetes v5 cleanup was incomplete")]
    Cleanup,
}

/// Terminal status for one deployed candidate run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualificationKubernetesConcurrentV5Status {
    /// The pure collector produced a complete checker-ready history.
    Passed,
    /// An operational or cleanup failure made the run inconclusive.
    Failed,
    /// Cancellation stopped the run and bounded cleanup completed.
    Cancelled,
}

/// Result of one deployed candidate v5 campaign.
pub struct QualificationKubernetesConcurrentV5Outcome {
    status: QualificationKubernetesConcurrentV5Status,
    failure: Option<QualificationKubernetesConcurrentV5Failure>,
    history: Option<QualificationConcurrentHistoryV5>,
    cleanup_complete: bool,
}

impl fmt::Debug for QualificationKubernetesConcurrentV5Outcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationKubernetesConcurrentV5Outcome")
            .field("status", &self.status)
            .field("failure", &self.failure)
            .field("history_available", &self.history.is_some())
            .field("cleanup_complete", &self.cleanup_complete)
            .finish()
    }
}

impl QualificationKubernetesConcurrentV5Outcome {
    /// Terminal campaign status.
    pub const fn status(&self) -> QualificationKubernetesConcurrentV5Status {
        self.status
    }

    /// Low-cardinality failure, absent only for a passing campaign.
    pub const fn failure(&self) -> Option<QualificationKubernetesConcurrentV5Failure> {
        self.failure
    }

    /// Checker-ready history, available only when the campaign passed.
    pub const fn history(&self) -> Option<&QualificationConcurrentHistoryV5> {
        self.history.as_ref()
    }

    /// Whether every idempotent local cleanup action returned its exact reply.
    pub const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }
}

#[derive(Clone)]
struct LeaseWorkload {
    handle: String,
    stable_id: String,
    owner: String,
    value: String,
}

struct FixedWorkload {
    token: String,
    leases: [LeaseWorkload; 2],
    state_type: QualificationConcurrentStateType,
    subscription_id: QualificationConcurrentSubscriptionId,
}

impl fmt::Debug for FixedWorkload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedWorkload")
            .field("lease_count", &self.leases.len())
            .field("identifiers", &"<redacted>")
            .finish()
    }
}

impl FixedWorkload {
    fn new(history_id: &str) -> Result<Self, QualificationConcurrentV5Error> {
        let mut hasher = Sha256::new();
        hasher.update(WORKLOAD_SCOPE_DOMAIN);
        hasher.update([0]);
        hasher.update(history_id.as_bytes());
        let digest = format!("{:x}", hasher.finalize());
        let retained = WORKLOAD_SCOPE_HEX_BYTES
            .checked_mul(2)
            .ok_or(QualificationConcurrentV5Error::Overflow)?;
        let token = digest
            .get(..retained)
            .ok_or(QualificationConcurrentV5Error::Identifier)?
            .to_owned();
        let lease = |suffix| LeaseWorkload {
            handle: format!("v5-{token}-lease-{suffix}"),
            stable_id: format!("v5-{token}-key-{suffix}"),
            owner: format!("v5-{token}-owner-{suffix}"),
            value: format!("v5-{token}-value-{suffix}"),
        };
        let leases = [lease('a'), lease('b')];
        let state_type = qualification_concurrent_state_type(history_id)
            .map_err(|_| QualificationConcurrentV5Error::Contract)?;
        let subscription_id =
            QualificationConcurrentSubscriptionId::new(format!("v5-{token}-watch"))
                .map_err(|_| QualificationConcurrentV5Error::Identifier)?;
        Ok(Self {
            token,
            leases,
            state_type,
            subscription_id,
        })
    }

    fn batch_command(&self) -> QualificationNodeCommand {
        QualificationNodeCommand::ConcurrentBatch {
            slots: vec![
                QualificationConcurrentBatchSlot {
                    lease_handle: self.leases[0].handle.clone(),
                    stable_id: self.leases[0].stable_id.clone(),
                    expected_generation: None,
                    new_generation: 1,
                    state_type: self.state_type.clone(),
                    value: self.leases[0].value.clone(),
                },
                QualificationConcurrentBatchSlot {
                    lease_handle: self.leases[1].handle.clone(),
                    stable_id: self.leases[1].stable_id.clone(),
                    expected_generation: Some(1),
                    new_generation: 2,
                    state_type: self.state_type.clone(),
                    value: self.leases[1].value.clone(),
                },
            ],
        }
    }

    fn expected_mutations(
        &self,
        fences: &[u64],
    ) -> Option<Vec<QualificationConcurrentMutationSnapshot>> {
        if fences.len() != self.leases.len() {
            return None;
        }
        let state_type_sha256 = qualification_state_type_sha256(self.state_type.as_str());
        Some(
            self.leases
                .iter()
                .zip(fences)
                .enumerate()
                .map(
                    |(index, (lease, fence))| QualificationConcurrentMutationSnapshot {
                        key_sha256: qualification_key_bytes_sha256(lease.stable_id.as_bytes()),
                        expected_generation: (index == 1).then_some(1),
                        new_generation: index as u64 + 1,
                        owner_sha256: qualification_owner_sha256(&lease.owner),
                        fence: *fence,
                        state_class: QualificationConcurrentStateClass::AuthoritativeSession,
                        state_type_sha256: state_type_sha256.clone(),
                        expires_at_ns: None,
                        value_sha256: qualification_value_sha256(lease.value.as_bytes()),
                    },
                )
                .collect(),
        )
    }
}

#[derive(Default)]
struct CleanupState {
    attempted_lease_handles: Vec<String>,
    watch_attempted: bool,
}

#[derive(Clone)]
struct TimedReply {
    started_ns: u64,
    completed_ns: u64,
    reply: QualificationNodeReply,
}

struct FleetGateTransition {
    members: Vec<TimedReply>,
}

struct FleetReadinessTransition {
    rounds: Vec<Vec<TimedReply>>,
}

#[derive(Clone, Copy)]
struct FleetReadinessTransitionRequest {
    expected_ready: bool,
    stage: QualificationKubernetesConcurrentV5Stage,
    transition_started_ns: u64,
    campaign_started_ns: u64,
}

impl FleetReadinessTransition {
    fn final_round(
        &self,
        stage: QualificationKubernetesConcurrentV5Stage,
    ) -> Result<&[TimedReply], QualificationKubernetesConcurrentV5Failure> {
        self.rounds
            .last()
            .map(Vec::as_slice)
            .ok_or(QualificationKubernetesConcurrentV5Failure::Reply { stage })
    }
}

struct CampaignObservations {
    initial: Vec<TimedReply>,
    batch: TimedReply,
    post_batch: Vec<TimedReply>,
    isolated: FleetReadinessTransition,
    recovered: FleetReadinessTransition,
    watch_started_ns: u64,
    watch: TimedReply,
    restore: TimedReply,
    isolation_actuation: FleetGateTransition,
    recovery_actuation: FleetGateTransition,
    campaign_started_ns: u64,
    campaign_completed_ns: u64,
    initial_journal_head: u64,
    terminal_journal_head: u64,
    fences: Vec<u64>,
}

/// Run the fixed deployed v5 campaign through an existing Kubernetes port.
///
/// Every mutating protected-store command is sent once only. Missing batch or
/// lease replies are indeterminate and are never retried. Cleanup may repeat
/// only idempotent process-local actions: making the fault gate available,
/// aborting a retained watch, forgetting lease handles, and publishing a
/// fail-closed Pod condition. Durable leases are deliberately not released;
/// the collector requires them to remain valid beyond the retained campaign
/// window and they expire under the bounded TTL.
pub async fn run_qualification_kubernetes_concurrent_v5_campaign<P, C>(
    config: &QualificationKubernetesConcurrentV5Config,
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<
    QualificationKubernetesConcurrentV5Outcome,
    QualificationKubernetesConcurrentV5ConfigError,
>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    config.validate()?;
    let workload = FixedWorkload::new(&config.history_id)
        .map_err(|_| QualificationKubernetesConcurrentV5ConfigError::InvalidWorkload)?;
    let expectations = qualification_kubernetes_readiness_expectations(config.member_count)
        .map_err(|_| QualificationKubernetesConcurrentV5ConfigError::InvalidIdentity)?;
    let mut cleanup_state = CleanupState::default();
    let result = execute_campaign(
        config,
        &workload,
        &expectations,
        port,
        clock,
        cancellation,
        &mut cleanup_state,
    )
    .await;
    let cleanup_complete = cleanup_campaign(config, &workload, port, &cleanup_state).await;
    let (status, failure, history) = match result {
        Ok(history) if cleanup_complete => (
            QualificationKubernetesConcurrentV5Status::Passed,
            None,
            Some(history),
        ),
        Ok(_) => (
            QualificationKubernetesConcurrentV5Status::Failed,
            Some(QualificationKubernetesConcurrentV5Failure::Cleanup),
            None,
        ),
        Err(QualificationKubernetesConcurrentV5Failure::Cancelled) if cleanup_complete => (
            QualificationKubernetesConcurrentV5Status::Cancelled,
            Some(QualificationKubernetesConcurrentV5Failure::Cancelled),
            None,
        ),
        Err(failure) if cleanup_complete => (
            QualificationKubernetesConcurrentV5Status::Failed,
            Some(failure),
            None,
        ),
        Err(_) => (
            QualificationKubernetesConcurrentV5Status::Failed,
            Some(QualificationKubernetesConcurrentV5Failure::Cleanup),
            None,
        ),
    };
    Ok(QualificationKubernetesConcurrentV5Outcome {
        status,
        failure,
        history,
        cleanup_complete,
    })
}

#[allow(clippy::too_many_arguments)]
async fn execute_campaign<P, C>(
    config: &QualificationKubernetesConcurrentV5Config,
    workload: &FixedWorkload,
    expectations: &[QualificationKubernetesReadinessExpectation],
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
    cleanup_state: &mut CleanupState,
) -> Result<QualificationConcurrentHistoryV5, QualificationKubernetesConcurrentV5Failure>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    check_cancellation(cancellation)?;
    publish_fleet_condition(
        config,
        port,
        &QualificationKubernetesReadinessCondition::not_ready(
            QualificationKubernetesReadinessReason::CampaignStopped,
        ),
        cancellation,
        QualificationKubernetesConcurrentV5Stage::ResetReadiness,
    )
    .await?;

    let lease_ttl_millis =
        u64::try_from(QUALIFICATION_KUBERNETES_CONCURRENT_V5_LEASE_TTL.as_millis())
            .map_err(|_| QualificationKubernetesConcurrentV5Failure::Clock)?;
    let lease_pod = pod_name(0);
    let mut fences = Vec::with_capacity(workload.leases.len());
    for lease in &workload.leases {
        cleanup_state
            .attempted_lease_handles
            .push(lease.handle.clone());
        let command = QualificationNodeCommand::Acquire {
            lease_handle: lease.handle.clone(),
            stable_id: lease.stable_id.clone(),
            owner: lease.owner.clone(),
            ttl_millis: lease_ttl_millis,
        };
        let reply = invoke_timed(
            port,
            clock,
            config,
            &lease_pod,
            &command,
            cancellation,
            QualificationKubernetesConcurrentV5Stage::AcquireLeases,
        )
        .await?;
        match reply.reply {
            QualificationNodeReply::LeaseAcquired { fence } if fence != 0 => fences.push(fence),
            _ => {
                return Err(QualificationKubernetesConcurrentV5Failure::Reply {
                    stage: QualificationKubernetesConcurrentV5Stage::AcquireLeases,
                })
            }
        }
    }

    let preflight = invoke_timed(
        port,
        clock,
        config,
        &pod_name(RESTORE_MEMBER_INDEX),
        &QualificationNodeCommand::ConcurrentRestore {
            state_type: workload.state_type.clone(),
        },
        cancellation,
        QualificationKubernetesConcurrentV5Stage::InitialRestore,
    )
    .await?;
    if !matches!(
        preflight.reply,
        QualificationNodeReply::ConcurrentRestore {
            complete: true,
            ref records,
        } if records.is_empty()
    ) {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply {
            stage: QualificationKubernetesConcurrentV5Stage::InitialRestore,
        });
    }

    let campaign_started_ns = clock.elapsed_ns();
    let initial = sample_fleet(
        config,
        expectations,
        port,
        clock,
        cancellation,
        true,
        QualificationKubernetesConcurrentV5Stage::InitialReadiness,
    )
    .await?;
    let initial_journal_head = common_ready_journal_head(
        &initial,
        QualificationKubernetesConcurrentV5Stage::InitialReadiness,
    )?;

    cleanup_state.watch_attempted = true;
    let watch_registration = invoke_timed(
        port,
        clock,
        config,
        &pod_name(WATCH_MEMBER_INDEX),
        &QualificationNodeCommand::StartConcurrentWatch {
            subscription_id: workload.subscription_id.clone(),
            requested_after_journal_sequence: initial_journal_head,
        },
        cancellation,
        QualificationKubernetesConcurrentV5Stage::StartWatch,
    )
    .await?;
    if !matches!(
        watch_registration.reply,
        QualificationNodeReply::ConcurrentWatchStarted {
            ref subscription_id,
            requested_after_journal_sequence,
        } if subscription_id == &workload.subscription_id
            && requested_after_journal_sequence == initial_journal_head
    ) {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply {
            stage: QualificationKubernetesConcurrentV5Stage::StartWatch,
        });
    }

    let batch = invoke_timed(
        port,
        clock,
        config,
        &lease_pod,
        &workload.batch_command(),
        cancellation,
        QualificationKubernetesConcurrentV5Stage::Batch,
    )
    .await?;
    validate_batch_reply(workload, &fences, &batch.reply)?;
    let post_batch = sample_fleet(
        config,
        expectations,
        port,
        clock,
        cancellation,
        true,
        QualificationKubernetesConcurrentV5Stage::PostBatchReadiness,
    )
    .await?;
    let terminal_journal_head = common_ready_journal_head(
        &post_batch,
        QualificationKubernetesConcurrentV5Stage::PostBatchReadiness,
    )?;
    if terminal_journal_head <= initial_journal_head {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply {
            stage: QualificationKubernetesConcurrentV5Stage::PostBatchReadiness,
        });
    }

    let isolation_actuation = set_fleet_rpc_availability(
        config,
        port,
        clock,
        cancellation,
        QualificationConsensusRpcAvailability::Unavailable,
        QualificationKubernetesConcurrentV5Stage::IsolateFleet,
    )
    .await?;
    let isolation_completed_ns = gate_transition_latest_completion(
        &isolation_actuation,
        config.member_count,
        QualificationConsensusRpcAvailability::Unavailable,
        QualificationKubernetesConcurrentV5Stage::IsolateFleet,
    )?;
    validate_campaign_bound(campaign_started_ns, isolation_completed_ns)?;
    let isolated = sample_fleet_transition(
        config,
        expectations,
        port,
        clock,
        cancellation,
        FleetReadinessTransitionRequest {
            expected_ready: false,
            stage: QualificationKubernetesConcurrentV5Stage::IsolatedReadiness,
            transition_started_ns: isolation_completed_ns,
            campaign_started_ns,
        },
    )
    .await?;

    let recovery_actuation = set_fleet_rpc_availability(
        config,
        port,
        clock,
        cancellation,
        QualificationConsensusRpcAvailability::Available,
        QualificationKubernetesConcurrentV5Stage::RecoverFleet,
    )
    .await?;
    let recovery_completed_ns = gate_transition_latest_completion(
        &recovery_actuation,
        config.member_count,
        QualificationConsensusRpcAvailability::Available,
        QualificationKubernetesConcurrentV5Stage::RecoverFleet,
    )?;
    validate_campaign_bound(campaign_started_ns, recovery_completed_ns)?;
    let recovered = sample_fleet_transition(
        config,
        expectations,
        port,
        clock,
        cancellation,
        FleetReadinessTransitionRequest {
            expected_ready: true,
            stage: QualificationKubernetesConcurrentV5Stage::RecoveredReadiness,
            transition_started_ns: recovery_completed_ns,
            campaign_started_ns,
        },
    )
    .await?;
    if common_ready_journal_head(
        recovered.final_round(QualificationKubernetesConcurrentV5Stage::RecoveredReadiness)?,
        QualificationKubernetesConcurrentV5Stage::RecoveredReadiness,
    )? != terminal_journal_head
    {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply {
            stage: QualificationKubernetesConcurrentV5Stage::RecoveredReadiness,
        });
    }

    let finish_command = QualificationNodeCommand::FinishConcurrentWatch {
        subscription_id: workload.subscription_id.clone(),
        complete_through_journal_sequence: terminal_journal_head,
    };
    let restore_command = QualificationNodeCommand::ConcurrentRestore {
        state_type: workload.state_type.clone(),
    };
    let watch_pod = pod_name(WATCH_MEMBER_INDEX);
    let restore_pod = pod_name(RESTORE_MEMBER_INDEX);
    let (watch, restore) = tokio::join!(
        invoke_timed(
            port,
            clock,
            config,
            &watch_pod,
            &finish_command,
            cancellation,
            QualificationKubernetesConcurrentV5Stage::FinishWatch,
        ),
        invoke_timed(
            port,
            clock,
            config,
            &restore_pod,
            &restore_command,
            cancellation,
            QualificationKubernetesConcurrentV5Stage::TerminalRestore,
        ),
    );
    let watch = watch?;
    let restore = restore?;
    let campaign_completed_ns = watch.completed_ns.max(restore.completed_ns);
    validate_campaign_bound(campaign_started_ns, campaign_completed_ns)?;

    let observations = CampaignObservations {
        initial,
        batch,
        post_batch,
        isolated,
        recovered,
        watch_started_ns: watch_registration.started_ns,
        watch,
        restore,
        isolation_actuation,
        recovery_actuation,
        campaign_started_ns,
        campaign_completed_ns,
        initial_journal_head,
        terminal_journal_head,
        fences,
    };
    collect_history(config, workload, expectations, observations)
}

fn collect_history(
    config: &QualificationKubernetesConcurrentV5Config,
    workload: &FixedWorkload,
    expectations: &[QualificationKubernetesReadinessExpectation],
    observations: CampaignObservations,
) -> Result<QualificationConcurrentHistoryV5, QualificationKubernetesConcurrentV5Failure> {
    let CampaignObservations {
        initial,
        batch,
        post_batch,
        isolated,
        recovered,
        watch_started_ns,
        watch,
        restore,
        isolation_actuation,
        recovery_actuation,
        campaign_started_ns,
        campaign_completed_ns,
        initial_journal_head,
        terminal_journal_head,
        fences,
    } = observations;
    let (isolation_started_ns, isolation_completed_ns) = gate_transition_bounds(
        &isolation_actuation,
        config.member_count,
        QualificationConsensusRpcAvailability::Unavailable,
        QualificationKubernetesConcurrentV5Stage::IsolateFleet,
    )?;
    let (recovery_started_ns, recovery_completed_ns) = gate_transition_bounds(
        &recovery_actuation,
        config.member_count,
        QualificationConsensusRpcAvailability::Available,
        QualificationKubernetesConcurrentV5Stage::RecoverFleet,
    )?;
    let initial_interval_end = isolation_started_ns
        .checked_sub(1)
        .ok_or(QualificationKubernetesConcurrentV5Failure::Clock)?;
    let isolated_interval_end = recovery_completed_ns;
    let recovered_interval_start = recovery_completed_ns
        .checked_add(1)
        .ok_or(QualificationKubernetesConcurrentV5Failure::Clock)?;
    let first_isolated_started_ns = transition_first_started_ns(
        &isolated,
        QualificationKubernetesConcurrentV5Stage::IsolatedReadiness,
    )?;
    let last_isolated_completed_ns = transition_last_completed_ns(
        &isolated,
        QualificationKubernetesConcurrentV5Stage::IsolatedReadiness,
    )?;
    let first_recovered_started_ns = transition_first_started_ns(
        &recovered,
        QualificationKubernetesConcurrentV5Stage::RecoveredReadiness,
    )?;
    let last_connected_completed_ns = initial
        .iter()
        .chain(&post_batch)
        .map(|observation| observation.completed_ns)
        .chain(std::iter::once(batch.completed_ns))
        .max()
        .ok_or(QualificationKubernetesConcurrentV5Failure::Clock)?;
    if initial_interval_end < campaign_started_ns
        || last_connected_completed_ns > initial_interval_end
        || isolation_completed_ns >= first_isolated_started_ns
        || recovery_started_ns <= last_isolated_completed_ns
        || recovered_interval_start > first_recovered_started_ns
        || campaign_completed_ns < recovered_interval_start
    {
        return Err(QualificationKubernetesConcurrentV5Failure::Clock);
    }

    let processes = expectations
        .iter()
        .enumerate()
        .map(|(index, expectation)| {
            QualificationConcurrentProcessV5::try_new(
                format!("node-{index}"),
                expectation.expected_node_id(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    let all_processes = (0..config.member_count).collect::<Vec<_>>();
    let all_pairs = (0..config.member_count)
        .flat_map(|left| (left + 1..config.member_count).map(move |right| (left, right)))
        .collect::<Vec<_>>();
    let mut schedule = QualificationConcurrentFaultScheduleV5Builder::new(
        config.history_id.clone(),
        &processes,
        campaign_started_ns,
    )
    .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    schedule
        .push_interval(initial_interval_end, &all_processes, &all_pairs)
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    schedule
        .push_interval(isolated_interval_end, &all_processes, &[])
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    schedule
        .push_interval(campaign_completed_ns, &all_processes, &all_pairs)
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    let schedule = schedule
        .finish()
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;

    let valid_through_ns = campaign_completed_ns
        .checked_add(1)
        .ok_or(QualificationKubernetesConcurrentV5Failure::Clock)?;
    let leases = workload
        .leases
        .iter()
        .zip(&fences)
        .map(|(lease, fence)| {
            QualificationConcurrentLeaseBindingV5::try_new(
                qualification_key_bytes_sha256(lease.stable_id.as_bytes()),
                qualification_owner_sha256(&lease.owner),
                *fence,
                campaign_started_ns,
                valid_through_ns,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    let contract = QualificationConcurrentHistoryContractV5::try_new(
        &config.history_id,
        initial_journal_head,
        QUALIFICATION_CONCURRENT_READINESS_V5_MAX_GAP_NS,
        leases,
    )
    .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    let mut collector = QualificationConcurrentHistoryV5Builder::new(
        config.history_id.clone(),
        processes,
        schedule,
        contract,
    )
    .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;

    record_readiness_group(&mut collector, workload, "initial", &initial)?;
    let expected_mutations = workload.expected_mutations(&fences).ok_or(
        QualificationKubernetesConcurrentV5Failure::Reply {
            stage: QualificationKubernetesConcurrentV5Stage::Collect,
        },
    )?;
    collector
        .record_batch(
            format!("v5-{}-batch", workload.token),
            "node-0",
            batch.started_ns,
            batch.completed_ns,
            &expected_mutations,
            &batch.reply,
        )
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    record_readiness_group(&mut collector, workload, "post-batch", &post_batch)?;
    record_transition_readiness(&mut collector, workload, "isolated", &isolated)?;
    record_transition_readiness(&mut collector, workload, "recovered", &recovered)?;

    let watch_expectation = QualificationConcurrentWatchExpectationV5::new(
        workload.subscription_id.clone(),
        initial_journal_head,
    );
    collector
        .record_watch(
            format!("v5-{}-watch", workload.token),
            &format!("node-{WATCH_MEMBER_INDEX}"),
            watch_started_ns,
            watch.completed_ns,
            &watch_expectation,
            &watch.reply,
        )
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    collector
        .record_restore(
            format!("v5-{}-restore", workload.token),
            &format!("node-{RESTORE_MEMBER_INDEX}"),
            restore.started_ns,
            restore.completed_ns,
            &restore.reply,
        )
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;

    let history = collector
        .finish()
        .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    if history.contract().initial_journal_head() != initial_journal_head
        || history
            .rows()
            .iter()
            .filter_map(|row| {
                match &row.operation {
                crate::qualification_concurrent_v5::QualificationConcurrentOperationV5::Readiness {
                    journal_head: Some(head),
                    ..
                } => Some(*head),
                _ => None,
            }
            })
            .max()
            != Some(terminal_journal_head)
    {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply {
            stage: QualificationKubernetesConcurrentV5Stage::Collect,
        });
    }
    Ok(history)
}

fn record_readiness_group(
    collector: &mut QualificationConcurrentHistoryV5Builder,
    workload: &FixedWorkload,
    phase: &str,
    group: &[TimedReply],
) -> Result<(), QualificationKubernetesConcurrentV5Failure> {
    for (index, observation) in group.iter().enumerate() {
        collector
            .record_readiness(
                format!("v5-{}-{phase}-{index}", workload.token),
                &format!("node-{index}"),
                observation.started_ns,
                observation.completed_ns,
                &observation.reply,
            )
            .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
    }
    Ok(())
}

fn record_transition_readiness(
    collector: &mut QualificationConcurrentHistoryV5Builder,
    workload: &FixedWorkload,
    phase: &str,
    transition: &FleetReadinessTransition,
) -> Result<(), QualificationKubernetesConcurrentV5Failure> {
    for (round_index, round) in transition.rounds.iter().enumerate() {
        for (member_index, observation) in round.iter().enumerate() {
            let QualificationNodeReply::ConcurrentReadiness { .. } = &observation.reply else {
                return Err(QualificationKubernetesConcurrentV5Failure::Reply {
                    stage: QualificationKubernetesConcurrentV5Stage::Collect,
                });
            };
            collector
                .record_readiness(
                    format!("v5-{}-{phase}-{round_index}-{member_index}", workload.token),
                    &format!("node-{member_index}"),
                    observation.started_ns,
                    observation.completed_ns,
                    &observation.reply,
                )
                .map_err(QualificationKubernetesConcurrentV5Failure::Collector)?;
        }
    }
    Ok(())
}

async fn sample_fleet<P, C>(
    config: &QualificationKubernetesConcurrentV5Config,
    expectations: &[QualificationKubernetesReadinessExpectation],
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
    expected_ready: bool,
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<Vec<TimedReply>, QualificationKubernetesConcurrentV5Failure>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    let observations =
        sample_fleet_round(config, expectations, port, clock, cancellation, stage).await?;
    if observations.iter().any(|observation| {
        !matches!(
            &observation.reply,
            QualificationNodeReply::ConcurrentReadiness { status }
                if status.ready == expected_ready
        )
    }) {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
    }
    Ok(observations)
}

async fn sample_fleet_transition<P, C>(
    config: &QualificationKubernetesConcurrentV5Config,
    expectations: &[QualificationKubernetesReadinessExpectation],
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
    request: FleetReadinessTransitionRequest,
) -> Result<FleetReadinessTransition, QualificationKubernetesConcurrentV5Failure>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    let FleetReadinessTransitionRequest {
        expected_ready,
        stage,
        transition_started_ns,
        campaign_started_ns,
    } = request;
    let timeout_ns =
        u64::try_from(QUALIFICATION_KUBERNETES_CONCURRENT_V5_TRANSITION_TIMEOUT.as_nanos())
            .map_err(|_| QualificationKubernetesConcurrentV5Failure::Clock)?;
    let deadline_ns = transition_started_ns
        .checked_add(timeout_ns)
        .ok_or(QualificationKubernetesConcurrentV5Failure::Clock)?;
    let mut rounds = Vec::with_capacity(MAX_TRANSITION_ROUNDS);
    for _ in 0..MAX_TRANSITION_ROUNDS {
        check_cancellation(cancellation)?;
        let round =
            sample_fleet_round(config, expectations, port, clock, cancellation, stage).await?;
        if !expected_ready
            && round.iter().any(|observation| {
                matches!(
                    &observation.reply,
                    QualificationNodeReply::ConcurrentReadiness { status } if status.ready
                )
            })
        {
            // Every disable command already returned its exact acknowledgement
            // and the conservative schedule has removed every pair. A `Ready`
            // reply is contradictory authority evidence, not healthy
            // lifecycle lag, and must never be omitted or retried.
            return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
        }
        let completed_ns = round
            .iter()
            .map(|observation| observation.completed_ns)
            .max()
            .ok_or(QualificationKubernetesConcurrentV5Failure::Reply { stage })?;
        validate_campaign_bound(campaign_started_ns, completed_ns)?;
        if completed_ns > deadline_ns {
            return Err(QualificationKubernetesConcurrentV5Failure::TransitionTimeout { stage });
        }
        let converged = round.iter().all(|observation| {
            matches!(
                &observation.reply,
                QualificationNodeReply::ConcurrentReadiness { status }
                    if status.ready == expected_ready
            )
        });
        rounds.push(round);
        check_cancellation(cancellation)?;
        if converged {
            return Ok(FleetReadinessTransition { rounds });
        }

        let before_sleep_ns = clock.elapsed_ns();
        if before_sleep_ns < transition_started_ns {
            return Err(QualificationKubernetesConcurrentV5Failure::Clock);
        }
        if before_sleep_ns >= deadline_ns {
            return Err(QualificationKubernetesConcurrentV5Failure::TransitionTimeout { stage });
        }
        let remaining = Duration::from_nanos(deadline_ns - before_sleep_ns);
        let sleep_for = QUALIFICATION_KUBERNETES_CONCURRENT_V5_TRANSITION_CADENCE.min(remaining);
        let slept = tokio::select! {
            biased;
            () = cancellation.cancelled() => false,
            () = clock.sleep(sleep_for) => true,
        };
        if !slept {
            return Err(QualificationKubernetesConcurrentV5Failure::Cancelled);
        }
        let after_sleep_ns = clock.elapsed_ns();
        if after_sleep_ns <= before_sleep_ns {
            return Err(QualificationKubernetesConcurrentV5Failure::Clock);
        }
        validate_campaign_bound(campaign_started_ns, after_sleep_ns)?;
    }
    Err(QualificationKubernetesConcurrentV5Failure::TransitionTimeout { stage })
}

async fn sample_fleet_round<P, C>(
    config: &QualificationKubernetesConcurrentV5Config,
    expectations: &[QualificationKubernetesReadinessExpectation],
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<Vec<TimedReply>, QualificationKubernetesConcurrentV5Failure>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    let futures = expectations
        .iter()
        .enumerate()
        .map(|(index, expectation)| async move {
            let observation = invoke_timed(
                port,
                clock,
                config,
                &pod_name(index),
                &QualificationNodeCommand::ProbeConcurrentReadiness,
                cancellation,
                stage,
            )
            .await?;
            let QualificationNodeReply::ConcurrentReadiness { status } = &observation.reply else {
                return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
            };
            if !expectation.accepts_concurrent_readiness_reply(&observation.reply) {
                return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
            }
            let condition = if status.ready {
                QualificationKubernetesReadinessCondition::ready()
            } else {
                QualificationKubernetesReadinessCondition::not_ready(readiness_reason(
                    status.reason_code,
                ))
            };
            port.publish_readiness(
                &config.namespace,
                &pod_name(index),
                &condition,
                cancellation,
            )
            .await
            .map_err(|error| map_port_failure(stage, error))?;
            Ok(observation)
        });
    join_all(futures).await.into_iter().collect()
}

async fn set_fleet_rpc_availability<P, C>(
    config: &QualificationKubernetesConcurrentV5Config,
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
    availability: QualificationConsensusRpcAvailability,
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<FleetGateTransition, QualificationKubernetesConcurrentV5Failure>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    let futures = (0..config.member_count).map(|index| async move {
        let command = QualificationNodeCommand::SetConsensusRpcAvailability { availability };
        let pod = pod_name(index);
        let observation =
            invoke_timed(port, clock, config, &pod, &command, cancellation, stage).await?;
        if !matches!(
            observation.reply,
            QualificationNodeReply::ConsensusRpcAvailability {
                availability: actual,
            } if actual == availability
        ) {
            return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
        }
        Ok(observation)
    });
    let completions = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    if completions.len() != config.member_count {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
    }
    Ok(FleetGateTransition {
        members: completions,
    })
}

fn gate_transition_latest_completion(
    transition: &FleetGateTransition,
    member_count: usize,
    availability: QualificationConsensusRpcAvailability,
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<u64, QualificationKubernetesConcurrentV5Failure> {
    gate_transition_bounds(transition, member_count, availability, stage)
        .map(|(_, completed_ns)| completed_ns)
}

fn gate_transition_bounds(
    transition: &FleetGateTransition,
    member_count: usize,
    availability: QualificationConsensusRpcAvailability,
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<(u64, u64), QualificationKubernetesConcurrentV5Failure> {
    if transition.members.len() != member_count {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
    }
    let mut started_ns = None;
    let mut completed_ns = None;
    for observation in &transition.members {
        if !matches!(
            observation.reply,
            QualificationNodeReply::ConsensusRpcAvailability {
                availability: actual,
            } if actual == availability
        ) || observation.completed_ns < observation.started_ns
        {
            return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
        }
        started_ns = Some(started_ns.map_or(observation.started_ns, |current: u64| {
            current.min(observation.started_ns)
        }));
        completed_ns = Some(
            completed_ns.map_or(observation.completed_ns, |current: u64| {
                current.max(observation.completed_ns)
            }),
        );
    }
    started_ns
        .zip(completed_ns)
        .ok_or(QualificationKubernetesConcurrentV5Failure::Reply { stage })
}

fn transition_first_started_ns(
    transition: &FleetReadinessTransition,
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<u64, QualificationKubernetesConcurrentV5Failure> {
    transition
        .rounds
        .iter()
        .flatten()
        .map(|observation| observation.started_ns)
        .min()
        .ok_or(QualificationKubernetesConcurrentV5Failure::Reply { stage })
}

fn transition_last_completed_ns(
    transition: &FleetReadinessTransition,
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<u64, QualificationKubernetesConcurrentV5Failure> {
    transition
        .rounds
        .iter()
        .flatten()
        .map(|observation| observation.completed_ns)
        .max()
        .ok_or(QualificationKubernetesConcurrentV5Failure::Reply { stage })
}

async fn invoke_timed<P, C>(
    port: &P,
    clock: &C,
    config: &QualificationKubernetesConcurrentV5Config,
    pod_name: &str,
    command: &QualificationNodeCommand,
    cancellation: &QualificationKubernetesCampaignCancellation,
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<TimedReply, QualificationKubernetesConcurrentV5Failure>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    check_cancellation(cancellation)?;
    let started_ns = clock.elapsed_ns();
    let reply = port
        .invoke_command(&config.namespace, pod_name, command, cancellation)
        .await
        .map_err(|error| map_port_failure(stage, error))?;
    let completed_ns = clock.elapsed_ns();
    if completed_ns < started_ns {
        return Err(QualificationKubernetesConcurrentV5Failure::Clock);
    }
    Ok(TimedReply {
        started_ns,
        completed_ns,
        reply,
    })
}

async fn publish_fleet_condition<P>(
    config: &QualificationKubernetesConcurrentV5Config,
    port: &P,
    condition: &QualificationKubernetesReadinessCondition,
    cancellation: &QualificationKubernetesCampaignCancellation,
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<(), QualificationKubernetesConcurrentV5Failure>
where
    P: QualificationKubernetesCampaignPort,
{
    let results = join_all((0..config.member_count).map(|index| async move {
        let pod = pod_name(index);
        port.publish_readiness(&config.namespace, &pod, condition, cancellation)
            .await
    }))
    .await;
    results
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map(|_| ())
        .map_err(|error| map_port_failure(stage, error))
}

async fn cleanup_campaign<P>(
    config: &QualificationKubernetesConcurrentV5Config,
    workload: &FixedWorkload,
    port: &P,
    state: &CleanupState,
) -> bool
where
    P: QualificationKubernetesCampaignPort,
{
    let cleanup_cancellation = QualificationKubernetesCampaignCancellation::new();
    let cleanup = &cleanup_cancellation;
    let availability_results = join_all((0..config.member_count).map(|index| async move {
        let pod = pod_name(index);
        let available = QualificationNodeCommand::SetConsensusRpcAvailability {
            availability: QualificationConsensusRpcAvailability::Available,
        };
        port.invoke_command(&config.namespace, &pod, &available, cleanup)
            .await
    }))
    .await;
    let mut complete = availability_results.into_iter().all(|result| {
        matches!(
            result,
            Ok(QualificationNodeReply::ConsensusRpcAvailability {
                availability: QualificationConsensusRpcAvailability::Available,
            })
        )
    });

    if state.watch_attempted {
        let aborted = port
            .invoke_command(
                &config.namespace,
                &pod_name(WATCH_MEMBER_INDEX),
                &QualificationNodeCommand::AbortConcurrentWatch {
                    subscription_id: workload.subscription_id.clone(),
                },
                cleanup,
            )
            .await;
        complete &= matches!(
            aborted,
            Ok(QualificationNodeReply::ConcurrentWatchAborted { subscription_id })
                if subscription_id == workload.subscription_id
        );
    }

    for handle in &state.attempted_lease_handles {
        let forgotten = port
            .invoke_command(
                &config.namespace,
                &pod_name(0),
                &QualificationNodeCommand::ForgetLease {
                    lease_handle: handle.clone(),
                },
                cleanup,
            )
            .await;
        complete &= matches!(forgotten, Ok(QualificationNodeReply::LeaseHandleForgotten));
    }

    let condition = QualificationKubernetesReadinessCondition::not_ready(
        QualificationKubernetesReadinessReason::CampaignStopped,
    );
    let condition = &condition;
    let condition_results = join_all((0..config.member_count).map(|index| async move {
        let pod = pod_name(index);
        port.publish_readiness(&config.namespace, &pod, condition, cleanup)
            .await
    }))
    .await;
    complete & condition_results.into_iter().all(|result| result.is_ok())
}

fn common_ready_journal_head(
    observations: &[TimedReply],
    stage: QualificationKubernetesConcurrentV5Stage,
) -> Result<u64, QualificationKubernetesConcurrentV5Failure> {
    let mut head = None;
    for observation in observations {
        let QualificationNodeReply::ConcurrentReadiness { status } = &observation.reply else {
            return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
        };
        let Some(candidate) = status.ready.then_some(status.journal_head).flatten() else {
            return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
        };
        if head.is_some_and(|current| current != candidate) {
            return Err(QualificationKubernetesConcurrentV5Failure::Reply { stage });
        }
        head = Some(candidate);
    }
    head.ok_or(QualificationKubernetesConcurrentV5Failure::Reply { stage })
}

fn validate_batch_reply(
    workload: &FixedWorkload,
    fences: &[u64],
    reply: &QualificationNodeReply,
) -> Result<(), QualificationKubernetesConcurrentV5Failure> {
    let expected = workload.expected_mutations(fences).ok_or(
        QualificationKubernetesConcurrentV5Failure::Reply {
            stage: QualificationKubernetesConcurrentV5Stage::Batch,
        },
    )?;
    let QualificationNodeReply::ConcurrentBatch { outcome, slots } = reply else {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply {
            stage: QualificationKubernetesConcurrentV5Stage::Batch,
        });
    };
    let exact_outcomes = [
        QualificationConcurrentBatchSlotOutcome::Success,
        QualificationConcurrentBatchSlotOutcome::Conflict,
    ];
    if *outcome != QualificationConcurrentBatchOutcome::Completed
        || slots.len() != expected.len()
        || slots
            .iter()
            .zip(expected.iter().zip(exact_outcomes))
            .enumerate()
            .any(|(index, (slot, (mutation, expected_outcome)))| {
                slot.slot_index != index + 1
                    || slot.outcome != expected_outcome
                    || slot.mutation != *mutation
            })
    {
        return Err(QualificationKubernetesConcurrentV5Failure::Reply {
            stage: QualificationKubernetesConcurrentV5Stage::Batch,
        });
    }
    Ok(())
}

fn validate_campaign_bound(
    started_ns: u64,
    completed_ns: u64,
) -> Result<(), QualificationKubernetesConcurrentV5Failure> {
    let elapsed = completed_ns
        .checked_sub(started_ns)
        .ok_or(QualificationKubernetesConcurrentV5Failure::Clock)?;
    let maximum = u64::try_from(QUALIFICATION_KUBERNETES_CONCURRENT_V5_MAX_DURATION.as_nanos())
        .map_err(|_| QualificationKubernetesConcurrentV5Failure::Clock)?;
    if elapsed > maximum {
        Err(QualificationKubernetesConcurrentV5Failure::Deadline)
    } else {
        Ok(())
    }
}

fn check_cancellation(
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<(), QualificationKubernetesConcurrentV5Failure> {
    if cancellation.is_cancelled() {
        Err(QualificationKubernetesConcurrentV5Failure::Cancelled)
    } else {
        Ok(())
    }
}

fn map_port_failure(
    stage: QualificationKubernetesConcurrentV5Stage,
    error: QualificationKubernetesPortError,
) -> QualificationKubernetesConcurrentV5Failure {
    if error == QualificationKubernetesPortError::Cancelled {
        QualificationKubernetesConcurrentV5Failure::Cancelled
    } else {
        QualificationKubernetesConcurrentV5Failure::Port { stage, error }
    }
}

fn readiness_reason(code: QualificationReadinessCode) -> QualificationKubernetesReadinessReason {
    match code {
        QualificationReadinessCode::TopologyInvalid => {
            QualificationKubernetesReadinessReason::DurableTopologyInvalid
        }
        QualificationReadinessCode::RecoveryRequired => {
            QualificationKubernetesReadinessReason::DurableRecoveryRequired
        }
        QualificationReadinessCode::Ready | QualificationReadinessCode::NoQuorum => {
            QualificationKubernetesReadinessReason::DurableQuorumUnavailable
        }
    }
}

fn pod_name(index: usize) -> String {
    format!("{QUALIFICATION_KUBERNETES_FLEET_NAME}-{index}-0")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::*;
    use crate::qualification::{
        QualificationConcurrentBatchSlotResult, QualificationConcurrentReadiness,
        QualificationConcurrentRecordSnapshot, QualificationConcurrentWatchEvent,
    };
    use crate::qualification_concurrent_v5::{
        QualificationConcurrentOperationV5, QualificationConcurrentReadinessStateV5,
    };
    use crate::qualification_kubernetes_campaign::QualificationKubernetesConditionStatus;

    struct FakeClock {
        now_ns: AtomicU64,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now_ns: AtomicU64::new(1),
            }
        }

        fn now_ns(&self) -> u64 {
            self.now_ns.load(Ordering::SeqCst)
        }

        fn advance_ns(&self, duration_ns: u64) {
            self.now_ns.fetch_add(duration_ns, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl QualificationKubernetesCampaignClock for FakeClock {
        fn elapsed_ns(&self) -> u64 {
            self.now_ns.fetch_add(1, Ordering::SeqCst)
        }

        async fn sleep(&self, duration: Duration) {
            let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
            self.now_ns.fetch_add(nanos, Ordering::SeqCst);
        }
    }

    #[derive(Clone, Copy)]
    struct FakeGateFailure {
        member_index: usize,
        availability: QualificationConsensusRpcAvailability,
    }

    #[derive(Clone, Copy)]
    struct FakeGateEvent {
        member_index: usize,
        availability: QualificationConsensusRpcAvailability,
        invoked_ns: u64,
        replied_ns: u64,
    }

    struct FakePort {
        history_id: String,
        member_count: usize,
        clock: Arc<FakeClock>,
        rpc_available: Mutex<Vec<bool>>,
        fences: Mutex<BTreeMap<String, u64>>,
        batch_applied: AtomicBool,
        batch_invocations: AtomicUsize,
        readiness_invocations: AtomicUsize,
        fail_batch: bool,
        saw_isolation: AtomicBool,
        delayed_loss_replies: AtomicUsize,
        delayed_recovery_replies: AtomicUsize,
        never_recovers: AtomicBool,
        disable_delays_ns: Vec<u64>,
        enable_delays_ns: Vec<u64>,
        gate_failure: Mutex<Option<FakeGateFailure>>,
        gate_events: Mutex<Vec<FakeGateEvent>>,
        conditions: Mutex<Vec<(String, QualificationKubernetesConditionStatus)>>,
    }

    impl FakePort {
        fn new(
            history_id: &str,
            member_count: usize,
            fail_batch: bool,
            clock: Arc<FakeClock>,
        ) -> Self {
            Self {
                history_id: history_id.to_owned(),
                member_count,
                clock,
                rpc_available: Mutex::new(vec![true; member_count]),
                fences: Mutex::new(BTreeMap::new()),
                batch_applied: AtomicBool::new(false),
                batch_invocations: AtomicUsize::new(0),
                readiness_invocations: AtomicUsize::new(0),
                fail_batch,
                saw_isolation: AtomicBool::new(false),
                delayed_loss_replies: AtomicUsize::new(0),
                delayed_recovery_replies: AtomicUsize::new(0),
                never_recovers: AtomicBool::new(false),
                disable_delays_ns: vec![0; member_count],
                enable_delays_ns: vec![0; member_count],
                gate_failure: Mutex::new(None),
                gate_events: Mutex::new(Vec::new()),
                conditions: Mutex::new(Vec::new()),
            }
        }

        fn with_transition_delays(
            mut self,
            disable_delays_ns: Vec<u64>,
            enable_delays_ns: Vec<u64>,
        ) -> Self {
            assert_eq!(disable_delays_ns.len(), self.member_count);
            assert_eq!(enable_delays_ns.len(), self.member_count);
            self.disable_delays_ns = disable_delays_ns;
            self.enable_delays_ns = enable_delays_ns;
            self
        }

        fn with_delayed_loss_replies(self, replies: usize) -> Self {
            self.delayed_loss_replies.store(replies, Ordering::SeqCst);
            self
        }

        fn with_delayed_recovery_replies(self, replies: usize) -> Self {
            self.delayed_recovery_replies
                .store(replies, Ordering::SeqCst);
            self
        }

        fn with_never_recovery(self) -> Self {
            self.never_recovers.store(true, Ordering::SeqCst);
            self
        }

        fn with_gate_failure(
            self,
            member_index: usize,
            availability: QualificationConsensusRpcAvailability,
        ) -> Self {
            *self.gate_failure.lock().expect("fake gate failure") = Some(FakeGateFailure {
                member_index,
                availability,
            });
            self
        }

        fn workload(&self) -> FixedWorkload {
            FixedWorkload::new(&self.history_id).expect("valid fake workload")
        }

        fn node_index(&self, pod: &str) -> usize {
            pod.strip_prefix(&format!("{QUALIFICATION_KUBERNETES_FLEET_NAME}-"))
                .and_then(|value| value.strip_suffix("-0"))
                .and_then(|value| value.parse().ok())
                .filter(|index| *index < self.member_count)
                .expect("runner emits a valid pod")
        }

        fn record(&self) -> QualificationConcurrentRecordSnapshot {
            let workload = self.workload();
            let lease = &workload.leases[0];
            QualificationConcurrentRecordSnapshot {
                key_sha256: qualification_key_bytes_sha256(lease.stable_id.as_bytes()),
                generation: 1,
                owner_sha256: qualification_owner_sha256(&lease.owner),
                fence: 7,
                state_class: QualificationConcurrentStateClass::AuthoritativeSession,
                state_type_sha256: qualification_state_type_sha256(workload.state_type.as_str()),
                expires_at_ns: None,
                value_sha256: qualification_value_sha256(lease.value.as_bytes()),
            }
        }

        fn readiness(&self, node_index: usize) -> QualificationNodeReply {
            let expectations = qualification_kubernetes_readiness_expectations(self.member_count)
                .expect("fake identities");
            let expectation = &expectations[node_index];
            self.readiness_invocations.fetch_add(1, Ordering::SeqCst);
            let rpc_available = self.rpc_available.lock().expect("fake RPC state");
            let all_available = rpc_available.iter().all(|available| *available);
            let all_unavailable = rpc_available.iter().all(|available| !*available);
            drop(rpc_available);
            let delayed_loss = all_unavailable
                && self
                    .delayed_loss_replies
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_ok();
            let delayed_recovery = all_available
                && self.saw_isolation.load(Ordering::SeqCst)
                && (self.never_recovers.load(Ordering::SeqCst)
                    || self
                        .delayed_recovery_replies
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                            remaining.checked_sub(1)
                        })
                        .is_ok());
            let available = delayed_loss || all_available && !delayed_recovery;
            let required_quorum = self.member_count / 2 + 1;
            let journal_head = if self.batch_applied.load(Ordering::SeqCst) {
                11
            } else {
                10
            };
            QualificationNodeReply::ConcurrentReadiness {
                status: QualificationConcurrentReadiness {
                    ready: available,
                    reason_code: if available {
                        QualificationReadinessCode::Ready
                    } else {
                        QualificationReadinessCode::NoQuorum
                    },
                    node_id: expectation.expected_node_id(),
                    configured_voters: self.member_count,
                    configured_voter_ids: expectation.expected_voter_ids().to_vec(),
                    fresh_reachable_voters: if available { required_quorum } else { 0 },
                    agreeing_voters: if available { required_quorum } else { 0 },
                    required_quorum,
                    raft_term: available.then_some(2),
                    raft_leader_id: available
                        .then(|| expectation.expected_voter_ids().first().copied())
                        .flatten(),
                    raft_commit_index: available.then_some(20),
                    raft_applied_index: available.then_some(20),
                    journal_head: available.then_some(journal_head),
                },
            }
        }

        fn batch_reply(
            &self,
            slots: &[QualificationConcurrentBatchSlot],
        ) -> QualificationNodeReply {
            let fences = self.fences.lock().expect("fake fences");
            let results = slots
                .iter()
                .enumerate()
                .map(|(index, slot)| QualificationConcurrentBatchSlotResult {
                    slot_index: index + 1,
                    outcome: if index == 0 {
                        QualificationConcurrentBatchSlotOutcome::Success
                    } else {
                        QualificationConcurrentBatchSlotOutcome::Conflict
                    },
                    mutation: QualificationConcurrentMutationSnapshot {
                        key_sha256: qualification_key_bytes_sha256(slot.stable_id.as_bytes()),
                        expected_generation: slot.expected_generation,
                        new_generation: slot.new_generation,
                        owner_sha256: qualification_owner_sha256(
                            &self.workload().leases[index].owner,
                        ),
                        fence: *fences
                            .get(&slot.lease_handle)
                            .expect("batch lease was acquired"),
                        state_class: QualificationConcurrentStateClass::AuthoritativeSession,
                        state_type_sha256: qualification_state_type_sha256(
                            slot.state_type.as_str(),
                        ),
                        expires_at_ns: None,
                        value_sha256: qualification_value_sha256(slot.value.as_bytes()),
                    },
                })
                .collect();
            QualificationNodeReply::ConcurrentBatch {
                outcome: QualificationConcurrentBatchOutcome::Completed,
                slots: results,
            }
        }

        fn final_conditions_are_false(&self) -> bool {
            let conditions = self.conditions.lock().expect("fake conditions");
            (0..self.member_count).all(|index| {
                let pod = pod_name(index);
                conditions
                    .iter()
                    .rev()
                    .find(|(candidate, _)| candidate == &pod)
                    .is_some_and(|(_, status)| {
                        *status == QualificationKubernetesConditionStatus::False
                    })
            })
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
            let node_index = self.node_index(pod_name);
            match command {
                QualificationNodeCommand::Acquire {
                    lease_handle,
                    ttl_millis,
                    ..
                } => {
                    assert_eq!(
                        *ttl_millis,
                        u64::try_from(QUALIFICATION_KUBERNETES_CONCURRENT_V5_LEASE_TTL.as_millis())
                            .expect("test TTL")
                    );
                    let fence = if lease_handle.ends_with("-a") { 7 } else { 8 };
                    self.fences
                        .lock()
                        .expect("fake fences")
                        .insert(lease_handle.clone(), fence);
                    Ok(QualificationNodeReply::LeaseAcquired { fence })
                }
                QualificationNodeCommand::ConcurrentRestore { state_type } => {
                    assert_eq!(state_type, &self.workload().state_type);
                    Ok(QualificationNodeReply::ConcurrentRestore {
                        complete: true,
                        records: if self.batch_applied.load(Ordering::SeqCst) {
                            vec![self.record()]
                        } else {
                            Vec::new()
                        },
                    })
                }
                QualificationNodeCommand::ProbeConcurrentReadiness => {
                    Ok(self.readiness(node_index))
                }
                QualificationNodeCommand::StartConcurrentWatch {
                    subscription_id,
                    requested_after_journal_sequence,
                } => Ok(QualificationNodeReply::ConcurrentWatchStarted {
                    subscription_id: subscription_id.clone(),
                    requested_after_journal_sequence: *requested_after_journal_sequence,
                }),
                QualificationNodeCommand::ConcurrentBatch { slots } => {
                    self.batch_invocations.fetch_add(1, Ordering::SeqCst);
                    if self.fail_batch {
                        return Err(QualificationKubernetesPortError::Timeout);
                    }
                    let reply = self.batch_reply(slots);
                    self.batch_applied.store(true, Ordering::SeqCst);
                    Ok(reply)
                }
                QualificationNodeCommand::SetConsensusRpcAvailability { availability } => {
                    let delay_ns = match availability {
                        QualificationConsensusRpcAvailability::Available => {
                            self.enable_delays_ns[node_index]
                        }
                        QualificationConsensusRpcAvailability::Unavailable => {
                            self.disable_delays_ns[node_index]
                        }
                    };
                    self.rpc_available.lock().expect("fake RPC state")[node_index] =
                        *availability == QualificationConsensusRpcAvailability::Available;
                    if *availability == QualificationConsensusRpcAvailability::Unavailable {
                        self.saw_isolation.store(true, Ordering::SeqCst);
                    }
                    let invoked_ns = self.clock.now_ns();
                    self.clock.advance_ns(delay_ns);
                    let replied_ns = self.clock.now_ns();
                    self.gate_events
                        .lock()
                        .expect("fake gate events")
                        .push(FakeGateEvent {
                            member_index: node_index,
                            availability: *availability,
                            invoked_ns,
                            replied_ns,
                        });
                    let failed = {
                        let mut failure = self.gate_failure.lock().expect("fake gate failure");
                        let matches = failure.as_ref().is_some_and(|failure| {
                            failure.member_index == node_index
                                && failure.availability == *availability
                        });
                        matches && failure.take().is_some()
                    };
                    if failed {
                        return Err(QualificationKubernetesPortError::Timeout);
                    }
                    Ok(QualificationNodeReply::ConsensusRpcAvailability {
                        availability: *availability,
                    })
                }
                QualificationNodeCommand::FinishConcurrentWatch {
                    subscription_id,
                    complete_through_journal_sequence,
                } => Ok(QualificationNodeReply::ConcurrentWatchFinished {
                    subscription_id: subscription_id.clone(),
                    complete_through_journal_sequence: *complete_through_journal_sequence,
                    events: vec![QualificationConcurrentWatchEvent {
                        journal_sequence: 11,
                        record: self.record(),
                    }],
                }),
                QualificationNodeCommand::AbortConcurrentWatch { subscription_id } => {
                    Ok(QualificationNodeReply::ConcurrentWatchAborted {
                        subscription_id: subscription_id.clone(),
                    })
                }
                QualificationNodeCommand::ForgetLease { lease_handle } => {
                    self.fences
                        .lock()
                        .expect("fake fences")
                        .remove(lease_handle);
                    Ok(QualificationNodeReply::LeaseHandleForgotten)
                }
                _ => Ok(QualificationNodeReply::Error {
                    code: crate::qualification::QualificationNodeErrorCode::InvalidRequest,
                }),
            }
        }

        async fn publish_readiness(
            &self,
            _namespace: &str,
            pod_name: &str,
            condition: &QualificationKubernetesReadinessCondition,
            _cancellation: &QualificationKubernetesCampaignCancellation,
        ) -> Result<(), QualificationKubernetesPortError> {
            self.conditions
                .lock()
                .expect("fake conditions")
                .push((pod_name.to_owned(), condition.status));
            Ok(())
        }
    }

    fn config(member_count: usize) -> QualificationKubernetesConcurrentV5Config {
        QualificationKubernetesConcurrentV5Config {
            namespace: "session-ha-qualification".to_owned(),
            member_count,
            history_id: format!("deployed-v5-{member_count}"),
        }
    }

    fn assert_frozen_checker_passes(history: &QualificationConcurrentHistoryV5) {
        let history_bytes = history.encode_json_lines().expect("history JSONL");
        let schedule_bytes = history
            .fault_schedule()
            .encode_json()
            .expect("fault schedule JSON");
        let checker_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/check-session-ha-concurrent-history-v5.py");
        let checker_bytes = fs::read(&checker_path).expect("checker bytes");
        let exact_sha256 = |bytes: &[u8]| format!("sha256:{:x}", Sha256::digest(bytes));
        let schedule = history.fault_schedule();
        let contract = history.contract();
        let mut evidence: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/session-ha/candidate-evidence-v5.json"
        ))
        .expect("candidate evidence fixture");
        evidence["execution"]["history_id"] = serde_json::json!(schedule.history_id);
        evidence["execution"]["campaign_started_ns"] =
            serde_json::json!(schedule.campaign_started_ns);
        evidence["execution"]["campaign_completed_ns"] =
            serde_json::json!(schedule.campaign_completed_ns);
        evidence["execution"]["topology_members"] = serde_json::json!(schedule.process_ids.len());
        evidence["execution"]["process_ids"] = serde_json::json!(schedule.process_ids);
        evidence["execution"]["max_readiness_gap_ns"] =
            serde_json::json!(contract.max_readiness_gap_ns());
        evidence["execution"]["fault_schedule_sha256"] =
            serde_json::json!(exact_sha256(&schedule_bytes));
        evidence["workload"]["initial_journal_head"] =
            serde_json::json!(contract.initial_journal_head());
        evidence["workload"]["state_type_sha256"] = serde_json::json!(contract.state_type_sha256());
        evidence["workload"]["preacquired_leases"] =
            serde_json::to_value(contract.preacquired_leases()).expect("lease evidence");
        evidence["history"]["sha256"] = serde_json::json!(exact_sha256(&history_bytes));
        evidence["history"]["operation_count"] = serde_json::json!(history.rows().len());
        evidence["checker"]["sha256"] = serde_json::json!(exact_sha256(&checker_bytes));

        let directory = tempfile::tempdir().expect("checker directory");
        let history_path = directory.path().join("history.jsonl");
        let schedule_path = directory.path().join("schedule.json");
        let evidence_path = directory.path().join("evidence.json");
        fs::write(&history_path, history_bytes).expect("history artifact");
        fs::write(&schedule_path, schedule_bytes).expect("schedule artifact");
        fs::write(
            &evidence_path,
            serde_json::to_vec_pretty(&evidence).expect("evidence JSON"),
        )
        .expect("evidence artifact");
        let output = Command::new("python3")
            .arg(checker_path)
            .arg("--evidence")
            .arg(evidence_path)
            .arg("--fault-schedule")
            .arg(schedule_path)
            .arg("--history")
            .arg(history_path)
            .output()
            .expect("run frozen checker");
        assert!(
            output.status.success(),
            "checker rejected deployed adapter output: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[tokio::test]
    async fn three_and_five_member_campaigns_feed_the_frozen_checker() {
        for member_count in [3, 5] {
            let config = config(member_count);
            let clock = Arc::new(FakeClock::new());
            let port = FakePort::new(&config.history_id, member_count, false, Arc::clone(&clock));
            let outcome = run_qualification_kubernetes_concurrent_v5_campaign(
                &config,
                &port,
                clock.as_ref(),
                &QualificationKubernetesCampaignCancellation::new(),
            )
            .await
            .expect("valid campaign config");
            assert_eq!(
                outcome.status(),
                QualificationKubernetesConcurrentV5Status::Passed
            );
            assert!(outcome.cleanup_complete());
            assert_eq!(port.batch_invocations.load(Ordering::SeqCst), 1);
            assert!(port.final_conditions_are_false());
            let history = outcome.history().expect("passing history");
            assert_eq!(history.fault_schedule().intervals.len(), 3);
            assert!(history.fault_schedule().intervals[1]
                .available_bidirectional_pairs
                .is_empty());
            assert_frozen_checker_passes(history);
        }
    }

    #[tokio::test]
    async fn delayed_recovery_and_staggered_acks_produce_truthful_checker_evidence() {
        let member_count = 3;
        let config = config(member_count);
        let clock = Arc::new(FakeClock::new());
        let port = FakePort::new(&config.history_id, member_count, false, Arc::clone(&clock))
            .with_transition_delays(
                vec![3_000_000_000, 7_000_000_000, 2_000_000_000],
                vec![5_000_000_000, 1_000_000_000, 9_000_000_000],
            )
            .with_delayed_recovery_replies(member_count * 2);
        let outcome = run_qualification_kubernetes_concurrent_v5_campaign(
            &config,
            &port,
            clock.as_ref(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign config");
        assert_eq!(
            outcome.status(),
            QualificationKubernetesConcurrentV5Status::Passed
        );
        let history = outcome.history().expect("passing delayed campaign");
        let schedule = history.fault_schedule();
        assert_eq!(schedule.intervals.len(), 3);
        assert!(schedule.intervals[1]
            .available_bidirectional_pairs
            .is_empty());

        let events = port.gate_events.lock().expect("fake gate events");
        let unavailable = events
            .iter()
            .filter(|event| {
                event.availability == QualificationConsensusRpcAvailability::Unavailable
            })
            .copied()
            .collect::<Vec<_>>();
        let available = events
            .iter()
            .filter(|event| event.availability == QualificationConsensusRpcAvailability::Available)
            .take(member_count)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(unavailable.len(), member_count);
        assert_eq!(available.len(), member_count);
        assert_eq!(
            unavailable
                .iter()
                .map(|event| event.member_index)
                .collect::<std::collections::BTreeSet<_>>(),
            (0..member_count).collect()
        );
        assert_eq!(
            available
                .iter()
                .map(|event| event.member_index)
                .collect::<std::collections::BTreeSet<_>>(),
            (0..member_count).collect()
        );
        let conservative_isolation_start = unavailable
            .iter()
            .map(|event| event.invoked_ns.checked_sub(1).expect("runner start"))
            .min()
            .expect("disable event");
        let confirmed_recovery_end = available
            .iter()
            .map(|event| event.replied_ns)
            .max()
            .expect("enable event");
        assert_eq!(
            schedule.intervals[1].started_ns,
            conservative_isolation_start
        );
        assert_eq!(schedule.intervals[2].started_ns, confirmed_recovery_end + 1);
        drop(events);

        let recovered_start = schedule.intervals[2].started_ns;
        let transient_recovery_samples = history
            .rows()
            .iter()
            .filter(|row| row.started_ns >= recovered_start)
            .filter(|row| {
                matches!(
                    row.operation,
                    QualificationConcurrentOperationV5::Readiness {
                        state: QualificationConcurrentReadinessStateV5::NotReady,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(transient_recovery_samples, member_count * 2);
        assert!(port.readiness_invocations.load(Ordering::SeqCst) > member_count * 4);
        assert_frozen_checker_passes(history);
    }

    #[tokio::test]
    async fn post_disable_ready_contradiction_fails_closed_without_history() {
        let member_count = 3;
        let config = config(member_count);
        let clock = Arc::new(FakeClock::new());
        let port = FakePort::new(&config.history_id, member_count, false, Arc::clone(&clock))
            .with_delayed_loss_replies(1);
        let outcome = run_qualification_kubernetes_concurrent_v5_campaign(
            &config,
            &port,
            clock.as_ref(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign config");
        assert_eq!(
            outcome.failure(),
            Some(QualificationKubernetesConcurrentV5Failure::Reply {
                stage: QualificationKubernetesConcurrentV5Stage::IsolatedReadiness,
            })
        );
        assert!(outcome.history().is_none());
        assert!(outcome.cleanup_complete());
        assert_eq!(port.batch_invocations.load(Ordering::SeqCst), 1);
        assert!(port.final_conditions_are_false());
    }

    #[tokio::test]
    async fn recovery_that_never_converges_is_bounded_and_withholds_history() {
        let member_count = 3;
        let config = config(member_count);
        let clock = Arc::new(FakeClock::new());
        let port = FakePort::new(&config.history_id, member_count, false, Arc::clone(&clock))
            .with_never_recovery();
        let outcome = run_qualification_kubernetes_concurrent_v5_campaign(
            &config,
            &port,
            clock.as_ref(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign config");
        assert_eq!(
            outcome.failure(),
            Some(
                QualificationKubernetesConcurrentV5Failure::TransitionTimeout {
                    stage: QualificationKubernetesConcurrentV5Stage::RecoveredReadiness,
                }
            )
        );
        assert!(outcome.history().is_none());
        assert!(outcome.cleanup_complete());
        assert!(
            port.readiness_invocations.load(Ordering::SeqCst)
                <= member_count * (MAX_TRANSITION_ROUNDS + 3)
        );
        assert!(port.final_conditions_are_false());
    }

    #[tokio::test]
    async fn partial_or_ambiguous_gate_actuation_fails_closed_and_cleans_up() {
        for availability in [
            QualificationConsensusRpcAvailability::Unavailable,
            QualificationConsensusRpcAvailability::Available,
        ] {
            let member_count = 3;
            let mut config = config(member_count);
            config.history_id = format!("partial-gate-{availability:?}").to_ascii_lowercase();
            let clock = Arc::new(FakeClock::new());
            let port = FakePort::new(&config.history_id, member_count, false, Arc::clone(&clock))
                .with_gate_failure(1, availability);
            let outcome = run_qualification_kubernetes_concurrent_v5_campaign(
                &config,
                &port,
                clock.as_ref(),
                &QualificationKubernetesCampaignCancellation::new(),
            )
            .await
            .expect("valid campaign config");
            let stage = if availability == QualificationConsensusRpcAvailability::Unavailable {
                QualificationKubernetesConcurrentV5Stage::IsolateFleet
            } else {
                QualificationKubernetesConcurrentV5Stage::RecoverFleet
            };
            assert_eq!(
                outcome.failure(),
                Some(QualificationKubernetesConcurrentV5Failure::Port {
                    stage,
                    error: QualificationKubernetesPortError::Timeout,
                })
            );
            assert!(outcome.history().is_none());
            assert!(outcome.cleanup_complete());
            assert_eq!(port.batch_invocations.load(Ordering::SeqCst), 1);
            assert!(port
                .rpc_available
                .lock()
                .expect("fake RPC state")
                .iter()
                .all(|available| *available));
            assert!(port.final_conditions_are_false());
        }
    }

    #[tokio::test]
    async fn ambiguous_batch_is_not_retried_and_cleanup_still_runs() {
        let config = config(3);
        let clock = Arc::new(FakeClock::new());
        let port = FakePort::new(&config.history_id, 3, true, Arc::clone(&clock));
        let outcome = run_qualification_kubernetes_concurrent_v5_campaign(
            &config,
            &port,
            clock.as_ref(),
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await
        .expect("valid campaign config");
        assert_eq!(
            outcome.status(),
            QualificationKubernetesConcurrentV5Status::Failed
        );
        assert_eq!(
            outcome.failure(),
            Some(QualificationKubernetesConcurrentV5Failure::Port {
                stage: QualificationKubernetesConcurrentV5Stage::Batch,
                error: QualificationKubernetesPortError::Timeout,
            })
        );
        assert!(outcome.history().is_none());
        assert!(outcome.cleanup_complete());
        assert_eq!(port.batch_invocations.load(Ordering::SeqCst), 1);
        assert!(port.fences.lock().expect("fake fences").is_empty());
        assert!(port
            .rpc_available
            .lock()
            .expect("fake RPC state")
            .iter()
            .all(|available| *available));
        assert!(port.final_conditions_are_false());
    }

    #[tokio::test]
    async fn cancellation_before_work_returns_after_fail_closed_cleanup() {
        let config = config(3);
        let clock = Arc::new(FakeClock::new());
        let port = FakePort::new(&config.history_id, 3, false, Arc::clone(&clock));
        let cancellation = QualificationKubernetesCampaignCancellation::new();
        cancellation.cancel();
        let outcome = run_qualification_kubernetes_concurrent_v5_campaign(
            &config,
            &port,
            clock.as_ref(),
            &cancellation,
        )
        .await
        .expect("valid campaign config");
        assert_eq!(
            outcome.status(),
            QualificationKubernetesConcurrentV5Status::Cancelled
        );
        assert!(outcome.cleanup_complete());
        assert_eq!(port.batch_invocations.load(Ordering::SeqCst), 0);
        assert!(port.final_conditions_are_false());
    }

    #[test]
    fn configuration_is_bounded_and_debug_is_redacted() {
        let valid = config(3);
        assert!(valid.validate().is_ok());
        let debug = format!("{valid:?}");
        assert!(!debug.contains(&valid.namespace));
        assert!(!debug.contains(&valid.history_id));

        let mut invalid = valid.clone();
        invalid.member_count = 4;
        assert_eq!(
            invalid.validate(),
            Err(QualificationKubernetesConcurrentV5ConfigError::InvalidTopology)
        );
        invalid = valid.clone();
        invalid.history_id = "bad history".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(QualificationKubernetesConcurrentV5ConfigError::InvalidHistoryId)
        );
        invalid = valid;
        invalid.namespace = "Bad_Namespace".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(QualificationKubernetesConcurrentV5ConfigError::InvalidNamespace)
        );
    }
}
