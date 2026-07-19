//! Atomic candidate-artifact publication for the deployed v5 HA campaign.
//!
//! This module is deliberately separate from the Kubernetes adapter. It takes
//! only a conclusive, cleanup-complete v5 outcome, retains the exact frozen
//! checker and separate additive workload verifier beside their digest-bound
//! inputs, executes both without a shell under fixed time and output bounds,
//! and publishes the complete directory with one no-replace rename. The
//! resulting bundle remains
//! experimental candidate evidence and never claims production qualification.

#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Component;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::{ExitStatus, Stdio};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use thiserror::Error;
#[cfg(target_os = "linux")]
use tokio::io::{AsyncRead, AsyncReadExt};
#[cfg(target_os = "linux")]
use tokio::process::{Child, Command};

#[cfg(target_os = "linux")]
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, open, openat, renameat_with, statat, unlinkat, AtFlags,
    FileType, Mode, OFlags, RenameFlags,
};
#[cfg(target_os = "linux")]
use rustix::process::{kill_process_group, Pid, Signal};

use crate::qualification::{QualificationCandidateSourceTreeStatus, QualificationSha256};
#[cfg(target_os = "linux")]
use crate::qualification::{
    SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V5, SESSION_HA_CANDIDATE_PROFILE_V5_JSON,
};
#[cfg(target_os = "linux")]
use crate::qualification_concurrent_v5::QualificationConcurrentHistoryV5;
#[cfg(target_os = "linux")]
use crate::qualification_concurrent_v5::QUALIFICATION_CONCURRENT_HISTORY_V5_SCHEMA;
use crate::qualification_kubernetes_campaign::{
    QualificationKubernetesCampaignCancellation, QualificationKubernetesCampaignClock,
    QualificationKubernetesCampaignPort,
};
use crate::qualification_kubernetes_concurrent_v5::{
    run_qualification_kubernetes_concurrent_v5_campaign, QualificationKubernetesConcurrentV5Config,
    QualificationKubernetesConcurrentV5Outcome, QualificationKubernetesConcurrentV5Status,
};

/// Schema identifier for one atomically published candidate-only v5 bundle.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_ARTIFACT_SUMMARY_SCHEMA: &str =
    "opc-session-kubernetes-concurrent-v5-artifacts/v2";
/// Exact retained v5 candidate-profile filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_PROFILE_FILE: &str = "session-ha-profile-v5.json";
/// Exact retained v5 JSONL history filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_HISTORY_FILE: &str = "concurrent-history-v5.jsonl";
/// Exact retained v5 fault-schedule filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_FAULT_SCHEDULE_FILE: &str =
    "fault-schedule-v5.json";
/// Exact retained fixed workload-schedule filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_SCHEDULE_FILE: &str =
    "workload-schedule-v5.json";
/// Exact retained closed candidate-evidence filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_EVIDENCE_FILE: &str = "candidate-evidence-v5.json";
/// Exact retained independent-checker source filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE: &str =
    "check-session-ha-concurrent-history-v5.py";
/// Exact retained additive workload-verifier source filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE: &str =
    "check-session-ha-kubernetes-concurrent-v5-workload-v1.py";
/// Exact retained independent-checker output filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_OUTPUT_FILE: &str =
    "checker-output-v5.json";
/// Exact retained additive workload-verifier output filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_OUTPUT_FILE: &str =
    "workload-verifier-output-v1.json";
/// Exact retained bundle summary filename.
pub const QUALIFICATION_KUBERNETES_CONCURRENT_V5_SUMMARY_FILE: &str = "summary.json";

#[cfg(target_os = "linux")]
const CANDIDATE_EVIDENCE_SCHEMA: &str = "opc-session-ha-candidate-evidence/v5";
#[cfg(target_os = "linux")]
const CANDIDATE_PROFILE_ID: &str = "opc-session-openraft-ha/v5-candidate";
#[cfg(target_os = "linux")]
const CHECKER_VERSION: &str = "5";
#[cfg(target_os = "linux")]
const WORKLOAD_VERIFIER_VERSION: &str = "1";
#[cfg(target_os = "linux")]
const CHECKER_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const CHECKER_REAP_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const INTERPRETER_VERSION_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const CHECKER_STDOUT_MAX_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const CHECKER_STDERR_MAX_BYTES: usize = 16 * 1024;
#[cfg(target_os = "linux")]
const INTERPRETER_VERSION_MAX_BYTES: usize = 4 * 1024;
#[cfg(target_os = "linux")]
const INTERPRETER_MAX_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(target_os = "linux")]
const EVIDENCE_MAX_BYTES: usize = 256 * 1024;
#[cfg(target_os = "linux")]
const SUMMARY_MAX_BYTES: usize = 256 * 1024;
#[cfg(target_os = "linux")]
const STAGING_ATTEMPTS: usize = 32;
const EMBEDDED_CHECKER: &[u8] =
    include_bytes!("../../../scripts/check-session-ha-concurrent-history-v5.py");
const EMBEDDED_WORKLOAD_VERIFIER: &[u8] =
    include_bytes!("../../../scripts/check-session-ha-kubernetes-concurrent-v5-workload-v1.py");
#[cfg(target_os = "linux")]
const EMBEDDED_PROFILE: &[u8] = SESSION_HA_CANDIDATE_PROFILE_V5_JSON.as_bytes();

#[cfg(target_os = "linux")]
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Caller-asserted candidate metadata bound into the v5 evidence document.
///
/// This type does not authenticate source or artifact provenance. In
/// particular, this candidate-only publisher always records
/// `exact_release_artifact=false`.
#[derive(Clone, PartialEq, Eq)]
pub struct QualificationKubernetesConcurrentV5CandidateBinding {
    /// Asserted lowercase 40-character source revision.
    pub asserted_source_revision: String,
    /// Caller-asserted source-tree classification.
    pub asserted_source_tree_status: QualificationCandidateSourceTreeStatus,
    /// Asserted bounded candidate artifact name.
    pub asserted_artifact_name: String,
    /// Asserted bounded candidate artifact version.
    pub asserted_artifact_version: String,
    /// Asserted digest of candidate artifact bytes not inspected here.
    pub asserted_artifact_sha256: QualificationSha256,
}

impl fmt::Debug for QualificationKubernetesConcurrentV5CandidateBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationKubernetesConcurrentV5CandidateBinding")
            .field("source_tree_status", &self.asserted_source_tree_status)
            .field("exact_release_artifact", &false)
            .field("identifiers", &"<redacted>")
            .field("digests", &"<redacted>")
            .finish()
    }
}

/// Validated publication inputs for one conclusive deployed v5 campaign.
#[derive(Clone, PartialEq, Eq)]
pub struct QualificationKubernetesConcurrentV5ArtifactConfig {
    /// New absolute output directory to create atomically.
    pub output_directory: PathBuf,
    /// Absolute Python interpreter path used for the independent checker.
    pub checker_interpreter: PathBuf,
    /// Expected digest of the exact checker embedded by this SDK build.
    pub expected_checker_sha256: QualificationSha256,
    /// Expected digest of the exact workload verifier embedded by this SDK build.
    pub expected_workload_verifier_sha256: QualificationSha256,
    /// Candidate metadata embedded in the closed evidence document.
    pub candidate: QualificationKubernetesConcurrentV5CandidateBinding,
}

impl fmt::Debug for QualificationKubernetesConcurrentV5ArtifactConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationKubernetesConcurrentV5ArtifactConfig")
            .field("candidate", &self.candidate)
            .field("paths", &"<redacted>")
            .field("verification_program_digests", &"<redacted>")
            .finish()
    }
}

impl QualificationKubernetesConcurrentV5ArtifactConfig {
    /// Validate closed metadata and both exact embedded program bindings.
    pub fn validate(&self) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
        if !is_lower_hex_width(&self.candidate.asserted_source_revision, 40)
            || !is_bounded_identifier(&self.candidate.asserted_artifact_name, 128)
            || !is_bounded_identifier(&self.candidate.asserted_artifact_version, 64)
        {
            return Err(QualificationKubernetesConcurrentV5ArtifactError::InvalidConfiguration);
        }
        if self.expected_checker_sha256 != embedded_v5_checker_sha256() {
            return Err(QualificationKubernetesConcurrentV5ArtifactError::CheckerDigestMismatch);
        }
        if self.expected_workload_verifier_sha256 != embedded_v5_workload_verifier_sha256() {
            return Err(
                QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierDigestMismatch,
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(QualificationKubernetesConcurrentV5ArtifactError::UnsupportedAtomicPublication)
        }
        #[cfg(target_os = "linux")]
        {
            validate_destination_shape(&self.output_directory)?;
            validate_interpreter_shape(&self.checker_interpreter)
        }
    }
}

/// Exact digest of the frozen independent checker embedded in this SDK build.
#[must_use]
pub fn embedded_v5_checker_sha256() -> QualificationSha256 {
    QualificationSha256::digest(EMBEDDED_CHECKER)
}

/// Exact digest of the additive workload verifier embedded in this SDK build.
#[must_use]
pub fn embedded_v5_workload_verifier_sha256() -> QualificationSha256 {
    QualificationSha256::digest(EMBEDDED_WORKLOAD_VERIFIER)
}

/// One retained file and its exact byte/digest binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationKubernetesConcurrentV5ArtifactDigest {
    /// Closed filename inside the published directory.
    pub file: String,
    /// Exact number of retained bytes.
    pub bytes: usize,
    /// SHA-256 digest of the exact retained bytes.
    pub sha256: QualificationSha256,
}

/// Interpreter identity retained with the checker result.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationKubernetesConcurrentV5InterpreterSummary {
    /// Canonical interpreter path used by the no-shell subprocess.
    pub canonical_path: String,
    /// SHA-256 digest of the descriptor-bound interpreter bytes.
    pub sha256: QualificationSha256,
    /// Bounded, UTF-8, whitespace-trimmed `--version` result.
    pub version: String,
}

impl fmt::Debug for QualificationKubernetesConcurrentV5InterpreterSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationKubernetesConcurrentV5InterpreterSummary")
            .field("identity", &"<redacted>")
            .finish()
    }
}

/// Closed operation counts reported by the independent checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationKubernetesConcurrentV5OperationCounts {
    /// Checked batch rows.
    pub batch: usize,
    /// Checked readiness rows.
    pub readiness: usize,
    /// Checked restore rows.
    pub restore: usize,
    /// Checked watch rows.
    pub watch: usize,
}

impl QualificationKubernetesConcurrentV5OperationCounts {
    fn total(self) -> Option<usize> {
        self.batch
            .checked_add(self.readiness)?
            .checked_add(self.restore)?
            .checked_add(self.watch)
    }
}

/// Honest summary of one atomic candidate-only v5 artifact bundle.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationKubernetesConcurrentV5ArtifactSummary {
    /// Closed summary schema identifier.
    pub schema_version: String,
    /// This slice always remains experimental.
    pub experimental: bool,
    /// This slice never completes all production qualification.
    pub qualification_complete: bool,
    /// This slice never counts as production evidence by itself.
    pub counts_for_production: bool,
    /// Conclusive independent-checker status.
    pub checker_status: String,
    /// Conclusive additive workload-verifier status.
    pub workload_verifier_status: String,
    /// Whether the adapter conclusively completed all cleanup.
    pub cleanup_complete: bool,
    /// Exact topology size.
    pub topology_members: usize,
    /// Exact number of retained history rows.
    pub history_operations: usize,
    /// Number of operations independently checked.
    pub history_operations_checked: usize,
    /// Exact per-kind checker counts.
    pub operation_counts: QualificationKubernetesConcurrentV5OperationCounts,
    /// Canonical checker interpreter identity.
    pub checker_interpreter: QualificationKubernetesConcurrentV5InterpreterSummary,
    /// Exact retained machine-readable v5 candidate profile.
    pub profile: QualificationKubernetesConcurrentV5ArtifactDigest,
    /// Exact retained history binding.
    pub history: QualificationKubernetesConcurrentV5ArtifactDigest,
    /// Exact retained fault-schedule binding.
    pub fault_schedule: QualificationKubernetesConcurrentV5ArtifactDigest,
    /// Exact retained workload-schedule binding.
    pub workload_schedule: QualificationKubernetesConcurrentV5ArtifactDigest,
    /// Exact retained checker binding.
    pub checker: QualificationKubernetesConcurrentV5ArtifactDigest,
    /// Exact retained additive workload-verifier binding.
    pub workload_verifier: QualificationKubernetesConcurrentV5ArtifactDigest,
    /// Exact retained checker-output binding.
    pub checker_output: QualificationKubernetesConcurrentV5ArtifactDigest,
    /// Exact retained additive workload-verifier output binding.
    pub workload_verifier_output: QualificationKubernetesConcurrentV5ArtifactDigest,
    /// Exact retained closed-evidence binding.
    pub candidate_evidence: QualificationKubernetesConcurrentV5ArtifactDigest,
    /// Complete production-acceptance inventory that remains open.
    pub remaining_acceptance: Vec<String>,
}

impl fmt::Debug for QualificationKubernetesConcurrentV5ArtifactSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationKubernetesConcurrentV5ArtifactSummary")
            .field("experimental", &self.experimental)
            .field("qualification_complete", &self.qualification_complete)
            .field("counts_for_production", &self.counts_for_production)
            .field("checker_status", &self.checker_status)
            .field("workload_verifier_status", &self.workload_verifier_status)
            .field("cleanup_complete", &self.cleanup_complete)
            .field("topology_members", &self.topology_members)
            .field("history_operations", &self.history_operations)
            .field("digests", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Stable, redaction-safe v5 campaign publication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QualificationKubernetesConcurrentV5ArtifactError {
    /// Candidate metadata, interpreter input, or checker binding is invalid.
    #[error("qualification Kubernetes v5 artifact configuration is invalid")]
    InvalidConfiguration,
    /// This platform cannot atomically publish a directory without replacing it.
    #[error("qualification Kubernetes v5 atomic publication is unsupported")]
    UnsupportedAtomicPublication,
    /// Destination path shape or its parent directory is unsafe.
    #[error("qualification Kubernetes v5 artifact destination is invalid")]
    InvalidDestination,
    /// The no-replace destination already exists.
    #[error("qualification Kubernetes v5 artifact destination already exists")]
    DestinationExists,
    /// The deployed campaign configuration was rejected before execution.
    #[error("qualification Kubernetes v5 campaign configuration is invalid")]
    CampaignConfiguration,
    /// Campaign status, cleanup, or retained history was not conclusive.
    #[error("qualification Kubernetes v5 campaign is inconclusive")]
    CampaignInconclusive,
    /// Cancellation prevented checker execution or publication.
    #[error("qualification Kubernetes v5 artifact publication was cancelled")]
    Cancelled,
    /// Deterministic artifact encoding failed.
    #[error("qualification Kubernetes v5 artifact encoding failed")]
    Encoding,
    /// An encoded artifact exceeded its fixed bound.
    #[error("qualification Kubernetes v5 artifact exceeded its bound")]
    TooLarge,
    /// The configured checker digest did not match the exact embedded bytes.
    #[error("qualification Kubernetes v5 checker digest mismatched")]
    CheckerDigestMismatch,
    /// The configured workload-verifier digest did not match the embedded bytes.
    #[error("qualification Kubernetes v5 workload-verifier digest mismatched")]
    WorkloadVerifierDigestMismatch,
    /// The configured checker interpreter was unavailable or invalid.
    #[error("qualification Kubernetes v5 checker interpreter is unavailable")]
    InterpreterUnavailable,
    /// The checker interpreter version probe exceeded its time bound.
    #[error("qualification Kubernetes v5 checker interpreter probe timed out")]
    InterpreterTimeout,
    /// The checker interpreter version output exceeded its fixed bound.
    #[error("qualification Kubernetes v5 checker interpreter output exceeded its bound")]
    InterpreterOutputTooLarge,
    /// The checker interpreter version probe could not be conclusively reaped.
    #[error("qualification Kubernetes v5 checker interpreter reap failed")]
    InterpreterReap,
    /// The independent checker could not be launched or reaped safely.
    #[error("qualification Kubernetes v5 checker process failed")]
    CheckerLaunch,
    /// The independent checker could not be conclusively reaped.
    #[error("qualification Kubernetes v5 checker reap failed")]
    CheckerReap,
    /// The independent checker exceeded its time bound.
    #[error("qualification Kubernetes v5 checker timed out")]
    CheckerTimeout,
    /// Independent checker stdout or stderr exceeded its fixed bound.
    #[error("qualification Kubernetes v5 checker output exceeded its bound")]
    CheckerOutputTooLarge,
    /// The checker exit or closed output was not a conclusive pass.
    #[error("qualification Kubernetes v5 checker rejected the candidate")]
    CheckerRejected,
    /// The workload verifier could not be launched safely.
    #[error("qualification Kubernetes v5 workload-verifier process failed")]
    WorkloadVerifierLaunch,
    /// The workload verifier could not be conclusively reaped.
    #[error("qualification Kubernetes v5 workload-verifier reap failed")]
    WorkloadVerifierReap,
    /// The workload verifier exceeded its time bound.
    #[error("qualification Kubernetes v5 workload verifier timed out")]
    WorkloadVerifierTimeout,
    /// Workload-verifier stdout or stderr exceeded its fixed bound.
    #[error("qualification Kubernetes v5 workload-verifier output exceeded its bound")]
    WorkloadVerifierOutputTooLarge,
    /// The workload-verifier exit or closed output was not a conclusive pass.
    #[error("qualification Kubernetes v5 workload verifier rejected the candidate")]
    WorkloadVerifierRejected,
    /// Private staging, durability, or atomic publication failed.
    #[error("qualification Kubernetes v5 artifact publication failed")]
    Publication,
    /// Staging cleanup or its parent-directory durability could not be
    /// confirmed. A private staging directory may remain and must be
    /// quarantined. Inspection/removal requires a separate audited operator
    /// procedure; this SDK supplies no acceptance verifier.
    #[error("qualification Kubernetes v5 artifact staging cleanup outcome is unknown")]
    StagingCleanupOutcomeUnknown,
    /// The no-replace rename completed, but parent durability could not be
    /// confirmed. The destination may exist and must be quarantined, never
    /// accepted, counted, or overwritten. Summary self-consistency is not
    /// provenance; this SDK supplies no authenticated acceptance verifier.
    #[error("qualification Kubernetes v5 artifact publication outcome is unknown")]
    PublicationOutcomeUnknown,
}

/// Validate destination, interpreter, and checker identity without mutation.
///
/// Executable campaign callers should run this before invoking Kubernetes.
pub async fn preflight_qualification_kubernetes_concurrent_v5_artifacts(
    config: &QualificationKubernetesConcurrentV5ArtifactConfig,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    prepare_publication(config, cancellation).await.map(|_| ())
}

/// Run one deployed v5 campaign and publish only its conclusive checked result.
///
/// Destination and checker-interpreter preflight completes before any
/// Kubernetes operation. A failed, token-cancelled, cleanup-incomplete, or
/// history-less campaign never creates the destination.
///
/// Callers must cancel through `cancellation` and await this future to receive
/// typed campaign and publication cleanup status. Dropping it while the
/// deployed campaign is running prevents the adapter's later asynchronous fleet
/// cleanup from running. After such a drop, an audited operator procedure must
/// restore every RPC gate, abort the watch, forget campaign-local lease handles,
/// and reset the custom Pod condition before fleet reuse.
///
/// Once the campaign has returned and artifact publication has begun, RAII
/// attempts private-staging cleanup and, while a direct child remains unreaped,
/// best-effort process-group termination. It cannot report either outcome. A
/// reaped child's old numeric process-group identifier is never signalled. The
/// trusted interpreter and verification programs must not daemonize or escape
/// their process group. A drop racing the atomic rename can leave a destination;
/// after any unacknowledged drop, callers must quarantine any staging or
/// destination path and must not accept, count, or overwrite it.
pub async fn run_and_publish_qualification_kubernetes_concurrent_v5_campaign<P, C>(
    campaign_config: &QualificationKubernetesConcurrentV5Config,
    artifact_config: &QualificationKubernetesConcurrentV5ArtifactConfig,
    port: &P,
    clock: &C,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<
    QualificationKubernetesConcurrentV5ArtifactSummary,
    QualificationKubernetesConcurrentV5ArtifactError,
>
where
    P: QualificationKubernetesCampaignPort,
    C: QualificationKubernetesCampaignClock,
{
    let prepared = prepare_publication(artifact_config, cancellation).await?;
    if cancellation.is_cancelled() {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::Cancelled);
    }
    let outcome = run_qualification_kubernetes_concurrent_v5_campaign(
        campaign_config,
        port,
        clock,
        cancellation,
    )
    .await
    .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::CampaignConfiguration)?;
    publish_prepared(artifact_config, &outcome, prepared, cancellation).await
}

/// Atomically publish an already-completed deployed v5 outcome.
///
/// This boundary repeats destination and interpreter preflight and refuses to
/// publish anything other than `Passed` plus conclusive cleanup and history.
pub async fn publish_qualification_kubernetes_concurrent_v5_artifacts(
    config: &QualificationKubernetesConcurrentV5ArtifactConfig,
    outcome: &QualificationKubernetesConcurrentV5Outcome,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<
    QualificationKubernetesConcurrentV5ArtifactSummary,
    QualificationKubernetesConcurrentV5ArtifactError,
> {
    let prepared = prepare_publication(config, cancellation).await?;
    publish_prepared(config, outcome, prepared, cancellation).await
}

#[cfg(target_os = "linux")]
struct PreparedPublication {
    parent_path: PathBuf,
    parent_descriptor: OwnedFd,
    parent_identity: DirectoryIdentity,
    destination_name: OsString,
    interpreter: PreparedInterpreter,
    interpreter_version: String,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
struct PreparedInterpreter {
    canonical_path: String,
    descriptor: OwnedFd,
    identity: InterpreterIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Clone, PartialEq, Eq)]
struct InterpreterIdentity {
    device: u64,
    inode: u64,
    size: u64,
    sha256: QualificationSha256,
}

#[cfg(not(target_os = "linux"))]
struct PreparedPublication;

async fn prepare_publication(
    config: &QualificationKubernetesConcurrentV5ArtifactConfig,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<PreparedPublication, QualificationKubernetesConcurrentV5ArtifactError> {
    config.validate()?;
    if cancellation.is_cancelled() {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::Cancelled);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        let _ = cancellation;
        Err(QualificationKubernetesConcurrentV5ArtifactError::UnsupportedAtomicPublication)
    }
    #[cfg(target_os = "linux")]
    {
        let output_directory = config.output_directory.clone();
        let checker_interpreter = config.checker_interpreter.clone();
        let (parent_path, parent_descriptor, parent_identity, destination_name, interpreter) =
            tokio::task::spawn_blocking(move || {
                let (parent_path, parent_descriptor, parent_identity, destination_name) =
                    open_artifact_parent(&output_directory)?;
                let interpreter = prepare_interpreter(&checker_interpreter)?;
                Ok::<_, QualificationKubernetesConcurrentV5ArtifactError>((
                    parent_path,
                    parent_descriptor,
                    parent_identity,
                    destination_name,
                    interpreter,
                ))
            })
            .await
            .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)??;
        let interpreter_version = probe_interpreter_version(&interpreter, cancellation).await?;
        if cancellation.is_cancelled() {
            return Err(QualificationKubernetesConcurrentV5ArtifactError::Cancelled);
        }
        Ok(PreparedPublication {
            parent_path,
            parent_descriptor,
            parent_identity,
            destination_name,
            interpreter,
            interpreter_version,
        })
    }
}

async fn publish_prepared(
    config: &QualificationKubernetesConcurrentV5ArtifactConfig,
    outcome: &QualificationKubernetesConcurrentV5Outcome,
    prepared: PreparedPublication,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<
    QualificationKubernetesConcurrentV5ArtifactSummary,
    QualificationKubernetesConcurrentV5ArtifactError,
> {
    if cancellation.is_cancelled() {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::Cancelled);
    }
    if outcome.status() != QualificationKubernetesConcurrentV5Status::Passed
        || !outcome.cleanup_complete()
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::CampaignInconclusive);
    }
    let history = outcome
        .history()
        .ok_or(QualificationKubernetesConcurrentV5ArtifactError::CampaignInconclusive)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        let _ = history;
        let _ = prepared;
        let _ = cancellation;
        Err(QualificationKubernetesConcurrentV5ArtifactError::UnsupportedAtomicPublication)
    }
    #[cfg(target_os = "linux")]
    {
        publish_linux(config, history, prepared, cancellation).await
    }
}

#[cfg(target_os = "linux")]
async fn publish_linux(
    config: &QualificationKubernetesConcurrentV5ArtifactConfig,
    history: &QualificationConcurrentHistoryV5,
    prepared: PreparedPublication,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<
    QualificationKubernetesConcurrentV5ArtifactSummary,
    QualificationKubernetesConcurrentV5ArtifactError,
> {
    ensure_not_cancelled(cancellation)?;
    let candidate = config.candidate.clone();
    let expected_checker_sha256 = config.expected_checker_sha256.clone();
    let expected_workload_verifier_sha256 = config.expected_workload_verifier_sha256.clone();
    let history = history.clone();
    let encoded = run_publication_blocking(cancellation, move |cancelled| {
        encode_candidate_artifacts(
            &candidate,
            &history,
            &expected_checker_sha256,
            &expected_workload_verifier_sha256,
            &cancelled,
        )
    })
    .await?;
    let staged = run_publication_blocking(cancellation, move |cancelled| {
        stage_candidate_artifacts(prepared, encoded, &cancelled)
    })
    .await?;

    let workload_verifier_output = match run_workload_verifier(
        &staged.prepared.interpreter,
        &staged.checker_inputs,
        cancellation,
    )
    .await
    {
        Ok(output) => output,
        Err(error) => return cleanup_after_error(staged, error).await,
    };
    let checker_output = match run_independent_checker(
        &staged.prepared.interpreter,
        &staged.checker_inputs,
        cancellation,
    )
    .await
    {
        Ok(output) => output,
        Err(error) => return cleanup_after_error(staged, error).await,
    };
    let expected_history_operations = staged.history_operations;
    run_publication_blocking(cancellation, move |cancelled| {
        finalize_candidate_artifacts(
            staged,
            checker_output,
            workload_verifier_output,
            expected_history_operations,
            &cancelled,
        )
    })
    .await
}

#[cfg(target_os = "linux")]
struct EncodedCandidateArtifacts {
    history: Vec<u8>,
    fault_schedule: Vec<u8>,
    workload_schedule: Vec<u8>,
    evidence: Vec<u8>,
    history_operations: usize,
    topology_members: usize,
}

#[cfg(target_os = "linux")]
struct CheckerInputDescriptors {
    checker: OwnedFd,
    workload_verifier: OwnedFd,
    evidence: OwnedFd,
    fault_schedule: OwnedFd,
    workload_schedule: OwnedFd,
    history: OwnedFd,
}

#[cfg(target_os = "linux")]
struct StagedCandidateArtifacts {
    prepared: PreparedPublication,
    staging_name: String,
    staging_descriptor: OwnedFd,
    checker_inputs: CheckerInputDescriptors,
    encoded: EncodedCandidateArtifacts,
    history_operations: usize,
    topology_members: usize,
    cleanup_required: bool,
}

#[cfg(target_os = "linux")]
impl Drop for StagedCandidateArtifacts {
    fn drop(&mut self) {
        if self.cleanup_required
            && cleanup_staging_directory(
                &self.prepared.parent_descriptor,
                &self.staging_descriptor,
                &self.staging_name,
            )
            .is_err()
        {
            tracing::error!(
                code = "qualification_kubernetes_v5_staging_cleanup_outcome_unknown",
                "qualification Kubernetes v5 staging cleanup could not be confirmed"
            );
        }
    }
}

#[cfg(target_os = "linux")]
struct BlockingCancellationOnDrop {
    cancelled: Arc<AtomicBool>,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl BlockingCancellationOnDrop {
    fn new(cancelled: Arc<AtomicBool>) -> Self {
        Self {
            cancelled,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for BlockingCancellationOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

#[cfg(target_os = "linux")]
async fn run_publication_blocking<T, F>(
    cancellation: &QualificationKubernetesCampaignCancellation,
    operation: F,
) -> Result<T, QualificationKubernetesConcurrentV5ArtifactError>
where
    T: Send + 'static,
    F: FnOnce(Arc<AtomicBool>) -> Result<T, QualificationKubernetesConcurrentV5ArtifactError>
        + Send
        + 'static,
{
    let cancelled = Arc::new(AtomicBool::new(cancellation.is_cancelled()));
    let mut drop_guard = BlockingCancellationOnDrop::new(Arc::clone(&cancelled));
    let operation_cancelled = Arc::clone(&cancelled);
    let mut task = tokio::task::spawn_blocking(move || operation(operation_cancelled));
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            cancelled.store(true, Ordering::Release);
            task.await
                .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?
        }
        result = &mut task => result
            .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?,
    };
    drop_guard.disarm();
    result
}

#[cfg(target_os = "linux")]
fn ensure_blocking_not_cancelled(
    cancelled: &AtomicBool,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    if cancelled.load(Ordering::Acquire) {
        Err(QualificationKubernetesConcurrentV5ArtifactError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn encode_candidate_artifacts(
    candidate: &QualificationKubernetesConcurrentV5CandidateBinding,
    history: &QualificationConcurrentHistoryV5,
    expected_checker_sha256: &QualificationSha256,
    expected_workload_verifier_sha256: &QualificationSha256,
    cancelled: &AtomicBool,
) -> Result<EncodedCandidateArtifacts, QualificationKubernetesConcurrentV5ArtifactError> {
    ensure_blocking_not_cancelled(cancelled)?;
    let history_bytes = history
        .encode_json_lines()
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Encoding)?;
    let fault_schedule_bytes = history
        .fault_schedule()
        .encode_json()
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Encoding)?;
    let workload_schedule = CandidateWorkloadScheduleV5::new(history);
    let workload_schedule_bytes = encode_pretty_bounded(&workload_schedule, EVIDENCE_MAX_BYTES)?;
    let checker_digest = QualificationSha256::digest(EMBEDDED_CHECKER);
    if &checker_digest != expected_checker_sha256 {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::CheckerDigestMismatch);
    }
    if &QualificationSha256::digest(EMBEDDED_WORKLOAD_VERIFIER) != expected_workload_verifier_sha256
    {
        return Err(
            QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierDigestMismatch,
        );
    }
    ensure_blocking_not_cancelled(cancelled)?;
    let evidence = CandidateEvidenceV5::new(
        candidate,
        history,
        &history_bytes,
        &fault_schedule_bytes,
        QualificationSha256::digest(&workload_schedule_bytes),
        checker_digest,
    );
    let evidence_bytes = encode_pretty_bounded(&evidence, EVIDENCE_MAX_BYTES)?;
    ensure_blocking_not_cancelled(cancelled)?;
    Ok(EncodedCandidateArtifacts {
        history: history_bytes,
        fault_schedule: fault_schedule_bytes,
        workload_schedule: workload_schedule_bytes,
        evidence: evidence_bytes,
        history_operations: history.rows().len(),
        topology_members: history.fault_schedule().process_ids.len(),
    })
}

#[cfg(target_os = "linux")]
fn stage_candidate_artifacts(
    prepared: PreparedPublication,
    encoded: EncodedCandidateArtifacts,
    cancelled: &AtomicBool,
) -> Result<StagedCandidateArtifacts, QualificationKubernetesConcurrentV5ArtifactError> {
    ensure_blocking_not_cancelled(cancelled)?;
    verify_parent_binding(&prepared)?;
    ensure_destination_absent(&prepared.parent_descriptor, &prepared.destination_name)?;
    let staging_name = create_staging_directory(&prepared.parent_descriptor)?;
    let staging_descriptor = match openat(
        &prepared.parent_descriptor,
        staging_name.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            return match cleanup_empty_staging_directory(
                &prepared.parent_descriptor,
                staging_name.as_str(),
            ) {
                Ok(()) => Err(map_publication_error(error)),
                Err(()) => Err(
                    QualificationKubernetesConcurrentV5ArtifactError::StagingCleanupOutcomeUnknown,
                ),
            };
        }
    };
    let history_operations = encoded.history_operations;
    let topology_members = encoded.topology_members;
    let staged = (|| {
        validate_private_staging(&staging_descriptor)?;
        for (name, bytes) in [
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_PROFILE_FILE,
                EMBEDDED_PROFILE,
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_HISTORY_FILE,
                encoded.history.as_slice(),
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_FAULT_SCHEDULE_FILE,
                encoded.fault_schedule.as_slice(),
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_SCHEDULE_FILE,
                encoded.workload_schedule.as_slice(),
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE,
                EMBEDDED_CHECKER,
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE,
                EMBEDDED_WORKLOAD_VERIFIER,
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_EVIDENCE_FILE,
                encoded.evidence.as_slice(),
            ),
        ] {
            ensure_blocking_not_cancelled(cancelled)?;
            write_private_file_at(&staging_descriptor, name, bytes)?;
        }
        fsync(&staging_descriptor)
            .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
        verify_staged_bytes(
            &staging_descriptor,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE,
            EMBEDDED_CHECKER,
        )?;
        verify_staged_bytes(
            &staging_descriptor,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE,
            EMBEDDED_WORKLOAD_VERIFIER,
        )?;
        let checker_inputs = open_checker_inputs(&staging_descriptor)?;
        ensure_blocking_not_cancelled(cancelled)?;
        Ok(CheckerInputDescriptors {
            checker: checker_inputs.checker,
            workload_verifier: checker_inputs.workload_verifier,
            evidence: checker_inputs.evidence,
            fault_schedule: checker_inputs.fault_schedule,
            workload_schedule: checker_inputs.workload_schedule,
            history: checker_inputs.history,
        })
    })();
    match staged {
        Ok(checker_inputs) => Ok(StagedCandidateArtifacts {
            prepared,
            staging_name,
            staging_descriptor,
            checker_inputs,
            encoded,
            history_operations,
            topology_members,
            cleanup_required: true,
        }),
        Err(error) => match cleanup_staging_directory(
            &prepared.parent_descriptor,
            &staging_descriptor,
            &staging_name,
        ) {
            Ok(()) => Err(error),
            Err(()) => {
                Err(QualificationKubernetesConcurrentV5ArtifactError::StagingCleanupOutcomeUnknown)
            }
        },
    }
}

#[cfg(target_os = "linux")]
async fn cleanup_after_error<T>(
    mut staged: StagedCandidateArtifacts,
    original: QualificationKubernetesConcurrentV5ArtifactError,
) -> Result<T, QualificationKubernetesConcurrentV5ArtifactError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let cleanup = cleanup_staging_directory(
            &staged.prepared.parent_descriptor,
            &staged.staging_descriptor,
            &staged.staging_name,
        );
        if cleanup.is_ok() {
            staged.cleanup_required = false;
        }
        drop(staged);
        cleanup
    })
    .await
    .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::StagingCleanupOutcomeUnknown)?
    .map_err(|()| QualificationKubernetesConcurrentV5ArtifactError::StagingCleanupOutcomeUnknown)?;
    Err(original)
}

#[cfg(target_os = "linux")]
fn finalize_candidate_artifacts(
    mut staged: StagedCandidateArtifacts,
    checker_output: Vec<u8>,
    workload_verifier_output: Vec<u8>,
    expected_history_operations: usize,
    cancelled: &AtomicBool,
) -> Result<
    QualificationKubernetesConcurrentV5ArtifactSummary,
    QualificationKubernetesConcurrentV5ArtifactError,
> {
    let mut published = false;
    let result = (|| {
        ensure_blocking_not_cancelled(cancelled)?;
        verify_staged_bytes(
            &staged.staging_descriptor,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE,
            EMBEDDED_CHECKER,
        )?;
        verify_staged_bytes(
            &staged.staging_descriptor,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE,
            EMBEDDED_WORKLOAD_VERIFIER,
        )?;
        let parsed_output = validate_checker_output(&checker_output, expected_history_operations)?;
        validate_workload_verifier_output(&workload_verifier_output)?;
        write_private_file_at(
            &staged.staging_descriptor,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_OUTPUT_FILE,
            &checker_output,
        )?;
        write_private_file_at(
            &staged.staging_descriptor,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_OUTPUT_FILE,
            &workload_verifier_output,
        )?;
        let summary = QualificationKubernetesConcurrentV5ArtifactSummary {
            schema_version: QUALIFICATION_KUBERNETES_CONCURRENT_V5_ARTIFACT_SUMMARY_SCHEMA
                .to_owned(),
            experimental: true,
            qualification_complete: false,
            counts_for_production: false,
            checker_status: "pass".to_owned(),
            workload_verifier_status: "pass".to_owned(),
            cleanup_complete: true,
            topology_members: staged.topology_members,
            history_operations: staged.history_operations,
            history_operations_checked: parsed_output.history_operations_checked,
            operation_counts: parsed_output.operation_counts,
            checker_interpreter: QualificationKubernetesConcurrentV5InterpreterSummary {
                canonical_path: staged.prepared.interpreter.canonical_path.clone(),
                sha256: staged.prepared.interpreter.identity.sha256.clone(),
                version: staged.prepared.interpreter_version.clone(),
            },
            profile: artifact_digest(
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_PROFILE_FILE,
                EMBEDDED_PROFILE,
            ),
            history: artifact_digest(
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_HISTORY_FILE,
                &staged.encoded.history,
            ),
            fault_schedule: artifact_digest(
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_FAULT_SCHEDULE_FILE,
                &staged.encoded.fault_schedule,
            ),
            workload_schedule: artifact_digest(
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_SCHEDULE_FILE,
                &staged.encoded.workload_schedule,
            ),
            checker: artifact_digest(
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE,
                EMBEDDED_CHECKER,
            ),
            workload_verifier: artifact_digest(
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE,
                EMBEDDED_WORKLOAD_VERIFIER,
            ),
            checker_output: artifact_digest(
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_OUTPUT_FILE,
                &checker_output,
            ),
            workload_verifier_output: artifact_digest(
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_OUTPUT_FILE,
                &workload_verifier_output,
            ),
            candidate_evidence: artifact_digest(
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_EVIDENCE_FILE,
                &staged.encoded.evidence,
            ),
            remaining_acceptance: SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V5
                .iter()
                .map(|gate| (*gate).to_owned())
                .collect(),
        };
        let summary_bytes = encode_pretty_bounded(&summary, SUMMARY_MAX_BYTES)?;
        write_private_file_at(
            &staged.staging_descriptor,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_SUMMARY_FILE,
            &summary_bytes,
        )?;
        for (name, expected) in [
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_PROFILE_FILE,
                EMBEDDED_PROFILE,
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_HISTORY_FILE,
                staged.encoded.history.as_slice(),
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_FAULT_SCHEDULE_FILE,
                staged.encoded.fault_schedule.as_slice(),
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_SCHEDULE_FILE,
                staged.encoded.workload_schedule.as_slice(),
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE,
                EMBEDDED_CHECKER,
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE,
                EMBEDDED_WORKLOAD_VERIFIER,
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_EVIDENCE_FILE,
                staged.encoded.evidence.as_slice(),
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_OUTPUT_FILE,
                checker_output.as_slice(),
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_OUTPUT_FILE,
                workload_verifier_output.as_slice(),
            ),
            (
                QUALIFICATION_KUBERNETES_CONCURRENT_V5_SUMMARY_FILE,
                summary_bytes.as_slice(),
            ),
        ] {
            verify_staged_bytes(&staged.staging_descriptor, name, expected)?;
        }
        fsync(&staged.staging_descriptor)
            .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
        ensure_blocking_not_cancelled(cancelled)?;
        verify_parent_binding(&staged.prepared)?;
        ensure_destination_absent(
            &staged.prepared.parent_descriptor,
            &staged.prepared.destination_name,
        )?;
        renameat_with(
            &staged.prepared.parent_descriptor,
            staged.staging_name.as_str(),
            &staged.prepared.parent_descriptor,
            &staged.prepared.destination_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(map_rename_error)?;
        published = true;
        staged.cleanup_required = false;
        let parent_sync = fsync(&staged.prepared.parent_descriptor);
        if cancelled.load(Ordering::Acquire) {
            tracing::error!(
                code = "qualification_kubernetes_v5_publication_abort_outcome_unknown",
                "qualification Kubernetes v5 publication completed across an unacknowledged cancellation boundary"
            );
            return Err(
                QualificationKubernetesConcurrentV5ArtifactError::PublicationOutcomeUnknown,
            );
        }
        map_post_rename_sync(parent_sync)?;
        Ok(summary)
    })();
    if result.is_err() && !published {
        if cleanup_staging_directory(
            &staged.prepared.parent_descriptor,
            &staged.staging_descriptor,
            &staged.staging_name,
        )
        .is_err()
        {
            return Err(
                QualificationKubernetesConcurrentV5ArtifactError::StagingCleanupOutcomeUnknown,
            );
        }
        staged.cleanup_required = false;
    }
    result
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateEvidenceV5 {
    schema_version: String,
    profile_id: String,
    experimental: bool,
    qualification_complete: bool,
    counts_for_production: bool,
    source_revision: String,
    source_tree_status: QualificationCandidateSourceTreeStatus,
    artifact: CandidateArtifactV5,
    execution: CandidateExecutionV5,
    workload: CandidateWorkloadV5,
    history: CandidateHistoryV5,
    checker: CandidateCheckerV5,
    coverage: CandidateCoverageV5,
    remaining_acceptance: Vec<String>,
}

#[cfg(target_os = "linux")]
impl CandidateEvidenceV5 {
    fn new(
        candidate: &QualificationKubernetesConcurrentV5CandidateBinding,
        history: &QualificationConcurrentHistoryV5,
        history_bytes: &[u8],
        fault_schedule_bytes: &[u8],
        workload_schedule_sha256: QualificationSha256,
        checker_sha256: QualificationSha256,
    ) -> Self {
        let schedule = history.fault_schedule();
        let contract = history.contract();
        Self {
            schema_version: CANDIDATE_EVIDENCE_SCHEMA.to_owned(),
            profile_id: CANDIDATE_PROFILE_ID.to_owned(),
            experimental: true,
            qualification_complete: false,
            counts_for_production: false,
            source_revision: candidate.asserted_source_revision.clone(),
            source_tree_status: candidate.asserted_source_tree_status,
            artifact: CandidateArtifactV5 {
                name: candidate.asserted_artifact_name.clone(),
                version: candidate.asserted_artifact_version.clone(),
                sha256: candidate.asserted_artifact_sha256.clone(),
                exact_release_artifact: false,
            },
            execution: CandidateExecutionV5 {
                history_id: schedule.history_id.clone(),
                campaign_started_ns: schedule.campaign_started_ns,
                campaign_completed_ns: schedule.campaign_completed_ns,
                topology_members: schedule.process_ids.len(),
                process_ids: schedule.process_ids.clone(),
                max_readiness_gap_ns: contract.max_readiness_gap_ns(),
                fault_schedule_sha256: QualificationSha256::digest(fault_schedule_bytes),
            },
            workload: CandidateWorkloadV5 {
                schedule_sha256: workload_schedule_sha256,
                isolated_digest_namespace: true,
                initial_state_empty: true,
                initial_journal_head: contract.initial_journal_head(),
                complete_write_history: true,
                serialized_batch_invocations: true,
                exclusive_application_journal_window: true,
                records_non_expiring_through_campaign: true,
                state_class: "authoritative-session".to_owned(),
                state_type_sha256: contract.state_type_sha256().to_owned(),
                no_lease_mutations_in_history_window: true,
                preacquired_leases: contract.preacquired_leases().to_vec(),
            },
            history: CandidateHistoryV5 {
                schema_version: QUALIFICATION_CONCURRENT_HISTORY_V5_SCHEMA.to_owned(),
                sha256: QualificationSha256::digest(history_bytes),
                operation_count: history.rows().len(),
                required_kinds: vec![
                    "batch".to_owned(),
                    "watch".to_owned(),
                    "restore".to_owned(),
                    "readiness".to_owned(),
                ],
            },
            checker: CandidateCheckerV5 {
                name: QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE.to_owned(),
                version: CHECKER_VERSION.to_owned(),
                sha256: checker_sha256,
            },
            coverage: CandidateCoverageV5 {
                cas_batch_per_slot_outcomes: true,
                gap_free_application_journal_watch: true,
                restore_state_within_call_interval: true,
                separate_raft_and_journal_domains: true,
                fault_schedule_derived_readiness_gating: true,
                fixed_campaign_lease_guards: true,
                authoritative_non_expiring_records: true,
            },
            remaining_acceptance: SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V5
                .iter()
                .map(|gate| (*gate).to_owned())
                .collect(),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateArtifactV5 {
    name: String,
    version: String,
    sha256: QualificationSha256,
    exact_release_artifact: bool,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateExecutionV5 {
    history_id: String,
    campaign_started_ns: u64,
    campaign_completed_ns: u64,
    topology_members: usize,
    process_ids: Vec<String>,
    max_readiness_gap_ns: u64,
    fault_schedule_sha256: QualificationSha256,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateWorkloadV5 {
    schedule_sha256: QualificationSha256,
    isolated_digest_namespace: bool,
    initial_state_empty: bool,
    initial_journal_head: u64,
    complete_write_history: bool,
    serialized_batch_invocations: bool,
    exclusive_application_journal_window: bool,
    records_non_expiring_through_campaign: bool,
    state_class: String,
    state_type_sha256: String,
    no_lease_mutations_in_history_window: bool,
    preacquired_leases:
        Vec<crate::qualification_concurrent_v5::QualificationConcurrentLeaseBindingV5>,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateWorkloadScheduleV5 {
    schema_version: String,
    operations: Vec<String>,
    isolated_digest_namespace: bool,
    initial_state_empty: bool,
    initial_journal_head: u64,
    complete_write_history: bool,
    serialized_batch_invocations: bool,
    exclusive_application_journal_window: bool,
    records_non_expiring_through_campaign: bool,
    state_class: String,
    state_type_sha256: String,
    no_lease_mutations_in_history_window: bool,
    preacquired_leases:
        Vec<crate::qualification_concurrent_v5::QualificationConcurrentLeaseBindingV5>,
}

#[cfg(target_os = "linux")]
impl CandidateWorkloadScheduleV5 {
    fn new(history: &QualificationConcurrentHistoryV5) -> Self {
        let contract = history.contract();
        Self {
            schema_version: "opc-session-kubernetes-concurrent-v5-workload/v1".to_owned(),
            operations: [
                "preacquire_leases",
                "prove_empty_restore_scope",
                "register_watch",
                "execute_partial_success_batch_once",
                "observe_ready_before_fault",
                "isolate_all_consensus_rpc_pairs",
                "observe_not_ready",
                "restore_all_consensus_rpc_pairs",
                "observe_ready_after_fault",
                "finish_watch_and_restore_concurrently",
                "cleanup",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            isolated_digest_namespace: true,
            initial_state_empty: true,
            initial_journal_head: contract.initial_journal_head(),
            complete_write_history: true,
            serialized_batch_invocations: true,
            exclusive_application_journal_window: true,
            records_non_expiring_through_campaign: true,
            state_class: "authoritative-session".to_owned(),
            state_type_sha256: contract.state_type_sha256().to_owned(),
            no_lease_mutations_in_history_window: true,
            preacquired_leases: contract.preacquired_leases().to_vec(),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateHistoryV5 {
    schema_version: String,
    sha256: QualificationSha256,
    operation_count: usize,
    required_kinds: Vec<String>,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateCheckerV5 {
    name: String,
    version: String,
    sha256: QualificationSha256,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateCoverageV5 {
    cas_batch_per_slot_outcomes: bool,
    gap_free_application_journal_watch: bool,
    restore_state_within_call_interval: bool,
    separate_raft_and_journal_domains: bool,
    fault_schedule_derived_readiness_gating: bool,
    fixed_campaign_lease_guards: bool,
    authoritative_non_expiring_records: bool,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckerOutput {
    checker: String,
    checker_version: String,
    history_operations_checked: usize,
    inconclusive_codes: Vec<String>,
    operation_counts: QualificationKubernetesConcurrentV5OperationCounts,
    status: VerificationStatus,
    violation_codes: Vec<String>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadVerifierOutput {
    verifier: String,
    verifier_version: String,
    status: VerificationStatus,
    violation_codes: Vec<String>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum VerificationStatus {
    Pass,
    Fail,
    Inconclusive,
    InvalidInput,
}

#[cfg(target_os = "linux")]
fn validate_checker_output(
    encoded: &[u8],
    expected_operations: usize,
) -> Result<CheckerOutput, QualificationKubernetesConcurrentV5ArtifactError> {
    let output: CheckerOutput = serde_json::from_slice(encoded)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::CheckerRejected)?;
    if output.checker != QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE
        || output.checker_version != CHECKER_VERSION
        || output.status != VerificationStatus::Pass
        || !output.inconclusive_codes.is_empty()
        || !output.violation_codes.is_empty()
        || output.history_operations_checked != expected_operations
        || output.operation_counts.total() != Some(expected_operations)
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::CheckerRejected);
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn validate_workload_verifier_output(
    encoded: &[u8],
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    let output: WorkloadVerifierOutput = serde_json::from_slice(encoded)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierRejected)?;
    if output.verifier != QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE
        || output.verifier_version != WORKLOAD_VERIFIER_VERSION
        || output.status != VerificationStatus::Pass
        || !output.violation_codes.is_empty()
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierRejected);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn artifact_digest(name: &str, bytes: &[u8]) -> QualificationKubernetesConcurrentV5ArtifactDigest {
    QualificationKubernetesConcurrentV5ArtifactDigest {
        file: name.to_owned(),
        bytes: bytes.len(),
        sha256: QualificationSha256::digest(bytes),
    }
}

#[cfg(target_os = "linux")]
fn encode_pretty_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, QualificationKubernetesConcurrentV5ArtifactError> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Encoding)?;
    encoded.push(b'\n');
    if encoded.len() > maximum {
        Err(QualificationKubernetesConcurrentV5ArtifactError::TooLarge)
    } else {
        Ok(encoded)
    }
}

#[cfg(target_os = "linux")]
fn validate_destination_shape(
    output_directory: &Path,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    if !output_directory.is_absolute()
        || output_directory
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        || !output_directory
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| is_bounded_identifier(name, 128))
    {
        Err(QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn validate_interpreter_shape(
    interpreter: &Path,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    if !interpreter.is_absolute()
        || interpreter
            .to_str()
            .is_none_or(|value| value.is_empty() || value.len() > 4096)
        || interpreter
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        Err(QualificationKubernetesConcurrentV5ArtifactError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn is_bounded_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'_' | b'-'))
}

fn is_lower_hex_width(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ensure_not_cancelled(
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    if cancellation.is_cancelled() {
        Err(QualificationKubernetesConcurrentV5ArtifactError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn open_artifact_parent(
    output_directory: &Path,
) -> Result<
    (PathBuf, OwnedFd, DirectoryIdentity, OsString),
    QualificationKubernetesConcurrentV5ArtifactError,
> {
    validate_destination_shape(output_directory)?;
    let parent = output_directory
        .parent()
        .ok_or(QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    if canonical_parent != parent {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination);
    }
    validate_owned_ancestors(&canonical_parent)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    let descriptor = open(
        &canonical_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    let descriptor_metadata = fstat(&descriptor)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    let path_metadata = fs::metadata(&canonical_parent)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    if !FileType::from_raw_mode(descriptor_metadata.st_mode).is_dir()
        || descriptor_metadata.st_dev != path_metadata.dev()
        || descriptor_metadata.st_ino != path_metadata.ino()
        || descriptor_metadata.st_uid != rustix::process::geteuid().as_raw()
        || Mode::from_raw_mode(descriptor_metadata.st_mode).bits() & 0o022 != 0
        || Mode::from_raw_mode(descriptor_metadata.st_mode).bits() & 0o200 == 0
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination);
    }
    let destination_name = output_directory
        .file_name()
        .ok_or(QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?
        .to_os_string();
    ensure_destination_absent(&descriptor, &destination_name)?;
    let identity = DirectoryIdentity {
        device: descriptor_metadata.st_dev,
        inode: descriptor_metadata.st_ino,
    };
    Ok((canonical_parent, descriptor, identity, destination_name))
}

#[cfg(target_os = "linux")]
fn validate_owned_ancestors(path: &Path) -> Result<(), ()> {
    let effective_user = rustix::process::geteuid().as_raw();
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| ())?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != effective_user)
            || metadata.mode() & 0o022 != 0
        {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_parent_binding(
    prepared: &PreparedPublication,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    let canonical = fs::canonicalize(&prepared.parent_path)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    if canonical != prepared.parent_path {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination);
    }
    validate_owned_ancestors(&canonical)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    let path_metadata = fs::metadata(&canonical)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    let descriptor_metadata = fstat(&prepared.parent_descriptor)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)?;
    if !FileType::from_raw_mode(descriptor_metadata.st_mode).is_dir()
        || path_metadata.dev() != prepared.parent_identity.device
        || path_metadata.ino() != prepared.parent_identity.inode
        || descriptor_metadata.st_dev != prepared.parent_identity.device
        || descriptor_metadata.st_ino != prepared.parent_identity.inode
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_destination_absent<Fd: AsFd>(
    parent: Fd,
    destination_name: &OsStr,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    match statat(parent, destination_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Err(QualificationKubernetesConcurrentV5ArtifactError::DestinationExists),
        Err(error) if std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination),
    }
}

#[cfg(target_os = "linux")]
fn prepare_interpreter(
    interpreter: &Path,
) -> Result<PreparedInterpreter, QualificationKubernetesConcurrentV5ArtifactError> {
    validate_interpreter_shape(interpreter)?;
    let canonical = fs::canonicalize(interpreter)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    let canonical_path = canonical
        .to_str()
        .ok_or(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?
        .to_owned();
    let parent = canonical
        .parent()
        .ok_or(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    validate_owned_ancestors(parent)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    let descriptor = open(
        &canonical,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    let metadata = fs::metadata(&canonical)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    let descriptor_metadata = fstat(&descriptor)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    let owner = descriptor_metadata.st_uid;
    if !canonical.is_absolute()
        || !FileType::from_raw_mode(descriptor_metadata.st_mode).is_file()
        || metadata.dev() != descriptor_metadata.st_dev
        || metadata.ino() != descriptor_metadata.st_ino
        || (owner != 0 && owner != rustix::process::geteuid().as_raw())
        || Mode::from_raw_mode(descriptor_metadata.st_mode).bits() & 0o022 != 0
        || Mode::from_raw_mode(descriptor_metadata.st_mode).bits() & 0o111 == 0
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable);
    }
    let identity = interpreter_identity(&descriptor)?;
    Ok(PreparedInterpreter {
        canonical_path,
        descriptor,
        identity,
    })
}

#[cfg(target_os = "linux")]
fn interpreter_identity<Fd: AsFd>(
    descriptor: Fd,
) -> Result<InterpreterIdentity, QualificationKubernetesConcurrentV5ArtifactError> {
    let before = fstat(&descriptor)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    let size = u64::try_from(before.st_size)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || size == 0
        || size > INTERPRETER_MAX_BYTES
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable);
    }
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while offset < size {
        let remaining =
            usize::try_from((size - offset).min(buffer.len() as u64)).map_err(|_| {
                QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable
            })?;
        let read =
            rustix::io::pread(&descriptor, &mut buffer[..remaining], offset).map_err(|_| {
                QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable
            })?;
        if read == 0 {
            return Err(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable);
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| {
                QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable
            })?)
            .ok_or(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    }
    let after = fstat(&descriptor)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mode != after.st_mode
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable);
    }
    let sha256 = QualificationSha256::new(format!("sha256:{:x}", hasher.finalize()))
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    Ok(InterpreterIdentity {
        device: before.st_dev,
        inode: before.st_ino,
        size,
        sha256,
    })
}

#[cfg(target_os = "linux")]
fn verify_interpreter_descriptor<Fd: AsFd>(
    descriptor: Fd,
    expected: &InterpreterIdentity,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    if interpreter_identity(descriptor)? == *expected {
        Ok(())
    } else {
        Err(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)
    }
}

#[cfg(target_os = "linux")]
async fn verified_interpreter_proc_path(
    interpreter: &PreparedInterpreter,
) -> Result<(OwnedFd, PathBuf), QualificationKubernetesConcurrentV5ArtifactError> {
    let descriptor = rustix::io::fcntl_dupfd_cloexec(&interpreter.descriptor, 0)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?;
    let expected = interpreter.identity.clone();
    tokio::task::spawn_blocking(move || {
        verify_interpreter_descriptor(&descriptor, &expected)?;
        let path = descriptor_proc_path(&descriptor);
        Ok((descriptor, path))
    })
    .await
    .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?
}

#[cfg(target_os = "linux")]
async fn reverify_interpreter_after_execution(
    descriptor: OwnedFd,
    expected: &InterpreterIdentity,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    let expected = expected.clone();
    tokio::task::spawn_blocking(move || verify_interpreter_descriptor(&descriptor, &expected))
        .await
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?
}

#[cfg(target_os = "linux")]
fn descriptor_proc_path(descriptor: &OwnedFd) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        descriptor.as_raw_fd()
    ))
}

#[cfg(target_os = "linux")]
async fn probe_interpreter_version(
    interpreter: &PreparedInterpreter,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<String, QualificationKubernetesConcurrentV5ArtifactError> {
    let (interpreter_descriptor, interpreter_path) =
        verified_interpreter_proc_path(interpreter).await?;
    let output = run_bounded_process(
        &interpreter_path,
        &[
            OsString::from("-I"),
            OsString::from("-B"),
            OsString::from("-S"),
            OsString::from("--version"),
        ],
        INTERPRETER_VERSION_TIMEOUT,
        INTERPRETER_VERSION_MAX_BYTES,
        INTERPRETER_VERSION_MAX_BYTES,
        cancellation,
    )
    .await
    .map_err(|error| match error {
        BoundedProcessError::Cancelled => {
            QualificationKubernetesConcurrentV5ArtifactError::Cancelled
        }
        BoundedProcessError::Timeout => {
            QualificationKubernetesConcurrentV5ArtifactError::InterpreterTimeout
        }
        BoundedProcessError::TooLarge => {
            QualificationKubernetesConcurrentV5ArtifactError::InterpreterOutputTooLarge
        }
        BoundedProcessError::Launch | BoundedProcessError::Io => {
            QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable
        }
        BoundedProcessError::Reap => {
            QualificationKubernetesConcurrentV5ArtifactError::InterpreterReap
        }
    })?;
    reverify_interpreter_after_execution(interpreter_descriptor, &interpreter.identity).await?;
    if !output.status.success() {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable);
    }
    let raw = match (output.stdout.is_empty(), output.stderr.is_empty()) {
        (false, true) => output.stdout,
        (true, false) => output.stderr,
        _ => return Err(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable),
    };
    let version = std::str::from_utf8(&raw)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)?
        .trim();
    if version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable);
    }
    Ok(version.to_owned())
}

#[cfg(target_os = "linux")]
async fn run_independent_checker(
    interpreter: &PreparedInterpreter,
    inputs: &CheckerInputDescriptors,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<Vec<u8>, QualificationKubernetesConcurrentV5ArtifactError> {
    let (interpreter_descriptor, interpreter_path) =
        verified_interpreter_proc_path(interpreter).await?;
    let arguments = [
        OsString::from("-I"),
        OsString::from("-B"),
        OsString::from("-S"),
        descriptor_proc_path(&inputs.checker).into_os_string(),
        OsString::from("--evidence"),
        descriptor_proc_path(&inputs.evidence).into_os_string(),
        OsString::from("--fault-schedule"),
        descriptor_proc_path(&inputs.fault_schedule).into_os_string(),
        OsString::from("--history"),
        descriptor_proc_path(&inputs.history).into_os_string(),
    ];
    let output = run_bounded_process(
        &interpreter_path,
        &arguments,
        CHECKER_TIMEOUT,
        CHECKER_STDOUT_MAX_BYTES,
        CHECKER_STDERR_MAX_BYTES,
        cancellation,
    )
    .await
    .map_err(|error| match error {
        BoundedProcessError::Cancelled => {
            QualificationKubernetesConcurrentV5ArtifactError::Cancelled
        }
        BoundedProcessError::Timeout => {
            QualificationKubernetesConcurrentV5ArtifactError::CheckerTimeout
        }
        BoundedProcessError::TooLarge => {
            QualificationKubernetesConcurrentV5ArtifactError::CheckerOutputTooLarge
        }
        BoundedProcessError::Launch | BoundedProcessError::Io => {
            QualificationKubernetesConcurrentV5ArtifactError::CheckerLaunch
        }
        BoundedProcessError::Reap => QualificationKubernetesConcurrentV5ArtifactError::CheckerReap,
    })?;
    reverify_interpreter_after_execution(interpreter_descriptor, &interpreter.identity).await?;
    if !output.status.success() || !output.stderr.is_empty() || output.stdout.is_empty() {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::CheckerRejected);
    }
    Ok(output.stdout)
}

#[cfg(target_os = "linux")]
async fn run_workload_verifier(
    interpreter: &PreparedInterpreter,
    inputs: &CheckerInputDescriptors,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<Vec<u8>, QualificationKubernetesConcurrentV5ArtifactError> {
    let (interpreter_descriptor, interpreter_path) =
        verified_interpreter_proc_path(interpreter).await?;
    let arguments = [
        OsString::from("-I"),
        OsString::from("-B"),
        OsString::from("-S"),
        descriptor_proc_path(&inputs.workload_verifier).into_os_string(),
        OsString::from("--evidence"),
        descriptor_proc_path(&inputs.evidence).into_os_string(),
        OsString::from("--workload-schedule"),
        descriptor_proc_path(&inputs.workload_schedule).into_os_string(),
    ];
    let output = run_bounded_process(
        &interpreter_path,
        &arguments,
        CHECKER_TIMEOUT,
        CHECKER_STDOUT_MAX_BYTES,
        CHECKER_STDERR_MAX_BYTES,
        cancellation,
    )
    .await
    .map_err(|error| match error {
        BoundedProcessError::Cancelled => {
            QualificationKubernetesConcurrentV5ArtifactError::Cancelled
        }
        BoundedProcessError::Timeout => {
            QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierTimeout
        }
        BoundedProcessError::TooLarge => {
            QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierOutputTooLarge
        }
        BoundedProcessError::Launch | BoundedProcessError::Io => {
            QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierLaunch
        }
        BoundedProcessError::Reap => {
            QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierReap
        }
    })?;
    reverify_interpreter_after_execution(interpreter_descriptor, &interpreter.identity).await?;
    if !output.status.success() || !output.stderr.is_empty() || output.stdout.is_empty() {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierRejected);
    }
    Ok(output.stdout)
}

#[cfg(target_os = "linux")]
struct BoundedProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
enum BoundedProcessError {
    Launch,
    Io,
    Timeout,
    TooLarge,
    Cancelled,
    Reap,
}

#[cfg(target_os = "linux")]
struct ProcessGroupDropGuard {
    process_group: Pid,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl ProcessGroupDropGuard {
    fn new(process_group: Pid) -> Self {
        Self {
            process_group,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProcessGroupDropGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = kill_process_group(self.process_group, Signal::KILL);
        }
    }
}

#[cfg(target_os = "linux")]
async fn run_bounded_process(
    executable: &Path,
    arguments: &[OsString],
    timeout: Duration,
    stdout_max: usize,
    stderr_max: usize,
    cancellation: &QualificationKubernetesCampaignCancellation,
) -> Result<BoundedProcessOutput, BoundedProcessError> {
    if cancellation.is_cancelled() {
        return Err(BoundedProcessError::Cancelled);
    }
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = command.spawn().map_err(|_| BoundedProcessError::Launch)?;
    let process_group = match child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw)
    {
        Some(process_group) => process_group,
        None => {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(CHECKER_REAP_TIMEOUT, child.wait()).await;
            return Err(BoundedProcessError::Launch);
        }
    };
    let mut process_group_guard = ProcessGroupDropGuard::new(process_group);
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_unreaped_process_group(&mut child, process_group, &mut process_group_guard)
                .await
                .map_err(|()| BoundedProcessError::Reap)?;
            return Err(BoundedProcessError::Launch);
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            terminate_unreaped_process_group(&mut child, process_group, &mut process_group_guard)
                .await
                .map_err(|()| BoundedProcessError::Reap)?;
            return Err(BoundedProcessError::Launch);
        }
    };
    let mut readers = tokio::task::JoinSet::new();
    readers.spawn(async move {
        (
            PipeKind::Stdout,
            read_bounded_pipe(stdout, stdout_max).await,
        )
    });
    readers.spawn(async move {
        (
            PipeKind::Stderr,
            read_bounded_pipe(stderr, stderr_max).await,
        )
    });
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let pipe_result = {
        let mut stdout_bytes = None;
        let mut stderr_bytes = None;
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break Err(BoundedProcessError::Cancelled),
                _ = &mut deadline => break Err(BoundedProcessError::Timeout),
                joined = readers.join_next() => {
                    match joined {
                        Some(Ok((PipeKind::Stdout, Ok(bytes)))) => stdout_bytes = Some(bytes),
                        Some(Ok((PipeKind::Stderr, Ok(bytes)))) => stderr_bytes = Some(bytes),
                        Some(Ok((_, Err(PipeReadError::TooLarge)))) => {
                            break Err(BoundedProcessError::TooLarge)
                        }
                        Some(Ok((_, Err(PipeReadError::Io)))) | Some(Err(_)) | None => {
                            break Err(BoundedProcessError::Io)
                        }
                    }
                }
            }
            if stdout_bytes.is_some() && stderr_bytes.is_some() {
                match (stdout_bytes.take(), stderr_bytes.take()) {
                    (Some(stdout), Some(stderr)) => break Ok((stdout, stderr)),
                    _ => break Err(BoundedProcessError::Io),
                }
            }
        }
    };

    let (stdout, stderr) = match pipe_result {
        Ok(output) => output,
        Err(error) => {
            readers.abort_all();
            while readers.join_next().await.is_some() {}
            if terminate_unreaped_process_group(&mut child, process_group, &mut process_group_guard)
                .await
                .is_err()
            {
                return Err(BoundedProcessError::Reap);
            }
            return Err(error);
        }
    };

    let wait_result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(BoundedProcessError::Cancelled),
        _ = &mut deadline => Err(BoundedProcessError::Timeout),
        waited = child.wait() => Ok(waited),
    };
    match wait_result {
        Ok(Ok(status)) => {
            // `wait` reaped the process leader. Disarm before doing anything
            // else: its numeric PID/PGID can now be reused.
            process_group_guard.disarm();
            Ok(BoundedProcessOutput {
                status,
                stdout,
                stderr,
            })
        }
        Ok(Err(_)) => {
            // Reap state is no longer knowable. Never signal the old numeric
            // process-group identifier after `wait` has returned.
            process_group_guard.disarm();
            Err(BoundedProcessError::Reap)
        }
        Err(error) => {
            if terminate_unreaped_process_group(&mut child, process_group, &mut process_group_guard)
                .await
                .is_err()
            {
                return Err(BoundedProcessError::Reap);
            }
            Err(error)
        }
    }
}

#[cfg(target_os = "linux")]
async fn terminate_unreaped_process_group(
    child: &mut Child,
    process_group: Pid,
    process_group_guard: &mut ProcessGroupDropGuard,
) -> Result<(), ()> {
    let signal_failed = kill_process_group(process_group, Signal::KILL)
        .is_err_and(|error| error != rustix::io::Errno::SRCH);
    match tokio::time::timeout(CHECKER_REAP_TIMEOUT, child.wait()).await {
        Ok(waited) => {
            // Whether `wait` succeeded or failed, do not retain a guard that
            // can later signal a reused numeric process-group identifier.
            process_group_guard.disarm();
            if signal_failed || waited.is_err() {
                Err(())
            } else {
                Ok(())
            }
        }
        Err(_) => Err(()),
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum PipeKind {
    Stdout,
    Stderr,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum PipeReadError {
    Io,
    TooLarge,
}

#[cfg(target_os = "linux")]
async fn read_bounded_pipe<R: AsyncRead + Unpin>(
    mut reader: R,
    maximum: usize,
) -> Result<Vec<u8>, PipeReadError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|_| PipeReadError::Io)?;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes
            .len()
            .checked_add(read)
            .is_none_or(|length| length > maximum)
        {
            return Err(PipeReadError::TooLarge);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

#[cfg(target_os = "linux")]
fn create_staging_directory<Fd: AsFd>(
    parent: Fd,
) -> Result<String, QualificationKubernetesConcurrentV5ArtifactError> {
    for _ in 0..STAGING_ATTEMPTS {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".opc-session-v5-staging-{}-{sequence}", std::process::id());
        match mkdirat(&parent, name.as_str(), Mode::from_raw_mode(0o700)) {
            Ok(()) => return Ok(name),
            Err(error)
                if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(QualificationKubernetesConcurrentV5ArtifactError::Publication),
        }
    }
    Err(QualificationKubernetesConcurrentV5ArtifactError::Publication)
}

#[cfg(target_os = "linux")]
fn validate_private_staging<Fd: AsFd>(
    staging: Fd,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    fchmod(&staging, Mode::from_raw_mode(0o700))
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    let metadata = fstat(&staging)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || Mode::from_raw_mode(metadata.st_mode).bits() & 0o777 != 0o700
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::Publication);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_private_file_at<Fd: AsFd>(
    directory: Fd,
    name: &str,
    encoded: &[u8],
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    fchmod(&descriptor, Mode::from_raw_mode(0o600))
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    let metadata = fstat(&descriptor)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || Mode::from_raw_mode(metadata.st_mode).bits() & 0o777 != 0o600
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::Publication);
    }
    let mut file = File::from(descriptor);
    file.write_all(encoded)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)
}

#[cfg(target_os = "linux")]
fn open_private_checker_input<Fd: AsFd>(
    directory: Fd,
    name: &str,
) -> Result<OwnedFd, QualificationKubernetesConcurrentV5ArtifactError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    let metadata = fstat(&descriptor)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || Mode::from_raw_mode(metadata.st_mode).bits() & 0o777 != 0o600
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::Publication);
    }
    Ok(descriptor)
}

#[cfg(target_os = "linux")]
fn open_checker_inputs<Fd: AsFd + Copy>(
    staging: Fd,
) -> Result<CheckerInputDescriptors, QualificationKubernetesConcurrentV5ArtifactError> {
    Ok(CheckerInputDescriptors {
        checker: open_private_checker_input(
            staging,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE,
        )?,
        workload_verifier: open_private_checker_input(
            staging,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE,
        )?,
        evidence: open_private_checker_input(
            staging,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_EVIDENCE_FILE,
        )?,
        fault_schedule: open_private_checker_input(
            staging,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_FAULT_SCHEDULE_FILE,
        )?,
        workload_schedule: open_private_checker_input(
            staging,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_SCHEDULE_FILE,
        )?,
        history: open_private_checker_input(
            staging,
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_HISTORY_FILE,
        )?,
    })
}

#[cfg(target_os = "linux")]
fn read_private_file_at<Fd: AsFd>(
    directory: Fd,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, QualificationKubernetesConcurrentV5ArtifactError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    let metadata = fstat(&descriptor)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    let length = usize::try_from(metadata.st_size)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::TooLarge)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || Mode::from_raw_mode(metadata.st_mode).bits() & 0o777 != 0o600
        || length > maximum
    {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::Publication);
    }
    let mut bytes = Vec::with_capacity(length);
    File::from(descriptor)
        .take(
            u64::try_from(maximum)
                .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::TooLarge)?
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::Publication)?;
    if bytes.len() > maximum {
        return Err(QualificationKubernetesConcurrentV5ArtifactError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn verify_staged_bytes<Fd: AsFd>(
    directory: Fd,
    name: &str,
    expected: &[u8],
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    let actual =
        read_private_file_at(directory, name, expected.len()).map_err(|error| match name {
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE => {
                QualificationKubernetesConcurrentV5ArtifactError::CheckerDigestMismatch
            }
            QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE => {
                QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierDigestMismatch
            }
            _ => error,
        })?;
    if actual == expected
        && QualificationSha256::digest(&actual) == QualificationSha256::digest(expected)
    {
        Ok(())
    } else if name == QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE {
        Err(QualificationKubernetesConcurrentV5ArtifactError::CheckerDigestMismatch)
    } else if name == QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE {
        Err(QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierDigestMismatch)
    } else {
        Err(QualificationKubernetesConcurrentV5ArtifactError::Publication)
    }
}

#[cfg(target_os = "linux")]
fn cleanup_staging_directory<ParentFd: AsFd, StagingFd: AsFd>(
    parent: ParentFd,
    staging: StagingFd,
    staging_name: &str,
) -> Result<(), ()> {
    for name in [
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_PROFILE_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_HISTORY_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_FAULT_SCHEDULE_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_SCHEDULE_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_EVIDENCE_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_OUTPUT_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_OUTPUT_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_SUMMARY_FILE,
    ] {
        match unlinkat(&staging, name, AtFlags::empty()) {
            Ok(()) => {}
            Err(error) if std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(()),
        }
    }
    unlinkat(&parent, staging_name, AtFlags::REMOVEDIR).map_err(|_| ())?;
    fsync(&parent).map_err(|_| ())
}

#[cfg(target_os = "linux")]
fn cleanup_empty_staging_directory<ParentFd: AsFd>(
    parent: ParentFd,
    staging_name: &str,
) -> Result<(), ()> {
    unlinkat(&parent, staging_name, AtFlags::REMOVEDIR).map_err(|_| ())?;
    fsync(&parent).map_err(|_| ())
}

#[cfg(target_os = "linux")]
fn map_publication_error(_: rustix::io::Errno) -> QualificationKubernetesConcurrentV5ArtifactError {
    QualificationKubernetesConcurrentV5ArtifactError::Publication
}

#[cfg(target_os = "linux")]
fn map_rename_error(error: rustix::io::Errno) -> QualificationKubernetesConcurrentV5ArtifactError {
    if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists {
        QualificationKubernetesConcurrentV5ArtifactError::DestinationExists
    } else {
        QualificationKubernetesConcurrentV5ArtifactError::Publication
    }
}

#[cfg(target_os = "linux")]
fn map_post_rename_sync(
    result: Result<(), rustix::io::Errno>,
) -> Result<(), QualificationKubernetesConcurrentV5ArtifactError> {
    result.map_err(|_| QualificationKubernetesConcurrentV5ArtifactError::PublicationOutcomeUnknown)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "qualification_kubernetes_concurrent_v5_artifacts_tests.rs"]
mod tests;
