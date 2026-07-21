#![cfg(target_os = "linux")]

use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use opc_session_testkit::qualification::{
    read_bounded_json_line, write_json_line, QualificationMember, QualificationNodeCommand,
    QualificationNodeConfig, QualificationNodeErrorCode, QualificationNodeReply,
    QualificationReadinessCode, QualificationTransportConfig, SessionHaQualificationProfile,
    QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS, QUALIFICATION_NODE_SCHEMA_VERSION,
    QUALIFICATION_OPERATION_TIMEOUT_MILLIS, SESSION_HA_EVIDENCE_SCHEMA_JSON,
    SESSION_HA_PROFILE_JSON,
};
use opc_session_testkit::qualification_sequential::{
    qualification_sequential_workload, QualificationSequentialHistoryBuilder,
    QualificationSequentialInvocation as ScheduledInvocation,
    QualificationSequentialOperation as ScheduledOperation,
    QUALIFICATION_LEASE_EXPIRY_WAIT as LEASE_EXPIRY_WAIT,
    QUALIFICATION_LONG_LEASE_MILLIS as LONG_LEASE_MILLIS,
    QUALIFICATION_SHORT_LEASE_MILLIS as SHORT_LEASE_MILLIS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use time::OffsetDateTime;

const CHILD_START_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_REPLY_TIMEOUT: Duration = Duration::from_secs(20);
const READINESS_REPLY_TIMEOUT: Duration =
    Duration::from_millis(QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS);
const FLEET_READY_TIMEOUT: Duration = Duration::from_secs(60);
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DATABASE_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROVENANCE_COMMAND_BYTES: usize = 16 * 1024;
const EVIDENCE_OUTPUT_DIRECTORY_ENV: &str = "OPC_SESSION_HA_EVIDENCE_DIR";
const FAILURE_EVIDENCE_DIRECTORY_ENV: &str = "OPC_SESSION_HA_FAILURE_DIR";
const FOUNDATION_RANDOM_SEED_BASE: u64 = 0x0143_0000;
const MAX_FAILURE_STDERR_BYTES: usize = 4 * 1024;
const MAX_FAILURE_STDERR_LINES: usize = 16;
const FAULT_TARGET_CANDIDATES: [usize; 2] = [0, 2];

#[derive(Debug)]
enum HarnessError {
    Io,
    Protocol,
    Evidence,
    Stage(Box<HarnessStageFailure>),
}

impl From<std::io::Error> for HarnessError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HarnessStage {
    InitialBind,
    InitialConfigure,
    InitialInitialize,
    InitialReadiness,
    Operation,
    FollowerObservation,
    LeaderObservation,
    StopFollower,
    StopLeader,
    ContinuityReadiness,
    LeaderFailoverReadiness,
    RestartBind,
    RestartConfigure,
    RestartInitialize,
    RestartReadiness,
    LeaderRestartBind,
    LeaderRestartConfigure,
    LeaderRestartInitialize,
    LeaderRestartReadiness,
    ConfigurationEvidence,
    HistoryEvidence,
    ThresholdEvidence,
    StorageEvidence,
    CheckerSpawn,
    CheckerExit,
    CheckerOutputSize,
    CheckerOutputJson,
    CheckerResult,
    CheckerArtifact,
    CheckerFailureRetention,
    DigestEvidence,
    EvidenceValidation,
    BundleEvidence,
    Cleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HarnessFailureKind {
    Deadline,
    Disconnected,
    ProcessExited,
    Protocol,
    Io,
    Evidence,
    ReadinessNotReady,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HarnessStageFailure {
    stage: HarnessStage,
    node_index: Option<usize>,
    kind: HarnessFailureKind,
    readiness: Vec<ReadinessDiagnostic>,
    exit: Option<ExitDiagnostic>,
    stderr: Option<StderrDiagnostic>,
    checker: Option<CheckerDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadinessDiagnostic {
    node_index: usize,
    ready: bool,
    reason_code: QualificationReadinessCode,
    node_id: u64,
    term: u64,
    leader_id: Option<u64>,
    configured_voters: usize,
    fresh_reachable_voters: usize,
    agreeing_voters: usize,
    required_quorum: usize,
    committed_index: Option<u64>,
    applied_index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExitDiagnostic {
    success: bool,
    code: Option<i32>,
    signal: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StderrLineCode {
    QualificationNodeFailed,
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StderrDiagnostic {
    total_bytes: u64,
    captured_bytes: usize,
    truncated: bool,
    line_codes: Vec<StderrLineCode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckerStatusDiagnostic {
    Pass,
    Fail,
    Inconclusive,
    InvalidInput,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckerFindingDiagnostic {
    UnexpectedHistoryOperation,
    MissingHistoryOperation,
    DependentOnUnknownOutcome,
    ScheduleHistoryMismatch,
    LeaseExpiryAmbiguity,
    UnknownOperationOutcome,
    LeaseStateViolation,
    FenceMonotonicityViolation,
    LeaseReferenceViolation,
    CasStateViolation,
    LinearizableReadViolation,
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CheckerDiagnostic {
    exit_code: Option<i32>,
    signal: Option<i32>,
    status: CheckerStatusDiagnostic,
    operations_checked: Option<u64>,
    violation_codes: Vec<CheckerFindingDiagnostic>,
    inconclusive_codes: Vec<CheckerFindingDiagnostic>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckerOutputDocument {
    checker: String,
    checker_version: String,
    status: String,
    operations_checked: u64,
    violation_codes: Vec<String>,
    inconclusive_codes: Vec<String>,
}

impl HarnessStageFailure {
    fn new(stage: HarnessStage, node_index: Option<usize>, kind: HarnessFailureKind) -> Self {
        Self {
            stage,
            node_index,
            kind,
            readiness: Vec::new(),
            exit: None,
            stderr: None,
            checker: None,
        }
    }

    fn with_readiness(mut self, readiness: Vec<ReadinessDiagnostic>) -> Self {
        self.readiness = readiness;
        self
    }

    fn with_checker(mut self, checker: CheckerDiagnostic) -> Self {
        self.checker = Some(checker);
        self
    }
}

fn stage_error(
    stage: HarnessStage,
    node_index: Option<usize>,
    kind: HarnessFailureKind,
) -> HarnessError {
    HarnessError::Stage(Box::new(HarnessStageFailure::new(stage, node_index, kind)))
}

fn at_stage<T>(result: Result<T, HarnessError>, stage: HarnessStage) -> Result<T, HarnessError> {
    result.map_err(|error| match error {
        HarnessError::Io => stage_error(stage, None, HarnessFailureKind::Io),
        HarnessError::Protocol => stage_error(stage, None, HarnessFailureKind::Protocol),
        HarnessError::Evidence => stage_error(stage, None, HarnessFailureKind::Evidence),
        HarnessError::Stage(_) => error,
    })
}

fn checker_status(value: &str) -> CheckerStatusDiagnostic {
    match value {
        "pass" => CheckerStatusDiagnostic::Pass,
        "fail" => CheckerStatusDiagnostic::Fail,
        "inconclusive" => CheckerStatusDiagnostic::Inconclusive,
        "invalid_input" => CheckerStatusDiagnostic::InvalidInput,
        _ => CheckerStatusDiagnostic::Unknown,
    }
}

fn checker_finding(value: &str) -> CheckerFindingDiagnostic {
    match value {
        "unexpected_history_operation" => CheckerFindingDiagnostic::UnexpectedHistoryOperation,
        "missing_history_operation" => CheckerFindingDiagnostic::MissingHistoryOperation,
        "dependent_on_unknown_outcome" => CheckerFindingDiagnostic::DependentOnUnknownOutcome,
        "schedule_history_mismatch" => CheckerFindingDiagnostic::ScheduleHistoryMismatch,
        "lease_expiry_ambiguity" => CheckerFindingDiagnostic::LeaseExpiryAmbiguity,
        "unknown_operation_outcome" => CheckerFindingDiagnostic::UnknownOperationOutcome,
        "lease_state_violation" => CheckerFindingDiagnostic::LeaseStateViolation,
        "fence_monotonicity_violation" => CheckerFindingDiagnostic::FenceMonotonicityViolation,
        "lease_reference_violation" => CheckerFindingDiagnostic::LeaseReferenceViolation,
        "cas_state_violation" => CheckerFindingDiagnostic::CasStateViolation,
        "linearizable_read_violation" => CheckerFindingDiagnostic::LinearizableReadViolation,
        _ => CheckerFindingDiagnostic::Redacted,
    }
}

fn checker_diagnostic(
    document: &CheckerOutputDocument,
    exit_code: Option<i32>,
    signal: Option<i32>,
) -> CheckerDiagnostic {
    CheckerDiagnostic {
        exit_code,
        signal,
        status: checker_status(&document.status),
        operations_checked: Some(document.operations_checked),
        violation_codes: document
            .violation_codes
            .iter()
            .map(|code| checker_finding(code))
            .collect(),
        inconclusive_codes: document
            .inconclusive_codes
            .iter()
            .map(|code| checker_finding(code))
            .collect(),
    }
}

fn unknown_checker_diagnostic(exit_code: Option<i32>, signal: Option<i32>) -> CheckerDiagnostic {
    CheckerDiagnostic {
        exit_code,
        signal,
        status: CheckerStatusDiagnostic::Unknown,
        operations_checked: None,
        violation_codes: Vec::new(),
        inconclusive_codes: Vec::new(),
    }
}

fn checker_stage_error(stage: HarnessStage, checker: CheckerDiagnostic) -> HarnessError {
    HarnessError::Stage(Box::new(
        HarnessStageFailure::new(stage, None, HarnessFailureKind::Evidence).with_checker(checker),
    ))
}

fn workload(member_count: usize) -> Vec<ScheduledInvocation> {
    qualification_sequential_workload(member_count).expect("fixed supported topology")
}

fn write_schedule(path: &Path, schedule: &[ScheduledInvocation]) -> Result<String, HarnessError> {
    let file = open_private_file(path, false)?;
    let mut writer = BufWriter::new(file);
    for invocation in schedule {
        serde_json::to_writer(&mut writer, invocation).map_err(|_| HarnessError::Evidence)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    let file = writer.into_inner().map_err(|_| HarnessError::Io)?;
    file.sync_all()?;
    sha256_file(path)
}

fn open_private_file(path: &Path, append: bool) -> Result<File, HarnessError> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(!append)
        .append(append)
        .mode(0o600)
        .open(path)
        .map_err(HarnessError::from)
}

fn sha256_file(path: &Path) -> Result<String, HarnessError> {
    let encoded = fs::read(path)?;
    Ok(sha256_bytes(&encoded))
}

fn sha256_bytes(encoded: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    format!("sha256:{:x}", hasher.finalize())
}

fn domain_separated_sha256(
    domain: &str,
    parts: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> Result<String, HarnessError> {
    let mut hasher = Sha256::new();
    hasher.update(b"opc-session-ha-evidence-domain-v1\0");
    let domain = domain.as_bytes();
    hasher.update(
        u64::try_from(domain.len())
            .map_err(|_| HarnessError::Evidence)?
            .to_be_bytes(),
    );
    hasher.update(domain);
    for part in parts {
        let part = part.as_ref();
        hasher.update(
            u64::try_from(part.len())
                .map_err(|_| HarnessError::Evidence)?
                .to_be_bytes(),
        );
        hasher.update(part);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn aggregate_file_sha256(domain: &str, paths: &[PathBuf]) -> Result<String, HarnessError> {
    let mut contents = Vec::with_capacity(paths.len());
    for path in paths {
        let content = fs::read(path)?;
        if content.len() > 1024 * 1024 {
            return Err(HarnessError::Evidence);
        }
        contents.push(content);
    }
    domain_separated_sha256(domain, &contents)
}

fn write_private_bytes(path: &Path, bytes: &[u8]) -> Result<(), HarnessError> {
    let mut file = open_private_file(path, false)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn write_private_json(path: &Path, value: &Value) -> Result<(), HarnessError> {
    let mut encoded = serde_json::to_vec(value).map_err(|_| HarnessError::Evidence)?;
    encoded.push(b'\n');
    write_private_bytes(path, &encoded)
}

fn preserve_checker_failure_bundle(
    member_count: usize,
    artifacts: &[(&str, &Path)],
    stdout: &[u8],
    stderr: &[u8],
    checker: &CheckerDiagnostic,
    child_cleanup_complete: bool,
) -> Result<(), HarnessError> {
    let Some(configured_root) = env::var_os(FAILURE_EVIDENCE_DIRECTORY_ENV) else {
        return Ok(());
    };
    let configured_root = PathBuf::from(configured_root);
    if !configured_root.is_absolute() {
        return Err(HarnessError::Evidence);
    }
    let mut root_builder = DirBuilder::new();
    root_builder.recursive(true).mode(0o700);
    root_builder.create(&configured_root)?;
    let canonical_root = fs::canonicalize(&configured_root)?;
    let root_metadata = fs::symlink_metadata(&configured_root)?;
    if canonical_root != configured_root
        || root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
    {
        return Err(HarnessError::Evidence);
    }
    fs::set_permissions(&canonical_root, Permissions::from_mode(0o700))?;

    let nonce = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let destination = canonical_root.join(format!(
        "{member_count}-node-{nonce}-{}",
        std::process::id()
    ));
    let mut destination_builder = DirBuilder::new();
    destination_builder.mode(0o700).create(&destination)?;
    for (name, source) in artifacts {
        if name.contains('/') {
            return Err(HarnessError::Evidence);
        }
        let metadata = fs::symlink_metadata(source)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 8 * 1024 * 1024
        {
            return Err(HarnessError::Evidence);
        }
        let target = destination.join(name);
        fs::copy(source, &target)?;
        fs::set_permissions(&target, Permissions::from_mode(0o600))?;
        File::open(&target)?.sync_all()?;
    }
    write_private_bytes(
        &destination.join("checker-stdout.bin"),
        &stdout[..stdout.len().min(MAX_PROVENANCE_COMMAND_BYTES)],
    )?;
    write_private_bytes(
        &destination.join("checker-stderr.bin"),
        &stderr[..stderr.len().min(MAX_FAILURE_STDERR_BYTES)],
    )?;
    let metadata = json!({
        "schema_version": "opc-session-ha-checker-failure/v1",
        "topology_members": member_count,
        "checker": serde_json::to_value(checker).map_err(|_| HarnessError::Evidence)?,
        "stdout_total_bytes": stdout.len(),
        "stdout_captured_bytes": stdout.len().min(MAX_PROVENANCE_COMMAND_BYTES),
        "stderr_total_bytes": stderr.len(),
        "stderr_captured_bytes": stderr.len().min(MAX_FAILURE_STDERR_BYTES),
        "child_cleanup_complete": child_cleanup_complete,
        "artifacts": artifacts.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
    });
    write_private_json(&destination.join("failure.json"), &metadata)?;
    File::open(&destination)?.sync_all()?;
    File::open(&canonical_root)?.sync_all()?;
    Ok(())
}

fn command_stdout(
    program: &str,
    args: &[&str],
    current_dir: Option<&Path>,
) -> Result<String, HarnessError> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    let output = command.output().map_err(|_| HarnessError::Evidence)?;
    if !output.status.success()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_PROVENANCE_COMMAND_BYTES
        || output.stdout.contains(&0)
    {
        return Err(HarnessError::Evidence);
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim_end().to_owned())
        .map_err(|_| HarnessError::Evidence)
}

fn source_provenance(repository: &Path) -> Result<(String, &'static str), HarnessError> {
    let revision = command_stdout("git", &["rev-parse", "HEAD"], Some(repository))?;
    if !is_lower_hex(&revision, 40) {
        return Err(HarnessError::Evidence);
    }
    let output = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .current_dir(repository)
        .output()
        .map_err(|_| HarnessError::Evidence)?;
    if !output.status.success() || output.stdout.len() > MAX_PROVENANCE_COMMAND_BYTES {
        return Err(HarnessError::Evidence);
    }
    let status = if output.stdout.is_empty() {
        "clean"
    } else {
        "dirty_unqualified"
    };
    Ok((revision, status))
}

fn environment_evidence() -> Result<Value, HarnessError> {
    let rustc_version = command_stdout("rustc", &["--version"], None)?;
    let cargo_version = command_stdout("cargo", &["--version"], None)?;
    let rustc_verbose = command_stdout("rustc", &["-vV"], None)?;
    let target = rustc_verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(HarnessError::Evidence)?;
    let kernel = command_stdout("uname", &["-sr"], None)?;
    if rustc_version.len() > 128 || cargo_version.len() > 128 || kernel.len() > 256 {
        return Err(HarnessError::Evidence);
    }
    Ok(json!({
        "rustc_version": rustc_version,
        "cargo_version": cargo_version,
        "target": target,
        "os": env::consts::OS,
        "kernel": kernel,
        "container_status": "not_collected_in_foundation",
        "container_image_digest": null,
    }))
}

fn utc_timestamp(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn duration_millis(duration: Duration) -> Result<u64, HarnessError> {
    u64::try_from(duration.as_millis()).map_err(|_| HarnessError::Evidence)
}

fn structural_schema_for_lightweight_validator(mut schema: Value) -> Value {
    match &mut schema {
        Value::Object(object) => {
            for unsupported in ["maxItems", "maxLength", "maximum", "pattern", "uniqueItems"] {
                object.remove(unsupported);
            }
            for value in object.values_mut() {
                *value = structural_schema_for_lightweight_validator(value.take());
            }
        }
        Value::Array(values) => {
            for value in values {
                *value = structural_schema_for_lightweight_validator(value.take());
            }
        }
        _ => {}
    }
    schema
}

fn is_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

fn valid_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    let decimal = |digits: &[u8]| {
        digits.iter().try_fold(0_u32, |value, digit| {
            digit
                .is_ascii_digit()
                .then_some(value * 10 + u32::from(*digit - b'0'))
        })
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        decimal(&bytes[0..4]),
        decimal(&bytes[5..7]),
        decimal(&bytes[8..10]),
        decimal(&bytes[11..13]),
        decimal(&bytes[14..16]),
        decimal(&bytes[17..19]),
    ) else {
        return false;
    };
    year >= 1970
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 60
}

fn validate_generated_evidence(
    evidence: &Value,
    member_count: usize,
    profile: &SessionHaQualificationProfile,
) -> Result<(), HarnessError> {
    let schema: Value = serde_json::from_str(SESSION_HA_EVIDENCE_SCHEMA_JSON)
        .map_err(|_| HarnessError::Evidence)?;
    opc_schema_validate::validate(
        &structural_schema_for_lightweight_validator(schema),
        evidence,
    )
    .map_err(|_| HarnessError::Evidence)?;

    if !evidence["source_revision"]
        .as_str()
        .is_some_and(|value| is_lower_hex(value, 40))
        || !matches!(
            evidence["source_tree_status"].as_str(),
            Some("clean" | "dirty_unqualified")
        )
        || evidence["artifact"]["foundation_feature_overrides"]
            != json!(["opc-session-net/insecure-test"])
    {
        return Err(HarnessError::Evidence);
    }

    let mut digests = vec![
        evidence["artifact"]["sha256"].as_str(),
        evidence["execution"]["profile_sha256"].as_str(),
        evidence["execution"]["configuration_sha256"].as_str(),
        evidence["execution"]["fault_schedule_sha256"].as_str(),
        evidence["history"]["schedule_sha256"].as_str(),
        evidence["history"]["sha256"].as_str(),
        evidence["checker"]["sha256"].as_str(),
        evidence["checker"]["output_sha256"].as_str(),
    ];
    digests.extend(
        evidence["topology"]["storage_identity_sha256"]
            .as_array()
            .into_iter()
            .flatten()
            .map(Value::as_str),
    );
    if !digests
        .into_iter()
        .all(|digest| digest.is_some_and(is_sha256))
    {
        return Err(HarnessError::Evidence);
    }

    let storage = evidence["topology"]["storage_identity_sha256"]
        .as_array()
        .ok_or(HarnessError::Evidence)?;
    let distinct_storage = storage
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if evidence["topology"]["members"].as_u64() != Some(member_count as u64)
        || storage.len() != member_count
        || distinct_storage.len() != member_count
    {
        return Err(HarnessError::Evidence);
    }

    let started = evidence["execution"]["started_at_utc"]
        .as_str()
        .ok_or(HarnessError::Evidence)?;
    let completed = evidence["execution"]["completed_at_utc"]
        .as_str()
        .ok_or(HarnessError::Evidence)?;
    if !valid_utc_timestamp(started) || !valid_utc_timestamp(completed) || started > completed {
        return Err(HarnessError::Evidence);
    }

    let results = &evidence["results"];
    let startup_within_bound = results["startup_millis"]
        .as_u64()
        .is_some_and(|value| value <= profile.provisional_test_thresholds.max_startup_millis);
    let continuity_within_bound = results["single_member_stop_service_continuity_millis"]
        .as_u64()
        .is_some_and(|value| {
            value
                <= profile
                    .provisional_test_thresholds
                    .max_single_member_stop_service_continuity_millis
        });
    let catchup_within_bound = results["restart_catchup_millis"]
        .as_u64()
        .is_some_and(|value| {
            value
                <= profile
                    .provisional_test_thresholds
                    .max_restart_catchup_millis
        });
    let leader_failover_within_bound =
        results["leader_failover_millis"]
            .as_u64()
            .is_some_and(|value| {
                value
                    <= profile
                        .provisional_test_thresholds
                        .max_leader_failover_millis
            });
    let leader_restart_within_bound = results["leader_restart_catchup_millis"]
        .as_u64()
        .is_some_and(|value| {
            value
                <= profile
                    .provisional_test_thresholds
                    .max_leader_restart_catchup_millis
        });
    if !(startup_within_bound
        && continuity_within_bound
        && catchup_within_bound
        && leader_failover_within_bound
        && leader_restart_within_bound
        && results["leader_outage_store_read_succeeded"] == true)
    {
        return Err(HarnessError::Evidence);
    }

    for artifact in ["logs", "metrics"] {
        if evidence[artifact]["collection_status"] != "not_collected_in_foundation"
            || evidence[artifact]["digests"] != json!([])
        {
            return Err(HarnessError::Evidence);
        }
    }
    if evidence["environment"]["container_status"] != "not_collected_in_foundation"
        || !evidence["environment"]["container_image_digest"].is_null()
    {
        return Err(HarnessError::Evidence);
    }

    let faults = evidence["faults"]
        .as_array()
        .ok_or(HarnessError::Evidence)?;
    let first_fault = faults.first().ok_or(HarnessError::Evidence)?;
    let expected_target = first_fault["target_process"]
        .as_str()
        .filter(|target| matches!(*target, "node-0" | "node-2"))
        .ok_or(HarnessError::Evidence)?;
    let expected_node_id = first_fault["observed_node_id"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or(HarnessError::Evidence)?;
    let expected_leader_id = first_fault["observed_leader_id"]
        .as_u64()
        .filter(|value| *value > 0 && *value != expected_node_id)
        .ok_or(HarnessError::Evidence)?;
    let expected_term = first_fault["observed_term"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or(HarnessError::Evidence)?;
    let leader_fault = faults.get(2).ok_or(HarnessError::Evidence)?;
    let leader_target = leader_fault["target_process"]
        .as_str()
        .filter(|target| {
            target
                .strip_prefix("node-")
                .and_then(|index| index.parse::<usize>().ok())
                .is_some_and(|index| index < member_count)
        })
        .ok_or(HarnessError::Evidence)?;
    let old_leader_id = leader_fault["observed_node_id"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or(HarnessError::Evidence)?;
    let old_term = leader_fault["observed_term"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or(HarnessError::Evidence)?;
    if faults.len() != 4
        || !faults[..2].iter().all(|fault| {
            fault["target_process"] == expected_target
                && fault["target_role"] == "follower"
                && fault["observed_node_id"].as_u64() == Some(expected_node_id)
                && fault["observed_leader_id"].as_u64() == Some(expected_leader_id)
                && fault["observed_term"].as_u64() == Some(expected_term)
                && fault["bounded"] == true
        })
        || !faults[2..].iter().all(|fault| {
            fault["target_process"] == leader_target
                && fault["target_role"] == "leader"
                && fault["observed_node_id"].as_u64() == Some(old_leader_id)
                && fault["observed_leader_id"].as_u64() == Some(old_leader_id)
                && fault["observed_term"].as_u64() == Some(old_term)
                && fault["bounded"] == true
        })
    {
        return Err(HarnessError::Evidence);
    }

    let transition = &evidence["leader_transition"];
    let new_leader_process = transition["new_leader_process"]
        .as_str()
        .filter(|target| {
            target
                .strip_prefix("node-")
                .and_then(|index| index.parse::<usize>().ok())
                .is_some_and(|index| index < member_count)
        })
        .ok_or(HarnessError::Evidence)?;
    let new_leader_id = transition["new_leader_node_id"]
        .as_u64()
        .filter(|value| *value > 0 && *value != old_leader_id)
        .ok_or(HarnessError::Evidence)?;
    let new_term = transition["new_term"]
        .as_u64()
        .filter(|value| *value > old_term)
        .ok_or(HarnessError::Evidence)?;
    if transition["old_leader_process"] != leader_target
        || transition["old_leader_node_id"].as_u64() != Some(old_leader_id)
        || transition["old_term"].as_u64() != Some(old_term)
        || transition["new_leader_process"] != new_leader_process
        || transition["new_leader_node_id"].as_u64() != Some(new_leader_id)
        || transition["new_term"].as_u64() != Some(new_term)
        || transition["failover_millis"] != results["leader_failover_millis"]
        || transition["old_leader_restart_catchup_millis"]
            != results["leader_restart_catchup_millis"]
    {
        return Err(HarnessError::Evidence);
    }

    let coverage = evidence["coverage"]
        .as_array()
        .ok_or(HarnessError::Evidence)?;
    let expected_topology = if member_count == 3 {
        "three_node"
    } else {
        "five_node"
    };
    let other_topology = if member_count == 3 {
        "five_node"
    } else {
        "three_node"
    };
    if !coverage.iter().any(|item| item == expected_topology)
        || coverage.iter().any(|item| item == other_topology)
        || !coverage.iter().any(|item| item == "lease_expiry_reacquire")
        || !coverage.iter().any(|item| item == "stale_fence_rejection")
        || !coverage
            .iter()
            .any(|item| item == "observed_leader_failover")
        || !evidence["remaining_acceptance"]
            .as_array()
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item == "leader_follower_crash_matrix")
            })
    {
        return Err(HarnessError::Evidence);
    }
    Ok(())
}

fn preserve_evidence_bundle(
    member_count: usize,
    artifacts: &[(&str, &Path)],
) -> Result<Option<PathBuf>, HarnessError> {
    let Some(configured_root) = env::var_os(EVIDENCE_OUTPUT_DIRECTORY_ENV) else {
        return Ok(None);
    };
    let configured_root = PathBuf::from(configured_root);
    if !configured_root.is_absolute() {
        return Err(HarnessError::Evidence);
    }
    fs::create_dir_all(&configured_root)?;
    let canonical_root = fs::canonicalize(&configured_root)?;
    if canonical_root != configured_root
        || fs::symlink_metadata(&canonical_root)?
            .file_type()
            .is_symlink()
    {
        return Err(HarnessError::Evidence);
    }
    let destination = canonical_root.join(format!("{member_count}-node"));
    fs::create_dir(&destination)?;
    for (name, source) in artifacts {
        let metadata = fs::symlink_metadata(source)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || name.contains('/') {
            return Err(HarnessError::Evidence);
        }
        let target = destination.join(name);
        fs::copy(source, &target)?;
        File::open(&target)?.sync_all()?;
    }
    File::open(&destination)?.sync_all()?;
    File::open(&canonical_root)?.sync_all()?;
    Ok(Some(destination))
}

fn validate_retained_jsonl_schema(path: &Path, schema: &Value) -> Result<(), HarnessError> {
    let raw = fs::read_to_string(path).map_err(|_| HarnessError::Evidence)?;
    if raw.is_empty() || !raw.ends_with('\n') {
        return Err(HarnessError::Evidence);
    }
    for line in raw.lines() {
        let value: Value = serde_json::from_str(line).map_err(|_| HarnessError::Evidence)?;
        opc_schema_validate::validate(
            &structural_schema_for_lightweight_validator(schema.clone()),
            &value,
        )
        .map_err(|_| HarnessError::Evidence)?;
    }
    Ok(())
}

fn verify_retained_bundle(destination: &Path, member_count: usize) -> Result<(), HarnessError> {
    if !destination.is_absolute()
        || fs::canonicalize(destination)? != destination
        || fs::symlink_metadata(destination)?.file_type().is_symlink()
    {
        return Err(HarnessError::Evidence);
    }
    let retained = |name: &str| -> Result<PathBuf, HarnessError> {
        if name.contains('/') {
            return Err(HarnessError::Evidence);
        }
        let path = destination.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(HarnessError::Evidence);
        }
        Ok(path)
    };

    let evidence_path = retained("evidence.json")?;
    let profile_path = retained("profile.json")?;
    let profile_schema_path = retained("profile.schema.json")?;
    let evidence_schema_path = retained("evidence.schema.json")?;
    let schedule_schema_path = retained("schedule.schema.json")?;
    let history_schema_path = retained("history.schema.json")?;
    let configuration_manifest_path = retained("configuration-manifest.json")?;
    let fault_schedule_path = retained("fault-schedule.json")?;
    let schedule_path = retained("schedule.jsonl")?;
    let history_path = retained("history.jsonl")?;
    let checker_output_path = retained("checker-output.json")?;
    let checker_path = retained("check-session-ha-history.py")?;
    let binary_path = retained("opc-session-quorum-node")?;

    let evidence: Value =
        serde_json::from_slice(&fs::read(&evidence_path)?).map_err(|_| HarnessError::Evidence)?;
    let profile_value: Value =
        serde_json::from_slice(&fs::read(&profile_path)?).map_err(|_| HarnessError::Evidence)?;
    let profile: SessionHaQualificationProfile =
        serde_json::from_value(profile_value.clone()).map_err(|_| HarnessError::Evidence)?;
    let profile_schema: Value = serde_json::from_slice(&fs::read(&profile_schema_path)?)
        .map_err(|_| HarnessError::Evidence)?;
    let evidence_schema: Value = serde_json::from_slice(&fs::read(&evidence_schema_path)?)
        .map_err(|_| HarnessError::Evidence)?;
    let schedule_schema: Value = serde_json::from_slice(&fs::read(&schedule_schema_path)?)
        .map_err(|_| HarnessError::Evidence)?;
    let history_schema: Value = serde_json::from_slice(&fs::read(&history_schema_path)?)
        .map_err(|_| HarnessError::Evidence)?;
    opc_schema_validate::validate(
        &structural_schema_for_lightweight_validator(profile_schema),
        &profile_value,
    )
    .map_err(|_| HarnessError::Evidence)?;
    opc_schema_validate::validate(
        &structural_schema_for_lightweight_validator(evidence_schema),
        &evidence,
    )
    .map_err(|_| HarnessError::Evidence)?;
    validate_retained_jsonl_schema(&schedule_path, &schedule_schema)?;
    validate_retained_jsonl_schema(&history_path, &history_schema)?;
    validate_generated_evidence(&evidence, member_count, &profile)?;

    let manifest_bytes = fs::read(&configuration_manifest_path)?;
    if !manifest_bytes.ends_with(b"\n") {
        return Err(HarnessError::Evidence);
    }
    let manifest: CanonicalConfigurationManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| HarnessError::Evidence)?;
    let synthetic_private_root = destination.join("offline-private-root");
    let runtime_configs = manifest.runtime_configs(&synthetic_private_root)?;
    if CanonicalConfigurationManifest::from_runtime_configs(
        &runtime_configs,
        &synthetic_private_root,
    )? != manifest
    {
        return Err(HarnessError::Evidence);
    }

    let fault_schedule: Value = serde_json::from_slice(&fs::read(&fault_schedule_path)?)
        .map_err(|_| HarnessError::Evidence)?;
    let evidence_faults = evidence["faults"]
        .as_array()
        .ok_or(HarnessError::Evidence)?;
    if fault_schedule["schema_version"] != "opc-session-ha-fault-schedule/v1"
        || fault_schedule["topology_members"].as_u64() != Some(member_count as u64)
        || !fault_schedule["faults"].as_array().is_some_and(|faults| {
            faults.len() == 4
                && evidence_faults.len() == faults.len()
                && faults.iter().zip(evidence_faults).enumerate().all(
                    |(index, (scheduled, retained))| {
                        scheduled["sequence"].as_u64() == Some((index + 1) as u64)
                            && scheduled["kind"] == retained["kind"]
                            && scheduled["target_process"] == retained["target_process"]
                            && scheduled["target_role"] == retained["target_role"]
                            && scheduled["observed_node_id"] == retained["observed_node_id"]
                            && scheduled["observed_leader_id"] == retained["observed_leader_id"]
                            && scheduled["observed_term"] == retained["observed_term"]
                            && scheduled["bounded"] == true
                            && retained["bounded"] == true
                    },
                )
        })
    {
        return Err(HarnessError::Evidence);
    }

    let fault_paths = vec![fault_schedule_path.clone()];
    let expected_storage = manifest.storage_identity_sha256()?;
    if evidence["artifact"]["sha256"] != sha256_file(&binary_path)?
        || evidence["execution"]["profile_sha256"] != sha256_file(&profile_path)?
        || evidence["execution"]["configuration_digest_domain"] != CONFIGURATION_DIGEST_DOMAIN
        || evidence["execution"]["configuration_sha256"]
            != domain_separated_sha256(CONFIGURATION_DIGEST_DOMAIN, [&manifest_bytes])?
        || evidence["execution"]["fault_schedule_digest_domain"] != FAULT_SCHEDULE_DIGEST_DOMAIN
        || evidence["execution"]["fault_schedule_sha256"]
            != aggregate_file_sha256(FAULT_SCHEDULE_DIGEST_DOMAIN, &fault_paths)?
        || evidence["topology"]["storage_identity_digest_domain"] != STORAGE_IDENTITY_DIGEST_DOMAIN
        || evidence["topology"]["storage_identity_sha256"] != json!(expected_storage)
        || evidence["history"]["schedule_sha256"] != sha256_file(&schedule_path)?
        || evidence["history"]["sha256"] != sha256_file(&history_path)?
        || evidence["checker"]["sha256"] != sha256_file(&checker_path)?
        || evidence["checker"]["output_sha256"] != sha256_file(&checker_output_path)?
    {
        return Err(HarnessError::Evidence);
    }

    let output = Command::new("python3")
        .arg(&checker_path)
        .arg("--schedule")
        .arg(&schedule_path)
        .arg("--history")
        .arg(&history_path)
        .output()
        .map_err(|_| HarnessError::Evidence)?;
    let retained_output = fs::read(&checker_output_path)?;
    let checker_result: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| HarnessError::Evidence)?;
    if output.status.code() != Some(0)
        || !output.stderr.is_empty()
        || output.stdout != retained_output
        || checker_result["status"] != "pass"
        || checker_result["operations_checked"].as_u64() != Some(15)
    {
        return Err(HarnessError::Evidence);
    }
    Ok(())
}

enum ReaderMessage {
    Reply(Box<QualificationNodeReply>),
    Protocol,
}

struct ChildNode {
    node_index: usize,
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    replies: Receiver<ReaderMessage>,
    reader_done: Receiver<()>,
    reader: Option<JoinHandle<()>>,
    stderr_path: PathBuf,
}

impl ChildNode {
    fn spawn_bound(
        binary: &Path,
        config: &Path,
        stderr_path: &Path,
        node_index: usize,
        requested_bind_addr: SocketAddr,
        stage: HarnessStage,
    ) -> Result<(Self, SocketAddr), HarnessError> {
        let stderr = open_private_file(stderr_path, true)?;
        let mut child = Command::new(binary)
            .arg("--config")
            .arg(config)
            .arg("--node-index")
            .arg(node_index.to_string())
            .arg("--bind-addr")
            .arg(requested_bind_addr.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|_| stage_error(stage, Some(node_index), HarnessFailureKind::Io))?;
        let Some(stdin) = child.stdin.take() else {
            terminate_failed_spawn(&mut child);
            return Err(stage_error(
                stage,
                Some(node_index),
                HarnessFailureKind::ProcessExited,
            ));
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_failed_spawn(&mut child);
            return Err(stage_error(
                stage,
                Some(node_index),
                HarnessFailureKind::ProcessExited,
            ));
        };
        let (sender, replies) = mpsc::sync_channel(8);
        let (done_sender, reader_done) = mpsc::sync_channel(1);
        let reader = match thread::Builder::new()
            .name(format!("qualification-node-{node_index}-stdout"))
            .spawn(move || {
                let mut stdout = BufReader::new(stdout);
                loop {
                    let message = match read_bounded_json_line(&mut stdout) {
                        Ok(Some(reply)) => ReaderMessage::Reply(Box::new(reply)),
                        Ok(None) => break,
                        Err(_) => ReaderMessage::Protocol,
                    };
                    let failed = matches!(message, ReaderMessage::Protocol);
                    if sender.send(message).is_err() || failed {
                        break;
                    }
                }
                let _ = done_sender.send(());
            }) {
            Ok(reader) => reader,
            Err(_) => {
                terminate_failed_spawn(&mut child);
                return Err(stage_error(stage, Some(node_index), HarnessFailureKind::Io));
            }
        };
        let mut node = Self {
            node_index,
            child,
            stdin: Some(BufWriter::new(stdin)),
            replies,
            reader_done,
            reader: Some(reader),
            stderr_path: stderr_path.to_path_buf(),
        };
        match node.recv(stage, CHILD_START_TIMEOUT)? {
            QualificationNodeReply::Bound {
                node_index: actual_node_index,
                bind_addr,
            } if actual_node_index == node_index
                && bind_addr.ip().is_loopback()
                && (requested_bind_addr.port() == 0 || bind_addr == requested_bind_addr) =>
            {
                Ok((node, bind_addr))
            }
            _ => Err(node.failure(stage, HarnessFailureKind::Protocol)),
        }
    }

    fn configure(&mut self, stage: HarnessStage) -> Result<(), HarnessError> {
        self.send(&QualificationNodeCommand::Configure, stage)?;
        match self.recv(stage, CHILD_START_TIMEOUT)? {
            QualificationNodeReply::Started { node_index } if node_index == self.node_index => {
                Ok(())
            }
            _ => Err(self.failure(stage, HarnessFailureKind::Protocol)),
        }
    }

    fn send(
        &mut self,
        command: &QualificationNodeCommand,
        stage: HarnessStage,
    ) -> Result<(), HarnessError> {
        let result = self
            .stdin
            .as_mut()
            .ok_or(())
            .and_then(|stdin| write_json_line(stdin, command).map_err(|_| ()));
        if result.is_err() {
            return Err(self.failure(stage, HarnessFailureKind::Disconnected));
        }
        Ok(())
    }

    fn recv(
        &mut self,
        stage: HarnessStage,
        timeout: Duration,
    ) -> Result<QualificationNodeReply, HarnessError> {
        match self.replies.recv_timeout(timeout) {
            Ok(ReaderMessage::Reply(reply)) => Ok(*reply),
            Ok(ReaderMessage::Protocol) => Err(self.failure(stage, HarnessFailureKind::Protocol)),
            Err(RecvTimeoutError::Timeout) => {
                Err(self.failure(stage, HarnessFailureKind::Deadline))
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err(self.failure(stage, HarnessFailureKind::Disconnected))
            }
        }
    }

    fn invoke(
        &mut self,
        command: &QualificationNodeCommand,
        stage: HarnessStage,
    ) -> Result<QualificationNodeReply, HarnessError> {
        self.send(command, stage)?;
        self.recv(stage, CHILD_REPLY_TIMEOUT)
    }

    fn kill_unclean(mut self, stage: HarnessStage) -> Result<(), HarnessError> {
        if self.child.kill().is_err() {
            return Err(self.failure(stage, HarnessFailureKind::Io));
        }
        self.stdin.take();
        if let Err(kind) = wait_for_exit(&mut self.child, PROCESS_STOP_TIMEOUT) {
            return Err(self.failure(stage, kind));
        }
        self.join_reader_bounded();
        Ok(())
    }

    fn failure(&mut self, stage: HarnessStage, mut kind: HarnessFailureKind) -> HarnessError {
        let exit = if kind == HarnessFailureKind::Disconnected {
            wait_for_exit(&mut self.child, Duration::from_millis(250))
                .ok()
                .map(exit_diagnostic)
        } else {
            self.child.try_wait().ok().flatten().map(exit_diagnostic)
        };
        if exit.is_some()
            && matches!(
                kind,
                HarnessFailureKind::Deadline | HarnessFailureKind::Disconnected
            )
        {
            kind = HarnessFailureKind::ProcessExited;
        }
        let mut failure = HarnessStageFailure::new(stage, Some(self.node_index), kind);
        failure.exit = exit;
        failure.stderr = stderr_diagnostic(&self.stderr_path);
        HarnessError::Stage(Box::new(failure))
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn stop_bounded(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            if let Some(stdin) = self.stdin.as_mut() {
                let _ = write_json_line(stdin, &QualificationNodeCommand::Shutdown);
            }
            let _ = self.recv(HarnessStage::Cleanup, Duration::from_secs(2));
            if wait_for_exit(&mut self.child, Duration::from_secs(3)).is_err() {
                let _ = self.child.kill();
                let _ = wait_for_exit(&mut self.child, PROCESS_STOP_TIMEOUT);
            }
        }
        self.stdin.take();
        self.join_reader_bounded();
    }

    fn join_reader_bounded(&mut self) {
        if self
            .reader_done
            .recv_timeout(Duration::from_secs(1))
            .is_ok()
        {
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        } else {
            self.reader.take();
        }
    }
}

fn stderr_diagnostic(path: &Path) -> Option<StderrDiagnostic> {
    let mut file = File::open(path).ok()?;
    let total_bytes = file.metadata().ok()?.len();
    let start = total_bytes.saturating_sub(MAX_FAILURE_STDERR_BYTES as u64);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut captured = Vec::with_capacity(MAX_FAILURE_STDERR_BYTES);
    file.take(MAX_FAILURE_STDERR_BYTES as u64)
        .read_to_end(&mut captured)
        .ok()?;
    let line_codes = captured
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .take(MAX_FAILURE_STDERR_LINES)
        .map(|line| {
            if line == b"qualification node failed" {
                StderrLineCode::QualificationNodeFailed
            } else {
                StderrLineCode::Redacted
            }
        })
        .collect();
    Some(StderrDiagnostic {
        total_bytes,
        captured_bytes: captured.len(),
        truncated: start > 0,
        line_codes,
    })
}

fn exit_diagnostic(status: std::process::ExitStatus) -> ExitDiagnostic {
    ExitDiagnostic {
        success: status.success(),
        code: status.code(),
        signal: status.signal(),
    }
}

fn terminate_failed_spawn(child: &mut Child) {
    let _ = child.kill();
    let _ = wait_for_exit(child, PROCESS_STOP_TIMEOUT);
}

impl Drop for ChildNode {
    fn drop(&mut self) {
        self.stop_bounded();
    }
}

fn wait_for_exit(
    child: &mut Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus, HarnessFailureKind> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|_| HarnessFailureKind::Io)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(HarnessFailureKind::Deadline);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn child_processes_gone(pids: &[u32], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if pids
            .iter()
            .all(|pid| !PathBuf::from(format!("/proc/{pid}")).exists())
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(
            Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

const CONFIGURATION_DIGEST_DOMAIN: &str = "opc-session-ha/configuration-set/v1";
const FAULT_SCHEDULE_DIGEST_DOMAIN: &str = "opc-session-ha/fault-schedule-set/v1";
const STORAGE_IDENTITY_DIGEST_DOMAIN: &str = "opc-session-ha/storage-identity/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalConfigurationManifest {
    schema_version: String,
    node_schema_version: u16,
    member_count: usize,
    cluster_id: String,
    configuration_generation: String,
    configuration_epoch: u64,
    backend_namespace: String,
    workload_schedule_sha256: String,
    operation_timeout_millis: u64,
    members: Vec<QualificationMember>,
    nodes: Vec<CanonicalNodePaths>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalNodePaths {
    node_index: usize,
    database_relative_path: String,
    snapshot_relative_path: String,
}

impl CanonicalConfigurationManifest {
    fn new(
        member_count: usize,
        workload_schedule_sha256: &str,
        addresses: &[SocketAddr],
    ) -> Result<Self, HarnessError> {
        if addresses.len() != member_count || !matches!(member_count, 3 | 5) {
            return Err(HarnessError::Evidence);
        }
        let members = addresses
            .iter()
            .enumerate()
            .map(|(node_index, address)| QualificationMember {
                node_index,
                replica_id: format!("node-{node_index}"),
                endpoint_host: format!("node-{node_index}.qualification.invalid"),
                endpoint_port: address.port(),
                dial_addr: Some(*address),
                tls_identity: format!(
                    "spiffe://qualification.invalid/tenant/test/ns/test/sa/session/nf/test/instance/{node_index}"
                ),
                failure_domain: format!("qualification-zone-{node_index}"),
                backing_identity: format!("qualification-disk-{node_index}"),
            })
            .collect();
        let nodes = (0..member_count)
            .map(|node_index| CanonicalNodePaths {
                node_index,
                database_relative_path: format!("node-{node_index}/session.sqlite"),
                snapshot_relative_path: format!("node-{node_index}/snapshots"),
            })
            .collect();
        Ok(Self {
            schema_version: "opc-session-ha-configuration-manifest/v1".to_owned(),
            node_schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
            member_count,
            cluster_id: format!("qualification-{member_count}-node"),
            configuration_generation: "v1".to_owned(),
            configuration_epoch: 1,
            backend_namespace: format!("qualification-{member_count}-node"),
            workload_schedule_sha256: workload_schedule_sha256.to_owned(),
            operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
            members,
            nodes,
        })
    }

    fn runtime_configs(&self, root: &Path) -> Result<Vec<QualificationNodeConfig>, HarnessError> {
        if self.schema_version != "opc-session-ha-configuration-manifest/v1"
            || self.node_schema_version != QUALIFICATION_NODE_SCHEMA_VERSION
            || !matches!(self.member_count, 3 | 5)
            || self.members.len() != self.member_count
            || self.nodes.len() != self.member_count
            || !root.is_absolute()
        {
            return Err(HarnessError::Evidence);
        }
        let mut configs = Vec::with_capacity(self.member_count);
        for (expected_index, paths) in self.nodes.iter().enumerate() {
            let expected_database = format!("node-{expected_index}/session.sqlite");
            let expected_snapshots = format!("node-{expected_index}/snapshots");
            if paths.node_index != expected_index
                || paths.database_relative_path != expected_database
                || paths.snapshot_relative_path != expected_snapshots
            {
                return Err(HarnessError::Evidence);
            }
            let config = QualificationNodeConfig {
                schema_version: self.node_schema_version,
                node_index: expected_index,
                cluster_id: self.cluster_id.clone(),
                configuration_generation: self.configuration_generation.clone(),
                configuration_epoch: self.configuration_epoch,
                backend_namespace: self.backend_namespace.clone(),
                workload_schedule_sha256: self.workload_schedule_sha256.clone(),
                members: self.members.clone(),
                workspace_directory: root.to_path_buf(),
                database_path: root.join(&paths.database_relative_path),
                snapshot_directory: root.join(&paths.snapshot_relative_path),
                operation_timeout_millis: self.operation_timeout_millis,
                transport: QualificationTransportConfig::LoopbackPlaintextTestOnly,
            };
            config.validate().map_err(|_| HarnessError::Evidence)?;
            configs.push(config);
        }
        Ok(configs)
    }

    fn from_runtime_configs(
        configs: &[QualificationNodeConfig],
        root: &Path,
    ) -> Result<Self, HarnessError> {
        let Some(first) = configs.first() else {
            return Err(HarnessError::Evidence);
        };
        if !matches!(configs.len(), 3 | 5)
            || !root.is_absolute()
            || first.workspace_directory != root
        {
            return Err(HarnessError::Evidence);
        }
        let nodes = configs
            .iter()
            .enumerate()
            .map(|(node_index, config)| {
                config.validate().map_err(|_| HarnessError::Evidence)?;
                let database_relative_path = format!("node-{node_index}/session.sqlite");
                let snapshot_relative_path = format!("node-{node_index}/snapshots");
                if config.node_index != node_index
                    || config.workspace_directory != root
                    || config.database_path != root.join(&database_relative_path)
                    || config.snapshot_directory != root.join(&snapshot_relative_path)
                    || config.schema_version != first.schema_version
                    || config.cluster_id != first.cluster_id
                    || config.configuration_generation != first.configuration_generation
                    || config.configuration_epoch != first.configuration_epoch
                    || config.backend_namespace != first.backend_namespace
                    || config.workload_schedule_sha256 != first.workload_schedule_sha256
                    || config.members != first.members
                    || config.operation_timeout_millis != first.operation_timeout_millis
                {
                    return Err(HarnessError::Evidence);
                }
                Ok(CanonicalNodePaths {
                    node_index,
                    database_relative_path,
                    snapshot_relative_path,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = Self {
            schema_version: "opc-session-ha-configuration-manifest/v1".to_owned(),
            node_schema_version: first.schema_version,
            member_count: configs.len(),
            cluster_id: first.cluster_id.clone(),
            configuration_generation: first.configuration_generation.clone(),
            configuration_epoch: first.configuration_epoch,
            backend_namespace: first.backend_namespace.clone(),
            workload_schedule_sha256: first.workload_schedule_sha256.clone(),
            operation_timeout_millis: first.operation_timeout_millis,
            members: first.members.clone(),
            nodes,
        };
        if manifest.runtime_configs(root)? != configs {
            return Err(HarnessError::Evidence);
        }
        Ok(manifest)
    }

    fn storage_identity_sha256(&self) -> Result<Vec<String>, HarnessError> {
        self.nodes
            .iter()
            .zip(&self.members)
            .map(|(paths, member)| {
                domain_separated_sha256(
                    STORAGE_IDENTITY_DIGEST_DOMAIN,
                    [
                        member.backing_identity.as_bytes(),
                        paths.database_relative_path.as_bytes(),
                    ],
                )
            })
            .collect()
    }
}

fn write_configuration_manifest(
    path: &Path,
    manifest: &CanonicalConfigurationManifest,
) -> Result<String, HarnessError> {
    let value = serde_json::to_value(manifest).map_err(|_| HarnessError::Evidence)?;
    write_private_json(path, &value)?;
    let encoded = fs::read(path)?;
    domain_separated_sha256(CONFIGURATION_DIGEST_DOMAIN, [&encoded])
}

fn sorted_readiness(readiness: &HashMap<usize, ReadinessDiagnostic>) -> Vec<ReadinessDiagnostic> {
    let mut readiness = readiness.values().cloned().collect::<Vec<_>>();
    readiness.sort_by_key(|diagnostic| diagnostic.node_index);
    readiness
}

fn readiness_map(readiness: &[ReadinessDiagnostic]) -> HashMap<usize, ReadinessDiagnostic> {
    readiness
        .iter()
        .cloned()
        .map(|diagnostic| (diagnostic.node_index, diagnostic))
        .collect()
}

fn coherent_leader_snapshot(
    readiness: &[ReadinessDiagnostic],
    member_count: usize,
) -> Option<(u64, u64)> {
    if readiness.len() != member_count
        || readiness
            .iter()
            .map(|diagnostic| diagnostic.node_index)
            .collect::<BTreeSet<_>>()
            .len()
            != member_count
        || readiness
            .iter()
            .map(|diagnostic| diagnostic.node_id)
            .collect::<BTreeSet<_>>()
            .len()
            != member_count
    {
        return None;
    }
    let first = readiness.first()?;
    let leader_id = first.leader_id?;
    let term = first.term;
    if leader_id == 0
        || term == 0
        || !readiness.iter().all(|diagnostic| {
            diagnostic.ready
                && diagnostic.reason_code == QualificationReadinessCode::Ready
                && diagnostic.node_id > 0
                && diagnostic.term == term
                && diagnostic.leader_id == Some(leader_id)
        })
        || readiness
            .iter()
            .filter(|diagnostic| diagnostic.node_id == leader_id)
            .count()
            != 1
    {
        return None;
    }
    Some((leader_id, term))
}

fn with_readiness(
    error: HarnessError,
    readiness: &HashMap<usize, ReadinessDiagnostic>,
) -> HarnessError {
    match error {
        HarnessError::Stage(mut failure) => {
            failure.readiness = sorted_readiness(readiness);
            HarnessError::Stage(failure)
        }
        other => other,
    }
}

fn readiness_deadline(
    stage: HarnessStage,
    readiness: &HashMap<usize, ReadinessDiagnostic>,
) -> HarnessError {
    HarnessError::Stage(Box::new(
        HarnessStageFailure::new(stage, None, HarnessFailureKind::ReadinessNotReady)
            .with_readiness(sorted_readiness(readiness)),
    ))
}

struct Fleet {
    _workspace: TempDir,
    root: PathBuf,
    binary: PathBuf,
    configs: Vec<PathBuf>,
    databases: Vec<PathBuf>,
    stderr_logs: Vec<PathBuf>,
    configuration_manifest_path: PathBuf,
    configuration_manifest: Option<CanonicalConfigurationManifest>,
    configuration_sha256: Option<String>,
    last_readiness: Vec<ReadinessDiagnostic>,
    nodes: Vec<Option<ChildNode>>,
}

impl Fleet {
    fn start(member_count: usize, schedule_sha256: &str) -> Result<Self, HarnessError> {
        if !matches!(member_count, 3 | 5) {
            return Err(HarnessError::Protocol);
        }
        let workspace = tempfile::tempdir().map_err(HarnessError::from)?;
        let root = workspace.path().to_path_buf();
        let mut configs = Vec::with_capacity(member_count);
        let mut databases = Vec::with_capacity(member_count);
        let mut stderr_logs = Vec::with_capacity(member_count);
        for node_index in 0..member_count {
            let node_directory = root.join(format!("node-{node_index}"));
            fs::create_dir(&node_directory)?;
            configs.push(node_directory.join("config.json"));
            databases.push(node_directory.join("session.sqlite"));
            stderr_logs.push(node_directory.join("stderr.log"));
        }
        if databases.iter().collect::<BTreeSet<_>>().len() != member_count {
            return Err(HarnessError::Evidence);
        }
        let binary = PathBuf::from(env!("CARGO_BIN_EXE_opc-session-quorum-node"));
        let configuration_manifest_path = root.join("configuration-manifest.json");
        let mut fleet = Self {
            _workspace: workspace,
            root,
            binary,
            configs,
            databases,
            stderr_logs,
            configuration_manifest_path,
            configuration_manifest: None,
            configuration_sha256: None,
            last_readiness: Vec::new(),
            nodes: (0..member_count).map(|_| None).collect(),
        };
        let mut addresses = Vec::with_capacity(member_count);
        for node_index in 0..member_count {
            addresses.push(fleet.spawn_node_bound(
                node_index,
                "127.0.0.1:0".parse().map_err(|_| HarnessError::Protocol)?,
                HarnessStage::InitialBind,
            )?);
        }
        let manifest =
            CanonicalConfigurationManifest::new(member_count, schedule_sha256, &addresses)?;
        let configuration_sha256 =
            write_configuration_manifest(&fleet.configuration_manifest_path, &manifest)?;
        let retained_manifest: CanonicalConfigurationManifest =
            serde_json::from_slice(&fs::read(&fleet.configuration_manifest_path)?)
                .map_err(|_| HarnessError::Evidence)?;
        if retained_manifest != manifest {
            return Err(HarnessError::Evidence);
        }
        let runtime_configs = retained_manifest.runtime_configs(&fleet.root)?;
        if CanonicalConfigurationManifest::from_runtime_configs(&runtime_configs, &fleet.root)?
            != retained_manifest
        {
            return Err(HarnessError::Evidence);
        }
        for (path, config) in fleet.configs.iter().zip(&runtime_configs) {
            let value = serde_json::to_value(config).map_err(|_| HarnessError::Evidence)?;
            write_private_json(path, &value)?;
            let decoded: QualificationNodeConfig =
                serde_json::from_slice(&fs::read(path)?).map_err(|_| HarnessError::Evidence)?;
            if decoded != *config {
                return Err(HarnessError::Evidence);
            }
        }
        fleet.configuration_manifest = Some(retained_manifest);
        fleet.configuration_sha256 = Some(configuration_sha256);
        fleet.configure_all(HarnessStage::InitialConfigure)?;
        fleet.initialize_all(HarnessStage::InitialInitialize)?;
        fleet.wait_ready(
            &(0..member_count).collect::<Vec<_>>(),
            HarnessStage::InitialReadiness,
            FLEET_READY_TIMEOUT,
        )?;
        Ok(fleet)
    }

    fn spawn_node_bound(
        &mut self,
        node_index: usize,
        bind_addr: SocketAddr,
        stage: HarnessStage,
    ) -> Result<SocketAddr, HarnessError> {
        if self.nodes[node_index].is_some() {
            return Err(stage_error(
                stage,
                Some(node_index),
                HarnessFailureKind::Protocol,
            ));
        }
        let (node, actual_addr) = ChildNode::spawn_bound(
            &self.binary,
            &self.configs[node_index],
            &self.stderr_logs[node_index],
            node_index,
            bind_addr,
            stage,
        )?;
        self.nodes[node_index] = Some(node);
        Ok(actual_addr)
    }

    fn configure_all(&mut self, stage: HarnessStage) -> Result<(), HarnessError> {
        for node_index in 0..self.nodes.len() {
            self.nodes[node_index]
                .as_mut()
                .ok_or_else(|| {
                    stage_error(stage, Some(node_index), HarnessFailureKind::Disconnected)
                })?
                .send(&QualificationNodeCommand::Configure, stage)?;
        }
        for node_index in 0..self.nodes.len() {
            let node = self.nodes[node_index].as_mut().ok_or_else(|| {
                stage_error(stage, Some(node_index), HarnessFailureKind::Disconnected)
            })?;
            if !matches!(node.recv(stage, CHILD_START_TIMEOUT)?, QualificationNodeReply::Started { node_index: actual } if actual == node_index)
            {
                return Err(node.failure(stage, HarnessFailureKind::Protocol));
            }
        }
        Ok(())
    }

    fn configure_one(
        &mut self,
        node_index: usize,
        stage: HarnessStage,
    ) -> Result<(), HarnessError> {
        self.nodes[node_index]
            .as_mut()
            .ok_or_else(|| stage_error(stage, Some(node_index), HarnessFailureKind::Disconnected))?
            .configure(stage)
    }

    fn initialize_all(&mut self, stage: HarnessStage) -> Result<(), HarnessError> {
        for node_index in 0..self.nodes.len() {
            self.nodes[node_index]
                .as_mut()
                .ok_or_else(|| {
                    stage_error(stage, Some(node_index), HarnessFailureKind::Disconnected)
                })?
                .send(&QualificationNodeCommand::Initialize, stage)?;
        }
        for node_index in 0..self.nodes.len() {
            let node = self.nodes[node_index].as_mut().ok_or_else(|| {
                stage_error(stage, Some(node_index), HarnessFailureKind::Disconnected)
            })?;
            if !matches!(
                node.recv(stage, CHILD_REPLY_TIMEOUT)?,
                QualificationNodeReply::Initialized
            ) {
                return Err(node.failure(stage, HarnessFailureKind::Protocol));
            }
        }
        Ok(())
    }

    fn initialize_one(
        &mut self,
        node_index: usize,
        stage: HarnessStage,
    ) -> Result<(), HarnessError> {
        let node = self.nodes[node_index].as_mut().ok_or_else(|| {
            stage_error(stage, Some(node_index), HarnessFailureKind::Disconnected)
        })?;
        if !matches!(
            node.invoke(&QualificationNodeCommand::Initialize, stage)?,
            QualificationNodeReply::Initialized
        ) {
            return Err(node.failure(stage, HarnessFailureKind::Protocol));
        }
        Ok(())
    }

    fn wait_ready(
        &mut self,
        node_indices: &[usize],
        stage: HarnessStage,
        timeout: Duration,
    ) -> Result<(), HarnessError> {
        let deadline = Instant::now() + timeout;
        let mut last_readiness = HashMap::new();
        loop {
            for node_index in node_indices {
                let result = self.nodes[*node_index]
                    .as_mut()
                    .ok_or_else(|| {
                        stage_error(stage, Some(*node_index), HarnessFailureKind::Disconnected)
                    })?
                    .send(&QualificationNodeCommand::Probe, stage);
                if let Err(error) = result {
                    return Err(with_readiness(error, &last_readiness));
                }
            }
            let mut ready = true;
            for node_index in node_indices {
                let now = Instant::now();
                if now >= deadline {
                    return Err(readiness_deadline(stage, &last_readiness));
                }
                let receive_timeout = READINESS_REPLY_TIMEOUT.min(deadline.duration_since(now));
                let reply = self.nodes[*node_index].as_ref().ok_or_else(|| {
                    stage_error(stage, Some(*node_index), HarnessFailureKind::Disconnected)
                });
                let node = match reply {
                    Ok(_) => self.nodes[*node_index].as_mut().ok_or_else(|| {
                        stage_error(stage, Some(*node_index), HarnessFailureKind::Disconnected)
                    })?,
                    Err(error) => return Err(with_readiness(error, &last_readiness)),
                };
                let reply = match node.recv(stage, receive_timeout) {
                    Ok(reply) => reply,
                    Err(error) => return Err(with_readiness(error, &last_readiness)),
                };
                match reply {
                    QualificationNodeReply::Readiness {
                        ready: node_ready,
                        reason_code,
                        node_id,
                        term,
                        leader_id,
                        configured_voters,
                        configured_voter_ids: _,
                        fresh_reachable_voters,
                        agreeing_voters,
                        required_quorum,
                        committed_index,
                        applied_index,
                    } => {
                        last_readiness.insert(
                            *node_index,
                            ReadinessDiagnostic {
                                node_index: *node_index,
                                ready: node_ready,
                                reason_code,
                                node_id,
                                term,
                                leader_id,
                                configured_voters,
                                fresh_reachable_voters,
                                agreeing_voters,
                                required_quorum,
                                committed_index,
                                applied_index,
                            },
                        );
                        if configured_voters != self.nodes.len()
                            || required_quorum != (self.nodes.len() / 2) + 1
                            || (node_ready
                                && (fresh_reachable_voters < required_quorum
                                    || agreeing_voters < required_quorum))
                        {
                            return Err(HarnessError::Stage(Box::new(
                                HarnessStageFailure::new(
                                    stage,
                                    Some(*node_index),
                                    HarnessFailureKind::Protocol,
                                )
                                .with_readiness(sorted_readiness(&last_readiness)),
                            )));
                        }
                        ready &= node_ready && reason_code == QualificationReadinessCode::Ready;
                    }
                    _ => {
                        return Err(HarnessError::Stage(Box::new(
                            HarnessStageFailure::new(
                                stage,
                                Some(*node_index),
                                HarnessFailureKind::Protocol,
                            )
                            .with_readiness(sorted_readiness(&last_readiness)),
                        )));
                    }
                }
            }
            if ready {
                self.last_readiness = sorted_readiness(&last_readiness);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(readiness_deadline(stage, &last_readiness));
            }
            thread::sleep(
                Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn probe_readiness_round(
        &mut self,
        stage: HarnessStage,
        deadline: Instant,
    ) -> Result<Vec<ReadinessDiagnostic>, HarnessError> {
        let node_indices = (0..self.nodes.len()).collect::<Vec<_>>();
        self.probe_readiness_round_for(&node_indices, stage, deadline)
    }

    fn probe_readiness_round_for(
        &mut self,
        node_indices: &[usize],
        stage: HarnessStage,
        deadline: Instant,
    ) -> Result<Vec<ReadinessDiagnostic>, HarnessError> {
        let mut readiness = HashMap::new();
        for node_index in node_indices {
            if Instant::now() >= deadline {
                return Err(readiness_deadline(stage, &readiness));
            }
            let result = self.nodes[*node_index]
                .as_mut()
                .ok_or_else(|| {
                    stage_error(stage, Some(*node_index), HarnessFailureKind::Disconnected)
                })?
                .send(&QualificationNodeCommand::Probe, stage);
            if let Err(error) = result {
                return Err(with_readiness(error, &readiness));
            }
        }
        for node_index in node_indices.iter().copied() {
            let now = Instant::now();
            if now >= deadline {
                return Err(readiness_deadline(stage, &readiness));
            }
            let timeout = READINESS_REPLY_TIMEOUT.min(deadline.duration_since(now));
            let node = self.nodes[node_index].as_mut().ok_or_else(|| {
                stage_error(stage, Some(node_index), HarnessFailureKind::Disconnected)
            })?;
            let reply = match node.recv(stage, timeout) {
                Ok(reply) => reply,
                Err(error) => return Err(with_readiness(error, &readiness)),
            };
            let QualificationNodeReply::Readiness {
                ready,
                reason_code,
                node_id,
                term,
                leader_id,
                configured_voters,
                configured_voter_ids: _,
                fresh_reachable_voters,
                agreeing_voters,
                required_quorum,
                committed_index,
                applied_index,
            } = reply
            else {
                return Err(HarnessError::Stage(Box::new(
                    HarnessStageFailure::new(stage, Some(node_index), HarnessFailureKind::Protocol)
                        .with_readiness(sorted_readiness(&readiness)),
                )));
            };
            readiness.insert(
                node_index,
                ReadinessDiagnostic {
                    node_index,
                    ready,
                    reason_code,
                    node_id,
                    term,
                    leader_id,
                    configured_voters,
                    fresh_reachable_voters,
                    agreeing_voters,
                    required_quorum,
                    committed_index,
                    applied_index,
                },
            );
            if configured_voters != self.nodes.len()
                || required_quorum != (self.nodes.len() / 2) + 1
                || (ready
                    && (fresh_reachable_voters < required_quorum
                        || agreeing_voters < required_quorum))
            {
                return Err(HarnessError::Stage(Box::new(
                    HarnessStageFailure::new(stage, Some(node_index), HarnessFailureKind::Protocol)
                        .with_readiness(sorted_readiness(&readiness)),
                )));
            }
        }
        Ok(sorted_readiness(&readiness))
    }

    fn invoke(
        &mut self,
        node_index: usize,
        command: &QualificationNodeCommand,
    ) -> Result<QualificationNodeReply, HarnessError> {
        self.nodes[node_index]
            .as_mut()
            .ok_or_else(|| {
                stage_error(
                    HarnessStage::Operation,
                    Some(node_index),
                    HarnessFailureKind::Disconnected,
                )
            })?
            .invoke(command, HarnessStage::Operation)
    }

    fn observe_stable_follower(
        &mut self,
        timeout: Duration,
    ) -> Result<ReadinessDiagnostic, HarnessError> {
        let deadline = Instant::now() + timeout;
        let mut last_readiness;
        loop {
            let observed =
                self.probe_readiness_round(HarnessStage::FollowerObservation, deadline)?;
            last_readiness = observed.clone();
            if let Some((leader_id, term)) = coherent_leader_snapshot(&observed, self.nodes.len()) {
                let candidate = FAULT_TARGET_CANDIDATES.iter().find_map(|node_index| {
                    observed
                        .iter()
                        .find(|diagnostic| diagnostic.node_index == *node_index)
                        .filter(|diagnostic| diagnostic.node_id != leader_id)
                        .cloned()
                });
                if let Some(candidate) = candidate {
                    let confirmed =
                        self.probe_readiness_round(HarnessStage::FollowerObservation, deadline)?;
                    last_readiness = confirmed.clone();
                    if coherent_leader_snapshot(&confirmed, self.nodes.len())
                        == Some((leader_id, term))
                    {
                        if let Some(target) = confirmed
                            .iter()
                            .find(|diagnostic| {
                                diagnostic.node_index == candidate.node_index
                                    && diagnostic.node_id == candidate.node_id
                                    && diagnostic.node_id != leader_id
                            })
                            .cloned()
                        {
                            self.last_readiness = confirmed;
                            return Ok(target);
                        }
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(readiness_deadline(
                    HarnessStage::FollowerObservation,
                    &readiness_map(&last_readiness),
                ));
            }
            thread::sleep(
                Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn observe_stable_leader(
        &mut self,
        timeout: Duration,
    ) -> Result<ReadinessDiagnostic, HarnessError> {
        let deadline = Instant::now() + timeout;
        let mut last_readiness;
        loop {
            let observed = self.probe_readiness_round(HarnessStage::LeaderObservation, deadline)?;
            last_readiness = observed.clone();
            if let Some((leader_id, term)) = coherent_leader_snapshot(&observed, self.nodes.len()) {
                let confirmed =
                    self.probe_readiness_round(HarnessStage::LeaderObservation, deadline)?;
                last_readiness = confirmed.clone();
                if coherent_leader_snapshot(&confirmed, self.nodes.len()) == Some((leader_id, term))
                {
                    if let Some(leader) = confirmed
                        .iter()
                        .find(|diagnostic| diagnostic.node_id == leader_id)
                        .cloned()
                    {
                        self.last_readiness = confirmed;
                        return Ok(leader);
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(readiness_deadline(
                    HarnessStage::LeaderObservation,
                    &readiness_map(&last_readiness),
                ));
            }
            thread::sleep(
                Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn observe_stable_replacement_leader(
        &mut self,
        survivors: &[usize],
        old_leader_id: u64,
        old_term: u64,
        timeout: Duration,
    ) -> Result<ReadinessDiagnostic, HarnessError> {
        let deadline = Instant::now() + timeout;
        let mut last_readiness;
        loop {
            let observed = self.probe_readiness_round_for(
                survivors,
                HarnessStage::LeaderFailoverReadiness,
                deadline,
            )?;
            last_readiness = observed.clone();
            if let Some((leader_id, term)) = coherent_leader_snapshot(&observed, survivors.len()) {
                if leader_id != old_leader_id && term > old_term {
                    let confirmed = self.probe_readiness_round_for(
                        survivors,
                        HarnessStage::LeaderFailoverReadiness,
                        deadline,
                    )?;
                    last_readiness = confirmed.clone();
                    if coherent_leader_snapshot(&confirmed, survivors.len())
                        == Some((leader_id, term))
                    {
                        if let Some(leader) = confirmed
                            .iter()
                            .find(|diagnostic| diagnostic.node_id == leader_id)
                            .cloned()
                        {
                            self.last_readiness = confirmed;
                            return Ok(leader);
                        }
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(readiness_deadline(
                    HarnessStage::LeaderFailoverReadiness,
                    &readiness_map(&last_readiness),
                ));
            }
            thread::sleep(
                Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn stop_unclean(&mut self, node_index: usize) -> Result<(), HarnessError> {
        self.stop_unclean_at(node_index, HarnessStage::StopFollower)
    }

    fn stop_unclean_at(
        &mut self,
        node_index: usize,
        stage: HarnessStage,
    ) -> Result<(), HarnessError> {
        self.nodes[node_index]
            .take()
            .ok_or_else(|| stage_error(stage, Some(node_index), HarnessFailureKind::Disconnected))?
            .kill_unclean(stage)
    }

    fn restart(&mut self, node_index: usize) -> Result<(), HarnessError> {
        self.restart_at(
            node_index,
            HarnessStage::RestartBind,
            HarnessStage::RestartConfigure,
            HarnessStage::RestartInitialize,
            HarnessStage::RestartReadiness,
        )
    }

    fn restart_leader(&mut self, node_index: usize) -> Result<(), HarnessError> {
        self.restart_at(
            node_index,
            HarnessStage::LeaderRestartBind,
            HarnessStage::LeaderRestartConfigure,
            HarnessStage::LeaderRestartInitialize,
            HarnessStage::LeaderRestartReadiness,
        )
    }

    fn restart_at(
        &mut self,
        node_index: usize,
        bind_stage: HarnessStage,
        configure_stage: HarnessStage,
        initialize_stage: HarnessStage,
        readiness_stage: HarnessStage,
    ) -> Result<(), HarnessError> {
        let bind_addr = self
            .configuration_manifest
            .as_ref()
            .and_then(|manifest| manifest.members.get(node_index))
            .and_then(|member| member.dial_addr)
            .ok_or(HarnessError::Evidence)?;
        let actual_addr = self.spawn_node_bound(node_index, bind_addr, bind_stage)?;
        if actual_addr != bind_addr {
            return Err(stage_error(
                bind_stage,
                Some(node_index),
                HarnessFailureKind::Protocol,
            ));
        }
        self.configure_one(node_index, configure_stage)?;
        self.initialize_one(node_index, initialize_stage)?;
        self.wait_ready(
            &(0..self.nodes.len()).collect::<Vec<_>>(),
            readiness_stage,
            FLEET_READY_TIMEOUT,
        )
    }

    fn configuration_sha256(&self) -> Result<String, HarnessError> {
        self.configuration_sha256
            .clone()
            .ok_or(HarnessError::Evidence)
    }

    fn storage_identity_sha256(&self) -> Result<Vec<String>, HarnessError> {
        let identities = self
            .configuration_manifest
            .as_ref()
            .ok_or(HarnessError::Evidence)?
            .storage_identity_sha256()?;
        if identities.iter().collect::<BTreeSet<_>>().len() != self.databases.len() {
            return Err(HarnessError::Evidence);
        }
        Ok(identities)
    }

    fn assert_distinct_encrypted_storage(&self) -> Result<(), HarnessError> {
        let canaries = [
            b"qualification-value-1".as_slice(),
            b"qualification-value-2".as_slice(),
            b"qualification-value-3".as_slice(),
            b"qualification-stale-value".as_slice(),
        ];
        let mut identities = BTreeSet::new();
        for (node_index, database) in self.databases.iter().enumerate() {
            let canonical = fs::canonicalize(database)?;
            if !canonical.starts_with(&self.root) || !identities.insert(canonical) {
                return Err(HarnessError::Evidence);
            }
            let mut pending = vec![self.root.join(format!("node-{node_index}"))];
            let mut examined_files = 0_usize;
            while let Some(path) = pending.pop() {
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    return Err(HarnessError::Evidence);
                }
                if metadata.is_dir() {
                    for entry in fs::read_dir(path)? {
                        pending.push(entry?.path());
                    }
                    continue;
                }
                if !metadata.is_file()
                    || metadata.len() > MAX_DATABASE_EVIDENCE_BYTES
                    || examined_files >= 1024
                {
                    return Err(HarnessError::Evidence);
                }
                examined_files += 1;
                let bytes = fs::read(path)?;
                for canary in canaries {
                    if bytes.windows(canary.len()).any(|window| window == canary) {
                        return Err(HarnessError::Evidence);
                    }
                }
            }
        }
        Ok(())
    }

    fn shutdown_all(&mut self) {
        for node in &mut self.nodes {
            if let Some(mut child) = node.take() {
                child.stop_bounded();
            }
        }
    }

    fn pids(&self) -> Vec<u32> {
        self.nodes.iter().flatten().map(ChildNode::pid).collect()
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        for node in self.nodes.iter_mut().flatten() {
            node.stop_bounded();
        }
    }
}

struct HistoryWriter {
    file: File,
    epoch: Instant,
    history: QualificationSequentialHistoryBuilder,
}

impl HistoryWriter {
    fn new(path: &Path, schedule: &[ScheduledInvocation]) -> Result<Self, HarnessError> {
        Ok(Self {
            file: open_private_file(path, false)?,
            epoch: Instant::now(),
            history: QualificationSequentialHistoryBuilder::new(schedule)
                .map_err(|_| HarnessError::Evidence)?,
        })
    }

    fn now_ns(&self) -> Result<u64, HarnessError> {
        u64::try_from(self.epoch.elapsed().as_nanos()).map_err(|_| HarnessError::Evidence)
    }

    fn record(
        &mut self,
        scheduled: &ScheduledInvocation,
        started_ns: u64,
        completed_ns: u64,
        reply: Option<&QualificationNodeReply>,
    ) -> Result<(), HarnessError> {
        let observation = self
            .history
            .observe(scheduled, started_ns, completed_ns, reply)
            .map_err(|_| HarnessError::Evidence)?;
        serde_json::to_writer(&mut self.file, &observation.history)
            .map_err(|_| HarnessError::Evidence)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }
}

fn invoke_and_record(
    fleet: &mut Fleet,
    history: &mut HistoryWriter,
    scheduled: &ScheduledInvocation,
) -> Result<QualificationNodeReply, HarnessError> {
    let started_ns = at_stage(history.now_ns(), HarnessStage::HistoryEvidence)?;
    let node_index = at_stage(
        scheduled.member_index().map_err(|_| HarnessError::Protocol),
        HarnessStage::HistoryEvidence,
    )?;
    let reply = fleet.invoke(node_index, &scheduled.command());
    let completed_ns = at_stage(history.now_ns(), HarnessStage::HistoryEvidence)?;
    at_stage(
        history.record(scheduled, started_ns, completed_ns, reply.as_ref().ok()),
        HarnessStage::HistoryEvidence,
    )?;
    reply
}

fn assert_applied(reply: QualificationNodeReply, generation: u64) -> Result<(), HarnessError> {
    match reply {
        QualificationNodeReply::CompareAndSet {
            applied: true,
            current_generation: Some(current),
        } if current == generation => Ok(()),
        _ => Err(HarnessError::Protocol),
    }
}

fn acquired_fence(reply: QualificationNodeReply) -> Result<u64, HarnessError> {
    match reply {
        QualificationNodeReply::LeaseAcquired { fence } if fence > 0 => Ok(fence),
        _ => Err(HarnessError::Protocol),
    }
}

fn assert_generation(reply: QualificationNodeReply, generation: u64) -> Result<(), HarnessError> {
    match reply {
        QualificationNodeReply::Record {
            present: true,
            generation: Some(current),
            owner_sha256: Some(_),
            fence: Some(_),
            value_sha256: Some(_),
        } if current == generation => Ok(()),
        _ => Err(HarnessError::Protocol),
    }
}

fn run_foundation(member_count: usize) -> Result<(), HarnessError> {
    let started_at = OffsetDateTime::now_utc();
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository = manifest_directory.join("../..");
    let profile_path = manifest_directory.join("qualification/v6/session-ha-profile.json");
    let profile_schema_path =
        manifest_directory.join("qualification/v6/session-ha-profile.schema.json");
    let evidence_schema_path =
        manifest_directory.join("qualification/v6/session-ha-evidence.schema.json");
    let schedule_schema_path =
        manifest_directory.join("qualification/v1/session-ha-schedule.schema.json");
    let history_schema_path =
        manifest_directory.join("qualification/v1/session-ha-history.schema.json");
    let checker = repository.join("scripts/check-session-ha-history.py");
    let profile: SessionHaQualificationProfile =
        serde_json::from_str(SESSION_HA_PROFILE_JSON).map_err(|_| HarnessError::Evidence)?;

    let schedule = workload(member_count);
    let artifact_workspace = tempfile::tempdir()?;
    let schedule_path = artifact_workspace.path().join("schedule.jsonl");
    let history_path = artifact_workspace.path().join("history.jsonl");
    let fault_schedule_path = artifact_workspace.path().join("fault-schedule.json");
    let checker_output_path = artifact_workspace.path().join("checker-output.json");
    let evidence_path = artifact_workspace.path().join("evidence.json");
    let schedule_sha256 = write_schedule(&schedule_path, &schedule)?;

    let startup_started = Instant::now();
    let mut fleet = Fleet::start(member_count, &schedule_sha256)?;
    let startup_millis = at_stage(
        duration_millis(startup_started.elapsed()),
        HarnessStage::ThresholdEvidence,
    )?;
    let configuration_sha256 = at_stage(
        fleet.configuration_sha256(),
        HarnessStage::ConfigurationEvidence,
    )?;
    let storage_identity_sha256 = at_stage(
        fleet.storage_identity_sha256(),
        HarnessStage::ConfigurationEvidence,
    )?;
    let mut history = at_stage(
        HistoryWriter::new(&history_path, &schedule),
        HarnessStage::HistoryEvidence,
    )?;

    let expiry_fence = at_stage(
        acquired_fence(invoke_and_record(&mut fleet, &mut history, &schedule[0])?),
        HarnessStage::Operation,
    )?;
    thread::sleep(LEASE_EXPIRY_WAIT);
    let reacquired_expiry_fence = at_stage(
        acquired_fence(invoke_and_record(&mut fleet, &mut history, &schedule[1])?),
        HarnessStage::Operation,
    )?;
    if reacquired_expiry_fence <= expiry_fence {
        return Err(stage_error(
            HarnessStage::Operation,
            None,
            HarnessFailureKind::Protocol,
        ));
    }
    if !matches!(
        invoke_and_record(&mut fleet, &mut history, &schedule[2])?,
        QualificationNodeReply::Released
    ) {
        return Err(stage_error(
            HarnessStage::Operation,
            None,
            HarnessFailureKind::Protocol,
        ));
    }

    let first_session_fence = at_stage(
        acquired_fence(invoke_and_record(&mut fleet, &mut history, &schedule[3])?),
        HarnessStage::Operation,
    )?;
    at_stage(
        assert_applied(
            invoke_and_record(&mut fleet, &mut history, &schedule[4])?,
            1,
        ),
        HarnessStage::Operation,
    )?;
    at_stage(
        assert_generation(
            invoke_and_record(&mut fleet, &mut history, &schedule[5])?,
            1,
        ),
        HarnessStage::Operation,
    )?;

    if !matches!(
        invoke_and_record(&mut fleet, &mut history, &schedule[6])?,
        QualificationNodeReply::Released
    ) {
        return Err(stage_error(
            HarnessStage::Operation,
            None,
            HarnessFailureKind::Protocol,
        ));
    }
    let second_session_fence = at_stage(
        acquired_fence(invoke_and_record(&mut fleet, &mut history, &schedule[7])?),
        HarnessStage::Operation,
    )?;
    if second_session_fence <= first_session_fence {
        return Err(stage_error(
            HarnessStage::Operation,
            None,
            HarnessFailureKind::Protocol,
        ));
    }
    at_stage(
        assert_applied(
            invoke_and_record(&mut fleet, &mut history, &schedule[8])?,
            2,
        ),
        HarnessStage::Operation,
    )?;
    match invoke_and_record(&mut fleet, &mut history, &schedule[9])? {
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::MutationRejected,
        } => {}
        _ => {
            return Err(stage_error(
                HarnessStage::Operation,
                None,
                HarnessFailureKind::Protocol,
            ));
        }
    }
    at_stage(
        assert_generation(
            invoke_and_record(&mut fleet, &mut history, &schedule[10])?,
            2,
        ),
        HarnessStage::Operation,
    )?;

    let observed_follower = fleet.observe_stable_follower(FLEET_READY_TIMEOUT)?;
    let fault_target_node_index = observed_follower.node_index;
    let fault_target_process = format!("node-{fault_target_node_index}");
    let fault_schedule = json!({
        "schema_version": "opc-session-ha-fault-schedule/v1",
        "topology_members": member_count,
        "faults": [
            {
                "sequence": 1,
                "kind": "process_stop",
                "target_process": fault_target_process.clone(),
                "target_role": "follower",
                "observed_node_id": observed_follower.node_id,
                "observed_leader_id": observed_follower.leader_id,
                "observed_term": observed_follower.term,
                "bounded": true
            },
            {
                "sequence": 2,
                "kind": "process_restart",
                "target_process": fault_target_process.clone(),
                "target_role": "follower",
                "observed_node_id": observed_follower.node_id,
                "observed_leader_id": observed_follower.leader_id,
                "observed_term": observed_follower.term,
                "bounded": true
            }
        ]
    });
    at_stage(
        write_private_json(&fault_schedule_path, &fault_schedule),
        HarnessStage::DigestEvidence,
    )?;
    let continuity_started = Instant::now();
    fleet.stop_unclean(fault_target_node_index)?;
    fleet.wait_ready(
        &(0..member_count)
            .filter(|node_index| *node_index != fault_target_node_index)
            .collect::<Vec<_>>(),
        HarnessStage::ContinuityReadiness,
        FLEET_READY_TIMEOUT,
    )?;
    let single_member_stop_service_continuity_millis = at_stage(
        duration_millis(continuity_started.elapsed()),
        HarnessStage::ThresholdEvidence,
    )?;
    at_stage(
        assert_applied(
            invoke_and_record(&mut fleet, &mut history, &schedule[11])?,
            3,
        ),
        HarnessStage::Operation,
    )?;
    at_stage(
        assert_generation(
            invoke_and_record(&mut fleet, &mut history, &schedule[12])?,
            3,
        ),
        HarnessStage::Operation,
    )?;
    if !matches!(
        invoke_and_record(&mut fleet, &mut history, &schedule[13])?,
        QualificationNodeReply::Released
    ) {
        return Err(stage_error(
            HarnessStage::Operation,
            None,
            HarnessFailureKind::Protocol,
        ));
    }

    let restart_started = Instant::now();
    at_stage(
        fleet.restart(fault_target_node_index),
        HarnessStage::ConfigurationEvidence,
    )?;
    let restart_catchup_millis = at_stage(
        duration_millis(restart_started.elapsed()),
        HarnessStage::ThresholdEvidence,
    )?;

    let observed_leader = fleet.observe_stable_leader(FLEET_READY_TIMEOUT)?;
    let leader_target_node_index = observed_leader.node_index;
    let leader_target_process = format!("node-{leader_target_node_index}");
    let fault_schedule = json!({
        "schema_version": "opc-session-ha-fault-schedule/v1",
        "topology_members": member_count,
        "faults": [
            {
                "sequence": 1,
                "kind": "process_stop",
                "target_process": fault_target_process.clone(),
                "target_role": "follower",
                "observed_node_id": observed_follower.node_id,
                "observed_leader_id": observed_follower.leader_id,
                "observed_term": observed_follower.term,
                "bounded": true
            },
            {
                "sequence": 2,
                "kind": "process_restart",
                "target_process": fault_target_process.clone(),
                "target_role": "follower",
                "observed_node_id": observed_follower.node_id,
                "observed_leader_id": observed_follower.leader_id,
                "observed_term": observed_follower.term,
                "bounded": true
            },
            {
                "sequence": 3,
                "kind": "process_stop",
                "target_process": leader_target_process.clone(),
                "target_role": "leader",
                "observed_node_id": observed_leader.node_id,
                "observed_leader_id": observed_leader.leader_id,
                "observed_term": observed_leader.term,
                "bounded": true
            },
            {
                "sequence": 4,
                "kind": "process_restart",
                "target_process": leader_target_process.clone(),
                "target_role": "leader",
                "observed_node_id": observed_leader.node_id,
                "observed_leader_id": observed_leader.leader_id,
                "observed_term": observed_leader.term,
                "bounded": true
            }
        ]
    });
    at_stage(
        write_private_json(&fault_schedule_path, &fault_schedule),
        HarnessStage::DigestEvidence,
    )?;
    let fault_schedule_sha256 = at_stage(
        aggregate_file_sha256(
            FAULT_SCHEDULE_DIGEST_DOMAIN,
            std::slice::from_ref(&fault_schedule_path),
        ),
        HarnessStage::DigestEvidence,
    )?;

    let leader_survivors = (0..member_count)
        .filter(|node_index| *node_index != leader_target_node_index)
        .collect::<Vec<_>>();
    let leader_failover_started = Instant::now();
    fleet.stop_unclean_at(leader_target_node_index, HarnessStage::StopLeader)?;
    let replacement_leader = fleet.observe_stable_replacement_leader(
        &leader_survivors,
        observed_leader.node_id,
        observed_leader.term,
        Duration::from_millis(
            profile
                .provisional_test_thresholds
                .max_leader_failover_millis,
        ),
    )?;
    let leader_failover_millis = at_stage(
        duration_millis(leader_failover_started.elapsed()),
        HarnessStage::ThresholdEvidence,
    )?;
    let replacement_leader_process = format!("node-{}", replacement_leader.node_index);
    at_stage(
        assert_generation(
            fleet.invoke(
                replacement_leader.node_index,
                &QualificationNodeCommand::Get {
                    stable_id: "session-a".to_owned(),
                },
            )?,
            3,
        ),
        HarnessStage::Operation,
    )?;
    let leader_outage_store_read_succeeded = true;

    let leader_restart_started = Instant::now();
    at_stage(
        fleet.restart_leader(leader_target_node_index),
        HarnessStage::ConfigurationEvidence,
    )?;
    let leader_restart_catchup_millis = at_stage(
        duration_millis(leader_restart_started.elapsed()),
        HarnessStage::ThresholdEvidence,
    )?;
    at_stage(
        assert_generation(
            invoke_and_record(&mut fleet, &mut history, &schedule[14])?,
            3,
        ),
        HarnessStage::Operation,
    )?;
    let child_pids = fleet.pids();
    fleet.shutdown_all();
    let child_cleanup_complete = child_processes_gone(&child_pids, PROCESS_STOP_TIMEOUT);
    if !child_cleanup_complete {
        return Err(stage_error(
            HarnessStage::Cleanup,
            None,
            HarnessFailureKind::Deadline,
        ));
    }
    at_stage(
        fleet.assert_distinct_encrypted_storage(),
        HarnessStage::StorageEvidence,
    )?;

    let checker_failure_artifacts = [
        ("schedule.jsonl", schedule_path.as_path()),
        ("history.jsonl", history_path.as_path()),
        ("fault-schedule.json", fault_schedule_path.as_path()),
        (
            "configuration-manifest.json",
            fleet.configuration_manifest_path.as_path(),
        ),
    ];
    let output = match Command::new("python3")
        .arg(&checker)
        .arg("--schedule")
        .arg(&schedule_path)
        .arg("--history")
        .arg(&history_path)
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            let diagnostic = unknown_checker_diagnostic(None, None);
            at_stage(
                preserve_checker_failure_bundle(
                    member_count,
                    &checker_failure_artifacts,
                    &[],
                    &[],
                    &diagnostic,
                    child_cleanup_complete,
                ),
                HarnessStage::CheckerFailureRetention,
            )?;
            return Err(checker_stage_error(HarnessStage::CheckerSpawn, diagnostic));
        }
    };
    let exit_code = output.status.code();
    let signal = output.status.signal();
    if output.stdout.is_empty()
        || output.stdout.len() > MAX_PROVENANCE_COMMAND_BYTES
        || output.stderr.len() > MAX_FAILURE_STDERR_BYTES
    {
        let diagnostic = unknown_checker_diagnostic(exit_code, signal);
        at_stage(
            preserve_checker_failure_bundle(
                member_count,
                &checker_failure_artifacts,
                &output.stdout,
                &output.stderr,
                &diagnostic,
                child_cleanup_complete,
            ),
            HarnessStage::CheckerFailureRetention,
        )?;
        return Err(checker_stage_error(
            HarnessStage::CheckerOutputSize,
            diagnostic,
        ));
    }
    let document: CheckerOutputDocument = match serde_json::from_slice(&output.stdout) {
        Ok(document) => document,
        Err(_) => {
            let diagnostic = unknown_checker_diagnostic(exit_code, signal);
            at_stage(
                preserve_checker_failure_bundle(
                    member_count,
                    &checker_failure_artifacts,
                    &output.stdout,
                    &output.stderr,
                    &diagnostic,
                    child_cleanup_complete,
                ),
                HarnessStage::CheckerFailureRetention,
            )?;
            return Err(checker_stage_error(
                HarnessStage::CheckerOutputJson,
                diagnostic,
            ));
        }
    };
    let diagnostic = checker_diagnostic(&document, exit_code, signal);
    let output_shape_valid = document.checker == "check-session-ha-history.py"
        && document.checker_version == "1"
        && !matches!(diagnostic.status, CheckerStatusDiagnostic::Unknown)
        && document.operations_checked <= schedule.len() as u64
        && document.violation_codes.len() <= 16
        && document.inconclusive_codes.len() <= 16
        && document
            .violation_codes
            .iter()
            .chain(&document.inconclusive_codes)
            .all(|code| !code.is_empty() && code.len() <= 64);
    if !output_shape_valid {
        at_stage(
            preserve_checker_failure_bundle(
                member_count,
                &checker_failure_artifacts,
                &output.stdout,
                &output.stderr,
                &diagnostic,
                child_cleanup_complete,
            ),
            HarnessStage::CheckerFailureRetention,
        )?;
        return Err(checker_stage_error(
            HarnessStage::CheckerOutputJson,
            diagnostic,
        ));
    }
    let expected_exit = match diagnostic.status {
        CheckerStatusDiagnostic::Pass => Some(0),
        CheckerStatusDiagnostic::Fail => Some(1),
        CheckerStatusDiagnostic::Inconclusive => Some(2),
        CheckerStatusDiagnostic::InvalidInput => Some(3),
        CheckerStatusDiagnostic::Unknown => None,
    };
    if exit_code != expected_exit || signal.is_some() || !output.stderr.is_empty() {
        at_stage(
            preserve_checker_failure_bundle(
                member_count,
                &checker_failure_artifacts,
                &output.stdout,
                &output.stderr,
                &diagnostic,
                child_cleanup_complete,
            ),
            HarnessStage::CheckerFailureRetention,
        )?;
        return Err(checker_stage_error(HarnessStage::CheckerExit, diagnostic));
    }
    if diagnostic.status != CheckerStatusDiagnostic::Pass
        || document.operations_checked != schedule.len() as u64
        || !document.violation_codes.is_empty()
        || !document.inconclusive_codes.is_empty()
    {
        at_stage(
            preserve_checker_failure_bundle(
                member_count,
                &checker_failure_artifacts,
                &output.stdout,
                &output.stderr,
                &diagnostic,
                child_cleanup_complete,
            ),
            HarnessStage::CheckerFailureRetention,
        )?;
        return Err(checker_stage_error(HarnessStage::CheckerResult, diagnostic));
    }
    at_stage(
        write_private_bytes(&checker_output_path, &output.stdout),
        HarnessStage::CheckerArtifact,
    )?;

    let (source_revision, source_tree_status) =
        at_stage(source_provenance(&repository), HarnessStage::DigestEvidence)?;
    let environment = at_stage(environment_evidence(), HarnessStage::DigestEvidence)?;
    let binary_sha256 = at_stage(sha256_file(&fleet.binary), HarnessStage::DigestEvidence)?;
    let profile_sha256 = at_stage(sha256_file(&profile_path), HarnessStage::DigestEvidence)?;
    let history_sha256 = at_stage(sha256_file(&history_path), HarnessStage::DigestEvidence)?;
    let checker_sha256 = at_stage(sha256_file(&checker), HarnessStage::DigestEvidence)?;
    let checker_output_sha256 = at_stage(
        sha256_file(&checker_output_path),
        HarnessStage::DigestEvidence,
    )?;
    let completed_at = OffsetDateTime::now_utc();
    let topology_coverage = if member_count == 3 {
        "three_node"
    } else {
        "five_node"
    };
    let evidence = json!({
        "schema_version": "opc-session-ha-evidence/v6",
        "profile_id": "opc-session-openraft-ha/v6",
        "experimental": true,
        "qualification_complete": false,
        "source_revision": source_revision,
        "source_tree_status": source_tree_status,
        "artifact": {
            "name": "opc-session-quorum-node",
            "version": env!("CARGO_PKG_VERSION"),
            "sha256": binary_sha256,
            "cargo_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "foundation_feature_overrides": ["opc-session-net/insecure-test"]
        },
        "environment": environment,
        "execution": {
            "random_seed": FOUNDATION_RANDOM_SEED_BASE + member_count as u64,
            "started_at_utc": utc_timestamp(started_at),
            "completed_at_utc": utc_timestamp(completed_at),
            "profile_sha256": profile_sha256,
            "configuration_digest_domain": CONFIGURATION_DIGEST_DOMAIN,
            "configuration_sha256": configuration_sha256,
            "fault_schedule_digest_domain": FAULT_SCHEDULE_DIGEST_DOMAIN,
            "fault_schedule_sha256": fault_schedule_sha256
        },
        "topology": {
            "members": member_count,
            "independent_processes": true,
            "storage_identity_digest_domain": STORAGE_IDENTITY_DIGEST_DOMAIN,
            "storage_identity_sha256": storage_identity_sha256,
            "transport_mode": "loopback-plaintext-test-only",
            "counts_for_tls_rotation": false
        },
        "payload_protection": {
            "mode": "fixed-memory-provider-synthetic-wrapper-only",
            "synthetic_data_only": true,
            "counts_for_production_encryption": false
        },
        "faults": [
            {
                "kind": "process_stop",
                "target_process": fault_target_process.clone(),
                "target_role": "follower",
                "observed_node_id": observed_follower.node_id,
                "observed_leader_id": observed_follower.leader_id,
                "observed_term": observed_follower.term,
                "bounded": true
            },
            {
                "kind": "process_restart",
                "target_process": fault_target_process.clone(),
                "target_role": "follower",
                "observed_node_id": observed_follower.node_id,
                "observed_leader_id": observed_follower.leader_id,
                "observed_term": observed_follower.term,
                "bounded": true
            },
            {
                "kind": "process_stop",
                "target_process": leader_target_process.clone(),
                "target_role": "leader",
                "observed_node_id": observed_leader.node_id,
                "observed_leader_id": observed_leader.leader_id,
                "observed_term": observed_leader.term,
                "bounded": true
            },
            {
                "kind": "process_restart",
                "target_process": leader_target_process.clone(),
                "target_role": "leader",
                "observed_node_id": observed_leader.node_id,
                "observed_leader_id": observed_leader.leader_id,
                "observed_term": observed_leader.term,
                "bounded": true
            }
        ],
        "leader_transition": {
            "old_leader_process": leader_target_process,
            "old_leader_node_id": observed_leader.node_id,
            "old_term": observed_leader.term,
            "new_leader_process": replacement_leader_process,
            "new_leader_node_id": replacement_leader.node_id,
            "new_term": replacement_leader.term,
            "failover_millis": leader_failover_millis,
            "old_leader_restart_catchup_millis": leader_restart_catchup_millis
        },
        "history": {
            "schema_version": "opc-session-ha-history/v1",
            "schedule_schema_version": "opc-session-ha-schedule/v1",
            "schedule_sha256": schedule_sha256,
            "sha256": history_sha256
        },
        "checker": {
            "name": "check-session-ha-history.py",
            "version": "1",
            "sha256": checker_sha256,
            "exit_code": 0,
            "status": "pass",
            "output_sha256": checker_output_sha256
        },
        "logs": {
            "collection_status": "not_collected_in_foundation",
            "digests": []
        },
        "metrics": {
            "collection_status": "not_collected_in_foundation",
            "digests": []
        },
        "results": {
            "startup_millis": startup_millis,
            "single_member_stop_service_continuity_millis": single_member_stop_service_continuity_millis,
            "restart_catchup_millis": restart_catchup_millis,
            "leader_failover_millis": leader_failover_millis,
            "leader_restart_catchup_millis": leader_restart_catchup_millis,
            "leader_outage_store_read_succeeded": leader_outage_store_read_succeeded,
            "acknowledged_write_loss": 0,
            "stale_owner_mutation_successes": 0,
            "history_checker_violations": 0
        },
        "coverage": [
            "profile_inventory",
            "independent_history_checker",
            "lease_acquire_release",
            "lease_expiry_reacquire",
            "compare_and_set",
            "linearizable_read",
            "stale_fence_rejection",
            "multi_process",
            "real_tcp",
            "persistent_sqlite",
            "process_stop_restart",
            "observed_leader_failover",
            topology_coverage
        ],
        "remaining_acceptance": [
            "tls_rotation_158_163_164",
            "kubernetes_3_5_node",
            "batch_history",
            "watch_history",
            "restore_history",
            "readiness_continuous_gating",
            "network_partition_faults",
            "packet_faults",
            "clock_skew",
            "leader_follower_crash_matrix",
            "crash_point_matrix",
            "version_migration_rollback",
            "resource_soak",
            "signed_release_bundle",
            "distributed_hkms_payload_key_rotation"
        ]
    });
    at_stage(
        validate_generated_evidence(&evidence, member_count, &profile),
        HarnessStage::EvidenceValidation,
    )?;
    at_stage(
        write_private_json(&evidence_path, &evidence),
        HarnessStage::EvidenceValidation,
    )?;
    let retained_bundle = at_stage(
        preserve_evidence_bundle(
            member_count,
            &[
                ("evidence.json", evidence_path.as_path()),
                ("profile.json", profile_path.as_path()),
                ("profile.schema.json", profile_schema_path.as_path()),
                ("evidence.schema.json", evidence_schema_path.as_path()),
                ("schedule.schema.json", schedule_schema_path.as_path()),
                ("history.schema.json", history_schema_path.as_path()),
                (
                    "configuration-manifest.json",
                    fleet.configuration_manifest_path.as_path(),
                ),
                ("fault-schedule.json", fault_schedule_path.as_path()),
                ("schedule.jsonl", schedule_path.as_path()),
                ("history.jsonl", history_path.as_path()),
                ("checker-output.json", checker_output_path.as_path()),
                ("check-session-ha-history.py", checker.as_path()),
                ("opc-session-quorum-node", fleet.binary.as_path()),
            ],
        ),
        HarnessStage::BundleEvidence,
    )?;
    if let Some(retained_bundle) = retained_bundle {
        at_stage(
            verify_retained_bundle(&retained_bundle, member_count),
            HarnessStage::BundleEvidence,
        )?;
    }
    Ok(())
}

#[test]
fn real_three_and_five_process_openraft_sqlite_stop_restart_foundation() {
    run_foundation(3).expect("three-process foundation evidence");
    run_foundation(5).expect("five-process foundation evidence");
}

#[test]
fn foundation_schedule_separates_expiry_from_the_explicit_mutation_lease_handoff() {
    let schedule = workload(3);
    assert_eq!(schedule.len(), 15);
    assert!(matches!(
        &schedule[0].operation,
        ScheduledOperation::LeaseAcquire {
            key,
            ttl_millis,
            ..
        } if key == "session-expiry" && *ttl_millis == SHORT_LEASE_MILLIS
    ));
    assert!(matches!(
        &schedule[1].operation,
        ScheduledOperation::LeaseAcquire {
            key,
            ttl_millis,
            ..
        } if key == "session-expiry" && *ttl_millis == LONG_LEASE_MILLIS
    ));
    assert!(matches!(
        &schedule[2].operation,
        ScheduledOperation::LeaseRelease {
            lease_operation_id,
            ..
        } if lease_operation_id == "op-2"
    ));
    assert!(matches!(
        &schedule[3].operation,
        ScheduledOperation::LeaseAcquire {
            owner,
            ttl_millis,
            ..
        } if owner == "owner-a" && *ttl_millis == LONG_LEASE_MILLIS
    ));
    assert!(matches!(
        &schedule[6].operation,
        ScheduledOperation::LeaseRelease {
            lease_operation_id,
            ..
        } if lease_operation_id == "op-4"
    ));
    assert!(matches!(
        &schedule[7].operation,
        ScheduledOperation::LeaseAcquire { owner, .. } if owner == "owner-b"
    ));
    assert!(matches!(
        &schedule[8].operation,
        ScheduledOperation::CompareAndSet {
            lease_operation_id,
            ..
        } if lease_operation_id == "op-8"
    ));
    assert!(matches!(
        &schedule[9].operation,
        ScheduledOperation::CompareAndSet {
            lease_operation_id,
            ..
        } if lease_operation_id == "op-4"
    ));
    assert!(schedule[11..=13]
        .iter()
        .all(|invocation| invocation.process_id == "node-1"));
    assert_eq!(schedule[14].process_id, "node-2");
}

fn assert_process_gone(pid: u32) {
    let path = PathBuf::from(format!("/proc/{pid}"));
    let deadline = Instant::now() + Duration::from_secs(2);
    while path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!path.exists(), "qualification child {pid} survived cleanup");
}

#[test]
fn occupied_initial_bind_is_a_typed_process_failure() {
    let directory = tempfile::tempdir().expect("bind conflict directory");
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve conflict port");
    let address = reservation.local_addr().expect("reserved address");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_opc-session-quorum-node"));
    let result = ChildNode::spawn_bound(
        &binary,
        &directory.path().join("not-yet-configured.json"),
        &directory.path().join("stderr.log"),
        0,
        address,
        HarnessStage::InitialBind,
    );
    let error = match result {
        Ok((mut child, _)) => {
            child.stop_bounded();
            panic!("child unexpectedly stole an occupied port");
        }
        Err(error) => error,
    };
    let HarnessError::Stage(failure) = error else {
        panic!("bind conflict did not retain its harness stage");
    };
    assert_eq!(failure.stage, HarnessStage::InitialBind);
    assert_eq!(failure.node_index, Some(0));
    assert_eq!(failure.kind, HarnessFailureKind::ProcessExited);
    assert!(failure.exit.is_some_and(|exit| !exit.success));
    assert!(failure.stderr.is_some_and(|stderr| {
        stderr
            .line_codes
            .contains(&StderrLineCode::QualificationNodeFailed)
    }));
}

#[test]
fn disconnected_child_reports_exit_and_cleanup_is_bounded() {
    let directory = tempfile::tempdir().expect("disconnected child directory");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_opc-session-quorum-node"));
    let (mut child, _) = ChildNode::spawn_bound(
        &binary,
        &directory.path().join("not-yet-configured.json"),
        &directory.path().join("stderr.log"),
        0,
        "127.0.0.1:0".parse().expect("loopback bind"),
        HarnessStage::InitialBind,
    )
    .expect("spawn pre-configuration child");
    let pid = child.pid();
    child.child.kill().expect("kill child");
    wait_for_exit(&mut child.child, PROCESS_STOP_TIMEOUT).expect("reap child");
    child.stdin.take();
    let error = child
        .recv(HarnessStage::Operation, Duration::from_secs(1))
        .expect_err("dead child cannot reply");
    let HarnessError::Stage(failure) = error else {
        panic!("disconnected child did not retain its harness stage");
    };
    assert_eq!(failure.stage, HarnessStage::Operation);
    assert_eq!(failure.node_index, Some(0));
    assert_eq!(failure.kind, HarnessFailureKind::ProcessExited);
    assert!(failure.exit.is_some_and(|exit| !exit.success));
    drop(child);
    assert_process_gone(pid);
}

#[test]
fn induced_no_quorum_retains_last_reason_and_reaps_every_child() {
    let schedule_sha256 = format!("sha256:{}", "0".repeat(64));
    let mut fleet = Fleet::start(3, &schedule_sha256).expect("start no-quorum fleet");
    let pids = fleet
        .nodes
        .iter()
        .map(|node| node.as_ref().expect("live fleet node").pid())
        .collect::<Vec<_>>();
    fleet.stop_unclean(1).expect("stop first quorum peer");
    fleet.stop_unclean(2).expect("stop second quorum peer");
    let error = fleet
        .wait_ready(
            &[0],
            HarnessStage::ContinuityReadiness,
            Duration::from_secs(13),
        )
        .expect_err("singleton survivor cannot report quorum ready");
    let HarnessError::Stage(failure) = error else {
        panic!("no-quorum failure did not retain its harness stage");
    };
    assert_eq!(failure.stage, HarnessStage::ContinuityReadiness);
    assert!(matches!(
        failure.kind,
        HarnessFailureKind::Deadline | HarnessFailureKind::ReadinessNotReady
    ));
    assert!(failure.readiness.iter().any(|readiness| {
        readiness.node_index == 0
            && !readiness.ready
            && readiness.reason_code == QualificationReadinessCode::NoQuorum
            && readiness.committed_index.is_none()
    }));
    fleet.shutdown_all();
    drop(fleet);
    for pid in pids {
        assert_process_gone(pid);
    }
}
