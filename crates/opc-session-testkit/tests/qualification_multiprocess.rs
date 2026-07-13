#![cfg(target_os = "linux")]

use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use opc_session_testkit::qualification::{
    qualification_key_sha256, qualification_owner_sha256, qualification_value_sha256,
    read_bounded_json_line, write_json_line, QualificationMember, QualificationNodeCommand,
    QualificationNodeConfig, QualificationNodeErrorCode, QualificationNodeReply,
    QualificationReadinessCode, SessionHaQualificationProfile, QUALIFICATION_NODE_SCHEMA_VERSION,
    QUALIFICATION_OPERATION_TIMEOUT_MILLIS, SESSION_HA_EVIDENCE_SCHEMA_JSON,
    SESSION_HA_PROFILE_JSON,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use time::OffsetDateTime;

const CHILD_START_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_REPLY_TIMEOUT: Duration = Duration::from_secs(20);
const FLEET_READY_TIMEOUT: Duration = Duration::from_secs(60);
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const LEASE_EXPIRY_WAIT: Duration = Duration::from_millis(1_600);
const SHORT_LEASE_MILLIS: u64 = 1_200;
const LONG_LEASE_MILLIS: u64 = 60_000;
const MAX_DATABASE_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROVENANCE_COMMAND_BYTES: usize = 16 * 1024;
const EVIDENCE_OUTPUT_DIRECTORY_ENV: &str = "OPC_SESSION_HA_EVIDENCE_DIR";
const FOUNDATION_RANDOM_SEED_BASE: u64 = 0x0143_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HarnessError {
    Io,
    Protocol,
    Timeout,
    Process,
    Evidence,
}

impl From<std::io::Error> for HarnessError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

#[derive(Clone, Serialize)]
struct ScheduledInvocation {
    schema_version: &'static str,
    schedule_id: String,
    operation_index: usize,
    schedule_operation_count: usize,
    operation_id: String,
    process_id: String,
    operation: ScheduledOperation,
}

impl ScheduledInvocation {
    fn node_index(&self) -> Result<usize, HarnessError> {
        self.process_id
            .strip_prefix("node-")
            .and_then(|value| value.parse().ok())
            .ok_or(HarnessError::Protocol)
    }

    fn command(&self) -> QualificationNodeCommand {
        match &self.operation {
            ScheduledOperation::LeaseAcquire {
                key,
                owner,
                ttl_millis,
            } => QualificationNodeCommand::Acquire {
                lease_handle: self.operation_id.clone(),
                stable_id: key.clone(),
                owner: owner.clone(),
                ttl_millis: *ttl_millis,
            },
            ScheduledOperation::CompareAndSet {
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
            ScheduledOperation::Read { key } => QualificationNodeCommand::Get {
                stable_id: key.clone(),
            },
            ScheduledOperation::LeaseRelease {
                lease_operation_id, ..
            } => QualificationNodeCommand::Release {
                lease_handle: lease_operation_id.clone(),
            },
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ScheduledOperation {
    LeaseAcquire {
        key: String,
        owner: String,
        ttl_millis: u64,
    },
    CompareAndSet {
        key: String,
        lease_operation_id: String,
        expected_generation: Option<u64>,
        new_generation: u64,
        value: String,
    },
    Read {
        key: String,
    },
    LeaseRelease {
        key: String,
        lease_operation_id: String,
    },
}

impl ScheduledOperation {
    fn key(&self) -> &str {
        match self {
            Self::LeaseAcquire { key, .. }
            | Self::CompareAndSet { key, .. }
            | Self::Read { key }
            | Self::LeaseRelease { key, .. } => key,
        }
    }
}

fn workload(member_count: usize) -> Vec<ScheduledInvocation> {
    let schedule_id = format!("session-ha-{member_count}-process-foundation");
    let operations = vec![
        (
            1,
            ScheduledOperation::LeaseAcquire {
                key: "session-a".to_owned(),
                owner: "owner-a".to_owned(),
                ttl_millis: SHORT_LEASE_MILLIS,
            },
        ),
        (
            1,
            ScheduledOperation::CompareAndSet {
                key: "session-a".to_owned(),
                lease_operation_id: "op-1".to_owned(),
                expected_generation: None,
                new_generation: 1,
                value: "qualification-value-1".to_owned(),
            },
        ),
        (
            2,
            ScheduledOperation::Read {
                key: "session-a".to_owned(),
            },
        ),
        (
            2,
            ScheduledOperation::LeaseAcquire {
                key: "session-a".to_owned(),
                owner: "owner-b".to_owned(),
                ttl_millis: LONG_LEASE_MILLIS,
            },
        ),
        (
            2,
            ScheduledOperation::CompareAndSet {
                key: "session-a".to_owned(),
                lease_operation_id: "op-4".to_owned(),
                expected_generation: Some(1),
                new_generation: 2,
                value: "qualification-value-2".to_owned(),
            },
        ),
        (
            1,
            ScheduledOperation::CompareAndSet {
                key: "session-a".to_owned(),
                lease_operation_id: "op-1".to_owned(),
                expected_generation: Some(2),
                new_generation: 3,
                value: "qualification-stale-value".to_owned(),
            },
        ),
        (
            1,
            ScheduledOperation::Read {
                key: "session-a".to_owned(),
            },
        ),
        (
            2,
            ScheduledOperation::CompareAndSet {
                key: "session-a".to_owned(),
                lease_operation_id: "op-4".to_owned(),
                expected_generation: Some(2),
                new_generation: 3,
                value: "qualification-value-3".to_owned(),
            },
        ),
        (
            1,
            ScheduledOperation::Read {
                key: "session-a".to_owned(),
            },
        ),
        (
            2,
            ScheduledOperation::LeaseRelease {
                key: "session-a".to_owned(),
                lease_operation_id: "op-4".to_owned(),
            },
        ),
        (
            0,
            ScheduledOperation::Read {
                key: "session-a".to_owned(),
            },
        ),
    ];
    let count = operations.len();
    operations
        .into_iter()
        .enumerate()
        .map(|(offset, (node_index, operation))| ScheduledInvocation {
            schema_version: "opc-session-ha-schedule/v1",
            schedule_id: schedule_id.clone(),
            operation_index: offset + 1,
            schedule_operation_count: count,
            operation_id: format!("op-{}", offset + 1),
            process_id: format!("node-{node_index}"),
            operation,
        })
        .collect()
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
    if !(startup_within_bound && continuity_within_bound && catchup_within_bound) {
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
) -> Result<(), HarnessError> {
    let Some(configured_root) = env::var_os(EVIDENCE_OUTPUT_DIRECTORY_ENV) else {
        return Ok(());
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
    Ok(())
}

struct ChildNode {
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    replies: Receiver<Result<QualificationNodeReply, HarnessError>>,
    reader: Option<JoinHandle<()>>,
}

impl ChildNode {
    fn spawn(
        binary: &Path,
        config: &Path,
        stderr: &Path,
        expected_node_index: usize,
    ) -> Result<Self, HarnessError> {
        let stderr = open_private_file(stderr, true)?;
        let mut child = Command::new(binary)
            .arg("--config")
            .arg(config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|_| HarnessError::Process)?;
        let Some(stdin) = child.stdin.take() else {
            terminate_failed_spawn(&mut child);
            return Err(HarnessError::Process);
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_failed_spawn(&mut child);
            return Err(HarnessError::Process);
        };
        let (sender, replies) = mpsc::sync_channel(8);
        let reader = match thread::Builder::new()
            .name(format!("qualification-node-{expected_node_index}-stdout"))
            .spawn(move || {
                let mut stdout = BufReader::new(stdout);
                loop {
                    let reply = match read_bounded_json_line(&mut stdout) {
                        Ok(Some(reply)) => Ok(reply),
                        Ok(None) => break,
                        Err(_) => Err(HarnessError::Protocol),
                    };
                    let failed = reply.is_err();
                    if sender.send(reply).is_err() || failed {
                        break;
                    }
                }
            }) {
            Ok(reader) => reader,
            Err(_) => {
                terminate_failed_spawn(&mut child);
                return Err(HarnessError::Process);
            }
        };
        let node = Self {
            child,
            stdin: Some(BufWriter::new(stdin)),
            replies,
            reader: Some(reader),
        };
        match node.recv(CHILD_START_TIMEOUT)? {
            QualificationNodeReply::Started { node_index } if node_index == expected_node_index => {
                Ok(node)
            }
            _ => Err(HarnessError::Protocol),
        }
    }

    fn send(&mut self, command: &QualificationNodeCommand) -> Result<(), HarnessError> {
        let stdin = self.stdin.as_mut().ok_or(HarnessError::Process)?;
        write_json_line(stdin, command).map_err(|_| HarnessError::Protocol)
    }

    fn recv(&self, timeout: Duration) -> Result<QualificationNodeReply, HarnessError> {
        self.replies
            .recv_timeout(timeout)
            .map_err(|_| HarnessError::Timeout)?
    }

    fn invoke(
        &mut self,
        command: &QualificationNodeCommand,
    ) -> Result<QualificationNodeReply, HarnessError> {
        self.send(command)?;
        self.recv(CHILD_REPLY_TIMEOUT)
    }

    fn kill_unclean(mut self) -> Result<(), HarnessError> {
        self.child.kill().map_err(|_| HarnessError::Process)?;
        self.stdin.take();
        wait_for_exit(&mut self.child, PROCESS_STOP_TIMEOUT)?;
        if let Some(reader) = self.reader.take() {
            reader.join().map_err(|_| HarnessError::Process)?;
        }
        Ok(())
    }

    fn stop_bounded(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            if let Some(stdin) = self.stdin.as_mut() {
                let _ = write_json_line(stdin, &QualificationNodeCommand::Shutdown);
            }
            let _ = self.recv(Duration::from_secs(2));
            if wait_for_exit(&mut self.child, Duration::from_secs(3)).is_err() {
                let _ = self.child.kill();
                let _ = wait_for_exit(&mut self.child, PROCESS_STOP_TIMEOUT);
            }
        }
        self.stdin.take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
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

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<(), HarnessError> {
    let deadline = Instant::now() + timeout;
    loop {
        if child
            .try_wait()
            .map_err(|_| HarnessError::Process)?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

struct Fleet {
    _workspace: TempDir,
    root: PathBuf,
    binary: PathBuf,
    configs: Vec<PathBuf>,
    databases: Vec<PathBuf>,
    stderr_logs: Vec<PathBuf>,
    nodes: Vec<Option<ChildNode>>,
}

impl Fleet {
    fn start(member_count: usize, schedule_sha256: &str) -> Result<Self, HarnessError> {
        if !matches!(member_count, 3 | 5) {
            return Err(HarnessError::Protocol);
        }
        let workspace = tempfile::tempdir().map_err(HarnessError::from)?;
        let root = workspace.path().to_path_buf();
        let addresses = reserve_loopback_routes(member_count)?;
        let members = addresses
            .iter()
            .enumerate()
            .map(|(node_index, address)| QualificationMember {
                node_index,
                replica_id: format!("node-{node_index}"),
                endpoint_host: format!("node-{node_index}.qualification.invalid"),
                endpoint_port: address.port(),
                dial_addr: *address,
                tls_identity: format!(
                    "spiffe://qualification.invalid/tenant/test/ns/test/sa/session/nf/test/instance/{node_index}"
                ),
                failure_domain: format!("qualification-zone-{node_index}"),
                backing_identity: format!("qualification-disk-{node_index}"),
            })
            .collect::<Vec<_>>();
        let mut configs = Vec::with_capacity(member_count);
        let mut databases = Vec::with_capacity(member_count);
        let mut stderr_logs = Vec::with_capacity(member_count);
        for node_index in 0..member_count {
            let node_directory = root.join(format!("node-{node_index}"));
            fs::create_dir(&node_directory)?;
            let database_path = node_directory.join("session.sqlite");
            let snapshot_directory = node_directory.join("snapshots");
            let config_path = node_directory.join("config.json");
            let stderr_path = node_directory.join("stderr.log");
            let config = QualificationNodeConfig {
                schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
                node_index,
                cluster_id: format!("qualification-{member_count}-node"),
                configuration_generation: "v1".to_owned(),
                configuration_epoch: 1,
                backend_namespace: format!("qualification-{member_count}-node"),
                workload_schedule_sha256: schedule_sha256.to_owned(),
                members: members.clone(),
                workspace_directory: root.clone(),
                database_path: database_path.clone(),
                snapshot_directory,
                operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
            };
            config.validate().map_err(|_| HarnessError::Protocol)?;
            let config_file = open_private_file(&config_path, false)?;
            let mut config_writer = BufWriter::new(config_file);
            serde_json::to_writer(&mut config_writer, &config)
                .map_err(|_| HarnessError::Evidence)?;
            config_writer.flush()?;
            let config_file = config_writer.into_inner().map_err(|_| HarnessError::Io)?;
            config_file.sync_all()?;
            configs.push(config_path);
            databases.push(database_path);
            stderr_logs.push(stderr_path);
        }
        if databases.iter().collect::<BTreeSet<_>>().len() != member_count {
            return Err(HarnessError::Evidence);
        }
        let binary = PathBuf::from(env!("CARGO_BIN_EXE_opc-session-quorum-node"));
        let mut fleet = Self {
            _workspace: workspace,
            root,
            binary,
            configs,
            databases,
            stderr_logs,
            nodes: (0..member_count).map(|_| None).collect(),
        };
        for node_index in 0..member_count {
            fleet.spawn_node(node_index)?;
        }
        fleet.initialize_all()?;
        fleet.wait_ready(&(0..member_count).collect::<Vec<_>>())?;
        Ok(fleet)
    }

    fn spawn_node(&mut self, node_index: usize) -> Result<(), HarnessError> {
        if self.nodes[node_index].is_some() {
            return Err(HarnessError::Process);
        }
        let node = ChildNode::spawn(
            &self.binary,
            &self.configs[node_index],
            &self.stderr_logs[node_index],
            node_index,
        )?;
        self.nodes[node_index] = Some(node);
        Ok(())
    }

    fn initialize_all(&mut self) -> Result<(), HarnessError> {
        for node in self.nodes.iter_mut().flatten() {
            node.send(&QualificationNodeCommand::Initialize)?;
        }
        for node in self.nodes.iter().flatten() {
            if !matches!(
                node.recv(CHILD_REPLY_TIMEOUT)?,
                QualificationNodeReply::Initialized
            ) {
                return Err(HarnessError::Protocol);
            }
        }
        Ok(())
    }

    fn initialize_one(&mut self, node_index: usize) -> Result<(), HarnessError> {
        let node = self.nodes[node_index]
            .as_mut()
            .ok_or(HarnessError::Process)?;
        if !matches!(
            node.invoke(&QualificationNodeCommand::Initialize)?,
            QualificationNodeReply::Initialized
        ) {
            return Err(HarnessError::Protocol);
        }
        Ok(())
    }

    fn wait_ready(&mut self, node_indices: &[usize]) -> Result<(), HarnessError> {
        let deadline = Instant::now() + FLEET_READY_TIMEOUT;
        loop {
            for node_index in node_indices {
                self.nodes[*node_index]
                    .as_mut()
                    .ok_or(HarnessError::Process)?
                    .send(&QualificationNodeCommand::Probe)?;
            }
            let mut ready = true;
            for node_index in node_indices {
                match self.nodes[*node_index]
                    .as_ref()
                    .ok_or(HarnessError::Process)?
                    .recv(CHILD_REPLY_TIMEOUT)?
                {
                    QualificationNodeReply::Readiness {
                        ready: true,
                        reason_code: QualificationReadinessCode::Ready,
                        configured_voters,
                        required_quorum,
                        ..
                    } if configured_voters == self.nodes.len()
                        && required_quorum == (self.nodes.len() / 2) + 1 => {}
                    QualificationNodeReply::Readiness { .. } => ready = false,
                    _ => return Err(HarnessError::Protocol),
                }
            }
            if ready {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn invoke(
        &mut self,
        node_index: usize,
        command: &QualificationNodeCommand,
    ) -> Result<QualificationNodeReply, HarnessError> {
        self.nodes[node_index]
            .as_mut()
            .ok_or(HarnessError::Process)?
            .invoke(command)
    }

    fn stop_unclean(&mut self, node_index: usize) -> Result<(), HarnessError> {
        self.nodes[node_index]
            .take()
            .ok_or(HarnessError::Process)?
            .kill_unclean()
    }

    fn restart(&mut self, node_index: usize) -> Result<(), HarnessError> {
        self.spawn_node(node_index)?;
        self.initialize_one(node_index)?;
        self.wait_ready(&(0..self.nodes.len()).collect::<Vec<_>>())
    }

    fn configuration_sha256(&self) -> Result<String, HarnessError> {
        aggregate_file_sha256("opc-session-ha/configuration-set/v1", &self.configs)
    }

    fn storage_identity_sha256(&self) -> Result<Vec<String>, HarnessError> {
        let canonical_root = fs::canonicalize(&self.root)?;
        let mut identities = Vec::with_capacity(self.databases.len());
        for database in &self.databases {
            let canonical = fs::canonicalize(database)?;
            if !canonical.starts_with(&canonical_root) {
                return Err(HarnessError::Evidence);
            }
            identities.push(domain_separated_sha256(
                "opc-session-ha/storage-identity/v1",
                [canonical.as_os_str().as_bytes()],
            )?);
        }
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
}

impl Drop for Fleet {
    fn drop(&mut self) {
        for node in self.nodes.iter_mut().flatten() {
            node.stop_bounded();
        }
    }
}

fn reserve_loopback_routes(member_count: usize) -> Result<Vec<SocketAddr>, HarnessError> {
    let listeners = (0..member_count)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<Result<Vec<_>, _>>()?;
    let addresses = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<Result<Vec<_>, _>>()?;
    drop(listeners);
    Ok(addresses)
}

#[derive(Clone)]
struct LeaseEvidence {
    owner: String,
    fence: u64,
}

struct HistoryWriter {
    file: File,
    schedule_sha256: String,
    history_id: String,
    operation_count: usize,
    epoch: Instant,
    leases: HashMap<String, LeaseEvidence>,
}

impl HistoryWriter {
    fn new(
        path: &Path,
        schedule_sha256: String,
        history_id: String,
        operation_count: usize,
    ) -> Result<Self, HarnessError> {
        Ok(Self {
            file: open_private_file(path, false)?,
            schedule_sha256,
            history_id,
            operation_count,
            epoch: Instant::now(),
            leases: HashMap::new(),
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
        let operation = self.history_operation(scheduled, reply)?;
        let history = json!({
            "schema_version": "opc-session-ha-history/v1",
            "schedule_sha256": &self.schedule_sha256,
            "history_id": &self.history_id,
            "operation_index": scheduled.operation_index,
            "history_operation_count": self.operation_count,
            "operation_id": &scheduled.operation_id,
            "process_id": &scheduled.process_id,
            "started_ns": started_ns,
            "completed_ns": completed_ns,
            "operation": operation,
        });
        serde_json::to_writer(&mut self.file, &history).map_err(|_| HarnessError::Evidence)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    fn history_operation(
        &mut self,
        scheduled: &ScheduledInvocation,
        reply: Option<&QualificationNodeReply>,
    ) -> Result<Value, HarnessError> {
        let key_sha256 = qualification_key_sha256(scheduled.operation.key());
        match &scheduled.operation {
            ScheduledOperation::LeaseAcquire { owner, .. } => {
                let (outcome, fence) = match reply {
                    Some(QualificationNodeReply::LeaseAcquired { fence }) => {
                        self.leases.insert(
                            scheduled.operation_id.clone(),
                            LeaseEvidence {
                                owner: owner.clone(),
                                fence: *fence,
                            },
                        );
                        ("success", Some(*fence))
                    }
                    Some(QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::LeaseRejected,
                    }) => ("rejected", None),
                    Some(QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::BackendUnavailable,
                    }) => ("unavailable", None),
                    _ => ("indeterminate", None),
                };
                Ok(json!({
                    "kind": "lease_acquire",
                    "key_sha256": key_sha256,
                    "owner_sha256": qualification_owner_sha256(owner),
                    "outcome": outcome,
                    "fence": fence,
                }))
            }
            ScheduledOperation::CompareAndSet {
                lease_operation_id,
                expected_generation,
                new_generation,
                value,
                ..
            } => {
                let lease = self
                    .leases
                    .get(lease_operation_id)
                    .ok_or(HarnessError::Evidence)?;
                let outcome = match reply {
                    Some(QualificationNodeReply::CompareAndSet { applied: true, .. }) => "success",
                    Some(QualificationNodeReply::CompareAndSet { applied: false, .. }) => {
                        "conflict"
                    }
                    Some(QualificationNodeReply::Error {
                        code:
                            QualificationNodeErrorCode::MutationRejected
                            | QualificationNodeErrorCode::LeaseRejected,
                    }) => "rejected",
                    Some(QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::BackendUnavailable,
                    }) => "unavailable",
                    _ => "indeterminate",
                };
                Ok(json!({
                    "kind": "compare_and_set",
                    "key_sha256": key_sha256,
                    "owner_sha256": qualification_owner_sha256(&lease.owner),
                    "fence": lease.fence,
                    "expected_generation": expected_generation,
                    "new_generation": new_generation,
                    "value_sha256": qualification_value_sha256(value.as_bytes()),
                    "outcome": outcome,
                }))
            }
            ScheduledOperation::Read { .. } => {
                let (outcome, record) = match reply {
                    Some(QualificationNodeReply::Record {
                        present: true,
                        generation: Some(generation),
                        owner_sha256: Some(owner_sha256),
                        fence: Some(fence),
                        value_sha256: Some(value_sha256),
                    }) => (
                        "success",
                        Some(json!({
                            "generation": generation,
                            "owner_sha256": owner_sha256,
                            "fence": fence,
                            "value_sha256": value_sha256,
                        })),
                    ),
                    Some(QualificationNodeReply::Record {
                        present: false,
                        generation: None,
                        owner_sha256: None,
                        fence: None,
                        value_sha256: None,
                    }) => ("success", None),
                    Some(QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::BackendUnavailable,
                    }) => ("unavailable", None),
                    _ => ("indeterminate", None),
                };
                Ok(json!({
                    "kind": "read",
                    "key_sha256": key_sha256,
                    "outcome": outcome,
                    "record": record,
                }))
            }
            ScheduledOperation::LeaseRelease {
                lease_operation_id, ..
            } => {
                let lease = self
                    .leases
                    .get(lease_operation_id)
                    .ok_or(HarnessError::Evidence)?;
                let outcome = match reply {
                    Some(QualificationNodeReply::Released) => "success",
                    Some(QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::LeaseRejected,
                    }) => "rejected",
                    Some(QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::BackendUnavailable,
                    }) => "unavailable",
                    _ => "indeterminate",
                };
                Ok(json!({
                    "kind": "lease_release",
                    "key_sha256": key_sha256,
                    "owner_sha256": qualification_owner_sha256(&lease.owner),
                    "fence": lease.fence,
                    "outcome": outcome,
                }))
            }
        }
    }
}

fn invoke_and_record(
    fleet: &mut Fleet,
    history: &mut HistoryWriter,
    scheduled: &ScheduledInvocation,
) -> Result<QualificationNodeReply, HarnessError> {
    let started_ns = history.now_ns()?;
    let reply = fleet.invoke(scheduled.node_index()?, &scheduled.command());
    let completed_ns = history.now_ns()?;
    history.record(scheduled, started_ns, completed_ns, reply.as_ref().ok())?;
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
    let profile_path = manifest_directory.join("qualification/v1/session-ha-profile.json");
    let evidence_schema_path =
        manifest_directory.join("qualification/v1/session-ha-evidence.schema.json");
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

    let fault_schedule = json!({
        "schema_version": "opc-session-ha-fault-schedule/v1",
        "topology_members": member_count,
        "faults": [
            {
                "sequence": 1,
                "kind": "process_stop",
                "target_process": "node-0",
                "target_role": "voter",
                "bounded": true
            },
            {
                "sequence": 2,
                "kind": "process_restart",
                "target_process": "node-0",
                "target_role": "voter",
                "bounded": true
            }
        ]
    });
    write_private_json(&fault_schedule_path, &fault_schedule)?;
    let fault_schedule_sha256 = aggregate_file_sha256(
        "opc-session-ha/fault-schedule-set/v1",
        std::slice::from_ref(&fault_schedule_path),
    )?;

    let startup_started = Instant::now();
    let mut fleet = Fleet::start(member_count, &schedule_sha256)?;
    let startup_millis = duration_millis(startup_started.elapsed())?;
    let configuration_sha256 = fleet.configuration_sha256()?;
    let storage_identity_sha256 = fleet.storage_identity_sha256()?;
    let mut history = HistoryWriter::new(
        &history_path,
        schedule_sha256.clone(),
        schedule[0].schedule_id.clone(),
        schedule.len(),
    )?;

    match invoke_and_record(&mut fleet, &mut history, &schedule[0])? {
        QualificationNodeReply::LeaseAcquired { fence } if fence > 0 => {}
        _ => return Err(HarnessError::Protocol),
    }
    assert_applied(
        invoke_and_record(&mut fleet, &mut history, &schedule[1])?,
        1,
    )?;
    assert_generation(
        invoke_and_record(&mut fleet, &mut history, &schedule[2])?,
        1,
    )?;

    thread::sleep(LEASE_EXPIRY_WAIT);
    match invoke_and_record(&mut fleet, &mut history, &schedule[3])? {
        QualificationNodeReply::LeaseAcquired { fence } if fence > 1 => {}
        _ => return Err(HarnessError::Protocol),
    }
    assert_applied(
        invoke_and_record(&mut fleet, &mut history, &schedule[4])?,
        2,
    )?;
    match invoke_and_record(&mut fleet, &mut history, &schedule[5])? {
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::MutationRejected,
        } => {}
        _ => return Err(HarnessError::Protocol),
    }
    assert_generation(
        invoke_and_record(&mut fleet, &mut history, &schedule[6])?,
        2,
    )?;

    let continuity_started = Instant::now();
    fleet.stop_unclean(0)?;
    fleet.wait_ready(&(1..member_count).collect::<Vec<_>>())?;
    let single_member_stop_service_continuity_millis =
        duration_millis(continuity_started.elapsed())?;
    assert_applied(
        invoke_and_record(&mut fleet, &mut history, &schedule[7])?,
        3,
    )?;
    assert_generation(
        invoke_and_record(&mut fleet, &mut history, &schedule[8])?,
        3,
    )?;
    if !matches!(
        invoke_and_record(&mut fleet, &mut history, &schedule[9])?,
        QualificationNodeReply::Released
    ) {
        return Err(HarnessError::Protocol);
    }

    let restart_started = Instant::now();
    fleet.restart(0)?;
    let restart_catchup_millis = duration_millis(restart_started.elapsed())?;
    assert_generation(
        invoke_and_record(&mut fleet, &mut history, &schedule[10])?,
        3,
    )?;
    fleet.assert_distinct_encrypted_storage()?;

    let output = Command::new("python3")
        .arg(&checker)
        .arg("--schedule")
        .arg(&schedule_path)
        .arg("--history")
        .arg(&history_path)
        .output()
        .map_err(|_| HarnessError::Evidence)?;
    if output.status.code() != Some(0)
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_PROVENANCE_COMMAND_BYTES
    {
        return Err(HarnessError::Evidence);
    }
    write_private_bytes(&checker_output_path, &output.stdout)?;
    let result: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| HarnessError::Evidence)?;
    if result["status"] != "pass"
        || result["operations_checked"].as_u64() != Some(schedule.len() as u64)
        || result["checker_version"] != "1"
        || result["violation_codes"] != json!([])
        || result["inconclusive_codes"] != json!([])
    {
        return Err(HarnessError::Evidence);
    }

    let (source_revision, source_tree_status) = source_provenance(&repository)?;
    let environment = environment_evidence()?;
    let binary_sha256 = sha256_file(&fleet.binary)?;
    let profile_sha256 = sha256_file(&profile_path)?;
    let history_sha256 = sha256_file(&history_path)?;
    let checker_sha256 = sha256_file(&checker)?;
    let checker_output_sha256 = sha256_file(&checker_output_path)?;
    let completed_at = OffsetDateTime::now_utc();
    let topology_coverage = if member_count == 3 {
        "three_node"
    } else {
        "five_node"
    };
    let evidence = json!({
        "schema_version": "opc-session-ha-evidence/v1",
        "profile_id": "opc-session-openraft-ha/v1",
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
            "configuration_digest_domain": "opc-session-ha/configuration-set/v1",
            "configuration_sha256": configuration_sha256,
            "fault_schedule_digest_domain": "opc-session-ha/fault-schedule-set/v1",
            "fault_schedule_sha256": fault_schedule_sha256
        },
        "topology": {
            "members": member_count,
            "independent_processes": true,
            "storage_identity_digest_domain": "opc-session-ha/storage-identity/v1",
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
            { "kind": "process_stop", "target_role": "voter", "bounded": true },
            { "kind": "process_restart", "target_role": "voter", "bounded": true }
        ],
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
            "acknowledged_write_loss": 0,
            "stale_owner_mutation_successes": 0,
            "history_checker_violations": 0
        },
        "coverage": [
            "profile_inventory",
            "independent_history_checker",
            "lease_acquire_release",
            "compare_and_set",
            "linearizable_read",
            "stale_fence_rejection",
            "multi_process",
            "real_tcp",
            "persistent_sqlite",
            "process_stop_restart",
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
    validate_generated_evidence(&evidence, member_count, &profile)?;
    write_private_json(&evidence_path, &evidence)?;
    preserve_evidence_bundle(
        member_count,
        &[
            ("evidence.json", evidence_path.as_path()),
            ("profile.json", profile_path.as_path()),
            ("evidence.schema.json", evidence_schema_path.as_path()),
            ("fault-schedule.json", fault_schedule_path.as_path()),
            ("schedule.jsonl", schedule_path.as_path()),
            ("history.jsonl", history_path.as_path()),
            ("checker-output.json", checker_output_path.as_path()),
            ("check-session-ha-history.py", checker.as_path()),
            ("opc-session-quorum-node", fleet.binary.as_path()),
        ],
    )?;
    Ok(())
}

#[test]
fn real_three_and_five_process_openraft_sqlite_stop_restart_foundation() {
    run_foundation(3).expect("three-process foundation evidence");
    run_foundation(5).expect("five-process foundation evidence");
}
