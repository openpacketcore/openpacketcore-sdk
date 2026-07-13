#![cfg(target_os = "linux")]

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::net::{SocketAddr, TcpListener};
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
    QualificationReadinessCode, QUALIFICATION_NODE_SCHEMA_VERSION,
    QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const CHILD_START_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_REPLY_TIMEOUT: Duration = Duration::from_secs(20);
const FLEET_READY_TIMEOUT: Duration = Duration::from_secs(60);
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const LEASE_EXPIRY_WAIT: Duration = Duration::from_millis(1_600);
const SHORT_LEASE_MILLIS: u64 = 1_200;
const LONG_LEASE_MILLIS: u64 = 60_000;
const MAX_DATABASE_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;

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
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    Ok(format!("sha256:{:x}", hasher.finalize()))
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
    let schedule = workload(member_count);
    let artifact_workspace = tempfile::tempdir()?;
    let schedule_path = artifact_workspace.path().join("schedule.jsonl");
    let history_path = artifact_workspace.path().join("history.jsonl");
    let schedule_sha256 = write_schedule(&schedule_path, &schedule)?;
    let mut fleet = Fleet::start(member_count, &schedule_sha256)?;
    let mut history = HistoryWriter::new(
        &history_path,
        schedule_sha256,
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

    fleet.stop_unclean(0)?;
    fleet.wait_ready(&(1..member_count).collect::<Vec<_>>())?;
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

    fleet.restart(0)?;
    assert_generation(
        invoke_and_record(&mut fleet, &mut history, &schedule[10])?,
        3,
    )?;
    fleet.assert_distinct_encrypted_storage()?;

    let checker =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check-session-ha-history.py");
    let output = Command::new("python3")
        .arg(checker)
        .arg("--schedule")
        .arg(&schedule_path)
        .arg("--history")
        .arg(&history_path)
        .output()
        .map_err(|_| HarnessError::Evidence)?;
    if !output.status.success() {
        return Err(HarnessError::Evidence);
    }
    let result: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| HarnessError::Evidence)?;
    if result["status"] != "pass"
        || result["operations_checked"].as_u64() != Some(schedule.len() as u64)
    {
        return Err(HarnessError::Evidence);
    }
    Ok(())
}

#[test]
fn real_three_and_five_process_openraft_sqlite_stop_restart_foundation() {
    run_foundation(3).expect("three-process foundation evidence");
    run_foundation(5).expect("five-process foundation evidence");
}
