#![allow(dead_code, unused_variables)]

#[path = "../../src/consensus/rpc_timing.rs"]
mod consensus_rpc_timing;

use opc_persist::NodeIdentity;
use rustls::pki_types::pem::PemObject;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};

thread_local! {
    static HOLDING_DIR_LOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct DirLock {
    lock_path: std::path::PathBuf,
}

impl DirLock {
    fn acquire() -> Self {
        let lock_path = std::env::temp_dir().join("opc_port_allocator.lock");
        let mut attempts = 0;
        loop {
            match std::fs::create_dir(&lock_path) {
                Ok(_) => {
                    HOLDING_DIR_LOCK.with(|v| v.set(true));
                    return Self { lock_path };
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    attempts += 1;
                    if attempts > 200 {
                        // Check metadata age of the lock directory
                        if let Ok(metadata) = std::fs::metadata(&lock_path) {
                            if let Ok(modified) = metadata.modified() {
                                if let Ok(elapsed) = modified.elapsed() {
                                    // A holder legitimately keeps this lock across an
                                    // entire cluster bootstrap (proxy starts, subprocess
                                    // spawns), which can exceed 10s on loaded CI runners;
                                    // stealing a live holder's lock double-allocates port
                                    // blocks and cross-wires clusters. 60s only reclaims
                                    // locks from genuinely dead processes.
                                    if elapsed > std::time::Duration::from_secs(60) {
                                        // Stale lock, remove it
                                        let _ = std::fs::remove_dir_all(&lock_path);
                                        attempts = 0;
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.lock_path);
        HOLDING_DIR_LOCK.with(|v| v.set(false));
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct PortAllocation {
    start_port: u16,
    end_port: u16,
    expires_at: u64,
}

static PORT_OFFSET: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

pub fn find_free_port_block(size: u16) -> u16 {
    let already_held = HOLDING_DIR_LOCK.with(|v| v.get());
    let _lock = if already_held {
        None
    } else {
        Some(DirLock::acquire())
    };

    let pid = std::process::id();
    let exe = std::env::current_exe().unwrap();
    let name = exe.file_name().unwrap().to_string_lossy();
    let exe_offset = if name.contains("e2e_tier1") {
        0
    } else if name.contains("e2e_tier2") {
        1
    } else if name.contains("e2e_tier3_tier4") {
        2
    } else if name.contains("empirical_stress_tests") {
        3
    } else {
        (pid % 4) as u16
    };

    // A PID-based base port offset to avoid conflicts between separate cargo test processes
    let pid_offset = ((pid % 5) as u16 + exe_offset * 5) * 2000;

    loop {
        // A thread-safe AtomicU16 PORT_OFFSET to allocate distinct port offsets
        let offset = PORT_OFFSET.fetch_add(size, std::sync::atomic::Ordering::SeqCst);
        let start_port = 20000 + pid_offset + (offset % 1800);

        // Check if all ports in the block are currently free
        let mut listeners = Vec::with_capacity(size as usize);
        let mut success = true;
        for i in 0..size {
            let port = start_port + i;
            match std::net::TcpListener::bind(format!("127.0.0.1:{port}")) {
                Ok(listener) => {
                    listeners.push(listener);
                }
                Err(_) => {
                    success = false;
                    break;
                }
            }
        }
        if success {
            // Drop listeners to free the ports
            drop(listeners);
            // Sleep slightly to let macOS release the sockets
            std::thread::sleep(std::time::Duration::from_millis(50));
            return start_port;
        }
    }
}

pub async fn wait_for_port(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..600 {
        if let Ok(stream) = tokio::net::TcpStream::connect(&addr).await {
            drop(stream);
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }
    panic!("Port {port} did not become available in time");
}

/// Polls `check` every 100ms until it returns true or `deadline` elapses.
/// Panics with `what` on timeout. For e2e conditions on real subprocesses.
pub async fn wait_until<F: FnMut() -> bool>(
    what: &str,
    deadline: std::time::Duration,
    mut check: F,
) {
    let start = std::time::Instant::now();
    loop {
        if check() {
            return;
        }
        if start.elapsed() > deadline {
            panic!("timed out after {deadline:?} waiting for {what}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Async variant of [`wait_until`] for checks that must read test state through async APIs.
pub async fn wait_until_async<F, Fut>(what: &str, deadline: std::time::Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if check().await {
            return;
        }
        if start.elapsed() > deadline {
            panic!("timed out after {deadline:?} waiting for {what}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Process-global serializer for multi-node cluster tests.
///
/// Spawning several 3–4 node clusters concurrently (the libtest default of
/// `--test-threads = cores`) oversubscribes CPU on small CI runners: nodes are
/// slow to bind their ports and tight election timers miss their deadlines,
/// producing non-deterministic "port did not become available" failures. Each
/// cluster test holds this guard for its lifetime so only one cluster is live
/// at a time per test binary, which keeps the suite deterministic without
/// changing what any test verifies.
static CLUSTER_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Acquire the cluster serializer; hold the returned guard for the test's
/// duration (store it in [`TestCluster`] or a local `let _g = ...`).
pub async fn acquire_cluster_serial() -> tokio::sync::MutexGuard<'static, ()> {
    CLUSTER_SERIAL.lock().await
}

pub fn generate_test_identities(node_ids: &[usize]) -> HashMap<usize, NodeIdentity> {
    let ca_key_pair = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
    let ca_cert_pem = ca_cert.pem();

    let mut identities = HashMap::new();

    for &node_id in node_ids {
        let node_key_pair = rcgen::KeyPair::generate().unwrap();
        let mut node_params = rcgen::CertificateParams::default();
        node_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");

        let spiffe = format!(
            "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/{node_id}"
        );

        node_params.subject_alt_names = vec![
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("localhost").unwrap()),
            rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
            rcgen::SanType::URI(rcgen::Ia5String::try_from(spiffe).unwrap()),
        ];

        node_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        node_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(10);

        let node_cert = node_params
            .signed_by(&node_key_pair, &ca_cert, &ca_key_pair)
            .unwrap();
        let node_cert_pem = node_cert.pem();
        let node_private_key_pem = node_key_pair.serialize_pem();

        identities.insert(
            node_id,
            NodeIdentity {
                cert_chain_pem: node_cert_pem,
                private_key_pem: node_private_key_pem,
                ca_cert_pem: ca_cert_pem.clone(),
            },
        );
    }
    identities
}

pub struct Proxy {
    local_port: u16,
    target_port: u16,
    enabled: Arc<AtomicBool>,
    disable_notify: Arc<tokio::sync::Notify>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Proxy {
    pub fn new(local_port: u16, target_port: u16) -> Self {
        Self {
            local_port,
            target_port,
            enabled: Arc::new(AtomicBool::new(true)),
            disable_notify: Arc::new(tokio::sync::Notify::new()),
            shutdown_tx: None,
            join_handle: None,
        }
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        self.disable_notify.notify_waiters();
    }

    pub async fn start(&mut self) -> Result<(), std::io::Error> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        #[cfg(unix)]
        socket.set_reuseport(true)?;
        let addr_str = format!("127.0.0.1:{}", self.local_port);
        let std_addr: std::net::SocketAddr = addr_str
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        socket.bind(std_addr)?;
        let listener = socket.listen(1024)?;
        let enabled = Arc::clone(&self.enabled);
        let disable_notify = Arc::clone(&self.disable_notify);
        let target_port = self.target_port;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        let join_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    res = listener.accept() => {
                        match res {
                            Ok((client_stream, _)) => {
                                if !enabled.load(Ordering::SeqCst) {
                                    std::mem::drop(client_stream);
                                    continue;
                                }
                                let enabled = Arc::clone(&enabled);
                                let disable_notify = Arc::clone(&disable_notify);
                                tokio::spawn(async move {
                                    if !enabled.load(Ordering::SeqCst) {
                                        return;
                                    }
                                    let target_addr = format!("127.0.0.1:{target_port}");
                                    let target_stream = match TcpStream::connect(&target_addr).await {
                                        Ok(s) => s,
                                        Err(_) => return,
                                    };

                                    let (mut client_reader, mut client_writer) = client_stream.into_split();
                                    let (mut target_reader, mut target_writer) = target_stream.into_split();

                                    let copy_client_to_target = tokio::io::copy(&mut client_reader, &mut target_writer);
                                    let copy_target_to_client = tokio::io::copy(&mut target_reader, &mut client_writer);

                                    tokio::select! {
                                        _ = async {
                                            if !enabled.load(Ordering::SeqCst) {
                                                return;
                                            }
                                            disable_notify.notified().await;
                                        } => {}
                                        _ = copy_client_to_target => {}
                                        _ = copy_target_to_client => {}
                                    }
                                });
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }
            }
        });

        self.join_handle = Some(join_handle);
        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

pub struct TestNode {
    pub node_id: usize,
    pub port: u16,
    pub db_path: PathBuf,
    pub process: Option<Child>,
    pub stdin: ChildStdin,
    pub stdout_rx: mpsc::Receiver<String>,
    pub cert_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub ca_cert_path: PathBuf,
    pub voting_members: Vec<usize>,
    pub peers: Vec<(usize, u16)>,
    pub cluster_id: String,
    pub audit_key_hex: String,
    pub election_timeout_min: u64,
    pub election_timeout_max: u64,
    pub rpc_timeout: u64,
}

impl TestNode {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        node_id: usize,
        port: u16,
        db_path: PathBuf,
        certs_dir: PathBuf,
        identity: &NodeIdentity,
        voting_members: &[usize],
        peers: &[(usize, u16)],
        cluster_id: &str,
        audit_key_hex: &str,
        election_timeout_min: u64,
        election_timeout_max: u64,
        rpc_timeout: u64,
    ) -> Self {
        let ca_cert_path = certs_dir.join(format!("ca_{node_id}.crt"));
        let cert_chain_path = certs_dir.join(format!("node_{node_id}.crt"));
        let private_key_path = certs_dir.join(format!("node_{node_id}.key"));

        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(&ca_cert_path, &identity.ca_cert_pem).unwrap();
        std::fs::write(&cert_chain_path, &identity.cert_chain_pem).unwrap();
        std::fs::write(&private_key_path, &identity.private_key_pem).unwrap();

        let mut exe_path = std::env::current_exe().unwrap();
        exe_path.pop();
        if exe_path.ends_with("deps") {
            exe_path.pop();
        }
        let mut binary_path = exe_path.join("opc-consensus-node");
        if !binary_path.exists() {
            binary_path = PathBuf::from("target/debug/opc-consensus-node");
        }

        let mut args = vec![
            "--node-id".to_string(),
            node_id.to_string(),
            "--db-path".to_string(),
            db_path.to_str().unwrap().to_string(),
            "--addr".to_string(),
            format!("127.0.0.1:{}", port),
            "--cluster-id".to_string(),
            cluster_id.to_string(),
            "--audit-key-hex".to_string(),
            audit_key_hex.to_string(),
            "--cert-chain-path".to_string(),
            cert_chain_path.to_str().unwrap().to_string(),
            "--private-key-path".to_string(),
            private_key_path.to_str().unwrap().to_string(),
            "--ca-cert-path".to_string(),
            ca_cert_path.to_str().unwrap().to_string(),
            format!("--election-timeout-min={}", election_timeout_min),
            format!("--election-timeout-max={}", election_timeout_max),
            format!("--rpc-timeout={}", rpc_timeout),
        ];

        let voting_members_str = voting_members
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        args.push("--voting-members".to_string());
        args.push(voting_members_str);

        for &(peer_id, peer_proxy_port) in peers {
            args.push("--peer".to_string());
            args.push(format!("{peer_id}=127.0.0.1:{peer_proxy_port}"));
        }

        let stderr_path = certs_dir.join(format!("node_{node_id}.err"));
        let stderr_file = std::fs::File::create(&stderr_path).unwrap();

        let mut child = Command::new(&binary_path)
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(stderr_file)
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn daemon binary at {binary_path:?}: {e}"));

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        let (tx, rx) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let trimmed = line.trim();
                if trimmed.starts_with('{') && tx.send(line).await.is_err() {
                    break;
                }
            }
        });

        Self {
            node_id,
            port,
            db_path,
            process: Some(child),
            stdin,
            stdout_rx: rx,
            cert_chain_path,
            private_key_path,
            ca_cert_path,
            voting_members: voting_members.to_vec(),
            peers: peers.to_vec(),
            cluster_id: cluster_id.to_string(),
            audit_key_hex: audit_key_hex.to_string(),
            election_timeout_min,
            election_timeout_max,
            rpc_timeout,
        }
    }

    pub async fn send_command(
        &mut self,
        cmd: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let line = cmd.to_string() + "\n";

        let parent_path = self.cert_chain_path.parent().unwrap();
        let mut process_ref = self.process.as_mut();
        let mut get_stderr = move |node_id: usize, parent_path: &std::path::Path| -> String {
            std::thread::sleep(std::time::Duration::from_millis(150));
            let status_str = if let Some(ref mut p) = process_ref {
                match p.try_wait() {
                    Ok(Some(status)) => format!(" (exited with status: {status})"),
                    Ok(None) => " (still running)".to_string(),
                    Err(e) => format!(" (try_wait error: {e})"),
                }
            } else {
                " (no process)".to_string()
            };
            let stderr_path = parent_path.join(format!("node_{node_id}.err"));
            let err_content = std::fs::read_to_string(&stderr_path)
                .unwrap_or_else(|_| "no stderr log".to_string());
            format!("{err_content} {status_str}")
        };

        if let Err(e) = self.stdin.write_all(line.as_bytes()).await {
            let stderr = get_stderr(self.node_id, parent_path);
            return Err(format!(
                "failed to write to child stdin: {e}, stderr: {stderr}"
            ));
        }
        if let Err(e) = self.stdin.flush().await {
            let stderr = get_stderr(self.node_id, parent_path);
            return Err(format!(
                "failed to flush child stdin: {e}, stderr: {stderr}"
            ));
        }

        match tokio::time::timeout(tokio::time::Duration::from_secs(10), self.stdout_rx.recv())
            .await
        {
            Ok(Some(line)) => {
                let resp: serde_json::Value = serde_json::from_str(&line).map_err(|e| {
                    format!(
                        "failed to parse JSON response: {}, raw: {}, stderr: {}",
                        e,
                        line,
                        get_stderr(self.node_id, parent_path)
                    )
                })?;
                Ok(resp)
            }
            Ok(None) => {
                let stderr = get_stderr(self.node_id, parent_path);
                Err(format!("child process stdout closed, stderr: {stderr}"))
            }
            Err(_) => {
                let stderr = get_stderr(self.node_id, parent_path);
                Err(format!(
                    "timeout waiting for command response, stderr: {stderr}"
                ))
            }
        }
    }
}

fn is_pid_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn kill_and_wait(mut proc: tokio::process::Child) {
    // Reap synchronously via try_wait (waitpid WNOHANG), never via an async
    // wait on a second runtime: on Linux, tokio observes child exits through
    // SIGCHLD dispatched to the runtime that spawned the child, and that
    // runtime is parked while we block here - an async wait on a helper
    // runtime therefore deadlocks (macOS avoids this via kqueue process
    // events, which is why the old approach only hung on Linux). SIGKILL is
    // unmaskable, so polling is bounded in practice; if the child somehow
    // outlives the window we leak it for the OS to reap at process exit
    // rather than hang the test suite.
    if let Ok(Some(_)) = proc.try_wait() {
        return;
    }
    let _ = proc.start_kill();
    for _ in 0..500 {
        match proc.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        if let Some(proc) = self.process.take() {
            kill_and_wait(proc);
        }
    }
}

pub struct TestCluster {
    pub nodes: HashMap<usize, TestNode>,
    pub proxies: HashMap<(usize, usize), Proxy>,
    pub base_port: u16,
    pub temp_dir: tempfile::TempDir,
    pub certs_dir: PathBuf,
    pub identities: HashMap<usize, NodeIdentity>,
    pub cluster_id: String,
    pub audit_key_hex: String,
    pub election_timeout_min: u64,
    pub election_timeout_max: u64,
    pub rpc_timeout: u64,
    // Held for the cluster's lifetime so only one cluster runs at a time per
    // test binary (see `acquire_cluster_serial`). Public so setups that build
    // the struct directly can attach it; read only via Drop.
    #[allow(dead_code)]
    pub serial_guard: Option<tokio::sync::MutexGuard<'static, ()>>,
}

const AUTOMATIC_ELECTION_ROUNDS: u32 = 4;
const AUTOMATIC_ELECTION_METRICS_POLL_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(200);

#[derive(Debug)]
pub struct NodeMetricsDiagnostic {
    pub node_id: usize,
    // Metrics fields retain the latest successful snapshot when a later command fails.
    pub role: Option<String>,
    pub term: Option<u64>,
    pub election_count: Option<u64>,
    pub leader_changes: Option<u64>,
    // This is the outcome of the latest command attempt, not the snapshot above.
    pub command_error: Option<String>,
}

impl NodeMetricsDiagnostic {
    pub(super) fn new(node_id: usize) -> Self {
        Self {
            node_id,
            role: None,
            term: None,
            election_count: None,
            leader_changes: None,
            command_error: None,
        }
    }

    pub(super) fn observe_response(&mut self, response: &serde_json::Value) {
        if response["success"].as_bool() == Some(true) {
            let role = response["data"]["role"].as_str();
            let term = response["data"]["term"].as_u64();
            let election_count = response["data"]["election_count"].as_u64();
            let leader_changes = response["data"]["leader_changes"].as_u64();

            if let (Some(role), Some(term), Some(election_count), Some(leader_changes)) =
                (role, term, election_count, leader_changes)
            {
                self.role = Some(role.to_owned());
                self.term = Some(term);
                self.election_count = Some(election_count);
                self.leader_changes = Some(leader_changes);
                self.command_error = None;
            } else {
                let mut missing_fields = Vec::new();
                if role.is_none() {
                    missing_fields.push("role");
                }
                if term.is_none() {
                    missing_fields.push("term");
                }
                if election_count.is_none() {
                    missing_fields.push("election_count");
                }
                if leader_changes.is_none() {
                    missing_fields.push("leader_changes");
                }
                self.command_error = Some(format!(
                    "DumpMetrics success response is missing required field(s): {}",
                    missing_fields.join(", ")
                ));
            }
        } else {
            self.command_error = Some(
                response["error"]
                    .as_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| format!("DumpMetrics returned an error: {response}")),
            );
        }
    }

    fn is_leader(&self) -> bool {
        self.role.as_deref() == Some("Leader") && self.command_error.is_none()
    }
}

#[derive(Debug)]
pub struct AutomaticLeaderObservation {
    pub leader_id: usize,
    pub diagnostics: Vec<NodeMetricsDiagnostic>,
}

fn automatic_election_wait_budget(cluster: &TestCluster) -> std::time::Duration {
    let election_timeout = std::time::Duration::from_millis(cluster.election_timeout_max);
    let rpc_timeout = std::time::Duration::from_millis(cluster.rpc_timeout);
    let election_round_budget = election_timeout.saturating_add(
        consensus_rpc_timing::rpc_logical_deadline_budget(rpc_timeout),
    );

    election_round_budget.saturating_mul(AUTOMATIC_ELECTION_ROUNDS)
}

/// Waits for a leader elected by the running nodes' timers, without triggering a campaign.
///
/// The finite test deadline budgets four rounds of the configured maximum election timeout plus
/// one end-to-end logical RPC deadline for the concurrent voting-peer fan-out. It is not a
/// protocol wall-clock guarantee. A timeout reports the latest successful metrics snapshot and
/// the latest command error for every candidate node.
pub async fn wait_for_automatic_leader(
    cluster: &mut TestCluster,
    candidate_ids: &[usize],
    context: &str,
) -> AutomaticLeaderObservation {
    assert!(
        !candidate_ids.is_empty(),
        "{context}: automatic election requires at least one candidate"
    );

    let wait_budget = automatic_election_wait_budget(cluster);
    let deadline = tokio::time::Instant::now()
        .checked_add(wait_budget)
        .expect("automatic-election wait budget should fit within tokio's instant range");
    let mut diagnostics = candidate_ids
        .iter()
        .copied()
        .map(NodeMetricsDiagnostic::new)
        .collect::<Vec<_>>();

    loop {
        let mut command_timed_out_at = None;

        for index in 0..diagnostics.len() {
            let diagnostic = &mut diagnostics[index];
            let command = cluster
                .nodes
                .get_mut(&diagnostic.node_id)
                .unwrap_or_else(|| {
                    panic!(
                        "{context}: candidate node {} should exist",
                        diagnostic.node_id
                    )
                })
                .send_command(serde_json::json!({
                    "command": "DumpMetrics"
                }));

            match tokio::time::timeout_at(deadline, command).await {
                Ok(Ok(response)) => diagnostic.observe_response(&response),
                Ok(Err(error)) => diagnostic.command_error = Some(error),
                Err(_) => {
                    diagnostic.command_error = Some(format!(
                        "DumpMetrics did not complete before the {wait_budget:?} automatic-election deadline ({context})"
                    ));
                    command_timed_out_at = Some(index);
                    break;
                }
            }

            // Stop before issuing another command once leadership is observed. If a later
            // command were cancelled at the deadline, its delayed response could desynchronize
            // that node's stdout command stream.
            if diagnostic.is_leader() {
                return AutomaticLeaderObservation {
                    leader_id: diagnostic.node_id,
                    diagnostics,
                };
            }
        }

        if let Some(timed_out_at) = command_timed_out_at {
            for diagnostic in diagnostics.iter_mut().skip(timed_out_at + 1) {
                diagnostic.command_error = Some(format!(
                    "DumpMetrics was not attempted because the {wait_budget:?} automatic-election deadline elapsed ({context})"
                ));
            }
        }

        if command_timed_out_at.is_some() || tokio::time::Instant::now() >= deadline {
            panic!(
                "{context}: leader should be elected automatically within {wait_budget:?}; \
                 candidate metrics diagnostics: {diagnostics:#?}"
            );
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::time::sleep(AUTOMATIC_ELECTION_METRICS_POLL_INTERVAL.min(remaining)).await;
    }
}

impl TestCluster {
    pub fn new(base_port: u16) -> Self {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let certs_dir = temp_dir.path().join("certs");
        let node_ids = vec![0, 1, 2];
        let identities = generate_test_identities(&node_ids);

        Self {
            nodes: HashMap::new(),
            proxies: HashMap::new(),
            base_port: find_free_port_block(50),
            temp_dir,
            certs_dir,
            identities,
            cluster_id: "tcp-test-cluster".to_string(),
            audit_key_hex: "a5".repeat(32),
            election_timeout_min: 2500,
            election_timeout_max: 4000,
            rpc_timeout: 500,
            serial_guard: None,
        }
    }

    pub async fn bootstrap(&mut self) -> Result<(), String> {
        if self.serial_guard.is_none() {
            self.serial_guard = Some(acquire_cluster_serial().await);
        }
        let _lock = DirLock::acquire();
        self.base_port = find_free_port_block(50);

        self.proxies
            .insert((0, 1), Proxy::new(self.base_port + 1, self.base_port + 10));
        self.proxies
            .insert((0, 2), Proxy::new(self.base_port + 2, self.base_port + 20));
        self.proxies
            .insert((1, 0), Proxy::new(self.base_port + 11, self.base_port));
        self.proxies
            .insert((1, 2), Proxy::new(self.base_port + 12, self.base_port + 20));
        self.proxies
            .insert((2, 0), Proxy::new(self.base_port + 21, self.base_port));
        self.proxies
            .insert((2, 1), Proxy::new(self.base_port + 22, self.base_port + 10));

        for proxy in self.proxies.values_mut() {
            proxy
                .start()
                .await
                .map_err(|e| format!("failed to start proxy: {e}"))?;
        }

        for node_id in 0..3 {
            let port = self.base_port + (node_id as u16 * 10);
            let db_path = self.temp_dir.path().join(format!("node_{node_id}.db"));
            let identity = self.identities.get(&node_id).unwrap();

            let mut peers = Vec::new();
            for peer_id in 0..3 {
                if peer_id != node_id {
                    let proxy_port = match (node_id, peer_id) {
                        (0, 1) => self.base_port + 1,
                        (0, 2) => self.base_port + 2,
                        (1, 0) => self.base_port + 11,
                        (1, 2) => self.base_port + 12,
                        (2, 0) => self.base_port + 21,
                        (2, 1) => self.base_port + 22,
                        _ => unreachable!(),
                    };
                    peers.push((peer_id, proxy_port));
                }
            }

            let voting_members = vec![0, 1, 2];
            let node = TestNode::spawn(
                node_id,
                port,
                db_path,
                self.certs_dir.clone(),
                identity,
                &voting_members,
                &peers,
                &self.cluster_id,
                &self.audit_key_hex,
                self.election_timeout_min,
                self.election_timeout_max,
                self.rpc_timeout,
            );
            self.nodes.insert(node_id, node);
        }

        for node_id in 0..3 {
            let port = self.base_port + (node_id as u16 * 10);
            let addr = format!("127.0.0.1:{port}");
            let mut success = false;
            for _ in 0..300 {
                if let Ok(stream) = tokio::net::TcpStream::connect(&addr).await {
                    drop(stream);
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    success = true;
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
            if !success {
                for nid in 0..3 {
                    let err_path = self.certs_dir.join(format!("node_{nid}.err"));
                    if let Ok(err_content) = std::fs::read_to_string(&err_path) {
                        println!("--- NODE {nid} STDERR --- \n{err_content}");
                    } else {
                        println!("--- NODE {nid} STDERR (not found/unread) ---");
                    }
                }
                panic!("Port {port} did not become available in time");
            }
        }

        Ok(())
    }

    pub fn partition(&mut self, node_a: usize, node_b: usize) {
        if let Some(proxy) = self.proxies.get(&(node_a, node_b)) {
            proxy.disable();
        }
        if let Some(proxy) = self.proxies.get(&(node_b, node_a)) {
            proxy.disable();
        }
    }

    pub fn heal(&mut self, node_a: usize, node_b: usize) {
        if let Some(proxy) = self.proxies.get(&(node_a, node_b)) {
            proxy.enable();
        }
        if let Some(proxy) = self.proxies.get(&(node_b, node_a)) {
            proxy.enable();
        }
    }

    pub async fn kill_node(&mut self, node_id: usize) {
        if let Some(node) = self.nodes.get_mut(&node_id) {
            if let Some(mut proc) = node.process.take() {
                let _ = proc.kill().await;
                let _ = proc.wait().await;
            }
        }
    }

    pub async fn restart_node(&mut self, node_id: usize) {
        self.kill_node(node_id).await;

        let node = self.nodes.get(&node_id).expect("node not found in cluster");
        let node_id = node.node_id;
        let port = node.port;
        let db_path = node.db_path.clone();
        let cert_chain_path = node.cert_chain_path.clone();
        let private_key_path = node.private_key_path.clone();
        let ca_cert_path = node.ca_cert_path.clone();
        let voting_members = node.voting_members.clone();
        let peers = node.peers.clone();
        let cluster_id = node.cluster_id.clone();
        let audit_key_hex = node.audit_key_hex.clone();
        let election_timeout_min = node.election_timeout_min;
        let election_timeout_max = node.election_timeout_max;
        let rpc_timeout = node.rpc_timeout;

        let mut exe_path = std::env::current_exe().unwrap();
        exe_path.pop();
        if exe_path.ends_with("deps") {
            exe_path.pop();
        }
        let mut binary_path = exe_path.join("opc-consensus-node");
        if !binary_path.exists() {
            binary_path = PathBuf::from("target/debug/opc-consensus-node");
        }

        let mut args = vec![
            "--node-id".to_string(),
            node_id.to_string(),
            "--db-path".to_string(),
            db_path.to_str().unwrap().to_string(),
            "--addr".to_string(),
            format!("127.0.0.1:{}", port),
            "--cluster-id".to_string(),
            cluster_id.to_string(),
            "--audit-key-hex".to_string(),
            audit_key_hex.to_string(),
            "--cert-chain-path".to_string(),
            cert_chain_path.to_str().unwrap().to_string(),
            "--private-key-path".to_string(),
            private_key_path.to_str().unwrap().to_string(),
            "--ca-cert-path".to_string(),
            ca_cert_path.to_str().unwrap().to_string(),
            format!("--election-timeout-min={}", election_timeout_min),
            format!("--election-timeout-max={}", election_timeout_max),
            format!("--rpc-timeout={}", rpc_timeout),
        ];

        let voting_members_str = voting_members
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        args.push("--voting-members".to_string());
        args.push(voting_members_str);

        for &(peer_id, peer_proxy_port) in &peers {
            args.push("--peer".to_string());
            args.push(format!("{peer_id}=127.0.0.1:{peer_proxy_port}"));
        }

        let mut child = Command::new(&binary_path)
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn daemon binary at {binary_path:?}: {e}"));

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        let (tx, rx) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let trimmed = line.trim();
                if trimmed.starts_with('{') && tx.send(line).await.is_err() {
                    break;
                }
            }
        });

        let new_node = TestNode {
            node_id,
            port,
            db_path,
            process: Some(child),
            stdin,
            stdout_rx: rx,
            cert_chain_path,
            private_key_path,
            ca_cert_path,
            voting_members,
            peers,
            cluster_id,
            audit_key_hex,
            election_timeout_min,
            election_timeout_max,
            rpc_timeout,
        };
        self.nodes.insert(node_id, new_node);
        wait_for_port(port).await;
    }

    pub async fn graceful_stop_node(&mut self, node_id: usize) {
        if let Some(node) = self.nodes.get_mut(&node_id) {
            if let Some(mut proc) = node.process.take() {
                if let Some(pid) = proc.id() {
                    let _ = std::process::Command::new("kill")
                        .arg("-15")
                        .arg(pid.to_string())
                        .status();
                    match tokio::time::timeout(tokio::time::Duration::from_millis(500), proc.wait())
                        .await
                    {
                        Ok(_) => {}
                        Err(_) => {
                            let _ = proc.kill().await;
                            let _ = proc.wait().await;
                        }
                    }
                }
            }
        }
    }
}

impl Drop for TestCluster {
    fn drop(&mut self) {
        for node in self.nodes.values_mut() {
            if let Some(proc) = node.process.take() {
                kill_and_wait(proc);
            }
        }
        self.nodes.clear();
        self.proxies.clear();
    }
}

pub fn generate_test_ca_and_identities(
    node_ids: &[usize],
) -> (
    rcgen::Certificate,
    rcgen::KeyPair,
    HashMap<usize, NodeIdentity>,
) {
    let ca_key_pair = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
    let ca_cert_pem = ca_cert.pem();

    let mut identities = HashMap::new();

    for &node_id in node_ids {
        let node_key_pair = rcgen::KeyPair::generate().unwrap();
        let mut node_params = rcgen::CertificateParams::default();
        node_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");

        let spiffe = format!(
            "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/{node_id}"
        );

        node_params.subject_alt_names = vec![
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("localhost").unwrap()),
            rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
            rcgen::SanType::URI(rcgen::Ia5String::try_from(spiffe).unwrap()),
        ];

        node_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        node_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(10);

        let node_cert = node_params
            .signed_by(&node_key_pair, &ca_cert, &ca_key_pair)
            .unwrap();
        let node_cert_pem = node_cert.pem();
        let node_private_key_pem = node_key_pair.serialize_pem();

        identities.insert(
            node_id,
            NodeIdentity {
                cert_chain_pem: node_cert_pem,
                private_key_pem: node_private_key_pem,
                ca_cert_pem: ca_cert_pem.clone(),
            },
        );
    }

    (ca_cert, ca_key_pair, identities)
}

pub fn generate_custom_identity(
    ca_cert: &rcgen::Certificate,
    ca_key_pair: &rcgen::KeyPair,
    spiffe_id: &str,
    expired: bool,
) -> NodeIdentity {
    let node_key_pair = rcgen::KeyPair::generate().unwrap();
    let mut node_params = rcgen::CertificateParams::default();
    node_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    node_params.subject_alt_names = vec![
        rcgen::SanType::DnsName(rcgen::Ia5String::try_from("localhost").unwrap()),
        rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
        rcgen::SanType::URI(rcgen::Ia5String::try_from(spiffe_id).unwrap()),
    ];

    if expired {
        node_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(10);
        node_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    } else {
        node_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        node_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(10);
    }

    let node_cert = node_params
        .signed_by(&node_key_pair, ca_cert, ca_key_pair)
        .unwrap();
    let node_cert_pem = node_cert.pem();
    let node_private_key_pem = node_key_pair.serialize_pem();

    NodeIdentity {
        cert_chain_pem: node_cert_pem,
        private_key_pem: node_private_key_pem,
        ca_cert_pem: ca_cert.pem(),
    }
}

pub fn load_certs_from_pem(
    pem: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, std::io::Error> {
    rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

pub fn load_private_key_from_pem(
    pem: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, std::io::Error> {
    rustls::pki_types::PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

pub async fn build_client_connector(identity: &NodeIdentity) -> tokio_rustls::TlsConnector {
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = load_certs_from_pem(&identity.ca_cert_pem).unwrap();
    for ca_cert in ca_certs {
        root_store.add(ca_cert).unwrap();
    }
    let client_certs = load_certs_from_pem(&identity.cert_chain_pem).unwrap();
    let private_key = load_private_key_from_pem(&identity.private_key_pem).unwrap();

    static INIT_CRYPTO: std::sync::Once = std::sync::Once::new();
    INIT_CRYPTO.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, private_key)
        .unwrap();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config))
}

pub async fn connect_raw_tls(
    addr: &str,
    identity: &NodeIdentity,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, std::io::Error> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let connector = build_client_connector(identity).await;
    let host = addr.split(':').next().unwrap_or("127.0.0.1");
    let server_name = rustls::pki_types::ServerName::try_from(host)
        .unwrap()
        .to_owned();
    connector.connect(server_name, tcp).await
}

#[derive(serde::Serialize)]
pub struct AuthenticatedRequest {
    pub sender_node_id: usize,
    pub target_node_id: usize,
    pub cluster_id: String,
    pub spiffe_id: Option<String>,
    pub client_cert_pem: Option<String>,
    pub request: serde_json::Value,
}

#[derive(serde::Deserialize)]
pub struct AuthenticatedResponse {
    pub response: serde_json::Value,
}

pub async fn bootstrap_4_nodes(_base_port: u16) -> Result<TestCluster, String> {
    let serial_guard = Some(acquire_cluster_serial().await);
    let temp_dir = tempfile::TempDir::new().unwrap();
    let certs_dir = temp_dir.path().join("certs");
    let node_ids = vec![0, 1, 2, 3];
    let identities = generate_test_identities(&node_ids);

    let base_port = find_free_port_block(50);

    let mut cluster = TestCluster {
        nodes: HashMap::new(),
        proxies: HashMap::new(),
        base_port,
        temp_dir,
        certs_dir,
        identities,
        cluster_id: "tcp-test-cluster".to_string(),
        audit_key_hex: "a5".repeat(32),
        election_timeout_min: 2500,
        election_timeout_max: 4000,
        rpc_timeout: 500,
        serial_guard,
    };

    for a in 0..4 {
        for b in 0..4 {
            if a != b {
                let local_port = if b < a {
                    base_port + (a as u16 * 10) + b as u16 + 1
                } else {
                    base_port + (a as u16 * 10) + b as u16
                };
                let target_port = base_port + (b as u16 * 10);
                cluster
                    .proxies
                    .insert((a, b), Proxy::new(local_port, target_port));
            }
        }
    }

    for proxy in cluster.proxies.values_mut() {
        proxy
            .start()
            .await
            .map_err(|e| format!("failed to start proxy: {e}"))?;
    }

    for node_id in 0..4 {
        let port = base_port + (node_id as u16 * 10);
        let db_path = cluster.temp_dir.path().join(format!("node_{node_id}.db"));
        let identity = cluster.identities.get(&node_id).unwrap();

        let mut peers = Vec::new();
        for peer_id in 0..4 {
            if peer_id != node_id {
                let proxy_port = if peer_id < node_id {
                    base_port + (node_id as u16 * 10) + peer_id as u16 + 1
                } else {
                    base_port + (node_id as u16 * 10) + peer_id as u16
                };
                peers.push((peer_id, proxy_port));
            }
        }

        let voting_members = vec![0, 1, 2];
        let node = TestNode::spawn(
            node_id,
            port,
            db_path,
            cluster.certs_dir.clone(),
            identity,
            &voting_members,
            &peers,
            &cluster.cluster_id,
            &cluster.audit_key_hex,
            cluster.election_timeout_min,
            cluster.election_timeout_max,
            cluster.rpc_timeout,
        );
        cluster.nodes.insert(node_id, node);
    }

    for node_id in 0..4 {
        let port = base_port + (node_id as u16 * 10);
        wait_for_port(port).await;
    }

    Ok(cluster)
}
