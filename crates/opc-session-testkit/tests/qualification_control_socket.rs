#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use opc_session_testkit::qualification::{
    read_bounded_json_line, write_json_line, QualificationMember, QualificationNodeCommand,
    QualificationNodeConfig, QualificationNodeReply, QualificationReadinessCode,
    QualificationTransportConfig, QUALIFICATION_MAX_CONTROL_LINE_BYTES,
    QUALIFICATION_NODE_SCHEMA_VERSION, QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
};
use serde_json::Value;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);
const CONTROL_DIRECTORY_MODE: u32 = 0o700;
const CONTROL_SOCKET_MODE: u32 = 0o600;

struct TestServer {
    child: Child,
}

impl TestServer {
    fn start(config_path: &Path, node_index: usize, bind_addr: SocketAddr, socket: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_opc-session-quorum-node"))
            .arg("--config")
            .arg(config_path)
            .arg("--node-index")
            .arg(node_index.to_string())
            .arg("--bind-addr")
            .arg(bind_addr.to_string())
            .arg("--control-socket")
            .arg(socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn control server");
        Self { child }
    }

    fn wait_for_socket(&mut self, socket: &Path) {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if fs::symlink_metadata(socket)
                .ok()
                .is_some_and(|metadata| metadata.file_type().is_socket())
                && UnixStream::connect(socket).is_ok()
            {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("poll control server") {
                let mut stderr = Vec::new();
                self.child
                    .stderr
                    .take()
                    .expect("control server stderr")
                    .read_to_end(&mut stderr)
                    .expect("read control server stderr");
                panic!(
                    "control server exited before publishing its socket: {status}; stderr={}",
                    String::from_utf8_lossy(&stderr)
                );
            }
            assert!(
                Instant::now() < deadline,
                "control socket startup timed out"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait(mut self) -> ExitStatus {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll control server exit") {
                return status;
            }
            assert!(Instant::now() < deadline, "control server exit timed out");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_output(mut self) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let status = self.wait_for_exit();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        self.child
            .stdout
            .take()
            .expect("control server stdout")
            .read_to_end(&mut stdout)
            .expect("read control server stdout");
        self.child
            .stderr
            .take()
            .expect("control server stderr")
            .read_to_end(&mut stderr)
            .expect("read control server stderr");
        (status, stdout, stderr)
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll control server exit") {
                return status;
            }
            assert!(Instant::now() < deadline, "control server exit timed out");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn kill_and_wait(&mut self) {
        self.child.kill().expect("kill control server");
        self.child.wait().expect("reap killed control server");
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn reserve_addresses(member_count: usize) -> Vec<SocketAddr> {
    let listeners = (0..member_count)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("reserve loopback address"))
        .collect::<Vec<_>>();
    listeners
        .iter()
        .map(|listener| listener.local_addr().expect("reserved loopback address"))
        .collect()
}

fn write_configs(root: &Path, addresses: &[SocketAddr]) -> Vec<PathBuf> {
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
            failure_domain: format!("zone-{node_index}"),
            backing_identity: format!("disk-{node_index}"),
        })
        .collect::<Vec<_>>();
    addresses
        .iter()
        .enumerate()
        .map(|(node_index, _)| {
            let node_directory = root.join(format!("node-{node_index}"));
            fs::create_dir(&node_directory).expect("create node directory");
            let config = QualificationNodeConfig {
                schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
                node_index,
                cluster_id: "qualification-control-socket-cluster".to_owned(),
                configuration_generation: "v1".to_owned(),
                configuration_epoch: 1,
                backend_namespace: "qualification-control-socket-cluster".to_owned(),
                workload_schedule_sha256: format!("sha256:{}", "0".repeat(64)),
                members: members.clone(),
                workspace_directory: root.to_path_buf(),
                database_path: node_directory.join("session.sqlite"),
                snapshot_directory: node_directory.join("snapshots"),
                operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
                transport: QualificationTransportConfig::LoopbackPlaintextTestOnly,
            };
            config.validate().expect("valid control config");
            let path = node_directory.join("config.json");
            fs::write(
                &path,
                serde_json::to_vec(&config).expect("encode control config"),
            )
            .expect("write control config");
            path
        })
        .collect()
}

fn invoke_client(socket: &Path, command: &QualificationNodeCommand) -> QualificationNodeReply {
    let mut child = Command::new(env!("CARGO_BIN_EXE_opc-session-quorum-node"))
        .arg("--control-client")
        .arg(socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn one-shot control client");
    write_json_line(child.stdin.as_mut().expect("control client stdin"), command)
        .expect("write one control command");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for control client");
    assert!(
        output.status.success(),
        "one-shot control client failed for {command:?}: {}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let mut reader = BufReader::new(output.stdout.as_slice());
    let reply = read_bounded_json_line(&mut reader)
        .expect("decode client reply")
        .expect("one client reply");
    let mut trailing = Vec::new();
    reader.read_to_end(&mut trailing).expect("read reply tail");
    assert!(trailing.is_empty(), "client emitted more than one reply");
    reply
}

fn invoke_raw(socket: &Path, bytes: &[u8]) -> Value {
    let mut stream = UnixStream::connect(socket).expect("connect raw control client");
    stream
        .set_read_timeout(Some(PROCESS_TIMEOUT))
        .expect("bound raw reply");
    stream.write_all(bytes).expect("write raw command");
    stream
        .shutdown(Shutdown::Write)
        .expect("finish raw command");
    read_bounded_json_line(&mut BufReader::new(stream))
        .expect("decode raw reply")
        .expect("raw reply")
}

#[test]
fn private_control_server_survives_bad_clients_and_recovers_stale_socket() {
    let workspace = tempfile::tempdir().expect("control test workspace");
    let addresses = reserve_addresses(3);
    let configs = write_configs(workspace.path(), &addresses);
    let control_directory = workspace.path().join("control");
    let socket = control_directory.join("node.sock");
    let mut server = TestServer::start(&configs[0], 0, addresses[0], &socket);
    server.wait_for_socket(&socket);
    assert_eq!(
        fs::metadata(&control_directory)
            .expect("control directory metadata")
            .permissions()
            .mode()
            & 0o777,
        CONTROL_DIRECTORY_MODE
    );
    assert_eq!(
        fs::metadata(&socket)
            .expect("control socket metadata")
            .permissions()
            .mode()
            & 0o777,
        CONTROL_SOCKET_MODE
    );

    for _ in 0..2 {
        assert!(matches!(
            invoke_client(&socket, &QualificationNodeCommand::Configure),
            QualificationNodeReply::Started { node_index: 0 }
        ));
    }
    assert!(matches!(
        invoke_client(&socket, &QualificationNodeCommand::Probe),
        QualificationNodeReply::Readiness {
            ready: false,
            reason_code: QualificationReadinessCode::NoQuorum,
            ..
        }
    ));

    let mut duplicate_shutdown = Vec::new();
    write_json_line(&mut duplicate_shutdown, &QualificationNodeCommand::Shutdown)
        .expect("encode first shutdown frame");
    write_json_line(&mut duplicate_shutdown, &QualificationNodeCommand::Probe)
        .expect("encode forbidden second frame");
    assert_eq!(
        invoke_raw(&socket, &duplicate_shutdown),
        serde_json::json!({"reply":"error","code":"invalid_request"})
    );
    assert!(matches!(
        invoke_client(&socket, &QualificationNodeCommand::Configure),
        QualificationNodeReply::Started { node_index: 0 }
    ));

    let mut malformed_shutdown = Vec::new();
    write_json_line(&mut malformed_shutdown, &QualificationNodeCommand::Shutdown)
        .expect("encode shutdown before malformed tail");
    malformed_shutdown.extend_from_slice(b"not-whitespace");
    assert_eq!(
        invoke_raw(&socket, &malformed_shutdown),
        serde_json::json!({"reply":"error","code":"invalid_request"})
    );
    assert!(matches!(
        invoke_client(&socket, &QualificationNodeCommand::Configure),
        QualificationNodeReply::Started { node_index: 0 }
    ));

    assert_eq!(
        invoke_raw(&socket, b"{malformed}\n"),
        serde_json::json!({"reply":"error","code":"invalid_request"})
    );
    let mut oversized = vec![b'x'; QUALIFICATION_MAX_CONTROL_LINE_BYTES + 1];
    oversized.push(b'\n');
    assert_eq!(
        invoke_raw(&socket, &oversized),
        serde_json::json!({"reply":"error","code":"invalid_request"})
    );

    let mut disconnected = UnixStream::connect(&socket).expect("connect then disconnect");
    write_json_line(&mut disconnected, &QualificationNodeCommand::Probe)
        .expect("send disconnected command once");
    drop(disconnected);
    assert!(matches!(
        invoke_client(&socket, &QualificationNodeCommand::Configure),
        QualificationNodeReply::Started { node_index: 0 }
    ));

    let active = TestServer::start(&configs[1], 1, addresses[1], &socket);
    let (status, stdout, stderr) = active.wait_output();
    assert!(!status.success());
    assert!(stdout.is_empty());
    assert_eq!(stderr, b"qualification node failed\n");
    assert!(matches!(
        invoke_client(&socket, &QualificationNodeCommand::Configure),
        QualificationNodeReply::Started { node_index: 0 }
    ));

    server.kill_and_wait();
    assert!(socket.exists(), "SIGKILL must leave a stale socket fixture");
    let mut restarted = TestServer::start(&configs[0], 0, addresses[0], &socket);
    restarted.wait_for_socket(&socket);
    assert!(matches!(
        invoke_client(&socket, &QualificationNodeCommand::Configure),
        QualificationNodeReply::Started { node_index: 0 }
    ));
    assert!(matches!(
        invoke_client(&socket, &QualificationNodeCommand::Shutdown),
        QualificationNodeReply::ShuttingDown
    ));
    assert!(restarted.wait().success());
    assert!(
        !socket.exists(),
        "clean shutdown must remove its exact socket"
    );
}

#[test]
fn control_client_failures_are_fixed_and_redacted() {
    let private = "/private/operator/control/node.sock";
    let output = Command::new(env!("CARGO_BIN_EXE_opc-session-quorum-node"))
        .args(["--control-client", private])
        .stdin(Stdio::null())
        .output()
        .expect("run rejected control client");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"qualification node failed\n");
    assert!(!String::from_utf8_lossy(&output.stderr).contains(private));
}

#[test]
fn legacy_stdio_mode_retains_its_exact_frame_sequence() {
    let workspace = tempfile::tempdir().expect("stdio test workspace");
    let addresses = reserve_addresses(3);
    let configs = write_configs(workspace.path(), &addresses);
    let mut child = Command::new(env!("CARGO_BIN_EXE_opc-session-quorum-node"))
        .arg("--config")
        .arg(&configs[0])
        .arg("--node-index")
        .arg("0")
        .arg("--bind-addr")
        .arg(addresses[0].to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn legacy stdio node");
    let mut stdin = child.stdin.take().expect("legacy stdio stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("legacy stdio stdout"));

    let assert_frame = |reader: &mut BufReader<_>, reply: QualificationNodeReply| {
        let mut actual = Vec::new();
        reader
            .read_until(b'\n', &mut actual)
            .expect("read legacy stdio frame");
        let mut expected = serde_json::to_vec(&reply).expect("encode expected legacy frame");
        expected.push(b'\n');
        assert_eq!(actual, expected);
    };
    assert_frame(
        &mut stdout,
        QualificationNodeReply::Bound {
            node_index: 0,
            bind_addr: addresses[0],
        },
    );
    write_json_line(&mut stdin, &QualificationNodeCommand::Configure)
        .expect("configure legacy stdio node");
    assert_frame(
        &mut stdout,
        QualificationNodeReply::Started { node_index: 0 },
    );
    write_json_line(&mut stdin, &QualificationNodeCommand::Shutdown)
        .expect("shutdown legacy stdio node");
    assert_frame(&mut stdout, QualificationNodeReply::ShuttingDown);
    drop(stdin);
    assert!(child.wait().expect("wait legacy stdio node").success());
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("legacy stdio stderr")
        .read_to_end(&mut stderr)
        .expect("read legacy stderr");
    assert!(stderr.is_empty());
}
