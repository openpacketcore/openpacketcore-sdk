#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::net::SocketAddr;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use opc_session_testkit::qualification::{
    read_bounded_json_line, write_json_line, QualificationConnectionLifecycleConfig,
    QualificationMember, QualificationNodeCommand, QualificationNodeConfig,
    QualificationNodeErrorCode, QualificationNodeReply, QualificationProjectedMtlsConfig,
    QualificationReadinessCode, QualificationTlsMaterialAvailability, QualificationTransportConfig,
    QUALIFICATION_NODE_SCHEMA_VERSION, QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};
use tempfile::TempDir;

const MEMBER_COUNT: usize = 3;
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
const READY_TIMEOUT: Duration = Duration::from_secs(60);

struct TestPki {
    ca_certificate: Certificate,
    ca_key: KeyPair,
}

impl TestPki {
    fn new() -> Self {
        let ca_key = KeyPair::generate().expect("generate qualification CA key");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(DnType::CommonName, "session mTLS qualification CA");
        let ca_certificate = parameters
            .self_signed(&ca_key)
            .expect("sign qualification CA");
        Self {
            ca_certificate,
            ca_key,
        }
    }

    fn write_projected_generation(&self, root: &Path, spiffe_id: &str) {
        let generation = root.join("..2026_07_13_0001");
        fs::create_dir_all(&generation).expect("create projected generation");

        let mut parameters = CertificateParams::default();
        parameters
            .distinguished_name
            .push(DnType::CommonName, "session qualification workload");
        parameters.subject_alt_names.push(SanType::URI(
            rcgen::Ia5String::try_from(spiffe_id).expect("valid qualification SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::hours(1);
        parameters.not_after = now + time::Duration::hours(1);
        let key = KeyPair::generate().expect("generate qualification workload key");
        let certificate = parameters
            .signed_by(&key, &self.ca_certificate, &self.ca_key)
            .expect("sign qualification workload certificate");

        fs::write(
            generation.join("tls.crt"),
            certificate.pem() + &self.ca_certificate.pem(),
        )
        .expect("write projected certificate chain");
        fs::write(generation.join("tls.key"), key.serialize_pem())
            .expect("write projected private key");
        fs::write(generation.join("ca.crt"), self.ca_certificate.pem())
            .expect("write projected trust bundle");
        symlink("..2026_07_13_0001", root.join("..data")).expect("publish projected generation");
    }
}

enum ReaderMessage {
    Reply(QualificationNodeReply),
    Invalid,
}

struct ChildNode {
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    replies: Receiver<ReaderMessage>,
    reader: Option<JoinHandle<()>>,
}

impl ChildNode {
    fn spawn(config: &Path, node_index: usize, stderr: &Path) -> (Self, SocketAddr) {
        let stderr = File::create(stderr).expect("create qualification stderr");
        let mut child = Command::new(env!("CARGO_BIN_EXE_opc-session-quorum-node"))
            .arg("--config")
            .arg(config)
            .arg("--node-index")
            .arg(node_index.to_string())
            .arg("--bind-addr")
            .arg("127.0.0.1:0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn mTLS qualification node");
        let stdin = child.stdin.take().expect("qualification child stdin");
        let stdout = child.stdout.take().expect("qualification child stdout");
        let (sender, replies) = mpsc::sync_channel(32);
        let reader = thread::Builder::new()
            .name(format!("qualification-mtls-node-{node_index}"))
            .spawn(move || {
                let mut stdout = BufReader::new(stdout);
                loop {
                    let message = match read_bounded_json_line(&mut stdout) {
                        Ok(Some(reply)) => ReaderMessage::Reply(reply),
                        Ok(None) => break,
                        Err(_) => ReaderMessage::Invalid,
                    };
                    let invalid = matches!(message, ReaderMessage::Invalid);
                    if sender.send(message).is_err() || invalid {
                        break;
                    }
                }
            })
            .expect("start qualification stdout reader");
        let mut node = Self {
            child,
            stdin: Some(BufWriter::new(stdin)),
            replies,
            reader: Some(reader),
        };
        let reply = node.receive();
        let QualificationNodeReply::Bound {
            node_index: actual,
            bind_addr,
        } = reply
        else {
            panic!("qualification child did not bind")
        };
        assert_eq!(actual, node_index);
        assert!(bind_addr.ip().is_loopback());
        (node, bind_addr)
    }

    fn send(&mut self, command: &QualificationNodeCommand) {
        write_json_line(
            self.stdin.as_mut().expect("qualification child stdin open"),
            command,
        )
        .expect("send qualification command");
    }

    fn receive(&mut self) -> QualificationNodeReply {
        match self.replies.recv_timeout(CHILD_TIMEOUT) {
            Ok(ReaderMessage::Reply(reply)) => reply,
            Ok(ReaderMessage::Invalid) => panic!("invalid qualification child response"),
            Err(error) => panic!("qualification child response unavailable: {error}"),
        }
    }

    fn invoke(&mut self, command: &QualificationNodeCommand) -> QualificationNodeReply {
        self.send(command);
        self.receive()
    }

    fn shutdown(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let reply = self.invoke(&QualificationNodeCommand::Shutdown);
            assert!(matches!(reply, QualificationNodeReply::ShuttingDown));
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.stdin.take();
        if let Some(reader) = self.reader.take() {
            reader.join().expect("join qualification stdout reader");
        }
    }
}

impl Drop for ChildNode {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.stdin.take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

struct Fleet {
    _workspace: TempDir,
    nodes: Vec<ChildNode>,
}

impl Fleet {
    fn start() -> Self {
        let workspace = tempfile::tempdir().expect("create mTLS qualification workspace");
        let root = workspace.path();
        let mut configs = Vec::with_capacity(MEMBER_COUNT);
        let mut nodes = Vec::with_capacity(MEMBER_COUNT);
        let mut addresses = Vec::with_capacity(MEMBER_COUNT);
        for node_index in 0..MEMBER_COUNT {
            let node_root = root.join(format!("node-{node_index}"));
            fs::create_dir(&node_root).expect("create qualification node directory");
            let config = node_root.join("config.json");
            let stderr = node_root.join("stderr.log");
            let (node, address) = ChildNode::spawn(&config, node_index, &stderr);
            configs.push(config);
            nodes.push(node);
            addresses.push(address);
        }

        let members = addresses
            .iter()
            .enumerate()
            .map(|(node_index, dial_addr)| QualificationMember {
                node_index,
                replica_id: format!("node-{node_index}"),
                endpoint_host: format!("node-{node_index}.qualification.invalid"),
                endpoint_port: dial_addr.port(),
                dial_addr: *dial_addr,
                tls_identity: spiffe_id(node_index),
                failure_domain: format!("zone-{node_index}"),
                backing_identity: format!("disk-{node_index}"),
            })
            .collect::<Vec<_>>();
        let pki = TestPki::new();
        for (node_index, config_path) in configs.iter().enumerate() {
            let node_root = root.join(format!("node-{node_index}"));
            let projected_root = node_root.join("projected");
            let snapshots = node_root.join("snapshots");
            fs::create_dir(&projected_root).expect("create projected root");
            fs::create_dir(&snapshots).expect("create snapshots root");
            pki.write_projected_generation(&projected_root, &spiffe_id(node_index));
            let config = QualificationNodeConfig {
                schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
                node_index,
                cluster_id: "qualification-mtls-cluster".to_owned(),
                configuration_generation: "v1".to_owned(),
                configuration_epoch: 1,
                backend_namespace: "qualification-mtls-cluster".to_owned(),
                workload_schedule_sha256: format!("sha256:{}", "a".repeat(64)),
                members: members.clone(),
                workspace_directory: root.to_path_buf(),
                database_path: node_root.join("session.sqlite"),
                snapshot_directory: snapshots,
                operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
                transport: QualificationTransportConfig::ProjectedMtls(
                    QualificationProjectedMtlsConfig {
                        projected_volume_root: projected_root,
                        certificate_file: PathBuf::from("tls.crt"),
                        private_key_file: PathBuf::from("tls.key"),
                        trust_bundle_files: vec![PathBuf::from("ca.crt")],
                        poll_interval_millis: 100,
                        lifecycle: QualificationConnectionLifecycleConfig {
                            maximum_authentication_age_millis: 60_000,
                            rotation_drain_window_millis: 5_000,
                            reconnect_backoff_min_millis: 25,
                            reconnect_backoff_max_millis: 250,
                            rotation_jitter_millis: 1_000,
                        },
                    },
                ),
            };
            config.validate().expect("valid mTLS node configuration");
            fs::write(
                config_path,
                serde_json::to_vec_pretty(&config).expect("encode node configuration"),
            )
            .expect("write node configuration");
        }

        for node in &mut nodes {
            node.send(&QualificationNodeCommand::Configure);
        }
        for (node_index, node) in nodes.iter_mut().enumerate() {
            assert!(matches!(
                node.receive(),
                QualificationNodeReply::Started { node_index: actual } if actual == node_index
            ));
        }
        for node in &mut nodes {
            node.send(&QualificationNodeCommand::Initialize);
        }
        for node in &mut nodes {
            assert!(matches!(
                node.receive(),
                QualificationNodeReply::Initialized
            ));
        }

        let mut fleet = Self {
            _workspace: workspace,
            nodes,
        };
        fleet.wait_ready();
        fleet
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let mut ready = true;
            for node in &mut self.nodes {
                match node.invoke(&QualificationNodeCommand::Probe) {
                    QualificationNodeReply::Readiness {
                        ready: node_ready,
                        reason_code,
                        configured_voters,
                        required_quorum,
                        ..
                    } => {
                        assert_eq!(configured_voters, MEMBER_COUNT);
                        assert_eq!(required_quorum, 2);
                        ready &= node_ready && reason_code == QualificationReadinessCode::Ready;
                    }
                    reply => panic!("unexpected readiness response: {reply:?}"),
                }
            }
            if ready {
                return;
            }
            assert!(Instant::now() < deadline, "mTLS fleet readiness deadline");
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn shutdown(&mut self) {
        for node in &mut self.nodes {
            node.shutdown();
        }
    }
}

fn spiffe_id(node_index: usize) -> String {
    format!(
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/session/nf/test/instance/{node_index}"
    )
}

#[test]
fn production_mtls_nodes_form_quorum_and_complete_directed_fresh_handshakes() {
    let mut fleet = Fleet::start();
    for node in &mut fleet.nodes {
        match node.invoke(&QualificationNodeCommand::MaterialStatus) {
            QualificationNodeReply::MaterialStatus { status } => {
                assert!(status.epoch >= 1);
                assert_eq!(
                    status.availability,
                    QualificationTlsMaterialAvailability::Ready
                );
                assert!(status.reason.is_none());
                assert!(status.leaf_expires_at.is_some());
                assert!(status.certificate_chain_expires_at.is_some());
            }
            reply => panic!("unexpected material response: {reply:?}"),
        }
    }

    for node_index in 0..MEMBER_COUNT {
        assert!(matches!(
            fleet.nodes[node_index].invoke(&QualificationNodeCommand::DirectedHandshake {
                remote_node_index: node_index,
            }),
            QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::InvalidRequest,
            }
        ));
    }
    assert!(matches!(
        fleet.nodes[0].invoke(&QualificationNodeCommand::DirectedHandshake {
            remote_node_index: 1,
        }),
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
        }
    ));

    for source in 0..MEMBER_COUNT {
        let generation =
            match fleet.nodes[source].invoke(&QualificationNodeCommand::RequestReauthentication) {
                QualificationNodeReply::ReauthenticationRequested { generation } => generation,
                reply => panic!("unexpected reauthentication response: {reply:?}"),
            };
        assert!(generation >= 1);
        for target in 0..MEMBER_COUNT {
            if source == target {
                continue;
            }
            match fleet.nodes[source].invoke(&QualificationNodeCommand::DirectedHandshake {
                remote_node_index: target,
            }) {
                QualificationNodeReply::DirectedHandshake {
                    remote_node_index,
                    reauthentication_generation,
                } => {
                    assert_eq!(remote_node_index, target);
                    assert_eq!(reauthentication_generation, generation);
                }
                reply => panic!("unexpected directed handshake response: {reply:?}"),
            }
        }
    }

    fleet.wait_ready();
    for node in &mut fleet.nodes {
        match node.invoke(&QualificationNodeCommand::LifecycleMetrics) {
            QualificationNodeReply::LifecycleMetrics { metrics } => {
                assert!(metrics.connection_attempts >= (MEMBER_COUNT - 1) as u64);
                assert!(metrics.connection_successes >= (MEMBER_COUNT - 1) as u64);
                assert!(metrics.connection_successes > metrics.connection_failure_authentication);
            }
            reply => panic!("unexpected lifecycle metrics response: {reply:?}"),
        }
    }
    fleet.shutdown();
}
