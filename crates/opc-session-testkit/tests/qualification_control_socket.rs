#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use opc_session_testkit::qualification::{
    qualification_concurrent_state_type, read_bounded_json_line, write_json_line,
    QualificationConcurrentBatchOutcome, QualificationConcurrentBatchSlot,
    QualificationConcurrentBatchSlotOutcome, QualificationConcurrentReadiness,
    QualificationConcurrentSubscriptionId, QualificationConsensusRpcAvailability,
    QualificationMember, QualificationNodeCommand, QualificationNodeConfig,
    QualificationNodeErrorCode, QualificationNodeReply, QualificationReadinessCode,
    QualificationTransportConfig, QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS,
    QUALIFICATION_CONCURRENT_BATCH_MAX_SLOTS,
    QUALIFICATION_CONCURRENT_COLLECTOR_MAX_JOURNAL_ENTRIES,
    QUALIFICATION_CONCURRENT_READINESS_CADENCE_MILLIS,
    QUALIFICATION_CONCURRENT_WATCH_MAX_SUBSCRIPTIONS, QUALIFICATION_MAX_CONTROL_LINE_BYTES,
    QUALIFICATION_NODE_SCHEMA_VERSION, QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
};
use serde_json::Value;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);
const FLEET_READY_TIMEOUT: Duration = Duration::from_secs(60);
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

fn write_fleet_control_configs(
    root: &Path,
    addresses: &[SocketAddr],
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let members = addresses
        .iter()
        .enumerate()
        .map(|(node_index, address)| QualificationMember {
            node_index,
            replica_id: format!("concurrent-node-{node_index}"),
            endpoint_host: format!("concurrent-node-{node_index}.qualification.invalid"),
            endpoint_port: address.port(),
            dial_addr: Some(*address),
            tls_identity: format!(
                "spiffe://qualification.invalid/tenant/test/ns/test/sa/session/nf/test/instance/concurrent-{node_index}"
            ),
            failure_domain: format!("concurrent-zone-{node_index}"),
            backing_identity: format!("concurrent-disk-{node_index}"),
        })
        .collect::<Vec<_>>();
    let mut configs = Vec::with_capacity(addresses.len());
    let mut sockets = Vec::with_capacity(addresses.len());
    for node_index in 0..addresses.len() {
        let node_directory = root.join(format!("concurrent-node-{node_index}"));
        fs::create_dir(&node_directory).expect("create concurrent node directory");
        let config = QualificationNodeConfig {
            schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
            node_index,
            cluster_id: "qualification-concurrent-control-cluster".to_owned(),
            configuration_generation: "v1".to_owned(),
            configuration_epoch: 1,
            backend_namespace: "qualification-concurrent-control-cluster".to_owned(),
            workload_schedule_sha256: format!("sha256:{}", "0".repeat(64)),
            members: members.clone(),
            workspace_directory: node_directory.clone(),
            database_path: node_directory.join("session.sqlite"),
            snapshot_directory: node_directory.join("snapshots"),
            operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
            transport: QualificationTransportConfig::LoopbackPlaintextTestOnly,
        };
        config.validate().expect("valid concurrent control config");
        let path = node_directory.join("config.json");
        fs::write(
            &path,
            serde_json::to_vec(&config).expect("encode concurrent control config"),
        )
        .expect("write concurrent control config");
        configs.push(path);
        sockets.push(node_directory.join("control/node.sock"));
    }
    (configs, sockets)
}

fn invoke_all(
    sockets: &[PathBuf],
    command: QualificationNodeCommand,
) -> Vec<QualificationNodeReply> {
    thread::scope(|scope| {
        sockets
            .iter()
            .map(|socket| {
                let command = command.clone();
                scope.spawn(move || invoke_client(socket, &command))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| worker.join().expect("join control client"))
            .collect()
    })
}

fn wait_concurrent_ready(sockets: &[PathBuf]) -> Vec<QualificationConcurrentReadiness> {
    let deadline = Instant::now() + FLEET_READY_TIMEOUT;
    loop {
        let statuses = invoke_all(sockets, QualificationNodeCommand::ProbeConcurrentReadiness)
            .into_iter()
            .map(|reply| match reply {
                QualificationNodeReply::ConcurrentReadiness { status } => status,
                other => panic!("unexpected concurrent readiness reply: {other:?}"),
            })
            .collect::<Vec<_>>();
        if statuses.iter().all(|status| {
            status.ready
                && status.reason_code == QualificationReadinessCode::Ready
                && status.configured_voters == sockets.len()
                && status.configured_voter_ids.len() == sockets.len()
                && status.fresh_reachable_voters == (sockets.len() / 2) + 1
                && status.agreeing_voters == (sockets.len() / 2) + 1
                && status.required_quorum == (sockets.len() / 2) + 1
                && status.raft_term.is_some()
                && status.raft_leader_id.is_some()
                && status.raft_commit_index.is_some()
                && status.raft_applied_index.is_some()
                && status.journal_head.is_some()
        }) {
            return statuses;
        }
        assert!(
            Instant::now() < deadline,
            "concurrent qualification fleet readiness timed out: {statuses:?}"
        );
        thread::sleep(Duration::from_millis(100));
    }
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

fn invoke_fake_readiness_client(
    reply: QualificationNodeReply,
    expected_node_id: u64,
    expected_voter_ids: &str,
) -> std::process::Output {
    let workspace = tempfile::tempdir().expect("readiness client workspace");
    let control_directory = workspace.path().join("control");
    fs::create_dir(&control_directory).expect("create readiness control directory");
    fs::set_permissions(
        &control_directory,
        fs::Permissions::from_mode(CONTROL_DIRECTORY_MODE),
    )
    .expect("set readiness control directory mode");
    let socket = control_directory.join("node.sock");
    let listener = UnixListener::bind(&socket).expect("bind fake readiness socket");
    fs::set_permissions(&socket, fs::Permissions::from_mode(CONTROL_SOCKET_MODE))
        .expect("set fake readiness socket mode");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept readiness client");
        stream
            .set_read_timeout(Some(PROCESS_TIMEOUT))
            .expect("bound readiness request");
        stream
            .set_write_timeout(Some(PROCESS_TIMEOUT))
            .expect("bound readiness reply");
        let command = read_bounded_json_line::<_, QualificationNodeCommand>(&mut BufReader::new(
            stream.try_clone().expect("clone readiness stream"),
        ))
        .expect("decode readiness command")
        .expect("readiness command");
        assert!(matches!(command, QualificationNodeCommand::Probe));
        write_json_line(&mut stream, &reply).expect("write readiness reply");
    });
    let output = Command::new(env!("CARGO_BIN_EXE_opc-session-quorum-node"))
        .arg("--readiness-client")
        .arg(&socket)
        .arg("--expected-node-id")
        .arg(expected_node_id.to_string())
        .arg("--expected-voter-ids")
        .arg(expected_voter_ids)
        .stdin(Stdio::null())
        .output()
        .expect("run readiness client");
    server.join().expect("join fake readiness server");
    output
}

#[test]
fn concurrent_controls_use_real_batch_watch_restore_and_readiness_paths() {
    let workspace = tempfile::tempdir().expect("concurrent control test workspace");
    let addresses = reserve_addresses(3);
    let (configs, sockets) = write_fleet_control_configs(workspace.path(), &addresses);
    let mut servers = configs
        .iter()
        .zip(&addresses)
        .zip(&sockets)
        .enumerate()
        .map(|(node_index, ((config, address), socket))| {
            let mut server = TestServer::start(config, node_index, *address, socket);
            server.wait_for_socket(socket);
            Some(server)
        })
        .collect::<Vec<_>>();
    for (node_index, socket) in sockets.iter().enumerate() {
        assert!(matches!(
            invoke_client(socket, &QualificationNodeCommand::Configure),
            QualificationNodeReply::Started { node_index: actual } if actual == node_index
        ));
    }

    let before_initialize = invoke_client(
        &sockets[0],
        &QualificationNodeCommand::ProbeConcurrentReadiness,
    );
    let QualificationNodeReply::ConcurrentReadiness { status } = before_initialize else {
        panic!("unexpected pre-initialize readiness reply")
    };
    assert!(!status.ready);
    assert!(status.raft_term.is_none());
    assert!(status.raft_leader_id.is_none());
    assert!(status.raft_commit_index.is_none());
    assert!(status.raft_applied_index.is_none());
    assert!(status.journal_head.is_none());

    for reply in invoke_all(&sockets, QualificationNodeCommand::Initialize) {
        assert!(matches!(reply, QualificationNodeReply::Initialized));
    }
    let initial = wait_concurrent_ready(&sockets);
    let mut voter_sets = initial
        .iter()
        .map(|status| status.configured_voter_ids.clone())
        .collect::<Vec<_>>();
    voter_sets.dedup();
    assert_eq!(voter_sets.len(), 1, "every node must report one voter set");
    assert!(initial.iter().all(|status| {
        status
            .raft_leader_id
            .is_some_and(|leader| status.configured_voter_ids.contains(&leader))
            && status.configured_voter_ids.contains(&status.node_id)
    }));

    for (lease_handle, stable_id, owner) in [
        (
            "concurrent-lease-a",
            "concurrent-key-a",
            "concurrent-owner-a",
        ),
        (
            "concurrent-lease-b",
            "concurrent-key-b",
            "concurrent-owner-b",
        ),
    ] {
        assert!(matches!(
            invoke_client(
                &sockets[0],
                &QualificationNodeCommand::Acquire {
                    lease_handle: lease_handle.to_owned(),
                    stable_id: stable_id.to_owned(),
                    owner: owner.to_owned(),
                    ttl_millis: 120_000,
                },
            ),
            QualificationNodeReply::LeaseAcquired { fence } if fence > 0
        ));
    }
    let after_leases = wait_concurrent_ready(&sockets);
    let requested_after = after_leases[0]
        .journal_head
        .expect("linearized journal head after leases");
    let bounded_watch_ids = (0..QUALIFICATION_CONCURRENT_WATCH_MAX_SUBSCRIPTIONS)
        .map(|index| {
            QualificationConcurrentSubscriptionId::new(format!("retained-watch-{index}"))
                .expect("bounded retained-watch ID")
        })
        .collect::<Vec<_>>();
    for subscription_id in &bounded_watch_ids {
        assert!(matches!(
            invoke_client(
                &sockets[1],
                &QualificationNodeCommand::StartConcurrentWatch {
                    subscription_id: subscription_id.clone(),
                    requested_after_journal_sequence: requested_after,
                },
            ),
            QualificationNodeReply::ConcurrentWatchStarted { .. }
        ));
    }
    let over_limit_id = QualificationConcurrentSubscriptionId::new("retained-watch-over-limit")
        .expect("over-limit watch ID");
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::StartConcurrentWatch {
                subscription_id: over_limit_id,
                requested_after_journal_sequence: requested_after,
            },
        ),
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::ConcurrentWatchUnavailable,
        }
    ));
    for subscription_id in bounded_watch_ids {
        assert!(matches!(
            invoke_client(
                &sockets[1],
                &QualificationNodeCommand::AbortConcurrentWatch { subscription_id },
            ),
            QualificationNodeReply::ConcurrentWatchAborted { .. }
        ));
    }
    let current_zero_id = QualificationConcurrentSubscriptionId::new("current-zero-watch")
        .expect("current zero-length subscription ID");
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::StartConcurrentWatch {
                subscription_id: current_zero_id.clone(),
                requested_after_journal_sequence: requested_after,
            },
        ),
        QualificationNodeReply::ConcurrentWatchStarted { .. }
    ));
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::FinishConcurrentWatch {
                subscription_id: current_zero_id,
                complete_through_journal_sequence: requested_after,
            },
        ),
        QualificationNodeReply::ConcurrentWatchFinished {
            complete_through_journal_sequence,
            ref events,
            ..
        } if complete_through_journal_sequence == requested_after && events.is_empty()
    ));

    let future_zero_id = QualificationConcurrentSubscriptionId::new("future-zero-watch")
        .expect("future zero-length subscription ID");
    let future_sequence = requested_after + 1;
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::StartConcurrentWatch {
                subscription_id: future_zero_id.clone(),
                requested_after_journal_sequence: future_sequence,
            },
        ),
        QualificationNodeReply::ConcurrentWatchStarted { .. }
    ));
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::FinishConcurrentWatch {
                subscription_id: future_zero_id.clone(),
                complete_through_journal_sequence: future_sequence,
            },
        ),
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::InvalidRequest,
        }
    ));
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::AbortConcurrentWatch {
                subscription_id: future_zero_id,
            },
        ),
        QualificationNodeReply::ConcurrentWatchAborted { .. }
    ));

    let subscription_id = QualificationConcurrentSubscriptionId::new("concurrent-watch-main")
        .expect("subscription ID");
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::StartConcurrentWatch {
                subscription_id: subscription_id.clone(),
                requested_after_journal_sequence: requested_after,
            },
        ),
        QualificationNodeReply::ConcurrentWatchStarted {
            requested_after_journal_sequence,
            ..
        } if requested_after_journal_sequence == requested_after
    ));
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::StartConcurrentWatch {
                subscription_id: subscription_id.clone(),
                requested_after_journal_sequence: requested_after,
            },
        ),
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::ConcurrentWatchDuplicate,
        }
    ));

    let state_type = qualification_concurrent_state_type("control-socket-real-history")
        .expect("history-derived state type");
    let batch = invoke_client(
        &sockets[0],
        &QualificationNodeCommand::ConcurrentBatch {
            slots: vec![
                QualificationConcurrentBatchSlot {
                    lease_handle: "concurrent-lease-a".to_owned(),
                    stable_id: "concurrent-key-a".to_owned(),
                    expected_generation: None,
                    new_generation: 1,
                    state_type: state_type.clone(),
                    value: "concurrent-value-a".to_owned(),
                },
                QualificationConcurrentBatchSlot {
                    lease_handle: "concurrent-lease-a".to_owned(),
                    stable_id: "concurrent-key-a".to_owned(),
                    expected_generation: None,
                    new_generation: 2,
                    state_type: state_type.clone(),
                    value: "conflicting-value".to_owned(),
                },
            ],
        },
    );
    let QualificationNodeReply::ConcurrentBatch { outcome, slots } = batch else {
        panic!("unexpected concurrent batch reply: {batch:?}")
    };
    assert_eq!(outcome, QualificationConcurrentBatchOutcome::Completed);
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0].slot_index, 1);
    assert_eq!(slots[1].slot_index, 2);
    assert_eq!(
        slots.iter().map(|slot| slot.outcome).collect::<Vec<_>>(),
        vec![
            QualificationConcurrentBatchSlotOutcome::Success,
            QualificationConcurrentBatchSlotOutcome::Conflict,
        ]
    );
    let encoded_batch = serde_json::to_string(&QualificationNodeReply::ConcurrentBatch {
        outcome,
        slots: slots.clone(),
    })
    .expect("encode concurrent batch reply");
    assert!(!encoded_batch.contains("journal_sequence"));

    let later_batch = invoke_client(
        &sockets[0],
        &QualificationNodeCommand::ConcurrentBatch {
            slots: vec![QualificationConcurrentBatchSlot {
                lease_handle: "concurrent-lease-b".to_owned(),
                stable_id: "concurrent-key-b".to_owned(),
                expected_generation: None,
                new_generation: 1,
                state_type: state_type.clone(),
                value: "concurrent-value-b".to_owned(),
            }],
        },
    );
    let QualificationNodeReply::ConcurrentBatch {
        outcome: later_outcome,
        slots: later_slots,
    } = later_batch
    else {
        panic!("unexpected later concurrent batch reply: {later_batch:?}")
    };
    assert_eq!(
        later_outcome,
        QualificationConcurrentBatchOutcome::Completed
    );
    assert_eq!(later_slots.len(), 1);
    assert_eq!(
        later_slots[0].outcome,
        QualificationConcurrentBatchSlotOutcome::Success
    );

    let terminal = wait_concurrent_ready(&sockets)[2]
        .journal_head
        .expect("linearized journal head after batch");
    assert!(terminal > requested_after);
    let watch = invoke_client(
        &sockets[1],
        &QualificationNodeCommand::FinishConcurrentWatch {
            subscription_id: subscription_id.clone(),
            complete_through_journal_sequence: terminal,
        },
    );
    let QualificationNodeReply::ConcurrentWatchFinished {
        complete_through_journal_sequence,
        events,
        ..
    } = watch
    else {
        panic!("unexpected concurrent watch reply: {watch:?}")
    };
    assert_eq!(complete_through_journal_sequence, terminal);
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| {
        event.journal_sequence > requested_after && event.journal_sequence <= terminal
    }));
    let successful_attempts = [&slots[0], &later_slots[0]];
    for event in &events {
        assert_eq!(
            successful_attempts
                .iter()
                .filter(|attempt| attempt.matches_committed_watch_event(event))
                .count(),
            1
        );
    }
    for attempt in successful_attempts {
        assert_eq!(
            events
                .iter()
                .filter(|event| attempt.matches_committed_watch_event(event))
                .count(),
            1
        );
    }
    assert!(events
        .iter()
        .all(|event| !slots[1].matches_committed_watch_event(event)));
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::FinishConcurrentWatch {
                subscription_id,
                complete_through_journal_sequence: terminal,
            },
        ),
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::ConcurrentWatchMissing,
        }
    ));

    let restore = invoke_client(
        &sockets[2],
        &QualificationNodeCommand::ConcurrentRestore {
            state_type: state_type.clone(),
        },
    );
    let QualificationNodeReply::ConcurrentRestore {
        complete: true,
        records,
    } = restore
    else {
        panic!("unexpected concurrent restore reply: {restore:?}")
    };
    assert_eq!(records.len(), 2);
    assert!(records
        .windows(2)
        .all(|pair| pair[0].key_sha256 < pair[1].key_sha256));
    let mut watched = events
        .into_iter()
        .map(|event| event.record)
        .collect::<Vec<_>>();
    watched.sort_unstable_by(|left, right| left.key_sha256.cmp(&right.key_sha256));
    assert_eq!(records, watched);

    let overflow_slots = (0..23)
        .map(|index| {
            let lease_handle = format!("overflow-lease-{index}");
            let stable_id = format!("overflow-key-{index}");
            assert!(matches!(
                invoke_client(
                    &sockets[0],
                    &QualificationNodeCommand::Acquire {
                        lease_handle: lease_handle.clone(),
                        stable_id: stable_id.clone(),
                        owner: format!("overflow-owner-{index}"),
                        ttl_millis: 120_000,
                    },
                ),
                QualificationNodeReply::LeaseAcquired { fence } if fence > 0
            ));
            QualificationConcurrentBatchSlot {
                lease_handle,
                stable_id,
                expected_generation: None,
                new_generation: 1,
                state_type: state_type.clone(),
                value: format!("overflow-value-{index}"),
            }
        })
        .collect::<Vec<_>>();
    for chunk in overflow_slots.chunks(QUALIFICATION_CONCURRENT_BATCH_MAX_SLOTS) {
        let reply = invoke_client(
            &sockets[0],
            &QualificationNodeCommand::ConcurrentBatch {
                slots: chunk.to_vec(),
            },
        );
        assert!(matches!(
            reply,
            QualificationNodeReply::ConcurrentBatch {
                outcome: QualificationConcurrentBatchOutcome::Completed,
                ref slots,
            } if slots.iter().all(|slot| slot.outcome == QualificationConcurrentBatchSlotOutcome::Success)
        ));
    }
    assert!(matches!(
        invoke_client(
            &sockets[2],
            &QualificationNodeCommand::ConcurrentRestore {
                state_type: state_type.clone(),
            },
        ),
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::ConcurrentRestoreOverflow,
        }
    ));

    let bounded_start = wait_concurrent_ready(&sockets)[1]
        .journal_head
        .expect("linearized bounded-watch start");
    let bounded_id = QualificationConcurrentSubscriptionId::new("bounded-watch")
        .expect("bounded subscription ID");
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::StartConcurrentWatch {
                subscription_id: bounded_id.clone(),
                requested_after_journal_sequence: bounded_start,
            },
        ),
        QualificationNodeReply::ConcurrentWatchStarted { .. }
    ));
    for index in 0..QUALIFICATION_CONCURRENT_COLLECTOR_MAX_JOURNAL_ENTRIES {
        assert!(matches!(
            invoke_client(
                &sockets[0],
                &QualificationNodeCommand::Acquire {
                    lease_handle: format!("bounded-lease-{index}"),
                    stable_id: format!("bounded-key-{index}"),
                    owner: format!("bounded-owner-{index}"),
                    ttl_millis: 120_000,
                },
            ),
            QualificationNodeReply::LeaseAcquired { fence } if fence > 0
        ));
    }
    let bounded_terminal = wait_concurrent_ready(&sockets)[1]
        .journal_head
        .expect("linearized bounded-watch terminal");
    assert_eq!(
        bounded_terminal - bounded_start,
        QUALIFICATION_CONCURRENT_COLLECTOR_MAX_JOURNAL_ENTRIES
    );
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::FinishConcurrentWatch {
                subscription_id: bounded_id,
                complete_through_journal_sequence: bounded_terminal,
            },
        ),
        QualificationNodeReply::ConcurrentWatchFinished {
            complete_through_journal_sequence,
            ref events,
            ..
        } if complete_through_journal_sequence == bounded_terminal && events.is_empty()
    ));

    let overflow_id = QualificationConcurrentSubscriptionId::new("overflow-watch")
        .expect("overflow subscription ID");
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::StartConcurrentWatch {
                subscription_id: overflow_id.clone(),
                requested_after_journal_sequence: bounded_terminal,
            },
        ),
        QualificationNodeReply::ConcurrentWatchStarted { .. }
    ));
    for index in 0..=QUALIFICATION_CONCURRENT_COLLECTOR_MAX_JOURNAL_ENTRIES {
        assert!(matches!(
            invoke_client(
                &sockets[0],
                &QualificationNodeCommand::Acquire {
                    lease_handle: format!("window-overflow-lease-{index}"),
                    stable_id: format!("window-overflow-key-{index}"),
                    owner: format!("window-overflow-owner-{index}"),
                    ttl_millis: 120_000,
                },
            ),
            QualificationNodeReply::LeaseAcquired { fence } if fence > 0
        ));
    }
    let overflow_terminal = wait_concurrent_ready(&sockets)[1]
        .journal_head
        .expect("linearized overflow-watch terminal");
    assert_eq!(
        overflow_terminal - bounded_terminal,
        QUALIFICATION_CONCURRENT_COLLECTOR_MAX_JOURNAL_ENTRIES + 1
    );
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::FinishConcurrentWatch {
                subscription_id: overflow_id.clone(),
                complete_through_journal_sequence: overflow_terminal,
            },
        ),
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::ConcurrentWatchOverflow,
        }
    ));
    for _ in 0..2 {
        assert!(matches!(
            invoke_client(
                &sockets[1],
                &QualificationNodeCommand::AbortConcurrentWatch {
                    subscription_id: overflow_id.clone(),
                },
            ),
            QualificationNodeReply::ConcurrentWatchAborted { .. }
        ));
    }

    for (lease_handle, stable_id, owner) in [
        ("fault-lease-a", "fault-key-a", "fault-owner-a"),
        ("fault-lease-b", "fault-key-b", "fault-owner-b"),
    ] {
        assert!(matches!(
            invoke_client(
                &sockets[0],
                &QualificationNodeCommand::Acquire {
                    lease_handle: lease_handle.to_owned(),
                    stable_id: stable_id.to_owned(),
                    owner: owner.to_owned(),
                    ttl_millis: 120_000,
                },
            ),
            QualificationNodeReply::LeaseAcquired { fence } if fence > 0
        ));
    }
    for node_index in [1, 2] {
        assert!(matches!(
            invoke_client(
                &sockets[node_index],
                &QualificationNodeCommand::SetConsensusRpcAvailability {
                    availability: QualificationConsensusRpcAvailability::Unavailable,
                },
            ),
            QualificationNodeReply::ConsensusRpcAvailability {
                availability: QualificationConsensusRpcAvailability::Unavailable,
            }
        ));
    }
    let unavailable_readiness = invoke_client(
        &sockets[0],
        &QualificationNodeCommand::ProbeConcurrentReadiness,
    );
    let QualificationNodeReply::ConcurrentReadiness {
        status: unavailable_status,
    } = unavailable_readiness
    else {
        panic!("unexpected unavailable readiness reply: {unavailable_readiness:?}")
    };
    assert!(!unavailable_status.ready);
    assert_eq!(
        unavailable_status.reason_code,
        QualificationReadinessCode::NoQuorum
    );
    assert!(unavailable_status.raft_term.is_none());
    assert!(unavailable_status.raft_leader_id.is_none());
    assert!(unavailable_status.raft_commit_index.is_none());
    assert!(unavailable_status.raft_applied_index.is_none());
    assert!(unavailable_status.journal_head.is_none());
    let long_control_started = Instant::now();
    let faulted_batch = invoke_client(
        &sockets[0],
        &QualificationNodeCommand::ConcurrentBatch {
            slots: vec![
                QualificationConcurrentBatchSlot {
                    lease_handle: "fault-lease-a".to_owned(),
                    stable_id: "fault-key-a".to_owned(),
                    expected_generation: None,
                    new_generation: 1,
                    state_type: state_type.clone(),
                    value: "fault-value-a".to_owned(),
                },
                QualificationConcurrentBatchSlot {
                    lease_handle: "fault-lease-b".to_owned(),
                    stable_id: "fault-key-b".to_owned(),
                    expected_generation: None,
                    new_generation: 1,
                    state_type: state_type.clone(),
                    value: "fault-value-b".to_owned(),
                },
            ],
        },
    );
    let long_control_elapsed = long_control_started.elapsed();
    assert!(
        long_control_elapsed < Duration::from_millis(QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS),
        "two-slot faulted batch exceeded its isolated response bound: {long_control_elapsed:?}"
    );
    assert!(matches!(
        faulted_batch,
        QualificationNodeReply::ConcurrentBatch {
            outcome: QualificationConcurrentBatchOutcome::Completed,
            ref slots,
        } if slots.len() == QUALIFICATION_CONCURRENT_BATCH_MAX_SLOTS
            && slots.iter().all(|slot| matches!(
                slot.outcome,
                QualificationConcurrentBatchSlotOutcome::Indeterminate
                    | QualificationConcurrentBatchSlotOutcome::Unavailable
            ))
    ));
    for node_index in [1, 2] {
        assert!(matches!(
            invoke_client(
                &sockets[node_index],
                &QualificationNodeCommand::SetConsensusRpcAvailability {
                    availability: QualificationConsensusRpcAvailability::Available,
                },
            ),
            QualificationNodeReply::ConsensusRpcAvailability {
                availability: QualificationConsensusRpcAvailability::Available,
            }
        ));
    }
    let readiness_started = Instant::now();
    assert!(matches!(
        invoke_client(
            &sockets[0],
            &QualificationNodeCommand::ProbeConcurrentReadiness,
        ),
        QualificationNodeReply::ConcurrentReadiness { .. }
    ));
    let readiness_elapsed = readiness_started.elapsed();
    assert!(
        readiness_elapsed < Duration::from_millis(QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS),
        "post-control readiness exceeded its isolated response bound: {readiness_elapsed:?}"
    );
    assert!(
        long_control_elapsed + readiness_elapsed
            < Duration::from_millis(QUALIFICATION_CONCURRENT_READINESS_CADENCE_MILLIS),
        "terminal control plus subsequent readiness exceeded the checker cadence"
    );
    let _ = wait_concurrent_ready(&sockets);

    let final_head = wait_concurrent_ready(&sockets)[1]
        .journal_head
        .expect("linearized final journal head");
    let residue_id = QualificationConcurrentSubscriptionId::new("shutdown-residue")
        .expect("residue subscription ID");
    assert!(matches!(
        invoke_client(
            &sockets[1],
            &QualificationNodeCommand::StartConcurrentWatch {
                subscription_id: residue_id,
                requested_after_journal_sequence: final_head,
            },
        ),
        QualificationNodeReply::ConcurrentWatchStarted { .. }
    ));
    assert!(matches!(
        invoke_client(&sockets[1], &QualificationNodeCommand::Shutdown),
        QualificationNodeReply::ShuttingDown
    ));
    assert!(servers[1].take().expect("node 1 server").wait().success());
    for node_index in [0, 2] {
        assert!(matches!(
            invoke_client(&sockets[node_index], &QualificationNodeCommand::Shutdown),
            QualificationNodeReply::ShuttingDown
        ));
        assert!(servers[node_index]
            .take()
            .expect("remaining server")
            .wait()
            .success());
    }
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
fn readiness_client_is_silent_and_requires_exact_uds_barrier_identity() {
    let ready_reply = |node_id| QualificationNodeReply::Readiness {
        ready: true,
        reason_code: QualificationReadinessCode::Ready,
        node_id,
        term: 2,
        leader_id: Some(22),
        configured_voters: 3,
        configured_voter_ids: Some(vec![11, 22, 33]),
        fresh_reachable_voters: 2,
        agreeing_voters: 2,
        required_quorum: 2,
        committed_index: Some(7),
        applied_index: Some(7),
    };
    let success = invoke_fake_readiness_client(ready_reply(11), 11, "11,22,33");
    assert!(success.status.success());
    assert!(success.stdout.is_empty());
    assert!(success.stderr.is_empty());

    let wrong_local = invoke_fake_readiness_client(ready_reply(11), 22, "11,22,33");
    assert!(!wrong_local.status.success());
    assert!(wrong_local.stdout.is_empty());
    assert_eq!(wrong_local.stderr, b"qualification node failed\n");

    let mut legacy_without_voter_ids = ready_reply(11);
    if let QualificationNodeReply::Readiness {
        configured_voter_ids,
        ..
    } = &mut legacy_without_voter_ids
    {
        *configured_voter_ids = None;
    }
    let missing_voters = invoke_fake_readiness_client(legacy_without_voter_ids, 11, "11,22,33");
    assert!(!missing_voters.status.success());
    assert!(missing_voters.stdout.is_empty());
    assert_eq!(missing_voters.stderr, b"qualification node failed\n");

    let mut outsider_leader = ready_reply(11);
    if let QualificationNodeReply::Readiness { leader_id, .. } = &mut outsider_leader {
        *leader_id = Some(44);
    }
    let wrong_leader = invoke_fake_readiness_client(outsider_leader, 11, "11,22,33");
    assert!(!wrong_leader.status.success());
    assert!(wrong_leader.stdout.is_empty());
    assert_eq!(wrong_leader.stderr, b"qualification node failed\n");
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
