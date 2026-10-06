//! Real process exits, with no harness kill on the successful path.

use super::*;
use opc_session_testkit::qualification::QualificationLineError;
use std::process::ChildStdin;
use std::sync::mpsc::{self, Receiver};

const EXIT_BOUND: Duration = Duration::from_secs(5);
type StdioRead = Result<Option<QualificationNodeReply>, QualificationLineError>;

fn stdio_failure(server: &mut TestServer, phase: &str, read_error: &str) -> ! {
    // The assertion has already failed. Give a naturally exiting child time
    // to publish its exit status before cleanup, without retrying the frame
    // or extending any successful startup/terminal-exit bound.
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut status = server.child.try_wait();
    while matches!(status, Ok(None)) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
        status = server.child.try_wait();
    }
    let exit_code = status
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .and_then(ExitStatus::code);
    let cleanup = if matches!(status, Ok(Some(_))) {
        None
    } else {
        Some((server.child.kill(), server.child.wait()))
    };
    let mut stderr = Vec::new();
    let stderr_read = server.child.stderr.take().map(|stderr_pipe| {
        stderr_pipe
            .take(QUALIFICATION_MAX_CONTROL_LINE_BYTES as u64)
            .read_to_end(&mut stderr)
    });
    panic!(
        "stdio {phase} failed: pid={}; read_error={read_error}; child_status_before_cleanup={status:?}; exit_code={exit_code:?}; cleanup={cleanup:?}; stderr_read={stderr_read:?}; stderr_limited_to={} bytes: {}",
        server.child.id(),
        QUALIFICATION_MAX_CONTROL_LINE_BYTES,
        String::from_utf8_lossy(&stderr),
    );
}

fn receive_stdio_reply(
    server: &mut TestServer,
    receiver: &Receiver<StdioRead>,
    phase: &str,
) -> QualificationNodeReply {
    match receiver.recv_timeout(PROCESS_TIMEOUT) {
        Ok(Ok(Some(reply))) => reply,
        result => stdio_failure(server, phase, &format!("{result:?}")),
    }
}

struct Voter {
    server: TestServer,
    socket: PathBuf,
    stdio: Option<(ChildStdin, Receiver<StdioRead>)>,
}

impl Voter {
    fn bind_for_configuration(
        config: &Path,
        index: usize,
        address: SocketAddr,
        socket: &Path,
        stdio: bool,
    ) -> (Self, SocketAddr) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_opc-session-quorum-node"));
        command
            .arg("--config")
            .arg(config)
            .arg("--node-index")
            .arg(index.to_string())
            .arg("--bind-addr")
            .arg(address.to_string());
        if !stdio {
            command.arg("--control-socket").arg(socket);
        }
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start voter with bind handshake");
        let mut server = TestServer { child };
        let stdin = server.child.stdin.take().expect("voter stdin");
        let mut stdout = BufReader::new(server.child.stdout.take().expect("voter stdout"));
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || loop {
            let result = read_bounded_json_line(&mut stdout);
            let terminal = !matches!(&result, Ok(Some(_)));
            if sender.send(result).is_err() || terminal {
                break;
            }
        });
        let phase = format!("startup Bound for node {index} at {address}");
        let bound = receive_stdio_reply(&mut server, &receiver, &phase);
        let bind_addr = match bound {
            QualificationNodeReply::Bound {
                node_index,
                bind_addr,
            } if node_index == index
                && bind_addr.ip() == address.ip()
                && bind_addr.port() != 0
                && (address.port() == 0 || bind_addr == address) =>
            {
                bind_addr
            }
            _ => stdio_failure(&mut server, &phase, &format!("unexpected reply: {bound:?}")),
        };
        (
            Self {
                server,
                socket: socket.to_path_buf(),
                stdio: Some((stdin, receiver)),
            },
            bind_addr,
        )
    }

    fn start(config: &Path, index: usize, address: SocketAddr, socket: &Path, stdio: bool) -> Self {
        let mut voter = if stdio {
            Self::bind_for_configuration(config, index, address, socket, true).0
        } else {
            let mut server = TestServer::start(config, index, address, socket);
            server.wait_for_socket(socket);
            Self {
                server,
                socket: socket.to_path_buf(),
                stdio: None,
            }
        };
        voter.configure(index);
        voter
    }

    fn configure(&mut self, index: usize) {
        assert!(matches!(self.command(&QualificationNodeCommand::Configure),
            QualificationNodeReply::Started { node_index } if node_index == index));
    }

    fn command(&mut self, command: &QualificationNodeCommand) -> QualificationNodeReply {
        if let Some((stdin, receiver)) = &mut self.stdio {
            if let Err(error) = write_json_line(stdin, command) {
                stdio_failure(&mut self.server, "command write", &format!("{error:?}"));
            }
            receive_stdio_reply(&mut self.server, receiver, "command reply")
        } else {
            invoke_client(&self.socket, command)
        }
    }

    fn ready(&mut self) -> bool {
        matches!(
            self.command(&QualificationNodeCommand::Probe),
            QualificationNodeReply::Readiness { ready: true, .. }
        )
    }
}

fn assert_record(voter: &mut Voter, fence: u64, generation: u64, value: &str) {
    let actual = voter.command(&QualificationNodeCommand::Get {
        stable_id: "fence-exit-key".into(),
    });
    assert!(
        matches!(&actual, QualificationNodeReply::Record {
        present: true, generation: Some(actual_generation), fence: Some(actual_fence),
        owner_sha256: Some(owner), value_sha256: Some(digest),
    } if *actual_generation == generation && *actual_fence == fence
        && *owner == opc_session_testkit::qualification::qualification_owner_sha256("fence-exit-owner")
        && *digest == opc_session_testkit::qualification::qualification_value_sha256(value.as_bytes())),
        "committed record must survive exactly: {actual:?}"
    );
}

struct VoterFleet {
    addresses: Vec<SocketAddr>,
    configs: Vec<PathBuf>,
    sockets: Vec<PathBuf>,
    voters: Vec<Voter>,
}

fn start_fleet<T>(
    root: &Path,
    stdio: bool,
    before_configure: impl FnOnce(&[SocketAddr]) -> T,
) -> VoterFleet {
    let mut voters = Vec::new();
    // Both modes retain child listeners across Bound and Configure. Dropping
    // parent reservations before either mode spawns leaves a competing-bind gap.
    let addresses = (0..3)
        .map(|index| {
            let directory = root.join(format!("concurrent-node-{index}"));
            let (voter, address) = Voter::bind_for_configuration(
                &directory.join("config.json"),
                index,
                "127.0.0.1:0".parse().expect("loopback bind"),
                &directory.join("control/node.sock"),
                stdio,
            );
            voters.push(voter);
            address
        })
        .collect::<Vec<_>>();
    let _competing_listeners = before_configure(&addresses);
    let (configs, sockets) = write_fleet_control_configs(root, &addresses);
    for (index, voter) in voters.iter_mut().enumerate() {
        voter.configure(index);
        if !stdio {
            // Configuration completed the test-only bootstrap exchange;
            // every operational command now exercises the real control socket.
            voter.stdio = None;
        }
    }
    VoterFleet {
        addresses,
        configs,
        sockets,
        voters,
    }
}

fn fleet_owns_its_ports_before_configuration(stdio: bool) {
    let workspace = tempfile::tempdir().expect("port ownership workspace");
    let mut stolen_ports = 0;
    let mut fleet = start_fleet(workspace.path(), stdio, |addresses| {
        // Force the competing bind into the startup gap. Keep any listeners
        // until configuration finishes, so a lost reservation cannot heal.
        let listeners = addresses
            .iter()
            .filter_map(|address| match TcpListener::bind(address) {
                Ok(listener) => Some(listener),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => None,
                Err(error) => panic!("unexpected competing bind failure: {error}"),
            })
            .collect::<Vec<_>>();
        stolen_ports = listeners.len();
        listeners
    });
    assert_eq!(stolen_ports, 0, "children must retain every chosen port");
    for voter in &mut fleet.voters {
        assert!(matches!(
            voter.command(&QualificationNodeCommand::Shutdown),
            QualificationNodeReply::ShuttingDown
        ));
        assert!(voter.server.wait_for_exit().success());
    }
}

#[test]
fn stdio_fleet_owns_its_ports_before_configuration() {
    fleet_owns_its_ports_before_configuration(true);
}

#[test]
fn control_fleet_owns_its_ports_before_configuration() {
    fleet_owns_its_ports_before_configuration(false);
}

fn fenced_voter_exits_and_rejoins(stdio: bool) {
    let workspace = tempfile::tempdir().expect("fenced voter workspace");
    let VoterFleet {
        addresses,
        configs,
        sockets,
        mut voters,
    } = start_fleet(workspace.path(), stdio, |_| ());
    thread::scope(|scope| {
        let workers = voters
            .iter_mut()
            .map(|voter| {
                scope.spawn(move || {
                    assert!(matches!(
                        voter.command(&QualificationNodeCommand::Initialize),
                        QualificationNodeReply::Initialized
                    ));
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().expect("initialize voter");
        }
    });
    let deadline = Instant::now() + FLEET_READY_TIMEOUT;
    while !voters.iter_mut().all(Voter::ready) {
        assert!(Instant::now() < deadline, "fleet must become ready");
        thread::sleep(Duration::from_millis(50));
    }
    let QualificationNodeReply::Readiness {
        leader_id: Some(leader),
        ..
    } = voters[0].command(&QualificationNodeCommand::Probe)
    else {
        panic!("ready leader")
    };
    // Cover a failed leader in control mode and a failed follower in stdio mode.
    let target = voters
        .iter_mut()
        .position(|voter| {
            let QualificationNodeReply::Readiness { node_id, .. } =
                voter.command(&QualificationNodeCommand::Probe)
            else {
                panic!("node identity")
            };
            (node_id == leader) != stdio
        })
        .expect("fault target");
    let writer = (target + 1) % voters.len();
    let QualificationNodeReply::LeaseAcquired { fence } =
        voters[writer].command(&QualificationNodeCommand::Acquire {
            lease_handle: "fence-exit-lease".into(),
            stable_id: "fence-exit-key".into(),
            owner: "fence-exit-owner".into(),
            ttl_millis: 120_000,
        })
    else {
        panic!("committed lease")
    };
    let write = |generation, value: &str| QualificationNodeCommand::CompareAndSet {
        lease_handle: "fence-exit-lease".into(),
        stable_id: "fence-exit-key".into(),
        expected_generation: (generation > 1).then_some(generation - 1),
        new_generation: generation,
        value: value.into(),
    };
    assert!(matches!(
        voters[writer].command(&write(1, "before-fence")),
        QualificationNodeReply::CompareAndSet { applied: true, .. }
    ));
    for voter in &mut voters {
        assert_record(voter, fence, 1, "before-fence");
    }

    assert!(matches!(
        voters[target].command(&QualificationNodeCommand::FenceStorageForTest),
        QualificationNodeReply::StorageFenceArmed
    ));
    // The readiness reply proves the server accepted this input before the
    // test releases the fence. Keep it open after the one-byte trigger so the
    // ordinary command reader stalls without another complete request.
    let mut stalled_client = if stdio {
        let voter = &mut voters[target];
        let (_, replies) = voter.stdio.as_ref().unwrap();
        assert!(matches!(
            receive_stdio_reply(&mut voter.server, replies, "fence input ready"),
            QualificationNodeReply::StorageFenceReady
        ));
        None
    } else {
        let mut client = UnixStream::connect(&sockets[target]).expect("stall control input");
        client
            .set_read_timeout(Some(PROCESS_TIMEOUT))
            .expect("bound fence handshake");
        assert!(matches!(
            read_bounded_json_line(&mut BufReader::new(&mut client)).expect("read fence handshake"),
            Some(QualificationNodeReply::StorageFenceReady)
        ));
        Some(client)
    };
    assert!(
        voters[target].server.child.try_wait().unwrap().is_none(),
        "the armed fence must await the client's explicit trigger"
    );
    let deadline = Instant::now() + EXIT_BOUND;
    if let Some(client) = stalled_client.as_mut() {
        client.write_all(b" ").expect("release control fence");
    } else {
        voters[target]
            .stdio
            .as_mut()
            .unwrap()
            .0
            .write_all(b" ")
            .expect("release stdio fence");
    }
    let status = loop {
        if let Some(status) = voters[target]
            .server
            .child
            .try_wait()
            .expect("observe self exit")
        {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "fenced voter did not exit itself within five seconds"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        status.code(),
        Some(74),
        "exit must identify the terminal storage fence"
    );
    drop(stalled_client);
    assert!(
        std::net::TcpStream::connect_timeout(&addresses[target], Duration::from_millis(100))
            .is_err(),
        "exit must close the consensus listener"
    );
    if !stdio {
        assert!(UnixStream::connect(&sockets[target]).is_err());
    }

    let deadline = Instant::now() + FLEET_READY_TIMEOUT;
    while !voters[writer].ready() {
        assert!(
            Instant::now() < deadline,
            "surviving quorum must recover authority"
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert_record(&mut voters[writer], fence, 1, "before-fence");
    assert!(matches!(
        voters[writer].command(&write(2, "during-restart")),
        QualificationNodeReply::CompareAndSet { applied: true, .. }
    ));
    // Model only the supervisor's ordinary spawn. Reuse every durable path
    // and the stale control socket without deleting or repairing anything.
    voters[target] = Voter::start(
        &configs[target],
        target,
        addresses[target],
        &sockets[target],
        stdio,
    );
    assert!(matches!(
        voters[target].command(&QualificationNodeCommand::Initialize),
        QualificationNodeReply::Initialized
    ));
    let deadline = Instant::now() + FLEET_READY_TIMEOUT;
    while !voters.iter_mut().all(Voter::ready) {
        assert!(Instant::now() < deadline, "restarted voter must rejoin");
        thread::sleep(Duration::from_millis(50));
    }
    for voter in &mut voters {
        assert_record(voter, fence, 2, "during-restart");
    }
    // Observe healthy incarnations for the same complete bound used for the
    // terminal exit; normal operation and restart must not arm an exit timer.
    let deadline = Instant::now() + EXIT_BOUND;
    while Instant::now() < deadline {
        for voter in &mut voters {
            assert!(voter
                .server
                .child
                .try_wait()
                .expect("healthy voter status")
                .is_none());
        }
        thread::sleep(Duration::from_millis(20));
    }
    for voter in &mut voters {
        assert!(matches!(
            voter.command(&QualificationNodeCommand::Shutdown),
            QualificationNodeReply::ShuttingDown
        ));
        assert!(
            voter.server.wait_for_exit().success(),
            "orderly shutdown stays successful"
        );
    }
}

#[test]
fn fenced_control_voter_exits_and_rejoins_with_committed_state() {
    fenced_voter_exits_and_rejoins(false);
}

#[test]
fn fenced_stdio_voter_exits_and_rejoins_with_committed_state() {
    fenced_voter_exits_and_rejoins(true);
}
