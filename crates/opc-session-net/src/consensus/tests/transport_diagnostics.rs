use super::*;
use std::process::{Command, Stdio};

const PROBE: &str = "consensus::tests::transport_diagnostics::connection_outcomes_are_attributed_only_with_test_control";
const CHILD: &str = "OPC_TRANSPORT_DIAGNOSTIC_PROBE";

async fn exercise_real_connection_failures() {
    let (server_binding, client_binding) = bindings();
    let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
    let (server, address) = SessionConsensusServer::from_transport(
        handler.clone(),
        None,
        SessionMembershipAdmission::from_current_binding(server_binding),
    )
    .listen("127.0.0.1:0".parse().expect("loopback"))
    .await
    .expect("listen");
    let before = METRICS
        .session_net_connection_failure_transport
        .load(Ordering::Relaxed);
    let stream = TcpStream::connect(address).await.expect("inbound TCP");
    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), async {
        while METRICS
            .session_net_connection_failure_transport
            .load(Ordering::Relaxed)
            != before + 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed pre-Hello connection is accounted");
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    server.abort_and_wait().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("peer listener");
    let address = listener.local_addr().expect("peer address");
    let close_before_ack = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("outbound accepted");
        let _: SessionConsensusBootstrapRequest = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
            .await
            .expect("complete Hello");
        // The actual TCP close occurs at the HelloAck boundary.
    });
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let peer = RemoteSessionConsensusPeer::from_transport(
        ConsensusTarget::resolved(&client_binding, resolver),
        None,
        client_binding.clone(),
        Some(Duration::from_secs(2)),
    );
    let request = SessionConsensusWireRequest::try_new(
        client_binding.consensus_identity(),
        client_binding.local_consensus_node_id(),
        ConsensusRpcFamily::Vote,
        b"diagnostic-probe".to_vec(),
    )
    .expect("bounded request");
    assert_eq!(
        peer.call(request).await,
        Err(SessionConsensusPeerError::Unavailable)
    );
    close_before_ack.await.expect("peer task");
    assert_eq!(
        METRICS
            .session_net_connection_failure_transport
            .load(Ordering::Relaxed),
        before + 2
    );
}

fn finish(mut child: std::process::Child) -> std::process::Output {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while matches!(child.try_wait(), Ok(None)) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if matches!(child.try_wait(), Ok(None)) {
        let _ = child.kill();
        let _ = child.wait();
        panic!("diagnostic probe blocked on its stderr sink");
    }
    child.wait_with_output().expect("probe output")
}

fn probe(stderr: Stdio) -> std::process::Output {
    finish(
        Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", PROBE, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .expect("probe child"),
    )
}

fn assert_probe_passed(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}

#[test]
fn connection_outcomes_are_attributed_only_with_test_control() {
    if std::env::var_os(CHILD).is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(exercise_real_connection_failures());
        return;
    }
    let output = probe(Stdio::piped());
    assert_probe_passed(&output);
    #[cfg(feature = "test-control")]
    {
        use crate::qualification_diagnostics::{ConnectionFailure, TRANSPORT_FAILURE_PREFIX};
        let stderr = std::str::from_utf8(&output.stderr).expect("structured stderr");
        let events = stderr
            .lines()
            .map(|line| {
                serde_json::from_str::<ConnectionFailure>(
                    line.strip_prefix(TRANSPORT_FAILURE_PREFIX)
                        .expect("only diagnostic records"),
                )
                .expect("valid event")
            })
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert_eq!(
            (
                &events[0].origin[..],
                &events[0].stage[..],
                &events[0].outcome[..]
            ),
            ("consensus-inbound", "hello-read", "Io")
        );
        assert_eq!(
            (
                &events[1].origin[..],
                &events[1].stage[..],
                &events[1].outcome[..]
            ),
            ("consensus-outbound", "ack-read", "Unavailable")
        );
        assert_eq!(events[0].counter, 1);
        assert_eq!(events[1].counter, 2);
        assert_ne!(events[0].connection_id, events[1].connection_id);
        for event in &events {
            assert_ne!(event.connection_id, 0);
            assert_eq!(event.io_kind.as_deref(), Some("UnexpectedEof"));
            assert!(event.local_addr.expect("local endpoint").ip().is_loopback());
            assert!(event.peer_addr.expect("remote endpoint").ip().is_loopback());
        }
        assert!(events[1].local_node.is_some());
        assert!(events[1].remote_node.is_some());
    }
    #[cfg(not(feature = "test-control"))]
    {
        assert!(
            output.stderr.is_empty(),
            "production diagnostics must be silent"
        );
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            use std::os::fd::OwnedFd;
            use std::os::unix::net::UnixStream;
            let failing = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("failing stderr");
            assert_probe_passed(&probe(Stdio::from(failing)));
            let (mut writer, reader) = UnixStream::pair().expect("stderr pair");
            writer.set_nonblocking(true).expect("nonblocking fill");
            loop {
                match writer.write(&[0; 8192]) {
                    Ok(0) => panic!("stderr closed"),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("fill stderr: {error}"),
                }
            }
            writer
                .set_nonblocking(false)
                .expect("blocking child stderr");
            let descriptor: OwnedFd = writer.into();
            assert_probe_passed(&probe(Stdio::from(descriptor)));
            drop(reader);
        }
    }
}
