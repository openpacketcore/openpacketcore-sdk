use super::*;

#[test]
fn transport_failure_attribution_selects_the_exact_process_and_counter_interval() {
    use opc_session_net::qualification_diagnostics::{ConnectionFailure, TRANSPORT_FAILURE_PREFIX};
    let mut stderr = b"unrelated child stderr\n".to_vec();
    for (process_id, counter) in [(7, 1), (7, 2), (6, 3), (7, 3), (7, 4), (7, 5)] {
        let event = serde_json::json!({
            "process_id": process_id, "counter": counter, "connection_id": counter + 10,
            "origin": "consensus-inbound", "stage": "hello-read", "outcome": "Io",
            "io_kind": "UnexpectedEof", "local_addr": "127.0.0.1:4000", "peer_addr": "127.0.0.1:5000",
            "local_node": null, "remote_node": null, "generation": 0, "material_epoch": 0,
        });
        let event: ConnectionFailure = serde_json::from_value(event).expect("closed event schema");
        stderr.extend_from_slice(TRANSPORT_FAILURE_PREFIX.as_bytes());
        stderr.extend_from_slice(&serde_json::to_vec(&event).expect("event JSON"));
        stderr.push(b'\n');
    }
    stderr.extend_from_slice(b"qualification_transport_failure malformed\n");
    let events = transport_failures_in_window(
        &stderr,
        7,
        TransportFailureWindow {
            node_index: 0,
            before: 2,
            after: 4,
        },
    );
    assert_eq!(
        events.iter().map(|event| event.counter).collect::<Vec<_>>(),
        vec![3, 4]
    );
    assert!(
        events
            .iter()
            .all(|event| event.connection_id != 0
                && event.io_kind.as_deref() == Some("UnexpectedEof"))
    );
}

#[test]
fn transport_failure_preserves_complete_stderr_after_the_fleet_workspace_is_removed() {
    let workspace = tempfile::tempdir().expect("fleet workspace");
    let evidence = tempfile::tempdir().expect("failure evidence");
    let paths = (0..3)
        .map(|node| workspace.path().join(format!("node-{node}.stderr")))
        .collect::<Vec<_>>();
    let mut expected = vec![b'x'; 32 * 1024];
    expected.extend_from_slice(&[0, 255, b'\n']);
    for path in &paths {
        fs::write(path, &expected).expect("child stderr");
    }
    let retained = retain_child_stderr(&paths, evidence.path()).expect("retain exact bytes");
    assert!(retained.unavailable.is_empty());
    drop(workspace);
    assert_eq!(
        fs::metadata(&retained.path)
            .expect("retained directory")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for node in 0..3 {
        assert_eq!(
            fs::read(retained.path.join(format!("node-{node}.stderr"))).expect("retained stderr"),
            expected
        );
    }
}

#[test]
fn transport_failure_diagnostics_never_queue_behind_an_outstanding_command() {
    let workspace = tempfile::tempdir().expect("child fixture");
    let mut child = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("idle child");
    let stdin = child.stdin.take().expect("child stdin");
    let (_sender, replies) = mpsc::channel();
    let pending = PendingCommand {
        kind: PendingCommandKind::from_command(&QualificationNodeCommand::TrafficStatusSnapshot),
        sequence: 4,
        sent_at: Instant::now(),
    };
    let mut node = ChildNode {
        child,
        stdin: Some(BufWriter::new(stdin)),
        replies,
        reader: None,
        node_index: 0,
        stderr_path: workspace.path().join("stderr"),
        pending: Some(pending),
        next_command_sequence: 5,
        initialization_stderr: None,
    };
    assert!(!node.try_send_failure_diagnostics(Instant::now() + Duration::from_secs(1)));
    assert_eq!(node.next_command_sequence, 5);
    assert_eq!(node.pending.expect("original command retained").sequence, 4);
    assert!(node
        .stdin
        .as_ref()
        .expect("stdin unchanged")
        .buffer()
        .is_empty());
    node.pending = None;
    assert!(!node.try_send_failure_diagnostics(Instant::now()));
    assert!(node.pending.is_none());
    assert_eq!(node.next_command_sequence, 5);
    node.child.kill().expect("exit child");
    node.child.wait().expect("reap child");
    assert!(!node.try_send_failure_diagnostics(Instant::now() + Duration::from_secs(1)));
    assert_eq!(node.next_command_sequence, 5);
}

#[test]
fn transport_failure_retains_available_children_when_one_stderr_file_is_missing() {
    let workspace = tempfile::tempdir().expect("fleet workspace");
    let evidence = tempfile::tempdir().expect("failure evidence");
    let paths = [
        workspace.path().join("missing"),
        workspace.path().join("available"),
    ];
    fs::write(&paths[1], b"retained child outcome\n").expect("child stderr");
    let retained =
        retain_child_stderr(&paths, evidence.path()).expect("available evidence survives");
    drop(workspace);
    assert_eq!(retained.unavailable, vec![(0, io::ErrorKind::NotFound)]);
    assert_eq!(
        fs::read(retained.path.join("node-1.stderr")).expect("available child retained"),
        b"retained child outcome\n"
    );
}
