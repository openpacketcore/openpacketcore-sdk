mod tcp_consensus_common;

use opc_persist::{
    ClusterMembership, ConsensusConfigStore, ConsensusPeer, ConsensusRpcFamily, ConsensusRpcStage,
    InstallSnapshotRequest, NodeIdentity, PersistErrorKind, RequestVoteRequest, SqliteBackend,
    TcpPeer, TimeoutNowRequest,
};
use std::sync::Arc;
use std::time::Duration;
use tcp_consensus_common::{generate_test_ca_and_identities, test_audit_key};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn build_test_acceptor(identity: NodeIdentity) -> tokio_rustls::TlsAcceptor {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(
            temp_dir.path().join("deadline-server.db"),
            true,
            0,
            test_audit_key(),
        )
        .await
        .unwrap(),
    );
    let store = ConsensusConfigStore::new(
        1,
        backend,
        Some(ClusterMembership {
            cluster_id: "deadline-test".to_string(),
            node_id: 1,
            voting_members: vec![0, 1],
            non_voting_members: vec![],
            old_voting_members: None,
            removed_members: vec![],
            epoch: 1,
        }),
        None,
    )
    .await
    .unwrap();
    store.set_identity(identity).await.unwrap();
    store.build_tls_acceptor().await.unwrap()
}

async fn configured_peer(
    addr: String,
    identity: NodeIdentity,
    timeout: Duration,
    cluster_id: String,
) -> TcpPeer {
    let peer = TcpPeer::new(1, addr, timeout);
    peer.set_identity(identity).await.unwrap();
    peer.set_auth(0, cluster_id, String::new()).await.unwrap();
    peer
}

fn vote_request() -> RequestVoteRequest {
    RequestVoteRequest {
        term: 1,
        candidate_id: 0,
        last_log_index: 0,
        last_log_term: 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawServerEvent {
    Accepted,
    Closed,
}

#[tokio::test]
async fn tls_blackhole_uses_one_deadline_and_cancels_the_connection() {
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            event_tx.send(RawServerEvent::Accepted).unwrap();
            let event_tx = event_tx.clone();
            tokio::spawn(async move {
                let mut received = Vec::new();
                let _ = stream.read_to_end(&mut received).await;
                let _ = event_tx.send(RawServerEvent::Closed);
            });
        }
    });
    let rpc_timeout = Duration::from_millis(80);
    let peer = configured_peer(
        addr,
        identities.get(&0).unwrap().clone(),
        rpc_timeout,
        "deadline-test".to_string(),
    )
    .await;

    let started = tokio::time::Instant::now();
    let error = peer.request_vote(vote_request()).await.unwrap_err();
    let elapsed = started.elapsed();

    assert_eq!(
        error.consensus_rpc_timeout_context(),
        Some((
            ConsensusRpcFamily::RequestVote,
            ConsensusRpcStage::TlsHandshake,
        ))
    );
    assert!(
        elapsed >= rpc_timeout && elapsed <= rpc_timeout + Duration::from_millis(200),
        "TLS stall exceeded one deadline plus tolerance: timeout={rpc_timeout:?} elapsed={elapsed:?}"
    );

    let mut accepted = 0;
    let mut saw_close = false;
    let event_deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    while tokio::time::Instant::now() < event_deadline && !saw_close {
        if let Ok(Some(event)) = tokio::time::timeout_at(event_deadline, event_rx.recv()).await {
            match event {
                RawServerEvent::Accepted => accepted += 1,
                RawServerEvent::Closed => saw_close = true,
            }
        }
    }
    assert!(
        saw_close,
        "deadline did not cancel and close the TLS attempt"
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    while let Ok(event) = event_rx.try_recv() {
        if event == RawServerEvent::Accepted {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 1, "a retry started after the logical deadline");
    server.abort();
}

#[derive(Debug, Clone, Copy)]
enum ResponseStall {
    Length,
    Body,
}

#[tokio::test]
async fn response_length_and_body_stalls_share_the_logical_deadline() {
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    let acceptor = build_test_acceptor(identities.get(&1).unwrap().clone()).await;

    for (stall, expected_stage) in [
        (ResponseStall::Length, ConsensusRpcStage::ResponseLength),
        (ResponseStall::Body, ConsensusRpcStage::ResponseBody),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let acceptor = acceptor.clone();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut request = vec![0u8; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).await.unwrap();
            if matches!(stall, ResponseStall::Body) {
                stream.write_all(&128u32.to_be_bytes()).await.unwrap();
                stream.write_all(b"{").await.unwrap();
                stream.flush().await.unwrap();
            }
            let mut remaining = Vec::new();
            let _ = stream.read_to_end(&mut remaining).await;
            let _ = closed_tx.send(());
        });
        let rpc_timeout = Duration::from_millis(80);
        let peer = configured_peer(
            addr,
            identities.get(&0).unwrap().clone(),
            rpc_timeout,
            "deadline-test".to_string(),
        )
        .await;

        let started = tokio::time::Instant::now();
        let error = peer.request_vote(vote_request()).await.unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(
            error.consensus_rpc_timeout_context(),
            Some((ConsensusRpcFamily::RequestVote, expected_stage))
        );
        assert!(
            elapsed >= rpc_timeout && elapsed <= rpc_timeout + Duration::from_millis(200),
            "{stall:?} stall exceeded one deadline plus tolerance: timeout={rpc_timeout:?} elapsed={elapsed:?}"
        );
        tokio::time::timeout(Duration::from_millis(250), closed_rx)
            .await
            .expect("deadline did not promptly close the stalled response socket")
            .expect("response close probe was dropped");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn blocked_request_write_cannot_reset_the_deadline() {
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    let acceptor = build_test_acceptor(identities.get(&1).unwrap().clone()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (inspect_tx, inspect_rx) = tokio::sync::oneshot::channel();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        inspect_rx.await.unwrap();
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received).await;
        let _ = closed_tx.send(());
    });
    let rpc_timeout = Duration::from_millis(500);
    let peer = configured_peer(
        addr,
        identities.get(&0).unwrap().clone(),
        rpc_timeout,
        "x".repeat(4 * 1024 * 1024),
    )
    .await;

    let started = tokio::time::Instant::now();
    let error = peer.request_vote(vote_request()).await.unwrap_err();
    let elapsed = started.elapsed();

    assert_eq!(
        error.consensus_rpc_timeout_context(),
        Some((
            ConsensusRpcFamily::RequestVote,
            ConsensusRpcStage::RequestWrite,
        ))
    );
    assert!(
        elapsed >= rpc_timeout && elapsed <= rpc_timeout + Duration::from_millis(300),
        "request-write stall exceeded one deadline plus tolerance: timeout={rpc_timeout:?} elapsed={elapsed:?}"
    );
    inspect_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), closed_rx)
        .await
        .expect("deadline did not close the stalled request-write socket")
        .expect("request-write close probe was dropped");
    server.await.unwrap();
}

#[tokio::test]
async fn timeout_now_is_not_replayed_after_ambiguous_delivery() {
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    let acceptor = build_test_acceptor(identities.get(&1).unwrap().clone()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let accepted_tx = accepted_tx.clone();
            tokio::spawn(async move {
                let mut stream = acceptor.accept(stream).await.unwrap();
                accepted_tx.send(()).unwrap();
                let mut length = [0u8; 4];
                stream.read_exact(&mut length).await.unwrap();
                let mut request = vec![0u8; u32::from_be_bytes(length) as usize];
                stream.read_exact(&mut request).await.unwrap();
                // Drop the connection after delivery but before responding.
            });
        }
    });
    let peer = configured_peer(
        addr,
        identities.get(&0).unwrap().clone(),
        Duration::from_millis(500),
        "deadline-test".to_string(),
    )
    .await;

    let error = peer
        .timeout_now(TimeoutNowRequest {
            term: 1,
            candidate_id: 1,
        })
        .await
        .unwrap_err();

    assert!(!error.is_consensus_rpc_timeout());
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut accepted = 0;
    while accepted_rx.try_recv().is_ok() {
        accepted += 1;
    }
    assert_eq!(accepted, 1, "TimeoutNow was replayed after delivery");
    server.abort();
}

#[tokio::test]
async fn hostile_remote_error_text_is_discarded_at_the_client_boundary() {
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    let acceptor = build_test_acceptor(identities.get(&1).unwrap().clone()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let hostile_error = format!(
        "token=peer-secret path=/var/lib/opc/private.db spiffe://tenant/workload\n{}TAIL_MARKER",
        "x".repeat(1024 * 1024)
    );
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut request_length = [0u8; 4];
        stream.read_exact(&mut request_length).await.unwrap();
        let mut request = vec![0u8; u32::from_be_bytes(request_length) as usize];
        stream.read_exact(&mut request).await.unwrap();

        let response = serde_json::json!({
            "response": {
                "InstallSnapshot": {
                    "Err": hostile_error,
                }
            }
        });
        let response = serde_json::to_vec(&response).unwrap();
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let peer = configured_peer(
        addr,
        identities.get(&0).unwrap().clone(),
        Duration::from_secs(2),
        "deadline-test".to_string(),
    )
    .await;

    let error = peer
        .install_snapshot(InstallSnapshotRequest {
            term: 1,
            leader_id: 0,
            last_included_index: 1,
            last_included_term: 1,
            data: vec![],
        })
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(matches!(
        error.kind(),
        PersistErrorKind::Io(message)
            if message == "remote consensus RPC failed family=install_snapshot"
    ));
    let debug = format!("{error:?}");
    for leaked in [
        "peer-secret",
        "/var/lib/opc/private.db",
        "spiffe://tenant/workload",
        "TAIL_MARKER",
    ] {
        assert!(!debug.contains(leaked), "Debug leaked {leaked}");
    }
    assert!(
        debug.len() < 256,
        "peer error produced an unbounded Debug value"
    );
}
