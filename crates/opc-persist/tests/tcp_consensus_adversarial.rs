mod common;
mod tcp_consensus_common;

use opc_persist::{
    ClusterMembership, ConsensusConfigStore, ConsensusMetricsDump, ConsensusPeer, TcpPeer,
    TcpRpcServer,
};
use std::sync::Arc;
use tcp_consensus_common::{
    generate_custom_identity, generate_test_ca_and_identities, test_audit_key, SqliteBackend,
};
use tempfile::TempDir;
use tokio::time::{sleep, Duration, Instant};

fn get_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_metrics<F>(
    store: &ConsensusConfigStore,
    timeout: Duration,
    mut predicate: F,
) -> ConsensusMetricsDump
where
    F: FnMut(&ConsensusMetricsDump) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        let metrics = store.dump_metrics().await.unwrap();
        if predicate(&metrics) || Instant::now() >= deadline {
            return metrics;
        }
        sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn test_adversarial_active_connections_desync() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("conn_desync_test.db");
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .unwrap(),
    );

    let membership = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let store = Arc::new(
        ConsensusConfigStore::new(0, backend, Some(membership), None)
            .await
            .unwrap(),
    );
    let (_, _, identities) = generate_test_ca_and_identities(&[0]);
    store
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();

    let port = get_free_port();
    let server = TcpRpcServer::new(store.clone(), format!("127.0.0.1:{port}"));
    let handle = server.start().await.unwrap();

    // 1. Parallel connection spikes with immediate/abnormal disconnections.
    let mut tasks = Vec::new();
    for _ in 0..80 {
        let addr = format!("127.0.0.1:{port}");
        tasks.push(tokio::spawn(async move {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
                // Send some random bytes to start a handshake or handshake attempt
                let _ = tokio::io::AsyncWriteExt::write_all(
                    &mut stream,
                    &[0x16, 0x03, 0x01, 0x00, 0x80],
                )
                .await;
                // Sleep tiny amount and close abruptly
                sleep(Duration::from_millis(5)).await;
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }

    // Give the server time to process disconnections and timeout/error cleanup
    sleep(Duration::from_millis(500)).await;

    // Verify active connections return to 0 and did not leak/desync
    let m = store.dump_metrics().await.unwrap();
    assert_eq!(
        m.server_active_connections, 0,
        "Active connections must return to 0, got {}",
        m.server_active_connections
    );
    assert!(
        m.auth_failures > 0,
        "Should have auth/handshake failures registered"
    );

    server.shutdown().await;
    let _ = handle.await;
}

#[tokio::test]
async fn test_adversarial_connection_limit_no_stall() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("conn_limit_stall_test.db");
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .unwrap(),
    );

    let membership = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let store = Arc::new(
        ConsensusConfigStore::new(0, backend, Some(membership), None)
            .await
            .unwrap(),
    );
    let (_, _, identities) = generate_test_ca_and_identities(&[0]);
    store
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();

    let port = get_free_port();
    let server = TcpRpcServer::new(store.clone(), format!("127.0.0.1:{port}"));
    let handle = server.start().await.unwrap();

    // 1. Establish 100 connections and leave them open.
    //
    // Under full-workspace test load the accept loop may take longer than a
    // fixed 200 ms to account for every connection. Poll the metric instead of
    // racing the listener; this test is about the connection limit, not accept
    // loop scheduling jitter.
    let mut connections = Vec::new();
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..100 {
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .expect("initial connection should be accepted by the OS");
        connections.push(stream);
        sleep(Duration::from_millis(2)).await;
    }

    let m1 = wait_for_metrics(&store, Duration::from_secs(3), |m| {
        m.server_active_connections == 100
    })
    .await;
    assert_eq!(m1.server_active_connections, 100);
    assert_eq!(m1.server_rejected_connections, 0);

    // 2. Establish 150 connections sequentially to avoid OS file descriptor limits (256 FDs limit).
    // As each connection is rejected and closed, its FD is released before the next connection is made.
    let mut rejected_count = 0;
    for _ in 0..150 {
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                // Try to read. Since the server drops the connection, this should return EOF (Ok(0))
                let mut buf = [0u8; 1];
                use tokio::io::AsyncReadExt;
                let _ = stream.read(&mut buf).await;
                rejected_count += 1;
            }
            Err(e) => {
                println!("Connect error: {e:?}");
            }
        }
    }

    let m2 = wait_for_metrics(&store, Duration::from_secs(3), |m| {
        m.server_active_connections == 100 && m.server_rejected_connections >= 150
    })
    .await;

    // Check that we rejected exactly 150 connections and didn't stall
    assert_eq!(m2.server_active_connections, 100);
    assert_eq!(rejected_count, 150);
    assert_eq!(m2.server_rejected_connections, 150);

    // Drop the original 100 connections
    drop(connections);

    let m3 = wait_for_metrics(&store, Duration::from_secs(3), |m| {
        m.server_active_connections == 0
    })
    .await;
    assert_eq!(m3.server_active_connections, 0);

    server.shutdown().await;
    let _ = handle.await;
}

#[tokio::test]
async fn test_adversarial_auth_failures_types() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("auth_failures_test.db");
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .unwrap(),
    );

    let membership = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let store = Arc::new(
        ConsensusConfigStore::new(0, backend, Some(membership), None)
            .await
            .unwrap(),
    );
    let (ca_cert, ca_key_pair, identities) = generate_test_ca_and_identities(&[0]);
    store
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();

    let port = get_free_port();
    let server = TcpRpcServer::new(store.clone(), format!("127.0.0.1:{port}"));
    let handle = server.start().await.unwrap();

    // Mode A: Plain TCP handshake, send some garbage, and close.
    {
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, b"NOT A TLS CLIENT HELLO").await;
        // Wait for server to process/close
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let m_a = store.dump_metrics().await.unwrap();
    assert_eq!(m_a.auth_failures, 1);
    assert_eq!(m_a.server_rejected_connections, 1);

    // Mode B: Connect with expired certificate.
    {
        // Expired identity signed by the same CA
        let expired_identity = generate_custom_identity(
            &ca_cert,
            &ca_key_pair,
            "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
            true, // expired
        );
        let peer = TcpPeer::new(
            0,
            format!("127.0.0.1:{port}"),
            std::time::Duration::from_millis(150),
        );
        peer.set_identity(expired_identity).await.unwrap();
        peer.set_auth(
            0,
            "tcp-test-cluster".to_string(),
            "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0"
                .to_string(),
        )
        .await
        .unwrap();
        let _ = peer.load_latest_consensus_rpc().await; // Should fail TLS handshake due to validity check
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let m_b = store.dump_metrics().await.unwrap();
    // Auth failures should have incremented
    assert!(m_b.auth_failures > m_a.auth_failures);

    // Mode C: Connect with valid TLS cert but bad SPIFFE ID format (e.g. wrong parts count).
    {
        // Cert is signed by the CA but has a malformed SPIFFE ID
        let bad_spiffe_identity = generate_custom_identity(
            &ca_cert,
            &ca_key_pair,
            "spiffe://test/bad-spiffe-id-format",
            false, // not expired
        );
        let peer = TcpPeer::new(
            0,
            format!("127.0.0.1:{port}"),
            std::time::Duration::from_millis(150),
        );
        peer.set_identity(bad_spiffe_identity).await.unwrap();
        peer.set_auth(
            0,
            "tcp-test-cluster".to_string(),
            "spiffe://test/bad-spiffe-id-format".to_string(),
        )
        .await
        .unwrap();
        let _ = peer.load_latest_consensus_rpc().await; // Should fail SPIFFE ID check
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let m_c = store.dump_metrics().await.unwrap();
    assert!(m_c.auth_failures > m_b.auth_failures);

    server.shutdown().await;
    let _ = handle.await;
}
