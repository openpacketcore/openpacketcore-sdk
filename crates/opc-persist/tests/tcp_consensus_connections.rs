mod common;
mod tcp_consensus_common;

use opc_persist::{
    ClusterMembership, ConsensusClock, ConsensusConfigStore, ConsensusPeer, Role, TcpPeer,
    TcpRpcServer,
};
use std::sync::Arc;
use tcp_consensus_common::{
    generate_custom_identity, generate_test_ca_and_identities, test_audit_key, SqliteBackend,
};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn test_tcp_consensus_mtls_validation_and_failures() {
    let temp_dir = TempDir::new().unwrap();
    let (ca_cert, ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1]);

    let db_path_0 = temp_dir.path().join("mtls_test_0.db");
    let backend_0 = Arc::new(
        SqliteBackend::open_with_audit_key(&db_path_0, true, 0, test_audit_key())
            .await
            .unwrap(),
    );
    let membership_0 = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0, 1],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let store_0 = Arc::new(
        ConsensusConfigStore::new(0, backend_0, Some(membership_0), None)
            .await
            .unwrap(),
    );
    store_0
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();
    let server_0 = TcpRpcServer::new(store_0.clone(), "127.0.0.1:16400".to_string());
    let handle_0 = server_0.start().await.unwrap();

    let db_path_1 = temp_dir.path().join("mtls_test_1.db");
    let backend_1 = Arc::new(
        SqliteBackend::open_with_audit_key(&db_path_1, true, 0, test_audit_key())
            .await
            .unwrap(),
    );
    let membership_1 = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 1,
        voting_members: vec![0, 1],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let store_1 = Arc::new(
        ConsensusConfigStore::new(1, backend_1, Some(membership_1), None)
            .await
            .unwrap(),
    );
    store_1
        .set_identity(identities.get(&1).unwrap().clone())
        .await
        .unwrap();
    let server_1 = TcpRpcServer::new(store_1.clone(), "127.0.0.1:16401".to_string());
    let handle_1 = server_1.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 1. Test wrong cluster ID
    let bad_peer = TcpPeer::new(
        1,
        "127.0.0.1:16401".to_string(),
        std::time::Duration::from_millis(150),
    );
    bad_peer
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();
    bad_peer
        .set_auth(0, "wrong-cluster".to_string(), "".to_string())
        .await
        .unwrap();
    let err_cluster = bad_peer
        .append_entries(opc_persist::AppendEntriesRequest {
            term: 1,
            leader_id: 0,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        })
        .await
        .unwrap_err();
    assert!(
        err_cluster.to_string().contains("redacted")
            || err_cluster.to_string().contains("unauthenticated")
            || err_cluster.to_string().contains("safety error")
    );

    // 2. Test wrong target node ID
    let bad_peer_target = TcpPeer::new(
        2,
        "127.0.0.1:16401".to_string(),
        std::time::Duration::from_millis(150),
    );
    bad_peer_target
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();
    bad_peer_target
        .set_auth(0, "tcp-test-cluster".to_string(), "".to_string())
        .await
        .unwrap();
    let err_target = bad_peer_target
        .append_entries(opc_persist::AppendEntriesRequest {
            term: 1,
            leader_id: 0,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        })
        .await
        .unwrap_err();
    assert!(
        err_target.to_string().contains("redacted")
            || err_target.to_string().contains("unauthenticated")
            || err_target.to_string().contains("safety error")
    );

    // 3. Test invalid SPIFFE ID (Impersonation / invalid suffix)
    let bad_peer_spiffe = TcpPeer::new(
        1,
        "127.0.0.1:16401".to_string(),
        std::time::Duration::from_millis(150),
    );
    let spiffe_999 =
        "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/999";
    let identity_999 = generate_custom_identity(&ca_cert, &ca_key_pair, spiffe_999, false);
    bad_peer_spiffe.set_identity(identity_999).await.unwrap();
    bad_peer_spiffe
        .set_auth(0, "tcp-test-cluster".to_string(), "".to_string())
        .await
        .unwrap();
    let err_spiffe = bad_peer_spiffe
        .append_entries(opc_persist::AppendEntriesRequest {
            term: 1,
            leader_id: 0,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        })
        .await
        .unwrap_err();
    assert!(
        err_spiffe.to_string().contains("redacted")
            || err_spiffe.to_string().contains("unauthenticated")
            || err_spiffe.to_string().contains("safety error")
    );

    // 4. Test unknown node
    let bad_peer_unknown = TcpPeer::new(
        1,
        "127.0.0.1:16401".to_string(),
        std::time::Duration::from_millis(150),
    );
    let identity_unknown = generate_custom_identity(&ca_cert, &ca_key_pair, spiffe_999, false);
    bad_peer_unknown
        .set_identity(identity_unknown)
        .await
        .unwrap();
    bad_peer_unknown
        .set_auth(999, "tcp-test-cluster".to_string(), "".to_string())
        .await
        .unwrap();
    let err_unknown = bad_peer_unknown
        .append_entries(opc_persist::AppendEntriesRequest {
            term: 1,
            leader_id: 999,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        })
        .await
        .unwrap_err();
    assert!(
        err_unknown.to_string().contains("redacted")
            || err_unknown.to_string().contains("unauthenticated")
            || err_unknown.to_string().contains("safety error")
    );

    // 5. Test cert verification failure
    let bad_peer_san = TcpPeer::new(
        1,
        "127.0.0.1:16401".to_string(),
        std::time::Duration::from_millis(150),
    );
    let identity_san =
        generate_custom_identity(&ca_cert, &ca_key_pair, "spiffe://test/wrong-san", false);
    bad_peer_san.set_identity(identity_san).await.unwrap();
    bad_peer_san
        .set_auth(0, "tcp-test-cluster".to_string(), "".to_string())
        .await
        .unwrap();
    let err_san = bad_peer_san
        .append_entries(opc_persist::AppendEntriesRequest {
            term: 1,
            leader_id: 0,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        })
        .await
        .unwrap_err();
    assert!(
        err_san.to_string().contains("redacted")
            || err_san.to_string().contains("unauthenticated")
            || err_san.to_string().contains("safety error")
    );

    // 6. Test wrong trust domain
    let bad_peer_td = TcpPeer::new(
        1,
        "127.0.0.1:16401".to_string(),
        std::time::Duration::from_millis(150),
    );
    let spiffe_td =
        "spiffe://wrong-domain/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
    let identity_td = generate_custom_identity(&ca_cert, &ca_key_pair, spiffe_td, false);
    bad_peer_td.set_identity(identity_td).await.unwrap();
    bad_peer_td
        .set_auth(0, "tcp-test-cluster".to_string(), "".to_string())
        .await
        .unwrap();
    let err_td = bad_peer_td
        .append_entries(opc_persist::AppendEntriesRequest {
            term: 1,
            leader_id: 0,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        })
        .await
        .unwrap_err();
    assert!(
        err_td.to_string().contains("redacted")
            || err_td.to_string().contains("unauthenticated")
            || err_td.to_string().contains("safety error")
    );

    // 7. Test expired certificate
    let bad_peer_expired = TcpPeer::new(
        1,
        "127.0.0.1:16401".to_string(),
        std::time::Duration::from_millis(150),
    );
    let spiffe_expired =
        "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
    let identity_expired = generate_custom_identity(&ca_cert, &ca_key_pair, spiffe_expired, true);
    bad_peer_expired
        .set_identity(identity_expired)
        .await
        .unwrap();
    bad_peer_expired
        .set_auth(0, "tcp-test-cluster".to_string(), "".to_string())
        .await
        .unwrap();
    let err_expired = bad_peer_expired
        .append_entries(opc_persist::AppendEntriesRequest {
            term: 1,
            leader_id: 0,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        })
        .await
        .unwrap_err();
    assert!(
        err_expired.to_string().contains("redacted")
            || err_expired.to_string().contains("unauthenticated")
            || err_expired.to_string().contains("safety error")
    );

    // 8. Test plain TCP connection
    let mut plain_stream = tokio::net::TcpStream::connect("127.0.0.1:16401")
        .await
        .unwrap();
    use tokio::io::AsyncWriteExt;
    plain_stream.write_all(b"Hello plain TCP!").await.unwrap();
    let mut buf = [0u8; 10];
    let read_res = plain_stream.read(&mut buf).await;
    assert!(read_res.is_ok());
    let read_len = read_res.unwrap();
    if read_len > 0 {
        let read_2 = plain_stream.read(&mut buf).await.unwrap();
        assert_eq!(read_2, 0);
    }

    server_0.shutdown().await;
    server_1.shutdown().await;
    let _ = handle_0.await;
    let _ = handle_1.await;
}

#[tokio::test]
async fn test_consensus_extended_metrics_incrementation() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("metrics_test.db");
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
    let clock = ConsensusClock {
        election_timeout_min: std::time::Duration::from_millis(150),
        election_timeout_max: std::time::Duration::from_millis(300),
        heartbeat_interval: std::time::Duration::from_millis(50),
        enable_timers: false,
    };
    let store = Arc::new(
        ConsensusConfigStore::new(0, backend, Some(membership), Some(clock))
            .await
            .unwrap(),
    );
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    store
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();

    let server = TcpRpcServer::new(store.clone(), "127.0.0.1:19100".to_string());
    let handle = server.start().await.unwrap();

    let m = store.dump_metrics().await.unwrap();
    assert_eq!(m.server_start_failures, 0);
    assert_eq!(m.auth_failures, 0);
    assert_eq!(m.server_rejected_connections, 0);
    assert_eq!(m.membership_change_attempts, 0);
    assert_eq!(m.membership_change_success, 0);
    assert_eq!(m.membership_change_failures, 0);

    let duplicate_start = server.start().await;
    assert!(duplicate_start.is_err());
    let m = store.dump_metrics().await.unwrap();
    assert_eq!(m.server_start_failures, 1);

    let bad_peer = TcpPeer::new(
        0,
        "127.0.0.1:19100".to_string(),
        std::time::Duration::from_millis(150),
    );
    bad_peer
        .set_identity(identities.get(&1).unwrap().clone())
        .await
        .unwrap();
    bad_peer
        .set_auth(1, "wrong-cluster".to_string(), "".to_string())
        .await
        .unwrap();
    let _ = bad_peer
        .append_entries(opc_persist::AppendEntriesRequest {
            term: 1,
            leader_id: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        })
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let m = store.dump_metrics().await.unwrap();
    assert!(m.auth_failures >= 1);
    assert!(m.server_rejected_connections >= 1);

    let res = store.add_node_as_non_voter(1).await;
    assert!(res.is_err());
    let m = store.dump_metrics().await.unwrap();
    assert_eq!(m.membership_change_attempts, 1);
    assert_eq!(m.membership_change_failures, 1);
    assert_eq!(m.membership_change_success, 0);

    store.campaign().await.unwrap();
    assert_eq!(store.get_role().await, Role::Leader);

    let res = store.add_node_as_non_voter(1).await;
    assert!(res.is_ok());
    let m = store.dump_metrics().await.unwrap();
    assert_eq!(m.membership_change_attempts, 2);
    assert_eq!(m.membership_change_failures, 1);
    assert_eq!(m.membership_change_success, 1);

    server.shutdown().await;
    let _ = handle.await;
}

#[tokio::test]
async fn test_consensus_metrics_leak_prevention() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("leak_test.db");
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
    let store = ConsensusConfigStore::new(0, backend, Some(membership), None)
        .await
        .unwrap();

    let m_dump = store.dump_metrics().await.unwrap();
    let serialized = serde_json::to_string(&m_dump).unwrap();

    assert!(
        !serialized.contains("spiffe://"),
        "Metrics leak SPIFFE IDs: {serialized}"
    );

    assert!(
        !serialized.contains("-----BEGIN"),
        "Metrics leak certificates: {serialized}"
    );

    assert!(
        !serialized.contains('/'),
        "Metrics leak UNIX paths: {serialized}"
    );
    assert!(
        !serialized.contains('\\'),
        "Metrics leak Windows paths: {serialized}"
    );
}

fn get_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn test_consensus_active_connections_and_limit() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("conn_limit_test.db");
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

    let mut connections = Vec::new();
    for _ in 0..100 {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await;
        if let Ok(s) = stream {
            connections.push(s);
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let m = store.dump_metrics().await.unwrap();
    assert_eq!(m.server_active_connections, connections.len() as u64);
    assert_eq!(m.server_rejected_connections, 0);

    let extra_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let m2 = store.dump_metrics().await.unwrap();
    assert_eq!(m2.server_rejected_connections, 1);

    drop(connections);
    drop(extra_stream);

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let m3 = store.dump_metrics().await.unwrap();
    assert_eq!(m3.server_active_connections, 0);

    server.shutdown().await;
    let _ = handle.await;
}

#[tokio::test]
async fn test_consensus_active_connections_handshake_timeout_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("conn_timeout_test.db");
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

    let mut connections = Vec::new();
    for _ in 0..100 {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await;
        if let Ok(s) = stream {
            connections.push(s);
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let m = store.dump_metrics().await.unwrap();
    assert_eq!(m.server_active_connections, 100);
    assert_eq!(m.server_rejected_connections, 0);

    let extra_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let m2 = store.dump_metrics().await.unwrap();
    assert_eq!(m2.server_rejected_connections, 1);

    tokio::time::sleep(std::time::Duration::from_millis(5500)).await;

    let m3 = store.dump_metrics().await.unwrap();
    assert_eq!(m3.server_active_connections, 0);
    assert_eq!(m3.server_rejected_connections, 101);
    assert!(m3.auth_failures >= 100);

    let new_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let m4 = store.dump_metrics().await.unwrap();
    assert_eq!(m4.server_active_connections, 1);

    drop(new_stream);
    drop(connections);
    drop(extra_stream);

    server.shutdown().await;
    let _ = handle.await;
}

#[tokio::test]
async fn test_consensus_active_connections_stress_concurrency() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("conn_stress_test.db");
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

    let mut connections = Vec::new();
    let mut connect_errors = 0;
    for _ in 0..200 {
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await {
            Ok(stream) => {
                connections.push(stream);
            }
            Err(_) => {
                connect_errors += 1;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(4)).await;
    }

    println!(
        "Successful connections: {}, Connect errors: {}",
        connections.len(),
        connect_errors
    );

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let m = store.dump_metrics().await.unwrap();
    assert!(m.server_active_connections <= 100);

    let total_accounted = m.server_active_connections + m.server_rejected_connections;
    let expected = connections.len() as u64;
    assert!(
        total_accounted >= expected.saturating_sub(2) && total_accounted <= expected,
        "Expected total accounted around {}, got active={}, rejected={}",
        expected,
        m.server_active_connections,
        m.server_rejected_connections
    );

    drop(connections);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let m2 = store.dump_metrics().await.unwrap();
    assert_eq!(m2.server_active_connections, 0);

    server.shutdown().await;
    let _ = handle.await;
}
