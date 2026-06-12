use opc_persist::{
    AuditKey, ClusterMembership, ConsensusConfigStore, ConsensusOp, ConsensusPeer, LogEntry,
    NodeIdentity, SqliteBackend, TcpPeer, TcpRpcServer,
};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TEST_AUDIT_KEY_BYTES: [u8; 32] = [0xA5; 32];

fn test_audit_key() -> AuditKey {
    AuditKey::new(TEST_AUDIT_KEY_BYTES).unwrap()
}

fn generate_test_ca_and_identities(
    node_ids: &[usize],
) -> (
    rcgen::Certificate,
    rcgen::KeyPair,
    std::collections::HashMap<usize, NodeIdentity>,
) {
    let ca_key_pair = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
    let ca_cert_pem = ca_cert.pem();

    let mut identities = std::collections::HashMap::new();

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

fn generate_custom_identity(
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

mod common;
use common::find_free_port_block;

fn get_free_port() -> u16 {
    find_free_port_block(1)
}

#[tokio::test]
async fn test_empirical_active_connections_desync_stress() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("stress_active_conns.db");
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .unwrap(),
    );

    let membership = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![1],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let store = Arc::new(
        ConsensusConfigStore::new(0, backend, Some(membership), None)
            .await
            .unwrap(),
    );
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    store
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();
    store.campaign().await.unwrap();

    let port = get_free_port();
    let server = TcpRpcServer::new(store.clone(), format!("127.0.0.1:{port}"));
    let handle = server.start().await.unwrap();

    // Spawn multiple tasks to cause connection spikes and disconnections.
    let mut tasks = Vec::new();

    // 1. Spammer tasks: raw TCP stream, write garbage, close immediately.
    for _ in 0..50 {
        let addr = format!("127.0.0.1:{port}");
        tasks.push(tokio::spawn(async move {
            if let Ok(mut stream) = TcpStream::connect(&addr).await {
                let _ = stream.write_all(b"GARBAGE").await;
                let _ = stream.flush().await;
            }
        }));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // 2. Hang tasks: raw TCP stream, connect, sleep, then close.
    for _ in 0..50 {
        let addr = format!("127.0.0.1:{port}");
        tasks.push(tokio::spawn(async move {
            if let Ok(_stream) = TcpStream::connect(&addr).await {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
        }));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // 3. Valid peer RPC tasks: correct handshake, do load_latest, close.
    let peer_identity = identities.get(&1).unwrap().clone();
    for _ in 0..50 {
        let addr = format!("127.0.0.1:{port}");
        let id_clone = peer_identity.clone();
        tasks.push(tokio::spawn(async move {
            let peer = TcpPeer::new(0, addr, std::time::Duration::from_millis(300));
            let _ = peer.set_identity(id_clone).await;
            let _ = peer
                .set_auth(1, "tcp-test-cluster".to_string(), "".to_string())
                .await;
            let _ = peer.load_latest_consensus_rpc().await;
        }));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Wait for all client tasks to complete.
    for t in tasks {
        let _ = t.await;
    }

    // Wait for server tasks to finish dropping resources (active connection guards etc.)
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // Active connections MUST return to exactly 0.
    let m = store.dump_metrics().await.unwrap();
    assert_eq!(
        m.server_active_connections, 0,
        "Active connections leaked: got {}",
        m.server_active_connections
    );

    server.shutdown().await;
    let _ = handle.await;
}

#[tokio::test]
async fn test_empirical_connection_rejections_no_listener_stall() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("rejections_stall.db");
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .unwrap(),
    );

    let membership = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![1],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let store = Arc::new(
        ConsensusConfigStore::new(0, backend, Some(membership), None)
            .await
            .unwrap(),
    );
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    store
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();
    store.campaign().await.unwrap();

    let port = get_free_port();
    let server = TcpRpcServer::new(store.clone(), format!("127.0.0.1:{port}"));
    let handle = server.start().await.unwrap();

    // 1. Occupy all 100 connection slots.
    let mut persistent_connections = Vec::new();
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..100 {
        let stream = TcpStream::connect(&addr).await.unwrap();
        persistent_connections.push(stream);
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    // Wait for the server tasks to spawn and increment active connections.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let m = store.dump_metrics().await.unwrap();
    assert_eq!(m.server_active_connections, 100);
    assert_eq!(m.server_rejected_connections, 0);

    // 2. Spam the server with 80 more connections, which should be rejected.
    for _ in 0..80 {
        if let Ok(stream) = TcpStream::connect(&addr).await {
            drop(stream);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Give a brief moment for the try_acquire failures to register.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let m_spam = store.dump_metrics().await.unwrap();
    assert_eq!(m_spam.server_active_connections, 100);
    assert!(
        m_spam.server_rejected_connections >= 50,
        "Expected at least 50 rejected connections, got {}",
        m_spam.server_rejected_connections
    );

    // 3. To prove that the listener thread didn't stall and is still healthy:
    // Drop 5 persistent connections, freeing up 5 slots.
    persistent_connections.truncate(95);

    // Give a brief moment for the drop to register and decrement active connections.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let m_after_drop = store.dump_metrics().await.unwrap();
    assert_eq!(m_after_drop.server_active_connections, 95);

    // Now, send a valid RPC through a new connection. It should be accepted and succeed!
    let peer_identity = identities.get(&1).unwrap().clone();
    let peer = TcpPeer::new(0, addr.clone(), std::time::Duration::from_millis(300));
    peer.set_identity(peer_identity).await.unwrap();
    peer.set_auth(1, "tcp-test-cluster".to_string(), "".to_string())
        .await
        .unwrap();

    let rpc_res = peer.load_latest_consensus_rpc().await;
    assert!(
        rpc_res.is_ok(),
        "RPC failed after rejections: {:?}",
        rpc_res.err()
    );

    // Clean up
    drop(persistent_connections);
    drop(peer);

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let m_final = store.dump_metrics().await.unwrap();
    assert_eq!(m_final.server_active_connections, 0);

    server.shutdown().await;
    let _ = handle.await;
}

#[tokio::test]
async fn test_empirical_auth_failures_tracking() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("auth_failures.db");
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .unwrap(),
    );

    let membership = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![1],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let store = Arc::new(
        ConsensusConfigStore::new(0, backend, Some(membership), None)
            .await
            .unwrap(),
    );
    let (ca_cert, ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1]);
    store
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();
    store.campaign().await.unwrap();

    let port = get_free_port();
    let server = TcpRpcServer::new(store.clone(), format!("127.0.0.1:{port}"));
    let handle = server.start().await.unwrap();
    let addr = format!("127.0.0.1:{port}");

    // Initial auth failures should be 0.
    let m0 = store.dump_metrics().await.unwrap();
    assert_eq!(m0.auth_failures, 0);

    // 1. plain TCP handshake (no TLS initiated, just connect and send garbage/close)
    {
        if let Ok(mut stream) = TcpStream::connect(&addr).await {
            let _ = stream.write_all(b"NOT_A_TLS_HANDSHAKE").await;
            let mut buf = [0u8; 100];
            let _ = stream.read(&mut buf).await;
        }
    }

    // Wait for connection handler to register plain TCP / TLS handshake failure
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let m1 = store.dump_metrics().await.unwrap();
    assert!(
        m1.auth_failures >= 1,
        "Expected plain TCP connection to trigger auth failure, got {}",
        m1.auth_failures
    );
    let auth_failures_after_plain = m1.auth_failures;

    // 2. Expired certificate
    {
        let expired_identity = generate_custom_identity(
            &ca_cert,
            &ca_key_pair,
            "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1",
            true, // expired
        );
        let peer = TcpPeer::new(0, addr.clone(), std::time::Duration::from_millis(300));
        peer.set_identity(expired_identity).await.unwrap();
        peer.set_auth(1, "tcp-test-cluster".to_string(), "".to_string())
            .await
            .unwrap();
        let _ = peer.load_latest_consensus_rpc().await;
    }

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let m2 = store.dump_metrics().await.unwrap();
    assert!(
        m2.auth_failures > auth_failures_after_plain,
        "Expected expired certificate to increment auth failures: initial={}, current={}",
        auth_failures_after_plain,
        m2.auth_failures
    );
    let auth_failures_after_expired = m2.auth_failures;

    // 3. Bad certificate (malformed SPIFFE ID, e.g., instance/abc instead of node_id)
    {
        let bad_spiffe_identity = generate_custom_identity(
            &ca_cert,
            &ca_key_pair,
            "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/abc",
            false,
        );
        let peer = TcpPeer::new(0, addr.clone(), std::time::Duration::from_millis(300));
        peer.set_identity(bad_spiffe_identity).await.unwrap();
        peer.set_auth(1, "tcp-test-cluster".to_string(), "".to_string())
            .await
            .unwrap();
        let _ = peer.load_latest_consensus_rpc().await;
    }

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let m3 = store.dump_metrics().await.unwrap();
    assert!(
        m3.auth_failures > auth_failures_after_expired,
        "Expected bad spiffe ID certificate to increment auth failures: initial={}, current={}",
        auth_failures_after_expired,
        m3.auth_failures
    );

    server.shutdown().await;
    let _ = handle.await;
}

#[tokio::test]
async fn test_empirical_active_membership_resolution_bug() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("active_membership_bug.db");

    // Open SqliteBackend
    let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
        .await
        .unwrap();

    // 1. Write an old membership configuration log entry (e.g. log index 1, voting_members [0, 1, 2], epoch 1)
    let old_membership = ClusterMembership {
        cluster_id: "test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0, 1, 2],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };

    let entry = LogEntry {
        index: 1,
        term: 1,
        op: ConsensusOp::ChangeMembership {
            membership: old_membership,
        },
    };

    backend.consensus_append_logs(0, vec![entry]).await.unwrap();

    // 2. Set the current membership table to a newer snapshot membership (epoch 2, voting_members [0, 1, 2, 3])
    let new_membership = ClusterMembership {
        cluster_id: "test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0, 1, 2, 3],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 2,
    };

    backend
        .consensus_set_membership(&new_membership)
        .await
        .unwrap();

    // 3. Resolve active membership
    let resolved = backend
        .consensus_get_active_membership()
        .await
        .unwrap()
        .unwrap();

    // 4. Assert that the resolved membership is the newer one (from the snapshot) and not the older log entry!
    println!(
        "Resolved membership epoch: {}, voting_members: {:?}",
        resolved.epoch, resolved.voting_members
    );
    assert_eq!(
        resolved.epoch, 2,
        "Expected resolved membership to be epoch 2 (snapshot), but got epoch {}",
        resolved.epoch
    );
}

#[tokio::test]
async fn test_empirical_consensus_node_exits_on_stdin_eof() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("stdin_eof.db");

    let node_ids = vec![0];
    let (_, _, identities) = generate_test_ca_and_identities(&node_ids);
    let identity = identities.get(&0).unwrap();

    let certs_dir = temp_dir.path().join("certs");
    let ca_cert_path = certs_dir.join("ca_0.crt");
    let cert_chain_path = certs_dir.join("node_0.crt");
    let private_key_path = certs_dir.join("node_0.key");
    std::fs::create_dir_all(&certs_dir).unwrap();
    std::fs::write(&ca_cert_path, &identity.ca_cert_pem).unwrap();
    std::fs::write(&cert_chain_path, &identity.cert_chain_pem).unwrap();
    std::fs::write(&private_key_path, &identity.private_key_pem).unwrap();

    let port = get_free_port();

    let mut exe_path = std::env::current_exe().unwrap();
    exe_path.pop();
    if exe_path.ends_with("deps") {
        exe_path.pop();
    }
    let mut binary_path = exe_path.join("opc-consensus-node");
    if !binary_path.exists() {
        binary_path = std::path::PathBuf::from("target/debug/opc-consensus-node");
    }

    let args = vec![
        "--node-id".to_string(),
        "0".to_string(),
        "--db-path".to_string(),
        db_path.to_str().unwrap().to_string(),
        "--addr".to_string(),
        format!("127.0.0.1:{}", port),
        "--cluster-id".to_string(),
        "stdin-test-cluster".to_string(),
        "--audit-key-hex".to_string(),
        "a5".repeat(32),
        "--cert-chain-path".to_string(),
        cert_chain_path.to_str().unwrap().to_string(),
        "--private-key-path".to_string(),
        private_key_path.to_str().unwrap().to_string(),
        "--ca-cert-path".to_string(),
        ca_cert_path.to_str().unwrap().to_string(),
        "--election-timeout-min=150".to_string(),
        "--election-timeout-max=300".to_string(),
        "--rpc-timeout=80".to_string(),
        "--voting-members".to_string(),
        "0".to_string(),
    ];

    let mut child = tokio::process::Command::new(&binary_path)
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    // Close stdin immediately
    let stdin = child.stdin.take().unwrap();
    drop(stdin);

    // Wait for it to exit
    let exit_status = tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;

    assert!(
        exit_status.is_ok(),
        "Consensus node did NOT exit on stdin EOF within 3 seconds! It is leaking!"
    );
}
