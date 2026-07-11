use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{RemoteAddrResolver, RemoteSessionBackend, SessionReplicationServer};
use opc_session_store::backend::{
    CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp, SessionBackend,
};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::fake::FakeSessionBackend;
use opc_session_store::lease::SessionLeaseManager;
use opc_session_store::model::{
    FenceToken, Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType,
};
use opc_session_store::quorum::{FencedSessionReplica, QuorumSessionStore, SessionStoreBackend};
use opc_session_store::record::{EncryptedSessionPayload, StoredSessionRecord};
use opc_session_store::{
    QuorumReplicaDescriptor, QuorumReplicaMember, QuorumTopologyConfig, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, RestoreScanCursor,
    RestoreScanRequest, RestoreScanScope, SqliteSessionBackend, StoreError,
    ValidatedQuorumTopology,
};
use opc_tls::TlsConfigBuilder;
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

#[derive(Clone)]
struct TestMtls {
    server_config: Arc<opc_tls::ServerConfig>,
    client_config: Arc<opc_tls::ClientConfig>,
}

fn topology_replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("test-replica-{index}")).expect("test replica ID")
}

fn topology_member(replica: FencedSessionReplica) -> QuorumReplicaMember {
    let index = replica.id;
    QuorumReplicaMember::new(
        QuorumReplicaDescriptor::new(
            topology_replica_id(index),
            ReplicaEndpoint::new(format!("test-replica-{index}.invalid"), 7443)
                .expect("test endpoint"),
            ReplicaTlsIdentity::new(format!("spiffe://test/session/replica/{index}"))
                .expect("test TLS identity"),
            ReplicaFailureDomain::new(format!("test-failure-domain-{index}"))
                .expect("test failure domain"),
            ReplicaBackingIdentity::new(format!("test-backing-{index}"))
                .expect("test backing identity"),
        ),
        replica,
    )
}

fn validated_quorum(
    local_replica_index: usize,
    replicas: Vec<FencedSessionReplica>,
) -> QuorumSessionStore {
    let topology = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new(
        topology_replica_id(local_replica_index),
        replicas.into_iter().map(topology_member).collect(),
    ))
    .expect("valid network test topology");
    QuorumSessionStore::from_validated_topology(topology)
}

fn test_key() -> SessionKey {
    test_key_with_stable_id(b"test-session")
}

fn test_key_with_stable_id(stable_id: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("tenant-a").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(stable_id),
    }
}

async fn write_test_record<B>(backend: &B, key: SessionKey, owner: OwnerId) -> StoredSessionRecord
where
    B: SessionBackend + SessionLeaseManager,
{
    let lease = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("acquire test lease");
    let record = test_record(&key, &owner, lease.fence(), Generation::new(1));
    let result = backend
        .compare_and_set(CompareAndSet {
            key,
            lease,
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .expect("write test record");
    assert_eq!(result, CompareAndSetResult::Success);
    record
}

fn test_record(
    key: &SessionKey,
    owner: &OwnerId,
    fence: FenceToken,
    generation: Generation,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key: key.clone(),
        generation,
        owner: owner.clone(),
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("test").unwrap(),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"payload"),
    }
}

fn mtls_configs() -> TestMtls {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Session Net Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let (server_cert, server_key) = signed_leaf(
        &ca_cert,
        &ca_key,
        "Session Server",
        "spiffe://test-domain/tenant/test/ns/default/sa/session-server/nf/smf/instance/0",
    );
    let (client_cert, client_key) = signed_leaf(
        &ca_cert,
        &ca_key,
        "Session Client",
        "spiffe://test-domain/tenant/test/ns/default/sa/session-client/nf/smf/instance/0",
    );
    let server_state = identity_state_from_pem(
        &(server_cert.pem() + &ca_cert.pem()),
        &server_key.serialize_pem(),
        &ca_cert.pem(),
    );
    let client_state = identity_state_from_pem(
        &(client_cert.pem() + &ca_cert.pem()),
        &client_key.serialize_pem(),
        &ca_cert.pem(),
    );
    let (_server_tx, server_rx) = tokio::sync::watch::channel(Some(server_state));
    let (_client_tx, client_rx) = tokio::sync::watch::channel(Some(client_state));
    let server_config = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_server_config()
        .expect("server tls config");
    let client_config = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_client_config()
        .expect("client tls config");

    TestMtls {
        server_config: Arc::new(server_config),
        client_config: Arc::new(client_config),
    }
}

fn signed_leaf(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    common_name: &str,
    spiffe_id: &str,
) -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).expect("spiffe id"),
    ));
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(1);

    let key = rcgen::KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, ca_cert, ca_key).expect("leaf cert");
    (cert, key)
}

fn identity_state_from_pem(
    cert_chain_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> opc_identity::IdentityState {
    let ca_certs = parse_certs_pem(ca_pem).expect("ca pem");
    let cert_chain = parse_certs_pem(cert_chain_pem).expect("cert chain pem");
    let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
    let mut trust_bundles = opc_identity::TrustBundleSet::new();
    trust_bundles.insert(TrustBundle {
        trust_domain,
        certificates: ca_certs,
    });
    let private_key = parse_key_pem(key_pem).expect("key pem");
    build_identity_state(cert_chain, private_key, trust_bundles).expect("identity state")
}

async fn start_server(
    mtls: &TestMtls,
) -> (
    SocketAddr,
    FakeSessionBackend,
    opc_session_net::server::ServerHandle,
) {
    let backend = FakeSessionBackend::new();
    start_server_with_backend(mtls, backend).await
}

async fn start_server_with_backend<B>(
    mtls: &TestMtls,
    backend: B,
) -> (SocketAddr, B, opc_session_net::server::ServerHandle)
where
    B: SessionStoreBackend + Clone + 'static,
{
    let server =
        SessionReplicationServer::new(Arc::new(backend.clone()), mtls.server_config.clone());
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    (addr, backend, handle)
}

#[tokio::test]
async fn remote_restore_scan_round_trips_scope_and_pagination_over_mtls() {
    let mtls = mtls_configs();
    let (addr, backend, handle) = start_server(&mtls).await;
    let remote = RemoteSessionBackend::new(addr, mtls.client_config.clone(), None);

    assert!(remote.capabilities().await.restore_scan);
    let empty = remote
        .scan_restore_records(RestoreScanRequest::all(1))
        .await
        .expect("empty remote restore scan");
    assert!(empty.records.is_empty());
    assert!(empty.complete);

    let owner_a = OwnerId::new("owner-a").unwrap();
    let owner_b = OwnerId::new("owner-b").unwrap();
    write_test_record(&backend, test_key_with_stable_id(b"a"), owner_a.clone()).await;
    write_test_record(&backend, test_key_with_stable_id(b"b"), owner_b.clone()).await;
    write_test_record(&backend, test_key_with_stable_id(b"c"), owner_a.clone()).await;

    let request = RestoreScanRequest {
        scope: RestoreScanScope {
            owner: Some(owner_a),
            ..RestoreScanScope::all()
        },
        cursor: None,
        limit: 1,
    };
    let first = remote
        .scan_restore_records(request.clone())
        .await
        .expect("first remote restore page");
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0].key.stable_id.as_ref(), b"a");
    assert_eq!(first.excluded_count, 1);
    assert!(!first.complete);
    assert!(first.next_cursor.is_some());

    let second = remote
        .scan_restore_records(RestoreScanRequest {
            cursor: first.next_cursor,
            ..request
        })
        .await
        .expect("second remote restore page");
    assert_eq!(second.records.len(), 1);
    assert_eq!(second.records[0].key.stable_id.as_ref(), b"c");
    assert_eq!(second.excluded_count, 1);
    assert!(second.complete);
    assert!(second.next_cursor.is_none());

    let large_key = test_key_with_stable_id(b"d");
    let large_lease = backend
        .acquire(&large_key, owner_b.clone(), Duration::from_secs(60))
        .await
        .expect("acquire large-record lease");
    let mut large_record = test_record(
        &large_key,
        &owner_b,
        large_lease.fence(),
        Generation::new(1),
    );
    large_record.payload = EncryptedSessionPayload::new(vec![7; 2048]);
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: large_key,
                lease: large_lease,
                expected_generation: None,
                new_record: large_record,
            })
            .await
            .expect("write large record"),
        CompareAndSetResult::Success
    );

    let small_frame_remote = RemoteSessionBackend::new(
        addr,
        mtls.client_config.clone(),
        Some(Duration::from_secs(1)),
    )
    .with_max_frame_size(512);
    let oversized = small_frame_remote
        .scan_restore_records(RestoreScanRequest {
            scope: RestoreScanScope::all(),
            cursor: Some(RestoreScanCursor::from_offset(3)),
            limit: 1,
        })
        .await
        .expect_err("a single record larger than the peer frame must fail closed");
    assert_eq!(
        oversized,
        StoreError::RestoreScanResponseTooLarge { max_bytes: 512 }
    );

    handle.abort();
}

#[tokio::test]
async fn remote_restore_capability_matches_executable_backend_support() {
    let mtls = mtls_configs();
    let mut capabilities = BackendCapabilities::all_enabled();
    capabilities.restore_scan = false;
    let backend = FakeSessionBackend::with_capabilities(capabilities);
    let (addr, _backend, handle) = start_server_with_backend(&mtls, backend).await;
    let remote = RemoteSessionBackend::new(addr, mtls.client_config.clone(), None);

    assert!(!remote.capabilities().await.restore_scan);
    assert_eq!(
        remote
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("remote backend without scan capability must fail closed"),
        StoreError::CapabilityNotSupported("restore_scan".to_string())
    );

    handle.abort();
}

#[tokio::test]
async fn unusable_client_or_server_frame_bound_masks_restore_capability() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls).await;
    let constrained_client = RemoteSessionBackend::new(
        addr,
        mtls.client_config.clone(),
        Some(Duration::from_secs(1)),
    )
    .with_max_frame_size(511);

    assert!(!constrained_client.capabilities().await.restore_scan);
    assert_eq!(
        constrained_client
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("client frame below the protocol minimum must reject scans"),
        StoreError::RestoreScanResponseTooLarge { max_bytes: 511 }
    );
    handle.abort();

    let backend = FakeSessionBackend::new();
    let server = SessionReplicationServer::new(Arc::new(backend), mtls.server_config.clone())
        .with_max_frame_size(511);
    let (server_handle, server_addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let default_client = RemoteSessionBackend::new(
        server_addr,
        mtls.client_config.clone(),
        Some(Duration::from_secs(1)),
    );

    assert!(!default_client.capabilities().await.restore_scan);
    server_handle.abort();
}

#[tokio::test]
async fn validated_bare_self_and_fqdn_peers_restore_over_mtls_sqlite_replicas() {
    let mtls = mtls_configs();
    let local = Arc::new(SqliteSessionBackend::in_memory().expect("local SQLite"));
    let (addr1, _backend1, handle1) = start_server_with_backend(
        &mtls,
        SqliteSessionBackend::in_memory().expect("remote SQLite 1"),
    )
    .await;
    let (addr2, _backend2, handle2) = start_server_with_backend(
        &mtls,
        SqliteSessionBackend::in_memory().expect("remote SQLite 2"),
    )
    .await;
    let peer1_host = "epdg-app-1.epdg-app-quorum.epdg-gateway.svc.cluster.local";
    let peer2_host = "epdg-app-2.epdg-app-quorum.epdg-gateway.svc.cluster.local";
    let resolver1: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(addr1) }));
    let resolver2: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(addr2) }));
    let remote1 = Arc::new(RemoteSessionBackend::new_with_resolver(
        peer1_host.to_string(),
        resolver1,
        mtls.client_config.clone(),
        Some(Duration::from_millis(300)),
    ));
    let remote2 = Arc::new(RemoteSessionBackend::new_with_resolver(
        peer2_host.to_string(),
        resolver2,
        mtls.client_config.clone(),
        Some(Duration::from_millis(300)),
    ));
    let logical_self = ReplicaId::new("epdg-app-0").expect("bare logical self");
    let member = |slot,
                  id: ReplicaId,
                  host: &str,
                  port,
                  tls_identity: &str,
                  backend: Arc<dyn SessionStoreBackend>| {
        QuorumReplicaMember::new(
            QuorumReplicaDescriptor::new(
                id,
                ReplicaEndpoint::new(host, port).expect("FQDN endpoint"),
                ReplicaTlsIdentity::new(tls_identity).expect("declared TLS identity"),
                ReplicaFailureDomain::new(format!("pod/epdg-app-{slot}")).expect("failure domain"),
                ReplicaBackingIdentity::new(format!("pvc/session-store-{slot}"))
                    .expect("backing identity"),
            ),
            FencedSessionReplica::new(slot, backend),
        )
    };
    let members = vec![
        member(
            0,
            logical_self.clone(),
            "epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local",
            7443,
            "spiffe://test/session/epdg-app-0",
            local,
        ),
        member(
            1,
            ReplicaId::new("epdg-app-1").expect("peer ID"),
            peer1_host,
            addr1.port(),
            "spiffe://test/session/epdg-app-1",
            remote1,
        ),
        member(
            2,
            ReplicaId::new("epdg-app-2").expect("peer ID"),
            peer2_host,
            addr2.port(),
            "spiffe://test/session/epdg-app-2",
            remote2,
        ),
    ];
    let topology =
        ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new(logical_self.clone(), members))
            .expect("bare logical self must match its explicit FQDN member record");
    assert_eq!(topology.summary().local_replica_id(), Some(&logical_self));
    let quorum = QuorumSessionStore::from_validated_topology(topology);

    let empty = quorum
        .scan_restore_records(RestoreScanRequest::all(2))
        .await
        .expect("one local and two remote replicas must complete an empty scan");
    assert!(empty.records.is_empty());

    let owner = OwnerId::new("owner-quorum-restore").unwrap();
    for stable_id in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
        write_test_record(&quorum, test_key_with_stable_id(stable_id), owner.clone()).await;
    }

    let expired_key = test_key_with_stable_id(b"expired");
    let expired_lease = quorum
        .acquire(&expired_key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("acquire expired-record lease");
    let mut expired_record = test_record(
        &expired_key,
        &owner,
        expired_lease.fence(),
        Generation::new(1),
    );
    expired_record.expires_at = Some(Timestamp::from_offset_datetime(
        time::OffsetDateTime::UNIX_EPOCH,
    ));
    assert_eq!(
        quorum
            .compare_and_set(CompareAndSet {
                key: expired_key,
                lease: expired_lease,
                expected_generation: None,
                new_record: expired_record,
            })
            .await
            .expect("write expired record"),
        CompareAndSetResult::Success
    );

    let request = RestoreScanRequest::all(2);
    let first = quorum
        .scan_restore_records(request.clone())
        .await
        .expect("first quorum restore page");
    assert_eq!(first.records.len(), 2);
    assert_eq!(first.records[0].key.stable_id.as_ref(), b"a");
    assert_eq!(first.records[1].key.stable_id.as_ref(), b"b");
    assert!(!first.complete);

    let second = quorum
        .scan_restore_records(RestoreScanRequest {
            cursor: first.next_cursor,
            ..request
        })
        .await
        .expect("second quorum restore page");
    assert_eq!(second.records.len(), 1);
    assert_eq!(second.records[0].key.stable_id.as_ref(), b"c");
    assert!(second.complete);

    handle1.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let degraded = quorum
        .scan_restore_records(RestoreScanRequest::all(3))
        .await
        .expect("one local and one remote replica must still satisfy quorum");
    assert_eq!(degraded.records.len(), 3);

    handle2.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let unavailable = quorum
        .scan_restore_records(RestoreScanRequest::all(3))
        .await
        .expect_err("one local replica must not satisfy a three-replica quorum");
    assert!(matches!(unavailable, StoreError::BackendUnavailable(_)));
}

#[tokio::test]
async fn stalled_connection_is_reaped_after_idle_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend = FakeSessionBackend::new();
    let mtls = mtls_configs();
    let server = SessionReplicationServer::new(Arc::new(backend), mtls.server_config.clone())
        .with_max_connections(1)
        .with_idle_timeout(Duration::from_millis(150));
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

    // Connect and send only a partial length prefix (2 of 4 bytes), then stall
    // — the classic slowloris move.
    let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
    stalled.write_all(&[0x00, 0x00]).await.unwrap();
    stalled.flush().await.unwrap();

    // The server must reap the idle connection rather than hold its slot
    // forever: a TLS alert byte or EOF are both acceptable, but the read must
    // complete once the server closes the stalled handshake.
    let mut buf = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), stalled.read(&mut buf))
        .await
        .expect("server should close the stalled connection within the timeout")
        .expect("read from reaped connection");

    drop(handle);
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn incompatible_client_receives_server_contract_before_disconnect() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};

    let server = SessionReplicationServer::new_insecure(Arc::new(FakeSessionBackend::new()));
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut stream,
        &Request::Hello {
            contract_version: CONTRACT_VERSION - 1,
            node_id: "old-client".to_string(),
        },
    )
    .await
    .unwrap();

    let response: Response = read_frame(&mut stream, 1024).await.unwrap();
    assert!(matches!(
        response,
        Response::HelloAck { contract_version } if contract_version == CONTRACT_VERSION
    ));

    handle.abort();
}

#[tokio::test]
async fn plaintext_rebuild_is_rejected_before_backend_dispatch() {
    let mtls = mtls_configs();
    let backend = FakeSessionBackend::new();
    let server =
        SessionReplicationServer::new(Arc::new(backend.clone()), mtls.server_config.clone())
            .with_idle_timeout(Duration::from_millis(150));
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = opc_session_net::protocol::write_frame(
        &mut stream,
        &opc_session_net::Request::Hello {
            contract_version: opc_session_net::protocol::CONTRACT_VERSION,
            node_id: "plaintext-peer".to_string(),
        },
    )
    .await;
    let _ = opc_session_net::protocol::write_frame(
        &mut stream,
        &opc_session_net::Request::RebuildReplicationState {
            entries: vec![ReplicationEntry {
                sequence: 1,
                tx_id: "plaintext-rebuild".to_string(),
                op: ReplicationOp::AcquireLease {
                    key: test_key(),
                    owner: OwnerId::new("plaintext-owner").unwrap(),
                    fence: FenceToken::new(1),
                    credential_id: 1,
                    ttl: Duration::from_secs(60),
                    expires_at: opc_types::Timestamp::now_utc(),
                },
                timestamp: opc_types::Timestamp::now_utc(),
            }],
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(backend.max_replication_sequence().await.unwrap(), 0);
    handle.abort();
}

#[tokio::test]
async fn test_three_node_quorum_kill_and_restart() {
    // 1. Spin up 3 servers
    let mtls = mtls_configs();
    let (addr1, backend1, handle1) = start_server(&mtls).await;
    let (addr2, _backend2, handle2) = start_server(&mtls).await;
    let (addr3, _backend3, handle3) = start_server(&mtls).await;

    // 2. Create 3 remote clients
    let remote1 = Arc::new(RemoteSessionBackend::new(
        addr1,
        mtls.client_config.clone(),
        None,
    ));
    let remote2 = Arc::new(RemoteSessionBackend::new(
        addr2,
        mtls.client_config.clone(),
        None,
    ));
    let remote3 = Arc::new(RemoteSessionBackend::new(
        addr3,
        mtls.client_config.clone(),
        None,
    ));

    // 3. Wrap in quorum replicas
    let replica1 = FencedSessionReplica::new(1, remote1.clone());
    let replica2 = FencedSessionReplica::new(2, remote2.clone());
    let replica3 = FencedSessionReplica::new(3, remote3.clone());

    let quorum = validated_quorum(
        1,
        vec![replica1.clone(), replica2.clone(), replica3.clone()],
    );

    let empty_restore = quorum
        .scan_restore_records(RestoreScanRequest::all(16))
        .await
        .expect("three remote replicas must complete an empty restore scan");
    assert!(empty_restore.records.is_empty());
    assert!(empty_restore.complete);

    // 4. Lease and write conformance
    let key = test_key();
    let owner = OwnerId::new("owner-1").unwrap();

    let lease = quorum
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(lease.key(), &key);
    assert_eq!(lease.owner(), &owner);

    let record = test_record(&key, &owner, lease.fence(), Generation::new(1));
    let cas_result = quorum
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_result, CompareAndSetResult::Success);

    let restored = quorum
        .scan_restore_records(RestoreScanRequest::all(16))
        .await
        .expect("three remote replicas must restore the committed record");
    assert_eq!(restored.records, vec![record.clone()]);

    // Read back
    let read = quorum.get(&key).await.unwrap();
    assert_eq!(read.as_ref(), Some(&record));

    // 5. Kill one server mid-stream
    handle1.abort();

    // Wait a moment for the connection to drop
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6. Assert quorum writes still succeed (2 of 3 is a quorum)
    let lease2 = quorum.renew(&lease, Duration::from_secs(60)).await.unwrap();
    let record2 = test_record(&key, &owner, lease2.fence(), Generation::new(2));
    let cas_result2 = quorum
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease2.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: record2.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_result2, CompareAndSetResult::Success);

    let restored_with_one_replica_down = quorum
        .scan_restore_records(RestoreScanRequest::all(16))
        .await
        .expect("two live remote replicas must complete a quorum restore scan");
    assert_eq!(
        restored_with_one_replica_down.records,
        vec![record2.clone()]
    );

    // 7. Restart the server
    let server1_new =
        SessionReplicationServer::new(Arc::new(backend1.clone()), mtls.server_config.clone());
    let (handle1_new, addr1_new) = server1_new.listen(addr1).await.unwrap();

    // Update the remote to point to the new address
    let remote1_new = Arc::new(RemoteSessionBackend::new(
        addr1_new,
        mtls.client_config.clone(),
        None,
    ));
    let replica1_new = FencedSessionReplica::new(1, remote1_new.clone());

    // Create a new quorum with the restarted replica
    let quorum2 = validated_quorum(1, vec![replica1_new, replica2.clone(), replica3.clone()]);

    // Wait for things to settle
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 8. Assert read-repair / resync behavior
    // The restarted replica should be repaired on the next read
    let read_repaired = quorum2.get(&key).await.unwrap();
    assert_eq!(read_repaired.as_ref(), Some(&record2));

    handle2.abort();
    handle3.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let no_restore_quorum = quorum2
        .scan_restore_records(RestoreScanRequest::all(16))
        .await
        .expect_err("one live remote replica must not satisfy a three-replica quorum");
    assert!(matches!(
        no_restore_quorum,
        StoreError::BackendUnavailable(_)
    ));

    // Cleanup
    handle1_new.abort();
}

#[tokio::test]
async fn test_persistent_connection_reconnect_after_restart() {
    let mtls = mtls_configs();
    let (addr, backend, handle) = start_server(&mtls).await;
    let remote = Arc::new(RemoteSessionBackend::new(
        addr,
        mtls.client_config.clone(),
        None,
    ));

    // Warm up the persistent connection.
    let key = test_key();
    assert_eq!(remote.get(&key).await.unwrap(), None);

    // Kill the server. The old TCP connection may linger until the next write.
    handle.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Restart a server on the same address with the same backend state.
    let server =
        SessionReplicationServer::new(Arc::new(backend.clone()), mtls.server_config.clone());
    let (handle_new, _addr_new) = server.listen(addr).await.unwrap();

    // The next request must transparently reconnect rather than fail.
    assert_eq!(remote.get(&key).await.unwrap(), None);

    handle_new.abort();
}

#[tokio::test]
async fn capabilities_uses_cached_success_after_disconnect() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls).await;
    let remote = RemoteSessionBackend::new(
        addr,
        mtls.client_config.clone(),
        Some(Duration::from_millis(200)),
    );

    let warmed = remote.capabilities().await;
    assert!(
        warmed.atomic_compare_and_set && warmed.monotonic_fencing_token && warmed.batch_write,
        "expected warmed remote capabilities to reflect the full backend"
    );

    handle.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let after_disconnect = remote.capabilities().await;
    let mut expected = warmed;
    expected.restore_scan = false;
    assert_eq!(
        after_disconnect, expected,
        "cached backend features may survive transport loss, but v2-only restore support must be masked without a fresh negotiation"
    );
}

#[tokio::test]
async fn test_in_flight_request_surfaces_error_on_disconnect() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls).await;

    // Short deadline so reconnect attempts expire before any restart.
    let remote = Arc::new(RemoteSessionBackend::new(
        addr,
        mtls.client_config.clone(),
        Some(Duration::from_millis(300)),
    ));

    // Warm up the persistent connection.
    let key = test_key();
    assert_eq!(remote.get(&key).await.unwrap(), None);

    // Kill the server while a request is about to be issued.
    handle.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let start = tokio::time::Instant::now();
    let result = remote.get(&key).await;
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "expected backend-unavailable error after disconnect, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "request hung instead of failing within deadline: {elapsed:?}"
    );
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn direct_cas_retry_after_dropped_response_reports_success() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    let backend = Arc::new(FakeSessionBackend::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let first_cas = Arc::new(AtomicBool::new(true));
    let cas_request_ids = Arc::new(Mutex::new(Vec::new()));

    let server = {
        let backend = backend.clone();
        let first_cas = first_cas.clone();
        let cas_request_ids = cas_request_ids.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let backend = backend.clone();
                let first_cas = first_cas.clone();
                let cas_request_ids = cas_request_ids.clone();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.into_split();
                    let hello: Request = read_frame(&mut r, 1 << 20).await.unwrap();
                    assert!(matches!(hello, Request::Hello { .. }));
                    write_frame(
                        &mut w,
                        &Response::HelloAck {
                            contract_version: CONTRACT_VERSION,
                        },
                    )
                    .await
                    .unwrap();

                    loop {
                        let req: Request = match read_frame(&mut r, 1 << 20).await {
                            Ok(req) => req,
                            Err(_) => return,
                        };
                        match req {
                            Request::AcquireLease { key, owner, ttl } => {
                                let res = backend.acquire(&key, owner, ttl).await;
                                write_frame(&mut w, &Response::AcquireLease(res))
                                    .await
                                    .unwrap();
                            }
                            Request::CompareAndSet { op, request_id } => {
                                let request_id =
                                    request_id.expect("direct CAS must carry an idempotency key");
                                let mut ids = cas_request_ids.lock().await;
                                let first_seen_id = ids.first().cloned();
                                ids.push(request_id.clone());
                                drop(ids);

                                if first_cas.swap(false, Ordering::SeqCst) {
                                    let res = backend.compare_and_set(op).await;
                                    assert_eq!(res.as_ref(), Ok(&CompareAndSetResult::Success));
                                    return;
                                }

                                if first_seen_id.as_ref() == Some(&request_id) {
                                    write_frame(
                                        &mut w,
                                        &Response::CompareAndSet(Ok(CompareAndSetResult::Success)),
                                    )
                                    .await
                                    .unwrap();
                                } else {
                                    let res = backend.compare_and_set(op).await;
                                    write_frame(&mut w, &Response::CompareAndSet(res))
                                        .await
                                        .unwrap();
                                }
                            }
                            other => panic!("unexpected request in CAS retry test: {other:?}"),
                        }
                    }
                });
            }
        })
    };

    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(2)));
    let key = test_key();
    let owner = OwnerId::new("owner-retry").unwrap();
    let lease = remote
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let result = remote
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(&key, &owner, lease.fence(), Generation::new(1)),
        })
        .await
        .unwrap();

    assert_eq!(result, CompareAndSetResult::Success);
    let ids = cas_request_ids.lock().await;
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1], "retry must reuse the same CAS request id");

    server.abort();
}

#[tokio::test]
async fn test_batch_and_delete() {
    let mtls = mtls_configs();
    let (addr1, _backend1, handle1) = start_server(&mtls).await;
    let (addr2, _backend2, handle2) = start_server(&mtls).await;
    let (addr3, _backend3, handle3) = start_server(&mtls).await;

    let remote1 = Arc::new(RemoteSessionBackend::new(
        addr1,
        mtls.client_config.clone(),
        None,
    ));
    let remote2 = Arc::new(RemoteSessionBackend::new(
        addr2,
        mtls.client_config.clone(),
        None,
    ));
    let remote3 = Arc::new(RemoteSessionBackend::new(
        addr3,
        mtls.client_config.clone(),
        None,
    ));

    let replica1 = FencedSessionReplica::new(1, remote1);
    let replica2 = FencedSessionReplica::new(2, remote2);
    let replica3 = FencedSessionReplica::new(3, remote3);

    let quorum = validated_quorum(1, vec![replica1, replica2, replica3]);

    let key = test_key();
    let owner = OwnerId::new("owner-batch").unwrap();

    let lease = quorum
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let record = test_record(&key, &owner, lease.fence(), Generation::new(1));

    let batch_results = quorum
        .batch(vec![
            opc_session_store::backend::SessionOp::Get { key: key.clone() },
            opc_session_store::backend::SessionOp::CompareAndSet(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: record.clone(),
            }),
            opc_session_store::backend::SessionOp::Get { key: key.clone() },
        ])
        .await
        .unwrap();

    assert_eq!(batch_results.len(), 3);
    assert!(matches!(
        batch_results[0],
        opc_session_store::backend::SessionOpResult::Get(Ok(None))
    ));
    assert!(matches!(
        batch_results[1],
        opc_session_store::backend::SessionOpResult::CompareAndSet(Ok(
            CompareAndSetResult::Success
        ))
    ));
    assert!(matches!(
        batch_results[2],
        opc_session_store::backend::SessionOpResult::Get(Ok(Some(_)))
    ));

    // Delete fenced
    quorum.delete_fenced(&lease).await.unwrap();
    let read = quorum.get(&key).await.unwrap();
    assert_eq!(read, None);

    handle1.abort();
    handle2.abort();
    handle3.abort();
}

#[tokio::test]
async fn test_replication_log_and_watch() {
    let mtls = mtls_configs();
    let (addr1, _backend1, handle1) = start_server(&mtls).await;
    let (addr2, _backend2, handle2) = start_server(&mtls).await;
    let (addr3, _backend3, handle3) = start_server(&mtls).await;

    let remote1 = Arc::new(RemoteSessionBackend::new(
        addr1,
        mtls.client_config.clone(),
        None,
    ));
    let remote2 = Arc::new(RemoteSessionBackend::new(
        addr2,
        mtls.client_config.clone(),
        None,
    ));
    let remote3 = Arc::new(RemoteSessionBackend::new(
        addr3,
        mtls.client_config.clone(),
        None,
    ));

    let replica1 = FencedSessionReplica::new(1, remote1);
    let replica2 = FencedSessionReplica::new(2, remote2);
    let replica3 = FencedSessionReplica::new(3, remote3);

    let quorum = validated_quorum(1, vec![replica1, replica2, replica3]);

    let key = test_key();
    let owner = OwnerId::new("owner-watch").unwrap();

    let lease = quorum
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let record = test_record(&key, &owner, lease.fence(), Generation::new(1));

    quorum
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    // Check replication log
    let max_seq = quorum.max_replication_sequence().await.unwrap();
    assert!(max_seq >= 2); // lease acquisition + CAS

    let log = quorum.get_replication_log(1, 10).await.unwrap();
    assert!(!log.is_empty());

    // Watch
    let mut watch_stream = quorum.watch(1).await.unwrap();
    let first_entry = watch_stream.next().await;
    assert!(first_entry.is_some());

    handle1.abort();
    handle2.abort();
    handle3.abort();
}

/// A deadline that fires mid-exchange must poison the connection: the next
/// request has to reconnect rather than reuse a connection whose pending
/// (stale) response would otherwise be read as the new request's reply.
#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn test_timeout_mid_exchange_forces_reconnect() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let conn_count = connections.clone();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let n = conn_count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                // Speak the handshake on every connection.
                let hello: Request = match read_frame(&mut r, 1 << 20).await {
                    Ok(req) => req,
                    Err(_) => return,
                };
                assert!(matches!(hello, Request::Hello { .. }));
                write_frame(
                    &mut w,
                    &Response::HelloAck {
                        contract_version: CONTRACT_VERSION,
                    },
                )
                .await
                .unwrap();

                loop {
                    let req: Request = match read_frame(&mut r, 1 << 20).await {
                        Ok(req) => req,
                        Err(_) => return,
                    };
                    if n == 0 {
                        // First connection: swallow the request forever so the
                        // client's deadline fires mid-exchange.
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return;
                    }
                    // Later connections answer promptly.
                    if let Request::Get { .. } = req {
                        write_frame(&mut w, &Response::Get(Ok(None))).await.unwrap();
                    }
                }
            });
        }
    });

    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(300)));
    let key = test_key();

    // First request hits the stalling connection and must fail at the
    // deadline rather than hang.
    let start = tokio::time::Instant::now();
    let first = remote.get(&key).await;
    assert!(first.is_err(), "stalled request must surface an error");
    assert!(start.elapsed() < Duration::from_secs(2));

    // Second request must succeed via a NEW connection - reusing the stalled
    // one would read no (or the wrong) response.
    let second = remote.get(&key).await;
    assert_eq!(second.unwrap(), None);
    assert!(
        connections.load(Ordering::SeqCst) >= 2,
        "client must reconnect after a timed-out exchange"
    );
}
