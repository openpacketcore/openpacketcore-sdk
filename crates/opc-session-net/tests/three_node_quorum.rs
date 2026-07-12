use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{
    LocalReplicaBinding, RemoteAddrResolver, RemoteReplicaBinding, RemoteSessionBackend,
    SessionClusterId, SessionConfigurationGeneration, SessionReplicationManifest,
    SessionReplicationServer,
};
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
    DurableReadinessOptions, DurableReadinessState, QuorumReplicaDescriptor, QuorumReplicaMember,
    QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaReadinessFailure, ReplicaTlsIdentity, RestoreScanCursor, RestoreScanRequest,
    RestoreScanScope, SqliteSessionBackend, StoreError, ValidatedQuorumTopology,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

#[derive(Clone)]
struct TestMtls {
    manifest: Arc<SessionReplicationManifest>,
    replicas: Arc<BTreeMap<ReplicaId, TestReplicaMtls>>,
}

#[derive(Clone)]
struct TestReplicaMtls {
    server_config: AuthenticatedServerConfig,
    client_config: AuthenticatedClientConfig,
}

fn topology_replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("test-replica-{index}")).expect("test replica ID")
}

fn topology_spiffe_id(index: usize) -> String {
    format!(
        "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/test-replica-{index}"
    )
}

fn topology_descriptor(index: usize) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        topology_replica_id(index),
        ReplicaEndpoint::new(format!("test-replica-{index}.invalid"), 7443).expect("test endpoint"),
        ReplicaTlsIdentity::new(topology_spiffe_id(index)).expect("test TLS identity"),
        ReplicaFailureDomain::new(format!("test-failure-domain-{index}"))
            .expect("test failure domain"),
        ReplicaBackingIdentity::new(format!("test-backing-{index}"))
            .expect("test backing identity"),
    )
}

fn topology_member(replica: FencedSessionReplica) -> QuorumReplicaMember {
    let index = replica.id;
    QuorumReplicaMember::new(topology_descriptor(index), replica)
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

impl TestMtls {
    fn standard() -> Self {
        Self::from_descriptors((1..=3).map(topology_descriptor).collect())
    }

    fn from_descriptors(descriptors: Vec<QuorumReplicaDescriptor>) -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Session Net Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let mut replicas = BTreeMap::new();

        for descriptor in &descriptors {
            let (cert, key) = signed_leaf(
                &ca_cert,
                &ca_key,
                descriptor.replica_id().as_str(),
                descriptor.tls_identity().as_str(),
            );
            let state = identity_state_from_pem(
                &(cert.pem() + &ca_cert.pem()),
                &key.serialize_pem(),
                &ca_cert.pem(),
            );
            let (_state_tx, state_rx) = tokio::sync::watch::channel(Some(state));
            let server_config = TlsConfigBuilder::new(state_rx.clone())
                .allow_any_trusted_peer()
                .build_authenticated_server_config()
                .expect("authenticated server TLS config");
            let client_config = TlsConfigBuilder::new(state_rx)
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("authenticated client TLS config");
            replicas.insert(
                descriptor.replica_id().clone(),
                TestReplicaMtls {
                    server_config,
                    client_config,
                },
            );
        }

        let manifest = Arc::new(
            SessionReplicationManifest::try_new(
                SessionClusterId::new("session-net-integration").expect("test cluster ID"),
                SessionConfigurationGeneration::new("v3").expect("test configuration generation"),
                descriptors,
            )
            .expect("test session replication manifest"),
        );
        Self {
            manifest,
            replicas: Arc::new(replicas),
        }
    }

    fn local_binding(&self, index: usize) -> LocalReplicaBinding {
        self.local_binding_for(&topology_replica_id(index))
    }

    fn local_binding_for(&self, replica_id: &ReplicaId) -> LocalReplicaBinding {
        self.manifest
            .bind_local(replica_id.clone())
            .expect("test local replica binding")
    }

    fn remote_binding(&self, local_index: usize, remote_index: usize) -> RemoteReplicaBinding {
        self.local_binding(local_index)
            .bind_remote(topology_replica_id(remote_index))
            .expect("test remote replica binding")
    }

    fn server_config(&self, index: usize) -> AuthenticatedServerConfig {
        self.server_config_for(&topology_replica_id(index))
    }

    fn server_config_for(&self, replica_id: &ReplicaId) -> AuthenticatedServerConfig {
        self.replicas
            .get(replica_id)
            .expect("test server TLS config")
            .server_config
            .clone()
    }

    fn client_config(&self, index: usize) -> AuthenticatedClientConfig {
        self.client_config_for(&topology_replica_id(index))
    }

    fn client_config_for(&self, replica_id: &ReplicaId) -> AuthenticatedClientConfig {
        self.replicas
            .get(replica_id)
            .expect("test client TLS config")
            .client_config
            .clone()
    }
}

fn mtls_configs() -> TestMtls {
    TestMtls::standard()
}

fn pinned_resolver(addr: SocketAddr) -> RemoteAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(addr) }))
}

fn remote_backend(
    mtls: &TestMtls,
    local_index: usize,
    remote_index: usize,
    addr: SocketAddr,
    deadline: Option<Duration>,
) -> RemoteSessionBackend {
    RemoteSessionBackend::new_with_resolver(
        mtls.remote_binding(local_index, remote_index),
        pinned_resolver(addr),
        mtls.client_config(local_index),
        deadline,
    )
}

#[cfg(feature = "insecure-test")]
fn hello_ack_for(
    request: &opc_session_net::Request,
    contract_version: u32,
) -> opc_session_net::Response {
    let opc_session_net::Request::Hello {
        node_id,
        expected_server_replica_id,
        cluster_id,
        configuration_id,
        handshake_nonce,
        ..
    } = request
    else {
        panic!("test handshake helper requires a hello request");
    };
    opc_session_net::Response::HelloAck {
        contract_version,
        server_replica_id: expected_server_replica_id.clone(),
        accepted_client_replica_id: Some(node_id.clone()),
        cluster_id: cluster_id.clone(),
        configuration_id: configuration_id.clone(),
        handshake_nonce: *handshake_nonce,
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
    server_index: usize,
) -> (
    SocketAddr,
    FakeSessionBackend,
    opc_session_net::server::ServerHandle,
) {
    let backend = FakeSessionBackend::new();
    start_server_with_backend(mtls, server_index, backend).await
}

async fn start_server_with_backend<B>(
    mtls: &TestMtls,
    server_index: usize,
    backend: B,
) -> (SocketAddr, B, opc_session_net::server::ServerHandle)
where
    B: SessionStoreBackend + Clone + 'static,
{
    start_server_with_backend_for(mtls, topology_replica_id(server_index), backend).await
}

async fn start_server_with_backend_for<B>(
    mtls: &TestMtls,
    server_replica_id: ReplicaId,
    backend: B,
) -> (SocketAddr, B, opc_session_net::server::ServerHandle)
where
    B: SessionStoreBackend + Clone + 'static,
{
    let server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config_for(&server_replica_id),
        mtls.local_binding_for(&server_replica_id),
    );
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    (addr, backend, handle)
}

#[tokio::test]
async fn remote_restore_scan_round_trips_scope_and_pagination_over_mtls() {
    let mtls = mtls_configs();
    let (addr, backend, handle) = start_server(&mtls, 2).await;
    let remote = remote_backend(&mtls, 1, 2, addr, None);

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

    let small_frame_remote =
        remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(1))).with_max_frame_size(512);
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
    let (addr, _backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let remote = remote_backend(&mtls, 1, 2, addr, None);

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
    let (addr, _backend, handle) = start_server(&mtls, 2).await;
    let constrained_client =
        remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(1))).with_max_frame_size(511);

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
    let server = SessionReplicationServer::new(
        Arc::new(backend),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_frame_size(511);
    let (server_handle, server_addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let default_client = remote_backend(&mtls, 1, 2, server_addr, Some(Duration::from_secs(1)));

    assert!(!default_client.capabilities().await.restore_scan);
    server_handle.abort();
}

#[tokio::test]
async fn validated_bare_self_and_fqdn_peers_restore_over_mtls_sqlite_replicas() {
    let peer1_host = "epdg-app-1.epdg-app-quorum.epdg-gateway.svc.cluster.local";
    let peer2_host = "epdg-app-2.epdg-app-quorum.epdg-gateway.svc.cluster.local";
    let logical_self = ReplicaId::new("epdg-app-0").expect("bare logical self");
    let peer1_id = ReplicaId::new("epdg-app-1").expect("peer ID");
    let peer2_id = ReplicaId::new("epdg-app-2").expect("peer ID");
    let descriptor = |slot: usize, replica_id: ReplicaId, host: &str| {
        QuorumReplicaDescriptor::new(
            replica_id,
            ReplicaEndpoint::new(host, 7443).expect("FQDN endpoint"),
            ReplicaTlsIdentity::new(format!(
                "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/epdg-app-{slot}"
            ))
            .expect("declared TLS identity"),
            ReplicaFailureDomain::new(format!("pod/epdg-app-{slot}"))
                .expect("failure domain"),
            ReplicaBackingIdentity::new(format!("pvc/session-store-{slot}"))
                .expect("backing identity"),
        )
    };
    let descriptors = vec![
        descriptor(
            0,
            logical_self.clone(),
            "epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local",
        ),
        descriptor(1, peer1_id.clone(), peer1_host),
        descriptor(2, peer2_id.clone(), peer2_host),
    ];
    let mtls = TestMtls::from_descriptors(descriptors.clone());
    let local = Arc::new(SqliteSessionBackend::in_memory().expect("local SQLite"));
    let (addr1, _backend1, handle1) = start_server_with_backend_for(
        &mtls,
        peer1_id.clone(),
        SqliteSessionBackend::in_memory().expect("remote SQLite 1"),
    )
    .await;
    let (addr2, _backend2, handle2) = start_server_with_backend_for(
        &mtls,
        peer2_id.clone(),
        SqliteSessionBackend::in_memory().expect("remote SQLite 2"),
    )
    .await;
    let local_binding = mtls.local_binding_for(&logical_self);
    let remote1 = Arc::new(RemoteSessionBackend::new_with_resolver(
        local_binding
            .bind_remote(peer1_id.clone())
            .expect("peer 1 binding"),
        pinned_resolver(addr1),
        mtls.client_config_for(&logical_self),
        Some(Duration::from_millis(300)),
    ));
    let remote2 = Arc::new(RemoteSessionBackend::new_with_resolver(
        local_binding
            .bind_remote(peer2_id.clone())
            .expect("peer 2 binding"),
        pinned_resolver(addr2),
        mtls.client_config_for(&logical_self),
        Some(Duration::from_millis(300)),
    ));
    let members = vec![
        QuorumReplicaMember::new(descriptors[0].clone(), FencedSessionReplica::new(0, local)),
        QuorumReplicaMember::new(
            descriptors[1].clone(),
            FencedSessionReplica::new(1, remote1),
        ),
        QuorumReplicaMember::new(
            descriptors[2].clone(),
            FencedSessionReplica::new(2, remote2),
        ),
    ];
    let topology =
        ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new(logical_self.clone(), members))
            .expect("bare logical self must match its explicit FQDN member record");
    assert_eq!(topology.summary().local_replica_id(), Some(&logical_self));
    let quorum = QuorumSessionStore::from_validated_topology(topology);

    let readiness = quorum.probe_durable_readiness().await;
    assert_eq!(readiness.state(), DurableReadinessState::Ready);
    assert_eq!(readiness.configured_voters(), 3);
    assert_eq!(readiness.fresh_reachable_voters(), 3);
    assert_eq!(readiness.agreeing_voters(), 3);
    assert_eq!(readiness.required_quorum(), 2);
    assert_eq!(readiness.majority_visible_prefix_index(), Some(0));
    assert_eq!(
        readiness
            .replica_observations()
            .iter()
            .map(|observation| observation.replica_id().as_str())
            .collect::<Vec<_>>(),
        vec![logical_self.as_str(), peer1_id.as_str(), peer2_id.as_str()],
        "readiness must report authenticated stable IDs, never endpoint aliases"
    );

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
    let server = SessionReplicationServer::new(
        Arc::new(backend),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
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
            expected_server_replica_id: None,
            cluster_id: None,
            configuration_id: None,
            handshake_nonce: None,
        },
    )
    .await
    .unwrap();

    let response: Response = read_frame(&mut stream, 1024).await.unwrap();
    assert!(matches!(
        response,
        Response::HelloAck {
            contract_version,
            ..
        } if contract_version == CONTRACT_VERSION
    ));

    handle.abort();
}

#[tokio::test]
async fn plaintext_rebuild_is_rejected_before_backend_dispatch() {
    let mtls = mtls_configs();
    let backend = FakeSessionBackend::new();
    let server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_idle_timeout(Duration::from_millis(150));
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = opc_session_net::protocol::write_frame(
        &mut stream,
        &opc_session_net::Request::Hello {
            contract_version: opc_session_net::protocol::CONTRACT_VERSION,
            node_id: "plaintext-peer".to_string(),
            expected_server_replica_id: None,
            cluster_id: None,
            configuration_id: None,
            handshake_nonce: None,
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
    let (addr1, backend1, handle1) = start_server(&mtls, 1).await;
    let (addr2, _backend2, handle2) = start_server(&mtls, 2).await;
    let (addr3, _backend3, handle3) = start_server(&mtls, 3).await;

    // 2. Create 3 remote clients
    let remote1 = Arc::new(remote_backend(&mtls, 1, 1, addr1, None));
    let remote2 = Arc::new(remote_backend(&mtls, 1, 2, addr2, None));
    let remote3 = Arc::new(remote_backend(&mtls, 1, 3, addr3, None));

    // 3. Wrap in quorum replicas
    let replica1 = FencedSessionReplica::new(1, remote1.clone());
    let replica2 = FencedSessionReplica::new(2, remote2.clone());
    let replica3 = FencedSessionReplica::new(3, remote3.clone());

    let quorum = validated_quorum(
        1,
        vec![replica1.clone(), replica2.clone(), replica3.clone()],
    );

    let initial_readiness = quorum.probe_durable_readiness().await;
    assert_eq!(initial_readiness.state(), DurableReadinessState::Ready);
    assert_eq!(initial_readiness.fresh_reachable_voters(), 3);

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

    let two_of_three_readiness = quorum.probe_durable_readiness().await;
    assert_eq!(two_of_three_readiness.state(), DurableReadinessState::Ready);
    assert_eq!(two_of_three_readiness.fresh_reachable_voters(), 2);

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
    let server1_new = SessionReplicationServer::new(
        Arc::new(backend1.clone()),
        mtls.server_config(1),
        mtls.local_binding(1),
    );
    let (handle1_new, addr1_new) = server1_new.listen(addr1).await.unwrap();

    // Update the remote to point to the new address
    let remote1_new = Arc::new(remote_backend(&mtls, 1, 1, addr1_new, None));
    let replica1_new = FencedSessionReplica::new(1, remote1_new.clone());

    // Create a new quorum with the restarted replica
    let quorum2 = validated_quorum(1, vec![replica1_new, replica2.clone(), replica3.clone()]);

    // Wait for things to settle
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 8. Assert safe strict-prefix catch-up behavior.
    // The restarted replica should receive only its missing suffix.
    let read_repaired = quorum2.get(&key).await.unwrap();
    assert_eq!(read_repaired.as_ref(), Some(&record2));

    handle2.abort();
    handle3.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let one_of_three_readiness = quorum2.probe_durable_readiness().await;
    assert_eq!(
        one_of_three_readiness.state(),
        DurableReadinessState::NoQuorum
    );
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
    let (addr, backend, handle) = start_server(&mtls, 2).await;
    let remote = Arc::new(remote_backend(&mtls, 1, 2, addr, None));

    // Warm up the persistent connection.
    let key = test_key();
    assert_eq!(remote.get(&key).await.unwrap(), None);

    // Kill the server. The old TCP connection may linger until the next write.
    handle.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Restart a server on the same address with the same backend state.
    let server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config(2),
        mtls.local_binding(2),
    );
    let (handle_new, _addr_new) = server.listen(addr).await.unwrap();

    // The next request must transparently reconnect rather than fail.
    assert_eq!(remote.get(&key).await.unwrap(), None);

    handle_new.abort();
}

#[tokio::test]
async fn capabilities_uses_cached_success_after_disconnect() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls, 2).await;
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_millis(200)));

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
        "cached backend features may survive transport loss, but restore support must be masked without a fresh negotiation"
    );
}

#[tokio::test]
async fn test_in_flight_request_surfaces_error_on_disconnect() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls, 2).await;

    // Short deadline so reconnect attempts expire before any restart.
    let remote = Arc::new(remote_backend(
        &mtls,
        1,
        2,
        addr,
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
                    write_frame(&mut w, &hello_ack_for(&hello, CONTRACT_VERSION))
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
    let (addr1, _backend1, handle1) = start_server(&mtls, 1).await;
    let (addr2, _backend2, handle2) = start_server(&mtls, 2).await;
    let (addr3, _backend3, handle3) = start_server(&mtls, 3).await;

    let remote1 = Arc::new(remote_backend(&mtls, 1, 1, addr1, None));
    let remote2 = Arc::new(remote_backend(&mtls, 1, 2, addr2, None));
    let remote3 = Arc::new(remote_backend(&mtls, 1, 3, addr3, None));

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
    let (addr1, _backend1, handle1) = start_server(&mtls, 1).await;
    let (addr2, _backend2, handle2) = start_server(&mtls, 2).await;
    let (addr3, _backend3, handle3) = start_server(&mtls, 3).await;

    let remote1 = Arc::new(remote_backend(&mtls, 1, 1, addr1, None));
    let remote2 = Arc::new(remote_backend(&mtls, 1, 2, addr2, None));
    let remote3 = Arc::new(remote_backend(&mtls, 1, 3, addr3, None));

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
                write_frame(&mut w, &hello_ack_for(&hello, CONTRACT_VERSION))
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

#[tokio::test]
async fn durable_readiness_probe_classifies_tls_accept_then_close_as_transport() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept TLS probe client");
        accepted_tx.send(()).expect("signal accepted connection");
        drop(stream);
    });

    let mtls = mtls_configs();
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_millis(250)));

    assert_eq!(
        remote.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Transport)
    );
    accepted_rx.await.expect("raw peer accepted TLS connection");
    server.await.expect("raw peer task");
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn durable_readiness_probe_classifies_stalled_peer_as_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept probe client");
        std::future::pending::<()>().await;
    });
    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(100)));

    assert_eq!(
        remote.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Timeout)
    );
    server.abort();
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn durable_readiness_probe_classifies_version_mismatch_as_protocol() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::Request;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept probe client");
        let hello: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut stream, &hello_ack_for(&hello, CONTRACT_VERSION - 1))
            .await
            .expect("write incompatible hello response");
    });
    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

    assert_eq!(
        remote.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Protocol)
    );
    server.await.expect("protocol test server");
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn durable_readiness_probe_classifies_redacted_remote_rejection_as_backend() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept probe client");
        let hello: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut stream, &hello_ack_for(&hello, CONTRACT_VERSION))
            .await
            .expect("write hello response");
        let probe: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read replication-head probe");
        assert!(matches!(probe, Request::MaxReplicationSequence));
        write_frame(
            &mut stream,
            &Response::MaxReplicationSequence(Err(StoreError::BackendUnavailable(
                "private-database-path-canary".to_string(),
            ))),
        )
        .await
        .expect("write backend rejection");
    });
    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

    let failure = remote
        .probe_replication_head()
        .await
        .expect_err("remote rejection must fail readiness");
    assert_eq!(failure, ReplicaReadinessFailure::Backend);
    assert!(!format!("{failure:?}").contains("private-database-path-canary"));
    server.await.expect("backend rejection test server");
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn durable_readiness_probe_classifies_redacted_generic_error_as_protocol() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept probe client");
        let hello: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut stream, &hello_ack_for(&hello, CONTRACT_VERSION))
            .await
            .expect("write hello response");
        let probe: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read replication-head probe");
        assert!(matches!(probe, Request::MaxReplicationSequence));
        write_frame(
            &mut stream,
            &Response::Error {
                message: "secret-peer-diagnostic-canary".to_string(),
            },
        )
        .await
        .expect("write generic protocol error");
    });
    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

    let failure = remote
        .probe_replication_head()
        .await
        .expect_err("a generic error response is not a valid replication head");
    assert_eq!(failure, ReplicaReadinessFailure::Protocol);
    assert!(!format!("{failure:?}").contains("secret-peer-diagnostic-canary"));
    server.await.expect("protocol-error test server");
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn cancelled_readiness_probe_drops_connection_before_the_next_probe() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let (first_probe_tx, first_probe_rx) = tokio::sync::oneshot::channel();
    let (release_stale_tx, release_stale_rx) = tokio::sync::oneshot::channel();
    let (first_connection_done_tx, first_connection_done_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("accept first probe client");
        let hello: Request = read_frame(&mut first, 1 << 20)
            .await
            .expect("read first client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut first, &hello_ack_for(&hello, CONTRACT_VERSION))
            .await
            .expect("write first hello response");
        let probe: Request = read_frame(&mut first, 1 << 20)
            .await
            .expect("read first replication-head probe");
        assert!(matches!(probe, Request::MaxReplicationSequence));
        first_probe_tx.send(()).expect("signal stalled exchange");

        release_stale_rx
            .await
            .expect("test releases stale response after cancellation");
        let _ = write_frame(&mut first, &Response::MaxReplicationSequence(Ok(7))).await;
        drop(first);
        first_connection_done_tx
            .send(())
            .expect("signal first connection completion");

        let (mut second, _) = listener.accept().await.expect("accept second probe client");
        let hello: Request = read_frame(&mut second, 1 << 20)
            .await
            .expect("read second client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut second, &hello_ack_for(&hello, CONTRACT_VERSION))
            .await
            .expect("write second hello response");
        let probe: Request = read_frame(&mut second, 1 << 20)
            .await
            .expect("read second replication-head probe");
        assert!(matches!(probe, Request::MaxReplicationSequence));
        write_frame(&mut second, &Response::MaxReplicationSequence(Ok(42)))
            .await
            .expect("write fresh replication head");
    });

    let remote = Arc::new(RemoteSessionBackend::new_insecure(
        addr,
        Some(Duration::from_secs(5)),
    ));
    let cancelled = tokio::spawn({
        let remote = remote.clone();
        async move { remote.probe_replication_head().await }
    });
    first_probe_rx
        .await
        .expect("first readiness request reached the peer");
    cancelled.abort();
    assert!(cancelled
        .await
        .expect_err("aborted readiness probe must be cancelled")
        .is_cancelled());
    release_stale_tx
        .send(())
        .expect("release stale first response");
    first_connection_done_rx
        .await
        .expect("first connection was retired");

    let recovered = tokio::time::timeout(Duration::from_secs(2), remote.probe_replication_head())
        .await
        .expect("fresh probe must not stall behind the cancelled exchange")
        .expect("fresh probe must reconnect");
    assert_eq!(
        recovered, 42,
        "the next probe must not consume the stale head from the cancelled exchange"
    );
    server.await.expect("cancellation test server");
}

#[tokio::test]
async fn cached_capabilities_do_not_substitute_for_fresh_quorum_evidence() {
    let mtls = mtls_configs();
    let (addr1, _backend1, handle1) = start_server(&mtls, 1).await;
    let (addr2, _backend2, handle2) = start_server(&mtls, 2).await;
    let (addr3, _backend3, handle3) = start_server(&mtls, 3).await;
    let remote1 = Arc::new(remote_backend(
        &mtls,
        1,
        1,
        addr1,
        Some(Duration::from_millis(200)),
    ));
    let remote2 = Arc::new(remote_backend(
        &mtls,
        1,
        2,
        addr2,
        Some(Duration::from_millis(200)),
    ));
    let remote3 = Arc::new(remote_backend(
        &mtls,
        1,
        3,
        addr3,
        Some(Duration::from_millis(200)),
    ));
    let quorum = validated_quorum(
        1,
        vec![
            FencedSessionReplica::new(1, remote1),
            FencedSessionReplica::new(2, remote2),
            FencedSessionReplica::new(3, remote3),
        ],
    )
    .with_durable_readiness_options(DurableReadinessOptions::new(Duration::from_millis(500), 32));

    let warmed = quorum.capabilities().await;
    assert!(warmed.atomic_compare_and_set);
    assert!(warmed.monotonic_fencing_token);
    assert!(warmed.batch_write);
    assert!(warmed.restore_scan);
    assert_eq!(
        quorum.probe_durable_readiness().await.state(),
        DurableReadinessState::Ready
    );

    handle2.abort();
    handle3.abort();
    let report = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let report = quorum.probe_durable_readiness().await;
            if report.state() == DurableReadinessState::NoQuorum {
                break report;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("two stopped voters must become unavailable within the test bound");
    assert_eq!(report.configured_voters(), 3);
    assert_eq!(report.fresh_reachable_voters(), 1);
    assert_eq!(report.agreeing_voters(), 0);
    assert_eq!(report.required_quorum(), 2);

    let still_descriptive = quorum.capabilities().await;
    assert_eq!(
        still_descriptive.atomic_compare_and_set,
        warmed.atomic_compare_and_set
    );
    assert_eq!(
        still_descriptive.monotonic_fencing_token,
        warmed.monotonic_fencing_token
    );
    assert_eq!(still_descriptive.batch_write, warmed.batch_write);
    assert_eq!(still_descriptive.max_value_bytes, warmed.max_value_bytes);

    let key = test_key_with_stable_id(b"cached-capabilities-no-quorum");
    assert!(
        quorum.get(&key).await.is_err(),
        "cached feature support must not authorize a read without fresh quorum evidence"
    );
    assert!(
        quorum
            .acquire(
                &key,
                OwnerId::new("cached-capabilities-owner").expect("test owner"),
                Duration::from_secs(60),
            )
            .await
            .is_err(),
        "cached feature support must not authorize a lease without fresh quorum evidence"
    );
    assert!(
        quorum
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .is_err(),
        "cached feature support must not authorize a restore scan without fresh quorum evidence"
    );

    handle1.abort();
}

#[tokio::test]
async fn durable_readiness_adaptively_pages_a_log_larger_than_one_wire_frame() {
    use opc_session_net::protocol::DEFAULT_MAX_FRAME_SIZE;
    use opc_session_net::Response;

    let expires_at =
        Timestamp::from_offset_datetime(time::OffsetDateTime::now_utc() + time::Duration::hours(1));
    let owner = OwnerId::new("large-log-owner").expect("test owner");
    let entries = (1_u64..=3)
        .map(|sequence| ReplicationEntry {
            sequence,
            tx_id: format!("large-log-{sequence}-{}", "x".repeat(400_000)),
            op: ReplicationOp::AcquireLease {
                key: SessionKey {
                    tenant: TenantId::new("tenant-a").expect("test tenant"),
                    nf_kind: NetworkFunctionKind::from_static("smf"),
                    key_type: SessionKeyType::PduSession,
                    stable_id: Bytes::from(format!("large-log-key-{sequence}")),
                },
                owner: owner.clone(),
                fence: FenceToken::new(sequence),
                credential_id: sequence,
                ttl: Duration::from_secs(60),
                expires_at,
            },
            timestamp: Timestamp::now_utc(),
        })
        .collect::<Vec<_>>();
    let aggregate_frame = serde_json::to_vec(&Response::GetReplicationLog(Ok(entries.clone())))
        .expect("serialize aggregate replication-log response");
    assert!(
        aggregate_frame.len() > DEFAULT_MAX_FRAME_SIZE,
        "fixture must exceed one default wire frame"
    );
    for entry in &entries {
        let single_frame =
            serde_json::to_vec(&Response::GetReplicationLog(Ok(vec![entry.clone()])))
                .expect("serialize one-entry replication-log response");
        assert!(
            single_frame.len() < DEFAULT_MAX_FRAME_SIZE,
            "each page must fit after adaptive reduction"
        );
    }

    let backends = [
        FakeSessionBackend::new(),
        FakeSessionBackend::new(),
        FakeSessionBackend::new(),
    ];
    for backend in &backends {
        for entry in &entries {
            backend
                .replicate_entry(entry.clone())
                .await
                .expect("seed identical replication log");
        }
    }

    let mtls = mtls_configs();
    let (addr1, _backend1, handle1) =
        start_server_with_backend(&mtls, 1, backends[0].clone()).await;
    let (addr2, _backend2, handle2) =
        start_server_with_backend(&mtls, 2, backends[1].clone()).await;
    let (addr3, _backend3, handle3) =
        start_server_with_backend(&mtls, 3, backends[2].clone()).await;
    let quorum = validated_quorum(
        1,
        vec![
            FencedSessionReplica::new(
                1,
                Arc::new(remote_backend(
                    &mtls,
                    1,
                    1,
                    addr1,
                    Some(Duration::from_secs(2)),
                )),
            ),
            FencedSessionReplica::new(
                2,
                Arc::new(remote_backend(
                    &mtls,
                    1,
                    2,
                    addr2,
                    Some(Duration::from_secs(2)),
                )),
            ),
            FencedSessionReplica::new(
                3,
                Arc::new(remote_backend(
                    &mtls,
                    1,
                    3,
                    addr3,
                    Some(Duration::from_secs(2)),
                )),
            ),
        ],
    )
    .with_durable_readiness_options(DurableReadinessOptions::new(
        Duration::from_secs(5),
        entries.len(),
    ));

    let report = quorum.probe_durable_readiness().await;
    assert_eq!(report.state(), DurableReadinessState::Ready);
    assert_eq!(report.fresh_reachable_voters(), 3);
    assert_eq!(report.agreeing_voters(), 3);
    assert_eq!(report.majority_visible_prefix_index(), Some(3));
    assert_eq!(
        quorum
            .get(&test_key_with_stable_id(b"large-log-read"))
            .await
            .expect("real read must use the same paged assessment"),
        None
    );

    handle1.abort();
    handle2.abort();
    handle3.abort();
}

#[tokio::test]
async fn durable_readiness_probe_classifies_untrusted_peer_as_authentication() {
    let server_mtls = mtls_configs();
    let unrelated_client_mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&server_mtls, 2).await;
    let remote = RemoteSessionBackend::new_with_resolver(
        server_mtls.remote_binding(1, 2),
        pinned_resolver(addr),
        unrelated_client_mtls.client_config(1),
        Some(Duration::from_millis(400)),
    );

    assert_eq!(
        remote.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Authentication)
    );
    handle.abort();
}
