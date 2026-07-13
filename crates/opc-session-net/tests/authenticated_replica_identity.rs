#![cfg(feature = "legacy-session-net-compat")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::StreamExt;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_redaction::metrics::METRICS;
use opc_session_net::protocol::{
    read_frame, write_frame, CONTRACT_VERSION, CURRENT_CONTRACT_PROFILE, DEFAULT_MAX_FRAME_SIZE,
    SESSION_NET_ALPN,
};
use opc_session_net::{
    ConnectionLifecyclePolicy, RemoteAddrResolver, RemoteReplicaBinding, RemoteSessionBackend,
    Request, Response, SessionClusterId, SessionConfigurationEpoch, SessionConfigurationGeneration,
    SessionReauthenticationControl, SessionReplicationManifest, SessionReplicationServer,
};
use opc_session_store::fake::FakeSessionBackend;
use opc_session_store::{
    BackendCapabilities, CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, Generation,
    LeaseError, LeaseGuard, OwnerId, QuorumReplicaDescriptor, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaReadinessFailure, ReplicaTlsIdentity,
    ReplicationEntry, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, SessionOp,
    SessionOpResult, StableId, StateClass, StateType, StoreError, StoredSessionRecord,
};
use opc_tls::{
    AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder,
    TlsMaterialAvailability, TlsMaterialEpoch,
};
use opc_types::{NetworkFunctionKind, TenantId};

const SERVER_REPLICA: u16 = 2;

struct TestPki {
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

impl TestPki {
    fn new() -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Session identity test CA");
        let ca_cert = params.self_signed(&ca_key).expect("CA certificate");
        Self { ca_cert, ca_key }
    }

    fn client_config(&self, replica: u16) -> AuthenticatedClientConfig {
        let state = self.identity_state(replica);
        let (_tx, rx) = tokio::sync::watch::channel(Some(state));
        TlsConfigBuilder::new(rx)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("authenticated client config")
    }

    fn server_config(&self, replica: u16) -> AuthenticatedServerConfig {
        let state = self.identity_state(replica);
        let (_tx, rx) = tokio::sync::watch::channel(Some(state));
        TlsConfigBuilder::new(rx)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("authenticated server config")
    }

    fn identity_state(&self, replica: u16) -> opc_identity::IdentityState {
        self.identity_state_with_trust_and_validity(
            replica,
            &[&self.ca_cert],
            time::Duration::days(1),
        )
    }

    fn identity_state_with_trust_and_validity(
        &self,
        replica: u16,
        trust_anchors: &[&rcgen::Certificate],
        validity: time::Duration,
    ) -> opc_identity::IdentityState {
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("replica-{replica}"));
        params.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::Ia5String::try_from(replica_spiffe(replica)).expect("SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + validity;
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .expect("leaf certificate");

        let certs = parse_certs_pem(&(cert.pem() + &self.ca_cert.pem())).expect("certificate PEM");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("private key PEM");
        let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
        let mut trust_bundles = opc_identity::TrustBundleSet::new();
        let trust_pem = trust_anchors
            .iter()
            .map(|certificate| certificate.pem())
            .collect::<String>();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: parse_certs_pem(&trust_pem).expect("CA PEM"),
        });
        build_identity_state(certs, private_key, trust_bundles).expect("identity state")
    }
}

#[derive(Default)]
struct RotationTrafficCounts {
    get: AtomicUsize,
    compare_and_set: AtomicUsize,
    batch: AtomicUsize,
    acquire: AtomicUsize,
    renew: AtomicUsize,
    release: AtomicUsize,
}

impl RotationTrafficCounts {
    fn snapshot(&self) -> [usize; 6] {
        [
            self.get.load(Ordering::SeqCst),
            self.compare_and_set.load(Ordering::SeqCst),
            self.batch.load(Ordering::SeqCst),
            self.acquire.load(Ordering::SeqCst),
            self.renew.load(Ordering::SeqCst),
            self.release.load(Ordering::SeqCst),
        ]
    }
}

struct RotationTrafficBackend {
    inner: FakeSessionBackend,
    counts: RotationTrafficCounts,
}

impl RotationTrafficBackend {
    fn new() -> Self {
        Self {
            inner: FakeSessionBackend::new(),
            counts: RotationTrafficCounts::default(),
        }
    }
}

#[async_trait]
impl SessionBackend for RotationTrafficBackend {
    fn restore_scan_cursor_profile(&self) -> Option<opc_session_store::RestoreScanCursorProfile> {
        self.inner.restore_scan_cursor_profile()
    }

    fn record_expiry_reference(&self) -> Option<opc_types::Timestamp> {
        self.inner.record_expiry_reference()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.counts.get.fetch_add(1, Ordering::SeqCst);
        self.inner.get(key).await
    }

    async fn compare_and_set(
        &self,
        operation: CompareAndSet,
    ) -> Result<CompareAndSetResult, StoreError> {
        self.counts.compare_and_set.fetch_add(1, Ordering::SeqCst);
        self.inner.compare_and_set(operation).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, operations: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        self.counts.batch.fetch_add(1, Ordering::SeqCst);
        self.inner.batch(operations).await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.inner.max_replication_sequence().await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.inner.get_replication_log(start, limit).await
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        self.inner.watch(start_sequence).await
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.inner.next_lease_info().await
    }
}

#[async_trait]
impl SessionLeaseManager for RotationTrafficBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        self.counts.acquire.fetch_add(1, Ordering::SeqCst);
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        self.counts.renew.fetch_add(1, Ordering::SeqCst);
        self.inner.renew(lease, ttl).await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        self.counts.release.fetch_add(1, Ordering::SeqCst);
        self.inner.release(lease).await
    }
}

fn lifecycle_policy() -> ConnectionLifecyclePolicy {
    ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_secs(4),
        Duration::from_millis(10),
        Duration::from_millis(50),
        Duration::ZERO,
    )
    .expect("connection lifecycle policy")
}

async fn wait_for_material_epoch_change(
    status: impl Fn() -> opc_tls::TlsMaterialStatus,
    previous: TlsMaterialEpoch,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let current = status();
            if current.epoch() != previous
                && current.availability() == TlsMaterialAvailability::Ready
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("material epoch update");
}

fn replica_id(replica: u16) -> ReplicaId {
    ReplicaId::new(format!("replica-{replica}")).expect("replica ID")
}

fn replica_spiffe(replica: u16) -> String {
    format!("spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/{replica}")
}

fn descriptor(replica: u16) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(replica),
        ReplicaEndpoint::new(format!("replica-{replica}.session.invalid"), 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(replica_spiffe(replica)).expect("TLS identity"),
        ReplicaFailureDomain::new(format!("zone-{replica}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("disk-{replica}")).expect("backing identity"),
    )
}

fn manifest(cluster: &str, generation: &str) -> Arc<SessionReplicationManifest> {
    manifest_with_epoch(cluster, generation, 1)
}

fn manifest_with_epoch(
    cluster: &str,
    generation: &str,
    epoch: u64,
) -> Arc<SessionReplicationManifest> {
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new(cluster).expect("cluster ID"),
            SessionConfigurationGeneration::new(generation).expect("configuration generation"),
            SessionConfigurationEpoch::new(epoch).expect("configuration epoch"),
            vec![descriptor(1), descriptor(2), descriptor(3)],
        )
        .expect("replication manifest"),
    )
}

fn resolver(addr: SocketAddr) -> RemoteAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(addr) }))
}

async fn start_server(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
) -> (opc_session_net::server::ServerHandle, SocketAddr) {
    start_server_with_config(pki.server_config(SERVER_REPLICA), manifest).await
}

async fn start_server_with_config(
    config: AuthenticatedServerConfig,
    manifest: &Arc<SessionReplicationManifest>,
) -> (opc_session_net::server::ServerHandle, SocketAddr) {
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let server =
        SessionReplicationServer::new(Arc::new(FakeSessionBackend::new()), config, binding);
    let (handle, addr) = server
        .listen("127.0.0.1:0".parse().expect("listen address"))
        .await
        .expect("listen");
    (handle, addr)
}

fn remote(
    manifest: &Arc<SessionReplicationManifest>,
    local_replica: u16,
    remote_replica: u16,
    addr: SocketAddr,
    tls: AuthenticatedClientConfig,
) -> RemoteSessionBackend {
    let binding = manifest
        .bind_local(replica_id(local_replica))
        .expect("local binding")
        .bind_remote(replica_id(remote_replica))
        .expect("remote binding");
    RemoteSessionBackend::new_with_resolver(
        binding,
        resolver(addr),
        tls,
        Some(Duration::from_millis(500)),
    )
}

#[derive(Clone, Copy, Debug)]
enum LifecycleEndpoint {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug)]
enum LifecycleLimit {
    MaximumAge,
    LocalLeafExpiry,
    PeerLeafExpiry,
}

fn lifecycle_policy_with(
    maximum_authentication_age: Duration,
    rotation_drain_window: Duration,
) -> ConnectionLifecyclePolicy {
    ConnectionLifecyclePolicy::try_new(
        maximum_authentication_age,
        rotation_drain_window,
        Duration::from_millis(5),
        Duration::from_millis(20),
        Duration::ZERO,
    )
    .expect("direct lifecycle policy")
}

fn retirement_reason_count(limit: LifecycleLimit) -> u64 {
    match limit {
        LifecycleLimit::MaximumAge => &METRICS.session_net_lifecycle_retirement_maximum_age,
        LifecycleLimit::LocalLeafExpiry => {
            &METRICS.session_net_lifecycle_retirement_local_leaf_expiry
        }
        LifecycleLimit::PeerLeafExpiry => {
            &METRICS.session_net_lifecycle_retirement_peer_leaf_expiry
        }
    }
    .load(Ordering::Relaxed)
}

async fn assert_paused_direct_lifecycle_wiring(endpoint: LifecycleEndpoint, limit: LifecycleLimit) {
    let pki = TestPki::new();
    let trust = [&pki.ca_cert];
    let long_validity = time::Duration::days(1);
    let short_validity = time::Duration::seconds(45);
    let (client_validity, server_validity) = match (endpoint, limit) {
        (_, LifecycleLimit::MaximumAge) => (long_validity, long_validity),
        (LifecycleEndpoint::Client, LifecycleLimit::LocalLeafExpiry)
        | (LifecycleEndpoint::Server, LifecycleLimit::PeerLeafExpiry) => {
            (short_validity, long_validity)
        }
        (LifecycleEndpoint::Client, LifecycleLimit::PeerLeafExpiry)
        | (LifecycleEndpoint::Server, LifecycleLimit::LocalLeafExpiry) => {
            (long_validity, short_validity)
        }
    };
    let client_config = TlsConfigBuilder::new(
        tokio::sync::watch::channel(Some(pki.identity_state_with_trust_and_validity(
            1,
            &trust,
            client_validity,
        )))
        .1,
    )
    .allow_any_trusted_peer()
    .build_authenticated_client_config()
    .expect("paused lifecycle client config");
    let server_config = TlsConfigBuilder::new(
        tokio::sync::watch::channel(Some(pki.identity_state_with_trust_and_validity(
            SERVER_REPLICA,
            &trust,
            server_validity,
        )))
        .1,
    )
    .allow_any_trusted_peer()
    .build_authenticated_server_config()
    .expect("paused lifecycle server config");

    let (target_policy, other_policy, soft_advance, hard_advance) = match limit {
        LifecycleLimit::MaximumAge => (
            lifecycle_policy_with(Duration::from_secs(30), Duration::from_secs(10)),
            lifecycle_policy_with(Duration::from_secs(120), Duration::from_secs(2)),
            Duration::from_secs(21),
            Duration::from_secs(10),
        ),
        LifecycleLimit::LocalLeafExpiry | LifecycleLimit::PeerLeafExpiry => (
            lifecycle_policy_with(Duration::from_secs(120), Duration::from_secs(15)),
            lifecycle_policy_with(Duration::from_secs(120), Duration::from_secs(2)),
            Duration::from_secs(31),
            Duration::from_secs(15),
        ),
    };
    let (client_policy, server_policy) = match endpoint {
        LifecycleEndpoint::Client => (target_policy, other_policy),
        LifecycleEndpoint::Server => (other_policy, target_policy),
    };

    let manifest = manifest("cluster-paused-lifecycle", "generation-paused-lifecycle");
    let counted = Arc::new(RotationTrafficBackend::new());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let server = SessionReplicationServer::new(counted.clone(), server_config, binding)
        .with_max_connections(1)
        .with_connection_lifecycle(server_policy);
    let (handle, addr) = server
        .listen("127.0.0.1:0".parse().expect("listen address"))
        .await
        .expect("paused lifecycle listener");
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let dynamic_resolver: RemoteAddrResolver = {
        let resolve_calls = resolve_calls.clone();
        Arc::new(move || {
            resolve_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let backend = RemoteSessionBackend::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        dynamic_resolver,
        client_config,
        Some(Duration::from_secs(3)),
    )
    .with_connection_lifecycle(client_policy);
    let key = rotation_key("paused-read", 0);

    assert_eq!(backend.get(&key).await, Ok(None));
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counted.counts.get.load(Ordering::SeqCst), 1);
    let retirement_before = retirement_reason_count(limit);

    tokio::time::pause();
    tokio::time::advance(soft_advance).await;
    tokio::time::resume();
    assert_eq!(backend.get(&key).await, Ok(None));
    assert_eq!(
        resolve_calls.load(Ordering::SeqCst),
        2,
        "{endpoint:?} {limit:?} soft retirement must reject reuse and establish one replacement"
    );
    assert_eq!(
        counted.counts.get.load(Ordering::SeqCst),
        2,
        "the soft-boundary request must dispatch exactly once"
    );
    assert!(
        retirement_reason_count(limit) > retirement_before,
        "{endpoint:?} must record the exact {limit:?} retirement source"
    );

    tokio::time::pause();
    tokio::time::advance(hard_advance).await;
    tokio::time::resume();
    assert_eq!(backend.get(&key).await, Ok(None));
    assert_eq!(
        resolve_calls.load(Ordering::SeqCst),
        2,
        "the original socket/slot must be gone by its hard deadline and never reused"
    );
    assert_eq!(counted.counts.get.load(Ordering::SeqCst), 3);

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn paused_time_client_wiring_retires_for_age_local_and_peer_leaf_expiry() {
    for limit in [
        LifecycleLimit::MaximumAge,
        LifecycleLimit::LocalLeafExpiry,
        LifecycleLimit::PeerLeafExpiry,
    ] {
        assert_paused_direct_lifecycle_wiring(LifecycleEndpoint::Client, limit).await;
    }
}

#[tokio::test]
async fn paused_time_server_wiring_retires_for_age_local_and_peer_leaf_expiry() {
    for limit in [
        LifecycleLimit::MaximumAge,
        LifecycleLimit::LocalLeafExpiry,
        LifecycleLimit::PeerLeafExpiry,
    ] {
        assert_paused_direct_lifecycle_wiring(LifecycleEndpoint::Server, limit).await;
    }
}

fn successful_hello_ack(hello: &Request) -> Response {
    let Request::Hello {
        node_id,
        expected_server_replica_id,
        cluster_id,
        configuration_id,
        configuration_epoch,
        handshake_nonce,
        requested_response_frame_size,
        ..
    } = hello
    else {
        panic!("expected Hello");
    };
    Response::HelloAck {
        contract_version: CONTRACT_VERSION,
        contract_profile: Some(CURRENT_CONTRACT_PROFILE),
        server_replica_id: expected_server_replica_id.clone(),
        accepted_client_replica_id: Some(node_id.clone()),
        cluster_id: cluster_id.clone(),
        configuration_id: configuration_id.clone(),
        configuration_epoch: *configuration_epoch,
        handshake_nonce: *handshake_nonce,
        cas_idempotency_epoch: Some(uuid::Uuid::from_u128(1)),
        accepted_response_frame_size: *requested_response_frame_size,
        server_request_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
    }
}

fn hello_for(binding: &RemoteReplicaBinding) -> Request {
    Request::Hello {
        contract_version: CONTRACT_VERSION,
        contract_profile: Some(CURRENT_CONTRACT_PROFILE),
        node_id: binding.local_replica_id().as_str().to_string(),
        expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_string()),
        cluster_id: Some(binding.cluster_id().as_str().to_string()),
        configuration_id: Some(binding.configuration_id().to_hex()),
        configuration_epoch: Some(binding.configuration_epoch().get()),
        handshake_nonce: Some(uuid::Uuid::new_v4()),
        requested_response_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
    }
}

#[tokio::test]
async fn exact_identity_succeeds_through_a_routing_alias() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", "generation-7");
    let (handle, addr) = start_server(&pki, &manifest).await;
    let backend = remote(&manifest, 1, SERVER_REPLICA, addr, pki.client_config(1));

    assert_eq!(backend.probe_replication_head().await, Ok(0));
    let binding = backend.peer_binding().expect("authenticated peer binding");
    assert_eq!(binding.local_replica_id(), &replica_id(1));
    assert_eq!(binding.remote_replica_id(), &replica_id(SERVER_REPLICA));

    handle.abort();
}

#[tokio::test]
async fn certificate_claim_scope_and_server_mismatches_fail_closed() {
    let pki = TestPki::new();
    let server_manifest = manifest("cluster-a", "generation-7");
    let (handle, addr) = start_server(&pki, &server_manifest).await;

    let wrong_certificate = remote(
        &server_manifest,
        1,
        SERVER_REPLICA,
        addr,
        pki.client_config(3),
    );
    assert_eq!(
        wrong_certificate.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Authentication)
    );

    let wrong_claim = remote(
        &server_manifest,
        3,
        SERVER_REPLICA,
        addr,
        pki.client_config(1),
    );
    assert_eq!(
        wrong_claim.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Authentication)
    );

    let wrong_scope_manifest = manifest("cluster-b", "generation-7");
    let wrong_scope = remote(
        &wrong_scope_manifest,
        1,
        SERVER_REPLICA,
        addr,
        pki.client_config(1),
    );
    assert_eq!(
        wrong_scope.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Authentication)
    );

    let wrong_generation_manifest = manifest("cluster-a", "generation-8");
    let wrong_generation = remote(
        &wrong_generation_manifest,
        1,
        SERVER_REPLICA,
        addr,
        pki.client_config(1),
    );
    assert_eq!(
        wrong_generation.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Authentication)
    );

    let wrong_epoch_manifest = manifest_with_epoch("cluster-a", "generation-7", 2);
    let wrong_epoch = remote(
        &wrong_epoch_manifest,
        1,
        SERVER_REPLICA,
        addr,
        pki.client_config(1),
    );
    assert_eq!(
        wrong_epoch.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Authentication)
    );

    let wrong_server = remote(&server_manifest, 1, 3, addr, pki.client_config(1));
    assert_eq!(
        wrong_server.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Authentication)
    );

    handle.abort();
}

async fn raw_tls_connection(
    addr: SocketAddr,
    authenticated: AuthenticatedClientConfig,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    raw_tls_connection_with_alpn(addr, authenticated, vec![SESSION_NET_ALPN.to_vec()]).await
}

async fn raw_tls_connection_with_alpn(
    addr: SocketAddr,
    authenticated: AuthenticatedClientConfig,
    alpn_protocols: Vec<Vec<u8>>,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    try_raw_tls_connection_with_alpn(addr, authenticated, alpn_protocols)
        .await
        .expect("mutual TLS connect")
}

async fn try_raw_tls_connection_with_alpn(
    addr: SocketAddr,
    authenticated: AuthenticatedClientConfig,
    alpn_protocols: Vec<Vec<u8>>,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let mut config = authenticated.rustls_config().as_ref().clone();
    config.alpn_protocols = alpn_protocols;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let server_name = rustls_pki_types::ServerName::IpAddress(addr.ip().into());
    connector.connect(server_name, tcp).await
}

async fn start_single_probe_server(
    authenticated: AuthenticatedServerConfig,
    sequence: u64,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("single-probe listener");
    let addr = listener.local_addr().expect("single-probe address");
    let mut config = authenticated.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("single-probe accept");
        let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
        else {
            return;
        };
        let Ok(hello) = read_frame::<_, Request>(&mut tls, DEFAULT_MAX_FRAME_SIZE).await else {
            return;
        };
        if write_frame(&mut tls, &successful_hello_ack(&hello))
            .await
            .is_err()
        {
            return;
        }
        let Ok(request) = read_frame::<_, Request>(&mut tls, DEFAULT_MAX_FRAME_SIZE).await else {
            return;
        };
        if matches!(request, Request::MaxReplicationSequence) {
            let _ = write_frame(&mut tls, &Response::MaxReplicationSequence(Ok(sequence))).await;
        }
    });
    (addr, handle)
}

async fn start_two_connection_probe_server(
    authenticated: AuthenticatedServerConfig,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Vec<Request>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("two-connection listener");
    let addr = listener.local_addr().expect("two-connection address");
    let (first_closed_tx, first_closed_rx) = tokio::sync::oneshot::channel();
    let (continue_tx, continue_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut hellos = Vec::with_capacity(3);
        let mut first_closed_tx = Some(first_closed_tx);
        let mut continue_rx = Some(continue_rx);
        for connection in 0..3 {
            let (tcp, _) = listener.accept().await.expect("probe accept");
            let handshake = authenticated.begin_handshake().expect("server material");
            let mut config = handshake.rustls_config().as_ref().clone();
            config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(tcp)
                .await
                .expect("probe mutual TLS");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(SESSION_NET_ALPN));
            let hello: Request = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("probe Hello");
            write_frame(&mut tls, &successful_hello_ack(&hello))
                .await
                .expect("probe HelloAck");
            handshake.admit().expect("server material admission");
            hellos.push(hello);

            if connection == 0 {
                let request = read_frame::<_, Request>(&mut tls, DEFAULT_MAX_FRAME_SIZE)
                    .await
                    .expect("initial probe request");
                assert!(matches!(request, Request::MaxReplicationSequence));
                write_frame(&mut tls, &Response::MaxReplicationSequence(Ok(11)))
                    .await
                    .expect("initial probe response");
                while let Ok(request) =
                    read_frame::<_, Request>(&mut tls, DEFAULT_MAX_FRAME_SIZE).await
                {
                    assert!(matches!(request, Request::MaxReplicationSequence));
                    write_frame(&mut tls, &Response::MaxReplicationSequence(Ok(11)))
                        .await
                        .expect("retained probe response");
                }
                first_closed_tx
                    .take()
                    .expect("first close sender")
                    .send(())
                    .expect("report first connection close");
                continue_rx
                    .take()
                    .expect("continue receiver")
                    .await
                    .expect("continue after material renewal");
                continue;
            }

            match read_frame::<_, Request>(&mut tls, DEFAULT_MAX_FRAME_SIZE).await {
                Ok(request) => {
                    assert!(matches!(request, Request::MaxReplicationSequence));
                    write_frame(&mut tls, &Response::MaxReplicationSequence(Ok(22)))
                        .await
                        .expect("replacement probe response");
                    return hellos;
                }
                Err(_) => {
                    // A material publication after the client froze its
                    // immutable attempt must invalidate that attempt and retry
                    // the complete TLS + Hello negotiation on a new socket.
                }
            }
        }
        panic!("current-material replacement did not dispatch within three attempts")
    });
    (addr, first_closed_rx, continue_tx, handle)
}

fn assert_exact_replacement_hello(first: &Request, replacement: &Request) {
    let (
        Request::Hello {
            contract_version: first_version,
            contract_profile: first_profile,
            handshake_nonce: Some(first_nonce),
            ..
        },
        Request::Hello {
            contract_version: replacement_version,
            contract_profile: replacement_profile,
            handshake_nonce: Some(replacement_nonce),
            ..
        },
    ) = (first, replacement)
    else {
        panic!("both connections must perform complete Hello negotiation");
    };
    assert_eq!(*first_version, CONTRACT_VERSION);
    assert_eq!(*replacement_version, CONTRACT_VERSION);
    assert_eq!(*first_profile, Some(CURRENT_CONTRACT_PROFILE));
    assert_eq!(*replacement_profile, Some(CURRENT_CONTRACT_PROFILE));
    assert_ne!(first_nonce, replacement_nonce);
}

async fn assert_real_mtls_leaf_expiry_reconnects(short_local_leaf: bool) {
    let pki = TestPki::new();
    let trust = [&pki.ca_cert];
    let short = time::Duration::seconds(7);
    let long = time::Duration::days(1);
    let client_validity = if short_local_leaf { short } else { long };
    let server_validity = if short_local_leaf { long } else { short };
    let (client_tx, client_rx) = tokio::sync::watch::channel(Some(
        pki.identity_state_with_trust_and_validity(1, &trust, client_validity),
    ));
    let (server_tx, server_rx) = tokio::sync::watch::channel(Some(
        pki.identity_state_with_trust_and_validity(SERVER_REPLICA, &trust, server_validity),
    ));
    let client_config = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("expiring client config");
    let server_config = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("expiring server config");
    let (addr, first_closed, continue_sender, server) =
        start_two_connection_probe_server(server_config.clone()).await;
    let manifest = manifest("cluster-expiry", "generation-expiry");
    let reconnect_allowed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let reconnect_notify = Arc::new(tokio::sync::Notify::new());
    let gated_resolver: RemoteAddrResolver = {
        let reconnect_allowed = reconnect_allowed.clone();
        let reconnect_notify = reconnect_notify.clone();
        Arc::new(move || {
            let reconnect_allowed = reconnect_allowed.clone();
            let reconnect_notify = reconnect_notify.clone();
            Box::pin(async move {
                while !reconnect_allowed.load(std::sync::atomic::Ordering::Acquire) {
                    reconnect_notify.notified().await;
                }
                Ok(addr)
            })
        })
    };
    let backend = RemoteSessionBackend::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("server binding"),
        gated_resolver,
        client_config.clone(),
        Some(Duration::from_secs(3)),
    )
    .with_connection_lifecycle(lifecycle_policy());

    assert_eq!(backend.probe_replication_head().await, Ok(11));
    reconnect_allowed.store(false, std::sync::atomic::Ordering::Release);
    tokio::time::sleep(Duration::from_millis(3_500)).await;
    let replacement_probe = tokio::spawn({
        let backend = backend.clone();
        async move { backend.probe_replication_head().await }
    });
    tokio::time::timeout(Duration::from_secs(1), first_closed)
        .await
        .expect("leaf soft deadline must reject reuse of the retained connection")
        .expect("leaf close signal");

    if short_local_leaf {
        let previous = client_config.material_status().epoch();
        client_tx.send_replace(Some(
            pki.identity_state_with_trust_and_validity(1, &trust, long),
        ));
        wait_for_material_epoch_change(|| client_config.material_status(), previous).await;
    } else {
        let previous = server_config.material_status().epoch();
        server_tx.send_replace(Some(pki.identity_state_with_trust_and_validity(
            SERVER_REPLICA,
            &trust,
            long,
        )));
        wait_for_material_epoch_change(|| server_config.material_status(), previous).await;
    }
    continue_sender
        .send(())
        .expect("continue with renewed material");
    reconnect_allowed.store(true, std::sync::atomic::Ordering::Release);
    reconnect_notify.notify_one();

    assert_eq!(replacement_probe.await.expect("replacement probe"), Ok(22));
    let hellos = server.await.expect("replacement server");
    assert!(hellos.len() >= 2);
    assert_exact_replacement_hello(
        hellos.first().expect("initial Hello"),
        hellos.last().expect("replacement Hello"),
    );
}

#[tokio::test]
async fn real_mtls_local_and_peer_leaf_expiry_force_exact_reauthentication() {
    assert_real_mtls_leaf_expiry_reconnects(true).await;
    assert_real_mtls_leaf_expiry_reconnects(false).await;
}

fn rotation_key(label: &str, index: usize) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("rotation-tenant").expect("rotation tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: StableId::new(Bytes::from(format!("{label}-{index}")))
            .expect("bounded rotation stable ID"),
    }
}

fn rotation_record(key: SessionKey, lease: &LeaseGuard, generation: u64) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("rotation-traffic").expect("rotation state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(format!("opaque-{generation}").into_bytes()),
    }
}

const ROTATION_OPERATION_DEADLINE: Duration = Duration::from_secs(3);
const ROTATION_CLEANUP_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Default)]
struct RotationTrafficOutcome {
    get: AtomicUsize,
    compare_and_set: AtomicUsize,
    lease_cycle: AtomicUsize,
    batch: AtomicUsize,
    watch: AtomicUsize,
    failures: StdMutex<Vec<&'static str>>,
}

impl RotationTrafficOutcome {
    fn snapshot(&self) -> [usize; 5] {
        [
            self.get.load(Ordering::SeqCst),
            self.compare_and_set.load(Ordering::SeqCst),
            self.lease_cycle.load(Ordering::SeqCst),
            self.batch.load(Ordering::SeqCst),
            self.watch.load(Ordering::SeqCst),
        ]
    }

    fn fail(&self, family: &'static str) {
        self.failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(family);
    }

    fn assert_no_failures(&self) {
        let failures = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            failures.is_empty(),
            "credential recycling surfaced application failures in fixed families: {failures:?}"
        );
    }
}

async fn wait_for_rotation_traffic_after(outcome: &RotationTrafficOutcome, baseline: [usize; 5]) {
    tokio::time::timeout(ROTATION_OPERATION_DEADLINE, async {
        loop {
            outcome.assert_no_failures();
            let current = outcome.snapshot();
            if current
                .iter()
                .zip(baseline)
                .all(|(current, baseline)| *current > baseline)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("every operation family and watch must progress after rotation");
}

struct RotationMaterialHarness<'a> {
    outcome: &'a RotationTrafficOutcome,
    client_config: &'a AuthenticatedClientConfig,
    server_config: &'a AuthenticatedServerConfig,
    client_tx: &'a tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
    server_tx: &'a tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
    reauthentication: &'a SessionReauthenticationControl,
}

impl RotationMaterialHarness<'_> {
    async fn rotate(
        &self,
        client_state: opc_identity::IdentityState,
        server_state: opc_identity::IdentityState,
    ) {
        let client_epoch = self.client_config.material_status().epoch();
        let server_epoch = self.server_config.material_status().epoch();
        self.client_tx.send_replace(Some(client_state));
        self.server_tx.send_replace(Some(server_state));
        wait_for_material_epoch_change(|| self.client_config.material_status(), client_epoch).await;
        wait_for_material_epoch_change(|| self.server_config.material_status(), server_epoch).await;
        self.reauthentication
            .request_reauthentication()
            .expect("request exact replacement authentication");
        let baseline = self.outcome.snapshot();
        wait_for_rotation_traffic_after(self.outcome, baseline).await;
    }
}

#[tokio::test]
async fn continuous_real_mtls_traffic_survives_trust_rotation_and_rejects_removed_old_trust() {
    let old_pki = TestPki::new();
    let new_pki = TestPki::new();
    let old_trust = [&old_pki.ca_cert];
    let overlap = [&old_pki.ca_cert, &new_pki.ca_cert];
    let new_trust = [&new_pki.ca_cert];
    let validity = time::Duration::days(1);
    let (client_tx, client_rx) = tokio::sync::watch::channel(Some(
        old_pki.identity_state_with_trust_and_validity(1, &old_trust, validity),
    ));
    let (server_tx, server_rx) = tokio::sync::watch::channel(Some(
        old_pki.identity_state_with_trust_and_validity(SERVER_REPLICA, &old_trust, validity),
    ));
    let client_config = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("rotating client config");
    let server_config = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("rotating server config");
    let manifest = manifest("cluster-trust-rotation", "generation-trust-rotation");
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let reauthentication = SessionReauthenticationControl::new();
    let counted = Arc::new(RotationTrafficBackend::new());
    let server = SessionReplicationServer::new(counted.clone(), server_config.clone(), binding)
        .with_connection_lifecycle(lifecycle_policy())
        .with_reauthentication_control(reauthentication.clone());
    let (handle, addr) = server
        .listen("127.0.0.1:0".parse().expect("listen address"))
        .await
        .expect("rotation listener");
    let backend = RemoteSessionBackend::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("rotation client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("rotation server binding"),
        resolver(addr),
        client_config.clone(),
        // The four concurrent direct families serialize through one bounded
        // pool. Keep their complete call SLO below the four-second lifecycle
        // drain while leaving enough budget for full mTLS + profile renewal.
        Some(ROTATION_OPERATION_DEADLINE),
    )
    .with_connection_lifecycle(lifecycle_policy())
    .with_reauthentication_control(reauthentication.clone());
    let cas_key = rotation_key("cas", 0);
    let cas_owner = OwnerId::new("rotation-cas-owner").expect("CAS owner");
    let cas_lease = backend
        .acquire(&cas_key, cas_owner, Duration::from_secs(300))
        .await
        .expect("initial CAS lease");
    let batch_key = rotation_key("batch", 0);
    let batch_owner = OwnerId::new("rotation-batch-owner").expect("batch owner");
    let batch_lease = backend
        .acquire(&batch_key, batch_owner, Duration::from_secs(300))
        .await
        .expect("initial batch lease");
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: batch_key.clone(),
                lease: batch_lease.clone(),
                expected_generation: None,
                new_record: rotation_record(batch_key.clone(), &batch_lease, 1),
            })
            .await,
        Ok(CompareAndSetResult::Success),
        "seed the record refreshed by continuous batch traffic"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let outcome = Arc::new(RotationTrafficOutcome::default());

    let get_task = tokio::spawn({
        let backend = backend.clone();
        let key = cas_key.clone();
        let stop = stop.clone();
        let outcome = outcome.clone();
        async move {
            while !stop.load(Ordering::Acquire) {
                if backend.get(&key).await.is_err() {
                    outcome.fail("get");
                    return;
                }
                outcome.get.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    });
    let cas_task = tokio::spawn({
        let backend = backend.clone();
        let key = cas_key.clone();
        let lease = cas_lease.clone();
        let stop = stop.clone();
        let outcome = outcome.clone();
        async move {
            let mut expected_generation = None;
            let mut generation = 1_u64;
            while !stop.load(Ordering::Acquire) {
                let result = backend
                    .compare_and_set(CompareAndSet {
                        key: key.clone(),
                        lease: lease.clone(),
                        expected_generation,
                        new_record: rotation_record(key.clone(), &lease, generation),
                    })
                    .await;
                if !matches!(result, Ok(CompareAndSetResult::Success)) {
                    outcome.fail("compare_and_set");
                    return;
                }
                outcome.compare_and_set.fetch_add(1, Ordering::SeqCst);
                expected_generation = Some(Generation::new(generation));
                generation = generation.checked_add(1).expect("bounded CAS generation");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    });
    let lease_task = tokio::spawn({
        let backend = backend.clone();
        let stop = stop.clone();
        let outcome = outcome.clone();
        async move {
            let mut index = 0_usize;
            while !stop.load(Ordering::Acquire) {
                let key = rotation_key("lease", index);
                let owner =
                    OwnerId::new(format!("rotation-lease-owner-{index}")).expect("lease owner");
                let Ok(lease) = backend.acquire(&key, owner, Duration::from_secs(300)).await else {
                    outcome.fail("acquire");
                    return;
                };
                let Ok(renewed) = backend.renew(&lease, Duration::from_secs(300)).await else {
                    outcome.fail("renew");
                    return;
                };
                if backend.release(renewed).await.is_err() {
                    outcome.fail("release");
                    return;
                }
                outcome.lease_cycle.fetch_add(1, Ordering::SeqCst);
                index = index.checked_add(1).expect("bounded lease index");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    });
    let batch_task = tokio::spawn({
        let backend = backend.clone();
        let key = batch_key.clone();
        let lease = batch_lease.clone();
        let stop = stop.clone();
        let outcome = outcome.clone();
        async move {
            while !stop.load(Ordering::Acquire) {
                let result = backend
                    .batch(vec![
                        SessionOp::Get { key: key.clone() },
                        SessionOp::RefreshTtl {
                            lease: lease.clone(),
                            ttl: Duration::from_secs(300),
                        },
                    ])
                    .await;
                if !matches!(
                    result.as_deref(),
                    Ok([
                        SessionOpResult::Get(Ok(_)),
                        SessionOpResult::RefreshTtl(Ok(()))
                    ])
                ) {
                    outcome.fail("batch");
                    return;
                }
                outcome.batch.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    });
    let (watch_target_tx, mut watch_target_rx) = tokio::sync::watch::channel(None::<u64>);
    let watch_task = tokio::spawn({
        let backend = backend.clone();
        let outcome = outcome.clone();
        async move {
            let Ok(mut stream) = backend.watch(1).await else {
                outcome.fail("watch_setup");
                return Vec::new();
            };
            let mut expected = 1_u64;
            let mut sequences = Vec::new();
            loop {
                tokio::select! {
                    changed = watch_target_rx.changed() => {
                        if changed.is_err() {
                            outcome.fail("watch_target");
                            return sequences;
                        }
                    }
                    item = stream.next() => {
                        let Some(Ok(entry)) = item else {
                            outcome.fail("watch_stream");
                            return sequences;
                        };
                        if entry.sequence != expected {
                            outcome.fail("watch_sequence");
                            return sequences;
                        }
                        sequences.push(entry.sequence);
                        outcome.watch.fetch_add(1, Ordering::SeqCst);
                        expected = expected.checked_add(1).expect("bounded watch sequence");
                    }
                }
                if watch_target_rx
                    .borrow()
                    .is_some_and(|target| sequences.last().copied() == Some(target))
                {
                    return sequences;
                }
            }
        }
    });

    wait_for_rotation_traffic_after(&outcome, [0; 5]).await;
    let rotation = RotationMaterialHarness {
        outcome: &outcome,
        client_config: &client_config,
        server_config: &server_config,
        client_tx: &client_tx,
        server_tx: &server_tx,
        reauthentication: &reauthentication,
    };
    rotation
        .rotate(
            old_pki.identity_state_with_trust_and_validity(1, &overlap, validity),
            old_pki.identity_state_with_trust_and_validity(SERVER_REPLICA, &overlap, validity),
        )
        .await;
    rotation
        .rotate(
            new_pki.identity_state_with_trust_and_validity(1, &overlap, validity),
            new_pki.identity_state_with_trust_and_validity(SERVER_REPLICA, &overlap, validity),
        )
        .await;
    rotation
        .rotate(
            new_pki.identity_state_with_trust_and_validity(1, &new_trust, validity),
            new_pki.identity_state_with_trust_and_validity(SERVER_REPLICA, &new_trust, validity),
        )
        .await;

    stop.store(true, Ordering::Release);
    // Cleanup gets scheduling margin beyond the three-second operation SLO.
    // This bound supervises task teardown only; it does not relax operation or
    // post-rotation progress deadlines.
    for task in [get_task, cas_task, lease_task, batch_task] {
        tokio::time::timeout(ROTATION_CLEANUP_DEADLINE, task)
            .await
            .expect("traffic task must stop within the cleanup scheduling margin")
            .expect("traffic task join");
    }
    outcome.assert_no_failures();
    let final_sequence = counted
        .inner
        .max_replication_sequence()
        .await
        .expect("final replication head");
    watch_target_tx.send_replace(Some(final_sequence));
    let sequences = tokio::time::timeout(ROTATION_CLEANUP_DEADLINE, watch_task)
        .await
        .expect("watch must reach the final successor within its cleanup-only margin")
        .expect("watch task join");
    outcome.assert_no_failures();
    assert_eq!(
        sequences,
        (1..=final_sequence).collect::<Vec<_>>(),
        "watch continuity must be gap-free and duplicate-free through every retirement"
    );
    let progress = outcome.snapshot();
    let backend_counts = counted.counts.snapshot();
    assert_eq!(backend_counts[0], progress[0]);
    assert_eq!(backend_counts[1], progress[1] + 1);
    assert_eq!(backend_counts[2], progress[3]);
    assert_eq!(backend_counts[3], progress[2] + 2);
    assert_eq!(backend_counts[4], progress[2]);
    assert_eq!(backend_counts[5], progress[2]);

    let old_client = TlsConfigBuilder::new(
        tokio::sync::watch::channel(Some(
            old_pki.identity_state_with_trust_and_validity(1, &overlap, validity),
        ))
        .1,
    )
    .allow_any_trusted_peer()
    .build_authenticated_client_config()
    .expect("old client config");
    let old_client_result =
        try_raw_tls_connection_with_alpn(addr, old_client, vec![SESSION_NET_ALPN.to_vec()]).await;
    let old_client_admitted = if let Ok(mut connection) = old_client_result {
        let binding = manifest
            .bind_local(replica_id(1))
            .expect("old client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("old server binding");
        write_frame(&mut connection, &hello_for(&binding))
            .await
            .is_ok()
            && matches!(
                read_frame::<_, Response>(&mut connection, DEFAULT_MAX_FRAME_SIZE).await,
                Ok(Response::HelloAck { .. })
            )
    } else {
        false
    };
    assert!(
        !old_client_admitted,
        "new-only server trust must reject the old client issuer before application admission"
    );

    let new_client = TlsConfigBuilder::new(
        tokio::sync::watch::channel(Some(
            new_pki.identity_state_with_trust_and_validity(1, &new_trust, validity),
        ))
        .1,
    )
    .allow_any_trusted_peer()
    .build_authenticated_client_config()
    .expect("new-only client config");
    let old_server = TlsConfigBuilder::new(
        tokio::sync::watch::channel(Some(old_pki.identity_state_with_trust_and_validity(
            SERVER_REPLICA,
            &overlap,
            validity,
        )))
        .1,
    )
    .allow_any_trusted_peer()
    .build_authenticated_server_config()
    .expect("old server config");
    let (old_addr, old_server_task) = start_single_probe_server(old_server, 33).await;
    assert!(
        try_raw_tls_connection_with_alpn(old_addr, new_client, vec![SESSION_NET_ALPN.to_vec()])
            .await
            .is_err(),
        "new-only client trust must reject the old server issuer"
    );
    tokio::time::timeout(Duration::from_secs(2), old_server_task)
        .await
        .expect("old server rejection task must finish within the transport bound")
        .expect("old server rejection task");
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn downgrade_and_malformed_hello_are_rejected_before_dispatch() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", "generation-7");
    let (handle, addr) = start_server(&pki, &manifest).await;

    let mut legacy = raw_tls_connection(addr, pki.client_config(1)).await;
    write_frame(
        &mut legacy,
        &Request::Hello {
            contract_version: CONTRACT_VERSION - 1,
            contract_profile: None,
            node_id: replica_id(1).as_str().to_string(),
            expected_server_replica_id: None,
            cluster_id: None,
            configuration_id: None,
            configuration_epoch: None,
            handshake_nonce: None,
            requested_response_frame_size: None,
        },
    )
    .await
    .expect("legacy Hello");
    let response: Response = read_frame(&mut legacy, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("version response");
    assert!(matches!(
        response,
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
            server_replica_id: None,
            ..
        }
    ));

    let binding = manifest
        .bind_local(replica_id(1))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let mut wrong_profile = CURRENT_CONTRACT_PROFILE;
    wrong_profile.error_set_revision = wrong_profile.error_set_revision.saturating_add(1);
    for incompatible_profile in [None, Some(wrong_profile)] {
        let mut profile_mismatch = raw_tls_connection(addr, pki.client_config(1)).await;
        let mut hello = hello_for(&binding);
        let Request::Hello {
            contract_profile, ..
        } = &mut hello
        else {
            unreachable!("helper always returns Hello");
        };
        *contract_profile = incompatible_profile;
        write_frame(&mut profile_mismatch, &hello)
            .await
            .expect("same-version incompatible-profile Hello");
        let response: Response = read_frame(&mut profile_mismatch, DEFAULT_MAX_FRAME_SIZE)
            .await
            .expect("contract-profile rejection response");
        assert!(matches!(
            response,
            Response::HelloAck {
                contract_version: CONTRACT_VERSION,
                contract_profile: Some(CURRENT_CONTRACT_PROFILE),
                server_replica_id: None,
                accepted_client_replica_id: None,
                cluster_id: None,
                configuration_id: None,
                handshake_nonce: None,
                ..
            }
        ));
    }

    let mut malformed = raw_tls_connection(addr, pki.client_config(1)).await;
    write_frame(
        &mut malformed,
        &Request::Hello {
            contract_version: CONTRACT_VERSION,
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
            node_id: replica_id(1).as_str().to_string(),
            expected_server_replica_id: None,
            cluster_id: None,
            configuration_id: None,
            configuration_epoch: None,
            handshake_nonce: None,
            requested_response_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
        },
    )
    .await
    .expect("malformed Hello");
    let response: Response = read_frame(&mut malformed, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("rejection response");
    assert!(matches!(
        response,
        Response::HelloRejected {
            reason: opc_session_net::HelloRejectReason::Malformed
        }
    ));

    handle.abort();
}

#[tokio::test]
async fn reconnect_accepts_rotation_but_new_connections_reject_a_relabelled_peer() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", "generation-7");
    let (identity_tx, identity_rx) =
        tokio::sync::watch::channel(Some(pki.identity_state(SERVER_REPLICA)));
    let server_config = TlsConfigBuilder::new(identity_rx)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("rotating server config");

    let (first_addr, first_server) = start_single_probe_server(server_config.clone(), 11).await;
    let current_addr = Arc::new(std::sync::RwLock::new(first_addr));
    let dynamic_resolver: RemoteAddrResolver = {
        let current_addr = current_addr.clone();
        Arc::new(move || {
            let current_addr = current_addr.clone();
            Box::pin(async move { Ok(*current_addr.read().expect("resolver address lock")) })
        })
    };
    let binding = manifest
        .bind_local(replica_id(1))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let backend = RemoteSessionBackend::new_with_resolver(
        binding,
        dynamic_resolver,
        pki.client_config(1),
        Some(Duration::from_millis(750)),
    );
    assert_eq!(backend.probe_replication_head().await, Ok(11));
    first_server.await.expect("first probe server");

    identity_tx
        .send(Some(pki.identity_state(SERVER_REPLICA)))
        .expect("rotate server certificate");
    let (second_addr, second_server) = start_single_probe_server(server_config.clone(), 22).await;
    *current_addr.write().expect("resolver address lock") = second_addr;
    assert_eq!(backend.probe_replication_head().await, Ok(22));
    second_server.await.expect("second probe server");

    identity_tx
        .send(Some(pki.identity_state(3)))
        .expect("rotate to wrong server identity");
    let (wrong_addr, wrong_server) = start_single_probe_server(server_config, 33).await;
    *current_addr.write().expect("resolver address lock") = wrong_addr;
    assert_eq!(
        backend.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Authentication)
    );
    wrong_server.await.expect("wrong-identity probe server");
}

#[tokio::test]
async fn replayed_ack_nonce_is_rejected_over_mutual_tls() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", "generation-7");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("scripted server listener");
    let addr = listener.local_addr().expect("scripted server address");
    let mut config = pki
        .server_config(SERVER_REPLICA)
        .rustls_config()
        .as_ref()
        .clone();
    config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    let scripted_server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("scripted server accept");
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .expect("scripted mutual TLS");
        let hello: Request = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
            .await
            .expect("read Hello");
        let mut ack = successful_hello_ack(&hello);
        let Response::HelloAck {
            handshake_nonce, ..
        } = &mut ack
        else {
            unreachable!("helper always returns HelloAck");
        };
        *handshake_nonce = Some(uuid::Uuid::nil());
        write_frame(&mut tls, &ack).await.expect("write stale Ack");
    });

    let backend = remote(&manifest, 1, SERVER_REPLICA, addr, pki.client_config(1));
    assert_eq!(
        backend.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Protocol)
    );
    scripted_server.await.expect("scripted server task");
}

#[tokio::test]
async fn authenticated_handshake_then_stalled_operation_is_bounded() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", "generation-7");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("stalling server listener");
    let addr = listener.local_addr().expect("stalling server address");
    let mut config = pki
        .server_config(SERVER_REPLICA)
        .rustls_config()
        .as_ref()
        .clone();
    config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    let (request_seen_tx, request_seen_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("stalling server accept");
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .expect("stalling mutual TLS");
        let hello: Request = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
            .await
            .expect("read authenticated Hello");
        write_frame(&mut tls, &successful_hello_ack(&hello))
            .await
            .expect("write authenticated Ack");
        let request: Request = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
            .await
            .expect("read readiness request");
        assert!(matches!(request, Request::MaxReplicationSequence));
        request_seen_tx.send(()).expect("signal readiness request");
        std::future::pending::<()>().await;
    });
    let backend = RemoteSessionBackend::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("server binding"),
        resolver(addr),
        pki.client_config(1),
        Some(Duration::from_secs(2)),
    );

    assert_eq!(
        backend.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Timeout)
    );
    request_seen_rx
        .await
        .expect("authenticated request observed");
    server.abort();
}

#[tokio::test]
async fn missing_or_wrong_alpn_fails_closed_on_both_sides() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", "generation-7");

    for server_alpn in [
        Vec::new(),
        vec![b"different-protocol".to_vec()],
        vec![b"opc-session-net/3".to_vec()],
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("wrong-ALPN server listener");
        let addr = listener.local_addr().expect("wrong-ALPN server address");
        let mut server_config = pki
            .server_config(SERVER_REPLICA)
            .rustls_config()
            .as_ref()
            .clone();
        server_config.alpn_protocols = server_alpn;
        let wrong_alpn_server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("wrong-ALPN accept");
            let _ = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await;
        });
        let backend = remote(&manifest, 1, SERVER_REPLICA, addr, pki.client_config(1));
        assert_eq!(
            backend.probe_replication_head().await,
            Err(ReplicaReadinessFailure::Protocol)
        );
        wrong_alpn_server.await.expect("wrong-ALPN server task");
    }

    let (handle, server_addr) = start_server(&pki, &manifest).await;
    for client_alpn in [
        vec![b"different-protocol".to_vec()],
        vec![b"opc-session-net/3".to_vec()],
    ] {
        let wrong_alpn_client =
            try_raw_tls_connection_with_alpn(server_addr, pki.client_config(1), client_alpn).await;
        assert!(wrong_alpn_client.is_err());
    }
    handle.abort();
}

#[tokio::test]
async fn server_revalidates_a_rotated_client_svid_instead_of_resuming_identity() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", "generation-7");
    let (handle, addr) = start_server(&pki, &manifest).await;
    let binding = manifest
        .bind_local(replica_id(1))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("server binding");

    let (identity_tx, identity_rx) = tokio::sync::watch::channel(Some(pki.identity_state(1)));
    let resumption_enabled_client = TlsConfigBuilder::new(identity_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("raw rotating client config");

    let mut first = raw_tls_connection(addr, resumption_enabled_client.clone()).await;
    let first_hello = hello_for(&binding);
    write_frame(&mut first, &first_hello)
        .await
        .expect("first Hello");
    let first_response: Response = read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("first Hello response");
    let first_epoch = match first_response {
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            cas_idempotency_epoch: Some(epoch),
            ..
        } => epoch,
        other => panic!("unexpected first Hello response: {other:?}"),
    };
    let key = SessionKey {
        tenant: TenantId::new("tenant-a").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: StableId::new(Bytes::from_static(b"credential-rotation-cas"))
            .expect("stable ID"),
    };
    let owner = OwnerId::new("credential-rotation-owner").expect("owner");
    write_frame(
        &mut first,
        &Request::AcquireLease {
            key: key.clone(),
            owner: owner.clone(),
            ttl: Duration::from_secs(60),
        },
    )
    .await
    .expect("acquire request");
    let lease = match read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("acquire response")
    {
        Response::AcquireLease(Ok(lease)) => lease,
        other => panic!("unexpected acquire response: {other:?}"),
    };
    let operation = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner,
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("credential-rotation").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"opaque-test-payload"),
        },
    };
    let request_id = uuid::Uuid::new_v4().hyphenated().to_string();
    let cas = Request::CompareAndSet {
        op: operation,
        request_id: Some(request_id),
        idempotency_epoch: Some(first_epoch.hyphenated().to_string()),
    };
    write_frame(&mut first, &cas).await.expect("first CAS");
    assert!(matches!(
        read_frame(&mut first, DEFAULT_MAX_FRAME_SIZE)
            .await
            .expect("first CAS response"),
        Response::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));
    drop(first);

    identity_tx.send_replace(Some(pki.identity_state(1)));
    let mut renewed = raw_tls_connection(addr, resumption_enabled_client.clone()).await;
    write_frame(&mut renewed, &hello_for(&binding))
        .await
        .expect("renewed Hello");
    let renewed_epoch = match read_frame(&mut renewed, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("renewed Hello response")
    {
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            cas_idempotency_epoch: Some(epoch),
            ..
        } => epoch,
        other => panic!("unexpected renewed Hello response: {other:?}"),
    };
    assert_eq!(renewed_epoch, first_epoch);
    write_frame(&mut renewed, &cas)
        .await
        .expect("replayed CAS after SVID renewal");
    assert!(matches!(
        read_frame(&mut renewed, DEFAULT_MAX_FRAME_SIZE)
            .await
            .expect("replayed CAS response"),
        Response::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));
    drop(renewed);

    identity_tx.send_replace(Some(pki.identity_state(3)));
    let mut rotated = raw_tls_connection(addr, resumption_enabled_client).await;
    write_frame(&mut rotated, &hello_for(&binding))
        .await
        .expect("rotated Hello");
    let rotated_response: Response = read_frame(&mut rotated, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("rotated Hello response");
    assert!(matches!(
        rotated_response,
        Response::HelloRejected {
            reason: opc_session_net::HelloRejectReason::Authentication
        }
    ));

    handle.abort();
}
