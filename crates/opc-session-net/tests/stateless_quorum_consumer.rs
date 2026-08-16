//! Contract tests for the production stateless quorum-consumer boundary.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{
    RemoteAddrResolver, SessionConsumerAuthorizer, SessionConsumerClientError,
    SessionConsumerLeaseMutationError, SessionConsumerMutationError, SessionQuorumConsumerServer,
    StatelessSessionConsumerClient, SESSION_QUORUM_CONSUMER_ALPN,
};
use opc_session_store::{
    BackendCapabilities, ConsensusSessionStore, OwnerId, QuorumReplicaDescriptor,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    SessionConsensusIdentity, SessionConsumerChange, SessionConsumerIdentity,
    SessionConsumerLeaseError, SessionConsumerOperation, SessionConsumerRejection,
    SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerResponse,
    SessionConsumerScope, SessionConsumerStoreError, SessionKey, SessionKeyType,
    SessionLeaseManager, SessionQuorumConsumer, SqliteSessionBackend, ValidatedQuorumTopology,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct TestPki {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    fn new() -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "stateless consumer test CA");
        Self {
            ca: rcgen::CertifiedIssuer::self_signed(parameters, ca_key)
                .expect("test CA certificate"),
        }
    }

    fn client_config(&self, spiffe_id: &str) -> AuthenticatedClientConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("test client mTLS config")
    }

    fn server_config(&self, spiffe_id: &str) -> AuthenticatedServerConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("test server mTLS config")
    }

    fn identity_state(&self, spiffe_id: &str) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "stateless consumer test leaf");
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe_id).expect("test SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("test leaf key");
        let certificate = parameters
            .signed_by(&key, &self.ca)
            .expect("test leaf certificate");
        let certificates =
            parse_certs_pem(&(certificate.pem() + &self.ca.pem())).expect("test certificate chain");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("test private key");
        let mut bundles = opc_identity::TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("test.example")
                .expect("test trust domain"),
            certificates: parse_certs_pem(&self.ca.pem()).expect("test trust bundle"),
        });
        build_identity_state(certificates, private_key, bundles).expect("test identity state")
    }
}

#[derive(Default)]
struct CountingConsumer {
    calls: AtomicUsize,
}

#[derive(Default)]
struct HangingConsumer {
    calls: AtomicUsize,
}

#[async_trait]
impl SessionQuorumConsumer for HangingConsumer {
    async fn execute(
        &self,
        _identity: &SessionConsumerIdentity,
        _request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }

    async fn watch(
        &self,
        _identity: &SessionConsumerIdentity,
        _scope: SessionConsumerScope,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        Err(SessionConsumerRejection::Unavailable)
    }
}

#[async_trait]
impl SessionQuorumConsumer for CountingConsumer {
    async fn execute(
        &self,
        _identity: &SessionConsumerIdentity,
        _request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled())
    }

    async fn watch(
        &self,
        _identity: &SessionConsumerIdentity,
        _scope: SessionConsumerScope,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        Err(SessionConsumerRejection::Unavailable)
    }
}

async fn authorizer_from_admitted_store(
    client_spiffe: &str,
) -> (SessionConsumerAuthorizer, SessionConsumerScope) {
    let (_snapshots, store, scope, authorizer) =
        admitted_store_and_authorizer([client_spiffe.to_owned()]).await;
    // The authorizer contains the store-issued scope and member exclusion set;
    // it remains valid after this short-lived fixture store is dropped.
    drop(store);
    (authorizer, scope)
}

async fn admitted_store_and_authorizer(
    client_spiffes: impl IntoIterator<Item = String>,
) -> (
    tempfile::TempDir,
    ConsensusSessionStore,
    SessionConsumerScope,
    SessionConsumerAuthorizer,
) {
    let snapshots = tempfile::tempdir().expect("snapshot directory");
    let replica_id = ReplicaId::new("stateless-consumer-authorizer-test").expect("replica ID");
    let descriptor = QuorumReplicaDescriptor::new(
        replica_id.clone(),
        ReplicaEndpoint::new("consumer-authorizer.test.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(spiffe("member")).expect("member TLS identity"),
        ReplicaFailureDomain::new("consumer-authorizer-zone").expect("failure domain"),
        ReplicaBackingIdentity::new("consumer-authorizer-disk").expect("backing identity"),
    );
    let cluster =
        ConsensusClusterId::new("stateless-consumer-authorizer-test").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let configuration =
        derive_configuration_id(cluster, epoch, &[descriptor.configuration_fingerprint()]);
    let topology = ValidatedQuorumTopology::try_new_consensus_lab_singleton(
        replica_id,
        vec![descriptor],
        SessionConsensusIdentity::new(cluster, configuration, epoch),
    )
    .expect("singleton topology");
    let store = ConsensusSessionStore::open(
        topology,
        SqliteSessionBackend::in_memory().expect("SQLite backend"),
        snapshots.path(),
        Default::default(),
    )
    .await
    .expect("open store");
    store.initialize_cluster().await.expect("initialize store");
    let manifest = store
        .consumer_authorization_manifest()
        .await
        .expect("admitted consumer manifest");
    let scope = manifest.scope();
    let authorizer = SessionConsumerAuthorizer::try_new(
        manifest,
        client_spiffes
            .into_iter()
            .map(|identity| SpiffeId::new(identity).expect("client SPIFFE")),
    )
    .expect("consumer authorizer");
    (snapshots, store, scope, authorizer)
}

fn spiffe(suffix: &str) -> String {
    format!("spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/{suffix}")
}

fn consumer_client(
    pki: &TestPki,
    address: SocketAddr,
    server_spiffe: &str,
    client_spiffe: &str,
    scope: SessionConsumerScope,
) -> StatelessSessionConsumerClient {
    StatelessSessionConsumerClient::new(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(client_spiffe),
    )
}

fn test_key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("consumer-test").expect("tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"opaque-session-reference")
            .try_into()
            .expect("stable ID"),
    }
}

async fn test_lease() -> opc_session_store::LeaseGuard {
    let backend = SqliteSessionBackend::in_memory().expect("test lease backend");
    backend
        .acquire(
            &test_key(),
            OwnerId::new("consumer-test-owner").expect("owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("test lease")
}

async fn raw_authenticated_consumer_connection(
    pki: &TestPki,
    address: SocketAddr,
    client_spiffe: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let handshake = pki
        .client_config(client_spiffe)
        .begin_handshake()
        .expect("raw test TLS handshake material");
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![SESSION_QUORUM_CONSUMER_ALPN.to_vec()];
    let tcp = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect raw consumer TLS socket");
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            tcp,
        )
        .await
        .expect("complete raw consumer mTLS")
}

#[test]
fn production_default_features_expose_a_dedicated_stateless_consumer_boundary() {
    let _ = std::any::TypeId::of::<StatelessSessionConsumerClient>();
    let _ = std::any::TypeId::of::<SessionQuorumConsumerServer>();
    let _ = std::any::TypeId::of::<SessionConsumerAuthorizer>();
    assert_ne!(SESSION_QUORUM_CONSUMER_ALPN, b"opc-session-consensus/2");
    assert_ne!(SESSION_QUORUM_CONSUMER_ALPN, b"opc-session-net/5");
}

#[tokio::test]
async fn one_authenticated_consumer_call_uses_the_dedicated_alpn_without_replay() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let client_spiffe = spiffe("client");
    let service = Arc::new(CountingConsumer::default());
    let (authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless consumer listener");
    let client = StatelessSessionConsumerClient::new(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    );

    assert_eq!(
        client
            .capabilities()
            .await
            .expect("authenticated capability call"),
        BackendCapabilities::all_enabled()
    );
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        1,
        "the client must send exactly one request and never replay it automatically"
    );

    let wrong_scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
        ConsensusClusterId::from_bytes([1; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([3; 32]),
        ConsensusConfigurationEpoch::new(1).expect("non-zero configuration epoch"),
    ));
    let wrong_scope_client = StatelessSessionConsumerClient::new(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        wrong_scope,
        pki.client_config(&client_spiffe),
    );
    assert_eq!(
        wrong_scope_client.capabilities().await,
        Err(SessionConsumerClientError::Scope),
        "a mismatched cluster/configuration/epoch scope must not reach the service"
    );
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn consumer_resolver_reconnects_the_same_client_after_endpoint_replacement() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("resolver-server");
    let client_spiffe = spiffe("resolver-client");
    let first_service = Arc::new(CountingConsumer::default());
    let (first_authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let (first_handle, first_address) = SessionQuorumConsumerServer::new(
        first_service.clone(),
        pki.server_config(&server_spiffe),
        first_authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start first consumer listener");

    let resolved_address = Arc::new(RwLock::new(first_address));
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolved_address = Arc::clone(&resolved_address);
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolved_address = Arc::clone(&resolved_address);
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Ok(*resolved_address.read().expect("resolver address lock"))
            })
        })
    };
    let client = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(first_address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    );

    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    assert_eq!(first_service.calls.load(Ordering::SeqCst), 1);
    first_handle.abort_and_wait().await;

    let second_service = Arc::new(CountingConsumer::default());
    let (second_authorizer, second_scope) = authorizer_from_admitted_store(&client_spiffe).await;
    assert_eq!(scope, second_scope, "replacement listener keeps its scope");
    let (second_handle, second_address) = SessionQuorumConsumerServer::new(
        second_service.clone(),
        pki.server_config(&server_spiffe),
        second_authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start replacement consumer listener");
    *resolved_address.write().expect("resolver address lock") = second_address;

    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled()),
        "the same client must reconnect through the replacement address"
    );
    assert_eq!(second_service.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "each new consumer connection must invoke the resolver"
    );
    second_handle.abort_and_wait().await;
}

#[tokio::test]
async fn pre_request_connection_budget_expires_during_a_stalled_tls_handshake() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("pre-request-stalled-server");
    let client_spiffe = spiffe("pre-request-stalled-client");
    let (_authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled TLS listener");
    let address = listener.local_addr().expect("stalled listener address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let stalled_tls = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept TLS client");
            accepted.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
        })
    };
    let client = StatelessSessionConsumerClient::new_with_resolver(
        Arc::new(move || Box::pin(async move { Ok(address) })),
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_pre_request_connection_timeout(Duration::from_millis(100))
    .with_operation_timeout(Duration::from_secs(1));

    let started_at = tokio::time::Instant::now();
    let outcome = client
        .delete_fenced_with_id(SessionConsumerRequestId::new(), test_lease().await)
        .await;
    let elapsed = started_at.elapsed();
    assert!(matches!(
        outcome,
        Err(SessionConsumerMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable
        })
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert!(
        elapsed < Duration::from_millis(500),
        "the pre-request budget must expire before the complete operation deadline"
    );
    stalled_tls.abort();
}

#[tokio::test]
async fn pre_request_connection_budget_leaves_time_for_a_healthy_later_roster_endpoint() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("pre-request-roster-server");
    let client_spiffe = spiffe("pre-request-roster-client");
    let (_first_authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let stalled_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled TLS listener");
    let stalled_address = stalled_listener
        .local_addr()
        .expect("stalled listener address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let stalled_tls = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            let (_stream, _) = stalled_listener
                .accept()
                .await
                .expect("accept stalled TLS client");
            accepted.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
        })
    };
    let healthy_service = Arc::new(CountingConsumer::default());
    let (healthy_authorizer, healthy_scope) = authorizer_from_admitted_store(&client_spiffe).await;
    assert_eq!(scope, healthy_scope, "fixed roster retains one scope");
    let (healthy_handle, healthy_address) = SessionQuorumConsumerServer::new(
        healthy_service.clone(),
        pki.server_config(&server_spiffe),
        healthy_authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start healthy consumer listener");

    let resolver_attempts = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolver_attempts = Arc::clone(&resolver_attempts);
        Arc::new(move || {
            let address = if resolver_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                stalled_address
            } else {
                healthy_address
            };
            Box::pin(async move { Ok(address) })
        })
    };
    let client = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(stalled_address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_pre_request_connection_timeout(Duration::from_millis(500))
    .with_operation_timeout(Duration::from_secs(2));

    let lease = test_lease().await;
    let started_at = tokio::time::Instant::now();
    let stalled = client
        .delete_fenced_with_id(SessionConsumerRequestId::new(), lease)
        .await;
    assert!(matches!(
        stalled,
        Err(SessionConsumerMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable
        })
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled()),
        "a later admitted endpoint must remain reachable within the caller window"
    );
    assert_eq!(healthy_service.calls.load(Ordering::SeqCst), 1);
    assert!(
        started_at.elapsed() < Duration::from_millis(1_500),
        "the stalled endpoint must not consume the fixed-roster renewal window"
    );
    stalled_tls.abort();
    healthy_handle.abort_and_wait().await;
}

#[tokio::test]
async fn pre_request_connection_budget_does_not_shorten_post_call_outcome_deadline() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("pre-request-post-call-server");
    let client_spiffe = spiffe("pre-request-post-call-client");
    let (authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let hanging = Arc::new(HangingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        hanging.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start hanging consumer listener");
    let request_id = SessionConsumerRequestId::new();
    let client = StatelessSessionConsumerClient::new_with_resolver(
        Arc::new(move || Box::pin(async move { Ok(address) })),
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_pre_request_connection_timeout(Duration::from_millis(500))
    .with_operation_timeout(Duration::from_secs(1));

    let lease = test_lease().await;
    let started_at = tokio::time::Instant::now();
    let outcome = client.delete_fenced_with_id(request_id, lease).await;
    assert!(matches!(
        outcome,
        Err(SessionConsumerMutationError::OutcomeUnknown { request_id: retry_id })
            if retry_id == request_id
    ));
    assert_eq!(hanging.calls.load(Ordering::SeqCst), 1);
    assert!(
        started_at.elapsed() >= Duration::from_millis(800),
        "the post-call response wait must retain the full operation deadline"
    );
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn resolver_failure_is_unavailable_and_not_transmitted_for_mutations_and_leases() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("resolver-failure-server");
    let client_spiffe = spiffe("resolver-failure-client");
    let (_authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("resolver failure is redacted"))
            })
        })
    };
    let client = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
        ),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    );

    let mutation = client
        .delete_fenced_with_id(SessionConsumerRequestId::new(), test_lease().await)
        .await;
    assert!(matches!(
        mutation,
        Err(SessionConsumerMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable
        })
    ));
    let lease = client
        .release_with_id(SessionConsumerRequestId::new(), test_lease().await)
        .await;
    assert!(matches!(
        lease,
        Err(SessionConsumerLeaseMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable
        })
    ));
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "each failed request resolves before its application frame is written"
    );
}

#[tokio::test]
async fn outcome_unknown_is_not_replayed_and_consumer_debug_is_redacted() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("debug-server");
    let client_spiffe = spiffe("debug-client");
    let (authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let hanging = Arc::new(HangingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        hanging.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start hanging consumer listener");
    let request_id = SessionConsumerRequestId::from_bytes([0x5a; 16]);
    let client = StatelessSessionConsumerClient::new_with_resolver(
        Arc::new(move || Box::pin(async move { Ok(address) })),
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1));

    let outcome = client
        .delete_fenced_with_id(request_id, test_lease().await)
        .await;
    assert!(matches!(
        &outcome,
        Err(SessionConsumerMutationError::OutcomeUnknown { request_id: retry_id })
            if *retry_id == request_id
    ));
    assert_eq!(
        hanging.calls.load(Ordering::SeqCst),
        1,
        "the client must never replay an application mutation after its outcome is unknown"
    );

    let diagnostic_address = "203.0.113.77:7443"
        .parse::<SocketAddr>()
        .expect("diagnostic address");
    let diagnostic_dns = "voter.state.example";
    let diagnostic_client = StatelessSessionConsumerClient::new_with_resolver(
        Arc::new(move || Box::pin(async move { Ok(diagnostic_address) })),
        rustls_pki_types::ServerName::try_from(diagnostic_dns.to_owned())
            .expect("diagnostic DNS server name"),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    );
    let client_debug = format!("{diagnostic_client:?}");
    let outcome_debug = format!("{outcome:?}");
    assert!(!client_debug.contains(&diagnostic_address.to_string()));
    assert!(!client_debug.contains(diagnostic_dns));
    assert!(!client_debug.contains(&server_spiffe));
    assert!(!client_debug.contains(&format!("{scope:?}")));
    assert!(!client_debug.contains("address"));
    assert!(!client_debug.contains("scope"));
    assert!(!outcome_debug.contains(&format!("{request_id:?}")));
    assert!(!outcome_debug.contains("request_id"));
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn lease_call_boundary_classifies_before_and_after_transmission() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let admitted_spiffe = spiffe("admitted");
    let rejected_spiffe = spiffe("rejected");
    let (authorizer, scope) = authorizer_from_admitted_store(&admitted_spiffe).await;
    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");

    let request_id = SessionConsumerRequestId::new();
    let rejected = consumer_client(&pki, address, &server_spiffe, &rejected_spiffe, scope)
        .release_with_id(request_id, test_lease().await)
        .await;
    assert!(
        matches!(
            &rejected,
            Err(SessionConsumerLeaseMutationError::NotTransmitted {
                cause: SessionConsumerClientError::Authentication
                    | SessionConsumerClientError::Unavailable
            })
        ),
        "unexpected pre-call result: {rejected:?}"
    );
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    handle.abort_and_wait().await;

    let (authorizer, scope) = authorizer_from_admitted_store(&admitted_spiffe).await;
    let hanging = Arc::new(HangingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        hanging.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start hanging consumer listener");
    let uncertain = consumer_client(&pki, address, &server_spiffe, &admitted_spiffe, scope)
        .with_operation_timeout(Duration::from_secs(1))
        .release_with_id(request_id, test_lease().await)
        .await;
    assert!(matches!(
        uncertain,
        Err(SessionConsumerLeaseMutationError::OutcomeUnknown {
            request_id: retry_id
        }) if retry_id == request_id
    ));
    assert_eq!(hanging.calls.load(Ordering::SeqCst), 1);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn twelve_concurrent_stateless_consumers_remain_outside_member_authority() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let client_spiffes = (0..12)
        .map(|index| spiffe(&format!("concurrent-{index}")))
        .collect::<Vec<_>>();
    let (_snapshots, store, scope, authorizer) =
        admitted_store_and_authorizer(client_spiffes.clone()).await;
    let manifest = store
        .consumer_authorization_manifest()
        .await
        .expect("authoritative member-exclusion manifest");
    assert_eq!(manifest.consensus_member_identities().count(), 1);
    assert!(format!("{authorizer:?}").contains("consumer_count: 12"));
    assert!(format!("{authorizer:?}").contains("consensus_member_count: 1"));

    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless consumer listener");
    let clients = client_spiffes
        .iter()
        .map(|client_spiffe| consumer_client(&pki, address, &server_spiffe, client_spiffe, scope))
        .collect::<Vec<_>>();

    let results =
        futures_util::future::join_all(clients.iter().map(|client| client.capabilities())).await;
    assert!(results
        .iter()
        .all(|result| result == &Ok(BackendCapabilities::all_enabled())));
    assert_eq!(service.calls.load(Ordering::SeqCst), 12);
    for client in clients {
        let diagnostic = format!("{client:?}");
        assert!(!diagnostic.contains("127.0.0.1"));
        assert!(!diagnostic.contains("concurrent-"));
        assert!(!diagnostic.contains("snapshot"));
        assert!(!diagnostic.contains("replica"));
    }
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn consumer_mtls_role_identity_and_server_identity_mismatches_fail_closed() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let admitted_spiffe = spiffe("admitted");
    let member_spiffe = spiffe("member");
    let (authorizer, scope) = authorizer_from_admitted_store(&admitted_spiffe).await;
    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless consumer listener");

    let unknown_consumer = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &spiffe("not-admitted"),
        scope,
    );
    assert_eq!(
        unknown_consumer.capabilities().await,
        Err(SessionConsumerClientError::Unavailable),
        "the listener must close an unauthorized authenticated connection without a role oracle"
    );

    let consensus_member_as_consumer =
        consumer_client(&pki, address, &server_spiffe, &member_spiffe, scope);
    assert_eq!(
        consensus_member_as_consumer.capabilities().await,
        Err(SessionConsumerClientError::Unavailable),
        "a consensus-member certificate must not receive a consumer-role oracle"
    );

    let wrong_server_identity = consumer_client(
        &pki,
        address,
        &spiffe("different-server"),
        &admitted_spiffe,
        scope,
    );
    assert_eq!(
        wrong_server_identity.capabilities().await,
        Err(SessionConsumerClientError::Authentication)
    );
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn malformed_and_oversized_consumer_frames_are_rejected_before_dispatch() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let client_spiffe = spiffe("client");
    let (authorizer, _scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless consumer listener");

    let mut malformed = raw_authenticated_consumer_connection(&pki, address, &client_spiffe).await;
    malformed
        .write_all(&[0, 0, 0, 1, b'{'])
        .await
        .expect("write malformed consumer frame");
    let mut response = [0_u8; 1];
    let malformed_result =
        tokio::time::timeout(Duration::from_secs(1), malformed.read(&mut response))
            .await
            .expect("malformed frame connection closes promptly");
    assert!(matches!(malformed_result, Err(_) | Ok(0)));

    let mut oversized = raw_authenticated_consumer_connection(&pki, address, &client_spiffe).await;
    oversized
        .write_all(&((16 * 1024 * 1024 + 1) as u32).to_be_bytes())
        .await
        .expect("write oversized consumer frame prefix");
    let oversized_result =
        tokio::time::timeout(Duration::from_secs(1), oversized.read(&mut response))
            .await
            .expect("oversized frame connection closes promptly");
    assert!(matches!(oversized_result, Err(_) | Ok(0)));
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn durable_consumer_request_ids_deduplicate_lease_races_and_fence_stale_owners() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let client_spiffe = spiffe("lease-client");
    let (_snapshots, store, scope, authorizer) =
        admitted_store_and_authorizer([client_spiffe.clone()]).await;
    let service = Arc::new(store.consumer_service());
    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start durable consumer listener");
    let client = consumer_client(&pki, address, &server_spiffe, &client_spiffe, scope);
    let first_request = SessionConsumerRequest::new(
        scope,
        SessionConsumerRequestId::from_bytes([1; 16]),
        SessionConsumerOperation::AcquireLease {
            key: test_key(),
            owner: OwnerId::new("first-owner").expect("first owner"),
            ttl: Duration::from_secs(30),
        },
    );
    let second_request = SessionConsumerRequest::new(
        scope,
        SessionConsumerRequestId::from_bytes([2; 16]),
        SessionConsumerOperation::AcquireLease {
            key: test_key(),
            owner: OwnerId::new("second-owner").expect("second owner"),
            ttl: Duration::from_secs(30),
        },
    );
    let (first, second) = tokio::join!(
        client.execute(first_request.clone()),
        client.execute(second_request.clone())
    );
    let first = first.expect("first lease response");
    let second = second.expect("second lease response");
    assert_eq!(
        [first.clone(), second.clone()]
            .iter()
            .filter(|response| matches!(response, SessionConsumerResponse::AcquireLease(Ok(_))))
            .count(),
        1,
        "only one concurrent stateless consumer request may acquire the lease"
    );
    assert_eq!(
        [first.clone(), second.clone()]
            .iter()
            .filter(|response| {
                matches!(
                    response,
                    SessionConsumerResponse::AcquireLease(Err(
                        SessionConsumerLeaseError::AlreadyHeld
                    ))
                )
            })
            .count(),
        1
    );

    let (winner_request, winner_response) =
        if matches!(first, SessionConsumerResponse::AcquireLease(Ok(_))) {
            (first_request, first)
        } else {
            (second_request, second)
        };
    assert_eq!(
        client
            .execute(winner_request.clone())
            .await
            .expect("exact durable request retry"),
        winner_response,
        "a retained consumer request ID must replay only its prior durable result"
    );
    let lease = match winner_response {
        SessionConsumerResponse::AcquireLease(Ok(lease)) => lease,
        _ => unreachable!("winner response is an acquired lease"),
    };
    let conflicting_reuse = SessionConsumerRequest::new(
        scope,
        winner_request.request_id(),
        SessionConsumerOperation::AcquireLease {
            key: test_key(),
            owner: OwnerId::new("conflicting-owner").expect("conflicting owner"),
            ttl: Duration::from_secs(30),
        },
    );
    assert!(matches!(
        client.execute(conflicting_reuse).await,
        Ok(SessionConsumerResponse::AcquireLease(Err(
            SessionConsumerLeaseError::RequestConflict
        )))
    ));

    assert!(matches!(
        client
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([3; 16]),
                SessionConsumerOperation::ReleaseLease {
                    lease: lease.clone()
                },
            ))
            .await,
        Ok(SessionConsumerResponse::ReleaseLease(Ok(())))
    ));
    assert!(matches!(
        client
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([4; 16]),
                SessionConsumerOperation::AcquireLease {
                    key: test_key(),
                    owner: OwnerId::new("successor-owner").expect("successor owner"),
                    ttl: Duration::from_secs(30),
                },
            ))
            .await,
        Ok(SessionConsumerResponse::AcquireLease(Ok(_)))
    ));
    assert!(matches!(
        client
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([5; 16]),
                SessionConsumerOperation::RenewLease {
                    lease,
                    ttl: Duration::from_secs(30),
                },
            ))
            .await,
        Ok(SessionConsumerResponse::RenewLease(Err(
            SessionConsumerLeaseError::StaleFence
        )))
    ));
    handle.abort_and_wait().await;
}
