//! Contract tests for the production stateless quorum-consumer boundary.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_key::{
    KeyHandle, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, Zeroizing,
    AES_256_GCM_SIV_KEY_LEN,
};
use opc_session_net::{
    conservative_payload_budget, PersistentSessionConsumerClient, PersistentSessionConsumerConfig,
    RemoteAddrResolver, SessionConsumerAuthorizer, SessionConsumerClientError,
    SessionConsumerFencedTransitionBackend, SessionConsumerLeaseMutationError,
    SessionConsumerMutationError, SessionQuorumConsumerServer, StatelessSessionConsumerClient,
    MAX_NEGOTIATED_FRAME_SIZE, SESSION_QUORUM_CONSUMER_ALPN,
    SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
};
use opc_session_store::{
    AtomicFencedTransitionCapability, BackendCapabilities, ConsensusSessionStore,
    EncryptedSessionPayload, EncryptingSessionBackend, FenceToken, FencedTransitionExecuteError,
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionStatus, Generation, OwnerId,
    PreparedFencedTransitionJournal, PreparedFencedTransitionJournalKey,
    PreparedFencedTransitionLookup, QuorumReplicaDescriptor, RecordExpiryPreflight,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    RestoreScanRequest, SessionBackend, SessionConsensusIdentity, SessionConsumerChange,
    SessionConsumerIdentity, SessionConsumerLeaseError, SessionConsumerOperation,
    SessionConsumerOutcomeUnknown, SessionConsumerRejection, SessionConsumerRequest,
    SessionConsumerRequestId, SessionConsumerResponse, SessionConsumerScope,
    SessionConsumerStoreError, SessionKey, SessionKeyType, SessionLeaseManager, SessionOp,
    SessionPayloadEncoding, SessionQuorumConsumer, SqliteSessionBackend, StateClass, StateType,
    StoreError, StoredSessionRecord, ValidatedQuorumTopology,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn transported_capabilities() -> BackendCapabilities {
    BackendCapabilities {
        max_value_bytes: conservative_payload_budget(MAX_NEGOTIATED_FRAME_SIZE),
        ..BackendCapabilities::all_enabled()
    }
}

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
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(request.operation(), SessionConsumerOperation::Watch { .. }) {
            SessionConsumerResponse::WatchOpened
        } else {
            std::future::pending().await
        }
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
        Ok(Box::pin(futures_util::stream::pending()))
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

struct CountingKeyProvider {
    inner: MemoryKeyProvider,
    calls: AtomicUsize,
}

impl CountingKeyProvider {
    fn with_active_session_key() -> Arc<Self> {
        let provider = Arc::new(Self {
            inner: MemoryKeyProvider::new(),
            calls: AtomicUsize::new(0),
        });
        provider
            .inner
            .insert_active_key(
                KeyId::new("consumer-v2-test-key").expect("test key ID"),
                KeyPurpose::Session,
                TenantId::new("consumer-test").expect("test tenant"),
                Zeroizing::new([0x61; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("install test key");
        provider
    }

    fn empty() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryKeyProvider::new(),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeyProvider for CountingKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, opc_key::KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, opc_key::KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyId, opc_key::KeyError> {
        self.inner.rotate_key(purpose, tenant).await
    }
}

/// For one successful physical transition, retain only the protected request
/// shape and deliberately replace the confirmed response with ambiguity.
struct OneShotOutcomeUnknownConsumer {
    inner: Arc<dyn SessionQuorumConsumer>,
    armed: AtomicBool,
    physical_payload_encoding: Mutex<Option<SessionPayloadEncoding>>,
    physical_payload_is_logical: AtomicBool,
}

impl OneShotOutcomeUnknownConsumer {
    fn new(inner: Arc<dyn SessionQuorumConsumer>) -> Self {
        Self {
            inner,
            armed: AtomicBool::new(true),
            physical_payload_encoding: Mutex::new(None),
            physical_payload_is_logical: AtomicBool::new(false),
        }
    }

    fn physical_payload_encoding(&self) -> Option<SessionPayloadEncoding> {
        *self
            .physical_payload_encoding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn physical_payload_is_logical(&self) -> bool {
        self.physical_payload_is_logical.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SessionQuorumConsumer for OneShotOutcomeUnknownConsumer {
    async fn execute(
        &self,
        identity: &SessionConsumerIdentity,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        let physical_evidence = match request.operation() {
            SessionConsumerOperation::FencedTransition { request } => {
                request.mutation().record().map(|record| {
                    (
                        record.payload.encoding(),
                        record.payload.as_bytes() == [0xa1],
                    )
                })
            }
            _ => None,
        };
        let request_id = request.request_id();
        let response = self.inner.execute(identity, request).await;
        if let Some((encoding, is_logical)) = physical_evidence {
            *self
                .physical_payload_encoding
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(encoding);
            self.physical_payload_is_logical
                .store(is_logical, Ordering::SeqCst);
            if matches!(response, SessionConsumerResponse::FencedTransition(Ok(_)))
                && self
                    .armed
                    .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                return SessionConsumerResponse::OutcomeUnknown(
                    SessionConsumerOutcomeUnknown::Mutation { request_id },
                );
            }
        }
        response
    }

    async fn watch(
        &self,
        identity: &SessionConsumerIdentity,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        self.inner.watch(identity, scope, start_sequence).await
    }
}

#[derive(Clone, Copy)]
enum FencedConsumerClientKind {
    Stateless,
    Persistent,
}

struct FencedConsumerClientHandle {
    backend: Arc<dyn SessionBackend>,
    persistent: Option<PersistentSessionConsumerClient>,
}

impl FencedConsumerClientHandle {
    async fn shutdown(self) {
        if let Some(client) = self.persistent {
            let _ = client.shutdown().await;
        }
    }
}

fn fenced_consumer_backend(
    kind: FencedConsumerClientKind,
    pki: &TestPki,
    address: SocketAddr,
    server_spiffe: &str,
    client_spiffe: &str,
    scope: SessionConsumerScope,
) -> FencedConsumerClientHandle {
    let stateless = consumer_client(pki, address, server_spiffe, client_spiffe, scope);
    match kind {
        FencedConsumerClientKind::Stateless => FencedConsumerClientHandle {
            backend: Arc::new(
                SessionConsumerFencedTransitionBackend::stateless(stateless)
                    .expect("stateless fenced-transition adapter"),
            ),
            persistent: None,
        },
        FencedConsumerClientKind::Persistent => {
            let persistent = PersistentSessionConsumerClient::try_from_stateless(
                stateless,
                PersistentSessionConsumerConfig::default(),
            )
            .expect("persistent fenced-transition client");
            FencedConsumerClientHandle {
                backend: Arc::new(
                    SessionConsumerFencedTransitionBackend::persistent(persistent.clone())
                        .expect("persistent fenced-transition adapter"),
                ),
                persistent: Some(persistent),
            }
        }
    }
}

fn fenced_create_request(payload: u8) -> FencedTransitionRequest {
    let key = test_key();
    let owner = OwnerId::new("x").expect("test owner");
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        Duration::from_secs(30),
    )
    .expect("test acquire lease");
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x71; 16]),
        lease.clone(),
        FencedTransitionMutation::create(StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner,
            fence: lease.committed_fence().expect("committed fence"),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("x"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([payload]),
        }),
    )
    .expect("test create request")
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

async fn counting_tcp_proxy(
    upstream: SocketAddr,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let address = listener.local_addr().expect("counting proxy address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let task = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = listener.accept().await.expect("accept consumer TCP");
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(mut upstream_stream) = tokio::net::TcpStream::connect(upstream).await
                    else {
                        return;
                    };
                    let _ =
                        tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream).await;
                });
            }
        })
    };
    (address, accepted, task)
}

async fn wait_for_dispatches(service: &HangingConsumer, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while service.calls.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded fixture observes authenticated dispatches");
}

#[test]
fn production_default_features_expose_a_dedicated_stateless_consumer_boundary() {
    let _ = std::any::TypeId::of::<StatelessSessionConsumerClient>();
    let _ = std::any::TypeId::of::<SessionQuorumConsumerServer>();
    let _ = std::any::TypeId::of::<SessionConsumerAuthorizer>();
    assert_ne!(SESSION_QUORUM_CONSUMER_ALPN, b"opc-session-consensus/2");
    assert_ne!(SESSION_QUORUM_CONSUMER_ALPN, b"opc-session-net/5");
}

#[test]
fn stateless_lease_response_payloads_remain_source_compatible_lease_guards() {
    fn assert_lease_payload(
        payload: Result<opc_session_store::LeaseGuard, SessionConsumerLeaseError>,
    ) {
        assert!(payload.is_err());
    }

    match SessionConsumerResponse::AcquireLease(Err(SessionConsumerLeaseError::Unavailable)) {
        SessionConsumerResponse::AcquireLease(payload) => assert_lease_payload(payload),
        _ => unreachable!("constructed acquire response"),
    }
    match SessionConsumerResponse::RenewLease(Err(SessionConsumerLeaseError::Unavailable)) {
        SessionConsumerResponse::RenewLease(payload) => assert_lease_payload(payload),
        _ => unreachable!("constructed renew response"),
    }
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
        transported_capabilities()
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
async fn stateless_serial_calls_authenticate_fresh_and_accumulate_setup_delay() {
    const CALLS: usize = 4;
    const SETUP_DELAY: Duration = Duration::from_millis(40);

    let pki = TestPki::new();
    let server_spiffe = spiffe("red-server");
    let client_spiffe = spiffe("red-client");
    let service = Arc::new(CountingConsumer::default());
    let (authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let (handle, upstream_address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");

    // Delay every end-to-end TLS connection before forwarding any handshake
    // byte. A completed capability response therefore proves that the counted
    // proxy connection completed the authenticated consumer setup.
    let proxy_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind deterministic setup-delay proxy");
    let proxy_address = proxy_listener.local_addr().expect("proxy address");
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let proxy_task = {
        let accepted_connections = Arc::clone(&accepted_connections);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = proxy_listener.accept().await.expect("accept client");
                accepted_connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    tokio::time::sleep(SETUP_DELAY).await;
                    let Ok(mut upstream) = tokio::net::TcpStream::connect(upstream_address).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                });
            }
        })
    };

    let client = consumer_client(&pki, proxy_address, &server_spiffe, &client_spiffe, scope);
    let started_at = tokio::time::Instant::now();
    for _ in 0..CALLS {
        assert_eq!(client.capabilities().await, Ok(transported_capabilities()));
    }
    let elapsed = started_at.elapsed();

    assert!(
        elapsed >= SETUP_DELAY * u32::try_from(CALLS).expect("small call count"),
        "serial cold calls must accumulate the deterministic setup delay"
    );
    assert_eq!(
        accepted_connections.load(Ordering::SeqCst),
        CALLS,
        "the stateless client deliberately authenticates a fresh transport per call"
    );

    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn cloned_stateless_request_connections_fail_fast_at_the_shared_physical_cap() {
    const PHYSICAL_CAP: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("physical-request-server");
    let client_spiffe = spiffe("physical-request-client");
    let (authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let service = Arc::new(HangingConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start physical-cap listener");
    let (proxy, accepted, proxy_task) = counting_tcp_proxy(upstream).await;
    let client = consumer_client(&pki, proxy, &server_spiffe, &client_spiffe, scope);

    let mut held = (0..PHYSICAL_CAP)
        .map(|_| {
            let clone = client.clone();
            tokio::spawn(async move { clone.capabilities().await })
        })
        .collect::<Vec<_>>();
    wait_for_dispatches(&service, PHYSICAL_CAP).await;
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::Overloaded),
        "the seventeenth clone is rejected before resolve, TCP, or dispatch"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(service.calls.load(Ordering::SeqCst), PHYSICAL_CAP);

    let released = held.pop().expect("one held caller");
    released.abort();
    assert!(
        released.await.is_err(),
        "cancelling a held connection completes"
    );
    let replacement = {
        let clone = client.clone();
        tokio::spawn(async move { clone.capabilities().await })
    };
    wait_for_dispatches(&service, PHYSICAL_CAP + 1).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        PHYSICAL_CAP + 1,
        "releasing one cap slot admits one fresh authenticated TCP connection"
    );
    replacement.abort();
    let _ = replacement.await;
    for caller in held {
        caller.abort();
        let _ = caller.await;
    }
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn cloned_stateless_watch_connections_have_an_isolated_shared_physical_cap() {
    const PHYSICAL_CAP: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("physical-watch-server");
    let client_spiffe = spiffe("physical-watch-client");
    let (authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let service = Arc::new(HangingConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start physical-watch listener");
    let (proxy, accepted, proxy_task) = counting_tcp_proxy(upstream).await;
    let client = consumer_client(&pki, proxy, &server_spiffe, &client_spiffe, scope);

    let mut watches = Vec::with_capacity(PHYSICAL_CAP);
    for _ in 0..PHYSICAL_CAP {
        watches.push(client.watch(0).await.expect("watch reaches exact cap"));
    }
    wait_for_dispatches(&service, PHYSICAL_CAP).await;
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert!(matches!(
        client.watch(0).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(service.calls.load(Ordering::SeqCst), PHYSICAL_CAP);

    drop(watches.pop().expect("one held watch"));
    let replacement = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(watch) = client.watch(0).await {
                break watch;
            }
            // Dropping the caller's stream closes its bounded queue. The
            // physical reader owns the permit and releases it on its next
            // poll, so wait for that observable release without assuming a
            // scheduler turn between drop and fail-fast admission.
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("released watch capacity becomes observable within the fixed bound");
    wait_for_dispatches(&service, PHYSICAL_CAP + 1).await;
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP + 1);
    drop(replacement);
    drop(watches);
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn independent_stateless_constructors_do_not_share_physical_request_budgets() {
    const PHYSICAL_CAP: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("independent-physical-server");
    let client_spiffe = spiffe("independent-physical-client");
    let (authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let service = Arc::new(HangingConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start independent-budget listener");
    let (proxy, accepted, proxy_task) = counting_tcp_proxy(upstream).await;
    let first = consumer_client(&pki, proxy, &server_spiffe, &client_spiffe, scope);
    let second = consumer_client(&pki, proxy, &server_spiffe, &client_spiffe, scope);

    let mut held = Vec::with_capacity(PHYSICAL_CAP * 2);
    for _ in 0..PHYSICAL_CAP {
        for client in [&first, &second] {
            let clone = client.clone();
            held.push(tokio::spawn(async move { clone.capabilities().await }));
            wait_for_dispatches(&service, held.len()).await;
        }
    }
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP * 2);
    assert_eq!(
        first.capabilities().await,
        Err(SessionConsumerClientError::Overloaded)
    );
    assert_eq!(
        second.capabilities().await,
        Err(SessionConsumerClientError::Overloaded)
    );
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP * 2);

    for caller in held.drain(..) {
        caller.abort();
        let _ = caller.await;
    }
    proxy_task.abort();
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

    assert_eq!(client.capabilities().await, Ok(transported_capabilities()));
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
        Ok(transported_capabilities()),
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
        Ok(transported_capabilities()),
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
async fn deserialized_structurally_invalid_lease_guards_fail_before_resolve_or_effect() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("invalid-guard-server");
    let client_spiffe = spiffe("invalid-guard-client");
    let (_authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("invalid guard must never resolve"))
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
    let mut encoded = serde_json::to_value(test_lease().await).expect("encode valid lease guard");
    encoded["credential_id"] = serde_json::json!(0);
    let forged: opc_session_store::LeaseGuard =
        serde_json::from_value(encoded).expect("public DTO accepts a structurally forged guard");

    assert!(matches!(
        client
            .delete_fenced_with_id(
                SessionConsumerRequestId::from_bytes([0x91; 16]),
                forged.clone()
            )
            .await,
        Err(SessionConsumerMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Protocol
        })
    ));
    assert_eq!(
        client
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([0x92; 16]),
                SessionConsumerOperation::Batch {
                    ops: vec![opc_session_store::SessionOp::DeleteFenced { lease: forged }]
                },
            ))
            .await,
        Err(SessionConsumerClientError::Protocol)
    );
    let descriptor = RecordExpiryPreflight::from_record(&StoredSessionRecord {
        key: test_key(),
        generation: Generation::new(1),
        owner: OwnerId::new("invalid-preflight-owner").expect("preflight owner"),
        fence: FenceToken::new(1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("invalid-preflight"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"opaque-invalid-preflight"),
    });
    for (request_byte, operation) in [
        (
            0x93,
            SessionConsumerOperation::AcquireLease {
                key: test_key(),
                owner: OwnerId::new("invalid-ttl-owner").expect("invalid TTL owner"),
                ttl: opc_session_store::MAX_SESSION_TTL + Duration::from_nanos(1),
            },
        ),
        (
            0x94,
            SessionConsumerOperation::Batch {
                ops: vec![SessionOp::Get { key: test_key() }; 257],
            },
        ),
        (
            0x95,
            SessionConsumerOperation::PreflightRecordExpiry {
                preflights: vec![descriptor; opc_session_store::MAX_RECORD_EXPIRY_PREFLIGHTS + 1],
            },
        ),
        (
            0x96,
            SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest::all(0),
            },
        ),
    ] {
        assert_eq!(
            client
                .execute(SessionConsumerRequest::new(
                    scope,
                    SessionConsumerRequestId::from_bytes([request_byte; 16]),
                    operation,
                ))
                .await,
            Err(SessionConsumerClientError::Protocol)
        );
    }
    assert_eq!(resolutions.load(Ordering::SeqCst), 0);
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
        .all(|result| result == &Ok(transported_capabilities())));
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
    let (authorizer, scope) = authorizer_from_admitted_store(&client_spiffe).await;
    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless consumer listener");

    // This peer completes the same mTLS and ALPN handshake as a real caller,
    // but offers the wrong fixed consumer revision. It must be closed before
    // any application dispatch and without an upgrade oracle.
    let mut wrong_revision =
        raw_authenticated_consumer_connection(&pki, address, &client_spiffe).await;
    let wrong_hello = serde_json::to_vec(&serde_json::json!({
        "kind": "hello",
        "body": {
            "transport_revision": SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION.wrapping_add(1),
            "scope": scope,
            "response_frame_size": opc_session_net::MAX_NEGOTIATED_FRAME_SIZE,
        },
    }))
    .expect("wrong revision hello encodes");
    wrong_revision
        .write_all(
            &u32::try_from(wrong_hello.len())
                .expect("wrong revision hello fits frame")
                .to_be_bytes(),
        )
        .await
        .expect("write wrong revision prefix");
    wrong_revision
        .write_all(&wrong_hello)
        .await
        .expect("write wrong revision hello");
    wrong_revision
        .flush()
        .await
        .expect("flush wrong revision hello");
    let mut response = [0_u8; 1];
    let wrong_revision_result =
        tokio::time::timeout(Duration::from_secs(1), wrong_revision.read(&mut response))
            .await
            .expect("wrong revision connection closes promptly");
    assert!(matches!(wrong_revision_result, Err(_) | Ok(0)));

    let mut malformed = raw_authenticated_consumer_connection(&pki, address, &client_spiffe).await;
    malformed
        .write_all(&[0, 0, 0, 1, b'{'])
        .await
        .expect("write malformed consumer frame");
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
        SessionConsumerResponse::AcquireLease(Ok(guard)) => guard,
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

#[tokio::test]
async fn stateless_and_persistent_consumers_accept_shorter_and_zero_ttl_renewals() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("renewal-server");
    let client_spiffe = spiffe("renewal-client");
    let (_snapshots, store, scope, authorizer) =
        admitted_store_and_authorizer([client_spiffe.clone()]).await;
    let service = Arc::new(store.consumer_service());
    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start renewal consumer listener");
    let stateless = consumer_client(&pki, address, &server_spiffe, &client_spiffe, scope);

    let original = stateless
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([0x81; 16]),
            test_key(),
            OwnerId::new("renewal-owner").expect("renewal owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire thirty-second lease");
    let shortened = stateless
        .renew_with_id(
            SessionConsumerRequestId::from_bytes([0x82; 16]),
            original.clone(),
            Duration::from_secs(7),
        )
        .await
        .expect("stateless renewal may shorten a live lease");
    assert!(shortened.expires_at() < original.expires_at());

    let persistent = PersistentSessionConsumerClient::from_stateless(stateless)
        .expect("valid persistent configuration");
    let zero = persistent
        .renew_with_id(
            SessionConsumerRequestId::from_bytes([0x83; 16]),
            &shortened,
            Duration::ZERO,
        )
        .await
        .expect("persistent renewal accepts the valid zero TTL boundary");
    assert!(zero.expires_at() <= shortened.expires_at());
    assert_eq!(zero.key(), shortened.key());
    assert_eq!(zero.owner(), shortened.owner());
    assert_eq!(zero.fence(), shortened.fence());

    persistent.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn authenticated_consumer_v2_recovers_journaled_protected_transition_after_tls_ambiguity() {
    for client_kind in [
        FencedConsumerClientKind::Stateless,
        FencedConsumerClientKind::Persistent,
    ] {
        let pki = TestPki::new();
        let server_spiffe = spiffe("v2-server");
        let client_spiffe = spiffe("v2-client");
        let (snapshots, store, scope, authorizer) =
            admitted_store_and_authorizer([client_spiffe.clone()]).await;
        let initial_service = Arc::new(OneShotOutcomeUnknownConsumer::new(Arc::new(
            store.consumer_service(),
        )));
        let initial_service_for_server: Arc<dyn SessionQuorumConsumer> = initial_service.clone();
        let (initial_handle, initial_address) = SessionQuorumConsumerServer::new(
            initial_service_for_server,
            pki.server_config(&server_spiffe),
            authorizer.clone(),
        )
        .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
        .await
        .expect("start initial consumer listener");

        let journal_directory = tempfile::tempdir().expect("journal directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(
                journal_directory.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .expect("private journal directory");
        }
        let journal_path = journal_directory.path().join("prepared.sqlite");
        let journal_key = [0x91; 32];
        let initial_journal = Arc::new(
            PreparedFencedTransitionJournal::open(
                &journal_path,
                PreparedFencedTransitionJournalKey::from_bytes(journal_key),
            )
            .expect("open prepared journal"),
        );
        let initial_client = fenced_consumer_backend(
            client_kind,
            &pki,
            initial_address,
            &server_spiffe,
            &client_spiffe,
            scope,
        );
        let initial_physical = Arc::clone(&initial_client.backend);
        let initial_provider = CountingKeyProvider::with_active_session_key();
        let initial_outer: Arc<dyn SessionBackend> = Arc::new(
            EncryptingSessionBackend::new(
                Arc::clone(&initial_physical),
                Arc::clone(&initial_provider),
                "consumer-v2-protected",
            )
            .with_fenced_transition_journal(Arc::clone(&initial_journal)),
        );

        assert!(matches!(
            initial_outer
                .fenced_transition_capability()
                .await
                .expect("capability"),
            Some(AtomicFencedTransitionCapability::V2)
        ));
        let prepared = initial_outer
            .prepare_fenced_transition(fenced_create_request(0xa1))
            .await
            .expect("prepare protected transition");
        assert_eq!(
            initial_provider.calls(),
            1,
            "preparation uses exactly one provider operation"
        );
        let request_id = prepared.request_id();
        let expected_token = Zeroizing::new(prepared.as_bytes().to_vec());
        assert!(matches!(
            initial_outer.fenced_transition(&prepared).await,
            Err(FencedTransitionExecuteError::OutcomeUnknown { request_id: recovered_id })
                if recovered_id == request_id
        ));
        assert_eq!(
            initial_service
                .physical_payload_encoding()
                .expect("initial service observed physical transition"),
            SessionPayloadEncoding::EnvelopeV1
        );
        assert!(
            !initial_service.physical_payload_is_logical(),
            "the physical consumer request remains sealed"
        );

        drop(initial_outer);
        drop(initial_physical);
        drop(initial_journal);
        initial_client.shutdown().await;
        drop(initial_provider);
        drop(prepared);
        initial_handle.abort_and_wait().await;

        let replacement_service = Arc::new(store.consumer_service());
        let (replacement_handle, replacement_address) = SessionQuorumConsumerServer::new(
            replacement_service,
            pki.server_config(&server_spiffe),
            authorizer,
        )
        .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
        .await
        .expect("start replacement consumer listener");
        let replacement_journal = Arc::new(
            PreparedFencedTransitionJournal::open(
                &journal_path,
                PreparedFencedTransitionJournalKey::from_bytes(journal_key),
            )
            .expect("reopen prepared journal"),
        );
        let replacement_client = fenced_consumer_backend(
            client_kind,
            &pki,
            replacement_address,
            &server_spiffe,
            &client_spiffe,
            scope,
        );
        let replacement_physical = Arc::clone(&replacement_client.backend);
        let replacement_provider = CountingKeyProvider::empty();
        let replacement_outer: Arc<dyn SessionBackend> = Arc::new(
            EncryptingSessionBackend::new(
                Arc::clone(&replacement_physical),
                Arc::clone(&replacement_provider),
                "consumer-v2-protected",
            )
            .with_fenced_transition_journal(replacement_journal),
        );
        let recovered = match replacement_outer
            .recover_prepared_fenced_transition(request_id)
            .await
            .expect("recover prepared transition")
        {
            PreparedFencedTransitionLookup::Found(prepared) => prepared,
            PreparedFencedTransitionLookup::Absent => panic!("prepared transition was lost"),
            _ => panic!("prepared transition lookup was unsupported"),
        };
        let recovered_is_exact = recovered.as_bytes() == expected_token.as_slice();
        assert!(recovered_is_exact, "recovered token is exact");

        let _outcome = replacement_outer
            .fenced_transition(&recovered)
            .await
            .expect("recover exact transition");
        assert!(matches!(
            replacement_outer
                .fenced_transition_status(&recovered)
                .await
                .expect("recover transition status"),
            FencedTransitionStatus::Recorded(_)
        ));
        assert_eq!(
            replacement_provider.calls(),
            0,
            "recovery never invokes the fresh provider"
        );
        assert!(matches!(
            replacement_outer
                .prepare_fenced_transition(fenced_create_request(0xa2))
                .await,
            Err(StoreError::FencedTransitionRequestConflict)
        ));
        assert_eq!(
            replacement_provider.calls(),
            0,
            "same-ID replacement is rejected before provider work"
        );

        drop(replacement_outer);
        drop(replacement_physical);
        replacement_client.shutdown().await;
        replacement_handle.abort_and_wait().await;
        drop(store);
        drop(snapshots);
    }
}
