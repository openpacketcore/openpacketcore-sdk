//! Boundary contracts for the bounded persistent consumer transport.
//!
//! These tests use only the public typed consumer boundary.  The small
//! in-process service records dispatch after the authenticated server has
//! checked the fixed scope and identity; it does not expose a backend,
//! consensus RPC, or replication operation to the client.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{self, BoxStream, StreamExt};
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{
    ConnectionLifecyclePolicy, PersistentSessionConsumerClient, PersistentSessionConsumerConfig,
    PersistentSessionConsumerExecuteError, RemoteAddrResolver, SessionConsumerAuthorizer,
    SessionQuorumConsumerServer, StatelessSessionConsumerClient,
};
use opc_session_store::{
    BackendCapabilities, ConsensusSessionStore, OwnerId, QuorumReplicaDescriptor,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    SessionConsensusIdentity, SessionConsumerChange, SessionConsumerIdentity,
    SessionConsumerLeaseError, SessionConsumerOperation, SessionConsumerRejection,
    SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerResponse,
    SessionConsumerScope, SessionConsumerStoreError, SessionKey, SessionKeyType,
    SessionQuorumConsumer, SqliteSessionBackend, ValidatedQuorumTopology,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use tokio::sync::watch;

struct TestPki {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().expect("test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "persistent boundary test CA");
        Self {
            ca: rcgen::CertifiedIssuer::self_signed(parameters, key).expect("test CA certificate"),
        }
    }

    fn identity_state(&self, spiffe_id: &str) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
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
            trust_domain: opc_identity::TrustDomain::new("test.example").expect("trust domain"),
            certificates: parse_certs_pem(&self.ca.pem()).expect("test trust bundle"),
        });
        build_identity_state(certificates, private_key, bundles).expect("test identity state")
    }

    fn client_config(&self, spiffe_id: &str) -> AuthenticatedClientConfig {
        let (_source, receiver) = watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("test client TLS config")
    }

    fn rotating_client_config(
        &self,
        spiffe_id: &str,
    ) -> (
        AuthenticatedClientConfig,
        watch::Sender<Option<opc_identity::IdentityState>>,
    ) {
        let (source, receiver) = watch::channel(Some(self.identity_state(spiffe_id)));
        let config = TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("rotating client TLS config");
        (config, source)
    }

    fn server_config(&self, spiffe_id: &str) -> AuthenticatedServerConfig {
        let (_source, receiver) = watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("test server TLS config")
    }
}

#[derive(Default)]
struct RecordingConsumer {
    calls: AtomicUsize,
    committed: AtomicUsize,
    block_after_commit: AtomicBool,
    requests: Mutex<Vec<SessionConsumerRequest>>,
}

impl RecordingConsumer {
    async fn wait_for_calls(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while self.calls.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("consumer dispatch reaches the bounded fixture deadline");
    }

    fn requests(&self) -> Vec<SessionConsumerRequest> {
        self.requests
            .lock()
            .expect("request recording lock")
            .clone()
    }
}

#[async_trait]
impl SessionQuorumConsumer for RecordingConsumer {
    async fn execute(
        &self,
        _identity: &SessionConsumerIdentity,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("request recording lock")
            .push(request.clone());
        if matches!(
            request.operation(),
            SessionConsumerOperation::AcquireLease { .. }
        ) {
            // This is the fixture's durable-effect boundary.  It is recorded
            // before intentionally withholding a response below.
            self.committed.fetch_add(1, Ordering::SeqCst);
        }
        if self.block_after_commit.load(Ordering::SeqCst) {
            std::future::pending().await
        }
        match request.operation() {
            SessionConsumerOperation::AcquireLease { .. } => SessionConsumerResponse::AcquireLease(
                Err(SessionConsumerLeaseError::OutcomeUnavailable),
            ),
            _ => SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled()),
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
        Ok(stream::pending().boxed())
    }
}

fn spiffe(name: &str) -> String {
    format!("spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/{name}")
}

async fn authorizer_and_scope(
    client_spiffe: &str,
) -> (SessionConsumerAuthorizer, SessionConsumerScope) {
    let snapshots = tempfile::tempdir().expect("snapshot directory");
    let replica_id = ReplicaId::new("persistent-boundary-test").expect("replica ID");
    let descriptor = QuorumReplicaDescriptor::new(
        replica_id.clone(),
        ReplicaEndpoint::new("persistent-boundary.test.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(spiffe("member")).expect("member TLS identity"),
        ReplicaFailureDomain::new("persistent-boundary-zone").expect("failure domain"),
        ReplicaBackingIdentity::new("persistent-boundary-disk").expect("backing identity"),
    );
    let cluster = ConsensusClusterId::new("persistent-boundary-test").expect("cluster ID");
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
        .expect("consumer authorization manifest");
    let scope = manifest.scope();
    let authorizer = SessionConsumerAuthorizer::try_new(
        manifest,
        [SpiffeId::new(client_spiffe).expect("client SPIFFE")],
    )
    .expect("consumer authorizer");
    (authorizer, scope)
}

fn config(request_connections: usize) -> PersistentSessionConsumerConfig {
    PersistentSessionConsumerConfig::try_new(
        request_connections,
        4,
        Duration::from_millis(250),
        1,
        Duration::from_millis(1_500),
        2,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .expect("bounded persistent config")
}

fn persistent_client(
    resolver: RemoteAddrResolver,
    server_name: rustls_pki_types::ServerName<'static>,
    server_spiffe: &str,
    scope: SessionConsumerScope,
    tls: AuthenticatedClientConfig,
    config: PersistentSessionConsumerConfig,
) -> PersistentSessionConsumerClient {
    PersistentSessionConsumerClient::try_from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            server_name,
            SpiffeId::new(server_spiffe).expect("server SPIFFE"),
            scope,
            tls,
        )
        .with_operation_timeout(Duration::from_secs(2)),
        config,
    )
    .expect("persistent client")
}

fn lease_request(
    scope: SessionConsumerScope,
    request_id: SessionConsumerRequestId,
) -> SessionConsumerRequest {
    SessionConsumerRequest::new(
        scope,
        request_id,
        SessionConsumerOperation::AcquireLease {
            key: SessionKey {
                tenant: TenantId::new("persistent-boundary").expect("tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"opaque-persistent-boundary")
                    .try_into()
                    .expect("stable ID"),
            },
            owner: OwnerId::new("persistent-boundary-owner").expect("owner"),
            ttl: Duration::from_secs(30),
        },
    )
}

#[tokio::test]
async fn reestablished_lanes_reresolve_exact_endpoint_without_resolving_warm_calls() {
    const LANES: usize = 2;
    let pki = TestPki::new();
    let server_spiffe = spiffe("resolver-server");
    let client_spiffe = spiffe("resolver-client");
    let (first_authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let first_service = Arc::new(RecordingConsumer::default());
    let (first_handle, first_address) = SessionQuorumConsumerServer::new(
        first_service.clone(),
        pki.server_config(&server_spiffe),
        first_authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start first listener");

    let resolved = Arc::new(RwLock::new(first_address));
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolved = Arc::clone(&resolved);
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolved = Arc::clone(&resolved);
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Ok(*resolved.read().expect("resolver address lock"))
            })
        })
    };
    let client = persistent_client(
        resolver,
        rustls_pki_types::ServerName::IpAddress(first_address.ip().into()),
        &server_spiffe,
        scope,
        pki.client_config(&client_spiffe),
        config(LANES),
    );
    assert_eq!(client.scope(), scope);
    assert_eq!(
        client
            .prewarm()
            .await
            .expect("first prewarm")
            .ready_request_connections,
        LANES
    );
    for _ in 0..3 {
        assert_eq!(
            client.capabilities().await,
            Ok(BackendCapabilities::all_enabled())
        );
    }
    assert_eq!(resolutions.load(Ordering::SeqCst), LANES);

    first_handle.abort_and_wait().await;
    let (second_authorizer, second_scope) = authorizer_and_scope(&client_spiffe).await;
    assert_eq!(second_scope, scope, "the replacement keeps the exact scope");
    let second_service = Arc::new(RecordingConsumer::default());
    let (second_handle, second_address) = SessionQuorumConsumerServer::new(
        second_service.clone(),
        pki.server_config(&server_spiffe),
        second_authorizer,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("replacement listen address"),
    )
    .await
    .expect("start replacement listener");
    *resolved.write().expect("resolver address lock") = second_address;
    client
        .request_reauthentication()
        .expect("drain stale lanes");
    assert_eq!(
        client
            .prewarm()
            .await
            .expect("replacement prewarm")
            .ready_request_connections,
        LANES
    );
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        LANES * 2,
        "each new physical lane resolves; warm logical calls do not"
    );
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    assert_eq!(second_service.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        client.diagnostics().await.setup_successes,
        (LANES * 2) as u64
    );

    client.shutdown().await;
    second_handle.abort_and_wait().await;
}

#[tokio::test]
async fn prewrite_retry_retains_one_request_and_postwrite_disconnect_is_unknown_once() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("mutation-server");
    let client_spiffe = spiffe("mutation-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(RecordingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let attempts = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let attempts = Arc::clone(&attempts);
        Arc::new(move || {
            let attempts = Arc::clone(&attempts);
            Box::pin(async move {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "test resolution failure",
                    ))
                } else {
                    Ok(address)
                }
            })
        })
    };
    let client = persistent_client(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        scope,
        pki.client_config(&client_spiffe),
        config(1),
    );

    let first_id = SessionConsumerRequestId::new();
    let first_request = lease_request(scope, first_id);
    assert!(matches!(
        client.execute(&first_request).await,
        Ok(SessionConsumerResponse::AcquireLease(Err(
            SessionConsumerLeaseError::OutcomeUnavailable
        )))
    ));
    service.wait_for_calls(1).await;
    let diagnostics = client.diagnostics().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(diagnostics.setup_attempts, 2);
    assert_eq!(diagnostics.resolve_attempts, 2);
    assert_eq!(diagnostics.resolve_failures, 1);
    assert_eq!(diagnostics.tcp_attempts, 1);
    assert!(
        service.requests() == vec![first_request],
        "the safe pre-write retry must dispatch one byte-identical request"
    );

    service.block_after_commit.store(true, Ordering::SeqCst);
    let postwrite_id = SessionConsumerRequestId::new();
    let postwrite = lease_request(scope, postwrite_id);
    let pending = {
        let client = client.clone();
        let retained_request = postwrite.clone();
        tokio::spawn(async move { client.execute(&retained_request).await })
    };
    service.wait_for_calls(2).await;
    assert_eq!(service.committed.load(Ordering::SeqCst), 2);
    handle.abort_and_wait().await;
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(500), pending)
            .await
            .expect("connection abort wakes caller")
            .expect("caller task"),
        Err(PersistentSessionConsumerExecuteError::OutcomeUnknown {
            request_id: postwrite_id,
        })
    );
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        2,
        "a post-write unknown outcome is never automatically replayed"
    );
    let recorded = service.requests();
    assert!(
        recorded.get(1) == Some(&postwrite),
        "the uncertain call must retain its exact request identity and body"
    );
    assert_eq!(client.diagnostics().await.outcome_unknown, 1);
    client.shutdown().await;
}

#[tokio::test]
async fn expired_prewarmed_idle_lane_is_replaced_before_the_next_logical_call() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("idle-server");
    let client_spiffe = spiffe("idle-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(RecordingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_idle_timeout(Duration::from_millis(20))
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start short-idle listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Ok(address)
            })
        })
    };
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_idle_timeout(Duration::from_millis(20))
    .with_operation_timeout(Duration::from_secs(2));
    let client = PersistentSessionConsumerClient::try_from_stateless(stateless, config(1))
        .expect("persistent client");
    client.prewarm().await.expect("prewarm one lane");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    assert_eq!(diagnostics.setup_successes, 2);
    assert_eq!(diagnostics.reused, 0);
    assert!(diagnostics.reconnects >= 1);
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn reauthentication_and_svid_rotation_drain_idle_lanes_then_prewarm_within_capacity() {
    const LANES: usize = 2;
    let pki = TestPki::new();
    let server_spiffe = spiffe("rotation-server");
    let client_spiffe = spiffe("rotation-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(RecordingConsumer::default());
    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .with_connection_lifecycle(
                ConnectionLifecyclePolicy::try_new(
                    Duration::from_secs(30),
                    Duration::from_secs(1),
                    Duration::from_millis(1),
                    Duration::from_millis(1),
                    Duration::ZERO,
                )
                .expect("deterministic lifecycle policy"),
            )
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let (tls, material_source) = pki.rotating_client_config(&client_spiffe);
    let client = persistent_client(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        scope,
        tls,
        config(LANES),
    );

    assert_eq!(
        client
            .prewarm()
            .await
            .expect("first prewarm")
            .ready_request_connections,
        LANES
    );
    client
        .request_reauthentication()
        .expect("explicit reauthentication");
    assert_eq!(client.readiness().await.ready_request_connections, 0);
    assert_eq!(
        client
            .prewarm()
            .await
            .expect("reauth prewarm")
            .ready_request_connections,
        LANES
    );

    let previous_epoch = client.credential_health().epoch();
    material_source
        .send(Some(pki.identity_state(&client_spiffe)))
        .expect("publish rotated SVID material");
    tokio::time::timeout(Duration::from_millis(500), async {
        while client.credential_health().epoch() <= previous_epoch {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("material controller publishes the new SVID epoch");
    assert_eq!(client.readiness().await.ready_request_connections, 0);
    let readiness = client.prewarm().await.expect("rotation prewarm");
    assert!(readiness.ready);
    assert_eq!(readiness.configured_request_connections, LANES);
    assert_eq!(readiness.ready_request_connections, LANES);
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, (LANES * 3) as u64);
    assert!(diagnostics.idle <= LANES as u64);

    client.shutdown().await;
    handle.abort_and_wait().await;
}
