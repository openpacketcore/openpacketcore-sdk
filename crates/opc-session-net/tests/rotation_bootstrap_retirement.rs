#![cfg(feature = "legacy-session-net-compat")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_redaction::metrics::METRICS;
use opc_session_net::protocol::{
    read_frame, write_frame, Request, Response, CONTRACT_VERSION, CURRENT_CONTRACT_PROFILE,
    DEFAULT_MAX_FRAME_SIZE, SESSION_NET_ALPN,
};
use opc_session_net::{
    ConnectionLifecyclePolicy, RemoteAddrResolver, RemoteSessionBackend,
    RemoteSessionConsensusPeer, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, SessionConsensusServer, SessionReauthenticationControl,
    SessionReplicationManifest, SessionReplicationServer, SESSION_CONSENSUS_ALPN,
};
use opc_session_store::fake::FakeSessionBackend;
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, SessionBackend, SessionConsensusPeer, SessionConsensusRpcFamily,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
};
use opc_tls::{
    AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder,
    TlsMaterialAvailability, TlsMaterialEpoch,
};

const CLIENT_REPLICA: u16 = 1;
const SERVER_REPLICA: u16 = 2;

struct TestPki {
    ca_certificate: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

impl TestPki {
    fn new() -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("generate test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "bootstrap retirement test CA");
        let ca_certificate = parameters.self_signed(&ca_key).expect("sign test CA");
        Self {
            ca_certificate,
            ca_key,
        }
    }

    fn identity_state(&self, replica: u16) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("replica-{replica}"));
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::Ia5String::try_from(replica_spiffe(replica)).expect("SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("generate leaf key");
        let certificate = parameters
            .signed_by(&key, &self.ca_certificate, &self.ca_key)
            .expect("sign leaf certificate");
        let certificates = parse_certs_pem(&(certificate.pem() + &self.ca_certificate.pem()))
            .expect("parse certificate chain");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("parse private key");
        let mut trust_bundles = opc_identity::TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("test-domain").expect("trust domain"),
            certificates: parse_certs_pem(&self.ca_certificate.pem()).expect("parse CA"),
        });
        build_identity_state(certificates, private_key, trust_bundles)
            .expect("build identity state")
    }

    fn client_source(
        &self,
        replica: u16,
    ) -> (
        tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
        AuthenticatedClientConfig,
    ) {
        let (sender, receiver) = tokio::sync::watch::channel(Some(self.identity_state(replica)));
        let config = TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("authenticated client config");
        (sender, config)
    }

    fn server_source(
        &self,
        replica: u16,
    ) -> (
        tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
        AuthenticatedServerConfig,
    ) {
        let (sender, receiver) = tokio::sync::watch::channel(Some(self.identity_state(replica)));
        let config = TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("authenticated server config");
        (sender, config)
    }
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
        ReplicaEndpoint::new(format!("replica-{replica}.session.invalid"), 7443)
            .expect("replica endpoint"),
        ReplicaTlsIdentity::new(replica_spiffe(replica)).expect("replica TLS identity"),
        ReplicaFailureDomain::new(format!("zone-{replica}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("disk-{replica}")).expect("backing identity"),
    )
}

fn manifest() -> Arc<SessionReplicationManifest> {
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new("bootstrap-retirement").expect("cluster ID"),
            SessionConfigurationGeneration::new("generation-1").expect("generation"),
            SessionConfigurationEpoch::new(1).expect("configuration epoch"),
            vec![descriptor(CLIENT_REPLICA), descriptor(SERVER_REPLICA)],
        )
        .expect("session replication manifest"),
    )
}

fn resolver(address: SocketAddr) -> RemoteAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(address) }))
}

fn lifecycle_policy() -> ConnectionLifecyclePolicy {
    ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(30),
        Duration::from_secs(2),
        Duration::from_millis(2),
        Duration::from_millis(10),
        Duration::ZERO,
    )
    .expect("test lifecycle policy")
}

async fn wait_for_material_epoch(
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
    .expect("material epoch must advance");
}

async fn raw_tls_connection(
    address: SocketAddr,
    authenticated: AuthenticatedClientConfig,
    alpn: &'static [u8],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut config = authenticated.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![alpn.to_vec()];
    let tcp = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect raw TLS socket");
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            tcp,
        )
        .await
        .expect("complete mutual TLS")
}

async fn accept_tls(
    listener: &tokio::net::TcpListener,
    authenticated: &AuthenticatedServerConfig,
    alpn: &'static [u8],
) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
    let (tcp, _) = listener.accept().await.expect("accept TLS socket");
    let handshake = authenticated.begin_handshake().expect("server material");
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![alpn.to_vec()];
    let stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
        .accept(tcp)
        .await
        .expect("accept mutual TLS");
    handshake.admit().expect("admit unchanged test material");
    stream
}

fn generic_hello_ack(hello: &Request) -> Response {
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
        panic!("expected generic Hello")
    };
    Response::HelloAck {
        contract_version: CONTRACT_VERSION,
        server_replica_id: expected_server_replica_id.clone(),
        accepted_client_replica_id: Some(node_id.clone()),
        cluster_id: cluster_id.clone(),
        configuration_id: configuration_id.clone(),
        configuration_epoch: *configuration_epoch,
        handshake_nonce: *handshake_nonce,
        cas_idempotency_epoch: Some(uuid::Uuid::from_u128(1)),
        contract_profile: Some(CURRENT_CONTRACT_PROFILE),
        accepted_response_frame_size: *requested_response_frame_size,
        server_request_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
    }
}

#[derive(Clone, Copy)]
struct MetricSnapshot {
    attempts: u64,
    successes: u64,
    transport_failures: u64,
    authentication_failures: u64,
    timeout_failures: u64,
    protocol_failures: u64,
    backend_failures: u64,
    reconnect_attempts: u64,
    reconnect_failures: u64,
    material_retirements: u64,
    explicit_retirements: u64,
}

impl MetricSnapshot {
    fn capture() -> Self {
        Self {
            attempts: load(&METRICS.session_net_connection_attempts),
            successes: load(&METRICS.session_net_connection_successes),
            transport_failures: load(&METRICS.session_net_connection_failure_transport),
            authentication_failures: load(&METRICS.session_net_connection_failure_authentication),
            timeout_failures: load(&METRICS.session_net_connection_failure_timeout),
            protocol_failures: load(&METRICS.session_net_connection_failure_protocol),
            backend_failures: load(&METRICS.session_net_connection_failure_backend),
            reconnect_attempts: load(&METRICS.session_net_reconnect_attempts),
            reconnect_failures: load(&METRICS.session_net_reconnect_failures),
            material_retirements: load(&METRICS.session_net_lifecycle_retirement_material_epoch),
            explicit_retirements: load(&METRICS.session_net_lifecycle_retirement_explicit),
        }
    }

    fn since(self, before: Self) -> Self {
        Self {
            attempts: self.attempts - before.attempts,
            successes: self.successes - before.successes,
            transport_failures: self.transport_failures - before.transport_failures,
            authentication_failures: self.authentication_failures - before.authentication_failures,
            timeout_failures: self.timeout_failures - before.timeout_failures,
            protocol_failures: self.protocol_failures - before.protocol_failures,
            backend_failures: self.backend_failures - before.backend_failures,
            reconnect_attempts: self.reconnect_attempts - before.reconnect_attempts,
            reconnect_failures: self.reconnect_failures - before.reconnect_failures,
            material_retirements: self.material_retirements - before.material_retirements,
            explicit_retirements: self.explicit_retirements - before.explicit_retirements,
        }
    }

    fn assert_no_failures(self) {
        assert_eq!(
            [
                self.transport_failures,
                self.authentication_failures,
                self.timeout_failures,
                self.protocol_failures,
                self.backend_failures,
                self.reconnect_failures,
            ],
            [0; 6],
            "expected retirement must not be classified as a connection or reconnect failure"
        );
    }
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

async fn wait_for_success_count(expected: u64) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while load(&METRICS.session_net_connection_successes) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("connection outcome metric must publish");
}

async fn generic_client_retries_authenticated_bootstrap_retirement(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
) {
    let (_server_source, server_config) = pki.server_source(SERVER_REPLICA);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind generic retry listener");
    let address = listener.local_addr().expect("generic retry address");
    let server = tokio::spawn(async move {
        let mut application_requests = 0;
        for attempt in 0..2 {
            let mut tls = accept_tls(&listener, &server_config, SESSION_NET_ALPN).await;
            let hello: Request = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read generic Hello");
            if attempt == 0 {
                write_frame(&mut tls, &Response::ConnectionRetiring)
                    .await
                    .expect("write generic bootstrap retirement control");
                if matches!(
                    tokio::time::timeout(
                        Duration::from_millis(100),
                        read_frame::<_, Request>(&mut tls, DEFAULT_MAX_FRAME_SIZE),
                    )
                    .await,
                    Ok(Ok(_))
                ) {
                    application_requests += 1;
                }
                continue;
            }
            write_frame(&mut tls, &generic_hello_ack(&hello))
                .await
                .expect("write fresh generic acknowledgement");
            let request: Request = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read fresh generic request");
            assert!(matches!(request, Request::MaxReplicationSequence));
            application_requests += 1;
            write_frame(&mut tls, &Response::MaxReplicationSequence(Ok(77)))
                .await
                .expect("write fresh generic response");
        }
        application_requests
    });
    let (_client_source, client_config) = pki.client_source(CLIENT_REPLICA);
    let binding = manifest
        .bind_local(replica_id(CLIENT_REPLICA))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let client = RemoteSessionBackend::new_with_resolver(
        binding,
        resolver(address),
        client_config,
        Some(Duration::from_secs(2)),
    )
    .with_connection_lifecycle(lifecycle_policy());
    let before = MetricSnapshot::capture();

    assert_eq!(client.max_replication_sequence().await, Ok(77));
    assert_eq!(server.await.expect("generic retry server"), 1);
    let delta = MetricSnapshot::capture().since(before);
    assert_eq!((delta.attempts, delta.successes), (2, 2));
    assert_eq!((delta.reconnect_attempts, delta.reconnect_failures), (1, 0));
    assert_eq!(
        (delta.material_retirements, delta.explicit_retirements),
        (0, 0)
    );
    delta.assert_no_failures();
}

async fn generic_unsigned_eof_remains_a_failure(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
) {
    let (_server_source, server_config) = pki.server_source(SERVER_REPLICA);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unsigned EOF listener");
    let address = listener.local_addr().expect("unsigned EOF address");
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let mut tls = accept_tls(&listener, &server_config, SESSION_NET_ALPN).await;
            let _: Request = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read unsigned EOF Hello");
            if attempt == 0 {
                // No complete control frame: dropping the first authenticated
                // stream must remain a transport failure and never become
                // safe-retry proof.
                continue;
            }
            // End the retry deterministically with a complete non-retirement
            // protocol violation. The client cannot reach this route until it
            // has classified and retried the first route's EOF.
            write_frame(
                &mut tls,
                &serde_json::json!({"InvalidBootstrapTerminator": true}),
            )
            .await
            .expect("write non-retryable bootstrap terminator");
        }
    });
    let (_client_source, client_config) = pki.client_source(CLIENT_REPLICA);
    let binding = manifest
        .bind_local(replica_id(CLIENT_REPLICA))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let client = RemoteSessionBackend::new_with_resolver(
        binding,
        resolver(address),
        client_config,
        Some(Duration::from_secs(2)),
    )
    .with_connection_lifecycle(lifecycle_policy());
    let before = MetricSnapshot::capture();

    assert!(client.max_replication_sequence().await.is_err());
    server.await.expect("unsigned EOF server");
    let delta = MetricSnapshot::capture().since(before);
    assert_eq!(delta.attempts, 2);
    assert!(delta.transport_failures >= 1);
    assert!(delta.protocol_failures >= 1);
    assert!(delta.reconnect_failures >= 1);
    assert_eq!(delta.successes, 0);
    assert_eq!(
        [
            delta.authentication_failures,
            delta.timeout_failures,
            delta.backend_failures,
        ],
        [0; 3]
    );
}

async fn consensus_client_retries_authenticated_bootstrap_retirement(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
) {
    let (_server_source, server_config) = pki.server_source(SERVER_REPLICA);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind consensus retry listener");
    let address = listener.local_addr().expect("consensus retry address");
    let server = tokio::spawn(async move {
        let mut application_calls = 0;
        for attempt in 0..2 {
            let mut tls = accept_tls(&listener, &server_config, SESSION_CONSENSUS_ALPN).await;
            let hello: serde_json::Value = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read consensus Hello");
            if attempt == 0 {
                write_frame(&mut tls, &serde_json::json!({"Rejected": "Rejected"}))
                    .await
                    .expect("write consensus bootstrap retirement control");
                if matches!(
                    tokio::time::timeout(
                        Duration::from_millis(100),
                        read_frame::<_, serde_json::Value>(&mut tls, DEFAULT_MAX_FRAME_SIZE),
                    )
                    .await,
                    Ok(Ok(_))
                ) {
                    application_calls += 1;
                }
                continue;
            }
            let hello = &hello["Hello"];
            write_frame(
                &mut tls,
                &serde_json::json!({
                    "Accepted": {
                        "transport_revision": hello["transport_revision"].clone(),
                        "contract_profile": hello["contract_profile"].clone(),
                        "identity": hello["identity"].clone(),
                        "server_node_id": hello["expected_server_node_id"].clone(),
                        "accepted_sender_node_id": hello["sender_node_id"].clone(),
                        "handshake_nonce": hello["handshake_nonce"].clone(),
                        "accepted_response_frame_size": hello["requested_response_frame_size"].clone(),
                        "server_request_frame_size": opc_session_net::MAX_NEGOTIATED_FRAME_SIZE as u32,
                    }
                }),
            )
            .await
            .expect("write fresh consensus acknowledgement");
            let call: serde_json::Value = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read fresh consensus call");
            let call = &call["Call"];
            application_calls += 1;
            write_frame(
                &mut tls,
                &serde_json::json!({
                    "Call": {
                        "call_id": call["call_id"].clone(),
                        "response": {"result": {"Ok": call["request"]["payload"].clone()}},
                    }
                }),
            )
            .await
            .expect("write fresh consensus response");
        }
        application_calls
    });
    let (_client_source, client_config) = pki.client_source(CLIENT_REPLICA);
    let binding = manifest
        .bind_local(replica_id(CLIENT_REPLICA))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let request = SessionConsensusWireRequest::try_new(
        binding.consensus_identity(),
        binding.local_consensus_node_id(),
        SessionConsensusRpcFamily::Vote,
        b"consensus-bootstrap-retry".to_vec(),
    )
    .expect("bounded consensus request");
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        binding,
        resolver(address),
        client_config,
        Some(Duration::from_secs(2)),
    )
    .with_connection_lifecycle(lifecycle_policy());
    let before = MetricSnapshot::capture();

    assert_eq!(
        peer.call(request).await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"consensus-bootstrap-retry".to_vec()),
        })
    );
    assert_eq!(server.await.expect("consensus retry server"), 1);
    let delta = MetricSnapshot::capture().since(before);
    assert_eq!((delta.attempts, delta.successes), (2, 2));
    assert_eq!((delta.reconnect_attempts, delta.reconnect_failures), (1, 0));
    assert_eq!(
        (delta.material_retirements, delta.explicit_retirements),
        (0, 0)
    );
    delta.assert_no_failures();
}

async fn consensus_partial_retirement_control_eof_remains_a_failure(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
) {
    let (_server_source, server_config) = pki.server_source(SERVER_REPLICA);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind partial consensus retirement listener");
    let address = listener
        .local_addr()
        .expect("partial consensus retirement address");
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let mut tls = accept_tls(&listener, &server_config, SESSION_CONSENSUS_ALPN).await;
            let _: serde_json::Value = read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read partial-control consensus Hello");
            if attempt == 0 {
                let mut control = Vec::new();
                write_frame(&mut control, &serde_json::json!({"Rejected": "Rejected"}))
                    .await
                    .expect("encode complete consensus retirement control");
                control
                    .pop()
                    .expect("retirement control has a final byte to withhold");
                tokio::io::AsyncWriteExt::write_all(&mut tls, &control)
                    .await
                    .expect("write incomplete consensus retirement control");
                tokio::io::AsyncWriteExt::flush(&mut tls)
                    .await
                    .expect("flush incomplete consensus retirement control");
                // The first authenticated stream ends before the declared
                // frame completes. It must remain a transport failure, never
                // safe-retirement proof.
                continue;
            }
            // A complete ordinary protocol rejection stops the retry only
            // after the client has classified the incomplete first route.
            write_frame(&mut tls, &serde_json::json!({"Rejected": "Protocol"}))
                .await
                .expect("write non-retryable consensus terminator");
        }
    });
    let (_client_source, client_config) = pki.client_source(CLIENT_REPLICA);
    let binding = manifest
        .bind_local(replica_id(CLIENT_REPLICA))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let request = SessionConsensusWireRequest::try_new(
        binding.consensus_identity(),
        binding.local_consensus_node_id(),
        SessionConsensusRpcFamily::Vote,
        b"partial-consensus-retirement".to_vec(),
    )
    .expect("bounded consensus request");
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        binding,
        resolver(address),
        client_config,
        Some(Duration::from_secs(2)),
    )
    .with_connection_lifecycle(lifecycle_policy());
    let before = MetricSnapshot::capture();

    assert!(peer.call(request).await.is_err());
    server.await.expect("partial consensus retirement server");
    let delta = MetricSnapshot::capture().since(before);
    assert_eq!(delta.attempts, 2);
    assert!(delta.transport_failures >= 1);
    assert!(delta.protocol_failures >= 1);
    assert!(delta.reconnect_failures >= 1);
    assert_eq!(delta.successes, 0);
    assert_eq!(
        [
            delta.authentication_failures,
            delta.timeout_failures,
            delta.backend_failures,
        ],
        [0; 3]
    );
}

#[derive(Clone, Copy)]
enum RotationRace {
    Material,
    Explicit,
}

async fn assert_generic_server_pre_hello_rotation(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
    race: RotationRace,
) {
    let (server_source, server_config) = pki.server_source(SERVER_REPLICA);
    let reauthentication = SessionReauthenticationControl::new();
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (handle, address) = SessionReplicationServer::new(
        Arc::new(FakeSessionBackend::new()),
        server_config.clone(),
        binding,
    )
    .with_connection_lifecycle(lifecycle_policy())
    .with_reauthentication_control(reauthentication.clone())
    .listen("127.0.0.1:0".parse().expect("listen address"))
    .await
    .expect("start generic production server");
    let (_client_source, client_config) = pki.client_source(CLIENT_REPLICA);
    let before = MetricSnapshot::capture();
    let mut tls = raw_tls_connection(address, client_config, SESSION_NET_ALPN).await;

    match race {
        RotationRace::Material => {
            let epoch = server_config.material_status().epoch();
            server_source.send_replace(Some(pki.identity_state(SERVER_REPLICA)));
            wait_for_material_epoch(|| server_config.material_status(), epoch).await;
        }
        RotationRace::Explicit => {
            reauthentication
                .request_reauthentication()
                .expect("request generic reauthentication");
        }
    }
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            read_frame::<_, Response>(&mut tls, DEFAULT_MAX_FRAME_SIZE),
        )
        .await
        .expect("generic retirement control timeout")
        .expect("read generic retirement control"),
        Response::ConnectionRetiring
    ));
    wait_for_success_count(before.successes + 1).await;
    let delta = MetricSnapshot::capture().since(before);
    assert_eq!((delta.attempts, delta.successes), (1, 1));
    assert_eq!((delta.reconnect_attempts, delta.reconnect_failures), (0, 0));
    match race {
        RotationRace::Material => {
            assert_eq!(
                (delta.material_retirements, delta.explicit_retirements),
                (1, 0)
            );
        }
        RotationRace::Explicit => {
            assert_eq!(
                (delta.material_retirements, delta.explicit_retirements),
                (0, 1)
            );
        }
    }
    delta.assert_no_failures();
    drop(tls);
    handle.abort_and_wait().await;
}

#[derive(Debug)]
struct CountingConsensusHandler(AtomicUsize);

#[async_trait]
impl SessionConsensusRpcHandler for CountingConsensusHandler {
    async fn handle(
        &self,
        _authenticated_sender: opc_session_store::SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.0.fetch_add(1, Ordering::Relaxed);
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

async fn assert_consensus_server_pre_hello_rotation(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
    race: RotationRace,
) {
    let (server_source, server_config) = pki.server_source(SERVER_REPLICA);
    let reauthentication = SessionReauthenticationControl::new();
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("consensus server binding");
    let handler = Arc::new(CountingConsensusHandler(AtomicUsize::new(0)));
    let (handle, address) =
        SessionConsensusServer::new(handler.clone(), server_config.clone(), binding)
            .with_connection_lifecycle(lifecycle_policy())
            .with_reauthentication_control(reauthentication.clone())
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("start consensus production server");
    let (_client_source, client_config) = pki.client_source(CLIENT_REPLICA);
    let before = MetricSnapshot::capture();
    let mut tls = raw_tls_connection(address, client_config, SESSION_CONSENSUS_ALPN).await;

    match race {
        RotationRace::Material => {
            let epoch = server_config.material_status().epoch();
            server_source.send_replace(Some(pki.identity_state(SERVER_REPLICA)));
            wait_for_material_epoch(|| server_config.material_status(), epoch).await;
        }
        RotationRace::Explicit => {
            reauthentication
                .request_reauthentication()
                .expect("request consensus reauthentication");
        }
    }
    let control: serde_json::Value = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(&mut tls, DEFAULT_MAX_FRAME_SIZE),
    )
    .await
    .expect("consensus retirement control timeout")
    .expect("read consensus retirement control");
    assert_eq!(control, serde_json::json!({"Rejected": "Rejected"}));
    wait_for_success_count(before.successes + 1).await;
    let delta = MetricSnapshot::capture().since(before);
    assert_eq!((delta.attempts, delta.successes), (1, 1));
    assert_eq!((delta.reconnect_attempts, delta.reconnect_failures), (0, 0));
    match race {
        RotationRace::Material => {
            assert_eq!(
                (delta.material_retirements, delta.explicit_retirements),
                (1, 0)
            );
        }
        RotationRace::Explicit => {
            assert_eq!(
                (delta.material_retirements, delta.explicit_retirements),
                (0, 1)
            );
        }
    }
    delta.assert_no_failures();
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    drop(tls);
    handle.abort_and_wait().await;
}

#[test]
fn authenticated_pre_hello_rotation_is_explicit_bounded_and_metric_clean() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("rotation-bootstrap test runtime");
    runtime.block_on(async {
        let pki = TestPki::new();
        let manifest = manifest();

        generic_client_retries_authenticated_bootstrap_retirement(&pki, &manifest).await;
        consensus_client_retries_authenticated_bootstrap_retirement(&pki, &manifest).await;
        generic_unsigned_eof_remains_a_failure(&pki, &manifest).await;
        consensus_partial_retirement_control_eof_remains_a_failure(&pki, &manifest).await;
        assert_generic_server_pre_hello_rotation(&pki, &manifest, RotationRace::Material).await;
        assert_generic_server_pre_hello_rotation(&pki, &manifest, RotationRace::Explicit).await;
        assert_consensus_server_pre_hello_rotation(&pki, &manifest, RotationRace::Material).await;
        assert_consensus_server_pre_hello_rotation(&pki, &manifest, RotationRace::Explicit).await;
    });
}
