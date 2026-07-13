#![cfg(feature = "legacy-session-net-compat")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
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
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, Generation, OwnerId,
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaReadinessFailure, ReplicaTlsIdentity, SessionBackend, SessionKey,
    SessionKeyType, StableId, StateClass, StateType, StoredSessionRecord,
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

#[tokio::test]
async fn overlapping_trust_rotation_reauthenticates_and_rejects_removed_old_trust() {
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
    let server = SessionReplicationServer::new(
        Arc::new(FakeSessionBackend::new()),
        server_config.clone(),
        binding,
    )
    .with_connection_lifecycle(lifecycle_policy())
    .with_reauthentication_control(reauthentication.clone());
    let (handle, addr) = server
        .listen("127.0.0.1:0".parse().expect("listen address"))
        .await
        .expect("rotation listener");
    let backend = remote(&manifest, 1, SERVER_REPLICA, addr, client_config.clone())
        .with_connection_lifecycle(lifecycle_policy())
        .with_reauthentication_control(reauthentication.clone());

    assert_eq!(backend.probe_replication_head().await, Ok(0));

    let client_epoch = client_config.material_status().epoch();
    let server_epoch = server_config.material_status().epoch();
    client_tx.send_replace(Some(
        old_pki.identity_state_with_trust_and_validity(1, &overlap, validity),
    ));
    server_tx.send_replace(Some(old_pki.identity_state_with_trust_and_validity(
        SERVER_REPLICA,
        &overlap,
        validity,
    )));
    wait_for_material_epoch_change(|| client_config.material_status(), client_epoch).await;
    wait_for_material_epoch_change(|| server_config.material_status(), server_epoch).await;
    reauthentication
        .request_reauthentication()
        .expect("reauthenticate on overlapping trust");
    assert_eq!(backend.probe_replication_head().await, Ok(0));

    let client_epoch = client_config.material_status().epoch();
    let server_epoch = server_config.material_status().epoch();
    client_tx.send_replace(Some(
        new_pki.identity_state_with_trust_and_validity(1, &overlap, validity),
    ));
    server_tx.send_replace(Some(new_pki.identity_state_with_trust_and_validity(
        SERVER_REPLICA,
        &overlap,
        validity,
    )));
    wait_for_material_epoch_change(|| client_config.material_status(), client_epoch).await;
    wait_for_material_epoch_change(|| server_config.material_status(), server_epoch).await;
    reauthentication
        .request_reauthentication()
        .expect("reauthenticate on renewed leaves");
    assert_eq!(backend.probe_replication_head().await, Ok(0));

    let client_epoch = client_config.material_status().epoch();
    let server_epoch = server_config.material_status().epoch();
    client_tx.send_replace(Some(
        new_pki.identity_state_with_trust_and_validity(1, &new_trust, validity),
    ));
    server_tx.send_replace(Some(new_pki.identity_state_with_trust_and_validity(
        SERVER_REPLICA,
        &new_trust,
        validity,
    )));
    wait_for_material_epoch_change(|| client_config.material_status(), client_epoch).await;
    wait_for_material_epoch_change(|| server_config.material_status(), server_epoch).await;
    reauthentication
        .request_reauthentication()
        .expect("reauthenticate after old-trust removal");
    assert_eq!(backend.probe_replication_head().await, Ok(0));

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
    old_server_task.await.expect("old server rejection task");
    handle.abort();
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
