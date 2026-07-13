#![cfg(feature = "legacy-session-net-compat")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::protocol::{
    read_frame, write_frame, CONTRACT_VERSION, CURRENT_CONTRACT_PROFILE, DEFAULT_MAX_FRAME_SIZE,
    SESSION_NET_ALPN,
};
use opc_session_net::{
    RemoteAddrResolver, RemoteReplicaBinding, RemoteSessionBackend, Request, Response,
    SessionClusterId, SessionConfigurationEpoch, SessionConfigurationGeneration,
    SessionReplicationManifest, SessionReplicationServer,
};
use opc_session_store::fake::FakeSessionBackend;
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaReadinessFailure, ReplicaTlsIdentity, SessionBackend,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};

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
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("replica-{replica}"));
        params.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::Ia5String::try_from(replica_spiffe(replica)).expect("SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .expect("leaf certificate");

        let certs = parse_certs_pem(&(cert.pem() + &self.ca_cert.pem())).expect("certificate PEM");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("private key PEM");
        let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
        let mut trust_bundles = opc_identity::TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: parse_certs_pem(&self.ca_cert.pem()).expect("CA PEM"),
        });
        build_identity_state(certs, private_key, trust_bundles).expect("identity state")
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
        ReplicaEndpoint::new(format!("replica-{replica}.session.invalid"), 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(replica_spiffe(replica)).expect("TLS identity"),
        ReplicaFailureDomain::new(format!("zone-{replica}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("disk-{replica}")).expect("backing identity"),
    )
}

fn manifest(cluster: &str, generation: &str) -> Arc<SessionReplicationManifest> {
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new(cluster).expect("cluster ID"),
            SessionConfigurationGeneration::new(generation).expect("configuration generation"),
            SessionConfigurationEpoch::new(1).expect("configuration epoch"),
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
    assert!(matches!(
        first_response,
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            ..
        }
    ));
    drop(first);

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
