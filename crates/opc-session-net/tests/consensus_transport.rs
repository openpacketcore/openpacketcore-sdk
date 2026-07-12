use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
#[cfg(feature = "legacy-session-net-compat")]
use opc_session_net::RemoteSessionBackend;
use opc_session_net::{
    RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, SessionConsensusServer, SessionReplicationManifest,
};
#[cfg(feature = "legacy-session-net-compat")]
use opc_session_store::ReplicaReadinessFailure;
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler, SessionConsensusWireRequest,
    SessionConsensusWireResponse, SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
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
            .push(rcgen::DnType::CommonName, "Session consensus test CA");
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

fn descriptor(replica: u16, endpoint_generation: u16) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(replica),
        ReplicaEndpoint::new(
            format!("replica-{replica}-g{endpoint_generation}.session.invalid"),
            7443,
        )
        .expect("endpoint"),
        ReplicaTlsIdentity::new(replica_spiffe(replica)).expect("TLS identity"),
        ReplicaFailureDomain::new(format!("zone-{replica}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("disk-{replica}")).expect("backing identity"),
    )
}

fn manifest(
    cluster: &str,
    epoch: u64,
    endpoint_generation: u16,
) -> Arc<SessionReplicationManifest> {
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new(cluster).expect("cluster ID"),
            SessionConfigurationGeneration::new("legacy-v4").expect("legacy generation"),
            SessionConfigurationEpoch::new(epoch).expect("configuration epoch"),
            vec![
                descriptor(1, endpoint_generation),
                descriptor(2, endpoint_generation),
                descriptor(3, endpoint_generation),
            ],
        )
        .expect("replication manifest"),
    )
}

fn resolver(addr: SocketAddr) -> RemoteAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(addr) }))
}

#[derive(Debug)]
struct EchoHandler {
    delay: Duration,
}

#[async_trait]
impl SessionConsensusRpcHandler for EchoHandler {
    async fn handle(
        &self,
        _authenticated_sender: opc_session_store::SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        tokio::time::sleep(self.delay).await;
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

async fn start_server(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
    delay: Duration,
) -> (opc_session_net::SessionConsensusServerHandle, SocketAddr) {
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    SessionConsensusServer::new(
        Arc::new(EchoHandler { delay }),
        pki.server_config(SERVER_REPLICA),
        binding,
    )
    .listen("127.0.0.1:0".parse().expect("listen address"))
    .await
    .expect("consensus listen")
}

fn peer(
    manifest: &Arc<SessionReplicationManifest>,
    local_replica: u16,
    remote_replica: u16,
    addr: SocketAddr,
    tls: AuthenticatedClientConfig,
    deadline: Duration,
) -> RemoteSessionConsensusPeer {
    let binding = manifest
        .bind_local(replica_id(local_replica))
        .expect("local binding")
        .bind_remote(replica_id(remote_replica))
        .expect("remote binding");
    RemoteSessionConsensusPeer::new_with_resolver(binding, resolver(addr), tls, Some(deadline))
}

fn request(
    manifest: &Arc<SessionReplicationManifest>,
    sender: u16,
    payload: Vec<u8>,
) -> SessionConsensusWireRequest {
    let binding = manifest
        .bind_local(replica_id(sender))
        .expect("sender binding");
    SessionConsensusWireRequest::try_new(
        binding.consensus_identity(),
        binding.local_consensus_node_id(),
        SessionConsensusRpcFamily::Vote,
        payload,
    )
    .expect("bounded request")
}

#[tokio::test]
async fn authenticated_consensus_call_uses_stable_manifest_node_ids() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", 7, 1);
    let (handle, addr) = start_server(&pki, &manifest, Duration::ZERO).await;
    let peer = peer(
        &manifest,
        1,
        SERVER_REPLICA,
        addr,
        pki.client_config(1),
        Duration::from_secs(1),
    );
    let port: Arc<dyn SessionConsensusPeer> = Arc::new(peer.clone());

    let expected_server_node = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding")
        .local_consensus_node_id();
    assert_eq!(port.node_id(), expected_server_node);
    assert_ne!(port.node_id().get(), 0);
    assert_eq!(
        port.call(request(&manifest, 1, b"bounded-vote".to_vec()))
            .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"bounded-vote".to_vec()),
        })
    );

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn certificate_sender_cluster_configuration_and_epoch_mismatches_fail_closed() {
    let pki = TestPki::new();
    let server_manifest = manifest("cluster-a", 7, 1);
    let (handle, addr) = start_server(&pki, &server_manifest, Duration::ZERO).await;

    let wrong_certificate = peer(
        &server_manifest,
        1,
        SERVER_REPLICA,
        addr,
        pki.client_config(3),
        Duration::from_millis(500),
    );
    assert_eq!(
        wrong_certificate
            .call(request(&server_manifest, 1, Vec::new()))
            .await,
        Err(SessionConsensusPeerError::Authentication)
    );

    let wrong_sender = peer(
        &server_manifest,
        1,
        SERVER_REPLICA,
        addr,
        pki.client_config(1),
        Duration::from_millis(500),
    );
    assert_eq!(
        wrong_sender
            .call(request(&server_manifest, 3, Vec::new()))
            .await,
        Err(SessionConsensusPeerError::ScopeMismatch)
    );

    for wrong_manifest in [
        manifest("cluster-b", 7, 1),
        manifest("cluster-a", 7, 2),
        manifest("cluster-a", 8, 1),
    ] {
        let wrong_scope = peer(
            &wrong_manifest,
            1,
            SERVER_REPLICA,
            addr,
            pki.client_config(1),
            Duration::from_millis(500),
        );
        assert_eq!(
            wrong_scope
                .call(request(&wrong_manifest, 1, Vec::new()))
                .await,
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
    }

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn oversized_payload_and_complete_call_deadline_are_bounded() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", 7, 1);
    let (handle, addr) = start_server(&pki, &manifest, Duration::from_secs(1)).await;
    let peer = peer(
        &manifest,
        1,
        SERVER_REPLICA,
        addr,
        pki.client_config(1),
        Duration::from_millis(75),
    );

    let binding = manifest.bind_local(replica_id(1)).expect("sender binding");
    let oversized = SessionConsensusWireRequest {
        schema_version: opc_session_store::SESSION_CONSENSUS_SCHEMA_VERSION,
        identity: binding.consensus_identity(),
        sender: binding.local_consensus_node_id(),
        family: SessionConsensusRpcFamily::Vote,
        payload: vec![0; SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES + 1],
    };
    assert_eq!(
        peer.call(oversized).await,
        Err(SessionConsensusPeerError::Protocol)
    );

    let started = Instant::now();
    assert_eq!(
        peer.call(request(&manifest, 1, Vec::new())).await,
        Err(SessionConsensusPeerError::Timeout)
    );
    assert!(started.elapsed() < Duration::from_millis(500));

    handle.abort_and_wait().await;
}

#[tokio::test]
#[cfg(feature = "legacy-session-net-compat")]
async fn production_consensus_listener_cannot_negotiate_legacy_backend_authority() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", 7, 1);
    let (handle, addr) = start_server(&pki, &manifest, Duration::ZERO).await;
    let binding = manifest
        .bind_local(replica_id(1))
        .expect("local binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let legacy = RemoteSessionBackend::new_with_resolver(
        binding,
        resolver(addr),
        pki.client_config(1),
        Some(Duration::from_millis(250)),
    );

    assert_eq!(
        opc_session_store::SessionBackend::probe_replication_head(&legacy).await,
        Err(ReplicaReadinessFailure::Protocol)
    );

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn logical_deadline_includes_a_stalled_resolver() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", 7, 1);
    let binding = manifest
        .bind_local(replica_id(1))
        .expect("local binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let stalled: RemoteAddrResolver =
        Arc::new(|| Box::pin(std::future::pending::<std::io::Result<SocketAddr>>()));
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        binding,
        stalled,
        pki.client_config(1),
        Some(Duration::from_millis(50)),
    );

    let started = Instant::now();
    assert_eq!(
        peer.call(request(&manifest, 1, Vec::new())).await,
        Err(SessionConsensusPeerError::Timeout)
    );
    assert!(started.elapsed() < Duration::from_millis(500));
}
