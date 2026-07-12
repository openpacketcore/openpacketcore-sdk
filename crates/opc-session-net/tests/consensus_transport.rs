use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_persist::{
    AuditKey, ConfigConsensusRequestId, ConfigConsensusTopology, ConfigStore, ConsensusConfigStore,
    PersistErrorKind, SqliteBackend,
};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_openraft_forms_and_commits_over_the_shared_mtls_adapter() {
    let pki = TestPki::new();
    let manifest = manifest("config-openraft-mtls", 9, 1);
    let directory = tempfile::tempdir().expect("config cluster directory");
    let addresses = (0..3)
        .map(|_| {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("reserve consensus address");
            listener.local_addr().expect("reserved address")
        })
        .collect::<Vec<_>>();
    let node_ids = [1_u16, 2, 3].map(|replica| {
        manifest
            .bind_local(replica_id(replica))
            .expect("local manifest binding")
            .local_consensus_node_id()
    });
    let members = node_ids.iter().copied().collect::<BTreeSet<_>>();
    let identity = manifest
        .bind_local(replica_id(1))
        .expect("identity binding")
        .consensus_identity();

    let mut stores = Vec::new();
    for (source, source_replica) in [1_u16, 2, 3].into_iter().enumerate() {
        let local = manifest
            .bind_local(replica_id(source_replica))
            .expect("source binding");
        let mut peers: BTreeMap<_, Arc<dyn SessionConsensusPeer>> = BTreeMap::new();
        for (target, target_replica) in [1_u16, 2, 3].into_iter().enumerate() {
            if source == target {
                continue;
            }
            let binding = local
                .clone()
                .bind_remote(replica_id(target_replica))
                .expect("remote binding");
            let peer = RemoteSessionConsensusPeer::new_with_resolver(
                binding,
                resolver(addresses[target]),
                pki.client_config(source_replica),
                Some(Duration::from_secs(3)),
            );
            peers.insert(node_ids[target], Arc::new(peer));
        }
        let backend = SqliteBackend::open_with_audit_key(
            directory.path().join(format!("config-{source}.sqlite")),
            true,
            0,
            AuditKey::new([0x75; 32]).expect("audit key"),
        )
        .await
        .expect("config backend");
        stores.push(
            ConsensusConfigStore::open_with_operation_timeout(
                ConfigConsensusTopology::try_new(identity, node_ids[source], members.clone())
                    .expect("config topology"),
                backend,
                directory.path().join(format!("snapshots-{source}")),
                peers,
                Duration::from_secs(8),
            )
            .await
            .expect("config store"),
        );
    }

    let mut servers = Vec::new();
    for (index, replica) in [1_u16, 2, 3].into_iter().enumerate() {
        let binding = manifest
            .bind_local(replica_id(replica))
            .expect("server binding");
        let (handle, actual) = SessionConsensusServer::new(
            stores[index].rpc_handler(),
            pki.server_config(replica),
            binding,
        )
        .listen(addresses[index])
        .await
        .expect("config consensus listener");
        assert_eq!(addresses[index], actual);
        servers.push(handle);
    }

    let (one, two, three) = tokio::join!(
        stores[0].initialize_cluster(),
        stores[1].initialize_cluster(),
        stores[2].initialize_cluster(),
    );
    one.expect("initialize config node one");
    two.expect("initialize config node two");
    three.expect("initialize config node three");
    // Real TLS handshakes, Openraft election, and the first read-index round
    // share a busy multi-threaded test runtime. This evidence deadline is
    // intentionally wider than the unchanged production operation timeout so
    // readiness synchronization cannot flake under full-workspace load.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if stores
                .iter()
                .any(|store| store.status().leader_id.is_none())
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            let (one, two, three) = tokio::join!(
                stores[0].probe_durable_readiness(),
                stores[1].probe_durable_readiness(),
                stores[2].probe_durable_readiness(),
            );
            if one.is_ok() && two.is_ok() && three.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("mTLS config cluster ready");

    let leader = stores
        .iter()
        .find_map(|store| store.status().leader_id)
        .expect("config leader");
    let follower = stores
        .iter()
        .find(|store| store.status().node_id != leader)
        .expect("config follower");
    let error = follower
        .mark_confirmed_idempotent(
            ConfigConsensusRequestId::from_bytes([0xBC; 16]),
            opc_types::TxId::new(),
        )
        .await
        .expect_err("committed missing target returns deterministic domain error");
    assert!(matches!(error.kind(), PersistErrorKind::RollbackNotFound));
    assert!(follower
        .load_latest()
        .await
        .expect("linearizable mTLS read")
        .is_none());
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if stores
                .iter()
                .all(|store| store.status().applied_index.is_some_and(|index| index >= 1))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("committed config command applied on every mTLS peer");

    let _ = tokio::join!(
        stores[0].shutdown(),
        stores[1].shutdown(),
        stores[2].shutdown(),
    );
    for server in servers {
        server.abort_and_wait().await;
    }
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
async fn new_consensus_handshakes_reauthenticate_after_svid_rotation() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", 7, 1);
    let server_binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server_identity_tx, server_identity_rx) =
        tokio::sync::watch::channel(Some(pki.identity_state(SERVER_REPLICA)));
    let server_tls = TlsConfigBuilder::new(server_identity_rx)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("rotating authenticated server config");
    let (handle, addr) = SessionConsensusServer::new(
        Arc::new(EchoHandler {
            delay: Duration::ZERO,
        }),
        server_tls,
        server_binding,
    )
    .listen("127.0.0.1:0".parse().expect("listen address"))
    .await
    .expect("consensus listen");

    let client_binding = manifest
        .bind_local(replica_id(1))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let (client_identity_tx, client_identity_rx) =
        tokio::sync::watch::channel(Some(pki.identity_state(1)));
    let client_tls = TlsConfigBuilder::new(client_identity_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("rotating authenticated client config");
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        client_binding,
        resolver(addr),
        client_tls,
        Some(Duration::from_secs(1)),
    );

    assert_eq!(
        peer.call(request(&manifest, 1, b"before-rotation".to_vec()))
            .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"before-rotation".to_vec()),
        })
    );

    server_identity_tx
        .send(Some(pki.identity_state(SERVER_REPLICA)))
        .expect("rotate server SVID in place");
    client_identity_tx
        .send(Some(pki.identity_state(1)))
        .expect("rotate client SVID in place");
    assert_eq!(
        peer.call(request(&manifest, 1, b"after-rotation".to_vec()))
            .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"after-rotation".to_vec()),
        })
    );

    server_identity_tx
        .send(Some(pki.identity_state(3)))
        .expect("rotate server to wrong SPIFFE identity");
    assert_eq!(
        peer.call(request(&manifest, 1, b"wrong-server".to_vec()))
            .await,
        Err(SessionConsensusPeerError::Authentication)
    );

    server_identity_tx
        .send(Some(pki.identity_state(SERVER_REPLICA)))
        .expect("restore server identity");
    client_identity_tx
        .send(Some(pki.identity_state(3)))
        .expect("rotate client to wrong SPIFFE identity");
    assert_eq!(
        peer.call(request(&manifest, 1, b"wrong-client".to_vec()))
            .await,
        Err(SessionConsensusPeerError::Authentication)
    );

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
