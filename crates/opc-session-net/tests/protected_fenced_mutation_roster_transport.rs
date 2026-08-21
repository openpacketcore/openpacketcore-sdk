//! Live transport evidence for the protected-roster consumer lane.
//!
//! This is deliberately a transport-only pre-landing gate: it proves real
//! loopback mTLS, fixed connection reuse, bounded admission, and credential
//! rotation across three independently listening endpoints. It does not claim
//! that those endpoints are a three-voter consensus quorum; the final product
//! qualification must supply that evidence after the production service is
//! composed and pinned downstream.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::{self, BoxStream, StreamExt};
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};

use opc_session_net::{
    FencedMutationRosterServicePort, FencedMutationRosterTenant,
    PersistentFencedMutationRosterClient, PersistentFencedMutationRosterConfig,
    PersistentFencedMutationRosterConfigError, PersistentFencedMutationRosterExecuteError,
    RemoteAddrResolver, SessionConsumerAuthorizer, SessionConsumerClientError,
    SessionQuorumConsumerServer, StatelessSessionConsumerClient,
    MAX_FENCED_MUTATION_ROSTER_V3_CALL_BYTES, MAX_FENCED_MUTATION_ROSTER_V3_RESPONSE_BYTES,
    SESSION_QUORUM_CONSUMER_V3_ALPN, SESSION_QUORUM_CONSUMER_V3_TRANSPORT_REVISION,
};
use opc_session_store::{
    ConsensusSessionStore, FencedMutationRosterCapability, QuorumReplicaDescriptor,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    SessionConsensusIdentity, SessionConsumerChange, SessionConsumerFencedMutationRosterProfile,
    SessionConsumerIdentity, SessionConsumerRejection, SessionConsumerRequest,
    SessionConsumerResponse, SessionConsumerScope, SessionConsumerStoreError,
    SessionConsumerV3Operation, SessionConsumerV3Request, SessionConsumerV3Response,
    SessionQuorumConsumer, SqliteSessionBackend, ValidatedQuorumTopology,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::SpiffeId;
use tokio::sync::Barrier;

struct TestPki {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().expect("test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters.distinguished_name.push(
            rcgen::DnType::CommonName,
            "protected roster transport test CA",
        );
        Self {
            ca: rcgen::CertifiedIssuer::self_signed(parameters, key).expect("test CA certificate"),
        }
    }

    fn client_config(&self, spiffe_id: &str) -> AuthenticatedClientConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("test client TLS config")
    }

    fn server_config(&self, spiffe_id: &str) -> AuthenticatedServerConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("test server TLS config")
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
}

#[derive(Default)]
struct CountingRosterConsumer {
    calls: AtomicUsize,
}

#[async_trait]
impl SessionQuorumConsumer for CountingRosterConsumer {
    async fn execute(
        &self,
        _identity: &SessionConsumerIdentity,
        _request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
    }

    fn fenced_mutation_roster_profile(&self) -> Option<SessionConsumerFencedMutationRosterProfile> {
        Some(SessionConsumerFencedMutationRosterProfile::v1())
    }

    async fn execute_v3(
        &self,
        _identity: &SessionConsumerIdentity,
        request: SessionConsumerV3Request,
    ) -> SessionConsumerV3Response {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match request.operation() {
            SessionConsumerV3Operation::FencedMutationRosterCapability => {
                SessionConsumerV3Response::FencedMutationRosterCapability(Ok((
                    FencedMutationRosterCapability::V1,
                    SessionConsumerFencedMutationRosterProfile::v1(),
                )))
            }
            _ => SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unavailable),
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
        Ok(stream::empty().boxed())
    }
}

fn spiffe(name: &str) -> String {
    format!("spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/{name}")
}

async fn authorizer_and_scope(
    client_spiffe: &str,
) -> (SessionConsumerAuthorizer, SessionConsumerScope) {
    let snapshots = tempfile::tempdir().expect("snapshot directory");
    let replica_id = ReplicaId::new("protected-roster-transport-test").expect("replica ID");
    let descriptor = QuorumReplicaDescriptor::new(
        replica_id.clone(),
        ReplicaEndpoint::new("protected-roster.test.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(spiffe("member")).expect("member TLS identity"),
        ReplicaFailureDomain::new("protected-roster-zone").expect("failure domain"),
        ReplicaBackingIdentity::new("protected-roster-disk").expect("backing identity"),
    );
    let cluster = ConsensusClusterId::new("protected-roster-transport-test").expect("cluster ID");
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

fn load_config(lanes: usize) -> PersistentFencedMutationRosterConfig {
    PersistentFencedMutationRosterConfig::try_new(
        lanes,
        256,
        8,
        256,
        MAX_FENCED_MUTATION_ROSTER_V3_CALL_BYTES,
        MAX_FENCED_MUTATION_ROSTER_V3_RESPONSE_BYTES,
        256,
        256,
        2,
        256,
        Duration::from_millis(1_500),
        Duration::from_secs(1),
    )
    .expect("bounded load configuration")
}

#[test]
fn revision_five_profile_and_alpn_are_isolated() {
    assert_eq!(SESSION_QUORUM_CONSUMER_V3_ALPN, b"opc-session-consumer/3");
    assert_eq!(SESSION_QUORUM_CONSUMER_V3_TRANSPORT_REVISION, 5);
    assert!(SessionConsumerFencedMutationRosterProfile::v1().is_exact());

    let mut mixed = SessionConsumerFencedMutationRosterProfile::v1();
    mixed.transport_revision = 4;
    assert!(!mixed.is_exact());
}

#[test]
fn fixed_roster_pool_bounds_reject_unbounded_or_empty_tenant_inputs() {
    assert_eq!(
        FencedMutationRosterTenant::new([0; 16]),
        Err(PersistentFencedMutationRosterConfigError::Capacity)
    );
    assert!(FencedMutationRosterTenant::new([1; 16]).is_ok());
    assert_eq!(
        PersistentFencedMutationRosterConfig::try_new(
            0,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            0,
            1,
            Duration::from_millis(1),
            Duration::from_millis(1),
        ),
        Err(PersistentFencedMutationRosterConfigError::Capacity)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn three_mtls_endpoints_reuse_fixed_lanes_for_one_thousand_concurrent_actors() {
    const ENDPOINTS: usize = 3;
    const LANES_PER_ENDPOINT: usize = 2;
    const ACTORS: usize = 1_000;

    let pki = TestPki::new();
    let client_spiffe = spiffe("scale-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(CountingRosterConsumer::default());
    let mut server_handles = Vec::with_capacity(ENDPOINTS);
    let mut clients = Vec::with_capacity(ENDPOINTS);
    let mut resolutions = Vec::with_capacity(ENDPOINTS);

    for endpoint in 0..ENDPOINTS {
        let server_spiffe = spiffe(&format!("scale-server-{endpoint}"));
        let consumer_service: Arc<dyn SessionQuorumConsumer> = service.clone();
        let roster_port = FencedMutationRosterServicePort::new(consumer_service.clone())
            .expect("validated roster service port");
        let (handle, address) = SessionQuorumConsumerServer::new(
            consumer_service,
            pki.server_config(&server_spiffe),
            authorizer.clone(),
        )
        .with_fenced_mutation_roster_service(roster_port)
        .with_max_connections(LANES_PER_ENDPOINT)
        .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
        .await
        .expect("start protected roster listener");
        server_handles.push(handle);

        let resolution_count = Arc::new(AtomicUsize::new(0));
        let resolver_count = Arc::clone(&resolution_count);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(address) })
        });
        resolutions.push(resolution_count);
        let stateless = StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
            scope,
            pki.client_config(&client_spiffe),
        )
        .with_operation_timeout(Duration::from_secs(2));
        clients.push(
            PersistentFencedMutationRosterClient::try_from_stateless(
                stateless,
                load_config(LANES_PER_ENDPOINT),
            )
            .expect("persistent protected roster client"),
        );
    }

    for client in &clients {
        let readiness = client.prewarm().await.expect("prewarm fixed mTLS lanes");
        assert!(readiness.ready);
        assert_eq!(readiness.configured_lanes, LANES_PER_ENDPOINT);
        assert_eq!(readiness.warm_lanes, LANES_PER_ENDPOINT);
    }
    assert_eq!(
        resolutions
            .iter()
            .map(|count| count.load(Ordering::SeqCst))
            .sum::<usize>(),
        ENDPOINTS * LANES_PER_ENDPOINT,
        "prewarm performs exactly one DNS/TCP/TLS/Hello setup per fixed lane",
    );

    let barrier = Arc::new(Barrier::new(ACTORS + 1));
    let local_overload = Arc::new(AtomicUsize::new(0));
    let local_unavailable = Arc::new(AtomicUsize::new(0));
    let mut actor_tasks = tokio::task::JoinSet::new();
    for actor in 0..ACTORS {
        let client = clients[actor % ENDPOINTS].clone();
        let barrier = Arc::clone(&barrier);
        let local_overload = Arc::clone(&local_overload);
        let local_unavailable = Arc::clone(&local_unavailable);
        actor_tasks.spawn(async move {
            let tenant_number =
                u16::try_from((actor / ENDPOINTS) % 250 + 1).expect("bounded tenant number");
            let mut tenant = [0_u8; 16];
            tenant[14..].copy_from_slice(&tenant_number.to_be_bytes());
            let tenant = FencedMutationRosterTenant::new(tenant).expect("opaque tenant");
            barrier.wait().await;
            for _ in 0..128 {
                let request = SessionConsumerV3Request::new(
                    scope,
                    SessionConsumerV3Operation::FencedMutationRosterCapability,
                );
                match client.execute(tenant, request).await {
                    Ok(SessionConsumerV3Response::FencedMutationRosterCapability(Ok((
                        FencedMutationRosterCapability::V1,
                        profile,
                    )))) if profile.is_exact() => return,
                    Err(PersistentFencedMutationRosterExecuteError::NotTransmitted {
                        cause: SessionConsumerClientError::Overloaded,
                    }) => {
                        local_overload.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                    }
                    Err(PersistentFencedMutationRosterExecuteError::NotTransmitted {
                        cause: SessionConsumerClientError::Unavailable,
                    }) => {
                        local_unavailable.fetch_add(1, Ordering::SeqCst);
                        client
                            .prewarm()
                            .await
                            .expect("a lost fixed lane must reconnect within its setup bound");
                    }
                    Err(PersistentFencedMutationRosterExecuteError::NotTransmitted { cause }) => {
                        panic!("actor received unexpected redacted pre-write cause: {cause:?}")
                    }
                    result => panic!("actor received unexpected redacted result: {result:?}"),
                }
            }
            panic!("actor exhausted its bounded local overload retries");
        });
    }
    barrier.wait().await;
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(result) = actor_tasks.join_next().await {
            result.expect("actor task completes");
        }
    })
    .await
    .expect("one thousand actors finish within the bounded test deadline");

    let expected_setups = ENDPOINTS * LANES_PER_ENDPOINT;
    assert_eq!(
        local_unavailable.load(Ordering::SeqCst),
        0,
        "the warm window must not sacrifice an actor operation to lane setup",
    );
    assert_eq!(
        resolutions
            .iter()
            .map(|count| count.load(Ordering::SeqCst))
            .sum::<usize>(),
        expected_setups,
        "ordinary operations perform no DNS/TCP/TLS/Hello setup",
    );
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        ACTORS + expected_setups,
        "only fixed-lane capability probes and actor operations reach the service",
    );

    let observed_overload = clients
        .iter()
        .map(|client| client.diagnostics().overload)
        .sum::<u64>();
    assert_eq!(
        observed_overload,
        local_overload.load(Ordering::SeqCst) as u64,
        "every bounded local rejection is accounted",
    );
    for client in &clients {
        let diagnostics = client.diagnostics();
        assert_eq!(diagnostics.warm_lanes, LANES_PER_ENDPOINT as u64);
        assert_eq!(diagnostics.max_lanes, LANES_PER_ENDPOINT as u64);
        assert_eq!(diagnostics.queued, 0);
        assert_eq!(diagnostics.inflight, 0);
        assert_eq!(diagnostics.response_cells, 0);
        assert_eq!(diagnostics.request_bytes, 0);
        assert!(diagnostics.queue_high_water <= client.config().pending_calls() as u64);
        assert!(diagnostics.inflight_high_water <= LANES_PER_ENDPOINT as u64);
        assert!(diagnostics.response_high_water <= client.config().response_cells() as u64);
        assert_eq!(diagnostics.retries, 0);
    }

    for client in &clients {
        client.shutdown().await;
    }
    for handle in server_handles {
        handle.abort_and_wait().await;
    }
}
