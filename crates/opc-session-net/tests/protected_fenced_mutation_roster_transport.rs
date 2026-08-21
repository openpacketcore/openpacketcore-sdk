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
use hmac::{Hmac, Mac};
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};

use bytes::Bytes;
use opc_session_net::{
    FencedMutationRosterServicePort, FencedMutationRosterTenant,
    PersistentFencedMutationRosterClient, PersistentFencedMutationRosterConfig,
    PersistentFencedMutationRosterConfigError, PersistentFencedMutationRosterExecuteError,
    RemoteAddrResolver, SessionConsumerAuthorizer, SessionConsumerClientError,
    SessionQuorumConsumerServer, StatelessSessionConsumerClient,
    MAX_FENCED_MUTATION_ROSTER_V3_CALL_BYTES, MAX_FENCED_MUTATION_ROSTER_V3_RESPONSE_BYTES,
    SESSION_QUORUM_CONSUMER_V3_ALPN, SESSION_QUORUM_CONSUMER_V3_TRANSPORT_REVISION,
    SESSION_QUORUM_CONSUMER_V4_ALPN, SESSION_QUORUM_CONSUMER_V4_TRANSPORT_REVISION,
};
use opc_session_store::{
    ConsensusSessionStore, FenceToken, FencedMutationMemberAdoption,
    FencedMutationMemberDisposition, FencedMutationRosterAdmission, FencedMutationRosterCapability,
    FencedMutationRosterFenceIntent, FencedMutationRosterMember,
    FencedMutationRosterMemberAttestation, FencedMutationRosterMemberAttestationError,
    FencedMutationRosterMemberAttestationProvider, FencedMutationRosterMemberAttestationVerifier,
    FencedMutationRosterMembers, FencedMutationRosterOperationId,
    FencedMutationRosterProtectedPlan, FencedMutationRosterProtectedResult,
    FencedMutationRosterProviderOutcome, FencedTransitionLease, FencedTransitionMutation,
    FencedTransitionRequest, FencedTransitionRequestId, Generation, OwnerId,
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, SessionConsensusIdentity, SessionConsumerChange,
    SessionConsumerFencedMutationRosterProfile, SessionConsumerIdentity, SessionConsumerOperation,
    SessionConsumerRejection, SessionConsumerRequest, SessionConsumerRequestId,
    SessionConsumerResponse, SessionConsumerScope, SessionConsumerStoreError,
    SessionConsumerV3Operation, SessionConsumerV3Request, SessionConsumerV3Response,
    SessionQuorumConsumer, SqliteSessionBackend, ValidatedQuorumTopology,
    FENCED_MUTATION_ROSTER_OPERATIONAL_TARGET, FENCED_MUTATION_ROSTER_RETAINED_RESULT_CAPACITY,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::SpiffeId;
use opc_types::{NetworkFunctionKind, TenantId};
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
        Some(SessionConsumerFencedMutationRosterProfile::v2())
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
                    FencedMutationRosterCapability::V2,
                    SessionConsumerFencedMutationRosterProfile::v2(),
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
    let (_store, authorizer, scope) = store_authorizer_and_scope(client_spiffe).await;
    (authorizer, scope)
}

async fn store_authorizer_and_scope(
    client_spiffe: &str,
) -> (
    ConsensusSessionStore,
    SessionConsumerAuthorizer,
    SessionConsumerScope,
) {
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
    (store, authorizer, scope)
}

async fn activate_roster_capability(
    store: &ConsensusSessionStore,
    scope: SessionConsumerScope,
    identity: &SessionConsumerIdentity,
) {
    let key = opc_session_store::SessionKey {
        tenant: TenantId::new("attested-roster-activation").expect("activation tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: opc_session_store::SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"attested-roster-activation")
            .try_into()
            .expect("activation ID"),
    };
    let transition = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x81; 16]),
        FencedTransitionLease::acquire(
            key,
            OwnerId::new("attested-roster-owner").expect("activation owner"),
            FenceToken::new(0),
            Duration::from_secs(30),
        )
        .expect("activation lease"),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .expect("activation transition");
    assert!(matches!(
        store
            .consumer_service()
            .execute(
                identity,
                SessionConsumerRequest::new(
                    scope,
                    SessionConsumerRequestId::from_bytes([0x81; 16]),
                    SessionConsumerOperation::FencedTransition {
                        request: Box::new(transition),
                    },
                ),
            )
            .await,
        SessionConsumerResponse::FencedTransition(_)
    ));
}

fn attested_roster_admission(tag: u8) -> FencedMutationRosterAdmission {
    let member = FencedMutationRosterMember::new(
        opc_session_store::fenced_mutation_roster::FencedMutationRosterOrdinal::new(0)
            .expect("member ordinal"),
        [tag; 16],
        opc_session_store::fenced_mutation_roster::FencedMutationRosterDescriptor::new(Vec::new())
            .expect("member descriptor"),
        1,
        1,
        FencedMutationMemberDisposition::Pending,
        FencedMutationMemberAdoption::Unreconciled,
    )
    .expect("member");
    FencedMutationRosterAdmission::new(
        1,
        FencedMutationRosterOperationId::new([tag.wrapping_add(1); 16]).expect("operation ID"),
        opc_session_store::FencedMutationRosterScope::from_digest([0; 32]),
        FencedMutationRosterFenceIntent::new(
            OwnerId::new("attested-roster-owner").expect("roster owner"),
            FenceToken::new(u64::from(tag)),
        ),
        Generation::new(1),
        FencedMutationRosterMembers::new([member]).expect("members"),
        FencedMutationRosterProtectedPlan::new(Box::new([])).expect("plan"),
    )
    .expect("admission")
    .with_terminal_result(
        FencedMutationRosterProtectedResult::new(vec![0x84].into_boxed_slice()).expect("result"),
    )
    .expect("result-bound admission")
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

const ATTESTATION_TEST_KEY: [u8; 32] = [0x91; 32];

fn attestation_signature(
    identity: &str,
    context: &opc_session_store::FencedMutationRosterMemberExecutionContext<'_>,
    outcome: FencedMutationRosterProviderOutcome,
) -> Vec<u8> {
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(&ATTESTATION_TEST_KEY).expect("fixed HMAC key");
    mac.update(b"opc-session-net/attested-roster-provider/v1\0");
    mac.update(
        &u16::try_from(identity.len())
            .expect("bounded identity")
            .to_be_bytes(),
    );
    mac.update(identity.as_bytes());
    mac.update(&context.attestation_commitment());
    mac.update(&[match outcome {
        FencedMutationRosterProviderOutcome::AppliedExecuted => 0,
        FencedMutationRosterProviderOutcome::AppliedAdopted => 1,
        FencedMutationRosterProviderOutcome::NotAppliedReconciled => 2,
        FencedMutationRosterProviderOutcome::CompensatedReconciled => 3,
    }]);
    mac.finalize().into_bytes().to_vec()
}

struct HmacAttestationProvider {
    effects: Arc<AtomicUsize>,
    evidence_identity: String,
    corrupt: bool,
}

#[async_trait]
impl FencedMutationRosterMemberAttestationProvider for HmacAttestationProvider {
    type Error = std::convert::Infallible;

    async fn execute_member(
        &self,
        context: &opc_session_store::FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<FencedMutationRosterMemberAttestation, Self::Error> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        let outcome = FencedMutationRosterProviderOutcome::AppliedExecuted;
        let mut evidence = attestation_signature(&self.evidence_identity, context, outcome);
        if self.corrupt {
            evidence[0] ^= 0xff;
        }
        Ok(FencedMutationRosterMemberAttestation::new(
            context,
            outcome,
            evidence.into_boxed_slice(),
        )
        .expect("bounded signed evidence"))
    }
}

struct HmacAttestationVerifier;

#[async_trait]
impl FencedMutationRosterMemberAttestationVerifier for HmacAttestationVerifier {
    async fn verify_member_attestation(
        &self,
        identity: &SessionConsumerIdentity,
        context: &opc_session_store::FencedMutationRosterMemberExecutionContext<'_>,
        attestation: &FencedMutationRosterMemberAttestation,
    ) -> Result<FencedMutationRosterProviderOutcome, FencedMutationRosterMemberAttestationError>
    {
        attestation
            .validate_for(context)
            .map_err(|_| FencedMutationRosterMemberAttestationError::Rejected)?;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&ATTESTATION_TEST_KEY)
            .map_err(|_| FencedMutationRosterMemberAttestationError::Unavailable)?;
        mac.update(b"opc-session-net/attested-roster-provider/v1\0");
        mac.update(
            &u16::try_from(identity.as_str().len())
                .map_err(|_| FencedMutationRosterMemberAttestationError::Rejected)?
                .to_be_bytes(),
        );
        mac.update(identity.as_str().as_bytes());
        mac.update(&context.attestation_commitment());
        mac.update(&[match attestation.outcome() {
            FencedMutationRosterProviderOutcome::AppliedExecuted => 0,
            FencedMutationRosterProviderOutcome::AppliedAdopted => 1,
            FencedMutationRosterProviderOutcome::NotAppliedReconciled => 2,
            FencedMutationRosterProviderOutcome::CompensatedReconciled => 3,
        }]);
        mac.verify_slice(attestation.evidence())
            .map_err(|_| FencedMutationRosterMemberAttestationError::Rejected)?;
        Ok(attestation.outcome())
    }
}

#[test]
fn revision_five_profile_and_alpn_are_isolated() {
    const QUALIFICATION_REQUIRED_BINDINGS: usize = 100 + 960_000;

    assert_eq!(SESSION_QUORUM_CONSUMER_V3_ALPN, b"opc-session-consumer/3");
    assert_eq!(SESSION_QUORUM_CONSUMER_V3_TRANSPORT_REVISION, 5);
    assert_eq!(SESSION_QUORUM_CONSUMER_V4_ALPN, b"opc-session-consumer/4");
    assert_eq!(SESSION_QUORUM_CONSUMER_V4_TRANSPORT_REVISION, 6);
    assert!(SessionConsumerFencedMutationRosterProfile::v2().is_exact());
    assert!(SessionConsumerFencedMutationRosterProfile::v3().is_exact_v3());

    let profile = SessionConsumerFencedMutationRosterProfile::v2();
    assert_eq!(profile.operation_revision, 2);
    assert_eq!(
        profile.retained_result_capacity as usize,
        FENCED_MUTATION_ROSTER_RETAINED_RESULT_CAPACITY,
    );
    assert!(profile.retained_result_capacity as usize >= QUALIFICATION_REQUIRED_BINDINGS);
    assert!(FENCED_MUTATION_ROSTER_OPERATIONAL_TARGET >= QUALIFICATION_REQUIRED_BINDINGS);

    let mut mixed = SessionConsumerFencedMutationRosterProfile::v2();
    mixed.transport_revision = 4;
    assert!(!mixed.is_exact());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_persistent_mtls_endpoints_terminalize_only_hmac_attested_provider_effects() {
    const ENDPOINTS: usize = 3;
    let pki = TestPki::new();
    let client_spiffe = spiffe("attested-worker");
    let (store, authorizer, scope) = store_authorizer_and_scope(&client_spiffe).await;
    let worker_identity =
        SessionConsumerIdentity::new(client_spiffe.clone()).expect("authenticated worker identity");
    activate_roster_capability(&store, scope, &worker_identity).await;
    let service: Arc<dyn SessionQuorumConsumer> = Arc::new(store.consumer_service());
    let mut handles = Vec::with_capacity(ENDPOINTS);
    let mut clients = Vec::with_capacity(ENDPOINTS);
    for endpoint in 0..ENDPOINTS {
        let server_spiffe = spiffe(&format!("attested-server-{endpoint}"));
        let roster_port = FencedMutationRosterServicePort::with_attestation_verifier(
            Arc::clone(&service),
            Arc::new(HmacAttestationVerifier),
        )
        .expect("attested server verifier port");
        let (handle, address) = SessionQuorumConsumerServer::new(
            Arc::clone(&service),
            pki.server_config(&server_spiffe),
            authorizer.clone(),
        )
        .with_fenced_mutation_roster_service(roster_port)
        .with_max_connections(2)
        .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
        .await
        .expect("start attested roster endpoint");
        handles.push(handle);
        let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
        let client = PersistentFencedMutationRosterClient::try_from_stateless(
            StatelessSessionConsumerClient::new_with_resolver(
                resolver,
                rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
                scope,
                pki.client_config(&client_spiffe),
            )
            .with_operation_timeout(Duration::from_secs(2)),
            load_config(1),
        )
        .expect("persistent client");
        client.prewarm().await.expect("persistent V3 status lane");
        client
            .prewarm_attested()
            .await
            .expect("persistent V4 attested lane");
        clients.push(client);
    }
    let tenant = FencedMutationRosterTenant::new([0x87; 16]).expect("tenant");
    let admitted = clients[0]
        .bind_fenced_mutation_roster_admission(attested_roster_admission(0x88))
        .expect("mTLS-bound admission");
    assert!(matches!(
        clients[0]
            .execute(
                tenant,
                SessionConsumerV3Request::new(
                    scope,
                    SessionConsumerV3Operation::FencedMutationRosterAdmit {
                        admission: Box::new(admitted.clone()),
                    },
                ),
            )
            .await,
        Ok(SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_)))
    ));
    let effects = Arc::new(AtomicUsize::new(0));
    let provider = HmacAttestationProvider {
        effects: Arc::clone(&effects),
        evidence_identity: client_spiffe.clone(),
        corrupt: false,
    };
    assert!(matches!(
        clients[0]
            .execute_attested_terminalization(
                tenant,
                admitted.clone(),
                vec![0x89].into_boxed_slice(),
                &provider,
            )
            .await,
        Ok(opc_session_store::SessionConsumerV4Response::FencedMutationRosterTerminalize(Ok(outcome)))
            if outcome.status.phase() == opc_session_store::FencedMutationRosterPhase::Established
    ));
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert!(matches!(
        clients[0]
            .execute_attested_terminalization(
                tenant,
                admitted,
                vec![0x89].into_boxed_slice(),
                &provider,
            )
            .await,
        Err(
            opc_session_net::PersistentFencedMutationRosterProviderExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            }
        )
    ));
    assert_eq!(
        effects.load(Ordering::SeqCst),
        1,
        "durable replay rejection runs before a second external worker effect"
    );

    for (tag, corrupt, evidence_identity) in [
        (0x8a, true, client_spiffe.clone()),
        (0x8c, false, spiffe("different-worker")),
    ] {
        let admission = clients[1]
            .bind_fenced_mutation_roster_admission(attested_roster_admission(tag))
            .expect("bound negative admission");
        assert!(matches!(
            clients[1]
                .execute(
                    tenant,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdmit {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            Ok(SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_)))
        ));
        let negative = HmacAttestationProvider {
            effects: Arc::clone(&effects),
            evidence_identity,
            corrupt,
        };
        assert!(
            matches!(
                clients[1]
                    .execute_attested_terminalization(
                        tenant,
                        admission.clone(),
                        vec![0x89].into_boxed_slice(),
                        &negative,
                    )
                    .await,
                Ok(opc_session_store::SessionConsumerV4Response::Rejected(
                    SessionConsumerRejection::Unauthorized,
                ))
            ),
            "forged or wrong-worker evidence must not reach terminal mutation"
        );
        assert!(matches!(
            clients[1]
                .execute(
                    tenant,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterStatus {
                            admission: Box::new(admission),
                        },
                    ),
                )
                .await,
            Ok(SessionConsumerV3Response::FencedMutationRosterStatus(Ok(status)))
                if status.phase() == opc_session_store::FencedMutationRosterPhase::PollAdmitted
        ));
    }
    assert_eq!(effects.load(Ordering::SeqCst), 3);
    for handle in handles {
        handle.abort_and_wait().await;
    }
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
                        FencedMutationRosterCapability::V2,
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
