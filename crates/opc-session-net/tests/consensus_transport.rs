use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use opc_consensus::{DURABLE_CONSENSUS_OPERATION_TIMEOUT, DURABLE_CONSENSUS_TIMING_PROFILE};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_persist::{
    AuditKey, ConfigConsensusRequestId, ConfigConsensusTopology, ConfigStore, ConsensusConfigStore,
    PersistErrorKind, SqliteBackend,
};
#[cfg(feature = "legacy-session-net-compat")]
use opc_session_net::RemoteSessionBackend;
use opc_session_net::{
    ConnectionLifecyclePolicy, RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId,
    SessionConfigurationEpoch, SessionConfigurationGeneration, SessionConsensusServer,
    SessionReauthenticationControl, SessionReplicationManifest,
};
#[cfg(feature = "legacy-session-net-compat")]
use opc_session_store::ReplicaReadinessFailure;
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, ConsensusSessionStore, EncryptedSessionPayload,
    EncryptingSessionBackend, Generation, LeaseGuard, OwnerId, QuorumReplicaDescriptor,
    QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaTlsIdentity, RestoreScanRequest, SessionBackend, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRpcFamily, SessionConsensusRpcHandler,
    SessionConsensusWireRequest, SessionConsensusWireResponse, SessionKey, SessionKeyType,
    SessionLeaseManager, SqliteSessionBackend, StateClass, StateType, StoredSessionRecord,
    SystemClock, ValidatedQuorumTopology, SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
};
use opc_tls::{
    AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder,
    TlsMaterialAvailability, TlsMaterialEpoch,
};
use opc_types::{NetworkFunctionKind, TenantId};

const SERVER_REPLICA: u16 = 2;
const CLUSTER_TRANSITION_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);

// Each scenario below starts a complete Openraft fleet in its own Tokio
// runtime. Running those fleets concurrently is artificial and can starve
// election/readiness progress on the i686 CI runner, so keep the expensive
// integration scenarios sequential within this test binary. The synchronous
// wrapper holds this guard until after its runtime has shut down, preventing a
// following fleet from overlapping background work owned by the prior runtime.
static OPENRAFT_FLEET_TEST_GUARD: StdMutex<()> = StdMutex::new(());

fn run_openraft_fleet_test(worker_threads: usize, scenario: impl std::future::Future<Output = ()>) {
    let _fleet_test_guard = OPENRAFT_FLEET_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .expect("Openraft fleet test runtime");
    runtime.block_on(scenario);
    drop(runtime);
}

struct TestPki {
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

struct RotationRoot {
    certificate: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl RotationRoot {
    fn new(label: &str) -> Self {
        let key = rcgen::KeyPair::generate().expect("rotation root key");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("{label} rotation root"));
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(30);
        let certificate = params.self_signed(&key).expect("rotation root certificate");
        Self { certificate, key }
    }

    fn issue_intermediate(&self, label: &str) -> RotationIntermediate {
        let key = rcgen::KeyPair::generate().expect("rotation intermediate key");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("{label} rotation intermediate"),
        );
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(14);
        let certificate = params
            .signed_by(&key, &self.certificate, &self.key)
            .expect("rotation intermediate certificate");
        RotationIntermediate { certificate, key }
    }
}

struct RotationIntermediate {
    certificate: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl RotationIntermediate {
    fn issue_leaf(&self, replica: u16) -> RotationLeaf {
        let key = rcgen::KeyPair::generate().expect("rotation leaf key");
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
        let certificate = params
            .signed_by(&key, &self.certificate, &self.key)
            .expect("rotation leaf certificate");
        RotationLeaf { certificate, key }
    }
}

struct RotationLeaf {
    certificate: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl RotationLeaf {
    fn identity_state(
        &self,
        intermediate: &RotationIntermediate,
        trust_roots: &[&RotationRoot],
    ) -> opc_identity::IdentityState {
        let cert_chain =
            parse_certs_pem(&(self.certificate.pem() + &intermediate.certificate.pem()))
                .expect("rotation certificate chain PEM");
        let private_key = parse_key_pem(&self.key.serialize_pem()).expect("rotation key PEM");
        let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
        let trust_pem = trust_roots
            .iter()
            .map(|root| root.certificate.pem())
            .collect::<String>();
        let mut trust_bundles = opc_identity::TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: parse_certs_pem(&trust_pem).expect("rotation trust PEM"),
        });
        build_identity_state(cert_chain, private_key, trust_bundles)
            .expect("rotation identity state")
    }
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
    .expect("consensus material epoch update");
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
    manifest_for_replicas(cluster, epoch, endpoint_generation, &[1, 2, 3])
}

fn manifest_for_replicas(
    cluster: &str,
    epoch: u64,
    endpoint_generation: u16,
    replicas: &[u16],
) -> Arc<SessionReplicationManifest> {
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new(cluster).expect("cluster ID"),
            SessionConfigurationGeneration::new("legacy-v4").expect("legacy generation"),
            SessionConfigurationEpoch::new(epoch).expect("configuration epoch"),
            replicas
                .iter()
                .map(|replica| descriptor(*replica, endpoint_generation))
                .collect(),
        )
        .expect("replication manifest"),
    )
}

fn resolver(addr: SocketAddr) -> RemoteAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(addr) }))
}

fn deferred_resolver(
    address: Arc<StdRwLock<Option<SocketAddr>>>,
    enabled: Arc<AtomicBool>,
) -> RemoteAddrResolver {
    deferred_resolver_with_counter(address, enabled, None)
}

fn counted_deferred_resolver(
    address: Arc<StdRwLock<Option<SocketAddr>>>,
    enabled: Arc<AtomicBool>,
    resolutions: Arc<AtomicUsize>,
) -> RemoteAddrResolver {
    deferred_resolver_with_counter(address, enabled, Some(resolutions))
}

fn deferred_resolver_with_counter(
    address: Arc<StdRwLock<Option<SocketAddr>>>,
    enabled: Arc<AtomicBool>,
    resolutions: Option<Arc<AtomicUsize>>,
) -> RemoteAddrResolver {
    Arc::new(move || {
        let address = Arc::clone(&address);
        let enabled = Arc::clone(&enabled);
        let resolutions = resolutions.clone();
        Box::pin(async move {
            if let Some(resolutions) = resolutions {
                resolutions.fetch_add(1, Ordering::SeqCst);
            }
            if !enabled.load(Ordering::Acquire) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "consensus test path disabled",
                ));
            }
            address
                .read()
                .map_err(|_| std::io::Error::other("consensus address lock poisoned"))?
                .as_ref()
                .copied()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "consensus server is not listening",
                    )
                })
        })
    })
}

fn delayed_profiled_resolver(
    address: Arc<StdRwLock<Option<SocketAddr>>>,
    delay_enabled: Arc<AtomicBool>,
    delayed_completions: Arc<AtomicUsize>,
) -> RemoteAddrResolver {
    Arc::new(move || {
        let address = Arc::clone(&address);
        let delay_enabled = Arc::clone(&delay_enabled);
        let delayed_completions = Arc::clone(&delayed_completions);
        Box::pin(async move {
            if delay_enabled.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(500)).await;
                delayed_completions.fetch_add(1, Ordering::AcqRel);
            }
            address
                .read()
                .map_err(|_| std::io::Error::other("consensus address lock poisoned"))?
                .as_ref()
                .copied()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "consensus server is not listening",
                    )
                })
        })
    })
}

fn restore_key(label: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::from_static("mtls-restore-tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(label)
            .try_into()
            .expect("valid stable ID"),
    }
}

fn restore_record(
    key: SessionKey,
    lease: &opc_session_store::LeaseGuard,
    payload: &'static [u8],
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("mtls-restore-session"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload),
    }
}

async fn wait_for_ready_nodes(
    stores: &[ConsensusSessionStore],
    nodes: &[usize],
    failure_message: &'static str,
    transport_stats: &BTreeMap<(usize, usize), Arc<TransportStats>>,
) {
    let deadline = tokio::time::Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    let mut attempts = 0_usize;
    loop {
        attempts += 1;
        let reports = futures_util::future::join_all(
            nodes
                .iter()
                .map(|index| stores[*index].probe_durable_readiness()),
        )
        .await;
        if reports.iter().all(|report| report.is_ready()) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{failure_message}: attempts={attempts}, reports={reports:?}, transport={:?}",
            transport_stats
                .iter()
                .map(|(path, stats)| (*path, stats.snapshot()))
                .collect::<BTreeMap<_, _>>()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[derive(Debug, Default)]
struct TransportStats {
    outcomes: StdMutex<BTreeMap<String, usize>>,
}

impl TransportStats {
    fn record(&self, outcome: String) {
        let mut outcomes = self
            .outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *outcomes.entry(outcome).or_default() += 1;
    }

    fn snapshot(&self) -> BTreeMap<String, usize> {
        self.outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn count(&self, outcome: &str) -> usize {
        self.outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(outcome)
            .copied()
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
struct InstrumentedConsensusPeer {
    inner: RemoteSessionConsensusPeer,
    stats: Arc<TransportStats>,
}

impl InstrumentedConsensusPeer {
    fn record_result(
        &self,
        family: &str,
        result: &Result<SessionConsensusWireResponse, SessionConsensusPeerError>,
    ) {
        let status = match result {
            Ok(response) if response.result.is_ok() => "ok",
            Ok(response) => match response.result {
                Err(SessionConsensusPeerError::Unavailable) => "remote_unavailable",
                Err(SessionConsensusPeerError::Timeout) => "remote_timeout",
                Err(SessionConsensusPeerError::Authentication) => "remote_authentication",
                Err(SessionConsensusPeerError::ScopeMismatch) => "remote_scope_mismatch",
                Err(SessionConsensusPeerError::Protocol) => "remote_protocol",
                Err(SessionConsensusPeerError::Rejected) => "remote_rejected",
                Err(_) => "remote_other",
                Ok(_) => "ok",
            },
            Err(SessionConsensusPeerError::Unavailable) => "unavailable",
            Err(SessionConsensusPeerError::Timeout) => "timeout",
            Err(SessionConsensusPeerError::Authentication) => "authentication",
            Err(SessionConsensusPeerError::ScopeMismatch) => "scope_mismatch",
            Err(SessionConsensusPeerError::Protocol) => "protocol",
            Err(SessionConsensusPeerError::Rejected) => "rejected",
            Err(_) => "other",
        };
        self.stats.record(format!("{family}:{status}"));
    }
}

#[async_trait]
impl SessionConsensusPeer for InstrumentedConsensusPeer {
    fn node_id(&self) -> opc_session_store::SessionConsensusNodeId {
        self.inner.node_id()
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let family = request.family.as_str();
        let result = self.inner.call(request).await;
        self.record_result(family, &result);
        result
    }

    async fn call_with_timeout(
        &self,
        request: SessionConsensusWireRequest,
        timeout: Duration,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let family = request.family.as_str();
        let result = self.inner.call_with_timeout(request, timeout).await;
        self.record_result(family, &result);
        result
    }
}

#[derive(Debug)]
struct ProbeDispatchCountingHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
    empty_vote_dispatches: Arc<AtomicUsize>,
}

#[async_trait]
impl SessionConsensusRpcHandler for ProbeDispatchCountingHandler {
    async fn handle(
        &self,
        authenticated_sender: opc_session_store::SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family == SessionConsensusRpcFamily::Vote && request.payload.is_empty() {
            self.empty_vote_dispatches.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

async fn wait_for_observed_leader(
    stats: &BTreeMap<(usize, usize), Arc<TransportStats>>,
    members: usize,
) -> usize {
    let baseline = stats
        .iter()
        .map(|(path, value)| (*path, value.count("append_entries:ok")))
        .collect::<BTreeMap<_, _>>();
    // A fresh observation may begin immediately after the prior heartbeat;
    // keep it within one complete profiled operation rather than the former
    // short-heartbeat assumption.
    let deadline = tokio::time::Instant::now() + DURABLE_CONSENSUS_OPERATION_TIMEOUT;
    loop {
        for source in 0..members {
            let observed_all_targets =
                (0..members)
                    .filter(|target| *target != source)
                    .all(|target| {
                        stats.get(&(source, target)).is_some_and(|value| {
                            value.count("append_entries:ok")
                                > baseline.get(&(source, target)).copied().unwrap_or(0)
                        })
                    });
            if observed_all_targets {
                return source;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no current leader emitted successful heartbeats: {:?}",
            stats
                .iter()
                .map(|(path, value)| (*path, value.snapshot()))
                .collect::<BTreeMap<_, _>>()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn fleet_rotation_lifecycle() -> ConnectionLifecyclePolicy {
    ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_millis(100),
        Duration::from_millis(1),
        Duration::from_millis(20),
        Duration::ZERO,
    )
    .expect("fleet rotation lifecycle policy")
}

fn single_attempt_removed_root_probe_lifecycle() -> ConnectionLifecyclePolicy {
    let cold_connect_timeout = DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_millis(100),
        cold_connect_timeout,
        cold_connect_timeout,
        Duration::ZERO,
    )
    .expect("single-attempt removed-root probe lifecycle policy")
}

struct RotatingNodeMaterial {
    source: tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
    client: AuthenticatedClientConfig,
    server: AuthenticatedServerConfig,
    reauthentication: SessionReauthenticationControl,
}

impl RotatingNodeMaterial {
    fn new(initial: opc_identity::IdentityState) -> Self {
        let (source, receiver) = tokio::sync::watch::channel(Some(initial));
        let client = TlsConfigBuilder::new(receiver.clone())
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("fleet rotation client config");
        let server = TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("fleet rotation server config");
        Self {
            source,
            client,
            server,
            reauthentication: SessionReauthenticationControl::new(),
        }
    }

    async fn publish(&self, state: opc_identity::IdentityState) {
        let client_epoch = self.client.material_status().epoch();
        let server_epoch = self.server.material_status().epoch();
        self.source.send_replace(Some(state));
        wait_for_material_epoch_change(|| self.client.material_status(), client_epoch).await;
        wait_for_material_epoch_change(|| self.server.material_status(), server_epoch).await;
        self.reauthentication
            .request_reauthentication()
            .expect("request fleet member reauthentication");
    }
}

struct RotationCanary {
    key: SessionKey,
    lease: LeaseGuard,
    generation: u64,
}

struct RotatingConsensusFleet {
    _directory: tempfile::TempDir,
    replicas: Vec<u16>,
    manifest: Arc<SessionReplicationManifest>,
    stores: Vec<ConsensusSessionStore>,
    materials: Vec<RotatingNodeMaterial>,
    addresses: Vec<SocketAddr>,
    probes: BTreeMap<(usize, usize), Arc<InstrumentedConsensusPeer>>,
    transport_stats: BTreeMap<(usize, usize), Arc<TransportStats>>,
    resolver_calls: BTreeMap<(usize, usize), Arc<AtomicUsize>>,
    probe_dispatches: Vec<Arc<AtomicUsize>>,
    servers: Vec<opc_session_net::SessionConsensusServerHandle>,
    provider: Arc<MemoryKeyProvider>,
    canary: Option<RotationCanary>,
}

impl RotatingConsensusFleet {
    async fn start(initial_states: Vec<opc_identity::IdentityState>) -> Self {
        let member_count = initial_states.len();
        assert!(matches!(member_count, 3 | 5), "qualification topology");
        let replicas = (1..=member_count)
            .map(|replica| u16::try_from(replica).expect("bounded test replica"))
            .collect::<Vec<_>>();
        let manifest =
            manifest_for_replicas(&format!("mtls-rotation-{member_count}"), 23, 1, &replicas);
        let descriptors = replicas
            .iter()
            .map(|replica| descriptor(*replica, 1))
            .collect::<Vec<_>>();
        let topologies = replicas
            .iter()
            .map(|replica| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    replica_id(*replica),
                    descriptors.clone(),
                    manifest.consensus_identity(),
                ))
                .expect("validated rotation topology")
            })
            .collect::<Vec<_>>();
        let directory = tempfile::tempdir().expect("rotation fleet directory");
        let backends = replicas
            .iter()
            .map(|replica| {
                SqliteSessionBackend::open(
                    directory
                        .path()
                        .join(format!("rotation-replica-{replica}.sqlite")),
                )
                .expect("rotation SQLite backend")
            })
            .collect::<Vec<_>>();
        let address_slots = replicas
            .iter()
            .map(|_| Arc::new(StdRwLock::new(None)))
            .collect::<Vec<_>>();
        let materials = initial_states
            .into_iter()
            .map(RotatingNodeMaterial::new)
            .collect::<Vec<_>>();
        let mut probes = BTreeMap::new();
        let mut transport_stats = BTreeMap::new();
        let mut resolver_calls = BTreeMap::new();
        let mut stores = Vec::with_capacity(member_count);

        for (source, replica) in replicas.iter().copied().enumerate() {
            let local = manifest
                .bind_local(replica_id(replica))
                .expect("rotation local binding");
            let mut peers = BTreeMap::<_, Arc<dyn SessionConsensusPeer>>::new();
            for (target, remote_replica) in replicas.iter().copied().enumerate() {
                if source == target {
                    continue;
                }
                let binding = local
                    .bind_remote(replica_id(remote_replica))
                    .expect("rotation remote binding");
                let node_id = binding.remote_consensus_node_id();
                let resolutions = Arc::new(AtomicUsize::new(0));
                let remote = RemoteSessionConsensusPeer::new_profiled_with_resolver(
                    binding,
                    counted_deferred_resolver(
                        Arc::clone(&address_slots[target]),
                        Arc::new(AtomicBool::new(true)),
                        Arc::clone(&resolutions),
                    ),
                    materials[source].client.clone(),
                )
                .with_connection_lifecycle(fleet_rotation_lifecycle())
                .with_reauthentication_control(materials[source].reauthentication.clone());
                let stats = Arc::new(TransportStats::default());
                let remote = Arc::new(InstrumentedConsensusPeer {
                    inner: remote,
                    stats: Arc::clone(&stats),
                });
                transport_stats.insert((source, target), stats);
                resolver_calls.insert((source, target), resolutions);
                probes.insert((source, target), Arc::clone(&remote));
                peers.insert(node_id, remote);
            }
            stores.push(
                ConsensusSessionStore::open_with_clock(
                    topologies[source].clone(),
                    backends[source].clone(),
                    directory
                        .path()
                        .join(format!("rotation-snapshots-{replica}")),
                    peers,
                    Arc::new(SystemClock),
                    DURABLE_CONSENSUS_OPERATION_TIMEOUT,
                )
                .await
                .expect("open rotation consensus store"),
            );
        }

        let mut servers = Vec::with_capacity(member_count);
        let mut addresses = Vec::with_capacity(member_count);
        let mut probe_dispatches = Vec::with_capacity(member_count);
        for (index, replica) in replicas.iter().copied().enumerate() {
            let binding = manifest
                .bind_local(replica_id(replica))
                .expect("rotation server binding");
            let empty_vote_dispatches = Arc::new(AtomicUsize::new(0));
            let (server, address) = SessionConsensusServer::new(
                Arc::new(ProbeDispatchCountingHandler {
                    inner: stores[index].rpc_handler(),
                    empty_vote_dispatches: Arc::clone(&empty_vote_dispatches),
                }),
                materials[index].server.clone(),
                binding,
            )
            .with_connection_lifecycle(fleet_rotation_lifecycle())
            .with_reauthentication_control(materials[index].reauthentication.clone())
            .listen("127.0.0.1:0".parse().expect("rotation listen address"))
            .await
            .expect("start rotation consensus listener");
            *address_slots[index].write().expect("rotation address lock") = Some(address);
            servers.push(server);
            addresses.push(address);
            probe_dispatches.push(empty_vote_dispatches);
        }

        let provider = Arc::new(MemoryKeyProvider::new());
        provider
            .insert_active_key(
                KeyId::new(format!("mtls-rotation-{member_count}")).expect("rotation key ID"),
                KeyPurpose::Session,
                TenantId::from_static("mtls-rotation-tenant"),
                Zeroizing::new([0x6b; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("install rotation payload key");
        let mut fleet = Self {
            _directory: directory,
            replicas,
            manifest,
            stores,
            materials,
            addresses,
            probes,
            transport_stats,
            resolver_calls,
            probe_dispatches,
            servers,
            provider,
            canary: None,
        };
        fleet.probe_all_paths().await;
        let initialized = futures_util::future::join_all(
            fleet
                .stores
                .iter()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await;
        for result in initialized {
            result.expect("initialize rotation consensus fleet");
        }
        fleet.wait_all_ready().await;
        fleet.seed_canary().await;
        fleet
    }

    async fn wait_all_ready(&self) {
        let nodes = (0..self.stores.len()).collect::<Vec<_>>();
        wait_for_ready_nodes(
            &self.stores,
            &nodes,
            "rotation fleet becomes durably ready",
            &self.transport_stats,
        )
        .await;
    }

    async fn wait_member_ready(&self, member: usize) {
        wait_for_ready_nodes(
            &self.stores,
            &[member],
            "rotated member proves fresh durable readiness",
            &self.transport_stats,
        )
        .await;
    }

    async fn probe_all_paths(&self) {
        self.probe_paths(self.probes.keys().copied().collect())
            .await;
    }

    async fn probe_member_paths(&self, member: usize) {
        self.probe_paths(
            self.probes
                .keys()
                .copied()
                .filter(|(source, target)| *source == member || *target == member)
                .collect(),
        )
        .await;
    }

    async fn probe_paths(&self, paths: Vec<(usize, usize)>) {
        let outcomes = futures_util::future::join_all(paths.into_iter().map(|path| {
            let peer = self.probes.get(&path).expect("rotation probe path");
            let resolver_calls = self
                .resolver_calls
                .get(&path)
                .expect("rotation resolver counter");
            let baseline = resolver_calls.load(Ordering::SeqCst);
            let manifest = Arc::clone(&self.manifest);
            let sender = self.replicas[path.0];
            async move {
                let deadline = tokio::time::Instant::now() + DURABLE_CONSENSUS_OPERATION_TIMEOUT;
                let mut unavailable_attempts = 0usize;
                let outcome = loop {
                    match peer.call(request(&manifest, sender, Vec::new())).await {
                        Ok(response) if resolver_calls.load(Ordering::SeqCst) > baseline => {
                            break Ok(response);
                        }
                        Ok(_) => {}
                        // A remote-only material change cannot be observed by
                        // this client's lifecycle watcher. Cached lanes may
                        // discover peer retirement as EOF, and resolution may
                        // complete before the replacement TLS listener is
                        // ready to finish a handshake. This qualification-only
                        // empty Vote probe is idempotent, so it may retry
                        // availability failures until the absolute deadline;
                        // production RPCs must never transparently replay an
                        // uncertain call.
                        Err(SessionConsensusPeerError::Unavailable) => {
                            unavailable_attempts += 1;
                        }
                        Err(error) => break Err(error),
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break Err(SessionConsensusPeerError::Timeout);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };
                (
                    path,
                    outcome,
                    baseline,
                    resolver_calls.load(Ordering::SeqCst),
                    unavailable_attempts,
                )
            }
        }))
        .await;
        for (path, outcome, baseline, resolutions, unavailable_attempts) in outcomes {
            assert!(
                outcome.is_ok(),
                "fresh bidirectional rotation handshake failed: path={path:?}, outcome={outcome:?}, baseline={baseline}, resolutions={resolutions}, unavailable_attempts={unavailable_attempts}"
            );
            assert!(
                resolutions > baseline,
                "rotation probe did not establish a fresh connection: path={path:?}, baseline={baseline}, resolutions={resolutions}"
            );
        }
    }

    fn leader_index(&self) -> usize {
        let leader = self
            .stores
            .iter()
            .find_map(|store| store.status().leader_id)
            .expect("rotation fleet leader");
        self.stores
            .iter()
            .position(|store| store.status().node_id == leader)
            .expect("leader belongs to rotation fleet")
    }

    fn protected_store(
        &self,
        index: usize,
    ) -> EncryptingSessionBackend<ConsensusSessionStore, MemoryKeyProvider> {
        EncryptingSessionBackend::new(
            Arc::new(self.stores[index].clone()),
            Arc::clone(&self.provider),
            "mtls-fleet-rotation",
        )
    }

    async fn seed_canary(&mut self) {
        let key = SessionKey {
            tenant: TenantId::from_static("mtls-rotation-tenant"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"mtls-rotation-canary")
                .try_into()
                .expect("rotation canary stable ID"),
        };
        let writer = self.protected_store(self.leader_index());
        let lease = writer
            .acquire(
                &key,
                OwnerId::new("mtls-rotation-owner").expect("rotation canary owner"),
                Duration::from_secs(900),
            )
            .await
            .expect("acquire rotation canary lease");
        let result = writer
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: fleet_rotation_record(key.clone(), &lease, 1),
            })
            .await
            .expect("seed rotation canary");
        assert_eq!(result, CompareAndSetResult::Success);
        self.canary = Some(RotationCanary {
            key,
            lease,
            generation: 1,
        });
        self.verify_canary().await;
    }

    async fn advance_canary(&mut self) {
        let canary = self.canary.as_ref().expect("seeded rotation canary");
        let key = canary.key.clone();
        let lease = canary.lease.clone();
        let previous = canary.generation;
        let generation = previous
            .checked_add(1)
            .expect("bounded rotation generation");
        let writer = self.protected_store(self.leader_index());
        let result = writer
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: Some(Generation::new(previous)),
                new_record: fleet_rotation_record(key, &canary.lease, generation),
            })
            .await
            .expect("advance rotation canary");
        assert_eq!(result, CompareAndSetResult::Success);
        self.canary
            .as_mut()
            .expect("seeded rotation canary")
            .generation = generation;
        self.verify_canary().await;
    }

    async fn verify_canary(&self) {
        let canary = self.canary.as_ref().expect("seeded rotation canary");
        for index in 0..self.stores.len() {
            let record = tokio::time::timeout(
                DURABLE_CONSENSUS_OPERATION_TIMEOUT,
                self.protected_store(index).get(&canary.key),
            )
            .await
            .expect("rotation canary read finishes within the transition SLO")
            .expect("linearizable rotation canary read")
            .expect("rotation canary remains present");
            assert_eq!(record.generation, Generation::new(canary.generation));
            assert_eq!(
                record.payload.as_bytes(),
                format!("rotation-generation-{}", canary.generation).as_bytes()
            );
        }
    }

    async fn publish_member(&mut self, member: usize, state: opc_identity::IdentityState) {
        self.materials[member].publish(state).await;
        self.probe_member_paths(member).await;
        self.wait_member_ready(member).await;
    }

    async fn complete_member_phase(&mut self) {
        self.wait_all_ready().await;
        self.advance_canary().await;
    }

    async fn publish_fleet(&mut self, states: Vec<opc_identity::IdentityState>) {
        assert_eq!(states.len(), self.materials.len());
        for (material, state) in self.materials.iter().zip(states) {
            material.publish(state).await;
        }
        self.probe_all_paths().await;
        self.wait_all_ready().await;
        self.advance_canary().await;
    }

    async fn assert_old_client_chains_rejected(
        &self,
        old_states_with_overlap: &[opc_identity::IdentityState],
    ) {
        for (source, state) in old_states_with_overlap.iter().cloned().enumerate() {
            let target = (source + 1) % self.replicas.len();
            let client = TlsConfigBuilder::new(tokio::sync::watch::channel(Some(state)).1)
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("old-chain probe client");
            let binding = self
                .manifest
                .bind_local(replica_id(self.replicas[source]))
                .expect("old-chain local binding")
                .bind_remote(replica_id(self.replicas[target]))
                .expect("old-chain remote binding");
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let resolver_calls_for_probe = Arc::clone(&resolver_calls);
            let target_address = self.addresses[target];
            let resolver: RemoteAddrResolver = Arc::new(move || {
                resolver_calls_for_probe.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(target_address) })
            });
            let peer = RemoteSessionConsensusPeer::new_with_resolver(
                binding,
                resolver,
                client,
                Some(DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout()),
            )
            .with_connection_lifecycle(single_attempt_removed_root_probe_lifecycle());
            let dispatches_before = self.probe_dispatches[target].load(Ordering::SeqCst);
            let outcome = peer
                .call(request(&self.manifest, self.replicas[source], Vec::new()))
                .await;
            assert!(
                matches!(
                    outcome,
                    Err(
                        SessionConsensusPeerError::Authentication
                            | SessionConsensusPeerError::Timeout
                    )
                ),
                "new-only server trust must reject the removed old issuer before application admission: source={source}, target={target}, outcome={outcome:?}"
            );
            assert_eq!(
                resolver_calls.load(Ordering::SeqCst),
                1,
                "the qualification-only removed-root probe must make exactly one connection attempt"
            );
            assert_eq!(
                self.probe_dispatches[target].load(Ordering::SeqCst),
                dispatches_before,
                "an old-root client must not reach the post-authentication consensus handler"
            );
        }
    }

    async fn assert_old_server_chain_rejected(
        &self,
        source: usize,
        target: usize,
        old_target_state_with_overlap: opc_identity::IdentityState,
    ) {
        let server_config = TlsConfigBuilder::new(
            tokio::sync::watch::channel(Some(old_target_state_with_overlap)).1,
        )
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("old-chain probe server");
        let binding = self
            .manifest
            .bind_local(replica_id(self.replicas[target]))
            .expect("old-chain probe server binding");
        let probe_dispatches = Arc::new(AtomicUsize::new(0));
        let (server, address) = SessionConsensusServer::new(
            Arc::new(ProbeDispatchCountingHandler {
                inner: self.stores[target].rpc_handler(),
                empty_vote_dispatches: Arc::clone(&probe_dispatches),
            }),
            server_config,
            binding,
        )
        .listen("127.0.0.1:0".parse().expect("old-chain probe address"))
        .await
        .expect("old-chain probe listener");
        let current_client = self.materials[source].client.clone();
        let peer = RemoteSessionConsensusPeer::new_with_resolver(
            self.manifest
                .bind_local(replica_id(self.replicas[source]))
                .expect("current client binding")
                .bind_remote(replica_id(self.replicas[target]))
                .expect("old probe server binding"),
            resolver(address),
            current_client,
            Some(Duration::from_secs(1)),
        );
        assert_eq!(
            peer.call(request(&self.manifest, self.replicas[source], Vec::new()))
                .await,
            Err(SessionConsensusPeerError::Authentication),
            "new-only client trust must reject a server chain under the removed old issuer"
        );
        assert_eq!(
            probe_dispatches.load(Ordering::SeqCst),
            0,
            "an old-root server must not reach the post-authentication consensus handler"
        );
        server.abort_and_wait().await;
    }

    async fn finish(self) {
        for server in self.servers {
            server.abort_and_wait().await;
        }
    }
}

fn fleet_rotation_record(
    key: SessionKey,
    lease: &LeaseGuard,
    generation: u64,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("mtls-fleet-rotation"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(
            format!("rotation-generation-{generation}").into_bytes(),
        ),
    }
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

#[derive(Debug)]
struct UnavailableHandler;

#[async_trait]
impl SessionConsensusRpcHandler for UnavailableHandler {
    async fn handle(
        &self,
        _authenticated_sender: opc_session_store::SessionConsensusNodeId,
        _request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        SessionConsensusWireResponse {
            result: Err(SessionConsensusPeerError::Unavailable),
        }
    }
}

#[derive(Debug, Default)]
struct CountingEchoHandler {
    calls: AtomicUsize,
}

#[async_trait]
impl SessionConsensusRpcHandler for CountingEchoHandler {
    async fn handle(
        &self,
        _authenticated_sender: opc_session_store::SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

#[derive(Debug, Default)]
struct LifecycleEchoHandler {
    calls: AtomicUsize,
    first_started: tokio::sync::Notify,
    first_release: tokio::sync::Notify,
    authenticated_senders: StdMutex<Vec<opc_session_store::SessionConsensusNodeId>>,
}

#[async_trait]
impl SessionConsensusRpcHandler for LifecycleEchoHandler {
    async fn handle(
        &self,
        authenticated_sender: opc_session_store::SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.authenticated_senders
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(authenticated_sender);
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            self.first_started.notify_one();
            self.first_release.notified().await;
        }
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

#[derive(Debug)]
struct StallEveryCallHandler {
    calls: AtomicUsize,
    started: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}

impl Default for StallEveryCallHandler {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for StallEveryCallHandler {
    async fn handle(
        &self,
        _authenticated_sender: opc_session_store::SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        self.release
            .acquire()
            .await
            .expect("test release semaphore remains open")
            .forget();
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

#[derive(Debug)]
struct SelectiveStallHandler {
    calls: AtomicUsize,
    cancelled_started: tokio::sync::Notify,
    cancelled_release: tokio::sync::Semaphore,
    primary_hold_started: tokio::sync::Notify,
    primary_hold_release: tokio::sync::Semaphore,
}

impl Default for SelectiveStallHandler {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            cancelled_started: tokio::sync::Notify::new(),
            cancelled_release: tokio::sync::Semaphore::new(0),
            primary_hold_started: tokio::sync::Notify::new(),
            primary_hold_release: tokio::sync::Semaphore::new(0),
        }
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for SelectiveStallHandler {
    async fn handle(
        &self,
        _authenticated_sender: opc_session_store::SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match request.payload.as_slice() {
            b"cancel-primary" => {
                self.cancelled_started.notify_one();
                self.cancelled_release
                    .acquire()
                    .await
                    .expect("test release semaphore remains open")
                    .forget();
            }
            b"hold-primary" => {
                self.primary_hold_started.notify_one();
                self.primary_hold_release
                    .acquire()
                    .await
                    .expect("test release semaphore remains open")
                    .forget();
            }
            _ => {}
        }
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

#[derive(Debug)]
struct PairBarrierHandler {
    calls: AtomicUsize,
    barrier: tokio::sync::Barrier,
}

impl PairBarrierHandler {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            barrier: tokio::sync::Barrier::new(2),
        }
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for PairBarrierHandler {
    async fn handle(
        &self,
        _authenticated_sender: opc_session_store::SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.barrier.wait().await;
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

async fn wait_for_handler_calls(
    calls: &AtomicUsize,
    started: &tokio::sync::Notify,
    expected: usize,
) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while calls.load(Ordering::SeqCst) < expected {
            started.notified().await;
        }
    })
    .await
    .expect("expected consensus handler calls");
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
    request_for_family(manifest, sender, SessionConsensusRpcFamily::Vote, payload)
}

fn request_for_family(
    manifest: &Arc<SessionReplicationManifest>,
    sender: u16,
    family: SessionConsensusRpcFamily,
    payload: Vec<u8>,
) -> SessionConsensusWireRequest {
    let binding = manifest
        .bind_local(replica_id(sender))
        .expect("sender binding");
    SessionConsensusWireRequest::try_new(
        binding.consensus_identity(),
        binding.local_consensus_node_id(),
        family,
        payload,
    )
    .expect("bounded request")
}

async fn assert_consensus_call_pair(
    peer: &RemoteSessionConsensusPeer,
    manifest: &Arc<SessionReplicationManifest>,
    first_payload: &'static [u8],
    second_payload: &'static [u8],
) {
    let first = peer.call(request_for_family(
        manifest,
        1,
        SessionConsensusRpcFamily::AppendEntries,
        first_payload.to_vec(),
    ));
    let second = peer.call(request_for_family(
        manifest,
        1,
        SessionConsensusRpcFamily::AppendEntries,
        second_payload.to_vec(),
    ));
    let (first, second) = tokio::join!(first, second);
    assert_eq!(
        first,
        Ok(SessionConsensusWireResponse {
            result: Ok(first_payload.to_vec()),
        })
    );
    assert_eq!(
        second,
        Ok(SessionConsensusWireResponse {
            result: Ok(second_payload.to_vec()),
        })
    );
}

type ConsensusCallTask =
    tokio::task::JoinHandle<Result<SessionConsensusWireResponse, SessionConsensusPeerError>>;

fn spawn_consensus_call_pair(
    peer: &RemoteSessionConsensusPeer,
    manifest: &Arc<SessionReplicationManifest>,
    first_payload: &'static [u8],
    second_payload: &'static [u8],
) -> (ConsensusCallTask, ConsensusCallTask) {
    let spawn = |payload: &'static [u8]| {
        let peer = peer.clone();
        let request = request_for_family(
            manifest,
            1,
            SessionConsensusRpcFamily::AppendEntries,
            payload.to_vec(),
        );
        tokio::spawn(async move { peer.call(request).await })
    };
    (spawn(first_payload), spawn(second_payload))
}

async fn assert_consensus_call_tasks(
    first: tokio::task::JoinHandle<Result<SessionConsensusWireResponse, SessionConsensusPeerError>>,
    second: tokio::task::JoinHandle<
        Result<SessionConsensusWireResponse, SessionConsensusPeerError>,
    >,
    first_payload: &'static [u8],
    second_payload: &'static [u8],
) {
    assert_eq!(
        first.await.expect("first consensus call join"),
        Ok(SessionConsensusWireResponse {
            result: Ok(first_payload.to_vec()),
        })
    );
    assert_eq!(
        second.await.expect("second consensus call join"),
        Ok(SessionConsensusWireResponse {
            result: Ok(second_payload.to_vec()),
        })
    );
}

#[tokio::test]
async fn authenticated_consensus_calls_reuse_the_primary_pool_lane() {
    let pki = TestPki::new();
    let manifest = manifest("cluster-a", 7, 1);
    let (handle, addr) = start_server(&pki, &manifest, Duration::ZERO).await;
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("local binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        counted_resolver,
        pki.client_config(1),
        Some(Duration::from_secs(1)),
    );
    let port: Arc<dyn SessionConsensusPeer> = Arc::new(peer.clone());

    let expected_server_node = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding")
        .local_consensus_node_id();
    assert_eq!(port.node_id(), expected_server_node);
    assert_ne!(port.node_id().get(), 0);
    for payload in [b"bounded-vote-one".as_slice(), b"bounded-vote-two"] {
        assert_eq!(
            port.call(request(&manifest, 1, payload.to_vec())).await,
            Ok(SessionConsensusWireResponse {
                result: Ok(payload.to_vec()),
            })
        );
    }
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        1,
        "sequential validated RPCs must reuse the primary resolver/TCP/mTLS/bootstrap path"
    );

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn stalled_append_entries_uses_the_overflow_pool_lane() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-overflow-lane", 7, 1);
    let handler = Arc::new(LifecycleEchoHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), pki.server_config(SERVER_REPLICA), binding)
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("consensus overflow listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("server binding"),
        counted_resolver,
        pki.client_config(1),
        Some(Duration::from_secs(2)),
    );

    let primary = tokio::spawn({
        let peer = peer.clone();
        let request = request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::AppendEntries,
            b"stalled-primary".to_vec(),
        );
        async move { peer.call(request).await }
    });
    tokio::time::timeout(Duration::from_secs(1), handler.first_started.notified())
        .await
        .expect("primary AppendEntries entered handler");

    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(1),
            peer.call(request_for_family(
                &manifest,
                1,
                SessionConsensusRpcFamily::AppendEntries,
                b"overflow-completes".to_vec(),
            )),
        )
        .await
        .expect("overflow AppendEntries completed before primary release"),
        Ok(SessionConsensusWireResponse {
            result: Ok(b"overflow-completes".to_vec()),
        })
    );
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);

    handler.first_release.notify_one();
    assert_eq!(
        primary.await.expect("primary call join"),
        Ok(SessionConsensusWireResponse {
            result: Ok(b"stalled-primary".to_vec()),
        })
    );
    server.abort_and_wait().await;
}

#[tokio::test]
async fn two_stalled_pool_lanes_bound_a_third_call_before_dispatch() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-two-lane-bound", 7, 1);
    let handler = Arc::new(StallEveryCallHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), pki.server_config(SERVER_REPLICA), binding)
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("consensus two-lane listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("server binding"),
        counted_resolver,
        pki.client_config(1),
    );
    let stalled_call = |payload: &'static [u8]| {
        let peer = peer.clone();
        let request = request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::Vote,
            payload.to_vec(),
        );
        tokio::spawn(async move { peer.call(request).await })
    };
    let primary = stalled_call(b"stalled-primary");
    let overflow = stalled_call(b"stalled-overflow");
    wait_for_handler_calls(&handler.calls, &handler.started, 2).await;
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);

    assert_eq!(
        peer.call(request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::AppendEntries,
            b"must-not-dispatch".to_vec(),
        ))
        .await,
        Err(SessionConsensusPeerError::Timeout)
    );
    assert_eq!(handler.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "waiting for a bounded lane must not resolve or open a third connection"
    );

    handler.release.add_permits(2);
    assert!(primary.await.expect("primary call join").is_ok());
    assert!(overflow.await.expect("overflow call join").is_ok());
    server.abort_and_wait().await;
}

#[tokio::test]
async fn cancelling_a_queued_lane_waiter_does_not_lose_released_capacity() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-cancelled-lane-waiter", 7, 1);
    let handler = Arc::new(StallEveryCallHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), pki.server_config(SERVER_REPLICA), binding)
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("cancelled lane waiter listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("server binding"),
        counted_resolver,
        pki.client_config(1),
    );
    let stalled_call = |payload: &'static [u8]| {
        let peer = peer.clone();
        let request = request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::Vote,
            payload.to_vec(),
        );
        tokio::spawn(async move { peer.call(request).await })
    };
    let mut first = stalled_call(b"first-occupied-lane");
    let mut second = stalled_call(b"second-occupied-lane");
    wait_for_handler_calls(&handler.calls, &handler.started, 2).await;
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);

    let waiter_queued = Arc::new(tokio::sync::Notify::new());
    let queued = tokio::spawn({
        let peer = peer.clone();
        let manifest = Arc::clone(&manifest);
        let waiter_queued = Arc::clone(&waiter_queued);
        async move {
            let mut call = Box::pin(peer.call(request_for_family(
                &manifest,
                1,
                SessionConsensusRpcFamily::Vote,
                b"cancelled-while-queued".to_vec(),
            )));
            futures_util::future::poll_fn(|context| {
                match std::future::Future::poll(call.as_mut(), context) {
                    std::task::Poll::Pending => std::task::Poll::Ready(()),
                    std::task::Poll::Ready(outcome) => {
                        panic!("queued waiter completed before a lane was available: {outcome:?}")
                    }
                }
            })
            .await;
            waiter_queued.notify_one();
            call.await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), waiter_queued.notified())
        .await
        .expect("third call entered the lane wait queue");
    assert_eq!(handler.calls.load(Ordering::SeqCst), 2);
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    queued.abort();
    assert!(queued
        .await
        .expect_err("queued waiter must be cancelled")
        .is_cancelled());

    handler.release.add_permits(1);
    let first_finished = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::select! {
            outcome = &mut first => {
                assert_eq!(outcome.expect("first lane join"), Ok(SessionConsensusWireResponse {
                    result: Ok(b"first-occupied-lane".to_vec()),
                }));
                true
            }
            outcome = &mut second => {
                assert_eq!(outcome.expect("second lane join"), Ok(SessionConsensusWireResponse {
                    result: Ok(b"second-occupied-lane".to_vec()),
                }));
                false
            }
        }
    })
    .await
    .expect("exactly one occupied lane was released");

    let recovered = tokio::spawn({
        let peer = peer.clone();
        let request = request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::Vote,
            b"after-queued-cancellation".to_vec(),
        );
        async move { peer.call(request).await }
    });
    wait_for_handler_calls(&handler.calls, &handler.started, 3).await;
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "the recovered call must reuse the released lane without opening a third socket"
    );

    handler.release.add_permits(2);
    assert_eq!(
        recovered.await.expect("recovered call join"),
        Ok(SessionConsensusWireResponse {
            result: Ok(b"after-queued-cancellation".to_vec()),
        })
    );
    if first_finished {
        assert_eq!(
            second.await.expect("remaining second lane join"),
            Ok(SessionConsensusWireResponse {
                result: Ok(b"second-occupied-lane".to_vec()),
            })
        );
    } else {
        assert_eq!(
            first.await.expect("remaining first lane join"),
            Ok(SessionConsensusWireResponse {
                result: Ok(b"first-occupied-lane".to_vec()),
            })
        );
    }
    assert_eq!(handler.calls.load(Ordering::SeqCst), 3);
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    server.abort_and_wait().await;
}

#[tokio::test]
async fn profiled_cold_connection_is_a_contained_fifteen_hundred_millisecond_bound() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-profiled-cold-bound", 8, 1);
    let handler = Arc::new(CountingEchoHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), pki.server_config(SERVER_REPLICA), binding)
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("profiled cold-bound listener");

    let delayed_resolver = |delay: Duration| -> RemoteAddrResolver {
        Arc::new(move || {
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(addr)
            })
        })
    };
    let remote_binding = || {
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding")
    };
    let within_bound = RemoteSessionConsensusPeer::new_profiled_with_resolver(
        remote_binding(),
        delayed_resolver(Duration::from_millis(500)),
        pki.client_config(1),
    );
    let payload = b"within-cold-bound".to_vec();
    assert_eq!(
        within_bound
            .call(request_for_family(
                &manifest,
                1,
                SessionConsensusRpcFamily::AppendEntries,
                payload.clone(),
            ))
            .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(payload),
        })
    );

    let beyond_bound = RemoteSessionConsensusPeer::new_profiled_with_resolver(
        remote_binding(),
        delayed_resolver(Duration::from_millis(1_600)),
        pki.client_config(1),
    );
    assert_eq!(
        beyond_bound
            .call(request_for_family(
                &manifest,
                1,
                SessionConsensusRpcFamily::AppendEntries,
                b"must-not-dispatch".to_vec(),
            ))
            .await,
        Err(SessionConsensusPeerError::Timeout)
    );
    assert_eq!(
        handler.calls.load(Ordering::SeqCst),
        1,
        "work beyond the cold sub-bound must fail before handler dispatch"
    );

    server.abort_and_wait().await;
}

#[tokio::test]
async fn append_soft_ttl_reserves_post_handshake_rpc_time_and_reuses_the_socket() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-append-soft-reserve", 18, 1);
    let handler = Arc::new(CountingEchoHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), pki.server_config(SERVER_REPLICA), binding)
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("profiled soft-reserve listener");

    let resolutions = Arc::new(AtomicUsize::new(0));
    let delayed_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                // Eighty percent of the derived one-second cold allocation is
                // consumed before TCP, mTLS, and bootstrap. The remaining
                // overall soft TTL must still carry the negotiated RPC.
                tokio::time::sleep(Duration::from_millis(800)).await;
                Ok(addr)
            })
        })
    };
    let remote_binding = manifest
        .bind_local(replica_id(1))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
        remote_binding,
        delayed_resolver,
        pki.client_config(1),
    );
    let soft_ttl = Duration::from_millis(1_500);

    for payload in [b"near-cold-cap".to_vec(), b"cached-follow-up".to_vec()] {
        assert_eq!(
            peer.call_with_timeout(
                request_for_family(
                    &manifest,
                    1,
                    SessionConsensusRpcFamily::AppendEntries,
                    payload.clone(),
                ),
                soft_ttl,
            )
            .await,
            Ok(SessionConsensusWireResponse {
                result: Ok(payload),
            })
        );
    }
    assert_eq!(handler.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        1,
        "the validated first response must return the authenticated socket to its lane"
    );

    let too_late_resolver: RemoteAddrResolver = Arc::new(move || {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            Ok(addr)
        })
    });
    let too_late_peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("late client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("late remote binding"),
        too_late_resolver,
        pki.client_config(1),
    );
    assert_eq!(
        too_late_peer
            .call_with_timeout(
                request_for_family(
                    &manifest,
                    1,
                    SessionConsensusRpcFamily::AppendEntries,
                    b"reserved-for-rpc".to_vec(),
                ),
                soft_ttl,
            )
            .await,
        Err(SessionConsensusPeerError::Timeout)
    );
    assert_eq!(
        handler.calls.load(Ordering::SeqCst),
        2,
        "cold work beyond its proportional allocation must not consume the negotiated RPC reserve"
    );

    server.abort_and_wait().await;
}

#[tokio::test]
async fn profiled_long_rpc_families_are_not_truncated_by_the_append_deadline() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-profiled-family-deadlines", 9, 1);
    let (server, addr) = start_server(&pki, &manifest, Duration::from_millis(2_100)).await;
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        counted_resolver,
        pki.client_config(1),
    );

    assert_eq!(
        peer.call(request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::AppendEntries,
            b"append-times-out".to_vec(),
        ))
        .await,
        Err(SessionConsensusPeerError::Timeout)
    );
    for family in [
        SessionConsensusRpcFamily::Vote,
        SessionConsensusRpcFamily::InstallSnapshot,
        SessionConsensusRpcFamily::ForwardMutation,
        SessionConsensusRpcFamily::ReadBarrier,
    ] {
        let payload = family.as_str().as_bytes().to_vec();
        assert_eq!(
            peer.call(request_for_family(&manifest, 1, family, payload.clone(),))
                .await,
            Ok(SessionConsensusWireResponse {
                result: Ok(payload),
            }),
            "{family:?} must retain its family deadline above two seconds"
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            2,
            "{family:?} unexpectedly replaced the authenticated connection"
        );
    }
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "the timed-out AppendEntries socket is replaced once and longer families reuse it"
    );

    server.abort_and_wait().await;
}

#[tokio::test]
async fn consensus_reauthentication_and_material_epochs_replace_both_cached_lanes() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-cached-rotation", 8, 1);
    let handler = Arc::new(PairBarrierHandler::new());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (handle, addr) =
        SessionConsensusServer::new(handler.clone(), pki.server_config(SERVER_REPLICA), binding)
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("rotating two-lane consensus listener");
    let (client_tx, client_rx) = tokio::sync::watch::channel(Some(pki.identity_state(1)));
    let client_config = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("rotating consensus client config");
    // This case verifies that both lanes are replaced by each epoch. Cached
    // jitter is covered separately with paused time; keep it at zero here so
    // the replacement assertion has no wall-clock sampling race.
    let immediate_rotation = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_secs(2),
        Duration::from_millis(1),
        Duration::from_millis(20),
        Duration::ZERO,
    )
    .expect("immediate rotation lifecycle");
    let reauthentication = SessionReauthenticationControl::new();
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("server binding"),
        counted_resolver,
        client_config.clone(),
        Some(Duration::from_secs(2)),
    )
    .with_connection_lifecycle(immediate_rotation)
    .with_reauthentication_control(reauthentication.clone());

    assert_consensus_call_pair(&peer, &manifest, b"initial-primary", b"initial-overflow").await;
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);

    reauthentication
        .request_reauthentication()
        .expect("request explicit consensus reauthentication");
    assert_consensus_call_pair(&peer, &manifest, b"explicit-primary", b"explicit-overflow").await;
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        4,
        "one explicit generation change must replace both established lanes"
    );

    let previous_epoch = client_config.material_status().epoch();
    client_tx.send_replace(Some(pki.identity_state(1)));
    wait_for_material_epoch_change(|| client_config.material_status(), previous_epoch).await;
    assert_consensus_call_pair(&peer, &manifest, b"material-primary", b"material-overflow").await;
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        6,
        "one admitted material epoch change must replace both established lanes"
    );
    assert_eq!(handler.calls.load(Ordering::SeqCst), 6);

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn both_consensus_lanes_rotate_across_real_mtls_trust_cutover() {
    let manifest = manifest("consensus-two-lane-trust-cutover", 8, 1);
    let old_root = RotationRoot::new("two-lane old");
    let new_root = RotationRoot::new("two-lane new");
    let old_intermediate = old_root.issue_intermediate("two-lane old");
    let new_intermediate = new_root.issue_intermediate("two-lane new");
    let old_client_leaf = old_intermediate.issue_leaf(1);
    let old_server_leaf = old_intermediate.issue_leaf(SERVER_REPLICA);
    let new_client_leaf = new_intermediate.issue_leaf(1);
    let new_server_leaf = new_intermediate.issue_leaf(SERVER_REPLICA);
    let old_only = [&old_root];
    let overlap = [&old_root, &new_root];
    let new_only = [&new_root];

    let old_client_with_overlap = old_client_leaf.identity_state(&old_intermediate, &overlap);
    let old_server_with_overlap = old_server_leaf.identity_state(&old_intermediate, &overlap);
    let client_material =
        RotatingNodeMaterial::new(old_client_leaf.identity_state(&old_intermediate, &old_only));
    let server_material =
        RotatingNodeMaterial::new(old_server_leaf.identity_state(&old_intermediate, &old_only));
    let lifecycle = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_secs(2),
        Duration::from_millis(1),
        Duration::from_millis(20),
        Duration::ZERO,
    )
    .expect("two-lane rotation lifecycle policy");
    let handler = Arc::new(StallEveryCallHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), server_material.server.clone(), binding)
            .with_connection_lifecycle(lifecycle)
            .with_reauthentication_control(server_material.reauthentication.clone())
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("two-lane trust cutover listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let remote_binding = manifest
        .bind_local(replica_id(1))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        remote_binding.clone(),
        counted_resolver,
        client_material.client.clone(),
        Some(Duration::from_secs(2)),
    )
    .with_connection_lifecycle(lifecycle)
    .with_reauthentication_control(client_material.reauthentication.clone());

    let (old_primary, old_overflow) =
        spawn_consensus_call_pair(&peer, &manifest, b"old-primary", b"old-overflow");
    wait_for_handler_calls(&handler.calls, &handler.started, 2).await;
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);

    tokio::join!(
        client_material.publish(old_client_with_overlap.clone()),
        server_material.publish(old_server_with_overlap.clone()),
    );
    handler.release.add_permits(2);
    assert_consensus_call_tasks(old_primary, old_overflow, b"old-primary", b"old-overflow").await;

    let (overlap_old_primary, overlap_old_overflow) = spawn_consensus_call_pair(
        &peer,
        &manifest,
        b"overlap-old-primary",
        b"overlap-old-overflow",
    );
    wait_for_handler_calls(&handler.calls, &handler.started, 4).await;
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        4,
        "adding overlap trust must retire and replace both old-only lanes"
    );
    handler.release.add_permits(2);
    assert_consensus_call_tasks(
        overlap_old_primary,
        overlap_old_overflow,
        b"overlap-old-primary",
        b"overlap-old-overflow",
    )
    .await;

    tokio::join!(
        client_material.publish(new_client_leaf.identity_state(&new_intermediate, &overlap)),
        server_material.publish(new_server_leaf.identity_state(&new_intermediate, &overlap)),
    );
    let (new_chain_primary, new_chain_overflow) = spawn_consensus_call_pair(
        &peer,
        &manifest,
        b"new-chain-primary",
        b"new-chain-overflow",
    );
    wait_for_handler_calls(&handler.calls, &handler.started, 6).await;
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        6,
        "both replacement lanes must authenticate the new chain during overlap"
    );
    handler.release.add_permits(2);
    assert_consensus_call_tasks(
        new_chain_primary,
        new_chain_overflow,
        b"new-chain-primary",
        b"new-chain-overflow",
    )
    .await;

    tokio::join!(
        client_material.publish(new_client_leaf.identity_state(&new_intermediate, &new_only)),
        server_material.publish(new_server_leaf.identity_state(&new_intermediate, &new_only)),
    );
    let (new_only_primary, new_only_overflow) =
        spawn_consensus_call_pair(&peer, &manifest, b"new-only-primary", b"new-only-overflow");
    wait_for_handler_calls(&handler.calls, &handler.started, 8).await;
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        8,
        "both lanes must remain available after old trust is removed"
    );
    handler.release.add_permits(2);
    assert_consensus_call_tasks(
        new_only_primary,
        new_only_overflow,
        b"new-only-primary",
        b"new-only-overflow",
    )
    .await;
    assert_eq!(handler.calls.load(Ordering::SeqCst), 8);

    let old_client_config =
        TlsConfigBuilder::new(tokio::sync::watch::channel(Some(old_client_with_overlap)).1)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("old-chain probe client");
    let old_client_resolutions = Arc::new(AtomicUsize::new(0));
    let old_client_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&old_client_resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let old_client_peer = RemoteSessionConsensusPeer::new_with_resolver(
        remote_binding.clone(),
        old_client_resolver,
        old_client_config,
        Some(Duration::from_secs(1)),
    )
    .with_connection_lifecycle(single_attempt_removed_root_probe_lifecycle());
    let dispatches_before = handler.calls.load(Ordering::SeqCst);
    let old_client_outcome = old_client_peer
        .call(request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::Vote,
            b"removed-old-client-chain".to_vec(),
        ))
        .await;
    assert!(
        matches!(
            old_client_outcome,
            Err(SessionConsensusPeerError::Authentication | SessionConsensusPeerError::Timeout)
        ),
        "new-only server trust must reject the removed old client chain: {old_client_outcome:?}"
    );
    assert_eq!(old_client_resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(
        handler.calls.load(Ordering::SeqCst),
        dispatches_before,
        "the removed old client chain must fail before consensus dispatch"
    );

    let old_server_config =
        TlsConfigBuilder::new(tokio::sync::watch::channel(Some(old_server_with_overlap)).1)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("old-chain probe server");
    let old_server_handler = Arc::new(CountingEchoHandler::default());
    let (old_server, old_server_addr) = SessionConsensusServer::new(
        old_server_handler.clone(),
        old_server_config,
        manifest
            .bind_local(replica_id(SERVER_REPLICA))
            .expect("old-chain server binding"),
    )
    .listen("127.0.0.1:0".parse().expect("old-chain listen address"))
    .await
    .expect("old-chain probe listener");
    let old_server_peer = RemoteSessionConsensusPeer::new_with_resolver(
        remote_binding,
        resolver(old_server_addr),
        client_material.client.clone(),
        Some(Duration::from_secs(1)),
    );
    assert_eq!(
        old_server_peer
            .call(request_for_family(
                &manifest,
                1,
                SessionConsensusRpcFamily::Vote,
                b"removed-old-server-chain".to_vec(),
            ))
            .await,
        Err(SessionConsensusPeerError::Authentication),
        "new-only client trust must reject the removed old server chain"
    );
    assert_eq!(
        old_server_handler.calls.load(Ordering::SeqCst),
        0,
        "the removed old server chain must fail before consensus dispatch"
    );

    old_server.abort_and_wait().await;
    server.abort_and_wait().await;
}

#[tokio::test]
async fn cancelled_consensus_lane_is_replaced_without_evicting_the_other_lane() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-cancelled-call", 9, 1);
    let handler = Arc::new(SelectiveStallHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), pki.server_config(SERVER_REPLICA), binding)
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("consensus cancellation listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        counted_resolver,
        pki.client_config(1),
        Some(Duration::from_secs(2)),
    );

    let cancelled = tokio::spawn({
        let peer = peer.clone();
        let request = request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::AppendEntries,
            b"cancel-primary".to_vec(),
        );
        async move { peer.call(request).await }
    });
    tokio::time::timeout(Duration::from_secs(1), handler.cancelled_started.notified())
        .await
        .expect("cancelled call entered the handler");

    assert_eq!(
        peer.call(request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::AppendEntries,
            b"establish-overflow".to_vec(),
        ))
        .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"establish-overflow".to_vec()),
        })
    );
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);

    cancelled.abort();
    assert!(cancelled
        .await
        .expect_err("cancelled task join")
        .is_cancelled());

    assert_eq!(
        peer.call(request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::AppendEntries,
            b"replace-primary".to_vec(),
        ))
        .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"replace-primary".to_vec()),
        })
    );
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        3,
        "only the cancelled primary lane must perform a replacement handshake"
    );

    let held_primary = tokio::spawn({
        let peer = peer.clone();
        let request = request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::AppendEntries,
            b"hold-primary".to_vec(),
        );
        async move { peer.call(request).await }
    });
    tokio::time::timeout(
        Duration::from_secs(1),
        handler.primary_hold_started.notified(),
    )
    .await
    .expect("replacement primary entered handler");
    assert_eq!(
        peer.call(request_for_family(
            &manifest,
            1,
            SessionConsensusRpcFamily::AppendEntries,
            b"reuse-overflow".to_vec(),
        ))
        .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"reuse-overflow".to_vec()),
        })
    );
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        3,
        "the unaffected overflow lane must remain reusable without reconnect"
    );

    handler.primary_hold_release.add_permits(1);
    assert!(held_primary.await.expect("held primary join").is_ok());
    handler.cancelled_release.add_permits(1);
    assert_eq!(handler.calls.load(Ordering::SeqCst), 5);
    server.abort_and_wait().await;
}

#[tokio::test]
async fn timed_out_consensus_rpc_drops_its_connection_before_the_next_call() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-timeout-call", 10, 1);
    let handler = Arc::new(LifecycleEchoHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), pki.server_config(SERVER_REPLICA), binding)
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("consensus timeout listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        counted_resolver,
        pki.client_config(1),
        Some(Duration::from_millis(500)),
    );

    assert_eq!(
        peer.call(request(&manifest, 1, b"times-out".to_vec()))
            .await,
        Err(SessionConsensusPeerError::Timeout)
    );
    assert_eq!(
        peer.call(request(&manifest, 1, b"after-timeout".to_vec()))
            .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"after-timeout".to_vec()),
        })
    );
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "a timed-out response cannot leave a reusable stream with an unknown frame position"
    );
    handler.first_release.notify_one();
    server.abort_and_wait().await;
}

#[tokio::test]
async fn typed_inner_consensus_timeout_is_returned_but_its_connection_is_not_reused() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-inner-timeout", 10, 1);
    let handler = Arc::new(LifecycleEchoHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), pki.server_config(SERVER_REPLICA), binding)
            .with_rpc_timeout(Duration::from_millis(25))
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("consensus inner-timeout listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        counted_resolver,
        pki.client_config(1),
        Some(Duration::from_secs(1)),
    );

    assert_eq!(
        peer.call(request(&manifest, 1, b"inner-timeout".to_vec()))
            .await,
        Ok(SessionConsensusWireResponse {
            result: Err(SessionConsensusPeerError::Timeout),
        })
    );
    assert_eq!(
        peer.call(request(&manifest, 1, b"after-inner-timeout".to_vec()))
            .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"after-inner-timeout".to_vec()),
        })
    );
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "a fully decoded inner timeout still forces one fresh authenticated connection"
    );
    handler.first_release.notify_one();
    server.abort_and_wait().await;
}

#[tokio::test]
async fn cached_dead_consensus_socket_is_evicted_before_a_fresh_reconnect() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-cached-dead-socket", 11, 1);
    let server_binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) = SessionConsensusServer::new(
        Arc::new(EchoHandler {
            delay: Duration::ZERO,
        }),
        pki.server_config(SERVER_REPLICA),
        server_binding,
    )
    .listen("127.0.0.1:0".parse().expect("listen address"))
    .await
    .expect("initial consensus listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        counted_resolver,
        pki.client_config(1),
        Some(Duration::from_secs(1)),
    );

    assert!(peer
        .call(request(&manifest, 1, b"cache-before-restart".to_vec()))
        .await
        .is_ok());
    assert_eq!(resolutions.load(Ordering::SeqCst), 1);
    server.abort_and_wait().await;

    let replacement_binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("replacement server binding");
    let (replacement, replacement_addr) = SessionConsensusServer::new(
        Arc::new(EchoHandler {
            delay: Duration::ZERO,
        }),
        pki.server_config(SERVER_REPLICA),
        replacement_binding,
    )
    .listen(addr)
    .await
    .expect("replacement consensus listener");
    assert_eq!(replacement_addr, addr);

    assert_eq!(
        peer.call(request(&manifest, 1, b"stale-socket".to_vec()))
            .await,
        Err(SessionConsensusPeerError::Unavailable),
        "the first post-restart call discovers the cached socket's EOF without replay"
    );
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        1,
        "discovering EOF on the cached socket must not hide an in-call replay"
    );
    assert_eq!(
        peer.call(request(&manifest, 1, b"fresh-after-restart".to_vec()))
            .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"fresh-after-restart".to_vec()),
        })
    );
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "the next Openraft retry must perform one fresh resolver/TCP/mTLS/bootstrap path"
    );

    replacement.abort_and_wait().await;
}

#[tokio::test]
async fn cached_consensus_connection_retires_at_the_finite_soft_lifecycle_bound() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-cached-lifetime", 12, 1);
    let client_policy = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(30),
        Duration::from_secs(10),
        Duration::from_millis(5),
        Duration::from_millis(20),
        Duration::ZERO,
    )
    .expect("client lifecycle policy");
    let server_policy = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(120),
        Duration::from_secs(2),
        Duration::from_millis(5),
        Duration::from_millis(20),
        Duration::ZERO,
    )
    .expect("server lifecycle policy");
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) = SessionConsensusServer::new(
        Arc::new(EchoHandler {
            delay: Duration::ZERO,
        }),
        pki.server_config(SERVER_REPLICA),
        binding,
    )
    .with_connection_lifecycle(server_policy)
    .listen("127.0.0.1:0".parse().expect("listen address"))
    .await
    .expect("consensus lifecycle listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        counted_resolver,
        pki.client_config(1),
        Some(Duration::from_secs(2)),
    )
    .with_connection_lifecycle(client_policy);

    assert!(peer
        .call(request(&manifest, 1, b"before-soft-bound".to_vec()))
        .await
        .is_ok());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(21)).await;
    tokio::time::resume();
    assert!(peer
        .call(request(&manifest, 1, b"after-soft-bound".to_vec()))
        .await
        .is_ok());
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "soft retirement must evict the cached connection before dispatch"
    );
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::time::resume();
    assert!(peer
        .call(request(&manifest, 1, b"after-old-hard-bound".to_vec()))
        .await
        .is_ok());
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "the replacement remains the only cached connection after the original hard bound"
    );

    server.abort_and_wait().await;
}

#[tokio::test]
async fn correlated_unavailable_response_reuses_the_authenticated_connection() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-correlated-unavailable", 12, 1);
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) = SessionConsensusServer::new(
        Arc::new(UnavailableHandler),
        pki.server_config(SERVER_REPLICA),
        binding,
    )
    .listen("127.0.0.1:0".parse().expect("listen address"))
    .await
    .expect("consensus unavailable listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted_resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        counted_resolver,
        pki.client_config(1),
        Some(Duration::from_secs(2)),
    );

    for payload in [b"first".as_slice(), b"second".as_slice()] {
        assert_eq!(
            peer.call(request(&manifest, 1, payload.to_vec())).await,
            Ok(SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Unavailable),
            })
        );
    }
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        1,
        "a complete correlated Unavailable response must not create a TLS reconnect storm"
    );

    server.abort_and_wait().await;
}

#[tokio::test]
async fn consensus_inflight_rpc_drains_and_reauthenticates_on_renewed_material() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-lifecycle", 11, 1);
    let (client_tx, client_rx) = tokio::sync::watch::channel(Some(pki.identity_state(1)));
    let (server_tx, server_rx) =
        tokio::sync::watch::channel(Some(pki.identity_state(SERVER_REPLICA)));
    let client_config = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("rotating consensus client config");
    let server_config = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("rotating consensus server config");
    let lifecycle = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_secs(2),
        Duration::from_millis(5),
        Duration::from_millis(20),
        Duration::ZERO,
    )
    .expect("consensus lifecycle policy");
    let reauthentication = SessionReauthenticationControl::new();
    let handler = Arc::new(LifecycleEchoHandler::default());
    let binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("server binding");
    let (server, addr) =
        SessionConsensusServer::new(handler.clone(), server_config.clone(), binding)
            .with_max_connections(1)
            .with_connection_lifecycle(lifecycle)
            .with_reauthentication_control(reauthentication.clone())
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("consensus lifecycle listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let lifecycle_resolver: RemoteAddrResolver = {
        let resolutions = resolutions.clone();
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(addr) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .expect("client binding")
            .bind_remote(replica_id(SERVER_REPLICA))
            .expect("remote binding"),
        lifecycle_resolver,
        client_config.clone(),
        Some(Duration::from_secs(3)),
    )
    .with_connection_lifecycle(lifecycle)
    .with_reauthentication_control(reauthentication.clone());

    let first = tokio::spawn({
        let peer = peer.clone();
        let request = request(&manifest, 1, b"inflight-before-rotation".to_vec());
        async move { peer.call(request).await }
    });
    tokio::time::timeout(Duration::from_secs(1), handler.first_started.notified())
        .await
        .expect("first consensus RPC must enter the handler");

    let client_epoch = client_config.material_status().epoch();
    let server_epoch = server_config.material_status().epoch();
    client_tx.send_replace(Some(pki.identity_state(1)));
    server_tx.send_replace(Some(pki.identity_state(SERVER_REPLICA)));
    wait_for_material_epoch_change(|| client_config.material_status(), client_epoch).await;
    wait_for_material_epoch_change(|| server_config.material_status(), server_epoch).await;
    reauthentication
        .request_reauthentication()
        .expect("retire the admitted consensus connection");
    handler.first_release.notify_one();

    assert_eq!(
        first.await.expect("first consensus call join"),
        Ok(SessionConsensusWireResponse {
            result: Ok(b"inflight-before-rotation".to_vec()),
        }),
        "an RPC admitted before soft retirement must complete once inside the drain"
    );
    assert_eq!(
        peer.call(request(
            &manifest,
            1,
            b"replacement-after-rotation".to_vec(),
        ))
        .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"replacement-after-rotation".to_vec()),
        }),
        "the sole server slot must be released and the replacement must repeat mTLS and exact bootstrap admission"
    );
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    assert_eq!(handler.calls.load(Ordering::SeqCst), 2);
    let expected_sender = manifest
        .bind_local(replica_id(1))
        .expect("sender binding")
        .local_consensus_node_id();
    assert_eq!(
        *handler
            .authenticated_senders
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![expected_sender, expected_sender],
        "both Vote RPCs must reach Openraft only after exact authenticated sender admission"
    );

    server.abort_and_wait().await;
}

async fn config_openraft_forms_and_commits_over_the_shared_mtls_adapter_case() {
    const REPLICAS: [u16; 3] = [1, 2, 3];

    let pki = TestPki::new();
    let manifest = manifest("config-openraft-mtls", 9, 1);
    let directory = tempfile::tempdir().expect("config cluster directory");
    let addresses = (0..3)
        .map(|_| Arc::new(StdRwLock::new(None)))
        .collect::<Vec<_>>();
    let node_ids = REPLICAS.map(|replica| {
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
    let mut path_delay_enabled = BTreeMap::new();
    let mut path_delayed_completions = BTreeMap::new();
    for source in 0..REPLICAS.len() {
        for target in 0..REPLICAS.len() {
            if source != target {
                path_delay_enabled.insert((source, target), Arc::new(AtomicBool::new(false)));
                path_delayed_completions.insert((source, target), Arc::new(AtomicUsize::new(0)));
            }
        }
    }

    let mut stores = Vec::new();
    for (source, source_replica) in REPLICAS.into_iter().enumerate() {
        let local = manifest
            .bind_local(replica_id(source_replica))
            .expect("source binding");
        let mut peers: BTreeMap<_, Arc<dyn SessionConsensusPeer>> = BTreeMap::new();
        for (target, target_replica) in REPLICAS.into_iter().enumerate() {
            if source == target {
                continue;
            }
            let binding = local
                .clone()
                .bind_remote(replica_id(target_replica))
                .expect("remote binding");
            let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
                binding,
                delayed_profiled_resolver(
                    Arc::clone(&addresses[target]),
                    Arc::clone(
                        path_delay_enabled
                            .get(&(source, target))
                            .expect("directed delay control"),
                    ),
                    Arc::clone(
                        path_delayed_completions
                            .get(&(source, target))
                            .expect("directed delayed completion count"),
                    ),
                ),
                pki.client_config(source_replica),
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
                DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            )
            .await
            .expect("config store"),
        );
    }

    let mut servers = Vec::new();
    for (index, replica) in REPLICAS.into_iter().enumerate() {
        let binding = manifest
            .bind_local(replica_id(replica))
            .expect("server binding");
        let (handle, actual) = SessionConsensusServer::new(
            stores[index].rpc_handler(),
            pki.server_config(replica),
            binding,
        )
        .listen("127.0.0.1:0".parse().expect("listen address"))
        .await
        .expect("config consensus listener");
        *addresses[index].write().expect("consensus address lock") = Some(actual);
        servers.push(Some(handle));
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

    let stable_statuses = tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        loop {
            let statuses = stores
                .iter()
                .map(ConsensusConfigStore::status)
                .collect::<Vec<_>>();
            let applied = statuses[0].applied_index;
            if applied.is_some()
                && statuses
                    .iter()
                    .all(|status| status.applied_index == applied)
            {
                break statuses;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("all mTLS peers converge before follower listener restart");
    let original_term = stable_statuses[0].term;
    assert!(original_term > 0, "formed cluster must have a nonzero term");
    assert!(stable_statuses
        .iter()
        .all(|status| status.term == original_term && status.leader_id == Some(leader)));
    let leader_index = stable_statuses
        .iter()
        .position(|status| status.node_id == leader)
        .expect("leader index");
    let follower_index = stable_statuses
        .iter()
        .position(|status| status.node_id != leader)
        .expect("restart follower index");
    let follower_applied_before_restart = stable_statuses[follower_index]
        .applied_index
        .expect("follower applied index before restart");

    // Bind the replacement first so listener restart has no bind race. The
    // address remains unpublished while the old listener is stopped and a
    // quorum command commits without this follower.
    let replacement_listener = tokio::net::TcpListener::bind(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("replacement bind address"),
    )
    .await
    .expect("pre-bind replacement follower listener");
    let replacement_addr = replacement_listener
        .local_addr()
        .expect("replacement listener address");
    servers[follower_index]
        .take()
        .expect("running follower listener")
        .abort_and_wait()
        .await;
    *addresses[follower_index]
        .write()
        .expect("consensus address lock") = None;

    let down_follower_error = tokio::time::timeout(
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
        stores[leader_index].mark_confirmed_idempotent(
            ConfigConsensusRequestId::from_bytes([0xBD; 16]),
            opc_types::TxId::new(),
        ),
    )
    .await
    .expect("quorum command must finish while one follower listener is down")
    .expect_err("committed missing target returns deterministic domain error");
    assert!(matches!(
        down_follower_error.kind(),
        PersistErrorKind::RollbackNotFound
    ));
    let catchup_index = tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        loop {
            let leader_applied = stores[leader_index].status().applied_index;
            let follower_applied = stores[follower_index].status().applied_index;
            if let Some(index) = leader_applied.filter(|index| {
                *index > follower_applied_before_restart
                    && follower_applied.is_some_and(|follower| follower < *index)
            }) {
                break index;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("stopped follower remains behind the newly committed index");

    let restarted_path = (leader_index, follower_index);
    path_delay_enabled
        .get(&restarted_path)
        .expect("leader-to-restarted-follower delay control")
        .store(true, Ordering::Release);
    let restarted_replica = REPLICAS[follower_index];
    let (replacement_server, actual_replacement_addr) = SessionConsensusServer::new(
        stores[follower_index].rpc_handler(),
        pki.server_config(restarted_replica),
        manifest
            .bind_local(replica_id(restarted_replica))
            .expect("replacement follower binding"),
    )
    .listen_on(replacement_listener)
    .await
    .expect("restart follower listener");
    assert_eq!(actual_replacement_addr, replacement_addr);
    servers[follower_index] = Some(replacement_server);
    *addresses[follower_index]
        .write()
        .expect("consensus address lock") = Some(actual_replacement_addr);

    // No raw peer preflight is allowed here. Openraft must evict the dead
    // cached socket, resolve after the injected 500 ms cold delay, and repair
    // the follower through its normal replication stream under the same
    // leader and term.
    tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        loop {
            let statuses = stores
                .iter()
                .map(ConsensusConfigStore::status)
                .collect::<Vec<_>>();
            if path_delayed_completions
                .get(&restarted_path)
                .expect("leader-to-follower delayed completion count")
                .load(Ordering::Acquire)
                > 0
                && statuses[follower_index]
                    .applied_index
                    .is_some_and(|index| index >= catchup_index)
                && statuses
                    .iter()
                    .all(|status| status.term == original_term && status.leader_id == Some(leader))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        stores[follower_index]
            .probe_durable_readiness()
            .await
            .expect("restarted follower durable readiness");
        assert!(stores[follower_index]
            .load_latest()
            .await
            .expect("restarted follower linearizable read")
            .is_none());
    })
    .await
    .expect("restarted follower catches up and becomes ready within ten seconds");

    let final_statuses = stores
        .iter()
        .map(ConsensusConfigStore::status)
        .collect::<Vec<_>>();
    assert!(final_statuses.iter().all(|status| {
        status.term == original_term
            && status.leader_id == Some(leader)
            && status
                .applied_index
                .is_some_and(|index| index >= catchup_index)
    }));

    let _ = tokio::join!(
        stores[0].shutdown(),
        stores[1].shutdown(),
        stores[2].shutdown(),
    );
    for server in servers.into_iter().flatten() {
        server.abort_and_wait().await;
    }
}

#[test]
fn config_openraft_forms_and_commits_over_the_shared_mtls_adapter() {
    run_openraft_fleet_test(
        4,
        config_openraft_forms_and_commits_over_the_shared_mtls_adapter_case(),
    );
}

async fn real_mtls_openraft_sqlite_boot_restore_and_live_survivor_scan_case() {
    const REPLICAS: [u16; 3] = [1, 2, 3];
    const CONSENSUS_TIMEOUT: Duration = Duration::from_secs(3);

    let pki = TestPki::new();
    let manifest = manifest("mtls-openraft-restore", 17, 1);
    let descriptors = REPLICAS
        .iter()
        .map(|replica| descriptor(*replica, 1))
        .collect::<Vec<_>>();
    let topologies = REPLICAS
        .iter()
        .map(|replica| {
            ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                replica_id(*replica),
                descriptors.clone(),
                manifest.consensus_identity(),
            ))
            .expect("validated mTLS consensus topology")
        })
        .collect::<Vec<_>>();
    let directory = tempfile::tempdir().expect("mTLS consensus directory");
    let backends = REPLICAS
        .iter()
        .map(|replica| {
            SqliteSessionBackend::open(directory.path().join(format!("replica-{replica}.sqlite")))
                .expect("file-backed SQLite replica")
        })
        .collect::<Vec<_>>();
    let addresses = REPLICAS
        .iter()
        .map(|_| Arc::new(StdRwLock::new(None)))
        .collect::<Vec<_>>();
    let mut path_enabled = BTreeMap::new();
    let mut transport_stats = BTreeMap::new();
    let mut probe_peers = BTreeMap::new();
    for source in 0..REPLICAS.len() {
        for target in 0..REPLICAS.len() {
            if source != target {
                path_enabled.insert((source, target), Arc::new(AtomicBool::new(true)));
            }
        }
    }

    let mut stores = Vec::with_capacity(REPLICAS.len());
    for (source, replica) in REPLICAS.iter().copied().enumerate() {
        let local = manifest
            .bind_local(replica_id(replica))
            .expect("local consensus binding");
        let mut peers = BTreeMap::<_, Arc<dyn SessionConsensusPeer>>::new();
        for (target, remote_replica) in REPLICAS.iter().copied().enumerate() {
            if source == target {
                continue;
            }
            let binding = local
                .bind_remote(replica_id(remote_replica))
                .expect("remote consensus binding");
            let node_id = binding.remote_consensus_node_id();
            let remote = RemoteSessionConsensusPeer::new_with_resolver(
                binding,
                deferred_resolver(
                    Arc::clone(&addresses[target]),
                    Arc::clone(
                        path_enabled
                            .get(&(source, target))
                            .expect("consensus path flag"),
                    ),
                ),
                pki.client_config(replica),
                Some(CONSENSUS_TIMEOUT),
            );
            let stats = Arc::new(TransportStats::default());
            let remote = Arc::new(InstrumentedConsensusPeer {
                inner: remote,
                stats: Arc::clone(&stats),
            });
            transport_stats.insert((source, target), stats);
            probe_peers.insert((source, target), Arc::clone(&remote));
            peers.insert(node_id, remote);
        }
        stores.push(
            ConsensusSessionStore::open_with_clock(
                topologies[source].clone(),
                backends[source].clone(),
                directory.path().join(format!("snapshots-{replica}")),
                peers,
                Arc::new(SystemClock),
                CONSENSUS_TIMEOUT,
            )
            .await
            .expect("open mTLS consensus store"),
        );
    }

    let mut servers = Vec::with_capacity(REPLICAS.len());
    for (index, replica) in REPLICAS.iter().copied().enumerate() {
        let binding = manifest
            .bind_local(replica_id(replica))
            .expect("server consensus binding");
        let (server, address) = SessionConsensusServer::new(
            stores[index].rpc_handler(),
            pki.server_config(replica),
            binding,
        )
        .listen("127.0.0.1:0".parse().expect("listen address"))
        .await
        .expect("start mTLS consensus listener");
        *addresses[index].write().expect("consensus address lock") = Some(address);
        servers.push(Some(server));
    }

    // Prove every directional resolver/TCP/mTLS/manifest path is executable
    // before starting election timers. The deliberately empty Vote payload is
    // rejected by the engine codec only after the authenticated transport has
    // completed its full request/response exchange.
    let transport_probes =
        futures_util::future::join_all(probe_peers.iter().map(|((source, target), peer)| {
            let manifest = Arc::clone(&manifest);
            async move {
                (
                    (*source, *target),
                    peer.call(request(&manifest, REPLICAS[*source], Vec::new()))
                        .await,
                )
            }
        }))
        .await;
    for (path, result) in transport_probes {
        assert!(
            result.is_ok(),
            "directional mTLS consensus preflight failed: path={path:?}, result={result:?}"
        );
    }

    let initialized = futures_util::future::join_all(
        stores.iter().map(ConsensusSessionStore::initialize_cluster),
    )
    .await;
    for result in initialized {
        result.expect("initialize real mTLS Openraft fleet");
    }
    wait_for_ready_nodes(
        &stores,
        &[0, 1, 2],
        "initial mTLS consensus fleet becomes durably ready",
        &transport_stats,
    )
    .await;
    let leader = wait_for_observed_leader(&transport_stats, REPLICAS.len()).await;

    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("mtls-restore-key").expect("key ID"),
            KeyPurpose::Session,
            TenantId::from_static("mtls-restore-tenant"),
            Zeroizing::new([0x5a; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("install restore key");
    let writer = EncryptingSessionBackend::new(
        Arc::new(stores[leader].clone()),
        Arc::clone(&provider),
        "mtls-openraft-restore",
    );
    for (label, payload) in [
        (b"restore-a".as_slice(), b"boot-state-a".as_slice()),
        (b"restore-b".as_slice(), b"boot-state-b".as_slice()),
    ] {
        let key = restore_key(label);
        let lease = writer
            .acquire(
                &key,
                OwnerId::new("mtls-restore-owner").expect("owner"),
                Duration::from_secs(30),
            )
            .await
            .expect("acquire restore lease through mTLS Openraft");
        assert_eq!(
            writer
                .compare_and_set(CompareAndSet {
                    key: key.clone(),
                    lease: lease.clone(),
                    expected_generation: None,
                    new_record: restore_record(key, &lease, payload),
                })
                .await
                .expect("commit restore state through mTLS Openraft"),
            CompareAndSetResult::Success
        );
    }

    let restore_reader = (0..REPLICAS.len())
        .find(|candidate| *candidate != leader)
        .expect("three-node fleet has a follower reader");
    let reader = EncryptingSessionBackend::new(
        Arc::new(stores[restore_reader].clone()),
        Arc::clone(&provider),
        "mtls-openraft-restore",
    );
    let first_request = RestoreScanRequest::all(1);
    let first = reader
        .scan_restore_records(first_request.clone())
        .await
        .expect("boot restore first page through real mTLS Openraft");
    first
        .validate_for_request(&first_request)
        .expect("boot restore first-page contract");
    assert_eq!(first.records[0].payload.as_bytes(), b"boot-state-a");
    let second_request = RestoreScanRequest {
        cursor: first.next_cursor,
        ..first_request
    };
    let second = reader
        .scan_restore_records(second_request.clone())
        .await
        .expect("boot restore continuation through real mTLS Openraft");
    second
        .validate_for_request(&second_request)
        .expect("boot restore continuation contract");
    assert_eq!(second.records[0].payload.as_bytes(), b"boot-state-b");
    assert!(second.complete);

    // #133 qualifies bounded applied-state restore while one voter is absent;
    // leader-loss/election qualification belongs to #143. Select a follower
    // from observed successful heartbeats so this test does not randomly
    // become an unrelated two-survivor election-liveness campaign.
    let isolated = (0..REPLICAS.len())
        .find(|candidate| *candidate != leader)
        .expect("three-node fleet has a follower");
    let survivors = (0..REPLICAS.len())
        .filter(|candidate| *candidate != isolated)
        .collect::<Vec<_>>();
    for ((source, target), enabled) in &path_enabled {
        if *source == isolated || *target == isolated {
            enabled.store(false, Ordering::Release);
        }
    }
    servers[isolated]
        .take()
        .expect("isolated follower consensus server")
        .abort_and_wait()
        .await;
    wait_for_ready_nodes(
        &stores,
        &survivors,
        "surviving mTLS consensus majority becomes durably ready",
        &transport_stats,
    )
    .await;

    let survivor = EncryptingSessionBackend::new(
        Arc::new(stores[leader].clone()),
        provider,
        "mtls-openraft-restore",
    );
    let adoption_request = RestoreScanRequest::all(16);
    let adoption = survivor
        .scan_restore_records(adoption_request.clone())
        .await
        .expect("live-survivor adoption scan through remaining mTLS quorum");
    adoption
        .validate_for_request(&adoption_request)
        .expect("live-survivor restore contract");
    assert_eq!(adoption.records.len(), 2);
    assert!(adoption.complete);

    for server in servers.into_iter().flatten() {
        server.abort_and_wait().await;
    }
}

#[test]
fn real_mtls_openraft_sqlite_boot_restore_and_live_survivor_scan() {
    run_openraft_fleet_test(
        4,
        real_mtls_openraft_sqlite_boot_restore_and_live_survivor_scan_case(),
    );
}

fn fleet_identity_states(
    leaves: &[RotationLeaf],
    intermediate: &RotationIntermediate,
    trust_roots: &[&RotationRoot],
) -> Vec<opc_identity::IdentityState> {
    leaves
        .iter()
        .map(|leaf| leaf.identity_state(intermediate, trust_roots))
        .collect()
}

async fn qualify_mtls_fleet_rotation(member_count: usize) {
    let replicas = (1..=member_count)
        .map(|replica| u16::try_from(replica).expect("bounded test replica"))
        .collect::<Vec<_>>();
    let old_root = RotationRoot::new(&format!("{member_count}-member old"));
    let new_root = RotationRoot::new(&format!("{member_count}-member new"));
    let old_intermediate = old_root.issue_intermediate("old");
    let rotated_intermediate = old_root.issue_intermediate("rotated");
    let new_intermediate = new_root.issue_intermediate("new");
    let initial_leaves = replicas
        .iter()
        .map(|replica| old_intermediate.issue_leaf(*replica))
        .collect::<Vec<_>>();
    let renewed_leaves = replicas
        .iter()
        .map(|replica| old_intermediate.issue_leaf(*replica))
        .collect::<Vec<_>>();
    let rotated_intermediate_leaves = replicas
        .iter()
        .map(|replica| rotated_intermediate.issue_leaf(*replica))
        .collect::<Vec<_>>();
    let new_root_leaves = replicas
        .iter()
        .map(|replica| new_intermediate.issue_leaf(*replica))
        .collect::<Vec<_>>();
    let old_only = [&old_root];
    let overlap = [&old_root, &new_root];
    let new_only = [&new_root];
    let initial_states = fleet_identity_states(&initial_leaves, &old_intermediate, &old_only);
    let mut fleet = RotatingConsensusFleet::start(initial_states).await;

    // Add the new root without changing any leaf or presented intermediate.
    fleet
        .publish_fleet(fleet_identity_states(
            &initial_leaves,
            &old_intermediate,
            &overlap,
        ))
        .await;

    // Renew only the leaf/key on one member at a time under the old chain.
    for (member, leaf) in renewed_leaves.iter().enumerate() {
        fleet
            .publish_member(member, leaf.identity_state(&old_intermediate, &overlap))
            .await;
    }
    fleet.complete_member_phase().await;

    // Roll the presented intermediate one member at a time, then exercise an
    // exact pre-cutover rollback to the prior leaf/intermediate material.
    for (member, leaf) in rotated_intermediate_leaves.iter().enumerate() {
        fleet
            .publish_member(member, leaf.identity_state(&rotated_intermediate, &overlap))
            .await;
    }
    fleet.complete_member_phase().await;
    for (member, leaf) in renewed_leaves.iter().enumerate() {
        fleet
            .publish_member(member, leaf.identity_state(&old_intermediate, &overlap))
            .await;
    }
    fleet.complete_member_phase().await;

    // Move every member to the new root, roll back before old-root removal,
    // then move forward again. Every member transition is followed by fresh
    // full handshakes in both directions and a durable-readiness probe from the
    // changed voter. Each completed phase advances an acknowledged encrypted
    // canary and linearizably reads it from every voter.
    for (member, leaf) in new_root_leaves.iter().enumerate() {
        fleet
            .publish_member(member, leaf.identity_state(&new_intermediate, &overlap))
            .await;
    }
    fleet.complete_member_phase().await;
    for (member, leaf) in renewed_leaves.iter().enumerate() {
        fleet
            .publish_member(member, leaf.identity_state(&old_intermediate, &overlap))
            .await;
    }
    fleet.complete_member_phase().await;
    for (member, leaf) in new_root_leaves.iter().enumerate() {
        fleet
            .publish_member(member, leaf.identity_state(&new_intermediate, &overlap))
            .await;
    }
    fleet.complete_member_phase().await;

    // Remove old trust without changing the new material, then prove both TLS
    // directions reject chains that still depend on the removed root.
    fleet
        .publish_fleet(fleet_identity_states(
            &new_root_leaves,
            &new_intermediate,
            &new_only,
        ))
        .await;
    let old_states_with_overlap =
        fleet_identity_states(&renewed_leaves, &old_intermediate, &overlap);
    fleet
        .assert_old_client_chains_rejected(&old_states_with_overlap)
        .await;
    fleet
        .assert_old_server_chain_rejected(0, 1, old_states_with_overlap[1].clone())
        .await;

    // The only safe post-removal rollback first restores overlap everywhere.
    // Roll every member back, prove it, and then execute the forward cutover a
    // final time so the test exits in the intended new-only trust state.
    fleet
        .publish_fleet(fleet_identity_states(
            &new_root_leaves,
            &new_intermediate,
            &overlap,
        ))
        .await;
    for (member, state) in old_states_with_overlap.iter().cloned().enumerate() {
        fleet.publish_member(member, state).await;
    }
    fleet.complete_member_phase().await;
    for (member, leaf) in new_root_leaves.iter().enumerate() {
        fleet
            .publish_member(member, leaf.identity_state(&new_intermediate, &overlap))
            .await;
    }
    fleet.complete_member_phase().await;
    fleet
        .publish_fleet(fleet_identity_states(
            &new_root_leaves,
            &new_intermediate,
            &new_only,
        ))
        .await;

    assert_eq!(
        fleet
            .canary
            .as_ref()
            .expect("qualified rotation canary")
            .generation,
        13,
        "every fleet-wide and member-rotation phase must durably advance the canary exactly once"
    );
    fleet.finish().await;
}

#[test]
fn three_member_openraft_fleet_rotates_and_rolls_back_real_mtls() {
    run_openraft_fleet_test(8, qualify_mtls_fleet_rotation(3));
}

#[test]
fn five_member_openraft_fleet_rotates_and_rolls_back_real_mtls() {
    run_openraft_fleet_test(8, qualify_mtls_fleet_rotation(5));
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
