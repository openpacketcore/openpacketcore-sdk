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
        let status = match &result {
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
                let mut unavailable_seen = false;
                let outcome = loop {
                    match peer.call(request(&manifest, sender, Vec::new())).await {
                        Ok(response) if resolver_calls.load(Ordering::SeqCst) > baseline => {
                            break Ok(response);
                        }
                        Ok(_) => {}
                        Err(SessionConsensusPeerError::Unavailable) if !unavailable_seen => {
                            unavailable_seen = true;
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
                    unavailable_seen,
                )
            }
        }))
        .await;
        for (path, outcome, baseline, resolutions, unavailable_seen) in outcomes {
            assert!(
                outcome.is_ok(),
                "fresh bidirectional rotation handshake failed: path={path:?}, outcome={outcome:?}, baseline={baseline}, resolutions={resolutions}, unavailable_seen={unavailable_seen}"
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

#[tokio::test]
async fn authenticated_consensus_calls_reuse_one_manifest_bound_connection() {
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
        "the second validated RPC must reuse the sole resolver/TCP/mTLS/bootstrap path"
    );

    handle.abort_and_wait().await;
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
    }
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "the timed-out AppendEntries socket is replaced once and longer families reuse it"
    );

    server.abort_and_wait().await;
}

#[tokio::test]
async fn consensus_reauthentication_and_material_epochs_each_replace_the_cached_connection_once() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-cached-rotation", 8, 1);
    let (handle, addr) = start_server(&pki, &manifest, Duration::ZERO).await;
    let (client_tx, client_rx) = tokio::sync::watch::channel(Some(pki.identity_state(1)));
    let client_config = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("rotating consensus client config");
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
    .with_reauthentication_control(reauthentication.clone());

    for payload in [b"initial".as_slice(), b"initial-reuse"] {
        assert_eq!(
            peer.call(request(&manifest, 1, payload.to_vec())).await,
            Ok(SessionConsensusWireResponse {
                result: Ok(payload.to_vec()),
            })
        );
    }
    assert_eq!(resolutions.load(Ordering::SeqCst), 1);

    reauthentication
        .request_reauthentication()
        .expect("request explicit consensus reauthentication");
    for payload in [b"after-explicit".as_slice(), b"explicit-reuse"] {
        assert_eq!(
            peer.call(request(&manifest, 1, payload.to_vec())).await,
            Ok(SessionConsensusWireResponse {
                result: Ok(payload.to_vec()),
            })
        );
    }
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "one explicit generation change must create exactly one replacement"
    );

    let previous_epoch = client_config.material_status().epoch();
    client_tx.send_replace(Some(pki.identity_state(1)));
    wait_for_material_epoch_change(|| client_config.material_status(), previous_epoch).await;
    for payload in [b"after-material".as_slice(), b"material-reuse"] {
        assert_eq!(
            peer.call(request(&manifest, 1, payload.to_vec())).await,
            Ok(SessionConsensusWireResponse {
                result: Ok(payload.to_vec()),
            })
        );
    }
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        3,
        "one admitted material epoch change must create exactly one replacement"
    );

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn cancelled_consensus_rpc_drops_its_taken_connection_before_the_next_call() {
    let pki = TestPki::new();
    let manifest = manifest("consensus-cancelled-call", 9, 1);
    let handler = Arc::new(LifecycleEchoHandler::default());
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
        let request = request(&manifest, 1, b"cancelled".to_vec());
        async move { peer.call(request).await }
    });
    tokio::time::timeout(Duration::from_secs(1), handler.first_started.notified())
        .await
        .expect("cancelled call entered the handler");
    cancelled.abort();
    assert!(cancelled
        .await
        .expect_err("cancelled task join")
        .is_cancelled());

    assert_eq!(
        peer.call(request(&manifest, 1, b"after-cancel".to_vec()))
            .await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"after-cancel".to_vec()),
        })
    );
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "a cancelled in-flight RPC must not return its ambiguous socket to the slot"
    );
    handler.first_release.notify_one();
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
