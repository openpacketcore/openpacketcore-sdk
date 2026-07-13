use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
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
    CompareAndSet, CompareAndSetResult, ConsensusSessionStore, EncryptedSessionPayload,
    EncryptingSessionBackend, Generation, OwnerId, QuorumReplicaDescriptor, QuorumTopologyConfig,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    RestoreScanRequest, SessionBackend, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler, SessionConsensusWireRequest,
    SessionConsensusWireResponse, SessionKey, SessionKeyType, SessionLeaseManager,
    SqliteSessionBackend, StateClass, StateType, StoredSessionRecord, SystemClock,
    ValidatedQuorumTopology, SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
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

fn deferred_resolver(
    address: Arc<StdRwLock<Option<SocketAddr>>>,
    enabled: Arc<AtomicBool>,
) -> RemoteAddrResolver {
    Arc::new(move || {
        let address = Arc::clone(&address);
        let enabled = Arc::clone(&enabled);
        Box::pin(async move {
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

fn restore_key(label: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::from_static("mtls-restore-tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(label),
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
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

async fn wait_for_observed_leader(
    stats: &BTreeMap<(usize, usize), Arc<TransportStats>>,
    members: usize,
) -> usize {
    let baseline = stats
        .iter()
        .map(|(path, value)| (*path, value.count("append_entries:ok")))
        .collect::<BTreeMap<_, _>>();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
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
        .map(|_| Arc::new(StdRwLock::new(None)))
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
                deferred_resolver(
                    Arc::clone(&addresses[target]),
                    Arc::new(AtomicBool::new(true)),
                ),
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
        .listen("127.0.0.1:0".parse().expect("listen address"))
        .await
        .expect("config consensus listener");
        *addresses[index].write().expect("consensus address lock") = Some(actual);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_mtls_openraft_sqlite_boot_restore_and_live_survivor_scan() {
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
