use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    DURABLE_CONSENSUS_TIMING_PROFILE,
};
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider,
    KeyPurpose, MemoryKeyProvider, SessionAad, Zeroizing, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, ConsensusSessionStore, DurableReadinessReport,
    DurableReadinessScope, DurableReadinessState, DurableRecoveryState, EncryptedSessionPayload,
    EncryptingSessionBackend, Generation, LeaseError, ObservedPhysicalNodeIdentity, OwnerId,
    QuorumReplicaDescriptor, QuorumTopologyAttestor, QuorumTopologyConfig, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, ReplicationOp,
    RestoreScanRequest, SessionBackend, SessionConsensusNodeId, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRpcFamily, SessionConsensusRpcHandler,
    SessionConsensusWireRequest, SessionConsensusWireResponse, SessionKey, SessionKeyType,
    SessionLeaseManager, SessionOp, SessionPayloadEncoding, SessionStorePlatformProfile,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord, SystemClock,
    TopologyAttestationClaims, TopologyAttestationEvidence, TopologyAttestationPolicy,
    TopologyAttestationProvenance, TopologyAttestationResult, TopologyAttestationTime,
    TopologyAttestationVerificationError, TopologyAttestationVerificationInput,
    TopologyCollectorId, ValidatedQuorumTopology, VerifiedQuorumTopologyAttestation,
    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};
use opc_types::{NetworkFunctionKind, TenantId};
use rusqlite::OptionalExtension;
use tempfile::TempDir;

const MEMBER_COUNT: usize = 3;
const OPERATION_TIMEOUT: Duration = Duration::from_millis(750);
// Allow one complete resampled election after a split vote, followed by one
// complete profiled operation. These test-evidence ceilings follow the shared
// timing authority instead of assuming the former short election window.
const RECOVERY_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);
const CLUSTER_START_TIMEOUT: Duration = RECOVERY_TIMEOUT;
const SNAPSHOT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOT_CATCH_UP_COMMANDS: usize = 4_300;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_CAPTURED_CONSENSUS_PAYLOADS: usize = 4_096;
// Keep the bounded election qualification from competing with the deliberately
// expensive snapshot-compaction qualification under the parallel test harness.
static ELECTION_AND_SNAPSHOT_TEST_PERMIT: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(1);
const ENCRYPTION_NAMESPACE: &str = "consensus-boundary-qualification";
const PLAINTEXT_CANARY_BEFORE_ROTATION: &[u8] =
    b"opc-session-consensus-plaintext-canary-before-key-rotation";
const PLAINTEXT_CANARY_AFTER_ROTATION: &[u8] =
    b"opc-session-consensus-plaintext-canary-after-key-rotation";
const RAW_KEY_MATERIAL_CANARY: &[u8; AES_256_GCM_SIV_KEY_LEN] = &[0x5a; AES_256_GCM_SIV_KEY_LEN];

#[derive(Clone)]
struct LoopbackPeer {
    target: SessionConsensusNodeId,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
    forward_responses_to_drop: Arc<AtomicUsize>,
    dropped_forward_responses: Arc<AtomicUsize>,
    forward_response_delay_millis: Arc<AtomicU64>,
    delayed_forward_responses: Arc<AtomicUsize>,
    rpc_delay_millis: Arc<AtomicU64>,
    captured_payloads: Arc<StdMutex<Vec<Bytes>>>,
}

impl LoopbackPeer {
    fn new(target: SessionConsensusNodeId) -> Self {
        Self {
            target,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
            forward_responses_to_drop: Arc::new(AtomicUsize::new(0)),
            dropped_forward_responses: Arc::new(AtomicUsize::new(0)),
            forward_response_delay_millis: Arc::new(AtomicU64::new(0)),
            delayed_forward_responses: Arc::new(AtomicUsize::new(0)),
            rpc_delay_millis: Arc::new(AtomicU64::new(0)),
            captured_payloads: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    fn drop_forward_responses(&self, count: usize) {
        self.forward_responses_to_drop
            .store(count, Ordering::SeqCst);
    }

    fn stop_dropping_forward_responses(&self) {
        self.forward_responses_to_drop.store(0, Ordering::SeqCst);
    }

    fn dropped_forward_responses(&self) -> usize {
        self.dropped_forward_responses.load(Ordering::SeqCst)
    }

    fn delay_forward_responses(&self, delay: Duration) {
        self.forward_response_delay_millis.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    fn stop_delaying_forward_responses(&self) {
        self.forward_response_delay_millis
            .store(0, Ordering::SeqCst);
    }

    fn delayed_forward_responses(&self) -> usize {
        self.delayed_forward_responses.load(Ordering::SeqCst)
    }

    fn delay_calls(&self, delay: Duration) {
        self.rpc_delay_millis.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    fn stop_delaying_calls(&self) {
        self.rpc_delay_millis.store(0, Ordering::SeqCst);
    }

    fn clear_captured_payloads(&self) {
        self.captured_payloads
            .lock()
            .expect("consensus capture mutex")
            .clear();
    }

    fn captured_payloads(&self) -> Vec<Bytes> {
        let captured = self
            .captured_payloads
            .lock()
            .expect("consensus capture mutex")
            .clone();
        assert!(
            captured.len() < MAX_CAPTURED_CONSENSUS_PAYLOADS,
            "consensus payload qualification capture was saturated"
        );
        captured
    }
}

impl fmt::Debug for LoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackPeer")
            .field("target", &self.target)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for LoopbackPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(SessionConsensusPeerError::Unavailable);
        }

        let rpc_delay = self.rpc_delay_millis.load(Ordering::SeqCst);
        if rpc_delay != 0 {
            tokio::time::sleep(Duration::from_millis(rpc_delay)).await;
        }

        {
            let mut captured = self
                .captured_payloads
                .lock()
                .expect("consensus capture mutex");
            if captured.len() < MAX_CAPTURED_CONSENSUS_PAYLOADS {
                captured.push(request.payload.clone().into());
            }
        }

        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        let sender = request.sender;
        let family = request.family;
        let response = handler.handle(sender, request).await;

        if family == SessionConsensusRpcFamily::ForwardMutation {
            let delay = self.forward_response_delay_millis.load(Ordering::SeqCst);
            if delay != 0 {
                self.delayed_forward_responses
                    .fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }

        if family == SessionConsensusRpcFamily::ForwardMutation
            && self
                .forward_responses_to_drop
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            self.dropped_forward_responses
                .fetch_add(1, Ordering::SeqCst);
            return Err(SessionConsensusPeerError::Unavailable);
        }

        Ok(response)
    }
}

struct TestCluster {
    _directory: TempDir,
    _backends: Vec<SqliteSessionBackend>,
    stores: Vec<ConsensusSessionStore>,
    paths: BTreeMap<(usize, usize), Arc<LoopbackPeer>>,
}

impl TestCluster {
    async fn start() -> Self {
        Self::start_with_operation_timeout(OPERATION_TIMEOUT).await
    }

    async fn start_with_operation_timeout(operation_timeout: Duration) -> Self {
        let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
        let identity = consensus_identity(&members);
        let topologies = (0..MEMBER_COUNT)
            .map(|index| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    replica_id(index),
                    members.clone(),
                    identity,
                ))
                .expect("validate consensus topology")
            })
            .collect::<Vec<_>>();
        Self::start_with_topologies(operation_timeout, topologies).await
    }

    async fn start_with_topologies(
        operation_timeout: Duration,
        topologies: Vec<ValidatedQuorumTopology>,
    ) -> Self {
        assert_eq!(topologies.len(), MEMBER_COUNT);
        let directory = tempfile::tempdir().expect("create fleet directory");
        let backends = (0..MEMBER_COUNT)
            .map(|index| {
                SqliteSessionBackend::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("open file-backed SQLite node")
            })
            .collect::<Vec<_>>();
        let node_ids = topologies
            .iter()
            .map(|topology| {
                topology
                    .local_consensus_node_id()
                    .expect("consensus node ID")
            })
            .collect::<Vec<_>>();

        let mut paths = BTreeMap::new();
        for source in 0..MEMBER_COUNT {
            for (target, node_id) in node_ids.iter().copied().enumerate() {
                if source != target {
                    paths.insert((source, target), Arc::new(LoopbackPeer::new(node_id)));
                }
            }
        }

        let mut stores = Vec::with_capacity(MEMBER_COUNT);
        for index in 0..MEMBER_COUNT {
            let peers = (0..MEMBER_COUNT)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn SessionConsensusPeer> =
                        paths.get(&(index, target)).expect("loopback path").clone();
                    (node_ids[target], peer)
                })
                .collect::<BTreeMap<_, _>>();
            let store = ConsensusSessionStore::open_with_clock(
                topologies[index].clone(),
                backends[index].clone(),
                directory.path().join(format!("snapshots-{index}")),
                peers,
                Arc::new(SystemClock),
                operation_timeout,
            )
            .await
            .expect("open consensus node");
            stores.push(store);
        }

        for ((_, target), path) in &paths {
            path.install(stores[*target].rpc_handler()).await;
        }

        let initialize = stores
            .iter()
            .map(ConsensusSessionStore::initialize_cluster)
            .collect::<Vec<_>>();
        let results = futures_util::future::join_all(initialize).await;
        for result in results {
            result.expect("initialize identical membership concurrently");
        }

        let cluster = Self {
            _directory: directory,
            _backends: backends,
            stores,
            paths,
        };
        cluster
            .wait_all_ready(CLUSTER_START_TIMEOUT)
            .await
            .expect("fresh cluster reaches durable readiness");
        cluster
    }

    async fn wait_all_ready(&self, deadline: Duration) -> Result<(), ()> {
        tokio::time::timeout(deadline, async {
            loop {
                let reports = futures_util::future::join_all(
                    self.stores
                        .iter()
                        .map(ConsensusSessionStore::probe_durable_readiness),
                )
                .await;
                if reports.iter().all(|report| report.is_ready()) {
                    return;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .map_err(|_| ())
    }

    fn observed_leader(&self) -> (usize, SessionConsensusNodeId, u64) {
        let statuses = self
            .stores
            .iter()
            .map(ConsensusSessionStore::status)
            .collect::<Vec<_>>();
        let leader_id = statuses
            .first()
            .and_then(|status| status.leader_id)
            .expect("known leader");
        let term = statuses.first().expect("cluster status").term;
        assert!(
            statuses
                .iter()
                .all(|status| status.leader_id == Some(leader_id) && status.term == term),
            "all ready members must agree on the observed leader and term"
        );
        let leader_index = statuses
            .iter()
            .position(|status| status.node_id == leader_id)
            .expect("leader is a configured member");
        (leader_index, leader_id, term)
    }

    fn isolate(&self, node: usize) {
        for peer in 0..MEMBER_COUNT {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("outbound path")
                    .set_enabled(false);
                self.paths
                    .get(&(peer, node))
                    .expect("inbound path")
                    .set_enabled(false);
            }
        }
    }

    fn heal(&self, node: usize) {
        for peer in 0..MEMBER_COUNT {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("outbound path")
                    .set_enabled(true);
                self.paths
                    .get(&(peer, node))
                    .expect("inbound path")
                    .set_enabled(true);
            }
        }
    }

    fn arm_forward_response_loss(&self, source: usize, count: usize) -> usize {
        let before = self.dropped_forward_responses(source);
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .drop_forward_responses(count);
            }
        }
        before
    }

    fn stop_forward_response_loss(&self, source: usize) {
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .stop_dropping_forward_responses();
            }
        }
    }

    fn arm_forward_response_delay(&self, source: usize, delay: Duration) -> usize {
        let before = self.delayed_forward_responses(source);
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .delay_forward_responses(delay);
            }
        }
        before
    }

    fn stop_forward_response_delay(&self, source: usize) {
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .stop_delaying_forward_responses();
            }
        }
    }

    fn delay_calls(&self, source: usize, delay: Duration) {
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .delay_calls(delay);
            }
        }
    }

    fn stop_delaying_calls(&self, source: usize) {
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .stop_delaying_calls();
            }
        }
    }

    fn delayed_forward_responses(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .delayed_forward_responses()
            })
            .sum()
    }

    fn dropped_forward_responses(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .dropped_forward_responses()
            })
            .sum()
    }

    fn clear_captured_payloads(&self) {
        for path in self.paths.values() {
            path.clear_captured_payloads();
        }
    }

    fn captured_payloads(&self) -> Vec<Bytes> {
        self.paths
            .values()
            .flat_map(|path| path.captured_payloads())
            .collect()
    }
}

struct CountingKeyProvider {
    inner: Arc<MemoryKeyProvider>,
    active_key_calls: AtomicUsize,
    key_by_id_calls: AtomicUsize,
    rotation_calls: AtomicUsize,
}

impl CountingKeyProvider {
    fn new(inner: Arc<MemoryKeyProvider>) -> Self {
        Self {
            inner,
            active_key_calls: AtomicUsize::new(0),
            key_by_id_calls: AtomicUsize::new(0),
            rotation_calls: AtomicUsize::new(0),
        }
    }

    fn call_counts(&self) -> (usize, usize, usize) {
        (
            self.active_key_calls.load(Ordering::SeqCst),
            self.key_by_id_calls.load(Ordering::SeqCst),
            self.rotation_calls.load(Ordering::SeqCst),
        )
    }
}

#[async_trait]
impl KeyProvider for CountingKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.active_key_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.key_by_id_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.rotation_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.rotate_key(purpose, tenant).await
    }
}

fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("consensus-test-{index}")).expect("replica ID")
}

fn member(index: usize) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(index),
        ReplicaEndpoint::new(format!("consensus-test-{index}.invalid"), 7443)
            .expect("replica endpoint"),
        ReplicaTlsIdentity::new(format!("spiffe://test/session/consensus/{index}"))
            .expect("TLS identity"),
        ReplicaFailureDomain::new(format!("consensus-test-zone-{index}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("consensus-test-disk-{index}"))
            .expect("backing identity"),
    )
}

fn consensus_identity(members: &[QuorumReplicaDescriptor]) -> ConsensusIdentity {
    consensus_identity_for_cluster(members, "session-openraft-integration-tests", 1)
}

fn consensus_identity_for_cluster(
    members: &[QuorumReplicaDescriptor],
    cluster_name: &str,
    epoch: u64,
) -> ConsensusIdentity {
    let cluster_id = ConsensusClusterId::new(cluster_name).expect("consensus cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(epoch).expect("consensus epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let configuration_id = derive_configuration_id(cluster_id, epoch, &fingerprints);
    ConsensusIdentity::new(cluster_id, configuration_id, epoch)
}

#[derive(Debug)]
struct DigestTopologyAttestor;

impl QuorumTopologyAttestor for DigestTopologyAttestor {
    fn verify(
        &self,
        input: TopologyAttestationVerificationInput<'_>,
    ) -> Result<(), TopologyAttestationVerificationError> {
        (input.proof() == input.canonical_digest())
            .then_some(())
            .ok_or(TopologyAttestationVerificationError::InvalidProof)
    }
}

fn attestation_collector() -> TopologyCollectorId {
    TopologyCollectorId::new("consensus-integration-attestor").expect("collector identity")
}

fn attestation_policy(
    collector: TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
) -> TopologyAttestationPolicy {
    TopologyAttestationPolicy::try_new(provenance, vec![collector], Duration::from_secs(300))
        .expect("attestation policy")
}

fn topology_evidence(
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
) -> Vec<TopologyAttestationEvidence> {
    members
        .iter()
        .enumerate()
        .map(|(index, descriptor)| {
            let claims = TopologyAttestationClaims::new(
                descriptor.replica_id().clone(),
                descriptor.tls_identity().clone(),
                ObservedPhysicalNodeIdentity::new(format!(
                    "consensus-integration-physical-node-{index}"
                ))
                .expect("physical node identity"),
                descriptor.failure_domain().clone(),
                descriptor.backing_identity().clone(),
                descriptor.configuration_fingerprint(),
                identity,
                collector.clone(),
                provenance,
                observed_at,
                expires_at,
            );
            let proof = claims.canonical_digest().to_vec();
            TopologyAttestationEvidence::try_new(claims, proof).expect("bounded evidence")
        })
        .collect()
}

fn attested_topologies(
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
    admitted_at: TopologyAttestationTime,
) -> Vec<ValidatedQuorumTopology> {
    let policy = attestation_policy(collector.clone(), provenance);
    let evidence = topology_evidence(
        members,
        identity,
        collector,
        provenance,
        observed_at,
        expires_at,
    );
    (0..MEMBER_COUNT)
        .map(|index| {
            ValidatedQuorumTopology::try_from_attested(
                QuorumTopologyConfig::new_consensus(replica_id(index), members.to_vec(), identity),
                evidence.clone(),
                &policy,
                &DigestTopologyAttestor,
                admitted_at,
            )
            .expect("attested topology")
        })
        .collect()
}

fn refreshed_attestation(
    topology: &ValidatedQuorumTopology,
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
    verified_at: TopologyAttestationTime,
) -> VerifiedQuorumTopologyAttestation {
    refreshed_attestation_with_provenance(
        topology,
        members,
        identity,
        collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        observed_at,
        expires_at,
        verified_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn refreshed_attestation_with_provenance(
    topology: &ValidatedQuorumTopology,
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
    verified_at: TopologyAttestationTime,
) -> VerifiedQuorumTopologyAttestation {
    let policy = attestation_policy(collector.clone(), provenance);
    topology
        .verify_attestation_evidence(
            topology_evidence(
                members,
                identity,
                collector,
                provenance,
                observed_at,
                expires_at,
            ),
            &policy,
            &DigestTopologyAttestor,
            verified_at,
        )
        .expect("refreshed attestation")
}

fn session_key(label: impl AsRef<[u8]>) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("consensus-test-tenant").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(label.as_ref())
            .try_into()
            .expect("valid stable ID"),
    }
}

fn owner(label: impl Into<String>) -> OwnerId {
    OwnerId::new(label).expect("owner")
}

fn plaintext_record(
    key: SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
    plaintext: &[u8],
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("consensus-encryption-boundary"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(plaintext),
    }
}

fn encryption_provider() -> Arc<CountingKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("consensus-boundary-key-2026-07").expect("key ID"),
            KeyPurpose::Session,
            TenantId::new("consensus-test-tenant").expect("tenant"),
            Zeroizing::new([0x5a; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("install qualification key");
    Arc::new(CountingKeyProvider::new(provider))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn json_contains_bytes(value: &serde_json::Value, needle: &[u8]) -> bool {
    match value {
        serde_json::Value::Array(values) => {
            let encoded_bytes = values
                .iter()
                .map(|value| value.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect::<Option<Vec<_>>>();
            encoded_bytes
                .as_deref()
                .is_some_and(|bytes| contains_bytes(bytes, needle))
                || values
                    .iter()
                    .any(|value| json_contains_bytes(value, needle))
        }
        serde_json::Value::Object(values) => values
            .values()
            .any(|value| json_contains_bytes(value, needle)),
        serde_json::Value::String(value) => contains_bytes(value.as_bytes(), needle),
        _ => false,
    }
}

fn assert_artifact_bytes_are_sealed(label: &str, bytes: &[u8]) {
    for canary in [
        PLAINTEXT_CANARY_BEFORE_ROTATION,
        PLAINTEXT_CANARY_AFTER_ROTATION,
        RAW_KEY_MATERIAL_CANARY.as_slice(),
    ] {
        assert!(
            !contains_bytes(bytes, canary),
            "plaintext session payload crossed the encryption boundary into {label}"
        );
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
            assert!(
                !json_contains_bytes(&value, canary),
                "JSON-encoded plaintext session payload crossed the encryption boundary into {label}"
            );
        }
    }
}

fn assert_file_tree_is_sealed(root: &Path) {
    let entries = std::fs::read_dir(root).expect("read durable artifact directory");
    for entry in entries {
        let path = entry.expect("durable artifact entry").path();
        if path.is_dir() {
            assert_file_tree_is_sealed(&path);
        } else if path.is_file() {
            let bytes = std::fs::read(&path).expect("read durable artifact");
            assert_artifact_bytes_are_sealed("durable file", &bytes);
        }
    }
}

fn assert_sqlite_authority_is_sealed(database: &Path) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open consensus database for qualification");
    for (table, column, is_json) in [
        ("session_records", "payload", false),
        ("session_replication_log", "entry_json", true),
        ("consensus_log", "entry_json", true),
        ("consensus_request_outcomes", "response_json", true),
    ] {
        let query = format!("SELECT CAST({column} AS BLOB) FROM {table}");
        let mut statement = connection.prepare(&query).expect("prepare authority scan");
        let values = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query authority bytes");
        for value in values {
            let bytes = value.expect("read authority bytes");
            assert_artifact_bytes_are_sealed("SQLite consensus authority", &bytes);
            if is_json {
                let value: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("authority JSON");
                for canary in [
                    PLAINTEXT_CANARY_BEFORE_ROTATION,
                    PLAINTEXT_CANARY_AFTER_ROTATION,
                    RAW_KEY_MATERIAL_CANARY.as_slice(),
                ] {
                    assert!(
                        !json_contains_bytes(&value, canary),
                        "plaintext session payload was encoded into SQLite consensus authority"
                    );
                }
            }
        }
    }
}

fn consensus_sqlite_progress(database: &Path) -> (Option<u64>, Option<u64>, Option<u64>, u64, u64) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open consensus database progress");
    let optional_index = |sql: &str| {
        connection
            .query_row(sql, [], |row| row.get::<_, i64>(0))
            .optional()
            .expect("read optional consensus index")
            .and_then(|value| u64::try_from(value).ok())
    };
    (
        optional_index("SELECT log_index FROM consensus_committed WHERE singleton = 1"),
        optional_index("SELECT log_index FROM consensus_applied WHERE singleton = 1"),
        optional_index("SELECT log_index FROM consensus_purged WHERE singleton = 1"),
        connection
            .query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("read consensus log row count"),
        connection
            .query_row("SELECT COUNT(*) FROM consensus_snapshot", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("read consensus snapshot row count"),
    )
}

fn sealed_record(
    key: SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
    payload: &'static [u8],
) -> StoredSessionRecord {
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("consensus-test-session"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    let key_id = KeyId::new("synthetic-consensus-test-key").expect("key ID");
    let aad = EnvelopeAad::session(
        record.key.tenant.clone(),
        1,
        SessionAad::new(
            record.key.nf_kind.as_str(),
            "synthetic-keyed-session-digest",
            record.state_type.as_str(),
            record.generation.get(),
            record.fence.get(),
            "synthetic-consensus-test-backend",
        )
        .expect("session AAD"),
    );
    let mut ciphertext_and_tag = payload.to_vec();
    ciphertext_and_tag.extend_from_slice(&[0xA5; AEAD_TAG_LEN]);
    let envelope = CryptoEnvelopeV1 {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_id: key_id.clone(),
        nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
        aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
        ciphertext_and_tag,
    }
    .encode()
    .expect("test envelope");
    record.payload = EncryptedSessionPayload::try_envelope(envelope).expect("valid envelope");
    record
}

async fn replication_logs(cluster: &TestCluster) -> Vec<Vec<opc_session_store::ReplicationEntry>> {
    futures_util::future::join_all(
        cluster
            .stores
            .iter()
            .map(|store| store.get_replication_log(1, 128)),
    )
    .await
    .into_iter()
    .map(|result| result.expect("read committed replication log"))
    .collect()
}

async fn assert_differing_replica_compaction_floors_never_union(cluster: &TestCluster) {
    let logs = replication_logs(cluster).await;
    assert!(logs.iter().all(|log| log == &logs[0]));
    assert!(logs[0].len() >= MEMBER_COUNT);

    // Test-only post-commit fault injection: no authoritative mutation follows
    // these deliberately different local floors. The read contract must expose
    // each typed outcome rather than constructing a cross-replica union page.
    for (index, floor) in (1_i64..=3).enumerate() {
        let connection = rusqlite::Connection::open(
            cluster
                ._directory
                .path()
                .join(format!("node-{index}.sqlite")),
        )
        .expect("open replica for deliberate compaction disagreement");
        connection
            .execute(
                "UPDATE consensus_operator_recovery SET watch_cursor_invalidation_floor = ?1 WHERE singleton = 1",
                [floor],
            )
            .expect("install deliberate local compaction floor");
    }

    let outcomes = futures_util::future::join_all(
        cluster
            .stores
            .iter()
            .map(|store| store.get_replication_log(1, MEMBER_COUNT)),
    )
    .await;
    for (index, outcome) in outcomes.into_iter().enumerate() {
        assert_eq!(
            outcome.expect_err("a stale cursor must not be filled from another replica"),
            StoreError::ReplicationLogCursorCompacted {
                resume_from: u64::try_from(index + 2).expect("small resume point"),
            }
        );
    }

    let watch_outcomes =
        futures_util::future::join_all(cluster.stores.iter().map(|store| store.watch(1))).await;
    for (index, outcome) in watch_outcomes.into_iter().enumerate() {
        let error = match outcome {
            Ok(_) => panic!("a compacted production watch must not skip history"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            StoreError::ReplicationLogCursorCompacted {
                resume_from: u64::try_from(index + 2).expect("small resume point"),
            }
        );
    }
}

fn assert_raw_consensus_guard<T>(result: Result<T, StoreError>) {
    assert!(matches!(
        result,
        Err(StoreError::CapabilityNotSupported(capability))
            if capability == "consensus_authority_required"
    ));
}

fn assert_raw_consensus_lease_guard<T>(result: Result<T, LeaseError>) {
    assert!(matches!(
        result,
        Err(LeaseError::Backend(message))
            if message.contains("consensus_authority_required")
    ));
}

#[tokio::test]
async fn production_readiness_requires_fresh_authenticated_topology_and_accepts_refresh() {
    let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
    let identity = consensus_identity(&members);
    let collector = attestation_collector();
    let topologies = attested_topologies(
        &members,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(1_000),
        TopologyAttestationTime::from_unix_seconds(1_010),
        TopologyAttestationTime::from_unix_seconds(1_000),
    );
    let attestation_context = topologies[0].clone();
    let cluster = TestCluster::start_with_topologies(Duration::from_secs(5), topologies).await;
    let store = &cluster.stores[0];

    assert_eq!(
        store.platform_profile(),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_001)),
        SessionStorePlatformProfile::Quorum
    );
    let admitted =
        store.topology_attestation_summary_at(TopologyAttestationTime::from_unix_seconds(1_001));
    assert_eq!(
        admitted.provenance(),
        TopologyAttestationProvenance::AuthenticatedPlatform
    );
    assert_eq!(admitted.configuration_epoch(), 1);
    assert_eq!(admitted.result(), TopologyAttestationResult::Verified);
    let production_ready = store
        .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(1_001))
        .await;
    assert_eq!(
        production_ready.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(production_ready.is_production_traffic_ready());
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_001)),
        SessionStorePlatformProfile::Quorum
    );
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_000)),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store
            .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(
                1_000,
            ))
            .await
            .state(),
        DurableReadinessState::TopologyInvalid
    );
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_001)),
        SessionStorePlatformProfile::Quorum
    );

    let (initial_leader, _, _) = cluster.observed_leader();
    cluster.delay_calls(initial_leader, Duration::from_millis(1_500));
    let initial_probe_started = Instant::now();
    let initial_crossed_expiry = cluster.stores[initial_leader]
        .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(1_009))
        .await;
    let initial_elapsed = initial_probe_started.elapsed();
    cluster.stop_delaying_calls(initial_leader);
    assert_eq!(
        initial_crossed_expiry.state(),
        DurableReadinessState::TopologyInvalid
    );
    assert!(
        initial_elapsed >= Duration::from_millis(500) && initial_elapsed < Duration::from_secs(2),
        "initial attestation deadline must bound the barrier; elapsed {initial_elapsed:?}"
    );
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("cluster recovers after the bounded initial probe");

    let expired =
        store.topology_attestation_summary_at(TopologyAttestationTime::from_unix_seconds(1_010));
    assert_eq!(expired.result(), TopologyAttestationResult::Expired);
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_010)),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store
            .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(
                1_010,
            ))
            .await
            .state(),
        DurableReadinessState::TopologyInvalid
    );
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_009)),
        SessionStorePlatformProfile::Unknown,
        "an expired forward evaluation must prevent wall-clock rollback revival"
    );

    let refreshed = refreshed_attestation(
        &attestation_context,
        &members,
        identity,
        &collector,
        TopologyAttestationTime::from_unix_seconds(1_020),
        TopologyAttestationTime::from_unix_seconds(1_100),
        TopologyAttestationTime::from_unix_seconds(1_020),
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_019),
        ),
        SessionStorePlatformProfile::Unknown,
        "a refreshed token cannot authorize a time before its verification"
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_021),
        ),
        SessionStorePlatformProfile::Quorum
    );
    let refreshed_ready = store
        .probe_production_durable_readiness_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_021),
        )
        .await;
    assert_eq!(
        refreshed_ready.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(refreshed_ready.is_production_traffic_ready());
    assert_eq!(
        store.platform_profile(),
        SessionStorePlatformProfile::Unknown
    );

    cluster.delay_calls(0, Duration::from_millis(750));
    let older_probe = store.probe_production_durable_readiness_with_attestation_at(
        &refreshed,
        TopologyAttestationTime::from_unix_seconds(1_022),
    );
    let newer_evaluation = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        store.production_platform_profile_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_023),
        )
    };
    let (older_report, newer_profile) = tokio::join!(older_probe, newer_evaluation);
    cluster.stop_delaying_calls(0);
    assert_eq!(newer_profile, SessionStorePlatformProfile::Quorum);
    assert_eq!(
        older_report.state(),
        DurableReadinessState::TopologyInvalid,
        "a delayed older evaluation must fail after a newer time is observed"
    );
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("cluster recovers after the delayed rollback race");

    let foreign_identity =
        consensus_identity_for_cluster(&members, "foreign-session-openraft-cluster", 1);
    let foreign_topologies = attested_topologies(
        &members,
        foreign_identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(9_000),
        TopologyAttestationTime::from_unix_seconds(9_100),
        TopologyAttestationTime::from_unix_seconds(9_000),
    );
    let foreign = refreshed_attestation(
        &foreign_topologies[0],
        &members,
        foreign_identity,
        &collector,
        TopologyAttestationTime::from_unix_seconds(9_000),
        TopologyAttestationTime::from_unix_seconds(9_100),
        TopologyAttestationTime::from_unix_seconds(9_000),
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &foreign,
            TopologyAttestationTime::from_unix_seconds(9_001),
        ),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store
            .probe_production_durable_readiness_with_attestation_at(
                &foreign,
                TopologyAttestationTime::from_unix_seconds(9_001),
            )
            .await
            .state(),
        DurableReadinessState::TopologyInvalid
    );
    let conformance_only = refreshed_attestation_with_provenance(
        &attestation_context,
        &members,
        identity,
        &collector,
        TopologyAttestationProvenance::DeterministicConformance,
        TopologyAttestationTime::from_unix_seconds(9_500),
        TopologyAttestationTime::from_unix_seconds(9_600),
        TopologyAttestationTime::from_unix_seconds(9_500),
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &conformance_only,
            TopologyAttestationTime::from_unix_seconds(9_501),
        ),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_023),
        ),
        SessionStorePlatformProfile::Quorum,
        "foreign and non-production future tokens must not poison the time authority"
    );

    let wall_start = TopologyAttestationTime::now().expect("current attestation time");
    let wall_expiry = TopologyAttestationTime::from_unix_seconds(
        wall_start
            .unix_seconds()
            .checked_add(2)
            .expect("test wall-clock expiry"),
    );
    let short_lived = refreshed_attestation(
        &attestation_context,
        &members,
        identity,
        &collector,
        wall_start,
        wall_expiry,
        wall_start,
    );
    cluster.delay_calls(0, Duration::from_millis(2_500));
    let probe_started = Instant::now();
    let crossed_expiry = store
        .probe_production_durable_readiness_with_attestation_at(&short_lived, wall_start)
        .await;
    let elapsed = probe_started.elapsed();
    cluster.stop_delaying_calls(0);
    assert_eq!(
        crossed_expiry.state(),
        DurableReadinessState::TopologyInvalid
    );
    assert!(
        elapsed >= Duration::from_millis(500) && elapsed < Duration::from_secs(3),
        "attestation deadline must bound the barrier; elapsed {elapsed:?}"
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(&short_lived, wall_start),
        SessionStorePlatformProfile::Unknown,
        "monotonic expiry must prevent a retry with the old pre-expiry wall time"
    );
    assert_eq!(
        store
            .probe_production_durable_readiness_with_attestation_at(&short_lived, wall_start)
            .await
            .state(),
        DurableReadinessState::TopologyInvalid
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &short_lived,
            TopologyAttestationTime::from_unix_seconds(u64::MAX),
        ),
        SessionStorePlatformProfile::Unknown,
        "the bounded time authority must fail closed at the representable maximum"
    );
}

#[tokio::test]
async fn descriptor_only_three_node_store_cannot_be_upgraded_by_attested_token() {
    let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
    let identity = consensus_identity(&members);
    let collector = attestation_collector();
    let attested = attested_topologies(
        &members,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(1_500),
        TopologyAttestationTime::from_unix_seconds(1_600),
        TopologyAttestationTime::from_unix_seconds(1_500),
    );
    let token = refreshed_attestation(
        &attested[0],
        &members,
        identity,
        &collector,
        TopologyAttestationTime::from_unix_seconds(1_500),
        TopologyAttestationTime::from_unix_seconds(1_600),
        TopologyAttestationTime::from_unix_seconds(1_500),
    );

    let cluster = TestCluster::start().await;
    let store = &cluster.stores[0];
    let now = TopologyAttestationTime::from_unix_seconds(1_501);
    assert_eq!(store.topology().mode().as_str(), "descriptor-only-lab-ha");
    assert_eq!(
        store.production_platform_profile_at(now),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(&token, now),
        SessionStorePlatformProfile::Unknown,
        "a valid same-identity token must not upgrade a descriptor-only store"
    );

    let initial = store.probe_production_durable_readiness_at(now).await;
    assert_eq!(initial.state(), DurableReadinessState::TopologyInvalid);
    assert_eq!(
        initial.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(!initial.is_production_traffic_ready());
    let refreshed = store
        .probe_production_durable_readiness_with_attestation_at(&token, now)
        .await;
    assert_eq!(refreshed.state(), DurableReadinessState::TopologyInvalid);
    assert_eq!(
        refreshed.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(!refreshed.is_production_traffic_ready());

    let engine = store.probe_durable_readiness().await;
    assert!(engine.is_ready());
    assert_eq!(engine.scope(), DurableReadinessScope::EngineOnly);
    assert!(!engine.is_production_traffic_ready());
}

#[tokio::test]
async fn deterministic_topology_is_visible_but_never_production_ready() {
    let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
    let identity = consensus_identity(&members);
    let collector = attestation_collector();
    let topologies = attested_topologies(
        &members,
        identity,
        &collector,
        TopologyAttestationProvenance::DeterministicConformance,
        TopologyAttestationTime::from_unix_seconds(2_000),
        TopologyAttestationTime::from_unix_seconds(2_100),
        TopologyAttestationTime::from_unix_seconds(2_000),
    );
    let cluster = TestCluster::start_with_topologies(OPERATION_TIMEOUT, topologies).await;
    let store = &cluster.stores[0];
    let now = TopologyAttestationTime::from_unix_seconds(2_001);

    assert_eq!(
        store.platform_profile(),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store.production_platform_profile_at(now),
        SessionStorePlatformProfile::Unknown
    );
    let summary = store.topology_attestation_summary_at(now);
    assert_eq!(
        summary.provenance(),
        TopologyAttestationProvenance::DeterministicConformance
    );
    assert_eq!(summary.result(), TopologyAttestationResult::Verified);
    assert!(!summary.is_production_verified());
    let production = store.probe_production_durable_readiness_at(now).await;
    assert_eq!(production.state(), DurableReadinessState::TopologyInvalid);
    assert_eq!(
        production.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(!production.is_production_traffic_ready());
    let engine = store.probe_durable_readiness().await;
    assert!(engine.is_ready());
    assert_eq!(engine.scope(), DurableReadinessScope::EngineOnly);
    assert!(!engine.is_production_traffic_ready());
}

#[tokio::test]
async fn consensus_claim_fences_retained_and_reopened_raw_sqlite_handles() {
    let cluster = TestCluster::start().await;
    let raw = &cluster._backends[0];
    let store = &cluster.stores[0];
    let key = session_key(b"raw-authority-bypass");

    let raw_capabilities = raw.capabilities().await;
    assert_eq!(
        raw_capabilities,
        opc_session_store::BackendCapabilities::minimal()
    );
    let consensus_capabilities = store.capabilities().await;
    assert!(consensus_capabilities.atomic_compare_and_set);
    assert!(consensus_capabilities.monotonic_fencing_token);
    assert!(consensus_capabilities.ordered_replication_log);
    assert!(consensus_capabilities.restore_scan);

    assert_raw_consensus_guard(raw.get(&key).await);
    assert_raw_consensus_guard(
        raw.scan_restore_records(RestoreScanRequest::default())
            .await,
    );
    assert_raw_consensus_guard(raw.max_replication_sequence().await);
    assert_raw_consensus_guard(raw.get_replication_log(1, 16).await);
    assert_raw_consensus_guard(raw.rebuild_replication_state(Vec::new()).await);
    assert_raw_consensus_guard(raw.next_lease_info().await);
    assert_raw_consensus_guard(raw.watch(1).await);
    assert_raw_consensus_lease_guard(
        raw.acquire(&key, owner("raw-owner"), Duration::from_secs(30))
            .await,
    );

    let lease = store
        .acquire(&key, owner("consensus-owner"), Duration::from_secs(30))
        .await
        .expect("consensus lease");
    let record = sealed_record(key.clone(), 1, &lease, b"opaque-authoritative-value");
    assert_raw_consensus_guard(
        raw.compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await,
    );
    assert_raw_consensus_guard(raw.delete_fenced(&lease).await);
    assert_raw_consensus_guard(raw.refresh_ttl(&lease, Duration::from_secs(30)).await);
    assert_raw_consensus_lease_guard(raw.renew(&lease, Duration::from_secs(30)).await);
    assert_raw_consensus_lease_guard(raw.release(lease.clone()).await);

    let batch = raw
        .batch(vec![SessionOp::Get { key: key.clone() }])
        .await
        .expect("batch retains per-slot result contract");
    assert!(matches!(
        batch.as_slice(),
        [opc_session_store::SessionOpResult::Get(Err(
            StoreError::CapabilityNotSupported(capability)
        ))] if capability == "consensus_authority_required"
    ));

    store
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: record,
        })
        .await
        .expect("consensus mutation remains available");
    let entry = store
        .get_replication_log(1, 128)
        .await
        .expect("committed application journal")
        .into_iter()
        .next()
        .expect("journal entry");
    assert_raw_consensus_guard(raw.replicate_entry(entry).await);

    let reopened = SqliteSessionBackend::open(cluster._directory.path().join("node-0.sqlite"))
        .expect("reopen consensus-owned SQLite file");
    assert_raw_consensus_guard(reopened.get(&key).await);
    assert_raw_consensus_lease_guard(
        reopened
            .acquire(&key, owner("reopened-owner"), Duration::from_secs(30))
            .await,
    );

    let committed = store
        .get(&key)
        .await
        .expect("linearizable read")
        .expect("committed record");
    assert_eq!(committed.generation, Generation::new(1));
}

#[tokio::test]
async fn batch_preflight_rejects_unsealed_payload_before_any_slot_commits() {
    let cluster = TestCluster::start().await;
    let store = &cluster.stores[0];
    let first_key = session_key(b"batch-sealed-first");
    let second_key = session_key(b"batch-unsealed-second");
    let first_lease = store
        .acquire(
            &first_key,
            owner("batch-owner-first"),
            Duration::from_secs(30),
        )
        .await
        .expect("first lease");
    let second_lease = store
        .acquire(
            &second_key,
            owner("batch-owner-second"),
            Duration::from_secs(30),
        )
        .await
        .expect("second lease");
    let before = store
        .max_replication_sequence()
        .await
        .expect("journal head before rejected batch");

    let error = store
        .batch(vec![
            SessionOp::CompareAndSet(CompareAndSet {
                key: first_key.clone(),
                lease: first_lease.clone(),
                expected_generation: None,
                new_record: sealed_record(first_key.clone(), 1, &first_lease, b"sealed-first-slot"),
            }),
            SessionOp::CompareAndSet(CompareAndSet {
                key: second_key.clone(),
                lease: second_lease.clone(),
                expected_generation: None,
                new_record: plaintext_record(second_key, 1, &second_lease, b"unsealed-second-slot"),
            }),
        ])
        .await
        .expect_err("an unsealed later slot rejects the complete raw batch");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert_eq!(
        store.get(&first_key).await.expect("read first key"),
        None,
        "preflight must run before the first slot reaches Openraft"
    );
    assert_eq!(
        store
            .max_replication_sequence()
            .await
            .expect("journal head after rejected batch"),
        before
    );
}

#[tokio::test]
async fn batch_commits_independent_slots_and_preserves_partial_results() {
    let cluster = TestCluster::start().await;
    let store = &cluster.stores[0];
    let first_key = session_key(b"batch-partial-first");
    let second_key = session_key(b"batch-partial-second");
    let first_lease = store
        .acquire(
            &first_key,
            owner("batch-partial-owner-first"),
            Duration::from_secs(30),
        )
        .await
        .expect("first lease");
    let second_lease = store
        .acquire(
            &second_key,
            owner("batch-partial-owner-second"),
            Duration::from_secs(30),
        )
        .await
        .expect("second lease");
    let first_record = sealed_record(
        first_key.clone(),
        1,
        &first_lease,
        b"sealed-batch-partial-first",
    );
    let second_record = sealed_record(
        second_key.clone(),
        1,
        &second_lease,
        b"sealed-batch-partial-second",
    );
    let conflict_record = sealed_record(
        first_key.clone(),
        2,
        &first_lease,
        b"sealed-batch-partial-conflict",
    );
    let before = store
        .max_replication_sequence()
        .await
        .expect("journal head before partial batch");

    let results = store
        .batch(vec![
            SessionOp::CompareAndSet(CompareAndSet {
                key: first_key.clone(),
                lease: first_lease.clone(),
                expected_generation: None,
                new_record: first_record.clone(),
            }),
            SessionOp::CompareAndSet(CompareAndSet {
                key: first_key.clone(),
                lease: first_lease,
                expected_generation: None,
                new_record: conflict_record,
            }),
            SessionOp::CompareAndSet(CompareAndSet {
                key: second_key.clone(),
                lease: second_lease,
                expected_generation: None,
                new_record: second_record.clone(),
            }),
        ])
        .await
        .expect("partial batch invocation");

    assert_eq!(results.len(), 3);
    assert!(matches!(
        &results[0],
        opc_session_store::SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));
    assert!(matches!(
        &results[1],
        opc_session_store::SessionOpResult::CompareAndSet(Ok(
            CompareAndSetResult::Conflict { current: Some(record) }
        )) if record == &first_record
    ));
    assert!(matches!(
        &results[2],
        opc_session_store::SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));

    let after = store
        .max_replication_sequence()
        .await
        .expect("journal head after partial batch");
    assert_eq!(after, before.checked_add(2).expect("small journal advance"));
    let entries = store
        .get_replication_log(before + 1, 2)
        .await
        .expect("partial batch journal entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].sequence, before + 1);
    assert_eq!(entries[1].sequence, before + 2);
    assert!(matches!(
        &entries[0].op,
        ReplicationOp::CompareAndSet { key, .. } if key == &first_key
    ));
    assert!(matches!(
        &entries[1].op,
        ReplicationOp::CompareAndSet { key, .. } if key == &second_key
    ));
    assert_eq!(
        store.get(&first_key).await.expect("first record read"),
        Some(first_record)
    );
    assert_eq!(
        store.get(&second_key).await.expect("second record read"),
        Some(second_record)
    );
}

#[tokio::test]
async fn encryption_wrapper_keeps_plaintext_above_consensus_and_durable_authority() {
    let cluster = TestCluster::start().await;
    let provider = encryption_provider();
    let writer = EncryptingSessionBackend::new(
        Arc::new(cluster.stores[0].clone()),
        Arc::clone(&provider),
        ENCRYPTION_NAMESPACE,
    );

    let before_key = session_key(b"encryption-boundary-before-rotation");
    let before_lease = writer
        .acquire(
            &before_key,
            owner("encryption-boundary-owner-before"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire pre-rotation lease");
    cluster.clear_captured_payloads();
    assert_eq!(
        writer
            .compare_and_set(CompareAndSet {
                key: before_key.clone(),
                lease: before_lease.clone(),
                expected_generation: None,
                new_record: plaintext_record(
                    before_key.clone(),
                    1,
                    &before_lease,
                    PLAINTEXT_CANARY_BEFORE_ROTATION,
                ),
            })
            .await
            .expect("write plaintext through encryption adapter"),
        CompareAndSetResult::Success
    );

    provider
        .rotate_key(
            KeyPurpose::Session,
            &TenantId::new("consensus-test-tenant").expect("tenant"),
        )
        .await
        .expect("rotate active data key");

    let after_key = session_key(b"encryption-boundary-after-rotation");
    let after_lease = writer
        .acquire(
            &after_key,
            owner("encryption-boundary-owner-after"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire post-rotation lease");
    assert_eq!(
        writer
            .compare_and_set(CompareAndSet {
                key: after_key.clone(),
                lease: after_lease.clone(),
                expected_generation: None,
                new_record: plaintext_record(
                    after_key.clone(),
                    1,
                    &after_lease,
                    PLAINTEXT_CANARY_AFTER_ROTATION,
                ),
            })
            .await
            .expect("write with rotated data key"),
        CompareAndSetResult::Success
    );
    assert_eq!(provider.call_counts(), (2, 0, 1));

    for store in &cluster.stores {
        for (key, plaintext) in [
            (&before_key, PLAINTEXT_CANARY_BEFORE_ROTATION),
            (&after_key, PLAINTEXT_CANARY_AFTER_ROTATION),
        ] {
            let record = store
                .get(key)
                .await
                .expect("linearizable raw read")
                .expect("raw record");
            assert_eq!(
                record.payload.encoding(),
                SessionPayloadEncoding::EnvelopeV1
            );
            assert!(!contains_bytes(record.payload.as_bytes(), plaintext));
        }
    }
    assert_eq!(
        provider.call_counts(),
        (2, 0, 1),
        "consensus and raw durable reads must not call the key provider"
    );

    for store in &cluster.stores {
        let reader = EncryptingSessionBackend::new(
            Arc::new(store.clone()),
            Arc::clone(&provider),
            ENCRYPTION_NAMESPACE,
        );
        for (key, expected) in [
            (&before_key, PLAINTEXT_CANARY_BEFORE_ROTATION),
            (&after_key, PLAINTEXT_CANARY_AFTER_ROTATION),
        ] {
            let record = reader
                .get(key)
                .await
                .expect("decrypt through outer adapter")
                .expect("decrypted record");
            assert_eq!(record.payload.encoding(), SessionPayloadEncoding::Plaintext);
            assert_eq!(record.payload.as_bytes(), expected);
        }
    }
    assert_eq!(provider.call_counts(), (2, MEMBER_COUNT * 2, 1));

    let captured_payloads = cluster.captured_payloads();
    assert!(
        !captured_payloads.is_empty(),
        "qualification must observe replicated consensus traffic"
    );
    for payload in captured_payloads {
        assert_artifact_bytes_are_sealed("consensus RPC payload", &payload);
    }
    for index in 0..MEMBER_COUNT {
        assert_sqlite_authority_is_sealed(
            &cluster
                ._directory
                .path()
                .join(format!("node-{index}.sqlite")),
        );
    }
    assert_file_tree_is_sealed(cluster._directory.path());
}

#[tokio::test]
async fn writes_leases_and_cas_converge_with_linearizable_reads() {
    let cluster = TestCluster::start().await;
    let key = session_key(b"cross-node-cas");
    let lease = cluster.stores[1]
        .acquire(&key, owner("owner-a"), Duration::from_secs(30))
        .await
        .expect("acquire through node 1");
    let initial = sealed_record(key.clone(), 1, &lease, b"sealed-v1");

    assert_eq!(
        cluster.stores[2]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: initial,
            })
            .await
            .expect("CAS through node 2"),
        CompareAndSetResult::Success
    );

    let renewed = cluster.stores[0]
        .renew(&lease, Duration::from_secs(30))
        .await
        .expect("renew through node 0");
    let updated = sealed_record(key.clone(), 2, &renewed, b"sealed-v2");
    assert_eq!(
        cluster.stores[1]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: renewed,
                expected_generation: Some(Generation::new(1)),
                new_record: updated.clone(),
            })
            .await
            .expect("update through node 1"),
        CompareAndSetResult::Success
    );

    let reads =
        futures_util::future::join_all(cluster.stores.iter().map(|store| store.get(&key))).await;
    for read in reads {
        assert_eq!(
            read.expect("linearizable read from every node"),
            Some(updated.clone())
        );
    }

    let logs = replication_logs(&cluster).await;
    assert!(logs.windows(2).all(|pair| pair[0] == pair[1]));
    let authoritative_entry = logs[0][0].clone();
    assert!(matches!(
        cluster.stores[0]
            .replicate_entry(authoritative_entry)
            .await,
        Err(StoreError::CapabilityNotSupported(capability))
            if capability == "direct_replication_authority"
    ));
    assert!(matches!(
        cluster.stores[0]
            .rebuild_replication_state(logs[0].clone())
            .await,
        Err(StoreError::CapabilityNotSupported(capability))
            if capability == "direct_rebuild_authority"
    ));
    assert_differing_replica_compaction_floors_never_union(&cluster).await;
}

#[tokio::test]
async fn cold_start_concurrent_mutations_share_one_gap_free_committed_sequence() {
    let cluster = TestCluster::start().await;
    let keys = [
        session_key(b"cold-start-a"),
        session_key(b"cold-start-b"),
        session_key(b"cold-start-c"),
    ];
    let acquisitions = futures_util::future::join_all((0..MEMBER_COUNT).map(|index| {
        cluster.stores[index].acquire(
            &keys[index],
            owner(format!("cold-owner-{index}")),
            Duration::from_secs(30),
        )
    }))
    .await;
    let leases = acquisitions
        .into_iter()
        .map(|result| result.expect("concurrent cold-start lease"))
        .collect::<Vec<_>>();

    let writes = futures_util::future::join_all((0..MEMBER_COUNT).map(|index| {
        cluster.stores[(index + 1) % MEMBER_COUNT].compare_and_set(CompareAndSet {
            key: keys[index].clone(),
            lease: leases[index].clone(),
            expected_generation: None,
            new_record: sealed_record(keys[index].clone(), 1, &leases[index], b"sealed-cold-start"),
        })
    }))
    .await;
    for result in writes {
        assert_eq!(
            result.expect("concurrent cold-start CAS"),
            CompareAndSetResult::Success
        );
    }

    let logs = replication_logs(&cluster).await;
    assert_eq!(logs[0].len(), MEMBER_COUNT * 2);
    assert!(logs.windows(2).all(|pair| pair[0] == pair[1]));
    for (offset, entry) in logs[0].iter().enumerate() {
        assert_eq!(
            entry.sequence,
            u64::try_from(offset + 1).expect("test index")
        );
        assert!(entry.tx_id.is_canonical());
        assert_eq!(
            entry.tx_id.len(),
            opc_session_store::REPLICATION_TX_ID_CANONICAL_BYTES
        );
    }
    let transaction_ids = logs[0]
        .iter()
        .map(|entry| entry.tx_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(transaction_ids.len(), logs[0].len());
}

#[tokio::test]
async fn restore_pages_use_only_linearizable_applied_state_and_fail_closed_when_stale() {
    // This test proves healthy linearizable paging and cursor invalidation
    // across isolate/heal. Use the production operation budget so concurrent
    // snapshot and SQLite qualification work cannot turn the stale-cursor
    // assertion into a scheduler-induced, correctly typed work-budget error.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;

    for label in [b"restore-a".as_slice(), b"restore-b", b"restore-c"] {
        let key = session_key(label);
        let lease = cluster.stores[0]
            .acquire(
                &key,
                owner(format!(
                    "restore-owner-{}",
                    char::from(label[label.len() - 1])
                )),
                Duration::from_secs(30),
            )
            .await
            .expect("acquire restore-test lease through the fleet");
        assert_eq!(
            cluster.stores[1]
                .compare_and_set(CompareAndSet {
                    key: key.clone(),
                    lease: lease.clone(),
                    expected_generation: None,
                    new_record: sealed_record(key, 1, &lease, b"sealed-restore-state"),
                })
                .await
                .expect("commit restore-test record through the fleet"),
            CompareAndSetResult::Success
        );
    }

    let first_pages = futures_util::future::join_all(
        cluster
            .stores
            .iter()
            .map(|store| store.scan_restore_records(RestoreScanRequest::all(2))),
    )
    .await
    .into_iter()
    .map(|page| page.expect("linearizable first restore page"))
    .collect::<Vec<_>>();
    assert_eq!(first_pages[0].records.len(), 2);
    assert!(!first_pages[0].complete);
    assert!(first_pages
        .iter()
        .all(|page| page.records == first_pages[0].records));

    let stale_cursor = first_pages[0]
        .next_cursor
        .clone()
        .expect("bounded first page has a continuation");
    for (store, first_page) in cluster.stores.iter().zip(&first_pages) {
        let second = store
            .scan_restore_records(RestoreScanRequest {
                cursor: first_page.next_cursor.clone(),
                ..RestoreScanRequest::all(2)
            })
            .await
            .expect("linearizable second restore page");
        assert_eq!(second.records.len(), 1);
        assert!(second.complete);
        assert_eq!(second.records[0].key.stable_id.as_ref(), b"restore-c");
    }

    cluster.isolate(0);
    let isolated = tokio::time::timeout(
        DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT + RECOVERY_TIMEOUT,
        cluster.stores[0].scan_restore_records(RestoreScanRequest::all(1)),
    )
    .await
    .expect("isolated restore attempt is bounded");
    assert!(matches!(isolated, Err(StoreError::BackendUnavailable(_))));

    cluster.heal(0);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("healed node regains linearizable restore authority");

    let new_key = session_key(b"restore-d");
    let new_lease = cluster.stores[2]
        .acquire(&new_key, owner("restore-owner-d"), Duration::from_secs(30))
        .await
        .expect("acquire lease after restore cursor publication");
    assert_eq!(
        cluster.stores[1]
            .compare_and_set(CompareAndSet {
                key: new_key.clone(),
                lease: new_lease.clone(),
                expected_generation: None,
                new_record: sealed_record(new_key, 1, &new_lease, b"sealed-restore-state"),
            })
            .await
            .expect("commit record after restore cursor publication"),
        CompareAndSetResult::Success
    );

    let stale = cluster.stores[0]
        .scan_restore_records(RestoreScanRequest {
            cursor: Some(stale_cursor),
            ..RestoreScanRequest::all(2)
        })
        .await
        .expect_err("record mutation must invalidate an older restore snapshot");
    assert_eq!(stale, StoreError::RestoreScanCursorStale);

    let restarted = cluster.stores[0]
        .scan_restore_records(RestoreScanRequest::all(4))
        .await
        .expect("restart from the first page after a stale cursor");
    assert_eq!(restarted.records.len(), 4);
    assert!(restarted.complete);
}

#[tokio::test]
async fn isolated_node_fails_closed_and_recovers_after_both_peer_paths_heal() {
    let cluster = TestCluster::start().await;
    cluster.isolate(0);

    let probe_started = Instant::now();
    let report = tokio::time::timeout(
        Duration::from_secs(2),
        cluster.stores[0].probe_durable_readiness(),
    )
    .await
    .expect("readiness probe is bounded");
    assert_eq!(report.state(), DurableReadinessState::NoQuorum);
    assert_eq!(
        report.recovery_progress().state(),
        DurableRecoveryState::AwaitingQuorum
    );
    assert_eq!(report.recovery_progress().reason_code(), "awaiting_quorum");
    assert!(
        report.recovery_progress().local_applied_index()
            <= report.recovery_progress().local_log_index()
    );
    assert!(probe_started.elapsed() < Duration::from_secs(2));

    let key = session_key(b"partitioned-write");
    let mutation_started = Instant::now();
    let mutation = tokio::time::timeout(
        Duration::from_secs(2),
        cluster.stores[0].acquire(&key, owner("isolated-owner"), Duration::from_secs(30)),
    )
    .await
    .expect("partitioned mutation is bounded");
    assert!(
        mutation.is_err(),
        "isolated node must not acknowledge a write"
    );
    assert!(mutation_started.elapsed() < Duration::from_secs(2));

    cluster.heal(0);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("healed node rejoins fresh readiness");
    let healed_report = cluster.stores[0].probe_durable_readiness().await;
    assert_eq!(healed_report.state(), DurableReadinessState::Ready);
    assert_eq!(
        healed_report.recovery_progress().state(),
        DurableRecoveryState::Synchronized
    );
    assert!(
        healed_report.recovery_progress().local_applied_index()
            >= healed_report.committed_barrier_index()
    );
    cluster.stores[0]
        .acquire(&key, owner("healed-owner"), Duration::from_secs(30))
        .await
        .expect("mutation succeeds after healing");
}

#[tokio::test]
async fn observed_leader_loss_elects_a_different_higher_term_leader_and_recovers() {
    let _timing_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("qualification semaphore remains open");
    let cluster = TestCluster::start().await;
    let (old_leader_index, old_leader_id, old_term) = cluster.observed_leader();
    cluster.isolate(old_leader_index);
    let survivors = (0..MEMBER_COUNT)
        .filter(|index| *index != old_leader_index)
        .collect::<Vec<_>>();
    let recovery_deadline = tokio::time::Instant::now() + RECOVERY_TIMEOUT;

    let (new_leader_id, new_term) = tokio::time::timeout_at(recovery_deadline, async {
        loop {
            let statuses = survivors
                .iter()
                .map(|index| cluster.stores[*index].status())
                .collect::<Vec<_>>();
            if let Some(new_leader_id) = statuses.first().and_then(|status| status.leader_id) {
                let new_term = statuses.first().expect("survivor status").term;
                if new_leader_id != old_leader_id
                    && new_term > old_term
                    && statuses.iter().all(|status| {
                        status.leader_id == Some(new_leader_id) && status.term == new_term
                    })
                {
                    break (new_leader_id, new_term);
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("surviving majority elects a different higher-term leader");
    assert_ne!(new_leader_id, old_leader_id);
    assert!(new_term > old_term);

    tokio::time::timeout_at(recovery_deadline, async {
        loop {
            let reports = futures_util::future::join_all(
                survivors
                    .iter()
                    .map(|index| cluster.stores[*index].probe_durable_readiness()),
            )
            .await;
            if reports.iter().all(DurableReadinessReport::is_ready) {
                let statuses = survivors
                    .iter()
                    .map(|index| cluster.stores[*index].status())
                    .collect::<Vec<_>>();
                if statuses.iter().all(|status| {
                    status.leader_id == Some(new_leader_id) && status.term == new_term
                }) {
                    break;
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("surviving majority reaches durable readiness after leader election");

    let key = session_key(b"observed-leader-loss");
    let lease = cluster.stores[survivors[0]]
        .acquire(&key, owner("post-failover-owner"), Duration::from_secs(30))
        .await
        .expect("survivor quorum accepts a lease after leader loss");
    let committed = sealed_record(key.clone(), 1, &lease, b"sealed-post-failover");
    assert_eq!(
        CompareAndSetResult::Success,
        cluster.stores[survivors[1]]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: committed.clone(),
            })
            .await
            .expect("survivor quorum commits after leader loss")
    );

    cluster.heal(old_leader_index);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("old leader catches up after rejoining");
    for store in &cluster.stores {
        assert_eq!(
            Some(committed.clone()),
            store.get(&key).await.expect("rejoined fleet converges")
        );
    }
}

#[tokio::test]
async fn lagging_replica_installs_compacted_snapshot_without_losing_committed_state() {
    let _timing_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("qualification semaphore remains open");
    let cluster = TestCluster::start().await;
    let lagging_before = cluster.stores[0]
        .probe_durable_readiness()
        .await
        .recovery_progress()
        .local_applied_index()
        .expect("lagging node initial applied index");
    cluster.isolate(0);
    tokio::time::timeout(SNAPSHOT_RECOVERY_TIMEOUT, async {
        loop {
            let reports = futures_util::future::join_all(
                cluster.stores[1..]
                    .iter()
                    .map(ConsensusSessionStore::probe_durable_readiness),
            )
            .await;
            if reports.iter().all(DurableReadinessReport::is_ready) {
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("surviving majority elects a current leader");

    let key = session_key(b"snapshot-catch-up-committed-record");
    let lease = cluster.stores[1]
        .acquire(
            &key,
            owner("snapshot-catch-up-owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("majority commits lease while follower is isolated");
    let committed_record = sealed_record(key.clone(), 1, &lease, b"sealed-snapshot-catch-up");
    assert_eq!(
        CompareAndSetResult::Success,
        cluster.stores[2]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: committed_record.clone(),
            })
            .await
            .expect("majority commits record while follower is isolated")
    );

    for _ in 0..SNAPSHOT_CATCH_UP_COMMANDS {
        cluster.stores[1]
            .max_replication_sequence()
            .await
            .expect("advance committed logical time toward snapshot compaction");
    }

    let compacted = tokio::time::timeout(SNAPSHOT_RECOVERY_TIMEOUT, async {
        loop {
            let progress = cluster.stores[1]
                .probe_durable_readiness()
                .await
                .recovery_progress();
            if progress
                .purged_index()
                .is_some_and(|index| index > lagging_before)
                && progress.snapshot_index().is_some()
            {
                break progress;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("majority compacts beyond the isolated follower");

    cluster.heal(0);
    if cluster
        .wait_all_ready(SNAPSHOT_RECOVERY_TIMEOUT)
        .await
        .is_err()
    {
        let reports = futures_util::future::join_all(
            cluster
                .stores
                .iter()
                .map(ConsensusSessionStore::probe_durable_readiness),
        )
        .await;
        let sqlite = consensus_sqlite_progress(&cluster._directory.path().join("node-0.sqlite"));
        panic!(
            "lagging follower did not rejoin after snapshot install: {reports:?}; sqlite={sqlite:?}"
        );
    }
    let recovered = cluster.stores[0]
        .get(&key)
        .await
        .expect("linearizable read after snapshot catch-up");
    assert_eq!(Some(committed_record), recovered);
    let recovered_progress = cluster.stores[0]
        .probe_durable_readiness()
        .await
        .recovery_progress();
    assert_eq!(
        DurableRecoveryState::Synchronized,
        recovered_progress.state()
    );
    assert!(recovered_progress.local_applied_index() >= compacted.snapshot_index());
}

#[tokio::test]
async fn repeated_lost_forward_responses_retry_one_request_without_duplicate_event() {
    // This test deliberately consumes more retry backoffs than the member
    // count. Use the production operation budget so concurrent snapshot and
    // SQLite qualification work cannot turn the success-path assertion into
    // a scheduler-induced, correctly typed deadline ambiguity.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;

    for source in 0..MEMBER_COUNT {
        let key = session_key(format!("lost-response-{source}").as_bytes());
        let lease = cluster.stores[source]
            .acquire(
                &key,
                owner(format!("lost-response-owner-{source}")),
                Duration::from_secs(30),
            )
            .await
            .expect("prepare lease before response loss");
        let before = cluster.stores[source]
            .max_replication_sequence()
            .await
            .expect("replication head before response loss");
        // More losses than the admitted member count proves retries are
        // deadline/backoff bounded rather than prematurely attempt bounded.
        let dropped_before = cluster.arm_forward_response_loss(source, MEMBER_COUNT + 1);

        let result = cluster.stores[source]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: sealed_record(key.clone(), 1, &lease, b"sealed-after-loss"),
            })
            .await;
        cluster.stop_forward_response_loss(source);
        let response_was_lost = cluster.dropped_forward_responses(source) > dropped_before;

        if response_was_lost {
            assert_eq!(
                result.expect("retry after delivered response loss"),
                CompareAndSetResult::Success
            );
            let after = cluster.stores[source]
                .max_replication_sequence()
                .await
                .expect("replication head after response loss");
            assert_eq!(after, before + 1);

            let logs = replication_logs(&cluster).await;
            assert!(logs.windows(2).all(|pair| pair[0] == pair[1]));
            let matching_events = logs[0]
                .iter()
                .filter(|entry| {
                    matches!(
                        &entry.op,
                        ReplicationOp::CompareAndSet { key: event_key, .. }
                            if event_key == &key
                    )
                })
                .count();
            assert_eq!(matching_events, 1);
            return;
        }

        assert_eq!(
            result.expect("local leader CAS"),
            CompareAndSetResult::Success
        );
    }

    panic!("no follower path was exercised while response loss was armed");
}

#[tokio::test]
async fn committed_write_with_a_late_forward_result_is_typed_ambiguous_and_applied_once() {
    let cluster = TestCluster::start().await;

    for source in 0..MEMBER_COUNT {
        let key = session_key(format!("late-result-{source}").as_bytes());
        let lease = cluster.stores[source]
            .acquire(
                &key,
                owner(format!("late-result-owner-{source}")),
                Duration::from_secs(30),
            )
            .await
            .expect("prepare lease before late result");
        let before = cluster.stores[source]
            .max_replication_sequence()
            .await
            .expect("replication head before late result");
        let delayed_before = cluster
            .arm_forward_response_delay(source, OPERATION_TIMEOUT + Duration::from_millis(250));
        let expected = sealed_record(key.clone(), 1, &lease, b"sealed-late-result");

        let result = cluster.stores[source]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: expected.clone(),
            })
            .await;
        cluster.stop_forward_response_delay(source);
        let response_was_delayed = cluster.delayed_forward_responses(source) > delayed_before;

        if response_was_delayed {
            assert_eq!(result, Err(StoreError::CasIdempotencyOutcomeUnavailable));
            let committed = cluster.stores[source]
                .get(&key)
                .await
                .expect("linearizable read after late result");
            assert_eq!(committed, Some(expected));
            let after = cluster.stores[source]
                .max_replication_sequence()
                .await
                .expect("replication head after late result");
            assert_eq!(after, before + 1);

            let logs = replication_logs(&cluster).await;
            assert!(logs.windows(2).all(|pair| pair[0] == pair[1]));
            let matching_events = logs[0]
                .iter()
                .filter(|entry| {
                    matches!(
                        &entry.op,
                        ReplicationOp::CompareAndSet { key: event_key, .. }
                            if event_key == &key
                    )
                })
                .count();
            assert_eq!(matching_events, 1);
            return;
        }

        assert_eq!(
            result.expect("local leader CAS"),
            CompareAndSetResult::Success
        );
    }

    panic!("no follower path was exercised while forward results were delayed");
}
