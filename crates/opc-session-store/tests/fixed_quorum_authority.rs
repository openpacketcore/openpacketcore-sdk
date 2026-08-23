use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use opc_session_store::{
    derive_fixed_durable_quorum_consensus_identity, ConsensusSessionStore,
    ConsensusSessionStoreOpenError, FixedQuorumTrafficAuthority, ObservedPhysicalNodeIdentity,
    OwnerId, PlacementResilienceDisposition, PlacementResiliencePolicy, QuorumReplicaDescriptor,
    QuorumTopologyAttestor, QuorumTopologyConfig, QuorumTopologyError, QuorumTopologyMode,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    SessionBackend, SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionConsumerAuthorizationGrant, SessionConsumerIdentity, SessionConsumerRejection,
    SessionConsumerTenantNfScope, SessionKey, SessionKeyType, SessionLeaseManager,
    SessionQuorumConsumer, SessionTopologyAbortAdmissionProof,
    SessionTopologyCandidateRetirementProof, SessionTopologyJointCommitAdmissionProof,
    SessionTopologyPrePrepareUnstageProof, SessionTopologyTransitionError,
    SessionTopologyTransitionId, SessionTopologyTransitionRequest,
    SessionTopologyTransportAdmission, SessionTopologyTransportAdmissionError,
    SessionTopologyUniformCommitAdmissionProof, SqliteSessionBackend, TopologyAttestationClaims,
    TopologyAttestationEvidence, TopologyAttestationPolicy, TopologyAttestationProvenance,
    TopologyAttestationTime, TopologyAttestationVerificationError,
    TopologyAttestationVerificationInput, TopologyCollectorId, ValidatedQuorumTopology,
};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};

fn fixed_consumer_identity() -> SessionConsumerIdentity {
    SessionConsumerIdentity::new(
        "spiffe://test/tenant/fixed-consumer/ns/default/sa/store/nf/smf/instance/one",
    )
    .expect("canonical fixed consumer identity")
}

fn fixed_consumer_grant() -> SessionConsumerAuthorizationGrant {
    SessionConsumerAuthorizationGrant::try_new(
        SpiffeId::new(
            "spiffe://test/tenant/fixed-consumer/ns/default/sa/store/nf/smf/instance/one",
        )
        .expect("canonical fixed consumer SPIFFE ID"),
        [SessionConsumerTenantNfScope::new(
            TenantId::from_static("fixed-consumer"),
            NetworkFunctionKind::smf(),
        )],
    )
    .expect("fixed consumer grant")
}

#[derive(Debug)]
struct UnscopedPeer {
    node_id: SessionConsensusNodeId,
}

#[async_trait]
impl SessionConsensusPeer for UnscopedPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node_id
    }

    async fn call(
        &self,
        _request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        Err(SessionConsensusPeerError::Unavailable)
    }
}

#[derive(Clone)]
struct ScopedLoopbackPeer {
    node_id: SessionConsensusNodeId,
    identity: ConsensusIdentity,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
}

impl ScopedLoopbackPeer {
    fn new(node_id: SessionConsensusNodeId, identity: ConsensusIdentity) -> Self {
        Self {
            node_id,
            identity,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }
}

impl fmt::Debug for ScopedLoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedLoopbackPeer")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for ScopedLoopbackPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node_id
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        Some(self.identity)
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
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

#[derive(Debug)]
struct NoopTopologyTransport;

#[async_trait]
impl SessionTopologyTransportAdmission for NoopTopologyTransport {
    async fn unstage_successor_before_prepare(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyPrePrepareUnstageProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }

    async fn retire_aborted_candidate(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyCandidateRetirementProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }

    async fn admit_successor_voting(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyJointCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }

    async fn finalize_successor(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyUniformCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }

    async fn abort_successor(
        &self,
        _request: &SessionTopologyTransitionRequest,
        _proof: &SessionTopologyAbortAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        Ok(())
    }
}

fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("fixed-voter-{index}")).expect("test replica ID")
}

fn descriptor(
    index: usize,
    failure_domain: usize,
    tls_identity: usize,
    backing_identity: usize,
) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(index),
        ReplicaEndpoint::new(format!("fixed-voter-{index}.test.invalid"), 7443)
            .expect("test endpoint"),
        ReplicaTlsIdentity::new(format!("spiffe://test/fixed-voter/{tls_identity}"))
            .expect("test TLS identity"),
        ReplicaFailureDomain::new(format!("test-failure-domain-{failure_domain}"))
            .expect("test failure domain"),
        ReplicaBackingIdentity::new(format!("test-backing-{backing_identity}"))
            .expect("test backing identity"),
    )
}

fn consensus_identity(members: &[QuorumReplicaDescriptor]) -> ConsensusIdentity {
    let cluster_id =
        ConsensusClusterId::new("fixed-quorum-authority-tests").expect("test cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("test configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let configuration_id = derive_configuration_id(cluster_id, epoch, &fingerprints);
    ConsensusIdentity::new(cluster_id, configuration_id, epoch)
}

fn fixed_consensus_identity(
    members: &[QuorumReplicaDescriptor],
    placement_policy: PlacementResiliencePolicy,
) -> ConsensusIdentity {
    let cluster_id =
        ConsensusClusterId::new("fixed-quorum-authority-tests").expect("test cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("test configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    derive_fixed_durable_quorum_consensus_identity(
        cluster_id,
        epoch,
        &fingerprints,
        placement_policy,
    )
}

fn fixed_topology(
    members: Vec<QuorumReplicaDescriptor>,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    fixed_topology_with_policy(members, PlacementResiliencePolicy::default())
}

fn fixed_topology_with_policy(
    members: Vec<QuorumReplicaDescriptor>,
    placement_policy: PlacementResiliencePolicy,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    fixed_topology_for_local(0, members, placement_policy)
}

fn fixed_topology_for_local(
    local_index: usize,
    members: Vec<QuorumReplicaDescriptor>,
    placement_policy: PlacementResiliencePolicy,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
        QuorumTopologyConfig::new_consensus(
            replica_id(local_index),
            members.clone(),
            fixed_consensus_identity(&members, placement_policy),
        ),
        placement_policy,
    )
}

#[tokio::test]
async fn fixed_placement_policy_changes_authenticated_scope_before_durable_open() {
    for voter_count in [3, 5] {
        let members = fixed_members(voter_count);
        let strict = fixed_topology_for_local(
            0,
            members.clone(),
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
        )
        .expect("strict fixed topology");
        let reduced = fixed_topology_for_local(
            0,
            members,
            PlacementResiliencePolicy::AllowReducedResilience,
        )
        .expect("reduced fixed topology");

        assert_ne!(
            strict.consensus_identity(),
            reduced.consensus_identity(),
            "fixed {voter_count}-voter policies must not share an authenticated scope"
        );
        let dynamic_members = fixed_members(voter_count);
        let dynamic = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
            replica_id(0),
            dynamic_members.clone(),
            consensus_identity(&dynamic_members),
        ))
        .expect("dynamic topology");
        assert_ne!(
            strict.consensus_identity(),
            dynamic.consensus_identity(),
            "fixed {voter_count}-voter authority must not share the dynamic profile scope"
        );

        let directory = tempfile::tempdir().expect("fixed policy test directory");
        let database_path = directory.path().join("voter.sqlite");
        let result = ConsensusSessionStore::open_fixed_durable_quorum(
            strict.clone(),
            SqliteSessionBackend::open(&database_path).expect("file-backed voter store"),
            directory.path().join("snapshots"),
            scoped_peers(&reduced),
        )
        .await;
        assert!(matches!(
            result,
            Err(ConsensusSessionStoreOpenError::PeerSetMismatch)
        ));

        let connection = rusqlite::Connection::open(database_path).expect("open voter database");
        let durable_raft_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'consensus_identity'",
                [],
                |row| row.get(0),
            )
            .expect("query durable raft schema");
        assert_eq!(
            durable_raft_rows, 0,
            "mixed policies must fail before durable Raft initialization"
        );

        let dynamic_database_path = directory.path().join("dynamic-voter.sqlite");
        let dynamic_result = ConsensusSessionStore::open_fixed_durable_quorum(
            strict,
            SqliteSessionBackend::open(&dynamic_database_path).expect("file-backed voter store"),
            directory.path().join("dynamic-snapshots"),
            scoped_peers(&dynamic),
        )
        .await;
        assert!(matches!(
            dynamic_result,
            Err(ConsensusSessionStoreOpenError::PeerSetMismatch)
        ));
    }
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn fixed_durable_quorum_rejects_unsupported_platform_before_durable_initialization() {
    let members = fixed_members(3);
    let topology = fixed_topology(members).expect("fixed topology admission");
    let directory = tempfile::tempdir().expect("fixed platform test directory");
    let database_path = directory.path().join("voter.sqlite");

    let result = ConsensusSessionStore::open_fixed_durable_quorum(
        topology.clone(),
        SqliteSessionBackend::open(&database_path).expect("file-backed voter store"),
        directory.path().join("snapshots"),
        scoped_peers(&topology),
    )
    .await;
    assert!(matches!(
        result,
        Err(ConsensusSessionStoreOpenError::FixedQuorumUnsupportedPlatform)
    ));

    let connection = rusqlite::Connection::open(database_path).expect("open voter database");
    let durable_raft_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'consensus_identity'",
            [],
            |row| row.get(0),
        )
        .expect("query durable raft schema");
    assert_eq!(
        durable_raft_rows, 0,
        "unsupported fixed quorum must fail before durable Raft initialization"
    );
}

fn fixed_members(count: usize) -> Vec<QuorumReplicaDescriptor> {
    (0..count)
        .map(|index| descriptor(index, index, index, index))
        .collect()
}

fn scoped_peers(
    topology: &ValidatedQuorumTopology,
) -> BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>> {
    let local_node_id = topology
        .local_consensus_node_id()
        .expect("fixed local node ID");
    let identity = topology.consensus_identity().expect("consensus identity");
    topology
        .members()
        .iter()
        .filter_map(|member| topology.consensus_node_id(member.replica_id()))
        .filter(|node_id| *node_id != local_node_id)
        .map(|node_id| {
            let peer: Arc<dyn SessionConsensusPeer> =
                Arc::new(ScopedLoopbackPeer::new(node_id, identity));
            (node_id, peer)
        })
        .collect()
}

async fn open_fixed_cluster(
    member_count: usize,
    placement_policy: PlacementResiliencePolicy,
) -> (tempfile::TempDir, Vec<PathBuf>, Vec<ConsensusSessionStore>) {
    let (directory, database_paths, stores, _) =
        open_fixed_cluster_with_paths(member_count, placement_policy).await;
    (directory, database_paths, stores)
}

async fn open_fixed_cluster_with_members(
    members: Vec<QuorumReplicaDescriptor>,
    placement_policy: PlacementResiliencePolicy,
) -> (tempfile::TempDir, Vec<ConsensusSessionStore>) {
    let member_count = members.len();
    let directory = tempfile::tempdir().expect("fixed cluster directory");
    let identity = fixed_consensus_identity(&members, placement_policy);
    let topologies = (0..member_count)
        .map(|index| {
            fixed_topology_for_local(index, members.clone(), placement_policy)
                .map(|topology| (index, topology))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("fixed cluster topologies");
    let node_ids = topologies
        .iter()
        .map(|(_, topology)| {
            topology
                .local_consensus_node_id()
                .expect("fixed local node ID")
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..member_count {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }
    let mut stores = Vec::new();
    for (source, topology) in topologies {
        let peers = (0..member_count)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("fixed scoped path")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        stores.push(
            ConsensusSessionStore::open_fixed_durable_quorum(
                topology,
                SqliteSessionBackend::open(directory.path().join(format!("voter-{source}.sqlite")))
                    .expect("file-backed voter store"),
                directory.path().join(format!("snapshots-{source}")),
                peers,
            )
            .await
            .expect("open fixed cluster voter"),
        );
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed cluster membership");
    }
    (directory, stores)
}

async fn open_fixed_cluster_with_paths(
    member_count: usize,
    placement_policy: PlacementResiliencePolicy,
) -> (
    tempfile::TempDir,
    Vec<PathBuf>,
    Vec<ConsensusSessionStore>,
    BTreeMap<(usize, usize), Arc<ScopedLoopbackPeer>>,
) {
    let directory = tempfile::tempdir().expect("fixed cluster directory");
    let (database_paths, stores, paths) =
        open_fixed_cluster_in_with_paths(directory.path(), member_count, placement_policy).await;
    (directory, database_paths, stores, paths)
}

async fn open_fixed_cluster_in(
    directory: &std::path::Path,
    member_count: usize,
    placement_policy: PlacementResiliencePolicy,
) -> (Vec<PathBuf>, Vec<ConsensusSessionStore>) {
    let (database_paths, stores, _) =
        open_fixed_cluster_in_with_paths(directory, member_count, placement_policy).await;
    (database_paths, stores)
}

async fn open_fixed_cluster_in_with_paths(
    directory: &std::path::Path,
    member_count: usize,
    placement_policy: PlacementResiliencePolicy,
) -> (
    Vec<PathBuf>,
    Vec<ConsensusSessionStore>,
    BTreeMap<(usize, usize), Arc<ScopedLoopbackPeer>>,
) {
    let members = fixed_members(member_count);
    let identity = fixed_consensus_identity(&members, placement_policy);
    let topologies = (0..member_count)
        .map(|index| {
            fixed_topology_for_local(index, members.clone(), placement_policy)
                .map(|topology| (index, topology))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("fixed cluster topologies");
    let database_paths = (0..member_count)
        .map(|index| directory.join(format!("fixed-voter-{index}.sqlite")))
        .collect::<Vec<_>>();
    let node_ids = topologies
        .iter()
        .map(|(_, topology)| {
            topology
                .local_consensus_node_id()
                .expect("fixed local node ID")
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..member_count {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }
    let mut stores = Vec::new();
    for (source, topology) in topologies {
        let peers = (0..member_count)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("fixed scoped path")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        let store = ConsensusSessionStore::open_fixed_durable_quorum(
            topology,
            SqliteSessionBackend::open(&database_paths[source]).expect("file-backed voter store"),
            directory.join(format!("snapshots-{source}")),
            peers,
        )
        .await
        .expect("open fixed cluster voter");
        stores.push(store);
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed cluster membership");
    }
    (database_paths, stores, paths)
}

fn successor_request(identity: ConsensusIdentity) -> SessionTopologyTransitionRequest {
    SessionTopologyTransitionRequest::try_new(
        SessionTopologyTransitionId::from_bytes([0x71; 16]),
        identity.cluster_id(),
        identity.configuration_epoch(),
        ConsensusConfigurationEpoch::new(2).expect("successor epoch"),
        fixed_members(3),
        Duration::from_secs(1),
    )
    .expect("valid successor request")
}

fn fixed_attested_topology(
    local_index: usize,
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    evidence: Vec<TopologyAttestationEvidence>,
    policy: &TopologyAttestationPolicy,
    admitted_at: TopologyAttestationTime,
) -> ValidatedQuorumTopology {
    ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_authenticated_placement(
        QuorumTopologyConfig::new_consensus(replica_id(local_index), members.to_vec(), identity),
        PlacementResiliencePolicy::default(),
        evidence,
        policy,
        &DigestTopologyAttestor,
        admitted_at,
    )
    .expect("fixed authenticated placement topology")
}

fn authenticated_placement_evidence(
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
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
                ObservedPhysicalNodeIdentity::new(format!("fixed-physical-node-{index}"))
                    .expect("physical node identity"),
                descriptor.failure_domain().clone(),
                descriptor.backing_identity().clone(),
                descriptor.configuration_fingerprint(),
                identity,
                collector.clone(),
                TopologyAttestationProvenance::AuthenticatedPlatform,
                observed_at,
                expires_at,
            );
            let proof = claims.canonical_digest().to_vec();
            TopologyAttestationEvidence::try_new(claims, proof).expect("bounded placement evidence")
        })
        .collect()
}

#[test]
fn fixed_quorum_authority_and_placement_resilience_are_separate_typed_results() {
    let authority = FixedQuorumTrafficAuthority::Granted;
    let strict = PlacementResiliencePolicy::default().evaluate_unverified();
    let reduced = PlacementResiliencePolicy::AllowReducedResilience.evaluate_unverified();

    assert!(authority.is_granted());
    assert_eq!(
        strict.disposition(),
        PlacementResilienceDisposition::IndependentPlacementWithheld,
    );
    assert_eq!(
        reduced.disposition(),
        PlacementResilienceDisposition::ReducedResilience,
    );
    assert!(!reduced.disposition().is_independent_placement_qualified());
}

#[test]
fn fixed_durable_quorum_admits_correlated_descriptors_without_claiming_independence() {
    let members = (0..3)
        .map(|index| descriptor(index, 0, index, index))
        .collect::<Vec<_>>();

    let strict = fixed_topology(members.clone());
    assert!(matches!(
        strict,
        Err(QuorumTopologyError::DuplicateFailureDomain)
    ));

    let fixed = fixed_topology_with_policy(
        members.clone(),
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .expect("fixed topology admission");
    assert_eq!(
        fixed.summary().mode(),
        QuorumTopologyMode::FixedDurableQuorum,
    );
    assert_eq!(fixed.summary().configured_members(), 3);
    assert_eq!(
        fixed.summary().fixed_durable_placement_policy(),
        Some(PlacementResiliencePolicy::AllowReducedResilience),
    );

    let descriptor_only = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
        replica_id(0),
        members.clone(),
        consensus_identity(&members),
    ));
    assert!(matches!(
        descriptor_only,
        Err(QuorumTopologyError::DuplicateFailureDomain)
    ));
}

#[tokio::test]
async fn reduced_policy_forms_a_live_correlated_fixed_three_voter_quorum() {
    let members = (0..3)
        .map(|index| descriptor(index, 0, index, index))
        .collect::<Vec<_>>();
    assert!(matches!(
        fixed_topology_with_policy(
            members.clone(),
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
        ),
        Err(QuorumTopologyError::DuplicateFailureDomain)
    ));

    let (_directory, stores) =
        open_fixed_cluster_with_members(members, PlacementResiliencePolicy::AllowReducedResilience)
            .await;
    let readiness = stores[0]
        .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
        .await;
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        readiness.placement_resilience().disposition(),
        PlacementResilienceDisposition::ReducedResilience,
    );
}

#[test]
fn fixed_durable_quorum_requires_exact_three_or_five_voters() {
    for count in [1_usize, 4, 7] {
        let members = (0..count)
            .map(|index| descriptor(index, index, index, index))
            .collect::<Vec<_>>();
        assert!(matches!(
            fixed_topology(members),
            Err(QuorumTopologyError::FixedQuorumMemberCount { configured }) if configured == count
        ));
    }
}

#[test]
fn fixed_durable_quorum_keeps_authenticated_identity_and_backing_bindings_distinct() {
    let duplicate_tls = vec![
        descriptor(0, 0, 0, 0),
        descriptor(1, 1, 0, 1),
        descriptor(2, 2, 2, 2),
    ];
    assert!(matches!(
        fixed_topology(duplicate_tls),
        Err(QuorumTopologyError::DuplicateTlsIdentity)
    ));

    let duplicate_backing = vec![
        descriptor(0, 0, 0, 0),
        descriptor(1, 1, 1, 0),
        descriptor(2, 2, 2, 2),
    ];
    assert!(matches!(
        fixed_topology(duplicate_backing),
        Err(QuorumTopologyError::DuplicateBackingIdentity)
    ));
}

#[test]
fn fixed_quorum_rejections_redact_descriptor_values() {
    let canary = "fixed-quorum-redaction-canary";
    let members = vec![
        QuorumReplicaDescriptor::new(
            replica_id(0),
            ReplicaEndpoint::new(format!("{canary}.test.invalid"), 7443).expect("test endpoint"),
            ReplicaTlsIdentity::new(format!("spiffe://test/{canary}")).expect("test TLS identity"),
            ReplicaFailureDomain::new(canary).expect("test failure domain"),
            ReplicaBackingIdentity::new(canary).expect("test backing identity"),
        ),
        QuorumReplicaDescriptor::new(
            replica_id(1),
            ReplicaEndpoint::new("second.test.invalid", 7443).expect("test endpoint"),
            ReplicaTlsIdentity::new("spiffe://test/second").expect("test TLS identity"),
            ReplicaFailureDomain::new("test-failure-domain-second").expect("test failure domain"),
            ReplicaBackingIdentity::new(canary).expect("test backing identity"),
        ),
        descriptor(2, 2, 2, 2),
    ];
    let error = match fixed_topology(members) {
        Err(error) => error,
        Ok(_) => panic!("duplicate backing must be rejected"),
    };

    assert_eq!(error, QuorumTopologyError::DuplicateBackingIdentity);
    assert!(!format!("{error:?}").contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[tokio::test]
async fn fixed_durable_quorum_rejects_unscoped_peer_before_engine_start() {
    let members = (0..3)
        .map(|index| descriptor(index, index, index, index))
        .collect::<Vec<_>>();
    let topology = fixed_topology(members).expect("fixed topology admission");
    let local_node_id = topology
        .local_consensus_node_id()
        .expect("fixed local node ID");
    let peers = topology
        .members()
        .iter()
        .filter_map(|member| topology.consensus_node_id(member.replica_id()))
        .filter(|node_id| *node_id != local_node_id)
        .map(|node_id| {
            (
                node_id,
                Arc::new(UnscopedPeer { node_id }) as Arc<dyn SessionConsensusPeer>,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let snapshots = tempfile::tempdir().expect("snapshot directory");
    let database = snapshots.path().join("fixed-voter.sqlite");

    let result = ConsensusSessionStore::open_fixed_durable_quorum(
        topology,
        SqliteSessionBackend::open(database).expect("file-backed voter store"),
        snapshots.path(),
        peers,
    )
    .await;

    assert!(matches!(
        result,
        Err(ConsensusSessionStoreOpenError::PeerSetMismatch)
    ));
}

#[tokio::test]
async fn fixed_durable_quorum_rejects_ephemeral_storage() {
    let members = (0..3)
        .map(|index| descriptor(index, index, index, index))
        .collect::<Vec<_>>();
    let topology = fixed_topology(members).expect("fixed topology admission");
    let local_node_id = topology
        .local_consensus_node_id()
        .expect("fixed local node ID");
    let identity = topology.consensus_identity().expect("consensus identity");
    let peers = topology
        .members()
        .iter()
        .filter_map(|member| topology.consensus_node_id(member.replica_id()))
        .filter(|node_id| *node_id != local_node_id)
        .map(|node_id| {
            let peer: Arc<dyn SessionConsensusPeer> =
                Arc::new(ScopedLoopbackPeer::new(node_id, identity));
            (node_id, peer)
        })
        .collect::<BTreeMap<_, _>>();
    let snapshots = tempfile::tempdir().expect("snapshot directory");

    let result = ConsensusSessionStore::open_fixed_durable_quorum(
        topology,
        SqliteSessionBackend::in_memory().expect("in-memory backend"),
        snapshots.path(),
        peers,
    )
    .await;

    assert!(matches!(
        result,
        Err(ConsensusSessionStoreOpenError::StorageUnavailable)
    ));
}

#[tokio::test]
async fn file_backed_fixed_five_voter_quorum_reaches_granted_authority() {
    let members = fixed_members(5);
    let identity =
        fixed_consensus_identity(&members, PlacementResiliencePolicy::AllowReducedResilience);
    let topologies = (0..5)
        .map(|index| {
            fixed_topology_for_local(
                index,
                members.clone(),
                PlacementResiliencePolicy::AllowReducedResilience,
            )
            .map(|topology| (index, topology))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("fixed five-voter topologies");
    let directory = tempfile::tempdir().expect("fixed five-voter directory");
    let node_ids = topologies
        .iter()
        .map(|(_, topology)| {
            topology
                .local_consensus_node_id()
                .expect("fixed local node ID")
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..5 {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }
    let mut stores = Vec::new();
    for (source, topology) in topologies {
        let peers = (0..5)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("fixed scoped path")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        let store = ConsensusSessionStore::open_fixed_durable_quorum(
            topology,
            SqliteSessionBackend::open(
                directory
                    .path()
                    .join(format!("fixed-voter-{source}.sqlite")),
            )
            .expect("file-backed voter store"),
            directory.path().join(format!("snapshots-{source}")),
            peers,
        )
        .await
        .expect("open fixed five-voter store");
        stores.push(store);
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed five-voter membership");
    }

    let readiness = stores[0]
        .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
        .await;
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert!(readiness.traffic_authority().is_granted());
}

#[tokio::test]
async fn initialized_fixed_three_voter_cluster_reopens_with_durable_authority_and_rpc_readiness() {
    let (directory, _database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    drop(stores);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (_database_paths, reopened) = open_fixed_cluster_in(
        directory.path(),
        3,
        PlacementResiliencePolicy::AllowReducedResilience,
    )
    .await;
    assert!(
        reopened.iter().all(|store| store.status().admitted),
        "reopened fixed voters must retain exact durable admission"
    );
    assert!(
        reopened[0]
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
            .await
            .traffic_authority()
            .is_granted(),
        "reopened fixed quorum RPC path must recover durable traffic authority"
    );
}

#[tokio::test]
async fn fixed_durable_quorum_reopen_rejects_placement_policy_mismatch() {
    for (initial, reopened) in [
        (
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
            PlacementResiliencePolicy::AllowReducedResilience,
        ),
        (
            PlacementResiliencePolicy::AllowReducedResilience,
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
        ),
    ] {
        let (directory, database_paths, stores) = open_fixed_cluster(3, initial).await;
        drop(stores);
        let members = fixed_members(3);
        let topology = fixed_topology_for_local(0, members, reopened).expect("reopen topology");
        let error = ConsensusSessionStore::open_fixed_durable_quorum(
            topology.clone(),
            SqliteSessionBackend::open(&database_paths[0]).expect("reopen backend"),
            directory.path().join("snapshots-0"),
            scoped_peers(&topology),
        )
        .await
        .expect_err("fixed placement policy must be durably bound");
        assert_eq!(
            ConsensusSessionStoreOpenError::DurableIdentityMismatch,
            error
        );
    }
}

#[tokio::test]
async fn fixed_five_voter_store_without_a_majority_reports_no_quorum() {
    let topology = fixed_topology(fixed_members(5)).expect("fixed five-voter topology");
    let peers = scoped_peers(&topology);
    let directory = tempfile::tempdir().expect("fixed five-voter directory");
    let store = ConsensusSessionStore::open_fixed_durable_quorum(
        topology,
        SqliteSessionBackend::open(directory.path().join("fixed-voter.sqlite"))
            .expect("file-backed voter store"),
        directory.path().join("snapshots"),
        peers,
    )
    .await
    .expect("open fixed five-voter store");

    let readiness = tokio::time::timeout(
        Duration::from_secs(1),
        store
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1)),
    )
    .await
    .expect("no-majority readiness must remain bounded");
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::NoQuorum,
    );
}

#[tokio::test]
async fn store_issued_consumer_manifest_retains_authoritative_node_to_tls_pairs() {
    let placement_policy = PlacementResiliencePolicy::AllowReducedResilience;
    let members = fixed_members(3);
    let topology = fixed_topology_for_local(0, members, placement_policy)
        .expect("fixed topology with canonical node IDs");
    let expected_scope = topology
        .consensus_identity()
        .expect("fixed consensus identity");
    let expected_pairs = topology
        .members()
        .iter()
        .map(|descriptor| {
            (
                topology
                    .consensus_node_id(descriptor.replica_id())
                    .expect("canonical topology node ID")
                    .get(),
                descriptor.tls_identity().as_str().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let (_directory, _database_paths, stores) = open_fixed_cluster(3, placement_policy).await;

    let manifest = stores[0]
        .consumer_authorization_manifest([fixed_consumer_grant()])
        .await
        .expect("admitted fixed store issues its consumer roster");
    let actual_pairs = manifest
        .consensus_members()
        .map(|member| (member.node_id().get(), member.tls_identity().to_owned()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(manifest.scope().consensus_identity(), expected_scope);
    assert_eq!(actual_pairs, expected_pairs);
}

#[tokio::test]
async fn persisted_fixed_binding_drift_revokes_consumer_and_traffic_authority() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    stores[0]
        .consumer_authorization_manifest([fixed_consumer_grant()])
        .await
        .expect("exact fixed store grants consumer authorization");

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    let encoded: Vec<u8> = connection
        .query_row(
            "SELECT current_bindings_json FROM consensus_membership_scope WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read fixed bindings");
    let mut bindings: serde_json::Value =
        serde_json::from_slice(&encoded).expect("decode fixed bindings");
    let first_descriptor_octet = bindings
        .as_array_mut()
        .and_then(|entries| entries.first_mut())
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|entry| entry.get_mut(1))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|binding| binding.get_mut("descriptor"))
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|digest| digest.first_mut())
        .expect("descriptor binding octet");
    let changed = first_descriptor_octet
        .as_u64()
        .expect("numeric descriptor octet")
        .wrapping_add(1)
        % 256;
    *first_descriptor_octet = serde_json::Value::from(changed);
    connection
        .execute(
            "UPDATE consensus_membership_scope SET current_bindings_json = ?1 WHERE singleton = 1",
            [serde_json::to_vec(&bindings).expect("encode changed fixed bindings")],
        )
        .expect("persist fixed binding drift");
    drop(connection);

    assert!(stores[0]
        .consumer_authorization_manifest([fixed_consumer_grant()])
        .await
        .is_err());
    let readiness = stores[0]
        .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
        .await;
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::StructuralRecoveryRequired,
    );
}

#[tokio::test]
async fn running_fixed_scope_drift_revokes_linearizable_readiness_authority() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    for database_path in database_paths {
        let connection =
            rusqlite::Connection::open(database_path).expect("open fixed voter database");
        connection
            .execute(
                "UPDATE consensus_membership_scope SET application_authority_epoch = application_authority_epoch + 1 WHERE singleton = 1",
                [],
            )
            .expect("persist fixed structural scope drift");
    }

    let readiness = stores[0].probe_durable_readiness().await;
    assert!(
        !readiness.is_ready(),
        "a linearizable read barrier must not report authority after durable fixed-scope drift"
    );
}

#[tokio::test]
async fn running_fixed_profile_drift_revokes_traffic_authority() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    for database_path in database_paths {
        let connection =
            rusqlite::Connection::open(database_path).expect("open fixed voter database");
        connection
            .execute(
                "UPDATE consensus_identity SET authority_profile = 1 WHERE singleton = 1",
                [],
            )
            .expect("persist fixed authority profile drift");
    }

    assert!(
        stores[0]
            .consumer_authorization_manifest([fixed_consumer_grant()])
            .await
            .is_err(),
        "consumer authority must fail closed after fixed-profile drift"
    );
    assert!(
        SessionBackend::batch(&stores[0], Vec::new()).await.is_err(),
        "mutation authority must fail closed after fixed-profile drift"
    );
    assert!(
        !stores[0].status().admitted,
        "status must not retain admission after fixed-profile drift"
    );
    let readiness = stores[0]
        .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
        .await;
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::StructuralRecoveryRequired,
    );
}

#[tokio::test]
async fn running_fixed_placement_policy_drift_revokes_live_authority() {
    for (configured_policy, drifted_policy) in [
        (
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
            PlacementResiliencePolicy::AllowReducedResilience,
        ),
        (
            PlacementResiliencePolicy::AllowReducedResilience,
            PlacementResiliencePolicy::RequireIndependentFailureDomains,
        ),
    ] {
        let (_directory, database_paths, stores) = open_fixed_cluster(3, configured_policy).await;
        stores[0]
            .consumer_authorization_manifest([fixed_consumer_grant()])
            .await
            .expect("exact fixed policy grants consumer authority");
        assert!(
            stores[0].status().admitted,
            "exact fixed policy is admitted"
        );
        let start_sequence = stores[0]
            .status()
            .last_log_index
            .map_or(0, |index| index.saturating_add(1));
        let mut watch = SessionBackend::watch(&stores[0], start_sequence)
            .await
            .expect("open idle generic watch before policy drift");

        let connection =
            rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
        let stored_policy = match drifted_policy {
            PlacementResiliencePolicy::RequireIndependentFailureDomains => 1_i64,
            PlacementResiliencePolicy::AllowReducedResilience => 2_i64,
            _ => unreachable!("test policy must have a durable encoding"),
        };
        connection
            .execute(
                "UPDATE consensus_identity SET fixed_placement_policy = ?1 WHERE singleton = 1",
                [stored_policy],
            )
            .expect("persist fixed placement policy drift");
        drop(connection);

        assert!(
            !stores[0].status().admitted,
            "status must revoke admission after fixed policy drift"
        );
        assert!(
            stores[0]
                .consumer_authorization_manifest([fixed_consumer_grant()])
                .await
                .is_err(),
            "consumer authority must fail closed after fixed policy drift"
        );
        assert!(
            SessionBackend::batch(&stores[0], Vec::new()).await.is_err(),
            "mutation authority must fail closed after fixed policy drift"
        );
        let readiness = stores[0]
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
            .await;
        assert_eq!(
            readiness.traffic_authority(),
            FixedQuorumTrafficAuthority::StructuralRecoveryRequired,
            "fixed policy drift must revoke traffic authority"
        );
        let item = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("idle watch must revalidate fixed policy promptly")
            .expect("idle watch must emit a terminal authority failure");
        assert!(
            item.is_err(),
            "idle watch must fail closed after fixed policy drift"
        );
        assert!(
            watch.next().await.is_none(),
            "watch must terminate after fixed policy revocation"
        );
    }
}

#[tokio::test]
async fn running_fixed_applied_membership_drift_revokes_status_and_mutation_authority() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_membership SET membership_json = x'00' WHERE singleton = 1",
            [],
        )
        .expect("persist malformed applied membership drift");
    drop(connection);

    assert!(
        !stores[0].status().admitted,
        "status must fail closed when the persisted applied membership is not exact"
    );
    assert!(
        SessionBackend::batch(&stores[0], Vec::new()).await.is_err(),
        "mutation authority must fail closed when the persisted applied membership is not exact"
    );
}

#[tokio::test]
async fn running_fixed_scope_drift_terminates_an_already_open_generic_watch() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let key = SessionKey {
        tenant: TenantId::new("fixed-watch-drift").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: b"fixed-watch-drift"
            .as_slice()
            .try_into()
            .expect("bounded stable ID"),
    };
    stores[0]
        .acquire(
            &key,
            OwnerId::new("fixed-watch-owner").expect("test owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("create watched consensus entry");
    let mut watch = SessionBackend::watch(&stores[0], 0)
        .await
        .expect("open generic watch before drift");

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_membership_scope SET application_authority_epoch = application_authority_epoch + 1 WHERE singleton = 1",
            [],
        )
        .expect("persist fixed structural scope drift");

    assert!(
        watch
            .next()
            .await
            .expect("watch must observe its queued entry")
            .is_err(),
        "an already-open fixed watch must not expose entries after durable scope drift"
    );
    assert!(
        watch.next().await.is_none(),
        "watch must terminate after revocation"
    );
}

#[tokio::test]
async fn running_fixed_scope_drift_terminates_an_idle_generic_watch_promptly() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let start_sequence = stores[0]
        .status()
        .last_log_index
        .map_or(0, |index| index.saturating_add(1));
    let mut watch = SessionBackend::watch(&stores[0], start_sequence)
        .await
        .expect("open idle generic watch before drift");

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_membership_scope SET application_authority_epoch = application_authority_epoch + 1 WHERE singleton = 1",
            [],
        )
        .expect("persist fixed structural scope drift");
    drop(connection);

    let item = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("idle watch must revalidate durable authority promptly")
        .expect("idle watch must emit a terminal authority failure");
    assert!(
        item.is_err(),
        "idle watch must fail closed after durable drift"
    );
    assert!(
        watch.next().await.is_none(),
        "watch must terminate after revocation"
    );
}

#[tokio::test]
async fn fixed_majority_loss_terminates_an_idle_generic_watch_without_an_event() {
    let (_directory, _database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let start_sequence = stores[0]
        .status()
        .last_log_index
        .map_or(0, |index| index.saturating_add(1));
    let mut watch = SessionBackend::watch(&stores[0], start_sequence)
        .await
        .expect("open idle generic watch before majority loss");

    paths
        .get(&(0, 1))
        .expect("fixed voter one path")
        .set_enabled(false);
    paths
        .get(&(0, 2))
        .expect("fixed voter two path")
        .set_enabled(false);

    let item = tokio::time::timeout(Duration::from_secs(12), watch.next())
        .await
        .expect("idle watch must re-establish majority authority within one bounded operation")
        .expect("idle watch must emit a terminal majority-authority failure");
    assert!(
        item.is_err(),
        "an idle fixed watch must fail closed after majority loss without a queued event"
    );
    assert!(
        watch.next().await.is_none(),
        "watch must terminate after majority authority is lost"
    );
}

#[tokio::test]
async fn fixed_scoped_consumer_watch_is_rejected_before_stream_admission() {
    let (_directory, _database_paths, stores, _paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let scope = stores[0]
        .consumer_scope()
        .expect("fixed consumer scope before majority loss");
    let start_sequence = stores[0]
        .status()
        .last_log_index
        .map_or(0, |index| index.saturating_add(1));
    let identity = fixed_consumer_identity();
    let manifest = stores[0]
        .consumer_authorization_manifest([fixed_consumer_grant()])
        .await
        .expect("fixed consumer authorization manifest");
    let authorization = manifest
        .authorize(&identity)
        .expect("fixed consumer authorization");
    let rejection = match stores[0]
        .consumer_service()
        .watch(&authorization, scope, start_sequence)
        .await
    {
        Ok(_) => panic!("a global watch must not be admitted for a scoped consumer"),
        Err(rejection) => rejection,
    };
    assert_eq!(
        rejection,
        SessionConsumerRejection::Unauthorized,
        "denial occurs before a stream can expose foreign-tenant timing or sequence movement"
    );
}

#[tokio::test]
async fn fixed_majority_loss_revokes_readiness_reads_and_stale_lease_owner_mutations() {
    let (_directory, _database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let key = SessionKey {
        tenant: TenantId::new("fixed-majority-fence").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: b"fixed-majority-fence"
            .as_slice()
            .try_into()
            .expect("bounded stable ID"),
    };
    let lease = stores[0]
        .acquire(
            &key,
            OwnerId::new("fixed-majority-owner").expect("test owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire lease before majority loss");

    paths
        .get(&(0, 1))
        .expect("fixed voter one path")
        .set_enabled(false);
    paths
        .get(&(0, 2))
        .expect("fixed voter two path")
        .set_enabled(false);

    let readiness = tokio::time::timeout(
        Duration::from_secs(12),
        stores[0]
            .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1)),
    )
    .await
    .expect("fixed readiness must remain bounded after majority loss");
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::NoQuorum,
        "a previously healthy fixed member must withdraw traffic authority after majority loss"
    );

    let (read, renewal, release) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(12),
            SessionBackend::get(&stores[0], &key),
        ),
        tokio::time::timeout(
            Duration::from_secs(12),
            SessionLeaseManager::renew(&stores[0], &lease, Duration::from_secs(30)),
        ),
        tokio::time::timeout(
            Duration::from_secs(12),
            SessionLeaseManager::release(&stores[0], lease.clone()),
        ),
    );
    assert!(
        read.expect("read must remain bounded after majority loss")
            .is_err(),
        "a fixed member without majority must not serve a linearizable read"
    );
    assert!(
        renewal
            .expect("lease renewal must remain bounded after majority loss")
            .is_err(),
        "a stale fixed lease owner must not renew without majority authority"
    );
    assert!(
        release
            .expect("lease release must remain bounded after majority loss")
            .is_err(),
        "a stale fixed lease owner must not release without majority authority"
    );
}

#[tokio::test]
async fn fixed_recovery_latch_terminates_an_idle_generic_watch_without_an_event() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let start_sequence = stores[0]
        .status()
        .last_log_index
        .map_or(0, |index| index.saturating_add(1));
    let mut watch = SessionBackend::watch(&stores[0], start_sequence)
        .await
        .expect("open idle generic watch before recovery latch activation");

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_operator_recovery \
             SET pending_epoch = recovery_epoch + 1, pending_plan_digest = zeroblob(32) \
             WHERE singleton = 1",
            [],
        )
        .expect("activate durable fixed recovery latch");
    drop(connection);

    let item = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("idle watch must recheck the durable recovery latch promptly")
        .expect("idle watch must emit a terminal recovery-authority failure");
    assert!(
        item.is_err(),
        "an idle fixed watch must fail closed after recovery latch activation without a queued event"
    );
    assert!(
        watch.next().await.is_none(),
        "watch must terminate after recovery authority is revoked"
    );
}

#[tokio::test]
async fn fixed_recovery_latch_during_readiness_barrier_never_grants_traffic() {
    let (_directory, database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let admitted_at = TopologyAttestationTime::from_unix_seconds(1);
    assert!(
        stores[0]
            .probe_fixed_durable_quorum_readiness_at(admitted_at)
            .await
            .traffic_authority()
            .is_granted(),
        "the detector requires an initially healthy fixed quorum"
    );

    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(false);
    }
    let probe_store = stores[0].clone();
    let readiness_probe = tokio::spawn(async move {
        probe_store
            .probe_fixed_durable_quorum_readiness_at(admitted_at)
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !readiness_probe.is_finished(),
        "the detector must hold readiness inside its quorum barrier"
    );

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_operator_recovery \
             SET pending_epoch = recovery_epoch + 1, pending_plan_digest = zeroblob(32) \
             WHERE singleton = 1",
            [],
        )
        .expect("activate durable fixed recovery latch during readiness barrier");
    drop(connection);
    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(true);
    }

    let readiness = tokio::time::timeout(Duration::from_secs(12), readiness_probe)
        .await
        .expect("readiness must remain bounded after Recovery activation")
        .expect("readiness task must not panic");
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::RecoveryRequired,
        "Recovery activated during a quorum barrier must revoke traffic before readiness returns"
    );
}

#[tokio::test]
async fn fixed_recovery_latch_during_ordinary_read_barrier_never_returns_data() {
    let (_directory, database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let key = SessionKey {
        tenant: TenantId::new("fixed-recovery-read-race").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: b"fixed-recovery-read-race"
            .as_slice()
            .try_into()
            .expect("bounded stable ID"),
    };

    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(false);
    }
    let read_store = stores[0].clone();
    let read_key = key.clone();
    let read = tokio::spawn(async move { SessionBackend::get(&read_store, &read_key).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !read.is_finished(),
        "the detector must hold the ordinary read inside its quorum barrier"
    );

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_operator_recovery \
             SET pending_epoch = recovery_epoch + 1, pending_plan_digest = zeroblob(32) \
             WHERE singleton = 1",
            [],
        )
        .expect("activate durable fixed recovery latch during ordinary read barrier");
    drop(connection);
    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(true);
    }

    assert!(
        tokio::time::timeout(Duration::from_secs(12), read)
            .await
            .expect("ordinary read must remain bounded after Recovery activation")
            .expect("ordinary read task must not panic")
            .is_err(),
        "Recovery activated during a quorum barrier must revoke an ordinary read before return"
    );
}

#[tokio::test]
async fn fixed_recovery_latch_during_mutation_barrier_never_admits_new_lease() {
    let (_directory, database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let key = SessionKey {
        tenant: TenantId::new("fixed-recovery-mutation-race").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: b"fixed-recovery-mutation-race"
            .as_slice()
            .try_into()
            .expect("bounded stable ID"),
    };

    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(false);
    }
    let mutation_store = stores[0].clone();
    let mutation = tokio::spawn(async move {
        mutation_store
            .acquire(
                &key,
                OwnerId::new("fixed-recovery-mutation-owner").expect("test owner"),
                Duration::from_secs(30),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !mutation.is_finished(),
        "the detector must hold the mutation inside its quorum barrier"
    );

    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("open fixed voter database");
    connection
        .execute(
            "UPDATE consensus_operator_recovery \
             SET pending_epoch = recovery_epoch + 1, pending_plan_digest = zeroblob(32) \
             WHERE singleton = 1",
            [],
        )
        .expect("activate durable fixed recovery latch during mutation barrier");
    drop(connection);
    for target in 1..3 {
        paths
            .get(&(0, target))
            .expect("fixed outbound path")
            .set_enabled(true);
    }

    assert!(
        tokio::time::timeout(Duration::from_secs(12), mutation)
            .await
            .expect("mutation must remain bounded after Recovery activation")
            .expect("mutation task must not panic")
            .is_err(),
        "Recovery activated during a quorum barrier must revoke mutation before proposal"
    );
    let connection =
        rusqlite::Connection::open(&database_paths[0]).expect("reopen fixed voter database");
    let record_count: u64 = connection
        .query_row("SELECT COUNT(*) FROM session_records", [], |row| row.get(0))
        .expect("count durable session records after rejected mutation");
    assert_eq!(
        record_count, 0,
        "rejected mutation must have no durable effect"
    );
}

#[tokio::test]
async fn fixed_quorum_rejects_every_dynamic_transition_entry_point() {
    let topology = fixed_topology(fixed_members(3)).expect("fixed topology admission");
    let identity = topology.consensus_identity().expect("consensus identity");
    let peers = scoped_peers(&topology);
    let directory = tempfile::tempdir().expect("fixed quorum directory");
    let store = ConsensusSessionStore::open_fixed_durable_quorum(
        topology,
        SqliteSessionBackend::open(directory.path().join("fixed-voter.sqlite"))
            .expect("file-backed voter store"),
        directory.path().join("snapshots"),
        peers,
    )
    .await
    .expect("open fixed durable quorum");
    let request = successor_request(identity);

    assert_eq!(
        store.bind_topology_transport_admission(Arc::new(NoopTopologyTransport)),
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store.stage_topology_transition_peers(&request, BTreeMap::new()),
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store.unstage_topology_transition_peers(&request).await,
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store
            .prepare_topology_transition(&request, BTreeMap::new())
            .await,
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store.topology_transition_status(&request).await,
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
    assert_eq!(
        store.abort_topology_transition(&request).await,
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );
}

#[tokio::test]
async fn fixed_authority_profile_persists_across_reopen_and_rejects_profile_changes() {
    let members = fixed_members(3);
    let fixed = fixed_topology(members.clone()).expect("fixed topology admission");
    let dynamic = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
        replica_id(0),
        members.clone(),
        consensus_identity(&members),
    ))
    .expect("dynamic topology admission");
    let directory = tempfile::tempdir().expect("authority-profile directory");
    let fixed_database = directory.path().join("fixed.sqlite");
    let dynamic_database = directory.path().join("dynamic.sqlite");

    let fixed_store = ConsensusSessionStore::open_fixed_durable_quorum(
        fixed.clone(),
        SqliteSessionBackend::open(&fixed_database).expect("file-backed fixed store"),
        directory.path().join("fixed-snapshots"),
        scoped_peers(&fixed),
    )
    .await
    .expect("open fixed store");
    drop(fixed_store);
    let fixed_reopened = ConsensusSessionStore::open_fixed_durable_quorum(
        fixed.clone(),
        SqliteSessionBackend::open(&fixed_database).expect("file-backed fixed store"),
        directory.path().join("fixed-snapshots"),
        scoped_peers(&fixed),
    )
    .await
    .expect("reopen fixed store with its persisted authority profile");
    drop(fixed_reopened);
    let fixed_as_dynamic = ConsensusSessionStore::open(
        dynamic.clone(),
        SqliteSessionBackend::open(&fixed_database).expect("file-backed fixed store"),
        directory.path().join("fixed-snapshots"),
        scoped_peers(&dynamic),
    )
    .await;
    assert!(matches!(
        fixed_as_dynamic,
        Err(ConsensusSessionStoreOpenError::DurableIdentityMismatch)
    ));

    let dynamic_store = ConsensusSessionStore::open(
        dynamic,
        SqliteSessionBackend::open(&dynamic_database).expect("file-backed dynamic store"),
        directory.path().join("dynamic-snapshots"),
        scoped_peers(&fixed),
    )
    .await
    .expect("open dynamic store");
    drop(dynamic_store);
    let dynamic_as_fixed = ConsensusSessionStore::open_fixed_durable_quorum(
        fixed.clone(),
        SqliteSessionBackend::open(dynamic_database).expect("file-backed dynamic store"),
        directory.path().join("dynamic-snapshots"),
        scoped_peers(&fixed),
    )
    .await;
    assert!(matches!(
        dynamic_as_fixed,
        Err(ConsensusSessionStoreOpenError::DurableIdentityMismatch)
    ));
}

#[tokio::test]
async fn placement_expiry_downgrades_only_the_fixed_quorum_placement_result() {
    let members = (0..3)
        .map(|index| descriptor(index, index, index, index))
        .collect::<Vec<_>>();
    let identity = fixed_consensus_identity(&members, PlacementResiliencePolicy::default());
    let observed_at = TopologyAttestationTime::from_unix_seconds(100);
    let admitted_at = TopologyAttestationTime::from_unix_seconds(110);
    let expires_at = TopologyAttestationTime::from_unix_seconds(200);
    let collector = TopologyCollectorId::new("fixed-placement-attestor").expect("collector ID");
    let policy = TopologyAttestationPolicy::try_new(
        TopologyAttestationProvenance::AuthenticatedPlatform,
        vec![collector.clone()],
        Duration::from_secs(300),
    )
    .expect("placement policy");
    let evidence =
        authenticated_placement_evidence(&members, identity, &collector, observed_at, expires_at);
    let topologies = (0..3)
        .map(|index| {
            fixed_attested_topology(
                index,
                &members,
                identity,
                evidence.clone(),
                &policy,
                admitted_at,
            )
        })
        .collect::<Vec<_>>();
    let refreshed_at = TopologyAttestationTime::from_unix_seconds(210);
    let refreshed_placement = topologies[0]
        .verify_fixed_durable_quorum_placement_evidence(
            authenticated_placement_evidence(
                &members,
                identity,
                &collector,
                TopologyAttestationTime::from_unix_seconds(205),
                TopologyAttestationTime::from_unix_seconds(400),
            ),
            &policy,
            &DigestTopologyAttestor,
            refreshed_at,
        )
        .expect("refreshed fixed placement evidence");
    let directory = tempfile::tempdir().expect("fixed quorum directory");
    let node_ids = topologies
        .iter()
        .map(|topology| {
            topology
                .local_consensus_node_id()
                .expect("fixed local node ID")
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..3 {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }
    let mut stores = Vec::new();
    for (source, topology) in topologies.iter().cloned().enumerate() {
        let peers = (0..3)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("fixed scoped path")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        let backend = SqliteSessionBackend::open(
            directory
                .path()
                .join(format!("fixed-voter-{source}.sqlite")),
        )
        .expect("file-backed voter store");
        let store = ConsensusSessionStore::open_fixed_durable_quorum(
            topology,
            backend,
            directory.path().join(format!("snapshots-{source}")),
            peers,
        )
        .await
        .expect("open fixed durable quorum voter");
        stores.push(store);
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed quorum membership");
    }

    let successor_epoch = ConsensusConfigurationEpoch::new(2).expect("successor epoch");
    let transition = SessionTopologyTransitionRequest::try_new(
        SessionTopologyTransitionId::from_bytes([0x71; 16]),
        identity.cluster_id(),
        identity.configuration_epoch(),
        successor_epoch,
        (3..6)
            .map(|index| descriptor(index, index, index, index))
            .collect(),
        Duration::from_secs(30),
    )
    .expect("valid successor request");
    assert_eq!(
        stores[0].stage_topology_transition_peers(&transition, BTreeMap::new()),
        Err(SessionTopologyTransitionError::ImmutableFixedQuorum),
    );

    let before_expiry = stores[0]
        .probe_fixed_durable_quorum_readiness_at(admitted_at)
        .await;
    assert_eq!(
        before_expiry.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        before_expiry.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementQualified,
    );

    let expired = stores[0]
        .probe_fixed_durable_quorum_readiness_at(expires_at)
        .await;
    assert_eq!(
        expired.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted
    );
    assert_eq!(
        expired.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementWithheld,
    );

    let refreshed = stores[0]
        .probe_fixed_durable_quorum_readiness_with_placement_attestation_at(
            &refreshed_placement,
            refreshed_at,
        )
        .await;
    assert_eq!(
        refreshed.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        refreshed.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementQualified,
    );
}

#[tokio::test]
async fn fixed_five_voter_authenticated_placement_expiry_preserves_traffic_authority() {
    let members = fixed_members(5);
    let identity = fixed_consensus_identity(&members, PlacementResiliencePolicy::default());
    let observed_at = TopologyAttestationTime::from_unix_seconds(100);
    let qualified_at = TopologyAttestationTime::from_unix_seconds(110);
    let expires_at = TopologyAttestationTime::from_unix_seconds(200);
    let collector =
        TopologyCollectorId::new("fixed-five-placement-attestor").expect("collector ID");
    let policy = TopologyAttestationPolicy::try_new(
        TopologyAttestationProvenance::AuthenticatedPlatform,
        vec![collector.clone()],
        Duration::from_secs(300),
    )
    .expect("placement policy");
    let topology =
        fixed_topology_for_local(0, members.clone(), PlacementResiliencePolicy::default())
            .expect("fixed five-voter topology");
    let placement = topology
        .verify_fixed_durable_quorum_placement_evidence(
            authenticated_placement_evidence(
                &members,
                identity,
                &collector,
                observed_at,
                expires_at,
            ),
            &policy,
            &DigestTopologyAttestor,
            qualified_at,
        )
        .expect("authenticated placement");
    let (_directory, _database_paths, stores) =
        open_fixed_cluster(5, PlacementResiliencePolicy::default()).await;

    let qualified = stores[0]
        .probe_fixed_durable_quorum_readiness_with_placement_attestation_at(
            &placement,
            qualified_at,
        )
        .await;
    assert_eq!(
        qualified.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        qualified.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementQualified,
    );

    let expired = stores[0]
        .probe_fixed_durable_quorum_readiness_with_placement_attestation_at(&placement, expires_at)
        .await;
    assert_eq!(
        expired.traffic_authority(),
        FixedQuorumTrafficAuthority::Granted,
    );
    assert_eq!(
        expired.placement_resilience().disposition(),
        PlacementResilienceDisposition::IndependentPlacementWithheld,
    );
}
