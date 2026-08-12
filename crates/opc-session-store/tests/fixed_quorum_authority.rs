use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_session_store::{
    ConsensusSessionStore, ConsensusSessionStoreOpenError, FixedQuorumTrafficAuthority,
    ObservedPhysicalNodeIdentity, PlacementResilienceDisposition, PlacementResiliencePolicy,
    QuorumReplicaDescriptor, QuorumTopologyAttestor, QuorumTopologyConfig, QuorumTopologyError,
    QuorumTopologyMode, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaTlsIdentity, SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionTopologyAbortAdmissionProof, SessionTopologyCandidateRetirementProof,
    SessionTopologyJointCommitAdmissionProof, SessionTopologyPrePrepareUnstageProof,
    SessionTopologyTransitionError, SessionTopologyTransitionId, SessionTopologyTransitionRequest,
    SessionTopologyTransportAdmission, SessionTopologyTransportAdmissionError,
    SessionTopologyUniformCommitAdmissionProof, SqliteSessionBackend, TopologyAttestationClaims,
    TopologyAttestationEvidence, TopologyAttestationPolicy, TopologyAttestationProvenance,
    TopologyAttestationTime, TopologyAttestationVerificationError,
    TopologyAttestationVerificationInput, TopologyCollectorId, ValidatedQuorumTopology,
};

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
}

impl ScopedLoopbackPeer {
    fn new(node_id: SessionConsensusNodeId, identity: ConsensusIdentity) -> Self {
        Self {
            node_id,
            identity,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
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
            consensus_identity(&members),
        ),
        placement_policy,
    )
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
    let members = fixed_members(member_count);
    let identity = consensus_identity(&members);
    let topologies = (0..member_count)
        .map(|index| {
            fixed_topology_for_local(index, members.clone(), placement_policy)
                .map(|topology| (index, topology))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("fixed cluster topologies");
    let directory = tempfile::tempdir().expect("fixed cluster directory");
    let database_paths = (0..member_count)
        .map(|index| directory.path().join(format!("fixed-voter-{index}.sqlite")))
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
            directory.path().join(format!("snapshots-{source}")),
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
    (directory, database_paths, stores)
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
    let identity = consensus_identity(&members);
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
async fn persisted_fixed_binding_drift_revokes_consumer_and_traffic_authority() {
    let (_directory, database_paths, stores) =
        open_fixed_cluster(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    stores[0]
        .consumer_authorization_manifest()
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

    assert!(stores[0].consumer_authorization_manifest().await.is_err());
    let readiness = stores[0]
        .probe_fixed_durable_quorum_readiness_at(TopologyAttestationTime::from_unix_seconds(1))
        .await;
    assert_eq!(
        readiness.traffic_authority(),
        FixedQuorumTrafficAuthority::StructuralRecoveryRequired,
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
        members,
        fixed.consensus_identity().expect("consensus identity"),
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
    let identity = consensus_identity(&members);
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
