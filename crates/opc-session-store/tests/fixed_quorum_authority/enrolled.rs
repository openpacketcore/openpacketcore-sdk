//! Volume-enrolled keys and real authenticated voter-slot RPCs.

use super::*;
use opc_consensus::voter_slots::*;
use opc_session_store::test_support::{
    append_consensus_padding_entry_for_test, consensus_padding_receipt_status_for_test,
    ConsensusPaddingReceiptStatusForTest,
};
use opc_session_store::VoterIdentitySigner;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(super) struct EnrolledPeer {
    pub(super) transport: ScopedLoopbackPeer,
    pub(super) pre_votes: AtomicUsize,
    pub(super) missed_votes: AtomicUsize,
    member: VoterSlotMember,
    signers: Arc<std::sync::RwLock<BTreeMap<SessionConsensusNodeId, VoterIdentitySigner>>>,
}

impl EnrolledPeer {
    async fn authenticated_call(
        &self,
        binding: VoterRpcBinding,
        request: SessionConsensusWireRequest,
        timeout: Duration,
    ) -> Result<VoterAuthenticatedResponse, SessionConsensusPeerError> {
        if !self.transport.enabled.load(Ordering::SeqCst) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        // Retain the route read guard through the RPC. Removing a listener
        // drains accepted calls before the volume and its key can be removed.
        let handler = self.transport.handler.read().await;
        let handler = handler
            .as_ref()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        if binding.destination != self.member {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        let (source, destination) = {
            let keys = self.signers.read().unwrap();
            (
                keys.get(&binding.source.identity.node_id()).cloned(),
                keys.get(&self.member.identity.node_id()).cloned(),
            )
        };
        let source = source.ok_or(SessionConsensusPeerError::Unavailable)?;
        let destination = destination.ok_or(SessionConsensusPeerError::Unavailable)?;
        let issuer = VoterChallengeIssuer::new();
        let channel = rand::random();
        let expires = tokio::time::Instant::now() + timeout.min(Duration::from_secs(60));
        let challenge = issuer
            .issue_rpc(binding.clone(), channel, expires)
            .map_err(|_| SessionConsensusPeerError::Rejected)?;
        let proof = issuer
            .verify_rpc(
                &challenge,
                &binding.source_spiffe_id,
                channel,
                source.public_key(),
                source
                    .sign_rpc(&challenge)
                    .map_err(|_| SessionConsensusPeerError::Rejected)?,
            )
            .map_err(|_| SessionConsensusPeerError::Rejected)?;
        let response = handler
            .handle_with_incarnation(proof, request.clone())
            .await;
        let response_binding = VoterRpcBinding {
            source: binding.destination.clone(),
            destination: binding.source.clone(),
            source_spiffe_id: binding.destination_spiffe_id,
            destination_spiffe_id: binding.source_spiffe_id,
            payload_digest: voter_rpc_response_digest(&request, &response)?,
            kind: VoterRpcProofKind::Response,
            ..binding
        };
        let challenge = issuer
            .issue_rpc(
                response_binding.clone(),
                channel,
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .map_err(|_| SessionConsensusPeerError::Rejected)?;
        let proof = issuer
            .verify_rpc(
                &challenge,
                &response_binding.source_spiffe_id,
                channel,
                destination.public_key(),
                destination
                    .sign_rpc(&challenge)
                    .map_err(|_| SessionConsensusPeerError::Rejected)?,
            )
            .map_err(|_| SessionConsensusPeerError::Rejected)?;
        Ok(VoterAuthenticatedResponse { response, proof })
    }
}

#[async_trait]
impl SessionConsensusPeer for EnrolledPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.member.identity.node_id()
    }

    async fn call(
        &self,
        _: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        panic!("the enrolled profile must never use an unproved RPC");
    }

    async fn call_with_incarnation(
        &self,
        request: SessionConsensusWireRequest,
        binding: VoterRpcBinding,
        timeout: Duration,
    ) -> Result<VoterAuthenticatedResponse, SessionConsensusPeerError> {
        let family = request.family;
        if family == SessionConsensusRpcFamily::PreVote {
            self.pre_votes.fetch_add(1, Ordering::SeqCst);
        }
        let result = self.authenticated_call(binding, request, timeout).await;
        if family == SessionConsensusRpcFamily::Vote
            && matches!(result, Err(SessionConsensusPeerError::Unavailable))
        {
            self.missed_votes.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
}

#[derive(Debug)]
struct Resolver {
    peers: Vec<Arc<EnrolledPeer>>,
    descriptors: Vec<QuorumReplicaDescriptor>,
}

impl VoterPeerResolver for Resolver {
    fn resolve(
        &self,
        member: &VoterSlotMember,
    ) -> Result<VoterPeerRoute, SessionConsensusPeerError> {
        let index = self
            .peers
            .iter()
            .position(|peer| peer.member == *member)
            .ok_or(SessionConsensusPeerError::ScopeMismatch)?;
        Ok(VoterPeerRoute {
            member: member.clone(),
            spiffe_id: self.descriptors[index].tls_identity().as_str().to_owned(),
            peer: self.peers[index].clone(),
        })
    }
}

/// A refused open has no store, engine, listener, or signer. Retaining the
/// typed result lets the unchanged safety/healing scenario inspect admission
/// and drain both outcomes without manufacturing a runnable empty voter.
pub(super) enum OpenVoter {
    Running(ConsensusSessionStore),
    Refused(ConsensusSessionStoreOpenError),
}

pub(super) struct VoterStatus {
    pub(super) admitted: bool,
    pub(super) leader_id: Option<SessionConsensusNodeId>,
    pub(super) last_log_index: Option<u64>,
    pub(super) term: u64,
}

impl OpenVoter {
    pub(super) fn refused(&self) -> bool {
        matches!(
            self,
            Self::Refused(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired)
        )
    }

    pub(super) fn status(&self) -> VoterStatus {
        match self {
            Self::Running(store) => {
                let status = store.status();
                VoterStatus {
                    admitted: status.admitted,
                    leader_id: status.leader_id,
                    last_log_index: status.last_log_index,
                    term: status.term,
                }
            }
            Self::Refused(error) => {
                assert_eq!(
                    *error,
                    ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired
                );
                VoterStatus {
                    admitted: false,
                    leader_id: None,
                    last_log_index: None,
                    term: 0,
                }
            }
        }
    }

    pub(super) async fn initialize_cluster(&self) -> Result<(), ConsensusSessionStoreOpenError> {
        match self {
            Self::Running(store) => store.initialize_cluster().await,
            Self::Refused(error) => Err(*error),
        }
    }

    pub(super) async fn shutdown(&self) -> Result<(), opc_session_store::StoreError> {
        match self {
            Self::Running(store) => store.shutdown().await,
            Self::Refused(_) => Ok(()),
        }
    }
}

impl std::ops::Deref for OpenVoter {
    type Target = ConsensusSessionStore;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Running(store) => store,
            Self::Refused(_) => panic!("a refused voter has no Raft or storage service"),
        }
    }
}

pub(super) struct EnrolledFleet {
    pub(super) directory: tempfile::TempDir,
    pub(super) peers: Vec<Arc<EnrolledPeer>>,
    pub(super) topologies: Vec<ValidatedQuorumTopology>,
    pub(super) genesis: VoterSlotTable,
    signers: Arc<std::sync::RwLock<BTreeMap<SessionConsensusNodeId, VoterIdentitySigner>>>,
    resolver: Arc<Resolver>,
}

impl EnrolledFleet {
    pub(super) async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let descriptors = fixed_members(3);
        let installation = ConsensusClusterId::from_bytes([0x81; 32]);
        let mut records = Vec::new();
        for (index, descriptor) in descriptors.iter().enumerate() {
            let volume = directory.path().join(format!("volume-{index}"));
            std::fs::create_dir(&volume).unwrap();
            let backend = SqliteSessionBackend::open(volume.join("voter.sqlite")).unwrap();
            let identity = VoterSlotIdentity::new(
                SlotId::new(index as u16 + 1).unwrap(),
                VoterIncarnation::new(1).unwrap(),
            );
            let signer = backend
                .enroll_voter_identity(installation, identity)
                .await
                .unwrap();
            // The publisher collects each digest through a fresh authenticated
            // challenge, then retains only public manifest material.
            let issuer = VoterChallengeIssuer::new();
            let channel = rand::random();
            let challenge = issuer
                .issue_enrollment(
                    VoterEnrollmentBinding {
                        cluster_instance: installation,
                        identity,
                        key_digest: signer.key_digest(),
                        spiffe_id: descriptor.tls_identity().as_str().to_owned(),
                    },
                    channel,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                )
                .unwrap();
            let proof = issuer
                .verify_enrollment(
                    &challenge,
                    descriptor.tls_identity().as_str(),
                    channel,
                    signer.public_key(),
                    signer.sign_enrollment(&challenge).unwrap(),
                )
                .unwrap();
            records.push(VoterSlotRecord {
                member: VoterSlotMember {
                    identity,
                    key_digest: proof.binding().unwrap().key_digest,
                    descriptor_digest: descriptor.configuration_fingerprint(),
                    admission_generation: 1,
                },
                retired_through: 0,
                phase: VoterSlotPhase::Voting,
                last_result: None,
            });
        }
        let mut genesis = VoterSlotTable {
            cluster_instance: installation,
            manifest_digest: [0x82; 32],
            revision: 1,
            configuration_epoch: ConsensusConfigurationEpoch::new(1).unwrap(),
            slots: records,
            replacement: None,
        };
        genesis.manifest_digest = Sha256::digest(encode_voter_slot_table(&genesis).unwrap()).into();
        let identity = genesis
            .current_configuration()
            .identity(installation, genesis.manifest_digest)
            .unwrap();
        let signers = Arc::new(std::sync::RwLock::new(BTreeMap::new()));
        let peers: Vec<_> = genesis
            .slots
            .iter()
            .map(|slot| {
                Arc::new(EnrolledPeer {
                    transport: ScopedLoopbackPeer::new(slot.member.identity.node_id(), identity),
                    pre_votes: AtomicUsize::new(0),
                    missed_votes: AtomicUsize::new(0),
                    member: slot.member.clone(),
                    signers: signers.clone(),
                })
            })
            .collect();
        let topologies = descriptors
            .iter()
            .map(|local| {
                ValidatedQuorumTopology::try_from_fixed_voter_slots(
                    QuorumTopologyConfig::new_consensus(
                        local.replica_id().clone(),
                        descriptors.clone(),
                        identity,
                    ),
                    genesis.clone(),
                    descriptors
                        .iter()
                        .enumerate()
                        .map(|(index, descriptor)| {
                            (
                                descriptor.replica_id().clone(),
                                SlotId::new(index as u16 + 1).unwrap(),
                            )
                        })
                        .collect(),
                    PlacementResiliencePolicy::AllowReducedResilience,
                )
                .unwrap()
            })
            .collect();
        let resolver = Arc::new(Resolver {
            peers: peers.clone(),
            descriptors,
        });
        Self {
            directory,
            peers,
            topologies,
            genesis,
            signers,
            resolver,
        }
    }

    pub(super) async fn open(&self, index: usize) -> OpenVoter {
        let volume = self.directory.path().join(format!("volume-{index}"));
        std::fs::create_dir_all(&volume).unwrap();
        let backend = SqliteSessionBackend::open(volume.join("voter.sqlite")).unwrap();
        let member = &self.genesis.slots[index].member;
        if let Ok(signer) = backend
            .voter_identity_signer(self.genesis.cluster_instance, member)
            .await
        {
            self.signers
                .write()
                .unwrap()
                .insert(member.identity.node_id(), signer);
        }
        let opened = ConsensusSessionStore::open_with_voter_slots_and_integrity(
            self.topologies[index].clone(),
            self.genesis.clone(),
            member.identity.node_id(),
            backend,
            volume.join("snapshots"),
            self.resolver.clone(),
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
        match opened {
            Ok(store) => {
                self.peers[index]
                    .transport
                    .install(store.rpc_handler())
                    .await;
                OpenVoter::Running(store)
            }
            Err(error) => {
                self.signers
                    .write()
                    .unwrap()
                    .remove(&member.identity.node_id());
                assert_eq!(
                    error,
                    ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired
                );
                assert!(self.peers[index].transport.handler.read().await.is_none());
                OpenVoter::Refused(error)
            }
        }
    }

    pub(super) fn forget_signers(&self) {
        self.signers.write().unwrap().clear();
    }
}

impl EnrolledFleet {
    async fn open_running(&self, index: usize) -> ConsensusSessionStore {
        match self.open(index).await {
            OpenVoter::Running(store) => store,
            OpenVoter::Refused(error) => panic!("intact enrolled volume refused: {error:?}"),
        }
    }
}

async fn missed_enrolled_bootstrap_campaign(restart_canonical: bool) {
    let fleet = EnrolledFleet::new().await;
    let mut stores = vec![fleet.open_running(0).await];
    let outcome = AssertUnwindSafe(async {
        // Both peer stores and listeners are absent, not merely delayed RPCs.
        // Observe the real campaigns while initialization is pending, within
        // its existing operation budget rather than starting another timeout.
        let campaign_deadline = tokio::time::Instant::now()
            + opc_session_store::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT;
        let (initialization, campaigns) = tokio::join!(
            stores[0].initialize_cluster(),
            tokio::time::timeout_at(campaign_deadline, async {
                while !fleet.peers[1..].iter().all(|peer| {
                    peer.missed_votes.load(Ordering::SeqCst) > 0
                        && peer.pre_votes.load(Ordering::SeqCst) > 0
                }) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }),
        );
        assert_eq!(
            initialization,
            Err(ConsensusSessionStoreOpenError::ClusterFormationRejected),
            "a lone voter cannot admit itself"
        );
        campaigns
            .expect("observe missed real votes and automatic Pre-Votes within the operation bound");
        for peer in &fleet.peers[1..] {
            assert!(
                peer.missed_votes.load(Ordering::SeqCst) > 0,
                "the canonical member's real bootstrap campaign missed this peer"
            );
            assert!(
                peer.pre_votes.load(Ordering::SeqCst) > 0,
                "automatic elections have reached Pre-Vote before peers start"
            );
        }
        let before = stores[0].status();
        assert_eq!(before.leader_id, None);
        assert!(!before.admitted);
        assert_eq!(before.last_log_index, Some(0));
        assert!(before.term > 0);
        assert_eq!(
            stores[0]
                .probe_fixed_durable_quorum_readiness()
                .await
                .traffic_authority(),
            FixedQuorumTrafficAuthority::NoQuorum
        );

        if restart_canonical {
            fleet.peers[0].transport.clear().await;
            stores.remove(0).shutdown().await.expect("drain lone voter");
            let reopened = fleet.open_running(0).await;
            // Opening returns before Raft publishes its recovered metrics.
            // Observe that publication before comparing the retained state.
            tokio::time::timeout(
                opc_session_store::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                async {
                    while reopened.status().last_log_index.is_none() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                },
            )
            .await
            .expect("reopened voter publishes its retained log");
            assert_eq!(reopened.status().last_log_index, before.last_log_index);
            assert_eq!(reopened.status().term, before.term);
            assert!(!reopened.status().admitted);
            stores.push(reopened);
        }
        // Opening installs the handler. Keep both routes unavailable until
        // their pristine-state assertions finish so replication cannot race
        // the second store's open or those assertions.
        for peer in &fleet.peers[1..] {
            peer.transport.set_enabled(false);
        }
        stores.push(fleet.open_running(1).await);
        stores.push(fleet.open_running(2).await);
        for store in &stores[1..] {
            assert_eq!(store.status().last_log_index, None);
            assert!(!store.status().admitted);
        }
        for peer in &fleet.peers[1..] {
            peer.transport.set_enabled(true);
        }

        // Retain the existing fixed-quorum 30-second readiness bound and every
        // initializer's production operation deadline. No forced election or
        // controlled clock can manufacture progress after the missed campaign.
        let formed = tokio::time::timeout(Duration::from_secs(30), async {
            join_all(stores.iter().map(|store| async {
                loop {
                    match store.initialize_cluster().await {
                        Ok(()) => break,
                        Err(ConsensusSessionStoreOpenError::ClusterFormationRejected) => {}
                        other => panic!("unexpected formation result: {other:?}"),
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }))
            .await;
            loop {
                let reports = join_all(
                    stores
                        .iter()
                        .map(|store| store.probe_fixed_durable_quorum_readiness()),
                )
                .await;
                if reports
                    .iter()
                    .all(|report| report.traffic_authority().is_granted())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            formed.is_ok(),
            "delayed pristine peers must form after a missed bootstrap campaign: {:?}",
            stores
                .iter()
                .map(ConsensusSessionStore::status)
                .collect::<Vec<_>>()
        );
        let leader = stores[0].status().leader_id.expect("elected leader");
        let request_id = [0x83; 16];
        let leader_store = stores
            .iter()
            .find(|store| store.status().node_id == leader)
            .expect("the elected leader belongs to the enrolled fleet");
        let committed = append_consensus_padding_entry_for_test(leader_store, request_id)
            .await
            .expect("the formed quorum durably commits a new command");
        for store in &stores {
            assert!(store.status().admitted);
            assert_eq!(store.status().leader_id, Some(leader));
            assert!(store.status().applied_index.is_some());
            tokio::time::timeout(
                opc_session_store::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                async {
                    loop {
                        match consensus_padding_receipt_status_for_test(store, request_id)
                            .await
                            .expect("read the exact durable command receipt")
                        {
                            ConsensusPaddingReceiptStatusForTest::NotFound => {}
                            receipt => {
                                assert_eq!(
                                    receipt,
                                    ConsensusPaddingReceiptStatusForTest::Recorded {
                                        raft_log_index: committed,
                                    }
                                );
                                break;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                },
            )
            .await
            .expect(
                "every enrolled voter applies the committed command within the operation bound",
            );
        }
    })
    .catch_unwind()
    .await;
    for peer in &fleet.peers {
        peer.transport.clear().await;
    }
    for result in join_all(stores.iter().map(ConsensusSessionStore::shutdown)).await {
        result.expect("drain cold formation voter");
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn delayed_pristine_enrolled_peers_recover_a_missed_bootstrap_campaign() {
    missed_enrolled_bootstrap_campaign(false).await;
}

#[tokio::test]
async fn delayed_pristine_enrolled_peers_recover_after_the_bootstrap_voter_restarts() {
    missed_enrolled_bootstrap_campaign(true).await;
}

#[tokio::test]
async fn isolated_enrolled_voters_never_gain_authority_or_repeat_real_campaigns() {
    let fleet = EnrolledFleet::new().await;
    for peer in &fleet.peers {
        peer.transport.set_enabled(false);
    }
    let stores = join_all((0..3).map(|index| fleet.open_running(index))).await;
    let outcome = AssertUnwindSafe(async {
        let mut initial_terms = Vec::new();
        for attempt in 0..2 {
            let results =
                join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster)).await;
            for (index, (store, result)) in stores.iter().zip(results).enumerate() {
                assert_eq!(
                    result,
                    Err(ConsensusSessionStoreOpenError::ClusterFormationRejected)
                );
                let status = store.status();
                assert_eq!(status.last_log_index, Some(0));
                assert_eq!(status.applied_index, None);
                assert_eq!(status.leader_id, None);
                assert!(!status.admitted);
                assert_eq!(status.term, 1);
                if attempt == 0 {
                    initial_terms.push(status.term);
                } else {
                    assert_eq!(
                        status.term, initial_terms[index],
                        "retrying initialization cannot bypass Pre-Vote or consume a term"
                    );
                }
            }
        }
    })
    .catch_unwind()
    .await;
    for peer in &fleet.peers {
        peer.transport.clear().await;
    }
    for result in join_all(stores.iter().map(ConsensusSessionStore::shutdown)).await {
        result.expect("drain isolated voter");
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
