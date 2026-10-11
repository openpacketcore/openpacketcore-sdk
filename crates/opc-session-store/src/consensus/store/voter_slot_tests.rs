use super::*;

#[path = "voter_slot_lifecycle_tests.rs"]
mod lifecycle_tests;
#[path = "voter_slot_progress_tests.rs"]
mod progress_tests;
#[path = "voter_slot_publication_tests.rs"]
mod publication_tests;
#[path = "voter_slot_retry_tests.rs"]
mod retry_tests;
use crate::topology::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
};
use opc_consensus::engine::{raft::VoteRequest, Vote};
use opc_consensus::voter_slots::*;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use std::sync::atomic::AtomicU64;

fn key(member: &VoterSlotMember) -> SigningKey {
    let seed = member.identity.slot().get() as u8 * 3 + member.identity.incarnation().get() as u8;
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}
fn public(member: &VoterSlotMember) -> [u8; 33] {
    key(member)
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn sign(member: &VoterSlotMember, bytes: &[u8]) -> [u8; 64] {
    let signature: Signature = key(member).sign_prehash(&Sha256::digest(bytes)).unwrap();
    signature.normalize_s().to_bytes().into()
}
fn member(slot: u16, incarnation: u64) -> VoterSlotMember {
    let mut member = VoterSlotMember {
        identity: VoterSlotIdentity::new(
            SlotId::new(slot).unwrap(),
            VoterIncarnation::new(incarnation).unwrap(),
        ),
        key_digest: [0; 32],
        descriptor_digest: descriptor(slot).configuration_fingerprint(),
        admission_generation: incarnation,
    };
    member.key_digest = Sha256::digest(public(&member)).into();
    member
}
fn genesis() -> VoterSlotTable {
    genesis_for(3)
}
fn genesis_for(size: u16) -> VoterSlotTable {
    VoterSlotTable {
        cluster_instance: opc_consensus::ConsensusClusterId::from_bytes([3; 32]),
        manifest_digest: [4; 32],
        revision: 1,
        configuration_epoch: opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
        slots: (1..=size)
            .map(|slot| VoterSlotRecord {
                member: member(slot, 1),
                retired_through: 0,
                phase: VoterSlotPhase::Voting,
                last_result: None,
            })
            .collect(),
        replacement: None,
    }
}

fn descriptor(slot: u16) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        ReplicaId::new(format!("slot-{slot}")).unwrap(),
        ReplicaEndpoint::new(format!("slot-{slot}.example.test"), 4100 + slot).unwrap(),
        ReplicaTlsIdentity::new(format!("spiffe://example.test/voter/{slot}")).unwrap(),
        ReplicaFailureDomain::new(format!("zone-{slot}")).unwrap(),
        ReplicaBackingIdentity::new(format!("volume-{slot}")).unwrap(),
    )
}
fn topology(local: u16) -> ValidatedQuorumTopology {
    topology_for(3, local)
}
fn topology_for(size: u16, local: u16) -> ValidatedQuorumTopology {
    let table = genesis_for(size);
    let identity = table
        .current_configuration()
        .identity(table.cluster_instance, table.manifest_digest)
        .unwrap();
    let descriptors: Vec<_> = (1..=size).map(descriptor).collect();
    let assignments = descriptors
        .iter()
        .enumerate()
        .map(|(offset, descriptor)| {
            (
                descriptor.replica_id().clone(),
                SlotId::new(offset as u16 + 1).unwrap(),
            )
        })
        .collect();
    ValidatedQuorumTopology::try_from_fixed_voter_slots(
        QuorumTopologyConfig::new_consensus(
            descriptor(local).replica_id().clone(),
            descriptors,
            identity,
        ),
        table,
        assignments,
        PlacementResiliencePolicy::RequireIndependentFailureDomains,
    )
    .unwrap()
}

fn published_voter_state(store: &ConsensusSessionStore) -> Option<VoterSlotDurableState> {
    let wal = store
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .core
        .private_wal
        .as_ref()
        .unwrap();
    match wal.native_voter_slot_state() {
        Ok(state) => Some(state),
        // Replication may have admitted the next WAL operation while its
        // strict flush is pending. Retry only that typed publication interval;
        // fencing, corruption and all other storage errors still fail here.
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            assert_eq!(
                wal.storage_health().0,
                crate::consensus::SessionStorageState::Running
            );
            None
        }
        Err(error) => panic!("voter state publication failed: {error}"),
    }
}

#[derive(Debug, Default)]
struct Network {
    handlers:
        std::sync::RwLock<BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusRpcHandler>>>,
    freeze_after_marker: AtomicU64,
    paused_replication_to: AtomicU64,
    allow_paused_requests: std::sync::Mutex<BTreeSet<[u8; 32]>>,
    paused_nonempty_append_to: AtomicU64,
    probe_append_total: AtomicU64,
    probe_append_refused: AtomicU64,
    probe_blocked: std::sync::Mutex<BTreeSet<(u64, u64)>>,
    probe_blocked_family: std::sync::Mutex<BTreeSet<(u64, u64, u8)>>,
    probe_refusals: std::sync::Mutex<Vec<String>>,
    probe_pause_after_begin_to: AtomicU64,
    probe_snapshot_delay_ms: AtomicU64,
    probe_snapshot_starts: AtomicU64,
    probe_snapshot_rpcs: AtomicU64,
    fail_nonzero_snapshot_once: AtomicU64,
    received_snapshot_offsets: std::sync::Mutex<Vec<(String, u64)>>,
    observe_empty_append_to: AtomicU64,
    empty_append_started: tokio::sync::Notify,
    held_response: std::sync::Mutex<Option<HeldResponse>>,
    active_handlers: tokio::sync::watch::Sender<BTreeMap<SessionConsensusNodeId, usize>>,
}
#[derive(Debug)]
struct HeldResponse {
    node: SessionConsensusNodeId,
    started: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}
impl Network {
    fn handler(
        &self,
        node: SessionConsensusNodeId,
    ) -> Result<InFlightHandler, SessionConsensusPeerError> {
        let handlers = self.handlers.read().unwrap();
        let handler = handlers
            .get(&node)
            .cloned()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        // Register while holding the route lock, so disconnect cannot miss a
        // handler cloned just before it removes the route.
        self.active_handlers.send_modify(|active| {
            *active.entry(node).or_default() += 1;
        });
        drop(handlers);
        Ok(InFlightHandler {
            handler,
            _call: InFlightCall {
                node,
                active: self.active_handlers.clone(),
            },
        })
    }

    async fn disconnect(&self, node: SessionConsensusNodeId) {
        let mut active = self.active_handlers.subscribe();
        self.handlers.write().unwrap().remove(&node);
        active
            .wait_for(|active| !active.contains_key(&node))
            .await
            .unwrap();
    }

    async fn disconnect_and_shutdown(&self, store: &ConsensusSessionStore) {
        tokio::time::timeout(store.inner.operation_timeout, async {
            self.disconnect(store.inner.local_node_id).await;
            store.shutdown().await.unwrap();
        })
        .await
        .expect("RPC drain and store shutdown must fit the operation budget");
    }
}
struct InFlightHandler {
    // Fields drop in declaration order: release the public store handle
    // before publishing that this RPC has drained, including on cancellation.
    handler: Arc<dyn SessionConsensusRpcHandler>,
    _call: InFlightCall,
}
struct InFlightCall {
    node: SessionConsensusNodeId,
    active: tokio::sync::watch::Sender<BTreeMap<SessionConsensusNodeId, usize>>,
}
impl Drop for InFlightCall {
    fn drop(&mut self) {
        self.active.send_modify(|active| {
            let count = active.get_mut(&self.node).unwrap();
            *count -= 1;
            if *count == 0 {
                active.remove(&self.node);
            }
        });
    }
}
#[derive(Debug, Clone)]
struct Resolver(Arc<Network>);
impl VoterPeerResolver for Resolver {
    fn resolve(
        &self,
        member: &VoterSlotMember,
    ) -> Result<VoterPeerRoute, SessionConsensusPeerError> {
        Ok(VoterPeerRoute {
            member: member.clone(),
            spiffe_id: format!(
                "spiffe://example.test/voter/{}",
                member.identity.slot().get()
            ),
            peer: Arc::new(Peer {
                network: self.0.clone(),
                member: member.clone(),
            }),
        })
    }
}
#[derive(Debug)]
struct Peer {
    network: Arc<Network>,
    member: VoterSlotMember,
}
#[async_trait]
impl SessionConsensusPeer for Peer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.member.identity.node_id()
    }
    async fn call(
        &self,
        _: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        panic!("incarnation profile used raw transport");
    }
    async fn call_with_incarnation(
        &self,
        request: SessionConsensusWireRequest,
        binding: VoterRpcBinding,
        timeout: Duration,
    ) -> Result<VoterAuthenticatedResponse, SessionConsensusPeerError> {
        if self.network.paused_replication_to.load(Ordering::SeqCst) == self.node_id().get()
            && !self
                .network
                .allow_paused_requests
                .lock()
                .unwrap()
                .contains(&voter_rpc_request_digest(&request)?)
            && matches!(
                request.family,
                SessionConsensusRpcFamily::AppendEntries
                    | SessionConsensusRpcFamily::InstallSnapshot
            )
        {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        if self
            .network
            .paused_nonempty_append_to
            .load(Ordering::SeqCst)
            == self.node_id().get()
            && request.family == SessionConsensusRpcFamily::AppendEntries
            && decode_bounded::<
                opc_consensus::engine::raft::AppendEntriesRequest<SessionRaftTypeConfig>,
            >(&request.payload)
            .is_ok_and(|rpc| !rpc.entries.is_empty())
        {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        if self
            .network
            .probe_blocked
            .lock()
            .unwrap()
            .contains(&(request.sender.get(), self.node_id().get()))
        {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        let family_code = match request.family {
            SessionConsensusRpcFamily::Vote => 1u8,
            SessionConsensusRpcFamily::AppendEntries => 2u8,
            SessionConsensusRpcFamily::InstallSnapshot => 3u8,
            SessionConsensusRpcFamily::TopologyAdmissionBarrier => 4u8,
            _ => 5u8,
        };
        if self
            .network
            .probe_blocked_family
            .lock()
            .unwrap()
            .contains(&(request.sender.get(), self.node_id().get(), family_code))
        {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        if request.family == SessionConsensusRpcFamily::InstallSnapshot {
            self.network
                .probe_snapshot_rpcs
                .fetch_add(1, Ordering::SeqCst);
            if decode_bounded::<
                opc_consensus::engine::raft::InstallSnapshotRequest<SessionRaftTypeConfig>,
            >(&request.payload)
            .is_ok_and(|rpc| rpc.offset == 0)
            {
                self.network
                    .probe_snapshot_starts
                    .fetch_add(1, Ordering::SeqCst);
            }
            let delay = self.network.probe_snapshot_delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }
        if request.family == SessionConsensusRpcFamily::InstallSnapshot
            && decode_bounded::<
                opc_consensus::engine::raft::InstallSnapshotRequest<SessionRaftTypeConfig>,
            >(&request.payload)
            .is_ok_and(|rpc| rpc.offset > 0)
            && self
                .network
                .fail_nonzero_snapshot_once
                .swap(0, Ordering::SeqCst)
                != 0
        {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        let handler = self.network.handler(self.node_id())?;
        assert_eq!(binding.destination, self.member);
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
                public(&binding.source),
                sign(
                    &binding.source,
                    &voter_rpc_possession_signing_input(&challenge).unwrap(),
                ),
            )
            .map_err(|_| SessionConsensusPeerError::Rejected)?;
        if self.network.observe_empty_append_to.load(Ordering::SeqCst) == self.node_id().get()
            && request.family == SessionConsensusRpcFamily::AppendEntries
            && decode_bounded::<
                opc_consensus::engine::raft::AppendEntriesRequest<SessionRaftTypeConfig>,
            >(&request.payload)
            .is_ok_and(|rpc| rpc.entries.is_empty())
        {
            self.network.empty_append_started.notify_one();
        }
        let response = handler
            .handler
            .handle_with_incarnation(proof, request.clone())
            .await;
        let held = {
            let mut held = self.network.held_response.lock().unwrap();
            if held
                .as_ref()
                .is_some_and(|held| held.node == self.node_id())
            {
                held.take()
            } else {
                None
            }
        };
        if let Some(held) = held {
            let _ = held.started.send(());
            let _ = held.release.await;
        }
        if request.family == SessionConsensusRpcFamily::InstallSnapshot && response.result.is_ok() {
            let rpc: opc_consensus::engine::raft::InstallSnapshotRequest<SessionRaftTypeConfig> =
                decode_bounded(&request.payload).unwrap();
            self.network
                .received_snapshot_offsets
                .lock()
                .unwrap()
                .push((rpc.meta.snapshot_id, rpc.offset));
        }
        if request.family == SessionConsensusRpcFamily::AppendEntries
            && self.network.probe_pause_after_begin_to.load(Ordering::SeqCst) == self.node_id().get()
            && decode_bounded::<
                opc_consensus::engine::raft::AppendEntriesRequest<SessionRaftTypeConfig>,
            >(&request.payload)
            .is_ok_and(|rpc| {
                rpc.entries.iter().any(|entry| {
                    matches!(&entry.payload, opc_consensus::engine::EntryPayload::Normal(command)
                        if matches!(&command.intent, SessionMutationIntent::VoterSlotControl(bytes)
                            if matches!(VoterSlotControl::decode(bytes), Ok(VoterSlotControl::Begin(_)))))
                })
            })
        {
            self.network.probe_pause_after_begin_to.store(0, Ordering::SeqCst);
            self.network
                .paused_replication_to
                .store(self.node_id().get(), Ordering::SeqCst);
        }
        if request.family == SessionConsensusRpcFamily::AppendEntries {
            self.network
                .probe_append_total
                .fetch_add(1, Ordering::SeqCst);
            if let Err(error) = &response.result {
                self.network
                    .probe_append_refused
                    .fetch_add(1, Ordering::SeqCst);
                let entries = decode_bounded::<
                    opc_consensus::engine::raft::AppendEntriesRequest<SessionRaftTypeConfig>,
                >(&request.payload)
                .map(|rpc| rpc.entries.len())
                .unwrap_or(usize::MAX);
                self.network.probe_refusals.lock().unwrap().push(format!(
                    "{}->{} entries={} error={error:?}",
                    request.sender.get(),
                    self.node_id().get(),
                    entries
                ));
            }
        }
        if request.family == SessionConsensusRpcFamily::TopologyAdmissionBarrier
            && self.network.freeze_after_marker.load(Ordering::SeqCst) == self.node_id().get()
            && response.result.as_ref().is_ok_and(|payload| {
                matches!(
                    decode_bounded::<Result<voter_slots::ControlReply, VoterReplacementError>>(
                        payload
                    ),
                    Ok(Ok(voter_slots::ControlReply::AppliedMarker(_)))
                )
            })
        {
            self.network.freeze_after_marker.store(0, Ordering::SeqCst);
            self.network
                .paused_replication_to
                .store(self.node_id().get(), Ordering::SeqCst);
        }

        let response_binding = VoterRpcBinding {
            source: binding.destination.clone(),
            destination: binding.source.clone(),
            source_spiffe_id: binding.destination_spiffe_id,
            destination_spiffe_id: binding.source_spiffe_id,
            kind: VoterRpcProofKind::Response,
            payload_digest: voter_rpc_response_digest(&request, &response)?,
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
                public(&self.member),
                sign(
                    &self.member,
                    &voter_rpc_possession_signing_input(&challenge).unwrap(),
                ),
            )
            .map_err(|_| SessionConsensusPeerError::Rejected)?;
        Ok(VoterAuthenticatedResponse { response, proof })
    }
}

struct Fleet {
    nodes: Vec<ConsensusSessionStore>,
    network: Arc<Network>,
    directories: Vec<tempfile::TempDir>,
}
impl Fleet {
    async fn open() -> Self {
        Self::open_size(3).await
    }
    async fn open_size(size: u16) -> Self {
        Self::open_size_with_io_hook(size, None).await
    }
    async fn open_size_with_io_hook(
        size: u16,
        hook: Option<(u16, crate::sqlite::consensus::wal::owner::IoHookForTest)>,
    ) -> Self {
        let network = Arc::new(Network::default());
        let mut nodes = Vec::new();
        let mut directories = Vec::new();
        for slot in 1..=size {
            let directory = tempfile::tempdir().unwrap();
            let backend =
                SqliteSessionBackend::open(directory.path().join("session.sqlite")).unwrap();
            if let Some((selected, hook)) = &hook {
                if slot == *selected {
                    backend
                        .native_owner
                        .as_ref()
                        .unwrap()
                        .set_io_hook_for_test(hook.clone());
                }
            }
            let store = ConsensusSessionStore::open_with_voter_slots_and_integrity(
                topology_for(size, slot),
                genesis_for(size),
                member(slot, 1).identity.node_id(),
                backend,
                directory.path().join("snapshots"),
                Arc::new(Resolver(network.clone())),
                super::super::SnapshotIntegrityPolicy::PortableVerified,
            )
            .await
            .unwrap();
            network
                .handlers
                .write()
                .unwrap()
                .insert(member(slot, 1).identity.node_id(), store.rpc_handler());
            nodes.push(store);
            directories.push(directory);
        }
        let mut formation = tokio::task::JoinSet::new();
        for node in &nodes {
            let node = node.clone();
            formation.spawn(async move { node.initialize_cluster().await });
        }
        while let Some(result) = formation.join_next().await {
            result.unwrap().unwrap();
        }
        let fleet = Self {
            nodes,
            network,
            directories,
        };
        fleet.nodes[0].inner.raft.trigger().elect().await.unwrap();
        fleet.nodes[0]
            .inner
            .raft
            .wait(Some(Duration::from_secs(5)))
            .current_leader(member(1, 1).identity.node_id(), "fixture leader")
            .await
            .unwrap();
        fleet.nodes[0]
            .inner
            .raft
            .ensure_linearizable()
            .await
            .unwrap();
        fleet
    }
    async fn close(self) {
        self.network.handlers.write().unwrap().clear();
        for node in self.nodes {
            self.network.disconnect_and_shutdown(&node).await;
        }
        drop(self.directories);
    }
}

fn verified_request(table: &VoterSlotTable, slot: u16) -> VerifiedVoterReplacement {
    let old = &table.slots[usize::from(slot - 1)].member;
    let candidate = member(slot, old.identity.incarnation().get() + 1);
    let controller = member(20, 1);
    let controller_spiffe = "spiffe://example.test/controller";
    let authority = VoterReplacementAuthorization::new(
        table.cluster_instance,
        BTreeSet::from([SlotId::new(slot).unwrap()]),
        controller_spiffe.into(),
        public(&controller),
        [8; 32],
        Duration::from_millis(100),
    )
    .unwrap();
    let expected_configuration = table
        .current_configuration()
        .identity(table.cluster_instance, table.manifest_digest)
        .unwrap();
    let mut attestation = LostVoterAttestationV1 {
        request_id: opc_consensus::ConsensusRequestId::from_bytes([slot as u8; 16]),
        request_digest: [0; 32],
        cluster_instance: table.cluster_instance,
        slot: old.identity.slot(),
        expected_incarnation: old.identity.incarnation(),
        old_descriptor_digest: old.descriptor_digest,
        candidate_key_digest: candidate.key_digest,
        admission_generation: candidate.admission_generation,
        candidate_spiffe_id: format!("spiffe://example.test/voter/{slot}"),
        controller_spiffe_id: controller_spiffe.into(),
        signing_key_digest: authority.credential_digest(),
        reason: VoterLossReason::TimeBoundLoss,
        policy_digest: [8; 32],
        observation_start_ms: 100,
        decision_ms: 200,
        issued_ms: 200,
        expires_ms: 60200,
        signature: [0; 64],
    };
    attestation.request_digest = voter_replacement_request_digest(
        table.revision,
        expected_configuration,
        &candidate,
        &attestation,
    )
    .unwrap();
    attestation.signature = sign(
        &controller,
        &lost_voter_attestation_signing_input(&attestation).unwrap(),
    );
    let request = VoterReplacementRequest {
        expected_revision: table.revision,
        expected_configuration,
        candidate: candidate.clone(),
        attestation,
    };
    let issuer = VoterChallengeIssuer::new();
    let challenge = issuer
        .issue_candidate(
            VoterCandidateBinding {
                cluster_instance: table.cluster_instance,
                identity: candidate.identity,
                request_digest: request.attestation.request_digest,
                key_digest: candidate.key_digest,
                spiffe_id: request.attestation.candidate_spiffe_id.clone(),
            },
            [7; 32],
            tokio::time::Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
    let candidate_proof = issuer
        .verify_candidate(
            &challenge,
            &request.attestation.candidate_spiffe_id,
            [7; 32],
            public(&candidate),
            sign(
                &candidate,
                &voter_candidate_possession_signing_input(&challenge).unwrap(),
            ),
        )
        .unwrap();
    VoterReplacementVerifier::new()
        .verify(
            &request,
            &authority,
            controller_spiffe,
            TrustedVoterTime::new(201, 202).unwrap(),
            candidate_proof,
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_loss_claim_for_a_live_voter_has_no_effect() {
    let fleet = Fleet::open().await;
    let leader = &fleet.nodes[0];
    let before = leader.voter_slot_state().await.unwrap();
    assert_eq!(
        leader
            .replace_voter(verified_request(before.table(), 3))
            .await,
        Err(VoterReplacementError::TargetStillLive)
    );
    assert_eq!(leader.voter_slot_state().await.unwrap(), before);
    leader.inner.raft.ensure_linearizable().await.unwrap();
    fleet.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_voter_replacement_installs_snapshot_and_finishes_real_joint_consensus() {
    let mut fleet = Fleet::open().await;
    let leader = fleet.nodes[0].clone();
    fleet.network.disconnect_and_shutdown(&fleet.nodes[2]).await;
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(100)).await;
    let prepared = leader
        .replace_voter(verified_request(&genesis(), 3))
        .await
        .unwrap();
    assert!(prepared.table().is_retired(member(3, 1).identity.node_id()));
    // Recovery queries use the controller's current authorization, even after
    // the accepted credential or policy has rotated. They grant no new slot.
    let retained = &prepared.table().replacement.as_ref().unwrap().attestation;
    let current = VoterReplacementAuthorization::new(
        genesis().cluster_instance,
        BTreeSet::from([SlotId::new(3).unwrap()]),
        "spiffe://example.test/recovery-controller".into(),
        public(&member(21, 1)),
        [19; 32],
        Duration::from_secs(90),
    )
    .unwrap();
    let status = leader
        .voter_replacement_status(
            &current,
            "spiffe://example.test/recovery-controller",
            SlotId::new(3).unwrap(),
            retained.request_id,
            retained.request_digest,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        status.table().replacement.as_ref().unwrap().attestation,
        *retained
    );
    assert_eq!(
        leader
            .voter_replacement_status(
                &current,
                "spiffe://example.test/unauthorized",
                SlotId::new(3).unwrap(),
                retained.request_id,
                retained.request_digest,
            )
            .await,
        Err(VoterReplacementError::UnauthorizedReplacement)
    );
    assert_eq!(
        leader
            .voter_replacement_status(
                &current,
                "spiffe://example.test/recovery-controller",
                SlotId::new(3).unwrap(),
                retained.request_id,
                [31; 32],
            )
            .await,
        Err(VoterReplacementError::IdempotencyConflict)
    );
    let prepare_index = prepared
        .table()
        .replacement
        .as_ref()
        .unwrap()
        .evidence
        .prepare
        .index;
    fleet.nodes[1]
        .inner
        .raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(prepare_index), "survivor prepare before restart")
        .await
        .unwrap();
    let survivor = fleet.nodes.remove(1);
    fleet.network.disconnect_and_shutdown(&survivor).await;
    drop(survivor);
    let directory = fleet.directories[1].path();
    let backend = SqliteSessionBackend::open(directory.join("session.sqlite")).unwrap();
    let survivor = ConsensusSessionStore::open_with_voter_slots_and_integrity(
        topology(2),
        genesis(),
        member(2, 1).identity.node_id(),
        backend,
        directory.join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
        super::super::SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .insert(member(2, 1).identity.node_id(), survivor.rpc_handler());
    fleet.nodes.insert(1, survivor.clone());
    let before = survivor
        .inner
        .raft
        .with_raft_state(|state| *state.vote_ref())
        .await
        .unwrap();
    let request = SessionConsensusWireRequest::try_new(
        leader.inner.storage_identity,
        member(3, 1).identity.node_id(),
        SessionConsensusRpcFamily::Vote,
        encode_bounded(&VoteRequest {
            vote: Vote::new(100, member(3, 1).identity.node_id()),
            last_log_id: None,
        })
        .unwrap(),
    )
    .unwrap();
    let response = fleet.nodes[2]
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .transport
        .peer(member(2, 1).identity.node_id())
        .call(request)
        .await
        .unwrap();
    assert_eq!(
        response.result,
        Err(SessionConsensusPeerError::ScopeMismatch)
    );
    assert_eq!(
        before,
        survivor
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap()
    );
    let directory = tempfile::tempdir().unwrap();
    let backend = SqliteSessionBackend::open(directory.path().join("session.sqlite")).unwrap();
    let candidate = ConsensusSessionStore::open_with_voter_slots_and_integrity(
        topology(3),
        prepared.table().clone(),
        member(3, 2).identity.node_id(),
        backend,
        directory.path().join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
        super::super::SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    // A selected, pristine candidate must recover its Pending binding before
    // the first snapshot, without manufacturing local voting authority.
    candidate.shutdown().await.unwrap();
    drop(candidate);
    let backend = SqliteSessionBackend::open(directory.path().join("session.sqlite")).unwrap();
    let candidate = ConsensusSessionStore::open_with_voter_slots_and_integrity(
        topology(3),
        prepared.table().clone(),
        member(3, 2).identity.node_id(),
        backend,
        directory.path().join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
        super::super::SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    assert!(!candidate
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
    fleet
        .network
        .freeze_after_marker
        .store(member(3, 2).identity.node_id().get(), Ordering::SeqCst);
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .insert(member(3, 2).identity.node_id(), candidate.rpc_handler());
    fleet.nodes.push(candidate.clone());
    fleet.directories.push(directory);
    let mut progress = leader
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .core
        .applied_progress
        .subscribe();
    let finished = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(state) = published_voter_state(&leader) {
                if state.table().replacement.is_none() {
                    break state;
                }
            }
            tokio::select! {
                result = progress.changed() => result.unwrap(),
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    })
    .await
    .expect("replacement must resume automatically when the selected candidate appears");
    assert_eq!(finished.table().configuration_epoch.get(), 2);
    assert!(finished.table().is_retired(member(3, 1).identity.node_id()));
    let membership = leader
        .inner
        .raft
        .with_raft_state(|state| state.membership_state.effective().membership().clone())
        .await
        .unwrap();
    assert_eq!(membership.get_joint_config().len(), 1);
    assert_eq!(
        membership.voter_ids().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            member(1, 1).identity.node_id(),
            member(2, 1).identity.node_id(),
            member(3, 2).identity.node_id()
        ])
    );
    // Finalize publication can precede the admission worker releasing the old
    // engine fence. That release deliberately invalidates in-flight read
    // probes, so require a fresh surviving quorum within the original budget.
    // The candidate stays disconnected throughout this proof.
    tokio::time::timeout(leader.inner.operation_timeout, async {
        loop {
            match leader.inner.raft.ensure_linearizable().await {
                Ok(_) => break,
                Err(opc_consensus::engine::error::RaftError::APIError(
                    opc_consensus::engine::error::CheckIsLeaderError::QuorumNotEnough(_),
                )) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => panic!("surviving quorum lost its leader: {error}"),
            }
        }
    })
    .await
    .expect("surviving quorum must recover admission without the candidate");
    assert!(!candidate.inner.voter_profile.as_ref().unwrap().admission.local_voting_admitted(), "the surviving majority finishes after Fence without the candidate's vote or another live barrier");
    fleet
        .network
        .paused_replication_to
        .store(0, Ordering::SeqCst);
    let mut applied = candidate
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .core
        .applied_progress
        .subscribe();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if published_voter_state(&candidate).is_some_and(|state| {
                state.table().replacement.is_none() && state.table().configuration_epoch.get() == 2
            }) && candidate
                .inner
                .voter_profile
                .as_ref()
                .unwrap()
                .admission
                .local_voting_admitted()
            {
                break;
            }
            tokio::select! {
                result = applied.changed() => result.unwrap(),
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    })
    .await
    .expect("candidate must apply finalization under the successor configuration");
    assert!(candidate
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
    // Reopening the retained selected identity recovers Voting and permanent
    // retirement from the native generation before its RPC handler is exposed.
    fleet.network.disconnect_and_shutdown(&candidate).await;
    fleet.nodes.pop();
    drop(candidate);
    let directory = fleet.directories.last().unwrap().path();
    let backend = SqliteSessionBackend::open(directory.join("session.sqlite")).unwrap();
    let reopened = ConsensusSessionStore::open_with_voter_slots_and_integrity(
        topology(3),
        prepared.table().clone(),
        member(3, 2).identity.node_id(),
        backend,
        directory.join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
        super::super::SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    assert_eq!(reopened.voter_slot_state().await.unwrap(), finished);
    assert!(reopened
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
    let core = &reopened.inner.voter_profile.as_ref().unwrap().core;
    assert!(
        !core
            .private_wal
            .as_ref()
            .unwrap()
            .native_fixed_read(
                crate::sqlite::consensus::wal::native::FixedReadExpectation {
                    identity: core.storage_identity,
                    members: &core.expected_members,
                    bindings: &core.expected_bindings,
                    placement: core.fixed_placement_policy.unwrap(),
                    pristine: false,
                    database_path: None,
                },
                |_, exact| Ok(exact),
            )
            .unwrap(),
        "reopening a voting successor must not manufacture legacy application authority"
    );
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .insert(member(3, 2).identity.node_id(), reopened.rpc_handler());
    fleet.nodes.push(reopened);
    drop(survivor);
    // Do not shut down the already stopped old instance twice.
    fleet.nodes.remove(2);
    fleet.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_slot_five_and_nine_voter_quorums_refuse_raw_high_term_traffic() {
    for size in [5, 9] {
        let fleet = Fleet::open_size(size).await;
        let receiver = &fleet.nodes[1];
        assert!(receiver.exact_membership_is_admitted());
        let before = receiver
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap();
        let response = receiver
            .rpc_handler()
            .handle(
                member(1, 1).identity.node_id(),
                SessionConsensusWireRequest::try_new(
                    receiver.inner.storage_identity,
                    member(1, 1).identity.node_id(),
                    SessionConsensusRpcFamily::Vote,
                    encode_bounded(&VoteRequest {
                        vote: Vote::new(100, member(1, 1).identity.node_id()),
                        last_log_id: None,
                    })
                    .unwrap(),
                )
                .unwrap(),
            )
            .await;
        assert_eq!(
            response.result,
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
        assert_eq!(
            before,
            receiver
                .inner
                .raft
                .with_raft_state(|state| *state.vote_ref())
                .await
                .unwrap()
        );
        assert_eq!(
            receiver.voter_slot_state().await.unwrap().table(),
            &genesis_for(size)
        );
        fleet.nodes[0]
            .inner
            .raft
            .ensure_linearizable()
            .await
            .unwrap();
        fleet.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_snapshot_barrier_closes_local_application_admission_before_dispatch() {
    let fleet = Fleet::open().await;
    let target = fleet.nodes[2].clone();
    assert!(target.exact_membership_is_admitted());
    let mut incoming = genesis();
    incoming
        .apply_control(
            &VoterSlotControl::Begin(Box::new(verified_request(&genesis(), 3).request().clone())),
            VoterSlotLogId {
                term: 10,
                index: 100,
            },
        )
        .unwrap();
    let members = genesis()
        .current_configuration()
        .members
        .iter()
        .map(|member| member.identity.node_id())
        .collect();
    let probe = target.clone();
    let closed = target
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .run_snapshot(
            incoming,
            members,
            tokio::time::Instant::now() + Duration::from_secs(5),
            move || async move { Ok(!probe.exact_membership_is_admitted()) },
        )
        .await
        .unwrap();
    assert!(
        closed,
        "local traffic must close before a snapshot can publish retirement"
    );
    assert!(
        target.exact_membership_is_admitted(),
        "a definitively unused snapshot barrier releases its provisional closure"
    );
    drop(target);
    fleet.close().await;
}

#[tokio::test]
async fn voter_slot_opener_rejects_a_local_incarnation_from_another_logical_slot() {
    let directory = tempfile::tempdir().unwrap();
    let backend = SqliteSessionBackend::open(directory.path().join("session.sqlite")).unwrap();
    let result = ConsensusSessionStore::open_with_voter_slots_and_integrity(
        topology(1),
        genesis(),
        member(2, 1).identity.node_id(),
        backend,
        directory.path().join("snapshots"),
        Arc::new(Resolver(Arc::new(Network::default()))),
        super::super::SnapshotIntegrityPolicy::PortableVerified,
    )
    .await;
    if let Ok(store) = &result {
        store.shutdown().await.unwrap();
    }
    assert!(matches!(
        result,
        Err(ConsensusSessionStoreOpenError::InvalidTopology)
    ));
    assert!(!directory.path().join("snapshots").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_snapshot_deadline_retains_inspected_artifact_until_engine_completion() {
    use super::super::snapshot::SnapshotArtifactGate;
    use opc_consensus::engine::raft::InstallSnapshotRequest;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let fleet = Fleet::open().await;
    let leader = &fleet.nodes[0];
    leader.inner.raft.trigger().snapshot().await.unwrap();
    let mut progress = leader.inner.raft.metrics();
    let mut snapshot = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(snapshot) = leader.inner.raft.get_snapshot().await.unwrap() {
                break snapshot;
            }
            progress.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    snapshot
        .snapshot
        .seek(std::io::SeekFrom::Start(0))
        .await
        .unwrap();
    let mut data = Vec::new();
    snapshot.snapshot.read_to_end(&mut data).await.unwrap();
    let vote = leader
        .inner
        .raft
        .with_raft_state(|state| *state.vote_ref())
        .await
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let backend = SqliteSessionBackend::open(directory.path().join("session.sqlite")).unwrap();
    let target = ConsensusSessionStore::open_with_voter_slots_and_integrity(
        topology(3),
        genesis(),
        member(3, 1).identity.node_id(),
        backend,
        directory.path().join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
        super::super::SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    let profile = target.inner.voter_profile.as_ref().unwrap().clone();
    let path = profile.core.snapshot_dir.as_ref().clone();
    let gate = Arc::new(SnapshotArtifactGate::new());
    gate.arm();
    let guard =
        storage::SnapshotInstallAppliedProgressGateGuard::install(path.clone(), gate.clone());
    let installer = target.clone();
    let call = tokio::spawn(async move {
        profile
            .receive_snapshot(
                &installer,
                member(1, 1).identity.node_id(),
                InstallSnapshotRequest {
                    vote,
                    meta: snapshot.meta,
                    offset: 0,
                    data,
                    done: true,
                },
                None,
                tokio::time::Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), gate.wait_started())
        .await
        .unwrap();
    let incoming = || -> BTreeSet<_> {
        std::fs::read_dir(&path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("incoming-")
            })
            .collect()
    };
    let retained = incoming();
    assert!(
        !retained.is_empty(),
        "inspection owns a sealed incoming artifact during install"
    );
    let result = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .unwrap()
        .unwrap();
    let still_retained = retained.is_subset(&incoming());
    gate.release();
    drop(guard);
    target.shutdown().await.unwrap();
    drop(target);
    fleet.close().await;
    assert_eq!(result, Err(VoterReplacementError::OutcomeUnknown));
    assert!(still_retained, "the caller deadline must not release the inspected artifact while the engine owns installation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_provisional_prepare_reinstalls_the_engine_fence_before_reopened_rpc_admission() {
    let mut fleet = Fleet::open().await;
    for node in &fleet.nodes {
        node.inner.raft.runtime_config().elect(false);
    }
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .remove(&member(3, 1).identity.node_id());
    fleet.nodes[2].shutdown().await.unwrap();
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(100)).await;
    // Empty read probes still reach the surviving majority. Only the Prepare
    // entry cannot replicate, so the local durable intent remains uncommitted.
    fleet
        .network
        .paused_nonempty_append_to
        .store(member(2, 1).identity.node_id().get(), Ordering::SeqCst);
    let leader = fleet.nodes.remove(0);
    assert_eq!(
        leader.replace_voter(verified_request(&genesis(), 3)).await,
        Err(VoterReplacementError::OutcomeUnknown)
    );
    let provisional = leader.voter_slot_state().await.unwrap();
    assert!(provisional.intent().is_some());
    assert_eq!(provisional.table(), &genesis());
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .remove(&member(1, 1).identity.node_id());
    leader.shutdown().await.unwrap();
    drop(leader);
    let directory = fleet.directories[0].path();
    let reopened = ConsensusSessionStore::open_with_voter_slots_and_integrity(
        topology(1),
        genesis(),
        member(1, 1).identity.node_id(),
        SqliteSessionBackend::open(directory.join("session.sqlite")).unwrap(),
        directory.join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
        super::super::SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    reopened.inner.raft.runtime_config().elect(false);
    assert_eq!(reopened.voter_slot_state().await.unwrap(), provisional);
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .insert(member(1, 1).identity.node_id(), reopened.rpc_handler());
    let before = reopened
        .inner
        .raft
        .with_raft_state(|state| *state.vote_ref())
        .await
        .unwrap();
    let request = SessionConsensusWireRequest::try_new(
        reopened.inner.storage_identity,
        member(3, 1).identity.node_id(),
        SessionConsensusRpcFamily::Vote,
        encode_bounded(&VoteRequest {
            vote: Vote::new(100, member(3, 1).identity.node_id()),
            last_log_id: None,
        })
        .unwrap(),
    )
    .unwrap();
    let response = fleet.nodes[1]
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .transport
        .peer(member(1, 1).identity.node_id())
        .call(request)
        .await
        .unwrap();
    assert_eq!(
        response.result,
        Err(SessionConsensusPeerError::ScopeMismatch)
    );
    assert_eq!(
        reopened
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap(),
        before
    );
    fleet
        .network
        .paused_nonempty_append_to
        .store(0, Ordering::SeqCst);
    reopened.inner.raft.trigger().elect().await.unwrap();
    let mut progress = reopened
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .core
        .applied_progress
        .subscribe();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if reopened
                .voter_slot_state()
                .await
                .unwrap()
                .table()
                .is_retired(member(3, 1).identity.node_id())
            {
                break;
            }
            progress.changed().await.unwrap();
        }
    })
    .await
    .expect(
        "a surviving majority can commit the inherited Prepare without another controller call",
    );
    assert!(reopened
        .voter_slot_state()
        .await
        .unwrap()
        .intent()
        .is_none());
    fleet.nodes.remove(1); // the old incarnation was already shut down
    fleet.nodes.push(reopened);
    fleet.close().await;
}

// Election recovery regressions derived from the adversarial review.

fn probe_marker(store: &ConsensusSessionStore, task: u8, n: u32) -> SessionConsensusCommand {
    let mut id = [0u8; 16];
    id[0] = 0xEE;
    id[1] = task;
    id[2..6].copy_from_slice(&n.to_be_bytes());
    let request_id = opc_consensus::ConsensusRequestId::from_bytes(id);
    SessionConsensusCommand {
        schema_version: crate::sqlite::consensus::voter_slots::COMMAND_VERSION,
        identity: store.inner.storage_identity,
        request_id,
        logical_time: store.inner.clock.now_utc(),
        intent: SessionMutationIntent::VoterSlotControl(
            VoterSlotControl::Marker {
                request_id,
                request_digest: [0; 32],
            }
            .encode()
            .unwrap(),
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_higher_term_target_leader_truncates_vetoed_prepare() {
    vetoed_prepare_recovers_with_elected_leader(3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_survivor_leader_truncates_vetoed_prepare() {
    vetoed_prepare_recovers_with_elected_leader(2).await;
}

async fn vetoed_prepare_recovers_with_elected_leader(winner: u16) {
    let a = member(1, 1).identity.node_id().get();
    let b = member(2, 1).identity.node_id().get();
    let c = member(3, 1).identity.node_id().get();
    let mut fleet = Fleet::open().await;
    let leader = fleet.nodes[0].clone();
    let loser = if winner == 3 { 2 } else { 3 };
    for node in &fleet.nodes {
        node.inner.raft.runtime_config().elect(false);
    }
    // C is alive but partitioned from both survivors for a full window, so the
    // leader's probe and the follower's probe both see no recent target traffic.
    {
        let mut blocked = fleet.network.probe_blocked.lock().unwrap();
        for pair in [(c, a), (a, c), (c, b), (b, c)] {
            blocked.insert(pair);
        }
    }
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(200)).await;
    // Hold the Prepare append to B in the network so the race is deterministic.
    fleet
        .network
        .paused_nonempty_append_to
        .store(b, Ordering::SeqCst);
    let request = verified_request(&genesis(), 3);
    let proposer = leader.clone();
    let proposal = tokio::spawn(async move { proposer.replace_voter(request).await });
    // Wait until A has passed its probe, fenced C and durably appended Prepare.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if published_voter_state(&leader).is_some_and(|state| state.intent().is_some()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("leader appends its provisional Prepare");
    // The live target reconnects to B and B accepts one authenticated message
    // from it before the Prepare append reaches B's pre-dispatch recheck.
    {
        let mut blocked = fleet.network.probe_blocked.lock().unwrap();
        blocked.remove(&(c, b));
        blocked.remove(&(b, c));
    }
    let vote = SessionConsensusWireRequest::try_new(
        leader.inner.storage_identity,
        member(3, 1).identity.node_id(),
        SessionConsensusRpcFamily::Vote,
        encode_bounded(&VoteRequest {
            vote: Vote::new(0, member(3, 1).identity.node_id()),
            last_log_id: None,
        })
        .unwrap(),
    )
    .unwrap();
    let traffic = fleet.nodes[2]
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .transport
        .peer(member(2, 1).identity.node_id())
        .call(vote)
        .await;
    assert!(traffic.is_ok(), "B accepts authenticated evidence from C");
    // Hold back the other contender only after delivering C's proof to B.
    // Admission reconciliation can re-enable ordinary election timers.
    {
        let mut families = fleet.network.probe_blocked_family.lock().unwrap();
        let source = member(loser, 1).identity.node_id().get();
        for target in [a, b, c].into_iter().filter(|target| *target != source) {
            families.insert((source, target, 1));
        }
    }
    assert_eq!(
        fleet.nodes[1]
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .check_target_absent(member(3, 1).identity.node_id()),
        Err(VoterReplacementError::TargetStillLive)
    );
    fleet
        .network
        .paused_nonempty_append_to
        .store(0, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fleet
                .network
                .probe_refusals
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.starts_with(&format!("{a}->{b}")))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("B must veto the replicated Prepare after its own target-traffic recheck");
    assert!(fleet.nodes[1]
        .voter_slot_state()
        .await
        .unwrap()
        .intent()
        .is_none());
    // Only the selected survivor can win the next ordinary election. Exercise
    // both B's normal recovery and the provisionally fenced target C.
    {
        let mut blocked = fleet.network.probe_blocked.lock().unwrap();
        blocked.remove(&(c, a));
        blocked.remove(&(a, c));
    }
    let target = fleet.nodes[usize::from(winner - 1)].clone();
    target.inner.raft.trigger().elect().await.unwrap();
    let elected = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if target.inner.raft.metrics().borrow().current_leader
                == Some(member(winner, 1).identity.node_id())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    elected.expect("selected survivor wins the next election");
    fleet.network.probe_blocked_family.lock().unwrap().clear();
    let refused_by_b = fleet
        .network
        .probe_refusals
        .lock()
        .unwrap()
        .iter()
        .filter(|line| line.starts_with(&format!("{a}->{b}")))
        .count();
    assert!(
        refused_by_b > 0,
        "survivor must veto the Prepare after seeing target traffic"
    );
    let _ = proposal.await.unwrap();
    let recovered = wait_for_intent_truncation(&leader).await;
    // Lose the other survivor: A and the elected leader must still commit.
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .remove(&member(loser, 1).identity.node_id());
    let write = tokio::time::timeout(
        Duration::from_secs(20),
        target
            .inner
            .raft
            .client_write(probe_marker(&target, 0xAA, 1)),
    )
    .await;
    fleet
        .nodes
        .remove(usize::from(loser - 1))
        .shutdown()
        .await
        .unwrap();
    fleet.close().await;
    assert!(
        recovered,
        "higher-term leader could not truncate the provisional Prepare"
    );
    assert!(
        matches!(write, Ok(Ok(_))),
        "A and the elected survivor must commit without operator recovery: {write:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_higher_term_target_leader_truncates_reopened_prepare() {
    let a = member(1, 1).identity.node_id().get();
    let b = member(2, 1).identity.node_id().get();
    let c = member(3, 1).identity.node_id().get();
    let mut fleet = Fleet::open().await;
    let leader = fleet.nodes[0].clone();
    {
        let mut blocked = fleet.network.probe_blocked.lock().unwrap();
        for pair in [(c, a), (a, c), (c, b), (b, c)] {
            blocked.insert(pair);
        }
    }
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(200)).await;
    fleet
        .network
        .paused_nonempty_append_to
        .store(b, Ordering::SeqCst);
    let proposer = leader.clone();
    let proposal = tokio::spawn(async move {
        proposer
            .replace_voter(verified_request(&genesis(), 3))
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if published_voter_state(&leader).is_some_and(|state| state.intent().is_some()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("leader appends its provisional Prepare");
    // A crashes right after its local Prepare append; no survivor vetoes anything.
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .remove(&member(1, 1).identity.node_id());
    let crashed = fleet.nodes.remove(0);
    crashed.shutdown().await.unwrap();
    drop(crashed);
    let _ = proposal.await;
    // Release every handle on the stopped instance, as a crashed process would.
    drop(leader);
    fleet
        .network
        .paused_nonempty_append_to
        .store(0, Ordering::SeqCst);
    fleet.network.probe_blocked.lock().unwrap().clear();
    // B's own vote requests are lost for a while, so the live target C wins.
    {
        let mut families = fleet.network.probe_blocked_family.lock().unwrap();
        families.insert((b, a, 1));
        families.insert((b, c, 1));
    }
    let target = fleet.nodes[1].clone();
    let elected = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if target.inner.raft.metrics().borrow().current_leader
                == Some(member(3, 1).identity.node_id())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    fleet.network.probe_blocked_family.lock().unwrap().clear();
    elected.expect("live target wins while the Prepare holder is down");
    // A restarts with its retained disk.
    let directory = fleet.directories[0].path().to_path_buf();
    let mut attempt = 0;
    let reopened = loop {
        attempt += 1;
        let result = ConsensusSessionStore::open_with_voter_slots_and_integrity(
            topology(1),
            genesis(),
            member(1, 1).identity.node_id(),
            SqliteSessionBackend::open(directory.join("session.sqlite")).unwrap(),
            directory.join("snapshots"),
            Arc::new(Resolver(fleet.network.clone())),
            super::super::SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
        match result {
            Ok(store) => {
                break store;
            }
            Err(error) => {
                if attempt >= 6 {
                    panic!("reopen never succeeded: {error:?}");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .insert(member(1, 1).identity.node_id(), reopened.rpc_handler());
    let recovered = wait_for_intent_truncation(&reopened).await;
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .remove(&member(2, 1).identity.node_id());
    let write = tokio::time::timeout(
        Duration::from_secs(20),
        target
            .inner
            .raft
            .client_write(probe_marker(&target, 0xAB, 1)),
    )
    .await;
    fleet.nodes.insert(0, reopened);
    fleet.close().await;
    assert!(
        recovered,
        "reopened intent refused the higher-term elected target"
    );
    assert!(
        matches!(write, Ok(Ok(_))),
        "recovered A and C must commit: {write:?}"
    );
}

async fn wait_for_intent_truncation(store: &ConsensusSessionStore) -> bool {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if published_voter_state(store).is_some_and(|state| state.intent().is_none()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

#[path = "voter_slot_review_tests.rs"]
mod review_tests;
