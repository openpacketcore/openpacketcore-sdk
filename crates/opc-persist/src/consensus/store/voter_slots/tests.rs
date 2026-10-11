use super::*;
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
        descriptor_digest: [slot as u8; 32],
        admission_generation: incarnation,
    };
    member.key_digest = Sha256::digest(public(&member)).into();
    member
}
fn genesis() -> VoterSlotTable {
    VoterSlotTable {
        cluster_instance: opc_consensus::ConsensusClusterId::from_bytes([3; 32]),
        manifest_digest: [4; 32],
        revision: 1,
        configuration_epoch: opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
        slots: (1..=3)
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

#[derive(Debug, Default)]
struct Network {
    handlers: std::sync::RwLock<BTreeMap<ConsensusNodeId, Arc<dyn ConsensusRpcHandler>>>,
    freeze_after_marker: AtomicU64,
    paused_replication_to: AtomicU64,
    allow_paused_requests: std::sync::Mutex<BTreeSet<[u8; 32]>>,
    paused_nonempty_append_to: AtomicU64,
}
#[derive(Debug, Clone)]
struct Resolver(Arc<Network>);
impl VoterPeerResolver for Resolver {
    fn resolve(&self, member: &VoterSlotMember) -> Result<VoterPeerRoute, ConsensusPeerError> {
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
impl ConsensusPeer for Peer {
    fn node_id(&self) -> ConsensusNodeId {
        self.member.identity.node_id()
    }
    async fn call(
        &self,
        _: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        panic!("incarnation profile used raw transport");
    }
    async fn call_with_incarnation(
        &self,
        request: ConsensusWireRequest,
        binding: VoterRpcBinding,
        timeout: Duration,
    ) -> Result<VoterAuthenticatedResponse, ConsensusPeerError> {
        if self.network.paused_replication_to.load(Ordering::SeqCst) == self.node_id().get()
            && !self
                .network
                .allow_paused_requests
                .lock()
                .unwrap()
                .contains(&voter_rpc_request_digest(&request)?)
            && matches!(
                request.family,
                ConsensusRpcFamily::AppendEntries | ConsensusRpcFamily::InstallSnapshot
            )
        {
            return Err(ConsensusPeerError::Unavailable);
        }
        if self
            .network
            .paused_nonempty_append_to
            .load(Ordering::SeqCst)
            == self.node_id().get()
            && request.family == ConsensusRpcFamily::AppendEntries
            && decode_config_wire::<
                opc_consensus::engine::raft::AppendEntriesRequest<ConfigRaftTypeConfig>,
            >(&request.payload)
            .is_ok_and(|rpc| !rpc.entries.is_empty())
        {
            return Err(ConsensusPeerError::Unavailable);
        }
        let handler = self
            .network
            .handlers
            .read()
            .unwrap()
            .get(&self.node_id())
            .cloned()
            .ok_or(ConsensusPeerError::Unavailable)?;
        assert_eq!(binding.destination, self.member);
        let issuer = VoterChallengeIssuer::new();
        let channel = rand::random();
        let expires = tokio::time::Instant::now() + timeout.min(Duration::from_secs(60));
        let challenge = issuer
            .issue_rpc(binding.clone(), channel, expires)
            .map_err(|_| ConsensusPeerError::Rejected)?;
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
            .map_err(|_| ConsensusPeerError::Rejected)?;
        let response = handler
            .handle_with_incarnation(proof, request.clone())
            .await;
        if request.family == ConsensusRpcFamily::TopologyAdmissionBarrier
            && self.network.freeze_after_marker.load(Ordering::SeqCst) == self.node_id().get()
            && response.result.as_ref().is_ok_and(|payload| {
                matches!(
                    decode_config_wire::<Result<ControlReply, VoterReplacementError>>(payload),
                    Ok(Ok(ControlReply::AppliedMarker(_)))
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
            .map_err(|_| ConsensusPeerError::Rejected)?;
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
            .map_err(|_| ConsensusPeerError::Rejected)?;
        Ok(VoterAuthenticatedResponse { response, proof })
    }
}

struct Fleet {
    nodes: Vec<ConsensusConfigStore>,
    network: Arc<Network>,
    directories: Vec<tempfile::TempDir>,
}
impl Fleet {
    async fn open() -> Self {
        let network = Arc::new(Network::default());
        let mut nodes = Vec::new();
        let mut directories = Vec::new();
        for slot in 1..=3 {
            let directory = tempfile::tempdir().unwrap();
            let backend = SqliteBackend::open_with_audit_key(
                directory.path().join("config.sqlite"),
                false,
                0,
                crate::AuditKey::new([42; 32]).unwrap(),
            )
            .await
            .unwrap();
            let store = ConsensusConfigStore::open_with_voter_slots(
                genesis(),
                member(slot, 1).identity.node_id(),
                backend,
                directory.path().join("snapshots"),
                Arc::new(Resolver(network.clone())),
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
        let (a, b, c) = tokio::join!(
            nodes[0].initialize_cluster(),
            nodes[1].initialize_cluster(),
            nodes[2].initialize_cluster()
        );
        a.unwrap();
        b.unwrap();
        c.unwrap();
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
            node.shutdown().await.unwrap();
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
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .remove(&member(3, 1).identity.node_id());
    fleet.nodes[2].shutdown().await.unwrap();
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
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .remove(&member(2, 1).identity.node_id());
    let survivor = fleet.nodes.remove(1);
    survivor.shutdown().await.unwrap();
    drop(survivor);
    let directory = fleet.directories[1].path();
    let backend = SqliteBackend::open_with_audit_key(
        directory.join("config.sqlite"),
        false,
        0,
        crate::AuditKey::new([42; 32]).unwrap(),
    )
    .await
    .unwrap();
    let survivor = ConsensusConfigStore::open_with_voter_slots(
        genesis(),
        member(2, 1).identity.node_id(),
        backend,
        directory.join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
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
    let request = ConsensusWireRequest::try_new(
        leader.inner.identity,
        member(3, 1).identity.node_id(),
        ConsensusRpcFamily::Vote,
        encode_config_wire(&VoteRequest {
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
    assert_eq!(response.result, Err(ConsensusPeerError::ScopeMismatch));
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
    let backend = SqliteBackend::open_with_audit_key(
        directory.path().join("config.sqlite"),
        false,
        0,
        crate::AuditKey::new([42; 32]).unwrap(),
    )
    .await
    .unwrap();
    let candidate = ConsensusConfigStore::open_with_voter_slots(
        prepared.table().clone(),
        member(3, 2).identity.node_id(),
        backend,
        directory.path().join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
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
    let mut progress = leader.inner.durable_progress.subscribe_applied();
    let finished = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let state = leader.voter_slot_state().await.unwrap();
            if state.table().replacement.is_none() {
                break state;
            }
            progress.changed().await.unwrap();
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
    // Finalize publication can precede release of the old engine fence, which
    // invalidates in-flight read probes. Require fresh quorum evidence within
    // the original budget while the candidate remains disconnected.
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
    let mut applied = candidate.inner.durable_progress.subscribe_applied();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = candidate.voter_slot_state().await.unwrap();
            if state.table().replacement.is_none()
                && state.table().configuration_epoch.get() == 2
                && candidate
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
    // The retained selected identity restores Voting and retirement before
    // its RPC handler can admit traffic after a full store reopen.
    fleet
        .network
        .handlers
        .write()
        .unwrap()
        .remove(&member(3, 2).identity.node_id());
    candidate.shutdown().await.unwrap();
    fleet.nodes.pop();
    drop(candidate);
    let directory = fleet.directories.last().unwrap().path();
    let backend = SqliteBackend::open_with_audit_key(
        directory.join("config.sqlite"),
        false,
        0,
        crate::AuditKey::new([42; 32]).unwrap(),
    )
    .await
    .unwrap();
    let reopened = ConsensusConfigStore::open_with_voter_slots(
        prepared.table().clone(),
        member(3, 2).identity.node_id(),
        backend,
        directory.join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
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
async fn authenticated_profile_forms_a_real_quorum_and_raw_vote_has_no_effect() {
    let fleet = Fleet::open().await;
    let store = &fleet.nodes[1];
    let before = store
        .inner
        .raft
        .with_raft_state(|state| *state.vote_ref())
        .await
        .unwrap();
    let mut vote = before;
    vote.leader_id.term += 100;
    let request = ConsensusWireRequest::try_new(
        store.inner.identity,
        member(1, 1).identity.node_id(),
        ConsensusRpcFamily::Vote,
        encode_config_wire(&VoteRequest {
            vote,
            last_log_id: None,
        })
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store
            .rpc_handler()
            .handle(member(1, 1).identity.node_id(), request)
            .await
            .result,
        Err(ConsensusPeerError::ScopeMismatch)
    );
    assert_eq!(
        before,
        store
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap()
    );
    let leader = &fleet.nodes[0];
    assert!(leader
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
    assert_eq!(
        leader
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .check_target_absent(member(3, 1).identity.node_id()),
        Err(VoterReplacementError::TargetStillLive)
    );
    assert_eq!(leader.voter_slot_state().await.unwrap().table(), &genesis());
    fleet.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incompatible_audit_profile_refuses_a_proven_incarnation_before_vote_effect() {
    let network = Arc::new(Network::default());
    let mut nodes = Vec::new();
    let mut directories = Vec::new();
    for slot in 1..=2 {
        let directory = tempfile::tempdir().unwrap();
        let backend = SqliteBackend::open_with_audit_key(
            directory.path().join("config.sqlite"),
            false,
            0,
            crate::AuditKey::new([slot as u8; 32]).unwrap(),
        )
        .await
        .unwrap();
        let node = ConsensusConfigStore::open_with_voter_slots(
            genesis(),
            member(slot, 1).identity.node_id(),
            backend,
            directory.path().join("snapshots"),
            Arc::new(Resolver(network.clone())),
        )
        .await
        .unwrap();
        network
            .handlers
            .write()
            .unwrap()
            .insert(member(slot, 1).identity.node_id(), node.rpc_handler());
        nodes.push(node);
        directories.push(directory);
    }
    let before = nodes[1]
        .inner
        .raft
        .with_raft_state(|state| *state.vote_ref())
        .await
        .unwrap();
    let vote = Vote::new(100, member(1, 1).identity.node_id());
    let request = ConsensusWireRequest::try_new(
        nodes[0].inner.identity,
        member(1, 1).identity.node_id(),
        ConsensusRpcFamily::Vote,
        encode_config_wire(&VoteRequest {
            vote,
            last_log_id: None,
        })
        .unwrap(),
    )
    .unwrap();
    let reply = nodes[0]
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .transport
        .peer(member(2, 1).identity.node_id())
        .call(request)
        .await
        .unwrap();
    assert_eq!(reply.result, Err(ConsensusPeerError::ScopeMismatch));
    assert_eq!(
        before,
        nodes[1]
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap()
    );
    assert_eq!(
        nodes[1]
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .check_target_absent(member(1, 1).identity.node_id()),
        Err(VoterReplacementError::TargetStillLive)
    );
    network.handlers.write().unwrap().clear();
    for node in nodes {
        node.shutdown().await.unwrap();
    }
    drop(directories);
}

#[path = "review_tests.rs"]
mod review_tests;

#[path = "retry_tests.rs"]
mod retry_tests;
