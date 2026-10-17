//! Authenticated incarnation routes for the existing three-voter repair cases.
//! They retain the shared transport's real election and replication gates.

use super::*;
use opc_consensus::voter_slots::*;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

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

pub(super) fn member(slot: u16, incarnation: u64) -> VoterSlotMember {
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

pub(super) fn genesis() -> VoterSlotTable {
    VoterSlotTable {
        cluster_instance: ConfigConsensusClusterId::new("opc-persist-three-node-tests").unwrap(),
        manifest_digest: [0x99; 32],
        revision: 1,
        configuration_epoch: ConfigConsensusConfigurationEpoch::new(1).unwrap(),
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

pub(super) fn options(
    path: &std::path::Path,
    initial: VoterSlotTable,
    local: ConfigConsensusNodeId,
    backing: u8,
) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        path,
        RetainedConfigBinding::for_voter_slots(initial, local, [backing; 32], [0x61; 32])
            .expect("incarnation binding"),
        RetainedConfigDurability::Ephemeral,
        64 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .expect("retained options")
}

#[derive(Debug)]
pub(super) struct Resolver {
    pub source: usize,
    pub paths: BTreeMap<(usize, usize), Arc<LoopbackPeer>>,
}

impl VoterPeerResolver for Resolver {
    fn resolve(&self, member: &VoterSlotMember) -> Result<VoterPeerRoute, ConsensusPeerError> {
        let target = usize::from(member.identity.slot().get() - 1);
        let mut peer = if self.source == target {
            // A candidate's predecessor configuration still names the lost
            // incarnation in its own slot. That distinct endpoint is absent;
            // never route it back to the new incarnation's handler.
            LoopbackPeer::new(member.identity.node_id())
        } else {
            self.paths
                .get(&(self.source, target))
                .ok_or(ConsensusPeerError::Unavailable)?
                .as_ref()
                .clone()
        };
        peer.target = member.identity.node_id();
        Ok(VoterPeerRoute {
            member: member.clone(),
            spiffe_id: format!(
                "spiffe://example.test/voter/{}",
                member.identity.slot().get()
            ),
            peer: Arc::new(peer),
        })
    }
}

pub(super) async fn call(
    peer: &LoopbackPeer,
    request: ConsensusWireRequest,
    binding: VoterRpcBinding,
    timeout: Duration,
) -> Result<VoterAuthenticatedResponse, ConsensusPeerError> {
    assert_eq!(binding.destination.identity.node_id(), peer.target);
    let issuer = VoterChallengeIssuer::new();
    let channel = rand::random();
    let challenge = issuer
        .issue_rpc(
            binding.clone(),
            channel,
            tokio::time::Instant::now() + timeout.min(Duration::from_secs(60)),
        )
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
    let response = peer
        .call_bound(request.clone(), None, Some(proof))
        .await?
        .response;
    let reply_binding = VoterRpcBinding {
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
            reply_binding.clone(),
            channel,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .map_err(|_| ConsensusPeerError::Rejected)?;
    let proof = issuer
        .verify_rpc(
            &challenge,
            &reply_binding.source_spiffe_id,
            channel,
            public(&reply_binding.source),
            sign(
                &reply_binding.source,
                &voter_rpc_possession_signing_input(&challenge).unwrap(),
            ),
        )
        .map_err(|_| ConsensusPeerError::Rejected)?;
    Ok(VoterAuthenticatedResponse { response, proof })
}

pub(super) fn verified_request(table: &VoterSlotTable, slot: u16) -> VerifiedVoterReplacement {
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
    let proof = issuer
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
            proof,
        )
        .unwrap()
}

pub(super) async fn prepare(cluster: &ThreeNodeCluster, lost: usize) -> VoterSlotTable {
    // Honor the configured authenticated-loss observation period while the
    // surviving engines elect their leader, if the stopped voter led the group.
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW).await;
    let leader = loop {
        if let Some((index, _)) = cluster.stores.iter().enumerate().find(|(index, store)| {
            *index != lost && store.status().leader_id == Some(store.status().node_id)
        }) {
            break index;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let initial = cluster.stores[leader].voter_slot_state().await.unwrap();
    let prepared = cluster.stores[leader]
        .replace_voter(verified_request(initial.table(), lost as u16 + 1))
        .await
        .expect("surviving quorum accepts the authenticated new identity");
    assert!(prepared
        .table()
        .is_retired(cluster.stores[lost].status().node_id));
    prepared.table().clone()
}

pub(super) async fn install(
    cluster: &mut ThreeNodeCluster,
    index: usize,
    replacement: ConsensusConfigStore,
) {
    for ((_, target), path) in &cluster.paths {
        if *target == index {
            path.install_incarnation(replacement.status().node_id, replacement.rpc_handler())
                .await;
        }
    }
    cluster.stores[index] = replacement;
    cluster.heal(index);
}
