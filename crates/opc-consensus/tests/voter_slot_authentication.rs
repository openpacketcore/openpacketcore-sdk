use std::collections::BTreeSet;
use std::time::Duration;

use opc_consensus::voter_slots::*;
use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId, ConsensusIdentity,
    ConsensusRequestId,
};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha256};
use tokio::time::Instant;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}
fn public(seed: u8) -> [u8; 33] {
    key(seed)
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn sign(seed: u8, message: &[u8]) -> [u8; 64] {
    let signature: Signature = key(seed).sign_prehash(&Sha256::digest(message)).unwrap();
    signature.normalize_s().to_bytes().into()
}
fn cluster() -> ConsensusClusterId {
    ConsensusClusterId::from_bytes([3; 32])
}
fn configuration() -> ConsensusIdentity {
    ConsensusIdentity::new(
        cluster(),
        ConsensusConfigurationId::from_bytes([4; 32]),
        ConsensusConfigurationEpoch::new(1).unwrap(),
    )
}
fn member(slot: u16, incarnation: u64, seed: u8) -> VoterSlotMember {
    VoterSlotMember {
        identity: VoterSlotIdentity::new(
            SlotId::new(slot).unwrap(),
            VoterIncarnation::new(incarnation).unwrap(),
        ),
        key_digest: Sha256::digest(public(seed)).into(),
        descriptor_digest: [slot as u8; 32],
        admission_generation: incarnation,
    }
}
fn binding() -> VoterRpcBinding {
    VoterRpcBinding {
        cluster_instance: cluster(),
        configuration: configuration(),
        profile_digest: [10; 32],
        source: member(3, 1, 3),
        destination: member(1, 1, 1),
        source_spiffe_id: "spiffe://example.test/voter/3".into(),
        destination_spiffe_id: "spiffe://example.test/voter/1".into(),
        replacement_digest: None,
        payload_digest: [8; 32],
        kind: VoterRpcProofKind::Request,
    }
}

#[test]
fn rpc_payload_commitments_cover_family_scope_and_both_response_outcomes() {
    use opc_consensus::{
        ConsensusPeerError, ConsensusRpcFamily, ConsensusWireRequest, ConsensusWireResponse,
    };
    let request = ConsensusWireRequest::try_new(
        configuration(),
        member(3, 1, 3).identity.node_id(),
        ConsensusRpcFamily::Vote,
        vec![1, 2, 3],
    )
    .unwrap();
    let digest = voter_rpc_request_digest(&request).unwrap();
    let mut other = request.clone();
    other.family = ConsensusRpcFamily::AppendEntries;
    assert_ne!(digest, voter_rpc_request_digest(&other).unwrap());
    other = request.clone();
    other.sender = member(3, 2, 4).identity.node_id();
    assert_ne!(digest, voter_rpc_request_digest(&other).unwrap());
    let success = ConsensusWireResponse {
        result: Ok(vec![9]),
    };
    let refusal = ConsensusWireResponse {
        result: Err(ConsensusPeerError::Rejected),
    };
    assert_ne!(
        voter_rpc_response_digest(&request, &success).unwrap(),
        voter_rpc_response_digest(&request, &refusal).unwrap()
    );
    assert_ne!(
        voter_rpc_response_digest(&request, &success).unwrap(),
        voter_rpc_response_digest(&other, &success).unwrap()
    );
}

#[tokio::test]
async fn legacy_transport_never_supplies_incarnation_admission() {
    use async_trait::async_trait;
    use opc_consensus::{
        ConsensusNodeId, ConsensusPeer, ConsensusPeerError, ConsensusRpcFamily,
        ConsensusWireRequest, ConsensusWireResponse,
    };
    #[derive(Debug)]
    struct Legacy;
    #[async_trait]
    impl ConsensusPeer for Legacy {
        fn node_id(&self) -> ConsensusNodeId {
            member(3, 1, 3).identity.node_id()
        }
        async fn call(
            &self,
            _: ConsensusWireRequest,
        ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
            panic!("legacy application bytes must not be sent for incarnation admission")
        }
    }
    let request = ConsensusWireRequest::try_new(
        configuration(),
        member(1, 1, 1).identity.node_id(),
        ConsensusRpcFamily::Vote,
        vec![],
    )
    .unwrap();
    let scope = VoterRpcBinding {
        source: member(1, 1, 1),
        destination: member(3, 1, 3),
        ..binding()
    };
    assert!(matches!(
        Legacy
            .call_with_incarnation(request, scope, Duration::from_secs(1))
            .await,
        Err(ConsensusPeerError::ScopeMismatch)
    ));
}

#[tokio::test(start_paused = true)]
async fn rpc_proof_binds_endpoints_channel_payload_and_is_one_use() {
    let issuer = VoterChallengeIssuer::new();
    let challenge = issuer
        .issue_rpc(binding(), [7; 32], Instant::now() + Duration::from_secs(5))
        .unwrap();
    let signature = sign(3, &voter_rpc_possession_signing_input(&challenge).unwrap());
    let proof = issuer
        .verify_rpc(
            &challenge,
            "spiffe://example.test/voter/3",
            [7; 32],
            public(3),
            signature,
        )
        .unwrap();
    assert!(issuer
        .verify_rpc(
            &challenge,
            "spiffe://example.test/voter/3",
            [7; 32],
            public(3),
            signature
        )
        .is_err());
    let evidence = proof.consume().unwrap();
    assert_eq!(evidence.binding(), &binding());
    assert!(proof.consume().is_err());

    for field in 0..8 {
        let mut challenge = issuer
            .issue_rpc(binding(), [7; 32], Instant::now() + Duration::from_secs(5))
            .unwrap();
        let signature = sign(3, &voter_rpc_possession_signing_input(&challenge).unwrap());
        match field {
            0 => challenge.binding.source.identity = member(3, 2, 4).identity,
            1 => challenge.binding.destination.identity = member(2, 1, 2).identity,
            2 => challenge.binding.replacement_digest = Some([1; 32]),
            3 => {
                challenge.binding.configuration = ConsensusIdentity::new(
                    cluster(),
                    ConsensusConfigurationId::from_bytes([9; 32]),
                    ConsensusConfigurationEpoch::new(2).unwrap(),
                )
            }
            4 => challenge.binding.payload_digest[0] ^= 1,
            5 => challenge.channel_binding[0] ^= 1,
            6 => challenge.binding.profile_digest[0] ^= 1,
            _ => challenge.binding.kind = VoterRpcProofKind::Response,
        }
        assert!(issuer
            .verify_rpc(
                &challenge,
                "spiffe://example.test/voter/3",
                [7; 32],
                public(3),
                signature
            )
            .is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn reused_workload_identity_does_not_prove_the_successor_key() {
    let issuer = VoterChallengeIssuer::new();
    let mut expected = binding();
    expected.source = member(3, 2, 4);
    let challenge = issuer
        .issue_rpc(
            expected.clone(),
            [7; 32],
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let old_signature = sign(3, &voter_rpc_possession_signing_input(&challenge).unwrap());
    assert!(issuer
        .verify_rpc(
            &challenge,
            "spiffe://example.test/voter/3",
            [7; 32],
            public(3),
            old_signature
        )
        .is_err());
    let challenge = issuer
        .issue_rpc(expected, [7; 32], Instant::now() + Duration::from_secs(5))
        .unwrap();
    let signature = sign(4, &voter_rpc_possession_signing_input(&challenge).unwrap());
    assert!(issuer
        .verify_rpc(
            &challenge,
            "spiffe://example.test/other",
            [7; 32],
            public(4),
            signature
        )
        .is_err());
    let challenge = issuer
        .issue_rpc(binding(), [7; 32], Instant::now() + Duration::from_secs(5))
        .unwrap();
    let signature = sign(3, &voter_rpc_possession_signing_input(&challenge).unwrap());
    assert!(issuer
        .verify_rpc(
            &challenge,
            "spiffe://example.test/voter/3",
            [9; 32],
            public(3),
            signature
        )
        .is_err());
}

#[tokio::test(start_paused = true)]
async fn expired_challenge_or_verified_proof_cannot_be_reused() {
    let issuer = VoterChallengeIssuer::new();
    let expires = Instant::now() + Duration::from_secs(5);
    let challenge = issuer.issue_rpc(binding(), [7; 32], expires).unwrap();
    let signature = sign(3, &voter_rpc_possession_signing_input(&challenge).unwrap());
    let verified = issuer
        .verify_rpc(
            &challenge,
            "spiffe://example.test/voter/3",
            [7; 32],
            public(3),
            signature,
        )
        .unwrap();
    let pending = issuer.issue_rpc(binding(), [7; 32], expires).unwrap();
    let pending_signature = sign(3, &voter_rpc_possession_signing_input(&pending).unwrap());
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(verified.consume().is_err());
    assert!(issuer
        .verify_rpc(
            &pending,
            "spiffe://example.test/voter/3",
            [7; 32],
            public(3),
            pending_signature
        )
        .is_err());
}

#[tokio::test(start_paused = true)]
async fn recent_key_proof_counts_before_a_later_rpc_refusal_and_restart_needs_full_window() {
    let target = member(3, 1, 3).identity.node_id();
    let traffic = VoterTrafficWindow::new(BTreeSet::from([target]));
    assert_eq!(
        traffic.check_absent(target),
        Err(VoterReplacementError::ObservationIncomplete)
    );
    tokio::time::advance(VOTER_RECENT_TRAFFIC_WINDOW).await;
    assert_eq!(traffic.check_absent(target), Ok(()));
    let issuer = VoterChallengeIssuer::new();
    let mut wrong_scope = binding();
    wrong_scope.configuration = ConsensusIdentity::new(
        cluster(),
        ConsensusConfigurationId::from_bytes([99; 32]),
        ConsensusConfigurationEpoch::new(99).unwrap(),
    );
    let challenge = issuer
        .issue_rpc(
            wrong_scope,
            [7; 32],
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let signature = sign(3, &voter_rpc_possession_signing_input(&challenge).unwrap());
    let proof = issuer
        .verify_rpc(
            &challenge,
            "spiffe://example.test/voter/3",
            [7; 32],
            public(3),
            signature,
        )
        .unwrap()
        .consume()
        .unwrap();
    traffic.observe(&proof);
    assert_ne!(
        proof.binding().configuration,
        configuration(),
        "the later scope check refuses this RPC"
    );
    assert_eq!(
        traffic.check_absent(target),
        Err(VoterReplacementError::TargetStillLive)
    );
    tokio::time::advance(VOTER_RECENT_TRAFFIC_WINDOW).await;
    traffic.observe(&proof);
    assert_eq!(
        traffic.check_absent(target),
        Ok(()),
        "re-observing one proof cannot extend its observation timestamp"
    );
    assert_eq!(
        VoterTrafficWindow::new(BTreeSet::from([target])).check_absent(target),
        Err(VoterReplacementError::ObservationIncomplete)
    );
}

fn replacement() -> (VoterReplacementRequest, VoterReplacementAuthorization) {
    let candidate = member(3, 2, 4);
    let authority = VoterReplacementAuthorization::new(
        cluster(),
        BTreeSet::from([SlotId::new(3).unwrap()]),
        "spiffe://example.test/controller".into(),
        public(9),
        [8; 32],
        Duration::from_millis(100),
    )
    .unwrap();
    let mut claims = LostVoterAttestationV1 {
        request_id: ConsensusRequestId::from_bytes([5; 16]),
        request_digest: [0; 32],
        cluster_instance: cluster(),
        slot: SlotId::new(3).unwrap(),
        expected_incarnation: VoterIncarnation::new(1).unwrap(),
        old_descriptor_digest: [3; 32],
        candidate_key_digest: candidate.key_digest,
        admission_generation: 2,
        candidate_spiffe_id: "spiffe://example.test/voter/3".into(),
        controller_spiffe_id: "spiffe://example.test/controller".into(),
        signing_key_digest: authority.credential_digest(),
        reason: VoterLossReason::TimeBoundLoss,
        policy_digest: [8; 32],
        observation_start_ms: 100,
        decision_ms: 200,
        issued_ms: 200,
        expires_ms: 300,
        signature: [0; 64],
    };
    claims.request_digest =
        voter_replacement_request_digest(1, configuration(), &candidate, &claims).unwrap();
    claims.signature = sign(9, &lost_voter_attestation_signing_input(&claims).unwrap());
    (
        VoterReplacementRequest {
            expected_revision: 1,
            expected_configuration: configuration(),
            candidate,
            attestation: claims,
        },
        authority,
    )
}

fn candidate_proof(
    issuer: &VoterChallengeIssuer,
    request: &VoterReplacementRequest,
) -> VerifiedVoterCandidate {
    let binding = VoterCandidateBinding {
        cluster_instance: cluster(),
        identity: request.candidate.identity,
        request_digest: request.attestation.request_digest,
        key_digest: request.candidate.key_digest,
        spiffe_id: request.attestation.candidate_spiffe_id.clone(),
    };
    let challenge = issuer
        .issue_candidate(binding, [6; 32], Instant::now() + Duration::from_secs(5))
        .unwrap();
    let signature = sign(
        4,
        &voter_candidate_possession_signing_input(&challenge).unwrap(),
    );
    issuer
        .verify_candidate(
            &challenge,
            &request.attestation.candidate_spiffe_id,
            [6; 32],
            public(4),
            signature,
        )
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn controller_signature_permission_time_and_candidate_possession_are_all_required() {
    let (request, authority) = replacement();
    let issuer = VoterChallengeIssuer::new();
    let verifier = VoterReplacementVerifier::new();
    let authorized = verifier
        .verify(
            &request,
            &authority,
            "spiffe://example.test/controller",
            TrustedVoterTime::new(210, 220).unwrap(),
            candidate_proof(&issuer, &request),
        )
        .unwrap();
    assert_eq!(authorized.request(), &request);
    for (earliest, latest) in [(199, 220), (220, 300), (209, 219)] {
        assert!(verifier
            .verify(
                &request,
                &authority,
                "spiffe://example.test/controller",
                TrustedVoterTime::new(earliest, latest).unwrap(),
                candidate_proof(&issuer, &request)
            )
            .is_err());
    }
    let denied_slot = VoterReplacementAuthorization::new(
        cluster(),
        BTreeSet::from([SlotId::new(2).unwrap()]),
        "spiffe://example.test/controller".into(),
        public(9),
        [8; 32],
        Duration::from_millis(100),
    )
    .unwrap();
    assert!(verifier
        .verify(
            &request,
            &denied_slot,
            "spiffe://example.test/controller",
            TrustedVoterTime::new(220, 230).unwrap(),
            candidate_proof(&issuer, &request)
        )
        .is_err());
    assert!(verifier
        .verify(
            &request,
            &authority,
            "spiffe://example.test/unauthorized",
            TrustedVoterTime::new(220, 230).unwrap(),
            candidate_proof(&issuer, &request)
        )
        .is_err());
    let mut bad_signature = request.clone();
    bad_signature.attestation.signature[0] ^= 1;
    assert!(verifier
        .verify(
            &bad_signature,
            &authority,
            "spiffe://example.test/controller",
            TrustedVoterTime::new(220, 230).unwrap(),
            candidate_proof(&issuer, &request)
        )
        .is_err());
    let mut other = request.clone();
    other.attestation.request_digest[0] ^= 1;
    assert!(verifier
        .verify(
            &request,
            &authority,
            "spiffe://example.test/controller",
            TrustedVoterTime::new(220, 230).unwrap(),
            candidate_proof(&issuer, &other)
        )
        .is_err());
}

#[tokio::test(start_paused = true)]
async fn possession_rejects_high_s_and_cross_protocol_signatures() {
    let issuer = VoterChallengeIssuer::new();
    let challenge = issuer
        .issue_rpc(binding(), [7; 32], Instant::now() + Duration::from_secs(5))
        .unwrap();
    let signature = Signature::from_slice(&sign(
        3,
        &voter_rpc_possession_signing_input(&challenge).unwrap(),
    ))
    .unwrap();
    let (r, s) = signature.split_scalars();
    let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    assert_ne!(high.normalize_s(), high);
    assert!(issuer
        .verify_rpc(
            &challenge,
            "spiffe://example.test/voter/3",
            [7; 32],
            public(3),
            high.to_bytes().into()
        )
        .is_err());
    let challenge = issuer
        .issue_rpc(binding(), [7; 32], Instant::now() + Duration::from_secs(5))
        .unwrap();
    let signature = sign(3, b"openpacketcore/consensus/candidate-possession/v1\0");
    assert!(issuer
        .verify_rpc(
            &challenge,
            "spiffe://example.test/voter/3",
            [7; 32],
            public(3),
            signature
        )
        .is_err());
}

#[tokio::test(start_paused = true)]
async fn new_request_authority_expires_and_new_observation_members_start_cold() {
    let (request, authority) = replacement();
    let issuer = VoterChallengeIssuer::new();
    let verified = VoterReplacementVerifier::new()
        .verify(
            &request,
            &authority,
            "spiffe://example.test/controller",
            TrustedVoterTime::new(210, 220).unwrap(),
            candidate_proof(&issuer, &request),
        )
        .unwrap();
    assert_eq!(verified.ensure_fresh(), Ok(()));
    tokio::time::advance(Duration::from_millis(80)).await;
    assert_eq!(
        verified.ensure_fresh(),
        Err(VoterReplacementError::Deadline)
    );
    let target = member(3, 1, 3).identity.node_id();
    let replacement = member(3, 2, 4).identity.node_id();
    let traffic = VoterTrafficWindow::new(BTreeSet::from([target]));
    tokio::time::advance(VOTER_RECENT_TRAFFIC_WINDOW).await;
    traffic.retain_members(BTreeSet::from([target, replacement]));
    assert_eq!(traffic.check_absent(target), Ok(()));
    assert_eq!(
        traffic.check_absent(replacement),
        Err(VoterReplacementError::ObservationIncomplete)
    );
}
