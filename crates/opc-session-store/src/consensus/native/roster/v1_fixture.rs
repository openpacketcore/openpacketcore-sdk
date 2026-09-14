//! Fully signed V1 commands for the native/SQL parity test. Every signature
//! is derived after selecting the mutation, phase and real admission epoch.

use crate::consensus::types::{
    roster_registration_handle, ConsensusRosterAdmissionCommand, ConsensusRosterTerminalCommand,
    ConsensusRosterTerminalCommandInput, RosterV2PersistenceFixture,
};
use crate::fenced_mutation_roster::{
    provider_receipt_compact_digest, roster_executor_evidence_commitment,
    stable_terminal_proof_commitment, Member, Phase, RequestId, RosterAttestationCertificateRoleV1,
    RosterAttestationLeafCertificatePartsV1, RosterAttestationLeafCertificateV1,
    RosterCompactTerminalEvidenceBindingV2, RosterCompactTerminalEvidenceV2,
    RosterCompactTerminalMemberProjectionV2, RosterCompactTerminalMemberProofPartsV2,
    RosterCompactTerminalMemberSigningInputV2, RosterExecutorMemberProofPartsV1,
    RosterExecutorProofBundleV1, RosterIngressAttestationSigningInputV1,
    RosterIngressAttestationV1, RosterProviderOperationV1, RosterProviderOutcomeV1,
    RosterProviderReceiptSigningInputV1, RosterTerminalAttestationSigningInputV1, TerminalRecord,
};
use crate::fenced_mutation_roster_executor::BackendRegistration;
use crate::fenced_mutation_roster_transport::roster_terminal_ingress_capsule_commitment;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

fn sign(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
    let signature: Signature = key.sign_prehash(&digest).unwrap();
    signature.normalize_s().to_bytes().into()
}

pub(crate) fn terminal(
    signed: &RosterV2PersistenceFixture,
    command: &ConsensusRosterAdmissionCommand,
    epoch: u64,
    phase: Phase,
) -> ConsensusRosterTerminalCommand {
    let admission = command.admission();
    let authority = command.authority();
    let provenance = command.admission_provenance().unwrap();
    let binding = admission.binding_key(epoch).unwrap();
    let registration = BackendRegistration::from_consensus_parts(
        roster_registration_handle(binding),
        RequestId::bind(epoch, admission).unwrap(),
        admission,
    )
    .unwrap();
    let (registration_handle, registration_request_id, registration_terminal_slot) =
        registration.consensus_parts();
    let root_key = SigningKey::from_bytes((&[0x96; 32]).into()).unwrap();
    let ingress_key = SigningKey::from_bytes((&[0x97; 32]).into()).unwrap();
    let executor_key = SigningKey::from_bytes((&[0x98; 32]).into()).unwrap();
    let provider_key = SigningKey::from_bytes((&[0xC0; 32]).into()).unwrap();
    let executor_subject = [0xC1; 32];
    let provider_subject = [0xC2; 32];
    let issue_certificate = |role, subject, key_id, key: &SigningKey| {
        let mut parts = RosterAttestationLeafCertificatePartsV1 {
            root_id: signed.root.root_id(),
            role,
            configuration_identity: signed.identity,
            scope: authority.ingress_scope().digest(),
            subject_identity_commitment: subject,
            leaf_epoch: 1,
            key_id,
            not_before: authority.acquired_at(),
            not_after: authority.expires_at(),
            public_key: key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            root_signature: [0; 64],
        };
        parts.root_signature = sign(
            &root_key,
            RosterAttestationLeafCertificateV1::signing_digest(&parts).unwrap(),
        );
        parts
    };
    let executor_certificate = issue_certificate(
        RosterAttestationCertificateRoleV1::Executor,
        executor_subject,
        [0xC3; 32],
        &executor_key,
    );
    let provider_certificate = issue_certificate(
        RosterAttestationCertificateRoleV1::Provider,
        provider_subject,
        [0xC4; 32],
        &provider_key,
    );
    let provider = RosterAttestationLeafCertificateV1::issue_from_signed_parts(
        &signed.root,
        provider_certificate.clone(),
    )
    .unwrap();
    let evidence = vec![0xC5, 0xC6];
    let (provider_operation, outcome) = match phase {
        Phase::Established => (
            RosterProviderOperationV1::Execute,
            RosterProviderOutcomeV1::AppliedExecuted,
        ),
        Phase::Aborted => (
            RosterProviderOperationV1::Reconcile,
            RosterProviderOutcomeV1::NotAppliedReconciled,
        ),
    };
    let terminal = TerminalRecord::new(
        admission,
        registration_request_id,
        phase,
        admission
            .members()
            .iter()
            .map(|member| {
                stable_terminal_proof_commitment(
                    binding,
                    registration,
                    admission,
                    phase,
                    member,
                    outcome,
                    roster_executor_evidence_commitment(&evidence),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let compact_binding = RosterCompactTerminalEvidenceBindingV2::for_terminal(
        signed.identity,
        binding,
        registration,
        &provenance,
        admission,
        authority,
        &terminal,
        executor_subject,
    )
    .unwrap();
    let input_for = |member: &Member| RosterTerminalAttestationSigningInputV1 {
        profile: admission.profile(),
        configuration_identity: signed.identity,
        certificate_subject_identity_commitment: executor_subject,
        certificate_role: RosterAttestationCertificateRoleV1::Executor,
        binding: binding.to_bytes(),
        registration_handle,
        registration_request_id: registration_request_id.to_bytes(),
        registration_terminal_slot: *registration_terminal_slot.as_bytes(),
        roster_id: *admission.roster_id().as_bytes(),
        admission_commitment: admission.body_commitment(),
        terminal_phase: phase,
        terminal_body_commitment: terminal.body_commitment(),
        ordinal: member.ordinal(),
        member_operation_id: *member.operation_id().as_bytes(),
        descriptor: member.descriptor().to_vec(),
        descriptor_commitment: member.descriptor_commitment(),
        expected_member_version: member.expected_version(),
        admission_generation: admission.expected_generation().get(),
        authority_scope: authority.scope().digest(),
        authority_ingress_scope: authority.ingress_scope().digest(),
        authority_key_canonical: authority.key().canonical_digest_input(),
        authority_owner: authority.owner().as_str().as_bytes().to_vec(),
        authority_fence: authority.fence().get(),
        authority_credential_id: authority.credential_id(),
        authority_generation: authority.generation().get(),
        authority_acquired_at: authority.acquired_at(),
        authority_expires_at: authority.expires_at(),
        proof_epoch: 1,
        provider_operation,
        outcome,
        evidence: evidence.clone(),
    };
    let mut raw = Vec::new();
    let mut compact = Vec::new();
    for (member, commitment) in admission.members().iter().zip(terminal.proof_commitments()) {
        let input = input_for(member);
        let projection =
            RosterCompactTerminalMemberProjectionV2::from_terminal_v1_input(&input, *commitment)
                .unwrap();
        let provider_digest =
            RosterProviderReceiptSigningInputV1::from_terminal_input(&input, provider_subject)
                .unwrap()
                .digest()
                .unwrap();
        assert_eq!(
            provider_digest,
            provider_receipt_compact_digest(&compact_binding, &projection, &provider).unwrap()
        );
        let provider_signature = sign(&provider_key, provider_digest);
        raw.push(RosterExecutorMemberProofPartsV1 {
            ordinal: member.ordinal(),
            provider_operation,
            outcome,
            proof_epoch: 1,
            evidence: evidence.clone(),
            provider_certificate: provider_certificate.clone(),
            provider_signature,
            signature: sign(&executor_key, input.digest().unwrap()),
        });
        compact.push(RosterCompactTerminalMemberProofPartsV2 {
            provider_certificate: provider_certificate.clone(),
            provider_signature,
            signature: sign(
                &executor_key,
                RosterCompactTerminalMemberSigningInputV2 {
                    binding: compact_binding.clone(),
                    member: projection.clone(),
                }
                .digest()
                .unwrap(),
            ),
            member: projection,
        });
    }
    let proof_bundle = RosterExecutorProofBundleV1::issue_from_signed_parts(
        &signed.root,
        executor_certificate.clone(),
        raw,
    )
    .unwrap();
    let terminal_evidence = RosterCompactTerminalEvidenceV2::issue_from_signed_parts(
        &signed.root,
        executor_certificate,
        &compact_binding,
        compact,
    )
    .unwrap();
    let ingress_input = RosterIngressAttestationSigningInputV1 {
        peer_identity_commitment: command
            .ingress_attestation()
            .unwrap()
            .signing_input()
            .peer_identity_commitment,
        consumer_scope: authority.ingress_scope().digest(),
        request_id: [0xC7; 16],
        operation_tag: 4,
        canonical_capsule_digest: roster_terminal_ingress_capsule_commitment(
            binding,
            registration,
            authority,
            &terminal,
            admission,
            &proof_bundle,
            &terminal_evidence,
        )
        .unwrap(),
        authenticated_at: authority.acquired_at().add_seconds(1).unwrap(),
        peer_certificate_expires_at: authority.expires_at(),
        material_generation: 1,
        handshake_epoch: 1,
    };
    let ingress_certificate = issue_certificate(
        RosterAttestationCertificateRoleV1::TransportIngress,
        ingress_input.peer_identity_commitment,
        [0xB7; 32],
        &ingress_key,
    );
    let ingress = RosterIngressAttestationV1::issue_from_signed_parts(
        &signed.root,
        ingress_certificate,
        &ingress_input,
        sign(&ingress_key, ingress_input.digest().unwrap()),
    )
    .unwrap();
    ConsensusRosterTerminalCommand::new_with_proof_bundle_evidence_and_ingress_request_id(
        ConsensusRosterTerminalCommandInput {
            binding,
            registration_handle,
            registration_request_id,
            registration_terminal_slot: *registration_terminal_slot.as_bytes(),
            authority: authority.clone(),
            record: terminal.to_canonical_bytes(admission).unwrap(),
        },
        proof_bundle,
        terminal_evidence,
        ingress_input.request_id,
        ingress,
    )
    .unwrap()
}
