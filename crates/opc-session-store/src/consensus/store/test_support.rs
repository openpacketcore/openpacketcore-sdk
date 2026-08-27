//! Feature-gated authenticated roster fixtures for live integration tests.

use std::time::Duration;

use bytes::Bytes;
use opc_consensus::engine::error::Fatal;
use opc_consensus::engine::StorageError;
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use serde::{Deserialize, Serialize};

use super::*;
use crate::backend::{CompareAndSet, CompareAndSetResult, SessionBackend};
use crate::consensus::SessionConsensusClusterId;
use crate::consumer::{
    session_consumer_identity_commitment, session_consumer_roster_ingress_operation,
    session_consumer_roster_scope_commitment, SessionConsumerAuthorizationGrant,
    SessionConsumerIdentity, SessionConsumerOperation, SessionConsumerRequest,
    SessionConsumerRequestId, SessionConsumerResponse, SessionConsumerRosterAdmissionCapsule,
    SessionConsumerRosterAdmissionMutationResponse,
    SessionConsumerRosterCurrentPublicationAuthorityCapsule,
    SessionConsumerRosterCurrentPublicationAuthorityReadResponse, SessionConsumerRosterRejection,
    SessionConsumerRosterTerminalCapsule, SessionConsumerRosterTerminalMutationResponse,
    SessionConsumerTenantNfScope, SessionQuorumRosterIngress,
};
use crate::fenced_mutation_roster::{
    roster_executor_evidence_commitment, stable_terminal_proof_commitment, Admission,
    AdmissionProposal, EstablishedMutation, Member, MemberOperationId, Phase, Profile,
    RequestId as RosterRequestId, RosterAttestationCertificateRoleV1,
    RosterAttestationLeafCertificatePartsV1, RosterAttestationLeafCertificateV1,
    RosterAttestationTrustRootV1, RosterCompactAdmissionProvenanceSigningInputV2,
    RosterCompactAdmissionProvenanceV2, RosterCompactTerminalEvidenceBindingV2,
    RosterCompactTerminalEvidenceV2, RosterCompactTerminalMemberProjectionV2,
    RosterCompactTerminalMemberProofPartsV2, RosterCompactTerminalMemberSigningInputV2,
    RosterExecutorMemberProofPartsV1, RosterExecutorProofBundleV1, RosterId,
    RosterIngressAttestationSigningInputV1, RosterIngressAttestationV1, RosterProviderOperationV1,
    RosterProviderOutcomeV1, RosterProviderReceiptSigningInputV1,
    RosterTerminalAttestationSigningInputV1, Scope, TerminalRecord, FRESH_ROSTER_MEMBERS,
};
use crate::fenced_mutation_roster_executor::{
    AuthorityBinding, AuthorityLeaseMetadata, BackendRegistration, CommittedTerminal,
};
use crate::lease::SessionLeaseManager;
use crate::model::{FenceToken, Generation, SessionKeyType, StateClass, StateType};
use crate::record::EncryptedSessionPayload;

const ADMISSION_REQUEST_MAGIC: [u8; 8] = *b"OPCRPA1\0";
const TERMINAL_REQUEST_MAGIC: [u8; 8] = *b"OPCRPT1\0";
const ADMISSION_RESPONSE_MAGIC: [u8; 8] = *b"OPCRPS1\0";
const TERMINAL_RESPONSE_MAGIC: [u8; 8] = *b"OPCRPU1\0";
const ADMISSION_REQUEST_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/admission-port/request/v1\0";
const TERMINAL_REQUEST_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/terminal-port/request/v1\0";
const ADMISSION_RESPONSE_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/admission-port/response/v1\0";
const TERMINAL_RESPONSE_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/terminal-port/response/v1\0";

/// Return the fixed test-only root whose signing half is confined to this
/// feature-gated module.
pub fn roster_attestation_trust_root_for_test() -> RosterAttestationTrustRootV1 {
    let root_key = SigningKey::from_bytes((&[0x41; 32]).into()).expect("test root key");
    RosterAttestationTrustRootV1::new(
        [0x42; 32],
        compressed_roster_test_key(root_key.verifying_key()),
    )
    .expect("test roster root")
}

/// Construct a root-bound topology request for integration coverage without
/// exposing the production-only root derivation constructor to SDK callers.
pub fn topology_transition_request_with_roster_attestation_trust_root_for_test(
    transition_id: crate::membership::SessionTopologyTransitionId,
    cluster_id: SessionConsensusClusterId,
    expected_epoch: SessionConsensusConfigurationEpoch,
    desired_epoch: SessionConsensusConfigurationEpoch,
    desired_members: Vec<crate::topology::QuorumReplicaDescriptor>,
    operation_timeout: Duration,
    roster_attestation_trust_root: RosterAttestationTrustRootV1,
) -> Result<
    crate::membership::SessionTopologyTransitionRequest,
    crate::membership::SessionTopologyTransitionError,
> {
    crate::membership::SessionTopologyTransitionRequest::try_new_with_roster_attestation_trust_root(
        transition_id,
        cluster_id,
        expected_epoch,
        desired_epoch,
        desired_members,
        operation_timeout,
        roster_attestation_trust_root,
    )
}

/// Request an engine-owned snapshot after a test has committed its exact
/// roster history. The snapshot is built and validated through the production
/// state-machine path; callers then reopen a member from the durable image.
pub async fn trigger_consensus_snapshot_for_test(
    store: &ConsensusSessionStore,
) -> Result<(), String> {
    store
        .inner
        .raft
        .trigger()
        .snapshot()
        .await
        .map_err(|_| "test consensus snapshot capture rejected".to_owned())
}

/// Fixed test-only classification of the local consensus engine state.
///
/// Failure sources and internal error text are deliberately discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusEngineStateForTest {
    /// The local Openraft engine remains running.
    Running,
    /// A durable storage I/O operation stopped the local engine.
    StorageIo,
    /// A defensive storage invariant stopped the local engine.
    StorageDefensive,
    /// The local engine task panicked.
    Panicked,
    /// The local engine stopped normally.
    Stopped,
}

/// Fixed-cardinality, redaction-safe local durable progress for integration
/// qualification. No node identity, payload, path, or raw error is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusLocalDurableProgressForTest {
    /// Fixed local engine-state category.
    pub engine_state: ConsensusEngineStateForTest,
    /// Highest log index stored locally.
    pub last_log_index: Option<u64>,
    /// Highest log index applied locally.
    pub applied_index: Option<u64>,
    /// Highest log index represented by the current local snapshot.
    pub snapshot_index: Option<u64>,
    /// Highest log index durably purged locally.
    pub purged_index: Option<u64>,
}

/// Return one passive local consensus observation without issuing a read
/// barrier or changing consensus state.
pub fn consensus_local_durable_progress_for_test(
    store: &ConsensusSessionStore,
) -> ConsensusLocalDurableProgressForTest {
    let metrics = store.inner.raft.metrics();
    let current = metrics.borrow();
    let engine_state = match &current.running_state {
        Ok(()) => ConsensusEngineStateForTest::Running,
        Err(Fatal::StorageError(StorageError::IO { .. })) => ConsensusEngineStateForTest::StorageIo,
        Err(Fatal::StorageError(StorageError::Defensive { .. })) => {
            ConsensusEngineStateForTest::StorageDefensive
        }
        Err(Fatal::Panicked) => ConsensusEngineStateForTest::Panicked,
        Err(Fatal::Stopped) => ConsensusEngineStateForTest::Stopped,
    };
    ConsensusLocalDurableProgressForTest {
        engine_state,
        last_log_index: current.last_log_index,
        applied_index: current.last_applied.as_ref().map(|log_id| log_id.index),
        snapshot_index: current.snapshot.as_ref().map(|log_id| log_id.index),
        purged_index: current.purged.as_ref().map(|log_id| log_id.index),
    }
}

/// Wait until the engine has purged beyond an isolated follower's previously
/// applied index. This is test-only evidence that healing must use the real
/// InstallSnapshot RPC rather than ordinary log replay.
pub async fn wait_for_consensus_log_purge_beyond_for_test(
    store: &ConsensusSessionStore,
    index: u64,
) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let purged_beyond_index = {
                let metrics = store.inner.raft.metrics();
                let metrics = metrics.borrow();
                metrics
                    .purged
                    .as_ref()
                    .is_some_and(|purged| purged.index > index)
            };
            if purged_beyond_index {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "test consensus log purge did not pass the isolated follower".to_owned())
}

/// Compact the fixture's bounded retained roster history and immediately run
/// the production restart/snapshot scanner over the resulting tombstones.
pub async fn compact_and_validate_protected_roster_for_test(
    store: &ConsensusSessionStore,
) -> Result<(), String> {
    let logical_time = store
        .inner
        .clock
        .now_utc()
        .add_seconds(2 * 24 * 60 * 60)
        .ok_or_else(|| "test compaction time overflow".to_owned())?;
    crate::sqlite::consensus::compact_and_validate_protected_roster_for_test(
        &store.inner.backend,
        store.inner.storage_identity,
        logical_time,
    )
    .await
    .map_err(|_| "mixed-identity compacted roster hydration rejected".to_owned())
}

#[derive(Serialize)]
struct RosterIngressAuthorityWire {
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    credential_id: u64,
    generation: Generation,
    acquired_at: Timestamp,
    expires_at: Timestamp,
}

impl From<&AuthorityBinding> for RosterIngressAuthorityWire {
    fn from(authority: &AuthorityBinding) -> Self {
        Self {
            key: authority.key().clone(),
            owner: authority.owner().clone(),
            fence: authority.fence(),
            credential_id: authority.credential_id(),
            generation: authority.generation(),
            acquired_at: authority.acquired_at(),
            expires_at: authority.expires_at(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct RosterIngressRegistrationWire {
    handle: [u8; 32],
    request_id: RosterRequestId,
    terminal_slot: [u8; 32],
}

impl From<BackendRegistration> for RosterIngressRegistrationWire {
    fn from(registration: BackendRegistration) -> Self {
        let (handle, request_id, terminal_slot) = registration.consensus_parts();
        Self {
            handle,
            request_id,
            terminal_slot: *terminal_slot.as_bytes(),
        }
    }
}

impl RosterIngressRegistrationWire {
    fn registration(&self, admission: &Admission) -> BackendRegistration {
        BackendRegistration::from_consensus_parts(self.handle, self.request_id, admission)
            .expect("registration response must match admission")
    }
}

#[derive(Serialize)]
enum RosterIngressAdmissionRequestWire {
    Register {
        scope: [u8; 32],
        admission: Vec<u8>,
        authority: RosterIngressAuthorityWire,
    },
}

#[allow(
    dead_code,
    reason = "the decoder must retain every production response discriminant"
)]
#[derive(Deserialize)]
enum RosterIngressAdmissionResponseWire {
    Fresh {
        scope: [u8; 32],
        registration: RosterIngressRegistrationWire,
        admission_provenance: Vec<u8>,
    },
    Replayed {
        scope: [u8; 32],
    },
    PollAdmitted {
        scope: [u8; 32],
        registration: RosterIngressRegistrationWire,
        admission: Vec<u8>,
        admission_provenance: Vec<u8>,
    },
    Terminal {
        scope: [u8; 32],
        registration: RosterIngressRegistrationWire,
        admission: Vec<u8>,
        committed: Vec<u8>,
        admission_provenance: Vec<u8>,
    },
    Compacted {
        scope: [u8; 32],
        history_epoch: u64,
        tombstone: Vec<u8>,
    },
    Reject {
        scope: [u8; 32],
        rejection: crate::consumer::SessionConsumerRosterRejection,
    },
}

#[derive(Serialize)]
struct RosterIngressTerminalRequestWire {
    scope: [u8; 32],
    binding: crate::fenced_mutation_roster::RequestBindingKey,
    registration: RosterIngressRegistrationWire,
    authority: RosterIngressAuthorityWire,
    record: Vec<u8>,
    proof_bundle: Vec<u8>,
    terminal_evidence: Vec<u8>,
}

#[allow(
    dead_code,
    reason = "the decoder must retain every production response discriminant"
)]
#[derive(Deserialize)]
enum RosterIngressTerminalResponseWire {
    Terminalized {
        scope: [u8; 32],
        committed: Vec<u8>,
    },
    Replayed {
        scope: [u8; 32],
        committed: Vec<u8>,
    },
    Admitted {
        scope: [u8; 32],
    },
    Compacted {
        scope: [u8; 32],
        history_epoch: u64,
        tombstone: Vec<u8>,
    },
    Reject {
        scope: [u8; 32],
        rejection: SessionConsumerRosterRejection,
    },
}

fn admission_capsule(
    scope: Scope,
    admission: &Admission,
    authority: &AuthorityBinding,
) -> SessionConsumerRosterAdmissionCapsule {
    let wire = RosterIngressAdmissionRequestWire::Register {
        scope: scope.digest(),
        admission: admission.to_canonical_bytes().expect("admission bytes"),
        authority: authority.into(),
    };
    SessionConsumerRosterAdmissionCapsule::new(
        crate::fenced_mutation_roster::encode_frame(
            ADMISSION_REQUEST_MAGIC,
            ADMISSION_REQUEST_DOMAIN,
            &wire,
            crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
        )
        .expect("admission frame"),
    )
    .expect("admission capsule")
}

struct TerminalCapsuleInput<'a> {
    scope: Scope,
    binding: crate::fenced_mutation_roster::RequestBindingKey,
    registration: BackendRegistration,
    authority: &'a AuthorityBinding,
    terminal: &'a TerminalRecord,
    admission: &'a Admission,
    proof_bundle: &'a RosterExecutorProofBundleV1,
    terminal_evidence: &'a RosterCompactTerminalEvidenceV2,
}

fn terminal_capsule(input: TerminalCapsuleInput<'_>) -> SessionConsumerRosterTerminalCapsule {
    let TerminalCapsuleInput {
        scope,
        binding,
        registration,
        authority,
        terminal,
        admission,
        proof_bundle,
        terminal_evidence,
    } = input;
    let wire = RosterIngressTerminalRequestWire {
        scope: scope.digest(),
        binding,
        registration: registration.into(),
        authority: authority.into(),
        record: terminal
            .to_canonical_bytes(admission)
            .expect("terminal bytes"),
        proof_bundle: proof_bundle.canonical_bytes().expect("proof bundle bytes"),
        terminal_evidence: terminal_evidence
            .canonical_bytes()
            .expect("terminal evidence bytes"),
    };
    SessionConsumerRosterTerminalCapsule::new(
        crate::fenced_mutation_roster::encode_frame(
            TERMINAL_REQUEST_MAGIC,
            TERMINAL_REQUEST_DOMAIN,
            &wire,
            crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
        )
        .expect("terminal frame"),
    )
    .expect("terminal capsule")
}

struct RosterIngressTestIssuer {
    root: RosterAttestationTrustRootV1,
    root_key: SigningKey,
    ingress_key: SigningKey,
    executor_key: SigningKey,
    identity: SessionConsensusIdentity,
    valid_from: Timestamp,
    valid_until: Timestamp,
}

impl RosterIngressTestIssuer {
    fn new(
        root: RosterAttestationTrustRootV1,
        identity: SessionConsensusIdentity,
        valid_from: Timestamp,
        valid_until: Timestamp,
    ) -> Self {
        Self {
            root,
            root_key: SigningKey::from_bytes((&[0x41; 32]).into()).expect("test root key"),
            ingress_key: SigningKey::from_bytes((&[0x43; 32]).into()).expect("ingress key"),
            executor_key: SigningKey::from_bytes((&[0x44; 32]).into()).expect("executor key"),
            identity,
            valid_from,
            valid_until,
        }
    }

    fn certificate(
        &self,
        role: RosterAttestationCertificateRoleV1,
        scope: [u8; 32],
        subject_identity_commitment: [u8; 32],
        key_id: [u8; 32],
        public_key: &p256::ecdsa::VerifyingKey,
    ) -> RosterAttestationLeafCertificatePartsV1 {
        let mut certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: self.root.root_id(),
            role,
            configuration_identity: self.identity,
            scope,
            subject_identity_commitment,
            leaf_epoch: 1,
            key_id,
            not_before: self.valid_from,
            not_after: self.valid_until,
            public_key: compressed_roster_test_key(public_key),
            root_signature: [0; 64],
        };
        certificate.root_signature = sign_roster_test_digest(
            &self.root_key,
            RosterAttestationLeafCertificateV1::signing_digest(&certificate)
                .expect("certificate digest"),
        );
        certificate
    }

    fn ingress(
        &self,
        peer_identity_commitment: [u8; 32],
        scope: [u8; 32],
        request_id: SessionConsumerRequestId,
        operation_tag: u8,
        capsule: [u8; 32],
    ) -> RosterIngressAttestationV1 {
        let input = RosterIngressAttestationSigningInputV1 {
            peer_identity_commitment,
            consumer_scope: scope,
            request_id: *request_id.as_bytes(),
            operation_tag,
            canonical_capsule_digest: capsule,
            authenticated_at: self.valid_from,
            peer_certificate_expires_at: self.valid_until,
            material_generation: 1,
            handshake_epoch: 1,
        };
        RosterIngressAttestationV1::issue_from_signed_parts(
            &self.root,
            self.certificate(
                RosterAttestationCertificateRoleV1::TransportIngress,
                scope,
                peer_identity_commitment,
                [0x45; 32],
                self.ingress_key.verifying_key(),
            ),
            &input,
            sign_roster_test_digest(&self.ingress_key, input.digest().expect("ingress digest")),
        )
        .expect("ingress attestation")
    }

    fn compact_admission(
        &self,
        scope: [u8; 32],
        subject_identity_commitment: [u8; 32],
        input: &RosterCompactAdmissionProvenanceSigningInputV2,
    ) -> RosterCompactAdmissionProvenanceV2 {
        RosterCompactAdmissionProvenanceV2::issue_from_signed_parts(
            &self.root,
            self.certificate(
                RosterAttestationCertificateRoleV1::TransportIngress,
                scope,
                subject_identity_commitment,
                [0x49; 32],
                self.ingress_key.verifying_key(),
            ),
            input,
            sign_roster_test_digest(
                &self.ingress_key,
                input.digest().expect("compact admission digest"),
            ),
        )
        .expect("compact admission provenance")
    }

    fn terminal(
        &self,
        admission: &Admission,
        binding: crate::fenced_mutation_roster::RequestBindingKey,
        registration: BackendRegistration,
        authority: &AuthorityBinding,
        admission_provenance: &RosterCompactAdmissionProvenanceV2,
        evidence_tag: u8,
    ) -> (
        TerminalRecord,
        RosterExecutorProofBundleV1,
        RosterCompactTerminalEvidenceV2,
    ) {
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            registration.consensus_parts();
        let evidence = admission
            .members()
            .iter()
            .map(|member| vec![evidence_tag, member.ordinal()])
            .collect::<Vec<_>>();
        let commitments = admission
            .members()
            .iter()
            .zip(&evidence)
            .map(|(member, evidence)| {
                stable_terminal_proof_commitment(
                    binding,
                    registration,
                    admission,
                    Phase::Established,
                    member,
                    RosterProviderOutcomeV1::AppliedExecuted,
                    roster_executor_evidence_commitment(evidence),
                )
                .expect("terminal proof commitment")
            })
            .collect();
        let terminal = TerminalRecord::new(
            admission,
            registration_request_id,
            Phase::Established,
            commitments,
        )
        .expect("terminal record");
        let terminal_inputs = admission
            .members()
            .iter()
            .zip(&evidence)
            .map(
                |(member, evidence)| RosterTerminalAttestationSigningInputV1 {
                    profile: admission.profile(),
                    configuration_identity: self.identity,
                    certificate_subject_identity_commitment: [0x47; 32],
                    certificate_role: RosterAttestationCertificateRoleV1::Executor,
                    binding: binding.to_bytes(),
                    registration_handle,
                    registration_request_id: registration_request_id.to_bytes(),
                    registration_terminal_slot: *registration_terminal_slot.as_bytes(),
                    roster_id: *admission.roster_id().as_bytes(),
                    admission_commitment: admission.body_commitment(),
                    terminal_phase: Phase::Established,
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
                    provider_operation: RosterProviderOperationV1::Execute,
                    outcome: RosterProviderOutcomeV1::AppliedExecuted,
                    evidence: evidence.clone(),
                },
            )
            .collect::<Vec<_>>();
        let proofs = terminal_inputs
            .iter()
            .map(|input| {
                let provider_input =
                    RosterProviderReceiptSigningInputV1::from_terminal_input(input, [0x4a; 32])
                        .expect("provider receipt input");
                RosterExecutorMemberProofPartsV1 {
                    ordinal: input.ordinal,
                    provider_operation: RosterProviderOperationV1::Execute,
                    outcome: RosterProviderOutcomeV1::AppliedExecuted,
                    proof_epoch: 1,
                    evidence: input.evidence.clone(),
                    provider_certificate: self.certificate(
                        RosterAttestationCertificateRoleV1::Provider,
                        authority.ingress_scope().digest(),
                        [0x4a; 32],
                        [0x4b; 32],
                        self.executor_key.verifying_key(),
                    ),
                    provider_signature: sign_roster_test_digest(
                        &self.executor_key,
                        provider_input.digest().expect("provider receipt digest"),
                    ),
                    signature: sign_roster_test_digest(
                        &self.executor_key,
                        input.digest().expect("executor proof digest"),
                    ),
                }
            })
            .collect();
        let proof_bundle = RosterExecutorProofBundleV1::issue_from_signed_parts(
            &self.root,
            self.certificate(
                RosterAttestationCertificateRoleV1::Executor,
                authority.ingress_scope().digest(),
                [0x47; 32],
                [0x48; 32],
                self.executor_key.verifying_key(),
            ),
            proofs,
        )
        .expect("executor proof bundle");
        let compact_binding = RosterCompactTerminalEvidenceBindingV2::from_terminal_v1_input(
            admission_provenance,
            admission.terminal_checkpoint(),
            admission.terminal_result(),
            terminal_inputs
                .first()
                .expect("admission always has at least one member"),
        )
        .expect("compact terminal binding");
        let compact_proofs = terminal_inputs
            .iter()
            .zip(terminal.proof_commitments())
            .map(|(input, stable_proof_commitment)| {
                let member = RosterCompactTerminalMemberProjectionV2::from_terminal_v1_input(
                    input,
                    *stable_proof_commitment,
                )
                .expect("compact terminal member projection");
                let provider_certificate = self.certificate(
                    RosterAttestationCertificateRoleV1::Provider,
                    authority.ingress_scope().digest(),
                    [0x4a; 32],
                    [0x4b; 32],
                    self.executor_key.verifying_key(),
                );
                let provider = RosterAttestationLeafCertificateV1::issue_from_signed_parts(
                    &self.root,
                    provider_certificate.clone(),
                )
                .expect("provider certificate");
                RosterCompactTerminalMemberProofPartsV2 {
                    provider_certificate,
                    provider_signature: sign_roster_test_digest(
                        &self.executor_key,
                        crate::fenced_mutation_roster::provider_receipt_compact_digest(
                            &compact_binding,
                            &member,
                            &provider,
                        )
                        .expect("provider receipt digest"),
                    ),
                    signature: sign_roster_test_digest(
                        &self.executor_key,
                        RosterCompactTerminalMemberSigningInputV2 {
                            binding: compact_binding.clone(),
                            member: member.clone(),
                        }
                        .digest()
                        .expect("compact terminal member digest"),
                    ),
                    member,
                }
            })
            .collect();
        let terminal_evidence = RosterCompactTerminalEvidenceV2::issue_from_signed_parts(
            &self.root,
            self.certificate(
                RosterAttestationCertificateRoleV1::Executor,
                authority.ingress_scope().digest(),
                [0x47; 32],
                [0x48; 32],
                self.executor_key.verifying_key(),
            ),
            &compact_binding,
            compact_proofs,
        )
        .expect("compact terminal evidence");
        (terminal, proof_bundle, terminal_evidence)
    }
}

fn compressed_roster_test_key(key: &p256::ecdsa::VerifyingKey) -> [u8; 33] {
    key.to_sec1_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed P-256 key")
}

fn sign_roster_test_digest(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
    let signature: p256::ecdsa::Signature = key.sign_prehash(&digest).expect("sign digest");
    signature.normalize_s().to_bytes().into()
}

/// One real signed admission kept live across a topology rollover by the
/// dynamic-membership integration fixture.
#[derive(Clone)]
pub struct SignedFreshRosterAdmissionForTest {
    authority_identity: SessionConsensusIdentity,
    admission: Admission,
    registration: BackendRegistration,
    admission_provenance: RosterCompactAdmissionProvenanceV2,
    authority: AuthorityBinding,
    lease: crate::lease::LeaseGuard,
}

impl SignedFreshRosterAdmissionForTest {
    /// Exact membership scope that signed the immutable admission provenance.
    pub const fn authority_identity(&self) -> SessionConsensusIdentity {
        self.authority_identity
    }
}

/// Exact SDK-issued terminal body retained by a dynamic-membership fixture.
///
/// A later successor lease authenticates status with its current guard while
/// presenting these byte-exact artifacts. It must not mint a different proof
/// body after the original terminal transition may have committed.
#[derive(Clone)]
pub struct SignedRosterTerminalForTest {
    authority_identity: SessionConsensusIdentity,
    authority: AuthorityBinding,
    successor_lease: Option<crate::lease::LeaseGuard>,
    terminal: TerminalRecord,
    /// Exact authenticated production composite captured before reclaim.
    /// Compacted-status assertions must retain its Raft index rather than
    /// deriving one from the admission history epoch.
    committed: CommittedTerminal,
    proof_bundle: RosterExecutorProofBundleV1,
    terminal_evidence: RosterCompactTerminalEvidenceV2,
}

impl SignedRosterTerminalForTest {
    /// Exact membership identity that certified the terminal transition.
    pub const fn authority_identity(&self) -> SessionConsensusIdentity {
        self.authority_identity
    }
}

/// Submit one fresh signed PollAdmit and its matching signed terminal proof
/// through the live consumer ingress. The returned authority identity is the
/// exact current membership scope used by every signed artifact.
pub async fn submit_signed_fresh_roster_cycle_for_test(
    store: &ConsensusSessionStore,
    seed: u8,
) -> Result<SessionConsensusIdentity, String> {
    let admission = submit_signed_fresh_roster_admission_for_test(store, seed).await?;
    submit_signed_roster_terminal_for_test(store, seed, &admission, &admission.authority)
        .await
        .map(|terminal| terminal.authority_identity())
}

/// Submit only a fresh signed PollAdmit. This leaves a real live row behind so
/// rollover/restart coverage can prove predecessor admission history without
/// manufacturing a storage fixture.
pub async fn submit_signed_fresh_roster_admission_for_test(
    store: &ConsensusSessionStore,
    seed: u8,
) -> Result<SignedFreshRosterAdmissionForTest, String> {
    submit_signed_fresh_roster_for_test(store, seed).await
}

/// Release the predecessor lease after its signed admission has been recorded
/// so a successor may take over with a strictly higher fence.
pub async fn release_signed_fresh_roster_admission_for_test(
    store: &ConsensusSessionStore,
    admission: &SignedFreshRosterAdmissionForTest,
) -> Result<(), String> {
    store
        .release(admission.lease.clone())
        .await
        .map_err(|_| "test predecessor roster lease release rejected".to_owned())
}

/// Terminalize an honest predecessor admission after a successor has acquired
/// the same key. The admission provenance remains predecessor-signed while the
/// terminal ingress, proofs, and compact evidence use the current scope.
pub async fn terminalize_signed_fresh_roster_admission_for_test(
    store: &ConsensusSessionStore,
    seed: u8,
    admission: &SignedFreshRosterAdmissionForTest,
) -> Result<SignedRosterTerminalForTest, String> {
    let consumer_scope = store
        .consumer_scope()
        .map_err(|_| "successor consumer scope unavailable".to_owned())?;
    let roster_scope = Scope::from_digest(session_consumer_roster_scope_commitment(consumer_scope));
    if roster_scope == admission.admission.scope() {
        return Err("successor consumer scope did not advance from predecessor".to_owned());
    }
    let lease = store
        .acquire(
            admission.admission.key(),
            OwnerId::new("roster-dynamic-successor-owner")
                .map_err(|_| "test successor owner rejected".to_owned())?,
            Duration::from_secs(60),
        )
        .await
        .map_err(|_| "test successor roster lease rejected".to_owned())?;
    let current = AuthorityBinding::from_consensus_parts(
        roster_scope.digest(),
        admission.admission.key().clone(),
        lease.owner().clone(),
        lease.fence(),
        AuthorityLeaseMetadata::new(
            lease.credential_id(),
            admission.admission.expected_generation(),
            lease.acquired_at(),
            lease.expires_at(),
        ),
    )
    .map_err(|_| "test successor ingress authority rejected".to_owned())?;
    let authority = AuthorityBinding::for_validated_admission(&admission.admission, &current, true)
        .map_err(|_| "test successor authority binding rejected".to_owned())?;
    if authority.fence() <= admission.authority.fence() {
        return Err("successor roster takeover did not advance the fence".to_owned());
    }
    match store.renew(&admission.lease, Duration::from_secs(60)).await {
        Err(crate::LeaseError::StaleFence) => {}
        _ => {
            let _ = store.release(lease).await;
            return Err(
                "released predecessor roster guard was not stale after takeover".to_owned(),
            );
        }
    }
    let terminal = submit_signed_roster_terminal_for_test(store, seed, admission, &authority).await;
    let released = store
        .release(lease)
        .await
        .map_err(|_| "test successor roster lease release rejected".to_owned());
    let terminal = terminal?;
    released?;
    Ok(terminal)
}

/// Recover current execution authority for an exact durable terminal after
/// the original execution lease has been released or expired. The immutable
/// admission, terminal body, provider proofs, and compact evidence remain
/// byte-identical; only the separately authenticated current lease guard is
/// replaced by a strictly higher fence.
pub async fn recover_signed_roster_terminal_authority_for_test(
    store: &ConsensusSessionStore,
    admission: &SignedFreshRosterAdmissionForTest,
    terminal: &mut SignedRosterTerminalForTest,
) -> Result<(), String> {
    if terminal.successor_lease.is_some() {
        return Err("test terminal already retains current execution authority".to_owned());
    }
    let (authority_identity, _) = store
        .current_scope()
        .map_err(|_| "recovery membership scope unavailable".to_owned())?;
    if authority_identity != terminal.authority_identity {
        return Err("terminal recovery changed the committed membership identity".to_owned());
    }
    let consumer_scope = store
        .consumer_scope()
        .map_err(|_| "recovery consumer scope unavailable".to_owned())?;
    let roster_scope = Scope::from_digest(session_consumer_roster_scope_commitment(consumer_scope));
    let lease = store
        .acquire(
            admission.admission.key(),
            OwnerId::new("roster-dynamic-recovery-owner")
                .map_err(|_| "test recovery owner rejected".to_owned())?,
            Duration::from_secs(60),
        )
        .await
        .map_err(|_| "test recovery roster lease rejected".to_owned())?;
    let current = AuthorityBinding::from_consensus_parts(
        roster_scope.digest(),
        admission.admission.key().clone(),
        lease.owner().clone(),
        lease.fence(),
        AuthorityLeaseMetadata::new(
            lease.credential_id(),
            admission.admission.expected_generation(),
            lease.acquired_at(),
            lease.expires_at(),
        ),
    )
    .map_err(|_| "test recovery ingress authority rejected".to_owned())?;
    let authority = AuthorityBinding::for_validated_admission(&admission.admission, &current, true)
        .map_err(|_| "test recovery authority binding rejected".to_owned())?;
    if authority.fence() <= terminal.authority.fence()
        || authority.fence() <= admission.authority.fence()
    {
        return Err("test recovery authority did not advance the execution fence".to_owned());
    }
    let admission_provenance_bytes = admission
        .admission_provenance
        .canonical_bytes()
        .map_err(|_| "test recovery admission provenance encoding failed".to_owned())?;
    let terminal_bytes = terminal
        .terminal
        .to_canonical_bytes(&admission.admission)
        .map_err(|_| "test recovery terminal encoding failed".to_owned())?;
    let proof_bundle_bytes = terminal
        .proof_bundle
        .canonical_bytes()
        .map_err(|_| "test recovery proof bundle encoding failed".to_owned())?;
    let terminal_evidence_bytes = terminal
        .terminal_evidence
        .canonical_bytes()
        .map_err(|_| "test recovery terminal evidence encoding failed".to_owned())?;
    terminal.authority = authority;
    terminal.successor_lease = Some(lease);
    if admission_provenance_bytes
        != admission
            .admission_provenance
            .canonical_bytes()
            .map_err(|_| "test recovered admission provenance encoding failed".to_owned())?
        || terminal_bytes
            != terminal
                .terminal
                .to_canonical_bytes(&admission.admission)
                .map_err(|_| "test recovered terminal encoding failed".to_owned())?
        || proof_bundle_bytes
            != terminal
                .proof_bundle
                .canonical_bytes()
                .map_err(|_| "test recovered proof bundle encoding failed".to_owned())?
        || terminal_evidence_bytes
            != terminal
                .terminal_evidence
                .canonical_bytes()
                .map_err(|_| "test recovered terminal evidence encoding failed".to_owned())?
    {
        return Err("test recovery rewrote an immutable signed roster artifact".to_owned());
    }
    Ok(())
}

/// Exercise protected-roster status after a real mixed-identity row has been
/// compacted. The final invocation can also submit a distinct, validly signed
/// terminal body and prove it is non-definitively closed as Conflict.
pub async fn assert_mixed_compacted_roster_status_and_terminal_conflict_for_test(
    store: &ConsensusSessionStore,
    seed: u8,
    admission: &SignedFreshRosterAdmissionForTest,
    committed_terminal: &SignedRosterTerminalForTest,
    exercise_terminal_conflict: bool,
) -> Result<(), String> {
    let (authority_identity, _) = store
        .current_scope()
        .map_err(|_| "current membership scope unavailable".to_owned())?;
    let root = store
        .inner
        .roster_attestation_trust_root
        .as_ref()
        .cloned()
        .ok_or_else(|| "current topology has no roster root".to_owned())?;
    if root != roster_attestation_trust_root_for_test() {
        return Err("current topology root does not match test issuer".to_owned());
    }
    let scope = store
        .consumer_scope()
        .map_err(|_| "consumer scope unavailable".to_owned())?;
    let roster_scope = Scope::from_digest(session_consumer_roster_scope_commitment(scope));
    let authority = committed_terminal.authority.clone();
    if committed_terminal.successor_lease.is_none() {
        return Err("compacted-roster successor lease was not retained".to_owned());
    }
    if authority.ingress_scope() != roster_scope
        || authority.key() != admission.admission.key()
        || authority.generation() != admission.admission.expected_generation()
    {
        return Err("retained compacted-roster authority changed scope or key".to_owned());
    }
    if authority.fence() <= admission.authority.fence() {
        return Err("compacted-roster successor did not advance the fence".to_owned());
    }
    if committed_terminal.committed.record() != &committed_terminal.terminal {
        return Err("test compacted roster retained composite changed terminal body".to_owned());
    }
    let expected_tombstone =
        crate::fenced_mutation_roster::TerminalConflictTombstone::from_committed_terminal(
            &admission.admission,
            &committed_terminal.committed,
        )
        .map_err(|_| "expected compacted roster tombstone was invalid".to_owned())?;
    if expected_tombstone.terminal_raft_log_index()
        != committed_terminal
            .committed
            .commit_metadata()
            .raft_log_index()
    {
        return Err(
            "compacted-roster tombstone did not retain the committed Raft index".to_owned(),
        );
    }
    let expected_tombstone_bytes = expected_tombstone
        .to_canonical_bytes()
        .map_err(|_| "expected compacted roster tombstone encoding failed".to_owned())?;

    let result = async {
        assert_exact_compacted_roster_row_for_test(
            store,
            admission,
            &authority,
            &expected_tombstone,
        )
        .await?;
        let now = store.inner.clock.now_utc();
        let issuer = RosterIngressTestIssuer::new(
            root,
            authority_identity,
            now.add_seconds(-30)
                .ok_or_else(|| "test certificate start overflow".to_owned())?,
            now.add_seconds(300)
                .ok_or_else(|| "test certificate expiry overflow".to_owned())?,
        );
        let consumer_identity = SessionConsumerIdentity::new(
            "spiffe://test.example/tenant/roster-dynamic-rollover/ns/default/sa/store/nf/smf/instance/one",
        )
        .map_err(|_| "test consumer identity rejected".to_owned())?;
        let manifest = store
            .consumer_authorization_manifest([SessionConsumerAuthorizationGrant::try_new(
                SpiffeId::new(consumer_identity.as_str())
                    .map_err(|_| "test consumer SPIFFE ID rejected".to_owned())?,
                [SessionConsumerTenantNfScope::new(
                    admission.admission.key().tenant.clone(),
                    admission.admission.key().nf_kind.clone(),
                )],
            )
            .map_err(|_| "test consumer grant rejected".to_owned())?])
            .await
            .map_err(|_| "test consumer manifest rejected".to_owned())?;
        let authorization = manifest
            .authorize(&consumer_identity)
            .map_err(|_| "test consumer authorization rejected".to_owned())?;
        let roster_authorization = authorization.roster_authorization();
        if roster_scope == admission.admission.scope() {
            return Err("successor consumer scope did not advance from predecessor".to_owned());
        }
        let service = store.consumer_service();
        let peer_identity_commitment = session_consumer_identity_commitment(authorization.identity());
        let binding = admission
            .admission
            .binding_key(admission.registration.consensus_parts().1.history_epoch())
            .map_err(|_| "test compacted terminal binding rejected".to_owned())?;
        if committed_terminal.authority_identity() != authority_identity {
            return Err("compacted terminal identity does not match current topology".to_owned());
        }
        let exact_terminal_status_capsule = terminal_capsule(TerminalCapsuleInput {
            scope: roster_scope,
            binding,
            registration: admission.registration,
            authority: &authority,
            terminal: &committed_terminal.terminal,
            admission: &admission.admission,
            proof_bundle: &committed_terminal.proof_bundle,
            terminal_evidence: &committed_terminal.terminal_evidence,
        });
        let (terminal, proof_bundle, terminal_evidence) = issuer.terminal(
            &admission.admission,
            binding,
            admission.registration,
            &authority,
            &admission.admission_provenance,
            0x56,
        );
        let exact_terminal_capsule = terminal_capsule(TerminalCapsuleInput {
            scope: roster_scope,
            binding,
            registration: admission.registration,
            authority: &authority,
            terminal: &terminal,
            admission: &admission.admission,
            proof_bundle: &proof_bundle,
            terminal_evidence: &terminal_evidence,
        });
        let status_request_id = SessionConsumerRequestId::from_bytes([seed.wrapping_add(7); 16]);
        let status_request = SessionConsumerRequest::new(
            scope,
            status_request_id,
            SessionConsumerOperation::FencedMutationRosterTerminalStatus {
                request: Box::new(exact_terminal_status_capsule),
            },
        );
        let (status_tag, status_digest) =
            session_consumer_roster_ingress_operation(status_request.operation())
                .map_err(|_| "test compacted status operation rejected".to_owned())?;
        let status_response = service
            .execute_roster_ingress(
                &roster_authorization,
                status_request,
                issuer.ingress(
                    peer_identity_commitment,
                    roster_scope.digest(),
                    status_request_id,
                    status_tag,
                    status_digest,
                ),
                None,
            )
            .await;
        let status_capsule = match status_response {
            SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                crate::consumer::SessionConsumerRosterTerminalReadResponse::Recorded(capsule),
            ) => capsule,
            _ => return Err("authenticated compacted terminal status was not recorded".to_owned()),
        };
        let status: RosterIngressTerminalResponseWire = crate::fenced_mutation_roster::decode_frame(
            status_capsule.canonical_bytes(),
            TERMINAL_RESPONSE_MAGIC,
            TERMINAL_RESPONSE_DOMAIN,
            crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
        )
        .map_err(|_| "authenticated compacted terminal status was malformed".to_owned())?;
        match status {
            RosterIngressTerminalResponseWire::Compacted {
                scope: returned_scope,
                history_epoch,
                tombstone,
            } if returned_scope == roster_scope.digest()
                && history_epoch == binding.history_epoch()
                && tombstone == expected_tombstone_bytes => {}
            _ => {
                return Err(
                    "authenticated compacted terminal status changed its exact body".to_owned(),
                );
            }
        }
        if !exercise_terminal_conflict {
            return Ok(());
        }

        let terminal_request_id = SessionConsumerRequestId::from_bytes([seed.wrapping_add(8); 16]);
        let terminal_request = SessionConsumerRequest::new(
            scope,
            terminal_request_id,
            SessionConsumerOperation::FencedMutationRosterTerminalize {
                request: Box::new(exact_terminal_capsule),
            },
        );
        let (terminal_tag, terminal_digest) =
            session_consumer_roster_ingress_operation(terminal_request.operation())
                .map_err(|_| "test compacted terminal operation rejected".to_owned())?;
        match service
            .execute_roster_ingress(
                &roster_authorization,
                terminal_request,
                issuer.ingress(
                    peer_identity_commitment,
                    roster_scope.digest(),
                    terminal_request_id,
                    terminal_tag,
                    terminal_digest,
                ),
                None,
            )
            .await
        {
            SessionConsumerResponse::FencedMutationRosterTerminalize(
                SessionConsumerRosterTerminalMutationResponse::Rejected(
                    SessionConsumerRosterRejection::Conflict,
                ),
            ) => Ok(()),
            _ => Err("compacted terminal mutation was definitive or unauthenticated".to_owned()),
        }
    }
    .await;
    if exercise_terminal_conflict {
        let released = store
            .release(
                committed_terminal
                    .successor_lease
                    .as_ref()
                    .expect("successor lease presence checked")
                    .clone(),
            )
            .await
            .map_err(|_| "test compacted-roster successor lease release rejected".to_owned());
        result?;
        released
    } else {
        result
    }
}

/// Submit a newly signed predecessor-identity admission after a successor
/// scope is active. The stale ingress certificate must be rejected before
/// decoding or consensus submission, so the bounded raft log cannot change.
pub async fn assert_stale_predecessor_signed_fresh_roster_admission_rejected_for_test(
    store: &ConsensusSessionStore,
    predecessor_identity: SessionConsensusIdentity,
    seed: u8,
) -> Result<(), String> {
    let (successor_identity, _) = store
        .current_scope()
        .map_err(|_| "current membership scope unavailable".to_owned())?;
    if predecessor_identity == successor_identity {
        return Err("stale predecessor identity matches active successor scope".to_owned());
    }
    let root = store
        .inner
        .roster_attestation_trust_root
        .as_ref()
        .cloned()
        .ok_or_else(|| "current topology has no roster root".to_owned())?;
    if root != roster_attestation_trust_root_for_test() {
        return Err("current topology root does not match test issuer".to_owned());
    }

    let scope = store
        .consumer_scope()
        .map_err(|_| "consumer scope unavailable".to_owned())?;
    let consumer_identity = SessionConsumerIdentity::new(
        "spiffe://test.example/tenant/roster-dynamic-rollover/ns/default/sa/store/nf/smf/instance/one",
    )
    .map_err(|_| "test consumer identity rejected".to_owned())?;
    let key = SessionKey {
        tenant: TenantId::new("roster-dynamic-rollover")
            .map_err(|_| "test tenant rejected".to_owned())?,
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![seed; 16])
            .try_into()
            .map_err(|_| "test stale stable ID rejected".to_owned())?,
    };
    let owner =
        OwnerId::new("roster-dynamic-owner").map_err(|_| "test owner rejected".to_owned())?;
    let now = store.inner.clock.now_utc();
    let acquired_at = now
        .add_seconds(-1)
        .ok_or_else(|| "test stale authority start overflow".to_owned())?;
    let expires_at = now
        .add_seconds(300)
        .ok_or_else(|| "test stale authority expiry overflow".to_owned())?;
    let roster_scope = Scope::from_digest(session_consumer_roster_scope_commitment(scope));
    let admission = Admission::authenticate(
        AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([seed; 16])
                .map_err(|_| "test stale roster ID rejected".to_owned())?,
            (0..FRESH_ROSTER_MEMBERS)
                .map(|ordinal| {
                    Member::new(
                        ordinal as u8,
                        MemberOperationId::from_bytes([seed.wrapping_add(ordinal as u8 + 1); 16])
                            .expect("test stale member operation ID"),
                        vec![ordinal as u8 + 1],
                        1,
                    )
                    .expect("test stale roster member")
                })
                .collect(),
            EstablishedMutation::no_op(),
            vec![seed.wrapping_add(1)],
            vec![seed.wrapping_add(2)],
            vec![seed.wrapping_add(3)],
        )
        .map_err(|_| "test stale admission proposal rejected".to_owned())?,
        key.clone(),
        roster_scope,
        owner.clone(),
        FenceToken::new(1),
        Generation::new(1),
    )
    .map_err(|_| "test stale admission rejected".to_owned())?;
    let authority = AuthorityBinding::for_admission(
        &admission,
        owner,
        FenceToken::new(1),
        AuthorityLeaseMetadata::new(1, Generation::new(1), acquired_at, expires_at),
    )
    .map_err(|_| "test stale authority binding rejected".to_owned())?;
    let manifest = store
        .consumer_authorization_manifest([SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(consumer_identity.as_str())
                .map_err(|_| "test consumer SPIFFE ID rejected".to_owned())?,
            [SessionConsumerTenantNfScope::new(
                key.tenant.clone(),
                key.nf_kind.clone(),
            )],
        )
        .map_err(|_| "test consumer grant rejected".to_owned())?])
        .await
        .map_err(|_| "test consumer manifest rejected".to_owned())?;
    let authorization = manifest
        .authorize(&consumer_identity)
        .map_err(|_| "test consumer authorization rejected".to_owned())?;
    let roster_authorization = authorization.roster_authorization();
    let request_id = SessionConsumerRequestId::from_bytes([seed.wrapping_add(4); 16]);
    let request = SessionConsumerRequest::new(
        scope,
        request_id,
        SessionConsumerOperation::FencedMutationRosterPollAdmit {
            request: Box::new(admission_capsule(roster_scope, &admission, &authority)),
        },
    );
    let (operation_tag, capsule_digest) =
        session_consumer_roster_ingress_operation(request.operation())
            .map_err(|_| "test stale admission operation rejected".to_owned())?;
    let issuer = RosterIngressTestIssuer::new(
        root,
        predecessor_identity,
        now.add_seconds(-30)
            .ok_or_else(|| "test certificate start overflow".to_owned())?,
        now.add_seconds(300)
            .ok_or_else(|| "test certificate expiry overflow".to_owned())?,
    );
    let peer_identity_commitment = session_consumer_identity_commitment(authorization.identity());
    let attestation = issuer.ingress(
        peer_identity_commitment,
        roster_scope.digest(),
        request_id,
        operation_tag,
        capsule_digest,
    );
    let provenance_input = RosterCompactAdmissionProvenanceSigningInputV2::for_admission(
        predecessor_identity,
        &admission,
        &authority,
        attestation.signing_input(),
        [seed.wrapping_add(5); 32],
    )
    .map_err(|_| "test stale admission provenance input rejected".to_owned())?;
    let provenance = issuer.compact_admission(
        roster_scope.digest(),
        [seed.wrapping_add(5); 32],
        &provenance_input,
    );
    let before = store.status().last_log_index;
    match store
        .consumer_service()
        .execute_roster_ingress(
            &roster_authorization,
            request,
            attestation,
            Some(provenance),
        )
        .await
    {
        SessionConsumerResponse::FencedMutationRosterPollAdmit(
            SessionConsumerRosterAdmissionMutationResponse::Rejected(
                SessionConsumerRosterRejection::Authority,
            ),
        ) => {}
        _ => {
            return Err("stale predecessor admission was not rejected as Authority".to_owned());
        }
    }
    if store.status().last_log_index != before {
        return Err("stale predecessor admission reached consensus submission".to_owned());
    }
    Ok(())
}

/// Observe only the exact compacted row selected by a live successor lease.
/// This test-control helper delegates to the typed production backend read;
/// it exposes neither SQL nor an administrative storage surface.
async fn assert_exact_compacted_roster_row_for_test(
    store: &ConsensusSessionStore,
    admission: &SignedFreshRosterAdmissionForTest,
    authority: &AuthorityBinding,
    expected_tombstone: &crate::fenced_mutation_roster::TerminalConflictTombstone,
) -> Result<(), String> {
    let (row, _) = store
        .inner
        .backend
        .consensus_protected_roster_admission_status(
            store.inner.storage_identity,
            admission.admission.clone(),
            authority.clone(),
            store.inner.clock.now_utc(),
        )
        .await
        .map_err(|_| "exact compacted roster row rejected".to_owned())?;
    match row {
        crate::sqlite::consensus::ProtectedRosterReadResult::Compacted {
            history_epoch,
            tombstone,
        } if history_epoch == admission.registration.consensus_parts().1.history_epoch()
            && tombstone.as_ref() == expected_tombstone =>
        {
            Ok(())
        }
        crate::sqlite::consensus::ProtectedRosterReadResult::Missing => {
            Err("exact roster row was missing after compaction".to_owned())
        }
        crate::sqlite::consensus::ProtectedRosterReadResult::Admitted(_) => {
            Err("exact roster row remained live after compaction".to_owned())
        }
        crate::sqlite::consensus::ProtectedRosterReadResult::Terminalized(_) => {
            Err("exact roster row remained retained after compaction".to_owned())
        }
        crate::sqlite::consensus::ProtectedRosterReadResult::Compacted { .. } => {
            Err("exact roster tombstone changed history epoch or body".to_owned())
        }
    }
}

async fn submit_signed_fresh_roster_for_test(
    store: &ConsensusSessionStore,
    seed: u8,
) -> Result<SignedFreshRosterAdmissionForTest, String> {
    let (authority_identity, _) = store
        .current_scope()
        .map_err(|_| "current membership scope unavailable".to_owned())?;
    let root = store
        .inner
        .roster_attestation_trust_root
        .as_ref()
        .cloned()
        .ok_or_else(|| "current topology has no roster root".to_owned())?;
    if root != roster_attestation_trust_root_for_test() {
        return Err("current topology root does not match test issuer".to_owned());
    }
    let now = store.inner.clock.now_utc();
    let issuer = RosterIngressTestIssuer::new(
        root,
        authority_identity,
        now.add_seconds(-30)
            .ok_or_else(|| "test certificate start overflow".to_owned())?,
        now.add_seconds(300)
            .ok_or_else(|| "test certificate expiry overflow".to_owned())?,
    );
    let key = SessionKey {
        tenant: TenantId::new("roster-dynamic-rollover")
            .map_err(|_| "test tenant rejected".to_owned())?,
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![seed; 16])
            .try_into()
            .map_err(|_| "test stable ID rejected".to_owned())?,
    };
    let owner =
        OwnerId::new("roster-dynamic-owner").map_err(|_| "test owner rejected".to_owned())?;
    let lease = store
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .map_err(|_| "test roster lease rejected".to_owned())?;
    match store
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: consumer_record(&key, &lease),
        })
        .await
        .map_err(|_| "test business record write rejected".to_owned())?
    {
        CompareAndSetResult::Success => {}
        CompareAndSetResult::Conflict { .. } => {
            return Err("test business record unexpectedly conflicted".to_owned());
        }
    }

    let scope = store
        .consumer_scope()
        .map_err(|_| "consumer scope unavailable".to_owned())?;
    let consumer_identity = SessionConsumerIdentity::new(
        "spiffe://test.example/tenant/roster-dynamic-rollover/ns/default/sa/store/nf/smf/instance/one",
    )
    .map_err(|_| "test consumer identity rejected".to_owned())?;
    let manifest = store
        .consumer_authorization_manifest([SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(consumer_identity.as_str())
                .map_err(|_| "test consumer SPIFFE ID rejected".to_owned())?,
            [SessionConsumerTenantNfScope::new(
                key.tenant.clone(),
                key.nf_kind.clone(),
            )],
        )
        .map_err(|_| "test consumer grant rejected".to_owned())?])
        .await
        .map_err(|_| "test consumer manifest rejected".to_owned())?;
    let authorization = manifest
        .authorize(&consumer_identity)
        .map_err(|_| "test consumer authorization rejected".to_owned())?;
    let roster_authorization = authorization.roster_authorization();
    let roster_scope = Scope::from_digest(session_consumer_roster_scope_commitment(scope));
    let admission = Admission::authenticate(
        AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([seed; 16]).map_err(|_| "test roster ID rejected".to_owned())?,
            (0..FRESH_ROSTER_MEMBERS)
                .map(|ordinal| {
                    Member::new(
                        ordinal as u8,
                        MemberOperationId::from_bytes([seed.wrapping_add(ordinal as u8 + 1); 16])
                            .expect("test member operation ID"),
                        vec![ordinal as u8 + 1],
                        1,
                    )
                    .expect("test roster member")
                })
                .collect(),
            EstablishedMutation::no_op(),
            vec![seed.wrapping_add(1)],
            vec![seed.wrapping_add(2)],
            vec![seed.wrapping_add(3)],
        )
        .map_err(|_| "test admission proposal rejected".to_owned())?,
        key.clone(),
        roster_scope,
        owner,
        lease.fence(),
        Generation::new(1),
    )
    .map_err(|_| "test admission rejected".to_owned())?;
    let authority = AuthorityBinding::for_admission(
        &admission,
        lease.owner().clone(),
        lease.fence(),
        AuthorityLeaseMetadata::new(
            lease.credential_id(),
            Generation::new(1),
            lease.acquired_at(),
            lease.expires_at(),
        ),
    )
    .map_err(|_| "test authority binding rejected".to_owned())?;
    let service = store.consumer_service();
    let peer_identity_commitment = session_consumer_identity_commitment(authorization.identity());
    let admission_request_id = SessionConsumerRequestId::from_bytes([seed.wrapping_add(4); 16]);
    let admission_request = SessionConsumerRequest::new(
        scope,
        admission_request_id,
        SessionConsumerOperation::FencedMutationRosterPollAdmit {
            request: Box::new(admission_capsule(roster_scope, &admission, &authority)),
        },
    );
    let (admission_tag, admission_digest) =
        session_consumer_roster_ingress_operation(admission_request.operation())
            .map_err(|_| "test admission operation rejected".to_owned())?;
    let admission_attestation = issuer.ingress(
        peer_identity_commitment,
        roster_scope.digest(),
        admission_request_id,
        admission_tag,
        admission_digest,
    );
    let admission_provenance_input = service
        .prepare_compact_admission_provenance_input(
            &roster_authorization,
            &admission_request,
            &admission_attestation,
            [seed.wrapping_add(5); 32],
        )
        .map_err(|_| "test admission provenance input rejected".to_owned())?;
    let admission_provenance = issuer.compact_admission(
        roster_scope.digest(),
        [seed.wrapping_add(5); 32],
        &admission_provenance_input,
    );
    let registration = match service
        .execute_roster_ingress(
            &roster_authorization,
            admission_request,
            admission_attestation,
            Some(admission_provenance.clone()),
        )
        .await
    {
        SessionConsumerResponse::FencedMutationRosterPollAdmit(
            SessionConsumerRosterAdmissionMutationResponse::Recorded(capsule),
        ) => match crate::fenced_mutation_roster::decode_frame(
            capsule.canonical_bytes(),
            ADMISSION_RESPONSE_MAGIC,
            ADMISSION_RESPONSE_DOMAIN,
            crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
        )
        .map_err(|_| "test fresh admission response rejected".to_owned())?
        {
            RosterIngressAdmissionResponseWire::Fresh { registration, .. } => {
                registration.registration(&admission)
            }
            _ => return Err("test PollAdmit did not record a fresh admission".to_owned()),
        },
        _ => return Err("test PollAdmit was not recorded".to_owned()),
    };
    Ok(SignedFreshRosterAdmissionForTest {
        authority_identity,
        admission,
        registration,
        admission_provenance,
        authority,
        lease,
    })
}

async fn submit_signed_roster_terminal_for_test(
    store: &ConsensusSessionStore,
    seed: u8,
    admission: &SignedFreshRosterAdmissionForTest,
    authority: &AuthorityBinding,
) -> Result<SignedRosterTerminalForTest, String> {
    let (authority_identity, _) = store
        .current_scope()
        .map_err(|_| "current membership scope unavailable".to_owned())?;
    let root = store
        .inner
        .roster_attestation_trust_root
        .as_ref()
        .cloned()
        .ok_or_else(|| "current topology has no roster root".to_owned())?;
    if root != roster_attestation_trust_root_for_test() {
        return Err("current topology root does not match test issuer".to_owned());
    }
    let now = store.inner.clock.now_utc();
    let issuer = RosterIngressTestIssuer::new(
        root,
        authority_identity,
        now.add_seconds(-30)
            .ok_or_else(|| "test certificate start overflow".to_owned())?,
        now.add_seconds(300)
            .ok_or_else(|| "test certificate expiry overflow".to_owned())?,
    );
    let scope = store
        .consumer_scope()
        .map_err(|_| "consumer scope unavailable".to_owned())?;
    let consumer_identity = SessionConsumerIdentity::new(
        "spiffe://test.example/tenant/roster-dynamic-rollover/ns/default/sa/store/nf/smf/instance/one",
    )
    .map_err(|_| "test consumer identity rejected".to_owned())?;
    let manifest = store
        .consumer_authorization_manifest([SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(consumer_identity.as_str())
                .map_err(|_| "test consumer SPIFFE ID rejected".to_owned())?,
            [SessionConsumerTenantNfScope::new(
                admission.admission.key().tenant.clone(),
                admission.admission.key().nf_kind.clone(),
            )],
        )
        .map_err(|_| "test consumer grant rejected".to_owned())?])
        .await
        .map_err(|_| "test consumer manifest rejected".to_owned())?;
    let authorization = manifest
        .authorize(&consumer_identity)
        .map_err(|_| "test consumer authorization rejected".to_owned())?;
    let roster_authorization = authorization.roster_authorization();
    let roster_scope = Scope::from_digest(session_consumer_roster_scope_commitment(scope));
    if authority.scope() != admission.admission.scope() || authority.ingress_scope() != roster_scope
    {
        return Err(
            "terminal authority does not bind predecessor admission to successor ingress"
                .to_owned(),
        );
    }
    let service = store.consumer_service();
    let peer_identity_commitment = session_consumer_identity_commitment(authorization.identity());
    let binding = admission
        .admission
        .binding_key(admission.registration.consensus_parts().1.history_epoch())
        .map_err(|_| "test admission binding rejected".to_owned())?;
    let (terminal, proof_bundle, terminal_evidence) = issuer.terminal(
        &admission.admission,
        binding,
        admission.registration,
        authority,
        &admission.admission_provenance,
        0x46,
    );
    let terminal_request_id = SessionConsumerRequestId::from_bytes([seed.wrapping_add(6); 16]);
    let exact_terminal_capsule = terminal_capsule(TerminalCapsuleInput {
        scope: roster_scope,
        binding,
        registration: admission.registration,
        authority,
        terminal: &terminal,
        admission: &admission.admission,
        proof_bundle: &proof_bundle,
        terminal_evidence: &terminal_evidence,
    });
    let terminal_request = SessionConsumerRequest::new(
        scope,
        terminal_request_id,
        SessionConsumerOperation::FencedMutationRosterTerminalize {
            request: Box::new(exact_terminal_capsule),
        },
    );
    let (terminal_tag, terminal_digest) =
        session_consumer_roster_ingress_operation(terminal_request.operation())
            .map_err(|_| "test terminal operation rejected".to_owned())?;
    let terminalized = service
        .execute_roster_ingress(
            &roster_authorization,
            terminal_request,
            issuer.ingress(
                peer_identity_commitment,
                roster_scope.digest(),
                terminal_request_id,
                terminal_tag,
                terminal_digest,
            ),
            None,
        )
        .await;
    match terminalized {
        SessionConsumerResponse::FencedMutationRosterTerminalize(
            SessionConsumerRosterTerminalMutationResponse::Recorded(_),
        ) => {}
        _ => return Err("test terminal proof was not recorded".to_owned()),
    }

    // Exercise the dedicated Established-only publication read through the
    // current successor ingress. The SQLite lookup must recover the immutable
    // predecessor scope from the retained admission rather than treating the
    // successor scope as historical identity.
    let terminal_status = store
        .inner
        .backend
        .consensus_protected_roster_terminal_status(
            store.inner.storage_identity,
            binding,
            {
                let (handle, request_id, terminal_slot) = admission.registration.consensus_parts();
                (handle, request_id, *terminal_slot.as_bytes())
            },
            authority.clone(),
            terminal.body_commitment(),
            terminal_evidence.clone(),
            store.inner.clock.now_utc(),
        )
        .await
        .map_err(|_| "test successor terminal status rejected".to_owned())?
        .0;
    let (receipt_commitment, committed) = match terminal_status {
        crate::sqlite::consensus::ProtectedRosterReadResult::Terminalized(read) => {
            (read.committed.receipt_commitment(), read.committed)
        }
        _ => return Err("test successor terminal status was not retained".to_owned()),
    };
    let (registration_handle, registration_request_id, registration_terminal_slot) =
        admission.registration.consensus_parts();
    let publication = SessionConsumerRosterCurrentPublicationAuthorityCapsule::new(
        roster_scope.digest(),
        admission.admission.key().clone(),
        *admission.admission.roster_id().as_bytes(),
        admission.admission.body_commitment(),
        terminal.body_commitment(),
        receipt_commitment,
        admission.admission.logical_owner().clone(),
        admission.admission.admission_fence(),
        registration_handle,
        registration_request_id.to_bytes(),
        *registration_terminal_slot.as_bytes(),
        authority.owner().clone(),
        authority.fence(),
        authority.credential_id(),
        authority.generation(),
        authority.acquired_at(),
        authority.expires_at(),
    )
    .map_err(|_| "test successor publication capsule rejected".to_owned())?;
    let publication_request_id = SessionConsumerRequestId::from_bytes([seed.wrapping_add(7); 16]);
    let publication_request = SessionConsumerRequest::new(
        scope,
        publication_request_id,
        SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority {
            request: Box::new(publication),
        },
    );
    let (publication_tag, publication_digest) =
        session_consumer_roster_ingress_operation(publication_request.operation())
            .map_err(|_| "test successor publication operation rejected".to_owned())?;
    match service
        .execute_roster_ingress(
            &roster_authorization,
            publication_request,
            issuer.ingress(
                peer_identity_commitment,
                roster_scope.digest(),
                publication_request_id,
                publication_tag,
                publication_digest,
            ),
            None,
        )
        .await
    {
        SessionConsumerResponse::FencedMutationRosterCurrentPublicationAuthority(
            SessionConsumerRosterCurrentPublicationAuthorityReadResponse::Current,
        ) => Ok(SignedRosterTerminalForTest {
            authority_identity,
            authority: authority.clone(),
            successor_lease: None,
            terminal,
            committed,
            proof_bundle,
            terminal_evidence,
        }),
        _ => Err("test successor publication authority was not current".to_owned()),
    }
}

fn consumer_record(key: &SessionKey, lease: &LeaseGuard) -> StoredSessionRecord {
    let mut record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("roster-dynamic-rollover"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    let key_id = KeyId::new("roster-dynamic-key").expect("test key ID");
    let aad = EnvelopeAad::session(
        record.key.tenant.clone(),
        1,
        SessionAad::new(
            record.key.nf_kind.as_str(),
            "roster-dynamic-rollover",
            record.state_type.as_str(),
            record.generation.get(),
            record.fence.get(),
            "roster-dynamic-backend",
        )
        .expect("test session AAD"),
    );
    let envelope = CryptoEnvelopeV1 {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_id: key_id.clone(),
        nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
        aad: serialize_bound_aad(&aad, &key_id).expect("test bound AAD"),
        ciphertext_and_tag: vec![0x5a; 32]
            .into_iter()
            .chain([0xa5; AEAD_TAG_LEN])
            .collect(),
    };
    record.payload =
        EncryptedSessionPayload::try_envelope(envelope.encode().expect("test envelope"))
            .expect("test encrypted payload");
    record
}
