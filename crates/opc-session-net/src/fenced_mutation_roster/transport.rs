//! Private client-side canonical wire codec and concrete quorum port.
//!
//! No trait in this module is implementable by downstream code. The sole port
//! is built by consuming the exact revision-five persistent client.

use super::{
    canonical::{
        decode_frame, encode_frame, Admission, EstablishedPublicationProvider, MemberProvider,
        Profile, RequestBindingKey, RequestId, RosterId, Scope, TerminalConflictTombstone,
        MAX_ADMISSION_CODEC_BYTES, MAX_COMMITTED_TERMINAL_CODEC_BYTES, MAX_TOMBSTONE_CODEC_BYTES,
    },
    client::FencedMutationRosterClient,
    diagnostics::{FencedMutationRosterDiagnostics, RosterDiagnostics},
    protected_roster_scope_from_consensus_identity,
    publication::PublicationAdapter,
    runtime::{
        AdmissionStatusRequest, AuthorityBinding, BackendRegistration, BackendRejection,
        CommittedTerminal, CurrentPublicationAuthorityRead, FencedMutationRosterExecutorAttestor,
        ProfiledTerminalConflictTombstone, PublicationAuthorityReader, RecoveryRequest,
        RegistrationAdmissionProvenance, RegistrationDecision, RegistrationRequest, RosterExecutor,
        RosterExecutorBackend, TerminalBody, TerminalStatusDecision, TerminalStatusRequest,
        TerminalizeDecision, TerminalizeRequest,
    },
};
use crate::consumer::{
    AuthenticatedRosterConsumer, PersistentSessionConsumerClient,
    PersistentSessionConsumerDiagnostics,
};
use opc_session_store::fenced_mutation_roster::{
    RosterAttestationTrustRootIdentityV1, RosterCompactAdmissionProvenanceV2,
    RosterProfileV2CompactAdmissionProvenanceV1, MAX_EXECUTOR_PROOF_BUNDLE_BYTES,
    MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES, MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES,
};
use opc_session_store::{
    FenceToken, Generation, OwnerId, SessionConsensusIdentity, SessionConsumerRequestId,
    SessionConsumerRosterAdmissionCapsule, SessionConsumerRosterAdmissionMutationResponse,
    SessionConsumerRosterAdmissionReadResponse,
    SessionConsumerRosterCurrentPublicationAuthorityCapsule,
    SessionConsumerRosterCurrentPublicationAuthorityReadResponse, SessionConsumerRosterRejection,
    SessionConsumerRosterTerminalCapsule, SessionConsumerRosterTerminalMutationResponse,
    SessionConsumerRosterTerminalReadResponse, SessionConsumerScope, SessionKey, Timestamp,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, num::NonZeroUsize, sync::Arc};

const ADMISSION_REQUEST_MAGIC: [u8; 8] = *b"OPCRPA1\0";
const ADMISSION_RESPONSE_MAGIC: [u8; 8] = *b"OPCRPS1\0";
const TERMINAL_REQUEST_MAGIC: [u8; 8] = *b"OPCRPT1\0";
const TERMINAL_RESPONSE_MAGIC: [u8; 8] = *b"OPCRPU1\0";
const ADMISSION_REQUEST_V2_MAGIC: [u8; 8] = *b"OPCRPA2\0";
const ADMISSION_RESPONSE_V2_MAGIC: [u8; 8] = *b"OPCRPS2\0";
const TERMINAL_REQUEST_V2_MAGIC: [u8; 8] = *b"OPCRPT2\0";
const TERMINAL_RESPONSE_V2_MAGIC: [u8; 8] = *b"OPCRPU2\0";
const ADMISSION_REQUEST_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/admission-port/request/v1\0";
const ADMISSION_RESPONSE_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/admission-port/response/v1\0";
const TERMINAL_REQUEST_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/terminal-port/request/v1\0";
const TERMINAL_RESPONSE_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/terminal-port/response/v1\0";
const ADMISSION_REQUEST_V2_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/admission-port/profile-v2/request/v1\0";
const ADMISSION_RESPONSE_V2_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/admission-port/profile-v2/response/v1\0";
const TERMINAL_REQUEST_V2_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/terminal-port/profile-v2/request/v1\0";
const TERMINAL_RESPONSE_V2_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/terminal-port/profile-v2/response/v1\0";
const REQUEST_ID_DOMAIN: &[u8] = b"openpacketcore/protected-roster/consumer-request/v1\0";

/// Reserved deterministic envelope allowance around canonical roster bodies.
pub const MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES: usize = 512;
/// Maximum admission-family capsule, including a terminal recovery reply.
pub const MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES: usize = MAX_ADMISSION_CODEC_BYTES
    + MAX_COMMITTED_TERMINAL_CODEC_BYTES
    + MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES
    + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;
/// Maximum terminal-family capsule, including the committed terminal reply.
pub const MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES: usize = MAX_COMMITTED_TERMINAL_CODEC_BYTES
    + MAX_EXECUTOR_PROOF_BUNDLE_BYTES
    + MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES
    + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;
/// Maximum `/4` terminal inner capsule.  It contains only V2 compact
/// provenance plus generic compact Executor evidence; the voter appends its
/// fresh V2 ingress when constructing retained evidence.
pub const MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES: usize = MAX_COMMITTED_TERMINAL_CODEC_BYTES
    + MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES
    + MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES
    + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;

const _: () = assert!(MAX_TOMBSTONE_CODEC_BYTES == 256);

/// Fixed redaction-safe refusal from consumed revision-five composition.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("protected roster transport unavailable")]
pub struct ProtectedRosterTransportError;

impl fmt::Debug for ProtectedRosterTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedRosterTransportError(<redacted>)")
    }
}

/// Fixed numeric, nonidentifying diagnostics for one consumed roster adapter.
///
/// The pool and roster snapshots share the same startup-owned persistent
/// consumer pool. Taking this snapshot performs no remote I/O and retains no
/// caller, tenant, scope, roster, member, or provider identifiers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FencedMutationRosterProviderAdapterDiagnostics {
    pub roster: FencedMutationRosterDiagnostics,
    pub pool: PersistentSessionConsumerDiagnostics,
}

/// Startup-fixed member and publication providers backed by one consumed pool.
pub struct FencedMutationRosterProviderAdapter<Q> {
    client: FencedMutationRosterClient,
    publication: PublicationAdapter<Q, RosterQuorumPort>,
    diagnostics: RosterDiagnostics,
    pool_diagnostics: PersistentSessionConsumerClient,
}

impl<Q> Clone for FencedMutationRosterProviderAdapter<Q> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            publication: self.publication.clone(),
            diagnostics: self.diagnostics.clone(),
            pool_diagnostics: self.pool_diagnostics.clone(),
        }
    }
}

impl<Q> fmt::Debug for FencedMutationRosterProviderAdapter<Q> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedMutationRosterProviderAdapter(<redacted>)")
    }
}

impl<Q> FencedMutationRosterProviderAdapter<Q>
where
    Q: EstablishedPublicationProvider,
{
    /// Borrow the shared roster client fixed at startup with this adapter.
    pub fn client(&self) -> &FencedMutationRosterClient {
        &self.client
    }

    /// Return the shared numeric diagnostics for this startup-owned adapter.
    pub fn diagnostics(&self) -> FencedMutationRosterDiagnostics {
        self.diagnostics.snapshot()
    }

    /// Return one fixed, redaction-safe roster and persistent-pool snapshot.
    ///
    /// The retained pool observer is an ordinary shared clone. It creates no
    /// connection, executor, task, channel, or second roster authority.
    pub fn diagnostics_with_pool(&self) -> FencedMutationRosterProviderAdapterDiagnostics {
        FencedMutationRosterProviderAdapterDiagnostics {
            roster: self.diagnostics(),
            pool: self.pool_diagnostics.diagnostics_without_io(),
        }
    }

    /// Publish an exact SDK-issued established publication locally.
    pub async fn publish(
        &self,
        publication: &mut super::client::EstablishedPublication,
    ) -> Result<super::canonical::PublicationEvidence, super::publication::PublicationAdapterError>
    {
        self.publication.publish(publication).await
    }

    /// Publish a directly terminalized Established capsule through the
    /// provider's one-call durable fresh-publication primitive.
    ///
    /// A provider that has not opted into
    /// [`EstablishedPublicationProvider::publish_fresh_established`] fails
    /// closed. Recovered and status-derived capsules are automatically
    /// restricted to status/adopt; this method never grants them execution
    /// authority.
    pub async fn publish_fresh_established(
        &self,
        publication: &mut super::client::EstablishedPublication,
    ) -> Result<super::canonical::PublicationEvidence, super::publication::PublicationAdapterError>
    {
        self.publication
            .publish_fresh_established(publication)
            .await
    }
}

pub(crate) fn compose_client<P>(
    consumer: AuthenticatedRosterConsumer,
    provider: Arc<P>,
    attestor: Arc<dyn FencedMutationRosterExecutorAttestor>,
    max_in_flight: NonZeroUsize,
) -> Result<FencedMutationRosterClient, ProtectedRosterTransportError>
where
    P: MemberProvider,
{
    let port = Arc::new(RosterQuorumPort::new(consumer)?);
    Ok(FencedMutationRosterClient::new(
        RosterExecutor::new(provider, port.clone(), attestor, max_in_flight),
        port.scope,
    ))
}

pub(crate) fn compose_client_v2<P>(
    consumer: AuthenticatedRosterConsumer,
    provider: Arc<P>,
    attestor: Arc<dyn FencedMutationRosterExecutorAttestor>,
    max_in_flight: NonZeroUsize,
) -> Result<FencedMutationRosterClient, ProtectedRosterTransportError>
where
    P: MemberProvider,
{
    let port = Arc::new(RosterQuorumPort::new_v2(consumer)?);
    Ok(FencedMutationRosterClient::new_v2(
        RosterExecutor::new_v2(provider, port.clone(), attestor, max_in_flight),
        port.scope,
    ))
}

pub(crate) fn compose_provider_adapter<P, Q>(
    consumer: AuthenticatedRosterConsumer,
    member_provider: Arc<P>,
    publication_provider: Arc<Q>,
    attestor: Arc<dyn FencedMutationRosterExecutorAttestor>,
    max_in_flight: NonZeroUsize,
) -> Result<FencedMutationRosterProviderAdapter<Q>, ProtectedRosterTransportError>
where
    P: MemberProvider,
    Q: EstablishedPublicationProvider,
{
    let pool_diagnostics = consumer.diagnostics_observer();
    let port = Arc::new(RosterQuorumPort::new(consumer)?);
    let executor = RosterExecutor::new(member_provider, port.clone(), attestor, max_in_flight);
    let publication = executor.publication_adapter(publication_provider);
    let client = FencedMutationRosterClient::new(executor, port.scope);
    let diagnostics = client.diagnostics_handle();
    Ok(FencedMutationRosterProviderAdapter {
        client,
        publication,
        diagnostics,
        pool_diagnostics,
    })
}

pub(crate) fn compose_provider_adapter_v2<P, Q>(
    consumer: AuthenticatedRosterConsumer,
    member_provider: Arc<P>,
    publication_provider: Arc<Q>,
    attestor: Arc<dyn FencedMutationRosterExecutorAttestor>,
    max_in_flight: NonZeroUsize,
) -> Result<FencedMutationRosterProviderAdapter<Q>, ProtectedRosterTransportError>
where
    P: MemberProvider,
    Q: EstablishedPublicationProvider,
{
    let pool_diagnostics = consumer.diagnostics_observer();
    let port = Arc::new(RosterQuorumPort::new_v2(consumer)?);
    let executor = RosterExecutor::new_v2(member_provider, port.clone(), attestor, max_in_flight);
    let publication = executor.publication_adapter(publication_provider);
    let client = FencedMutationRosterClient::new_v2(executor, port.scope);
    let diagnostics = client.diagnostics_handle();
    Ok(FencedMutationRosterProviderAdapter {
        client,
        publication,
        diagnostics,
        pool_diagnostics,
    })
}

fn protected_roster_scope_from_consumer_scope(scope: SessionConsumerScope) -> Scope {
    protected_roster_scope_from_consensus_identity(scope.consensus_identity())
}

#[derive(Clone)]
pub(crate) struct RosterQuorumPort {
    consumer: AuthenticatedRosterConsumer,
    scope: Scope,
    configuration_identity: SessionConsensusIdentity,
    roster_attestation_root_identity: RosterAttestationTrustRootIdentityV1,
    profile: Profile,
}

impl RosterQuorumPort {
    fn new(consumer: AuthenticatedRosterConsumer) -> Result<Self, ProtectedRosterTransportError> {
        Self::new_for_profile(consumer, Profile::v1())
    }

    fn new_v2(
        consumer: AuthenticatedRosterConsumer,
    ) -> Result<Self, ProtectedRosterTransportError> {
        Self::new_for_profile(consumer, Profile::v2())
    }

    fn new_for_profile(
        consumer: AuthenticatedRosterConsumer,
        profile: Profile,
    ) -> Result<Self, ProtectedRosterTransportError> {
        let roster_attestation_root_identity = consumer
            .roster_attestation_root_identity()
            .ok_or(ProtectedRosterTransportError)?;
        consumer.claim_roster_executor()?;
        let scope = protected_roster_scope_from_consumer_scope(consumer.scope());
        let configuration_identity = consumer.scope().consensus_identity();
        Ok(Self {
            consumer,
            scope,
            configuration_identity,
            roster_attestation_root_identity,
            profile,
        })
    }

    async fn poll_admit(
        &self,
        request_id: SessionConsumerRequestId,
        capsule: SessionConsumerRosterAdmissionCapsule,
    ) -> Result<SessionConsumerRosterAdmissionMutationResponse, ProtectedRosterTransportError> {
        self.consumer.poll_admit(request_id, capsule).await
    }

    async fn admission_status(
        &self,
        request_id: SessionConsumerRequestId,
        capsule: SessionConsumerRosterAdmissionCapsule,
    ) -> Result<SessionConsumerRosterAdmissionReadResponse, ProtectedRosterTransportError> {
        self.consumer.admission_status(request_id, capsule).await
    }

    async fn recover(
        &self,
        request_id: SessionConsumerRequestId,
        capsule: SessionConsumerRosterAdmissionCapsule,
    ) -> Result<SessionConsumerRosterAdmissionReadResponse, ProtectedRosterTransportError> {
        self.consumer.recover(request_id, capsule).await
    }

    async fn terminalize(
        &self,
        request_id: SessionConsumerRequestId,
        capsule: SessionConsumerRosterTerminalCapsule,
    ) -> Result<SessionConsumerRosterTerminalMutationResponse, ProtectedRosterTransportError> {
        self.consumer.terminalize(request_id, capsule).await
    }

    async fn terminal_status(
        &self,
        request_id: SessionConsumerRequestId,
        capsule: SessionConsumerRosterTerminalCapsule,
    ) -> Result<SessionConsumerRosterTerminalReadResponse, ProtectedRosterTransportError> {
        self.consumer.terminal_status(request_id, capsule).await
    }

    async fn current_publication_authority(
        &self,
        request_id: SessionConsumerRequestId,
        capsule: SessionConsumerRosterCurrentPublicationAuthorityCapsule,
    ) -> Result<
        SessionConsumerRosterCurrentPublicationAuthorityReadResponse,
        ProtectedRosterTransportError,
    > {
        self.consumer
            .current_publication_authority(request_id, capsule)
            .await
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AdapterError;

impl fmt::Debug for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdapterError(<redacted>)")
    }
}

#[async_trait::async_trait]
impl RosterExecutorBackend for RosterQuorumPort {
    type Error = AdapterError;

    fn expected_roster_attestation_trust_root_identity(
        &self,
    ) -> Option<RosterAttestationTrustRootIdentityV1> {
        Some(self.roster_attestation_root_identity)
    }

    fn current_roster_configuration_identity(&self) -> Option<SessionConsensusIdentity> {
        Some(self.configuration_identity)
    }

    async fn register(
        &self,
        request: &RegistrationRequest,
    ) -> Result<RegistrationDecision, Self::Error> {
        if request.admission().profile() != self.profile {
            return Err(AdapterError);
        }
        let capsule =
            admission_capsule_for_registration(request, self.profile).map_err(|_| AdapterError)?;
        let response = self
            .poll_admit(admission_mutation_request_id(request.admission()), capsule)
            .await
            .map_err(|_| AdapterError)?;
        match response {
            SessionConsumerRosterAdmissionMutationResponse::Recorded(capsule) => {
                decode_admission_response_for_profile(
                    capsule.canonical_bytes(),
                    self.scope,
                    Some(request.admission()),
                    self.profile,
                )
                .map_err(|_| AdapterError)
            }
            SessionConsumerRosterAdmissionMutationResponse::NotTransmitted => {
                Ok(RegistrationDecision::NotTransmitted)
            }
            SessionConsumerRosterAdmissionMutationResponse::OutcomeUnknown => Err(AdapterError),
            SessionConsumerRosterAdmissionMutationResponse::Rejected(rejection) => {
                Ok(RegistrationDecision::Reject(rejection.into()))
            }
            _ => Err(AdapterError),
        }
    }

    async fn admission_status(
        &self,
        request: AdmissionStatusRequest<'_>,
    ) -> Result<RegistrationDecision, Self::Error> {
        let registration = request.registration();
        if registration.admission().profile() != self.profile {
            return Err(AdapterError);
        }
        let capsule = admission_capsule_for_registration(registration, self.profile)
            .map_err(|_| AdapterError)?;
        let response = self
            .admission_status(
                admission_mutation_request_id(registration.admission()),
                capsule,
            )
            .await
            .map_err(|_| AdapterError)?;
        decode_admission_read_response(
            response,
            self.scope,
            Some(registration.admission()),
            self.profile,
        )
    }

    async fn recover(
        &self,
        request: &RecoveryRequest,
    ) -> Result<RegistrationDecision, Self::Error> {
        let capsule =
            admission_capsule_for_recovery(request, self.profile).map_err(|_| AdapterError)?;
        let response = self
            .recover(
                recovery_request_id(
                    AdmissionRequestKind::Recover,
                    request.lookup().scope(),
                    request.lookup().roster_id(),
                ),
                capsule,
            )
            .await
            .map_err(|_| AdapterError)?;
        decode_admission_read_response(response, self.scope, None, self.profile)
    }

    async fn terminal_status(
        &self,
        request: TerminalStatusRequest<'_>,
    ) -> Result<TerminalStatusDecision, Self::Error> {
        let capsule =
            terminal_capsule_for_profile(&request, self.profile).map_err(|_| AdapterError)?;
        let response = self
            .terminal_status(terminal_mutation_request_id(request.admission()), capsule)
            .await
            .map_err(|_| AdapterError)?;
        decode_terminal_read_response(response, self.scope, request.admission(), self.profile)
    }

    async fn terminalize(
        &self,
        request: TerminalizeRequest<'_>,
    ) -> Result<TerminalizeDecision, Self::Error> {
        let capsule =
            terminal_capsule_for_profile(&request, self.profile).map_err(|_| AdapterError)?;
        let response = self
            .terminalize(terminal_mutation_request_id(request.admission()), capsule)
            .await
            .map_err(|_| AdapterError)?;
        match response {
            SessionConsumerRosterTerminalMutationResponse::Recorded(capsule) => {
                decode_terminal_mutation_response_for_profile(
                    capsule.canonical_bytes(),
                    self.scope,
                    request.admission(),
                    self.profile,
                )
                .map_err(|_| AdapterError)
            }
            SessionConsumerRosterTerminalMutationResponse::NotTransmitted => {
                Ok(TerminalizeDecision::NotTransmitted)
            }
            SessionConsumerRosterTerminalMutationResponse::OutcomeUnknown => Err(AdapterError),
            SessionConsumerRosterTerminalMutationResponse::Rejected(rejection) => {
                Ok(TerminalizeDecision::Reject(rejection.into()))
            }
            _ => Err(AdapterError),
        }
    }
}

#[async_trait::async_trait]
impl PublicationAuthorityReader for RosterQuorumPort {
    type Error = AdapterError;

    async fn read_current_publication_authority(
        &self,
        request: CurrentPublicationAuthorityRead<'_>,
    ) -> Result<(), Self::Error> {
        let authority = request.current_authority();
        if authority.ingress_scope() != self.scope {
            return Err(AdapterError);
        }
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            request.current_registration().consensus_parts();
        let capsule = SessionConsumerRosterCurrentPublicationAuthorityCapsule::new(
            authority.ingress_scope().digest(),
            authority.key().clone(),
            *request.roster_id().as_bytes(),
            request.admission_commitment(),
            request.terminal_body_commitment(),
            request.receipt_commitment(),
            request.logical_owner().clone(),
            request.admission_fence(),
            registration_handle,
            registration_request_id.to_bytes(),
            *registration_terminal_slot.as_bytes(),
            authority.owner().clone(),
            request.current_fence(),
            authority.credential_id(),
            authority.generation(),
            request.current_lease_acquired_at(),
            request.current_lease_expires_at(),
        )
        .map_err(|_| AdapterError)?;
        match self
            .current_publication_authority(
                recovery_request_id(
                    AdmissionRequestKind::CurrentPublicationAuthority,
                    authority.ingress_scope(),
                    request.roster_id(),
                ),
                capsule,
            )
            .await
            .map_err(|_| AdapterError)?
        {
            SessionConsumerRosterCurrentPublicationAuthorityReadResponse::Current => Ok(()),
            SessionConsumerRosterCurrentPublicationAuthorityReadResponse::Rejected => {
                Err(AdapterError)
            }
            _ => Err(AdapterError),
        }
    }
}

impl From<SessionConsumerRosterRejection> for BackendRejection {
    fn from(value: SessionConsumerRosterRejection) -> Self {
        match value {
            SessionConsumerRosterRejection::Authority => Self::Authority,
            SessionConsumerRosterRejection::RecoveryRequired => Self::RecoveryRequired,
            SessionConsumerRosterRejection::RecordMissing => Self::RecordMissing,
            SessionConsumerRosterRejection::GenerationConflict => Self::GenerationConflict,
            SessionConsumerRosterRejection::GenerationExhausted => Self::GenerationExhausted,
            SessionConsumerRosterRejection::BusinessKeyReserved => Self::BusinessKeyReserved,
            SessionConsumerRosterRejection::InvalidProtectedCheckpoint => {
                Self::InvalidProtectedCheckpoint
            }
            SessionConsumerRosterRejection::AggregateBytesFull => Self::AggregateBytesFull,
            SessionConsumerRosterRejection::LiveFull => Self::LiveFull,
            SessionConsumerRosterRejection::HistoryFull => Self::HistoryFull,
            SessionConsumerRosterRejection::RecordAlreadyExists => Self::RecordAlreadyExists,
            SessionConsumerRosterRejection::Malformed
            | SessionConsumerRosterRejection::Capability
            | SessionConsumerRosterRejection::Conflict => Self::TerminalConflict,
            SessionConsumerRosterRejection::Unavailable => Self::Unavailable,
            _ => Self::TerminalConflict,
        }
    }
}

#[derive(Clone, Copy)]
enum AdmissionRequestKind {
    PollAdmit = 1,
    Recover = 3,
    Terminalize = 4,
    CurrentPublicationAuthority = 6,
}

fn admission_mutation_request_id(admission: &Admission) -> SessionConsumerRequestId {
    recovery_request_id(
        AdmissionRequestKind::PollAdmit,
        admission.scope(),
        admission.roster_id(),
    )
}

fn terminal_mutation_request_id(admission: &Admission) -> SessionConsumerRequestId {
    recovery_request_id(
        AdmissionRequestKind::Terminalize,
        admission.scope(),
        admission.roster_id(),
    )
}

fn recovery_request_id(
    kind: AdmissionRequestKind,
    scope: Scope,
    roster_id: RosterId,
) -> SessionConsumerRequestId {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_ID_DOMAIN);
    hasher.update([kind as u8]);
    hasher.update(scope.digest());
    hasher.update(roster_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    if request_id == [0; 16] {
        request_id[0] = 1;
    }
    SessionConsumerRequestId::from_bytes(request_id)
}

#[derive(Clone, Serialize, Deserialize)]
struct AuthorityWire {
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    credential_id: u64,
    generation: Generation,
    acquired_at: Timestamp,
    expires_at: Timestamp,
}

impl From<&AuthorityBinding> for AuthorityWire {
    fn from(value: &AuthorityBinding) -> Self {
        Self {
            key: value.key().clone(),
            owner: value.owner().clone(),
            fence: value.fence(),
            credential_id: value.credential_id(),
            generation: value.generation(),
            acquired_at: value.acquired_at(),
            expires_at: value.expires_at(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RegistrationWire {
    handle: [u8; 32],
    request_id: RequestId,
    terminal_slot: [u8; 32],
}

impl RegistrationWire {
    fn from_registration(registration: BackendRegistration) -> Self {
        let (handle, request_id, terminal_slot) = registration.consensus_parts();
        Self {
            handle,
            request_id,
            terminal_slot: *terminal_slot.as_bytes(),
        }
    }

    fn into_registration(self, admission: &Admission) -> Result<BackendRegistration, ()> {
        let registration =
            BackendRegistration::from_consensus_parts(self.handle, self.request_id, admission)
                .map_err(|_| ())?;
        (registration.consensus_parts().2.as_bytes() == &self.terminal_slot)
            .then_some(registration)
            .ok_or(())
    }
}

#[derive(Serialize, Deserialize)]
enum AdmissionRequestWire {
    Register {
        scope: [u8; 32],
        admission: Vec<u8>,
        authority: AuthorityWire,
    },
    Recover {
        scope: [u8; 32],
        roster_id: RosterId,
        original_owner: OwnerId,
        original_admission_fence: FenceToken,
        authority: AuthorityWire,
    },
}

#[derive(Serialize, Deserialize)]
enum AdmissionResponseWire {
    Fresh {
        scope: [u8; 32],
        registration: RegistrationWire,
        admission_provenance: Vec<u8>,
    },
    Replayed {
        scope: [u8; 32],
    },
    PollAdmitted {
        scope: [u8; 32],
        registration: RegistrationWire,
        admission: Vec<u8>,
        admission_provenance: Vec<u8>,
    },
    Terminal {
        scope: [u8; 32],
        registration: RegistrationWire,
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
        rejection: SessionConsumerRosterRejection,
    },
}

#[derive(Serialize, Deserialize)]
struct TerminalRequestWire {
    scope: [u8; 32],
    binding: RequestBindingKey,
    registration: RegistrationWire,
    authority: AuthorityWire,
    record: Vec<u8>,
    proof_bundle: Vec<u8>,
    terminal_evidence: Vec<u8>,
}

/// `/4` terminal request.  This is a separately framed inner carrier: it
/// contains V2 admission provenance and generic Executor evidence, but never
/// a V1 bundle or a client-minted TransportIngress attestation.
#[derive(Serialize, Deserialize)]
struct TerminalRequestWireV2 {
    scope: [u8; 32],
    binding: RequestBindingKey,
    registration: RegistrationWire,
    authority: AuthorityWire,
    record: Vec<u8>,
    admission_provenance: Vec<u8>,
    terminal_evidence: Vec<u8>,
}

/// `/4` admission response.  It cannot deserialize the frozen `/3`
/// response because both the frame domain and the provenance carrier differ.
#[derive(Serialize, Deserialize)]
enum AdmissionResponseWireV2 {
    Fresh {
        scope: [u8; 32],
        registration: RegistrationWire,
        admission_provenance: Vec<u8>,
    },
    Replayed {
        scope: [u8; 32],
    },
    PollAdmitted {
        scope: [u8; 32],
        registration: RegistrationWire,
        admission: Vec<u8>,
        admission_provenance: Vec<u8>,
    },
    Terminal {
        scope: [u8; 32],
        registration: RegistrationWire,
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
        rejection: SessionConsumerRosterRejection,
    },
}

#[derive(Serialize, Deserialize)]
enum TerminalResponseWire {
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

/// Disjoint `/4` terminal response envelope. It deliberately mirrors only
/// application decisions; its independent Postcard enum and frame are the
/// fail-closed profile boundary for terminal mutation and status replies.
#[derive(Serialize, Deserialize)]
enum TerminalResponseWireV2 {
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

fn admission_capsule_for_registration(
    request: &RegistrationRequest,
    profile: Profile,
) -> Result<SessionConsumerRosterAdmissionCapsule, ()> {
    let wire = AdmissionRequestWire::Register {
        scope: request.authority().ingress_scope().digest(),
        admission: request.admission().to_canonical_bytes().map_err(|_| ())?,
        authority: request.authority().into(),
    };
    let canonical = if profile == Profile::v1() {
        encode_admission_request(&wire)?
    } else if profile == Profile::v2() {
        encode_admission_request_v2(&wire)?
    } else {
        return Err(());
    };
    SessionConsumerRosterAdmissionCapsule::new(canonical).map_err(|_| ())
}

fn admission_capsule_for_recovery(
    request: &RecoveryRequest,
    profile: Profile,
) -> Result<SessionConsumerRosterAdmissionCapsule, ()> {
    let wire = AdmissionRequestWire::Recover {
        scope: request.lookup().scope().digest(),
        roster_id: request.lookup().roster_id(),
        original_owner: request.original_owner().clone(),
        original_admission_fence: request.original_admission_fence(),
        authority: request.authority().into(),
    };
    let canonical = if profile == Profile::v1() {
        encode_admission_request(&wire)?
    } else if profile == Profile::v2() {
        encode_admission_request_v2(&wire)?
    } else {
        return Err(());
    };
    SessionConsumerRosterAdmissionCapsule::new(canonical).map_err(|_| ())
}

fn terminal_capsule(
    registration: BackendRegistration,
    authority: &AuthorityBinding,
    body: &TerminalBody,
    admission: &Admission,
) -> Result<SessionConsumerRosterTerminalCapsule, ()> {
    let (_, request_id, _) = registration.consensus_parts();
    let wire = TerminalRequestWire {
        scope: authority.ingress_scope().digest(),
        binding: admission
            .binding_key(request_id.history_epoch())
            .map_err(|_| ())?,
        registration: RegistrationWire::from_registration(registration),
        authority: authority.into(),
        record: body
            .record()
            .to_canonical_bytes(admission)
            .map_err(|_| ())?,
        proof_bundle: body
            .bundle()
            .map_err(|_| ())?
            .canonical_bytes()
            .map_err(|_| ())?,
        terminal_evidence: body
            .compact_evidence()
            .map_err(|_| ())?
            .canonical_bytes()
            .map_err(|_| ())?,
    };
    SessionConsumerRosterTerminalCapsule::new(encode_terminal_request(&wire)?).map_err(|_| ())
}

trait TerminalRequestView {
    fn registration(&self) -> BackendRegistration;
    fn authority(&self) -> &AuthorityBinding;
    fn body(&self) -> &TerminalBody;
    fn admission(&self) -> &Admission;
    fn admission_provenance(&self) -> Option<&RegistrationAdmissionProvenance>;
}

impl TerminalRequestView for TerminalStatusRequest<'_> {
    fn registration(&self) -> BackendRegistration {
        self.registration()
    }
    fn authority(&self) -> &AuthorityBinding {
        self.authority()
    }
    fn body(&self) -> &TerminalBody {
        self.body()
    }
    fn admission(&self) -> &Admission {
        self.admission()
    }
    fn admission_provenance(&self) -> Option<&RegistrationAdmissionProvenance> {
        self.admission_provenance()
    }
}

impl TerminalRequestView for TerminalizeRequest<'_> {
    fn registration(&self) -> BackendRegistration {
        self.registration()
    }
    fn authority(&self) -> &AuthorityBinding {
        self.authority()
    }
    fn body(&self) -> &TerminalBody {
        self.body()
    }
    fn admission(&self) -> &Admission {
        self.admission()
    }
    fn admission_provenance(&self) -> Option<&RegistrationAdmissionProvenance> {
        self.admission_provenance()
    }
}

fn terminal_capsule_for_profile(
    request: &impl TerminalRequestView,
    profile: Profile,
) -> Result<SessionConsumerRosterTerminalCapsule, ()> {
    match (profile, request.admission_provenance()) {
        (profile, _) if profile == Profile::v1() => terminal_capsule(
            request.registration(),
            request.authority(),
            request.body(),
            request.admission(),
        ),
        (profile, Some(RegistrationAdmissionProvenance::V2(provenance)))
            if profile == Profile::v2() =>
        {
            terminal_capsule_v2(
                request.registration(),
                request.authority(),
                request.body(),
                request.admission(),
                provenance,
            )
        }
        _ => Err(()),
    }
}

fn terminal_capsule_v2(
    registration: BackendRegistration,
    authority: &AuthorityBinding,
    body: &TerminalBody,
    admission: &Admission,
    admission_provenance: &RosterProfileV2CompactAdmissionProvenanceV1,
) -> Result<SessionConsumerRosterTerminalCapsule, ()> {
    if admission.profile() != Profile::v2() {
        return Err(());
    }
    let (_, request_id, _) = registration.consensus_parts();
    let wire = TerminalRequestWireV2 {
        scope: authority.ingress_scope().digest(),
        binding: admission
            .binding_key(request_id.history_epoch())
            .map_err(|_| ())?,
        registration: RegistrationWire::from_registration(registration),
        authority: authority.into(),
        record: body
            .record()
            .to_canonical_bytes(admission)
            .map_err(|_| ())?,
        admission_provenance: admission_provenance.canonical_bytes().map_err(|_| ())?,
        terminal_evidence: body
            .compact_evidence_v2()
            .map_err(|_| ())?
            .canonical_bytes()
            .map_err(|_| ())?,
    };
    SessionConsumerRosterTerminalCapsule::new(encode_terminal_request_v2(&wire)?).map_err(|_| ())
}

fn decode_admission_read_response(
    response: SessionConsumerRosterAdmissionReadResponse,
    scope: Scope,
    original_admission: Option<&Admission>,
    profile: Profile,
) -> Result<RegistrationDecision, AdapterError> {
    match response {
        SessionConsumerRosterAdmissionReadResponse::Recorded(capsule) => {
            decode_admission_response_for_profile(
                capsule.canonical_bytes(),
                scope,
                original_admission,
                profile,
            )
            .map_err(|_| AdapterError)
        }
        SessionConsumerRosterAdmissionReadResponse::Rejected(rejection) => {
            Ok(RegistrationDecision::Reject(rejection.into()))
        }
        _ => Err(AdapterError),
    }
}

fn decode_admission_response_for_profile(
    bytes: &[u8],
    scope: Scope,
    original_admission: Option<&Admission>,
    profile: Profile,
) -> Result<RegistrationDecision, ()> {
    if profile == Profile::v1() {
        decode_admission_response(bytes, scope, original_admission)
    } else if profile == Profile::v2() {
        decode_admission_response_v2(bytes, scope, original_admission)
    } else {
        Err(())
    }
}

fn decode_terminal_read_response(
    response: SessionConsumerRosterTerminalReadResponse,
    scope: Scope,
    admission: &Admission,
    profile: Profile,
) -> Result<TerminalStatusDecision, AdapterError> {
    match response {
        SessionConsumerRosterTerminalReadResponse::Recorded(capsule) => {
            decode_terminal_status_response_for_profile(
                capsule.canonical_bytes(),
                scope,
                admission,
                profile,
            )
            .map_err(|_| AdapterError)
        }
        SessionConsumerRosterTerminalReadResponse::Rejected(rejection) => {
            Ok(TerminalStatusDecision::Reject(rejection.into()))
        }
        _ => Err(AdapterError),
    }
}

fn encode_admission_request(wire: &AdmissionRequestWire) -> Result<Vec<u8>, ()> {
    encode_frame(
        ADMISSION_REQUEST_MAGIC,
        ADMISSION_REQUEST_DOMAIN,
        wire,
        MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    )
    .map_err(|_| ())
}

fn encode_terminal_request(wire: &TerminalRequestWire) -> Result<Vec<u8>, ()> {
    encode_frame(
        TERMINAL_REQUEST_MAGIC,
        TERMINAL_REQUEST_DOMAIN,
        wire,
        MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ())
}

fn encode_admission_request_v2(wire: &AdmissionRequestWire) -> Result<Vec<u8>, ()> {
    encode_frame(
        ADMISSION_REQUEST_V2_MAGIC,
        ADMISSION_REQUEST_V2_DOMAIN,
        wire,
        MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    )
    .map_err(|_| ())
}

fn encode_terminal_request_v2(wire: &TerminalRequestWireV2) -> Result<Vec<u8>, ()> {
    encode_frame(
        TERMINAL_REQUEST_V2_MAGIC,
        TERMINAL_REQUEST_V2_DOMAIN,
        wire,
        MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ())
}

fn decode_admission_response(
    bytes: &[u8],
    scope: Scope,
    original_admission: Option<&Admission>,
) -> Result<RegistrationDecision, ()> {
    let wire: AdmissionResponseWire = decode_frame(
        bytes,
        ADMISSION_RESPONSE_MAGIC,
        ADMISSION_RESPONSE_DOMAIN,
        MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    )
    .map_err(|_| ())?;
    if encode_admission_response(&wire)? != bytes {
        return Err(());
    }
    match wire {
        AdmissionResponseWire::Fresh {
            scope: actual,
            registration,
            admission_provenance,
        } => {
            let admission = original_admission.ok_or(())?;
            expect_scope(actual, scope)?;
            let provenance =
                RosterCompactAdmissionProvenanceV2::decode_canonical(&admission_provenance)
                    .map_err(|_| ())?;
            Ok(RegistrationDecision::FreshlyAdmittedWithProvenance(
                registration.into_registration(admission)?,
                RegistrationAdmissionProvenance::V1(provenance),
            ))
        }
        AdmissionResponseWire::Replayed { scope: actual } => {
            expect_scope(actual, scope)?;
            Ok(RegistrationDecision::AdmissionReplayed)
        }
        AdmissionResponseWire::PollAdmitted {
            scope: actual,
            registration,
            admission,
            admission_provenance,
        } => {
            expect_scope(actual, scope)?;
            let admission = decode_admission(&admission, original_admission)?;
            let provenance =
                RosterCompactAdmissionProvenanceV2::decode_canonical(&admission_provenance)
                    .map_err(|_| ())?;
            Ok(RegistrationDecision::PollAdmittedWithProvenance {
                registration: registration.into_registration(&admission)?,
                admission: Arc::new(admission),
                admission_provenance: RegistrationAdmissionProvenance::V1(provenance),
            })
        }
        AdmissionResponseWire::Terminal {
            scope: actual,
            registration,
            admission,
            committed,
            admission_provenance,
        } => {
            expect_scope(actual, scope)?;
            let admission = decode_admission(&admission, original_admission)?;
            RosterCompactAdmissionProvenanceV2::decode_canonical(&admission_provenance)
                .map_err(|_| ())?;
            let registration = registration.into_registration(&admission)?;
            let committed =
                CommittedTerminal::from_canonical_bytes(&committed, &admission).map_err(|_| ())?;
            Ok(RegistrationDecision::Terminal {
                registration,
                admission: Arc::new(admission),
                committed: Box::new(committed),
            })
        }
        AdmissionResponseWire::Compacted {
            scope: actual,
            history_epoch,
            tombstone,
        } => {
            expect_scope(actual, scope)?;
            if history_epoch == 0 {
                return Err(());
            }
            Ok(RegistrationDecision::Compacted {
                history_epoch,
                tombstone: ProfiledTerminalConflictTombstone::V1(
                    TerminalConflictTombstone::from_canonical_bytes(&tombstone).map_err(|_| ())?,
                ),
            })
        }
        AdmissionResponseWire::Reject {
            scope: actual,
            rejection,
        } => {
            expect_scope(actual, scope)?;
            Ok(RegistrationDecision::Reject(rejection.into()))
        }
    }
}

fn decode_admission_response_v2(
    bytes: &[u8],
    scope: Scope,
    original_admission: Option<&Admission>,
) -> Result<RegistrationDecision, ()> {
    let wire: AdmissionResponseWireV2 = decode_frame(
        bytes,
        ADMISSION_RESPONSE_V2_MAGIC,
        ADMISSION_RESPONSE_V2_DOMAIN,
        MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    )
    .map_err(|_| ())?;
    if encode_frame(
        ADMISSION_RESPONSE_V2_MAGIC,
        ADMISSION_RESPONSE_V2_DOMAIN,
        &wire,
        MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    )
    .map_err(|_| ())?
        != bytes
    {
        return Err(());
    }
    match wire {
        AdmissionResponseWireV2::Fresh {
            scope: actual,
            registration,
            admission_provenance,
        } => {
            let admission = original_admission.ok_or(())?;
            if admission.profile() != Profile::v2() {
                return Err(());
            }
            expect_scope(actual, scope)?;
            let provenance = RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(
                &admission_provenance,
            )
            .map_err(|_| ())?;
            Ok(RegistrationDecision::FreshlyAdmittedWithProvenance(
                registration.into_registration(admission)?,
                RegistrationAdmissionProvenance::V2(provenance),
            ))
        }
        AdmissionResponseWireV2::Replayed { scope: actual } => {
            expect_scope(actual, scope)?;
            Ok(RegistrationDecision::AdmissionReplayed)
        }
        AdmissionResponseWireV2::PollAdmitted {
            scope: actual,
            registration,
            admission,
            admission_provenance,
        } => {
            expect_scope(actual, scope)?;
            let admission = decode_admission(&admission, original_admission)?;
            if admission.profile() != Profile::v2() {
                return Err(());
            }
            let provenance = RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(
                &admission_provenance,
            )
            .map_err(|_| ())?;
            Ok(RegistrationDecision::PollAdmittedWithProvenance {
                registration: registration.into_registration(&admission)?,
                admission: Arc::new(admission),
                admission_provenance: RegistrationAdmissionProvenance::V2(provenance),
            })
        }
        AdmissionResponseWireV2::Terminal {
            scope: actual,
            registration,
            admission,
            committed,
            admission_provenance,
        } => {
            expect_scope(actual, scope)?;
            let admission = decode_admission(&admission, original_admission)?;
            if admission.profile() != Profile::v2() {
                return Err(());
            }
            RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(&admission_provenance)
                .map_err(|_| ())?;
            let registration = registration.into_registration(&admission)?;
            let committed =
                CommittedTerminal::from_canonical_bytes(&committed, &admission).map_err(|_| ())?;
            Ok(RegistrationDecision::Terminal {
                registration,
                admission: Arc::new(admission),
                committed: Box::new(committed),
            })
        }
        AdmissionResponseWireV2::Compacted {
            scope: actual,
            history_epoch,
            tombstone,
        } => {
            expect_scope(actual, scope)?;
            if history_epoch == 0 {
                return Err(());
            }
            Ok(RegistrationDecision::Compacted {
                history_epoch,
                tombstone: ProfiledTerminalConflictTombstone::V2(
                    TerminalConflictTombstone::from_canonical_bytes(&tombstone).map_err(|_| ())?,
                ),
            })
        }
        AdmissionResponseWireV2::Reject {
            scope: actual,
            rejection,
        } => {
            expect_scope(actual, scope)?;
            Ok(RegistrationDecision::Reject(rejection.into()))
        }
    }
}

fn decode_terminal_mutation_response(
    bytes: &[u8],
    scope: Scope,
    admission: &Admission,
) -> Result<TerminalizeDecision, ()> {
    let wire: TerminalResponseWire = decode_frame(
        bytes,
        TERMINAL_RESPONSE_MAGIC,
        TERMINAL_RESPONSE_DOMAIN,
        MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ())?;
    if encode_terminal_response(&wire)? != bytes {
        return Err(());
    }
    match wire {
        TerminalResponseWire::Terminalized {
            scope: actual,
            committed,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalizeDecision::Terminalized(
                CommittedTerminal::from_canonical_bytes(&committed, admission).map_err(|_| ())?,
            ))
        }
        TerminalResponseWire::Replayed {
            scope: actual,
            committed,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalizeDecision::Replayed(
                CommittedTerminal::from_canonical_bytes(&committed, admission).map_err(|_| ())?,
            ))
        }
        TerminalResponseWire::Compacted {
            scope: actual,
            history_epoch,
            tombstone,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalizeDecision::Compacted {
                history_epoch,
                tombstone: ProfiledTerminalConflictTombstone::V1(
                    TerminalConflictTombstone::from_canonical_bytes(&tombstone).map_err(|_| ())?,
                ),
            })
        }
        TerminalResponseWire::Admitted { .. } => Err(()),
        TerminalResponseWire::Reject {
            scope: actual,
            rejection,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalizeDecision::Reject(rejection.into()))
        }
    }
}

fn decode_terminal_mutation_response_v2(
    bytes: &[u8],
    scope: Scope,
    admission: &Admission,
) -> Result<TerminalizeDecision, ()> {
    if admission.profile() != Profile::v2() {
        return Err(());
    }
    let wire: TerminalResponseWireV2 = decode_frame(
        bytes,
        TERMINAL_RESPONSE_V2_MAGIC,
        TERMINAL_RESPONSE_V2_DOMAIN,
        MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ())?;
    if encode_terminal_response_v2(&wire)? != bytes {
        return Err(());
    }
    match wire {
        TerminalResponseWireV2::Terminalized {
            scope: actual,
            committed,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalizeDecision::Terminalized(
                CommittedTerminal::from_canonical_bytes(&committed, admission).map_err(|_| ())?,
            ))
        }
        TerminalResponseWireV2::Replayed {
            scope: actual,
            committed,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalizeDecision::Replayed(
                CommittedTerminal::from_canonical_bytes(&committed, admission).map_err(|_| ())?,
            ))
        }
        TerminalResponseWireV2::Compacted {
            scope: actual,
            history_epoch,
            tombstone,
        } => {
            expect_scope(actual, scope)?;
            if history_epoch == 0 {
                return Err(());
            }
            Ok(TerminalizeDecision::Compacted {
                history_epoch,
                tombstone: ProfiledTerminalConflictTombstone::V2(
                    TerminalConflictTombstone::from_canonical_bytes(&tombstone).map_err(|_| ())?,
                ),
            })
        }
        TerminalResponseWireV2::Admitted { .. } => Err(()),
        TerminalResponseWireV2::Reject {
            scope: actual,
            rejection,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalizeDecision::Reject(rejection.into()))
        }
    }
}

fn decode_terminal_mutation_response_for_profile(
    bytes: &[u8],
    scope: Scope,
    admission: &Admission,
    profile: Profile,
) -> Result<TerminalizeDecision, ()> {
    if profile == Profile::v1() {
        decode_terminal_mutation_response(bytes, scope, admission)
    } else if profile == Profile::v2() {
        decode_terminal_mutation_response_v2(bytes, scope, admission)
    } else {
        Err(())
    }
}

fn decode_terminal_status_response(
    bytes: &[u8],
    scope: Scope,
    admission: &Admission,
) -> Result<TerminalStatusDecision, ()> {
    let wire: TerminalResponseWire = decode_frame(
        bytes,
        TERMINAL_RESPONSE_MAGIC,
        TERMINAL_RESPONSE_DOMAIN,
        MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ())?;
    if encode_terminal_response(&wire)? != bytes {
        return Err(());
    }
    match wire {
        TerminalResponseWire::Admitted { scope: actual } => {
            expect_scope(actual, scope)?;
            Ok(TerminalStatusDecision::Admitted)
        }
        TerminalResponseWire::Terminalized {
            scope: actual,
            committed,
        }
        | TerminalResponseWire::Replayed {
            scope: actual,
            committed,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalStatusDecision::Recorded(Box::new(
                CommittedTerminal::from_canonical_bytes(&committed, admission).map_err(|_| ())?,
            )))
        }
        TerminalResponseWire::Compacted {
            scope: actual,
            history_epoch,
            tombstone,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalStatusDecision::Compacted {
                history_epoch,
                tombstone: Box::new(ProfiledTerminalConflictTombstone::V1(
                    TerminalConflictTombstone::from_canonical_bytes(&tombstone).map_err(|_| ())?,
                )),
            })
        }
        TerminalResponseWire::Reject {
            scope: actual,
            rejection,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalStatusDecision::Reject(rejection.into()))
        }
    }
}

fn decode_terminal_status_response_v2(
    bytes: &[u8],
    scope: Scope,
    admission: &Admission,
) -> Result<TerminalStatusDecision, ()> {
    if admission.profile() != Profile::v2() {
        return Err(());
    }
    let wire: TerminalResponseWireV2 = decode_frame(
        bytes,
        TERMINAL_RESPONSE_V2_MAGIC,
        TERMINAL_RESPONSE_V2_DOMAIN,
        MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ())?;
    if encode_terminal_response_v2(&wire)? != bytes {
        return Err(());
    }
    match wire {
        TerminalResponseWireV2::Admitted { scope: actual } => {
            expect_scope(actual, scope)?;
            Ok(TerminalStatusDecision::Admitted)
        }
        TerminalResponseWireV2::Terminalized {
            scope: actual,
            committed,
        }
        | TerminalResponseWireV2::Replayed {
            scope: actual,
            committed,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalStatusDecision::Recorded(Box::new(
                CommittedTerminal::from_canonical_bytes(&committed, admission).map_err(|_| ())?,
            )))
        }
        TerminalResponseWireV2::Compacted {
            scope: actual,
            history_epoch,
            tombstone,
        } => {
            expect_scope(actual, scope)?;
            if history_epoch == 0 {
                return Err(());
            }
            Ok(TerminalStatusDecision::Compacted {
                history_epoch,
                tombstone: Box::new(ProfiledTerminalConflictTombstone::V2(
                    TerminalConflictTombstone::from_canonical_bytes(&tombstone).map_err(|_| ())?,
                )),
            })
        }
        TerminalResponseWireV2::Reject {
            scope: actual,
            rejection,
        } => {
            expect_scope(actual, scope)?;
            Ok(TerminalStatusDecision::Reject(rejection.into()))
        }
    }
}

fn decode_terminal_status_response_for_profile(
    bytes: &[u8],
    scope: Scope,
    admission: &Admission,
    profile: Profile,
) -> Result<TerminalStatusDecision, ()> {
    if profile == Profile::v1() {
        decode_terminal_status_response(bytes, scope, admission)
    } else if profile == Profile::v2() {
        decode_terminal_status_response_v2(bytes, scope, admission)
    } else {
        Err(())
    }
}

fn decode_admission(bytes: &[u8], original_admission: Option<&Admission>) -> Result<Admission, ()> {
    let admission = Admission::from_canonical_bytes(bytes).map_err(|_| ())?;
    if original_admission.is_some_and(|original| original != &admission) {
        return Err(());
    }
    Ok(admission)
}

fn expect_scope(actual: [u8; 32], expected: Scope) -> Result<(), ()> {
    (actual == expected.digest()).then_some(()).ok_or(())
}

fn encode_admission_response(wire: &AdmissionResponseWire) -> Result<Vec<u8>, ()> {
    encode_frame(
        ADMISSION_RESPONSE_MAGIC,
        ADMISSION_RESPONSE_DOMAIN,
        wire,
        MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    )
    .map_err(|_| ())
}

fn encode_terminal_response(wire: &TerminalResponseWire) -> Result<Vec<u8>, ()> {
    encode_frame(
        TERMINAL_RESPONSE_MAGIC,
        TERMINAL_RESPONSE_DOMAIN,
        wire,
        MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ())
}

fn encode_terminal_response_v2(wire: &TerminalResponseWireV2) -> Result<Vec<u8>, ()> {
    encode_frame(
        TERMINAL_RESPONSE_V2_MAGIC,
        TERMINAL_RESPONSE_V2_DOMAIN,
        wire,
        MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fenced_mutation_roster::{client::ClientError, runtime::ExecutorError};

    const PROFILE_V2_TRANSPORT_COMPATIBILITY_DESCRIPTOR: &[u8] = concat!(
        "admission-request-v2=postcard-frame,magic:OPCRPA2\\0,domain:admission-port/profile-v2/request/v1,wire:AdmissionRequestWire(register:scope,admission,authority|recover:scope,roster-id,original-owner,original-admission-fence,authority)\n",
        "admission-response-v2=postcard-frame,magic:OPCRPS2\\0,domain:admission-port/profile-v2/response/v1,wire:AdmissionResponseWireV2(fresh:scope,registration,profile-v2-admission-provenance|replayed:scope|poll-admitted:scope,registration,admission,profile-v2-admission-provenance|terminal:scope,registration,admission,committed,profile-v2-admission-provenance|compacted:scope,history-epoch,profile-v2-terminal-conflict-tombstone|reject:scope,rejection)\n",
        "terminal-request-v2=postcard-frame,magic:OPCRPT2\\0,domain:terminal-port/profile-v2/request/v1,wire:TerminalRequestWireV2(scope,binding,registration,authority,record,profile-v2-admission-provenance,generic-compact-terminal-evidence),no-v1-bundle-or-voter-ingress\n",
        "terminal-response-v2=postcard-frame,magic:OPCRPU2\\0,domain:terminal-port/profile-v2/response/v1,wire:TerminalResponseWireV2(terminalized:scope,committed|replayed:scope,committed|admitted:scope|compacted:scope,history-epoch,profile-v2-terminal-conflict-tombstone|reject:scope,rejection),no-v1-tombstone\n",
        "bounds=admission-capsule,terminal-v2-capsule,terminal-v2-hello-frame,port-envelope-overhead;response=profile-v2-frames-only,no-v1-frame-probe\n"
    )
    .as_bytes();

    fn profile_v2_transport_compatibility_digest_from_net_codec() -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"openpacketcore/protected-roster/profile-v2/transport-carriers/v1\0");
        hasher.update(PROFILE_V2_TRANSPORT_COMPATIBILITY_DESCRIPTOR);
        for magic in [
            ADMISSION_REQUEST_V2_MAGIC,
            ADMISSION_RESPONSE_V2_MAGIC,
            TERMINAL_REQUEST_V2_MAGIC,
            TERMINAL_RESPONSE_V2_MAGIC,
        ] {
            hasher.update(b"\0magic:");
            hasher.update(magic);
        }
        for domain in [
            ADMISSION_REQUEST_V2_DOMAIN,
            ADMISSION_RESPONSE_V2_DOMAIN,
            TERMINAL_REQUEST_V2_DOMAIN,
            TERMINAL_RESPONSE_V2_DOMAIN,
        ] {
            hasher.update(b"\0domain:");
            hasher.update(domain);
        }
        for bound in [
            MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
            MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES,
            opc_session_store::consumer::MAX_SESSION_CONSUMER_ROSTER_V2_TERMINAL_FRAME_BYTES,
            MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES,
        ] {
            hasher.update((bound as u64).to_be_bytes());
        }
        hasher.finalize().into()
    }

    #[test]
    fn net_v2_transport_literals_exactly_match_store_activation_contract() {
        assert_eq!(
            profile_v2_transport_compatibility_digest_from_net_codec(),
            opc_session_store::
                fenced_mutation_roster_profile_v2_transport_compatibility_descriptor_digest()
        );
    }

    #[test]
    fn terminal_response_profiles_reject_each_others_framed_carrier() {
        let scope = [0x53; 32];
        let v1 = encode_terminal_response(&TerminalResponseWire::Admitted { scope })
            .expect("bounded frozen V1 terminal response");
        let v2 = encode_terminal_response_v2(&TerminalResponseWireV2::Admitted { scope })
            .expect("bounded V2 terminal response");

        assert!(
            decode_frame::<TerminalResponseWireV2>(
                &v1,
                TERMINAL_RESPONSE_V2_MAGIC,
                TERMINAL_RESPONSE_V2_DOMAIN,
                MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES,
            )
            .is_err(),
            "a frozen V1 terminal response cannot enter the /4 decoder"
        );
        assert!(
            decode_frame::<TerminalResponseWire>(
                &v2,
                TERMINAL_RESPONSE_MAGIC,
                TERMINAL_RESPONSE_DOMAIN,
                MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
            )
            .is_err(),
            "a /4 terminal response cannot enter the V1 decoder"
        );
    }

    #[test]
    fn v2_compact_response_never_decodes_a_frozen_v1_tombstone_frame() {
        let scope = [0x54; 32];
        let v1_compacted = encode_terminal_response(&TerminalResponseWire::Compacted {
            scope,
            history_epoch: 1,
            tombstone: vec![0],
        })
        .expect("bounded frozen V1 compact response");

        assert!(
            decode_frame::<TerminalResponseWireV2>(
                &v1_compacted,
                TERMINAL_RESPONSE_V2_MAGIC,
                TERMINAL_RESPONSE_V2_DOMAIN,
                MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES,
            )
            .is_err(),
            "a V1 compact tombstone frame cannot reach the /4 carrier decoder"
        );
    }

    #[test]
    fn v2_tombstone_uses_common_cap_and_max_plus_one_is_rejected() {
        let maximum = MAX_TOMBSTONE_CODEC_BYTES;
        assert_eq!(maximum, 256);
        assert!(
            TerminalConflictTombstone::from_canonical_bytes(&vec![0; maximum + 1]).is_err(),
            "a V2 tombstone above its exact canonical cap is rejected before use"
        );
    }

    #[test]
    fn production_roster_rejection_adapter_preserves_wire_rejection_classes() {
        let scope = Scope::from_digest([0x53; 32]);
        let cases = [
            (
                SessionConsumerRosterRejection::Malformed,
                BackendRejection::TerminalConflict,
                ExecutorError::TerminalConflict,
                ClientError::TerminalConflict,
            ),
            (
                SessionConsumerRosterRejection::Authority,
                BackendRejection::Authority,
                ExecutorError::AuthorityRejected,
                ClientError::AuthorityRejected,
            ),
            (
                SessionConsumerRosterRejection::RecoveryRequired,
                BackendRejection::RecoveryRequired,
                ExecutorError::RecoveryRequired,
                ClientError::RecoveryRequired,
            ),
            (
                SessionConsumerRosterRejection::RecordMissing,
                BackendRejection::RecordMissing,
                ExecutorError::AdmissionRecordMissing,
                ClientError::AdmissionRecordMissing,
            ),
            (
                SessionConsumerRosterRejection::GenerationConflict,
                BackendRejection::GenerationConflict,
                ExecutorError::AdmissionGenerationConflict,
                ClientError::AdmissionGenerationConflict,
            ),
            (
                SessionConsumerRosterRejection::GenerationExhausted,
                BackendRejection::GenerationExhausted,
                ExecutorError::AdmissionGenerationExhausted,
                ClientError::AdmissionGenerationExhausted,
            ),
            (
                SessionConsumerRosterRejection::BusinessKeyReserved,
                BackendRejection::BusinessKeyReserved,
                ExecutorError::AdmissionBusinessKeyReserved,
                ClientError::AdmissionBusinessKeyReserved,
            ),
            (
                SessionConsumerRosterRejection::InvalidProtectedCheckpoint,
                BackendRejection::InvalidProtectedCheckpoint,
                ExecutorError::AdmissionInvalidProtectedCheckpoint,
                ClientError::AdmissionInvalidProtectedCheckpoint,
            ),
            (
                SessionConsumerRosterRejection::AggregateBytesFull,
                BackendRejection::AggregateBytesFull,
                ExecutorError::AdmissionAggregateBytesFull,
                ClientError::AdmissionAggregateCapacityFull,
            ),
            (
                SessionConsumerRosterRejection::LiveFull,
                BackendRejection::LiveFull,
                ExecutorError::AdmissionLiveFull,
                ClientError::AdmissionLiveCapacityFull,
            ),
            (
                SessionConsumerRosterRejection::HistoryFull,
                BackendRejection::HistoryFull,
                ExecutorError::AdmissionHistoryFull,
                ClientError::AdmissionHistoryCapacityFull,
            ),
            (
                SessionConsumerRosterRejection::Conflict,
                BackendRejection::TerminalConflict,
                ExecutorError::TerminalConflict,
                ClientError::TerminalConflict,
            ),
            (
                SessionConsumerRosterRejection::Capability,
                BackendRejection::TerminalConflict,
                ExecutorError::TerminalConflict,
                ClientError::TerminalConflict,
            ),
            (
                SessionConsumerRosterRejection::Unavailable,
                BackendRejection::Unavailable,
                ExecutorError::BackendUnavailable,
                ClientError::Unavailable,
            ),
        ];

        for (rejection, backend, executor, client) in cases {
            let response = encode_admission_response(&AdmissionResponseWire::Reject {
                scope: scope.digest(),
                rejection,
            })
            .expect("bounded production roster rejection response");
            match decode_admission_response(&response, scope, None)
                .expect("canonical production roster rejection response")
            {
                RegistrationDecision::Reject(actual) => {
                    assert_eq!(actual, backend);
                    assert_eq!(ExecutorError::from(actual), executor);
                    assert_eq!(ClientError::from(executor), client);
                }
                _ => panic!("rejection response must not decode as an admission"),
            }
        }
    }

    #[test]
    fn unavailable_rejection_is_never_recovery_or_not_transmitted() {
        let backend = BackendRejection::from(SessionConsumerRosterRejection::Unavailable);
        let executor = ExecutorError::from(backend);

        assert_eq!(backend, BackendRejection::Unavailable);
        assert_eq!(executor, ExecutorError::BackendUnavailable);
        assert_ne!(executor, ExecutorError::RecoveryRequired);
        assert_ne!(executor, ExecutorError::AdmissionNotTransmitted);
        assert_ne!(executor, ExecutorError::TerminalizeNotTransmitted);
        assert_eq!(ClientError::from(executor), ClientError::Unavailable);
    }
}
