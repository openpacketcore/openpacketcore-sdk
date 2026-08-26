//! Private client-side canonical wire codec and concrete quorum port.
//!
//! No trait in this module is implementable by downstream code. The sole port
//! is built by consuming the exact revision-five persistent client.

use super::{
    canonical::{
        decode_frame, encode_frame, Admission, EstablishedPublicationProvider, MemberProvider,
        RequestBindingKey, RequestId, RosterId, Scope, TerminalConflictTombstone,
        MAX_ADMISSION_CODEC_BYTES, MAX_COMMITTED_TERMINAL_CODEC_BYTES,
    },
    client::FencedMutationRosterClient,
    diagnostics::{FencedMutationRosterDiagnostics, RosterDiagnostics},
    publication::PublicationAdapter,
    runtime::{
        AdmissionStatusRequest, AuthorityBinding, BackendRegistration, BackendRejection,
        CommittedTerminal, FencedMutationRosterExecutorAttestor, RecoveryRequest,
        RegistrationDecision, RegistrationRequest, RosterExecutor, RosterExecutorBackend,
        TerminalBody, TerminalStatusDecision, TerminalStatusRequest, TerminalizeDecision,
        TerminalizeRequest,
    },
};
use crate::consumer::{
    AuthenticatedRosterConsumer, PersistentSessionConsumerClient,
    PersistentSessionConsumerDiagnostics,
};
use opc_session_store::fenced_mutation_roster::MAX_EXECUTOR_PROOF_BUNDLE_BYTES;
use opc_session_store::{
    FenceToken, Generation, OwnerId, SessionConsumerRequestId,
    SessionConsumerRosterAdmissionCapsule, SessionConsumerRosterAdmissionMutationResponse,
    SessionConsumerRosterAdmissionReadResponse, SessionConsumerRosterRejection,
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
const ADMISSION_REQUEST_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/admission-port/request/v1\0";
const ADMISSION_RESPONSE_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/admission-port/response/v1\0";
const TERMINAL_REQUEST_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/terminal-port/request/v1\0";
const TERMINAL_RESPONSE_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/terminal-port/response/v1\0";
const SCOPE_DOMAIN: &[u8] = b"openpacketcore/protected-roster/consumer-scope/v1\0";
const REQUEST_ID_DOMAIN: &[u8] = b"openpacketcore/protected-roster/consumer-request/v1\0";

/// Reserved deterministic envelope allowance around canonical roster bodies.
pub const MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES: usize = 512;
/// Maximum admission-family capsule, including a terminal recovery reply.
pub const MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES: usize = MAX_ADMISSION_CODEC_BYTES
    + MAX_COMMITTED_TERMINAL_CODEC_BYTES
    + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;
/// Maximum terminal-family capsule, including the committed terminal reply.
pub const MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES: usize = MAX_COMMITTED_TERMINAL_CODEC_BYTES
    + MAX_EXECUTOR_PROOF_BUNDLE_BYTES
    + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;

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
    publication: PublicationAdapter<Q>,
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

fn protected_roster_scope_from_consumer_scope(scope: SessionConsumerScope) -> Scope {
    let identity = scope.consensus_identity();
    let mut hasher = Sha256::new();
    hasher.update(SCOPE_DOMAIN);
    hasher.update(identity.cluster_id().as_bytes());
    hasher.update(identity.configuration_id().as_bytes());
    hasher.update(identity.configuration_epoch().get().to_be_bytes());
    Scope::from_digest(hasher.finalize().into())
}

#[derive(Clone)]
pub(crate) struct RosterQuorumPort {
    consumer: AuthenticatedRosterConsumer,
    scope: Scope,
}

impl RosterQuorumPort {
    fn new(consumer: AuthenticatedRosterConsumer) -> Result<Self, ProtectedRosterTransportError> {
        consumer.claim_roster_executor()?;
        let scope = protected_roster_scope_from_consumer_scope(consumer.scope());
        Ok(Self { consumer, scope })
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

    async fn register(
        &self,
        request: &RegistrationRequest,
    ) -> Result<RegistrationDecision, Self::Error> {
        let capsule = admission_capsule_for_registration(request).map_err(|_| AdapterError)?;
        let response = self
            .poll_admit(admission_mutation_request_id(request.admission()), capsule)
            .await
            .map_err(|_| AdapterError)?;
        match response {
            SessionConsumerRosterAdmissionMutationResponse::Recorded(capsule) => {
                decode_admission_response(
                    capsule.canonical_bytes(),
                    self.scope,
                    Some(request.admission()),
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
        let capsule = admission_capsule_for_registration(registration).map_err(|_| AdapterError)?;
        let response = self
            .admission_status(
                admission_mutation_request_id(registration.admission()),
                capsule,
            )
            .await
            .map_err(|_| AdapterError)?;
        decode_admission_read_response(response, self.scope, Some(registration.admission()))
    }

    async fn recover(
        &self,
        request: &RecoveryRequest,
    ) -> Result<RegistrationDecision, Self::Error> {
        let capsule = admission_capsule_for_recovery(request).map_err(|_| AdapterError)?;
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
        decode_admission_read_response(response, self.scope, None)
    }

    async fn terminal_status(
        &self,
        request: TerminalStatusRequest<'_>,
    ) -> Result<TerminalStatusDecision, Self::Error> {
        let capsule = terminal_capsule(
            request.registration(),
            request.authority(),
            request.body(),
            request.admission(),
        )
        .map_err(|_| AdapterError)?;
        let response = self
            .terminal_status(terminal_mutation_request_id(request.admission()), capsule)
            .await
            .map_err(|_| AdapterError)?;
        decode_terminal_read_response(response, self.scope, request.admission())
    }

    async fn terminalize(
        &self,
        request: TerminalizeRequest<'_>,
    ) -> Result<TerminalizeDecision, Self::Error> {
        let capsule = terminal_capsule(
            request.registration(),
            request.authority(),
            request.body(),
            request.admission(),
        )
        .map_err(|_| AdapterError)?;
        let response = self
            .terminalize(terminal_mutation_request_id(request.admission()), capsule)
            .await
            .map_err(|_| AdapterError)?;
        match response {
            SessionConsumerRosterTerminalMutationResponse::Recorded(capsule) => {
                decode_terminal_mutation_response(
                    capsule.canonical_bytes(),
                    self.scope,
                    request.admission(),
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
            SessionConsumerRosterRejection::Malformed
            | SessionConsumerRosterRejection::Capability
            | SessionConsumerRosterRejection::Conflict => Self::TerminalConflict,
            SessionConsumerRosterRejection::Unavailable => Self::RecoveryRequired,
            _ => Self::TerminalConflict,
        }
    }
}

#[derive(Clone, Copy)]
enum AdmissionRequestKind {
    PollAdmit = 1,
    Recover = 3,
    Terminalize = 4,
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
        authority: AuthorityWire,
    },
}

#[derive(Serialize, Deserialize)]
enum AdmissionResponseWire {
    Fresh {
        scope: [u8; 32],
        registration: RegistrationWire,
    },
    Replayed {
        scope: [u8; 32],
    },
    PollAdmitted {
        scope: [u8; 32],
        registration: RegistrationWire,
        admission: Vec<u8>,
    },
    Terminal {
        scope: [u8; 32],
        registration: RegistrationWire,
        admission: Vec<u8>,
        committed: Vec<u8>,
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

fn admission_capsule_for_registration(
    request: &RegistrationRequest,
) -> Result<SessionConsumerRosterAdmissionCapsule, ()> {
    let wire = AdmissionRequestWire::Register {
        scope: request.authority().scope().digest(),
        admission: request.admission().to_canonical_bytes().map_err(|_| ())?,
        authority: request.authority().into(),
    };
    SessionConsumerRosterAdmissionCapsule::new(encode_admission_request(&wire)?).map_err(|_| ())
}

fn admission_capsule_for_recovery(
    request: &RecoveryRequest,
) -> Result<SessionConsumerRosterAdmissionCapsule, ()> {
    let wire = AdmissionRequestWire::Recover {
        scope: request.lookup().scope().digest(),
        roster_id: request.lookup().roster_id(),
        authority: request.authority().into(),
    };
    SessionConsumerRosterAdmissionCapsule::new(encode_admission_request(&wire)?).map_err(|_| ())
}

fn terminal_capsule(
    registration: BackendRegistration,
    authority: &AuthorityBinding,
    body: &TerminalBody,
    admission: &Admission,
) -> Result<SessionConsumerRosterTerminalCapsule, ()> {
    let (_, request_id, _) = registration.consensus_parts();
    let wire = TerminalRequestWire {
        scope: authority.scope().digest(),
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
    };
    SessionConsumerRosterTerminalCapsule::new(encode_terminal_request(&wire)?).map_err(|_| ())
}

fn decode_admission_read_response(
    response: SessionConsumerRosterAdmissionReadResponse,
    scope: Scope,
    original_admission: Option<&Admission>,
) -> Result<RegistrationDecision, AdapterError> {
    match response {
        SessionConsumerRosterAdmissionReadResponse::Recorded(capsule) => {
            decode_admission_response(capsule.canonical_bytes(), scope, original_admission)
                .map_err(|_| AdapterError)
        }
        SessionConsumerRosterAdmissionReadResponse::Rejected(rejection) => {
            Ok(RegistrationDecision::Reject(rejection.into()))
        }
        _ => Err(AdapterError),
    }
}

fn decode_terminal_read_response(
    response: SessionConsumerRosterTerminalReadResponse,
    scope: Scope,
    admission: &Admission,
) -> Result<TerminalStatusDecision, AdapterError> {
    match response {
        SessionConsumerRosterTerminalReadResponse::Recorded(capsule) => {
            decode_terminal_status_response(capsule.canonical_bytes(), scope, admission)
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
        } => {
            let admission = original_admission.ok_or(())?;
            expect_scope(actual, scope)?;
            Ok(RegistrationDecision::FreshlyAdmitted(
                registration.into_registration(admission)?,
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
        } => {
            expect_scope(actual, scope)?;
            let admission = decode_admission(&admission, scope, original_admission)?;
            Ok(RegistrationDecision::PollAdmitted {
                registration: registration.into_registration(&admission)?,
                admission: Arc::new(admission),
            })
        }
        AdmissionResponseWire::Terminal {
            scope: actual,
            registration,
            admission,
            committed,
        } => {
            expect_scope(actual, scope)?;
            let admission = decode_admission(&admission, scope, original_admission)?;
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
                tombstone: TerminalConflictTombstone::from_canonical_bytes(&tombstone)
                    .map_err(|_| ())?,
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
                tombstone: TerminalConflictTombstone::from_canonical_bytes(&tombstone)
                    .map_err(|_| ())?,
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
                tombstone: Box::new(
                    TerminalConflictTombstone::from_canonical_bytes(&tombstone).map_err(|_| ())?,
                ),
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

fn decode_admission(
    bytes: &[u8],
    scope: Scope,
    original_admission: Option<&Admission>,
) -> Result<Admission, ()> {
    let admission = Admission::from_canonical_bytes(bytes).map_err(|_| ())?;
    if admission.scope() != scope
        || original_admission.is_some_and(|original| original != &admission)
    {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fenced_mutation_roster::{client::ClientError, runtime::ExecutorError};

    #[test]
    fn production_roster_rejection_adapter_preserves_documented_admission_errors() {
        let scope = Scope::from_digest([0x53; 32]);
        let cases = [
            (
                SessionConsumerRosterRejection::RecoveryRequired,
                BackendRejection::RecoveryRequired,
                ClientError::RecoveryRequired,
            ),
            (
                SessionConsumerRosterRejection::RecordMissing,
                BackendRejection::RecordMissing,
                ClientError::AdmissionRecordMissing,
            ),
            (
                SessionConsumerRosterRejection::GenerationConflict,
                BackendRejection::GenerationConflict,
                ClientError::AdmissionGenerationConflict,
            ),
            (
                SessionConsumerRosterRejection::GenerationExhausted,
                BackendRejection::GenerationExhausted,
                ClientError::AdmissionGenerationExhausted,
            ),
            (
                SessionConsumerRosterRejection::BusinessKeyReserved,
                BackendRejection::BusinessKeyReserved,
                ClientError::AdmissionBusinessKeyReserved,
            ),
            (
                SessionConsumerRosterRejection::InvalidProtectedCheckpoint,
                BackendRejection::InvalidProtectedCheckpoint,
                ClientError::AdmissionInvalidProtectedCheckpoint,
            ),
            (
                SessionConsumerRosterRejection::AggregateBytesFull,
                BackendRejection::AggregateBytesFull,
                ClientError::AdmissionAggregateCapacityFull,
            ),
            (
                SessionConsumerRosterRejection::LiveFull,
                BackendRejection::LiveFull,
                ClientError::AdmissionLiveCapacityFull,
            ),
            (
                SessionConsumerRosterRejection::HistoryFull,
                BackendRejection::HistoryFull,
                ClientError::AdmissionHistoryCapacityFull,
            ),
        ];

        for (rejection, backend, client) in cases {
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
                    assert_eq!(ClientError::from(ExecutorError::from(actual)), client);
                }
                _ => panic!("rejection response must not decode as an admission"),
            }
        }
    }
}
