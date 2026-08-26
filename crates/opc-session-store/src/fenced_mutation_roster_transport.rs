//! Least-authority protected-roster transport composition.
//!
//! This module is the only client-side bridge from a consumer transport to
//! the roster executor.  It carries opaque, canonical capsules; it does not
//! expose a consensus store, a raw authority binding, or a proof constructor.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::{
    consumer::{
        SessionConsumerRosterAdmissionCapsule, SessionConsumerRosterRejection,
        SessionConsumerRosterTerminalCapsule, SessionConsumerScope,
    },
    fenced_mutation_roster::{
        decode_frame, encode_frame, roster_ingress_capsule_commitment, Admission,
        RequestBindingKey, RequestId, RosterExecutorProofBundleV1, RosterId, Scope,
        TerminalConflictTombstone, TerminalRecord, MAX_ADMISSION_CODEC_BYTES,
        MAX_COMMITTED_TERMINAL_CODEC_BYTES, MAX_EXECUTOR_PROOF_BUNDLE_BYTES,
        MAX_TOMBSTONE_CODEC_BYTES,
    },
    fenced_mutation_roster_executor::{
        AuthorityBinding, AuthorityLeaseMetadata, BackendRegistration, BackendRejection,
        CommittedTerminal, RecoveryRequest, RegistrationRequest, TerminalBody,
    },
    FenceToken, Generation, OwnerId, SessionKey, Timestamp,
};

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
const TOMBSTONE_FRAME_MAGIC: [u8; 8] = *b"OPCRTB1\0";
const TOMBSTONE_FRAME_DOMAIN: &[u8] = b"opc/session-store/protected-roster/tombstone-frame/v1\0";
const SCOPE_DOMAIN: &[u8] = b"openpacketcore/protected-roster/consumer-scope/v1\0";

/// Reserved deterministic envelope allowance around canonical roster bodies.
///
/// This covers the versioned port header, frame digest, scope binding,
/// registration, authority lease fields, and fixed postcard length markers.
/// It is intentionally not caller configurable.
pub(crate) const MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES: usize = 512;

/// Maximum admission-family capsule, including a terminal recovery reply.
pub(crate) const MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES: usize = MAX_ADMISSION_CODEC_BYTES
    + MAX_COMMITTED_TERMINAL_CODEC_BYTES
    + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;

/// Maximum terminal-family capsule, including the committed terminal reply.
pub(crate) const MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES: usize =
    MAX_COMMITTED_TERMINAL_CODEC_BYTES
        + MAX_EXECUTOR_PROOF_BUNDLE_BYTES
        + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;

/// Fixed redaction-safe failure from the protected-roster client transport.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("protected roster transport unavailable")]
pub(crate) struct ProtectedRosterTransportError;

impl fmt::Debug for ProtectedRosterTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedRosterTransportError(<redacted>)")
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
        }
    }
}

/// Derive the sole protected-roster scope from authenticated transport scope.
///
/// This is an SDK dispatcher seam; it is deliberately crate-private so a
/// consumer cannot select or substitute a roster scope.
#[doc(hidden)]
pub(crate) fn protected_roster_scope_from_consumer_scope(scope: SessionConsumerScope) -> Scope {
    let identity = scope.consensus_identity();
    let mut hasher = Sha256::new();
    hasher.update(SCOPE_DOMAIN);
    hasher.update(identity.cluster_id().as_bytes());
    hasher.update(identity.configuration_id().as_bytes());
    hasher.update(identity.configuration_epoch().get().to_be_bytes());
    Scope::from_digest(hasher.finalize().into())
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

impl AuthorityWire {
    fn into_authority(self, scope: Scope) -> Result<AuthorityBinding, ()> {
        AuthorityBinding::from_consensus_parts(
            scope.digest(),
            self.key,
            self.owner,
            self.fence,
            AuthorityLeaseMetadata::new(
                self.credential_id,
                self.generation,
                self.acquired_at,
                self.expires_at,
            ),
        )
        .map_err(|_| ())
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
    // This producer does not emit the legacy replay response, but its
    // revision-five discriminant is part of the persistent /3 wire ABI.
    #[allow(dead_code)]
    Replayed { scope: [u8; 32] },
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
    // Rejections are carried by the outer consumer response. Keep the
    // revision-five capsule discriminant reserved for schema parity.
    #[allow(dead_code)]
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
    // Rejections are carried by the outer consumer response. Keep the
    // revision-five capsule discriminant reserved for schema parity.
    #[allow(dead_code)]
    Reject {
        scope: [u8; 32],
        rejection: SessionConsumerRosterRejection,
    },
}

/// Reconstruct the exact opaque PollAdmit request capsule commitment carried
/// by a root-certified ingress statement. This has no provider or wall-clock
/// dependency and is shared by deterministic SQLite apply/followers.
pub(crate) fn roster_poll_admit_ingress_capsule_commitment(
    admission: &Admission,
    authority: &AuthorityBinding,
) -> Result<[u8; 32], ()> {
    let wire = AdmissionRequestWire::Register {
        scope: authority.scope().digest(),
        admission: admission.to_canonical_bytes().map_err(|_| ())?,
        authority: authority.into(),
    };
    roster_ingress_capsule_commitment(1, &encode_admission_request(&wire)?).map_err(|_| ())
}

/// Reconstruct the exact opaque Terminalize request capsule commitment
/// against the retained admission. The executor bundle is included because it
/// is part of the authenticated transport request, despite being replaceable
/// and excluded from the stable terminal payload digest.
pub(crate) fn roster_terminal_ingress_capsule_commitment(
    binding: RequestBindingKey,
    registration: BackendRegistration,
    authority: &AuthorityBinding,
    terminal: &TerminalRecord,
    admission: &Admission,
    proof_bundle: &RosterExecutorProofBundleV1,
) -> Result<[u8; 32], ()> {
    let wire = TerminalRequestWire {
        scope: authority.scope().digest(),
        binding,
        registration: RegistrationWire::from_registration(registration),
        authority: authority.into(),
        record: terminal.to_canonical_bytes(admission).map_err(|_| ())?,
        proof_bundle: proof_bundle.canonical_bytes().map_err(|_| ())?,
    };
    roster_ingress_capsule_commitment(4, &encode_terminal_request(&wire)?).map_err(|_| ())
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

fn response_scope(consumer_scope: SessionConsumerScope) -> [u8; 32] {
    protected_roster_scope_from_consumer_scope(consumer_scope).digest()
}

fn admission_bytes_for_consumer_scope(
    consumer_scope: SessionConsumerScope,
    admission: &Admission,
) -> Result<Vec<u8>, ProtectedRosterTransportError> {
    (admission.scope().digest() == response_scope(consumer_scope))
        .then_some(())
        .ok_or(ProtectedRosterTransportError)?;
    admission
        .to_canonical_bytes()
        .map_err(|_| ProtectedRosterTransportError)
}

fn admission_response_capsule(
    wire: AdmissionResponseWire,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    SessionConsumerRosterAdmissionCapsule::new(
        encode_admission_response(&wire).map_err(|_| ProtectedRosterTransportError)?,
    )
    .map_err(|_| ProtectedRosterTransportError)
}

fn terminal_response_capsule(
    wire: TerminalResponseWire,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    SessionConsumerRosterTerminalCapsule::new(
        encode_terminal_response(&wire).map_err(|_| ProtectedRosterTransportError)?,
    )
    .map_err(|_| ProtectedRosterTransportError)
}

/// Encode a successful admission mutation response under an authenticated
/// consumer scope. This SDK-boundary hook accepts only a backend-issued
/// registration; it is not a public capability constructor.
#[doc(hidden)]
pub(crate) fn encode_admission_fresh_response(
    consumer_scope: SessionConsumerScope,
    registration: BackendRegistration,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    admission_response_capsule(AdmissionResponseWire::Fresh {
        scope: response_scope(consumer_scope),
        registration: RegistrationWire::from_registration(registration),
    })
}

/// Encode a read-only nonterminal roster recovery response.
#[doc(hidden)]
pub(crate) fn encode_admission_poll_admitted_response(
    consumer_scope: SessionConsumerScope,
    registration: BackendRegistration,
    admission: &Admission,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    admission_response_capsule(AdmissionResponseWire::PollAdmitted {
        scope: response_scope(consumer_scope),
        registration: RegistrationWire::from_registration(registration),
        admission: admission_bytes_for_consumer_scope(consumer_scope, admission)?,
    })
}

/// Encode a read-only committed-terminal recovery response.
#[doc(hidden)]
pub(crate) fn encode_admission_terminal_response(
    consumer_scope: SessionConsumerScope,
    registration: BackendRegistration,
    admission: &Admission,
    committed: &CommittedTerminal,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    admission_response_capsule(AdmissionResponseWire::Terminal {
        scope: response_scope(consumer_scope),
        registration: RegistrationWire::from_registration(registration),
        admission: admission_bytes_for_consumer_scope(consumer_scope, admission)?,
        committed: committed
            .to_canonical_bytes(admission)
            .map_err(|_| ProtectedRosterTransportError)?,
    })
}

/// Encode a bounded terminal-compaction recovery response without payload.
#[doc(hidden)]
pub(crate) fn encode_admission_compacted_response(
    consumer_scope: SessionConsumerScope,
    history_epoch: u64,
    tombstone: TerminalConflictTombstone,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    if history_epoch == 0 {
        return Err(ProtectedRosterTransportError);
    }
    admission_response_capsule(AdmissionResponseWire::Compacted {
        scope: response_scope(consumer_scope),
        history_epoch,
        tombstone: tombstone
            .to_canonical_bytes()
            .map_err(|_| ProtectedRosterTransportError)?,
    })
}

fn encode_terminal_committed_bytes_response(
    consumer_scope: SessionConsumerScope,
    committed: Vec<u8>,
    replayed: bool,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    if committed.is_empty() || committed.len() > MAX_COMMITTED_TERMINAL_CODEC_BYTES {
        return Err(ProtectedRosterTransportError);
    }
    let scope = response_scope(consumer_scope);
    let wire = if replayed {
        TerminalResponseWire::Replayed { scope, committed }
    } else {
        TerminalResponseWire::Terminalized { scope, committed }
    };
    terminal_response_capsule(wire)
}

/// Wrap already-canonical committed terminal bytes emitted by the same
/// terminal consensus apply. The client validates the bytes against its
/// retained immutable admission before accepting them.
#[doc(hidden)]
pub(crate) fn encode_terminal_terminalized_bytes_response(
    consumer_scope: SessionConsumerScope,
    committed: Vec<u8>,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    encode_terminal_committed_bytes_response(consumer_scope, committed, false)
}

/// Wrap a retained canonical terminal for a status read after the caller has
/// compared the exact request, registration, and terminal body. The admission
/// has already been decoded by durable row validation, so this preserves the
/// scope defense without re-encoding that potentially multi-megabyte body.
#[doc(hidden)]
pub(crate) fn encode_terminal_terminalized_validated_bytes_response(
    consumer_scope: SessionConsumerScope,
    admission: &Admission,
    committed: Vec<u8>,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    (admission.scope().digest() == response_scope(consumer_scope))
        .then_some(())
        .ok_or(ProtectedRosterTransportError)?;
    encode_terminal_committed_bytes_response(consumer_scope, committed, false)
}

/// Wrap already-canonical bytes for an idempotent terminal replay emitted by
/// the terminal consensus apply. No record or authority is reconstructed at
/// the transport boundary.
#[doc(hidden)]
pub(crate) fn encode_terminal_replayed_bytes_response(
    consumer_scope: SessionConsumerScope,
    committed: Vec<u8>,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    encode_terminal_committed_bytes_response(consumer_scope, committed, true)
}

/// Encode an exact nonterminal terminal-status response.
#[doc(hidden)]
pub(crate) fn encode_terminal_admitted_response(
    consumer_scope: SessionConsumerScope,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    terminal_response_capsule(TerminalResponseWire::Admitted {
        scope: response_scope(consumer_scope),
    })
}

/// Encode a compacted terminal-status response without terminal payload.
#[doc(hidden)]
pub(crate) fn encode_terminal_compacted_response(
    consumer_scope: SessionConsumerScope,
    history_epoch: u64,
    tombstone: TerminalConflictTombstone,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    if history_epoch == 0 {
        return Err(ProtectedRosterTransportError);
    }
    terminal_response_capsule(TerminalResponseWire::Compacted {
        scope: response_scope(consumer_scope),
        history_epoch,
        tombstone: tombstone
            .to_canonical_bytes()
            .map_err(|_| ProtectedRosterTransportError)?,
    })
}

/// Decode a canonical admission port request after the listener has proven
/// the authenticated consumer scope. This is an SDK dispatcher seam.
#[doc(hidden)]
pub(crate) fn decode_admission_request_for_scope(
    capsule: &SessionConsumerRosterAdmissionCapsule,
    consumer_scope: SessionConsumerScope,
) -> Result<DecodedAdmissionRequest, ProtectedRosterTransportError> {
    let scope = protected_roster_scope_from_consumer_scope(consumer_scope);
    let wire: AdmissionRequestWire = decode_frame(
        capsule.canonical_bytes(),
        ADMISSION_REQUEST_MAGIC,
        ADMISSION_REQUEST_DOMAIN,
        MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    )
    .map_err(|_| ProtectedRosterTransportError)?;
    if encode_admission_request(&wire).ok().as_deref() != Some(capsule.canonical_bytes()) {
        return Err(ProtectedRosterTransportError);
    }
    match wire {
        AdmissionRequestWire::Register {
            scope: actual,
            admission,
            authority,
        } => {
            expect_scope(actual, scope).map_err(|_| ProtectedRosterTransportError)?;
            let admission = decode_admission(&admission, scope, None)
                .map_err(|_| ProtectedRosterTransportError)?;
            let authority = authority
                .into_authority(scope)
                .map_err(|_| ProtectedRosterTransportError)?;
            let request = RegistrationRequest::new_with_lease_metadata(
                admission,
                authority.owner().clone(),
                authority.fence(),
                authority.credential_id(),
                authority.generation(),
                authority.acquired_at(),
                authority.expires_at(),
            )
            .map_err(|_| ProtectedRosterTransportError)?;
            if request.authority() != &authority {
                return Err(ProtectedRosterTransportError);
            }
            Ok(DecodedAdmissionRequest::Register(request))
        }
        AdmissionRequestWire::Recover {
            scope: actual,
            roster_id,
            authority,
        } => {
            expect_scope(actual, scope).map_err(|_| ProtectedRosterTransportError)?;
            let authority = authority
                .into_authority(scope)
                .map_err(|_| ProtectedRosterTransportError)?;
            let request = RecoveryRequest::new_with_lease_metadata(
                scope,
                roster_id,
                authority.key().clone(),
                authority.owner().clone(),
                authority.fence(),
                AuthorityLeaseMetadata::new(
                    authority.credential_id(),
                    authority.generation(),
                    authority.acquired_at(),
                    authority.expires_at(),
                ),
            )
            .map_err(|_| ProtectedRosterTransportError)?;
            Ok(DecodedAdmissionRequest::Recover(request))
        }
    }
}

/// SDK-private admission request decoded under an authenticated scope.
#[doc(hidden)]
pub(crate) enum DecodedAdmissionRequest {
    /// Immutable registration mutation input.
    Register(RegistrationRequest),
    /// Read-only successor recovery input.
    Recover(RecoveryRequest),
}

impl DecodedAdmissionRequest {
    /// Consume an admission mutation into the exact immutable body and
    /// authority that the consensus command must bind atomically.
    pub(crate) fn into_register_parts(
        self,
    ) -> Result<(Admission, AuthorityBinding), ProtectedRosterTransportError> {
        match self {
            Self::Register(request) => {
                Ok((request.admission().clone(), request.authority().clone()))
            }
            Self::Recover(_) => Err(ProtectedRosterTransportError),
        }
    }

    /// Consume a read-only successor recovery request.
    pub(crate) fn into_recovery(self) -> Result<RecoveryRequest, ProtectedRosterTransportError> {
        match self {
            Self::Recover(request) => Ok(request),
            Self::Register(_) => Err(ProtectedRosterTransportError),
        }
    }
}

/// Decode a terminal port request without accepting a client-supplied
/// admission. The listener must resolve the returned registration against its
/// live durable row, then call [`DecodedTerminalRequest::into_terminal_request`].
#[doc(hidden)]
pub(crate) fn decode_terminal_request_for_scope(
    capsule: &SessionConsumerRosterTerminalCapsule,
    consumer_scope: SessionConsumerScope,
) -> Result<DecodedTerminalRequest, ProtectedRosterTransportError> {
    let scope = protected_roster_scope_from_consumer_scope(consumer_scope);
    let wire: TerminalRequestWire = decode_frame(
        capsule.canonical_bytes(),
        TERMINAL_REQUEST_MAGIC,
        TERMINAL_REQUEST_DOMAIN,
        MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ProtectedRosterTransportError)?;
    if encode_terminal_request(&wire).ok().as_deref() != Some(capsule.canonical_bytes()) {
        return Err(ProtectedRosterTransportError);
    }
    expect_scope(wire.scope, scope).map_err(|_| ProtectedRosterTransportError)?;
    Ok(DecodedTerminalRequest {
        binding: wire.binding,
        registration: wire.registration,
        authority: wire
            .authority
            .into_authority(scope)
            .map_err(|_| ProtectedRosterTransportError)?,
        record: wire.record,
        proof_bundle: RosterExecutorProofBundleV1::decode_canonical(&wire.proof_bundle)
            .map_err(|_| ProtectedRosterTransportError)?
            .canonical_bytes()
            .map_err(|_| ProtectedRosterTransportError)?,
    })
}

/// SDK-private terminal request awaiting server-side live admission lookup.
#[doc(hidden)]
pub(crate) struct DecodedTerminalRequest {
    binding: RequestBindingKey,
    registration: RegistrationWire,
    authority: AuthorityBinding,
    record: Vec<u8>,
    proof_bundle: Vec<u8>,
}

impl DecodedTerminalRequest {
    /// Return the immutable terminal binding selected by the admission's
    /// atomic apply. SQLite rederives and compares it after resolving the
    /// retained admission inside the terminal transaction.
    pub(crate) const fn binding(&self) -> RequestBindingKey {
        self.binding
    }

    /// Return the non-authoritative registration parts retained in the
    /// terminal request. The service uses these only to select the exact
    /// durable row and derives/revalidates the slot inside its mutation.
    pub(crate) fn registration_parts(&self) -> ([u8; 32], RequestId, [u8; 32]) {
        (
            self.registration.handle,
            self.registration.request_id,
            self.registration.terminal_slot,
        )
    }

    /// Borrow the exact current authority that terminalization must recheck.
    pub(crate) fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }

    /// Borrow the canonical terminal-record frame. It is decoded only after
    /// the server has resolved the immutable retained admission.
    pub(crate) fn canonical_record(&self) -> &[u8] {
        &self.record
    }

    /// Decode the exact bounded canonical proof bundle.  The ingress/store
    /// layer must pass this typed bundle into the sole terminal consensus
    /// command; no unbounded or caller-forged proof fields cross this seam.
    pub(crate) fn proof_bundle(
        &self,
    ) -> Result<RosterExecutorProofBundleV1, ProtectedRosterTransportError> {
        RosterExecutorProofBundleV1::decode_canonical(&self.proof_bundle)
            .map_err(|_| ProtectedRosterTransportError)
    }

    /// Return the supplied canonical terminal-body commitment before its
    /// retained admission is available. Compacted status uses this to compare
    /// the request with the exact commitment retained in its tombstone.
    pub(crate) fn terminal_body_commitment(
        &self,
    ) -> Result<[u8; 32], ProtectedRosterTransportError> {
        TerminalRecord::canonical_body_commitment(&self.record)
            .map_err(|_| ProtectedRosterTransportError)
    }

    /// Rehydrate the terminal request only against the server-retained exact admission.
    pub(crate) fn into_terminal_request(
        self,
        admission: &Admission,
    ) -> Result<(BackendRegistration, AuthorityBinding, TerminalBody), ProtectedRosterTransportError>
    {
        if self.authority.scope() != admission.scope()
            || self.authority.key() != admission.key()
            || self.authority.generation() != admission.expected_generation()
        {
            return Err(ProtectedRosterTransportError);
        }
        let registration = self
            .registration
            .into_registration(admission)
            .map_err(|_| ProtectedRosterTransportError)?;
        if self.binding
            != admission
                .binding_key(registration.consensus_parts().1.history_epoch())
                .map_err(|_| ProtectedRosterTransportError)?
        {
            return Err(ProtectedRosterTransportError);
        }
        let record = TerminalRecord::from_canonical_bytes(&self.record, admission)
            .map_err(|_| ProtectedRosterTransportError)?;
        let body = TerminalBody::from_record(record, admission)
            .map_err(|_| ProtectedRosterTransportError)?;
        Ok((registration, self.authority, body))
    }
}

#[derive(Serialize, Deserialize)]
struct TerminalConflictTombstoneWire {
    binding_key: RequestBindingKey,
    admission_body_commitment: [u8; 32],
    terminal_body_commitment: [u8; 32],
    admission_fence: u64,
    expected_generation: u64,
    phase_tag: u8,
}

/// Extract the immutable terminal-body commitment from a canonical compacted
/// tombstone without exposing a tombstone constructor or raw server response.
pub(crate) fn compacted_terminal_body_commitment(
    tombstone: TerminalConflictTombstone,
) -> Result<[u8; 32], ProtectedRosterTransportError> {
    let bytes = tombstone
        .to_canonical_bytes()
        .map_err(|_| ProtectedRosterTransportError)?;
    let wire: TerminalConflictTombstoneWire = decode_frame(
        &bytes,
        TOMBSTONE_FRAME_MAGIC,
        TOMBSTONE_FRAME_DOMAIN,
        MAX_TOMBSTONE_CODEC_BYTES,
    )
    .map_err(|_| ProtectedRosterTransportError)?;
    if encode_frame(
        TOMBSTONE_FRAME_MAGIC,
        TOMBSTONE_FRAME_DOMAIN,
        &wire,
        MAX_TOMBSTONE_CODEC_BYTES,
    )
    .map_err(|_| ProtectedRosterTransportError)?
        != bytes
        || wire.terminal_body_commitment == [0; 32]
    {
        return Err(ProtectedRosterTransportError);
    }
    Ok(wire.terminal_body_commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity,
    };

    fn consumer_scope(configuration: u8, epoch: u64) -> SessionConsumerScope {
        SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([0xA1; 32]),
            SessionConsensusConfigurationId::from_bytes([configuration; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).expect("nonzero epoch"),
        ))
    }

    fn postcard_variant_tag<T: Serialize>(wire: &T) -> u8 {
        *postcard::to_allocvec(wire)
            .expect("bounded response wire")
            .first()
            .expect("postcard enum tag")
    }

    #[test]
    fn revision_five_response_discriminants_remain_frozen() {
        let scope = [0xB2; 32];

        // Replayed and Reject are intentionally producer-unused. Their
        // reserved positions bracket the active recovery responses:
        // PollAdmitted=2, Terminal=3, and Compacted=4.
        assert_eq!(
            postcard_variant_tag(&AdmissionResponseWire::Replayed { scope }),
            1
        );
        assert_eq!(
            postcard_variant_tag(&AdmissionResponseWire::Compacted {
                scope,
                history_epoch: 1,
                tombstone: vec![1],
            }),
            4
        );
        assert_eq!(
            postcard_variant_tag(&AdmissionResponseWire::Reject {
                scope,
                rejection: SessionConsumerRosterRejection::Authority,
            }),
            5
        );

        assert_eq!(
            postcard_variant_tag(&TerminalResponseWire::Terminalized {
                scope,
                committed: vec![1],
            }),
            0
        );
        assert_eq!(
            postcard_variant_tag(&TerminalResponseWire::Replayed {
                scope,
                committed: vec![1],
            }),
            1
        );
        assert_eq!(
            postcard_variant_tag(&TerminalResponseWire::Admitted { scope }),
            2
        );
        assert_eq!(
            postcard_variant_tag(&TerminalResponseWire::Compacted {
                scope,
                history_epoch: 1,
                tombstone: vec![1],
            }),
            3
        );
        assert_eq!(
            postcard_variant_tag(&TerminalResponseWire::Reject {
                scope,
                rejection: SessionConsumerRosterRejection::Authority,
            }),
            4
        );
    }

    #[test]
    fn terminal_response_is_exactly_canonical_and_scope_bound() {
        let scope = consumer_scope(0xB3, 8);
        let capsule = encode_terminal_admitted_response(scope).expect("bounded response");
        let decoded: TerminalResponseWire = decode_frame(
            capsule.canonical_bytes(),
            TERMINAL_RESPONSE_MAGIC,
            TERMINAL_RESPONSE_DOMAIN,
            MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
        )
        .expect("canonical response decodes");
        assert_eq!(
            encode_terminal_response(&decoded).expect("response reencodes"),
            capsule.canonical_bytes(),
        );
        assert!(expect_scope(
            match decoded {
                TerminalResponseWire::Admitted { scope } => scope,
                _ => unreachable!("encoded admitted response"),
            },
            protected_roster_scope_from_consumer_scope(consumer_scope(0xB4, 8)),
        )
        .is_err());
    }

    #[test]
    fn diagnostics_do_not_render_scope_or_capsule_bytes() {
        let scope = consumer_scope(0xB5, 9);
        let capsule = encode_terminal_admitted_response(scope).expect("bounded response");
        assert_eq!(
            format!("{:#?}", ProtectedRosterTransportError),
            "ProtectedRosterTransportError(<redacted>)"
        );
        assert_eq!(
            format!("{:#?}", capsule),
            "SessionConsumerRosterTerminalCapsule(<redacted>)"
        );
        assert_eq!(format!("{:#?}", scope), "SessionConsumerScope(<redacted>)");
    }
}
