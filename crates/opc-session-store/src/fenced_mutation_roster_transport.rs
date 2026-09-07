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
        RequestBindingKey, RequestId, RosterCompactAdmissionProvenanceV2,
        RosterCompactTerminalEvidenceV2, RosterExecutorProofBundleV1, RosterId,
        RosterProfileV2CompactAdmissionProvenanceV1, Scope, TerminalConflictTombstone,
        TerminalRecord, MAX_ADMISSION_CODEC_BYTES, MAX_COMMITTED_TERMINAL_CODEC_BYTES,
        MAX_EXECUTOR_PROOF_BUNDLE_BYTES, MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES,
        MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES,
    },
    fenced_mutation_roster_executor::{
        AuthorityBinding, AuthorityLeaseMetadata, BackendRegistration, BackendRejection,
        CommittedTerminal, RecoveryLookup, RecoveryRequest, RecoveryRequestInput,
        RegistrationRequest, TerminalBody,
    },
    FenceToken, Generation, OwnerId, SessionKey, Timestamp,
};

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
const PROTECTED_ROSTER_V2_TRANSPORT_COMPATIBILITY_DESCRIPTOR_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/profile-v2/transport-carriers/v1\0";
const PROTECTED_ROSTER_V2_TRANSPORT_COMPATIBILITY_DESCRIPTOR: &[u8] = concat!(
    "admission-request-v2=postcard-frame,magic:OPCRPA2\\0,domain:admission-port/profile-v2/request/v1,wire:AdmissionRequestWire(register:scope,admission,authority|recover:scope,roster-id,original-owner,original-admission-fence,authority)\n",
    "admission-response-v2=postcard-frame,magic:OPCRPS2\\0,domain:admission-port/profile-v2/response/v1,wire:AdmissionResponseWireV2(fresh:scope,registration,profile-v2-admission-provenance|replayed:scope|poll-admitted:scope,registration,admission,profile-v2-admission-provenance|terminal:scope,registration,admission,committed,profile-v2-admission-provenance|compacted:scope,history-epoch,profile-v2-terminal-conflict-tombstone|reject:scope,rejection)\n",
    "terminal-request-v2=postcard-frame,magic:OPCRPT2\\0,domain:terminal-port/profile-v2/request/v1,wire:TerminalRequestWireV2(scope,binding,registration,authority,record,profile-v2-admission-provenance,generic-compact-terminal-evidence),no-v1-bundle-or-voter-ingress\n",
    "terminal-response-v2=postcard-frame,magic:OPCRPU2\\0,domain:terminal-port/profile-v2/response/v1,wire:TerminalResponseWireV2(terminalized:scope,committed|replayed:scope,committed|admitted:scope|compacted:scope,history-epoch,profile-v2-terminal-conflict-tombstone|reject:scope,rejection),no-v1-tombstone\n",
    "bounds=admission-capsule,terminal-v2-capsule,terminal-v2-hello-frame,port-envelope-overhead;response=profile-v2-frames-only,no-v1-frame-probe\n"
).as_bytes();
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
    + MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES
    + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;

/// Maximum terminal-family capsule, including the committed terminal reply.
pub(crate) const MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES: usize =
    MAX_COMMITTED_TERMINAL_CODEC_BYTES
        + MAX_EXECUTOR_PROOF_BUNDLE_BYTES
        + MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES
        + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;

/// Maximum `/4` terminal inner capsule. Its V2 admission provenance and
/// generic executor evidence are client-supplied; the voter adds the fresh
/// typed ingress envelope only after authenticating the `/4` transport.
pub(crate) const MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES: usize =
    MAX_COMMITTED_TERMINAL_CODEC_BYTES
        + MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES
        + MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES
        + MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES;

/// Exact authenticated consumer Hello frame bound for a `/4` terminal
/// capsule. This is deliberately a V2-only value: `/3` retains its frozen
/// larger terminal envelope bound.
pub(crate) const MAX_PROTECTED_ROSTER_V2_TERMINAL_FRAME_BYTES: usize =
    MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES * 4 + 4 * 1024;

/// Digest the exact `/4` consumer-port carrier contract used in V2 activation.
///
/// This is public only through the crate-root compatibility re-export so the
/// network-side duplicate codec literals can assert equality with the durable
/// contract. It carries no caller material.
#[doc(hidden)]
pub fn protected_roster_v2_transport_compatibility_descriptor_digest() -> [u8; 32] {
    protected_roster_v2_transport_compatibility_descriptor_digest_for(
        PROTECTED_ROSTER_V2_TRANSPORT_COMPATIBILITY_DESCRIPTOR,
        [
            ADMISSION_REQUEST_V2_MAGIC,
            ADMISSION_RESPONSE_V2_MAGIC,
            TERMINAL_REQUEST_V2_MAGIC,
            TERMINAL_RESPONSE_V2_MAGIC,
        ],
        [
            ADMISSION_REQUEST_V2_DOMAIN,
            ADMISSION_RESPONSE_V2_DOMAIN,
            TERMINAL_REQUEST_V2_DOMAIN,
            TERMINAL_RESPONSE_V2_DOMAIN,
        ],
        [
            MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
            MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES,
            MAX_PROTECTED_ROSTER_V2_TERMINAL_FRAME_BYTES,
            MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES,
        ],
    )
}

fn protected_roster_v2_transport_compatibility_descriptor_digest_for(
    descriptor: &[u8],
    magics: [[u8; 8]; 4],
    domains: [&[u8]; 4],
    bounds: [usize; 4],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PROTECTED_ROSTER_V2_TRANSPORT_COMPATIBILITY_DESCRIPTOR_DOMAIN);
    h.update(descriptor);
    for magic in magics {
        h.update(b"\0magic:");
        h.update(magic);
    }
    for domain in domains {
        h.update(b"\0domain:");
        h.update(domain);
    }
    for bound in bounds {
        h.update((bound as u64).to_be_bytes());
    }
    h.finalize().into()
}

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
            SessionConsumerRosterRejection::RecordAlreadyExists => Self::RecordAlreadyExists,
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
    // Its revision-five discriminant is part of the persistent /3 wire ABI.
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
    // Rejections are carried by the outer consumer response. Keep the
    // revision-five capsule discriminant reserved for schema parity.
    #[allow(dead_code)]
    Reject {
        scope: [u8; 32],
        rejection: SessionConsumerRosterRejection,
    },
}

/// Disjoint `/4` admission response envelope. The fields intentionally
/// mirror V1 where the application response is the same, but its Postcard
/// enum lives behind a distinct framed domain and its provenance can only be
/// decoded as the V2 carrier.
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
struct TerminalRequestWire {
    scope: [u8; 32],
    binding: RequestBindingKey,
    registration: RegistrationWire,
    authority: AuthorityWire,
    record: Vec<u8>,
    proof_bundle: Vec<u8>,
    terminal_evidence: Vec<u8>,
}

/// V2 terminal requests carry retained V2 admission provenance and generic
/// executor evidence only. A client must never send a voter TransportIngress
/// attestation, a V1 executor bundle, or a V1 terminal evidence wrapper.
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

/// Disjoint `/4` terminal response envelope. It intentionally mirrors the
/// terminal decision shape while using an independent enum, frame magic, and
/// domain so a frozen `/3` response cannot be decoded after `/4` negotiation.
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

/// Reconstruct the exact opaque PollAdmit request capsule commitment carried
/// by a root-certified ingress statement. This has no provider or wall-clock
/// dependency and is shared by deterministic SQLite apply/followers.
pub(crate) fn roster_poll_admit_ingress_capsule_commitment(
    admission: &Admission,
    authority: &AuthorityBinding,
) -> Result<[u8; 32], ()> {
    let wire = AdmissionRequestWire::Register {
        scope: authority.ingress_scope().digest(),
        admission: admission.to_canonical_bytes().map_err(|_| ())?,
        authority: authority.into(),
    };
    roster_ingress_capsule_commitment(1, &encode_admission_request(&wire)?).map_err(|_| ())
}

/// Reconstruct the exact `/4` PollAdmit capsule commitment. The V1 helper
/// above is frozen and must never authenticate an `/4` frame.
pub(crate) fn roster_poll_admit_ingress_capsule_commitment_v2(
    admission: &Admission,
    authority: &AuthorityBinding,
) -> Result<[u8; 32], ()> {
    if admission.profile() != crate::fenced_mutation_roster::Profile::v2() {
        return Err(());
    }
    let wire = AdmissionRequestWire::Register {
        scope: authority.ingress_scope().digest(),
        admission: admission.to_canonical_bytes().map_err(|_| ())?,
        authority: authority.into(),
    };
    roster_ingress_capsule_commitment(1, &encode_admission_request_v2(&wire)?).map_err(|_| ())
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
    terminal_evidence: &RosterCompactTerminalEvidenceV2,
) -> Result<[u8; 32], ()> {
    let wire = TerminalRequestWire {
        scope: authority.ingress_scope().digest(),
        binding,
        registration: RegistrationWire::from_registration(registration),
        authority: authority.into(),
        record: terminal.to_canonical_bytes(admission).map_err(|_| ())?,
        proof_bundle: proof_bundle.canonical_bytes().map_err(|_| ())?,
        terminal_evidence: terminal_evidence.canonical_bytes().map_err(|_| ())?,
    };
    roster_ingress_capsule_commitment(4, &encode_terminal_request(&wire)?).map_err(|_| ())
}

/// Reconstruct the `/4` terminal capsule commitment from only Profile V2
/// carriers.  The frozen V1 helper remains intentionally separate: accepting
/// a V2 proof through it would make the carrier choice depend on decode order.
pub(crate) fn roster_terminal_ingress_capsule_commitment_v2(
    binding: RequestBindingKey,
    registration: BackendRegistration,
    authority: &AuthorityBinding,
    terminal: &TerminalRecord,
    admission: &Admission,
    admission_provenance: &RosterProfileV2CompactAdmissionProvenanceV1,
    terminal_evidence: &RosterCompactTerminalEvidenceV2,
) -> Result<[u8; 32], ()> {
    if admission.profile() != crate::fenced_mutation_roster::Profile::v2() {
        return Err(());
    }
    let wire = TerminalRequestWireV2 {
        scope: authority.ingress_scope().digest(),
        binding,
        registration: RegistrationWire::from_registration(registration),
        authority: authority.into(),
        record: terminal.to_canonical_bytes(admission).map_err(|_| ())?,
        admission_provenance: admission_provenance.canonical_bytes().map_err(|_| ())?,
        terminal_evidence: terminal_evidence.canonical_bytes().map_err(|_| ())?,
    };
    roster_ingress_capsule_commitment(4, &encode_terminal_request_v2(&wire)?).map_err(|_| ())
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

fn encode_admission_response_v2(wire: &AdmissionResponseWireV2) -> Result<Vec<u8>, ()> {
    encode_frame(
        ADMISSION_RESPONSE_V2_MAGIC,
        ADMISSION_RESPONSE_V2_DOMAIN,
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

fn response_scope(consumer_scope: SessionConsumerScope) -> [u8; 32] {
    protected_roster_scope_from_consumer_scope(consumer_scope).digest()
}

fn admission_bytes_for_consumer_scope(
    _consumer_scope: SessionConsumerScope,
    admission: &Admission,
) -> Result<Vec<u8>, ProtectedRosterTransportError> {
    admission
        .to_canonical_bytes()
        .map_err(|_| ProtectedRosterTransportError)
}

fn admission_provenance_bytes(
    provenance: &RosterCompactAdmissionProvenanceV2,
) -> Result<Vec<u8>, ProtectedRosterTransportError> {
    provenance
        .canonical_bytes()
        .map_err(|_| ProtectedRosterTransportError)
}

fn admission_provenance_v2_bytes(
    provenance: &RosterProfileV2CompactAdmissionProvenanceV1,
) -> Result<Vec<u8>, ProtectedRosterTransportError> {
    provenance
        .canonical_bytes()
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

fn admission_response_capsule_v2(
    wire: AdmissionResponseWireV2,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    SessionConsumerRosterAdmissionCapsule::new(
        encode_admission_response_v2(&wire).map_err(|_| ProtectedRosterTransportError)?,
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

fn terminal_response_capsule_v2(
    wire: TerminalResponseWireV2,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    SessionConsumerRosterTerminalCapsule::new(
        encode_terminal_response_v2(&wire).map_err(|_| ProtectedRosterTransportError)?,
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
    admission_provenance: &RosterCompactAdmissionProvenanceV2,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    admission_response_capsule(AdmissionResponseWire::Fresh {
        scope: response_scope(consumer_scope),
        registration: RegistrationWire::from_registration(registration),
        admission_provenance: admission_provenance_bytes(admission_provenance)?,
    })
}

/// Encode the `/4` fresh admission reply with only the Profile V2 compact
/// provenance carrier. The wire envelope is frozen; the profile-specific
/// client decoder selects this variant only after `/4` negotiation.
#[doc(hidden)]
pub(crate) fn encode_admission_fresh_response_v2(
    consumer_scope: SessionConsumerScope,
    registration: BackendRegistration,
    admission_provenance: &RosterProfileV2CompactAdmissionProvenanceV1,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    admission_response_capsule_v2(AdmissionResponseWireV2::Fresh {
        scope: response_scope(consumer_scope),
        registration: RegistrationWire::from_registration(registration),
        admission_provenance: admission_provenance_v2_bytes(admission_provenance)?,
    })
}

/// Encode an admitted stable-slot replay without issuing an execution
/// capability. The consumer must use the authenticated recovery read path.
#[doc(hidden)]
pub(crate) fn encode_admission_replayed_response(
    consumer_scope: SessionConsumerScope,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    admission_response_capsule(AdmissionResponseWire::Replayed {
        scope: response_scope(consumer_scope),
    })
}

/// Encode a `/4` stable-slot replay. This must not use the frozen `/3`
/// response envelope, even though its body has no profile-specific fields.
#[doc(hidden)]
pub(crate) fn encode_admission_replayed_response_v2(
    consumer_scope: SessionConsumerScope,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    admission_response_capsule_v2(AdmissionResponseWireV2::Replayed {
        scope: response_scope(consumer_scope),
    })
}

/// Encode a read-only nonterminal roster recovery response.
#[doc(hidden)]
pub(crate) fn encode_admission_poll_admitted_response(
    consumer_scope: SessionConsumerScope,
    registration: BackendRegistration,
    admission: &Admission,
    admission_provenance: &RosterCompactAdmissionProvenanceV2,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    admission_response_capsule(AdmissionResponseWire::PollAdmitted {
        scope: response_scope(consumer_scope),
        registration: RegistrationWire::from_registration(registration),
        admission: admission_bytes_for_consumer_scope(consumer_scope, admission)?,
        admission_provenance: admission_provenance_bytes(admission_provenance)?,
    })
}

/// Encode a `/4` live admission response without substituting V1 provenance.
#[doc(hidden)]
pub(crate) fn encode_admission_poll_admitted_response_v2(
    consumer_scope: SessionConsumerScope,
    registration: BackendRegistration,
    admission: &Admission,
    admission_provenance: &RosterProfileV2CompactAdmissionProvenanceV1,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    if admission.profile() != crate::fenced_mutation_roster::Profile::v2() {
        return Err(ProtectedRosterTransportError);
    }
    admission_response_capsule_v2(AdmissionResponseWireV2::PollAdmitted {
        scope: response_scope(consumer_scope),
        registration: RegistrationWire::from_registration(registration),
        admission: admission_bytes_for_consumer_scope(consumer_scope, admission)?,
        admission_provenance: admission_provenance_v2_bytes(admission_provenance)?,
    })
}

/// Encode a read-only committed-terminal recovery response.
#[doc(hidden)]
pub(crate) fn encode_admission_terminal_response(
    consumer_scope: SessionConsumerScope,
    registration: BackendRegistration,
    admission: &Admission,
    committed: &CommittedTerminal,
    admission_provenance: &RosterCompactAdmissionProvenanceV2,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    admission_response_capsule(AdmissionResponseWire::Terminal {
        scope: response_scope(consumer_scope),
        registration: RegistrationWire::from_registration(registration),
        admission: admission_bytes_for_consumer_scope(consumer_scope, admission)?,
        committed: committed
            .to_canonical_bytes(admission)
            .map_err(|_| ProtectedRosterTransportError)?,
        admission_provenance: admission_provenance_bytes(admission_provenance)?,
    })
}

/// Encode a `/4` terminal recovery response with its retained V2 provenance.
#[doc(hidden)]
pub(crate) fn encode_admission_terminal_response_v2(
    consumer_scope: SessionConsumerScope,
    registration: BackendRegistration,
    admission: &Admission,
    committed: &CommittedTerminal,
    admission_provenance: &RosterProfileV2CompactAdmissionProvenanceV1,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    if admission.profile() != crate::fenced_mutation_roster::Profile::v2() {
        return Err(ProtectedRosterTransportError);
    }
    admission_response_capsule_v2(AdmissionResponseWireV2::Terminal {
        scope: response_scope(consumer_scope),
        registration: RegistrationWire::from_registration(registration),
        admission: admission_bytes_for_consumer_scope(consumer_scope, admission)?,
        committed: committed
            .to_canonical_bytes(admission)
            .map_err(|_| ProtectedRosterTransportError)?,
        admission_provenance: admission_provenance_v2_bytes(admission_provenance)?,
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

/// Encode a `/4` compact-admission response with only a Profile V2 compact
/// tombstone. This is deliberately not a projection of the frozen V1
/// tombstone: an old carrier must fail frame decoding after `/4` negotiation.
#[doc(hidden)]
pub(crate) fn encode_admission_compacted_response_v2(
    consumer_scope: SessionConsumerScope,
    history_epoch: u64,
    tombstone: &TerminalConflictTombstone,
) -> Result<SessionConsumerRosterAdmissionCapsule, ProtectedRosterTransportError> {
    if history_epoch == 0 {
        return Err(ProtectedRosterTransportError);
    }
    admission_response_capsule_v2(AdmissionResponseWireV2::Compacted {
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

fn encode_terminal_committed_bytes_response_v2(
    consumer_scope: SessionConsumerScope,
    committed: Vec<u8>,
    replayed: bool,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    if committed.is_empty() || committed.len() > MAX_COMMITTED_TERMINAL_CODEC_BYTES {
        return Err(ProtectedRosterTransportError);
    }
    let scope = response_scope(consumer_scope);
    let wire = if replayed {
        TerminalResponseWireV2::Replayed { scope, committed }
    } else {
        TerminalResponseWireV2::Terminalized { scope, committed }
    };
    terminal_response_capsule_v2(wire)
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

/// Wrap Profile V2 terminal bytes in the disjoint `/4` response frame.
#[doc(hidden)]
pub(crate) fn encode_terminal_terminalized_bytes_response_v2(
    consumer_scope: SessionConsumerScope,
    committed: Vec<u8>,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    encode_terminal_committed_bytes_response_v2(consumer_scope, committed, false)
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
    let _ = admission;
    encode_terminal_committed_bytes_response(consumer_scope, committed, false)
}

/// Wrap a validated Profile V2 terminal status reply in the `/4` frame.
#[doc(hidden)]
pub(crate) fn encode_terminal_terminalized_validated_bytes_response_v2(
    consumer_scope: SessionConsumerScope,
    admission: &Admission,
    committed: Vec<u8>,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    let _ = admission;
    encode_terminal_committed_bytes_response_v2(consumer_scope, committed, false)
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

/// Wrap a Profile V2 terminal replay in the disjoint `/4` response frame.
#[doc(hidden)]
pub(crate) fn encode_terminal_replayed_bytes_response_v2(
    consumer_scope: SessionConsumerScope,
    committed: Vec<u8>,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    encode_terminal_committed_bytes_response_v2(consumer_scope, committed, true)
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

/// Encode a Profile V2 nonterminal terminal-status reply in the `/4` frame.
#[doc(hidden)]
pub(crate) fn encode_terminal_admitted_response_v2(
    consumer_scope: SessionConsumerScope,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    terminal_response_capsule_v2(TerminalResponseWireV2::Admitted {
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

/// Encode a Profile V2 compact-terminal response with the independently
/// framed Profile V2 tombstone. A frozen V1 tombstone has no conversion into
/// this carrier and cannot reach the `/4` response lane.
#[doc(hidden)]
pub(crate) fn encode_terminal_compacted_response_v2(
    consumer_scope: SessionConsumerScope,
    history_epoch: u64,
    tombstone: &TerminalConflictTombstone,
) -> Result<SessionConsumerRosterTerminalCapsule, ProtectedRosterTransportError> {
    if history_epoch == 0 {
        return Err(ProtectedRosterTransportError);
    }
    terminal_response_capsule_v2(TerminalResponseWireV2::Compacted {
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
            original_owner,
            original_admission_fence,
            authority,
        } => {
            expect_scope(actual, scope).map_err(|_| ProtectedRosterTransportError)?;
            let authority = authority
                .into_authority(scope)
                .map_err(|_| ProtectedRosterTransportError)?;
            let request = RecoveryRequest::new(RecoveryRequestInput::new(
                RecoveryLookup::new(scope, roster_id),
                original_owner,
                original_admission_fence,
                authority,
            ))
            .map_err(|_| ProtectedRosterTransportError)?;
            Ok(DecodedAdmissionRequest::Recover(request))
        }
    }
}

/// Decode only a separately framed `/4` admission request. The caller must
/// have selected the negotiated V2 profile before this point; this function
/// never probes the V1 frame as a fallback.
#[doc(hidden)]
pub(crate) fn decode_admission_request_for_scope_v2(
    capsule: &SessionConsumerRosterAdmissionCapsule,
    consumer_scope: SessionConsumerScope,
) -> Result<DecodedAdmissionRequest, ProtectedRosterTransportError> {
    let scope = protected_roster_scope_from_consumer_scope(consumer_scope);
    let wire: AdmissionRequestWire = decode_frame(
        capsule.canonical_bytes(),
        ADMISSION_REQUEST_V2_MAGIC,
        ADMISSION_REQUEST_V2_DOMAIN,
        MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    )
    .map_err(|_| ProtectedRosterTransportError)?;
    if encode_admission_request_v2(&wire).ok().as_deref() != Some(capsule.canonical_bytes()) {
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
            if admission.profile() != crate::fenced_mutation_roster::Profile::v2() {
                return Err(ProtectedRosterTransportError);
            }
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
            original_owner,
            original_admission_fence,
            authority,
        } => {
            expect_scope(actual, scope).map_err(|_| ProtectedRosterTransportError)?;
            let authority = authority
                .into_authority(scope)
                .map_err(|_| ProtectedRosterTransportError)?;
            let request = RecoveryRequest::new(RecoveryRequestInput::new(
                RecoveryLookup::new(scope, roster_id),
                original_owner,
                original_admission_fence,
                authority,
            ))
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
        terminal_evidence: RosterCompactTerminalEvidenceV2::decode_canonical(
            &wire.terminal_evidence,
        )
        .map_err(|_| ProtectedRosterTransportError)?
        .canonical_bytes()
        .map_err(|_| ProtectedRosterTransportError)?,
    })
}

/// Decode a `/4` terminal port request after the listener has authenticated
/// the negotiated Profile V2 ingress. This deliberately decodes only the V2
/// proof/evidence carriers: callers must never use it as a speculative
/// fallback for the frozen `/3` lane.
#[doc(hidden)]
pub(crate) fn decode_terminal_request_for_scope_v2(
    capsule: &SessionConsumerRosterTerminalCapsule,
    consumer_scope: SessionConsumerScope,
) -> Result<DecodedTerminalRequestV2, ProtectedRosterTransportError> {
    let scope = protected_roster_scope_from_consumer_scope(consumer_scope);
    let wire: TerminalRequestWireV2 = decode_frame(
        capsule.canonical_bytes(),
        TERMINAL_REQUEST_V2_MAGIC,
        TERMINAL_REQUEST_V2_DOMAIN,
        MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES,
    )
    .map_err(|_| ProtectedRosterTransportError)?;
    if encode_terminal_request_v2(&wire).ok().as_deref() != Some(capsule.canonical_bytes()) {
        return Err(ProtectedRosterTransportError);
    }
    expect_scope(wire.scope, scope).map_err(|_| ProtectedRosterTransportError)?;
    Ok(DecodedTerminalRequestV2 {
        binding: wire.binding,
        registration: wire.registration,
        authority: wire
            .authority
            .into_authority(scope)
            .map_err(|_| ProtectedRosterTransportError)?,
        record: wire.record,
        admission_provenance: RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(
            &wire.admission_provenance,
        )
        .map_err(|_| ProtectedRosterTransportError)?
        .canonical_bytes()
        .map_err(|_| ProtectedRosterTransportError)?,
        terminal_evidence: RosterCompactTerminalEvidenceV2::decode_canonical(
            &wire.terminal_evidence,
        )
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
    terminal_evidence: Vec<u8>,
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

    /// Decode the direct per-member compact terminal evidence.  The raw V1
    /// bundle remains available only for the initial correspondence check.
    pub(crate) fn terminal_evidence(
        &self,
    ) -> Result<RosterCompactTerminalEvidenceV2, ProtectedRosterTransportError> {
        RosterCompactTerminalEvidenceV2::decode_canonical(&self.terminal_evidence)
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
        let authority =
            AuthorityBinding::for_validated_admission(admission, &self.authority, false)
                .map_err(|_| ProtectedRosterTransportError)?;
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
        Ok((registration, authority, body))
    }
}

/// SDK-private `/4` terminal request awaiting its exact V2 admission lookup.
#[doc(hidden)]
pub(crate) struct DecodedTerminalRequestV2 {
    binding: RequestBindingKey,
    registration: RegistrationWire,
    authority: AuthorityBinding,
    record: Vec<u8>,
    admission_provenance: Vec<u8>,
    terminal_evidence: Vec<u8>,
}

impl DecodedTerminalRequestV2 {
    pub(crate) const fn binding(&self) -> RequestBindingKey {
        self.binding
    }

    pub(crate) fn registration_parts(&self) -> ([u8; 32], RequestId, [u8; 32]) {
        (
            self.registration.handle,
            self.registration.request_id,
            self.registration.terminal_slot,
        )
    }

    pub(crate) fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }

    pub(crate) fn canonical_record(&self) -> &[u8] {
        &self.record
    }

    /// Decode exactly the retained V2 admission provenance supplied by the
    /// executor. The service cross-checks it against durable V2 state before
    /// constructing the voter-side proof/evidence envelopes.
    pub(crate) fn admission_provenance(
        &self,
    ) -> Result<RosterProfileV2CompactAdmissionProvenanceV1, ProtectedRosterTransportError> {
        RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(&self.admission_provenance)
            .map_err(|_| ProtectedRosterTransportError)
    }

    pub(crate) fn terminal_evidence(
        &self,
    ) -> Result<RosterCompactTerminalEvidenceV2, ProtectedRosterTransportError> {
        RosterCompactTerminalEvidenceV2::decode_canonical(&self.terminal_evidence)
            .map_err(|_| ProtectedRosterTransportError)
    }

    pub(crate) fn terminal_body_commitment(
        &self,
    ) -> Result<[u8; 32], ProtectedRosterTransportError> {
        TerminalRecord::canonical_body_commitment(&self.record)
            .map_err(|_| ProtectedRosterTransportError)
    }

    pub(crate) fn into_terminal_request(
        self,
        admission: &Admission,
    ) -> Result<(BackendRegistration, AuthorityBinding, TerminalBody), ProtectedRosterTransportError>
    {
        let authority =
            AuthorityBinding::for_validated_admission(admission, &self.authority, false)
                .map_err(|_| ProtectedRosterTransportError)?;
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
        Ok((registration, authority, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity, SessionKeyType, StableId,
    };
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};

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
    fn profile_v2_terminal_response_frame_rejects_the_frozen_v1_lane() {
        let scope = [0xB1; 32];
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
            "a frozen V1 terminal response cannot enter the /4 encoder contract"
        );
        assert!(
            decode_frame::<TerminalResponseWire>(
                &v2,
                TERMINAL_RESPONSE_MAGIC,
                TERMINAL_RESPONSE_DOMAIN,
                MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
            )
            .is_err(),
            "a /4 terminal response cannot enter the frozen V1 encoder contract"
        );
    }

    #[test]
    fn recovery_wire_keeps_original_tuple_distinct_from_current_successor() {
        let consumer_scope = consumer_scope(0xB6, 10);
        let scope = protected_roster_scope_from_consumer_scope(consumer_scope);
        let original_owner = OwnerId::new("recovery-original-owner").expect("owner");
        let original_fence = FenceToken::new(7);
        let acquired_at = Timestamp::now_utc();
        let expires_at = acquired_at.add_seconds(60).expect("lease expiry");
        let key = SessionKey {
            tenant: TenantId::from_static("recovery-wire-tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"recovery-wire-key")).expect("stable ID"),
        };
        let authority = AuthorityWire {
            key,
            owner: OwnerId::new("recovery-successor-owner").expect("successor owner"),
            fence: FenceToken::new(8),
            credential_id: 11,
            generation: Generation::new(3),
            acquired_at,
            expires_at,
        };
        let wire = AdmissionRequestWire::Recover {
            scope: scope.digest(),
            roster_id: RosterId::from_bytes([0xB7; 16]).expect("roster ID"),
            original_owner: original_owner.clone(),
            original_admission_fence: original_fence,
            authority,
        };
        let capsule = SessionConsumerRosterAdmissionCapsule::new(
            encode_admission_request(&wire).expect("canonical recovery request"),
        )
        .expect("recovery capsule");
        let DecodedAdmissionRequest::Recover(decoded) =
            decode_admission_request_for_scope(&capsule, consumer_scope)
                .expect("strictly newer recovery request")
        else {
            panic!("recovery wire must remain a recovery request");
        };
        assert_eq!(decoded.original_owner(), &original_owner);
        assert_eq!(decoded.original_admission_fence(), original_fence);
        assert!(decoded.authority().fence() > decoded.original_admission_fence());

        let non_successor = AdmissionRequestWire::Recover {
            scope: scope.digest(),
            roster_id: RosterId::from_bytes([0xB7; 16]).expect("roster ID"),
            original_owner,
            original_admission_fence: original_fence,
            authority: AuthorityWire {
                key: decoded.authority().key().clone(),
                owner: decoded.authority().owner().clone(),
                fence: original_fence,
                credential_id: decoded.authority().credential_id(),
                generation: decoded.authority().generation(),
                acquired_at,
                expires_at,
            },
        };
        let capsule = SessionConsumerRosterAdmissionCapsule::new(
            encode_admission_request(&non_successor).expect("canonical non-successor request"),
        )
        .expect("non-successor capsule");
        assert!(
            decode_admission_request_for_scope(&capsule, consumer_scope).is_err(),
            "an equal current fence is rejected before any durable lookup"
        );
    }

    #[test]
    fn revision_five_response_discriminants_remain_frozen() {
        let scope = [0xB2; 32];

        // Reject is intentionally producer-unused. The revision-five replay
        // position remains between Fresh and the active recovery responses:
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
    fn admission_replayed_response_is_canonical_and_scope_bound() {
        let scope = consumer_scope(0xB3, 8);
        let capsule = encode_admission_replayed_response(scope).expect("bounded response");
        let decoded: AdmissionResponseWire = decode_frame(
            capsule.canonical_bytes(),
            ADMISSION_RESPONSE_MAGIC,
            ADMISSION_RESPONSE_DOMAIN,
            MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
        )
        .expect("canonical response decodes");
        assert_eq!(
            encode_admission_response(&decoded).expect("response reencodes"),
            capsule.canonical_bytes(),
        );
        assert!(expect_scope(
            match decoded {
                AdmissionResponseWire::Replayed { scope } => scope,
                _ => unreachable!("encoded replay response"),
            },
            protected_roster_scope_from_consumer_scope(consumer_scope(0xB4, 8)),
        )
        .is_err());
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
