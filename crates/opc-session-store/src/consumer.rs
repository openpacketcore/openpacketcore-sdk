//! Least-authority application consumer contract for a session quorum.
//!
//! This module intentionally models only application state and lease
//! operations. It has no Openraft member, vote, topology, snapshot, or raw
//! replication-rebuild operation. A transport authenticates a
//! [`SessionConsumerIdentity`] separately from quorum members, then forwards
//! the typed request to a quorum-side implementation of
//! [`SessionQuorumConsumer`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::backend::ProtectedRosterEstablishedSuccessor;
use crate::consensus::types::{
    validate_fenced_transition_v2_batch, MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS,
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_REQUEST_BYTES,
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_RESPONSE_BYTES,
};
use crate::fenced_mutation_roster::RosterAttestationTrustRootIdentityV1;
use crate::{
    AtomicFencedTransitionCapability, BackendCapabilities, CompareAndSet, CompareAndSetResult,
    FenceToken, FencedTransitionObservation, FencedTransitionOutcome, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionStatus, FencedTransitionV2Capability,
    FencedTransitionV2HistoryState, FencedTransitionV2Request, FencedTransitionV2RequestId,
    FencedTransitionV2Status, Generation, LeaseError, LeaseGuard, OwnerId, QuorumReplicaDescriptor,
    RecordExpiryPreflight, RestoreScanPage, RestoreScanRequest, SessionConsensusIdentity,
    SessionConsensusNodeId, SessionConsensusRequestId, SessionKey, SessionOp, SessionOpResult,
    StoreError, StoredSessionRecord, Timestamp, FENCED_TRANSITION_REQUEST_ID_BYTES,
    FENCED_TRANSITION_V2_MAX_PAYLOAD_TOO_LARGE_ACTUAL_BYTES,
    FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES, QUORUM_TOPOLOGY_MAX_MEMBERS,
};

#[cfg(test)]
use crate::MAX_REPLICATION_OPERATIONS_PER_ENTRY;

/// Maximum batch slots admitted by one consumer request.
pub const MAX_SESSION_CONSUMER_BATCH_OPERATIONS: usize = 256;

/// Maximum serialized batch response bytes retained for one consumer request.
///
/// This is deliberately lower than the transport frame ceiling. It bounds the
/// aggregate of otherwise individually valid point-read results before the
/// quorum service retains them in a batch response.
pub const MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum V2 fenced transitions admitted by one protected batch request.
pub const MAX_SESSION_CONSUMER_V2_FENCED_TRANSITION_BATCH_OPERATIONS: usize =
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS;

/// Maximum fully Postcard-encoded V2 fenced-transition batch request bytes.
pub const MAX_SESSION_CONSUMER_V2_FENCED_TRANSITION_BATCH_REQUEST_BYTES: usize =
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_REQUEST_BYTES;

/// Maximum fully Postcard-encoded V2 fenced-transition batch response bytes.
pub const MAX_SESSION_CONSUMER_V2_FENCED_TRANSITION_BATCH_RESPONSE_BYTES: usize =
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_RESPONSE_BYTES;

/// Maximum projected watch bytes queued for one authenticated consumer.
///
/// The consumer registry applies this bound before it clones a change to a
/// subscriber, so a large raw replication entry cannot multiply by consumer
/// connections in the backend's watch queues.
pub const MAX_SESSION_CONSUMER_WATCH_BUFFER_BYTES: usize = 256 * 1024;

/// Fixed byte width of one durable consumer request identity.
pub const SESSION_CONSUMER_REQUEST_ID_BYTES: usize = 16;

/// Maximum UTF-8 width of an authenticated consumer identity.
pub const SESSION_CONSUMER_IDENTITY_MAX_BYTES: usize = 253;

/// ALPN selected only by the protected fenced-mutation-roster consumer
/// capability.
///
/// This is deliberately separate from the general consumer lane. A peer that
/// did not opt into this ALPN cannot submit a roster capsule.
pub const SESSION_CONSUMER_ROSTER_ALPN: &[u8] = b"opc-session-consumer/3";

/// Wire revision required by [`SESSION_CONSUMER_ROSTER_ALPN`].
pub const SESSION_CONSUMER_ROSTER_TRANSPORT_REVISION: u16 = 5;

/// ALPN selected only by the additive V2 protected-roster capability.
///
/// This deliberately differs from [`SESSION_CONSUMER_ROSTER_ALPN`], so a
/// V1 peer cannot interpret an absent-predecessor operation as a V1 roster
/// operation before the exact Hello profile is checked.
pub const SESSION_CONSUMER_ROSTER_V2_ALPN: &[u8] = b"opc-session-consumer/4";

/// Wire revision required by [`SESSION_CONSUMER_ROSTER_V2_ALPN`].
pub const SESSION_CONSUMER_ROSTER_V2_TRANSPORT_REVISION: u16 = 6;

/// Largest byte-exact canonical admission capsule accepted by the consumer
/// boundary. One admission remains one quorum mutation.
pub const MAX_SESSION_CONSUMER_ROSTER_ADMISSION_CAPSULE_BYTES: usize =
    crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES;

/// Largest byte-exact canonical terminal capsule accepted by the consumer
/// boundary. This includes the committed-terminal receipt envelope.
pub const MAX_SESSION_CONSUMER_ROSTER_TERMINAL_CAPSULE_BYTES: usize =
    crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES;

/// Largest byte-exact `/4` terminal capsule accepted by the consumer
/// boundary. Unlike `/3`, this contains retained V2 provenance plus generic
/// compact terminal evidence and never a V1 executor bundle.
pub const MAX_SESSION_CONSUMER_ROSTER_V2_TERMINAL_CAPSULE_BYTES: usize =
    crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_V2_TERMINAL_CAPSULE_BYTES;

/// Largest authenticated consumer JSON frame accepted for a complete
/// protected-roster admission capsule and its consumer envelope.
pub const MAX_SESSION_CONSUMER_ROSTER_ADMISSION_FRAME_BYTES: usize =
    MAX_SESSION_CONSUMER_ROSTER_ADMISSION_CAPSULE_BYTES * 4 + 4 * 1024;

/// Largest authenticated consumer JSON frame accepted for a complete
/// protected-roster terminal capsule and its consumer envelope.
pub const MAX_SESSION_CONSUMER_ROSTER_TERMINAL_FRAME_BYTES: usize =
    MAX_SESSION_CONSUMER_ROSTER_TERMINAL_CAPSULE_BYTES * 4 + 4 * 1024;

/// Largest authenticated consumer JSON frame accepted for a complete `/4`
/// terminal capsule and its consumer envelope.
pub const MAX_SESSION_CONSUMER_ROSTER_V2_TERMINAL_FRAME_BYTES: usize =
    crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_V2_TERMINAL_FRAME_BYTES;

/// Exact profile negotiated before a protected-roster consumer operation is
/// admitted.
///
/// The roster profile is opaque at this boundary: consumers can compare it
/// only as one fixed capability, never relax individual resource or semantic
/// limits. Its frame fields apply only to the consumer envelope.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerRosterTransportProfile {
    roster_profile: crate::fenced_mutation_roster::Profile,
    admission_capsule_bytes: u32,
    terminal_capsule_bytes: u32,
    admission_frame_bytes: u32,
    terminal_frame_bytes: u32,
}

impl SessionConsumerRosterTransportProfile {
    /// Return the frozen V1 roster profile.
    pub fn current() -> Self {
        Self {
            roster_profile: crate::fenced_mutation_roster::Profile::v1(),
            admission_capsule_bytes: MAX_SESSION_CONSUMER_ROSTER_ADMISSION_CAPSULE_BYTES as u32,
            terminal_capsule_bytes: MAX_SESSION_CONSUMER_ROSTER_TERMINAL_CAPSULE_BYTES as u32,
            admission_frame_bytes: MAX_SESSION_CONSUMER_ROSTER_ADMISSION_FRAME_BYTES as u32,
            terminal_frame_bytes: MAX_SESSION_CONSUMER_ROSTER_TERMINAL_FRAME_BYTES as u32,
        }
    }

    /// Return the additive V2 roster profile for absent-predecessor admission.
    pub fn v2() -> Self {
        Self {
            roster_profile: crate::fenced_mutation_roster::Profile::v2(),
            admission_capsule_bytes: MAX_SESSION_CONSUMER_ROSTER_ADMISSION_CAPSULE_BYTES as u32,
            terminal_capsule_bytes: MAX_SESSION_CONSUMER_ROSTER_V2_TERMINAL_CAPSULE_BYTES as u32,
            admission_frame_bytes: MAX_SESSION_CONSUMER_ROSTER_ADMISSION_FRAME_BYTES as u32,
            terminal_frame_bytes: MAX_SESSION_CONSUMER_ROSTER_V2_TERMINAL_FRAME_BYTES as u32,
        }
    }

    /// Return whether this is exactly the frozen V1 profile.
    pub fn is_current(self) -> bool {
        self == Self::current()
    }

    /// Return whether this is exactly the additive V2 profile.
    pub fn is_v2(self) -> bool {
        self == Self::v2()
    }

    /// Return the exact frame budget required for a whole admission capsule.
    pub const fn admission_frame_bytes(self) -> usize {
        self.admission_frame_bytes as usize
    }

    /// Return the exact canonical terminal capsule budget for this profile.
    pub const fn terminal_capsule_bytes(self) -> usize {
        self.terminal_capsule_bytes as usize
    }

    /// Return the exact frame budget required for a whole terminal capsule.
    pub const fn terminal_frame_bytes(self) -> usize {
        self.terminal_frame_bytes as usize
    }
}

impl fmt::Debug for SessionConsumerRosterTransportProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterTransportProfile(<redacted>)")
    }
}

/// Redaction-safe invalid protected-roster capsule error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid protected roster capsule")]
pub struct SessionConsumerRosterCapsuleError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionConsumerRosterCapsuleWire {
    bytes: Vec<u8>,
}

fn validate_session_consumer_roster_capsule(
    bytes: &[u8],
    maximum: usize,
) -> Result<(), SessionConsumerRosterCapsuleError> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err(SessionConsumerRosterCapsuleError)
    } else {
        Ok(())
    }
}

/// Fixed-width canonical bytes of the durable protected-roster request
/// identity.  Serde's built-in array implementation intentionally stops
/// below this width, so preserve the bound with a tiny tuple codec instead of
/// widening the identity to a caller-sized byte vector.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RosterCurrentAuthorityRequestIdBytes([u8; 56]);

impl Serialize for RosterCurrentAuthorityRequestIdBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        let mut tuple = serializer.serialize_tuple(self.0.len())?;
        for byte in self.0 {
            tuple.serialize_element(&byte)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for RosterCurrentAuthorityRequestIdBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = RosterCurrentAuthorityRequestIdBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a fixed 56-byte roster request identity")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0; 56];
                for byte in &mut bytes {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                }
                if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(57, &self));
                }
                Ok(RosterCurrentAuthorityRequestIdBytes(bytes))
            }
        }

        deserializer.deserialize_tuple(56, BytesVisitor)
    }
}

/// Opaque canonical bytes for one protected-roster admission request or its
/// admission/recovery response.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SessionConsumerRosterAdmissionCapsule {
    bytes: Vec<u8>,
}

impl SessionConsumerRosterAdmissionCapsule {
    /// Construct one bounded opaque admission capsule from canonical SDK bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SessionConsumerRosterCapsuleError> {
        validate_session_consumer_roster_capsule(
            &bytes,
            MAX_SESSION_CONSUMER_ROSTER_ADMISSION_CAPSULE_BYTES,
        )?;
        Ok(Self { bytes })
    }

    /// Return the bounded canonical byte length without exposing its contents.
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the canonical capsule is empty.
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow the bounded opaque bytes for an SDK transport adapter.
    #[doc(hidden)]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'de> Deserialize<'de> for SessionConsumerRosterAdmissionCapsule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SessionConsumerRosterCapsuleWire::deserialize(deserializer)?;
        Self::new(wire.bytes).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SessionConsumerRosterAdmissionCapsule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterAdmissionCapsule(<redacted>)")
    }
}

/// Opaque canonical bytes for one protected-roster terminal request, terminal
/// status, or terminal response.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SessionConsumerRosterTerminalCapsule {
    bytes: Vec<u8>,
}

impl SessionConsumerRosterTerminalCapsule {
    /// Construct one bounded opaque terminal capsule from canonical SDK bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SessionConsumerRosterCapsuleError> {
        validate_session_consumer_roster_capsule(
            &bytes,
            MAX_SESSION_CONSUMER_ROSTER_TERMINAL_CAPSULE_BYTES,
        )?;
        Ok(Self { bytes })
    }

    /// Return the bounded canonical byte length without exposing its contents.
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the canonical capsule is empty.
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow the bounded opaque bytes for an SDK transport adapter.
    #[doc(hidden)]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'de> Deserialize<'de> for SessionConsumerRosterTerminalCapsule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SessionConsumerRosterCapsuleWire::deserialize(deserializer)?;
        Self::new(wire.bytes).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SessionConsumerRosterTerminalCapsule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterTerminalCapsule(<redacted>)")
    }
}

/// Authenticated, read-only current-publication-authority query carried only
/// by the revision-five protected-roster consumer lane.
///
/// This is deliberately a query capsule rather than a caller-minted
/// publication authority: the quorum resolves the retained admission and
/// Established receipt, then compares every field with its own current
/// authority under a linearizable read barrier.  Constructing this value
/// therefore grants no authority and cannot make a publication eligible.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerRosterCurrentPublicationAuthorityCapsule {
    scope: [u8; 32],
    key: SessionKey,
    roster_id: [u8; 16],
    admission_commitment: [u8; 32],
    terminal_body_commitment: [u8; 32],
    receipt_commitment: [u8; 32],
    logical_owner: OwnerId,
    admission_fence: FenceToken,
    registration_handle: [u8; 32],
    registration_request_id: RosterCurrentAuthorityRequestIdBytes,
    registration_terminal_slot: [u8; 32],
    current_owner: OwnerId,
    current_fence: FenceToken,
    current_credential_id: u64,
    current_generation: Generation,
    current_lease_acquired_at: Timestamp,
    current_lease_expires_at: Timestamp,
}

impl SessionConsumerRosterCurrentPublicationAuthorityCapsule {
    /// Bind one complete, untrusted query to the identity claimed by the
    /// publication adapter.  The dedicated quorum ingress validates it
    /// against durable state before reporting success.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: [u8; 32],
        key: SessionKey,
        roster_id: [u8; 16],
        admission_commitment: [u8; 32],
        terminal_body_commitment: [u8; 32],
        receipt_commitment: [u8; 32],
        logical_owner: OwnerId,
        admission_fence: FenceToken,
        registration_handle: [u8; 32],
        registration_request_id: [u8; 56],
        registration_terminal_slot: [u8; 32],
        current_owner: OwnerId,
        current_fence: FenceToken,
        current_credential_id: u64,
        current_generation: Generation,
        current_lease_acquired_at: Timestamp,
        current_lease_expires_at: Timestamp,
    ) -> Result<Self, SessionConsumerRosterCapsuleError> {
        let capsule = Self {
            scope,
            key,
            roster_id,
            admission_commitment,
            terminal_body_commitment,
            receipt_commitment,
            logical_owner,
            admission_fence,
            registration_handle,
            registration_request_id: RosterCurrentAuthorityRequestIdBytes(registration_request_id),
            registration_terminal_slot,
            current_owner,
            current_fence,
            current_credential_id,
            current_generation,
            current_lease_acquired_at,
            current_lease_expires_at,
        };
        capsule.validate()?;
        Ok(capsule)
    }

    fn validate(&self) -> Result<(), SessionConsumerRosterCapsuleError> {
        (self.scope != [0; 32]
            && self.roster_id != [0; 16]
            && self.admission_commitment != [0; 32]
            && self.terminal_body_commitment != [0; 32]
            && self.receipt_commitment != [0; 32]
            && self.admission_fence.get() != 0
            && self.registration_handle != [0; 32]
            && self.registration_request_id.0 != [0; 56]
            && self.registration_terminal_slot != [0; 32]
            && self.current_fence.get() != 0
            && self.current_credential_id != 0
            && self.current_generation.get() != 0
            && self.current_lease_acquired_at < self.current_lease_expires_at)
            .then_some(())
            .ok_or(SessionConsumerRosterCapsuleError)
    }

    pub(crate) const fn scope(&self) -> [u8; 32] {
        self.scope
    }

    pub(crate) fn key(&self) -> &SessionKey {
        &self.key
    }

    pub(crate) const fn roster_id(&self) -> [u8; 16] {
        self.roster_id
    }

    pub(crate) const fn admission_commitment(&self) -> [u8; 32] {
        self.admission_commitment
    }

    pub(crate) const fn terminal_body_commitment(&self) -> [u8; 32] {
        self.terminal_body_commitment
    }

    pub(crate) const fn receipt_commitment(&self) -> [u8; 32] {
        self.receipt_commitment
    }

    pub(crate) fn logical_owner(&self) -> &OwnerId {
        &self.logical_owner
    }

    pub(crate) const fn admission_fence(&self) -> FenceToken {
        self.admission_fence
    }

    pub(crate) const fn registration_handle(&self) -> [u8; 32] {
        self.registration_handle
    }

    pub(crate) const fn registration_request_id(&self) -> [u8; 56] {
        self.registration_request_id.0
    }

    pub(crate) const fn registration_terminal_slot(&self) -> [u8; 32] {
        self.registration_terminal_slot
    }

    pub(crate) fn current_owner(&self) -> &OwnerId {
        &self.current_owner
    }

    pub(crate) const fn current_fence(&self) -> FenceToken {
        self.current_fence
    }

    pub(crate) const fn current_credential_id(&self) -> u64 {
        self.current_credential_id
    }

    pub(crate) const fn current_generation(&self) -> Generation {
        self.current_generation
    }

    pub(crate) const fn current_lease_acquired_at(&self) -> Timestamp {
        self.current_lease_acquired_at
    }

    pub(crate) const fn current_lease_expires_at(&self) -> Timestamp {
        self.current_lease_expires_at
    }
}

impl fmt::Debug for SessionConsumerRosterCurrentPublicationAuthorityCapsule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterCurrentPublicationAuthorityCapsule(<redacted>)")
    }
}

/// Closed, redaction-safe protected-roster consumer rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SessionConsumerRosterRejection {
    /// The opaque capsule did not satisfy a fixed bound or canonical profile.
    Malformed,
    /// The authenticated caller or current durable authority was not eligible.
    Authority,
    /// The operation is only legal after recovering an ambiguous admission.
    RecoveryRequired,
    /// Admission found no exact protected business record.
    RecordMissing,
    /// Admission found a different protected business generation.
    GenerationConflict,
    /// Admission could not produce a checked successor generation.
    GenerationExhausted,
    /// A live admission already reserves the exact protected business key.
    BusinessKeyReserved,
    /// The proposed protected checkpoint cannot become the authoritative record.
    InvalidProtectedCheckpoint,
    /// Admission could not reserve its deterministic aggregate storage peak.
    AggregateBytesFull,
    /// Admission could not reserve a bounded live-roster slot.
    LiveFull,
    /// Admission could not reserve a bounded retained-history slot.
    HistoryFull,
    /// The exact stable roster identity is already bound to different canonical bytes.
    Conflict,
    /// A required roster profile/capability was absent or did not match exactly.
    Capability,
    /// The bounded quorum path could not dispatch the operation.
    Unavailable,
    /// Admission required exact row absence but an authoritative row exists.
    RecordAlreadyExists,
}

/// Exact safe outcome of the sole admission mutation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerRosterAdmissionMutationResponse {
    /// The exact admission result is available in an opaque bounded capsule.
    Recorded(SessionConsumerRosterAdmissionCapsule),
    /// No admission byte reached the quorum boundary.
    NotTransmitted,
    /// Admission may have committed; only admission status or recovery may follow.
    OutcomeUnknown,
    /// The request was rejected without exposing implementation details.
    Rejected(SessionConsumerRosterRejection),
}

impl fmt::Debug for SessionConsumerRosterAdmissionMutationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterAdmissionMutationResponse(<redacted>)")
    }
}

/// Exact safe outcome of the sole terminal mutation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerRosterTerminalMutationResponse {
    /// The exact terminal result is available in an opaque bounded capsule.
    Recorded(SessionConsumerRosterTerminalCapsule),
    /// No terminalization byte reached the quorum boundary.
    NotTransmitted,
    /// Terminalization may have committed; only terminal status may follow.
    OutcomeUnknown,
    /// The request was rejected without exposing implementation details.
    Rejected(SessionConsumerRosterRejection),
}

impl fmt::Debug for SessionConsumerRosterTerminalMutationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterTerminalMutationResponse(<redacted>)")
    }
}

/// Bounded opaque result of a read-only admission or recovery operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerRosterAdmissionReadResponse {
    /// The exact read result is available in an opaque bounded capsule.
    Recorded(SessionConsumerRosterAdmissionCapsule),
    /// The request was rejected without exposing implementation details.
    Rejected(SessionConsumerRosterRejection),
}

impl fmt::Debug for SessionConsumerRosterAdmissionReadResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterAdmissionReadResponse(<redacted>)")
    }
}

/// Bounded opaque result of a read-only terminal-status operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerRosterTerminalReadResponse {
    /// The exact read result is available in an opaque bounded capsule.
    Recorded(SessionConsumerRosterTerminalCapsule),
    /// The request was rejected without exposing implementation details.
    Rejected(SessionConsumerRosterRejection),
}

impl fmt::Debug for SessionConsumerRosterTerminalReadResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterTerminalReadResponse(<redacted>)")
    }
}

/// Fixed redaction-safe result of a current-publication-authority read.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerRosterCurrentPublicationAuthorityReadResponse {
    /// The quorum linearized the read and found every exact field current.
    Current,
    /// The query did not match the current durable Established authority.
    Rejected,
}

impl fmt::Debug for SessionConsumerRosterCurrentPublicationAuthorityReadResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("SessionConsumerRosterCurrentPublicationAuthorityReadResponse(<redacted>)")
    }
}

/// Maximum distinct authenticated application consumers in one manifest.
pub const MAX_SESSION_CONSUMER_AUTHORIZATION_IDENTITIES: usize = 256;
/// Maximum tenant/NF grants retained for one authenticated consumer.
pub const MAX_SESSION_CONSUMER_AUTHORIZATION_SCOPES_PER_IDENTITY: usize = 256;
/// Maximum total identity-to-tenant/NF grant tuples in one manifest.
pub const MAX_SESSION_CONSUMER_AUTHORIZATION_GRANT_TUPLES: usize = 4096;

const SESSION_CONSUMER_ROSTER_IDENTITY_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/session-consumer-roster/identity/v1\0";
const SESSION_CONSUMER_ROSTER_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/session-consumer-roster/commitment/v1\0";
const SESSION_CONSUMER_TENANT_NF_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/session-consumer-tenant-nf-scope/v1\0";

/// Redaction-safe construction failure for [`SessionConsumerIdentity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid session consumer identity")]
pub struct SessionConsumerIdentityError;

/// Authenticated application identity, deliberately distinct from a quorum
/// member/node identity.
///
/// This value is supplied by the mTLS authorization layer, never by a
/// consumer request frame. Its textual form is retained only for identity
/// binding of durable request IDs and is redacted from `Debug` and errors.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionConsumerIdentity(String);

impl SessionConsumerIdentity {
    /// Validate one canonical authenticated application identity.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionConsumerIdentityError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > SESSION_CONSUMER_IDENTITY_MAX_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(SessionConsumerIdentityError);
        }
        Ok(Self(value))
    }

    /// Borrow the identity for authenticated authorization and request binding.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SessionConsumerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerIdentity(<redacted>)")
    }
}

/// Fixed-width client-generated request identity for one consumer operation.
///
/// The quorum-side adapter combines it with the authenticated consumer
/// identity before submitting the existing durable consensus request ID. A
/// client may explicitly retry an unconfirmed request with this same ID, but
/// this SDK never performs that replay automatically.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionConsumerRequestId([u8; SESSION_CONSUMER_REQUEST_ID_BYTES]);

impl SessionConsumerRequestId {
    /// Generate a new opaque request identity.
    pub fn new() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Reconstruct an identity retained by an application across a retry.
    pub const fn from_bytes(bytes: [u8; SESSION_CONSUMER_REQUEST_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width representation.
    pub const fn as_bytes(&self) -> &[u8; SESSION_CONSUMER_REQUEST_ID_BYTES] {
        &self.0
    }
}

impl Default for SessionConsumerRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SessionConsumerRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRequestId(<redacted>)")
    }
}

/// Exact cluster/configuration/epoch scope a consumer must present on every
/// request.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsumerScope(SessionConsensusIdentity);

impl SessionConsumerScope {
    /// Bind the consumer contract to one exact consensus scope.
    pub const fn new(identity: SessionConsensusIdentity) -> Self {
        Self(identity)
    }

    /// Return the exact consensus identity being scoped.
    pub const fn consensus_identity(self) -> SessionConsensusIdentity {
        self.0
    }
}

impl fmt::Debug for SessionConsumerScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerScope(<redacted>)")
    }
}

/// Fixed-width, domain-separated commitment to one admitted consumer roster.
///
/// The constructor remains internal to the store-issued authorization
/// manifest. Its bytes are safe to retain or compare, but `Debug` deliberately
/// omits them so topology material cannot enter diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionConsumerRosterCommitment([u8; 32]);

impl SessionConsumerRosterCommitment {
    /// Borrow the fixed-width commitment for equality checks or durable local
    /// binding. This is a digest, never a raw topology value.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionConsumerRosterCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterCommitment(<redacted>)")
    }
}

/// One store-issued, node-keyed member of an admitted consumer roster.
///
/// The exact TLS/SPIFFE identity is retained solely so the existing consumer
/// listener can exclude every voting identity. The paired roster commitment
/// binds its domain-separated identity commitment to this non-zero node ID.
/// There is intentionally no public constructor.
#[derive(Clone)]
pub struct SessionConsumerRosterMember {
    node_id: SessionConsensusNodeId,
    tls_identity: SessionConsumerIdentity,
    identity_commitment: [u8; 32],
}

impl SessionConsumerRosterMember {
    /// Canonical non-zero consensus node ID assigned to this member.
    pub const fn node_id(&self) -> SessionConsensusNodeId {
        self.node_id
    }

    /// Exact admitted TLS/SPIFFE identity for this consensus node.
    ///
    /// This is exposed only through a store-issued manifest so a consumer
    /// listener can continue to reject quorum-member credentials.
    pub fn tls_identity(&self) -> &str {
        self.tls_identity.as_str()
    }
}

impl fmt::Debug for SessionConsumerRosterMember {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterMember(<redacted>)")
    }
}

/// Redaction-safe failure while converting exact topology descriptor bindings
/// into a consumer roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid session consumer roster")]
pub enum SessionConsumerRosterError {
    /// The topology has no consensus identity from which to bind a roster.
    MissingConsensusIdentity,
    /// The exact voter set was empty.
    Empty,
    /// The exact voter set exceeded the SDK's bounded maximum.
    MemberCountTooLarge,
    /// More than one descriptor named the same consensus node ID.
    DuplicateNodeId,
    /// More than one descriptor named the same TLS/SPIFFE identity.
    DuplicateTlsIdentity,
    /// A supplied or expected consensus node ID was invalid.
    InvalidNodeId,
    /// A supplied TLS/SPIFFE identity was invalid for the consumer boundary.
    InvalidTlsIdentity,
    /// Descriptors did not exactly cover the authoritative voter set.
    ScopeMismatch,
}

/// Scope-bound canonical consensus-voter roster.
///
/// The public value can be obtained only from validated SDK topology or from a
/// store-issued authorization manifest. Its private fields prevent product
/// code from inventing a node mapping or roster commitment.
#[derive(Clone)]
pub struct SessionConsumerRoster {
    scope: SessionConsumerScope,
    consensus_members: BTreeMap<SessionConsensusNodeId, SessionConsumerRosterMember>,
    roster_commitment: SessionConsumerRosterCommitment,
    roster_attestation_root_identity: Option<RosterAttestationTrustRootIdentityV1>,
}

impl SessionConsumerRoster {
    /// Construct one roster from the store's exact current voter IDs and
    /// descriptors. `expected_members` is the current scope's authoritative
    /// voter set; every supplied descriptor must correspond to it exactly.
    ///
    /// Raw node IDs are accepted only at this crate-private boundary so the
    /// conversion rejects zero and non-portable ordinals before a roster member
    /// can exist. The public roster always carries `SessionConsensusNodeId`.
    pub(crate) fn try_new(
        scope: SessionConsumerScope,
        expected_members: &BTreeSet<SessionConsensusNodeId>,
        descriptors: impl IntoIterator<Item = (u64, QuorumReplicaDescriptor)>,
    ) -> Result<Self, SessionConsumerRosterError> {
        Self::try_new_with_roster_attestation_root_identity(
            scope,
            expected_members,
            descriptors,
            None,
        )
    }

    /// Construct a roster from validated topology while retaining only the
    /// opaque identity of its protected-roster verifier root. This cannot
    /// configure a root or expose its key; it merely lets the consumed
    /// protected-roster client reject a caller-selected attestor root.
    #[doc(hidden)]
    pub(crate) fn try_new_with_roster_attestation_root_identity(
        scope: SessionConsumerScope,
        expected_members: &BTreeSet<SessionConsensusNodeId>,
        descriptors: impl IntoIterator<Item = (u64, QuorumReplicaDescriptor)>,
        roster_attestation_root_identity: Option<RosterAttestationTrustRootIdentityV1>,
    ) -> Result<Self, SessionConsumerRosterError> {
        validate_expected_roster_members(expected_members)?;

        let mut consensus_members = BTreeMap::new();
        let mut tls_identities = BTreeSet::new();
        for (raw_node_id, descriptor) in descriptors {
            let node_id = SessionConsensusNodeId::new(raw_node_id)
                .map_err(|_| SessionConsumerRosterError::InvalidNodeId)?;
            if consensus_members.contains_key(&node_id) {
                return Err(SessionConsumerRosterError::DuplicateNodeId);
            }
            if !expected_members.contains(&node_id) {
                return Err(SessionConsumerRosterError::ScopeMismatch);
            }
            let tls_identity = SessionConsumerIdentity::new(descriptor.tls_identity().as_str())
                .map_err(|_| SessionConsumerRosterError::InvalidTlsIdentity)?;
            if !tls_identities.insert(tls_identity.clone()) {
                return Err(SessionConsumerRosterError::DuplicateTlsIdentity);
            }
            let identity_commitment = roster_identity_commitment(&tls_identity);
            consensus_members.insert(
                node_id,
                SessionConsumerRosterMember {
                    node_id,
                    tls_identity,
                    identity_commitment,
                },
            );
        }

        if consensus_members.len() != expected_members.len() {
            return Err(SessionConsumerRosterError::ScopeMismatch);
        }

        let roster_commitment = SessionConsumerRosterCommitment(roster_commitment(
            scope.consensus_identity(),
            &consensus_members,
        ));
        Ok(Self {
            scope,
            consensus_members,
            roster_commitment,
            roster_attestation_root_identity,
        })
    }

    /// Exact scope attested by the quorum store when this manifest was made.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Fixed-width commitment to this exact scope and sorted node-to-identity
    /// roster. Reordering the source descriptor map cannot change it.
    pub const fn roster_commitment(&self) -> SessionConsumerRosterCommitment {
        self.roster_commitment
    }

    /// Iterate the authoritative node-to-TLS/SPIFFE roster in ascending
    /// canonical node-ID order without exposing a constructor that could
    /// replace it.
    pub fn consensus_members(&self) -> impl Iterator<Item = &SessionConsumerRosterMember> {
        self.consensus_members.values()
    }

    /// Iterate the authoritative member exclusion set without exposing a
    /// constructor that could replace it.
    pub fn consensus_member_identities(&self) -> impl Iterator<Item = &str> {
        self.consensus_members
            .values()
            .map(SessionConsumerRosterMember::tls_identity)
    }

    /// Number of exact voters bound by this roster.
    pub fn voter_count(&self) -> usize {
        self.consensus_members.len()
    }

    /// Derive private-field authority for one exact roster member.
    pub fn voter(&self, node_id: SessionConsensusNodeId) -> Option<SessionConsumerVoterAuthority> {
        self.consensus_members
            .get(&node_id)
            .cloned()
            .map(|member| SessionConsumerVoterAuthority {
                scope: self.scope,
                member,
                voter_count: self.consensus_members.len(),
                roster_commitment: self.roster_commitment,
                roster_attestation_root_identity: self.roster_attestation_root_identity,
            })
    }

    /// Bind explicit application grants to this already SDK-validated roster.
    ///
    /// This is the safe composition path for an SDK client that obtained this
    /// roster from [`crate::ValidatedQuorumTopology`]. It cannot create or
    /// alter the roster, its scope, or its voter-to-TLS identity bindings.
    pub fn authorization_manifest(
        self,
        local_node_id: SessionConsensusNodeId,
        grants: impl IntoIterator<Item = SessionConsumerAuthorizationGrant>,
    ) -> Result<SessionConsumerAuthorizationManifest, SessionConsumerAuthorizationManifestError>
    {
        SessionConsumerAuthorizationManifest::try_new(local_node_id, self, grants)
    }
}

impl fmt::Debug for SessionConsumerRoster {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerRoster")
            .field("scope", &self.scope)
            .field("consensus_member_count", &self.consensus_members.len())
            .field("roster_commitment", &self.roster_commitment)
            .finish()
    }
}

/// Private-field authority for one exact server in a canonical roster.
///
/// Callers can inspect the fixed binding needed to configure transport, but
/// cannot construct or substitute one from raw node or commitment bytes.
#[derive(Clone)]
pub struct SessionConsumerVoterAuthority {
    scope: SessionConsumerScope,
    member: SessionConsumerRosterMember,
    voter_count: usize,
    roster_commitment: SessionConsumerRosterCommitment,
    roster_attestation_root_identity: Option<RosterAttestationTrustRootIdentityV1>,
}

impl SessionConsumerVoterAuthority {
    /// Exact consensus scope shared by the voter roster.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Exact SDK consensus node ID expected from this server.
    pub const fn node_id(&self) -> SessionConsensusNodeId {
        self.member.node_id
    }

    /// Exact configured TLS/SPIFFE identity for this server.
    pub fn tls_identity(&self) -> &str {
        self.member.tls_identity.as_str()
    }

    /// Exact voter count committed by the roster.
    pub const fn voter_count(&self) -> usize {
        self.voter_count
    }

    /// Exact canonical roster commitment expected from this server.
    pub const fn roster_commitment(&self) -> SessionConsumerRosterCommitment {
        self.roster_commitment
    }

    /// Return the topology-issued opaque verifier-root identity for the
    /// protected-roster profile. `None` keeps the ordinary consumer usable
    /// but makes protected-roster composition fail closed.
    #[doc(hidden)]
    pub const fn roster_attestation_trust_root_identity(
        &self,
    ) -> Option<RosterAttestationTrustRootIdentityV1> {
        self.roster_attestation_root_identity
    }
}

impl fmt::Debug for SessionConsumerVoterAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerVoterAuthority(<redacted>)")
    }
}

/// Exact tenant and network-function namespace granted to one consumer.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionConsumerTenantNfScope {
    tenant: TenantId,
    nf_kind: NetworkFunctionKind,
}

impl SessionConsumerTenantNfScope {
    /// Construct one explicit tenant/NF scope. Neither field is inferred from
    /// SPIFFE, Kubernetes, a session key, or another deployment identity.
    pub const fn new(tenant: TenantId, nf_kind: NetworkFunctionKind) -> Self {
        Self { tenant, nf_kind }
    }

    /// Exact tenant named by this grant.
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Exact network-function kind named by this grant.
    pub const fn nf_kind(&self) -> &NetworkFunctionKind {
        &self.nf_kind
    }
}

impl fmt::Debug for SessionConsumerTenantNfScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerTenantNfScope(<redacted>)")
    }
}

/// Invalid bounded grant construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerAuthorizationGrantError {
    /// The exact SPIFFE identity was not valid for this consumer boundary.
    #[error("invalid session consumer authorization grant identity")]
    InvalidIdentity,
    /// A grant must name at least one exact tenant/NF scope.
    #[error("session consumer authorization grant has no scopes")]
    EmptyScopes,
    /// A grant exceeded the bounded scopes-per-identity limit.
    #[error("session consumer authorization grant has too many scopes")]
    TooManyScopes,
    /// The input named one exact tenant/NF scope more than once.
    #[error("session consumer authorization grant contains a duplicate scope")]
    DuplicateScope,
}

/// Explicit SPIFFE-to-tenant/NF authorization grant.
///
/// The identity is parsed before construction and every grant contains a
/// nonempty, bounded, duplicate-free scope set. Wildcards are not supported.
#[derive(Clone)]
pub struct SessionConsumerAuthorizationGrant {
    consumer: SessionConsumerIdentity,
    scopes: BTreeSet<SessionConsumerTenantNfScope>,
}

impl SessionConsumerAuthorizationGrant {
    /// Construct one explicit bounded authorization grant.
    pub fn try_new(
        consumer: SpiffeId,
        scopes: impl IntoIterator<Item = SessionConsumerTenantNfScope>,
    ) -> Result<Self, SessionConsumerAuthorizationGrantError> {
        let mut admitted_scopes = BTreeSet::new();
        for scope in scopes {
            if !admitted_scopes.insert(scope) {
                return Err(SessionConsumerAuthorizationGrantError::DuplicateScope);
            }
            if admitted_scopes.len() > MAX_SESSION_CONSUMER_AUTHORIZATION_SCOPES_PER_IDENTITY {
                return Err(SessionConsumerAuthorizationGrantError::TooManyScopes);
            }
        }
        if admitted_scopes.is_empty() {
            return Err(SessionConsumerAuthorizationGrantError::EmptyScopes);
        }
        let consumer = SessionConsumerIdentity::new(consumer.as_str().to_owned())
            .map_err(|_| SessionConsumerAuthorizationGrantError::InvalidIdentity)?;
        Ok(Self {
            consumer,
            scopes: admitted_scopes,
        })
    }
}

impl fmt::Debug for SessionConsumerAuthorizationGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerAuthorizationGrant(<redacted>)")
    }
}

/// Invalid store-issued consumer authorization manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerAuthorizationManifestError {
    /// The manifest local voter was not present in its exact roster.
    #[error("session consumer authorization local voter is absent from the roster")]
    LocalVoterMissing,
    /// An application grant attempted to reuse a consensus voter identity.
    #[error("session consumer authorization grant reuses a voter identity")]
    VoterIdentity,
    /// More than one grant named the same exact SPIFFE identity.
    #[error("session consumer authorization manifest contains a duplicate identity")]
    DuplicateIdentity,
    /// The manifest exceeded its bounded identity limit.
    #[error("session consumer authorization manifest has too many identities")]
    TooManyIdentities,
    /// The manifest exceeded its bounded total grant tuple limit.
    #[error("session consumer authorization manifest has too many grant tuples")]
    TooManyGrantTuples,
    /// The manifest must contain at least one application consumer grant.
    #[error("session consumer authorization manifest has no consumers")]
    Empty,
}

/// Non-constructible authenticated consumer authority passed to the quorum
/// service after mTLS authorization.
#[derive(Clone)]
pub struct SessionConsumerAuthorization {
    identity: SessionConsumerIdentity,
    allowed_scopes: Arc<BTreeSet<[u8; 32]>>,
}

impl fmt::Debug for SessionConsumerAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerAuthorization(<redacted>)")
    }
}

/// Non-constructible, roster-specific authority derived from an authenticated
/// consumer authorization.
///
/// This token carries only the authenticated identity and opaque exact
/// tenant/NF grant commitments required to admit the decoded authority key of
/// a protected-roster request. It is neither a general store authority nor a
/// serializable transport credential.
#[derive(Clone)]
pub struct SessionConsumerRosterAuthorization {
    identity: SessionConsumerIdentity,
    allowed_scopes: Arc<BTreeSet<[u8; 32]>>,
}

impl fmt::Debug for SessionConsumerRosterAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterAuthorization(<redacted>)")
    }
}

/// Store-issued local-voter manifest containing one canonical roster and a
/// bounded explicit authorization map. It is never serialized.
#[derive(Clone)]
pub struct SessionConsumerAuthorizationManifest {
    local_node_id: SessionConsensusNodeId,
    roster: SessionConsumerRoster,
    consumers: BTreeMap<SessionConsumerIdentity, Arc<BTreeSet<[u8; 32]>>>,
}

impl SessionConsumerAuthorizationManifest {
    pub(crate) fn try_new(
        local_node_id: SessionConsensusNodeId,
        roster: SessionConsumerRoster,
        grants: impl IntoIterator<Item = SessionConsumerAuthorizationGrant>,
    ) -> Result<Self, SessionConsumerAuthorizationManifestError> {
        if roster.voter(local_node_id).is_none() {
            return Err(SessionConsumerAuthorizationManifestError::LocalVoterMissing);
        }
        let member_identities = roster
            .consensus_member_identities()
            .collect::<BTreeSet<_>>();
        let mut consumers = BTreeMap::new();
        let mut total_scopes = 0_usize;
        for grant in grants {
            if member_identities.contains(grant.consumer.as_str()) {
                return Err(SessionConsumerAuthorizationManifestError::VoterIdentity);
            }
            if consumers.contains_key(&grant.consumer) {
                return Err(SessionConsumerAuthorizationManifestError::DuplicateIdentity);
            }
            total_scopes = total_scopes
                .checked_add(grant.scopes.len())
                .ok_or(SessionConsumerAuthorizationManifestError::TooManyGrantTuples)?;
            if consumers.len() >= MAX_SESSION_CONSUMER_AUTHORIZATION_IDENTITIES {
                return Err(SessionConsumerAuthorizationManifestError::TooManyIdentities);
            }
            if total_scopes > MAX_SESSION_CONSUMER_AUTHORIZATION_GRANT_TUPLES {
                return Err(SessionConsumerAuthorizationManifestError::TooManyGrantTuples);
            }
            let allowed_scopes = grant
                .scopes
                .iter()
                .map(session_consumer_tenant_nf_commitment)
                .collect::<BTreeSet<_>>();
            consumers.insert(grant.consumer, Arc::new(allowed_scopes));
        }
        if consumers.is_empty() {
            return Err(SessionConsumerAuthorizationManifestError::Empty);
        }
        Ok(Self {
            local_node_id,
            roster,
            consumers,
        })
    }

    /// Exact consensus scope authorized by this manifest.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.roster.scope
    }

    /// Exact local server node ID bound by this manifest.
    pub const fn local_node_id(&self) -> SessionConsensusNodeId {
        self.local_node_id
    }

    /// Exact voter count bound by this manifest.
    pub fn voter_count(&self) -> usize {
        self.roster.voter_count()
    }

    /// Exact canonical roster commitment bound by this manifest.
    pub const fn roster_commitment(&self) -> SessionConsumerRosterCommitment {
        self.roster.roster_commitment
    }

    /// Iterate the exact consensus-member exclusion identities.
    pub fn consensus_member_identities(&self) -> impl Iterator<Item = &str> {
        self.roster.consensus_member_identities()
    }

    /// Iterate the exact canonical voter roster bound to this manifest.
    pub fn consensus_members(&self) -> impl Iterator<Item = &SessionConsumerRosterMember> {
        self.roster.consensus_members()
    }

    /// Resolve one already-authenticated configured consumer into a
    /// non-constructible quorum-service authority token.
    pub fn authorize(
        &self,
        identity: &SessionConsumerIdentity,
    ) -> Result<SessionConsumerAuthorization, SessionConsumerRejection> {
        let allowed_scopes = self
            .consumers
            .get(identity)
            .cloned()
            .ok_or(SessionConsumerRejection::Unauthorized)?;
        Ok(SessionConsumerAuthorization {
            identity: identity.clone(),
            allowed_scopes,
        })
    }
}

impl fmt::Debug for SessionConsumerAuthorizationManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerAuthorizationManifest")
            .field("local_node_id", &"<redacted>")
            .field("voter_count", &self.roster.voter_count())
            .field("consumer_count", &self.consumers.len())
            .finish()
    }
}

fn session_consumer_tenant_nf_commitment(scope: &SessionConsumerTenantNfScope) -> [u8; 32] {
    session_consumer_tenant_nf_fields_commitment(scope.tenant.as_str(), scope.nf_kind.as_str())
}

fn session_consumer_tenant_nf_fields_commitment(tenant: &str, nf_kind: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_CONSUMER_TENANT_NF_COMMITMENT_DOMAIN);
    update_length_delimited(&mut hasher, tenant.as_bytes());
    update_length_delimited(&mut hasher, nf_kind.as_bytes());
    hasher.finalize().into()
}

fn validate_expected_roster_members(
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> Result<(), SessionConsumerRosterError> {
    if expected_members.is_empty() {
        return Err(SessionConsumerRosterError::Empty);
    }
    if expected_members.len() > QUORUM_TOPOLOGY_MAX_MEMBERS {
        return Err(SessionConsumerRosterError::MemberCountTooLarge);
    }
    if expected_members
        .iter()
        .any(|node_id| node_id.get() == 0 || node_id.get() > i64::MAX as u64)
    {
        return Err(SessionConsumerRosterError::InvalidNodeId);
    }
    Ok(())
}

fn roster_identity_commitment(identity: &SessionConsumerIdentity) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_CONSUMER_ROSTER_IDENTITY_COMMITMENT_DOMAIN);
    update_length_delimited(&mut hasher, identity.as_str().as_bytes());
    hasher.finalize().into()
}

fn roster_commitment(
    scope: SessionConsensusIdentity,
    consensus_members: &BTreeMap<SessionConsensusNodeId, SessionConsumerRosterMember>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_CONSUMER_ROSTER_COMMITMENT_DOMAIN);
    update_length_delimited(&mut hasher, scope.cluster_id().as_bytes());
    update_length_delimited(&mut hasher, scope.configuration_id().as_bytes());
    update_length_delimited(
        &mut hasher,
        &scope.configuration_epoch().get().to_be_bytes(),
    );
    hasher.update(
        u32::try_from(consensus_members.len())
            .expect("consumer roster member count is bounded")
            .to_be_bytes(),
    );
    for (node_id, member) in consensus_members {
        hasher.update(node_id.get().to_be_bytes());
        update_length_delimited(&mut hasher, &member.identity_commitment);
    }
    hasher.finalize().into()
}

fn update_length_delimited(hasher: &mut Sha256, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("consumer roster field length is bounded");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

/// Typed operation admitted by the stateless consumer boundary.
///
/// Deliberately absent are consensus-engine RPCs, membership/topology changes,
/// snapshots, raw replication append, and replication rebuild.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SessionConsumerOperation {
    /// Read the quorum's current backend capability declaration.
    Capabilities,
    /// Authoritative, linearizable record read.
    Get {
        /// Session key to retrieve.
        key: SessionKey,
    },
    /// Validate payload-free absolute-expiry preflights at leader authority.
    PreflightRecordExpiry {
        /// Bounded payload-free expiry descriptors.
        preflights: Vec<RecordExpiryPreflight>,
    },
    /// Fenced compare-and-set mutation.
    CompareAndSet {
        /// Exact fenced mutation.
        op: Box<CompareAndSet>,
    },
    /// Fenced deletion.
    DeleteFenced {
        /// Existing lease credential.
        lease: LeaseGuard,
    },
    /// Fenced TTL refresh.
    RefreshTtl {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Bounded sequential application batch.
    Batch {
        /// Operations in caller order.
        ops: Vec<SessionOp>,
    },
    /// Bounded restore scan.
    ScanRestoreRecords {
        /// Requested restore page.
        request: RestoreScanRequest,
    },
    /// Open a bounded committed-change watch from the inclusive sequence.
    Watch {
        /// Inclusive committed sequence to watch.
        start_sequence: u64,
    },
    /// Acquire a fenced lease.
    AcquireLease {
        /// Session key to lease.
        key: SessionKey,
        /// Requested owner.
        owner: OwnerId,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Renew an existing lease.
    RenewLease {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Recover the exact durable receipt for one ordinary lease mutation.
    ///
    /// This is a leader-linearizable, read-only operation.  The complete
    /// original public request identity and lease body are retained by the
    /// caller and rebuilt by the server under its authenticated identity; it
    /// never accepts a derived consensus ID or submits a lease mutation.
    LeaseMutationStatus {
        /// Complete original lease request retained by the caller.
        request: Box<SessionConsumerLeaseMutationRequest>,
    },
    /// Recover the exact durable outcome of one compare-and-set.
    ///
    /// This is a leader-linearizable, read-only operation. The complete
    /// original request is retained by the caller's local affine handle;
    /// it is never replayed or proposed by this status operation.
    CompareAndSetStatus {
        /// Complete original compare-and-set request retained by the caller.
        request: Box<SessionConsumerCompareAndSetRequest>,
    },
    /// Prove the exact atomic fenced-transition capability across the current
    /// admitted voter set.
    FencedTransitionCapability,
    /// Observe one exact record key and its durable fence floor.
    ObserveFencedTransition {
        /// Exact key to observe.
        key: SessionKey,
    },
    /// Atomically acquire or renew one lease and mutate its exact record.
    FencedTransition {
        /// Complete canonical transition body.
        request: Box<FencedTransitionRequest>,
    },
    /// Recover the exact status of one previously submitted transition.
    FencedTransitionStatus {
        /// Complete canonical transition body.
        request: Box<FencedTransitionRequest>,
    },
    /// Perform the only fresh protected-roster quorum mutation: immutable
    /// admission. The opaque body is one canonical admission and is never
    /// split across consumer or consensus mutations.
    FencedMutationRosterPollAdmit {
        /// Exact bounded opaque admission capsule.
        request: Box<SessionConsumerRosterAdmissionCapsule>,
    },
    /// Read the exact original admission after ambiguity without submitting a
    /// second admission mutation.
    FencedMutationRosterAdmissionStatus {
        /// Exact bounded opaque admission-status capsule.
        request: Box<SessionConsumerRosterAdmissionCapsule>,
    },
    /// Recover a durable protected roster under current authority without a
    /// quorum mutation.
    FencedMutationRosterRecover {
        /// Exact bounded opaque recovery capsule.
        request: Box<SessionConsumerRosterAdmissionCapsule>,
    },
    /// Perform the only terminal protected-roster quorum mutation. The exact
    /// body is one canonical terminalization and is never split.
    FencedMutationRosterTerminalize {
        /// Exact bounded opaque terminal capsule.
        request: Box<SessionConsumerRosterTerminalCapsule>,
    },
    /// Read one exact prepared terminal body without a quorum mutation.
    FencedMutationRosterTerminalStatus {
        /// Exact bounded opaque terminal-status capsule.
        request: Box<SessionConsumerRosterTerminalCapsule>,
    },
    /// Linearly read the complete current authority for one already
    /// Established publication without proposing a consensus command.
    FencedMutationRosterCurrentPublicationAuthority {
        /// Complete untrusted query capsule; the quorum compares it with its
        /// retained admission, receipt, and current authority.
        request: Box<SessionConsumerRosterCurrentPublicationAuthorityCapsule>,
    },
    /// Release an existing lease.
    ReleaseLease {
        /// Existing lease credential.
        lease: LeaseGuard,
    },
}

impl fmt::Debug for SessionConsumerOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Capabilities => "Capabilities",
            Self::Get { .. } => "Get",
            Self::PreflightRecordExpiry { .. } => "PreflightRecordExpiry",
            Self::CompareAndSet { .. } => "CompareAndSet",
            Self::DeleteFenced { .. } => "DeleteFenced",
            Self::RefreshTtl { .. } => "RefreshTtl",
            Self::Batch { .. } => "Batch",
            Self::ScanRestoreRecords { .. } => "ScanRestoreRecords",
            Self::Watch { .. } => "Watch",
            Self::AcquireLease { .. } => "AcquireLease",
            Self::RenewLease { .. } => "RenewLease",
            Self::LeaseMutationStatus { .. } => "LeaseMutationStatus",
            Self::CompareAndSetStatus { .. } => "CompareAndSetStatus",
            Self::ReleaseLease { .. } => "ReleaseLease",
            Self::FencedTransitionCapability => "FencedTransitionCapability",
            Self::ObserveFencedTransition { .. } => "ObserveFencedTransition",
            Self::FencedTransition { .. } => "FencedTransition",
            Self::FencedTransitionStatus { .. } => "FencedTransitionStatus",
            Self::FencedMutationRosterPollAdmit { .. } => "FencedMutationRosterPollAdmit",
            Self::FencedMutationRosterAdmissionStatus { .. } => {
                "FencedMutationRosterAdmissionStatus"
            }
            Self::FencedMutationRosterRecover { .. } => "FencedMutationRosterRecover",
            Self::FencedMutationRosterTerminalize { .. } => "FencedMutationRosterTerminalize",
            Self::FencedMutationRosterTerminalStatus { .. } => "FencedMutationRosterTerminalStatus",
            Self::FencedMutationRosterCurrentPublicationAuthority { .. } => {
                "FencedMutationRosterCurrentPublicationAuthority"
            }
        };
        formatter.write_str(name)
    }
}

impl SessionConsumerOperation {
    /// Check fixed consumer-side operation bounds before quorum dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        let validate_lease = |lease: &LeaseGuard| {
            lease
                .validate_profile()
                .map_err(|_| SessionConsumerRejection::MalformedRequest)
        };
        match self {
            Self::PreflightRecordExpiry { preflights } => {
                crate::validate_record_expiry_preflights_profile(preflights)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::Batch { ops } => {
                if ops.len() > MAX_SESSION_CONSUMER_BATCH_OPERATIONS {
                    return Err(SessionConsumerRejection::MalformedRequest);
                }
                crate::validate_session_ops_profile(ops)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::ScanRestoreRecords { request } => request
                .validate()
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::CompareAndSet { op } => validate_lease(&op.lease),
            Self::DeleteFenced { lease } | Self::ReleaseLease { lease } => validate_lease(lease),
            Self::RefreshTtl { lease, ttl } | Self::RenewLease { lease, ttl } => {
                validate_lease(lease)?;
                crate::validate_session_ttl(*ttl)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::AcquireLease { ttl, .. } => crate::validate_session_ttl(*ttl)
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::LeaseMutationStatus { request } => request.validate(),
            Self::CompareAndSetStatus { request } => request.validate(),
            Self::FencedTransition { request } | Self::FencedTransitionStatus { request } => {
                request
                    .validate()
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::FencedMutationRosterPollAdmit { request }
            | Self::FencedMutationRosterAdmissionStatus { request }
            | Self::FencedMutationRosterRecover { request } => (!request.is_empty()
                && request.len() <= MAX_SESSION_CONSUMER_ROSTER_ADMISSION_CAPSULE_BYTES)
                .then_some(())
                .ok_or(SessionConsumerRejection::MalformedRequest),
            Self::FencedMutationRosterTerminalize { request }
            | Self::FencedMutationRosterTerminalStatus { request } => (!request.is_empty()
                && request.len() <= MAX_SESSION_CONSUMER_ROSTER_TERMINAL_CAPSULE_BYTES)
                .then_some(())
                .ok_or(SessionConsumerRejection::MalformedRequest),
            Self::FencedMutationRosterCurrentPublicationAuthority { request } => request
                .validate()
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::Capabilities
            | Self::Get { .. }
            | Self::Watch { .. }
            | Self::FencedTransitionCapability
            | Self::ObserveFencedTransition { .. } => Ok(()),
        }
    }
}

/// One scope-bound consumer request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerRequest {
    scope: SessionConsumerScope,
    request_id: SessionConsumerRequestId,
    operation: SessionConsumerOperation,
}

impl SessionConsumerRequest {
    /// Construct one exact operation request.
    pub const fn new(
        scope: SessionConsumerScope,
        request_id: SessionConsumerRequestId,
        operation: SessionConsumerOperation,
    ) -> Self {
        Self {
            scope,
            request_id,
            operation,
        }
    }

    /// Exact cluster/configuration/epoch scope supplied by the caller.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Caller-retained durable request identity.
    pub const fn request_id(&self) -> SessionConsumerRequestId {
        self.request_id
    }

    /// Typed application operation.
    pub const fn operation(&self) -> &SessionConsumerOperation {
        &self.operation
    }

    /// Consume the request after server-side validation and binding have
    /// completed. This is crate-private so the consensus service can move one
    /// maximum-sized CAS body directly into its single commit intent without
    /// cloning it for validation or receipt bookkeeping.
    pub(crate) fn into_operation(self) -> SessionConsumerOperation {
        self.operation
    }

    /// Validate the operation before dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation.validate()?;
        match &self.operation {
            SessionConsumerOperation::FencedTransition { request }
            | SessionConsumerOperation::FencedTransitionStatus { request }
                if request.request_id().as_bytes() != self.request_id.as_bytes() =>
            {
                Err(SessionConsumerRejection::MalformedRequest)
            }
            SessionConsumerOperation::LeaseMutationStatus { request }
                if request.request_id().as_bytes() != self.request_id.as_bytes() =>
            {
                Err(SessionConsumerRejection::MalformedRequest)
            }
            SessionConsumerOperation::CompareAndSetStatus { request }
                if request.request_id().as_bytes() != self.request_id.as_bytes() =>
            {
                Err(SessionConsumerRejection::MalformedRequest)
            }
            _ => Ok(()),
        }
    }
}

/// Complete original compare-and-set request used only for read-only exact
/// consensus-outcome recovery.
///
/// The public request ID and immutable body are retained by the volatile
/// local affine handle. This type has no execute operation and cannot mint a new
/// request identity or replay the mutation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerCompareAndSetRequest {
    request_id: SessionConsumerRequestId,
    operation: CompareAndSet,
}

impl SessionConsumerCompareAndSetRequest {
    /// Construct one retained compare-and-set body from its caller-owned ID.
    pub const fn new(request_id: SessionConsumerRequestId, operation: CompareAndSet) -> Self {
        Self {
            request_id,
            operation,
        }
    }

    /// Return the original caller-owned public request identity.
    pub const fn request_id(&self) -> SessionConsumerRequestId {
        self.request_id
    }

    /// Return the exact original compare-and-set body.
    pub const fn operation(&self) -> &CompareAndSet {
        &self.operation
    }

    /// Validate the retained body before it reaches the receipt lookup.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation
            .lease
            .validate_profile()
            .map_err(|_| SessionConsumerRejection::MalformedRequest)
    }

    pub(crate) fn into_original_consumer_request(
        self,
        scope: SessionConsumerScope,
    ) -> SessionConsumerRequest {
        let operation = SessionConsumerOperation::CompareAndSet {
            op: Box::new(self.operation),
        };
        SessionConsumerRequest::new(scope, self.request_id, operation)
    }
}

impl fmt::Debug for SessionConsumerCompareAndSetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerCompareAndSetRequest(<redacted>)")
    }
}

/// One ordinary lease operation whose complete original body is retained for
/// exact receipt recovery.
///
/// This type deliberately contains the public request ID and original body,
/// rather than an internal consensus request ID or digest.  The server derives
/// every internal binding from the authenticated consumer identity and exact
/// consumer scope at the read boundary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "lease_operation",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerLeaseMutationOperation {
    /// Original acquire-lease body.
    Acquire {
        /// Session key to lease.
        key: SessionKey,
        /// Requested owner.
        owner: OwnerId,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Original renew-lease body.
    Renew {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Original release-lease body.
    Release {
        /// Existing lease credential.
        lease: LeaseGuard,
    },
}

impl fmt::Debug for SessionConsumerLeaseMutationOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Acquire { .. } => "Acquire",
            Self::Renew { .. } => "Renew",
            Self::Release { .. } => "Release",
        };
        formatter.write_str(name)
    }
}

impl SessionConsumerLeaseMutationOperation {
    fn validate(&self) -> Result<(), SessionConsumerRejection> {
        let validate_lease = |lease: &LeaseGuard| {
            lease
                .validate_profile()
                .map_err(|_| SessionConsumerRejection::MalformedRequest)
        };
        match self {
            Self::Acquire { ttl, .. } => crate::validate_session_ttl(*ttl)
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::Renew { lease, ttl } => {
                validate_lease(lease)?;
                crate::validate_session_ttl(*ttl)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::Release { lease } => validate_lease(lease),
        }
    }

    fn into_consumer_operation(self) -> SessionConsumerOperation {
        match self {
            Self::Acquire { key, owner, ttl } => {
                SessionConsumerOperation::AcquireLease { key, owner, ttl }
            }
            Self::Renew { lease, ttl } => SessionConsumerOperation::RenewLease { lease, ttl },
            Self::Release { lease } => SessionConsumerOperation::ReleaseLease { lease },
        }
    }
}

/// Complete original public lease request used only for read-only receipt
/// recovery.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerLeaseMutationRequest {
    request_id: SessionConsumerRequestId,
    operation: SessionConsumerLeaseMutationOperation,
}

impl SessionConsumerLeaseMutationRequest {
    /// Construct a retained ordinary lease request from its original public
    /// request ID and complete mutation body.
    pub const fn new(
        request_id: SessionConsumerRequestId,
        operation: SessionConsumerLeaseMutationOperation,
    ) -> Self {
        Self {
            request_id,
            operation,
        }
    }

    /// Return the original caller-owned public request identity.
    pub const fn request_id(&self) -> SessionConsumerRequestId {
        self.request_id
    }

    /// Return the exact original lease body.
    pub const fn operation(&self) -> &SessionConsumerLeaseMutationOperation {
        &self.operation
    }

    /// Validate the retained body before it reaches the receipt lookup.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation.validate()
    }

    pub(crate) fn into_original_consumer_request(
        self,
        scope: SessionConsumerScope,
    ) -> SessionConsumerRequest {
        let operation = self.operation.into_consumer_operation();
        SessionConsumerRequest::new(scope, self.request_id, operation)
    }
}

impl fmt::Debug for SessionConsumerLeaseMutationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerLeaseMutationRequest(<redacted>)")
    }
}

impl SessionConsumerAuthorization {
    /// Derive the least-authority token required by protected-roster ingress.
    ///
    /// Only a store-issued [`SessionConsumerAuthorization`] can mint this
    /// token; an independently constructed [`SessionConsumerIdentity`] cannot
    /// recover its grant commitments.
    #[doc(hidden)]
    pub fn roster_authorization(&self) -> SessionConsumerRosterAuthorization {
        SessionConsumerRosterAuthorization {
            identity: self.identity.clone(),
            allowed_scopes: Arc::clone(&self.allowed_scopes),
        }
    }

    /// Return the authenticated peer identity bound to this authority token.
    ///
    /// The dedicated protected-roster ingress uses this only to bind its
    /// transport-issued attestation after the normal manifest authorization
    /// and operation grant have already succeeded.
    #[doc(hidden)]
    pub fn identity(&self) -> &SessionConsumerIdentity {
        &self.identity
    }

    fn permits_key(&self, key: &SessionKey) -> bool {
        let commitment =
            session_consumer_tenant_nf_fields_commitment(key.tenant.as_str(), key.nf_kind.as_str());
        self.allowed_scopes.contains(&commitment)
    }

    fn permits_compare_and_set(&self, operation: &CompareAndSet) -> bool {
        self.permits_key(&operation.key)
            && self.permits_key(operation.lease.key())
            && self.permits_key(&operation.new_record.key)
    }

    fn permits_session_op(&self, operation: &SessionOp) -> bool {
        match operation {
            SessionOp::Get { key } => self.permits_key(key),
            SessionOp::CompareAndSet(operation) => self.permits_compare_and_set(operation),
            SessionOp::DeleteFenced { lease } | SessionOp::RefreshTtl { lease, .. } => {
                self.permits_key(lease.key())
            }
        }
    }

    fn permits_lease_mutation(&self, request: &SessionConsumerLeaseMutationRequest) -> bool {
        match request.operation() {
            SessionConsumerLeaseMutationOperation::Acquire { key, .. } => self.permits_key(key),
            SessionConsumerLeaseMutationOperation::Renew { lease, .. }
            | SessionConsumerLeaseMutationOperation::Release { lease } => {
                self.permits_key(lease.key())
            }
        }
    }

    fn permits_fenced_transition(&self, request: &FencedTransitionRequest) -> bool {
        self.permits_key(request.lease().key())
            && request
                .mutation()
                .record()
                .is_none_or(|record| self.permits_key(&record.key))
    }

    fn permits_fenced_transition_v2(&self, request: &FencedTransitionV2Request) -> bool {
        self.permits_key(request.lease().key())
            && request
                .mutation()
                .record()
                .is_none_or(|record| self.permits_key(&record.key))
    }

    /// Check whether this already-authenticated authority grants one complete
    /// validated operation.
    ///
    /// The authority is minted only by a store-issued manifest after the
    /// transport has authenticated the consumer identity.  This method takes
    /// no scope argument, so callers cannot substitute a caller-selected
    /// cluster/configuration scope for the listener's separately validated
    /// request scope.  Consumers of [`SessionQuorumConsumer`] must invoke it
    /// before constructing any service execution or watch future.
    pub fn authorize_operation(
        &self,
        operation: &SessionConsumerOperation,
    ) -> Result<(), SessionConsumerRejection> {
        let authorized = match operation {
            SessionConsumerOperation::Capabilities
            | SessionConsumerOperation::PreflightRecordExpiry { .. }
            | SessionConsumerOperation::FencedTransitionCapability => true,
            // A single global replication cursor exposes otherwise foreign
            // tenants' mutation timing and ordering even when every change
            // item is filtered. Scoped consumers therefore cannot subscribe
            // until the protocol has an identity-and-scope-bound cursor.
            SessionConsumerOperation::Watch { .. }
            // The general consumer authorization token deliberately grants
            // no opaque roster call. The `/3` listener separately requires
            // mTLS identity and scope, a current root-matched ingress signer,
            // and its exact attestation before the private ingress can look
            // up or decode a capsule.
            | SessionConsumerOperation::FencedMutationRosterPollAdmit { .. }
            | SessionConsumerOperation::FencedMutationRosterAdmissionStatus { .. }
            | SessionConsumerOperation::FencedMutationRosterRecover { .. }
            | SessionConsumerOperation::FencedMutationRosterTerminalize { .. }
            | SessionConsumerOperation::FencedMutationRosterTerminalStatus { .. }
            | SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority { .. } => {
                false
            }
            SessionConsumerOperation::Get { key }
            | SessionConsumerOperation::AcquireLease { key, .. }
            | SessionConsumerOperation::ObserveFencedTransition { key } => self.permits_key(key),
            SessionConsumerOperation::CompareAndSet { op } => self.permits_compare_and_set(op),
            SessionConsumerOperation::DeleteFenced { lease }
            | SessionConsumerOperation::RefreshTtl { lease, .. }
            | SessionConsumerOperation::RenewLease { lease, .. }
            | SessionConsumerOperation::ReleaseLease { lease } => self.permits_key(lease.key()),
            SessionConsumerOperation::Batch { ops } => ops
                .iter()
                .all(|operation| self.permits_session_op(operation)),
            SessionConsumerOperation::ScanRestoreRecords { request } => {
                match (&request.scope.tenant, &request.scope.nf_kind) {
                    (Some(tenant), Some(nf_kind)) => {
                        self.allowed_scopes
                            .contains(&session_consumer_tenant_nf_fields_commitment(
                                tenant.as_str(),
                                nf_kind.as_str(),
                            ))
                    }
                    _ => false,
                }
            }
            SessionConsumerOperation::LeaseMutationStatus { request } => {
                self.permits_lease_mutation(request)
            }
            SessionConsumerOperation::CompareAndSetStatus { request } => {
                self.permits_compare_and_set(request.operation())
            }
            SessionConsumerOperation::FencedTransition { request }
            | SessionConsumerOperation::FencedTransitionStatus { request } => {
                self.permits_fenced_transition(request)
            }
        };
        authorized
            .then_some(())
            .ok_or(SessionConsumerRejection::Unauthorized)
    }

    /// Check whether this manifest-issued authority grants one complete V2
    /// fenced-transition operation. V2 uses a distinct wire envelope, but it
    /// never bypasses the same tenant/NF authority boundary as V1.
    pub fn authorize_v2_operation(
        &self,
        operation: &SessionConsumerV2Operation,
    ) -> Result<(), SessionConsumerRejection> {
        let authorized = match operation {
            SessionConsumerV2Operation::FencedTransitionV2Capability
            | SessionConsumerV2Operation::FencedTransitionV2HistoryState => true,
            SessionConsumerV2Operation::FencedTransitionV2 { request }
            | SessionConsumerV2Operation::FencedTransitionV2Status { request } => {
                self.permits_fenced_transition_v2(request)
            }
            SessionConsumerV2Operation::FencedTransitionV2Batch { requests } => requests
                .iter()
                .all(|request| self.permits_fenced_transition_v2(request)),
        };
        authorized
            .then_some(())
            .ok_or(SessionConsumerRejection::Unauthorized)
    }
}

impl SessionConsumerRosterAuthorization {
    /// Return the authenticated peer identity bound to this roster authority.
    #[doc(hidden)]
    pub fn identity(&self) -> &SessionConsumerIdentity {
        &self.identity
    }

    /// Check whether the exact decoded roster authority key is granted.
    ///
    /// The token exposes only this membership decision and never its grant
    /// commitments or an allowed-scope enumeration.
    #[doc(hidden)]
    pub fn authorize_session_key(&self, key: &SessionKey) -> Result<(), SessionConsumerRejection> {
        let commitment =
            session_consumer_tenant_nf_fields_commitment(key.tenant.as_str(), key.nf_kind.as_str());
        self.allowed_scopes
            .contains(&commitment)
            .then_some(())
            .ok_or(SessionConsumerRejection::Unauthorized)
    }
}

impl fmt::Debug for SessionConsumerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerRequest")
            .field("scope", &self.scope)
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .finish()
    }
}

/// Explicit revision-5-only operations for the V2 fenced-transition
/// contract.
///
/// This is deliberately a distinct request family rather than variants on
/// [`SessionConsumerOperation`]. Revision 3's JSON operation vocabulary and
/// its V1 transition semantics therefore remain frozen byte-for-byte.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SessionConsumerV2Operation {
    /// Prove support for precisely the V2 fenced-transition contract.
    FencedTransitionV2Capability,
    /// Read the bounded public state of the active V2 history epoch.
    FencedTransitionV2HistoryState,
    /// Execute exactly one V2 transition under its full committed identity.
    FencedTransitionV2 {
        /// Complete canonical V2 transition body.
        request: Box<FencedTransitionV2Request>,
    },
    /// Execute an ordered coalescing of independent protected V2 transitions.
    ///
    /// Every item carries its complete 56-byte identity. The outer batch
    /// request ID is intentionally absent here: the quorum store derives its
    /// durable command identity from the ordered full IDs at dispatch time.
    /// One physical command is an optimization; this is not an all-or-nothing
    /// multi-key transaction and every item keeps its own status identity.
    FencedTransitionV2Batch {
        /// Canonical ordered V2 transition bodies.
        requests: Vec<FencedTransitionV2Request>,
    },
    /// Read status for exactly one complete V2 transition body.
    FencedTransitionV2Status {
        /// Complete canonical V2 transition body.
        request: Box<FencedTransitionV2Request>,
    },
}

impl fmt::Debug for SessionConsumerV2Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FencedTransitionV2Capability => "FencedTransitionV2Capability",
            Self::FencedTransitionV2HistoryState => "FencedTransitionV2HistoryState",
            Self::FencedTransitionV2 { .. } => "FencedTransitionV2",
            Self::FencedTransitionV2Batch { .. } => "FencedTransitionV2Batch",
            Self::FencedTransitionV2Status { .. } => "FencedTransitionV2Status",
        };
        formatter.write_str(name)
    }
}

impl SessionConsumerV2Operation {
    fn request_id(&self) -> Option<FencedTransitionV2RequestId> {
        match self {
            Self::FencedTransitionV2 { request } | Self::FencedTransitionV2Status { request } => {
                Some(request.request_id())
            }
            Self::FencedTransitionV2Capability
            | Self::FencedTransitionV2HistoryState
            | Self::FencedTransitionV2Batch { .. } => None,
        }
    }

    /// Validate the bounded V2 request body before quorum dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        match self {
            Self::FencedTransitionV2 { request } | Self::FencedTransitionV2Status { request } => {
                // A complete V2 ID commits to its body. A structurally valid
                // body substituted under a retained full ID is therefore a
                // typed request conflict, not a malformed wire frame. Admit
                // it so execute/status can report their respective conflict
                // semantics; every other validation failure remains a
                // transport rejection.
                match request.validate() {
                    Ok(()) | Err(StoreError::FencedTransitionRequestConflict) => Ok(()),
                    Err(_) => Err(SessionConsumerRejection::MalformedRequest),
                }
            }
            Self::FencedTransitionV2Batch { requests } => {
                validate_fenced_transition_v2_batch(requests)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::FencedTransitionV2Capability | Self::FencedTransitionV2HistoryState => Ok(()),
        }
    }

    /// Whether this operation may have crossed a state-machine effect point
    /// after it has been accepted for quorum dispatch.
    pub const fn is_effectful(&self) -> bool {
        matches!(
            self,
            Self::FencedTransitionV2 { .. } | Self::FencedTransitionV2Batch { .. }
        )
    }
}

/// One scope-bound revision-5 V2 consumer request.
///
/// V2 execute/status retain the full 56-byte V2 request identity outside the
/// operation body as well as inside it. The duplicated value is intentional:
/// it closes truncated-ID and cross-body substitutions before the request can
/// reach the consensus service. Capability and history-state reads have no
/// mutation identity and therefore use `None`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerV2Request {
    scope: SessionConsumerScope,
    request_id: Option<FencedTransitionV2RequestId>,
    operation: SessionConsumerV2Operation,
}

impl SessionConsumerV2Request {
    /// Construct an exact revision-5 V2 request.
    pub fn new(scope: SessionConsumerScope, operation: SessionConsumerV2Operation) -> Self {
        let request_id = operation.request_id();
        Self {
            scope,
            request_id,
            operation,
        }
    }

    /// Exact consensus scope supplied by the caller.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Full V2 stable identity for singleton execute/status, if present.
    ///
    /// A V2 batch deliberately has no caller-controlled outer identity: its
    /// durable batch ID is derived by the store from ordered full item IDs.
    pub const fn request_id(&self) -> Option<FencedTransitionV2RequestId> {
        self.request_id
    }

    /// Typed revision-5-only operation.
    pub const fn operation(&self) -> &SessionConsumerV2Operation {
        &self.operation
    }

    /// Enforce V2's full outer-ID commitment before dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation.validate()?;
        if self.request_id != self.operation.request_id() {
            return Err(SessionConsumerRejection::MalformedRequest);
        }
        Ok(())
    }
}

impl fmt::Debug for SessionConsumerV2Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerV2Request")
            .field("scope", &self.scope)
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .finish()
    }
}

/// Closed, wire-safe store error returned by a consumer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerStoreError {
    /// No live record exists.
    NotFound,
    /// A newer lease owner fenced this request.
    StaleFence,
    /// Compare-and-set did not match the current generation.
    CasConflict,
    /// A request ID was reused for another operation.
    RequestConflict,
    /// A mutation outcome is no longer known.
    OutcomeUnavailable,
    /// Topology authority is unavailable or no quorum is reachable.
    Unavailable,
    /// Input is structurally invalid.
    InvalidInput,
    /// The requested capability is deliberately absent.
    CapabilityNotSupported,
    /// A bounded watch requires coherent catch-up.
    WatchCatchUpRequired,
    /// The restore request or page is invalid.
    RestoreRejected,
    /// The restore cursor is stale.
    RestoreCursorStale,
    /// A restore scan exceeded its work or frame budget.
    RestoreBudgetExceeded,
    /// The requested TTL is invalid.
    InvalidTtl,
    /// The provided lease is held or expired.
    LeaseUnavailable,
    /// A payload exceeded the admitted size.
    PayloadTooLarge,
    /// The backend rejected protected data.
    ProtectedDataRejected,
    /// A protected roster exclusively owns the exact session-record pre-state.
    SessionRecordReserved,
}

impl From<StoreError> for SessionConsumerStoreError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound => Self::NotFound,
            StoreError::StaleFence | StoreError::TopologyAuthorityRevoked => Self::StaleFence,
            StoreError::CasConflict => Self::CasConflict,
            StoreError::CasIdempotencyConflict | StoreError::FencedTransitionRequestConflict => {
                Self::RequestConflict
            }
            // The closed generic store-error family has no specialized
            // fenced-transition exhaustion category. Preserve a fail-closed
            // capability response rather than widening that shared enum.
            StoreError::FencedTransitionHistoryFull
            | StoreError::FencedTransitionRetentionExhausted
            | StoreError::FencedTransitionStorageExhausted
            // These V2-only errors are unreachable through revision 3's V1
            // dispatch. Keep the frozen V1 family closed if a faulty backend
            // nevertheless leaks one across that boundary; revision 5 maps
            // them with `SessionConsumerV2FencedTransitionError` instead.
            | StoreError::FencedTransitionHistoryEpochRetired
            | StoreError::FencedTransitionHistoryEpochNotActive => Self::CapabilityNotSupported,
            StoreError::CasIdempotencyOutcomeUnavailable
            | StoreError::FencedTransitionOutcomeUnknown
            | StoreError::FencedTransitionRequestExpired
            | StoreError::BackendOperationOutcomeUnavailable => Self::OutcomeUnavailable,
            StoreError::BackendUnavailable(_) => Self::Unavailable,
            StoreError::CapabilityNotSupported(_) => Self::CapabilityNotSupported,
            StoreError::InvalidKey(_)
            | StoreError::InvalidReplicationSequence
            | StoreError::InvalidReplicationLogRange
            | StoreError::ReplicationLogPageTooLarge { .. }
            | StoreError::ReplicationLogCursorCompacted { .. }
            | StoreError::ReplicationOperationLimitExceeded
            | StoreError::RecordExpiryPreflightLimitExceeded
            | StoreError::InvalidRecordExpiry => Self::InvalidInput,
            StoreError::ReplicationWatchCatchUpRequired => Self::WatchCatchUpRequired,
            StoreError::InvalidSessionTtl => Self::InvalidTtl,
            StoreError::LeaseHeld | StoreError::LeaseExpired => Self::LeaseUnavailable,
            StoreError::Crypto(_) | StoreError::Serialization(_) => Self::ProtectedDataRejected,
            StoreError::PayloadTooLarge { .. } => Self::PayloadTooLarge,
            StoreError::SessionRecordReserved => Self::SessionRecordReserved,
            StoreError::InvalidRestoreScanRequest(_)
            | StoreError::InvalidRestoreScanResponse(_)
            | StoreError::RestoreScanPageTooLarge { .. } => Self::RestoreRejected,
            StoreError::RestoreScanCursorStale => Self::RestoreCursorStale,
            StoreError::RestoreScanWorkBudgetExceeded
            | StoreError::RestoreScanResponseTooLarge { .. } => Self::RestoreBudgetExceeded,
        }
    }
}

impl SessionConsumerStoreError {
    /// Convert a safe protocol error into the domain error expected by
    /// application-facing storage traits.
    pub fn into_store_error(self) -> StoreError {
        match self {
            Self::NotFound => StoreError::NotFound,
            Self::StaleFence => StoreError::StaleFence,
            Self::CasConflict => StoreError::CasConflict,
            Self::RequestConflict => StoreError::CasIdempotencyConflict,
            Self::OutcomeUnavailable => StoreError::BackendOperationOutcomeUnavailable,
            Self::Unavailable => {
                StoreError::BackendUnavailable("consumer quorum unavailable".into())
            }
            Self::InvalidInput => StoreError::InvalidKey("consumer request rejected".into()),
            Self::CapabilityNotSupported => {
                StoreError::CapabilityNotSupported("consumer capability unavailable".into())
            }
            Self::WatchCatchUpRequired => StoreError::ReplicationWatchCatchUpRequired,
            Self::RestoreRejected => {
                StoreError::InvalidRestoreScanRequest("consumer restore request rejected".into())
            }
            Self::RestoreCursorStale => StoreError::RestoreScanCursorStale,
            Self::RestoreBudgetExceeded => StoreError::RestoreScanWorkBudgetExceeded,
            Self::InvalidTtl => StoreError::InvalidSessionTtl,
            Self::LeaseUnavailable => StoreError::LeaseHeld,
            Self::PayloadTooLarge => StoreError::PayloadTooLarge { actual: 0, max: 0 },
            Self::ProtectedDataRejected => {
                StoreError::Crypto("consumer protected data rejected".into())
            }
            Self::SessionRecordReserved => StoreError::SessionRecordReserved,
        }
    }
}

/// Closed, wire-safe lease error returned by a consumer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerLeaseError {
    /// A caller-owned consumer request ID was reused for another operation.
    RequestConflict,
    /// Another consumer currently owns the lease.
    AlreadyHeld,
    /// The presented lease is expired.
    Expired,
    /// The presented fence is stale.
    StaleFence,
    /// The lease no longer exists.
    NotFound,
    /// The requested TTL is invalid.
    InvalidTtl,
    /// The mutation outcome is unknown and the lease must be treated as lost.
    OutcomeUnavailable,
    /// The quorum is unavailable and the lease must be treated as lost.
    Unavailable,
}

impl From<LeaseError> for SessionConsumerLeaseError {
    fn from(error: LeaseError) -> Self {
        match error {
            LeaseError::AlreadyHeld => Self::AlreadyHeld,
            LeaseError::Expired => Self::Expired,
            LeaseError::StaleFence => Self::StaleFence,
            LeaseError::NotFound => Self::NotFound,
            LeaseError::InvalidSessionTtl => Self::InvalidTtl,
            LeaseError::OperationOutcomeUnavailable => Self::OutcomeUnavailable,
            LeaseError::Backend(_) => Self::Unavailable,
        }
    }
}

impl SessionConsumerLeaseError {
    /// Convert a safe protocol lease error into the application trait error.
    pub fn into_lease_error(self) -> LeaseError {
        match self {
            Self::RequestConflict => LeaseError::Backend("consumer request conflict".into()),
            Self::AlreadyHeld => LeaseError::AlreadyHeld,
            Self::Expired => LeaseError::Expired,
            Self::StaleFence => LeaseError::StaleFence,
            Self::NotFound => LeaseError::NotFound,
            Self::InvalidTtl => LeaseError::InvalidSessionTtl,
            Self::OutcomeUnavailable => LeaseError::OperationOutcomeUnavailable,
            Self::Unavailable => LeaseError::Backend("consumer quorum unavailable".into()),
        }
    }
}

/// Exact persisted result for one ordinary lease mutation receipt.
///
/// This is distinct from a current lease observation.  A successful acquire
/// or renew is returned only from the matching durable consensus outcome, so
/// a later holder, expiry, or TTL change cannot be mistaken for the original
/// mutation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerLeaseMutationResult {
    /// Exact guard persisted by the original acquire request.
    Acquire(LeaseGuard),
    /// Exact guard persisted by the original renew request.
    Renew(LeaseGuard),
    /// Exact successful release receipt.
    Release,
}

/// Exact read-only receipt status for an ordinary lease mutation.
///
/// `NotFound`, transport timeout, and quorum unavailability do not establish
/// that the original mutation was never transmitted.  Callers must therefore
/// keep the original request identity and body and remain fail-closed until a
/// matching [`Self::Recorded`] result is observed or their own ambiguity
/// fence expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerLeaseMutationStatus {
    /// The exact persisted success or deterministic lease error.
    Recorded(Box<Result<SessionConsumerLeaseMutationResult, SessionConsumerLeaseError>>),
    /// The public request identity is durably bound to another exact body.
    RequestConflict,
    /// No matching receipt existed at the completed linearizable read barrier.
    NotFound,
}

/// Exact read-only receipt status for one prepared compare-and-set.
///
/// This projects the existing authoritative consensus outcome ledger. It is
/// not a current-row observation and never replays or proposes the mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerCompareAndSetStatus {
    /// The exact persisted success or deterministic compare-and-set failure.
    Recorded(SessionConsumerCompareAndSetReceiptOutcome),
    /// The public request identity is durably bound to another exact body.
    RequestConflict,
    /// No matching receipt existed at the completed linearizable read barrier.
    NotFound,
}

/// Fixed, payload-free projection of a recorded compare-and-set receipt.
///
/// The consensus ledger may retain an internal `CompareAndSetResult`, but a
/// receipt never serializes a current row or sealed payload back to a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerCompareAndSetReceiptOutcome {
    /// The exact CAS applied.
    Applied,
    /// The exact CAS predicate conflicted.
    Conflict,
    /// The exact CAS was deterministically rejected.
    Rejected(SessionConsumerStoreError),
}

/// Explicit classification for a request that might have crossed its effect
/// point but cannot be confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionConsumerOutcomeUnknown {
    /// An application state mutation may have committed.
    Mutation {
        /// Stable caller-retained identity used for exact status recovery.
        request_id: SessionConsumerRequestId,
    },
    /// A lease mutation may have committed; the current guard is lost.
    Lease,
}

/// Safe deterministic error retained by a fenced-transition receipt.
///
/// This is intentionally a closed projection rather than `StoreError`: a
/// receipt must never serialize backend-provided diagnostic text to a
/// consumer transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerFencedTransitionError {
    /// A deterministic store result represented by the safe consumer error set.
    Store(SessionConsumerStoreError),
    /// The public identity is permanently bound to another body.
    RequestConflict,
    /// The exact retained outcome elapsed.
    Expired,
    /// The permanent receipt ledger cannot bind a new identity.
    HistoryFull,
    /// Logical time cannot retain a complete result window.
    RetentionExhausted,
    /// The deterministic transition receipt could not be retained.
    StorageExhausted,
}

/// Revision-5-only safe error family for V2 execution.
///
/// It is separate from the frozen V1 receipt error enum: V2 can retire a
/// bounded epoch and can be temporarily inactive while a new epoch is being
/// established. Neither condition exists in V1's absorbing-history wire
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerV2FencedTransitionError {
    /// A deterministic error represented by the common safe store set.
    Store(SessionConsumerStoreError),
    /// The committed topology authority no longer admits this operation.
    TopologyAuthorityRevoked,
    /// The V2 transition lifetime is invalid.
    InvalidSessionTtl,
    /// The V2 record expiry is invalid.
    InvalidRecordExpiry,
    /// Another owner still holds the requested lease.
    LeaseHeld,
    /// The presented lease has elapsed.
    LeaseExpired,
    /// A V2 record payload exceeded its fixed profile bound.
    ///
    /// Both widths remain `u64` on every platform. A retained receipt only
    /// admits the fixed maximum and a checked actual length.
    PayloadTooLarge {
        /// Rejected payload size in bytes.
        actual: u64,
        /// Fixed V2 payload maximum in bytes.
        max: u64,
    },
    /// The referenced V2 history epoch was retired and can never execute.
    Retired,
    /// No V2 history epoch is active at this authority yet.
    EpochNotActive,
    /// The complete V2 identity is permanently bound to another body.
    RequestConflict,
    /// The transition may have crossed its effect boundary, but its exact
    /// outcome cannot be confirmed through this response.
    OutcomeUnknown,
    /// The exact retained outcome elapsed for this V2 identity.
    Expired,
    /// The active V2 history epoch cannot bind another identity.
    HistoryFull,
    /// Logical time cannot retain a complete V2 result window.
    RetentionExhausted,
    /// The deterministic V2 transition receipt could not be retained.
    StorageExhausted,
}

impl From<StoreError> for SessionConsumerV2FencedTransitionError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::TopologyAuthorityRevoked => Self::TopologyAuthorityRevoked,
            StoreError::InvalidSessionTtl => Self::InvalidSessionTtl,
            StoreError::InvalidRecordExpiry => Self::InvalidRecordExpiry,
            StoreError::LeaseHeld => Self::LeaseHeld,
            StoreError::LeaseExpired => Self::LeaseExpired,
            StoreError::PayloadTooLarge { actual, max } => Self::PayloadTooLarge {
                actual: actual as u64,
                max: max as u64,
            },
            StoreError::FencedTransitionHistoryEpochRetired => Self::Retired,
            StoreError::FencedTransitionHistoryEpochNotActive => Self::EpochNotActive,
            StoreError::FencedTransitionRequestConflict => Self::RequestConflict,
            StoreError::FencedTransitionOutcomeUnknown => Self::OutcomeUnknown,
            StoreError::FencedTransitionRequestExpired => Self::Expired,
            StoreError::FencedTransitionHistoryFull => Self::HistoryFull,
            StoreError::FencedTransitionRetentionExhausted => Self::RetentionExhausted,
            StoreError::FencedTransitionStorageExhausted => Self::StorageExhausted,
            error => Self::Store(SessionConsumerStoreError::from(error)),
        }
    }
}

impl SessionConsumerV2FencedTransitionError {
    /// Whether this error has the fixed revision-5 wire representation.
    ///
    /// All closed discriminants are wire-valid. The payload-too-large form is
    /// the sole structured variant, so it must retain the frozen maximum and
    /// the architecture-independent bounded actual width before transport
    /// accepts it.
    pub fn is_wire_valid(self) -> bool {
        !matches!(
            self,
            Self::PayloadTooLarge { actual, max }
                if max != FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES as u64
                    || actual <= max
                    || actual > FENCED_TRANSITION_V2_MAX_PAYLOAD_TOO_LARGE_ACTUAL_BYTES
        )
    }

    /// Whether the error is a deterministic admission result that is known
    /// not to have crossed the effect boundary.  This is narrower than the
    /// recorded-receipt set: it is used only to safely reuse a live call lane.
    pub fn is_pre_dispatch_deterministic(self) -> bool {
        self.is_wire_valid()
            && matches!(
                self,
                Self::RequestConflict
                    | Self::Retired
                    | Self::EpochNotActive
                    | Self::Expired
                    | Self::HistoryFull
                    | Self::RetentionExhausted
                    | Self::StorageExhausted
            )
    }

    /// Project a deterministic V2 receipt error into its closed wire form.
    ///
    /// Only errors that the V2 consensus command can durably retain are
    /// admitted here. In particular, backend diagnostics and generic
    /// validation failures must remain outside a retained status response.
    pub fn from_recorded_store_error(error: StoreError) -> Option<Self> {
        matches!(
            error,
            StoreError::TopologyAuthorityRevoked
                | StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::CasConflict
                | StoreError::InvalidSessionTtl
                | StoreError::InvalidRecordExpiry
                | StoreError::LeaseHeld
                | StoreError::LeaseExpired
                | StoreError::PayloadTooLarge { .. }
                | StoreError::FencedTransitionStorageExhausted
        )
        .then(|| Self::from(error))
        .filter(|error| error.is_recorded_deterministic())
    }

    /// Whether this closed V2 error can occur in a durably retained receipt.
    ///
    /// This rejects transport-only categories such as `Unavailable` even
    /// though they are representable by the shared safe store-error family.
    pub fn is_recorded_deterministic(self) -> bool {
        self.is_wire_valid()
            && (matches!(
                self,
                Self::Store(
                    SessionConsumerStoreError::NotFound
                        | SessionConsumerStoreError::StaleFence
                        | SessionConsumerStoreError::CasConflict
                ) | Self::TopologyAuthorityRevoked
                    | Self::InvalidSessionTtl
                    | Self::InvalidRecordExpiry
                    | Self::LeaseHeld
                    | Self::LeaseExpired
                    | Self::StorageExhausted
            ) || matches!(self, Self::PayloadTooLarge { .. }))
    }

    /// Convert this exact V2 wire error back into its storage-domain form.
    ///
    /// Unlike the shared consumer store-error family, each V2 fenced
    /// execution semantic has a lossless mapping so callers can retain the
    /// terminal/recovery distinction after crossing the consumer boundary.
    pub fn into_store_error(self) -> StoreError {
        match self {
            Self::Store(error) => error.into_store_error(),
            Self::TopologyAuthorityRevoked => StoreError::TopologyAuthorityRevoked,
            Self::InvalidSessionTtl => StoreError::InvalidSessionTtl,
            Self::InvalidRecordExpiry => StoreError::InvalidRecordExpiry,
            Self::LeaseHeld => StoreError::LeaseHeld,
            Self::LeaseExpired => StoreError::LeaseExpired,
            Self::PayloadTooLarge { actual, max } => {
                let (Ok(actual), Ok(max)) = (usize::try_from(actual), usize::try_from(max)) else {
                    return StoreError::InvalidKey("invalid V2 payload-too-large receipt".into());
                };
                StoreError::PayloadTooLarge { actual, max }
            }
            Self::Retired => StoreError::FencedTransitionHistoryEpochRetired,
            Self::EpochNotActive => StoreError::FencedTransitionHistoryEpochNotActive,
            Self::RequestConflict => StoreError::FencedTransitionRequestConflict,
            Self::OutcomeUnknown => StoreError::FencedTransitionOutcomeUnknown,
            Self::Expired => StoreError::FencedTransitionRequestExpired,
            Self::HistoryFull => StoreError::FencedTransitionHistoryFull,
            Self::RetentionExhausted => StoreError::FencedTransitionRetentionExhausted,
            Self::StorageExhausted => StoreError::FencedTransitionStorageExhausted,
        }
    }
}

/// Exact correlated result for one item in a protected V2 batch.
///
/// The complete V2 request ID is repeated beside its result so callers can
/// recover each outcome without relying on a position or a truncated ID.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerV2FencedTransitionBatchResult {
    request_id: FencedTransitionV2RequestId,
    result: Result<FencedTransitionOutcome, SessionConsumerV2FencedTransitionError>,
}

impl SessionConsumerV2FencedTransitionBatchResult {
    /// Construct one exact V2 batch item result.
    pub const fn new(
        request_id: FencedTransitionV2RequestId,
        result: Result<FencedTransitionOutcome, SessionConsumerV2FencedTransitionError>,
    ) -> Self {
        Self { request_id, result }
    }

    /// Complete 56-byte request identity correlated with this result.
    pub const fn request_id(&self) -> FencedTransitionV2RequestId {
        self.request_id
    }

    /// Deterministic success or safe V2 execution error for this item.
    pub const fn result(
        &self,
    ) -> &Result<FencedTransitionOutcome, SessionConsumerV2FencedTransitionError> {
        &self.result
    }
}

impl fmt::Debug for SessionConsumerV2FencedTransitionBatchResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerV2FencedTransitionBatchResult(<redacted>)")
    }
}

/// Safe batch-level error for a protected V2 transition batch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum SessionConsumerV2FencedTransitionBatchError {
    /// A deterministic request-level error represented by the common safe
    /// consumer error family.
    Store(SessionConsumerStoreError),
    /// The batch may have crossed its effect point. Every item identity is
    /// retained for exact singleton-status recovery; automatic replay is
    /// forbidden.
    OutcomeUnknown {
        /// Ordered complete V2 request identities from the ambiguous batch.
        request_ids: Vec<FencedTransitionV2RequestId>,
    },
}

impl SessionConsumerV2FencedTransitionBatchError {
    /// Build the explicit ambiguous-outcome classification for one batch.
    pub fn outcome_unknown(
        request_ids: Vec<FencedTransitionV2RequestId>,
    ) -> Result<Self, SessionConsumerRejection> {
        validate_v2_batch_ids(&request_ids)?;
        Ok(Self::OutcomeUnknown { request_ids })
    }

    /// Validate fixed correlation and full encoded response bounds.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        match self {
            Self::Store(_) => Ok(()),
            Self::OutcomeUnknown { request_ids } => validate_v2_batch_ids(request_ids),
        }
    }
}

impl fmt::Debug for SessionConsumerV2FencedTransitionBatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerV2FencedTransitionBatchError(<redacted>)")
    }
}

impl From<StoreError> for SessionConsumerV2FencedTransitionBatchError {
    fn from(error: StoreError) -> Self {
        Self::Store(SessionConsumerStoreError::from(error))
    }
}

/// Validate ordered protected V2 batch response items before transmission.
pub fn validate_session_consumer_v2_fenced_transition_batch_results(
    results: &[SessionConsumerV2FencedTransitionBatchResult],
) -> Result<(), SessionConsumerRejection> {
    let ids = results
        .iter()
        .map(SessionConsumerV2FencedTransitionBatchResult::request_id)
        .collect::<Vec<_>>();
    validate_v2_batch_ids(&ids)?;
    let encoded = opc_consensus::encode_bounded(results)
        .map_err(|_| SessionConsumerRejection::MalformedRequest)?;
    if encoded.len() > MAX_SESSION_CONSUMER_V2_FENCED_TRANSITION_BATCH_RESPONSE_BYTES {
        return Err(SessionConsumerRejection::MalformedRequest);
    }
    Ok(())
}

fn validate_v2_batch_ids(
    request_ids: &[FencedTransitionV2RequestId],
) -> Result<(), SessionConsumerRejection> {
    if request_ids.is_empty()
        || request_ids.len() > MAX_SESSION_CONSUMER_V2_FENCED_TRANSITION_BATCH_OPERATIONS
    {
        return Err(SessionConsumerRejection::MalformedRequest);
    }
    let epoch = request_ids[0].epoch();
    let mut ids = BTreeSet::new();
    for request_id in request_ids {
        if request_id.epoch() != epoch || !ids.insert(request_id.to_bytes()) {
            return Err(SessionConsumerRejection::MalformedRequest);
        }
    }
    Ok(())
}

impl From<StoreError> for SessionConsumerFencedTransitionError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::FencedTransitionRequestConflict => Self::RequestConflict,
            StoreError::FencedTransitionRequestExpired => Self::Expired,
            StoreError::FencedTransitionHistoryFull => Self::HistoryFull,
            StoreError::FencedTransitionRetentionExhausted => Self::RetentionExhausted,
            StoreError::FencedTransitionStorageExhausted => Self::StorageExhausted,
            error => Self::Store(SessionConsumerStoreError::from(error)),
        }
    }
}

/// Exact consumer-safe status of a fenced transition request/body pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerFencedTransitionStatus {
    /// A success or deterministic error remains recoverable.
    Recorded(Box<Result<FencedTransitionOutcome, SessionConsumerFencedTransitionError>>),
    /// The identity is bound to another body.
    RequestConflict,
    /// The exact recovery window elapsed.
    Expired,
    /// The receipt ledger is full for a fresh identity.
    HistoryFull,
    /// The retention horizon is exhausted for a fresh identity.
    RetentionExhausted,
    /// No request/body receipt existed at the read barrier.
    NotFound,
}

impl From<FencedTransitionStatus> for SessionConsumerFencedTransitionStatus {
    fn from(status: FencedTransitionStatus) -> Self {
        match status {
            FencedTransitionStatus::Recorded(result) => Self::Recorded(Box::new(
                result.map_err(SessionConsumerFencedTransitionError::from),
            )),
            FencedTransitionStatus::RequestConflict => Self::RequestConflict,
            FencedTransitionStatus::Expired => Self::Expired,
            FencedTransitionStatus::HistoryFull => Self::HistoryFull,
            FencedTransitionStatus::RetentionExhausted => Self::RetentionExhausted,
            FencedTransitionStatus::NotFound => Self::NotFound,
        }
    }
}

/// Closed, wire-safe V2 status of a fenced transition request/body pair.
///
/// Unlike the storage-domain [`FencedTransitionV2Status`], a recorded error
/// here cannot carry backend diagnostics, platform-sized fields, or future
/// unconstrained store variants across the revision-5 consumer transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum SessionConsumerV2FencedTransitionStatus {
    /// A success or deterministic V2 error remains recoverable.
    Recorded(Box<Result<FencedTransitionOutcome, SessionConsumerV2FencedTransitionError>>),
    /// The complete ID is bound to another body.
    RequestConflict,
    /// The exact recovery window elapsed.
    Expired,
    /// The request epoch is retired permanently.
    Retired,
    /// The active epoch cannot bind another identity.
    HistoryFull,
    /// No receipt exists for this complete V2 identity.
    NotFound,
    /// The named epoch is not active yet.
    EpochNotActive,
    /// Logical time cannot retain a complete result window.
    RetentionExhausted,
}

impl TryFrom<FencedTransitionV2Status> for SessionConsumerV2FencedTransitionStatus {
    type Error = SessionConsumerStoreError;

    fn try_from(status: FencedTransitionV2Status) -> Result<Self, Self::Error> {
        match status {
            FencedTransitionV2Status::Recorded(result) => match *result {
                Ok(outcome) => Ok(Self::Recorded(Box::new(Ok(outcome)))),
                Err(error) => {
                    SessionConsumerV2FencedTransitionError::from_recorded_store_error(error)
                        .map(|error| Self::Recorded(Box::new(Err(error))))
                        // Do not project untrusted backend diagnostics or an
                        // unexpected generic store error into a durable receipt.
                        .ok_or(SessionConsumerStoreError::Unavailable)
                }
            },
            FencedTransitionV2Status::RequestConflict => Ok(Self::RequestConflict),
            FencedTransitionV2Status::Expired => Ok(Self::Expired),
            FencedTransitionV2Status::Retired => Ok(Self::Retired),
            FencedTransitionV2Status::HistoryFull => Ok(Self::HistoryFull),
            FencedTransitionV2Status::NotFound => Ok(Self::NotFound),
            FencedTransitionV2Status::EpochNotActive => Ok(Self::EpochNotActive),
            FencedTransitionV2Status::RetentionExhausted => Ok(Self::RetentionExhausted),
        }
    }
}

/// Least-authority committed-change projection for application consumers.
///
/// This is intentionally not a replication entry: it omits replay payloads,
/// lease credentials, absolute deadlines, transaction IDs, and raw
/// replication operation trees.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerChange {
    sequence: u64,
    changes: Vec<SessionConsumerChangeItem>,
}

/// One affected session key within a [`SessionConsumerChange`].
///
/// This is a deliberately coarse projection. It is not a lease credential,
/// fence, expiry, owner, record payload, replication transaction, or replay
/// instruction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerChangeItem {
    key: SessionKey,
    kind: SessionConsumerChangeKind,
}

impl SessionConsumerChange {
    /// Committed change sequence used only as a consumer watch cursor.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Coarse affected keys in their committed batch order.
    ///
    /// One replication sequence can contain a bounded nested batch, so the
    /// consumer projection preserves every leaf change in one envelope rather
    /// than dropping all but the first key.
    pub fn changes(&self) -> &[SessionConsumerChangeItem] {
        self.changes.as_slice()
    }
}

impl fmt::Debug for SessionConsumerChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerChange(<redacted>)")
    }
}

impl SessionConsumerChangeItem {
    /// Session key affected by this committed leaf change.
    pub const fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Coarse application-visible change kind.
    pub const fn kind(&self) -> SessionConsumerChangeKind {
        self.kind
    }
}

impl fmt::Debug for SessionConsumerChangeItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerChangeItem(<redacted>)")
    }
}

/// Coarse committed change class exposed by [`SessionConsumerChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionConsumerChangeKind {
    /// A session record was created or replaced.
    RecordWritten,
    /// A session record was deleted.
    RecordDeleted,
    /// A session record TTL changed.
    RecordTtlRefreshed,
    /// A session lease was acquired.
    LeaseAcquired,
    /// A session lease was renewed.
    LeaseRenewed,
    /// A session lease was released.
    LeaseReleased,
}

#[cfg(test)]
pub(crate) fn session_consumer_change(
    entry: &crate::ReplicationEntry,
) -> Result<SessionConsumerChange, StoreError> {
    // A replication batch is a recursive replay instruction. Flatten it
    // iteratively so a historical bounded nested batch remains faithfully
    // observable without exposing that instruction tree at the consumer
    // boundary. Count both batch containers and leaves under the existing
    // SDK-wide admission cap; a malformed stored entry therefore fails the
    // watch closed instead of allocating an unbounded projection.
    let mut pending = vec![&entry.op];
    let mut visited = 0_usize;
    let mut changes = Vec::with_capacity(MAX_REPLICATION_OPERATIONS_PER_ENTRY);
    while let Some(operation) = pending.pop() {
        visited = visited
            .checked_add(1)
            .ok_or(StoreError::ReplicationOperationLimitExceeded)?;
        if visited > MAX_REPLICATION_OPERATIONS_PER_ENTRY {
            return Err(StoreError::ReplicationOperationLimitExceeded);
        }
        let item = match operation {
            crate::ReplicationOp::CompareAndSet { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::RecordWritten,
            }),
            crate::ReplicationOp::DeleteFenced { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::RecordDeleted,
            }),
            crate::ReplicationOp::RefreshTtl { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::RecordTtlRefreshed,
            }),
            crate::ReplicationOp::AcquireLease { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::LeaseAcquired,
            }),
            crate::ReplicationOp::RenewLease { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::LeaseRenewed,
            }),
            crate::ReplicationOp::ReleaseLease { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::LeaseReleased,
            }),
            crate::ReplicationOp::ProtectedRosterEstablished { key, successor, .. } => {
                // This journal variant is emitted only for an Established
                // terminal after the SQLite replay adapter has compared the
                // exact admission-reserved row under its current owner/fence
                // guard. Its public watch projection must preserve that
                // authoritative row effect without exposing the guard or any
                // roster proof material. Aborted terminals and retained
                // replays never construct this replication operation.
                let kind = match &**successor {
                    ProtectedRosterEstablishedSuccessor::Put { .. }
                    | ProtectedRosterEstablishedSuccessor::NoOp => {
                        SessionConsumerChangeKind::RecordWritten
                    }
                    ProtectedRosterEstablishedSuccessor::Delete => {
                        SessionConsumerChangeKind::RecordDeleted
                    }
                };
                Some(SessionConsumerChangeItem {
                    key: key.clone(),
                    kind,
                })
            }
            crate::ReplicationOp::ProtectedRosterEstablishedCreate { key, .. } => {
                Some(SessionConsumerChangeItem {
                    key: key.clone(),
                    kind: SessionConsumerChangeKind::RecordWritten,
                })
            }
            crate::ReplicationOp::Batch { ops } => {
                pending.extend(ops.iter().rev());
                None
            }
        };
        if let Some(item) = item {
            changes.push(item);
        }
    }
    Ok(SessionConsumerChange {
        sequence: entry.sequence,
        changes,
    })
}

/// Closed rejection before an operation reaches the consensus state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionConsumerRejection {
    /// Cluster/configuration/epoch differs from the live quorum scope.
    ScopeMismatch,
    /// The authenticated Hello named a different exact state-voter topology.
    ///
    /// This is intentionally distinct from [`Self::Unauthorized`]: a peer
    /// can prove the caller's identity yet reject its expected node, voter
    /// count, or roster commitment after an authority cutover. Clients must
    /// stop an activated exact-roster handle rather than rotate it as a
    /// transient credential failure.
    TopologyMismatch,
    /// The typed request violated a fixed contract bound.
    MalformedRequest,
    /// The mTLS identity is not authorized as a consumer.
    Unauthorized,
    /// The server cannot dispatch the request within its bound.
    Unavailable,
}

/// Safe result of one batch slot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SessionConsumerBatchResult {
    /// Point-read slot result.
    Get(Result<Option<StoredSessionRecord>, SessionConsumerStoreError>),
    /// Compare-and-set slot result.
    CompareAndSet(Result<CompareAndSetResult, SessionConsumerStoreError>),
    /// Delete slot result.
    DeleteFenced(Result<(), SessionConsumerStoreError>),
    /// TTL-refresh slot result.
    RefreshTtl(Result<(), SessionConsumerStoreError>),
}

impl fmt::Debug for SessionConsumerBatchResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerBatchResult(<redacted>)")
    }
}

/// Typed response from one stateless consumer operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "response",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerResponse {
    /// Capability declaration.
    Capabilities(BackendCapabilities),
    /// Point-read result.
    Get(Result<Option<StoredSessionRecord>, SessionConsumerStoreError>),
    /// Record-expiry preflight result.
    PreflightRecordExpiry(Result<(), SessionConsumerStoreError>),
    /// Compare-and-set result.
    CompareAndSet(Result<CompareAndSetResult, SessionConsumerStoreError>),
    /// Delete result.
    DeleteFenced(Result<(), SessionConsumerStoreError>),
    /// TTL-refresh result.
    RefreshTtl(Result<(), SessionConsumerStoreError>),
    /// Batch result.
    Batch(Result<Vec<SessionConsumerBatchResult>, SessionConsumerStoreError>),
    /// Restore scan result.
    ScanRestoreRecords(Result<RestoreScanPage, SessionConsumerStoreError>),
    /// Watch admission result; entries follow as separately framed messages.
    WatchOpened,
    /// Lease acquisition result.
    AcquireLease(Result<LeaseGuard, SessionConsumerLeaseError>),
    /// Lease renewal result.
    RenewLease(Result<LeaseGuard, SessionConsumerLeaseError>),
    /// Lease release result.
    ReleaseLease(Result<(), SessionConsumerLeaseError>),
    /// Exact read-only receipt status for an ordinary lease mutation.
    LeaseMutationStatus(Result<SessionConsumerLeaseMutationStatus, SessionConsumerStoreError>),
    /// Exact read-only receipt status for a prepared compare-and-set.
    CompareAndSetStatus(Result<SessionConsumerCompareAndSetStatus, SessionConsumerStoreError>),
    /// Exact unanimous atomic-transition capability result.
    FencedTransitionCapability(Result<AtomicFencedTransitionCapability, SessionConsumerStoreError>),
    /// Exact-key record and fence-floor observation.
    ObserveFencedTransition(Result<FencedTransitionObservation, SessionConsumerStoreError>),
    /// Atomic lease-and-record transition result.
    FencedTransition(Result<FencedTransitionOutcome, SessionConsumerFencedTransitionError>),
    /// Exact retained transition status.
    FencedTransitionStatus(
        Result<SessionConsumerFencedTransitionStatus, SessionConsumerStoreError>,
    ),
    /// Outcome of the sole fresh protected-roster admission mutation.
    FencedMutationRosterPollAdmit(SessionConsumerRosterAdmissionMutationResponse),
    /// Read-only exact status of an original protected-roster admission.
    FencedMutationRosterAdmissionStatus(SessionConsumerRosterAdmissionReadResponse),
    /// Read-only protected-roster recovery under current authority.
    FencedMutationRosterRecover(SessionConsumerRosterAdmissionReadResponse),
    /// Outcome of the sole protected-roster terminal mutation.
    FencedMutationRosterTerminalize(SessionConsumerRosterTerminalMutationResponse),
    /// Read-only exact protected-roster terminal status.
    FencedMutationRosterTerminalStatus(SessionConsumerRosterTerminalReadResponse),
    /// Read-only exact backend-current authority for an Established
    /// publication. This carries no authority or receipt bytes.
    FencedMutationRosterCurrentPublicationAuthority(
        SessionConsumerRosterCurrentPublicationAuthorityReadResponse,
    ),
    /// A mutation outcome is ambiguous and must never be automatically replayed.
    OutcomeUnknown(SessionConsumerOutcomeUnknown),
    /// A request was rejected before dispatch.
    Rejected(SessionConsumerRejection),
}

/// Typed response carried only by the revision-5 V2 consumer lane.
///
/// This intentionally does not extend [`SessionConsumerResponse`]: adding a
/// V2 response discriminator there would allow a revision-3 decoder to
/// accept a new semantic contract.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "response",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerV2Response {
    /// Exact V2 capability proof result.
    FencedTransitionV2Capability(Result<FencedTransitionV2Capability, SessionConsumerStoreError>),
    /// Bounded current V2 history state.
    FencedTransitionV2HistoryState(
        Result<FencedTransitionV2HistoryState, SessionConsumerStoreError>,
    ),
    /// Exact V2 execution result.
    FencedTransitionV2(Result<FencedTransitionOutcome, SessionConsumerV2FencedTransitionError>),
    /// Ordered, full-ID-correlated V2 batch execution result.
    FencedTransitionV2Batch(
        Result<
            Vec<SessionConsumerV2FencedTransitionBatchResult>,
            SessionConsumerV2FencedTransitionBatchError,
        >,
    ),
    /// Exact V2 retained-status result.
    FencedTransitionV2Status(
        Result<SessionConsumerV2FencedTransitionStatus, SessionConsumerStoreError>,
    ),
    /// The V2 operation was rejected before dispatch.
    Rejected(SessionConsumerRejection),
}

impl fmt::Debug for SessionConsumerV2Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FencedTransitionV2Capability(_) => "FencedTransitionV2Capability",
            Self::FencedTransitionV2HistoryState(_) => "FencedTransitionV2HistoryState",
            Self::FencedTransitionV2(_) => "FencedTransitionV2",
            Self::FencedTransitionV2Batch(_) => "FencedTransitionV2Batch",
            Self::FencedTransitionV2Status(_) => "FencedTransitionV2Status",
            Self::Rejected(_) => "Rejected",
        };
        formatter.write_str(name)
    }
}

impl fmt::Debug for SessionConsumerResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Capabilities(_) => "Capabilities",
            Self::Get(_) => "Get",
            Self::PreflightRecordExpiry(_) => "PreflightRecordExpiry",
            Self::CompareAndSet(_) => "CompareAndSet",
            Self::DeleteFenced(_) => "DeleteFenced",
            Self::RefreshTtl(_) => "RefreshTtl",
            Self::Batch(_) => "Batch",
            Self::ScanRestoreRecords(_) => "ScanRestoreRecords",
            Self::WatchOpened => "WatchOpened",
            Self::AcquireLease(_) => "AcquireLease",
            Self::RenewLease(_) => "RenewLease",
            Self::ReleaseLease(_) => "ReleaseLease",
            Self::LeaseMutationStatus(_) => "LeaseMutationStatus",
            Self::CompareAndSetStatus(_) => "CompareAndSetStatus",
            Self::FencedTransitionCapability(_) => "FencedTransitionCapability",
            Self::ObserveFencedTransition(_) => "ObserveFencedTransition",
            Self::FencedTransition(_) => "FencedTransition",
            Self::FencedTransitionStatus(_) => "FencedTransitionStatus",
            Self::FencedMutationRosterPollAdmit(_) => "FencedMutationRosterPollAdmit",
            Self::FencedMutationRosterAdmissionStatus(_) => "FencedMutationRosterAdmissionStatus",
            Self::FencedMutationRosterRecover(_) => "FencedMutationRosterRecover",
            Self::FencedMutationRosterTerminalize(_) => "FencedMutationRosterTerminalize",
            Self::FencedMutationRosterTerminalStatus(_) => "FencedMutationRosterTerminalStatus",
            Self::FencedMutationRosterCurrentPublicationAuthority(_) => {
                "FencedMutationRosterCurrentPublicationAuthority"
            }
            Self::OutcomeUnknown(_) => "OutcomeUnknown",
            Self::Rejected(_) => "Rejected",
        };
        formatter.write_str(name)
    }
}

/// Quorum-side typed application service used by the dedicated consumer
/// transport.
///
/// Implementations must receive a store-manifest-issued authorization from
/// their inbound boundary, reject a scope mismatch before backend work, and
/// route mutations through the durable quorum leader path. This trait intentionally cannot
/// express any consensus RPC, member/topology mutation, snapshot, or raw
/// replication append/rebuild request.
#[async_trait]
pub trait SessionQuorumConsumer: Send + Sync {
    /// Execute one authenticated, scope-bound consumer request.
    async fn execute(
        &self,
        authorization: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse;

    /// Execute one authenticated revision-5 V2 request.
    ///
    /// The default does no backend work and keeps an existing V1-only quorum
    /// implementation fail-closed on the new lane. Implementations that
    /// advertise V2 override this method and must perform the same scope and
    /// durable leader checks as [`Self::execute`].
    async fn execute_v2(
        &self,
        _authorization: &SessionConsumerAuthorization,
        _request: SessionConsumerV2Request,
    ) -> SessionConsumerV2Response {
        SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
    }

    /// Open a bounded committed-change watch after authenticated scope checks.
    async fn watch(
        &self,
        authorization: &SessionConsumerAuthorization,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    >;
}

#[cfg(test)]
fn invoke_legacy_roster_ingress_for_profile<T>(
    profile: SessionConsumerRosterTransportProfile,
    invoke: impl FnOnce() -> T,
) -> Result<T, SessionConsumerRosterRejection> {
    profile
        .is_current()
        .then(invoke)
        .ok_or(SessionConsumerRosterRejection::Capability)
}

/// Dedicated protected-roster ingress port.
///
/// Unlike [`SessionQuorumConsumer`], this port is usable only with a
/// root-certified transport-ingress attestation for one exact roster request.
/// The ordinary service must reject every roster operation before it decodes
/// or looks up the opaque capsule.
#[async_trait]
pub trait SessionQuorumRosterIngress: Send + Sync {
    /// Return the topology-provisioned verifier-root identity expected by this
    /// ingress. The fail-closed default keeps legacy/custom implementations
    /// source compatible but prevents them from enabling the protected lane.
    fn expected_roster_attestation_trust_root_identity(
        &self,
    ) -> Option<crate::fenced_mutation_roster::RosterAttestationTrustRootIdentityV1> {
        None
    }

    /// Prepare the exact compact-admission signer input after this ingress has
    /// authenticated the V1 connection and decoded the exact PollAdmit body.
    ///
    /// This is deliberately a narrow pre-sign seam: it exposes commitments
    /// and the already authenticated ingress input, never a store, raw
    /// consensus authority, or an arbitrary signing preimage.  The default
    /// keeps legacy ingress implementations fail-closed on the protected
    /// compact-provenance profile.
    fn prepare_compact_admission_provenance_input(
        &self,
        _authorization: &SessionConsumerRosterAuthorization,
        _request: &SessionConsumerRequest,
        _attestation: &crate::fenced_mutation_roster::RosterIngressAttestationV1,
        _certificate_subject_identity_commitment: [u8; 32],
    ) -> Result<
        crate::fenced_mutation_roster::RosterCompactAdmissionProvenanceSigningInputV2,
        SessionConsumerRosterRejection,
    > {
        Err(SessionConsumerRosterRejection::Capability)
    }

    /// Prepare the exact compact-admission signer input for one negotiated
    /// protected-roster profile.
    ///
    /// The source-compatible default preserves the frozen V1 path exactly.
    /// It rejects V2 before legacy ingress code can decode a capsule, look up
    /// roster state, or submit consensus work. An ingress that intentionally
    /// supports V2 must override this method and validate the profile before
    /// performing any profile-dependent recovery or admission lookup.
    fn prepare_compact_admission_provenance_input_for_profile(
        &self,
        profile: SessionConsumerRosterTransportProfile,
        authorization: &SessionConsumerRosterAuthorization,
        request: &SessionConsumerRequest,
        attestation: &crate::fenced_mutation_roster::RosterIngressAttestation,
        certificate_subject_identity_commitment: [u8; 32],
    ) -> Result<
        crate::fenced_mutation_roster::RosterCompactAdmissionProvenanceInput,
        SessionConsumerRosterRejection,
    > {
        if !profile.is_current() {
            return Err(SessionConsumerRosterRejection::Capability);
        }
        let crate::fenced_mutation_roster::RosterIngressAttestation::V1(attestation) = attestation
        else {
            return Err(SessionConsumerRosterRejection::Capability);
        };
        self.prepare_compact_admission_provenance_input(
            authorization,
            request,
            attestation,
            certificate_subject_identity_commitment,
        )
        .map(crate::fenced_mutation_roster::RosterCompactAdmissionProvenanceInput::V1)
    }

    /// Dispatch one already-authenticated revision-five protected-roster
    /// request.
    ///
    /// Implementations must first verify the root-certified `attestation`,
    /// then canonically decode the request capsule and call
    /// [`SessionConsumerRosterAuthorization::authorize_session_key`] on its
    /// exact decoded authority/admission key before any roster lookup or
    /// consensus work. A cross-tenant or wrong-NF key must not be accepted.
    async fn execute_roster_ingress(
        &self,
        authorization: &SessionConsumerRosterAuthorization,
        request: SessionConsumerRequest,
        attestation: crate::fenced_mutation_roster::RosterIngressAttestationV1,
        admission_provenance: Option<
            crate::fenced_mutation_roster::RosterCompactAdmissionProvenanceV2,
        >,
    ) -> SessionConsumerResponse;

    /// Dispatch one already-authenticated request for the exact negotiated
    /// protected-roster profile.
    ///
    /// The default delegates only the frozen V1 profile to the existing
    /// ingress method. V2 fails closed before legacy ingress code can inspect
    /// a capsule or touch provider/consensus state.
    async fn execute_roster_ingress_for_profile(
        &self,
        profile: SessionConsumerRosterTransportProfile,
        authorization: &SessionConsumerRosterAuthorization,
        request: SessionConsumerRequest,
        attestation: crate::fenced_mutation_roster::RosterIngressAttestation,
        admission_provenance: Option<
            crate::fenced_mutation_roster::RosterCompactAdmissionProvenance,
        >,
    ) -> SessionConsumerResponse {
        if !profile.is_current() {
            return SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest);
        }
        let crate::fenced_mutation_roster::RosterIngressAttestation::V1(attestation) = attestation
        else {
            return SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest);
        };
        let admission_provenance = match admission_provenance {
            Some(crate::fenced_mutation_roster::RosterCompactAdmissionProvenance::V1(value)) => {
                Some(value)
            }
            None => None,
            Some(crate::fenced_mutation_roster::RosterCompactAdmissionProvenance::V2(_)) => {
                return SessionConsumerResponse::Rejected(
                    SessionConsumerRejection::MalformedRequest,
                );
            }
        };
        self.execute_roster_ingress(authorization, request, attestation, admission_provenance)
            .await
    }
}

/// Derive the exact opaque commitment of an authenticated peer identity for a
/// root-certified transport-ingress statement.
#[doc(hidden)]
pub fn session_consumer_identity_commitment(identity: &SessionConsumerIdentity) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/ingress-peer/v1\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    digest.finalize().into()
}

/// Return the fixed protected-roster authority scope committed by the ingress
/// certificate and statement for one consumer scope.
#[doc(hidden)]
pub fn session_consumer_roster_scope_commitment(scope: SessionConsumerScope) -> [u8; 32] {
    crate::fenced_mutation_roster_transport::protected_roster_scope_from_consumer_scope(scope)
        .digest()
}

/// Return the fixed operation tag and canonical opaque capsule digest for a
/// protected-roster ingress statement.
///
/// This deliberately does not decode the capsule. The dedicated ingress
/// service verifies the resulting statement before it hands exact bytes to
/// the roster transport decoder.
#[doc(hidden)]
pub fn session_consumer_roster_ingress_operation(
    operation: &SessionConsumerOperation,
) -> Result<(u8, [u8; 32]), SessionConsumerRosterRejection> {
    let (tag, capsule) = match operation {
        SessionConsumerOperation::FencedMutationRosterPollAdmit { request } => {
            (1_u8, request.canonical_bytes())
        }
        SessionConsumerOperation::FencedMutationRosterAdmissionStatus { request } => {
            (2_u8, request.canonical_bytes())
        }
        SessionConsumerOperation::FencedMutationRosterRecover { request } => {
            (3_u8, request.canonical_bytes())
        }
        SessionConsumerOperation::FencedMutationRosterTerminalize { request } => {
            (4_u8, request.canonical_bytes())
        }
        SessionConsumerOperation::FencedMutationRosterTerminalStatus { request } => {
            (5_u8, request.canonical_bytes())
        }
        SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority { request } => {
            // This structured capsule is itself the canonical authenticated
            // input to the dedicated revision-five ingress discriminator.
            // Serialize only after its operation-level validation above.
            let capsule = serde_json::to_vec(request.as_ref())
                .map_err(|_| SessionConsumerRosterRejection::Malformed)?;
            return Ok((
                6_u8,
                crate::fenced_mutation_roster::roster_ingress_capsule_commitment(6_u8, &capsule)
                    .map_err(|_| SessionConsumerRosterRejection::Capability)?,
            ));
        }
        _ => return Err(SessionConsumerRosterRejection::Capability),
    };
    let digest = crate::fenced_mutation_roster::roster_ingress_capsule_commitment(tag, capsule)
        .map_err(|_| SessionConsumerRosterRejection::Capability)?;
    Ok((tag, digest))
}

/// Convert an application batch result into its wire-safe counterpart.
pub fn session_consumer_batch_result(result: SessionOpResult) -> SessionConsumerBatchResult {
    match result {
        SessionOpResult::Get(result) => {
            SessionConsumerBatchResult::Get(result.map_err(SessionConsumerStoreError::from))
        }
        SessionOpResult::CompareAndSet(result) => SessionConsumerBatchResult::CompareAndSet(
            result.map_err(SessionConsumerStoreError::from),
        ),
        SessionOpResult::DeleteFenced(result) => SessionConsumerBatchResult::DeleteFenced(
            result.map_err(SessionConsumerStoreError::from),
        ),
        SessionOpResult::RefreshTtl(result) => {
            SessionConsumerBatchResult::RefreshTtl(result.map_err(SessionConsumerStoreError::from))
        }
    }
}

/// Convert a consumer batch result into the application-facing result.
pub fn session_consumer_batch_result_into_store(
    result: SessionConsumerBatchResult,
) -> SessionOpResult {
    match result {
        SessionConsumerBatchResult::Get(result) => {
            SessionOpResult::Get(result.map_err(SessionConsumerStoreError::into_store_error))
        }
        SessionConsumerBatchResult::CompareAndSet(result) => SessionOpResult::CompareAndSet(
            result.map_err(SessionConsumerStoreError::into_store_error),
        ),
        SessionConsumerBatchResult::DeleteFenced(result) => SessionOpResult::DeleteFenced(
            result.map_err(SessionConsumerStoreError::into_store_error),
        ),
        SessionConsumerBatchResult::RefreshTtl(result) => {
            SessionOpResult::RefreshTtl(result.map_err(SessionConsumerStoreError::into_store_error))
        }
    }
}

/// Derive the durable consumer-request binding ID from an authenticated
/// identity and caller-owned request ID.
///
/// This deliberately excludes the operation commitment: the resulting ID is
/// used for a small quorum-durable binding command, whose payload commitment
/// makes reuse of this caller ID for a different request a closed conflict.
pub(crate) fn derive_consumer_request_binding_id(
    identity: &SessionConsumerIdentity,
    request: &SessionConsumerRequest,
) -> SessionConsensusRequestId {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/request-binding/v1\\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    // Keep this stable across a configuration-epoch transition. The marker
    // payload commits the exact scope, so an old caller ID can only recover
    // its original binding or receive a closed conflict; it cannot become a
    // fresh mutation in a successor scope.
    digest.update(request.scope().consensus_identity().cluster_id().as_bytes());
    digest.update(request.request_id().as_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut request_bytes = [0_u8; SESSION_CONSUMER_REQUEST_ID_BYTES];
    request_bytes.copy_from_slice(&hash[..SESSION_CONSUMER_REQUEST_ID_BYTES]);
    SessionConsensusRequestId::from_bytes(request_bytes)
}

/// Hash the full serialized request shape without exposing protected contents.
pub(crate) fn consumer_request_commitment(
    request: &SessionConsumerRequest,
) -> Result<[u8; 32], SessionConsumerRejection> {
    use sha2::{Digest, Sha256};

    let encoded =
        serde_json::to_vec(request).map_err(|_| SessionConsumerRejection::MalformedRequest)?;
    #[cfg(test)]
    {
        let _ = CONSUMER_REQUEST_COMMITMENT_V2_TEST_COUNTERS.try_with(|counters| {
            counters.record(encoded.len());
        });
    }
    let mut digest = Sha256::new();
    // Keep the ordinary request commitment domain at v2 after the removed
    // prepared wire field changed the serialized shape. A reused legacy
    // binding can therefore only conflict closed; no v1 interpretation is
    // accepted.
    digest.update(b"openpacketcore/session-consumer/request-commitment/v2\\0");
    digest.update(encoded);
    Ok(digest.finalize().into())
}

/// Test-only accounting for whole-request v2 commitment serialization. The
/// task-local scope keeps allocation evidence isolated when the test runner
/// executes unrelated consumer calls concurrently. The production path
/// retains no metrics labels, request IDs, or payload copies.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct ConsumerRequestCommitmentV2TestCounters {
    serializations: AtomicUsize,
    serialized_bytes: AtomicUsize,
}

#[cfg(test)]
impl ConsumerRequestCommitmentV2TestCounters {
    fn record(&self, encoded_bytes: usize) {
        self.serializations.fetch_add(1, Ordering::Relaxed);
        self.serialized_bytes
            .fetch_add(encoded_bytes, Ordering::Relaxed);
    }

    pub(crate) fn serializations(&self) -> usize {
        self.serializations.load(Ordering::Relaxed)
    }

    pub(crate) fn serialized_bytes(&self) -> usize {
        self.serialized_bytes.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
tokio::task_local! {
    pub(crate) static CONSUMER_REQUEST_COMMITMENT_V2_TEST_COUNTERS:
        Arc<ConsumerRequestCommitmentV2TestCounters>;
}

/// Derive the operation-specific durable consensus request ID from an
/// authenticated identity, the complete request commitment, and bounded batch
/// slot. The full parent request shape prevents a changed batch from moving a
/// mutation onto an unrelated slot's durable outcome.
pub fn derive_consumer_consensus_request_id(
    identity: &SessionConsumerIdentity,
    request: &SessionConsumerRequest,
    slot: u16,
) -> Result<SessionConsensusRequestId, SessionConsumerRejection> {
    let commitment = consumer_request_commitment(request)?;
    Ok(derive_consumer_consensus_request_id_from_commitment(
        identity, commitment, slot,
    ))
}

/// Derive an operation receipt ID from one already-authenticated full request
/// commitment. Receipt lookup uses this to avoid serializing the retained body
/// a second time after the service has validated it.
pub(crate) fn derive_consumer_consensus_request_id_from_commitment(
    identity: &SessionConsumerIdentity,
    commitment: [u8; 32],
    slot: u16,
) -> SessionConsensusRequestId {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/operation-request-id/v2\\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    digest.update(commitment);
    digest.update(slot.to_be_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut request_bytes = [0_u8; SESSION_CONSUMER_REQUEST_ID_BYTES];
    request_bytes.copy_from_slice(&hash[..SESSION_CONSUMER_REQUEST_ID_BYTES]);
    SessionConsensusRequestId::from_bytes(request_bytes)
}

/// Rebuild a transition for the internal receipt ledger without exposing that
/// ledger's global identity domain to consumers.
///
/// The outer scope is still enforced at every proposal/read boundary. Its
/// stable cluster component isolates unrelated deployments while deliberately
/// excluding changing configuration and epoch values: a retry or status read
/// remains recoverable after an authorized authority rollover. The body is
/// excluded so the existing transition receipt binding can reject a reused ID
/// with a different body as `RequestConflict`.
pub(crate) fn derive_consumer_fenced_transition_request(
    identity: &SessionConsumerIdentity,
    scope: SessionConsumerScope,
    request: &FencedTransitionRequest,
) -> Result<FencedTransitionRequest, SessionConsumerRejection> {
    use sha2::{Digest, Sha256};

    request
        .validate()
        .map_err(|_| SessionConsumerRejection::MalformedRequest)?;
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/fenced-transition-id/v1\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    digest.update(scope.consensus_identity().cluster_id().as_bytes());
    digest.update(request.request_id().as_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut internal_id = [0_u8; FENCED_TRANSITION_REQUEST_ID_BYTES];
    internal_id.copy_from_slice(&hash[..FENCED_TRANSITION_REQUEST_ID_BYTES]);
    // The public transition contract reserves the all-zero ID. A truncated
    // digest can equal that value in principle, so keep the derivation total
    // instead of probabilistically rejecting an otherwise valid request.
    if internal_id.iter().all(|byte| *byte == 0) {
        internal_id[FENCED_TRANSITION_REQUEST_ID_BYTES - 1] = 1;
    }
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes(internal_id),
        request.lease().clone(),
        request.mutation().clone(),
    )
    .map_err(|_| SessionConsumerRejection::MalformedRequest)
}

/// Marker imported by stateless clients to make accidental use of
/// [`crate::SessionBackend`] explicit at composition time.
///
/// A consumer client deliberately composes the application subset instead of
/// implementing `SessionBackend` or [`crate::SessionLeaseManager`]: the former carries
/// legacy replication reconstruction authority and the latter would hide
/// freshly generated retry IDs. Lease calls on this boundary therefore always
/// require a caller-owned [`SessionConsumerRequestId`].
pub trait StatelessSessionConsumer: Send + Sync {}

#[cfg(test)]
mod tests {
    use super::{
        derive_consumer_consensus_request_id, derive_consumer_fenced_transition_request,
        SessionConsumerAuthorizationGrant, SessionConsumerAuthorizationGrantError,
        SessionConsumerAuthorizationManifestError, SessionConsumerFencedTransitionError,
        SessionConsumerFencedTransitionStatus, SessionConsumerIdentity, SessionConsumerOperation,
        SessionConsumerRejection, SessionConsumerRequest, SessionConsumerRequestId,
        SessionConsumerRoster, SessionConsumerRosterError, SessionConsumerScope,
        SessionConsumerStoreError, SessionConsumerTenantNfScope,
        SessionConsumerV2FencedTransitionError, SessionConsumerV2FencedTransitionStatus,
        SessionConsumerV2Operation, SessionConsumerV2Request, SessionConsumerV2Response,
        SESSION_CONSUMER_IDENTITY_MAX_BYTES,
    };
    use crate::{
        AtomicFencedTransitionCapability, FenceToken, FencedTransitionLease,
        FencedTransitionMutation, FencedTransitionRequest, FencedTransitionRequestId,
        FencedTransitionStatus, FencedTransitionV2CallerNonce, FencedTransitionV2Capability,
        FencedTransitionV2HistoryEpoch, FencedTransitionV2Request, FencedTransitionV2Status,
        Generation, OwnerId, QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint,
        ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, RestoreScanRequest, RestoreScanScope,
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity, SessionConsensusNodeId,
        SessionKey, SessionKeyType, SessionOp, StableId, StoreError, QUORUM_TOPOLOGY_MAX_MEMBERS,
    };
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
    use std::collections::BTreeSet;
    use std::time::Duration;

    #[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
    enum LegacySessionConsumerStoreError {
        NotFound,
        StaleFence,
        CasConflict,
        RequestConflict,
        OutcomeUnavailable,
        Unavailable,
        InvalidInput,
        CapabilityNotSupported,
        WatchCatchUpRequired,
        RestoreRejected,
        RestoreCursorStale,
        RestoreBudgetExceeded,
        InvalidTtl,
        LeaseUnavailable,
        PayloadTooLarge,
        ProtectedDataRejected,
    }

    fn scope(configuration: u8, epoch: u64) -> SessionConsumerScope {
        SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([configuration; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).expect("non-zero configuration epoch"),
        ))
    }

    fn roster_scope(cluster: u8, configuration: u8, epoch: u64) -> SessionConsumerScope {
        SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([cluster; 32]),
            SessionConsensusConfigurationId::from_bytes([configuration; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).expect("non-zero configuration epoch"),
        ))
    }

    fn roster_nodes(values: &[u64]) -> BTreeSet<SessionConsensusNodeId> {
        values
            .iter()
            .copied()
            .map(|value| SessionConsensusNodeId::new(value).expect("valid roster node ID"))
            .collect()
    }

    fn roster_descriptor(node: u64, tls_identity: impl Into<String>) -> QuorumReplicaDescriptor {
        QuorumReplicaDescriptor::new(
            ReplicaId::new(format!("consumer-roster-node-{node}")).expect("replica ID"),
            ReplicaEndpoint::new(format!("consumer-roster-node-{node}.test.invalid"), 7443)
                .expect("endpoint"),
            ReplicaTlsIdentity::new(tls_identity).expect("TLS identity"),
            ReplicaFailureDomain::new(format!("consumer-roster-zone-{node}"))
                .expect("failure domain"),
            ReplicaBackingIdentity::new(format!("consumer-roster-backing-{node}"))
                .expect("backing identity"),
        )
    }

    fn roster_descriptors() -> Vec<(u64, QuorumReplicaDescriptor)> {
        vec![
            (
                1,
                roster_descriptor(1, "spiffe://test.invalid/consumer-roster/one"),
            ),
            (
                2,
                roster_descriptor(2, "spiffe://test.invalid/consumer-roster/two"),
            ),
        ]
    }

    fn authorization_fixture() -> (super::SessionConsumerAuthorization, SessionKey) {
        let scope = roster_scope(9, 8, 7);
        let node_id = SessionConsensusNodeId::new(1).expect("roster node");
        let roster = SessionConsumerRoster::try_new(
            scope,
            &roster_nodes(&[1]),
            vec![(
                (node_id.get()),
                roster_descriptor(1, "spiffe://test.invalid/consumer-roster/voter"),
            )],
        )
        .expect("validated roster");
        let identity = SessionConsumerIdentity::new(
            "spiffe://test.invalid/tenant/tenant-a/ns/default/sa/app/nf/smf/instance/one",
        )
        .expect("consumer identity");
        let grant = SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(identity.as_str()).expect("canonical SPIFFE ID"),
            [SessionConsumerTenantNfScope::new(
                TenantId::from_static("tenant-a"),
                NetworkFunctionKind::smf(),
            )],
        )
        .expect("consumer grant");
        let manifest = roster
            .authorization_manifest(node_id, [grant])
            .expect("authorization manifest");
        let key = SessionKey {
            tenant: TenantId::from_static("tenant-a"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"authorized-key")).expect("stable ID"),
        };
        (
            manifest.authorize(&identity).expect("authorization token"),
            key,
        )
    }

    #[test]
    fn v2_profile_never_invokes_legacy_roster_ingress() {
        let mut invoked = false;
        let result = super::invoke_legacy_roster_ingress_for_profile(
            super::SessionConsumerRosterTransportProfile::v2(),
            || {
                invoked = true;
            },
        );
        assert_eq!(
            result,
            Err(super::SessionConsumerRosterRejection::Capability)
        );
        assert!(!invoked);

        let result = super::invoke_legacy_roster_ingress_for_profile(
            super::SessionConsumerRosterTransportProfile::current(),
            || {
                invoked = true;
            },
        );
        assert_eq!(result, Ok(()));
        assert!(invoked);
    }

    #[test]
    fn explicit_grants_reject_duplicate_scopes_and_identities() {
        let identity = SpiffeId::new(
            "spiffe://test.invalid/tenant/tenant-a/ns/default/sa/app/nf/smf/instance/one",
        )
        .expect("canonical SPIFFE ID");
        let scope = SessionConsumerTenantNfScope::new(
            TenantId::from_static("tenant-a"),
            NetworkFunctionKind::smf(),
        );
        assert!(matches!(
            SessionConsumerAuthorizationGrant::try_new(identity.clone(), [scope.clone(), scope]),
            Err(SessionConsumerAuthorizationGrantError::DuplicateScope)
        ));

        let roster_scope = roster_scope(9, 8, 7);
        let node_id = SessionConsensusNodeId::new(1).expect("roster node");
        let roster = SessionConsumerRoster::try_new(
            roster_scope,
            &roster_nodes(&[1]),
            vec![(
                1,
                roster_descriptor(1, "spiffe://test.invalid/consumer-roster/voter"),
            )],
        )
        .expect("validated roster");
        let grant = || {
            SessionConsumerAuthorizationGrant::try_new(
                identity.clone(),
                [SessionConsumerTenantNfScope::new(
                    TenantId::from_static("tenant-a"),
                    NetworkFunctionKind::smf(),
                )],
            )
            .expect("grant")
        };
        assert!(matches!(
            roster.authorization_manifest(node_id, [grant(), grant()]),
            Err(SessionConsumerAuthorizationManifestError::DuplicateIdentity)
        ));
    }

    #[test]
    fn authorization_requires_exact_scope_and_denies_global_watch() {
        let (authorization, key) = authorization_fixture();
        let roster_authorization = authorization.roster_authorization();
        let foreign = SessionKey {
            tenant: TenantId::from_static("tenant-z"),
            ..key.clone()
        };
        let wrong_nf = SessionKey {
            nf_kind: NetworkFunctionKind::amf(),
            ..key.clone()
        };
        assert_eq!(
            roster_authorization.authorize_session_key(&key),
            Ok(()),
            "the narrow roster token admits its exact tenant/NF grant"
        );
        assert_eq!(
            roster_authorization.authorize_session_key(&foreign),
            Err(SessionConsumerRejection::Unauthorized),
            "the narrow roster token rejects a foreign tenant"
        );
        assert_eq!(
            roster_authorization.authorize_session_key(&wrong_nf),
            Err(SessionConsumerRejection::Unauthorized),
            "the narrow roster token rejects an ungranted NF"
        );
        assert_eq!(
            format!("{roster_authorization:?}"),
            "SessionConsumerRosterAuthorization(<redacted>)"
        );
        assert_eq!(
            roster_authorization.identity(),
            authorization.identity(),
            "roster ingress can bind the same authenticated identity without grant enumeration"
        );
        assert_eq!(
            authorization.authorize_operation(&SessionConsumerOperation::Get {
                key: foreign.clone()
            }),
            Err(SessionConsumerRejection::Unauthorized),
            "an ungranted third tenant is never inferred from the SPIFFE ID"
        );
        assert_eq!(
            authorization.authorize_operation(&SessionConsumerOperation::Batch {
                ops: vec![
                    SessionOp::Get { key: key.clone() },
                    SessionOp::Get {
                        key: foreign.clone()
                    }
                ],
            }),
            Err(SessionConsumerRejection::Unauthorized),
            "every bounded batch slot is checked before dispatch"
        );
        assert_eq!(
            authorization.authorize_operation(&SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest {
                    scope: RestoreScanScope {
                        tenant: Some(key.tenant.clone()),
                        ..RestoreScanScope::all()
                    },
                    cursor: None,
                    limit: 1,
                },
            }),
            Err(SessionConsumerRejection::Unauthorized),
            "restore requires both exact tenant and NF instead of a prefix filter"
        );
        assert!(authorization
            .authorize_operation(&SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest {
                    scope: RestoreScanScope {
                        tenant: Some(key.tenant.clone()),
                        nf_kind: Some(key.nf_kind.clone()),
                        ..RestoreScanScope::all()
                    },
                    cursor: None,
                    limit: 1,
                },
            })
            .is_ok());
        assert_eq!(
            authorization
                .authorize_operation(&SessionConsumerOperation::Watch { start_sequence: 77 }),
            Err(SessionConsumerRejection::Unauthorized),
            "a global sequence would reveal foreign-tenant mutation timing even after item filtering"
        );
    }

    #[test]
    fn consumer_roster_is_sorted_and_commits_every_scope_and_member_component() {
        let scope = roster_scope(1, 2, 3);
        let expected_nodes = roster_nodes(&[1, 2]);
        let roster = SessionConsumerRoster::try_new(
            scope,
            &expected_nodes,
            vec![
                (
                    2,
                    roster_descriptor(2, "spiffe://test.invalid/consumer-roster/two"),
                ),
                (
                    1,
                    roster_descriptor(1, "spiffe://test.invalid/consumer-roster/one"),
                ),
            ],
        )
        .expect("complete roster");
        let reordered =
            SessionConsumerRoster::try_new(scope, &expected_nodes, roster_descriptors())
                .expect("reordered complete roster");

        assert_eq!(
            roster
                .consensus_members()
                .map(|member| (member.node_id().get(), member.tls_identity().to_owned()))
                .collect::<Vec<_>>(),
            vec![
                (1, "spiffe://test.invalid/consumer-roster/one".to_owned()),
                (2, "spiffe://test.invalid/consumer-roster/two".to_owned()),
            ]
        );
        assert_eq!(roster.roster_commitment(), reordered.roster_commitment());
        let commitment = roster.roster_commitment();
        for changed_scope in [
            roster_scope(4, 2, 3),
            roster_scope(1, 5, 3),
            roster_scope(1, 2, 6),
        ] {
            assert_ne!(
                commitment,
                SessionConsumerRoster::try_new(
                    changed_scope,
                    &expected_nodes,
                    roster_descriptors()
                )
                .expect("changed scope roster")
                .roster_commitment()
            );
        }
        assert_ne!(
            commitment,
            SessionConsumerRoster::try_new(
                scope,
                &expected_nodes,
                vec![
                    (
                        1,
                        roster_descriptor(1, "spiffe://test.invalid/consumer-roster/replaced")
                    ),
                    (
                        2,
                        roster_descriptor(2, "spiffe://test.invalid/consumer-roster/two")
                    ),
                ],
            )
            .expect("changed TLS roster")
            .roster_commitment()
        );
        let changed_nodes = roster_nodes(&[1, 7]);
        assert_ne!(
            commitment,
            SessionConsumerRoster::try_new(
                scope,
                &changed_nodes,
                vec![
                    (
                        1,
                        roster_descriptor(1, "spiffe://test.invalid/consumer-roster/one")
                    ),
                    (
                        7,
                        roster_descriptor(7, "spiffe://test.invalid/consumer-roster/two")
                    ),
                ],
            )
            .expect("changed node roster")
            .roster_commitment()
        );
        assert!(!format!("{roster:?}").contains("consumer-roster/one"));
        assert_eq!(
            format!("{:?}", roster.roster_commitment()),
            "SessionConsumerRosterCommitment(<redacted>)"
        );
    }

    #[test]
    fn consumer_roster_rejects_invalid_duplicate_and_scope_mismatched_bindings() {
        let scope = roster_scope(1, 2, 3);
        let one_member = roster_nodes(&[1]);
        let two_members = roster_nodes(&[1, 2]);
        let valid = roster_descriptor(1, "spiffe://test.invalid/consumer-roster/one");

        assert!(matches!(
            SessionConsumerRoster::try_new(scope, &BTreeSet::new(), std::iter::empty()),
            Err(SessionConsumerRosterError::Empty)
        ));
        let oversized_values = (1..=(QUORUM_TOPOLOGY_MAX_MEMBERS as u64 + 1)).collect::<Vec<_>>();
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &roster_nodes(&oversized_values),
                std::iter::empty()
            ),
            Err(SessionConsumerRosterError::MemberCountTooLarge)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &one_member,
                vec![
                    (1, valid.clone()),
                    (
                        1,
                        roster_descriptor(1, "spiffe://test.invalid/consumer-roster/other")
                    ),
                ],
            ),
            Err(SessionConsumerRosterError::DuplicateNodeId)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &two_members,
                vec![(1, valid.clone()), (2, valid.clone())],
            ),
            Err(SessionConsumerRosterError::DuplicateTlsIdentity)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(scope, &one_member, vec![(0, valid.clone())]),
            Err(SessionConsumerRosterError::InvalidNodeId)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &one_member,
                vec![(i64::MAX as u64 + 1, valid.clone())],
            ),
            Err(SessionConsumerRosterError::InvalidNodeId)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &one_member,
                vec![(
                    1,
                    roster_descriptor(1, "x".repeat(SESSION_CONSUMER_IDENTITY_MAX_BYTES + 1)),
                )],
            ),
            Err(SessionConsumerRosterError::InvalidTlsIdentity)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(scope, &two_members, vec![(1, valid)]),
            Err(SessionConsumerRosterError::ScopeMismatch)
        ));
    }

    #[test]
    fn revision_four_epoch_capability_keeps_the_v2_wire_shape_but_not_the_journal_type() {
        let response = SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
            FencedTransitionV2Capability::V2,
        ));
        let encoded = serde_json::to_string(&response).expect("revision-four capability encodes");
        assert_eq!(
            encoded, r#"{"response":"fenced_transition_v2_capability","body":{"Ok":"V2"}}"#,
            "the established revision-four V2 capability JSON remains frozen"
        );
        assert_eq!(
            serde_json::from_str::<SessionConsumerV2Response>(&encoded)
                .expect("revision-four capability decodes"),
            response
        );

        let epoch_capability: FencedTransitionV2Capability =
            serde_json::from_str("\"V2\"").expect("epoch capability decodes");
        let journal_capability: AtomicFencedTransitionCapability =
            serde_json::from_str("\"V2\"").expect("journal capability decodes");
        assert_eq!(epoch_capability, FencedTransitionV2Capability::V2);
        assert_eq!(journal_capability, AtomicFencedTransitionCapability::V2);
    }

    fn transition(id: u8) -> FencedTransitionRequest {
        let key = SessionKey {
            tenant: TenantId::from_static("consumer-transition-test"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"transition-id")).expect("stable ID"),
        };
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([id; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("consumer-transition-owner").expect("owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("transition")
    }

    #[test]
    fn durable_request_identity_is_stable_and_consumer_bound() {
        let request_id = SessionConsumerRequestId::from_bytes([7; 16]);
        let scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([2; 32]),
            SessionConsensusConfigurationEpoch::new(3).expect("non-zero configuration epoch"),
        ));
        let request =
            SessionConsumerRequest::new(scope, request_id, SessionConsumerOperation::Capabilities);
        let changed_request = SessionConsumerRequest::new(
            scope,
            request_id,
            SessionConsumerOperation::Watch { start_sequence: 7 },
        );
        let first = SessionConsumerIdentity::new("spiffe://test.example/consumer/first")
            .expect("valid first consumer identity");
        let second = SessionConsumerIdentity::new("spiffe://test.example/consumer/second")
            .expect("valid second consumer identity");

        assert_eq!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&first, &request, 0),
            "an explicit retry must preserve the durable request identity"
        );
        assert_ne!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&second, &request, 0),
            "one consumer cannot collide with another consumer's retry domain"
        );
        assert_ne!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&first, &request, 1),
            "batch slots must retain independently durable outcomes"
        );
        assert_ne!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&first, &changed_request, 0),
            "a changed full request shape cannot reuse a slot outcome"
        );
    }

    #[test]
    fn consumer_identity_and_request_debug_are_redacted() {
        let identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/secret")
            .expect("valid consumer identity");
        let request_id = SessionConsumerRequestId::from_bytes([9; 16]);
        let scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([7; 32]),
            SessionConsensusConfigurationId::from_bytes([8; 32]),
            SessionConsensusConfigurationEpoch::new(9).expect("non-zero configuration epoch"),
        ));

        assert!(!format!("{identity:?}").contains(identity.as_str()));
        assert!(!format!("{request_id:?}").contains("090909"));
        assert_eq!(format!("{scope:?}"), "SessionConsumerScope(<redacted>)");
    }

    #[test]
    fn consumer_request_rejects_unknown_wire_fields() {
        let request = SessionConsumerRequest::new(
            SessionConsumerScope::new(SessionConsensusIdentity::new(
                SessionConsensusClusterId::from_bytes([1; 32]),
                SessionConsensusConfigurationId::from_bytes([2; 32]),
                SessionConsensusConfigurationEpoch::new(3).expect("non-zero configuration epoch"),
            )),
            SessionConsumerRequestId::from_bytes([4; 16]),
            SessionConsumerOperation::Watch { start_sequence: 5 },
        );
        let encoded = serde_json::to_value(request).expect("request encodes");
        let mut root_unknown = encoded.clone();
        let serde_json::Value::Object(fields) = &mut root_unknown else {
            panic!("request is an object");
        };
        fields.insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SessionConsumerRequest>(root_unknown).is_err());

        let mut legacy_prepared_authority = encoded.clone();
        let serde_json::Value::Object(fields) = &mut legacy_prepared_authority else {
            panic!("request is an object");
        };
        fields.insert("prepared_authority".into(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<SessionConsumerRequest>(legacy_prepared_authority).is_err(),
            "legacy prepared wire authority is an unknown field"
        );

        let mut operation_unknown = encoded;
        let serde_json::Value::Object(fields) = &mut operation_unknown else {
            panic!("request is an object");
        };
        let operation = fields
            .get_mut("operation")
            .and_then(serde_json::Value::as_object_mut)
            .expect("operation is an object");
        operation.insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SessionConsumerRequest>(operation_unknown).is_err());
    }

    #[test]
    fn fenced_transition_identity_is_consumer_bound_and_rollover_stable() {
        let first = SessionConsumerIdentity::new("spiffe://test.example/consumer/first")
            .expect("first identity");
        let second = SessionConsumerIdentity::new("spiffe://test.example/consumer/second")
            .expect("second identity");
        let request = transition(0x55);
        let successor_scope = scope(3, 2);
        let first_scope = scope(2, 1);

        let first_internal =
            derive_consumer_fenced_transition_request(&first, first_scope, &request)
                .expect("first internal request");
        assert_eq!(
            first_internal.request_id(),
            derive_consumer_fenced_transition_request(&first, successor_scope, &request)
                .expect("successor internal request")
                .request_id(),
            "an authorized successor scope must recover the same receipt"
        );
        assert_ne!(
            first_internal.request_id(),
            derive_consumer_fenced_transition_request(&second, first_scope, &request)
                .expect("second internal request")
                .request_id(),
            "different authenticated consumers must not share a receipt domain"
        );
        let changed_body = FencedTransitionRequest::new(
            request.request_id(),
            request.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("changed transition body");
        assert_eq!(
            first_internal.request_id(),
            derive_consumer_fenced_transition_request(&first, first_scope, &changed_body)
                .expect("changed-body internal request")
                .request_id(),
            "the receipt ledger, not the derivation, must bind conflicting bodies"
        );
    }

    #[test]
    fn fenced_transition_requires_matching_outer_and_nested_identity() {
        let request = transition(0x44);
        let consumer = SessionConsumerRequest::new(
            scope(2, 1),
            SessionConsumerRequestId::from_bytes([0x45; 16]),
            SessionConsumerOperation::FencedTransition {
                request: Box::new(request),
            },
        );
        assert_eq!(
            consumer.validate(),
            Err(SessionConsumerRejection::MalformedRequest)
        );
    }

    #[test]
    fn v2_transition_requires_the_full_outer_request_commitment() {
        let v1 = transition(0x46);
        let v2 = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("nonzero epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x47; 16]),
            v1.lease().clone(),
            v1.mutation().clone(),
        )
        .expect("v2 transition");
        let request = SessionConsumerV2Request::new(
            scope(2, 1),
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(v2),
            },
        );
        assert!(request.validate().is_ok());

        let mut encoded = serde_json::to_value(request).expect("v2 request encodes");
        let serde_json::Value::Object(fields) = &mut encoded else {
            panic!("v2 request is an object");
        };
        fields.insert("request_id".into(), serde_json::Value::Null);
        let mismatched: SessionConsumerV2Request =
            serde_json::from_value(encoded).expect("well-formed mismatched envelope");
        assert_eq!(
            mismatched.validate(),
            Err(SessionConsumerRejection::MalformedRequest),
            "the outer ID must retain all V2 epoch, nonce, and body-commitment bytes"
        );
    }

    #[test]
    fn v2_transition_retains_a_structurally_valid_body_conflict_for_dispatch() {
        let original = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("nonzero epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x48; 16]),
            transition(0x49).lease().clone(),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("original V2 transition");
        let altered = FencedTransitionV2Request::new(
            original.request_id().epoch(),
            original.request_id().nonce(),
            original.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("altered V2 transition");
        let original_request = SessionConsumerV2Request::new(
            scope(2, 1),
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(original),
            },
        );
        let altered_request = SessionConsumerV2Request::new(
            scope(2, 1),
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(altered),
            },
        );

        let mut encoded = serde_json::to_value(altered_request).expect("altered request encodes");
        let original_id =
            serde_json::to_value(original_request.request_id()).expect("original full ID encodes");
        let serde_json::Value::Object(fields) = &mut encoded else {
            panic!("V2 envelope is an object");
        };
        fields.insert("request_id".into(), original_id.clone());
        let operation = fields
            .get_mut("operation")
            .and_then(serde_json::Value::as_object_mut)
            .expect("V2 operation is an object");
        let body = operation
            .get_mut("request")
            .and_then(serde_json::Value::as_object_mut)
            .expect("V2 body is an object");
        body.insert("request_id".into(), original_id);
        let conflicted: SessionConsumerV2Request =
            serde_json::from_value(encoded).expect("structural conflict decodes");

        assert_eq!(conflicted.request_id(), original_request.request_id());
        assert_eq!(
            conflicted.validate(),
            Ok(()),
            "a same-full-ID body conflict must reach V2 execute/status dispatch"
        );
        let SessionConsumerV2Operation::FencedTransitionV2 { request } = conflicted.operation()
        else {
            panic!("V2 execute operation");
        };
        assert_eq!(
            request.validate(),
            Err(StoreError::FencedTransitionRequestConflict)
        );
    }

    #[test]
    fn v2_batch_admits_only_unique_same_epoch_items_and_returns_full_id_correlation() {
        let make = |nonce, id| {
            let transition = transition(id);
            FencedTransitionV2Request::new(
                FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                FencedTransitionV2CallerNonce::from_bytes([nonce; 16]),
                transition.lease().clone(),
                transition.mutation().clone(),
            )
            .expect("V2 transition")
        };
        let first = make(0x61, 0x62);
        let second = make(0x63, 0x64);
        let request = SessionConsumerV2Request::new(
            scope(2, 1),
            SessionConsumerV2Operation::FencedTransitionV2Batch {
                requests: vec![first.clone(), second.clone()],
            },
        );
        assert_eq!(request.request_id(), None);
        assert!(request.validate().is_ok());
        assert!(request.operation().is_effectful());

        let duplicate = SessionConsumerV2Request::new(
            scope(2, 1),
            SessionConsumerV2Operation::FencedTransitionV2Batch {
                requests: vec![first.clone(), first.clone()],
            },
        );
        assert_eq!(
            duplicate.validate(),
            Err(SessionConsumerRejection::MalformedRequest)
        );
        let ambiguous = super::SessionConsumerV2FencedTransitionBatchError::outcome_unknown(vec![
            first.request_id(),
            second.request_id(),
        ])
        .expect("unique full IDs");
        let response = SessionConsumerV2Response::FencedTransitionV2Batch(Err(ambiguous));
        assert_eq!(
            serde_json::from_str::<SessionConsumerV2Response>(
                &serde_json::to_string(&response).expect("response encodes"),
            )
            .expect("response decodes"),
            response,
        );
    }

    #[test]
    fn fenced_transition_status_is_safe_and_preserves_terminal_states() {
        assert_eq!(
            SessionConsumerFencedTransitionStatus::from(FencedTransitionStatus::Expired),
            SessionConsumerFencedTransitionStatus::Expired
        );
        assert_eq!(
            SessionConsumerFencedTransitionStatus::from(FencedTransitionStatus::HistoryFull),
            SessionConsumerFencedTransitionStatus::HistoryFull
        );
        assert_eq!(
            SessionConsumerFencedTransitionError::from(
                StoreError::FencedTransitionStorageExhausted
            ),
            SessionConsumerFencedTransitionError::StorageExhausted,
        );
    }

    #[test]
    fn v2_fenced_transition_errors_preserve_each_execution_semantic_on_the_wire() {
        let cases = [
            (
                StoreError::FencedTransitionRequestConflict,
                SessionConsumerV2FencedTransitionError::RequestConflict,
            ),
            (
                StoreError::FencedTransitionOutcomeUnknown,
                SessionConsumerV2FencedTransitionError::OutcomeUnknown,
            ),
            (
                StoreError::FencedTransitionRequestExpired,
                SessionConsumerV2FencedTransitionError::Expired,
            ),
            (
                StoreError::FencedTransitionHistoryFull,
                SessionConsumerV2FencedTransitionError::HistoryFull,
            ),
            (
                StoreError::FencedTransitionRetentionExhausted,
                SessionConsumerV2FencedTransitionError::RetentionExhausted,
            ),
            (
                StoreError::FencedTransitionStorageExhausted,
                SessionConsumerV2FencedTransitionError::StorageExhausted,
            ),
            (
                StoreError::FencedTransitionHistoryEpochRetired,
                SessionConsumerV2FencedTransitionError::Retired,
            ),
            (
                StoreError::FencedTransitionHistoryEpochNotActive,
                SessionConsumerV2FencedTransitionError::EpochNotActive,
            ),
            (
                StoreError::NotFound,
                SessionConsumerV2FencedTransitionError::Store(
                    super::SessionConsumerStoreError::NotFound,
                ),
            ),
        ];
        let mut encodings = std::collections::BTreeSet::new();

        for (store_error, wire_error) in cases {
            assert_eq!(
                SessionConsumerV2FencedTransitionError::from(store_error.clone()),
                wire_error
            );
            assert_eq!(wire_error.into_store_error(), store_error);
            let encoded = serde_json::to_string(&wire_error).expect("V2 error encodes");
            assert_eq!(
                serde_json::from_str::<SessionConsumerV2FencedTransitionError>(&encoded)
                    .expect("V2 error decodes"),
                wire_error
            );
            assert!(
                encodings.insert(encoded),
                "every V2 execution semantic needs a distinct wire value"
            );
        }
    }

    #[test]
    fn v2_recorded_status_projects_every_admitted_error_without_diagnostics() {
        let payload_actual = crate::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES + 1;
        let cases = [
            (
                StoreError::TopologyAuthorityRevoked,
                SessionConsumerV2FencedTransitionError::TopologyAuthorityRevoked,
            ),
            (
                StoreError::NotFound,
                SessionConsumerV2FencedTransitionError::Store(SessionConsumerStoreError::NotFound),
            ),
            (
                StoreError::StaleFence,
                SessionConsumerV2FencedTransitionError::Store(
                    SessionConsumerStoreError::StaleFence,
                ),
            ),
            (
                StoreError::CasConflict,
                SessionConsumerV2FencedTransitionError::Store(
                    SessionConsumerStoreError::CasConflict,
                ),
            ),
            (
                StoreError::InvalidSessionTtl,
                SessionConsumerV2FencedTransitionError::InvalidSessionTtl,
            ),
            (
                StoreError::InvalidRecordExpiry,
                SessionConsumerV2FencedTransitionError::InvalidRecordExpiry,
            ),
            (
                StoreError::LeaseHeld,
                SessionConsumerV2FencedTransitionError::LeaseHeld,
            ),
            (
                StoreError::LeaseExpired,
                SessionConsumerV2FencedTransitionError::LeaseExpired,
            ),
            (
                StoreError::PayloadTooLarge {
                    actual: payload_actual,
                    max: crate::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES,
                },
                SessionConsumerV2FencedTransitionError::PayloadTooLarge {
                    actual: payload_actual as u64,
                    max: crate::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES as u64,
                },
            ),
            (
                StoreError::FencedTransitionStorageExhausted,
                SessionConsumerV2FencedTransitionError::StorageExhausted,
            ),
        ];

        for (store_error, wire_error) in cases {
            let status = SessionConsumerV2FencedTransitionStatus::try_from(
                FencedTransitionV2Status::Recorded(Box::new(Err(store_error.clone()))),
            )
            .expect("admitted V2 receipt error projects");
            assert_eq!(
                status,
                SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(Err(wire_error)))
            );
            assert_eq!(wire_error.into_store_error(), store_error);
            assert!(wire_error.is_wire_valid());
            assert!(wire_error.is_recorded_deterministic());
            let encoded = serde_json::to_string(&status).expect("closed V2 status encodes");
            assert_eq!(
                serde_json::from_str::<SessionConsumerV2FencedTransitionStatus>(&encoded)
                    .expect("closed V2 status decodes"),
                status
            );
        }

        let diagnostic = "backend diagnostic must never cross the consumer wire";
        assert_eq!(
            SessionConsumerV2FencedTransitionStatus::try_from(FencedTransitionV2Status::Recorded(
                Box::new(Err(StoreError::BackendUnavailable(diagnostic.into(),)))
            ),),
            Err(SessionConsumerStoreError::Unavailable),
            "backend diagnostics are deliberately non-projectable"
        );
        assert_eq!(
            SessionConsumerV2FencedTransitionStatus::try_from(FencedTransitionV2Status::Recorded(
                Box::new(Err(StoreError::InvalidKey(diagnostic.into(),)))
            ),),
            Err(SessionConsumerStoreError::Unavailable),
            "generic non-receipt errors are deliberately non-projectable"
        );
        assert!(
            !SessionConsumerV2FencedTransitionError::PayloadTooLarge { actual: 1, max: 2 }
                .is_wire_valid(),
            "a noncanonical payload bound cannot be represented on the V2 wire"
        );
        assert!(
            !SessionConsumerV2FencedTransitionError::PayloadTooLarge {
                actual: u64::MAX,
                max: 1,
            }
            .is_recorded_deterministic(),
            "a platform-independent overflow cannot be represented as a receipt"
        );
    }

    #[test]
    fn v2_error_additions_do_not_change_frozen_v1_error_shape_or_ordinal() {
        assert_eq!(
            serde_json::to_string(&SessionConsumerFencedTransitionError::RequestConflict)
                .expect("V1 request conflict encodes"),
            "\"RequestConflict\""
        );
        assert_eq!(
            serde_json::to_string(&SessionConsumerFencedTransitionError::Store(
                super::SessionConsumerStoreError::NotFound,
            ))
            .expect("V1 store error encodes"),
            "{\"Store\":\"NotFound\"}"
        );
        assert_eq!(
            opc_consensus::encode_bounded(&SessionConsumerFencedTransitionError::RequestConflict)
                .expect("V1 request conflict postcard encodes"),
            vec![1],
            "the frozen V1 RequestConflict discriminant remains ordinal one"
        );
        assert_eq!(
            opc_consensus::encode_bounded(&SessionConsumerFencedTransitionError::StorageExhausted)
                .expect("V1 storage exhausted postcard encodes"),
            vec![5],
            "the frozen V1 StorageExhausted discriminant remains ordinal five"
        );
    }

    #[test]
    fn session_record_reserved_store_error_is_append_only_and_round_trips() {
        let legacy_pairs = [
            (
                SessionConsumerStoreError::NotFound,
                LegacySessionConsumerStoreError::NotFound,
            ),
            (
                SessionConsumerStoreError::StaleFence,
                LegacySessionConsumerStoreError::StaleFence,
            ),
            (
                SessionConsumerStoreError::CasConflict,
                LegacySessionConsumerStoreError::CasConflict,
            ),
            (
                SessionConsumerStoreError::RequestConflict,
                LegacySessionConsumerStoreError::RequestConflict,
            ),
            (
                SessionConsumerStoreError::OutcomeUnavailable,
                LegacySessionConsumerStoreError::OutcomeUnavailable,
            ),
            (
                SessionConsumerStoreError::Unavailable,
                LegacySessionConsumerStoreError::Unavailable,
            ),
            (
                SessionConsumerStoreError::InvalidInput,
                LegacySessionConsumerStoreError::InvalidInput,
            ),
            (
                SessionConsumerStoreError::CapabilityNotSupported,
                LegacySessionConsumerStoreError::CapabilityNotSupported,
            ),
            (
                SessionConsumerStoreError::WatchCatchUpRequired,
                LegacySessionConsumerStoreError::WatchCatchUpRequired,
            ),
            (
                SessionConsumerStoreError::RestoreRejected,
                LegacySessionConsumerStoreError::RestoreRejected,
            ),
            (
                SessionConsumerStoreError::RestoreCursorStale,
                LegacySessionConsumerStoreError::RestoreCursorStale,
            ),
            (
                SessionConsumerStoreError::RestoreBudgetExceeded,
                LegacySessionConsumerStoreError::RestoreBudgetExceeded,
            ),
            (
                SessionConsumerStoreError::InvalidTtl,
                LegacySessionConsumerStoreError::InvalidTtl,
            ),
            (
                SessionConsumerStoreError::LeaseUnavailable,
                LegacySessionConsumerStoreError::LeaseUnavailable,
            ),
            (
                SessionConsumerStoreError::PayloadTooLarge,
                LegacySessionConsumerStoreError::PayloadTooLarge,
            ),
            (
                SessionConsumerStoreError::ProtectedDataRejected,
                LegacySessionConsumerStoreError::ProtectedDataRejected,
            ),
        ];
        for (current, legacy) in legacy_pairs {
            let current_bytes =
                opc_consensus::encode_bounded(&current).expect("current consumer error encoding");
            let legacy_bytes =
                opc_consensus::encode_bounded(&legacy).expect("legacy consumer error encoding");
            assert_eq!(current_bytes, legacy_bytes, "legacy ordinal changed");
            opc_consensus::decode_bounded::<LegacySessionConsumerStoreError>(&current_bytes)
                .expect("legacy decode of current consumer error");
            assert_eq!(
                opc_consensus::decode_bounded::<SessionConsumerStoreError>(&legacy_bytes)
                    .expect("current decode of legacy consumer error"),
                current
            );
        }

        let current = SessionConsumerStoreError::SessionRecordReserved;
        let encoded =
            opc_consensus::encode_bounded(&current).expect("appended consumer error encoding");
        assert!(
            opc_consensus::decode_bounded::<LegacySessionConsumerStoreError>(&encoded).is_err()
        );
        assert_eq!(
            opc_consensus::decode_bounded::<SessionConsumerStoreError>(&encoded)
                .expect("current consumer error round trip"),
            current
        );
        assert_eq!(
            SessionConsumerStoreError::from(StoreError::SessionRecordReserved),
            current
        );
        assert_eq!(
            current.into_store_error(),
            StoreError::SessionRecordReserved
        );
    }
}
