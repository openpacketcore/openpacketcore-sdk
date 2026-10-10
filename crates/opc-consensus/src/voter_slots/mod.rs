//! Fixed-quorum incarnation records, authenticated admission and replacement control.
//!
//! Decoded records grant no authority. Trusted channel adapters construct
//! opaque possession proofs; stores atomically persist the accepted control
//! state with their engine log, membership and snapshot cuts. The RFC 023
//! replacement capability remains unadvertised until its integration qualifies.

mod admission;
mod authentication;
mod codec;
mod control;
mod durable;
mod identity;
mod records;
mod traffic;
mod transport;
mod validation;

pub use admission::{
    RaftVoterResponseFence, VoterAdmission, VoterIntentOrigin, VoterPeerRequest,
    VoterResponseFenceEngine, VoterSlotStateReader,
};
pub use authentication::{
    voter_candidate_possession_signing_input, voter_rpc_possession_signing_input,
    AuthenticatedVoterEvidence, TrustedVoterTime, VerifiedVoterCandidate, VerifiedVoterReplacement,
    VerifiedVoterRpc, VoterCandidateBinding, VoterCandidateChallenge, VoterChallengeIssuer,
    VoterReplacementAuthorization, VoterReplacementVerifier, VoterRpcBinding, VoterRpcChallenge,
    VoterRpcProofKind,
};
pub use codec::{
    decode_lost_voter_attestation, decode_voter_slot_table, encode_lost_voter_attestation,
    encode_voter_slot_table, lost_voter_attestation_signing_input,
    voter_replacement_request_digest,
};
pub use control::{
    VoterReplacementError, VoterReplacementRequest, VoterReplacementStep, VoterSlotControl,
};
pub use durable::{VoterSlotDurableState, VoterSlotIntent};
pub use identity::{SlotId, VoterIncarnation, VoterSlotIdentity, MAX_VOTER_INCARNATION};
pub use records::*;
pub use traffic::{VoterTrafficWindow, VOTER_RECENT_TRAFFIC_WINDOW};
pub use transport::{
    voter_rpc_request_digest, voter_rpc_response_digest, VoterAuthenticatedResponse,
    VoterPeerResolver, VoterPeerRoute, VoterTransport,
};

/// Redaction-safe failure in an incarnation identity or durable record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VoterSlotError {
    /// The slot ordinal is zero.
    #[error("invalid voter slot")]
    InvalidSlot,
    /// The incarnation is outside the signed-63-bit engine identity domain.
    #[error("invalid voter incarnation")]
    InvalidIncarnation,
    /// No further incarnation fits the engine identity domain.
    #[error("voter incarnation exhausted")]
    IncarnationExhausted,
    /// A durable table has another format; it requires a fresh installation.
    #[error("voter slot format requires a fresh installation")]
    FreshInstallationRequired,
    /// Encoded input or a variable field exceeds its fixed admission bound.
    #[error("voter slot record exceeds its size limit")]
    TooLarge,
    /// The record is malformed, noncanonical, or structurally inconsistent.
    #[error("invalid voter slot record")]
    InvalidRecord,
    /// A proposed snapshot would change the installation or regress retained state.
    #[error("voter slot state regression")]
    Regression,
}
