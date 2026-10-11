use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use super::*;
use crate::{ConsensusClusterId, ConsensusIdentity};

const UNAUTHORIZED: VoterReplacementError = VoterReplacementError::UnauthorizedReplacement;
const MAX_CHALLENGES: usize = 128;
const MAX_CHALLENGE_LIFETIME: Duration = Duration::from_secs(60);

/// Signature direction. A request signature cannot authenticate a returned response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoterRpcProofKind {
    /// Proof for a complete incoming request.
    Request,
    /// Proof for a complete response to a freshly challenged call.
    Response,
}

/// Complete public binding signed by an incarnation key on the carrying connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoterRpcBinding {
    /// Fresh installation identity.
    pub cluster_instance: ConsensusClusterId,
    /// Exact configuration under which the call is made.
    pub configuration: ConsensusIdentity,
    /// Purpose-separated store, persistence and wire compatibility commitment.
    pub profile_digest: [u8; 32],
    /// Authenticated signing endpoint, including its incarnation-key commitment.
    pub source: VoterSlotMember,
    /// Exact intended recipient, independently authenticated by the transport.
    pub destination: VoterSlotMember,
    /// Canonical source workload identity proved by the platform transport.
    pub source_spiffe_id: String,
    /// Canonical intended recipient workload identity.
    pub destination_spiffe_id: String,
    /// Exact active replacement commitment, if this call belongs to one.
    pub replacement_digest: Option<[u8; 32]>,
    /// Domain-separated commitment to the complete request, or request and response pair.
    pub payload_digest: [u8; 32],
    /// Request and response proof domains remain distinct.
    pub kind: VoterRpcProofKind,
}

/// Public challenge data. Copying or deserializing it does not prove possession.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoterRpcChallenge {
    /// Exact bounded endpoint and call binding.
    pub binding: VoterRpcBinding,
    /// Fresh random receiver challenge, consumed once at its issuer.
    pub challenge: [u8; 32],
    /// Binding obtained from the actual mutually authenticated connection.
    pub channel_binding: [u8; 32],
}

/// Selected candidate coordinates for the narrow proof/pull service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoterCandidateBinding {
    /// Exact installation.
    pub cluster_instance: ConsensusClusterId,
    /// Selected slot and successor incarnation.
    pub identity: VoterSlotIdentity,
    /// Canonical replacement request commitment, obtained from selection or a quorum read.
    pub request_digest: [u8; 32],
    /// Digest of the canonical compressed candidate P-256 key.
    pub key_digest: [u8; 32],
    /// Workload identity independently proved by the carrying transport.
    pub spiffe_id: String,
}

/// One-use, channel-bound candidate-key challenge from a retained voter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoterCandidateChallenge {
    /// Exact selected or quorum-read candidate binding.
    pub binding: VoterCandidateBinding,
    /// Fresh random challenge.
    pub challenge: [u8; 32],
    /// The actual authenticated channel, never a value trusted from a payload.
    pub channel_binding: [u8; 32],
}

/// Emit the RFC 023 candidate signature message, using fixed-width big-endian fields.
pub fn voter_candidate_possession_signing_input(
    challenge: &VoterCandidateChallenge,
) -> Result<Vec<u8>, VoterReplacementError> {
    validate_spiffe(&challenge.binding.spiffe_id)?;
    let binding = &challenge.binding;
    let mut bytes = b"openpacketcore/consensus/candidate-possession/v1\0".to_vec();
    bytes.extend_from_slice(binding.cluster_instance.as_bytes());
    bytes.extend_from_slice(&binding.identity.slot().get().to_be_bytes());
    bytes.extend_from_slice(&binding.identity.incarnation().get().to_be_bytes());
    bytes.extend_from_slice(&binding.request_digest);
    bytes.extend_from_slice(&binding.key_digest);
    bytes.extend_from_slice(&challenge.challenge);
    bytes.extend_from_slice(&challenge.channel_binding);
    Ok(bytes)
}

/// Emit the canonical incarnation admission signature message for both RPC directions.
///
/// Every endpoint includes its slot, incarnation, derived engine ID, key,
/// descriptor, selection generation and length-prefixed canonical SPIFFE ID.
/// The complete message also binds installation, configuration, active request,
/// payload, signature direction, fresh challenge and actual channel.
pub fn voter_rpc_possession_signing_input(
    challenge: &VoterRpcChallenge,
) -> Result<Vec<u8>, VoterReplacementError> {
    let binding = &challenge.binding;
    if binding.configuration.cluster_id() != binding.cluster_instance
        || binding.source.admission_generation == 0
        || binding.destination.admission_generation == 0
    {
        return Err(UNAUTHORIZED);
    }
    let mut bytes = b"openpacketcore/consensus/incarnation-admission/v1\0".to_vec();
    bytes.push(match binding.kind {
        VoterRpcProofKind::Request => 0,
        VoterRpcProofKind::Response => 1,
    });
    bytes.extend_from_slice(binding.cluster_instance.as_bytes());
    bytes.extend_from_slice(&binding.profile_digest);
    for (member, spiffe) in [
        (&binding.source, &binding.source_spiffe_id),
        (&binding.destination, &binding.destination_spiffe_id),
    ] {
        validate_spiffe(spiffe)?;
        bytes.extend_from_slice(&member.identity.slot().get().to_be_bytes());
        bytes.extend_from_slice(&member.identity.incarnation().get().to_be_bytes());
        bytes.extend_from_slice(&member.identity.node_id().get().to_be_bytes());
        bytes.extend_from_slice(&member.key_digest);
        bytes.extend_from_slice(&member.descriptor_digest);
        bytes.extend_from_slice(&member.admission_generation.to_be_bytes());
        bytes.extend_from_slice(&(spiffe.len() as u16).to_be_bytes());
        bytes.extend_from_slice(spiffe.as_bytes());
    }
    bytes.extend_from_slice(binding.configuration.configuration_id().as_bytes());
    bytes.extend_from_slice(
        &binding
            .configuration
            .configuration_epoch()
            .get()
            .to_be_bytes(),
    );
    match binding.replacement_digest {
        None => bytes.push(0),
        Some(digest) => {
            bytes.push(1);
            bytes.extend_from_slice(&digest);
        }
    }
    bytes.extend_from_slice(&binding.payload_digest);
    bytes.extend_from_slice(&challenge.challenge);
    bytes.extend_from_slice(&challenge.channel_binding);
    Ok(bytes)
}

#[derive(Clone, PartialEq, Eq)]
enum PendingBinding {
    Rpc(Box<VoterRpcChallenge>),
    Candidate(VoterCandidateChallenge),
}
struct Pending {
    binding: PendingBinding,
    expires: Instant,
}

/// Bounded receiver-owned challenge registry. It never accepts caller-chosen freshness.
///
/// A transport issues challenges only after authenticating its connection and
/// applies its ordinary rate limit and complete call deadline. Cancellation or
/// failure consumes no durable replacement authority. Outstanding challenges
/// expire automatically and are never carried across a process restart.
#[derive(Default)]
pub struct VoterChallengeIssuer {
    pending: Mutex<BTreeMap<[u8; 32], Pending>>,
}

impl std::fmt::Debug for VoterChallengeIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoterChallengeIssuer")
            .finish_non_exhaustive()
    }
}

impl VoterChallengeIssuer {
    /// Start an empty, process-local challenge registry.
    pub fn new() -> Self {
        Self::default()
    }

    fn issue<T>(
        &self,
        deadline: Instant,
        make: impl FnOnce([u8; 32]) -> Result<(T, PendingBinding), VoterReplacementError>,
    ) -> Result<T, VoterReplacementError> {
        let now = Instant::now();
        if deadline <= now || deadline.duration_since(now) > MAX_CHALLENGE_LIFETIME {
            return Err(VoterReplacementError::Deadline);
        }
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| VoterReplacementError::Unavailable)?;
        pending.retain(|_, value| value.expires > now);
        if pending.len() >= MAX_CHALLENGES {
            return Err(VoterReplacementError::Unavailable);
        }
        let nonce: [u8; 32] = rand::random();
        if pending.contains_key(&nonce) {
            return Err(VoterReplacementError::Unavailable);
        }
        let (result, binding) = make(nonce)?;
        pending.insert(
            nonce,
            Pending {
                binding,
                expires: deadline,
            },
        );
        Ok(result)
    }

    /// Challenge one exact call on its authenticated connection.
    pub fn issue_rpc(
        &self,
        binding: VoterRpcBinding,
        channel_binding: [u8; 32],
        deadline: Instant,
    ) -> Result<VoterRpcChallenge, VoterReplacementError> {
        self.issue(deadline, |challenge| {
            let result = VoterRpcChallenge {
                binding,
                challenge,
                channel_binding,
            };
            voter_rpc_possession_signing_input(&result)?;
            Ok((result.clone(), PendingBinding::Rpc(Box::new(result))))
        })
    }

    /// Challenge the selected candidate, including a binding recovered by quorum-backed pull.
    pub fn issue_candidate(
        &self,
        binding: VoterCandidateBinding,
        channel_binding: [u8; 32],
        deadline: Instant,
    ) -> Result<VoterCandidateChallenge, VoterReplacementError> {
        self.issue(deadline, |challenge| {
            let result = VoterCandidateChallenge {
                binding,
                challenge,
                channel_binding,
            };
            voter_candidate_possession_signing_input(&result)?;
            Ok((result.clone(), PendingBinding::Candidate(result)))
        })
    }

    fn take(
        &self,
        nonce: [u8; 32],
        binding: PendingBinding,
    ) -> Result<Instant, VoterReplacementError> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| VoterReplacementError::Unavailable)?
            .remove(&nonce)
            .ok_or(UNAUTHORIZED)?;
        if pending.binding != binding || Instant::now() >= pending.expires {
            return Err(UNAUTHORIZED);
        }
        Ok(pending.expires)
    }

    /// Verify key possession and the platform-authenticated source on the actual channel.
    ///
    /// `authenticated_spiffe` and `actual_channel` come from the trusted transport,
    /// never from request fields. The returned fact still needs store admission;
    /// even a later refusal must count as recent traffic from this proved key.
    pub fn verify_rpc(
        &self,
        challenge: &VoterRpcChallenge,
        authenticated_spiffe: &str,
        actual_channel: [u8; 32],
        key: [u8; 33],
        signature: [u8; 64],
    ) -> Result<VerifiedVoterRpc, VoterReplacementError> {
        let expires = self.take(
            challenge.challenge,
            PendingBinding::Rpc(Box::new(challenge.clone())),
        )?;
        if authenticated_spiffe != challenge.binding.source_spiffe_id
            || actual_channel != challenge.channel_binding
            || key_digest(key) != challenge.binding.source.key_digest
        {
            return Err(UNAUTHORIZED);
        }
        verify_signature(
            key,
            signature,
            &voter_rpc_possession_signing_input(challenge)?,
        )?;
        Ok(VerifiedVoterRpc {
            binding: challenge.binding.clone(),
            verified_at: Instant::now(),
            expires,
            consumed: AtomicBool::new(false),
        })
    }

    /// Verify the selected incarnation key for replacement or committed-binding pull.
    pub fn verify_candidate(
        &self,
        challenge: &VoterCandidateChallenge,
        authenticated_spiffe: &str,
        actual_channel: [u8; 32],
        key: [u8; 33],
        signature: [u8; 64],
    ) -> Result<VerifiedVoterCandidate, VoterReplacementError> {
        let expires = self.take(
            challenge.challenge,
            PendingBinding::Candidate(challenge.clone()),
        )?;
        if authenticated_spiffe != challenge.binding.spiffe_id
            || actual_channel != challenge.channel_binding
            || key_digest(key) != challenge.binding.key_digest
        {
            return Err(UNAUTHORIZED);
        }
        verify_signature(
            key,
            signature,
            &voter_candidate_possession_signing_input(challenge)?,
        )?;
        Ok(VerifiedVoterCandidate {
            binding: challenge.binding.clone(),
            expires,
        })
    }
}

/// Opaque one-use RPC proof. It has no deserialization or unchecked constructor.
pub struct VerifiedVoterRpc {
    binding: VoterRpcBinding,
    verified_at: Instant,
    expires: Instant,
    consumed: AtomicBool,
}
impl std::fmt::Debug for VerifiedVoterRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedVoterRpc").finish_non_exhaustive()
    }
}
impl VerifiedVoterRpc {
    /// Consume before observing activity or admitting any part of the RPC.
    pub fn consume(&self) -> Result<AuthenticatedVoterEvidence, VoterReplacementError> {
        if self.consumed.swap(true, Ordering::SeqCst) || Instant::now() >= self.expires {
            return Err(UNAUTHORIZED);
        }
        Ok(AuthenticatedVoterEvidence {
            binding: self.binding.clone(),
            verified_at: self.verified_at,
        })
    }
}

/// Cryptographically proved call coordinates, still subject to durable store gates.
pub struct AuthenticatedVoterEvidence {
    binding: VoterRpcBinding,
    pub(super) verified_at: Instant,
}
impl std::fmt::Debug for AuthenticatedVoterEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedVoterEvidence")
            .finish_non_exhaustive()
    }
}
impl AuthenticatedVoterEvidence {
    /// Exact signed coordinates. These alone are not voting or application admission.
    pub fn binding(&self) -> &VoterRpcBinding {
        &self.binding
    }
}

/// Opaque candidate proof, consumed by value and bounded by its original deadline.
pub struct VerifiedVoterCandidate {
    binding: VoterCandidateBinding,
    expires: Instant,
}
impl std::fmt::Debug for VerifiedVoterCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedVoterCandidate")
            .finish_non_exhaustive()
    }
}
impl VerifiedVoterCandidate {
    /// Consume one proof for the exact selected binding, including a quorum-read pull result.
    pub fn consume(self, expected: &VoterCandidateBinding) -> Result<(), VoterReplacementError> {
        if &self.binding != expected || Instant::now() >= self.expires {
            return Err(UNAUTHORIZED);
        }
        Ok(())
    }
}

/// Trusted current time uncertainty interval, supplied by the admission authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedVoterTime {
    earliest_ms: u64,
    latest_ms: u64,
}
impl TrustedVoterTime {
    /// Bind an ordered trusted interval; missing or reversed time cannot authorize a call.
    pub fn new(earliest_ms: u64, latest_ms: u64) -> Result<Self, VoterReplacementError> {
        if earliest_ms > latest_ms {
            return Err(VoterReplacementError::InvalidLossEvidence);
        }
        Ok(Self {
            earliest_ms,
            latest_ms,
        })
    }
}

/// Server-selected current controller authorization, never deserialized from a request.
///
/// The embedding admission adapter builds this only after validating the current
/// credential and rotating trust bundle, then applying its live per-slot policy.
/// An exact retry of retained work checks current authorization separately from
/// the historical attestation's expiry; it does not call new-request verification.
#[derive(Clone)]
pub struct VoterReplacementAuthorization {
    cluster: ConsensusClusterId,
    slots: BTreeSet<SlotId>,
    controller: String,
    key: [u8; 33],
    credential_digest: [u8; 32],
    policy: [u8; 32],
    minimum_loss_ms: u64,
}
impl std::fmt::Debug for VoterReplacementAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoterReplacementAuthorization")
            .finish_non_exhaustive()
    }
}
impl VoterReplacementAuthorization {
    /// Bind the authenticated current P-256 credential and the server's live policy.
    pub fn new(
        cluster: ConsensusClusterId,
        slots: BTreeSet<SlotId>,
        controller: String,
        key: [u8; 33],
        policy: [u8; 32],
        minimum_loss: Duration,
    ) -> Result<Self, VoterReplacementError> {
        validate_spiffe(&controller)?;
        if slots.is_empty() || slots.len() > MAX_FIXED_VOTER_SLOTS {
            return Err(UNAUTHORIZED);
        }
        let credential = VerifyingKey::from_sec1_bytes(&key)
            .map_err(|_| UNAUTHORIZED)?
            .to_public_key_der()
            .map_err(|_| UNAUTHORIZED)?;
        let minimum_loss_ms = u64::try_from(minimum_loss.as_millis()).map_err(|_| UNAUTHORIZED)?;
        Ok(Self {
            cluster,
            slots,
            controller,
            key,
            credential_digest: Sha256::digest(credential.as_bytes()).into(),
            policy,
            minimum_loss_ms,
        })
    }

    /// SHA-256 of the credential's canonical SubjectPublicKeyInfo, for signed claims.
    pub const fn credential_digest(&self) -> [u8; 32] {
        self.credential_digest
    }

    /// Check current authorization for a status query or retained exact retry.
    /// This grants no new incarnation and does not revalidate expired accepted claims.
    pub fn authorize_slot(
        &self,
        cluster: ConsensusClusterId,
        slot: SlotId,
        authenticated_controller: &str,
    ) -> Result<(), VoterReplacementError> {
        if self.cluster != cluster
            || !self.slots.contains(&slot)
            || self.controller != authenticated_controller
        {
            return Err(UNAUTHORIZED);
        }
        Ok(())
    }
}

/// Per-service verifier retaining only the monotonic trusted-time observation floor.
#[derive(Default, Debug)]
pub struct VoterReplacementVerifier {
    time_floor: Mutex<Option<TrustedVoterTime>>,
}
impl VoterReplacementVerifier {
    /// Start a verifier without an observed trusted-time floor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify a new loss selection against current credentials, policy, time and possession.
    pub fn verify(
        &self,
        request: &VoterReplacementRequest,
        authority: &VoterReplacementAuthorization,
        authenticated_controller: &str,
        now: TrustedVoterTime,
        candidate: VerifiedVoterCandidate,
    ) -> Result<VerifiedVoterReplacement, VoterReplacementError> {
        let invalid = VoterReplacementError::InvalidLossEvidence;
        request.validate()?;
        let claims = &request.attestation;
        authority.authorize_slot(
            claims.cluster_instance,
            claims.slot,
            authenticated_controller,
        )?;
        if authority.controller != claims.controller_spiffe_id
            || authority.credential_digest != claims.signing_key_digest
            || authority.policy != claims.policy_digest
        {
            return Err(UNAUTHORIZED);
        }
        if claims.issued_ms > now.earliest_ms
            || now.latest_ms >= claims.expires_ms
            || (claims.reason == VoterLossReason::TimeBoundLoss
                && claims.decision_ms - claims.observation_start_ms < authority.minimum_loss_ms)
        {
            return Err(invalid);
        }
        verify_signature(
            authority.key,
            claims.signature,
            &lost_voter_attestation_signing_input(claims).map_err(|_| invalid)?,
        )
        .map_err(|_| invalid)?;
        let expires = candidate.expires.min(
            Instant::now()
                + Duration::from_millis(claims.expires_ms - now.latest_ms)
                    .min(MAX_CHALLENGE_LIFETIME),
        );
        candidate.consume(&VoterCandidateBinding {
            cluster_instance: claims.cluster_instance,
            identity: request.candidate.identity,
            request_digest: claims.request_digest,
            key_digest: request.candidate.key_digest,
            spiffe_id: claims.candidate_spiffe_id.clone(),
        })?;
        let mut floor = self
            .time_floor
            .lock()
            .map_err(|_| VoterReplacementError::Unavailable)?;
        if floor.is_some_and(|previous| {
            now.earliest_ms < previous.earliest_ms || now.latest_ms < previous.latest_ms
        }) {
            return Err(invalid);
        }
        *floor = Some(now);
        Ok(VerifiedVoterReplacement {
            request: request.clone(),
            expires,
        })
    }
}

/// New-request authority, constructed only after all independent proofs verify.
pub struct VerifiedVoterReplacement {
    request: VoterReplacementRequest,
    expires: Instant,
}
impl std::fmt::Debug for VerifiedVoterReplacement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedVoterReplacement")
            .finish_non_exhaustive()
    }
}
impl VerifiedVoterReplacement {
    /// Canonical claims to validate against current state and propose once.
    pub fn request(&self) -> &VoterReplacementRequest {
        &self.request
    }

    /// Recheck immediately before a new proposal; caching verified claims cannot extend validity.
    pub fn ensure_fresh(&self) -> Result<(), VoterReplacementError> {
        if Instant::now() >= self.expires {
            return Err(VoterReplacementError::Deadline);
        }
        Ok(())
    }
}

fn key_digest(key: [u8; 33]) -> [u8; 32] {
    Sha256::digest(key).into()
}
fn verify_signature(
    key: [u8; 33],
    signature: [u8; 64],
    message: &[u8],
) -> Result<(), VoterReplacementError> {
    let signature = Signature::from_slice(&signature).map_err(|_| UNAUTHORIZED)?;
    if signature.normalize_s() != signature {
        return Err(UNAUTHORIZED);
    }
    VerifyingKey::from_sec1_bytes(&key)
        .map_err(|_| UNAUTHORIZED)?
        .verify_prehash(&Sha256::digest(message), &signature)
        .map_err(|_| UNAUTHORIZED)
}
fn validate_spiffe(identity: &str) -> Result<(), VoterReplacementError> {
    if identity.len() > MAX_VOTER_SPIFFE_ID_BYTES
        || !identity.starts_with("spiffe://")
        || identity.len() <= 9
        || identity
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(UNAUTHORIZED);
    }
    Ok(())
}
