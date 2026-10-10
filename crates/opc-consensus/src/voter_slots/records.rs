use sha2::{Digest, Sha256};

use crate::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId, ConsensusIdentity,
    ConsensusRequestId,
};

use super::{SlotId, VoterIncarnation, VoterSlotError, VoterSlotIdentity};

/// Maximum fixed topology size, including configuration-store quorums.
pub const MAX_FIXED_VOTER_SLOTS: usize = 9;
/// Hard ceiling for one complete durable slot table, independent of application size.
pub const MAX_VOTER_SLOT_TABLE_BYTES: usize = 64 * 1024;
/// Hard ceiling for one complete signed loss-attestation frame.
pub const MAX_LOST_VOTER_ATTESTATION_BYTES: usize = 8 * 1024;
/// Maximum UTF-8 byte length of each attested workload identity.
pub const MAX_VOTER_SPIFFE_ID_BYTES: usize = 2048;
/// Maximum UTF-8 byte length of the engine's retained snapshot identifier.
pub const MAX_VOTER_SNAPSHOT_ID_BYTES: usize = 256;

/// Public incarnation binding. No field establishes possession or authorization.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoterSlotMember {
    /// Installation-scoped slot and incarnation.
    pub identity: VoterSlotIdentity,
    /// Digest of the separately held canonical compressed P-256 public key.
    pub key_digest: [u8; 32],
    /// Digest of the immutable selected descriptor, including workload identity.
    pub descriptor_digest: [u8; 32],
    /// Strictly increasing platform selection generation for this slot.
    pub admission_generation: u64,
}

/// Observable admission stage; engine membership remains the quorum authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum VoterSlotPhase {
    /// Selected but no learner membership has been committed.
    Pending = 0,
    /// Snapshot installed and learner membership committed; voting remains closed.
    CatchingUp = 1,
    /// Committed joint or uniform membership; local voting still requires admission.
    Voting = 2,
}

/// Permanent retirement floor and bounded idempotency receipt for one manifest slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterSlotRecord {
    /// Currently selected incarnation and its public binding.
    pub member: VoterSlotMember,
    /// Every incarnation up to this value is permanently retired; zero is genesis.
    pub retired_through: u64,
    /// Selected incarnation's replicated progress.
    pub phase: VoterSlotPhase,
    /// Most recent terminal request, replaced only with a later terminal result.
    pub last_result: Option<VoterReplacementResult>,
}

/// Full log identity under the pinned engine's `single-term-leader` profile.
/// It contains term and index only; absent evidence uses `None`, never index zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoterSlotLogId {
    /// Engine leader term, retained without rewriting after replacement.
    pub term: u64,
    /// Engine log index.
    pub index: u64,
}

impl<N: crate::engine::NodeId> From<crate::engine::LogId<N>> for VoterSlotLogId {
    fn from(log_id: crate::engine::LogId<N>) -> Self {
        Self {
            term: log_id.leader_id.term,
            index: log_id.index,
        }
    }
}

/// Exact artifact initially installed before adding the replacement learner.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoterSnapshotEvidence {
    /// Full committed cut included by the artifact.
    pub cut: VoterSlotLogId,
    /// Engine snapshot identifier, bounded independently of application state.
    pub snapshot_id: String,
    /// Digest of the verified artifact; decoding this digest does not verify it.
    pub digest: [u8; 32],
}

/// Exact canonical configuration, sorted by immutable slot ordinal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterConfiguration {
    /// Monotonic uniform configuration epoch.
    pub epoch: ConsensusConfigurationEpoch,
    /// Incarnation-qualified members and keys, one per immutable slot.
    pub members: Vec<VoterSlotMember>,
}

impl VoterConfiguration {
    /// Hash the exact configuration with its installation and immutable manifest.
    pub fn identity(
        &self,
        cluster: ConsensusClusterId,
        manifest: [u8; 32],
    ) -> Result<ConsensusIdentity, VoterSlotError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/consensus/voter-configuration/v1\0");
        hash.update(cluster.as_bytes());
        hash.update(manifest);
        hash.update(self.epoch.get().to_be_bytes());
        hash.update([self.members.len() as u8]);
        for member in &self.members {
            hash.update(member.identity.slot().get().to_be_bytes());
            hash.update(member.identity.incarnation().get().to_be_bytes());
            hash.update(member.key_digest);
            hash.update(member.descriptor_digest);
            hash.update(member.admission_generation.to_be_bytes());
        }
        Ok(ConsensusIdentity::new(
            cluster,
            ConsensusConfigurationId::from_bytes(hash.finalize().into()),
            self.epoch,
        ))
    }
}

/// Controller-declared reason; ordinary engine timeouts cannot construct authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VoterLossReason {
    /// Controller verified loss of the prior durable state.
    StorageLost = 1,
    /// Controller applied its authorized time-bound loss policy.
    TimeBoundLoss = 2,
}

/// Bounded signed claims retained with a replacement (RFC 023, version 1).
///
/// This is untrusted serializable data, including after decoding. The admission
/// adapter must verify the current credential, signature/low-S form, trusted time,
/// slot permission, policy and candidate proof before proposing these claims.
/// Deterministic storage validation performs no network or wall-clock checks.
#[derive(Clone, PartialEq, Eq)]
pub struct LostVoterAttestationV1 {
    /// Caller-stable idempotency identity.
    pub request_id: ConsensusRequestId,
    /// Canonical request-body digest, excluding its own field and proofs.
    pub request_digest: [u8; 32],
    /// Fresh-installation cluster identity.
    pub cluster_instance: ConsensusClusterId,
    /// Target logical slot.
    pub slot: SlotId,
    /// Exact incarnation whose loss the controller declares.
    pub expected_incarnation: VoterIncarnation,
    /// Prior incarnation's selected descriptor digest.
    pub old_descriptor_digest: [u8; 32],
    /// Selected candidate's independent public-key digest.
    pub candidate_key_digest: [u8; 32],
    /// Monotonic platform selection generation.
    pub admission_generation: u64,
    /// Candidate workload identity, separately authenticated at admission.
    pub candidate_spiffe_id: String,
    /// Controller identity authorized by the current platform policy.
    pub controller_spiffe_id: String,
    /// Controller signing credential's SPKI digest.
    pub signing_key_digest: [u8; 32],
    /// Explicit controller loss-policy decision.
    pub reason: VoterLossReason,
    /// Policy digest interpreted by the trusted admission adapter.
    pub policy_digest: [u8; 32],
    /// Unix milliseconds at the beginning of the loss observation.
    pub observation_start_ms: u64,
    /// Unix milliseconds at the loss decision.
    pub decision_ms: u64,
    /// Unix milliseconds at issuance.
    pub issued_ms: u64,
    /// Exclusive validity deadline in Unix milliseconds.
    pub expires_ms: u64,
    /// Raw P-256 `r || s`; canonicality and cryptographic validity need verification.
    pub signature: [u8; 64],
}

impl std::fmt::Debug for LostVoterAttestationV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LostVoterAttestationV1")
            .field("slot", &self.slot)
            .field("expected_incarnation", &self.expected_incarnation)
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// Replicated replacement progress. Fence and later phases cannot be superseded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum VoterReplacementPhase {
    /// Prepare committed; prior incarnation retired.
    Prepared = 0,
    /// Verified out-of-band snapshot installed before learner addition.
    SnapshotInstalled = 1,
    /// Exact learner membership committed.
    LearnerAdded = 2,
    /// Candidate durably applied the current-term catch-up marker.
    CaughtUp = 3,
    /// Authority Fence applied with effect; only forward completion is allowed.
    Fenced = 4,
    /// Exact joint membership committed.
    Joint = 5,
    /// Successor uniform membership committed; Finalize may release the operation.
    Uniform = 6,
}

/// Retained full engine cuts. Optional continuation depends on activation family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterReplacementEvidence {
    /// Committed retirement/reservation cut.
    pub prepare: VoterSlotLogId,
    /// Initial installed snapshot's cut, at or after Prepare.
    pub snapshot: Option<VoterSnapshotEvidence>,
    /// Learner membership after verified snapshot installation.
    pub learner: Option<VoterSlotLogId>,
    /// Marker durably applied by the candidate. A new leader may advance it
    /// before Fence; after Fence this proof is retained without a live recheck.
    pub caught_up: Option<VoterSlotLogId>,
    /// Required activation/capability continuation, when this profile uses one.
    pub continuation: Option<VoterSlotLogId>,
    /// Fence applied with effect, the point of no return. No live candidate
    /// barrier is allowed afterward; a committed but refused Fence supplies none.
    pub fence: Option<VoterSlotLogId>,
    /// Actual committed joint entry emitted by the engine.
    pub joint: Option<VoterSlotLogId>,
    /// Actual committed uniform entry emitted by the engine.
    pub uniform: Option<VoterSlotLogId>,
}

/// One durable desired replacement; decode alone never establishes authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterReplacementRecord {
    /// Exact table revision against which the reservation was submitted.
    pub expected_revision: u64,
    /// Accepted claims and historical signature retained for recovery.
    pub attestation: LostVoterAttestationV1,
    /// Exact old engine membership, retaining the retired ID in its denominator.
    pub predecessor: VoterConfiguration,
    /// Exact desired membership, changing one logical slot only.
    pub successor: VoterConfiguration,
    /// Replicated phase, independent of local observed progress.
    pub phase: VoterReplacementPhase,
    /// Durable engine evidence for that phase.
    pub evidence: VoterReplacementEvidence,
}

/// Terminal disposition retained for an idempotent retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VoterReplacementResultKind {
    /// Finalize after uniform membership.
    Completed = 0,
    /// Candidate replaced under a new request before Fence.
    Superseded = 1,
}

/// One bounded per-slot receipt; floors still reject older attempts after pruning it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterReplacementResult {
    /// Terminal request identity.
    pub request_id: ConsensusRequestId,
    /// Terminal canonical request body.
    pub request_digest: [u8; 32],
    /// Incarnation selected by that request.
    pub incarnation: VoterIncarnation,
    /// Revision recording this terminal outcome.
    pub revision: u64,
    /// Uniform epoch at which the outcome was recorded.
    pub configuration_epoch: ConsensusConfigurationEpoch,
    /// Success or pre-Fence supersession.
    pub kind: VoterReplacementResultKind,
    /// Full Finalize or supersession log ID.
    pub terminal: VoterSlotLogId,
}

/// Reserved durable incarnation metadata, atomically included in store snapshots.
///
/// Fields are data and may be assembled by store state machines. Call the bounded
/// codec for persistence; it validates every record. No serialization path creates
/// a verified peer, a voting permit, or an enabled replacement capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterSlotTable {
    /// Installation identity, never derived solely from a reused display name.
    pub cluster_instance: ConsensusClusterId,
    /// Immutable manifest, including slot ordinals and placement policy.
    pub manifest_digest: [u8; 32],
    /// Monotonic state revision; zero is invalid.
    pub revision: u64,
    /// Current committed uniform configuration epoch.
    pub configuration_epoch: ConsensusConfigurationEpoch,
    /// Exact manifest slots sorted by ordinal; retired history is a floor per slot.
    pub slots: Vec<VoterSlotRecord>,
    /// At most one active replacement across the entire installation.
    pub replacement: Option<VoterReplacementRecord>,
}
