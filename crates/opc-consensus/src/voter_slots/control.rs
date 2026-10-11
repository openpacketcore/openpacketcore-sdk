use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::*;
use crate::{ConsensusConfigurationEpoch, ConsensusIdentity, ConsensusNodeId, ConsensusRequestId};

/// Stable replacement refusal. Admission distinguishes no effect from uncertain submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VoterReplacementError {
    /// Current controller, incarnation or slot authorization was not proved.
    #[error("unauthorized voter replacement")]
    UnauthorizedReplacement,
    /// Loss claims, signature, validity or canonical request binding is invalid.
    #[error("invalid voter loss evidence")]
    InvalidLossEvidence,
    /// The caller's revision, configuration or incarnation is obsolete.
    #[error("stale voter incarnation")]
    StaleIncarnation,
    /// The same request ID names different canonical claims.
    #[error("voter replacement request identity conflict")]
    IdempotencyConflict,
    /// Another slot or effective uncommitted intent owns the operation slot.
    #[error("voter replacement already in progress")]
    ReplacementInProgress,
    /// An unchanged authenticated engine quorum could not be proved.
    #[error("no surviving voter quorum")]
    NoSurvivingQuorum,
    /// A survivor observed recent target-key-proven traffic.
    #[error("replacement target is still live")]
    TargetStillLive,
    /// The survivor has not observed the complete recent-traffic window yet.
    #[error("voter observation window is incomplete")]
    ObservationIncomplete,
    /// Authority has switched; this exact transition must finish forward.
    #[error("voter replacement is past its authority fence")]
    ReplacementPastFence,
    /// The retained activation family has no qualified continuation.
    #[error("activation continuation is unavailable")]
    ActivationContinuationUnavailable,
    /// This persistence, format or capability profile is not qualified.
    #[error("incompatible voter replacement profile")]
    IncompatibleProfile,
    /// No new engine identity fits the incarnation domain.
    #[error("voter incarnation exhausted")]
    IncarnationExhausted,
    /// No successor uniform configuration epoch is representable.
    #[error("voter configuration epoch exhausted")]
    ConfigurationEpochExhausted,
    /// No further table revision is representable.
    #[error("voter table revision exhausted")]
    RevisionExhausted,
    /// A command or membership is not the next authorized transition.
    #[error("invalid voter replacement transition")]
    InvalidTransition,
    /// The command may have entered consensus; only committed reconciliation resolves it.
    #[error("voter replacement outcome is unknown")]
    OutcomeUnknown,
    /// The original bounded operation deadline expired before submission.
    #[error("voter replacement deadline elapsed")]
    Deadline,
    /// The durable state or engine is unavailable; existing gates remain closed.
    #[error("voter replacement state is unavailable")]
    Unavailable,
}

/// Untrusted, bounded canonical request. Only admission constructs a verified request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoterReplacementRequest {
    /// Exact compare-and-set table revision.
    pub expected_revision: u64,
    /// Exact current uniform configuration, including every incarnation and key.
    pub expected_configuration: ConsensusIdentity,
    /// Selected successor's public binding.
    pub candidate: VoterSlotMember,
    /// Claims and signature remain untrusted after deserialization.
    #[serde(with = "attestation_wire")]
    pub attestation: LostVoterAttestationV1,
}

impl VoterReplacementRequest {
    /// Validate canonical claims and self-digest, without granting authentication.
    pub fn validate(&self) -> Result<(), VoterReplacementError> {
        let invalid = VoterReplacementError::InvalidLossEvidence;
        self.attestation.validate().map_err(|_| invalid)?;
        let digest = voter_replacement_request_digest(
            self.expected_revision,
            self.expected_configuration,
            &self.candidate,
            &self.attestation,
        )
        .map_err(|_| invalid)?;
        if self.expected_revision == 0
            || self.expected_configuration.cluster_id() != self.attestation.cluster_instance
            || self.candidate.identity.slot() != self.attestation.slot
            || self
                .attestation
                .expected_incarnation
                .next()
                .map_err(|_| VoterReplacementError::IncarnationExhausted)?
                != self.candidate.identity.incarnation()
            || self.candidate.key_digest != self.attestation.candidate_key_digest
            || self.candidate.admission_generation != self.attestation.admission_generation
            || digest != self.attestation.request_digest
        {
            return Err(invalid);
        }
        Ok(())
    }
}

/// Data carried by a committed control entry. Engine membership is observed separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoterReplacementStep {
    /// Retain the exact verified initial snapshot, before adding its learner.
    RecordSnapshot(VoterSnapshotEvidence),
    /// Retain a separately verified, durably applied current-term marker.
    RecordCaughtUp(VoterSlotLogId),
    /// Retain this command's exact committed capability-continuation cut.
    RecordContinuation,
    /// Publish only when the store's authority switch applies with effect atomically.
    Fence,
    /// Retain completion after the engine's uniform entry applied.
    Finalize,
}

/// Bounded store-owned control command; decoding it grants no controller authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoterSlotControl {
    /// Compare and set one slot, retiring its prior incarnation permanently.
    Begin(Box<VoterReplacementRequest>),
    /// Advance one exact retained operation.
    Advance {
        /// Original caller-stable request identity.
        request_id: ConsensusRequestId,
        /// Original canonical request commitment.
        request_digest: [u8; 32],
        /// Required next step.
        step: VoterReplacementStep,
    },
    /// A current-term committed marker; proof of candidate apply is recorded separately.
    Marker {
        /// Exact retained operation.
        request_id: ConsensusRequestId,
        /// Canonical operation digest.
        request_digest: [u8; 32],
    },
}

impl VoterSlotControl {
    /// Encode the canonical command under a fixed bound, independent of application state.
    pub fn encode(&self) -> Result<Vec<u8>, VoterSlotError> {
        let bytes = crate::encode_bounded(self).map_err(|_| VoterSlotError::InvalidRecord)?;
        if bytes.len() > MAX_VOTER_SLOT_TABLE_BYTES {
            return Err(VoterSlotError::TooLarge);
        }
        Ok(bytes)
    }

    /// Decode only the current bounded command representation, without admission.
    pub fn decode(bytes: &[u8]) -> Result<Self, VoterSlotError> {
        if bytes.len() > MAX_VOTER_SLOT_TABLE_BYTES {
            return Err(VoterSlotError::TooLarge);
        }
        crate::decode_bounded(bytes).map_err(|_| VoterSlotError::InvalidRecord)
    }
}

impl VoterSlotTable {
    /// Current uniform configuration. A selected pending candidate does not change it.
    pub fn current_configuration(&self) -> VoterConfiguration {
        if let Some(operation) = &self.replacement {
            if operation.phase < VoterReplacementPhase::Uniform {
                return operation.predecessor.clone();
            }
        }
        VoterConfiguration {
            epoch: self.configuration_epoch,
            members: self.slots.iter().map(|slot| slot.member.clone()).collect(),
        }
    }

    /// Apply a deterministic control at its actual engine cut, atomically or without effect.
    ///
    /// The store authenticates new proposals, durably fences Begin before append
    /// acknowledgement, and couples Fence to a successful authority switch in the
    /// same transaction. This method neither synthesizes membership nor proves IO.
    pub fn apply_control(
        &mut self,
        control: &VoterSlotControl,
        cut: VoterSlotLogId,
    ) -> Result<(), VoterReplacementError> {
        self.validate()
            .map_err(|_| VoterReplacementError::InvalidTransition)?;
        if cut.term == 0 || cut.index == 0 {
            return Err(VoterReplacementError::InvalidTransition);
        }
        let mut next = self.clone();
        match control {
            VoterSlotControl::Begin(request) => next.begin(request, cut)?,
            VoterSlotControl::Advance {
                request_id,
                request_digest,
                step,
            } => next.advance(*request_id, *request_digest, step, cut)?,
            VoterSlotControl::Marker {
                request_id,
                request_digest,
            } => {
                let operation = next
                    .replacement
                    .as_ref()
                    .ok_or(VoterReplacementError::InvalidTransition)?;
                if operation.attestation.request_id != *request_id
                    || operation.attestation.request_digest != *request_digest
                    || !matches!(
                        operation.phase,
                        VoterReplacementPhase::LearnerAdded | VoterReplacementPhase::CaughtUp
                    )
                {
                    return Err(VoterReplacementError::InvalidTransition);
                }
            }
        }
        if next == *self {
            return Ok(());
        }
        next.validate_successor_of(self)
            .map_err(|_| VoterReplacementError::InvalidTransition)?;
        *self = next;
        Ok(())
    }

    fn next_revision(&self) -> Result<u64, VoterReplacementError> {
        self.revision
            .checked_add(1)
            .ok_or(VoterReplacementError::RevisionExhausted)
    }

    fn begin(
        &mut self,
        request: &VoterReplacementRequest,
        cut: VoterSlotLogId,
    ) -> Result<(), VoterReplacementError> {
        use VoterReplacementError::*;
        let claims = &request.attestation;
        let existing_digest = self
            .replacement
            .as_ref()
            .filter(|op| op.attestation.request_id == claims.request_id)
            .map(|op| op.attestation.request_digest)
            .or_else(|| {
                self.slots
                    .iter()
                    .filter_map(|slot| slot.last_result.as_ref())
                    .find(|result| result.request_id == claims.request_id)
                    .map(|result| result.request_digest)
            });
        if let Some(digest) = existing_digest {
            if digest != claims.request_digest {
                return Err(IdempotencyConflict);
            }
            request.validate()?;
            return Ok(());
        }
        if let Some(operation) = &self.replacement {
            if operation.attestation.slot != claims.slot {
                return Err(ReplacementInProgress);
            }
            if operation.phase >= VoterReplacementPhase::Fenced {
                return Err(ReplacementPastFence);
            }
            if cut.index <= operation.evidence.prepare.index {
                return Err(InvalidTransition);
            }
        }
        request.validate()?;
        let index = self
            .slots
            .iter()
            .position(|slot| slot.member.identity.slot() == claims.slot)
            .ok_or(StaleIncarnation)?;
        let old = &self.slots[index].member;
        if self.revision != request.expected_revision
            || self
                .current_configuration()
                .identity(self.cluster_instance, self.manifest_digest)
                .map_err(|_| InvalidTransition)?
                != request.expected_configuration
            || claims.cluster_instance != self.cluster_instance
            || claims.expected_incarnation != old.identity.incarnation()
            || claims.old_descriptor_digest != old.descriptor_digest
        {
            return Err(StaleIncarnation);
        }
        if self.slots.len() < 3 {
            return Err(NoSurvivingQuorum);
        }
        if request.candidate.admission_generation <= old.admission_generation
            || request.candidate.key_digest == old.key_digest
        {
            return Err(InvalidLossEvidence);
        }
        let predecessor = self.current_configuration();
        let epoch = ConsensusConfigurationEpoch::new(
            predecessor
                .epoch
                .get()
                .checked_add(1)
                .ok_or(ConfigurationEpochExhausted)?,
        )
        .map_err(|_| ConfigurationEpochExhausted)?;
        let revision = self.next_revision()?;
        if let Some(previous) = self.replacement.take() {
            self.slots[index].last_result = Some(VoterReplacementResult {
                request_id: previous.attestation.request_id,
                request_digest: previous.attestation.request_digest,
                incarnation: old.identity.incarnation(),
                revision,
                configuration_epoch: self.configuration_epoch,
                kind: VoterReplacementResultKind::Superseded,
                terminal: cut,
            });
        }
        self.slots[index].member = request.candidate.clone();
        self.slots[index].retired_through = claims.expected_incarnation.get();
        self.slots[index].phase = VoterSlotPhase::Pending;
        let successor = VoterConfiguration {
            epoch,
            members: self.slots.iter().map(|slot| slot.member.clone()).collect(),
        };
        self.revision = revision;
        self.replacement = Some(VoterReplacementRecord {
            expected_revision: request.expected_revision,
            attestation: claims.clone(),
            predecessor,
            successor,
            phase: VoterReplacementPhase::Prepared,
            evidence: VoterReplacementEvidence {
                prepare: cut,
                snapshot: None,
                learner: None,
                caught_up: None,
                continuation: None,
                fence: None,
                joint: None,
                uniform: None,
            },
        });
        Ok(())
    }

    fn advance(
        &mut self,
        request_id: ConsensusRequestId,
        digest: [u8; 32],
        step: &VoterReplacementStep,
        cut: VoterSlotLogId,
    ) -> Result<(), VoterReplacementError> {
        use VoterReplacementError::*;
        use VoterReplacementPhase::*;
        let revision = self.next_revision()?;
        let Some(operation) = self.replacement.as_mut() else {
            return if matches!(step, VoterReplacementStep::Finalize)
                && self
                    .slots
                    .iter()
                    .filter_map(|slot| slot.last_result.as_ref())
                    .any(|result| {
                        result.request_id == request_id
                            && result.request_digest == digest
                            && result.kind == VoterReplacementResultKind::Completed
                    })
            {
                Ok(())
            } else {
                Err(StaleIncarnation)
            };
        };
        if operation.attestation.request_id != request_id {
            return Err(StaleIncarnation);
        }
        if operation.attestation.request_digest != digest {
            return Err(IdempotencyConflict);
        }
        if cut.index <= operation.evidence.prepare.index
            || cut.term < operation.evidence.prepare.term
        {
            return Err(InvalidTransition);
        }
        match step {
            VoterReplacementStep::RecordSnapshot(snapshot) => {
                if let Some(existing) = &operation.evidence.snapshot {
                    return if existing == snapshot {
                        Ok(())
                    } else {
                        Err(IdempotencyConflict)
                    };
                }
                if operation.phase != Prepared
                    || snapshot.cut.index >= cut.index
                    || snapshot.cut.term > cut.term
                {
                    return Err(InvalidTransition);
                }
                operation.evidence.snapshot = Some(snapshot.clone());
                operation.phase = SnapshotInstalled;
            }
            VoterReplacementStep::RecordCaughtUp(marker) => {
                if operation.evidence.caught_up == Some(*marker) {
                    return Ok(());
                }
                if !matches!(operation.phase, LearnerAdded | CaughtUp)
                    || marker.term != cut.term
                    || marker.index >= cut.index
                {
                    return Err(InvalidTransition);
                }
                operation.evidence.caught_up = Some(*marker);
                operation.phase = CaughtUp;
            }
            VoterReplacementStep::RecordContinuation => {
                if operation.evidence.continuation.is_some() {
                    return Ok(());
                }
                if operation.phase >= Fenced {
                    return Err(InvalidTransition);
                }
                operation.evidence.continuation = Some(cut);
            }
            VoterReplacementStep::Fence => {
                if operation.phase >= Fenced {
                    return Ok(());
                }
                if operation.phase != CaughtUp
                    || operation
                        .evidence
                        .caught_up
                        .is_none_or(|marker| marker.term != cut.term)
                {
                    return Err(InvalidTransition);
                }
                operation.evidence.fence = Some(cut);
                operation.phase = Fenced;
            }
            VoterReplacementStep::Finalize => {
                if operation.phase != Uniform {
                    return Err(InvalidTransition);
                }
                let slot = self
                    .slots
                    .iter_mut()
                    .find(|slot| slot.member.identity.slot() == operation.attestation.slot)
                    .ok_or(InvalidTransition)?;
                slot.last_result = Some(VoterReplacementResult {
                    request_id,
                    request_digest: digest,
                    incarnation: slot.member.identity.incarnation(),
                    revision,
                    configuration_epoch: self.configuration_epoch,
                    kind: VoterReplacementResultKind::Completed,
                    terminal: cut,
                });
                self.replacement = None;
            }
        }
        self.revision = revision;
        Ok(())
    }

    /// Validate and observe an actual applied engine membership entry.
    ///
    /// Every voter set retains the manifest's original cardinality. A learner
    /// never substitutes for a voter, and uniform cannot skip committed joint.
    pub fn observe_membership(
        &mut self,
        configurations: &[BTreeSet<ConsensusNodeId>],
        nodes: &BTreeSet<ConsensusNodeId>,
        cut: VoterSlotLogId,
    ) -> Result<(), VoterReplacementError> {
        use VoterReplacementPhase::*;
        let invalid = VoterReplacementError::InvalidTransition;
        let mut next = self.clone();
        let revision = self.next_revision()?;
        let Some(operation) = next.replacement.as_mut() else {
            let current = member_ids(&self.current_configuration());
            return if configurations == [current.clone()] && nodes == &current {
                Ok(())
            } else {
                Err(invalid)
            };
        };
        let old = member_ids(&operation.predecessor);
        let new = member_ids(&operation.successor);
        let union = old.union(&new).copied().collect::<BTreeSet<_>>();
        let candidate = new.difference(&old).next().copied().ok_or(invalid)?;
        if configurations == [old.clone()] {
            if operation.phase >= Joint || !old.is_subset(nodes) || nodes.len() > old.len() + 1 {
                return Err(invalid);
            }
            // Supersede retires the previous candidate atomically with Prepare.
            // Its already-applied learner entry remains real until Openraft
            // removes it. It grants no catch-up or voting rights to the new key.
            if let Some(obsolete) = nodes.difference(&union).next() {
                let identity = VoterSlotIdentity::from_node_id(*obsolete).map_err(|_| invalid)?;
                let predecessor = operation
                    .predecessor
                    .members
                    .iter()
                    .find(|member| member.identity.slot() == operation.attestation.slot)
                    .ok_or(invalid)?;
                if operation.phase > SnapshotInstalled
                    || identity.slot() != operation.attestation.slot
                    || identity.incarnation() <= predecessor.identity.incarnation()
                    || identity.incarnation() > operation.attestation.expected_incarnation
                {
                    return Err(invalid);
                }
            }
            if nodes.contains(&candidate) {
                if operation.phase < SnapshotInstalled {
                    return Err(invalid);
                }
                if operation.phase == SnapshotInstalled {
                    operation.evidence.learner = Some(cut);
                    operation.phase = LearnerAdded;
                }
            } else if operation.phase >= LearnerAdded {
                return Err(invalid);
            }
        } else if configurations == [old, new.clone()] && nodes == &union {
            if !matches!(operation.phase, Fenced | Joint) {
                return Err(invalid);
            }
            if operation.phase == Fenced {
                operation.evidence.joint = Some(cut);
                operation.phase = Joint;
            }
        } else if configurations == [new.clone()] && nodes == &new {
            if !matches!(operation.phase, Joint | Uniform) {
                return Err(invalid);
            }
            if operation.phase == Joint {
                operation.evidence.uniform = Some(cut);
                operation.phase = Uniform;
                next.configuration_epoch = operation.successor.epoch;
            }
        } else {
            return Err(invalid);
        }
        let slot = next
            .slots
            .iter_mut()
            .find(|slot| slot.member.identity.slot() == operation.attestation.slot)
            .ok_or(invalid)?;
        slot.phase = match operation.phase {
            Prepared | SnapshotInstalled => VoterSlotPhase::Pending,
            LearnerAdded | CaughtUp | Fenced => VoterSlotPhase::CatchingUp,
            Joint | Uniform => VoterSlotPhase::Voting,
        };
        if next == *self {
            return Ok(());
        }
        next.revision = revision;
        next.validate_successor_of(self).map_err(|_| invalid)?;
        *self = next;
        Ok(())
    }

    /// Whether an engine identity is covered by this installation's permanent floor.
    pub fn is_retired(&self, node: ConsensusNodeId) -> bool {
        let Ok(identity) = VoterSlotIdentity::from_node_id(node) else {
            return false;
        };
        self.slots.iter().any(|slot| {
            slot.member.identity.slot() == identity.slot()
                && identity.incarnation().get() <= slot.retired_through
        })
    }
}

fn member_ids(configuration: &VoterConfiguration) -> BTreeSet<ConsensusNodeId> {
    configuration
        .members
        .iter()
        .map(|member| member.identity.node_id())
        .collect()
}

mod attestation_wire {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub(super) fn serialize<S: Serializer>(
        value: &LostVoterAttestationV1,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        encode_lost_voter_attestation(value)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<LostVoterAttestationV1, D::Error> {
        decode_lost_voter_attestation(&Vec::<u8>::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}
