use super::*;

fn require(valid: bool) -> Result<(), VoterSlotError> {
    if valid {
        Ok(())
    } else {
        Err(VoterSlotError::InvalidRecord)
    }
}

pub(super) fn validate_count(count: usize) -> Result<(), VoterSlotError> {
    require(count > 0 && count <= MAX_FIXED_VOTER_SLOTS && count % 2 == 1)
}

impl VoterConfiguration {
    pub(super) fn validate(&self) -> Result<(), VoterSlotError> {
        validate_count(self.members.len())?;
        require(self.members.iter().all(|m| m.admission_generation > 0))?;
        require(
            self.members
                .windows(2)
                .all(|pair| pair[0].identity.slot() < pair[1].identity.slot()),
        )
    }
}

impl LostVoterAttestationV1 {
    pub(super) fn validate(&self) -> Result<(), VoterSlotError> {
        for identity in [&self.candidate_spiffe_id, &self.controller_spiffe_id] {
            if identity.len() > MAX_VOTER_SPIFFE_ID_BYTES {
                return Err(VoterSlotError::TooLarge);
            }
            // Full SPIFFE syntax/trust and credential checks belong to admission.
            require(
                identity.starts_with("spiffe://")
                    && identity.len() > 9
                    && !identity
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace()),
            )?;
        }
        require(
            self.admission_generation > 0
                && self.observation_start_ms <= self.decision_ms
                && self.decision_ms <= self.issued_ms
                && self.issued_ms < self.expires_ms,
        )
    }
}

impl VoterSlotLogId {
    fn validate(self) -> Result<(), VoterSlotError> {
        require(self.term > 0 && self.index > 0)
    }

    fn follows(self, older: Self, allow_equal: bool) -> bool {
        if self.index == older.index {
            return allow_equal && self == older;
        }
        self.index > older.index && self.term >= older.term
    }
}

impl VoterReplacementEvidence {
    fn validate(&self, phase: VoterReplacementPhase) -> Result<(), VoterSlotError> {
        use VoterReplacementPhase::*;
        self.prepare.validate()?;
        if let Some(snapshot) = &self.snapshot {
            if snapshot.snapshot_id.len() > MAX_VOTER_SNAPSHOT_ID_BYTES {
                return Err(VoterSlotError::TooLarge);
            }
            require(
                !snapshot.snapshot_id.is_empty()
                    && !snapshot.snapshot_id.chars().any(char::is_control),
            )?;
        }
        let ordered = [
            (self.snapshot.as_ref().map(|s| s.cut), SnapshotInstalled),
            (self.learner, LearnerAdded),
            (self.caught_up, CaughtUp),
            (self.fence, Fenced),
            (self.joint, Joint),
            (self.uniform, Uniform),
        ];
        let mut previous = self.prepare;
        for (cut, required_at) in ordered {
            require(cut.is_some() == (phase >= required_at))?;
            if let Some(cut) = cut {
                cut.validate()?;
                require(cut.follows(previous, required_at == SnapshotInstalled))?;
                previous = cut;
            }
        }
        if let Some(continuation) = self.continuation {
            continuation.validate()?;
            require(continuation.follows(self.prepare, false))?;
            if let Some(fence) = self.fence {
                require(fence.follows(continuation, false))?;
            }
            for (cut, is_snapshot) in [
                (self.snapshot.as_ref().map(|s| s.cut), true),
                (self.learner, false),
                (self.caught_up, false),
            ] {
                if let Some(cut) = cut {
                    require(if continuation.index >= cut.index {
                        continuation.follows(cut, is_snapshot)
                    } else {
                        cut.follows(continuation, false)
                    })?;
                }
            }
        }
        Ok(())
    }

    fn retains(&self, previous: &Self, previous_phase: VoterReplacementPhase) -> bool {
        let retains_marker = match (self.caught_up, previous.caught_up) {
            (_, None) => true,
            (Some(new), Some(old)) => {
                new == old
                    || (previous_phase < VoterReplacementPhase::Fenced && new.follows(old, false))
            }
            (None, Some(_)) => false,
        };
        self.prepare == previous.prepare
            && (previous.snapshot.is_none() || self.snapshot == previous.snapshot)
            && retains_marker
            && [
                (self.learner, previous.learner),
                (self.continuation, previous.continuation),
                (self.fence, previous.fence),
                (self.joint, previous.joint),
                (self.uniform, previous.uniform),
            ]
            .iter()
            .all(|(new, old)| old.is_none() || new == old)
    }

    fn latest(&self) -> VoterSlotLogId {
        [
            self.snapshot.as_ref().map(|s| s.cut),
            self.learner,
            self.caught_up,
            self.continuation,
            self.fence,
            self.joint,
            self.uniform,
        ]
        .into_iter()
        .flatten()
        .fold(self.prepare, |latest, cut| {
            if cut.index > latest.index {
                cut
            } else {
                latest
            }
        })
    }
}

impl VoterSlotTable {
    pub(super) fn validate(&self) -> Result<(), VoterSlotError> {
        validate_count(self.slots.len())?;
        require(self.revision > 0)?;
        require(
            self.slots
                .windows(2)
                .all(|p| p[0].member.identity.slot() < p[1].member.identity.slot()),
        )?;
        for slot in &self.slots {
            require(
                slot.member.admission_generation > 0
                    && slot.retired_through == slot.member.identity.incarnation().get() - 1,
            )?;
            let is_active = self
                .replacement
                .as_ref()
                .is_some_and(|op| op.attestation.slot == slot.member.identity.slot());
            if !is_active && slot.member.identity.incarnation().get() > 1 {
                require(slot.last_result.as_ref().is_some_and(|result| {
                    result.incarnation == slot.member.identity.incarnation()
                        && result.kind == VoterReplacementResultKind::Completed
                }))?;
            }
            if let Some(result) = &slot.last_result {
                result.terminal.validate()?;
                require(
                    result.revision > 0
                        && result.revision <= self.revision
                        && result.configuration_epoch <= self.configuration_epoch
                        && result.incarnation.get() > 1
                        && result.incarnation <= slot.member.identity.incarnation(),
                )?;
                require(!is_active || result.incarnation < slot.member.identity.incarnation())?;
                if result.incarnation == slot.member.identity.incarnation() {
                    require(
                        slot.phase == VoterSlotPhase::Voting
                            && result.kind == VoterReplacementResultKind::Completed,
                    )?;
                }
            }
        }
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(result) = &slot.last_result {
                require(
                    self.slots[..i]
                        .iter()
                        .filter_map(|s| s.last_result.as_ref())
                        .all(|r| r.request_id != result.request_id),
                )?;
            }
        }
        if let Some(operation) = &self.replacement {
            self.validate_operation(operation)
        } else {
            require(self.slots.iter().all(|s| s.phase == VoterSlotPhase::Voting))
        }
    }

    fn validate_operation(&self, op: &VoterReplacementRecord) -> Result<(), VoterSlotError> {
        op.attestation.validate()?;
        op.predecessor.validate()?;
        op.successor.validate()?;
        op.evidence.validate(op.phase)?;
        require(
            op.expected_revision > 0
                && op.expected_revision < self.revision
                && op.attestation.cluster_instance == self.cluster_instance
                && self.slots.len() >= 3
                && op.predecessor.members.len() == self.slots.len()
                && op.successor.members.len() == self.slots.len()
                && op.predecessor.epoch.get().checked_add(1) == Some(op.successor.epoch.get()),
        )?;
        let current_epoch = if op.phase == VoterReplacementPhase::Uniform {
            op.successor.epoch
        } else {
            op.predecessor.epoch
        };
        require(self.configuration_epoch == current_epoch)?;
        let mut found_target = false;
        for ((slot, predecessor), successor) in self
            .slots
            .iter()
            .zip(&op.predecessor.members)
            .zip(&op.successor.members)
        {
            require(
                slot.member == *successor
                    && predecessor.identity.slot() == successor.identity.slot(),
            )?;
            if slot.member.identity.slot() == op.attestation.slot {
                found_target = true;
                require(
                    op.attestation.expected_incarnation.next()? == successor.identity.incarnation()
                        && predecessor.identity.incarnation()
                            <= op.attestation.expected_incarnation
                        && successor.admission_generation > predecessor.admission_generation
                        && successor.admission_generation == op.attestation.admission_generation
                        && successor.key_digest == op.attestation.candidate_key_digest,
                )?;
                let phase = match op.phase {
                    VoterReplacementPhase::Prepared | VoterReplacementPhase::SnapshotInstalled => {
                        VoterSlotPhase::Pending
                    }
                    VoterReplacementPhase::LearnerAdded
                    | VoterReplacementPhase::CaughtUp
                    | VoterReplacementPhase::Fenced => VoterSlotPhase::CatchingUp,
                    VoterReplacementPhase::Joint | VoterReplacementPhase::Uniform => {
                        VoterSlotPhase::Voting
                    }
                };
                require(slot.phase == phase)?;
                if predecessor.identity.incarnation() == op.attestation.expected_incarnation {
                    require(predecessor.descriptor_digest == op.attestation.old_descriptor_digest)?;
                } else {
                    // A supersession reserves the new operation atomically with
                    // the old candidate's bounded terminal receipt.
                    let receipt = slot
                        .last_result
                        .as_ref()
                        .ok_or(VoterSlotError::InvalidRecord)?;
                    require(
                        receipt.incarnation == op.attestation.expected_incarnation
                            && receipt.kind == VoterReplacementResultKind::Superseded
                            && receipt.terminal == op.evidence.prepare,
                    )?;
                }
            } else {
                require(predecessor == successor && slot.phase == VoterSlotPhase::Voting)?;
            }
            require(
                slot.last_result
                    .as_ref()
                    .is_none_or(|r| r.request_id != op.attestation.request_id),
            )?;
        }
        require(found_target)
    }

    /// Validate a newer snapshot against locally retained metadata before install.
    ///
    /// Necessary but not sufficient: the store must also authenticate the snapshot,
    /// verify its committed engine cut, and publish it atomically with application
    /// and membership state. This check supplies no commit or admission proof.
    pub fn validate_successor_of(&self, previous: &Self) -> Result<(), VoterSlotError> {
        self.validate()?;
        previous.validate()?;
        let regression = VoterSlotError::Regression;
        if self.cluster_instance != previous.cluster_instance
            || self.manifest_digest != previous.manifest_digest
            || self.revision < previous.revision
            || self.configuration_epoch < previous.configuration_epoch
            || self.slots.len() != previous.slots.len()
        {
            return Err(regression);
        }
        if self.revision == previous.revision {
            return if self == previous {
                Ok(())
            } else {
                Err(regression)
            };
        }
        for (new, old) in self.slots.iter().zip(&previous.slots) {
            if new.member.identity.slot() != old.member.identity.slot()
                || new.retired_through < old.retired_through
                || new.member.identity.incarnation() < old.member.identity.incarnation()
                || (new.member.identity.incarnation() == old.member.identity.incarnation()
                    && (new.member != old.member || new.phase < old.phase))
                || (new.member.identity.incarnation() > old.member.identity.incarnation()
                    && new.member.admission_generation <= old.member.admission_generation)
            {
                return Err(regression);
            }
            if let Some(old_result) = &old.last_result {
                let result = new.last_result.as_ref().ok_or(regression)?;
                if result.revision < old_result.revision
                    || result.incarnation < old_result.incarnation
                    || result.configuration_epoch < old_result.configuration_epoch
                    || ((result.revision == old_result.revision
                        || result.incarnation == old_result.incarnation)
                        && result != old_result)
                {
                    return Err(regression);
                }
            }
        }
        if let Some(old) = &previous.replacement {
            if let Some(new) = self
                .replacement
                .as_ref()
                .filter(|r| r.attestation.request_id == old.attestation.request_id)
            {
                if new.expected_revision != old.expected_revision
                    || new.attestation != old.attestation
                    || new.predecessor != old.predecessor
                    || new.successor != old.successor
                    || new.phase < old.phase
                    || !new.evidence.retains(&old.evidence, old.phase)
                {
                    return Err(regression);
                }
            } else {
                let slot = self
                    .slots
                    .iter()
                    .find(|s| s.member.identity.slot() == old.attestation.slot)
                    .ok_or(regression)?;
                let old_incarnation = old.attestation.expected_incarnation.next()?;
                let receipt = slot.last_result.as_ref().ok_or(regression)?;
                if receipt.incarnation < old_incarnation
                    || !receipt.terminal.follows(old.evidence.latest(), false)
                    || (old.phase >= VoterReplacementPhase::Fenced
                        && self.configuration_epoch < old.successor.epoch)
                {
                    return Err(regression);
                }
                if receipt.incarnation == old_incarnation {
                    if receipt.request_id != old.attestation.request_id
                        || receipt.request_digest != old.attestation.request_digest
                    {
                        return Err(regression);
                    }
                    if receipt.kind == VoterReplacementResultKind::Completed {
                        if self.configuration_epoch < old.successor.epoch {
                            return Err(regression);
                        }
                    } else if old.phase >= VoterReplacementPhase::Fenced {
                        return Err(regression);
                    }
                }
            }
        }
        Ok(())
    }
}
