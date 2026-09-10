//! Native roster row admission. The canonical V1 and V2 carriers and their
//! cryptographic verifiers are the existing production ones. This module
//! contains no database access and constructs no certificate from a digest.
//!
//! A caller retains only the small projection and derived index facts between
//! reads. Every selected carrier must be hydrated and authenticated against
//! the admitted root, membership interval, floor, cursor and business state.

use super::*;
use serde::{Deserialize, Serialize};

// The native envelope carries the original canonical record unchanged and
// uses its existing descriptor-derived ceiling, not an independent limit.
pub(crate) const MAX_CANONICAL_BYTES: usize = PROTECTED_ROSTER_MAX_CANONICAL_RECORD_BYTES;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Profile {
    V1,
    V2,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum State {
    Live,
    Retained,
    Tombstone,
}

/// Immutable Q1 authority survives compaction without retaining a raw key or
/// admission body. Its fields are authenticated by the original signed frames.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalAuthority {
    pub(super) owner: OwnerId,
    pub(super) fence: u64,
    pub(super) credential_id: u64,
    pub(super) generation: u64,
    pub(super) acquired_at: Timestamp,
    pub(super) expires_at: Timestamp,
}

impl OriginalAuthority {
    pub(crate) fn recovery_parts(&self) -> (&OwnerId, u64, u64) {
        (&self.owner, self.fence, self.generation)
    }

    pub(crate) fn from_authority(authority: &AuthorityBinding) -> Self {
        Self {
            owner: authority.owner().clone(),
            fence: authority.fence().get(),
            credential_id: authority.credential_id(),
            generation: authority.generation().get(),
            acquired_at: authority.acquired_at(),
            expires_at: authority.expires_at(),
        }
    }

    fn validate(&self, profile: Profile) -> Result<(), ProtectedRosterApplyError> {
        if [self.fence, self.credential_id, self.generation]
            .into_iter()
            .any(|value| value == 0 || value > i64::MAX as u64)
            || (profile == Profile::V2 && self.generation != 1)
            || self.acquired_at >= self.expires_at
            || ops::persisted_owner_id(self.owner.as_str().to_owned()).is_err()
        {
            return Err(ProtectedRosterApplyError::Corrupt);
        }
        Ok(())
    }

    pub(crate) fn for_admission(
        &self,
        admission: &Admission,
    ) -> Result<AuthorityBinding, ProtectedRosterApplyError> {
        let authority = AuthorityBinding::from_consensus_parts(
            admission.scope().digest(),
            admission.key().clone(),
            self.owner.clone(),
            FenceToken::new(self.fence),
            AuthorityLeaseMetadata::new(
                self.credential_id,
                Generation::new(self.generation),
                self.acquired_at,
                self.expires_at,
            ),
        )
        .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
        if authority.owner() != admission.logical_owner()
            || authority.fence() != admission.admission_fence()
            || authority.generation() != admission.expected_generation()
        {
            return Err(ProtectedRosterApplyError::Corrupt);
        }
        Ok(authority)
    }

    pub(crate) fn v2_projection(
        &self,
    ) -> Result<ProtectedRosterV2OriginalAuthorityProjection, ProtectedRosterApplyError> {
        self.validate(Profile::V2)?;
        Ok(ProtectedRosterV2OriginalAuthorityProjection {
            owner: self.owner.clone(),
            fence: self.fence,
            credential_id: self.credential_id,
            acquired_at: self.acquired_at,
            expires_at: self.expires_at,
        })
    }
}

/// The two exact request IDs are derived from these full slots. Native storage
/// has no duplicate SQL child rows: the projection and carrier form one row.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Projection {
    pub(crate) profile: Profile,
    pub(crate) stable_slot: [u8; 32],
    pub(crate) terminal_slot: [u8; 32],
    pub(crate) original: OriginalAuthority,
}

impl Projection {
    pub(crate) fn from_admission(
        binding: RequestBindingKey,
        command: &ConsensusRosterAdmissionCommand,
    ) -> Result<Self, ProtectedRosterApplyError> {
        let admission = command.admission();
        let profile = if admission.profile() == crate::fenced_mutation_roster::Profile::v1() {
            Profile::V1
        } else if admission.profile() == crate::fenced_mutation_roster::Profile::v2() {
            Profile::V2
        } else {
            return Err(ProtectedRosterApplyError::Corrupt);
        };
        let original = OriginalAuthority::from_authority(command.authority());
        original.validate(profile)?;
        if original.for_admission(admission)? != *command.authority()
            || admission
                .binding_key(binding.history_epoch())
                .map_err(|_| ProtectedRosterApplyError::Corrupt)?
                != binding
        {
            return Err(ProtectedRosterApplyError::Corrupt);
        }
        let (stable_slot, terminal_slot) = admission_slots(profile, binding, admission)?;
        if command
            .admission_slot()
            .map_err(|_| ProtectedRosterApplyError::Corrupt)?
            != stable_slot
            || command
                .request_id()
                .map_err(|_| ProtectedRosterApplyError::Corrupt)?
                .as_bytes()
                != &protected_roster_request_id(stable_slot)
        {
            return Err(ProtectedRosterApplyError::Corrupt);
        }
        Ok(Self {
            profile,
            stable_slot,
            terminal_slot,
            original,
        })
    }

    pub(crate) fn request_ids(&self) -> [[u8; 16]; 2] {
        [
            protected_roster_request_id(self.stable_slot),
            protected_roster_request_id(self.terminal_slot),
        ]
    }
}

fn admission_slots(
    profile: Profile,
    binding: RequestBindingKey,
    admission: &Admission,
) -> Result<([u8; 32], [u8; 32]), ProtectedRosterApplyError> {
    let stable = match profile {
        Profile::V1 if admission.profile() == crate::fenced_mutation_roster::Profile::v1() => {
            protected_roster_stable_slot(admission.scope(), admission.key(), admission.roster_id())
        }
        Profile::V2 if admission.profile() == crate::fenced_mutation_roster::Profile::v2() => {
            protected_roster_v2_stable_slot(
                admission.scope(),
                admission.key(),
                admission.roster_id(),
            )
        }
        _ => return Err(ProtectedRosterApplyError::Corrupt),
    };
    let terminal = RosterRequestId::bind(binding.history_epoch(), admission)
        .and_then(|request| request.terminal_slot_id(admission))
        .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
    Ok((stable, *terminal.as_bytes()))
}

/// Scalar facts are derived only from a fully authenticated canonical row.
/// They may feed resident indexes, but deserializing them does not certify a row.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Facts {
    pub(crate) state: State,
    pub(crate) terminalized_at: Option<ConsensusMaintenanceTimestamp>,
    pub(crate) terminal_sequence: Option<u64>,
    pub(crate) terminal_raft_log_index: Option<u64>,
}

pub(crate) enum Body {
    V1(Box<HydratedProductionReservationRecord>),
    V2(Box<HydratedProductionReservationRecordV2>),
}

/// Owns the complete hydration and its temporary-allocation reservation. A
/// caller may move the guard with the body; it must never outlive that guard.
pub(crate) struct Hydration {
    pub(crate) projection: Projection,
    pub(crate) facts: Facts,
    body: Body,
    memory: crate::consensus::verified_snapshot::VerificationMemory,
}

impl Hydration {
    pub(crate) fn body(&self) -> &Body {
        &self.body
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Body,
        crate::consensus::verified_snapshot::VerificationMemory,
    ) {
        (self.body, self.memory)
    }

    pub(crate) fn binding(&self) -> RequestBindingKey {
        match &self.body {
            Body::V1(row) => row.record().binding(),
            Body::V2(row) => row.record().binding(),
        }
    }

    pub(crate) fn canonical(&self) -> &[u8] {
        match &self.body {
            Body::V1(row) => row.canonical(),
            Body::V2(row) => row.canonical(),
        }
    }

    pub(crate) fn reserved_key(&self) -> Option<&SessionKey> {
        match &self.body {
            Body::V1(row) => row
                .record()
                .business_reservation()
                .map(|reservation| reservation.expected().key()),
            Body::V2(row) => row
                .record()
                .absence_reservation()
                .map(|reservation| reservation.predicate().key()),
        }
    }

    /// Stable commitments from the original signed provenance/evidence. They
    /// compare lifecycle replacements after complete authentication; neither
    /// value is accepted as a signature or as a row admission certificate.
    pub(crate) fn history_commitments(
        &self,
    ) -> Result<([u8; 32], Option<[u8; 32]>), ProtectedRosterApplyError> {
        let rejected = |_| ProtectedRosterApplyError::Corrupt;
        match &self.body {
            Body::V1(row) => match row.payload() {
                HydratedProductionReservationPayload::Live {
                    admission_provenance,
                    ..
                } => Ok((admission_provenance.commitment().map_err(rejected)?, None)),
                HydratedProductionReservationPayload::Retained {
                    admission_provenance,
                    terminal_evidence,
                    ..
                }
                | HydratedProductionReservationPayload::Tombstone {
                    admission_provenance,
                    terminal_evidence,
                    ..
                } => Ok((
                    admission_provenance.commitment().map_err(rejected)?,
                    Some(terminal_evidence.commitment().map_err(rejected)?),
                )),
                #[cfg(test)]
                HydratedProductionReservationPayload::Legacy => {
                    Err(ProtectedRosterApplyError::Corrupt)
                }
            },
            Body::V2(row) => Ok((
                row.admission_provenance().commitment().map_err(rejected)?,
                row.terminal_evidence()
                    .map(|evidence| evidence.commitment())
                    .transpose()
                    .map_err(rejected)?,
            )),
        }
    }

    pub(crate) fn validate_business(
        &self,
        current: Option<&StoredSessionRecord>,
    ) -> Result<(), ProtectedRosterApplyError> {
        match &self.body {
            Body::V1(row) => {
                if let Some(reservation) = row.record().business_reservation() {
                    let actual = current.ok_or(ProtectedRosterApplyError::Corrupt)?;
                    if ProductionBusinessState::from_authoritative_record(actual)
                        .map_err(|_| ProtectedRosterApplyError::Corrupt)?
                        != *reservation.expected()
                    {
                        return Err(ProtectedRosterApplyError::Corrupt);
                    }
                }
            }
            Body::V2(row) => {
                if row.record().absence_reservation().is_some() && current.is_some() {
                    return Err(ProtectedRosterApplyError::Corrupt);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_partition(
        &self,
        floor: IrreversibleHistoryFloor,
        cursor: Option<&ProductionRetirementCursor>,
    ) -> Result<(), ProtectedRosterApplyError> {
        let binding = self.binding();
        let key = ProductionFloorKey::from_binding(binding)
            .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
        if ProductionFloorKey::from_floor(floor).map_err(|_| ProtectedRosterApplyError::Corrupt)?
            != key
            || floor.validate_new_binding(binding).is_err()
        {
            return Err(ProtectedRosterApplyError::Corrupt);
        }
        if let Some(cursor) = cursor {
            if cursor.key() != key
                || cursor.validate_for_floor(floor).is_err()
                || (binding.history_epoch() <= cursor.target_epoch()
                    && (self.facts.state != State::Tombstone
                        || binding.history_epoch() != cursor.target_epoch()
                        || cursor.last_deleted().is_some_and(|last| binding <= last)))
            {
                return Err(ProtectedRosterApplyError::Corrupt);
            }
        }
        Ok(())
    }

    /// The shared stream validator also detects cross-profile binding and
    /// terminal-sequence aliases and reconstructs the original global charge.
    pub(crate) fn account(
        &self,
        validator: &mut ProductionSnapshotStreamValidator,
        witness: GlobalChargeWitness,
    ) -> Result<(), ProtectedRosterApplyError> {
        match &self.body {
            Body::V1(row) => validator.add_record(
                row.record(),
                self.facts.terminal_raft_log_index,
                witness,
                ChargeProfile::v1(),
            ),
            Body::V2(row) => validator.add_v2_record(
                row.record(),
                self.facts.terminal_raft_log_index,
                witness,
                ChargeProfile::v1(),
            ),
        }
        .map_err(|_| ProtectedRosterApplyError::Corrupt)
    }
}

/// Full recovery/read admission of one carrier. The input owner is charged by
/// its enclosing selected-row reader. Pinned Postcard's Slice sequence hint
/// never advertises a length greater than the remaining actual input, so the
/// original bounded byte visitor cannot preallocate a forged missing extent.
/// Reserve before the canonical decoder:
/// twelve input lengths cover the canonical carrier, bounded component copies,
/// hydrated admission/terminal, recanonicalization, envelope and proof scratch;
/// 64KiB covers the at-most-eight-member scalar/key/cryptographic metadata.
/// The original process-wide verification ceiling is unchanged.
pub(crate) fn hydrate(
    projection: Projection,
    binding: RequestBindingKey,
    canonical: Vec<u8>,
    root: &RosterAttestationTrustRootV1,
    scope: &MembershipValidationScope,
) -> Result<Hydration, ProtectedRosterApplyError> {
    let expected = (projection.stable_slot, projection.terminal_slot);
    let hydrated = hydrate_original(
        projection.profile,
        projection.original,
        binding,
        canonical,
        root,
        scope,
    )?;
    if expected
        != (
            hydrated.projection.stable_slot,
            hydrated.projection.terminal_slot,
        )
    {
        return Err(ProtectedRosterApplyError::Corrupt);
    }
    Ok(hydrated)
}

/// The cold SQL importer has the original authority and stored request IDs,
/// while a native frame also persists the complete terminal slot. Derive both
/// slots through the same signed carrier validators; the importer must compare
/// every SQL child projection against this result before emitting a frame.
/// This constructor grants no ledger, business, or durable install authority.
pub(super) fn hydrate_original(
    profile: Profile,
    original: OriginalAuthority,
    binding: RequestBindingKey,
    canonical: Vec<u8>,
    root: &RosterAttestationTrustRootV1,
    scope: &MembershipValidationScope,
) -> Result<Hydration, ProtectedRosterApplyError> {
    if canonical.is_empty() || canonical.len() > PROTECTED_ROSTER_MAX_CANONICAL_RECORD_BYTES {
        return Err(ProtectedRosterApplyError::Corrupt);
    }
    let bytes = canonical
        .len()
        .checked_mul(12)
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .ok_or(ProtectedRosterApplyError::Corrupt)?;
    let memory = crate::consensus::verified_snapshot::VerificationMemory::reserve(bytes)
        .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
    original.validate(profile)?;
    let (body, facts, slots) = match profile {
        Profile::V1 => {
            let row = ProductionReservationRecord::from_canonical_vec_hydrated(canonical)
                .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
            if row.record().binding() != binding {
                return Err(ProtectedRosterApplyError::Corrupt);
            }
            let (slots, terminal_raft_log_index) = match row.payload() {
                HydratedProductionReservationPayload::Live { admission, .. }
                | HydratedProductionReservationPayload::Retained { admission, .. } => {
                    let original = original.for_admission(admission)?;
                    validate_hydrated_protected_roster_attestations_sync(
                        root,
                        scope,
                        binding,
                        row.payload(),
                        &original,
                    )?;
                    let terminal = match row.payload() {
                        HydratedProductionReservationPayload::Retained {
                            committed_terminal,
                            ..
                        } => Some(committed_terminal.commit_metadata().raft_log_index()),
                        _ => None,
                    };
                    (admission_slots(Profile::V1, binding, admission)?, terminal)
                }
                HydratedProductionReservationPayload::Tombstone {
                    tombstone,
                    admission_provenance,
                    terminal_evidence,
                    ..
                } => {
                    validate_roster_admission_attestation_identity_interval(
                        scope,
                        binding,
                        admission_provenance.configuration_identity(),
                    )?;
                    validate_roster_tombstone_terminal_attestation_identity_interval(
                        scope,
                        terminal_evidence.configuration_identity(),
                        tombstone,
                    )?;
                    let original = &original;
                    let slots = verify_compacted_tombstone_history_v2(
                        CompactedTombstoneHistoryVerificationV2 {
                            root,
                            configuration_identity: terminal_evidence.configuration_identity(),
                            logical_time: row
                                .record()
                                .terminalized_at()
                                .ok_or(ProtectedRosterApplyError::Corrupt)?
                                .to_consensus_timestamp()
                                .map_err(|_| ProtectedRosterApplyError::Corrupt)?,
                            binding,
                            tombstone,
                            admission_provenance,
                            terminal_evidence,
                            original_owner: &original.owner,
                            original_fence: original.fence,
                            original_credential_id: original.credential_id,
                            original_generation: original.generation,
                            original_acquired_at: original.acquired_at,
                            original_expires_at: original.expires_at,
                        },
                    )
                    .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
                    (
                        (slots.stable_slot(), slots.terminal_slot()),
                        Some(tombstone.terminal_raft_log_index()),
                    )
                }
                // Unsigned historical test carriers are never a native format.
                #[cfg(test)]
                HydratedProductionReservationPayload::Legacy => {
                    return Err(ProtectedRosterApplyError::Corrupt)
                }
            };
            let record = row.record();
            let facts = Facts {
                state: match record.state() {
                    ReservationState::Live => State::Live,
                    ReservationState::Retained => State::Retained,
                    ReservationState::Tombstone => State::Tombstone,
                },
                terminalized_at: record.terminalized_at(),
                terminal_sequence: record.terminal_sequence(),
                terminal_raft_log_index,
            };
            (Body::V1(Box::new(row)), facts, slots)
        }
        Profile::V2 => {
            let row = ProductionReservationRecordV2::from_canonical_vec_hydrated(canonical)
                .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
            if row.record().binding() != binding {
                return Err(ProtectedRosterApplyError::Corrupt);
            }
            let (slots, terminal_raft_log_index) =
                if row.record().state() == ProductionReservationStateV2::Tombstone {
                    let original = original.v2_projection()?;
                    let slots = validate_hydrated_protected_roster_v2_compacted_sync(
                        root, scope, binding, &row, &original,
                    )?;
                    (
                        (slots.stable_slot(), slots.terminal_slot()),
                        Some(
                            row.tombstone()
                                .ok_or(ProtectedRosterApplyError::Corrupt)?
                                .terminal_raft_log_index(),
                        ),
                    )
                } else {
                    let admission = row.admission().ok_or(ProtectedRosterApplyError::Corrupt)?;
                    let original = original.for_admission(admission)?;
                    validate_hydrated_protected_roster_v2_attestations_sync(
                        root, scope, binding, &row, &original,
                    )?;
                    (
                        admission_slots(Profile::V2, binding, admission)?,
                        row.committed_terminal()
                            .map(|terminal| terminal.commit_metadata().raft_log_index()),
                    )
                };
            let record = row.record();
            let facts = Facts {
                state: match record.state() {
                    ProductionReservationStateV2::Live => State::Live,
                    ProductionReservationStateV2::Retained => State::Retained,
                    ProductionReservationStateV2::Tombstone => State::Tombstone,
                },
                terminalized_at: record.terminalized_at(),
                terminal_sequence: record.terminal_sequence(),
                terminal_raft_log_index,
            };
            (Body::V2(Box::new(row)), facts, slots)
        }
    };
    let projection = Projection {
        profile,
        stable_slot: slots.0,
        terminal_slot: slots.1,
        original,
    };
    Ok(Hydration {
        projection,
        facts,
        body,
        memory,
    })
}

#[cfg(test)]
#[path = "roster_rows_tests.rs"]
pub(crate) mod tests;
