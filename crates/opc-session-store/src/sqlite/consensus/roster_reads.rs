//! Original public roster read decisions shared by SQL and native storage.
//! Callers supply one immutable predecessor and its independently admitted
//! authority. The evaluator cannot write through this borrowed adapter.

use super::roster_engine::RosterCommandStore;
use super::*;

fn protected_roster_read_result_sync(
    store: &(impl RosterCommandStore + ?Sized),
    hydrated: HydratedProductionReservationRecord,
    original_authority: AuthorityBinding,
    current_authority: &AuthorityBinding,
    logical_time: Timestamp,
    mode: ProtectedRosterReadAuthorityMode,
) -> Result<ProtectedRosterReadResult, ProtectedRosterApplyError> {
    let (record, _canonical, payload) = hydrated.into_parts();
    match (record.state(), payload) {
        (
            ReservationState::Live,
            HydratedProductionReservationPayload::Live {
                admission,
                admission_provenance,
                ..
            },
        ) => {
            roster_engine::validate_current_authority(
                store,
                &admission,
                &original_authority,
                current_authority,
                logical_time,
                false,
            )?;
            if matches!(mode, ProtectedRosterReadAuthorityMode::StrictSuccessor)
                && current_authority.fence() <= original_authority.fence()
            {
                return Err(ProtectedRosterApplyError::Rejected);
            }
            Ok(ProtectedRosterReadResult::Admitted(Box::new(
                ProtectedRosterLiveRead {
                    registration: protected_roster_registration(record.binding(), &admission)?,
                    admission: admission.clone(),
                    admission_provenance,
                },
            )))
        }
        (
            ReservationState::Retained,
            HydratedProductionReservationPayload::Retained {
                admission,
                admission_provenance,
                committed_terminal,
                committed_canonical,
                ..
            },
        ) => {
            roster_engine::validate_current_authority(
                store,
                &admission,
                &original_authority,
                current_authority,
                logical_time,
                false,
            )?;
            if matches!(mode, ProtectedRosterReadAuthorityMode::StrictSuccessor)
                && current_authority.fence() <= original_authority.fence()
            {
                return Err(ProtectedRosterApplyError::Rejected);
            }
            Ok(ProtectedRosterReadResult::Terminalized(Box::new(
                ProtectedRosterTerminalRead {
                    registration: protected_roster_registration(record.binding(), &admission)?,
                    admission: admission.clone(),
                    admission_provenance,
                    committed: *committed_terminal,
                    committed_canonical,
                },
            )))
        }
        (
            ReservationState::Tombstone,
            HydratedProductionReservationPayload::Tombstone { tombstone, .. },
        ) => {
            store.validate_live_authority(
                current_authority,
                Some(original_authority.generation()),
                logical_time,
            )?;
            let allowed = match mode {
                ProtectedRosterReadAuthorityMode::StrictSuccessor => {
                    current_authority.fence() > original_authority.fence()
                }
                ProtectedRosterReadAuthorityMode::OriginalOrSuccessor => {
                    current_authority == &original_authority
                        || current_authority.fence() > original_authority.fence()
                }
            };
            if !allowed {
                return Err(ProtectedRosterApplyError::Rejected);
            }
            Ok(ProtectedRosterReadResult::Compacted {
                history_epoch: record.binding().history_epoch(),
                tombstone: Box::new(tombstone),
            })
        }
        _ => Err(ProtectedRosterApplyError::Corrupt),
    }
}

fn protected_roster_v2_read_result_sync(
    store: &(impl RosterCommandStore + ?Sized),
    identity: SessionConsensusIdentity,
    hydrated: HydratedProductionReservationRecordV2,
    current_authority: &AuthorityBinding,
    logical_time: Timestamp,
    mode: ProtectedRosterReadAuthorityMode,
) -> Result<ProtectedRosterV2ReadResult, ProtectedRosterApplyError> {
    let record = hydrated.record();
    if record.state() == ProductionReservationStateV2::Tombstone {
        store.validate_live_authority(current_authority, Some(Generation::new(1)), logical_time)?;
        let original = store.original_projection_v2(identity, record.binding())?;
        let same_original = current_authority.fence().get() == original.fence
            && current_authority.owner() == &original.owner
            && current_authority.credential_id() == original.credential_id
            && current_authority.generation() == Generation::new(1)
            && current_authority.acquired_at() == original.acquired_at
            && current_authority.expires_at() == original.expires_at;
        let allowed = match mode {
            ProtectedRosterReadAuthorityMode::StrictSuccessor => {
                current_authority.fence().get() > original.fence
            }
            ProtectedRosterReadAuthorityMode::OriginalOrSuccessor => {
                same_original || current_authority.fence().get() > original.fence
            }
        };
        if !allowed {
            return Err(ProtectedRosterApplyError::Rejected);
        }
        let root = store
            .trust_root()
            .map_err(|_| ProtectedRosterApplyError::Corrupt)?
            .ok_or(ProtectedRosterApplyError::Corrupt)?;
        let membership_scope = store
            .membership_scope(identity)
            .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
        validate_hydrated_protected_roster_v2_compacted_sync(
            &root,
            &membership_scope,
            record.binding(),
            &hydrated,
            &original,
        )?;
        return Ok(ProtectedRosterV2ReadResult::Compacted {
            history_epoch: record.binding().history_epoch(),
            tombstone: Box::new(
                hydrated
                    .tombstone()
                    .ok_or(ProtectedRosterApplyError::Corrupt)?
                    .clone(),
            ),
        });
    }
    let admission = hydrated
        .admission()
        .ok_or(ProtectedRosterApplyError::Corrupt)?;
    if admission.profile() != crate::fenced_mutation_roster::Profile::v2() {
        return Err(ProtectedRosterApplyError::Corrupt);
    }
    let original = store.original_authority_v2(identity, record.binding(), admission)?;
    store.validate_live_authority(
        current_authority,
        Some(admission.expected_generation()),
        logical_time,
    )?;
    let allowed = match mode {
        ProtectedRosterReadAuthorityMode::StrictSuccessor => {
            current_authority.fence() > original.fence()
        }
        ProtectedRosterReadAuthorityMode::OriginalOrSuccessor => {
            current_authority == &original || current_authority.fence() > original.fence()
        }
    };
    if !allowed {
        return Err(ProtectedRosterApplyError::Rejected);
    }
    roster_engine::validate_current_authority(
        store,
        admission,
        &original,
        current_authority,
        logical_time,
        false,
    )?;
    #[cfg(any(test, feature = "test-control"))]
    record_protected_roster_v2_terminal_status_validation_stage(
        &PROTECTED_ROSTER_V2_TERMINAL_STATUS_VALIDATION_STAGES.authority_verified,
    );
    let registration = BackendRegistration::from_consensus_parts(
        roster_registration_handle(record.binding()),
        RosterRequestId::bind(record.binding().history_epoch(), admission)
            .map_err(|_| ProtectedRosterApplyError::Corrupt)?,
        admission,
    )
    .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
    let root = store
        .trust_root()
        .map_err(|_| ProtectedRosterApplyError::Corrupt)?
        .ok_or(ProtectedRosterApplyError::Corrupt)?;
    let membership_scope = store
        .membership_scope(identity)
        .map_err(|_| ProtectedRosterApplyError::Corrupt)?;
    validate_hydrated_protected_roster_v2_attestations_sync(
        &root,
        &membership_scope,
        record.binding(),
        &hydrated,
        &original,
    )?;
    match record.state() {
        ProductionReservationStateV2::Live => {
            if record.absence_reservation().is_none() {
                return Err(ProtectedRosterApplyError::Corrupt);
            }
            Ok(ProtectedRosterV2ReadResult::Admitted(Box::new(
                ProtectedRosterV2LiveRead {
                    admission: admission.clone(),
                    admission_provenance: hydrated.admission_provenance().clone(),
                    registration,
                },
            )))
        }
        ProductionReservationStateV2::Retained => {
            if record.absence_reservation().is_some() {
                return Err(ProtectedRosterApplyError::Corrupt);
            }
            let committed_canonical = hydrated
                .committed_canonical()
                .ok_or(ProtectedRosterApplyError::Corrupt)?
                .to_vec();
            let committed = hydrated
                .committed_terminal()
                .ok_or(ProtectedRosterApplyError::Corrupt)?
                .clone();
            #[cfg(any(test, feature = "test-control"))]
            record_protected_roster_v2_terminal_status_validation_stage(
                &PROTECTED_ROSTER_V2_TERMINAL_STATUS_VALIDATION_STAGES.retained_shape_verified,
            );
            Ok(ProtectedRosterV2ReadResult::Terminalized(Box::new(
                ProtectedRosterV2TerminalRead {
                    admission: admission.clone(),
                    admission_provenance: hydrated.admission_provenance().clone(),
                    registration,
                    committed,
                    committed_canonical,
                },
            )))
        }
        ProductionReservationStateV2::Tombstone => Err(ProtectedRosterApplyError::Corrupt),
    }
}

pub(crate) fn read_protected_roster_v2_admission_status_sync(
    store: &(impl RosterCommandStore + ?Sized),
    identity: SessionConsensusIdentity,
    admission: &Admission,
    current_authority: &AuthorityBinding,
    logical_time: Timestamp,
) -> Result<ProtectedRosterV2ReadResult, StoreError> {
    if admission.profile() != crate::fenced_mutation_roster::Profile::v2()
        || current_authority.scope() != admission.scope()
        || current_authority.key() != admission.key()
        || current_authority.generation() != admission.expected_generation()
        || current_authority.fence() < admission.admission_fence()
    {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    store
        .validate_live_authority(current_authority, Some(Generation::new(1)), logical_time)
        .map_err(ProtectedRosterApplyError::store_error)?;
    let slot =
        protected_roster_v2_stable_slot(admission.scope(), admission.key(), admission.roster_id());
    let Some(binding) = store
        .stable_slot_v2(slot)
        .map_err(ProtectedRosterApplyError::store_error)?
    else {
        return Ok(ProtectedRosterV2ReadResult::Missing);
    };
    let record = store
        .record_v2(identity, binding)
        .map_err(ProtectedRosterApplyError::store_error)?
        .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
    store
        .authenticate_record_v2(identity, binding, &record)
        .map_err(ProtectedRosterApplyError::store_error)?;
    if record.record().state() == ProductionReservationStateV2::Tombstone {
        record
            .tombstone()
            .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?
            .validate_admission_for_profile(
                crate::fenced_mutation_roster::Profile::v2(),
                binding.history_epoch(),
                admission,
            )
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
    } else if record.admission() != Some(admission) {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    protected_roster_v2_read_result_sync(
        store,
        identity,
        record,
        current_authority,
        logical_time,
        ProtectedRosterReadAuthorityMode::OriginalOrSuccessor,
    )
    .map_err(ProtectedRosterApplyError::store_error)
}

pub(crate) fn read_protected_roster_v2_recovery_sync(
    store: &(impl RosterCommandStore + ?Sized),
    identity: SessionConsensusIdentity,
    recovery: &RecoveryRequest,
    logical_time: Timestamp,
) -> Result<ProtectedRosterV2ReadResult, StoreError> {
    let current = recovery.authority();
    if current.ingress_scope() != recovery.lookup().scope()
        || current.fence() <= recovery.original_admission_fence()
    {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    store
        .validate_live_authority(current, Some(Generation::new(1)), logical_time)
        .map_err(ProtectedRosterApplyError::store_error)?;
    let slot = protected_roster_v2_stable_slot(
        recovery.lookup().scope(),
        current.key(),
        recovery.lookup().roster_id(),
    );
    let Some(binding) = store
        .stable_slot_v2(slot)
        .map_err(ProtectedRosterApplyError::store_error)?
    else {
        return Ok(ProtectedRosterV2ReadResult::Missing);
    };
    let record = store
        .record_v2(identity, binding)
        .map_err(ProtectedRosterApplyError::store_error)?
        .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
    store
        .authenticate_record_v2(identity, binding, &record)
        .map_err(ProtectedRosterApplyError::store_error)?;
    if record.record().state() == ProductionReservationStateV2::Tombstone {
        record
            .tombstone()
            .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?
            .validate_lookup_for_profile(
                crate::fenced_mutation_roster::Profile::v2(),
                recovery.compacted_terminal_lookup(binding.history_epoch()),
            )
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
        return protected_roster_v2_read_result_sync(
            store,
            identity,
            record,
            current,
            logical_time,
            ProtectedRosterReadAuthorityMode::StrictSuccessor,
        )
        .map_err(ProtectedRosterApplyError::store_error);
    }
    let admission = record
        .admission()
        .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
    let original = store
        .original_authority_v2(identity, binding, admission)
        .map_err(ProtectedRosterApplyError::store_error)?;
    if admission.scope() != recovery.lookup().scope()
        || admission.key() != current.key()
        || admission.roster_id() != recovery.lookup().roster_id()
        || original.owner() != recovery.original_owner()
        || original.fence() != recovery.original_admission_fence()
    {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    protected_roster_v2_read_result_sync(
        store,
        identity,
        record,
        current,
        logical_time,
        ProtectedRosterReadAuthorityMode::StrictSuccessor,
    )
    .map_err(ProtectedRosterApplyError::store_error)
}

pub(crate) fn read_protected_roster_v2_terminal_status_sync(
    store: &(impl RosterCommandStore + ?Sized),
    identity: SessionConsensusIdentity,
    binding: RequestBindingKey,
    request: ProtectedRosterV2TerminalStatusRequest<'_>,
) -> Result<ProtectedRosterV2ReadResult, StoreError> {
    let ProtectedRosterV2TerminalStatusRequest {
        registration_parts,
        current_authority,
        terminal_body_commitment,
        terminal_evidence,
        logical_time,
    } = request;
    protected_roster_validate_binding_authority_before_lookup(binding, current_authority)
        .map_err(ProtectedRosterApplyError::store_error)?;
    let (registration_handle, registration_request_id, registration_terminal_slot) =
        registration_parts;
    if registration_handle != roster_registration_handle(binding)
        || registration_terminal_slot == [0; 32]
        || registration_request_id.history_epoch() != binding.history_epoch()
    {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    store
        .validate_live_authority(current_authority, Some(Generation::new(1)), logical_time)
        .map_err(ProtectedRosterApplyError::store_error)?;
    let record = store
        .record_v2(identity, binding)
        .map_err(ProtectedRosterApplyError::store_error)?;
    let Some(record) = record else {
        return Ok(ProtectedRosterV2ReadResult::Missing);
    };
    store
        .authenticate_record_v2(identity, binding, &record)
        .map_err(ProtectedRosterApplyError::store_error)?;
    #[cfg(any(test, feature = "test-control"))]
    record_protected_roster_v2_terminal_status_validation_stage(
        &PROTECTED_ROSTER_V2_TERMINAL_STATUS_VALIDATION_STAGES.record_decoded,
    );
    if record.record().state() == ProductionReservationStateV2::Tombstone {
        let tombstone = record
            .tombstone()
            .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
        let stored_evidence = record
            .terminal_evidence()
            .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
        // The compact carrier retains Q2's operation-four ingress, whereas
        // this status request is authenticated with a fresh operation-five
        // ingress.  Compare only the immutable provenance and generic compact
        // terminal evidence, exactly as retained status does; the caller's
        // fresh status capsule is authenticated independently.
        let stored_provenance = stored_evidence
            .provenance()
            .canonical_bytes()
            .map_err(|_| ProtectedRosterApplyError::Corrupt.store_error())?;
        let incoming_provenance = terminal_evidence
            .provenance()
            .canonical_bytes()
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
        let stored_compact = stored_evidence
            .evidence()
            .canonical_bytes()
            .map_err(|_| ProtectedRosterApplyError::Corrupt.store_error())?;
        let incoming_compact = terminal_evidence
            .evidence()
            .canonical_bytes()
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
        if stored_provenance != incoming_provenance || stored_compact != incoming_compact {
            return Err(ProtectedRosterApplyError::Rejected.store_error());
        }
        tombstone
            .validate_compacted_terminal_for_profile(CompactedTerminalValidation {
                profile: crate::fenced_mutation_roster::Profile::v2(),
                binding,
                request_id: registration_request_id,
                terminal_slot: registration_terminal_slot,
                current_fence: current_authority.fence(),
                current_generation: current_authority.generation(),
                terminal_body_commitment,
            })
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
        return protected_roster_v2_read_result_sync(
            store,
            identity,
            record,
            current_authority,
            logical_time,
            ProtectedRosterReadAuthorityMode::OriginalOrSuccessor,
        )
        .map_err(ProtectedRosterApplyError::store_error);
    }
    let admission = record
        .admission()
        .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
    let registration = BackendRegistration::from_consensus_parts(
        registration_handle,
        registration_request_id,
        admission,
    )
    .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
    if registration.consensus_parts().2.as_bytes() != &registration_terminal_slot {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    if record.record().state() == ProductionReservationStateV2::Retained {
        let committed = record
            .committed_terminal()
            .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
        let retained = record
            .terminal_evidence()
            .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
        // Status ingress is freshly issued for operation five; it must not be
        // byte-equal to the terminalize ingress retained in Q2.  The caller
        // authenticates that fresh V2 ingress against this exact status
        // capsule before this read. Here we compare only the immutable
        // admission provenance and generic compact terminal evidence that
        // identify the retained terminal body without leaking an oracle.
        let retained_provenance = retained
            .provenance()
            .canonical_bytes()
            .map_err(|_| ProtectedRosterApplyError::Corrupt.store_error())?;
        let incoming_provenance = terminal_evidence
            .provenance()
            .canonical_bytes()
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
        let retained_compact = retained
            .evidence()
            .canonical_bytes()
            .map_err(|_| ProtectedRosterApplyError::Corrupt.store_error())?;
        let incoming_compact = terminal_evidence
            .evidence()
            .canonical_bytes()
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
        if committed.record().body_commitment() != terminal_body_commitment
            || retained_provenance != incoming_provenance
            || retained_compact != incoming_compact
        {
            return Err(ProtectedRosterApplyError::Rejected.store_error());
        }
        #[cfg(any(test, feature = "test-control"))]
        record_protected_roster_v2_terminal_status_validation_stage(
            &PROTECTED_ROSTER_V2_TERMINAL_STATUS_VALIDATION_STAGES.retained_evidence_invariant,
        );
    }
    protected_roster_v2_read_result_sync(
        store,
        identity,
        record,
        current_authority,
        logical_time,
        ProtectedRosterReadAuthorityMode::OriginalOrSuccessor,
    )
    .map_err(ProtectedRosterApplyError::store_error)
}

pub(crate) fn read_protected_roster_admission_status_sync(
    store: &(impl RosterCommandStore + ?Sized),
    identity: SessionConsensusIdentity,
    admission: &Admission,
    current_authority: &AuthorityBinding,
    logical_time: Timestamp,
) -> Result<ProtectedRosterReadResult, StoreError> {
    // Preserve the pre-lookup scope/key defense: a valid lease for a
    // different session must not turn Missing into an existence oracle.
    if current_authority.scope() != admission.scope()
        || current_authority.key() != admission.key()
        || current_authority.generation() != admission.expected_generation()
        || current_authority.fence() < admission.admission_fence()
    {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    store
        .validate_live_authority(
            current_authority,
            Some(admission.expected_generation()),
            logical_time,
        )
        .map_err(ProtectedRosterApplyError::store_error)?;
    let slot =
        protected_roster_stable_slot(admission.scope(), admission.key(), admission.roster_id());
    let Some(binding) = store
        .stable_slot_v1(slot)
        .map_err(ProtectedRosterApplyError::store_error)?
    else {
        return Ok(ProtectedRosterReadResult::Missing);
    };
    let hydrated = store
        .record_v1(identity, binding)
        .map_err(ProtectedRosterApplyError::store_error)?
        .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
    let original = store
        .original_authority_v1(identity, binding, admission)
        .map_err(ProtectedRosterApplyError::store_error)?;
    match hydrated.payload() {
        HydratedProductionReservationPayload::Tombstone { tombstone, .. } => {
            roster_engine::validate_current_authority(
                store,
                admission,
                &original,
                current_authority,
                logical_time,
                false,
            )
            .map_err(ProtectedRosterApplyError::store_error)?;
            tombstone
                .validate_admission(binding.history_epoch(), admission)
                .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
            Ok(ProtectedRosterReadResult::Compacted {
                history_epoch: binding.history_epoch(),
                tombstone: Box::new(tombstone.clone()),
            })
        }
        HydratedProductionReservationPayload::Live {
            admission: stored_admission,
            ..
        }
        | HydratedProductionReservationPayload::Retained {
            admission: stored_admission,
            ..
        } if stored_admission == admission => protected_roster_read_result_sync(
            store,
            hydrated,
            original,
            current_authority,
            logical_time,
            // The admission and stored provenance remain exact and immutable,
            // while the execution lease may be the original live authority or
            // an authenticated strictly higher-fence successor.
            ProtectedRosterReadAuthorityMode::OriginalOrSuccessor,
        )
        .map_err(ProtectedRosterApplyError::store_error),
        _ => Err(ProtectedRosterApplyError::Rejected.store_error()),
    }
}

pub(crate) fn read_protected_roster_recovery_sync(
    store: &(impl RosterCommandStore + ?Sized),
    identity: SessionConsensusIdentity,
    recovery: &RecoveryRequest,
    logical_time: Timestamp,
) -> Result<ProtectedRosterReadResult, StoreError> {
    let current = recovery.authority();
    if current.ingress_scope() != recovery.lookup().scope() {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    store
        .validate_live_authority(current, None, logical_time)
        .map_err(ProtectedRosterApplyError::store_error)?;
    if current.fence() <= recovery.original_admission_fence() {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    let Some(binding) = store
        .original_binding_v1(
            current.key(),
            recovery.lookup().roster_id(),
            recovery.original_owner(),
            recovery.original_admission_fence(),
            current.generation(),
        )
        .map_err(ProtectedRosterApplyError::store_error)?
    else {
        return Ok(ProtectedRosterReadResult::Missing);
    };
    let hydrated = store
        .record_v1(identity, binding)
        .map_err(ProtectedRosterApplyError::store_error)?
        .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
    if let HydratedProductionReservationPayload::Tombstone { tombstone, .. } = hydrated.payload() {
        tombstone
            .validate_lookup(recovery.compacted_terminal_lookup(binding.history_epoch()))
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
        return Ok(ProtectedRosterReadResult::Compacted {
            history_epoch: binding.history_epoch(),
            tombstone: Box::new(tombstone.clone()),
        });
    }
    let admission = hydrated
        .record()
        .admission()
        .map_err(|_| ProtectedRosterApplyError::Corrupt.store_error())?;
    let current = AuthorityBinding::for_validated_admission(&admission, current, true)
        .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
    let original = store
        .original_authority_v1(identity, binding, &admission)
        .map_err(ProtectedRosterApplyError::store_error)?;
    if original.owner() != recovery.original_owner()
        || original.fence() != recovery.original_admission_fence()
        || original.generation() != current.generation()
    {
        return Err(ProtectedRosterApplyError::Corrupt.store_error());
    }
    protected_roster_read_result_sync(
        store,
        hydrated,
        original,
        &current,
        logical_time,
        ProtectedRosterReadAuthorityMode::StrictSuccessor,
    )
    .map_err(ProtectedRosterApplyError::store_error)
}

pub(crate) fn read_protected_roster_terminal_status_sync(
    store: &(impl RosterCommandStore + ?Sized),
    identity: SessionConsensusIdentity,
    binding: RequestBindingKey,
    request: ProtectedRosterTerminalStatusRequest<'_>,
) -> Result<ProtectedRosterReadResult, StoreError> {
    let ProtectedRosterTerminalStatusRequest {
        registration_parts,
        current_authority,
        terminal_body_commitment,
        terminal_evidence,
        logical_time,
    } = request;
    let (_scope, _roster_id) =
        protected_roster_validate_binding_authority_before_lookup(binding, current_authority)
            .map_err(ProtectedRosterApplyError::store_error)?;
    let (registration_handle, registration_request_id, registration_terminal_slot) =
        registration_parts;
    if registration_handle != roster_registration_handle(binding)
        || registration_terminal_slot == [0; 32]
        || registration_request_id.history_epoch() != binding.history_epoch()
    {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    store
        .validate_live_authority(current_authority, None, logical_time)
        .map_err(ProtectedRosterApplyError::store_error)?;
    let Some(hydrated) = store
        .record_v1(identity, binding)
        .map_err(ProtectedRosterApplyError::store_error)?
    else {
        return Ok(ProtectedRosterReadResult::Missing);
    };
    if let HydratedProductionReservationPayload::Tombstone {
        tombstone,
        terminal_evidence: stored_evidence,
        ..
    } = hydrated.payload()
    {
        if stored_evidence != terminal_evidence {
            return Err(ProtectedRosterApplyError::Rejected.store_error());
        }
        tombstone
            .validate_compacted_terminal(
                binding,
                registration_request_id,
                registration_terminal_slot,
                current_authority.fence(),
                current_authority.generation(),
                terminal_body_commitment,
            )
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
        return Ok(ProtectedRosterReadResult::Compacted {
            history_epoch: binding.history_epoch(),
            tombstone: Box::new(tombstone.clone()),
        });
    }
    let admission = hydrated
        .record()
        .admission()
        .map_err(|_| ProtectedRosterApplyError::Corrupt.store_error())?;
    let resolved_authority =
        AuthorityBinding::for_validated_admission(&admission, current_authority, false)
            .map_err(|_| ProtectedRosterApplyError::Rejected.store_error())?;
    let expected_registration = protected_roster_registration(binding, &admission)
        .map_err(ProtectedRosterApplyError::store_error)?;
    let (expected_handle, expected_request_id, expected_terminal_slot) =
        expected_registration.consensus_parts();
    if expected_handle != registration_handle
        || expected_request_id != registration_request_id
        || expected_terminal_slot.as_bytes() != &registration_terminal_slot
    {
        return Err(ProtectedRosterApplyError::Rejected.store_error());
    }
    if let HydratedProductionReservationPayload::Retained {
        committed_terminal,
        terminal_evidence: stored_evidence,
        ..
    } = hydrated.payload()
    {
        if committed_terminal.record().body_commitment() != terminal_body_commitment
            || stored_evidence != terminal_evidence
        {
            return Err(ProtectedRosterApplyError::Rejected.store_error());
        }
    }
    let original = store
        .original_authority_v1(identity, binding, &admission)
        .map_err(ProtectedRosterApplyError::store_error)?;
    protected_roster_read_result_sync(
        store,
        hydrated,
        original,
        &resolved_authority,
        logical_time,
        ProtectedRosterReadAuthorityMode::OriginalOrSuccessor,
    )
    .map_err(ProtectedRosterApplyError::store_error)
}

pub(crate) fn read_protected_roster_current_publication_authority_sync(
    store: &(impl RosterCommandStore + ?Sized),
    identity: SessionConsensusIdentity,
    request: &crate::consumer::SessionConsumerRosterCurrentPublicationAuthorityCapsule,
    logical_time: Timestamp,
) -> Result<(), StoreError> {
    let reject = || ProtectedRosterApplyError::Rejected.store_error();
    let roster_id = RosterId::from_bytes(request.roster_id()).map_err(|_| reject())?;
    let raw_current = AuthorityBinding::from_consensus_parts(
        request.scope(),
        request.key().clone(),
        request.current_owner().clone(),
        request.current_fence(),
        AuthorityLeaseMetadata::new(
            request.current_credential_id(),
            request.current_generation(),
            request.current_lease_acquired_at(),
            request.current_lease_expires_at(),
        ),
    )
    .map_err(|_| reject())?;

    // Reject a stale or expired same-key guard before resolving any durable
    // roster lineage. Besides fencing publication, this keeps the
    // redacted rejection from becoming a retained-roster existence oracle.
    store
        .validate_live_authority(
            &raw_current,
            Some(request.current_generation()),
            logical_time,
        )
        .map_err(ProtectedRosterApplyError::store_error)?;

    // Resolve immutable admission scope only from durable lineage. The
    // authenticated current ingress scope can differ after a configuration
    // successor takes over, and must never be accepted as historical scope.
    let binding = store
        .original_binding_v1(
            request.key(),
            roster_id,
            request.logical_owner(),
            request.admission_fence(),
            request.current_generation(),
        )
        .map_err(ProtectedRosterApplyError::store_error)?
        .ok_or_else(reject)?;
    let (admission_scope, bound_roster_id) =
        protected_roster_validate_binding_authority_before_lookup(binding, &raw_current)
            .map_err(ProtectedRosterApplyError::store_error)?;
    if bound_roster_id != roster_id {
        return Err(reject());
    }

    let hydrated = store
        .record_v1(identity, binding)
        .map_err(ProtectedRosterApplyError::store_error)?;
    let hydrated = hydrated.ok_or_else(reject)?;
    let (admission, committed) = match hydrated.payload() {
        HydratedProductionReservationPayload::Retained {
            admission,
            committed_terminal,
            ..
        } => (admission, committed_terminal),
        // Live, Aborted, and compacted state can never mint or preserve
        // publication eligibility.
        _ => return Err(reject()),
    };
    if admission.scope() != admission_scope
        || admission.key() != request.key()
        || admission.roster_id() != roster_id
        || admission.body_commitment() != request.admission_commitment()
        || admission.logical_owner() != request.logical_owner()
        || admission.admission_fence() != request.admission_fence()
        || admission.expected_generation() != request.current_generation()
    {
        return Err(reject());
    }
    let current = AuthorityBinding::for_validated_admission(admission, &raw_current, false)
        .map_err(|_| reject())?;

    let expected_registration = protected_roster_registration(binding, admission)
        .map_err(ProtectedRosterApplyError::store_error)?;
    let (registration_handle, registration_request_id, registration_terminal_slot) =
        expected_registration.consensus_parts();
    if registration_handle != request.registration_handle()
        || registration_request_id.to_bytes() != request.registration_request_id()
        || registration_terminal_slot.as_bytes() != &request.registration_terminal_slot()
    {
        return Err(reject());
    }

    // The hydrated retained terminal has already passed its canonical receipt
    // validation. Require its Established phase and both immutable
    // commitments so a body/receipt from any other terminal cannot publish.
    if committed.record().phase().map_err(|_| reject())?
        != crate::fenced_mutation_roster::Phase::Established
        || committed.record().body_commitment() != request.terminal_body_commitment()
        || committed.receipt_commitment() != request.receipt_commitment()
    {
        return Err(reject());
    }

    let original = store
        .original_authority_v1(identity, binding, admission)
        .map_err(ProtectedRosterApplyError::store_error)?;
    roster_engine::validate_current_authority(
        store,
        admission,
        &original,
        &current,
        logical_time,
        false,
    )
    .map_err(ProtectedRosterApplyError::store_error)
}

pub(crate) fn read_protected_roster_v2_current_publication_authority_sync(
    store: &(impl RosterCommandStore + ?Sized),
    identity: SessionConsensusIdentity,
    request: &crate::consumer::SessionConsumerRosterCurrentPublicationAuthorityCapsule,
    logical_time: Timestamp,
) -> Result<(), StoreError> {
    let reject = || ProtectedRosterApplyError::Rejected.store_error();
    let roster_id = RosterId::from_bytes(request.roster_id()).map_err(|_| reject())?;
    let current = AuthorityBinding::from_consensus_parts(
        request.scope(),
        request.key().clone(),
        request.current_owner().clone(),
        request.current_fence(),
        AuthorityLeaseMetadata::new(
            request.current_credential_id(),
            request.current_generation(),
            request.current_lease_acquired_at(),
            request.current_lease_expires_at(),
        ),
    )
    .map_err(|_| reject())?;
    let slot = protected_roster_v2_stable_slot(
        Scope::from_digest(request.scope()),
        request.key(),
        roster_id,
    );
    let binding = store
        .stable_slot_v2(slot)
        .map_err(ProtectedRosterApplyError::store_error)?
        .ok_or_else(reject)?;
    let record = store
        .record_v2(identity, binding)
        .map_err(ProtectedRosterApplyError::store_error)?
        .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
    store
        .authenticate_record_v2(identity, binding, &record)
        .map_err(ProtectedRosterApplyError::store_error)?;
    if record.record().state() != ProductionReservationStateV2::Retained {
        return Err(reject());
    }
    let admission = record
        .admission()
        .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
    let committed = record
        .committed_terminal()
        .ok_or_else(|| ProtectedRosterApplyError::Corrupt.store_error())?;
    if admission.profile() != crate::fenced_mutation_roster::Profile::v2()
        || admission.scope().digest() != request.scope()
        || admission.key() != request.key()
        || admission.roster_id() != roster_id
        || admission.body_commitment() != request.admission_commitment()
        || admission.logical_owner() != request.logical_owner()
        || admission.admission_fence() != request.admission_fence()
        || admission.expected_generation() != request.current_generation()
        || committed.record().phase().map_err(|_| reject())?
            != crate::fenced_mutation_roster::Phase::Established
        || committed.record().body_commitment() != request.terminal_body_commitment()
        || committed.receipt_commitment() != request.receipt_commitment()
    {
        return Err(reject());
    }
    let registration = BackendRegistration::from_consensus_parts(
        roster_registration_handle(binding),
        RosterRequestId::bind(binding.history_epoch(), admission).map_err(|_| reject())?,
        admission,
    )
    .map_err(|_| reject())?;
    let (handle, request_id, terminal_slot) = registration.consensus_parts();
    if handle != request.registration_handle()
        || request_id.to_bytes() != request.registration_request_id()
        || terminal_slot.as_bytes() != &request.registration_terminal_slot()
    {
        return Err(reject());
    }
    let original = store
        .original_authority_v2(identity, binding, admission)
        .map_err(ProtectedRosterApplyError::store_error)?;
    roster_engine::validate_current_authority(
        store,
        admission,
        &original,
        &current,
        logical_time,
        false,
    )
    .map_err(ProtectedRosterApplyError::store_error)
}
