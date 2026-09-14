//! Shared V1 and V2 roster command evaluation. Storage adapters supply exact reads
//! and one atomic prepared transaction; all authority, attestation, replay,
//! capacity, and terminal-result decisions remain in this single evaluator.

use super::*;

/// Reads belong to the same predecessor as the final prepared transaction.
/// A deterministic rejection discards every staged business change; any local
/// fault aborts the complete outer consensus apply. Implementations must keep
/// these two failure classes distinct and preserve the cross-profile vacancy
/// and business-key reservation checks in the prepared transaction.
pub(crate) trait RosterCommandStore {
    fn trust_root(
        &self,
    ) -> Result<Option<RosterAttestationTrustRootV1>, SessionConsensusStorageError>;
    fn validate_live_authority(
        &self,
        authority: &AuthorityBinding,
        expected_generation: Option<Generation>,
        logical_time: Timestamp,
    ) -> Result<(), ProtectedRosterApplyError>;
    fn record_v1(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
    ) -> Result<Option<HydratedProductionReservationRecord>, ProtectedRosterApplyError>;
    fn original_authority_v1(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        admission: &Admission,
    ) -> Result<AuthorityBinding, ProtectedRosterApplyError>;
    fn raw_record(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError>;
    fn stable_slot_v1(
        &self,
        slot: [u8; 32],
    ) -> Result<Option<RequestBindingKey>, ProtectedRosterApplyError>;
    fn original_binding_v1(
        &self,
        key: &SessionKey,
        roster_id: RosterId,
        owner: &OwnerId,
        fence: FenceToken,
        generation: Generation,
    ) -> Result<Option<RequestBindingKey>, ProtectedRosterApplyError>;
    fn floor(
        &self,
        identity: SessionConsensusIdentity,
        key: ProductionFloorKey,
    ) -> Result<Option<IrreversibleHistoryFloor>, ProtectedRosterApplyError>;
    fn retirement_cursor(
        &self,
        identity: SessionConsensusIdentity,
        key: ProductionFloorKey,
    ) -> Result<Option<ProductionRetirementCursor>, ReservationError>;
    fn witness(
        &self,
        identity: SessionConsensusIdentity,
    ) -> Result<Option<GlobalChargeWitness>, ProtectedRosterApplyError>;
    fn vacancy(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
    ) -> Result<ProductionBindingVacancyGuard, ProtectedRosterApplyError>;
    fn apply_v1(
        &mut self,
        identity: SessionConsensusIdentity,
        transaction: PreparedProductionTransaction,
        admission: Option<&ConsensusRosterAdmissionCommand>,
        authority: Option<&AuthorityBinding>,
    ) -> Result<(), ReservationError>;
    fn membership_scope(
        &self,
        identity: SessionConsensusIdentity,
    ) -> io::Result<MembershipValidationScope>;
    fn stable_slot_v2(
        &self,
        slot: [u8; 32],
    ) -> Result<Option<RequestBindingKey>, ProtectedRosterApplyError>;
    fn record_v2(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
    ) -> Result<Option<HydratedProductionReservationRecordV2>, ProtectedRosterApplyError>;
    fn authenticate_record_v2(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        hydrated: &HydratedProductionReservationRecordV2,
    ) -> Result<(), ProtectedRosterApplyError>;
    fn original_authority_v2(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        admission: &Admission,
    ) -> Result<AuthorityBinding, ProtectedRosterApplyError>;
    fn original_projection_v2(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
    ) -> Result<ProtectedRosterV2OriginalAuthorityProjection, ProtectedRosterApplyError>;
    fn live_reservation_v2(
        &self,
        identity: SessionConsensusIdentity,
        key: &SessionKey,
    ) -> Result<Option<RequestBindingKey>, ProtectedRosterApplyError>;
    fn apply_admission_v2(
        &mut self,
        identity: SessionConsensusIdentity,
        record: &ProductionReservationRecordV2,
        command: &ConsensusRosterAdmissionCommand,
        preparation: &PreparedProductionV2Admission,
    ) -> Result<(), ProtectedRosterCommandApplyError>;
    fn apply_terminal_v2(
        &mut self,
        identity: SessionConsensusIdentity,
        authority: &AuthorityBinding,
        write: V2TerminalWrite<'_>,
        next_witness: GlobalChargeWitness,
    ) -> Result<Option<ReplicationOp>, ProtectedRosterCommandApplyError>;
}

/// Exact canonical CAS and business action derived only after the V2 terminal
/// verifier and capacity planner accepted the predecessor. The adapter must
/// compare the original V2 carrier and its absence reservation, then publish
/// the replacement, optional generation-one create, reservation release, and
/// next shared witness in one outer transaction.
pub(crate) struct V2TerminalWrite<'a> {
    pub(crate) binding: RequestBindingKey,
    pub(crate) replacement: &'a ProductionReservationRecordV2,
    pub(crate) old_canonical: Vec<u8>,
    pub(crate) new_canonical: Vec<u8>,
    pub(crate) replacement_terminalized_at: [u8; 16],
    pub(crate) replacement_terminal_sequence: i64,
    pub(crate) action: ProductionTerminalAbsentBusinessActionV2<'a>,
}

pub(crate) fn validate_current_authority(
    store: &(impl RosterCommandStore + ?Sized),
    admission: &Admission,
    original: &AuthorityBinding,
    current: &AuthorityBinding,
    logical_time: Timestamp,
    require_original: bool,
) -> Result<(), ProtectedRosterApplyError> {
    if current.scope() != admission.scope()
        || current.key() != admission.key()
        || current.generation() != admission.expected_generation()
        || current.fence() < admission.admission_fence()
        || (require_original && current != original)
        // Logical ownership is immutable provenance for the original
        // admission guard, not a permanent execution-owner restriction. An
        // authenticated lease successor may have a different owner, but only
        // at a strictly higher fence; the exact live-lease comparison below
        // still rejects invented, stale, or expired successor authorities.
        || (!require_original
            && current.fence() == admission.admission_fence()
            && current != original)
    {
        return Err(ProtectedRosterApplyError::Rejected);
    }
    store.validate_live_authority(current, Some(admission.expected_generation()), logical_time)
}

fn admission_business(
    store: &impl RosterCommandStore,
    admission: &Admission,
    authority: &AuthorityBinding,
) -> Result<ProductionBusinessState, ProtectedRosterCommandApplyError> {
    if authority.key() != admission.key()
        || authority.owner() != admission.logical_owner()
        || authority.fence() != admission.admission_fence()
        || authority.generation() != admission.expected_generation()
    {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::Authority,
        ));
    }
    let current = store
        .raw_record(admission.key())
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    if admission
        .established_mutation()
        .requires_absent_predecessor()
    {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::InvalidProtectedCheckpoint,
        ));
    }
    let current = current.ok_or_else(|| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::RecordMissing)
    })?;
    if current.generation != admission.expected_generation() {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::GenerationConflict,
        ));
    }
    if current.owner != *admission.logical_owner() || current.fence != admission.admission_fence() {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::Authority,
        ));
    }
    if let Some(state_type) = admission.established_mutation().state_type() {
        let generation = admission.expected_generation().next().ok_or_else(|| {
            ProtectedRosterCommandApplyError::rejected(
                ConsensusRosterRejection::GenerationExhausted,
            )
        })?;
        let payload = EncryptedSessionPayload::try_envelope(admission.terminal_checkpoint())
            .map_err(|_| {
                ProtectedRosterCommandApplyError::rejected(
                    ConsensusRosterRejection::InvalidProtectedCheckpoint,
                )
            })?;
        let successor = StoredSessionRecord {
            key: admission.key().clone(),
            generation,
            owner: admission.logical_owner().clone(),
            fence: admission.admission_fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: state_type.clone(),
            expires_at: None,
            payload,
        };
        successor
            .payload
            .validate_envelope_for_record(&successor)
            .map_err(|_| {
                ProtectedRosterCommandApplyError::rejected(
                    ConsensusRosterRejection::InvalidProtectedCheckpoint,
                )
            })?;
    }
    ProductionBusinessState::from_authoritative_record(&current)
        .map_err(|_| ProtectedRosterCommandApplyError::Fatal)
}

pub(crate) fn admit_v1(
    store: &mut impl RosterCommandStore,
    storage_identity: SessionConsensusIdentity,
    authority_identity: SessionConsensusIdentity,
    raft_log_index: u64,
    logical_time: Timestamp,
    command: &ConsensusRosterAdmissionCommand,
) -> Result<ConsensusRosterAdmissionOutcome, ProtectedRosterCommandApplyError> {
    if raft_log_index == 0 {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::HistoryFull,
        ));
    }
    let root = store
        .trust_root()
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .ok_or_else(|| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    let admission = command.admission();
    let authority = command.authority();
    validate_current_authority(store, admission, authority, authority, logical_time, false)
        .map_err(ProtectedRosterCommandApplyError::from_authority)?;
    let ingress = command.ingress_attestation().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    let capsule =
        roster_poll_admit_ingress_capsule_commitment(admission, authority).map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    ingress
        .verify_roster_command(
            &root,
            &RosterIngressAttestationRosterCommandInputV1 {
                configuration_identity: &authority_identity,
                expected_scope: authority.scope().digest(),
                expected_request_id: command.ingress_request_id(),
                expected_operation_tag: 1,
                expected_capsule_digest: capsule,
                logical_time,
            },
        )
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    let admission_provenance = command.admission_provenance().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    let provenance_binding = admission.binding_key(raft_log_index).map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::HistoryFull)
    })?;
    verify_compact_admission_provenance_v2(CompactAdmissionProvenanceVerificationV2 {
        root: &root,
        configuration_identity: authority_identity,
        binding: provenance_binding,
        admission,
        original_authority: authority,
        ingress: ingress.signing_input(),
        provenance: &admission_provenance,
    })
    .map_err(|_| ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority))?;
    // The roster-ID slot is permanent for this body namespace.  Replaying
    // the exact admission returns its original registration; another body
    // with the same stable ID is a closed conflict and never reaches the
    // reservation/budget path a second time.
    let slot = command.admission_slot().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::RecoveryRequired)
    })?;
    if let Some(binding) = store
        .stable_slot_v1(slot)
        .map_err(ProtectedRosterCommandApplyError::fatal)?
    {
        let hydrated = store
            .record_v1(storage_identity, binding)
            .map_err(ProtectedRosterCommandApplyError::fatal)?
            .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
        match hydrated.payload() {
            HydratedProductionReservationPayload::Live {
                admission: stored_admission,
                admission_provenance: stored_provenance,
                ..
            }
            | HydratedProductionReservationPayload::Retained {
                admission: stored_admission,
                admission_provenance: stored_provenance,
                ..
            } if stored_admission == admission => {
                let original = store
                    .original_authority_v1(storage_identity, binding, stored_admission)
                    .map_err(ProtectedRosterCommandApplyError::fatal)?;
                verify_historical_compact_admission_provenance_v2(
                    HistoricalCompactAdmissionProvenanceVerificationV2 {
                        root: &root,
                        configuration_identity: authority_identity,
                        binding,
                        admission: stored_admission,
                        original_authority: &original,
                        provenance: stored_provenance,
                    },
                )
                .map_err(|_| {
                    ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
                })?;
                // A retry may arrive through a valid strictly newer execution
                // fence.  It replays the immutable admission registration;
                // it never rewrites the original authority provenance.
                validate_current_authority(
                    store,
                    stored_admission,
                    &original,
                    authority,
                    logical_time,
                    false,
                )
                .map_err(ProtectedRosterCommandApplyError::from_authority)?;
                return ConsensusRosterAdmissionOutcome::replayed(command)
                    .map_err(ProtectedRosterCommandApplyError::fatal);
            }
            HydratedProductionReservationPayload::Tombstone {
                tombstone,
                admission_provenance: stored_provenance,
                ..
            } => {
                tombstone
                    .validate_admission(binding.history_epoch(), admission)
                    .map_err(|_| {
                        ProtectedRosterCommandApplyError::rejected(
                            ConsensusRosterRejection::TerminalConflict,
                        )
                    })?;
                let original = store
                    .original_authority_v1(storage_identity, binding, admission)
                    .map_err(ProtectedRosterCommandApplyError::fatal)?;
                verify_historical_compact_admission_provenance_v2(
                    HistoricalCompactAdmissionProvenanceVerificationV2 {
                        root: &root,
                        configuration_identity: authority_identity,
                        binding,
                        admission,
                        original_authority: &original,
                        provenance: stored_provenance,
                    },
                )
                .map_err(|_| {
                    ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
                })?;
                validate_current_authority(
                    store,
                    admission,
                    &original,
                    authority,
                    logical_time,
                    false,
                )
                .map_err(ProtectedRosterCommandApplyError::from_authority)?;
                return ConsensusRosterAdmissionOutcome::replayed(command)
                    .map_err(ProtectedRosterCommandApplyError::fatal);
            }
            _ => {
                return Err(ProtectedRosterCommandApplyError::rejected(
                    ConsensusRosterRejection::TerminalConflict,
                ));
            }
        }
    }
    let business = admission_business(store, admission, authority)?;
    let reservation = ProductionAdmissionBusinessReservation::new(admission, business)
        .map_err(protected_roster_reservation_error)?;
    let record = ProductionReservationRecord::live_with_provenance_and_ingress(
        admission,
        &ingress,
        &admission_provenance,
        raft_log_index,
        reservation,
        ChargeProfile::v1(),
    )
    .map_err(protected_roster_reservation_error)?;
    let floor_key = ProductionFloorKey::from_floor(
        IrreversibleHistoryFloor::initial(record.binding()).map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::HistoryFull)
        })?,
    )
    .map_err(protected_roster_reservation_error)?;
    let floor = store
        .floor(storage_identity, floor_key)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    let retirement_cursor = store
        .retirement_cursor(storage_identity, floor_key)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    let witness = store
        .witness(storage_identity)
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .unwrap_or_else(GlobalChargeWitness::empty);
    let vacancy = store
        .vacancy(storage_identity, record.binding())
        .map_err(ProtectedRosterCommandApplyError::from_vacancy)?;
    let prepared = prepare_production_admission(ProductionAdmissionPreparation {
        vacancy: &vacancy,
        existing: None,
        record: record.clone(),
        existing_floor: floor,
        existing_retirement_cursor: retirement_cursor.as_ref(),
        witness,
        budget: GlobalChargeBudget::production(),
        profile: ChargeProfile::v1(),
    })
    .map_err(protected_roster_reservation_error)?;
    let registration = BackendRegistration::from_consensus_parts(
        roster_registration_handle(record.binding()),
        RosterRequestId::bind(raft_log_index, admission).map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::HistoryFull)
        })?,
        admission,
    )
    .map_err(ProtectedRosterCommandApplyError::fatal)?;
    store
        .apply_v1(storage_identity, prepared, Some(command), None)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    ConsensusRosterAdmissionOutcome::admitted(command, registration)
        .map_err(ProtectedRosterCommandApplyError::fatal)
}

pub(crate) fn terminal_v1(
    store: &mut impl RosterCommandStore,
    storage_identity: SessionConsensusIdentity,
    authority_identity: SessionConsensusIdentity,
    application_sequence: u64,
    raft_log_index: u64,
    logical_time: Timestamp,
    command: &ConsensusRosterTerminalCommand,
) -> Result<(ConsensusRosterTerminalOutcome, Option<ReplicationOp>), ProtectedRosterCommandApplyError>
{
    protected_roster_terminalization_sequences_are_valid(application_sequence, raft_log_index)?;
    let binding = command.binding();
    // Authenticate the exact least-authority binding and the current live
    // execution guard before probing the stable roster slot. Existing and
    // absent foreign rows must therefore be observationally indistinguishable.
    protected_roster_validate_binding_authority_before_lookup(binding, command.authority())
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    store
        .validate_live_authority(command.authority(), None, logical_time)
        .map_err(ProtectedRosterCommandApplyError::from_authority)?;
    let hydrated = store
        .record_v1(storage_identity, binding)
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .ok_or_else(|| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::TerminalLocked)
        })?;
    let state = hydrated.record().state();
    if state == ReservationState::Tombstone {
        // A compacted row deliberately retains only the authenticated history
        // required for reads.  It no longer has the raw admission, provider
        // proof bundle, or terminal ingress capsule required to authenticate a
        // terminal *mutation* under the current membership authority.  Do not
        // turn a syntactically matching retry into a definitive mutation
        // response before those inputs are verified.  Authenticated callers
        // can obtain compacted status through the read-only terminal-status
        // path, which compares the retained evidence after the restart scanner
        // has reauthenticated the tombstone against the persisted current
        // membership lineage and its trust root.
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::TerminalConflict,
        ));
    }
    // The row hydration already decoded, authenticated, and recanonicalized
    // this potentially multi-megabyte body. Retain one owned copy for receipt
    // construction while the sealed hydration itself moves into the live-row
    // terminal CAS preparation below.
    let admission = match hydrated.payload() {
        HydratedProductionReservationPayload::Live { admission, .. }
        | HydratedProductionReservationPayload::Retained { admission, .. } => admission.clone(),
        HydratedProductionReservationPayload::Tombstone { .. } => {
            return Err(ProtectedRosterCommandApplyError::Fatal);
        }
        #[cfg(test)]
        HydratedProductionReservationPayload::Legacy => hydrated
            .record()
            .admission()
            .map_err(ProtectedRosterCommandApplyError::fatal)?,
    };
    let original = store
        .original_authority_v1(storage_identity, binding, &admission)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    let authority =
        AuthorityBinding::for_validated_admission(&admission, command.authority(), false).map_err(
            |_| ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority),
        )?;
    validate_current_authority(
        store,
        &admission,
        &original,
        &authority,
        logical_time,
        false,
    )
    .map_err(ProtectedRosterCommandApplyError::from_authority)?;
    let (handle, request_id, terminal_slot) = command.registration_parts();
    let expected_request = RosterRequestId::bind(binding.history_epoch(), &admission)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    let registration = BackendRegistration::from_consensus_parts(handle, request_id, &admission)
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::TerminalConflict)
        })?;
    if request_id != expected_request
        || handle != roster_registration_handle(binding)
        || registration.consensus_parts().2.as_bytes() != &terminal_slot
    {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::TerminalConflict,
        ));
    }
    #[cfg(any(test, feature = "test-control"))]
    let decode_and_proof_started = Instant::now();
    let terminal = TerminalRecord::from_canonical_bytes(command.record_bytes(), &admission)
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::TerminalConflict)
        })?;
    if terminal.request_id() != request_id {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::TerminalConflict,
        ));
    }
    let root = store
        .trust_root()
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .ok_or_else(|| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    let proof_bundle = command.proof_bundle().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    verify_executor_terminal_proof_bundle(ExecutorTerminalProofVerification {
        root: Some(&root),
        configuration_identity: authority_identity,
        logical_time,
        binding,
        registration,
        admission: &admission,
        authority: &authority,
        terminal: &terminal,
        bundle: &proof_bundle,
    })
    .map_err(|_| ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority))?;
    let ingress = command.ingress_attestation().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    let terminal_evidence = command.terminal_evidence().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    let capsule = roster_terminal_ingress_capsule_commitment(
        binding,
        registration,
        &authority,
        &terminal,
        &admission,
        &proof_bundle,
        &terminal_evidence,
    )
    .map_err(|_| ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority))?;
    ingress
        .verify_roster_command(
            &root,
            &RosterIngressAttestationRosterCommandInputV1 {
                configuration_identity: &authority_identity,
                expected_scope: authority.ingress_scope().digest(),
                expected_request_id: command.ingress_request_id(),
                expected_operation_tag: 4,
                expected_capsule_digest: capsule,
                logical_time,
            },
        )
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    let admission_provenance = match hydrated.payload() {
        HydratedProductionReservationPayload::Live {
            admission_provenance,
            ..
        }
        | HydratedProductionReservationPayload::Retained {
            admission_provenance,
            ..
        }
        | HydratedProductionReservationPayload::Tombstone {
            admission_provenance,
            ..
        } => admission_provenance.clone(),
        #[cfg(test)]
        HydratedProductionReservationPayload::Legacy => {
            return Err(ProtectedRosterCommandApplyError::fatal(
                ReservationError::StateShape,
            ));
        }
    };
    verify_compact_terminal_evidence_v2(CompactTerminalEvidenceVerificationV2 {
        root: &root,
        configuration_identity: authority_identity,
        logical_time,
        binding,
        registration,
        admission_provenance: &admission_provenance,
        committing_authority: &authority,
        evidence: &terminal_evidence,
    })
    .map_err(|_| ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority))?;
    #[cfg(any(test, feature = "test-control"))]
    record_protected_roster_terminal_apply_timing(
        &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.decode_and_proof_count,
        &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.decode_and_proof_nanos,
        decode_and_proof_started,
    );
    match state {
        ReservationState::Tombstone => Err(ProtectedRosterCommandApplyError::Fatal),
        ReservationState::Retained => {
            let (committed, retained_evidence) = match hydrated.payload() {
                HydratedProductionReservationPayload::Retained {
                    committed_terminal,
                    terminal_evidence,
                    ..
                } => (committed_terminal.as_ref(), terminal_evidence),
                #[cfg(test)]
                HydratedProductionReservationPayload::Legacy => {
                    return Err(ProtectedRosterCommandApplyError::Fatal);
                }
                _ => return Err(ProtectedRosterCommandApplyError::Fatal),
            };
            if committed.record() != &terminal || retained_evidence != &terminal_evidence {
                return Err(ProtectedRosterCommandApplyError::rejected(
                    ConsensusRosterRejection::TerminalConflict,
                ));
            }
            #[cfg(any(test, feature = "test-control"))]
            let committed_outcome_started = Instant::now();
            let outcome =
                ConsensusRosterTerminalOutcome::committed(command, true, committed, &admission)
                    .map_err(ProtectedRosterCommandApplyError::fatal)?;
            #[cfg(any(test, feature = "test-control"))]
            record_protected_roster_terminal_apply_timing(
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.committed_outcome_count,
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.committed_outcome_nanos,
                committed_outcome_started,
            );
            Ok((outcome, None))
        }
        ReservationState::Live => {
            // This closes the deliberately separate deterministic planner
            // phase: metadata issuance, witness read, protected transaction
            // construction, and the derived replication projection.  It is
            // neither terminal decoding/proof verification nor SQLite apply.
            #[cfg(any(test, feature = "test-control"))]
            let terminalization_preparation_started = Instant::now();
            let metadata =
                ConsensusCommitMetadata::issue(application_sequence, raft_log_index, logical_time)
                    .map_err(ProtectedRosterCommandApplyError::fatal)?;
            let committed = CommittedTerminal::issue_from_record(
                registration,
                &admission,
                &authority,
                terminal,
                metadata,
            )
            .map_err(|_| {
                ProtectedRosterCommandApplyError::rejected(
                    ConsensusRosterRejection::TerminalConflict,
                )
            })?;
            let witness = store
                .witness(storage_identity)
                .map_err(ProtectedRosterCommandApplyError::fatal)?
                .unwrap_or_else(GlobalChargeWitness::empty);
            let prepared = prepare_production_terminalization_hydrated_with_evidence_and_ingress(
                hydrated,
                binding,
                &committed,
                &proof_bundle,
                &ingress,
                &terminal_evidence,
                witness,
                GlobalChargeBudget::production(),
                ChargeProfile::v1(),
            )
            .map_err(protected_roster_terminalization_reservation_error)?;
            let replication = protected_roster_established_replication(&prepared, &authority)?;
            #[cfg(any(test, feature = "test-control"))]
            record_protected_roster_terminal_apply_timing(
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.terminalization_preparation_count,
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.terminalization_preparation_nanos,
                terminalization_preparation_started,
            );
            #[cfg(any(test, feature = "test-control"))]
            let production_apply_started = Instant::now();
            store
                .apply_v1(storage_identity, prepared, None, Some(&authority))
                .map_err(ProtectedRosterCommandApplyError::fatal)?;
            #[cfg(any(test, feature = "test-control"))]
            record_protected_roster_terminal_apply_timing(
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.production_apply_count,
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.production_apply_nanos,
                production_apply_started,
            );
            #[cfg(any(test, feature = "test-control"))]
            let committed_outcome_started = Instant::now();
            let outcome =
                ConsensusRosterTerminalOutcome::committed(command, false, &committed, &admission)
                    .map_err(ProtectedRosterCommandApplyError::fatal)?;
            #[cfg(any(test, feature = "test-control"))]
            record_protected_roster_terminal_apply_timing(
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.committed_outcome_count,
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.committed_outcome_nanos,
                committed_outcome_started,
            );
            Ok((outcome, replication))
        }
    }
}

pub(crate) fn admit_v2(
    store: &mut impl RosterCommandStore,
    storage_identity: SessionConsensusIdentity,
    authority_identity: SessionConsensusIdentity,
    raft_log_index: u64,
    logical_time: Timestamp,
    command: &ConsensusRosterAdmissionCommand,
) -> Result<ConsensusRosterAdmissionOutcome, ProtectedRosterCommandApplyError> {
    if raft_log_index == 0 {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::HistoryFull,
        ));
    }
    let admission = command.admission();
    let authority = command.authority();
    if admission.profile() != crate::fenced_mutation_roster::Profile::v2() {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::Authority,
        ));
    }

    // Authenticate the `/4` transport and its V2-only compact provenance
    // before a lease, roster, or business-row lookup.  The typed outer intent
    // and typed decoders make a structurally valid V1 capsule unusable here.
    let root = store
        .trust_root()
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .ok_or_else(|| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    let ingress = command.ingress_attestation_v2().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    let capsule =
        roster_poll_admit_ingress_capsule_commitment_v2(admission, authority).map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    ingress
        .verify_roster_command(
            &root,
            &RosterIngressAttestationRosterCommandInputV2 {
                configuration_identity: &authority_identity,
                expected_scope: authority.scope().digest(),
                expected_request_id: command.ingress_request_id(),
                expected_operation_tag: 1,
                expected_capsule_digest: capsule,
                logical_time,
            },
        )
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    let admission_provenance = command.admission_provenance_v2().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    admission_provenance
        .verify_for(&root, authority_identity, admission, authority, &ingress)
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;

    validate_current_authority(store, admission, authority, authority, logical_time, true)
        .map_err(ProtectedRosterCommandApplyError::from_authority)?;

    let slot = command.admission_slot().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::RecoveryRequired)
    })?;
    if let Some(binding) = store
        .stable_slot_v2(slot)
        .map_err(ProtectedRosterCommandApplyError::fatal)?
    {
        let stored = store
            .record_v2(storage_identity, binding)
            .map_err(ProtectedRosterCommandApplyError::fatal)?
            .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
        store
            .authenticate_record_v2(storage_identity, binding, &stored)
            .map_err(ProtectedRosterCommandApplyError::fatal)?;
        if stored.record().state() == ProductionReservationStateV2::Tombstone {
            let tombstone = stored
                .tombstone()
                .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
            tombstone
                .validate_admission_for_profile(
                    crate::fenced_mutation_roster::Profile::v2(),
                    binding.history_epoch(),
                    admission,
                )
                .map_err(|_| {
                    ProtectedRosterCommandApplyError::rejected(
                        ConsensusRosterRejection::TerminalConflict,
                    )
                })?;
            let original = store
                .original_authority_v2(storage_identity, binding, admission)
                .map_err(ProtectedRosterCommandApplyError::fatal)?;
            let membership_scope = store
                .membership_scope(storage_identity)
                .map_err(ProtectedRosterCommandApplyError::fatal)?;
            let original_projection = store
                .original_projection_v2(storage_identity, binding)
                .map_err(ProtectedRosterCommandApplyError::fatal)?;
            validate_hydrated_protected_roster_v2_compacted_sync(
                &root,
                &membership_scope,
                binding,
                &stored,
                &original_projection,
            )
            .map_err(ProtectedRosterCommandApplyError::fatal)?;
            validate_current_authority(store, admission, &original, authority, logical_time, false)
                .map_err(ProtectedRosterCommandApplyError::from_authority)?;
            return ConsensusRosterAdmissionOutcome::replayed(command)
                .map_err(ProtectedRosterCommandApplyError::fatal);
        }
        let stored_admission = stored
            .admission()
            .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
        if stored_admission != admission {
            return Err(ProtectedRosterCommandApplyError::rejected(
                ConsensusRosterRejection::TerminalConflict,
            ));
        }
        let original = store
            .original_authority_v2(storage_identity, binding, stored_admission)
            .map_err(ProtectedRosterCommandApplyError::fatal)?;
        let stored_ingress = stored
            .admission_ingress()
            .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
        let stored_provenance = stored.admission_provenance();
        // The retained Q1 envelope is immutable evidence from its original
        // membership epoch.  A retry after a membership cutover still has to
        // authenticate its fresh ingress under the current identity (above),
        // but it must not reinterpret the stored ingress/provenance as a
        // statement by that newer configuration.  First prove the stored
        // identity owned this binding's exact historical interval, then
        // verify both retained V2 carriers in that sealed identity.
        let historical_identity = stored_provenance.configuration_identity();
        let membership_scope = store
            .membership_scope(storage_identity)
            .map_err(ProtectedRosterCommandApplyError::fatal)?;
        validate_roster_admission_attestation_identity_interval(
            &membership_scope,
            binding,
            historical_identity,
        )
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
        let stored_capsule =
            roster_poll_admit_ingress_capsule_commitment_v2(stored_admission, &original)
                .map_err(ProtectedRosterCommandApplyError::fatal)?;
        let stored_time = stored_ingress.signing_input().authenticated_at;
        stored_ingress
            .verify_roster_command(
                &root,
                &RosterIngressAttestationRosterCommandInputV2 {
                    configuration_identity: &historical_identity,
                    expected_scope: stored_admission.scope().digest(),
                    expected_request_id: stored_ingress.request_id(),
                    expected_operation_tag: 1,
                    expected_capsule_digest: stored_capsule,
                    logical_time: stored_time,
                },
            )
            .map_err(|_| {
                ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
            })?;
        stored_provenance
            .verify_for(
                &root,
                historical_identity,
                stored_admission,
                &original,
                stored_ingress,
            )
            .map_err(|_| {
                ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
            })?;
        validate_current_authority(
            store,
            stored_admission,
            &original,
            authority,
            logical_time,
            false,
        )
        .map_err(ProtectedRosterCommandApplyError::from_authority)?;
        return ConsensusRosterAdmissionOutcome::replayed(command)
            .map_err(ProtectedRosterCommandApplyError::fatal);
    }

    // Replay is resolved before absence. A distinct admission that hashes to
    // another V2 stable slot still cannot reserve an existing authoritative
    // session row; V1 roster tables are never queried or written here.
    if store
        .raw_record(admission.key())
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .is_some()
    {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::RecordAlreadyExists,
        ));
    }
    let binding = admission.binding_key(raft_log_index).map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::HistoryFull)
    })?;
    let reservation = ProductionAdmissionAbsentBusinessReservationV2::new(admission, binding)
        .map_err(protected_roster_v2_admission_reservation_error)?;
    let record = ProductionReservationRecord::live_v2_absent_with_provenance_and_ingress(
        admission,
        &ingress,
        &admission_provenance,
        raft_log_index,
        reservation,
        ChargeProfile::v1(),
    )
    .map_err(protected_roster_v2_admission_reservation_error)?;
    if store
        .live_reservation_v2(storage_identity, admission.key())
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .is_some()
    {
        // This is the one deterministic Q1 reservation conflict: the exact
        // committed session-key reservation was read and revalidated as a
        // live V2 carrier.  All malformed or unreadable side-table states
        // reached the fatal branch above.
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::BusinessKeyReserved,
        ));
    }
    // Q1 reserves both its live occupancy and the exact maximum retained
    // terminal carrier in the same global V1+V2 witness.  Q2 only exchanges
    // that pre-reserved peak for its smaller retained body, so it cannot
    // discover a late capacity failure after terminal authority is accepted.
    let witness = store
        .witness(storage_identity)
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .unwrap_or_else(GlobalChargeWitness::empty);
    let floor_key = ProductionFloorKey::from_binding(record.binding())
        .map_err(protected_roster_v2_admission_reservation_error)?;
    let floor = store
        .floor(storage_identity, floor_key)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    let cursor = store
        .retirement_cursor(storage_identity, floor_key)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    let vacancy = store
        .vacancy(storage_identity, record.binding())
        .map_err(ProtectedRosterCommandApplyError::from_vacancy)?;
    let admission_preparation = prepare_production_v2_admission_with_floor(
        &vacancy,
        &record,
        floor,
        cursor.as_ref(),
        witness,
        GlobalChargeBudget::production(),
        ChargeProfile::v1(),
    )
    .map_err(protected_roster_v2_admission_reservation_error)?;
    store.apply_admission_v2(storage_identity, &record, command, &admission_preparation)?;
    let registration = BackendRegistration::from_consensus_parts(
        roster_registration_handle(record.binding()),
        RosterRequestId::bind(raft_log_index, admission).map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::HistoryFull)
        })?,
        admission,
    )
    .map_err(ProtectedRosterCommandApplyError::fatal)?;
    ConsensusRosterAdmissionOutcome::admitted(command, registration)
        .map_err(ProtectedRosterCommandApplyError::fatal)
}

pub(crate) fn terminal_v2(
    store: &mut impl RosterCommandStore,
    storage_identity: SessionConsensusIdentity,
    authority_identity: SessionConsensusIdentity,
    application_sequence: u64,
    raft_log_index: u64,
    logical_time: Timestamp,
    command: &ConsensusRosterTerminalCommandV2,
) -> Result<(ConsensusRosterTerminalOutcome, Option<ReplicationOp>), ProtectedRosterCommandApplyError>
{
    protected_roster_terminalization_sequences_are_valid(application_sequence, raft_log_index)?;
    let binding = command.binding();
    // Validate the untrusted current authority before we resolve a V2
    // binding.  In particular, this intentionally does not probe V1 rows as
    // a fallback: an absent V2 reservation and a V1 row are distinct states.
    protected_roster_validate_binding_authority_before_lookup(binding, command.authority())
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    store
        .validate_live_authority(command.authority(), None, logical_time)
        .map_err(ProtectedRosterCommandApplyError::from_authority)?;

    let hydrated = store
        .record_v2(storage_identity, binding)
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .ok_or_else(|| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::TerminalLocked)
        })?;
    store
        .authenticate_record_v2(storage_identity, binding, &hydrated)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    let record = hydrated.record();
    if record.state() == ProductionReservationStateV2::Tombstone {
        store
            .validate_live_authority(command.authority(), Some(Generation::new(1)), logical_time)
            .map_err(ProtectedRosterCommandApplyError::from_authority)?;
        let (handle, request_id, terminal_slot) = command.registration_parts();
        if handle != roster_registration_handle(binding) || terminal_slot == [0; 32] {
            return Err(ProtectedRosterCommandApplyError::rejected(
                ConsensusRosterRejection::TerminalConflict,
            ));
        }
        let tombstone = hydrated
            .tombstone()
            .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
        let terminal_body = TerminalRecord::canonical_body_commitment(command.record_bytes())
            .map_err(|_| {
                ProtectedRosterCommandApplyError::rejected(
                    ConsensusRosterRejection::TerminalConflict,
                )
            })?;
        tombstone
            .validate_compacted_terminal_for_profile(CompactedTerminalValidation {
                profile: crate::fenced_mutation_roster::Profile::v2(),
                binding,
                request_id,
                terminal_slot,
                current_fence: command.authority().fence(),
                current_generation: command.authority().generation(),
                terminal_body_commitment: terminal_body,
            })
            .map_err(|_| {
                ProtectedRosterCommandApplyError::rejected(
                    ConsensusRosterRejection::TerminalConflict,
                )
            })?;
        let original = store
            .original_projection_v2(storage_identity, binding)
            .map_err(ProtectedRosterCommandApplyError::fatal)?;
        let root = store
            .trust_root()
            .map_err(ProtectedRosterCommandApplyError::fatal)?
            .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
        let membership_scope = store
            .membership_scope(storage_identity)
            .map_err(ProtectedRosterCommandApplyError::fatal)?;
        validate_hydrated_protected_roster_v2_compacted_sync(
            &root,
            &membership_scope,
            binding,
            &hydrated,
            &original,
        )
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
        return ConsensusRosterTerminalOutcome::compacted_v2(command, tombstone.clone())
            .map(|outcome| (outcome, None))
            .map_err(ProtectedRosterCommandApplyError::fatal);
    }
    let admission = hydrated
        .admission()
        .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
    if admission.profile() != crate::fenced_mutation_roster::Profile::v2() {
        return Err(ProtectedRosterCommandApplyError::Fatal);
    }
    let original = store
        .original_authority_v2(storage_identity, binding, admission)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    let authority =
        AuthorityBinding::for_validated_admission(admission, command.authority(), false).map_err(
            |_| ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority),
        )?;
    validate_current_authority(store, admission, &original, &authority, logical_time, false)
        .map_err(ProtectedRosterCommandApplyError::from_authority)?;

    let (handle, request_id, terminal_slot) = command.registration_parts();
    let expected_request = RosterRequestId::bind(binding.history_epoch(), admission)
        .map_err(ProtectedRosterCommandApplyError::fatal)?;
    let registration = BackendRegistration::from_consensus_parts(handle, request_id, admission)
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::TerminalConflict)
        })?;
    if request_id != expected_request
        || handle != roster_registration_handle(binding)
        || registration.consensus_parts().2.as_bytes() != &terminal_slot
    {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::TerminalConflict,
        ));
    }
    // Keep the Profile-V2 timing boundaries identical to the frozen V1 path.
    // These aggregate-only counters exist solely behind test/test-control and
    // intentionally do not influence admission, proof, or transaction flow.
    #[cfg(any(test, feature = "test-control"))]
    let decode_and_proof_started = Instant::now();
    let terminal = TerminalRecord::from_canonical_bytes(command.record_bytes(), admission)
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::TerminalConflict)
        })?;
    if terminal.request_id() != request_id {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::TerminalConflict,
        ));
    }

    let root = store
        .trust_root()
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        .ok_or_else(|| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    let admission_ingress = hydrated
        .admission_ingress()
        .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
    let stored_provenance = hydrated.admission_provenance();
    let proof_bundle = command.proof_bundle().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    let terminal_evidence = command.terminal_evidence().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    let ingress = command.ingress_attestation().map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    // A V2 outer command must retain exactly the immutable Q1 provenance and
    // must authenticate its own fresh terminal ingress.  Equality here is
    // over canonical bytes; no structurally similar V1 carrier is probed.
    if terminal_evidence
        .provenance()
        .canonical_bytes()
        .map_err(ProtectedRosterCommandApplyError::fatal)?
        != stored_provenance
            .canonical_bytes()
            .map_err(ProtectedRosterCommandApplyError::fatal)?
        || terminal_evidence
            .ingress()
            .canonical_bytes()
            .map_err(ProtectedRosterCommandApplyError::fatal)?
            != ingress
                .canonical_bytes()
                .map_err(ProtectedRosterCommandApplyError::fatal)?
        || proof_bundle.admission_provenance_commitment()
            != stored_provenance
                .commitment()
                .map_err(ProtectedRosterCommandApplyError::fatal)?
        || proof_bundle
            .ingress()
            .canonical_bytes()
            .map_err(ProtectedRosterCommandApplyError::fatal)?
            != ingress
                .canonical_bytes()
                .map_err(ProtectedRosterCommandApplyError::fatal)?
    {
        return Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::Authority,
        ));
    }
    let capsule = roster_terminal_ingress_capsule_commitment_v2(
        binding,
        registration,
        &authority,
        &terminal,
        admission,
        stored_provenance,
        terminal_evidence.evidence(),
    )
    .map_err(|_| ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority))?;
    let admission_capsule = roster_poll_admit_ingress_capsule_commitment_v2(admission, &original)
        .map_err(|_| {
        ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
    })?;
    let historical_identity = stored_provenance.configuration_identity();
    verify_profile_v2_compact_terminal_evidence(ProfileV2CompactTerminalEvidenceVerificationV1 {
        root: &root,
        terminal_configuration_identity: authority_identity,
        terminal_logical_time: logical_time,
        binding,
        registration,
        admission,
        original_authority: &original,
        admission_provenance: stored_provenance,
        admission_ingress,
        admission_ingress_command: RosterIngressAttestationRosterCommandInputV2 {
            configuration_identity: &historical_identity,
            expected_scope: original.ingress_scope().digest(),
            expected_request_id: admission_ingress.request_id(),
            expected_operation_tag: 1,
            expected_capsule_digest: admission_capsule,
            logical_time: admission_ingress.signing_input().authenticated_at,
        },
        committing_authority: &authority,
        terminal: &terminal,
        proof_bundle: &proof_bundle,
        evidence: &terminal_evidence,
    })
    .map_err(|_| ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority))?;
    ingress
        .verify_roster_command(
            &root,
            &RosterIngressAttestationRosterCommandInputV2 {
                configuration_identity: &authority_identity,
                expected_scope: authority.ingress_scope().digest(),
                expected_request_id: command.ingress_request_id(),
                expected_operation_tag: 4,
                expected_capsule_digest: capsule,
                logical_time,
            },
        )
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    // The sealed verifier authenticates signatures and membership. The raw
    // terminal bytes additionally must be the exact checkpoint/result whose
    // commitments the compact evidence carries.
    terminal_evidence
        .evidence()
        .verify_raw_terminal(admission, &terminal)
        .map_err(|_| {
            ProtectedRosterCommandApplyError::rejected(ConsensusRosterRejection::Authority)
        })?;
    #[cfg(any(test, feature = "test-control"))]
    record_protected_roster_terminal_apply_timing(
        &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.decode_and_proof_count,
        &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.decode_and_proof_nanos,
        decode_and_proof_started,
    );

    match record.state() {
        ProductionReservationStateV2::Retained => {
            let committed = hydrated
                .committed_terminal()
                .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
            let retained_proof = hydrated
                .terminal_proof_bundle()
                .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
            let retained_evidence = hydrated
                .terminal_evidence()
                .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
            let proof_bytes = proof_bundle
                .canonical_bytes()
                .map_err(ProtectedRosterCommandApplyError::fatal)?;
            let evidence_bytes = terminal_evidence
                .canonical_bytes()
                .map_err(ProtectedRosterCommandApplyError::fatal)?;
            if committed.record() != &terminal
                || retained_proof
                    .canonical_bytes()
                    .map_err(ProtectedRosterCommandApplyError::fatal)?
                    != proof_bytes
                || retained_evidence
                    .canonical_bytes()
                    .map_err(ProtectedRosterCommandApplyError::fatal)?
                    != evidence_bytes
            {
                return Err(ProtectedRosterCommandApplyError::rejected(
                    ConsensusRosterRejection::TerminalConflict,
                ));
            }
            #[cfg(any(test, feature = "test-control"))]
            let committed_outcome_started = Instant::now();
            let outcome =
                ConsensusRosterTerminalOutcome::committed_v2(command, true, committed, admission)
                    .map_err(ProtectedRosterCommandApplyError::fatal)?;
            #[cfg(any(test, feature = "test-control"))]
            record_protected_roster_terminal_apply_timing(
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.committed_outcome_count,
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.committed_outcome_nanos,
                committed_outcome_started,
            );
            Ok((outcome, None))
        }
        ProductionReservationStateV2::Live => {
            if record.absence_reservation().is_none() {
                return Err(ProtectedRosterCommandApplyError::Fatal);
            }
            #[cfg(any(test, feature = "test-control"))]
            let terminalization_preparation_started = Instant::now();
            let metadata =
                ConsensusCommitMetadata::issue(application_sequence, raft_log_index, logical_time)
                    .map_err(ProtectedRosterCommandApplyError::fatal)?;
            let committed = CommittedTerminal::issue_from_record(
                registration,
                admission,
                &authority,
                terminal,
                metadata,
            )
            .map_err(|_| {
                ProtectedRosterCommandApplyError::rejected(
                    ConsensusRosterRejection::TerminalConflict,
                )
            })?;
            let prepared = record
                .prepare_terminalization(
                    &committed,
                    &proof_bundle,
                    &terminal_evidence,
                    ChargeProfile::v1(),
                )
                .map_err(protected_roster_terminalization_reservation_error)?;
            let witness = store
                .witness(storage_identity)
                .map_err(ProtectedRosterCommandApplyError::fatal)?
                .unwrap_or_else(GlobalChargeWitness::empty);
            let capacity = prepare_production_v2_terminal_capacity(
                record,
                &prepared,
                witness,
                GlobalChargeBudget::production(),
                ChargeProfile::v1(),
            )
            .map_err(protected_roster_terminalization_reservation_error)?;
            let old_canonical = hydrated.canonical().to_vec();
            let replacement = prepared.replacement();
            let new_canonical = replacement
                .to_canonical_bytes()
                .map_err(protected_roster_terminalization_reservation_error)?;
            if replacement.binding() != binding
                || replacement.state() != ProductionReservationStateV2::Retained
            {
                return Err(ProtectedRosterCommandApplyError::Fatal);
            }
            let replacement_terminalized_at = replacement
                .terminalized_at()
                .map(|value| value.as_nanos().to_be_bytes())
                .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
            let replacement_terminal_sequence = replacement
                .terminal_sequence()
                .map(checked_positive_i64)
                .transpose()
                .map_err(ProtectedRosterCommandApplyError::fatal)?
                .ok_or(ProtectedRosterCommandApplyError::Fatal)?;
            let action = prepared.business_cas().action();
            let reservation = action.reservation();
            reservation
                .validate_for(admission, binding)
                .map_err(protected_roster_terminalization_reservation_error)?;
            #[cfg(any(test, feature = "test-control"))]
            record_protected_roster_terminal_apply_timing(
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.terminalization_preparation_count,
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.terminalization_preparation_nanos,
                terminalization_preparation_started,
            );
            // The predicate read, V2-row compare-and-swap, optional
            // generation-one create, reservation release, and witness update
            // are one indivisible production-apply phase.  In particular an
            // Aborted terminal reaches this phase even though it emits no
            // replication notification.
            #[cfg(any(test, feature = "test-control"))]
            let production_apply_started = Instant::now();
            let replication = store.apply_terminal_v2(
                storage_identity,
                &authority,
                V2TerminalWrite {
                    binding,
                    replacement,
                    old_canonical,
                    new_canonical,
                    replacement_terminalized_at,
                    replacement_terminal_sequence,
                    action,
                },
                capacity.next_witness(),
            )?;
            #[cfg(any(test, feature = "test-control"))]
            record_protected_roster_terminal_apply_timing(
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.production_apply_count,
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.production_apply_nanos,
                production_apply_started,
            );
            #[cfg(any(test, feature = "test-control"))]
            let committed_outcome_started = Instant::now();
            let outcome =
                ConsensusRosterTerminalOutcome::committed_v2(command, false, &committed, admission)
                    .map_err(ProtectedRosterCommandApplyError::fatal)?;
            #[cfg(any(test, feature = "test-control"))]
            record_protected_roster_terminal_apply_timing(
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.committed_outcome_count,
                &PROTECTED_ROSTER_TERMINAL_APPLY_TIMINGS.committed_outcome_nanos,
                committed_outcome_started,
            );
            Ok((outcome, replication))
        }
        ProductionReservationStateV2::Tombstone => Err(ProtectedRosterCommandApplyError::rejected(
            ConsensusRosterRejection::TerminalLocked,
        )),
    }
}
