//! Deterministic aggregate snapshot-charge accounting for protected rosters.
//!
//! This deliberately models schema charge, rather than an engine's page cache
//! or a backend's physical layout. Production derives the one finite budget
//! for the complete protected-roster ledger from the frozen roster profile.
//! Authoritative business-row
//! materialization is protected by its own exact CAS, but deliberately stays
//! outside this witness so the frozen roster-only allocation never pretends to
//! account for unrelated session-store storage, raw SQLite bytes, global-store
//! bytes, or physical snapshot size. The 100k operational target remains
//! subject to this roster-ledger logical/schema-charge budget.

#[cfg(test)]
use crate::fenced_mutation_roster::MAX_HISTORY_FLOOR_CODEC_BYTES;
use crate::fenced_mutation_roster::{
    Admission, IrreversibleHistoryFloor, RequestBindingKey, TerminalConflictTombstone,
    CHARGE_WITNESS_VERSION, MAX_ADMISSION_CODEC_BYTES, MAX_BUSINESS_SESSION_HEADER_BYTES,
    MAX_CHECKPOINT_BYTES, MAX_COMMITTED_TERMINAL_CODEC_BYTES, MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES,
    MAX_EXECUTOR_PROOF_BUNDLE_BYTES, MAX_HISTORY_EPOCH, MAX_LIVE_ROSTERS,
    MAX_RESERVED_AND_RETAINED, MAX_ROSTER_INGRESS_ATTESTATION_BYTES, MAX_TOMBSTONE_CODEC_BYTES,
    PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES, RECLAIM_BATCH, STORAGE_CHARGE_LIVE_INDEX_BYTES,
    STORAGE_CHARGE_LIVE_ROW_BYTES, STORAGE_CHARGE_PAGE_BYTES, STORAGE_CHARGE_RETAINED_INDEX_BYTES,
    STORAGE_CHARGE_RETAINED_ROW_BYTES, STORAGE_CHARGE_TOMBSTONE_INDEX_BYTES,
    STORAGE_CHARGE_TOMBSTONE_ROW_BYTES,
};
use crate::fenced_mutation_roster_executor::{
    CommittedTerminal, EstablishedMaterialization, TerminalMaterialization,
};
use opc_types::Timestamp;
use serde::{
    de::{SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};

/// The sole ledger-global protected-roster charge-witness version accepted.
///
/// This is derived from the roster profile, rather than being an independently
/// configurable storage version.
pub(crate) const GLOBAL_CHARGE_WITNESS_V1: u16 = CHARGE_WITNESS_VERSION as u16;

/// A valid production snapshot may contain every durable row at its frozen
/// per-field maximum.  This is deliberately derived from the protocol bounds
/// instead of an arbitrary decoder cap (a fixed 512 MiB cap cannot represent
/// a valid 1,024-row maximum-payload deployment).  The decode path still
/// preflights the actual frame against the persisted aggregate budget before
/// it asks postcard to allocate anything.
const MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES: usize = MAX_ADMISSION_CODEC_BYTES
    + MAX_COMMITTED_TERMINAL_CODEC_BYTES
    + MAX_TOMBSTONE_CODEC_BYTES
    + MAX_BUSINESS_SESSION_COPY_BYTES
    + 512;
/// The complete V3 stream is bounded in `u64`, rather than `usize` or a
/// postcard frame length. A valid frozen deployment can legitimately exceed
/// both a 32-bit postcard frame and a 32-bit process address space.
#[cfg(test)]
const MAX_PRODUCTION_SNAPSHOT_CODEC_BYTES: u64 = PRODUCTION_SNAPSHOT_MAGIC.len() as u64
    + SNAPSHOT_CHUNK_HEADER_BYTES
    + SNAPSHOT_START_MAX_BYTES as u64
    + MAX_RESERVED_AND_RETAINED as u64
        * (SNAPSHOT_CHUNK_HEADER_BYTES + MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES as u64)
    + MAX_RESERVED_AND_RETAINED as u64
        * (SNAPSHOT_CHUNK_HEADER_BYTES + MAX_HISTORY_FLOOR_CODEC_BYTES as u64)
    + MAX_RESERVED_AND_RETAINED as u64
        * (SNAPSHOT_CHUNK_HEADER_BYTES + MAX_RETIREMENT_CURSOR_CODEC_BYTES as u64)
    + SNAPSHOT_CHUNK_HEADER_BYTES
    + SNAPSHOT_CHUNK_DIGEST_BYTES as u64;
#[cfg(test)]
const PRODUCTION_SNAPSHOT_MAGIC: [u8; 8] = *b"OPCRSS3\0";
#[cfg(test)]
const PRODUCTION_SNAPSHOT_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/production-snapshot/v3\0";
const SNAPSHOT_FLOOR_FRAME_HEADER_BYTES: usize = 14;
const SNAPSHOT_FLOOR_PARTITION_BYTES: usize = 64;
const MAX_RETIREMENT_CURSOR_CODEC_BYTES: usize = 256;
const TERMINAL_RETENTION_NANOS: i128 = 24 * 60 * 60 * 1_000_000_000;
#[cfg(test)]
const SNAPSHOT_CHUNK_HEADER_BYTES: u64 = 5;
#[cfg(test)]
const SNAPSHOT_CHUNK_DIGEST_BYTES: usize = 32;
#[cfg(test)]
const SNAPSHOT_START_MAX_BYTES: usize = 512;
#[cfg(test)]
const SNAPSHOT_CHUNK_START: u8 = 1;
#[cfg(test)]
const SNAPSHOT_CHUNK_RECORD: u8 = 2;
#[cfg(test)]
const SNAPSHOT_CHUNK_FLOOR: u8 = 3;
#[cfg(test)]
const SNAPSHOT_CHUNK_CURSOR: u8 = 4;
#[cfg(test)]
const SNAPSHOT_CHUNK_DIGEST: u8 = 5;

/// Versioned protected-roster ledger snapshot charge limit.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GlobalChargeBudget {
    version: u16,
    maximum_total_charge_bytes: u64,
}

#[cfg(test)]
mod production_tests {
    use super::*;
    use crate::fenced_mutation_roster::{
        AdmissionProposal, EstablishedMutation, Member, MemberOperationId, Phase, Profile,
        RequestId, RosterId, Scope, TerminalRecord, MEMBER_OPERATION_ID_BYTES, ROSTER_ID_BYTES,
    };
    use crate::fenced_mutation_roster_executor::{
        AuthorityBinding, AuthorityLeaseMetadata, BackendRegistration, ConsensusCommitMetadata,
    };
    use crate::model::{FenceToken, Generation, OwnerId, SessionKey};
    use crate::{SessionKeyType, StableId};
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    fn profile() -> ChargeProfile {
        ChargeProfile::test_profile(16, 8, 6, 3, 2, 2, 1)
    }

    fn admission_business_reservation(
        admission: &Admission,
    ) -> ProductionAdmissionBusinessReservation {
        ProductionAdmissionBusinessReservation::new(
            admission,
            ProductionBusinessState::present(
                admission.key().clone(),
                admission.expected_generation(),
                admission.body_commitment().to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn live(
        admission: &Admission,
        epoch: u64,
        profile: ChargeProfile,
    ) -> ProductionReservationRecord {
        ProductionReservationRecord::live(
            admission,
            epoch,
            admission_business_reservation(admission),
            profile,
        )
        .unwrap()
    }

    fn empty_witness() -> GlobalChargeWitness {
        GlobalChargeWitness::v1(0, 0, zero_counters())
    }

    fn aged_maintenance_time() -> ConsensusMaintenanceTimestamp {
        ConsensusMaintenanceTimestamp::from_consensus_timestamp(
            Timestamp::now_utc().add_seconds(2 * 24 * 60 * 60).unwrap(),
        )
        .unwrap()
    }

    fn retirement_selected_prefix(
        records: &BTreeMap<RequestBindingKey, ProductionReservationRecord>,
        previous: IrreversibleHistoryFloor,
        next: IrreversibleHistoryFloor,
        cursor: Option<&ProductionRetirementCursor>,
    ) -> Vec<(RequestBindingKey, ProductionReservationRecord)> {
        let key = ProductionFloorKey::from_floor(previous).unwrap();
        records
            .iter()
            .filter(|(binding, _)| {
                ProductionFloorKey::from_binding(**binding) == Ok(key)
                    && binding.history_epoch() == next.retired_through()
                    && cursor
                        .and_then(|cursor| cursor.last_deleted)
                        .is_none_or(|after| **binding > after)
            })
            .take(RECLAIM_BATCH)
            .map(|(binding, record)| (*binding, record.clone()))
            .collect()
    }

    fn v3_stream(chunks: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = PRODUCTION_SNAPSHOT_MAGIC.to_vec();
        let mut hasher = production_snapshot_hasher();
        for (tag, payload) in chunks {
            let chunk = encode_snapshot_chunk(*tag, payload).unwrap();
            hasher.update(&chunk);
            bytes.extend_from_slice(&chunk);
        }
        let digest: [u8; SNAPSHOT_CHUNK_DIGEST_BYTES] = hasher.finalize().into();
        bytes.extend_from_slice(&encode_snapshot_chunk(SNAPSHOT_CHUNK_DIGEST, &digest).unwrap());
        bytes
    }

    fn v3_chunks(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        assert!(bytes.starts_with(&PRODUCTION_SNAPSHOT_MAGIC));
        let mut offset = PRODUCTION_SNAPSHOT_MAGIC.len();
        let mut chunks = Vec::new();
        while offset < bytes.len() {
            let tag = bytes[offset];
            let length =
                u32::from_be_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
            offset += 5;
            let payload = bytes[offset..offset + length].to_vec();
            offset += length;
            if tag == SNAPSHOT_CHUNK_DIGEST {
                assert_eq!(offset, bytes.len());
                break;
            }
            chunks.push((tag, payload));
        }
        chunks
    }

    #[derive(Clone, Copy)]
    enum AdapterStage {
        Row,
        Business,
        Floor,
        Witness,
    }

    #[derive(Clone)]
    struct InMemoryProductionStore {
        rows: BTreeMap<RequestBindingKey, ProductionReservationRecord>,
        witness: GlobalChargeWitness,
        floors: BTreeMap<ProductionFloorKey, IrreversibleHistoryFloor>,
        retirement_cursors: BTreeMap<ProductionFloorKey, ProductionRetirementCursor>,
        business: Option<ProductionBusinessState>,
        business_reservation: Option<ProductionAdmissionBusinessReservation>,
        fail_at: Option<AdapterStage>,
    }

    impl ProductionReservationTransactionAdapter for InMemoryProductionStore {
        fn compare_and_apply_production(
            &mut self,
            transaction: PreparedProductionTransaction,
        ) -> Result<(), ReservationError> {
            if self.witness != transaction.previous {
                return Err(ReservationError::WitnessMismatch);
            }
            for row in &transaction.rows {
                if self.rows.get(&row.binding) != row.expected.as_ref() {
                    return Err(ReservationError::SnapshotMismatch);
                }
            }
            if let Some(guard) = transaction.reclaim_oldest_guard.as_ref() {
                let mut eligible = self
                    .rows
                    .iter()
                    .filter(|(_, record)| record.state == ReservationState::Retained)
                    .filter_map(|(binding, record)| {
                        record
                            .terminalized_at
                            .filter(|terminalized_at| {
                                terminalized_at
                                    .checked_add_retention()
                                    .is_ok_and(|eligible_at| eligible_at <= guard.maintenance_time)
                            })
                            .map(|terminalized_at| (terminalized_at, *binding))
                    })
                    .collect::<Vec<_>>();
                eligible.sort_unstable();
                if eligible
                    .iter()
                    .take(RECLAIM_BATCH)
                    .copied()
                    .collect::<Vec<_>>()
                    != guard.selected
                    || transaction.rows.len() != guard.selected.len()
                    || transaction
                        .rows
                        .iter()
                        .zip(&guard.selected)
                        .any(|(row, expected)| {
                            row.binding != expected.1
                                || row.expected.as_ref().is_none_or(|record| {
                                    record.state != ReservationState::Retained
                                        || record.terminalized_at != Some(expected.0)
                                })
                        })
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
            }
            if let Some(guard) = transaction.partition_guard.as_ref() {
                let cursor_matches_guard =
                    transaction
                        .retirement_cursor
                        .as_ref()
                        .is_some_and(|cursor| {
                            cursor.key == guard.key
                                && cursor
                                    .expected
                                    .as_ref()
                                    .and_then(|expected| expected.last_deleted)
                                    == guard.after
                        });
                let floor_present = transaction.floor.is_some();
                if self
                    .floors
                    .get(&guard.key)
                    .map(|floor| floor.retired_through())
                    != Some(guard.previous_floor_through)
                    || guard.selected.len() > RECLAIM_BATCH
                    || guard.selected.is_empty()
                    || !cursor_matches_guard
                    || (guard.final_batch != floor_present)
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
                let mut target = Vec::new();
                for (binding, record) in &self.rows {
                    if ProductionFloorKey::from_binding(*binding) != Ok(guard.key) {
                        continue;
                    }
                    if binding.history_epoch() <= guard.previous_floor_through
                        || binding.history_epoch() < guard.target_epoch
                        || (binding.history_epoch() == guard.target_epoch
                            && guard.after.is_some_and(|after| *binding <= after))
                    {
                        return Err(ReservationError::SnapshotMismatch);
                    }
                    if binding.history_epoch() == guard.target_epoch {
                        if record.state != ReservationState::Tombstone {
                            return Err(ReservationError::SnapshotMismatch);
                        }
                        target.push(*binding);
                    }
                }
                let expected = target
                    .iter()
                    .copied()
                    .take(RECLAIM_BATCH)
                    .collect::<Vec<_>>();
                if expected != guard.selected
                    || transaction.rows.len() != guard.selected.len()
                    || transaction
                        .rows
                        .iter()
                        .zip(&guard.selected)
                        .any(|(row, binding)| row.binding != *binding || row.replacement.is_some())
                    || (guard.final_batch && target.len() != guard.selected.len())
                    || (!guard.final_batch && target.len() <= guard.selected.len())
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
            }
            if matches!(self.fail_at, Some(AdapterStage::Row)) {
                return Err(ReservationError::SnapshotMismatch);
            }
            if let Some(reservation) = transaction.admission_business_reservation.as_ref() {
                if self.business.as_ref() != Some(reservation.expected())
                    || self.business_reservation.is_some()
                {
                    return Err(ReservationError::BusinessCas);
                }
            }
            if let Some(business) = transaction.business.as_ref() {
                let action = business.action();
                if self.business.as_ref() != Some(action.expected()) {
                    return Err(ReservationError::BusinessCas);
                }
                if self
                    .business_reservation
                    .as_ref()
                    .map(ProductionAdmissionBusinessReservation::expected)
                    != Some(action.expected())
                {
                    return Err(ReservationError::BusinessCas);
                }
            }
            if matches!(self.fail_at, Some(AdapterStage::Business)) {
                return Err(ReservationError::BusinessCas);
            }
            if let Some(floor) = transaction.floor {
                if self.floors.get(&floor.key()) != floor.expected().as_ref() {
                    return Err(ReservationError::FloorAdvance);
                }
            }
            if let Some(cursor) = transaction.retirement_cursor.as_ref() {
                if self.retirement_cursors.get(&cursor.key) != cursor.expected.as_ref() {
                    return Err(ReservationError::FloorAdvance);
                }
            }
            if matches!(self.fail_at, Some(AdapterStage::Floor)) {
                return Err(ReservationError::FloorAdvance);
            }
            if matches!(self.fail_at, Some(AdapterStage::Witness)) {
                return Err(ReservationError::WitnessMismatch);
            }

            // All validation ran against the pre-state. Build the whole next
            // state in locals and publish it only after every stage succeeds.
            let mut rows = self.rows.clone();
            let mut floors = self.floors.clone();
            let mut retirement_cursors = self.retirement_cursors.clone();
            let mut business_row = self.business.clone();
            let mut business_reservation = self.business_reservation.clone();
            for row in transaction.rows {
                match row.replacement {
                    Some(replacement) => {
                        rows.insert(row.binding, replacement);
                    }
                    None => {
                        rows.remove(&row.binding);
                    }
                }
            }
            if let Some(reservation) = transaction.admission_business_reservation {
                business_reservation = Some(reservation);
            }
            if let Some(business) = transaction.business {
                match business.action() {
                    ProductionTerminalBusinessAction::AbortedCompareRelease { .. } => {}
                    ProductionTerminalBusinessAction::EstablishedPut { successor, .. } => {
                        business_row = Some(successor.clone());
                    }
                    ProductionTerminalBusinessAction::EstablishedDelete { .. } => {
                        business_row = None;
                    }
                }
                business_reservation = None;
            }
            if let Some(floor) = transaction.floor {
                floors.insert(floor.key(), floor.replacement());
            }
            if let Some(cursor) = transaction.retirement_cursor {
                match cursor.replacement {
                    Some(replacement) => {
                        retirement_cursors.insert(cursor.key, replacement);
                    }
                    None => {
                        retirement_cursors.remove(&cursor.key);
                    }
                }
            }
            self.rows = rows;
            self.floors = floors;
            self.retirement_cursors = retirement_cursors;
            self.business = business_row;
            self.business_reservation = business_reservation;
            self.witness = transaction.next;
            Ok(())
        }
    }

    fn admission(identity: u16) -> Admission {
        admission_for("tenant", identity)
    }

    fn admission_for(tenant: &'static str, identity: u16) -> Admission {
        let proposal = AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([7; ROSTER_ID_BYTES]).unwrap(),
            vec![Member::new(
                0,
                MemberOperationId::from_bytes([1; MEMBER_OPERATION_ID_BYTES]).unwrap(),
                vec![1],
                1,
            )
            .unwrap()],
            EstablishedMutation::no_op(),
            vec![1],
            vec![2],
            vec![3],
        )
        .unwrap();
        let key = SessionKey {
            tenant: TenantId::from_static(tenant),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from(identity.to_be_bytes().to_vec())).unwrap(),
        };
        Admission::authenticate(
            proposal,
            key,
            Scope::from_digest([9; 32]),
            OwnerId::new("owner").unwrap(),
            FenceToken::new(1),
            Generation::new(1),
        )
        .unwrap()
    }

    fn terminal(admission: &Admission) -> CommittedTerminal {
        terminal_at(admission, 1)
    }

    fn terminal_at(admission: &Admission, epoch: u64) -> CommittedTerminal {
        let record = TerminalRecord::new(
            admission,
            RequestId::bind(epoch, admission).unwrap(),
            Phase::Aborted,
            vec![[1; 32]; admission.members().len()],
        )
        .unwrap();
        let request = RequestId::bind(epoch, admission).unwrap();
        let registration = BackendRegistration::issue([1; 32], request, admission).unwrap();
        let committed_at = Timestamp::now_utc();
        let authority = AuthorityBinding::for_admission(
            admission,
            OwnerId::new("owner").unwrap(),
            FenceToken::new(1),
            AuthorityLeaseMetadata::new(
                1,
                Generation::new(1),
                committed_at,
                committed_at.add_seconds(1).unwrap(),
            ),
        )
        .unwrap();
        CommittedTerminal::issue_from_record(
            registration,
            admission,
            &authority,
            record,
            ConsensusCommitMetadata::issue(1, 1, committed_at).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn admission_reserves_peak_and_terminalization_at_capacity_preserves_terminal_frame() {
        let profile = profile();
        let admission = admission(1);
        let live = live(&admission, 1, profile);
        let floor = IrreversibleHistoryFloor::initial(admission.binding_key(1).unwrap()).unwrap();
        let budget = GlobalChargeBudget::v1(
            live.peak_charge_bytes
                + u64::try_from(floor.to_canonical_bytes().unwrap().len()).unwrap(),
        );
        let prepared =
            prepare_production_admission(None, live, None, None, empty_witness(), budget, profile)
                .unwrap();
        assert!(prepared.is_insertion());
        assert_eq!(prepared.canonical_rows_validated(), 1);
        assert_eq!(prepared.next_witness().roster.live_reservations, 1);
        assert_eq!(prepared.next_witness().roster.retained_and_live_bindings, 1);
        assert_eq!(
            validate_production_snapshot_with_floors(
                std::slice::from_ref(prepared.replacement().unwrap()),
                &[floor],
                &[],
                prepared.next_witness(),
                budget,
                profile,
            )
            .unwrap(),
            prepared.next_witness().roster
        );

        let terminal = terminal(&admission);
        let terminal_bytes = terminal.to_canonical_bytes(&admission).unwrap();
        let completed = prepare_production_terminalization(
            prepared.replacement().unwrap(),
            prepared.binding().unwrap(),
            &terminal,
            prepared.next_witness(),
            budget,
            profile,
        )
        .unwrap();
        assert_eq!(completed.canonical_rows_validated(), 1);
        assert_eq!(
            completed.replacement().unwrap().terminal.as_deref(),
            Some(terminal_bytes.as_slice())
        );
        assert_eq!(completed.next_witness().roster.live_reservations, 0);
        assert_eq!(
            completed.next_witness().roster.reserved_future_charge_bytes,
            0
        );
        assert_eq!(
            validate_production_snapshot_with_floors(
                std::slice::from_ref(completed.replacement().unwrap()),
                &[floor],
                &[],
                completed.next_witness(),
                budget,
                profile,
            )
            .unwrap(),
            completed.next_witness().roster
        );
    }

    #[test]
    fn aborted_terminal_is_compare_release_without_a_session_replacement() {
        let profile = profile();
        let admission = admission(31);
        let live = live(&admission, 1, profile);
        let terminal = terminal(&admission);
        let admitted = prepare_production_admission(
            None,
            live,
            None,
            None,
            empty_witness(),
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let prepared = prepare_production_terminalization(
            admitted.replacement().unwrap(),
            admitted.binding().unwrap(),
            &terminal,
            admitted.next_witness(),
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let business = prepared.business_cas().unwrap();
        let replacement_request = match business.action() {
            ProductionTerminalBusinessAction::AbortedCompareRelease { expected } => {
                assert_eq!(
                    expected,
                    admission_business_reservation(&admission).expected()
                );
                None
            }
            ProductionTerminalBusinessAction::EstablishedPut { successor, .. } => Some(successor),
            ProductionTerminalBusinessAction::EstablishedDelete { .. } => None,
        };

        assert!(replacement_request.is_none());
        assert!(matches!(
            business.action(),
            ProductionTerminalBusinessAction::AbortedCompareRelease { .. }
        ));
    }

    #[test]
    fn terminal_evidence_envelope_is_reserved_at_admission_and_charged_at_terminal() {
        let profile = profile();
        let admission = admission(32);
        let mut live = live(&admission, 1, profile);
        let without_evidence = ComponentBytes::from_exact(
            live.admission.len(),
            MAX_COMMITTED_TERMINAL_CODEC_BYTES,
            MAX_BUSINESS_SESSION_COPY_BYTES,
            MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES,
            0,
            MAX_TOMBSTONE_CODEC_BYTES,
        )
        .unwrap();
        let reserved = production_components(&live.admission, None, None).unwrap();
        assert_eq!(
            reserved.terminal_evidence_envelope_bytes,
            MAX_EXECUTOR_PROOF_BUNDLE_BYTES + 16 + MAX_ROSTER_INGRESS_ATTESTATION_BYTES
        );
        assert!(
            profile.charge(reserved).unwrap().retained
                > profile.charge(without_evidence).unwrap().retained
        );
        assert!(live.peak_charge_bytes >= profile.charge(reserved).unwrap().retained);

        let terminal = terminal(&admission);
        let terminal_bytes = terminal.to_canonical_bytes(&admission).unwrap();
        let retained_without_evidence = ComponentBytes::from_exact(
            live.admission.len(),
            terminal_bytes.len(),
            MAX_BUSINESS_SESSION_COPY_BYTES,
            MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES,
            0,
            MAX_TOMBSTONE_CODEC_BYTES,
        )
        .unwrap();
        live.terminalize(&terminal, profile).unwrap();

        assert!(
            live.retained_charge_bytes
                > profile.charge(retained_without_evidence).unwrap().retained
        );
        assert!(live.retained_charge_bytes <= live.peak_charge_bytes);
    }

    #[test]
    fn admission_rejects_one_byte_short_global_budget_and_unknown_witness() {
        let profile = profile();
        let admission = admission(2);
        let record = live(&admission, 1, profile);
        let floor = IrreversibleHistoryFloor::initial(record.binding).unwrap();
        let short = GlobalChargeBudget::v1(
            record.peak_charge_bytes
                + u64::try_from(floor.to_canonical_bytes().unwrap().len()).unwrap()
                - 1,
        );
        assert!(matches!(
            prepare_production_admission(
                None,
                record.clone(),
                None,
                None,
                empty_witness(),
                short,
                profile
            ),
            Err(ReservationError::BudgetExceeded)
        ));
        let unknown = GlobalChargeWitness {
            version: GLOBAL_CHARGE_WITNESS_V1 + 1,
            ..empty_witness()
        };
        assert!(matches!(
            prepare_production_admission(
                None,
                record,
                None,
                None,
                unknown,
                GlobalChargeBudget::v1(u64::MAX),
                profile
            ),
            Err(ReservationError::UnknownWitnessVersion)
        ));
    }

    #[test]
    fn frozen_production_budget_and_witness_version_reject_tampering() {
        let exact = GlobalChargeBudget::production();
        assert_eq!(
            exact.maximum_total_charge_bytes,
            PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES
        );
        assert_eq!(exact.version, CHARGE_WITNESS_VERSION as u16);
        assert!(exact.validate_frozen_profile().is_ok());
        assert!(matches!(
            GlobalChargeBudget {
                maximum_total_charge_bytes: PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES + 1,
                ..exact
            }
            .validate_frozen_profile(),
            Err(ReservationError::InvalidProfile)
        ));
        assert!(matches!(
            GlobalChargeBudget {
                version: GLOBAL_CHARGE_WITNESS_V1 + 1,
                ..exact
            }
            .validate_frozen_profile(),
            Err(ReservationError::UnknownWitnessVersion)
        ));
        assert!(matches!(
            GlobalChargeWitness {
                version: GLOBAL_CHARGE_WITNESS_V1 + 1,
                ..empty_witness()
            }
            .validate_for(exact),
            Err(ReservationError::UnknownWitnessVersion)
        ));
    }

    #[test]
    fn snapshot_is_order_independent_and_tampering_fails_closed() {
        let profile = profile();
        let first = live(&admission(3), 1, profile);
        let second = live(&admission(4), 1, profile);
        let ordered = vec![first.clone(), second.clone()];
        let mut reversed = ordered.clone();
        reversed.reverse();
        assert_eq!(
            validate_production_snapshot(&ordered, profile).unwrap(),
            validate_production_snapshot(&reversed, profile).unwrap()
        );

        let mut changed_admission = first.clone();
        changed_admission.admission.push(0);
        assert!(matches!(
            validate_production_snapshot(&[changed_admission], profile),
            Err(ReservationError::CanonicalEncoding)
        ));

        let mut retained = second;
        retained
            .terminalize(&terminal(&admission(4)), profile)
            .unwrap();
        retained.terminal.as_mut().unwrap().push(0);
        assert!(matches!(
            validate_production_snapshot(&[retained], profile),
            Err(ReservationError::CanonicalEncoding)
        ));

        assert!(matches!(
            validate_production_snapshot(&[first.clone(), first.clone()], profile),
            Err(ReservationError::Duplicate)
        ));
        let same_business_other_epoch = live(&admission(3), 2, profile);
        assert!(matches!(
            validate_production_snapshot(&[first.clone(), same_business_other_epoch], profile),
            Err(ReservationError::Duplicate)
        ));
        let mut invalid_shape = first.clone();
        invalid_shape.terminal = Some(Vec::new());
        assert!(matches!(
            validate_production_snapshot(&[invalid_shape], profile),
            Err(ReservationError::StateShape)
        ));
        assert!(matches!(
            validate_production_snapshot_witness(
                &[first],
                empty_witness(),
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::WitnessMismatch)
        ));
    }

    #[test]
    fn canonical_charge_overflow_and_invalid_epoch_fail_closed() {
        let admission = admission(8);
        assert!(matches!(
            ProductionReservationRecord::live(
                &admission,
                1,
                admission_business_reservation(&admission),
                ChargeProfile::test_profile(u64::MAX, u64::MAX, 1, 1, 1, 1, 1),
            ),
            Err(ReservationError::Arithmetic)
        ));
        assert!(matches!(
            ProductionReservationRecord::live(
                &admission,
                0,
                admission_business_reservation(&admission),
                profile(),
            ),
            Err(ReservationError::InvalidEpoch)
        ));
    }

    #[test]
    fn exact_live_combined_and_durable_limits_are_enforced() {
        let profile = profile();
        let mut live_records = (0..MAX_LIVE_ROSTERS)
            .map(|identity| live(&admission(identity as u16), 1, profile))
            .collect::<Vec<_>>();
        assert_eq!(
            validate_production_snapshot(&live_records, profile)
                .unwrap()
                .live_reservations(),
            MAX_LIVE_ROSTERS
        );
        live_records.push(live(&admission(MAX_LIVE_ROSTERS as u16), 1, profile));
        assert!(matches!(
            validate_production_snapshot(&live_records, profile),
            Err(ReservationError::LiveLimit)
        ));

        let admitted = admission(u16::MAX - 1);
        let record = live(&admitted, 1, profile);
        let floor = IrreversibleHistoryFloor::initial(record.binding).unwrap();
        let boundary = AggregateCounters {
            retained_and_live_bindings: MAX_RESERVED_AND_RETAINED - 1,
            durable_epoch_bindings: MAX_RESERVED_AND_RETAINED - 1,
            ..zero_counters()
        };
        let at_boundary = prepare_production_admission(
            None,
            record.clone(),
            None,
            None,
            GlobalChargeWitness::v1(0, 0, boundary),
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(
            at_boundary
                .next_witness()
                .roster
                .retained_and_live_bindings(),
            MAX_RESERVED_AND_RETAINED
        );
        assert_eq!(
            at_boundary.next_witness().roster.durable_epoch_bindings(),
            MAX_RESERVED_AND_RETAINED
        );
        assert!(matches!(
            prepare_production_admission(
                None,
                record.clone(),
                Some(floor),
                None,
                GlobalChargeWitness::v1(
                    0,
                    0,
                    AggregateCounters {
                        retained_and_live_bindings: MAX_RESERVED_AND_RETAINED,
                        durable_epoch_bindings: MAX_RESERVED_AND_RETAINED - 1,
                        ..zero_counters()
                    },
                ),
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::BindingLimit)
        ));
        assert!(matches!(
            prepare_production_admission(
                None,
                record,
                Some(floor),
                None,
                GlobalChargeWitness::v1(
                    0,
                    0,
                    AggregateCounters {
                        durable_epoch_bindings: MAX_RESERVED_AND_RETAINED,
                        ..zero_counters()
                    },
                ),
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::DurableBindingLimit)
        ));

        let floor_limited_admission = admission(u16::MAX - 2);
        let floor_limited_record = live(&floor_limited_admission, 1, profile);
        assert!(matches!(
            prepare_production_admission(
                None,
                floor_limited_record,
                None,
                None,
                GlobalChargeWitness::v1(
                    0,
                    0,
                    AggregateCounters {
                        floor_count: MAX_RESERVED_AND_RETAINED,
                        ..zero_counters()
                    },
                ),
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::FloorLimit)
        ));
    }

    #[test]
    fn counter_growth_caps_floors_and_cursors_before_any_collection_growth() {
        let record = live(&admission(u16::MAX - 3), 1, profile());
        let floor = IrreversibleHistoryFloor::initial(record.binding).unwrap();
        let cursor = ProductionRetirementCursor::initial(
            ProductionFloorKey::from_floor(floor).unwrap(),
            record.binding.history_epoch(),
        )
        .unwrap();
        assert!(matches!(
            counters_with_production_floor(
                AggregateCounters {
                    floor_count: MAX_RESERVED_AND_RETAINED,
                    ..zero_counters()
                },
                floor,
            ),
            Err(ReservationError::FloorLimit)
        ));
        assert!(matches!(
            counters_with_retirement_cursor(
                AggregateCounters {
                    retirement_cursor_count: MAX_RESERVED_AND_RETAINED,
                    ..zero_counters()
                },
                &cursor,
            ),
            Err(ReservationError::FloorLimit)
        ));
    }

    #[test]
    fn terminalization_rejects_a_witness_that_cannot_cover_its_current_row() {
        let profile = profile();
        let admission = admission(5);
        let live = live(&admission, 1, profile);
        assert!(matches!(
            prepare_production_terminalization(
                &live,
                live.binding,
                &terminal(&admission),
                empty_witness(),
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::WitnessMismatch)
        ));
    }

    #[test]
    fn reclaim_is_oldest_bounded_and_never_reclaims_live_or_young_rows() {
        let profile = profile();
        let now = aged_maintenance_time();
        let mut records = BTreeMap::new();
        let mut oldest = Vec::new();
        for identity in 0..=RECLAIM_BATCH {
            let admission = admission(identity as u16);
            let mut record = live(&admission, 1, profile);
            record.terminalize(&terminal(&admission), profile).unwrap();
            oldest.push((record.terminalized_at.unwrap(), record.binding));
            records.insert(record.binding, record);
        }
        let live = live(&admission(u16::MAX), 1, profile);
        records.insert(live.binding, live.clone());
        oldest = records
            .iter()
            .filter(|(_, record)| record.state == ReservationState::Retained)
            .map(|(binding, record)| (record.terminalized_at.unwrap(), *binding))
            .collect();
        oldest.sort_unstable();

        assert_eq!(
            reclaim_oldest_eligible(&mut records, now, profile).unwrap(),
            RECLAIM_BATCH
        );
        for (_, binding) in oldest.iter().take(RECLAIM_BATCH) {
            assert_eq!(records[binding].state, ReservationState::Tombstone);
        }
        assert_eq!(records[&live.binding].state, ReservationState::Live);
        assert_eq!(
            reclaim_oldest_eligible(&mut records, now, profile).unwrap(),
            1
        );
        assert_eq!(
            records[&oldest[RECLAIM_BATCH].1].state,
            ReservationState::Tombstone
        );
    }

    #[test]
    fn adapter_rejects_reclaim_when_a_caller_omits_an_older_eligible_row() {
        let profile = profile();
        let mut records = BTreeMap::new();
        for identity in [61, 62] {
            let admitted = admission(identity);
            let mut record = live(&admitted, 1, profile);
            record.terminalize(&terminal(&admitted), profile).unwrap();
            records.insert(record.binding, record);
        }
        let counters =
            validate_production_snapshot(&records.values().cloned().collect::<Vec<_>>(), profile)
                .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        let mut ordered = records
            .values()
            .map(|record| (record.terminalized_at.unwrap(), record.binding))
            .collect::<Vec<_>>();
        ordered.sort_unstable();
        let omitted_oldest = ordered[0].1;
        let selected_younger = ordered[1].1;
        let partial = BTreeMap::from([(
            selected_younger,
            records.get(&selected_younger).unwrap().clone(),
        )]);
        let reclaim = prepare_production_reclaim(
            &partial,
            aged_maintenance_time(),
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(reclaim.selected(), 1);
        assert_ne!(reclaim.transaction.rows[0].binding, omitted_oldest);
        let mut store = InMemoryProductionStore {
            rows: records,
            witness,
            floors: BTreeMap::new(),
            retirement_cursors: BTreeMap::new(),
            business: None,
            business_reservation: None,
            fail_at: None,
        };
        assert!(matches!(
            store.compare_and_apply_production(reclaim.transaction),
            Err(ReservationError::SnapshotMismatch)
        ));
    }

    #[test]
    fn retirement_requires_a_strict_same_scope_floor_and_releases_tombstone_charge() {
        let profile = profile();
        let fixture = admission(6);
        let mut record = live(&fixture, 1, profile);
        record.terminalize(&terminal(&fixture), profile).unwrap();
        record.reclaim_at(aged_maintenance_time(), profile).unwrap();
        let previous = IrreversibleHistoryFloor::initial(record.binding).unwrap();
        let counters = counters_with_production_floor(
            validate_production_snapshot(std::slice::from_ref(&record), profile).unwrap(),
            previous,
        )
        .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        let next = previous.advance_to(1).unwrap();
        let records = BTreeMap::from([(record.binding, record.clone())]);
        let prepared = prepare_production_retirement(
            ProductionRetirementPrefix::new(
                previous,
                next,
                &retirement_selected_prefix(&records, previous, next, None),
                true,
            )
            .unwrap(),
            previous,
            next,
            None,
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(prepared.next_witness().roster.floor_count(), 1);
        assert_eq!(prepared.next_witness().roster.durable_epoch_bindings(), 0);
        assert!(matches!(
            prepare_production_retirement(
                ProductionRetirementPrefix::new(
                    previous,
                    next,
                    &retirement_selected_prefix(&records, previous, next, None),
                    true,
                )
                .unwrap(),
                previous,
                previous,
                None,
                witness,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::FloorAdvance)
        ));
    }

    #[test]
    fn complete_transaction_adapter_commits_rows_witness_and_floor_together() {
        let profile = profile();
        let admitted = admission(42);
        let live = live(&admitted, 1, profile);
        let floor = IrreversibleHistoryFloor::initial(live.binding).unwrap();
        let mut store = InMemoryProductionStore {
            rows: BTreeMap::new(),
            witness: empty_witness(),
            floors: BTreeMap::new(),
            retirement_cursors: BTreeMap::new(),
            business: Some(live.business_reservation.as_ref().unwrap().expected.clone()),
            business_reservation: None,
            fail_at: None,
        };
        let admission_tx = prepare_production_admission(
            None,
            live,
            None,
            None,
            store.witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let stale = admission_tx.clone();
        store.compare_and_apply_production(admission_tx).unwrap();
        assert!(matches!(
            store.compare_and_apply_production(stale),
            Err(ReservationError::WitnessMismatch)
        ));

        let binding = admitted.binding_key(1).unwrap();
        let terminal_tx = prepare_production_terminalization(
            store.rows.get(&binding).unwrap(),
            binding,
            &terminal(&admitted),
            store.witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let mut wrong_row = terminal_tx.clone();
        wrong_row.rows[0].expected = None;
        assert!(matches!(
            store.compare_and_apply_production(wrong_row),
            Err(ReservationError::SnapshotMismatch)
        ));
        assert_eq!(store.rows[&binding].state, ReservationState::Live);
        store.compare_and_apply_production(terminal_tx).unwrap();
        assert_eq!(
            store.business.as_ref(),
            Some(admission_business_reservation(&admitted).expected())
        );
        assert!(store.business_reservation.is_none());
        validate_production_snapshot_with_floors(
            &store.rows.values().cloned().collect::<Vec<_>>(),
            &store.floors.values().copied().collect::<Vec<_>>(),
            &store
                .retirement_cursors
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            store.witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();

        let reclaim = prepare_production_reclaim(
            &store.rows,
            aged_maintenance_time(),
            store.witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(reclaim.selected(), 1);
        store
            .compare_and_apply_production(reclaim.transaction.clone())
            .unwrap();
        let next_floor = floor.advance_to(1).unwrap();
        let retire = prepare_production_retirement(
            ProductionRetirementPrefix::new(
                floor,
                next_floor,
                &retirement_selected_prefix(&store.rows, floor, next_floor, None),
                true,
            )
            .unwrap(),
            floor,
            next_floor,
            None,
            store.witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let mut wrong_floor = retire.clone();
        wrong_floor.floor.as_mut().unwrap().expected = Some(next_floor);
        assert!(matches!(
            store.compare_and_apply_production(wrong_floor),
            Err(ReservationError::FloorAdvance)
        ));
        assert!(store.rows.contains_key(&binding));
        store.compare_and_apply_production(retire).unwrap();
        assert!(store.rows.is_empty());
        assert_eq!(store.witness.roster.floor_count(), 1);
        assert_eq!(store.witness.roster.durable_epoch_bindings(), 0);
    }

    #[test]
    fn adapter_failure_at_every_stage_rolls_back_admission_row_reservation_floor_and_witness() {
        let profile = profile();
        let admitted = admission(44);
        let record = live(&admitted, 1, profile);
        let expected_business = record
            .business_reservation
            .as_ref()
            .unwrap()
            .expected
            .clone();
        let transaction = prepare_production_admission(
            None,
            record,
            None,
            None,
            empty_witness(),
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();

        for stage in [
            AdapterStage::Row,
            AdapterStage::Business,
            AdapterStage::Floor,
            AdapterStage::Witness,
        ] {
            let mut store = InMemoryProductionStore {
                rows: BTreeMap::new(),
                witness: empty_witness(),
                floors: BTreeMap::new(),
                retirement_cursors: BTreeMap::new(),
                business: Some(expected_business.clone()),
                business_reservation: None,
                fail_at: Some(stage),
            };
            assert!(store
                .compare_and_apply_production(transaction.clone())
                .is_err());
            assert!(store.rows.is_empty());
            assert!(store.floors.is_empty());
            assert_eq!(store.business.as_ref(), Some(&expected_business));
            assert!(store.business_reservation.is_none());
            assert_eq!(store.witness, empty_witness());
        }
    }

    #[test]
    fn reclaim_requires_exact_24_hour_boundary_with_nanosecond_precision() {
        let profile = profile();
        let admitted = admission(45);
        let mut retained = live(&admitted, 1, profile);
        retained.terminalize(&terminal(&admitted), profile).unwrap();
        let exact = retained
            .terminalized_at
            .unwrap()
            .checked_add_retention()
            .unwrap();
        let just_young = ConsensusMaintenanceTimestamp(exact.0 - 1);

        assert!(matches!(
            retained.clone().reclaim_at(just_young, profile),
            Err(ReservationError::NotEligible)
        ));
        let mut reclaimed = retained;
        reclaimed.reclaim_at(exact, profile).unwrap();
        assert_eq!(reclaimed.state, ReservationState::Tombstone);
    }

    #[test]
    fn retirement_can_jump_sparse_epochs_but_never_crosses_a_live_binding() {
        let profile = profile();
        let admitted = admission(46);
        let mut tombstone = live(&admitted, 5, profile);
        tombstone
            .terminalize(&terminal_at(&admitted, 5), profile)
            .unwrap();
        tombstone
            .reclaim_at(aged_maintenance_time(), profile)
            .unwrap();
        let previous = IrreversibleHistoryFloor::initial(tombstone.binding).unwrap();
        let sparse_next = previous.advance_to(5).unwrap();
        let sparse_records = BTreeMap::from([(tombstone.binding, tombstone.clone())]);
        let sparse_witness = GlobalChargeWitness::v1(
            0,
            0,
            counters_with_production_floor(
                validate_production_snapshot(std::slice::from_ref(&tombstone), profile).unwrap(),
                previous,
            )
            .unwrap(),
        );
        assert!(prepare_production_retirement(
            ProductionRetirementPrefix::new(
                previous,
                sparse_next,
                &retirement_selected_prefix(&sparse_records, previous, sparse_next, None),
                true,
            )
            .unwrap(),
            previous,
            sparse_next,
            None,
            sparse_witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .is_ok());

        let live_binding = live(&admitted, 6, profile);
        let records = BTreeMap::from([
            (tombstone.binding, tombstone),
            (live_binding.binding, live_binding),
        ]);
        let crossing_witness = GlobalChargeWitness::v1(
            0,
            0,
            counters_with_production_floor(
                validate_production_snapshot(
                    &records.values().cloned().collect::<Vec<_>>(),
                    profile,
                )
                .unwrap(),
                previous,
            )
            .unwrap(),
        );
        let crossing = previous.advance_to(6).unwrap();
        assert!(matches!(
            prepare_production_retirement(
                ProductionRetirementPrefix::new(
                    previous,
                    crossing,
                    &retirement_selected_prefix(&records, previous, crossing, None),
                    true,
                )
                .unwrap(),
                previous,
                crossing,
                None,
                crossing_witness,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::FloorAdvance)
        ));
    }

    #[test]
    fn retirement_deletes_every_tombstone_at_its_lowest_epoch_even_above_reclaim_batch() {
        let profile = profile();
        let epoch = 7;
        let mut records = BTreeMap::new();
        let mut floors = None;
        for identity in 0..=RECLAIM_BATCH {
            let admitted = admission(identity as u16);
            let mut record = live(&admitted, epoch, profile);
            record
                .terminalize(&terminal_at(&admitted, epoch), profile)
                .unwrap();
            record.reclaim_at(aged_maintenance_time(), profile).unwrap();
            floors.get_or_insert(IrreversibleHistoryFloor::initial(record.binding).unwrap());
            records.insert(record.binding, record);
        }
        let previous = floors.unwrap();
        let next = previous.advance_to(epoch).unwrap();
        let witness = GlobalChargeWitness::v1(
            0,
            0,
            counters_with_production_floor(
                validate_production_snapshot(
                    &records.values().cloned().collect::<Vec<_>>(),
                    profile,
                )
                .unwrap(),
                previous,
            )
            .unwrap(),
        );
        let first = prepare_production_retirement(
            ProductionRetirementPrefix::new(
                previous,
                next,
                &retirement_selected_prefix(&records, previous, next, None),
                false,
            )
            .unwrap(),
            previous,
            next,
            None,
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(first.rows().len(), RECLAIM_BATCH);
        assert!(first.rows().len() <= RECLAIM_BATCH);
        assert!(first
            .partition_range_guard()
            .is_some_and(|guard| guard.selected().len() <= RECLAIM_BATCH));
        assert!(first.floor.is_none());
        let cursor = first
            .retirement_cursor
            .as_ref()
            .and_then(|cas| cas.replacement.clone())
            .unwrap();
        for row in first.rows() {
            records.remove(&row.binding);
        }
        let final_batch = prepare_production_retirement(
            ProductionRetirementPrefix::new(
                previous,
                next,
                &retirement_selected_prefix(&records, previous, next, Some(&cursor)),
                true,
            )
            .unwrap(),
            previous,
            next,
            Some(&cursor),
            first.next_witness(),
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(final_batch.rows().len(), 1);
        assert!(final_batch.rows().len() <= RECLAIM_BATCH);
        assert!(final_batch
            .partition_range_guard()
            .is_some_and(|guard| guard.selected().len() <= RECLAIM_BATCH));
        assert!(final_batch.floor.is_some());
        assert!(final_batch
            .retirement_cursor
            .as_ref()
            .is_some_and(|cas| cas.replacement.is_none()));
    }

    #[test]
    fn adapter_rejects_retirement_when_the_prepared_range_omits_a_live_row() {
        let profile = profile();
        let tombstone_admission = admission(47);
        let live_admission = admission(48);
        let mut tombstone = live(&tombstone_admission, 5, profile);
        tombstone
            .terminalize(&terminal_at(&tombstone_admission, 5), profile)
            .unwrap();
        tombstone
            .reclaim_at(aged_maintenance_time(), profile)
            .unwrap();
        let live_row = live(&live_admission, 3, profile);
        let floor = IrreversibleHistoryFloor::initial(tombstone.binding).unwrap();
        let next = floor.advance_to(5).unwrap();
        let rows = BTreeMap::from([
            (tombstone.binding, tombstone.clone()),
            (live_row.binding, live_row),
        ]);
        let witness = GlobalChargeWitness::v1(
            0,
            0,
            counters_with_production_floor(
                validate_production_snapshot(&rows.values().cloned().collect::<Vec<_>>(), profile)
                    .unwrap(),
                floor,
            )
            .unwrap(),
        );
        let partial = BTreeMap::from([(tombstone.binding, tombstone)]);
        let transaction = prepare_production_retirement(
            ProductionRetirementPrefix::new(
                floor,
                next,
                &retirement_selected_prefix(&partial, floor, next, None),
                true,
            )
            .unwrap(),
            floor,
            next,
            None,
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let mut store = InMemoryProductionStore {
            rows: rows.clone(),
            witness,
            floors: BTreeMap::from([(ProductionFloorKey::from_floor(floor).unwrap(), floor)]),
            retirement_cursors: BTreeMap::new(),
            business: None,
            business_reservation: None,
            fail_at: None,
        };
        assert!(matches!(
            store.compare_and_apply_production(transaction),
            Err(ReservationError::SnapshotMismatch)
        ));
        assert_eq!(store.rows, rows);
        assert_eq!(
            store.floors.values().copied().collect::<Vec<_>>(),
            vec![floor]
        );
        assert_eq!(store.witness, witness);

        let first_admission = admission(70);
        let second_admission = admission(71);
        let mut first = live(&first_admission, 5, profile);
        let mut second = live(&second_admission, 5, profile);
        first
            .terminalize(&terminal_at(&first_admission, 5), profile)
            .unwrap();
        second
            .terminalize(&terminal_at(&second_admission, 5), profile)
            .unwrap();
        first.reclaim_at(aged_maintenance_time(), profile).unwrap();
        second.reclaim_at(aged_maintenance_time(), profile).unwrap();
        let tombstone_floor = IrreversibleHistoryFloor::initial(first.binding).unwrap();
        assert_eq!(
            ProductionFloorKey::from_binding(second.binding).unwrap(),
            ProductionFloorKey::from_floor(tombstone_floor).unwrap()
        );
        let tombstone_next = tombstone_floor.advance_to(5).unwrap();
        let all_tombstones = BTreeMap::from([
            (first.binding, first.clone()),
            (second.binding, second.clone()),
        ]);
        let tombstone_witness = GlobalChargeWitness::v1(
            0,
            0,
            counters_with_production_floor(
                validate_production_snapshot(
                    &all_tombstones.values().cloned().collect::<Vec<_>>(),
                    profile,
                )
                .unwrap(),
                tombstone_floor,
            )
            .unwrap(),
        );
        let partial_tombstones = BTreeMap::from([(first.binding, first)]);
        let omitted_tombstone = prepare_production_retirement(
            ProductionRetirementPrefix::new(
                tombstone_floor,
                tombstone_next,
                &retirement_selected_prefix(
                    &partial_tombstones,
                    tombstone_floor,
                    tombstone_next,
                    None,
                ),
                true,
            )
            .unwrap(),
            tombstone_floor,
            tombstone_next,
            None,
            tombstone_witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let mut tombstone_store = InMemoryProductionStore {
            rows: all_tombstones,
            witness: tombstone_witness,
            floors: BTreeMap::from([(
                ProductionFloorKey::from_floor(tombstone_floor).unwrap(),
                tombstone_floor,
            )]),
            retirement_cursors: BTreeMap::new(),
            business: None,
            business_reservation: None,
            fail_at: None,
        };
        assert!(matches!(
            tombstone_store.compare_and_apply_production(omitted_tombstone),
            Err(ReservationError::SnapshotMismatch)
        ));
    }

    #[test]
    fn cursor_blocks_admission_and_round_trips_with_its_charge_witness() {
        let profile = profile();
        let admitted = admission(49);
        let mut tombstone = live(&admitted, 4, profile);
        tombstone
            .terminalize(&terminal_at(&admitted, 4), profile)
            .unwrap();
        tombstone
            .reclaim_at(aged_maintenance_time(), profile)
            .unwrap();
        let floor = IrreversibleHistoryFloor::initial(tombstone.binding).unwrap();
        let cursor =
            ProductionRetirementCursor::initial(ProductionFloorKey::from_floor(floor).unwrap(), 4)
                .unwrap();
        let counters = counters_with_retirement_cursor(
            counters_with_production_floor(
                validate_production_snapshot(std::slice::from_ref(&tombstone), profile).unwrap(),
                floor,
            )
            .unwrap(),
            &cursor,
        )
        .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        let snapshot = ProductionSnapshot::new(
            vec![tombstone],
            vec![floor],
            vec![cursor.clone()],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let bytes = snapshot.to_canonical_bytes().unwrap();
        let restored = ProductionSnapshot::from_canonical_bytes(
            &bytes,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(restored.retirement_cursors(), std::slice::from_ref(&cursor));

        let blocked = live(&admitted, 4, profile);
        assert!(matches!(
            prepare_production_admission(
                None,
                blocked,
                Some(floor),
                Some(&cursor),
                witness,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::FloorAdvance)
        ));
    }

    #[test]
    fn restart_envelope_recomputes_witness_floors_and_committed_time() {
        let profile = profile();
        let admitted = admission(43);
        let mut retained = live(&admitted, 1, profile);
        retained.terminalize(&terminal(&admitted), profile).unwrap();
        let floor = IrreversibleHistoryFloor::initial(retained.binding).unwrap();
        let witness = GlobalChargeWitness::v1(
            0,
            0,
            counters_with_production_floor(
                validate_production_snapshot(std::slice::from_ref(&retained), profile).unwrap(),
                floor,
            )
            .unwrap(),
        );
        let snapshot = ProductionSnapshot::new(
            vec![retained.clone()],
            vec![floor],
            vec![],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let bytes = snapshot.to_canonical_bytes().unwrap();
        let rehydrated = ProductionSnapshot::from_canonical_bytes(
            &bytes,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(rehydrated.witness(), witness);
        assert_eq!(rehydrated.records(), std::slice::from_ref(&retained));

        let mut timestamp_tamper = retained;
        timestamp_tamper.terminalized_at = Some(ConsensusMaintenanceTimestamp(
            timestamp_tamper.terminalized_at.unwrap().0 + 1,
        ));
        assert!(matches!(
            ProductionSnapshot::new(
                vec![timestamp_tamper],
                vec![floor],
                vec![],
                witness,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::SnapshotMismatch)
        ));
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            ProductionSnapshot::from_canonical_bytes(
                &trailing,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::CanonicalEncoding)
        ));
    }

    #[test]
    fn snapshot_is_canonical_and_rejects_duplicate_omitted_or_oversized_sections() {
        let profile = profile();
        let first = live(&admission_for("snapshot-a", 51), 1, profile);
        let second = live(&admission_for("snapshot-b", 52), 1, profile);
        let first_floor = IrreversibleHistoryFloor::initial(first.binding).unwrap();
        let second_floor = IrreversibleHistoryFloor::initial(second.binding).unwrap();
        let counters = counters_with_production_floor(
            counters_with_production_floor(
                validate_production_snapshot(&[first.clone(), second.clone()], profile).unwrap(),
                first_floor,
            )
            .unwrap(),
            second_floor,
        )
        .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        let canonical = ProductionSnapshot::new(
            vec![first.clone(), second.clone()],
            vec![first_floor, second_floor],
            vec![],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let reordered = ProductionSnapshot::new(
            vec![second.clone(), first.clone()],
            vec![second_floor, first_floor],
            vec![],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(
            canonical.to_canonical_bytes().unwrap(),
            reordered.to_canonical_bytes().unwrap()
        );
        assert!(matches!(
            ProductionSnapshot::new(
                vec![first.clone(), second.clone()],
                vec![first_floor, first_floor],
                vec![],
                witness,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::Duplicate)
        ));
        assert!(matches!(
            ProductionSnapshot::new(
                vec![first.clone(), second.clone()],
                vec![first_floor],
                vec![],
                witness,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::FloorAdvance)
        ));

        let bytes = canonical.to_canonical_bytes().unwrap();
        let chunks = v3_chunks(&bytes);
        assert_eq!(chunks[0].0, SNAPSHOT_CHUNK_START);
        assert_eq!(chunks[1].0, SNAPSHOT_CHUNK_RECORD);
        let mut reordered_chunks = chunks.clone();
        reordered_chunks.swap(1, 2);
        assert!(matches!(
            ProductionSnapshot::from_canonical_bytes(
                &v3_stream(&reordered_chunks),
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::CanonicalEncoding)
        ));
        let mut digest_tamper = bytes.clone();
        digest_tamper[PRODUCTION_SNAPSHOT_MAGIC.len() + 7] ^= 1;
        assert!(matches!(
            ProductionSnapshot::from_canonical_bytes(
                &digest_tamper,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::CanonicalEncoding)
        ));

        let mut raw_oversized = first;
        raw_oversized.admission = vec![0; MAX_ADMISSION_CODEC_BYTES + 1];
        let raw_oversized = v3_stream(&[
            (
                SNAPSHOT_CHUNK_START,
                postcard::to_allocvec(&ProductionSnapshotStart {
                    version: PRODUCTION_SNAPSHOT_V3,
                    record_count: 1,
                    floor_count: 0,
                    cursor_count: 0,
                    witness: empty_witness(),
                })
                .unwrap(),
            ),
            (
                SNAPSHOT_CHUNK_RECORD,
                postcard::to_allocvec(&raw_oversized).unwrap(),
            ),
        ]);
        assert!(matches!(
            ProductionSnapshot::from_canonical_bytes(
                &raw_oversized,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::CanonicalEncoding)
        ));

        let oversized_outer = v3_stream(&[(
            SNAPSHOT_CHUNK_START,
            postcard::to_allocvec(&ProductionSnapshotStart {
                version: PRODUCTION_SNAPSHOT_V3,
                record_count: u32::try_from(MAX_RESERVED_AND_RETAINED + 1).unwrap(),
                floor_count: 0,
                cursor_count: 0,
                witness: empty_witness(),
            })
            .unwrap(),
        )]);
        assert!(matches!(
            ProductionSnapshot::from_canonical_bytes(
                &oversized_outer,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::CanonicalEncoding)
        ));
        assert!(MAX_PRODUCTION_SNAPSHOT_CODEC_BYTES > u64::from(u32::MAX));
    }

    #[test]
    fn same_scope_tenant_partitions_cannot_share_floor_cas() {
        let profile = profile();
        let first = live(&admission_for("tenant-a", 50), 1, profile);
        let second = live(&admission_for("tenant-b", 50), 1, profile);
        let first_floor = IrreversibleHistoryFloor::initial(first.binding).unwrap();
        let second_floor = IrreversibleHistoryFloor::initial(second.binding).unwrap();
        assert!(matches!(
            prepare_production_admission(
                None,
                second,
                Some(first_floor),
                None,
                empty_witness(),
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::FloorAdvance)
        ));
        assert_ne!(first_floor, second_floor);
    }
}

impl GlobalChargeBudget {
    /// Return the frozen ledger-global protected-roster charge budget.
    ///
    /// This bounds only canonical roster-ledger logical/schema charge. It is
    /// not a SQLite-file, global-store, allocator, or physical-snapshot cap.
    pub(crate) const fn production() -> Self {
        Self {
            version: GLOBAL_CHARGE_WITNESS_V1,
            maximum_total_charge_bytes: PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES,
        }
    }

    /// Decode a production budget claimed by a legacy caller.
    ///
    /// Kept source-compatible for callers that previously supplied the same
    /// profile constant. Production validation rejects every value other than
    /// [`PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES`]; new callers should use
    /// [`Self::production`].
    #[cfg(not(test))]
    pub(crate) const fn v1(maximum_total_charge_bytes: u64) -> Self {
        if maximum_total_charge_bytes == PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES {
            Self::production()
        } else {
            Self {
                version: GLOBAL_CHARGE_WITNESS_V1,
                maximum_total_charge_bytes,
            }
        }
    }

    /// Construct a deliberately small budget for focused accounting tests.
    #[cfg(test)]
    pub(crate) const fn v1(maximum_total_charge_bytes: u64) -> Self {
        Self {
            version: GLOBAL_CHARGE_WITNESS_V1,
            maximum_total_charge_bytes,
        }
    }

    /// Validate the immutable production profile independently of test seams.
    fn validate_frozen_profile(self) -> Result<(), ReservationError> {
        if self.version != GLOBAL_CHARGE_WITNESS_V1 {
            return Err(ReservationError::UnknownWitnessVersion);
        }
        if self.maximum_total_charge_bytes != PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES {
            return Err(ReservationError::InvalidProfile);
        }
        Ok(())
    }

    fn validate(self) -> Result<(), ReservationError> {
        if self.version != GLOBAL_CHARGE_WITNESS_V1 {
            return Err(ReservationError::UnknownWitnessVersion);
        }
        #[cfg(not(test))]
        self.validate_frozen_profile()?;
        Ok(())
    }
}

impl fmt::Debug for GlobalChargeBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GlobalChargeBudget(<redacted>)")
    }
}

/// Persisted charge witness covering the dedicated protected-roster ledger.
///
/// The two scalar charges are reserved exclusively for fixed roster-owned
/// metadata that is not represented by a reservation row. They deliberately do
/// not charge `session_records` (or any other business table): this bounded
/// witness is the frozen roster-only 256 GiB allocation, not a global store
/// accounting claim. Every roster mutation persists this witness with the
/// matching roster counters in the same entry.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GlobalChargeWitness {
    version: u16,
    fixed_roster_metadata_charge_bytes: u64,
    reserved_roster_auxiliary_charge_bytes: u64,
    roster: AggregateCounters,
}

impl GlobalChargeWitness {
    /// Initial durable witness before the first protected-roster admission.
    pub(crate) const fn empty() -> Self {
        Self::v1(0, 0, zero_counters())
    }

    /// Construct a V1 witness from fixed roster-only metadata and rows.
    pub(crate) const fn v1(
        fixed_roster_metadata_charge_bytes: u64,
        reserved_roster_auxiliary_charge_bytes: u64,
        roster: AggregateCounters,
    ) -> Self {
        Self {
            version: GLOBAL_CHARGE_WITNESS_V1,
            fixed_roster_metadata_charge_bytes,
            reserved_roster_auxiliary_charge_bytes,
            roster,
        }
    }

    fn validate_for(self, budget: GlobalChargeBudget) -> Result<(), ReservationError> {
        budget.validate()?;
        if self.version != GLOBAL_CHARGE_WITNESS_V1 {
            return Err(ReservationError::UnknownWitnessVersion);
        }
        self.total_charge_bytes()?;
        Ok(())
    }

    fn with_roster(self, roster: AggregateCounters) -> Self {
        Self { roster, ..self }
    }

    /// Return the checked aggregate charge across this complete roster ledger.
    pub(crate) fn total_charge_bytes(self) -> Result<u64, ReservationError> {
        add4(
            self.fixed_roster_metadata_charge_bytes,
            self.reserved_roster_auxiliary_charge_bytes,
            self.roster.materialized_charge_bytes,
            self.roster.reserved_future_charge_bytes,
        )
    }

    /// Encode the exact fixed witness for one SQLite consensus row.
    pub(crate) fn to_canonical_bytes(self) -> Result<Vec<u8>, ReservationError> {
        postcard::to_allocvec(&self).map_err(|_| ReservationError::CanonicalEncoding)
    }

    /// Decode and canonicalize one retained fixed witness.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReservationError> {
        let value: Self =
            postcard::from_bytes(bytes).map_err(|_| ReservationError::CanonicalEncoding)?;
        if value.to_canonical_bytes()? != bytes {
            return Err(ReservationError::CanonicalEncoding);
        }
        value.total_charge_bytes()?;
        Ok(value)
    }

    fn admits(self, budget: GlobalChargeBudget) -> Result<(), ReservationError> {
        self.validate_for(budget)?;
        if self.total_charge_bytes()? > budget.maximum_total_charge_bytes {
            return Err(ReservationError::BudgetExceeded);
        }
        Ok(())
    }
}

impl fmt::Debug for GlobalChargeWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GlobalChargeWitness(<redacted>)")
    }
}

/// Exact checkpoint plus a conservative authoritative-record header envelope.
const MAX_BUSINESS_SESSION_COPY_BYTES: usize =
    MAX_CHECKPOINT_BYTES + MAX_BUSINESS_SESSION_HEADER_BYTES;

/// Bounded future terminal evidence retained alongside the terminal receipt.
///
/// This is reserved when a live roster is admitted, even though the evidence
/// arrives only with its terminal command. The ingress request ID is fixed at
/// 16 bytes; terminal-row and receipt framing remain in their respective
/// schema-charge components below.
const MAX_TERMINAL_EVIDENCE_ENVELOPE_BYTES: usize =
    MAX_EXECUTOR_PROOF_BUNDLE_BYTES + 16 + MAX_ROSTER_INGRESS_ATTESTATION_BYTES;

/// Fixed, versioned schema charge parameters.
///
/// The values are a logical, page-rounded envelope.  They are intentionally
/// independent of SQLite pragmas, allocator state, or physical page layout.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChargeProfile {
    page_bytes: u64,
    live_row_bytes: u64,
    retained_row_bytes: u64,
    tombstone_row_bytes: u64,
    live_index_bytes: u64,
    retained_index_bytes: u64,
    tombstone_index_bytes: u64,
}

impl ChargeProfile {
    /// Return the frozen schema profile for this roster version.
    pub(crate) const fn v1() -> Self {
        Self {
            page_bytes: STORAGE_CHARGE_PAGE_BYTES,
            live_row_bytes: STORAGE_CHARGE_LIVE_ROW_BYTES,
            retained_row_bytes: STORAGE_CHARGE_RETAINED_ROW_BYTES,
            tombstone_row_bytes: STORAGE_CHARGE_TOMBSTONE_ROW_BYTES,
            live_index_bytes: STORAGE_CHARGE_LIVE_INDEX_BYTES,
            retained_index_bytes: STORAGE_CHARGE_RETAINED_INDEX_BYTES,
            tombstone_index_bytes: STORAGE_CHARGE_TOMBSTONE_INDEX_BYTES,
        }
    }

    #[cfg(test)]
    const fn test_profile(
        page_bytes: u64,
        live_row_bytes: u64,
        retained_row_bytes: u64,
        tombstone_row_bytes: u64,
        live_index_bytes: u64,
        retained_index_bytes: u64,
        tombstone_index_bytes: u64,
    ) -> Self {
        Self {
            page_bytes,
            live_row_bytes,
            retained_row_bytes,
            tombstone_row_bytes,
            live_index_bytes,
            retained_index_bytes,
            tombstone_index_bytes,
        }
    }

    fn validate(self) -> Result<(), ReservationError> {
        if self.page_bytes == 0 {
            return Err(ReservationError::InvalidProfile);
        }
        #[cfg(not(test))]
        if self != Self::v1() {
            return Err(ReservationError::InvalidProfile);
        }
        Ok(())
    }

    fn charge(self, components: ComponentBytes) -> Result<Charges, ReservationError> {
        self.validate()?;
        let live = self.page_round(add4(
            self.live_row_bytes,
            self.live_index_bytes,
            as_u64(components.canonical_admission_bytes)?,
            0,
        )?)?;
        let retained = self.page_round(add4(
            self.retained_row_bytes,
            self.retained_index_bytes,
            as_u64(components.canonical_admission_bytes)?,
            add4(
                as_u64(components.terminal_record_bytes)?,
                as_u64(components.business_session_copy_bytes)?,
                as_u64(components.composite_receipt_bytes)?,
                as_u64(components.terminal_evidence_envelope_bytes)?,
            )?,
        )?)?;
        let tombstone = self.page_round(add3(
            self.tombstone_row_bytes,
            self.tombstone_index_bytes,
            as_u64(components.tombstone_bytes)?,
        )?)?;
        let peak = live.max(retained);
        Ok(Charges {
            live,
            retained,
            tombstone,
            peak,
        })
    }

    fn page_round(self, bytes: u64) -> Result<u64, ReservationError> {
        let remainder = bytes % self.page_bytes;
        if remainder == 0 {
            Ok(bytes)
        } else {
            bytes
                .checked_add(self.page_bytes - remainder)
                .ok_or(ReservationError::Arithmetic)
        }
    }
}

impl fmt::Debug for ChargeProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChargeProfile(<redacted>)")
    }
}

/// Exact schema-component lengths committed by an admitted roster.
///
/// A live admission materializes its canonical live data and reserves enough
/// future charge to reach the larger of its live and retained durable states.
/// This is intentionally a schema envelope, not a measurement of a storage
/// engine.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ComponentBytes {
    canonical_admission_bytes: usize,
    terminal_record_bytes: usize,
    business_session_copy_bytes: usize,
    composite_receipt_bytes: usize,
    terminal_evidence_envelope_bytes: usize,
    tombstone_bytes: usize,
}

impl ComponentBytes {
    fn from_exact(
        canonical_admission_bytes: usize,
        terminal_record_bytes: usize,
        business_session_copy_bytes: usize,
        composite_receipt_bytes: usize,
        terminal_evidence_envelope_bytes: usize,
        tombstone_bytes: usize,
    ) -> Result<Self, ReservationError> {
        let result = Self {
            canonical_admission_bytes,
            terminal_record_bytes,
            business_session_copy_bytes,
            composite_receipt_bytes,
            terminal_evidence_envelope_bytes,
            tombstone_bytes,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(self) -> Result<(), ReservationError> {
        if self.canonical_admission_bytes > MAX_ADMISSION_CODEC_BYTES
            || self.terminal_record_bytes > MAX_COMMITTED_TERMINAL_CODEC_BYTES
            || self.business_session_copy_bytes > MAX_BUSINESS_SESSION_COPY_BYTES
            || self.composite_receipt_bytes > MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES
            || self.terminal_evidence_envelope_bytes > MAX_TERMINAL_EVIDENCE_ENVELOPE_BYTES
            || self.tombstone_bytes > MAX_TOMBSTONE_CODEC_BYTES
        {
            return Err(ReservationError::ComponentBounds);
        }
        Ok(())
    }
}

impl fmt::Debug for ComponentBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ComponentBytes(<redacted>)")
    }
}

/// Durable lifecycle state of a reservation record.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ReservationState {
    /// The admission row is materialized and the terminal row is reserved.
    Live,
    /// Terminal material is retained exactly through its retention interval.
    Retained,
    /// The compact conflict tombstone remains until irreversible retirement.
    Tombstone,
}

impl fmt::Debug for ReservationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReservationState(<redacted>)")
    }
}

/// Persisted aggregate counters, checked again during restart.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AggregateCounters {
    materialized_charge_bytes: u64,
    reserved_future_charge_bytes: u64,
    live_reservations: usize,
    retained_and_live_bindings: usize,
    durable_epoch_bindings: usize,
    floor_count: usize,
    floor_charge_bytes: u64,
    retirement_cursor_count: usize,
    retirement_cursor_charge_bytes: u64,
}

impl AggregateCounters {
    /// Return the number of live reservations.
    #[cfg(test)]
    pub(crate) const fn live_reservations(self) -> usize {
        self.live_reservations
    }

    /// Return the number of live and retained epoch bindings.
    #[cfg(test)]
    pub(crate) const fn retained_and_live_bindings(self) -> usize {
        self.retained_and_live_bindings
    }

    /// Return all durable epoch bindings, including compact tombstones.
    #[cfg(test)]
    pub(crate) const fn durable_epoch_bindings(self) -> usize {
        self.durable_epoch_bindings
    }

    /// Return the number of exact partition floors retained by this witness.
    #[cfg(test)]
    pub(crate) const fn floor_count(self) -> usize {
        self.floor_count
    }
}

impl fmt::Debug for AggregateCounters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AggregateCounters(<redacted>)")
    }
}

/// Consensus-derived logical time accepted by roster maintenance.
///
/// This deliberately has no integer constructor.  A maintenance caller must
/// pass a timestamp obtained from the consensus clock, so it cannot select an
/// arbitrary far-future `u64` merely to force retention reclamation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct ConsensusMaintenanceTimestamp(i128);

impl ConsensusMaintenanceTimestamp {
    /// Convert an authenticated consensus timestamp without discarding its
    /// nanosecond precision.
    pub(crate) fn from_consensus_timestamp(timestamp: Timestamp) -> Result<Self, ReservationError> {
        let nanos = timestamp.as_offset_datetime().unix_timestamp_nanos();
        if nanos < 0 {
            return Err(ReservationError::InvalidMaintenanceTime);
        }
        Ok(Self(nanos))
    }

    fn checked_add_retention(self) -> Result<Self, ReservationError> {
        self.0
            .checked_add(TERMINAL_RETENTION_NANOS)
            .map(Self)
            .ok_or(ReservationError::Arithmetic)
    }

    /// Return the exact nonnegative consensus nanosecond value for ordering.
    pub(crate) const fn as_nanos(self) -> i128 {
        self.0
    }
}

impl fmt::Debug for ConsensusMaintenanceTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsensusMaintenanceTimestamp(<redacted>)")
    }
}

/// Production durable record keyed exclusively by the roster's authenticated
/// request binding. Raw component lengths are deliberately absent.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProductionReservationRecord {
    binding: RequestBindingKey,
    admission: Vec<u8>,
    terminal: Option<Vec<u8>>,
    tombstone: Option<Vec<u8>>,
    terminalized_at: Option<ConsensusMaintenanceTimestamp>,
    business_reservation: Option<ProductionAdmissionBusinessReservation>,
    state: ReservationState,
    peak_charge_bytes: u64,
    retained_charge_bytes: u64,
    tombstone_charge_bytes: u64,
}

/// One fully validated durable roster row together with the exact bytes read
/// from SQLite. Read-side adapters retain this hydration so a status lookup
/// never reparses its potentially multi-megabyte admission or terminal body.
#[derive(Clone)]
pub(crate) struct HydratedProductionReservationRecord {
    record: ProductionReservationRecord,
    canonical: Vec<u8>,
    payload: HydratedProductionReservationPayload,
}

/// Decoded payload retained by one validated production roster row.
#[derive(Clone)]
pub(crate) enum HydratedProductionReservationPayload {
    Live {
        admission: Admission,
    },
    Retained {
        admission: Admission,
        committed_terminal: Box<CommittedTerminal>,
        committed_canonical: Vec<u8>,
    },
    Tombstone {
        tombstone: TerminalConflictTombstone,
    },
}

impl HydratedProductionReservationRecord {
    /// Return the validated durable row projection.
    pub(crate) const fn record(&self) -> &ProductionReservationRecord {
        &self.record
    }

    /// Return the exact canonical row bytes read from durable storage.
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Return the decoded payload that was validated with this row.
    pub(crate) const fn payload(&self) -> &HydratedProductionReservationPayload {
        &self.payload
    }

    /// Discard read-side hydration after a caller only needs the durable row.
    pub(crate) fn into_record(self) -> ProductionReservationRecord {
        self.record
    }

    /// Consume the complete one-pass hydration for a read-side result.
    pub(crate) fn into_parts(
        self,
    ) -> (
        ProductionReservationRecord,
        Vec<u8>,
        HydratedProductionReservationPayload,
    ) {
        (self.record, self.canonical, self.payload)
    }
}

impl<'de> Deserialize<'de> for ProductionReservationRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            binding: RequestBindingKey,
            admission: BoundedSnapshotBytes<MAX_ADMISSION_CODEC_BYTES>,
            terminal: Option<BoundedSnapshotBytes<MAX_COMMITTED_TERMINAL_CODEC_BYTES>>,
            tombstone: Option<BoundedSnapshotBytes<MAX_TOMBSTONE_CODEC_BYTES>>,
            terminalized_at: Option<ConsensusMaintenanceTimestamp>,
            business_reservation: Option<ProductionAdmissionBusinessReservation>,
            state: ReservationState,
            peak_charge_bytes: u64,
            retained_charge_bytes: u64,
            tombstone_charge_bytes: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            binding: wire.binding,
            admission: wire.admission.0,
            terminal: wire.terminal.map(|value| value.0),
            tombstone: wire.tombstone.map(|value| value.0),
            terminalized_at: wire.terminalized_at,
            business_reservation: wire.business_reservation,
            state: wire.state,
            peak_charge_bytes: wire.peak_charge_bytes,
            retained_charge_bytes: wire.retained_charge_bytes,
            tombstone_charge_bytes: wire.tombstone_charge_bytes,
        })
    }
}

impl ProductionReservationRecord {
    /// Encode one exact row for a SQLite compare-and-swap.
    pub(crate) fn to_canonical_bytes(&self) -> Result<Vec<u8>, ReservationError> {
        self.validate(ChargeProfile::v1())?;
        let bytes = postcard::to_allocvec(self).map_err(|_| ReservationError::CanonicalEncoding)?;
        if bytes.len() > MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES {
            return Err(ReservationError::ComponentBounds);
        }
        Ok(bytes)
    }

    /// Decode, bound, canonicalize, and fully validate one SQLite row while
    /// retaining its exact durable bytes and parsed payload for a read path.
    pub(crate) fn from_canonical_vec_hydrated(
        canonical: Vec<u8>,
    ) -> Result<HydratedProductionReservationRecord, ReservationError> {
        if canonical.len() > MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES {
            return Err(ReservationError::ComponentBounds);
        }
        let record: Self =
            postcard::from_bytes(&canonical).map_err(|_| ReservationError::CanonicalEncoding)?;
        let payload = record.validate_and_hydrate(ChargeProfile::v1())?;
        if postcard::to_allocvec(&record).map_err(|_| ReservationError::CanonicalEncoding)?
            != canonical
        {
            return Err(ReservationError::CanonicalEncoding);
        }
        Ok(HydratedProductionReservationRecord {
            record,
            canonical,
            payload,
        })
    }

    /// Return this row's opaque fixed binding key.
    pub(crate) const fn binding(&self) -> RequestBindingKey {
        self.binding
    }

    /// Return the durable lifecycle state used by fixed SQLite indexes.
    pub(crate) const fn state(&self) -> ReservationState {
        self.state
    }

    /// Return the consensus terminal timestamp, present only for retained rows.
    pub(crate) const fn terminalized_at(&self) -> Option<ConsensusMaintenanceTimestamp> {
        self.terminalized_at
    }

    /// Return the exact business-key reservation carried only by a live row.
    /// SQLite restart and snapshot validation compare this projection with
    /// the separate exclusion table; it is never an enumeration surface.
    pub(crate) const fn business_reservation(
        &self,
    ) -> Option<&ProductionAdmissionBusinessReservation> {
        self.business_reservation.as_ref()
    }

    /// Rehydrate the exact immutable admission retained by consensus.
    ///
    /// Storage adapters use this seam for status/recovery and for the compact
    /// terminal command, which deliberately does not carry a second copy of
    /// the potentially multi-megabyte admission body.
    pub(crate) fn admission(&self) -> Result<Admission, ReservationError> {
        Admission::from_canonical_bytes(&self.admission)
            .map_err(|_| ReservationError::CanonicalEncoding)
    }

    /// Rehydrate the exact terminal composite retained with this row.
    /// Live rows return `None`; retained rows return their byte-identical
    /// Established or Aborted receipt, including protected checkpoint/result.
    pub(crate) fn committed_terminal(&self) -> Result<Option<CommittedTerminal>, ReservationError> {
        let Some(bytes) = self.terminal.as_deref() else {
            return Ok(None);
        };
        let admission = self.admission()?;
        CommittedTerminal::from_canonical_bytes(bytes, &admission)
            .map(Some)
            .map_err(|_| ReservationError::CanonicalEncoding)
    }

    /// Rehydrate the exact compact conflict evidence retained after terminal
    /// payload reclamation. Non-tombstone rows return `None`; a malformed or
    /// binding-mismatched tombstone fails closed instead of being exposed as
    /// conclusive history.
    pub(crate) fn tombstone(&self) -> Result<Option<TerminalConflictTombstone>, ReservationError> {
        if self.state != ReservationState::Tombstone {
            return if self.tombstone.is_none() {
                Ok(None)
            } else {
                Err(ReservationError::StateShape)
            };
        }
        let bytes = self
            .tombstone
            .as_deref()
            .ok_or(ReservationError::StateShape)?;
        let tombstone = TerminalConflictTombstone::from_canonical_bytes(bytes)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        if tombstone.binding_key() != self.binding {
            return Err(ReservationError::SnapshotMismatch);
        }
        Ok(Some(tombstone))
    }

    /// Build a live durable record from one SDK-authenticated admission.
    pub(crate) fn live(
        admission: &Admission,
        epoch: u64,
        business_reservation: ProductionAdmissionBusinessReservation,
        profile: ChargeProfile,
    ) -> Result<Self, ReservationError> {
        validate_epoch(epoch)?;
        let admission_bytes = admission
            .to_canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let binding = admission
            .binding_key(epoch)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let charges = profile.charge(production_components(&admission_bytes, None, None)?)?;
        business_reservation.validate_for(admission)?;
        Ok(Self {
            binding,
            admission: admission_bytes,
            terminal: None,
            tombstone: None,
            terminalized_at: None,
            business_reservation: Some(business_reservation),
            state: ReservationState::Live,
            peak_charge_bytes: charges.peak,
            retained_charge_bytes: charges.retained,
            tombstone_charge_bytes: charges.tombstone,
        })
    }

    /// Consume the pre-reserved admission peak using an exact terminal frame.
    pub(crate) fn terminalize(
        &mut self,
        terminal: &CommittedTerminal,
        profile: ChargeProfile,
    ) -> Result<(), ReservationError> {
        if self.state != ReservationState::Live {
            return Err(ReservationError::InvalidState);
        }
        let admission = Admission::from_canonical_bytes(&self.admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        if admission
            .binding_key(self.binding.history_epoch())
            .map_err(|_| ReservationError::CanonicalEncoding)?
            != self.binding
            || terminal.record().request_id().history_epoch() != self.binding.history_epoch()
        {
            return Err(ReservationError::SnapshotMismatch);
        }
        let terminal_bytes = terminal
            .to_canonical_bytes(&admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let live = profile.charge(production_components(&self.admission, None, None)?)?;
        let retained = profile.charge(production_components(
            &self.admission,
            Some(&terminal_bytes),
            None,
        )?)?;
        if self.peak_charge_bytes != live.peak || retained.retained > self.peak_charge_bytes {
            return Err(ReservationError::SnapshotMismatch);
        }
        self.terminal = Some(terminal_bytes);
        self.terminalized_at = Some(ConsensusMaintenanceTimestamp::from_consensus_timestamp(
            terminal.commit_metadata().committed_at(),
        )?);
        self.business_reservation = None;
        self.state = ReservationState::Retained;
        self.retained_charge_bytes = retained.retained;
        Ok(())
    }

    fn validate(&self, profile: ChargeProfile) -> Result<(), ReservationError> {
        self.validate_and_hydrate(profile).map(|_| ())
    }

    /// Validate every durable invariant while retaining the decoded payload
    /// needed by a hot status read. This remains the same validation boundary
    /// used by writes, restart scans, and snapshot installation.
    fn validate_and_hydrate(
        &self,
        profile: ChargeProfile,
    ) -> Result<HydratedProductionReservationPayload, ReservationError> {
        validate_epoch(self.binding.history_epoch())?;
        if self.state == ReservationState::Tombstone {
            if !self.admission.is_empty()
                || self.terminal.is_some()
                || self.terminalized_at.is_some()
                || self.business_reservation.is_some()
            {
                return Err(ReservationError::StateShape);
            }
            let tombstone = self
                .tombstone
                .as_deref()
                .ok_or(ReservationError::StateShape)?;
            let decoded = TerminalConflictTombstone::from_canonical_bytes(tombstone)
                .map_err(|_| ReservationError::CanonicalEncoding)?;
            if decoded.binding_key() != self.binding {
                return Err(ReservationError::SnapshotMismatch);
            }
            let charges = profile.charge(production_components(&[], None, Some(tombstone))?)?;
            return if self.peak_charge_bytes == 0
                && self.retained_charge_bytes == 0
                && self.tombstone_charge_bytes == charges.tombstone
            {
                Ok(HydratedProductionReservationPayload::Tombstone { tombstone: decoded })
            } else {
                Err(ReservationError::SnapshotMismatch)
            };
        }
        let admission = Admission::from_canonical_bytes(&self.admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        if admission
            .binding_key(self.binding.history_epoch())
            .map_err(|_| ReservationError::CanonicalEncoding)?
            != self.binding
        {
            return Err(ReservationError::SnapshotMismatch);
        }
        match self.state {
            ReservationState::Live => self
                .business_reservation
                .as_ref()
                .ok_or(ReservationError::StateShape)?
                .validate_for(&admission)?,
            ReservationState::Retained if self.business_reservation.is_none() => {}
            _ => return Err(ReservationError::StateShape),
        }
        match self.state {
            ReservationState::Live
                if self.terminal.is_none()
                    && self.tombstone.is_none()
                    && self.terminalized_at.is_none() =>
            {
                let charges =
                    profile.charge(production_components(&self.admission, None, None)?)?;
                if self.peak_charge_bytes == charges.peak
                    && self.retained_charge_bytes == charges.retained
                    && self.tombstone_charge_bytes == charges.tombstone
                {
                    Ok(HydratedProductionReservationPayload::Live { admission })
                } else {
                    Err(ReservationError::SnapshotMismatch)
                }
            }
            ReservationState::Retained
                if self.tombstone.is_none() && self.terminalized_at.is_some() =>
            {
                let terminal = self
                    .terminal
                    .as_deref()
                    .ok_or(ReservationError::StateShape)?;
                let decoded = CommittedTerminal::from_canonical_bytes(terminal, &admission)
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                if decoded.record().request_id().history_epoch() != self.binding.history_epoch() {
                    return Err(ReservationError::SnapshotMismatch);
                }
                let committed_at = ConsensusMaintenanceTimestamp::from_consensus_timestamp(
                    decoded.commit_metadata().committed_at(),
                )?;
                if self.terminalized_at != Some(committed_at) {
                    return Err(ReservationError::SnapshotMismatch);
                }
                let live = profile.charge(production_components(&self.admission, None, None)?)?;
                let retained = profile.charge(production_components(
                    &self.admission,
                    Some(terminal),
                    None,
                )?)?;
                if self.peak_charge_bytes == live.peak
                    && self.retained_charge_bytes == retained.retained
                    && self.tombstone_charge_bytes == retained.tombstone
                {
                    Ok(HydratedProductionReservationPayload::Retained {
                        admission,
                        committed_terminal: Box::new(decoded),
                        committed_canonical: terminal.to_vec(),
                    })
                } else {
                    Err(ReservationError::SnapshotMismatch)
                }
            }
            ReservationState::Tombstone => Err(ReservationError::StateShape),
            _ => Err(ReservationError::StateShape),
        }
    }

    fn reclaim_at(
        &mut self,
        maintenance_time: ConsensusMaintenanceTimestamp,
        profile: ChargeProfile,
    ) -> Result<(), ReservationError> {
        if self.state != ReservationState::Retained {
            return Err(ReservationError::InvalidState);
        }
        let terminalized_at = self.terminalized_at.ok_or(ReservationError::StateShape)?;
        if terminalized_at.checked_add_retention()? > maintenance_time {
            return Err(ReservationError::NotEligible);
        }
        let admission = Admission::from_canonical_bytes(&self.admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let terminal_bytes = self
            .terminal
            .as_deref()
            .ok_or(ReservationError::StateShape)?;
        let terminal = CommittedTerminal::from_canonical_bytes(terminal_bytes, &admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let tombstone = TerminalConflictTombstone::new(&admission, terminal.record())
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        if tombstone.binding_key() != self.binding {
            return Err(ReservationError::SnapshotMismatch);
        }
        let tombstone_bytes = tombstone
            .to_canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let charges = profile.charge(production_components(&[], None, Some(&tombstone_bytes))?)?;
        self.admission.clear();
        self.terminal = None;
        self.tombstone = Some(tombstone_bytes);
        self.terminalized_at = None;
        self.business_reservation = None;
        self.state = ReservationState::Tombstone;
        self.peak_charge_bytes = 0;
        self.retained_charge_bytes = 0;
        self.tombstone_charge_bytes = charges.tombstone;
        Ok(())
    }
}

impl fmt::Debug for ProductionReservationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionReservationRecord(<redacted>)")
    }
}

fn production_components(
    admission: &[u8],
    terminal: Option<&[u8]>,
    tombstone: Option<&[u8]>,
) -> Result<ComponentBytes, ReservationError> {
    ComponentBytes::from_exact(
        admission.len(),
        terminal.map_or(MAX_COMMITTED_TERMINAL_CODEC_BYTES, <[u8]>::len),
        MAX_BUSINESS_SESSION_COPY_BYTES,
        MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES,
        MAX_TERMINAL_EVIDENCE_ENVELOPE_BYTES,
        tombstone.map_or(MAX_TOMBSTONE_CODEC_BYTES, <[u8]>::len),
    )
}

/// Pure, prevalidated deterministic retained-to-tombstone batch.
///
/// The adapter compares every `rows` entry before it makes any replacement.
/// This makes a malformed or stale later row fail the entire reclaim batch.
#[derive(Clone)]
pub(crate) struct PreparedProductionReclaim {
    transaction: PreparedProductionTransaction,
}

impl PreparedProductionReclaim {
    pub(crate) fn transaction(&self) -> &PreparedProductionTransaction {
        &self.transaction
    }

    pub(crate) fn selected(&self) -> usize {
        self.transaction.rows.len()
    }
}

/// Opaque proof obligation for a reclaim prefix.
///
/// It is constructed only while preparing a bounded sorted prefix and carried
/// inside the all-or-none transaction. A storage adapter must re-evaluate the
/// indexed eligible-retained order against its own authoritative rows before
/// applying the CASes; a caller-provided `BTreeMap` is therefore never the
/// authority for what was oldest.
#[derive(Clone)]
pub(crate) struct ProductionReclaimOldestGuard {
    maintenance_time: ConsensusMaintenanceTimestamp,
    selected: Vec<(ConsensusMaintenanceTimestamp, RequestBindingKey)>,
}

impl ProductionReclaimOldestGuard {
    fn new(
        maintenance_time: ConsensusMaintenanceTimestamp,
        selected: Vec<(ConsensusMaintenanceTimestamp, RequestBindingKey)>,
    ) -> Result<Self, ReservationError> {
        if selected.len() > RECLAIM_BATCH || selected.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ReservationError::SnapshotMismatch);
        }
        Ok(Self {
            maintenance_time,
            selected,
        })
    }

    /// Consensus time used to test the fixed terminal retention interval.
    pub(crate) const fn maintenance_time(&self) -> ConsensusMaintenanceTimestamp {
        self.maintenance_time
    }

    /// Exact globally-oldest eligible retained prefix expected by the adapter.
    pub(crate) fn selected(&self) -> &[(ConsensusMaintenanceTimestamp, RequestBindingKey)] {
        &self.selected
    }
}

impl fmt::Debug for ProductionReclaimOldestGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionReclaimOldestGuard(<redacted>)")
    }
}

impl fmt::Debug for PreparedProductionReclaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedProductionReclaim(<redacted>)")
    }
}

/// Prepare, but do not mutate, the oldest eligible retained rows.
///
/// Terminal time is authenticated by the retained `CommittedTerminal` frame;
/// the maintenance value merely chooses which already committed rows have
/// reached their fixed age.  Ordering is `(terminalized_at, binding)` and the
/// exact batch is `min(RECLAIM_BATCH, eligible)`.
pub(crate) fn prepare_production_reclaim(
    records: &BTreeMap<RequestBindingKey, ProductionReservationRecord>,
    maintenance_time: ConsensusMaintenanceTimestamp,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionReclaim, ReservationError> {
    witness.admits(budget)?;
    let mut eligible = Vec::new();
    for (binding, record) in records.iter() {
        if record.state == ReservationState::Retained {
            let terminalized_at = record.terminalized_at.ok_or(ReservationError::StateShape)?;
            if terminalized_at.checked_add_retention()? <= maintenance_time {
                eligible.push((terminalized_at, *binding));
            }
        }
    }
    eligible.sort_unstable();
    let selected = eligible.len().min(RECLAIM_BATCH);
    let oldest_guard = ProductionReclaimOldestGuard::new(
        maintenance_time,
        eligible.iter().copied().take(selected).collect(),
    )?;
    let mut next_counters = witness.roster;
    let mut rows = Vec::with_capacity(selected);
    for (_, binding) in eligible.into_iter().take(selected) {
        let current = records
            .get(&binding)
            .ok_or(ReservationError::SnapshotMismatch)?;
        current.validate(profile)?;
        let mut replacement = current.clone();
        replacement.reclaim_at(maintenance_time, profile)?;
        next_counters = counters_without_production_record(next_counters, current, profile)?;
        next_counters = counters_with_production_record(next_counters, &replacement, profile)?;
        rows.push(ProductionRowCas {
            binding,
            expected: Some(current.clone()),
            replacement: Some(replacement),
        });
    }
    let next = witness.with_roster(next_counters);
    next.admits(budget)?;
    Ok(PreparedProductionReclaim {
        transaction: PreparedProductionTransaction {
            canonical_rows_validated: u32::try_from(selected)
                .map_err(|_| ReservationError::Arithmetic)?,
            rows,
            previous: witness,
            next,
            floor: None,
            retirement_cursor: None,
            partition_guard: None,
            reclaim_oldest_guard: Some(oldest_guard),
            admission_business_reservation: None,
            business: None,
        },
    })
}

#[cfg(test)]
fn reclaim_oldest_eligible(
    records: &mut BTreeMap<RequestBindingKey, ProductionReservationRecord>,
    maintenance_time: ConsensusMaintenanceTimestamp,
    profile: ChargeProfile,
) -> Result<usize, ReservationError> {
    let counters =
        validate_production_snapshot(&records.values().cloned().collect::<Vec<_>>(), profile)?;
    let prepared = prepare_production_reclaim(
        records,
        maintenance_time,
        GlobalChargeWitness::v1(0, 0, counters),
        GlobalChargeBudget::v1(u64::MAX),
        profile,
    )?;
    for row in &prepared.transaction.rows {
        let current = records
            .get(&row.binding)
            .ok_or(ReservationError::SnapshotMismatch)?;
        if row.expected.as_ref() != Some(current) {
            return Err(ReservationError::SnapshotMismatch);
        }
    }
    for row in &prepared.transaction.rows {
        let replacement = row
            .replacement
            .clone()
            .ok_or(ReservationError::InvalidState)?;
        records.insert(row.binding, replacement);
    }
    Ok(prepared.selected())
}

/// Recompute production counters after canonical-frame validation.
///
/// The length guard runs before any identity-index allocation. Each decoder
/// rejects truncated, trailing, and noncanonical frames; duplicate bindings
/// and cross-lifecycle aliases are rejected before the result is returned.
pub(crate) fn validate_production_snapshot(
    records: &[ProductionReservationRecord],
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    if records.len() > MAX_RESERVED_AND_RETAINED {
        return Err(ReservationError::DurableBindingLimit);
    }
    let mut seen = BTreeMap::new();
    // A live roster is also an exact business-row reservation.  The binding
    // includes the history epoch, so binding uniqueness alone would otherwise
    // accept two simultaneous live reservations for one authoritative key.
    let mut seen_business_keys = BTreeMap::new();
    let mut counters = AggregateCounters {
        materialized_charge_bytes: 0,
        reserved_future_charge_bytes: 0,
        live_reservations: 0,
        retained_and_live_bindings: 0,
        durable_epoch_bindings: 0,
        floor_count: 0,
        floor_charge_bytes: 0,
        retirement_cursor_count: 0,
        retirement_cursor_charge_bytes: 0,
    };
    for record in records {
        record.validate(profile)?;
        if seen.insert(record.binding, record.state).is_some() {
            return Err(ReservationError::Duplicate);
        }
        if record.state == ReservationState::Live {
            let reservation = record
                .business_reservation
                .as_ref()
                .ok_or(ReservationError::StateShape)?;
            if seen_business_keys
                .insert(
                    reservation.expected.key.canonical_digest_input(),
                    (record.binding, reservation.admission_commitment),
                )
                .is_some()
            {
                return Err(ReservationError::Duplicate);
            }
        }
        let charges = match record.state {
            ReservationState::Live => {
                profile.charge(production_components(&record.admission, None, None)?)?
            }
            ReservationState::Retained => profile.charge(production_components(
                &record.admission,
                record.terminal.as_deref(),
                None,
            )?)?,
            ReservationState::Tombstone => profile.charge(production_components(
                &[],
                None,
                record.tombstone.as_deref(),
            )?)?,
        };
        counters = counters_for_record(counters, record.state, charges)?;
        if counters.live_reservations > MAX_LIVE_ROSTERS {
            return Err(ReservationError::LiveLimit);
        }
        if counters.retained_and_live_bindings > MAX_RESERVED_AND_RETAINED {
            return Err(ReservationError::BindingLimit);
        }
    }
    Ok(counters)
}

/// Recompute a restart snapshot and require its persisted global witness to match.
#[cfg(test)]
pub(crate) fn validate_production_snapshot_witness(
    records: &[ProductionReservationRecord],
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    let counters = validate_production_snapshot(records, profile)?;
    witness.admits(budget)?;
    if witness.roster != counters {
        return Err(ReservationError::WitnessMismatch);
    }
    Ok(counters)
}

/// Restart/follower validation with the exact persisted tenant/scope floors.
///
/// Every durable row, including a tombstone, must remain strictly above its
/// partition floor.  A transaction that advances a floor therefore deletes all
/// covered tombstones in the same linearization; a partial floor/row snapshot
/// is never accepted after restart.
pub(crate) fn validate_production_snapshot_with_floors(
    records: &[ProductionReservationRecord],
    floors: &[IrreversibleHistoryFloor],
    retirement_cursors: &[ProductionRetirementCursor],
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    let mut counters = validate_production_snapshot(records, profile)?;
    if floors.len() > MAX_RESERVED_AND_RETAINED {
        return Err(ReservationError::FloorLimit);
    }
    let mut floor_index = BTreeMap::new();
    for floor in floors {
        let key = ProductionFloorKey::from_floor(*floor)?;
        if floor_index.insert(key, *floor).is_some() {
            return Err(ReservationError::Duplicate);
        }
        counters = counters_with_production_floor(counters, *floor)?;
    }
    if retirement_cursors.len() > MAX_RESERVED_AND_RETAINED {
        return Err(ReservationError::FloorLimit);
    }
    let mut cursor_index = BTreeMap::new();
    for cursor in retirement_cursors {
        let floor = floor_index
            .get(&cursor.key)
            .ok_or(ReservationError::FloorAdvance)?;
        cursor.validate_for_floor(*floor)?;
        if cursor_index.insert(cursor.key, cursor).is_some() {
            return Err(ReservationError::Duplicate);
        }
        counters = counters_with_retirement_cursor(counters, cursor)?;
    }
    let mut used_floors = BTreeMap::new();
    let mut used_cursors = BTreeMap::new();
    for record in records {
        let key = ProductionFloorKey::from_binding(record.binding)?;
        let floor = floor_index
            .get(&key)
            .ok_or(ReservationError::FloorAdvance)?;
        floor
            .validate_new_binding(record.binding)
            .map_err(|_| ReservationError::FloorAdvance)?;
        if let Some(cursor) = cursor_index.get(&key) {
            if record.binding.history_epoch() <= cursor.target_epoch {
                if record.state != ReservationState::Tombstone
                    || record.binding.history_epoch() != cursor.target_epoch
                    || cursor
                        .last_deleted
                        .is_some_and(|last| record.binding <= last)
                {
                    return Err(ReservationError::FloorAdvance);
                }
                used_cursors.insert(key, ());
            }
        }
        used_floors.insert(key, ());
    }
    for (key, floor) in floor_index {
        // A nonzero floor is still meaningful after retirement deletes the
        // final tombstone in its partition.  A zero initial floor without a
        // row is instead an unused, accidentally persisted partition.
        if !used_floors.contains_key(&key) && floor.retired_through() == 0 {
            return Err(ReservationError::FloorAdvance);
        }
    }
    for key in cursor_index.keys() {
        if !used_cursors.contains_key(key) {
            return Err(ReservationError::FloorAdvance);
        }
    }
    witness.admits(budget)?;
    if witness.roster != counters {
        return Err(ReservationError::WitnessMismatch);
    }
    Ok(counters)
}

#[cfg(test)]
const PRODUCTION_SNAPSHOT_V3: u16 = 3;

/// The first digest-covered chunk fixes bounded section counts and the exact
/// global witness. Every following chunk is independently length-framed, so
/// a maximal snapshot never needs one 32-bit postcard body.
#[cfg(test)]
#[derive(Clone, Copy, Serialize, Deserialize)]
struct ProductionSnapshotStart {
    version: u16,
    record_count: u32,
    floor_count: u32,
    cursor_count: u32,
    witness: GlobalChargeWitness,
}

/// Decoder-only byte wrapper that rejects a claimed oversized sequence before
/// reserving capacity and bounds every allocation by the frozen field limit.
struct BoundedSnapshotBytes<const MAX: usize>(Vec<u8>);

impl<'de, const MAX: usize> Deserialize<'de> for BoundedSnapshotBytes<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor<const MAX: usize>;
        impl<'de, const MAX: usize> Visitor<'de> for BytesVisitor<MAX> {
            type Value = BoundedSnapshotBytes<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "at most {MAX} bounded snapshot bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                if value.len() > MAX {
                    return Err(E::custom("bounded snapshot bytes"));
                }
                Ok(BoundedSnapshotBytes(value.to_vec()))
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                if sequence.size_hint().is_some_and(|length| length > MAX) {
                    return Err(serde::de::Error::custom("bounded snapshot bytes"));
                }
                let mut value = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
                while let Some(byte) = sequence.next_element()? {
                    if value.len() == MAX {
                        return Err(serde::de::Error::custom("bounded snapshot bytes"));
                    }
                    value.push(byte);
                }
                Ok(BoundedSnapshotBytes(value))
            }
        }
        deserializer.deserialize_seq(BytesVisitor::<MAX>)
    }
}

/// Test-only canonical restart-envelope codec.
///
/// SQLite restart and follower validation use the production row, floor,
/// cursor, and witness codecs directly. This aggregate stream remains as a
/// codec-conformance fixture over that same durable state.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ProductionSnapshot {
    records: Vec<ProductionReservationRecord>,
    floors: Vec<IrreversibleHistoryFloor>,
    retirement_cursors: Vec<ProductionRetirementCursor>,
    witness: GlobalChargeWitness,
}

#[cfg(test)]
impl ProductionSnapshot {
    pub(crate) fn new(
        mut records: Vec<ProductionReservationRecord>,
        mut floors: Vec<IrreversibleHistoryFloor>,
        mut retirement_cursors: Vec<ProductionRetirementCursor>,
        witness: GlobalChargeWitness,
        budget: GlobalChargeBudget,
        profile: ChargeProfile,
    ) -> Result<Self, ReservationError> {
        records.sort_unstable_by_key(|record| record.binding);
        let mut keyed_floors = floors
            .into_iter()
            .map(|floor| Ok((ProductionFloorKey::from_floor(floor)?, floor)))
            .collect::<Result<Vec<_>, ReservationError>>()?;
        keyed_floors.sort_unstable_by_key(|(key, _)| *key);
        floors = keyed_floors.into_iter().map(|(_, floor)| floor).collect();
        retirement_cursors.sort_unstable_by_key(|cursor| (cursor.key, cursor.target_epoch));
        validate_production_snapshot_with_floors(
            &records,
            &floors,
            &retirement_cursors,
            witness,
            budget,
            profile,
        )?;
        Ok(Self {
            records,
            floors,
            retirement_cursors,
            witness,
        })
    }

    /// Yield bounded canonical V3 chunks without materializing one giant
    /// postcard frame; the final chunk authenticates all preceding bytes.
    pub(crate) fn canonical_chunks(&self) -> ProductionSnapshotChunks<'_> {
        ProductionSnapshotChunks::new(self)
    }

    /// Collect a V3 stream only when it is representable by this process.
    ///
    /// Large valid snapshots are intentionally supported through
    /// [`Self::canonical_chunks`]. This convenience path never truncates or
    /// silently wraps a length on a 32-bit host.
    pub(crate) fn to_canonical_bytes(&self) -> Result<Vec<u8>, ReservationError> {
        let mut bytes = Vec::new();
        let mut total = 0u64;
        for chunk in self.canonical_chunks() {
            let chunk = chunk?;
            total = total
                .checked_add(as_u64(chunk.len())?)
                .ok_or(ReservationError::CanonicalEncoding)?;
            if total > MAX_PRODUCTION_SNAPSHOT_CODEC_BYTES {
                return Err(ReservationError::CanonicalEncoding);
            }
            usize::try_from(total).map_err(|_| ReservationError::CanonicalEncoding)?;
            bytes
                .try_reserve(chunk.len())
                .map_err(|_| ReservationError::CanonicalEncoding)?;
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
        budget: GlobalChargeBudget,
        profile: ChargeProfile,
    ) -> Result<Self, ReservationError> {
        budget.validate()?;
        let total_input = as_u64(bytes.len())?;
        if total_input > MAX_PRODUCTION_SNAPSHOT_CODEC_BYTES
            || total_input > budget.maximum_total_charge_bytes
            || !bytes.starts_with(&PRODUCTION_SNAPSHOT_MAGIC)
        {
            return Err(ReservationError::CanonicalEncoding);
        }
        let mut offset = PRODUCTION_SNAPSHOT_MAGIC.len();
        let mut charged = as_u64(offset)?;
        let (tag, payload, frame_end) = read_snapshot_chunk(bytes, offset, &mut charged, budget)?;
        if tag != SNAPSHOT_CHUNK_START || payload.len() > SNAPSHOT_START_MAX_BYTES {
            return Err(ReservationError::CanonicalEncoding);
        }
        let start: ProductionSnapshotStart =
            postcard::from_bytes(payload).map_err(|_| ReservationError::CanonicalEncoding)?;
        if postcard::to_allocvec(&start).map_err(|_| ReservationError::CanonicalEncoding)?
            != payload
            || start.version != PRODUCTION_SNAPSHOT_V3
            || start.record_count as usize > MAX_RESERVED_AND_RETAINED
            || start.floor_count as usize > MAX_RESERVED_AND_RETAINED
            || start.cursor_count as usize > MAX_RESERVED_AND_RETAINED
        {
            return Err(ReservationError::CanonicalEncoding);
        }
        let mut hasher = production_snapshot_hasher();
        hasher.update(&bytes[offset..frame_end]);
        offset = frame_end;

        let record_count =
            usize::try_from(start.record_count).map_err(|_| ReservationError::CanonicalEncoding)?;
        let floor_count =
            usize::try_from(start.floor_count).map_err(|_| ReservationError::CanonicalEncoding)?;
        let cursor_count =
            usize::try_from(start.cursor_count).map_err(|_| ReservationError::CanonicalEncoding)?;
        let mut records = Vec::new();
        records
            .try_reserve(record_count)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let mut previous_binding = None;
        for _ in 0..record_count {
            let (tag, payload, end) = read_snapshot_chunk(bytes, offset, &mut charged, budget)?;
            if tag != SNAPSHOT_CHUNK_RECORD || payload.len() > MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES
            {
                return Err(ReservationError::CanonicalEncoding);
            }
            let record: ProductionReservationRecord =
                postcard::from_bytes(payload).map_err(|_| ReservationError::CanonicalEncoding)?;
            if postcard::to_allocvec(&record).map_err(|_| ReservationError::CanonicalEncoding)?
                != payload
                || previous_binding.is_some_and(|previous| record.binding <= previous)
            {
                return Err(ReservationError::CanonicalEncoding);
            }
            previous_binding = Some(record.binding);
            hasher.update(&bytes[offset..end]);
            offset = end;
            records.push(record);
        }

        let mut floors = Vec::new();
        floors
            .try_reserve(floor_count)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let mut previous_floor = None;
        for _ in 0..floor_count {
            let (tag, payload, end) = read_snapshot_chunk(bytes, offset, &mut charged, budget)?;
            if tag != SNAPSHOT_CHUNK_FLOOR || payload.len() > MAX_HISTORY_FLOOR_CODEC_BYTES {
                return Err(ReservationError::CanonicalEncoding);
            }
            let floor = IrreversibleHistoryFloor::from_canonical_bytes(payload)
                .map_err(|_| ReservationError::CanonicalEncoding)?;
            let key = ProductionFloorKey::from_floor(floor)?;
            if floor
                .to_canonical_bytes()
                .map_err(|_| ReservationError::CanonicalEncoding)?
                .as_slice()
                != payload
                || previous_floor.is_some_and(|previous| key <= previous)
            {
                return Err(ReservationError::CanonicalEncoding);
            }
            previous_floor = Some(key);
            hasher.update(&bytes[offset..end]);
            offset = end;
            floors.push(floor);
        }

        let mut retirement_cursors = Vec::new();
        retirement_cursors
            .try_reserve(cursor_count)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let mut previous_cursor = None;
        for _ in 0..cursor_count {
            let (tag, payload, end) = read_snapshot_chunk(bytes, offset, &mut charged, budget)?;
            if tag != SNAPSHOT_CHUNK_CURSOR || payload.len() > MAX_RETIREMENT_CURSOR_CODEC_BYTES {
                return Err(ReservationError::CanonicalEncoding);
            }
            let cursor: ProductionRetirementCursor =
                postcard::from_bytes(payload).map_err(|_| ReservationError::CanonicalEncoding)?;
            let cursor_key = (cursor.key, cursor.target_epoch);
            if postcard::to_allocvec(&cursor).map_err(|_| ReservationError::CanonicalEncoding)?
                != payload
                || previous_cursor.is_some_and(|previous| cursor_key <= previous)
            {
                return Err(ReservationError::CanonicalEncoding);
            }
            previous_cursor = Some(cursor_key);
            hasher.update(&bytes[offset..end]);
            offset = end;
            retirement_cursors.push(cursor);
        }

        let (tag, payload, end) = read_snapshot_chunk(bytes, offset, &mut charged, budget)?;
        if tag != SNAPSHOT_CHUNK_DIGEST
            || payload.len() != SNAPSHOT_CHUNK_DIGEST_BYTES
            || end != bytes.len()
            || hasher.finalize().as_slice() != payload
        {
            return Err(ReservationError::CanonicalEncoding);
        }
        let snapshot = Self::new(
            records,
            floors,
            retirement_cursors,
            start.witness,
            budget,
            profile,
        )?;
        Ok(snapshot)
    }

    pub(crate) fn records(&self) -> &[ProductionReservationRecord] {
        &self.records
    }

    pub(crate) fn witness(&self) -> GlobalChargeWitness {
        self.witness
    }

    /// Return the sorted bounded in-epoch cursor set. Cursors are part of the
    /// same restart envelope as roster rows, floors, and the charge witness.
    pub(crate) fn retirement_cursors(&self) -> &[ProductionRetirementCursor] {
        &self.retirement_cursors
    }
}

/// Bounded streaming encoder for the canonical snapshot fixture.
#[cfg(test)]
pub(crate) struct ProductionSnapshotChunks<'a> {
    snapshot: &'a ProductionSnapshot,
    prefix_emitted: bool,
    position: usize,
    hasher: Sha256,
    finished: bool,
}

#[cfg(test)]
impl<'a> ProductionSnapshotChunks<'a> {
    fn new(snapshot: &'a ProductionSnapshot) -> Self {
        Self {
            snapshot,
            prefix_emitted: false,
            position: 0,
            hasher: production_snapshot_hasher(),
            finished: false,
        }
    }

    fn next_payload(&self) -> Result<Option<(u8, Vec<u8>)>, ReservationError> {
        let records_end = self.snapshot.records.len();
        let floors_end = records_end
            .checked_add(self.snapshot.floors.len())
            .ok_or(ReservationError::CanonicalEncoding)?;
        let cursors_end = floors_end
            .checked_add(self.snapshot.retirement_cursors.len())
            .ok_or(ReservationError::CanonicalEncoding)?;
        if self.position == 0 {
            let start = ProductionSnapshotStart {
                version: PRODUCTION_SNAPSHOT_V3,
                record_count: u32::try_from(self.snapshot.records.len())
                    .map_err(|_| ReservationError::CanonicalEncoding)?,
                floor_count: u32::try_from(self.snapshot.floors.len())
                    .map_err(|_| ReservationError::CanonicalEncoding)?,
                cursor_count: u32::try_from(self.snapshot.retirement_cursors.len())
                    .map_err(|_| ReservationError::CanonicalEncoding)?,
                witness: self.snapshot.witness,
            };
            return Ok(Some((
                SNAPSHOT_CHUNK_START,
                postcard::to_allocvec(&start).map_err(|_| ReservationError::CanonicalEncoding)?,
            )));
        }
        let index = self.position - 1;
        if index < records_end {
            return Ok(Some((
                SNAPSHOT_CHUNK_RECORD,
                postcard::to_allocvec(&self.snapshot.records[index])
                    .map_err(|_| ReservationError::CanonicalEncoding)?,
            )));
        }
        if index < floors_end {
            return Ok(Some((
                SNAPSHOT_CHUNK_FLOOR,
                self.snapshot.floors[index - records_end]
                    .to_canonical_bytes()
                    .map_err(|_| ReservationError::CanonicalEncoding)?,
            )));
        }
        if index < cursors_end {
            return Ok(Some((
                SNAPSHOT_CHUNK_CURSOR,
                postcard::to_allocvec(&self.snapshot.retirement_cursors[index - floors_end])
                    .map_err(|_| ReservationError::CanonicalEncoding)?,
            )));
        }
        Ok(None)
    }
}

#[cfg(test)]
impl Iterator for ProductionSnapshotChunks<'_> {
    type Item = Result<Vec<u8>, ReservationError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if !self.prefix_emitted {
            self.prefix_emitted = true;
            return Some(Ok(PRODUCTION_SNAPSHOT_MAGIC.to_vec()));
        }
        match self.next_payload() {
            Ok(Some((tag, payload))) => {
                let max = match tag {
                    SNAPSHOT_CHUNK_START => SNAPSHOT_START_MAX_BYTES,
                    SNAPSHOT_CHUNK_RECORD => MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES,
                    SNAPSHOT_CHUNK_FLOOR => MAX_HISTORY_FLOOR_CODEC_BYTES,
                    SNAPSHOT_CHUNK_CURSOR => MAX_RETIREMENT_CURSOR_CODEC_BYTES,
                    _ => return Some(Err(ReservationError::CanonicalEncoding)),
                };
                if payload.len() > max {
                    self.finished = true;
                    return Some(Err(ReservationError::CanonicalEncoding));
                }
                self.position = match self.position.checked_add(1) {
                    Some(position) => position,
                    None => {
                        self.finished = true;
                        return Some(Err(ReservationError::CanonicalEncoding));
                    }
                };
                match encode_snapshot_chunk(tag, &payload) {
                    Ok(chunk) => {
                        self.hasher.update(&chunk);
                        Some(Ok(chunk))
                    }
                    Err(error) => {
                        self.finished = true;
                        Some(Err(error))
                    }
                }
            }
            Ok(None) => {
                self.finished = true;
                let digest: [u8; SNAPSHOT_CHUNK_DIGEST_BYTES] =
                    self.hasher.clone().finalize().into();
                Some(encode_snapshot_chunk(SNAPSHOT_CHUNK_DIGEST, &digest))
            }
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
fn production_snapshot_hasher() -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(PRODUCTION_SNAPSHOT_DOMAIN);
    hasher.update(PRODUCTION_SNAPSHOT_MAGIC);
    hasher
}

#[cfg(test)]
fn encode_snapshot_chunk(tag: u8, payload: &[u8]) -> Result<Vec<u8>, ReservationError> {
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| ReservationError::CanonicalEncoding)?;
    let total = 1usize
        .checked_add(4)
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or(ReservationError::CanonicalEncoding)?;
    let mut chunk = Vec::new();
    chunk
        .try_reserve_exact(total)
        .map_err(|_| ReservationError::CanonicalEncoding)?;
    chunk.push(tag);
    chunk.extend_from_slice(&payload_len.to_be_bytes());
    chunk.extend_from_slice(payload);
    Ok(chunk)
}

#[cfg(test)]
fn read_snapshot_chunk<'a>(
    bytes: &'a [u8],
    offset: usize,
    charged: &mut u64,
    budget: GlobalChargeBudget,
) -> Result<(u8, &'a [u8], usize), ReservationError> {
    let header_end = offset
        .checked_add(SNAPSHOT_CHUNK_HEADER_BYTES as usize)
        .ok_or(ReservationError::CanonicalEncoding)?;
    let header = bytes
        .get(offset..header_end)
        .ok_or(ReservationError::CanonicalEncoding)?;
    let payload_len = u32::from_be_bytes(
        header[1..]
            .try_into()
            .map_err(|_| ReservationError::CanonicalEncoding)?,
    ) as usize;
    let end = header_end
        .checked_add(payload_len)
        .ok_or(ReservationError::CanonicalEncoding)?;
    let payload = bytes
        .get(header_end..end)
        .ok_or(ReservationError::CanonicalEncoding)?;
    *charged = charged
        .checked_add(SNAPSHOT_CHUNK_HEADER_BYTES)
        .and_then(|total| total.checked_add(as_u64(payload_len).ok()?))
        .ok_or(ReservationError::CanonicalEncoding)?;
    if *charged > MAX_PRODUCTION_SNAPSHOT_CODEC_BYTES
        || *charged > budget.maximum_total_charge_bytes
    {
        return Err(ReservationError::CanonicalEncoding);
    }
    Ok((header[0], payload, end))
}

#[cfg(test)]
impl fmt::Debug for ProductionSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionSnapshot(<redacted>)")
    }
}

/// One exact row compare-and-swap within a prepared consensus transaction.
///
/// `expected: None` means the key must be absent.  A present value is compared
/// byte-for-byte through its canonical durable fields before the replacement or
/// deletion is made.  It is deliberately not an independently applicable row
/// operation: only [`PreparedProductionTransaction`] carries the witness CAS.
#[derive(Clone)]
pub(crate) struct ProductionRowCas {
    binding: RequestBindingKey,
    expected: Option<ProductionReservationRecord>,
    replacement: Option<ProductionReservationRecord>,
}

impl ProductionRowCas {
    pub(crate) const fn binding(&self) -> RequestBindingKey {
        self.binding
    }

    pub(crate) fn expected(&self) -> Option<&ProductionReservationRecord> {
        self.expected.as_ref()
    }

    pub(crate) fn replacement(&self) -> Option<&ProductionReservationRecord> {
        self.replacement.as_ref()
    }
}

impl fmt::Debug for ProductionRowCas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionRowCas(<redacted>)")
    }
}

/// Stable, opaque key for one tenant/scope floor row.
///
/// A floor frame begins with its fixed-width scope digest and tenant/scope
/// partition commitment.  The retired epoch follows those two commitments,
/// so this key remains stable across monotonic floor advances without exposing
/// a tenant identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ProductionFloorKey([u8; SNAPSHOT_FLOOR_PARTITION_BYTES]);

impl Serialize for ProductionFloorKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProductionFloorKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes =
            BoundedSnapshotBytes::<SNAPSHOT_FLOOR_PARTITION_BYTES>::deserialize(deserializer)?;
        let key: [u8; SNAPSHOT_FLOOR_PARTITION_BYTES] = bytes
            .0
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid floor key length"))?;
        Ok(Self(key))
    }
}

impl ProductionFloorKey {
    pub(crate) fn from_bytes(
        bytes: [u8; SNAPSHOT_FLOOR_PARTITION_BYTES],
    ) -> Result<Self, ReservationError> {
        if bytes[..32] == [0; 32] || bytes[32..] == [0; 32] {
            return Err(ReservationError::CanonicalEncoding);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn from_floor(floor: IrreversibleHistoryFloor) -> Result<Self, ReservationError> {
        let bytes = floor
            .to_canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let start = SNAPSHOT_FLOOR_FRAME_HEADER_BYTES;
        let end = start
            .checked_add(SNAPSHOT_FLOOR_PARTITION_BYTES)
            .ok_or(ReservationError::Arithmetic)?;
        let partition = bytes
            .get(start..end)
            .ok_or(ReservationError::CanonicalEncoding)?;
        let mut key = [0; SNAPSHOT_FLOOR_PARTITION_BYTES];
        key.copy_from_slice(partition);
        Ok(Self(key))
    }

    fn from_binding(binding: RequestBindingKey) -> Result<Self, ReservationError> {
        Self::from_floor(
            IrreversibleHistoryFloor::initial(binding)
                .map_err(|_| ReservationError::FloorAdvance)?,
        )
    }

    /// Return the fixed scope-and-tenant partition commitment.
    pub(crate) const fn as_bytes(&self) -> &[u8; SNAPSHOT_FLOOR_PARTITION_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ProductionFloorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionFloorKey(<redacted>)")
    }
}

/// Exact partition-keyed irreversible-floor compare-and-swap.
///
/// `expected: None` proves absence and is used only by admission to insert the
/// initial floor.  A present expected floor is compared byte-for-byte before
/// its replacement is persisted.  The partition key is carried separately so
/// an adapter never searches for a matching retired epoch value.
#[derive(Clone, Copy)]
pub(crate) struct ProductionFloorCas {
    key: ProductionFloorKey,
    expected: Option<IrreversibleHistoryFloor>,
    replacement: IrreversibleHistoryFloor,
}

impl ProductionFloorCas {
    pub(crate) const fn key(&self) -> ProductionFloorKey {
        self.key
    }

    pub(crate) const fn expected(&self) -> Option<IrreversibleHistoryFloor> {
        self.expected
    }

    pub(crate) const fn replacement(&self) -> IrreversibleHistoryFloor {
        self.replacement
    }
}

impl fmt::Debug for ProductionFloorCas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionFloorCas(<redacted>)")
    }
}

/// Bounded page from the authoritative partition index used to prepare one
/// retirement operation. It contains only the selected prefix (at most
/// `RECLAIM_BATCH` rows), never a partition-wide binding list. `final_batch`
/// is deliberately only a hint: the adapter independently proves it against
/// the indexed partition range in the committing transaction.
pub(crate) struct ProductionRetirementPrefix<'a> {
    key: ProductionFloorKey,
    target_epoch: u64,
    selected: &'a [(RequestBindingKey, ProductionReservationRecord)],
    final_batch: bool,
}

impl<'a> ProductionRetirementPrefix<'a> {
    /// Bind a bounded contiguous target-epoch prefix to the expected floor.
    pub(crate) fn new(
        previous_floor: IrreversibleHistoryFloor,
        next_floor: IrreversibleHistoryFloor,
        selected: &'a [(RequestBindingKey, ProductionReservationRecord)],
        final_batch: bool,
    ) -> Result<Self, ReservationError> {
        let key = ProductionFloorKey::from_floor(previous_floor)?;
        if key != ProductionFloorKey::from_floor(next_floor)?
            || next_floor.retired_through() <= previous_floor.retired_through()
            || selected.is_empty()
            || selected.len() > RECLAIM_BATCH
        {
            return Err(ReservationError::FloorAdvance);
        }
        let target_epoch = next_floor.retired_through();
        let mut previous = None;
        for (binding, _) in selected {
            if ProductionFloorKey::from_binding(*binding)? != key
                || binding.history_epoch() != target_epoch
                || previous.is_some_and(|last| *binding <= last)
            {
                return Err(ReservationError::FloorAdvance);
            }
            previous = Some(*binding);
        }
        Ok(Self {
            key,
            target_epoch,
            selected,
            final_batch,
        })
    }
}

impl fmt::Debug for ProductionRetirementPrefix<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionRetirementPrefix(<redacted>)")
    }
}

/// Exact bounded indexed-range predicate carried into a retirement
/// transaction. This is not a caller promise: the adapter must evaluate the
/// lower-epoch no-gap predicate and selected target-epoch prefix against its
/// authoritative partition index in the same transaction as row deletion and
/// floor/cursor CAS.
#[derive(Clone)]
pub(crate) struct ProductionPartitionRangeGuard {
    key: ProductionFloorKey,
    previous_floor_through: u64,
    target_epoch: u64,
    after: Option<RequestBindingKey>,
    selected: Vec<RequestBindingKey>,
    final_batch: bool,
}

impl ProductionPartitionRangeGuard {
    fn from_prefix(
        prefix: &ProductionRetirementPrefix<'_>,
        previous_floor: IrreversibleHistoryFloor,
        cursor: &ProductionRetirementCursor,
    ) -> Result<Self, ReservationError> {
        if prefix.key != ProductionFloorKey::from_floor(previous_floor)?
            || prefix.key != cursor.key
            || prefix.target_epoch != cursor.target_epoch
        {
            return Err(ReservationError::FloorAdvance);
        }
        let selected = prefix
            .selected
            .iter()
            .map(|(binding, _)| *binding)
            .collect();
        Ok(Self {
            key: prefix.key,
            previous_floor_through: previous_floor.retired_through(),
            target_epoch: prefix.target_epoch,
            after: cursor.last_deleted,
            selected,
            final_batch: prefix.final_batch,
        })
    }

    /// Stable partition key the adapter must range-check.
    pub(crate) const fn key(&self) -> ProductionFloorKey {
        self.key
    }

    /// Persisted floor position immediately before this operation.
    pub(crate) const fn previous_floor_through(&self) -> u64 {
        self.previous_floor_through
    }

    /// Target epoch whose next contiguous tombstone prefix is deleted.
    pub(crate) const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    /// Cursor boundary after which the selected prefix begins.
    pub(crate) const fn after(&self) -> Option<RequestBindingKey> {
        self.after
    }

    /// Exact selected prefix; its length is permanently bounded by 1,024.
    pub(crate) fn selected(&self) -> &[RequestBindingKey] {
        &self.selected
    }

    /// Whether this operation claims the target epoch is exhausted and may
    /// atomically advance the floor and delete its cursor.
    pub(crate) const fn final_batch(&self) -> bool {
        self.final_batch
    }
}

impl fmt::Debug for ProductionPartitionRangeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionPartitionRangeGuard(<redacted>)")
    }
}

/// Durable in-epoch retirement range marker.
///
/// A floor advances only after all tombstones at its next target epoch are
/// gone.  When more than `RECLAIM_BATCH` bindings share that epoch, this
/// cursor blocks new admissions through the target and records the last
/// contiguous binding already deleted.  That makes each bounded delete safe
/// across a restart without ever allowing a partial floor/row state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProductionRetirementCursor {
    key: ProductionFloorKey,
    target_epoch: u64,
    last_deleted: Option<RequestBindingKey>,
}

impl ProductionRetirementCursor {
    fn initial(key: ProductionFloorKey, target_epoch: u64) -> Result<Self, ReservationError> {
        validate_epoch(target_epoch)?;
        Ok(Self {
            key,
            target_epoch,
            last_deleted: None,
        })
    }

    fn advance_through(&self, binding: RequestBindingKey) -> Result<Self, ReservationError> {
        if ProductionFloorKey::from_binding(binding)? != self.key
            || binding.history_epoch() != self.target_epoch
            || self.last_deleted.is_some_and(|last| binding <= last)
        {
            return Err(ReservationError::FloorAdvance);
        }
        Ok(Self {
            key: self.key,
            target_epoch: self.target_epoch,
            last_deleted: Some(binding),
        })
    }

    pub(crate) fn validate_for_floor(
        &self,
        floor: IrreversibleHistoryFloor,
    ) -> Result<(), ReservationError> {
        if self.key != ProductionFloorKey::from_floor(floor)?
            || self.target_epoch <= floor.retired_through()
        {
            return Err(ReservationError::FloorAdvance);
        }
        validate_epoch(self.target_epoch)?;
        if let Some(last) = self.last_deleted {
            if ProductionFloorKey::from_binding(last)? != self.key
                || last.history_epoch() != self.target_epoch
            {
                return Err(ReservationError::FloorAdvance);
            }
        }
        Ok(())
    }

    fn canonical_len(&self) -> Result<u64, ReservationError> {
        let bytes = self.to_canonical_bytes()?;
        as_u64(bytes.len())
    }

    pub(crate) const fn key(&self) -> ProductionFloorKey {
        self.key
    }

    pub(crate) const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    pub(crate) const fn last_deleted(&self) -> Option<RequestBindingKey> {
        self.last_deleted
    }

    pub(crate) fn to_canonical_bytes(&self) -> Result<Vec<u8>, ReservationError> {
        validate_epoch(self.target_epoch)?;
        if let Some(last) = self.last_deleted {
            if ProductionFloorKey::from_binding(last)? != self.key
                || last.history_epoch() != self.target_epoch
            {
                return Err(ReservationError::FloorAdvance);
            }
        }
        let bytes = postcard::to_allocvec(self).map_err(|_| ReservationError::CanonicalEncoding)?;
        if bytes.len() > MAX_RETIREMENT_CURSOR_CODEC_BYTES {
            return Err(ReservationError::ComponentBounds);
        }
        Ok(bytes)
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReservationError> {
        if bytes.len() > MAX_RETIREMENT_CURSOR_CODEC_BYTES {
            return Err(ReservationError::ComponentBounds);
        }
        let value: Self =
            postcard::from_bytes(bytes).map_err(|_| ReservationError::CanonicalEncoding)?;
        if value.to_canonical_bytes()?.as_slice() != bytes {
            return Err(ReservationError::CanonicalEncoding);
        }
        Ok(value)
    }
}

impl fmt::Debug for ProductionRetirementCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionRetirementCursor(<redacted>)")
    }
}

/// Exact durable cursor compare-and-swap coupled to a bounded retirement
/// range.  A `None` replacement deletes the cursor only in the same
/// transaction that advances the floor past its target.
#[derive(Clone)]
pub(crate) struct ProductionRetirementCursorCas {
    key: ProductionFloorKey,
    expected: Option<ProductionRetirementCursor>,
    replacement: Option<ProductionRetirementCursor>,
}

impl ProductionRetirementCursorCas {
    fn assert_existing(
        key: ProductionFloorKey,
        existing: Option<ProductionRetirementCursor>,
    ) -> Self {
        Self {
            key,
            expected: existing.clone(),
            replacement: existing,
        }
    }

    /// Return the exact partition cursor key to compare.
    pub(crate) const fn key(&self) -> ProductionFloorKey {
        self.key
    }

    /// Return the exact prior cursor, or absence assertion.
    pub(crate) fn expected(&self) -> Option<&ProductionRetirementCursor> {
        self.expected.as_ref()
    }

    /// Return the cursor replacement, or deletion.
    pub(crate) fn replacement(&self) -> Option<&ProductionRetirementCursor> {
        self.replacement.as_ref()
    }
}

impl fmt::Debug for ProductionRetirementCursorCas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionRetirementCursorCas(<redacted>)")
    }
}

/// Exact bounded canonical representation of one authoritative business row.
///
/// A backend obtains this only from its authoritative-row read during
/// admission.  The tuple binds those bytes to the exact session key and
/// generation reserved by the admission; terminalization never accepts a
/// caller-selected replacement.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProductionBusinessState {
    key: crate::model::SessionKey,
    generation: crate::model::Generation,
    canonical: Vec<u8>,
}

impl ProductionBusinessState {
    /// Wrap one exact authoritative row observed at the admission barrier.
    pub(crate) fn present(
        key: crate::model::SessionKey,
        generation: crate::model::Generation,
        canonical: Vec<u8>,
    ) -> Result<Self, ReservationError> {
        if canonical.len() > MAX_BUSINESS_SESSION_COPY_BYTES {
            return Err(ReservationError::ComponentBounds);
        }
        Ok(Self {
            key,
            generation,
            canonical,
        })
    }

    /// Capture one exact authoritative SQLite row at the admission barrier.
    /// The protected payload bytes are copied verbatim and validated against
    /// their existing record AAD; this operation never decrypts or reseals.
    pub(crate) fn from_authoritative_record(
        record: &crate::record::StoredSessionRecord,
    ) -> Result<Self, ReservationError> {
        #[derive(Serialize)]
        struct UpdatedBusinessWire<'a> {
            key: &'a crate::model::SessionKey,
            owner: &'a crate::model::OwnerId,
            fence: crate::model::FenceToken,
            generation: crate::model::Generation,
            state_type: &'a crate::model::StateType,
            checkpoint: &'a [u8],
            record_commitment: [u8; 32],
        }

        if record.state_class != crate::model::StateClass::AuthoritativeSession
            || record.expires_at.is_some()
            || record.payload.encoding() != crate::record::SessionPayloadEncoding::EnvelopeV1
            || record.payload.as_bytes().len() > MAX_CHECKPOINT_BYTES
        {
            return Err(ReservationError::BusinessCas);
        }
        record
            .payload
            .validate_envelope_for_record(record)
            .map_err(|_| ReservationError::BusinessCas)?;

        let exact_record =
            postcard::to_allocvec(record).map_err(|_| ReservationError::CanonicalEncoding)?;
        if exact_record.len() > MAX_BUSINESS_SESSION_COPY_BYTES {
            return Err(ReservationError::ComponentBounds);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"opc/session-store/protected-roster/business-row/v1\0");
        hasher.update((exact_record.len() as u64).to_be_bytes());
        hasher.update(&exact_record);
        let record_commitment: [u8; 32] = hasher.finalize().into();
        let canonical = postcard::to_allocvec(&UpdatedBusinessWire {
            key: &record.key,
            owner: &record.owner,
            fence: record.fence,
            generation: record.generation,
            state_type: &record.state_type,
            checkpoint: record.payload.as_bytes(),
            record_commitment,
        })
        .map_err(|_| ReservationError::CanonicalEncoding)?;
        Self::present(record.key.clone(), record.generation, canonical)
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Return the exact protected session key represented by this row.
    pub(crate) fn key(&self) -> &crate::model::SessionKey {
        &self.key
    }

    /// Return the exact authoritative generation represented by this row.
    pub(crate) const fn generation(&self) -> crate::model::Generation {
        self.generation
    }

    /// Materialize the replacement as the real authoritative session-record
    /// type. This is intentionally available only to the production SQLite
    /// adapter; arbitrary opaque bytes can never be written to `session_records`.
    pub(crate) fn authoritative_record(
        &self,
    ) -> Result<crate::record::StoredSessionRecord, ReservationError> {
        #[derive(Deserialize)]
        struct UpdatedBusinessWire {
            key: crate::model::SessionKey,
            owner: crate::model::OwnerId,
            fence: crate::model::FenceToken,
            generation: crate::model::Generation,
            state_type: crate::model::StateType,
            checkpoint: Vec<u8>,
            record_commitment: [u8; 32],
        }

        let wire: UpdatedBusinessWire = postcard::from_bytes(&self.canonical)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        if wire.key != self.key
            || wire.generation != self.generation
            || wire.record_commitment == [0; 32]
        {
            return Err(ReservationError::BusinessCas);
        }
        let payload = crate::record::EncryptedSessionPayload::try_envelope(&wire.checkpoint)
            .map_err(|_| ReservationError::BusinessCas)?;
        let record = crate::record::StoredSessionRecord {
            key: wire.key,
            generation: wire.generation,
            owner: wire.owner,
            fence: wire.fence,
            state_class: crate::model::StateClass::AuthoritativeSession,
            state_type: wire.state_type,
            expires_at: None,
            payload,
        };
        record
            .payload
            .validate_envelope_for_record(&record)
            .map_err(|_| ReservationError::BusinessCas)?;
        Ok(record)
    }

    fn updated(
        admission: &Admission,
        generation: crate::model::Generation,
        _terminal_record_commitment: [u8; 32],
    ) -> Result<Self, ReservationError> {
        let state_type = admission
            .established_mutation()
            .state_type()
            .ok_or(ReservationError::BusinessCas)?;
        // The terminal receipt commitment is intentionally domain-separated
        // from the durable business-row commitment.  Reconstruct the exact
        // authoritative record and use the same canonical business-state
        // encoder as the post-write readback, rather than comparing those two
        // different commitments. `CommittedTerminal` already authenticated
        // this value before it reaches the storage-only transition builder.
        let payload =
            crate::record::EncryptedSessionPayload::try_envelope(admission.terminal_checkpoint())
                .map_err(|_| ReservationError::BusinessCas)?;
        let record = crate::record::StoredSessionRecord {
            key: admission.key().clone(),
            generation,
            owner: admission.logical_owner().clone(),
            fence: admission.admission_fence(),
            state_class: crate::model::StateClass::AuthoritativeSession,
            state_type: state_type.clone(),
            expires_at: None,
            payload,
        };
        record
            .payload
            .validate_envelope_for_record(&record)
            .map_err(|_| ReservationError::BusinessCas)?;
        Self::from_authoritative_record(&record)
    }
}

impl<'de> Deserialize<'de> for ProductionBusinessState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            key: crate::model::SessionKey,
            generation: crate::model::Generation,
            canonical: BoundedSnapshotBytes<MAX_BUSINESS_SESSION_COPY_BYTES>,
        }
        let wire = Wire::deserialize(deserializer)?;
        ProductionBusinessState::present(wire.key, wire.generation, wire.canonical.0)
            .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for ProductionBusinessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionBusinessState(<redacted>)")
    }
}

/// Exact admission-barrier reservation of one authoritative business row.
///
/// It is the first of the two real quorum mutations: the adapter compares the
/// exact present row and creates this key-exclusive reservation together with
/// the live roster row/floor/witness.  It does not materialize a business
/// replacement or alter non-roster charge.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProductionAdmissionBusinessReservation {
    expected: ProductionBusinessState,
    admission_commitment: [u8; 32],
}

impl ProductionAdmissionBusinessReservation {
    pub(crate) fn new(
        admission: &Admission,
        expected: ProductionBusinessState,
    ) -> Result<Self, ReservationError> {
        if expected.key != *admission.key()
            || expected.generation != admission.expected_generation()
        {
            return Err(ReservationError::BusinessCas);
        }
        Ok(Self {
            expected,
            admission_commitment: admission.body_commitment(),
        })
    }

    pub(crate) fn expected(&self) -> &ProductionBusinessState {
        &self.expected
    }

    fn validate_for(&self, admission: &Admission) -> Result<(), ReservationError> {
        if self.admission_commitment != admission.body_commitment()
            || self.expected.key != *admission.key()
            || self.expected.generation != admission.expected_generation()
        {
            return Err(ReservationError::BusinessCas);
        }
        Ok(())
    }
}

impl fmt::Debug for ProductionAdmissionBusinessReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionAdmissionBusinessReservation(<redacted>)")
    }
}

/// Exact authoritative business-row CAS coupled only to a terminal mutation.
#[derive(Clone)]
pub(crate) enum ProductionTerminalBusinessCas {
    /// An Aborted terminal compares the admission-reserved authoritative row
    /// and releases only its reservation. It never requests a session-row
    /// insert, replacement, or deletion.
    AbortedCompareRelease { expected: ProductionBusinessState },
    /// An Established terminal compares and writes one exact successor row.
    EstablishedPut {
        expected: ProductionBusinessState,
        successor: ProductionBusinessState,
    },
    /// An Established terminal compares and deletes its exact present row.
    EstablishedDelete { expected: ProductionBusinessState },
}

/// The terminal business operation an adapter must apply atomically with its
/// retained terminal receipt and reservation release.
///
/// This deliberately has no `Option<ProductionBusinessState>` successor:
/// absence must be selected explicitly as `EstablishedDelete`, so an Aborted
/// compare-and-release can never be mistaken for a session-row deletion.
pub(crate) enum ProductionTerminalBusinessAction<'a> {
    /// Compare the exact admitted raw authoritative row and release only its
    /// key-exclusive reservation.
    AbortedCompareRelease {
        expected: &'a ProductionBusinessState,
    },
    /// Compare the exact admitted row and insert-or-replace this successor.
    EstablishedPut {
        expected: &'a ProductionBusinessState,
        successor: &'a ProductionBusinessState,
    },
    /// Compare the exact admitted row and delete it as an Established action.
    EstablishedDelete {
        expected: &'a ProductionBusinessState,
    },
}

impl<'a> ProductionTerminalBusinessAction<'a> {
    /// Return the exact admitted authoritative pre-state to compare before
    /// either releasing the reservation or applying the selected action.
    pub(crate) const fn expected(&self) -> &'a ProductionBusinessState {
        match self {
            Self::AbortedCompareRelease { expected }
            | Self::EstablishedPut { expected, .. }
            | Self::EstablishedDelete { expected } => expected,
        }
    }
}

impl ProductionTerminalBusinessCas {
    /// Return the exact typed terminal business operation for adapter dispatch.
    pub(crate) const fn action(&self) -> ProductionTerminalBusinessAction<'_> {
        match self {
            Self::AbortedCompareRelease { expected } => {
                ProductionTerminalBusinessAction::AbortedCompareRelease { expected }
            }
            Self::EstablishedPut {
                expected,
                successor,
            } => ProductionTerminalBusinessAction::EstablishedPut {
                expected,
                successor,
            },
            Self::EstablishedDelete { expected } => {
                ProductionTerminalBusinessAction::EstablishedDelete { expected }
            }
        }
    }

    /// Return the exact business pre-state for legacy compare validation.
    ///
    /// New adapters must dispatch through [`Self::action`] so the aborted
    /// compare-and-release operation cannot be represented as a replacement.
    pub(crate) fn expected(&self) -> Option<&ProductionBusinessState> {
        match self {
            Self::AbortedCompareRelease { expected }
            | Self::EstablishedPut { expected, .. }
            | Self::EstablishedDelete { expected } => Some(expected),
        }
    }

    /// Legacy replacement projection for the pre-#707 SQLite adapter.
    ///
    /// New adapters must use [`Self::action`]. In particular, this projection
    /// preserves the previous no-op write for Aborted only while callers are
    /// migrated; it is not the prepared Aborted business operation.
    pub(crate) fn replacement(&self) -> Option<&ProductionBusinessState> {
        match self {
            Self::AbortedCompareRelease { expected } => Some(expected),
            Self::EstablishedPut { successor, .. } => Some(successor),
            Self::EstablishedDelete { .. } => None,
        }
    }

    fn from_committed(
        admission: &Admission,
        terminal: &CommittedTerminal,
        reservation: &ProductionAdmissionBusinessReservation,
    ) -> Result<Self, ReservationError> {
        reservation.validate_for(admission)?;
        let expected = reservation.expected.clone();
        match terminal.materialization() {
            TerminalMaterialization::Aborted => Ok(Self::AbortedCompareRelease { expected }),
            TerminalMaterialization::Established(EstablishedMaterialization::Updated {
                from,
                to,
                record_commitment,
            }) => {
                if *from != expected.generation {
                    return Err(ReservationError::BusinessCas);
                }
                Ok(Self::EstablishedPut {
                    expected,
                    successor: ProductionBusinessState::updated(
                        admission,
                        *to,
                        *record_commitment,
                    )?,
                })
            }
            TerminalMaterialization::Established(EstablishedMaterialization::Deleted {
                generation,
            }) => {
                if *generation != expected.generation {
                    return Err(ReservationError::BusinessCas);
                }
                Ok(Self::EstablishedDelete { expected })
            }
            TerminalMaterialization::Established(EstablishedMaterialization::NoOp {
                generation,
            }) => {
                if *generation != expected.generation {
                    return Err(ReservationError::BusinessCas);
                }
                Ok(Self::EstablishedPut {
                    expected: expected.clone(),
                    successor: expected,
                })
            }
        }
    }
}

impl fmt::Debug for ProductionTerminalBusinessCas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionTerminalBusinessCas(<redacted>)")
    }
}

/// Complete prepared durable mutation.
///
/// A consensus storage adapter must compare all rows, the global witness, the
/// optional exact tenant/scope floor, optional cursor, and retirement range
/// predicate, then apply every replacement and the next witness together. The
/// type intentionally offers no witness-only operation, so a terminal receipt,
/// reclaim, or retirement cannot release or reserve charge separately from its
/// durable rows.
#[derive(Clone)]
pub(crate) struct PreparedProductionTransaction {
    rows: Vec<ProductionRowCas>,
    previous: GlobalChargeWitness,
    next: GlobalChargeWitness,
    floor: Option<ProductionFloorCas>,
    retirement_cursor: Option<ProductionRetirementCursorCas>,
    partition_guard: Option<ProductionPartitionRangeGuard>,
    reclaim_oldest_guard: Option<ProductionReclaimOldestGuard>,
    admission_business_reservation: Option<ProductionAdmissionBusinessReservation>,
    business: Option<ProductionTerminalBusinessCas>,
    canonical_rows_validated: u32,
}

/// Consensus adapter contract for one all-or-none prepared roster mutation.
pub(crate) trait ProductionReservationTransactionAdapter {
    /// Compare the exact expected rows, business reservation/CAS, witness,
    /// optional floor/cursor, and both bounded guards, then atomically persist
    /// all replacements and the next witness. For a reclaim-oldest guard, the
    /// adapter must use its retained-terminal index to prove the carried rows
    /// equal the global `min(1024, eligible)` prefix. For a retirement range
    /// guard, it must use the partition index in the same transaction to prove
    /// no row exists below the target and that the carried rows are exactly
    /// the next cursor-delimited target-epoch prefix; floor advance/cursor
    /// deletion is legal only when that target has no remainder. An admission
    /// reservation is a compare-only business barrier; a terminal CAS is the
    /// sole business-row materialization.
    fn compare_and_apply_production(
        &mut self,
        transaction: PreparedProductionTransaction,
    ) -> Result<(), ReservationError>;
}

impl PreparedProductionTransaction {
    /// Return the exact prior witness required by the consensus compare step.
    pub(crate) const fn previous_witness(&self) -> GlobalChargeWitness {
        self.previous
    }

    /// Return the exact next witness to persist with this mutation.
    pub(crate) const fn next_witness(&self) -> GlobalChargeWitness {
        self.next
    }

    /// Return whether this is the single-row absent-key admission mutation.
    pub(crate) fn is_insertion(&self) -> bool {
        self.rows.len() == 1
            && self.rows[0].expected.is_none()
            && self.rows[0].replacement.is_some()
    }

    /// Return the authenticated binding without formatting it.
    pub(crate) fn binding(&self) -> Result<RequestBindingKey, ReservationError> {
        self.rows
            .first()
            .map(ProductionRowCas::binding)
            .ok_or(ReservationError::InvalidState)
    }

    /// Return the canonical replacement to persist atomically with the witness.
    #[cfg(test)]
    pub(crate) fn replacement(&self) -> Result<&ProductionReservationRecord, ReservationError> {
        self.rows
            .first()
            .and_then(ProductionRowCas::replacement)
            .ok_or(ReservationError::InvalidState)
    }

    /// Return every exact row CAS that must be committed with this witness.
    pub(crate) fn rows(&self) -> &[ProductionRowCas] {
        &self.rows
    }

    /// Return the optional exact tenant/scope floor CAS.
    pub(crate) const fn floor_cas(&self) -> Option<ProductionFloorCas> {
        self.floor
    }

    /// Return the bounded retirement cursor CAS, when this transaction either
    /// enters, advances, or closes an in-epoch retirement range.
    pub(crate) fn retirement_cursor_cas(&self) -> Option<&ProductionRetirementCursorCas> {
        self.retirement_cursor.as_ref()
    }

    /// Return the mandatory adapter-enforced exact range predicate for a
    /// bounded retirement batch.
    pub(crate) fn partition_range_guard(&self) -> Option<&ProductionPartitionRangeGuard> {
        self.partition_guard.as_ref()
    }

    /// Return the adapter-enforced global-oldest reclaim predicate, when this
    /// transaction converts retained rows into tombstones.
    pub(crate) fn reclaim_oldest_guard(&self) -> Option<&ProductionReclaimOldestGuard> {
        self.reclaim_oldest_guard.as_ref()
    }

    /// Return the exact business CAS carried only by a terminal transaction.
    pub(crate) fn business_cas(&self) -> Option<&ProductionTerminalBusinessCas> {
        self.business.as_ref()
    }

    /// Return the exact admission barrier, carried only by a live admission
    /// transaction.  The adapter must compare the business row to `expected`
    /// and install a key-exclusive reservation in the same transaction.
    pub(crate) fn admission_business_reservation(
        &self,
    ) -> Option<&ProductionAdmissionBusinessReservation> {
        self.admission_business_reservation.as_ref()
    }

    /// Return the fixed number of canonical rows examined by this hot path.
    ///
    /// Admission validates its proposed row; terminalization validates the
    /// fetched current row and its replacement is derived from it.  Aggregate
    /// reconstruction deliberately remains a restart-only operation.
    pub(crate) const fn canonical_rows_validated(&self) -> u32 {
        self.canonical_rows_validated
    }
}

impl fmt::Debug for PreparedProductionTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedProductionTransaction(<redacted>)")
    }
}

/// Compatibility name for the one-row admission/terminal production path.
pub(crate) type PreparedProductionChargeTransition = PreparedProductionTransaction;
/// Compatibility name for the floor-bound delete production path.
pub(crate) type PreparedProductionRetirement = PreparedProductionTransaction;

/// Prepare one atomic consensus admission plus witness transition.
pub(crate) fn prepare_production_admission(
    existing: Option<&ProductionReservationRecord>,
    record: ProductionReservationRecord,
    existing_floor: Option<IrreversibleHistoryFloor>,
    existing_retirement_cursor: Option<&ProductionRetirementCursor>,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionChargeTransition, ReservationError> {
    if existing.is_some() {
        return Err(ReservationError::Duplicate);
    }
    let initial_floor = IrreversibleHistoryFloor::initial(record.binding)
        .map_err(|_| ReservationError::FloorAdvance)?;
    let floor = match existing_floor {
        Some(existing_floor) => {
            existing_floor
                .validate_new_binding(record.binding)
                .map_err(|_| ReservationError::FloorAdvance)?;
            ProductionFloorCas {
                key: ProductionFloorKey::from_binding(record.binding)?,
                expected: Some(existing_floor),
                replacement: existing_floor,
            }
        }
        None => ProductionFloorCas {
            key: ProductionFloorKey::from_binding(record.binding)?,
            expected: None,
            replacement: initial_floor,
        },
    };
    if let Some(cursor) = existing_retirement_cursor {
        cursor.validate_for_floor(floor.replacement)?;
        if record.binding.history_epoch() <= cursor.target_epoch {
            return Err(ReservationError::FloorAdvance);
        }
    }
    let reservation = record
        .business_reservation
        .clone()
        .ok_or(ReservationError::StateShape)?;
    let admission = Admission::from_canonical_bytes(&record.admission)
        .map_err(|_| ReservationError::CanonicalEncoding)?;
    reservation.validate_for(&admission)?;
    let binding = record.binding;
    prepare_production_transition(ProductionTransitionPreparation {
        current: None,
        binding,
        replacement: record,
        insertion: true,
        floor: Some(floor),
        retirement_cursor: Some(ProductionRetirementCursorCas::assert_existing(
            ProductionFloorKey::from_binding(binding)?,
            existing_retirement_cursor.cloned(),
        )),
        partition_guard: None,
        admission_business_reservation: Some(reservation),
        business: None,
        witness,
        budget,
        profile,
    })
}

/// Prepare one atomic consensus terminalization plus witness transition.
pub(crate) fn prepare_production_terminalization(
    current: &ProductionReservationRecord,
    binding: RequestBindingKey,
    terminal: &CommittedTerminal,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionChargeTransition, ReservationError> {
    if current.binding != binding {
        return Err(ReservationError::Unknown);
    }
    let admission = Admission::from_canonical_bytes(&current.admission)
        .map_err(|_| ReservationError::CanonicalEncoding)?;
    let reservation = current
        .business_reservation
        .as_ref()
        .ok_or(ReservationError::StateShape)?;
    let business =
        ProductionTerminalBusinessCas::from_committed(&admission, terminal, reservation)?;
    let mut replacement = current.clone();
    replacement.terminalize(terminal, profile)?;
    prepare_production_transition(ProductionTransitionPreparation {
        current: Some(current),
        binding,
        replacement,
        insertion: false,
        floor: None,
        retirement_cursor: None,
        partition_guard: None,
        admission_business_reservation: None,
        business: Some(business),
        witness,
        budget,
        profile,
    })
}

/// Prepare a compare-and-apply deletion that advances the exact same-scope floor.
///
/// The consensus transaction must atomically delete this binding, persist
/// `next_floor`, and compare/apply the witness transition.  Separating any of
/// those writes would make capacity release reversible, so this type exposes
/// only the complete three-part transition.
pub(crate) fn prepare_production_retirement(
    selected_prefix: ProductionRetirementPrefix<'_>,
    previous_floor: IrreversibleHistoryFloor,
    next_floor: IrreversibleHistoryFloor,
    existing_retirement_cursor: Option<&ProductionRetirementCursor>,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionRetirement, ReservationError> {
    witness.admits(budget)?;
    let previous_key = ProductionFloorKey::from_floor(previous_floor)?;
    if previous_key != ProductionFloorKey::from_floor(next_floor)?
        || previous_key != selected_prefix.key
        || next_floor.retired_through() <= previous_floor.retired_through()
        || selected_prefix.target_epoch != next_floor.retired_through()
    {
        return Err(ReservationError::FloorAdvance);
    }
    next_floor
        .strictly_advances(previous_floor)
        .map_err(|_| ReservationError::FloorAdvance)?;
    let cursor = match existing_retirement_cursor {
        Some(cursor) => {
            cursor.validate_for_floor(previous_floor)?;
            if cursor.key != previous_key || cursor.target_epoch != next_floor.retired_through() {
                return Err(ReservationError::FloorAdvance);
            }
            cursor.clone()
        }
        None => ProductionRetirementCursor::initial(previous_key, next_floor.retired_through())?,
    };
    let range_guard =
        ProductionPartitionRangeGuard::from_prefix(&selected_prefix, previous_floor, &cursor)?;
    let mut rows = Vec::new();
    rows.try_reserve(selected_prefix.selected.len())
        .map_err(|_| ReservationError::Arithmetic)?;
    let mut next_counters = witness.roster;
    let mut previous_binding = cursor.last_deleted;
    for (binding, record) in selected_prefix.selected {
        if previous_binding.is_some_and(|last| *binding <= last)
            || ProductionFloorKey::from_binding(*binding)? != previous_key
            || binding.history_epoch() != next_floor.retired_through()
            || record.state != ReservationState::Tombstone
        {
            return Err(ReservationError::FloorAdvance);
        }
        record.validate(profile)?;
        previous_floor
            .validate_new_binding(*binding)
            .map_err(|_| ReservationError::FloorAdvance)?;
        next_counters = counters_without_production_record(next_counters, record, profile)?;
        rows.push(ProductionRowCas {
            binding: *binding,
            expected: Some(record.clone()),
            replacement: None,
        });
        previous_binding = Some(*binding);
    }
    let final_batch = selected_prefix.final_batch;
    let cursor_cas = if final_batch {
        Some(ProductionRetirementCursorCas {
            key: previous_key,
            expected: existing_retirement_cursor.cloned(),
            replacement: None,
        })
    } else {
        let advanced =
            cursor.advance_through(rows.last().ok_or(ReservationError::FloorAdvance)?.binding)?;
        if let Some(existing) = existing_retirement_cursor {
            next_counters = counters_without_retirement_cursor(next_counters, existing)?;
        }
        next_counters = counters_with_retirement_cursor(next_counters, &advanced)?;
        Some(ProductionRetirementCursorCas {
            key: previous_key,
            expected: existing_retirement_cursor.cloned(),
            replacement: Some(advanced),
        })
    };
    if final_batch {
        if let Some(existing) = existing_retirement_cursor {
            next_counters = counters_without_retirement_cursor(next_counters, existing)?;
        }
    }
    let next = witness.with_roster(next_counters);
    next.admits(budget)?;
    Ok(PreparedProductionTransaction {
        previous: witness,
        next,
        floor: final_batch.then_some(ProductionFloorCas {
            key: previous_key,
            expected: Some(previous_floor),
            replacement: next_floor,
        }),
        retirement_cursor: cursor_cas,
        partition_guard: Some(range_guard),
        reclaim_oldest_guard: None,
        admission_business_reservation: None,
        business: None,
        canonical_rows_validated: u32::try_from(rows.len())
            .map_err(|_| ReservationError::Arithmetic)?,
        rows,
    })
}

struct ProductionTransitionPreparation<'a> {
    current: Option<&'a ProductionReservationRecord>,
    binding: RequestBindingKey,
    replacement: ProductionReservationRecord,
    insertion: bool,
    floor: Option<ProductionFloorCas>,
    retirement_cursor: Option<ProductionRetirementCursorCas>,
    partition_guard: Option<ProductionPartitionRangeGuard>,
    admission_business_reservation: Option<ProductionAdmissionBusinessReservation>,
    business: Option<ProductionTerminalBusinessCas>,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
}

fn prepare_production_transition(
    transition: ProductionTransitionPreparation<'_>,
) -> Result<PreparedProductionChargeTransition, ReservationError> {
    let ProductionTransitionPreparation {
        current,
        binding,
        replacement,
        insertion,
        floor,
        retirement_cursor,
        partition_guard,
        admission_business_reservation,
        business,
        witness,
        budget,
        profile,
    } = transition;
    witness.admits(budget)?;
    if admission_business_reservation.is_some() && business.is_some() {
        return Err(ReservationError::InvalidState);
    }
    if insertion != admission_business_reservation.is_some() {
        return Err(ReservationError::InvalidState);
    }
    if insertion != current.is_none() {
        return Err(ReservationError::InvalidState);
    }
    if replacement.binding != binding {
        return Err(ReservationError::SnapshotMismatch);
    }
    replacement.validate(profile)?;
    if let Some(current) = current {
        if current.binding != binding {
            return Err(ReservationError::Unknown);
        }
        current.validate(profile)?;
    }
    let without_current = match current {
        Some(current) => counters_without_production_record(witness.roster, current, profile)?,
        None => witness.roster,
    };
    let mut next_counters =
        counters_with_production_record(without_current, &replacement, profile)?;
    if let Some(floor) = floor {
        if floor.expected.is_none() {
            next_counters = counters_with_production_floor(next_counters, floor.replacement)?;
        }
    }
    if next_counters.live_reservations > MAX_LIVE_ROSTERS {
        return Err(ReservationError::LiveLimit);
    }
    if next_counters.retained_and_live_bindings > MAX_RESERVED_AND_RETAINED {
        return Err(ReservationError::BindingLimit);
    }
    if next_counters.durable_epoch_bindings > MAX_RESERVED_AND_RETAINED {
        return Err(ReservationError::DurableBindingLimit);
    }
    if next_counters.floor_count > MAX_RESERVED_AND_RETAINED
        || next_counters.retirement_cursor_count > MAX_RESERVED_AND_RETAINED
    {
        return Err(ReservationError::FloorLimit);
    }
    // The durable 256 GiB witness is deliberately roster-only.  Business-row
    // materialization is still guarded by the exact terminal CAS, but its
    // changing byte size must not debit this roster ledger (in particular a
    // delete or shrinking put cannot underflow an otherwise empty witness).
    let next = witness.with_roster(next_counters);
    next.admits(budget)?;
    Ok(PreparedProductionTransaction {
        rows: vec![ProductionRowCas {
            binding,
            expected: current.cloned(),
            replacement: Some(replacement),
        }],
        previous: witness,
        next,
        floor,
        retirement_cursor,
        partition_guard,
        reclaim_oldest_guard: None,
        admission_business_reservation,
        business,
        canonical_rows_validated: 1,
    })
}

fn counters_with_production_record(
    counters: AggregateCounters,
    record: &ProductionReservationRecord,
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    counters_for_record(
        counters,
        record.state,
        production_record_charges(record, profile)?,
    )
}

fn counters_with_production_floor(
    mut counters: AggregateCounters,
    floor: IrreversibleHistoryFloor,
) -> Result<AggregateCounters, ReservationError> {
    let bytes = floor
        .to_canonical_bytes()
        .map_err(|_| ReservationError::CanonicalEncoding)?;
    counters.floor_count = counters
        .floor_count
        .checked_add(1)
        .ok_or(ReservationError::Arithmetic)?;
    if counters.floor_count > MAX_RESERVED_AND_RETAINED {
        return Err(ReservationError::FloorLimit);
    }
    counters.floor_charge_bytes = counters
        .floor_charge_bytes
        .checked_add(as_u64(bytes.len())?)
        .ok_or(ReservationError::Arithmetic)?;
    counters.materialized_charge_bytes = counters
        .materialized_charge_bytes
        .checked_add(as_u64(bytes.len())?)
        .ok_or(ReservationError::Arithmetic)?;
    Ok(counters)
}

fn counters_with_retirement_cursor(
    mut counters: AggregateCounters,
    cursor: &ProductionRetirementCursor,
) -> Result<AggregateCounters, ReservationError> {
    let bytes = cursor.canonical_len()?;
    counters.retirement_cursor_count = counters
        .retirement_cursor_count
        .checked_add(1)
        .ok_or(ReservationError::Arithmetic)?;
    if counters.retirement_cursor_count > MAX_RESERVED_AND_RETAINED {
        return Err(ReservationError::FloorLimit);
    }
    counters.retirement_cursor_charge_bytes = counters
        .retirement_cursor_charge_bytes
        .checked_add(bytes)
        .ok_or(ReservationError::Arithmetic)?;
    counters.materialized_charge_bytes = counters
        .materialized_charge_bytes
        .checked_add(bytes)
        .ok_or(ReservationError::Arithmetic)?;
    Ok(counters)
}

fn counters_without_retirement_cursor(
    mut counters: AggregateCounters,
    cursor: &ProductionRetirementCursor,
) -> Result<AggregateCounters, ReservationError> {
    let bytes = cursor.canonical_len()?;
    counters.retirement_cursor_count = counters
        .retirement_cursor_count
        .checked_sub(1)
        .ok_or(ReservationError::WitnessMismatch)?;
    counters.retirement_cursor_charge_bytes = counters
        .retirement_cursor_charge_bytes
        .checked_sub(bytes)
        .ok_or(ReservationError::WitnessMismatch)?;
    counters.materialized_charge_bytes = counters
        .materialized_charge_bytes
        .checked_sub(bytes)
        .ok_or(ReservationError::WitnessMismatch)?;
    Ok(counters)
}

fn counters_without_production_record(
    mut counters: AggregateCounters,
    record: &ProductionReservationRecord,
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    let contribution = counters_for_record(
        zero_counters(),
        record.state,
        production_record_charges(record, profile)?,
    )?;
    counters.materialized_charge_bytes = counters
        .materialized_charge_bytes
        .checked_sub(contribution.materialized_charge_bytes)
        .ok_or(ReservationError::WitnessMismatch)?;
    counters.reserved_future_charge_bytes = counters
        .reserved_future_charge_bytes
        .checked_sub(contribution.reserved_future_charge_bytes)
        .ok_or(ReservationError::WitnessMismatch)?;
    counters.live_reservations = counters
        .live_reservations
        .checked_sub(contribution.live_reservations)
        .ok_or(ReservationError::WitnessMismatch)?;
    counters.retained_and_live_bindings = counters
        .retained_and_live_bindings
        .checked_sub(contribution.retained_and_live_bindings)
        .ok_or(ReservationError::WitnessMismatch)?;
    counters.durable_epoch_bindings = counters
        .durable_epoch_bindings
        .checked_sub(contribution.durable_epoch_bindings)
        .ok_or(ReservationError::WitnessMismatch)?;
    Ok(counters)
}

fn production_record_charges(
    record: &ProductionReservationRecord,
    profile: ChargeProfile,
) -> Result<Charges, ReservationError> {
    match record.state {
        ReservationState::Live => {
            profile.charge(production_components(&record.admission, None, None)?)
        }
        ReservationState::Retained => profile.charge(production_components(
            &record.admission,
            record.terminal.as_deref(),
            None,
        )?),
        ReservationState::Tombstone => profile.charge(production_components(
            &[],
            None,
            record.tombstone.as_deref(),
        )?),
    }
}

const fn zero_counters() -> AggregateCounters {
    AggregateCounters {
        materialized_charge_bytes: 0,
        reserved_future_charge_bytes: 0,
        live_reservations: 0,
        retained_and_live_bindings: 0,
        durable_epoch_bindings: 0,
        floor_count: 0,
        floor_charge_bytes: 0,
        retirement_cursor_count: 0,
        retirement_cursor_charge_bytes: 0,
    }
}

#[derive(Clone, Copy)]
struct Charges {
    live: u64,
    retained: u64,
    tombstone: u64,
    peak: u64,
}

fn as_u64(value: usize) -> Result<u64, ReservationError> {
    u64::try_from(value).map_err(|_| ReservationError::Arithmetic)
}

fn add3(first: u64, second: u64, third: u64) -> Result<u64, ReservationError> {
    first
        .checked_add(second)
        .and_then(|value| value.checked_add(third))
        .ok_or(ReservationError::Arithmetic)
}

fn add4(first: u64, second: u64, third: u64, fourth: u64) -> Result<u64, ReservationError> {
    add3(first, second, third)?
        .checked_add(fourth)
        .ok_or(ReservationError::Arithmetic)
}

fn validate_epoch(epoch: u64) -> Result<(), ReservationError> {
    if epoch == 0 || epoch > MAX_HISTORY_EPOCH {
        return Err(ReservationError::InvalidEpoch);
    }
    Ok(())
}

fn counters_for_record(
    mut counters: AggregateCounters,
    state: ReservationState,
    charges: Charges,
) -> Result<AggregateCounters, ReservationError> {
    counters.durable_epoch_bindings = counters
        .durable_epoch_bindings
        .checked_add(1)
        .ok_or(ReservationError::Arithmetic)?;
    if counters.durable_epoch_bindings > MAX_RESERVED_AND_RETAINED {
        return Err(ReservationError::DurableBindingLimit);
    }
    match state {
        ReservationState::Live => {
            counters.materialized_charge_bytes = counters
                .materialized_charge_bytes
                .checked_add(charges.live)
                .ok_or(ReservationError::Arithmetic)?;
            counters.reserved_future_charge_bytes = counters
                .reserved_future_charge_bytes
                .checked_add(
                    charges
                        .peak
                        .checked_sub(charges.live)
                        .ok_or(ReservationError::Arithmetic)?,
                )
                .ok_or(ReservationError::Arithmetic)?;
            counters.live_reservations = counters
                .live_reservations
                .checked_add(1)
                .ok_or(ReservationError::Arithmetic)?;
            if counters.live_reservations > MAX_LIVE_ROSTERS {
                return Err(ReservationError::LiveLimit);
            }
            counters.retained_and_live_bindings = counters
                .retained_and_live_bindings
                .checked_add(1)
                .ok_or(ReservationError::Arithmetic)?;
            if counters.retained_and_live_bindings > MAX_RESERVED_AND_RETAINED {
                return Err(ReservationError::BindingLimit);
            }
        }
        ReservationState::Retained => {
            counters.materialized_charge_bytes = counters
                .materialized_charge_bytes
                .checked_add(charges.retained)
                .ok_or(ReservationError::Arithmetic)?;
            counters.retained_and_live_bindings = counters
                .retained_and_live_bindings
                .checked_add(1)
                .ok_or(ReservationError::Arithmetic)?;
            if counters.retained_and_live_bindings > MAX_RESERVED_AND_RETAINED {
                return Err(ReservationError::BindingLimit);
            }
        }
        ReservationState::Tombstone => {
            counters.materialized_charge_bytes = counters
                .materialized_charge_bytes
                .checked_add(charges.tombstone)
                .ok_or(ReservationError::Arithmetic)?;
        }
    }
    Ok(counters)
}

/// Redacted, deterministic reservation failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservationError {
    /// The frozen charge profile is malformed.
    InvalidProfile,
    /// A canonical component length exceeds its fixed schema bound.
    ComponentBounds,
    /// A checked integer operation could not be represented.
    Arithmetic,
    /// Aggregate materialized plus reserved charge exceeds the roster budget.
    BudgetExceeded,
    /// The persisted roster-ledger witness version is not understood.
    UnknownWitnessVersion,
    /// The persisted witness does not exactly match roster counters.
    WitnessMismatch,
    /// A durable canonical frame is truncated, trailing, or otherwise invalid.
    CanonicalEncoding,
    /// Canonical fields are incompatible with their claimed lifecycle state.
    StateShape,
    /// Irreversible floor retirement is not an exact strict same-scope advance.
    FloorAdvance,
    /// A partition-floor count or canonical-byte total exceeds its frozen bound.
    FloorLimit,
    /// A terminal business-row compare-and-swap does not match its exact phase.
    BusinessCas,
    /// The live reservation count is exhausted.
    LiveLimit,
    /// The retained and live epoch-binding count is exhausted.
    BindingLimit,
    /// Durable epoch bindings, including tombstones, are exhausted.
    DurableBindingLimit,
    /// A canonical reservation identity is duplicated.
    Duplicate,
    /// A requested reservation identity does not exist.
    Unknown,
    /// The lifecycle transition does not match the durable state.
    InvalidState,
    /// A retained record has not reached the frozen reclaim age.
    NotEligible,
    /// A maintenance timestamp was not derived from the supported consensus clock.
    InvalidMaintenanceTime,
    /// A durable epoch lies outside the frozen history range.
    InvalidEpoch,
    /// Snapshot records or their aggregate witness are inconsistent.
    SnapshotMismatch,
}

impl fmt::Debug for ReservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReservationError(<redacted>)")
    }
}

impl fmt::Display for ReservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidProfile => "invalid reservation charge profile",
            Self::ComponentBounds => "reservation component exceeds schema bound",
            Self::Arithmetic => "reservation arithmetic is not representable",
            Self::BudgetExceeded => "protected roster snapshot budget is exhausted",
            Self::UnknownWitnessVersion => "protected roster witness version is unsupported",
            Self::WitnessMismatch => "protected roster witness does not match reservation state",
            Self::CanonicalEncoding => "canonical reservation encoding is invalid",
            Self::StateShape => "reservation lifecycle shape is invalid",
            Self::FloorAdvance => "irreversible retirement floor is invalid",
            Self::FloorLimit => "partition floor limit is exhausted",
            Self::BusinessCas => "terminal business compare-and-swap is invalid",
            Self::LiveLimit => "live reservation limit is exhausted",
            Self::BindingLimit => "retained and live binding limit is exhausted",
            Self::DurableBindingLimit => "durable epoch binding limit is exhausted",
            Self::Duplicate => "duplicate reservation identity",
            Self::Unknown => "reservation identity is unavailable",
            Self::InvalidState => "reservation lifecycle transition is invalid",
            Self::NotEligible => "retained reservation is not reclaim eligible",
            Self::InvalidMaintenanceTime => "maintenance timestamp is invalid",
            Self::InvalidEpoch => "reservation epoch is invalid",
            Self::SnapshotMismatch => "reservation snapshot validation failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ReservationError {}
