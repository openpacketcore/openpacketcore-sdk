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
    decode_frame, encode_frame, Admission, IrreversibleHistoryFloor, RequestBindingKey,
    RosterCompactAdmissionProvenanceV2, RosterCompactTerminalEvidenceV2,
    RosterExecutorProofBundleV1, RosterIngressAttestationV1, RosterIngressAttestationV2,
    RosterProfileV2CompactAdmissionProvenanceV1, RosterProfileV2CompactTerminalEvidenceV1,
    RosterProfileV2ExecutorProofBundleV1, TerminalConflictTombstone, CHARGE_WITNESS_VERSION,
    MAX_ADMISSION_CODEC_BYTES, MAX_BUSINESS_SESSION_HEADER_BYTES, MAX_CHECKPOINT_BYTES,
    MAX_COMMITTED_TERMINAL_CODEC_BYTES, MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES,
    MAX_EXECUTOR_PROOF_BUNDLE_BYTES, MAX_HISTORY_EPOCH, MAX_LIVE_ROSTERS,
    MAX_RESERVED_AND_RETAINED, MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES,
    MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES, MAX_ROSTER_INGRESS_ATTESTATION_BYTES,
    MAX_TOMBSTONE_CODEC_BYTES, PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES, RECLAIM_BATCH,
    STORAGE_CHARGE_LIVE_INDEX_BYTES, STORAGE_CHARGE_LIVE_ROW_BYTES, STORAGE_CHARGE_PAGE_BYTES,
    STORAGE_CHARGE_RETAINED_INDEX_BYTES, STORAGE_CHARGE_RETAINED_ROW_BYTES,
    STORAGE_CHARGE_TOMBSTONE_INDEX_BYTES, STORAGE_CHARGE_TOMBSTONE_ROW_BYTES,
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
/// V2 adds the fixed-size authenticated terminal-history closure horizon.
/// Older V1 bytes are deliberately not accepted: they cannot prove that an
/// omitted final-partition tombstone was retired instead of rolled back.
const GLOBAL_CHARGE_WITNESS_V2: u16 = GLOBAL_CHARGE_WITNESS_V1 + 1;
const GLOBAL_CHARGE_WITNESS_VERSION: u16 = GLOBAL_CHARGE_WITNESS_V2;

/// A valid production snapshot may contain every durable row at its frozen
/// per-field maximum.  This is deliberately derived from the protocol bounds
/// instead of an arbitrary decoder cap (a fixed 512 MiB cap cannot represent
/// a valid 1,024-row maximum-payload deployment).  The decode path still
/// preflights the actual frame against the persisted aggregate budget before
/// it asks postcard to allocate anything.
const MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES: usize = MAX_ADMISSION_CODEC_BYTES
    + MAX_COMMITTED_TERMINAL_CODEC_BYTES
    + MAX_TOMBSTONE_CODEC_BYTES
    + MAX_COMPACT_PROVENANCE_BYTES
    + MAX_EXECUTOR_PROOF_BUNDLE_BYTES
    + 2 * MAX_ROSTER_INGRESS_ATTESTATION_BYTES
    + MAX_BUSINESS_SESSION_COPY_BYTES
    + 512;
/// V2 has a distinct retained-evidence envelope which binds typed `/4`
/// ingress and V2 admission provenance. It is never admitted by the frozen
/// V1 record decoder or its V1 charge accounting.
const MAX_PRODUCTION_RESERVATION_RECORD_V2_SNAPSHOT_BYTES: usize = MAX_ADMISSION_CODEC_BYTES
    + MAX_COMMITTED_TERMINAL_CODEC_BYTES
    + MAX_TOMBSTONE_CODEC_BYTES
    + MAX_BUSINESS_SESSION_COPY_BYTES
    + (3 * MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES)
    + (4 * MAX_ROSTER_INGRESS_ATTESTATION_BYTES)
    + (2 * MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES)
    + 512;
const MAX_PROFILE_V2_COMPACT_TERMINAL_EVIDENCE_BYTES: usize =
    MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES
        + MAX_ROSTER_INGRESS_ATTESTATION_BYTES
        + MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES;
const MAX_PROFILE_V2_EXECUTOR_PROOF_BUNDLE_BYTES: usize =
    MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES
        + (2 * MAX_ROSTER_INGRESS_ATTESTATION_BYTES)
        + MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES;
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
    use crate::consensus::SessionConsensusIdentity;
    use crate::fenced_mutation_roster::{
        AdmissionProposal, EstablishedMutation, Member, MemberOperationId, Phase, Profile,
        RequestId, RosterAttestationCertificateRoleV1, RosterAttestationLeafCertificatePartsV1,
        RosterAttestationLeafCertificateV1, RosterAttestationTrustRootV1,
        RosterCompactTerminalEvidenceBindingV2, RosterCompactTerminalEvidenceV2,
        RosterCompactTerminalMemberProjectionV2, RosterCompactTerminalMemberProofPartsV2,
        RosterCompactTerminalMemberSigningInputV2, RosterId,
        RosterIngressAttestationSigningInputV1, RosterIngressAttestationSigningInputV2,
        RosterIngressAttestationV1, RosterProfileV2CompactAdmissionProvenanceSigningInputV1,
        RosterProfileV2TerminalAttestationSigningInputV1, RosterProviderOperationV1,
        RosterProviderOutcomeV1, Scope, TerminalRecord, MEMBER_OPERATION_ID_BYTES, ROSTER_ID_BYTES,
    };
    use crate::fenced_mutation_roster_executor::{
        AuthorityBinding, AuthorityLeaseMetadata, BackendRegistration, ConsensusCommitMetadata,
    };
    use crate::model::{FenceToken, Generation, OwnerId, SessionKey, StateType};
    use crate::{SessionKeyType, StableId};
    use bytes::Bytes;
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{
        serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

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

    fn live_v2(
        admission: &Admission,
        epoch: u64,
        profile: ChargeProfile,
    ) -> ProductionReservationRecordV2 {
        let binding = admission.binding_key(epoch).unwrap();
        let reservation =
            ProductionAdmissionAbsentBusinessReservationV2::new(admission, binding).unwrap();
        let (ingress, provenance) = v2_carrier_inputs(admission);
        ProductionReservationRecord::live_v2_absent_with_provenance_and_ingress(
            admission,
            &ingress,
            &provenance,
            epoch,
            reservation,
            profile,
        )
        .unwrap()
    }

    fn empty_witness() -> GlobalChargeWitness {
        GlobalChargeWitness::v1(0, 0, zero_counters())
    }

    fn vacant(binding: RequestBindingKey) -> ProductionBindingVacancyGuard {
        ProductionBindingVacancyGuard::from_lookups(binding, None, None).unwrap()
    }

    fn aged_maintenance_time() -> ConsensusMaintenanceTimestamp {
        ConsensusMaintenanceTimestamp::from_consensus_timestamp(
            Timestamp::now_utc().add_seconds(2 * 24 * 60 * 60).unwrap(),
        )
        .unwrap()
    }

    fn compact_v1_terminal(
        admission: &Admission,
        epoch: u64,
        profile: ChargeProfile,
    ) -> ProductionReservationRecord {
        let mut record = live(admission, epoch, profile);
        record
            .terminalize(&terminal_at(admission, epoch), profile)
            .unwrap();
        let at_boundary = record
            .terminalized_at()
            .unwrap()
            .checked_add_retention()
            .unwrap();
        record.reclaim_at(at_boundary, profile).unwrap();
        record
    }

    fn compact_v2_terminal(
        admission: &Admission,
        profile: ChargeProfile,
    ) -> ProductionReservationRecordV2 {
        let live = live_v2(admission, 1, profile);
        let (terminal, evidence, bundle) = v2_terminal_fixture(admission);
        let mut record = live
            .prepare_terminalization(&terminal, &bundle, &evidence, profile)
            .unwrap()
            .replacement()
            .clone();
        let at_boundary = record
            .terminalized_at()
            .unwrap()
            .checked_add_retention()
            .unwrap();
        record.reclaim_at(at_boundary, profile).unwrap();
        record
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
                                    .and_then(|cursor| cursor.last_deleted)
                                    == guard.after
                        });
                if self
                    .floors
                    .get(&guard.key)
                    .map(|floor| floor.retired_through())
                    != Some(guard.previous_floor_through)
                    || guard.selected.is_empty()
                    || guard.selected.len() > RECLAIM_BATCH
                    || !cursor_matches_guard
                    || (guard.final_batch != transaction.floor.is_some())
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
                let mut target = Vec::new();
                let mut higher_epoch_exists = false;
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
                    } else if binding.history_epoch() > guard.target_epoch {
                        higher_epoch_exists = true;
                    }
                }
                let expected = target
                    .iter()
                    .copied()
                    .take(RECLAIM_BATCH)
                    .collect::<Vec<_>>();
                let floor_transition_matches = match (guard.final_batch, transaction.floor) {
                    (false, None) => true,
                    (true, Some(floor))
                        if floor.key == guard.key
                            && floor.expected == self.floors.get(&guard.key).copied() =>
                    {
                        match floor.replacement {
                            None => guard.partition_empty_after,
                            Some(replacement) => {
                                !guard.partition_empty_after
                                    && ProductionFloorKey::from_floor(replacement) == Ok(guard.key)
                                    && replacement.retired_through() == guard.target_epoch
                            }
                        }
                    }
                    _ => false,
                };
                if expected != guard.selected
                    || transaction.rows.len() != guard.selected.len()
                    || transaction
                        .rows
                        .iter()
                        .zip(&guard.selected)
                        .any(|(row, binding)| row.binding != *binding || row.replacement.is_some())
                    || (guard.final_batch && target.len() != guard.selected.len())
                    || (!guard.final_batch && target.len() <= guard.selected.len())
                    || guard.partition_empty_after != (guard.final_batch && !higher_epoch_exists)
                    || !floor_transition_matches
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
            }
            if let Some(guard) = transaction.global_terminal_retirement_guard.as_ref() {
                let mut terminal_history = self
                    .rows
                    .iter()
                    .filter_map(|(binding, record)| {
                        record
                            .terminal_sequence
                            .map(|sequence| (sequence, *binding, record.state))
                    })
                    .filter(|(sequence, _, _)| {
                        *sequence > transaction.previous.retired_terminal_sequence
                    })
                    .collect::<Vec<_>>();
                terminal_history
                    .sort_unstable_by_key(|(sequence, binding, _)| (*sequence, *binding));
                let expected = terminal_history
                    .iter()
                    .take_while(|(_, _, state)| *state == ReservationState::Tombstone)
                    .take(RECLAIM_BATCH)
                    .map(|(sequence, binding, _)| (*sequence, *binding))
                    .collect::<Vec<_>>();
                if expected != guard.selected
                    || transaction.rows.len() != expected.len()
                    || transaction
                        .rows
                        .iter()
                        .zip(&expected)
                        .any(|(row, expected)| {
                            row.binding != expected.1
                                || row.replacement.is_some()
                                || row.expected.as_ref().is_none_or(|record| {
                                    record.state != ReservationState::Tombstone
                                        || record.terminal_sequence != Some(expected.0)
                                })
                        })
                    || transaction.next.retired_terminal_sequence
                        != expected
                            .last()
                            .map(|(sequence, _)| *sequence)
                            .ok_or(ReservationError::SnapshotMismatch)?
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
                let mut selected_per_partition = BTreeMap::new();
                for (_, binding) in &expected {
                    let key = ProductionFloorKey::from_binding(*binding)?;
                    *selected_per_partition.entry(key).or_insert(0_usize) += 1;
                }
                let expected_releases = selected_per_partition
                    .iter()
                    .filter_map(|(key, selected)| {
                        let total = self
                            .rows
                            .keys()
                            .filter(|binding| {
                                ProductionFloorKey::from_binding(**binding) == Ok(*key)
                            })
                            .count();
                        (total == *selected).then_some(*key)
                    })
                    .collect::<Vec<_>>();
                if expected_releases != guard.released_partitions
                    || transaction.released_floors.len() != expected_releases.len()
                    || transaction
                        .released_floors
                        .iter()
                        .zip(&expected_releases)
                        .any(|(floor, key)| {
                            floor.key != *key
                                || floor.expected != self.floors.get(key).copied()
                                || floor.replacement.is_some()
                        })
                    || transaction
                        .released_retirement_cursors
                        .iter()
                        .any(|cursor| {
                            !expected_releases.contains(&cursor.key)
                                || cursor.expected.as_ref()
                                    != self.retirement_cursors.get(&cursor.key)
                                || cursor.replacement.is_some()
                        })
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
            for floor in &transaction.released_floors {
                if self.floors.get(&floor.key) != floor.expected.as_ref()
                    || floor.replacement.is_some()
                {
                    return Err(ReservationError::FloorAdvance);
                }
            }
            for cursor in &transaction.released_retirement_cursors {
                if self.retirement_cursors.get(&cursor.key) != cursor.expected.as_ref()
                    || cursor.replacement.is_some()
                {
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
                match floor.replacement() {
                    Some(replacement) => {
                        floors.insert(floor.key(), replacement);
                    }
                    None => {
                        floors.remove(&floor.key());
                    }
                }
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
            for cursor in transaction.released_retirement_cursors {
                retirement_cursors.remove(&cursor.key);
            }
            for floor in transaction.released_floors {
                floors.remove(&floor.key);
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
        admission_for_authority(
            tenant,
            identity,
            OwnerId::new("owner").unwrap(),
            FenceToken::new(1),
            Generation::new(1),
        )
    }

    fn admission_for_authority(
        tenant: &'static str,
        identity: u16,
        owner: OwnerId,
        fence: FenceToken,
        generation: Generation,
    ) -> Admission {
        admission_for_authority_in_scope(tenant, identity, owner, fence, generation, [9; 32])
    }

    fn admission_for_authority_in_scope(
        tenant: &'static str,
        identity: u16,
        owner: OwnerId,
        fence: FenceToken,
        generation: Generation,
        scope: [u8; 32],
    ) -> Admission {
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
            Scope::from_digest(scope),
            owner,
            fence,
            generation,
        )
        .unwrap()
    }

    fn absent_predecessor_admission(identity: u16) -> Admission {
        try_absent_predecessor_admission(identity, Generation::new(1)).unwrap()
    }

    fn v2_carrier_inputs(
        admission: &Admission,
    ) -> (
        RosterIngressAttestationV2,
        RosterProfileV2CompactAdmissionProvenanceV1,
    ) {
        let root_key = SigningKey::from_bytes((&[0x71; 32]).into()).unwrap();
        let root = RosterAttestationTrustRootV1::new(
            [0x72; 32],
            root_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let ingress_key = SigningKey::from_bytes((&[0x73; 32]).into()).unwrap();
        let identity = SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::new("v2-storage").unwrap(),
            crate::consensus::SessionConsensusConfigurationId::from_bytes([0x74; 32]),
            crate::consensus::SessionConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let at: Timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let ingress_input = RosterIngressAttestationSigningInputV2 {
            peer_identity_commitment: [0x75; 32],
            consumer_scope: admission.scope().digest(),
            request_id: [0x76; 16],
            operation_tag: 1,
            canonical_capsule_digest: [0x77; 32],
            authenticated_at: at.add_seconds(1).unwrap(),
            peer_certificate_expires_at: at.add_seconds(9).unwrap(),
            material_generation: 1,
            handshake_epoch: 1,
        };
        let ingress_certificate = attestation_certificate(
            &root,
            &root_key,
            &ingress_key,
            identity,
            admission.scope().digest(),
            [0x78; 32],
            at,
        );
        let ingress = RosterIngressAttestationV2::issue_from_signed_parts(
            &root,
            ingress_certificate.clone(),
            &ingress_input,
            sign_digest(&ingress_key, ingress_input.digest().unwrap()),
        )
        .unwrap();
        let authority = AuthorityBinding::for_admission(
            admission,
            admission.logical_owner().clone(),
            admission.admission_fence(),
            AuthorityLeaseMetadata::new(
                1,
                admission.expected_generation(),
                at.add_seconds(1).unwrap(),
                at.add_seconds(9).unwrap(),
            ),
        )
        .unwrap();
        let provenance_input =
            RosterProfileV2CompactAdmissionProvenanceSigningInputV1::for_admission(
                identity, admission, &authority, &ingress, [0x78; 32],
            )
            .unwrap();
        let provenance = RosterProfileV2CompactAdmissionProvenanceV1::issue_from_signed_parts(
            &root,
            ingress_certificate,
            &provenance_input,
            sign_digest(&ingress_key, provenance_input.digest().unwrap()),
        )
        .unwrap();
        (ingress, provenance)
    }

    fn attestation_certificate(
        root: &RosterAttestationTrustRootV1,
        root_key: &SigningKey,
        ingress_key: &SigningKey,
        identity: SessionConsensusIdentity,
        scope: [u8; 32],
        subject: [u8; 32],
        at: Timestamp,
    ) -> RosterAttestationLeafCertificatePartsV1 {
        let mut certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role: RosterAttestationCertificateRoleV1::TransportIngress,
            configuration_identity: identity,
            scope,
            subject_identity_commitment: subject,
            leaf_epoch: 1,
            key_id: [0x79; 32],
            not_before: at,
            not_after: at.add_seconds(10).unwrap(),
            public_key: ingress_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            root_signature: [0; 64],
        };
        certificate.root_signature = sign_digest(
            root_key,
            RosterAttestationLeafCertificateV1::signing_digest(&certificate).unwrap(),
        );
        certificate
    }

    fn sign_digest(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        signature.normalize_s().to_bytes().into()
    }

    fn v2_terminal_fixture(
        admission: &Admission,
    ) -> (
        CommittedTerminal,
        RosterProfileV2CompactTerminalEvidenceV1,
        RosterProfileV2ExecutorProofBundleV1,
    ) {
        let root_key = SigningKey::from_bytes((&[0x71; 32]).into()).unwrap();
        let root = RosterAttestationTrustRootV1::new(
            [0x72; 32],
            root_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let ingress_key = SigningKey::from_bytes((&[0x73; 32]).into()).unwrap();
        let executor_key = SigningKey::from_bytes((&[0x7a; 32]).into()).unwrap();
        let identity = SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::new("v2-storage").unwrap(),
            crate::consensus::SessionConsensusConfigurationId::from_bytes([0x74; 32]),
            crate::consensus::SessionConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let at: Timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let (admission_ingress, provenance) = v2_carrier_inputs(admission);
        let authority = AuthorityBinding::for_admission(
            admission,
            admission.logical_owner().clone(),
            admission.admission_fence(),
            AuthorityLeaseMetadata::new(
                1,
                admission.expected_generation(),
                at.add_seconds(1).unwrap(),
                at.add_seconds(9).unwrap(),
            ),
        )
        .unwrap();
        let binding = admission.binding_key(1).unwrap();
        let request_id = RequestId::bind(1, admission).unwrap();
        let registration = BackendRegistration::issue([0x7b; 32], request_id, admission).unwrap();
        let evidence = vec![0x7c];
        let terminal_record = TerminalRecord::new(
            admission,
            request_id,
            Phase::Established,
            admission
                .members()
                .iter()
                .map(|member| {
                    crate::fenced_mutation_roster::stable_terminal_proof_commitment(
                        binding,
                        registration,
                        admission,
                        Phase::Established,
                        member,
                        RosterProviderOutcomeV1::AppliedExecuted,
                        crate::fenced_mutation_roster::roster_executor_evidence_commitment(
                            &evidence,
                        ),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let committed = CommittedTerminal::issue_from_record(
            registration,
            admission,
            &authority,
            terminal_record.clone(),
            ConsensusCommitMetadata::issue(1, 2, at.add_seconds(2).unwrap()).unwrap(),
        )
        .unwrap();
        let terminal_input = RosterIngressAttestationSigningInputV2 {
            peer_identity_commitment: [0x75; 32],
            consumer_scope: admission.scope().digest(),
            request_id: [0x7d; 16],
            operation_tag: 4,
            canonical_capsule_digest: [0x7e; 32],
            authenticated_at: at.add_seconds(2).unwrap(),
            peer_certificate_expires_at: at.add_seconds(9).unwrap(),
            material_generation: 1,
            handshake_epoch: 1,
        };
        let terminal_ingress = RosterIngressAttestationV2::issue_from_signed_parts(
            &root,
            attestation_certificate(
                &root,
                &root_key,
                &ingress_key,
                identity,
                admission.scope().digest(),
                [0x78; 32],
                at,
            ),
            &terminal_input,
            sign_digest(&ingress_key, terminal_input.digest().unwrap()),
        )
        .unwrap();
        assert_ne!(admission_ingress, terminal_ingress);
        let (handle, registration_request_id, terminal_slot) = registration.consensus_parts();
        let input_for = |member: &Member| RosterProfileV2TerminalAttestationSigningInputV1 {
            profile: Profile::v2(),
            configuration_identity: identity,
            certificate_subject_identity_commitment: [0x7f; 32],
            certificate_role: RosterAttestationCertificateRoleV1::Executor,
            admission_provenance_commitment: provenance.commitment().unwrap(),
            binding: binding.to_bytes(),
            registration_handle: handle,
            registration_request_id: registration_request_id.to_bytes(),
            registration_terminal_slot: *terminal_slot.as_bytes(),
            roster_id: *admission.roster_id().as_bytes(),
            admission_commitment: admission.body_commitment(),
            terminal_phase: Phase::Established,
            terminal_body_commitment: terminal_record.body_commitment(),
            ordinal: member.ordinal(),
            member_operation_id: *member.operation_id().as_bytes(),
            descriptor: member.descriptor().to_vec(),
            descriptor_commitment: member.descriptor_commitment(),
            expected_member_version: member.expected_version(),
            admission_generation: admission.expected_generation().get(),
            authority_scope: authority.scope().digest(),
            authority_ingress_scope: authority.ingress_scope().digest(),
            authority_key_canonical: authority.key().canonical_digest_input(),
            authority_owner: authority.owner().as_str().as_bytes().to_vec(),
            authority_fence: authority.fence().get(),
            authority_credential_id: authority.credential_id(),
            authority_generation: authority.generation().get(),
            authority_acquired_at: authority.acquired_at(),
            authority_expires_at: authority.expires_at(),
            proof_epoch: 1,
            provider_operation: RosterProviderOperationV1::Execute,
            outcome: RosterProviderOutcomeV1::AppliedExecuted,
            evidence: evidence.clone(),
        };
        let compact_binding = RosterCompactTerminalEvidenceBindingV2::from_terminal_v2_input(
            &provenance,
            admission.terminal_checkpoint(),
            admission.terminal_result(),
            &input_for(&admission.members()[0]),
        )
        .unwrap();
        let certificate_for = |role, subject, key: &SigningKey| {
            let mut certificate = RosterAttestationLeafCertificatePartsV1 {
                root_id: root.root_id(),
                role,
                configuration_identity: identity,
                scope: authority.ingress_scope().digest(),
                subject_identity_commitment: subject,
                leaf_epoch: 1,
                key_id: [0x80; 32],
                not_before: at,
                not_after: at.add_seconds(10).unwrap(),
                public_key: key
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                root_signature: [0; 64],
            };
            certificate.root_signature = sign_digest(
                &root_key,
                RosterAttestationLeafCertificateV1::signing_digest(&certificate).unwrap(),
            );
            certificate
        };
        let proofs = admission
            .members()
            .iter()
            .zip(terminal_record.proof_commitments())
            .map(|(member, stable)| {
                let projection = RosterCompactTerminalMemberProjectionV2::from_terminal_v2_input(
                    &input_for(member),
                    *stable,
                )
                .unwrap();
                let provider_certificate = certificate_for(
                    RosterAttestationCertificateRoleV1::Provider,
                    [0x81; 32],
                    &executor_key,
                );
                let provider = RosterAttestationLeafCertificateV1::issue_from_signed_parts(
                    &root,
                    provider_certificate.clone(),
                )
                .unwrap();
                RosterCompactTerminalMemberProofPartsV2 {
                    provider_signature: sign_digest(
                        &executor_key,
                        crate::fenced_mutation_roster::provider_receipt_compact_digest(
                            &compact_binding,
                            &projection,
                            &provider,
                        )
                        .unwrap(),
                    ),
                    signature: sign_digest(
                        &executor_key,
                        RosterCompactTerminalMemberSigningInputV2 {
                            binding: compact_binding.clone(),
                            member: projection.clone(),
                        }
                        .digest()
                        .unwrap(),
                    ),
                    member: projection,
                    provider_certificate,
                }
            })
            .collect();
        let compact_evidence = RosterCompactTerminalEvidenceV2::issue_from_signed_parts(
            &root,
            certificate_for(
                RosterAttestationCertificateRoleV1::Executor,
                [0x7f; 32],
                &executor_key,
            ),
            &compact_binding,
            proofs,
        )
        .unwrap();
        let terminal_evidence = RosterProfileV2CompactTerminalEvidenceV1::from_verified(
            provenance.clone(),
            terminal_ingress.clone(),
            compact_evidence,
        )
        .unwrap();
        let bundle = RosterProfileV2ExecutorProofBundleV1::from_verified(
            &provenance,
            &terminal_ingress,
            terminal_evidence.clone(),
        )
        .unwrap();
        (committed, terminal_evidence, bundle)
    }

    fn try_absent_predecessor_admission(
        identity: u16,
        generation: Generation,
    ) -> Result<Admission, crate::fenced_mutation_roster::Error> {
        let key = SessionKey {
            tenant: TenantId::from_static("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from(identity.to_be_bytes().to_vec())).unwrap(),
        };
        let state_type = StateType::from_static("created");
        let key_id = KeyId::new("v2-roster-test-key").unwrap();
        let session_key_digest = crate::hex::encode_lower(&key.digest());
        let aad = EnvelopeAad::session(
            key.tenant.clone(),
            1,
            SessionAad::new(
                key.nf_kind.as_str(),
                session_key_digest,
                state_type.as_str(),
                Generation::new(1).get(),
                FenceToken::new(1).get(),
                "v2-roster-test-backend",
            )
            .unwrap(),
        );
        let checkpoint = CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            key_id: key_id.clone(),
            nonce: vec![0x51; 12],
            aad: serialize_bound_aad(&aad, &key_id).unwrap(),
            ciphertext_and_tag: vec![0x52; AEAD_TAG_LEN],
        }
        .encode()
        .unwrap();
        let proposal = AdmissionProposal::new(
            Profile::v2(),
            RosterId::from_bytes([8; ROSTER_ID_BYTES]).unwrap(),
            vec![Member::new(
                0,
                MemberOperationId::from_bytes([2; MEMBER_OPERATION_ID_BYTES]).unwrap(),
                vec![2],
                1,
            )
            .unwrap()],
            EstablishedMutation::create_checkpoint(state_type),
            vec![2],
            checkpoint,
            vec![4],
        )
        .unwrap();
        Admission::authenticate(
            proposal,
            key,
            Scope::from_digest([10; 32]),
            OwnerId::new("owner").unwrap(),
            FenceToken::new(1),
            generation,
        )
    }

    fn maximum_authority_admission(identity: u16) -> Admission {
        admission_for_authority(
            "tenant",
            identity,
            OwnerId::new("o".repeat(OwnerId::MAX_BYTES)).expect("maximum owner"),
            FenceToken::new(u64::MAX),
            Generation::new(u64::MAX),
        )
    }

    fn terminal(admission: &Admission) -> CommittedTerminal {
        terminal_at(admission, 1)
    }

    fn terminal_at(admission: &Admission, epoch: u64) -> CommittedTerminal {
        // Test admissions encode their unique identity in the stable id. Keep
        // the synthetic commit sequence globally unique so snapshot/restart
        // validation exercises the production total-order invariant. Identity
        // zero intentionally yields sequence one for the H=0 boundary.
        let terminal_sequence = admission
            .key()
            .stable_id
            .as_ref()
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
            + 1;
        terminal_at_with_raft_log_index(admission, epoch, terminal_sequence)
    }

    fn terminal_at_with_raft_log_index(
        admission: &Admission,
        epoch: u64,
        raft_log_index: u64,
    ) -> CommittedTerminal {
        terminal_at_with_phase(admission, epoch, raft_log_index, Phase::Aborted)
    }

    fn established_terminal(admission: &Admission) -> CommittedTerminal {
        let terminal_sequence = admission
            .key()
            .stable_id
            .as_ref()
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
            + 1;
        terminal_at_with_phase(admission, 1, terminal_sequence, Phase::Established)
    }

    fn terminal_at_with_phase(
        admission: &Admission,
        epoch: u64,
        raft_log_index: u64,
        phase: Phase,
    ) -> CommittedTerminal {
        let terminal_sequence = admission
            .key()
            .stable_id
            .as_ref()
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
            + 1;
        let record = TerminalRecord::new(
            admission,
            RequestId::bind(epoch, admission).unwrap(),
            phase,
            vec![[1; 32]; admission.members().len()],
        )
        .unwrap();
        let request = RequestId::bind(epoch, admission).unwrap();
        let registration = BackendRegistration::issue([1; 32], request, admission).unwrap();
        let committed_at = Timestamp::now_utc();
        let authority = AuthorityBinding::for_admission(
            admission,
            admission.logical_owner().clone(),
            admission.admission_fence(),
            AuthorityLeaseMetadata::new(
                1,
                admission.expected_generation(),
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
            ConsensusCommitMetadata::issue(terminal_sequence, raft_log_index, committed_at)
                .unwrap(),
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
        let prepared = prepare_production_admission(ProductionAdmissionPreparation {
            vacancy: &vacant(live.binding),
            existing: None,
            record: live,
            existing_floor: None,
            existing_retirement_cursor: None,
            witness: empty_witness(),
            budget,
            profile,
        })
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
        let admitted = prepare_production_admission(ProductionAdmissionPreparation {
            vacancy: &vacant(live.binding),
            existing: None,
            record: live,
            existing_floor: None,
            existing_retirement_cursor: None,
            witness: empty_witness(),
            budget: GlobalChargeBudget::v1(u64::MAX),
            profile,
        })
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
    fn v1_business_reservation_rejects_v2_absent_predecessor_create() {
        let admission = absent_predecessor_admission(33);
        let present = ProductionBusinessState::present(
            admission.key().clone(),
            Generation::new(1),
            admission.body_commitment().to_vec(),
        )
        .unwrap();

        assert_eq!(
            ProductionAdmissionBusinessReservation::new(&admission, present),
            Err(ReservationError::BusinessCas)
        );
    }

    #[test]
    fn v2_absent_reservation_accepts_only_v2_create_at_generation_one() {
        let v2_admission = absent_predecessor_admission(34);
        let binding = v2_admission.binding_key(1).unwrap();
        let reservation =
            ProductionAdmissionAbsentBusinessReservationV2::new(&v2_admission, binding).unwrap();

        assert_eq!(reservation.predicate().key(), v2_admission.key());
        assert_eq!(reservation.predicate().generation(), Generation::new(1));
        assert_eq!(
            reservation.admission_commitment(),
            v2_admission.body_commitment()
        );
        assert_eq!(reservation.binding(), binding);
        let present_predecessor_admission = admission(35);
        assert!(ProductionAdmissionAbsentBusinessReservationV2::new(
            &present_predecessor_admission,
            present_predecessor_admission.binding_key(1).unwrap(),
        )
        .is_err());
        assert!(try_absent_predecessor_admission(36, Generation::new(2)).is_err());

        let other = absent_predecessor_admission(37);
        assert!(reservation.validate_for(&other, binding).is_err());
        assert!(reservation
            .validate_for(&v2_admission, other.binding_key(1).unwrap())
            .is_err());

        let bytes = reservation.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..8], &ABSENT_BUSINESS_RESERVATION_V2_MAGIC);
        assert_eq!(
            ProductionAdmissionAbsentBusinessReservationV2::from_canonical_bytes(&bytes).unwrap(),
            reservation
        );
    }

    #[test]
    fn v2_q1_rejects_malformed_checkpoint_and_binds_the_exact_successor() {
        let admission = absent_predecessor_admission(41);
        let binding = admission.binding_key(1).unwrap();
        let reservation =
            ProductionAdmissionAbsentBusinessReservationV2::new(&admission, binding).unwrap();
        assert_eq!(reservation.successor().key(), admission.key());
        assert_eq!(reservation.successor().generation(), Generation::new(1));
        let successor = reservation.successor().authoritative_record().unwrap();
        assert_eq!(successor.key, *admission.key());
        assert_eq!(successor.owner, *admission.logical_owner());
        assert_eq!(successor.fence, admission.admission_fence());
        assert_eq!(successor.generation, Generation::new(1));
        assert_eq!(
            successor.state_type,
            *admission.established_mutation().state_type().unwrap()
        );
        assert!(successor.expires_at.is_none());

        let mut altered = reservation.clone();
        altered.successor.canonical.push(0);
        assert_eq!(
            altered.validate_for(&admission, binding),
            Err(ReservationError::BusinessCas),
            "Q2 cannot replace the Q1-validated successor",
        );

        let malformed = AdmissionProposal::new(
            Profile::v2(),
            RosterId::from_bytes([0x42; ROSTER_ID_BYTES]).unwrap(),
            vec![Member::new(
                0,
                MemberOperationId::from_bytes([0x43; MEMBER_OPERATION_ID_BYTES]).unwrap(),
                vec![1],
                1,
            )
            .unwrap()],
            EstablishedMutation::create_checkpoint(StateType::from_static("created")),
            vec![1],
            vec![0x44],
            vec![2],
        )
        .unwrap();
        let malformed = Admission::authenticate(
            malformed,
            admission.key().clone(),
            admission.scope(),
            admission.logical_owner().clone(),
            admission.admission_fence(),
            Generation::new(1),
        )
        .unwrap();
        assert_eq!(
            ProductionAdmissionAbsentBusinessReservationV2::new(
                &malformed,
                malformed.binding_key(1).unwrap(),
            ),
            Err(ReservationError::BusinessCas),
            "Q1 rejects a noncanonical checkpoint before any provider effect",
        );
    }

    #[test]
    fn v2_established_terminal_is_generation_one_insert_only() {
        let admission = absent_predecessor_admission(38);
        let binding = admission.binding_key(1).unwrap();
        let reservation =
            ProductionAdmissionAbsentBusinessReservationV2::new(&admission, binding).unwrap();
        let terminal = established_terminal(&admission);
        let cas = ProductionTerminalAbsentBusinessCasV2::from_committed(
            &admission,
            binding,
            &terminal,
            &reservation,
        )
        .unwrap();

        match cas.action() {
            ProductionTerminalAbsentBusinessActionV2::EstablishedCreate {
                reservation: action_reservation,
                successor,
            } => {
                assert_eq!(action_reservation, &reservation);
                assert_eq!(successor.key(), admission.key());
                assert_eq!(successor.generation(), Generation::new(1));
            }
            ProductionTerminalAbsentBusinessActionV2::AbortedCompareAbsentRelease { .. } => {
                panic!("Established V2 create must materialize exactly one successor")
            }
        }
    }

    #[test]
    fn v2_aborted_terminal_reproves_absence_and_releases_without_a_row() {
        let admission = absent_predecessor_admission(39);
        let binding = admission.binding_key(1).unwrap();
        let reservation =
            ProductionAdmissionAbsentBusinessReservationV2::new(&admission, binding).unwrap();
        let cas = ProductionTerminalAbsentBusinessCasV2::from_committed(
            &admission,
            binding,
            &terminal(&admission),
            &reservation,
        )
        .unwrap();

        match cas.action() {
            ProductionTerminalAbsentBusinessActionV2::AbortedCompareAbsentRelease {
                reservation: action_reservation,
            } => {
                assert_eq!(action_reservation, &reservation);
                assert_eq!(action_reservation.predicate().key(), admission.key());
            }
            ProductionTerminalAbsentBusinessActionV2::EstablishedCreate { .. } => {
                panic!("Aborted V2 terminal must not materialize a business row")
            }
        }
    }

    #[test]
    fn v2_live_carrier_round_trips_and_binds_q1_ingress_to_provenance() {
        let admission = absent_predecessor_admission(40);
        let binding = admission.binding_key(1).unwrap();
        let reservation =
            ProductionAdmissionAbsentBusinessReservationV2::new(&admission, binding).unwrap();
        let (ingress, provenance) = v2_carrier_inputs(&admission);
        let record = ProductionReservationRecord::live_v2_absent_with_provenance_and_ingress(
            &admission,
            &ingress,
            &provenance,
            1,
            reservation,
            ChargeProfile::v1(),
        )
        .unwrap();

        let canonical = record.to_canonical_bytes().unwrap();
        assert_eq!(&canonical[..8], &PRODUCTION_RESERVATION_RECORD_V2_MAGIC);
        let hydrated =
            ProductionReservationRecordV2::from_canonical_vec_hydrated(canonical.clone()).unwrap();
        assert_eq!(hydrated.canonical(), canonical);
        assert_eq!(hydrated.record(), &record);
        assert_eq!(hydrated.admission(), Some(&admission));
        assert_eq!(
            hydrated
                .admission_ingress()
                .expect("live V2 row retains Q1 ingress")
                .canonical_bytes()
                .unwrap(),
            ingress.canonical_bytes().unwrap(),
        );
        assert_eq!(
            hydrated.admission_provenance().canonical_bytes().unwrap(),
            provenance.canonical_bytes().unwrap(),
        );
        let mut corrupt = canonical;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(matches!(
            ProductionReservationRecordV2::from_canonical_vec_hydrated(corrupt),
            Err(ReservationError::CanonicalEncoding)
        ));

        let root_key = SigningKey::from_bytes((&[0x71; 32]).into()).unwrap();
        let ingress_key = SigningKey::from_bytes((&[0x73; 32]).into()).unwrap();
        let root = RosterAttestationTrustRootV1::new(
            [0x72; 32],
            root_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let identity = SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::new("v2-storage").unwrap(),
            crate::consensus::SessionConsensusConfigurationId::from_bytes([0x74; 32]),
            crate::consensus::SessionConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let at: Timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let v1_input = RosterIngressAttestationSigningInputV1 {
            peer_identity_commitment: [0x75; 32],
            consumer_scope: admission.scope().digest(),
            request_id: [0x7a; 16],
            operation_tag: 1,
            canonical_capsule_digest: [0x77; 32],
            authenticated_at: at.add_seconds(1).unwrap(),
            peer_certificate_expires_at: at.add_seconds(9).unwrap(),
            material_generation: 1,
            handshake_epoch: 1,
        };
        let v1_ingress = RosterIngressAttestationV1::issue_from_signed_parts(
            &root,
            attestation_certificate(
                &root,
                &root_key,
                &ingress_key,
                identity,
                admission.scope().digest(),
                [0x78; 32],
                at,
            ),
            &v1_input,
            sign_digest(&ingress_key, v1_input.digest().unwrap()),
        )
        .unwrap();
        let mut cross_profile = record;
        cross_profile.admission_ingress = v1_ingress.canonical_bytes().unwrap();
        let cross_profile = encode_frame(
            PRODUCTION_RESERVATION_RECORD_V2_MAGIC,
            PRODUCTION_RESERVATION_RECORD_V2_DOMAIN,
            &cross_profile,
            MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES,
        )
        .unwrap();
        assert!(matches!(
            ProductionReservationRecordV2::from_canonical_bytes(&cross_profile),
            Err(ReservationError::SnapshotMismatch)
        ));
    }

    #[test]
    fn v2_distinct_q1_q2_terminalization_round_trips_retained_carrier() {
        let admission = absent_predecessor_admission(42);
        let record = live_v2(&admission, 1, ChargeProfile::v1());
        let (terminal, evidence, bundle) = v2_terminal_fixture(&admission);

        let prepared = record
            .prepare_terminalization(&terminal, &bundle, &evidence, ChargeProfile::v1())
            .unwrap();
        let retained = prepared.replacement();
        assert!(matches!(
            retained.state(),
            ProductionReservationStateV2::Retained
        ));
        assert!(retained.absence_reservation().is_none());
        let canonical = retained.to_canonical_bytes().unwrap();
        assert_eq!(
            ProductionReservationRecordV2::from_canonical_bytes(&canonical).unwrap(),
            *retained
        );
        assert_eq!(
            retained.terminal_evidence_bytes().unwrap(),
            evidence.canonical_bytes().unwrap()
        );
        assert_eq!(
            retained.terminal_proof_bundle_bytes().unwrap(),
            bundle.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn v2_rejects_reusing_q1_ingress_as_q2() {
        let admission = absent_predecessor_admission(43);
        let record = live_v2(&admission, 1, ChargeProfile::v1());
        let (terminal, evidence, _) = v2_terminal_fixture(&admission);
        let provenance = RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(
            record.admission_provenance_bytes(),
        )
        .unwrap();
        let q1_ingress =
            RosterIngressAttestationV2::decode_canonical(record.admission_ingress_bytes()).unwrap();
        let reused_evidence = RosterProfileV2CompactTerminalEvidenceV1::from_verified(
            provenance.clone(),
            q1_ingress.clone(),
            evidence.evidence().clone(),
        )
        .unwrap();
        let reused_bundle = RosterProfileV2ExecutorProofBundleV1::from_verified(
            &provenance,
            &q1_ingress,
            reused_evidence.clone(),
        )
        .unwrap();

        assert!(matches!(
            record.prepare_terminalization(
                &terminal,
                &reused_bundle,
                &reused_evidence,
                ChargeProfile::v1(),
            ),
            Err(ReservationError::SnapshotMismatch)
        ));
    }

    #[test]
    fn v2_rejects_mismatched_q2_capsule_before_prepared_write() {
        let admission = absent_predecessor_admission(44);
        let record = live_v2(&admission, 1, ChargeProfile::v1());
        let before = record.to_canonical_bytes().unwrap();
        let (terminal, evidence, _) = v2_terminal_fixture(&admission);
        let provenance = RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(
            record.admission_provenance_bytes(),
        )
        .unwrap();
        let q1_ingress =
            RosterIngressAttestationV2::decode_canonical(record.admission_ingress_bytes()).unwrap();
        let substituted = RosterProfileV2CompactTerminalEvidenceV1::from_verified(
            provenance.clone(),
            q1_ingress.clone(),
            evidence.evidence().clone(),
        )
        .unwrap();
        let tampered_bundle = RosterProfileV2ExecutorProofBundleV1::from_verified(
            &provenance,
            &q1_ingress,
            substituted,
        )
        .unwrap();

        assert!(matches!(
            record.prepare_terminalization(
                &terminal,
                &tampered_bundle,
                &evidence,
                ChargeProfile::v1(),
            ),
            Err(ReservationError::SnapshotMismatch)
        ));
        assert_eq!(record.to_canonical_bytes().unwrap(), before);
    }

    #[test]
    fn v2_reclaim_requires_the_exact_retention_boundary_and_preserves_conflict_closure() {
        let profile = profile();
        let admission = absent_predecessor_admission(49);
        let live = live_v2(&admission, 1, profile);
        let (terminal, evidence, bundle) = v2_terminal_fixture(&admission);
        let retained = live
            .prepare_terminalization(&terminal, &bundle, &evidence, profile)
            .unwrap()
            .replacement()
            .clone();
        let witness = GlobalChargeWitness::empty().with_roster(
            counters_with_production_record_v2(zero_counters(), &retained, profile).unwrap(),
        );
        let boundary = retained
            .terminalized_at()
            .unwrap()
            .checked_add_retention()
            .unwrap();

        assert!(matches!(
            prepare_production_v2_reclaim(
                &retained,
                ConsensusMaintenanceTimestamp(boundary.0 - 1),
                witness,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::NotEligible)
        ));

        let prepared = prepare_production_v2_reclaim(
            &retained,
            boundary,
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let compact = prepared.replacement();
        assert!(matches!(
            compact.state(),
            ProductionReservationStateV2::Tombstone
        ));
        assert!(compact.absence_reservation().is_none());
        assert!(compact.admission().is_err());
        let tombstone = compact.tombstone().unwrap().unwrap();
        assert!(tombstone
            .validate_admission_for_profile(
                crate::fenced_mutation_roster::Profile::v2(),
                1,
                &admission,
            )
            .is_ok());
        assert!(tombstone
            .validate_admission_for_profile(
                crate::fenced_mutation_roster::Profile::v2(),
                1,
                &absent_predecessor_admission(50),
            )
            .is_err());
        assert!(tombstone
            .validate_profile_v2_compact_terminal_evidence(
                &compact.v2_terminal_evidence().unwrap().unwrap(),
            )
            .is_ok());
        assert!(
            prepared.next_witness().total_charge_bytes().unwrap()
                < prepared.previous_witness().total_charge_bytes().unwrap()
        );
    }

    #[test]
    fn v2_compact_tombstone_round_trip_keeps_terminal_conflict_evidence() {
        let profile = ChargeProfile::v1();
        let admission = absent_predecessor_admission(51);
        let live = live_v2(&admission, 1, profile);
        let (terminal, evidence, bundle) = v2_terminal_fixture(&admission);
        let retained = live
            .prepare_terminalization(&terminal, &bundle, &evidence, profile)
            .unwrap()
            .replacement()
            .clone();
        let witness = GlobalChargeWitness::empty().with_roster(
            counters_with_production_record_v2(zero_counters(), &retained, profile).unwrap(),
        );
        let compact = prepare_production_v2_reclaim(
            &retained,
            retained
                .terminalized_at()
                .unwrap()
                .checked_add_retention()
                .unwrap(),
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap()
        .replacement()
        .clone();

        let canonical = compact.to_canonical_bytes().unwrap();
        let hydrated =
            ProductionReservationRecordV2::from_canonical_vec_hydrated(canonical.clone()).unwrap();
        assert_eq!(hydrated.canonical(), canonical);
        assert!(hydrated.admission().is_none());
        assert!(hydrated.admission_ingress().is_none());
        assert_eq!(
            hydrated
                .terminal_evidence()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            evidence.canonical_bytes().unwrap(),
        );
        let tombstone = compact.tombstone().unwrap().unwrap();
        let binding = admission.binding_key(1).unwrap();
        assert!(tombstone
            .validate_binding_for_profile(crate::fenced_mutation_roster::Profile::v2(), binding)
            .is_ok());
        assert!(tombstone
            .validate_binding_for_profile(crate::fenced_mutation_roster::Profile::v1(), binding)
            .is_err());
        assert!(tombstone
            .validate_profile_v2_compact_terminal_evidence(
                &compact.v2_terminal_evidence().unwrap().unwrap(),
            )
            .is_ok());
        assert!(hydrated.tombstone().is_some());
        assert!(hydrated.terminal_evidence().is_some());
        assert_eq!(
            hydrated.admission_provenance().canonical_bytes().unwrap(),
            compact
                .v2_admission_provenance()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
        );
    }

    #[test]
    fn v2_q1_reserves_shared_witness_peak_and_rejects_without_effect() {
        let profile = profile();
        let v1 = live(&admission(45), 1, profile);
        let v2 = live_v2(&absent_predecessor_admission(46), 1, profile);
        let witness = GlobalChargeWitness::v1(
            0,
            0,
            validate_production_snapshot(std::slice::from_ref(&v1), profile).unwrap(),
        );
        let required = witness
            .total_charge_bytes()
            .unwrap()
            .checked_add(v2.peak_charge_bytes())
            .unwrap();

        let unchanged = witness;
        assert!(matches!(
            prepare_production_v2_admission_capacity(
                &v2,
                witness,
                GlobalChargeBudget::v1(required - 1),
                profile,
            ),
            Err(ReservationError::BudgetExceeded),
        ));
        assert_eq!(witness, unchanged, "a rejected V2 Q1 has no witness effect");

        let prepared = prepare_production_v2_admission_capacity(
            &v2,
            witness,
            GlobalChargeBudget::v1(required),
            profile,
        )
        .unwrap();
        assert_eq!(
            prepared.next_witness().roster.live_reservations,
            witness.roster.live_reservations + 1
        );
        assert_eq!(
            prepared.next_witness().roster.retained_and_live_bindings,
            witness.roster.retained_and_live_bindings + 1
        );
        assert_eq!(
            validate_production_snapshot_combined_witness(
                std::slice::from_ref(&v1),
                std::slice::from_ref(&v2),
                prepared.next_witness(),
                GlobalChargeBudget::v1(required),
                profile,
            )
            .unwrap(),
            prepared.next_witness().roster,
        );

        let mut tampered = prepared.next_witness();
        tampered.roster.live_reservations += 1;
        assert_eq!(
            validate_production_snapshot_combined_witness(
                std::slice::from_ref(&v1),
                std::slice::from_ref(&v2),
                tampered,
                GlobalChargeBudget::v1(required),
                profile,
            ),
            Err(ReservationError::WitnessMismatch),
        );
    }

    #[test]
    fn v2_combined_snapshot_rejects_binding_alias_and_preserves_key_isolation() {
        let profile = profile();
        let first = live_v2(&absent_predecessor_admission(47), 1, profile);
        let second = live_v2(&absent_predecessor_admission(48), 1, profile);
        assert_ne!(
            first.absence_reservation().unwrap().predicate().key(),
            second.absence_reservation().unwrap().predicate().key(),
        );
        assert!(
            validate_production_snapshot_combined(&[], &[first.clone(), second], profile,).is_ok()
        );
        assert_eq!(
            validate_production_snapshot_combined(&[], &[first.clone(), first], profile),
            Err(ReservationError::Duplicate),
        );
    }

    #[test]
    fn binding_vacancy_requires_both_profile_tables_to_be_absent() {
        let profile = profile();
        let v1 = live(&admission(52), 1, profile);
        let mut v2 = live_v2(&absent_predecessor_admission(53), 1, profile);
        v2.binding = v1.binding;

        assert!(matches!(
            ProductionBindingVacancyGuard::from_lookups(v1.binding, Some(&v1), None),
            Err(ReservationError::Duplicate)
        ));
        assert!(matches!(
            ProductionBindingVacancyGuard::from_lookups(v1.binding, None, Some(&v2)),
            Err(ReservationError::Duplicate)
        ));

        let wrong = vacant(v1.binding);
        let other = live(&admission(54), 1, profile);
        assert!(matches!(
            prepare_production_admission(ProductionAdmissionPreparation {
                vacancy: &wrong,
                existing: None,
                record: other,
                existing_floor: None,
                existing_retirement_cursor: None,
                witness: empty_witness(),
                budget: GlobalChargeBudget::v1(u64::MAX),
                profile,
            }),
            Err(ReservationError::SnapshotMismatch)
        ));

        let v2 = live_v2(&absent_predecessor_admission(55), 1, profile);
        let prepared = prepare_production_v2_admission_with_floor(
            &vacant(v2.binding()),
            &v2,
            None,
            None,
            empty_witness(),
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(
            prepared.floor_cas().key(),
            ProductionFloorKey::from_binding(v2.binding()).unwrap()
        );
    }

    #[test]
    fn mixed_reclaim_rows_expose_only_their_exact_profile_carriers() {
        let profile = profile();
        let v1 = live(&admission(56), 1, profile);
        let v2 = live_v2(&absent_predecessor_admission(57), 1, profile);

        let v1_update = ProductionMixedReclaimRow::V1 {
            expected: Box::new(v1.clone()),
            replacement: Box::new(v1.clone()),
        };
        assert_eq!(v1_update.v1_replacement(), Some((&v1, &v1)));
        assert_eq!(v1_update.v1_expected_row(), Some(&v1));
        assert_eq!(v1_update.v1_replacement_row(), Some(&v1));
        assert!(v1_update.v2_replacement().is_none());
        assert!(v1_update.v1_delete().is_none());

        let v2_update = ProductionMixedReclaimRow::V2 {
            expected: Box::new(v2.clone()),
            replacement: Box::new(v2.clone()),
        };
        assert_eq!(v2_update.v2_replacement(), Some((&v2, &v2)));
        assert_eq!(v2_update.v2_expected_row(), Some(&v2));
        assert_eq!(v2_update.v2_replacement_row(), Some(&v2));
        assert!(v2_update.v1_replacement().is_none());
        assert!(v2_update.v2_delete().is_none());

        let v1_delete = ProductionMixedReclaimRow::DeleteV1(Box::new(v1.clone()));
        assert_eq!(v1_delete.v1_delete(), Some(&v1));
        assert_eq!(v1_delete.v1_expected_row(), Some(&v1));
        assert!(v1_delete.v1_replacement_row().is_none());
        assert!(v1_delete.v2_delete().is_none());

        let v2_delete = ProductionMixedReclaimRow::DeleteV2(Box::new(v2.clone()));
        assert_eq!(v2_delete.v2_delete(), Some(&v2));
        assert_eq!(v2_delete.v2_expected_row(), Some(&v2));
        assert!(v2_delete.v2_replacement_row().is_none());
        assert!(v2_delete.v1_delete().is_none());
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
        let reserved = production_components(&live.admission, None, None, 0).unwrap();
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
    fn production_compact_evidence_reserves_the_complete_tombstone_envelope() {
        let components = production_components(&[], None, None, MAX_COMPACT_PROVENANCE_BYTES)
            .expect("current bounded production components");
        let charges = ChargeProfile::v1()
            .charge(components)
            .expect("current compact evidence fits the frozen charge profile");

        assert_eq!(MAX_COMPACT_PROVENANCE_BYTES, 10 * 1024);
        assert_eq!(MAX_TOMBSTONE_CHARGE_BYTES, 3 * STORAGE_CHARGE_PAGE_BYTES);
        assert_eq!(charges.tombstone, MAX_TOMBSTONE_CHARGE_BYTES);
    }

    #[test]
    fn prevalidated_terminal_finalizer_preserves_exact_canonical_cas_witness() {
        let profile = profile();
        let admission = admission(33);
        let current = live(&admission, 1, profile);
        let terminal = terminal(&admission);
        let witness = GlobalChargeWitness::v1(
            0,
            0,
            validate_production_snapshot(std::slice::from_ref(&current), profile).unwrap(),
        );
        let budget = GlobalChargeBudget::v1(u64::MAX);
        let ordinary = prepare_production_terminalization(
            &current,
            current.binding,
            &terminal,
            witness,
            budget,
            profile,
        )
        .unwrap();
        let expected_canonical = current.to_canonical_bytes().unwrap();
        let reservation = current.business_reservation.as_ref().unwrap();
        let business =
            ProductionTerminalBusinessCas::from_committed(&admission, &terminal, reservation)
                .unwrap();
        let mut replacement = current.clone();
        replacement.terminalize(&terminal, profile).unwrap();
        let prepared =
            prepare_production_transition_prevalidated(ProductionTransitionPreparation {
                current: Some(current),
                expected_canonical: Some(expected_canonical.clone()),
                binding: ordinary.binding().unwrap(),
                replacement,
                replacement_canonical: None,
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
            .unwrap();
        let ordinary_row = ordinary.rows().first().unwrap();
        let prepared_row = prepared.rows().first().unwrap();
        assert_eq!(
            prepared_row.expected_canonical_bytes(),
            Some(expected_canonical.as_slice())
        );
        assert_eq!(
            ordinary_row
                .replacement()
                .unwrap()
                .to_canonical_bytes()
                .unwrap(),
            prepared_row
                .replacement()
                .unwrap()
                .to_canonical_bytes()
                .unwrap(),
        );
        assert_eq!(ordinary.next_witness(), prepared.next_witness());
    }

    #[test]
    fn hydrated_production_terminal_gate_rejects_legacy_payload() {
        let profile = profile();
        let admission = admission(34);
        let current = live(&admission, 1, profile);
        let binding = current.binding;
        let hydrated = ProductionReservationRecord::from_canonical_vec_hydrated(
            current.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        assert!(matches!(
            into_hydrated_live_terminal_parts(hydrated, binding),
            Err(ReservationError::InvalidState)
        ));
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
            prepare_production_admission(ProductionAdmissionPreparation {
                vacancy: &vacant(record.binding),
                existing: None,
                record: record.clone(),
                existing_floor: None,
                existing_retirement_cursor: None,
                witness: empty_witness(),
                budget: short,
                profile,
            }),
            Err(ReservationError::BudgetExceeded)
        ));
        let unknown = GlobalChargeWitness {
            version: GLOBAL_CHARGE_WITNESS_VERSION + 1,
            ..empty_witness()
        };
        assert!(matches!(
            prepare_production_admission(ProductionAdmissionPreparation {
                vacancy: &vacant(record.binding),
                existing: None,
                record,
                existing_floor: None,
                existing_retirement_cursor: None,
                witness: unknown,
                budget: GlobalChargeBudget::v1(u64::MAX),
                profile,
            }),
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
        assert_eq!(exact.version, GLOBAL_CHARGE_WITNESS_VERSION);
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
                version: GLOBAL_CHARGE_WITNESS_VERSION + 1,
                ..exact
            }
            .validate_frozen_profile(),
            Err(ReservationError::UnknownWitnessVersion)
        ));
        assert!(matches!(
            GlobalChargeWitness {
                version: GLOBAL_CHARGE_WITNESS_VERSION + 1,
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
        let at_boundary = prepare_production_admission(ProductionAdmissionPreparation {
            vacancy: &vacant(record.binding),
            existing: None,
            record: record.clone(),
            existing_floor: None,
            existing_retirement_cursor: None,
            witness: GlobalChargeWitness::v1(0, 0, boundary),
            budget: GlobalChargeBudget::v1(u64::MAX),
            profile,
        })
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
            prepare_production_admission(ProductionAdmissionPreparation {
                vacancy: &vacant(record.binding),
                existing: None,
                record: record.clone(),
                existing_floor: Some(floor),
                existing_retirement_cursor: None,
                witness: GlobalChargeWitness::v1(
                    0,
                    0,
                    AggregateCounters {
                        retained_and_live_bindings: MAX_RESERVED_AND_RETAINED,
                        durable_epoch_bindings: MAX_RESERVED_AND_RETAINED - 1,
                        ..zero_counters()
                    },
                ),
                budget: GlobalChargeBudget::v1(u64::MAX),
                profile,
            }),
            Err(ReservationError::BindingLimit)
        ));
        assert!(matches!(
            prepare_production_admission(ProductionAdmissionPreparation {
                vacancy: &vacant(record.binding),
                existing: None,
                record,
                existing_floor: Some(floor),
                existing_retirement_cursor: None,
                witness: GlobalChargeWitness::v1(
                    0,
                    0,
                    AggregateCounters {
                        durable_epoch_bindings: MAX_RESERVED_AND_RETAINED,
                        ..zero_counters()
                    },
                ),
                budget: GlobalChargeBudget::v1(u64::MAX),
                profile,
            }),
            Err(ReservationError::DurableBindingLimit)
        ));

        let floor_limited_admission = admission(u16::MAX - 2);
        let floor_limited_record = live(&floor_limited_admission, 1, profile);
        assert!(matches!(
            prepare_production_admission(ProductionAdmissionPreparation {
                vacancy: &vacant(floor_limited_record.binding),
                existing: None,
                record: floor_limited_record,
                existing_floor: None,
                existing_retirement_cursor: None,
                witness: GlobalChargeWitness::v1(
                    0,
                    0,
                    AggregateCounters {
                        floor_count: MAX_RESERVED_AND_RETAINED,
                        ..zero_counters()
                    },
                ),
                budget: GlobalChargeBudget::v1(u64::MAX),
                profile,
            }),
            Err(ReservationError::FloorLimit)
        ));
    }

    #[test]
    fn counter_growth_caps_floors_before_any_collection_growth() {
        let record = live(&admission(u16::MAX - 3), 1, profile());
        let floor = IrreversibleHistoryFloor::initial(record.binding).unwrap();
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
    fn terminalization_reuses_its_admission_slot_at_capacity() {
        let profile = profile();
        let admitted = admission(55);
        let live = live(&admitted, 1, profile);
        let mut counters =
            validate_production_snapshot(std::slice::from_ref(&live), profile).unwrap();
        counters.retained_and_live_bindings = MAX_RESERVED_AND_RETAINED;
        counters.durable_epoch_bindings = MAX_RESERVED_AND_RETAINED;
        let prepared = prepare_production_terminalization(
            &live,
            live.binding,
            &terminal(&admitted),
            GlobalChargeWitness::v1(0, 0, counters),
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .expect("live-to-retained must not consume another capacity/history slot");
        assert_eq!(
            prepared.next_witness().roster.retained_and_live_bindings(),
            MAX_RESERVED_AND_RETAINED
        );
        assert_eq!(
            prepared.next_witness().roster.durable_epoch_bindings(),
            MAX_RESERVED_AND_RETAINED
        );
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
    fn complete_transaction_adapter_commits_rows_witness_and_floor_together() {
        let profile = profile();
        let admitted = admission(42);
        let live = live(&admitted, 1, profile);
        let mut store = InMemoryProductionStore {
            rows: BTreeMap::new(),
            witness: empty_witness(),
            floors: BTreeMap::new(),
            retirement_cursors: BTreeMap::new(),
            business: Some(live.business_reservation.as_ref().unwrap().expected.clone()),
            business_reservation: None,
            fail_at: None,
        };
        let admission_tx = prepare_production_admission(ProductionAdmissionPreparation {
            vacancy: &vacant(live.binding),
            existing: None,
            record: live,
            existing_floor: None,
            existing_retirement_cursor: None,
            witness: store.witness,
            budget: GlobalChargeBudget::v1(u64::MAX),
            profile,
        })
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
        assert_eq!(store.rows[&binding].state, ReservationState::Tombstone);
        assert_eq!(store.witness.roster.floor_count(), 1);
        assert_eq!(store.witness.roster.durable_epoch_bindings(), 1);
    }

    #[test]
    fn reclaim_preserves_the_committed_terminal_raft_log_index_in_the_tombstone() {
        let profile = profile();
        let admitted = admission(77);
        let committed = terminal_at(&admitted, 7);
        let commit_metadata = committed.commit_metadata();
        let expected_raft_log_index = commit_metadata.raft_log_index();
        let exact_reclaim_time = ConsensusMaintenanceTimestamp::from_consensus_timestamp(
            commit_metadata
                .committed_at()
                .add_seconds(24 * 60 * 60)
                .expect("exact retention boundary"),
        )
        .expect("bounded maintenance timestamp");
        let mut record = live(&admitted, 7, profile);
        record
            .terminalize(&committed, profile)
            .expect("retain committed terminal");
        record
            .reclaim_at(exact_reclaim_time, profile)
            .expect("reclaim at the retention boundary");

        let tombstone = record
            .tombstone()
            .expect("decode compact tombstone")
            .expect("compact tombstone present");
        assert_eq!(
            tombstone.terminal_raft_log_index(),
            expected_raft_log_index,
            "reclaim must preserve the exact authenticated commit interval"
        );
        assert!(
            tombstone
                .to_canonical_bytes()
                .expect("canonical tombstone")
                .len()
                <= MAX_TOMBSTONE_CODEC_BYTES
        );
    }

    #[test]
    fn reclaim_maximum_owner_and_scalars_fit_the_fixed_tombstone_ceiling() {
        let profile = profile();
        let admitted = maximum_authority_admission(78);
        let committed = terminal_at_with_raft_log_index(&admitted, 7, u64::MAX);
        let commit_metadata = committed.commit_metadata();
        let exact_reclaim_time = ConsensusMaintenanceTimestamp::from_consensus_timestamp(
            commit_metadata
                .committed_at()
                .add_seconds(24 * 60 * 60)
                .expect("exact retention boundary"),
        )
        .expect("bounded maintenance timestamp");
        let mut record = live(&admitted, 7, profile);
        record
            .terminalize(&committed, profile)
            .expect("retain committed terminal");
        record
            .reclaim_at(exact_reclaim_time, profile)
            .expect("reclaim maximum compact terminal");

        let tombstone = record
            .tombstone()
            .expect("decode compact tombstone")
            .expect("compact tombstone present");
        let canonical = tombstone
            .to_canonical_bytes()
            .expect("canonical maximum tombstone");
        assert_eq!(canonical.len(), 237);
        assert!(canonical.len() <= MAX_TOMBSTONE_CODEC_BYTES);
        assert_eq!(tombstone.terminal_raft_log_index(), u64::MAX);
    }

    #[test]
    fn production_snapshot_validator_bounds_admission_and_terminal_indices_by_applied_horizon() {
        let profile = profile();
        let horizon = 10;
        let witness = GlobalChargeWitness::empty();
        let live_within_horizon = live(&admission(79), 7, profile);
        let live_future = live(&admission(80), 11, profile);

        assert!(
            ProductionSnapshotStreamValidator::new(u64::MAX, Some(horizon))
                .add_record(&live_within_horizon, None, witness, profile)
                .is_ok()
        );
        for applied in [None, Some(0)] {
            assert_eq!(
                ProductionSnapshotStreamValidator::new(u64::MAX, applied).add_record(
                    &live_within_horizon,
                    None,
                    witness,
                    profile,
                ),
                Err(ReservationError::SnapshotMismatch),
                "a roster admission needs a nonzero applied Raft horizon",
            );
        }
        assert_eq!(
            ProductionSnapshotStreamValidator::new(u64::MAX, Some(horizon)).add_record(
                &live_future,
                None,
                witness,
                profile,
            ),
            Err(ReservationError::SnapshotMismatch),
            "a live admission cannot point beyond the applied Raft horizon",
        );

        let admitted = admission(81);
        let committed = terminal_at_with_raft_log_index(&admitted, 7, 8);
        let mut retained = live(&admitted, 7, profile);
        retained
            .terminalize(&committed, profile)
            .expect("retain terminal for applied-horizon validation");
        let exact_reclaim_time = ConsensusMaintenanceTimestamp::from_consensus_timestamp(
            committed
                .commit_metadata()
                .committed_at()
                .add_seconds(24 * 60 * 60)
                .expect("exact retention boundary"),
        )
        .expect("bounded maintenance timestamp");
        let mut tombstone = retained.clone();
        tombstone
            .reclaim_at(exact_reclaim_time, profile)
            .expect("compact terminal for applied-horizon validation");

        for (label, record) in [("retained", &retained), ("tombstone", &tombstone)] {
            assert!(
                ProductionSnapshotStreamValidator::new(u64::MAX, Some(horizon))
                    .add_record(record, Some(8), witness, profile)
                    .is_ok(),
                "{label} terminal index inside its interval is valid"
            );
            for terminal_raft_log_index in [None, Some(6), Some(7), Some(11)] {
                assert_eq!(
                    ProductionSnapshotStreamValidator::new(u64::MAX, Some(horizon)).add_record(
                        record,
                        terminal_raft_log_index,
                        witness,
                        profile,
                    ),
                    Err(ReservationError::SnapshotMismatch),
                    "{label} terminal index must satisfy admission < terminal <= applied",
                );
            }
        }
    }

    #[test]
    fn retirement_deletes_a_completed_empty_partition_and_releases_its_floor() {
        let profile = profile();
        let admitted = admission(43);
        let mut record = live(&admitted, 7, profile);
        record
            .terminalize(&terminal_at(&admitted, 7), profile)
            .unwrap();
        record.reclaim_at(aged_maintenance_time(), profile).unwrap();
        let previous = IrreversibleHistoryFloor::initial(record.binding).unwrap();
        let counters = counters_with_production_floor(
            validate_production_snapshot(std::slice::from_ref(&record), profile).unwrap(),
            previous,
        )
        .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        let next = previous.advance_to(record.binding.history_epoch()).unwrap();
        let selected = vec![(record.binding, record.clone())];
        let prepared = prepare_production_retirement(
            ProductionRetirementPrefix::new(previous, next, &selected, true, true).unwrap(),
            previous,
            next,
            None,
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let mut store = InMemoryProductionStore {
            rows: BTreeMap::from([(record.binding, record)]),
            witness,
            floors: BTreeMap::from([(ProductionFloorKey::from_floor(previous).unwrap(), previous)]),
            retirement_cursors: BTreeMap::new(),
            business: None,
            business_reservation: None,
            fail_at: None,
        };
        store.compare_and_apply_production(prepared).unwrap();
        assert!(store.rows.is_empty());
        assert!(store.floors.is_empty());
        assert_eq!(
            next.retired_through(),
            7,
            "sparse history epochs advance directly"
        );
        assert_eq!(store.witness.roster.durable_epoch_bindings(), 0);
        assert_eq!(store.witness.roster.floor_count(), 0);
    }

    #[test]
    fn retirement_advances_the_floor_when_a_higher_epoch_remains() {
        let profile = profile();
        let admitted = admission(143);
        let mut retired = live(&admitted, 7, profile);
        retired
            .terminalize(&terminal_at(&admitted, 7), profile)
            .unwrap();
        retired
            .reclaim_at(aged_maintenance_time(), profile)
            .unwrap();
        let later_admission = admission(144);
        let later = live(&later_admission, 8, profile);
        let previous = IrreversibleHistoryFloor::initial(retired.binding).unwrap();
        let next = previous.advance_to(7).unwrap();
        let records = vec![retired.clone(), later.clone()];
        let counters = counters_with_production_floor(
            validate_production_snapshot(&records, profile).unwrap(),
            previous,
        )
        .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        let selected = vec![(retired.binding, retired.clone())];
        let incorrectly_empty = prepare_production_retirement(
            ProductionRetirementPrefix::new(previous, next, &selected, true, true).unwrap(),
            previous,
            next,
            None,
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        let mut store = InMemoryProductionStore {
            rows: BTreeMap::from([
                (retired.binding, retired.clone()),
                (later.binding, later.clone()),
            ]),
            witness,
            floors: BTreeMap::from([(ProductionFloorKey::from_floor(previous).unwrap(), previous)]),
            retirement_cursors: BTreeMap::new(),
            business: None,
            business_reservation: None,
            fail_at: None,
        };
        assert!(matches!(
            store.compare_and_apply_production(incorrectly_empty),
            Err(ReservationError::SnapshotMismatch)
        ));

        let prepared = prepare_production_retirement(
            ProductionRetirementPrefix::new(previous, next, &selected, true, false).unwrap(),
            previous,
            next,
            None,
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        store.compare_and_apply_production(prepared).unwrap();
        assert_eq!(store.rows, BTreeMap::from([(later.binding, later)]));
        assert_eq!(
            store.floors[&ProductionFloorKey::from_floor(next).unwrap()],
            next
        );
        assert_eq!(store.witness.roster.durable_epoch_bindings(), 1);
        assert_eq!(store.witness.roster.floor_count(), 1);
    }

    #[test]
    fn mixed_terminal_retirement_releases_a_v1_only_empty_final_partition() {
        let profile = profile();
        let record = compact_v1_terminal(&admission(145), 1, profile);
        let floor = IrreversibleHistoryFloor::initial(record.binding()).unwrap();
        let counters = counters_with_production_floor(
            counters_with_production_record(zero_counters(), &record, profile).unwrap(),
            floor,
        )
        .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        let partition = ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
            floor, None, 1, true, true,
        )
        .unwrap();

        let prepared = prepare_production_mixed_terminal_retirement(
            &[ProductionMixedTerminalRetirementSelection::V1(&record)],
            &[partition],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();

        assert_eq!(prepared.floor_actions().len(), 1);
        assert_eq!(prepared.floor_actions()[0].floor().expected(), Some(floor));
        assert_eq!(prepared.floor_actions()[0].floor().replacement(), None);
        assert_eq!(prepared.floor_actions()[0].cursor().replacement(), None);
        assert_eq!(prepared.next_witness().roster.durable_epoch_bindings(), 0);
        assert_eq!(prepared.next_witness().roster.floor_count(), 0);
    }

    #[test]
    fn mixed_terminal_retirement_releases_one_shared_empty_v1_v2_partition() {
        let profile = profile();
        let v1_admission = admission_for_authority_in_scope(
            "tenant",
            146,
            OwnerId::new("owner").unwrap(),
            FenceToken::new(1),
            Generation::new(1),
            [10; 32],
        );
        let v1 = compact_v1_terminal(&v1_admission, 1, profile);
        let v2 = compact_v2_terminal(&absent_predecessor_admission(147), profile);
        let floor = IrreversibleHistoryFloor::initial(v1.binding()).unwrap();
        assert_eq!(
            ProductionFloorKey::from_binding(v2.binding()).unwrap(),
            ProductionFloorKey::from_floor(floor).unwrap()
        );
        let counters = counters_with_production_floor(
            counters_with_production_record_v2(
                counters_with_production_record(zero_counters(), &v1, profile).unwrap(),
                &v2,
                profile,
            )
            .unwrap(),
            floor,
        )
        .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        let partition = ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
            floor, None, 1, true, true,
        )
        .unwrap();

        let prepared = prepare_production_mixed_terminal_retirement(
            &[
                ProductionMixedTerminalRetirementSelection::V2(&v2),
                ProductionMixedTerminalRetirementSelection::V1(&v1),
            ],
            &[partition],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();

        assert_eq!(prepared.rows().len(), 2);
        assert!(prepared.rows()[0].v2_delete().is_some());
        assert!(prepared.rows()[1].v1_delete().is_some());
        assert_eq!(prepared.floor_actions().len(), 1);
        assert_eq!(prepared.floor_actions()[0].floor().replacement(), None);
        assert_eq!(prepared.next_witness().roster.durable_epoch_bindings(), 0);
        assert_eq!(prepared.next_witness().roster.floor_count(), 0);
    }

    #[test]
    fn mixed_terminal_retirement_preserves_the_floor_for_a_higher_epoch_or_partial_page() {
        let profile = profile();
        let retired = compact_v1_terminal(&admission(148), 1, profile);
        let higher = live(&admission(149), 2, profile);
        let floor = IrreversibleHistoryFloor::initial(retired.binding()).unwrap();
        let counters = counters_with_production_floor(
            counters_with_production_record(
                counters_with_production_record(zero_counters(), &retired, profile).unwrap(),
                &higher,
                profile,
            )
            .unwrap(),
            floor,
        )
        .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);

        let higher_epoch =
            ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
                floor, None, 1, true, false,
            )
            .unwrap();
        let advanced = prepare_production_mixed_terminal_retirement(
            &[ProductionMixedTerminalRetirementSelection::V1(&retired)],
            &[higher_epoch],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(
            advanced.floor_actions()[0].floor().replacement(),
            Some(floor.advance_to(1).unwrap())
        );
        assert_eq!(advanced.next_witness().roster.durable_epoch_bindings(), 1);
        assert_eq!(advanced.next_witness().roster.floor_count(), 1);

        let partial = ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
            floor, None, 1, false, false,
        )
        .unwrap();
        let partial = prepare_production_mixed_terminal_retirement(
            &[ProductionMixedTerminalRetirementSelection::V1(&retired)],
            &[partial],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(
            partial.floor_actions()[0].floor().replacement(),
            Some(floor)
        );
        assert_eq!(partial.floor_actions()[0].cursor().replacement(), None);
        assert!(matches!(
            ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
                floor, None, 1, false, true,
            ),
            Err(ReservationError::FloorAdvance)
        ));
    }

    #[test]
    fn mixed_terminal_retirement_global_prefix_never_installs_a_partition_cursor() {
        let profile = profile();
        let records = (1..=(RECLAIM_BATCH + 1))
            .map(|identity| {
                compact_v1_terminal(&admission(u16::try_from(identity).unwrap()), 1, profile)
            })
            .collect::<Vec<_>>();
        let floor = IrreversibleHistoryFloor::initial(records[0].binding()).unwrap();
        let counters = counters_with_production_floor(
            records
                .iter()
                .try_fold(zero_counters(), |counters, record| {
                    counters_with_production_record(counters, record, profile)
                })
                .unwrap(),
            floor,
        )
        .unwrap();
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        let selections = records
            .iter()
            .take(RECLAIM_BATCH)
            .map(ProductionMixedTerminalRetirementSelection::V1)
            .collect::<Vec<_>>();
        let prefix_partition =
            ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
                floor, None, 1, false, false,
            )
            .unwrap();

        let prefix = prepare_production_mixed_terminal_retirement(
            &selections,
            &[prefix_partition],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();

        assert_eq!(prefix.rows().len(), RECLAIM_BATCH);
        assert_eq!(prefix.floor_actions().len(), 1);
        assert_eq!(prefix.floor_actions()[0].floor().replacement(), Some(floor));
        assert_eq!(prefix.floor_actions()[0].cursor().expected(), None);
        assert_eq!(prefix.floor_actions()[0].cursor().replacement(), None);
        assert_eq!(prefix.next_witness().roster.durable_epoch_bindings(), 1);
        assert_eq!(prefix.next_witness().roster.floor_count(), 1);

        let final_partition =
            ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
                floor, None, 1, true, true,
            )
            .unwrap();
        let final_page = prepare_production_mixed_terminal_retirement(
            &[ProductionMixedTerminalRetirementSelection::V1(
                records.last().unwrap(),
            )],
            &[final_partition],
            prefix.next_witness(),
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(final_page.floor_actions()[0].floor().replacement(), None);
        assert_eq!(final_page.floor_actions()[0].cursor().replacement(), None);
        assert_eq!(final_page.next_witness().roster.durable_epoch_bindings(), 0);
        assert_eq!(final_page.next_witness().roster.floor_count(), 0);
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
        let transaction = prepare_production_admission(ProductionAdmissionPreparation {
            vacancy: &vacant(record.binding),
            existing: None,
            record,
            existing_floor: None,
            existing_retirement_cursor: None,
            witness: empty_witness(),
            budget: GlobalChargeBudget::v1(u64::MAX),
            profile,
        })
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
    fn reclaim_compaction_requires_exact_24_hour_boundary_with_nanosecond_precision() {
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
        let records = BTreeMap::from([(retained.binding, retained)]);
        let witness = GlobalChargeWitness::v1(
            0,
            0,
            validate_production_snapshot(&records.values().cloned().collect::<Vec<_>>(), profile)
                .unwrap(),
        );
        let before = prepare_production_reclaim(
            &records,
            just_young,
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(before.selected(), 0);
        let at_boundary = prepare_production_reclaim(
            &records,
            exact,
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .unwrap();
        assert_eq!(at_boundary.selected(), 1);
        assert_eq!(
            at_boundary.transaction.rows[0]
                .replacement
                .as_ref()
                .expect("compact replacement")
                .state,
            ReservationState::Tombstone
        );
        assert_eq!(
            at_boundary
                .transaction()
                .next_witness()
                .roster
                .retained_and_live_bindings(),
            0
        );
        assert_eq!(
            at_boundary
                .transaction()
                .next_witness()
                .roster
                .durable_epoch_bindings(),
            1
        );
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
    fn restart_snapshot_rejects_a_present_terminal_at_or_below_global_closure() {
        let profile = profile();
        let admitted = admission(45);
        let mut tombstone = live(&admitted, 7, profile);
        tombstone
            .terminalize(&terminal_at(&admitted, 7), profile)
            .expect("terminalize fixture");
        tombstone
            .reclaim_at(aged_maintenance_time(), profile)
            .expect("compact fixture");
        let floor = IrreversibleHistoryFloor::initial(tombstone.binding).expect("fixture floor");
        let counters = counters_with_production_floor(
            validate_production_snapshot(std::slice::from_ref(&tombstone), profile)
                .expect("fixture counters"),
            floor,
        )
        .expect("fixture floor counters");
        let witness = GlobalChargeWitness::v1(0, 0, counters);
        validate_production_snapshot_with_floors(
            std::slice::from_ref(&tombstone),
            &[floor],
            &[],
            witness,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .expect("unclosed tombstone snapshot");
        let closed_with_present_row = witness
            .retired_through_terminal_sequence_for_test(
                tombstone.terminal_sequence().expect("terminal sequence"),
            )
            .expect("closure witness");
        assert!(matches!(
            validate_production_snapshot_with_floors(
                std::slice::from_ref(&tombstone),
                &[floor],
                &[],
                closed_with_present_row,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            ),
            Err(ReservationError::SnapshotMismatch)
        ));
        let closed_empty = GlobalChargeWitness::v1(0, 0, zero_counters())
            .retired_through_terminal_sequence_for_test(
                tombstone.terminal_sequence().expect("terminal sequence"),
            )
            .expect("empty closure witness");
        validate_production_snapshot_with_floors(
            &[],
            &[],
            &[],
            closed_empty,
            GlobalChargeBudget::v1(u64::MAX),
            profile,
        )
        .expect("closed empty snapshot");
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
            prepare_production_admission(ProductionAdmissionPreparation {
                vacancy: &vacant(second.binding),
                existing: None,
                record: second,
                existing_floor: Some(first_floor),
                existing_retirement_cursor: None,
                witness: empty_witness(),
                budget: GlobalChargeBudget::v1(u64::MAX),
                profile,
            }),
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
            version: GLOBAL_CHARGE_WITNESS_VERSION,
            maximum_total_charge_bytes: PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES,
        }
    }

    /// Construct a deliberately small budget for focused accounting tests.
    #[cfg(test)]
    pub(crate) const fn v1(maximum_total_charge_bytes: u64) -> Self {
        Self {
            version: GLOBAL_CHARGE_WITNESS_VERSION,
            maximum_total_charge_bytes,
        }
    }

    /// Validate the immutable production profile independently of test seams.
    fn validate_frozen_profile(self) -> Result<(), ReservationError> {
        if self.version != GLOBAL_CHARGE_WITNESS_VERSION {
            return Err(ReservationError::UnknownWitnessVersion);
        }
        if self.maximum_total_charge_bytes != PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES {
            return Err(ReservationError::InvalidProfile);
        }
        Ok(())
    }

    fn validate(self) -> Result<(), ReservationError> {
        if self.version != GLOBAL_CHARGE_WITNESS_VERSION {
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
    /// The greatest globally ordered terminal consensus sequence whose
    /// compact tombstone has been deterministically retired. Sequence zero
    /// denotes no retired terminal history; committed terminal sequences are
    /// always positive.
    retired_terminal_sequence: u64,
}

impl GlobalChargeWitness {
    /// Initial durable witness before the first protected-roster admission.
    pub(crate) const fn empty() -> Self {
        Self::v1(0, 0, zero_counters())
    }

    /// Construct the current witness from fixed roster-only metadata and rows.
    ///
    /// The legacy `v1` constructor name is retained for the internal callers
    /// that build the fixed charge projection; the encoded witness is the
    /// current version and starts with an empty terminal-history closure.
    pub(crate) const fn v1(
        fixed_roster_metadata_charge_bytes: u64,
        reserved_roster_auxiliary_charge_bytes: u64,
        roster: AggregateCounters,
    ) -> Self {
        Self {
            version: GLOBAL_CHARGE_WITNESS_VERSION,
            fixed_roster_metadata_charge_bytes,
            reserved_roster_auxiliary_charge_bytes,
            roster,
            retired_terminal_sequence: 0,
        }
    }

    fn validate_for(self, budget: GlobalChargeBudget) -> Result<(), ReservationError> {
        budget.validate()?;
        if self.version != GLOBAL_CHARGE_WITNESS_VERSION {
            return Err(ReservationError::UnknownWitnessVersion);
        }
        self.total_charge_bytes()?;
        Ok(())
    }

    fn with_roster(self, roster: AggregateCounters) -> Self {
        Self { roster, ..self }
    }

    /// Return the authenticated terminal-history closure horizon.
    pub(crate) const fn retired_terminal_sequence(self) -> u64 {
        self.retired_terminal_sequence
    }

    /// Advance the closure only from deterministic terminal-history
    /// maintenance.  Admission, terminalization, and payload reclaim carry
    /// the witness unchanged.
    fn retire_through_terminal_sequence(self, sequence: u64) -> Result<Self, ReservationError> {
        if sequence == 0 || sequence <= self.retired_terminal_sequence {
            return Err(ReservationError::SnapshotMismatch);
        }
        Ok(Self {
            retired_terminal_sequence: sequence,
            ..self
        })
    }

    /// Test-only constructor for authenticated snapshots that have already
    /// completed a deterministic terminal-history closure. Production code
    /// can advance this field only through the guarded maintenance planner.
    #[cfg(test)]
    pub(crate) fn retired_through_terminal_sequence_for_test(
        self,
        sequence: u64,
    ) -> Result<Self, ReservationError> {
        self.retire_through_terminal_sequence(sequence)
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

    /// Return the fixed numeric ledger occupancy authenticated by this
    /// witness.  The projection deliberately contains no partition, tenant,
    /// request, member, or descriptor material and therefore remains safe for
    /// store-scoped diagnostics.
    pub(crate) fn diagnostic_occupancy(
        self,
    ) -> Result<ProtectedRosterLedgerOccupancy, ReservationError> {
        let retained_reservations = self
            .roster
            .retained_and_live_bindings
            .checked_sub(self.roster.live_reservations)
            .ok_or(ReservationError::SnapshotMismatch)?;
        let tombstone_reservations = self
            .roster
            .durable_epoch_bindings
            .checked_sub(self.roster.retained_and_live_bindings)
            .ok_or(ReservationError::SnapshotMismatch)?;
        Ok(ProtectedRosterLedgerOccupancy {
            live_reservations: u64::try_from(self.roster.live_reservations)
                .map_err(|_| ReservationError::SnapshotMismatch)?,
            retained_reservations: u64::try_from(retained_reservations)
                .map_err(|_| ReservationError::SnapshotMismatch)?,
            tombstone_reservations: u64::try_from(tombstone_reservations)
                .map_err(|_| ReservationError::SnapshotMismatch)?,
            history_floors: u64::try_from(self.roster.floor_count)
                .map_err(|_| ReservationError::SnapshotMismatch)?,
            retirement_cursors: u64::try_from(self.roster.retirement_cursor_count)
                .map_err(|_| ReservationError::SnapshotMismatch)?,
            materialized_charge_bytes: self.roster.materialized_charge_bytes,
            reserved_future_charge_bytes: self.roster.reserved_future_charge_bytes,
        })
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

/// Fixed-cardinality, redaction-safe projection of one durable roster ledger.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProtectedRosterLedgerOccupancy {
    pub(crate) live_reservations: u64,
    pub(crate) retained_reservations: u64,
    pub(crate) tombstone_reservations: u64,
    pub(crate) history_floors: u64,
    pub(crate) retirement_cursors: u64,
    pub(crate) materialized_charge_bytes: u64,
    pub(crate) reserved_future_charge_bytes: u64,
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

/// The root-verifiable admission provenance and direct per-member terminal
/// evidence are retained with a terminal row through its fixed retention
/// interval. They are charged as a fixed 2048 + 8192 byte component,
/// independent of the raw admission, terminal, proof, and ingress bytes.
const MAX_COMPACT_PROVENANCE_BYTES: usize =
    MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES + MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES;

/// The frozen page-rounded maximum for one terminal tombstone snapshot row.
/// Derive it from the same evidence and codec bounds charged below so
/// strengthening a bounded proof cannot make every otherwise-valid admission
/// fail during its pre-effect capacity reservation.
const MAX_TOMBSTONE_UNROUNDED_CHARGE_BYTES: u64 = STORAGE_CHARGE_TOMBSTONE_ROW_BYTES
    + STORAGE_CHARGE_TOMBSTONE_INDEX_BYTES
    + MAX_TOMBSTONE_CODEC_BYTES as u64
    + MAX_COMPACT_PROVENANCE_BYTES as u64;
const MAX_TOMBSTONE_CHARGE_BYTES: u64 = MAX_TOMBSTONE_UNROUNDED_CHARGE_BYTES
    .div_ceil(STORAGE_CHARGE_PAGE_BYTES)
    * STORAGE_CHARGE_PAGE_BYTES;

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
            as_u64(components.compact_provenance_bytes)?,
        )?)?;
        let retained = self.page_round(add4(
            self.retained_row_bytes,
            self.retained_index_bytes,
            as_u64(components.canonical_admission_bytes)?,
            add4(
                as_u64(components.terminal_record_bytes)?,
                as_u64(components.business_session_copy_bytes)?,
                as_u64(components.composite_receipt_bytes)?,
                add2(
                    as_u64(components.terminal_evidence_envelope_bytes)?,
                    as_u64(components.compact_provenance_bytes)?,
                )?,
            )?,
        )?)?;
        let tombstone = self.page_round(add3(
            self.tombstone_row_bytes,
            self.tombstone_index_bytes,
            add2(
                as_u64(components.tombstone_bytes)?,
                as_u64(components.compact_provenance_bytes)?,
            )?,
        )?)?;
        if self == Self::v1() && tombstone > MAX_TOMBSTONE_CHARGE_BYTES {
            return Err(ReservationError::ComponentBounds);
        }
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
    compact_provenance_bytes: usize,
    tombstone_bytes: usize,
}

impl ComponentBytes {
    #[cfg(test)]
    fn from_exact(
        canonical_admission_bytes: usize,
        terminal_record_bytes: usize,
        business_session_copy_bytes: usize,
        composite_receipt_bytes: usize,
        terminal_evidence_envelope_bytes: usize,
        tombstone_bytes: usize,
    ) -> Result<Self, ReservationError> {
        Self::from_exact_with_compact(
            canonical_admission_bytes,
            terminal_record_bytes,
            business_session_copy_bytes,
            composite_receipt_bytes,
            terminal_evidence_envelope_bytes,
            0,
            tombstone_bytes,
        )
    }

    fn from_exact_with_compact(
        canonical_admission_bytes: usize,
        terminal_record_bytes: usize,
        business_session_copy_bytes: usize,
        composite_receipt_bytes: usize,
        terminal_evidence_envelope_bytes: usize,
        compact_provenance_bytes: usize,
        tombstone_bytes: usize,
    ) -> Result<Self, ReservationError> {
        let result = Self {
            canonical_admission_bytes,
            terminal_record_bytes,
            business_session_copy_bytes,
            composite_receipt_bytes,
            terminal_evidence_envelope_bytes,
            compact_provenance_bytes,
            tombstone_bytes,
        };
        result.validate_with_tombstone_bound(MAX_TOMBSTONE_CODEC_BYTES)?;
        Ok(result)
    }

    fn validate_with_tombstone_bound(self, tombstone_bound: usize) -> Result<(), ReservationError> {
        if self.canonical_admission_bytes > MAX_ADMISSION_CODEC_BYTES
            || self.terminal_record_bytes > MAX_COMMITTED_TERMINAL_CODEC_BYTES
            || self.business_session_copy_bytes > MAX_BUSINESS_SESSION_COPY_BYTES
            || self.composite_receipt_bytes > MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES
            || self.terminal_evidence_envelope_bytes > MAX_TERMINAL_EVIDENCE_ENVELOPE_BYTES
            || self.compact_provenance_bytes
                > MAX_COMPACT_PROVENANCE_BYTES.max(MAX_PROFILE_V2_COMPACT_TERMINAL_EVIDENCE_BYTES)
            || self.tombstone_bytes > tombstone_bound
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
    /// Compact conflict evidence awaiting bounded irreversible epoch retirement.
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

    /// Recover the exact consensus timestamp retained for a terminal event.
    /// The stored maintenance time is nonnegative by construction, but its
    /// durable canonical form still has to be range-checked before it is used
    /// as the cryptographic verification time during restart hydration.
    pub(crate) fn to_consensus_timestamp(self) -> Result<Timestamp, ReservationError> {
        time::OffsetDateTime::from_unix_timestamp_nanos(self.0)
            .map(Timestamp::from_offset_datetime)
            .map_err(|_| ReservationError::InvalidMaintenanceTime)
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
    admission_ingress: Vec<u8>,
    admission_provenance: Vec<u8>,
    terminal: Option<Vec<u8>>,
    terminal_proof_bundle: Option<Vec<u8>>,
    terminal_ingress: Option<Vec<u8>>,
    terminal_evidence: Option<Vec<u8>>,
    tombstone: Option<Vec<u8>>,
    terminalized_at: Option<ConsensusMaintenanceTimestamp>,
    /// Exact globally monotonic sequence from the authenticated committed
    /// terminal.  It is absent for live rows, checked against the retained
    /// frame, and carried unchanged into the compact tombstone.
    terminal_sequence: Option<u64>,
    business_reservation: Option<ProductionAdmissionBusinessReservation>,
    state: ReservationState,
    peak_charge_bytes: u64,
    retained_charge_bytes: u64,
    tombstone_charge_bytes: u64,
}

/// Structurally disjoint V2 live-admission row for an absent predecessor.
///
/// This is deliberately not an optional field on [`ProductionReservationRecord`]:
/// doing so would alter the frozen V1 Postcard layout and could let a V2
/// absence reservation enter V1 restart/snapshot validation. SQLite persists
/// this object through its dedicated V2 admissions/reservation tables.
///
/// Its ingress and compact provenance are concretely `/4` values.  A V1
/// envelope is not an alternate representation here: accepting one would
/// make a V2 absence predicate durable under V1 authentication semantics.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProductionReservationRecordV2 {
    binding: RequestBindingKey,
    admission: Vec<u8>,
    admission_ingress: Vec<u8>,
    admission_provenance: Vec<u8>,
    terminal: Option<Vec<u8>>,
    terminal_proof_bundle: Option<Vec<u8>>,
    terminal_evidence: Option<Vec<u8>>,
    tombstone: Option<Vec<u8>>,
    terminalized_at: Option<ConsensusMaintenanceTimestamp>,
    terminal_sequence: Option<u64>,
    absence_reservation: Option<ProductionAdmissionAbsentBusinessReservationV2>,
    state: ProductionReservationStateV2,
    peak_charge_bytes: u64,
    retained_charge_bytes: u64,
    tombstone_charge_bytes: u64,
}

const PRODUCTION_RESERVATION_RECORD_V2_MAGIC: [u8; 8] = *b"OPCRRV2\0";
const PRODUCTION_RESERVATION_RECORD_V2_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/reservation-record/v2\0";

/// Digest of V2's disjoint row framing and shared retention contract.
///
/// V2 owns only its reservation-record frame and table layout. Its compact
/// terminal, irreversible floor, and retirement cursor are the common
/// protected-roster frames, keyed only by `RequestBindingKey` partition.
/// Literal contract labels keep this descriptor honest without coupling it to
/// private constants in the roster domain module.
#[doc(hidden)]
pub fn protected_roster_v2_storage_descriptor_digest() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"opc/session-store/protected-roster/v2-storage-descriptor/v2\0");
    hasher.update(PRODUCTION_RESERVATION_RECORD_V2_MAGIC);
    hasher.update(PRODUCTION_RESERVATION_RECORD_V2_DOMAIN);
    hasher.update(b"common-terminal-conflict-tombstone/v1\0");
    hasher.update(b"common-irreversible-history-floor/v1\0");
    hasher.update(b"common-production-floor-key-cas/v1\0");
    hasher.update(b"common-production-retirement-cursor-cas/v1\0");
    hasher.update(b"binding,root-signed-v2-provenance,root-signed-v2-terminal-evidence;shared-floor(scope,tenant-partition,retired-through);shared-cursor(scope,tenant-partition,target-epoch,last-deleted);global-terminal-sequence-horizon\0");
    hasher.finalize().into()
}

/// Dedicated V2 row lifecycle with a disjoint compact terminal carrier.
/// It shares no serialized state field with the V1 Postcard record.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ProductionReservationStateV2 {
    /// Q1's exact absent-row reservation is still live.
    Live,
    /// Q2 retained one exact terminal carrier after atomically releasing Q1.
    Retained,
    /// V2 row carrying the common compact conflict tombstone until shared
    /// irreversible-history retirement removes it.
    Tombstone,
}

impl<'de> Deserialize<'de> for ProductionReservationRecordV2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            binding: RequestBindingKey,
            admission: BoundedSnapshotBytes<MAX_ADMISSION_CODEC_BYTES>,
            admission_ingress: BoundedSnapshotBytes<MAX_ROSTER_INGRESS_ATTESTATION_BYTES>,
            admission_provenance:
                BoundedSnapshotBytes<MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES>,
            terminal: Option<BoundedSnapshotBytes<MAX_COMMITTED_TERMINAL_CODEC_BYTES>>,
            terminal_proof_bundle:
                Option<BoundedSnapshotBytes<MAX_PROFILE_V2_EXECUTOR_PROOF_BUNDLE_BYTES>>,
            terminal_evidence:
                Option<BoundedSnapshotBytes<MAX_PROFILE_V2_COMPACT_TERMINAL_EVIDENCE_BYTES>>,
            tombstone: Option<BoundedSnapshotBytes<MAX_TOMBSTONE_CODEC_BYTES>>,
            terminalized_at: Option<ConsensusMaintenanceTimestamp>,
            terminal_sequence: Option<u64>,
            absence_reservation: Option<ProductionAdmissionAbsentBusinessReservationV2>,
            state: ProductionReservationStateV2,
            peak_charge_bytes: u64,
            retained_charge_bytes: u64,
            tombstone_charge_bytes: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            binding: wire.binding,
            admission: wire.admission.0,
            admission_ingress: wire.admission_ingress.0,
            admission_provenance: wire.admission_provenance.0,
            terminal: wire.terminal.map(|value| value.0),
            terminal_proof_bundle: wire.terminal_proof_bundle.map(|value| value.0),
            terminal_evidence: wire.terminal_evidence.map(|value| value.0),
            tombstone: wire.tombstone.map(|value| value.0),
            terminalized_at: wire.terminalized_at,
            terminal_sequence: wire.terminal_sequence,
            absence_reservation: wire.absence_reservation,
            state: wire.state,
            peak_charge_bytes: wire.peak_charge_bytes,
            retained_charge_bytes: wire.retained_charge_bytes,
            tombstone_charge_bytes: wire.tombstone_charge_bytes,
        })
    }
}

/// One fully validated Profile-V2 durable roster row together with its exact
/// framed SQLite bytes. This seals the one-pass decode used by V2 status and
/// recovery reads: callers can use the authenticated component values without
/// reparsing the potentially multi-megabyte admission or terminal carrier.
#[derive(Clone)]
pub(crate) struct HydratedProductionReservationRecordV2 {
    record: ProductionReservationRecordV2,
    canonical: Vec<u8>,
    admission: Option<Admission>,
    admission_ingress: Option<RosterIngressAttestationV2>,
    admission_provenance: RosterProfileV2CompactAdmissionProvenanceV1,
    committed_terminal: Option<Box<CommittedTerminal>>,
    committed_canonical: Option<Vec<u8>>,
    terminal_proof_bundle: Option<RosterProfileV2ExecutorProofBundleV1>,
    terminal_evidence: Option<RosterProfileV2CompactTerminalEvidenceV1>,
    tombstone: Option<TerminalConflictTombstone>,
}

impl HydratedProductionReservationRecordV2 {
    /// Return the validated durable V2 row projection.
    pub(crate) const fn record(&self) -> &ProductionReservationRecordV2 {
        &self.record
    }

    /// Return the exact framed bytes which were decoded for this row.
    pub(crate) fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// Return the decoded admission authenticated with this durable row.
    pub(crate) const fn admission(&self) -> Option<&Admission> {
        self.admission.as_ref()
    }

    /// Return the decoded V2 admission ingress authenticated with this row.
    pub(crate) const fn admission_ingress(&self) -> Option<&RosterIngressAttestationV2> {
        self.admission_ingress.as_ref()
    }

    /// Return the decoded V2 compact admission provenance for this row.
    pub(crate) const fn admission_provenance(
        &self,
    ) -> &RosterProfileV2CompactAdmissionProvenanceV1 {
        &self.admission_provenance
    }

    /// Return the retained terminal already decoded during row validation.
    pub(crate) fn committed_terminal(&self) -> Option<&CommittedTerminal> {
        self.committed_terminal.as_deref()
    }

    /// Return the exact original terminal frame retained by this row.
    pub(crate) fn committed_canonical(&self) -> Option<&[u8]> {
        self.committed_canonical.as_deref()
    }

    /// Return the decoded Profile-V2 retained proof bundle.
    pub(crate) fn terminal_proof_bundle(&self) -> Option<&RosterProfileV2ExecutorProofBundleV1> {
        self.terminal_proof_bundle.as_ref()
    }

    /// Return the decoded Profile-V2 compact terminal evidence.
    pub(crate) fn terminal_evidence(&self) -> Option<&RosterProfileV2CompactTerminalEvidenceV1> {
        self.terminal_evidence.as_ref()
    }

    /// Return the common compact tombstone already decoded and validated with
    /// this V2 row. A recovery verifier can combine it with the retained
    /// provenance and evidence above without reparsing durable bytes.
    pub(crate) fn tombstone(&self) -> Option<&TerminalConflictTombstone> {
        self.tombstone.as_ref()
    }

    /// Discard read-side hydration after a caller only needs the durable row.
    pub(crate) fn into_record(self) -> ProductionReservationRecordV2 {
        self.record
    }
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
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(crate) enum HydratedProductionReservationPayload {
    Live {
        admission: Admission,
        admission_ingress: RosterIngressAttestationV1,
        admission_provenance: RosterCompactAdmissionProvenanceV2,
    },
    Retained {
        admission: Admission,
        admission_ingress: RosterIngressAttestationV1,
        admission_provenance: RosterCompactAdmissionProvenanceV2,
        committed_terminal: Box<CommittedTerminal>,
        committed_canonical: Vec<u8>,
        terminal_proof_bundle: RosterExecutorProofBundleV1,
        terminal_ingress: RosterIngressAttestationV1,
        terminal_evidence: RosterCompactTerminalEvidenceV2,
    },
    Tombstone {
        tombstone: TerminalConflictTombstone,
        admission_provenance: RosterCompactAdmissionProvenanceV2,
        terminal_evidence: RosterCompactTerminalEvidenceV2,
        #[expect(
            dead_code,
            reason = "retained for legacy tombstone snapshot validation"
        )]
        terminalized_at: ConsensusMaintenanceTimestamp,
    },
    /// Rootless fixture state exists only in crate tests. Production does not
    /// compile its constructors or this variant, so durable recovery always
    /// requires the root-verifiable V2 evidence above.
    #[cfg(test)]
    Legacy,
}

impl HydratedProductionReservationRecord {
    /// Return the validated durable row projection.
    pub(crate) const fn record(&self) -> &ProductionReservationRecord {
        &self.record
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
            admission_ingress: BoundedSnapshotBytes<MAX_ROSTER_INGRESS_ATTESTATION_BYTES>,
            admission_provenance:
                BoundedSnapshotBytes<MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES>,
            terminal: Option<BoundedSnapshotBytes<MAX_COMMITTED_TERMINAL_CODEC_BYTES>>,
            terminal_proof_bundle: Option<BoundedSnapshotBytes<MAX_EXECUTOR_PROOF_BUNDLE_BYTES>>,
            terminal_ingress: Option<BoundedSnapshotBytes<MAX_ROSTER_INGRESS_ATTESTATION_BYTES>>,
            terminal_evidence:
                Option<BoundedSnapshotBytes<MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES>>,
            tombstone: Option<BoundedSnapshotBytes<MAX_TOMBSTONE_CODEC_BYTES>>,
            terminalized_at: Option<ConsensusMaintenanceTimestamp>,
            terminal_sequence: Option<u64>,
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
            admission_ingress: wire.admission_ingress.0,
            admission_provenance: wire.admission_provenance.0,
            terminal: wire.terminal.map(|value| value.0),
            terminal_proof_bundle: wire.terminal_proof_bundle.map(|value| value.0),
            terminal_ingress: wire.terminal_ingress.map(|value| value.0),
            terminal_evidence: wire.terminal_evidence.map(|value| value.0),
            tombstone: wire.tombstone.map(|value| value.0),
            terminalized_at: wire.terminalized_at,
            terminal_sequence: wire.terminal_sequence,
            business_reservation: wire.business_reservation,
            state: wire.state,
            peak_charge_bytes: wire.peak_charge_bytes,
            retained_charge_bytes: wire.retained_charge_bytes,
            tombstone_charge_bytes: wire.tombstone_charge_bytes,
        })
    }
}

impl ProductionReservationRecord {
    /// Build the dedicated V2 live-admission row for an exact absent
    /// predecessor. This never creates a V1 business reservation or a
    /// synthetic authoritative-row value.
    pub(crate) fn live_v2_absent_with_provenance_and_ingress(
        admission: &Admission,
        admission_ingress: &RosterIngressAttestationV2,
        admission_provenance: &RosterProfileV2CompactAdmissionProvenanceV1,
        epoch: u64,
        absence_reservation: ProductionAdmissionAbsentBusinessReservationV2,
        profile: ChargeProfile,
    ) -> Result<ProductionReservationRecordV2, ReservationError> {
        ProductionReservationRecordV2::live_with_provenance_and_ingress(
            admission,
            admission_ingress,
            admission_provenance,
            epoch,
            absence_reservation,
            profile,
        )
    }

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

    /// Return the globally ordered terminal sequence carried by terminal
    /// history. Live rows deliberately have no terminal sequence.
    pub(crate) const fn terminal_sequence(&self) -> Option<u64> {
        self.terminal_sequence
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

    /// Rehydrate exact compact conflict evidence from a legacy tombstone
    /// snapshot row. Non-tombstone rows return `None`; a malformed or
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
        if tombstone.validate_binding(self.binding).is_err() {
            return Err(ReservationError::SnapshotMismatch);
        }
        Ok(Some(tombstone))
    }

    /// Build the production live row from exact root-certified ingress and
    /// compact admission provenance. The raw ingress is retained only until
    /// fixed-duration reclaim; the compact proof survives all later states.
    pub(crate) fn live_with_provenance_and_ingress(
        admission: &Admission,
        admission_ingress: &RosterIngressAttestationV1,
        admission_provenance: &RosterCompactAdmissionProvenanceV2,
        epoch: u64,
        business_reservation: ProductionAdmissionBusinessReservation,
        profile: ChargeProfile,
    ) -> Result<Self, ReservationError> {
        validate_epoch(epoch)?;
        let admission_bytes = admission
            .to_canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let admission_ingress = admission_ingress
            .canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let admission_provenance = admission_provenance
            .canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let binding = admission
            .binding_key(epoch)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let charges = profile.charge(production_components(
            &admission_bytes,
            None,
            None,
            MAX_COMPACT_PROVENANCE_BYTES,
        )?)?;
        business_reservation.validate_for(admission)?;
        Ok(Self {
            binding,
            admission: admission_bytes,
            admission_ingress,
            admission_provenance,
            terminal: None,
            terminal_proof_bundle: None,
            terminal_ingress: None,
            terminal_evidence: None,
            tombstone: None,
            terminalized_at: None,
            terminal_sequence: None,
            business_reservation: Some(business_reservation),
            state: ReservationState::Live,
            peak_charge_bytes: charges.peak,
            retained_charge_bytes: charges.retained,
            tombstone_charge_bytes: charges.tombstone,
        })
    }

    /// Build a test-only legacy row. It is rejected in every production
    /// decode/write path, so no rootless V1 row can activate this profile.
    #[cfg(test)]
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
        let charges = profile.charge(production_components(&admission_bytes, None, None, 0)?)?;
        business_reservation.validate_for(admission)?;
        Ok(Self {
            binding,
            admission: admission_bytes,
            admission_ingress: Vec::new(),
            admission_provenance: Vec::new(),
            terminal: None,
            terminal_proof_bundle: None,
            terminal_ingress: None,
            terminal_evidence: None,
            tombstone: None,
            terminalized_at: None,
            terminal_sequence: None,
            business_reservation: Some(business_reservation),
            state: ReservationState::Live,
            peak_charge_bytes: charges.peak,
            retained_charge_bytes: charges.retained,
            tombstone_charge_bytes: charges.tombstone,
        })
    }

    /// Test-only legacy terminal transition. Production requires the exact
    /// compact evidence and both original raw proof materials above.
    #[cfg(test)]
    pub(crate) fn terminalize(
        &mut self,
        terminal: &CommittedTerminal,
        profile: ChargeProfile,
    ) -> Result<(), ReservationError> {
        let admission = Admission::from_canonical_bytes(&self.admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        self.terminalize_with_hydrated_admission(&admission, terminal, None, None, None, profile)
    }

    /// Terminalize from the decoded admission retained by an authenticated
    /// hydration. This is intentionally private: the production terminal
    /// path receives its admission only from an authenticated hydration.
    fn terminalize_with_hydrated_admission(
        &mut self,
        admission: &Admission,
        terminal: &CommittedTerminal,
        proof_bundle: Option<&RosterExecutorProofBundleV1>,
        terminal_ingress: Option<&RosterIngressAttestationV1>,
        terminal_evidence: Option<&RosterCompactTerminalEvidenceV2>,
        profile: ChargeProfile,
    ) -> Result<(), ReservationError> {
        if self.state != ReservationState::Live {
            return Err(ReservationError::InvalidState);
        }
        if admission
            .binding_key(self.binding.history_epoch())
            .map_err(|_| ReservationError::CanonicalEncoding)?
            != self.binding
            || terminal.record().request_id().history_epoch() != self.binding.history_epoch()
        {
            return Err(ReservationError::SnapshotMismatch);
        }
        let terminal_bytes = terminal
            .to_canonical_bytes(admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let compact_bytes = match (&self.admission_provenance[..], terminal_evidence) {
            (admission_provenance, Some(terminal_evidence)) if !admission_provenance.is_empty() => {
                let compact = terminal_evidence
                    .canonical_bytes()
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                terminal_evidence
                    .verify_raw_terminal(admission, terminal.record())
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                admission_provenance
                    .len()
                    .checked_add(compact.len())
                    .ok_or(ReservationError::Arithmetic)?
            }
            _ if cfg!(test)
                && self.admission_provenance.is_empty()
                && proof_bundle.is_none()
                && terminal_ingress.is_none()
                && terminal_evidence.is_none() =>
            {
                0
            }
            _ => return Err(ReservationError::StateShape),
        };
        let live = profile.charge(production_components(
            &self.admission,
            None,
            None,
            if self.admission_provenance.is_empty() {
                0
            } else {
                MAX_COMPACT_PROVENANCE_BYTES
            },
        )?)?;
        let retained = profile.charge(production_components(
            &self.admission,
            Some(&terminal_bytes),
            None,
            compact_bytes,
        )?)?;
        if self.peak_charge_bytes != live.peak || retained.retained > self.peak_charge_bytes {
            return Err(ReservationError::SnapshotMismatch);
        }
        self.terminal = Some(terminal_bytes);
        self.terminal_proof_bundle = proof_bundle
            .map(RosterExecutorProofBundleV1::canonical_bytes)
            .transpose()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        self.terminal_ingress = terminal_ingress
            .map(RosterIngressAttestationV1::canonical_bytes)
            .transpose()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        self.terminal_evidence = terminal_evidence
            .map(RosterCompactTerminalEvidenceV2::canonical_bytes)
            .transpose()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        self.terminalized_at = Some(ConsensusMaintenanceTimestamp::from_consensus_timestamp(
            terminal.commit_metadata().committed_at(),
        )?);
        self.terminal_sequence = Some(terminal.terminal_sequence());
        self.business_reservation = None;
        self.state = ReservationState::Retained;
        self.retained_charge_bytes = retained.retained;
        self.tombstone_charge_bytes = retained.tombstone;
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
                || !self.admission_ingress.is_empty()
                || self.terminal.is_some()
                || self.terminal_proof_bundle.is_some()
                || self.terminal_ingress.is_some()
                || self.business_reservation.is_some()
            {
                return Err(ReservationError::StateShape);
            }
            let terminalized_at = self.terminalized_at.ok_or(ReservationError::StateShape)?;
            self.terminal_sequence
                .filter(|sequence| *sequence > 0)
                .ok_or(ReservationError::StateShape)?;
            let tombstone = self
                .tombstone
                .as_deref()
                .ok_or(ReservationError::StateShape)?;
            let decoded = TerminalConflictTombstone::from_canonical_bytes(tombstone)
                .map_err(|_| ReservationError::CanonicalEncoding)?;
            if decoded.validate_binding(self.binding).is_err() {
                return Err(ReservationError::SnapshotMismatch);
            }
            #[cfg(test)]
            if self.admission_provenance.is_empty() && self.terminal_evidence.is_none() {
                let charges =
                    profile.charge(production_components(&[], None, Some(tombstone), 0)?)?;
                return if self.peak_charge_bytes == 0
                    && self.retained_charge_bytes == 0
                    && self.tombstone_charge_bytes == charges.tombstone
                {
                    Ok(HydratedProductionReservationPayload::Legacy)
                } else {
                    Err(ReservationError::SnapshotMismatch)
                };
            }
            let admission_provenance =
                RosterCompactAdmissionProvenanceV2::decode_canonical(&self.admission_provenance)
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
            let terminal_evidence = self
                .terminal_evidence
                .as_deref()
                .ok_or(ReservationError::StateShape)
                .and_then(|bytes| {
                    RosterCompactTerminalEvidenceV2::decode_canonical(bytes)
                        .map_err(|_| ReservationError::CanonicalEncoding)
                })?;
            let compact_bytes = self
                .admission_provenance
                .len()
                .checked_add(self.terminal_evidence.as_ref().map_or(0, Vec::len))
                .ok_or(ReservationError::Arithmetic)?;
            let charges = profile.charge(production_components(
                &[],
                None,
                Some(tombstone),
                compact_bytes,
            )?)?;
            return if self.peak_charge_bytes == 0
                && self.retained_charge_bytes == 0
                && self.tombstone_charge_bytes == charges.tombstone
            {
                Ok(HydratedProductionReservationPayload::Tombstone {
                    tombstone: decoded,
                    admission_provenance,
                    terminal_evidence,
                    terminalized_at,
                })
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
        let legacy =
            cfg!(test) && self.admission_ingress.is_empty() && self.admission_provenance.is_empty();
        let admission_ingress = if legacy {
            None
        } else {
            Some(
                RosterIngressAttestationV1::decode_canonical(&self.admission_ingress)
                    .map_err(|_| ReservationError::CanonicalEncoding)?,
            )
        };
        let admission_provenance = if legacy {
            None
        } else {
            Some(
                RosterCompactAdmissionProvenanceV2::decode_canonical(&self.admission_provenance)
                    .map_err(|_| ReservationError::CanonicalEncoding)?,
            )
        };
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
                    && self.terminal_proof_bundle.is_none()
                    && self.terminal_ingress.is_none()
                    && self.terminal_evidence.is_none()
                    && self.tombstone.is_none()
                    && self.terminalized_at.is_none()
                    && self.terminal_sequence.is_none() =>
            {
                #[cfg(test)]
                if legacy {
                    return Ok(HydratedProductionReservationPayload::Legacy);
                }
                let charges = profile.charge(production_components(
                    &self.admission,
                    None,
                    None,
                    if legacy {
                        0
                    } else {
                        MAX_COMPACT_PROVENANCE_BYTES
                    },
                )?)?;
                if self.peak_charge_bytes == charges.peak
                    && self.retained_charge_bytes == charges.retained
                    && self.tombstone_charge_bytes == charges.tombstone
                {
                    match (admission_ingress, admission_provenance) {
                        (Some(admission_ingress), Some(admission_provenance)) => {
                            Ok(HydratedProductionReservationPayload::Live {
                                admission,
                                admission_ingress,
                                admission_provenance,
                            })
                        }
                        _ => Err(ReservationError::StateShape),
                    }
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
                if self.terminal_sequence != Some(decoded.terminal_sequence()) {
                    return Err(ReservationError::SnapshotMismatch);
                }
                let committed_at = ConsensusMaintenanceTimestamp::from_consensus_timestamp(
                    decoded.commit_metadata().committed_at(),
                )?;
                if self.terminalized_at != Some(committed_at) {
                    return Err(ReservationError::SnapshotMismatch);
                }
                #[cfg(test)]
                if legacy {
                    return Ok(HydratedProductionReservationPayload::Legacy);
                }
                let proof_bundle = self
                    .terminal_proof_bundle
                    .as_deref()
                    .map(RosterExecutorProofBundleV1::decode_canonical)
                    .transpose()
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                let terminal_ingress = self
                    .terminal_ingress
                    .as_deref()
                    .map(RosterIngressAttestationV1::decode_canonical)
                    .transpose()
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                let terminal_evidence = self
                    .terminal_evidence
                    .as_deref()
                    .map(RosterCompactTerminalEvidenceV2::decode_canonical)
                    .transpose()
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                let compact_bytes = match (&admission_provenance, &terminal_evidence) {
                    (Some(_), Some(_)) => self
                        .admission_provenance
                        .len()
                        .checked_add(self.terminal_evidence.as_ref().map_or(0, Vec::len))
                        .ok_or(ReservationError::Arithmetic)?,
                    (None, None)
                        if legacy && proof_bundle.is_none() && terminal_ingress.is_none() =>
                    {
                        0
                    }
                    _ => return Err(ReservationError::StateShape),
                };
                if let Some(evidence) = terminal_evidence.as_ref() {
                    evidence
                        .verify_raw_terminal(&admission, decoded.record())
                        .map_err(|_| ReservationError::CanonicalEncoding)?;
                }
                let live = profile.charge(production_components(
                    &self.admission,
                    None,
                    None,
                    if legacy {
                        0
                    } else {
                        MAX_COMPACT_PROVENANCE_BYTES
                    },
                )?)?;
                let retained = profile.charge(production_components(
                    &self.admission,
                    Some(terminal),
                    None,
                    compact_bytes,
                )?)?;
                if self.peak_charge_bytes == live.peak
                    && self.retained_charge_bytes == retained.retained
                    && self.tombstone_charge_bytes == retained.tombstone
                {
                    match (
                        admission_ingress,
                        admission_provenance,
                        proof_bundle,
                        terminal_ingress,
                        terminal_evidence,
                    ) {
                        (
                            Some(admission_ingress),
                            Some(admission_provenance),
                            Some(terminal_proof_bundle),
                            Some(terminal_ingress),
                            Some(terminal_evidence),
                        ) => Ok(HydratedProductionReservationPayload::Retained {
                            admission,
                            admission_ingress,
                            admission_provenance,
                            committed_terminal: Box::new(decoded),
                            committed_canonical: terminal.to_vec(),
                            terminal_proof_bundle,
                            terminal_ingress,
                            terminal_evidence,
                        }),
                        _ => Err(ReservationError::StateShape),
                    }
                } else {
                    Err(ReservationError::SnapshotMismatch)
                }
            }
            ReservationState::Tombstone => Err(ReservationError::StateShape),
            _ => Err(ReservationError::StateShape),
        }
    }

    /// Compact one conclusively terminal row after the fixed retention age.
    /// The exact protected admission/checkpoint/result and raw proof material
    /// are removed, while the bounded commitments required to reject replay or
    /// a changed body remain durable until irreversible epoch retirement.
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
        let tombstone = TerminalConflictTombstone::from_committed_terminal(&admission, &terminal)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        if tombstone.validate_binding(self.binding).is_err() {
            return Err(ReservationError::SnapshotMismatch);
        }
        let tombstone_bytes = tombstone
            .to_canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let compact_bytes = self
            .admission_provenance
            .len()
            .checked_add(self.terminal_evidence.as_ref().map_or(0, Vec::len))
            .ok_or(ReservationError::Arithmetic)?;
        if !cfg!(test) && (self.admission_provenance.is_empty() || self.terminal_evidence.is_none())
        {
            return Err(ReservationError::StateShape);
        }
        let charges = profile.charge(production_components(
            &[],
            None,
            Some(&tombstone_bytes),
            compact_bytes,
        )?)?;
        self.admission.clear();
        self.admission_ingress.clear();
        self.terminal = None;
        self.terminal_proof_bundle = None;
        self.terminal_ingress = None;
        self.tombstone = Some(tombstone_bytes);
        self.business_reservation = None;
        self.state = ReservationState::Tombstone;
        self.peak_charge_bytes = 0;
        self.retained_charge_bytes = 0;
        self.tombstone_charge_bytes = charges.tombstone;
        Ok(())
    }
}

impl ProductionReservationRecordV2 {
    fn live_with_provenance_and_ingress(
        admission: &Admission,
        admission_ingress: &RosterIngressAttestationV2,
        admission_provenance: &RosterProfileV2CompactAdmissionProvenanceV1,
        epoch: u64,
        absence_reservation: ProductionAdmissionAbsentBusinessReservationV2,
        profile: ChargeProfile,
    ) -> Result<Self, ReservationError> {
        validate_epoch(epoch)?;
        let admission_bytes = admission
            .to_canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let admission_ingress = admission_ingress
            .canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let admission_provenance = admission_provenance
            .canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let binding = admission
            .binding_key(epoch)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        absence_reservation.validate_for(admission, binding)?;
        let charges = profile.charge(production_components_v2(
            &admission_bytes,
            None,
            None,
            max_v2_compact_evidence_bytes(),
        )?)?;
        Ok(Self {
            binding,
            admission: admission_bytes,
            admission_ingress,
            admission_provenance,
            terminal: None,
            terminal_proof_bundle: None,
            terminal_evidence: None,
            tombstone: None,
            terminalized_at: None,
            terminal_sequence: None,
            absence_reservation: Some(absence_reservation),
            state: ProductionReservationStateV2::Live,
            peak_charge_bytes: charges.peak,
            retained_charge_bytes: charges.retained,
            tombstone_charge_bytes: charges.tombstone,
        })
    }

    /// Return the exact V2 live-row binding.
    pub(crate) const fn binding(&self) -> RequestBindingKey {
        self.binding
    }

    /// Return the isolated V2 lifecycle state. SQLite must accept an absence
    /// reservation only when this is [`ProductionReservationStateV2::Live`].
    pub(crate) const fn state(&self) -> ProductionReservationStateV2 {
        self.state
    }

    /// Return the global terminal sequence retained by V2 Q2.
    pub(crate) const fn terminal_sequence(&self) -> Option<u64> {
        self.terminal_sequence
    }

    /// Return the authenticated terminal time used by deterministic V2
    /// maintenance selection. It exists only after Q2.
    pub(crate) const fn terminalized_at(&self) -> Option<ConsensusMaintenanceTimestamp> {
        self.terminalized_at
    }

    /// Rehydrate the V2-profile admission provenance retained in every V2
    /// lifecycle state, including compact tombstones.
    #[cfg(test)]
    pub(crate) fn v2_admission_provenance(
        &self,
    ) -> Result<RosterProfileV2CompactAdmissionProvenanceV1, ReservationError> {
        RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(&self.admission_provenance)
            .map_err(|_| ReservationError::CanonicalEncoding)
    }

    /// Rehydrate V2 terminal evidence where Q2 has completed. A tombstone
    /// retains this typed evidence to keep post-compaction status fail-closed.
    #[cfg(test)]
    pub(crate) fn v2_terminal_evidence(
        &self,
    ) -> Result<Option<RosterProfileV2CompactTerminalEvidenceV1>, ReservationError> {
        self.terminal_evidence
            .as_deref()
            .map(RosterProfileV2CompactTerminalEvidenceV1::decode_canonical)
            .transpose()
            .map_err(|_| ReservationError::CanonicalEncoding)
    }

    #[cfg(test)]
    pub(crate) const fn peak_charge_bytes(&self) -> u64 {
        self.peak_charge_bytes
    }

    /// Rehydrate the exact authenticated V2 admission after canonical row
    /// validation. This never manufactures an absent predecessor.
    pub(crate) fn admission(&self) -> Result<Admission, ReservationError> {
        Admission::from_canonical_bytes(&self.admission)
            .map_err(|_| ReservationError::CanonicalEncoding)
    }

    /// Return the sealed canonical admission bytes for the dedicated V2
    /// admissions table.
    pub(crate) fn admission_bytes(&self) -> &[u8] {
        &self.admission
    }

    /// Return the root-certified admission ingress bytes retained by V2.
    #[cfg(test)]
    pub(crate) fn admission_ingress_bytes(&self) -> &[u8] {
        &self.admission_ingress
    }

    /// Return the compact admission provenance bytes retained by V2.
    #[cfg(test)]
    pub(crate) fn admission_provenance_bytes(&self) -> &[u8] {
        &self.admission_provenance
    }

    /// Return the sealed terminal evidence canonical bytes only after Q2 has
    /// retained the profile-V2 terminal carrier.
    #[cfg(test)]
    pub(crate) fn terminal_evidence_bytes(&self) -> Option<&[u8]> {
        self.terminal_evidence.as_deref()
    }

    /// Return the sealed V2 proof-bundle canonical bytes retained with Q2.
    #[cfg(test)]
    pub(crate) fn terminal_proof_bundle_bytes(&self) -> Option<&[u8]> {
        self.terminal_proof_bundle.as_deref()
    }

    /// Return the exact absence reservation Q1 installed atomically.
    pub(crate) fn absence_reservation(
        &self,
    ) -> Option<&ProductionAdmissionAbsentBusinessReservationV2> {
        self.absence_reservation.as_ref()
    }

    /// Rehydrate the compact V2 conflict carrier after the full terminal has
    /// been reclaimed. A malformed compact row is never treated as absence.
    pub(crate) fn tombstone(&self) -> Result<Option<TerminalConflictTombstone>, ReservationError> {
        match (self.state, self.tombstone.as_deref()) {
            (ProductionReservationStateV2::Tombstone, Some(bytes)) => {
                let tombstone = TerminalConflictTombstone::from_canonical_bytes(bytes)
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                tombstone
                    .validate_binding_for_profile(
                        crate::fenced_mutation_roster::Profile::v2(),
                        self.binding,
                    )
                    .map_err(|_| ReservationError::SnapshotMismatch)?;
                Ok(Some(tombstone))
            }
            (ProductionReservationStateV2::Tombstone, None) => Err(ReservationError::StateShape),
            (_, None) => Ok(None),
            _ => Err(ReservationError::StateShape),
        }
    }

    /// Frame this V2 row under a disjoint prefix; V1 decoders cannot accept
    /// it as a `ProductionReservationRecord`.
    pub(crate) fn to_canonical_bytes(&self) -> Result<Vec<u8>, ReservationError> {
        self.to_canonical_bytes_with_profile(ChargeProfile::v1())
    }

    fn to_canonical_bytes_with_profile(
        &self,
        profile: ChargeProfile,
    ) -> Result<Vec<u8>, ReservationError> {
        self.validate(profile)?;
        encode_frame(
            PRODUCTION_RESERVATION_RECORD_V2_MAGIC,
            PRODUCTION_RESERVATION_RECORD_V2_DOMAIN,
            self,
            MAX_PRODUCTION_RESERVATION_RECORD_V2_SNAPSHOT_BYTES,
        )
        .map_err(|_| ReservationError::CanonicalEncoding)
    }

    /// Decode and fully revalidate one dedicated V2 row.
    #[cfg(test)]
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReservationError> {
        Self::from_canonical_vec_hydrated(bytes.to_vec())
            .map(HydratedProductionReservationRecordV2::into_record)
    }

    /// Decode, validate, and byte-for-byte recanonicalize one dedicated V2
    /// row while retaining every parsed authenticated component needed by a
    /// status or recovery read. Unlike [`Self::from_canonical_bytes`], this
    /// owns the exact durable frame and never invokes validation recursively.
    pub(crate) fn from_canonical_vec_hydrated(
        canonical: Vec<u8>,
    ) -> Result<HydratedProductionReservationRecordV2, ReservationError> {
        if canonical.len() > MAX_PRODUCTION_RESERVATION_RECORD_V2_SNAPSHOT_BYTES {
            return Err(ReservationError::ComponentBounds);
        }
        let record: Self = decode_frame(
            &canonical,
            PRODUCTION_RESERVATION_RECORD_V2_MAGIC,
            PRODUCTION_RESERVATION_RECORD_V2_DOMAIN,
            MAX_PRODUCTION_RESERVATION_RECORD_V2_SNAPSHOT_BYTES,
        )
        .map_err(|_| ReservationError::CanonicalEncoding)?;
        let (
            admission,
            admission_ingress,
            admission_provenance,
            committed_terminal,
            committed_canonical,
            terminal_proof_bundle,
            terminal_evidence,
            tombstone,
        ) = record.validate_and_hydrate(ChargeProfile::v1())?;
        if encode_frame(
            PRODUCTION_RESERVATION_RECORD_V2_MAGIC,
            PRODUCTION_RESERVATION_RECORD_V2_DOMAIN,
            &record,
            MAX_PRODUCTION_RESERVATION_RECORD_V2_SNAPSHOT_BYTES,
        )
        .map_err(|_| ReservationError::CanonicalEncoding)?
            != canonical
        {
            return Err(ReservationError::CanonicalEncoding);
        }
        Ok(HydratedProductionReservationRecordV2 {
            record,
            canonical,
            admission,
            admission_ingress,
            admission_provenance,
            committed_terminal,
            committed_canonical,
            terminal_proof_bundle,
            terminal_evidence,
            tombstone,
        })
    }

    /// Build the exact Q2 absent-row CAS from a live V2 admission. This does
    /// not itself authorize a retained terminal record: callers must use
    /// [`Self::prepare_terminalization`] with the V2-only terminal carrier.
    pub(crate) fn terminal_cas(
        &self,
        terminal: &CommittedTerminal,
    ) -> Result<ProductionTerminalAbsentBusinessCasV2, ReservationError> {
        let admission = Admission::from_canonical_bytes(&self.admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let reservation = self
            .absence_reservation
            .as_ref()
            .filter(|_| self.state == ProductionReservationStateV2::Live)
            .ok_or(ReservationError::InvalidState)?;
        ProductionTerminalAbsentBusinessCasV2::from_committed(
            &admission,
            self.binding,
            terminal,
            reservation,
        )
    }

    /// Prepare the one retained V2 terminal carrier and exact Q2 absence CAS.
    ///
    /// SQLite must persist `replacement`, apply `business_cas`, and delete
    /// the exact V2 absence-reservation row in one second consensus mutation.
    /// The V2 compact envelope binds its ingress and provenance back to this
    /// live row; V1 evidence cannot reach this transition. The full root,
    /// authority, registration, and fresh-terminal-ingress cryptographic
    /// verifier requires consensus-owned inputs and runs before this storage
    /// preparation path; this layer rechecks only canonical structural and
    /// exact durable-binding facts.
    pub(crate) fn prepare_terminalization(
        &self,
        terminal: &CommittedTerminal,
        terminal_proof_bundle: &RosterProfileV2ExecutorProofBundleV1,
        terminal_evidence: &RosterProfileV2CompactTerminalEvidenceV1,
        profile: ChargeProfile,
    ) -> Result<PreparedProductionTerminalizationV2, ReservationError> {
        self.validate(profile)?;
        if self.state != ProductionReservationStateV2::Live {
            return Err(ReservationError::InvalidState);
        }
        let admission = Admission::from_canonical_bytes(&self.admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let terminal_bytes = terminal
            .to_canonical_bytes(&admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        if terminal.record().request_id().history_epoch() != self.binding.history_epoch() {
            return Err(ReservationError::SnapshotMismatch);
        }
        let evidence_bytes = terminal_evidence
            .canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let proof_bundle_bytes = terminal_proof_bundle
            .canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        validate_v2_terminal_evidence(
            terminal_evidence,
            &admission,
            &self.admission_ingress,
            &self.admission_provenance,
            terminal.record(),
        )?;
        validate_v2_terminal_proof_bundle(
            terminal_proof_bundle,
            terminal_evidence,
            &self.admission_provenance,
        )?;
        let business_cas = self.terminal_cas(terminal)?;
        let compact_bytes = self
            .admission_provenance
            .len()
            .checked_add(evidence_bytes.len())
            .ok_or(ReservationError::Arithmetic)?;
        if compact_bytes > max_v2_compact_evidence_bytes() {
            return Err(ReservationError::ComponentBounds);
        }
        let retained = profile.charge(production_components_v2(
            &self.admission,
            Some(&terminal_bytes),
            None,
            compact_bytes,
        )?)?;
        if retained.retained > self.peak_charge_bytes {
            return Err(ReservationError::SnapshotMismatch);
        }
        let replacement = Self {
            binding: self.binding,
            admission: self.admission.clone(),
            admission_ingress: self.admission_ingress.clone(),
            admission_provenance: self.admission_provenance.clone(),
            terminal: Some(terminal_bytes),
            terminal_proof_bundle: Some(proof_bundle_bytes),
            terminal_evidence: Some(evidence_bytes),
            tombstone: None,
            terminalized_at: Some(ConsensusMaintenanceTimestamp::from_consensus_timestamp(
                terminal.commit_metadata().committed_at(),
            )?),
            terminal_sequence: Some(terminal.terminal_sequence()),
            absence_reservation: None,
            state: ProductionReservationStateV2::Retained,
            peak_charge_bytes: self.peak_charge_bytes,
            retained_charge_bytes: retained.retained,
            tombstone_charge_bytes: retained.tombstone,
        };
        replacement.validate(profile)?;
        Ok(PreparedProductionTerminalizationV2 {
            replacement,
            business_cas,
        })
    }

    /// Compact an aged V2 terminal without ever restoring the Q1 absence
    /// reservation. The replacement retains V2's root-signed compact
    /// provenance and terminal evidence beside the shared conflict tombstone.
    fn reclaim_at(
        &mut self,
        maintenance_time: ConsensusMaintenanceTimestamp,
        profile: ChargeProfile,
    ) -> Result<(), ReservationError> {
        self.validate(profile)?;
        if self.state != ProductionReservationStateV2::Retained {
            return Err(ReservationError::InvalidState);
        }
        let terminalized_at = self.terminalized_at.ok_or(ReservationError::StateShape)?;
        if terminalized_at.checked_add_retention()? > maintenance_time {
            return Err(ReservationError::NotEligible);
        }
        let admission = Admission::from_canonical_bytes(&self.admission)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let terminal = CommittedTerminal::from_canonical_bytes(
            self.terminal
                .as_deref()
                .ok_or(ReservationError::StateShape)?,
            &admission,
        )
        .map_err(|_| ReservationError::CanonicalEncoding)?;
        let provenance = RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(
            &self.admission_provenance,
        )
        .map_err(|_| ReservationError::CanonicalEncoding)?;
        let evidence = RosterProfileV2CompactTerminalEvidenceV1::decode_canonical(
            self.terminal_evidence
                .as_deref()
                .ok_or(ReservationError::StateShape)?,
        )
        .map_err(|_| ReservationError::CanonicalEncoding)?;
        if evidence.provenance() != &provenance {
            return Err(ReservationError::SnapshotMismatch);
        }
        let tombstone = TerminalConflictTombstone::from_committed_terminal(&admission, &terminal)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        tombstone
            .validate_binding_for_profile(
                crate::fenced_mutation_roster::Profile::v2(),
                self.binding,
            )
            .map_err(|_| ReservationError::SnapshotMismatch)?;
        tombstone
            .validate_profile_v2_compact_terminal_evidence(&evidence)
            .map_err(|_| ReservationError::SnapshotMismatch)?;
        let tombstone_bytes = tombstone
            .to_canonical_bytes()
            .map_err(|_| ReservationError::CanonicalEncoding)?;
        let compact_bytes = self
            .admission_provenance
            .len()
            .checked_add(self.terminal_evidence.as_ref().map_or(0, Vec::len))
            .ok_or(ReservationError::Arithmetic)?;
        let charges = profile.charge(production_components_v2(
            &[],
            None,
            Some(&tombstone_bytes),
            compact_bytes,
        )?)?;
        self.admission.clear();
        self.admission_ingress.clear();
        self.terminal = None;
        self.terminal_proof_bundle = None;
        self.tombstone = Some(tombstone_bytes);
        self.absence_reservation = None;
        self.state = ProductionReservationStateV2::Tombstone;
        self.peak_charge_bytes = 0;
        self.retained_charge_bytes = 0;
        self.tombstone_charge_bytes = charges.tombstone;
        self.validate(profile)
    }

    fn validate(&self, profile: ChargeProfile) -> Result<(), ReservationError> {
        self.validate_and_hydrate(profile).map(|_| ())
    }

    /// Validate every V2 durable invariant while retaining the decoded
    /// authenticated pieces needed by a hot status/recovery read.
    #[allow(clippy::type_complexity)]
    fn validate_and_hydrate(
        &self,
        profile: ChargeProfile,
    ) -> Result<
        (
            Option<Admission>,
            Option<RosterIngressAttestationV2>,
            RosterProfileV2CompactAdmissionProvenanceV1,
            Option<Box<CommittedTerminal>>,
            Option<Vec<u8>>,
            Option<RosterProfileV2ExecutorProofBundleV1>,
            Option<RosterProfileV2CompactTerminalEvidenceV1>,
            Option<TerminalConflictTombstone>,
        ),
        ReservationError,
    > {
        validate_epoch(self.binding.history_epoch())?;
        let admission_provenance = RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(
            &self.admission_provenance,
        )
        .map_err(|_| ReservationError::CanonicalEncoding)?;
        validate_v2_provenance_binding(self.binding, &admission_provenance)?;
        let (admission, admission_ingress) =
            if self.state == ProductionReservationStateV2::Tombstone {
                if !self.admission.is_empty() || !self.admission_ingress.is_empty() {
                    return Err(ReservationError::StateShape);
                }
                (None, None)
            } else {
                let admission = Admission::from_canonical_bytes(&self.admission)
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                if admission
                    .binding_key(self.binding.history_epoch())
                    .map_err(|_| ReservationError::CanonicalEncoding)?
                    != self.binding
                    || admission.profile() != crate::fenced_mutation_roster::Profile::v2()
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
                let ingress = RosterIngressAttestationV2::decode_canonical(&self.admission_ingress)
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                if admission_provenance.input().ingress != *ingress.signing_input() {
                    return Err(ReservationError::SnapshotMismatch);
                }
                (Some(admission), Some(ingress))
            };
        match self.state {
            ProductionReservationStateV2::Live => {
                let admission = admission.as_ref().ok_or(ReservationError::StateShape)?;
                let admission_ingress = admission_ingress
                    .as_ref()
                    .ok_or(ReservationError::StateShape)?;
                let live = profile.charge(production_components_v2(
                    &self.admission,
                    None,
                    None,
                    max_v2_compact_evidence_bytes(),
                )?)?;
                if self.terminal.is_some()
                    || self.terminal_proof_bundle.is_some()
                    || self.terminal_evidence.is_some()
                    || self.tombstone.is_some()
                    || self.terminalized_at.is_some()
                    || self.terminal_sequence.is_some()
                {
                    return Err(ReservationError::StateShape);
                }
                self.absence_reservation
                    .as_ref()
                    .ok_or(ReservationError::StateShape)?
                    .validate_for(admission, self.binding)?;
                if self.peak_charge_bytes == live.peak
                    && self.retained_charge_bytes == live.retained
                    && self.tombstone_charge_bytes == live.tombstone
                {
                    Ok((
                        Some(admission.clone()),
                        Some(admission_ingress.clone()),
                        admission_provenance,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ))
                } else {
                    Err(ReservationError::SnapshotMismatch)
                }
            }
            ProductionReservationStateV2::Retained => {
                let admission = admission.as_ref().ok_or(ReservationError::StateShape)?;
                let admission_ingress = admission_ingress
                    .as_ref()
                    .ok_or(ReservationError::StateShape)?;
                let live = profile.charge(production_components_v2(
                    &self.admission,
                    None,
                    None,
                    max_v2_compact_evidence_bytes(),
                )?)?;
                if self.absence_reservation.is_some() || self.tombstone.is_some() {
                    return Err(ReservationError::StateShape);
                }
                let terminal = self
                    .terminal
                    .as_deref()
                    .ok_or(ReservationError::StateShape)?;
                let terminal = CommittedTerminal::from_canonical_bytes(terminal, admission)
                    .map_err(|_| ReservationError::CanonicalEncoding)?;
                if terminal.record().request_id().history_epoch() != self.binding.history_epoch()
                    || self.terminal_sequence != Some(terminal.terminal_sequence())
                    || self.terminalized_at
                        != Some(ConsensusMaintenanceTimestamp::from_consensus_timestamp(
                            terminal.commit_metadata().committed_at(),
                        )?)
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
                let terminal_evidence = self
                    .terminal_evidence
                    .as_deref()
                    .ok_or(ReservationError::StateShape)
                    .and_then(|bytes| {
                        RosterProfileV2CompactTerminalEvidenceV1::decode_canonical(bytes)
                            .map_err(|_| ReservationError::CanonicalEncoding)
                    })?;
                let terminal_proof_bundle = self
                    .terminal_proof_bundle
                    .as_deref()
                    .ok_or(ReservationError::StateShape)
                    .and_then(|bytes| {
                        RosterProfileV2ExecutorProofBundleV1::decode_canonical(bytes)
                            .map_err(|_| ReservationError::CanonicalEncoding)
                    })?;
                validate_v2_terminal_evidence(
                    &terminal_evidence,
                    admission,
                    &self.admission_ingress,
                    &self.admission_provenance,
                    terminal.record(),
                )?;
                validate_v2_terminal_proof_bundle(
                    &terminal_proof_bundle,
                    &terminal_evidence,
                    &self.admission_provenance,
                )?;
                let compact_bytes = self
                    .admission_provenance
                    .len()
                    .checked_add(self.terminal_evidence.as_ref().map_or(0, Vec::len))
                    .ok_or(ReservationError::Arithmetic)?;
                if compact_bytes > max_v2_compact_evidence_bytes() {
                    return Err(ReservationError::ComponentBounds);
                }
                let retained = profile.charge(production_components_v2(
                    &self.admission,
                    self.terminal.as_deref(),
                    None,
                    compact_bytes,
                )?)?;
                if self.peak_charge_bytes == live.peak
                    && self.retained_charge_bytes == retained.retained
                    && self.tombstone_charge_bytes == retained.tombstone
                {
                    Ok((
                        Some(admission.clone()),
                        Some(admission_ingress.clone()),
                        admission_provenance,
                        Some(Box::new(terminal)),
                        Some(self.terminal.as_deref().unwrap_or_default().to_vec()),
                        Some(terminal_proof_bundle),
                        Some(terminal_evidence),
                        None,
                    ))
                } else {
                    Err(ReservationError::SnapshotMismatch)
                }
            }
            ProductionReservationStateV2::Tombstone => {
                if self.absence_reservation.is_some()
                    || !self.admission.is_empty()
                    || !self.admission_ingress.is_empty()
                    || self.terminal.is_some()
                    || self.terminal_proof_bundle.is_some()
                {
                    return Err(ReservationError::StateShape);
                }
                let terminalized_at = self.terminalized_at.ok_or(ReservationError::StateShape)?;
                let terminal_sequence = self
                    .terminal_sequence
                    .filter(|sequence| *sequence > 0)
                    .ok_or(ReservationError::StateShape)?;
                let terminal_evidence = self
                    .terminal_evidence
                    .as_deref()
                    .ok_or(ReservationError::StateShape)
                    .and_then(|bytes| {
                        RosterProfileV2CompactTerminalEvidenceV1::decode_canonical(bytes)
                            .map_err(|_| ReservationError::CanonicalEncoding)
                    })?;
                if terminal_evidence.provenance() != &admission_provenance {
                    return Err(ReservationError::SnapshotMismatch);
                }
                let tombstone = self.tombstone()?.ok_or(ReservationError::StateShape)?;
                if tombstone.terminal_raft_log_index() == 0 {
                    return Err(ReservationError::SnapshotMismatch);
                }
                tombstone
                    .validate_binding_for_profile(
                        crate::fenced_mutation_roster::Profile::v2(),
                        self.binding,
                    )
                    .map_err(|_| ReservationError::SnapshotMismatch)?;
                tombstone
                    .validate_profile_v2_compact_terminal_evidence(&terminal_evidence)
                    .map_err(|_| ReservationError::SnapshotMismatch)?;
                let compact_bytes = self
                    .admission_provenance
                    .len()
                    .checked_add(self.terminal_evidence.as_ref().map_or(0, Vec::len))
                    .ok_or(ReservationError::Arithmetic)?;
                let tombstone_bytes = self
                    .tombstone
                    .as_deref()
                    .ok_or(ReservationError::StateShape)?;
                let charges = profile.charge(production_components_v2(
                    &[],
                    None,
                    Some(tombstone_bytes),
                    compact_bytes,
                )?)?;
                if self.peak_charge_bytes == 0
                    && self.retained_charge_bytes == 0
                    && self.tombstone_charge_bytes == charges.tombstone
                {
                    let _ = (terminalized_at, terminal_sequence);
                    Ok((
                        None,
                        None,
                        admission_provenance,
                        None,
                        None,
                        None,
                        Some(terminal_evidence),
                        Some(tombstone),
                    ))
                } else {
                    Err(ReservationError::SnapshotMismatch)
                }
            }
        }
    }
}

/// Complete V2 Q2 replacement. It is deliberately distinct from the V1
/// prepared transaction: Q2 has exactly one retained V2 carrier and one
/// absence-predicate CAS, never a V1 business-reservation transition.
#[derive(Clone)]
pub(crate) struct PreparedProductionTerminalizationV2 {
    replacement: ProductionReservationRecordV2,
    business_cas: ProductionTerminalAbsentBusinessCasV2,
}

/// V2's witness-coupled Q1/Q2 result.
///
/// The V2 row and the shared global witness are separate durable projections,
/// but this type keeps their expected and replacement values together so a
/// SQLite caller cannot reserve or release charge without the exact carrier
/// CAS.  It deliberately contains no authority or verifier input: those are
/// validated before this capacity-only planner is called.
#[derive(Clone)]
pub(crate) struct PreparedProductionV2CapacityTransition {
    next: GlobalChargeWitness,
}

/// Q1's row-capacity and V2 floor insertion/assertion are one prepared
/// consensus action.  Keeping the floor beside the witness transition makes
/// it impossible for an adapter to persist a live absent reservation without
/// its conflict-closing history floor.
#[derive(Clone)]
pub(crate) struct PreparedProductionV2Admission {
    previous: GlobalChargeWitness,
    next: GlobalChargeWitness,
    floor: ProductionFloorCas,
    retirement_cursor: ProductionRetirementCursorCas,
}

impl PreparedProductionV2Admission {
    pub(crate) const fn previous_witness(&self) -> GlobalChargeWitness {
        self.previous
    }

    pub(crate) const fn next_witness(&self) -> GlobalChargeWitness {
        self.next
    }

    pub(crate) const fn floor_cas(&self) -> &ProductionFloorCas {
        &self.floor
    }

    /// Return the exact shared cursor assertion paired with V2 admission.
    pub(crate) const fn retirement_cursor_cas(&self) -> &ProductionRetirementCursorCas {
        &self.retirement_cursor
    }
}

/// Exact one-row V2 retained-to-compact replacement plus its shared-witness
/// compare-and-swap. Mixed-profile maintenance composes these transitions in
/// the one globally ordered reclaim prefix selected by consensus.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct PreparedProductionV2Reclaim {
    replacement: ProductionReservationRecordV2,
    previous: GlobalChargeWitness,
    next: GlobalChargeWitness,
}

#[cfg(test)]
impl PreparedProductionV2Reclaim {
    pub(crate) const fn replacement(&self) -> &ProductionReservationRecordV2 {
        &self.replacement
    }

    pub(crate) const fn previous_witness(&self) -> GlobalChargeWitness {
        self.previous
    }

    pub(crate) const fn next_witness(&self) -> GlobalChargeWitness {
        self.next
    }
}

#[cfg(test)]
impl fmt::Debug for PreparedProductionV2Reclaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedProductionV2Reclaim(<redacted>)")
    }
}

/// Namespace tag carried by common maintenance guards. It is deliberately not
/// serialized into either frozen V1 or isolated V2 row codec.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProductionRosterProfileTag {
    V1,
    V2,
}

/// Borrowed row selected from the single profile-union reclaim query.
pub(crate) enum ProductionMixedReclaimSelection<'a> {
    V1(&'a ProductionReservationRecord),
    V2(&'a ProductionReservationRecordV2),
}

/// Exact replacement action produced by one union reclaim preparation.
#[derive(Clone)]
pub(crate) enum ProductionMixedReclaimRow {
    V1 {
        expected: Box<ProductionReservationRecord>,
        replacement: Box<ProductionReservationRecord>,
    },
    V2 {
        expected: Box<ProductionReservationRecordV2>,
        replacement: Box<ProductionReservationRecordV2>,
    },
    DeleteV1(Box<ProductionReservationRecord>),
    DeleteV2(Box<ProductionReservationRecordV2>),
}

impl ProductionMixedReclaimRow {
    pub(crate) fn binding(&self) -> RequestBindingKey {
        match self {
            Self::V1 { expected, .. } => expected.binding(),
            Self::V2 { expected, .. } => expected.binding(),
            Self::DeleteV1(expected) => expected.binding(),
            Self::DeleteV2(expected) => expected.binding(),
        }
    }

    /// Return the exact V1 compare-and-replace pair. The adapter must compare
    /// `expected` before it writes `replacement` in the V1 table.
    pub(crate) fn v1_replacement(
        &self,
    ) -> Option<(&ProductionReservationRecord, &ProductionReservationRecord)> {
        match self {
            Self::V1 {
                expected,
                replacement,
            } => Some((expected, replacement)),
            Self::V2 { .. } | Self::DeleteV1(_) | Self::DeleteV2(_) => None,
        }
    }

    /// Return the exact V2 compare-and-replace pair. The adapter must compare
    /// `expected` before it writes `replacement` in the V2 table.
    pub(crate) fn v2_replacement(
        &self,
    ) -> Option<(
        &ProductionReservationRecordV2,
        &ProductionReservationRecordV2,
    )> {
        match self {
            Self::V2 {
                expected,
                replacement,
            } => Some((expected, replacement)),
            Self::V1 { .. } | Self::DeleteV1(_) | Self::DeleteV2(_) => None,
        }
    }

    /// Return the exact V1 row that the adapter must compare and delete.
    pub(crate) fn v1_delete(&self) -> Option<&ProductionReservationRecord> {
        match self {
            Self::DeleteV1(expected) => Some(expected),
            Self::V1 { .. } | Self::V2 { .. } | Self::DeleteV2(_) => None,
        }
    }

    /// Return the exact V2 row that the adapter must compare and delete.
    pub(crate) fn v2_delete(&self) -> Option<&ProductionReservationRecordV2> {
        match self {
            Self::DeleteV2(expected) => Some(expected),
            Self::V1 { .. } | Self::V2 { .. } | Self::DeleteV1(_) => None,
        }
    }

    /// Return the V1 expected carrier for either a replace or delete action.
    #[cfg(test)]
    pub(crate) fn v1_expected_row(&self) -> Option<&ProductionReservationRecord> {
        match self {
            Self::V1 { expected, .. } | Self::DeleteV1(expected) => Some(expected),
            Self::V2 { .. } | Self::DeleteV2(_) => None,
        }
    }

    /// Return the V1 replacement carrier, if this action writes rather than
    /// deletes its exact expected row.
    #[cfg(test)]
    pub(crate) fn v1_replacement_row(&self) -> Option<&ProductionReservationRecord> {
        match self {
            Self::V1 { replacement, .. } => Some(replacement),
            Self::V2 { .. } | Self::DeleteV1(_) | Self::DeleteV2(_) => None,
        }
    }

    /// Return the V2 expected carrier for either a replace or delete action.
    #[cfg(test)]
    pub(crate) fn v2_expected_row(&self) -> Option<&ProductionReservationRecordV2> {
        match self {
            Self::V2 { expected, .. } => Some(expected.as_ref()),
            Self::DeleteV2(expected) => Some(expected),
            Self::V1 { .. } | Self::DeleteV1(_) => None,
        }
    }

    /// Return the V2 replacement carrier, if this action writes rather than
    /// deletes its exact expected row.
    #[cfg(test)]
    pub(crate) fn v2_replacement_row(&self) -> Option<&ProductionReservationRecordV2> {
        match self {
            Self::V2 { replacement, .. } => Some(replacement),
            Self::V1 { .. } | Self::DeleteV1(_) | Self::DeleteV2(_) => None,
        }
    }
}

/// Adapter-reproved exact oldest union prefix under
/// `(terminalized_at, binding, profile)`. The final partial batch is legal;
/// a shorter caller-selected subset is not.
#[derive(Clone)]
pub(crate) struct ProductionMixedReclaimOldestGuard {
    selected: Vec<(
        ConsensusMaintenanceTimestamp,
        RequestBindingKey,
        ProductionRosterProfileTag,
    )>,
}

impl ProductionMixedReclaimOldestGuard {
    pub(crate) fn selected(
        &self,
    ) -> &[(
        ConsensusMaintenanceTimestamp,
        RequestBindingKey,
        ProductionRosterProfileTag,
    )] {
        &self.selected
    }
}

/// One composable witness transition for a profile-union reclaim batch.
#[derive(Clone)]
pub(crate) struct PreparedProductionMixedReclaim {
    rows: Vec<ProductionMixedReclaimRow>,
    previous: GlobalChargeWitness,
    next: GlobalChargeWitness,
    guard: ProductionMixedReclaimOldestGuard,
}

impl PreparedProductionMixedReclaim {
    pub(crate) fn rows(&self) -> &[ProductionMixedReclaimRow] {
        &self.rows
    }

    pub(crate) const fn previous_witness(&self) -> GlobalChargeWitness {
        self.previous
    }

    pub(crate) const fn next_witness(&self) -> GlobalChargeWitness {
        self.next
    }

    pub(crate) const fn oldest_guard(&self) -> &ProductionMixedReclaimOldestGuard {
        &self.guard
    }
}

/// Plan the exact selected cross-profile reclaim prefix. SQLite must issue one
/// UNION query with the guard tuple/order/cutoff/limit and compare every row
/// before applying any replacement and the one shared-witness CAS.
pub(crate) fn prepare_production_mixed_reclaim(
    selected: &[ProductionMixedReclaimSelection<'_>],
    maintenance_time: ConsensusMaintenanceTimestamp,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionMixedReclaim, ReservationError> {
    witness.admits(budget)?;
    if selected.is_empty() || selected.len() > RECLAIM_BATCH {
        return Err(ReservationError::SnapshotMismatch);
    }
    let mut previous_order = None;
    let mut rows = Vec::with_capacity(selected.len());
    let mut guard_rows = Vec::with_capacity(selected.len());
    let mut counters = witness.roster;
    for selection in selected {
        match selection {
            ProductionMixedReclaimSelection::V1(record) => {
                record.validate(profile)?;
                if record.state != ReservationState::Retained {
                    return Err(ReservationError::InvalidState);
                }
                let at = record.terminalized_at.ok_or(ReservationError::StateShape)?;
                if at.checked_add_retention()? > maintenance_time {
                    return Err(ReservationError::NotEligible);
                }
                let order = (at, record.binding(), ProductionRosterProfileTag::V1);
                if previous_order.is_some_and(|previous| previous >= order) {
                    return Err(ReservationError::SnapshotMismatch);
                }
                previous_order = Some(order);
                let mut replacement = (*record).clone();
                replacement.reclaim_at(maintenance_time, profile)?;
                counters = counters_without_production_record(counters, record, profile)?;
                counters = counters_with_production_record(counters, &replacement, profile)?;
                rows.push(ProductionMixedReclaimRow::V1 {
                    expected: Box::new((*record).clone()),
                    replacement: Box::new(replacement),
                });
                guard_rows.push(order);
            }
            ProductionMixedReclaimSelection::V2(record) => {
                record.validate(profile)?;
                if record.state != ProductionReservationStateV2::Retained {
                    return Err(ReservationError::InvalidState);
                }
                let at = record.terminalized_at.ok_or(ReservationError::StateShape)?;
                if at.checked_add_retention()? > maintenance_time {
                    return Err(ReservationError::NotEligible);
                }
                let order = (at, record.binding(), ProductionRosterProfileTag::V2);
                if previous_order.is_some_and(|previous| previous >= order) {
                    return Err(ReservationError::SnapshotMismatch);
                }
                previous_order = Some(order);
                let mut replacement = (*record).clone();
                replacement.reclaim_at(maintenance_time, profile)?;
                counters = counters_without_production_record_v2(counters, record, profile)?;
                counters = counters_with_production_record_v2(counters, &replacement, profile)?;
                rows.push(ProductionMixedReclaimRow::V2 {
                    expected: Box::new((*record).clone()),
                    replacement: Box::new(replacement),
                });
                guard_rows.push(order);
            }
        }
    }
    let next = witness.with_roster(counters);
    next.admits(budget)?;
    Ok(PreparedProductionMixedReclaim {
        rows,
        previous: witness,
        next,
        guard: ProductionMixedReclaimOldestGuard {
            selected: guard_rows,
        },
    })
}

/// Borrowed compact row from the single cross-profile terminal-sequence
/// prefix. A caller cannot mix independent V1/V2 retirement horizons.
pub(crate) enum ProductionMixedTerminalRetirementSelection<'a> {
    V1(&'a ProductionReservationRecord),
    V2(&'a ProductionReservationRecordV2),
}

/// Exact profile-tagged terminal-history prefix which SQLite must re-prove
/// before deleting rows and applying the accompanying shared floor/cursor
/// CASes in the same witness transaction.
#[derive(Clone)]
pub(crate) struct ProductionMixedTerminalRetirementGuard {
    selected: Vec<(u64, RequestBindingKey, ProductionRosterProfileTag)>,
    partitions: Vec<ProductionMixedTerminalRetirementPartitionGuard>,
}

/// Authoritative shared partition state for one page of the global terminal
/// prefix. A partition applies equally to V1 and V2 row tables because its
/// key derives solely from the request binding.
#[derive(Clone)]
pub(crate) struct ProductionMixedTerminalRetirementPartition {
    floor: IrreversibleHistoryFloor,
    cursor: Option<ProductionRetirementCursor>,
    target_epoch: u64,
    final_batch: bool,
    partition_empty_after: bool,
}

impl ProductionMixedTerminalRetirementPartition {
    /// Build a partition retirement action with the adapter's exact
    /// cross-profile partition-empty proof. An empty-partition assertion is
    /// meaningful only after the final target-epoch page; it releases the
    /// floor instead of preserving it at the retired epoch.
    pub(crate) fn new_with_partition_empty_after(
        floor: IrreversibleHistoryFloor,
        cursor: Option<ProductionRetirementCursor>,
        target_epoch: u64,
        final_batch: bool,
        partition_empty_after: bool,
    ) -> Result<Self, ReservationError> {
        validate_epoch(target_epoch)?;
        if target_epoch <= floor.retired_through() || (partition_empty_after && !final_batch) {
            return Err(ReservationError::FloorAdvance);
        }
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate_for_floor(floor)?;
            if cursor.target_epoch() != target_epoch {
                return Err(ReservationError::FloorAdvance);
            }
        }
        Ok(Self {
            floor,
            cursor,
            target_epoch,
            final_batch,
            partition_empty_after,
        })
    }
}

/// Exact partition range that SQLite must re-prove along with the global
/// terminal-sequence prefix. On a final page, the adapter must also prove no
/// retained or tombstone row from either profile remains at `target_epoch`.
#[derive(Clone)]
pub(crate) struct ProductionMixedTerminalRetirementPartitionGuard;

/// Exact shared retention mutation produced by mixed terminal retirement.
/// Profile tags belong only to the independent row deletes, never to the
/// floor/cursor authority that closes their common binding namespace.
#[derive(Clone)]
pub(crate) struct ProductionMixedTerminalRetirementFloorAction {
    floor: ProductionFloorCas,
    cursor: ProductionRetirementCursorCas,
}

impl ProductionMixedTerminalRetirementFloorAction {
    pub(crate) const fn floor(&self) -> &ProductionFloorCas {
        &self.floor
    }

    pub(crate) const fn cursor(&self) -> &ProductionRetirementCursorCas {
        &self.cursor
    }
}

impl ProductionMixedTerminalRetirementGuard {
    pub(crate) fn selected(&self) -> &[(u64, RequestBindingKey, ProductionRosterProfileTag)] {
        &self.selected
    }

    pub(crate) fn partitions(&self) -> &[ProductionMixedTerminalRetirementPartitionGuard] {
        &self.partitions
    }
}

/// Row deletions and one shared witness advance for an exact global terminal
/// prefix. Shared floor/cursor CASes are validated under this guard; no
/// independent planner may advance the global terminal horizon.
#[derive(Clone)]
pub(crate) struct PreparedProductionMixedTerminalRetirement {
    rows: Vec<ProductionMixedReclaimRow>,
    floor_actions: Vec<ProductionMixedTerminalRetirementFloorAction>,
    previous: GlobalChargeWitness,
    next: GlobalChargeWitness,
    guard: ProductionMixedTerminalRetirementGuard,
}

impl PreparedProductionMixedTerminalRetirement {
    pub(crate) fn rows(&self) -> &[ProductionMixedReclaimRow] {
        &self.rows
    }

    /// Shared floor/cursor CASes to apply with profile-tagged row deletes and
    /// the one shared witness compare-and-swap.
    pub(crate) fn floor_actions(&self) -> &[ProductionMixedTerminalRetirementFloorAction] {
        &self.floor_actions
    }

    pub(crate) const fn previous_witness(&self) -> GlobalChargeWitness {
        self.previous
    }

    pub(crate) const fn next_witness(&self) -> GlobalChargeWitness {
        self.next
    }

    pub(crate) const fn guard(&self) -> &ProductionMixedTerminalRetirementGuard {
        &self.guard
    }
}

/// Validate and plan one profile-union tombstone prefix. Terminal sequences
/// are consensus/application coordinates and may legitimately be sparse; the
/// guard therefore requires strictly increasing values above the witness
/// horizon. SQLite re-proves that this is the complete ordered union prefix
/// before it may advance the shared closure, so no V1 or V2 row can be
/// omitted. A final partition page also requires the adapter to prove that an
/// opposite-profile retained row does not remain at the target epoch. A
/// floor can be deleted only when its partition also carries an adapter-proved
/// absence of higher-epoch rows across both profiles.
pub(crate) fn prepare_production_mixed_terminal_retirement(
    selected: &[ProductionMixedTerminalRetirementSelection<'_>],
    partitions: &[ProductionMixedTerminalRetirementPartition],
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionMixedTerminalRetirement, ReservationError> {
    witness.admits(budget)?;
    if selected.is_empty() || selected.len() > RECLAIM_BATCH {
        return Err(ReservationError::SnapshotMismatch);
    }
    let mut previous_sequence = witness.retired_terminal_sequence();
    let mut counters = witness.roster;
    let mut rows = Vec::with_capacity(selected.len());
    let mut guard_rows = Vec::with_capacity(selected.len());
    let mut seen_bindings = BTreeMap::new();
    for selection in selected {
        match selection {
            ProductionMixedTerminalRetirementSelection::V1(record) => {
                record.validate(profile)?;
                let sequence = record
                    .terminal_sequence()
                    .ok_or(ReservationError::StateShape)?;
                if record.state != ReservationState::Tombstone || sequence <= previous_sequence {
                    return Err(ReservationError::SnapshotMismatch);
                }
                if seen_bindings.insert(record.binding(), ()).is_some() {
                    return Err(ReservationError::Duplicate);
                }
                counters = counters_without_production_record(counters, record, profile)?;
                rows.push(ProductionMixedReclaimRow::DeleteV1(Box::new(
                    (*record).clone(),
                )));
                guard_rows.push((sequence, record.binding(), ProductionRosterProfileTag::V1));
            }
            ProductionMixedTerminalRetirementSelection::V2(record) => {
                record.validate(profile)?;
                let sequence = record
                    .terminal_sequence()
                    .ok_or(ReservationError::StateShape)?;
                if record.state != ProductionReservationStateV2::Tombstone
                    || sequence <= previous_sequence
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
                if seen_bindings.insert(record.binding(), ()).is_some() {
                    return Err(ReservationError::Duplicate);
                }
                counters = counters_without_production_record_v2(counters, record, profile)?;
                rows.push(ProductionMixedReclaimRow::DeleteV2(Box::new(
                    (*record).clone(),
                )));
                guard_rows.push((sequence, record.binding(), ProductionRosterProfileTag::V2));
            }
        }
        previous_sequence = match guard_rows.last() {
            Some((sequence, _, _)) => *sequence,
            None => return Err(ReservationError::SnapshotMismatch),
        };
    }
    let mut floor_actions: Vec<ProductionMixedTerminalRetirementFloorAction> =
        Vec::with_capacity(partitions.len());
    let mut partition_guards = Vec::with_capacity(partitions.len());
    let mut covered = BTreeMap::new();
    for partition in partitions {
        let key = ProductionFloorKey::from_floor(partition.floor)?;
        if covered.insert((key, partition.target_epoch), ()).is_some() {
            return Err(ReservationError::Duplicate);
        }
        let mut bindings = selected
            .iter()
            .filter_map(|selection| {
                let binding = match selection {
                    ProductionMixedTerminalRetirementSelection::V1(record) => record.binding(),
                    ProductionMixedTerminalRetirementSelection::V2(record) => record.binding(),
                };
                (ProductionFloorKey::from_binding(binding).ok() == Some(key)
                    && binding.history_epoch() == partition.target_epoch)
                    .then_some(binding)
            })
            .collect::<Vec<_>>();
        bindings.sort_unstable();
        if bindings.is_empty() || bindings.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ReservationError::FloorAdvance);
        }
        if let Some(cursor) = partition.cursor.as_ref() {
            cursor.validate_for_floor(partition.floor)?;
            if cursor.target_epoch() != partition.target_epoch {
                return Err(ReservationError::FloorAdvance);
            }
        }
        for binding in &bindings {
            partition
                .floor
                .validate_new_binding(*binding)
                .map_err(|_| ReservationError::FloorAdvance)?;
        }
        let (floor, cursor) = if partition.final_batch {
            let replacement = partition
                .floor
                .advance_to(partition.target_epoch)
                .map_err(|_| ReservationError::FloorAdvance)?;
            counters = counters_without_production_floor(counters, partition.floor)?;
            if !partition.partition_empty_after {
                counters = counters_with_production_floor(counters, replacement)?;
            }
            if let Some(cursor) = partition.cursor.as_ref() {
                counters = counters_without_retirement_cursor(counters, cursor)?;
            }
            (
                ProductionFloorCas {
                    key,
                    expected: Some(partition.floor),
                    replacement: (!partition.partition_empty_after).then_some(replacement),
                },
                ProductionRetirementCursorCas {
                    key,
                    expected: partition.cursor.clone(),
                    replacement: None,
                },
            )
        } else {
            // A global terminal-sequence prefix does not establish that its
            // bindings are the next contiguous range in this partition's
            // binding order. It therefore cannot create or advance a
            // partition-local cursor. An already durable cursor is preserved
            // until a final page consumes it.
            (
                ProductionFloorCas {
                    key,
                    expected: Some(partition.floor),
                    replacement: Some(partition.floor),
                },
                ProductionRetirementCursorCas {
                    key,
                    expected: partition.cursor.clone(),
                    replacement: partition.cursor.clone(),
                },
            )
        };
        partition_guards.push(ProductionMixedTerminalRetirementPartitionGuard);
        floor_actions.push(ProductionMixedTerminalRetirementFloorAction { floor, cursor });
    }
    for selection in selected {
        let binding = match selection {
            ProductionMixedTerminalRetirementSelection::V1(record) => record.binding(),
            ProductionMixedTerminalRetirementSelection::V2(record) => record.binding(),
        };
        let key = ProductionFloorKey::from_binding(binding)?;
        if !covered.contains_key(&(key, binding.history_epoch())) {
            return Err(ReservationError::FloorAdvance);
        }
    }
    let next = witness
        .with_roster(counters)
        .retire_through_terminal_sequence(previous_sequence)?;
    next.admits(budget)?;
    Ok(PreparedProductionMixedTerminalRetirement {
        rows,
        floor_actions,
        previous: witness,
        next,
        guard: ProductionMixedTerminalRetirementGuard {
            selected: guard_rows,
            partitions: partition_guards,
        },
    })
}

impl PreparedProductionV2CapacityTransition {
    /// Return the exact witness to write with the V2 row transition.
    pub(crate) const fn next_witness(&self) -> GlobalChargeWitness {
        self.next
    }
}

impl fmt::Debug for PreparedProductionV2CapacityTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedProductionV2CapacityTransition(<redacted>)")
    }
}

/// Reserve V2 Q1's live slot, its one retained terminal-history slot, and
/// the exact maximum terminal charge in the existing global witness.
///
/// The live row's contribution is `live + (peak - live)`, rather than merely
/// its current bytes.  Consequently a later valid Q2 can only replace that
/// reserved peak with a retained charge no greater than the peak; it never
/// needs a second capacity admission.  The caller must compare-and-insert the
/// exact V2 row and write [`PreparedProductionV2CapacityTransition::next_witness`]
/// in the same consensus transaction.
#[cfg(test)]
pub(crate) fn prepare_production_v2_admission_capacity(
    record: &ProductionReservationRecordV2,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionV2CapacityTransition, ReservationError> {
    record.validate(profile)?;
    if record.state != ProductionReservationStateV2::Live {
        return Err(ReservationError::InvalidState);
    }
    witness.admits(budget)?;
    let next = witness.with_roster(counters_with_production_record_v2(
        witness.roster,
        record,
        profile,
    )?);
    next.admits(budget)?;
    Ok(PreparedProductionV2CapacityTransition { next })
}

/// Prepare V2 Q1 with the exact shared floor, cursor, and dual-table vacancy
/// assertions. This is the sole production admission entry point; the
/// capacity-only helper is retained for focused domain tests.
pub(crate) fn prepare_production_v2_admission_with_floor(
    vacancy: &ProductionBindingVacancyGuard,
    record: &ProductionReservationRecordV2,
    existing_floor: Option<IrreversibleHistoryFloor>,
    existing_cursor: Option<&ProductionRetirementCursor>,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionV2Admission, ReservationError> {
    vacancy.validate_for(record.binding())?;
    record.validate(profile)?;
    if record.state != ProductionReservationStateV2::Live {
        return Err(ReservationError::InvalidState);
    }
    witness.admits(budget)?;
    let key = ProductionFloorKey::from_binding(record.binding())?;
    let initial_floor = IrreversibleHistoryFloor::initial(record.binding())
        .map_err(|_| ReservationError::FloorAdvance)?;
    let floor = match existing_floor {
        Some(existing_floor) => {
            existing_floor
                .validate_new_binding(record.binding())
                .map_err(|_| ReservationError::FloorAdvance)?;
            ProductionFloorCas {
                key,
                expected: Some(existing_floor),
                replacement: Some(existing_floor),
            }
        }
        None => ProductionFloorCas {
            key,
            expected: None,
            replacement: Some(initial_floor),
        },
    };
    if let Some(cursor) = existing_cursor {
        cursor.validate_for_floor(floor.replacement().ok_or(ReservationError::FloorAdvance)?)?;
        // An unfinished common-partition retirement closes admissions for
        // both row tables until its cursor is consumed by maintenance.
        return Err(ReservationError::FloorAdvance);
    }
    let retirement_cursor = ProductionRetirementCursorCas::assert_existing(key, None);
    let mut counters = witness.roster;
    if floor.expected().is_none() {
        counters = counters_with_production_floor(
            counters,
            floor.replacement().ok_or(ReservationError::FloorAdvance)?,
        )?;
    }
    counters = counters_with_production_record_v2(counters, record, profile)?;
    let next = witness.with_roster(counters);
    next.admits(budget)?;
    Ok(PreparedProductionV2Admission {
        previous: witness,
        next,
        floor,
        retirement_cursor,
    })
}

/// Consume a V2 Q1 capacity reservation during Q2.
///
/// This is intentionally after all terminal cryptographic verification and
/// after [`ProductionReservationRecordV2::prepare_terminalization`] has bound
/// the exact absence CAS.  A valid Q2 cannot fail from capacity: the live
/// contribution already reserved `peak`, and the retained carrier is checked
/// to be no larger than that peak.  Any failure here is therefore malformed
/// or mismatched durable state, never a late "full" result.
pub(crate) fn prepare_production_v2_terminal_capacity(
    current: &ProductionReservationRecordV2,
    terminalization: &PreparedProductionTerminalizationV2,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionV2CapacityTransition, ReservationError> {
    current.validate(profile)?;
    if current.state != ProductionReservationStateV2::Live {
        return Err(ReservationError::InvalidState);
    }
    let replacement = terminalization.replacement();
    replacement.validate(profile)?;
    if replacement.binding != current.binding
        || replacement.state != ProductionReservationStateV2::Retained
        || replacement.peak_charge_bytes != current.peak_charge_bytes
        || replacement.retained_charge_bytes > current.peak_charge_bytes
    {
        return Err(ReservationError::SnapshotMismatch);
    }
    witness.admits(budget)?;
    let counters = counters_without_production_record_v2(witness.roster, current, profile)?;
    let next = witness.with_roster(counters_with_production_record_v2(
        counters,
        replacement,
        profile,
    )?);
    // This also verifies a forged/mismatched witness fails before it can be
    // exchanged for a retained row.  Given the checks above it cannot reject
    // a valid pre-admitted Q2 for capacity.
    next.admits(budget)?;
    Ok(PreparedProductionV2CapacityTransition { next })
}

/// Prepare exactly one V2 retained carrier for compaction at its fixed
/// terminal retention boundary. This is intentionally composable: consensus
/// first selects the single cross-profile oldest prefix, then chains each
/// selected row's witness transition in that order.
#[cfg(test)]
pub(crate) fn prepare_production_v2_reclaim(
    current: &ProductionReservationRecordV2,
    maintenance_time: ConsensusMaintenanceTimestamp,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionV2Reclaim, ReservationError> {
    current.validate(profile)?;
    if current.state != ProductionReservationStateV2::Retained {
        return Err(ReservationError::InvalidState);
    }
    let terminalized_at = current
        .terminalized_at
        .ok_or(ReservationError::StateShape)?;
    if terminalized_at.checked_add_retention()? > maintenance_time {
        return Err(ReservationError::NotEligible);
    }
    witness.admits(budget)?;
    let mut replacement = current.clone();
    replacement.reclaim_at(maintenance_time, profile)?;
    let counters = counters_without_production_record_v2(witness.roster, current, profile)?;
    let next = witness.with_roster(counters_with_production_record_v2(
        counters,
        &replacement,
        profile,
    )?);
    next.admits(budget)?;
    Ok(PreparedProductionV2Reclaim {
        replacement,
        previous: witness,
        next,
    })
}

impl PreparedProductionTerminalizationV2 {
    /// Return the V2 terminal carrier to retain in the dedicated V2 table.
    pub(crate) const fn replacement(&self) -> &ProductionReservationRecordV2 {
        &self.replacement
    }

    /// Return the exact absent-row action that must share Q2 with the
    /// replacement and removal of the V2 reservation row.
    pub(crate) const fn business_cas(&self) -> &ProductionTerminalAbsentBusinessCasV2 {
        &self.business_cas
    }
}

impl fmt::Debug for PreparedProductionTerminalizationV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedProductionTerminalizationV2(<redacted>)")
    }
}

const fn max_v2_compact_evidence_bytes() -> usize {
    MAX_PROFILE_V2_COMPACT_TERMINAL_EVIDENCE_BYTES
}

fn validate_v2_provenance_binding(
    binding: RequestBindingKey,
    provenance: &RosterProfileV2CompactAdmissionProvenanceV1,
) -> Result<(), ReservationError> {
    let bytes = binding.to_bytes();
    let input = provenance.input();
    if input.profile != crate::fenced_mutation_roster::Profile::v2()
        || input.scope.as_slice() != &bytes[8..40]
        || input.tenant_scope_partition.as_slice() != &bytes[40..72]
        || input.session_key_commitment.as_slice() != &bytes[72..104]
        || input.roster_id.as_slice() != &bytes[104..120]
    {
        return Err(ReservationError::SnapshotMismatch);
    }
    Ok(())
}

fn validate_v2_terminal_evidence(
    terminal_evidence: &RosterProfileV2CompactTerminalEvidenceV1,
    admission: &Admission,
    admission_ingress: &[u8],
    admission_provenance: &[u8],
    terminal: &crate::fenced_mutation_roster::TerminalRecord,
) -> Result<(), ReservationError> {
    // Q1 and Q2 carry distinct authenticated ingress statements. Durable
    // storage can prove that Q1 provenance still names Q1 ingress, but the
    // fresh Q2 ingress is cryptographically checked by consensus with its
    // command, root, authority, and registration inputs.
    if terminal_evidence
        .provenance()
        .canonical_bytes()
        .map_err(|_| ReservationError::CanonicalEncoding)?
        .as_slice()
        != admission_provenance
    {
        return Err(ReservationError::SnapshotMismatch);
    }
    let admission_ingress = RosterIngressAttestationV2::decode_canonical(admission_ingress)
        .map_err(|_| ReservationError::CanonicalEncoding)?;
    if terminal_evidence.provenance().input().ingress != *admission_ingress.signing_input()
        || terminal_evidence.ingress() == &admission_ingress
    {
        return Err(ReservationError::SnapshotMismatch);
    }
    terminal_evidence
        .evidence()
        .verify_raw_terminal(admission, terminal)
        .map_err(|_| ReservationError::CanonicalEncoding)
}

fn validate_v2_terminal_proof_bundle(
    terminal_proof_bundle: &RosterProfileV2ExecutorProofBundleV1,
    terminal_evidence: &RosterProfileV2CompactTerminalEvidenceV1,
    admission_provenance: &[u8],
) -> Result<(), ReservationError> {
    let admission_provenance =
        RosterProfileV2CompactAdmissionProvenanceV1::decode_canonical(admission_provenance)
            .map_err(|_| ReservationError::CanonicalEncoding)?;
    if terminal_proof_bundle.admission_provenance_commitment()
        != admission_provenance
            .commitment()
            .map_err(|_| ReservationError::CanonicalEncoding)?
        || terminal_proof_bundle.ingress() != terminal_evidence.ingress()
        || terminal_proof_bundle.terminal_evidence() != terminal_evidence
    {
        return Err(ReservationError::SnapshotMismatch);
    }
    Ok(())
}

impl fmt::Debug for ProductionReservationRecordV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionReservationRecordV2(<redacted>)")
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
    compact_provenance_bytes: usize,
) -> Result<ComponentBytes, ReservationError> {
    ComponentBytes::from_exact_with_compact(
        admission.len(),
        terminal.map_or(MAX_COMMITTED_TERMINAL_CODEC_BYTES, <[u8]>::len),
        MAX_BUSINESS_SESSION_COPY_BYTES,
        MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES,
        MAX_TERMINAL_EVIDENCE_ENVELOPE_BYTES,
        compact_provenance_bytes,
        tombstone.map_or(MAX_TOMBSTONE_CODEC_BYTES, <[u8]>::len),
    )
}

/// V2-only charge components.  Its larger compact carrier bound must never
/// relax the frozen V1 `ComponentBytes` validation path.
fn production_components_v2(
    admission: &[u8],
    terminal: Option<&[u8]>,
    tombstone: Option<&[u8]>,
    compact_provenance_bytes: usize,
) -> Result<ComponentBytes, ReservationError> {
    ComponentBytes::from_exact_with_compact(
        admission.len(),
        terminal.map_or(MAX_COMMITTED_TERMINAL_CODEC_BYTES, <[u8]>::len),
        MAX_BUSINESS_SESSION_COPY_BYTES,
        MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES,
        MAX_TERMINAL_EVIDENCE_ENVELOPE_BYTES,
        compact_provenance_bytes,
        tombstone.map_or(MAX_TOMBSTONE_CODEC_BYTES, <[u8]>::len),
    )
}

/// Pure, prevalidated deterministic retained-to-tombstone batch.
///
/// The adapter compares every `rows` entry before it replaces any row. This
/// makes a malformed or stale later row fail the entire reclaim batch.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct PreparedProductionReclaim {
    transaction: PreparedProductionTransaction,
}

#[cfg(test)]
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
    #[cfg(test)]
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

#[cfg(test)]
impl fmt::Debug for PreparedProductionReclaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedProductionReclaim(<redacted>)")
    }
}

/// Prepare, but do not mutate, the oldest eligible retained rows.
///
/// Terminal time is authenticated by the retained `CommittedTerminal` frame;
/// the maintenance value merely chooses which already committed rows have
/// reached the fixed 24-hour age. Ordering is `(terminalized_at, binding)` and
/// the exact batch is the oldest `min(1024, eligible)`, including a smaller
/// final batch. A live or ambiguous row is never selected.
#[cfg(test)]
pub(crate) fn prepare_production_reclaim(
    records: &BTreeMap<RequestBindingKey, ProductionReservationRecord>,
    maintenance_time: ConsensusMaintenanceTimestamp,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionReclaim, ReservationError> {
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
            expected_canonical: None,
            replacement: Some(replacement),
            replacement_canonical: None,
        });
    }
    let next = witness.with_roster(next_counters);
    next.admits(budget)?;
    Ok(PreparedProductionReclaim {
        transaction: PreparedProductionTransaction {
            #[cfg(test)]
            canonical_rows_validated: u32::try_from(selected)
                .map_err(|_| ReservationError::Arithmetic)?,
            rows,
            previous: witness,
            next,
            floor: None,
            retirement_cursor: None,
            released_floors: Vec::new(),
            released_retirement_cursors: Vec::new(),
            partition_guard: None,
            global_terminal_retirement_guard: None,
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
#[cfg(test)]
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
    // Terminal commit sequences are a global total order.  Reconstructing
    // this uniqueness only at snapshot/restart boundaries keeps Q1/Q2 on
    // their fixed single-row paths while making a forged/duplicated closure
    // fail closed before it can influence retirement.
    let mut seen_terminal_sequences = BTreeMap::new();
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
        if let Some(sequence) = record.terminal_sequence {
            if seen_terminal_sequences
                .insert(sequence, record.binding)
                .is_some()
            {
                return Err(ReservationError::Duplicate);
            }
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
            ReservationState::Live => profile.charge(production_components(
                &record.admission,
                None,
                None,
                if record.admission_provenance.is_empty() {
                    0
                } else {
                    MAX_COMPACT_PROVENANCE_BYTES
                },
            )?)?,
            ReservationState::Retained => profile.charge(production_components(
                &record.admission,
                record.terminal.as_deref(),
                None,
                record
                    .admission_provenance
                    .len()
                    .checked_add(record.terminal_evidence.as_ref().map_or(0, Vec::len))
                    .ok_or(ReservationError::Arithmetic)?,
            )?)?,
            ReservationState::Tombstone => profile.charge(production_components(
                &[],
                None,
                record.tombstone.as_deref(),
                record
                    .admission_provenance
                    .len()
                    .checked_add(record.terminal_evidence.as_ref().map_or(0, Vec::len))
                    .ok_or(ReservationError::Arithmetic)?,
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

/// Reconstruct the one global V1+V2 capacity projection for focused snapshot
/// conformance tests.  Production recovery uses
/// [`ProductionSnapshotStreamValidator`] so it can merge the two SQL tables
/// without materializing a second ledger-sized collection.
#[cfg(test)]
pub(crate) fn validate_production_snapshot_combined(
    records: &[ProductionReservationRecord],
    records_v2: &[ProductionReservationRecordV2],
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    let mut counters = validate_production_snapshot(records, profile)?;
    let mut bindings = BTreeMap::new();
    let mut live_business = BTreeMap::new();
    for record in records {
        bindings.insert(record.binding(), ());
        if let Some(reservation) = record.business_reservation() {
            live_business.insert(reservation.expected().key().canonical_digest_input(), ());
        }
    }
    for record in records_v2 {
        record.validate(profile)?;
        if bindings.insert(record.binding(), ()).is_some() {
            return Err(ReservationError::Duplicate);
        }
        if record.state() == ProductionReservationStateV2::Live {
            let reservation = record
                .absence_reservation()
                .ok_or(ReservationError::StateShape)?;
            if live_business
                .insert(reservation.predicate().key().canonical_digest_input(), ())
                .is_some()
            {
                return Err(ReservationError::Duplicate);
            }
        }
        counters = counters_with_production_record_v2(counters, record, profile)?;
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
    if records.iter().any(|record| {
        record
            .terminal_sequence()
            .is_some_and(|sequence| sequence <= witness.retired_terminal_sequence())
    }) {
        return Err(ReservationError::SnapshotMismatch);
    }
    if witness.roster != counters {
        return Err(ReservationError::WitnessMismatch);
    }
    Ok(counters)
}

/// Require a persisted witness to reconstruct exactly from both profile
/// tables.  This is the test counterpart of the production streaming pass.
#[cfg(test)]
pub(crate) fn validate_production_snapshot_combined_witness(
    records: &[ProductionReservationRecord],
    records_v2: &[ProductionReservationRecordV2],
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    let counters = validate_production_snapshot_combined(records, records_v2, profile)?;
    witness.admits(budget)?;
    if witness.roster != counters {
        return Err(ReservationError::WitnessMismatch);
    }
    Ok(counters)
}

/// Incremental restart/snapshot validator for an already SQL-ordered roster
/// namespace. It retains aggregate counters plus only the bounded fixed-width
/// binding and terminal-sequence keys needed to reject aliases across the V1
/// and V2 SQL namespaces. Neither map carries subscriber payload or becomes
/// a parallel durable ledger.
///
/// This is deliberately separate from the slice-based conformance validator
/// below.  The latter remains useful to pure-domain tests which intentionally
/// supply unordered, duplicate fixtures; durable recovery must never turn a
/// legal 131,072-row ledger into a second in-memory copy merely to re-prove
/// those SQLite-enforced keys.
pub(crate) struct ProductionSnapshotStreamValidator {
    application_sequence: u64,
    /// Exact consensus Raft horizon from the database's durable applied
    /// pointer. Unlike the application sequence, this bounds the coordinates
    /// embedded in roster admissions and terminal receipts.
    applied_raft_log_index: Option<u64>,
    counters: AggregateCounters,
    record_count: usize,
    floor_count: usize,
    cursor_count: usize,
    // Row tables are profile-specific, but their durable binding authority is
    // shared. A V1/V2 alias would create two claims on one request binding.
    bindings: BTreeMap<RequestBindingKey, ()>,
    terminal_sequences: BTreeMap<u64, RequestBindingKey>,
}

impl ProductionSnapshotStreamValidator {
    /// Start an empty SQL-stream validation pass.
    pub(crate) const fn new(
        application_sequence: u64,
        applied_raft_log_index: Option<u64>,
    ) -> Self {
        Self {
            application_sequence,
            applied_raft_log_index,
            counters: zero_counters(),
            record_count: 0,
            floor_count: 0,
            cursor_count: 0,
            bindings: BTreeMap::new(),
            terminal_sequences: BTreeMap::new(),
        }
    }

    /// Account for one fully canonicalized durable row, then let the caller
    /// immediately drop its raw and decoded bodies.
    pub(crate) fn add_record(
        &mut self,
        record: &ProductionReservationRecord,
        terminal_raft_log_index: Option<u64>,
        witness: GlobalChargeWitness,
        profile: ChargeProfile,
    ) -> Result<(), ReservationError> {
        record.validate(profile)?;
        let applied_raft_log_index = self
            .applied_raft_log_index
            .filter(|index| *index != 0)
            .ok_or(ReservationError::SnapshotMismatch)?;
        let admission_raft_log_index = record.binding().history_epoch();
        if admission_raft_log_index == 0 || admission_raft_log_index > applied_raft_log_index {
            return Err(ReservationError::SnapshotMismatch);
        }
        match record.state() {
            ReservationState::Live if terminal_raft_log_index.is_none() => {}
            ReservationState::Retained | ReservationState::Tombstone => {
                let terminal_raft_log_index = terminal_raft_log_index
                    .filter(|index| *index != 0)
                    .ok_or(ReservationError::SnapshotMismatch)?;
                if terminal_raft_log_index <= admission_raft_log_index
                    || terminal_raft_log_index > applied_raft_log_index
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
            }
            ReservationState::Live => return Err(ReservationError::SnapshotMismatch),
        }
        if record
            .terminal_sequence()
            .is_some_and(|sequence| sequence <= witness.retired_terminal_sequence())
        {
            return Err(ReservationError::SnapshotMismatch);
        }
        if record
            .terminal_sequence()
            .is_some_and(|sequence| sequence > self.application_sequence)
        {
            return Err(ReservationError::SnapshotMismatch);
        }
        if self.bindings.insert(record.binding(), ()).is_some() {
            return Err(ReservationError::Duplicate);
        }
        if let Some(sequence) = record.terminal_sequence() {
            if self
                .terminal_sequences
                .insert(sequence, record.binding())
                .is_some()
            {
                return Err(ReservationError::Duplicate);
            }
        }
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(ReservationError::Arithmetic)?;
        if self.record_count > MAX_RESERVED_AND_RETAINED {
            return Err(ReservationError::DurableBindingLimit);
        }
        self.counters = counters_with_production_record(self.counters, record, profile)?;
        Ok(())
    }

    /// Account for one canonical V2 carrier in the same deployment-wide
    /// witness pass as V1 rows. Profile-specific row identities remain
    /// disjoint, while terminal sequences and capacity share one witness.
    pub(crate) fn add_v2_record(
        &mut self,
        record: &ProductionReservationRecordV2,
        terminal_raft_log_index: Option<u64>,
        witness: GlobalChargeWitness,
        profile: ChargeProfile,
    ) -> Result<(), ReservationError> {
        record.validate(profile)?;
        let applied_raft_log_index = self
            .applied_raft_log_index
            .filter(|index| *index != 0)
            .ok_or(ReservationError::SnapshotMismatch)?;
        let admission_raft_log_index = record.binding().history_epoch();
        if admission_raft_log_index == 0 || admission_raft_log_index > applied_raft_log_index {
            return Err(ReservationError::SnapshotMismatch);
        }
        match record.state() {
            ProductionReservationStateV2::Live if terminal_raft_log_index.is_none() => {}
            ProductionReservationStateV2::Retained => {
                let terminal_raft_log_index = terminal_raft_log_index
                    .filter(|index| *index != 0)
                    .ok_or(ReservationError::SnapshotMismatch)?;
                if terminal_raft_log_index <= admission_raft_log_index
                    || terminal_raft_log_index > applied_raft_log_index
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
            }
            ProductionReservationStateV2::Tombstone => {
                let terminal_raft_log_index = terminal_raft_log_index
                    .filter(|index| *index != 0)
                    .ok_or(ReservationError::SnapshotMismatch)?;
                if terminal_raft_log_index <= admission_raft_log_index
                    || terminal_raft_log_index > applied_raft_log_index
                {
                    return Err(ReservationError::SnapshotMismatch);
                }
            }
            ProductionReservationStateV2::Live => return Err(ReservationError::SnapshotMismatch),
        }
        if record
            .terminal_sequence()
            .is_some_and(|sequence| sequence <= witness.retired_terminal_sequence())
        {
            return Err(ReservationError::SnapshotMismatch);
        }
        if record
            .terminal_sequence()
            .is_some_and(|sequence| sequence > self.application_sequence)
        {
            return Err(ReservationError::SnapshotMismatch);
        }
        if self.bindings.insert(record.binding(), ()).is_some() {
            return Err(ReservationError::Duplicate);
        }
        if let Some(sequence) = record.terminal_sequence() {
            if self
                .terminal_sequences
                .insert(sequence, record.binding())
                .is_some()
            {
                return Err(ReservationError::Duplicate);
            }
        }
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(ReservationError::Arithmetic)?;
        if self.record_count > MAX_RESERVED_AND_RETAINED {
            return Err(ReservationError::DurableBindingLimit);
        }
        self.counters = counters_with_production_record_v2(self.counters, record, profile)?;
        Ok(())
    }

    /// Account for one normalized floor after its SQL key projection has been
    /// checked by the caller.
    pub(crate) fn add_floor(
        &mut self,
        floor: IrreversibleHistoryFloor,
    ) -> Result<(), ReservationError> {
        self.floor_count = self
            .floor_count
            .checked_add(1)
            .ok_or(ReservationError::Arithmetic)?;
        if self.floor_count > MAX_RESERVED_AND_RETAINED {
            return Err(ReservationError::FloorLimit);
        }
        self.counters = counters_with_production_floor(self.counters, floor)?;
        Ok(())
    }

    /// Account for one normalized cursor after its matching floor has been
    /// checked by the caller.
    pub(crate) fn add_cursor(
        &mut self,
        cursor: &ProductionRetirementCursor,
    ) -> Result<(), ReservationError> {
        self.cursor_count = self
            .cursor_count
            .checked_add(1)
            .ok_or(ReservationError::Arithmetic)?;
        if self.cursor_count > MAX_RESERVED_AND_RETAINED {
            return Err(ReservationError::FloorLimit);
        }
        self.counters = counters_with_retirement_cursor(self.counters, cursor)?;
        Ok(())
    }

    /// Complete the aggregate witness proof after every SQL stream reaches
    /// EOF.  Empty namespaces are intentionally represented by no witness.
    pub(crate) fn finish(
        self,
        witness: Option<GlobalChargeWitness>,
        budget: GlobalChargeBudget,
    ) -> Result<(), ReservationError> {
        match witness {
            None if self.record_count == 0 && self.floor_count == 0 && self.cursor_count == 0 => {
                Ok(())
            }
            None => Err(ReservationError::SnapshotMismatch),
            Some(witness) => {
                if witness.retired_terminal_sequence() > self.application_sequence {
                    return Err(ReservationError::SnapshotMismatch);
                }
                witness.admits(budget)?;
                if witness.roster != self.counters {
                    return Err(ReservationError::WitnessMismatch);
                }
                Ok(())
            }
        }
    }
}

/// Restart/follower validation with the exact persisted tenant/scope floors.
///
/// Every durable row must remain strictly above its partition floor. Direct
/// reclaim deletes the globally oldest eligible retained rows at or beyond
/// 24 hours, up to 1,024 per final-or-partial batch, and never deletes live
/// rows. Legacy cursor/tombstone snapshots remain subject to their original
/// floor consistency checks during restart validation.
#[cfg(test)]
pub(crate) fn validate_production_snapshot_with_floors(
    records: &[ProductionReservationRecord],
    floors: &[IrreversibleHistoryFloor],
    retirement_cursors: &[ProductionRetirementCursor],
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    let mut counters = validate_production_snapshot(records, profile)?;
    witness.admits(budget)?;
    if records.iter().any(|record| {
        record
            .terminal_sequence()
            .is_some_and(|sequence| sequence <= witness.retired_terminal_sequence())
    }) {
        return Err(ReservationError::SnapshotMismatch);
    }
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
        // A nonzero floor is meaningful after an older snapshot's legacy
        // cursor/tombstone cleanup. A zero initial floor without a row is an
        // unused, accidentally persisted partition.
        if !used_floors.contains_key(&key) && floor.retired_through() == 0 {
            return Err(ReservationError::FloorAdvance);
        }
    }
    for key in cursor_index.keys() {
        if !used_cursors.contains_key(key) {
            return Err(ReservationError::FloorAdvance);
        }
    }
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
    /// Exact durable expected bytes when a caller consumed a validated SQLite
    /// hydration. Adapters may use this instead of recanonicalizing the row.
    expected_canonical: Option<Vec<u8>>,
    replacement: Option<ProductionReservationRecord>,
    /// Exact validated replacement bytes prepared once by the hydrated hot
    /// path. Ordinary/maintenance paths leave this absent and retain the
    /// adapter's full validation-and-encoding fallback.
    replacement_canonical: Option<Vec<u8>>,
}

impl ProductionRowCas {
    pub(crate) const fn binding(&self) -> RequestBindingKey {
        self.binding
    }

    pub(crate) fn expected(&self) -> Option<&ProductionReservationRecord> {
        self.expected.as_ref()
    }

    /// Return the sealed exact SQLite CAS witness, when preparation started
    /// from a fully canonical hydrated row.
    pub(crate) fn expected_canonical_bytes(&self) -> Option<&[u8]> {
        self.expected_canonical.as_deref()
    }

    pub(crate) fn replacement(&self) -> Option<&ProductionReservationRecord> {
        self.replacement.as_ref()
    }

    /// Return the exact replacement bytes already validated by preparation.
    pub(crate) fn replacement_canonical_bytes(&self) -> Option<&[u8]> {
        self.replacement_canonical.as_deref()
    }
}

/// Exact cross-table vacancy proof for one requested roster binding.
///
/// V1 and V2 retain physically distinct rows, but neither may independently
/// admit a binding: both tables must have been queried under the same
/// consensus transaction before Q1 creates either row. The guard carries no
/// row body, only the exact opaque key whose absence the adapter proved.
#[derive(Clone, Copy)]
pub(crate) struct ProductionBindingVacancyGuard {
    binding: RequestBindingKey,
}

impl ProductionBindingVacancyGuard {
    /// Construct a guard from the two exact lookups performed by the
    /// committing adapter. A present row is never converted into an absence
    /// assertion, including when it belongs to the other profile table.
    pub(crate) fn from_lookups(
        binding: RequestBindingKey,
        v1: Option<&ProductionReservationRecord>,
        v2: Option<&ProductionReservationRecordV2>,
    ) -> Result<Self, ReservationError> {
        if let Some(record) = v1 {
            if record.binding() != binding {
                return Err(ReservationError::SnapshotMismatch);
            }
            return Err(ReservationError::Duplicate);
        }
        if let Some(record) = v2 {
            if record.binding() != binding {
                return Err(ReservationError::SnapshotMismatch);
            }
            return Err(ReservationError::Duplicate);
        }
        Ok(Self { binding })
    }

    fn validate_for(&self, binding: RequestBindingKey) -> Result<(), ReservationError> {
        if self.binding == binding {
            Ok(())
        } else {
            Err(ReservationError::SnapshotMismatch)
        }
    }
}

impl fmt::Debug for ProductionBindingVacancyGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionBindingVacancyGuard(<redacted>)")
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

    pub(crate) fn from_binding(binding: RequestBindingKey) -> Result<Self, ReservationError> {
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
/// initial floor. A present expected floor is compared byte-for-byte before it
/// is advanced, or deleted once the final bounded retirement page proves the
/// partition is empty. The partition key is carried separately so an adapter
/// never searches for a matching retired epoch value.
#[derive(Clone, Copy)]
pub(crate) struct ProductionFloorCas {
    key: ProductionFloorKey,
    expected: Option<IrreversibleHistoryFloor>,
    replacement: Option<IrreversibleHistoryFloor>,
}

impl ProductionFloorCas {
    pub(crate) const fn key(&self) -> ProductionFloorKey {
        self.key
    }

    pub(crate) const fn expected(&self) -> Option<IrreversibleHistoryFloor> {
        self.expected
    }

    pub(crate) const fn replacement(&self) -> Option<IrreversibleHistoryFloor> {
        self.replacement
    }
}

impl fmt::Debug for ProductionFloorCas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionFloorCas(<redacted>)")
    }
}

/// Bounded page from one authoritative partition's next retireable epoch.
///
/// This is retained only for the legacy unit fixtures. Production maintenance
/// uses the global terminal-sequence closure below.
#[cfg(test)]
pub(crate) struct ProductionRetirementPrefix<'a> {
    key: ProductionFloorKey,
    target_epoch: u64,
    selected: &'a [(RequestBindingKey, ProductionReservationRecord)],
    final_batch: bool,
    partition_empty_after: bool,
}

#[cfg(test)]
impl<'a> ProductionRetirementPrefix<'a> {
    pub(crate) fn new(
        previous_floor: IrreversibleHistoryFloor,
        next_floor: IrreversibleHistoryFloor,
        selected: &'a [(RequestBindingKey, ProductionReservationRecord)],
        final_batch: bool,
        partition_empty_after: bool,
    ) -> Result<Self, ReservationError> {
        let key = ProductionFloorKey::from_floor(previous_floor)?;
        if key != ProductionFloorKey::from_floor(next_floor)?
            || next_floor.retired_through() <= previous_floor.retired_through()
            || selected.is_empty()
            || selected.len() > RECLAIM_BATCH
            || (partition_empty_after && !final_batch)
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
            partition_empty_after,
        })
    }
}

#[cfg(test)]
impl fmt::Debug for ProductionRetirementPrefix<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionRetirementPrefix(<redacted>)")
    }
}

/// Exact indexed-range predicate that the storage adapter re-proves in its
/// committing transaction before deleting a bounded tombstone prefix.
#[derive(Clone)]
pub(crate) struct ProductionPartitionRangeGuard {
    key: ProductionFloorKey,
    previous_floor_through: u64,
    target_epoch: u64,
    after: Option<RequestBindingKey>,
    selected: Vec<RequestBindingKey>,
    final_batch: bool,
    partition_empty_after: bool,
}

impl ProductionPartitionRangeGuard {
    #[cfg(test)]
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
        Ok(Self {
            key: prefix.key,
            previous_floor_through: previous_floor.retired_through(),
            target_epoch: prefix.target_epoch,
            after: cursor.last_deleted,
            selected: prefix
                .selected
                .iter()
                .map(|(binding, _)| *binding)
                .collect(),
            final_batch: prefix.final_batch,
            partition_empty_after: prefix.partition_empty_after,
        })
    }

    pub(crate) const fn key(&self) -> ProductionFloorKey {
        self.key
    }
    pub(crate) const fn previous_floor_through(&self) -> u64 {
        self.previous_floor_through
    }
    pub(crate) const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }
    pub(crate) const fn after(&self) -> Option<RequestBindingKey> {
        self.after
    }
    pub(crate) fn selected(&self) -> &[RequestBindingKey] {
        &self.selected
    }
    pub(crate) const fn final_batch(&self) -> bool {
        self.final_batch
    }
    pub(crate) const fn partition_empty_after(&self) -> bool {
        self.partition_empty_after
    }
}

impl fmt::Debug for ProductionPartitionRangeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionPartitionRangeGuard(<redacted>)")
    }
}

/// Exact globally ordered terminal-history prefix that may be removed in one
/// maintenance transaction.  The adapter re-proves it against the indexed
/// `(terminal_sequence, binding)` projection before any deletion.  This is
/// the trust anchor for the witness high-water: a live row has no sequence,
/// so it cannot block unrelated terminal-history closure.
#[derive(Clone)]
pub(crate) struct ProductionGlobalTerminalRetirementGuard {
    selected: Vec<(u64, RequestBindingKey)>,
    released_partitions: Vec<ProductionFloorKey>,
}

impl ProductionGlobalTerminalRetirementGuard {
    pub(crate) fn selected(&self) -> &[(u64, RequestBindingKey)] {
        &self.selected
    }

    pub(crate) fn released_partitions(&self) -> &[ProductionFloorKey] {
        &self.released_partitions
    }
}

impl fmt::Debug for ProductionGlobalTerminalRetirementGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionGlobalTerminalRetirementGuard(<redacted>)")
    }
}

/// Durable in-epoch retirement marker. It closes admissions through a partly
/// deleted target epoch until its final bounded tombstone prefix advances the floor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProductionRetirementCursor {
    key: ProductionFloorKey,
    target_epoch: u64,
    last_deleted: Option<RequestBindingKey>,
}

impl ProductionRetirementCursor {
    #[cfg(test)]
    fn initial(key: ProductionFloorKey, target_epoch: u64) -> Result<Self, ReservationError> {
        validate_epoch(target_epoch)?;
        Ok(Self {
            key,
            target_epoch,
            last_deleted: None,
        })
    }

    #[cfg(test)]
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

/// Exact durable cursor compare-and-swap carried by an admission transaction.
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

    /// Return the exact prior cursor, or absence assertion.
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

    /// Materialize and validate the sole V2 generation-one successor before
    /// admission is allowed to cross the provider-effect boundary.
    fn created(admission: &Admission) -> Result<Self, ReservationError> {
        if admission.profile() != crate::fenced_mutation_roster::Profile::v2()
            || !admission
                .established_mutation()
                .requires_absent_predecessor()
            || admission.expected_generation() != crate::model::Generation::new(1)
        {
            return Err(ReservationError::BusinessCas);
        }
        Self::updated(admission, crate::model::Generation::new(1), [0; 32])
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
        if admission.profile() != crate::fenced_mutation_roster::Profile::v1()
            || !admission
                .established_mutation()
                .requires_present_predecessor()
            || expected.key != *admission.key()
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
        if admission.profile() != crate::fenced_mutation_roster::Profile::v1()
            || !admission
                .established_mutation()
                .requires_present_predecessor()
            || self.admission_commitment != admission.body_commitment()
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

    fn from_committed(
        admission: &Admission,
        terminal: &CommittedTerminal,
        reservation: &ProductionAdmissionBusinessReservation,
    ) -> Result<Self, ReservationError> {
        reservation.validate_for(admission)?;
        let expected = reservation.expected.clone();
        match terminal.materialization() {
            TerminalMaterialization::Aborted => Ok(Self::AbortedCompareRelease { expected }),
            TerminalMaterialization::Established(EstablishedMaterialization::Created {
                ..
            }) => Err(ReservationError::BusinessCas),
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

#[cfg(test)]
const MAX_ABSENT_BUSINESS_RESERVATION_V2_CODEC_BYTES: usize =
    MAX_BUSINESS_SESSION_COPY_BYTES + 1024;
#[cfg(test)]
const ABSENT_BUSINESS_RESERVATION_V2_MAGIC: [u8; 8] = *b"OPCABR2\0";
#[cfg(test)]
const ABSENT_BUSINESS_RESERVATION_V2_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/absent-business-reservation/v2\0";

/// Exact V2 predicate that proves the authoritative business row was absent
/// at admission.
///
/// A V2 create never carries a fake business record or a caller-chosen
/// generation. The only generation represented by this type is the fixed
/// first generation, returned by [`Self::generation`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProductionAbsentBusinessPredicateV2 {
    key: crate::model::SessionKey,
    admission_commitment: [u8; 32],
}

impl ProductionAbsentBusinessPredicateV2 {
    fn for_admission(admission: &Admission) -> Result<Self, ReservationError> {
        if admission.profile() != crate::fenced_mutation_roster::Profile::v2()
            || !admission
                .established_mutation()
                .requires_absent_predecessor()
            || admission.expected_generation() != crate::model::Generation::new(1)
        {
            return Err(ReservationError::BusinessCas);
        }
        Ok(Self {
            key: admission.key().clone(),
            admission_commitment: admission.body_commitment(),
        })
    }

    fn validate_for(&self, admission: &Admission) -> Result<(), ReservationError> {
        if self.key != *admission.key() || self.admission_commitment != admission.body_commitment()
        {
            return Err(ReservationError::BusinessCas);
        }
        Self::for_admission(admission).map(|_| ())
    }

    /// Return the exact session key whose authoritative row must be absent.
    pub(crate) fn key(&self) -> &crate::model::SessionKey {
        &self.key
    }

    /// Return the only generation an absent-predecessor V2 create may write.
    pub(crate) const fn generation(&self) -> crate::model::Generation {
        crate::model::Generation::new(1)
    }

    #[cfg(test)]
    fn validate_shape(&self) -> Result<(), ReservationError> {
        if self.admission_commitment == [0; 32] {
            return Err(ReservationError::CanonicalEncoding);
        }
        Ok(())
    }

    #[cfg(test)]
    const fn admission_commitment(&self) -> [u8; 32] {
        self.admission_commitment
    }
}

impl fmt::Debug for ProductionAbsentBusinessPredicateV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionAbsentBusinessPredicateV2(<redacted>)")
    }
}

/// Exact V2 admission reservation for an absent authoritative row.
///
/// SQLite persists this in its dedicated V2 reservation table. The binding is
/// part of the durable predicate, so replay and conflict handling remain tied
/// to the exact tenant/scope/fence-authenticated admission rather than merely
/// to a session key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProductionAdmissionAbsentBusinessReservationV2 {
    predicate: ProductionAbsentBusinessPredicateV2,
    binding: RequestBindingKey,
    /// Exact canonical generation-one successor validated before any provider
    /// effect.  Retaining this alongside the absence predicate prevents Q2
    /// from constructing a different record from caller-controlled bytes.
    successor: ProductionBusinessState,
}

impl ProductionAdmissionAbsentBusinessReservationV2 {
    /// Reserve exact absence for the supplied authenticated V2 admission and
    /// its one issued roster binding.
    pub(crate) fn new(
        admission: &Admission,
        binding: RequestBindingKey,
    ) -> Result<Self, ReservationError> {
        let predicate = ProductionAbsentBusinessPredicateV2::for_admission(admission)?;
        let expected_binding = admission
            .binding_key(binding.history_epoch())
            .map_err(|_| ReservationError::BusinessCas)?;
        if binding != expected_binding {
            return Err(ReservationError::BusinessCas);
        }
        let successor = ProductionBusinessState::created(admission)?;
        Ok(Self {
            predicate,
            binding,
            successor,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReservationError> {
        let value: Self = decode_frame(
            bytes,
            ABSENT_BUSINESS_RESERVATION_V2_MAGIC,
            ABSENT_BUSINESS_RESERVATION_V2_DOMAIN,
            MAX_ABSENT_BUSINESS_RESERVATION_V2_CODEC_BYTES,
        )
        .map_err(|_| ReservationError::CanonicalEncoding)?;
        value.predicate.validate_shape()?;
        if value.to_canonical_bytes()?.as_slice() != bytes {
            return Err(ReservationError::CanonicalEncoding);
        }
        Ok(value)
    }

    #[cfg(test)]
    pub(crate) fn to_canonical_bytes(&self) -> Result<Vec<u8>, ReservationError> {
        self.predicate.validate_shape()?;
        encode_frame(
            ABSENT_BUSINESS_RESERVATION_V2_MAGIC,
            ABSENT_BUSINESS_RESERVATION_V2_DOMAIN,
            self,
            MAX_ABSENT_BUSINESS_RESERVATION_V2_CODEC_BYTES,
        )
        .map_err(|_| ReservationError::CanonicalEncoding)
    }

    /// Re-prove every exact V2 admission and binding fact before Q2.
    pub(crate) fn validate_for(
        &self,
        admission: &Admission,
        binding: RequestBindingKey,
    ) -> Result<(), ReservationError> {
        self.predicate.validate_for(admission)?;
        if self.binding != binding {
            return Err(ReservationError::BusinessCas);
        }
        let expected = Self::new(admission, binding)?;
        if self.successor != expected.successor {
            return Err(ReservationError::BusinessCas);
        }
        Ok(())
    }

    /// Return the exact absence predicate that Q1 and Q2 must compare.
    pub(crate) fn predicate(&self) -> &ProductionAbsentBusinessPredicateV2 {
        &self.predicate
    }

    /// Return the exact durable roster binding that owns this reservation.
    pub(crate) const fn binding(&self) -> RequestBindingKey {
        self.binding
    }

    #[cfg(test)]
    pub(crate) const fn admission_commitment(&self) -> [u8; 32] {
        self.predicate.admission_commitment()
    }

    /// Return the exact canonical successor committed by Q1.
    pub(crate) const fn successor(&self) -> &ProductionBusinessState {
        &self.successor
    }
}

impl fmt::Debug for ProductionAdmissionAbsentBusinessReservationV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionAdmissionAbsentBusinessReservationV2(<redacted>)")
    }
}

/// Exact V2 absent-row transition coupled only to Q2 terminalization.
#[derive(Clone)]
pub(crate) enum ProductionTerminalAbsentBusinessCasV2 {
    /// Re-prove absence and release the V2 reservation without materializing
    /// any authoritative session row.
    AbortedCompareAbsentRelease {
        reservation: ProductionAdmissionAbsentBusinessReservationV2,
    },
    /// Re-prove absence, insert the exact generation-one successor, and
    /// release the V2 reservation atomically.
    EstablishedCreate {
        reservation: ProductionAdmissionAbsentBusinessReservationV2,
        successor: ProductionBusinessState,
    },
}

/// Borrowed V2 terminal action for dedicated SQLite V2-table dispatch.
pub(crate) enum ProductionTerminalAbsentBusinessActionV2<'a> {
    /// Re-prove exact absence and remove only the V2 reservation.
    AbortedCompareAbsentRelease {
        reservation: &'a ProductionAdmissionAbsentBusinessReservationV2,
    },
    /// Re-prove exact absence, INSERT the successor, and remove the V2
    /// reservation in the same consensus mutation.
    EstablishedCreate {
        reservation: &'a ProductionAdmissionAbsentBusinessReservationV2,
        successor: &'a ProductionBusinessState,
    },
}

impl<'a> ProductionTerminalAbsentBusinessActionV2<'a> {
    /// Return the exact V2 absence predicate to compare before Q2 applies.
    pub(crate) fn predicate(&self) -> &'a ProductionAbsentBusinessPredicateV2 {
        match self {
            Self::AbortedCompareAbsentRelease { reservation }
            | Self::EstablishedCreate { reservation, .. } => reservation.predicate(),
        }
    }

    /// Return the exact V2 reservation that Q2 must remove atomically.
    pub(crate) fn reservation(&self) -> &'a ProductionAdmissionAbsentBusinessReservationV2 {
        match self {
            Self::AbortedCompareAbsentRelease { reservation }
            | Self::EstablishedCreate { reservation, .. } => reservation,
        }
    }
}

impl ProductionTerminalAbsentBusinessCasV2 {
    /// Return the exact typed Q2 operation for SQLite consensus dispatch.
    pub(crate) const fn action(&self) -> ProductionTerminalAbsentBusinessActionV2<'_> {
        match self {
            Self::AbortedCompareAbsentRelease { reservation } => {
                ProductionTerminalAbsentBusinessActionV2::AbortedCompareAbsentRelease {
                    reservation,
                }
            }
            Self::EstablishedCreate {
                reservation,
                successor,
            } => ProductionTerminalAbsentBusinessActionV2::EstablishedCreate {
                reservation,
                successor,
            },
        }
    }

    /// Build the sole V2 Q2 transition from an authenticated terminal. No
    /// other materialization can consume an absent-predecessor reservation.
    pub(crate) fn from_committed(
        admission: &Admission,
        binding: RequestBindingKey,
        terminal: &CommittedTerminal,
        reservation: &ProductionAdmissionAbsentBusinessReservationV2,
    ) -> Result<Self, ReservationError> {
        reservation.validate_for(admission, binding)?;
        match terminal.materialization() {
            TerminalMaterialization::Aborted => Ok(Self::AbortedCompareAbsentRelease {
                reservation: reservation.clone(),
            }),
            TerminalMaterialization::Established(EstablishedMaterialization::Created {
                generation,
                record_commitment: _,
            }) if *generation == reservation.predicate().generation() => {
                Ok(Self::EstablishedCreate {
                    reservation: reservation.clone(),
                    successor: reservation.successor().clone(),
                })
            }
            _ => Err(ReservationError::BusinessCas),
        }
    }
}

impl fmt::Debug for ProductionTerminalAbsentBusinessCasV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProductionTerminalAbsentBusinessCasV2(<redacted>)")
    }
}

/// Complete prepared durable mutation.
///
/// A consensus storage adapter must compare all rows, the global witness, and
/// optional exact tenant/scope floor/cursor, then apply every replacement and
/// the next witness together. The type intentionally offers no witness-only
/// operation, so a terminal receipt or reclaim cannot release or reserve
/// charge separately from its durable rows.
#[derive(Clone)]
pub(crate) struct PreparedProductionTransaction {
    rows: Vec<ProductionRowCas>,
    previous: GlobalChargeWitness,
    next: GlobalChargeWitness,
    floor: Option<ProductionFloorCas>,
    retirement_cursor: Option<ProductionRetirementCursorCas>,
    released_floors: Vec<ProductionFloorCas>,
    released_retirement_cursors: Vec<ProductionRetirementCursorCas>,
    partition_guard: Option<ProductionPartitionRangeGuard>,
    global_terminal_retirement_guard: Option<ProductionGlobalTerminalRetirementGuard>,
    reclaim_oldest_guard: Option<ProductionReclaimOldestGuard>,
    admission_business_reservation: Option<ProductionAdmissionBusinessReservation>,
    business: Option<ProductionTerminalBusinessCas>,
    #[cfg(test)]
    canonical_rows_validated: u32,
}

/// Consensus adapter contract for one all-or-none prepared roster mutation.
pub(crate) trait ProductionReservationTransactionAdapter {
    /// Compare the exact expected rows, business reservation/CAS, witness,
    /// optional floor/cursor, and the bounded reclaim guard, then atomically persist
    /// all replacements and the next witness. For a reclaim-oldest guard, the
    /// adapter must use its retained-terminal index to prove the carried rows
    /// equal the global `min(1024, eligible)` prefix. An admission reservation
    /// is a compare-only business barrier; a terminal CAS is the sole
    /// business-row materialization.
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
    #[cfg(test)]
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

    /// Return the exact admission cursor assertion, when present.
    pub(crate) fn retirement_cursor_cas(&self) -> Option<&ProductionRetirementCursorCas> {
        self.retirement_cursor.as_ref()
    }

    /// Return fixed per-partition metadata releases coupled to an indexed
    /// global terminal-history deletion prefix.
    pub(crate) fn released_floor_cas(&self) -> &[ProductionFloorCas] {
        &self.released_floors
    }

    pub(crate) fn released_retirement_cursor_cas(&self) -> &[ProductionRetirementCursorCas] {
        &self.released_retirement_cursors
    }

    pub(crate) fn partition_range_guard(&self) -> Option<&ProductionPartitionRangeGuard> {
        self.partition_guard.as_ref()
    }

    /// Return the adapter-enforced global-oldest reclaim predicate, when this
    /// transaction converts retained rows into durable tombstones.
    pub(crate) fn reclaim_oldest_guard(&self) -> Option<&ProductionReclaimOldestGuard> {
        self.reclaim_oldest_guard.as_ref()
    }

    pub(crate) fn global_terminal_retirement_guard(
        &self,
    ) -> Option<&ProductionGlobalTerminalRetirementGuard> {
        self.global_terminal_retirement_guard.as_ref()
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
    #[cfg(test)]
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
#[cfg(test)]
pub(crate) type PreparedProductionRetirement = PreparedProductionTransaction;

/// Inputs consumed when preparing an admission's one-row production transition.
pub(crate) struct ProductionAdmissionPreparation<'a> {
    pub(crate) vacancy: &'a ProductionBindingVacancyGuard,
    pub(crate) existing: Option<&'a ProductionReservationRecord>,
    pub(crate) record: ProductionReservationRecord,
    pub(crate) existing_floor: Option<IrreversibleHistoryFloor>,
    pub(crate) existing_retirement_cursor: Option<&'a ProductionRetirementCursor>,
    pub(crate) witness: GlobalChargeWitness,
    pub(crate) budget: GlobalChargeBudget,
    pub(crate) profile: ChargeProfile,
}

/// Prepare one atomic consensus admission plus its capacity reservation and
/// witness transition. The terminal-history slot is charged here, before any
/// provider effect, so a valid live admission cannot fail terminalization for
/// retained-history capacity.
pub(crate) fn prepare_production_admission(
    preparation: ProductionAdmissionPreparation<'_>,
) -> Result<PreparedProductionChargeTransition, ReservationError> {
    let ProductionAdmissionPreparation {
        vacancy,
        existing,
        record,
        existing_floor,
        existing_retirement_cursor,
        witness,
        budget,
        profile,
    } = preparation;
    vacancy.validate_for(record.binding)?;
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
                replacement: Some(existing_floor),
            }
        }
        None => ProductionFloorCas {
            key: ProductionFloorKey::from_binding(record.binding)?,
            expected: None,
            replacement: Some(initial_floor),
        },
    };
    if let Some(cursor) = existing_retirement_cursor {
        cursor.validate_for_floor(floor.replacement.ok_or(ReservationError::FloorAdvance)?)?;
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
        expected_canonical: None,
        binding,
        replacement: record,
        replacement_canonical: None,
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

/// Prepare a production terminal transition from one fully authenticated
/// SQLite hydration. The consumed hydration retains both the exact prior row
/// bytes for the compare-and-swap and its already-decoded live admission, so
/// this hot path never reparses the protected admission body.
///
/// Proof, ingress, and compact-evidence semantics are exactly those of the
/// ordinary production terminalizer: the raw materials are canonicalized and
/// the compact evidence is bound to the admission and terminal before the
/// retained row is built. Recovery and snapshot paths deliberately retain the
/// ordinary `validate_and_hydrate` validation boundary.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_production_terminalization_hydrated_with_evidence_and_ingress(
    current: HydratedProductionReservationRecord,
    binding: RequestBindingKey,
    terminal: &CommittedTerminal,
    proof_bundle: &RosterExecutorProofBundleV1,
    terminal_ingress: &RosterIngressAttestationV1,
    terminal_evidence: &RosterCompactTerminalEvidenceV2,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
) -> Result<PreparedProductionChargeTransition, ReservationError> {
    let (expected, expected_canonical, admission) =
        into_hydrated_live_terminal_parts(current, binding)?;
    let reservation = expected
        .business_reservation
        .as_ref()
        .ok_or(ReservationError::StateShape)?;
    reservation.validate_for(&admission)?;
    let business =
        ProductionTerminalBusinessCas::from_committed(&admission, terminal, reservation)?;
    let mut replacement = expected.clone();
    replacement.terminalize_with_hydrated_admission(
        &admission,
        terminal,
        Some(proof_bundle),
        Some(terminal_ingress),
        Some(terminal_evidence),
        profile,
    )?;
    // Validate and encode the derived retained row exactly once. The sealed
    // bytes travel with the prepared transaction through SQLite writeback.
    let replacement_canonical = replacement.to_canonical_bytes()?;
    prepare_production_transition_prevalidated(ProductionTransitionPreparation {
        current: Some(expected),
        expected_canonical: Some(expected_canonical),
        binding,
        replacement,
        replacement_canonical: Some(replacement_canonical),
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

/// Consume the sealed read-side hydration and expose only the checked live
/// pieces needed by production terminalization. Keeping this gate separate
/// makes it impossible for the fast path to accidentally accept the
/// test-only rootless `Legacy` payload.
fn into_hydrated_live_terminal_parts(
    current: HydratedProductionReservationRecord,
    binding: RequestBindingKey,
) -> Result<(ProductionReservationRecord, Vec<u8>, Admission), ReservationError> {
    let (expected, expected_canonical, payload) = current.into_parts();
    if expected.binding != binding {
        return Err(ReservationError::Unknown);
    }
    // `HydratedProductionReservationRecord` is sealed and can only be issued
    // after `from_canonical_vec_hydrated` has decoded, fully validated, and
    // byte-for-byte recanonicalized this row. Repeating that multi-megabyte
    // serialization here would discard the proof carried by the type.
    if expected_canonical.is_empty()
        || expected_canonical.len() > MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES
    {
        return Err(ReservationError::CanonicalEncoding);
    }
    let HydratedProductionReservationPayload::Live { admission, .. } = payload else {
        return Err(ReservationError::InvalidState);
    };
    Ok((expected, expected_canonical, admission))
}

/// Test-only legacy terminalization constructor. Production must use the
/// evidence-carrying form above.
#[cfg(test)]
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
        current: Some(current.clone()),
        expected_canonical: None,
        binding,
        replacement,
        replacement_canonical: None,
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

/// Prepare one bounded exact-partition tombstone deletion.  Retained rows are
/// never deleted by this path: only a completed 24-hour reclaim produces the
/// tombstones whose stable admission slot can then be retired.
#[cfg(test)]
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
    let key = ProductionFloorKey::from_floor(previous_floor)?;
    if key != ProductionFloorKey::from_floor(next_floor)?
        || key != selected_prefix.key
        || selected_prefix.target_epoch != next_floor.retired_through()
        || next_floor.retired_through() <= previous_floor.retired_through()
    {
        return Err(ReservationError::FloorAdvance);
    }
    next_floor
        .strictly_advances(previous_floor)
        .map_err(|_| ReservationError::FloorAdvance)?;
    let cursor = match existing_retirement_cursor {
        Some(cursor)
            if cursor.key == key && cursor.target_epoch == next_floor.retired_through() =>
        {
            cursor.validate_for_floor(previous_floor)?;
            cursor.clone()
        }
        Some(_) => return Err(ReservationError::FloorAdvance),
        None => ProductionRetirementCursor::initial(key, next_floor.retired_through())?,
    };
    let guard =
        ProductionPartitionRangeGuard::from_prefix(&selected_prefix, previous_floor, &cursor)?;
    let mut next_counters = witness.roster;
    let mut rows = Vec::with_capacity(selected_prefix.selected.len());
    let mut previous_binding = cursor.last_deleted;
    for (binding, record) in selected_prefix.selected {
        if previous_binding.is_some_and(|last| *binding <= last)
            || ProductionFloorKey::from_binding(*binding)? != key
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
            expected_canonical: None,
            replacement: None,
            replacement_canonical: None,
        });
        previous_binding = Some(*binding);
    }
    let cursor_cas = if selected_prefix.final_batch {
        if let Some(existing) = existing_retirement_cursor {
            next_counters = counters_without_retirement_cursor(next_counters, existing)?;
        }
        ProductionRetirementCursorCas {
            key,
            expected: existing_retirement_cursor.cloned(),
            replacement: None,
        }
    } else {
        let advanced =
            cursor.advance_through(rows.last().ok_or(ReservationError::FloorAdvance)?.binding)?;
        if let Some(existing) = existing_retirement_cursor {
            next_counters = counters_without_retirement_cursor(next_counters, existing)?;
        }
        next_counters = counters_with_retirement_cursor(next_counters, &advanced)?;
        ProductionRetirementCursorCas {
            key,
            expected: existing_retirement_cursor.cloned(),
            replacement: Some(advanced),
        }
    };
    if selected_prefix.final_batch {
        next_counters = counters_without_production_floor(next_counters, previous_floor)?;
        if !selected_prefix.partition_empty_after {
            next_counters = counters_with_production_floor(next_counters, next_floor)?;
        }
    }
    let next = witness.with_roster(next_counters);
    next.admits(budget)?;
    Ok(PreparedProductionTransaction {
        rows,
        previous: witness,
        next,
        floor: selected_prefix.final_batch.then_some(ProductionFloorCas {
            key,
            expected: Some(previous_floor),
            replacement: (!selected_prefix.partition_empty_after).then_some(next_floor),
        }),
        retirement_cursor: Some(cursor_cas),
        released_floors: Vec::new(),
        released_retirement_cursors: Vec::new(),
        partition_guard: Some(guard),
        global_terminal_retirement_guard: None,
        reclaim_oldest_guard: None,
        admission_business_reservation: None,
        business: None,
        #[cfg(test)]
        canonical_rows_validated: u32::try_from(selected_prefix.selected.len())
            .map_err(|_| ReservationError::Arithmetic)?,
    })
}

struct ProductionTransitionPreparation {
    current: Option<ProductionReservationRecord>,
    expected_canonical: Option<Vec<u8>>,
    binding: RequestBindingKey,
    replacement: ProductionReservationRecord,
    replacement_canonical: Option<Vec<u8>>,
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
    transition: ProductionTransitionPreparation,
) -> Result<PreparedProductionChargeTransition, ReservationError> {
    let ProductionTransitionPreparation {
        current,
        expected_canonical,
        binding,
        replacement,
        replacement_canonical,
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
    if let Some(current) = current.as_ref() {
        if current.binding != binding {
            return Err(ReservationError::Unknown);
        }
        current.validate(profile)?;
    }
    prepare_production_transition_prevalidated(ProductionTransitionPreparation {
        current,
        expected_canonical,
        binding,
        replacement,
        replacement_canonical,
        insertion,
        floor,
        retirement_cursor,
        partition_guard,
        admission_business_reservation,
        business,
        witness,
        budget,
        profile,
    })
}

/// Finish a transition after its row inputs have been fully validated. The
/// hydrated terminal path reaches this only after deriving and checking the
/// replacement from its authenticated live payload; legacy/recovery paths
/// retain the full validation above.
fn prepare_production_transition_prevalidated(
    transition: ProductionTransitionPreparation,
) -> Result<PreparedProductionChargeTransition, ReservationError> {
    let ProductionTransitionPreparation {
        current,
        expected_canonical,
        binding,
        replacement,
        replacement_canonical,
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
    // A fresh Q2 terminal receipt must linearize after the authenticated
    // closure horizon. This is a fixed comparison against its own committed
    // sequence, not a roster scan; Q1 has no terminal sequence at all.
    if replacement
        .terminal_sequence()
        .is_some_and(|sequence| sequence <= witness.retired_terminal_sequence())
    {
        return Err(ReservationError::SnapshotMismatch);
    }
    if current
        .as_ref()
        .is_some_and(|current| current.binding != binding)
    {
        return Err(ReservationError::Unknown);
    }
    if expected_canonical.is_some() && current.is_none() {
        return Err(ReservationError::InvalidState);
    }
    if replacement_canonical.as_ref().is_some_and(|canonical| {
        canonical.is_empty() || canonical.len() > MAX_PRODUCTION_RECORD_SNAPSHOT_BYTES
    }) {
        return Err(ReservationError::CanonicalEncoding);
    }
    let without_current = match current.as_ref() {
        Some(current) => counters_without_production_record(witness.roster, current, profile)?,
        None => witness.roster,
    };
    let mut next_counters =
        counters_with_production_record(without_current, &replacement, profile)?;
    if let Some(floor) = floor {
        match (floor.expected, floor.replacement) {
            (None, Some(replacement)) => {
                next_counters = counters_with_production_floor(next_counters, replacement)?;
            }
            (Some(expected), Some(replacement)) => {
                next_counters = counters_without_production_floor(next_counters, expected)?;
                next_counters = counters_with_production_floor(next_counters, replacement)?;
            }
            _ => return Err(ReservationError::FloorAdvance),
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
            expected: current,
            expected_canonical,
            replacement: Some(replacement),
            replacement_canonical,
        }],
        previous: witness,
        next,
        floor,
        retirement_cursor,
        released_floors: Vec::new(),
        released_retirement_cursors: Vec::new(),
        partition_guard,
        global_terminal_retirement_guard: None,
        reclaim_oldest_guard: None,
        admission_business_reservation,
        business,
        #[cfg(test)]
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

/// Add one V2 carrier to the same global witness used by V1.  The profiles
/// have disjoint durable row encodings, but their finite live/history slots
/// and schema-charge budget are one deployment-wide resource.
fn counters_with_production_record_v2(
    counters: AggregateCounters,
    record: &ProductionReservationRecordV2,
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    counters_for_record(
        counters,
        match record.state {
            ProductionReservationStateV2::Live => ReservationState::Live,
            ProductionReservationStateV2::Retained => ReservationState::Retained,
            ProductionReservationStateV2::Tombstone => ReservationState::Tombstone,
        },
        production_record_v2_charges(record, profile)?,
    )
}

pub(crate) fn counters_with_production_floor(
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

fn counters_without_production_floor(
    mut counters: AggregateCounters,
    floor: IrreversibleHistoryFloor,
) -> Result<AggregateCounters, ReservationError> {
    let bytes = floor
        .to_canonical_bytes()
        .map_err(|_| ReservationError::CanonicalEncoding)?;
    counters.floor_count = counters
        .floor_count
        .checked_sub(1)
        .ok_or(ReservationError::WitnessMismatch)?;
    counters.floor_charge_bytes = counters
        .floor_charge_bytes
        .checked_sub(as_u64(bytes.len())?)
        .ok_or(ReservationError::WitnessMismatch)?;
    counters.materialized_charge_bytes = counters
        .materialized_charge_bytes
        .checked_sub(as_u64(bytes.len())?)
        .ok_or(ReservationError::WitnessMismatch)?;
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

/// Remove one V2 carrier from the shared witness before replacing it at Q2.
fn counters_without_production_record_v2(
    mut counters: AggregateCounters,
    record: &ProductionReservationRecordV2,
    profile: ChargeProfile,
) -> Result<AggregateCounters, ReservationError> {
    let contribution = counters_for_record(
        zero_counters(),
        match record.state {
            ProductionReservationStateV2::Live => ReservationState::Live,
            ProductionReservationStateV2::Retained => ReservationState::Retained,
            ProductionReservationStateV2::Tombstone => ReservationState::Tombstone,
        },
        production_record_v2_charges(record, profile)?,
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
        ReservationState::Live => profile.charge(production_components(
            &record.admission,
            None,
            None,
            if record.admission_provenance.is_empty() {
                0
            } else {
                MAX_COMPACT_PROVENANCE_BYTES
            },
        )?),
        ReservationState::Retained => profile.charge(production_components(
            &record.admission,
            record.terminal.as_deref(),
            None,
            record
                .admission_provenance
                .len()
                .checked_add(record.terminal_evidence.as_ref().map_or(0, Vec::len))
                .ok_or(ReservationError::Arithmetic)?,
        )?),
        ReservationState::Tombstone => profile.charge(production_components(
            &[],
            None,
            record.tombstone.as_deref(),
            record
                .admission_provenance
                .len()
                .checked_add(record.terminal_evidence.as_ref().map_or(0, Vec::len))
                .ok_or(ReservationError::Arithmetic)?,
        )?),
    }
}

/// Recompute the V2 carrier's exact charge from canonical row components.
///
/// A V2 `Live` row reserves the full compact terminal envelope at Q1.  A
/// `Retained` row materializes only its actually sealed V2 evidence; its
/// construction already proves that charge is bounded by the reservation.
fn production_record_v2_charges(
    record: &ProductionReservationRecordV2,
    profile: ChargeProfile,
) -> Result<Charges, ReservationError> {
    match record.state {
        ProductionReservationStateV2::Live => profile.charge(production_components_v2(
            &record.admission,
            None,
            None,
            max_v2_compact_evidence_bytes(),
        )?),
        ProductionReservationStateV2::Retained => profile.charge(production_components_v2(
            &record.admission,
            record.terminal.as_deref(),
            None,
            record
                .admission_provenance
                .len()
                .checked_add(record.terminal_evidence.as_ref().map_or(0, Vec::len))
                .ok_or(ReservationError::Arithmetic)?,
        )?),
        ProductionReservationStateV2::Tombstone => profile.charge(production_components_v2(
            &[],
            None,
            record.tombstone.as_deref(),
            record
                .admission_provenance
                .len()
                .checked_add(record.terminal_evidence.as_ref().map_or(0, Vec::len))
                .ok_or(ReservationError::Arithmetic)?,
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

fn add2(first: u64, second: u64) -> Result<u64, ReservationError> {
    first
        .checked_add(second)
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
    /// A terminal row has not reached the fixed retention age.
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
            Self::NotEligible => "terminal reservation is not eligible for reclaim",
            Self::InvalidMaintenanceTime => "maintenance timestamp is invalid",
            Self::InvalidEpoch => "reservation epoch is invalid",
            Self::SnapshotMismatch => "reservation snapshot validation failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ReservationError {}
