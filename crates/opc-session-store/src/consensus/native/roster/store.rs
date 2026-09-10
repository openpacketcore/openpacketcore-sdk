//! Savepoint adapter for the unchanged production Q1/Q2 evaluator. All writes
//! remain private until the caller accepts the complete evaluator result.

use super::*;
use crate::backend::ReplicationOp;
use crate::consensus::types::ConsensusRosterAdmissionCommand;
use crate::fenced_mutation_roster::Admission;
use crate::fenced_mutation_roster_executor::AuthorityBinding;
use crate::fenced_mutation_roster_storage::{
    HydratedProductionReservationRecord, HydratedProductionReservationRecordV2,
    PreparedProductionTransaction, PreparedProductionV2Admission, ProductionBindingVacancyGuard,
    ProductionBusinessState, ProductionFloorCas, ProductionReservationRecordV2,
    ProductionRetirementCursorCas, ProductionTerminalAbsentBusinessActionV2,
    ProductionTerminalBusinessAction, ReservationError,
};
use crate::model::Generation;
use crate::sqlite::consensus::{
    roster_engine::{RosterCommandStore, V2TerminalWrite},
    ProtectedRosterApplyError as ReadError, ProtectedRosterCommandApplyError as ApplyError,
    ProtectedRosterV2OriginalAuthorityProjection,
};
use std::cell::RefCell;

pub(in crate::consensus::native) struct Store<'s, 'a> {
    base: &'s NativeDelta<'a>,
    root: Option<&'s RosterAttestationTrustRootV1>,
    scope: MembershipValidationScope,
    ledger: Ledger,
    changes: Journal,
    keys: HashMap<SessionKey, NativeKeyState>,
    restore_revision: u64,
    // Trait reads transfer an owned hydration to the evaluator. Keep its
    // allocation reservation until the entire savepoint/evaluator is dropped.
    hydration_memory: RefCell<Vec<VerificationMemory>>,
    detached_check: Option<&'s dyn Fn() -> io::Result<()>>,
}

impl<'s, 'a> Store<'s, 'a> {
    pub(in crate::consensus::native) fn new(
        base: &'s NativeDelta<'a>,
        ledger: &Ledger,
        root: &'s RosterAttestationTrustRootV1,
    ) -> io::Result<Self> {
        Ok(Self {
            base,
            root: Some(root),
            scope: fixed_scope(base.base.identity, &base.base.members),
            ledger: ledger.clone(),
            changes: Journal::empty(ledger)?,
            keys: HashMap::new(),
            restore_revision: base.frontiers.restore_revision,
            hydration_memory: RefCell::new(Vec::new()),
            detached_check: None,
        })
    }

    /// The caller has released State and retains its exact application
    /// capture. Every selected I/O and full verifier remains in that scope.
    pub(in crate::consensus::native) fn new_detached(
        base: &'s NativeDelta<'a>,
        ledger: &Ledger,
        root: &'s RosterAttestationTrustRootV1,
        check: &'s dyn Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        let mut store = Self::new(base, ledger, root)?;
        store.detached_check = Some(check);
        Ok(store)
    }

    pub(in crate::consensus::native) fn for_command(
        base: &'s NativeDelta<'a>,
        check: &'s dyn Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        Ok(Self {
            base,
            root: base.base.roster_root.as_deref(),
            scope: fixed_scope(base.base.identity, &base.base.members),
            ledger: base.roster.clone(),
            changes: Journal::empty(&base.roster)?,
            keys: HashMap::new(),
            restore_revision: base.frontiers.restore_revision,
            hydration_memory: RefCell::new(Vec::new()),
            detached_check: Some(check),
        })
    }

    #[cfg(test)]
    pub(in crate::consensus::native) fn finish(
        self,
    ) -> (Ledger, HashMap<SessionKey, NativeKeyState>, u64) {
        (self.ledger, self.keys, self.restore_revision)
    }

    pub(in crate::consensus::native) fn finish_with_changes(
        self,
    ) -> io::Result<(Ledger, Journal, HashMap<SessionKey, NativeKeyState>, u64)> {
        self.changes.require_current(&self.ledger)?;
        self.changes.validate(&|| Ok(()))?;
        Ok((self.ledger, self.changes, self.keys, self.restore_revision))
    }

    fn accept(&mut self, edit: Edit) -> io::Result<()> {
        if !Arc::ptr_eq(self.changes.target(), self.ledger.certificate()?) {
            return Err(invalid("native roster savepoint lost its current journal"));
        }
        let (ledger, changes) = edit.finish()?;
        self.changes.append(changes)?;
        self.ledger = ledger;
        Ok(())
    }

    fn identity(&self, identity: SessionConsensusIdentity) -> Result<(), ReadError> {
        if identity != self.base.base.identity {
            return Err(ReadError::Corrupt);
        }
        Ok(())
    }

    fn key(&self, key: &SessionKey) -> NativeKeyState {
        self.keys
            .get(key)
            .cloned()
            .unwrap_or_else(|| self.base.key(key))
    }

    fn hydrate_row(&self, binding: RequestBindingKey) -> io::Result<Option<carrier::Hydration>> {
        let root = self
            .root
            .ok_or_else(|| invalid("native roster selected row lacks its configured root"))?;
        match self.detached_check {
            None => self.ledger.hydrate(binding, root, &self.scope),
            Some(check) => self
                .ledger
                .hydrate_detached(binding, root, &self.scope, &|| check()),
        }
    }

    fn hydration(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        profile: Profile,
    ) -> Result<Option<carrier::Hydration>, ReadError> {
        self.identity(identity)?;
        if self
            .ledger
            .rows
            .get(&binding)
            .is_none_or(|row| row.projection.profile != profile)
        {
            return Ok(None);
        }
        let hydrated = self
            .hydrate_row(binding)
            .map_err(|_| ReadError::Corrupt)?
            .ok_or(ReadError::Corrupt)?;
        if let Some(key) = hydrated.reserved_key() {
            let state = self.key(key);
            if !state.reserved || self.ledger.index.reservation(key) != Some(binding) {
                return Err(ReadError::Corrupt);
            }
            hydrated
                .validate_business(state.record.as_ref())
                .map_err(|_| ReadError::Corrupt)?;
        }
        Ok(Some(hydrated))
    }

    fn original(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        admission: &Admission,
        profile: Profile,
    ) -> Result<AuthorityBinding, ReadError> {
        self.identity(identity)?;
        let row = self.ledger.rows.get(&binding).ok_or(ReadError::Corrupt)?;
        if row.projection.profile != profile {
            return Err(ReadError::Corrupt);
        }
        row.projection.original.for_admission(admission)
    }

    fn partition_cas(
        ledger: &mut Edit,
        floor: Option<&ProductionFloorCas>,
        cursor: Option<&ProductionRetirementCursorCas>,
    ) -> Result<(), ReservationError> {
        // Both comparisons refer to the same predecessor. In particular,
        // releasing a floor must not erase its cursor before comparing the
        // cursor CAS which consumes that exact prior row.
        if let Some(floor) = floor {
            let current = ledger.partitions.get(&floor.key());
            if current.map(|row| row.floor) != floor.expected() {
                return Err(ReservationError::SnapshotMismatch);
            }
        }
        if let Some(cursor) = cursor {
            let current = ledger
                .partitions
                .get(&cursor.key())
                .and_then(|row| row.cursor.as_ref());
            if current != cursor.expected() {
                return Err(ReservationError::SnapshotMismatch);
            }
        }
        let mut replacements = Vec::with_capacity(2);
        for key in floor
            .map(ProductionFloorCas::key)
            .into_iter()
            .chain(cursor.map(ProductionRetirementCursorCas::key))
        {
            if replacements.iter().any(|(seen, _)| *seen == key) {
                continue;
            }
            let before = ledger.partitions.get(&key);
            let next_floor = floor.filter(|cas| cas.key() == key).map_or_else(
                || before.map(|row| row.floor),
                ProductionFloorCas::replacement,
            );
            let next_cursor = cursor.filter(|cas| cas.key() == key).map_or_else(
                || before.and_then(|row| row.cursor.clone()),
                |cas| cas.replacement().cloned(),
            );
            let next = match next_floor {
                Some(floor) => {
                    let row = Partition {
                        floor,
                        cursor: next_cursor,
                    };
                    row.validate(key)
                        .map_err(|_| ReservationError::SnapshotMismatch)?;
                    Some(row)
                }
                None if next_cursor.is_none() => None,
                None => return Err(ReservationError::SnapshotMismatch),
            };
            replacements.push((key, next));
        }
        for (key, next) in replacements {
            ledger
                .replace_partition(key, next)
                .map_err(|_| ReservationError::SnapshotMismatch)?;
        }
        Ok(())
    }

    fn replacement(
        &self,
        ledger: &Ledger,
        binding: RequestBindingKey,
        projection: Projection,
        canonical: Vec<u8>,
    ) -> Result<Row, ReservationError> {
        let hydrated = carrier::hydrate(
            projection,
            binding,
            canonical,
            self.root.ok_or(ReservationError::SnapshotMismatch)?,
            &self.scope,
        )
        .map_err(|_| ReservationError::SnapshotMismatch)?;
        let partition = ledger
            .partition(binding)
            .map_err(|_| ReservationError::SnapshotMismatch)?;
        hydrated
            .validate_partition(partition.floor, partition.cursor.as_ref())
            .map_err(|_| ReservationError::SnapshotMismatch)?;
        Row::from_hydration(&hydrated).map_err(|_| ReservationError::SnapshotMismatch)
    }

    fn install(
        ledger: &mut Edit,
        binding: RequestBindingKey,
        row: Row,
        next_witness: GlobalChargeWitness,
    ) -> Result<(), ReservationError> {
        let current = ledger.rows.get(&binding);
        if current.is_some_and(|before| {
            before.projection != row.projection
                || !matches!(
                    (before.facts.state, row.facts.state),
                    (State::Live, State::Retained) | (State::Retained, State::Tombstone)
                )
        }) {
            return Err(ReservationError::SnapshotMismatch);
        }
        let index = ledger
            .index
            .replaced(binding, current.map(|row| &**row), Some(&row))
            .map_err(|_| ReservationError::SnapshotMismatch)?;
        ledger
            .replace_row(binding, Some(SharedRow::new(row)))
            .map_err(|_| ReservationError::SnapshotMismatch)?;
        ledger.index = index;
        ledger.witness = Some(next_witness);
        Ok(())
    }

    fn reserved_business(
        &self,
        expected: &ProductionBusinessState,
        binding: RequestBindingKey,
    ) -> Result<NativeKeyState, ReservationError> {
        let current = self.key(expected.key());
        let record = current
            .record
            .as_ref()
            .ok_or(ReservationError::BusinessCas)?;
        if ProductionBusinessState::from_authoritative_record(record)? != *expected
            || !current.reserved
            || self.ledger.index.reservation(expected.key()) != Some(binding)
        {
            return Err(ReservationError::BusinessCas);
        }
        Ok(current)
    }
}

impl RosterCommandStore for Store<'_, '_> {
    fn trust_root(
        &self,
    ) -> Result<
        Option<RosterAttestationTrustRootV1>,
        crate::consensus::storage::SessionConsensusStorageError,
    > {
        Ok(self.root.cloned())
    }

    fn validate_live_authority(
        &self,
        authority: &AuthorityBinding,
        expected_generation: Option<Generation>,
        logical_time: Timestamp,
    ) -> Result<(), ReadError> {
        let current = self.key(authority.key());
        let Some(lease) = current.lease.as_ref() else {
            return Err(ReadError::Rejected);
        };
        let acquired_at = lease.acquired_at.ok_or(ReadError::Corrupt)?;
        if !lease.active
            || lease.owner != *authority.owner()
            || lease.fence != authority.fence()
            || lease.credential_id != authority.credential_id()
            || acquired_at != authority.acquired_at()
            || lease.guard_expires_at != authority.expires_at()
            || logical_time < acquired_at
            || logical_time >= lease.guard_expires_at
            || expected_generation.is_some_and(|generation| generation != authority.generation())
        {
            return Err(ReadError::Rejected);
        }
        Ok(())
    }

    fn record_v1(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
    ) -> Result<Option<HydratedProductionReservationRecord>, ReadError> {
        let Some(hydrated) = self.hydration(identity, binding, Profile::V1)? else {
            return Ok(None);
        };
        let (body, memory) = hydrated.into_parts();
        self.hydration_memory.borrow_mut().push(memory);
        match body {
            carrier::Body::V1(row) => Ok(Some(*row)),
            _ => Err(ReadError::Corrupt),
        }
    }

    fn original_authority_v1(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        admission: &Admission,
    ) -> Result<AuthorityBinding, ReadError> {
        self.original(identity, binding, admission, Profile::V1)
    }

    fn raw_record(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        Ok(self.key(key).record)
    }
    fn stable_slot_v1(&self, slot: [u8; 32]) -> Result<Option<RequestBindingKey>, ReadError> {
        self.ledger
            .index
            .stable(slot, Profile::V1)
            .map_err(|_| ReadError::Corrupt)
    }
    fn original_binding_v1(
        &self,
        key: &SessionKey,
        roster: crate::fenced_mutation_roster::RosterId,
        owner: &crate::OwnerId,
        fence: crate::FenceToken,
        generation: Generation,
    ) -> Result<Option<RequestBindingKey>, ReadError> {
        self.ledger
            .index
            .original_v1(key, roster, owner, fence, generation)
    }
    fn stable_slot_v2(&self, slot: [u8; 32]) -> Result<Option<RequestBindingKey>, ReadError> {
        self.ledger
            .index
            .stable(slot, Profile::V2)
            .map_err(|_| ReadError::Corrupt)
    }

    fn floor(
        &self,
        identity: SessionConsensusIdentity,
        key: ProductionFloorKey,
    ) -> Result<Option<IrreversibleHistoryFloor>, ReadError> {
        self.identity(identity)?;
        Ok(self.ledger.partitions.get(&key).map(|row| row.floor))
    }

    fn retirement_cursor(
        &self,
        identity: SessionConsensusIdentity,
        key: ProductionFloorKey,
    ) -> Result<Option<ProductionRetirementCursor>, ReservationError> {
        self.identity(identity)
            .map_err(|_| ReservationError::SnapshotMismatch)?;
        Ok(self
            .ledger
            .partitions
            .get(&key)
            .and_then(|row| row.cursor.clone()))
    }

    fn witness(
        &self,
        identity: SessionConsensusIdentity,
    ) -> Result<Option<GlobalChargeWitness>, ReadError> {
        self.identity(identity)?;
        Ok(self.ledger.witness)
    }

    fn vacancy(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
    ) -> Result<ProductionBindingVacancyGuard, ReadError> {
        self.identity(identity)?;
        if self.ledger.rows.contains_key(&binding) {
            return Err(ReadError::Rejected);
        }
        ProductionBindingVacancyGuard::from_lookups(binding, None, None)
            .map_err(|_| ReadError::Corrupt)
    }

    fn membership_scope(
        &self,
        identity: SessionConsensusIdentity,
    ) -> io::Result<MembershipValidationScope> {
        self.identity(identity)
            .map_err(|_| invalid("native roster membership identity differs"))?;
        Ok(self.scope.clone())
    }

    fn record_v2(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
    ) -> Result<Option<HydratedProductionReservationRecordV2>, ReadError> {
        let Some(hydrated) = self.hydration(identity, binding, Profile::V2)? else {
            return Ok(None);
        };
        let (body, memory) = hydrated.into_parts();
        self.hydration_memory.borrow_mut().push(memory);
        match body {
            carrier::Body::V2(row) => Ok(Some(*row)),
            _ => Err(ReadError::Corrupt),
        }
    }

    fn authenticate_record_v2(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        hydrated: &HydratedProductionReservationRecordV2,
    ) -> Result<(), ReadError> {
        self.identity(identity)?;
        let row = self.ledger.rows.get(&binding).ok_or(ReadError::Corrupt)?;
        if row.projection.profile != Profile::V2 || !row.matches_canonical(hydrated.canonical()) {
            return Err(ReadError::Corrupt);
        }
        // record_v2 already authenticated these exact bytes against this
        // immutable scope/root and retains its reservation for this savepoint.
        Ok(())
    }

    fn original_authority_v2(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        admission: &Admission,
    ) -> Result<AuthorityBinding, ReadError> {
        self.original(identity, binding, admission, Profile::V2)
    }

    fn original_projection_v2(
        &self,
        identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
    ) -> Result<ProtectedRosterV2OriginalAuthorityProjection, ReadError> {
        self.identity(identity)?;
        let row = self.ledger.rows.get(&binding).ok_or(ReadError::Corrupt)?;
        if row.projection.profile != Profile::V2 {
            return Err(ReadError::Corrupt);
        }
        row.projection.original.v2_projection()
    }

    fn live_reservation_v2(
        &self,
        identity: SessionConsensusIdentity,
        key: &SessionKey,
    ) -> Result<Option<RequestBindingKey>, ReadError> {
        self.identity(identity)?;
        let Some(binding) = self.ledger.index.reservation(key) else {
            return Ok(None);
        };
        let row = self.ledger.rows.get(&binding).ok_or(ReadError::Corrupt)?;
        Ok((row.projection.profile == Profile::V2).then_some(binding))
    }

    fn apply_v1(
        &mut self,
        identity: SessionConsensusIdentity,
        transaction: PreparedProductionTransaction,
        admission: Option<&ConsensusRosterAdmissionCommand>,
        authority: Option<&AuthorityBinding>,
    ) -> Result<(), ReservationError> {
        self.identity(identity)
            .map_err(|_| ReservationError::SnapshotMismatch)?;
        // This adapter entry is the evaluator's one-row Q1/Q2 contract.
        // Bounded mixed-profile maintenance has its own prepared input.
        if transaction.rows().len() != 1
            || transaction.partition_range_guard().is_some()
            || transaction.global_terminal_retirement_guard().is_some()
            || transaction.reclaim_oldest_guard().is_some()
            || !transaction.released_floor_cas().is_empty()
            || !transaction.released_retirement_cursor_cas().is_empty()
            || self
                .ledger
                .witness
                .unwrap_or_else(GlobalChargeWitness::empty)
                != transaction.previous_witness()
        {
            return Err(ReservationError::SnapshotMismatch);
        }
        let cas = &transaction.rows()[0];
        let binding = cas.binding();
        let current = self.ledger.rows.get(&binding);
        match (current, cas.expected()) {
            (None, None) if cas.expected_canonical_bytes().is_none() => {}
            (Some(current), Some(expected)) if current.projection.profile == Profile::V1 => {
                let encoded;
                let canonical = match cas.expected_canonical_bytes() {
                    Some(bytes) => bytes,
                    None => {
                        encoded = expected.to_canonical_bytes()?;
                        &encoded
                    }
                };
                if !current.matches_canonical(canonical) {
                    return Err(ReservationError::SnapshotMismatch);
                }
            }
            _ => return Err(ReservationError::SnapshotMismatch),
        }
        let replacement = cas
            .replacement()
            .ok_or(ReservationError::SnapshotMismatch)?;
        let projection = match admission {
            Some(command) if current.is_none() => Projection::from_admission(binding, command)
                .map_err(|_| ReservationError::SnapshotMismatch)?,
            None => current
                .ok_or(ReservationError::SnapshotMismatch)?
                .projection
                .clone(),
            _ => return Err(ReservationError::SnapshotMismatch),
        };
        let mut ledger =
            Edit::new(&self.ledger, 1, 2).map_err(|_| ReservationError::SnapshotMismatch)?;
        Self::partition_cas(
            &mut ledger,
            transaction.floor_cas().as_ref(),
            transaction.retirement_cursor_cas(),
        )?;
        let canonical = match cas.replacement_canonical_bytes() {
            Some(bytes) => bytes.to_vec(),
            None => replacement.to_canonical_bytes()?,
        };
        let row = self.replacement(&ledger, binding, projection, canonical)?;
        let effect;
        let mut restore_revision = self.restore_revision;
        match (
            transaction.admission_business_reservation(),
            transaction.business_cas(),
        ) {
            (Some(reservation), None)
                if admission.is_some() && authority.is_none() && row.facts.state == State::Live =>
            {
                let expected = reservation.expected();
                let mut key = self.key(expected.key());
                if ProductionBusinessState::from_authoritative_record(
                    key.record.as_ref().ok_or(ReservationError::BusinessCas)?,
                )? != *expected
                    || key.reserved
                    || self.ledger.index.reservation(expected.key()).is_some()
                {
                    return Err(ReservationError::BusinessCas);
                }
                key.reserved = true;
                effect = (expected.key().clone(), key);
            }
            (None, Some(business)) if admission.is_none() && row.facts.state == State::Retained => {
                let action = business.action();
                let expected = action.expected();
                let mut key = self.reserved_business(expected, binding)?;
                let authority = authority.ok_or(ReservationError::BusinessCas)?;
                if authority.key() != expected.key() || key.fence > authority.fence().get() {
                    return Err(ReservationError::BusinessCas);
                }
                key.fence = authority.fence().get();
                match action {
                    ProductionTerminalBusinessAction::AbortedCompareRelease { .. } => {}
                    ProductionTerminalBusinessAction::EstablishedPut { successor, .. } => {
                        key.record = Some(successor.authoritative_record()?);
                        restore_revision = restore_revision
                            .checked_add(1)
                            .filter(|value| *value <= COUNTER_MAX)
                            .ok_or(ReservationError::BusinessCas)?;
                    }
                    ProductionTerminalBusinessAction::EstablishedDelete { .. } => {
                        key.record = None;
                        restore_revision = restore_revision
                            .checked_add(1)
                            .filter(|value| *value <= COUNTER_MAX)
                            .ok_or(ReservationError::BusinessCas)?;
                    }
                }
                key.reserved = false;
                effect = (expected.key().clone(), key);
            }
            _ => return Err(ReservationError::SnapshotMismatch),
        }
        Self::install(&mut ledger, binding, row, transaction.next_witness())?;
        self.accept(ledger)
            .map_err(|_| ReservationError::SnapshotMismatch)?;
        self.keys.insert(effect.0, effect.1);
        self.restore_revision = restore_revision;
        Ok(())
    }

    fn apply_admission_v2(
        &mut self,
        identity: SessionConsensusIdentity,
        record: &ProductionReservationRecordV2,
        command: &ConsensusRosterAdmissionCommand,
        preparation: &PreparedProductionV2Admission,
    ) -> Result<(), ApplyError> {
        self.identity(identity).map_err(|_| ApplyError::Fatal)?;
        let binding = record.binding();
        if self.ledger.rows.contains_key(&binding)
            || self
                .ledger
                .witness
                .unwrap_or_else(GlobalChargeWitness::empty)
                != preparation.previous_witness()
        {
            return Err(ApplyError::Fatal);
        }
        let reservation = record.absence_reservation().ok_or(ApplyError::Fatal)?;
        let key = reservation.predicate().key();
        let mut value = self.key(key);
        if value.record.is_some() {
            return Err(ApplyError::Rejected(
                crate::consensus::types::ConsensusRosterRejection::RecordAlreadyExists,
            ));
        }
        if value.reserved || self.ledger.index.reservation(key).is_some() {
            return Err(ApplyError::Fatal);
        }
        let mut ledger = Edit::new(&self.ledger, 1, 2).map_err(|_| ApplyError::Fatal)?;
        Self::partition_cas(
            &mut ledger,
            Some(preparation.floor_cas()),
            Some(preparation.retirement_cursor_cas()),
        )
        .map_err(|_| ApplyError::Fatal)?;
        let projection =
            Projection::from_admission(binding, command).map_err(|_| ApplyError::Fatal)?;
        let row = self
            .replacement(
                &ledger,
                binding,
                projection,
                record.to_canonical_bytes().map_err(|_| ApplyError::Fatal)?,
            )
            .map_err(|_| ApplyError::Fatal)?;
        if row.projection.profile != Profile::V2
            || row.facts.state != State::Live
            || row.reserved_key() != Some(key)
        {
            return Err(ApplyError::Fatal);
        }
        Self::install(&mut ledger, binding, row, preparation.next_witness())
            .map_err(|_| ApplyError::Fatal)?;
        self.accept(ledger).map_err(|_| ApplyError::Fatal)?;
        value.reserved = true;
        self.keys.insert(key.clone(), value);
        Ok(())
    }

    fn apply_terminal_v2(
        &mut self,
        identity: SessionConsensusIdentity,
        authority: &AuthorityBinding,
        write: V2TerminalWrite<'_>,
        next_witness: GlobalChargeWitness,
    ) -> Result<Option<ReplicationOp>, ApplyError> {
        self.identity(identity).map_err(|_| ApplyError::Fatal)?;
        let V2TerminalWrite {
            binding,
            replacement,
            old_canonical,
            new_canonical,
            replacement_terminalized_at,
            replacement_terminal_sequence,
            action,
        } = write;
        let current = self.ledger.rows.get(&binding).ok_or(ApplyError::Fatal)?;
        if current.projection.profile != Profile::V2
            || current.facts.state != State::Live
            || !current.matches_canonical(&old_canonical)
            || replacement.binding() != binding
            || replacement
                .to_canonical_bytes()
                .map_err(|_| ApplyError::Fatal)?
                != new_canonical
        {
            return Err(ApplyError::Fatal);
        }
        let key = action.predicate().key();
        let mut value = self.key(key);
        if value.record.is_some()
            || !value.reserved
            || self.ledger.index.reservation(key) != Some(binding)
        {
            return Err(ApplyError::Fatal);
        }
        let mut ledger = Edit::new(&self.ledger, 1, 0).map_err(|_| ApplyError::Fatal)?;
        let row = self
            .replacement(&ledger, binding, current.projection.clone(), new_canonical)
            .map_err(|_| ApplyError::Fatal)?;
        if row.facts.state != State::Retained
            || row
                .facts
                .terminalized_at
                .map(|time| time.as_nanos().to_be_bytes())
                != Some(replacement_terminalized_at)
            || row.facts.terminal_sequence != u64::try_from(replacement_terminal_sequence).ok()
        {
            return Err(ApplyError::Fatal);
        }
        let mut restore_revision = self.restore_revision;
        let replication = match action {
            ProductionTerminalAbsentBusinessActionV2::AbortedCompareAbsentRelease { .. } => None,
            ProductionTerminalAbsentBusinessActionV2::EstablishedCreate { successor, .. } => {
                let successor = successor
                    .authoritative_record()
                    .map_err(|_| ApplyError::Fatal)?;
                if successor.key != *authority.key()
                    || successor.key != *key
                    || successor.generation != Generation::new(1)
                {
                    return Err(ApplyError::Fatal);
                }
                crate::sqlite::validate_consensus_record(&successor)
                    .map_err(|_| ApplyError::Fatal)?;
                restore_revision = restore_revision
                    .checked_add(1)
                    .filter(|value| *value <= COUNTER_MAX)
                    .ok_or(ApplyError::Fatal)?;
                value.record = Some(successor.clone());
                Some(ReplicationOp::ProtectedRosterEstablishedCreate {
                    key: successor.key.clone(),
                    record: successor,
                    owner: authority.owner().clone(),
                    fence: authority.fence(),
                    credential_id: authority.credential_id(),
                    guard_acquired_at: authority.acquired_at(),
                    guard_expires_at: authority.expires_at(),
                })
            }
        };
        Self::install(&mut ledger, binding, row, next_witness).map_err(|_| ApplyError::Fatal)?;
        self.accept(ledger).map_err(|_| ApplyError::Fatal)?;
        value.reserved = false;
        self.keys.insert(key.clone(), value);
        self.restore_revision = restore_revision;
        Ok(replication)
    }
}

#[path = "maintenance.rs"]
mod maintenance;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
