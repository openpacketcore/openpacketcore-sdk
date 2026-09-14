//! Streaming forms of the original mixed-history planners. A caller may
//! release each authenticated carrier after staging its exact row action.
//! Nothing is publishable until finish returns the shared witness and guard;
//! every staged action must be discarded on any error.

use super::*;

pub(crate) struct ReclaimClosure {
    pub(crate) previous: GlobalChargeWitness,
    pub(crate) next: GlobalChargeWitness,
    pub(crate) guard: ProductionMixedReclaimOldestGuard,
}

pub(crate) struct ProductionMixedReclaimStream {
    maintenance_time: ConsensusMaintenanceTimestamp,
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
    counters: AggregateCounters,
    selected: Vec<(
        ConsensusMaintenanceTimestamp,
        RequestBindingKey,
        ProductionRosterProfileTag,
    )>,
}

impl ProductionMixedReclaimStream {
    pub(crate) fn new(
        maintenance_time: ConsensusMaintenanceTimestamp,
        witness: GlobalChargeWitness,
        budget: GlobalChargeBudget,
        profile: ChargeProfile,
    ) -> Result<Self, ReservationError> {
        witness.admits(budget)?;
        Ok(Self {
            maintenance_time,
            witness,
            budget,
            profile,
            counters: witness.roster,
            selected: Vec::new(),
        })
    }

    pub(crate) fn push(
        &mut self,
        selection: ProductionMixedReclaimSelection<'_>,
    ) -> Result<ProductionMixedReclaimRow, ReservationError> {
        if self.selected.len() == RECLAIM_BATCH {
            return Err(ReservationError::SnapshotMismatch);
        }
        let previous_order = self.selected.last().copied();
        let profile = self.profile;
        let maintenance_time = self.maintenance_time;
        let mut counters = self.counters;
        let (row, order) = match selection {
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
                let mut replacement = record.clone();
                replacement.reclaim_at(maintenance_time, profile)?;
                counters = counters_without_production_record(counters, record, profile)?;
                counters = counters_with_production_record(counters, &replacement, profile)?;
                (
                    ProductionMixedReclaimRow::V1 {
                        expected: Box::new(record.clone()),
                        replacement: Box::new(replacement),
                    },
                    order,
                )
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
                let mut replacement = record.clone();
                replacement.reclaim_at(maintenance_time, profile)?;
                counters = counters_without_production_record_v2(counters, record, profile)?;
                counters = counters_with_production_record_v2(counters, &replacement, profile)?;
                (
                    ProductionMixedReclaimRow::V2 {
                        expected: Box::new(record.clone()),
                        replacement: Box::new(replacement),
                    },
                    order,
                )
            }
        };
        self.counters = counters;
        self.selected.push(order);
        Ok(row)
    }

    pub(crate) fn finish(self) -> Result<ReclaimClosure, ReservationError> {
        if self.selected.is_empty() {
            return Err(ReservationError::SnapshotMismatch);
        }
        let next = self.witness.with_roster(self.counters);
        next.admits(self.budget)?;
        Ok(ReclaimClosure {
            previous: self.witness,
            next,
            guard: ProductionMixedReclaimOldestGuard {
                selected: self.selected,
            },
        })
    }
}

pub(crate) struct RetirementClosure {
    pub(crate) floor_actions: Vec<ProductionMixedTerminalRetirementFloorAction>,
    pub(crate) previous: GlobalChargeWitness,
    pub(crate) next: GlobalChargeWitness,
    pub(crate) guard: ProductionMixedTerminalRetirementGuard,
}

pub(crate) struct ProductionMixedTerminalRetirementStream {
    witness: GlobalChargeWitness,
    budget: GlobalChargeBudget,
    profile: ChargeProfile,
    counters: AggregateCounters,
    selected: Vec<(u64, RequestBindingKey, ProductionRosterProfileTag)>,
    seen_bindings: BTreeMap<RequestBindingKey, ()>,
}

impl ProductionMixedTerminalRetirementStream {
    pub(crate) fn new(
        witness: GlobalChargeWitness,
        budget: GlobalChargeBudget,
        profile: ChargeProfile,
    ) -> Result<Self, ReservationError> {
        witness.admits(budget)?;
        Ok(Self {
            witness,
            budget,
            profile,
            counters: witness.roster,
            selected: Vec::new(),
            seen_bindings: BTreeMap::new(),
        })
    }

    pub(crate) fn push(
        &mut self,
        selection: ProductionMixedTerminalRetirementSelection<'_>,
    ) -> Result<ProductionMixedReclaimRow, ReservationError> {
        if self.selected.len() == RECLAIM_BATCH {
            return Err(ReservationError::SnapshotMismatch);
        }
        let previous_sequence = self
            .selected
            .last()
            .map_or(self.witness.retired_terminal_sequence(), |row| row.0);
        let profile = self.profile;
        let mut counters = self.counters;
        let (row, order) = match selection {
            ProductionMixedTerminalRetirementSelection::V1(record) => {
                record.validate(profile)?;
                let sequence = record
                    .terminal_sequence()
                    .ok_or(ReservationError::StateShape)?;
                if record.state != ReservationState::Tombstone || sequence <= previous_sequence {
                    return Err(ReservationError::SnapshotMismatch);
                }
                if self.seen_bindings.contains_key(&record.binding()) {
                    return Err(ReservationError::Duplicate);
                }
                counters = counters_without_production_record(counters, record, profile)?;
                (
                    ProductionMixedReclaimRow::DeleteV1(Box::new(record.clone())),
                    (sequence, record.binding(), ProductionRosterProfileTag::V1),
                )
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
                if self.seen_bindings.contains_key(&record.binding()) {
                    return Err(ReservationError::Duplicate);
                }
                counters = counters_without_production_record_v2(counters, record, profile)?;
                (
                    ProductionMixedReclaimRow::DeleteV2(Box::new(record.clone())),
                    (sequence, record.binding(), ProductionRosterProfileTag::V2),
                )
            }
        };
        self.counters = counters;
        self.seen_bindings.insert(order.1, ());
        self.selected.push(order);
        Ok(row)
    }

    pub(crate) fn finish(
        self,
        partitions: &[ProductionMixedTerminalRetirementPartition],
    ) -> Result<RetirementClosure, ReservationError> {
        let previous_sequence = self
            .selected
            .last()
            .ok_or(ReservationError::SnapshotMismatch)?
            .0;
        let mut counters = self.counters;
        let mut floor_actions = Vec::with_capacity(partitions.len());
        let mut partition_guards = Vec::with_capacity(partitions.len());
        let mut covered = BTreeMap::new();
        for partition in partitions {
            let key = ProductionFloorKey::from_floor(partition.floor)?;
            if covered.insert((key, partition.target_epoch), ()).is_some() {
                return Err(ReservationError::Duplicate);
            }
            let mut bindings = self
                .selected
                .iter()
                .filter_map(|(_, binding, _)| {
                    (ProductionFloorKey::from_binding(*binding).ok() == Some(key)
                        && binding.history_epoch() == partition.target_epoch)
                        .then_some(*binding)
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
                // A global terminal prefix cannot manufacture or advance a
                // binding-order cursor. Preserve any existing cursor until
                // the final target-epoch page consumes it.
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
        for (_, binding, _) in &self.selected {
            let key = ProductionFloorKey::from_binding(*binding)?;
            if !covered.contains_key(&(key, binding.history_epoch())) {
                return Err(ReservationError::FloorAdvance);
            }
        }
        let next = self
            .witness
            .with_roster(counters)
            .retire_through_terminal_sequence(previous_sequence)?;
        next.admits(self.budget)?;
        Ok(RetirementClosure {
            floor_actions,
            previous: self.witness,
            next,
            guard: ProductionMixedTerminalRetirementGuard {
                selected: self.selected,
                partitions: partition_guards,
            },
        })
    }
}
