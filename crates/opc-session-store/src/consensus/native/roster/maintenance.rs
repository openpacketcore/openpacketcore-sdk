//! One original mixed-profile maintenance turn in the native savepoint.
//! All comparisons use its immutable predecessor. Only scalar selections and
//! compact replacements survive between streamed, authenticated row reads.

use super::*;
use crate::fenced_mutation_roster::{RECLAIM_BATCH, TERMINAL_RETENTION};
use crate::fenced_mutation_roster_storage::{
    ChargeProfile, ConsensusMaintenanceTimestamp, ProductionMixedReclaimSelection,
    ProductionMixedReclaimStream, ProductionMixedTerminalRetirementPartition,
    ProductionMixedTerminalRetirementSelection, ProductionMixedTerminalRetirementStream,
    ProductionRosterProfileTag,
};

fn corrupt(_: ReservationError) -> io::Error {
    invalid("native roster maintenance predecessor differs")
}

fn profile(value: Profile) -> ProductionRosterProfileTag {
    match value {
        Profile::V1 => ProductionRosterProfileTag::V1,
        Profile::V2 => ProductionRosterProfileTag::V2,
    }
}

/// Holds all bounded selection vectors, guard tuples, partition maps and
/// planner metadata. Per-carrier decoder/plan reservations are separate and
/// expire before the next row; compact staged rows retain their own guards.
const SELECTION_MEMORY: usize = (RECLAIM_BATCH + 1) * 2048;

fn planner_memory(hydrated: &carrier::Hydration) -> io::Result<VerificationMemory> {
    let bytes = hydrated
        .canonical()
        .len()
        .checked_mul(12)
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .ok_or_else(|| invalid("native roster maintenance allocation overflow"))?;
    VerificationMemory::reserve(bytes)
}

fn retirement_selection(
    ledger: &Ledger,
    witness: GlobalChargeWitness,
) -> io::Result<Vec<(u64, RequestBindingKey, ProductionRosterProfileTag)>> {
    let mut selected = Vec::new();
    let mut epochs = BTreeMap::new();
    for (sequence, binding, state) in ledger
        .index
        .terminal_prefix(witness.retired_terminal_sequence())?
    {
        if state != State::Tombstone {
            break;
        }
        let key = ProductionFloorKey::from_binding(binding).map_err(corrupt)?;
        if epochs
            .get(&key)
            .is_some_and(|epoch| *epoch != binding.history_epoch())
        {
            break;
        }
        epochs.insert(key, binding.history_epoch());
        let row = ledger
            .rows
            .get(&binding)
            .ok_or_else(|| invalid("native roster retirement row missing"))?;
        if row.facts.state != state || row.facts.terminal_sequence != Some(sequence) {
            return Err(invalid("native roster retirement projection differs"));
        }
        selected.push((sequence, binding, profile(row.projection.profile)));
        if selected.len() == RECLAIM_BATCH {
            break;
        }
    }
    Ok(selected)
}

fn retirement_partitions(
    ledger: &Ledger,
    selected: &[(u64, RequestBindingKey, ProductionRosterProfileTag)],
) -> io::Result<Vec<ProductionMixedTerminalRetirementPartition>> {
    let mut counts = BTreeMap::<(ProductionFloorKey, u64), usize>::new();
    for (_, binding, _) in selected {
        *counts
            .entry((
                ProductionFloorKey::from_binding(*binding).map_err(corrupt)?,
                binding.history_epoch(),
            ))
            .or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((key, epoch), count)| {
            let (first, last) = ledger
                .index
                .partition_bounds(key)
                .ok_or_else(|| invalid("native roster retirement partition absent"))?;
            let total = ledger.index.epoch_count(key, epoch);
            if count > total {
                return Err(invalid(
                    "native roster retirement count exceeds its partition",
                ));
            }
            let final_batch = count == total && first.history_epoch() >= epoch;
            let empty_after = final_batch && last.history_epoch() <= epoch;
            let partition = ledger
                .partitions
                .get(&key)
                .ok_or_else(|| invalid("native roster retirement floor missing"))?;
            ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
                partition.floor,
                partition.cursor.clone(),
                epoch,
                final_batch,
                empty_after,
            )
            .map_err(corrupt)
        })
        .collect()
}

impl Store<'_, '_> {
    /// Called by the enclosing committed-command path after its exact roster
    /// activation check. This performs no proposal and changes no business,
    /// lease, response, restore revision or replication notification.
    pub(in crate::consensus::native) fn maintain_due(
        &mut self,
        logical_time: Timestamp,
    ) -> io::Result<bool> {
        let maintenance = ConsensusMaintenanceTimestamp::from_consensus_timestamp(logical_time)
            .map_err(corrupt)?;
        let retention = i128::try_from(TERMINAL_RETENTION.as_nanos())
            .map_err(|_| invalid("native roster retention overflow"))?;
        let Some(cutoff) = maintenance
            .as_nanos()
            .checked_sub(retention)
            .filter(|cutoff| *cutoff >= 0)
        else {
            return Ok(false);
        };
        let Some(witness) = self.ledger.witness else {
            if !self.ledger.rows.is_empty() || !self.ledger.partitions.is_empty() {
                return Err(invalid("native roster maintenance witness missing"));
            }
            return Ok(false);
        };
        let reclaim = self.ledger.index.has_due_retained(cutoff);
        if !reclaim
            && self
                .ledger
                .index
                .first_terminal_state(witness.retired_terminal_sequence())?
                != Some(State::Tombstone)
        {
            return Ok(false);
        }
        let _memory = VerificationMemory::reserve(SELECTION_MEMORY)?;
        let next = if reclaim {
            self.reclaim(maintenance, cutoff, witness)?
        } else {
            self.retire(witness)?
        };
        // No part of the candidate was visible through this savepoint while
        // a later carrier, partition action or final witness could fail.
        self.accept(next)?;
        Ok(true)
    }

    fn reclaim(
        &self,
        maintenance: ConsensusMaintenanceTimestamp,
        cutoff: i128,
        witness: GlobalChargeWitness,
    ) -> io::Result<Edit> {
        let selected = self.ledger.index.reclaim_prefix(cutoff);
        let mut expected_order = Vec::with_capacity(selected.len());
        let mut stream = ProductionMixedReclaimStream::new(
            maintenance,
            witness,
            GlobalChargeBudget::production(),
            ChargeProfile::v1(),
        )
        .map_err(corrupt)?;
        let mut next = Edit::new(&self.ledger, selected.len(), 0)?;
        for (at, binding) in &selected {
            let before = self
                .ledger
                .rows
                .get(binding)
                .ok_or_else(|| invalid("native roster reclaim row missing"))?;
            let hydrated = self
                .hydrate_row(*binding)?
                .ok_or_else(|| invalid("native roster reclaim hydration missing"))?;
            if hydrated.facts.state != State::Retained
                || hydrated.facts.terminalized_at.map(|time| time.as_nanos()) != Some(*at)
                || hydrated.reserved_key().is_some()
            {
                return Err(invalid(
                    "native roster reclaim order or reservation differs",
                ));
            }
            let _planning = planner_memory(&hydrated)?;
            let action = stream
                .push(match hydrated.body() {
                    carrier::Body::V1(row) => ProductionMixedReclaimSelection::V1(row.record()),
                    carrier::Body::V2(row) => ProductionMixedReclaimSelection::V2(row.record()),
                })
                .map_err(corrupt)?;
            let (expected, replacement) = match (action.v1_replacement(), action.v2_replacement()) {
                (Some((expected, replacement)), None)
                    if before.projection.profile == Profile::V1 =>
                {
                    (
                        expected.to_canonical_bytes().map_err(corrupt)?,
                        replacement.to_canonical_bytes().map_err(corrupt)?,
                    )
                }
                (None, Some((expected, replacement)))
                    if before.projection.profile == Profile::V2 =>
                {
                    (
                        expected.to_canonical_bytes().map_err(corrupt)?,
                        replacement.to_canonical_bytes().map_err(corrupt)?,
                    )
                }
                _ => return Err(invalid("native roster reclaim action profile differs")),
            };
            if action.binding() != *binding || !before.matches_canonical(&expected) {
                return Err(invalid(
                    "native roster reclaim canonical predecessor differs",
                ));
            }
            let row = self
                .replacement(&next, *binding, before.projection.clone(), replacement)
                .map_err(corrupt)?;
            let mut facts = before.facts;
            facts.state = State::Tombstone;
            if row.facts != facts || row.reserved_key().is_some() {
                return Err(invalid(
                    "native roster reclaim changes immutable terminal history",
                ));
            }
            Self::install(&mut next, *binding, row, witness).map_err(corrupt)?;
            expected_order.push((
                hydrated
                    .facts
                    .terminalized_at
                    .ok_or_else(|| invalid("native roster terminal time missing"))?,
                *binding,
                profile(before.projection.profile),
            ));
        }
        let closure = stream.finish().map_err(corrupt)?;
        if closure.previous != witness
            || self.ledger.witness != Some(witness)
            || closure.guard.selected() != expected_order
            || selected != self.ledger.index.reclaim_prefix(cutoff)
        {
            return Err(invalid("native roster reclaim prefix or witness differs"));
        }
        next.witness = Some(closure.next);
        Ok(next)
    }

    fn retire(&self, witness: GlobalChargeWitness) -> io::Result<Edit> {
        let selected = retirement_selection(&self.ledger, witness)?;
        let partitions = retirement_partitions(&self.ledger, &selected)?;
        let mut stream = ProductionMixedTerminalRetirementStream::new(
            witness,
            GlobalChargeBudget::production(),
            ChargeProfile::v1(),
        )
        .map_err(corrupt)?;
        let mut next = Edit::new(&self.ledger, selected.len(), partitions.len())?;
        for (sequence, binding, tag) in &selected {
            let before = self
                .ledger
                .rows
                .get(binding)
                .ok_or_else(|| invalid("native roster retirement row missing"))?;
            let hydrated = self
                .hydrate_row(*binding)?
                .ok_or_else(|| invalid("native roster retirement hydration missing"))?;
            if hydrated.facts.state != State::Tombstone
                || hydrated.facts.terminal_sequence != Some(*sequence)
                || profile(hydrated.projection.profile) != *tag
                || hydrated.reserved_key().is_some()
            {
                return Err(invalid(
                    "native roster retirement order or reservation differs",
                ));
            }
            let _planning = planner_memory(&hydrated)?;
            let action = stream
                .push(match hydrated.body() {
                    carrier::Body::V1(row) => {
                        ProductionMixedTerminalRetirementSelection::V1(row.record())
                    }
                    carrier::Body::V2(row) => {
                        ProductionMixedTerminalRetirementSelection::V2(row.record())
                    }
                })
                .map_err(corrupt)?;
            let expected = match (action.v1_delete(), action.v2_delete()) {
                (Some(expected), None) if *tag == ProductionRosterProfileTag::V1 => {
                    expected.to_canonical_bytes().map_err(corrupt)?
                }
                (None, Some(expected)) if *tag == ProductionRosterProfileTag::V2 => {
                    expected.to_canonical_bytes().map_err(corrupt)?
                }
                _ => return Err(invalid("native roster retirement action profile differs")),
            };
            if action.binding() != *binding || !before.matches_canonical(&expected) {
                return Err(invalid(
                    "native roster retirement canonical predecessor differs",
                ));
            }
            next.index = next.index.replaced(*binding, Some(before), None)?;
            next.replace_row(*binding, None)?;
        }
        let closure = stream.finish(&partitions).map_err(corrupt)?;
        if closure.previous != witness
            || self.ledger.witness != Some(witness)
            || closure.guard.selected() != selected
            || selected != retirement_selection(&self.ledger, witness)?
            || closure.guard.partitions().len() != closure.floor_actions.len()
        {
            return Err(invalid(
                "native roster retirement prefix or witness differs",
            ));
        }
        for action in &closure.floor_actions {
            Self::partition_cas(&mut next, Some(action.floor()), Some(action.cursor()))
                .map_err(corrupt)?;
            let key = action.floor().key();
            if next.partitions.contains_key(&key) != (next.index.partition_count(key) != 0) {
                return Err(invalid(
                    "native roster retirement partition closure differs",
                ));
            }
        }
        next.witness = Some(closure.next);
        Ok(next)
    }
}
