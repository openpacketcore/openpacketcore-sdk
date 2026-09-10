//! Persistent scalar indexes for both roster profiles. A failed replacement
//! returns no new root, so it cannot leave a partially updated access path.

use super::*;
use crate::fenced_mutation_roster::{session_key_commitment, RECLAIM_BATCH};
use std::ops::Bound::{Excluded, Included, Unbounded};

#[derive(Clone, PartialEq, Eq)]
struct Indexed {
    profile: Profile,
    stable: [u8; 32],
    requests: [[u8; 16]; 2],
    facts: Facts,
    reserved: bool,
    original: (crate::OwnerId, u64, u64),
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct OriginalLookup {
    key: [u8; 32],
    roster: [u8; 16],
    owner: crate::OwnerId,
    fence: u64,
    generation: u64,
}

impl OriginalLookup {
    fn of(binding: RequestBindingKey, original: &(crate::OwnerId, u64, u64)) -> Self {
        let bytes = binding.to_bytes();
        let mut roster = [0; 16];
        roster.copy_from_slice(&bytes[104..]);
        Self {
            key: binding.session_key_commitment(),
            roster,
            owner: original.0.clone(),
            fence: original.1,
            generation: original.2,
        }
    }
}

/// Constructed only while a complete authenticated carrier is alive. The
/// cold catalog removes all changed predecessors before inserting these
/// entries, allowing a valid same-checkpoint reservation handoff in any order.
pub(in crate::consensus::native) struct CatalogEntry {
    binding: RequestBindingKey,
    indexed: Indexed,
}

impl CatalogEntry {
    pub(in crate::consensus::native) fn of(row: &carrier::Hydration) -> io::Result<Self> {
        if row.reserved_key().is_some_and(|key| {
            session_key_commitment(key) != row.binding().session_key_commitment()
        }) {
            return Err(invalid(
                "native catalog reservation key differs from its full binding",
            ));
        }
        Ok(Self {
            binding: row.binding(),
            indexed: Indexed::hydrated(row),
        })
    }
}

impl Indexed {
    fn of(row: &Row) -> Self {
        let (owner, fence, generation) = row.projection().original.recovery_parts();
        Self {
            profile: row.projection().profile,
            stable: row.projection().stable_slot,
            requests: row.projection().request_ids(),
            facts: row.facts(),
            reserved: row.reserved_key().is_some(),
            original: (owner.clone(), fence, generation),
        }
    }

    fn hydrated(row: &carrier::Hydration) -> Self {
        let (owner, fence, generation) = row.projection.original.recovery_parts();
        Self {
            profile: row.projection.profile,
            stable: row.projection.stable_slot,
            requests: row.projection.request_ids(),
            facts: row.facts,
            reserved: row.reserved_key().is_some(),
            original: (owner.clone(), fence, generation),
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct Index {
    bindings: ResidentMap<RequestBindingKey, Indexed>,
    stable: ResidentMap<[u8; 32], RequestBindingKey>,
    requests: [ResidentMap<[u8; 16], RequestBindingKey>; 2],
    reservations: ResidentMap<[u8; 32], RequestBindingKey>,
    partitions: imbl::OrdMap<ProductionFloorKey, imbl::OrdMap<RequestBindingKey, Facts>>,
    epochs: imbl::OrdMap<(ProductionFloorKey, u64), usize>,
    terminals: imbl::OrdMap<u64, RequestBindingKey>,
    retained: imbl::OrdSet<(i128, RequestBindingKey)>,
    non_tombstones: imbl::OrdSet<(ProductionFloorKey, RequestBindingKey)>,
    original_v1: ResidentMap<OriginalLookup, imbl::OrdSet<RequestBindingKey>>,
}

impl Index {
    pub(crate) fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Exact original-lineage lookup has the same ambiguity rule as SQL's
    /// LIMIT 2 query, without scanning retained configurations or carriers.
    pub(super) fn original_v1(
        &self,
        key: &SessionKey,
        roster: crate::fenced_mutation_roster::RosterId,
        owner: &crate::OwnerId,
        fence: crate::FenceToken,
        generation: crate::Generation,
    ) -> Result<Option<RequestBindingKey>, crate::sqlite::consensus::ProtectedRosterApplyError>
    {
        use crate::sqlite::consensus::ProtectedRosterApplyError as Error;
        // Preserve the original SQL positive-i64 lookup domain even for a
        // missing lineage. Live-lease validation intentionally does not
        // establish the caller's historical generation.
        if fence.get() == 0
            || fence.get() > i64::MAX as u64
            || generation.get() == 0
            || generation.get() > i64::MAX as u64
        {
            return Err(Error::Rejected);
        }
        let lookup = OriginalLookup {
            key: session_key_commitment(key),
            roster: *roster.as_bytes(),
            owner: owner.clone(),
            fence: fence.get(),
            generation: generation.get(),
        };
        let Some(rows) = self.original_v1.get(&lookup) else {
            return Ok(None);
        };
        if rows.len() != 1 {
            return Err(Error::Rejected);
        }
        rows.get_min().copied().map(Some).ok_or(Error::Corrupt)
    }

    pub(crate) fn stable(
        &self,
        slot: [u8; 32],
        profile: Profile,
    ) -> io::Result<Option<RequestBindingKey>> {
        let Some(binding) = self.stable.get(&slot) else {
            return Ok(None);
        };
        let row = self
            .bindings
            .get(binding)
            .ok_or_else(|| invalid("native roster stable index is orphaned"))?;
        // SQL keeps two namespaces and returns absence in the other profile.
        // Global insertion still checks cross-profile slot and request aliases.
        Ok((row.profile == profile).then_some(*binding))
    }

    pub(crate) fn reservation(&self, key: &SessionKey) -> Option<RequestBindingKey> {
        self.reservations.get(&session_key_commitment(key)).copied()
    }

    pub(in crate::consensus::native) fn reservation_commitment(
        &self,
        key: [u8; 32],
    ) -> Option<RequestBindingKey> {
        self.reservations.get(&key).copied()
    }

    pub(in crate::consensus::native) fn reservation_count(&self) -> usize {
        self.reservations.len()
    }
    pub(in crate::consensus::native) fn partition_len(&self) -> usize {
        self.partitions.len()
    }

    pub(in crate::consensus::native) fn validate_retired(&self, retired: u64) -> io::Result<()> {
        if self
            .terminals
            .get_min()
            .is_some_and(|(sequence, _)| *sequence <= retired)
        {
            return Err(invalid(
                "native roster retained terminal lies within retired history",
            ));
        }
        Ok(())
    }

    /// The same floor/cursor predicate as full hydration, using ordered extrema
    /// and a separate ordered non-tombstone set. A floor update cannot skip an
    /// untouched older or live row; no whole-ledger scan is needed per delta.
    pub(in crate::consensus::native) fn validate_partition(
        &self,
        key: ProductionFloorKey,
        partition: &Partition,
    ) -> io::Result<()> {
        partition.validate(key)?;
        let Some((first, _)) = self.partition_bounds(key) else {
            return Err(invalid("native roster contains an orphan partition"));
        };
        partition
            .floor
            .validate_new_binding(first)
            .map_err(|_| invalid("native roster row lies below its partition floor"))?;
        if let Some(cursor) = &partition.cursor {
            if first.history_epoch() <= cursor.target_epoch() {
                if first.history_epoch() != cursor.target_epoch()
                    || cursor.last_deleted().is_some_and(|last| first <= last)
                    || self
                        .non_tombstones
                        .range((Included((key, first)), Unbounded))
                        .next()
                        .is_some_and(|(other, binding)| {
                            *other == key && binding.history_epoch() <= cursor.target_epoch()
                        })
                {
                    return Err(invalid(
                        "native roster row lies outside its retirement cursor",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn partition_count(&self, key: ProductionFloorKey) -> usize {
        self.partitions.get(&key).map_or(0, imbl::OrdMap::len)
    }

    pub(crate) fn epoch_count(&self, key: ProductionFloorKey, epoch: u64) -> usize {
        self.epochs.get(&(key, epoch)).copied().unwrap_or(0)
    }

    pub(crate) fn partition_bounds(
        &self,
        key: ProductionFloorKey,
    ) -> Option<(RequestBindingKey, RequestBindingKey)> {
        let rows = self.partitions.get(&key)?;
        Some((rows.get_min()?.0, rows.get_max()?.0))
    }

    /// At most one original retirement page plus its lookahead. Epoch filtering
    /// follows the ordered seek; earlier epochs are checked through bounds.
    #[cfg(test)]
    pub(crate) fn partition_prefix(
        &self,
        key: ProductionFloorKey,
        epoch: u64,
        after: Option<RequestBindingKey>,
    ) -> Vec<(RequestBindingKey, Facts)> {
        let Some(rows) = self.partitions.get(&key) else {
            return Vec::new();
        };
        match after {
            Some(after) => rows
                .range((Excluded(after), Unbounded))
                .take_while(|(binding, _)| binding.history_epoch() == epoch)
                .take(RECLAIM_BATCH + 1)
                .map(|(binding, facts)| (*binding, *facts))
                .collect(),
            None => rows
                .iter()
                .take_while(|(binding, _)| binding.history_epoch() == epoch)
                .take(RECLAIM_BATCH + 1)
                .map(|(binding, facts)| (*binding, *facts))
                .collect(),
        }
    }

    pub(crate) fn reclaim_prefix(&self, cutoff: i128) -> Vec<(i128, RequestBindingKey)> {
        self.retained
            .iter()
            .take_while(|(at, _)| *at <= cutoff)
            .take(RECLAIM_BATCH)
            .copied()
            .collect()
    }

    pub(crate) fn has_due_retained(&self, cutoff: i128) -> bool {
        self.retained
            .iter()
            .next()
            .is_some_and(|(at, _)| *at <= cutoff)
    }

    pub(crate) fn first_terminal_state(&self, retired_through: u64) -> io::Result<Option<State>> {
        let Some((sequence, binding)) = self
            .terminals
            .range((Excluded(retired_through), Unbounded))
            .next()
        else {
            return Ok(None);
        };
        let row = self
            .bindings
            .get(binding)
            .ok_or_else(|| invalid("native roster terminal index is orphaned"))?;
        if row.facts.terminal_sequence != Some(*sequence) || row.facts.state == State::Live {
            return Err(invalid("native roster terminal index differs"));
        }
        Ok(Some(row.facts.state))
    }

    pub(crate) fn terminal_prefix(
        &self,
        retired_through: u64,
    ) -> io::Result<Vec<(u64, RequestBindingKey, State)>> {
        self.terminals
            .range((Excluded(retired_through), Unbounded))
            .take(RECLAIM_BATCH + 1)
            .map(|(sequence, binding)| {
                let row = self
                    .bindings
                    .get(binding)
                    .ok_or_else(|| invalid("native roster terminal index is orphaned"))?;
                if row.facts.terminal_sequence != Some(*sequence) || row.facts.state == State::Live
                {
                    return Err(invalid("native roster terminal index differs"));
                }
                Ok((*sequence, *binding, row.facts.state))
            })
            .collect()
    }

    /// Prepare the complete index replacement against one exact predecessor.
    /// Full cryptographic, partition, business and witness admission belongs to
    /// the caller; this method proves uniqueness and index conservation.
    pub(crate) fn replaced(
        &self,
        binding: RequestBindingKey,
        before: Option<&Row>,
        after: Option<&Row>,
    ) -> io::Result<Self> {
        if before.is_some_and(|row| row.binding != binding)
            || after.is_some_and(|row| row.binding != binding)
            || self.bindings.get(&binding) != before.map(Indexed::of).as_ref()
        {
            return Err(invalid("native roster index predecessor differs"));
        }
        let mut next = self.clone();
        if let Some(row) = before {
            next.remove(binding, &Indexed::of(row))?;
        }
        if let Some(row) = after {
            next.insert(binding, Indexed::of(row), row.reserved_key())?;
        }
        Ok(next)
    }

    /// Cold decoding has already compared the complete prior row fingerprint.
    /// Insert metadata only from this fully authenticated hydration; this
    /// method does not manufacture an unselected Row or a ledger certificate.
    pub(in crate::consensus::native) fn replaced_hydration(
        &self,
        binding: RequestBindingKey,
        after: Option<&carrier::Hydration>,
    ) -> io::Result<Self> {
        if after.is_some_and(|row| row.binding() != binding) {
            return Err(invalid("native roster decoded binding differs"));
        }
        let mut next = self.clone();
        if let Some(before) = self.bindings.get(&binding) {
            next.remove(binding, before)?;
        }
        if let Some(after) = after {
            next.insert(binding, Indexed::hydrated(after), after.reserved_key())?;
        }
        Ok(next)
    }

    pub(in crate::consensus::native) fn insert_catalog(
        &mut self,
        entry: &CatalogEntry,
    ) -> io::Result<()> {
        let mut next = self.clone();
        next.insert(entry.binding, entry.indexed.clone(), None)?;
        *self = next;
        Ok(())
    }

    fn remove(&mut self, binding: RequestBindingKey, row: &Indexed) -> io::Result<()> {
        if self.bindings.remove(&binding).as_ref() != Some(row)
            || self.stable.remove(&row.stable) != Some(binding)
        {
            return Err(invalid("native roster index removal differs"));
        }
        if row.profile == Profile::V1 {
            let lookup = OriginalLookup::of(binding, &row.original);
            let mut rows = self
                .original_v1
                .get(&lookup)
                .cloned()
                .ok_or_else(|| invalid("native roster original index missing"))?;
            if rows.remove(&binding).is_none() {
                return Err(invalid("native roster original index differs"));
            }
            if rows.is_empty() {
                self.original_v1.remove(&lookup);
            } else {
                self.original_v1.insert(lookup, rows);
            }
        }
        for (index, id) in row.requests.iter().enumerate() {
            if self.requests[index].remove(id) != Some(binding) {
                return Err(invalid("native roster request index removal differs"));
            }
        }
        if row.reserved
            && self.reservations.remove(&binding.session_key_commitment()) != Some(binding)
        {
            return Err(invalid("native roster reservation index removal differs"));
        }
        let key = ProductionFloorKey::from_binding(binding)
            .map_err(|_| invalid("native roster partition key invalid"))?;
        let mut partition = self
            .partitions
            .get(&key)
            .cloned()
            .ok_or_else(|| invalid("native roster partition index absent"))?;
        if partition.remove(&binding) != Some(row.facts) {
            return Err(invalid("native roster partition index removal differs"));
        }
        if partition.is_empty() {
            self.partitions.remove(&key);
        } else {
            self.partitions.insert(key, partition);
        }
        let epoch_key = (key, binding.history_epoch());
        let count = self
            .epochs
            .get(&epoch_key)
            .copied()
            .ok_or_else(|| invalid("native roster epoch count absent"))?;
        match count {
            0 => return Err(invalid("native roster epoch count is empty")),
            1 => {
                self.epochs.remove(&epoch_key);
            }
            _ => {
                self.epochs.insert(epoch_key, count - 1);
            }
        }
        if let Some(sequence) = row.facts.terminal_sequence {
            if self.terminals.remove(&sequence) != Some(binding) {
                return Err(invalid("native roster terminal index removal differs"));
            }
        }
        if row.facts.state == State::Retained {
            let at = row
                .facts
                .terminalized_at
                .ok_or_else(|| invalid("native retained roster time absent"))?
                .as_nanos();
            if self.retained.remove(&(at, binding)).is_none() {
                return Err(invalid("native retained roster index removal differs"));
            }
        }
        if row.facts.state != State::Tombstone
            && self.non_tombstones.remove(&(key, binding)).is_none()
        {
            return Err(invalid("native roster non-tombstone index removal differs"));
        }
        Ok(())
    }

    fn insert(
        &mut self,
        binding: RequestBindingKey,
        indexed: Indexed,
        reserved_key: Option<&SessionKey>,
    ) -> io::Result<()> {
        if self.bindings.contains_key(&binding)
            || self.stable.contains_key(&indexed.stable)
            || indexed
                .requests
                .iter()
                .enumerate()
                .any(|(index, id)| self.requests[index].contains_key(id))
            || (indexed.reserved
                && self
                    .reservations
                    .contains_key(&binding.session_key_commitment()))
            || indexed
                .facts
                .terminal_sequence
                .is_some_and(|sequence| self.terminals.contains_key(&sequence))
            || reserved_key
                .is_some_and(|key| session_key_commitment(key) != binding.session_key_commitment())
        {
            return Err(invalid("native roster index aliases an existing binding"));
        }
        match indexed.facts.state {
            State::Live
                if indexed.reserved
                    && indexed.facts.terminal_sequence.is_none()
                    && indexed.facts.terminalized_at.is_none()
                    && indexed.facts.terminal_raft_log_index.is_none() => {}
            State::Retained | State::Tombstone
                if !indexed.reserved
                    && indexed
                        .facts
                        .terminal_sequence
                        .is_some_and(|sequence| sequence > 0)
                    && indexed.facts.terminalized_at.is_some()
                    && indexed
                        .facts
                        .terminal_raft_log_index
                        .is_some_and(|index| index > binding.history_epoch()) => {}
            _ => return Err(invalid("native roster index state shape differs")),
        }
        self.stable.insert(indexed.stable, binding);
        if indexed.profile == Profile::V1 {
            let lookup = OriginalLookup::of(binding, &indexed.original);
            let mut rows = self.original_v1.get(&lookup).cloned().unwrap_or_default();
            if rows.insert(binding).is_some() {
                return Err(invalid("native roster original index repeated binding"));
            }
            self.original_v1.insert(lookup, rows);
        }
        for (index, id) in indexed.requests.iter().enumerate() {
            self.requests[index].insert(*id, binding);
        }
        if indexed.reserved {
            self.reservations
                .insert(binding.session_key_commitment(), binding);
        }
        let key = ProductionFloorKey::from_binding(binding)
            .map_err(|_| invalid("native roster partition key invalid"))?;
        let mut partition = self.partitions.get(&key).cloned().unwrap_or_default();
        partition.insert(binding, indexed.facts);
        self.partitions.insert(key, partition);
        let epoch_key = (key, binding.history_epoch());
        let count = self
            .epoch_count(key, binding.history_epoch())
            .checked_add(1)
            .ok_or_else(|| invalid("native roster epoch count overflow"))?;
        self.epochs.insert(epoch_key, count);
        if let Some(sequence) = indexed.facts.terminal_sequence {
            self.terminals.insert(sequence, binding);
        }
        if indexed.facts.state == State::Retained {
            let at = indexed
                .facts
                .terminalized_at
                .ok_or_else(|| invalid("native retained roster time absent"))?
                .as_nanos();
            self.retained.insert((at, binding));
        }
        if indexed.facts.state != State::Tombstone {
            self.non_tombstones.insert((key, binding));
        }
        self.bindings.insert(binding, indexed);
        Ok(())
    }
}
