//! Streaming V4 roster admission. Changed rows retain only independent scalar
//! metadata, while original carriers, signatures, charges and business values
//! are checked under their existing guards. The index is prospective resident
//! state; temporary changed-ID vectors use the shared verification budget.

use super::*;
use crate::consensus::native::resident::RowFingerprint;
use crate::fenced_mutation_roster::{
    RequestBindingKey, RosterAttestationTrustRootV1, MAX_RESERVED_AND_RETAINED, TERMINAL_RETENTION,
};
use crate::fenced_mutation_roster_storage::{
    GlobalChargeBudget, GlobalChargeWitness, ProductionFloorKey, ProductionSnapshotAccounting,
};
use crate::sqlite::consensus::MembershipValidationScope;
use roster::catalog::Metadata;
use roster::{Partition, State};

pub(super) struct Entry {
    pub(super) range: Range,
    pub(super) row: Metadata,
}
struct PartitionEntry {
    row: Partition,
    content: [u8; 32],
    charge: ProductionSnapshotAccounting,
}

pub(super) struct Rosters {
    pub(super) rows: HashMap<RequestBindingKey, Entry>,
    partitions: HashMap<ProductionFloorKey, PartitionEntry>,
    index: roster::Index,
    charges: ProductionSnapshotAccounting,
    summary: [Summary; 2],
    reserved_keys: usize,
    invalid_business: usize,
}

struct Changed {
    binding: RequestBindingKey,
    retired: Option<u64>,
}
struct PartitionEvent {
    key: ProductionFloorKey,
    introduced: u64,
    removed: u64,
    removed_rows: u64,
    required_floors: [Option<u64>; 2],
    matched_floors: [bool; 2],
    removed_floor: Option<u64>,
    final_removal: bool,
}

fn witness(context: &Context) -> Option<GlobalChargeWitness> {
    context
        .business
        .roster
        .as_ref()
        .and_then(|roster| roster.witness)
}
fn retired(context: &Context) -> u64 {
    witness(context).map_or(0, GlobalChargeWitness::retired_terminal_sequence)
}

fn endpoint(
    before: bool,
    after: bool,
    counts: [u64; 2],
    removed: bool,
    base: bool,
) -> io::Result<()> {
    if counts.into_iter().any(|count| count > COUNTER_MAX)
        || removed != (counts[1] != 0)
        || u64::from(before)
            .checked_add(counts[0])
            .and_then(|count| count.checked_sub(counts[1]))
            != Some(u64::from(after))
        || (base && (before || !after || counts != [1, 0] || removed))
        || (!before && !after && counts == [0, 0])
    {
        return Err(invalid(
            "native roster generation lifecycle does not conserve its endpoints",
        ));
    }
    Ok(())
}

fn counts(reader: &mut Cursor<'_>) -> io::Result<[u64; 2]> {
    Ok([
        u64::from_le_bytes(reader.scalar()?),
        u64::from_le_bytes(reader.scalar()?),
    ])
}

fn partition(
    reader: &mut Cursor<'_>,
    key: ProductionFloorKey,
) -> io::Result<Option<PartitionEntry>> {
    if !reader.present()? {
        return Ok(None);
    }
    let (_, input) = reader.bytes(roster::frame::MAX_PARTITION)?;
    let (actual, row) = roster::frame::read_partition(
        &mut io::Cursor::new(input.bytes()),
        input.bytes().len() as u32,
    )?;
    if actual != key {
        return Err(invalid("native catalog roster partition identity differs"));
    }
    let content = row.row_fingerprint(5, &key.as_bytes().as_slice())?;
    let charge = row.accounting()?;
    Ok(Some(PartitionEntry {
        row,
        content,
        charge,
    }))
}

fn partition_transition(before: Option<&Partition>, after: &Partition) -> io::Result<Option<u64>> {
    let previous = before.map_or(0, |row| row.floor.retired_through());
    if after.floor.retired_through() < previous {
        return Err(invalid(
            "native roster generation partition floor regressed",
        ));
    }
    let old_cursor = before.and_then(|row| row.cursor.as_ref());
    // The original mixed-profile terminal stream preserves a binding-order
    // cursor until the final target epoch consumes it. It cannot create or
    // advance one, including across a released/recreated partition.
    if after.cursor.as_ref() != old_cursor
        && !(after.cursor.is_none()
            && old_cursor.is_some_and(|old| after.floor.retired_through() >= old.target_epoch()))
    {
        return Err(invalid(
            "native roster generation retirement cursor has no original transition",
        ));
    }
    Ok((after.floor.retired_through() > previous).then_some(after.floor.retired_through()))
}

fn row(
    reader: &mut Cursor<'_>,
    binding: RequestBindingKey,
    root: Option<&RosterAttestationTrustRootV1>,
    scope: &MembershipValidationScope,
    after: &Context,
    accounting_witness: Option<GlobalChargeWitness>,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Option<Entry>> {
    if !reader.present()? {
        return Ok(None);
    }
    let root = root.ok_or_else(|| invalid("native catalog roster configured root absent"))?;
    let (range, input) = reader.bytes(roster::frame::MAX_ROW)?;
    let hydrated = roster::frame::read_row(
        &mut io::Cursor::new(input.bytes()),
        input.bytes().len() as u32,
        root,
        scope,
    )?;
    if hydrated.binding() != binding {
        return Err(invalid("native catalog roster full binding differs"));
    }
    let frontiers = &after.business.frontiers;
    let activated = match hydrated.projection.profile {
        roster::Profile::V1 => frontiers.roster_v1_namespace,
        roster::Profile::V2 => frontiers.roster_v2_activation.is_some(),
    };
    if !activated {
        return Err(invalid(
            "native catalog roster precedes its profile namespace",
        ));
    }
    if let Some(at) = hydrated.facts.terminalized_at {
        let at = at.as_nanos();
        let now = frontiers
            .logical_time
            .ok_or_else(|| invalid("native catalog roster terminal time absent"))?
            .as_offset_datetime()
            .unix_timestamp_nanos();
        if at > now {
            return Err(invalid(
                "native catalog roster terminal exceeds logical time",
            ));
        }
        if hydrated.facts.state == State::Tombstone {
            let retention = i128::try_from(TERMINAL_RETENTION.as_nanos())
                .map_err(|_| invalid("native catalog roster retention overflow"))?;
            if at.checked_add(retention).is_none_or(|due| due > now) {
                return Err(invalid(
                    "native catalog roster reclaimed before its original retention",
                ));
            }
        }
    }
    let row = Metadata::of(
        &hydrated,
        frontiers.sequence,
        frontiers.applied.map(|id| id.index),
        accounting_witness,
    )?;
    check()?;
    Ok(Some(Entry { range, row }))
}

fn new_history(
    before: Option<&Metadata>,
    after: &Metadata,
    context: &Context,
    base: bool,
) -> io::Result<()> {
    if base {
        return Ok(());
    }
    if before.is_none_or(|row| row.facts.state == State::Live)
        && after.facts.state != State::Live
        && (after
            .facts
            .terminal_sequence
            .is_none_or(|sequence| sequence <= context.business.frontiers.sequence)
            || after.facts.terminal_raft_log_index.is_none_or(|index| {
                index <= context.business.frontiers.applied.map_or(0, |id| id.index)
            }))
    {
        return Err(invalid(
            "native catalog roster terminal predates its checkpoint predecessor",
        ));
    }
    Ok(())
}

impl Rosters {
    pub(super) fn new() -> Self {
        Self {
            rows: HashMap::new(),
            partitions: HashMap::new(),
            index: roster::Index::default(),
            charges: ProductionSnapshotAccounting::empty(),
            summary: [Summary::default(); 2],
            reserved_keys: 0,
            invalid_business: 0,
        }
    }

    pub(super) fn key_replaced(
        &mut self,
        id: facts::KeyId,
        before: Option<&facts::Key>,
        after: &facts::Key,
    ) -> io::Result<()> {
        self.reserved_keys = self
            .reserved_keys
            .checked_sub(usize::from(before.is_some_and(|row| row.reserved)))
            .and_then(|count| count.checked_add(usize::from(after.reserved)))
            .ok_or_else(|| invalid("native catalog reserved business count overflow"))?;
        if let Some(binding) = self.index.reservation_commitment(after.commitment) {
            let row = &self
                .rows
                .get(&binding)
                .ok_or_else(|| invalid("native catalog reservation index is orphaned"))?
                .row;
            if row.key() != Some(id) {
                return Err(invalid(
                    "native catalog reservation full business identity differs",
                ));
            }
            self.invalid_business = self
                .invalid_business
                .checked_sub(usize::from(!row.matches_business(before)))
                .and_then(|count| {
                    count.checked_add(usize::from(!row.matches_business(Some(after))))
                })
                .ok_or_else(|| invalid("native catalog business predicate count overflow"))?;
        }
        Ok(())
    }

    pub(super) fn read(
        &mut self,
        reader: &mut Cursor<'_>,
        before: &Context,
        after: &Context,
        changed: [usize; 2],
        base: bool,
        keys: &HashMap<facts::KeyId, Indexed<facts::Key>>,
        root: Option<&RosterAttestationTrustRootV1>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        if changed
            .into_iter()
            .any(|count| count > validation::MAX_ITEMS)
        {
            return Err(invalid(
                "native roster generation count exceeds original bound",
            ));
        }
        let minimum = (changed[0] as u64)
            .checked_mul(140)
            .and_then(|bytes| bytes.checked_add((changed[1] as u64).checked_mul(84)?))
            .ok_or_else(|| invalid("native roster generation extent overflow"))?;
        if minimum > reader.maximum - reader.position {
            return Err(invalid(
                "native roster generation counts exceed selected extent",
            ));
        }
        let row_count = if base { 0 } else { changed[0] };
        let partition_count = if base { 0 } else { changed[1] };
        let bytes = row_count
            .checked_mul(size_of::<Changed>())
            .and_then(|bytes| {
                bytes.checked_add(partition_count.checked_mul(size_of::<PartitionEvent>())?)
            })
            .ok_or_else(|| invalid("native roster changed metadata reservation overflow"))?;
        let _changed_memory = VerificationMemory::reserve(bytes)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(row_count)
            .map_err(|_| invalid("native roster changed row allocation failed"))?;
        let mut partitions = Vec::new();
        partitions
            .try_reserve_exact(partition_count)
            .map_err(|_| invalid("native roster changed partition allocation failed"))?;
        let mut partitions_retained = false;
        for _ in 0..changed[1] {
            check()?;
            expect(reader, &[5])?;
            let prior = reader.before()?;
            let key = ProductionFloorKey::from_bytes(reader.scalar()?)
                .map_err(|_| invalid("native catalog partition key invalid"))?;
            let lifecycle = counts(reader)?;
            let removed = partition(reader, key)?;
            let next = partition(reader, key)?;
            if next.is_none() && partitions_retained {
                return Err(invalid(
                    "native roster partition removals must precede retained after-images",
                ));
            }
            partitions_retained |= next.is_some();
            let old = self.partitions.get(&key);
            if old.map(|row| row.content) != prior || (base && prior.is_some()) {
                return Err(invalid("native catalog partition predecessor differs"));
            }
            endpoint(
                old.is_some(),
                next.is_some(),
                lifecycle,
                removed.is_some(),
                base,
            )?;
            let mut required_floors = [None; 2];
            if !base {
                if let Some(removed) = &removed {
                    required_floors[0] = partition_transition(
                        if lifecycle[1] == 1 {
                            old.map(|row| &row.row)
                        } else {
                            None
                        },
                        &removed.row,
                    )?;
                }
                if let Some(next) = &next {
                    required_floors[1] = partition_transition(
                        if lifecycle[1] == 0 {
                            old.map(|row| &row.row)
                        } else {
                            None
                        },
                        &next.row,
                    )?;
                }
            }
            for row in removed.iter().chain(next.iter()) {
                if row.row.floor.retired_through()
                    > after.business.frontiers.applied.map_or(0, |id| id.index)
                {
                    return Err(invalid(
                        "native catalog partition floor exceeds applied history",
                    ));
                }
            }
            self.charges
                .replace(
                    old.map(|row| row.charge),
                    next.as_ref().map(|row| row.charge),
                )
                .map_err(|_| invalid("native catalog partition charge differs"))?;
            self.summary[1].replace(prior, next.as_ref().map(|row| row.content))?;
            if let Some(next) = next {
                put(&mut self.partitions, key, next, MAX_RESERVED_AND_RETAINED)?;
            } else {
                self.partitions.remove(&key);
            }
            if !base {
                partitions.push(PartitionEvent {
                    key,
                    introduced: lifecycle[0],
                    removed: lifecycle[1],
                    removed_rows: 0,
                    required_floors,
                    matched_floors: [false; 2],
                    removed_floor: removed.as_ref().map(|row| row.row.floor.retired_through()),
                    final_removal: false,
                });
            }
        }
        partitions.sort_unstable_by_key(|event| event.key);
        if partitions.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(invalid("native catalog repeats a changed roster partition"));
        }
        let scope = roster::fixed_scope(after.business.identity, &after.business.members);
        let mut maximum_retired = retired(before);
        let mut rows_retained = false;
        for _ in 0..changed[0] {
            check()?;
            expect(reader, &[6])?;
            let prior = reader.before()?;
            let binding = RequestBindingKey::from_bytes(reader.scalar()?)
                .map_err(|_| invalid("native catalog roster binding invalid"))?;
            let lifecycle = counts(reader)?;
            let removed = row(reader, binding, root, &scope, after, witness(before), check)?;
            let next = row(reader, binding, root, &scope, after, witness(after), check)?;
            if next.is_none() && rows_retained {
                return Err(invalid(
                    "native roster removals must precede retained after-images",
                ));
            }
            rows_retained |= next.is_some();
            let old = self.rows.get(&binding);
            if old.map(|row| row.row.content) != prior || (base && prior.is_some()) {
                return Err(invalid("native catalog roster predecessor differs"));
            }
            endpoint(
                old.is_some(),
                next.is_some(),
                lifecycle,
                removed.is_some(),
                base,
            )?;
            if lifecycle.into_iter().any(|count| count > 1) || (removed.is_some() && next.is_some())
            {
                return Err(invalid(
                    "native catalog reintroduces a retired roster binding",
                ));
            }
            if !base
                && old.is_none()
                && binding.history_epoch()
                    <= before.business.frontiers.applied.map_or(0, |id| id.index)
            {
                return Err(invalid(
                    "native catalog new roster predates its selected predecessor",
                ));
            }
            let terminal =
                if let Some(removed) = &removed {
                    if removed.row.facts.state != State::Tombstone {
                        return Err(invalid(
                            "native catalog roster removal lacks an authenticated tombstone",
                        ));
                    }
                    let sequence = removed.row.facts.terminal_sequence.ok_or_else(|| {
                        invalid("native catalog retired terminal sequence absent")
                    })?;
                    if sequence <= retired(before) || sequence > retired(after) {
                        return Err(invalid(
                            "native catalog roster removal lies outside terminal retirement",
                        ));
                    }
                    if let Some(old) = old {
                        removed.row.validate_replacement(&old.row)?;
                    }
                    new_history(old.map(|row| &row.row), &removed.row, before, base)?;
                    maximum_retired = maximum_retired.max(sequence);
                    let key = ProductionFloorKey::from_binding(binding)
                        .map_err(|_| invalid("native catalog retired partition key invalid"))?;
                    let position = partitions
                        .binary_search_by_key(&key, |event| event.key)
                        .map_err(|_| {
                            invalid("native catalog roster removal omitted its partition action")
                        })?;
                    let event = &mut partitions[position];
                    event.removed_rows = event.removed_rows.checked_add(1).ok_or_else(|| {
                        invalid("native catalog partition removal count overflow")
                    })?;
                    for (required, matched) in
                        event.required_floors.iter().zip(&mut event.matched_floors)
                    {
                        *matched |= *required == Some(binding.history_epoch());
                    }
                    event.final_removal |= event
                        .removed_floor
                        .is_some_and(|floor| binding.history_epoch() > floor);
                    Some(sequence)
                } else {
                    None
                };
            if let Some(next) = &next {
                if let Some(old) = old {
                    next.row.validate_replacement(&old.row)?;
                }
                new_history(old.map(|row| &row.row), &next.row, before, base)?;
            }
            let business_matches = |row: &Metadata| {
                row.matches_business(
                    row.key()
                        .and_then(|key| keys.get(&key).map(|row| &row.row.facts)),
                )
            };
            self.invalid_business = self
                .invalid_business
                .checked_sub(usize::from(
                    old.is_some_and(|row| !business_matches(&row.row)),
                ))
                .and_then(|count| {
                    count.checked_add(usize::from(
                        next.as_ref().is_some_and(|row| !business_matches(&row.row)),
                    ))
                })
                .ok_or_else(|| invalid("native catalog roster business contribution differs"))?;
            self.charges
                .replace(
                    old.map(|row| row.row.charge),
                    next.as_ref().map(|row| row.row.charge),
                )
                .map_err(|_| invalid("native catalog roster charge differs"))?;
            self.summary[0].replace(prior, next.as_ref().map(|row| row.row.content))?;
            self.index = self.index.replaced_hydration(binding, None)?;
            if let Some(next) = next {
                if base {
                    self.index.insert_catalog(&next.row.index)?;
                }
                put(&mut self.rows, binding, next, MAX_RESERVED_AND_RETAINED)?;
            } else {
                self.rows.remove(&binding);
            }
            if !base {
                rows.push(Changed {
                    binding,
                    retired: terminal,
                });
            }
        }
        rows.sort_unstable_by_key(|change| change.binding);
        if rows
            .windows(2)
            .any(|pair| pair[0].binding == pair[1].binding)
        {
            return Err(invalid("native catalog repeats a changed roster binding"));
        }
        for change in &rows {
            check()?;
            if let Some(row) = self.rows.get(&change.binding) {
                self.index.insert_catalog(&row.row.index)?;
            }
        }
        rows.sort_unstable_by_key(|change| change.retired);
        if rows
            .windows(2)
            .any(|pair| pair[0].retired.is_some() && pair[0].retired == pair[1].retired)
        {
            return Err(invalid(
                "native catalog retired roster terminal sequence aliases",
            ));
        }
        for change in &rows {
            check()?;
            if self.rows.contains_key(&change.binding) {
                let key = ProductionFloorKey::from_binding(change.binding)
                    .map_err(|_| invalid("native catalog roster partition key invalid"))?;
                let partition = self
                    .partitions
                    .get(&key)
                    .ok_or_else(|| invalid("native catalog roster partition absent"))?;
                self.index.validate_partition(key, &partition.row)?;
            }
        }
        if base {
            for (key, partition) in &self.partitions {
                check()?;
                self.index.validate_partition(*key, &partition.row)?;
            }
        } else {
            for event in &partitions {
                check()?;
                if event.removed > event.removed_rows
                    || event.introduced > event.removed_rows.saturating_add(1)
                {
                    return Err(invalid(
                        "native catalog partition lifecycle lacks retired roster history",
                    ));
                }
                if event
                    .required_floors
                    .iter()
                    .zip(event.matched_floors)
                    .any(|(required, matched)| required.is_some() && !matched)
                    || (event.removed_floor.is_some() && !event.final_removal)
                {
                    return Err(invalid(
                        "native catalog partition floor lacks authenticated retirement history",
                    ));
                }
                if let Some(partition) = self.partitions.get(&event.key) {
                    self.index.validate_partition(event.key, &partition.row)?;
                    if event.removed != 0
                        && self
                            .index
                            .partition_bounds(event.key)
                            .is_some_and(|(first, _)| {
                                first.history_epoch()
                                    <= before.business.frontiers.applied.map_or(0, |id| id.index)
                            })
                    {
                        return Err(invalid(
                            "native catalog released partition retains predecessor rows",
                        ));
                    }
                } else if self.index.partition_count(event.key) != 0 {
                    return Err(invalid(
                        "native catalog partition removed with retained rows",
                    ));
                }
            }
            if maximum_retired != retired(after) {
                return Err(invalid(
                    "native catalog terminal retirement has no exact authenticated closure",
                ));
            }
        }
        self.validate(after)?;
        check()
    }

    pub(super) fn validate(&self, context: &Context) -> io::Result<()> {
        let counts = context
            .business
            .roster
            .as_ref()
            .map_or([0; 2], |roster| roster.counts);
        let content = context
            .business
            .roster
            .as_ref()
            .map_or([[0; 32]; 2], |roster| roster.content);
        if counts != [self.rows.len(), self.partitions.len()]
            || counts != self.summary.map(|table| table.count)
            || content != self.summary.map(|table| table.content)
            || self.index.len() != self.rows.len()
            || self.index.partition_len() != self.partitions.len()
            || self.invalid_business != 0
            || self.reserved_keys != self.index.reservation_count()
        {
            return Err(invalid("native catalog roster or business summary differs"));
        }
        self.index.validate_retired(retired(context))?;
        self.charges
            .finish(
                context.business.frontiers.sequence,
                witness(context),
                GlobalChargeBudget::production(),
            )
            .map_err(|_| invalid("native catalog original roster witness differs"))
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        HashMap<RequestBindingKey, Entry>,
        impl Iterator<Item = (ProductionFloorKey, Partition)>,
    ) {
        let Self {
            rows,
            partitions,
            index,
            charges: _,
            summary: _,
            reserved_keys: _,
            invalid_business: _,
        } = self;
        // Drop all prospective uniqueness indexes before reconstructing the
        // final ledger, whose independent indexes enforce the same full keys.
        drop(index);
        (
            rows,
            partitions.into_iter().map(|(key, row)| (key, row.row)),
        )
    }

    pub(super) fn allocation_bound(&self) -> io::Result<usize> {
        let rows = self
            .rows
            .capacity()
            .checked_mul(2)
            .and_then(|count| count.checked_add(16))
            .and_then(|count| count.checked_mul(size_of::<(RequestBindingKey, Entry)>() + 1));
        let partitions = self
            .partitions
            .capacity()
            .checked_mul(2)
            .and_then(|count| count.checked_add(16))
            .and_then(|count| {
                count.checked_mul(size_of::<(ProductionFloorKey, PartitionEntry)>() + 1)
            });
        rows.and_then(|bytes| bytes.checked_add(partitions?))
            .and_then(|bytes| bytes.checked_add(self.index.reservation_count().checked_mul(1024)?))
            .and_then(|bytes| {
                bytes.checked_add(self.index.len().checked_add(1)?.checked_mul(4096)?)
            })
            .ok_or_else(|| invalid("native roster catalog resident allocation accounting overflow"))
    }
}

pub(super) fn validate_context(
    context: &Context,
    root: Option<&RosterAttestationTrustRootV1>,
) -> io::Result<()> {
    let expected = root.map(RosterAttestationTrustRootV1::fingerprint);
    let declared = context
        .business
        .roster
        .as_ref()
        .and_then(|roster| roster.root);
    if declared != expected
        || context.business.roster.as_ref().is_some_and(|roster| {
            roster
                .counts
                .into_iter()
                .any(|count| count > MAX_RESERVED_AND_RETAINED)
                || (root.is_none() && (roster.counts != [0; 2] || roster.witness.is_some()))
        })
    {
        return Err(invalid(
            "native generation roster context differs from independently configured root",
        ));
    }
    Ok(())
}

pub(super) fn transition(before: &Context, after: &Context) -> io::Result<()> {
    if retired(after) < retired(before)
        || (witness(before).is_some() && witness(after).is_none())
        || before
            .business
            .roster
            .as_ref()
            .and_then(|roster| roster.root)
            != after
                .business
                .roster
                .as_ref()
                .and_then(|roster| roster.root)
    {
        return Err(invalid(
            "native generation roster witness or configured root regressed",
        ));
    }
    Ok(())
}
