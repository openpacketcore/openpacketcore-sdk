//! Exact process lineage for roster after-images. Only full ledger admission
//! or an accepted evaluator savepoint creates a certificate. These summaries
//! compare already authenticated rows; nothing here admits serialized facts.

use super::super::changes::{fingerprint, stamp, RowStamp, TableSummary};
use super::super::resident::RowFingerprint;
use super::super::shared::RowValue;
use super::*;
use std::mem::size_of;

impl RowFingerprint for Partition {
    fn row_fingerprint(&self, table: u8, key: &impl Serialize) -> io::Result<[u8; 32]> {
        use super::super::changes::fingerprint;
        let expected = ProductionFloorKey::from_floor(self.floor)
            .map_err(|_| invalid("native roster partition fingerprint key invalid"))?;
        if table != 5
            || fingerprint(table, key, &())?
                != fingerprint(table, &expected.as_bytes().as_slice(), &())?
        {
            return Err(invalid("native roster partition fingerprint key differs"));
        }
        let _memory = VerificationMemory::reserve(frame::MAX_PARTITION)?;
        let mut bytes = Vec::with_capacity(frame::MAX_PARTITION);
        frame::write_partition(&mut bytes, expected, self)?;
        fingerprint(table, key, &bytes)
    }
}

fn partition_stamp(key: ProductionFloorKey, row: &SharedRow<Partition>) -> io::Result<RowStamp> {
    stamp(5, &key.as_bytes().as_slice(), row)
}

pub(in crate::consensus::native) struct Certificate {
    tables: [TableSummary; 2],
    witness: Option<GlobalChargeWitness>,
    // Process-only counts since this admitted base. A create-then-delete
    // cannot disappear merely because both endpoint rows are absent.
    lifecycle: [u64; 4],
    revision: u64,
}

impl Certificate {
    pub(super) fn empty() -> Arc<Self> {
        Arc::new(Self {
            tables: [TableSummary::default(); 2],
            witness: None,
            lifecycle: [0; 4],
            revision: 0,
        })
    }

    pub(super) fn admit(ledger: &Ledger) -> io::Result<Arc<Self>> {
        let mut tables = [TableSummary::default(); 2];
        for (binding, row) in &ledger.rows {
            tables[0].replace(None, Some(stamp(4, binding, row)?))?;
        }
        for (key, row) in &ledger.partitions {
            tables[1].replace(None, Some(partition_stamp(*key, row)?))?;
        }
        Ok(Arc::new(Self {
            tables,
            witness: ledger.witness,
            lifecycle: [0; 4],
            revision: 0,
        }))
    }

    pub(in crate::consensus::native) fn counts(&self) -> [usize; 2] {
        self.tables.map(|table| table.count)
    }
    pub(in crate::consensus::native) fn content(&self) -> [[u8; 32]; 2] {
        self.tables.map(|table| table.checksum)
    }
    pub(in crate::consensus::native) fn witness(&self) -> Option<GlobalChargeWitness> {
        self.witness
    }
}

impl Ledger {
    pub(in crate::consensus::native) fn certificate(&self) -> io::Result<&Arc<Certificate>> {
        if self.certificate.counts() != [self.rows.len(), self.partitions.len()]
            || self.index.len() != self.rows.len()
            || self.certificate.witness != self.witness
        {
            return Err(invalid(
                "native roster certificate no longer matches its ledger",
            ));
        }
        Ok(&self.certificate)
    }
}

pub(in crate::consensus::native) struct Change<T: RowValue> {
    pub(in crate::consensus::native) before: Option<SharedRow<T>>,
    pub(in crate::consensus::native) after: Option<SharedRow<T>>,
    // The last removed original row survives coalescing. A generation must
    // authenticate its tombstone even when both endpoint rows are absent.
    pub(in crate::consensus::native) retired: Option<SharedRow<T>>,
    key_stamp: [u8; 32],
    before_stamp: Option<RowStamp>,
    after_stamp: Option<RowStamp>,
    retired_stamp: Option<RowStamp>,
    introduced: u64,
    removed: u64,
}

fn same<T: RowValue>(left: Option<&SharedRow<T>>, right: Option<&SharedRow<T>>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.ptr_eq(right),
        _ => false,
    }
}

impl<T: RowValue> Change<T> {
    fn follows(&self, before: &Self) -> bool {
        self.key_stamp == before.key_stamp
            && same(self.before.as_ref(), before.after.as_ref())
            && self.before_stamp == before.after_stamp
            && before.introduced.checked_add(self.introduced).is_some()
            && before.removed.checked_add(self.removed).is_some()
    }

    fn checked(
        &self,
        key_stamp: [u8; 32],
        before: Option<RowStamp>,
        after: Option<RowStamp>,
        retired: Option<RowStamp>,
        table: &mut TableSummary,
        lifecycle: &mut [u64],
    ) -> io::Result<()> {
        if key_stamp != self.key_stamp
            || before != self.before_stamp
            || after != self.after_stamp
            || retired != self.retired_stamp
            || retired.is_some() != (self.removed != 0)
            || u64::from(before.is_some())
                .checked_add(self.introduced)
                .and_then(|count| count.checked_sub(self.removed))
                != Some(u64::from(after.is_some()))
        {
            return Err(invalid("native roster captured row fingerprint differs"));
        }
        table.replace(before, after)?;
        lifecycle[0] = lifecycle[0]
            .checked_add(self.introduced)
            .ok_or_else(|| invalid("native roster introduction count overflow"))?;
        lifecycle[1] = lifecycle[1]
            .checked_add(self.removed)
            .ok_or_else(|| invalid("native roster removal count overflow"))?;
        Ok(())
    }

    pub(in crate::consensus::native) fn predecessor_content(&self) -> Option<[u8; 32]> {
        self.before_stamp.map(|stamp| stamp.content())
    }
    pub(in crate::consensus::native) fn lifecycle(&self) -> [u64; 2] {
        [self.introduced, self.removed]
    }
}

/// A bounded private candidate for one Q1/Q2 or maintenance transaction. Its
/// row and partition inventories are allocated before the evaluator writes.
/// Every candidate, including its inventory, is discarded on a late failure.
pub(super) struct Edit {
    pub(super) ledger: Ledger,
    base: Arc<Certificate>,
    tables: [TableSummary; 2],
    lifecycle: [u64; 4],
    row_changes: Vec<(RequestBindingKey, Change<Row>)>,
    partition_changes: Vec<(ProductionFloorKey, Change<Partition>)>,
    row_limit: usize,
    partition_limit: usize,
    memory: Arc<VerificationMemory>,
}

impl std::ops::Deref for Edit {
    type Target = Ledger;
    fn deref(&self) -> &Ledger {
        &self.ledger
    }
}
impl std::ops::DerefMut for Edit {
    fn deref_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }
}

impl Edit {
    pub(super) fn new(ledger: &Ledger, rows: usize, partitions: usize) -> io::Result<Self> {
        let base = Arc::clone(ledger.certificate()?);
        // Includes the candidate vectors, both journal hash tables during
        // transfer/growth, and certificate/reference metadata. Actual row
        // bodies retain their separate original lifetime reservations.
        let bytes =
            rows.checked_mul(8 * (size_of::<(RequestBindingKey, Change<Row>)>() + 1))
                .and_then(|bytes| {
                    bytes.checked_add(partitions.checked_mul(
                        8 * (size_of::<(ProductionFloorKey, Change<Partition>)>() + 1),
                    )?)
                })
                .and_then(|bytes| bytes.checked_add(4 * size_of::<Certificate>() + 1024))
                .ok_or_else(|| invalid("native roster change allocation overflow"))?;
        let memory = Arc::new(VerificationMemory::reserve(bytes)?);
        Ok(Self {
            ledger: ledger.clone(),
            tables: base.tables,
            lifecycle: base.lifecycle,
            base,
            row_changes: Vec::with_capacity(rows),
            partition_changes: Vec::with_capacity(partitions),
            row_limit: rows,
            partition_limit: partitions,
            memory,
        })
    }

    pub(super) fn replace_row(
        &mut self,
        binding: RequestBindingKey,
        after: Option<SharedRow<Row>>,
    ) -> io::Result<()> {
        if self.row_changes.len() == self.row_limit
            || self.row_changes.iter().any(|(key, _)| *key == binding)
        {
            return Err(invalid(
                "native roster savepoint row inventory exceeded or repeated",
            ));
        }
        let before = self.ledger.rows.get(&binding).cloned();
        let before_stamp = before
            .as_ref()
            .map(|row| stamp(4, &binding, row))
            .transpose()?;
        let after_stamp = after
            .as_ref()
            .map(|row| stamp(4, &binding, row))
            .transpose()?;
        self.tables[0].replace(before_stamp, after_stamp)?;
        let introduced = u64::from(before.is_none() && after.is_some());
        let removed = u64::from(before.is_some() && after.is_none());
        self.lifecycle[0] = self.lifecycle[0]
            .checked_add(introduced)
            .ok_or_else(|| invalid("native roster introduction counter exhausted"))?;
        self.lifecycle[1] = self.lifecycle[1]
            .checked_add(removed)
            .ok_or_else(|| invalid("native roster removal counter exhausted"))?;
        match &after {
            Some(row) => {
                self.ledger.rows.insert(binding, row.clone());
            }
            None => {
                self.ledger.rows.remove(&binding);
            }
        }
        let retired = (removed != 0).then(|| before.clone()).flatten();
        let retired_stamp = (removed != 0).then_some(before_stamp).flatten();
        self.row_changes.push((
            binding,
            Change {
                before,
                after,
                retired,
                key_stamp: fingerprint(4, &binding, &())?,
                before_stamp,
                after_stamp,
                retired_stamp,
                introduced,
                removed,
            },
        ));
        Ok(())
    }

    pub(super) fn replace_partition(
        &mut self,
        key: ProductionFloorKey,
        value: Option<Partition>,
    ) -> io::Result<()> {
        let before = self.ledger.partitions.get(&key).cloned();
        if before.as_deref() == value.as_ref() {
            return Ok(());
        }
        if self.partition_changes.len() == self.partition_limit
            || self.partition_changes.iter().any(|(seen, _)| *seen == key)
        {
            return Err(invalid(
                "native roster savepoint partition inventory exceeded or repeated",
            ));
        }
        if let Some(value) = &value {
            value.validate(key)?;
        }
        let after = value.map(SharedRow::new).transpose()?;
        let before_stamp = before
            .as_ref()
            .map(|row| partition_stamp(key, row))
            .transpose()?;
        let after_stamp = after
            .as_ref()
            .map(|row| partition_stamp(key, row))
            .transpose()?;
        self.tables[1].replace(before_stamp, after_stamp)?;
        let introduced = u64::from(before.is_none() && after.is_some());
        let removed = u64::from(before.is_some() && after.is_none());
        self.lifecycle[2] = self.lifecycle[2]
            .checked_add(introduced)
            .ok_or_else(|| invalid("native roster partition introduction counter exhausted"))?;
        self.lifecycle[3] = self.lifecycle[3]
            .checked_add(removed)
            .ok_or_else(|| invalid("native roster partition removal counter exhausted"))?;
        match &after {
            Some(row) => {
                self.ledger.partitions.insert(key, row.clone());
            }
            None => {
                self.ledger.partitions.remove(&key);
            }
        }
        let retired = (removed != 0).then(|| before.clone()).flatten();
        let retired_stamp = (removed != 0).then_some(before_stamp).flatten();
        self.partition_changes.push((
            key,
            Change {
                before,
                after,
                retired,
                key_stamp: fingerprint(5, &key.as_bytes().as_slice(), &())?,
                before_stamp,
                after_stamp,
                retired_stamp,
                introduced,
                removed,
            },
        ));
        Ok(())
    }

    pub(super) fn finish(mut self) -> io::Result<(Ledger, Journal)> {
        if !Arc::ptr_eq(&self.base, &self.ledger.certificate)
            || self.tables.map(|table| table.count)
                != [self.ledger.rows.len(), self.ledger.partitions.len()]
            || self.ledger.index.len() != self.ledger.rows.len()
        {
            return Err(invalid(
                "native roster savepoint inventory differs from its candidate",
            ));
        }
        let target = if self.row_changes.is_empty()
            && self.partition_changes.is_empty()
            && self.ledger.witness == self.base.witness
        {
            Arc::clone(&self.base)
        } else {
            Arc::new(Certificate {
                tables: self.tables,
                witness: self.ledger.witness,
                lifecycle: self.lifecycle,
                revision: self
                    .base
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| invalid("native roster revision exhausted"))?,
            })
        };
        self.ledger.certificate = Arc::clone(&target);
        let journal = Journal {
            base: self.base,
            target,
            rows: self.row_changes.into_iter().collect(),
            partitions: self.partition_changes.into_iter().collect(),
            memory: vec![self.memory],
        };
        journal.validate(&|| Ok(()))?;
        Ok((self.ledger, journal))
    }
}

/// One original before-image and latest exact after-image per touched key.
/// The journal owns no full-ledger roots and is never cloned by a capture.
pub(in crate::consensus::native) struct Journal {
    base: Arc<Certificate>,
    target: Arc<Certificate>,
    pub(in crate::consensus::native) rows: HashMap<RequestBindingKey, Change<Row>>,
    pub(in crate::consensus::native) partitions: HashMap<ProductionFloorKey, Change<Partition>>,
    memory: Vec<Arc<VerificationMemory>>,
}

impl Journal {
    pub(in crate::consensus::native) fn empty(ledger: &Ledger) -> io::Result<Self> {
        Ok(Self::empty_at(ledger.certificate()?))
    }

    pub(in crate::consensus::native) fn empty_at(base: &Arc<Certificate>) -> Self {
        Self {
            target: Arc::clone(base),
            base: Arc::clone(base),
            rows: HashMap::new(),
            partitions: HashMap::new(),
            memory: Vec::new(),
        }
    }

    pub(in crate::consensus::native) fn starts_at(&self, base: &Arc<Certificate>) -> bool {
        Arc::ptr_eq(&self.base, base)
    }
    pub(in crate::consensus::native) fn target(&self) -> &Arc<Certificate> {
        &self.target
    }

    pub(in crate::consensus::native) fn require_base(&self, ledger: &Ledger) -> io::Result<()> {
        if !self.starts_at(ledger.certificate()?)
            || self
                .rows
                .iter()
                .any(|(key, change)| !same(change.before.as_ref(), ledger.rows.get(key)))
            || self
                .partitions
                .iter()
                .any(|(key, change)| !same(change.before.as_ref(), ledger.partitions.get(key)))
        {
            return Err(invalid(
                "native roster journal is not its exact predecessor ledger",
            ));
        }
        Ok(())
    }

    pub(in crate::consensus::native) fn require_current(&self, ledger: &Ledger) -> io::Result<()> {
        if !Arc::ptr_eq(&self.target, ledger.certificate()?)
            || self
                .rows
                .iter()
                .any(|(key, change)| !same(change.after.as_ref(), ledger.rows.get(key)))
            || self
                .partitions
                .iter()
                .any(|(key, change)| !same(change.after.as_ref(), ledger.partitions.get(key)))
        {
            return Err(invalid(
                "native roster journal is not its exact current ledger",
            ));
        }
        Ok(())
    }

    pub(in crate::consensus::native) fn append(&mut self, next: Self) -> io::Result<()> {
        // Only the new bounded fragment is visited here. Revalidating the
        // entire accumulated journal per command would be quadratic.
        next.validate(&|| Ok(()))?;
        self.prepare_append(next)?.commit();
        Ok(())
    }

    /// The fragment was fully validated by detached publication preparation.
    /// With exclusive ownership, only exact lineage and allocation remain.
    /// This phase performs no serialization, carrier hydration or file I/O.
    pub(in crate::consensus::native) fn prepare_append(
        &mut self,
        next: Self,
    ) -> io::Result<PreparedAppend<'_>> {
        if !Arc::ptr_eq(&self.target, &next.base) {
            return Err(invalid("native roster journal predecessor changed"));
        }
        fn preflight<K: std::hash::Hash + Eq, T: RowValue>(
            old: &HashMap<K, Change<T>>,
            new: &HashMap<K, Change<T>>,
        ) -> io::Result<()> {
            if new
                .iter()
                .any(|(key, change)| old.get(key).is_some_and(|before| !change.follows(before)))
            {
                return Err(invalid("native roster journal row predecessor changed"));
            }
            Ok(())
        }
        preflight(&self.rows, &next.rows)?;
        preflight(&self.partitions, &next.partitions)?;
        self.rows
            .try_reserve(next.rows.len())
            .map_err(|_| invalid("native roster journal row allocation failed"))?;
        self.partitions
            .try_reserve(next.partitions.len())
            .map_err(|_| invalid("native roster journal partition allocation failed"))?;
        self.memory
            .try_reserve(next.memory.len())
            .map_err(|_| invalid("native roster journal guard allocation failed"))?;
        Ok(PreparedAppend {
            journal: self,
            next,
        })
    }

    pub(in crate::consensus::native) fn validate(
        &self,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        if self.base.revision > self.target.revision {
            return Err(invalid("native roster capture revision regressed"));
        }
        let mut tables = self.base.tables;
        let mut lifecycle = self.base.lifecycle;
        for (binding, change) in &self.rows {
            check()?;
            let before = change
                .before
                .as_ref()
                .map(|row| stamp(4, binding, row))
                .transpose()?;
            let after = change
                .after
                .as_ref()
                .map(|row| stamp(4, binding, row))
                .transpose()?;
            let retired = change
                .retired
                .as_ref()
                .map(|row| stamp(4, binding, row))
                .transpose()?;
            change.checked(
                fingerprint(4, binding, &())?,
                before,
                after,
                retired,
                &mut tables[0],
                &mut lifecycle[..2],
            )?;
        }
        for (key, change) in &self.partitions {
            check()?;
            let before = change
                .before
                .as_ref()
                .map(|row| partition_stamp(*key, row))
                .transpose()?;
            let after = change
                .after
                .as_ref()
                .map(|row| partition_stamp(*key, row))
                .transpose()?;
            let retired = change
                .retired
                .as_ref()
                .map(|row| partition_stamp(*key, row))
                .transpose()?;
            change.checked(
                fingerprint(5, &key.as_bytes().as_slice(), &())?,
                before,
                after,
                retired,
                &mut tables[1],
                &mut lifecycle[2..],
            )?;
        }
        if tables != self.target.tables || lifecycle != self.target.lifecycle {
            return Err(invalid(
                "native roster capture omitted or changed published history",
            ));
        }
        check()
    }

    pub(in crate::consensus::native) fn validate_detached(
        &self,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        self.validate(check)?;
        for change in self.rows.values() {
            for row in [
                change.before.as_ref(),
                change.after.as_ref(),
                change.retired.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                row.hydrate_detached(root, scope, check)?;
            }
        }
        check()
    }
}

/// Exclusive ownership prevents a predecessor change between the final
/// preflight and the infallible move into the owner's existing journal.
pub(in crate::consensus::native) struct PreparedAppend<'a> {
    journal: &'a mut Journal,
    next: Journal,
}

impl PreparedAppend<'_> {
    pub(in crate::consensus::native) fn commit(self) {
        let Self { journal, next } = self;
        fn merge<K: std::hash::Hash + Eq, T: RowValue>(
            old: &mut HashMap<K, Change<T>>,
            new: HashMap<K, Change<T>>,
        ) {
            for (key, change) in new {
                match old.entry(key) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(change);
                    }
                    std::collections::hash_map::Entry::Occupied(mut slot) => {
                        let before = slot.get_mut();
                        before.after = change.after;
                        before.after_stamp = change.after_stamp;
                        if change.retired.is_some() {
                            before.retired = change.retired;
                            before.retired_stamp = change.retired_stamp;
                        }
                        before.introduced += change.introduced;
                        before.removed += change.removed;
                    }
                }
            }
        }
        merge(&mut journal.rows, next.rows);
        merge(&mut journal.partitions, next.partitions);
        journal.target = next.target;
        journal.memory.extend(next.memory);
    }
}
