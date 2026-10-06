//! Lossless deletion inventory over immutable ordinal-index roots. A range
//! retains every original identity; it is not a history counter or a digest.
//! Before-row fingerprints remain individually owned and checked unchanged.

use super::*;

struct Range {
    epoch: u64,
    first: u64,
    count: usize,
    source: history_order::ReceiptOrder,
}

#[derive(Default)]
pub(in crate::consensus::native) struct Removals {
    #[cfg(not(test))]
    ranges: Vec<Range>,
    #[cfg(test)]
    ranges: super::staging::Rows<Range>,
    count: usize,
    // Last: the range vector and cloned epoch descriptors die before refund.
    // Shared index leaves/complete row bodies can become solely owned by this
    // inventory after publication; they remain resident-state allocations.
    memory: Option<VerificationMemory>,
}

impl Removals {
    pub(in crate::consensus::native) fn len(&self) -> usize {
        self.count
    }

    pub(in crate::consensus::native) fn contains(
        &self,
        id: &FencedTransitionV2RequestId,
        ordinal: u64,
    ) -> bool {
        self.ranges.iter().any(|range| {
            range.epoch == id.epoch().get()
                && ordinal >= range.first
                && ordinal - range.first < range.count as u64
                && range
                    .source
                    .get(range.epoch, ordinal)
                    .is_some_and(|row| row.id == *id)
        })
    }

    pub(in crate::consensus::native) fn insert(
        &mut self,
        id: FencedTransitionV2RequestId,
        ordinal: u64,
        source: &history_order::ReceiptOrder,
    ) -> io::Result<()> {
        if source
            .get(id.epoch().get(), ordinal)
            .is_none_or(|row| row.id != id)
        {
            return Err(invalid(
                "native removed identity differs from its exact index",
            ));
        }
        let next = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid("native removed inventory count overflow"))?;
        if let Some(range) = self.ranges.last_mut() {
            let end = range.first + range.count as u64;
            if (id.epoch().get(), ordinal) < (range.epoch, end) {
                return Err(invalid("native removed inventory repeats or regresses"));
            }
            if range.epoch == id.epoch().get() && end == ordinal {
                if range
                    .source
                    .get(range.epoch, ordinal)
                    .is_none_or(|row| row.id != id)
                {
                    return Err(invalid("native removed range changed its immutable index"));
                }
                range.count += 1;
                self.count = next;
                return Ok(());
            }
        }
        // Eight inline persistent-vector roots, a growing range slot and
        // allocator/container slack fit one 64 KiB accounting block. Shared
        // leaves are not copied. Keep this type-size assertion with the charge.
        const RANGE_BYTES: usize = 64 * 1024;
        const {
            assert!(
                history_order::ReceiptOrder::clone_metadata_bytes() + 4 * size_of::<Range>() + 64
                    <= RANGE_BYTES
            );
        }
        let bytes = (self.ranges.len() + 1)
            .checked_mul(RANGE_BYTES)
            .ok_or_else(|| invalid("native removal range charge overflow"))?;
        match &mut self.memory {
            Some(memory) => memory.grow_to(bytes)?,
            None => self.memory = Some(VerificationMemory::reserve(bytes)?),
        }
        self.ranges.push(Range {
            epoch: id.epoch().get(),
            first: ordinal,
            count: 1,
            source: source.clone(),
        });
        self.count = next;
        Ok(())
    }

    pub(in crate::consensus::native) fn iter(
        &self,
    ) -> impl Iterator<Item = io::Result<(FencedTransitionV2RequestId, u64)>> + '_ {
        self.ranges.iter().flat_map(|range| {
            (range.first..range.first + range.count as u64).map(move |ordinal| {
                range
                    .source
                    .get(range.epoch, ordinal)
                    .map(|row| (row.id, ordinal))
                    .ok_or_else(|| invalid("native removed inventory has an ordinal hole"))
            })
        })
    }

    #[cfg(test)]
    pub(in crate::consensus::native) fn omit_first_for_test(&mut self) {
        let range = self.ranges.first_mut().unwrap();
        range.first += 1;
        range.count -= 1;
        self.count -= 1;
    }
}

struct Before {
    row: row_map::CapturedRow<FencedTransitionV2RequestId, SharedRow<NativeReceipt>>,
    hash: RowStamp,
}

pub(super) struct DeletedRows {
    inventory: Removals,
    #[cfg(not(test))]
    rows: Vec<Before>,
    #[cfg(test)]
    rows: super::staging::Rows<Before>,
    _memory: VerificationMemory,
}

impl DeletedRows {
    #[cfg(test)]
    pub(super) fn observe_allocation_lifetimes_for_test(
        &mut self,
        refunds: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let ranges = Arc::new(());
        let rows = Arc::new(());
        let ranges_gone = Arc::downgrade(&ranges);
        let rows_gone = Arc::downgrade(&rows);
        self.inventory.ranges.allocation_lifetime = Some(ranges);
        self.rows.allocation_lifetime = Some(rows);
        let inventory_gone = ranges_gone.clone();
        let inventory_refunds = Arc::clone(&refunds);
        self.inventory
            .memory
            .as_mut()
            .unwrap()
            .observe_refund_for_test(move || {
                assert!(
                    inventory_gone.upgrade().is_none(),
                    "range inventory allocation outlives its charge"
                );
                inventory_refunds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        self._memory.observe_refund_for_test(move || {
            assert!(
                rows_gone.upgrade().is_none(),
                "before-row buffer outlives its charge"
            );
            assert!(
                ranges_gone.upgrade().is_none(),
                "deletion inventory outlives its final charge"
            );
            refunds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
    }

    #[cfg(test)]
    pub(super) fn corrupt_for_test(&mut self, kind: usize) {
        match kind {
            0 => {
                self.inventory.omit_first_for_test();
                self.rows.remove(0);
            }
            1 => self.rows.swap(0, 1),
            2 => self.rows[0].hash.content[0] ^= 1,
            3 => self.rows[0].hash.revision[0] ^= 1,
            _ => self.inventory.ranges[0].count += 1,
        }
    }

    pub(super) const fn row_bytes() -> usize {
        size_of::<Before>()
    }

    pub(super) fn index_verification_bytes(&self) -> usize {
        self.inventory
            .memory
            .as_ref()
            .map_or(0, VerificationMemory::reserved_bytes)
            + self._memory.reserved_bytes()
    }

    pub(super) fn before_count(
        inventory: &Removals,
        base: &RowMap<FencedTransitionV2RequestId, SharedRow<NativeReceipt>>,
    ) -> io::Result<usize> {
        inventory.iter().try_fold(0usize, |count, row| {
            Ok(count + usize::from(base.contains_key(&row?.0)))
        })
    }

    pub(super) fn prepare(
        inventory: Removals,
        base: &RowMap<FencedTransitionV2RequestId, SharedRow<NativeReceipt>>,
        count: usize,
        table: &mut TableSummary,
        memory: Option<VerificationMemory>,
    ) -> io::Result<Self> {
        let bytes = count
            .checked_mul(Self::row_bytes())
            .ok_or_else(|| invalid("native deletion fingerprint reservation overflow"))?;
        let memory = match memory {
            Some(mut memory) => {
                memory.grow_to(bytes)?;
                memory.shrink_to(bytes)?;
                memory
            }
            None => VerificationMemory::reserve(bytes)?,
        };
        let mut rows = Vec::with_capacity(count);
        for entry in inventory.iter() {
            let (id, ordinal) = entry?;
            if let Some(row) = base.capture_row(&id) {
                if row.value().ordinal != ordinal {
                    return Err(invalid(
                        "native removed row differs from its indexed ordinal",
                    ));
                }
                let hash = stamp(1, &id, row.value())?;
                table.replace(Some(hash), None)?;
                rows.push(Before { row, hash });
            }
        }
        if rows.len() != count {
            return Err(invalid("native removed before-row inventory changed"));
        }
        #[cfg(test)]
        let rows = rows.into();
        Ok(Self {
            inventory,
            rows,
            _memory: memory,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.inventory.len()
    }

    // Only publication calls this after for_each has checked the complete
    // immutable inventory and every predecessor. No I/O, allocation or
    // recoverable error may be introduced into this mutation pass.
    pub(super) fn publish_ids(&self, mut visit: impl FnMut(FencedTransitionV2RequestId)) {
        for range in &self.inventory.ranges {
            for ordinal in range.first..range.first + range.count as u64 {
                visit(
                    range
                        .source
                        .get(range.epoch, ordinal)
                        .expect("validated immutable deletion ordinal")
                        .id,
                );
            }
        }
    }

    pub(super) fn for_each(
        &self,
        mut visit: impl FnMut(
            FencedTransitionV2RequestId,
            u64,
            Option<&SharedRow<NativeReceipt>>,
            Option<RowStamp>,
        ) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut rows = self.rows.iter().peekable();
        let mut count = 0;
        for entry in self.inventory.iter() {
            let (id, ordinal) = entry?;
            let row = if rows.peek().is_some_and(|row| *row.row.key() == id) {
                rows.next()
            } else {
                None
            };
            let before = row.map(|row| row.row.value());
            let hash = row.map(|row| row.hash);
            visit(id, ordinal, before, hash)?;
            count += 1;
        }
        if rows.next().is_some() || count != self.inventory.len() {
            return Err(invalid("native removed inventory cardinality differs"));
        }
        Ok(())
    }
}
