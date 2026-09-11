//! Derived ordinal access for the bounded V2 lifecycle. Immutable vector
//! paths let a captured proof share the index while live work touches only
//! appended rows or the original bounded reclaim prefix. This resident index
//! is part of the three-voter RSS charge, never a serialized certificate.

use super::*;
use crate::fenced_transition::{FencedTransitionV2CallerNonce, FencedTransitionV2HistoryEpoch};

#[derive(Clone, Copy)]
pub(super) struct OrderedReceipt {
    pub(super) id: FencedTransitionV2RequestId,
    pub(super) retained_until: Timestamp,
}

// The containing epoch owns the exact common eight-byte prefix. Preserve
// every remaining ID byte and the complete timestamp; no hash-only key or
// payload ownership enters the ordinal index. Expansion is lossless and
// every lookup/validation still compares the complete original request ID.
#[derive(Clone, Copy)]
struct IndexedReceipt {
    nonce: FencedTransitionV2CallerNonce,
    commitment: [u8; 32],
    retained_until: Timestamp,
}

impl IndexedReceipt {
    fn new(id: FencedTransitionV2RequestId, retained_until: Timestamp) -> Self {
        Self {
            nonce: id.nonce(),
            commitment: *id.body_commitment(),
            retained_until,
        }
    }

    fn expand(self, epoch: FencedTransitionV2HistoryEpoch) -> OrderedReceipt {
        OrderedReceipt {
            id: FencedTransitionV2RequestId::from_parts(epoch, self.nonce, self.commitment),
            retained_until: self.retained_until,
        }
    }
}

#[derive(Clone)]
struct Epoch {
    epoch: FencedTransitionV2HistoryEpoch,
    first: u64,
    filled: usize,
    rows: ResidentVector<Option<IndexedReceipt>>,
}

#[derive(Clone, Default)]
pub(super) struct ReceiptOrder {
    epochs: Vec<Epoch>,
}

impl ReceiptOrder {
    pub(super) fn preparing(history: Option<FencedTransitionV2HistoryState>) -> io::Result<Self> {
        let epochs = lifecycle::ranges(history)?
            .into_iter()
            .filter(|range| range.count != 0)
            .map(|range| {
                Ok(Epoch {
                    epoch: FencedTransitionV2HistoryEpoch::new(range.epoch)
                        .map_err(|_| invalid("native receipt index epoch invalid"))?,
                    first: range.first,
                    filled: 0,
                    rows: std::iter::repeat_n(None, range.count).collect(),
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { epochs })
    }

    // Cold admission fills exact pre-sized ordinal slots in any input order.
    // Every neighbor relation is checked when its second endpoint arrives;
    // filled counts then prove that no unchecked hole remains.
    pub(super) fn insert_cold(
        &mut self,
        id: FencedTransitionV2RequestId,
        ordinal: u64,
        retained_until: Timestamp,
    ) -> io::Result<()> {
        let epoch = self
            .epochs
            .iter_mut()
            .find(|epoch| epoch.epoch == id.epoch())
            .ok_or_else(|| invalid("native receipt index epoch is outside history"))?;
        let index = ordinal
            .checked_sub(epoch.first)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < epoch.rows.len())
            .ok_or_else(|| invalid("native receipt index ordinal is outside history"))?;
        if epoch.rows[index].is_some() {
            return Err(invalid("native receipt index repeats an ordinal"));
        }
        let previous = index
            .checked_sub(1)
            .and_then(|index| epoch.rows.get(index))
            .and_then(Option::as_ref);
        let next = epoch.rows.get(index + 1).and_then(Option::as_ref);
        if previous.is_some_and(|row| row.retained_until > retained_until)
            || next.is_some_and(|row| row.retained_until < retained_until)
        {
            return Err(invalid("native receipt retention order regressed"));
        }
        epoch.rows[index] = Some(IndexedReceipt::new(id, retained_until));
        epoch.filled += 1;
        Ok(())
    }

    pub(super) fn append(
        &mut self,
        id: FencedTransitionV2RequestId,
        ordinal: u64,
        retained_until: Timestamp,
    ) -> io::Result<()> {
        self.append_with_first(id, ordinal, retained_until, 1)
    }

    pub(super) fn append_captured(
        &mut self,
        id: FencedTransitionV2RequestId,
        ordinal: u64,
        retained_until: Timestamp,
        history: Option<FencedTransitionV2HistoryState>,
    ) -> io::Result<()> {
        let first = lifecycle::ordinal_bounds(
            history.ok_or_else(|| invalid("native captured receipt history absent"))?,
            id.epoch().get(),
        )?
        .0;
        self.append_with_first(id, ordinal, retained_until, first)
    }

    fn append_with_first(
        &mut self,
        id: FencedTransitionV2RequestId,
        ordinal: u64,
        retained_until: Timestamp,
        first: u64,
    ) -> io::Result<()> {
        let number = id.epoch();
        if let Some(previous) = self.epochs.last() {
            if previous
                .rows
                .back()
                .and_then(Option::as_ref)
                .is_some_and(|row| row.retained_until > retained_until)
            {
                return Err(invalid("native appended receipt retention regressed"));
            }
            if previous.epoch != number
                && (previous.epoch.get().checked_add(1) != Some(number.get())
                    || previous.first.checked_add(previous.rows.len() as u64)
                        != Some(FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64 + 1))
            {
                return Err(invalid("native appended receipt skips a full epoch"));
            }
        }
        if self.epochs.last().is_none_or(|epoch| epoch.epoch != number) {
            if ordinal != first
                || self.epochs.len()
                    >= crate::fenced_transition::FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES
                        / FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            {
                return Err(invalid(
                    "native appended receipt exceeds the retained epoch bound",
                ));
            }
            self.epochs.push(Epoch {
                epoch: number,
                first,
                filled: 0,
                rows: ResidentVector::new(),
            });
        }
        let epoch = self
            .epochs
            .last_mut()
            .ok_or_else(|| invalid("native appended receipt epoch absent"))?;
        if ordinal != epoch.first + epoch.rows.len() as u64
            || ordinal > FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64
        {
            return Err(invalid(
                "native appended receipt is not the ordinal successor",
            ));
        }
        epoch
            .rows
            .push_back(Some(IndexedReceipt::new(id, retained_until)));
        epoch.filled += 1;
        Ok(())
    }

    pub(super) fn get(&self, epoch: u64, ordinal: u64) -> Option<OrderedReceipt> {
        let epoch = self.epochs.iter().find(|row| row.epoch.get() == epoch)?;
        let index = usize::try_from(ordinal.checked_sub(epoch.first)?).ok()?;
        epoch
            .rows
            .get(index)
            .copied()
            .flatten()
            .map(|row| row.expand(epoch.epoch))
    }

    pub(super) fn last(&self, epoch: u64) -> Option<OrderedReceipt> {
        let epoch = self.epochs.iter().find(|row| row.epoch.get() == epoch)?;
        epoch
            .rows
            .back()
            .copied()
            .flatten()
            .map(|row| row.expand(epoch.epoch))
    }

    pub(super) fn remove_prefix(
        &mut self,
        id: FencedTransitionV2RequestId,
        ordinal: u64,
    ) -> io::Result<()> {
        let epoch = self
            .epochs
            .first_mut()
            .ok_or_else(|| invalid("native reclaim index is empty"))?;
        if epoch.epoch != id.epoch()
            || epoch.first != ordinal
            || epoch
                .rows
                .front()
                .copied()
                .flatten()
                .is_none_or(|row| row.expand(epoch.epoch).id != id)
        {
            return Err(invalid("native reclaim is not the exact ordered prefix"));
        }
        epoch.rows.pop_front();
        epoch.first += 1;
        epoch.filled -= 1;
        if epoch.rows.is_empty() {
            self.epochs.remove(0);
        }
        Ok(())
    }

    pub(super) fn validate(
        &self,
        history: Option<FencedTransitionV2HistoryState>,
    ) -> io::Result<()> {
        let ranges = lifecycle::ranges(history)?;
        let ranges = ranges
            .into_iter()
            .filter(|range| range.count != 0)
            .collect::<Vec<_>>();
        if ranges.len() != self.epochs.len() {
            return Err(invalid("native receipt index epoch count differs"));
        }
        let mut previous_until = None;
        for (range, epoch) in ranges.iter().zip(&self.epochs) {
            if epoch.epoch.get() != range.epoch
                || epoch.first != range.first
                || epoch.rows.len() != range.count
                || epoch.filled != range.count
            {
                return Err(invalid(
                    "native receipt index does not cover the exact ordinal ranges",
                ));
            }
            let first = epoch
                .rows
                .front()
                .copied()
                .flatten()
                .ok_or_else(|| invalid("native receipt index has a leading hole"))?;
            let last = epoch
                .rows
                .back()
                .copied()
                .flatten()
                .ok_or_else(|| invalid("native receipt index has a trailing hole"))?;
            if previous_until.is_some_and(|until| until > first.retained_until) {
                return Err(invalid("native receipt retention regressed across epochs"));
            }
            previous_until = Some(last.retained_until);
        }
        Ok(())
    }

    pub(super) fn validate_retirement(
        &self,
        before: Option<FencedTransitionV2HistoryState>,
        after: Option<FencedTransitionV2HistoryState>,
        now: Option<Timestamp>,
    ) -> io::Result<()> {
        let previous = lifecycle::floor(before);
        let next = lifecycle::floor(after);
        for epoch in &self.epochs {
            if epoch.epoch.get() > previous
                && epoch.epoch.get() <= next
                && epoch
                    .rows
                    .back()
                    .copied()
                    .flatten()
                    .is_none_or(|row| now.is_none_or(|now| row.retained_until > now))
            {
                return Err(invalid("native history retired an unexpired exact epoch"));
            }
        }
        Ok(())
    }

    /// Reusing a published index saves its allocation, never its validation.
    /// Every slot must match the complete external key and exact row ordinal;
    /// equal cardinalities then establish a bijection, including interior
    /// holes and duplicate IDs. Retention is checked across every neighbor.
    pub(super) fn validate_rows(
        &self,
        receipts: &RowMap<FencedTransitionV2RequestId, SharedRow<NativeReceipt>>,
    ) -> io::Result<()> {
        let mut count = 0usize;
        let mut previous_until = None;
        for epoch in &self.epochs {
            for (index, slot) in epoch.rows.iter().enumerate() {
                let ordered = slot
                    .as_ref()
                    .copied()
                    .ok_or_else(|| invalid("native reused receipt index has a hole"))?
                    .expand(epoch.epoch);
                let row = receipts
                    .get(&ordered.id)
                    .ok_or_else(|| invalid("native reused receipt index key is absent"))?;
                if ordered.id.epoch() != epoch.epoch
                    || epoch.first.checked_add(index as u64) != Some(row.ordinal)
                    || row.retained_until != ordered.retained_until
                    || previous_until.is_some_and(|until| until > ordered.retained_until)
                {
                    return Err(invalid(
                        "native reused receipt index differs from complete rows",
                    ));
                }
                previous_until = Some(ordered.retained_until);
                count += 1;
            }
        }
        if count != receipts.len() {
            return Err(invalid("native reused receipt index row count differs"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_receipt_order_epoch_prefix_preserves_complete_id_and_exact_timestamp() {
        let epoch = FencedTransitionV2HistoryEpoch::new(
            crate::fenced_transition::FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH,
        )
        .unwrap();
        let id = FencedTransitionV2RequestId::from_parts(
            epoch,
            FencedTransitionV2CallerNonce::from_bytes([0xD7; 16]),
            [0xAE; 32],
        );
        let until = Timestamp::from_offset_datetime(
            changes::tests::time(20)
                .as_offset_datetime()
                .replace_nanosecond(999_999_999)
                .unwrap(),
        );
        let mut index = ReceiptOrder::default();
        index.append(id, 1, until).unwrap();
        let captured = index.clone();
        assert_eq!(
            index.get(epoch.get(), 1).unwrap().id.to_bytes(),
            id.to_bytes()
        );
        assert_eq!(index.last(epoch.get()).unwrap().retained_until, until);
        let wrong_epoch = FencedTransitionV2HistoryEpoch::new(1).unwrap();
        let wrong =
            FencedTransitionV2RequestId::from_parts(wrong_epoch, id.nonce(), *id.body_commitment());
        assert!(index.insert_cold(wrong, 1, until).is_err());
        assert!(index.remove_prefix(wrong, 1).is_err());
        assert!(index.get(wrong_epoch.get(), 1).is_none());
        index.remove_prefix(id, 1).unwrap();
        assert!(index.get(epoch.get(), 1).is_none());
        assert_eq!(
            captured.get(epoch.get(), 1).unwrap().id.to_bytes(),
            id.to_bytes()
        );
        assert_eq!(captured.last(epoch.get()).unwrap().retained_until, until);
    }

    #[test]
    fn native_reused_receipt_index_rejects_interior_holes_duplicates_and_changed_full_keys() {
        let (mut storage, _, _) = changes::tests::fixture();
        let history = FencedTransitionV2HistoryState::new(
            Some(FencedTransitionV2HistoryEpoch::new(1).unwrap()),
            None,
            None,
            0,
            0,
            3,
            0,
        )
        .unwrap();
        lifecycle_tests::seed(&mut storage, history, changes::tests::time(20), None, false);
        let original = storage
            .business
            .require_business_proof()
            .unwrap()
            .receipt_order
            .clone();
        original.validate_rows(&storage.business.receipts).unwrap();
        for case in 0..4 {
            let mut index = original.clone();
            let mut middle = index.epochs[0].rows[1].unwrap();
            match case {
                0 => index.epochs[0].rows[1] = None,
                1 => index.epochs[0].rows[1] = index.epochs[0].rows[0],
                2 => {
                    middle = IndexedReceipt::new(
                        lifecycle_tests::synthetic_id(1, 4),
                        middle.retained_until,
                    );
                    index.epochs[0].rows[1] = Some(middle);
                }
                3 => {
                    middle.retained_until = changes::tests::time(19);
                    index.epochs[0].rows[1] = Some(middle);
                }
                _ => unreachable!(),
            }
            // Boundary/count-only validation cannot reject these corrupt
            // interior slots. Reuse must independently visit their full rows.
            index.validate(Some(history)).unwrap();
            assert!(
                index.validate_rows(&storage.business.receipts).is_err(),
                "case {case}"
            );
        }
    }
}
