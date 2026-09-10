//! Derived ordinal access for the bounded V2 lifecycle. Immutable vector
//! paths let a captured proof share the index while live work touches only
//! appended rows or the original bounded reclaim prefix. This resident index
//! is part of the three-voter RSS charge, never a serialized certificate.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct OrderedReceipt {
    pub(super) id: FencedTransitionV2RequestId,
    pub(super) retained_until: Timestamp,
}

#[derive(Clone)]
struct Epoch {
    epoch: u64,
    first: u64,
    filled: usize,
    rows: ResidentVector<Option<OrderedReceipt>>,
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
            .map(|range| Epoch {
                epoch: range.epoch,
                first: range.first,
                filled: 0,
                rows: std::iter::repeat_n(None, range.count).collect(),
            })
            .collect();
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
            .find(|epoch| epoch.epoch == id.epoch().get())
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
        epoch.rows[index] = Some(OrderedReceipt { id, retained_until });
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
        let number = id.epoch().get();
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
                && (previous.epoch.checked_add(1) != Some(number)
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
            .push_back(Some(OrderedReceipt { id, retained_until }));
        epoch.filled += 1;
        Ok(())
    }

    pub(super) fn get(&self, epoch: u64, ordinal: u64) -> Option<OrderedReceipt> {
        let epoch = self.epochs.iter().find(|row| row.epoch == epoch)?;
        let index = usize::try_from(ordinal.checked_sub(epoch.first)?).ok()?;
        epoch.rows.get(index).copied().flatten()
    }

    pub(super) fn last(&self, epoch: u64) -> Option<OrderedReceipt> {
        self.epochs
            .iter()
            .find(|row| row.epoch == epoch)?
            .rows
            .back()
            .copied()
            .flatten()
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
        if epoch.epoch != id.epoch().get()
            || epoch.first != ordinal
            || epoch
                .rows
                .front()
                .copied()
                .flatten()
                .is_none_or(|row| row.id != id)
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
            if epoch.epoch != range.epoch
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
            if epoch.epoch > previous
                && epoch.epoch <= next
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
}
