//! Cold catalog ordinal and retention checks. These are verification scratch,
//! charged to the same process-wide budget and dropped before the resident
//! catalog returns. Each existing protocol epoch has at most its fixed slots.

use super::*;

struct Epoch {
    epoch: u64,
    times: Vec<Option<Timestamp>>,
    count: usize,
    first: usize,
    last: usize,
    _memory: VerificationMemory,
}

pub(super) struct Ordinals {
    epochs: Vec<Epoch>,
    _memory: VerificationMemory,
}

impl Ordinals {
    pub(super) fn new() -> io::Result<Self> {
        let memory = VerificationMemory::reserve(size_of::<Self>() + 16 * size_of::<Epoch>())?;
        Ok(Self {
            epochs: Vec::new(),
            _memory: memory,
        })
    }

    fn index(ordinal: u64) -> io::Result<usize> {
        usize::try_from(ordinal)
            .ok()
            .and_then(|ordinal| ordinal.checked_sub(1))
            .filter(|ordinal| *ordinal < FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES)
            .ok_or_else(|| invalid("native receipt ordinal exceeds its original bound"))
    }

    pub(super) fn insert(&mut self, epoch: u64, ordinal: u64, until: Timestamp) -> io::Result<()> {
        let index = Self::index(ordinal)?;
        let slot = match self.epochs.iter().position(|row| row.epoch == epoch) {
            Some(slot) => slot,
            None => {
                if self.epochs.len()
                    >= crate::fenced_transition::FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS + 1
                {
                    return Err(invalid(
                        "native catalog exceeds the original retained epoch bound",
                    ));
                }
                let count = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES;
                let memory = VerificationMemory::reserve(
                    count
                        .checked_mul(size_of::<Option<Timestamp>>())
                        .ok_or_else(|| invalid("native ordinal reservation overflow"))?,
                )?;
                let mut times = Vec::new();
                times
                    .try_reserve_exact(count)
                    .map_err(|_| invalid("native ordinal allocation failed"))?;
                times.resize(count, None);
                self.epochs.push(Epoch {
                    epoch,
                    times,
                    count: 0,
                    first: count,
                    last: 0,
                    _memory: memory,
                });
                self.epochs.sort_unstable_by_key(|row| row.epoch);
                self.epochs
                    .iter()
                    .position(|row| row.epoch == epoch)
                    .ok_or_else(|| invalid("native ordinal epoch allocation absent"))?
            }
        };
        let epoch = &mut self.epochs[slot];
        if epoch.times[index].is_some() {
            return Err(invalid("native catalog repeats a receipt ordinal"));
        }
        let previous = index.checked_sub(1).and_then(|index| epoch.times[index]);
        let next = epoch.times.get(index + 1).copied().flatten();
        if previous.is_some_and(|previous| previous > until)
            || next.is_some_and(|next| next < until)
        {
            return Err(invalid("native catalog receipt retention order regressed"));
        }
        epoch.times[index] = Some(until);
        epoch.first = epoch.first.min(index);
        epoch.last = epoch.last.max(index);
        epoch.count += 1;
        Ok(())
    }

    pub(super) fn remove(&mut self, epoch: u64, ordinal: u64, until: Timestamp) -> io::Result<()> {
        let index = Self::index(ordinal)?;
        let slot = self
            .epochs
            .iter()
            .position(|row| row.epoch == epoch)
            .ok_or_else(|| invalid("native deleted ordinal epoch absent"))?;
        let epoch = &mut self.epochs[slot];
        if epoch.times[index] != Some(until) {
            return Err(invalid(
                "native deleted ordinal differs from its complete prior row",
            ));
        }
        epoch.times[index] = None;
        epoch.count -= 1;
        if epoch.count == 0 {
            self.epochs.remove(slot);
        } else {
            while epoch.times[epoch.first].is_none() {
                epoch.first += 1;
            }
            while epoch.times[epoch.last].is_none() {
                epoch.last -= 1;
            }
        }
        Ok(())
    }

    pub(super) fn validate(
        &self,
        history: Option<FencedTransitionV2HistoryState>,
    ) -> io::Result<()> {
        let ranges = lifecycle::ranges(history)?
            .into_iter()
            .filter(|range| range.count != 0)
            .collect::<Vec<_>>();
        if self.epochs.len() != ranges.len() {
            return Err(invalid("native catalog represented epoch count differs"));
        }
        let mut previous = None;
        for (epoch, range) in self.epochs.iter().zip(ranges) {
            if epoch.epoch != range.epoch
                || epoch.count != range.count
                || epoch.first as u64 + 1 != range.first
                || epoch.last + 1 - epoch.first != range.count
            {
                return Err(invalid(
                    "native catalog does not cover exact history ordinal ranges",
                ));
            }
            let first = epoch.times[epoch.first]
                .ok_or_else(|| invalid("native catalog leading ordinal absent"))?;
            let last = epoch.times[epoch.last]
                .ok_or_else(|| invalid("native catalog trailing ordinal absent"))?;
            if previous.is_some_and(|previous| previous > first) {
                return Err(invalid("native catalog retention regressed across epochs"));
            }
            previous = Some(last);
        }
        Ok(())
    }

    pub(super) fn validate_retirement(
        &self,
        before: Option<FencedTransitionV2HistoryState>,
        after: Option<FencedTransitionV2HistoryState>,
        now: Option<Timestamp>,
    ) -> io::Result<()> {
        for epoch in &self.epochs {
            if epoch.epoch > lifecycle::floor(before)
                && epoch.epoch <= lifecycle::floor(after)
                && epoch.times[epoch.last].is_none_or(|until| now.is_none_or(|now| until > now))
            {
                return Err(invalid("native catalog retired an unexpired exact epoch"));
            }
        }
        Ok(())
    }
}
