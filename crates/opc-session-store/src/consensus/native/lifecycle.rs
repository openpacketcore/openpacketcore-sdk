//! The existing V2 maintenance CAS and signed horizons. Rotation and each
//! physical reclaim batch retain the original protocol's sequence, clock,
//! no-generic-receipt and no-watch semantics.

use super::*;
use crate::fenced_transition::{
    FencedTransitionV2HistoryEpoch, FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS,
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES, FENCED_TRANSITION_V2_RECLAIM_BATCH,
};

pub(super) struct EpochRange {
    pub(super) epoch: u64,
    pub(super) first: u64,
    pub(super) count: usize,
}

pub(super) fn floor(history: Option<FencedTransitionV2HistoryState>) -> u64 {
    history
        .and_then(|history| history.retired_through())
        .map_or(0, |epoch| epoch.get())
}

pub(super) fn ranges(
    history: Option<FencedTransitionV2HistoryState>,
) -> io::Result<Vec<EpochRange>> {
    let Some(history) = history else {
        return Ok(Vec::new());
    };
    FencedTransitionV2HistoryState::new(
        history.active_epoch(),
        history.retired_through(),
        history.reclaim_epoch(),
        history.reclaim_remaining(),
        history.generation(),
        history.bound_entries(),
        history.reclaimed_entries(),
    )
    .map_err(|_| invalid("native history lifecycle invalid"))?;
    if history.reclaimed_entries() > COUNTER_MAX {
        return Err(invalid(
            "native history reclaimed counter exceeds the signed horizon",
        ));
    }
    let active = history
        .active_epoch()
        .ok_or_else(|| invalid("native history active epoch absent"))?
        .get();
    let first = if history.reclaim_epoch().is_some() {
        floor(Some(history))
    } else {
        floor(Some(history)) + 1
    };
    let mut ranges = Vec::with_capacity(FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS + 1);
    for epoch in first..=active {
        let (first, count) = if history
            .reclaim_epoch()
            .is_some_and(|reclaim| reclaim.get() == epoch)
        {
            (
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64
                    - history.reclaim_remaining() as u64
                    + 1,
                history.reclaim_remaining(),
            )
        } else {
            (
                1,
                if epoch == active {
                    history.bound_entries()
                } else {
                    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                },
            )
        };
        ranges.push(EpochRange {
            epoch,
            first,
            count,
        });
    }
    Ok(ranges)
}

pub(super) fn receipt_count(history: Option<FencedTransitionV2HistoryState>) -> io::Result<usize> {
    let count = ranges(history)?
        .into_iter()
        .try_fold(0usize, |count, range| count.checked_add(range.count))
        .ok_or_else(|| invalid("native history total count overflow"))?;
    if count > FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES {
        return Err(invalid(
            "native history exceeds the original retained receipt bound",
        ));
    }
    Ok(count)
}

pub(super) fn ordinal_bounds(
    history: FencedTransitionV2HistoryState,
    epoch: u64,
) -> io::Result<(u64, usize)> {
    let active = history
        .active_epoch()
        .ok_or_else(|| invalid("native history active epoch absent"))?
        .get();
    let minimum = floor(Some(history)) + u64::from(history.reclaim_epoch().is_none());
    if !(minimum..=active).contains(&epoch) {
        return Err(invalid(
            "native receipt epoch is outside represented history",
        ));
    }
    if history
        .reclaim_epoch()
        .is_some_and(|reclaim| reclaim.get() == epoch)
    {
        Ok((
            FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64 - history.reclaim_remaining() as u64
                + 1,
            history.reclaim_remaining(),
        ))
    } else {
        Ok((
            1,
            if epoch == active {
                history.bound_entries()
            } else {
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            },
        ))
    }
}

pub(super) fn validate_ordinal(
    history: FencedTransitionV2HistoryState,
    id: FencedTransitionV2RequestId,
    ordinal: u64,
) -> io::Result<()> {
    let (first, count) = ordinal_bounds(history, id.epoch().get())?;
    if ordinal < first || ordinal - first >= count as u64 {
        return Err(invalid(
            "native receipt ordinal is outside its exact epoch range",
        ));
    }
    Ok(())
}

pub(super) fn transition(
    before: Option<FencedTransitionV2HistoryState>,
    after: Option<FencedTransitionV2HistoryState>,
) -> io::Result<()> {
    ranges(before)?;
    ranges(after)?;
    if before.is_some() && after.is_none() {
        return Err(invalid("native history activation was withdrawn"));
    }
    let old_active = before
        .and_then(|history| history.active_epoch())
        .map_or(1, |epoch| epoch.get());
    let new_active = after
        .and_then(|history| history.active_epoch())
        .map_or(1, |epoch| epoch.get());
    let rotations = new_active
        .checked_sub(old_active)
        .ok_or_else(|| invalid("native history active epoch regressed"))?;
    let generations = after
        .map_or(0, |history| history.generation())
        .checked_sub(before.map_or(0, |history| history.generation()))
        .ok_or_else(|| invalid("native history generation regressed"))?;
    let reclaimed = after
        .map_or(0, |history| history.reclaimed_entries())
        .checked_sub(before.map_or(0, |history| history.reclaimed_entries()))
        .ok_or_else(|| invalid("native history reclaimed count regressed"))?;
    let changed = rotations != 0
        || floor(before) != floor(after)
        || before.and_then(|history| history.reclaim_epoch())
            != after.and_then(|history| history.reclaim_epoch())
        || before.map_or(0, |history| history.reclaim_remaining())
            != after.map_or(0, |history| history.reclaim_remaining())
        || reclaimed != 0;
    if floor(after) < floor(before)
        || (rotations == 0
            && after.map_or(0, |history| history.bound_entries())
                < before.map_or(0, |history| history.bound_entries()))
        || changed != (generations != 0)
        || u128::from(generations)
            < u128::from(rotations)
                + u128::from(reclaimed.div_ceil(FENCED_TRANSITION_V2_RECLAIM_BATCH as u64))
    {
        return Err(invalid("native history lifecycle transition differs"));
    }
    Ok(())
}

pub(super) fn removed_is_retired(
    id: FencedTransitionV2RequestId,
    before: Option<u64>,
    after: Option<FencedTransitionV2HistoryState>,
) -> io::Result<()> {
    if id.epoch().get() > floor(after) {
        return Err(invalid("native receipt removal is above the retired floor"));
    }
    if let (Some(before), Some(after)) = (before, after) {
        if after.reclaim_epoch() == Some(id.epoch())
            && before
                > FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64 - after.reclaim_remaining() as u64
        {
            return Err(invalid("native receipt removal skips the reclaim cursor"));
        }
    }
    Ok(())
}

// Counts include absent-to-absent rows: an interval may bind and reclaim a
// request before capture. Its complete ID remains in the coalesced journal,
// so neither that binding nor its physical removal disappears from this law.
pub(super) fn conservation(
    before: Option<FencedTransitionV2HistoryState>,
    after: Option<FencedTransitionV2HistoryState>,
    added: usize,
    removed: usize,
    transient: usize,
) -> io::Result<()> {
    let previous_active = before
        .and_then(|history| history.active_epoch())
        .map_or(1, |epoch| epoch.get());
    let next_active = after
        .and_then(|history| history.active_epoch())
        .map_or(1, |epoch| epoch.get());
    let bound = u128::from(
        next_active
            .checked_sub(previous_active)
            .ok_or_else(|| invalid("native history active epoch regressed"))?,
    ) * FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u128
        + after.map_or(0, |history| history.bound_entries()) as u128;
    let bound = bound
        .checked_sub(before.map_or(0, |history| history.bound_entries()) as u128)
        .ok_or_else(|| invalid("native history bound count regressed"))?;
    let deleted = after
        .map_or(0, |history| history.reclaimed_entries())
        .checked_sub(before.map_or(0, |history| history.reclaimed_entries()))
        .ok_or_else(|| invalid("native reclaimed count regressed"))?;
    if bound != added as u128 + transient as u128
        || u128::from(deleted) != removed as u128 + transient as u128
        || receipt_count(before)? as u128 + bound
            != receipt_count(after)? as u128 + u128::from(deleted)
    {
        return Err(invalid(
            "native history binding and reclamation conservation differs",
        ));
    }
    Ok(())
}

impl NativeDelta<'_> {
    pub(super) fn maintain_history(
        &mut self,
        command: &SessionConsensusCommand,
        now: Timestamp,
        index: u64,
    ) -> io::Result<SessionConsensusResponse> {
        let SessionMutationIntent::MaintainFencedTransitionV2History {
            expected_generation,
            expected_active_epoch,
            expected_retired_through,
            expected_bound_entries,
        } = &command.intent
        else {
            return Err(invalid(
                "native history maintenance must be a raw internal command",
            ));
        };
        if !fenced_transition_v2_timestamp_is_in_range(command.logical_time) {
            return Err(invalid("native history maintenance time outside profile"));
        }
        let Some(history) = self.frontiers.history else {
            return Ok(self.clock_response(
                now,
                index,
                StoreError::FencedTransitionHistoryEpochNotActive,
            ));
        };
        if history.generation() != *expected_generation
            || history.active_epoch() != *expected_active_epoch
            || floor(Some(history)) != *expected_retired_through
            || history.bound_entries() as u64 != *expected_bound_entries
        {
            return Ok(self.clock_response(
                now,
                index,
                StoreError::FencedTransitionHistoryEpochNotActive,
            ));
        }
        if self.frontiers.sequence >= COUNTER_MAX
            || history.generation() >= COUNTER_MAX
            || history
                .active_epoch()
                .is_some_and(|epoch| epoch.get() >= COUNTER_MAX)
            || history
                .reclaim_epoch()
                .is_some_and(|epoch| epoch.get() >= COUNTER_MAX)
        {
            return Ok(self.clock_response(
                now,
                index,
                StoreError::FencedTransitionStorageExhausted,
            ));
        }
        let active = history
            .active_epoch()
            .ok_or_else(|| invalid("native maintenance active epoch absent"))?;
        let generation = history.generation() + 1;
        let updated = if history.reclaim_epoch().is_none()
            && active.get() - floor(Some(history))
                < (FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS + 1) as u64
        {
            if history.bound_entries() < FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
                None
            } else {
                Some(
                    FencedTransitionV2HistoryState::new(
                        Some(
                            FencedTransitionV2HistoryEpoch::new(active.get() + 1)
                                .map_err(|_| invalid("native successor epoch invalid"))?,
                        ),
                        history.retired_through(),
                        None,
                        0,
                        generation,
                        0,
                        history.reclaimed_entries(),
                    )
                    .map_err(|_| invalid("native rotated history invalid"))?,
                )
            }
        } else {
            let epoch = history
                .reclaim_epoch()
                .map_or(floor(Some(history)) + 1, |epoch| epoch.get());
            let remaining = if history.reclaim_epoch().is_some() {
                history.reclaim_remaining()
            } else {
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            };
            let last = self
                .receipt_order
                .last(epoch)
                .ok_or_else(|| invalid("native retiring epoch is missing"))?;
            if history.reclaim_epoch().is_none() && last.retained_until > now {
                None
            } else {
                let count = remaining.min(FENCED_TRANSITION_V2_RECLAIM_BATCH);
                if history.reclaimed_entries() > COUNTER_MAX - count as u64 {
                    return Ok(self.clock_response(
                        now,
                        index,
                        StoreError::FencedTransitionStorageExhausted,
                    ));
                }
                let first = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64 - remaining as u64 + 1;
                // Exactly the fixed original batch. No map scan, payload
                // decoding or cold-file access is needed for reclamation.
                for ordinal in first..first + count as u64 {
                    let indexed = self
                        .receipt_order
                        .get(epoch, ordinal)
                        .ok_or_else(|| invalid("native reclaim ordinal missing"))?;
                    let row = self
                        .receipt(&indexed.id)
                        .ok_or_else(|| invalid("native reclaim row missing"))?;
                    if row.ordinal != ordinal || row.retained_until != indexed.retained_until {
                        return Err(invalid("native reclaim row differs from admitted order"));
                    }
                    self.receipt_order.remove_prefix(indexed.id, ordinal)?;
                    self.receipts.remove(&indexed.id);
                    self.receipt_removals.insert(indexed.id);
                }
                let retired = FencedTransitionV2HistoryEpoch::new(epoch)
                    .map_err(|_| invalid("native retired epoch invalid"))?;
                Some(
                    FencedTransitionV2HistoryState::new(
                        Some(active),
                        Some(retired),
                        (remaining > count).then_some(retired),
                        remaining - count,
                        generation,
                        history.bound_entries(),
                        history.reclaimed_entries() + count as u64,
                    )
                    .map_err(|_| invalid("native reclaimed history invalid"))?,
                )
            }
        };
        if let Some(updated) = updated {
            self.frontiers.history = Some(updated);
        }
        self.receipt_order.validate(self.frontiers.history)?;
        let sequence = self.frontiers.sequence + 1;
        let digest = command
            .calculate_applied_digest(sequence, self.frontiers.digest, now)
            .map_err(|_| invalid("native maintenance digest failed"))?;
        self.frontiers.sequence = sequence;
        self.frontiers.digest = digest;
        self.frontiers.logical_time = Some(now);
        Ok(self.response(index, Ok(SessionMutationOutcome::Unit)))
    }
}
