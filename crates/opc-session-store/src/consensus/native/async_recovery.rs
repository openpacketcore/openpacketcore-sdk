//! Replicated retirement of an Async authority range. The local reservation
//! and unanimous preparation are checked by the WAL owner before publication.
//! These state-machine predicates are independently repeated on cold input.

use super::*;
use crate::sqlite::consensus::wal::async_authority::Reservation;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Boundary {
    pub(crate) era: u64,
    pub(crate) plan: [u8; 32],
    pub(crate) applied: LogId<SessionConsensusNodeId>,
    watch_before: u64,
    history: HistoryRetirement,
}

// Cumulative discontinuities keep the ordinary lifecycle conservation law
// exact even when a writer coalesces mutations across several boundaries.
// Arrays, rather than a serde u128, preserve the existing JSON number domain.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRetirement {
    skipped_bindings: [u8; 16],
    skipped_rotations: u64,
    reclaimed: u64,
    skipped_generations: u64,
}

impl Boundary {
    pub(crate) fn from_entry(
        era: u64,
        plan: [u8; 32],
        applied: LogId<SessionConsensusNodeId>,
    ) -> Self {
        Self {
            era,
            plan,
            applied,
            watch_before: 0,
            history: HistoryRetirement::default(),
        }
    }
    pub(crate) fn validate(&self) -> io::Result<()> {
        let reservation = Reservation::from_era(self.era)?;
        if self.era < 2
            || self.plan == [0; 32]
            || self.applied.index == 0
            || self.applied.leader_id.term <= reservation.retired_through()
        {
            return Err(invalid("native asynchronous recovery boundary differs"));
        }
        if self.history.skipped_rotations > self.floor()
            || u128::from_be_bytes(self.history.skipped_bindings)
                > u128::from(self.history.skipped_rotations)
                    * FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u128
            || self.history.skipped_generations > reservation.ceiling()
            || self.history.reclaimed > COUNTER_MAX
        {
            return Err(invalid("native asynchronous history retirement differs"));
        }
        reservation.check(self.applied.index)?;
        reservation.check(self.applied.leader_id.term)
    }

    fn floor(&self) -> u64 {
        // Every producer and independent cold reader validates the era first.
        Reservation::from_era(self.era)
            .map(Reservation::retired_through)
            .unwrap_or(COUNTER_MAX)
    }
}

impl NativeFrontierValues {
    pub(super) fn async_fence_floor(&self) -> u64 {
        self.async_recovery.as_ref().map_or(0, Boundary::floor)
    }

    pub(super) fn validate_async_boundary(&self) -> io::Result<()> {
        let Some(boundary) = &self.async_recovery else {
            return Ok(());
        };
        boundary.validate()?;
        let floor = boundary.floor();
        if self.next_fence <= floor
            || self.next_credential <= floor
            || self.restore_revision <= floor
            || self.applied.is_none_or(|applied| {
                applied.index < boundary.applied.index
                    || applied.leader_id < boundary.applied.leader_id
                    || (applied.index == boundary.applied.index && applied != boundary.applied)
            })
        {
            return Err(invalid("native asynchronous recovery frontiers differ"));
        }
        if let Some(history) = self.history {
            if history
                .active_epoch()
                .is_none_or(|active| active.get() <= floor)
                || history
                    .retired_through()
                    .is_none_or(|retired| retired.get() < floor)
                || history.generation() <= floor
                || history.generation() < boundary.history.skipped_generations
                || history.reclaimed_entries() < boundary.history.reclaimed
            {
                return Err(invalid("native asynchronous history frontier differs"));
            }
        } else if boundary.history.reclaimed != 0
            || boundary.history.skipped_generations != floor + 1
        {
            return Err(invalid("native asynchronous history activation differs"));
        }
        // Independently check a cold base against genesis. A delta also checks
        // its predecessor, but a rewritten full image has no prior interval
        // from which to recover omitted binding/reclamation evidence.
        let total = u128::from(self.effective_history_epoch() - 1)
            * FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u128
            + self.history.map_or(0, |history| history.bound_entries()) as u128;
        let issued = total
            .checked_sub(u128::from_be_bytes(boundary.history.skipped_bindings))
            .ok_or_else(|| invalid("native asynchronous history total regressed"))?;
        if issued
            != lifecycle::receipt_count(self.history)? as u128
                + u128::from(
                    self.history
                        .map_or(0, |history| history.reclaimed_entries()),
                )
        {
            return Err(invalid(
                "native asynchronous history total conservation differs",
            ));
        }
        let reservation = Reservation::from_era(boundary.era)?;
        reservation.check(self.outward_watch(self.watch_sequence)?)
    }
}

impl NativeKeyState {
    pub(super) fn apply_async_floor(&mut self, floor: u64) {
        self.fence = self.fence.max(floor);
        if let Some(lease) = self.lease.as_mut() {
            if lease.fence.get() <= floor || lease.credential_id <= floor {
                lease.active = false;
            }
        }
    }
}

#[cfg(test)]
#[path = "async_recovery_tests.rs"]
mod tests;

impl NativeDelta<'_> {
    pub(super) fn apply_async_boundary(
        &mut self,
        command: &SessionConsensusCommand,
        applied: LogId<SessionConsensusNodeId>,
    ) -> io::Result<SessionConsensusResponse> {
        crate::sqlite::consensus::validate_command_for_log(command, self.base.identity)?;
        let SessionMutationIntent::AsyncRecoveryBoundary { era, plan } = command.intent else {
            return Err(invalid("native asynchronous recovery command differs"));
        };
        let mut boundary = Boundary::from_entry(era, plan, applied);
        boundary.validate()?;
        if self
            .frontiers
            .async_recovery
            .as_ref()
            .is_some_and(|prior| prior.era >= era)
        {
            return Err(invalid("native asynchronous recovery era did not advance"));
        }
        // A recovery capability must account for every activated authority
        // vocabulary before it prepares a round. Do not partially retire an
        // unsupported protected history or roster.
        if self.frontiers.roster_v1_namespace
            || self.frontiers.roster_v2_activation.is_some()
            || !self.roster.rows.is_empty()
            || !self.roster.partitions.is_empty()
        {
            return Err(invalid("native asynchronous recovery capability differs"));
        }
        let floor = boundary.floor();
        if self.frontiers.next_fence > floor
            || self.frontiers.next_credential > floor
            || self.frontiers.restore_revision > floor
        {
            return Err(invalid(
                "native asynchronous recovery range does not cover state",
            ));
        }
        let now = self
            .frontiers
            .logical_time
            .map_or(command.logical_time, |prior| {
                prior.max(command.logical_time)
            });
        let sequence = self
            .frontiers
            .sequence
            .checked_add(1)
            .filter(|value| *value <= COUNTER_MAX)
            .ok_or_else(|| invalid("native asynchronous recovery sequence exhausted"))?;
        let digest = command
            .calculate_applied_digest(sequence, self.frontiers.digest, now)
            .map_err(|_| invalid("native asynchronous recovery digest failed"))?;
        boundary.history = self.retire_async_history(floor)?;
        boundary.watch_before = self.frontiers.watch_sequence;
        self.frontiers.next_fence = floor + 1;
        self.frontiers.next_credential = floor + 1;
        self.frontiers.restore_revision = floor + 1;
        self.frontiers.async_recovery = Some(boundary);
        self.frontiers.sequence = sequence;
        self.frontiers.digest = digest;
        self.frontiers.logical_time = Some(now);
        Ok(self.response(applied.index, Ok(SessionMutationOutcome::Unit)))
    }
}

impl NativeFrontierValues {
    pub(super) fn async_history_epoch(&self) -> u64 {
        self.async_fence_floor() + 1
    }

    pub(super) fn async_history_generation(&self) -> u64 {
        self.async_recovery.as_ref().map_or(0, |b| b.floor() + 1)
    }

    fn effective_history_generation(&self) -> u64 {
        self.history.map_or_else(
            || self.async_history_generation(),
            |history| history.generation(),
        )
    }

    pub(super) fn async_watch_before(&self) -> u64 {
        self.async_recovery.as_ref().map_or(0, |b| b.watch_before)
    }

    pub(super) fn outward_watch(&self, raw: u64) -> io::Result<u64> {
        raw.checked_sub(self.async_watch_before())
            .and_then(|sequence| sequence.checked_add(self.async_fence_floor()))
            .ok_or_else(|| invalid("native recovered watch sequence differs"))
    }

    pub(super) fn async_history_retired(
        &self,
    ) -> io::Result<Option<crate::FencedTransitionV2HistoryEpoch>> {
        let floor = self.async_fence_floor();
        if floor == 0 {
            return Ok(None);
        }
        crate::FencedTransitionV2HistoryEpoch::new(floor)
            .map(Some)
            .map_err(|_| invalid("native asynchronous history floor invalid"))
    }

    fn history_retirement(&self) -> HistoryRetirement {
        self.async_recovery
            .as_ref()
            .map_or(HistoryRetirement::default(), |b| b.history)
    }

    fn effective_history_epoch(&self) -> u64 {
        self.history
            .and_then(|h| h.active_epoch())
            .map_or_else(|| self.async_history_epoch(), |e| e.get())
    }
}

impl NativeDelta<'_> {
    fn retire_async_history(&mut self, floor: u64) -> io::Result<HistoryRetirement> {
        let mut accounting = self.frontiers.history_retirement();
        let history = self.frontiers.history;
        let rotations = (floor + 1)
            .checked_sub(self.frontiers.effective_history_epoch())
            .ok_or_else(|| invalid("native asynchronous history epoch regressed"))?;
        let bindings = u128::from(rotations) * FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u128;
        let bindings = bindings
            .checked_sub(history.map_or(0, |h| h.bound_entries()) as u128)
            .ok_or_else(|| invalid("native asynchronous history binding retirement regressed"))?;
        accounting.skipped_rotations = accounting
            .skipped_rotations
            .checked_add(rotations)
            .ok_or_else(|| invalid("native asynchronous history rotations exhausted"))?;
        accounting.skipped_bindings = u128::from_be_bytes(accounting.skipped_bindings)
            .checked_add(bindings)
            .ok_or_else(|| invalid("native asynchronous history bindings exhausted"))?
            .to_be_bytes();
        let count = lifecycle::receipt_count(history)? as u64;
        let generation = floor + 1;
        let skipped = generation
            .checked_sub(self.frontiers.effective_history_generation())
            .ok_or_else(|| invalid("native asynchronous history generation regressed"))?;
        accounting.skipped_generations = accounting
            .skipped_generations
            .checked_add(skipped)
            .ok_or_else(|| invalid("native asynchronous history generations exhausted"))?;
        if let Some(history) = history {
            accounting.reclaimed = accounting
                .reclaimed
                .checked_add(count)
                .ok_or_else(|| invalid("native asynchronous history reclamation exhausted"))?;
            let reclaimed = history
                .reclaimed_entries()
                .checked_add(count)
                .filter(|value| *value <= COUNTER_MAX)
                .ok_or_else(|| invalid("native asynchronous history reclaim counter exhausted"))?;
            self.frontiers.history = Some(
                FencedTransitionV2HistoryState::new(
                    Some(
                        crate::FencedTransitionV2HistoryEpoch::new(floor + 1).map_err(|_| {
                            invalid("native asynchronous history successor invalid")
                        })?,
                    ),
                    Some(
                        crate::FencedTransitionV2HistoryEpoch::new(floor).map_err(|_| {
                            invalid("native asynchronous history predecessor invalid")
                        })?,
                    ),
                    None,
                    0,
                    generation,
                    0,
                    reclaimed,
                )
                .map_err(|_| invalid("native asynchronous history state invalid"))?,
            );
        }
        for id in self
            .base
            .receipts
            .iter()
            .map(|(id, _)| id)
            .chain(self.receipts.keys())
        {
            self.receipt_removals.insert(*id);
        }
        self.receipts.clear();
        self.receipt_order = history_order::ReceiptOrder::default();
        Ok(accounting)
    }
}

pub(super) fn history_conservation(
    before: &NativeFrontiers,
    after: &NativeFrontiers,
    added: usize,
    removed: usize,
    transient: usize,
) -> io::Result<()> {
    if before.async_recovery.is_none() && after.async_recovery.is_none() {
        return lifecycle::conservation(before.history, after.history, added, removed, transient);
    }
    let old = before.history_retirement();
    let new = after.history_retirement();
    let skipped = u128::from_be_bytes(new.skipped_bindings)
        .checked_sub(u128::from_be_bytes(old.skipped_bindings))
        .ok_or_else(|| invalid("native asynchronous skipped bindings regressed"))?;
    let rotations = after
        .effective_history_epoch()
        .checked_sub(before.effective_history_epoch())
        .ok_or_else(|| invalid("native asynchronous active epoch regressed"))?;
    let bound = (u128::from(rotations) * FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u128
        + after.history.map_or(0, |h| h.bound_entries()) as u128)
        .checked_sub(before.history.map_or(0, |h| h.bound_entries()) as u128)
        .and_then(|value| value.checked_sub(skipped))
        .ok_or_else(|| invalid("native asynchronous bindings regressed"))?;
    let deleted = after
        .history
        .map_or(0, |h| h.reclaimed_entries())
        .checked_sub(before.history.map_or(0, |h| h.reclaimed_entries()))
        .ok_or_else(|| invalid("native reclaimed count regressed"))?;
    if bound != added as u128 + transient as u128
        || u128::from(deleted) != removed as u128 + transient as u128
        || lifecycle::receipt_count(before.history)? as u128 + bound
            != lifecycle::receipt_count(after.history)? as u128 + u128::from(deleted)
    {
        return Err(invalid(
            "native history binding and reclamation conservation differs",
        ));
    }
    Ok(())
}

pub(super) fn history_transition(
    before: &NativeFrontiers,
    after: &NativeFrontiers,
) -> io::Result<()> {
    if before.async_recovery.is_none() && after.async_recovery.is_none() {
        return lifecycle::transition(before.history, after.history);
    }
    lifecycle::ranges(before.history)?;
    lifecycle::ranges(after.history)?;
    let old = before.history_retirement();
    let new = after.history_retirement();
    let sub = |next: u64, prior: u64| {
        next.checked_sub(prior)
            .ok_or_else(|| invalid("native asynchronous lifecycle counter regressed"))
    };
    let rotations = sub(
        after.effective_history_epoch(),
        before.effective_history_epoch(),
    )?;
    let normal_rotations = sub(
        rotations,
        sub(new.skipped_rotations, old.skipped_rotations)?,
    )?;
    let generations = sub(
        after.effective_history_generation(),
        before.effective_history_generation(),
    )?;
    let skipped_generations = sub(new.skipped_generations, old.skipped_generations)?;
    let reclaimed = sub(
        after.history.map_or(0, |h| h.reclaimed_entries()),
        before.history.map_or(0, |h| h.reclaimed_entries()),
    )?;
    let normal_reclaimed = sub(reclaimed, sub(new.reclaimed, old.reclaimed)?)?;
    let changed = rotations != 0
        || lifecycle::floor(before.history) != lifecycle::floor(after.history)
        || before.history.and_then(|h| h.reclaim_epoch())
            != after.history.and_then(|h| h.reclaim_epoch())
        || before.history.map_or(0, |h| h.reclaim_remaining())
            != after.history.map_or(0, |h| h.reclaim_remaining())
        || reclaimed != 0;
    if (before.history.is_some() && after.history.is_none())
        || lifecycle::floor(after.history) < lifecycle::floor(before.history)
        || (rotations == 0
            && after.history.map_or(0, |h| h.bound_entries())
                < before.history.map_or(0, |h| h.bound_entries()))
        || (before.history.is_some() && changed != (generations != 0))
        || u128::from(generations)
            < u128::from(normal_rotations)
                + u128::from(
                    normal_reclaimed.div_ceil(
                        crate::fenced_transition::FENCED_TRANSITION_V2_RECLAIM_BATCH as u64,
                    ),
                )
                + u128::from(skipped_generations)
        || u128::from_be_bytes(new.skipped_bindings) < u128::from_be_bytes(old.skipped_bindings)
    {
        return Err(invalid("native history lifecycle transition differs"));
    }
    Ok(())
}
