//! Resident acknowledgement with one coalescing, selected after-image writer.
//! The foreground owns no disk request or disk-capacity wait. The native
//! journal and verified reads retain their existing finite memory bound.

use super::*;
use crate::consensus::{SessionAsyncPersistenceProgress, SessionStorageFailureKind};

const CAPTURE_INTERVAL: Duration = Duration::from_millis(250);
pub(super) const MAX_GENERATION_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub(super) struct Observation {
    pub(super) generation: u64,
    pub(super) completed: checkpoint::AsyncCut,
    pub(super) captured: Option<u64>,
    lag_since: Option<Instant>,
    completed_bytes: u64,
    pub(super) failure: Option<SessionStorageFailure>,
}

impl Observation {
    pub(super) fn recovered(anchor: Option<&checkpoint::Anchor>) -> io::Result<Self> {
        let completed = match anchor {
            Some(anchor) => anchor
                .async_cut
                .ok_or_else(|| invalid_data("asynchronous observation lacks its selected cut"))?,
            None => checkpoint::AsyncCut {
                generation: 0,
                sequence: 0,
                committed: None,
                applied: None,
            },
        };
        let generation = completed
            .generation
            .checked_add(1)
            .filter(|generation| *generation != u64::MAX)
            .ok_or_else(|| invalid_data("asynchronous generation exhausted"))?;
        // Cold replay and the local restore incarnation may change resident
        // state without a new log callback. Persist that exact startup state.
        Ok(Self {
            generation,
            completed,
            captured: None,
            lag_since: Some(Instant::now()),
            completed_bytes: anchor.map_or(0, |anchor| anchor.basis_bytes),
            failure: None,
        })
    }

    pub(super) fn caught_up(&self) -> bool {
        self.completed.generation == self.generation && self.captured.is_none()
    }

    pub(super) fn completed(&mut self, cut: checkpoint::AsyncCut, bytes: u64) {
        self.completed = cut;
        self.completed_bytes = bytes;
        self.captured = None;
        if cut.generation == self.generation {
            self.lag_since = None;
        }
    }

    pub(super) fn observe(&self, resident_sequence: u64) -> SessionAsyncPersistenceProgress {
        SessionAsyncPersistenceProgress {
            resident_generation: self.generation,
            completed_generation: self.completed.generation,
            captured_generation: self.captured,
            resident_sequence,
            completed_sequence: self.completed.sequence,
            completed_committed_index: self.completed.committed.map(|id| id.index),
            completed_applied_index: self.completed.applied.map(|id| id.index),
            lag_millis: self.lag_since.map_or(0, |since| {
                u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
            }),
            completed_bytes: self.completed_bytes,
            generation_limit_bytes: MAX_GENERATION_BYTES,
            saturated: self.failure.is_some_and(|failure| {
                matches!(
                    failure.kind,
                    SessionStorageFailureKind::StorageFull | SessionStorageFailureKind::OutOfMemory
                )
            }),
            background_failure: self.failure,
        }
    }
}

pub(super) fn dirty(state: &mut State) {
    if let Some(progress) = &mut state.asynchronous {
        progress.generation = progress.generation.saturating_add(1);
        progress.lag_since.get_or_insert_with(Instant::now);
    }
}

pub(super) fn admit(
    wal: &Wal,
    state: &mut State,
    operation: &Operation,
    mut completion: Completion,
) -> io::Result<()> {
    let sequence = state
        .sequence
        .checked_add(1)
        .filter(|sequence| *sequence != u64::MAX)
        .ok_or_else(|| invalid_data("asynchronous storage sequence exhausted"))?;
    if state
        .asynchronous
        .as_ref()
        .is_none_or(|progress| progress.generation >= u64::MAX - 1)
    {
        return Err(invalid_data("asynchronous generation exhausted"));
    }
    application::project_operation(state, wal.binding, operation)?;
    state.sequence = sequence;
    dirty(state);
    // This completes storage admission only. Openraft still performs actual
    // quorum replication and state-machine application before public success.
    completion.finish(Ok(sequence));
    wal.shared.ready.notify_all();
    Ok(())
}

pub(super) fn write_loop(
    shared: &Arc<Shared>,
    disk: &mut Disk,
    basis: &mut native_basis::Owner,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
) -> io::Result<()> {
    let mut next_capture = Instant::now() + CAPTURE_INTERVAL;
    loop {
        if basis.has_relocations() {
            basis.relocate_step(shared, disk, control)?;
            continue;
        }
        let mut state = lock_state(shared)?;
        loop {
            ensure_readable(&state)?;
            let progress = state
                .asynchronous
                .as_ref()
                .ok_or_else(|| invalid_data("asynchronous writer lost its mode"))?;
            if let Some(failure) = progress.failure {
                if state.status != Status::Running {
                    application::record_failure(&mut state, failure);
                    return Err(io::Error::other(
                        "asynchronous persistence failed before drain",
                    ));
                }
                state = shared
                    .ready
                    .wait(state)
                    .map_err(|_| io::Error::other("asynchronous failed-writer wait poisoned"))?;
                continue;
            }
            if state.snapshot.is_some() {
                if !progress.caught_up() {
                    return Err(invalid_data(
                        "asynchronous install predecessor is not selected",
                    ));
                }
                drop(state);
                snapshot::advance_native(shared, disk, basis, binding, limits, control)?;
                state = lock_state(shared)?;
                continue;
            }
            if state.status != Status::Running && progress.caught_up() {
                state.status = Status::Closed;
                shared.ready.notify_all();
                return Ok(());
            }
            let requested = state.checkpoint_requested
                || state.native_snapshot_pending.is_some()
                || state.native_checkpoint_target.is_some();
            let force =
                requested || state.native_install_pending || state.status != Status::Running;
            if !progress.caught_up() && (force || Instant::now() >= next_capture) {
                break;
            }
            if progress.caught_up() {
                state = shared
                    .ready
                    .wait(state)
                    .map_err(|_| io::Error::other("asynchronous writer wait poisoned"))?;
            } else {
                state = shared
                    .ready
                    .wait_timeout(
                        state,
                        next_capture.saturating_duration_since(Instant::now()),
                    )
                    .map_err(|_| io::Error::other("asynchronous writer schedule poisoned"))?
                    .0;
            }
        }
        let capture_started = Instant::now();
        let mut anchor = disk
            .anchor
            .clone()
            .ok_or_else(|| invalid_data("asynchronous capture lacks its selected predecessor"))?;
        let old_epoch = anchor.epoch;
        anchor.epoch = old_epoch
            .checked_add(1)
            .filter(|epoch| *epoch != u64::MAX)
            .ok_or_else(|| invalid_data("asynchronous checkpoint epoch exhausted"))?;
        let sequence = state.sequence;
        let generation = state
            .asynchronous
            .as_ref()
            .ok_or_else(|| invalid_data("asynchronous capture observation missing"))?
            .generation;
        let candidate = state.native_snapshot_pending.clone();
        if let (Some(snapshots), Some(candidate)) = (&mut anchor.native_snapshots, &candidate) {
            snapshots.current = candidate.clone();
        }
        let native = state
            .native
            .as_mut()
            .ok_or_else(|| invalid_data("asynchronous capture owner missing"))?;
        let cut = checkpoint::AsyncCut {
            generation,
            sequence,
            committed: native.log.committed,
            applied: native.business.applied(),
        };
        anchor.async_cut = Some(cut);
        let (changes, snapshot_selection) = native.take_checkpoint_changes(candidate.clone())?;
        state
            .asynchronous
            .as_mut()
            .ok_or_else(|| invalid_data("asynchronous capture observation disappeared"))?
            .captured = Some(generation);
        state.native_basis_active = true;
        state.checkpoint_requested = false;
        let capture_time = capture_started.elapsed();
        state.checkpoint_costs.native_capture += capture_time;
        state.checkpoint_costs.native_owner_maximum = state
            .checkpoint_costs
            .native_owner_maximum
            .max(capture_time);
        drop(state);

        // Encoding, append verification, sync and selector replacement all run
        // with no State guard. Exactly one capture and writer own this work.
        let started = Instant::now();
        next_capture = started + CAPTURE_INTERVAL;
        let result = (|| {
            let relocations = basis.append_async(changes, &mut anchor, binding, limits, control)?;
            checkpoint::select(&disk.directory, &anchor, control)?;
            Ok::<_, io::Error>(relocations)
        })();
        let mut state = lock_state(shared)?;
        ensure_readable(&state)?;
        if state.checkpoint_epoch != old_epoch
            || state
                .asynchronous
                .as_ref()
                .and_then(|progress| progress.captured)
                != Some(generation)
        {
            return Err(invalid_data(
                "asynchronous publication lost its predecessor",
            ));
        }
        state.native_basis_active = false;
        match result {
            Ok(relocations) => {
                if let Some(selection) = snapshot_selection {
                    state
                        .native
                        .as_mut()
                        .ok_or_else(|| {
                            invalid_data("asynchronous snapshot publication owner missing")
                        })?
                        .business
                        .publish_checkpoint_snapshot(selection)?;
                    if state.native_snapshot_pending != candidate {
                        return Err(invalid_data("asynchronous snapshot publication changed"));
                    }
                    state.native_snapshot_pending = None;
                }
                state.base_sequence = cut.sequence;
                state.checkpoint_epoch = anchor.epoch;
                state.durable_committed = cut.committed;
                state.authority.frozen_applied = cut.applied;
                state.native_relocations_pending = !relocations.is_empty();
                state
                    .asynchronous
                    .as_mut()
                    .ok_or_else(|| invalid_data("asynchronous publication observation missing"))?
                    .completed(cut, anchor.basis_bytes);
                if state
                    .native_checkpoint_target
                    .is_some_and(|target| target.satisfied(&state))
                {
                    state.native_checkpoint_target = None;
                }
                state.checkpoint_requested = state.native_checkpoint_target.is_some()
                    || state.native_snapshot_pending.is_some();
                let elapsed = started.elapsed();
                state.checkpoint_costs.completed += 1;
                state.checkpoint_costs.elapsed += elapsed;
                state.checkpoint_costs.maximum = state.checkpoint_costs.maximum.max(elapsed);
                state.checkpoint_costs.native_basis_count += 1;
                state.checkpoint_costs.native_basis_bytes += anchor.basis_bytes;
                disk.anchor = Some(anchor);
                basis.begin_async_relocations(relocations)?;
            }
            Err(error) => {
                let failure =
                    SessionStorageFailure::from_io(SessionStorageFailureStage::Persistence, &error);
                let progress = state
                    .asynchronous
                    .as_mut()
                    .ok_or_else(|| invalid_data("asynchronous failed observation missing"))?;
                progress.captured = None;
                progress.failure = Some(failure);
                state.checkpoint_costs.failures += 1;
                // Resident authority survives an ordinary I/O failure while
                // its finite native allocation permits progress. Corruption
                // still fences the original owner immediately.
                if failure.kind == SessionStorageFailureKind::InvalidData {
                    application::record_failure(&mut state, failure);
                    return Err(error);
                }
            }
        }
        shared.ready.notify_all();
    }
}
