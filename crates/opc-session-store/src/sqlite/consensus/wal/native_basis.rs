//! One immutable capture and one owned preparation thread. The writer alone
//! selects CURRENT; newer admitted projections, callbacks and published WAL
//! cuts remain live throughout preparation and survive selection unchanged.

use super::*;
use crate::consensus::native::NativeStorage;

mod generation;
pub(super) use generation::{bootstrap, Selected};

#[derive(Clone, Copy)]
pub(super) struct Target {
    epoch: u64,
    sequence: u64,
    applied: Option<LogId<SessionConsensusNodeId>>,
}

impl Target {
    pub(super) fn requested(state: &State) -> io::Result<Self> {
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native checkpoint owner missing"))?;
        Ok(Self {
            epoch: state.checkpoint_epoch,
            sequence: state.sequence,
            applied: native.business.applied(),
        })
    }

    pub(super) fn satisfied(self, state: &State) -> bool {
        state.checkpoint_epoch > self.epoch
            && state.base_sequence >= self.sequence
            && pointer_covers(state.authority.frozen_applied, self.applied)
    }
}

fn pointer_covers(
    current: Option<LogId<SessionConsensusNodeId>>,
    requested: Option<LogId<SessionConsensusNodeId>>,
) -> bool {
    requested.is_none_or(|requested| {
        current.is_some_and(|current| {
            super::super::ensure_log_id_not_after(
                &requested,
                &current,
                "native captured pointer regressed",
            )
            .is_ok()
        })
    })
}

pub(super) fn needed(state: &State, disk: &Disk, limits: Limits) -> bool {
    if state.native_basis_active || state.snapshot.is_some() {
        return false;
    }
    if state.checkpoint_requested
        || state.native_checkpoint_target.is_some()
        || state.native_snapshot_pending.is_some()
    {
        return true;
    }
    // These are preparation triggers, not additional capacity. All original
    // admission and recovery limits continue to apply to the retained suffix.
    state.status == Status::Running
        && !state.native_install_pending
        && state.sequence > state.base_sequence
        && (state.sequence - state.base_sequence >= limits.history_count.div_ceil(4) as u64
            || state.history_bytes >= limits.history_bytes.div_ceil(4)
            || disk.segment - disk.base_position().segment >= limits.segments.div_ceil(4) as u64)
}

struct Capture {
    changes: crate::consensus::native::NativeChanges,
    binding: Binding,
    limits: Limits,
    directory: PathBuf,
    epoch: u64,
    base_sequence: u64,
    history_bytes: usize,
    position: CutPosition,
    cut: u64,
    cut_chain: [u8; 32],
    durable_cut: DurableCut,
    applied: Option<LogId<SessionConsensusNodeId>>,
    snapshot: Option<super::super::CurrentSnapshot>,
    snapshot_selection: Option<crate::consensus::native::SnapshotSelection>,
    native_snapshots: Option<checkpoint::NativeSnapshots>,
    started: Instant,
    _memory: crate::consensus::verified_snapshot::VerificationMemory,
}

pub(super) struct Prepared {
    anchor: checkpoint::Anchor,
    old_epoch: u64,
    old_base_sequence: u64,
    covered_bytes: usize,
    snapshot: Option<super::super::CurrentSnapshot>,
    snapshot_selection: Option<crate::consensus::native::SnapshotSelection>,
    selected: Selected,
    relocations: crate::consensus::native::generation::Relocations,
    costs: integration::CheckpointCosts,
    elapsed: Duration,
}

pub(super) struct Owner {
    selected: Option<Selected>,
    worker: Option<JoinHandle<io::Result<Prepared>>>,
    relocations: Option<crate::consensus::native::generation::Relocations>,
}

impl Owner {
    pub(super) fn new(selected: Option<Selected>) -> Self {
        Self {
            selected,
            worker: None,
            relocations: None,
        }
    }

    pub(super) fn has_relocations(&self) -> bool {
        self.relocations.is_some()
    }

    pub(super) fn require_install_owner(&self, anchor: &checkpoint::Anchor) -> io::Result<()> {
        if self.worker.is_some()
            || self.relocations.is_some()
            || self
                .selected
                .as_ref()
                .map(|selected| selected.append.current().identity())
                != anchor.native_prefix()?
        {
            return Err(invalid_data(
                "native install lacks exclusive selected generation ownership",
            ));
        }
        Ok(())
    }

    pub(super) fn replace_for_install(
        &mut self,
        old: &checkpoint::Anchor,
        next: Selected,
    ) -> io::Result<Selected> {
        self.require_install_owner(old)?;
        self.selected
            .replace(next)
            .ok_or_else(|| invalid_data("native install selected owner disappeared"))
    }

    pub(super) fn start(
        &mut self,
        shared: &Arc<Shared>,
        state: &mut State,
        disk: &Disk,
        binding: Binding,
        limits: Limits,
        control: &IoControl,
    ) -> io::Result<()> {
        let started = Instant::now();
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native basis owner missing"))?;
        let selected = self
            .selected
            .as_ref()
            .ok_or_else(|| invalid_data("native append generation owner missing"))?;
        let previous = selected.append.current().identity();
        if self.worker.is_some()
            || self.relocations.is_some()
            || state.native_basis_active
            || state.native_basis_ready
            || state.snapshot.is_some()
            || state.outstanding != 0
            || !state.queue.is_empty()
            || state.sequence != disk.sequence
            || native.log.committed != state.durable_committed
            || state.application_marker.is_some()
            || previous.checkpoint_epoch != state.checkpoint_epoch
            || previous.operation_sequence != state.base_sequence
            || disk
                .anchor
                .as_ref()
                .and_then(|anchor| anchor.native_prefix().ok())
                .flatten()
                != Some(previous)
        {
            return Err(invalid_data(
                "native basis capture is not a drained selected cut",
            ));
        }
        let durable_cut = *state
            .durable_cuts
            .get(&disk.sequence)
            .filter(|cut| cut.chain == disk.chain && cut.committed == native.log.committed)
            .ok_or_else(|| invalid_data("native basis lacks its exact durable cut"))?;
        if disk.cuts.get(&disk.sequence) != Some(&durable_cut) {
            return Err(invalid_data("native disk and owner cuts differ"));
        }
        let epoch = state
            .checkpoint_epoch
            .checked_add(1)
            .filter(|epoch| *epoch != u64::MAX)
            .ok_or_else(|| invalid_data("native basis epoch exhausted"))?;
        let memory = crate::consensus::verified_snapshot::VerificationMemory::reserve(64 * 1024)?;
        let applied = native.business.applied();
        let snapshot = state.native_snapshot_pending.clone();
        let mut native_snapshots = disk
            .anchor
            .as_ref()
            .and_then(|anchor| anchor.native_snapshots.clone());
        if let (Some(snapshots), Some(current)) = (&mut native_snapshots, &snapshot) {
            snapshots.current = current.clone();
        }
        let (changes, snapshot_selection) = state
            .native
            .as_mut()
            .ok_or_else(|| invalid_data("native checkpoint capture owner missing"))?
            .take_checkpoint_changes(snapshot.clone())?;
        let capture = Capture {
            changes,
            binding,
            limits,
            directory: disk.directory.clone(),
            epoch,
            base_sequence: state.base_sequence,
            history_bytes: state.history_bytes,
            position: disk.position(),
            cut: disk.cut,
            cut_chain: disk.cut_chain,
            durable_cut,
            applied,
            snapshot,
            snapshot_selection,
            native_snapshots,
            started,
            _memory: memory,
        };
        let selected = self
            .selected
            .take()
            .ok_or_else(|| invalid_data("native checkpoint selected owner disappeared"))?;
        let shared = Arc::clone(shared);
        let control = control.clone();
        self.worker = Some(
            std::thread::Builder::new()
                .name("session-native-basis".into())
                .spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        prepare(capture, selected, &control, &|| {
                            let state = lock_state(&shared)?;
                            ensure_readable(&state)
                        })
                    }))
                    .unwrap_or_else(|_| Err(io::Error::other("native basis worker panicked")));
                    let mut state = match shared.state.lock() {
                        Ok(state) => state,
                        Err(poison) => poison.into_inner(),
                    };
                    if result.is_err() {
                        state.checkpoint_costs.failures += 1;
                        application::fence(&mut state);
                    }
                    state.native_basis_ready = true;
                    shared.ready.notify_all();
                    result
                })?,
        );
        state.native_basis_active = true;
        state.checkpoint_requested = false;
        let elapsed = started.elapsed();
        state.checkpoint_costs.native_capture += elapsed;
        state.checkpoint_costs.native_owner_maximum =
            state.checkpoint_costs.native_owner_maximum.max(elapsed);
        Ok(())
    }

    /// State is released before joining. The worker takes it to signal its
    /// result, and its append descriptor must retire before directory LOCK.
    pub(super) fn join(&mut self) -> io::Result<Option<Prepared>> {
        self.worker
            .take()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| io::Error::other("native basis worker join panicked"))?
            })
            .transpose()
    }

    pub(super) fn select(
        &mut self,
        shared: &Arc<Shared>,
        disk: &mut Disk,
        prepared: Prepared,
        binding: Binding,
        limits: Limits,
        control: &IoControl,
    ) -> io::Result<()> {
        if self.selected.is_some() || self.worker.is_some() || self.relocations.is_some() {
            return Err(invalid_data("native selection owner is not detached"));
        }
        let (selected, relocations) = select(shared, disk, prepared, binding, limits, control)?;
        self.selected = Some(selected);
        if !relocations.is_empty() {
            self.relocations = Some(relocations);
        }
        Ok(())
    }

    /// Exactly one fixed-size relocation unit, then back to the writer's
    /// ordinary queue. Pending units keep the same selected append owner and
    /// preparation guard; no next checkpoint starts until those units drain.
    /// Existing admission limits provide backpressure while the queue drains.
    pub(super) fn relocate_step(
        &mut self,
        shared: &Arc<Shared>,
        disk: &Disk,
        control: &IoControl,
    ) -> io::Result<()> {
        let selected = self
            .selected
            .as_ref()
            .ok_or_else(|| invalid_data("native relocation selected owner missing"))?;
        let prefix = selected.append.current().identity();
        let rows = self
            .relocations
            .as_mut()
            .ok_or_else(|| invalid_data("native relocation work missing"))?;
        let mut state = lock_state(shared)?;
        let held = Instant::now();
        ensure_readable(&state)?;
        if state.checkpoint_epoch != prefix.checkpoint_epoch
            || state.base_sequence != prefix.operation_sequence
            || state.native_basis_active
            || state.native_basis_ready
            || state.snapshot.is_some()
            || disk
                .anchor
                .as_ref()
                .and_then(|anchor| anchor.native_prefix().ok())
                .flatten()
                != Some(prefix)
        {
            return Err(invalid_data(
                "native relocation no longer owns its selected generation",
            ));
        }
        let retired = rows.publish_step(
            state
                .native
                .as_mut()
                .ok_or_else(|| invalid_data("native relocation resident owner missing"))?,
        )?;
        state.native_relocations_pending = retired.has_remaining();
        let elapsed = held.elapsed();
        state.checkpoint_costs.native_owner_publish += elapsed;
        state.checkpoint_costs.native_owner_maximum =
            state.checkpoint_costs.native_owner_maximum.max(elapsed);
        shared.ready.notify_all();
        drop(state);
        drop(retired);
        // This point is outside State and before the queue's next service.
        (control.hook)(Point::AfterNativeRelocationStep)?;
        if rows.is_empty() {
            self.relocations = None;
        }
        Ok(())
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.join();
    }
}

fn prepare(
    capture: Capture,
    mut selected: Selected,
    control: &IoControl,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Prepared> {
    let Capture {
        changes,
        binding,
        limits,
        directory,
        epoch,
        base_sequence,
        history_bytes,
        position,
        cut,
        cut_chain,
        durable_cut,
        applied,
        snapshot,
        snapshot_selection,
        native_snapshots,
        started,
        _memory,
    } = capture;
    check()?;
    let previous = selected.append.current();
    let old = previous.identity();
    let mut anchor = checkpoint::Anchor {
        root: binding.digest()?,
        epoch,
        basis: [0; 32],
        basis_bytes: old.block_bytes as u64,
        position,
        cut,
        cut_chain,
        prefix: checkpoint::hash_prefix(
            &directory.join(format!("segment-{:020}.wal", position.segment)),
            position.offset,
        )?,
        applied,
        marker: None,
        cuts: BTreeMap::from([(position.sequence, durable_cut)]),
        native: true,
        native_generation: Some(checkpoint::NativeGeneration {
            file_epoch: old.file_epoch,
            block_bytes: old.block_bytes,
            frontiers: [0; 32],
        }),
        native_snapshots,
    };
    let cut_binding = anchor.native_cut_binding()?;
    let serialize_started = Instant::now();
    let delta = crate::consensus::native::generation::PreparedDelta::prepare(
        previous,
        &selected.version,
        epoch,
        position.sequence,
        cut_binding,
        changes,
        check,
    )?;
    let serialized = Instant::now();
    (control.hook)(Point::BeforeNativeGenerationAppend)?;
    let (source, relocations) = delta.append_with_relocations(&mut selected.append, check)?;
    (control.hook)(Point::AfterNativeGenerationAppend)?;
    let verified = Instant::now();
    let identity = source.identity();
    anchor.basis = identity.digest;
    anchor.basis_bytes = identity.length;
    anchor.native_generation = Some(checkpoint::NativeGeneration {
        file_epoch: identity.file_epoch,
        block_bytes: identity.block_bytes,
        frontiers: identity.frontiers,
    });
    if anchor.native_prefix()? != Some(identity) || anchor.native_cut_binding()? != cut_binding {
        return Err(invalid_data(
            "native appended generation differs from captured selector",
        ));
    }
    anchor.validate(binding, limits)?;
    selected.version = delta.target_version();
    drop(delta);
    check()?;
    let costs = integration::CheckpointCosts {
        native_basis_count: 1,
        native_basis_bytes: identity
            .length
            .checked_sub(old.length)
            .ok_or_else(|| invalid_data("native appended extent regressed"))?,
        native_serialize: serialized.duration_since(serialize_started),
        native_decode_validate: verified.duration_since(serialized),
        ..Default::default()
    };
    Ok(Prepared {
        anchor,
        old_epoch: epoch - 1,
        old_base_sequence: base_sequence,
        covered_bytes: history_bytes,
        snapshot,
        snapshot_selection,
        selected,
        relocations,
        costs,
        elapsed: started.elapsed(),
    })
}

fn validate_selection(
    state: &State,
    disk: &Disk,
    prepared: &Prepared,
    binding: Binding,
    limits: Limits,
) -> io::Result<usize> {
    let Prepared {
        anchor,
        old_epoch,
        old_base_sequence,
        covered_bytes,
        snapshot,
        selected,
        ..
    } = prepared;
    anchor.validate(binding, limits)?;
    let captured_cut = anchor
        .cuts
        .get(&anchor.position.sequence)
        .ok_or_else(|| invalid_data("native selected cut missing"))?;
    let native = state
        .native
        .as_ref()
        .ok_or_else(|| invalid_data("native selection owner missing"))?;
    if !state.native_basis_active
        || !state.native_basis_ready
        || !anchor.native
        || anchor.marker.is_some()
        || anchor.cuts.len() != 1
        || state.snapshot.is_some()
        || state.application_marker.is_some()
        || state.checkpoint_epoch != *old_epoch
        || anchor.epoch != old_epoch + 1
        || state.base_sequence != *old_base_sequence
        || anchor.position.sequence < *old_base_sequence
        || anchor.position.sequence > disk.sequence
        || disk.sequence > state.sequence
        || state.durable_cuts.get(&anchor.position.sequence) != Some(captured_cut)
        || disk.cuts.get(&anchor.position.sequence) != Some(captured_cut)
        || !pointer_covers(state.durable_committed, captured_cut.committed)
        || !pointer_covers(native.business.applied(), anchor.applied)
        || (snapshot.is_some() && &state.native_snapshot_pending != snapshot)
        || anchor.native_prefix()? != Some(selected.append.current().identity())
    {
        return Err(invalid_data(
            "native prepared basis no longer matches retained owner cut",
        ));
    }
    state
        .history_bytes
        .checked_sub(*covered_bytes)
        .ok_or_else(|| invalid_data("native captured history charge exceeds live history"))
}

fn select(
    shared: &Arc<Shared>,
    disk: &mut Disk,
    prepared: Prepared,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
) -> io::Result<(Selected, crate::consensus::native::generation::Relocations)> {
    let started = Instant::now();
    let preflight_hold = {
        let state = lock_state(shared)?;
        let held = Instant::now();
        ensure_readable(&state)?;
        validate_selection(&state, disk, &prepared, binding, limits)?;
        held.elapsed()
    };
    // The single writer retains Disk ownership. Admissions/applications may
    // advance State during this I/O; no newer WAL cut is published concurrently.
    // CURRENT is durable before any row eviction or covered-prefix removal.
    let select_io_started = Instant::now();
    checkpoint::select(&disk.directory, &prepared.anchor, control)?;
    let select_io = select_io_started.elapsed();
    let reclaim_io_started = Instant::now();
    checkpoint::reclaim_covered(disk, &prepared.anchor, control)?;
    let reclaim_io = reclaim_io_started.elapsed();
    let mut state = lock_state(shared)?;
    let held = Instant::now();
    ensure_readable(&state)?;
    let remaining = validate_selection(&state, disk, &prepared, binding, limits)?;
    let Prepared {
        anchor,
        snapshot,
        snapshot_selection,
        selected,
        relocations,
        costs,
        elapsed,
        ..
    } = prepared;
    state.base_sequence = anchor.position.sequence;
    state.history_bytes = remaining;
    state.checkpoint_epoch = anchor.epoch;
    state
        .durable_cuts
        .retain(|sequence, _| *sequence >= anchor.position.sequence);
    disk.cuts
        .retain(|sequence, _| *sequence >= anchor.position.sequence);
    state.authority.frozen_applied = anchor.applied;
    if let Some(selection) = snapshot_selection {
        state
            .native
            .as_mut()
            .ok_or_else(|| invalid_data("native snapshot selection owner missing"))?
            .business
            .publish_checkpoint_snapshot(selection)?;
        state.native_snapshot_pending = None;
    } else if snapshot.is_some() {
        return Err(invalid_data("native snapshot selection proof missing"));
    }
    disk.anchor = Some(anchor);
    state.native_basis_active = false;
    state.native_basis_ready = false;
    state.native_relocations_pending = !relocations.is_empty();
    if state
        .native_checkpoint_target
        .is_some_and(|target| target.satisfied(&state))
    {
        state.native_checkpoint_target = None;
    }
    state.checkpoint_requested =
        state.native_checkpoint_target.is_some() || state.native_snapshot_pending.is_some();
    let total = elapsed + started.elapsed();
    let publication_hold = held.elapsed();
    let recorded = &mut state.checkpoint_costs;
    recorded.completed += 1;
    recorded.elapsed += total;
    recorded.maximum = recorded.maximum.max(total);
    recorded.native_basis_count += costs.native_basis_count;
    recorded.native_basis_bytes += costs.native_basis_bytes;
    recorded.native_serialize += costs.native_serialize;
    recorded.native_file_sync += costs.native_file_sync;
    recorded.native_proof += costs.native_proof;
    recorded.native_decode_validate += costs.native_decode_validate;
    recorded.native_file_publish += costs.native_file_publish;
    recorded.native_select_io += select_io;
    recorded.native_select_io_maximum = recorded.native_select_io_maximum.max(select_io);
    recorded.native_reclaim_io += reclaim_io;
    recorded.native_reclaim_io_maximum = recorded.native_reclaim_io_maximum.max(reclaim_io);
    recorded.native_owner_publish += preflight_hold + publication_hold;
    recorded.native_owner_maximum = recorded
        .native_owner_maximum
        .max(preflight_hold)
        .max(publication_hold);
    shared.ready.notify_all();
    drop(state);
    Ok((selected, relocations))
}

#[cfg(test)]
impl Wal {
    pub(in crate::sqlite::consensus) fn native_cold_counts_for_test(
        &self,
    ) -> io::Result<[usize; 3]> {
        let state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        Ok(state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native cold observation owner missing"))?
            .cold_counts_for_test())
    }

    pub(in crate::sqlite::consensus) fn native_basis_waiters_for_test(
        &self,
    ) -> io::Result<(bool, Option<LogId<SessionConsensusNodeId>>, bool)> {
        let state = lock_state(&self.shared)?;
        Ok((
            state.native_snapshot_pending.is_some(),
            state
                .native_checkpoint_target
                .and_then(|target| target.applied),
            state.native_basis_active,
        ))
    }

    pub(in crate::sqlite::consensus) fn native_submit_with_backpressure_for_test(
        &self,
        operation: Operation,
    ) -> io::Result<Ticket> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.admit_inner(
            operation,
            Completion(Some(CompletionTarget::Blocking(sender))),
            true,
        )?;
        Ok(Ticket(receiver))
    }
}
