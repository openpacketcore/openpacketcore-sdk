//! One immutable capture and one owned preparation thread. The writer alone
//! selects CURRENT; newer admitted projections, callbacks and published WAL
//! cuts remain live throughout preparation and survive selection unchanged.

use super::*;
use crate::consensus::native::NativeStorage;

mod background;
mod generation;
pub(super) mod pending;
use background::Background;
mod rollover;
pub(super) use generation::{bootstrap, Selected};
pub(super) use rollover::Coordinator;

#[derive(Clone, Copy)]
pub(super) struct Target {
    epoch: u64,
    sequence: u64,
    applied: Option<LogId<SessionConsensusNodeId>>,
}

impl Target {
    #[cfg(any(test, feature = "test-control"))]
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
    if state.volatile_mode() || state.native_basis_active || state.snapshot.is_some() {
        return false;
    }
    if (state.native_live_capacity
        && (state.sequence > state.base_sequence
            || state
                .native
                .as_ref()
                .is_some_and(|native| native.changed_verification_bytes() != 0)))
        || state.checkpoint_requested
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
        && (state
            .native
            .as_ref()
            .is_some_and(|native| native.changed_verification_bytes() >= JOURNAL_TRIGGER_BYTES)
            || state.sequence - state.base_sequence >= limits.history_count.div_ceil(4) as u64
            || state.history_bytes >= limits.history_bytes.div_ceil(4)
            || disk.segment - disk.base_position().segment >= limits.segments.div_ceil(4) as u64)
}

// These are process-local scheduling bounds, independent of the protocol's
// reclaim batch and transport delivery. A captured journal keeps its charge
// in VerificationMemory; allowing a second live journal does not refund it.
// Partition the real 128 MiB cap: 1/4 for the existing optional journal-read
// page pool, 1/8 for checkpoint/apply workspace, leaving 80 MiB at retirement
// admission. The 16 MiB workspace matches the large-log decoder scheduling
// threshold; ordinary reclaim scratch is much smaller (80 KiB capture,
// 512 KiB generation header, two prefix-block buffers, and relocation only
// for emitted log rows). It is an allowance, not a worst-case payload bound.
// A 1/16-cap trigger starts draining after about 60 single-command
// journals (1024*72 + 64 KiB + publication metadata ~= 137 KiB each).
// The live stop is three triggers: 24 MiB leaves room for a second captured
// journal of that size and 32 MiB of baseline/candidate within the 80 MiB line.
// Log, roster and business journals all feed this trigger. Their allocation
// reservations additionally preserve checkpoint workspace under mixed load.
const JOURNAL_TRIGGER_BYTES: usize =
    crate::consensus::verified_snapshot::PROCESS_VERIFICATION_BYTES / 16;
const JOURNAL_STOP_BYTES: usize = 3 * JOURNAL_TRIGGER_BYTES;
const CONSUMER_HEADROOM_BYTES: usize =
    crate::consensus::verified_snapshot::PROCESS_VERIFICATION_BYTES / 4;
const CHECKPOINT_AND_APPLY_BYTES: usize =
    crate::consensus::verified_snapshot::PROCESS_VERIFICATION_BYTES / 8;
const RETIREMENT_ADMISSION_BYTES: usize =
    crate::consensus::verified_snapshot::PROCESS_VERIFICATION_BYTES
        - CONSUMER_HEADROOM_BYTES
        - CHECKPOINT_AND_APPLY_BYTES;

pub(super) fn manages_retirement(state: &State) -> bool {
    state.asynchronous.is_none() && !state.volatile_mode()
}

pub(super) fn retirement_ready(state: &State, candidate_bytes: usize) -> bool {
    use crate::consensus::verified_snapshot::VerificationMemory;
    // Asynchronous persistence has a separate writer/admission lifecycle.
    // Its existing reservation and extent gates remain authoritative.
    candidate_bytes == 0
        || !manages_retirement(state)
        || (state
            .native
            .as_ref()
            .is_some_and(|native| native.changed_verification_bytes() < JOURNAL_STOP_BYTES)
            && VerificationMemory::used_bytes()
                .checked_add(candidate_bytes)
                .is_some_and(|bytes| bytes <= RETIREMENT_ADMISSION_BYTES))
}

pub(super) fn retirement_shortfall(candidate_bytes: usize) -> usize {
    crate::consensus::verified_snapshot::VerificationMemory::used_bytes()
        .saturating_add(candidate_bytes)
        .saturating_sub(RETIREMENT_ADMISSION_BYTES)
}

pub(super) fn reserve_retirement(
    candidate_bytes: usize,
) -> Option<crate::consensus::verified_snapshot::VerificationMemory> {
    crate::consensus::verified_snapshot::VerificationMemory::try_reserve_keeping(
        candidate_bytes,
        CONSUMER_HEADROOM_BYTES + CHECKPOINT_AND_APPLY_BYTES,
    )
}

// A journal capture already in progress owns its own wakeup. Repeated
// polls must never schedule empty or unhelpful generations, or interfere
// with installation. Consumer writes can refill a journal while unrelated
// owners keep admission closed; draining that journal must be able to reach
// the admission line, unless the journal itself has reached its stop.
pub(super) fn request_retirement_checkpoint(state: &mut State, candidate_bytes: usize) -> bool {
    request_checkpoint_for_memory(state, candidate_bytes, RETIREMENT_ADMISSION_BYTES)
}

pub(super) fn request_journal_checkpoint(state: &mut State, candidate_bytes: usize) -> bool {
    use crate::consensus::verified_snapshot::{JOURNAL_HEADROOM_BYTES, PROCESS_VERIFICATION_BYTES};
    request_checkpoint_for_memory(
        state,
        candidate_bytes,
        PROCESS_VERIFICATION_BYTES - JOURNAL_HEADROOM_BYTES,
    )
}

fn request_checkpoint_for_memory(
    state: &mut State,
    candidate_bytes: usize,
    admission_bytes: usize,
) -> bool {
    use crate::consensus::verified_snapshot::VerificationMemory;
    if state.status != Status::Running
        || state.retirement_stopped
        || state.snapshot.is_some()
        || state.native_install_pending
        || state.native_basis_active
        || state.checkpoint_requested
    {
        return false;
    }
    let journal_bytes = state
        .native
        .as_ref()
        .map_or(0, |native| native.changed_verification_bytes());
    let can_admit_after_capture = VerificationMemory::used_bytes()
        .saturating_sub(journal_bytes)
        .checked_add(candidate_bytes)
        .is_some_and(|bytes| bytes <= admission_bytes);
    if journal_bytes == 0 || (journal_bytes < JOURNAL_STOP_BYTES && !can_admit_after_capture) {
        return false;
    }
    state.checkpoint_requested = true;
    true
}

// Allow one shared durable-operation budget (currently 10 s) without at
// least 64 KiB of relief, and at most three budgets for the entire episode.
// A successful reservation ends it. A single checkpoint or relocation drain
// without enough observable relief still uses the existing inactivity bound.
pub(super) const RETIREMENT_WAIT_TIMEOUT: Duration =
    opc_consensus::DURABLE_CONSENSUS_OPERATION_TIMEOUT;

// Tiny counter fluctuations cannot extend a stalled wait. Progress renews
// only the inactivity window; the whole pressure episode has a fixed bound.
pub(in crate::sqlite::consensus) struct PressureProgress {
    started: Instant,
    last_progress: Instant,
    shortfall: usize,
    journal: usize,
    file_paused: Option<Instant>,
}
impl PressureProgress {
    pub(super) fn new(shortfall: usize, journal: usize) -> Self {
        Self {
            started: Instant::now(),
            last_progress: Instant::now(),
            shortfall,
            journal,
            file_paused: None,
        }
    }
    pub(super) fn observe(&mut self, shortfall: usize, journal: usize) {
        const MINIMUM_RELIEF: usize = 64 * 1024;
        if self.shortfall.saturating_sub(shortfall) >= MINIMUM_RELIEF
            || self.journal.saturating_sub(journal) >= MINIMUM_RELIEF
        {
            self.last_progress = Instant::now();
            self.shortfall = self.shortfall.min(shortfall);
            self.journal = self.journal.min(journal);
        }
    }
    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn expire_for_test(&mut self) {
        // A deterministic clock hook, used only after real allocation pressure
        // has created an episode. The production budget and fence stay intact.
        self.last_progress -= RETIREMENT_WAIT_TIMEOUT;
    }

    pub(super) fn total_expired(&self) -> bool {
        self.started.elapsed() >= 3 * RETIREMENT_WAIT_TIMEOUT
    }
    pub(super) fn stalled(&self) -> bool {
        self.last_progress.elapsed() >= RETIREMENT_WAIT_TIMEOUT
    }

    /// Resource retries while file-guarded do not age an existing memory
    /// episode, including the work between notifications. Rechecking the guard
    /// cannot renew the pause. A file-only wait never creates an episode.
    pub(super) fn pause_for_file_guard(&mut self) {
        self.pause_at(Instant::now());
    }
    fn pause_at(&mut self, now: Instant) {
        self.file_paused.get_or_insert(now);
    }
    pub(super) fn resume_after_file_guard(&mut self) {
        self.resume_at(Instant::now());
    }
    fn resume_at(&mut self, now: Instant) {
        if let Some(started) = self.file_paused.take() {
            self.exclude_file_wait(now.duration_since(started));
        }
    }

    /// Ceiling backpressure is a separate resource episode. Preserve time
    /// already spent on a real memory stall while excluding only this wait.
    pub(super) fn exclude_file_wait(&mut self, elapsed: Duration) {
        self.started += elapsed;
        self.last_progress += elapsed;
    }
}

struct Capture {
    changes: crate::consensus::native::NativeChanges,
    full: crate::consensus::native::SnapshotCapture,
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
    retired: Option<Selected>,
    relocations: crate::consensus::native::generation::Relocations,
    costs: integration::CheckpointCosts,
    elapsed: Duration,
    frame: Option<rollover::Frame>,
    cut: Option<rollover::Cut>,
    background: VecDeque<Background>,
}

// These bounded, single-owner transfers already belong to captured workspace.
// Keep them inline: boxing would add an allocation to every checkpoint. The
// compile-time size bounds below prevent growth beyond that fixed workspace.
#[expect(
    clippy::large_enum_variant,
    reason = "bounded inline owner transfer avoids per-checkpoint boxing"
)]
pub(super) enum Preparation {
    Checkpoint(Prepared),
    Capacity {
        request: pending::Request,
        selected: Selected,
    },
}

pub(super) struct AsyncCapture {
    pub(super) changes: crate::consensus::native::NativeChanges,
    pub(super) full: crate::consensus::native::SnapshotCapture,
    pub(super) snapshot: Option<super::super::CurrentSnapshot>,
    pub(super) selection: Option<crate::consensus::native::SnapshotSelection>,
}
#[expect(
    clippy::large_enum_variant,
    reason = "bounded inline owner transfer avoids per-checkpoint boxing"
)]
pub(super) enum AsyncAppend {
    Selected {
        rows: crate::consensus::native::generation::Relocations,
        snapshot: Option<super::super::CurrentSnapshot>,
        selection: Option<crate::consensus::native::SnapshotSelection>,
    },
    Capacity(pending::Request),
}

const _: () = assert!(std::mem::size_of::<Preparation>() <= 16 * 1024);
const _: () = assert!(std::mem::size_of::<AsyncAppend>() <= 8 * 1024);

pub(super) struct Owner {
    selected: Option<Selected>,
    retired: Option<Selected>,
    worker: Option<JoinHandle<io::Result<Preparation>>>,
    relocations: Option<crate::consensus::native::generation::Relocations>,
    compactor: Option<rollover::Job>,
    coordination: Arc<rollover::Coordinator>,
    ready: Option<rollover::Built>,
    cut: Option<rollover::Cut>,
    background: VecDeque<Background>,
    background_worker: Option<JoinHandle<io::Result<Background>>>,
    async_frame: Option<rollover::Frame>,
    async_cut: Option<rollover::Cut>,
    async_switched: bool,
    pending: Option<pending::Slot>,
}

pub(super) fn record_generation_size(
    state: &mut State,
    selected: &Selected,
    mode: SessionPersistenceMode,
    control: &IoControl,
) -> io::Result<()> {
    #[cfg(any(test, feature = "test-control"))]
    {
        let prefix = selected.append.current().identity();
        let appended_bytes = prefix
            .length
            .checked_sub(selected.base_bytes)
            .ok_or_else(|| invalid_data("native selected base exceeds generation"))?;
        if selected.last_switch.is_some() {
            state.checkpoint_costs.last_switch = selected.last_switch;
        }
        state.checkpoint_costs.generation = integration::GenerationSize {
            epoch: prefix.checkpoint_epoch,
            file_epoch: prefix.file_epoch,
            base_bytes: selected.base_bytes,
            appended_bytes,
            total_bytes: prefix.length,
            block_bytes: prefix.block_bytes as u64,
            trigger_bytes: rollover::threshold(selected, mode, control)?,
        };
    }
    #[cfg(not(any(test, feature = "test-control")))]
    let _ = (state, selected, mode, control);
    Ok(())
}

impl Owner {
    pub(super) fn new(selected: Option<Selected>, coordination: Arc<Coordinator>) -> Self {
        Self {
            selected,
            retired: None,
            worker: None,
            relocations: None,
            compactor: None,
            coordination,
            ready: None,
            cut: None,
            background: VecDeque::new(),
            background_worker: None,
            async_frame: None,
            async_cut: None,
            async_switched: false,
            pending: None,
        }
    }

    /// Experimental after-image persistence: no WAL cut selection, resident
    /// relocation or foreground progress dependency. All work is detached.
    #[cfg(feature = "test-control")]
    pub(super) fn persist_volatile(
        &mut self,
        changes: crate::consensus::native::NativeChanges,
        binding: Binding,
        generation: u64,
        sequence: u64,
        control: &IoControl,
    ) -> io::Result<u64> {
        if self.worker.is_some() || self.relocations.is_some() {
            return Err(invalid_data("volatile writer has an earlier basis owner"));
        }
        let selected = self
            .selected
            .as_mut()
            .ok_or_else(|| invalid_data("volatile generation owner missing"))?;
        let previous = selected.append.current();
        let identity = previous.identity();
        let epoch = identity
            .checkpoint_epoch
            .checked_add(1)
            .ok_or_else(|| invalid_data("volatile generation epoch exhausted"))?;
        let mut cut = Sha256::new();
        cut.update(b"OPC-volatile-experiment-unselected-after-images-v1\0");
        cut.update(binding.digest()?);
        cut.update(generation.to_le_bytes());
        cut.update(sequence.to_le_bytes());
        let delta = crate::consensus::native::generation::PreparedDelta::prepare(
            previous,
            &selected.version,
            epoch,
            sequence,
            cut.finalize().into(),
            changes,
            &|| Ok(()),
        )?;
        if identity
            .length
            .checked_add(delta.payload_bytes())
            .and_then(|bytes| bytes.checked_add(identity.block_bytes as u64))
            .is_none_or(|bytes| bytes > volatile_experiment::MAX_GENERATION_BYTES)
        {
            return Err(io::Error::other(
                "volatile background generation byte bound reached",
            ));
        }
        (control.hook)(Point::BeforeNativeGenerationAppend)?;
        let source = delta.append(&mut selected.append, &|| Ok(()))?;
        (control.hook)(Point::AfterNativeGenerationAppend)?;
        selected.version = delta.target_version();
        Ok(source.identity().length)
    }

    pub(in crate::sqlite::consensus::wal) fn record_generation_size(
        &self,
        state: &mut State,
        mode: SessionPersistenceMode,
        control: &IoControl,
    ) -> io::Result<()> {
        record_generation_size(
            state,
            self.selected
                .as_ref()
                .ok_or_else(|| invalid_data("native selected generation facts missing"))?,
            mode,
            control,
        )
    }

    pub(super) fn has_relocations(&self) -> bool {
        self.relocations.is_some()
    }

    pub(super) fn compactor_restart_ready(&self) -> bool {
        self.compactor.is_some() && self.coordination.restart_finished()
    }

    pub(super) fn guard_compactor_needed(&self, state: &State) -> bool {
        state.native_ceiling_wait
            && self.compactor.is_none()
            && self.ready.is_none()
            && self
                .cut
                .as_ref()
                .is_some_and(|cut| self.coordination.eligible(cut.head.identity()))
            && self.background.is_empty()
            && self.background_worker.is_none()
    }

    /// This runs outside State, including every compactor join.
    pub(super) fn poll_compactor(
        &mut self,
        shared: &Arc<Shared>,
        disk: &Disk,
        binding: Binding,
        control: &IoControl,
    ) -> io::Result<()> {
        if self.pending.is_some() {
            return Ok(());
        }
        #[cfg(test)]
        if self.compactor.is_some() {
            // The poison proof parks the owner before any queue mutex read.
            (control.hook)(Point::NativeCompactorOwnerTake)?;
        }
        if let Some(selected) = self.selected.as_mut() {
            if let Some(capture) = selected.initial_capture.take() {
                if self.cut.is_none() {
                    self.cut = Some(rollover::Cut {
                        capture,
                        requested: false,
                        anchor: disk
                            .anchor
                            .clone()
                            .ok_or_else(|| invalid_data("native initial CURRENT missing"))?,
                        head: selected.append.current(),
                        base_bytes: selected.base_bytes,
                    });
                }
            }
        }
        let guarded = lock_state(shared)?.native_ceiling_wait;
        if self.coordination.restart_finished() {
            if let Some(mut job) = self.compactor.take() {
                job.join()?;
            }
            lock_state(shared)?.native_rollover_ready = false;
        }
        if self.worker.is_none() && self.ready.is_none() && self.compactor.is_some() {
            if let Some(selected) = &self.selected {
                if let Some(built) = self
                    .coordination
                    .try_take(selected.append.current().identity())?
                {
                    if let Some(mut job) = self.compactor.take() {
                        job.join()?;
                    }
                    self.ready = Some(built);
                    let mut state = lock_state(shared)?;
                    state.native_rollover_ready = false;
                    state.checkpoint_requested = true;
                    if state.asynchronous.as_ref().is_some_and(|p| p.caught_up()) {
                        async_persistence::dirty(&mut state);
                    }
                    shared.ready.notify_all();
                } else {
                    lock_state(shared)?.native_rollover_ready = false;
                }
            }
        }
        if self.compactor.is_none()
            && self.ready.is_none()
            && self.background.is_empty()
            && self.background_worker.is_none()
            && self.cut.as_ref().is_some_and(|cut| {
                (cut.requested || guarded) && self.coordination.eligible(cut.head.identity())
            })
            && (self.worker.is_none() || guarded || self.coordination.restarting())
        {
            let cut = self
                .cut
                .take()
                .ok_or_else(|| invalid_data("native compactor cut missing"))?;
            if disk
                .anchor
                .as_ref()
                .and_then(|a| a.native_prefix().ok())
                .flatten()
                != Some(cut.head.identity())
            {
                return Err(invalid_data("native compactor cut is not selected"));
            }
            self.compactor = Some(rollover::Job::start(
                cut,
                Arc::clone(&self.coordination),
                shared,
                &disk.directory,
                binding,
                control,
            )?);
        }
        Ok(())
    }

    /// Append and verify one asynchronous generation without a State guard.
    /// CURRENT selection and resident publication are owned by the caller.
    #[expect(
        clippy::too_many_arguments,
        reason = "keep existing owner, namespace, mode and bound inputs explicit"
    )]
    pub(super) fn append_async(
        &mut self,
        capture: AsyncCapture,
        anchor: &mut checkpoint::Anchor,
        disk: &Disk,
        binding: Binding,
        limits: Limits,
        control: &IoControl,
        shared: &Arc<Shared>,
    ) -> io::Result<AsyncAppend> {
        let AsyncCapture {
            mut changes,
            full,
            snapshot,
            selection,
        } = capture;
        let old_base_sequence = lock_state(shared)?.base_sequence;
        let directory = &disk.directory;
        if binding.persistence != SessionPersistenceMode::Async
            || anchor.async_cut.is_none()
            || self.worker.is_some()
            || self.relocations.is_some()
            || self.retired.is_some()
            || self.async_frame.is_some()
            || self.async_cut.is_some()
        {
            return Err(invalid_data("asynchronous append ownership differs"));
        }
        let mut candidate = self.ready.take();
        let old = self
            .selected
            .as_ref()
            .ok_or_else(|| invalid_data("asynchronous generation owner missing"))?
            .append
            .current()
            .identity();
        if anchor.epoch != old.checkpoint_epoch.saturating_add(1)
            || anchor.native_sequence() < old.operation_sequence
            || anchor.root != old.binding
        {
            return Err(invalid_data("asynchronous append predecessor differs"));
        }
        loop {
            let selected = self
                .selected
                .as_mut()
                .ok_or_else(|| invalid_data("asynchronous generation owner missing"))?;
            let previous = candidate
                .as_ref()
                .map_or_else(|| selected.append.current(), |built| built.append.current());
            let identity = previous.identity();
            anchor
                .native_generation
                .as_mut()
                .ok_or_else(|| invalid_data("asynchronous selector missing"))?
                .file_epoch = identity.file_epoch;
            let delta = crate::consensus::native::generation::PreparedDelta::prepare(
                previous,
                &selected.version,
                anchor.epoch,
                anchor.native_sequence(),
                anchor.native_cut_binding()?,
                changes,
                &|| Ok(()),
            )?;
            (control.hook)(Point::BeforeNativeGenerationAppend)?;
            let maximum = rollover::limit(binding.persistence, identity.block_bytes, control)?;
            let next = identity
                .length
                .checked_add(delta.payload_bytes())
                .and_then(|n| n.checked_add(identity.block_bytes as u64 - 1))
                .map(|n| n / identity.block_bytes as u64 * identity.block_bytes as u64);
            if candidate.is_none() {
                self.coordination
                    .warn_headroom(identity, next, maximum, control)?;
            }
            if candidate.is_none() && next.is_none_or(|n| n > maximum) {
                changes = delta.into_capture();
                {
                    let mut state = lock_state(shared)?;
                    state.native_ceiling_wait = true;
                    shared.ready.notify_all();
                }
                (control.hook)(Point::NativeGenerationCeilingWait)?;
                // The previous switch may have consumed most of this file.
                // Finish independent relocation units and launch its next
                // compactor while this ordinary capture waits at the guard.
                // No journal/projection is retried or discarded here.
                loop {
                    self.poll_background(shared, disk, control)?;
                    if self.background.is_empty() && self.background_worker.is_none() {
                        break;
                    }
                    let mut state = lock_state(shared)?;
                    while !self.background_actionable(&state) {
                        ensure_readable(&state)?;
                        state = shared.ready.wait(state).map_err(|_| {
                            io::Error::other("asynchronous guard relocation wait poisoned")
                        })?;
                    }
                }
                candidate = loop {
                    self.poll_compactor(shared, disk, binding, control)?;
                    if let Some(built) = self.ready.take() {
                        break Some(built);
                    }
                    match self
                        .coordination
                        .wait_take(old, &|| check_guard_owner(shared))?
                    {
                        rollover::Take::Built(built) => break Some(built),
                        rollover::Take::Capacity => break None,
                        // This owner is the only Async restart scheduler.
                        // Keep the exact capture and return to its join/start.
                        rollover::Take::Restart => continue,
                    }
                };
                if candidate.is_none() {
                    #[cfg(test)]
                    (control.hook)(Point::BeforeNativeAsyncCapacityRequest)?;
                    return Ok(AsyncAppend::Capacity(pending::Request::asynchronous(
                        AsyncCapture {
                            changes,
                            full,
                            snapshot,
                            selection,
                        },
                        anchor.clone(),
                        old_base_sequence,
                    )?));
                }
                continue;
            }
            if let Some(built) = &candidate {
                let bounded = delta.switch_payload_bound()?;
                if !built.append.fits_append(bounded, 0) {
                    let fresh = built.cut == old;
                    let capacity = rollover::Capacity {
                        after: built.cut,
                        live_context: fresh
                            .then(|| delta.target_version().context_digest())
                            .transpose()?,
                        required: built
                            .append
                            .current()
                            .identity()
                            .length
                            .saturating_add(bounded),
                        maximum,
                    };
                    candidate
                        .take()
                        .ok_or_else(|| invalid_data("asynchronous capacity candidate missing"))?
                        .discard(control)?;
                    self.coordination
                        .capacity_abort(capacity, shared, control)?;
                    changes = delta.into_capture();
                    continue;
                }
            }
            let needs = candidate.is_none()
                && rollover::needed(
                    selected,
                    delta.payload_bytes(),
                    binding.persistence,
                    control,
                )?;
            if needs || candidate.is_some() {
                delta.target_version().require_current(&full.storage)?;
            }
            let payload = delta.payload_bytes();
            let target = delta.target_version();
            let (source, relocations) = if let Some(mut built) = candidate.take() {
                let before_switch = built.append.current().identity().length;
                let frames = built.shifts.len();
                let cut = built.cut;
                let result = delta
                    .append_switch(&mut built.append, &|| Ok(()))?
                    .ok_or_else(|| invalid_data("asynchronous switch preflight changed"))?;
                let final_path = anchor.basis_path(directory);
                crate::consensus::snapshot::rename_noreplace_in_directory(
                    &File::open(directory)?,
                    built
                        .preparing
                        .file_name()
                        .ok_or_else(|| invalid_data("asynchronous compactor name missing"))?,
                    final_path
                        .file_name()
                        .ok_or_else(|| invalid_data("asynchronous final name missing"))?,
                )?;
                (control.hook)(Point::AfterBasisRename)?;
                File::open(directory)?.sync_all()?;
                (control.hook)(Point::AfterBasisDirectorySync)?;
                built.append.confirm_named(&final_path)?;
                let base_bytes = built.base_view.identity().length;
                self.background.push_back(Background::new(
                    Arc::clone(&result.0),
                    crate::consensus::native::generation::Relocations::from_base(
                        built.base_capture,
                        built.base_view,
                    )?,
                ));
                let mut next = Selected::admitted(built.append, &full.storage, base_bytes)?;
                next.record_switch_size(cut, old, before_switch, frames, false)?;
                if rollover::needed(&next, 0, binding.persistence, control)? {
                    self.async_cut = Some(rollover::Cut {
                        capture: full.storage.capture_snapshot()?,
                        requested: false,
                        anchor: anchor.clone(),
                        head: Arc::clone(&result.0),
                        base_bytes,
                    });
                }
                self.background.push_back(Background::new(
                    Arc::clone(&result.0),
                    crate::consensus::native::generation::Relocations::from_replay(
                        full,
                        Arc::clone(&result.0),
                        selected.append.current(),
                        built.cut,
                        built.shifts,
                    )?,
                ));
                self.retired = self.selected.replace(next);
                self.async_switched = true;
                result
            } else {
                let result = delta.append_with_relocations(&mut selected.append, &|| Ok(()))?;
                selected.version = target;
                self.async_frame = Some(rollover::Frame::new(old, Arc::clone(&result.0), payload)?);
                self.async_cut = Some(rollover::Cut {
                    capture: full,
                    requested: needs,
                    anchor: anchor.clone(),
                    head: Arc::clone(&result.0),
                    base_bytes: selected.base_bytes,
                });
                result
            };
            (control.hook)(Point::AfterNativeGenerationAppend)?;
            let prefix = source.identity();
            anchor.basis = prefix.digest;
            anchor.basis_bytes = prefix.length;
            anchor.native_generation = Some(checkpoint::NativeGeneration {
                file_epoch: prefix.file_epoch,
                block_bytes: prefix.block_bytes,
                frontiers: prefix.frontiers,
            });
            anchor.validate(binding, limits)?;
            if anchor.native_prefix()? != Some(prefix) {
                return Err(invalid_data("asynchronous prefix differs from selector"));
            }
            // Store the final anchor, after basis/frontier completion.
            if let Some(cut) = &mut self.async_cut {
                cut.anchor = anchor.clone();
            }
            return Ok(AsyncAppend::Selected {
                rows: relocations,
                snapshot,
                selection,
            });
        }
    }

    pub(super) fn after_async_selection(
        &mut self,
        shared: &Arc<Shared>,
        disk: &Disk,
        binding: Binding,
        control: &IoControl,
    ) -> io::Result<()> {
        let switching = std::mem::take(&mut self.async_switched);
        if switching {
            self.cut = None;
        }
        // The caller retires the previous owner before reclamation. A normal
        // frame is queued only after CURRENT and the State cut are selected.
        if let Some(cut) = self.async_cut.take() {
            self.cut = Some(cut);
        }
        if let Some(frame) = self.async_frame.take() {
            if self.coordination.active() {
                self.coordination.enqueue(frame)?;
                lock_state(shared)?.native_rollover_ready = false;
            }
        } else if self.compactor.is_some() || switching {
            if let Some(mut job) = self.compactor.take() {
                job.join()?;
            }
            let mut state = lock_state(shared)?;
            state.native_ceiling_wait = false;
            state.native_rollover_ready = false;
            shared.ready.notify_all();
        }
        if switching {
            self.coordination.record_switch(shared, control)?;
        }
        self.poll_compactor(shared, disk, binding, control)
    }

    /// CURRENT has been synced; all old views may now finish after unlink.
    pub(super) fn retire_previous(&mut self) -> bool {
        if let Some(previous) = self.retired.take() {
            previous.append.retire();
            true
        } else {
            false
        }
    }

    pub(super) fn begin_async_relocations(
        &mut self,
        relocations: crate::consensus::native::generation::Relocations,
    ) -> io::Result<()> {
        if self.worker.is_some() || self.relocations.is_some() {
            return Err(invalid_data("asynchronous relocation owner is occupied"));
        }
        if !relocations.is_empty() {
            self.relocations = Some(relocations);
        }
        Ok(())
    }

    /// Cancel only optional work, after the ordinary captured checkpoint has
    /// drained. Never discard an accepted journal to make an install or close
    /// appear complete. All joins and namespace I/O are outside State.
    pub(super) fn stop_optional(
        &mut self,
        shared: &Arc<Shared>,
        directory: &Path,
        control: &IoControl,
    ) -> io::Result<()> {
        self.stop_pending(control)?;
        if self.worker.is_some() {
            return Err(invalid_data(
                "native optional cancellation precedes checkpoint drain",
            ));
        }
        let mut names = BTreeSet::new();
        if let Some(mut job) = self.compactor.take() {
            job.cancel_and_join()?;
            names.insert(job.owned.clone());
        }
        if let Some(built) = self.ready.take() {
            names.insert(built.preparing.clone());
            drop(built);
        }
        self.stop_background()?;
        self.cut = None;
        for name in names {
            match fs::remove_file(name) {
                Ok(()) => File::open(directory)?.sync_all()?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
        }
        // A completed capacity restart may already have been joined/removed
        // by poll_compactor. It still must not survive an installed file epoch.
        self.coordination.reset_after_join()?;
        let mut state = lock_state(shared)?;
        state.native_ceiling_wait = false;
        state.native_live_capacity = false;
        state.native_pending_base = false;
        state.native_pending_ready = false;
        state.native_pending_journal_pressure = false;
        state.native_rollover_ready = false;
        state.native_background_ready = false;
        state.native_background_pending = false;
        shared.ready.notify_all();
        Ok(())
    }

    pub(super) fn require_install_owner(&self, anchor: &checkpoint::Anchor) -> io::Result<()> {
        if self.worker.is_some()
            || self.relocations.is_some()
            || self.retired.is_some()
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
        #[cfg(feature = "test-control")]
        if native.changed_verification_bytes() >= JOURNAL_TRIGGER_BYTES {
            eprintln!(
                "native_retirement_memory_checkpoint bytes={}",
                native.changed_verification_bytes()
            );
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
        let journal_bytes = native.changed_verification_bytes() as u64;
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
        let mut full = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native checkpoint full capture owner missing"))?
            .capture_snapshot()?;
        if let Some(selection) = &snapshot_selection {
            full.select_checkpoint_snapshot(selection)?;
        }
        let capture = Capture {
            changes,
            full,
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
        let candidate = self.ready.take();
        let coordination = Arc::clone(&self.coordination);
        self.worker = Some(
            std::thread::Builder::new()
                .name("session-native-basis".into())
                .spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        prepare(
                            capture,
                            selected,
                            candidate,
                            &coordination,
                            &shared,
                            &control,
                            &|| {
                                let state = lock_state(&shared)?;
                                ensure_readable(&state)
                            },
                        )
                    }))
                    .unwrap_or_else(|_| Err(io::Error::other("native basis worker panicked")));
                    let mut state = match shared.state.lock() {
                        Ok(state) => state,
                        Err(poison) => poison.into_inner(),
                    };
                    if result
                        .as_ref()
                        .is_err_and(|error| !pending::is_stopped(error))
                    {
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
        state.checkpoint_costs.ordinary_journal_captured_bytes += journal_bytes;
        state.checkpoint_costs.ordinary_journal_capture_maximum = state
            .checkpoint_costs
            .ordinary_journal_capture_maximum
            .max(journal_bytes);
        let elapsed = started.elapsed();
        state.checkpoint_costs.native_capture += elapsed;
        state.checkpoint_costs.native_owner_maximum =
            state.checkpoint_costs.native_owner_maximum.max(elapsed);
        Ok(())
    }

    /// State is released before joining. The worker takes it to signal its
    /// result, and its append descriptor must retire before directory LOCK.
    pub(super) fn join(&mut self) -> io::Result<Option<Preparation>> {
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
        prepared: Preparation,
        binding: Binding,
        limits: Limits,
        control: &IoControl,
    ) -> io::Result<()> {
        if self.selected.is_some() || self.worker.is_some() || self.relocations.is_some() {
            return Err(invalid_data("native selection owner is not detached"));
        }
        let mut prepared = match prepared {
            Preparation::Checkpoint(prepared) => prepared,
            Preparation::Capacity { request, selected } => {
                self.selected = Some(selected);
                return self.begin_pending(request, shared, disk, control);
            }
        };
        let frame = prepared.frame.take();
        let cut = prepared.cut.take();
        let background = std::mem::take(&mut prepared.background);
        let switching = prepared.retired.is_some();
        let owned = self.compactor.as_ref().map(|job| job.owned.as_path());
        let (selected, relocations) =
            select(shared, disk, prepared, binding, limits, control, owned)?;
        self.selected = Some(selected);
        if switching {
            if let Some(mut job) = self.compactor.take() {
                job.join()?;
            }
            self.cut = cut;
            let mut state = lock_state(shared)?;
            state.native_ceiling_wait = false;
            state.native_rollover_ready = false;
            shared.ready.notify_all();
        } else {
            if let Some(cut) = cut {
                self.cut = Some(cut);
            }
            if self.coordination.active() {
                if let Some(frame) = frame {
                    self.coordination.enqueue(frame)?;
                    lock_state(shared)?.native_rollover_ready = false;
                }
            }
        }
        self.background.extend(background);
        if !relocations.is_empty() {
            self.relocations = Some(relocations);
        }
        if switching {
            self.coordination.record_switch(shared, control)?;
        }
        self.poll_compactor(shared, disk, binding, control)?;
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
        rows.prepare_step(&|| {
            let state = lock_state(shared)?;
            ensure_readable(&state)
        })?;
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
        let retired = rows.publish_step_mirrored(
            state
                .native
                .as_mut()
                .ok_or_else(|| invalid_data("native relocation resident owner missing"))?,
            self.cut.as_mut().map(|cut| &mut cut.capture.storage),
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
        let _ = self.stop_background();
    }
}

fn prepare(
    capture: Capture,
    mut selected: Selected,
    mut candidate: Option<rollover::Built>,
    coordination: &Arc<rollover::Coordinator>,
    shared: &Arc<Shared>,
    control: &IoControl,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Preparation> {
    (control.hook)(Point::AfterNativeGenerationCapture)?;
    let Capture {
        mut changes,
        full,
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
        async_cut: None,
    };
    let serialize_started = Instant::now();
    let mut serialized;
    let mut frame = None;
    let mut next_cut = None;
    let mut background = VecDeque::new();
    let mut replay = None;
    let mut retired = None;
    let written_bytes;
    let cut_binding;
    let relocations;
    loop {
        let previous = candidate
            .as_ref()
            .map_or_else(|| selected.append.current(), |built| built.append.current());
        let prefix = previous.identity();
        anchor
            .native_generation
            .as_mut()
            .ok_or_else(|| invalid_data("native checkpoint selector missing"))?
            .file_epoch = prefix.file_epoch;
        let binding_at_cut = anchor.native_cut_binding()?;
        let delta = crate::consensus::native::generation::PreparedDelta::prepare(
            previous,
            &selected.version,
            epoch,
            position.sequence,
            binding_at_cut,
            changes,
            check,
        )?;
        serialized = Instant::now();
        (control.hook)(Point::BeforeNativeGenerationAppend)?;
        let maximum = rollover::limit(binding.persistence, prefix.block_bytes, control)?;
        let next_length = prefix
            .length
            .checked_add(delta.payload_bytes())
            .and_then(|n| n.checked_add(prefix.block_bytes as u64 - 1))
            .map(|n| n / prefix.block_bytes as u64 * prefix.block_bytes as u64);
        if candidate.is_none() {
            coordination.warn_headroom(prefix, next_length, maximum, control)?;
        }
        if candidate.is_none() && next_length.is_none_or(|length| length > maximum) {
            changes = delta.into_capture();
            {
                let mut state = lock_state(shared)?;
                ensure_readable(&state)?;
                state.native_ceiling_wait = true;
                shared.ready.notify_all();
            }
            (control.hook)(Point::NativeGenerationCeilingWait)?;
            let wait_check = || {
                check()?;
                check_guard_owner(shared)
            };
            candidate = loop {
                match coordination.wait_take(old, &wait_check)? {
                    rollover::Take::Built(built) => break Some(built),
                    rollover::Take::Capacity => break None,
                    rollover::Take::Restart => coordination.wait_restart(old, &wait_check)?,
                }
            };
            if candidate.is_none() {
                let native_snapshots = anchor.native_snapshots.clone();
                return Ok(Preparation::Capacity {
                    selected,
                    request: pending::Request::durable(
                        Capture {
                            changes,
                            full,
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
                        },
                        anchor,
                    ),
                });
            }
            continue;
        }
        if let Some(built) = &candidate {
            let bounded = delta.switch_payload_bound()?;
            if !built.append.fits_append(bounded, 0) {
                let capacity = rollover::Capacity {
                    after: built.cut,
                    live_context: (built.cut == old)
                        .then(|| delta.target_version().context_digest())
                        .transpose()?,
                    required: built
                        .append
                        .current()
                        .identity()
                        .length
                        .saturating_add(bounded),
                    maximum,
                };
                candidate
                    .take()
                    .ok_or_else(|| invalid_data("native capacity candidate missing"))?
                    .discard(control)?;
                coordination.capacity_abort(capacity, shared, control)?;
                changes = delta.into_capture();
                continue;
            }
        }
        let needs_compactor = candidate.is_none()
            && rollover::needed(
                &selected,
                delta.payload_bytes(),
                binding.persistence,
                control,
            )?;
        if needs_compactor || candidate.is_some() {
            delta.target_version().require_current(&full.storage)?;
        }
        let payload = delta.payload_bytes();
        let target_version = delta.target_version();
        if let Some(mut built) = candidate.take() {
            let before_switch = built.append.current().identity().length;
            let frames = built.shifts.len();
            let switch_cut = built.cut;
            let (source, rows) = delta
                .append_switch(&mut built.append, check)?
                .ok_or_else(|| invalid_data("native switch preflight changed"))?;
            let final_path = anchor.basis_path(&directory);
            crate::consensus::snapshot::rename_noreplace_in_directory(
                &File::open(&directory)?,
                built
                    .preparing
                    .file_name()
                    .ok_or_else(|| invalid_data("native compactor preparation name missing"))?,
                final_path
                    .file_name()
                    .ok_or_else(|| invalid_data("native compactor final name missing"))?,
            )?;
            (control.hook)(Point::AfterBasisRename)?;
            File::open(&directory)?.sync_all()?;
            (control.hook)(Point::AfterBasisDirectorySync)?;
            built.append.confirm_named(&final_path)?;
            let base_bytes = built.base_view.identity().length;
            background.push_back(Background::new(
                Arc::clone(&source),
                crate::consensus::native::generation::Relocations::from_base(
                    built.base_capture,
                    built.base_view,
                )?,
            ));
            replay = Some((
                Arc::clone(&source),
                selected.append.current(),
                built.cut,
                built.shifts,
            ));
            let mut next = Selected::admitted(built.append, &full.storage, base_bytes)?;
            next.record_switch_size(switch_cut, old, before_switch, frames, false)?;
            if rollover::needed(&next, 0, binding.persistence, control)? {
                next_cut = Some((Arc::clone(&source), false));
            }
            retired = Some(std::mem::replace(&mut selected, next));
            written_bytes = source.identity().length;
            relocations = rows;
        } else {
            let (source, rows) = delta.append_with_relocations(&mut selected.append, check)?;
            selected.version = target_version;
            written_bytes = source
                .identity()
                .length
                .checked_sub(old.length)
                .ok_or_else(|| invalid_data("native appended extent regressed"))?;
            frame = Some(rollover::Frame::new(old, Arc::clone(&source), payload)?);
            relocations = rows;
            // Preserve the latest selected cut even below the trigger: the
            // next single delta may exceed the remaining headroom. Only the
            // requested bit starts ordinary background work at the trigger.
            next_cut = Some((source, needs_compactor));
        }
        cut_binding = binding_at_cut;
        break;
    }
    (control.hook)(Point::AfterNativeGenerationAppend)?;
    let verified = Instant::now();
    let identity = selected.append.current().identity();
    anchor.basis = identity.digest;
    anchor.basis_bytes = identity.length;
    anchor.native_generation = Some(checkpoint::NativeGeneration {
        file_epoch: identity.file_epoch,
        block_bytes: identity.block_bytes,
        frontiers: identity.frontiers,
    });
    if anchor.native_prefix()? != Some(identity)
        || (retired.is_none() && anchor.native_cut_binding()? != cut_binding)
    {
        return Err(invalid_data(
            "native appended generation differs from captured selector",
        ));
    }
    anchor.validate(binding, limits)?;
    check()?;
    let costs = integration::CheckpointCosts {
        native_basis_count: 1,
        native_basis_bytes: written_bytes,
        native_serialize: serialized.duration_since(serialize_started),
        native_decode_validate: verified.duration_since(serialized),
        ..Default::default()
    };
    let mut full = Some(full);
    if let Some((source, old, cut, shifts)) = replay {
        let replay_capture = if next_cut.is_some() {
            full.as_ref()
                .ok_or_else(|| invalid_data("native switch capture missing"))?
                .storage
                .capture_snapshot()?
        } else {
            full.take()
                .ok_or_else(|| invalid_data("native switch capture missing"))?
        };
        background.push_back(Background::new(
            Arc::clone(&source),
            crate::consensus::native::generation::Relocations::from_replay(
                replay_capture,
                source,
                old,
                cut,
                shifts,
            )?,
        ));
    }
    let cut = if let Some((head, requested)) = next_cut {
        Some(rollover::Cut {
            requested,
            capture: full
                .take()
                .ok_or_else(|| invalid_data("native next build capture missing"))?,
            anchor: anchor.clone(),
            head,
            base_bytes: selected.base_bytes,
        })
    } else {
        None
    };
    Ok(Preparation::Checkpoint(Prepared {
        anchor,
        old_epoch: epoch - 1,
        old_base_sequence: base_sequence,
        covered_bytes: history_bytes,
        snapshot,
        snapshot_selection,
        selected,
        retired,
        relocations,
        costs,
        elapsed: started.elapsed(),
        frame,
        cut,
        background,
    }))
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
    mut prepared: Prepared,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
    owned_next: Option<&Path>,
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
    if let Some(previous) = prepared.retired.take() {
        previous.append.retire();
    }
    let select_io = select_io_started.elapsed();
    let reclaim_io_started = Instant::now();
    checkpoint::reclaim_covered_owned(
        disk,
        &prepared.anchor,
        control,
        binding.async_recovery_format,
        owned_next,
    )?;
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
    record_generation_size(&mut state, &selected, binding.persistence, control)?;
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

    pub(in crate::sqlite::consensus) fn native_request_journal_checkpoint_for_test(
        &self,
    ) -> io::Result<(usize, bool)> {
        let mut state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        let bytes = state
            .native
            .as_ref()
            .map_or(0, NativeStorage::changed_verification_bytes);
        let requested = state.checkpoint_requested || request_journal_checkpoint(&mut state, 0);
        if requested {
            self.shared.ready.notify_all();
        }
        Ok((bytes, requested))
    }
}

// Coordinator Closing publication forces a fresh owner check outside work.
// Closing retains the ordinary checkpoint drain; only the existing complete
// pending-capacity path emits Stopped when it cannot select the accepted cut.
fn check_guard_owner(shared: &Arc<Shared>) -> io::Result<()> {
    let state = lock_state(shared)?;
    ensure_readable(&state)
}

#[cfg(test)]
mod pressure_pause_tests {
    use super::*;

    #[test]
    fn native_rollover_file_guard_pauses_one_whole_existing_pressure_interval() {
        let mut progress = PressureProgress::new(100, 200);
        let started = progress.started;
        let last = progress.last_progress;
        let pause = started + Duration::from_secs(1);
        progress.pause_at(pause);
        // Notifications and resource retries must not restart the exclusion.
        progress.pause_at(pause + Duration::from_secs(3));
        assert_eq!(progress.file_paused, Some(pause));
        progress.resume_at(pause + Duration::from_secs(60));
        assert_eq!(progress.started, started + Duration::from_secs(60));
        assert_eq!(progress.last_progress, last + Duration::from_secs(60));
        assert_eq!((progress.shortfall, progress.journal), (100, 200));
        assert!(progress.file_paused.is_none());
        progress.resume_at(pause + Duration::from_secs(90));
        assert_eq!(progress.started, started + Duration::from_secs(60));
        assert_eq!(progress.last_progress, last + Duration::from_secs(60));
    }
}
