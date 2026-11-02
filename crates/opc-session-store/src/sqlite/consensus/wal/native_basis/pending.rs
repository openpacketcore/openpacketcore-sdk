//! Capacity-only complete pending-cut bases. The writer owns cut capture and
//! CURRENT; a separate worker owns all encoding, sync and fresh admission.

use super::*;
use crate::consensus::native::generation::{Relocations, Version};
use crate::consensus::native::SnapshotCapture;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Token {
    sequence: u64,
    applied: Option<LogId<SessionConsensusNodeId>>,
    generation: Option<u64>,
}
impl Token {
    fn advanced(self, previous: Self) -> bool {
        self.sequence > previous.sequence
            || self
                .generation
                .zip(previous.generation)
                .is_some_and(|(new, old)| new > old)
            || (self.applied != previous.applied && pointer_covers(self.applied, previous.applied))
    }
}

pub(super) struct Meta {
    anchor: checkpoint::Anchor,
    old_epoch: u64,
    old_base_sequence: u64,
    covered_bytes: usize,
    snapshot: Option<super::super::super::CurrentSnapshot>,
    selection: Option<crate::consensus::native::SnapshotSelection>,
    token: Token,
    started: Instant,
    _memory: crate::consensus::verified_snapshot::VerificationMemory,
}

pub(in crate::sqlite::consensus::wal) struct Request {
    meta: Meta,
    changes: crate::consensus::native::NativeChanges,
    full: SnapshotCapture,
}

impl Request {
    pub(super) fn durable(capture: Capture, anchor: checkpoint::Anchor) -> Self {
        Self {
            meta: Meta {
                old_epoch: capture.epoch - 1,
                old_base_sequence: capture.base_sequence,
                covered_bytes: capture.history_bytes,
                token: Token {
                    sequence: capture.position.sequence,
                    applied: capture.applied,
                    generation: None,
                },
                anchor,
                snapshot: capture.snapshot,
                selection: capture.snapshot_selection,
                started: capture.started,
                _memory: capture._memory,
            },
            changes: capture.changes,
            full: capture.full,
        }
    }

    pub(super) fn asynchronous(
        capture: AsyncCapture,
        anchor: checkpoint::Anchor,
        old_base_sequence: u64,
    ) -> io::Result<Self> {
        let cut = anchor
            .async_cut
            .ok_or_else(|| invalid_data("pending Async cut missing"))?;
        Ok(Self {
            meta: Meta {
                old_epoch: anchor.epoch - 1,
                old_base_sequence,
                covered_bytes: 0,
                token: Token {
                    sequence: cut.sequence,
                    applied: cut.applied,
                    generation: Some(cut.generation),
                },
                anchor,
                snapshot: capture.snapshot,
                selection: capture.selection,
                started: Instant::now(),
                _memory: crate::consensus::verified_snapshot::VerificationMemory::reserve(
                    64 * 1024,
                )?,
            },
            changes: capture.changes,
            full: capture.full,
        })
    }
}

// The result is already covered by the pending capture's workspace. Avoid a
// second allocation just to transfer it to the sole writer; bound it below.
#[expect(
    clippy::large_enum_variant,
    reason = "bounded inline pending owner transfer"
)]
enum Built {
    Ready { meta: Meta, base: rollover::Built },
    Full,
    Drained,
}

const _: () = assert!(std::mem::size_of::<Built>() <= 8 * 1024);

pub(super) struct Slot {
    old: crate::consensus::native::prefix::PrefixIdentity,
    old_epoch: u64,
    old_base_sequence: u64,
    observed: Token,
    context: Option<[u8; 32]>,
    initial: Option<Request>,
    worker: Option<JoinHandle<io::Result<Built>>>,
}

#[derive(Debug)]
struct Stopped;
impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native live-capacity drain interrupted")
    }
}
impl std::error::Error for Stopped {}
pub(in crate::sqlite::consensus::wal) fn stopped() -> io::Error {
    io::Error::other(Stopped)
}
pub(in crate::sqlite::consensus::wal) fn is_stopped(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<Stopped>())
}

impl Owner {
    pub(in crate::sqlite::consensus::wal) fn begin_pending(
        &mut self,
        request: Request,
        shared: &Arc<Shared>,
        disk: &Disk,
        control: &IoControl,
    ) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(invalid_data("duplicate native pending-capacity owner"));
        }
        if let Some(mut job) = self.compactor.take() {
            job.cancel_and_join()?;
        }
        if let Some(base) = self.ready.take() {
            base.discard(control)?;
        }
        self.cut = None;
        let old = self
            .selected
            .as_ref()
            .ok_or_else(|| invalid_data("pending selected owner missing"))?
            .append
            .current()
            .identity();
        if disk
            .anchor
            .as_ref()
            .and_then(|anchor| anchor.native_prefix().ok())
            .flatten()
            != Some(old)
        {
            return Err(invalid_data("pending selected CURRENT differs"));
        }
        let mut state = lock_state(shared)?;
        ensure_readable(&state)?;
        if !state.native_live_capacity || !state.native_ceiling_wait || !state.native_basis_active {
            return Err(invalid_data("pending base lacks capacity preconditions"));
        }
        state.native_basis_ready = false;
        state.native_pending_base = true;
        state.native_pending_journal_pressure = false;
        state.native_rollover_ready = false;
        self.pending = Some(Slot {
            old,
            old_epoch: request.meta.old_epoch,
            old_base_sequence: request.meta.old_base_sequence,
            observed: request.meta.token,
            context: None,
            initial: Some(request),
            worker: None,
        });
        shared.ready.notify_all();
        Ok(())
    }

    pub(in crate::sqlite::consensus::wal) fn pending_active(&self) -> bool {
        self.pending.is_some()
    }

    pub(in crate::sqlite::consensus::wal) fn pending_actionable(
        &self,
        state: &State,
        disk: &Disk,
    ) -> bool {
        // A pressure drain needs the current retained cut, even without cut
        // advancement. Let accepted Durable groups flush before recapturing it.
        self.pending.as_ref().is_some_and(|slot| {
            state.native_pending_ready
                || (slot.worker.is_none()
                    && (slot.initial.is_some()
                        || (state.status != Status::Running
                            && state.queue.is_empty()
                            && state.outstanding == 0
                            && state.native_operations == 0)
                        || token(state, disk).is_some_and(|token| {
                            token.advanced(slot.observed) || state.native_pending_journal_pressure
                        })))
        })
    }

    /// Returns true while this capacity-only capture still owns the checkpoint.
    pub(in crate::sqlite::consensus::wal) fn poll_pending(
        &mut self,
        shared: &Arc<Shared>,
        disk: &mut Disk,
        binding: Binding,
        limits: Limits,
        control: &IoControl,
    ) -> io::Result<bool> {
        let Some(mut slot) = self.pending.take() else {
            return Ok(false);
        };
        if lock_state(shared)?.native_pending_ready {
            let result = slot
                .worker
                .take()
                .ok_or_else(|| invalid_data("pending ready worker missing"))?
                .join()
                .map_err(|_| io::Error::other("native pending-base worker panicked"))??;
            lock_state(shared)?.native_pending_ready = false;
            match result {
                Built::Ready { meta, base } => {
                    self.select_pending(shared, disk, meta, base, binding, limits, control)?;
                    return Ok(false);
                }
                Built::Drained => {
                    #[cfg(test)]
                    (control.hook)(Point::NativePendingJournalDrained)?;
                }
                Built::Full => {
                    let mut state = lock_state(shared)?;
                    ensure_readable(&state)?;
                    state.checkpoint_costs.pending_capacity_waits += 1;
                    shared.ready.notify_all();
                    drop(state);
                    (control.hook)(Point::NativePendingCapacityWait)?;
                }
            }
        }
        if slot.worker.is_none() {
            let request = if let Some(request) = slot.initial.take() {
                Some(request)
            } else {
                capture_advanced(&mut slot, shared, disk, binding)?
            };
            if let Some(mut request) = request {
                let context = Version::capture(&request.full.storage)?.context_digest()?;
                let advanced = request.meta.token.advanced(slot.observed) || slot.context.is_none();
                slot.observed = request.meta.token;
                // Timer/scheduler wakeups and an explicit empty checkpoint can
                // advance an Async scheduling generation without changing state.
                // They never authorize another serialization of an unchanged cut.
                let build = advanced && slot.context != Some(context);
                if build {
                    slot.context = Some(context);
                }
                {
                    validate_before_build(shared, disk, &request.meta, slot.old, binding)?;
                    request
                        .meta
                        .anchor
                        .native_generation
                        .as_mut()
                        .ok_or_else(|| invalid_data("pending generation missing"))?
                        .file_epoch = slot.old.file_epoch + 1;
                    let preparing = disk
                        .directory
                        .join(format!("basis-{:020}.preparing", slot.old.file_epoch + 1));
                    let worker_shared = Arc::clone(shared);
                    let worker_control = control.clone();
                    let old = slot.old;
                    if build {
                        self.coordination
                            .record_pending_attempt(shared, old.file_epoch)?;
                        (control.hook)(Point::BeforeNativePendingCapture)?;
                    }
                    slot.worker = Some(std::thread::Builder::new().name("session-native-capacity".into()).spawn(move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            { let state = lock_state(&worker_shared)?; ensure_readable(&state)?; }
                            Version::require_capture(&request.changes, &request.full.storage, &|| Ok(()))?;
                            { let state = lock_state(&worker_shared)?; ensure_readable(&state)?; }
                            drop(request.changes);
                            if !build {
                                return Ok(Built::Drained);
                            }
                            if request.meta.anchor.async_cut.is_none() {
                                request.meta.anchor.prefix = checkpoint::hash_prefix(
                                    &preparing.parent().ok_or_else(|| invalid_data("pending WAL directory missing"))?
                                        .join(format!("segment-{:020}.wal", request.meta.anchor.position.segment)), request.meta.anchor.position.offset,
                                )?;
                            }
                            (worker_control.hook)(Point::BeforeNativePendingBaseBuild)?;
                            let base = rollover::build_pending(request.full, request.meta.anchor.clone(), old,
                                &preparing, binding, &worker_control, &|| Ok(()));
                            match base {
                                Ok(base) => {
                                    (worker_control.hook)(Point::AfterNativePendingBaseBuild)?;
                                    Ok(Built::Ready { meta: request.meta, base })
                                }
                                Err(error) if crate::consensus::native::prefix::is_capacity_limit(&error) => Ok(Built::Full),
                                Err(error) => Err(error),
                            }
                        })).unwrap_or_else(|_| Err(io::Error::other("native pending-base worker panicked")));
                        let mut state = match worker_shared.state.lock() {
                            Ok(state) => state,
                            Err(poison) => {
                                let mut state = poison.into_inner();
                                application::fence(&mut state);
                                state.native_pending_ready = true;
                                worker_shared.ready.notify_all();
                                return Err(io::Error::other("native pending completion poisoned"));
                            }
                        };
                        state.native_pending_ready = true;
                        worker_shared.ready.notify_all();
                        result
                    })?);
                    #[cfg(test)]
                    (control.hook)(Point::AfterNativePendingWorkerStart)?;
                }
            } else {
                let state = lock_state(shared)?;
                if state.status != Status::Running
                    && state.queue.is_empty()
                    && state.outstanding == 0
                    && state.native_operations == 0
                {
                    return Err(stopped());
                }
            }
        }
        self.pending = Some(slot);
        Ok(true)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "keep existing owner, namespace, mode and bound inputs explicit"
    )]
    fn select_pending(
        &mut self,
        shared: &Arc<Shared>,
        disk: &mut Disk,
        mut meta: Meta,
        base: rollover::Built,
        binding: Binding,
        limits: Limits,
        control: &IoControl,
    ) -> io::Result<()> {
        validate_before_build(shared, disk, &meta, base.cut, binding)?;
        let prefix = base.append.current();
        let identity = prefix.identity();
        meta.anchor.basis = identity.digest;
        meta.anchor.basis_bytes = identity.length;
        meta.anchor.native_generation = Some(checkpoint::NativeGeneration {
            file_epoch: identity.file_epoch,
            block_bytes: identity.block_bytes,
            frontiers: identity.frontiers,
        });
        meta.anchor.validate(binding, limits)?;
        if meta.anchor.native_prefix()? != Some(identity) {
            return Err(invalid_data("pending admitted selector differs"));
        }
        let final_path = meta.anchor.basis_path(&disk.directory);
        crate::consensus::snapshot::rename_noreplace_in_directory(
            &File::open(&disk.directory)?,
            base.preparing
                .file_name()
                .ok_or_else(|| invalid_data("pending preparation name missing"))?,
            final_path
                .file_name()
                .ok_or_else(|| invalid_data("pending final name missing"))?,
        )?;
        (control.hook)(Point::AfterBasisRename)?;
        File::open(&disk.directory)?.sync_all()?;
        (control.hook)(Point::AfterBasisDirectorySync)?;
        base.append.confirm_named(&final_path)?;
        let empty = Relocations::empty(&base.base_capture.storage, Arc::clone(&prefix))?;
        let mut next =
            Selected::admitted(base.append, &base.base_capture.storage, identity.length)?;
        next.record_switch_size(base.cut, base.old_head, identity.length, 0, true)?;
        // A single next delta may exceed the headroom even when this base is
        // below the trigger. Keep its exact selected capture available; only
        // the unchanged trigger (or guard) requests another background build.
        let next_cut = Some(rollover::Cut {
            capture: next
                .initial_capture
                .take()
                .ok_or_else(|| invalid_data("pending selected capture missing"))?,
            anchor: meta.anchor.clone(),
            head: Arc::clone(&prefix),
            base_bytes: identity.length,
            requested: false,
        });
        let previous = self
            .selected
            .take()
            .ok_or_else(|| invalid_data("pending previous selected owner missing"))?;
        (control.hook)(Point::BeforeNativePendingBaseSelect)?;
        if binding.persistence == SessionPersistenceMode::Durable {
            lock_state(shared)?.native_basis_ready = true;
            let prepared = Prepared {
                anchor: meta.anchor,
                old_epoch: meta.old_epoch,
                old_base_sequence: meta.old_base_sequence,
                covered_bytes: meta.covered_bytes,
                snapshot: meta.snapshot,
                snapshot_selection: meta.selection,
                selected: next,
                retired: Some(previous),
                relocations: empty,
                costs: integration::CheckpointCosts {
                    native_basis_count: 1,
                    native_basis_bytes: identity.length,
                    ..Default::default()
                },
                elapsed: meta.started.elapsed(),
                frame: None,
                cut: None,
                background: VecDeque::new(),
            };
            let (selected, rows) = select(shared, disk, prepared, binding, limits, control, None)?;
            self.selected = Some(selected);
            if !rows.is_empty() {
                return Err(invalid_data("pending base has ordinary delta relocation"));
            }
        } else {
            drop(empty);
            checkpoint::select(&disk.directory, &meta.anchor, control)?;
            previous.append.retire();
            checkpoint::reclaim_covered(
                disk,
                &meta.anchor,
                control,
                binding.async_recovery_format,
            )?;
            let mut state = lock_state(shared)?;
            ensure_readable(&state)?;
            validate_async(&state, &meta)?;
            if let Some(selection) = meta.selection {
                state
                    .native
                    .as_mut()
                    .ok_or_else(|| invalid_data("pending Async native owner missing"))?
                    .business
                    .publish_checkpoint_snapshot(selection)?;
                state.native_snapshot_pending = None;
            }
            let cut = meta
                .anchor
                .async_cut
                .ok_or_else(|| invalid_data("pending Async selection cut missing"))?;
            state.base_sequence = cut.sequence;
            state.checkpoint_epoch = meta.anchor.epoch;
            state.durable_committed = cut.committed;
            state.authority.frozen_applied = cut.applied;
            state
                .asynchronous
                .as_mut()
                .ok_or_else(|| invalid_data("pending Async progress missing"))?
                .completed(cut, identity.length);
            state.native_basis_active = false;
            state.native_basis_ready = false;
            if state
                .native_checkpoint_target
                .is_some_and(|target| target.satisfied(&state))
            {
                state.native_checkpoint_target = None;
            }
            state.checkpoint_requested =
                state.native_checkpoint_target.is_some() || state.native_snapshot_pending.is_some();
            state.checkpoint_costs.completed += 1;
            state.checkpoint_costs.native_basis_count += 1;
            state.checkpoint_costs.native_basis_bytes += identity.length;
            record_generation_size(&mut state, &next, binding.persistence, control)?;
            let elapsed = meta.started.elapsed();
            state.checkpoint_costs.elapsed += elapsed;
            state.checkpoint_costs.maximum = state.checkpoint_costs.maximum.max(elapsed);
            disk.anchor = Some(meta.anchor);
            shared.async_progress.send_replace(());
            shared.ready.notify_all();
            drop(state);
            self.selected = Some(next);
        }
        let rows = Relocations::from_base(base.base_capture, prefix)?;
        self.cut = next_cut;
        #[cfg(test)]
        (control.hook)(Point::NativePendingSelectedCaptureReady(
            self.cut.is_some()
                || self
                    .selected
                    .as_ref()
                    .is_some_and(|selected| selected.initial_capture.is_some()),
        ))?;
        self.background.push_back(Background::new(
            self.selected.as_ref().unwrap().append.current(),
            rows,
        ));
        let mut state = lock_state(shared)?;
        state.native_pending_base = false;
        state.native_pending_ready = false;
        state.native_pending_journal_pressure = false;
        state.native_ceiling_wait = false;
        state.native_live_capacity = false;
        state.checkpoint_costs.pending_base_selections += 1;
        shared.ready.notify_all();
        drop(state);
        self.coordination.finish_pending();
        self.coordination.record_switch(shared, control)?;
        (control.hook)(Point::AfterNativePendingBaseSelect)?;
        Ok(())
    }

    pub(super) fn stop_pending(&mut self, control: &IoControl) -> io::Result<()> {
        if let Some(mut slot) = self.pending.take() {
            if let Some(worker) = slot.worker.take() {
                match worker
                    .join()
                    .map_err(|_| io::Error::other("pending worker join panicked"))??
                {
                    Built::Ready { base, .. } => base.discard(control)?,
                    Built::Full | Built::Drained => (),
                }
            }
        }
        Ok(())
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn token(state: &State, disk: &Disk) -> Option<Token> {
    let native = state.native.as_ref()?;
    if let Some(progress) = &state.asynchronous {
        Some(Token {
            sequence: state.sequence,
            applied: native.business.applied(),
            generation: Some(progress.generation),
        })
    } else if state.queue.is_empty()
        && state.outstanding == 0
        && state.sequence == disk.sequence
        && native.log.committed == state.durable_committed
    {
        Some(Token {
            sequence: disk.sequence,
            applied: native.business.applied(),
            generation: None,
        })
    } else {
        None
    }
}

fn capture_advanced(
    slot: &mut Slot,
    shared: &Arc<Shared>,
    disk: &Disk,
    binding: Binding,
) -> io::Result<Option<Request>> {
    let mut state = lock_state(shared)?;
    ensure_readable(&state)?;
    let pressure = state.native_pending_journal_pressure;
    let Some(current) =
        token(&state, disk).filter(|current| current.advanced(slot.observed) || pressure)
    else {
        return Ok(None);
    };
    if state.checkpoint_epoch != slot.old_epoch
        || state.base_sequence != slot.old_base_sequence
        || state.snapshot.is_some()
    {
        return Err(invalid_data("pending recapture predecessor changed"));
    }
    let snapshot = state.native_snapshot_pending.clone();
    let native = state
        .native
        .as_mut()
        .ok_or_else(|| invalid_data("pending recapture native missing"))?;
    let (changes, selection) = native.take_checkpoint_changes(snapshot.clone())?;
    let mut full = native.capture_snapshot()?;
    if let Some(selection) = &selection {
        full.select_checkpoint_snapshot(selection)?;
    }
    let mut anchor = disk
        .anchor
        .clone()
        .ok_or_else(|| invalid_data("pending recapture CURRENT missing"))?;
    anchor.epoch = slot.old_epoch + 1;
    // Async application authority lives only in async_cut. Its ordinary WAL
    // selector fields remain pristine, exactly as normal Async capture does.
    anchor.applied = if binding.persistence == SessionPersistenceMode::Durable {
        current.applied
    } else {
        None
    };
    if let (Some(snapshots), Some(snapshot)) = (&mut anchor.native_snapshots, &snapshot) {
        snapshots.current = snapshot.clone();
    }
    if binding.persistence == SessionPersistenceMode::Async {
        let cut = checkpoint::AsyncCut {
            generation: current.generation.unwrap(),
            sequence: current.sequence,
            committed: native.log.committed,
            applied: current.applied,
        };
        anchor.async_cut = Some(cut);
        state.asynchronous.as_mut().unwrap().captured = current.generation;
    } else {
        let cut = *disk
            .cuts
            .get(&disk.sequence)
            .filter(|cut| cut.chain == disk.chain && cut.committed == state.durable_committed)
            .ok_or_else(|| invalid_data("pending recapture durable cut missing"))?;
        if state.durable_cuts.get(&disk.sequence) != Some(&cut) {
            return Err(invalid_data("pending recapture state/disk cuts differ"));
        }
        anchor.position = disk.position();
        anchor.cut = disk.cut;
        anchor.cut_chain = disk.cut_chain;
        anchor.cuts = BTreeMap::from([(disk.sequence, cut)]);
    }
    state.native_pending_journal_pressure = false;
    Ok(Some(Request {
        meta: Meta {
            anchor,
            old_epoch: slot.old_epoch,
            old_base_sequence: slot.old_base_sequence,
            covered_bytes: state.history_bytes,
            snapshot,
            selection,
            token: current,
            started: Instant::now(),
            _memory: crate::consensus::verified_snapshot::VerificationMemory::reserve(64 * 1024)?,
        },
        changes,
        full,
    }))
}

fn validate_async(state: &State, meta: &Meta) -> io::Result<()> {
    if state.checkpoint_epoch != meta.old_epoch
        || state.base_sequence != meta.old_base_sequence
        || state
            .asynchronous
            .as_ref()
            .and_then(|progress| progress.captured)
            != meta.token.generation
        || (meta.snapshot.is_some() && state.native_snapshot_pending != meta.snapshot)
        || state.snapshot.is_some()
    {
        return Err(invalid_data(
            "pending Async publication predecessor differs",
        ));
    }
    Ok(())
}

fn validate_before_build(
    shared: &Arc<Shared>,
    disk: &Disk,
    meta: &Meta,
    old: crate::consensus::native::prefix::PrefixIdentity,
    binding: Binding,
) -> io::Result<()> {
    let state = lock_state(shared)?;
    ensure_readable(&state)?;
    if !state.native_basis_active
        || !state.native_pending_base
        || !state.native_live_capacity
        || !state.native_ceiling_wait
        || disk
            .anchor
            .as_ref()
            .and_then(|anchor| anchor.native_prefix().ok())
            .flatten()
            != Some(old)
    {
        return Err(invalid_data("pending capacity ownership changed"));
    }
    if binding.persistence == SessionPersistenceMode::Async {
        return validate_async(&state, meta);
    }
    let captured = meta
        .anchor
        .cuts
        .get(&meta.anchor.position.sequence)
        .ok_or_else(|| invalid_data("pending captured WAL cut missing"))?;
    if state.checkpoint_epoch != meta.old_epoch
        || state.base_sequence != meta.old_base_sequence
        || meta.anchor.epoch != meta.old_epoch + 1
        || state.snapshot.is_some()
        || meta.anchor.position.sequence < meta.old_base_sequence
        || meta.anchor.position.sequence > disk.sequence
        || disk.sequence > state.sequence
        || state.durable_cuts.get(&meta.anchor.position.sequence) != Some(captured)
        || disk.cuts.get(&meta.anchor.position.sequence) != Some(captured)
        || !pointer_covers(state.durable_committed, captured.committed)
        || !pointer_covers(
            state
                .native
                .as_ref()
                .ok_or_else(|| invalid_data("pending current native missing"))?
                .business
                .applied(),
            meta.anchor.applied,
        )
    {
        return Err(invalid_data("pending retained WAL capture differs"));
    }
    Ok(())
}
