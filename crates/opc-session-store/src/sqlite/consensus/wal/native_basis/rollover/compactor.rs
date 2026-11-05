//! Disposable file ownership, independent of the admission checkpoint worker.
//! Only already selected old frames enter the queue; no change journal survives
//! an ordinary checkpoint on behalf of this worker.

use super::*;
use crate::consensus::native::generation::{try_rebase_frame, FrameMapping, Version};
use crate::consensus::native::prefix::{PrefixIdentity, VerifiedAppendOwner, VerifiedPrefix};
use crate::consensus::verified_snapshot::VerificationMemory;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[path = "capacity.rs"]
mod capacity;
pub(in crate::sqlite::consensus::wal::native_basis) use capacity::Capacity;

pub(in crate::sqlite::consensus::wal::native_basis) struct Cut {
    pub capture: SnapshotCapture,
    pub anchor: checkpoint::Anchor,
    pub head: Arc<VerifiedPrefix>,
    pub base_bytes: u64,
    pub requested: bool,
}

pub(in crate::sqlite::consensus::wal::native_basis) struct Frame {
    pub start: PrefixIdentity,
    pub end: Arc<VerifiedPrefix>,
    pub payload: u64,
    _memory: VerificationMemory,
}

impl Frame {
    pub fn new(start: PrefixIdentity, end: Arc<VerifiedPrefix>, payload: u64) -> io::Result<Self> {
        // Capacity growth and the queue entry coexist; the view has its own
        // existing reservation. No payload or typed journal is retained.
        let memory = VerificationMemory::reserve(2 * std::mem::size_of::<Self>())?;
        Ok(Self {
            start,
            end,
            payload,
            _memory: memory,
        })
    }
}

pub(in crate::sqlite::consensus::wal::native_basis) struct Built {
    pub append: VerifiedAppendOwner,
    pub base_capture: SnapshotCapture,
    pub base_view: Arc<VerifiedPrefix>,
    pub old_head: PrefixIdentity,
    pub shifts: Vec<FrameMapping>,
    pub cut: PrefixIdentity,
    pub preparing: PathBuf,
}

#[derive(Debug)]
struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native compactor cancelled")
    }
}
impl std::error::Error for Cancelled {}
fn cancelled() -> io::Error {
    io::Error::other(Cancelled)
}
fn is_cancelled(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<Cancelled>())
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod retry_tests;
#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum ProbePoint {
    BeforeTakeWait,
    BeforeQueueWait,
    BeforeOwnerTake,
    CancelLockContended,
    AfterCancelNotify,
}

#[cfg(test)]
type Probe = Arc<dyn Fn(ProbePoint) + Send + Sync>;
struct Failure {
    kind: io::ErrorKind,
    message: String,
    cancelled: bool,
}
impl Failure {
    fn error(&self) -> io::Error {
        if self.cancelled {
            cancelled()
        } else {
            io::Error::new(self.kind, self.message.clone())
        }
    }
}

struct Work {
    queue: VecDeque<Frame>,
    built: Option<Built>,
    active: bool,
    error: Option<Failure>,
    stop: bool,
    restart_after: Option<PrefixIdentity>,
    live_context: Option<[u8; 32]>,
    finished: bool,
    attempt_file: u64,
    attempts: u64,
}

pub(in crate::sqlite::consensus::wal) struct Coordinator {
    work: Mutex<Work>,
    changed: Condvar,
    cancel: AtomicBool,
    closing: AtomicBool,
    warned_epoch: AtomicU64,
    #[cfg(test)]
    probe: Mutex<Option<Probe>>,
}

// Keep the already bounded owner transfer inline, as Option<Built> did.
#[expect(
    clippy::large_enum_variant,
    reason = "bounded inline compactor owner transfer"
)]
pub(in crate::sqlite::consensus::wal::native_basis) enum Take {
    Built(Built),
    Restart,
    Capacity,
}
const _: () = assert!(std::mem::size_of::<Take>() <= 8 * 1024);
#[cfg(test)]
impl Take {
    fn is_none(&self) -> bool {
        matches!(self, Self::Capacity)
    }
}

impl Coordinator {
    fn capacity_ready(work: &Work, head: PrefixIdentity) -> bool {
        work.live_context.is_some()
            && (work.restart_after == Some(head)
                || (work.live_context == Some(head.frontiers)
                    && work.restart_after.is_some_and(|after| {
                        after.file_epoch == head.file_epoch
                            && after.checkpoint_epoch <= head.checkpoint_epoch
                    })))
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            work: Mutex::new(Work {
                queue: VecDeque::new(),
                built: None,
                active: false,
                error: None,
                stop: false,
                restart_after: None,
                live_context: None,
                finished: true,
                attempt_file: 0,
                attempts: 0,
            }),
            changed: Condvar::new(),
            cancel: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            warned_epoch: AtomicU64::new(0),
            #[cfg(test)]
            probe: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn probe(&self, point: ProbePoint) {
        let hook = self.probe.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook(point);
        }
    }

    pub fn warn_headroom(
        &self,
        head: PrefixIdentity,
        next: Option<u64>,
        maximum: u64,
        control: &IoControl,
    ) -> io::Result<()> {
        if next.is_none_or(|length| length >= maximum - maximum / 4)
            && self.warned_epoch.swap(head.file_epoch, Ordering::AcqRel) != head.file_epoch
        {
            eprintln!(
                "native_generation_headroom_warning file_epoch={} bytes={} maximum={maximum}",
                head.file_epoch, head.length
            );
            (control.hook)(Point::NativeGenerationHeadroomWarning)?;
        }
        Ok(())
    }

    pub fn active(&self) -> bool {
        self.work.lock().unwrap().active
    }

    pub(in crate::sqlite::consensus::wal::native_basis) fn enqueue(
        &self,
        frame: Frame,
    ) -> io::Result<()> {
        let mut work = self
            .work
            .lock()
            .map_err(|_| invalid_data("native compactor queue poisoned"))?;
        if !work.active && work.restart_after.is_some() {
            return Ok(());
        }
        if !work.active || work.stop {
            return Err(invalid_data("native compactor no longer owns suffix"));
        }
        work.queue.push_back(frame);
        self.changed.notify_all();
        Ok(())
    }

    pub(in crate::sqlite::consensus::wal::native_basis) fn try_take(
        &self,
        head: PrefixIdentity,
    ) -> io::Result<Option<Built>> {
        #[cfg(test)]
        self.probe(ProbePoint::BeforeOwnerTake);
        let mut work = self
            .work
            .lock()
            .map_err(|_| invalid_data("native compactor ownership poisoned"))?;
        if let Some(error) = &work.error {
            return Err(error.error());
        }
        if work.queue.is_empty()
            && work
                .built
                .as_ref()
                .is_some_and(|built| built.old_head == head)
        {
            work.stop = true;
            self.changed.notify_all();
            return Ok(work.built.take());
        }
        Ok(None)
    }

    pub(in crate::sqlite::consensus::wal::native_basis) fn wait_take(
        &self,
        head: PrefixIdentity,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Take> {
        let mut closing_seen = false;
        loop {
            check()?;
            let mut work = self
                .work
                .lock()
                .map_err(|_| invalid_data("native compactor ownership poisoned"))?;
            if let Some(error) = &work.error {
                return Err(error.error());
            }
            if Self::capacity_ready(&work, head) {
                // A full base at an older cut with identical authenticated
                // context has the same canonical body. Only its <=64 KiB
                // header changes (block width is >=64 KiB), so rebinding can
                // save at most one block. Even if a fresh base now fits exactly,
                // the mandatory switch frame still cannot fit. Return the
                // capacity outcome, not an ineligible unchanged-state restart.
                return Ok(Take::Capacity);
            }
            if self.cancel.load(Ordering::Acquire) {
                return Err(cancelled());
            }
            if work.finished && work.restart_after.is_some() {
                return Ok(Take::Restart);
            }
            if work.queue.is_empty()
                && work
                    .built
                    .as_ref()
                    .is_some_and(|built| built.old_head == head)
            {
                work.stop = true;
                self.changed.notify_all();
                return Ok(Take::Built(work.built.take().ok_or_else(|| {
                    invalid_data("native compactor candidate disappeared")
                })?));
            }
            if self.closing.load(Ordering::Acquire) && !closing_seen {
                // Closing is a lossless owner recheck, not cancellation of an
                // admissible in-flight switch. Capacity restart/Full outcomes
                // still return control; ordinary checkpoint drain must finish.
                closing_seen = true;
                drop(work);
                check()?;
                continue;
            }
            #[cfg(test)]
            self.probe(ProbePoint::BeforeTakeWait);
            work = self
                .changed
                .wait(work)
                .map_err(|_| invalid_data("native compactor wait poisoned"))?;
            drop(work);
        }
    }

    // Durable has a separate writer which owns restart/join. Do not spin
    // on the same completed restart marker while that writer starts its job.
    pub fn wait_restart(
        &self,
        head: PrefixIdentity,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut closing_seen = false;
        loop {
            check()?;
            let work = self
                .work
                .lock()
                .map_err(|_| invalid_data("native restart wait poisoned"))?;
            if self.cancel.load(Ordering::Acquire) {
                return Err(cancelled());
            }
            if !work.finished || work.restart_after.is_none() || Self::capacity_ready(&work, head) {
                // A later attempt can already have finished Full before this
                // wait registers. Return to wait_take for that terminal result;
                // it cannot require another selected cut merely to wake us.
                return Ok(());
            }
            if self.closing.load(Ordering::Acquire) && !closing_seen {
                closing_seen = true;
                drop(work);
                check()?;
                continue;
            }
            drop(
                self.changed
                    .wait(work)
                    .map_err(|_| invalid_data("native restart wait poisoned"))?,
            );
        }
    }

    pub fn close(&self) {
        let _work = self
            .work
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        self.closing.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    /// The writer drains checkpoint waiters and joins optional work before
    /// resetting lifecycle predicates. Attempt accounting survives for the
    /// approved pending-cut continuation of the same rollover.
    pub fn reset_after_join(&self) -> io::Result<()> {
        let mut work = self
            .work
            .lock()
            .map_err(|_| invalid_data("native compactor reset poisoned"))?;
        if work.active {
            return Err(invalid_data("native compactor reset precedes join"));
        }
        work.built = None;
        work.queue.clear();
        work.error = None;
        work.stop = false;
        work.restart_after = None;
        work.live_context = None;
        work.finished = true;
        self.cancel.store(false, Ordering::Release);
        self.changed.notify_all();
        Ok(())
    }

    pub fn cancel(&self) {
        // The queue predicate and Condvar registration are protected by work.
        // Publish cancellation under that same mutex; the atomic remains for
        // lock-free checks inside the authenticated reader/encoder adapters.
        #[cfg(test)]
        if self.work.try_lock().is_err() {
            self.probe(ProbePoint::CancelLockContended);
        }
        let _work = self
            .work
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        self.cancel.store(true, Ordering::Release);
        self.changed.notify_all();
        #[cfg(test)]
        self.probe(ProbePoint::AfterCancelNotify);
    }
}

pub(in crate::sqlite::consensus::wal::native_basis) struct Job {
    worker: Option<JoinHandle<()>>,
    pub owned: PathBuf,
    signal: Arc<Coordinator>,
}

impl Job {
    pub fn start(
        cut: Cut,
        signal: Arc<Coordinator>,
        shared: &Arc<Shared>,
        directory: &Path,
        binding: Binding,
        control: &IoControl,
    ) -> io::Result<Self> {
        let epoch = cut
            .head
            .identity()
            .file_epoch
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or_else(|| invalid_data("native compactor file epoch exhausted"))?;
        let owned = directory.join(format!("basis-{epoch:020}.preparing"));
        {
            let mut work = signal
                .work
                .lock()
                .map_err(|_| invalid_data("native compactor ownership poisoned"))?;
            if work.active {
                return Err(invalid_data("native compactor already active"));
            }
            if work
                .restart_after
                .is_some_and(|after| cut.head.identity().checkpoint_epoch <= after.checkpoint_epoch)
                || work
                    .live_context
                    .is_some_and(|context| cut.head.identity().frontiers == context)
            {
                return Err(invalid_data("native restart cut did not advance"));
            }
            let attempts = if work.attempt_file == cut.head.identity().file_epoch {
                work.attempts + 1
            } else {
                1
            };
            *work = Work {
                queue: VecDeque::new(),
                built: None,
                active: true,
                error: None,
                stop: false,
                restart_after: None,
                live_context: None,
                finished: false,
                attempt_file: cut.head.identity().file_epoch,
                attempts,
            };
            signal.cancel.store(false, Ordering::Release);
            signal.changed.notify_all();
        }
        lock_state(shared)?.checkpoint_costs.compactor_attempts += 1;
        tracing::warn!(
            selected_bytes = cut.head.identity().length,
            compact_base_bytes = cut.base_bytes,
            maximum_bytes = maximum(binding.persistence, cut.head.identity().block_bytes)?,
            "native generation compact rollover started"
        );
        #[cfg(test)]
        {
            let control = control.clone();
            *signal.probe.lock().unwrap() = Some(Arc::new(move |point| {
                let point = match point {
                    ProbePoint::BeforeTakeWait => Point::NativeCompactorWaitTake,
                    ProbePoint::BeforeOwnerTake => Point::NativeCompactorOwnerTake,
                    ProbePoint::BeforeQueueWait => Point::NativeCompactorQueueWait,
                    ProbePoint::AfterCancelNotify => Point::NativeCompactorCancelled,
                    _ => return,
                };
                (control.hook)(point).expect("compactor wait test hook");
            }));
        }
        let worker_signal = Arc::clone(&signal);
        let wal = Arc::clone(shared);
        let path = owned.clone();
        let control = control.clone();
        let worker = std::thread::Builder::new()
            .name("session-native-compactor".into())
            .spawn(move || {
                #[cfg(test)]
                let _adapters =
                    crate::consensus::native::rollover_costs::AdapterScope::begin(Arc::new({
                        let control = control.clone();
                        move |adapter| {
                            use crate::consensus::native::rollover_costs::Adapter;
                            let point = match adapter {
                                Adapter::BaseBlock => Point::NativeCompactorBaseBlock,
                                Adapter::ExtentRead => Point::NativeCompactorExtentRead,
                            };
                            (control.hook)(point).expect("compactor adapter test hook");
                        }
                    }));
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
                        let check = || {
                            if worker_signal.cancel.load(Ordering::Acquire) {
                                Err(cancelled())
                            } else {
                                Ok(())
                            }
                        };
                        let initial = cut.head.identity();
                        let mut built = match build(cut, &path, binding, &control, &check) {
                            Ok(built) => built,
                            Err(error)
                                if crate::consensus::native::prefix::is_capacity_limit(&error) =>
                            {
                                let maximum =
                                    limit(binding.persistence, initial.block_bytes, &control)?;
                                worker_signal.capacity_abort(
                                    Capacity {
                                        after: initial,
                                        live_context: Some(initial.frontiers),
                                        required: maximum.saturating_add(1),
                                        maximum,
                                    },
                                    &wal,
                                    &control,
                                )?;
                                return Ok(());
                            }
                            Err(error) => return Err(error),
                        };
                        loop {
                            check()?;
                            let frame = {
                                let mut work = worker_signal
                                    .work
                                    .lock()
                                    .map_err(|_| invalid_data("native compactor queue poisoned"))?;
                                if let Some(frame) = work.queue.pop_front() {
                                    Some(frame)
                                } else {
                                    work.built = Some(built);
                                    drop(work);
                                    // Release the independent queue before State;
                                    // both owners acquire State before the queue.
                                    let _caught_up = {
                                        let mut state = lock_state(&wal)?;
                                        let work = worker_signal.work.lock().map_err(|_| {
                                            invalid_data("native compactor queue poisoned")
                                        })?;
                                        let ready = work.queue.is_empty()
                                            && work.built.as_ref().is_some_and(|built| {
                                                built.old_head.checkpoint_epoch
                                                    == state.checkpoint_epoch
                                                    && built.old_head.operation_sequence
                                                        == state.base_sequence
                                            });
                                        if ready {
                                            state.native_rollover_ready = true;
                                            state.checkpoint_requested = true;
                                            if state
                                                .asynchronous
                                                .as_ref()
                                                .is_some_and(|p| p.caught_up())
                                            {
                                                async_persistence::dirty(&mut state);
                                            }
                                            wal.ready.notify_all();
                                        }
                                        ready
                                    };
                                    #[cfg(test)]
                                    if _caught_up {
                                        (control.hook)(Point::NativeCompactorCaughtUp)?;
                                    }
                                    worker_signal.changed.notify_all();
                                    let mut work = worker_signal.work.lock().map_err(|_| {
                                        invalid_data("native compactor queue poisoned")
                                    })?;
                                    while work.queue.is_empty()
                                        && !work.stop
                                        && !worker_signal.cancel.load(Ordering::Acquire)
                                    {
                                        #[cfg(test)]
                                        worker_signal.probe(ProbePoint::BeforeQueueWait);
                                        work = worker_signal.changed.wait(work).map_err(|_| {
                                            invalid_data("native compactor wait poisoned")
                                        })?;
                                    }
                                    if work.stop {
                                        return Ok(());
                                    }
                                    check()?;
                                    built = work.built.take().ok_or_else(|| {
                                        invalid_data("native compactor owner disappeared")
                                    })?;
                                    work.queue.pop_front()
                                }
                            };
                            let Some(frame) = frame else {
                                continue;
                            };
                            if frame.start != built.old_head {
                                return Err(invalid_data(
                                    "native compactor suffix is discontinuous",
                                ));
                            }
                            (control.hook)(Point::BeforeNativeFrameRebase)?;
                            let memory = VerificationMemory::reserve(
                                2 * std::mem::size_of::<FrameMapping>(),
                            )?;
                            #[cfg(test)]
                            let abort = control
                                .native_rebase_capacity_abort
                                .as_ref()
                                .is_some_and(|abort| abort.swap(false, Ordering::AcqRel));
                            #[cfg(not(test))]
                            let abort = false;
                            let rebased = if abort {
                                None
                            } else {
                                try_rebase_frame(
                                    Arc::clone(&frame.end),
                                    frame.start,
                                    frame.payload,
                                    &mut built.append,
                                    &check,
                                )?
                            };
                            let Some((view, shift)) = rebased else {
                                let after = built.cut;
                                let maximum =
                                    limit(binding.persistence, frame.start.block_bytes, &control)?;
                                built.discard(&control)?;
                                worker_signal.capacity_abort(
                                    Capacity {
                                        after,
                                        live_context: None,
                                        required: maximum.saturating_add(1),
                                        maximum,
                                    },
                                    &wal,
                                    &control,
                                )?;
                                return Ok(());
                            };
                            if view.identity().frontiers != frame.end.identity().frontiers {
                                return Err(invalid_data(
                                    "native compactor suffix context differs",
                                ));
                            }
                            built.shifts.push(FrameMapping {
                                value: shift,
                                _memory: memory,
                            });
                            built.old_head = frame.end.identity();
                            (control.hook)(Point::AfterNativeFrameRebase)?;
                        }
                    }))
                    .unwrap_or_else(|_| Err(io::Error::other("native compactor panicked")));
                // Poison must still publish one terminal predicate and wake all
                // owners. Recover the guard only to fail closed; its poison is
                // retained, and no captured owner is admitted through it.
                let (failed, cancelled, restart) = {
                    let (mut work, poisoned) = match worker_signal.work.lock() {
                        Ok(work) => (work, false),
                        Err(poison) => (poison.into_inner(), true),
                    };
                    let result = if poisoned {
                        Err(invalid_data("native compactor completion poisoned"))
                    } else {
                        result
                    };
                    let failed = result.is_err();
                    let mut cancelled = false;
                    if let Err(error) = result {
                        cancelled = is_cancelled(&error);
                        work.error = Some(Failure {
                            kind: error.kind(),
                            message: error.to_string(),
                            cancelled,
                        });
                        work.active = false;
                    }
                    work.finished = true;
                    (
                        failed,
                        cancelled,
                        work.restart_after.is_some() && work.error.is_none(),
                    )
                };
                if failed || restart {
                    let (mut state, poisoned) = match wal.state.lock() {
                        Ok(state) => (state, false),
                        Err(poison) => (poison.into_inner(), true),
                    };
                    if poisoned || (failed && !cancelled) {
                        application::fence(&mut state);
                    }
                    if failed {
                        state.native_ceiling_wait = false;
                        state.native_rollover_ready = false;
                    } else if !poisoned {
                        state.native_rollover_ready = true;
                    }
                    wal.ready.notify_all();
                }
                worker_signal.changed.notify_all();
            })?;
        Ok(Self {
            worker: Some(worker),
            owned,
            signal,
        })
    }

    pub fn join(&mut self) -> io::Result<()> {
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("native compactor join panicked"))?;
        }
        self.signal
            .work
            .lock()
            .map_err(|_| invalid_data("native compactor owner poisoned"))?
            .active = false;
        Ok(())
    }

    pub fn cancel_and_join(&mut self) -> io::Result<()> {
        self.signal.cancel();
        self.join()?;
        self.signal.reset_after_join()
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        if self.worker.is_some() {
            let _ = self.cancel_and_join();
        }
    }
}

fn build(
    cut: Cut,
    path: &Path,
    binding: Binding,
    control: &IoControl,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Built> {
    let old = cut.head.identity();
    if Version::capture(&cut.capture.storage)?.context_digest()? != old.frontiers {
        return Err(invalid_data(
            "native compactor capture differs from selected cut",
        ));
    }
    build_at(cut.capture, cut.anchor, old, path, binding, control, check)
}

pub(in crate::sqlite::consensus::wal::native_basis) fn build_pending(
    capture: SnapshotCapture,
    anchor: checkpoint::Anchor,
    old: PrefixIdentity,
    path: &Path,
    binding: Binding,
    control: &IoControl,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Built> {
    if anchor.epoch
        != old
            .checkpoint_epoch
            .checked_add(1)
            .ok_or_else(|| invalid_data("native pending epoch exhausted"))?
        || anchor.native_sequence() < old.operation_sequence
    {
        return Err(invalid_data("native pending base cut regressed"));
    }
    build_at(capture, anchor, old, path, binding, control, check)
}

fn build_at(
    capture: SnapshotCapture,
    mut anchor: checkpoint::Anchor,
    old: PrefixIdentity,
    path: &Path,
    binding: Binding,
    control: &IoControl,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Built> {
    #[cfg(test)]
    let _costs = crate::consensus::native::rollover_costs::Scope::begin(
        control.native_rollover_costs.clone(),
    );
    check()?;
    let epoch = old
        .file_epoch
        .checked_add(1)
        .filter(|value| *value != u64::MAX)
        .ok_or_else(|| invalid_data("native pending file epoch exhausted"))?;
    anchor
        .native_generation
        .as_mut()
        .ok_or_else(|| invalid_data("native pending selector missing"))?
        .file_epoch = epoch;
    let maximum = limit(binding.persistence, old.block_bytes, control)?;
    let base = StreamingBase::prepare(
        &capture.storage,
        BaseParameters {
            binding: old.binding,
            file_epoch: epoch,
            checkpoint_epoch: anchor.epoch,
            operation_sequence: anchor.native_sequence(),
            cut_binding: anchor.native_cut_binding()?,
            block_bytes: old.block_bytes,
            maximum,
        },
        check,
    )?;
    (control.hook)(Point::BeforeBasisCreate)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    (control.hook)(Point::AfterBasisCreate)?;
    let pin = file.try_clone()?;
    let created = match base.write_new_concurrent(file, maximum, check) {
        Ok(created) => created,
        Err(error) if crate::consensus::native::prefix::is_capacity_limit(&error) => {
            (control.hook)(Point::BeforeNativeCandidateDiscard)?;
            crate::consensus::native::prefix::discard_owned_preparing(&pin, path, maximum)?;
            (control.hook)(Point::AfterNativeCandidateDiscard)?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    (control.hook)(Point::BeforeBasisSync)?;
    created.file().sync_all()?;
    (control.hook)(Point::AfterBasisSync)?;
    let append = created.admit(path, check)?;
    (control.hook)(Point::AfterNativeBasisAdmission)?;
    let base_view = append.current();
    drop(base);
    Ok(Built {
        append,
        base_capture: capture,
        base_view,
        old_head: old,
        cut: old,
        shifts: Vec::new(),
        preparing: path.to_path_buf(),
    })
}
