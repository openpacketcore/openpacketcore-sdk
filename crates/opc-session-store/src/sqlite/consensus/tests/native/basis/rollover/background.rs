//! Release witnesses prove ordering; finite hang guards only diagnose missing progress.

use crate::test_process::witness::{CondvarExt, JoinExt};

use super::*;

const WITNESS_HANG_GUARD: Duration = Duration::from_secs(180);

fn wait_for_witness<'a, T: std::fmt::Debug>(
    changed: &Condvar,
    state: std::sync::MutexGuard<'a, T>,
    mut pending: impl FnMut(&T) -> bool,
    step: impl std::fmt::Display,
) -> std::sync::MutexGuard<'a, T> {
    let (state, timeout) = changed
        .wait_timeout_while(state, WITNESS_HANG_GUARD, |state| pending(state))
        .unwrap();
    assert!(
        !timeout.timed_out() || !pending(&state),
        "native rollover witness stalled at {step}: state={state:?}"
    );
    state
}

fn join_witness<'scope, T>(
    thread: std::thread::ScopedJoinHandle<'scope, T>,
    step: &str,
    state: impl Fn() -> String,
) -> std::thread::Result<T> {
    let deadline = Instant::now() + WITNESS_HANG_GUARD;
    while !thread.is_finished() {
        assert!(
            Instant::now() < deadline,
            "native rollover join stalled at {step}: {}",
            state()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    thread.test_join()
}

struct StopFillOnDrop<'a>(&'a AtomicBool);
impl Drop for StopFillOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(super) struct Park {
    point: Point,
    background_only: bool,
    armed: AtomicBool,
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Park {
    pub(super) fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
    fn new() -> Arc<Self> {
        Self::at(Point::BeforeBasisCreate, false)
    }

    pub(super) fn at(point: Point, background_only: bool) -> Arc<Self> {
        Arc::new(Self {
            point,
            background_only,
            armed: AtomicBool::new(false),
            state: Mutex::new((false, false)),
            changed: Condvar::new(),
        })
    }

    pub(super) fn hook(&self, point: Point) -> io::Result<()> {
        if point != self.point
            || !self.armed.load(Ordering::Acquire)
            || (self.background_only
                && std::thread::current().name() != Some("session-native-relocate"))
        {
            return Ok(());
        }
        let mut state = self.state.lock().unwrap();
        if state.0 {
            return Ok(());
        }
        state.0 = true;
        self.changed.notify_all();
        drop(wait_for_witness(
            &self.changed,
            state,
            |s| !s.1,
            format_args!("release parked {:?}", self.point),
        ));
        Ok(())
    }

    pub(super) fn entered(&self) {
        drop(wait_for_witness(
            &self.changed,
            self.state.lock().unwrap(),
            |s| !s.0,
            format_args!("enter parked {:?}", self.point),
        ));
    }

    pub(super) fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }

    pub(super) fn control(self: &Arc<Self>) -> IoControl {
        let park = Arc::clone(self);
        IoControl {
            native_rollover_bytes: Some(64 * 1024),
            hook: Arc::new(move |point| park.hook(point)),
            ..IoControl::default()
        }
    }
}

pub(super) struct Release(pub(super) Arc<Park>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[test]
fn native_rollover_admission_advances_while_compactor_parked() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let mut failures = Vec::new();
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let park = Park::new();
            let limits = Limits {
                history_count: 8,
                ..Limits::default()
            };
            let fixture = Fixture::with_persistence(limits, park.control(), mode);
            let _release = Release(Arc::clone(&park));
            let initial = selected(&fixture);
            park.armed.store(true, Ordering::Release);
            std::thread::scope(|scope| {
                let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
                park.entered();
                let owns_checkpoint_slot = fixture.wal.native_basis_waiters_for_test().unwrap().2;
                if owns_checkpoint_slot {
                    // Deterministic RED probe rather than deadlocking the ninth
                    // adapter call behind the parked synchronous build. There is
                    // no other producer or checkpoint at this declared boundary.
                    for _ in 0..8 {
                        fixture
                            .wal
                            .submit(Operation::Barrier)
                            .unwrap()
                            .wait()
                            .unwrap();
                    }
                    let ninth = fixture.wal.submit(Operation::Barrier);
                    if mode == SessionPersistenceMode::Durable {
                        assert_eq!(ninth.err().unwrap().kind(), io::ErrorKind::WouldBlock);
                    } else {
                        ninth.unwrap().wait().unwrap();
                    }
                    failures.push(format!("{mode:?}: parked full build owns the checkpoint slot; CURRENT epoch {}, retained {}",
                    selected(&fixture)["epoch"], fixture.wal.integration_cost_snapshot().unwrap()["live_retained_requests"]));
                } else {
                    let before = fixture.wal.integration_cost_snapshot().unwrap()["requests"]
                        .as_u64()
                        .unwrap();
                    for ordinal in 1..=80 {
                        assert_eq!(
                            fixture
                                .wal
                                .native_submit_with_backpressure_for_test(Operation::Barrier)
                                .unwrap()
                                .wait()
                                .unwrap(),
                            before + ordinal
                        );
                    }
                    assert!(
                        selected(&fixture)["epoch"].as_u64().unwrap()
                            > initial["epoch"].as_u64().unwrap()
                    );
                    assert_eq!(
                        selected(&fixture)["native_generation"]["file_epoch"],
                        initial["native_generation"]["file_epoch"]
                    );
                    if mode == SessionPersistenceMode::Durable {
                        assert!(
                            fixture.wal.integration_cost_snapshot().unwrap()
                                ["live_retained_requests"]
                                .as_u64()
                                .unwrap()
                                <= 8
                        );
                    }
                    assert!(fixture.wal.storage_health().1.is_none());
                }
                park.release();
                checkpoint.test_join().unwrap().unwrap();
            });
            fixture.wal.shutdown().unwrap();
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    });
}

#[test]
fn native_rollover_journal_pressure_is_relieved_while_compactor_parked() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let mut failures = Vec::new();
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let park = Park::new();
            let fixture = Fixture::with_persistence(Limits::default(), park.control(), mode);
            let _release = Release(Arc::clone(&park));
            park.armed.store(true, Ordering::Release);
            std::thread::scope(|scope| {
                let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
                park.entered();
                let entry = Entry {
                    log_id: log_id(0),
                    payload: EntryPayload::Blank,
                };
                fixture
                    .wal
                    .submit(append(&[entry]))
                    .unwrap()
                    .wait()
                    .unwrap();
                let (journal, requested) = fixture
                    .wal
                    .native_request_journal_checkpoint_for_test()
                    .unwrap();
                if journal != 0 && !requested {
                    // Exercise the real pressure checkpoint request. The old
                    // active-build exclusion rejects it even with dirty bytes.
                    failures.push(format!("{mode:?}: live journal {journal} bytes; checkpoint request refused during compact build"));
                } else {
                    // A concurrently completed ordinary checkpoint is also actual
                    // relief; a zero journal never grants a false failure.
                    assert!(requested || journal == 0);
                    fixture.wal.checkpoint().unwrap();
                    assert!(fixture.wal.storage_health().1.is_none());
                }
                park.release();
                checkpoint.test_join().unwrap().unwrap();
            });
            fixture.wal.shutdown().unwrap();
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    });
}

#[test]
fn native_rollover_background_relocation_does_not_gate_checkpoints() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let build = Park::at(Point::AfterNativeBasisAdmission, false);
            let relocate = Park::at(Point::AfterNativeRelocationStep, true);
            let control = IoControl {
                native_rollover_bytes: Some(64 * 1024),
                hook: Arc::new({
                    let build = Arc::clone(&build);
                    let relocate = Arc::clone(&relocate);
                    move |point| {
                        build.hook(point)?;
                        relocate.hook(point)
                    }
                }),
                ..IoControl::default()
            };
            let fixture = Fixture::with_persistence(
                Limits {
                    history_count: 8,
                    ..Limits::default()
                },
                control,
                mode,
            );
            let _release_build = Release(Arc::clone(&build));
            let _release_relocate = Release(Arc::clone(&relocate));
            build.armed.store(true, Ordering::Release);
            relocate.armed.store(true, Ordering::Release);
            fixture.wal.checkpoint().unwrap();
            build.entered();
            let old = selected(&fixture)["native_generation"]["file_epoch"]
                .as_u64()
                .unwrap();
            build.release();
            relocate.entered();
            let switched = selected(&fixture);
            assert_eq!(
                switched["native_generation"]["file_epoch"]
                    .as_u64()
                    .unwrap(),
                old + 1
            );
            let initial = fixture.wal.integration_cost_snapshot().unwrap()["requests"]
                .as_u64()
                .unwrap();
            for ordinal in 1..=80 {
                assert_eq!(
                    fixture
                        .wal
                        .native_submit_with_backpressure_for_test(Operation::Barrier)
                        .unwrap()
                        .wait()
                        .unwrap(),
                    initial + ordinal
                );
            }
            fixture.wal.checkpoint().unwrap();
            assert!(
                selected(&fixture)["epoch"].as_u64().unwrap() > switched["epoch"].as_u64().unwrap()
            );
            assert!(fixture.wal.storage_health().1.is_none());
            relocate.release();
            fixture.wal.shutdown().unwrap();
        }
    });
}

#[derive(Default)]
struct CeilingEvents {
    state: Mutex<(bool, usize, usize)>, // guard, waiting admissions, warnings
    changed: Condvar,
}

impl CeilingEvents {
    fn hook(&self, point: Point) {
        let mut state = self.state.lock().unwrap();
        match point {
            Point::NativeGenerationCeilingWait => state.0 = true,
            Point::NativeFileGuardWaitStarted | Point::NativeRetentionWaitStarted => state.1 += 1,
            Point::NativeGenerationHeadroomWarning => state.2 += 1,
            _ => return,
        }
        self.changed.notify_all();
    }
    fn guard(&self) {
        drop(wait_for_witness(
            &self.changed,
            self.state.lock().unwrap(),
            |s| !s.0,
            "observe generation ceiling (guard, admissions, warnings)",
        ));
    }
    fn waiter(&self) {
        drop(wait_for_witness(
            &self.changed,
            self.state.lock().unwrap(),
            |s| s.1 == 0,
            "observe waiting admission (guard, admissions, warnings)",
        ));
    }
}

#[test]
fn native_rollover_ceiling_backpressure_never_refuses_or_poisons() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let build = Park::at(Point::AfterNativeBasisAdmission, false);
            let events = Arc::new(CeilingEvents::default());
            let control = IoControl {
                native_rollover_bytes: Some(64 * 1024),
                native_rollover_maximum: Some(512 * 1024),
                hook: Arc::new({
                    let build = Arc::clone(&build);
                    let events = Arc::clone(&events);
                    move |point| {
                        events.hook(point);
                        build.hook(point)
                    }
                }),
                ..IoControl::default()
            };
            let fixture = Fixture::with_persistence(
                Limits {
                    history_count: 8,
                    ..Limits::default()
                },
                control,
                mode,
            );
            let _release = Release(Arc::clone(&build));
            build.armed.store(true, Ordering::Release);
            fixture.wal.checkpoint().unwrap();
            build.entered();
            let first = selected(&fixture);
            let done = AtomicBool::new(false);
            std::thread::scope(|scope| {
                let fill = scope.spawn(|| {
                    for _ in 0..16 {
                        fixture
                            .wal
                            .native_submit_with_backpressure_for_test(Operation::Barrier)
                            .unwrap()
                            .wait()
                            .unwrap();
                        fixture.wal.checkpoint().unwrap();
                    }
                });
                events.guard();
                let guarded = selected(&fixture);
                assert_eq!(
                    guarded["native_generation"]["file_epoch"],
                    first["native_generation"]["file_epoch"]
                );
                assert!(guarded["basis_bytes"].as_u64().unwrap() <= 512 * 1024);
                assert_eq!(events.state.lock().unwrap().2, 1);
                let pending = scope.spawn(|| {
                    // Durable uses the unchanged history_count wait; Async waits
                    // before projection. Neither path refuses this operation.
                    for _ in 0..9 {
                        fixture
                            .wal
                            .native_submit_with_backpressure_for_test(Operation::Barrier)
                            .unwrap()
                            .wait()
                            .unwrap();
                    }
                    done.store(true, Ordering::Release);
                });
                events.waiter();
                assert!(!done.load(Ordering::Acquire));
                assert!(fixture.wal.storage_health().1.is_none());
                assert_eq!(fixture.wal.retirement_wait_state_for_test().unwrap().0, 0);
                build.release();
                pending.test_join().unwrap();
                fill.test_join().unwrap();
                assert!(done.load(Ordering::Acquire));
            });
            assert!(
                selected(&fixture)["native_generation"]["file_epoch"]
                    .as_u64()
                    .unwrap()
                    > first["native_generation"]["file_epoch"].as_u64().unwrap()
            );
            assert!(fixture.wal.storage_health().1.is_none());
            fixture.wal.shutdown().unwrap();
            let reopened = fixture.reopened();
            reopened.shutdown().unwrap();
        }
    });
}

#[test]
fn native_rollover_real_journal_stall_without_file_guard_still_fences() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        const CASE: &str = "native_rollover_real_journal_stall_without_file_guard_still_fences";
        const CHILD: &str = "OPC_ROLLOVER_PRESSURE_CHILD";
        if std::env::var(CHILD).as_deref() != Ok(CASE) {
            let name =
                format!("sqlite::consensus::tests::native::basis::rollover::background::{CASE}");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--test-threads=1", "--nocapture"])
                .env(CHILD, CASE)
                .test_output_with_deadline(std::time::Duration::from_secs(1800))
                .unwrap();
            assert!(
                super::concurrency::child_ran_one_exact_test(&output, &name),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use crate::consensus::verified_snapshot::{VerificationMemory, PROCESS_VERIFICATION_BYTES};
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let waits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let guards = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let control = IoControl {
                native_pressure_clock: Some(Arc::new(|progress| progress.expire_for_test())),
                hook: Arc::new({
                    let waits = Arc::clone(&waits);
                    let guards = Arc::clone(&guards);
                    move |point| {
                        if point == Point::NativeJournalWaitStarted {
                            waits.fetch_add(1, Ordering::AcqRel);
                        }
                        if point == Point::NativeFileGuardWaitStarted {
                            guards.fetch_add(1, Ordering::AcqRel);
                        }
                        Ok(())
                    }
                }),
                ..IoControl::default()
            };
            let fixture = Fixture::with_persistence(Limits::default(), control, mode);
            fixture.wal.checkpoint().unwrap();
            let pressure = VerificationMemory::reserve(
                PROCESS_VERIFICATION_BYTES - VerificationMemory::used_bytes() - 64 * 1024,
            )
            .unwrap();
            let entry = Entry {
                log_id: log_id(0),
                payload: EntryPayload::Blank,
            };
            let error = fixture
                .wal
                .native_submit_with_backpressure_for_test(append(&[entry]))
                .err()
                .unwrap();
            assert_eq!(error.to_string(), "native journal admission timed out");
            assert_eq!(waits.load(Ordering::Acquire), 1);
            assert_eq!(guards.load(Ordering::Acquire), 0);
            assert!(fixture.wal.storage_health().1.is_some());
            drop(pressure);
            assert!(fixture.wal.shutdown().is_err());
        }
    });
}

// The same valid conflicting-request log shape used by native delta bounds.
// It is retained but never applied, so ciphertext size does not change business
// behavior. JSON's byte-array encoding makes the base fill three 64 KiB blocks.
pub(super) fn capacity_entry(index: u64, ciphertext_bytes: usize) -> Entry<SessionRaftTypeConfig> {
    use crate::fenced_transition::{
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2Request,
        FencedTransitionV2RequestId,
    };
    #[derive(serde::Serialize)]
    struct Wire<'a> {
        request_id: FencedTransitionV2RequestId,
        lease: &'a FencedTransitionLease,
        mutation: FencedTransitionMutation,
    }
    let original = fenced_transition_v2_request(0xC7, 1, "pending-capacity");
    let mut record = original.mutation().record().unwrap().clone();
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(record.payload.as_bytes()).unwrap();
    envelope.ciphertext_and_tag = vec![0; ciphertext_bytes];
    record.payload =
        crate::EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
    let request: FencedTransitionV2Request = postcard::from_bytes(
        &postcard::to_allocvec(&Wire {
            request_id: original.request_id(),
            lease: original.lease(),
            mutation: FencedTransitionMutation::create(record),
        })
        .unwrap(),
    )
    .unwrap();
    fenced_transition_v2_authorized_entry(index, request, timestamp(1), node_id(), identity())
}

#[test]
fn native_rollover_pending_capacity_selects_a_complete_base_without_delta() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let pending = Park::at(Point::AfterNativePendingBaseBuild, false);
            let events = Arc::new(CeilingEvents::default());
            let control = IoControl {
                native_rollover_bytes: Some(64 * 1024),
                native_rollover_maximum: Some(3 * 64 * 1024),
                hook: Arc::new({
                    let pending = Arc::clone(&pending);
                    let events = Arc::clone(&events);
                    move |point| {
                        events.hook(point);
                        pending.hook(point)
                    }
                }),
                ..IoControl::default()
            };
            let fixture = Fixture::with_persistence(Limits::default(), control, mode);
            let _release = Release(Arc::clone(&pending));
            let initial = selected(&fixture);
            pending.armed.store(true, Ordering::Release);
            let entry = capacity_entry(0, 70 * 1024);
            fixture
                .wal
                .submit(append(std::slice::from_ref(&entry)))
                .unwrap()
                .wait()
                .unwrap();
            let completed = AtomicBool::new(false);
            std::thread::scope(|scope| {
                let _release = Release(Arc::clone(&pending));
                let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
                pending.entered();
                assert_eq!(
                    selected(&fixture),
                    initial,
                    "CURRENT stays old until the whole pending base is ready"
                );
                let costs = fixture.wal.integration_cost_snapshot().unwrap();
                assert_eq!(costs["checkpoint"]["pending_base_attempts"], 1);
                assert_eq!(costs["checkpoint"]["pending_base_selections"], 0);
                assert!(fixture.wal.storage_health().1.is_none());
                let waiting = scope.spawn(|| {
                    let sequence = fixture
                        .wal
                        .native_submit_with_backpressure_for_test(Operation::Barrier)
                        .unwrap()
                        .wait()
                        .unwrap();
                    completed.store(true, Ordering::Release);
                    sequence
                });
                events.waiter();
                assert!(!completed.load(Ordering::Acquire));
                pending.release();
                checkpoint.test_join().unwrap().unwrap();
                waiting.test_join().unwrap();
                assert!(completed.load(Ordering::Acquire));
            });
            let current = selected(&fixture);
            assert_eq!(
                current["native_generation"]["file_epoch"].as_u64().unwrap(),
                initial["native_generation"]["file_epoch"].as_u64().unwrap() + 1
            );
            assert_eq!(fixture.wal.read(0, 1).unwrap().len(), 1);
            let costs = fixture.wal.integration_cost_snapshot().unwrap();
            assert_eq!(costs["checkpoint"]["pending_base_selections"], 1);
            assert!(fixture.wal.storage_health().1.is_none());
            fixture.wal.shutdown().unwrap();
            let reopened = fixture.reopened();
            assert_eq!(reopened.read(0, 1).unwrap().len(), 1);
            reopened.shutdown().unwrap();
        }
    });
}
#[derive(Default)]
struct PendingEvents {
    state: Mutex<(usize, usize)>, // completed capacity attempts, idle observations
    changed: Condvar,
}
impl PendingEvents {
    fn hook(&self, point: Point) {
        let mut state = self.state.lock().unwrap();
        match point {
            Point::NativePendingCapacityWait => state.0 += 1,
            Point::NativePendingIdle => state.1 += 1,
            _ => return,
        }
        self.changed.notify_all();
    }
    fn wait(&self, predicate: impl Fn(&(usize, usize)) -> bool) {
        drop(
            self.changed
                .test_wait_while(self.state.lock().unwrap(), |state| !predicate(state))
                .unwrap(),
        );
    }
}

#[test]
fn native_rollover_live_capacity_retirement_resumes_without_relabeling() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        use super::super::super::lifecycle::maintenance;
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            eprintln!("pending_capacity_retirement mode={mode:?} phase=fixture");
            let mut fixture =
                Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
            let initial = fenced_transition_v2_request(0xD7, 1, "capacity-retirement");
            fixture.parity(&[formation(), activation(1, initial, timestamp(1))]);
            fixture.wal.shutdown().unwrap();
            let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
            let remaining = 1024;
            let history = FencedTransitionV2HistoryState::new(
                Some(epoch(2)),
                Some(epoch(1)),
                Some(epoch(1)),
                remaining,
                1,
                0,
                (FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - remaining) as u64,
            )
            .unwrap();
            fixture.wal = Wal::open_reclaim_fixture_for_test(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                history,
                timestamp(10),
                IoControl::default(),
            )
            .unwrap();
            let ceiling = selected(&fixture)["basis_bytes"].as_u64().unwrap();
            fixture.wal.shutdown().unwrap();
            let pending = Park::at(Point::AfterNativePendingBaseBuild, false);
            let selected_cut = Park::at(Point::AfterNativePendingBaseSelect, false);
            let cut_ready = Arc::new(AtomicBool::new(false));
            let build_costs = Arc::new(Mutex::new(Vec::new()));
            let switches = Arc::new((Mutex::new(0_usize), Condvar::new()));
            let events = Arc::new(PendingEvents::default());
            let admission = Arc::new(CeilingEvents::default());
            let control = IoControl {
                // Use the ordinary ceiling/2 threshold. Retirement makes the new
                // base no larger than that trigger, before a large next delta.
                native_rollover_bytes: None,
                native_rollover_maximum: Some(ceiling),
                native_rollover_costs: Some(Arc::clone(&build_costs)),
                hook: Arc::new({
                    let pending = Arc::clone(&pending);
                    let selected_cut = Arc::clone(&selected_cut);
                    let cut_ready = Arc::clone(&cut_ready);
                    let switches = Arc::clone(&switches);
                    let events = Arc::clone(&events);
                    let admission = Arc::clone(&admission);
                    move |point| {
                        if point == Point::AfterNativeSwitchSelection {
                            *switches.0.lock().unwrap() += 1;
                            switches.1.notify_all();
                        }
                        if let Point::NativePendingSelectedCaptureReady(ready) = point {
                            cut_ready.store(ready, Ordering::Release);
                        }
                        selected_cut.hook(point)?;
                        events.hook(point);
                        admission.hook(point);
                        pending.hook(point)
                    }
                }),
                ..IoControl::default()
            };
            fixture.wal = Wal::open(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                Limits::default(),
                control,
            )
            .unwrap();
            let old = selected(&fixture);
            pending.armed.store(true, Ordering::Release);
            selected_cut.armed.store(true, Ordering::Release);
            let maintenance = maintenance(2, history, timestamp(11));
            let padding = capacity_entry(3, 40 * 1024);
            fixture
                .wal
                .submit(append(&[maintenance.clone(), padding]))
                .unwrap()
                .wait()
                .unwrap();
            fixture
                .wal
                .submit(Operation::Committed(Some(log_id(2))))
                .unwrap()
                .wait()
                .unwrap();
            let done = AtomicBool::new(false);
            std::thread::scope(|scope| {
                let _release = Release(Arc::clone(&pending));
                let _release_selected = Release(Arc::clone(&selected_cut));
                let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
                events.wait(|state| state.0 == 1 && state.1 != 0);
                let before = fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]
                    ["pending_base_attempts"]
                    .as_u64()
                    .unwrap();
                assert_eq!(before, 1);
                let idle = events.state.lock().unwrap().1;
                fixture.wal.native_pending_wake_for_test();
                events.wait(|state| state.1 > idle);
                assert_eq!(
                    fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]
                        ["pending_base_attempts"],
                    before,
                    "an unchanged captured cut cannot authorize another serialization"
                );
                let waiting = scope.spawn(|| {
                    fixture
                        .wal
                        .native_submit_with_backpressure_for_test(Operation::Barrier)
                        .unwrap()
                        .wait()
                        .unwrap();
                    done.store(true, Ordering::Release);
                });
                admission.waiter();
                assert!(!done.load(Ordering::Acquire));
                assert_eq!(selected(&fixture), old);
                assert!(fixture.wal.storage_health().1.is_none());
                fixture
                    .wal
                    .native_apply_committed(std::slice::from_ref(&maintenance))
                    .unwrap();
                pending.entered();
                assert_eq!(
                    selected(&fixture),
                    old,
                    "old CURRENT and WAL remain authoritative before base-only selection"
                );
                let costs = fixture.wal.integration_cost_snapshot().unwrap();
                assert_eq!(costs["checkpoint"]["pending_base_attempts"], 2);
                assert_eq!(costs["checkpoint"]["pending_base_selections"], 0);
                assert_eq!(
                    fixture
                        .wal
                        .with_native_read(|state| state.history_state())
                        .unwrap()
                        .reclaim_remaining(),
                    0
                );
                pending.release();
                selected_cut.entered();
                assert!(selected(&fixture)["basis_bytes"].as_u64().unwrap() <= ceiling / 2);
                assert!(
                    cut_ready.load(Ordering::Acquire),
                    "a selected base below the trigger still needs a guard capture"
                );
                // Choose the smallest legal encoded row exceeding two blocks;
                // this forces the next guard without overfilling the compact base.
                let (mut low, mut high) = (16, 128 * 1024);
                while low < high {
                    let middle = low + (high - low) / 2;
                    if encode_json(&capacity_entry(4, middle)).unwrap().len() > 2 * 64 * 1024 {
                        high = middle;
                    } else {
                        low = middle + 1;
                    }
                }
                let next_entry = capacity_entry(4, low);
                let encoded = encode_json(&next_entry).unwrap().len();
                assert!(
                    encoded > 2 * 64 * 1024,
                    "the next delta must need at least3 padded blocks"
                );
                eprintln!("pending_capacity_next_guard mode={mode:?} base={} encoded_next_entry={encoded} ceiling={ceiling}", selected(&fixture)["basis_bytes"]);
                let next = fixture.wal.submit(append(&[next_entry])).unwrap();
                selected_cut.release();
                next.wait().unwrap();
                checkpoint.test_join().unwrap().unwrap();
                waiting.test_join().unwrap();
                assert!(done.load(Ordering::Acquire));
            });
            fixture.wal.checkpoint().unwrap();
            // The next guard may switch its ordinary candidate or select a newer
            // complete pending base. Both must use the retained selected capture.
            drop(
                switches
                    .1
                    .test_wait_while(switches.0.lock().unwrap(), |count| *count < 2)
                    .unwrap(),
            );
            assert!(
                fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]
                    ["pending_base_selections"]
                    .as_u64()
                    .unwrap()
                    >= 1
            );
            let accounting = fixture.wal.integration_cost_snapshot().unwrap();
            assert!(
                accounting["checkpoint"]["compactor_switches"]
                    .as_u64()
                    .unwrap()
                    >= 2
            );
            let attempts = build_costs.lock().unwrap();
            assert_eq!(
                attempts.len() as u64,
                accounting["checkpoint"]["compactor_attempts"]
                    .as_u64()
                    .unwrap()
            );
            assert_eq!(attempts.len(), 5);
            for attempt in attempts.iter() {
                assert_eq!(
                    attempt.serializations, 1,
                    "one encoder traversal, including a capacity-aborted attempt: {attempt:?}"
                );
                assert_eq!(attempt.repairs, 0);
                assert_eq!(attempt.state_locks, 0);
            }
            assert_eq!(attempts.iter().filter(|attempt| attempt.authenticated_output_blocks == 0).count(), 1,
            "the one oversized pending base is discarded before admission; all other builds authenticate their output");
            drop(attempts);
            eprintln!(
                "pending_capacity_accounting mode={mode:?} counters={}",
                accounting["checkpoint"]
            );
            assert!(fixture.wal.storage_health().1.is_none());
            fixture.wal.shutdown().unwrap();
            let reopened = fixture.reopened();
            assert_eq!(
                reopened
                    .with_native_read(|state| state.history_state())
                    .unwrap()
                    .reclaim_remaining(),
                0
            );
            assert_eq!(reopened.read(0, 5).unwrap().len(), 5);
            reopened.shutdown().unwrap();
            eprintln!("pending_capacity_retirement mode={mode:?} phase=complete");
        }
    });
}

#[test]
fn native_rollover_pending_capacity_reopens_at_each_new_boundary() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let points = [
            Point::BeforeNativeCandidateDiscard,
            Point::AfterNativeCandidateDiscard,
            Point::BeforeNativePendingCapture,
            Point::BeforeNativePendingBaseBuild,
            Point::AfterNativePendingBaseBuild,
            Point::BeforeNativePendingBaseSelect,
            Point::AfterNativePendingBaseSelect,
        ];
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            for point in points {
                eprintln!("pending_boundary mode={mode:?} point={point:?} phase=start");
                let fired = Arc::new(AtomicBool::new(false));
                let control = IoControl {
                    native_rollover_bytes: Some(64 * 1024),
                    native_rollover_maximum: Some(3 * 64 * 1024),
                    hook: Arc::new({
                        let fired = Arc::clone(&fired);
                        move |actual| {
                            if actual == point && !fired.swap(true, Ordering::AcqRel) {
                                Err(io::Error::other("pending-base boundary crash injection"))
                            } else {
                                Ok(())
                            }
                        }
                    }),
                    ..IoControl::default()
                };
                let fixture = Fixture::with_persistence(Limits::default(), control, mode);
                let initial = selected(&fixture);
                fixture
                    .wal
                    .submit(append(&[capacity_entry(0, 70 * 1024)]))
                    .unwrap()
                    .wait()
                    .unwrap();
                let checkpoint_result = fixture.wal.checkpoint();
                // The final hook follows durable publication and its notification;
                // a waiter may already have observed the successful selected cut.
                if point != Point::AfterNativePendingBaseSelect {
                    assert!(checkpoint_result.is_err());
                }
                assert!(fixture.wal.shutdown().is_err());
                assert!(
                    fired.load(Ordering::Acquire),
                    "mode={mode:?} point={point:?}"
                );
                let switched = point == Point::AfterNativePendingBaseSelect;
                let current = selected(&fixture);
                assert_eq!(
                    current["native_generation"]["file_epoch"].as_u64().unwrap(),
                    initial["native_generation"]["file_epoch"].as_u64().unwrap()
                        + u64::from(switched)
                );
                let switches = Arc::new((Mutex::new(0_usize), Condvar::new()));
                let reopened = Wal::open(
                    &fixture.directory.path().join("wal"),
                    fixture.wal.binding(),
                    Limits::default(),
                    IoControl {
                        native_rollover_bytes: Some(64 * 1024),
                        hook: Arc::new({
                            let switches = Arc::clone(&switches);
                            move |point| {
                                if point == Point::AfterNativeSwitchSelection {
                                    *switches.0.lock().unwrap() += 1;
                                    switches.1.notify_all();
                                }
                                Ok(())
                            }
                        }),
                        ..IoControl::default()
                    },
                )
                .unwrap();
                let expected = usize::from(mode == SessionPersistenceMode::Durable || switched);
                assert_eq!(
                    reopened.read(0, 1).unwrap().len(),
                    expected,
                    "mode={mode:?} point={point:?}"
                );
                // An ordinary checkpoint and a second rollover after recovery must
                // work; an interrupted attempt cannot leave an owned next name.
                for round in 0..2 {
                    eprintln!("pending_boundary mode={mode:?} point={point:?} phase=later-rollover round={round}");
                    let before = selected(&fixture)["native_generation"]["file_epoch"]
                        .as_u64()
                        .unwrap();
                    let previous = *switches.0.lock().unwrap();
                    reopened.submit(Operation::Barrier).unwrap().wait().unwrap();
                    reopened.checkpoint().unwrap();
                    drop(
                        switches
                            .1
                            .test_wait_while(switches.0.lock().unwrap(), |count| *count == previous)
                            .unwrap(),
                    );
                    assert!(
                        selected(&fixture)["native_generation"]["file_epoch"]
                            .as_u64()
                            .unwrap()
                            > before
                    );
                }
                assert!(reopened.storage_health().1.is_none());
                reopened.shutdown().unwrap();
            }
        }
    });
}

#[test]
fn native_rollover_multiple_full_journals_drain_and_keep_the_owned_preparation() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        const ROWS: u64 = 6000;
        let trigger = crate::consensus::verified_snapshot::PROCESS_VERIFICATION_BYTES as u64 / 16;
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let build = Park::at(Point::AfterNativeBasisAdmission, false);
            let ordinary: Arc<Mutex<Option<Arc<Park>>>> = Arc::new(Mutex::new(None));
            let switches = Arc::new((Mutex::new(0_usize), Condvar::new()));
            let control = IoControl {
                native_rollover_bytes: Some(64 * 1024),
                hook: Arc::new({
                    let build = Arc::clone(&build);
                    let ordinary = Arc::clone(&ordinary);
                    let switches = Arc::clone(&switches);
                    move |point| {
                        if point == Point::AfterNativeSwitchSelection {
                            *switches.0.lock().unwrap() += 1;
                            switches.1.notify_all();
                        }
                        let gate = ordinary.lock().unwrap().clone();
                        if let Some(gate) = gate {
                            gate.hook(point)?;
                        }
                        build.hook(point)
                    }
                }),
                ..IoControl::default()
            };
            let fixture = Fixture::with_persistence(Limits::default(), control, mode);
            let _release = Release(Arc::clone(&build));
            build.armed.store(true, Ordering::Release);
            fixture.wal.checkpoint().unwrap();
            build.entered();
            let cut = selected(&fixture);
            let owned = fixture.directory.path().join(format!(
                "wal/basis-{:020}.preparing",
                cut["native_generation"]["file_epoch"].as_u64().unwrap() + 1
            ));
            assert!(owned.is_file());
            for wave in 0..3 {
                let gate = Park::at(Point::BeforeNativeGenerationAppend, false);
                gate.armed.store(true, Ordering::Release);
                *ordinary.lock().unwrap() = Some(Arc::clone(&gate));
                let before = fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]
                    ["ordinary_journal_captured_bytes"]
                    .as_u64()
                    .unwrap();
                std::thread::scope(|scope| {
                    let _release_ordinary = Release(Arc::clone(&gate));
                    let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
                    gate.entered();
                    let entries = (wave * ROWS..(wave + 1) * ROWS)
                        .map(|index| Entry {
                            log_id: log_id(index),
                            payload: EntryPayload::Blank,
                        })
                        .collect::<Vec<_>>();
                    // MAX_ENTRIES remains64. The ordinary capture is parked so a
                    // real >=8MiB live journal accumulates without a timing race.
                    for chunk in entries.chunks(64) {
                        fixture.wal.submit(append(chunk)).unwrap().wait().unwrap();
                    }
                    let (journal, _) = fixture
                        .wal
                        .native_request_journal_checkpoint_for_test()
                        .unwrap();
                    assert!(
                        journal as u64 >= trigger,
                        "mode={mode:?} wave={wave} journal={journal} trigger={trigger}"
                    );
                    gate.release();
                    checkpoint.test_join().unwrap().unwrap();
                });
                *ordinary.lock().unwrap() = None;
                fixture.wal.checkpoint().unwrap();
                let costs = fixture.wal.integration_cost_snapshot().unwrap();
                let bytes = costs["checkpoint"]["ordinary_journal_captured_bytes"]
                    .as_u64()
                    .unwrap()
                    - before;
                assert!(
                    bytes >= trigger,
                    "mode={mode:?} wave={wave} captured={bytes} trigger={trigger}"
                );
                assert!(
                    costs["checkpoint"]["ordinary_journal_capture_maximum"]
                        .as_u64()
                        .unwrap()
                        >= trigger
                );
                let current = selected(&fixture);
                assert_eq!(
                    current["native_generation"]["file_epoch"],
                    cut["native_generation"]["file_epoch"]
                );
                assert!(current["epoch"].as_u64().unwrap() > cut["epoch"].as_u64().unwrap());
                assert!(
                    owned.is_file(),
                    "only the live compactor owns this preparation through each reclaim"
                );
                assert!(fixture.wal.storage_health().1.is_none());
            }
            build.release();
            drop(
                switches
                    .1
                    .test_wait_while(switches.0.lock().unwrap(), |count| *count == 0)
                    .unwrap(),
            );
            fixture.wal.shutdown().unwrap();
            let reopened = fixture.reopened();
            assert_eq!(
                reopened
                    .native_log_read(0, None, Some(3 * ROWS as usize))
                    .unwrap()
                    .len(),
                3 * ROWS as usize
            );
            assert!(reopened.storage_health().1.is_none());
            reopened.shutdown().unwrap();
        }
    });
}

#[derive(Default)]
pub(super) struct Events {
    count: Mutex<usize>,
    changed: Condvar,
}
impl Events {
    pub(super) fn hook(&self, point: Point) {
        if matches!(
            point,
            Point::AfterNativeRelocationStep
                | Point::AfterNativeBackgroundRelocationPublish
                | Point::AfterNativeSwitchSelection
        ) {
            *self.count.lock().unwrap() += 1;
            self.changed.notify_all();
        }
    }
    pub(super) fn wait_until(&self, predicate: impl Fn() -> bool) {
        // Publication releases State before taking this mutex. Holding it
        // through the predicate makes a subsequent condvar wake lossless.
        let mut count = self.count.lock().unwrap();
        while !predicate() {
            count = self.changed.test_wait(count).unwrap();
        }
    }
}

#[test]
fn native_rollover_pinned_base_and_suffix_readers_survive_the_switch() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let build = Park::at(Point::AfterNativeBasisAdmission, false);
            let base_read = Park::at(Point::BeforeNativeReceiptRead, false);
            let suffix_read = Park::at(Point::BeforeNativeReceiptRead, false);
            let events = Arc::new(Events::default());
            let read_armed = Arc::new(AtomicBool::new(false));
            let ordinal = Arc::new(AtomicUsize::new(0));
            let control = IoControl {
                native_rollover_bytes: Some(SMALL_GENERATION),
                hook: Arc::new({
                    let build = Arc::clone(&build);
                    let base_read = Arc::clone(&base_read);
                    let suffix_read = Arc::clone(&suffix_read);
                    let events = Arc::clone(&events);
                    let read_armed = Arc::clone(&read_armed);
                    let ordinal = Arc::clone(&ordinal);
                    move |point| {
                        events.hook(point);
                        build.hook(point)?;
                        if point == Point::BeforeNativeReceiptRead
                            && read_armed.load(Ordering::Acquire)
                        {
                            match ordinal.fetch_add(1, Ordering::AcqRel) {
                                0 => base_read.hook(point)?,
                                1 => suffix_read.hook(point)?,
                                _ => (),
                            }
                        }
                        Ok(())
                    }
                }),
                ..IoControl::default()
            };
            let mut fixture =
                Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
            let base = fenced_transition_v2_request(0xB7, 1, "rollover-base-reader");
            fixture.parity(&[formation(), activation(1, base.clone(), timestamp(1))]);
            fixture.wal.checkpoint().unwrap();
            fixture.wal.shutdown().unwrap();
            fixture.wal = Wal::open(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                Limits::default(),
                control,
            )
            .unwrap();
            let _release_build = Release(Arc::clone(&build));
            build.arm();
            fixture.wal.checkpoint().unwrap();
            for _ in 0..4 {
                fixture
                    .wal
                    .submit(Operation::Barrier)
                    .unwrap()
                    .wait()
                    .unwrap();
                fixture.wal.checkpoint().unwrap();
            }
            build.entered();
            let old = selected(&fixture)["native_generation"]["file_epoch"]
                .as_u64()
                .unwrap();
            let suffix = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
            fixture.parity(&[fenced_transition_v2_authorized_entry(
                2,
                suffix.clone(),
                timestamp(2),
                node_id(),
                identity(),
            )]);
            fixture.wal.checkpoint().unwrap();
            events.wait_until(|| fixture.wal.native_cold_counts_for_test().unwrap() == [2, 2, 3]);
            let weak = fixture
                .wal
                .native_receipt_source_for_test(base.request_id())
                .unwrap()
                .unwrap();
            let suffix_weak = fixture
                .wal
                .native_receipt_source_for_test(suffix.request_id())
                .unwrap()
                .unwrap();
            assert!(weak.ptr_eq(&suffix_weak));
            base_read.arm();
            suffix_read.arm();
            read_armed.store(true, Ordering::Release);
            std::thread::scope(|scope| {
                let _release_build = Release(Arc::clone(&build));
                let _release_base = Release(Arc::clone(&base_read));
                let _release_suffix = Release(Arc::clone(&suffix_read));
                let first = scope.spawn(|| status(&fixture.wal, &base));
                base_read.entered();
                let second = scope.spawn(|| status(&fixture.wal, &suffix));
                suffix_read.entered();
                read_armed.store(false, Ordering::Release);
                build.release();
                events.wait_until(|| {
                    fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]["generation"]
                        ["file_epoch"]
                        .as_u64()
                        .unwrap()
                        > old
                });
                assert!(!fixture
                    .directory
                    .path()
                    .join(format!("wal/basis-{old:020}.native"))
                    .exists());
                assert!(
                    weak.upgrade().is_some(),
                    "both readers hold the authenticated unlinked source"
                );
                base_read.release();
                suffix_read.release();
                assert!(matches!(
                    first.test_join().unwrap(),
                    FencedTransitionV2Status::Recorded(_)
                ));
                assert!(matches!(
                    second.test_join().unwrap(),
                    FencedTransitionV2Status::Recorded(_)
                ));
            });
            events.wait_until(|| weak.upgrade().is_none());
            assert!(suffix_weak.upgrade().is_none());
            assert!(fixture.wal.storage_health().1.is_none());
            fixture.wal.shutdown().unwrap();
            let reopened = fixture.reopened();
            assert!(matches!(
                status(&reopened, &base),
                FencedTransitionV2Status::Recorded(_)
            ));
            assert!(matches!(
                status(&reopened, &suffix),
                FencedTransitionV2Status::Recorded(_)
            ));
            reopened.shutdown().unwrap();
        }
    });
}

#[test]
fn native_rollover_switch_replays_exact_suffix() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let build = Park::at(Point::AfterNativeBasisAdmission, false);
            let events = Arc::new(Events::default());
            let costs = Arc::new(Mutex::new(Vec::new()));
            let control = IoControl {
                native_rollover_bytes: Some(SMALL_GENERATION),
                native_rollover_costs: Some(Arc::clone(&costs)),
                hook: Arc::new({
                    let build = Arc::clone(&build);
                    let events = Arc::clone(&events);
                    move |point| {
                        events.hook(point);
                        build.hook(point)
                    }
                }),
                ..IoControl::default()
            };
            let mut fixture =
                Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
            let base = fenced_transition_v2_request(0xB8, 1, "exact-suffix-base");
            fixture.parity(&[formation(), activation(1, base.clone(), timestamp(1))]);
            fixture.wal.checkpoint().unwrap();
            fixture.wal.shutdown().unwrap();
            fixture.wal = Wal::open(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                Limits::default(),
                control,
            )
            .unwrap();
            let _release = Release(Arc::clone(&build));
            build.arm();
            for _ in 0..4 {
                fixture
                    .wal
                    .submit(Operation::Barrier)
                    .unwrap()
                    .wait()
                    .unwrap();
                fixture.wal.checkpoint().unwrap();
            }
            build.entered();
            for _ in 0..3 {
                fixture
                    .wal
                    .submit(Operation::Barrier)
                    .unwrap()
                    .wait()
                    .unwrap();
                fixture.wal.checkpoint().unwrap();
            }
            let suffix = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
            fixture.parity(&[fenced_transition_v2_authorized_entry(
                2,
                suffix.clone(),
                timestamp(2),
                node_id(),
                identity(),
            )]);
            fixture.wal.checkpoint().unwrap();
            let old = selected(&fixture);
            let old_epoch = old["epoch"].as_u64().unwrap();
            let old_file = old["native_generation"]["file_epoch"].as_u64().unwrap();
            build.release();
            events.wait_until(|| {
                fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]["generation"]
                    ["file_epoch"]
                    .as_u64()
                    .unwrap()
                    > old_file
            });
            let observed = fixture.wal.integration_cost_snapshot().unwrap();
            let receipt = &observed["checkpoint"]["last_switch"];
            let n = |name: &str| receipt[name].as_u64().unwrap();
            let block = observed["checkpoint"]["generation"]["block_bytes"]
                .as_u64()
                .unwrap();
            assert_eq!(n("old_head_epoch"), old_epoch, "{receipt}");
            assert_eq!(n("frame_count"), n("old_head_epoch") - n("old_cut_epoch"));
            assert!(n("frame_count") >= 3, "{receipt}");
            assert_eq!(
                n("raw_selected_suffix_bytes"),
                n("old_head_bytes") - n("old_cut_bytes")
            );
            assert_eq!(
                n("total_bytes"),
                n("compact_base_bytes") + n("rebased_suffix_bytes") + n("switch_frame_bytes")
            );
            for name in [
                "compact_base_bytes",
                "rebased_suffix_bytes",
                "switch_frame_bytes",
                "total_bytes",
            ] {
                assert_eq!(n(name) % block, 0, "{receipt}");
            }
            // Only Previous is rebound: four u64s, one usize, and three
            // 32-byte decimal arrays. Punctuation is unchanged. The maximum
            // type-derived width increase is below one block, so each original
            // padded frame can gain at most one block.
            let digits = u64::MAX.to_string().len().max(usize::MAX.to_string().len());
            let header_growth = 5 * (digits - 1) + 3 * 32 * 2;
            assert!((header_growth as u64) < block);
            assert!(
                n("rebased_suffix_bytes")
                    <= n("raw_selected_suffix_bytes") + n("frame_count") * block
            );
            assert!(n("compact_base_bytes") <= SMALL_GENERATION);
            assert!(
                n("total_bytes")
                    <= SMALL_GENERATION + n("rebased_suffix_bytes") + n("switch_frame_bytes")
            );
            assert_eq!(receipt["pending_base_only"], false);
            eprintln!("exact_suffix mode={mode:?} {receipt}");
            let logs = encode_json(&fixture.wal.read(0, 3).unwrap()).unwrap();
            fixture.wal.shutdown().unwrap();
            let reopened = fixture.reopened();
            for request in [&base, &suffix] {
                assert!(matches!(
                    status(&reopened, request),
                    FencedTransitionV2Status::Recorded(_)
                ));
            }
            assert_eq!(encode_json(&reopened.read(0, 3).unwrap()).unwrap(), logs);
            assert!(reopened.storage_health().1.is_none());
            reopened.shutdown().unwrap();
            let costs = costs.lock().unwrap();
            assert!(!costs.is_empty());
            for attempt in costs.iter() {
                assert_eq!(attempt.serializations, 1);
                assert_eq!(attempt.repairs, 0);
            }
        }
    });
}

#[test]
fn native_rollover_ceiling_wait_wakes_for_shutdown_and_install() {
    crate::test_process::with_completion_deadline(Duration::from_secs(240), || {
        ceiling_handoff_case()
    });
}

fn ceiling_handoff_case() {
    use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        for install in [false, true] {
            let build = Park::at(Point::AfterNativeBasisAdmission, false);
            let handoff = Park::at(
                if install {
                    Point::NativeInstallWaitStarted
                } else {
                    Point::NativeShutdownWaitStarted
                },
                false,
            );
            let events = Arc::new(CeilingEvents::default());
            let control = IoControl {
                native_rollover_bytes: Some(64 * 1024),
                native_rollover_maximum: Some(512 * 1024),
                hook: Arc::new({
                    let build = Arc::clone(&build);
                    let handoff = Arc::clone(&handoff);
                    let events = Arc::clone(&events);
                    move |point| {
                        assert_ne!(
                            point,
                            Point::NativeJournalWaitStarted,
                            "file-only wait started a journal-pressure episode"
                        );
                        events.hook(point);
                        build.hook(point)?;
                        handoff.hook(point)
                    }
                }),
                ..IoControl::default()
            };
            let limits = Limits {
                history_count: 8,
                ..Limits::default()
            };
            let mut fixture = Fixture::with_persistence(limits, IoControl::default(), mode);
            let base = fenced_transition_v2_request(0xB9, 1, "ceiling-handoff");
            fixture.parity(&[formation(), activation(1, base.clone(), timestamp(1))]);
            fixture.wal.checkpoint().unwrap();
            fixture.wal.shutdown().unwrap();
            fixture.wal = Wal::open(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                limits,
                control,
            )
            .unwrap();
            let incoming = if install {
                let producer = Fixture::new();
                let suffix = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
                producer.parity(&[
                    formation(),
                    activation(1, base.clone(), timestamp(1)),
                    fenced_transition_v2_authorized_entry(
                        2,
                        suffix,
                        timestamp(2),
                        node_id(),
                        identity(),
                    ),
                ]);
                let conn = producer.oracle.conn.blocking_lock();
                Some(IncomingSnapshot::with_identity(&conn, identity()))
            } else {
                None
            };
            let _release_build = Release(Arc::clone(&build));
            let _release_handoff = Release(Arc::clone(&handoff));
            build.arm();
            fixture.wal.checkpoint().unwrap();
            build.entered();
            // Observe the selected generation only after preparation is
            // parked. A cold-open checkpoint may retire an earlier source.
            let source = fixture
                .wal
                .native_receipt_source_for_test(base.request_id())
                .unwrap()
                .unwrap();
            let stop = AtomicBool::new(false);
            let completed = AtomicUsize::new(0);
            std::thread::scope(|scope| {
                let _release_build = Release(Arc::clone(&build));
                let _release_handoff = Release(Arc::clone(&handoff));
                // Unwinding must stop the filler before the scope joins it.
                let _stop_fill = StopFillOnDrop(&stop);
                let fill = scope.spawn(|| {
                    while !stop.load(Ordering::Acquire) {
                        fixture
                            .wal
                            .native_submit_with_backpressure_for_test(Operation::Barrier)
                            .unwrap()
                            .wait()
                            .unwrap();
                        if fixture.wal.checkpoint().is_err() {
                            // Closing interrupts an outstanding diagnostic
                            // checkpoint; its already admitted WAL callback
                            // above must still complete successfully.
                            assert!(!install && stop.load(Ordering::Acquire));
                            break;
                        }
                    }
                });
                events.guard();
                let before_waiter = fixture.wal.native_guard_admission_cut_for_test().unwrap();
                let waiter = scope.spawn(|| {
                    for _ in 0..9 {
                        match fixture
                            .wal
                            .native_submit_with_backpressure_for_test(Operation::Barrier)
                        {
                            Ok(ticket) => {
                                ticket.wait().unwrap();
                                completed.fetch_add(1, Ordering::AcqRel);
                            }
                            Err(error) => return Some(error.kind()),
                        }
                    }
                    None
                });
                events.waiter();
                if mode == SessionPersistenceMode::Async {
                    assert_eq!(
                        fixture.wal.native_guard_admission_cut_for_test().unwrap(),
                        before_waiter,
                        "waiting admission changed sequence, history, journal or generation"
                    );
                }
                assert!(completed.load(Ordering::Acquire) < 9);
                assert!(!source.upgrade().unwrap().failed_for_test());
                stop.store(true, Ordering::Release);
                handoff.arm();
                let transfer = scope.spawn(|| {
                    if let Some(incoming) = &incoming {
                        let conn = fixture.oracle.conn.blocking_lock();
                        fixture
                            .wal
                            .install_snapshot(&conn, incoming.source().unwrap())
                    } else {
                        fixture.wal.shutdown()
                    }
                });
                handoff.entered();
                // Closing interrupts a suspended pre-projection guard. An
                // unarmed install claim instead preserves the waiting cut;
                // its operations complete after the predecessor and handoff.
                let waiter = if mode == SessionPersistenceMode::Async && !install {
                    assert_eq!(
                        join_witness(waiter, "admission waiter completion", || format!(
                            "events={:?} stop={} completed={}",
                            events.state.try_lock(),
                            stop.load(Ordering::Acquire),
                            completed.load(Ordering::Acquire)
                        ))
                        .unwrap(),
                        Some(io::ErrorKind::Interrupted)
                    );
                    None
                } else {
                    if mode == SessionPersistenceMode::Async {
                        assert_eq!(
                            fixture.wal.native_guard_admission_cut_for_test().unwrap(),
                            before_waiter,
                            "an unarmed install claim changed a waiting admission"
                        );
                    }
                    Some(waiter)
                };
                assert!(!source.upgrade().unwrap().failed_for_test());
                handoff.release();
                build.release();
                join_witness(fill, "fill worker completion", || {
                    format!(
                        "events={:?} stop={} completed={}",
                        events.state.try_lock(),
                        stop.load(Ordering::Acquire),
                        completed.load(Ordering::Acquire)
                    )
                })
                .unwrap();
                join_witness(transfer, "shutdown/install completion", || {
                    format!(
                        "events={:?} stop={} completed={}",
                        events.state.try_lock(),
                        stop.load(Ordering::Acquire),
                        completed.load(Ordering::Acquire)
                    )
                })
                .unwrap()
                .unwrap();
                if let Some(waiter) = waiter {
                    let result = join_witness(waiter, "admission waiter completion", || {
                        format!(
                            "events={:?} stop={} completed={}",
                            events.state.try_lock(),
                            stop.load(Ordering::Acquire),
                            completed.load(Ordering::Acquire)
                        )
                    })
                    .unwrap();
                    if install {
                        assert_eq!(
                            result, None,
                            "waiting operations must survive an unarmed claim"
                        );
                        assert_eq!(completed.load(Ordering::Acquire), 9);
                    }
                }
            });
            assert!(
                fixture.wal.storage_health().1.is_none(),
                "{mode:?} install={install}"
            );
            if let Some(source) = source.upgrade() {
                assert!(!source.failed_for_test());
            }
            if let Some(incoming) = &incoming {
                assert_eq!(
                    fixture
                        .wal
                        .with_native_read(|state| Ok(state.applied()))
                        .unwrap()
                        .unwrap()
                        .index,
                    2
                );
                fixture.wal.shutdown().unwrap();
                let opening = crate::sqlite::consensus::wal::native::Opening::new(
                    &fixture.directory.path().join("wal"),
                    fixture.wal.binding(),
                    None,
                    limits,
                    IoControl::default(),
                )
                .unwrap();
                let raw = incoming.source().unwrap();
                let reopened = opening
                    .finish_with_install_source(Some(&raw), || Ok(()))
                    .unwrap();
                assert_eq!(
                    reopened
                        .with_native_read(|state| Ok(state.applied()))
                        .unwrap()
                        .unwrap()
                        .index,
                    2
                );
                reopened.shutdown().unwrap();
            } else {
                let reopened = fixture.reopened();
                assert!(matches!(
                    status(&reopened, &base),
                    FencedTransitionV2Status::Recorded(_)
                ));
                reopened.shutdown().unwrap();
            }
        }
    }
}

#[test]
fn native_rollover_live_capacity_install_leaves_a_retirement_progress_path() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        live_capacity_install_cases(false);
    });
}

#[test]
fn native_rollover_install_claim_before_capacity_detection_yields_for_retirement() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        live_capacity_install_cases(true);
    });
}

fn live_capacity_install_cases(install_first: bool) {
    let mut failures = Vec::new();
    use super::super::super::lifecycle::maintenance;
    use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        for shutdown in [false, true] {
            let mut fixture =
                Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
            let initial = fenced_transition_v2_request(0xDA, 1, "capacity-install-retirement");
            fixture.parity(&[formation(), activation(1, initial.clone(), timestamp(1))]);
            fixture.wal.shutdown().unwrap();
            let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
            let history = FencedTransitionV2HistoryState::new(
                Some(epoch(2)),
                Some(epoch(1)),
                Some(epoch(1)),
                1024,
                1,
                0,
                (FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - 1024) as u64,
            )
            .unwrap();
            fixture.wal = Wal::open_reclaim_fixture_for_test(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                history,
                timestamp(10),
                IoControl::default(),
            )
            .unwrap();
            let ceiling = selected(&fixture)["basis_bytes"].as_u64().unwrap();
            fixture.wal.shutdown().unwrap();
            let events = Arc::new(PendingEvents::default());
            let install = Park::at(Point::NativeInstallWaitStarted, false);
            let discard = Park::at(Point::BeforeNativeCandidateDiscard, false);
            let capacity_wait = Arc::new((Mutex::new(false), Condvar::new()));
            let claims = Arc::new((Mutex::new(0_usize), Condvar::new()));
            let control = IoControl {
                native_rollover_maximum: Some(ceiling),
                hook: Arc::new({
                    let events = Arc::clone(&events);
                    let install = Arc::clone(&install);
                    let discard = Arc::clone(&discard);
                    let capacity_wait = Arc::clone(&capacity_wait);
                    let claims = Arc::clone(&claims);
                    move |point| {
                        events.hook(point);
                        if point == Point::NativeInstallWaitStarted {
                            *claims.0.lock().unwrap() += 1;
                            claims.1.notify_all();
                        }
                        if point == Point::NativeInstallCapacityWaitStarted {
                            *capacity_wait.0.lock().unwrap() = true;
                            capacity_wait.1.notify_all();
                        }
                        discard.hook(point)?;
                        install.hook(point)
                    }
                }),
                ..IoControl::default()
            };
            let _release_discard_early = Release(Arc::clone(&discard));
            if install_first {
                discard.arm();
            }
            fixture.wal = Wal::open(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                Limits::default(),
                control,
            )
            .unwrap();
            let maintenance = maintenance(2, history, timestamp(11));
            fixture
                .wal
                .submit(append(&[maintenance.clone(), capacity_entry(3, 40 * 1024)]))
                .unwrap()
                .wait()
                .unwrap();
            fixture
                .wal
                .submit(Operation::Committed(Some(log_id(2))))
                .unwrap()
                .wait()
                .unwrap();
            // Produce the incoming cut by applying this exact already committed
            // retirement to an independently exported image. An unrelated
            // formation would regress the retained history/logical floors.
            let source_conn = fixture.wal.native_export_snapshot().unwrap();
            // This connection is a disposable independent export; the live owner
            // and its cold file remain immutable. Re-enable writes only on this
            // fixture copy to construct the exact later committed source cut.
            source_conn
                .pragma_update(None, "query_only", false)
                .unwrap();
            apply_entries_with_authority_sync(
                &source_conn,
                identity(),
                &fixture.oracle.caps,
                ConsensusAuthorityProfile::FixedImmutable,
                &fixed_members(),
                &test_member_bindings(&fixed_members()),
                FIXED_TEST_PLACEMENT_POLICY,
                vec![maintenance.clone()],
            )
            .unwrap();
            let incoming = IncomingSnapshot::with_identity(&source_conn, identity());

            let _release_install = Release(Arc::clone(&install));
            let mut escaped_red = false;
            std::thread::scope(|scope| {
                let _release_discard = Release(Arc::clone(&discard));
                if install_first {
                    discard.arm();
                }
                let _release_install = Release(Arc::clone(&install));
                let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
                if install_first {
                    discard.entered();
                } else {
                    events.wait(|state| state.0 == 1 && state.1 != 0);
                }
                let old = selected(&fixture);
                install.arm();
                let installer = scope.spawn(|| {
                    let conn = fixture.oracle.conn.blocking_lock();
                    fixture
                        .wal
                        .install_snapshot(&conn, incoming.source().unwrap())
                });
                if install_first {
                    install.entered();
                    assert_eq!(
                        fixture.wal.native_capacity_handoff_for_test().unwrap()["install_pending"],
                        true
                    );
                    discard.release();
                    events.wait(|state| state.0 == 1 && state.1 != 0);
                    install.release();
                }
                let ready = if install_first
                    && std::env::var_os("OPC_SESSION_STORE_HANG_ESCAPE").is_some()
                {
                    let (state, _) = capacity_wait
                        .1
                        .wait_timeout_while(
                            capacity_wait.0.lock().unwrap(),
                            Duration::from_secs(10),
                            |waiting| !*waiting,
                        )
                        .unwrap();
                    *state
                } else {
                    *capacity_wait
                        .1
                        .test_wait_while(capacity_wait.0.lock().unwrap(), |waiting| !*waiting)
                        .unwrap()
                };
                if !ready {
                    failures.push(format!("{mode:?}, shutdown={shutdown}: installer kept its gate after live-capacity detection"));
                    escaped_red = true;
                    let _ = fixture.wal.shutdown();
                    let _ = checkpoint.test_join().unwrap();
                    let _ = installer.test_join().unwrap();
                    return;
                }
                let before = fixture.wal.native_capacity_handoff_for_test().unwrap();
                assert_eq!(before["live_capacity"], true);
                assert_eq!(
                    before["install_pending"], false,
                    "install must leave internal retirement's existing operation gate open"
                );
                assert_eq!(before["native_operations"], 0);
                assert_eq!(selected(&fixture), old);
                assert!(fixture.wal.storage_health().1.is_none());
                if shutdown {
                    // A live-full close cannot manufacture a selected cut or an
                    // Async closed certificate. It stops cleanly, with the old
                    // CURRENT and retained Durable WAL still authoritative.
                    let error = fixture.wal.shutdown().unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                    assert!(checkpoint.test_join().unwrap().is_err());
                    assert!(installer.test_join().unwrap().is_err());
                    fixture.wal.native_capacity_handoff_for_test().unwrap();
                    assert!(fixture.wal.storage_health().1.is_none());
                } else {
                    fixture
                        .wal
                        .native_apply_committed(std::slice::from_ref(&maintenance))
                        .unwrap();
                    if !install_first {
                        install.entered();
                    } else {
                        // The single-shot park observed the original claim.
                        // Await the new ownership event after retirement instead
                        // of reusing that old latch or racing publication.
                        drop(
                            claims
                                .1
                                .test_wait_while(claims.0.lock().unwrap(), |count| *count < 2)
                                .unwrap(),
                        );
                    }
                    let recovered = fixture.wal.native_capacity_handoff_for_test().unwrap();
                    assert_eq!(recovered["live_capacity"], false);
                    if !install_first {
                        assert_eq!(recovered["install_pending"], true);
                    }
                    assert_eq!(
                        fixture
                            .wal
                            .with_native_read(|state| state.history_state())
                            .unwrap()
                            .reclaim_remaining(),
                        0
                    );
                    assert!(selected(&fixture)["basis_bytes"].as_u64().unwrap() <= ceiling);
                    eprintln!("live_capacity_install mode={mode:?} before={before} after_retirement={recovered}");
                    install.release();
                    checkpoint.test_join().unwrap().unwrap();
                    installer.test_join().unwrap().unwrap();
                    assert!(fixture.wal.storage_health().1.is_none());
                }
            });
            if escaped_red {
                continue;
            }
            if shutdown {
                let reopened = fixture.reopened();
                assert_eq!(
                    reopened
                        .with_native_read(|state| Ok(state.applied()))
                        .unwrap()
                        .unwrap()
                        .index,
                    if mode == SessionPersistenceMode::Durable {
                        2
                    } else {
                        1
                    }
                );
                assert!(!reopened.take_closed_async_restart());
                assert!(reopened.storage_health().1.is_none());
                reopened.shutdown().unwrap();
            } else {
                assert!(selected(&fixture)["basis_bytes"].as_u64().unwrap() <= ceiling);
                fixture.wal.shutdown().unwrap();
                let opening = crate::sqlite::consensus::wal::native::Opening::new(
                    &fixture.directory.path().join("wal"),
                    fixture.wal.binding(),
                    None,
                    Limits::default(),
                    IoControl::default(),
                )
                .unwrap();
                let raw = incoming.source().unwrap();
                let reopened = opening
                    .finish_with_install_source(Some(&raw), || Ok(()))
                    .unwrap();
                assert_eq!(
                    reopened
                        .with_native_read(|state| Ok(state.applied()))
                        .unwrap()
                        .unwrap()
                        .index,
                    2
                );
                assert!(reopened.storage_health().1.is_none());
                reopened.shutdown().unwrap();
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}
