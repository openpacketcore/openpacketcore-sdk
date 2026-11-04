//! Hook-ordered rollover regressions. Completion uses events, never durations.

use crate::test_process::witness::{CondvarExt, JoinExt, ReceiverExt};

use super::*;

pub(super) fn child_ran_one_exact_test(output: &std::process::Output, name: &str) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    output.status.success()
        && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
        && stdout.contains(&format!("test {name} ... ok"))
}

#[test]
fn native_rollover_child_filter_rejects_a_successful_empty_selection() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        // The dash makes this impossible as a Rust test identifier. libtest still
        // exits successfully, so status alone cannot establish proof execution.
        let missing = "sqlite::consensus::tests::native::basis::rollover::missing-proof";
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", missing, "--test-threads=1"])
            .test_output_with_deadline(std::time::Duration::from_secs(1800))
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok. 0 passed;"));
        assert!(!child_ran_one_exact_test(&output, missing));
    });
}

fn completion<T>(receiver: &mpsc::Receiver<T>) -> Option<T> {
    if std::env::var_os("OPC_SESSION_STORE_HANG_ESCAPE").is_some() {
        receiver.recv_timeout(Duration::from_secs(10)).ok()
    } else {
        Some(receiver.test_recv().unwrap())
    }
}

#[test]
fn native_rollover_durable_groups_complete_with_caught_up_compactor_and_active_checkpoint() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let build = Park::at(Point::AfterNativeBasisAdmission, false);
        let worker = Park::at(Point::BeforeNativeGenerationAppend, false);
        let caught_up = Arc::new((Mutex::new(false), Condvar::new()));
        let control = IoControl {
            native_rollover_bytes: Some(65536),
            hook: Arc::new({
                let build = Arc::clone(&build);
                let worker = Arc::clone(&worker);
                let caught_up = Arc::clone(&caught_up);
                move |point| {
                    build.hook(point)?;
                    if std::thread::current().name() == Some("session-native-basis") {
                        worker.hook(point)?;
                    }
                    if point == Point::NativeCompactorCaughtUp {
                        *caught_up.0.lock().unwrap() = true;
                        caught_up.1.notify_all();
                    }
                    Ok(())
                }
            }),
            ..IoControl::default()
        };
        let fixture =
            Fixture::with_persistence(Limits::default(), control, SessionPersistenceMode::Durable);
        let mut completed_before_release = false;
        std::thread::scope(|scope| {
            let _release_build = Release(Arc::clone(&build));
            let _release_worker = Release(Arc::clone(&worker));
            build.arm();
            fixture.wal.checkpoint().unwrap();
            build.entered();
            worker.arm();
            let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
            worker.entered();
            build.release();
            drop(
                caught_up
                    .1
                    .test_wait_while(caught_up.0.lock().unwrap(), |ready| !*ready)
                    .unwrap(),
            );
            assert!(fixture.wal.native_basis_waiters_for_test().unwrap().2);
            let before = fixture.wal.integration_cost_snapshot().unwrap()["requests"]
                .as_u64()
                .unwrap();
            let requests = (0..4)
                .map(|_| fixture.wal.submit(Operation::Barrier).unwrap())
                .collect::<Vec<_>>();
            let (done, received) = mpsc::channel();
            let callbacks = scope.spawn(move || {
                let values = requests
                    .into_iter()
                    .map(|request| request.wait().unwrap())
                    .collect::<Vec<_>>();
                done.send(values).unwrap();
            });
            let result = completion(&received);
            if let Some(values) = result {
                assert_eq!(values, (before + 1..=before + 4).collect::<Vec<_>>());
                completed_before_release = true;
            }
            worker.release();
            callbacks.test_join().unwrap();
            checkpoint.test_join().unwrap().unwrap();
            assert!(fixture.wal.storage_health().1.is_none());
        });
        fixture.wal.shutdown().unwrap();
        assert!(
            completed_before_release,
            "caught-up optional work starved queued Durable callbacks during the active checkpoint"
        );
    });
}

#[test]
fn native_rollover_guarded_resource_wait_rechecks_relief_before_the_file_guard_clears() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        const CASE: &str =
            "native_rollover_guarded_resource_wait_rechecks_relief_before_the_file_guard_clears";
        const CHILD: &str = "OPC_SESSION_STORE_RESOURCE_WAIT_CHILD";
        if std::env::var(CHILD).as_deref() != Ok(CASE) {
            let name =
                format!("sqlite::consensus::tests::native::basis::rollover::concurrency::{CASE}");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture", "--test-threads=1"])
                .env(CHILD, CASE)
                .test_output_with_deadline(std::time::Duration::from_secs(1800))
                .unwrap();
            assert!(
                child_ran_one_exact_test(&output, &name),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use crate::consensus::verified_snapshot::{VerificationMemory, PROCESS_VERIFICATION_BYTES};
        let mut failures = Vec::new();
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let waiting = Arc::new((Mutex::new(false), Condvar::new()));
            let control = IoControl {
                hook: Arc::new({
                    let waiting = Arc::clone(&waiting);
                    move |point| {
                        if point == Point::NativeFileGuardWaitStarted {
                            *waiting.0.lock().unwrap() = true;
                            waiting.1.notify_all();
                        }
                        Ok(())
                    }
                }),
                native_pressure_clock: Some(Arc::new(|_| {
                    panic!("a file-only resource wait must not start or age the journal-pressure timer")
                })),
                ..IoControl::default()
            };
            let fixture = Fixture::with_persistence(Limits::default(), control, mode);
            fixture.wal.checkpoint().unwrap();
            fixture.wal.native_live_capacity_guard_for_test(true);
            let cut = fixture.wal.native_guard_admission_cut_for_test().unwrap();
            let pressure = VerificationMemory::reserve(
                PROCESS_VERIFICATION_BYTES - 15 * 1024 * 1024 - VerificationMemory::used_bytes(),
            )
            .unwrap();
            std::thread::scope(|scope| {
                let (done, received) = mpsc::channel();
                let wal = &fixture.wal;
                let waiter = scope.spawn(move || {
                    done.send(
                        wal.native_retry_journal_reservation_for_test(256 * 1024)
                            .is_ok(),
                    )
                    .unwrap();
                });
                drop(
                    waiting
                        .1
                        .test_wait_while(waiting.0.lock().unwrap(), |started| !*started)
                        .unwrap(),
                );
                drop(pressure);
                fixture.wal.native_pending_wake_for_test();
                let result = completion(&received);
                if result.is_none() {
                    failures.push(format!("{mode:?}: resource relief notified, but the waiter still depends on the file guard"));
                    fixture.wal.native_live_capacity_guard_for_test(false); // RED cleanup only.
                    assert!(received.test_recv().unwrap());
                } else {
                    assert_eq!(result, Some(true));
                    assert_eq!(
                        fixture.wal.native_capacity_handoff_for_test().unwrap()["live_capacity"],
                        true
                    );
                    assert_eq!(
                        fixture.wal.native_guard_admission_cut_for_test().unwrap(),
                        cut
                    );
                }
                waiter.test_join().unwrap();
            });
            fixture.wal.native_live_capacity_guard_for_test(false);
            assert!(fixture.wal.storage_health().1.is_none());
            fixture.wal.shutdown().unwrap();
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    });
}

#[test]
fn native_rollover_relocation_worker_panic_notifies_and_fails_closed() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let mut failures = Vec::new();
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let (entered, observed) = mpsc::channel();
            let panicked = Arc::new(AtomicBool::new(false));
            let armed = Arc::new(AtomicBool::new(false));
            let worker_armed = Arc::clone(&armed);
            let control = IoControl {
                native_rollover_bytes: Some(65536),
                hook: Arc::new(move |point| {
                    if point == Point::AfterNativeRelocationStep
                        && std::thread::current().name() == Some("session-native-relocate")
                        && worker_armed.load(Ordering::Acquire)
                        && !panicked.swap(true, Ordering::AcqRel)
                    {
                        entered.send(()).unwrap();
                        panic!("injected detached relocation panic");
                    }
                    Ok(())
                }),
                ..IoControl::default()
            };
            let fixture = Fixture::with_persistence(Limits::default(), control, mode);
            let request = fenced_transition_v2_request(0xDE, 1, "relocation-panic");
            fixture.parity(&[formation(), activation(1, request, timestamp(1))]);
            armed.store(true, Ordering::Release);
            fixture.wal.checkpoint().unwrap();
            observed.test_recv().unwrap();
            std::thread::scope(|scope| {
                let (done, received) = mpsc::channel();
                let wal = &fixture.wal;
                let waiter = scope.spawn(move || {
                    done.send(wal.native_wait_for_background_failure_for_test())
                        .unwrap();
                });
                let result = completion(&received);
                if result.is_none() {
                    failures.push(format!(
                        "{mode:?}: relocation panic never published a terminal wake"
                    ));
                    let _ = fixture.wal.shutdown(); // RED cleanup joins the failed worker.
                    let _ = received.test_recv().unwrap();
                } else {
                    assert_eq!(result, Some(true));
                    assert!(fixture.wal.storage_health().1.is_some());
                    assert!(fixture.wal.shutdown().is_err());
                }
                waiter.test_join().unwrap();
            });
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    });
}

fn capacity_fixture(
    mode: SessionPersistenceMode,
    control: impl FnOnce(u64) -> IoControl,
) -> Fixture {
    let mut fixture = Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
    let initial = fenced_transition_v2_request(0xDC, 1, "async-capacity-error");
    fixture.parity(&[formation(), activation(1, initial, timestamp(1))]);
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
    fixture.wal = Wal::open(
        &fixture.directory.path().join("wal"),
        fixture.wal.binding(),
        Limits::default(),
        control(ceiling),
    )
    .unwrap();
    fixture
}

#[test]
fn native_rollover_async_capacity_error_clears_guard_and_install_fails_fast() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
        let failed = Arc::new((Mutex::new(false), Condvar::new()));
        let control = {
            let failed = Arc::clone(&failed);
            move |ceiling| IoControl {
                native_rollover_maximum: Some(ceiling),
                hook: Arc::new(move |point| {
                    if point == Point::BeforeNativeAsyncCapacityRequest {
                        return Err(io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            "injected capacity request reservation failure",
                        ));
                    }
                    if point == Point::NativeAsyncPersistenceFailed {
                        *failed.0.lock().unwrap() = true;
                        failed.1.notify_all();
                    }
                    Ok(())
                }),
                ..IoControl::default()
            }
        };
        let fixture = capacity_fixture(SessionPersistenceMode::Async, control);
        fixture
            .wal
            .submit(append(&[capacity_entry(2, 40 * 1024)]))
            .unwrap()
            .wait()
            .unwrap();
        let source_conn = fixture.wal.native_export_snapshot().unwrap();
        let incoming = IncomingSnapshot::with_identity(&source_conn, identity());
        let mut completed_before_rescue = false;
        std::thread::scope(|scope| {
            let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
            drop(
                failed
                    .1
                    .test_wait_while(failed.0.lock().unwrap(), |ready| !*ready)
                    .unwrap(),
            );
            let flags = fixture.wal.native_capacity_handoff_for_test().unwrap();
            let (done, received) = mpsc::channel();
            let wal = &fixture.wal;
            let conn = &fixture.oracle.conn;
            let installer = scope.spawn(move || {
                let conn = conn.blocking_lock();
                done.send(
                    wal.install_snapshot(&conn, incoming.source().unwrap())
                        .is_err(),
                )
                .unwrap();
            });
            let result = completion(&received);
            if let Some(failed_fast) = result {
                assert!(failed_fast);
                assert_eq!(flags["live_capacity"], false);
                assert_eq!(
                    fixture.wal.native_capacity_handoff_for_test().unwrap()["install_pending"],
                    false
                );
                assert!(
                    fixture.wal.storage_health().1.is_none(),
                    "resident authority survives the injected ordinary persistence error"
                );
                completed_before_rescue = true;
            } else {
                fixture.wal.native_live_capacity_guard_for_test(false); // RED cleanup only.
                assert!(received.test_recv().unwrap());
            }
            installer.test_join().unwrap();
            assert!(checkpoint.test_join().unwrap().is_err());
        });
        let _ = fixture.wal.shutdown();
        assert!(
            completed_before_rescue,
            "Async capacity error left live-capacity latched and subsequent install asleep"
        );
    });
}

// Each RED child may exit at its generous hang escape without joining the
// original stuck owner. GREEN children receive only ordered completion events.
fn isolated_modes(case: &str) -> Option<SessionPersistenceMode> {
    const CHILD: &str = "OPC_SESSION_STORE_ROLLOVER_CHILD";
    if let Ok(value) = std::env::var(CHILD) {
        return Some(match value.as_str() {
            "durable" => SessionPersistenceMode::Durable,
            "async" => SessionPersistenceMode::Async,
            _ => panic!("unknown ordered child mode"),
        });
    }
    let cases: &[&str] =
        if case == "native_rollover_shutdown_and_install_cancel_inside_real_io_adapters" {
            &["00", "01", "10", "11"]
        } else if case
            == "native_rollover_installers_during_capacity_restart_preserve_ownership_and_close"
        {
            &["continue", "shutdown"]
        } else {
            &["all"]
        };
    let mut failures = Vec::new();
    for mode in ["durable", "async"] {
        for io in cases {
            let name =
                format!("sqlite::consensus::tests::native::basis::rollover::concurrency::{case}");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture", "--test-threads=1"])
                .env(CHILD, mode)
                .env("OPC_SESSION_STORE_ROLLOVER_CASE", io)
                .test_output_with_deadline(std::time::Duration::from_secs(1800))
                .unwrap();
            if !child_ran_one_exact_test(&output, &name) {
                failures.push(format!(
                    "{mode}/{io}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    None
}

#[test]
fn native_rollover_rebase_abort_inside_guard_wait_restarts_and_completes_once() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let Some(mode) = isolated_modes(
            "native_rollover_rebase_abort_inside_guard_wait_restarts_and_completes_once",
        ) else {
            return;
        };
        let build = Park::at(Point::AfterNativeBasisAdmission, false);
        let events = Arc::new((Mutex::new((false, false, false)), Condvar::new()));
        let control = IoControl {
            native_rollover_bytes: Some(65536),
            native_rollover_maximum: Some(512 * 1024),
            native_rebase_capacity_abort: Some(Arc::new(AtomicBool::new(true))),
            hook: Arc::new({
                let build = Arc::clone(&build);
                let events = Arc::clone(&events);
                move |point| {
                    {
                        let mut state = events.0.lock().unwrap();
                        match point {
                            Point::NativeCompactorWaitTake => state.0 = true,
                            Point::NativeCandidateCapacityRestart => state.1 = true,
                            Point::AfterNativeSwitchSelection => state.2 = true,
                            _ => (),
                        }
                        events.1.notify_all();
                    }
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
        build.arm();
        fixture.wal.checkpoint().unwrap();
        build.entered();
        let old = selected(&fixture);
        let completed = Arc::new(Mutex::new(Vec::new()));
        std::thread::scope(|scope| {
            let completed_fill = Arc::clone(&completed);
            let (done, received) = mpsc::channel();
            let wal = &fixture.wal;
            let fill = scope.spawn(move || {
                for _ in 0..16 {
                    let sequence = wal
                        .native_submit_with_backpressure_for_test(Operation::Barrier)
                        .unwrap()
                        .wait()
                        .unwrap();
                    completed_fill.lock().unwrap().push(sequence);
                    wal.checkpoint().unwrap();
                }
                done.send(()).unwrap();
            });
            drop(
                events
                    .1
                    .test_wait_while(events.0.lock().unwrap(), |state| !state.0)
                    .unwrap(),
            );
            // The real Async writer (Durable checkpoint worker in that mode) is
            // now inside wait_take, with the selected suffix queued for rebase.
            assert_eq!(
                selected(&fixture)["native_generation"]["file_epoch"],
                old["native_generation"]["file_epoch"]
            );
            let completed_waiter = Arc::clone(&completed);
            let wal = &fixture.wal;
            let waiter = scope.spawn(move || {
                for _ in 0..9 {
                    let sequence = wal
                        .native_submit_with_backpressure_for_test(Operation::Barrier)
                        .unwrap()
                        .wait()
                        .unwrap();
                    completed_waiter.lock().unwrap().push(sequence);
                }
            });
            build.release();
            if completion(&received).is_none() {
                eprintln!(
                    "{mode:?}: rebase capacity abort left the actual guard owner inside wait_take"
                );
                std::process::exit(101); // pre-fix hang escape only
            }
            fill.test_join().unwrap();
            waiter.test_join().unwrap();
        });
        let state = *events.0.lock().unwrap();
        assert!(state.0 && state.1 && state.2);
        let mut sequences = completed.lock().unwrap().clone();
        assert_eq!(sequences.len(), 25);
        sequences.sort_unstable();
        sequences.dedup();
        assert_eq!(
            sequences.len(),
            25,
            "each accepted operation completes exactly once"
        );
        let now = selected(&fixture);
        assert!(
            now["native_generation"]["file_epoch"].as_u64().unwrap()
                > old["native_generation"]["file_epoch"].as_u64().unwrap()
        );
        assert!(fixture.wal.storage_health().1.is_none());
        fixture.wal.shutdown().unwrap();
        fixture.reopened().shutdown().unwrap();
    });
}

#[test]
fn native_rollover_live_capacity_at_journal_stop_drains_and_retires_once() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        use super::super::super::lifecycle::maintenance;
        use crate::consensus::verified_snapshot::{VerificationMemory, PROCESS_VERIFICATION_BYTES};
        let Some(mode) =
            isolated_modes("native_rollover_live_capacity_at_journal_stop_drains_and_retires_once")
        else {
            return;
        };
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
        let maintenance = maintenance(2, history, timestamp(11));
        let mut fixture = capacity_fixture(mode, |_| IoControl::default());
        fixture
            .wal
            .submit(append(std::slice::from_ref(&maintenance)))
            .unwrap()
            .wait()
            .unwrap();
        // Retain ordinary unapplied rows in the admitted old base. The later
        // truncate/reappend restores exactly these values, leaving the same full
        // native context while accumulating an actual pressure journal.
        let rows = (3..=18002)
            .map(|index| Entry {
                log_id: log_id(index),
                payload: EntryPayload::Blank,
            })
            .collect::<Vec<_>>();
        for batch in rows.chunks(64) {
            fixture.wal.submit(append(batch)).unwrap().wait().unwrap();
        }
        fixture.wal.shutdown().unwrap();
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
        let start = Park::at(Point::BeforeGroup, false);
        if mode == SessionPersistenceMode::Async {
            start.arm();
        }
        let capture = Park::at(Point::BeforeNativeGenerationAppend, false);
        let pending = Park::at(Point::NativePendingCapacityWait, false);
        let resource = Arc::new((Mutex::new(false), Condvar::new()));
        let attempts = Arc::new(AtomicUsize::new(0));
        let control = IoControl {
            native_rollover_maximum: Some(ceiling),
            hook: Arc::new({
                let start = Arc::clone(&start);
                let capture = Arc::clone(&capture);
                let pending = Arc::clone(&pending);
                let resource = Arc::clone(&resource);
                let attempts = Arc::clone(&attempts);
                move |point| {
                    start.hook(point)?;
                    capture.hook(point)?;
                    pending.hook(point)?;
                    if point == Point::NativeFileGuardWaitStarted {
                        *resource.0.lock().unwrap() = true;
                        resource.1.notify_all();
                    }
                    if point == Point::BeforeNativePendingBaseBuild {
                        attempts.fetch_add(1, Ordering::AcqRel);
                    }
                    Ok(())
                }
            }),
            native_pressure_clock: Some(Arc::new(|_| {
                panic!("file-guarded recovery entered a timed pressure episode")
            })),
            ..IoControl::default()
        };
        fixture.wal = Wal::open(
            &fixture.directory.path().join("wal"),
            fixture.wal.binding(),
            Limits::default(),
            control,
        )
        .unwrap();
        let _release_start = Release(Arc::clone(&start));
        if mode == SessionPersistenceMode::Async {
            start.entered();
        }
        let _release_capture = Release(Arc::clone(&capture));
        let _release_pending = Release(Arc::clone(&pending));
        capture.arm();
        pending.arm();
        let payload = capacity_entry(18003, 40 * 1024);
        fixture
            .wal
            .submit(append(std::slice::from_ref(&payload)))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(2))))
            .unwrap()
            .wait()
            .unwrap();
        start.release();
        std::thread::scope(|scope| {
            let wal = &fixture.wal;
            let checkpoint = scope.spawn(move || wal.checkpoint());
            capture.entered();
            fixture
                .wal
                .submit(Operation::Truncate(log_id(3)))
                .unwrap()
                .wait()
                .unwrap();
            for batch in rows.chunks(64) {
                fixture.wal.submit(append(batch)).unwrap().wait().unwrap();
            }
            fixture
                .wal
                .submit(append(std::slice::from_ref(&payload)))
                .unwrap()
                .wait()
                .unwrap();
            let journal = fixture.wal.native_journal_owners_for_test().unwrap();
            eprintln!(
                "live_capacity_journal_stop mode={mode:?} journal={journal:?} ceiling={ceiling}"
            );
            assert!(
                journal[0] + journal[2] >= 24 * 1024 * 1024,
                "fixture must reach the real stop line"
            );
            capture.release();
            pending.entered();
            assert_eq!(
                fixture.wal.native_capacity_handoff_for_test().unwrap()["live_capacity"],
                true
            );
            let pressure = if mode == SessionPersistenceMode::Async {
                Some(
                    VerificationMemory::reserve(
                        PROCESS_VERIFICATION_BYTES
                            - 15 * 1024 * 1024
                            - VerificationMemory::used_bytes(),
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            let (done, received) = mpsc::channel();
            let wal = &fixture.wal;
            let retirement = scope.spawn(move || {
                let result = wal.native_apply_committed(std::slice::from_ref(&maintenance));
                done.send(result).unwrap();
            });
            drop(
                resource
                    .1
                    .test_wait_while(resource.0.lock().unwrap(), |started| !*started)
                    .unwrap(),
            );
            let old = selected(&fixture);
            pending.release();
            let Some(result) = completion(&received) else {
                eprintln!("{mode:?}: live capacity and the actual journal stop line wait on their own recovery application");
                std::process::exit(101); // pre-fix hang escape only
            };
            result.unwrap();
            retirement.test_join().unwrap();
            checkpoint.test_join().unwrap().unwrap();
            drop(pressure);
            assert_eq!(
                attempts.load(Ordering::Acquire),
                2,
                "one full attempt, an unchanged-context journal drain, and one retirement attempt"
            );
            assert!(
                selected(&fixture)["native_generation"]["file_epoch"]
                    .as_u64()
                    .unwrap()
                    > old["native_generation"]["file_epoch"].as_u64().unwrap()
            );
        });
        assert_eq!(
            fixture
                .wal
                .with_native_read(|state| Ok(state.applied()))
                .unwrap()
                .unwrap()
                .index,
            2
        );
        assert!(fixture.wal.storage_health().1.is_none());
        let rows = encode_json(&fixture.wal.read(0, 18004).unwrap()).unwrap();
        fixture.wal.shutdown().unwrap();
        let reopened = fixture.reopened();
        assert_eq!(
            encode_json(&reopened.read(0, 18004).unwrap()).unwrap(),
            rows
        );
        assert_eq!(
            reopened
                .with_native_read(|state| Ok(state.applied()))
                .unwrap()
                .unwrap()
                .index,
            2
        );
        reopened.shutdown().unwrap();
    });
}

#[test]
fn native_rollover_shutdown_and_install_cancel_inside_real_io_adapters() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
        let Some(mode) =
            isolated_modes("native_rollover_shutdown_and_install_cancel_inside_real_io_adapters")
        else {
            return;
        };
        for compare in [false, true] {
            for install in [false, true] {
                let selected_case = format!("{}{}", u8::from(compare), u8::from(install));
                if std::env::var("OPC_SESSION_STORE_ROLLOVER_CASE").as_deref()
                    != Ok(selected_case.as_str())
                {
                    continue;
                }

                let adapter = Park::at(
                    if compare {
                        Point::NativeCompactorExtentRead
                    } else {
                        Point::NativeCompactorBaseBlock
                    },
                    false,
                );
                let build = Park::at(Point::AfterNativeBasisAdmission, false);
                let cancelled = Arc::new((Mutex::new(false), Condvar::new()));
                let control = IoControl {
                    native_rollover_bytes: Some(65536),
                    hook: Arc::new({
                        let adapter = Arc::clone(&adapter);
                        let build = Arc::clone(&build);
                        let cancelled = Arc::clone(&cancelled);
                        move |point| {
                            adapter.hook(point)?;
                            build.hook(point)?;
                            if point == Point::NativeCompactorCancelled {
                                *cancelled.0.lock().unwrap() = true;
                                cancelled.1.notify_all();
                            }
                            Ok(())
                        }
                    }),
                    ..IoControl::default()
                };
                let mut fixture =
                    Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
                let initial = fenced_transition_v2_request(0xE1, 1, "adapter-cancel-owner");
                fixture.parity(&[formation(), activation(1, initial.clone(), timestamp(1))]);
                fixture
                    .wal
                    .submit(append(&[capacity_entry(2, 80 * 1024)]))
                    .unwrap()
                    .wait()
                    .unwrap();
                fixture.wal.checkpoint().unwrap();
                fixture.wal.shutdown().unwrap();
                fixture.wal = Wal::open(
                    &fixture.directory.path().join("wal"),
                    fixture.wal.binding(),
                    Limits::default(),
                    control,
                )
                .unwrap();
                let old = fixture
                    .wal
                    .native_receipt_source_for_test(initial.request_id())
                    .unwrap()
                    .unwrap()
                    .upgrade()
                    .unwrap();
                let incoming = if install {
                    let producer = Fixture::new();
                    let extra = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
                    producer.parity(&[
                        formation(),
                        activation(1, initial.clone(), timestamp(1)),
                        fenced_transition_v2_authorized_entry(
                            2,
                            extra,
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
                let _release_adapter = Release(Arc::clone(&adapter));
                let _release_build = Release(Arc::clone(&build));
                adapter.arm();
                if compare {
                    build.arm();
                }
                fixture.wal.checkpoint().unwrap();
                if compare {
                    build.entered();
                    fixture
                        .wal
                        .submit(Operation::Barrier)
                        .unwrap()
                        .wait()
                        .unwrap();
                    fixture.wal.checkpoint().unwrap();
                    build.release();
                }
                adapter.entered();
                std::thread::scope(|scope| {
                    let (done, received) = mpsc::channel();
                    let wal = &fixture.wal;
                    let oracle = &fixture.oracle;
                    let incoming = &incoming;
                    let transfer = scope.spawn(move || {
                        let result = if let Some(incoming) = incoming {
                            let conn = oracle.conn.blocking_lock();
                            wal.install_snapshot(&conn, incoming.source().unwrap())
                        } else {
                            wal.shutdown()
                        };
                        done.send(result).unwrap();
                    });
                    drop(
                        cancelled
                            .1
                            .test_wait_while(cancelled.0.lock().unwrap(), |done| !*done)
                            .unwrap(),
                    );
                    assert!(!old.failed_for_test());
                    adapter.release();
                    let Some(result) = completion(&received) else {
                        eprintln!("{mode:?}, compare={compare}, install={install}: cancellation retried inside a real I/O adapter");
                        std::process::exit(101); // pre-fix hang escape only
                    };
                    result.unwrap();
                    transfer.test_join().unwrap();
                });
                assert!(!old.failed_for_test());
                assert!(fixture.wal.storage_health().1.is_none());
                if install {
                    fixture.wal.shutdown().unwrap();
                }
                // Both handoffs reaped the disposable owner before releasing LOCK.
                assert!(!std::fs::read_dir(fixture.directory.path().join("wal"))
                    .unwrap()
                    .any(|entry| entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".preparing")));
                if let Some(incoming) = &incoming {
                    let raw = incoming.source().unwrap();
                    let opening = crate::sqlite::consensus::wal::native::Opening::new(
                        &fixture.directory.path().join("wal"),
                        fixture.wal.binding(),
                        None,
                        Limits::default(),
                        IoControl::default(),
                    )
                    .unwrap();
                    opening
                        .finish_with_install_source(Some(&raw), || Ok(()))
                        .unwrap()
                        .shutdown()
                        .unwrap();
                } else {
                    fixture.reopened().shutdown().unwrap();
                }
            }
        }
    });
}

#[test]
fn native_rollover_compactor_queue_poison_notifies_even_with_owner_parked() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let Some(mode) = isolated_modes(
            "native_rollover_compactor_queue_poison_notifies_even_with_owner_parked",
        ) else {
            return;
        };
        let owner = Park::at(Point::NativeCompactorOwnerTake, false);
        let queue = Park::at(Point::NativeCompactorQueueWait, false);
        let control = IoControl {
            native_rollover_bytes: Some(65536),
            hook: Arc::new({
                let owner = Arc::clone(&owner);
                let queue = Arc::clone(&queue);
                move |point| {
                    owner.hook(point)?;
                    queue.hook(point)?;
                    if point == Point::NativeCompactorQueueWait {
                        panic!("injected compactor Work poison");
                    }
                    Ok(())
                }
            }),
            ..IoControl::default()
        };
        let fixture = Fixture::with_persistence(Limits::default(), control, mode);
        let _release_owner = Release(Arc::clone(&owner));
        let _release_queue = Release(Arc::clone(&queue));
        owner.arm();
        queue.arm();
        fixture.wal.checkpoint().unwrap();
        owner.entered();
        queue.entered();
        std::thread::scope(|scope| {
            let (done, received) = mpsc::channel();
            let wal = &fixture.wal;
            let health = scope.spawn(move || {
                done.send(wal.native_wait_for_background_failure_for_test())
                    .unwrap()
            });
            queue.release();
            let Some(failed) = completion(&received) else {
                eprintln!(
                "{mode:?}: poisoned Work prevented terminal publication while the owner was parked"
            );
                std::process::exit(101); // pre-fix hang escape only
            };
            assert!(failed);
            owner.release();
            health.test_join().unwrap();
        });
        assert!(fixture.wal.shutdown().is_err());
    });
}

#[test]
fn native_rollover_pending_pressure_drains_without_token_advance_or_serialization() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let Some(mode) = isolated_modes(
            "native_rollover_pending_pressure_drains_without_token_advance_or_serialization",
        ) else {
            return;
        };
        let idle = Arc::new((Mutex::new(false), Condvar::new()));
        let (drained, observed) = mpsc::channel();
        let fixture = capacity_fixture(mode, {
            let idle = Arc::clone(&idle);
            move |ceiling| IoControl {
                native_rollover_maximum: Some(ceiling),
                hook: Arc::new(move |point| {
                    if point == Point::NativePendingIdle {
                        *idle.0.lock().unwrap() = true;
                        idle.1.notify_all();
                    }
                    if point == Point::NativePendingJournalDrained {
                        drained.send(()).unwrap();
                    }
                    Ok(())
                }),
                ..IoControl::default()
            }
        });
        fixture
            .wal
            .submit(append(&[capacity_entry(2, 40 * 1024)]))
            .unwrap()
            .wait()
            .unwrap();
        std::thread::scope(|scope| {
            let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
            drop(
                idle.1
                    .test_wait_while(idle.0.lock().unwrap(), |idle| !*idle)
                    .unwrap(),
            );
            let before = fixture.wal.native_guard_admission_cut_for_test().unwrap();
            let attempts = fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]
                ["pending_base_attempts"]
                .clone();
            assert_eq!(
                fixture.wal.native_capacity_handoff_for_test().unwrap()["live_capacity"],
                true
            );
            // Exercise the real pending owner with its exact observed cut. The
            // journal-stop proof supplies actual memory pressure; this empty-journal
            // control isolates the missing-token wake and the no-build condition.
            fixture.wal.native_request_pending_journal_drain_for_test();
            if completion(&observed).is_none() {
                eprintln!("{mode:?}: pending pressure drain requires a token advance");
                std::process::exit(101); // pre-fix hang escape only
            }
            assert_eq!(
                fixture.wal.native_guard_admission_cut_for_test().unwrap(),
                before
            );
            assert_eq!(
                fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]
                    ["pending_base_attempts"],
                attempts
            );
            assert_eq!(
                fixture.wal.native_capacity_handoff_for_test().unwrap()["pending_base"],
                true
            );
            assert_eq!(
                fixture.wal.shutdown().unwrap_err().kind(),
                io::ErrorKind::Interrupted
            );
            assert!(checkpoint.test_join().unwrap().is_err());
        });
        assert!(fixture.wal.storage_health().1.is_none());
    });
}

#[test]
fn native_rollover_pending_pressure_flushes_an_already_admitted_durable_cut() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let Some(mode) = isolated_modes(
            "native_rollover_pending_pressure_flushes_an_already_admitted_durable_cut",
        ) else {
            return;
        };
        if mode != SessionPersistenceMode::Durable {
            return;
        } // Async has no WAL group queue.
        let capture = Park::at(Point::BeforeNativeGenerationAppend, false);
        let discard = Park::at(Point::BeforeNativeCandidateDiscard, false);
        let group = Park::at(Point::BeforeGroup, false);
        let pending = Park::at(Point::AfterNativePendingWorkerStart, false);
        let fixture = capacity_fixture(mode, {
            let capture = Arc::clone(&capture);
            let discard = Arc::clone(&discard);
            let group = Arc::clone(&group);
            let pending = Arc::clone(&pending);
            move |ceiling| IoControl {
                native_rollover_maximum: Some(ceiling),
                hook: Arc::new(move |point| {
                    capture.hook(point)?;
                    discard.hook(point)?;
                    group.hook(point)?;
                    pending.hook(point)
                }),
                ..IoControl::default()
            }
        });
        let _release_capture = Release(Arc::clone(&capture));
        let _release_discard = Release(Arc::clone(&discard));
        let _release_group = Release(Arc::clone(&group));
        let _release_pending = Release(Arc::clone(&pending));
        capture.arm();
        discard.arm();
        pending.arm();
        fixture
            .wal
            .submit(append(&[capacity_entry(2, 40 * 1024)]))
            .unwrap()
            .wait()
            .unwrap();
        std::thread::scope(|scope| {
            let _release_capture = Release(Arc::clone(&capture));
            let _release_discard = Release(Arc::clone(&discard));
            let _release_group = Release(Arc::clone(&group));
            let _release_pending = Release(Arc::clone(&pending));
            let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
            capture.entered();
            capture.release();
            // Let the writer start the compactor before parking it. Capacity has
            // been checked, but the live guard has not yet closed new admission.
            discard.entered();
            assert_eq!(
                fixture.wal.native_capacity_handoff_for_test().unwrap()["live_capacity"],
                false
            );
            group.arm();
            let kick = fixture.wal.submit(Operation::Barrier).unwrap();
            group.entered();
            let queued_before_retained = fixture.wal.native_capacity_handoff_for_test().unwrap()
                ["queued"]
                .as_u64()
                .unwrap();
            let expected = fixture.wal.native_guard_admission_cut_for_test().unwrap().0 + 1;
            let retained = fixture.wal.submit(Operation::Barrier).unwrap();
            discard.release();
            fixture.wal.native_wait_for_checkpoint_ready_for_test(false);
            group.release();
            pending.entered();
            fixture.wal.native_wait_for_checkpoint_ready_for_test(true);
            assert_eq!(
                fixture.wal.native_capacity_handoff_for_test().unwrap()["queued"],
                queued_before_retained + 1
            );
            fixture.wal.native_request_pending_journal_drain_for_test();
            let (done, received) = mpsc::channel();
            let callback = scope.spawn(move || done.send(retained.wait()).unwrap());
            pending.release();
            let Some(result) = completion(&received) else {
                eprintln!(
                "Durable: pending journal pressure preempted flushing its already admitted WAL cut"
            );
                std::process::exit(101); // new-defect RED child escape only
            };
            assert_eq!(result.unwrap(), expected);
            assert_eq!(kick.wait().unwrap(), expected - 1);
            callback.test_join().unwrap();
            assert_eq!(
                fixture.wal.native_capacity_handoff_for_test().unwrap()["live_capacity"],
                true
            );
            assert!(fixture.wal.storage_health().1.is_none());
            assert_eq!(
                fixture.wal.shutdown().unwrap_err().kind(),
                io::ErrorKind::Interrupted
            );
            assert!(checkpoint.test_join().unwrap().is_err());
        });
        assert!(fixture.wal.storage_health().1.is_none());
    });
}

#[test]
fn native_rollover_installers_during_capacity_restart_preserve_ownership_and_close() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
        let Some(mode) = isolated_modes(
            "native_rollover_installers_during_capacity_restart_preserve_ownership_and_close",
        ) else {
            return;
        };
        let shutdown =
            std::env::var("OPC_SESSION_STORE_ROLLOVER_CASE").as_deref() == Ok("shutdown");
        let build = Park::at(Point::AfterNativeBasisAdmission, false);
        let restart = Park::at(Point::NativeCandidateCapacityRestart, false);
        let claim = Park::at(Point::NativeInstallWaitStarted, false);
        let events = Arc::new((Mutex::new([false; 3]), Condvar::new())); // guard owner, second installer, Closing
        let claims = Arc::new(AtomicUsize::new(0));
        let control = IoControl {
            native_rollover_bytes: Some(65536),
            native_rollover_maximum: Some(512 * 1024),
            native_rebase_capacity_abort: Some(Arc::new(AtomicBool::new(true))),
            hook: Arc::new({
                let build = Arc::clone(&build);
                let restart = Arc::clone(&restart);
                let claim = Arc::clone(&claim);
                let events = Arc::clone(&events);
                let claims = Arc::clone(&claims);
                move |point| {
                    {
                        let mut state = events.0.lock().unwrap();
                        match point {
                            Point::NativeCompactorWaitTake => state[0] = true,
                            Point::NativeInstallOwnershipWaitStarted => state[1] = true,
                            Point::NativeShutdownWaitStarted => state[2] = true,
                            _ => (),
                        }
                        events.1.notify_all();
                    }
                    if point == Point::NativeInstallWaitStarted {
                        claims.fetch_add(1, Ordering::AcqRel);
                    }
                    build.hook(point)?;
                    restart.hook(point)?;
                    claim.hook(point)
                }
            }),
            ..IoControl::default()
        };
        let limits = Limits {
            history_count: 8,
            ..Limits::default()
        };
        let mut fixture = Fixture::with_persistence(limits, IoControl::default(), mode);
        let initial = fenced_transition_v2_request(0xE2, 1, "restart-install-owner");
        fixture.parity(&[formation(), activation(1, initial.clone(), timestamp(1))]);
        fixture.wal.checkpoint().unwrap();
        fixture.wal.shutdown().unwrap();
        fixture.wal = Wal::open(
            &fixture.directory.path().join("wal"),
            fixture.wal.binding(),
            limits,
            control,
        )
        .unwrap();
        let old = fixture
            .wal
            .native_receipt_source_for_test(initial.request_id())
            .unwrap()
            .unwrap()
            .upgrade()
            .unwrap();
        let producer = Fixture::new();
        let extra = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
        producer.parity(&[
            formation(),
            activation(1, initial, timestamp(1)),
            fenced_transition_v2_authorized_entry(2, extra, timestamp(2), node_id(), identity()),
        ]);
        let incoming = {
            let conn = producer.oracle.conn.blocking_lock();
            IncomingSnapshot::with_identity(&conn, identity())
        };
        let newer = sdk741_component_request(Sdk741Payload::Create, 3, 0, None);
        producer.parity(&[fenced_transition_v2_authorized_entry(
            3,
            newer,
            timestamp(3),
            node_id(),
            identity(),
        )]);
        let incoming_second = {
            let conn = producer.oracle.conn.blocking_lock();
            IncomingSnapshot::with_identity(&conn, identity())
        };
        let _release_build = Release(Arc::clone(&build));
        let _release_restart = Release(Arc::clone(&restart));
        let _release_claim = Release(Arc::clone(&claim));
        build.arm();
        restart.arm();
        claim.arm();
        fixture.wal.checkpoint().unwrap();
        build.entered();
        let stop = AtomicBool::new(false);
        let completed = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            let _release_build = Release(Arc::clone(&build));
            let _release_restart = Release(Arc::clone(&restart));
            let _release_claim = Release(Arc::clone(&claim));
            let fill = scope.spawn(|| {
                for _ in 0..16 {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let sequence = fixture
                        .wal
                        .native_submit_with_backpressure_for_test(Operation::Barrier)
                        .unwrap()
                        .wait()
                        .unwrap();
                    completed.lock().unwrap().push(sequence);
                    if let Err(error) = fixture.wal.checkpoint() {
                        assert!(
                            shutdown && stop.load(Ordering::Acquire),
                            "unexpected checkpoint error: {error}"
                        );
                        break;
                    }
                }
            });
            drop(
                events
                    .1
                    .test_wait_while(events.0.lock().unwrap(), |state| !state[0])
                    .unwrap(),
            );
            build.release();
            restart.entered();
            stop.store(true, Ordering::Release);
            assert!(
                fixture.wal.native_capacity_handoff_for_test().unwrap()["checkpoint_active"]
                    .as_bool()
                    .unwrap()
            );
            let (done, received) = mpsc::channel();
            let wal = &fixture.wal;
            let incoming = &incoming;
            let first_done = done.clone();
            let first = scope.spawn(move || {
                // Native installation does not use the legacy SQL connection.
                // Separate connections let both installers reach the real gate.
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                first_done
                    .send((1, wal.install_snapshot(&conn, incoming.source().unwrap())))
                    .unwrap();
            });
            claim.entered();
            assert_eq!(claims.load(Ordering::Acquire), 1);
            assert_eq!(
                fixture.wal.native_capacity_handoff_for_test().unwrap()["install_pending"],
                true
            );
            let second_source = &incoming_second;
            let second = scope.spawn(move || {
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                done.send((
                    2,
                    wal.install_snapshot(&conn, second_source.source().unwrap()),
                ))
                .unwrap();
            });
            drop(
                events
                    .1
                    .test_wait_while(events.0.lock().unwrap(), |state| !state[1])
                    .unwrap(),
            );
            assert_eq!(
                claims.load(Ordering::Acquire),
                1,
                "second installer claimed another owner's gate"
            );
            let closing = if shutdown {
                Some(scope.spawn(|| fixture.wal.shutdown()))
            } else {
                None
            };
            if shutdown {
                drop(
                    events
                        .1
                        .test_wait_while(events.0.lock().unwrap(), |state| !state[2])
                        .unwrap(),
                );
            }
            claim.release();
            if !shutdown {
                restart.release();
            }
            let mut outcomes = Vec::new();
            for _ in 0..2 {
                let Some(outcome) = completion(&received) else {
                    eprintln!("{mode:?}, shutdown={shutdown}: installers did not leave pending-restart ownership waits");
                    std::process::exit(101); // pre-fix hang escape only
                };
                outcomes.push(outcome);
            }
            outcomes.sort_by_key(|(owner, _)| *owner);
            assert_eq!(
                outcomes.iter().map(|(owner, _)| *owner).collect::<Vec<_>>(),
                vec![1, 2]
            );
            if shutdown {
                assert!(outcomes.iter().all(|(_, result)| result.is_err()));
                if fixture.wal.storage_health().1.is_some() {
                    eprintln!(
                        "{mode:?}: shutdown fenced an unarmed installer during a pending restart"
                    );
                    std::process::exit(101); // pre-fix hang escape only
                }
                assert!(!old.failed_for_test());
                restart.release();
            } else {
                for (_, result) in outcomes {
                    result.unwrap();
                }
                assert_eq!(claims.load(Ordering::Acquire), 2);
                assert_eq!(
                    fixture
                        .wal
                        .with_native_read(|state| Ok(state.applied()))
                        .unwrap()
                        .unwrap()
                        .index,
                    3
                );
            }
            first.test_join().unwrap();
            second.test_join().unwrap();
            fill.test_join().unwrap();
            if let Some(closing) = closing {
                closing.test_join().unwrap().unwrap();
            }
        });
        let mut sequences = completed.lock().unwrap().clone();
        let count = sequences.len();
        assert!(count > 0);
        sequences.sort_unstable();
        sequences.dedup();
        assert_eq!(sequences.len(), count);
        assert!(!old.failed_for_test());
        assert!(fixture.wal.storage_health().1.is_none());
        if shutdown {
            fixture.reopened().shutdown().unwrap();
        } else {
            fixture.wal.shutdown().unwrap();
            let opening = crate::sqlite::consensus::wal::native::Opening::new(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                None,
                limits,
                IoControl::default(),
            )
            .unwrap();
            let raw = incoming_second.source().unwrap();
            let reopened = opening
                .finish_with_install_source(Some(&raw), || Ok(()))
                .unwrap();
            assert_eq!(
                reopened
                    .with_native_read(|state| Ok(state.applied()))
                    .unwrap()
                    .unwrap()
                    .index,
                3
            );
            reopened.shutdown().unwrap();
        }
    });
}

#[test]
fn native_rollover_guarded_resource_wait_obeys_the_shutdown_stop() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        use crate::consensus::verified_snapshot::{VerificationMemory, PROCESS_VERIFICATION_BYTES};
        let Some(mode) =
            isolated_modes("native_rollover_guarded_resource_wait_obeys_the_shutdown_stop")
        else {
            return;
        };
        let waiting = Arc::new((Mutex::new(false), Condvar::new()));
        let control = IoControl {
            hook: Arc::new({
                let waiting = Arc::clone(&waiting);
                move |point| {
                    if point == Point::NativeFileGuardWaitStarted {
                        *waiting.0.lock().unwrap() = true;
                        waiting.1.notify_all();
                    }
                    Ok(())
                }
            }),
            native_pressure_clock: Some(Arc::new(|_| {
                panic!("guarded shutdown entered a journal-pressure timer")
            })),
            ..IoControl::default()
        };
        let fixture = Fixture::with_persistence(Limits::default(), control, mode);
        fixture.wal.checkpoint().unwrap();
        fixture.wal.native_live_capacity_guard_for_test(true);
        let cut = fixture.wal.native_guard_admission_cut_for_test().unwrap();
        let pressure = VerificationMemory::reserve(
            PROCESS_VERIFICATION_BYTES - 15 * 1024 * 1024 - VerificationMemory::used_bytes(),
        )
        .unwrap();
        std::thread::scope(|scope| {
            let (done, received) = mpsc::channel();
            let wal = &fixture.wal;
            let waiter = scope.spawn(move || {
                done.send(wal.native_retry_journal_reservation_for_test(256 * 1024))
                    .unwrap()
            });
            drop(
                waiting
                    .1
                    .test_wait_while(waiting.0.lock().unwrap(), |waiting| !*waiting)
                    .unwrap(),
            );
            // This is the production shutdown cancellation before the state-machine
            // joins, not a test mutation of Status or the file guard.
            fixture.wal.stop_retirement_waits();
            let Some(result) = completion(&received) else {
                eprintln!("{mode:?}: resource wait ignored the shutdown retirement stop");
                std::process::exit(101); // RED escape only
            };
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            waiter.test_join().unwrap();
        });
        assert_eq!(
            fixture.wal.native_guard_admission_cut_for_test().unwrap(),
            cut
        );
        assert!(fixture.wal.storage_health().1.is_none());
        drop(pressure);
        fixture.wal.native_live_capacity_guard_for_test(false);
        fixture.wal.shutdown().unwrap();
    });
}
