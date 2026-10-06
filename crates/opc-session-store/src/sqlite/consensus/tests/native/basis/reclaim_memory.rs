use super::super::lifecycle::maintenance;
use super::*;

fn isolated(case: &str) -> bool {
    const CHILD: &str = "OPC_RECLAIM_WAIT_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(case) {
        return false;
    }
    let name = format!("sqlite::consensus::tests::native::basis::reclaim_memory::{case}");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--test-threads=1", "--nocapture"])
        .env(CHILD, case)
        .test_output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for line in String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| {
            line.starts_with("native_reclaim_recovery_maximum")
                || line.starts_with("native_reclaim_void_")
        })
    {
        eprintln!("{line}");
    }
    true
}

fn waiting_fixture() -> (Fixture, Entry<SessionRaftTypeConfig>) {
    waiting_fixture_with(IoControl::default())
}

fn retiring_fixture(control: IoControl, remaining: usize) -> Fixture {
    let mut fixture = Fixture::new();
    let initial = fenced_transition_v2_request(0xD7, 1, "reclaim-wait");
    fixture.parity(&[formation(), activation(1, initial, timestamp(1))]);
    fixture.wal.shutdown().unwrap();
    let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
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
        control,
    )
    .unwrap();
    fixture
}

fn waiting_fixture_with(control: IoControl) -> (Fixture, Entry<SessionRaftTypeConfig>) {
    let fixture = retiring_fixture(control, 1024);
    let history = fixture
        .wal
        .with_native_read(|state| state.history_state())
        .unwrap();
    let entry = maintenance(2, history, timestamp(11));
    fixture.append_commit(std::slice::from_ref(&entry));
    fixture.wal.checkpoint().unwrap();
    (fixture, entry)
}

fn void_entry(
    index: u64,
    request: &FencedTransitionV2Request,
    now: Timestamp,
    activate: bool,
) -> Entry<SessionRaftTypeConfig> {
    let mut entry =
        fenced_transition_v2_authorized_entry(index, request.clone(), now, node_id(), identity());
    let EntryPayload::Normal(value) = &mut entry.payload else {
        unreachable!()
    };
    value.request_id = SessionConsensusRequestId::from_bytes(
        crate::fenced_transition::fenced_transition_v2_void_outer_request_id(request.request_id()),
    );
    let SessionMutationIntent::Authorized { mutation, .. } = &mut value.intent else {
        unreachable!()
    };
    **mutation = if activate {
        SessionMutationIntent::ActivateVoidFencedTransitionV2 {
            request: Box::new(request.clone()),
            scope_identity: identity(),
            voter_set_digest: fenced_transition_voter_set_digest(identity(), &fixed_members()),
            profile_digest: crate::FencedTransitionV2Profile::V2WithVoid.digest(),
        }
    } else {
        SessionMutationIntent::VoidFencedTransitionV2(Box::new(request.clone()))
    };
    entry
}

fn void_fixture() -> (Fixture, FencedTransitionV2Request, SessionConsensusResponse) {
    let fixture = Fixture::with_fenced_profile(
        Limits::default(),
        IoControl::default(),
        crate::SessionPersistenceMode::Durable,
        crate::FencedTransitionV2Profile::V2WithVoid,
    );
    let request = fenced_transition_v2_request(0xC1, 1, "void-reclaim");
    let response = fixture
        .parity(&[formation(), void_entry(1, &request, timestamp(1), true)])
        .responses
        .remove(1);
    assert_eq!(response.result, Err(StoreError::FencedTransitionVoided));
    (fixture, request, response)
}

// These children exit without dropping the live fixture or asking its WAL to
// checkpoint. The parent owns TMPDIR, so it retains and then cleans the crashed
// process's files while reopening them with a fresh process-local memory budget.
fn crashed_void_fixture<T: serde::de::DeserializeOwned>(
    case: &str,
    prepare: impl FnOnce(&std::path::Path),
) -> (tempfile::TempDir, T) {
    const CHILD: &str = "OPC_RECLAIM_VOID_CRASH_CHILD";
    const REPORT: &str = "OPC_RECLAIM_VOID_CRASH_REPORT";
    if std::env::var(CHILD).as_deref() == Ok(case) {
        prepare(std::path::Path::new(&std::env::var(REPORT).unwrap()));
        panic!("crash fixture must exit with its live WAL still owned");
    }
    let root = tempfile::tempdir().unwrap();
    let report = root.path().join("crash.json");
    let name = format!("sqlite::consensus::tests::native::basis::reclaim_memory::{case}");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--test-threads=1", "--nocapture"])
        .env(CHILD, case)
        .env(REPORT, &report)
        .env("TMPDIR", root.path())
        .test_output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(73),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    (root, report)
}

fn exit_with_void_report(path: &std::path::Path, report: impl serde::Serialize) -> ! {
    std::fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
    std::process::exit(73);
}

fn void_crash_binding(basis: [u8; 32]) -> crate::sqlite::consensus::wal::Binding {
    crate::sqlite::consensus::wal::Binding {
        identity: identity(),
        generation: [0xE1; 32],
        basis,
        native: true,
        persistence: crate::SessionPersistenceMode::Durable,
        async_closed_format: false,
        async_recovery_format: false,
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VoidReplayCrashReport {
    wal_path: std::path::PathBuf,
    basis: [u8; 32],
    voided: FencedTransitionV2Request,
    original: FencedTransitionV2Request,
    requests: Vec<FencedTransitionV2Request>,
    original_status: FencedTransitionV2Status,
    expected_digest: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VoidRetirementCrashReport {
    wal_path: std::path::PathBuf,
    basis: [u8; 32],
    voided: FencedTransitionV2Request,
}

#[test]
fn native_reclaim_memory_void_checkpoint_and_replay_preserve_first_binding() {
    if isolated("native_reclaim_memory_void_checkpoint_and_replay_preserve_first_binding") {
        return;
    }
    let (_root, report): (_, VoidReplayCrashReport) = crashed_void_fixture(
        "native_reclaim_memory_void_checkpoint_and_replay_preserve_first_binding",
        |report_path| {
            let (fixture, voided, void_response) = void_fixture();
            let original = fenced_transition_v2_request(0xC2, 1, "original-wins");
            let results = fixture
                .parity(&[
                    fenced_transition_v2_authorized_entry(
                        2,
                        voided.clone(),
                        timestamp(2),
                        node_id(),
                        identity(),
                    ),
                    fenced_transition_v2_authorized_entry(
                        3,
                        original.clone(),
                        timestamp(3),
                        node_id(),
                        identity(),
                    ),
                    void_entry(4, &original, timestamp(4), false),
                ])
                .responses;
            assert_eq!(results[0], void_response);
            assert_eq!(results[1], results[2]);
            let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &results[1].result else {
                panic!("the earlier original retains its real effect")
            };
            let mut straight = fixture
                .wal
                .with_native_read(|state| Ok(state.clone()))
                .unwrap();
            fixture.wal.checkpoint().unwrap();
            assert_eq!(
                status(&fixture.wal, &voided),
                FencedTransitionV2Status::Recorded(Box::new(Err(
                    StoreError::FencedTransitionVoided
                )))
            );
            let original_status = status(&fixture.wal, &original);
            // More than one eight-entry replay cohort, with live void receipts and
            // owned log bodies rather than already expired fixture tombstones.
            let requests: Vec<_> = (10..50)
                .map(|nonce| {
                    FencedTransitionV2Request::new(
                        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
                        crate::FencedTransitionV2CallerNonce::from_bytes([nonce; 16]),
                        crate::FencedTransitionLease::renew(
                            outcome.lease().clone(),
                            Duration::from_secs(60),
                        )
                        .unwrap(),
                        crate::FencedTransitionMutation::delete(outcome.committed_generation()),
                    )
                    .unwrap()
                })
                .collect();
            let mut entries: Vec<_> = requests
                .iter()
                .enumerate()
                .map(|(offset, request)| {
                    void_entry(5 + offset as u64, request, timestamp(5), false)
                })
                .collect();
            entries.push(fenced_transition_v2_authorized_entry(
                45,
                voided.clone(),
                timestamp(6),
                node_id(),
                identity(),
            ));
            entries.push(void_entry(46, &original, timestamp(6), false));
            let expected = straight.apply(&entries).unwrap();
            assert!(expected.responses[..requests.len()]
                .iter()
                .all(|response| { response.result == Err(StoreError::FencedTransitionVoided) }));
            let expected_digest = straight.business_digest_for_test().unwrap();
            drop(straight);
            fixture.append_commit(&entries); // Durable but unapplied when the child exits.
            exit_with_void_report(
                report_path,
                VoidReplayCrashReport {
                    wal_path: fixture.directory.path().join("wal"),
                    basis: fixture.wal.binding().basis,
                    voided,
                    original,
                    requests,
                    original_status,
                    expected_digest,
                },
            );
        },
    );
    let VoidReplayCrashReport {
        wal_path,
        basis,
        voided,
        original,
        requests,
        original_status,
        expected_digest,
    } = report;
    let binding = void_crash_binding(basis);
    let (reopened, [journal, _, peak]) =
        Wal::open_replay_observation_for_test(&wal_path, binding).unwrap();
    assert!(journal > 0);
    assert!(peak < 64 * 1024 * 1024, "void replay peak={peak}");
    assert_eq!(
        reopened
            .with_native_read(|state| state.business_digest_for_test())
            .unwrap(),
        expected_digest,
    );
    for request in requests.iter().chain(std::iter::once(&voided)) {
        assert_eq!(
            status(&reopened, request),
            FencedTransitionV2Status::Recorded(Box::new(Err(StoreError::FencedTransitionVoided)))
        );
    }
    assert_eq!(status(&reopened, &original), original_status);
    reopened.checkpoint().unwrap();
    reopened.shutdown().unwrap();
    let selected = Wal::open(&wal_path, binding, Limits::default(), IoControl::default()).unwrap();
    assert_eq!(
        selected
            .with_native_read(|state| state.business_digest_for_test())
            .unwrap(),
        expected_digest
    );
    assert_eq!(status(&selected, &original), original_status);
    selected.shutdown().unwrap();
    eprintln!(
        "native_reclaim_void_replay entries={} journal_bytes={journal} peak_bytes={peak}",
        requests.len() + 2
    );
}

#[test]
fn native_reclaim_memory_void_pressure_fence_replays_and_retires_epoch() {
    if isolated("native_reclaim_memory_void_pressure_fence_replays_and_retires_epoch") {
        return;
    }
    use crate::consensus::verified_snapshot::VerificationMemory;
    let (_root, report): (_, VoidRetirementCrashReport) = crashed_void_fixture(
        "native_reclaim_memory_void_pressure_fence_replays_and_retires_epoch",
        |report_path| {
            let (mut fixture, voided, response) = void_fixture();
            fixture.wal.shutdown().unwrap();
            let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
            let max = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES;
            let history = FencedTransitionV2HistoryState::new(
                Some(epoch(2)),
                Some(epoch(1)),
                Some(epoch(1)),
                max,
                1,
                0,
                0,
            )
            .unwrap();
            let now = "2026-08-12T00:00:00Z".parse().unwrap();
            fixture.wal = Wal::open_reclaim_fixture_with_receipts_for_test(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                history,
                now,
                IoControl::default(),
                Some(response),
                true,
            )
            .unwrap();
            let entry = maintenance(2, history, now);
            fixture.append_commit(std::slice::from_ref(&entry));
            fixture.wal.checkpoint().unwrap();
            let pressure = VerificationMemory::reserve(80 * 1024 * 1024).unwrap();
            let started = Instant::now();
            let (tx, rx) = mpsc::channel();
            std::thread::scope(|scope| {
                let apply = scope.spawn(|| {
                    tx.send(fixture.wal.native_apply_committed(&[entry]).map(|_| ()))
                        .unwrap()
                });
                let result = rx.recv_timeout(Duration::from_secs(12));
                drop(pressure);
                apply.join().unwrap();
                assert_eq!(
                    result
                        .expect("void-profile pressure wait is bounded")
                        .unwrap_err()
                        .to_string(),
                    "native retirement admission timed out"
                );
                assert!(started.elapsed() < Duration::from_secs(12));
            });
            assert!(fixture
                .wal
                .with_native_read(|state| state.history_state())
                .is_err());
            assert!(fixture.wal.shutdown().is_err());
            exit_with_void_report(
                report_path,
                VoidRetirementCrashReport {
                    wal_path: fixture.directory.path().join("wal"),
                    basis: fixture.wal.binding().basis,
                    voided,
                },
            );
        },
    );
    let VoidRetirementCrashReport {
        wal_path,
        basis,
        voided,
    } = report;
    let binding = void_crash_binding(basis);
    let max = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES;
    let now = "2026-08-12T00:00:00Z".parse().unwrap();
    let (reopened, [journal, _, recovery_peak]) =
        Wal::open_replay_observation_for_test(&wal_path, binding).unwrap();
    assert!(journal >= 1024 * 72 + 64 * 1024);
    assert!(recovery_peak < 64 * 1024 * 1024);
    let history = reopened
        .with_native_read(|state| state.history_state())
        .unwrap();
    assert_eq!(history.reclaim_remaining(), max - 1024);
    let entries: Vec<_> = (0..127)
        .map(|offset| {
            let mut entry = maintenance(3 + offset, history, now);
            let EntryPayload::Normal(value) = &mut entry.payload else {
                unreachable!()
            };
            let SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation,
                ..
            } = &mut value.intent
            else {
                unreachable!()
            };
            *expected_generation += offset;
            entry
        })
        .collect();
    for chunk in entries.chunks(64) {
        reopened.submit(append(chunk)).unwrap().wait().unwrap();
    }
    reopened
        .submit(Operation::Committed(
            entries.last().map(|entry| entry.log_id),
        ))
        .unwrap()
        .wait()
        .unwrap();
    VerificationMemory::begin_retirement_phase_for_test();
    let result = reopened.native_apply_committed(&entries).unwrap();
    assert!(result
        .responses
        .iter()
        .all(|response| response.result.is_ok()));
    let retirement_peak = VerificationMemory::retirement_peak_for_test();
    assert!(
        retirement_peak < 64 * 1024 * 1024,
        "void retirement peak={retirement_peak}"
    );
    let history = reopened
        .with_native_read(|state| state.history_state())
        .unwrap();
    assert_eq!(history.reclaim_remaining(), 0);
    assert_eq!(history.reclaimed_entries(), max as u64);
    assert_eq!(
        status(&reopened, &voided),
        FencedTransitionV2Status::Retired
    );
    let late = fenced_transition_v2_authorized_entry(130, voided, now, node_id(), identity());
    reopened
        .submit(append(std::slice::from_ref(&late)))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .submit(Operation::Committed(Some(late.log_id)))
        .unwrap()
        .wait()
        .unwrap();
    let late_result = reopened.native_apply_committed(&[late]).unwrap();
    assert!(late_result.notifications.is_empty());
    assert_eq!(
        late_result.responses[0].result,
        Err(StoreError::FencedTransitionHistoryEpochRetired)
    );
    reopened.checkpoint().unwrap();
    reopened.shutdown().unwrap();
    let selected = Wal::open(&wal_path, binding, Limits::default(), IoControl::default()).unwrap();
    assert_eq!(
        selected
            .with_native_read(|state| state.history_state())
            .unwrap(),
        history
    );
    selected.shutdown().unwrap();
    eprintln!("native_reclaim_void_retirement rows={max} recovery_peak_bytes={recovery_peak} retirement_peak_bytes={retirement_peak}");
}

#[test]
fn native_reclaim_memory_committed_wait_releases_permit_and_proceeds() {
    if isolated("native_reclaim_memory_committed_wait_releases_permit_and_proceeds") {
        return;
    }
    let (fixture, entry) = waiting_fixture();
    let pressure =
        crate::consensus::verified_snapshot::VerificationMemory::reserve(80 * 1024 * 1024).unwrap();
    let before = selected(&fixture);
    assert!(!fixture.wal.native_retirement_ready().unwrap());
    std::thread::scope(|scope| {
        let apply = scope.spawn(|| fixture.wal.native_apply_committed(&[entry]));
        until(|| fixture.wal.retirement_wait_state_for_test().unwrap().0 > 0);
        let (_, permits, requested) = fixture.wal.retirement_wait_state_for_test().unwrap();
        assert_eq!(permits, 0);
        assert!(
            !requested,
            "an empty journal cannot relieve external pressure"
        );
        assert_eq!(selected(&fixture), before);
        assert!(!apply.is_finished());
        drop(pressure);
        assert!(apply.join().unwrap().unwrap().responses[0].result.is_ok());
    });
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_committed_wait_fails_closed_with_bounded_reason() {
    if isolated("native_reclaim_memory_committed_wait_fails_closed_with_bounded_reason") {
        return;
    }
    let (fixture, entry) = waiting_fixture();
    let pressure =
        crate::consensus::verified_snapshot::VerificationMemory::reserve(80 * 1024 * 1024).unwrap();
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            tx.send(fixture.wal.native_apply_committed(&[entry]).map(|_| ()))
                .unwrap();
        });
        let result = rx.recv_timeout(Duration::from_secs(12));
        drop(pressure); // Also lets a regressed unbounded implementation join.
        let error = result
            .expect("committed pressure has a finite deadline")
            .unwrap_err();
        assert_eq!(error.to_string(), "native retirement admission timed out");
        assert!(started.elapsed() < Duration::from_secs(12));
        assert!(fixture
            .wal
            .with_native_read(|state| state.history_state())
            .is_err());
    });
    assert!(fixture.wal.shutdown().is_err());
}

#[test]
fn native_reclaim_memory_shutdown_interrupts_committed_wait() {
    if isolated("native_reclaim_memory_shutdown_interrupts_committed_wait") {
        return;
    }
    let armed = Arc::new(AtomicBool::new(false));
    let gate = Gate::new(Point::BeforeGroup, 1);
    let (fixture, entry) = waiting_fixture_with(IoControl {
        hook: Arc::new({
            let armed = Arc::clone(&armed);
            let gate = Arc::clone(&gate);
            move |point| {
                if armed.load(Ordering::Acquire) {
                    gate.hook(point)
                } else {
                    Ok(())
                }
            }
        }),
        ..IoControl::default()
    });
    let pressure =
        crate::consensus::verified_snapshot::VerificationMemory::reserve(80 * 1024 * 1024).unwrap();
    std::thread::scope(|scope| {
        let apply = scope.spawn(|| fixture.wal.native_apply_committed(&[entry]));
        until(|| fixture.wal.retirement_wait_state_for_test().unwrap().0 > 0);
        armed.store(true, Ordering::Release);
        fixture
            .wal
            .submit(Operation::Barrier)
            .unwrap()
            .wait()
            .unwrap();
        gate.entered();
        let queued = fixture.wal.submit(Operation::Barrier).unwrap();
        let started = Instant::now();
        fixture.wal.stop_retirement_waits();
        let error = apply.join().unwrap().err().unwrap();
        gate.release();
        assert_eq!(error.to_string(), "native retirement admission stopped");
        assert!(started.elapsed() < Duration::from_secs(1));
        queued
            .wait()
            .expect("shutdown cancellation preserves accepted WAL work");
    });
    drop(pressure);
    fixture
        .wal
        .shutdown()
        .expect("a cancelled wait does not fence shutdown");
}

#[test]
fn native_reclaim_memory_progress_extends_committed_wait() {
    if isolated("native_reclaim_memory_progress_extends_committed_wait") {
        return;
    }
    let fixture = retiring_fixture(IoControl::default(), 2048);
    let history = fixture
        .wal
        .with_native_read(|state| state.history_state())
        .unwrap();
    let first = maintenance(2, history, timestamp(11));
    fixture.append_commit(std::slice::from_ref(&first));
    fixture.wal.native_apply_committed(&[first]).unwrap();
    let history = fixture
        .wal
        .with_native_read(|state| state.history_state())
        .unwrap();
    let entry = maintenance(3, history, timestamp(11));
    fixture.append_commit(std::slice::from_ref(&entry));
    assert!(fixture.wal.retirement_journal_bytes_for_test() > 128 * 1024);
    let pressure =
        crate::consensus::verified_snapshot::VerificationMemory::reserve(80 * 1024 * 1024).unwrap();
    std::thread::scope(|scope| {
        let apply = scope.spawn(|| fixture.wal.native_apply_committed(&[entry]));
        until(|| fixture.wal.retirement_wait_state_for_test().unwrap().0 > 0);
        std::thread::sleep(Duration::from_secs(6));
        // This capture really shrinks the live journal, even though unrelated
        // owners still keep the process above admission after it completes.
        fixture.wal.checkpoint().unwrap();
        assert_eq!(fixture.wal.retirement_journal_bytes_for_test(), 0);
        std::thread::sleep(Duration::from_secs(5));
        let still_waiting = !apply.is_finished();
        drop(pressure);
        let result = apply.join().unwrap();
        assert!(
            still_waiting,
            "progressing storage must outlive the original ten-second deadline"
        );
        assert!(result.unwrap().responses[0].result.is_ok());
    });
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_unhelpful_checkpoints_do_not_extend_wait() {
    if isolated("native_reclaim_memory_unhelpful_checkpoints_do_not_extend_wait") {
        return;
    }
    let armed = Arc::new(AtomicBool::new(false));
    let gate = Gate::new(Point::BeforeNativeGenerationAppend, 1);
    let (fixture, entry) = waiting_fixture_with(IoControl {
        hook: Arc::new({
            let armed = Arc::clone(&armed);
            let gate = Arc::clone(&gate);
            move |point| {
                if armed.load(Ordering::Acquire) {
                    gate.hook(point)
                } else {
                    Ok(())
                }
            }
        }),
        ..IoControl::default()
    });
    use crate::consensus::verified_snapshot::VerificationMemory;
    let pressure = VerificationMemory::reserve(80 * 1024 * 1024).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let apply = scope.spawn(|| {
            tx.send(fixture.wal.native_apply_committed(&[entry]).map(|_| ()))
                .unwrap();
        });
        until(|| fixture.wal.retirement_wait_state_for_test().unwrap().0 > 0);
        let started = Instant::now();
        let used_before = VerificationMemory::used_bytes();
        let before = selected(&fixture);
        std::thread::sleep(Duration::from_secs(6));
        // Keep the final shortfall above its initial value even if this tiny
        // empty checkpoint releases some retained metadata. Also expose the
        // temporary checkpoint allocations for multiple admission polls.
        let extra = VerificationMemory::reserve(4 * 1024 * 1024).unwrap();
        armed.store(true, Ordering::Release);
        let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
        gate.entered();
        std::thread::sleep(Duration::from_millis(100));
        gate.release();
        checkpoint.join().unwrap().unwrap();
        let after = selected(&fixture);
        assert_ne!(after, before);
        assert!(VerificationMemory::used_bytes() >= used_before);
        std::thread::sleep(Duration::from_secs(3));
        fixture.wal.checkpoint().unwrap();
        assert_ne!(selected(&fixture), after);
        assert_eq!(fixture.wal.retirement_journal_bytes_for_test(), 0);
        assert!(VerificationMemory::used_bytes() >= used_before);
        let result = rx.recv_timeout(Duration::from_secs(12).saturating_sub(started.elapsed()));
        drop((pressure, extra)); // Let a regressed unbounded waiter join too.
        apply.join().unwrap();
        let error = result
            .expect("checkpoints without admission relief cannot renew the bound")
            .unwrap_err();
        assert_eq!(error.to_string(), "native retirement admission timed out");
        assert!(started.elapsed() < Duration::from_secs(12));
    });
    assert!(fixture.wal.shutdown().is_err());
}

#[test]
fn native_reclaim_memory_shortfall_relief_extends_committed_wait() {
    if isolated("native_reclaim_memory_shortfall_relief_extends_committed_wait") {
        return;
    }
    let (fixture, entry) = waiting_fixture();
    let mut pressure =
        crate::consensus::verified_snapshot::VerificationMemory::reserve(84 * 1024 * 1024).unwrap();
    let before = selected(&fixture);
    std::thread::scope(|scope| {
        let apply = scope.spawn(|| fixture.wal.native_apply_committed(&[entry]));
        until(|| fixture.wal.retirement_wait_state_for_test().unwrap().0 > 0);
        std::thread::sleep(Duration::from_secs(6));
        pressure.shrink_to(82 * 1024 * 1024).unwrap();
        std::thread::sleep(Duration::from_secs(5));
        let still_waiting = !apply.is_finished();
        drop(pressure);
        let result = apply.join().unwrap();
        assert!(
            still_waiting,
            "a smaller shortfall renews the inactivity budget"
        );
        assert!(result.unwrap().responses[0].result.is_ok());
    });
    assert_eq!(selected(&fixture), before);
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_successful_reservation_resets_wait_after_retry() {
    if isolated("native_reclaim_memory_successful_reservation_resets_wait_after_retry") {
        return;
    }
    let armed = Arc::new(AtomicBool::new(false));
    let plans = Arc::new(AtomicUsize::new(0));
    let preparations = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let resume = Mutex::new(resume_rx);
    let (fixture, entry) = waiting_fixture_with(IoControl {
        hook: Arc::new({
            let armed = Arc::clone(&armed);
            let plans = Arc::clone(&plans);
            let preparations = Arc::clone(&preparations);
            move |point| {
                if !armed.load(Ordering::Acquire) {
                    return Ok(());
                }
                if point == Point::BeforeNativeRetirementPlan {
                    plans.fetch_add(1, Ordering::SeqCst);
                }
                if point == Point::BeforeNativeApplyPublish
                    && preparations.fetch_add(1, Ordering::SeqCst) == 0
                {
                    entered_tx.send(()).map_err(io::Error::other)?;
                    resume
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(20))
                        .map_err(io::Error::other)?;
                }
                Ok(())
            }
        }),
        ..IoControl::default()
    });
    use crate::consensus::verified_snapshot::VerificationMemory;
    let first_pressure = VerificationMemory::reserve(80 * 1024 * 1024).unwrap();
    armed.store(true, Ordering::Release);
    std::thread::scope(|scope| {
        let apply = scope.spawn(|| fixture.wal.native_apply_committed(&[entry]));
        until(|| fixture.wal.retirement_wait_state_for_test().unwrap().0 == 1);
        drop(first_pressure);
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // A reservation succeeded and detached preparation completed. Select
        // real snapshot metadata so that this publication must be recaptured.
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: Some(log_id(1)),
            last_membership: fixture
                .wal
                .with_native_read(|state| Ok(state.membership()))
                .unwrap(),
            snapshot_id: fixture.wal.native_snapshot_id().unwrap(),
        };
        fixture
            .wal
            .native_publish_snapshot((
                meta,
                format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
                [0xD8; 32],
                100,
            ))
            .unwrap();
        let second_pressure = VerificationMemory::reserve(84 * 1024 * 1024).unwrap();
        // The previous episode's deadline has passed while preparation was
        // active. A new pressure wait must still have its own full budget.
        std::thread::sleep(Duration::from_secs(11));
        resume_tx.send(()).unwrap();
        until(|| plans.load(Ordering::SeqCst) >= 3);
        until(|| {
            fixture.wal.retirement_wait_state_for_test().unwrap().0 == 2 || apply.is_finished()
        });
        let waits = fixture.wal.retirement_wait_state_for_test().unwrap().0;
        std::thread::sleep(Duration::from_millis(100));
        let still_waiting = !apply.is_finished();
        drop(second_pressure);
        let result = apply.join().unwrap();
        assert_eq!(
            waits, 2,
            "successful reservation ends the first pressure episode"
        );
        assert!(
            still_waiting,
            "a later wait must not inherit an expired timer"
        );
        assert!(result.unwrap().responses[0].result.is_ok());
    });
    assert_eq!(preparations.load(Ordering::SeqCst), 2);
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_planner_error_uses_real_evaluation() {
    if isolated("native_reclaim_memory_planner_error_uses_real_evaluation") {
        return;
    }
    let attempts = Arc::new(AtomicUsize::new(0));
    let (fixture, entry) = waiting_fixture_with(IoControl {
        hook: Arc::new({
            let attempts = Arc::clone(&attempts);
            move |point| {
                if point == Point::BeforeNativeRetirementPlan {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::other("injected retirement planner failure"))
                } else {
                    Ok(())
                }
            }
        }),
        ..IoControl::default()
    });
    let result = fixture.wal.native_apply_committed(&[entry]);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(result.unwrap().responses[0].result.is_ok());
    assert_eq!(
        fixture.wal.integration_cost_snapshot().unwrap()["application"]
            ["retirement_plan_fallbacks"]
            .as_u64(),
        Some(1),
        "planner fallback is observable without recording command values"
    );
    assert_eq!(
        fixture
            .wal
            .with_native_read(|state| state.history_state())
            .unwrap()
            .reclaim_remaining(),
        0
    );
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_preflight_avoids_unhelpful_checkpoints() {
    if isolated("native_reclaim_memory_preflight_avoids_unhelpful_checkpoints") {
        return;
    }
    let fixture = retiring_fixture(IoControl::default(), 2048);
    let state = fixture
        .wal
        .with_native_read(|state| state.history_state())
        .unwrap();
    let entry = maintenance(2, state, timestamp(11));
    fixture.append_commit(std::slice::from_ref(&entry));
    fixture.wal.native_apply_committed(&[entry]).unwrap();
    let pressure =
        crate::consensus::verified_snapshot::VerificationMemory::reserve(80 * 1024 * 1024).unwrap();
    // An explicit checkpoint completed but could not remove external pressure.
    fixture.wal.checkpoint().unwrap();
    let selected_before = selected(&fixture);
    for index in 3..=12 {
        let mut entry = maintenance(index, state, timestamp(12));
        let opc_consensus::engine::EntryPayload::Normal(command) = &mut entry.payload else {
            unreachable!()
        };
        command.intent = SessionMutationIntent::AdvanceLogicalTime;
        fixture.append_commit(std::slice::from_ref(&entry));
        fixture.wal.native_apply_committed(&[entry]).unwrap();
        assert!(fixture.wal.retirement_journal_bytes_for_test() > 0);
        assert!(!fixture.wal.native_retirement_ready().unwrap());
        assert!(!fixture.wal.retirement_wait_state_for_test().unwrap().2);
    }
    assert_eq!(
        selected(&fixture),
        selected_before,
        "polling must not churn generations under irreducible pressure"
    );
    drop(pressure);
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_requested_checkpoint_relieves_wait() {
    if isolated("native_reclaim_memory_requested_checkpoint_relieves_wait") {
        return;
    }
    let gate = Gate::new(Point::BeforeNativeGenerationAppend, 1);
    let fixture = retiring_fixture(gate.control(), 3072);
    for index in 2..=3 {
        let state = fixture
            .wal
            .with_native_read(|state| state.history_state())
            .unwrap();
        let entry = maintenance(index, state, timestamp(11));
        fixture.append_commit(std::slice::from_ref(&entry));
        fixture.wal.native_apply_committed(&[entry]).unwrap();
    }
    let state = fixture
        .wal
        .with_native_read(|state| state.history_state())
        .unwrap();
    let entry = maintenance(4, state, timestamp(11));
    fixture.append_commit(std::slice::from_ref(&entry));
    assert!(fixture.wal.retirement_journal_bytes_for_test() > 256 * 1024);
    use crate::consensus::verified_snapshot::VerificationMemory;
    let pressure =
        VerificationMemory::reserve(80 * 1024 * 1024 - VerificationMemory::used_bytes()).unwrap();
    std::thread::scope(|scope| {
        let apply = scope.spawn(|| fixture.wal.native_apply_committed(&[entry]));
        gate.entered(); // Only the waiting apply can have requested this capture.
        let waited = fixture.wal.retirement_wait_state_for_test().unwrap().0;
        gate.release();
        let result = apply.join().unwrap();
        assert!(waited > 0);
        assert!(result.unwrap().responses[0].result.is_ok());
    });
    assert_eq!(gate.hits.load(Ordering::Acquire), 1);
    drop(pressure);
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_eight_mib_journal_requests_checkpoint() {
    if isolated("native_reclaim_memory_eight_mib_journal_requests_checkpoint") {
        return;
    }
    let gate = Gate::new(Point::BeforeNativeGenerationAppend, 1);
    let fixture = retiring_fixture(gate.control(), 64 * 1024);
    // Fewer than 256 WAL operations, tiny serialized input, no explicit
    // checkpoint/preflight request: only the memory trigger can start one.
    let mut previous = 0;
    for index in 2..=61 {
        previous = fixture.wal.retirement_journal_bytes_for_test();
        assert!(previous < 8 * 1024 * 1024);
        assert_eq!(gate.hits.load(Ordering::Acquire), 0);
        let state = fixture
            .wal
            .with_native_read(|state| state.history_state())
            .unwrap();
        let entry = maintenance(index, state, timestamp(11));
        fixture.append_commit(std::slice::from_ref(&entry));
        fixture.wal.native_apply_committed(&[entry]).unwrap();
    }
    gate.entered();
    gate.release();
    assert!(
        previous > 8 * 1024 * 1024 - 160 * 1024,
        "last publication crosses the 8 MiB scheduling line"
    );
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_noop_admission_keeps_consumers_live() {
    const CHILD: &str = "OPC_RECLAIM_ADMISSION_CHILD";
    const TEST: &str = "sqlite::consensus::tests::native::basis::reclaim_memory::native_reclaim_memory_noop_admission_keeps_consumers_live";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .test_output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let gate = Gate::new(Point::BeforeNativeGenerationAppend, 1);
    let fixture = Fixture::with_control(Limits::default(), gate.control());
    let sentinel = fenced_transition_v2_request(0xD6, 1, "reclaim-admission");
    fixture.parity(&[formation(), activation(1, sentinel.clone(), timestamp(1))]);
    let expected = status(&fixture.wal, &sentinel);
    let replay = fenced_transition_v2_entry(2, sentinel.clone(), timestamp(2));
    fixture.append_commit(std::slice::from_ref(&replay));
    let response = fixture
        .wal
        .native_apply_committed(&[replay])
        .unwrap()
        .responses[0]
        .clone();
    std::thread::scope(|scope| {
        let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
        gate.entered();
        // Model other admitted images/codec owners, all charged to the real
        // process counter. Optional maintenance must leave their headroom.
        let pressure =
            crate::consensus::verified_snapshot::VerificationMemory::reserve(80 * 1024 * 1024)
                .unwrap();
        assert!(
            fixture.wal.native_retirement_ready().unwrap(),
            "this epoch can only no-op, so external pressure must not defer it"
        );
        assert_eq!(status(&fixture.wal, &sentinel), expected);
        let replay = fenced_transition_v2_entry(3, sentinel.clone(), timestamp(3));
        fixture.append_commit(std::slice::from_ref(&replay));
        assert_eq!(
            fixture
                .wal
                .native_apply_committed(&[replay])
                .unwrap()
                .responses[0],
            response
        );
        assert!(
            fixture.wal.native_retirement_ready().unwrap(),
            "this epoch can only no-op, so external pressure must not defer it"
        );
        drop(pressure);
        assert!(fixture.wal.native_retirement_ready().unwrap());
        gate.release();
        checkpoint.join().unwrap().unwrap();
    });
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_held_checkpoint_allows_consumer_work_and_finishes() {
    const CHILD: &str = "OPC_RECLAIM_CHECKPOINT_CHILD";
    const TEST: &str = "sqlite::consensus::tests::native::basis::reclaim_memory::native_reclaim_memory_held_checkpoint_allows_consumer_work_and_finishes";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .test_output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            output.status.success(),
            "held checkpoint: {stdout}\n{stderr}"
        );
        assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
        return;
    }
    let mut fixture = Fixture::new();
    let original = fenced_transition_v2_request(0xD4, 1, "reclaim-checkpoint");
    fixture.parity(&[formation(), activation(1, original.clone(), timestamp(1))]);
    fixture.wal.shutdown().unwrap();
    let epoch = |number| FencedTransitionV2HistoryEpoch::new(number).unwrap();
    let history = FencedTransitionV2HistoryState::new(
        Some(epoch(2)),
        Some(epoch(1)),
        Some(epoch(1)),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
        1,
        0,
        0,
    )
    .unwrap();
    let gate = Gate::new(Point::BeforeNativeGenerationAppend, 1);
    fixture.wal = Wal::open_reclaim_fixture_for_test(
        &fixture.directory.path().join("wal"),
        fixture.wal.binding(),
        history,
        timestamp(10),
        gate.control(),
    )
    .unwrap();
    let sentinel = FencedTransitionV2Request::new(
        epoch(2),
        crate::FencedTransitionV2CallerNonce::from_bytes([0xD5; 16]),
        original.lease().clone(),
        original.mutation().clone(),
    )
    .unwrap();
    let entry = fenced_transition_v2_entry(2, sentinel.clone(), timestamp(11));
    fixture.append_commit(std::slice::from_ref(&entry));
    let expected = fixture
        .wal
        .native_apply_committed(&[entry])
        .unwrap()
        .responses[0]
        .clone();
    let sentinel_status = status(&fixture.wal, &sentinel);
    assert!(matches!(
        sentinel_status,
        FencedTransitionV2Status::Recorded(_)
    ));
    let progress = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
        gate.entered();
        let retiring = scope.spawn(|| {
            let mut index = 3;
            for batch in 1..=128 {
                let history = fixture
                    .wal
                    .with_native_read(|state| state.history_state())?;
                let entry = maintenance(index, history, timestamp(12));
                fixture.append_commit(std::slice::from_ref(&entry));
                let result = fixture.wal.native_apply_committed(&[entry])?;
                assert!(result.responses[0].result.is_ok());
                index += 1;
                if batch % 4 == 0 {
                    assert_eq!(status(&fixture.wal, &sentinel), sentinel_status);
                    let replay = fenced_transition_v2_entry(index, sentinel.clone(), timestamp(12));
                    fixture.append_commit(std::slice::from_ref(&replay));
                    let result = fixture.wal.native_apply_committed(&[replay])?;
                    assert_eq!(result.responses[0], expected);
                    index += 1;
                }
                progress.store(batch, Ordering::Release);
            }
            Ok::<_, io::Error>(())
        });
        until(|| progress.load(Ordering::Acquire) >= 16 || retiring.is_finished());
        assert!(progress.load(Ordering::Acquire) >= 16);
        assert_eq!(status(&fixture.wal, &sentinel), sentinel_status);
        gate.release();
        checkpoint.join().unwrap().unwrap();
        retiring.join().unwrap().unwrap();
    });
    let history = fixture
        .wal
        .with_native_read(|state| state.history_state())
        .unwrap();
    assert_eq!(history.reclaimed_entries(), 131_072);
    assert_eq!(history.reclaim_remaining(), 0);
    assert_eq!(history.bound_entries(), 1);
    let reopened = fixture.reopened();
    assert_eq!(
        reopened
            .with_native_read(|state| state.history_state())
            .unwrap(),
        history
    );
    assert_eq!(status(&reopened, &sentinel), sentinel_status);
    reopened.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_preflight_does_not_request_during_install() {
    if isolated("native_reclaim_memory_preflight_does_not_request_during_install") {
        return;
    }
    let (fixture, _) = waiting_fixture();
    let pressure =
        crate::consensus::verified_snapshot::VerificationMemory::reserve(80 * 1024 * 1024).unwrap();
    fixture.wal.retirement_install_for_test(true).unwrap();
    assert!(!fixture.wal.native_retirement_ready().unwrap());
    assert!(!fixture.wal.retirement_wait_state_for_test().unwrap().2);
    fixture.wal.retirement_install_for_test(false).unwrap();
    drop(pressure);
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_reclaim_memory_full_generation_replays_maximum_retirement_suffix() {
    if isolated("native_reclaim_memory_full_generation_replays_maximum_retirement_suffix") {
        return;
    }
    let mut fixture = Fixture::new();
    let original = fenced_transition_v2_request(0xD8, 1, "reclaim-recovery");
    fixture.parity(&[formation(), activation(1, original, timestamp(1))]);
    fixture.wal.shutdown().unwrap();
    let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
    let max = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES;
    let full =
        FencedTransitionV2HistoryState::new(Some(epoch(8)), None, None, 0, 7, max, 0).unwrap();
    fixture.wal = Wal::open_reclaim_fixture_for_test(
        &fixture.directory.path().join("wal"),
        fixture.wal.binding(),
        full,
        timestamp(10),
        IoControl::default(),
    )
    .unwrap();
    let mut entries = Vec::new();
    // Exhaust both epochs that maintenance can retire without new consumer
    // receipts: 128 reclaims, one rotation, then 128 reclaims. This exceeds
    // the ordinary 8 MiB trigger and models a capture lost before selection.
    for batch in 0..128 {
        let state = FencedTransitionV2HistoryState::new(
            Some(epoch(8)),
            (batch != 0).then_some(epoch(1)),
            (batch != 0).then_some(epoch(1)),
            if batch == 0 { 0 } else { max - batch * 1024 },
            7 + batch as u64,
            max,
            (batch * 1024) as u64,
        )
        .unwrap();
        entries.push(maintenance(2 + entries.len() as u64, state, timestamp(11)));
    }
    let retired = FencedTransitionV2HistoryState::new(
        Some(epoch(8)),
        Some(epoch(1)),
        None,
        0,
        135,
        max,
        max as u64,
    )
    .unwrap();
    entries.push(maintenance(
        2 + entries.len() as u64,
        retired,
        timestamp(11),
    ));
    for batch in 0..128 {
        let state = FencedTransitionV2HistoryState::new(
            Some(epoch(9)),
            Some(epoch(if batch == 0 { 1 } else { 2 })),
            (batch != 0).then_some(epoch(2)),
            if batch == 0 { 0 } else { max - batch * 1024 },
            136 + batch as u64,
            0,
            (max + batch * 1024) as u64,
        )
        .unwrap();
        entries.push(maintenance(2 + entries.len() as u64, state, timestamp(11)));
    }
    assert_eq!(
        fixture
            .wal
            .with_native_read(|state| state.reclaim_candidate_bytes(&entries))
            .unwrap(),
        2 * max * 72
    );
    for batch in entries.chunks(64) {
        fixture.append_commit(batch);
    }
    let binding = fixture.wal.binding();
    fixture.wal.shutdown().unwrap();
    fixture
        .wal
        .release_closed_native_memory_for_test(|_, release| release())
        .unwrap(); // Release the prior verifier owners before cold reopen.
    let (reopened, [journal, retained, peak]) =
        Wal::open_replay_observation_for_test(&fixture.directory.path().join("wal"), binding)
            .unwrap();
    let state = reopened
        .with_native_read(|state| state.history_state())
        .unwrap();
    assert_eq!(state.active_epoch(), Some(epoch(9)));
    assert_eq!(state.retired_through(), Some(epoch(2)));
    assert_eq!(state.reclaim_remaining(), 0);
    assert_eq!(state.reclaimed_entries(), (2 * max) as u64);
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied().unwrap().index))
            .unwrap(),
        258
    );
    // 262,144 * 72 B = 18 MiB; <=34 ranges *64 KiB plus <=33
    // publication guards leave the retained suffix below 21 MiB. Cold
    // generation/audit/decoder overlap must leave half the real cap unused.
    assert!(journal >= 18 * 1024 * 1024);
    assert!(journal < 21 * 1024 * 1024, "journal={journal}");
    assert!(peak < 64 * 1024 * 1024, "peak={peak}, retained={retained}");
    eprintln!("native_reclaim_recovery_maximum rows=1048576 entries=257 journal_bytes={journal} retained_bytes={retained} peak_bytes={peak} cap_bytes={}", crate::consensus::verified_snapshot::PROCESS_VERIFICATION_BYTES);
    reopened.checkpoint().unwrap(); // Validate and append the complete replay journal.
    reopened.shutdown().unwrap();
}
