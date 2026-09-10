//! Deterministic ownership and concurrent-prefix witnesses for native bases.

use super::*;
use crate::sqlite::consensus::wal::Point;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Condvar, Mutex,
};
use std::time::Instant;

mod application;
mod cold_reads;
mod export;
mod public_reads;

struct Gate {
    point: Point,
    occurrence: usize,
    hits: AtomicUsize,
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Gate {
    fn new(point: Point, occurrence: usize) -> Arc<Self> {
        Arc::new(Self {
            point,
            occurrence,
            hits: AtomicUsize::new(0),
            state: Mutex::new((false, false)),
            changed: Condvar::new(),
        })
    }
    fn hook(&self, point: Point) -> io::Result<()> {
        if point != self.point || self.hits.fetch_add(1, Ordering::SeqCst) + 1 != self.occurrence {
            return Ok(());
        }
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.1)
            .unwrap();
        if !state.1 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native test gate not released",
            ));
        }
        Ok(())
    }
    fn entered(&self) {
        let (state, _) = self
            .changed
            .wait_timeout_while(
                self.state.lock().unwrap(),
                Duration::from_secs(5),
                |state| !state.0,
            )
            .unwrap();
        assert!(state.0, "worker reached declared native boundary");
    }
    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
    fn control(self: &Arc<Self>) -> IoControl {
        let gate = Arc::clone(self);
        IoControl {
            hook: Arc::new(move |point| gate.hook(point)),
            ..IoControl::default()
        }
    }
}

fn until(mut predicate: impl FnMut() -> bool) {
    let started = Instant::now();
    while !predicate() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "native ownership condition did not complete"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn selected(fixture: &Fixture) -> serde_json::Value {
    let bytes = std::fs::read(fixture.directory.path().join("wal/CURRENT")).unwrap();
    serde_json::from_slice(&bytes[8..bytes.len() - 32]).unwrap()
}

#[test]
fn native_generation_relocation_services_queue_skips_expired_revision_and_keeps_idle_writer_live() {
    let first = Gate::new(Point::AfterNativeRelocationStep, 1);
    let second = Gate::new(Point::AfterNativeRelocationStep, 2);
    let gates = (Arc::clone(&first), Arc::clone(&second));
    let control = IoControl {
        hook: Arc::new(move |point| {
            gates.0.hook(point)?;
            gates.1.hook(point)
        }),
        ..IoControl::default()
    };
    let fixture = Fixture::with_control(Limits::default(), control);
    let initial = fenced_transition_v2_request(0xF1, 1, "native-relocation-revision");
    let requests = (0..160)
        .map(|slot| sdk741_component_request(Sdk741Payload::Create, 2, slot, None))
        .collect::<Vec<_>>();
    fixture.parity(&[
        formation(),
        activation(1, initial.clone(), timestamp(1)),
        fenced_transition_v2_batch_entry(2, requests.clone(), timestamp(2)),
    ]);
    let expiry = timestamp(1)
        .add_seconds(i64::try_from(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs()).unwrap())
        .unwrap();
    let expired =
        fenced_transition_v2_authorized_entry(3, initial.clone(), expiry, node_id(), identity());
    std::thread::scope(|scope| {
        let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
        first.entered();
        assert_eq!(
            fixture
                .wal
                .native_cold_counts_for_test()
                .unwrap()
                .iter()
                .sum::<usize>(),
            64,
            "first unit has a fixed mutation bound"
        );
        assert_eq!(
            selected(&fixture)["applied"]["index"],
            2,
            "CURRENT is selected before the first relocation"
        );
        let appended = fixture
            .wal
            .submit(append(std::slice::from_ref(&expired)))
            .unwrap();
        let committed = fixture
            .wal
            .submit(Operation::Committed(Some(log_id(3))))
            .unwrap();
        let queued = fixture.wal.submit(Operation::Barrier).unwrap();
        assert!(matches!(queued.try_recv(), Err(mpsc::TryRecvError::Empty)));
        first.release();
        second.entered();
        appended.wait().unwrap();
        committed.wait().unwrap();
        queued.wait().unwrap();
        assert_eq!(
            fixture
                .wal
                .native_cold_counts_for_test()
                .unwrap()
                .iter()
                .sum::<usize>(),
            128
        );
        fixture
            .wal
            .native_apply_committed(std::slice::from_ref(&expired))
            .unwrap();
        assert_eq!(
            status(&fixture.wal, &initial),
            FencedTransitionV2Status::Expired
        );
        second.release();
        checkpoint.join().unwrap().unwrap();
    });
    until(|| {
        fixture
            .wal
            .native_cold_counts_for_test()
            .is_ok_and(|counts| counts == [160, 161, 3])
    });
    assert_eq!(
        status(&fixture.wal, &initial),
        FencedTransitionV2Status::Expired,
        "late relocation cannot restore the expired retained body"
    );
    for request in &requests {
        assert!(matches!(
            status(&fixture.wal, request),
            FencedTransitionV2Status::Recorded(_)
        ));
    }
    let later = Entry {
        log_id: log_id(4),
        payload: EntryPayload::Blank,
    };
    fixture
        .wal
        .submit(append(std::slice::from_ref(&later)))
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(
        encode_json(&fixture.wal.read(4, 5).unwrap()).unwrap(),
        encode_json(&[later]).unwrap(),
        "idle owner accepts and completes the later original append"
    );
    fixture.wal.shutdown().unwrap();
    let reopened = Wal::open(
        &fixture.directory.path().join("wal"),
        fixture.wal.binding(),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    assert_eq!(
        status(&reopened, &initial),
        FencedTransitionV2Status::Expired
    );
    assert_eq!(reopened.read(4, 5).unwrap().len(), 1);
    reopened.shutdown().unwrap();
}

#[test]
fn native_basis_selects_captured_prefix_and_recovers_exact_concurrent_suffix() {
    let gate = Gate::new(Point::BeforeNativeGenerationAppend, 1);
    let fixture = Fixture::with_control(Limits::default(), gate.control());
    let initial = fenced_transition_v2_request(0xEA, 1, "native-background-initial");
    fixture.parity(&[formation(), activation(1, initial.clone(), timestamp(1))]);
    let initial_epoch = selected(&fixture)["epoch"].as_u64().unwrap();
    let applied = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
    let committed = sdk741_component_request(Sdk741Payload::Create, 2, 1, None);
    let tail = sdk741_component_request(Sdk741Payload::Create, 2, 2, None);
    let entries = [
        fenced_transition_v2_entry(2, applied.clone(), timestamp(2)),
        fenced_transition_v2_entry(3, committed.clone(), timestamp(3)),
        fenced_transition_v2_entry(4, tail.clone(), timestamp(4)),
    ];
    let before = fixture.wal.integration_cost_snapshot().unwrap();
    let captured_sequence = before["requests"].as_u64().unwrap();
    let captured_bytes = before["live_retained_bytes"].as_u64().unwrap();
    let exact_applied = std::thread::scope(|scope| {
        let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
        gate.entered();
        // These original completions must all arrive while image creation is
        // still paused, including a committed but deliberately unapplied row.
        fixture
            .wal
            .submit(append(&entries))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(3))))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.native_apply_committed(&entries[..1]).unwrap();
        let exact = status(&fixture.wal, &applied);
        assert!(matches!(exact, FencedTransitionV2Status::Recorded(_)));
        let retained_before_select = fixture.wal.integration_cost_snapshot().unwrap();
        gate.release();
        assert_eq!(checkpoint.join().unwrap().unwrap(), initial_epoch + 1);
        let after = fixture.wal.integration_cost_snapshot().unwrap();
        assert_eq!(
            selected(&fixture)["position"]["sequence"],
            captured_sequence
        );
        assert_eq!(
            after["live_retained_bytes"].as_u64().unwrap(),
            retained_before_select["live_retained_bytes"]
                .as_u64()
                .unwrap()
                - captured_bytes
        );
        assert_eq!(
            after["live_retained_requests"].as_u64().unwrap(),
            retained_before_select["requests"].as_u64().unwrap() - captured_sequence
        );
        assert_eq!(
            status(&fixture.wal, &applied),
            exact,
            "selection preserves newer live business effect"
        );
        exact
    });
    let exact_initial = status(&fixture.wal, &initial);
    let reopened = fixture.reopened();
    assert_eq!(status(&reopened, &initial), exact_initial);
    assert_eq!(status(&reopened, &applied), exact_applied);
    assert!(matches!(
        status(&reopened, &committed),
        FencedTransitionV2Status::Recorded(_)
    ));
    assert_eq!(status(&reopened, &tail), FencedTransitionV2Status::NotFound);
    assert_eq!(
        encode_json(&reopened.read(2, 5).unwrap()).unwrap(),
        encode_json(&entries).unwrap()
    );
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(3))
    );
    reopened.shutdown().unwrap();
}

#[test]
fn native_basis_later_snapshot_and_same_sequence_applied_checkpoint_wait_for_own_image() {
    let first = Gate::new(Point::BeforeNativeGenerationAppend, 1);
    let second = Gate::new(Point::BeforeNativeGenerationAppend, 2);
    let gates = (Arc::clone(&first), Arc::clone(&second));
    let control = IoControl {
        hook: Arc::new(move |point| {
            gates.0.hook(point)?;
            gates.1.hook(point)
        }),
        ..IoControl::default()
    };
    let fixture = Fixture::with_control(Limits::default(), control);
    fixture.parity(&[formation()]);
    let initial_epoch = selected(&fixture)["epoch"].as_u64().unwrap();
    let request = fenced_transition_v2_request(0xEB, 1, "native-background-snapshot");
    let entry = activation(1, request.clone(), timestamp(1));
    fixture.append_commit(std::slice::from_ref(&entry));
    std::thread::scope(|scope| {
        let old_checkpoint = scope.spawn(|| fixture.wal.checkpoint());
        first.entered();
        let sequence = fixture.wal.integration_cost_snapshot().unwrap()["requests"].clone();
        fixture
            .wal
            .native_apply_committed(std::slice::from_ref(&entry))
            .unwrap();
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: Some(log_id(1)),
            last_membership: fixture
                .wal
                .with_native_read(|state| Ok(state.membership()))
                .unwrap(),
            snapshot_id: fixture.wal.native_snapshot_id().unwrap(),
        };
        let candidate = (
            meta,
            format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
            [0xEC; 32],
            100,
        );
        let (snapshot_tx, snapshot_rx) = mpsc::channel();
        let published_candidate = candidate.clone();
        let wal = &fixture.wal;
        let snapshot = scope.spawn(move || {
            snapshot_tx
                .send(wal.native_publish_snapshot(published_candidate))
                .unwrap();
        });
        let (checkpoint_tx, checkpoint_rx) = mpsc::channel();
        let checkpoint = scope.spawn(move || {
            checkpoint_tx.send(wal.checkpoint()).unwrap();
        });
        until(|| {
            fixture
                .wal
                .native_basis_waiters_for_test()
                .is_ok_and(|(pending, applied, active)| {
                    pending && applied == Some(log_id(1)) && active
                })
        });
        first.release();
        second.entered();
        assert_eq!(old_checkpoint.join().unwrap().unwrap(), initial_epoch + 1);
        assert_eq!(
            selected(&fixture)["position"]["sequence"],
            sequence,
            "apply advanced with no additional WAL operation"
        );
        assert_eq!(selected(&fixture)["applied"]["index"], 0);
        assert!(fixture
            .wal
            .with_native_read(|state| Ok(state.current_snapshot()))
            .unwrap()
            .is_none());
        assert!(matches!(
            snapshot_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert!(matches!(
            checkpoint_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        second.release();
        snapshot_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert_eq!(
            checkpoint_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            initial_epoch + 2
        );
        snapshot.join().unwrap();
        checkpoint.join().unwrap();
        assert_eq!(
            fixture
                .wal
                .with_native_read(|state| Ok(state.current_snapshot()))
                .unwrap(),
            Some(candidate)
        );
    });
    let reopened = fixture.reopened();
    assert!(matches!(
        status(&reopened, &request),
        FencedTransitionV2Status::Recorded(_)
    ));
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.current_snapshot().unwrap().0.last_log_id))
            .unwrap(),
        Some(log_id(1))
    );
    reopened.shutdown().unwrap();
}

#[test]
fn native_basis_error_and_panic_fence_queued_and_inflight_callbacks_once() {
    for panic in [false, true] {
        let basis = Gate::new(Point::BeforeNativeGenerationAppend, 1);
        let cut = Gate::new(Point::BeforeCutPublish, 1);
        let armed = Arc::new(AtomicBool::new(false));
        let hooks = (Arc::clone(&basis), Arc::clone(&cut), Arc::clone(&armed));
        let control = IoControl {
            hook: Arc::new(move |point| {
                if point == Point::BeforeNativeGenerationAppend {
                    hooks.0.hook(point)?;
                    if panic {
                        panic!("injected native preparation panic");
                    }
                    return Err(io::Error::other("injected native preparation failure"));
                }
                if hooks.2.load(Ordering::SeqCst) {
                    hooks.1.hook(point)?;
                }
                Ok(())
            }),
            ..IoControl::default()
        };
        let fixture = Fixture::with_control(Limits::default(), control);
        fixture.parity(&[formation()]);
        std::thread::scope(|scope| {
            let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
            basis.entered();
            armed.store(true, Ordering::SeqCst);
            let inflight = fixture
                .wal
                .submit(append(&[Entry {
                    log_id: log_id(1),
                    payload: EntryPayload::Blank,
                }]))
                .unwrap();
            cut.entered();
            let queued = fixture.wal.submit(Operation::Barrier).unwrap();
            basis.release();
            until(|| {
                fixture
                    .wal
                    .with_native_read(|state| Ok(state.applied()))
                    .is_err()
            });
            assert!(fixture.wal.submit(Operation::Barrier).is_err());
            assert!(fixture.wal.native_apply_committed(&[]).is_err());
            assert!(queued.try_recv().unwrap().is_err());
            assert!(matches!(
                queued.try_recv(),
                Err(mpsc::TryRecvError::Disconnected)
            ));
            assert!(matches!(
                inflight.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
            cut.release();
            until(|| match inflight.try_recv() {
                Ok(result) => {
                    assert!(result.is_err());
                    true
                }
                Err(mpsc::TryRecvError::Empty) => false,
                Err(error) => panic!("missing original callback: {error}"),
            });
            assert!(matches!(
                inflight.try_recv(),
                Err(mpsc::TryRecvError::Disconnected)
            ));
            assert!(checkpoint.join().unwrap().is_err());
        });
        assert!(fixture.wal.shutdown().is_err());
        let reopened = Wal::open(
            &fixture.directory.path().join("wal"),
            fixture.wal.binding(),
            Limits::default(),
            IoControl::default(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .with_native_read(|state| Ok(state.applied()))
                .unwrap(),
            Some(log_id(0))
        );
        assert_eq!(
            reopened.read(1, 2).unwrap().len(),
            1,
            "failed callback may retain its completely published uncommitted tail"
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn native_basis_shutdown_and_wal_failure_join_worker_before_releasing_directory_lock() {
    for fail_wal in [false, true] {
        let basis = Gate::new(Point::BeforeNativeGenerationAppend, 1);
        let armed = Arc::new(AtomicBool::new(false));
        let hooks = (Arc::clone(&basis), Arc::clone(&armed));
        let control = IoControl {
            hook: Arc::new(move |point| {
                hooks.0.hook(point)?;
                if hooks.1.load(Ordering::SeqCst) && point == Point::AfterIntentPublish {
                    return Err(io::Error::other(
                        "injected WAL failure during native preparation",
                    ));
                }
                Ok(())
            }),
            ..IoControl::default()
        };
        let fixture = Fixture::with_control(Limits::default(), control);
        fixture.parity(&[formation()]);
        std::thread::scope(|scope| {
            let checkpoint = scope.spawn(|| fixture.wal.checkpoint());
            basis.entered();
            if fail_wal {
                armed.store(true, Ordering::SeqCst);
                assert!(fixture
                    .wal
                    .submit(Operation::Barrier)
                    .unwrap()
                    .wait()
                    .is_err());
            }
            let (started_tx, started_rx) = mpsc::channel();
            let (result_tx, result_rx) = mpsc::channel();
            let wal = &fixture.wal;
            let shutdown = scope.spawn(move || {
                started_tx.send(()).unwrap();
                result_tx.send(wal.shutdown()).unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(
                matches!(
                    result_rx.recv_timeout(Duration::from_millis(20)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "shutdown still owns its paused worker"
            );
            assert!(
                Wal::open(
                    &fixture.directory.path().join("wal"),
                    fixture.wal.binding(),
                    Limits::default(),
                    IoControl::default()
                )
                .is_err(),
                "directory LOCK remains held during join"
            );
            basis.release();
            assert_eq!(
                result_rx
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .is_err(),
                fail_wal
            );
            shutdown.join().unwrap();
            let _ = checkpoint.join().unwrap();
        });
        let reopened = Wal::open(
            &fixture.directory.path().join("wal"),
            fixture.wal.binding(),
            Limits::default(),
            IoControl::default(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .with_native_read(|state| Ok(state.applied()))
                .unwrap(),
            Some(log_id(0))
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn native_basis_hard_retention_waits_without_re_admission_during_preparation() {
    let gate = Gate::new(Point::BeforeNativeGenerationAppend, 1);
    let limits = Limits {
        history_count: 8,
        ..Limits::default()
    };
    let fixture = Fixture::with_control(limits, gate.control());
    // At two of the original eight slots the preparation trigger captures a
    // prefix. Six more original operations remain available while it is paused.
    fixture.parity(&[formation()]);
    gate.entered();
    for _ in 0..6 {
        fixture
            .wal
            .submit(Operation::Barrier)
            .unwrap()
            .wait()
            .unwrap();
    }
    assert_eq!(
        fixture.wal.integration_cost_snapshot().unwrap()["live_retained_requests"],
        8
    );
    assert_eq!(
        fixture.wal.submit(Operation::Barrier).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    std::thread::scope(|scope| {
        let (done_tx, done_rx) = mpsc::channel();
        let wal = &fixture.wal;
        let blocked = scope.spawn(move || {
            done_tx
                .send(
                    wal.native_submit_with_backpressure_for_test(Operation::Barrier)
                        .and_then(|ticket| ticket.wait()),
                )
                .unwrap();
        });
        until(|| fixture.wal.checkpoint_pending_for_test().unwrap());
        assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(
            fixture.wal.integration_cost_snapshot().unwrap()["requests"],
            8,
            "waiting operation has not entered the projection"
        );
        gate.release();
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            9
        );
        blocked.join().unwrap();
    });
    assert_eq!(
        fixture.wal.integration_cost_snapshot().unwrap()["requests"],
        9,
        "original operation admitted and completed once"
    );
    fixture.wal.shutdown().unwrap();
    let reopened = Wal::open(
        &fixture.directory.path().join("wal"),
        fixture.wal.binding(),
        limits,
        IoControl::default(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(0))
    );
    reopened.shutdown().unwrap();
}
