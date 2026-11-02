//! Size-triggered native bases must remain bounded across repeated checkpoints.

use super::*;
use crate::SessionPersistenceMode;

const SMALL_GENERATION: u64 = 4 * 64 * 1024;

mod background;
mod concurrency;
mod install_claim;
use background::{capacity_entry, Events, Park, Release};

fn repeated_rollover(mode: SessionPersistenceMode) {
    let events = Arc::new(Events::default());
    let control = IoControl {
        native_rollover_bytes: Some(SMALL_GENERATION),
        hook: Arc::new({
            let events = Arc::clone(&events);
            move |point| {
                events.hook(point);
                Ok(())
            }
        }),
        ..IoControl::default()
    };
    assert_eq!(control.native_rollover_bytes, Some(SMALL_GENERATION));
    let fixture = Fixture::with_persistence(Limits::default(), control, mode);
    let request = fenced_transition_v2_request(0xAD, 1, "generation-rollover");
    fixture.parity(&[formation(), activation(1, request.clone(), timestamp(1))]);
    let expected = status(&fixture.wal, &request);
    let first = selected(&fixture)["native_generation"]["file_epoch"]
        .as_u64()
        .unwrap();
    for round in 1..=4 {
        for _ in 0..4 {
            fixture
                .wal
                .submit(Operation::Barrier)
                .unwrap()
                .wait()
                .unwrap();
            fixture.wal.checkpoint().unwrap();
            let costs = fixture.wal.integration_cost_snapshot().unwrap();
            let size = &costs["checkpoint"]["generation"];
            let base = size["base_bytes"].as_u64().unwrap();
            let suffix = size["appended_bytes"].as_u64().unwrap();
            let total = size["total_bytes"].as_u64().unwrap();
            let trigger = size["trigger_bytes"].as_u64().unwrap();
            assert!(
                base <= trigger,
                "this fixed live-data fixture has a compact base below its trigger"
            );
            assert_eq!(total, base + suffix);
            // The selected file is the compact cut plus its actual appended or
            // rebased suffix. Since this fixture's base is <=trigger, the old
            // synchronous bound becomes trigger+bytes appended since that cut.
            // background::native_rollover_switch_replays_exact_suffix proves
            // the physical bound using each rebased frame and switch extent.
            assert!(total <= trigger + suffix, "{size}");
            assert_eq!(status(&fixture.wal, &request), expected);
            assert!(fixture.wal.storage_health().1.is_none());
        }
        events.wait_until(|| {
            fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]["compactor_switches"]
                .as_u64()
                .unwrap()
                >= round
        });
    }
    assert!(
        selected(&fixture)["native_generation"]["file_epoch"]
            .as_u64()
            .unwrap()
            >= first + 3,
        "the same owner must cross several generation boundaries"
    );
    let logs = encode_json(&fixture.wal.read(0, 2).unwrap()).unwrap();
    let reopened = fixture.reopened();
    assert_eq!(status(&reopened, &request), expected);
    assert_eq!(encode_json(&reopened.read(0, 2).unwrap()).unwrap(), logs);
    reopened.shutdown().unwrap();
}

#[test]
fn native_generation_rollover_keeps_durable_checkpoints_bounded() {
    repeated_rollover(SessionPersistenceMode::Durable);
}

#[test]
fn native_generation_rollover_keeps_async_checkpoints_bounded() {
    repeated_rollover(SessionPersistenceMode::Async);
}

#[test]
fn native_generation_rollover_keeps_a_pinned_receipt_reader_live() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let gate = Park::at(Point::BeforeNativeReceiptRead, false);
        let events = Arc::new(Events::default());
        let control = IoControl {
            native_rollover_bytes: Some(SMALL_GENERATION),
            hook: Arc::new({
                let gate = Arc::clone(&gate);
                let events = Arc::clone(&events);
                move |point| {
                    events.hook(point);
                    gate.hook(point)
                }
            }),
            ..IoControl::default()
        };
        let mut fixture = Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
        let request = fenced_transition_v2_request(0xAE, 1, "rollover-pinned-reader");
        fixture.parity(&[formation(), activation(1, request.clone(), timestamp(1))]);
        fixture.wal.checkpoint().unwrap();
        // Cold reopen starts from an admitted selected image with no previous
        // optional job. Arming therefore identifies this test's build exactly.
        fixture.wal.shutdown().unwrap();
        fixture.wal = Wal::open(
            &fixture.directory.path().join("wal"),
            fixture.wal.binding(),
            Limits::default(),
            control,
        )
        .unwrap();

        events.wait_until(|| fixture.wal.native_cold_counts_for_test().unwrap() == [1, 1, 2]);
        let weak = fixture
            .wal
            .native_receipt_source_for_test(request.request_id())
            .unwrap()
            .unwrap();
        gate.arm();
        let initial = selected(&fixture)["native_generation"]["file_epoch"]
            .as_u64()
            .unwrap();
        std::thread::scope(|scope| {
            let _release = Release(Arc::clone(&gate));
            let read = scope.spawn(|| status(&fixture.wal, &request));
            gate.entered();
            for _ in 0..8 {
                fixture
                    .wal
                    .submit(Operation::Barrier)
                    .unwrap()
                    .wait()
                    .unwrap();
                fixture.wal.checkpoint().unwrap();
            }
            events.wait_until(|| {
                fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]["generation"]
                    ["file_epoch"]
                    .as_u64()
                    .unwrap()
                    > initial
            });
            assert!(
                weak.upgrade().is_some(),
                "the parked authenticated reader pins the old source"
            );
            assert!(
                selected(&fixture)["native_generation"]["file_epoch"]
                    .as_u64()
                    .unwrap()
                    > initial
            );
            assert!(!fixture
                .directory
                .path()
                .join(format!("wal/basis-{initial:020}.native"))
                .exists());
            gate.release();
            assert!(matches!(
                read.join().unwrap(),
                FencedTransitionV2Status::Recorded(_)
            ));
        });
        fixture
            .wal
            .submit(Operation::Barrier)
            .unwrap()
            .wait()
            .unwrap();
        events.wait_until(|| weak.upgrade().is_none());
        assert!(fixture.wal.storage_health().1.is_none());
        fixture.wal.shutdown().unwrap();
    }
}

#[test]
fn native_generation_rollover_preserves_changes_after_the_captured_cut() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let gate = Park::at(Point::AfterNativeBasisAdmission, false);
        let events = Arc::new(Events::default());
        let armed = Arc::new(AtomicBool::new(false));
        let control = IoControl {
            native_rollover_bytes: Some(SMALL_GENERATION),
            hook: Arc::new({
                let gate = Arc::clone(&gate);
                let events = Arc::clone(&events);
                let armed = Arc::clone(&armed);
                move |point| {
                    events.hook(point);
                    if armed.load(Ordering::SeqCst) {
                        gate.hook(point)?;
                    }
                    Ok(())
                }
            }),
            ..IoControl::default()
        };
        let mut fixture = Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
        let initial = fenced_transition_v2_request(0xB0, 1, "rollover-newer-revision");
        let requests = (0..160)
            .map(|slot| sdk741_component_request(Sdk741Payload::Create, 2, slot, None))
            .collect::<Vec<_>>();
        fixture.parity(&[
            formation(),
            activation(1, initial.clone(), timestamp(1)),
            fenced_transition_v2_batch_entry(2, requests.clone(), timestamp(2)),
        ]);
        fixture.wal.checkpoint().unwrap();
        // Cold reopen starts from an admitted selected image with no previous
        // optional job. Arming therefore identifies this test's build exactly.
        fixture.wal.shutdown().unwrap();
        fixture.wal = Wal::open(
            &fixture.directory.path().join("wal"),
            fixture.wal.binding(),
            Limits::default(),
            control,
        )
        .unwrap();

        events.wait_until(|| fixture.wal.native_cold_counts_for_test().unwrap() == [161, 161, 3]);
        let captured_file = selected(&fixture)["native_generation"]["file_epoch"]
            .as_u64()
            .unwrap();
        gate.arm();
        armed.store(true, Ordering::SeqCst);
        std::thread::scope(|scope| {
            let _release = Release(Arc::clone(&gate));
            let checkpoints = scope.spawn(|| {
                for _ in 0..8 {
                    fixture
                        .wal
                        .submit(Operation::Barrier)
                        .unwrap()
                        .wait()
                        .unwrap();
                    fixture.wal.checkpoint().unwrap();
                }
            });
            gate.entered();
            let expiry = timestamp(1)
                .add_seconds(i64::try_from(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs()).unwrap())
                .unwrap();
            fixture.parity(&[fenced_transition_v2_authorized_entry(
                3,
                initial.clone(),
                expiry,
                node_id(),
                identity(),
            )]);
            assert_eq!(
                status(&fixture.wal, &initial),
                FencedTransitionV2Status::Expired
            );
            fixture.wal.checkpoint().unwrap();
            gate.release();
            checkpoints.join().unwrap();
        });
        events.wait_until(|| {
            fixture.wal.integration_cost_snapshot().unwrap()["checkpoint"]["generation"]
                ["file_epoch"]
                .as_u64()
                .unwrap()
                > captured_file
        });
        assert_eq!(
            status(&fixture.wal, &initial),
            FencedTransitionV2Status::Expired
        );
        let logs = encode_json(&fixture.wal.read(0, 4).unwrap()).unwrap();
        let reopened = fixture.reopened();
        assert_eq!(
            status(&reopened, &initial),
            FencedTransitionV2Status::Expired
        );
        for request in &requests {
            assert!(matches!(
                status(&reopened, request),
                FencedTransitionV2Status::Recorded(_)
            ));
        }
        assert_eq!(encode_json(&reopened.read(0, 4).unwrap()).unwrap(), logs);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn native_generation_rollover_reopens_at_every_publication_boundary() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        for boundary in [
            Point::BeforeBasisCreate,
            Point::AfterBasisCreate,
            Point::BeforeBasisSync,
            Point::AfterBasisSync,
            Point::AfterBasisRename,
            Point::AfterBasisDirectorySync,
            Point::AfterNativeBasisAdmission,
            Point::BeforeNativeFrameRebase,
            Point::AfterNativeFrameRebase,
            Point::BeforeBasisSelector,
            Point::BeforeBasisSelectorSync,
            Point::AfterBasisSelectorSync,
            Point::AfterBasisSelectorRename,
            Point::BeforeBasisPublicationSync,
            Point::AfterBasisPublicationSync,
            Point::BeforeBasisReclaim,
            Point::AfterBasisReclaimFile,
            Point::BeforeBasisReclaimSync,
            Point::AfterBasisReclaimSync,
            Point::AfterNativeSwitchSelection,
        ] {
            let armed = Arc::new(AtomicBool::new(false));
            let rollover = Arc::new(AtomicBool::new(false));
            let failed = Arc::new((Mutex::new(false), Condvar::new()));
            let build = Park::at(Point::AfterNativeBasisAdmission, false);
            let rebase = matches!(
                boundary,
                Point::BeforeNativeFrameRebase | Point::AfterNativeFrameRebase
            );
            let control = IoControl {
                native_rollover_bytes: Some(SMALL_GENERATION),
                hook: Arc::new({
                    let build = Arc::clone(&build);
                    let (armed, rollover, failed) = (
                        Arc::clone(&armed),
                        Arc::clone(&rollover),
                        Arc::clone(&failed),
                    );
                    move |point| {
                        if armed.load(Ordering::SeqCst) && point == Point::BeforeBasisCreate {
                            rollover.store(true, Ordering::SeqCst);
                        }
                        if rollover.load(Ordering::SeqCst) && point == boundary {
                            *failed.0.lock().unwrap() = true;
                            failed.1.notify_all();
                            return Err(io::Error::other("interrupted native rollover"));
                        }
                        if rebase && armed.load(Ordering::SeqCst) {
                            build.hook(point)?;
                        }
                        Ok(())
                    }
                }),
                ..IoControl::default()
            };
            let mut fixture =
                Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
            let request = fenced_transition_v2_request(0xAF, 1, "rollover-interruption");
            fixture.parity(&[formation(), activation(1, request.clone(), timestamp(1))]);
            fixture.wal.checkpoint().unwrap();
            // Cold reopen starts from an admitted selected image with no previous
            // optional job. Arming therefore identifies this test's build exactly.
            fixture.wal.shutdown().unwrap();
            fixture.wal = Wal::open(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                Limits::default(),
                control,
            )
            .unwrap();

            let expected = status(&fixture.wal, &request);
            let _release = Release(Arc::clone(&build));
            if rebase {
                build.arm();
            }
            armed.store(true, Ordering::SeqCst);
            for _ in 0..4 {
                if fixture
                    .wal
                    .submit(Operation::Barrier)
                    .and_then(|ticket| ticket.wait())
                    .is_err()
                    || fixture.wal.checkpoint().is_err()
                {
                    break;
                }
            }
            if rebase {
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
            drop(
                failed
                    .1
                    .wait_while(failed.0.lock().unwrap(), |failed| !*failed)
                    .unwrap(),
            );
            assert!(fixture.wal.shutdown().is_err());
            let events = Arc::new(Events::default());
            let reopened = Wal::open(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                Limits::default(),
                IoControl {
                    native_rollover_bytes: Some(64 * 1024),
                    hook: Arc::new({
                        let events = Arc::clone(&events);
                        move |point| {
                            events.hook(point);
                            Ok(())
                        }
                    }),
                    ..IoControl::default()
                },
            )
            .unwrap_or_else(|error| panic!("reopen after {boundary:?} in {mode:?}: {error}"));
            assert_eq!(
                status(&reopened, &request),
                expected,
                "{boundary:?} in {mode:?}"
            );
            assert_eq!(
                reopened
                    .with_native_read(|state| Ok(state.applied()))
                    .unwrap(),
                Some(log_id(1))
            );
            let recovered_file = selected(&fixture)["native_generation"]["file_epoch"]
                .as_u64()
                .unwrap();
            for round in 1..=2 {
                reopened.submit(Operation::Barrier).unwrap().wait().unwrap();
                reopened.checkpoint().unwrap();
                events.wait_until(|| {
                    reopened.integration_cost_snapshot().unwrap()["checkpoint"]
                        ["compactor_switches"]
                        .as_u64()
                        .unwrap()
                        >= round
                });
            }
            assert!(
                selected(&fixture)["native_generation"]["file_epoch"]
                    .as_u64()
                    .unwrap()
                    >= recovered_file + 2
            );
            assert_eq!(status(&reopened, &request), expected);
            assert!(reopened.storage_health().1.is_none());
            reopened.shutdown().unwrap();
        }
    }
}

#[test]
fn native_generation_rollover_serializes_the_complete_capture_once() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let costs = Arc::new(Mutex::new(Vec::new()));
        let switches = Arc::new((Mutex::new(0_usize), Condvar::new()));
        let control = IoControl {
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
            native_rollover_bytes: Some(SMALL_GENERATION),
            native_rollover_costs: Some(Arc::clone(&costs)),
            ..IoControl::default()
        };
        let fixture = Fixture::with_persistence(Limits::default(), control, mode);
        let request = fenced_transition_v2_request(0xB1, 1, "single-pass-rollover");
        fixture.parity(&[formation(), activation(1, request.clone(), timestamp(1))]);
        for round in 1..=2 {
            for _ in 0..4 {
                fixture
                    .wal
                    .submit(Operation::Barrier)
                    .unwrap()
                    .wait()
                    .unwrap();
                fixture.wal.checkpoint().unwrap();
            }
            drop(
                switches
                    .1
                    .wait_while(switches.0.lock().unwrap(), |count| *count < round)
                    .unwrap(),
            );
        }
        fixture.wal.shutdown().unwrap();
        let costs = costs.lock().unwrap();
        assert!(
            !costs.is_empty(),
            "the real fixture must cross the rollover threshold"
        );
        for pass in costs.iter() {
            assert_eq!(
                pass.serializations, 1,
                "one canonical serialization per rollover: {mode:?}: {pass:?}"
            );
            assert_eq!(
                pass.repairs, 0,
                "a newly verified base must not need cold repair: {pass:?}"
            );
            assert_eq!(
                pass.state_locks, 0,
                "the compactor checks cancellation atomically: {pass:?}"
            );
            assert_eq!(
                pass.cache_locks, pass.read_calls,
                "each ordinary authenticated read takes exactly one cache lock: {pass:?}"
            );
            // Source::read uses one initial and final metadata check, plus one
            // per additional touched block. Empty reads still have both checks.
            // Created has five fixed descriptor/name checks (encode2, admit3).
            assert_eq!(pass.metadata, 5 + pass.read_calls + pass.read_blocks + pass.empty_reads,
                "every metadata read must have a specific authenticated-read or fresh-file bookend: {pass:?}");
            assert!(pass.output_blocks > 0);
            assert_eq!(
                pass.authenticated_output_blocks, pass.output_blocks,
                "every compared output block is authenticated once after sync: {pass:?}"
            );
        }
    }
}
