//! An unarmed install claim has no irreversible relocation or waiter effects.
use crate::test_process::witness::{CondvarExt, JoinExt, ReceiverExt};

use super::*;

struct ReleaseCeiling<'a>(&'a Wal);
impl Drop for ReleaseCeiling<'_> {
    fn drop(&mut self) {
        self.0.native_hold_ceiling_checkpoint_for_test(false);
    }
}

#[test]
fn native_rollover_ceiling_checkpoint_yields_install_until_relocation_drains() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let build = Park::at(Point::AfterNativeBasisAdmission, false);
            let switched = Park::at(Point::AfterNativeSwitchSelection, false);
            let poll = Park::at(Point::AfterNativeBackgroundPoll, false);
            let claim = Park::at(Point::NativeInstallWaitStarted, false);
            let next_claim = Park::at(Point::NativeInstallWaitStarted, false);
            let next_build = Park::at(Point::BeforeBasisCreate, false);
            let claims = Arc::new(AtomicUsize::new(0));
            let ownership_wait = Arc::new((Mutex::new(false), Condvar::new()));
            let observe_idle = Arc::new(AtomicBool::new(false));
            let idle = Arc::new((Mutex::new(false), Condvar::new()));
            let control = IoControl {
                native_rollover_bytes: Some(64 * 1024),
                hook: Arc::new({
                    let build = Arc::clone(&build);
                    let switched = Arc::clone(&switched);
                    let poll = Arc::clone(&poll);
                    let claim = Arc::clone(&claim);
                    let next_claim = Arc::clone(&next_claim);
                    let next_build = Arc::clone(&next_build);
                    let claims = Arc::clone(&claims);
                    let ownership_wait = Arc::clone(&ownership_wait);
                    let observe_idle = Arc::clone(&observe_idle);
                    let idle = Arc::clone(&idle);
                    move |point| {
                        build.hook(point)?;
                        switched.hook(point)?;
                        poll.hook(point)?;
                        if std::thread::current().name() == Some("session-native-compactor") {
                            next_build.hook(point)?;
                        }
                        if point == Point::NativeInstallWaitStarted {
                            if claims.fetch_add(1, Ordering::AcqRel) == 0 {
                                claim.hook(point)?;
                            } else {
                                next_claim.hook(point)?;
                            }
                        }
                        if point == Point::NativeInstallOwnershipWaitStarted {
                            *ownership_wait.0.lock().unwrap() = true;
                            ownership_wait.1.notify_all();
                        }
                        if point == Point::NativeBackgroundRelocationIdle
                            && observe_idle.load(Ordering::Acquire)
                        {
                            *idle.0.lock().unwrap() = true;
                            idle.1.notify_all();
                        }
                        Ok(())
                    }
                }),
                ..IoControl::default()
            };
            let mut fixture =
                Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
            let request = fenced_transition_v2_request(0xD8, 1, "install-ceiling-relocation");
            fixture.parity(&[formation(), activation(1, request.clone(), timestamp(1))]);
            fixture.wal.checkpoint().unwrap();
            fixture.wal.shutdown().unwrap();
            fixture.wal = Wal::open(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                Limits::default(),
                control,
            )
            .unwrap();
            let exported = fixture.wal.native_export_snapshot().unwrap();
            let incoming = IncomingSnapshot::with_identity(&exported, identity());
            drop(exported);
            let old = fixture
                .wal
                .native_receipt_source_for_test(request.request_id())
                .unwrap()
                .unwrap();
            let old_epoch = selected(&fixture)["native_generation"]["file_epoch"]
                .as_u64()
                .unwrap();
            let _release_build = Release(Arc::clone(&build));
            let _release_switch = Release(Arc::clone(&switched));
            let _release_poll = Release(Arc::clone(&poll));
            let _release_claim = Release(Arc::clone(&claim));
            let _release_next_claim = Release(Arc::clone(&next_claim));
            let _release_next_build = Release(Arc::clone(&next_build));
            build.arm();
            switched.arm();
            fixture.wal.checkpoint().unwrap();
            build.entered();
            build.release();
            switched.entered();
            std::thread::scope(|scope| {
                let _release_poll = Release(Arc::clone(&poll));
                let _release_claim = Release(Arc::clone(&claim));
                let _release_next_claim = Release(Arc::clone(&next_claim));
                let _release_next_build = Release(Arc::clone(&next_build));
                let _release_switch = Release(Arc::clone(&switched));
                let _clear_guard = ReleaseCeiling(&fixture.wal);
                claim.arm();
                next_claim.arm();
                let installer = scope.spawn(|| {
                    let conn = rusqlite::Connection::open_in_memory().unwrap();
                    fixture
                        .wal
                        .install_snapshot(&conn, incoming.source().unwrap())
                });
                claim.entered();
                poll.arm();
                next_build.arm();
                switched.release();
                poll.entered();
                // Hold the normal ceiling-checkpoint predicate after Async's
                // current capture has finished. It needs the retained relocation;
                // live-data capacity has not been reached.
                fixture.wal.native_hold_ceiling_checkpoint_for_test(true);
                claim.release();
                drop(
                    ownership_wait
                        .1
                        .test_wait_while(ownership_wait.0.lock().unwrap(), |waiting| !*waiting)
                        .unwrap(),
                );
                assert_eq!(
                    fixture.wal.native_capacity_handoff_for_test().unwrap()["install_pending"],
                    false
                );
                observe_idle.store(true, Ordering::Release);
                poll.release();
                // No new admission wakes this writer: withdrawal alone must make
                // retained relocation actionable, including a finished unit.
                drop(
                    idle.1
                        .test_wait_while(idle.0.lock().unwrap(), |done| !*done)
                        .unwrap(),
                );
                assert!(
                    old.upgrade().is_none(),
                    "the guarded checkpoint's relocation must release the retired source"
                );
                assert_eq!(
                    selected(&fixture)["native_generation"]["file_epoch"].as_u64(),
                    Some(old_epoch + 1)
                );
                fixture.wal.native_hold_ceiling_checkpoint_for_test(false);
                next_build.release();
                next_claim.release();
                installer.test_join().unwrap().unwrap();
            });
            assert!(fixture.wal.storage_health().1.is_none());
            assert!(matches!(
                status(&fixture.wal, &request),
                FencedTransitionV2Status::Recorded(_)
            ));
            fixture.wal.shutdown().unwrap();
            let opening = crate::sqlite::consensus::wal::native::Opening::new(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                None,
                Limits::default(),
                IoControl::default(),
            )
            .unwrap();
            let original = incoming.source().unwrap();
            let reopened = opening
                .finish_with_install_source(Some(&original), || Ok(()))
                .unwrap();
            assert!(matches!(
                status(&reopened, &request),
                FencedTransitionV2Status::Recorded(_)
            ));
            reopened.shutdown().unwrap();
        }
    });
}

#[test]
fn native_rollover_withdrawn_install_claim_preserves_queued_relocation() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let mut failures = Vec::new();
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            let build = Park::at(Point::AfterNativeBasisAdmission, false);
            let switched = Park::at(Point::AfterNativeSwitchSelection, false);
            let claimed_poll = Park::at(Point::AfterNativeBackgroundPoll, false);
            let next_build = Park::at(Point::BeforeBasisCreate, false);
            let observe_idle = Arc::new(AtomicBool::new(false));
            let idle = Arc::new((Mutex::new(false), Condvar::new()));
            let control = IoControl {
                native_rollover_bytes: Some(64 * 1024),
                hook: Arc::new({
                    let build = Arc::clone(&build);
                    let switched = Arc::clone(&switched);
                    let claimed_poll = Arc::clone(&claimed_poll);
                    let next_build = Arc::clone(&next_build);
                    let observe_idle = Arc::clone(&observe_idle);
                    let idle = Arc::clone(&idle);
                    move |point| {
                        build.hook(point)?;
                        switched.hook(point)?;
                        claimed_poll.hook(point)?;
                        if std::thread::current().name() == Some("session-native-compactor") {
                            next_build.hook(point)?;
                        }
                        if point == Point::NativeBackgroundRelocationIdle
                            && observe_idle.load(Ordering::Acquire)
                        {
                            *idle.0.lock().unwrap() = true;
                            idle.1.notify_all();
                        }
                        Ok(())
                    }
                }),
                ..IoControl::default()
            };
            let mut fixture =
                Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
            let request = fenced_transition_v2_request(0xD7, 1, "withdrawn-install-relocation");
            fixture.parity(&[formation(), activation(1, request.clone(), timestamp(1))]);
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
            let _release_switch = Release(Arc::clone(&switched));
            let _release_poll = Release(Arc::clone(&claimed_poll));
            let _release_next = Release(Arc::clone(&next_build));
            let source = fixture
                .wal
                .native_receipt_source_for_test(request.request_id())
                .unwrap()
                .unwrap();
            let old_epoch = selected(&fixture)["native_generation"]["file_epoch"]
                .as_u64()
                .unwrap();
            build.arm();
            switched.arm();
            fixture.wal.checkpoint().unwrap();
            build.entered();
            build.release();
            switched.entered();
            assert_eq!(
                selected(&fixture)["native_generation"]["file_epoch"].as_u64(),
                Some(old_epoch + 1)
            );
            assert!(!fixture
                .directory
                .path()
                .join(format!("wal/basis-{old_epoch:020}.native"))
                .exists());
            assert!(
                source.upgrade().is_some(),
                "queued resident relocation still pins the retired source"
            );

            // The switch has queued relocation, but no unit has started yet.
            // Model precisely the claim/yield State transitions of an unarmed
            // installer; the existing install proofs exercise the full handoff.
            fixture.wal.native_unarmed_install_claim_for_test(true);
            claimed_poll.arm();
            next_build.arm();
            switched.release();
            claimed_poll.entered();
            observe_idle.store(true, Ordering::Release);
            fixture.wal.native_unarmed_install_claim_for_test(false);
            // Queue work before releasing the writer, so the empty-queue RED
            // cannot park after the withdrawal's notification has already landed.
            let ticket = fixture
                .wal
                .native_submit_with_backpressure_for_test(Operation::Barrier)
                .unwrap();
            claimed_poll.release();
            ticket.wait().unwrap();
            drop(
                idle.1
                    .test_wait_while(idle.0.lock().unwrap(), |done| !*done)
                    .unwrap(),
            );
            if source.upgrade().is_some() {
                failures.push(format!("{mode:?}: withdrawing an unarmed claim discarded relocation and pinned the retired source"));
            }
            assert_eq!(
                selected(&fixture)["native_generation"]["file_epoch"].as_u64(),
                Some(old_epoch + 1),
                "relocation must release the old source without a later switch"
            );
            assert!(matches!(
                status(&fixture.wal, &request),
                FencedTransitionV2Status::Recorded(_)
            ));
            assert!(fixture.wal.storage_health().1.is_none());
            next_build.release();
            fixture.wal.shutdown().unwrap();
            let reopened = fixture.reopened();
            assert!(matches!(
                status(&reopened, &request),
                FencedTransitionV2Status::Recorded(_)
            ));
            reopened.shutdown().unwrap();
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}

#[test]
fn native_rollover_unarmed_install_claim_does_not_interrupt_guarded_waiters() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        let mut failures = Vec::new();
        for mode in [
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ] {
            // Both resource checks (before and after sleeping) and admission's
            // file guard must preserve a withdrawn, unarmed install claim.
            for (resource, claim_before_wait) in [(false, true), (true, true), (true, false)] {
                let (sent, received) = mpsc::channel();
                let control = IoControl {
                    hook: Arc::new({
                        let sent = sent.clone();
                        move |point| {
                            if point == Point::NativeFileGuardWaitStarted {
                                sent.send(None).unwrap();
                            }
                            Ok(())
                        }
                    }),
                    ..IoControl::default()
                };
                let fixture = Fixture::with_persistence(Limits::default(), control, mode);
                fixture.wal.native_live_capacity_guard_for_test(true);
                fixture
                    .wal
                    .native_unarmed_install_claim_for_test(claim_before_wait);
                std::thread::scope(|scope| {
                    let waiter = scope.spawn(|| {
                        let result = fixture.wal.native_wait_at_guard_for_test(resource);
                        sent.send(Some(result.is_ok())).unwrap();
                    });
                    let first = received.test_recv().unwrap();
                    let completed = if first.is_none() {
                        if resource {
                            fixture.wal.native_unarmed_install_claim_for_test(true);
                        } else {
                            fixture.wal.native_live_capacity_guard_for_test(false);
                        }
                        received.test_recv().unwrap().unwrap()
                    } else {
                        false
                    };
                    fixture.wal.native_unarmed_install_claim_for_test(false);
                    fixture.wal.native_live_capacity_guard_for_test(false);
                    waiter.test_join().unwrap();
                    if first.is_some() || !completed {
                        failures.push(format!("{mode:?}, resource={resource}, early_claim={claim_before_wait}: unarmed claim interrupted a guarded waiter"));
                    }
                });
                assert!(fixture.wal.storage_health().1.is_none());
                fixture.wal.shutdown().unwrap();
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}
