//! The live writer, durable selector and original incoming-source recovery
//! participate in these checks; a standalone converted image is insufficient.

use super::install_base::copy;
use super::*;
use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
use crate::sqlite::consensus::wal::{snapshot::InstallSource, Point};
use crate::sqlite::ops::RestoreScanIncarnation;
use opc_consensus::engine::Vote;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Condvar, Mutex,
};
use std::time::Instant;

fn destination(
    signed: &RosterV2PersistenceFixture,
    control: IoControl,
) -> (tempfile::TempDir, SqliteSessionBackend, Wal) {
    let directory = tempfile::tempdir().unwrap();
    let backend = SqliteSessionBackend::open(directory.path().join("primary.sqlite")).unwrap();
    initialize(&backend, signed);
    let wal = Wal::create_native_with_root(
        &directory.path().join("wal"),
        &backend.conn.blocking_lock(),
        signed.identity,
        [0xED; 32],
        Some(Arc::new(signed.root.clone())),
        Limits::default(),
        control,
    )
    .unwrap();
    (directory, backend, wal)
}

fn selected(directory: &Path) -> serde_json::Value {
    let bytes = fs::read(directory.join("wal/CURRENT")).unwrap();
    serde_json::from_slice(&bytes[8..bytes.len() - 32]).unwrap()
}

fn restored(
    wal: &Wal,
    directory: &Path,
    signed: &RosterV2PersistenceFixture,
    incoming: &IncomingSnapshot,
) -> Wal {
    let opening = Opening::new(
        &directory.join("wal"),
        wal.binding(),
        Some(Arc::new(signed.root.clone())),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    assert_eq!(
        opening.install_candidate(),
        Some(incoming.candidate.clone())
    );
    assert!(opening.snapshots().contains(&incoming.candidate));
    let source = incoming.source().unwrap();
    opening
        .finish_with_install_source(Some(&source), || source.verify())
        .unwrap()
}

fn exact(wal: &Wal, expected: &Connection, signed: &RosterV2PersistenceFixture) {
    let actual = wal.native_export_install_base_for_test().unwrap();
    assert!(
        database(&actual) == database(expected),
        "every schema object, column, retained log, vote and local restore identity"
    );
    validate_fixed_durable_state_sync(&actual, signed.identity, &fixed_members()).unwrap();
    validate_protected_roster_recovery_state_sync(&actual, signed.identity).unwrap();
    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
}

#[test]
fn native_durable_install_original_transaction_preserves_vote_suffix_and_every_column_after_reopen()
{
    for phase in [Phase::Established, Phase::Aborted] {
        let (_producer_dir, producer, signed, producer_wal) = fresh(phase);
        parity(
            &producer_wal,
            &producer,
            &signed,
            &[admission(&signed), terminal(&signed, 4)],
        );
        let incoming =
            IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
        let (directory, primary, wal) = destination(&signed, IoControl::default());
        parity(&wal, &primary, &signed, &setup(&signed));
        let suffix = ordinary(&signed, 5, SessionMutationIntent::AdvanceLogicalTime);
        let retained = [admission(&signed), terminal(&signed, 4), suffix.clone()];
        wal.submit(append(&retained)).unwrap().wait().unwrap();
        let vote = Vote::new_committed(9, node_id());
        wal.submit(Operation::Vote(vote)).unwrap().wait().unwrap();
        {
            let conn = primary.conn.blocking_lock();
            append_logs_with_authority_sync(
                &conn,
                signed.identity,
                ConsensusAuthorityProfile::FixedImmutable,
                &fixed_members(),
                &test_member_bindings(&fixed_members()),
                FIXED_TEST_PLACEMENT_POLICY,
                &retained,
            )
            .unwrap();
            save_vote_sync(&conn, signed.identity, &vote).unwrap();
        }
        let before = database(&primary.conn.blocking_lock());
        let expected = copy(&primary.conn.blocking_lock());
        wal.install_snapshot(&primary.conn.blocking_lock(), incoming.source().unwrap())
            .unwrap();
        assert_eq!(
            database(&primary.conn.blocking_lock()),
            before,
            "installation never mutates the live SQL cache"
        );
        let actual = wal.native_export_install_base_for_test().unwrap();
        let incarnation = RestoreScanIncarnation::from_installed_sync(&actual).unwrap();
        incoming
            .source()
            .unwrap()
            .apply_native_original(
                &expected,
                wal.binding(),
                Some(&signed.root),
                &incarnation,
                &|| Ok(()),
            )
            .unwrap();
        exact(&wal, &expected, &signed);
        assert_eq!(
            read_vote_sync(&actual, signed.identity).unwrap(),
            Some(vote)
        );
        assert_eq!(
            read_applied_sync(&actual, signed.identity).unwrap(),
            Some(log_id(4))
        );
        assert_eq!(
            read_committed_sync(&actual, signed.identity).unwrap(),
            Some(log_id(4))
        );
        assert_eq!(
            read_purged_sync(&actual, signed.identity).unwrap(),
            Some(log_id(4))
        );
        assert_eq!(count(&actual, "consensus_log"), 1);
        assert_eq!(
            encode_json(&wal.native_log_read(5, None, Some(2)).unwrap()).unwrap(),
            encode_json(&std::slice::from_ref(&suffix)).unwrap()
        );
        wal.checkpoint().unwrap();
        wal.shutdown().unwrap();
        let reopened = restored(&wal, directory.path(), &signed, &incoming);
        exact(&reopened, &expected, &signed);
        reopened
            .submit(Operation::Committed(Some(log_id(5))))
            .unwrap()
            .wait()
            .unwrap();
        let applied = reopened
            .native_apply_committed(std::slice::from_ref(&suffix))
            .unwrap();
        expected.pragma_update(None, "query_only", false).unwrap();
        save_committed_with_authority_sync(
            &expected,
            signed.identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            FIXED_TEST_PLACEMENT_POLICY,
            Some(log_id(5)),
        )
        .unwrap();
        let sql = apply_entries_with_authority_sync(
            &expected,
            signed.identity,
            &primary.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            FIXED_TEST_PLACEMENT_POLICY,
            vec![suffix],
        )
        .unwrap();
        assert_eq!(
            encode_json(&applied.responses).unwrap(),
            encode_json(&sql.responses).unwrap()
        );
        assert_eq!(
            encode_json(&applied.notifications).unwrap(),
            encode_json(&sql.notifications).unwrap()
        );
        exact(&reopened, &expected, &signed);
        reopened.checkpoint().unwrap();
        reopened.shutdown().unwrap();
        let final_owner = restored(&reopened, directory.path(), &signed, &incoming);
        exact(&final_owner, &expected, &signed);
        final_owner.shutdown().unwrap();
        producer_wal.shutdown().unwrap();
    }
}

#[test]
fn native_durable_install_empty_sequence_rotates_once_per_install_and_reopens_first_membership() {
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let (directory, primary, mut wal) = destination(&signed, IoControl::default());
    let incoming = IncomingSnapshot::with_identity(&primary.conn.blocking_lock(), signed.identity);
    let mut previous = RestoreScanIncarnation::from_installed_sync(&primary.conn.blocking_lock())
        .unwrap()
        .native_image();
    let mut epoch = selected(directory.path())["epoch"].as_u64().unwrap();
    for _ in 0..2 {
        wal.install_snapshot(&primary.conn.blocking_lock(), incoming.source().unwrap())
            .unwrap();
        let anchor = selected(directory.path());
        assert_eq!(anchor["position"]["sequence"], 0);
        assert_eq!(anchor["epoch"].as_u64().unwrap(), epoch + 1);
        assert_eq!(anchor["native_generation"]["file_epoch"], anchor["epoch"]);
        epoch += 1;
        let actual = wal.native_export_install_base_for_test().unwrap();
        let installed = RestoreScanIncarnation::from_installed_sync(&actual)
            .unwrap()
            .native_image();
        assert!(
            installed != previous,
            "each newly acknowledged install gets its own local restore identity"
        );
        assert!(read_applied_sync(&actual, signed.identity)
            .unwrap()
            .is_none());
        assert!(read_committed_sync(&actual, signed.identity)
            .unwrap()
            .is_none());
        assert!(read_purged_sync(&actual, signed.identity)
            .unwrap()
            .is_none());
        wal.shutdown().unwrap();
        wal = restored(&wal, directory.path(), &signed, &incoming);
        exact(&wal, &actual, &signed);
        assert!(
            RestoreScanIncarnation::from_installed_sync(
                &wal.native_export_install_base_for_test().unwrap()
            )
            .unwrap()
            .native_image()
                == installed,
            "cold admission preserves the selected choice instead of rotating again"
        );
        previous = installed;
    }
    commit(&wal, &[formation()]);
    wal.native_apply_committed(&[formation()]).unwrap();
    wal.checkpoint().unwrap();
    wal.shutdown().unwrap();
    let reopened = restored(&wal, directory.path(), &signed, &incoming);
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(0))
    );
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(*state.membership().log_id()))
            .unwrap(),
        Some(log_id(0))
    );
    assert!(
        RestoreScanIncarnation::from_installed_sync(
            &reopened.native_export_install_base_for_test().unwrap()
        )
        .unwrap()
        .native_image()
            == previous
    );
    reopened.shutdown().unwrap();
}

#[test]
fn native_durable_install_retains_original_with_later_local_snapshot_and_rejects_substitution_before_repair(
) {
    let (_producer_dir, producer, signed, producer_wal) = fresh(Phase::Established);
    parity(
        &producer_wal,
        &producer,
        &signed,
        &[admission(&signed), terminal(&signed, 4)],
    );
    let incoming = IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
    let (directory, primary, wal) = destination(&signed, IoControl::default());
    wal.install_snapshot(&primary.conn.blocking_lock(), incoming.source().unwrap())
        .unwrap();
    let mut later =
        IncomingSnapshot::with_identity(&wal.native_export_snapshot().unwrap(), signed.identity);
    later.candidate.0.snapshot_id = wal.native_snapshot_id().unwrap();
    wal.native_publish_snapshot(later.candidate.clone())
        .unwrap();
    let retained = vec![incoming.candidate.clone(), later.candidate.clone()];
    assert_eq!(wal.native_retained_snapshots().unwrap(), retained);
    let later_source = later.source().unwrap();
    later_source.verify().unwrap();
    incoming.source().unwrap().verify().unwrap();
    let suffix = terminal(&signed, 5);
    commit(&wal, std::slice::from_ref(&suffix));
    wal.shutdown().unwrap();
    let before = files(&directory.path().join("wal"));
    let original_source = incoming.source().unwrap();
    for wrong in 0..3 {
        let root = if wrong == 2 {
            wrong_root(&signed)
        } else {
            Arc::new(signed.root.clone())
        };
        let attempt = Opening::new(
            &directory.path().join("wal"),
            wal.binding(),
            Some(root),
            Limits::default(),
            IoControl::default(),
        )
        .and_then(|opening| {
            assert_eq!(opening.snapshots(), retained);
            assert_eq!(
                opening.install_candidate(),
                Some(incoming.candidate.clone())
            );
            opening.finish_with_install_source(
                match wrong {
                    0 => None,
                    1 => Some(&later_source),
                    _ => Some(&original_source),
                },
                || Ok(()),
            )
        });
        assert!(
            attempt.is_err(),
            "missing source, later local source and wrong configured root all reject"
        );
        assert_eq!(
            files(&directory.path().join("wal")),
            before,
            "failed admission cannot repair or start an owner"
        );
    }
    let origin = incoming.source().unwrap();
    wal.native_audit_closed(
        |snapshots, selected| {
            assert_eq!(snapshots, retained);
            assert_eq!(selected, Some(incoming.candidate.clone()));
            Ok((origin, later_source))
        },
        |sources| Some(&sources.0),
        |sources| {
            sources.0.verify()?;
            sources.1.verify()
        },
        |state| {
            assert_eq!(
                state.applied(),
                Some(log_id(5)),
                "joined audit replays the actual acknowledged suffix"
            );
            assert_eq!(state.current_snapshot(), Some(later.candidate.clone()));
            assert_eq!(
                state.get(signed.authority.key()),
                producer_wal
                    .with_native_read(|state| Ok(state.get(signed.authority.key())))
                    .unwrap()
            );
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        files(&directory.path().join("wal")),
        before,
        "closed audit holds admission and never repairs or starts a writer"
    );
    let reopened = restored(&wal, directory.path(), &signed, &incoming);
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(5))
    );
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.current_snapshot()))
            .unwrap(),
        Some(later.candidate.clone())
    );
    assert_eq!(reopened.native_retained_snapshots().unwrap(), retained);
    assert_eq!(
        encode_json(&reopened.native_log_read(5, None, Some(2)).unwrap()).unwrap(),
        encode_json(&[suffix]).unwrap()
    );
    reopened.shutdown().unwrap();
    producer_wal.shutdown().unwrap();
}

#[test]
fn native_durable_install_interrupted_publication_recovers_only_selected_original_or_installed_state(
) {
    let (_producer_dir, producer, signed, producer_wal) = fresh(Phase::Established);
    parity(
        &producer_wal,
        &producer,
        &signed,
        &[admission(&signed), terminal(&signed, 4)],
    );
    let incoming = IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
    for point in [
        Point::BeforeBasisSync,
        Point::AfterBasisDirectorySync,
        Point::AfterNativeBasisAdmission,
        Point::BeforeBasisSelector,
        Point::BeforeBasisPublicationSync,
        Point::BeforeBasisReclaim,
    ] {
        let armed = Arc::new(AtomicBool::new(false));
        let triggered = Arc::new(AtomicBool::new(false));
        let flags = (Arc::clone(&armed), Arc::clone(&triggered));
        let control = IoControl {
            hook: Arc::new(move |actual| {
                if actual == point && flags.0.swap(false, Ordering::SeqCst) {
                    flags.1.store(true, Ordering::SeqCst);
                    return Err(io::Error::other("native install original fault"));
                }
                Ok(())
            }),
            ..IoControl::default()
        };
        let (directory, primary, wal) = destination(&signed, control);
        parity(&wal, &primary, &signed, &setup(&signed));
        let before = database(&wal.native_export_install_base_for_test().unwrap());
        let old_epoch = selected(directory.path())["epoch"].as_u64().unwrap();
        armed.store(true, Ordering::SeqCst);
        assert!(wal
            .install_snapshot(&primary.conn.blocking_lock(), incoming.source().unwrap())
            .is_err());
        assert!(
            triggered.load(Ordering::SeqCst),
            "the declared original fault actually executed: {point:?}"
        );
        assert!(
            wal.shutdown().is_err(),
            "an indeterminate install fences and joins its writer"
        );
        let new = matches!(
            point,
            Point::BeforeBasisPublicationSync | Point::BeforeBasisReclaim
        );
        assert_eq!(
            selected(directory.path())["epoch"].as_u64().unwrap(),
            old_epoch + u64::from(new)
        );
        let opening = Opening::new(
            &directory.path().join("wal"),
            wal.binding(),
            Some(Arc::new(signed.root.clone())),
            Limits::default(),
            IoControl::default(),
        )
        .unwrap();
        let source = incoming.source().unwrap();
        assert_eq!(
            opening.install_candidate(),
            new.then(|| incoming.candidate.clone())
        );
        let recovered = opening
            .finish_with_install_source(new.then_some(&source), || source.verify())
            .unwrap();
        let actual = recovered.native_export_install_base_for_test().unwrap();
        if new {
            let expected = copy(&primary.conn.blocking_lock());
            source
                .apply_native_original(
                    &expected,
                    wal.binding(),
                    Some(&signed.root),
                    &RestoreScanIncarnation::from_installed_sync(&actual).unwrap(),
                    &|| Ok(()),
                )
                .unwrap();
            assert!(database(&actual) == database(&expected));
            assert_eq!(
                recovered
                    .with_native_read(|state| Ok(state.current_snapshot()))
                    .unwrap(),
                Some(incoming.candidate.clone())
            );
        } else {
            assert!(
                database(&actual) == before,
                "only the old selector's exact acknowledged suffix is replayed"
            );
        }
        assert_eq!(recovered.native_sql_fallback_count().unwrap(), 0);
        recovered.shutdown().unwrap();
    }
    producer_wal.shutdown().unwrap();
}

struct Gate {
    point: Point,
    armed: AtomicBool,
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Gate {
    fn new(point: Point) -> Arc<Self> {
        Arc::new(Self {
            point,
            armed: AtomicBool::new(false),
            state: Mutex::new((false, false)),
            changed: Condvar::new(),
        })
    }
    fn control(self: &Arc<Self>) -> IoControl {
        let gate = Arc::clone(self);
        IoControl {
            hook: Arc::new(move |point| {
                if point != gate.point || !gate.armed.swap(false, Ordering::SeqCst) {
                    return Ok(());
                }
                let mut state = gate.state.lock().unwrap();
                state.0 = true;
                gate.changed.notify_all();
                let (state, _) = gate
                    .changed
                    .wait_timeout_while(state, Duration::from_secs(10), |state| !state.1)
                    .unwrap();
                if !state.1 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "native install test gate not released",
                    ));
                }
                Ok(())
            }),
            ..IoControl::default()
        }
    }
    fn entered(&self) {
        let (state, _) = self
            .changed
            .wait_timeout_while(
                self.state.lock().unwrap(),
                Duration::from_secs(10),
                |state| !state.0,
            )
            .unwrap();
        assert!(state.0, "old owner reached declared boundary");
    }
    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

#[test]
fn native_durable_install_drains_captured_reads_apply_and_relocation_before_releasing_new_admission(
) {
    let producer = Fixture::new();
    let initial = fenced_transition_v2_request(0xED, 1, "native-install-captured-receipt");
    producer.parity(&[formation(), activation(1, initial.clone(), timestamp(1))]);
    let later = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
    let entry = fenced_transition_v2_entry(2, later.clone(), timestamp(2));
    producer.parity(std::slice::from_ref(&entry));
    let incoming =
        IncomingSnapshot::with_identity(&producer.oracle.conn.blocking_lock(), identity());
    for point in [
        Point::BeforeNativeApplyPrepare,
        Point::BeforeNativeLogRead,
        Point::BeforeNativeSnapshotRead,
        Point::BeforeNativeReceiptRead,
        Point::AfterNativeRelocationStep,
    ] {
        let gate = Gate::new(point);
        let fixture = Fixture::with_control(Limits::default(), gate.control());
        fixture.parity(&[formation(), activation(1, initial.clone(), timestamp(1))]);
        if point != Point::AfterNativeRelocationStep {
            fixture.wal.checkpoint().unwrap();
        }
        if point == Point::BeforeNativeApplyPrepare {
            fixture.append_commit(std::slice::from_ref(&entry));
        }
        let before_requests = fixture.wal.integration_cost_snapshot().unwrap()["requests"]
            .as_u64()
            .unwrap();
        gate.armed.store(true, Ordering::SeqCst);
        std::thread::scope(|scope| {
            let old = scope.spawn(|| match point {
                Point::BeforeNativeApplyPrepare => {
                    assert!(fixture
                        .wal
                        .native_apply_committed(std::slice::from_ref(&entry))
                        .unwrap()
                        .responses[0]
                        .result
                        .is_ok());
                }
                Point::BeforeNativeLogRead => {
                    assert_eq!(
                        fixture
                            .wal
                            .native_log_read(0, Some(2), Some(2))
                            .unwrap()
                            .len(),
                        2
                    );
                }
                Point::BeforeNativeSnapshotRead => {
                    assert_eq!(
                        read_applied_sync(
                            &fixture.wal.native_export_snapshot().unwrap(),
                            identity()
                        )
                        .unwrap(),
                        Some(log_id(1))
                    );
                }
                Point::BeforeNativeReceiptRead => {
                    assert_eq!(
                        status(&fixture.wal, &initial),
                        status(&producer.wal, &initial)
                    );
                }
                Point::AfterNativeRelocationStep => {
                    fixture.wal.checkpoint().unwrap();
                }
                _ => unreachable!(),
            });
            gate.entered();
            let source = incoming.source().unwrap();
            let wal = &fixture.wal;
            let primary = &fixture.oracle;
            let install =
                scope.spawn(move || wal.install_snapshot(&primary.conn.blocking_lock(), source));
            let started = Instant::now();
            while !fixture.wal.native_install_waiting_for_test().unwrap() {
                assert!(started.elapsed() < Duration::from_secs(10));
                std::thread::yield_now();
            }
            let (entered_tx, entered_rx) = mpsc::channel();
            let (completed_tx, completed_rx) = mpsc::channel();
            let next = scope.spawn(move || {
                entered_tx.send(()).unwrap();
                let result = wal
                    .submit(Operation::Barrier)
                    .and_then(|pending| pending.wait());
                completed_tx.send(result).unwrap();
            });
            entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert!(matches!(
                completed_rx.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
            gate.release();
            old.join().unwrap();
            install.join().unwrap().unwrap();
            completed_rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap()
                .unwrap();
            next.join().unwrap();
        });
        assert_eq!(
            fixture.wal.integration_cost_snapshot().unwrap()["requests"]
                .as_u64()
                .unwrap(),
            before_requests + 1,
            "the held admission completes exactly once after installation"
        );
        assert_eq!(status(&fixture.wal, &later), status(&producer.wal, &later));
        assert_eq!(
            fixture
                .wal
                .with_native_read(|state| Ok(state.applied()))
                .unwrap(),
            Some(log_id(2))
        );
        fixture.wal.shutdown().unwrap();
        let source = incoming.source().unwrap();
        let reopened = Opening::new(
            &fixture.directory.path().join("wal"),
            fixture.wal.binding(),
            None,
            Limits::default(),
            IoControl::default(),
        )
        .unwrap()
        .finish_with_install_source(Some(&source), || source.verify())
        .unwrap();
        assert_eq!(status(&reopened, &initial), status(&producer.wal, &initial));
        assert_eq!(status(&reopened, &later), status(&producer.wal, &later));
        reopened.shutdown().unwrap();
    }
    producer.wal.shutdown().unwrap();
}

#[test]
fn native_durable_install_joined_closed_audit_preserves_full_original_receipts_and_files() {
    let producer = Fixture::new();
    let initial = fenced_transition_v2_request(0xEE, 1, "native-install-closed-receipt");
    let creates = (0..8)
        .map(|slot| sdk741_component_request(Sdk741Payload::Create, 2, slot, None))
        .collect::<Vec<_>>();
    producer.parity(&[
        formation(),
        activation(1, initial.clone(), timestamp(1)),
        fenced_transition_v2_batch_entry(2, creates.clone(), timestamp(2)),
    ]);
    let incoming =
        IncomingSnapshot::with_identity(&producer.oracle.conn.blocking_lock(), identity());
    let destination = Fixture::new();
    destination
        .wal
        .install_snapshot(
            &destination.oracle.conn.blocking_lock(),
            incoming.source().unwrap(),
        )
        .unwrap();
    destination.wal.checkpoint().unwrap();
    destination.wal.shutdown().unwrap();
    let before = files(&destination.directory.path().join("wal"));
    let source = incoming.source().unwrap();
    destination
        .wal
        .native_audit_closed(
            |snapshots, origin| {
                assert_eq!(snapshots, vec![incoming.candidate.clone()]);
                assert_eq!(origin, Some(incoming.candidate.clone()));
                Ok(source)
            },
            |source| Some(source),
            InstallSource::verify,
            |state| {
                assert_eq!(state.applied(), Some(log_id(2)));
                for request in std::iter::once(&initial).chain(&creates) {
                    let expected = read_fenced_transition_v2_status_sync(
                        &producer.oracle.conn.blocking_lock(),
                        identity(),
                        identity(),
                        request,
                    )
                    .unwrap();
                    assert!(matches!(&expected, FencedTransitionV2Status::Recorded(_)));
                    assert_eq!(
                        state.status(request).unwrap(),
                        expected,
                        "complete original committed receipt including witness and ordinal"
                    );
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(files(&destination.directory.path().join("wal")), before);
    assert_eq!(destination.wal.native_sql_fallback_count().unwrap(), 0);
    producer.wal.shutdown().unwrap();
}
