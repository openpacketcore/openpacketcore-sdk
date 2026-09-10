use super::*;

fn statuses(
    wal: &Wal,
    requests: &[FencedTransitionV2Request],
) -> io::Result<Vec<FencedTransitionV2Status>> {
    wal.with_native_receipt_read(requests, |state, receipts| {
        requests
            .iter()
            .map(|request| {
                match receipts {
                    Some(receipts) => state.status_with_receipts(request, receipts),
                    None => state.status(request),
                }
                .map_err(|_| io::Error::other("native selected cohort status"))
            })
            .collect()
    })
}

#[test]
fn native_selected_receipt_cohort_resolves_newly_bound_and_newly_relocated_rows() {
    for previously_bound in [false, true] {
        let gate = Gate::new(Point::BeforeNativeReceiptRead, 1);
        let fixture = Fixture::with_control(Limits::default(), gate.control());
        let first = fenced_transition_v2_request(0xF2, 1, "native-cold-cohort-first");
        let second = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
        fixture.parity(&[formation(), activation(1, first.clone(), timestamp(1))]);
        fixture.wal.checkpoint().unwrap();
        until(|| {
            fixture
                .wal
                .native_cold_counts_for_test()
                .is_ok_and(|counts| counts == [1, 1, 2])
        });
        let entry = fenced_transition_v2_entry(2, second.clone(), timestamp(2));
        if previously_bound {
            fixture.parity(std::slice::from_ref(&entry));
        }
        let requests = [first, second];
        std::thread::scope(|scope| {
            let read = scope.spawn(|| statuses(&fixture.wal, &requests));
            gate.entered();
            if !previously_bound {
                fixture.parity(std::slice::from_ref(&entry));
            }
            fixture.wal.checkpoint().unwrap();
            until(|| {
                fixture
                    .wal
                    .native_cold_counts_for_test()
                    .is_ok_and(|counts| counts == [2, 2, 3])
            });
            let oracle = requests
                .iter()
                .map(|request| {
                    read_fenced_transition_v2_status_sync(
                        &fixture.oracle.conn.blocking_lock(),
                        identity(),
                        identity(),
                        request,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            gate.release();
            assert_eq!(
                read.join().unwrap().unwrap(),
                oracle,
                "one final cohort uses current state for both complete IDs"
            );
        });
        assert_eq!(
            gate.hits.load(Ordering::SeqCst),
            if previously_bound { 1 } else { 2 },
            "resident revision pins need no reread; an unseen ID needs one additional pass"
        );
        fixture
            .wal
            .submit(Operation::Barrier)
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.shutdown().unwrap();
    }
}

#[test]
fn native_detached_receipt_log_and_snapshot_failures_fence_wake_and_join() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    for point in [
        Point::BeforeNativeReceiptRead,
        Point::BeforeNativeLogRead,
        Point::BeforeNativeSnapshotRead,
        Point::BeforeNativeApplyPrepare,
        Point::BeforeNativeApplyPublish,
        Point::BeforeNativePublicRead,
    ] {
        for panic in [false, true] {
            let cut = Gate::new(Point::BeforeCutPublish, 1);
            let armed = Arc::new(AtomicBool::new(false));
            let hooks = (Arc::clone(&cut), Arc::clone(&armed));
            let control = IoControl {
                hook: Arc::new(move |current| {
                    if !hooks.1.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    hooks.0.hook(current)?;
                    if current == point {
                        if panic {
                            panic!("injected detached native read panic");
                        }
                        return Err(io::Error::other(
                            "injected detached native read I/O failure",
                        ));
                    }
                    Ok(())
                }),
                ..IoControl::default()
            };
            let fixture = Fixture::with_control(Limits::default(), control);
            let request = fenced_transition_v2_request(0xF3, 1, "native-detached-failure");
            fixture.parity(&[formation(), activation(1, request.clone(), timestamp(1))]);
            fixture.wal.checkpoint().unwrap();
            until(|| {
                fixture
                    .wal
                    .native_cold_counts_for_test()
                    .is_ok_and(|counts| counts == [1, 1, 2])
            });
            armed.store(true, Ordering::SeqCst);
            let inflight = fixture
                .wal
                .submit(append(&[Entry {
                    log_id: log_id(2),
                    payload: EntryPayload::Blank,
                }]))
                .unwrap();
            cut.entered();
            let queued = fixture.wal.submit(Operation::Barrier).unwrap();
            let failure = catch_unwind(AssertUnwindSafe(|| match point {
                Point::BeforeNativeReceiptRead => {
                    statuses(&fixture.wal, std::slice::from_ref(&request)).map(|_| ())
                }
                Point::BeforeNativeLogRead => fixture.wal.read(0, 2).map(|_| ()),
                Point::BeforeNativeSnapshotRead => fixture.wal.native_export_snapshot().map(drop),
                Point::BeforeNativePublicRead => fixture
                    .wal
                    .native_public_read(&|| Ok(()), |state, _| {
                        state.get_at(request.lease().key(), timestamp(2))
                    })
                    .map(drop),
                Point::BeforeNativeApplyPrepare | Point::BeforeNativeApplyPublish => {
                    fixture.wal.native_apply_committed(&[]).map(drop)
                }
                _ => unreachable!(),
            }));
            if panic {
                assert!(failure.is_err());
            } else {
                assert!(failure.unwrap().is_err());
            }
            assert!(fixture
                .wal
                .with_native_read(|state| Ok(state.applied()))
                .is_err());
            assert!(fixture.wal.native_apply_committed(&[]).is_err());
            assert!(fixture.wal.submit(Operation::Barrier).is_err());
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
            assert!(inflight.wait().is_err());
            assert!(fixture.wal.shutdown().is_err());
            let reopened = Wal::open(
                &fixture.directory.path().join("wal"),
                fixture.wal.binding(),
                Limits::default(),
                IoControl::default(),
            )
            .unwrap();
            assert!(matches!(
                status(&reopened, &request),
                FencedTransitionV2Status::Recorded(_)
            ));
            reopened.shutdown().unwrap();
        }
    }
}

#[test]
fn native_selected_log_read_returns_eight_full_256_request_rows_with_shared_memory_bound() {
    let fixture = Fixture::new();
    let initial = fenced_transition_v2_request(0xF4, 1, "native-log-output-bound");
    fixture.parity(&[formation(), activation(1, initial, timestamp(1))]);
    let count = crate::consensus::types::MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS;
    assert_eq!(count, 256);
    let entries = (0..8)
        .map(|batch| {
            let requests = (0..count)
                .map(|slot| sdk741_component_request(Sdk741Payload::Create, 10 + batch, slot, None))
                .collect::<Vec<_>>();
            fenced_transition_v2_batch_entry(2 + batch as u64, requests, timestamp(2 + batch as u8))
        })
        .collect::<Vec<_>>();
    fixture.parity(&entries);
    fixture.wal.checkpoint().unwrap();
    until(|| {
        fixture
            .wal
            .native_cold_counts_for_test()
            .is_ok_and(|counts| counts == [2049, 2049, 10])
    });
    let output = fixture.wal.native_log_read(2, Some(10), Some(64)).unwrap();
    assert_eq!(
        encode_json(&output).unwrap(),
        encode_json(&entries).unwrap()
    );
    assert_eq!(
        output.len(),
        8,
        "all completed copy guards coexist under the unchanged process cap"
    );
    drop(output);
    let reopened = fixture.reopened();
    assert_eq!(
        encode_json(&reopened.native_log_read(2, Some(10), Some(64)).unwrap()).unwrap(),
        encode_json(&entries).unwrap()
    );
    reopened.shutdown().unwrap();
}
