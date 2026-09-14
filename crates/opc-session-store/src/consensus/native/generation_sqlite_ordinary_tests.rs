use super::*;
use crate::consensus::native::changes::tests::{apply, clock, fixture, time};
use crate::consensus::verified_snapshot::PROCESS_VERIFICATION_BYTES;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

fn request(index: usize) -> SessionConsensusRequestId {
    SessionConsensusRequestId::from_bytes((index as u128 + 1000).to_be_bytes())
}

fn fixture_rows(count: usize) -> (Connection, Context, NativeOrdinaryReceipt) {
    let (mut storage, _, _) = fixture();
    apply(&mut storage, &[clock(2, time(2))]);
    let (_, original) = storage.business.generic_receipts.iter().next().unwrap();
    let NativeGenericReceipt::Ordinary(original) = &**original else {
        panic!("ordinary clock receipt");
    };
    let mut context = Version::capture(&storage).unwrap().context();
    context.business.counts[2] = 0;
    context.business.content[2] = [0; 32];
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE consensus_request_outcomes(configuration_epoch,request_id,payload_digest,response_json)").unwrap();
    for index in 0..count {
        conn.execute(
            "INSERT INTO consensus_request_outcomes VALUES(?1,?2,?3,?4)",
            params![
                context.business.identity.configuration_epoch().get(),
                request(index).as_bytes().as_slice(),
                original.payload_digest.as_slice(),
                serde_json::to_vec(&original.response).unwrap(),
            ],
        )
        .unwrap();
    }
    (conn, context, original.clone())
}

fn bounded_rows(count: usize, shape: usize) -> (Connection, Context) {
    let (conn, context, mut original) = fixture_rows(count);
    if shape == 0 {
        return (conn, context);
    }
    let (_, _, previous) = fixture();
    for index in 0..count {
        let kind = if shape == 3 { index % 3 } else { shape };
        original.response.result = Ok(match kind {
            0 => SessionMutationOutcome::Unit,
            1 => SessionMutationOutcome::Lease(previous.lease().clone()),
            _ => {
                SessionMutationOutcome::CompareAndSet(crate::backend::CompareAndSetResult::Success)
            }
        });
        conn.execute(
            "UPDATE consensus_request_outcomes SET response_json=?1 WHERE request_id=?2",
            params![
                serde_json::to_vec(&original.response).unwrap(),
                request(index).as_bytes().as_slice()
            ],
        )
        .unwrap();
    }
    (conn, context)
}

// The complete pre-change ordinary loop is the oracle, including its separate
// per-ID SQL reader and streaming writer. It does not call candidate helpers.
fn original_serial(
    tx: &Transaction<'_>,
    writer: &mut dyn Write,
    context: &mut Context,
) -> io::Result<()> {
    let mut statement = tx.prepare("SELECT request_id,COALESCE(length(response_json),0) FROM consensus_request_outcomes ORDER BY request_id").map_err(db)?;
    let mut rows = statement.query([]).map_err(db)?;
    while let Some(row) = rows.next().map_err(db)? {
        let id = SessionConsensusRequestId::from_bytes(scalar(row, 0)?);
        let length: usize = row.get(1).map_err(db)?;
        if length > MAX_ITEM {
            return Err(invalid(
                "native SQL generic response exceeds original bound",
            ));
        }
        let _memory = row_memory(length)?;
        let (payload_digest, response) = source::ordinary(tx, context.business.identity, id)?;
        let receipt = NativeGenericReceipt::Ordinary(NativeOrdinaryReceipt {
            payload_digest,
            response: Box::new(response),
        });
        validation::validate_generic(&id, &receipt, &context.business.frontiers)?;
        account(
            &mut context.business.counts[2],
            &mut context.business.content[2],
            receipt.row_fingerprint(2, &id)?,
            validation::MAX_ITEMS,
        )?;
        writer.write_all(&[2])?;
        write_before(writer, None)?;
        write_binary(writer, &(id, Some(&receipt)))?;
    }
    Ok(())
}

struct Budget {
    used: &'static AtomicUsize,
    limit: usize,
    peak: Cell<usize>,
}

impl Budget {
    fn new(used: &'static AtomicUsize, limit: usize) -> Self {
        assert_eq!(used.load(Ordering::Acquire), 0);
        OBSERVED.with(|value| *value.borrow_mut() = Observation::default());
        Self {
            used,
            limit,
            peak: Cell::new(0),
        }
    }

    fn reserve(&self, bytes: usize) -> io::Result<VerificationMemory> {
        let memory = VerificationMemory::reserve_for_test(self.used, bytes, self.limit)?;
        self.peak
            .set(self.peak.get().max(self.used.load(Ordering::Acquire)));
        Ok(memory)
    }

    fn released(&self) {
        assert_eq!(self.used.load(Ordering::Acquire), 0);
        assert!(self.peak.get() <= self.limit);
        OBSERVED.with(|value| {
            let value = value.borrow();
            assert_eq!(value.started, value.joined);
            assert!(value.max_rows <= ROWS);
            assert!(value.max_bytes <= BYTES);
        });
    }
}

fn candidate(
    tx: &Transaction<'_>,
    writer: &mut dyn Write,
    context: &mut Context,
    check: &impl Fn() -> io::Result<()>,
    budget: &Budget,
    available: usize,
) -> io::Result<()> {
    let mut binary = SqliteBinaryRows::new()?;
    let result = write_with_resources(
        tx,
        writer,
        &mut binary,
        context,
        check,
        &Resources {
            reserve: &|bytes| budget.reserve(bytes),
            available,
        },
    );
    budget.released();
    result
}

#[test]
fn native_sql_ordinary_hash_matches_original_complete_bytes_and_context() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    let (mut conn, context, _) = fixture_rows(257);
    let tx = conn.transaction().unwrap();
    let mut expected = Vec::new();
    let mut expected_context = context.clone();
    original_serial(&tx, &mut expected, &mut expected_context).unwrap();
    for available in [1, 2, 8, 128] {
        let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
        let mut actual = Vec::new();
        let mut actual_context = context.clone();
        candidate(
            &tx,
            &mut actual,
            &mut actual_context,
            &|| Ok(()),
            &budget,
            available,
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert!(actual_context == expected_context);
        OBSERVED.with(|value| {
            let value = value.borrow();
            assert_eq!(value.started > 0, available > 1);
            eprintln!("native_sql_ordinary available={available} rows=257 max_batch={} charged={} started={} joined={} peak={}", value.max_rows, value.max_bytes, value.started, value.joined, budget.peak.get());
        });
    }
}

#[test]
fn native_sql_ordinary_hash_borrows_lease_and_cas_without_allocating_row_owners() {
    for shape in [1, 2] {
        let (mut conn, context) = bounded_rows(1, shape);
        let tx = conn.transaction().unwrap();
        let id = request(0);
        let (payload_digest, response) =
            source::ordinary(&tx, context.business.identity, id).unwrap();
        let receipt = NativeGenericReceipt::Ordinary(NativeOrdinaryReceipt {
            payload_digest,
            response: Box::new(response),
        });
        validation::validate_generic(&id, &receipt, &context.business.frontiers).unwrap();
        let expected = receipt.row_fingerprint(2, &id).unwrap();
        let memory = allocation_counter::measure(|| {
            assert_eq!(receipt.row_fingerprint(2, &id).unwrap(), expected);
        });
        assert_eq!(memory.count_total, 0, "shape {shape}");
        assert_eq!(memory.bytes_total, 0, "shape {shape}");
    }
}

#[test]
fn native_sql_ordinary_hash_lease_and_cas_match_original_under_memory_pressure() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    for shape in 1..=3 {
        let (mut conn, context) = bounded_rows(257, shape);
        let tx = conn.transaction().unwrap();
        let largest: usize = tx
            .query_row(
                "SELECT MAX(length(response_json)) FROM consensus_request_outcomes",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let maximum = row_memory_bytes(largest).unwrap();
        let mut expected = Vec::new();
        let mut expected_context = context.clone();
        original_serial(&tx, &mut expected, &mut expected_context).unwrap();
        for available in [1, 2, 8] {
            for limit in [
                PROCESS_VERIFICATION_BYTES,
                maximum,
                maximum * 4,
                BYTES + 128 * 1024,
            ] {
                let budget = Budget::new(&USED, limit);
                let mut actual = Vec::new();
                let mut actual_context = context.clone();
                candidate(
                    &tx,
                    &mut actual,
                    &mut actual_context,
                    &|| Ok(()),
                    &budget,
                    available,
                )
                .unwrap();
                assert_eq!(
                    actual, expected,
                    "shape {shape}, available {available}, limit {limit}"
                );
                assert!(actual_context == expected_context);
                OBSERVED.with(|value| {
                    let value = value.borrow();
                    if limit == PROCESS_VERIFICATION_BYTES {
                        assert_eq!(value.started > 0, available > 1);
                    } else if limit <= maximum * 4 {
                        assert_eq!(value.started, 0);
                    }
                });
            }
        }
    }
}

#[test]
fn native_sql_ordinary_hash_rejects_malformed_leases_with_original_prefix_and_context() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    for index in [1, 70] {
        for field in ["fence", "credential_id", "expires_at"] {
            let (mut conn, context) = bounded_rows(80, 1);
            let tx = conn.transaction().unwrap();
            let id = request(index);
            let (_, mut response) = source::ordinary(&tx, context.business.identity, id).unwrap();
            let mut guard = match &response.result {
                Ok(SessionMutationOutcome::Lease(guard)) => serde_json::to_value(guard).unwrap(),
                _ => unreachable!(),
            };
            guard[field] = if field == "expires_at" {
                serde_json::to_value(time(0)).unwrap()
            } else {
                serde_json::json!(0)
            };
            response.result = Ok(SessionMutationOutcome::Lease(
                serde_json::from_value(guard).unwrap(),
            ));
            tx.execute(
                "UPDATE consensus_request_outcomes SET response_json=?1 WHERE request_id=?2",
                params![
                    serde_json::to_vec(&response).unwrap(),
                    id.as_bytes().as_slice()
                ],
            )
            .unwrap();
            let mut expected = Vec::new();
            let mut expected_context = context.clone();
            let expected_error =
                original_serial(&tx, &mut expected, &mut expected_context).unwrap_err();
            assert_eq!(expected_error.to_string(), "native generic lease invalid");
            for available in [1, 8] {
                let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
                let mut actual = Vec::new();
                let mut actual_context = context.clone();
                let error = candidate(
                    &tx,
                    &mut actual,
                    &mut actual_context,
                    &|| Ok(()),
                    &budget,
                    available,
                )
                .unwrap_err();
                assert_eq!(
                    (error.kind(), error.to_string()),
                    (expected_error.kind(), expected_error.to_string())
                );
                assert_eq!(
                    actual, expected,
                    "index {index}, field {field}, available {available}"
                );
                assert!(actual_context == expected_context);
            }
        }
    }
}

#[test]
fn native_sql_ordinary_hash_rereads_current_sql_and_preserves_complete_rejections() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    for case in 0..19 {
        let (mut conn, context, mut original) = fixture_rows(80);
        let tx = conn.transaction().unwrap();
        let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
        candidate(
            &tx,
            &mut io::sink(),
            &mut context.clone(),
            &|| Ok(()),
            &budget,
            8,
        )
        .unwrap();
        let id = request(70);
        let update = match case {
            0 => Some("UPDATE consensus_request_outcomes SET configuration_epoch=-1 WHERE request_id=?1"),
            1 => Some("UPDATE consensus_request_outcomes SET configuration_epoch='bad' WHERE request_id=?1"),
            2 => Some("UPDATE consensus_request_outcomes SET payload_digest=x'00' WHERE request_id=?1"),
            3 => Some("UPDATE consensus_request_outcomes SET payload_digest=5 WHERE request_id=?1"),
            4 => Some("UPDATE consensus_request_outcomes SET response_json=x'7b' WHERE request_id=?1"),
            5 => Some("UPDATE consensus_request_outcomes SET response_json=5 WHERE request_id=?1"),
            6 => Some("UPDATE consensus_request_outcomes SET response_json=NULL WHERE request_id=?1"),
            7 => Some("UPDATE consensus_request_outcomes SET request_id=x'00' WHERE request_id=?1"),
            8 => Some("UPDATE consensus_request_outcomes SET request_id=5 WHERE request_id=?1"),
            9 => Some("UPDATE consensus_request_outcomes SET configuration_epoch=-1,payload_digest=x'00',response_json=x'7b' WHERE request_id=?1"),
            _ => None,
        };
        if let Some(update) = update {
            tx.execute(update, [id.as_bytes().as_slice()]).unwrap();
        } else {
            match case {
                10 => original.response.sequence = 0,
                11 => original.response.sequence = context.business.frontiers.sequence + 1,
                12 => original.response.digest = None,
                13 => original.response.logical_time = None,
                14 => original.response.logical_time = Some(time(3)),
                15 => {
                    original.response.raft_log_index =
                        context.business.frontiers.applied.unwrap().index + 1
                }
                16 => {
                    original.response.result =
                        Ok(SessionMutationOutcome::FencedTransitionV2Batch(vec![]))
                }
                17 => {
                    let (storage, _, _) = fixture();
                    let mut record = storage
                        .business
                        .keys
                        .values()
                        .find_map(|row| row.record.as_ref())
                        .unwrap()
                        .clone();
                    record.payload = crate::EncryptedSessionPayload::new([1, 2, 3]);
                    original.response.result =
                        Ok(SessionMutationOutcome::ConsumerRecord(Some(record)));
                }
                18 => {
                    tx.execute("UPDATE consensus_request_outcomes SET response_json=zeroblob(?1) WHERE request_id=?2", params![MAX_ITEM + 1, id.as_bytes().as_slice()]).unwrap();
                }
                _ => unreachable!(),
            }
            if case != 18 {
                tx.execute(
                    "UPDATE consensus_request_outcomes SET response_json=?1 WHERE request_id=?2",
                    params![
                        serde_json::to_vec(&original.response).unwrap(),
                        id.as_bytes().as_slice()
                    ],
                )
                .unwrap();
            }
        }
        let mut expected = Vec::new();
        let mut expected_context = context.clone();
        let error = original_serial(&tx, &mut expected, &mut expected_context).unwrap_err();
        for available in [1, 8] {
            let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
            let mut actual = Vec::new();
            let mut actual_context = context.clone();
            let actual_error = candidate(
                &tx,
                &mut actual,
                &mut actual_context,
                &|| Ok(()),
                &budget,
                available,
            )
            .unwrap_err();
            assert_eq!(
                (actual_error.kind(), actual_error.to_string()),
                (error.kind(), error.to_string()),
                "case {case}, available {available}"
            );
            assert_eq!(actual, expected, "case {case}, available {available}");
            assert!(
                actual_context == expected_context,
                "case {case}, available {available}"
            );
        }
    }
}

#[test]
fn native_sql_ordinary_hash_keeps_original_blob_bound_namespace_and_full_request_ids() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    let (mut conn, context, original) = fixture_rows(80);
    // The same full bytes stored as TEXT are visited first by the outer SQL
    // cursor, but the original per-ID BLOB query still selects the BLOB row.
    // Its deliberately different TEXT columns must never become authoritative.
    let text_id = "abcdefghijklmnop";
    conn.execute(
        "INSERT INTO consensus_request_outcomes VALUES(-1,?1,x'00',x'7b')",
        [text_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO consensus_request_outcomes VALUES(?1,?2,?3,?4)",
        params![
            context.business.identity.configuration_epoch().get(),
            text_id.as_bytes(),
            original.payload_digest.as_slice(),
            serde_json::to_vec(&original.response).unwrap()
        ],
    )
    .unwrap();
    let tx = conn.transaction().unwrap();
    for missing_blob in [false, true] {
        if missing_blob {
            tx.execute(
                "DELETE FROM consensus_request_outcomes WHERE request_id=?1",
                [text_id.as_bytes()],
            )
            .unwrap();
        }
        let mut expected = Vec::new();
        let mut expected_context = context.clone();
        let expected_result = original_serial(&tx, &mut expected, &mut expected_context);
        for available in [1, 8] {
            let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
            let mut actual = Vec::new();
            let mut actual_context = context.clone();
            let result = candidate(
                &tx,
                &mut actual,
                &mut actual_context,
                &|| Ok(()),
                &budget,
                available,
            );
            assert_eq!(result.is_err(), missing_blob);
            assert_eq!(
                result.as_ref().err().map(ToString::to_string),
                expected_result.as_ref().err().map(ToString::to_string)
            );
            assert_eq!(actual, expected);
            assert!(actual_context == expected_context);
        }
    }
}

struct ResetFaults(Faults);
impl Drop for ResetFaults {
    fn drop(&mut self) {
        FAULTS.with(|value| value.set(self.0));
    }
}

#[test]
fn native_sql_ordinary_hash_worker_faults_preserve_order_and_join_before_refunding() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    for shape in 0..=3 {
        for faults in [
            Faults {
                spawn: Some(3),
                panic: None,
            },
            Faults {
                spawn: None,
                panic: Some(3),
            },
        ] {
            let _reset = ResetFaults(FAULTS.with(|value| value.replace(faults)));
            let (mut conn, context) = bounded_rows(80, shape);
            let tx = conn.transaction().unwrap();
            // A later SQL failure cannot replace the failure of an earlier batch.
            tx.execute(
                "UPDATE consensus_request_outcomes SET response_json=x'7b' WHERE request_id=?1",
                [request(70).as_bytes().as_slice()],
            )
            .unwrap();
            let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
            let error = candidate(
                &tx,
                &mut io::sink(),
                &mut context.clone(),
                &|| Ok(()),
                &budget,
                8,
            )
            .unwrap_err();
            assert!(error.to_string().contains("worker"));
            OBSERVED.with(|value| assert!(value.borrow().started >= 3));
            // Conversely an early original decoder failure occurs before any
            // parallel-sized batch. Its exact original error must still win.
            tx.execute(
                "UPDATE consensus_request_outcomes SET response_json=x'7b' WHERE request_id=?1",
                [request(1).as_bytes().as_slice()],
            )
            .unwrap();
            let expected = original_serial(&tx, &mut io::sink(), &mut context.clone()).unwrap_err();
            let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
            let error = candidate(
                &tx,
                &mut io::sink(),
                &mut context.clone(),
                &|| Ok(()),
                &budget,
                8,
            )
            .unwrap_err();
            assert_eq!(error.to_string(), expected.to_string());
            OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
        }
    }
}

struct RejectWriter;
impl Write for RejectWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "writer fault",
        ))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn native_sql_ordinary_hash_cancellation_and_earlier_output_failure_release_all_owners() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    for shape in 0..=3 {
        let (mut conn, context) = bounded_rows(128, shape);
        let tx = conn.transaction().unwrap();
        let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
        let calls = Cell::new(0);
        candidate(
            &tx,
            &mut io::sink(),
            &mut context.clone(),
            &|| {
                calls.set(calls.get() + 1);
                Ok(())
            },
            &budget,
            8,
        )
        .unwrap();
        let total = calls.get();
        let caller = std::thread::current().id();
        for cancel_at in [1, 20, total / 2, total - 1] {
            let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
            calls.set(0);
            let error = candidate(
                &tx,
                &mut io::sink(),
                &mut context.clone(),
                &|| {
                    assert_eq!(std::thread::current().id(), caller);
                    calls.set(calls.get() + 1);
                    if calls.get() == cancel_at {
                        Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
                    } else {
                        Ok(())
                    }
                },
                &budget,
                8,
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert_eq!(calls.get(), cancel_at);
        }
        // Flushing the first completed rows still precedes a later SQL error.
        tx.execute(
            "UPDATE consensus_request_outcomes SET response_json=x'7b' WHERE request_id=?1",
            [request(20).as_bytes().as_slice()],
        )
        .unwrap();
        let expected = original_serial(&tx, &mut RejectWriter, &mut context.clone()).unwrap_err();
        let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
        let actual = candidate(
            &tx,
            &mut RejectWriter,
            &mut context.clone(),
            &|| Ok(()),
            &budget,
            8,
        )
        .unwrap_err();
        assert_eq!(
            (actual.kind(), actual.to_string()),
            (expected.kind(), expected.to_string())
        );
        assert_eq!(actual.kind(), io::ErrorKind::PermissionDenied);
    }
}

#[test]
fn native_sql_ordinary_hash_pressure_preserves_original_row_admission_and_count_bound() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    let (mut conn, context, original) = fixture_rows(128);
    let maximum = row_memory_bytes(serde_json::to_vec(&original.response).unwrap().len()).unwrap();
    let tx = conn.transaction().unwrap();
    let mut expected = Vec::new();
    let mut expected_context = context.clone();
    original_serial(&tx, &mut expected, &mut expected_context).unwrap();
    for limit in [maximum, maximum * 4, BYTES + 128 * 1024] {
        let budget = Budget::new(&USED, limit);
        let mut actual = Vec::new();
        let mut actual_context = context.clone();
        candidate(
            &tx,
            &mut actual,
            &mut actual_context,
            &|| Ok(()),
            &budget,
            8,
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert!(actual_context == expected_context);
        if limit <= maximum * 4 {
            OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
        }
    }
    let budget = Budget::new(&USED, maximum - 1);
    assert!(candidate(
        &tx,
        &mut io::sink(),
        &mut context.clone(),
        &|| Ok(()),
        &budget,
        8
    )
    .is_err());
    let mut context = context;
    context.business.counts[2] = validation::MAX_ITEMS - 2;
    let mut expected = Vec::new();
    let mut expected_context = context.clone();
    let expected_error = original_serial(&tx, &mut expected, &mut expected_context).unwrap_err();
    let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
    let mut actual = Vec::new();
    let mut actual_context = context.clone();
    let error = candidate(
        &tx,
        &mut actual,
        &mut actual_context,
        &|| Ok(()),
        &budget,
        8,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), expected_error.to_string());
    assert_eq!(actual, expected);
    assert!(actual_context == expected_context);
}

#[test]
fn native_sql_ordinary_hash_keeps_small_large_and_interrupted_batches_serial() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    for case in 0..3 {
        let count = if case == 0 { PARALLEL_MIN - 1 } else { 80 };
        let (mut conn, context, mut original) = fixture_rows(count);
        let limit = if case == 1 {
            let mut padded = serde_json::to_vec(&original.response).unwrap();
            padded.resize(400_000, b' ');
            let limit = row_memory_bytes(padded.len()).unwrap();
            conn.execute(
                "UPDATE consensus_request_outcomes SET response_json=?1 WHERE request_id=?2",
                params![padded, request(4).as_bytes().as_slice()],
            )
            .unwrap();
            limit
        } else if case == 2 {
            let (storage, _, previous) = fixture();
            let record = storage
                .business
                .keys
                .values()
                .find_map(|row| row.record.as_ref())
                .unwrap()
                .clone();
            let outcomes = [
                Ok(SessionMutationOutcome::ConsumerRecord(Some(record))),
                Ok(SessionMutationOutcome::Lease(previous.lease().clone())),
                Ok(SessionMutationOutcome::CompareAndSet(
                    crate::backend::CompareAndSetResult::Success,
                )),
                Err(StoreError::InvalidKey(
                    "compare-and-set key does not match record key".into(),
                )),
                Err(StoreError::NotFound),
            ];
            for index in 0..count {
                original.response.result = outcomes[index % outcomes.len()].clone();
                conn.execute(
                    "UPDATE consensus_request_outcomes SET response_json=?1 WHERE request_id=?2",
                    params![
                        serde_json::to_vec(&original.response).unwrap(),
                        request(index).as_bytes().as_slice()
                    ],
                )
                .unwrap();
            }
            PROCESS_VERIFICATION_BYTES
        } else {
            PROCESS_VERIFICATION_BYTES
        };
        let tx = conn.transaction().unwrap();
        let mut expected = Vec::new();
        let mut expected_context = context.clone();
        original_serial(&tx, &mut expected, &mut expected_context).unwrap();
        let budget = Budget::new(&USED, limit);
        let mut actual = Vec::new();
        let mut actual_context = context.clone();
        candidate(
            &tx,
            &mut actual,
            &mut actual_context,
            &|| Ok(()),
            &budget,
            8,
        )
        .unwrap();
        assert_eq!(actual, expected, "case {case}");
        assert!(actual_context == expected_context, "case {case}");
        OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
        if case == 1 {
            assert_eq!(budget.peak.get(), limit);
        }
    }
}
