//! Ordered, bounded notification decoding within each original SQL pass.
//! Only owned column bytes and the immutable frontier cross decoder threads.
//! SQL access, cancellation checks, accounting and encoding stay with the
//! caller. Every started decoder joins before its reservations are released.

use super::*;

const BATCH_ROWS: usize = 64;
const BATCH_BYTES: usize = 4 * 1024 * 1024;
const PARALLEL_MIN_ROWS: usize = 16;
const WORKERS: usize = 8;
const WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;

struct Resources<'a> {
    reserve: &'a dyn Fn(usize) -> io::Result<VerificationMemory>,
    available: usize,
}

struct ColumnBytes<const N: usize> {
    bytes: [u8; N],
    length: usize,
}

impl<const N: usize> ColumnBytes<N> {
    fn copy(value: &[u8]) -> Self {
        // The original column reader has already enforced this bound.
        let mut bytes = [0; N];
        bytes[..value.len()].copy_from_slice(value);
        Self {
            bytes,
            length: value.len(),
        }
    }
}

impl<const N: usize> AsRef<[u8]> for ColumnBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

struct Projection<T, U> {
    sequence: io::Result<u64>,
    tx_id: io::Result<T>,
    timestamp: io::Result<U>,
}

type OwnedProjection =
    Projection<ColumnBytes<{ crate::backend::REPLICATION_TX_ID_MAX_BYTES }>, ColumnBytes<30>>;

impl<'a> Projection<&'a [u8], &'a [u8]> {
    fn read(row: &'a Row<'_>) -> Self {
        // Defer errors until after JSON decoding, in the original sequence /
        // transaction-id / timestamp short-circuit order.
        Self {
            sequence: row.get(0).map_err(db),
            tx_id: bytes(row, 1, crate::backend::REPLICATION_TX_ID_MAX_BYTES),
            timestamp: bytes(row, 3, 30),
        }
    }

    fn into_owned(self) -> OwnedProjection {
        Projection {
            sequence: self.sequence,
            tx_id: self.tx_id.map(ColumnBytes::copy),
            timestamp: self.timestamp.map(ColumnBytes::copy),
        }
    }
}

struct DecodedNotification {
    entry: ReplicationEntry,
    sequence: u64,
    content: [u8; 32],
}

fn decode(
    encoded: &[u8],
    projection: Projection<impl AsRef<[u8]>, impl AsRef<[u8]>>,
    expected: u64,
    frontiers: &NativeFrontiers,
) -> io::Result<DecodedNotification> {
    let entry: ReplicationEntry = serde_json::from_slice(encoded)
        .map_err(|_| invalid("native SQL notification cannot decode"))?;
    let sequence = projection.sequence?;
    if sequence != expected
        || entry.tx_id.as_str().as_bytes() != projection.tx_id?.as_ref()
        || entry.timestamp
            != timestamp(
                std::str::from_utf8(projection.timestamp?.as_ref())
                    .map_err(|_| invalid("native SQL notification timestamp invalid"))?
                    .to_owned(),
            )?
    {
        return Err(invalid("native SQL notification projection differs"));
    }
    validation::validate_notification(&entry, sequence, frontiers)?;
    sql::validate_sealed_replication_op(&entry.op)?;
    let content = changes::fingerprint(3, &sequence, &entry)?;
    Ok(DecodedNotification {
        entry,
        sequence,
        content,
    })
}

fn emit(
    row: DecodedNotification,
    writer: &mut dyn Write,
    binary: &mut SqliteBinaryRows,
    context: &mut Context,
) -> io::Result<()> {
    if row.sequence != context.business.counts[3] as u64 + 1 {
        return Err(invalid("native SQL notification projection differs"));
    }
    account(
        &mut context.business.counts[3],
        &mut context.business.content[3],
        row.content,
        validation::MAX_ITEMS,
    )?;
    writer.write_all(&[3])?;
    binary.write(writer, &row.entry)
}

struct StagedRow {
    encoded: Zeroizing<Vec<u8>>,
    projection: Option<OwnedProjection>,
    decoded: Option<io::Result<DecodedNotification>>,
    expected: u64,
    // Both the input copy and decoded value die before returning this charge.
    _memory: VerificationMemory,
}

impl StagedRow {
    fn decode(&mut self, frontiers: &NativeFrontiers) {
        self.decoded = Some(
            self.projection
                .take()
                .ok_or_else(|| invalid("native SQL notification projection consumed"))
                .and_then(|projection| decode(&self.encoded, projection, self.expected, frontiers)),
        );
    }
}

fn decode_chunk(rows: &mut [StagedRow], frontiers: &NativeFrontiers) {
    for row in rows {
        row.decode(frontiers);
    }
}

fn decode_batch(
    rows: &mut [StagedRow],
    frontiers: &NativeFrontiers,
    resources: &Resources<'_>,
) -> io::Result<()> {
    let workers = WORKERS.min(resources.available.max(1)).min(rows.len());
    if rows.len() < PARALLEL_MIN_ROWS || workers <= 1 {
        decode_chunk(rows, frontiers);
        return Ok(());
    }
    let rows_per_worker = rows.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(workers)
            .map_err(|_| invalid("native SQL notification worker allocation failed"))?;
        let mut worker_error = None;
        for (worker, chunk) in rows.chunks_mut(rows_per_worker).enumerate() {
            // Stack space is admitted under the same process ceiling before
            // spawning. Pressure selects the original inline decoder.
            let memory = match (resources.reserve)(WORKER_STACK_BYTES) {
                Ok(memory) => memory,
                Err(_) => {
                    decode_chunk(chunk, frontiers);
                    continue;
                }
            };
            #[cfg(not(test))]
            let _ = worker;
            #[cfg(test)]
            if FAULTS.with(|faults| faults.get().spawn == Some(worker)) {
                worker_error = Some(invalid("native SQL notification worker spawn failed"));
                break;
            }
            #[cfg(test)]
            let panic_worker = FAULTS.with(|faults| faults.get().panic == Some(worker));
            match std::thread::Builder::new()
                .stack_size(WORKER_STACK_BYTES)
                .spawn_scoped(scope, move || {
                    #[cfg(test)]
                    if panic_worker {
                        panic!("injected native SQL notification worker failure");
                    }
                    decode_chunk(chunk, frontiers);
                }) {
                Ok(handle) => {
                    handles.push((handle, memory));
                    #[cfg(test)]
                    OBSERVATION.with(|value| value.borrow_mut().started += 1);
                }
                Err(error) => {
                    worker_error = Some(io::Error::other(error));
                    break;
                }
            }
        }
        for (handle, memory) in handles {
            if handle.join().is_err() && worker_error.is_none() {
                worker_error = Some(invalid("native SQL notification worker failed"));
            }
            #[cfg(test)]
            OBSERVATION.with(|value| value.borrow_mut().joined += 1);
            drop(memory);
        }
        worker_error.map_or(Ok(()), Err)
    })
}

struct Batch {
    rows: Vec<StagedRow>,
    bytes: usize,
    // Covers retained row descriptors and temporary join-handle capacity.
    _memory: VerificationMemory,
}

impl Batch {
    fn new(resources: &Resources<'_>) -> io::Result<Self> {
        let descriptors = BATCH_ROWS * std::mem::size_of::<StagedRow>()
            + WORKERS
                * std::mem::size_of::<(
                    std::thread::ScopedJoinHandle<'static, ()>,
                    VerificationMemory,
                )>();
        let memory = (resources.reserve)(descriptors)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(BATCH_ROWS)
            .map_err(|_| invalid("native SQL notification batch allocation failed"))?;
        Ok(Self {
            rows,
            bytes: 0,
            _memory: memory,
        })
    }

    fn flush(
        &mut self,
        writer: &mut dyn Write,
        binary: &mut SqliteBinaryRows,
        context: &mut Context,
        check: &impl Fn() -> io::Result<()>,
        resources: &Resources<'_>,
    ) -> io::Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        check()?;
        #[cfg(test)]
        OBSERVATION.with(|value| {
            let mut value = value.borrow_mut();
            value.max_rows = value.max_rows.max(self.rows.len());
            value.max_bytes = value.max_bytes.max(self.bytes);
        });
        let worker_result = decode_batch(&mut self.rows, &context.business.frontiers, resources);
        // Every decoder is joined. Visit results in original SQL order, so
        // scheduling cannot select which malformed row is reported first.
        for row in &mut self.rows {
            let decoded = row
                .decoded
                .take()
                .ok_or_else(|| invalid("native SQL notification worker did not complete"))??;
            check()?;
            emit(decoded, writer, binary, context)?;
        }
        worker_result?;
        self.rows.clear();
        self.bytes = 0;
        check()
    }
}

pub(super) fn write(
    tx: &Transaction<'_>,
    writer: &mut dyn Write,
    binary: &mut SqliteBinaryRows,
    context: &mut Context,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let resources = Resources {
        reserve: &VerificationMemory::reserve,
        available: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1),
    };
    write_with_resources(tx, writer, binary, context, check, &resources)
}

fn write_with_resources(
    tx: &Transaction<'_>,
    writer: &mut dyn Write,
    binary: &mut SqliteBinaryRows,
    context: &mut Context,
    check: &impl Fn() -> io::Result<()>,
    resources: &Resources<'_>,
) -> io::Result<()> {
    let mut statement = tx.prepare("SELECT sequence,tx_id,entry_json,timestamp FROM session_replication_log ORDER BY sequence").map_err(db)?;
    let mut rows = statement.query([]).map_err(db)?;
    // Metadata admission failure keeps the original one-row memory behavior.
    let mut batch = Batch::new(resources).ok();
    loop {
        let row = match rows.next().map_err(db) {
            Ok(Some(row)) => row,
            next => {
                if let Some(batch) = &mut batch {
                    batch.flush(writer, binary, context, check, resources)?;
                }
                return next.map(|_| ());
            }
        };
        check()?;
        let encoded = match bytes(row, 2, MAX_ITEM) {
            Ok(encoded) => encoded,
            Err(error) => {
                if let Some(batch) = &mut batch {
                    batch.flush(writer, binary, context, check, resources)?;
                }
                return Err(error);
            }
        };
        let original_bytes = row_memory_bytes(encoded.len())?;
        // Retain the complete original decoder reservation and additionally
        // charge the raw copy. Oversized individual rows remain borrowed.
        let charged_bytes = original_bytes
            .checked_add(encoded.len())
            .ok_or_else(|| invalid("native SQL notification reservation overflow"))?;
        if let Some(batch) = &mut batch {
            if batch.rows.len() == BATCH_ROWS || charged_bytes > BATCH_BYTES - batch.bytes {
                batch.flush(writer, binary, context, check, resources)?;
            }
        }
        if charged_bytes > BATCH_BYTES {
            // A large borrowed row also gets the original capacity with no
            // extra batch descriptors held against the process ceiling.
            batch = None;
        } else {
            if let Some(pending) = &mut batch {
                let memory = match (resources.reserve)(charged_bytes) {
                    Ok(memory) => Ok(memory),
                    Err(_) => {
                        // Release the previous batch before retrying: staging
                        // must not reject a row the original decoder can admit.
                        pending.flush(writer, binary, context, check, resources)?;
                        (resources.reserve)(charged_bytes)
                    }
                };
                if let Ok(memory) = memory {
                    let mut copied = Zeroizing::new(Vec::new());
                    copied
                        .try_reserve_exact(encoded.len())
                        .map_err(|_| invalid("native SQL notification input allocation failed"))?;
                    copied.extend_from_slice(encoded);
                    let expected =
                        context.business.counts[3] as u64 + pending.rows.len() as u64 + 1;
                    pending.rows.push(StagedRow {
                        encoded: copied,
                        projection: Some(Projection::read(row).into_owned()),
                        decoded: None,
                        expected,
                        _memory: memory,
                    });
                    pending.bytes += charged_bytes;
                    continue;
                }
                // Even the extra descriptors/copy cannot consume capacity
                // needed by a serial row. Refund them before original admission.
                batch = None;
            }
        }
        let _memory = (resources.reserve)(original_bytes)?;
        let decoded = decode(
            encoded,
            Projection::read(row),
            context.business.counts[3] as u64 + 1,
            &context.business.frontiers,
        )?;
        emit(decoded, writer, binary, context)?;
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct Faults {
    spawn: Option<usize>,
    panic: Option<usize>,
}

#[cfg(test)]
#[derive(Default)]
struct Observation {
    started: usize,
    joined: usize,
    max_rows: usize,
    max_bytes: usize,
}

#[cfg(test)]
thread_local! {
    static FAULTS: std::cell::Cell<Faults> = const { std::cell::Cell::new(Faults { spawn: None, panic: None }) };
    static OBSERVATION: std::cell::RefCell<Observation> = std::cell::RefCell::new(Observation::default());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ReplicationOp;
    use crate::consensus::native::changes::tests::{fixture, time};
    use crate::consensus::verified_snapshot::PROCESS_VERIFICATION_BYTES;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture_rows(count: usize) -> (Connection, Context, Vec<ReplicationEntry>) {
        let (storage, _, _) = fixture();
        let original = storage
            .business
            .notifications
            .front()
            .unwrap()
            .resident()
            .unwrap();
        let mut context = Version::capture(&storage).unwrap().context();
        context.business.counts[3] = 0;
        context.business.content[3] = [0; 32];
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE session_replication_log(sequence,tx_id,entry_json,timestamp)",
        )
        .unwrap();
        let entries: Vec<_> = (1..=count)
            .map(|sequence| ReplicationEntry {
                sequence: sequence as u64,
                tx_id: ReplicationTxId::from_request_bytes((sequence as u128).to_le_bytes()),
                ..original.clone()
            })
            .collect();
        for entry in &entries {
            conn.execute(
                "INSERT INTO session_replication_log VALUES(?1,?2,?3,?4)",
                params![
                    entry.sequence,
                    entry.tx_id.as_str(),
                    serde_json::to_vec(entry).unwrap(),
                    ops::format_rfc3339_normalized(entry.timestamp)
                ],
            )
            .unwrap();
        }
        (conn, context, entries)
    }

    // The pre-change serial loop is an independent oracle. In particular it
    // borrows SQL columns, decodes before reading projections, and uses the
    // original streaming binary writer instead of the batch implementation.
    fn original_serial(
        tx: &Transaction<'_>,
        writer: &mut dyn Write,
        context: &mut Context,
    ) -> io::Result<()> {
        let mut statement = tx.prepare("SELECT sequence,tx_id,entry_json,timestamp FROM session_replication_log ORDER BY sequence").map_err(db)?;
        let mut rows = statement.query([]).map_err(db)?;
        while let Some(row) = rows.next().map_err(db)? {
            let encoded = bytes(row, 2, MAX_ITEM)?;
            let _memory = row_memory(encoded.len())?;
            let entry: ReplicationEntry = serde_json::from_slice(encoded)
                .map_err(|_| invalid("native SQL notification cannot decode"))?;
            let sequence: u64 = row.get(0).map_err(db)?;
            if sequence != context.business.counts[3] as u64 + 1
                || entry.tx_id.as_str().as_bytes()
                    != bytes(row, 1, crate::backend::REPLICATION_TX_ID_MAX_BYTES)?
                || entry.timestamp
                    != timestamp(
                        std::str::from_utf8(bytes(row, 3, 30)?)
                            .map_err(|_| invalid("native SQL notification timestamp invalid"))?
                            .to_owned(),
                    )?
            {
                return Err(invalid("native SQL notification projection differs"));
            }
            validation::validate_notification(&entry, sequence, &context.business.frontiers)?;
            sql::validate_sealed_replication_op(&entry.op)?;
            account(
                &mut context.business.counts[3],
                &mut context.business.content[3],
                changes::fingerprint(3, &sequence, &entry)?,
                validation::MAX_ITEMS,
            )?;
            writer.write_all(&[3])?;
            write_binary(writer, &entry)?;
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
            OBSERVATION.with(|value| *value.borrow_mut() = Observation::default());
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
            OBSERVATION.with(|value| {
                let value = value.borrow();
                assert_eq!(value.started, value.joined);
                assert!(value.max_rows <= BATCH_ROWS);
                assert!(value.max_bytes <= BATCH_BYTES);
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
        let reserve = |bytes| budget.reserve(bytes);
        let result = write_with_resources(
            tx,
            writer,
            &mut binary,
            context,
            check,
            &Resources {
                reserve: &reserve,
                available,
            },
        );
        budget.released();
        result
    }

    #[test]
    fn native_sql_notification_batch_matches_original_serial_bytes_and_context() {
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
            OBSERVATION.with(|value| {
                let value = value.borrow();
                assert_eq!(value.started > 0, available > 1);
                assert!(value.max_rows >= PARALLEL_MIN_ROWS);
                eprintln!("native_sql_notifications available={available} rows=257 max_batch={} charged={} started={} joined={} peak={}", value.max_rows, value.max_bytes, value.started, value.joined, budget.peak.get());
            });
        }
    }

    #[test]
    fn native_sql_notification_batch_preserves_current_source_and_all_original_rejections() {
        static USED: AtomicUsize = AtomicUsize::new(0);
        for case in 0..15 {
            let (mut conn, context, entries) = fixture_rows(80);
            let tx = conn.transaction().unwrap();
            // Success in this same transaction cannot authorize a later row
            // change, even when its first batch has already been converted.
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
            match case {
                0 => {
                    tx.execute(
                        "UPDATE session_replication_log SET entry_json=x'7b' WHERE sequence=2",
                        [],
                    )
                    .unwrap();
                }
                1 => {
                    tx.execute("UPDATE session_replication_log SET tx_id='different-tx-id' WHERE sequence=2", []).unwrap();
                }
                2 => {
                    tx.execute(
                        "UPDATE session_replication_log SET tx_id=17 WHERE sequence=2",
                        [],
                    )
                    .unwrap();
                }
                3 => {
                    tx.execute(
                        "UPDATE session_replication_log SET timestamp=x'ff' WHERE sequence=2",
                        [],
                    )
                    .unwrap();
                }
                4 => {
                    tx.execute("UPDATE session_replication_log SET timestamp='2026-07-12T00:00:01+00:00' WHERE sequence=2", []).unwrap();
                }
                5 => {
                    tx.execute(
                        "UPDATE session_replication_log SET sequence=-1 WHERE sequence=2",
                        [],
                    )
                    .unwrap();
                }
                6 => {
                    tx.execute(
                        "UPDATE session_replication_log SET entry_json=17 WHERE sequence=2",
                        [],
                    )
                    .unwrap();
                }
                7 => {
                    tx.execute(
                        "UPDATE session_replication_log SET tx_id=?1 WHERE sequence=2",
                        [vec![0_u8; crate::backend::REPLICATION_TX_ID_MAX_BYTES + 1]],
                    )
                    .unwrap();
                }
                8 => {
                    tx.execute(
                        "UPDATE session_replication_log SET timestamp=?1 WHERE sequence=2",
                        [vec![0_u8; 31]],
                    )
                    .unwrap();
                }
                9 => {
                    tx.execute("UPDATE session_replication_log SET entry_json=x'7b',tx_id=17,sequence=-1 WHERE sequence=2", []).unwrap();
                }
                10 => {
                    tx.execute("DELETE FROM session_replication_log WHERE sequence=2", [])
                        .unwrap();
                }
                _ => {
                    let mut entry = entries[1].clone();
                    match case {
                        11 => entry.sequence += 1,
                        12 => {
                            entry.timestamp = time(2);
                            tx.execute(
                                "UPDATE session_replication_log SET timestamp=?1 WHERE sequence=2",
                                [ops::format_rfc3339_normalized(entry.timestamp)],
                            )
                            .unwrap();
                        }
                        13 => {
                            let ReplicationOp::Batch { ops } = &mut entry.op else {
                                panic!("V2 fixture");
                            };
                            let ReplicationOp::CompareAndSet { new_record, .. } = &mut ops[1]
                            else {
                                panic!("V2 mutation");
                            };
                            new_record.payload = crate::EncryptedSessionPayload::new([1, 2, 3]);
                        }
                        14 => {
                            for _ in 0..150 {
                                entry.op = ReplicationOp::Batch {
                                    ops: vec![entry.op],
                                };
                            }
                        }
                        _ => unreachable!(),
                    }
                    tx.execute(
                        "UPDATE session_replication_log SET entry_json=?1 WHERE sequence=2",
                        [serde_json::to_vec(&entry).unwrap()],
                    )
                    .unwrap();
                }
            }
            let expected = original_serial(&tx, &mut io::sink(), &mut context.clone()).unwrap_err();
            for available in [1, 8] {
                let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
                let actual = candidate(
                    &tx,
                    &mut io::sink(),
                    &mut context.clone(),
                    &|| Ok(()),
                    &budget,
                    available,
                )
                .unwrap_err();
                assert_eq!(
                    (actual.kind(), actual.to_string()),
                    (expected.kind(), expected.to_string()),
                    "case {case}, workers {available}"
                );
            }
        }
    }

    #[test]
    fn native_sql_notification_batch_reports_first_source_error_after_joining() {
        static USED: AtomicUsize = AtomicUsize::new(0);
        for first_json in [false, true] {
            let (mut conn, context, _) = fixture_rows(80);
            let tx = conn.transaction().unwrap();
            for (sequence, json) in [(2, first_json), (20, !first_json)] {
                let update = if json {
                    "UPDATE session_replication_log SET entry_json=x'7b' WHERE sequence=?1"
                } else {
                    "UPDATE session_replication_log SET tx_id='different-tx-id' WHERE sequence=?1"
                };
                tx.execute(update, [sequence]).unwrap();
            }
            let expected = original_serial(&tx, &mut io::sink(), &mut context.clone()).unwrap_err();
            for _ in 0..8 {
                let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
                let actual = candidate(
                    &tx,
                    &mut io::sink(),
                    &mut context.clone(),
                    &|| Ok(()),
                    &budget,
                    8,
                )
                .unwrap_err();
                assert_eq!(actual.to_string(), expected.to_string());
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
    fn native_sql_notification_batch_worker_faults_join_and_refund_before_returning() {
        static USED: AtomicUsize = AtomicUsize::new(0);
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
            let (mut conn, context, _) = fixture_rows(80);
            let tx = conn.transaction().unwrap();
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
            OBSERVATION.with(|value| assert!(value.borrow().started > 0));
            tx.execute(
                "UPDATE session_replication_log SET entry_json=x'7b' WHERE sequence=2",
                [],
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
            assert_eq!(error.to_string(), "native SQL notification cannot decode");
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
    fn native_sql_notification_batch_cancellation_and_output_failure_release_every_owner() {
        static USED: AtomicUsize = AtomicUsize::new(0);
        let (mut conn, context, _) = fixture_rows(128);
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
        let thread = std::thread::current().id();
        for cancel_at in [1, 20, total / 2, total - 1] {
            let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
            calls.set(0);
            let error = candidate(
                &tx,
                &mut io::sink(),
                &mut context.clone(),
                &|| {
                    assert_eq!(std::thread::current().id(), thread);
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
        }
        let budget = Budget::new(&USED, PROCESS_VERIFICATION_BYTES);
        let error = candidate(
            &tx,
            &mut RejectWriter,
            &mut context.clone(),
            &|| Ok(()),
            &budget,
            8,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn native_sql_notification_batch_pressure_preserves_original_serial_admission() {
        static USED: AtomicUsize = AtomicUsize::new(0);
        let (mut conn, context, entries) = fixture_rows(128);
        let maximum = entries
            .iter()
            .map(|entry| row_memory_bytes(serde_json::to_vec(entry).unwrap().len()).unwrap())
            .max()
            .unwrap();
        let tx = conn.transaction().unwrap();
        let mut expected = Vec::new();
        let mut expected_context = context.clone();
        original_serial(&tx, &mut expected, &mut expected_context).unwrap();
        for limit in [maximum, maximum * 4, BATCH_BYTES + 128 * 1024] {
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
                OBSERVATION.with(|value| assert_eq!(value.borrow().started, 0));
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
    }

    #[test]
    fn native_sql_notification_large_row_keeps_borrowed_input_and_original_reservation() {
        static USED: AtomicUsize = AtomicUsize::new(0);
        let (mut conn, context, entries) = fixture_rows(80);
        let mut padded = serde_json::to_vec(&entries[4]).unwrap();
        padded.resize(400_000, b' ');
        let limit = row_memory_bytes(padded.len()).unwrap();
        conn.execute(
            "UPDATE session_replication_log SET entry_json=?1 WHERE sequence=5",
            [padded],
        )
        .unwrap();
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
        assert_eq!(actual, expected);
        assert!(actual_context == expected_context);
        assert_eq!(budget.peak.get(), limit);
    }
}
