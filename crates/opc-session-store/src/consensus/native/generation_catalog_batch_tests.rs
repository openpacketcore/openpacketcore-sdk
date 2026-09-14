use super::*;
use crate::consensus::native::changes::tests::{apply, clock, fixture, time};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

// The complete pre-change table loops are an independent source-order oracle.
// Frame decoding and every predecessor/lifecycle step remain here unchanged.
fn original_serial(
    rows: &mut Rows,
    reader: &mut Cursor<'_>,
    after: &Context,
    section: RowSection,
    table: Table,
) -> io::Result<()> {
    let mut counts = [0; 5];
    counts[table.index()] = section.counts[table.index()];
    let RowSection {
        checkpoint,
        base,
        format,
        ..
    } = section;
    let frontiers = &after.business.frontiers;
    let check = &|| Ok(());
    for _ in 0..counts[2] {
        check()?;
        expect(reader, &[2])?;
        let before = reader.before()?;
        let (range, input) = reader.bytes(MAX_ITEM)?;
        let (id, row) = decode::inspect_generic_format(input.bytes(), format, frontiers, check)?;
        predecessor(rows.generic.get(&id), before, checkpoint, base)?;
        let row = row.ok_or_else(|| {
            invalid("native generation generic removal lacks its lifecycle codec")
        })?;
        if let Some(before) = rows.generic.get(&id) {
            row.facts
                .validate_replacement(before.row.facts, before.row.content != row.content)?;
        } else if row.facts.retained_until.is_some() {
            rows.v1_count += 1;
            if rows.v1_count > crate::fenced_transition::FENCED_TRANSITION_MAX_HISTORY_ENTRIES {
                return Err(invalid(
                    "native catalog V1 count exceeds original lifetime bound",
                ));
            }
        }
        rows.summary[2].replace(before, Some(row.content))?;
        put(
            &mut rows.generic,
            id,
            Indexed {
                range,
                row,
                checkpoint,
            },
            validation::MAX_ITEMS,
        )?;
    }
    for _ in 0..counts[3] {
        check()?;
        expect(reader, &[3])?;
        if rows.notifications.len() >= validation::MAX_ITEMS {
            return Err(invalid("native catalog watch count exceeds original bound"));
        }
        let (range, input) = reader.bytes(MAX_ITEM)?;
        let sequence = rows.notifications.len() as u64 + 1;
        let row = decode::inspect_notification(input.bytes(), sequence, frontiers, check)?;
        rows.summary[3].replace(None, Some(row.content))?;
        rows.notifications
            .try_reserve(1)
            .map_err(|_| invalid("native resident watch catalog allocation failed"))?;
        rows.notifications.push(Indexed {
            range,
            row,
            checkpoint,
        });
    }
    Ok(())
}

struct Encoded {
    tag: u8,
    before: Option<[u8; 32]>,
    length: Option<u32>,
    bytes: Vec<u8>,
}

struct Fixture {
    storage: NativeStorage,
    after: Context,
    table: Table,
    encoded: Vec<Encoded>,
}

impl Fixture {
    fn new(table: Table, count: usize) -> Self {
        let (mut storage, _, _) = fixture();
        for first in (2..count + 2).step_by(64) {
            let entries = (first..(first + 64).min(count + 2))
                .map(|index| clock(index as u64, time(2)))
                .collect::<Vec<_>>();
            apply(&mut storage, &entries);
        }
        let mut after = Version::capture(&storage).unwrap().context();
        after.business.counts[table.index()] = count;
        let bodies = match table {
            Table::Generic => {
                let mut rows = storage.business.generic_receipts.iter().collect::<Vec<_>>();
                rows.sort_unstable_by_key(|(id, _)| *id.as_bytes());
                rows.into_iter()
                    .map(|(id, row)| postcard::to_allocvec(&(id, Some(&**row))).unwrap())
                    .collect()
            }
            Table::Notification => {
                let entry = storage.business.notifications[0].resident().unwrap();
                (0..count)
                    .map(|index| {
                        let mut entry = entry.clone();
                        entry.sequence = index as u64 + 1;
                        postcard::to_allocvec(&entry).unwrap()
                    })
                    .collect::<Vec<_>>()
            }
        };
        let encoded = bodies
            .into_iter()
            .map(|bytes| Encoded {
                tag: table.index() as u8,
                before: None,
                length: None,
                bytes,
            })
            .collect();
        Self {
            storage,
            after,
            table,
            encoded,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for row in &self.encoded {
            bytes.push(row.tag);
            if matches!(self.table, Table::Generic) {
                bytes.push(u8::from(row.before.is_some()));
                if let Some(before) = row.before {
                    bytes.extend_from_slice(&before);
                }
            }
            bytes.extend_from_slice(&row.length.unwrap_or(row.bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&row.bytes);
        }
        bytes
    }

    fn section(&self, base: bool) -> RowSection {
        let mut counts = [0; 5];
        counts[self.table.index()] = self.encoded.len();
        RowSection {
            checkpoint: if base { 1 } else { 2 },
            counts,
            base,
            format: Format::V3,
        }
    }

    fn empty(&self) -> Rows {
        Rows {
            context: self.after.clone(),
            keys: HashMap::new(),
            receipts: HashMap::new(),
            generic: HashMap::new(),
            v1_count: 0,
            notifications: Vec::new(),
            logs: BTreeMap::new(),
            summary: [Summary::default(); 5],
            rosters: Rosters::new(),
            _memory: VerificationMemory::reserve(128 * 1024).unwrap(),
        }
    }

    fn run(
        &self,
        rows: &mut Rows,
        base: bool,
        resources: Option<&Resources<'_>>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let bytes = self.bytes();
        let mut input = bytes.as_slice();
        let mut reader = Cursor {
            reader: &mut input,
            position: 0,
            maximum: bytes.len() as u64,
            hash: Sha256::new(),
        };
        match resources {
            Some(resources) => rows.read_catalog_table_with(
                &mut reader,
                &self.after,
                self.section(base),
                self.table,
                resources,
                check,
            )?,
            None => original_serial(
                rows,
                &mut reader,
                &self.after,
                self.section(base),
                self.table,
            )?,
        }
        assert_eq!(reader.position, bytes.len() as u64);
        assert_eq!(
            reader.hash.finalize().as_slice(),
            Sha256::digest(&bytes).as_slice()
        );
        Ok(())
    }

    fn future_row(&mut self, index: usize) {
        match self.table {
            Table::Generic => {
                let (id, Some(NativeGenericReceipt::Ordinary(mut row))): (
                    SessionConsensusRequestId,
                    Option<NativeGenericReceipt>,
                ) = binary::decode(&self.encoded[index].bytes).unwrap() else {
                    panic!("ordinary receipt");
                };
                row.response.logical_time = Some(time(3));
                self.encoded[index].bytes =
                    postcard::to_allocvec(&(id, Some(NativeGenericReceipt::Ordinary(row))))
                        .unwrap();
            }
            Table::Notification => {
                let mut row: ReplicationEntry = binary::decode(&self.encoded[index].bytes).unwrap();
                row.timestamp = time(3);
                self.encoded[index].bytes = postcard::to_allocvec(&row).unwrap();
            }
        }
    }
}

fn resources(available: usize, limit: usize, run: impl FnOnce(&Resources<'_>, &Cell<usize>)) {
    let counter = Box::leak(Box::new(AtomicUsize::new(0)));
    let peak = Cell::new(0);
    let reserve = |bytes| {
        let guard = VerificationMemory::reserve_for_test(counter, bytes, limit)?;
        peak.set(peak.get().max(counter.load(Ordering::Acquire)));
        Ok(guard)
    };
    OBSERVED.with(|value| *value.borrow_mut() = Observed::default());
    run(
        &Resources {
            reserve: &reserve,
            available,
        },
        &peak,
    );
    assert_eq!(
        counter.load(Ordering::Acquire),
        0,
        "all temporary charges returned"
    );
    OBSERVED.with(|value| {
        let value = value.borrow();
        assert_eq!(value.started, value.joined);
        assert!(value.rows <= ROWS);
        assert!(value.bytes <= BYTES);
    });
}

fn exact(actual: &Rows, expected: &Rows) {
    assert_eq!(actual.generic.len(), expected.generic.len());
    assert_eq!(actual.notifications.len(), expected.notifications.len());
    assert_eq!(actual.v1_count, expected.v1_count);
    for (actual, expected) in actual.summary.iter().zip(expected.summary) {
        assert_eq!(actual.count, expected.count);
        assert_eq!(actual.content, expected.content);
    }
    fn row<T: PartialEq>(actual: &Indexed<T>, expected: &Indexed<T>) {
        assert_eq!(actual.range.offset, expected.range.offset);
        assert_eq!(actual.range.length, expected.range.length);
        assert_eq!(actual.checkpoint, expected.checkpoint);
        assert!(
            actual.row == expected.row,
            "every fixed fact from the complete decoder remains exact"
        );
    }
    for (id, expected) in &expected.generic {
        row(&actual.generic[id], expected);
    }
    for (actual, expected) in actual.notifications.iter().zip(&expected.notifications) {
        row(actual, expected);
    }
}

fn error(result: io::Result<()>) -> (io::ErrorKind, String) {
    let error = result.unwrap_err();
    (error.kind(), error.to_string())
}

#[test]
fn native_catalog_batch_matches_original_complete_serial_tables() {
    for table in [Table::Generic, Table::Notification] {
        let fixture = Fixture::new(table, 257);
        let mut expected = fixture.empty();
        fixture.run(&mut expected, true, None, &|| Ok(())).unwrap();
        for available in [1, 2, 8, 128] {
            resources(available, 128 * 1024 * 1024, |resources, peak| {
                let mut actual = fixture.empty();
                let before = changes::generic_fingerprint_calls();
                fixture
                    .run(&mut actual, true, Some(resources), &|| Ok(()))
                    .unwrap();
                let hashes = changes::generic_fingerprint_calls() - before;
                assert_eq!(
                    hashes,
                    if matches!(table, Table::Generic) {
                        257
                    } else {
                        0
                    }
                );
                exact(&actual, &expected);
                OBSERVED.with(|value| {
                    let value = value.borrow();
                    if available > 1 { assert!(value.started > 0); }
                    eprintln!("native_catalog_batch table={} available={available} rows={} bytes={} peak_charged={} started={} joined={}", table.index(), value.rows, value.bytes, peak.get(), value.started, value.joined);
                });
            });
        }
    }
}

#[test]
fn native_catalog_batch_preserves_delta_predecessors_and_watch_offsets() {
    for table in [Table::Generic, Table::Notification] {
        let mut fixture = Fixture::new(table, 65);
        let mut expected = fixture.empty();
        let mut actual = fixture.empty();
        fixture.run(&mut expected, true, None, &|| Ok(())).unwrap();
        fixture.run(&mut actual, true, None, &|| Ok(())).unwrap();
        for row in &mut fixture.encoded {
            match table {
                Table::Generic => {
                    let (id, _): (SessionConsensusRequestId, Option<NativeGenericReceipt>) =
                        binary::decode(&row.bytes).unwrap();
                    row.before = Some(expected.generic[&id].row.content);
                }
                Table::Notification => {
                    let mut entry: ReplicationEntry = binary::decode(&row.bytes).unwrap();
                    entry.sequence += 65;
                    row.bytes = postcard::to_allocvec(&entry).unwrap();
                }
            }
        }
        fixture.run(&mut expected, false, None, &|| Ok(())).unwrap();
        resources(8, 128 * 1024 * 1024, |resources, _| {
            fixture
                .run(&mut actual, false, Some(resources), &|| Ok(()))
                .unwrap();
            exact(&actual, &expected);
        });
    }
}

#[test]
fn native_catalog_batch_preserves_first_row_and_framing_errors() {
    for table in [Table::Generic, Table::Notification] {
        for case in 0..9 {
            let mut fixture = Fixture::new(table, 65);
            match case {
                0 => {
                    fixture.encoded[9].bytes.pop();
                }
                1 => fixture.encoded[9].bytes.push(0),
                2 => fixture.encoded[9].tag = 9,
                3 => fixture.encoded[9].length = Some(0),
                4 => fixture.encoded[9].length = Some(MAX_ITEM as u32 + 1),
                5 => fixture.future_row(9),
                6 => {
                    fixture.future_row(9);
                    fixture.encoded[10].tag = 9;
                }
                7 => {
                    fixture.future_row(9);
                    fixture.encoded[10].bytes.pop();
                }
                _ => fixture.encoded[9].bytes = fixture.encoded[8].bytes.clone(),
            }
            let mut expected = fixture.empty();
            let failure = error(fixture.run(&mut expected, true, None, &|| Ok(())));
            assert_eq!(expected.summary[table.index()].count, 9);
            for available in [1, 8] {
                resources(available, 128 * 1024 * 1024, |resources, _| {
                    let mut actual = fixture.empty();
                    assert_eq!(
                        error(fixture.run(&mut actual, true, Some(resources), &|| Ok(()))),
                        failure,
                        "table {}, case {case}",
                        table.index()
                    );
                    exact(&actual, &expected);
                });
            }
        }
    }
}

#[test]
fn native_catalog_batch_joins_workers_on_spawn_and_panic_failures() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULTS.with(|value| value.set(Faults::default()));
        }
    }
    let _reset = Reset;
    for table in [Table::Generic, Table::Notification] {
        for corrupt in [false, true] {
            let mut fixture = Fixture::new(table, 64);
            if corrupt {
                fixture.future_row(0);
            }
            for fault in [
                Faults {
                    spawn: Some(2),
                    panic: None,
                },
                Faults {
                    spawn: None,
                    panic: Some(2),
                },
            ] {
                FAULTS.with(|value| value.set(fault));
                resources(8, 128 * 1024 * 1024, |resources, _| {
                    let mut actual = fixture.empty();
                    let actual = error(fixture.run(&mut actual, true, Some(resources), &|| Ok(())));
                    if corrupt {
                        assert_eq!(
                            actual,
                            error(fixture.run(&mut fixture.empty(), true, None, &|| Ok(())))
                        );
                    } else {
                        assert!(actual.1.contains("worker"));
                    }
                    OBSERVED.with(|value| assert!(value.borrow().started > 0));
                });
                FAULTS.with(|value| value.set(Faults::default()));
            }
        }
    }
}

#[test]
fn native_catalog_batch_keeps_cancellation_on_the_caller() {
    let caller = std::thread::current().id();
    for table in [Table::Generic, Table::Notification] {
        let fixture = Fixture::new(table, 257);
        for at in [1, 10, 50, 100, 200, 300] {
            resources(8, 128 * 1024 * 1024, |resources, _| {
                let calls = Cell::new(0);
                let result = fixture.run(&mut fixture.empty(), true, Some(resources), &|| {
                    assert_eq!(std::thread::current().id(), caller);
                    calls.set(calls.get() + 1);
                    if calls.get() == at {
                        Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "catalog cancellation",
                        ))
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(
                    error(result),
                    (
                        io::ErrorKind::Interrupted,
                        "catalog cancellation".to_owned()
                    )
                );
            });
        }
    }
}

#[test]
fn native_catalog_batch_pressure_and_small_sections_keep_serial_admission() {
    for table in [Table::Generic, Table::Notification] {
        let fixture = Fixture::new(table, 257);
        let mut expected = fixture.empty();
        fixture.run(&mut expected, true, None, &|| Ok(())).unwrap();
        for limit in [0, 32 * 1024, 128 * 1024, 3 * 1024 * 1024] {
            resources(8, limit, |resources, peak| {
                let mut actual = fixture.empty();
                fixture
                    .run(&mut actual, true, Some(resources), &|| Ok(()))
                    .unwrap();
                exact(&actual, &expected);
                assert!(peak.get() <= limit);
                if limit < STACK {
                    OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
                }
            });
        }
        for count in [0, 1, 15] {
            let fixture = Fixture::new(table, count);
            resources(8, 128 * 1024 * 1024, |resources, peak| {
                let mut expected = fixture.empty();
                fixture.run(&mut expected, true, None, &|| Ok(())).unwrap();
                let mut actual = fixture.empty();
                fixture
                    .run(&mut actual, true, Some(resources), &|| Ok(()))
                    .unwrap();
                exact(&actual, &expected);
                assert_eq!(
                    peak.get(),
                    0,
                    "original small serial path has no batch resources"
                );
            });
        }
    }
}

#[test]
fn native_catalog_batch_large_input_keeps_original_serial_reservation() {
    let mut fixture = Fixture::new(Table::Generic, 65);
    let (id, Some(NativeGenericReceipt::Ordinary(mut row))): (
        SessionConsensusRequestId,
        Option<NativeGenericReceipt>,
    ) = binary::decode(&fixture.encoded[4].bytes).unwrap() else {
        panic!("ordinary receipt");
    };
    let mut record = fixture
        .storage
        .business
        .keys
        .values()
        .find_map(|row| row.record.clone())
        .unwrap();
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(record.payload.as_bytes()).unwrap();
    envelope.ciphertext_and_tag.resize(80 * 1024, 0);
    record.payload =
        crate::EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
    row.response.result = Ok(SessionMutationOutcome::ConsumerRecord(Some(record)));
    fixture.encoded[4].bytes =
        postcard::to_allocvec(&(id, Some(NativeGenericReceipt::Ordinary(row)))).unwrap();
    assert!(fixture.encoded[4].bytes.len() > INPUT);
    let mut expected = fixture.empty();
    fixture.run(&mut expected, true, None, &|| Ok(())).unwrap();
    resources(8, 128 * 1024 * 1024, |resources, _| {
        let mut actual = fixture.empty();
        fixture
            .run(&mut actual, true, Some(resources), &|| Ok(()))
            .unwrap();
        exact(&actual, &expected);
        OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
    });
}
