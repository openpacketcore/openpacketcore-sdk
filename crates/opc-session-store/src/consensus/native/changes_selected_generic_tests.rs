use super::*;
use crate::consensus::native::changes::tests::{apply, clock, fixture, time};
use crate::consensus::native::prefix::{PrefixIdentity, VerifiedAppendOwner, VerifiedPrefix};
use std::cell::Cell;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Row {
    id: SessionConsensusRequestId,
    facts: generation::facts::Row<generation::facts::Request>,
    bytes: Vec<u8>,
}

struct Fixture {
    _directory: tempfile::TempDir,
    source: Arc<VerifiedPrefix>,
    rows: Vec<Row>,
    offsets: Vec<u64>,
    frontiers: NativeFrontiers,
}

impl Fixture {
    fn new(count: usize, alter: impl FnOnce(&mut Vec<Row>, &NativeStorage)) -> Self {
        let (mut storage, _, _) = fixture();
        for first in (2..count + 2).step_by(64) {
            let entries = (first..(first + 64).min(count + 2))
                .map(|index| clock(index as u64, time(2)))
                .collect::<Vec<_>>();
            apply(&mut storage, &entries);
        }
        let mut rows = storage
            .business
            .generic_receipts
            .iter()
            .map(|(id, row)| {
                let bytes = postcard::to_allocvec(&(*id, Some(&**row))).unwrap();
                let (_, facts) = generation::decode::inspect_generic(
                    &bytes,
                    &storage.business.frontiers,
                    &|| Ok(()),
                )
                .unwrap();
                Row {
                    id: *id,
                    facts: facts.unwrap(),
                    bytes,
                }
            })
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|row| *row.id.as_bytes());
        alter(&mut rows, &storage);
        let mut raw = Vec::new();
        let mut offsets = Vec::new();
        for row in &rows {
            offsets.push(raw.len() as u64);
            raw.extend_from_slice(&row.bytes);
        }
        raw.resize(raw.len().div_ceil(64 * 1024) * 64 * 1024, 0);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected-rows.bin");
        std::fs::write(&path, &raw).unwrap();
        let identity = PrefixIdentity {
            binding: [1; 32],
            file_epoch: 1,
            checkpoint_epoch: 1,
            operation_sequence: 1,
            frontiers: [2; 32],
            length: raw.len() as u64,
            block_bytes: 64 * 1024,
            digest: Sha256::digest(&raw).into(),
        };
        let owner = VerifiedAppendOwner::open(
            &path,
            identity,
            identity.length,
            || Ok(()),
            |reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                assert_eq!(observed, raw);
                Ok(())
            },
        )
        .unwrap();
        Self {
            _directory: directory,
            source: owner.current(),
            rows,
            offsets,
            frontiers: storage.business.frontiers.clone(),
        }
    }

    fn selections(&self) -> Vec<io::Result<GenericSelection>> {
        self.rows
            .iter()
            .zip(&self.offsets)
            .map(|(row, offset)| {
                Ok(GenericSelection {
                    id: row.id,
                    row: row.facts,
                    range: resident::SelectedRange::new(
                        Arc::clone(&self.source),
                        *offset,
                        row.bytes.len() as u32,
                        generation::MAX_ITEM,
                    )
                    .unwrap(),
                })
            })
            .collect()
    }

    fn serial(&self) -> io::Result<SelectedGenericRows> {
        let mut result = SelectedGenericRows::new(&self.frontiers);
        for row in &self.rows {
            result.insert(&row.bytes, row.id, row.facts, &|| Ok(()))?;
        }
        Ok(result)
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
        "all temporary charges must be refunded"
    );
    OBSERVED.with(|value| {
        let value = value.borrow();
        assert_eq!(value.started, value.joined);
        assert!(value.rows <= ROWS);
        assert!(value.bytes <= BYTES);
    });
}

fn exact(actual: &SelectedGenericRows, expected: &SelectedGenericRows) {
    assert_eq!(actual.rows.len(), expected.rows.len());
    assert_eq!(actual.table.count, expected.table.count);
    assert_eq!(actual.table.checksum, expected.table.checksum);
    for (id, row) in &expected.rows {
        assert_eq!(
            postcard::to_allocvec(&**actual.rows.get(id).unwrap()).unwrap(),
            postcard::to_allocvec(&**row).unwrap()
        );
    }
}

#[test]
fn native_selected_generic_parallel_matches_complete_serial_rows_and_counts() {
    let fixture = Fixture::new(257, |_, _| {});
    let expected = fixture.serial().unwrap();
    for available in [1, 2, 8, 128] {
        resources(available, 128 * 1024 * 1024, |resources, peak| {
            let mut actual = SelectedGenericRows::new(&fixture.frontiers);
            let before = generic_fingerprint_calls();
            actual
                .insert_selected_with(fixture.selections(), resources, &|| Ok(()))
                .unwrap();
            assert_eq!(
                generic_fingerprint_calls() - before,
                257,
                "count actual full fingerprints across joined threads"
            );
            exact(&actual, &expected);
            OBSERVED.with(|value| {
                let value = value.borrow();
                if available > 1 { assert!(value.started > 0); }
                eprintln!("native_selected_generic_parallel available={available} rows={} bytes={} peak_charged={} started={} joined={}", value.rows, value.bytes, peak.get(), value.started, value.joined);
            });
        });
    }
}

fn error(result: io::Result<()>) -> (io::ErrorKind, String) {
    let error = result.unwrap_err();
    (error.kind(), error.to_string())
}

#[test]
fn native_selected_generic_parallel_rejects_corruption_in_original_source_order() {
    for case in 0..9 {
        let fixture = Fixture::new(65, |rows, _| match case {
            0 => rows[9].facts.content[0] ^= 1,
            1 => rows[9].id = SessionConsensusRequestId::from_bytes([0xFA; 16]),
            2 => {
                rows[9].bytes.pop();
            }
            3 => rows[9].bytes.push(0),
            4 => rows[9].bytes[16] = 0,
            5 => rows[9].bytes[17] = 2,
            6 => rows[9].id = rows[8].id,
            7 => {
                rows[9].facts.content[0] ^= 1;
                rows[10].bytes.pop();
            }
            _ => {
                rows[9].facts.content[0] ^= 1;
                rows[33].facts.content[1] ^= 1;
            }
        });
        let expected = error(fixture.serial().map(|_| ()));
        for available in [1, 8] {
            resources(available, 128 * 1024 * 1024, |resources, _| {
                let mut actual = SelectedGenericRows::new(&fixture.frontiers);
                assert_eq!(
                    error(actual.insert_selected_with(fixture.selections(), resources, &|| Ok(()))),
                    expected,
                    "case {case}, available {available}"
                );
                assert_eq!(
                    actual.rows.len(),
                    9,
                    "only preceding fully checked source rows entered the private builder"
                );
            });
        }
    }
}

#[test]
fn native_selected_generic_parallel_joins_spawn_and_panic_failures_before_refund() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULTS.with(|value| value.set(Faults::default()));
        }
    }
    let _reset = Reset;
    for corrupt in [false, true] {
        let fixture = Fixture::new(64, |rows, _| {
            if corrupt {
                rows[0].facts.content[0] ^= 1;
            }
        });
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
                let mut actual = SelectedGenericRows::new(&fixture.frontiers);
                let actual =
                    error(actual.insert_selected_with(fixture.selections(), resources, &|| Ok(())));
                if corrupt {
                    assert_eq!(actual, error(fixture.serial().map(|_| ())));
                } else {
                    assert!(actual.1.contains("worker"));
                }
                OBSERVED.with(|value| assert!(value.borrow().started > 0));
            });
        }
    }
}

#[test]
fn native_selected_generic_parallel_keeps_cancellation_and_destination_on_caller() {
    let fixture = Fixture::new(257, |_, _| {});
    let caller = std::thread::current().id();
    for at in [1, 10, 50, 100, 200, 300] {
        resources(8, 128 * 1024 * 1024, |resources, _| {
            let calls = Cell::new(0);
            let mut actual = SelectedGenericRows::new(&fixture.frontiers);
            let result = actual.insert_selected_with(fixture.selections(), resources, &|| {
                assert_eq!(std::thread::current().id(), caller);
                calls.set(calls.get() + 1);
                if calls.get() == at {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "selected cancellation",
                    ))
                } else {
                    Ok(())
                }
            });
            assert_eq!(
                error(result),
                (
                    io::ErrorKind::Interrupted,
                    "selected cancellation".to_owned()
                )
            );
        });
    }
}

#[test]
fn native_selected_generic_parallel_pressure_preserves_original_serial_admissibility() {
    let fixture = Fixture::new(257, |_, _| {});
    let expected = fixture.serial().unwrap();
    for limit in [0, 32 * 1024, 128 * 1024, 3 * 1024 * 1024] {
        resources(8, limit, |resources, _| {
            let mut actual = SelectedGenericRows::new(&fixture.frontiers);
            actual
                .insert_selected_with(fixture.selections(), resources, &|| Ok(()))
                .unwrap();
            exact(&actual, &expected);
            OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
        });
    }
}

#[test]
fn native_selected_generic_small_conversions_keep_original_serial_scratch() {
    let fixture = Fixture::new(15, |_, _| {});
    for count in [0, 1, 15] {
        resources(8, 128 * 1024 * 1024, |resources, peak| {
            let mut actual = SelectedGenericRows::new(&fixture.frontiers);
            let before = generic_fingerprint_calls();
            actual
                .insert_selected_with(
                    fixture.selections().into_iter().take(count),
                    resources,
                    &|| Ok(()),
                )
                .unwrap();
            assert_eq!(actual.rows.len(), count);
            assert_eq!(generic_fingerprint_calls() - before, count as u64);
            assert_eq!(peak.get(), 0, "no batch descriptors, decoder copies or decoder threads for the original small serial lane");
            OBSERVED.with(|value| {
                let value = value.borrow();
                assert_eq!(value.rows, 0);
                assert_eq!(value.started, 0);
            });
        });
    }
}

#[test]
fn native_selected_generic_parallel_large_payload_uses_original_borrowed_serial_row() {
    let fixture = Fixture::new(65, |rows, storage| {
        let (id, Some(mut row)): (SessionConsensusRequestId, Option<NativeGenericReceipt>) =
            crate::consensus::native::image::binary::decode(&rows[4].bytes).unwrap()
        else {
            panic!("present row")
        };
        let NativeGenericReceipt::Ordinary(ordinary) = &mut row else {
            panic!("ordinary row")
        };
        let mut record = storage
            .business
            .keys
            .values()
            .find_map(|row| row.record.clone())
            .unwrap();
        let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(record.payload.as_bytes()).unwrap();
        envelope.ciphertext_and_tag.resize(80 * 1024, 0);
        record.payload =
            crate::EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
        ordinary.response.result = Ok(SessionMutationOutcome::ConsumerRecord(Some(record)));
        rows[4].bytes = postcard::to_allocvec(&(id, Some(row))).unwrap();
        rows[4].facts = generation::decode::inspect_generic(
            &rows[4].bytes,
            &storage.business.frontiers,
            &|| Ok(()),
        )
        .unwrap()
        .1
        .unwrap();
        assert!(rows[4].bytes.len() > INPUT);
    });
    let expected = fixture.serial().unwrap();
    resources(8, 128 * 1024 * 1024, |resources, _| {
        let mut actual = SelectedGenericRows::new(&fixture.frontiers);
        actual
            .insert_selected_with(fixture.selections(), resources, &|| Ok(()))
            .unwrap();
        exact(&actual, &expected);
        OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
    });
}
