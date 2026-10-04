use super::*;
use crate::consensus::native::changes::tests::{clock, command, fixture, request, time};
use crate::consensus::native::prefix::{PrefixIdentity, VerifiedAppendOwner, VerifiedPrefix};
use sha2::{Digest as _, Sha256};
use std::cell::Cell;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

type Output = Vec<(LogId<SessionConsensusNodeId>, Vec<u8>)>;

struct Row {
    facts: generation::facts::Row<generation::facts::Log>,
    bytes: Vec<u8>,
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    source: Arc<VerifiedPrefix>,
    rows: Vec<Row>,
    offsets: Vec<u64>,
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
}

impl Fixture {
    fn new(count: usize, alter: impl FnOnce(&mut [Row], &NativeStorage)) -> Self {
        let (storage, _, _) = fixture();
        let mut rows = (0..count)
            .map(|offset| {
                let index = offset as u64 + 2;
                let entry = match offset % 4 {
                    0 => {
                        let mut entry = storage
                            .log
                            .entries
                            .get(&0)
                            .unwrap()
                            .resident()
                            .unwrap()
                            .entry
                            .clone();
                        entry.log_id.index = index;
                        entry
                    }
                    2 => command(index, &request(index, None), time(2), false),
                    _ => clock(index, time(2)),
                };
                let bytes = serde_json::to_vec(&entry).unwrap();
                let facts = generation::decode::inspect_log(
                    &bytes,
                    index,
                    storage.business.identity,
                    &storage.business.members,
                    &|| Ok(()),
                )
                .unwrap();
                Row { facts, bytes }
            })
            .collect::<Vec<_>>();
        alter(&mut rows, &storage);
        let mut raw = Vec::new();
        let mut offsets = Vec::new();
        for row in &rows {
            offsets.push(raw.len() as u64);
            raw.extend_from_slice(&row.bytes);
        }
        raw.resize(raw.len().max(1).div_ceil(64 * 1024) * 64 * 1024, 0);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected-logs.bin");
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
            path,
            source: owner.current(),
            rows,
            offsets,
            identity: storage.business.identity,
            members: storage.business.members.clone(),
        }
    }

    fn entries(&self) -> Vec<SharedRow<NativeLogEntry>> {
        self.rows
            .iter()
            .zip(&self.offsets)
            .map(|(row, offset)| {
                SharedRow::new(
                    NativeLogEntry::from_admitted_range(
                        row.facts,
                        Arc::clone(&self.source),
                        *offset,
                        row.bytes.len() as u32,
                        self.identity,
                        &self.members,
                    )
                    .unwrap(),
                )
                .unwrap()
            })
            .collect()
    }

    // The original serial exporter remains the independent byte/error oracle.
    // It reads the selected range through NativeLogEntry::read_bytes and uses
    // its original full-fact comparison, without the new preparation type.
    fn serial(&self, entries: &[SharedRow<NativeLogEntry>]) -> (io::Result<()>, Output) {
        let mut output = Vec::new();
        let result = (|| {
            for entry in entries {
                let bytes = entry.read_bytes(self.identity, &self.members, &|| Ok(()))?;
                output.push((entry.id(), bytes.bytes().to_vec()));
            }
            Ok(())
        })();
        (result, output)
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
        "refund every temporary charge"
    );
    OBSERVED.with(|value| {
        let value = value.borrow();
        assert_eq!(value.started, value.joined);
        assert!(value.rows <= ROWS);
        assert!(value.bytes <= BYTES);
    });
}

fn visit(
    fixture: &Fixture,
    entries: &[SharedRow<NativeLogEntry>],
    resources: &Resources<'_>,
) -> (io::Result<()>, Output) {
    let mut output = Vec::new();
    let caller = std::thread::current().id();
    let result = NativeLogEntry::visit_export_with(
        &entries.iter().collect::<Vec<_>>(),
        fixture.identity,
        &fixture.members,
        resources,
        &|| {
            assert_eq!(std::thread::current().id(), caller);
            Ok(())
        },
        &mut |id, bytes| {
            assert_eq!(std::thread::current().id(), caller);
            output.push((id, bytes.to_vec()));
            Ok(())
        },
    );
    (result, output)
}

fn error(result: io::Result<()>) -> (io::ErrorKind, String) {
    let error = result.unwrap_err();
    (error.kind(), error.to_string())
}

#[test]
fn native_log_export_parallel_preserves_complete_serial_bytes_and_full_ids() {
    let fixture = Fixture::new(257, |_, _| {});
    let entries = fixture.entries();
    let (result, expected) = fixture.serial(&entries);
    result.unwrap();
    for available in [1, 2, 8, 128] {
        resources(available, 128 * 1024 * 1024, |resources, peak| {
            let before = fixture.source.blocks_read();
            let (result, actual) = visit(&fixture, &entries, resources);
            result.unwrap();
            assert_eq!(actual, expected);
            assert!(
                fixture.source.blocks_read() - before
                    <= fixture.source.identity().length / (64 * 1024)
            );
            OBSERVED.with(|value| {
                let value = value.borrow();
                if available > 1 { assert!(value.started > 0); }
                eprintln!("native_log_export_parallel available={available} rows={} bytes={} peak_charged={} started={} joined={}", value.rows, value.bytes, peak.get(), value.started, value.joined);
            });
        });
    }
}

#[test]
fn native_log_export_parallel_preserves_earliest_complete_validation_failure() {
    for case in 0..9 {
        let fixture = Fixture::new(65, |rows, _| match case {
            0 => rows[9].facts.content[0] ^= 1,
            1 => rows[9].facts.facts.id.index += 1,
            2 => rows[9].facts.facts.id.leader_id.term += 1,
            3 => rows[9].facts.facts.membership = Some([0xAC; 32]),
            4 => {
                rows[9].bytes.pop();
            }
            5 => rows[9].bytes.push(0),
            6 => rows[9].bytes[0] = b'[',
            7 => {
                rows[9].facts.content[0] ^= 1;
                rows[10].bytes.pop();
            }
            _ => {
                rows[9].facts.content[0] ^= 1;
                rows[33].facts.content[1] ^= 1;
            }
        });
        let entries = fixture.entries();
        let (result, expected_rows) = fixture.serial(&entries);
        let expected = error(result);
        assert_eq!(expected_rows.len(), 9);
        for available in [1, 8] {
            resources(available, 128 * 1024 * 1024, |resources, _| {
                let (result, actual) = visit(&fixture, &entries, resources);
                assert_eq!(error(result), expected, "case {case}, CPU {available}");
                assert_eq!(actual, expected_rows);
            });
        }
    }
}

#[test]
fn native_log_export_parallel_fences_changed_source_and_authority_without_retry() {
    for earlier_corruption in [false, true] {
        let fixture = Fixture::new(65, |rows, _| {
            if earlier_corruption {
                rows[9].facts.content[0] ^= 1;
            }
        });
        let bad_source = Fixture::new(1, |_, _| {});
        let mut entries = fixture.entries();
        entries[10] = bad_source.entries().pop().unwrap();
        let mut bytes = std::fs::read(&bad_source.path).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&bad_source.path, bytes).unwrap();
        let (result, expected_rows) = fixture.serial(&entries);
        let expected = error(result);
        resources(8, 128 * 1024 * 1024, |resources, _| {
            let (result, actual) = visit(&fixture, &entries, resources);
            assert_eq!(error(result), expected);
            assert_eq!(actual, expected_rows);
        });
    }
    let fixture = Fixture::new(65, |_, _| {});
    let mut entries = fixture.entries();
    let mut changed = (*entries[9]).clone();
    let Body::Selected(selected) = &mut changed.body else {
        panic!("selected log")
    };
    selected.authority[0] ^= 1;
    entries[9] = SharedRow::new(changed).unwrap();
    let (result, expected_rows) = fixture.serial(&entries);
    let expected = error(result);
    resources(8, 128 * 1024 * 1024, |resources, _| {
        let (result, actual) = visit(&fixture, &entries, resources);
        assert_eq!(error(result), expected);
        assert_eq!(actual, expected_rows);
    });
}

#[test]
fn native_log_export_parallel_joins_failed_workers_before_refund() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULTS.with(|value| value.set(Faults::default()));
        }
    }
    let _reset = Reset;
    for corrupt in [false, true] {
        let fixture = Fixture::new(65, |rows, _| {
            if corrupt {
                rows[0].facts.content[0] ^= 1;
            }
        });
        let entries = fixture.entries();
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
                let (result, _) = visit(&fixture, &entries, resources);
                let actual = error(result);
                if corrupt {
                    assert_eq!(actual, error(fixture.serial(&entries).0));
                } else {
                    assert!(actual.1.contains("worker"));
                }
                OBSERVED.with(|value| assert!(value.borrow().started > 0));
            });
        }
    }
}

#[test]
fn native_log_export_parallel_preserves_caller_cancellation_and_emission_errors() {
    let fixture = Fixture::new(257, |_, _| {});
    let entries = fixture.entries();
    let rows = entries.iter().collect::<Vec<_>>();
    let caller = std::thread::current().id();
    for at in [1, 10, 50, 100, 200, 300, 1000] {
        resources(8, 128 * 1024 * 1024, |resources, _| {
            let calls = Cell::new(0);
            let result = NativeLogEntry::visit_export_with(
                &rows,
                fixture.identity,
                &fixture.members,
                resources,
                &|| {
                    assert_eq!(std::thread::current().id(), caller);
                    calls.set(calls.get() + 1);
                    if calls.get() == at {
                        Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "selected log cancellation",
                        ))
                    } else {
                        Ok(())
                    }
                },
                &mut |_, _| {
                    assert_eq!(std::thread::current().id(), caller);
                    Ok(())
                },
            );
            assert_eq!(
                error(result),
                (
                    io::ErrorKind::Interrupted,
                    "selected log cancellation".to_owned()
                )
            );
        });
    }
    resources(8, 128 * 1024 * 1024, |resources, _| {
        let emitted = Cell::new(0);
        let result = NativeLogEntry::visit_export_with(
            &rows,
            fixture.identity,
            &fixture.members,
            resources,
            &|| Ok(()),
            &mut |_, _| {
                emitted.set(emitted.get() + 1);
                if emitted.get() == 11 {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "exact SQL writer failure",
                    ))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(emitted.get(), 11);
        assert_eq!(
            error(result),
            (
                io::ErrorKind::WriteZero,
                "exact SQL writer failure".to_owned()
            )
        );
    });
}

#[test]
fn native_log_export_parallel_pressure_and_small_inputs_keep_serial_admissibility() {
    let fixture = Fixture::new(65, |_, _| {});
    let entries = fixture.entries();
    let (result, expected) = fixture.serial(&entries);
    result.unwrap();
    for limit in [0, 32 * 1024, 128 * 1024, 3 * 1024 * 1024] {
        resources(8, limit, |resources, peak| {
            let (result, actual) = visit(&fixture, &entries, resources);
            result.unwrap();
            assert_eq!(actual, expected);
            assert!(peak.get() <= limit);
            if limit == 32 * 1024 {
                OBSERVED.with(|value| {
                    assert_eq!(
                        value.borrow().preflight_serial,
                        1,
                        "preflight pressure releases staging before the original serial decoder"
                    );
                });
            }
        });
    }
    for count in [0, 1, 15] {
        resources(8, 128 * 1024 * 1024, |resources, peak| {
            let (result, actual) = visit(&fixture, &entries[..count], resources);
            result.unwrap();
            assert_eq!(actual, expected[..count]);
            assert_eq!(peak.get(), 0, "small input keeps the original serial path");
            OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
        });
    }
}

#[test]
fn native_log_export_parallel_large_legacy_row_keeps_complete_original_codec() {
    let fixture = Fixture::new(65, |rows, storage| {
        // Legacy JSON permits whitespace; it still crosses the original full
        // arbitrary-byte codec. A large input must not acquire a batch permit.
        rows[5].bytes.extend(std::iter::repeat_n(b' ', 80 * 1024));
        rows[5].facts = generation::decode::inspect_log(
            &rows[5].bytes,
            rows[5].facts.facts.id.index,
            storage.business.identity,
            &storage.business.members,
            &|| Ok(()),
        )
        .unwrap();
        assert!(rows[5].bytes.len() > INPUT);
    });
    let entries = fixture.entries();
    let (result, expected) = fixture.serial(&entries);
    result.unwrap();
    resources(8, 128 * 1024 * 1024, |resources, _| {
        let (result, actual) = visit(&fixture, &entries, resources);
        result.unwrap();
        assert_eq!(actual, expected);
        OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
    });
}
