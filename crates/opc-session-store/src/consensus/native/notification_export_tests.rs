use super::*;
use crate::backend::ReplicationOp;
use crate::consensus::native::changes::tests::{fixture, time};
use crate::consensus::native::prefix::{PrefixIdentity, VerifiedAppendOwner, VerifiedPrefix};
use sha2::{Digest as _, Sha256};
use std::cell::Cell;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};

type Output = Vec<(u64, String, String, String)>;

struct Row {
    facts: generation::facts::Row<generation::facts::Notification>,
    bytes: Vec<u8>,
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    source: Arc<VerifiedPrefix>,
    rows: Vec<Row>,
    offsets: Vec<u64>,
    frontiers: NativeFrontiers,
}

impl Fixture {
    fn new(count: usize, alter: impl FnOnce(&mut [Row], &NativeFrontiers)) -> Self {
        let (storage, _, _) = fixture();
        let original = storage
            .business
            .notifications
            .front()
            .unwrap()
            .resident()
            .unwrap();
        let ReplicationOp::Batch { ops } = &original.op else {
            panic!("fixture V2 pair")
        };
        let mut frontiers = storage.business.frontiers.clone();
        frontiers.watch_sequence = count as u64;
        let mut rows = (0..count)
            .map(|offset| {
                let entry = ReplicationEntry {
                    sequence: offset as u64 + 1,
                    op: match offset % 3 {
                        1 => ops[0].clone(),
                        2 => ops[1].clone(),
                        _ => original.op.clone(),
                    },
                    ..original.clone()
                };
                let bytes = postcard::to_allocvec(&entry).unwrap();
                let facts = generation::decode::inspect_notification(
                    &bytes,
                    entry.sequence,
                    &frontiers,
                    &|| Ok(()),
                )
                .unwrap();
                Row { facts, bytes }
            })
            .collect::<Vec<_>>();
        alter(&mut rows, &frontiers);
        let mut raw = Vec::new();
        let mut offsets = Vec::new();
        for row in &rows {
            offsets.push(raw.len() as u64);
            raw.extend_from_slice(&row.bytes);
        }
        raw.resize(raw.len().max(1).div_ceil(64 * 1024) * 64 * 1024, 0);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected-notifications.bin");
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
            frontiers,
        }
    }

    fn entries(&self) -> Vec<NotificationRow> {
        self.rows
            .iter()
            .zip(&self.offsets)
            .map(|(row, offset)| {
                NotificationRow::new(
                    NativeNotification::from_admitted_range(
                        row.facts,
                        Arc::clone(&self.source),
                        *offset,
                        row.bytes.len() as u32,
                    )
                    .unwrap(),
                )
                .unwrap()
            })
            .collect()
    }

    // Independent original serial export: complete selected read, original
    // payload charge and all four exact SQL values in their original order.
    fn serial(&self, entries: &[NotificationRow]) -> (io::Result<()>, Output) {
        let mut output = Vec::new();
        let result = (|| {
            for row in entries {
                let owned = row.read(&self.frontiers, &|| Ok(()))?;
                let entry = owned.entry();
                let bytes = changes::notification_payload(entry)? * 12 + 64 * 1024;
                let _memory = VerificationMemory::reserve(bytes)?;
                output.push(values(entry)?);
            }
            Ok(())
        })();
        (result, output)
    }
}

fn values(entry: &ReplicationEntry) -> io::Result<(u64, String, String, String)> {
    Ok((
        entry.sequence,
        entry.tx_id.as_str().to_owned(),
        serde_json::to_string(entry).map_err(io::Error::other)?,
        crate::sqlite::ops::format_rfc3339_normalized(entry.timestamp),
    ))
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
    rows: &[NotificationRow],
    resources: &Resources<'_>,
) -> (io::Result<()>, Output) {
    let mut output = Vec::new();
    let caller = std::thread::current().id();
    let result = NativeNotification::visit_export_with(
        rows,
        &fixture.frontiers,
        resources,
        &|| {
            assert_eq!(std::thread::current().id(), caller);
            Ok(())
        },
        &mut |entry| {
            assert_eq!(std::thread::current().id(), caller);
            output.push(values(entry)?);
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
fn native_notification_export_parallel_preserves_complete_serial_sql_values() {
    let fixture = Fixture::new(257, |_, _| {});
    let rows = fixture.entries();
    let (result, expected) = fixture.serial(&rows);
    result.unwrap();
    for available in [1, 2, 8, 128] {
        resources(available, 128 * 1024 * 1024, |resources, peak| {
            let (result, actual) = visit(&fixture, &rows, resources);
            result.unwrap();
            assert_eq!(actual, expected);
            assert!(peak.get() <= BYTES + INPUT + WORKERS * STACK + 64 * 1024);
            OBSERVED.with(|value| {
                let value = value.borrow();
                if available > 1 { assert!(value.started > 0); }
                eprintln!("native_notification_export_parallel available={available} rows={} bytes={} peak_charged={} started={} joined={}", value.rows, value.bytes, peak.get(), value.started, value.joined);
            });
        });
    }
}

#[test]
fn native_notification_export_parallel_preserves_first_full_validation_failure() {
    for case in 0..8 {
        let fixture = Fixture::new(65, |rows, _| match case {
            0 => rows[9].facts.content[0] ^= 1,
            1 => rows[9].facts.facts.sequence += 1,
            2 => rows[9].facts.facts.timestamp = time(2),
            3 => {
                rows[9].bytes.pop();
            }
            4 => rows[9].bytes.push(0),
            5 => {
                rows[9].facts.content[0] ^= 1;
                rows[10].bytes.pop();
            }
            6 => {
                rows[9].facts.content[0] ^= 1;
                rows[33].facts.content[0] ^= 1;
            }
            _ => rows[9].bytes[0] = 0,
        });
        let rows = fixture.entries();
        let (result, expected_rows) = fixture.serial(&rows);
        let expected = error(result);
        assert_eq!(expected_rows.len(), 9);
        for available in [1, 8] {
            resources(available, 128 * 1024 * 1024, |resources, _| {
                let (result, actual) = visit(&fixture, &rows, resources);
                assert_eq!(error(result), expected, "case {case}, CPU {available}");
                assert_eq!(actual, expected_rows);
            });
        }
    }
}

#[test]
fn native_notification_export_parallel_fences_selected_source_and_frontiers() {
    for earlier_corruption in [false, true] {
        let fixture = Fixture::new(65, |rows, _| {
            if earlier_corruption {
                rows[9].facts.content[0] ^= 1;
            }
        });
        let bad_source = Fixture::new(1, |_, _| {});
        let mut rows = fixture.entries();
        rows[10] = bad_source.entries().pop().unwrap();
        let mut bytes = std::fs::read(&bad_source.path).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&bad_source.path, bytes).unwrap();
        let (result, expected_rows) = fixture.serial(&rows);
        let expected = error(result);
        resources(8, 128 * 1024 * 1024, |resources, _| {
            let (result, actual) = visit(&fixture, &rows, resources);
            assert_eq!(error(result), expected);
            assert_eq!(actual, expected_rows);
        });
    }
    let mut fixture = Fixture::new(65, |_, _| {});
    fixture.frontiers.logical_time = Some(time(0));
    let rows = fixture.entries();
    let expected = error(fixture.serial(&rows).0);
    resources(8, 128 * 1024 * 1024, |resources, _| {
        let (result, actual) = visit(&fixture, &rows, resources);
        assert_eq!(error(result), expected);
        assert!(actual.is_empty());
    });
}

#[test]
fn native_notification_export_parallel_joins_failed_workers_before_refund() {
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
        let rows = fixture.entries();
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
                let (result, _) = visit(&fixture, &rows, resources);
                let actual = error(result);
                if corrupt {
                    assert_eq!(actual, error(fixture.serial(&rows).0));
                } else {
                    assert!(actual.1.contains("worker"));
                }
                OBSERVED.with(|value| assert!(value.borrow().started > 0));
            });
        }
    }
}

#[test]
fn native_notification_export_parallel_preserves_caller_cancellation_and_sql_error() {
    let fixture = Fixture::new(257, |_, _| {});
    let rows = fixture.entries();
    let caller = std::thread::current().id();
    for at in [1, 10, 50, 100, 200, 300, 1000] {
        resources(8, 128 * 1024 * 1024, |resources, _| {
            let calls = Cell::new(0);
            let result = NativeNotification::visit_export_with(
                &rows,
                &fixture.frontiers,
                resources,
                &|| {
                    assert_eq!(std::thread::current().id(), caller);
                    calls.set(calls.get() + 1);
                    if calls.get() >= at {
                        Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "selected notification cancellation",
                        ))
                    } else {
                        Ok(())
                    }
                },
                &mut |_| {
                    assert_eq!(std::thread::current().id(), caller);
                    Ok(())
                },
            );
            assert_eq!(
                error(result),
                (
                    io::ErrorKind::Interrupted,
                    "selected notification cancellation".to_owned()
                )
            );
        });
    }
    resources(8, 128 * 1024 * 1024, |resources, _| {
        let emitted = Cell::new(0);
        let result = NativeNotification::visit_export_with(
            &rows,
            &fixture.frontiers,
            resources,
            &|| Ok(()),
            &mut |_| {
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
fn native_notification_export_parallel_pressure_small_and_resident_rows_keep_serial_admission() {
    let fixture = Fixture::new(65, |_, _| {});
    let mut rows = fixture.entries();
    let (result, expected) = fixture.serial(&rows);
    result.unwrap();
    for limit in [0, 32 * 1024, 128 * 1024, 3 * 1024 * 1024, 6 * 1024 * 1024] {
        resources(8, limit, |resources, peak| {
            let (result, actual) = visit(&fixture, &rows, resources);
            result.unwrap();
            assert_eq!(actual, expected);
            assert!(peak.get() <= limit);
        });
    }
    for count in [0, 1, 15] {
        resources(8, 128 * 1024 * 1024, |resources, peak| {
            let (result, actual) = visit(&fixture, &rows[..count], resources);
            result.unwrap();
            assert_eq!(actual, expected[..count]);
            assert_eq!(peak.get(), 0);
        });
    }
    let entry = rows[40]
        .read(&fixture.frontiers, &|| Ok(()))
        .unwrap()
        .entry()
        .clone();
    rows[40] = NotificationRow::new(NativeNotification::new(entry)).unwrap();
    resources(8, 128 * 1024 * 1024, |resources, _| {
        let (result, actual) = visit(&fixture, &rows, resources);
        result.unwrap();
        assert_eq!(actual, expected);
    });
}

#[test]
fn native_notification_export_parallel_large_payload_keeps_original_full_codec() {
    let fixture = Fixture::new(65, |rows, frontiers| {
        let mut entry: ReplicationEntry = postcard::from_bytes(&rows[5].bytes).unwrap();
        let ReplicationOp::CompareAndSet { new_record, .. } = &mut entry.op else {
            panic!("ordinary CAS fixture")
        };
        let mut envelope =
            opc_crypto::CryptoEnvelopeV1::decode(new_record.payload.as_bytes()).unwrap();
        envelope.ciphertext_and_tag = vec![0; 80 * 1024];
        new_record.payload =
            crate::EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
        rows[5].bytes = postcard::to_allocvec(&entry).unwrap();
        rows[5].facts = generation::decode::inspect_notification(
            &rows[5].bytes,
            entry.sequence,
            frontiers,
            &|| Ok(()),
        )
        .unwrap();
        assert!(rows[5].bytes.len() > INPUT);
    });
    let rows = fixture.entries();
    let (result, expected) = fixture.serial(&rows);
    result.unwrap();
    resources(8, 128 * 1024 * 1024, |resources, _| {
        let (result, actual) = visit(&fixture, &rows, resources);
        result.unwrap();
        assert_eq!(actual, expected);
        OBSERVED.with(|value| assert_eq!(value.borrow().started, 0));
    });
}
