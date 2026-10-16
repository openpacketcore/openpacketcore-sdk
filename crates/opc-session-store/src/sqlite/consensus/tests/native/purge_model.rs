//! Seeded operation schedules against an independent retained-row model and SQL.

use super::*;
use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
use crate::sqlite::consensus::wal::native::Opening;
use crate::SessionPersistenceMode;

struct Model {
    rows: BTreeMap<u64, Entry<SessionRaftTypeConfig>>,
    committed: u64,
    applied: u64,
    purged: Option<u64>,
    snapshots: Vec<IncomingSnapshot>,
    operations: [usize; 8],
}

impl Model {
    fn last(&self) -> u64 {
        self.rows
            .last_key_value()
            .map(|(index, _)| *index)
            .or(self.purged)
            .unwrap()
    }

    fn apply(&mut self, fixture: &Fixture) {
        if self.applied == self.committed {
            return;
        }
        let entries = self
            .rows
            .range(self.applied + 1..=self.committed)
            .map(|(_, entry)| entry.clone())
            .collect::<Vec<_>>();
        // SQL remains an independent business-state oracle. Equal-byte native
        // append/commit retries are intentional and also exercise dirty rows.
        fixture.parity(&entries);
        self.applied = self.committed;
        self.operations[2] += 1;
    }

    fn snapshot(&mut self, fixture: &Fixture) {
        let mut snapshot = IncomingSnapshot::new(&fixture.wal.native_export_snapshot().unwrap());
        snapshot.candidate.0.snapshot_id = fixture.wal.native_snapshot_id().unwrap();
        fixture
            .wal
            .native_publish_snapshot(snapshot.candidate.clone())
            .unwrap();
        self.snapshots.push(snapshot);
        self.operations[3] += 1;
    }

    fn check(&self, fixture: &Fixture, seed: u64, step: usize) {
        let actual = fixture.wal.read(0, self.last() + 1).unwrap();
        assert_eq!(
            serde_json::to_vec(&actual).unwrap(),
            serde_json::to_vec(&self.rows.values().collect::<Vec<_>>()).unwrap(),
            "exact retained payloads seed={seed} step={step}"
        );
        let (count, first, purged, _) = fixture.wal.native_log_inventory_for_test().unwrap();
        assert_eq!(count, self.rows.len(), "seed={seed} step={step}");
        assert_eq!(first, self.rows.first_key_value().map(|(index, _)| *index));
        assert_eq!(purged, self.purged);
        assert_eq!(
            fixture.wal.committed().unwrap(),
            Some(log_id(self.committed))
        );
        let expected_first = self.purged.map_or(0, |index| index + 1);
        if !self.rows.is_empty() {
            assert_eq!(first, Some(expected_first));
            assert_eq!(self.rows.len() as u64, self.last() - expected_first + 1);
        }
        fixture
            .wal
            .with_native_read(|state| {
                assert_eq!(state.applied(), Some(log_id(self.applied)));
                assert_eq!(*state.membership().log_id(), Some(log_id(0)));
                assert_eq!(
                    state.current_snapshot(),
                    self.snapshots
                        .last()
                        .map(|snapshot| snapshot.candidate.clone())
                );
                Ok(())
            })
            .unwrap();
        let exported = fixture.wal.native_export_snapshot().unwrap();
        let oracle = fixture.oracle.conn.blocking_lock();
        for table in [
            "consensus_machine",
            "consensus_applied",
            "consensus_membership",
            "consensus_request_outcomes",
            "session_records",
            "leases",
            "key_fences",
            "session_replication_log",
        ] {
            assert_eq!(
                super::ordinary::rows(&exported, table),
                super::ordinary::rows(&oracle, table),
                "SQL business parity for {table}, seed={seed} step={step}"
            );
        }
    }

    fn reopen(&mut self, fixture: &mut Fixture) {
        // Complete the chosen application batch before this selected-cut
        // reopen; process loss with an incomplete cut has its own crash matrix.
        self.apply(fixture);
        let digest = fixture
            .wal
            .with_native_read(|state| Ok(state.application_digest()))
            .unwrap();
        fixture.wal.checkpoint().unwrap();
        fixture.wal.shutdown().unwrap();
        fixture.wal = Opening::new(
            &fixture.directory.path().join("wal"),
            fixture.wal.binding(),
            None,
            Limits::default(),
            IoControl::default(),
        )
        .unwrap()
        .finish(|| match self.snapshots.last() {
            Some(snapshot) => snapshot.source().unwrap().verify(),
            None => Ok(()),
        })
        .unwrap();
        assert_eq!(
            fixture
                .wal
                .with_native_read(|state| Ok(state.application_digest()))
                .unwrap(),
            digest
        );
        self.operations[7] += 1;
    }
}

fn next(random: &mut u64) -> u64 {
    *random = random
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *random >> 32
}

fn randomized_schedule(mode: SessionPersistenceMode, seed: u64) -> (Fixture, Model) {
    let mut random = seed;
    let mut fixture = Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
    fixture.parity(&[formation()]);
    let mut model = Model {
        rows: BTreeMap::from([(0, formation())]),
        committed: 0,
        applied: 0,
        purged: None,
        snapshots: Vec::new(),
        operations: [0; 8],
    };
    for step in 0..192 {
        match next(&mut random) % 8 {
            0 => {
                let first = model.last() + 1;
                let count = 1 + next(&mut random) % 4;
                let entries = (first..first + count)
                    .map(|index| Entry {
                        log_id: log_id(index),
                        payload: EntryPayload::Normal(SessionConsensusCommand {
                            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                            identity: identity(),
                            request_id: SessionConsensusRequestId::from_bytes(
                                u128::from(index).to_be_bytes(),
                            ),
                            logical_time: timestamp(0).add_seconds(index as i64).unwrap(),
                            intent: SessionMutationIntent::Authorized {
                                origin: node_id(),
                                authority_identity: identity(),
                                mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
                            },
                        }),
                    })
                    .collect::<Vec<_>>();
                fixture
                    .wal
                    .submit(append(&entries))
                    .unwrap()
                    .wait()
                    .unwrap();
                model
                    .rows
                    .extend(entries.into_iter().map(|entry| (entry.log_id.index, entry)));
                model.operations[0] += 1;
            }
            1 if model.committed < model.last() => {
                model.committed += 1 + next(&mut random) % (model.last() - model.committed);
                fixture
                    .wal
                    .submit(Operation::Committed(Some(log_id(model.committed))))
                    .unwrap()
                    .wait()
                    .unwrap();
                model.operations[1] += 1;
            }
            2 => model.apply(&fixture),
            3 => model.snapshot(&fixture),
            4 => {
                if let Some(snapshot) = model.snapshots.last() {
                    let maximum = snapshot.candidate.0.last_log_id.unwrap().index;
                    let first = model.purged.map_or(0, |index| index + 1);
                    if first <= maximum {
                        let through = first + next(&mut random) % (maximum - first + 1);
                        fixture
                            .wal
                            .submit(Operation::Purge(log_id(through)))
                            .unwrap()
                            .wait()
                            .unwrap();
                        model.rows.retain(|index, _| *index > through);
                        model.purged = Some(through);
                        model.operations[4] += 1;
                    }
                }
            }
            5 if model.committed < model.last() => {
                let since =
                    model.committed + 1 + next(&mut random) % (model.last() - model.committed);
                fixture
                    .wal
                    .submit(Operation::Truncate(log_id(since)))
                    .unwrap()
                    .wait()
                    .unwrap();
                model.rows.retain(|index, _| *index < since);
                model.operations[5] += 1;
            }
            6 => {
                fixture.wal.checkpoint().unwrap();
                model.operations[6] += 1;
            }
            7 => model.reopen(&mut fixture),
            _ => {}
        }
        model.check(&fixture, seed, step);
    }
    model.reopen(&mut fixture);
    model.check(&fixture, seed, 192);
    assert!(
        model.operations.iter().all(|count| *count > 0),
        "seed={seed} operations={:?}",
        model.operations
    );
    eprintln!(
        "NATIVE_PURGE_MODEL mode={mode:?} seed={seed} operations={:?}",
        model.operations
    );
    (fixture, model)
}

#[test]
fn native_randomized_prefix_reclamation_matches_retained_rows_and_sql_business_state() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        for seed in [0x118, 0x29B, 0x34C, 0x45D] {
            randomized_schedule(mode, seed);
        }
    }
}

const CRASH_CASE: &str = "OPC_NATIVE_PURGE_MODEL_CRASH_CASE";
const CRASH_REPORT: &str = "OPC_NATIVE_PURGE_MODEL_CRASH_REPORT";

#[derive(serde::Serialize, serde::Deserialize)]
struct CrashReport {
    wal: PathBuf,
    basis: [u8; 32],
    snapshots: Vec<super::purge_crash::SnapshotFile>,
    before: Vec<Entry<SessionRaftTypeConfig>>,
    after: Vec<Entry<SessionRaftTypeConfig>>,
    committed: u64,
    applied: u64,
    purged: Option<u64>,
    business: [u8; 32],
    oracle: BTreeMap<String, Vec<Vec<String>>>,
}

fn crash_model(fixture: Fixture, model: Model, boundary: &str) -> ! {
    use crate::sqlite::consensus::wal::Point;
    use std::sync::atomic::{AtomicBool, Ordering};

    let point = match boundary {
        "before" => Point::BeforeBasisSelector,
        "after" => Point::AfterBasisSelectorRename,
        _ => panic!("unknown model crash boundary"),
    };
    // Preserve the randomly generated cut, then append a new uncommitted
    // suffix. Durable replays it from the WAL; Async recovers it only after
    // the selector rename. Neither outcome changes the business oracle.
    fixture.wal.shutdown().unwrap();
    let armed = Arc::new(AtomicBool::new(false));
    let hook_armed = Arc::clone(&armed);
    let control = IoControl {
        hook: Arc::new(move |observed| {
            if observed == point && hook_armed.load(Ordering::SeqCst) {
                std::process::exit(73);
            }
            Ok(())
        }),
        ..IoControl::default()
    };
    let wal_path = fixture.directory.path().join("wal");
    let wal = Opening::new(
        &wal_path,
        fixture.wal.binding(),
        None,
        Limits::default(),
        control,
    )
    .unwrap()
    .finish(|| match model.snapshots.last() {
        Some(snapshot) => snapshot.source().unwrap().verify(),
        None => Ok(()),
    })
    .unwrap();
    let added = (model.last() + 1..=model.last() + 3)
        .map(|index| Entry {
            log_id: log_id(index),
            payload: EntryPayload::Blank,
        })
        .collect::<Vec<_>>();
    let before = model.rows.values().cloned().collect::<Vec<_>>();
    let after = before.iter().chain(&added).cloned().collect();
    let conn = fixture.oracle.conn.blocking_lock();
    let oracle = [
        "consensus_machine",
        "consensus_applied",
        "consensus_membership",
        "consensus_request_outcomes",
        "session_records",
        "leases",
        "key_fences",
        "session_replication_log",
    ]
    .into_iter()
    .map(|table| (table.to_owned(), super::ordinary::rows(&conn, table)))
    .collect();
    let report = CrashReport {
        wal: wal_path,
        basis: wal.binding().basis,
        snapshots: model
            .snapshots
            .iter()
            .map(super::purge_crash::SnapshotFile::capture)
            .collect(),
        before,
        after,
        committed: model.committed,
        applied: model.applied,
        purged: model.purged,
        business: wal
            .with_native_read(|state| state.business_digest_for_test())
            .unwrap(),
        oracle,
    };
    std::fs::write(
        std::env::var(CRASH_REPORT).unwrap(),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    armed.store(true, Ordering::SeqCst);
    wal.submit(append(&added)).unwrap().wait().unwrap();
    wal.checkpoint().unwrap();
    panic!("model crash hook was not reached");
}

#[test]
fn native_randomized_prefix_model_recovers_process_loss_at_checkpoint_twice() {
    use crate::sqlite::consensus::wal::{snapshot::InstallSource, Binding};

    if let Ok(case) = std::env::var(CRASH_CASE) {
        let mut parts = case.split(':');
        let mode = match parts.next().unwrap() {
            "Durable" => SessionPersistenceMode::Durable,
            "Async" => SessionPersistenceMode::Async,
            _ => panic!("unknown model persistence mode"),
        };
        let seed = parts.next().unwrap().parse().unwrap();
        let boundary = parts.next().unwrap();
        assert!(parts.next().is_none());
        // Each child executes the complete schedule for its own seed. The
        // parent covers every mode, seed and crash boundary exactly once.
        let (fixture, model) = randomized_schedule(mode, seed);
        crash_model(fixture, model, boundary);
    }

    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        for seed in [0x118, 0x29B, 0x34C, 0x45D] {
            for boundary in ["before", "after"] {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("model.json");
                let case = format!("{mode:?}:{seed}:{boundary}");
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "sqlite::consensus::tests::native::purge_model::native_randomized_prefix_model_recovers_process_loss_at_checkpoint_twice",
                        "--test-threads=1",
                        "--nocapture",
                    ])
                    .env(CRASH_CASE, &case)
                    .env(CRASH_REPORT, &path)
                    .env("TMPDIR", directory.path())
                    .test_output()
                    .unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(73),
                    "{case}\n{}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let report: CrashReport =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                let binding = Binding {
                    identity: identity(),
                    generation: [0xE1; 32],
                    basis: report.basis,
                    native: true,
                    persistence: mode,
                    async_closed_format: mode == SessionPersistenceMode::Async,
                    async_recovery_format: mode == SessionPersistenceMode::Async,
                };
                let expected = if mode == SessionPersistenceMode::Durable || boundary == "after" {
                    &report.after
                } else {
                    &report.before
                };
                for reopen in 0..2 {
                    let opening = Opening::new(
                        &report.wal,
                        binding,
                        None,
                        Limits::default(),
                        IoControl::default(),
                    )
                    .unwrap();
                    let sources = opening
                        .snapshots()
                        .iter()
                        .map(|candidate| {
                            report
                                .snapshots
                                .iter()
                                .find(|snapshot| &snapshot.candidate == candidate)
                                .unwrap()
                                .source()
                                .unwrap()
                        })
                        .collect::<Vec<_>>();
                    let wal = opening
                        .finish(|| sources.iter().try_for_each(InstallSource::verify))
                        .unwrap();
                    let last = expected
                        .last()
                        .map(|entry| entry.log_id.index)
                        .or(report.purged)
                        .unwrap();
                    assert_eq!(
                        serde_json::to_vec(&wal.read(0, last + 1).unwrap()).unwrap(),
                        serde_json::to_vec(expected).unwrap(),
                        "exact recovered rows {case} reopen={reopen}"
                    );
                    let (count, first, purged, _) = wal.native_log_inventory_for_test().unwrap();
                    assert_eq!(
                        (count, first, purged),
                        (
                            expected.len(),
                            expected.first().map(|entry| entry.log_id.index),
                            report.purged,
                        )
                    );
                    assert_eq!(wal.committed().unwrap(), Some(log_id(report.committed)));
                    wal.with_native_read(|state| {
                        assert_eq!(state.applied(), Some(log_id(report.applied)));
                        assert_eq!(*state.membership().log_id(), Some(log_id(0)));
                        assert_eq!(
                            state.current_snapshot(),
                            report
                                .snapshots
                                .last()
                                .map(|snapshot| snapshot.candidate.clone())
                        );
                        assert_eq!(state.business_digest_for_test()?, report.business);
                        Ok(())
                    })
                    .unwrap();
                    let exported = wal.native_export_snapshot().unwrap();
                    for (table, rows) in &report.oracle {
                        assert_eq!(
                            &super::ordinary::rows(&exported, table),
                            rows,
                            "{case} {table}"
                        );
                    }
                    wal.checkpoint().unwrap();
                    wal.shutdown().unwrap();
                    eprintln!("NATIVE_PURGE_MODEL_CRASH case={case} reopen={reopen}");
                }
            }
        }
    }
}
