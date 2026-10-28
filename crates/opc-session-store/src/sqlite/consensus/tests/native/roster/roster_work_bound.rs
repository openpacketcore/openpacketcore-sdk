use super::*;
use crate::consensus::types::{roster_v2_fresh_wal_work_history_fixture, RosterV2FixtureSigner};
use crate::sqlite::consensus::roster_work_observer::{Counts, WorkObservation};

#[test]
fn roster_maintenance_native_work_is_independent_of_retained_history() {
    assert_work_is_independent_of_history(true);
}

#[test]
fn roster_maintenance_sqlite_work_is_independent_of_retained_history() {
    assert_work_is_independent_of_history(false);
}

struct WorkBackend {
    backend: SqliteSessionBackend,
    wal: Option<Wal>,
}

impl WorkBackend {
    fn new(directory: &Path, signed: &RosterV2PersistenceFixture, native: bool) -> Self {
        let backend = SqliteSessionBackend::open(directory.join("backend.sqlite")).unwrap();
        initialize(&backend, signed);
        let wal = native.then(|| {
            Wal::create_native_with_root(
                &directory.join("wal"),
                &backend.conn.blocking_lock(),
                signed.identity,
                [0xD9; 32],
                Some(Arc::new(signed.root.clone())),
                Limits::default(),
                IoControl::default(),
            )
            .unwrap()
        });
        Self { backend, wal }
    }

    fn apply(
        &self,
        signed: &RosterV2PersistenceFixture,
        entries: &[Entry<SessionRaftTypeConfig>],
    ) -> AppliedBatch {
        match &self.wal {
            Some(wal) => {
                // Physical WAL records retain their 64-entry limit. Commit the
                // complete seed prefix once, then apply the chunk atomically.
                for fragment in entries.chunks(64) {
                    wal.submit(append(fragment)).unwrap().wait().unwrap();
                }
                wal.submit(Operation::Committed(
                    entries.last().map(|entry| entry.log_id),
                ))
                .unwrap()
                .wait()
                .unwrap();
                wal.native_apply_committed(entries).unwrap()
            }
            None => sql_apply(&self.backend, signed, entries),
        }
    }

    fn probe(&self, signed: &RosterV2PersistenceFixture, now: Timestamp) -> bool {
        match &self.wal {
            Some(wal) => {
                wal.native_public_scalar_read(|state| state.protected_roster_maintenance_due(now))
                    .unwrap()
                    .1
            }
            None => {
                protected_roster_maintenance_due_sync(
                    &self.backend.conn.blocking_lock(),
                    signed.identity,
                    now,
                )
                .unwrap()
                .1
            }
        }
    }

    fn occupancy(&self, signed: &RosterV2PersistenceFixture) -> ProtectedRosterLedgerOccupancy {
        match &self.wal {
            Some(wal) => wal
                .native_public_scalar_read(|state| state.protected_roster_diagnostic_occupancy())
                .unwrap(),
            None => protected_roster_diagnostic_occupancy_sync(
                &self.backend.conn.blocking_lock(),
                signed.identity,
            )
            .unwrap(),
        }
    }

    fn persist_retained_history(
        &self,
        signed: &RosterV2PersistenceFixture,
        retained: u64,
    ) -> Duration {
        let started = std::time::Instant::now();
        if let Some(wal) = &self.wal {
            // Use the ordinary generation writer to select and relocate the
            // retained carriers. A direct apply fixture has no Raft snapshot
            // scheduler; keeping every canonical carrier hot would measure
            // the process memory cap instead of per-turn storage work.
            std::thread::scope(|scope| {
                let (send, receive) = std::sync::mpsc::channel();
                scope.spawn(move || send.send(wal.checkpoint()).unwrap());
                receive
                    .recv_timeout(Duration::from_secs(30))
                    .expect("normal retained-history checkpoint fits the setup budget")
                    .expect("normal retained-history checkpoint succeeds");
            });
        }
        let occupancy = self.occupancy(signed);
        assert_eq!(occupancy.live_reservations, 0);
        assert_eq!(occupancy.retained_reservations, retained);
        assert_eq!(occupancy.tombstone_reservations, 0);
        started.elapsed()
    }
}

fn at_time(entry: &mut Entry<SessionRaftTypeConfig>, now: Timestamp) {
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.logical_time = now;
}

// Two capped terminal-prefix reads, three ten-row scans including lookahead,
// and seven fixed head/eligibility observations. Only reclaimed/retired carriers
// are hydrated: ten in each phase.
const NATIVE_INDEX_CEILING: u64 = 2 * (1_024 + 1) + 3 * (10 + 1) + 7;
const NATIVE_HYDRATION_CEILING: u64 = 2 * 10;
// Conservative SQLite plan envelope: two bounded 1,025-row prefix cursors at
// 64 VM instructions per candidate, 1,024 per mutated row in the two ten-row
// phases, and 8,192 for fixed schema/policy/witness reads and statement setup.
// It covers VM work, not Rust decoding, signing or physical I/O. This is larger
// than the observed plan and must still reject an additional fixed query loop.
const SQLITE_VM_CEILING: u64 = 2 * (1_024 + 1) * 64 + 2 * 10 * 1_024 + 8_192;

fn within_work_ceiling(native: bool, work: Counts) -> bool {
    if native {
        work.native_index_entries > 0
            && work.native_index_entries <= NATIVE_INDEX_CEILING
            && work.native_hydrations > 0
            && work.native_hydrations <= NATIVE_HYDRATION_CEILING
            && work.sqlite_vm_steps == 0
    } else {
        work.sqlite_vm_steps > 0
            && work.sqlite_vm_steps <= SQLITE_VM_CEILING
            && work.native_index_entries == 0
            && work.native_hydrations == 0
    }
}

fn inflate_read_cost(backend: &WorkBackend, signed: &RosterV2PersistenceFixture, now: Timestamp) {
    if backend.wal.is_some() {
        for _ in 0..=NATIVE_INDEX_CEILING {
            assert!(
                !backend.probe(signed, now),
                "repeated eligibility reads stay idle"
            );
        }
    } else {
        let conn = backend.backend.conn.blocking_lock();
        let _scope =
            crate::sqlite::consensus::roster_work_observer::sqlite_probe(&conn, signed.identity)
                .unwrap();
        for _ in 0..=SQLITE_VM_CEILING / 4 {
            assert_eq!(
                conn.query_row("SELECT 1", [], |row| row.get::<_, u32>(0))
                    .unwrap(),
                1
            );
        }
    }
}

fn assert_work_is_independent_of_history(native: bool) {
    let mut observed = Vec::<Vec<Counts>>::new();
    let mut inflated = Vec::new();
    let signer = RosterV2FixtureSigner::for_work_history();
    // This isolates backend work from replication: every signed Q1/Q2 still
    // uses the real append, commit and apply path. Separate three-voter tests
    // cover controlled turns and measure independent physical arrivals.
    // Ten turns retire 100 rows. These are the smallest integer histories
    // that remain above the 1,025-row capped read throughout every turn,
    // with the larger history at least twice the smaller one.
    let histories = [1_126_u16, 2_252];
    assert!(histories[0] - 100 > 1_025);
    assert!(histories[1] >= histories[0] * 2);
    for rows in histories {
        let directory = tempfile::tempdir().unwrap();
        let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Aborted);
        let backend = WorkBackend::new(directory.path(), &signed, native);
        let setup = backend.apply(&signed, &export::setup(&signed));
        assert!(setup
            .responses
            .iter()
            .all(|response| response.result.is_ok()));
        // Native checkpoint preparation revalidates pending signed entries.
        // Keep its O0 batches well inside the unchanged 30-second deadline.
        let chunk_rows = if native { 24 } else { 300 };
        let mut seed = Vec::with_capacity(usize::from(chunk_rows) * 2);
        let mut checkpoint_max = Duration::ZERO;
        for row in 0..rows {
            let index = 3 + u64::from(row) * 2;
            let history = roster_v2_fresh_wal_work_history_fixture(
                &signer,
                (0xD90000 + u128::from(row)).to_be_bytes(),
                index,
            );
            // Ten due rows per turn, followed by a young tail. Both sizes keep
            // the same nonempty partition shape through all ten measured turns.
            let second = if row < 100 {
                i64::from(row / 10) + 1
            } else {
                20
            };
            let now = signed.authority.acquired_at().add_seconds(second).unwrap();
            let mut q1 = admission(&history);
            q1.log_id = log_id(index);
            at_time(&mut q1, now);
            let mut q2 = terminal(&history, index + 1);
            at_time(&mut q2, now);
            seed.extend([q1, q2]);
            if (row + 1).is_multiple_of(chunk_rows) || row + 1 == rows {
                // One durable transaction per chunk, retaining the real signed
                // append/commit/apply path and every individual Q1/Q2 outcome.
                let result = backend.apply(&signed, &seed);
                assert_eq!(result.responses.len(), seed.len());
                for pair in result.responses.as_chunks::<2>().0 {
                    assert!(matches!(
                        &pair[0].result,
                        Ok(SessionMutationOutcome::RosterAdmissionV2(
                            ConsensusRosterAdmissionOutcome::Admitted { .. }
                        ))
                    ));
                    assert!(matches!(
                        &pair[1].result,
                        Ok(SessionMutationOutcome::RosterTerminalV2(
                            ConsensusRosterTerminalOutcome::Committed {
                                replayed: false,
                                ..
                            }
                        ))
                    ));
                }
                seed.clear();
                let checkpoint = backend.persist_retained_history(&signed, u64::from(row + 1));
                checkpoint_max = checkpoint_max.max(checkpoint);
                eprintln!(
                    "roster backend history seed: native={native}, retained={}, total={rows}, checkpoint_seconds={}, verification_memory={:?}",
                    row + 1,
                    checkpoint.as_secs_f64(),
                    crate::consensus::verified_snapshot::VerificationMemory::usage_for_test(),
                );
            }
        }
        assert!(
            seed.is_empty(),
            "both histories end on a complete seed chunk"
        );
        eprintln!(
            "roster history checkpoint maximum: native={native}, history={rows}, seconds={}",
            checkpoint_max.as_secs_f64()
        );
        assert_eq!(
            backend.occupancy(&signed).retained_reservations,
            u64::from(rows)
        );
        let observation = WorkObservation::new(signed.identity);
        let mut turns = Vec::new();
        for turn in 1_u16..=10 {
            let now = signed
                .authority
                .acquired_at()
                .add_seconds(24 * 60 * 60 + i64::from(turn))
                .unwrap();
            let before = observation.counts();
            for phase in 0..2 {
                assert!(backend.probe(&signed, now));
                let index = 3 + u64::from(rows) * 2 + u64::from(turn - 1) * 2 + phase;
                let result = backend.apply(&signed, &[export::tick(&signed, index, now)]);
                assert!(result
                    .responses
                    .iter()
                    .all(|response| response.result.is_ok()));
                let occupancy = backend.occupancy(&signed);
                assert_eq!(occupancy.live_reservations, 0);
                assert_eq!(occupancy.retained_reservations, u64::from(rows - turn * 10));
                assert_eq!(
                    occupancy.tombstone_reservations,
                    if phase == 0 { 10 } else { 0 }
                );
            }
            let work = observation.counts().since(before);
            assert_eq!(work.turns, 2, "one reclaim and one retirement command");
            assert_eq!(work.probes, 2, "one eligibility probe per proposal");
            if native {
                assert!(work.native_index_entries > 0 && work.native_hydrations > 0);
                assert_eq!(work.sqlite_vm_steps, 0);
            } else {
                assert!(work.sqlite_vm_steps > 0);
                assert_eq!(work.native_index_entries, 0);
                assert_eq!(work.native_hydrations, 0);
            }
            assert!(
                within_work_ceiling(native, work),
                "bounded per-turn work: {work:?}"
            );
            eprintln!("roster maintenance work: native={native}, history={rows}, turn={turn}, work={work:?}");
            turns.push(work);
            if turn == 10 {
                let unchanged = backend.occupancy(&signed);
                inflate_read_cost(&backend, &signed, now);
                assert!(
                    backend.occupancy(&signed) == unchanged,
                    "equal-cost extra reads must not change any durable result"
                );
                inflated.push(observation.counts().since(before));
            }
        }
        if let Some(wal) = backend.wal {
            wal.shutdown().unwrap();
        }
        observed.push(turns);
    }
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0].len(), 10);
    assert_eq!(observed[1].len(), 10);
    for (turn, (small, large)) in observed[0].iter().zip(&observed[1]).enumerate() {
        assert_eq!(small, large,
            "the same ten due rows must require the same maintenance work at both history sizes; native={native}, turn={}", turn + 1);
    }
    assert_eq!(inflated.len(), 2);
    assert_eq!(
        inflated[0], inflated[1],
        "the negative control adds equal real work at both sizes"
    );
    assert!(
        !within_work_ceiling(native, inflated[0]),
        "equal cost inflation must fail the absolute ceiling: {:?}",
        inflated[0]
    );
}
