use super::*;
use crate::consensus::types::roster_v2_fresh_wal_work_history_fixture;
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
                commit(wal, entries);
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

    fn persist_retained_history(&self, signed: &RosterV2PersistenceFixture, retained: u64) {
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
    }
}

fn at_time(entry: &mut Entry<SessionRaftTypeConfig>, now: Timestamp) {
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.logical_time = now;
}

fn assert_work_is_independent_of_history(native: bool) {
    let mut observed = Vec::<Vec<Counts>>::new();
    // This isolates backend work from replication: every signed Q1/Q2 still
    // uses the real append, commit and apply path. Separate three-voter tests
    // cover controlled turns and measure independent physical arrivals.
    for rows in [1_800_u16, 18_000] {
        let directory = tempfile::tempdir().unwrap();
        let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Aborted);
        let backend = WorkBackend::new(directory.path(), &signed, native);
        let setup = backend.apply(&signed, &export::setup(&signed));
        assert!(setup
            .responses
            .iter()
            .all(|response| response.result.is_ok()));
        for row in 0..rows {
            let index = 3 + u64::from(row) * 2;
            let history = roster_v2_fresh_wal_work_history_fixture(
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
            let result = backend.apply(&history, &[q1, q2]);
            assert!(matches!(
                &result.responses[0].result,
                Ok(SessionMutationOutcome::RosterAdmissionV2(
                    ConsensusRosterAdmissionOutcome::Admitted { .. }
                ))
            ));
            assert!(matches!(
                &result.responses[1].result,
                Ok(SessionMutationOutcome::RosterTerminalV2(
                    ConsensusRosterTerminalOutcome::Committed {
                        replayed: false,
                        ..
                    }
                ))
            ));
            if (row + 1).is_multiple_of(300) {
                backend.persist_retained_history(&signed, u64::from(row + 1));
                eprintln!(
                    "roster backend history seed: native={native}, retained={}, total={rows}, verification_memory={:?}",
                    row + 1,
                    crate::consensus::verified_snapshot::VerificationMemory::usage_for_test(),
                );
            }
        }
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
            eprintln!("roster maintenance work: native={native}, history={rows}, turn={turn}, work={work:?}");
            turns.push(work);
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
}
