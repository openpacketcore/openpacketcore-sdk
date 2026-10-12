//! A receiver's physically reclaimed predecessor remains a valid install base.

use super::*;
use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
use crate::sqlite::consensus::wal::native::Opening;
use crate::SessionPersistenceMode;

struct Receiver {
    directory: tempfile::TempDir,
    backend: SqliteSessionBackend,
    wal: Wal,
    identity: SessionConsensusIdentity,
}

impl Receiver {
    fn new(slots: bool, mode: SessionPersistenceMode) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let backend = SqliteSessionBackend::open(directory.path().join("seed.sqlite")).unwrap();
        let conn = backend.conn.blocking_lock();
        let identity = if slots {
            initialize(&conn, &fixture::genesis(3), true).unwrap()
        } else {
            initialize_schema_with_storage_anchor_and_pending_and_bindings_and_fenced_profile(
                &conn,
                None,
                identity(),
                &fixed_members(),
                &test_member_bindings(&fixed_members()),
                None,
                ConsensusAuthorityProfile::FixedImmutable,
                Some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
                None,
                crate::FencedTransitionV2Profile::V2,
            )
            .unwrap()
        };
        let wal = Wal::create_native_with_persistence(
            &directory.path().join("wal"),
            &conn,
            identity,
            [0xBD; 32],
            None,
            Limits::default(),
            IoControl::default(),
            mode,
        )
        .unwrap();
        drop(conn);
        Self {
            directory,
            backend,
            wal,
            identity,
        }
    }

    fn apply(&self, entries: &[Entry<SessionRaftTypeConfig>]) {
        self.wal.submit(append(entries)).unwrap().wait().unwrap();
        self.wal
            .submit(Operation::Committed(Some(entries.last().unwrap().log_id)))
            .unwrap()
            .wait()
            .unwrap();
        self.wal.native_apply_committed(entries).unwrap();
    }

    fn snapshot(&self) -> IncomingSnapshot {
        IncomingSnapshot::with_identity(&self.wal.native_export_snapshot().unwrap(), self.identity)
    }

    fn leave_retired_files(&self, previous: u64) -> Vec<PathBuf> {
        self.wal.shutdown().unwrap();
        let directory = self.directory.path().join("wal");
        let selected = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "native")
            })
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 1);
        let name = selected[0].file_stem().unwrap().to_str().unwrap();
        let epoch = name.strip_prefix("basis-").unwrap().parse::<u64>().unwrap();
        assert!(epoch >= 2, "the installed base advanced the file epoch");
        let mut retired = Vec::new();
        for number in (epoch - previous..epoch).chain(std::iter::once(epoch + 1)) {
            let path = directory.join(format!("basis-{number:020}.native"));
            assert!(!path.exists());
            std::fs::copy(&selected[0], &path).unwrap();
            std::fs::File::open(&path).unwrap().sync_all().unwrap();
            retired.push(path);
        }
        std::fs::File::open(directory).unwrap().sync_all().unwrap();
        retired
    }

    fn reopen(&mut self, origin: &IncomingSnapshot, current: &IncomingSnapshot) {
        self.wal.shutdown().unwrap();
        let opening = Opening::new(
            &self.directory.path().join("wal"),
            self.wal.binding(),
            None,
            Limits::default(),
            IoControl::default(),
        )
        .unwrap();
        let origin = origin.source().unwrap();
        let current = current.source().unwrap();
        self.wal = opening
            .finish_with_install_source(Some(&origin), || {
                origin.verify()?;
                current.verify()
            })
            .unwrap();
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.wal.shutdown();
    }
}

fn select_reclaim_and_reopen(receiver: &mut Receiver, through: u64) -> IncomingSnapshot {
    let mut snapshot = receiver.snapshot();
    snapshot.candidate.0.snapshot_id = receiver.wal.native_snapshot_id().unwrap();
    receiver
        .wal
        .native_publish_snapshot(snapshot.candidate.clone())
        .unwrap();
    receiver
        .wal
        .submit(Operation::Purge(fixture::cut(through)))
        .unwrap()
        .wait()
        .unwrap();
    receiver.wal.checkpoint().unwrap();
    let state = receiver.wal.native_voter_slot_state().unwrap();
    let membership = receiver
        .wal
        .with_native_read(|state| Ok(state.membership()))
        .unwrap();
    let application = receiver
        .wal
        .with_native_read(|state| Ok(state.application_digest()))
        .unwrap();
    for _ in 0..2 {
        assert_eq!(receiver.wal.native_log_inventory_for_test().unwrap().0, 0);
        assert_eq!(
            receiver.wal.native_log_state().unwrap().last_purged_log_id,
            Some(fixture::cut(through))
        );
        receiver.wal.shutdown().unwrap();
        receiver.wal = Opening::new(
            &receiver.directory.path().join("wal"),
            receiver.wal.binding(),
            None,
            Limits::default(),
            IoControl::default(),
        )
        .unwrap()
        .finish(|| snapshot.source().unwrap().verify())
        .unwrap();
        assert_eq!(receiver.wal.native_voter_slot_state().unwrap(), state);
        receiver
            .wal
            .with_native_read(|state| {
                assert_eq!(state.membership(), membership);
                assert_eq!(state.application_digest(), application);
                assert_eq!(state.applied(), Some(fixture::cut(through)));
                Ok(())
            })
            .unwrap();
    }
    snapshot
}

#[test]
fn native_voter_replacement_survives_reclaim_before_during_and_after_joint_consensus() {
    // The middle schedule removes the prepare, marker and fencing witnesses
    // before joint membership is appended. Their selected slot state, rather
    // than historical log rows, must retain the exact replacement authority.
    for purge_after in [3, 9, 12] {
        let mut receiver = Receiver::new(true, SessionPersistenceMode::Durable);
        let initial = fixture::genesis(3);
        let old = initial
            .current_configuration()
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect::<BTreeSet<_>>();
        let mut prefix = vec![Entry {
            log_id: fixture::cut(0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![old.clone()],
                None,
            )),
        }];
        prefix.extend((1..=3).map(|index| Entry {
            log_id: fixture::cut(index),
            payload: EntryPayload::Blank,
        }));
        receiver.apply(&prefix);
        let mut snapshots = Vec::new();
        if purge_after == 3 {
            snapshots.push(select_reclaim_and_reopen(&mut receiver, 3));
        }
        let request = fixture::request(&initial, 3);
        let advance = |step| VoterSlotControl::Advance {
            request_id: request.attestation.request_id,
            request_digest: request.attestation.request_digest,
            step,
        };
        receiver.apply(&[fixture::command(
            &initial,
            4,
            VoterSlotControl::Begin(Box::new(request.clone())),
        )]);
        let prepared = receiver.wal.native_voter_slot_state().unwrap();
        let operation = prepared.table().replacement.as_ref().unwrap();
        let new = operation
            .successor
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect::<BTreeSet<_>>();
        let union = old.union(&new).copied().collect::<BTreeSet<_>>();
        let membership = |index, configurations, nodes| Entry {
            log_id: fixture::cut(index),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                configurations,
                nodes,
            )),
        };
        let steps = [
            fixture::command(
                &initial,
                5,
                advance(VoterReplacementStep::RecordSnapshot(
                    VoterSnapshotEvidence {
                        cut: VoterSlotLogId { term: 2, index: 4 },
                        snapshot_id: "replacement-before-reclaim".into(),
                        digest: [0xD1; 32],
                    },
                )),
            ),
            membership(6, vec![old.clone()], Some(union.clone())),
            fixture::command(
                &initial,
                7,
                VoterSlotControl::Marker {
                    request_id: request.attestation.request_id,
                    request_digest: request.attestation.request_digest,
                },
            ),
            fixture::command(
                &initial,
                8,
                advance(VoterReplacementStep::RecordCaughtUp(VoterSlotLogId {
                    term: 2,
                    index: 7,
                })),
            ),
            fixture::command(&initial, 9, advance(VoterReplacementStep::Fence)),
            membership(10, vec![old, new.clone()], Some(union)),
            membership(11, vec![new], None),
            fixture::command(&initial, 12, advance(VoterReplacementStep::Finalize)),
        ];
        for entry in steps {
            receiver.apply(std::slice::from_ref(&entry));
            if entry.log_id.index == purge_after {
                snapshots.push(select_reclaim_and_reopen(&mut receiver, purge_after));
            }
        }
        let completed = receiver.wal.native_voter_slot_state().unwrap();
        assert!(completed.table().replacement.is_none());
        assert_eq!(completed.table().configuration_epoch.get(), 2);
        assert_eq!(completed.table().slots[2].member, request.candidate);
        assert!(completed
            .table()
            .is_retired(fixture::member(3, 1).identity.node_id()));
        if purge_after != 12 {
            snapshots.push(select_reclaim_and_reopen(&mut receiver, 12));
        }
        assert_eq!(receiver.wal.native_voter_slot_state().unwrap(), completed);
        assert!(receiver.wal.read(0, 13).unwrap().is_empty());
        assert_eq!(receiver.wal.native_log_inventory_for_test().unwrap().0, 0);
        eprintln!("NATIVE_PURGE_REPLACEMENT purge_after={purge_after} final_index=12");
    }
}

#[test]
fn native_reclaimed_fixed_and_slot_receivers_install_preserving_exact_suffix_then_purge_again() {
    for (slots, mode) in [
        (false, SessionPersistenceMode::Durable),
        (false, SessionPersistenceMode::Async),
        (true, SessionPersistenceMode::Durable),
    ] {
        let source = Receiver::new(slots, mode);
        let mut target = Receiver::new(slots, mode);
        let id = |index| {
            if slots {
                fixture::cut(index)
            } else {
                log_id(index)
            }
        };
        let members = if slots {
            fixture::genesis(3)
                .current_configuration()
                .members
                .iter()
                .map(|member| member.identity.node_id())
                .collect()
        } else {
            fixed_members()
        };
        let formation = Entry {
            log_id: id(0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![members],
                None,
            )),
        };
        let mut prefix = vec![formation];
        prefix.extend((1..=3).map(|index| Entry {
            log_id: id(index),
            payload: EntryPayload::Blank,
        }));
        source.apply(&prefix);
        target.apply(&prefix);
        let mut old = target.snapshot();
        old.candidate.0.snapshot_id = target.wal.native_snapshot_id().unwrap();
        target
            .wal
            .native_publish_snapshot(old.candidate.clone())
            .unwrap();
        target
            .wal
            .submit(Operation::Purge(id(1)))
            .unwrap()
            .wait()
            .unwrap();
        target.wal.checkpoint().unwrap();
        assert_eq!(target.wal.native_log_inventory_for_test().unwrap().0, 2);
        assert_eq!(
            target.wal.native_log_state().unwrap().last_purged_log_id,
            Some(id(1))
        );
        assert_eq!(
            target
                .wal
                .read(0, 4)
                .unwrap()
                .iter()
                .map(|entry| entry.log_id)
                .collect::<Vec<_>>(),
            vec![id(2), id(3)]
        );
        let suffix = (4..=7)
            .map(|index| Entry {
                log_id: id(index),
                payload: EntryPayload::Blank,
            })
            .collect::<Vec<_>>();
        target.wal.submit(append(&suffix)).unwrap().wait().unwrap();
        source.apply(&suffix[..3]);
        let incoming = source.snapshot();
        let before_membership = source
            .wal
            .with_native_read(|state| Ok(state.membership()))
            .unwrap();
        let before_slots = slots.then(|| source.wal.native_voter_slot_state().unwrap());
        target
            .wal
            .install_snapshot(
                &target.backend.conn.blocking_lock(),
                incoming.source().unwrap(),
            )
            .unwrap();
        for previous in 0..=2 {
            assert_eq!(
                target.wal.native_log_state().unwrap().last_purged_log_id,
                Some(id(6))
            );
            assert_eq!(target.wal.committed().unwrap(), Some(id(6)));
            assert_eq!(
                target
                    .wal
                    .read(0, 8)
                    .unwrap()
                    .iter()
                    .map(|entry| entry.log_id)
                    .collect::<Vec<_>>(),
                vec![id(7)]
            );
            assert_eq!(target.wal.native_log_inventory_for_test().unwrap().0, 1);
            target
                .wal
                .with_native_read(|state| {
                    assert_eq!(state.applied(), Some(id(6)));
                    assert_eq!(state.membership(), before_membership);
                    assert_eq!(state.current_snapshot(), Some(incoming.candidate.clone()));
                    Ok(())
                })
                .unwrap();
            if let Some(expected) = &before_slots {
                assert_eq!(&target.wal.native_voter_slot_state().unwrap(), expected);
            }
            let retired = target.leave_retired_files(previous);
            target.reopen(&incoming, &incoming);
            assert!(
                retired.iter().all(|path| !path.exists()),
                "reopen removes one next and {previous} previous native files"
            );
        }
        target
            .wal
            .submit(Operation::Committed(Some(id(7))))
            .unwrap()
            .wait()
            .unwrap();
        target.wal.native_apply_committed(&suffix[3..]).unwrap();
        let later = Entry {
            log_id: id(8),
            payload: EntryPayload::Blank,
        };
        target.apply(std::slice::from_ref(&later));
        let mut next = target.snapshot();
        next.candidate.0.snapshot_id = target.wal.native_snapshot_id().unwrap();
        target
            .wal
            .native_publish_snapshot(next.candidate.clone())
            .unwrap();
        target
            .wal
            .submit(Operation::Purge(id(8)))
            .unwrap()
            .wait()
            .unwrap();
        target.wal.checkpoint().unwrap();
        target.reopen(&incoming, &next);
        assert_eq!(
            target.wal.native_log_state().unwrap().last_purged_log_id,
            Some(id(8))
        );
        assert_eq!(target.wal.native_log_inventory_for_test().unwrap().0, 0);
        assert!(target.wal.read(0, 9).unwrap().is_empty());
        assert_eq!(
            target
                .wal
                .with_native_read(|state| Ok(state.applied()))
                .unwrap(),
            Some(id(8))
        );
        assert_eq!(target.wal.native_sql_fallback_count().unwrap(), 0);
        eprintln!("NATIVE_PURGE_INSTALL slots={slots} mode={mode:?} reclaimed_before=2 retained_after_install=1 retained_after_local_purge=0");
    }
}
