use super::super::types::{ConfigConsensusCommand, VOTER_SLOT_CONFIG_COMMAND_VERSION};
use super::*;
use opc_consensus::engine::{CommittedLeaderId, Membership};
use opc_consensus::voter_slots::*;
use opc_consensus::{ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusRequestId};

fn member(slot: u16, incarnation: u64) -> VoterSlotMember {
    VoterSlotMember {
        identity: VoterSlotIdentity::new(
            SlotId::new(slot).unwrap(),
            VoterIncarnation::new(incarnation).unwrap(),
        ),
        key_digest: [incarnation as u8; 32],
        descriptor_digest: [slot as u8; 32],
        admission_generation: incarnation,
    }
}

fn genesis() -> VoterSlotTable {
    VoterSlotTable {
        cluster_instance: ConsensusClusterId::from_bytes([3; 32]),
        manifest_digest: [4; 32],
        revision: 1,
        configuration_epoch: ConsensusConfigurationEpoch::new(1).unwrap(),
        slots: (1..=3)
            .map(|slot| VoterSlotRecord {
                member: member(slot, 1),
                retired_through: 0,
                phase: VoterSlotPhase::Voting,
                last_result: None,
            })
            .collect(),
        replacement: None,
    }
}

fn identity() -> ConsensusIdentity {
    let table = genesis();
    table
        .current_configuration()
        .identity(table.cluster_instance, table.manifest_digest)
        .unwrap()
}

fn members() -> BTreeSet<ConsensusNodeId> {
    genesis()
        .slots
        .iter()
        .map(|slot| slot.member.identity.node_id())
        .collect()
}

fn cut(index: u64) -> LogId<ConsensusNodeId> {
    LogId::new(
        CommittedLeaderId::new(2, member(1, 1).identity.node_id()),
        index,
    )
}

fn request(table: &VoterSlotTable, slot: u16, id: u8) -> VoterReplacementRequest {
    let old = &table.slots[usize::from(slot - 1)].member;
    let candidate = member(slot, old.identity.incarnation().get() + 1);
    let expected_configuration = table
        .current_configuration()
        .identity(table.cluster_instance, table.manifest_digest)
        .unwrap();
    let mut attestation = LostVoterAttestationV1 {
        request_id: ConsensusRequestId::from_bytes([id; 16]),
        request_digest: [0; 32],
        cluster_instance: table.cluster_instance,
        slot: old.identity.slot(),
        expected_incarnation: old.identity.incarnation(),
        old_descriptor_digest: old.descriptor_digest,
        candidate_key_digest: candidate.key_digest,
        admission_generation: candidate.admission_generation,
        candidate_spiffe_id: format!("spiffe://example.test/voter/{slot}"),
        controller_spiffe_id: "spiffe://example.test/controller".into(),
        signing_key_digest: [7; 32],
        reason: VoterLossReason::TimeBoundLoss,
        policy_digest: [8; 32],
        observation_start_ms: 100,
        decision_ms: 200,
        issued_ms: 200,
        expires_ms: 300,
        signature: [9; 64],
    };
    attestation.request_digest = voter_replacement_request_digest(
        table.revision,
        expected_configuration,
        &candidate,
        &attestation,
    )
    .unwrap();
    VoterReplacementRequest {
        expected_revision: table.revision,
        expected_configuration,
        candidate,
        attestation,
    }
}

fn control_entry(index: u64, control: VoterSlotControl) -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: cut(index),
        payload: EntryPayload::Normal(ConfigConsensusCommand {
            schema_version: VOTER_SLOT_CONFIG_COMMAND_VERSION,
            identity: identity(),
            request_id: ConsensusRequestId::from_bytes([index as u8; 16]),
            logical_time: Timestamp::now_utc(),
            intent: ConfigMutationIntent::VoterSlotControl(control.encode().unwrap()),
        }),
    }
}

#[test]
fn slot_control_keeps_wire_index_nine_after_the_rejected_capacity_variant() {
    let entry = control_entry(
        1,
        VoterSlotControl::Begin(Box::new(request(&genesis(), 3, 1))),
    );
    let bytes = super::super::types::encode_config_wire(&entry).unwrap();
    let decoded: Entry<ConfigRaftTypeConfig> =
        super::super::types::decode_config_wire(&bytes).unwrap();
    assert_eq!(entry, decoded);
}

async fn backend() -> SqliteBackend {
    let backend = SqliteBackend::in_memory_for_test().await.unwrap();
    let shared = backend.conn();
    let conn = shared.lock().await;
    initialize_schema_with_slots(
        &conn,
        identity(),
        &members(),
        backend.audit_key(),
        None,
        Some(&genesis()),
        &Arc::new(SqliteWorkCancellation::new()),
        None,
    )
    .unwrap();
    let initial = Entry {
        log_id: cut(0),
        payload: EntryPayload::Membership(Membership::new(vec![members()], None)),
    };
    append_logs_sync(
        &conn,
        identity(),
        &members(),
        std::slice::from_ref(&initial),
    )
    .unwrap();
    apply_entries_sync(
        &conn,
        backend.audit_key(),
        identity(),
        &members(),
        vec![initial],
    )
    .unwrap();
    drop(conn);
    backend
}

#[tokio::test]
async fn append_truncate_and_apply_publish_exact_durable_intent_atomically() {
    let backend = backend().await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    let wanted = request(&genesis(), 3, 1);
    let prepare = control_entry(1, VoterSlotControl::Begin(Box::new(wanted.clone())));
    append_logs_sync(
        &conn,
        identity(),
        &members(),
        std::slice::from_ref(&prepare),
    )
    .unwrap();
    let state = voter_slots::read_sync(&conn).unwrap().unwrap();
    assert_eq!(state.table(), &genesis());
    assert_eq!(
        state.intent().unwrap().log_id,
        VoterSlotLogId { term: 2, index: 1 }
    );
    assert_eq!(state.intent().unwrap().request, wanted);
    let reopened = VoterSlotDurableState::decode(&state.encode().unwrap()).unwrap();
    assert_eq!(
        reopened, state,
        "the durable append itself restores the provisional gate"
    );
    assert!(truncate_logs_sync(&conn, identity(), &cut(0)).is_err());
    assert_eq!(voter_slots::read_sync(&conn).unwrap().unwrap(), state);
    truncate_logs_sync(&conn, identity(), &cut(1)).unwrap();
    assert!(voter_slots::read_sync(&conn)
        .unwrap()
        .unwrap()
        .intent()
        .is_none());
    append_logs_sync(
        &conn,
        identity(),
        &members(),
        std::slice::from_ref(&prepare),
    )
    .unwrap();
    let response = apply_entries_sync(
        &conn,
        backend.audit_key(),
        identity(),
        &members(),
        vec![prepare],
    )
    .unwrap();
    assert_eq!(response[0].result, Ok(()));
    let applied = voter_slots::read_sync(&conn).unwrap().unwrap();
    assert!(applied.intent().is_none());
    assert!(applied.table().is_retired(member(3, 1).identity.node_id()));
    assert_eq!(read_applied_sync(&conn, identity()).unwrap(), Some(cut(1)));
    assert_eq!(
        read_machine_sync(&conn, identity()).unwrap().0,
        0,
        "bounded slot receipts do not consume application outcomes"
    );
    assert!(truncate_logs_sync(&conn, identity(), &cut(1)).is_err());
    initialize_schema_with_slots(
        &conn,
        identity(),
        &members(),
        backend.audit_key(),
        None,
        Some(&genesis()),
        &Arc::new(SqliteWorkCancellation::new()),
        None,
    )
    .unwrap();
    assert_eq!(voter_slots::read_sync(&conn).unwrap().unwrap(), applied);
}

#[tokio::test]
async fn failed_log_write_never_publishes_an_intent() {
    let backend = backend().await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    conn.execute_batch("CREATE TEMP TRIGGER fail_append BEFORE INSERT ON config_raft_log BEGIN SELECT RAISE(ABORT, 'injected durable failure'); END;").unwrap();
    let prepare = control_entry(
        1,
        VoterSlotControl::Begin(Box::new(request(&genesis(), 3, 1))),
    );
    assert!(append_logs_sync(&conn, identity(), &members(), &[prepare]).is_err());
    assert_eq!(last_log_sync(&conn, identity()).unwrap(), Some(cut(0)));
    assert!(voter_slots::read_sync(&conn)
        .unwrap()
        .unwrap()
        .intent()
        .is_none());
}

#[tokio::test]
async fn actual_snapshot_cuts_preserve_or_resolve_the_local_prepare_intent() {
    for committed_prepare in [false, true] {
        let backend = backend().await;
        let shared = backend.conn();
        let source = shared.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let mut target = Connection::open(directory.path().join("target.sqlite")).unwrap();
        let cancellation = Arc::new(SqliteWorkCancellation::new());
        {
            let backup = rusqlite::backup::Backup::new(&source, &mut target).unwrap();
            backup
                .run_to_completion(128, std::time::Duration::from_millis(1), None)
                .unwrap();
        }
        let blank = Entry {
            log_id: cut(1),
            payload: EntryPayload::Blank,
        };
        for conn in [&*source, &target] {
            append_logs_sync(conn, identity(), &members(), std::slice::from_ref(&blank)).unwrap();
        }
        apply_entries_sync(
            &source,
            backend.audit_key(),
            identity(),
            &members(),
            vec![blank],
        )
        .unwrap();
        let below = directory.path().join("below.sqlite");
        let (last_log_id, last_membership) = build_snapshot_database_sync(
            &source,
            identity(),
            &members(),
            backend.audit_key(),
            &below,
        )
        .unwrap();
        let below_meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "below-intent".into(),
        };
        let prepare = control_entry(
            2,
            VoterSlotControl::Begin(Box::new(request(&genesis(), 3, 2))),
        );
        append_logs_sync(
            &target,
            identity(),
            &members(),
            std::slice::from_ref(&prepare),
        )
        .unwrap();
        let intent = voter_slots::read_sync(&target).unwrap().unwrap();
        install_snapshot_database_sync(
            &target,
            identity(),
            &members(),
            backend.audit_key(),
            &below,
            &below_meta,
            "below.snapshot",
            [9; 32],
            below.metadata().unwrap().len(),
        )
        .unwrap();
        assert_eq!(voter_slots::read_sync(&target).unwrap().unwrap(), intent);
        validate_durable_log_state_sync(&target, identity(), &members(), false, &cancellation)
            .unwrap();
        initialize_schema_with_slots(
            &target,
            identity(),
            &members(),
            backend.audit_key(),
            None,
            Some(&genesis()),
            &Arc::new(SqliteWorkCancellation::new()),
            None,
        )
        .unwrap();
        let later = |index| {
            LogId::new(
                CommittedLeaderId::new(3, member(1, 1).identity.node_id()),
                index,
            )
        };
        let decision = if committed_prepare {
            prepare
        } else {
            Entry {
                log_id: later(2),
                payload: EntryPayload::Blank,
            }
        };
        let checkpoint = Entry {
            log_id: later(3),
            payload: EntryPayload::Blank,
        };
        let entries = vec![decision, checkpoint];
        append_logs_sync(&source, identity(), &members(), &entries).unwrap();
        apply_entries_sync(
            &source,
            backend.audit_key(),
            identity(),
            &members(),
            entries,
        )
        .unwrap();
        let above = directory.path().join("above.sqlite");
        let (last_log_id, last_membership) = build_snapshot_database_sync(
            &source,
            identity(),
            &members(),
            backend.audit_key(),
            &above,
        )
        .unwrap();
        let above_meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "after-intent".into(),
        };
        install_snapshot_database_sync(
            &target,
            identity(),
            &members(),
            backend.audit_key(),
            &above,
            &above_meta,
            "above.snapshot",
            [10; 32],
            above.metadata().unwrap().len(),
        )
        .unwrap();
        let published = voter_slots::read_sync(&target).unwrap().unwrap();
        assert!(published.intent().is_none());
        assert_eq!(
            published
                .table()
                .is_retired(member(3, 1).identity.node_id()),
            committed_prepare
        );
        drop(target);
        let reopened = Connection::open(directory.path().join("target.sqlite")).unwrap();
        initialize_schema_with_slots(
            &reopened,
            identity(),
            &members(),
            backend.audit_key(),
            None,
            Some(&genesis()),
            &Arc::new(SqliteWorkCancellation::new()),
            None,
        )
        .unwrap();
        assert_eq!(
            voter_slots::read_sync(&reopened).unwrap().unwrap(),
            published
        );
    }
}

#[tokio::test]
async fn lagging_apply_admits_only_the_candidate_selected_in_the_durable_log() {
    let backend = backend().await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    let wanted = request(&genesis(), 3, 1);
    let prepare = control_entry(1, VoterSlotControl::Begin(Box::new(wanted.clone())));
    append_logs_sync(&conn, identity(), &members(), &[prepare]).unwrap();
    let snapshot = control_entry(
        2,
        VoterSlotControl::Advance {
            request_id: wanted.attestation.request_id,
            request_digest: wanted.attestation.request_digest,
            step: VoterReplacementStep::RecordSnapshot(VoterSnapshotEvidence {
                cut: VoterSlotLogId { term: 2, index: 1 },
                snapshot_id: "initial-1".into(),
                digest: [5; 32],
            }),
        },
    );
    let learner = |incarnation| Entry {
        log_id: cut(3),
        payload: EntryPayload::Membership(Membership::new(
            vec![members()],
            Some(
                members()
                    .into_iter()
                    .chain(std::iter::once(member(3, incarnation).identity.node_id()))
                    .collect::<BTreeSet<_>>(),
            ),
        )),
    };
    assert!(append_logs_sync(
        &conn,
        identity(),
        &members(),
        &[snapshot.clone(), learner(3)]
    )
    .is_err());
    append_logs_sync(&conn, identity(), &members(), &[snapshot, learner(2)]).unwrap();
    assert_eq!(
        voter_slots::read_sync(&conn).unwrap().unwrap().table(),
        &genesis()
    );
    initialize_schema_with_slots(
        &conn,
        identity(),
        &members(),
        backend.audit_key(),
        None,
        Some(&genesis()),
        &Arc::new(SqliteWorkCancellation::new()),
        None,
    )
    .unwrap();
    let entries = read_log_range_sync(&conn, identity(), &members(), 1, None, None).unwrap();
    apply_entries_sync(&conn, backend.audit_key(), identity(), &members(), entries).unwrap();
    assert_eq!(
        voter_slots::read_sync(&conn)
            .unwrap()
            .unwrap()
            .table()
            .replacement
            .as_ref()
            .unwrap()
            .phase,
        VoterReplacementPhase::LearnerAdded
    );
}

#[tokio::test]
async fn lagging_apply_records_supersession_against_the_actual_durable_prefix() {
    let backend = backend().await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    let wanted = request(&genesis(), 3, 1);
    let prepare = control_entry(1, VoterSlotControl::Begin(Box::new(wanted.clone())));
    append_logs_sync(
        &conn,
        identity(),
        &members(),
        std::slice::from_ref(&prepare),
    )
    .unwrap();
    apply_entries_sync(
        &conn,
        backend.audit_key(),
        identity(),
        &members(),
        vec![prepare],
    )
    .unwrap();
    let snapshot = VoterSlotControl::Advance {
        request_id: wanted.attestation.request_id,
        request_digest: wanted.attestation.request_digest,
        step: VoterReplacementStep::RecordSnapshot(VoterSnapshotEvidence {
            cut: VoterSlotLogId { term: 2, index: 1 },
            snapshot_id: "initial-1".into(),
            digest: [5; 32],
        }),
    };
    append_logs_sync(
        &conn,
        identity(),
        &members(),
        &[control_entry(2, snapshot.clone())],
    )
    .unwrap();
    let mut projected = voter_slots::read_sync(&conn)
        .unwrap()
        .unwrap()
        .table()
        .clone();
    projected
        .apply_control(&snapshot, VoterSlotLogId { term: 2, index: 2 })
        .unwrap();
    let successor = request(&projected, 3, 2);
    append_logs_sync(
        &conn,
        identity(),
        &members(),
        &[control_entry(
            3,
            VoterSlotControl::Begin(Box::new(successor.clone())),
        )],
    )
    .unwrap();
    let before_apply = voter_slots::read_sync(&conn).unwrap().unwrap();
    assert_eq!(
        before_apply.intent().map(|intent| &intent.request),
        Some(&successor)
    );
    initialize_schema_with_slots(
        &conn,
        identity(),
        &members(),
        backend.audit_key(),
        None,
        Some(&genesis()),
        &Arc::new(SqliteWorkCancellation::new()),
        None,
    )
    .unwrap();
    let entries = read_log_range_sync(&conn, identity(), &members(), 2, None, None).unwrap();
    apply_entries_sync(&conn, backend.audit_key(), identity(), &members(), entries).unwrap();
    let after = voter_slots::read_sync(&conn).unwrap().unwrap();
    assert!(after.intent().is_none());
    assert!(after.table().is_retired(member(3, 2).identity.node_id()));
}

#[tokio::test]
async fn reopening_refuses_missing_or_displaced_durable_intent() {
    let backend = backend().await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    let prepare = control_entry(
        1,
        VoterSlotControl::Begin(Box::new(request(&genesis(), 3, 1))),
    );
    append_logs_sync(
        &conn,
        identity(),
        &members(),
        std::slice::from_ref(&prepare),
    )
    .unwrap();
    let retained = voter_slots::read_sync(&conn).unwrap().unwrap();
    let reopen = || {
        initialize_schema_with_slots(
            &conn,
            identity(),
            &members(),
            backend.audit_key(),
            None,
            Some(&genesis()),
            &Arc::new(SqliteWorkCancellation::new()),
            None,
        )
    };
    assert!(reopen().is_ok());
    voter_slots::write_sync(&conn, &VoterSlotDurableState::new(genesis()).unwrap()).unwrap();
    assert_eq!(
        reopen(),
        Err(ConfigConsensusStorageError::CorruptState),
        "an effective uncommitted Prepare cannot reopen without its fence intent"
    );
    voter_slots::write_sync(&conn, &retained).unwrap();
    let other: Entry<ConfigRaftTypeConfig> = Entry {
        log_id: cut(1),
        payload: EntryPayload::Blank,
    };
    conn.execute(
        "UPDATE config_raft_log SET entry_json = ?1 WHERE log_index = 1",
        [encode_json(&other).unwrap()],
    )
    .unwrap();
    assert_eq!(
        reopen(),
        Err(ConfigConsensusStorageError::CorruptState),
        "an intent must identify its actual durable Prepare"
    );
}

#[tokio::test]
async fn profile_cannot_be_changed_in_place_and_version_precedes_identity() {
    let backend = SqliteBackend::in_memory_for_test().await.unwrap();
    let shared = backend.conn();
    let conn = shared.lock().await;
    initialize_schema(
        &conn,
        identity(),
        &members(),
        backend.audit_key(),
        None,
        &Arc::new(SqliteWorkCancellation::new()),
        None,
    )
    .unwrap();
    assert_eq!(
        initialize_schema_with_slots(
            &conn,
            identity(),
            &members(),
            backend.audit_key(),
            None,
            Some(&genesis()),
            &Arc::new(SqliteWorkCancellation::new()),
            None
        ),
        Err(ConfigConsensusStorageError::IdentityMismatch)
    );
    assert!(voter_slots::read_sync(&conn).unwrap().is_none());
    conn.execute_batch("UPDATE config_raft_identity SET schema_version = 5, cluster_id = zeroblob(32); DROP TABLE config_raft_voter_slots;").unwrap();
    assert_eq!(
        initialize_schema(
            &conn,
            identity(),
            &members(),
            backend.audit_key(),
            None,
            &Arc::new(SqliteWorkCancellation::new()),
            None
        ),
        Err(ConfigConsensusStorageError::SchemaVersionMismatch)
    );
}

#[tokio::test]
async fn fixed_membership_uses_real_learner_joint_and_uniform_apply_cuts() {
    let backend = backend().await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    let wanted = request(&genesis(), 3, 1);
    let advance = |step| VoterSlotControl::Advance {
        request_id: wanted.attestation.request_id,
        request_digest: wanted.attestation.request_digest,
        step,
    };
    let apply = |entry: Entry<ConfigRaftTypeConfig>| {
        append_logs_sync(&conn, identity(), &members(), std::slice::from_ref(&entry)).unwrap();
        let responses = apply_entries_sync(
            &conn,
            backend.audit_key(),
            identity(),
            &members(),
            vec![entry],
        )
        .unwrap();
        assert_eq!(responses[0].result, Ok(()));
    };
    apply(control_entry(
        1,
        VoterSlotControl::Begin(Box::new(wanted.clone())),
    ));
    apply(control_entry(
        2,
        advance(VoterReplacementStep::RecordSnapshot(
            VoterSnapshotEvidence {
                cut: VoterSlotLogId { term: 2, index: 1 },
                snapshot_id: "initial-1".into(),
                digest: [5; 32],
            },
        )),
    ));
    let old = members();
    let new: BTreeSet<_> = [member(1, 1), member(2, 1), member(3, 2)]
        .iter()
        .map(|m| m.identity.node_id())
        .collect();
    let union: BTreeSet<_> = old.union(&new).copied().collect();
    let membership_entry =
        |index, configs: Vec<BTreeSet<ConsensusNodeId>>, nodes: BTreeSet<ConsensusNodeId>| Entry {
            log_id: cut(index),
            payload: EntryPayload::Membership(Membership::new(configs, Some(nodes))),
        };
    apply(membership_entry(3, vec![old.clone()], union.clone()));
    apply(Entry {
        log_id: cut(4),
        payload: EntryPayload::Blank,
    });
    apply(control_entry(
        5,
        advance(VoterReplacementStep::RecordCaughtUp(VoterSlotLogId {
            term: 2,
            index: 4,
        })),
    ));
    apply(control_entry(6, advance(VoterReplacementStep::Fence)));
    apply(membership_entry(7, vec![old, new.clone()], union));
    apply(membership_entry(8, vec![new.clone()], new));
    apply(control_entry(9, advance(VoterReplacementStep::Finalize)));
    let state = voter_slots::read_sync(&conn).unwrap().unwrap();
    assert!(state.table().replacement.is_none());
    assert_eq!(state.table().configuration_epoch.get(), 2);
    assert!(state.table().is_retired(member(3, 1).identity.node_id()));
    initialize_schema_with_slots(
        &conn,
        identity(),
        &members(),
        backend.audit_key(),
        None,
        Some(&genesis()),
        &Arc::new(SqliteWorkCancellation::new()),
        None,
    )
    .unwrap();
    assert_eq!(voter_slots::read_sync(&conn).unwrap().unwrap(), state);
}
