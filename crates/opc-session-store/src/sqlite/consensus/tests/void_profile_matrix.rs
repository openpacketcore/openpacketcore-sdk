use super::*;
use crate::FencedTransitionV2Profile;

struct MatrixApply<'a> {
    conn: &'a Connection,
    backend: &'a SqliteSessionBackend,
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    index: u64,
}

fn matrix_members() -> BTreeSet<SessionConsensusNodeId> {
    [7, 8, 9]
        .into_iter()
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .collect()
}

impl MatrixApply<'_> {
    fn write(&mut self, intent: SessionMutationIntent) -> SessionConsensusResponse {
        self.index += 1;
        let request_id = match &intent {
            SessionMutationIntent::FencedTransition(request) => {
                SessionConsensusRequestId::from_bytes(*request.request_id().as_bytes())
            }
            SessionMutationIntent::FencedTransitionV2(request) => {
                SessionConsensusRequestId::from_bytes(fenced_transition_v2_outer_request_id(
                    request.request_id(),
                ))
            }
            SessionMutationIntent::VoidFencedTransitionV2(request) => {
                SessionConsensusRequestId::from_bytes(
                    crate::fenced_transition::fenced_transition_v2_void_outer_request_id(
                        request.request_id(),
                    ),
                )
            }
            SessionMutationIntent::RosterAdmissionV2(command) => command.request_id().unwrap(),
            SessionMutationIntent::RosterTerminalV2(command) => command.request_id().unwrap(),
            _ => SessionConsensusRequestId::from_bytes([self.index as u8; 16]),
        };
        let entry = Entry {
            log_id: LogId::new(
                CommittedLeaderId::new(1, *self.members.first().unwrap()),
                self.index,
            ),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: self.identity,
                request_id,
                logical_time: v2_persistence_logical_time(),
                intent: SessionMutationIntent::Authorized {
                    origin: *self.members.first().unwrap(),
                    authority_identity: self.identity,
                    mutation: Box::new(intent),
                },
            }),
        };
        append_logs_sync(self.conn, self.identity, std::slice::from_ref(&entry)).unwrap();
        save_committed_sync(self.conn, self.identity, Some(entry.log_id)).unwrap();
        apply_entries_sync(self.conn, self.identity, &self.backend.caps, vec![entry])
            .unwrap()
            .responses
            .remove(0)
    }
}

fn initialize_matrix(
    conn: &Connection,
    fixture: &crate::consensus::types::RosterV2PersistenceFixture,
    authority: ConsensusAuthorityProfile,
    profile: FencedTransitionV2Profile,
) {
    let members = matrix_members();
    initialize_schema_with_storage_anchor_and_pending_and_bindings_and_fenced_profile(
        conn,
        None,
        fixture.identity,
        &members,
        &test_member_bindings(&members),
        None,
        authority,
        (authority == ConsensusAuthorityProfile::FixedImmutable)
            .then_some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
        Some(&fixture.root),
        profile,
    )
    .unwrap();
}

fn matrix_request(id: u8) -> FencedTransitionRequest {
    let mut request_key = key();
    request_key.stable_id = Bytes::from(vec![id; 8]).try_into().unwrap();
    let record = sealed_record_for_key(request_key.clone(), 1_024);
    FencedTransitionRequest::new(
        crate::FencedTransitionRequestId::from_bytes([id; 16]),
        FencedTransitionLease::acquire(
            request_key,
            record.owner.clone(),
            FenceToken::new(0),
            Duration::from_secs(30),
        )
        .unwrap(),
        FencedTransitionMutation::create(record),
    )
    .unwrap()
}

fn matrix_rows(conn: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    if !table_exists(conn, table).unwrap() {
        return Vec::new();
    }
    let columns = conn
        .prepare(&format!("SELECT * FROM {table}"))
        .unwrap()
        .column_count();
    let order = (1..=columns)
        .map(|column| column.to_string())
        .collect::<Vec<_>>()
        .join(",");
    conn.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))
        .unwrap()
        .query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn every_fenced_and_roster_profile_combination_snapshots_restores_and_reopens() {
    for profile in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
    ] {
        for authority in [
            ConsensusAuthorityProfile::Dynamic,
            ConsensusAuthorityProfile::FixedImmutable,
        ] {
            // The four independently selected lanes are generic V1, generic
            // V2 history, roster V1, and roster V2. Their schema dependencies
            // remain prepared when a lane itself is not selected.
            for lanes in 0_u8..16 {
                for history_first in [false, true] {
                    let admission_index = 4
                        + u64::from(lanes & 1 != 0)
                        + u64::from(lanes & 2 != 0)
                            * (1 + u64::from(profile == FencedTransitionV2Profile::V2WithVoid));
                    let fixture =
                        crate::consensus::types::roster_v2_aborted_persistence_fixture_for_history(
                            [0x91; 16],
                            admission_index,
                        );
                    let directory = tempfile::tempdir().unwrap();
                    let source_path = directory.path().join("source.sqlite");
                    let target_path = directory.path().join("target.sqlite");
                    let snapshot = directory.path().join("snapshot.sqlite");
                    let source = SqliteSessionBackend::open_with_fenced_transition_v2_profile(
                        &source_path,
                        profile,
                    )
                    .unwrap();
                    let conn = source.conn.blocking_lock();
                    initialize_matrix(&conn, &fixture, authority, profile);
                    let members = matrix_members();
                    let membership = Entry {
                        log_id: LogId::new(CommittedLeaderId::new(1, *members.first().unwrap()), 0),
                        payload: EntryPayload::Membership(Membership::new(
                            vec![members.clone()],
                            members.clone(),
                        )),
                    };
                    append_logs_sync(&conn, fixture.identity, std::slice::from_ref(&membership))
                        .unwrap();
                    save_committed_sync(&conn, fixture.identity, Some(membership.log_id)).unwrap();
                    apply_entries_sync(&conn, fixture.identity, &source.caps, vec![membership])
                        .unwrap();
                    let activate_history = || {
                        if lanes & 2 != 0 {
                            activate_fenced_transition_v2_scope_sync(
                                &conn,
                                fixture.identity,
                                fixture.identity,
                                &members,
                                profile.digest(),
                                FencedTransitionV2HistoryEpoch::new(1).unwrap(),
                            )
                            .unwrap();
                        }
                    };
                    if history_first {
                        activate_history();
                    }
                    if lanes & 4 != 0 {
                        activate_protected_roster_schema_sync(&conn).unwrap();
                        activate_fenced_transition_scope_with_voter_digest_sync(
                            &conn,
                            fixture.identity,
                            fixture.identity,
                            &members,
                            protected_roster_profile_voter_set_digest(fixture.identity, &members),
                        )
                        .unwrap();
                    }
                    if lanes & 8 != 0 {
                        activate_protected_roster_profile_v2_scope_sync(
                            &conn,
                            fixture.identity,
                            fixture.identity,
                            &members,
                            crate::fenced_mutation_roster::Profile::v2().digest(),
                        )
                        .unwrap();
                    }
                    if !history_first {
                        activate_history();
                    }
                    if lanes & 1 != 0 {
                        activate_fenced_transition_scope_sync(
                            &conn,
                            fixture.identity,
                            fixture.identity,
                            &members,
                        )
                        .unwrap();
                    }
                    let mut apply = MatrixApply {
                        conn: &conn,
                        backend: &source,
                        identity: fixture.identity,
                        members: members.clone(),
                        index: 0,
                    };
                    assert!(apply
                        .write(SessionMutationIntent::AdvanceLogicalTime)
                        .result
                        .is_ok());
                    assert!(apply
                        .write(SessionMutationIntent::AcquireLease {
                            key: matrix_request(0x30).lease().key().clone(),
                            owner: OwnerId::new("matrix-base-owner").unwrap(),
                            ttl: Duration::from_secs(30),
                        })
                        .result
                        .is_ok());
                    assert!(apply
                        .write(SessionMutationIntent::AcquireLease {
                            key: matrix_request(0x2f).lease().key().clone(),
                            owner: OwnerId::new("matrix-base-owner").unwrap(),
                            ttl: Duration::from_secs(30),
                        })
                        .result
                        .is_ok());
                    if lanes & 1 != 0 {
                        assert!(apply
                            .write(SessionMutationIntent::FencedTransition(Box::new(
                                matrix_request(0x31)
                            )))
                            .result
                            .is_ok());
                    }
                    if lanes & 2 != 0 {
                        let request = matrix_request(0x32);
                        let request = FencedTransitionV2Request::new(
                            FencedTransitionV2HistoryEpoch::new(1).unwrap(),
                            crate::FencedTransitionV2CallerNonce::from_bytes([0x32; 16]),
                            request.lease().clone(),
                            request.mutation().clone(),
                        )
                        .unwrap();
                        assert!(apply
                            .write(SessionMutationIntent::FencedTransitionV2(Box::new(request)))
                            .result
                            .is_ok());
                        if profile == FencedTransitionV2Profile::V2WithVoid {
                            let request = matrix_request(0x33);
                            let request = FencedTransitionV2Request::new(
                                FencedTransitionV2HistoryEpoch::new(1).unwrap(),
                                crate::FencedTransitionV2CallerNonce::from_bytes([0x33; 16]),
                                request.lease().clone(),
                                request.mutation().clone(),
                            )
                            .unwrap();
                            assert_eq!(
                                apply
                                    .write(SessionMutationIntent::VoidFencedTransitionV2(Box::new(
                                        request
                                    )))
                                    .result,
                                Err(StoreError::FencedTransitionVoided)
                            );
                        }
                    }
                    if lanes & 4 != 0 {
                        // Use the canonical retained V1 carrier and the same
                        // durable lane writers used by retirement tests. This
                        // proves nonempty V1 tables survive alongside V2.
                        let retained = retirement_fixture_retained_with_terminal_sequence(
                            0x71,
                            1,
                            1,
                            v2_persistence_logical_time(),
                            2,
                        );
                        write_retirement_fixture_record_for_identity(
                            &conn,
                            fixture.identity,
                            &retained,
                            v2_persistence_logical_time(),
                        );
                        write_retirement_fixture_floor_for_identity(
                            &conn,
                            fixture.identity,
                            retained.binding(),
                        );
                        write_retirement_fixture_witness_for_identity(
                            &conn,
                            fixture.identity,
                            &[retained],
                        );
                    }
                    if lanes & 8 != 0 {
                        // The sealed V2 fixture has an exact authority lease.
                        // Seed its paired allocator state, then write Q1/Q2
                        // through normal logged consensus apply.
                        conn.execute("INSERT INTO leases (tenant,nf_kind,key_type,stable_id,active,credential_id,owner,fence,acquired_at,expires_at_unix_ms,guard_expires_at) VALUES (?1,?2,?3,?4,1,?5,?6,?7,?8,?9,?10)", params![fixture.authority.key().tenant.as_str(), fixture.authority.key().nf_kind.as_str(), fixture.authority.key().key_type.to_string(), fixture.authority.key().stable_id.as_ref(), checked_positive_i64(fixture.authority.credential_id()).unwrap(), fixture.authority.owner().as_str(), checked_positive_i64(fixture.authority.fence().get()).unwrap(), ops::format_rfc3339_normalized(fixture.authority.acquired_at()), ops::timestamp_unix_millis(fixture.authority.expires_at()).unwrap(), ops::format_rfc3339_normalized(fixture.authority.expires_at())]).unwrap();
                        ops::insert_or_replace_fence_sync(
                            &conn,
                            fixture.authority.key(),
                            fixture.authority.fence().get(),
                        )
                        .unwrap();
                        conn.execute(
                            "UPDATE lease_globals SET val=MAX(val,?1) WHERE key='next_fence'",
                            [checked_positive_i64(fixture.authority.fence().get() + 1).unwrap()],
                        )
                        .unwrap();
                        conn.execute("UPDATE lease_globals SET val=MAX(val,?1) WHERE key='next_credential_id'", [checked_positive_i64(fixture.authority.credential_id()+1).unwrap()]).unwrap();
                        let admission = ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id_v2(fixture.admission.clone(), fixture.authority.clone(), fixture.admission_ingress.request_id(), fixture.admission_ingress.clone(), fixture.admission_provenance.clone()).unwrap();
                        let admission_result = apply
                            .write(SessionMutationIntent::RosterAdmissionV2(Box::new(
                                admission,
                            )))
                            .result;
                        assert!(matches!(
                            &admission_result,
                            Ok(SessionMutationOutcome::RosterAdmissionV2(
                                ConsensusRosterAdmissionOutcome::Admitted { .. }
                            ))
                        ), "profile={profile:?} authority={authority:?} lanes={lanes} history_first={history_first}: {admission_result:?}");
                        assert!(matches!(
                            apply
                                .write(SessionMutationIntent::RosterTerminalV2(Box::new(
                                    fixture.terminal_command.clone()
                                )))
                                .result,
                            Ok(SessionMutationOutcome::RosterTerminalV2(
                                ConsensusRosterTerminalOutcome::Committed { .. }
                            ))
                        ));
                    }
                    let tables = [
                        "session_records",
                        "leases",
                        "consensus_fenced_transition_receipts",
                        "consensus_fenced_transition_v2_receipts",
                        "consensus_protected_roster_rows",
                        "consensus_protected_roster_v2_admissions",
                    ];
                    let expected = tables.map(|table| matrix_rows(&conn, table));
                    let expected_schema = schema_manifest_in_sync(&conn, false).unwrap();
                    let scan_index_count =
                        crate::sqlite::scope_scan::schema::optional_object_count(&conn, false)
                            .unwrap();
                    assert_eq!(scan_index_count, 2);
                    assert_eq!(
                        expected_schema.len(),
                        33 + scan_index_count
                            + usize::from(lanes & 2 != 0) * 5
                            + usize::from(lanes & 8 != 0) * 6
                            + usize::from(profile == FencedTransitionV2Profile::V2WithVoid)
                    );
                    validate_existing_schema(&conn, fixture.identity).unwrap_or_else(|error| panic!("source profile={profile:?} authority={authority:?} lanes={lanes} history_first={history_first}: {error}"));
                    let (last_log_id, last_membership) = build_snapshot_database_sync(&conn, fixture.identity, &snapshot).unwrap_or_else(|error| panic!("profile={profile:?} authority={authority:?} lanes={lanes} history_first={history_first}: {error}"));
                    drop(conn);
                    drop(source);
                    let target = SqliteSessionBackend::open_with_fenced_transition_v2_profile(
                        &target_path,
                        profile,
                    )
                    .unwrap();
                    let conn = target.conn.blocking_lock();
                    initialize_matrix(&conn, &fixture, authority, profile);
                    let meta = opc_consensus::engine::SnapshotMeta {
                        last_log_id,
                        last_membership,
                        snapshot_id: "profile-matrix".into(),
                    };
                    install_snapshot_database_with_authority_sync(
                        &conn,
                        fixture.identity,
                        authority,
                        Some(&members),
                        Some(&test_member_bindings(&members)),
                        (authority == ConsensusAuthorityProfile::FixedImmutable)
                            .then_some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
                        &snapshot,
                        &meta,
                        "snapshot-00000000-0000-4000-8000-000000000707.opc",
                        [0x70; 32],
                        std::fs::metadata(&snapshot).unwrap().len(),
                    )
                    .unwrap();
                    drop(conn);
                    drop(target);
                    for path in [&source_path, &target_path] {
                        let reopened =
                            SqliteSessionBackend::open_with_fenced_transition_v2_profile(
                                path, profile,
                            )
                            .unwrap();
                        let conn = reopened.conn.blocking_lock();
                        initialize_matrix(&conn, &fixture, authority, profile);
                        assert_eq!(
                            schema_manifest_in_sync(&conn, false).unwrap(),
                            expected_schema
                        );
                        for (table, rows) in tables.iter().zip(&expected) {
                            assert_eq!(&matrix_rows(&conn, table), rows, "{table}");
                        }
                    }
                }
            }
        }
    }
}
