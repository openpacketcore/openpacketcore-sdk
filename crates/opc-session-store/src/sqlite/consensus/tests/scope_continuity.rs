use super::*;
use crate::scope_lease::{ScopeProfileActivation, ScopeProfileContinuation};
use crate::scope_storage::{self as rows, ContinuationRow, ScopeRow};

fn certificate(seed: u8) -> ScopeProfileContinuation {
    ScopeProfileContinuation {
        transition_id: [seed; 16],
        transition_digest: [seed; 32],
        predecessor: ScopeProfileActivation::new(
            identity(),
            fenced_transition_voter_set_digest(identity(), &members(&[7, 8, 9])),
        ),
        successor: ScopeProfileActivation::new(
            identity_at(2, 0xA3),
            fenced_transition_voter_set_digest(identity_at(2, 0xA3), &members(&[7, 8, 10])),
        ),
    }
}

fn prepare(index: u64, seed: u8) -> Entry<SessionRaftTypeConfig> {
    let desired = members(&[7, 8, 10]);
    topology_entry_at(
        index,
        index as u8,
        SessionMutationIntent::PrepareTopologyTransition {
            transition_id: [seed; 16],
            request_digest: [seed; 32],
            desired_identity: identity_at(2, 0xA3),
            desired_bindings: test_member_bindings(&desired),
            desired_members: desired,
        },
    )
}

fn commit(conn: &Connection, caps: &BackendCapabilities, entry: Entry<SessionRaftTypeConfig>) {
    append_logs_sync(conn, identity(), std::slice::from_ref(&entry)).unwrap();
    save_committed_sync(conn, identity(), Some(entry.log_id)).unwrap();
    let result = apply_entries_sync(conn, identity(), caps, vec![entry]).unwrap();
    assert!(result
        .responses
        .iter()
        .all(|response| response.result.is_ok()));
}

fn prepared(conn: &Connection, caps: &BackendCapabilities, proof: bool) {
    let current = members(&[7, 8, 9]);
    initialize_schema(conn, identity(), &current).unwrap();
    commit(
        conn,
        caps,
        membership_entry_at(0, vec![current.clone()], current.clone()),
    );
    commit(
        conn,
        caps,
        topology_entry_at(
            1,
            1,
            SessionMutationIntent::Authorized {
                origin: member(7),
                authority_identity: identity(),
                mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                    certificate(0).predecessor,
                ))),
            },
        ),
    );
    // All-zero fixed-width transition identifiers are valid exact bindings.
    commit(conn, caps, prepare(2, 0));
    let continuation = if proof {
        topology_entry_at(
            3,
            3,
            SessionMutationIntent::CertifyScopeProfileContinuation(Box::new(certificate(0))),
        )
    } else {
        Entry {
            log_id: log_id(3),
            payload: EntryPayload::Blank,
        }
    };
    commit(conn, caps, continuation);
    commit(
        conn,
        caps,
        membership_entry_at(4, vec![current], members(&[7, 8, 9, 10])),
    );
    commit(
        conn,
        caps,
        topology_entry_at(
            5,
            5,
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id: [0; 16],
                request_digest: [0; 32],
            },
        ),
    );
}

fn fence() -> Entry<SessionRaftTypeConfig> {
    topology_entry_at(
        6,
        6,
        SessionMutationIntent::FenceTopologyAuthority {
            transition_id: [0; 16],
            request_digest: [0; 32],
        },
    )
}

fn continuation(conn: &Connection) -> ContinuationRow {
    match super::super::scope_batch::read(
        conn,
        &rows::continuation_key(identity().cluster_id()).unwrap(),
    )
    .unwrap()
    .unwrap()
    {
        ScopeRow::Continuation(row) => *row,
        other => panic!("continuation expected: {other:?}"),
    }
}

#[test]
fn scope_profile_previous_format_reopen_requires_fresh_installation() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("previous-scope-format.sqlite");
    let current = members(&[7, 8, 9]);
    let legacy = rows::previous_profile_record_for_test(certificate(0).predecessor);
    {
        let backend = SqliteSessionBackend::open(&database).unwrap();
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &current).unwrap();
        let current_record = ScopeRow::Activation(certificate(0).predecessor)
            .to_record()
            .unwrap();
        ops::insert_or_replace_scope_record_sync(&conn, &current_record).unwrap();
        // Write the frozen old bytes directly: the live insertion path rightly
        // accepts only the current format and is not this reopen test's subject.
        conn.execute(
            "UPDATE session_records SET payload = ?1, state_type = ?2 WHERE key_type = 'opc-scope-profile'",
            params![legacy.payload.as_bytes(), "opc-scope-state-v2"],
        )
        .unwrap();
    }
    let backend = SqliteSessionBackend::open(&database).unwrap();
    let conn = backend.conn.blocking_lock();
    let error = initialize_schema(&conn, identity(), &current).unwrap_err();
    assert!(
        error.to_string().contains("fresh installation required"),
        "the known previous format needs an actionable reopen reason: {error:?}"
    );
    assert_eq!(
        error,
        SessionConsensusStorageError::FreshInstallationRequired
    );
    let public: crate::ConsensusSessionStoreOpenError = error.into();
    assert!(public.to_string().contains("fresh installation required"));
    assert_eq!(
        public,
        crate::ConsensusSessionStoreOpenError::FreshInstallationRequired
    );
    // Refusal must leave the old bytes intact, without attempting migration.
    let payload: Vec<u8> = conn
        .query_row(
            "SELECT payload FROM session_records WHERE key_type = 'opc-scope-profile'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(payload, legacy.payload.as_bytes());

    let mut corrupt = legacy;
    corrupt.state_type = crate::StateType::from_static("opc-scope-state-v3");
    corrupt.payload = EncryptedSessionPayload::new(b"OPSC\x03invalid");
    conn.execute(
        "UPDATE session_records SET payload = ?1, state_type = ?2 WHERE key_type = 'opc-scope-profile'",
        params![corrupt.payload.as_bytes(), "opc-scope-state-v3"],
    )
    .unwrap();
    assert_eq!(
        initialize_schema(&conn, identity(), &current).unwrap_err(),
        SessionConsensusStorageError::CorruptState,
        "current-format corruption must retain its distinct reason"
    );
}

#[test]
fn scope_profile_continuity_candidate_replays_activation_before_durable_prepare() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    let current = members(&[7, 8, 9]);
    let desired = members(&[7, 8, 10]);
    let bindings = test_member_bindings(&desired);
    initialize_schema_with_pending(
        &conn,
        identity(),
        &current,
        Some(PendingMembershipBootstrap {
            local_candidate_node_id: Some(member(10)),
            transition_id: [0; 16],
            transition_digest: [0; 32],
            desired_identity: certificate(0).successor.identity,
            desired_members: &desired,
            desired_bindings: &bindings,
        }),
    )
    .unwrap();
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(0, vec![current.clone()], current),
    );
    assert_eq!(
        read_membership_scope_sync(&conn, identity())
            .unwrap()
            .pending
            .unwrap()
            .transition_start_log_index,
        0
    );
    let activation = |index| {
        topology_entry_at(
            index,
            index as u8,
            SessionMutationIntent::Authorized {
                origin: member(7),
                authority_identity: identity(),
                mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                    certificate(0).predecessor,
                ))),
            },
        )
    };
    // Candidate metadata is installed before the historical prefix is replayed.
    // Its provisional transition must not change the outcome of that prefix.
    commit(&conn, &backend.caps, activation(1));
    assert!(super::super::scope_batch::active(
        &conn,
        &read_membership_scope_sync(&conn, identity()).unwrap()
    )
    .unwrap());
    commit(&conn, &backend.caps, prepare(2, 0));
    let late = activation(3);
    append_logs_sync(&conn, identity(), std::slice::from_ref(&late)).unwrap();
    save_committed_sync(&conn, identity(), Some(late.log_id)).unwrap();
    let applied = apply_entries_sync(&conn, identity(), &backend.caps, vec![late]).unwrap();
    assert!(matches!(
        applied.responses.as_slice(),
        [SessionConsensusResponse {
            result: Err(StoreError::TopologyAuthorityRevoked),
            ..
        }]
    ));
    assert_eq!(
        read_applied_sync(&conn, identity()).unwrap(),
        Some(log_id(3))
    );
}

#[test]
fn scope_profile_continuity_candidate_replays_stale_activation_receipt_exactly() {
    let stale = topology_entry_at(
        1,
        0x41,
        SessionMutationIntent::Authorized {
            origin: member(7),
            authority_identity: identity_at(1, 0x77),
            mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                certificate(0).predecessor,
            ))),
        },
    );
    let mut duplicate = stale.clone();
    duplicate.log_id = log_id(2);
    let mut observed = Vec::new();
    for candidate in [false, true] {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        let current = members(&[7, 8, 9]);
        let desired = members(&[7, 8, 10]);
        let bindings = test_member_bindings(&desired);
        initialize_schema_with_pending(
            &conn,
            identity(),
            &current,
            candidate.then_some(PendingMembershipBootstrap {
                local_candidate_node_id: Some(member(10)),
                transition_id: [0; 16],
                transition_digest: [0; 32],
                desired_identity: certificate(0).successor.identity,
                desired_members: &desired,
                desired_bindings: &bindings,
            }),
        )
        .unwrap();
        commit(
            &conn,
            &backend.caps,
            membership_entry_at(0, vec![current.clone()], current),
        );
        let mut sequences = Vec::new();
        for entry in [stale.clone(), duplicate.clone()] {
            append_logs_sync(&conn, identity(), std::slice::from_ref(&entry)).unwrap();
            save_committed_sync(&conn, identity(), Some(entry.log_id)).unwrap();
            let applied = apply_entries_sync(&conn, identity(), &backend.caps, vec![entry])
                .expect("stale activation is a committed refusal");
            assert!(matches!(
                applied.responses.as_slice(),
                [SessionConsensusResponse {
                    result: Err(StoreError::TopologyAuthorityRevoked),
                    ..
                }]
            ));
            sequences.push(applied.responses[0].sequence);
        }
        let receipts: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM consensus_request_outcomes WHERE request_id = ?1",
                [[0x41_u8; 16].as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let machine: (i64, Vec<u8>) = conn
            .query_row(
                "SELECT application_sequence, last_digest FROM consensus_machine WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        observed.push((receipts, sequences, machine));
    }
    assert_eq!(observed[0].0, 1);
    assert_eq!(observed[0].1, [1, 1]);
    let (sequence, _) = &observed[0].2;
    assert_eq!(*sequence, 1);
    assert_eq!(
        observed[0], observed[1],
        "a provisional candidate must retain the same receipt, duplicate sequence and digest as a voter"
    );
}

#[test]
fn scope_profile_continuity_missing_or_wrong_proof_commits_fence_refusal() {
    for variant in 0..7 {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        prepared(&conn, &backend.caps, false);
        let before = read_membership_scope_sync(&conn, identity()).unwrap();
        if variant != 0 {
            let mut wrong = certificate(0);
            match variant {
                1 => wrong.transition_id = [1; 16],
                2 => wrong.transition_digest = [1; 32],
                3 => wrong.predecessor.voters = [1; 32],
                4 => wrong.successor.voters = [1; 32],
                5 => wrong.successor.identity = identity_at(2, 0xA4),
                6 => (), // A proof from before Prepare is not evidence for it.
                _ => unreachable!(),
            }
            let row = ScopeRow::Continuation(Box::new(ContinuationRow {
                certificate: wrong,
                log_index: if variant == 6 { 2 } else { 3 },
            }))
            .to_record()
            .unwrap();
            ops::insert_or_replace_scope_record_sync(&conn, &row).unwrap();
        }
        append_logs_sync(&conn, identity(), &[fence()]).unwrap();
        save_committed_sync(&conn, identity(), Some(log_id(6))).unwrap();
        let applied = apply_entries_sync(&conn, identity(), &backend.caps, vec![fence()])
            .unwrap_or_else(|error| {
                panic!("decodable proof case {variant} must not wedge apply: {error}")
            });
        assert!(matches!(
            applied.responses.as_slice(),
            [SessionConsensusResponse { result: Err(StoreError::InvalidKey(code)), .. }]
                if code == "topology_transition_rejected"
        ));
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(6))
        );
        assert_eq!(
            read_membership_scope_sync(&conn, identity()).unwrap(),
            before
        );
        commit(
            &conn,
            &backend.caps,
            topology_entry_at(
                7,
                7,
                SessionMutationIntent::AbortTopologyTransition {
                    transition_id: [0; 16],
                    request_digest: [0; 32],
                },
            ),
        );
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(7))
        );
    }
}

#[test]
fn scope_profile_continuity_late_activation_is_refused_without_wedging_log() {
    for late_certificate in [false, true] {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        let current = members(&[7, 8, 9]);
        initialize_schema(&conn, identity(), &current).unwrap();
        commit(
            &conn,
            &backend.caps,
            membership_entry_at(0, vec![current.clone()], current.clone()),
        );
        commit(&conn, &backend.caps, prepare(1, 0));
        commit(
            &conn,
            &backend.caps,
            membership_entry_at(2, vec![current], members(&[7, 8, 9, 10])),
        );
        commit(
            &conn,
            &backend.caps,
            topology_entry_at(
                3,
                3,
                SessionMutationIntent::MarkTopologyLearnersReady {
                    transition_id: [0; 16],
                    request_digest: [0; 32],
                },
            ),
        );
        let activation = topology_entry_at(
            4,
            4,
            SessionMutationIntent::Authorized {
                origin: member(7),
                authority_identity: identity(),
                mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                    certificate(0).predecessor,
                ))),
            },
        );
        append_logs_sync(&conn, identity(), std::slice::from_ref(&activation)).unwrap();
        save_committed_sync(&conn, identity(), Some(activation.log_id)).unwrap();
        let applied =
            apply_entries_sync(&conn, identity(), &backend.caps, vec![activation.clone()]).unwrap();
        assert!(
            matches!(
                applied.responses.as_slice(),
                [SessionConsensusResponse {
                    result: Err(StoreError::TopologyAuthorityRevoked),
                    ..
                }]
            ),
            "a pending transition must freeze initial activation"
        );
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(4))
        );
        assert!(super::super::scope_batch::read(
            &conn,
            &rows::profile_key(identity().cluster_id()).unwrap()
        )
        .unwrap()
        .is_none());
        let next = if late_certificate {
            let proof = topology_entry_at(
                5,
                5,
                SessionMutationIntent::CertifyScopeProfileContinuation(Box::new(certificate(0))),
            );
            append_logs_sync(&conn, identity(), std::slice::from_ref(&proof)).unwrap();
            save_committed_sync(&conn, identity(), Some(proof.log_id)).unwrap();
            let applied =
                apply_entries_sync(&conn, identity(), &backend.caps, vec![proof]).unwrap();
            assert!(matches!(applied.responses.as_slice(),
                [SessionConsensusResponse { result: Err(StoreError::InvalidKey(code)), .. }]
                    if code == "topology_transition_rejected"));
            6
        } else {
            5
        };
        commit(
            &conn,
            &backend.caps,
            topology_entry_at(
                next,
                next as u8,
                SessionMutationIntent::FenceTopologyAuthority {
                    transition_id: [0; 16],
                    request_digest: [0; 32],
                },
            ),
        );
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(next))
        );
        commit(
            &conn,
            &backend.caps,
            topology_entry_at(
                next + 1,
                10,
                SessionMutationIntent::AbortTopologyTransition {
                    transition_id: [0; 16],
                    request_digest: [0; 32],
                },
            ),
        );
        commit(
            &conn,
            &backend.caps,
            membership_entry_at(next + 2, vec![members(&[7, 8, 9])], members(&[7, 8, 9])),
        );
        let mut retry = activation;
        retry.log_id = log_id(next + 3);
        commit(&conn, &backend.caps, retry);
        assert!(
            super::super::scope_batch::active(
                &conn,
                &read_membership_scope_sync(&conn, identity()).unwrap()
            )
            .unwrap(),
            "the exact activation retry must succeed after abort"
        );
    }
}

#[test]
fn scope_profile_continuity_late_certificate_recovers_after_refused_fence() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    prepared(&conn, &backend.caps, false);
    append_logs_sync(&conn, identity(), &[fence()]).unwrap();
    save_committed_sync(&conn, identity(), Some(log_id(6))).unwrap();
    let result = apply_entries_sync(&conn, identity(), &backend.caps, vec![fence()])
        .expect("missing proof is a committed refusal, so prepare can resume");
    assert!(matches!(result.responses.as_slice(),
        [SessionConsensusResponse { result: Err(StoreError::InvalidKey(code)), .. }]
            if code == "topology_transition_rejected"));
    commit(
        &conn,
        &backend.caps,
        topology_entry_at(
            7,
            7,
            SessionMutationIntent::CertifyScopeProfileContinuation(Box::new(certificate(0))),
        ),
    );
    assert_eq!(continuation(&conn).log_index, 7);
    let mut retry = fence();
    retry.log_id = log_id(8);
    commit(&conn, &backend.caps, retry);
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(
            9,
            vec![members(&[7, 8, 9]), members(&[7, 8, 10])],
            members(&[7, 8, 9, 10]),
        ),
    );
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(10, vec![members(&[7, 8, 10])], members(&[7, 8, 10])),
    );
    let scope = read_membership_scope_sync(&conn, identity()).unwrap();
    assert_eq!(scope.current_identity, certificate(0).successor.identity);
    assert!(super::super::scope_batch::active(&conn, &scope).unwrap());
}

#[test]
fn scope_profile_continuity_unreadable_proof_still_aborts_fence_apply() {
    for decode_fault in [false, true] {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        prepared(&conn, &backend.caps, true);
        if decode_fault {
            conn.execute("UPDATE session_records SET payload = x'00' WHERE key_type = 'opc-scope-continuation'", []).unwrap();
        } else {
            conn.execute_batch("ALTER TABLE session_records RENAME TO unreadable_scope_records")
                .unwrap();
        }
        assert!(apply_entries_sync(&conn, identity(), &backend.caps, vec![fence()]).is_err());
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(5))
        );
        assert_eq!(
            read_membership_scope_sync(&conn, identity())
                .unwrap()
                .application_authority_epoch,
            identity().configuration_epoch()
        );
    }
}

#[test]
fn scope_profile_continuity_fence_drains_old_stamps_and_preserves_issued_permits() {
    use crate::scope_batch::{
        ScopeBatchCommand, ScopeBatchError, ScopeBatchRequest, ScopeCounterMutation,
    };
    use crate::scope_lease::{
        ScopeClockBounds, ScopeLeaseCommand, ScopeLeaseError, ScopeLeaseId, ScopeLeaseOperation,
        ScopeLeaseRequest,
    };
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    prepared(&conn, &backend.caps, true);
    let scope = ScopeLeaseId::new(
        identity(),
        opc_types::TenantId::from_static("scope-drain"),
        opc_types::NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let execution = crate::scope_lease::tests::execution(1);
    let bounds = ScopeClockBounds::new(timestamp(5), timestamp(5)).unwrap();
    let lease = |id, revision, operation| {
        SessionMutationIntent::ScopeLease(Box::new(ScopeLeaseCommand {
            request: ScopeLeaseRequest::new(scope.clone(), [id; 16], revision, operation).unwrap(),
            bounds,
        }))
    };
    let apply = |index, id, authority, mutation| {
        let entry = topology_entry_at(
            index,
            id,
            SessionMutationIntent::Authorized {
                origin: member(7),
                authority_identity: authority,
                mutation: Box::new(mutation),
            },
        );
        append_logs_sync(&conn, identity(), std::slice::from_ref(&entry)).unwrap();
        save_committed_sync(&conn, identity(), Some(entry.log_id)).unwrap();
        apply_entries_sync(&conn, identity(), &backend.caps, vec![entry])
            .unwrap()
            .responses
            .remove(0)
            .result
            .unwrap()
    };
    apply(
        6,
        6,
        identity(),
        lease(
            6,
            0,
            ScopeLeaseOperation::Select {
                execution: execution.clone(),
            },
        ),
    );
    let SessionMutationOutcome::ScopeLease(Ok(acquired)) = apply(
        7,
        7,
        identity(),
        lease(
            7,
            1,
            ScopeLeaseOperation::Acquire {
                execution,
                selection: 1,
            },
        ),
    ) else {
        panic!("acquire under the pending predecessor");
    };
    let acquired = acquired.state().unwrap().view;
    let batch = |id, revision, permit: &crate::scope_lease::ScopePermit| {
        SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
            request: ScopeBatchRequest::new(
                permit,
                [id; 16],
                revision,
                vec![],
                vec![ScopeCounterMutation::new(0, revision, revision + 1).unwrap()],
            )
            .unwrap(),
            bounds,
        }))
    };
    assert!(matches!(
        apply(8, 8, identity(), batch(8, 0, acquired.permit().unwrap())),
        SessionMutationOutcome::ScopeBatch(Ok(_))
    ));
    let SessionMutationOutcome::ScopeLease(Ok(renewed)) = apply(
        9,
        9,
        identity(),
        lease(
            9,
            acquired.revision(),
            ScopeLeaseOperation::Renew {
                permit: acquired.permit().unwrap().clone(),
            },
        ),
    ) else {
        panic!("renew under the pending predecessor");
    };
    let renewed = renewed.state().unwrap().view;
    let before_lease = super::super::scope_lease::read(&conn, identity(), &scope).unwrap();
    let before_batch =
        super::super::scope_batch::read(&conn, &rows::batch_key(&scope).unwrap()).unwrap();
    commit(
        &conn,
        &backend.caps,
        topology_entry_at(
            10,
            10,
            SessionMutationIntent::FenceTopologyAuthority {
                transition_id: [0; 16],
                request_digest: [0; 32],
            },
        ),
    );
    let delayed_lease = lease(
        11,
        renewed.revision(),
        ScopeLeaseOperation::Renew {
            permit: renewed.permit().unwrap().clone(),
        },
    );
    let delayed_batch = batch(12, 1, renewed.permit().unwrap());
    assert!(matches!(
        apply(11, 11, identity(), delayed_lease.clone()),
        SessionMutationOutcome::ScopeLease(Err(ScopeLeaseError::Unavailable))
    ));
    assert!(matches!(
        apply(12, 12, identity(), delayed_batch.clone()),
        SessionMutationOutcome::ScopeBatch(Err(ScopeBatchError::Scope(
            ScopeLeaseError::Unavailable
        )))
    ));
    assert_eq!(
        super::super::scope_lease::read(&conn, identity(), &scope).unwrap(),
        before_lease
    );
    assert_eq!(
        super::super::scope_batch::read(&conn, &rows::batch_key(&scope).unwrap()).unwrap(),
        before_batch
    );
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(
            13,
            vec![members(&[7, 8, 9]), members(&[7, 8, 10])],
            members(&[7, 8, 9, 10]),
        ),
    );
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(14, vec![members(&[7, 8, 10])], members(&[7, 8, 10])),
    );
    // The exact client requests and the pre-Fence permit are still valid;
    // only the proposal's authority stamp follows the new configuration.
    let successor = certificate(0).successor.identity;
    let SessionMutationOutcome::ScopeLease(Ok(retried)) = apply(15, 11, successor, delayed_lease)
    else {
        panic!("an issued permit survives cutover without a new grant");
    };
    assert_eq!(
        retried.state().unwrap().view.grant_floor(),
        renewed.grant_floor()
    );
    assert!(matches!(
        apply(16, 12, successor, delayed_batch),
        SessionMutationOutcome::ScopeBatch(Ok(_))
    ));
}

#[test]
fn scope_profile_continuity_survives_receipt_pruning_restart_and_cutover() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("continuity.sqlite");
    let backend = SqliteSessionBackend::open(&database).unwrap();
    {
        let conn = backend.conn.blocking_lock();
        prepared(&conn, &backend.caps, true);
        conn.execute("DELETE FROM consensus_request_outcomes", [])
            .unwrap();
        assert_eq!(continuation(&conn).certificate, certificate(0));
    }
    drop(backend);
    let backend = SqliteSessionBackend::open(&database).unwrap();
    let conn = backend.conn.blocking_lock();
    initialize_schema(&conn, identity(), &members(&[7, 8, 9])).unwrap();
    assert_eq!(continuation(&conn).certificate, certificate(0));
    commit(&conn, &backend.caps, fence());
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(
            7,
            vec![members(&[7, 8, 9]), members(&[7, 8, 10])],
            members(&[7, 8, 9, 10]),
        ),
    );
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(8, vec![members(&[7, 8, 10])], members(&[7, 8, 10])),
    );
    let scope = read_membership_scope_sync(&conn, identity()).unwrap();
    assert_eq!(scope.current_identity, certificate(0).successor.identity);
    assert!(super::super::scope_batch::active(&conn, &scope).unwrap());
    assert_eq!(
        super::super::scope_batch::read(
            &conn,
            &rows::profile_key(identity().cluster_id()).unwrap()
        )
        .unwrap(),
        Some(ScopeRow::Activation(certificate(0).successor))
    );
    build_snapshot_database_sync(&conn, identity(), &directory.path().join("snapshot.sqlite"))
        .unwrap();
    validate_sealed_state_sync(&conn).unwrap();
}

#[test]
fn scope_profile_continuity_abort_keeps_activation_but_cannot_certify_next_transition() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    prepared(&conn, &backend.caps, true);
    commit(
        &conn,
        &backend.caps,
        topology_entry_at(
            6,
            6,
            SessionMutationIntent::AbortTopologyTransition {
                transition_id: [0; 16],
                request_digest: [0; 32],
            },
        ),
    );
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(7, vec![members(&[7, 8, 9])], members(&[7, 8, 9])),
    );
    let scope = read_membership_scope_sync(&conn, identity()).unwrap();
    assert!(super::super::scope_batch::active(&conn, &scope).unwrap());
    assert_eq!(continuation(&conn).certificate, certificate(0));
    commit(&conn, &backend.caps, prepare(8, 1));
    let scope = read_membership_scope_sync(&conn, identity()).unwrap();
    assert!(super::super::scope_continuity::require_for_pending(&conn, &scope).is_err());
    assert!(
        super::super::scope_continuity::certify(&conn, identity(), &certificate(0), 9).is_err()
    );
    commit(
        &conn,
        &backend.caps,
        topology_entry_at(
            9,
            9,
            SessionMutationIntent::CertifyScopeProfileContinuation(Box::new(certificate(1))),
        ),
    );
    let next = continuation(&conn);
    assert_eq!(next.certificate, certificate(1));
    assert_eq!(next.log_index, 9);
    assert!(
        super::super::scope_continuity::require_for_pending(&conn, &scope)
            .unwrap()
            .is_some()
    );
    let rows: u64 = conn
        .query_row("SELECT COUNT(*) FROM session_records", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        rows, 2,
        "one activation and one continuation, independent of transition count"
    );
}

#[test]
fn scope_profile_continuity_removed_voter_readdition_requires_new_certificate() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    prepared(&conn, &backend.caps, true);
    commit(&conn, &backend.caps, fence());
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(
            7,
            vec![members(&[7, 8, 9]), members(&[7, 8, 10])],
            members(&[7, 8, 9, 10]),
        ),
    );
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(8, vec![members(&[7, 8, 10])], members(&[7, 8, 10])),
    );
    commit(
        &conn,
        &backend.caps,
        topology_entry_at(
            9,
            9,
            SessionMutationIntent::FinalizeTopologyTransition {
                transition_id: [0; 16],
                request_digest: [0; 32],
            },
        ),
    );
    let predecessor = certificate(0).successor;
    let successor_identity = identity_at(3, 0xA4);
    let desired = members(&[7, 8, 9]);
    assert!(!read_membership_scope_sync(&conn, identity())
        .unwrap()
        .current_members
        .contains(&member(9)));
    let next = ScopeProfileContinuation {
        transition_id: [1; 16],
        transition_digest: [1; 32],
        predecessor,
        successor: ScopeProfileActivation::new(
            successor_identity,
            fenced_transition_voter_set_digest(successor_identity, &desired),
        ),
    };
    commit(
        &conn,
        &backend.caps,
        topology_entry_at(
            10,
            10,
            SessionMutationIntent::PrepareTopologyTransition {
                transition_id: next.transition_id,
                request_digest: next.transition_digest,
                desired_identity: successor_identity,
                desired_bindings: test_member_bindings(&desired),
                desired_members: desired.clone(),
            },
        ),
    );
    let scope = read_membership_scope_sync(&conn, identity()).unwrap();
    assert!(matches!(
        super::super::scope_continuity::require_for_pending(&conn, &scope),
        Err(MembershipScopeMutationError::InvalidScope)
    ));
    assert!(matches!(
        super::super::scope_continuity::certify(&conn, identity(), &certificate(0), 11),
        Err(MembershipScopeMutationError::InvalidScope)
    ));
    commit(
        &conn,
        &backend.caps,
        topology_entry_at(
            11,
            11,
            SessionMutationIntent::CertifyScopeProfileContinuation(Box::new(next.clone())),
        ),
    );
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(12, vec![members(&[7, 8, 10])], members(&[7, 8, 9, 10])),
    );
    for (index, intent) in [
        SessionMutationIntent::MarkTopologyLearnersReady {
            transition_id: next.transition_id,
            request_digest: next.transition_digest,
        },
        SessionMutationIntent::FenceTopologyAuthority {
            transition_id: next.transition_id,
            request_digest: next.transition_digest,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let index = 13 + index as u64;
        commit(
            &conn,
            &backend.caps,
            topology_entry_at(index, index as u8, intent),
        );
    }
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(
            15,
            vec![members(&[7, 8, 10]), desired.clone()],
            members(&[7, 8, 9, 10]),
        ),
    );
    commit(
        &conn,
        &backend.caps,
        membership_entry_at(16, vec![desired.clone()], desired.clone()),
    );
    let scope = read_membership_scope_sync(&conn, identity()).unwrap();
    assert_eq!(scope.current_members, desired);
    assert_eq!(scope.current_identity, successor_identity);
    assert!(super::super::scope_batch::active(&conn, &scope).unwrap());
    assert_eq!(continuation(&conn).certificate, next);
    assert_eq!(continuation(&conn).log_index, 11);
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM session_records", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        count, 2,
        "readdition retains one activation and one continuation"
    );
}

#[test]
fn scope_profile_continuity_snapshot_preserves_attestation_floor() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    prepared(&conn, &backend.caps, true);
    conn.execute_batch(
        "ATTACH DATABASE ':memory:' AS consensus_incoming;
        CREATE TABLE consensus_incoming.session_records AS SELECT * FROM main.session_records;",
    )
    .unwrap();
    super::super::scope_batch::validate_snapshot_preserves_scopes(&conn).unwrap();
    conn.execute(
        "DELETE FROM consensus_incoming.session_records WHERE key_type = 'opc-scope-continuation'",
        [],
    )
    .unwrap();
    assert!(super::super::scope_batch::validate_snapshot_preserves_scopes(&conn).is_err());
    let mut old = continuation(&conn);
    old.log_index -= 1;
    let old = ScopeRow::Continuation(Box::new(old)).to_record().unwrap();
    conn.execute("INSERT INTO consensus_incoming.session_records SELECT * FROM main.session_records WHERE key_type = 'opc-scope-continuation'", []).unwrap();
    conn.execute("UPDATE consensus_incoming.session_records SET generation = ?1, payload = ?2 WHERE key_type = 'opc-scope-continuation'",
        params![2, old.payload.as_bytes()]).unwrap();
    assert!(super::super::scope_batch::validate_snapshot_preserves_scopes(&conn).is_err());
}

#[test]
fn scope_profile_continuity_cutover_and_activation_are_one_transaction() {
    for missing_proof in [false, true] {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        prepared(&conn, &backend.caps, true);
        commit(&conn, &backend.caps, fence());
        commit(
            &conn,
            &backend.caps,
            membership_entry_at(
                7,
                vec![members(&[7, 8, 9]), members(&[7, 8, 10])],
                members(&[7, 8, 9, 10]),
            ),
        );
        let proof = continuation(&conn);
        if missing_proof {
            conn.execute(
                "DELETE FROM session_records WHERE key_type = 'opc-scope-continuation'",
                [],
            )
            .unwrap();
        } else {
            conn.execute_batch("CREATE TEMP TRIGGER fail_scope_activation BEFORE INSERT ON session_records
                WHEN NEW.key_type = 'opc-scope-profile' BEGIN SELECT RAISE(ABORT, 'injected activation write failure'); END;").unwrap();
        }
        let before = read_membership_scope_sync(&conn, identity()).unwrap();
        let uniform = membership_entry_at(8, vec![members(&[7, 8, 10])], members(&[7, 8, 10]));
        assert!(
            apply_entries_sync(&conn, identity(), &backend.caps, vec![uniform.clone()]).is_err()
        );
        assert_eq!(
            read_membership_scope_sync(&conn, identity()).unwrap(),
            before
        );
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(7))
        );
        assert_eq!(
            super::super::scope_batch::read(
                &conn,
                &rows::profile_key(identity().cluster_id()).unwrap()
            )
            .unwrap(),
            Some(ScopeRow::Activation(certificate(0).predecessor))
        );
        if missing_proof {
            ops::insert_or_replace_scope_record_sync(
                &conn,
                &ScopeRow::Continuation(Box::new(proof)).to_record().unwrap(),
            )
            .unwrap();
        } else {
            conn.execute_batch("DROP TRIGGER fail_scope_activation")
                .unwrap();
        }
        commit(&conn, &backend.caps, uniform);
        let after = read_membership_scope_sync(&conn, identity()).unwrap();
        assert_eq!(after.current_identity, certificate(0).successor.identity);
        assert!(super::super::scope_batch::active(&conn, &after).unwrap());
    }
}
