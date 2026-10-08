use super::*;
use crate::scope_lease::{
    ScopeClockBounds, ScopeLeaseCommand, ScopeLeaseError, ScopeLeaseId, ScopeLeaseOperation,
    ScopeLeaseRequest,
};
use crate::sqlite::consensus::scope_lease as scope_storage;

fn scoped_entry(
    storage: SessionConsensusIdentity,
    authority: SessionConsensusIdentity,
    index: u64,
) -> Entry<SessionRaftTypeConfig> {
    let scope = ScopeLeaseId::new(
        storage,
        TenantId::from_static("scope-cutover"),
        NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let request_id = SessionConsensusRequestId::from_bytes([0xAA; 16]);
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: storage,
            request_id,
            logical_time: timestamp(4),
            intent: SessionMutationIntent::Authorized {
                origin: member(7),
                authority_identity: authority,
                mutation: Box::new(SessionMutationIntent::ScopeLease(Box::new(
                    ScopeLeaseCommand {
                        request: ScopeLeaseRequest::new(
                            scope,
                            *request_id.as_bytes(),
                            0,
                            ScopeLeaseOperation::Select {
                                execution: crate::scope_lease::tests::execution(1),
                            },
                        )
                        .unwrap(),
                        bounds: ScopeClockBounds::new(timestamp(4), timestamp(4)).unwrap(),
                    },
                ))),
            },
        }),
    }
}

fn activation_entry(
    storage: SessionConsensusIdentity,
    authority: SessionConsensusIdentity,
    voters: &BTreeSet<SessionConsensusNodeId>,
    index: u64,
) -> Entry<SessionRaftTypeConfig> {
    let mut entry = scoped_entry(storage, authority, index);
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.request_id =
        SessionConsensusRequestId::from_bytes((0x1000 + u128::from(index)).to_be_bytes());
    command.intent = SessionMutationIntent::Authorized {
        origin: member(7),
        authority_identity: authority,
        mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
            crate::scope_lease::ScopeProfileActivation::new(
                authority,
                fenced_transition_voter_set_digest(authority, voters),
            ),
        ))),
    };
    entry
}

#[test]
fn scope_checkpoint_survives_ordinary_request_receipt_pruning() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    let identity = identity();
    let voters = members(&[7, 8, 9]);
    initialize_schema(&conn, identity, &voters).unwrap();
    let entry = scoped_entry(identity, identity, 2);
    let EntryPayload::Normal(command) = &entry.payload else {
        unreachable!()
    };
    let target = scope_storage::operation(&command.intent)
        .unwrap()
        .request
        .scope()
        .clone();
    let applied = apply_entries_sync(
        &conn,
        identity,
        &backend.caps,
        vec![
            membership_entry_at(0, vec![voters.clone()], voters.clone()),
            activation_entry(identity, identity, &voters, 1),
            entry,
        ],
    )
    .unwrap();
    assert!(matches!(
        applied.responses.last().unwrap().result,
        Ok(SessionMutationOutcome::ScopeLease(Ok(_)))
    ));
    let before = scope_storage::read(&conn, identity, &target).unwrap();
    assert!(before.1.is_some());
    validate_sealed_state_sync(&conn)
        .expect("a scope checkpoint has its own authority, no ordinary key fence");
    // Even a future ordinary-receipt collector that prunes the complete
    // collection must not reset selection, grant, or exact-replay floors.
    conn.execute("DELETE FROM consensus_request_outcomes", [])
        .unwrap();
    assert_eq!(
        scope_storage::read(&conn, identity, &target).unwrap(),
        before,
        "scope authority must live independently of ordinary request receipts"
    );
}

#[test]
fn scope_lease_refuses_mutation_before_scope_profile_activation() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    let identity = identity();
    let voters = members(&[7, 8, 9]);
    initialize_schema(&conn, identity, &voters).unwrap();
    let applied = apply_entries_sync(
        &conn,
        identity,
        &backend.caps,
        vec![
            membership_entry_at(0, vec![voters.clone()], voters),
            scoped_entry(identity, identity, 1),
        ],
    )
    .unwrap();
    assert!(
        !matches!(
            applied.responses.last().unwrap().result,
            Ok(SessionMutationOutcome::ScopeLease(Ok(_)))
        ),
        "scope profile 2 cannot be used before every voter supports it"
    );
}

#[test]
fn scope_lease_retries_after_sqlite_authority_cutover_without_changing_the_checkpoint() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    let before = identity();
    let after = identity_at(2, 0xE7);
    let old_members = members(&[7, 8, 9]);
    let new_members = members(&[7, 8, 9, 10, 11]);
    let transition_id = [0xE8; MEMBERSHIP_TRANSITION_ID_BYTES];
    let transition_digest = [0xE9; 32];
    initialize_schema(&conn, before, &old_members).unwrap();
    apply_entries_sync(
        &conn,
        before,
        &backend.caps,
        vec![membership_entry_at(
            0,
            vec![old_members.clone()],
            old_members.clone(),
        )],
    )
    .unwrap();
    // Stamp the request before the actual durable authority switch; only its
    // application is delayed until the successor configuration is admitted.
    let delayed = scoped_entry(before, before, 3);
    let EntryPayload::Normal(command) = &delayed.payload else {
        unreachable!()
    };
    let target = scope_storage::operation(&command.intent)
        .unwrap()
        .request
        .scope()
        .clone();
    assert_eq!(
        scope_storage::read(&conn, before, &target).unwrap(),
        (false, None)
    );
    stage_membership_scope_sync(
        &conn,
        before,
        transition_id,
        transition_digest,
        after,
        &new_members,
    )
    .unwrap();
    apply_entries_sync(
        &conn,
        before,
        &backend.caps,
        vec![
            membership_entry_at(1, vec![old_members], new_members.clone()),
            topology_entry_at(
                2,
                0xE8,
                SessionMutationIntent::MarkTopologyLearnersReady {
                    transition_id,
                    request_digest: transition_digest,
                },
            ),
        ],
    )
    .unwrap();
    fence_application_authority_sync(&conn, before, transition_id, transition_digest).unwrap();
    let rejected = apply_entries_sync(&conn, before, &backend.caps, vec![delayed]).unwrap();
    assert_eq!(
        rejected.responses[0].result,
        Ok(SessionMutationOutcome::ScopeLease(Err(
            ScopeLeaseError::Unavailable
        ))),
        "a delayed configuration stamp must be retryable, not an admission refusal"
    );
    assert_eq!(
        scope_storage::read(&conn, before, &target).unwrap(),
        (false, None),
        "a rejected stamp leaves no scope authority or replay poison"
    );
    let retry = apply_entries_sync(
        &conn,
        before,
        &backend.caps,
        vec![
            activation_entry(before, after, &new_members, 4),
            scoped_entry(before, after, 5),
        ],
    )
    .unwrap();
    let Ok(SessionMutationOutcome::ScopeLease(Ok(checkpoint))) = &retry.responses[1].result else {
        panic!("the exact request must succeed under the successor stamp")
    };
    assert_eq!(checkpoint.state().unwrap().view.revision(), 1);

    for (index, authority, origin) in [
        (6, after, member(99)),
        (
            7,
            SessionConsensusIdentity::new(
                crate::SessionConsensusClusterId::new("another-cluster").unwrap(),
                before.configuration_id(),
                before.configuration_epoch(),
            ),
            member(7),
        ),
    ] {
        let mut invalid = scoped_entry(before, authority, index);
        let EntryPayload::Normal(command) = &mut invalid.payload else {
            unreachable!()
        };
        let SessionMutationIntent::Authorized {
            origin: stamped_origin,
            ..
        } = &mut command.intent
        else {
            unreachable!()
        };
        *stamped_origin = origin;
        let rejected = apply_entries_sync(&conn, before, &backend.caps, vec![invalid]).unwrap();
        assert_eq!(
            rejected.responses[0].result,
            Ok(SessionMutationOutcome::ScopeLease(Err(
                ScopeLeaseError::Unauthorized
            )))
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn scope_lease_retries_after_native_stale_authority_stamp_without_changing_the_checkpoint() {
    let before = identity();
    let after = identity_at(2, 0xE7);
    let voters = members(&[7, 8, 9]);
    let mut native = crate::consensus::native::NativeState::empty(after, voters.clone()).unwrap();
    native
        .apply(&[
            membership_entry_at(0, vec![voters.clone()], voters.clone()),
            activation_entry(after, after, &voters, 1),
        ])
        .unwrap();
    let footprint = native.scope_checkpoint_footprint_for_test();
    let rejected = native.apply(&[scoped_entry(after, before, 2)]).unwrap();
    assert_eq!(
        rejected.responses[0].result,
        Ok(SessionMutationOutcome::ScopeLease(Err(
            ScopeLeaseError::Unavailable
        )))
    );
    assert_eq!(native.scope_checkpoint_footprint_for_test(), footprint);
    let retry = native.apply(&[scoped_entry(after, after, 3)]).unwrap();
    let Ok(SessionMutationOutcome::ScopeLease(Ok(checkpoint))) = &retry.responses[0].result else {
        panic!("the exact request must succeed under the current stamp")
    };
    assert_eq!(checkpoint.state().unwrap().view.revision(), 1);
}
