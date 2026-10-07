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
            membership_entry_at(1, vec![old_members], new_members),
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
        vec![scoped_entry(before, after, 4)],
    )
    .unwrap();
    let Ok(SessionMutationOutcome::ScopeLease(Ok(checkpoint))) = &retry.responses[0].result else {
        panic!("the exact request must succeed under the successor stamp")
    };
    assert_eq!(checkpoint.state().unwrap().view.revision(), 1);

    for (index, authority, origin) in [
        (5, after, member(99)),
        (
            6,
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
        .apply(&[membership_entry_at(0, vec![voters.clone()], voters)])
        .unwrap();
    let footprint = native.scope_checkpoint_footprint_for_test();
    let rejected = native.apply(&[scoped_entry(after, before, 1)]).unwrap();
    assert_eq!(
        rejected.responses[0].result,
        Ok(SessionMutationOutcome::ScopeLease(Err(
            ScopeLeaseError::Unavailable
        )))
    );
    assert_eq!(native.scope_checkpoint_footprint_for_test(), footprint);
    let retry = native.apply(&[scoped_entry(after, after, 2)]).unwrap();
    let Ok(SessionMutationOutcome::ScopeLease(Ok(checkpoint))) = &retry.responses[0].result else {
        panic!("the exact request must succeed under the current stamp")
    };
    assert_eq!(checkpoint.state().unwrap().view.revision(), 1);
}
