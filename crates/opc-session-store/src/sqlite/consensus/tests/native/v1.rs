use super::*;
use crate::{FencedTransitionRequest, FencedTransitionRequestId, FencedTransitionStatus};

fn now(second: i64) -> Timestamp {
    timestamp(0).add_seconds(second).unwrap()
}

fn request(byte: u8, slot: usize) -> FencedTransitionRequest {
    let template = sdk741_component_request(Sdk741Payload::Create, 81, slot, None);
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([byte; 16]),
        template.lease().clone(),
        template.mutation().clone(),
    )
    .unwrap()
}

fn entry(
    index: u64,
    request: &FencedTransitionRequest,
    time: Timestamp,
    activate: bool,
    authorized: bool,
) -> Entry<SessionRaftTypeConfig> {
    let intent = if activate {
        SessionMutationIntent::ActivateFencedTransition {
            request: Box::new(request.clone()),
            scope_identity: identity(),
            voter_set_digest: fenced_transition_voter_set_digest(identity(), &fixed_members()),
        }
    } else {
        SessionMutationIntent::FencedTransition(Box::new(request.clone()))
    };
    ordinary(
        index,
        *request.request_id().as_bytes(),
        intent,
        time,
        authorized,
    )
}

fn ordinary(
    index: u64,
    id: [u8; 16],
    intent: SessionMutationIntent,
    time: Timestamp,
    authorized: bool,
) -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes(id),
            logical_time: time,
            intent: SessionMutationIntent::Authorized {
                origin: if authorized {
                    node_id()
                } else {
                    SessionConsensusNodeId::new(99).unwrap()
                },
                authority_identity: identity(),
                mutation: Box::new(intent),
            },
        }),
    }
}

fn physical(wal: &Wal, oracle: &SqliteSessionBackend) {
    let exported = wal.native_export_snapshot().unwrap();
    let conn = oracle.conn.blocking_lock();
    for table in [
        "session_records",
        "leases",
        "key_fences",
        "lease_globals",
        "restore_scan_state",
        "consensus_machine",
        "consensus_applied",
        "consensus_committed",
        "consensus_membership",
        "consensus_request_outcomes",
        "session_replication_log",
        "consensus_log",
        "consensus_fenced_transition_receipts",
        "consensus_fenced_transition_activation",
    ] {
        assert_eq!(
            super::ordinary::rows(&exported, table),
            super::ordinary::rows(&conn, table),
            "complete physical V1 parity: {table}"
        );
    }
    validate_fenced_transition_receipt_storage_bounds_sync(&exported).unwrap();
    validate_fenced_transition_activation_certificate_sync(&exported, identity(), false).unwrap();
    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
    super::roster::export::import::rootless_roundtrip(&conn);
}

fn step(fixture: &Fixture, entry: Entry<SessionRaftTypeConfig>) -> SessionConsensusResponse {
    let mut applied = fixture.parity(&[entry]);
    physical(&fixture.wal, &fixture.oracle);
    applied.responses.remove(0)
}

fn status(
    wal: &Wal,
    oracle: &SqliteSessionBackend,
    request: &FencedTransitionRequest,
) -> FencedTransitionStatus {
    let actual = wal
        .with_native_read(|state| {
            state
                .status_v1(request)
                .map_err(|_| io::Error::other("native V1 status"))
        })
        .unwrap();
    let expected = read_fenced_transition_status_sync(
        &oracle.conn.blocking_lock(),
        identity(),
        identity(),
        request,
    )
    .unwrap();
    assert_eq!(actual, expected);
    actual
}

#[test]
fn native_v1_exact_replay_namespace_expiry_and_selected_reopen_match_sql() {
    let fixture = Fixture::new();
    fixture.parity(&[formation()]);
    let first = request(0xA1, 1);
    let original = step(&fixture, entry(1, &first, now(1), true, true));
    assert!(
        matches!(&original.result,Ok(SessionMutationOutcome::FencedTransition(outcome)) if outcome.matches_request(&first))
    );
    assert_eq!(
        step(&fixture, entry(2, &first, now(2), false, true)),
        original
    );
    let changed = request(0xA1, 2);
    assert_eq!(
        step(&fixture, entry(3, &changed, now(3), false, true)).result,
        Err(StoreError::FencedTransitionRequestConflict)
    );
    assert_eq!(
        step(
            &fixture,
            ordinary(
                4,
                [0xA1; 16],
                SessionMutationIntent::BindConsumerRequest {
                    request_commitment: [4; 32]
                },
                now(4),
                true
            )
        )
        .result,
        Err(StoreError::CasIdempotencyConflict)
    );
    assert_eq!(
        fixture
            .wal
            .with_native_read(|state| Ok(state.logical_time()))
            .unwrap(),
        Some(now(3)),
        "ordinary conflict leaves the machine clock unchanged"
    );
    step(
        &fixture,
        ordinary(
            5,
            [0xA2; 16],
            SessionMutationIntent::BindConsumerRequest {
                request_commitment: [5; 32],
            },
            now(5),
            true,
        ),
    );
    let generic_collision = request(0xA2, 3);
    assert_eq!(
        step(&fixture, entry(6, &generic_collision, now(6), false, true)).result,
        Err(StoreError::FencedTransitionRequestConflict)
    );
    let second = request(0xA3, 4);
    step(&fixture, entry(7, &second, now(7), false, true));
    let until = now(1)
        .add_seconds(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs() as i64)
        .unwrap();
    assert_eq!(
        step(&fixture, entry(8, &changed, until, false, true)).result,
        Err(StoreError::FencedTransitionRequestConflict)
    );
    assert_eq!(
        status(&fixture.wal, &fixture.oracle, &first),
        FencedTransitionStatus::Expired
    );
    assert_eq!(
        step(&fixture, entry(9, &first, until, false, true)).result,
        Err(StoreError::FencedTransitionRequestExpired)
    );
    let later = until.add_seconds(20).unwrap();
    step(
        &fixture,
        ordinary(
            10,
            [0xA4; 16],
            SessionMutationIntent::BindConsumerRequest {
                request_commitment: [10; 32],
            },
            later,
            true,
        ),
    );
    assert_eq!(
        status(&fixture.wal, &fixture.oracle, &second),
        FencedTransitionStatus::Expired
    );
    assert_eq!(
        status(&fixture.wal, &fixture.oracle, &generic_collision),
        FencedTransitionStatus::RequestConflict
    );
    fixture.wal.checkpoint().unwrap();
    let reopened = fixture.reopened();
    physical(&reopened, &fixture.oracle);
    assert_eq!(
        status(&reopened, &fixture.oracle, &first),
        FencedTransitionStatus::Expired
    );
    assert_eq!(
        reopened.native_log_read(0, None, Some(64)).unwrap().len(),
        11
    );
    reopened.shutdown().unwrap();
}

#[test]
fn native_v1_capability_lattice_and_revoked_receipt_precedence_match_sql() {
    let fixture = Fixture::new();
    fixture.parity(&[formation()]);
    let first = request(0xB1, 1);
    let revoked = step(&fixture, entry(1, &first, now(1), true, false));
    assert_eq!(revoked.result, Err(StoreError::TopologyAuthorityRevoked));
    assert_eq!(revoked.sequence, 0);
    assert_eq!(
        status(&fixture.wal, &fixture.oracle, &first),
        FencedTransitionStatus::NotFound
    );
    let protected = crate::consensus::types::protected_roster_profile_voter_set_digest(
        identity(),
        &fixed_members(),
    );
    for (index, voters) in [
        (2, protected),
        (
            3,
            fenced_transition_voter_set_digest(identity(), &fixed_members()),
        ),
    ] {
        let capability = SessionMutationIntent::ActivateFencedTransitionCapability {
            schema_version: FENCED_TRANSITION_SCHEMA_V1,
            scope_identity: identity(),
            voter_set_digest: voters,
        };
        assert_eq!(
            step(
                &fixture,
                ordinary(
                    index,
                    [index as u8; 16],
                    capability,
                    now(index as i64),
                    true
                )
            )
            .result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert!(fixture
            .wal
            .with_native_read(
                |state| Ok(state.v1_activation_matches(identity(), &fixed_members())
                    && state.protected_roster_activation_matches(identity(), &fixed_members()))
            )
            .unwrap());
    }
    let original = step(&fixture, entry(4, &first, now(4), true, true));
    assert!(original.result.is_ok());
    let replay = step(&fixture, entry(5, &first, now(5), false, false));
    assert_eq!(replay.result, Err(StoreError::TopologyAuthorityRevoked));
    assert_eq!(replay.sequence, original.sequence);
    let second = request(0xB2, 2);
    let bound = step(&fixture, entry(6, &second, now(6), false, false));
    assert_eq!(bound.result, Err(StoreError::TopologyAuthorityRevoked));
    assert_eq!(bound.sequence, original.sequence + 1);
    assert_eq!(
        step(&fixture, entry(7, &second, now(7), false, true)),
        bound
    );
    assert_eq!(
        status(&fixture.wal, &fixture.oracle, &second),
        FencedTransitionStatus::Recorded(Box::new(Err(StoreError::TopologyAuthorityRevoked)))
    );
    fixture.wal.checkpoint().unwrap();
    let reopened = fixture.reopened();
    physical(&reopened, &fixture.oracle);
    assert!(reopened
        .with_native_read(|state| Ok(
            state.protected_roster_activation_matches(identity(), &fixed_members())
        ))
        .unwrap());
    reopened.shutdown().unwrap();
}

#[test]
fn native_v1_renew_update_refresh_delete_and_rejected_guard_match_sql() {
    let fixture = Fixture::new();
    fixture.parity(&[formation()]);
    let first = request(0xC1, 1);
    let original = step(&fixture, entry(1, &first, now(1), true, true));
    let Ok(SessionMutationOutcome::FencedTransition(original)) = original.result else {
        panic!("V1 create");
    };
    let mut record = first.mutation().record().unwrap().clone();
    record.generation = Generation::new(2);
    sdk741_seal_record(&mut record, 83_002, true);
    let update = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0xC2; 16]),
        FencedTransitionLease::Renew {
            lease: original.lease().clone(),
            ttl: Duration::from_secs(90),
        },
        FencedTransitionMutation::Update {
            expected_generation: original.committed_generation(),
            record: Box::new(record),
        },
    )
    .unwrap();
    let updated = step(&fixture, entry(2, &update, now(2), false, true));
    let Ok(SessionMutationOutcome::FencedTransition(updated)) = updated.result else {
        panic!("V1 update");
    };
    let stale = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0xC3; 16]),
        FencedTransitionLease::Renew {
            lease: original.lease().clone(),
            ttl: Duration::from_secs(90),
        },
        FencedTransitionMutation::Delete {
            expected_generation: Generation::new(99),
        },
    )
    .unwrap();
    assert_eq!(
        step(&fixture, entry(3, &stale, now(3), false, true)).result,
        Err(StoreError::StaleFence)
    );
    let refresh = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0xC4; 16]),
        FencedTransitionLease::Renew {
            lease: updated.lease().clone(),
            ttl: Duration::from_secs(120),
        },
        FencedTransitionMutation::RefreshTtl {
            expected_generation: Generation::new(2),
            ttl: Duration::from_secs(60),
        },
    )
    .unwrap();
    let refreshed = step(&fixture, entry(4, &refresh, now(4), false, true));
    let Ok(SessionMutationOutcome::FencedTransition(refreshed)) = refreshed.result else {
        panic!("V1 TTL refresh");
    };
    assert!(refreshed.matches_request(&refresh));
    let delete = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0xC5; 16]),
        FencedTransitionLease::Renew {
            lease: refreshed.lease().clone(),
            ttl: Duration::from_secs(120),
        },
        FencedTransitionMutation::Delete {
            expected_generation: Generation::new(2),
        },
    )
    .unwrap();
    assert!(
        matches!(step(&fixture,entry(5,&delete,now(5),false,true)).result,Ok(SessionMutationOutcome::FencedTransition(outcome)) if outcome.matches_request(&delete))
    );
    assert_eq!(
        step(&fixture, entry(6, &update, now(6), false, true)).result,
        Ok(SessionMutationOutcome::FencedTransition(updated))
    );
    fixture.wal.checkpoint().unwrap();
    let reopened = fixture.reopened();
    physical(&reopened, &fixture.oracle);
    for request in [&first, &update, &stale, &refresh, &delete] {
        assert!(matches!(
            status(&reopened, &fixture.oracle, request),
            FencedTransitionStatus::Recorded(_)
        ));
    }
    reopened.shutdown().unwrap();
}
