use super::*;
use crate::CompareAndSet;

mod public_reads;

fn now(second: u64) -> Timestamp {
    timestamp(0)
        .add_seconds(i64::try_from(second).unwrap())
        .unwrap()
}

fn command(
    index: u64,
    intent: SessionMutationIntent,
    time: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes(
                (0xE900_0000_0000_0000u128 + u128::from(index)).to_be_bytes(),
            ),
            logical_time: time,
            intent: SessionMutationIntent::Authorized {
                origin: node_id(),
                authority_identity: identity(),
                mutation: Box::new(intent),
            },
        }),
    }
}

pub(super) fn rows(conn: &Connection, table: &str) -> Vec<Vec<String>> {
    let mut statement = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
    let columns = statement.column_count();
    let mut rows = statement
        .query_map([], |row| {
            (0..columns)
                .map(|column| {
                    row.get::<_, rusqlite::types::Value>(column)
                        .map(|value| format!("{value:?}"))
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    rows.sort();
    rows
}

fn physical_parity(wal: &Wal, oracle: &SqliteSessionBackend) {
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
    ] {
        assert_eq!(
            rows(&exported, table),
            rows(&conn, table),
            "complete physical parity for {table}"
        );
    }
    validate_lease_state_sync(&exported).unwrap();
    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
    super::roster::export::import::rootless_roundtrip(&conn);
}

fn step(fixture: &Fixture, entry: Entry<SessionRaftTypeConfig>) -> SessionConsensusResponse {
    let mut applied = fixture.parity(std::slice::from_ref(&entry));
    physical_parity(&fixture.wal, &fixture.oracle);
    applied.responses.remove(0)
}

fn lease(response: SessionConsensusResponse) -> crate::LeaseGuard {
    match response.result {
        Ok(SessionMutationOutcome::Lease(guard)) => guard,
        _ => panic!("ordinary lease outcome"),
    }
}

fn record(
    guard: &crate::LeaseGuard,
    generation: u64,
    expires_at: Option<Timestamp>,
) -> StoredSessionRecord {
    let request = sdk741_component_request(Sdk741Payload::Create, 30, 0, None);
    let mut value = request.mutation().record().unwrap().clone();
    value.key = guard.key().clone();
    value.owner = guard.owner().clone();
    value.fence = guard.fence();
    value.generation = Generation::new(generation);
    value.expires_at = expires_at;
    sdk741_seal_record(
        &mut value,
        10_000 + generation + guard.credential_id(),
        true,
    );
    value
}

fn cas(guard: &crate::LeaseGuard, expected: Option<u64>, generation: u64) -> SessionMutationIntent {
    SessionMutationIntent::CompareAndSet(Arc::new(CompareAndSet {
        key: guard.key().clone(),
        lease: guard.clone(),
        expected_generation: expected.map(Generation::new),
        new_record: record(guard, generation, None),
    }))
}

#[test]
fn native_ordinary_complete_lease_record_retry_and_selected_reopen_match_sql() {
    let fixture = Fixture::new();
    fixture.parity(&[formation()]);
    let owner = OwnerId::new("native-ordinary-owner").unwrap();
    let acquire = SessionMutationIntent::AcquireLease {
        key: key(),
        owner: owner.clone(),
        ttl: Duration::from_secs(60),
    };
    let first = lease(step(&fixture, command(1, acquire.clone(), now(1))));
    assert_eq!(first.fence().get(), 1);
    assert!(matches!(
        step(&fixture, command(2, cas(&first, None, 1), now(2))).result,
        Ok(SessionMutationOutcome::CompareAndSet(
            CompareAndSetResult::Success
        ))
    ));
    let read = command(
        3,
        SessionMutationIntent::ReadConsumerRecord { key: key() },
        now(3),
    );
    let original_read = step(&fixture, read.clone());
    assert!(
        matches!(&original_read.result,Ok(SessionMutationOutcome::ConsumerRecord(Some(value))) if value.generation.get() == 1)
    );
    let renewed = lease(step(
        &fixture,
        command(
            4,
            SessionMutationIntent::RenewLease {
                lease: first.clone(),
                ttl: Duration::from_secs(90),
            },
            now(4),
        ),
    ));
    assert_eq!(renewed.acquired_at(), first.acquired_at());
    assert_eq!(renewed.credential_id(), first.credential_id());
    assert_eq!(
        step(&fixture, command(5, cas(&first, Some(1), 2), now(5))).result,
        Err(StoreError::StaleFence)
    );
    assert!(matches!(
        step(
            &fixture,
            command(
                6,
                SessionMutationIntent::RefreshTtl {
                    lease: renewed.clone(),
                    ttl: Duration::from_secs(30)
                },
                now(6)
            )
        )
        .result,
        Ok(SessionMutationOutcome::Unit)
    ));
    assert!(
        matches!(step(&fixture,command(7,SessionMutationIntent::ReadConsumerRecord { key:key() },now(7))).result,
        Ok(SessionMutationOutcome::ConsumerRecord(Some(value))) if value.expires_at == Some(now(36)))
    );
    for index in [8, 9] {
        assert!(matches!(
            step(
                &fixture,
                command(
                    index,
                    SessionMutationIntent::DeleteFenced(renewed.clone()),
                    now(index)
                )
            )
            .result,
            Ok(SessionMutationOutcome::Unit)
        ));
    }
    assert_eq!(
        step(
            &fixture,
            command(
                10,
                SessionMutationIntent::RefreshTtl {
                    lease: renewed.clone(),
                    ttl: Duration::from_secs(30)
                },
                now(10)
            )
        )
        .result,
        Err(StoreError::NotFound)
    );
    assert!(matches!(
        step(
            &fixture,
            command(
                11,
                SessionMutationIntent::ReleaseLease(renewed.clone()),
                now(11)
            )
        )
        .result,
        Ok(SessionMutationOutcome::Unit)
    ));
    let released = rows(&fixture.oracle.conn.blocking_lock(), "leases");
    assert_eq!(
        released.len(),
        1,
        "release retains the original expiry column"
    );
    assert_eq!(
        step(
            &fixture,
            command(
                12,
                SessionMutationIntent::ReleaseLease(renewed.clone()),
                now(12)
            )
        )
        .result,
        Err(StoreError::StaleFence)
    );
    assert_eq!(
        rows(&fixture.oracle.conn.blocking_lock(), "leases"),
        released,
        "deterministic failure rolls back pruning of the released row"
    );
    let mut retry = read;
    retry.log_id = log_id(13);
    let EntryPayload::Normal(value) = &mut retry.payload else {
        unreachable!()
    };
    value.logical_time = now(20);
    assert_eq!(
        step(&fixture, retry.clone()),
        original_read,
        "retry preserves the original record, time, digest and index"
    );
    retry.log_id = log_id(14);
    let EntryPayload::Normal(value) = &mut retry.payload else {
        unreachable!()
    };
    value.intent = SessionMutationIntent::BindConsumerRequest {
        request_commitment: [0x91; 32],
    };
    assert_eq!(
        step(&fixture, retry).result,
        Err(StoreError::CasIdempotencyConflict)
    );
    assert_eq!(
        fixture
            .wal
            .with_native_read(|state| Ok(state.logical_time()))
            .unwrap(),
        Some(now(12))
    );
    step(
        &fixture,
        command(
            15,
            SessionMutationIntent::BindConsumerRequest {
                request_commitment: [0x92; 32],
            },
            now(22),
        ),
    );
    assert_eq!(
        rows(&fixture.oracle.conn.blocking_lock(), "leases"),
        released,
        "binding does not prune"
    );
    let second = lease(step(&fixture, command(16, acquire.clone(), now(23))));
    let third = lease(step(&fixture, command(17, acquire, now(24))));
    assert_eq!(
        (second.fence().get(), third.fence().get()),
        (2, 3),
        "same owner reacquires with a new global fence"
    );
    let mut other = key();
    other.stable_id = Bytes::from_static(b"ordinary-second-key")
        .try_into()
        .unwrap();
    let fourth = lease(step(
        &fixture,
        command(
            18,
            SessionMutationIntent::AcquireLease {
                key: other.clone(),
                owner: owner.clone(),
                ttl: Duration::from_secs(60),
            },
            now(25),
        ),
    ));
    assert_eq!(fourth.fence().get(), 4, "new key uses the global successor");
    let other_owner = OwnerId::new("native-ordinary-other").unwrap();
    assert_eq!(
        step(
            &fixture,
            command(
                19,
                SessionMutationIntent::AcquireLease {
                    key: key(),
                    owner: other_owner.clone(),
                    ttl: Duration::from_secs(60)
                },
                now(26)
            )
        )
        .result,
        Err(StoreError::LeaseHeld)
    );
    let forged_owner = crate::LeaseGuard::new(
        key(),
        other_owner,
        third.fence(),
        third.acquired_at(),
        third.expires_at(),
        third.credential_id(),
    );
    assert_eq!(
        step(
            &fixture,
            command(
                20,
                SessionMutationIntent::RenewLease {
                    lease: forged_owner,
                    ttl: Duration::from_secs(60)
                },
                now(27)
            )
        )
        .result,
        Err(StoreError::LeaseHeld)
    );
    let forged_time = crate::LeaseGuard::new(
        key(),
        owner.clone(),
        third.fence(),
        now(23),
        third.expires_at(),
        third.credential_id(),
    );
    assert_eq!(
        step(
            &fixture,
            command(
                21,
                SessionMutationIntent::ReleaseLease(forged_time),
                now(28)
            )
        )
        .result,
        Err(StoreError::StaleFence)
    );
    let mut missing = key();
    missing.stable_id = Bytes::from_static(b"ordinary-missing-key")
        .try_into()
        .unwrap();
    let unknown = crate::LeaseGuard::new(missing, owner, FenceToken::new(99), now(1), now(100), 99);
    assert_eq!(
        step(
            &fixture,
            command(
                22,
                SessionMutationIntent::RenewLease {
                    lease: unknown,
                    ttl: Duration::from_secs(60)
                },
                now(29)
            )
        )
        .result,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        step(
            &fixture,
            command(
                23,
                SessionMutationIntent::ReleaseLease(third.clone()),
                now(85)
            )
        )
        .result,
        Err(StoreError::StaleFence)
    );
    assert_eq!(
        step(
            &fixture,
            command(
                24,
                SessionMutationIntent::RenewLease {
                    lease: third,
                    ttl: Duration::from_secs(60)
                },
                now(86)
            )
        )
        .result,
        Err(StoreError::LeaseExpired)
    );
    fixture.wal.checkpoint().unwrap();
    let reopened = fixture.reopened();
    physical_parity(&reopened, &fixture.oracle);
    assert_eq!(
        reopened.native_log_read(0, None, Some(64)).unwrap().len(),
        25
    );
    reopened.shutdown().unwrap();
}

#[test]
fn native_ordinary_pruning_savepoint_and_same_apply_index_match_sql() {
    let mut fixture = Fixture::new();
    let initial = sdk741_component_request(Sdk741Payload::Create, 40, 0, None);
    let seeded = fixture.parity(&[formation(), activation(1, initial.clone(), now(1))]);
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &seeded.responses[1].result else {
        panic!("initial exact transition")
    };
    let guard = outcome.lease().clone();
    let mut expired = Vec::new();
    for slot in 1..=2 {
        let template = sdk741_component_request(Sdk741Payload::Create, 40, slot, None);
        let mut value = template.mutation().record().unwrap().clone();
        value.expires_at = Some(now(3));
        sdk741_seal_record(&mut value, 20_000 + slot as u64, true);
        expired.push(
            FencedTransitionV2Request::new(
                template.request_id().epoch(),
                crate::fenced_transition::FencedTransitionV2CallerNonce::from_bytes(
                    (20_000u128 + slot as u128).to_be_bytes(),
                ),
                template.lease().clone(),
                FencedTransitionMutation::create(value),
            )
            .unwrap(),
        );
    }
    fixture.parity(&[fenced_transition_v2_batch_entry(2, expired, now(2))]);
    physical_parity(&fixture.wal, &fixture.oracle);
    let before = rows(&fixture.oracle.conn.blocking_lock(), "restore_scan_state");
    let forged = crate::LeaseGuard::new(
        guard.key().clone(),
        guard.owner().clone(),
        guard.fence(),
        guard.acquired_at(),
        guard.expires_at(),
        guard.credential_id() + 100,
    );
    assert_eq!(
        step(&fixture, command(3, cas(&forged, Some(1), 2), now(5))).result,
        Err(StoreError::StaleFence)
    );
    assert_eq!(
        rows(&fixture.oracle.conn.blocking_lock(), "session_records").len(),
        3
    );
    assert_eq!(
        rows(&fixture.oracle.conn.blocking_lock(), "restore_scan_state"),
        before
    );
    let conflict = step(&fixture, command(4, cas(&guard, Some(99), 2), now(6)));
    assert!(
        matches!(conflict.result,Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict { current:Some(value) })) if value.generation.get() == 1)
    );
    let conn = fixture.oracle.conn.blocking_lock();
    assert_eq!(rows(&conn, "session_records").len(), 1);
    assert_eq!(
        conn.query_row("SELECT revision FROM restore_scan_state", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        4,
        "one sweep advances revision once for two deleted records"
    );
    assert_eq!(
        read_machine_sync(&conn, identity()).unwrap().3,
        3,
        "CAS conflict adds no notification"
    );
    drop(conn);
    // A single committed delivery exercises the delta's updated expiry index
    // before the publication proof is rebuilt from its coalesced after-images.
    let entries = [
        command(
            5,
            SessionMutationIntent::RefreshTtl {
                lease: guard.clone(),
                ttl: Duration::from_secs(2),
            },
            now(7),
        ),
        command(6, SessionMutationIntent::AdvanceLogicalTime, now(10)),
        command(
            7,
            SessionMutationIntent::AcquireLease {
                key: key(),
                owner: OwnerId::new("ordinary-sweep").unwrap(),
                ttl: Duration::from_secs(60),
            },
            now(10),
        ),
        command(
            8,
            SessionMutationIntent::ReadConsumerRecord {
                key: guard.key().clone(),
            },
            now(10),
        ),
    ];
    let applied = fixture.parity(&entries);
    assert!(matches!(
        applied.responses[3].result,
        Ok(SessionMutationOutcome::ConsumerRecord(None))
    ));
    physical_parity(&fixture.wal, &fixture.oracle);
    assert!(rows(&fixture.oracle.conn.blocking_lock(), "session_records").is_empty());
    step(&fixture, command(9, cas(&guard, None, 2), now(11)));
    step(
        &fixture,
        command(
            10,
            SessionMutationIntent::RefreshTtl {
                lease: guard.clone(),
                ttl: Duration::from_secs(2),
            },
            now(12),
        ),
    );
    fixture.wal.checkpoint().unwrap();
    fixture.wal = fixture.reopened();
    physical_parity(&fixture.wal, &fixture.oracle);
    let mut successor = key();
    successor.stable_id = Bytes::from_static(b"ordinary-cold-sweep")
        .try_into()
        .unwrap();
    step(
        &fixture,
        command(
            11,
            SessionMutationIntent::AcquireLease {
                key: successor,
                owner: OwnerId::new("ordinary-sweep").unwrap(),
                ttl: Duration::from_secs(60),
            },
            now(15),
        ),
    );
    assert!(
        rows(&fixture.oracle.conn.blocking_lock(), "session_records").is_empty(),
        "cold admission rebuilt the due-record index"
    );
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_generic_projection_reuses_preparation_and_reads_current_rows() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    initialize_schema(&conn, identity(), &expected_members()).unwrap();
    let mut expected = Vec::new();
    for index in 1_u8..=64 {
        let id = SessionConsensusRequestId::from_bytes([index; 16]);
        let digest = [index; 32];
        let response = SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::Unit),
            sequence: u64::from(index),
            digest: Some(SessionConsensusEntryDigest::from_bytes([index; 32])),
            logical_time: Some(now(u64::from(index))),
            raft_log_index: u64::from(index),
        };
        conn.execute(
            "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, response_json) VALUES (?1, ?2, ?3, ?4)",
            params![id.as_bytes().as_slice(), epoch_i64(identity()).unwrap(), digest.as_slice(), encode_json(&response).unwrap()],
        )
        .unwrap();
        expected.push((id, digest, response));
    }
    conn.flush_prepared_statement_cache();
    let selects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&selects);
    conn.authorizer(Some(move |context: rusqlite::hooks::AuthContext<'_>| {
        if matches!(context.action, rusqlite::hooks::AuthAction::Select) {
            observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        rusqlite::hooks::Authorization::Allow
    }));
    for _ in 0..4 {
        for (id, digest, response) in &expected {
            assert_eq!(
                crate::sqlite::consensus::native_snapshot::ordinary(&conn, identity(), *id)
                    .unwrap(),
                (*digest, response.clone())
            );
        }
    }
    let preparations = selects.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("native_snapshot_generic_query_preparations reads=256 prepares={preparations}");
    // A reused statement must still observe and validate the caller's current
    // transaction. No previous receipt result may survive a changed row.
    let (id, digest, response) = &expected[0];
    let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate).unwrap();
    tx.execute(
        "UPDATE consensus_request_outcomes SET response_json = ?1 WHERE request_id = ?2",
        params![b"invalid-json".as_slice(), id.as_bytes().as_slice()],
    )
    .unwrap();
    assert!(crate::sqlite::consensus::native_snapshot::ordinary(&tx, identity(), *id).is_err());
    tx.rollback().unwrap();
    assert_eq!(
        crate::sqlite::consensus::native_snapshot::ordinary(&conn, identity(), *id).unwrap(),
        (*digest, response.clone())
    );
    assert_eq!(
        preparations, 1,
        "one parameterized query serves the whole projection"
    );
}
