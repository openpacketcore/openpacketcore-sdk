//! Real retained target admission must stop counting at the existing byte bound.
//! This file-backed fixture uses the existing native SQLite reducer and actual
//! provider encryption. It is not a quorum, joint-profile or whole-memory test.

use super::*;
use crate::audit_authority::ledger::target_budget_probe::Observation;
use crate::audit_authority::ledger::{EntryPayload, RetainedTargetIntent, MAX_STATE_BYTES};
use crate::audit_authority::{NetconfLockDatastore, NetconfTargetReplacement};

fn stored_ledger(conn: &Connection) -> (Vec<u8>, Vec<u8>) {
    conn.query_row(
        "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

#[tokio::test]
async fn target_ledger_budget_stops_oversized_native_admission_without_partial_state() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    let provider = replacement_provider();
    let schema = opc_types::SchemaDigest::from_bytes([0x71; 32]);
    // Same individually representable payload size as the existing native
    // aggregate-refusal fixture; no new limit or altered deadline is used.
    let mut content =
        vec![b'x'; crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES / 16 * 3];
    content[0] = b'"';
    *content.last_mut().unwrap() = b'"';
    let frozen = fixture
        .frozen_target(&conn, &session, NetconfLockDatastore::Candidate)
        .unwrap();
    let mut event = fixture.event(248);
    event.operation = ManagementAuditOperationCode::Update;
    let effect = frozen
        .prepare_replacement(
            &session,
            NetconfTargetReplacement::edit(&frozen, &content, schema, &provider),
            opc_types::TenantId::from_static("fixture-tenant"),
            &event,
            160,
        )
        .await
        .unwrap();
    let first = fixture.bind_frozen_target(&frozen, effect, event);
    let first_bytes = first.encode().unwrap();
    assert_eq!(fixture.preflight(&conn, &first, 100).unwrap(), None);
    let first_state = fixture.submit(&conn, &first);
    assert!(matches!(first_state, AuditOperationState::TargetV1(_)));
    fixture.settle(&conn, &first);
    let next = fixture
        .frozen_target(&conn, &session, NetconfLockDatastore::Candidate)
        .unwrap();
    let mut event = fixture.event(249);
    event.operation = ManagementAuditOperationCode::Update;
    let effect = next
        .prepare_replacement(
            &session,
            NetconfTargetReplacement::edit(&next, &content, schema, &provider),
            opc_types::TenantId::from_static("fixture-tenant"),
            &event,
            160,
        )
        .await
        .unwrap();
    let second = fixture.bind_frozen_target(&next, effect, event);
    let second_bytes = second.encode().unwrap();
    let before_ledger = fixture.ledger(&conn);
    let before_row = stored_ledger(&conn);
    let before_targets = target_rows(&conn);
    let before_changes = conn.total_changes();
    let before_history: u64 = conn
        .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
        .unwrap();

    // Test-only compatibility oracles outside the observation prove that the
    // entries alone cross the bound, before serde reaches operations. They do
    // not manufacture a persisted row or stand in for actual ledger admission.
    let retained_entries = serde_json::to_vec(&before_ledger.entries).unwrap().len();
    let next_payload = EntryPayload::TargetIntent(Box::new(RetainedTargetIntent {
        handle: second.handle().clone(),
        recovery: String::from_utf8(second_bytes.clone()).unwrap(),
    }));
    let additional = serde_json::to_vec(&next_payload).unwrap().len();
    assert!(
        retained_entries + additional - 2 > MAX_STATE_BYTES,
        "TARGET_LEDGER_BUDGET_OVERFLOW_SETUP"
    );
    drop(next_payload);
    let observation = Observation::start();
    before_ledger.check_target_capacity().unwrap();
    assert_eq!(
        observation.sample().checks,
        1,
        "TARGET_LEDGER_BUDGET_PROBE_SETUP"
    );
    assert_eq!(
        observation.sample().operations_started,
        1,
        "TARGET_LEDGER_BUDGET_PROBE_SETUP"
    );
    drop(observation);

    let mut budget_samples = [("preflight", None), ("admit", None)];
    for (phase, captured) in &mut budget_samples {
        let observation = Observation::start();
        if *phase == "preflight" {
            assert_eq!(
                fixture.preflight(&conn, &second, 100),
                Err(AuditAuthorityError::Full),
                "TARGET_LEDGER_BUDGET_LOGICAL_FULL"
            );
        } else {
            assert_eq!(
                fixture.apply(
                    &conn,
                    AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(
                        second.clone()
                    ))),
                    100
                ),
                Err(ConfigMutationFailure::HistoryFull),
                "TARGET_LEDGER_BUDGET_LOGICAL_FULL"
            );
        }
        let sample = observation.sample();
        drop(observation);
        assert!(sample.checks > 0, "TARGET_LEDGER_BUDGET_PROBE_SETUP");
        *captured = Some(sample);
        println!("TARGET_LEDGER_BUDGET_STREAM phase={phase} checks={} completed_operations={} stopped_before_operations={}", sample.checks, sample.operations_started, sample.stopped_before_operations);
        assert_eq!(
            conn.total_changes(),
            before_changes,
            "TARGET_LEDGER_BUDGET_NO_PARTIAL_WRITE"
        );
        assert_eq!(stored_ledger(&conn), before_row);
        assert_eq!(target_rows(&conn), before_targets);
        assert!(fixture.ledger(&conn) == before_ledger);
        assert!(fixture
            .ledger(&conn)
            .lookup(&fixture.key, second.handle(), second.effect.caller)
            .unwrap()
            .is_none());
    }
    let retry = PreparedTargetMutation::decode(&second_bytes).unwrap();
    assert_eq!(retry.encode().unwrap(), second_bytes);
    assert_eq!(
        fixture.preflight(&conn, &retry, 100),
        Err(AuditAuthorityError::Full)
    );
    let original = PreparedTargetMutation::decode(&first_bytes).unwrap();
    let receipt = fixture.preflight(&conn, &original, 100).unwrap().unwrap();
    assert_eq!(receipt.state(), first_state);
    assert!(receipt.terminal_recorded());
    assert_eq!(
        before_ledger
            .recover_target(&fixture.key, original.handle(), original.effect.caller)
            .unwrap()
            .encode()
            .unwrap(),
        first_bytes
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM config_history", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        before_history
    );
    assert_eq!(stored_ledger(&conn), before_row);
    assert_eq!(target_rows(&conn), before_targets);
    assert_eq!(conn.total_changes(), before_changes);
    let reopened = Connection::open(fixture.directory.path().join("authority.sqlite")).unwrap();
    assert_eq!(stored_ledger(&reopened), before_row);
    assert_eq!(target_rows(&reopened), before_targets);
    let restored = fixture.ledger(&reopened);
    assert!(restored == before_ledger);
    assert_eq!(
        restored
            .lookup(&fixture.key, original.handle(), original.effect.caller)
            .unwrap()
            .unwrap()
            .state(),
        first_state
    );
    // Check traversal after both real refusals, unchanged native rows and the
    // exact-original retry/reopen assertions. The allocation-removal baseline
    // must reach this boundary rather than failing fixture setup or recovery.
    for (phase, captured) in budget_samples {
        let sample = captured.unwrap();
        assert!(sample.stopped_before_operations > 0, "TARGET_LEDGER_BUDGET_STREAM_CUTOFF: {phase} traversed the whole oversized row before enforcing its byte bound");
    }
}
