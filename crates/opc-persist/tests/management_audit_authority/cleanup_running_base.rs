//! A real ordinary Running commit can stale cleanup without changing lifecycle.
//! All state changes use the existing authenticated native reducers.
use super::*;

fn commit_ordinary(fixture: &Fixture, conn: &Connection, request: u8) {
    let prepared = fixture.ordinary_running(conn, request);
    fixture.admit_ordinary(conn, &prepared);
    assert!(matches!(
        fixture.apply_ordinary(conn, &prepared),
        Ok(Ok(()))
    ));
    let receipt = fixture
        .ledger(conn)
        .lookup(
            &fixture.key,
            prepared.handle(),
            prepared.handle().body.binding.caller,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed {
            version: prepared.handle().body.binding.base_version + 1,
        }
    );
    fixture
        .apply(conn, AuditCommand::Terminal(prepared.handle().clone()), 100)
        .unwrap();
    fixture.checkpoint(conn);
    let ledger = fixture.ledger(conn);
    assert!(ledger.operations.iter().all(|operation| {
        operation.terminal_recorded && !ledger.mutation_outcome_needs_checkpoint(operation)
    }));
}

fn running_head(conn: &Connection) -> (Vec<u8>, u64, Vec<u8>, u64) {
    conn.query_row(
        "SELECT tx_id,version,encrypted_blob,(SELECT COUNT(*) FROM config_history) \
         FROM config_history ORDER BY version DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .unwrap()
}

#[tokio::test]
async fn cleanup_retirement_running_base_only_requires_real_rejection_and_settlement() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    commit_ordinary(&fixture, &conn, 221);

    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    session.invalidate();
    let original = session
        .retain_cleanup(fixture.cleanup_at(&conn, &session, 222, 100))
        .unwrap();
    assert_eq!(original.handle.body.binding.base_version, 1);
    let TargetExpectationV1::Lifecycle { state_digest } = &original.effect.destination else {
        panic!("signed cleanup must retain a lifecycle expectation")
    };
    let rows = target_rows(&conn);
    let profile = row(&conn, "config_netconf_profile", "singleton", 1);
    assert_eq!(
        profile["state_digest"],
        serde_json::to_value(state_digest).unwrap()
    );
    assert!(fixture
        .ledger(&conn)
        .lookup(&fixture.key, original.handle(), session.caller)
        .unwrap()
        .is_none());

    commit_ordinary(&fixture, &conn, 223);
    let head = running_head(&conn);
    assert_eq!((head.1, head.3), (2, 2));
    assert_eq!(
        target_rows(&conn),
        rows,
        "RUNNING_BASE_ONLY: ordinary commit must preserve every authenticated target row"
    );
    assert_eq!(
        row(&conn, "config_netconf_profile", "singleton", 1)["state_digest"],
        serde_json::to_value(state_digest).unwrap()
    );
    let before = fixture.ledger(&conn);
    assert!(before.operations.iter().all(|operation| {
        operation.terminal_recorded && !before.mutation_outcome_needs_checkpoint(operation)
    }));
    // Raw consensus Admit only reserves the ledger. Exercise the real current-
    // history preflight in Fixture::preflight's explicit transaction instead;
    // that helper verifies total_changes, authenticated ledger and target rows.
    assert_eq!(
        fixture.preflight(&conn, &original, 100),
        Err(AuditAuthorityError::BindingMismatch),
        "RUNNING_BASE_PREFLIGHT_REFUSAL: the stale base must refuse without admission"
    );
    assert!(fixture.ledger(&conn) == before);
    assert_eq!(target_rows(&conn), rows);
    assert_eq!(running_head(&conn), head);
    println!("CLEANUP_RUNNING_BASE_REDUCER_PRECONDITION base=1 current=2 lifecycle_unchanged=true original_absent=true competing_debt=false normal_preflight_refused=true");

    let retired = fixture.apply(
        &conn,
        AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::RetireCleanup(
            original.clone(),
        ))),
        100,
    );
    assert!(retired.is_ok(),
        "CLEANUP_RUNNING_BASE_REDUCER_RETIREMENT: authenticated running-base mismatch must independently permit retirement; actual={retired:?}");
    let ledger = fixture.ledger(&conn);
    let receipt = ledger
        .lookup(&fixture.key, original.handle(), session.caller)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state(), AuditOperationState::Rejected);
    assert!(!receipt.terminal_recorded());
    assert_eq!(ledger.sequence, before.sequence + 2);
    assert!(
        ledger
            .recover_target(&fixture.key, original.handle(), session.caller)
            .unwrap()
            == original
    );
    assert_eq!(target_rows(&conn), rows);
    assert_eq!(running_head(&conn), head);
    assert_eq!(
        original.verify_settled_cleanup_retirement(&session, &ledger, &fixture.key, 110),
        Err(AuditAuthorityError::RecoveryRequired)
    );
    fixture
        .apply(&conn, AuditCommand::Terminal(original.handle.clone()), 100)
        .unwrap();
    assert_eq!(
        original.verify_settled_cleanup_retirement(
            &session,
            &fixture.ledger(&conn),
            &fixture.key,
            110,
        ),
        Err(AuditAuthorityError::RecoveryRequired),
        "RUNNING_BASE_RETIREMENT_NEEDS_CHECKPOINT"
    );
    fixture.checkpoint(&conn);
    let ledger = fixture.ledger(&conn);
    original
        .verify_settled_cleanup_retirement(&session, &ledger, &fixture.key, 110)
        .unwrap();

    let event = fixture.device_event(224);
    let effect = fixture
        .device_view(&conn)
        .prepare_session_cleanup(&session, &event, original.handle.body.expires_at)
        .unwrap();
    let mut next = fixture.prepare(effect, event);
    next.handle.body.issued_at = 110;
    let next = fixture.bind_current_base(&conn, next);
    let next = session
        .retain_retirement_successor(&original, next, &ledger, &fixture.key, 110)
        .unwrap();
    assert!(next.handle != original.handle);
    assert!(next.effect.destination == original.effect.destination);
    assert_eq!(next.handle.body.binding.base_version, 2);
    assert_eq!(next.handle.body.expires_at, original.handle.body.expires_at);
    assert!(fixture.ledger(&conn) == ledger);
    assert!(matches!(
        fixture.submit_at(&conn, &next, 110),
        AuditOperationState::TargetV1(result)
            if matches!(result.outcome(), NetconfAppliedOutcome::Lifecycle { .. })
    ));
    fixture.settle(&conn, &next);
    let final_ledger = fixture.ledger(&conn);
    assert!(final_ledger.operations.iter().all(|operation| {
        operation.terminal_recorded && !final_ledger.mutation_outcome_needs_checkpoint(operation)
    }));
    assert_ne!(target_rows(&conn), rows);
    assert_eq!(running_head(&conn), head);
    // A real original stays known even after the original closing window and
    // the successor's lifecycle change; retirement never replaces its identity.
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::RetireCleanup(original))),
            3600,
        )
        .unwrap();
    assert!(fixture.ledger(&conn) == final_ledger);
    println!("CLEANUP_RUNNING_BASE_REDUCER_COMPLETE predecessor_rejected=true terminal_checkpoint=true successor_fixed_expiry=true successor_applied=true running_unchanged=true original_replayed_after_expiry=true");
}
