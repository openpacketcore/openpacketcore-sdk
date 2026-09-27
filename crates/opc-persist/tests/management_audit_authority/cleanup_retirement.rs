//! Serialized retirement adversaries using the real encrypted native authority
//! transaction, signed preparations and retained ledger. No lifecycle SQL writes.
use super::*;
use crate::audit_authority::{AuditCaller, NetconfSessionOwner};

fn stale_cleanup(
    fixture: &Fixture,
    conn: &Connection,
) -> (
    std::sync::Arc<()>,
    NetconfSessionOwner,
    PreparedTargetMutation,
) {
    fixture.active(conn);
    let worker = std::sync::Arc::new(());
    let first = fixture.session_owner(conn, &worker, 0x61);
    let second = fixture.session_owner(conn, &worker, 0x62);
    first.invalidate();
    second.invalidate();
    let a = first
        .retain_cleanup(fixture.cleanup_at(conn, &first, 210, 100))
        .unwrap();
    let b = second
        .retain_cleanup(fixture.cleanup_at(conn, &second, 211, 100))
        .unwrap();
    assert!(matches!(
        fixture.submit(conn, &a),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(conn, &a);
    (worker, second, b)
}

fn retire(
    fixture: &Fixture,
    conn: &Connection,
    prepared: &PreparedTargetMutation,
    now: i64,
) -> Result<(), ConfigMutationFailure> {
    fixture.apply(
        conn,
        AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::RetireCleanup(
            prepared.clone(),
        ))),
        now,
    )
}

#[tokio::test]
async fn cleanup_retirement_durable_original_blocks_delayed_admit_and_apply() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let (_worker, session, original) = stale_cleanup(&fixture, &conn);
    let rows = target_rows(&conn);
    let sequence = fixture.ledger(&conn).sequence;
    assert!(fixture
        .ledger(&conn)
        .lookup(&fixture.key, original.handle(), session.caller)
        .unwrap()
        .is_none());
    retire(&fixture, &conn, &original, 100).unwrap();
    let ledger = fixture.ledger(&conn);
    let receipt = ledger
        .lookup(&fixture.key, original.handle(), session.caller)
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.state(),
        AuditOperationState::Rejected,
        "RETIREMENT_REAL_REJECTED"
    );
    assert!(!receipt.terminal_recorded());
    assert_eq!(
        ledger.sequence,
        sequence + 2,
        "RETIREMENT_REAL_INTENT_AND_OUTCOME"
    );
    assert_eq!(
        ledger
            .recover_target(&fixture.key, original.handle(), session.caller)
            .unwrap(),
        original
    );
    assert_eq!(target_rows(&conn), rows, "RETIREMENT_HAS_NO_TARGET_EFFECT");
    for phase in [
        TargetAuditCommandV1::Admit(original.clone()),
        TargetAuditCommandV1::Apply(original.clone()),
    ] {
        // Even a command that was already in flight before retirement uses the
        // same serial transition and authentic result producer afterwards.
        let _ = fixture.apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(phase.clone())),
            100,
        );
        let tx = conn.unchecked_transaction().unwrap();
        let proof = crate::consensus::audit::applied_receipt_sync(
            &tx,
            &fixture.key,
            fixture.identity,
            &crate::consensus::ConfigMutationIntent::ManagementAudit(Box::new(
                AuditCommand::NetconfTarget(Box::new(phase.clone())),
            )),
        )
        .unwrap()
        .unwrap();
        let replay = phase
            .read_back_receipt(&proof, &fixture.key, fixture.identity, session.caller)
            .unwrap();
        assert_eq!(
            replay.state(),
            AuditOperationState::Rejected,
            "RETIREMENT_LATE_PHASE_NEVER_REVIVES"
        );
        tx.commit().unwrap();
        assert!(fixture.ledger(&conn) == ledger);
        assert_eq!(target_rows(&conn), rows);
    }
    fixture.settle(&conn, &original);
    let before = fixture.ledger(&conn);
    retire(&fixture, &conn, &original, 3600).unwrap();
    assert!(
        fixture.ledger(&conn) == before,
        "RETIREMENT_KNOWN_BEFORE_EXPIRY"
    );
    let reopened = Connection::open(fixture.directory.path().join("authority.sqlite")).unwrap();
    assert!(fixture.ledger(&reopened) == before);
}

#[tokio::test]
async fn cleanup_retirement_authenticates_closed_signed_payload_inside_transaction() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let (_worker, _session, original) = stale_cleanup(&fixture, &conn);
    let rows = target_rows(&conn);
    let ledger = fixture.ledger(&conn);
    let mut forged = original.clone();
    forged.effect.resolution = Some(TargetResolutionV1::EndSession {
        session: [0x63; 16],
    });
    let mut foreign_caller = original.clone();
    foreign_caller.effect.caller =
        AuditCaller::project(&fixture.privacy, "other", "other").unwrap();
    let mut event = original.handle.body.event.clone();
    event.transport = ManagementAuditTransportCode::NetconfSsh;
    let signed_wrong_transport = fixture.prepare(original.effect.clone(), event);
    // This valid general target signature is deliberately not the closed
    // Internal Exec cleanup authority. Ordinary codec/admit checks accept its
    // signature; retirement must authenticate its narrower action context.
    signed_wrong_transport.verify_effect(&fixture.key).unwrap();
    for wrong in [forged, foreign_caller, signed_wrong_transport] {
        assert!(
            retire(&fixture, &conn, &wrong, 100).is_err(),
            "RETIREMENT_DURABLE_CLOSED_AUTHORITY"
        );
        assert!(fixture.ledger(&conn) == ledger);
        assert_eq!(target_rows(&conn), rows);
    }
}

#[tokio::test]
async fn cleanup_retirement_preserves_apply_winner_before_expiry_and_debt_checks() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    session.invalidate();
    let original = session
        .retain_cleanup(fixture.cleanup_at(&conn, &session, 212, 100))
        .unwrap();
    // Apply wins the consensus serialization order; terminal/checkpoint remains
    // outstanding and retirement is deliberately replayed after original expiry.
    let known = fixture.submit(&conn, &original);
    assert!(matches!(known, AuditOperationState::TargetV1(_)));
    let rows = target_rows(&conn);
    let ledger = fixture.ledger(&conn);
    let retired = retire(&fixture, &conn, &original, 3600);
    assert!(retired.is_ok(), "RETIREMENT_APPLIED_PRECEDENCE");
    assert!(fixture.ledger(&conn) == ledger);
    assert_eq!(target_rows(&conn), rows);
    assert_eq!(
        ledger
            .lookup(&fixture.key, original.handle(), session.caller)
            .unwrap()
            .unwrap()
            .state(),
        known
    );
}

#[tokio::test]
async fn cleanup_retirement_successor_requires_checkpoint_and_caps_original_window() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let (_worker, session, original) = stale_cleanup(&fixture, &conn);
    assert!(original
        .verify_settled_cleanup_retirement(&session, &fixture.ledger(&conn), &fixture.key, 110)
        .is_err());
    retire(&fixture, &conn, &original, 100).unwrap();
    assert_eq!(
        original.verify_settled_cleanup_retirement(
            &session,
            &fixture.ledger(&conn),
            &fixture.key,
            110
        ),
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
            110
        ),
        Err(AuditAuthorityError::RecoveryRequired),
        "RETIREMENT_SUCCESSOR_CHECKPOINT"
    );
    fixture.checkpoint(&conn);
    let ledger = fixture.ledger(&conn);
    assert_eq!(
        original.verify_settled_cleanup_retirement(&session, &ledger, &fixture.key, 110),
        Ok(())
    );
    assert_eq!(
        original.verify_settled_cleanup_retirement(&session, &ledger, &fixture.key, 160),
        Err(AuditAuthorityError::Expired),
        "RETIREMENT_CANNOT_RENEW_EXPIRED_WINDOW"
    );
    let renewed = fixture.cleanup_at(&conn, &session, 213, 110);
    assert!(
        session
            .retain_retirement_successor(&original, renewed, &ledger, &fixture.key, 110)
            .is_err(),
        "RETIREMENT_SUCCESSOR_FIXED_EXPIRY"
    );
    let event = fixture.device_event(214);
    let effect = fixture
        .device_view(&conn)
        .prepare_session_cleanup(&session, &event, original.handle.body.expires_at)
        .unwrap();
    let mut shorter = fixture.prepare(effect, event.clone());
    shorter.handle.body.issued_at = 110;
    shorter = fixture.bind_current_base(&conn, shorter);
    let selected = session
        .retain_retirement_successor(&original, shorter, &ledger, &fixture.key, 110)
        .unwrap();
    assert_eq!(
        selected.handle.body.expires_at,
        original.handle.body.expires_at
    );
    assert_eq!(
        session.retirement_successor(&original, &event).unwrap(),
        Some(selected.clone())
    );
    assert!(
        fixture.ledger(&conn) == ledger,
        "successor preparation must not admit work"
    );
    assert!(matches!(
        fixture.submit_at(&conn, &selected, 110),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &selected);
}
