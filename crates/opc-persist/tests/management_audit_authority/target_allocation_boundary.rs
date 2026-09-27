//! Real reservation faults at retained target adapters must remain outer I/O.
//! The thread-local probe overflows Vec::try_reserve_exact; it does not return
//! an invented audit error. All authoritative state is read from native SQLite.
use super::*;
use crate::audit_authority::ledger::allocation_probe::FailureGuard;
use crate::audit_authority::{NetconfSessionOwner, PreparedNetconfEmptyCommit};
use rusqlite::types::Value as SqlValue;
use std::{io, sync::Arc};

#[derive(Debug, PartialEq)]
struct TableRows {
    table: &'static str,
    rows: Vec<Vec<SqlValue>>,
}

fn authoritative_rows(conn: &Connection) -> Vec<TableRows> {
    [
        ("config_raft_management_audit", "singleton"),
        ("config_netconf_profile", "singleton"),
        ("config_netconf_targets", "target"),
        ("config_netconf_lifecycle", "singleton"),
        ("config_history", "version"),
    ]
    .into_iter()
    .map(|(table, order)| {
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| row.get(index))
                    .collect::<rusqlite::Result<Vec<SqlValue>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        TableRows { table, rows }
    })
    .collect()
}

struct AuthoritySnapshot {
    rows: Vec<TableRows>,
    ledger: LedgerState,
    changes: u64,
}

impl AuthoritySnapshot {
    fn capture(fixture: &Fixture, conn: &Connection) -> Self {
        Self {
            rows: authoritative_rows(conn),
            ledger: fixture.ledger(conn),
            changes: conn.total_changes(),
        }
    }

    fn assert_unchanged(&self, fixture: &Fixture, conn: &Connection) {
        assert_eq!(conn.total_changes(), self.changes, "unexpected SQL write");
        assert_eq!(authoritative_rows(conn), self.rows);
        assert!(fixture.ledger(conn) == self.ledger);
        let reopened = Connection::open(fixture.directory.path().join("authority.sqlite")).unwrap();
        assert_eq!(authoritative_rows(&reopened), self.rows);
        assert!(fixture.ledger(&reopened) == self.ledger);
    }

    fn assert_effect_rows_unchanged(&self, conn: &Connection) {
        for (actual, expected) in authoritative_rows(conn).iter().zip(&self.rows) {
            if expected.table != "config_raft_management_audit" {
                assert_eq!(
                    actual, expected,
                    "observation/retirement changed target or history"
                );
            }
        }
    }
}

// Mirror Fixture::apply's transaction policy while retaining its outer I/O
// result for inspection. This calls the production audit reducer, not a mock.
fn apply_io(
    fixture: &Fixture,
    conn: &Connection,
    command: &AuditCommand,
    now: i64,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    let tx = conn.unchecked_transaction().unwrap();
    let result = apply_sync(
        &tx,
        &fixture.key,
        fixture.identity,
        command,
        now,
        Some(&fixture.keys),
    );
    if result.is_ok() {
        tx.commit().unwrap();
    } else {
        tx.rollback().unwrap();
    }
    result
}

fn preflight_io(
    fixture: &Fixture,
    conn: &Connection,
    original: &PreparedTargetMutation,
) -> io::Result<Result<Option<AuditOperationReceipt>, AuditAuthorityError>> {
    let tx = conn.unchecked_transaction().unwrap();
    let result = crate::consensus::audit_targets::preflight_target_sync(
        &tx,
        &fixture.key,
        original,
        &fixture.ledger(&tx),
        &fixture.keys,
        100,
        &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
    );
    tx.rollback().unwrap();
    result
}

fn allocation_failure<T>(after: usize, marker: &str, run: impl FnOnce() -> io::Result<T>) {
    // No await occurs while this thread-local, RAII-reset probe is armed.
    let fault = FailureGuard::start(after);
    let result = run();
    assert!(
        fault.injected(),
        "ALLOCATION_PROBE_SETUP: {marker} after={after}"
    );
    drop(fault);
    println!("TARGET_ALLOCATION_PROBE marker={marker} after={after} injected=true");
    assert_eq!(
        result.as_ref().err().map(io::Error::kind),
        Some(io::ErrorKind::OutOfMemory),
        "{marker}: allocation failure became a deterministic authority result"
    );
}

fn command(phase: TargetAuditCommandV1) -> AuditCommand {
    AuditCommand::NetconfTarget(Box::new(phase))
}

fn assert_absent(fixture: &Fixture, conn: &Connection, original: &PreparedTargetMutation) {
    assert!(fixture
        .ledger(conn)
        .lookup(&fixture.key, original.handle(), original.effect.caller)
        .unwrap()
        .is_none());
}

fn assert_original(
    fixture: &Fixture,
    conn: &Connection,
    original: &PreparedTargetMutation,
    state: AuditOperationState,
) {
    let ledger = fixture.ledger(conn);
    assert_eq!(
        ledger
            .lookup(&fixture.key, original.handle(), original.effect.caller)
            .unwrap()
            .unwrap()
            .state(),
        state
    );
    assert!(
        ledger
            .recover_target(&fixture.key, original.handle(), original.effect.caller)
            .unwrap()
            == *original
    );
}

#[tokio::test]
async fn target_admit_allocation_fault_preserves_original() {
    // The operation index reservation and the following Intent-row reservation
    // both go through the actual target Admit adapter.
    for after in [0, 1] {
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        fixture.active(&conn);
        let original = fixture.request(&conn, 240, 2, 0x61, 0);
        let bytes = original.encode().unwrap();
        let before = AuthoritySnapshot::capture(&fixture, &conn);
        allocation_failure(after, "TARGET_ADMIT_ALLOCATION_IS_IO", || {
            apply_io(
                &fixture,
                &conn,
                &command(TargetAuditCommandV1::Admit(original.clone())),
                100,
            )
        });
        before.assert_unchanged(&fixture, &conn);
        assert_absent(&fixture, &conn, &original);

        let retry = PreparedTargetMutation::decode(&bytes).unwrap();
        assert!(retry == original);
        fixture
            .apply(
                &conn,
                command(TargetAuditCommandV1::Admit(retry.clone())),
                100,
            )
            .unwrap();
        assert_original(&fixture, &conn, &original, AuditOperationState::Intent);
        assert_eq!(fixture.ledger(&conn).sequence, before.ledger.sequence + 1);
        let admitted = authoritative_rows(&conn);
        fixture
            .apply(
                &conn,
                command(TargetAuditCommandV1::Admit(retry.clone())),
                100,
            )
            .unwrap();
        assert_eq!(
            authoritative_rows(&conn),
            admitted,
            "exact Admit duplicated rows"
        );
        assert!(matches!(
            fixture.submit(&conn, &retry),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &retry);
        let settled = authoritative_rows(&conn);
        fixture
            .apply(
                &conn,
                command(TargetAuditCommandV1::Admit(retry.clone())),
                3600,
            )
            .unwrap();
        assert_eq!(authoritative_rows(&conn), settled);
        assert_eq!(
            retry.encode().unwrap(),
            bytes,
            "retry changed original identity or expiry"
        );
    }
}

#[tokio::test]
async fn target_preflight_allocation_fault_preserves_original() {
    for after in [0, 1] {
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        fixture.active(&conn);
        let original = fixture.request(&conn, 240, 2, 0x61, 0);
        let bytes = original.encode().unwrap();
        let before = AuthoritySnapshot::capture(&fixture, &conn);
        allocation_failure(after, "TARGET_PREFLIGHT_ALLOCATION_IS_IO", || {
            preflight_io(&fixture, &conn, &original)
        });
        before.assert_unchanged(&fixture, &conn);
        assert_absent(&fixture, &conn, &original);
        let retry = PreparedTargetMutation::decode(&bytes).unwrap();
        assert!(retry == original);
        assert!(matches!(
            preflight_io(&fixture, &conn, &retry),
            Ok(Ok(None))
        ));
        before.assert_unchanged(&fixture, &conn);
        assert!(matches!(
            fixture.submit(&conn, &retry),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &retry);
        assert_eq!(retry.encode().unwrap(), bytes);
    }
}

fn stale_cleanup(
    fixture: &Fixture,
    conn: &Connection,
) -> (Arc<()>, NetconfSessionOwner, PreparedTargetMutation) {
    fixture.active(conn);
    let worker = Arc::new(());
    let winner = fixture.session_owner(conn, &worker, 0x61);
    let owner = fixture.session_owner(conn, &worker, 0x62);
    winner.invalidate();
    owner.invalidate();
    let first = winner
        .retain_cleanup(fixture.cleanup_at(conn, &winner, 241, 100))
        .unwrap();
    let original = owner
        .retain_cleanup(fixture.cleanup_at(conn, &owner, 242, 100))
        .unwrap();
    assert!(matches!(
        fixture.submit(conn, &first),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(conn, &first);
    assert_eq!(
        fixture.preflight(conn, &original, 100),
        Err(AuditAuthorityError::BindingMismatch),
        "RETIREMENT_SETUP: original must be stale through a real prior cleanup"
    );
    (worker, owner, original)
}

async fn retirement_fault(after: usize, acknowledged: bool) {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let (_worker, owner, original) = stale_cleanup(&fixture, &conn);
    let bytes = original.encode().unwrap();
    if acknowledged {
        // An earlier preflight could have raced the other cleanup. A real
        // acknowledged Intent remains owned when retirement's outcome reserve fails.
        fixture
            .apply(
                &conn,
                command(TargetAuditCommandV1::Admit(original.clone())),
                100,
            )
            .unwrap();
        fixture.checkpoint(&conn);
        assert_original(&fixture, &conn, &original, AuditOperationState::Intent);
    } else {
        assert_absent(&fixture, &conn, &original);
    }
    let before = AuthoritySnapshot::capture(&fixture, &conn);
    let marker = if acknowledged {
        "TARGET_ACKNOWLEDGED_RETIREMENT_ALLOCATION_IS_IO"
    } else {
        "TARGET_RETIREMENT_ALLOCATION_IS_IO"
    };
    allocation_failure(after, marker, || {
        apply_io(
            &fixture,
            &conn,
            &command(TargetAuditCommandV1::RetireCleanup(original.clone())),
            100,
        )
    });
    before.assert_unchanged(&fixture, &conn);
    if acknowledged {
        assert_original(&fixture, &conn, &original, AuditOperationState::Intent);
    } else {
        assert_absent(&fixture, &conn, &original);
    }
    let retry = PreparedTargetMutation::decode(&bytes).unwrap();
    assert!(retry == original);
    fixture
        .apply(
            &conn,
            command(TargetAuditCommandV1::RetireCleanup(retry.clone())),
            100,
        )
        .unwrap();
    assert_original(&fixture, &conn, &original, AuditOperationState::Rejected);
    assert_eq!(
        fixture.ledger(&conn).sequence,
        before.ledger.sequence + if acknowledged { 1 } else { 2 }
    );
    before.assert_effect_rows_unchanged(&conn);
    fixture.settle(&conn, &retry);
    retry
        .verify_settled_cleanup_retirement(&owner, &fixture.ledger(&conn), &fixture.key, 110)
        .unwrap();
    let settled = authoritative_rows(&conn);
    fixture
        .apply(
            &conn,
            command(TargetAuditCommandV1::RetireCleanup(retry.clone())),
            3600,
        )
        .unwrap();
    assert_eq!(
        authoritative_rows(&conn),
        settled,
        "retirement replay duplicated rows"
    );
    assert_eq!(retry.encode().unwrap(), bytes);
}

#[tokio::test]
async fn target_retirement_allocation_fault_preserves_original() {
    // New operation, Intent, then Rejected: failing after the candidate has
    // appended Intent must still leave no partial authoritative admission.
    for after in [0, 1, 2] {
        retirement_fault(after, false).await;
    }
}

#[tokio::test]
async fn target_acknowledged_retirement_allocation_fault_preserves_intent() {
    retirement_fault(0, true).await;
}

#[tokio::test]
async fn target_empty_commit_allocation_fault_preserves_original() {
    for after in [0, 1] {
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        fixture.active(&conn);
        let worker = Arc::new(());
        let owner = fixture.session_owner(&conn, &worker, 0x61);
        let frozen = fixture.frozen_empty_commit(&conn, &owner).unwrap();
        let original = fixture.prepare_empty_commit(&frozen, &owner, 240);
        let bytes = original.encode().unwrap();
        let before = AuthoritySnapshot::capture(&fixture, &conn);
        allocation_failure(after, "TARGET_EMPTY_COMMIT_ALLOCATION_IS_IO", || {
            apply_io(
                &fixture,
                &conn,
                &command(TargetAuditCommandV1::EmptyCommit(original.clone())),
                100,
            )
        });
        before.assert_unchanged(&fixture, &conn);
        assert!(fixture
            .ledger(&conn)
            .lookup_empty_commit(&fixture.key, &original, owner.caller)
            .unwrap()
            .is_none());
        let retry = PreparedNetconfEmptyCommit::decode(&bytes).unwrap();
        assert!(retry == original);
        fixture.observe_empty_commit(&conn, &retry, 100).unwrap();
        let ledger = fixture.ledger(&conn);
        let receipt = ledger
            .lookup_empty_commit(&fixture.key, &original, owner.caller)
            .unwrap()
            .unwrap();
        assert_eq!(
            receipt.state(),
            AuditOperationState::Observed {
                outcome: ManagementAuditOutcomeCode::Success,
            }
        );
        assert!(receipt.terminal_recorded());
        assert_eq!(ledger.sequence, before.ledger.sequence + 1);
        before.assert_effect_rows_unchanged(&conn);
        fixture.checkpoint(&conn);
        let observed = authoritative_rows(&conn);
        fixture.observe_empty_commit(&conn, &retry, 3600).unwrap();
        assert_eq!(authoritative_rows(&conn), observed);
        assert_eq!(retry.encode().unwrap(), bytes);
    }
}

fn fill_operations(fixture: &Fixture, conn: &Connection) {
    let worker = Arc::new(());
    let owner = fixture.session_owner(conn, &worker, 0x69);
    let frozen = fixture.frozen_empty_commit(conn, &owner).unwrap();
    let ledger = fixture.ledger(conn);
    let remaining = ledger.limits.max_operations - ledger.operations.len();
    for index in 0..remaining {
        let request = 100 + u8::try_from(index).unwrap();
        let observed = fixture.prepare_empty_commit(&frozen, &owner, request);
        fixture.observe_empty_commit(conn, &observed, 100).unwrap();
    }
    fixture.checkpoint(conn);
    let full = fixture.ledger(conn);
    assert_eq!(full.operations.len(), full.limits.max_operations);
    assert!(full.used_capacity().unwrap() < full.limits.max_events);
    assert!(full.operations.iter().all(|operation| {
        operation.terminal_recorded && !full.mutation_outcome_needs_checkpoint(operation)
    }));
}

fn full_apply(fixture: &Fixture, conn: &Connection, original: &AuditCommand, marker: &str) {
    let before = AuthoritySnapshot::capture(fixture, conn);
    for _ in 0..2 {
        let fault = FailureGuard::start(0);
        let result = apply_io(fixture, conn, original, 100);
        assert!(
            !fault.injected(),
            "FULL_SETUP: logical bound reached allocation"
        );
        drop(fault);
        assert!(
            matches!(result, Ok(Err(ConfigMutationFailure::HistoryFull))),
            "{marker}: real ledger Full must remain deterministic; actual={result:?}"
        );
        before.assert_unchanged(fixture, conn);
    }
}

#[tokio::test]
async fn target_admit_logical_full_is_deterministic() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let original = fixture.request(&conn, 240, 2, 0x61, 0);
    fill_operations(&fixture, &conn);
    full_apply(
        &fixture,
        &conn,
        &command(TargetAuditCommandV1::Admit(original.clone())),
        "TARGET_ADMIT_FULL_IS_DETERMINISTIC",
    );
    assert_absent(&fixture, &conn, &original);
}

#[tokio::test]
async fn target_preflight_logical_full_is_deterministic() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let original = fixture.request(&conn, 240, 2, 0x61, 0);
    fill_operations(&fixture, &conn);
    let before = AuthoritySnapshot::capture(&fixture, &conn);
    for _ in 0..2 {
        let fault = FailureGuard::start(0);
        let result = preflight_io(&fixture, &conn, &original);
        assert!(
            !fault.injected(),
            "FULL_SETUP: preflight bound reached allocation"
        );
        drop(fault);
        assert!(
            matches!(result, Ok(Err(AuditAuthorityError::Full))),
            "TARGET_PREFLIGHT_FULL_IS_DETERMINISTIC: real Full became I/O"
        );
        before.assert_unchanged(&fixture, &conn);
    }
    assert_absent(&fixture, &conn, &original);
}

#[tokio::test]
async fn target_retirement_logical_full_is_deterministic() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let (_worker, _owner, original) = stale_cleanup(&fixture, &conn);
    fill_operations(&fixture, &conn);
    full_apply(
        &fixture,
        &conn,
        &command(TargetAuditCommandV1::RetireCleanup(original.clone())),
        "TARGET_RETIREMENT_FULL_IS_DETERMINISTIC",
    );
    assert_absent(&fixture, &conn, &original);
}

#[tokio::test]
async fn target_empty_commit_logical_full_is_deterministic() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = Arc::new(());
    let owner = fixture.session_owner(&conn, &worker, 0x61);
    let frozen = fixture.frozen_empty_commit(&conn, &owner).unwrap();
    let original = fixture.prepare_empty_commit(&frozen, &owner, 240);
    fill_operations(&fixture, &conn);
    full_apply(
        &fixture,
        &conn,
        &command(TargetAuditCommandV1::EmptyCommit(original.clone())),
        "TARGET_EMPTY_COMMIT_FULL_IS_DETERMINISTIC",
    );
    assert!(fixture
        .ledger(&conn)
        .lookup_empty_commit(&fixture.key, &original, owner.caller)
        .unwrap()
        .is_none());
}
