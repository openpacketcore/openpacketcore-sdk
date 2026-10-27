//! Count-free preflight remains subject to the caller's explicit work budget.
use super::*;

fn table(protocol_cap: Option<u64>) -> ProtectedRosterPreflightTable {
    ProtectedRosterPreflightTable {
        count_query: "SELECT COUNT(*) FROM (SELECT value FROM rows LIMIT ?1)",
        values_query: "SELECT COUNT(*), COALESCE(MAX(length(value)),0), COALESCE(SUM(length(value)),0) FROM (SELECT value FROM rows LIMIT ?1)",
        protocol_cap,
        protocol_max_value: ProtectedRosterValueCap::Fixed(8),
    }
}

fn budget(max_rows: u64) -> InspectionBudget {
    InspectionBudget::new(
        RecoveryLimits::try_new(16 * 1024 * 1024, 16 * 1024 * 1024, max_rows, 8).unwrap(),
    )
}

#[test]
fn roster_capacity_recovery_preflight_accepts_history_past_old_cap_with_explicit_work_budget() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE rows (value BLOB NOT NULL); WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<131073) INSERT INTO rows SELECT X'01' FROM n;").unwrap();
    let mut bytes = 0;
    preflight_protected_roster_table(&conn, &budget(131_073), &mut bytes, table(None), 8, 8)
        .unwrap();
    assert_eq!(bytes, 131_073);
    assert_eq!(
        preflight_protected_roster_table(&conn, &budget(131_072), &mut 0, table(None), 8, 8),
        Err(RecoveryError::WorkLimitExceeded)
    );
    let mut partly_used = budget(131_073);
    partly_used.rows = 1;
    assert_eq!(
        preflight_protected_roster_table(&conn, &partly_used, &mut 0, table(None), 8, 8),
        Err(RecoveryError::WorkLimitExceeded)
    );
    // Singleton cardinality and malformed field widths are still corruption,
    // not history pressure. This test certifies preflight, not row signatures.
    assert_eq!(
        preflight_protected_roster_table(&conn, &budget(131_073), &mut 0, table(Some(1)), 8, 8),
        Err(RecoveryError::CorruptReplica)
    );
    conn.execute("UPDATE rows SET value=zeroblob(9) WHERE rowid=1", [])
        .unwrap();
    assert_eq!(
        preflight_protected_roster_table(&conn, &budget(131_073), &mut 0, table(None), 8, 8),
        Err(RecoveryError::CorruptReplica)
    );
}
