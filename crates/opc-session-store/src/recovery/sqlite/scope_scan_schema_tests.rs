//! Derived scan indexes must compose with the existing exact recovery schemas.

use super::*;

const INDEX_NAMES: [&str; 2] = ["scope_scan_keys", "scope_scan_bad_keys"];

fn checkpoint(current: bool, indexes: bool) -> Connection {
    let conn = crate::sqlite::SqliteSessionBackend::canonical_schema_connection().unwrap();
    if current {
        consensus::install_recovery_validation_schema_sync(&conn, false).unwrap();
        conn.execute(
            "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, 1)",
            rusqlite::params![i64::from(SESSION_CONSENSUS_SCHEMA_VERSION), [0x71u8;32].as_slice(), [0x72u8;32].as_slice()],
        ).unwrap();
    }
    if !indexes {
        conn.execute_batch("DROP INDEX scope_scan_keys; DROP INDEX scope_scan_bad_keys;")
            .unwrap();
    }
    conn
}

fn inspect(conn: &Connection, current: bool) -> Result<(), RecoveryError> {
    if current {
        validate_exact_recovery_schema(conn, false)
    } else {
        validate_legacy_schema(conn)
    }
}

fn schema(conn: &Connection) -> Vec<(String, String, Option<String>)> {
    conn.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn scope_scan_schema_recovery_accepts_exact_pair_and_unindexed_layout_without_writes() {
    for current in [false, true] {
        for indexes in [false, true] {
            let conn = checkpoint(current, indexes);
            let before = schema(&conn);
            let changes = conn.total_changes();
            inspect(&conn, current).unwrap_or_else(|error| {
                panic!("exact scan index layout must remain recoverable: current={current}, indexes={indexes}: {error:?}")
            });
            assert_eq!(schema(&conn), before, "inspection cannot install indexes");
            assert_eq!(conn.total_changes(), changes);
        }
    }
}

#[test]
fn scope_scan_schema_budget_counts_only_the_exact_pair_on_main_and_attached() {
    for indexes in [false, true] {
        let conn = checkpoint(true, indexes);
        let expected = consensus::CONSENSUS_SCHEMA_MAX_OBJECTS + if indexes { 2 } else { 0 };
        assert_eq!(
            consensus::consensus_schema_max_objects_in_sync(&conn, false).unwrap(),
            expected,
            "physical schema budget must include exactly the validated scan indexes",
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scan-indexes.sqlite");
        let mut copy = Connection::open(&path).unwrap();
        Backup::new(&conn, &mut copy)
            .unwrap()
            .run_to_completion(128, Duration::ZERO, None)
            .unwrap();
        drop(copy);
        let attached = Connection::open_in_memory().unwrap();
        attached
            .execute(
                "ATTACH DATABASE ?1 AS consensus_incoming",
                [path.to_str().unwrap()],
            )
            .unwrap();
        assert_eq!(
            consensus::consensus_schema_max_objects_in_sync(&attached, true).unwrap(),
            expected,
            "attached images use the same exact physical schema budget",
        );
    }
}

fn damage_index(conn: &Connection, damage: &str) {
    let name = if matches!(damage, "prefix" | "empty-key-filter") {
        INDEX_NAMES[1]
    } else {
        INDEX_NAMES[0]
    };
    let original: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute_batch(&format!("DROP INDEX {name}")).unwrap();
    let changed = match damage {
        "partial-pair" => return,
        "wrong-kind" => format!("CREATE VIEW {name} AS SELECT 1 AS singleton"),
        "key-width" => original.replace("length(stable_id)=64", "length(stable_id)=63"),
        "key-kind" => original.replace("'opc-scope-claim'", "'opc-scope-other'"),
        "literal-case" => original.replace("'opc-scope-child'", "'OPC-SCOPE-CHILD'"),
        "literal-space" => original.replace("'opc-scope-child'", "'opc-scope- child'"),
        "prefix" => original.replace("substr(stable_id,1,32)", "substr(stable_id,1,31)"),
        "empty-key-filter" => original.replace("length(stable_id)!=64", "length(stable_id)>64"),
        "oversized-ddl" => original.replace(
            "(tenant,",
            &format!("(tenant /*{}*/,", "x".repeat(17 * 1024)),
        ),
        _ => unreachable!("fixed corruption matrix"),
    };
    assert_ne!(original, changed, "fixture must change the index DDL");
    conn.execute_batch(&changed).unwrap();
}

#[test]
fn scope_scan_schema_rejects_partial_or_tampered_pair_before_budget_admission() {
    for damage in [
        "partial-pair",
        "wrong-kind",
        "key-width",
        "key-kind",
        "literal-case",
        "literal-space",
        "prefix",
        "empty-key-filter",
        "oversized-ddl",
    ] {
        for current in [false, true] {
            let conn = checkpoint(current, true);
            damage_index(&conn, damage);
            let before = schema(&conn);
            assert!(
                consensus::consensus_schema_max_objects_in_sync(&conn, false).is_err(),
                "tampered scan index must not grant a schema allowance: {damage}",
            );
            assert!(
                matches!(inspect(&conn, current), Err(RecoveryError::CorruptReplica)),
                "recovery must refuse the damaged index definition: {damage}",
            );
            assert_eq!(schema(&conn), before, "inspection cannot repair corruption");
        }
    }
}

#[test]
fn scope_scan_schema_pair_does_not_admit_an_unrelated_object() {
    for current in [false, true] {
        for extra in [
            "CREATE VIEW scope_scan_keys_unknown AS SELECT 1 AS singleton",
            "CREATE INDEX scope_scan_keys_unknown ON session_records(tenant)",
        ] {
            let conn = checkpoint(current, true);
            inspect(&conn, current).expect("valid indexed checkpoint");
            conn.execute_batch(extra).unwrap();
            assert!(matches!(
                inspect(&conn, current),
                Err(RecoveryError::CorruptReplica)
            ));
        }
    }
}

#[test]
fn scope_scan_schema_preserves_exact_markerless_predecessor_with_or_without_indexes() {
    for indexes in [false, true] {
        let conn = checkpoint(true, indexes);
        conn.execute_batch(
            "DROP TABLE consensus_fenced_transition_receipts;
             DROP TABLE consensus_fenced_transition_activation;
             ALTER TABLE consensus_identity DROP COLUMN fenced_transition_receipt_ledger_activated;",
        ).unwrap();
        let before = schema(&conn);
        assert_eq!(
            consensus::fenced_transition_receipt_ledger_layout_sync(&conn).unwrap(),
            consensus::FencedTransitionReceiptLedgerLayout::Published684,
            "derived indexes do not redefine the frozen predecessor layout",
        );
        inspect(&conn, true).expect("exact markerless predecessor remains recoverable");
        assert_eq!(schema(&conn), before);
    }
}
