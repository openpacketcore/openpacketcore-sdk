//! Bounded, read-only pre-upgrade audit for persisted session identities.
//!
//! The audit opens an existing SQLite database read-only, scans one consistent
//! snapshot with caller-supplied work budgets, and reports counts only. It does
//! not create tables, modify rows, locate sensitive values, or repair state.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    OwnerId, ReplicationEntry, ReplicationTxId, SessionKeyType, OWNER_ID_MAX_BYTES,
    REPLICATION_TX_ID_MAX_BYTES, SESSION_KEY_TYPE_MAX_BYTES, STABLE_ID_MAX_BYTES,
    STABLE_ID_MIN_BYTES,
};

/// Version of the count-only SQLite identity-audit report.
pub const SQLITE_IDENTITY_AUDIT_REPORT_VERSION: u32 = 3;

/// Fixed number of SQLite rows requested by each bounded audit page.
pub const SQLITE_IDENTITY_AUDIT_PAGE_ROWS: u32 = 256;

const SQLITE_AUDIT_BUSY_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Deserialize)]
struct ReplicationTxIdProbe {
    tx_id: ReplicationTxId,
}

// Struct deserialization streams the bounded source, rejects a duplicate
// `tx_id`, and ignores unrelated fields. The strict decode below owns every
// other field/cardinality violation.
fn probe_replication_tx_id(encoded: &str) -> Option<ReplicationTxId> {
    serde_json::from_str::<ReplicationTxIdProbe>(encoded)
        .ok()
        .map(|probe| probe.tx_id)
}

/// Caller-approved work limits for one SQLite identity audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SqliteIdentityAuditLimits {
    max_rows: u64,
    max_entry_json_bytes: u64,
    max_total_json_bytes: u64,
}

impl SqliteIdentityAuditLimits {
    /// Validate explicit non-zero work limits.
    ///
    /// `max_entry_json_bytes` cannot exceed `max_total_json_bytes` or SQLite's
    /// signed length range. Exhausting any limit produces an incomplete
    /// report, never a partial success.
    pub fn try_new(
        max_rows: u64,
        max_entry_json_bytes: u64,
        max_total_json_bytes: u64,
    ) -> Result<Self, SqliteIdentityAuditError> {
        if max_rows == 0
            || max_entry_json_bytes == 0
            || max_total_json_bytes == 0
            || max_entry_json_bytes > max_total_json_bytes
            || max_entry_json_bytes > i64::MAX as u64
        {
            return Err(SqliteIdentityAuditError::InvalidLimits);
        }
        Ok(Self {
            max_rows,
            max_entry_json_bytes,
            max_total_json_bytes,
        })
    }

    /// Maximum total rows that may be inspected across all audited tables.
    pub const fn max_rows(self) -> u64 {
        self.max_rows
    }

    /// Maximum encoded bytes accepted for one replication-log JSON entry.
    pub const fn max_entry_json_bytes(self) -> u64 {
        self.max_entry_json_bytes
    }

    /// Maximum cumulative replication-log JSON bytes decoded by the audit.
    pub const fn max_total_json_bytes(self) -> u64 {
        self.max_total_json_bytes
    }
}

/// Overall result of a SQLite identity audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SqliteIdentityAuditStatus {
    /// Every row was inspected within budget and all values were valid.
    Compliant,
    /// Every row was inspected within budget and one or more values failed.
    ViolationsFound,
    /// The audit could not inspect the complete snapshot within its contract.
    Incomplete,
}

/// Bounded reason that a SQLite identity audit could not finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SqliteIdentityAuditIncompleteReason {
    /// More rows existed than the caller-approved row budget.
    RowBudgetExceeded,
    /// One replication entry exceeded the caller-approved per-entry budget.
    EntryJsonBudgetExceeded,
    /// Replication entries exceeded the caller-approved cumulative JSON budget.
    TotalJsonBudgetExceeded,
    /// The database did not contain the expected session-store schema.
    UnsupportedSchema,
    /// SQLite could not complete a bounded read.
    DatabaseReadFailed,
    /// A report counter could not be represented.
    CounterOverflow,
}

/// Number of rows fully inspected in each SQLite table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SqliteIdentityAuditScannedCounts {
    session_records: u64,
    leases: u64,
    key_fences: u64,
    replication_entries: u64,
}

impl SqliteIdentityAuditScannedCounts {
    /// Fully inspected `session_records` rows.
    pub const fn session_records(self) -> u64 {
        self.session_records
    }

    /// Fully inspected `leases` rows.
    pub const fn leases(self) -> u64 {
        self.leases
    }

    /// Fully inspected `key_fences` rows.
    pub const fn key_fences(self) -> u64 {
        self.key_fences
    }

    /// Fully inspected `session_replication_log` rows.
    pub const fn replication_entries(self) -> u64 {
        self.replication_entries
    }
}

/// Count-only invariant failures found by a complete or partial audit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SqliteIdentityAuditViolationCounts {
    invalid_owner_fields: u64,
    invalid_session_key_type_fields: u64,
    invalid_stable_id_fields: u64,
    invalid_replication_tx_id_fields: u64,
    invalid_replication_entries: u64,
}

impl SqliteIdentityAuditViolationCounts {
    /// Invalid owner fields in relational session or lease rows.
    pub const fn invalid_owner_fields(self) -> u64 {
        self.invalid_owner_fields
    }

    /// Invalid session-key type fields in relational rows.
    pub const fn invalid_session_key_type_fields(self) -> u64 {
        self.invalid_session_key_type_fields
    }

    /// Empty, oversized, or non-BLOB stable identifiers in relational rows.
    pub const fn invalid_stable_id_fields(self) -> u64 {
        self.invalid_stable_id_fields
    }

    /// Invalid, missing, or relational/encoded-inconsistent replication
    /// transaction IDs.
    pub const fn invalid_replication_tx_id_fields(self) -> u64 {
        self.invalid_replication_tx_id_fields
    }

    /// Replication entries rejected by strict decode or domain validation.
    pub const fn invalid_replication_entries(self) -> u64 {
        self.invalid_replication_entries
    }

    const fn any(self) -> bool {
        self.invalid_owner_fields != 0
            || self.invalid_session_key_type_fields != 0
            || self.invalid_stable_id_fields != 0
            || self.invalid_replication_tx_id_fields != 0
            || self.invalid_replication_entries != 0
    }
}

/// Count-only result of one bounded SQLite identity audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SqliteIdentityAuditReport {
    report_version: u32,
    status: SqliteIdentityAuditStatus,
    limits: SqliteIdentityAuditLimits,
    scanned: SqliteIdentityAuditScannedCounts,
    violations: SqliteIdentityAuditViolationCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    incomplete_reason: Option<SqliteIdentityAuditIncompleteReason>,
}

impl SqliteIdentityAuditReport {
    fn new(limits: SqliteIdentityAuditLimits) -> Self {
        Self {
            report_version: SQLITE_IDENTITY_AUDIT_REPORT_VERSION,
            status: SqliteIdentityAuditStatus::Compliant,
            limits,
            scanned: SqliteIdentityAuditScannedCounts::default(),
            violations: SqliteIdentityAuditViolationCounts::default(),
            incomplete_reason: None,
        }
    }

    fn finish(&mut self) {
        if self.incomplete_reason.is_some() {
            self.status = SqliteIdentityAuditStatus::Incomplete;
        } else if self.violations.any() {
            self.status = SqliteIdentityAuditStatus::ViolationsFound;
        }
    }

    fn mark_incomplete(&mut self, reason: SqliteIdentityAuditIncompleteReason) {
        if self.incomplete_reason.is_none() {
            self.incomplete_reason = Some(reason);
        }
        self.status = SqliteIdentityAuditStatus::Incomplete;
    }

    /// Stable report schema version.
    pub const fn report_version(&self) -> u32 {
        self.report_version
    }

    /// Overall audit status.
    pub const fn status(&self) -> SqliteIdentityAuditStatus {
        self.status
    }

    /// Caller-approved work limits used for this audit.
    pub const fn limits(&self) -> SqliteIdentityAuditLimits {
        self.limits
    }

    /// Counts of rows fully inspected before the result was produced.
    pub const fn scanned(&self) -> SqliteIdentityAuditScannedCounts {
        self.scanned
    }

    /// Count-only invariant failures observed in inspected rows.
    pub const fn violations(&self) -> SqliteIdentityAuditViolationCounts {
        self.violations
    }

    /// Why the complete snapshot could not be inspected, if applicable.
    pub const fn incomplete_reason(&self) -> Option<SqliteIdentityAuditIncompleteReason> {
        self.incomplete_reason
    }
}

/// Static, redaction-safe failure to configure or start an identity audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SqliteIdentityAuditError {
    /// One or more work limits were zero or internally inconsistent.
    #[error("invalid SQLite identity audit limits")]
    InvalidLimits,
    /// The target could not be opened as an existing read-only SQLite database.
    #[error("SQLite identity audit database open failed")]
    DatabaseOpenFailed,
    /// The read-only SQLite connection or snapshot could not be configured.
    #[error("SQLite identity audit setup failed")]
    DatabaseSetupFailed,
}

impl SqliteIdentityAuditError {
    /// Stable machine-readable reason code.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "invalid_limits",
            Self::DatabaseOpenFailed => "database_open_failed",
            Self::DatabaseSetupFailed => "database_setup_failed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ScannedTable {
    SessionRecords,
    Leases,
    KeyFences,
    ReplicationEntries,
}

struct AuditState {
    report: SqliteIdentityAuditReport,
    rows_seen: u64,
    json_bytes_seen: u64,
}

impl AuditState {
    fn new(limits: SqliteIdentityAuditLimits) -> Self {
        Self {
            report: SqliteIdentityAuditReport::new(limits),
            rows_seen: 0,
            json_bytes_seen: 0,
        }
    }

    fn remaining_rows(&self) -> u64 {
        self.report.limits.max_rows.saturating_sub(self.rows_seen)
    }

    fn page_limit(&self) -> u32 {
        u32::try_from(
            self.remaining_rows()
                .min(u64::from(SQLITE_IDENTITY_AUDIT_PAGE_ROWS)),
        )
        .unwrap_or(SQLITE_IDENTITY_AUDIT_PAGE_ROWS)
    }

    fn increment_scanned(&mut self, table: ScannedTable) -> bool {
        let Some(rows_seen) = self.rows_seen.checked_add(1) else {
            self.report
                .mark_incomplete(SqliteIdentityAuditIncompleteReason::CounterOverflow);
            return false;
        };
        let counter = match table {
            ScannedTable::SessionRecords => &mut self.report.scanned.session_records,
            ScannedTable::Leases => &mut self.report.scanned.leases,
            ScannedTable::KeyFences => &mut self.report.scanned.key_fences,
            ScannedTable::ReplicationEntries => &mut self.report.scanned.replication_entries,
        };
        let Some(next) = counter.checked_add(1) else {
            self.report
                .mark_incomplete(SqliteIdentityAuditIncompleteReason::CounterOverflow);
            return false;
        };
        self.rows_seen = rows_seen;
        *counter = next;
        true
    }

    fn increment_invalid_owner(&mut self) -> bool {
        let Some(next) = self.report.violations.invalid_owner_fields.checked_add(1) else {
            self.report
                .mark_incomplete(SqliteIdentityAuditIncompleteReason::CounterOverflow);
            return false;
        };
        self.report.violations.invalid_owner_fields = next;
        true
    }

    fn increment_invalid_key_type(&mut self) -> bool {
        let Some(next) = self
            .report
            .violations
            .invalid_session_key_type_fields
            .checked_add(1)
        else {
            self.report
                .mark_incomplete(SqliteIdentityAuditIncompleteReason::CounterOverflow);
            return false;
        };
        self.report.violations.invalid_session_key_type_fields = next;
        true
    }

    fn increment_invalid_stable_id(&mut self) -> bool {
        let Some(next) = self
            .report
            .violations
            .invalid_stable_id_fields
            .checked_add(1)
        else {
            self.report
                .mark_incomplete(SqliteIdentityAuditIncompleteReason::CounterOverflow);
            return false;
        };
        self.report.violations.invalid_stable_id_fields = next;
        true
    }

    fn increment_invalid_replication_entry(&mut self) -> bool {
        let Some(next) = self
            .report
            .violations
            .invalid_replication_entries
            .checked_add(1)
        else {
            self.report
                .mark_incomplete(SqliteIdentityAuditIncompleteReason::CounterOverflow);
            return false;
        };
        self.report.violations.invalid_replication_entries = next;
        true
    }

    fn increment_invalid_replication_tx_id(&mut self) -> bool {
        let Some(next) = self
            .report
            .violations
            .invalid_replication_tx_id_fields
            .checked_add(1)
        else {
            self.report
                .mark_incomplete(SqliteIdentityAuditIncompleteReason::CounterOverflow);
            return false;
        };
        self.report.violations.invalid_replication_tx_id_fields = next;
        true
    }
}

enum ScanControl {
    Continue,
    Stop,
}

/// Audit an existing session-store SQLite database without modifying it.
///
/// The caller must provide a drained, consistent database snapshot and explicit
/// non-zero work limits. A compliant result certifies only the fully inspected
/// point-in-time snapshot. `Incomplete` and `ViolationsFound` must both block an
/// upgrade until the store is re-audited successfully.
pub fn audit_sqlite_identity_invariants(
    path: impl AsRef<Path>,
    limits: SqliteIdentityAuditLimits,
) -> Result<SqliteIdentityAuditReport, SqliteIdentityAuditError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)
        .map_err(|_| SqliteIdentityAuditError::DatabaseOpenFailed)?;
    conn.busy_timeout(SQLITE_AUDIT_BUSY_TIMEOUT)
        .map_err(|_| SqliteIdentityAuditError::DatabaseSetupFailed)?;
    conn.execute_batch(
        "PRAGMA query_only = ON;\
         PRAGMA trusted_schema = OFF;",
    )
    .map_err(|_| SqliteIdentityAuditError::DatabaseSetupFailed)?;
    let snapshot = conn
        .unchecked_transaction()
        .map_err(|_| SqliteIdentityAuditError::DatabaseSetupFailed)?;

    let mut state = AuditState::new(limits);
    match schema_is_supported(&snapshot) {
        Ok(true) => {}
        Ok(false) => {
            state
                .report
                .mark_incomplete(SqliteIdentityAuditIncompleteReason::UnsupportedSchema);
            state.report.finish();
            return Ok(state.report);
        }
        Err(()) => {
            state
                .report
                .mark_incomplete(SqliteIdentityAuditIncompleteReason::DatabaseReadFailed);
            state.report.finish();
            return Ok(state.report);
        }
    }

    for scan in [
        scan_session_records as fn(&Connection, &mut AuditState) -> Result<ScanControl, ()>,
        scan_leases,
        scan_key_fences,
        scan_replication_entries,
    ] {
        match scan(&snapshot, &mut state) {
            Ok(ScanControl::Continue) => {}
            Ok(ScanControl::Stop) => break,
            Err(()) => {
                state
                    .report
                    .mark_incomplete(SqliteIdentityAuditIncompleteReason::DatabaseReadFailed);
                break;
            }
        }
    }
    state.report.finish();
    Ok(state.report)
}

fn schema_is_supported(conn: &Connection) -> Result<bool, ()> {
    for (table, columns) in [
        ("session_records", &["owner", "key_type", "stable_id"][..]),
        ("leases", &["owner", "key_type", "stable_id"][..]),
        ("key_fences", &["key_type", "stable_id"][..]),
        (
            "session_replication_log",
            &["sequence", "tx_id", "entry_json"][..],
        ),
    ] {
        for column in columns {
            if !schema_column_exists(conn, table, column)? {
                return Ok(false);
            }
        }
    }

    // The ordinary tables are paged by SQLite's intrinsic, unique rowid. A
    // declared `rowid` column would shadow it and could make keyset paging skip
    // rows, so such a non-SDK schema is never certified.
    for table in ["session_records", "leases", "key_fences"] {
        if schema_column_exists(conn, table, "rowid")? {
            return Ok(false);
        }
    }

    // Replication entries are paged by their SDK-defined integer primary key.
    // Merely finding a column called `sequence` is insufficient: duplicates
    // in a lookalike schema would make keyset paging skip entries.
    conn.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM pragma_table_info('session_replication_log')
            WHERE name = 'sequence' AND upper(type) = 'INTEGER' AND pk = 1
              AND (
                  SELECT count(*)
                  FROM pragma_table_info('session_replication_log')
                  WHERE pk != 0
              ) = 1
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )
    .map_err(|_| ())
}

fn schema_column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, ()> {
    conn.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM pragma_table_info(?1)
            WHERE name = ?2 COLLATE NOCASE
        )
        "#,
        params![table, column],
        |row| row.get::<_, bool>(0),
    )
    .map_err(|_| ())
}

const SESSION_RECORDS_FIRST_PAGE: &str = r#"
    SELECT rowid,
           typeof(owner), length(CAST(owner AS BLOB)),
           CASE WHEN typeof(owner) = 'text'
                  AND length(CAST(owner AS BLOB)) <= ?1 THEN owner END,
           typeof(key_type), length(CAST(key_type AS BLOB)),
           CASE WHEN typeof(key_type) = 'text'
                  AND length(CAST(key_type AS BLOB)) <= ?2 THEN key_type END,
           typeof(stable_id), length(stable_id)
    FROM session_records
    ORDER BY rowid
    LIMIT ?3
"#;

const SESSION_RECORDS_NEXT_PAGE: &str = r#"
    SELECT rowid,
           typeof(owner), length(CAST(owner AS BLOB)),
           CASE WHEN typeof(owner) = 'text'
                  AND length(CAST(owner AS BLOB)) <= ?1 THEN owner END,
           typeof(key_type), length(CAST(key_type AS BLOB)),
           CASE WHEN typeof(key_type) = 'text'
                  AND length(CAST(key_type AS BLOB)) <= ?2 THEN key_type END,
           typeof(stable_id), length(stable_id)
    FROM session_records
    WHERE rowid > ?3
    ORDER BY rowid
    LIMIT ?4
"#;

const LEASES_FIRST_PAGE: &str = r#"
    SELECT rowid,
           typeof(owner), length(CAST(owner AS BLOB)),
           CASE WHEN typeof(owner) = 'text'
                  AND length(CAST(owner AS BLOB)) <= ?1 THEN owner END,
           typeof(key_type), length(CAST(key_type AS BLOB)),
           CASE WHEN typeof(key_type) = 'text'
                  AND length(CAST(key_type AS BLOB)) <= ?2 THEN key_type END,
           typeof(stable_id), length(stable_id)
    FROM leases
    ORDER BY rowid
    LIMIT ?3
"#;

const LEASES_NEXT_PAGE: &str = r#"
    SELECT rowid,
           typeof(owner), length(CAST(owner AS BLOB)),
           CASE WHEN typeof(owner) = 'text'
                  AND length(CAST(owner AS BLOB)) <= ?1 THEN owner END,
           typeof(key_type), length(CAST(key_type AS BLOB)),
           CASE WHEN typeof(key_type) = 'text'
                  AND length(CAST(key_type AS BLOB)) <= ?2 THEN key_type END,
           typeof(stable_id), length(stable_id)
    FROM leases
    WHERE rowid > ?3
    ORDER BY rowid
    LIMIT ?4
"#;

fn scan_session_records(conn: &Connection, state: &mut AuditState) -> Result<ScanControl, ()> {
    scan_owner_and_key_type_table(
        conn,
        SESSION_RECORDS_FIRST_PAGE,
        SESSION_RECORDS_NEXT_PAGE,
        "SELECT 1 FROM session_records LIMIT 1",
        "SELECT 1 FROM session_records WHERE rowid > ?1 LIMIT 1",
        ScannedTable::SessionRecords,
        state,
    )
}

fn scan_leases(conn: &Connection, state: &mut AuditState) -> Result<ScanControl, ()> {
    scan_owner_and_key_type_table(
        conn,
        LEASES_FIRST_PAGE,
        LEASES_NEXT_PAGE,
        "SELECT 1 FROM leases LIMIT 1",
        "SELECT 1 FROM leases WHERE rowid > ?1 LIMIT 1",
        ScannedTable::Leases,
        state,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_owner_and_key_type_table(
    conn: &Connection,
    first_page_sql: &str,
    next_page_sql: &str,
    first_exists_sql: &str,
    next_exists_sql: &str,
    table: ScannedTable,
    state: &mut AuditState,
) -> Result<ScanControl, ()> {
    let mut cursor = None;
    loop {
        if state.remaining_rows() == 0 {
            if page_has_more(conn, first_exists_sql, next_exists_sql, cursor)? {
                state
                    .report
                    .mark_incomplete(SqliteIdentityAuditIncompleteReason::RowBudgetExceeded);
                return Ok(ScanControl::Stop);
            }
            return Ok(ScanControl::Continue);
        }
        let limit = state.page_limit();
        let mut stmt = conn
            .prepare(if cursor.is_some() {
                next_page_sql
            } else {
                first_page_sql
            })
            .map_err(|_| ())?;
        let mut rows = match cursor {
            Some(last) => stmt
                .query(params![
                    u64::try_from(OWNER_ID_MAX_BYTES).map_err(|_| ())?,
                    u64::try_from(SESSION_KEY_TYPE_MAX_BYTES).map_err(|_| ())?,
                    last,
                    limit
                ])
                .map_err(|_| ())?,
            None => stmt
                .query(params![
                    u64::try_from(OWNER_ID_MAX_BYTES).map_err(|_| ())?,
                    u64::try_from(SESSION_KEY_TYPE_MAX_BYTES).map_err(|_| ())?,
                    limit
                ])
                .map_err(|_| ())?,
        };
        let mut rows_in_page = 0_u32;
        while let Some(row) = rows.next().map_err(|_| ())? {
            let rowid: i64 = row.get(0).map_err(|_| ())?;
            if !state.increment_scanned(table) {
                return Ok(ScanControl::Stop);
            }
            if !owner_field_is_valid(row, 1, 2, 3)? && !state.increment_invalid_owner() {
                return Ok(ScanControl::Stop);
            }
            if !key_type_field_is_valid(row, 4, 5, 6)? && !state.increment_invalid_key_type() {
                return Ok(ScanControl::Stop);
            }
            if !stable_id_field_is_valid(row, 7, 8)? && !state.increment_invalid_stable_id() {
                return Ok(ScanControl::Stop);
            }
            cursor = Some(rowid);
            rows_in_page = rows_in_page.checked_add(1).ok_or(())?;
        }
        if rows_in_page < limit {
            return Ok(ScanControl::Continue);
        }
    }
}

fn owner_field_is_valid(
    row: &Row<'_>,
    type_index: usize,
    length_index: usize,
    value_index: usize,
) -> Result<bool, ()> {
    bounded_text_value(
        row,
        type_index,
        length_index,
        value_index,
        OWNER_ID_MAX_BYTES,
    )
    .map(|value| value.is_some_and(|value| OwnerId::new(value).is_ok()))
}

fn key_type_field_is_valid(
    row: &Row<'_>,
    type_index: usize,
    length_index: usize,
    value_index: usize,
) -> Result<bool, ()> {
    bounded_text_value(
        row,
        type_index,
        length_index,
        value_index,
        SESSION_KEY_TYPE_MAX_BYTES,
    )
    .map(|value| value.is_some_and(|value| SessionKeyType::from_str(&value).is_ok()))
}

fn bounded_text_value(
    row: &Row<'_>,
    type_index: usize,
    length_index: usize,
    value_index: usize,
    max_bytes: usize,
) -> Result<Option<String>, ()> {
    let value_type: String = row.get(type_index).map_err(|_| ())?;
    let byte_length: Option<i64> = row.get(length_index).map_err(|_| ())?;
    let Some(byte_length) = byte_length.and_then(|value| u64::try_from(value).ok()) else {
        return Ok(None);
    };
    if value_type != "text" || byte_length > u64::try_from(max_bytes).map_err(|_| ())? {
        return Ok(None);
    }
    row.get(value_index).map_err(|_| ())
}

fn stable_id_field_is_valid(
    row: &Row<'_>,
    type_index: usize,
    length_index: usize,
) -> Result<bool, ()> {
    let value_type: String = row.get(type_index).map_err(|_| ())?;
    let byte_length: Option<i64> = row.get(length_index).map_err(|_| ())?;
    let Some(byte_length) = byte_length.and_then(|value| usize::try_from(value).ok()) else {
        return Ok(false);
    };
    Ok(value_type == "blob" && (STABLE_ID_MIN_BYTES..=STABLE_ID_MAX_BYTES).contains(&byte_length))
}

const KEY_FENCES_FIRST_PAGE: &str = r#"
    SELECT rowid,
           typeof(key_type), length(CAST(key_type AS BLOB)),
           CASE WHEN typeof(key_type) = 'text'
                  AND length(CAST(key_type AS BLOB)) <= ?1 THEN key_type END,
           typeof(stable_id), length(stable_id)
    FROM key_fences
    ORDER BY rowid
    LIMIT ?2
"#;

const KEY_FENCES_NEXT_PAGE: &str = r#"
    SELECT rowid,
           typeof(key_type), length(CAST(key_type AS BLOB)),
           CASE WHEN typeof(key_type) = 'text'
                  AND length(CAST(key_type AS BLOB)) <= ?1 THEN key_type END,
           typeof(stable_id), length(stable_id)
    FROM key_fences
    WHERE rowid > ?2
    ORDER BY rowid
    LIMIT ?3
"#;

fn scan_key_fences(conn: &Connection, state: &mut AuditState) -> Result<ScanControl, ()> {
    let mut cursor = None;
    loop {
        if state.remaining_rows() == 0 {
            if page_has_more(
                conn,
                "SELECT 1 FROM key_fences LIMIT 1",
                "SELECT 1 FROM key_fences WHERE rowid > ?1 LIMIT 1",
                cursor,
            )? {
                state
                    .report
                    .mark_incomplete(SqliteIdentityAuditIncompleteReason::RowBudgetExceeded);
                return Ok(ScanControl::Stop);
            }
            return Ok(ScanControl::Continue);
        }
        let limit = state.page_limit();
        let mut stmt = conn
            .prepare(if cursor.is_some() {
                KEY_FENCES_NEXT_PAGE
            } else {
                KEY_FENCES_FIRST_PAGE
            })
            .map_err(|_| ())?;
        let mut rows = match cursor {
            Some(last) => stmt
                .query(params![
                    u64::try_from(SESSION_KEY_TYPE_MAX_BYTES).map_err(|_| ())?,
                    last,
                    limit
                ])
                .map_err(|_| ())?,
            None => stmt
                .query(params![
                    u64::try_from(SESSION_KEY_TYPE_MAX_BYTES).map_err(|_| ())?,
                    limit
                ])
                .map_err(|_| ())?,
        };
        let mut rows_in_page = 0_u32;
        while let Some(row) = rows.next().map_err(|_| ())? {
            let rowid: i64 = row.get(0).map_err(|_| ())?;
            if !state.increment_scanned(ScannedTable::KeyFences) {
                return Ok(ScanControl::Stop);
            }
            if !key_type_field_is_valid(row, 1, 2, 3)? && !state.increment_invalid_key_type() {
                return Ok(ScanControl::Stop);
            }
            if !stable_id_field_is_valid(row, 4, 5)? && !state.increment_invalid_stable_id() {
                return Ok(ScanControl::Stop);
            }
            cursor = Some(rowid);
            rows_in_page = rows_in_page.checked_add(1).ok_or(())?;
        }
        if rows_in_page < limit {
            return Ok(ScanControl::Continue);
        }
    }
}

const REPLICATION_LOG_FIRST_PAGE: &str = r#"
    SELECT sequence,
           typeof(tx_id), length(CAST(tx_id AS BLOB)),
           CASE WHEN typeof(tx_id) = 'text'
                  AND length(CAST(tx_id AS BLOB)) <= ?1 THEN tx_id END,
           typeof(entry_json), length(CAST(entry_json AS BLOB)),
           CASE WHEN typeof(entry_json) = 'text'
                  AND length(CAST(entry_json AS BLOB)) <= ?2 THEN entry_json END
    FROM session_replication_log
    ORDER BY sequence
    LIMIT ?3
"#;

const REPLICATION_LOG_NEXT_PAGE: &str = r#"
    SELECT sequence,
           typeof(tx_id), length(CAST(tx_id AS BLOB)),
           CASE WHEN typeof(tx_id) = 'text'
                  AND length(CAST(tx_id AS BLOB)) <= ?1 THEN tx_id END,
           typeof(entry_json), length(CAST(entry_json AS BLOB)),
           CASE WHEN typeof(entry_json) = 'text'
                  AND length(CAST(entry_json AS BLOB)) <= ?2 THEN entry_json END
    FROM session_replication_log
    WHERE sequence > ?3
    ORDER BY sequence
    LIMIT ?4
"#;

fn scan_replication_entries(conn: &Connection, state: &mut AuditState) -> Result<ScanControl, ()> {
    let mut cursor = None;
    loop {
        if state.remaining_rows() == 0 {
            if page_has_more(
                conn,
                "SELECT 1 FROM session_replication_log LIMIT 1",
                "SELECT 1 FROM session_replication_log WHERE sequence > ?1 LIMIT 1",
                cursor,
            )? {
                state
                    .report
                    .mark_incomplete(SqliteIdentityAuditIncompleteReason::RowBudgetExceeded);
                return Ok(ScanControl::Stop);
            }
            return Ok(ScanControl::Continue);
        }
        let limit = state.page_limit();
        let mut stmt = conn
            .prepare(if cursor.is_some() {
                REPLICATION_LOG_NEXT_PAGE
            } else {
                REPLICATION_LOG_FIRST_PAGE
            })
            .map_err(|_| ())?;
        let mut rows = match cursor {
            Some(last) => stmt
                .query(params![
                    REPLICATION_TX_ID_MAX_BYTES,
                    state.report.limits.max_entry_json_bytes,
                    last,
                    limit
                ])
                .map_err(|_| ())?,
            None => stmt
                .query(params![
                    REPLICATION_TX_ID_MAX_BYTES,
                    state.report.limits.max_entry_json_bytes,
                    limit
                ])
                .map_err(|_| ())?,
        };
        let mut rows_in_page = 0_u32;
        while let Some(row) = rows.next().map_err(|_| ())? {
            let sequence: i64 = row.get(0).map_err(|_| ())?;
            let stored_tx_id = bounded_text_value(row, 1, 2, 3, REPLICATION_TX_ID_MAX_BYTES)?
                .and_then(|value| ReplicationTxId::try_from(value).ok());
            let value_type: String = row.get(4).map_err(|_| ())?;
            let byte_length: Option<i64> = row.get(5).map_err(|_| ())?;
            let byte_length = byte_length.and_then(|value| u64::try_from(value).ok());

            if value_type != "text" || byte_length.is_none() {
                if !state.increment_scanned(ScannedTable::ReplicationEntries)
                    || (stored_tx_id.is_none() && !state.increment_invalid_replication_tx_id())
                    || !state.increment_invalid_replication_entry()
                {
                    return Ok(ScanControl::Stop);
                }
            } else {
                let byte_length = byte_length.unwrap_or_default();
                if byte_length > state.report.limits.max_entry_json_bytes {
                    state.report.mark_incomplete(
                        SqliteIdentityAuditIncompleteReason::EntryJsonBudgetExceeded,
                    );
                    return Ok(ScanControl::Stop);
                }
                let Some(next_total) = state.json_bytes_seen.checked_add(byte_length) else {
                    state
                        .report
                        .mark_incomplete(SqliteIdentityAuditIncompleteReason::CounterOverflow);
                    return Ok(ScanControl::Stop);
                };
                if next_total > state.report.limits.max_total_json_bytes {
                    state.report.mark_incomplete(
                        SqliteIdentityAuditIncompleteReason::TotalJsonBudgetExceeded,
                    );
                    return Ok(ScanControl::Stop);
                }
                let entry_json: Option<String> = row.get(6).map_err(|_| ())?;
                let Some(entry_json) = entry_json else {
                    return Err(());
                };
                state.json_bytes_seen = next_total;
                let encoded_tx_id = probe_replication_tx_id(&entry_json);
                let entry = serde_json::from_str::<ReplicationEntry>(&entry_json)
                    .ok()
                    .and_then(|entry| entry.into_validated().ok());
                let stored_sequence = u64::try_from(sequence)
                    .ok()
                    .filter(|sequence| *sequence != 0);
                let valid = stored_sequence
                    .zip(entry.as_ref())
                    .is_some_and(|(stored_sequence, entry)| entry.sequence == stored_sequence);
                let tx_id_valid = stored_tx_id
                    .as_ref()
                    .zip(encoded_tx_id.as_ref())
                    .is_some_and(|(stored_tx_id, encoded_tx_id)| stored_tx_id == encoded_tx_id);
                if !state.increment_scanned(ScannedTable::ReplicationEntries) {
                    return Ok(ScanControl::Stop);
                }
                if !tx_id_valid && !state.increment_invalid_replication_tx_id() {
                    return Ok(ScanControl::Stop);
                }
                if !valid && !state.increment_invalid_replication_entry() {
                    return Ok(ScanControl::Stop);
                }
            }
            cursor = Some(sequence);
            rows_in_page = rows_in_page.checked_add(1).ok_or(())?;
        }
        if rows_in_page < limit {
            return Ok(ScanControl::Continue);
        }
    }
}

fn page_has_more(
    conn: &Connection,
    first_sql: &str,
    next_sql: &str,
    cursor: Option<i64>,
) -> Result<bool, ()> {
    let value = match cursor {
        Some(cursor) => conn
            .query_row(next_sql, params![cursor], |row| row.get::<_, i64>(0))
            .optional(),
        None => conn
            .query_row(first_sql, [], |row| row.get::<_, i64>(0))
            .optional(),
    }
    .map_err(|_| ())?;
    Ok(value.is_some())
}
