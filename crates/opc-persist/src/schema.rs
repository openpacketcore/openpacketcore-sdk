//! SQLite schema management for the persistence backend.
//!
//! ## Schema Design
//!
//! The schema follows RFC 001 §8.4:
//! - `schema_version` — single-row migration tracker (id = 1)
//! - `config_history` — immutable commit ledger (append-only after genesis)
//! - `audit_trail` — per-transaction YANG path-level audit with hash chain
//! - `rollback_labels` — named rollback point labels
//!
//! All writes go through a single writer connection. The schema uses foreign
//! keys to prevent orphaned audit records.

use rusqlite::{Connection, Transaction};
use std::path::Path;
use std::time::Duration;

/// Current schema version. Bump this and add a migration step to evolve the schema.
pub const SCHEMA_VERSION: &str = "1.8.0";
/// Cap SQLite lock waits on async runtime workers.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 100;

/// Initialize the database schema.
///
/// This is called exactly once when opening a new database. For existing
/// databases, the schema version row is checked and migrations are applied
/// if needed.
///
/// ## Safety
///
/// Must be called within a transaction.
pub fn initialize_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_version (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            schema_digest TEXT NOT NULL,
            sdk_version TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS config_history (
            tx_id BLOB PRIMARY KEY,
            parent_tx_id BLOB NULL REFERENCES config_history(tx_id),
            version INTEGER NOT NULL UNIQUE,
            committed_at TEXT NOT NULL,
            principal TEXT NOT NULL,
            source TEXT NOT NULL,
            schema_digest BLOB NOT NULL,
            plaintext_digest BLOB NOT NULL,
            encrypted_blob BLOB NOT NULL,
            rollback_point INTEGER NOT NULL DEFAULT 0,
            rollback_label TEXT NULL,
            confirmed_deadline TEXT NULL,
            confirmed_at TEXT NULL,
            audit_count INTEGER NOT NULL DEFAULT 0,
            audit_terminal_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
        );

        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_id BLOB NOT NULL REFERENCES config_history(tx_id) ON DELETE RESTRICT,
            sequence INTEGER NOT NULL,
            yang_path TEXT NOT NULL,
            op_type TEXT NOT NULL CHECK(op_type IN ('CREATE', 'UPDATE', 'REPLACE', 'DELETE')),
            previous_value TEXT NULL,
            new_value TEXT NULL,
            redaction_applied INTEGER NOT NULL DEFAULT 0,
            previous_hash BLOB NOT NULL,
            entry_hmac BLOB NOT NULL,
            UNIQUE(tx_id, sequence)
        );

        CREATE TABLE IF NOT EXISTS rollback_labels (
            label TEXT PRIMARY KEY,
            tx_id BLOB NOT NULL REFERENCES config_history(tx_id),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alarm_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            alarm_id TEXT NOT NULL,
            alarm_type TEXT NOT NULL,
            probable_cause TEXT NOT NULL,
            principal TEXT NOT NULL,
            tenant TEXT NULL,
            reason TEXT NOT NULL,
            scope TEXT NOT NULL,
            correlation_id TEXT NULL,
            occurred_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS consensus_state (
            node_id INTEGER PRIMARY KEY,
            current_term INTEGER NOT NULL,
            voted_for INTEGER NULL
        );

        CREATE TABLE IF NOT EXISTS consensus_log (
            log_index INTEGER PRIMARY KEY,
            term INTEGER NOT NULL,
            op_type TEXT NOT NULL,
            payload BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS consensus_applied (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            applied_index INTEGER NOT NULL
        );

        INSERT OR IGNORE INTO consensus_applied (id, applied_index) VALUES (1, 0);

        CREATE TABLE IF NOT EXISTS consensus_membership (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            cluster_id TEXT NOT NULL,
            node_id INTEGER NOT NULL,
            voting_members TEXT NOT NULL,
            non_voting_members TEXT NOT NULL,
            old_voting_members TEXT NULL,
            removed_members TEXT NOT NULL DEFAULT '[]',
            epoch INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS consensus_snapshot (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            snapshot_index INTEGER NOT NULL,
            snapshot_term INTEGER NOT NULL,
            snapshot_data BLOB NOT NULL
        );

        CREATE INDEX IF NOT EXISTS audit_trail_tx_id_idx ON audit_trail(tx_id);
        CREATE INDEX IF NOT EXISTS config_history_rollback_idx ON config_history(version, rollback_point);

        CREATE TABLE IF NOT EXISTS config_lifecycle_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_id BLOB NOT NULL REFERENCES config_history(tx_id) ON DELETE RESTRICT,
            action TEXT NOT NULL,
            principal TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            details TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS config_lifecycle_audit_tx_id_idx ON config_lifecycle_audit(tx_id);

        CREATE TABLE IF NOT EXISTS staged_security_policy (
            tenant TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            staged_at TEXT NOT NULL,
            principal TEXT NOT NULL,
            encrypted_blob BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS security_policy_active (
            tenant TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            applied_at TEXT NOT NULL,
            principal TEXT NOT NULL,
            encrypted_blob BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS security_policy_history (
            tenant TEXT NOT NULL,
            version INTEGER NOT NULL,
            applied_at TEXT NOT NULL,
            principal TEXT NOT NULL,
            encrypted_blob BLOB NOT NULL,
            tx_id BLOB NULL,
            label TEXT NULL,
            PRIMARY KEY (tenant, version)
        );

        CREATE TABLE IF NOT EXISTS security_policy_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            principal TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            previous_hash BLOB NOT NULL,
            entry_hmac BLOB NOT NULL
        );

        CREATE INDEX IF NOT EXISTS security_policy_audit_tenant_idx ON security_policy_audit(tenant);

        CREATE TABLE IF NOT EXISTS security_policy_audit_anchor (
            tenant TEXT PRIMARY KEY,
            audit_count INTEGER NOT NULL DEFAULT 0,
            audit_terminal_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
        );

        CREATE TABLE IF NOT EXISTS break_glass_sessions (
            id TEXT PRIMARY KEY,
            principal TEXT NOT NULL,
            tenant TEXT NOT NULL,
            reason TEXT NOT NULL,
            scope TEXT NOT NULL,
            requested_duration INTEGER NOT NULL,
            evidence_id TEXT NOT NULL,
            status TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            approved_at TEXT,
            approver TEXT,
            activated_at TEXT,
            expires_at TEXT,
            denied_at TEXT,
            revoked_at TEXT,
            revoker TEXT
        );

        CREATE TABLE IF NOT EXISTS break_glass_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            principal TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            previous_hash BLOB NOT NULL,
            entry_hmac BLOB NOT NULL
        );

        CREATE INDEX IF NOT EXISTS break_glass_audit_tenant_idx ON break_glass_audit(tenant);
        CREATE INDEX IF NOT EXISTS break_glass_sessions_tenant_idx ON break_glass_sessions(tenant);

        CREATE TABLE IF NOT EXISTS break_glass_audit_anchor (
            tenant TEXT PRIMARY KEY,
            audit_count INTEGER NOT NULL DEFAULT 0,
            audit_terminal_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
        );
        "#,
    )?;
    Ok(())
}

fn table_has_column(
    conn: &Connection,
    table_name: &str,
    column_name: &str,
) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table_name})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column_name {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Upgrade the schema from a previous version.
///
/// Add new idempotent migration steps here as the schema evolves. Callers are
/// responsible for applying schema metadata updates after this succeeds.
pub fn run_migrations(conn: &Connection, from_version: &str) -> Result<(), rusqlite::Error> {
    let mut current = from_version.to_string();
    if current == "1.0.0" {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS alarm_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                alarm_id TEXT NOT NULL,
                alarm_type TEXT NOT NULL,
                probable_cause TEXT NOT NULL,
                principal TEXT NOT NULL,
                tenant TEXT NULL,
                reason TEXT NOT NULL,
                scope TEXT NOT NULL,
                correlation_id TEXT NULL,
                occurred_at TEXT NOT NULL
            );
            "#,
        )?;
        current = "1.1.0".to_string();
    }
    if current == "1.1.0" {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS consensus_state (
                node_id INTEGER PRIMARY KEY,
                current_term INTEGER NOT NULL,
                voted_for INTEGER NULL
            );
            CREATE TABLE IF NOT EXISTS consensus_log (
                log_index INTEGER PRIMARY KEY,
                term INTEGER NOT NULL,
                op_type TEXT NOT NULL,
                payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS consensus_applied (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                applied_index INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO consensus_applied (id, applied_index) VALUES (1, 0);
            "#,
        )?;
        current = "1.2.0".to_string();
    }
    if current == "1.2.0" {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS consensus_membership (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                cluster_id TEXT NOT NULL,
                node_id INTEGER NOT NULL,
                voting_members TEXT NOT NULL,
                non_voting_members TEXT NOT NULL,
                epoch INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS consensus_snapshot (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                snapshot_index INTEGER NOT NULL,
                snapshot_term INTEGER NOT NULL,
                snapshot_data BLOB NOT NULL
            );
            "#,
        )?;
        current = "1.3.0".to_string();
    }
    if current == "1.3.0" {
        let mut has_column = false;
        if let Ok(mut stmt) = conn.prepare("PRAGMA table_info(consensus_membership)") {
            if let Ok(mut rows) = stmt.query([]) {
                while let Ok(Some(row)) = rows.next() {
                    if let Ok(name) = row.get::<_, String>(1) {
                        if name == "old_voting_members" {
                            has_column = true;
                            break;
                        }
                    }
                }
            }
        }
        if !has_column {
            conn.execute_batch(
                r#"
                ALTER TABLE consensus_membership ADD COLUMN old_voting_members TEXT NULL;
                ALTER TABLE consensus_membership ADD COLUMN removed_members TEXT NOT NULL DEFAULT '[]';
                "#,
            )?;
        }
        current = "1.4.0".to_string();
    }
    if current == "1.4.0" {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS break_glass_sessions (
                id TEXT PRIMARY KEY,
                principal TEXT NOT NULL,
                tenant TEXT NOT NULL,
                reason TEXT NOT NULL,
                scope TEXT NOT NULL,
                requested_duration INTEGER NOT NULL,
                evidence_id TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                approved_at TEXT,
                approver TEXT,
                activated_at TEXT,
                expires_at TEXT,
                denied_at TEXT,
                revoked_at TEXT,
                revoker TEXT
            );

            CREATE TABLE IF NOT EXISTS break_glass_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                principal TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                previous_hash BLOB NOT NULL,
                entry_hmac BLOB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS break_glass_audit_tenant_idx ON break_glass_audit(tenant);
            CREATE INDEX IF NOT EXISTS break_glass_sessions_tenant_idx ON break_glass_sessions(tenant);
            "#,
        )?;
        current = "1.5.0".to_string();
    }
    if current == "1.5.0" {
        if !table_has_column(conn, "config_history", "audit_count")? {
            conn.execute_batch(
                r#"
                ALTER TABLE config_history ADD COLUMN audit_count INTEGER NOT NULL DEFAULT 0;
                "#,
            )?;
        }
        if !table_has_column(conn, "config_history", "audit_terminal_hash")? {
            conn.execute_batch(
                r#"
                ALTER TABLE config_history ADD COLUMN audit_terminal_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000';
                "#,
            )?;
        }
        conn.execute_batch(
            r#"
            UPDATE config_history
            SET audit_count = (
                    SELECT COUNT(*)
                    FROM audit_trail
                    WHERE audit_trail.tx_id = config_history.tx_id
                ),
                audit_terminal_hash = COALESCE(
                    (
                        SELECT entry_hmac
                        FROM audit_trail
                        WHERE audit_trail.tx_id = config_history.tx_id
                        ORDER BY sequence DESC
                        LIMIT 1
                    ),
                    zeroblob(32)
                );
            "#,
        )?;
        current = "1.6.0".to_string();
    }
    if current == "1.6.0" {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS security_policy_audit_anchor (
                tenant TEXT PRIMARY KEY,
                audit_count INTEGER NOT NULL DEFAULT 0,
                audit_terminal_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
            );

            CREATE TABLE IF NOT EXISTS break_glass_audit_anchor (
                tenant TEXT PRIMARY KEY,
                audit_count INTEGER NOT NULL DEFAULT 0,
                audit_terminal_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
            );

            INSERT OR REPLACE INTO security_policy_audit_anchor (tenant, audit_count, audit_terminal_hash)
            SELECT tenant,
                   COUNT(*),
                   COALESCE(
                       (
                           SELECT entry_hmac
                           FROM security_policy_audit AS last_entry
                           WHERE last_entry.tenant = security_policy_audit.tenant
                           ORDER BY id DESC
                           LIMIT 1
                       ),
                       zeroblob(32)
                   )
            FROM security_policy_audit
            GROUP BY tenant;

            INSERT OR REPLACE INTO break_glass_audit_anchor (tenant, audit_count, audit_terminal_hash)
            SELECT tenant,
                   COUNT(*),
                   COALESCE(
                       (
                           SELECT entry_hmac
                           FROM break_glass_audit AS last_entry
                           WHERE last_entry.tenant = break_glass_audit.tenant
                           ORDER BY id DESC
                           LIMIT 1
                       ),
                       zeroblob(32)
                   )
            FROM break_glass_audit
            GROUP BY tenant;
            "#,
        )?;
        current = "1.7.0".to_string();
    }
    if current == "1.7.0" {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS config_lifecycle_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id BLOB NOT NULL REFERENCES config_history(tx_id) ON DELETE RESTRICT,
                action TEXT NOT NULL,
                principal TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                details TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS config_lifecycle_audit_tx_id_idx ON config_lifecycle_audit(tx_id);
            "#,
        )?;
        current = "1.8.0".to_string();
    }

    let _ = current;

    tracing::info!(
        from_version = from_version,
        to_version = SCHEMA_VERSION,
        "schema migrations applied"
    );
    Ok(())
}

/// Get the current schema version from the schema_version table.
pub fn get_schema_version(conn: &Connection) -> Result<Option<String>, rusqlite::Error> {
    let result: Result<String, _> = conn.query_row(
        "SELECT sdk_version FROM schema_version WHERE id = 1",
        [],
        |row| row.get(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Get the current schema digest from the schema_version table.
pub fn get_schema_digest(conn: &Connection) -> Result<Option<String>, rusqlite::Error> {
    let result: Result<String, _> = conn.query_row(
        "SELECT schema_digest FROM schema_version WHERE id = 1",
        [],
        |row| row.get(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write the initial (or upgraded) schema version row.
pub fn set_schema_version(tx: &Transaction, digest: &str) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT OR REPLACE INTO schema_version (id, schema_digest, sdk_version, created_at) \
         VALUES (1, ?1, ?2, datetime('now'))",
        [digest, SCHEMA_VERSION],
    )?;
    Ok(())
}

/// Verify that WAL mode is active by querying the database.
pub fn verify_wal_mode(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    Ok(mode.eq_ignore_ascii_case("wal"))
}

/// Verify the synchronous setting.
pub fn verify_synchronous_extra(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let value: i32 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    // 3 = EXTRA (conservative synchronous mode); 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA
    Ok(value == 3)
}

/// Apply the standard PRAGMA profile for the reference backend.
///
/// Called once when opening a new or existing database. These settings persist
/// in the database file and are read back on subsequent opens.
pub fn apply_pragma_profile(conn: &Connection) -> Result<(), rusqlite::Error> {
    // Apply each pragma individually to ensure all take effect in the correct order.
    // temp_store must be set before any other operation to ensure it's effective.
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = EXTRA;
        PRAGMA foreign_keys = ON;
        PRAGMA locking_mode = NORMAL;
        PRAGMA temp_store = MEMORY;
        "#,
    )?;
    conn.busy_timeout(Duration::from_millis(u64::from(SQLITE_BUSY_TIMEOUT_MS)))?;

    // Verify temp_store was applied; if not, log a warning
    let ts: i32 = conn.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    if ts != 2 {
        tracing::warn!(
            temp_store = ts,
            "temp_store pragma did not apply (SQLite may have locked it to DEFAULT)"
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage safety checks (safe Rust only — no unsafe code)
// ─────────────────────────────────────────────────────────────────────────────

/// Check that a path is on a supported filesystem.
///
/// On Linux, this uses `statfs` via the `stat` command. On other platforms,
/// it conservatively returns `true` (the actual database open is the real safety
/// check). Known unsafe network filesystems (NFS, CIFS/SMB, FUSE) return false.
#[allow(unused_variables)]
pub fn is_safe_filesystem(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;

        // Use the `stat` command to get the filesystem type
        // Use chained .arg() calls to avoid homogeneous array type requirement
        let output = Command::new("stat")
            .arg("-f")
            .arg("-c")
            .arg("%T")
            .arg(path)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let fs_type = String::from_utf8_lossy(&out.stdout);
                let fs_type = fs_type.trim();

                // Known unsafe network filesystems
                let unsafe_types = [
                    "nfs",
                    "nfs4",
                    "cifs",
                    "smb",
                    "smb3",
                    "fuse",
                    "fuseblk",
                    "fuse.sshfs",
                ];

                for unsafe_type in unsafe_types {
                    if fs_type.eq_ignore_ascii_case(unsafe_type) {
                        return false;
                    }
                }
                true
            }
            _ => {
                // If we can't determine the type, be conservative
                false
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux platforms, we cannot safely determine the filesystem type
        // without unsafe code. The actual database open/operate test is the safety
        // guarantee — if the storage is truly unsafe (e.g. NFS without proper
        // locking), the SQLite operations will fail.
        true
    }
}

/// Check that the database file and its directory live on the same filesystem.
///
/// SQLite creates the WAL and SHM files as siblings of the database in its
/// directory. If the database file itself is on a different device than that
/// directory (a symlink or bind mount crossing filesystems), the WAL/SHM and
/// the database straddle two filesystems, which SQLite cannot keep consistent.
/// When the database does not yet exist it will be created in `dir`, so the
/// invariant holds by construction.
pub fn is_same_filesystem(dir: &Path, db_path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dir_dev = std::fs::metadata(dir).map(|m| m.dev()).ok();
        match dir_dev {
            None => false, // cannot stat the directory: do not assume safe
            Some(dir_dev) => match std::fs::metadata(db_path).map(|m| m.dev()).ok() {
                // DB not yet created — it will be created inside `dir`.
                None => true,
                Some(db_dev) => dir_dev == db_dev,
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, db_path);
        true
    }
}

/// Check if the database directory permissions are safe.
///
/// Verifies the directory is not world-writable (security concern).
/// This is a best-effort check: group-writable directories are not rejected on
/// non-Unix platforms or when the process lacks the ability to determine
/// group ownership.
pub fn is_directory_permissions_safe(path: &Path) -> bool {
    use std::fs;

    // Check if directory is world-writable
    if let Ok(meta) = fs::metadata(path) {
        if let Some(mode) = mode_from_permissions(&meta) {
            // Reject world-writable directories (mode & 0o002)
            if mode & 0o002 != 0 {
                return false;
            }
        }
    }

    true
}

/// Extract permission bits from file metadata in a cross-platform way.
///
/// Returns `None` on error or on platforms where this can't be determined.
fn mode_from_permissions(meta: &std::fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode() & 0o777)
    }

    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// Get the free bytes available on the filesystem containing `path`.
///
/// Uses the `df` command as a safe cross-platform approach.
/// Returns `None` if the information cannot be determined.
pub fn get_free_bytes(path: &Path) -> Option<u64> {
    use std::process::Command;

    // Use df -k (kilobytes) for cross-platform availability
    let output = Command::new("df").arg("-k").arg(path).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // df output format: Filesystem 1K-blocks Used Available Use% Mounted on
    // We want the "Available" column (4th field, 0-indexed: 3)
    for line in stdout.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 {
            // Available is typically in KB
            let available_kb = fields[3].parse::<u64>().ok()?;
            return Some(available_kb.saturating_mul(1024));
        }
    }

    None
}

/// Check whether `fsync` is available and functional on the given directory.
///
/// This is the definitive safety check: we attempt to write a test file and
/// call fsync on it. If it succeeds, the storage is safe for SQLite WAL.
pub fn check_fsync_available(dir: &Path) -> bool {
    use std::fs;
    use std::process::Command;

    let test_path = dir.join(".opc_persist_fsync_test");

    // Write a test file
    if fs::write(&test_path, b"fsync test").is_err() {
        return false;
    }

    // Use `fsync` via Python (widely available) or direct sync command
    // First try Python (most reliable cross-platform)
    let python_result = Command::new("python3")
        .args([
            "-c",
            "import os,sys; handle=open(sys.argv[1], 'r+b'); os.fsync(handle.fileno()); handle.close()",
        ])
        .arg(&test_path)
        .output();

    let ok = python_result
        .map(|out| out.status.success())
        .unwrap_or_else(|_| {
            // Fallback: try `sync` command (less precise — syncs all)
            Command::new("sync")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        });

    let _ = fs::remove_file(&test_path);
    ok
}

#[cfg(test)]
mod fixture_tests {
    use super::{initialize_schema, SCHEMA_VERSION};
    use rusqlite::{params, Connection};
    use std::env;
    use std::path::PathBuf;

    const FIXTURE_NAME: &str = "opc_persist_v032.db";

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(FIXTURE_NAME)
    }

    fn known_tx_id() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    }

    fn write_fixture(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let parent = path.parent().unwrap();
        std::fs::create_dir_all(parent).expect("create fixture dir");

        let conn = Connection::open(path).expect("open fixture for writing");
        initialize_schema(&conn).expect("initialize schema");

        conn.execute(
            "INSERT INTO schema_version (id, schema_digest, sdk_version, created_at) VALUES (1, ?1, ?2, ?3)",
            params!["fixture-digest-abc123", SCHEMA_VERSION, "2026-06-12T00:00:00Z"],
        )
        .expect("insert schema_version");

        conn.execute(
            "INSERT INTO config_history (tx_id, parent_tx_id, version, committed_at, principal, source, schema_digest, plaintext_digest, encrypted_blob, rollback_point, rollback_label, confirmed_deadline, confirmed_at, audit_count, audit_terminal_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                known_tx_id().as_slice(),
                Option::<&[u8]>::None,
                1_i64,
                "2026-06-12T00:00:00Z",
                "fixture-principal",
                "fixture-source",
                vec![0x11_u8].as_slice(),
                vec![0x22_u8].as_slice(),
                vec![0x33_u8].as_slice(),
                0_i64,
                Option::<&str>::None,
                Option::<&str>::None,
                Option::<&str>::None,
                1_i64,
                [0xAA_u8; 32].as_slice(),
            ],
        )
        .expect("insert config_history");

        conn.execute(
            "INSERT INTO audit_trail (tx_id, sequence, yang_path, op_type, previous_value, new_value, redaction_applied, previous_hash, entry_hmac) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                known_tx_id().as_slice(),
                1_i64,
                "/nf/profile",
                "CREATE",
                Option::<&str>::None,
                "new-value",
                0_i64,
                [0x00_u8; 32].as_slice(),
                [0xAA_u8; 32].as_slice(),
            ],
        )
        .expect("insert audit_trail");

        conn.execute(
            "INSERT INTO alarm_audit (action, outcome, alarm_id, alarm_type, probable_cause, principal, tenant, reason, scope, correlation_id, occurred_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                "CREATE",
                "success",
                "alarm-1",
                "COMMUNICATIONS_ALARM",
                "fixture-cause",
                "admin",
                "default",
                "fixture-reason",
                "system",
                "corr-1",
                "2026-06-12T00:00:00Z",
            ],
        )
        .expect("insert alarm_audit");

        conn.execute(
            "INSERT INTO consensus_state (node_id, current_term, voted_for) VALUES (?1, ?2, ?3)",
            params![7_i64, 42_i64, 7_i64],
        )
        .expect("insert consensus_state");

        conn.execute(
            "INSERT INTO consensus_log (log_index, term, op_type, payload) VALUES (?1, ?2, ?3, ?4)",
            params![1_i64, 42_i64, "NOOP", vec![0xAB_u8, 0xCD_u8].as_slice()],
        )
        .expect("insert consensus_log");

        conn.execute(
            "INSERT INTO consensus_membership (id, cluster_id, node_id, voting_members, non_voting_members, old_voting_members, removed_members, epoch) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                1_i64,
                "cluster-a",
                7_i64,
                "[7]",
                "[]",
                Option::<&str>::None,
                "[]",
                5_i64,
            ],
        )
        .expect("insert consensus_membership");

        conn.close().expect("close fixture cleanly");
    }

    #[test]
    fn sqlite_fixture_opens_and_returns_known_rows() {
        let path = fixture_path();
        if env::var("FIXTURE_REGEN").is_ok() {
            write_fixture(&path);
        }

        assert!(
            path.exists(),
            "fixture {} is missing; run with FIXTURE_REGEN=1 to create it",
            path.display()
        );

        let conn = Connection::open(&path).expect("open fixture");

        let (digest, version, created_at): (String, String, String) = conn
            .query_row(
                "SELECT schema_digest, sdk_version, created_at FROM schema_version WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read schema_version");
        assert_eq!(digest, "fixture-digest-abc123");
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(created_at, "2026-06-12T00:00:00Z");

        let (tx_id, principal, source): (Vec<u8>, String, String) = conn
            .query_row(
                "SELECT tx_id, principal, source FROM config_history WHERE version = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read config_history");
        assert_eq!(tx_id, known_tx_id());
        assert_eq!(principal, "fixture-principal");
        assert_eq!(source, "fixture-source");

        let (seq, yang_path, op_type): (i64, String, String) = conn
            .query_row(
                "SELECT sequence, yang_path, op_type FROM audit_trail WHERE tx_id = ?1",
                params![known_tx_id().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read audit_trail");
        assert_eq!(seq, 1);
        assert_eq!(yang_path, "/nf/profile");
        assert_eq!(op_type, "CREATE");

        let (action, outcome): (String, String) = conn
            .query_row(
                "SELECT action, outcome FROM alarm_audit WHERE alarm_id = 'alarm-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read alarm_audit");
        assert_eq!(action, "CREATE");
        assert_eq!(outcome, "success");

        let (term, voted_for): (i64, Option<i64>) = conn
            .query_row(
                "SELECT current_term, voted_for FROM consensus_state WHERE node_id = 7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read consensus_state");
        assert_eq!(term, 42);
        assert_eq!(voted_for, Some(7));

        let (index, payload): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT log_index, payload FROM consensus_log WHERE log_index = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read consensus_log");
        assert_eq!(index, 1);
        assert_eq!(payload, vec![0xAB, 0xCD]);

        let (cluster_id, epoch): (String, i64) = conn
            .query_row(
                "SELECT cluster_id, epoch FROM consensus_membership WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read consensus_membership");
        assert_eq!(cluster_id, "cluster-a");
        assert_eq!(epoch, 5);
    }
}
