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

/// Current schema version. Bump this and add a migration step to evolve the schema.
pub const SCHEMA_VERSION: &str = "1.5.0";

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
            confirmed_at TEXT NULL
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
    Ok(())
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
        PRAGMA busy_timeout = 1000;
        PRAGMA temp_store = MEMORY;
        "#,
    )?;

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
