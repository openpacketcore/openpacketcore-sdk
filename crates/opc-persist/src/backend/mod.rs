//! SQLite-backed [`ConfigStore`] implementation.
//!
//! ## Thread Safety
//!
//! This implementation uses a `tokio::sync::Mutex` to protect a single
//! synchronous SQLite connection. All database operations are synchronous
//! (rusqlite does not provide an async API). The mutex enforces a hard
//! one-operation-at-a-time cap across all concurrent async tasks, and the SQLite
//! busy timeout is capped at [`SqliteBackend::SQLITE_BUSY_TIMEOUT_MS`] so a lock
//! wait cannot pin a shared runtime worker for an unbounded or multi-second
//! interval. This bounded profile is intentional for the management-plane
//! single-replica reference backend.
//!
//! ## Atomicity
//!
//! `append_commit` uses a SQLite transaction to make the commit record and all
//! audit records co-durable. If the process crashes mid-commit, SQLite's WAL
//! recovery will roll back to the last consistent state.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::PersistError;
use crate::preflight::PersistCapabilities;
use crate::schema;
use crate::types::{extract_tenant, AuditKey, AuditOpType, AuditRecord, CommitSource};
use opc_types::TxId;

mod ops;
mod replication;

type StoredConfigRow = (
    Vec<u8>,
    Option<Vec<u8>>,
    i64,
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i32,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    Vec<u8>,
);

/// Convert a 16-byte slice to a Uuid. Returns zero Uuid if the slice is shorter
/// than 16 bytes (graceful degradation, not panic).
pub(crate) fn uuid_from_bytes(bytes: &[u8]) -> Uuid {
    let n = bytes.len().min(16);
    let mut buf = [0u8; 16];
    buf[..n].copy_from_slice(&bytes[..n]);
    Uuid::from_bytes(buf)
}

/// Validate that a byte slice is exactly 16 bytes for use as a Uuid.
/// Returns `PersistError::corrupt_blob()` if the length is wrong.
pub(crate) fn validate_uuid_bytes(name: &str, bytes: &[u8]) -> Result<(), PersistError> {
    if bytes.len() != 16 {
        warn!(
            field = name,
            actual_len = bytes.len(),
            "corrupt UUID blob length in persisted state"
        );
        return Err(PersistError::corrupt_blob());
    }
    Ok(())
}

/// Deserialize a CommitSource from a DB-stored lowercase string.
/// Returns `PersistError::inconsistent_state()` if the value is unrecognized.
pub(crate) fn deserialize_commit_source(source: &str) -> Result<CommitSource, PersistError> {
    match source {
        "gnmi" => Ok(CommitSource::Gnmi),
        "netconf" => Ok(CommitSource::Netconf),
        "local_operator" => Ok(CommitSource::LocalOperator),
        "startup_restore" => Ok(CommitSource::StartupRestore),
        "rollback" => Ok(CommitSource::Rollback),
        "commit_confirmed_restore" => Ok(CommitSource::CommitConfirmedRestore),
        _ => Err(PersistError::inconsistent_state(
            "unrecognized CommitSource in config_history",
        )),
    }
}

/// Deserialize an AuditOpType from a DB-stored uppercase string.
/// Returns `PersistError::corrupt_blob()` if the value is unrecognized.
pub(crate) fn deserialize_audit_op_type(s: &str) -> Result<AuditOpType, PersistError> {
    match s {
        "CREATE" => Ok(AuditOpType::Create),
        "UPDATE" => Ok(AuditOpType::Update),
        "REPLACE" => Ok(AuditOpType::Replace),
        "DELETE" => Ok(AuditOpType::Delete),
        unknown => {
            warn!(op_type = unknown, "unknown audit op_type in database");
            Err(PersistError::corrupt_blob())
        }
    }
}

/// SQLite-backed ConfigStore suitable for the reference management-plane store.
///
/// Created via [`SqliteBackend::open`] or `SqliteBackend::in_memory_for_test`.
#[derive(Debug, Clone)]
pub struct SqliteBackend {
    /// Path to the database (for preflight reporting).
    db_path: PathBuf,
    /// Ephemeral mode: skip durability checks.
    ephemeral: bool,
    /// Minimum free bytes required on the volume.
    min_free_bytes: u64,
    /// The shared database connection protected by an async mutex.
    /// All DB operations hold this lock for the duration of the call.
    conn: Arc<AsyncMutex<rusqlite::Connection>>,
    /// Audit HMAC key used to seal and verify local audit-trail rows.
    audit_key: Arc<AuditKey>,
    /// Cached preflight result (populated after first successful preflight).
    cached_caps: std::sync::OnceLock<PersistCapabilities>,
}

impl SqliteBackend {
    /// Hard cap enforced by the single SQLite connection mutex.
    pub const MAX_CONCURRENT_DB_OPERATIONS: usize = 1;
    /// Maximum time SQLite may busy-wait on this backend connection.
    pub const SQLITE_BUSY_TIMEOUT_MS: u32 = schema::SQLITE_BUSY_TIMEOUT_MS;

    const EPHEMERAL_AUDIT_KEY_BYTES: [u8; 32] = [0xA5; 32];

    /// Open (or create) a SQLite database at the given path.
    ///
    /// The directory must exist. If `ephemeral` is true, durability preflight
    /// checks are skipped and the store may be used with tmpfs or in-memory
    /// databases.
    ///
    /// # Behavioral Notes
    ///
    /// The `:memory:` path is **always** treated as ephemeral regardless of the
    /// `ephemeral` flag. Passing `ephemeral=false` with `:memory:` is explicitly
    /// rejected at this entry point to prevent a backend whose `ephemeral` struct
    /// field contradicts its reported `PersistCapabilities::ephemeral_mode`. SQLite
    /// itself forces `journal_mode=memory` for in-memory databases — WAL is not
    /// applicable — but `synchronous=EXTRA` is still applied via the pragma profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened, the schema cannot be
    /// initialized, or the WAL pragma profile cannot be applied.
    pub async fn open(
        path: impl Into<PathBuf>,
        ephemeral: bool,
        min_free_bytes: u64,
    ) -> Result<Self, PersistError> {
        let path = path.into();
        if !ephemeral && !Self::is_in_memory_database(&path) {
            return Err(PersistError::preflight_failed(
                "durable SQLite backend requires an explicit audit HMAC key; use open_with_audit_key",
            ));
        }

        Self::open_inner(
            path,
            ephemeral,
            min_free_bytes,
            AuditKey::from_static_test_bytes(Self::EPHEMERAL_AUDIT_KEY_BYTES),
        )
        .await
    }

    /// Open (or create) a durable SQLite database with an explicit audit HMAC key.
    ///
    /// Production callers must use this constructor so audit-trail rows are
    /// sealed with deployment-owned key material rather than a development key.
    pub async fn open_with_audit_key(
        path: impl Into<PathBuf>,
        ephemeral: bool,
        min_free_bytes: u64,
        audit_key: AuditKey,
    ) -> Result<Self, PersistError> {
        Self::open_inner(path.into(), ephemeral, min_free_bytes, audit_key).await
    }

    pub fn audit_key(&self) -> &AuditKey {
        &self.audit_key
    }

    pub fn conn(&self) -> Arc<AsyncMutex<rusqlite::Connection>> {
        self.conn.clone()
    }

    async fn open_inner(
        path: PathBuf,
        ephemeral: bool,
        min_free_bytes: u64,
        audit_key: AuditKey,
    ) -> Result<Self, PersistError> {
        // Reject contradictory combination: :memory: is always ephemeral, so
        // passing ephemeral=false with :memory: would create a backend with a
        // self.ephemeral field that contradicts its reported capabilities.
        if Self::is_in_memory_database(&path) && !ephemeral {
            return Err(PersistError::preflight_failed(
                "`:memory:` path is always ephemeral; pass ephemeral=true or use a file path",
            ));
        }

        // Pre-open: run storage preflight on the directory
        let caps = Self::run_preflight(&path, ephemeral, min_free_bytes).await?;
        if !caps.is_safe_for_writes() && !ephemeral {
            return Err(PersistError::new(
                crate::error::PersistErrorKind::PreflightFailed(
                    "storage preflight failed — unsafe for durable writes".into(),
                ),
            ));
        }

        let conn = Self::open_connection(&path, &audit_key)?;

        let backend = Self {
            db_path: path,
            ephemeral,
            min_free_bytes,
            conn: Arc::new(AsyncMutex::new(conn)),
            audit_key: Arc::new(audit_key),
            cached_caps: std::sync::OnceLock::new(),
        };

        // Cache the preflight result
        let _ = backend.cached_caps.set(caps);

        Ok(backend)
    }

    /// Create an in-memory database for testing (non-durable).
    #[cfg(test)]
    pub async fn in_memory_for_test() -> Result<Self, PersistError> {
        Self::open(std::path::PathBuf::from(":memory:"), true, 0).await
    }

    fn open_connection(
        path: &Path,
        audit_key: &AuditKey,
    ) -> Result<rusqlite::Connection, PersistError> {
        let in_memory = Self::is_in_memory_database(path);
        let conn = if in_memory {
            rusqlite::Connection::open_in_memory()
        } else {
            rusqlite::Connection::open(path)
        }
        .map_err(|e| PersistError::sqlite(e.to_string()))?;

        // Apply the WAL pragma profile first
        schema::apply_pragma_profile(&conn).map_err(|e| PersistError::sqlite(e.to_string()))?;
        if !in_memory
            && !schema::verify_wal_mode(&conn).map_err(|e| PersistError::sqlite(e.to_string()))?
        {
            return Err(PersistError::sqlite(
                "failed to verify WAL journal_mode".to_string(),
            ));
        }
        if !in_memory
            && !schema::verify_synchronous_extra(&conn)
                .map_err(|e| PersistError::sqlite(e.to_string()))?
        {
            return Err(PersistError::sqlite(
                "failed to verify synchronous=EXTRA".to_string(),
            ));
        }

        schema::initialize_schema(&conn).map_err(|e| PersistError::sqlite(e.to_string()))?;

        let current_version =
            schema::get_schema_version(&conn).map_err(|e| PersistError::sqlite(e.to_string()))?;
        let current_digest =
            schema::get_schema_digest(&conn).map_err(|e| PersistError::sqlite(e.to_string()))?;

        match (current_version.as_deref(), current_digest.as_deref()) {
            (Some(schema::SCHEMA_VERSION), Some(digest)) => {
                debug!(schema_digest = %digest, "existing database schema found");
            }
            (Some("1.0.0"), _)
            | (Some("1.1.0"), _)
            | (Some("1.2.0"), _)
            | (Some("1.3.0"), _)
            | (Some("1.4.0"), _)
            | (Some("1.5.0"), _)
            | (Some("1.6.0"), _)
            | (Some("1.7.0"), _)
            | (None, _) => {
                if let Some(from_version) = current_version.as_deref() {
                    schema::run_migrations(&conn, from_version)
                        .map_err(|e| PersistError::sqlite(e.to_string()))?;
                }
                Self::reseal_audit_chains_for_schema_1_6(&conn, audit_key)?;
                let tx = conn
                    .unchecked_transaction()
                    .map_err(|e| PersistError::sqlite(e.to_string()))?;
                let digest = Self::current_schema_digest();
                schema::set_schema_version(&tx, &digest)
                    .map_err(|e| PersistError::sqlite(e.to_string()))?;
                tx.commit()
                    .map_err(|e| PersistError::sqlite(e.to_string()))?;
            }
            (Some(found), _) => {
                return Err(PersistError::schema_version_mismatch(
                    schema::SCHEMA_VERSION,
                    found.to_string(),
                ));
            }
        }

        info!(path = %path.display(), "SQLite backend opened");
        Ok(conn)
    }

    fn reseal_audit_chains_for_schema_1_6(
        conn: &rusqlite::Connection,
        audit_key: &AuditKey,
    ) -> Result<(), PersistError> {
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let configs = {
            let mut stmt = tx
                .prepare("SELECT tx_id, principal FROM config_history ORDER BY version ASC")
                .map_err(|e| PersistError::sqlite(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| PersistError::sqlite(e.to_string()))?;

            let mut configs = Vec::new();
            for row in rows {
                configs.push(row.map_err(|e| PersistError::sqlite(e.to_string()))?);
            }
            configs
        };

        for (tx_id_bytes, principal) in configs {
            validate_uuid_bytes("config_history tx_id", &tx_id_bytes)?;
            let tx_id = TxId::from_uuid(uuid_from_bytes(&tx_id_bytes));
            let tenant = extract_tenant(&principal);
            let mut audit = Self::load_audit_rows_for_reseal(&tx, tx_id, &tx_id_bytes)?;
            let audit_count =
                u32::try_from(audit.len()).map_err(|_| PersistError::audit_chain_broken())?;

            if !Self::audit_chain_verifies_with_count(&audit, audit_key, &tenant, audit_count) {
                Self::verify_legacy_audit_chain(&audit, audit_key, &tenant)?;
                let mut prev_hash = [0u8; 32];
                for entry in &mut audit {
                    entry.previous_hash = prev_hash;
                    entry.entry_hmac =
                        entry.calculate_hmac_with_audit_count(audit_key, &tenant, audit_count);
                    tx.execute(
                        "UPDATE audit_trail SET previous_hash = ?3, entry_hmac = ?4 WHERE tx_id = ?1 AND sequence = ?2",
                        rusqlite::params![
                            tx_id_bytes.as_slice(),
                            entry.sequence,
                            &entry.previous_hash[..],
                            &entry.entry_hmac[..],
                        ],
                    )
                    .map_err(|e| PersistError::sqlite(e.to_string()))?;
                    prev_hash = entry.entry_hmac;
                }
            }

            let terminal_hash = audit
                .last()
                .map(|entry| entry.entry_hmac)
                .unwrap_or([0u8; 32]);
            tx.execute(
                "UPDATE config_history SET audit_count = ?2, audit_terminal_hash = ?3 WHERE tx_id = ?1",
                rusqlite::params![
                    tx_id_bytes.as_slice(),
                    audit_count as i64,
                    &terminal_hash[..],
                ],
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        Ok(())
    }

    fn load_audit_rows_for_reseal(
        conn: &rusqlite::Connection,
        tx_id: TxId,
        tx_id_bytes: &[u8],
    ) -> Result<Vec<AuditRecord>, PersistError> {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT sequence, yang_path, op_type, previous_value, new_value,
                       redaction_applied, previous_hash, entry_hmac
                FROM audit_trail
                WHERE tx_id = ?1
                ORDER BY sequence ASC
                "#,
            )
            .map_err(|e| PersistError::sqlite(e.to_string()))?;
        let rows = stmt
            .query_map([tx_id_bytes], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i32>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            })
            .map_err(|e| PersistError::sqlite(e.to_string()))?;

        let mut audit = Vec::new();
        for row in rows {
            let (
                sequence,
                yang_path,
                op_type,
                previous_value,
                new_value,
                redaction_applied,
                previous_hash,
                entry_hmac,
            ) = row.map_err(|e| PersistError::sqlite(e.to_string()))?;
            if previous_hash.len() != 32 || entry_hmac.len() != 32 {
                return Err(PersistError::corrupt_blob());
            }
            audit.push(AuditRecord {
                tx_id,
                sequence,
                yang_path,
                op_type: deserialize_audit_op_type(&op_type)?,
                previous_value,
                new_value,
                redaction_applied: redaction_applied != 0,
                previous_hash: previous_hash
                    .try_into()
                    .expect("previous_hash length validated above"),
                entry_hmac: entry_hmac
                    .try_into()
                    .expect("entry_hmac length validated above"),
            });
        }
        Ok(audit)
    }

    fn audit_chain_verifies_with_count(
        audit: &[AuditRecord],
        audit_key: &AuditKey,
        tenant: &str,
        audit_count: u32,
    ) -> bool {
        let mut prev_hash = [0u8; 32];
        for entry in audit {
            if entry.previous_hash != prev_hash {
                return false;
            }
            if entry.entry_hmac
                != entry.calculate_hmac_with_audit_count(audit_key, tenant, audit_count)
            {
                return false;
            }
            prev_hash = entry.entry_hmac;
        }
        true
    }

    fn verify_legacy_audit_chain(
        audit: &[AuditRecord],
        audit_key: &AuditKey,
        tenant: &str,
    ) -> Result<(), PersistError> {
        let mut prev_hash = [0u8; 32];
        for entry in audit {
            if entry.previous_hash != prev_hash {
                return Err(PersistError::audit_chain_broken());
            }
            if entry.entry_hmac != entry.calculate_hmac(audit_key, tenant) {
                return Err(PersistError::audit_chain_broken());
            }
            prev_hash = entry.entry_hmac;
        }
        Ok(())
    }

    fn is_in_memory_database(path: &Path) -> bool {
        path == Path::new(":memory:")
    }

    /// SHA-256 of the current schema SQL — used as the schema digest.
    fn current_schema_digest() -> String {
        let sql = r#"
        CREATE TABLE schema_version (id INTEGER PRIMARY KEY CHECK (id = 1), schema_digest TEXT NOT NULL, sdk_version TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE config_history (tx_id BLOB PRIMARY KEY, parent_tx_id BLOB NULL, version INTEGER NOT NULL UNIQUE, committed_at TEXT NOT NULL, principal TEXT NOT NULL, source TEXT NOT NULL, schema_digest BLOB NOT NULL, plaintext_digest BLOB NOT NULL, encrypted_blob BLOB NOT NULL, rollback_point INTEGER NOT NULL DEFAULT 0, rollback_label TEXT NULL, confirmed_deadline TEXT NULL, confirmed_at TEXT NULL, audit_count INTEGER NOT NULL DEFAULT 0, audit_terminal_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000');
        CREATE TABLE audit_trail (id INTEGER PRIMARY KEY AUTOINCREMENT, tx_id BLOB NOT NULL, sequence INTEGER NOT NULL, yang_path TEXT NOT NULL, op_type TEXT NOT NULL, previous_value TEXT NULL, new_value TEXT NULL, redaction_applied INTEGER NOT NULL DEFAULT 0, previous_hash BLOB NOT NULL, entry_hmac BLOB NOT NULL, UNIQUE(tx_id, sequence));
        CREATE TABLE config_lifecycle_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, tx_id BLOB NOT NULL, action TEXT NOT NULL, principal TEXT NOT NULL, occurred_at TEXT NOT NULL, details TEXT NOT NULL);
        CREATE TABLE rollback_labels (label TEXT PRIMARY KEY, tx_id BLOB NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE alarm_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, outcome TEXT NOT NULL, alarm_id TEXT NOT NULL, alarm_type TEXT NOT NULL, probable_cause TEXT NOT NULL, principal TEXT NOT NULL, tenant TEXT NULL, reason TEXT NOT NULL, scope TEXT NOT NULL, correlation_id TEXT NULL, occurred_at TEXT NOT NULL);
        CREATE TABLE consensus_state (node_id INTEGER PRIMARY KEY, current_term INTEGER NOT NULL, voted_for INTEGER NULL);
        CREATE TABLE consensus_log (log_index INTEGER PRIMARY KEY, term INTEGER NOT NULL, op_type TEXT NOT NULL, payload BLOB NOT NULL);
        CREATE TABLE consensus_applied (id INTEGER PRIMARY KEY CHECK (id = 1), applied_index INTEGER NOT NULL);
        CREATE TABLE consensus_membership (id INTEGER PRIMARY KEY CHECK (id = 1), cluster_id TEXT NOT NULL, node_id INTEGER NOT NULL, voting_members TEXT NOT NULL, non_voting_members TEXT NOT NULL, old_voting_members TEXT NULL, removed_members TEXT NOT NULL, epoch INTEGER NOT NULL);
        CREATE TABLE consensus_snapshot (id INTEGER PRIMARY KEY CHECK (id = 1), snapshot_index INTEGER NOT NULL, snapshot_term INTEGER NOT NULL, snapshot_data BLOB NOT NULL);
        CREATE TABLE staged_security_policy (tenant TEXT PRIMARY KEY, version INTEGER NOT NULL, staged_at TEXT NOT NULL, principal TEXT NOT NULL, encrypted_blob BLOB NOT NULL);
        CREATE TABLE security_policy_active (tenant TEXT PRIMARY KEY, version INTEGER NOT NULL, applied_at TEXT NOT NULL, principal TEXT NOT NULL, encrypted_blob BLOB NOT NULL);
        CREATE TABLE security_policy_history (tenant TEXT NOT NULL, version INTEGER NOT NULL, applied_at TEXT NOT NULL, principal TEXT NOT NULL, encrypted_blob BLOB NOT NULL, tx_id BLOB NULL, label TEXT NULL, PRIMARY KEY (tenant, version));
        CREATE TABLE security_policy_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, timestamp TEXT NOT NULL, principal TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL, previous_hash BLOB NOT NULL, entry_hmac BLOB NOT NULL);
        CREATE TABLE security_policy_audit_anchor (tenant TEXT PRIMARY KEY, audit_count INTEGER NOT NULL DEFAULT 0, audit_terminal_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000');
        CREATE TABLE break_glass_sessions (id TEXT PRIMARY KEY, principal TEXT NOT NULL, tenant TEXT NOT NULL, reason TEXT NOT NULL, scope TEXT NOT NULL, requested_duration INTEGER NOT NULL, evidence_id TEXT NOT NULL, status TEXT NOT NULL, requested_at TEXT NOT NULL, approved_at TEXT, approver TEXT, activated_at TEXT, expires_at TEXT, denied_at TEXT, revoked_at TEXT, revoker TEXT);
        CREATE TABLE break_glass_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, timestamp TEXT NOT NULL, principal TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL, previous_hash BLOB NOT NULL, entry_hmac BLOB NOT NULL);
        CREATE TABLE break_glass_audit_anchor (tenant TEXT PRIMARY KEY, audit_count INTEGER NOT NULL DEFAULT 0, audit_terminal_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000');
        "#;
        let mut hasher = Sha256::new();
        hasher.update(sql.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    async fn run_preflight(
        path: &Path,
        ephemeral: bool,
        min_free_bytes: u64,
    ) -> Result<PersistCapabilities, PersistError> {
        if Self::is_in_memory_database(path) {
            // SQLite always uses journal_mode=memory for true in-memory databases;
            // WAL is not applicable. Report the actual configuration, not the generic
            // ephemeral-path defaults.
            return Ok(PersistCapabilities {
                ephemeral_mode: true,
                storage_path: ":memory:".into(),
                fsync_available: true,
                locking_compatible: true,
                same_filesystem: true,
                safe_filesystem: true,
                free_bytes: u64::MAX,
                min_free_bytes: 0,
                directory_permissions_safe: true,
                wal_autocheckpoint_pages: 0,
                journal_mode: "memory".into(),
                // journal_mode is forced to "memory" by SQLite for :memory: databases,
                // but apply_pragma_profile still sets synchronous=EXTRA — report that.
                synchronous_setting: "extra".into(),
                foreign_keys_on: true,
                wal_mode: false,
            });
        }

        if ephemeral {
            // Ephemeral (non-durable) file-backed path — skip safety checks but
            // still apply the full WAL pragma profile.
            return Ok(PersistCapabilities {
                ephemeral_mode: true,
                storage_path: path.to_string_lossy().into_owned(),
                fsync_available: true,
                locking_compatible: true,
                same_filesystem: true,
                safe_filesystem: true,
                free_bytes: u64::MAX,
                min_free_bytes: 0,
                directory_permissions_safe: true,
                wal_autocheckpoint_pages: 1000,
                journal_mode: "wal".into(),
                synchronous_setting: "extra".into(),
                foreign_keys_on: true,
                wal_mode: true,
            });
        }

        let dir = path.parent().unwrap_or(Path::new("."));
        let storage_path = dir.to_string_lossy().into_owned();

        // Filesystem safety check
        let safe_filesystem = schema::is_safe_filesystem(dir);
        if !safe_filesystem {
            warn!(path = %dir.display(), "preflight: filesystem is a known-unsafe network filesystem");
        }

        // Directory permissions check
        let directory_permissions_safe = schema::is_directory_permissions_safe(dir);
        if !directory_permissions_safe {
            warn!(path = %dir.display(), "preflight: directory has unsafe permissions");
        }

        // Free space check
        let free_bytes = schema::get_free_bytes(dir).unwrap_or(0);
        if free_bytes < min_free_bytes {
            warn!(path = %dir.display(), free_bytes = free_bytes, min_free_bytes = min_free_bytes, "preflight: insufficient free space");
        }

        // fsync availability
        let fsync_available = schema::check_fsync_available(dir);

        // The database file and its WAL/SHM siblings must share one filesystem.
        let same_filesystem = schema::is_same_filesystem(dir, path);
        if !same_filesystem {
            warn!(path = %dir.display(), "preflight: database file and its WAL/SHM directory are on different filesystems");
        }

        // POSIX byte-range locking is unreliable precisely on the network
        // filesystems rejected by is_safe_filesystem; on a safe (local)
        // filesystem it is available. Derive the flag from that real check
        // rather than asserting it unconditionally.
        let locking_compatible = safe_filesystem;

        Ok(PersistCapabilities {
            ephemeral_mode: false,
            storage_path,
            fsync_available,
            locking_compatible,
            same_filesystem,
            safe_filesystem,
            free_bytes,
            min_free_bytes,
            directory_permissions_safe,
            wal_autocheckpoint_pages: 1000,
            journal_mode: "wal".into(),
            synchronous_setting: "extra".into(),
            foreign_keys_on: true,
            wal_mode: true,
        })
    }
}
