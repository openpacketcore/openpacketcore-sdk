//! Durable SQLite implementation of the storage and lease APIs.
//!
//! Intended for single-node and edge/single-replica profiles: it provides
//! transactional fenced CAS, monotonic per-key fences, server-side lease
//! expiry, and per-key TTL on one local database file (WAL mode, full sync).
//! Replication-log application and watch are implemented so a SQLite node
//! can serve as a quorum replica, but the backend deliberately does not
//! advertise `ordered_replication_log`/`watch` capabilities and therefore
//! fails validation for the `replicated-disaster-recovery` profile on its
//! own.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension};

use crate::{
    backend::{
        CompareAndSet, CompareAndSetResult, ReplicationEntry, SessionBackend, SessionOp,
        SessionOpResult,
    },
    capability::BackendCapabilities,
    clock::Clock,
    error::{LeaseError, StoreError},
    lease::{LeaseGuard, SessionLeaseManager},
    model::{OwnerId, SessionKey},
    record::StoredSessionRecord,
    restore::{RestoreScanPage, RestoreScanRequest},
};

pub(crate) mod lease;
pub(crate) mod ops;
pub(crate) mod replication;
pub(crate) mod watch;

const SQLITE_SESSION_MAX_VALUE_BYTES: usize = 1_048_576;

/// SQLite-backed durable session backend and lease manager.
///
/// This backend is intended for single-node and edge/single-replica profiles. It
/// provides durable CAS, fencing, leases, TTL refresh, and sequential batch
/// operations, but it does not provide a backend watch stream or ordered
/// replication log.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct SqliteSessionBackend {
    conn: Arc<tokio::sync::Mutex<Connection>>,
    caps: BackendCapabilities,
    clock: Arc<dyn Clock>,
    watchers: Arc<
        tokio::sync::Mutex<
            Vec<tokio::sync::mpsc::UnboundedSender<Result<ReplicationEntry, StoreError>>>,
        >,
    >,
}

impl SqliteSessionBackend {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn =
            Connection::open(path).map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Self::new_with_conn(conn, false)
    }

    /// Open an ephemeral in-memory SQLite database.
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Self::new_with_conn(conn, true)
    }

    fn new_with_conn(conn: Connection, in_memory: bool) -> Result<Self, StoreError> {
        apply_pragma_profile(&conn, in_memory)?;

        // Create table for storing session records
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS session_records (
                tenant TEXT NOT NULL,
                nf_kind TEXT NOT NULL,
                key_type TEXT NOT NULL,
                stable_id BLOB NOT NULL,
                generation INTEGER NOT NULL,
                owner TEXT NOT NULL,
                fence INTEGER NOT NULL,
                state_class TEXT NOT NULL,
                state_type TEXT NOT NULL,
                expires_at TEXT,
                payload BLOB NOT NULL,
                encoding INTEGER NOT NULL,
                PRIMARY KEY (tenant, nf_kind, key_type, stable_id)
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        // Create table for storing lease entries
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS leases (
                tenant TEXT NOT NULL,
                nf_kind TEXT NOT NULL,
                key_type TEXT NOT NULL,
                stable_id BLOB NOT NULL,
                active INTEGER NOT NULL,
                credential_id INTEGER NOT NULL,
                owner TEXT NOT NULL,
                fence INTEGER NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                guard_expires_at TEXT NOT NULL,
                PRIMARY KEY (tenant, nf_kind, key_type, stable_id)
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        // Create table for key fences
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS key_fences (
                tenant TEXT NOT NULL,
                nf_kind TEXT NOT NULL,
                key_type TEXT NOT NULL,
                stable_id BLOB NOT NULL,
                fence INTEGER NOT NULL,
                PRIMARY KEY (tenant, nf_kind, key_type, stable_id)
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        // Create table for lease globals (credential ID, global fence sequence)
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS lease_globals (
                key TEXT PRIMARY KEY,
                val INTEGER NOT NULL
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        conn.execute(
            "INSERT OR IGNORE INTO lease_globals (key, val) VALUES ('next_fence', 1);",
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        conn.execute(
            "INSERT OR IGNORE INTO lease_globals (key, val) VALUES ('next_credential_id', 1);",
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        // Create table for replication logs
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS session_replication_log (
                sequence INTEGER PRIMARY KEY,
                tx_id TEXT NOT NULL,
                entry_json TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        Ok(Self {
            conn: Arc::new(tokio::sync::Mutex::new(conn)),
            caps: sqlite_capabilities(),
            clock: Arc::new(crate::clock::SystemClock),
            watchers: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        })
    }

    /// Replace the default `SystemClock`.
    ///
    /// The clock drives record TTL expiry and server-side lease expiry
    /// checks; substituting a virtual clock makes expiry behavior testable
    /// without real waiting. Has no effect on rows already written — only on
    /// how their deadlines are evaluated.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

fn sqlite_capabilities() -> BackendCapabilities {
    BackendCapabilities {
        atomic_compare_and_set: true,
        monotonic_fencing_token: true,
        per_key_ttl: true,
        server_side_lease_expiry: true,
        ordered_replication_log: false,
        batch_write: true,
        watch: false,
        max_value_bytes: SQLITE_SESSION_MAX_VALUE_BYTES,
    }
}

fn apply_pragma_profile(conn: &Connection, in_memory: bool) -> Result<(), StoreError> {
    if in_memory {
        conn.execute_batch(
            r#"
            PRAGMA synchronous = EXTRA;
            PRAGMA foreign_keys = ON;
            PRAGMA locking_mode = NORMAL;
            PRAGMA busy_timeout = 5000;
            PRAGMA temp_store = MEMORY;
            "#,
        )
    } else {
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = EXTRA;
            PRAGMA foreign_keys = ON;
            PRAGMA locking_mode = NORMAL;
            PRAGMA busy_timeout = 5000;
            PRAGMA temp_store = MEMORY;
            "#,
        )
    }
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    let foreign_keys: i32 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    if foreign_keys != 1 {
        return Err(StoreError::BackendUnavailable(
            "failed to enable SQLite foreign key enforcement".into(),
        ));
    }

    if !in_memory {
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::BackendUnavailable(format!(
                "failed to enable SQLite WAL journal mode: {journal_mode}"
            )));
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionBackend Implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl SessionBackend for SqliteSessionBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        self.caps
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        ops::get_sync(&conn, key, now)
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        let res = ops::compare_and_set_sync(&tx, op, &self.caps, now)?;
        tx.commit()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok(res)
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        ops::delete_fenced_sync(&tx, lease, &self.caps, now)?;
        tx.commit()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok(())
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        ops::refresh_ttl_sync(&tx, lease, ttl, &self.caps, now)?;
        tx.commit()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok(())
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        if !self.caps.batch_write {
            return Err(StoreError::CapabilityNotSupported("batch_write".into()));
        }

        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            let res = match op {
                SessionOp::Get { key } => SessionOpResult::Get(ops::get_sync(&conn, &key, now)),
                SessionOp::CompareAndSet(cas) => {
                    let run_cas = || {
                        let tx = conn
                            .unchecked_transaction()
                            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                        let res = ops::compare_and_set_sync(&tx, cas, &self.caps, now)?;
                        tx.commit()
                            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                        Ok(res)
                    };
                    SessionOpResult::CompareAndSet(run_cas())
                }
                SessionOp::DeleteFenced { lease } => {
                    let run_del = || {
                        let tx = conn
                            .unchecked_transaction()
                            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                        ops::delete_fenced_sync(&tx, &lease, &self.caps, now)?;
                        tx.commit()
                            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                        Ok(())
                    };
                    SessionOpResult::DeleteFenced(run_del())
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    let run_ref = || {
                        let tx = conn
                            .unchecked_transaction()
                            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                        ops::refresh_ttl_sync(&tx, &lease, ttl, &self.caps, now)?;
                        tx.commit()
                            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                        Ok(())
                    };
                    SessionOpResult::RefreshTtl(run_ref())
                }
            };
            results.push(res);
        }
        Ok(results)
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        ops::scan_restore_records_sync(&conn, request, now)
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        let conn = self.conn.lock().await;
        let seq: Option<Option<i64>> = conn
            .query_row(
                "SELECT MAX(sequence) FROM session_replication_log",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok(seq.flatten().unwrap_or(0) as u64)
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT entry_json FROM session_replication_log WHERE sequence >= ?1 ORDER BY sequence ASC LIMIT ?2"
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        let entries = stmt
            .query_map(params![start as i64, limit as i64], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        let mut res = Vec::new();
        for item in entries {
            let json = item.map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            let entry: ReplicationEntry = serde_json::from_str(&json)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            res.push(entry);
        }
        Ok(res)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let should_notify = {
            let conn = self.conn.lock().await;
            let now = self.clock.now_utc();
            replication::replicate_entry_sync(&conn, &entry, &self.caps, now)?
        };

        if should_notify {
            let watchers = self.watchers.lock().await;
            for watcher in watchers.iter() {
                let _ = watcher.send(Ok(entry.clone()));
            }
        }

        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        replication::rebuild_replication_state_sync(&conn, &entries, &self.caps)
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // Query existing entries starting from start_sequence
        let existing = self.get_replication_log(start_sequence, 10000).await?;
        for entry in existing {
            let _ = tx.send(Ok(entry));
        }

        let mut watchers = self.watchers.lock().await;
        watchers.push(tx);

        use futures_util::StreamExt;
        let stream = watch::SqliteWatchStream { rx };
        Ok(stream.boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        let conn = self.conn.lock().await;
        let mut global_stmt = conn
            .prepare("SELECT val FROM lease_globals WHERE key = ?1")
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        let next_fence: i64 = global_stmt
            .query_row(["next_fence"], |row| row.get(0))
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        let next_credential_id: i64 = global_stmt
            .query_row(["next_credential_id"], |row| row.get(0))
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok((next_fence as u64, next_credential_id as u64))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionLeaseManager Implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl SessionLeaseManager for SqliteSessionBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        let res = lease::acquire_sync(&tx, key, owner, ttl, now)?;
        tx.commit()
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        Ok(res)
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        let res = lease::renew_sync(&tx, lease, ttl, now)?;
        tx.commit()
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        Ok(res)
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        lease::release_sync(&tx, lease, now)?;
        tx.commit()
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        Ok(())
    }
}
