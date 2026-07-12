//! Durable SQLite implementation of the storage and lease APIs.
//!
//! Intended for single-node and edge/single-replica profiles: it provides
//! transactional fenced CAS, monotonic per-key fences, server-side lease
//! expiry, and per-key TTL on one local database file (WAL mode, full sync).
//! Application-journal replay and watch remain for standalone compatibility.
//! Once the durable consensus identity claims a database, every public raw
//! backend operation fails closed; Openraft's internal state-machine adapter
//! is the only mutation and read-authority path.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::{
    backend::{
        validate_replication_page_owned, validate_replication_prefix_owned,
        validate_session_ops_ttls, BackendInstanceIdentity, CompareAndSet, CompareAndSetResult,
        ReplicationEntry, SessionBackend, SessionOp, SessionOpResult, WATCH_CHANNEL_CAPACITY,
    },
    capability::BackendCapabilities,
    clock::Clock,
    error::{LeaseError, StoreError},
    lease::{LeaseGuard, SessionLeaseManager},
    model::{OwnerId, SessionKey},
    record::StoredSessionRecord,
    restore::{RestoreScanPage, RestoreScanRequest},
    ttl::{checked_session_deadline, validate_session_ttl},
};

pub mod audit;
pub(crate) mod consensus;
pub(crate) mod lease;
pub(crate) mod ops;
pub(crate) mod replication;
pub(crate) mod watch;

const SQLITE_SESSION_MAX_VALUE_BYTES: usize = 1_048_576;
const CONSENSUS_AUTHORITY_REQUIRED: &str = "consensus_authority_required";

/// Begin one standalone operation while holding SQLite's write reservation.
///
/// The immediate transaction is the hand-off fence between the standalone
/// backend and consensus admission, including when another process opens the
/// same database through a distinct `Connection`. If consensus admission wins
/// first, the durable identity marker is visible and this operation fails. If
/// this operation wins first, admission waits and then either observes an
/// empty compatible database or rejects its newly written legacy authority.
fn standalone_transaction(conn: &Connection) -> Result<Transaction<'_>, StoreError> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))?;
    let consensus_owned = consensus_identity_exists(&tx)?;
    if consensus_owned || operator_recovery_latch_exists(&tx)? {
        return Err(StoreError::CapabilityNotSupported(
            CONSENSUS_AUTHORITY_REQUIRED.into(),
        ));
    }
    Ok(tx)
}

fn operator_recovery_latch_exists(conn: &Connection) -> Result<bool, StoreError> {
    let database_path: String = conn
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))?;
    if database_path.is_empty() {
        return Ok(false);
    }
    consensus::read_operator_recovery_latch_sync(Path::new(&database_path))
        .map(|latch| latch.is_some())
        .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))
}

fn consensus_identity_exists(conn: &Connection) -> Result<bool, StoreError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'consensus_identity')",
        [],
        |row| row.get(0),
    )
    .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))
}

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
    database_path: Option<Arc<PathBuf>>,
    caps: BackendCapabilities,
    clock: Arc<dyn Clock>,
    watchers: Arc<
        tokio::sync::Mutex<Vec<tokio::sync::mpsc::Sender<Result<ReplicationEntry, StoreError>>>>,
    >,
}

impl SqliteSessionBackend {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let conn = Connection::open(path)
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Self::new_with_conn(conn, false, Some(canonical))
    }

    /// Open an ephemeral in-memory SQLite database.
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Self::new_with_conn(conn, true, None)
    }

    fn new_with_conn(
        conn: Connection,
        in_memory: bool,
        database_path: Option<PathBuf>,
    ) -> Result<Self, StoreError> {
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
                sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
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
            database_path: database_path.map(Arc::new),
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

    /// Capabilities consumed by the consensus adapter that owns this backend.
    pub(crate) const fn consensus_capabilities(&self) -> BackendCapabilities {
        self.caps
    }

    /// Read at a logical timestamp already committed by the consensus state
    /// machine. This path is read-only: expiry affects visibility but never
    /// prunes physical rows outside a committed command.
    pub(crate) async fn consensus_get_at(
        &self,
        key: &SessionKey,
        logical_time: opc_types::Timestamp,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        let conn = self.conn.lock().await;
        let tx = conn
            .unchecked_transaction()
            .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
        let result = ops::get_sync(&tx, key, logical_time)?;
        tx.commit()
            .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
        Ok(result)
    }

    /// Restore scan at one persisted consensus logical timestamp.
    pub(crate) async fn consensus_scan_restore_records_at(
        &self,
        request: RestoreScanRequest,
        logical_time: opc_types::Timestamp,
    ) -> Result<RestoreScanPage, StoreError> {
        let conn = self.conn.lock().await;
        let tx = conn
            .unchecked_transaction()
            .map_err(|_| StoreError::BackendUnavailable("session store scan failed".into()))?;
        let result = ops::scan_restore_records_sync(&tx, request, logical_time)?;
        tx.commit()
            .map_err(|_| StoreError::BackendUnavailable("session store scan failed".into()))?;
        Ok(result)
    }

    /// Read the committed application-journal head after the caller has
    /// completed its Openraft linearizable barrier and local apply wait.
    pub(crate) async fn consensus_max_replication_sequence(&self) -> Result<u64, StoreError> {
        let conn = self.conn.lock().await;
        let seq: i64 = conn
            .query_row(
                "SELECT MAX(machine.watch_sequence, recovery.watch_cursor_invalidation_floor)
                 FROM consensus_machine AS machine
                 JOIN consensus_operator_recovery AS recovery ON recovery.singleton = machine.singleton
                 WHERE machine.singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
        consensus::checked_u64(seq)
            .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))
    }

    /// Whether an offline operator reset is awaiting its Openraft-committed
    /// recovery epoch. A pending replica may exchange Raft traffic and rejoin,
    /// but must not admit ordinary session operations or advertise readiness.
    pub(crate) async fn consensus_operator_recovery_pending(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
    ) -> Result<bool, StoreError> {
        let conn = self.conn.lock().await;
        let database_latch = self
            .database_path
            .as_deref()
            .map(|path| consensus::read_operator_recovery_latch_sync(path))
            .transpose()
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "session operator recovery latch is unavailable".into(),
                )
            })?
            .flatten();
        if let Some(latch) = database_latch {
            if latch.identity != identity {
                return Err(StoreError::BackendUnavailable(
                    "session operator recovery latch identity does not match".into(),
                ));
            }
            opc_redaction::metrics::METRICS
                .session_operator_recovery_required
                .store(1, std::sync::atomic::Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .session_operator_recovery_epoch
                .fetch_max(latch.recovery_epoch, std::sync::atomic::Ordering::Relaxed);
            if latch.audit_pending {
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_audit_pending
                    .store(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        consensus::read_operator_recovery_sync(&conn, identity)
            .map(|state| state.pending_epoch.is_some() || database_latch.is_some())
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "session operator recovery state is unavailable".into(),
                )
            })
    }

    pub(crate) async fn consensus_operator_recovery_committed(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        recovery_epoch: u64,
        plan_digest: [u8; 32],
    ) -> Result<bool, StoreError> {
        let conn = self.conn.lock().await;
        consensus::read_operator_recovery_sync(&conn, identity)
            .map(|state| {
                state.pending_epoch.is_none()
                    && state.recovery_epoch == recovery_epoch
                    && state.last_plan_digest == plan_digest
            })
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "session operator recovery state is unavailable".into(),
                )
            })
    }

    /// Read committed application-journal entries after the caller's Openraft
    /// barrier. This internal path cannot allocate sequencing authority.
    pub(crate) async fn consensus_get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let Ok(sqlite_start) = i64::try_from(start) else {
            return Ok(Vec::new());
        };
        let sqlite_limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.conn.lock().await;
        let invalidation_floor = consensus::read_watch_cursor_invalidation_floor_sync(&conn)
            .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
        if invalidation_floor != 0 && start <= invalidation_floor {
            return Err(StoreError::BackendUnavailable(
                "replication log invalidated before requested start".into(),
            ));
        }
        let mut stmt = conn
            .prepare(
                "SELECT sequence, entry_json FROM session_replication_log WHERE sequence >= ?1 ORDER BY sequence ASC LIMIT ?2",
            )
            .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
        let entries = stmt
            .query_map(params![sqlite_start, sqlite_limit], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
        let mut result = Vec::new();
        for item in entries {
            let (stored_sequence, json) = item
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let stored_sequence = replication::stored_replication_sequence(stored_sequence)?;
            let entry: ReplicationEntry = serde_json::from_str(&json).map_err(|_| {
                StoreError::Serialization("session journal entry is invalid".into())
            })?;
            let entry = entry.into_validated()?;
            if entry.sequence != stored_sequence {
                return Err(StoreError::InvalidReplicationSequence);
            }
            result.push(entry);
        }
        validate_replication_page_owned(result)
    }

    /// Subscribe to the committed application journal. The caller must first
    /// complete an Openraft barrier; this function only reads already-applied
    /// state and registers for later state-machine notifications.
    pub(crate) async fn consensus_watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let existing = self
            .consensus_get_replication_log(start_sequence, 10_000)
            .await?;
        let (tx, rx) = tokio::sync::mpsc::channel(WATCH_CHANNEL_CAPACITY);
        for entry in existing {
            if tx.try_send(Ok(entry)).is_err() {
                break;
            }
        }
        self.watchers.lock().await.push(tx);
        use futures_util::StreamExt;
        Ok(watch::SqliteWatchStream { rx }.boxed())
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
        restore_scan: true,
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
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.conn))
    }

    async fn capabilities(&self) -> BackendCapabilities {
        let conn = self.conn.lock().await;
        match (
            consensus_identity_exists(&conn),
            operator_recovery_latch_exists(&conn),
        ) {
            (Ok(false), Ok(false)) => self.caps,
            _ => BackendCapabilities::minimal(),
        }
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = standalone_transaction(&conn)?;
        let result = ops::get_sync(&tx, key, now)?;
        // Standalone SQLite owns its local monotonic clock and may physically
        // prune on reads. Consensus reads use `consensus_get_at` instead and
        // never mutate outside an Openraft-applied command.
        ops::prune_sync(&tx, now)?;
        tx.commit()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok(result)
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = standalone_transaction(&conn)?;
        let res = ops::compare_and_set_sync(&tx, op, &self.caps, now)?;
        tx.commit()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok(res)
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = standalone_transaction(&conn)?;
        ops::delete_fenced_sync(&tx, lease, &self.caps, now)?;
        tx.commit()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok(())
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        let now = self.clock.now_utc();
        checked_session_deadline(now, ttl)?;
        let conn = self.conn.lock().await;
        let tx = standalone_transaction(&conn)?;
        ops::refresh_ttl_sync(&tx, lease, ttl, &self.caps, now)?;
        tx.commit()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok(())
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        validate_session_ops_ttls(&ops)?;
        let now = self.clock.now_utc();
        for op in &ops {
            if let SessionOp::RefreshTtl { ttl, .. } = op {
                checked_session_deadline(now, *ttl)?;
            }
        }
        if !self.caps.batch_write {
            return Err(StoreError::CapabilityNotSupported("batch_write".into()));
        }

        let conn = self.conn.lock().await;
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            let res = match op {
                SessionOp::Get { key } => {
                    let run_get = || {
                        let tx = standalone_transaction(&conn)?;
                        let result = ops::get_sync(&tx, &key, now)?;
                        tx.commit()
                            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                        Ok(result)
                    };
                    SessionOpResult::Get(run_get())
                }
                SessionOp::CompareAndSet(cas) => {
                    let run_cas = || {
                        let tx = standalone_transaction(&conn)?;
                        let res = ops::compare_and_set_sync(&tx, cas, &self.caps, now)?;
                        tx.commit()
                            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                        Ok(res)
                    };
                    SessionOpResult::CompareAndSet(run_cas())
                }
                SessionOp::DeleteFenced { lease } => {
                    let run_del = || {
                        let tx = standalone_transaction(&conn)?;
                        ops::delete_fenced_sync(&tx, &lease, &self.caps, now)?;
                        tx.commit()
                            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                        Ok(())
                    };
                    SessionOpResult::DeleteFenced(run_del())
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    let run_ref = || {
                        let tx = standalone_transaction(&conn)?;
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
        let tx = standalone_transaction(&conn)?;
        let result = ops::scan_restore_records_sync(&tx, request, now)?;
        ops::prune_sync(&tx, now)?;
        tx.commit()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Ok(result)
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        let conn = self.conn.lock().await;
        let tx = standalone_transaction(&conn)?;
        let seq: Option<Option<i64>> = tx
            .query_row(
                "SELECT MAX(sequence) FROM session_replication_log",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        let sequence = seq
            .flatten()
            .map(replication::stored_replication_sequence)
            .transpose()
            .map(|sequence| sequence.unwrap_or(0))?;
        tx.commit()
            .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))?;
        Ok(sequence)
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let Ok(sqlite_start) = i64::try_from(start) else {
            return Ok(Vec::new());
        };
        let sqlite_limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.conn.lock().await;
        let tx = standalone_transaction(&conn)?;
        let res = {
            let mut stmt = tx.prepare(
                "SELECT sequence, entry_json FROM session_replication_log WHERE sequence >= ?1 ORDER BY sequence ASC LIMIT ?2"
            )
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            let entries = stmt
                .query_map(params![sqlite_start, sqlite_limit], |row| {
                    let sequence: i64 = row.get(0)?;
                    let json: String = row.get(1)?;
                    Ok((sequence, json))
                })
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

            let mut res = Vec::new();
            for item in entries {
                let (stored_sequence, json) =
                    item.map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                let stored_sequence = replication::stored_replication_sequence(stored_sequence)?;
                let entry: ReplicationEntry = serde_json::from_str(&json)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                let entry = entry.into_validated()?;
                if entry.sequence != stored_sequence {
                    return Err(StoreError::InvalidReplicationSequence);
                }
                res.push(entry);
            }
            validate_replication_page_owned(res)?
        };
        tx.commit()
            .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))?;
        Ok(res)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        let should_notify = {
            let conn = self.conn.lock().await;
            let now = self.clock.now_utc();
            replication::replicate_entry_sync(&conn, &entry, &self.caps, now)?
        };

        if should_notify {
            let mut watchers = self.watchers.lock().await;
            watchers.retain(|watcher| watcher.try_send(Ok(entry.clone())).is_ok());
        }

        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let entries = validate_replication_prefix_owned(entries)?;
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
        let (tx, rx) = tokio::sync::mpsc::channel(WATCH_CHANNEL_CAPACITY);

        // Query existing entries starting from start_sequence
        let existing = self.get_replication_log(start_sequence, 10000).await?;
        for entry in existing {
            if tx.try_send(Ok(entry)).is_err() {
                break;
            }
        }

        let mut watchers = self.watchers.lock().await;
        watchers.push(tx);

        use futures_util::StreamExt;
        let stream = watch::SqliteWatchStream { rx };
        Ok(stream.boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        let conn = self.conn.lock().await;
        let tx = standalone_transaction(&conn)?;
        let (next_fence, next_credential_id) = {
            let mut global_stmt = tx
                .prepare("SELECT val FROM lease_globals WHERE key = ?1")
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            let next_fence: i64 = global_stmt
                .query_row(["next_fence"], |row| row.get(0))
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            let next_credential_id: i64 = global_stmt
                .query_row(["next_credential_id"], |row| row.get(0))
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            (next_fence, next_credential_id)
        };
        let result = (
            ops::persisted_u64(next_fence)?,
            ops::persisted_u64(next_credential_id)?,
        );
        tx.commit()
            .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))?;
        Ok(result)
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
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        let now = self.clock.now_utc();
        checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
        let conn = self.conn.lock().await;
        let tx = standalone_transaction(&conn).map_err(LeaseError::from)?;
        let res = lease::acquire_sync(&tx, key, owner, ttl, now)?;
        tx.commit()
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        Ok(res)
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        let now = self.clock.now_utc();
        checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
        let conn = self.conn.lock().await;
        let tx = standalone_transaction(&conn).map_err(LeaseError::from)?;
        let res = lease::renew_sync(&tx, lease, ttl, now)?;
        tx.commit()
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        Ok(res)
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let conn = self.conn.lock().await;
        let now = self.clock.now_utc();
        let tx = standalone_transaction(&conn).map_err(LeaseError::from)?;
        lease::release_sync(&tx, lease, now)?;
        tx.commit()
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        Ok(())
    }
}
