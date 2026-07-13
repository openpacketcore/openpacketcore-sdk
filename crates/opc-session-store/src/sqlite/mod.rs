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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use rusqlite::{
    params, Connection, InterruptHandle, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::{
    backend::{
        validate_replication_log_page_owned, validate_replication_prefix_owned,
        validate_session_ops_at, BackendInstanceIdentity, CompareAndSet, CompareAndSetResult,
        ReplicationEntry, ReplicationLogRange, ReplicationWatchCursor, SessionBackend, SessionOp,
        SessionOpResult, REPLICATION_TX_ID_MAX_BYTES, REPLICATION_TX_ID_MIN_BYTES,
    },
    capability::BackendCapabilities,
    clock::Clock,
    error::{LeaseError, StoreError},
    lease::{LeaseGuard, SessionLeaseManager},
    model::{OwnerId, SessionKey},
    record::StoredSessionRecord,
    replication_watch::{
        prepare_watch_registration, watch_backlog_query_limit, ReplicationWatcher,
    },
    restore::{RestoreScanPage, RestoreScanRequest},
    ttl::{checked_session_deadline, validate_session_ttl, validate_stored_record_expiry_at},
};

pub mod audit;
pub(crate) mod consensus;
pub(crate) mod lease;
pub(crate) mod ops;
pub(crate) mod replication;

const SQLITE_SESSION_MAX_VALUE_BYTES: usize = 1_048_576;
const CONSENSUS_AUTHORITY_REQUIRED: &str = "consensus_authority_required";
const RESTORE_SCAN_BLOCKING_WORKERS: usize = 1;
const SQLITE_OPERATION_BLOCKING_WORKERS: usize = 1;
const SQLITE_OPERATION_MAX_WORK: Duration = Duration::from_secs(2);
const SQLITE_BUSY_TIMEOUT_MILLIS: u64 = 100;
const SQLITE_OPERATION_PROGRESS_INTERVAL: i32 = 1_000;

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
    restore_scan_workers: Arc<tokio::sync::Semaphore>,
    operation_workers: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    pub(crate) consensus_apply_gate: Arc<tokio::sync::Semaphore>,
    watchers: Arc<tokio::sync::Mutex<Vec<ReplicationWatcher>>>,
    #[cfg(test)]
    pub(crate) watch_registration_gate: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    pub(crate) watch_backlog_captured: Arc<AtomicBool>,
}

struct RestoreScanCancellation {
    cancellation: Arc<AtomicBool>,
    abort: tokio::task::AbortHandle,
    cancel_queued: Option<Box<dyn FnOnce() + Send>>,
    armed: bool,
}

impl RestoreScanCancellation {
    fn disarm(&mut self) {
        self.armed = false;
        self.cancel_queued = None;
    }
}

impl Drop for RestoreScanCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.store(true, Ordering::Release);
            if let Some(cancel_queued) = self.cancel_queued.take() {
                cancel_queued();
            }
            self.abort.abort();
        }
    }
}

struct SqliteOperationCancellation {
    cancellation: Arc<AtomicBool>,
    interrupt: InterruptHandle,
    abort: tokio::task::AbortHandle,
    cancel_queued: Option<Box<dyn FnOnce() + Send>>,
    armed: bool,
}

impl SqliteOperationCancellation {
    fn disarm(&mut self) {
        self.armed = false;
        self.cancel_queued = None;
    }
}

impl Drop for SqliteOperationCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.store(true, Ordering::Release);
            self.interrupt.interrupt();
            if let Some(cancel_queued) = self.cancel_queued.take() {
                cancel_queued();
            }
            // A running blocking job ignores abort and remains bounded by its
            // SQLite interrupt/progress handler.
            self.abort.abort();
        }
    }
}

struct SqliteOperationProgressGuard<'a>(&'a Connection);

impl Drop for SqliteOperationProgressGuard<'_> {
    fn drop(&mut self) {
        self.0.progress_handler(0, None::<fn() -> bool>);
    }
}

#[derive(Clone, Copy)]
enum SqliteStoreWorkKind {
    Read,
    CompareAndSet,
    Mutation,
}

#[derive(Clone, Copy)]
enum SqliteWorkerFailure {
    Admission,
    OutcomeUnavailable,
}

fn install_sqlite_operation_progress_handler(
    conn: &Connection,
    cancellation: Arc<AtomicBool>,
    deadline: std::time::Instant,
) -> SqliteOperationProgressGuard<'_> {
    conn.progress_handler(
        SQLITE_OPERATION_PROGRESS_INTERVAL,
        Some(move || cancellation.load(Ordering::Acquire) || std::time::Instant::now() >= deadline),
    );
    SqliteOperationProgressGuard(conn)
}

impl SqliteSessionBackend {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let conn =
            Connection::open(path).map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        if let Some(latch) =
            consensus::read_operator_recovery_latch_sync(&canonical).map_err(|_| {
                StoreError::BackendUnavailable(
                    "session operator recovery latch is unavailable".into(),
                )
            })?
        {
            opc_redaction::metrics::METRICS
                .session_operator_recovery_required
                .store(1, std::sync::atomic::Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .session_operator_recovery_epoch
                .fetch_max(latch.recovery_epoch, std::sync::atomic::Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .session_operator_recovery_audit_pending
                .store(
                    i64::from(latch.audit_pending),
                    std::sync::atomic::Ordering::Relaxed,
                );
        }
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
                stable_id BLOB NOT NULL CHECK (
                    typeof(stable_id) = 'blob' AND length(stable_id) BETWEEN 1 AND 64
                ),
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

        // Local, non-authoritative metadata for opaque bounded restore
        // cursors. The epoch distinguishes database incarnations while the
        // revision invalidates pagination whenever visible record state
        // changes. Neither value allocates session mutation authority.
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS restore_scan_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                revision INTEGER NOT NULL CHECK (revision >= 0),
                cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32)
            );
            "#,
            [],
        )
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
        ops::initialize_restore_scan_metadata_sync(&conn)?;

        // Create table for storing lease entries
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS leases (
                tenant TEXT NOT NULL,
                nf_kind TEXT NOT NULL,
                key_type TEXT NOT NULL,
                stable_id BLOB NOT NULL CHECK (
                    typeof(stable_id) = 'blob' AND length(stable_id) BETWEEN 1 AND 64
                ),
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
                stable_id BLOB NOT NULL CHECK (
                    typeof(stable_id) = 'blob' AND length(stable_id) BETWEEN 1 AND 64
                ),
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
                tx_id TEXT NOT NULL CHECK (
                    typeof(tx_id) = 'text'
                    AND length(CAST(tx_id AS BLOB)) BETWEEN 1 AND 128
                ),
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
            restore_scan_workers: Arc::new(tokio::sync::Semaphore::new(
                RESTORE_SCAN_BLOCKING_WORKERS,
            )),
            operation_workers: Arc::new(tokio::sync::Semaphore::new(
                SQLITE_OPERATION_BLOCKING_WORKERS,
            )),
            #[cfg(test)]
            consensus_apply_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            watchers: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            #[cfg(test)]
            watch_registration_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            #[cfg(test)]
            watch_backlog_captured: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Build the exact standalone schema used by the production constructor
    /// and return its connection to internal schema validators.
    ///
    /// Keeping this behind the adapter prevents recovery code from maintaining
    /// a second, potentially weaker copy of the session-table definitions.
    pub(crate) fn canonical_schema_connection() -> Result<Connection, StoreError> {
        let Self { conn, .. } = Self::in_memory()?;
        Arc::try_unwrap(conn)
            .map(tokio::sync::Mutex::into_inner)
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "canonical session schema connection is unexpectedly shared".into(),
                )
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

    async fn run_sqlite_task<T, E, F>(
        &self,
        operation: F,
    ) -> Result<Result<T, E>, SqliteWorkerFailure>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, E> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now()
            .checked_add(SQLITE_OPERATION_MAX_WORK)
            .ok_or(SqliteWorkerFailure::Admission)?;
        let worker_permit = tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.operation_workers).acquire_owned(),
        )
        .await
        .map_err(|_| SqliteWorkerFailure::Admission)?
        .map_err(|_| SqliteWorkerFailure::Admission)?;
        // The async connection lock is acquired before `spawn_blocking`, so a
        // blocked database cannot accumulate detached blocking jobs. Once the
        // job starts, both the connection and worker permit stay in its
        // closure even if the caller disconnects or its future is cancelled.
        let conn = tokio::time::timeout_at(deadline, Arc::clone(&self.conn).lock_owned())
            .await
            .map_err(|_| SqliteWorkerFailure::Admission)?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let interrupt = conn.get_interrupt_handle();
        let operation_deadline = deadline.into_std();
        let task_cancellation = Arc::clone(&cancellation);
        let queued_job = Arc::new(StdMutex::new(Some((conn, worker_permit, operation))));
        let task_job = Arc::clone(&queued_job);
        let task = tokio::task::spawn_blocking(move || {
            let (conn, worker_permit, operation) = task_job
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()?;
            let result = {
                let _progress = install_sqlite_operation_progress_handler(
                    &conn,
                    Arc::clone(&task_cancellation),
                    operation_deadline,
                );
                if task_cancellation.load(Ordering::Acquire) {
                    Err(SqliteWorkerFailure::OutcomeUnavailable)
                } else {
                    Ok(operation(&conn))
                }
            };
            // Return both guards with the result. The async wrapper disarms
            // its interrupt before dropping them, so completion cannot issue
            // a stale interrupt against a successor operation. If the wrapper
            // was dropped, this output is discarded only after the worker
            // exits, retaining bounded admission for the full lifetime.
            Some((result, conn, worker_permit))
        });
        let cancel_job = Arc::clone(&queued_job);
        let mut cancel_on_drop = SqliteOperationCancellation {
            cancellation: Arc::clone(&cancellation),
            interrupt,
            abort: task.abort_handle(),
            cancel_queued: Some(Box::new(move || {
                drop(
                    cancel_job
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take(),
                );
            })),
            armed: true,
        };
        match tokio::time::timeout_at(deadline, task).await {
            Err(_) => Err(SqliteWorkerFailure::OutcomeUnavailable),
            Ok(Err(_)) => {
                cancel_on_drop.disarm();
                Err(SqliteWorkerFailure::OutcomeUnavailable)
            }
            Ok(Ok(Some((result, conn, worker_permit)))) => {
                cancel_on_drop.disarm();
                drop(conn);
                drop(worker_permit);
                result
            }
            Ok(Ok(None)) => {
                cancel_on_drop.disarm();
                Err(SqliteWorkerFailure::OutcomeUnavailable)
            }
        }
    }

    async fn run_store_sqlite_task<T, F>(
        &self,
        kind: SqliteStoreWorkKind,
        operation: F,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    {
        match self.run_sqlite_task(operation).await {
            Ok(Ok(value)) => Ok(value),
            Err(SqliteWorkerFailure::OutcomeUnavailable) => {
                Err(sqlite_store_outcome_unavailable(kind))
            }
            Ok(Err(error)) => Err(error),
            Err(SqliteWorkerFailure::Admission) => Err(StoreError::BackendUnavailable(
                "session SQLite worker admission deadline exceeded".into(),
            )),
        }
    }

    async fn run_lease_sqlite_task<T, F>(&self, operation: F) -> Result<T, LeaseError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, LeaseError> + Send + 'static,
    {
        match self.run_sqlite_task(operation).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(error),
            Err(SqliteWorkerFailure::OutcomeUnavailable) => {
                Err(LeaseError::OperationOutcomeUnavailable)
            }
            Err(SqliteWorkerFailure::Admission) => Err(LeaseError::Backend(
                "session SQLite worker admission deadline exceeded".into(),
            )),
        }
    }

    /// Capabilities consumed by the consensus adapter that owns this backend.
    pub(crate) const fn consensus_capabilities(&self) -> BackendCapabilities {
        self.caps
    }

    /// Read the last committed state-machine logical time after a caller-owned
    /// Openraft linearizable barrier. This path is read-only and allocates no
    /// sequencing authority.
    pub(crate) async fn consensus_logical_time(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
    ) -> Result<Option<opc_types::Timestamp>, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::logical_time_sync(conn, identity).map_err(|_| {
                StoreError::BackendUnavailable(
                    "session consensus logical time is unavailable".into(),
                )
            })
        })
        .await
    }

    /// Read at a logical timestamp already committed by the consensus state
    /// machine. This path is read-only: expiry affects visibility but never
    /// prunes physical rows outside a committed command.
    pub(crate) async fn consensus_get_at(
        &self,
        key: &SessionKey,
        logical_time: opc_types::Timestamp,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        let key = key.clone();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let result = ops::get_sync(&tx, &key, logical_time)?;
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(result)
        })
        .await
    }

    /// Restore scan at one persisted consensus logical timestamp.
    pub(crate) async fn consensus_scan_restore_records_at(
        &self,
        request: RestoreScanRequest,
        logical_time: opc_types::Timestamp,
        deadline: tokio::time::Instant,
    ) -> Result<RestoreScanPage, StoreError> {
        self.run_restore_scan(request, logical_time, deadline, false)
            .await
    }

    async fn run_restore_scan(
        &self,
        request: RestoreScanRequest,
        logical_time: opc_types::Timestamp,
        deadline: tokio::time::Instant,
        standalone: bool,
    ) -> Result<RestoreScanPage, StoreError> {
        let cancellation = Arc::new(AtomicBool::new(false));
        // Admission happens before `spawn_blocking` and the owned permit stays
        // with the blocking closure. A timed-out caller therefore cannot
        // detach another worker behind the one SQLite connection; later calls
        // wait asynchronously and disappear cleanly when their futures drop.
        let worker_permit = tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.restore_scan_workers).acquire_owned(),
        )
        .await
        .map_err(|_| StoreError::RestoreScanWorkBudgetExceeded)?
        .map_err(|_| StoreError::BackendUnavailable("session restore scan unavailable".into()))?;
        // Acquire the async connection guard before entering the blocking
        // pool so a busy connection is part of the same absolute operation
        // deadline and never strands a blocking thread waiting on a mutex.
        let conn = tokio::time::timeout_at(deadline, Arc::clone(&self.conn).lock_owned())
            .await
            .map_err(|_| StoreError::RestoreScanWorkBudgetExceeded)?;
        let operation_deadline = deadline.into_std();
        let task_cancellation = Arc::clone(&cancellation);
        let queued_job = Arc::new(StdMutex::new(Some((conn, worker_permit, request))));
        let task_job = Arc::clone(&queued_job);
        let task = tokio::task::spawn_blocking(move || {
            let (conn, worker_permit, request) = task_job
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()?;
            let _worker_permit = worker_permit;
            if task_cancellation.load(Ordering::Acquire) {
                return Some(Err(StoreError::RestoreScanWorkBudgetExceeded));
            }
            let tx = if standalone {
                match standalone_transaction(&conn) {
                    Ok(tx) => tx,
                    Err(error) => return Some(Err(error)),
                }
            } else {
                match conn
                    .unchecked_transaction()
                    .map_err(|_| StoreError::BackendUnavailable("session store scan failed".into()))
                {
                    Ok(tx) => tx,
                    Err(error) => return Some(Err(error)),
                }
            };
            let result = match ops::scan_restore_records_sync(
                &tx,
                request,
                logical_time,
                Arc::clone(&task_cancellation),
                operation_deadline,
                standalone,
            ) {
                Ok(result) => result,
                Err(error) => return Some(Err(error)),
            };
            if task_cancellation.load(Ordering::Acquire) {
                return Some(Err(StoreError::RestoreScanWorkBudgetExceeded));
            }
            if tx.commit().is_err() {
                return Some(Err(StoreError::BackendUnavailable(
                    "session store scan failed".into(),
                )));
            }
            Some(Ok(result))
        });
        let cancel_job = Arc::clone(&queued_job);
        let mut cancel_on_drop = RestoreScanCancellation {
            cancellation: Arc::clone(&cancellation),
            abort: task.abort_handle(),
            cancel_queued: Some(Box::new(move || {
                drop(
                    cancel_job
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take(),
                );
            })),
            armed: true,
        };
        match tokio::time::timeout_at(deadline, task).await {
            Err(_) => Err(StoreError::RestoreScanWorkBudgetExceeded),
            Ok(Err(_)) => {
                cancel_on_drop.disarm();
                Err(StoreError::BackendUnavailable(
                    "session restore scan task failed".into(),
                ))
            }
            Ok(Ok(Some(result))) => {
                cancel_on_drop.disarm();
                result
            }
            Ok(Ok(None)) => {
                cancel_on_drop.disarm();
                Err(StoreError::RestoreScanWorkBudgetExceeded)
            }
        }
    }

    /// Read the committed application-journal head after the caller has
    /// completed its Openraft linearizable barrier and local apply wait.
    pub(crate) async fn consensus_max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
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
        })
        .await
    }

    /// Whether an offline operator reset is awaiting its Openraft-committed
    /// recovery epoch. A pending replica may exchange Raft traffic and rejoin,
    /// but must not admit ordinary session operations or advertise readiness.
    pub(crate) async fn consensus_operator_recovery_pending(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
    ) -> Result<bool, StoreError> {
        let database_path = self.database_path.clone();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let database_latch = database_path
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
            consensus::read_operator_recovery_sync(conn, identity)
                .map(|state| state.pending_epoch.is_some() || database_latch.is_some())
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery state is unavailable".into(),
                    )
                })
        })
        .await
    }

    pub(crate) async fn consensus_operator_recovery_committed(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        recovery_epoch: u64,
        plan_digest: [u8; 32],
    ) -> Result<bool, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::read_operator_recovery_sync(conn, identity)
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
        })
        .await
    }

    /// Read committed application-journal entries after the caller's Openraft
    /// barrier. This internal path cannot allocate sequencing authority.
    pub(crate) async fn consensus_get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let range = ReplicationLogRange::try_new(start, limit)?;
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let Ok(sqlite_start) = i64::try_from(range.first_sequence()) else {
            return Ok(Vec::new());
        };
        let sqlite_limit =
            i64::try_from(range.limit()).map_err(|_| StoreError::InvalidReplicationLogRange)?;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let invalidation_floor = consensus::read_watch_cursor_invalidation_floor_sync(conn)
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            range.ensure_not_compacted(invalidation_floor)?;
            let mut stmt = conn
                .prepare(
                    r#"
                SELECT sequence,
                       CASE
                           WHEN typeof(tx_id) = 'text'
                            AND length(CAST(tx_id AS BLOB)) BETWEEN ?3 AND ?4
                           THEN tx_id
                       END,
                       entry_json
                FROM session_replication_log
                WHERE sequence >= ?1
                ORDER BY sequence ASC
                LIMIT ?2
                "#,
                )
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let entries = stmt
                .query_map(
                    params![
                        sqlite_start,
                        sqlite_limit,
                        REPLICATION_TX_ID_MIN_BYTES,
                        REPLICATION_TX_ID_MAX_BYTES
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let mut result = Vec::new();
            for item in entries {
                let (stored_sequence, stored_tx_id, json) = item.map_err(|_| {
                    StoreError::BackendUnavailable("session store read failed".into())
                })?;
                result.push(replication::hydrate_replication_entry(
                    stored_sequence,
                    stored_tx_id,
                    &json,
                )?);
            }
            validate_replication_log_page_owned(start, limit, result)
        })
        .await
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
        let cursor = ReplicationWatchCursor::new(start_sequence);
        let mut watchers = self.watchers.lock().await;
        let existing = self
            .consensus_get_replication_log(
                cursor.first_sequence(),
                watch_backlog_query_limit(cursor),
            )
            .await?;
        #[cfg(test)]
        self.pause_after_watch_backlog_capture().await?;
        let (stream, watcher) = prepare_watch_registration(cursor, existing)?;
        watchers.retain(|watcher| !watcher.is_closed());
        if let Some(watcher) = watcher {
            watchers.push(watcher);
        }
        use futures_util::StreamExt;
        Ok(stream.boxed())
    }

    #[cfg(test)]
    async fn pause_after_watch_backlog_capture(&self) -> Result<(), StoreError> {
        self.watch_backlog_captured.store(true, Ordering::SeqCst);
        let permit = Arc::clone(&self.watch_registration_gate)
            .acquire_owned()
            .await
            .map_err(|_| StoreError::BackendUnavailable("watch registration unavailable".into()))?;
        drop(permit);
        Ok(())
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

fn sqlite_store_outcome_unavailable(kind: SqliteStoreWorkKind) -> StoreError {
    match kind {
        SqliteStoreWorkKind::Read => {
            StoreError::BackendUnavailable("session SQLite operation did not complete".into())
        }
        SqliteStoreWorkKind::CompareAndSet => StoreError::CasIdempotencyOutcomeUnavailable,
        SqliteStoreWorkKind::Mutation => StoreError::BackendOperationOutcomeUnavailable,
    }
}

fn session_op_result_has_backend_unavailable(result: &SessionOpResult) -> bool {
    let error = match result {
        SessionOpResult::Get(Err(error))
        | SessionOpResult::CompareAndSet(Err(error))
        | SessionOpResult::DeleteFenced(Err(error))
        | SessionOpResult::RefreshTtl(Err(error)) => Some(error),
        SessionOpResult::Get(Ok(_))
        | SessionOpResult::CompareAndSet(Ok(_))
        | SessionOpResult::DeleteFenced(Ok(()))
        | SessionOpResult::RefreshTtl(Ok(())) => None,
    };
    matches!(error, Some(StoreError::BackendUnavailable(_)))
}

fn apply_pragma_profile(conn: &Connection, in_memory: bool) -> Result<(), StoreError> {
    if in_memory {
        conn.execute_batch(
            r#"
            PRAGMA synchronous = EXTRA;
            PRAGMA foreign_keys = ON;
            PRAGMA locking_mode = NORMAL;
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
            PRAGMA temp_store = MEMORY;
            "#,
        )
    }
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MILLIS))
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
    fn restore_scan_cursor_profile(&self) -> Option<crate::RestoreScanCursorProfile> {
        Some(crate::RestoreScanCursorProfile::DurableOpaqueV1)
    }

    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.conn))
    }

    async fn capabilities(&self) -> BackendCapabilities {
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            Ok(
                match (
                    consensus_identity_exists(conn),
                    operator_recovery_latch_exists(conn),
                ) {
                    (Ok(false), Ok(false)) => caps,
                    _ => BackendCapabilities::minimal(),
                },
            )
        })
        .await
        .unwrap_or_else(|_| BackendCapabilities::minimal())
    }

    fn record_expiry_reference(&self) -> Option<opc_types::Timestamp> {
        Some(self.clock.now_utc())
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let key = key.clone();
        let now = self.clock.now_utc();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = standalone_transaction(conn)?;
            let result = ops::get_sync(&tx, &key, now)?;
            // Standalone SQLite owns its local monotonic clock and may
            // physically prune on reads. Consensus reads never mutate outside
            // an Openraft-applied command.
            ops::prune_sync(&tx, now)?;
            tx.commit()
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            Ok(result)
        })
        .await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let now = self.clock.now_utc();
        validate_stored_record_expiry_at(&op.new_record, now)?;
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::CompareAndSet, move |conn| {
            let tx = standalone_transaction(conn)?;
            let result = ops::compare_and_set_sync(&tx, op, &caps, now)?;
            tx.commit()
                .map_err(|_| StoreError::CasIdempotencyOutcomeUnavailable)?;
            Ok(result)
        })
        .await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let lease = lease.clone();
        let now = self.clock.now_utc();
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Mutation, move |conn| {
            let tx = standalone_transaction(conn)?;
            ops::delete_fenced_sync(&tx, &lease, &caps, now)?;
            tx.commit()
                .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;
            Ok(())
        })
        .await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        let now = self.clock.now_utc();
        checked_session_deadline(now, ttl)?;
        let lease = lease.clone();
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Mutation, move |conn| {
            let tx = standalone_transaction(conn)?;
            ops::refresh_ttl_sync(&tx, &lease, ttl, &caps, now)?;
            tx.commit()
                .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;
            Ok(())
        })
        .await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        let now = self.clock.now_utc();
        validate_session_ops_at(&ops, now)?;
        for op in &ops {
            if let SessionOp::RefreshTtl { ttl, .. } = op {
                checked_session_deadline(now, *ttl)?;
            }
        }
        if !self.caps.batch_write {
            return Err(StoreError::CapabilityNotSupported("batch_write".into()));
        }
        let contains_mutation = ops.iter().any(|op| !matches!(op, SessionOp::Get { .. }));
        let kind = if contains_mutation {
            SqliteStoreWorkKind::Mutation
        } else {
            SqliteStoreWorkKind::Read
        };
        let caps = self.caps;
        self.run_store_sqlite_task(kind, move |conn| {
            let mut results = Vec::with_capacity(ops.len());
            let mut effect_may_have_committed = false;
            for op in ops {
                let mutation_slot = !matches!(&op, SessionOp::Get { .. });
                let result = match op {
                    SessionOp::Get { key } => {
                        let run_get = || {
                            let tx = standalone_transaction(conn)?;
                            let result = ops::get_sync(&tx, &key, now)?;
                            tx.commit()
                                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                            Ok(result)
                        };
                        SessionOpResult::Get(run_get())
                    }
                    SessionOp::CompareAndSet(cas) => {
                        let run_cas = || {
                            let tx = standalone_transaction(conn)?;
                            let result = ops::compare_and_set_sync(&tx, cas, &caps, now)?;
                            tx.commit()
                                .map_err(|_| StoreError::CasIdempotencyOutcomeUnavailable)?;
                            Ok(result)
                        };
                        SessionOpResult::CompareAndSet(run_cas())
                    }
                    SessionOp::DeleteFenced { lease } => {
                        let run_delete = || {
                            let tx = standalone_transaction(conn)?;
                            ops::delete_fenced_sync(&tx, &lease, &caps, now)?;
                            tx.commit()
                                .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;
                            Ok(())
                        };
                        SessionOpResult::DeleteFenced(run_delete())
                    }
                    SessionOp::RefreshTtl { lease, ttl } => {
                        let run_refresh = || {
                            let tx = standalone_transaction(conn)?;
                            ops::refresh_ttl_sync(&tx, &lease, ttl, &caps, now)?;
                            tx.commit()
                                .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;
                            Ok(())
                        };
                        SessionOpResult::RefreshTtl(run_refresh())
                    }
                };
                if session_op_result_has_backend_unavailable(&result) {
                    return Err(if effect_may_have_committed {
                        StoreError::BackendOperationOutcomeUnavailable
                    } else {
                        StoreError::BackendUnavailable(
                            "session SQLite batch outcome is unavailable".into(),
                        )
                    });
                }
                if mutation_slot {
                    // A non-generic result proves the slot crossed its SQLite
                    // admission/transaction setup. From this point onward a
                    // later generic backend error cannot prove that no prior
                    // batch effect committed.
                    effect_may_have_committed = true;
                }
                results.push(result);
            }
            Ok(results)
        })
        .await
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        let now = self.clock.now_utc();
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(
                crate::RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS,
            ))
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
        self.run_restore_scan(request, now, deadline, true).await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = standalone_transaction(conn)?;
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
            tx.commit().map_err(|_| {
                StoreError::BackendUnavailable("session store operation failed".into())
            })?;
            Ok(sequence)
        })
        .await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let range = ReplicationLogRange::try_new(start, limit)?;
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let Ok(sqlite_start) = i64::try_from(range.first_sequence()) else {
            return Ok(Vec::new());
        };
        let sqlite_limit =
            i64::try_from(range.limit()).map_err(|_| StoreError::InvalidReplicationLogRange)?;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = standalone_transaction(conn)?;
            let result = {
                let mut stmt = tx
                    .prepare(
                        r#"
                SELECT sequence,
                       CASE
                           WHEN typeof(tx_id) = 'text'
                            AND length(CAST(tx_id AS BLOB)) BETWEEN ?3 AND ?4
                           THEN tx_id
                       END,
                       entry_json
                FROM session_replication_log
                WHERE sequence >= ?1
                ORDER BY sequence ASC
                LIMIT ?2
                "#,
                    )
                    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                let entries = stmt
                    .query_map(
                        params![
                            sqlite_start,
                            sqlite_limit,
                            REPLICATION_TX_ID_MIN_BYTES,
                            REPLICATION_TX_ID_MAX_BYTES
                        ],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, Option<String>>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    )
                    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

                let mut result = Vec::new();
                for item in entries {
                    let (stored_sequence, stored_tx_id, json) =
                        item.map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                    result.push(replication::hydrate_replication_entry(
                        stored_sequence,
                        stored_tx_id,
                        &json,
                    )?);
                }
                validate_replication_log_page_owned(start, limit, result)?
            };
            tx.commit().map_err(|_| {
                StoreError::BackendUnavailable("session store operation failed".into())
            })?;
            Ok(result)
        })
        .await
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        let worker_entry = entry.clone();
        let now = self.clock.now_utc();
        let caps = self.caps;
        let should_notify = self
            .run_store_sqlite_task(SqliteStoreWorkKind::Mutation, move |conn| {
                replication::replicate_entry_sync(conn, &worker_entry, &caps, now)
            })
            .await?;

        if should_notify {
            let mut watchers = self.watchers.lock().await;
            watchers.retain_mut(|watcher| watcher.notify(&entry));
        }

        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let entries = validate_replication_prefix_owned(entries)?;
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Mutation, move |conn| {
            replication::rebuild_replication_state_sync(conn, &entries, &caps)
        })
        .await
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let cursor = ReplicationWatchCursor::new(start_sequence);
        let mut watchers = self.watchers.lock().await;
        let existing = self
            .get_replication_log(cursor.first_sequence(), watch_backlog_query_limit(cursor))
            .await?;
        #[cfg(test)]
        self.pause_after_watch_backlog_capture().await?;
        let (stream, watcher) = prepare_watch_registration(cursor, existing)?;
        watchers.retain(|watcher| !watcher.is_closed());
        if let Some(watcher) = watcher {
            watchers.push(watcher);
        }

        use futures_util::StreamExt;
        Ok(stream.boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = standalone_transaction(conn)?;
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
            tx.commit().map_err(|_| {
                StoreError::BackendUnavailable("session store operation failed".into())
            })?;
            Ok(result)
        })
        .await
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
        let key = key.clone();
        self.run_lease_sqlite_task(move |conn| {
            let tx = standalone_transaction(conn).map_err(LeaseError::from)?;
            let result = lease::acquire_sync(&tx, &key, owner, ttl, now)?;
            tx.commit()
                .map_err(|_| LeaseError::OperationOutcomeUnavailable)?;
            Ok(result)
        })
        .await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        let now = self.clock.now_utc();
        checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
        let lease = lease.clone();
        self.run_lease_sqlite_task(move |conn| {
            let tx = standalone_transaction(conn).map_err(LeaseError::from)?;
            let result = lease::renew_sync(&tx, &lease, ttl, now)?;
            tx.commit()
                .map_err(|_| LeaseError::OperationOutcomeUnavailable)?;
            Ok(result)
        })
        .await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let now = self.clock.now_utc();
        self.run_lease_sqlite_task(move |conn| {
            let tx = standalone_transaction(conn).map_err(LeaseError::from)?;
            lease::release_sync(&tx, lease, now)?;
            tx.commit()
                .map_err(|_| LeaseError::OperationOutcomeUnavailable)?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod operation_lifetime_tests {
    use super::*;
    use crate::{
        backend::ReplicationOp,
        model::{FenceToken, Generation, SessionKeyType, StateClass, StateType},
        record::EncryptedSessionPayload,
    };
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    fn key(stable_id: &'static [u8]) -> SessionKey {
        SessionKey {
            tenant: TenantId::new("sqlite-lifetime").expect("tenant"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(stable_id).try_into().expect("stable ID"),
        }
    }

    fn record(key: SessionKey, lease: &LeaseGuard) -> StoredSessionRecord {
        StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: lease.owner().clone(),
            fence: FenceToken::new(lease.fence().get()),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("sqlite-lifetime").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(vec![0x5a]),
        }
    }

    fn replication_entry(key: SessionKey, lease: &LeaseGuard) -> ReplicationEntry {
        let timestamp = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let expires_at = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60),
        );
        ReplicationEntry {
            sequence: 1,
            tx_id: "sqlite-lifetime-replication"
                .try_into()
                .expect("transaction ID"),
            op: ReplicationOp::RefreshTtl {
                key,
                owner: lease.owner().clone(),
                fence: FenceToken::new(lease.fence().get()),
                ttl: Duration::from_secs(60),
                expires_at,
            },
            timestamp,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_sqlite_lock_contention_is_bounded_and_known_preeffect_failures_remain_retryable()
    {
        let directory = tempfile::tempdir().expect("SQLite lifetime directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let key = key(b"blocked-operation");
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("sqlite-lifetime-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("prepare lease");
        let compare_and_set = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record(key.clone(), &lease),
        };
        let entry = replication_entry(key.clone(), &lease);

        let blocker = Connection::open(&path).expect("blocking SQLite connection");
        blocker
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold SQLite write reservation");

        assert!(matches!(
            backend.get(&key).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.compare_and_set(compare_and_set).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.delete_fenced(&lease).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.replicate_entry(entry.clone()).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.rebuild_replication_state(vec![entry]).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.renew(&lease, Duration::from_secs(60)).await,
            Err(LeaseError::Backend(_))
        ));
        assert_eq!(
            backend.operation_workers.available_permits(),
            SQLITE_OPERATION_BLOCKING_WORKERS
        );

        blocker.execute_batch("ROLLBACK").expect("release blocker");
        assert_eq!(backend.get(&key).await.expect("read after unblock"), None);
    }

    #[tokio::test]
    async fn batch_backend_failure_after_an_earlier_commit_is_typed_ambiguous() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let key = key(b"partially-committed-batch");
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("partial-batch-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("prepare batch lease");
        backend
            .conn
            .lock()
            .await
            .execute_batch(
                "CREATE TRIGGER fail_test_refresh
                 BEFORE UPDATE OF expires_at ON session_records
                 BEGIN SELECT RAISE(ABORT, 'forced refresh failure'); END;",
            )
            .expect("install deterministic second-slot failure");

        let error = backend
            .batch(vec![
                SessionOp::CompareAndSet(CompareAndSet {
                    key: key.clone(),
                    lease: lease.clone(),
                    expected_generation: None,
                    new_record: record(key.clone(), &lease),
                }),
                SessionOp::RefreshTtl {
                    lease,
                    ttl: Duration::from_secs(30),
                },
            ])
            .await
            .expect_err("later backend failure makes the whole batch outcome unknown");
        assert_eq!(error, StoreError::BackendOperationOutcomeUnavailable);
        assert!(
            backend
                .get(&key)
                .await
                .expect("read committed first slot")
                .is_some(),
            "the first slot committed before the second slot failed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_sqlite_mutation_retains_its_worker_until_blocking_work_stops() {
        let directory = tempfile::tempdir().expect("SQLite cancellation directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let key = key(b"cancelled-operation");
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("sqlite-cancel-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("prepare lease");
        let operation = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record(key.clone(), &lease),
        };
        let blocker = Connection::open(&path).expect("blocking SQLite connection");
        blocker
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold SQLite write reservation");

        let worker_backend = backend.clone();
        let task = tokio::spawn(async move { worker_backend.compare_and_set(operation).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while backend.operation_workers.available_permits() == SQLITE_OPERATION_BLOCKING_WORKERS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking worker starts");
        assert_eq!(
            backend.operation_workers.available_permits(),
            0,
            "the live blocking job retains its admission permit"
        );
        task.abort();
        assert!(task.await.expect_err("cancel task").is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), async {
            while backend.operation_workers.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("interrupted blocking worker exits within the SQLite busy bound");

        blocker.execute_batch("ROLLBACK").expect("release blocker");
        assert_eq!(backend.get(&key).await.expect("read after unblock"), None);
    }

    #[test]
    fn cancelling_queued_blocking_tasks_releases_captured_sqlite_admission() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("single blocking-thread runtime");

        let (
            ordinary_released,
            ordinary_connection_released,
            restore_released,
            restore_connection_released,
        ) = runtime.block_on(async {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let saturator = tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
            });
            started_rx.await.expect("blocking pool saturator starts");

            let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
            let ordinary_backend = backend.clone();
            let ordinary = tokio::spawn(async move {
                ordinary_backend
                    .run_sqlite_task(|_| Ok::<(), StoreError>(()))
                    .await
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                while backend.operation_workers.available_permits()
                    == SQLITE_OPERATION_BLOCKING_WORKERS
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("ordinary SQLite job queues behind saturated pool");
            ordinary.abort();
            let _ = ordinary.await;
            let ordinary_released = tokio::time::timeout(Duration::from_secs(1), async {
                while backend.operation_workers.available_permits() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok();
            let ordinary_connection_released = backend.conn.try_lock().is_ok();

            let restore_backend = backend.clone();
            let restore = tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                restore_backend
                    .run_restore_scan(
                        RestoreScanRequest::all(1),
                        restore_backend.clock.now_utc(),
                        deadline,
                        true,
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                while backend.restore_scan_workers.available_permits()
                    == RESTORE_SCAN_BLOCKING_WORKERS
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("restore SQLite job queues behind saturated pool");
            restore.abort();
            let _ = restore.await;
            let restore_released = tokio::time::timeout(Duration::from_secs(1), async {
                while backend.restore_scan_workers.available_permits() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok();
            let restore_connection_released = backend.conn.try_lock().is_ok();

            let _ = release_tx.send(());
            saturator.await.expect("blocking pool saturator exits");
            (
                ordinary_released,
                ordinary_connection_released,
                restore_released,
                restore_connection_released,
            )
        });

        assert!(ordinary_released, "queued ordinary job retained its permit");
        assert!(
            ordinary_connection_released,
            "queued ordinary job retained its connection guard"
        );
        assert!(restore_released, "queued restore job retained its permit");
        assert!(
            restore_connection_released,
            "queued restore job retained its connection guard"
        );
    }
}

#[cfg(test)]
mod restore_cancellation_tests {
    use super::*;

    #[tokio::test]
    async fn queued_worker_admission_uses_the_restore_operation_deadline() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let held_permit = Arc::clone(&backend.restore_scan_workers)
            .acquire_owned()
            .await
            .expect("hold restore worker admission");

        for _ in 0..4 {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(25);
            let error = backend
                .run_restore_scan(
                    RestoreScanRequest::all(1),
                    backend.clock.now_utc(),
                    deadline,
                    true,
                )
                .await
                .expect_err("queued scan must stop at its absolute deadline");
            assert_eq!(error, StoreError::RestoreScanWorkBudgetExceeded);
        }
        drop(held_permit);

        let page = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect("worker admission recovers after repeated timeouts");
        assert!(page.complete);
    }

    #[tokio::test]
    async fn held_connection_admission_is_async_bounded_and_recovers() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let held_connection = backend.conn.lock().await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(25);
        let error = backend
            .run_restore_scan(
                RestoreScanRequest::all(1),
                backend.clock.now_utc(),
                deadline,
                true,
            )
            .await
            .expect_err("connection admission must stop at the operation deadline");
        assert_eq!(error, StoreError::RestoreScanWorkBudgetExceeded);
        assert_eq!(
            backend.restore_scan_workers.available_permits(),
            RESTORE_SCAN_BLOCKING_WORKERS,
            "a connection timeout cannot detach a blocking worker"
        );
        drop(held_connection);

        let page = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect("connection admission recovers after timeout");
        assert!(page.complete);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_cancelled_restore_scans_admit_only_one_blocking_worker() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let held_connection = backend.conn.lock().await;
        let first_backend = backend.clone();
        let mut scans = vec![tokio::spawn(async move {
            first_backend
                .scan_restore_records(RestoreScanRequest::all(1))
                .await
        })];
        tokio::time::timeout(Duration::from_secs(1), async {
            while backend.restore_scan_workers.available_permits()
                != RESTORE_SCAN_BLOCKING_WORKERS - 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first restore worker acquires the sole admission permit");

        for _ in 0..64 {
            let cancelled_backend = backend.clone();
            scans.push(tokio::spawn(async move {
                cancelled_backend
                    .scan_restore_records(RestoreScanRequest::all(1))
                    .await
            }));
        }
        tokio::task::yield_now().await;
        assert_eq!(
            backend.restore_scan_workers.available_permits(),
            0,
            "queued callers cannot admit another blocking worker"
        );

        for scan in &scans {
            scan.abort();
        }
        for scan in scans {
            let cancelled = scan.await.expect_err("scan task is cancelled");
            assert!(cancelled.is_cancelled());
        }
        assert_eq!(
            backend.restore_scan_workers.available_permits(),
            RESTORE_SCAN_BLOCKING_WORKERS,
            "cancelling async connection admission cannot detach a worker"
        );
        drop(held_connection);

        let page = tokio::time::timeout(
            Duration::from_secs(1),
            backend.scan_restore_records(RestoreScanRequest::all(1)),
        )
        .await
        .expect("cancelled blocking task releases the connection promptly")
        .expect("fresh restore scan succeeds");
        assert!(page.complete);
    }
}

#[cfg(test)]
mod watcher_lifetime_tests {
    use super::*;
    use crate::ReplicationOp;
    use futures_util::StreamExt;
    use opc_types::Timestamp;

    fn watch_entry(sequence: u64) -> ReplicationEntry {
        ReplicationEntry {
            sequence,
            tx_id: format!("sqlite-watch-{sequence}")
                .try_into()
                .expect("transaction ID"),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp: Timestamp::now_utc(),
        }
    }

    #[tokio::test]
    async fn repeated_idle_watch_disconnects_are_pruned_before_registration() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        for _ in 0..128 {
            let stream = backend.watch(1).await.expect("register idle watch");
            drop(stream);
        }

        let live = backend.watch(1).await.expect("register live watch");
        assert_eq!(
            backend.watchers.lock().await.len(),
            1,
            "closed idle watchers cannot accumulate without a later mutation"
        );
        drop(live);
    }

    #[tokio::test]
    async fn append_between_backlog_capture_and_registration_is_delivered_once() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        backend
            .replicate_entry(watch_entry(1))
            .await
            .expect("seed backlog");

        let held_registration = Arc::clone(&backend.watch_registration_gate)
            .acquire_owned()
            .await
            .expect("hold registration failpoint");
        let watch_backend = backend.clone();
        let watch = tokio::spawn(async move { watch_backend.watch(1).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !backend.watch_backlog_captured.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("watch captures backlog before registration");

        let append_backend = backend.clone();
        let append =
            tokio::spawn(async move { append_backend.replicate_entry(watch_entry(2)).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if backend
                    .max_replication_sequence()
                    .await
                    .expect("read committed standalone head")
                    == 2
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("append commits while notification waits on registration");

        drop(held_registration);
        let mut stream = watch
            .await
            .expect("watch task")
            .expect("atomic watch registration");
        append
            .await
            .expect("append task")
            .expect("append notification");
        assert_eq!(
            stream
                .next()
                .await
                .expect("backlog entry")
                .expect("valid")
                .sequence,
            1
        );
        assert_eq!(
            stream
                .next()
                .await
                .expect("live entry")
                .expect("valid")
                .sequence,
            2
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(25), stream.next())
                .await
                .is_err(),
            "handoff must not duplicate the append"
        );
    }

    #[tokio::test]
    async fn slow_sqlite_watch_receiver_is_evicted_at_the_live_bound() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let mut stream = backend.watch(1).await.expect("register slow watcher");
        for sequence in 1..=u64::try_from(crate::backend::WATCH_CHANNEL_CAPACITY + 1)
            .expect("bounded fixture width")
        {
            backend
                .replicate_entry(watch_entry(sequence))
                .await
                .expect("append live watch fixture");
        }

        for expected in 1..=u64::try_from(crate::backend::WATCH_CHANNEL_CAPACITY)
            .expect("bounded fixture width")
        {
            assert_eq!(
                stream
                    .next()
                    .await
                    .expect("buffered live item")
                    .expect("valid live item")
                    .sequence,
                expected
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.next())
                .await
                .expect("closed slow watcher deadline")
                .is_none(),
            "slow watcher must close rather than retain more live state"
        );
    }
}
