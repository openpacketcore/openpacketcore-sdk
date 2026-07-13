//! Durable SQLite primitives for the config Openraft adapter.
//!
//! These functions persist decisions made by Openraft. None implements an
//! election, quorum, commit-index, read-index, membership, or repair policy.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opc_consensus::engine::{
    EmptyNode, Entry, EntryPayload, LogId, SnapshotMeta, StoredMembership, Vote,
};
use opc_consensus::{ConsensusEntryDigest, ConsensusIdentity, ConsensusNodeId};
use opc_types::Timestamp;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::storage::ConfigConsensusStorageError;
use super::types::CONFIG_CONSENSUS_STORAGE_VERSION;
use super::{
    ApprovedLegacyConfigRecovery, ConfigConsensusResponse, ConfigMutationFailure,
    ConfigMutationIntent, ConfigRaftTypeConfig,
};
use crate::backend::SqliteBackend;
use crate::types::{AuditKey, AuditOpType, CommitSource};

pub(crate) struct StagedLegacyRecovery {
    pub(crate) path: PathBuf,
    pub(crate) approval: ApprovedLegacyConfigRecovery,
}

impl Drop for StagedLegacyRecovery {
    fn drop(&mut self) {
        remove_sqlite_staging_files(&self.path);
    }
}

fn remove_sqlite_staging_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(sidecar));
    }
}

const CONFIG_RAFT_SCHEMA: &str = r#"
CREATE TABLE config_raft_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    cluster_id BLOB NOT NULL CHECK (length(cluster_id) = 32),
    configuration_id BLOB NOT NULL CHECK (length(configuration_id) = 32),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    audit_key_epoch INTEGER NOT NULL CHECK (audit_key_epoch > 0),
    audit_key_fingerprint BLOB NOT NULL CHECK (length(audit_key_fingerprint) = 32),
    schema_manifest_digest BLOB NOT NULL CHECK (length(schema_manifest_digest) = 32)
);
CREATE TABLE config_raft_vote (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    node_id INTEGER,
    vote_json BLOB NOT NULL
);
CREATE TABLE config_raft_committed (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    log_index INTEGER NOT NULL CHECK (log_index >= 0),
    log_id_json BLOB NOT NULL
);
CREATE TABLE config_raft_purged (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    log_index INTEGER NOT NULL CHECK (log_index >= 0),
    log_id_json BLOB NOT NULL
);
CREATE TABLE config_raft_log (
    log_index INTEGER PRIMARY KEY CHECK (log_index >= 0),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    entry_json BLOB NOT NULL
);
CREATE TABLE config_raft_applied (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    log_index INTEGER NOT NULL CHECK (log_index >= 0),
    log_id_json BLOB NOT NULL
);
CREATE TABLE config_raft_membership (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    membership_json BLOB NOT NULL
);
CREATE TABLE config_raft_machine (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    application_sequence INTEGER NOT NULL CHECK (application_sequence >= 0),
    last_digest BLOB NOT NULL CHECK (length(last_digest) = 32),
    logical_time TEXT
);
CREATE TABLE config_raft_request_outcomes (
    request_id BLOB PRIMARY KEY CHECK (length(request_id) = 16),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    applied_sequence INTEGER NOT NULL CHECK (applied_sequence > 0),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    response_json BLOB NOT NULL
);
CREATE INDEX config_raft_request_outcomes_sequence_idx
    ON config_raft_request_outcomes(applied_sequence);
CREATE TABLE config_raft_snapshot (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    meta_json BLOB NOT NULL,
    file_name TEXT NOT NULL CHECK (length(file_name) > 0),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0)
);
CREATE TABLE config_raft_legacy_recovery (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    approved_sha256 BLOB NOT NULL CHECK (length(approved_sha256) = 32),
    authoritative_tx_id BLOB NOT NULL CHECK (length(authoritative_tx_id) = 16),
    authoritative_version INTEGER NOT NULL CHECK (authoritative_version > 0),
    disposition INTEGER NOT NULL CHECK (disposition = 1),
    completed INTEGER NOT NULL CHECK (completed = 1)
);
"#;

/// Hard ceiling for one serialized config Openraft entry on disk.
pub(crate) const CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Hard ceiling for entries accepted by one Openraft log append callback.
pub(crate) const CONFIG_CONSENSUS_LOG_APPEND_MAX_ENTRIES: usize = 1_024;
/// Hard ceiling for serialized bytes accepted by one Openraft log append.
pub(crate) const CONFIG_CONSENSUS_LOG_APPEND_MAX_BYTES: usize = 64 * 1024 * 1024;
const CONFIG_CONSENSUS_RETAINED_REQUEST_OUTCOMES: u64 = 4_096;
const SQLITE_WORK_RUNNING: u8 = 0;
const SQLITE_WORK_CANCELLED: u8 = 1;
const SQLITE_WORK_COMMITTING: u8 = 2;

pub(crate) struct SqliteWorkCancellation {
    state: AtomicU8,
    deadline: Option<std::time::Instant>,
}

impl SqliteWorkCancellation {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(SQLITE_WORK_RUNNING),
            deadline: None,
        }
    }

    fn with_deadline(deadline: std::time::Instant) -> Self {
        Self {
            state: AtomicU8::new(SQLITE_WORK_RUNNING),
            deadline: Some(deadline),
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        let state = self.state.load(Ordering::Acquire);
        state == SQLITE_WORK_CANCELLED
            || state == SQLITE_WORK_RUNNING
                && self
                    .deadline
                    .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }

    fn cancel_before_commit(&self) -> bool {
        self.state
            .compare_exchange(
                SQLITE_WORK_RUNNING,
                SQLITE_WORK_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn authorize_commit(&self) -> Result<(), ConfigConsensusStorageError> {
        if self.is_cancelled() {
            let _ = self.cancel_before_commit();
            return Err(ConfigConsensusStorageError::BackendUnavailable);
        }
        self.state
            .compare_exchange(
                SQLITE_WORK_RUNNING,
                SQLITE_WORK_COMMITTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)
    }

    fn check(&self) -> Result<(), ConfigConsensusStorageError> {
        if self.is_cancelled() {
            Err(ConfigConsensusStorageError::BackendUnavailable)
        } else {
            Ok(())
        }
    }

    pub(crate) fn check_io(&self) -> io::Result<()> {
        if self.is_cancelled() {
            Err(timed_out("config consensus SQLite operation timed out"))
        } else {
            Ok(())
        }
    }
}

type InitializationCommitHook = Box<dyn FnOnce(&SqliteWorkCancellation) + Send>;

const AUTHORITY_TABLES: &[&str] = &[
    "config_history",
    "audit_trail",
    "rollback_labels",
    "config_lifecycle_audit",
];

const RAFT_TABLES: &[&str] = &[
    "config_raft_identity",
    "config_raft_vote",
    "config_raft_committed",
    "config_raft_purged",
    "config_raft_log",
    "config_raft_applied",
    "config_raft_membership",
    "config_raft_machine",
    "config_raft_request_outcomes",
    "config_raft_snapshot",
    "config_raft_legacy_recovery",
];

const LEGACY_RAFT_TABLES: &[&str] = &[
    "consensus_state",
    "consensus_log",
    "consensus_applied",
    "consensus_membership",
    "consensus_snapshot",
];

#[derive(Clone)]
pub(crate) struct ConfigConsensusCore {
    pub(crate) conn: Arc<tokio::sync::Mutex<Connection>>,
    pub(crate) identity: ConsensusIdentity,
    pub(crate) expected_members: Arc<BTreeSet<ConsensusNodeId>>,
    pub(crate) snapshot_dir: Arc<PathBuf>,
    pub(crate) snapshot_gate: Arc<tokio::sync::Mutex<()>>,
    pub(crate) audit_key: Arc<AuditKey>,
    pub(crate) _snapshot_dir_guard: Arc<std::fs::File>,
    pub(crate) snapshot_binding_path: Arc<PathBuf>,
    pub(crate) durable_progress: Arc<super::storage::ConfigDurableProgress>,
    sqlite_worker_gate: Arc<tokio::sync::Semaphore>,
}

impl ConfigConsensusCore {
    pub(crate) async fn initialize(
        backend: &SqliteBackend,
        snapshot_directory: super::storage::AdmittedSnapshotDirectory,
        identity: ConsensusIdentity,
        expected_members: BTreeSet<ConsensusNodeId>,
        durable_progress: Arc<super::storage::ConfigDurableProgress>,
        recovery: Option<StagedLegacyRecovery>,
    ) -> Result<Self, ConfigConsensusStorageError> {
        Self::initialize_with_timeout(
            backend,
            snapshot_directory,
            identity,
            expected_members,
            durable_progress,
            recovery,
            Duration::from_secs(30),
            None,
        )
        .await
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn initialize_with_test_timeout<F>(
        backend: &SqliteBackend,
        snapshot_directory: super::storage::AdmittedSnapshotDirectory,
        identity: ConsensusIdentity,
        expected_members: BTreeSet<ConsensusNodeId>,
        durable_progress: Arc<super::storage::ConfigDurableProgress>,
        recovery: Option<StagedLegacyRecovery>,
        timeout: Duration,
        before_commit: F,
    ) -> Result<Self, ConfigConsensusStorageError>
    where
        F: FnOnce(&SqliteWorkCancellation) + Send + 'static,
    {
        Self::initialize_with_timeout(
            backend,
            snapshot_directory,
            identity,
            expected_members,
            durable_progress,
            recovery,
            timeout,
            Some(Box::new(before_commit)),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn initialize_with_timeout(
        backend: &SqliteBackend,
        snapshot_directory: super::storage::AdmittedSnapshotDirectory,
        identity: ConsensusIdentity,
        expected_members: BTreeSet<ConsensusNodeId>,
        durable_progress: Arc<super::storage::ConfigDurableProgress>,
        recovery: Option<StagedLegacyRecovery>,
        timeout: Duration,
        before_commit: Option<InitializationCommitHook>,
    ) -> Result<Self, ConfigConsensusStorageError> {
        validate_expected_members(&expected_members)
            .map_err(|_| ConfigConsensusStorageError::InvalidIdentity)?;
        if timeout.is_zero() {
            return Err(ConfigConsensusStorageError::BackendUnavailable);
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or(ConfigConsensusStorageError::BackendUnavailable)?;
        let std_deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or(ConfigConsensusStorageError::BackendUnavailable)?;
        let worker_gate = backend.config_consensus_worker_gate();
        let permit = tokio::time::timeout_at(deadline, worker_gate.clone().acquire_owned())
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        let conn = backend.conn();
        let worker_conn = tokio::time::timeout_at(deadline, conn.clone().lock_owned())
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        let worker_members = expected_members.clone();
        let worker_audit_key = backend.audit_key().clone();
        let cancellation = Arc::new(SqliteWorkCancellation::with_deadline(std_deadline));
        let worker_cancellation = cancellation.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let progress_cancellation = worker_cancellation.clone();
            worker_conn.progress_handler(1_000, Some(move || progress_cancellation.is_cancelled()));
            let result = initialize_schema(
                &worker_conn,
                identity,
                &worker_members,
                &worker_audit_key,
                recovery.as_ref(),
                &worker_cancellation,
                before_commit,
            );
            worker_conn.progress_handler(0, None::<fn() -> bool>);
            result
        });
        let initialization = match tokio::time::timeout_at(deadline, &mut worker).await {
            Ok(joined) => joined.map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?,
            Err(_) if cancellation.cancel_before_commit() => {
                // Cancellation won before commit authorization. Observe the
                // worker exit so no transaction can outlive this error.
                let _ = worker.await;
                return Err(ConfigConsensusStorageError::BackendUnavailable);
            }
            Err(_) => {
                // Commit authorization won the race. Its result is authority,
                // so wait for and report the actual durable outcome.
                worker
                    .await
                    .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
            }
        };
        initialization?;
        let super::storage::AdmittedSnapshotDirectory {
            path: snapshot_dir,
            binding_path: snapshot_binding_path,
            guard: snapshot_dir_guard,
        } = snapshot_directory;
        Ok(Self {
            conn,
            identity,
            expected_members: Arc::new(expected_members),
            snapshot_dir: Arc::new(snapshot_dir),
            snapshot_gate: Arc::new(tokio::sync::Mutex::new(())),
            audit_key: Arc::new(backend.audit_key().clone()),
            _snapshot_dir_guard: snapshot_dir_guard,
            snapshot_binding_path: Arc::new(snapshot_binding_path),
            durable_progress,
            sqlite_worker_gate: worker_gate,
        })
    }

    pub(crate) async fn run_sqlite<T, F>(&self, operation: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> io::Result<T> + Send + 'static,
    {
        self.run_sqlite_with_timeout(Duration::from_secs(30), move |conn, _cancellation| {
            operation(conn)
        })
        .await
    }

    pub(crate) async fn run_sqlite_cancellable<T, F>(&self, operation: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection, &Arc<SqliteWorkCancellation>) -> io::Result<T> + Send + 'static,
    {
        self.run_sqlite_with_timeout(Duration::from_secs(30), operation)
            .await
    }

    pub(crate) async fn run_sqlite_cancellable_until<T, F>(
        &self,
        deadline: tokio::time::Instant,
        operation: F,
    ) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection, &Arc<SqliteWorkCancellation>) -> io::Result<T> + Send + 'static,
    {
        run_sqlite_worker_until(
            self.sqlite_worker_gate.clone(),
            self.conn.clone(),
            deadline,
            operation,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn run_sqlite_with_test_timeout_controlled<T, F>(
        &self,
        timeout: Duration,
        operation: F,
    ) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection, &Arc<SqliteWorkCancellation>) -> io::Result<T> + Send + 'static,
    {
        self.run_sqlite_with_timeout(timeout, operation).await
    }

    async fn run_sqlite_with_timeout<T, F>(&self, timeout: Duration, operation: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection, &Arc<SqliteWorkCancellation>) -> io::Result<T> + Send + 'static,
    {
        if timeout.is_zero() {
            return Err(invalid_data(
                "config consensus SQLite timeout must be positive",
            ));
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid_data("config consensus SQLite deadline overflow"))?;
        run_sqlite_worker_until(
            self.sqlite_worker_gate.clone(),
            self.conn.clone(),
            deadline,
            operation,
        )
        .await
    }
}

pub(crate) async fn run_backend_sqlite_with_timeout<T, F>(
    backend: &SqliteBackend,
    timeout: Duration,
    operation: F,
) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Connection, &Arc<SqliteWorkCancellation>) -> io::Result<T> + Send + 'static,
{
    if timeout.is_zero() {
        return Err(invalid_data(
            "config consensus SQLite timeout must be positive",
        ));
    }
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| invalid_data("config consensus SQLite deadline overflow"))?;
    run_sqlite_worker_until(
        backend.config_consensus_worker_gate(),
        backend.conn(),
        deadline,
        operation,
    )
    .await
}

async fn run_sqlite_worker_until<T, F>(
    worker_gate: Arc<tokio::sync::Semaphore>,
    conn: Arc<tokio::sync::Mutex<Connection>>,
    deadline: tokio::time::Instant,
    operation: F,
) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Connection, &Arc<SqliteWorkCancellation>) -> io::Result<T> + Send + 'static,
{
    if deadline <= tokio::time::Instant::now() {
        return Err(timed_out("config consensus SQLite deadline elapsed"));
    }
    let std_deadline = deadline.into_std();
    let permit = tokio::time::timeout_at(deadline, worker_gate.acquire_owned())
        .await
        .map_err(|_| timed_out("config consensus SQLite admission timed out"))?
        .map_err(|_| invalid_data("config consensus SQLite worker is closed"))?;
    let conn = tokio::time::timeout_at(deadline, conn.lock_owned())
        .await
        .map_err(|_| timed_out("config consensus SQLite connection timed out"))?;
    let cancellation = Arc::new(SqliteWorkCancellation::with_deadline(std_deadline));
    let worker_cancellation = cancellation.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let commit_cancellation = worker_cancellation.clone();
        conn.commit_hook(Some(move || {
            commit_cancellation.authorize_commit().is_err()
        }));
        let progress_cancellation = worker_cancellation.clone();
        conn.progress_handler(
            1_000,
            Some(move || {
                progress_cancellation.is_cancelled() || std::time::Instant::now() >= std_deadline
            }),
        );
        let result = operation(&conn, &worker_cancellation);
        conn.commit_hook(None::<fn() -> bool>);
        conn.progress_handler(0, None::<fn() -> bool>);
        result
    });
    match tokio::time::timeout_at(deadline, &mut worker).await {
        Ok(Ok(result)) => {
            if cancellation.is_cancelled() && cancellation.cancel_before_commit() {
                Err(timed_out("config consensus SQLite operation timed out"))
            } else {
                result
            }
        }
        Ok(Err(_)) => Err(invalid_data("config consensus SQLite worker failed")),
        Err(_) if cancellation.cancel_before_commit() => {
            // Cancellation won before SQLite authorized any commit. Drain the
            // worker so neither the transaction nor its connection can outlive
            // this error. A late `Ok` is still a timeout because the caller
            // lost authority to observe the result when cancellation won.
            match worker.await {
                Ok(_) => Err(timed_out("config consensus SQLite operation timed out")),
                Err(_) => Err(invalid_data("config consensus SQLite worker failed")),
            }
        }
        Err(_) => {
            // SQLite authorized a commit before the timeout won. Drain it and
            // report the actual durable result instead of an ambiguous timeout.
            worker
                .await
                .map_err(|_| invalid_data("config consensus SQLite worker failed"))?
        }
    }
}

fn initialize_schema(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    audit_key: &AuditKey,
    recovery: Option<&StagedLegacyRecovery>,
    cancellation: &Arc<SqliteWorkCancellation>,
    before_commit: Option<InitializationCommitHook>,
) -> Result<(), ConfigConsensusStorageError> {
    if let Some(recovery) = recovery {
        validate_legacy_recovery_snapshot(recovery, audit_key, cancellation)?;
        let path = recovery
            .path
            .to_str()
            .ok_or(ConfigConsensusStorageError::InvalidIdentity)?;
        conn.execute("ATTACH DATABASE ?1 AS config_legacy_approved", [path])
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    }
    let result = initialize_schema_transaction(
        conn,
        identity,
        expected_members,
        audit_key,
        recovery,
        cancellation,
        before_commit,
    );
    if recovery.is_some() {
        let detach = conn.execute("DETACH DATABASE config_legacy_approved", []);
        if result.is_ok() && detach.is_err() {
            return Err(ConfigConsensusStorageError::BackendUnavailable);
        }
    }
    result
}

fn initialize_schema_transaction(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    audit_key: &AuditKey,
    recovery: Option<&StagedLegacyRecovery>,
    cancellation: &SqliteWorkCancellation,
    before_commit: Option<InitializationCommitHook>,
) -> Result<(), ConfigConsensusStorageError> {
    cancellation.check()?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    if !table_exists(&tx, "config_raft_identity")
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
    {
        let legacy_nonempty = legacy_authority_is_nonempty(&tx)
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        match (legacy_nonempty, recovery) {
            (true, None) => return Err(ConfigConsensusStorageError::RecoveryRequired),
            (true, Some(_)) => import_approved_legacy_snapshot(&tx, audit_key, cancellation)?,
            (false, Some(_)) => return Err(ConfigConsensusStorageError::InvalidIdentity),
            (false, None) => {}
        }
        drop_empty_legacy_tables(&tx)
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        tx.execute_batch(CONFIG_RAFT_SCHEMA)
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        let epoch = checked_positive_i64(identity.configuration_epoch().get())
            .map_err(|_| ConfigConsensusStorageError::InvalidIdentity)?;
        let schema_manifest_digest = config_schema_manifest_digest(&tx, cancellation)
            .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
        tx.execute(
            "INSERT INTO config_raft_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch, audit_key_epoch, audit_key_fingerprint, schema_manifest_digest) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                i64::from(CONFIG_CONSENSUS_STORAGE_VERSION),
                identity.cluster_id().as_bytes().as_slice(),
                identity.configuration_id().as_bytes().as_slice(),
                epoch,
                checked_positive_i64(audit_key.epoch()).map_err(|_| ConfigConsensusStorageError::InvalidIdentity)?,
                audit_key.fingerprint().as_slice(),
                schema_manifest_digest.as_slice(),
            ],
        )
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        if let Some(recovery) = recovery {
            tx.execute(
                "INSERT INTO config_raft_legacy_recovery (singleton, approved_sha256, authoritative_tx_id, authoritative_version, disposition, completed) VALUES (1, ?1, ?2, ?3, 1, 1)",
                params![
                    recovery.approval.expected_sha256().as_slice(),
                    recovery.approval.authoritative_tx_id().as_uuid().as_bytes().as_slice(),
                    checked_positive_i64(recovery.approval.authoritative_version().get())
                        .map_err(|_| ConfigConsensusStorageError::InvalidIdentity)?,
                ],
            )
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        }
        tx.execute(
            "INSERT INTO config_raft_membership (singleton, configuration_epoch, membership_json) VALUES (1, ?1, ?2)",
            params![epoch, encode_json(&StoredMembership::<ConsensusNodeId, EmptyNode>::default()).map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?],
        )
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        tx.execute(
            "INSERT INTO config_raft_machine (singleton, configuration_epoch, application_sequence, last_digest, logical_time) VALUES (1, ?1, 0, ?2, NULL)",
            params![epoch, ConsensusEntryDigest::GENESIS.as_bytes().as_slice()],
        )
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    } else if let Some(recovery) = recovery {
        validate_existing_schema(
            &tx,
            identity,
            expected_members,
            audit_key,
            false,
            cancellation,
        )?;
        validate_completed_legacy_recovery(&tx, &recovery.approval)?;
    } else {
        validate_existing_schema(
            &tx,
            identity,
            expected_members,
            audit_key,
            false,
            cancellation,
        )?;
    }
    if let Some(before_commit) = before_commit {
        before_commit(cancellation);
    }
    cancellation.authorize_commit()?;
    tx.commit()
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)
}

fn validate_completed_legacy_recovery(
    conn: &Connection,
    approval: &ApprovedLegacyConfigRecovery,
) -> Result<(), ConfigConsensusStorageError> {
    let row = conn
        .query_row(
            "SELECT approved_sha256, authoritative_tx_id, authoritative_version, disposition, completed FROM config_raft_legacy_recovery WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
        .ok_or(ConfigConsensusStorageError::InvalidIdentity)?;
    if row.0.as_slice() != approval.expected_sha256()
        || row.1.as_slice() != approval.authoritative_tx_id().as_uuid().as_bytes()
        || checked_positive_u64(row.2).map_err(|_| ConfigConsensusStorageError::CorruptState)?
            != approval.authoritative_version().get()
        || row.3 != 1
        || row.4 != 1
    {
        return Err(ConfigConsensusStorageError::IdentityMismatch);
    }
    Ok(())
}

pub(crate) fn completed_legacy_recovery_matches_sync(
    conn: &Connection,
    approval: &ApprovedLegacyConfigRecovery,
) -> Result<bool, ConfigConsensusStorageError> {
    if !table_exists(conn, "config_raft_legacy_recovery")
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
    {
        return Ok(false);
    }
    validate_completed_legacy_recovery(conn, approval)?;
    Ok(true)
}

fn validate_legacy_recovery_snapshot(
    recovery: &StagedLegacyRecovery,
    audit_key: &AuditKey,
    cancellation: &Arc<SqliteWorkCancellation>,
) -> Result<(), ConfigConsensusStorageError> {
    let conn = Connection::open_with_flags(
        &recovery.path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let progress_cancellation = cancellation.clone();
    conn.progress_handler(1_000, Some(move || progress_cancellation.is_cancelled()));
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    if integrity != "ok" {
        return Err(ConfigConsensusStorageError::CorruptState);
    }
    for table in AUTHORITY_TABLES {
        if !table_exists(&conn, table)
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
        {
            return Err(ConfigConsensusStorageError::CorruptState);
        }
    }
    if table_exists(&conn, "config_raft_identity")
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
    {
        return Err(ConfigConsensusStorageError::InvalidIdentity);
    }
    let latest = validate_history_chain_sync(&conn)
        .map_err(|_| ConfigConsensusStorageError::CorruptState)?
        .ok_or(ConfigConsensusStorageError::CorruptState)?;
    if latest.0.as_slice() != recovery.approval.authoritative_tx_id().as_uuid().as_bytes()
        || latest.1 != recovery.approval.authoritative_version().get()
    {
        return Err(ConfigConsensusStorageError::IdentityMismatch);
    }
    let mut statement = conn
        .prepare("SELECT tx_id FROM config_history ORDER BY version ASC")
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let mut transaction_ids = Vec::new();
    for row in rows {
        cancellation.check()?;
        transaction_ids.push(row.map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?);
    }
    drop(statement);
    for tx_id in transaction_ids {
        cancellation.check()?;
        let stored = SqliteBackend::load_by_tx_id_bytes(&conn, &tx_id, audit_key)
            .map_err(|_| ConfigConsensusStorageError::CorruptState)?
            .ok_or(ConfigConsensusStorageError::CorruptState)?;
        super::types::validate_encrypted_record(&stored.record)
            .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
    }
    if recovery.approval.disposition()
        != super::LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix
    {
        return Err(ConfigConsensusStorageError::InvalidIdentity);
    }
    Ok(())
}

fn import_approved_legacy_snapshot(
    tx: &Transaction<'_>,
    audit_key: &AuditKey,
    cancellation: &SqliteWorkCancellation,
) -> Result<(), ConfigConsensusStorageError> {
    for table in [
        "config_lifecycle_audit",
        "rollback_labels",
        "audit_trail",
        "config_history",
    ] {
        cancellation.check()?;
        tx.execute(&format!("DELETE FROM {table}"), [])
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    }
    for (table, columns) in [
        (
            "config_history",
            "tx_id, parent_tx_id, version, committed_at, principal, source, schema_digest, plaintext_digest, encrypted_blob, rollback_point, rollback_label, confirmed_deadline, confirmed_at, audit_count, audit_terminal_hash",
        ),
        (
            "audit_trail",
            "id, tx_id, sequence, yang_path, op_type, previous_value, new_value, redaction_applied, previous_hash, entry_hmac",
        ),
        ("rollback_labels", "label, tx_id, created_at"),
        (
            "config_lifecycle_audit",
            "id, tx_id, action, principal, occurred_at, details",
        ),
    ] {
        cancellation.check()?;
        tx.execute(
            &format!("INSERT INTO {table} ({columns}) SELECT {columns} FROM config_legacy_approved.{table}"),
            [],
        )
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    }
    reseal_imported_audit(tx, audit_key, cancellation)?;
    Ok(())
}

fn reseal_imported_audit(
    tx: &Transaction<'_>,
    audit_key: &AuditKey,
    cancellation: &SqliteWorkCancellation,
) -> Result<(), ConfigConsensusStorageError> {
    let mut statement = tx
        .prepare("SELECT tx_id, principal FROM config_history ORDER BY version ASC")
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let mut configs = Vec::new();
    for row in rows {
        cancellation.check()?;
        configs.push(row.map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?);
    }
    drop(statement);
    for (tx_id, principal) in configs {
        cancellation.check()?;
        let mut stored = SqliteBackend::load_by_tx_id_bytes(tx, &tx_id, audit_key)
            .map_err(|_| ConfigConsensusStorageError::CorruptState)?
            .ok_or(ConfigConsensusStorageError::CorruptState)?;
        let audit_count = u32::try_from(stored.audit.len())
            .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
        let tenant = crate::types::extract_tenant(&principal);
        let mut previous = [0_u8; 32];
        for entry in &mut stored.audit {
            cancellation.check()?;
            entry.yang_path = super::types::tokenize_audit_path(&entry.yang_path, audit_key)
                .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
            if entry.previous_value.is_some() {
                entry.previous_value = Some("\"<redacted>\"".to_owned());
                entry.redaction_applied = true;
            }
            if entry.new_value.is_some() {
                entry.new_value = Some("\"<redacted>\"".to_owned());
                entry.redaction_applied = true;
            }
            entry.previous_hash = previous;
            entry.entry_hmac =
                entry.calculate_hmac_with_audit_count(audit_key, &tenant, audit_count);
            previous = entry.entry_hmac;
            tx.execute(
                "UPDATE audit_trail SET yang_path = ?3, previous_value = ?4, new_value = ?5, redaction_applied = ?6, previous_hash = ?7, entry_hmac = ?8 WHERE tx_id = ?1 AND sequence = ?2",
                params![
                    tx_id.as_slice(),
                    i64::from(entry.sequence),
                    &entry.yang_path,
                    &entry.previous_value,
                    &entry.new_value,
                    i32::from(entry.redaction_applied),
                    entry.previous_hash.as_slice(),
                    entry.entry_hmac.as_slice(),
                ],
            )
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        }
        tx.execute(
            "UPDATE config_history SET audit_count = ?2, audit_terminal_hash = ?3 WHERE tx_id = ?1",
            params![
                tx_id.as_slice(),
                i64::from(audit_count),
                previous.as_slice()
            ],
        )
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    }
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
    )
}

fn table_nonempty(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    if !table_exists(conn, table)? {
        return Ok(false);
    }
    let sql = format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)");
    conn.query_row(&sql, [], |row| row.get(0))
}

fn legacy_authority_is_nonempty(conn: &Connection) -> rusqlite::Result<bool> {
    for table in AUTHORITY_TABLES {
        if table_nonempty(conn, table)? {
            return Ok(true);
        }
    }
    for table in [
        "consensus_state",
        "consensus_log",
        "consensus_membership",
        "consensus_snapshot",
    ] {
        if table_nonempty(conn, table)? {
            return Ok(true);
        }
    }
    if table_exists(conn, "consensus_applied")? {
        let applied: Option<i64> = conn
            .query_row(
                "SELECT applied_index FROM consensus_applied WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if applied.is_some_and(|value| value != 0) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn drop_empty_legacy_tables(conn: &Connection) -> rusqlite::Result<()> {
    for table in LEGACY_RAFT_TABLES {
        conn.execute(&format!("DROP TABLE IF EXISTS {table}"), [])?;
    }
    Ok(())
}

fn validate_existing_schema(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    audit_key: &AuditKey,
    allow_detached_snapshot: bool,
    cancellation: &SqliteWorkCancellation,
) -> Result<(), ConfigConsensusStorageError> {
    for table in RAFT_TABLES {
        cancellation.check()?;
        if !table_exists(conn, table)
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
        {
            return Err(ConfigConsensusStorageError::CorruptState);
        }
    }
    let schema_manifest_digest = config_schema_manifest_digest(conn, cancellation)
        .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
    let row = conn
        .query_row(
            "SELECT schema_version, cluster_id, configuration_id, configuration_epoch, audit_key_epoch, audit_key_fingerprint, schema_manifest_digest FROM config_raft_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, Vec<u8>>(5)?, row.get::<_, Vec<u8>>(6)?)),
        )
        .optional()
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
        .ok_or(ConfigConsensusStorageError::CorruptState)?;
    if row.0 != i64::from(CONFIG_CONSENSUS_STORAGE_VERSION) {
        return Err(ConfigConsensusStorageError::SchemaVersionMismatch);
    }
    if row.1.as_slice() != identity.cluster_id().as_bytes()
        || row.2.as_slice() != identity.configuration_id().as_bytes()
        || checked_positive_u64(row.3).map_err(|_| ConfigConsensusStorageError::CorruptState)?
            != identity.configuration_epoch().get()
        || checked_positive_u64(row.4).map_err(|_| ConfigConsensusStorageError::CorruptState)?
            != audit_key.epoch()
        || row.5.as_slice() != audit_key.fingerprint()
        || row.6.as_slice() != schema_manifest_digest
    {
        return Err(ConfigConsensusStorageError::IdentityMismatch);
    }
    let machine_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM config_raft_machine", [], |row| {
            row.get(0)
        })
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let membership_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM config_raft_membership", [], |row| {
            row.get(0)
        })
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    if machine_rows != 1 || membership_rows != 1 {
        return Err(ConfigConsensusStorageError::CorruptState);
    }
    let membership = read_membership_unchecked_sync(conn, identity)
        .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
    if !is_pristine_membership(&membership) {
        validate_fixed_membership(&membership, expected_members)
            .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
    }
    read_vote_sync(conn, identity, expected_members)
        .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
    cancellation.check()?;
    validate_durable_log_state_sync(
        conn,
        identity,
        expected_members,
        allow_detached_snapshot,
        cancellation,
    )
    .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
    validate_sealed_state_sync(conn, audit_key, cancellation)
        .map_err(|_| ConfigConsensusStorageError::CorruptState)
}

fn config_schema_manifest(
    conn: &Connection,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<Vec<(String, String, String, String)>> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_master \
             WHERE type IN ('table', 'index', 'trigger', 'view') \
               AND (name GLOB 'config_raft_*' OR tbl_name GLOB 'config_raft_*') \
               AND name NOT GLOB 'sqlite_autoindex_*' \
             ORDER BY type, name",
        )
        .map_err(db_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(db_error)?;
    let mut manifest = Vec::new();
    for row in rows {
        cancellation.check_io()?;
        manifest.push(row.map_err(db_error)?);
    }
    Ok(manifest)
}

fn config_schema_manifest_digest(
    conn: &Connection,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<[u8; 32]> {
    cancellation.check_io()?;
    let expected = Connection::open_in_memory().map_err(db_error)?;
    expected
        .execute_batch(CONFIG_RAFT_SCHEMA)
        .map_err(db_error)?;
    let expected_manifest = config_schema_manifest(&expected, cancellation)?;
    let live_manifest = config_schema_manifest(conn, cancellation)?;
    if live_manifest != expected_manifest {
        return Err(invalid_data(
            "config consensus owned schema manifest does not match",
        ));
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"openpacketcore/config-consensus/storage-manifest/v1\0");
    for (kind, name, table, sql) in live_manifest {
        cancellation.check_io()?;
        for value in [kind, name, table, sql] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
    }
    Ok(hasher.finalize().into())
}

pub(crate) fn checked_i64(value: u64) -> io::Result<i64> {
    i64::try_from(value).map_err(|_| invalid_data("config consensus integer exceeds SQLite range"))
}

fn checked_positive_i64(value: u64) -> io::Result<i64> {
    if value == 0 {
        return Err(invalid_data("config consensus integer must be positive"));
    }
    checked_i64(value)
}

fn checked_u64(value: i64) -> io::Result<u64> {
    u64::try_from(value).map_err(|_| invalid_data("negative config consensus integer"))
}

fn checked_positive_u64(value: i64) -> io::Result<u64> {
    let value = checked_u64(value)?;
    if value == 0 {
        return Err(invalid_data("config consensus integer must be positive"));
    }
    Ok(value)
}

pub(crate) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

fn db_error(_: rusqlite::Error) -> io::Error {
    io::Error::other("config consensus SQLite operation failed")
}

fn encode_json<T: Serialize + ?Sized>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid_data("config consensus encoding failed"))
}

struct BoundedJsonWriter<'a> {
    bytes: Vec<u8>,
    limit: usize,
    limit_exceeded: bool,
    cancellation: &'a SqliteWorkCancellation,
}

impl io::Write for BoundedJsonWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.cancellation.check_io()?;
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| invalid_data("config consensus encoding length overflow"))?;
        if next > self.limit {
            self.limit_exceeded = true;
            return Err(invalid_data("config consensus encoding exceeds limit"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("config consensus encoding allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_json_bounded_cancellable<T: Serialize + ?Sized>(
    value: &T,
    limit: usize,
    limit_message: &'static str,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<Vec<u8>> {
    let mut writer = BoundedJsonWriter {
        bytes: Vec::new(),
        limit,
        limit_exceeded: false,
        cancellation,
    };
    let encoded = serde_json::to_writer(&mut writer, value);
    if cancellation.is_cancelled() {
        return Err(timed_out("config consensus SQLite operation timed out"));
    }
    if writer.limit_exceeded {
        return Err(invalid_data(limit_message));
    }
    encoded
        .map_err(|_| invalid_data("config consensus encoding failed"))
        .map(|()| writer.bytes)
}

fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(|_| invalid_data("config consensus decoding failed"))
}

fn epoch_i64(identity: ConsensusIdentity) -> io::Result<i64> {
    checked_positive_i64(identity.configuration_epoch().get())
}

fn validate_epoch(stored: i64, identity: ConsensusIdentity) -> io::Result<()> {
    if checked_positive_u64(stored)? != identity.configuration_epoch().get() {
        return Err(invalid_data("config consensus epoch mismatch"));
    }
    Ok(())
}

fn validate_log_id(log_id: &LogId<ConsensusNodeId>) -> io::Result<(i64, i64)> {
    Ok((
        checked_i64(log_id.leader_id.term)?,
        checked_i64(log_id.index)?,
    ))
}

fn validate_expected_members(members: &BTreeSet<ConsensusNodeId>) -> io::Result<()> {
    if members.is_empty() || members.iter().any(|node| node.get() == 0) {
        return Err(invalid_data("invalid config consensus members"));
    }
    Ok(())
}

fn is_pristine_membership(membership: &StoredMembership<ConsensusNodeId, EmptyNode>) -> bool {
    membership.log_id().is_none()
        && membership.membership().voter_ids().next().is_none()
        && membership.membership().learner_ids().next().is_none()
}

fn validate_fixed_membership(
    membership: &StoredMembership<ConsensusNodeId, EmptyNode>,
    expected: &BTreeSet<ConsensusNodeId>,
) -> io::Result<()> {
    let configs = membership.membership().get_joint_config();
    let nodes = membership
        .membership()
        .nodes()
        .map(|(node, _)| *node)
        .collect::<BTreeSet<_>>();
    if configs.len() != 1
        || configs.first() != Some(expected)
        || membership.membership().learner_ids().next().is_some()
        || nodes != *expected
    {
        return Err(invalid_data(
            "config consensus membership differs from immutable voter set",
        ));
    }
    Ok(())
}

pub(crate) fn read_vote_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
) -> io::Result<Option<Vote<ConsensusNodeId>>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, term, node_id, vote_json FROM config_raft_vote WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, Vec<u8>>(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, term, node_id, encoded)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    let vote: Vote<ConsensusNodeId> = decode_json(&encoded)?;
    if checked_u64(term)? != vote.leader_id.term {
        return Err(invalid_data(
            "persisted config consensus vote term mismatch",
        ));
    }
    match (node_id, vote.leader_id.voted_for()) {
        (Some(stored), Some(voted_for))
            if checked_positive_u64(stored)? == voted_for.get()
                && expected_members.contains(&voted_for) => {}
        (None, None) => {}
        _ => {
            return Err(invalid_data(
                "persisted config consensus vote node mismatch",
            ))
        }
    }
    Ok(Some(vote))
}

pub(crate) fn save_vote_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    vote: &Vote<ConsensusNodeId>,
) -> io::Result<()> {
    if vote
        .leader_id
        .voted_for()
        .is_some_and(|node| !expected_members.contains(&node))
    {
        return Err(invalid_data(
            "config consensus vote is outside the immutable voter set",
        ));
    }
    if let Some(current) = read_vote_sync(conn, identity, expected_members)? {
        if vote.partial_cmp(&current) != Some(std::cmp::Ordering::Greater) && vote != &current {
            return Err(invalid_data("config consensus vote did not advance"));
        }
    }
    let node_id = vote
        .leader_id
        .voted_for()
        .map(|node| checked_positive_i64(node.get()))
        .transpose()?;
    conn.execute(
        "INSERT OR REPLACE INTO config_raft_vote (singleton, configuration_epoch, term, node_id, vote_json) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            epoch_i64(identity)?,
            checked_i64(vote.leader_id.term)?,
            node_id,
            encode_json(vote)?,
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

fn read_log_pointer(
    conn: &Connection,
    table: &'static str,
    identity: ConsensusIdentity,
) -> io::Result<Option<LogId<ConsensusNodeId>>> {
    let sql = format!(
        "SELECT configuration_epoch, term, log_index, log_id_json FROM {table} WHERE singleton = 1"
    );
    let row = conn
        .query_row(&sql, [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .optional()
        .map_err(db_error)?;
    let Some((epoch, term, index, encoded)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    let log_id: LogId<ConsensusNodeId> = decode_json(&encoded)?;
    if checked_u64(term)? != log_id.leader_id.term || checked_u64(index)? != log_id.index {
        return Err(invalid_data(
            "persisted config consensus log pointer mismatch",
        ));
    }
    Ok(Some(log_id))
}

fn save_log_pointer(
    conn: &Connection,
    table: &'static str,
    identity: ConsensusIdentity,
    log_id: &LogId<ConsensusNodeId>,
) -> io::Result<()> {
    let (term, index) = validate_log_id(log_id)?;
    conn.execute(
        &format!("INSERT OR REPLACE INTO {table} (singleton, configuration_epoch, term, log_index, log_id_json) VALUES (1, ?1, ?2, ?3, ?4)"),
        params![epoch_i64(identity)?, term, index, encode_json(log_id)?],
    )
    .map_err(db_error)?;
    Ok(())
}

pub(crate) fn read_committed_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
) -> io::Result<Option<LogId<ConsensusNodeId>>> {
    read_log_pointer(conn, "config_raft_committed", identity)
}

pub(crate) fn save_committed_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    committed: Option<LogId<ConsensusNodeId>>,
) -> io::Result<()> {
    let Some(committed) = committed else {
        if read_committed_sync(conn, identity)?.is_some() {
            return Err(invalid_data(
                "config consensus committed pointer cannot clear",
            ));
        }
        return Ok(());
    };
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    if let Some(current) = read_committed_sync(&tx, identity)? {
        if committed.index < current.index
            || (committed.index == current.index && committed != current)
        {
            return Err(invalid_data("config consensus committed pointer regressed"));
        }
    }
    for floor in [
        read_applied_sync(&tx, identity)?,
        read_purged_sync(&tx, identity)?,
    ] {
        if floor.is_some_and(|floor| {
            committed.index < floor.index || (committed.index == floor.index && committed != floor)
        }) {
            return Err(invalid_data(
                "config consensus committed pointer crosses durable floor",
            ));
        }
    }
    if validate_pointer_against_log_sync(&tx, identity, &committed).is_err() {
        let covered = read_applied_sync(&tx, identity)? == Some(committed)
            || read_purged_sync(&tx, identity)? == Some(committed)
            || read_snapshot_log_id_unchecked_sync(&tx, identity)? == Some(committed);
        if !covered {
            return Err(invalid_data(
                "config consensus committed pointer lacks durable lineage",
            ));
        }
    }
    save_log_pointer(&tx, "config_raft_committed", identity, &committed)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn read_purged_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
) -> io::Result<Option<LogId<ConsensusNodeId>>> {
    read_log_pointer(conn, "config_raft_purged", identity)
}

pub(crate) fn read_applied_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
) -> io::Result<Option<LogId<ConsensusNodeId>>> {
    read_log_pointer(conn, "config_raft_applied", identity)
}

pub(crate) fn last_log_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
) -> io::Result<Option<LogId<ConsensusNodeId>>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, term, log_index, entry_json FROM config_raft_log ORDER BY log_index DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    if let Some((epoch, term, index, encoded)) = row {
        validate_epoch(epoch, identity)?;
        let entry: Entry<ConfigRaftTypeConfig> = decode_json(&encoded)?;
        if checked_u64(term)? != entry.log_id.leader_id.term
            || checked_u64(index)? != entry.log_id.index
        {
            return Err(invalid_data("persisted config consensus log row mismatch"));
        }
        return Ok(Some(entry.log_id));
    }
    read_purged_sync(conn, identity)
}

fn validate_entry(
    entry: &Entry<ConfigRaftTypeConfig>,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
) -> io::Result<()> {
    match &entry.payload {
        EntryPayload::Normal(command) => command
            .validate(identity)
            .map_err(|_| invalid_data("invalid encrypted config consensus command")),
        EntryPayload::Membership(membership) => validate_fixed_membership(
            &StoredMembership::new(Some(entry.log_id), membership.clone()),
            expected_members,
        ),
        EntryPayload::Blank => Ok(()),
    }
}

fn read_log_id_at_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    index: u64,
) -> io::Result<Option<LogId<ConsensusNodeId>>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, term, entry_json FROM config_raft_log WHERE log_index = ?1",
            [checked_i64(index)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, term, encoded)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    if encoded.len() > CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
        return Err(invalid_data(
            "persisted config consensus log entry exceeds storage limit",
        ));
    }
    let entry: Entry<ConfigRaftTypeConfig> = decode_json(&encoded)?;
    if entry.log_id.index != index || checked_u64(term)? != entry.log_id.leader_id.term {
        return Err(invalid_data("persisted config consensus log row mismatch"));
    }
    Ok(Some(entry.log_id))
}

fn validate_pointer_against_log_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    pointer: &LogId<ConsensusNodeId>,
) -> io::Result<()> {
    let Some(stored) = read_log_id_at_sync(conn, identity, pointer.index)? else {
        return Err(invalid_data(
            "config consensus pointer has no exact durable log entry",
        ));
    };
    if stored != *pointer {
        return Err(invalid_data(
            "config consensus pointer does not match durable log entry",
        ));
    }
    Ok(())
}

fn read_snapshot_log_id_unchecked_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
) -> io::Result<Option<LogId<ConsensusNodeId>>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, meta_json FROM config_raft_snapshot WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, encoded)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    let meta: SnapshotMeta<ConsensusNodeId, EmptyNode> = decode_json(&encoded)?;
    Ok(meta.last_log_id)
}

fn validate_ordered_floor(
    lower: Option<LogId<ConsensusNodeId>>,
    upper: Option<LogId<ConsensusNodeId>>,
) -> io::Result<()> {
    if let (Some(lower), Some(upper)) = (lower, upper) {
        if lower.index > upper.index || (lower.index == upper.index && lower != upper) {
            return Err(invalid_data(
                "config consensus durable log pointers are inconsistent",
            ));
        }
    }
    Ok(())
}

fn validate_durable_log_state_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    allow_detached_snapshot: bool,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    cancellation.check_io()?;
    let (committed, applied, purged) = validate_durable_pointer_relationships_sync(conn, identity)?;
    let snapshot_log_id = read_current_snapshot_sync(conn, identity, expected_members)?
        .and_then(|(meta, _, _, _)| meta.last_log_id);

    if let Some(applied_pointer) = applied {
        let covered = read_log_id_at_sync(conn, identity, applied_pointer.index)?
            .is_some_and(|stored| stored == applied_pointer)
            || purged == Some(applied_pointer)
            || snapshot_log_id == Some(applied_pointer)
            || (allow_detached_snapshot && snapshot_log_id.is_none());
        if !covered {
            return Err(invalid_data(
                "config consensus applied pointer lacks log or snapshot lineage",
            ));
        }
    }
    if let Some(committed_pointer) = committed {
        let covered = read_log_id_at_sync(conn, identity, committed_pointer.index)?
            .is_some_and(|stored| stored == committed_pointer)
            || applied == Some(committed_pointer)
            || purged == Some(committed_pointer)
            || snapshot_log_id == Some(committed_pointer);
        if !covered {
            return Err(invalid_data(
                "config consensus committed pointer lacks durable lineage",
            ));
        }
    }
    if purged.is_some() && snapshot_log_id.is_none() && !allow_detached_snapshot {
        return Err(invalid_data(
            "config consensus purged pointer lacks snapshot lineage",
        ));
    }

    let (minimum, maximum, count): (Option<i64>, Option<i64>, i64) = conn
        .query_row(
            "SELECT MIN(log_index), MAX(log_index), COUNT(*) FROM config_raft_log",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(db_error)?;
    match (minimum, maximum, count) {
        (None, None, 0) => {}
        (Some(minimum), Some(maximum), count) if count > 0 => {
            let minimum = checked_u64(minimum)?;
            let maximum = checked_u64(maximum)?;
            let expected_count = maximum
                .checked_sub(minimum)
                .and_then(|span| span.checked_add(1))
                .ok_or_else(|| invalid_data("config consensus log span overflow"))?;
            if checked_u64(count)? != expected_count {
                return Err(invalid_data(
                    "persisted config consensus log contains a hole",
                ));
            }
            if purged.is_some_and(|floor| minimum <= floor.index) {
                return Err(invalid_data(
                    "persisted config consensus log crosses purged floor",
                ));
            }
            let expected_minimum = match purged.or(snapshot_log_id) {
                Some(floor) => floor
                    .index
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("config consensus log floor overflow"))?,
                None => 0,
            };
            if minimum != expected_minimum {
                return Err(invalid_data(
                    "persisted config consensus log is detached from its floor",
                ));
            }
            let entries = read_log_rows_unchecked_sync(
                conn,
                identity,
                expected_members,
                minimum,
                Some(
                    maximum
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("config consensus log range overflow"))?,
                ),
                None,
                Some(cancellation),
            )?;
            if entries.len()
                != usize::try_from(expected_count)
                    .map_err(|_| invalid_data("config consensus log count overflow"))?
            {
                return Err(invalid_data(
                    "persisted config consensus log contains a hole",
                ));
            }
        }
        _ => {
            return Err(invalid_data(
                "persisted config consensus log aggregate is invalid",
            ))
        }
    }
    Ok(())
}

type DurableLogPointers = (
    Option<LogId<ConsensusNodeId>>,
    Option<LogId<ConsensusNodeId>>,
    Option<LogId<ConsensusNodeId>>,
);

fn validate_durable_pointer_relationships_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
) -> io::Result<DurableLogPointers> {
    let committed = read_committed_sync(conn, identity)?;
    let applied = read_applied_sync(conn, identity)?;
    let purged = read_purged_sync(conn, identity)?;
    validate_ordered_floor(purged, applied)?;
    validate_ordered_floor(applied, committed)?;
    validate_ordered_floor(purged, committed)?;
    Ok((committed, applied, purged))
}

fn read_log_rows_unchecked_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    start: u64,
    end: Option<u64>,
    limit: Option<usize>,
    cancellation: Option<&SqliteWorkCancellation>,
) -> io::Result<Vec<Entry<ConfigRaftTypeConfig>>> {
    let start = checked_i64(start)?;
    let end = end.map(checked_i64).transpose()?;
    let limit = limit
        .map(|limit| {
            i64::try_from(limit).map_err(|_| invalid_data("config consensus log limit overflow"))
        })
        .transpose()?
        .unwrap_or(i64::MAX);
    let mut statement = conn
        .prepare(
            "SELECT configuration_epoch, term, log_index, entry_json FROM config_raft_log WHERE log_index >= ?1 AND (?2 IS NULL OR log_index < ?2) ORDER BY log_index ASC LIMIT ?3",
        )
        .map_err(db_error)?;
    let rows = statement
        .query_map(params![start, end, limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(db_error)?;
    let mut entries = Vec::new();
    for row in rows {
        if let Some(cancellation) = cancellation {
            cancellation.check_io()?;
        }
        let (epoch, term, index, encoded) = row.map_err(db_error)?;
        validate_epoch(epoch, identity)?;
        if encoded.len() > CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(invalid_data(
                "persisted config consensus log entry exceeds storage limit",
            ));
        }
        let entry: Entry<ConfigRaftTypeConfig> = decode_json(&encoded)?;
        if checked_u64(term)? != entry.log_id.leader_id.term
            || checked_u64(index)? != entry.log_id.index
        {
            return Err(invalid_data("persisted config consensus log row mismatch"));
        }
        validate_entry(&entry, identity, expected_members)?;
        entries.push(entry);
    }
    for pair in entries.windows(2) {
        if pair[1].log_id.index != pair[0].log_id.index.saturating_add(1) {
            return Err(invalid_data(
                "persisted config consensus log contains a hole",
            ));
        }
    }
    Ok(entries)
}

pub(crate) fn read_log_range_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    start: u64,
    end: Option<u64>,
    limit: Option<usize>,
) -> io::Result<Vec<Entry<ConfigRaftTypeConfig>>> {
    let (_, _, purged) = validate_durable_pointer_relationships_sync(conn, identity)?;
    let entries =
        read_log_rows_unchecked_sync(conn, identity, expected_members, start, end, limit, None)?;
    if limit == Some(0) {
        return Ok(entries);
    }
    let expected_start = match purged {
        Some(purged) if start <= purged.index => purged.index.checked_add(1),
        _ => Some(start),
    };
    if let Some(expected_start) = expected_start {
        let range_can_contain_expected = end.is_none_or(|end| expected_start < end);
        if range_can_contain_expected {
            if let Some(first) = entries.first() {
                if first.log_id.index != expected_start {
                    return Err(invalid_data(
                        "persisted config consensus log contains a hole",
                    ));
                }
            } else {
                let later_exists: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM config_raft_log WHERE log_index > ?1 AND (?2 IS NULL OR log_index < ?2))",
                        params![checked_i64(expected_start)?, end.map(checked_i64).transpose()?],
                        |row| row.get(0),
                    )
                    .map_err(db_error)?;
                if later_exists {
                    return Err(invalid_data(
                        "persisted config consensus log contains a hole",
                    ));
                }
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
pub(crate) fn append_logs_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    entries: &[Entry<ConfigRaftTypeConfig>],
) -> io::Result<()> {
    append_logs_cancellable_sync(
        conn,
        identity,
        expected_members,
        entries,
        &SqliteWorkCancellation::new(),
    )
}

pub(crate) fn append_logs_cancellable_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    entries: &[Entry<ConfigRaftTypeConfig>],
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    if entries.len() > CONFIG_CONSENSUS_LOG_APPEND_MAX_ENTRIES {
        return Err(invalid_data(
            "config consensus log append exceeds entry-count limit",
        ));
    }
    let mut encoded_entries = Vec::with_capacity(entries.len());
    let mut encoded_bytes = 0_usize;
    for entry in entries {
        cancellation.check_io()?;
        validate_entry(entry, identity, expected_members)?;
        let remaining = CONFIG_CONSENSUS_LOG_APPEND_MAX_BYTES
            .checked_sub(encoded_bytes)
            .ok_or_else(|| {
                invalid_data("config consensus log append exceeds aggregate byte limit")
            })?;
        let entry_budget = CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES.min(remaining);
        let limit_message = if remaining < CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            "config consensus log append exceeds aggregate byte limit"
        } else {
            "config consensus log entry exceeds storage limit"
        };
        let encoded =
            encode_json_bounded_cancellable(entry, entry_budget, limit_message, cancellation)?;
        encoded_bytes = encoded_bytes
            .checked_add(encoded.len())
            .ok_or_else(|| invalid_data("config consensus log append byte count overflow"))?;
        encoded_entries.push(encoded);
    }
    cancellation.check_io()?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    let (committed, applied, purged) = validate_durable_pointer_relationships_sync(&tx, identity)?;
    let floor = [last_log_sync(&tx, identity)?, committed, applied, purged]
        .into_iter()
        .flatten()
        .max_by_key(|log_id| log_id.index);
    let expected = floor
        .map(|log_id| {
            log_id
                .index
                .checked_add(1)
                .ok_or_else(|| invalid_data("config consensus log index exhausted"))
        })
        .transpose()?
        .unwrap_or(0);
    if entries[0].log_id.index != expected {
        return Err(invalid_data(
            "config consensus log append would overwrite a durable entry or create a hole",
        ));
    }
    for (offset, entry) in entries.iter().enumerate() {
        cancellation.check_io()?;
        let offset = u64::try_from(offset)
            .map_err(|_| invalid_data("config consensus log batch exceeds integer range"))?;
        if entry.log_id.index
            != expected
                .checked_add(offset)
                .ok_or_else(|| invalid_data("config consensus log index exhausted"))?
        {
            return Err(invalid_data("config consensus log batch is not contiguous"));
        }
    }
    for (entry, encoded) in entries.iter().zip(encoded_entries) {
        cancellation.check_io()?;
        tx.execute(
            "INSERT INTO config_raft_log (log_index, configuration_epoch, term, entry_json) VALUES (?1, ?2, ?3, ?4)",
            params![
                checked_i64(entry.log_id.index)?,
                epoch_i64(identity)?,
                checked_i64(entry.log_id.leader_id.term)?,
                encoded,
            ],
        )
        .map_err(db_error)?;
    }
    cancellation.check_io()?;
    tx.commit().map_err(db_error)
}

pub(crate) fn truncate_logs_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    log_id: &LogId<ConsensusNodeId>,
) -> io::Result<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    for floor in [
        read_committed_sync(&tx, identity)?,
        read_applied_sync(&tx, identity)?,
        read_purged_sync(&tx, identity)?,
    ] {
        if floor.is_some_and(|floor| log_id.index <= floor.index) {
            return Err(invalid_data(
                "cannot truncate config consensus durable log floor",
            ));
        }
    }
    tx.execute(
        "DELETE FROM config_raft_log WHERE log_index >= ?1",
        [checked_i64(log_id.index)?],
    )
    .map_err(db_error)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn purge_logs_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    log_id: &LogId<ConsensusNodeId>,
) -> io::Result<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    if read_applied_sync(&tx, identity)?.is_none_or(|applied| {
        log_id.index > applied.index || (log_id.index == applied.index && *log_id != applied)
    }) {
        return Err(invalid_data("cannot purge unapplied config consensus log"));
    }
    if let Some(purged) = read_purged_sync(&tx, identity)? {
        if log_id.index < purged.index || (log_id.index == purged.index && *log_id != purged) {
            return Err(invalid_data("config consensus purged pointer regressed"));
        }
    }
    validate_pointer_against_log_sync(&tx, identity, log_id)?;
    tx.execute(
        "DELETE FROM config_raft_log WHERE log_index <= ?1",
        [checked_i64(log_id.index)?],
    )
    .map_err(db_error)?;
    save_log_pointer(&tx, "config_raft_purged", identity, log_id)?;
    tx.commit().map_err(db_error)
}

fn read_membership_unchecked_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
) -> io::Result<StoredMembership<ConsensusNodeId, EmptyNode>> {
    let (epoch, encoded): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT configuration_epoch, membership_json FROM config_raft_membership WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    decode_json(&encoded)
}

pub(crate) fn read_membership_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
) -> io::Result<StoredMembership<ConsensusNodeId, EmptyNode>> {
    let membership = read_membership_unchecked_sync(conn, identity)?;
    if is_pristine_membership(&membership) && read_applied_sync(conn, identity)?.is_none() {
        return Ok(membership);
    }
    validate_fixed_membership(&membership, expected_members)?;
    Ok(membership)
}

fn store_membership_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    membership: &StoredMembership<ConsensusNodeId, EmptyNode>,
) -> io::Result<()> {
    validate_fixed_membership(membership, expected_members)?;
    conn.execute(
        "INSERT OR REPLACE INTO config_raft_membership (singleton, configuration_epoch, membership_json) VALUES (1, ?1, ?2)",
        params![epoch_i64(identity)?, encode_json(membership)?],
    )
    .map_err(db_error)?;
    Ok(())
}

type MachineState = (u64, ConsensusEntryDigest, Option<Timestamp>);

pub(crate) fn read_machine_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
) -> io::Result<MachineState> {
    let (epoch, sequence, digest, logical_time): (i64, i64, Vec<u8>, Option<String>) = conn
        .query_row(
            "SELECT configuration_epoch, application_sequence, last_digest, logical_time FROM config_raft_machine WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| invalid_data("invalid config consensus machine digest"))?;
    let logical_time = logical_time
        .map(|value| {
            Timestamp::from_str(&value)
                .map_err(|_| invalid_data("invalid config consensus logical time"))
        })
        .transpose()?;
    Ok((
        checked_u64(sequence)?,
        ConsensusEntryDigest::from_bytes(digest),
        logical_time,
    ))
}

fn read_outcome_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    request_id: opc_consensus::ConsensusRequestId,
) -> io::Result<Option<([u8; 32], ConfigConsensusResponse)>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, payload_digest, response_json FROM config_raft_request_outcomes WHERE request_id = ?1",
            [request_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, digest, response)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    Ok(Some((
        digest
            .try_into()
            .map_err(|_| invalid_data("invalid config consensus outcome digest"))?,
        decode_json(&response)?,
    )))
}

fn commit_source(source: &CommitSource) -> &'static str {
    match source {
        CommitSource::Gnmi => "gnmi",
        CommitSource::Netconf => "netconf",
        CommitSource::LocalOperator => "local_operator",
        CommitSource::StartupRestore => "startup_restore",
        CommitSource::Rollback => "rollback",
        CommitSource::CommitConfirmedRestore => "commit_confirmed_restore",
    }
}

fn audit_op_type(op: &AuditOpType) -> &'static str {
    match op {
        AuditOpType::Create => "CREATE",
        AuditOpType::Update => "UPDATE",
        AuditOpType::Replace => "REPLACE",
        AuditOpType::Delete => "DELETE",
    }
}

fn deterministic_row_id(domain: &[u8], identity: &[u8]) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(b"openpacketcore/config-consensus/sqlite-row-id/v1\0");
    hasher.update((domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    hasher.update((identity.len() as u32).to_be_bytes());
    hasher.update(identity);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let id = u64::from_be_bytes(bytes) & i64::MAX as u64;
    i64::try_from(id.max(1)).expect("masked deterministic row ID fits i64")
}

fn append_prepared_commit_sync(
    conn: &Connection,
    commit: &super::PreparedConfigCommit,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    cancellation.check_io()?;
    if commit.validate().is_err() {
        return Ok(Err(ConfigMutationFailure::InvalidInput));
    }
    let record = &commit.record;
    let tx_id = record.tx_id.as_uuid().as_bytes().as_slice();
    let duplicate: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM config_history WHERE tx_id = ?1 OR version = ?2)",
            params![tx_id, checked_i64(record.version.get())?],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if duplicate {
        return Ok(Err(ConfigMutationFailure::Conflict));
    }
    let latest: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT tx_id, version FROM config_history ORDER BY version DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db_error)?;
    match (latest, record.parent_tx_id) {
        (None, None) => {}
        (Some((latest_tx, latest_version)), Some(parent))
            if latest_tx.as_slice() == parent.as_uuid().as_bytes()
                && checked_u64(latest_version)?
                    .checked_add(1)
                    .is_some_and(|next| next == record.version.get()) => {}
        _ => return Ok(Err(ConfigMutationFailure::Conflict)),
    }
    let terminal_hash = commit
        .audit
        .last()
        .map(|entry| entry.entry_hmac)
        .unwrap_or([0_u8; 32]);
    conn.execute(
        r#"INSERT INTO config_history
            (tx_id, parent_tx_id, version, committed_at, principal, source,
             schema_digest, plaintext_digest, encrypted_blob, rollback_point,
             confirmed_deadline, audit_count, audit_terminal_hash)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"#,
        params![
            tx_id,
            record
                .parent_tx_id
                .map(|parent| parent.as_uuid().as_bytes().to_vec()),
            checked_i64(record.version.get())?,
            record.committed_at.to_string(),
            &record.principal,
            commit_source(&record.source),
            record.schema_digest.as_bytes(),
            &record.plaintext_digest,
            &record.encrypted_blob,
            i32::from(record.rollback_point),
            record.confirmed_deadline.map(|value| value.to_string()),
            i64::try_from(commit.audit.len())
                .map_err(|_| invalid_data("config audit count overflow"))?,
            terminal_hash.as_slice(),
        ],
    )
    .map_err(db_error)?;
    for entry in &commit.audit {
        cancellation.check_io()?;
        let mut audit_identity = tx_id.to_vec();
        audit_identity.extend_from_slice(&entry.sequence.to_be_bytes());
        conn.execute(
            r#"INSERT INTO audit_trail
                (id, tx_id, sequence, yang_path, op_type, previous_value, new_value,
                 redaction_applied, previous_hash, entry_hmac)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            params![
                deterministic_row_id(b"audit", &audit_identity),
                tx_id,
                i64::from(entry.sequence),
                &entry.yang_path,
                audit_op_type(&entry.op_type),
                &entry.previous_value,
                &entry.new_value,
                i32::from(entry.redaction_applied),
                entry.previous_hash.as_slice(),
                entry.entry_hmac.as_slice(),
            ],
        )
        .map_err(db_error)?;
    }
    Ok(Ok(()))
}

fn mark_confirmed_sync(
    conn: &Connection,
    tx_id: opc_types::TxId,
    logical_time: Timestamp,
    request_id: opc_consensus::ConsensusRequestId,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    let tx_id = tx_id.as_uuid().as_bytes().as_slice();
    let principal: Option<String> = conn
        .query_row(
            "SELECT principal FROM config_history WHERE tx_id = ?1",
            [tx_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    let Some(principal) = principal else {
        return Ok(Err(ConfigMutationFailure::NotFound));
    };
    conn.execute(
        "UPDATE config_history SET confirmed_at = ?1 WHERE tx_id = ?2",
        params![logical_time.to_string(), tx_id],
    )
    .map_err(db_error)?;
    conn.execute(
        "INSERT INTO config_lifecycle_audit (id, tx_id, action, principal, occurred_at, details) VALUES (?1, ?2, 'MARK_CONFIRMED', ?3, ?4, 'commit confirmed')",
        params![deterministic_row_id(b"lifecycle-confirm", request_id.as_bytes()), tx_id, principal, logical_time.to_string()],
    )
    .map_err(db_error)?;
    Ok(Ok(()))
}

fn create_rollback_point_sync(
    conn: &Connection,
    tx_id: opc_types::TxId,
    label: &Option<super::types::ValidatedRollbackLabel>,
    logical_time: Timestamp,
    request_id: opc_consensus::ConsensusRequestId,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    if let Some(label) = label {
        let label = label.as_str();
        let collision: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM rollback_labels WHERE label = ?1 AND tx_id != ?2)",
                params![label, tx_id.as_uuid().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if collision {
            return Ok(Err(ConfigMutationFailure::Conflict));
        }
    }
    let bytes = tx_id.as_uuid().as_bytes().as_slice();
    let principal: Option<String> = conn
        .query_row(
            "SELECT principal FROM config_history WHERE tx_id = ?1",
            [bytes],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    let Some(principal) = principal else {
        return Ok(Err(ConfigMutationFailure::NotFound));
    };
    conn.execute(
        "UPDATE config_history SET rollback_point = 1 WHERE tx_id = ?1",
        [bytes],
    )
    .map_err(db_error)?;
    if let Some(label) = label {
        let label = label.as_str();
        conn.execute(
            "INSERT OR REPLACE INTO rollback_labels (label, tx_id, created_at) VALUES (?1, ?2, ?3)",
            params![label, bytes, logical_time.to_string()],
        )
        .map_err(db_error)?;
    }
    let details = if label.is_some() {
        "named rollback point created"
    } else {
        "rollback point created"
    };
    conn.execute(
        "INSERT INTO config_lifecycle_audit (id, tx_id, action, principal, occurred_at, details) VALUES (?1, ?2, 'CREATE_ROLLBACK_POINT', ?3, ?4, ?5)",
        params![deterministic_row_id(b"lifecycle-rollback", request_id.as_bytes()), bytes, principal, logical_time.to_string(), details],
    )
    .map_err(db_error)?;
    Ok(Ok(()))
}

fn execute_intent_sync(
    conn: &Connection,
    intent: &ConfigMutationIntent,
    logical_time: Timestamp,
    request_id: opc_consensus::ConsensusRequestId,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    match intent {
        ConfigMutationIntent::AppendCommit(commit) => {
            append_prepared_commit_sync(conn, commit, cancellation)
        }
        ConfigMutationIntent::MarkConfirmed { tx_id } => {
            mark_confirmed_sync(conn, *tx_id, logical_time, request_id)
        }
        ConfigMutationIntent::CreateRollbackPoint { tx_id, label } => {
            create_rollback_point_sync(conn, *tx_id, label, logical_time, request_id)
        }
    }
}

#[cfg(test)]
pub(crate) fn apply_entries_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    entries: Vec<Entry<ConfigRaftTypeConfig>>,
) -> io::Result<Vec<ConfigConsensusResponse>> {
    apply_entries_cancellable_sync(
        conn,
        identity,
        expected_members,
        entries,
        &SqliteWorkCancellation::new(),
    )
}

pub(crate) fn apply_entries_cancellable_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    entries: Vec<Entry<ConfigRaftTypeConfig>>,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<Vec<ConfigConsensusResponse>> {
    if entries.len() > CONFIG_CONSENSUS_LOG_APPEND_MAX_ENTRIES {
        return Err(invalid_data(
            "config consensus apply exceeds entry-count limit",
        ));
    }
    let mut encoded_bytes = 0_usize;
    for entry in &entries {
        cancellation.check_io()?;
        validate_entry(entry, identity, expected_members)?;
        let remaining = CONFIG_CONSENSUS_LOG_APPEND_MAX_BYTES
            .checked_sub(encoded_bytes)
            .ok_or_else(|| invalid_data("config consensus apply exceeds aggregate byte limit"))?;
        let entry_budget = CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES.min(remaining);
        let limit_message = if remaining < CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            "config consensus apply exceeds aggregate byte limit"
        } else {
            "config consensus apply entry exceeds storage limit"
        };
        let encoded =
            encode_json_bounded_cancellable(entry, entry_budget, limit_message, cancellation)?;
        encoded_bytes = encoded_bytes
            .checked_add(encoded.len())
            .ok_or_else(|| invalid_data("config consensus apply byte count overflow"))?;
    }
    let tx = conn.unchecked_transaction().map_err(db_error)?;
    let mut last_applied = read_applied_sync(&tx, identity)?;
    let mut machine = read_machine_sync(&tx, identity)?;
    let mut responses = Vec::with_capacity(entries.len());
    for entry in entries {
        cancellation.check_io()?;
        let expected_index = last_applied
            .map(|log_id| {
                log_id
                    .index
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("config consensus applied index exhausted"))
            })
            .transpose()?
            .unwrap_or(0);
        if entry.log_id.index != expected_index {
            return Err(invalid_data("config consensus apply is not contiguous"));
        }
        let response = match entry.payload {
            EntryPayload::Blank => ConfigConsensusResponse {
                result: Ok(()),
                sequence: 0,
                digest: None,
                logical_time: None,
                raft_log_index: entry.log_id.index,
            },
            EntryPayload::Membership(membership) => {
                let stored = StoredMembership::new(Some(entry.log_id), membership);
                store_membership_sync(&tx, identity, expected_members, &stored)?;
                ConfigConsensusResponse {
                    result: Ok(()),
                    sequence: 0,
                    digest: None,
                    logical_time: None,
                    raft_log_index: entry.log_id.index,
                }
            }
            EntryPayload::Normal(command) => {
                command
                    .validate(identity)
                    .map_err(|_| invalid_data("invalid committed config consensus command"))?;
                let payload_digest = command
                    .payload_digest()
                    .map_err(|_| invalid_data("config consensus payload digest failed"))?;
                if let Some((stored_digest, stored_response)) =
                    read_outcome_sync(&tx, identity, command.request_id)?
                {
                    if payload_digest != stored_digest {
                        ConfigConsensusResponse {
                            result: Err(ConfigMutationFailure::RequestIdCollision),
                            sequence: machine.0,
                            digest: (machine.0 != 0).then_some(machine.1),
                            logical_time: machine.2,
                            raft_log_index: entry.log_id.index,
                        }
                    } else {
                        stored_response
                    }
                } else {
                    let sequence = machine
                        .0
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("config consensus sequence exhausted"))?;
                    let logical_time = machine
                        .2
                        .map_or(command.logical_time, |last| last.max(command.logical_time));
                    let digest = command
                        .calculate_applied_digest(sequence, machine.1, logical_time)
                        .map_err(|_| invalid_data("config consensus applied digest failed"))?;
                    let result = execute_intent_sync(
                        &tx,
                        &command.intent,
                        logical_time,
                        command.request_id,
                        cancellation,
                    )?;
                    let response = ConfigConsensusResponse {
                        result,
                        sequence,
                        digest: Some(digest),
                        logical_time: Some(logical_time),
                        raft_log_index: entry.log_id.index,
                    };
                    tx.execute(
                        "INSERT INTO config_raft_request_outcomes (request_id, configuration_epoch, applied_sequence, payload_digest, response_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            command.request_id.as_bytes().as_slice(),
                            epoch_i64(identity)?,
                            checked_positive_i64(sequence)?,
                            payload_digest.as_slice(),
                            encode_json(&response)?,
                        ],
                    )
                    .map_err(db_error)?;
                    let expired_through =
                        sequence.saturating_sub(CONFIG_CONSENSUS_RETAINED_REQUEST_OUTCOMES);
                    if expired_through > 0 {
                        tx.execute(
                            "DELETE FROM config_raft_request_outcomes WHERE applied_sequence <= ?1",
                            [checked_positive_i64(expired_through)?],
                        )
                        .map_err(db_error)?;
                    }
                    let changed = tx
                        .execute(
                            "UPDATE config_raft_machine SET application_sequence = ?1, last_digest = ?2, logical_time = ?3 WHERE singleton = 1 AND configuration_epoch = ?4",
                            params![
                                checked_positive_i64(sequence)?,
                                digest.as_bytes().as_slice(),
                                logical_time.to_string(),
                                epoch_i64(identity)?,
                            ],
                        )
                        .map_err(db_error)?;
                    if changed != 1 {
                        return Err(invalid_data("config consensus machine state is missing"));
                    }
                    machine = (sequence, digest, Some(logical_time));
                    response
                }
            }
        };
        save_log_pointer(&tx, "config_raft_applied", identity, &entry.log_id)?;
        last_applied = Some(entry.log_id);
        responses.push(response);
    }
    let membership = read_membership_unchecked_sync(&tx, identity)?;
    if !is_pristine_membership(&membership) {
        validate_fixed_membership(&membership, expected_members)?;
    }
    cancellation.check_io()?;
    tx.commit().map_err(db_error)?;
    Ok(responses)
}

fn validate_sealed_state_sync(
    conn: &Connection,
    audit_key: &AuditKey,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    validate_history_chain_cancellable_sync(conn, cancellation)?;
    let mut statement = conn
        .prepare(
            "SELECT tx_id, parent_tx_id, version, committed_at, principal, schema_digest, plaintext_digest, encrypted_blob, audit_count, audit_terminal_hash FROM config_history ORDER BY version ASC",
        )
        .map_err(db_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Vec<u8>>(9)?,
            ))
        })
        .map_err(db_error)?;
    for row in rows {
        cancellation.check_io()?;
        let (
            tx_id,
            parent_tx_id,
            version,
            committed_at,
            principal,
            schema_digest,
            plaintext_digest,
            encrypted_blob,
            audit_count,
            terminal_hash,
        ) = row.map_err(db_error)?;
        if tx_id.len() != 16
            || parent_tx_id
                .as_ref()
                .is_some_and(|parent| parent.len() != 16)
            || schema_digest.len() != 32
            || plaintext_digest.len() != 32
            || terminal_hash.len() != 32
        {
            return Err(invalid_data(
                "config consensus sealed record metadata is invalid",
            ));
        }
        let envelope = opc_crypto::CryptoEnvelopeV1::decode(&encrypted_blob).map_err(|_| {
            invalid_data("config consensus state contains plaintext or malformed envelope")
        })?;
        if envelope.nonce.len() != envelope.algorithm.nonce_len()
            || envelope.aad.is_empty()
            || envelope.ciphertext_and_tag.len() < opc_key::AEAD_TAG_LEN
        {
            return Err(invalid_data("config consensus state envelope is invalid"));
        }
        let (aad, key_id) = opc_key::decode_bound_aad(&envelope.aad)
            .map_err(|_| invalid_data("config consensus state AAD is invalid"))?;
        let opc_key::EnvelopeMetadata::Config(metadata) = aad.metadata() else {
            return Err(invalid_data(
                "config consensus state AAD purpose is invalid",
            ));
        };
        let tx_uuid = uuid::Uuid::from_slice(&tx_id)
            .map_err(|_| invalid_data("config consensus transaction ID is invalid"))?;
        let tx_id_value = opc_types::TxId::from_uuid(tx_uuid);
        let parent_value = parent_tx_id
            .as_deref()
            .map(uuid::Uuid::from_slice)
            .transpose()
            .map_err(|_| invalid_data("config consensus parent ID is invalid"))?
            .map(opc_types::TxId::from_uuid);
        let version = checked_u64(version)?;
        let committed_at = Timestamp::from_str(&committed_at)
            .map_err(|_| invalid_data("config consensus committed time is invalid"))?;
        let schema_digest = opc_types::SchemaDigest::from_bytes(
            schema_digest
                .try_into()
                .map_err(|_| invalid_data("config consensus schema digest is invalid"))?,
        );
        if key_id != envelope.key_id
            || aad.purpose() != opc_key::KeyPurpose::Config
            || aad.version() != version
            || metadata.tx_id() != &tx_id_value
            || metadata.parent_tx_id() != parent_value.as_ref()
            || metadata.committed_at() != &committed_at
            || metadata.principal() != principal
            || metadata.schema_digest() != &schema_digest
        {
            return Err(invalid_data("config consensus state AAD metadata mismatch"));
        }
        let audit_count = usize::try_from(audit_count)
            .map_err(|_| invalid_data("config consensus audit count is invalid"))?;
        if audit_count > super::types::CONFIG_AUDIT_RECORDS_MAX {
            return Err(invalid_data(
                "config consensus audit count exceeds durable bound",
            ));
        }
        let mut audit = conn
            .prepare(
                "SELECT sequence, yang_path, op_type, previous_value, new_value, redaction_applied, previous_hash, entry_hmac FROM audit_trail WHERE tx_id = ?1 ORDER BY sequence ASC",
            )
            .map_err(db_error)?;
        let rows = audit
            .query_map([tx_id.as_slice()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            })
            .map_err(db_error)?;
        let mut previous = [0_u8; 32];
        let mut seen = 0_usize;
        for row in rows {
            cancellation.check_io()?;
            let (sequence, yang_path, op_type, old, new, redacted, previous_hash, entry_hmac) =
                row.map_err(db_error)?;
            let previous_hash: [u8; 32] = previous_hash
                .try_into()
                .map_err(|_| invalid_data("config consensus audit predecessor is invalid"))?;
            let entry_hmac: [u8; 32] = entry_hmac
                .try_into()
                .map_err(|_| invalid_data("config consensus audit HMAC is invalid"))?;
            let sequence = u32::try_from(sequence)
                .map_err(|_| invalid_data("config consensus audit sequence is invalid"))?;
            let op_type = match op_type.as_str() {
                "CREATE" => AuditOpType::Create,
                "UPDATE" => AuditOpType::Update,
                "REPLACE" => AuditOpType::Replace,
                "DELETE" => AuditOpType::Delete,
                _ => return Err(invalid_data("config consensus audit operation is invalid")),
            };
            if usize::try_from(sequence).ok() != Some(seen)
                || previous_hash != previous
                || !super::types::audit_path_is_safe(&yang_path)
                || old
                    .as_deref()
                    .is_some_and(|value| value != "\"<redacted>\"")
                || new
                    .as_deref()
                    .is_some_and(|value| value != "\"<redacted>\"")
                || (old.is_some() || new.is_some()) && redacted != 1
            {
                return Err(invalid_data("config consensus audit state is invalid"));
            }
            let entry = crate::types::AuditRecord {
                tx_id: tx_id_value,
                sequence,
                yang_path,
                op_type,
                previous_value: old,
                new_value: new,
                redaction_applied: redacted == 1,
                previous_hash,
                entry_hmac,
            };
            let expected_hmac = entry.calculate_hmac_with_audit_count(
                audit_key,
                &crate::types::extract_tenant(&principal),
                u32::try_from(audit_count)
                    .map_err(|_| invalid_data("config consensus audit count is invalid"))?,
            );
            if entry_hmac != expected_hmac {
                return Err(invalid_data("config consensus audit HMAC is invalid"));
            }
            previous = entry_hmac;
            seen = seen
                .checked_add(1)
                .ok_or_else(|| invalid_data("config consensus audit count overflow"))?;
        }
        if seen != audit_count || previous.as_slice() != terminal_hash.as_slice() {
            return Err(invalid_data("config consensus audit anchor mismatch"));
        }
    }

    let mut statement = conn
        .prepare("SELECT applied_sequence, response_json FROM config_raft_request_outcomes")
        .map_err(db_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(db_error)?;
    let mut outcome_count = 0_u64;
    for row in rows {
        cancellation.check_io()?;
        let (applied_sequence, encoded) = row.map_err(db_error)?;
        let response: ConfigConsensusResponse = decode_json(&encoded)?;
        if checked_positive_u64(applied_sequence)? != response.sequence {
            return Err(invalid_data(
                "config consensus request outcome sequence mismatch",
            ));
        }
        outcome_count = outcome_count
            .checked_add(1)
            .ok_or_else(|| invalid_data("config consensus request outcome count overflow"))?;
        if outcome_count > CONFIG_CONSENSUS_RETAINED_REQUEST_OUTCOMES {
            return Err(invalid_data(
                "config consensus request outcomes exceed retention bound",
            ));
        }
    }
    Ok(())
}

fn validate_history_chain_sync(conn: &Connection) -> io::Result<Option<(Vec<u8>, u64)>> {
    validate_history_chain_cancellable_sync(conn, &SqliteWorkCancellation::new())
}

fn validate_history_chain_cancellable_sync(
    conn: &Connection,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<Option<(Vec<u8>, u64)>> {
    let mut statement = conn
        .prepare(
            "SELECT tx_id, parent_tx_id, version FROM config_history ORDER BY version ASC, tx_id ASC",
        )
        .map_err(db_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(db_error)?;
    let mut head: Option<(Vec<u8>, u64)> = None;
    for row in rows {
        cancellation.check_io()?;
        let (tx_id, parent_tx_id, version) = row.map_err(db_error)?;
        if tx_id.len() != 16
            || parent_tx_id
                .as_ref()
                .is_some_and(|parent| parent.len() != 16)
        {
            return Err(invalid_data(
                "config consensus history transaction ID is invalid",
            ));
        }
        let version = checked_u64(version)?;
        match &head {
            None if parent_tx_id.is_none() => {}
            Some((previous_tx_id, previous_version))
                if parent_tx_id.as_deref() == Some(previous_tx_id.as_slice())
                    && previous_version
                        .checked_add(1)
                        .is_some_and(|next| next == version) => {}
            _ => {
                return Err(invalid_data(
                    "config consensus history is not a contiguous linear chain",
                ))
            }
        }
        head = Some((tx_id, version));
    }
    Ok(head)
}

pub(crate) type AppliedMembership = (
    Option<LogId<ConsensusNodeId>>,
    StoredMembership<ConsensusNodeId, EmptyNode>,
);

#[cfg(test)]
pub(crate) fn build_snapshot_database_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    audit_key: &AuditKey,
    path: &Path,
) -> io::Result<AppliedMembership> {
    build_snapshot_database_cancellable_sync(
        conn,
        identity,
        expected_members,
        audit_key,
        path,
        &Arc::new(SqliteWorkCancellation::new()),
    )
}

pub(crate) fn build_snapshot_database_cancellable_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    audit_key: &AuditKey,
    path: &Path,
    cancellation: &Arc<SqliteWorkCancellation>,
) -> io::Result<AppliedMembership> {
    cancellation.check_io()?;
    validate_sealed_state_sync(conn, audit_key, cancellation)?;
    let applied = read_applied_sync(conn, identity)?;
    let membership = read_membership_sync(conn, identity, expected_members)?;
    validate_fixed_membership(&membership, expected_members)?;
    let mut destination = Connection::open(path).map_err(db_error)?;
    let progress_cancellation = cancellation.clone();
    destination.progress_handler(1_000, Some(move || progress_cancellation.is_cancelled()));
    {
        let backup = rusqlite::backup::Backup::new(conn, &mut destination).map_err(db_error)?;
        loop {
            cancellation.check_io()?;
            match backup.step(128).map_err(db_error)? {
                rusqlite::backup::StepResult::Done => break,
                rusqlite::backup::StepResult::More => {}
                rusqlite::backup::StepResult::Busy | rusqlite::backup::StepResult::Locked => {
                    std::thread::yield_now();
                }
                _ => return Err(invalid_data("config consensus snapshot backup failed")),
            }
        }
    }
    cancellation.check_io()?;
    destination
        .execute_batch(
            r#"
            DELETE FROM config_raft_vote;
            DELETE FROM config_raft_committed;
            DELETE FROM config_raft_purged;
            DELETE FROM config_raft_log;
            DELETE FROM config_raft_snapshot;
            PRAGMA journal_mode = DELETE;
            VACUUM;
            "#,
        )
        .map_err(db_error)?;
    cancellation.check_io()?;
    validate_existing_schema(
        &destination,
        identity,
        expected_members,
        audit_key,
        true,
        cancellation,
    )
    .map_err(|_| invalid_data("built config consensus snapshot failed validation"))?;
    validate_snapshot_has_no_log_authority(&destination, cancellation)?;
    Ok((applied, membership))
}

fn validate_snapshot_has_no_log_authority(
    conn: &Connection,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    for table in [
        "config_raft_vote",
        "config_raft_committed",
        "config_raft_purged",
        "config_raft_log",
        "config_raft_snapshot",
    ] {
        cancellation.check_io()?;
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(db_error)?;
        if count != 0 {
            return Err(invalid_data("config snapshot contains log-store authority"));
        }
    }
    Ok(())
}

fn validate_snapshot_database_sync(
    path: &Path,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    audit_key: &AuditKey,
    meta: &SnapshotMeta<ConsensusNodeId, EmptyNode>,
    cancellation: &Arc<SqliteWorkCancellation>,
) -> io::Result<()> {
    cancellation.check_io()?;
    validate_fixed_membership(&meta.last_membership, expected_members)?;
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(db_error)?;
    let progress_cancellation = cancellation.clone();
    conn.progress_handler(1_000, Some(move || progress_cancellation.is_cancelled()));
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(db_error)?;
    if integrity != "ok" {
        return Err(invalid_data(
            "config consensus snapshot integrity check failed",
        ));
    }
    cancellation.check_io()?;
    validate_existing_schema(
        &conn,
        identity,
        expected_members,
        audit_key,
        true,
        cancellation,
    )
    .map_err(|_| invalid_data("config consensus snapshot identity is invalid"))?;
    validate_sealed_state_sync(&conn, audit_key, cancellation)?;
    validate_snapshot_has_no_log_authority(&conn, cancellation)?;
    if read_applied_sync(&conn, identity)? != meta.last_log_id
        || read_membership_sync(&conn, identity, expected_members)? != meta.last_membership
    {
        return Err(invalid_data("config consensus snapshot metadata mismatch"));
    }
    Ok(())
}

fn valid_snapshot_file_name(file_name: &str) -> bool {
    !file_name.is_empty()
        && file_name != "."
        && file_name != ".."
        && !file_name.contains('/')
        && !file_name.contains('\\')
        && file_name.len() <= 255
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn install_snapshot_database_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    audit_key: &AuditKey,
    snapshot_db_path: &Path,
    meta: &SnapshotMeta<ConsensusNodeId, EmptyNode>,
    final_file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    install_snapshot_database_cancellable_sync(
        conn,
        identity,
        expected_members,
        audit_key,
        snapshot_db_path,
        meta,
        final_file_name,
        checksum,
        byte_length,
        &Arc::new(SqliteWorkCancellation::new()),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn install_snapshot_database_cancellable_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    audit_key: &AuditKey,
    snapshot_db_path: &Path,
    meta: &SnapshotMeta<ConsensusNodeId, EmptyNode>,
    final_file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
    cancellation: &Arc<SqliteWorkCancellation>,
) -> io::Result<()> {
    validate_snapshot_database_sync(
        snapshot_db_path,
        identity,
        expected_members,
        audit_key,
        meta,
        cancellation,
    )?;
    if !valid_snapshot_file_name(final_file_name) {
        return Err(invalid_data("invalid config consensus snapshot file name"));
    }
    let snapshot_path = snapshot_db_path
        .to_str()
        .ok_or_else(|| invalid_data("config consensus snapshot path is not UTF-8"))?;
    cancellation.check_io()?;
    let stale_incoming: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_database_list WHERE name = 'config_raft_incoming')",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if stale_incoming {
        // A previous post-commit cleanup failure is non-authoritative, but it
        // must not poison every later install attempt on this shared handle.
        // This pre-transaction detach is safe to fail: no new authority has
        // been written yet.
        conn.execute("DETACH DATABASE config_raft_incoming", [])
            .map_err(db_error)?;
    }
    conn.execute(
        "ATTACH DATABASE ?1 AS config_raft_incoming",
        [snapshot_path],
    )
    .map_err(db_error)?;
    let result = (|| {
        cancellation.check_io()?;
        let tx = conn.unchecked_transaction().map_err(db_error)?;
        for table in [
            "config_lifecycle_audit",
            "rollback_labels",
            "audit_trail",
            "config_history",
            "config_raft_request_outcomes",
            "config_raft_machine",
            "config_raft_membership",
            "config_raft_applied",
        ] {
            cancellation.check_io()?;
            tx.execute(&format!("DELETE FROM {table}"), [])
                .map_err(db_error)?;
        }
        for (table, columns) in [
            (
                "config_history",
                "tx_id, parent_tx_id, version, committed_at, principal, source, schema_digest, plaintext_digest, encrypted_blob, rollback_point, rollback_label, confirmed_deadline, confirmed_at, audit_count, audit_terminal_hash",
            ),
            (
                "audit_trail",
                "id, tx_id, sequence, yang_path, op_type, previous_value, new_value, redaction_applied, previous_hash, entry_hmac",
            ),
            ("rollback_labels", "label, tx_id, created_at"),
            (
                "config_lifecycle_audit",
                "id, tx_id, action, principal, occurred_at, details",
            ),
            (
                "config_raft_request_outcomes",
                "request_id, configuration_epoch, applied_sequence, payload_digest, response_json",
            ),
            (
                "config_raft_machine",
                "singleton, configuration_epoch, application_sequence, last_digest, logical_time",
            ),
            (
                "config_raft_membership",
                "singleton, configuration_epoch, membership_json",
            ),
            (
                "config_raft_applied",
                "singleton, configuration_epoch, term, log_index, log_id_json",
            ),
        ] {
            cancellation.check_io()?;
            tx.execute(
                &format!("INSERT INTO {table} ({columns}) SELECT {columns} FROM config_raft_incoming.{table}"),
                [],
            )
            .map_err(db_error)?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO config_raft_snapshot (singleton, configuration_epoch, meta_json, file_name, checksum, byte_length) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                epoch_i64(identity)?,
                encode_json(meta)?,
                final_file_name,
                checksum.as_slice(),
                checked_positive_i64(byte_length)?,
            ],
        )
        .map_err(db_error)?;
        cancellation.check_io()?;
        tx.commit().map_err(db_error)
    })();
    let detach = conn
        .execute("DETACH DATABASE config_raft_incoming", [])
        .map_err(db_error);
    match result {
        Ok(()) => {
            // The state-machine transaction is authority. A post-commit
            // DETACH failure must not turn that durable success into an error
            // that makes the caller delete the now-referenced envelope.
            let _ = detach;
            Ok(())
        }
        Err(error) => {
            let _ = detach;
            Err(error)
        }
    }
}

pub(crate) fn save_current_snapshot_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
    meta: &SnapshotMeta<ConsensusNodeId, EmptyNode>,
    file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    validate_fixed_membership(&meta.last_membership, expected_members)?;
    if !valid_snapshot_file_name(file_name) {
        return Err(invalid_data("invalid config consensus snapshot file name"));
    }
    conn.execute(
        "INSERT OR REPLACE INTO config_raft_snapshot (singleton, configuration_epoch, meta_json, file_name, checksum, byte_length) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            epoch_i64(identity)?,
            encode_json(meta)?,
            file_name,
            checksum.as_slice(),
            checked_positive_i64(byte_length)?,
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

pub(crate) type CurrentSnapshot = (
    SnapshotMeta<ConsensusNodeId, EmptyNode>,
    String,
    [u8; 32],
    u64,
);

pub(crate) fn read_current_snapshot_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    expected_members: &BTreeSet<ConsensusNodeId>,
) -> io::Result<Option<CurrentSnapshot>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, meta_json, file_name, checksum, byte_length FROM config_raft_snapshot WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, i64>(4)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, encoded, file_name, checksum, length)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    if !valid_snapshot_file_name(&file_name) {
        return Err(invalid_data("invalid persisted config snapshot file name"));
    }
    let meta: SnapshotMeta<ConsensusNodeId, EmptyNode> = decode_json(&encoded)?;
    validate_fixed_membership(&meta.last_membership, expected_members)?;
    Ok(Some((
        meta,
        file_name,
        checksum
            .try_into()
            .map_err(|_| invalid_data("invalid persisted config snapshot checksum"))?,
        checked_positive_u64(length)?,
    )))
}

#[cfg(test)]
mod tests {
    use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId, Membership};
    use opc_types::{ConfigVersion, TxId};

    use super::*;
    use crate::consensus::types::ValidatedRollbackLabel;
    use crate::consensus::{
        ConfigConsensusClusterId, ConfigConsensusCommand, ConfigConsensusConfigurationEpoch,
        ConfigConsensusConfigurationId, ConfigConsensusRequestId, ConfigMutationIntent,
        CONFIG_CONSENSUS_COMMAND_VERSION,
    };

    fn identity() -> ConsensusIdentity {
        ConsensusIdentity::new(
            ConfigConsensusClusterId::new("config-state-machine-tests").expect("cluster ID"),
            ConfigConsensusConfigurationId::from_bytes([0x71; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("configuration epoch"),
        )
    }

    fn node_id() -> ConsensusNodeId {
        ConsensusNodeId::new(7).expect("node ID")
    }

    fn expected_members() -> BTreeSet<ConsensusNodeId> {
        BTreeSet::from([node_id()])
    }

    fn log_id(index: u64) -> LogId<ConsensusNodeId> {
        LogId::new(CommittedLeaderId::new(1, node_id()), index)
    }

    fn log_id_with_term(term: u64, index: u64) -> LogId<ConsensusNodeId> {
        LogId::new(CommittedLeaderId::new(term, node_id()), index)
    }

    fn membership_entry() -> Entry<ConfigRaftTypeConfig> {
        Entry {
            log_id: log_id(0),
            payload: EntryPayload::Membership(Membership::new(
                vec![expected_members()],
                expected_members(),
            )),
        }
    }

    fn mark_confirmed_entry(
        index: u64,
        request_id: [u8; 16],
        tx_id: TxId,
    ) -> Entry<ConfigRaftTypeConfig> {
        mark_confirmed_entry_with_term(1, index, request_id, tx_id)
    }

    fn mark_confirmed_entry_with_term(
        term: u64,
        index: u64,
        request_id: [u8; 16],
        tx_id: TxId,
    ) -> Entry<ConfigRaftTypeConfig> {
        Entry {
            log_id: log_id_with_term(term, index),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
                identity: identity(),
                request_id: ConfigConsensusRequestId::from_bytes(request_id),
                logical_time: Timestamp::now_utc(),
                intent: ConfigMutationIntent::MarkConfirmed { tx_id },
            }),
        }
    }

    fn rollback_label_entry(label_length: usize) -> Entry<ConfigRaftTypeConfig> {
        Entry {
            log_id: log_id(1),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
                identity: identity(),
                request_id: ConfigConsensusRequestId::from_bytes([0xC1; 16]),
                logical_time: Timestamp::from_str("2026-01-01T00:00:00Z").expect("fixed timestamp"),
                intent: ConfigMutationIntent::CreateRollbackPoint {
                    tx_id: TxId::new(),
                    label: Some(ValidatedRollbackLabel("x".repeat(label_length))),
                },
            }),
        }
    }

    async fn initialized_backend() -> SqliteBackend {
        let backend = SqliteBackend::in_memory_for_test()
            .await
            .expect("in-memory config backend");
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        initialize_schema(
            &conn,
            identity(),
            &expected_members(),
            backend.audit_key(),
            None,
            &Arc::new(SqliteWorkCancellation::new()),
            None,
        )
        .expect("config consensus schema");
        drop(conn);
        backend
    }

    fn insert_history_metadata(
        conn: &Connection,
        tx_id: &[u8],
        parent_tx_id: Option<&[u8]>,
        version: u64,
    ) {
        conn.execute(
            r#"INSERT INTO config_history
                (tx_id, parent_tx_id, version, committed_at, principal, source,
                 schema_digest, plaintext_digest, encrypted_blob, rollback_point,
                 confirmed_deadline, confirmed_at, audit_count, audit_terminal_hash)
                VALUES (?1, ?2, ?3, '2026-01-01T00:00:00Z', ?4, 'gnmi',
                        ?5, ?6, ?7, 0, NULL, NULL, 0, ?8)"#,
            params![
                tx_id,
                parent_tx_id,
                checked_i64(version).expect("version"),
                "spiffe://test.example/tenant/tenant-a/ns/core/sa/config/nf/amf/instance/a",
                [0x11_u8; 32].as_slice(),
                [0x22_u8; 32].as_slice(),
                [0x33_u8; 32].as_slice(),
                [0_u8; 32].as_slice(),
            ],
        )
        .expect("history metadata");
    }

    #[tokio::test]
    async fn history_validation_accepts_bootstrap_and_arbitrary_origins_but_rejects_forks() {
        let backend = initialized_backend().await;
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        let first = [0x01_u8; 16];
        let second = [0x02_u8; 16];
        for first_version in [ConfigVersion::INITIAL.get(), 41] {
            conn.execute("DELETE FROM config_history", [])
                .expect("reset history origin");
            insert_history_metadata(&conn, &first, None, first_version);
            insert_history_metadata(&conn, &second, Some(&first), first_version + 1);
            assert_eq!(
                Some((second.to_vec(), first_version + 1)),
                validate_history_chain_sync(&conn).expect("valid history origin")
            );
        }

        conn.execute_batch("PRAGMA foreign_keys = OFF;")
            .expect("permit malformed external history fixtures");
        let invalid_cases = [
            (Some([0x09_u8; 16]), 41_u64, Some(first), 42_u64),
            (None, 41, Some(first), 43),
            (None, 41, Some([0x09_u8; 16]), 42),
        ];
        for (first_parent, first_version, second_parent, second_version) in invalid_cases {
            conn.execute("DELETE FROM config_history", [])
                .expect("reset history");
            insert_history_metadata(
                &conn,
                &first,
                first_parent.as_ref().map(|value| &value[..]),
                first_version,
            );
            insert_history_metadata(
                &conn,
                &second,
                second_parent.as_ref().map(|value| &value[..]),
                second_version,
            );
            assert!(
                validate_history_chain_sync(&conn).is_err(),
                "non-linear history was accepted"
            );
        }

        conn.execute("DELETE FROM config_history", [])
            .expect("reset history");
        insert_history_metadata(&conn, &[0x04; 15], None, 41);
        assert!(validate_history_chain_sync(&conn).is_err());
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("restore foreign keys");
    }

    #[tokio::test]
    async fn invalid_snapshot_history_is_rejected_before_target_mutation() {
        let temp = tempfile::tempdir().expect("snapshot directory");
        let source = initialized_backend().await;
        let source_conn = source.conn();
        let source_conn = source_conn.lock().await;
        let membership = membership_entry();
        apply_entries_sync(
            &source_conn,
            identity(),
            &expected_members(),
            vec![membership.clone()],
        )
        .expect("source membership");
        let snapshot_path = temp.path().join("invalid-chain.sqlite");
        let (last_log_id, last_membership) = build_snapshot_database_sync(
            &source_conn,
            identity(),
            &expected_members(),
            source.audit_key(),
            &snapshot_path,
        )
        .expect("source snapshot database");
        drop(source_conn);

        let incoming = Connection::open(&snapshot_path).expect("open incoming snapshot");
        let first = [0x71_u8; 16];
        let second = [0x72_u8; 16];
        insert_history_metadata(&incoming, &first, None, 17);
        insert_history_metadata(&incoming, &second, Some(&first), 19);
        drop(incoming);

        let target = initialized_backend().await;
        let target_conn = target.conn();
        let target_conn = target_conn.lock().await;
        target_conn
            .execute(
                "UPDATE config_raft_machine SET application_sequence = 73 WHERE singleton = 1",
                [],
            )
            .expect("target sentinel");
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "invalid-history".to_owned(),
        };
        assert!(install_snapshot_database_sync(
            &target_conn,
            identity(),
            &expected_members(),
            target.audit_key(),
            &snapshot_path,
            &meta,
            "snapshot-invalid.opc",
            [0x81; 32],
            1,
        )
        .is_err());
        let sequence: i64 = target_conn
            .query_row(
                "SELECT application_sequence FROM config_raft_machine WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("target sentinel after rejection");
        assert_eq!(73, sequence);
        let target_history: i64 = target_conn
            .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
            .expect("target history count");
        assert_eq!(0, target_history);
    }

    #[tokio::test]
    async fn committed_applied_and_purged_floors_are_immutable() {
        let backend = initialized_backend().await;
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        let membership = membership_entry();
        let applied = mark_confirmed_entry(1, [0x11; 16], TxId::new());
        let tail = mark_confirmed_entry(2, [0x22; 16], TxId::new());
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            &[membership.clone(), applied.clone(), tail.clone()],
        )
        .expect("initial log");
        save_committed_sync(&conn, identity(), Some(applied.log_id)).expect("committed floor");
        apply_entries_sync(
            &conn,
            identity(),
            &expected_members(),
            vec![membership, applied.clone()],
        )
        .expect("applied floor");
        purge_logs_sync(&conn, identity(), &log_id(0)).expect("purged floor");

        assert!(save_committed_sync(
            &conn,
            identity(),
            Some(log_id_with_term(2, applied.log_id.index)),
        )
        .is_err());
        assert_eq!(
            Some(applied.log_id),
            read_committed_sync(&conn, identity()).expect("committed pointer")
        );
        assert!(purge_logs_sync(&conn, identity(), &log_id_with_term(2, 0)).is_err());
        assert_eq!(
            Some(log_id(0)),
            read_purged_sync(&conn, identity()).expect("purged pointer")
        );

        assert!(truncate_logs_sync(&conn, identity(), &applied.log_id).is_err());
        conn.execute("DELETE FROM config_raft_committed", [])
            .expect("isolate applied floor");
        assert!(truncate_logs_sync(&conn, identity(), &applied.log_id).is_err());
        conn.execute("DELETE FROM config_raft_applied", [])
            .expect("isolate purged floor");
        assert!(truncate_logs_sync(&conn, identity(), &log_id(0)).is_err());

        let replacement = mark_confirmed_entry_with_term(2, 2, [0x33; 16], TxId::new());
        assert!(append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            std::slice::from_ref(&replacement),
        )
        .is_err());
        assert_eq!(
            Some(tail.log_id),
            last_log_sync(&conn, identity()).expect("tail remains intact")
        );
    }

    #[tokio::test]
    async fn uncommitted_tail_can_be_truncated_and_reappended() {
        let backend = initialized_backend().await;
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        let membership = membership_entry();
        let committed = mark_confirmed_entry(1, [0x41; 16], TxId::new());
        let stale_tail = mark_confirmed_entry(2, [0x42; 16], TxId::new());
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            &[membership.clone(), committed.clone(), stale_tail],
        )
        .expect("initial log");
        save_committed_sync(&conn, identity(), Some(committed.log_id)).expect("committed floor");
        apply_entries_sync(
            &conn,
            identity(),
            &expected_members(),
            vec![membership, committed.clone()],
        )
        .expect("applied prefix");

        truncate_logs_sync(&conn, identity(), &log_id(2)).expect("truncate uncommitted tail");
        let replacement = mark_confirmed_entry_with_term(2, 2, [0x43; 16], TxId::new());
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            std::slice::from_ref(&replacement),
        )
        .expect("append replacement tail");
        assert_eq!(
            vec![committed.log_id, replacement.log_id],
            read_log_range_sync(&conn, identity(), &expected_members(), 1, None, None,)
                .expect("read replacement")
                .into_iter()
                .map(|entry| entry.log_id)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn persisted_log_holes_fail_reads_and_startup_validation() {
        let backend = initialized_backend().await;
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            &[
                membership_entry(),
                mark_confirmed_entry(1, [0x51; 16], TxId::new()),
                mark_confirmed_entry(2, [0x52; 16], TxId::new()),
            ],
        )
        .expect("initial log");
        conn.execute("DELETE FROM config_raft_log WHERE log_index = 1", [])
            .expect("inject persisted hole");

        assert!(
            read_log_range_sync(&conn, identity(), &expected_members(), 0, None, None,).is_err()
        );
        assert_eq!(
            Err(ConfigConsensusStorageError::CorruptState),
            initialize_schema(
                &conn,
                identity(),
                &expected_members(),
                backend.audit_key(),
                None,
                &Arc::new(SqliteWorkCancellation::new()),
                None,
            )
        );
    }

    #[tokio::test]
    async fn preproposal_label_bound_is_stricter_than_log_storage_ceiling() {
        let accepted =
            rollback_label_entry(crate::consensus::types::CONFIG_ROLLBACK_LABEL_MAX_BYTES);
        assert!(
            encode_json(&accepted).expect("bounded encoding").len()
                < CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES
        );
        let backend = initialized_backend().await;
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            &[membership_entry(), accepted],
        )
        .expect("maximum valid label entry");
        drop(conn);
        drop(shared_conn);
        drop(backend);

        let rejected =
            rollback_label_entry(crate::consensus::types::CONFIG_ROLLBACK_LABEL_MAX_BYTES + 1);
        let backend = initialized_backend().await;
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            std::slice::from_ref(&membership_entry()),
        )
        .expect("membership log");
        assert!(append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            std::slice::from_ref(&rejected),
        )
        .is_err());
        assert_eq!(
            Some(log_id(0)),
            last_log_sync(&conn, identity()).expect("invalid append is atomic")
        );
    }

    #[tokio::test]
    async fn inconsistent_durable_pointers_fail_startup_validation() {
        let backend = initialized_backend().await;
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            &[
                membership_entry(),
                mark_confirmed_entry(1, [0x61; 16], TxId::new()),
            ],
        )
        .expect("initial log");
        save_log_pointer(&conn, "config_raft_committed", identity(), &log_id(0))
            .expect("committed pointer");
        save_log_pointer(&conn, "config_raft_applied", identity(), &log_id(1))
            .expect("inconsistent applied pointer");

        assert_eq!(
            Err(ConfigConsensusStorageError::CorruptState),
            initialize_schema(
                &conn,
                identity(),
                &expected_members(),
                backend.audit_key(),
                None,
                &Arc::new(SqliteWorkCancellation::new()),
                None,
            )
        );
    }

    #[tokio::test]
    async fn committed_but_unapplied_entry_replays_after_atomic_apply_faults() {
        let backend = initialized_backend().await;
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        let membership = membership_entry();
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            std::slice::from_ref(&membership),
        )
        .expect("membership log");
        save_committed_sync(&conn, identity(), Some(membership.log_id))
            .expect("membership committed");
        apply_entries_sync(&conn, identity(), &expected_members(), vec![membership])
            .expect("membership applied");

        let tx_id = TxId::new();
        conn.execute(
            r#"INSERT INTO config_history
                (tx_id, parent_tx_id, version, committed_at, principal, source,
                 schema_digest, plaintext_digest, encrypted_blob, rollback_point,
                 confirmed_deadline, confirmed_at, audit_count, audit_terminal_hash)
                VALUES (?1, NULL, ?2, ?3, ?4, 'gnmi', ?5, ?6, ?7, 0,
                        NULL, NULL, 0, ?8)"#,
            params![
                tx_id.as_uuid().as_bytes().as_slice(),
                checked_i64(ConfigVersion::new(1).get()).expect("version"),
                Timestamp::now_utc().to_string(),
                "spiffe://test.example/tenant/tenant-a/ns/core/sa/config/nf/amf/instance/a",
                [0x11_u8; 32].as_slice(),
                [0x22_u8; 32].as_slice(),
                [0x33_u8; 32].as_slice(),
                [0_u8; 32].as_slice(),
            ],
        )
        .expect("seed target record");
        let entry = mark_confirmed_entry(1, [0xA1; 16], tx_id);
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            std::slice::from_ref(&entry),
        )
        .expect("normal log");
        save_committed_sync(&conn, identity(), Some(entry.log_id)).expect("normal committed");
        let baseline_machine = read_machine_sync(&conn, identity()).expect("baseline machine");

        conn.execute_batch(
            r#"
            CREATE TRIGGER fail_config_lifecycle_apply
            BEFORE INSERT ON config_lifecycle_audit
            BEGIN
                SELECT RAISE(ABORT, 'node-local-secret-canary');
            END;
            "#,
        )
        .expect("install mid-intent fault");
        let error = apply_entries_sync(&conn, identity(), &expected_members(), vec![entry.clone()])
            .expect_err("mid-intent SQLite fault must abort apply");
        assert_eq!(io::ErrorKind::Other, error.kind());
        assert!(!error.to_string().contains("node-local-secret-canary"));
        conn.execute("DROP TRIGGER fail_config_lifecycle_apply", [])
            .expect("remove mid-intent fault");

        for stage in ["mid-intent", "before-commit"] {
            assert_eq!(
                Some(entry.log_id),
                read_committed_sync(&conn, identity()).expect("committed pointer"),
                "{stage}: committed authority must survive"
            );
            assert_eq!(
                Some(log_id(0)),
                read_applied_sync(&conn, identity()).expect("applied pointer"),
                "{stage}: applied pointer must not advance"
            );
            assert_eq!(
                baseline_machine,
                read_machine_sync(&conn, identity()).expect("machine state"),
                "{stage}: machine state must roll back"
            );
            assert!(
                read_outcome_sync(
                    &conn,
                    identity(),
                    ConfigConsensusRequestId::from_bytes([0xA1; 16]),
                )
                .expect("outcome lookup")
                .is_none(),
                "{stage}: outcome must roll back"
            );
            let confirmed: Option<String> = conn
                .query_row(
                    "SELECT confirmed_at FROM config_history WHERE tx_id = ?1",
                    [tx_id.as_uuid().as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .expect("confirmed timestamp");
            assert!(
                confirmed.is_none(),
                "{stage}: domain mutation must roll back"
            );
        }

        conn.execute_batch(
            r#"
            CREATE TRIGGER fail_config_applied_pointer
            BEFORE INSERT ON config_raft_applied
            WHEN NEW.log_index = 1
            BEGIN
                SELECT RAISE(ABORT, 'after-outcome-before-commit');
            END;
            "#,
        )
        .expect("install pre-commit fault");
        apply_entries_sync(&conn, identity(), &expected_members(), vec![entry.clone()])
            .expect_err("fault after domain, outcome, and machine writes must abort apply");
        conn.execute("DROP TRIGGER fail_config_applied_pointer", [])
            .expect("remove pre-commit fault");
        assert_eq!(
            Some(log_id(0)),
            read_applied_sync(&conn, identity()).expect("applied after pre-commit fault")
        );
        assert_eq!(
            baseline_machine,
            read_machine_sync(&conn, identity()).expect("machine after pre-commit fault")
        );
        assert!(read_outcome_sync(
            &conn,
            identity(),
            ConfigConsensusRequestId::from_bytes([0xA1; 16]),
        )
        .expect("outcome after pre-commit fault")
        .is_none());

        apply_entries_sync(&conn, identity(), &expected_members(), vec![entry.clone()])
            .expect("committed entry replay");
        assert_eq!(
            Some(entry.log_id),
            read_applied_sync(&conn, identity()).expect("replayed applied pointer")
        );
        assert!(read_outcome_sync(
            &conn,
            identity(),
            ConfigConsensusRequestId::from_bytes([0xA1; 16]),
        )
        .expect("replayed outcome")
        .is_some());
    }

    #[tokio::test]
    async fn history_beyond_65536_entries_snapshots_and_compacts_with_bounded_reads() {
        const HISTORY_ENTRIES: u64 = 65_537;
        const CHUNK: u64 = 1_024;

        let backend = initialized_backend().await;
        let shared_conn = backend.conn();
        let conn = shared_conn.lock().await;
        let membership = membership_entry();
        append_logs_sync(
            &conn,
            identity(),
            &expected_members(),
            std::slice::from_ref(&membership),
        )
        .expect("membership log");
        save_committed_sync(&conn, identity(), Some(membership.log_id))
            .expect("membership committed");
        apply_entries_sync(&conn, identity(), &expected_members(), vec![membership])
            .expect("membership applied");

        let missing_tx = TxId::new();
        let mut start = 1_u64;
        while start <= HISTORY_ENTRIES {
            let end = start
                .saturating_add(CHUNK)
                .min(HISTORY_ENTRIES.saturating_add(1));
            let entries = (start..end)
                .map(|index| {
                    mark_confirmed_entry(index, u128::from(index).to_be_bytes(), missing_tx)
                })
                .collect::<Vec<_>>();
            append_logs_sync(&conn, identity(), &expected_members(), &entries)
                .expect("bounded log append");
            save_committed_sync(&conn, identity(), entries.last().map(|entry| entry.log_id))
                .expect("advance committed pointer");
            apply_entries_sync(&conn, identity(), &expected_members(), entries)
                .expect("bounded state-machine apply");
            start = end;
        }

        let machine = read_machine_sync(&conn, identity()).expect("machine state");
        assert_eq!(HISTORY_ENTRIES, machine.0);
        let outcome_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM config_raft_request_outcomes",
                [],
                |row| row.get(0),
            )
            .expect("outcome count");
        assert_eq!(
            i64::try_from(CONFIG_CONSENSUS_RETAINED_REQUEST_OUTCOMES).expect("retention fits i64"),
            outcome_count
        );
        let bounded = read_log_range_sync(
            &conn,
            identity(),
            &expected_members(),
            1,
            None,
            Some(CHUNK as usize),
        )
        .expect("bounded range read");
        assert_eq!(CHUNK as usize, bounded.len());

        let temp = tempfile::tempdir().expect("snapshot directory");
        let snapshot = temp.path().join("large-history.sqlite");
        build_snapshot_database_sync(
            &conn,
            identity(),
            &expected_members(),
            backend.audit_key(),
            &snapshot,
        )
        .expect("large history snapshot");
        assert!(snapshot.metadata().expect("snapshot metadata").len() > 0);

        purge_logs_sync(&conn, identity(), &log_id(HISTORY_ENTRIES)).expect("compact applied log");
        let remaining_logs: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| row.get(0))
            .expect("remaining log count");
        assert_eq!(0, remaining_logs);
        assert_eq!(
            Some(log_id(HISTORY_ENTRIES)),
            read_purged_sync(&conn, identity()).expect("purged pointer")
        );
    }
}
