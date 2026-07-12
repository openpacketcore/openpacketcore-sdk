//! Fail-closed SQLite persistence for the Openraft session state machine.
//!
//! This module contains synchronous transaction primitives. The Openraft
//! adapter in `consensus::storage` owns async locking and maps these coarse,
//! redaction-safe failures into Openraft storage errors.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use opc_consensus::engine::{Entry, EntryPayload, LogId, StoredMembership, Vote};
use opc_types::Timestamp;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::backend::{CompareAndSetResult, ReplicationEntry, ReplicationOp};
use crate::capability::BackendCapabilities;
use crate::consensus::storage::SessionConsensusStorageError;
use crate::consensus::types::{
    SessionConsensusCommand, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
    SessionConsensusEntryDigest, SessionConsensusIdentity, SessionConsensusNodeId,
    SessionConsensusRequestId, SessionConsensusResponse, SessionMutationIntent,
    SessionMutationOutcome, SESSION_CONSENSUS_SCHEMA_VERSION,
};
use crate::consensus::SessionRaftTypeConfig;
use crate::error::{LeaseError, StoreError};
use crate::record::SessionPayloadEncoding;

use super::{lease, ops, SqliteSessionBackend};

const CONSENSUS_LOG_ENTRY_MAX_BYTES: usize = 16 * 1024 * 1024;
const OUTCOME_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/outcome-payload/v1\0";
const OPERATOR_RECOVERY_LATCH_MAGIC: &[u8; 8] = b"OPCRL001";
const OPERATOR_RECOVERY_LATCH_BYTES: usize = 8 + 32 + 32 + 8 + 8 + 32 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OperatorRecoveryLatch {
    pub(crate) identity: SessionConsensusIdentity,
    pub(crate) recovery_epoch: u64,
    pub(crate) plan_digest: [u8; 32],
    pub(crate) audit_pending: bool,
}

pub(crate) fn operator_recovery_latch_path(database: &Path) -> io::Result<PathBuf> {
    let name = database
        .file_name()
        .ok_or_else(|| invalid_data("session recovery database path has no file name"))?;
    let mut latch_name = name.to_os_string();
    latch_name.push(".opc-recovery-latch");
    Ok(database.with_file_name(latch_name))
}

fn encode_operator_recovery_latch(
    latch: OperatorRecoveryLatch,
) -> [u8; OPERATOR_RECOVERY_LATCH_BYTES] {
    let mut encoded = [0_u8; OPERATOR_RECOVERY_LATCH_BYTES];
    encoded[..8].copy_from_slice(OPERATOR_RECOVERY_LATCH_MAGIC);
    encoded[8..40].copy_from_slice(latch.identity.cluster_id().as_bytes());
    encoded[40..72].copy_from_slice(latch.identity.configuration_id().as_bytes());
    encoded[72..80].copy_from_slice(&latch.identity.configuration_epoch().get().to_be_bytes());
    encoded[80..88].copy_from_slice(&latch.recovery_epoch.to_be_bytes());
    encoded[88..120].copy_from_slice(&latch.plan_digest);
    encoded[120] = u8::from(latch.audit_pending);
    encoded
}

fn decode_operator_recovery_latch(
    encoded: &[u8; OPERATOR_RECOVERY_LATCH_BYTES],
) -> io::Result<OperatorRecoveryLatch> {
    if &encoded[..8] != OPERATOR_RECOVERY_LATCH_MAGIC || encoded[120] > 1 {
        return Err(invalid_data("session operator recovery latch is invalid"));
    }
    let cluster = encoded[8..40]
        .try_into()
        .map_err(|_| invalid_data("session operator recovery latch is invalid"))?;
    let configuration = encoded[40..72]
        .try_into()
        .map_err(|_| invalid_data("session operator recovery latch is invalid"))?;
    let configuration_epoch = u64::from_be_bytes(
        encoded[72..80]
            .try_into()
            .map_err(|_| invalid_data("session operator recovery latch is invalid"))?,
    );
    let recovery_epoch = u64::from_be_bytes(
        encoded[80..88]
            .try_into()
            .map_err(|_| invalid_data("session operator recovery latch is invalid"))?,
    );
    let plan_digest = encoded[88..120]
        .try_into()
        .map_err(|_| invalid_data("session operator recovery latch is invalid"))?;
    if recovery_epoch == 0 || plan_digest == [0; 32] {
        return Err(invalid_data("session operator recovery latch is invalid"));
    }
    let epoch = SessionConsensusConfigurationEpoch::new(configuration_epoch)
        .map_err(|_| invalid_data("session operator recovery latch is invalid"))?;
    Ok(OperatorRecoveryLatch {
        identity: SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::from_bytes(cluster),
            SessionConsensusConfigurationId::from_bytes(configuration),
            epoch,
        ),
        recovery_epoch,
        plan_digest,
        audit_pending: encoded[120] == 1,
    })
}

fn open_latch_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

pub(crate) fn read_operator_recovery_latch_sync(
    database: &Path,
) -> io::Result<Option<OperatorRecoveryLatch>> {
    let path = operator_recovery_latch_path(database)?;
    let mut file = match open_latch_read(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != OPERATOR_RECOVERY_LATCH_BYTES as u64 {
        return Err(invalid_data("session operator recovery latch is invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid_data(
                "session operator recovery latch permissions are invalid",
            ));
        }
    }
    let mut encoded = [0_u8; OPERATOR_RECOVERY_LATCH_BYTES];
    file.read_exact(&mut encoded)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(invalid_data("session operator recovery latch is oversized"));
    }
    decode_operator_recovery_latch(&encoded).map(Some)
}

fn write_latch_file(path: &Path, latch: OperatorRecoveryLatch, create_new: bool) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(!create_new)
        .create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    file.write_all(&encode_operator_recovery_latch(latch))?;
    file.flush()?;
    file.sync_all()?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| invalid_data("session recovery latch has no parent"))?,
    )?
    .sync_all()
}

pub(crate) fn ensure_operator_recovery_latch_sync(
    database: &Path,
    expected: OperatorRecoveryLatch,
) -> io::Result<()> {
    match read_operator_recovery_latch_sync(database)? {
        Some(observed)
            if observed == expected
                || (observed
                    == OperatorRecoveryLatch {
                        audit_pending: !expected.audit_pending,
                        ..expected
                    }) =>
        {
            Ok(())
        }
        Some(_) => Err(invalid_data(
            "a different session operator recovery latch is active",
        )),
        None => write_latch_file(&operator_recovery_latch_path(database)?, expected, true),
    }
}

pub(crate) fn set_operator_recovery_latch_audit_pending_sync(
    database: &Path,
    expected: OperatorRecoveryLatch,
    audit_pending: bool,
) -> io::Result<()> {
    let observed = read_operator_recovery_latch_sync(database)?
        .ok_or_else(|| invalid_data("session operator recovery latch is missing"))?;
    if observed.identity != expected.identity
        || observed.recovery_epoch != expected.recovery_epoch
        || observed.plan_digest != expected.plan_digest
    {
        return Err(invalid_data(
            "session operator recovery latch does not match",
        ));
    }
    let path = operator_recovery_latch_path(database)?;
    let temporary = path.with_extension("opc-recovery-latch.tmp");
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    write_latch_file(
        &temporary,
        OperatorRecoveryLatch {
            audit_pending,
            ..observed
        },
        true,
    )?;
    std::fs::rename(&temporary, &path)?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| invalid_data("session recovery latch has no parent"))?,
    )?
    .sync_all()
}

pub(crate) fn clear_operator_recovery_latch_sync(
    database: &Path,
    expected: OperatorRecoveryLatch,
) -> io::Result<()> {
    let Some(observed) = read_operator_recovery_latch_sync(database)? else {
        return Ok(());
    };
    if observed.identity != expected.identity
        || observed.recovery_epoch != expected.recovery_epoch
        || observed.plan_digest != expected.plan_digest
        || observed.audit_pending
    {
        return Err(invalid_data(
            "session operator recovery latch cannot be cleared",
        ));
    }
    let path = operator_recovery_latch_path(database)?;
    std::fs::remove_file(&path)?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| invalid_data("session recovery latch has no parent"))?,
    )?
    .sync_all()
}

type ConsensusWatcher = tokio::sync::mpsc::Sender<Result<ReplicationEntry, StoreError>>;
type ConsensusAppliedMembership = (
    Option<LogId<SessionConsensusNodeId>>,
    StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
);

const CONSENSUS_SCHEMA: &str = r#"
CREATE TABLE consensus_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    cluster_id BLOB NOT NULL CHECK (length(cluster_id) = 32),
    configuration_id BLOB NOT NULL CHECK (length(configuration_id) = 32),
    configuration_epoch INTEGER NOT NULL UNIQUE CHECK (configuration_epoch > 0)
);

CREATE TABLE consensus_vote (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    node_id INTEGER CHECK (node_id > 0),
    vote_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_committed (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    log_index INTEGER NOT NULL CHECK (log_index >= 0),
    log_id_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_purged (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    log_index INTEGER NOT NULL CHECK (log_index >= 0),
    log_id_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_log (
    log_index INTEGER PRIMARY KEY CHECK (log_index >= 0),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    entry_json BLOB NOT NULL CHECK (length(entry_json) > 0),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_applied (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    term INTEGER NOT NULL CHECK (term >= 0),
    log_index INTEGER NOT NULL CHECK (log_index >= 0),
    log_id_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_membership (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    membership_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_machine (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    application_sequence INTEGER NOT NULL CHECK (application_sequence >= 0),
    last_digest BLOB NOT NULL CHECK (length(last_digest) = 32),
    logical_time TEXT,
    watch_sequence INTEGER NOT NULL CHECK (watch_sequence >= 0),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_request_outcomes (
    request_id BLOB PRIMARY KEY CHECK (length(request_id) = 16),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    response_json BLOB NOT NULL,
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_snapshot (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    meta_json BLOB NOT NULL,
    file_name TEXT NOT NULL CHECK (length(file_name) > 0),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);

CREATE TABLE consensus_operator_recovery (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    last_plan_digest BLOB NOT NULL CHECK (length(last_plan_digest) = 32),
    pending_epoch INTEGER CHECK (pending_epoch > recovery_epoch),
    pending_plan_digest BLOB CHECK (
        pending_plan_digest IS NULL OR length(pending_plan_digest) = 32
    ),
    watch_cursor_invalidation_floor INTEGER NOT NULL CHECK (watch_cursor_invalidation_floor >= 0),
    CHECK (
        (pending_epoch IS NULL AND pending_plan_digest IS NULL)
        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL)
    ),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);
"#;

/// Shared persistence resources used by the log store, state machine, and
/// snapshot builder. One async mutex serializes every vote/log/state write.
#[derive(Clone)]
pub(crate) struct SqliteConsensusCore {
    pub(crate) conn: Arc<tokio::sync::Mutex<Connection>>,
    pub(crate) identity: SessionConsensusIdentity,
    pub(crate) expected_members: Arc<BTreeSet<SessionConsensusNodeId>>,
    pub(crate) snapshot_dir: Arc<PathBuf>,
    pub(crate) caps: BackendCapabilities,
    pub(crate) snapshot_gate: Arc<tokio::sync::Mutex<()>>,
    pub(crate) applied_progress: tokio::sync::watch::Sender<Option<LogId<SessionConsensusNodeId>>>,
    pub(crate) watchers: Arc<tokio::sync::Mutex<Vec<ConsensusWatcher>>>,
}

impl SqliteConsensusCore {
    pub(crate) async fn initialize(
        backend: &SqliteSessionBackend,
        snapshot_dir: PathBuf,
        identity: SessionConsensusIdentity,
        expected_members: BTreeSet<SessionConsensusNodeId>,
    ) -> Result<Self, SessionConsensusStorageError> {
        validate_expected_members(&expected_members)
            .map_err(|_| SessionConsensusStorageError::InvalidIdentity)?;
        tokio::fs::create_dir_all(&snapshot_dir)
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        let canonical_snapshot_dir = tokio::fs::canonicalize(&snapshot_dir)
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;

        let applied = {
            let conn = backend.conn.lock().await;
            initialize_schema(&conn, identity, &expected_members)?;
            read_applied_sync(&conn, identity)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?
        };
        let (applied_progress, _) = tokio::sync::watch::channel(applied);

        Ok(Self {
            conn: Arc::clone(&backend.conn),
            identity,
            expected_members: Arc::new(expected_members),
            snapshot_dir: Arc::new(canonical_snapshot_dir),
            caps: backend.caps,
            snapshot_gate: Arc::new(tokio::sync::Mutex::new(())),
            applied_progress,
            watchers: Arc::clone(&backend.watchers),
        })
    }
}

fn initialize_schema(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> Result<(), SessionConsensusStorageError> {
    // The immediate transaction is the durable authority hand-off fence. A
    // standalone operation on another SQLite connection either finishes
    // before this claim (and is included in the legacy-state check) or starts
    // after the consensus identity commits and fails closed.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let identity_table_exists = table_exists(&tx, "consensus_identity")
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;

    if !identity_table_exists {
        if legacy_authority_is_nonempty(&tx)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        {
            return Err(SessionConsensusStorageError::RecoveryRequired);
        }
        tx.execute_batch(CONSENSUS_SCHEMA)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        let epoch = checked_positive_i64(identity.configuration_epoch().get())
            .map_err(|_| SessionConsensusStorageError::InvalidIdentity)?;
        tx.execute(
            "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
                identity.cluster_id().as_bytes().as_slice(),
                identity.configuration_id().as_bytes().as_slice(),
                epoch,
            ],
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        tx.execute(
            "INSERT INTO consensus_membership (singleton, configuration_epoch, membership_json) VALUES (1, ?1, ?2)",
            params![epoch, encode_json(&StoredMembership::<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>::default()).map_err(|_| SessionConsensusStorageError::BackendUnavailable)?],
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        tx.execute(
            "INSERT INTO consensus_machine (singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence) VALUES (1, ?1, 0, ?2, NULL, 0)",
            params![epoch, SessionConsensusEntryDigest::GENESIS.as_bytes().as_slice()],
        )
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    }

    ensure_operator_recovery_schema_sync(&tx, identity)
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    if identity_table_exists {
        validate_existing_schema(&tx, identity, expected_members)?;
    }

    validate_persisted_membership_sync(&tx, identity, expected_members)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;

    tx.commit()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)
}

fn table_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
    )
}

fn legacy_authority_is_nonempty(conn: &Connection) -> rusqlite::Result<bool> {
    for table in [
        "session_records",
        "leases",
        "key_fences",
        "session_replication_log",
    ] {
        if table_exists(conn, table)? {
            let sql = format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)");
            if conn.query_row(&sql, [], |row| row.get::<_, bool>(0))? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn validate_existing_schema(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> Result<(), SessionConsensusStorageError> {
    for table in [
        "consensus_identity",
        "consensus_vote",
        "consensus_committed",
        "consensus_purged",
        "consensus_log",
        "consensus_applied",
        "consensus_membership",
        "consensus_machine",
        "consensus_request_outcomes",
        "consensus_snapshot",
        "consensus_operator_recovery",
    ] {
        if !table_exists(conn, table)
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        {
            return Err(SessionConsensusStorageError::CorruptState);
        }
    }

    let row = conn
        .query_row(
            "SELECT schema_version, cluster_id, configuration_id, configuration_epoch FROM consensus_identity WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        .ok_or(SessionConsensusStorageError::CorruptState)?;

    let (schema, cluster, config, epoch) = row;
    if schema != i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) {
        return Err(SessionConsensusStorageError::SchemaVersionMismatch);
    }
    let stored_epoch =
        checked_positive_u64(epoch).map_err(|_| SessionConsensusStorageError::CorruptState)?;
    if cluster.as_slice() != identity.cluster_id().as_bytes()
        || config.as_slice() != identity.configuration_id().as_bytes()
        || stored_epoch != identity.configuration_epoch().get()
    {
        return Err(SessionConsensusStorageError::IdentityMismatch);
    }

    let machine_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM consensus_machine", [], |row| {
            row.get(0)
        })
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let membership_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM consensus_membership", [], |row| {
            row.get(0)
        })
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    if machine_rows != 1 || membership_rows != 1 {
        return Err(SessionConsensusStorageError::CorruptState);
    }
    validate_persisted_membership_sync(conn, identity, expected_members)
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    Ok(())
}

const OPERATOR_RECOVERY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS consensus_operator_recovery (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    last_plan_digest BLOB NOT NULL CHECK (length(last_plan_digest) = 32),
    pending_epoch INTEGER CHECK (pending_epoch > recovery_epoch),
    pending_plan_digest BLOB CHECK (
        pending_plan_digest IS NULL OR length(pending_plan_digest) = 32
    ),
    watch_cursor_invalidation_floor INTEGER NOT NULL DEFAULT 0 CHECK (watch_cursor_invalidation_floor >= 0),
    CHECK (
        (pending_epoch IS NULL AND pending_plan_digest IS NULL)
        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL)
    ),
    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch)
);
"#;

pub(crate) fn ensure_operator_recovery_schema_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    conn.execute_batch(OPERATOR_RECOVERY_SCHEMA)
        .map_err(db_error)?;
    let has_cursor_floor: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_operator_recovery') WHERE name = 'watch_cursor_invalidation_floor')",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if !has_cursor_floor {
        conn.execute_batch(
            "ALTER TABLE consensus_operator_recovery ADD COLUMN watch_cursor_invalidation_floor INTEGER NOT NULL DEFAULT 0 CHECK (watch_cursor_invalidation_floor >= 0);",
        )
        .map_err(db_error)?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO consensus_operator_recovery (singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor) VALUES (1, ?1, 0, ?2, NULL, NULL, 0)",
        params![epoch_i64(identity)?, [0_u8; 32].as_slice()],
    )
    .map_err(db_error)?;
    let (stored_epoch, rows): (i64, i64) = conn
        .query_row(
            "SELECT configuration_epoch, (SELECT COUNT(*) FROM consensus_operator_recovery) FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db_error)?;
    validate_epoch(stored_epoch, identity)?;
    if rows != 1 {
        return Err(invalid_data(
            "session consensus operator recovery state is invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OperatorRecoveryState {
    pub(crate) recovery_epoch: u64,
    pub(crate) last_plan_digest: [u8; 32],
    pub(crate) pending_epoch: Option<u64>,
    pub(crate) pending_plan_digest: Option<[u8; 32]>,
    pub(crate) watch_cursor_invalidation_floor: u64,
}

type StoredOperatorRecoveryRow = (i64, i64, Vec<u8>, Option<i64>, Option<Vec<u8>>, i64);

pub(crate) fn read_operator_recovery_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<OperatorRecoveryState> {
    if !table_exists(conn, "consensus_operator_recovery").map_err(db_error)? {
        return Ok(OperatorRecoveryState {
            recovery_epoch: 0,
            last_plan_digest: [0; 32],
            pending_epoch: None,
            pending_plan_digest: None,
            watch_cursor_invalidation_floor: 0,
        });
    }
    let row: StoredOperatorRecoveryRow = if operator_recovery_cursor_column_exists(conn)? {
        conn.query_row(
            "SELECT configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .map_err(db_error)?
    } else {
        let legacy: (i64, i64, Vec<u8>, Option<i64>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest FROM consensus_operator_recovery WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .map_err(db_error)?;
        (legacy.0, legacy.1, legacy.2, legacy.3, legacy.4, 0)
    };
    let (stored_epoch, recovery_epoch, last_digest, pending_epoch, pending_digest, cursor_floor) =
        row;
    validate_epoch(stored_epoch, identity)?;
    let recovery_epoch = checked_u64(recovery_epoch)?;
    let last_plan_digest = last_digest
        .try_into()
        .map_err(|_| invalid_data("session consensus recovery plan digest has invalid length"))?;
    let pending_epoch = pending_epoch.map(checked_positive_u64).transpose()?;
    let pending_plan_digest = pending_digest
        .map(|value| {
            value.try_into().map_err(|_| {
                invalid_data("session consensus pending recovery digest has invalid length")
            })
        })
        .transpose()?;
    if pending_epoch.is_some() != pending_plan_digest.is_some()
        || pending_epoch.is_some_and(|pending| pending <= recovery_epoch)
    {
        return Err(invalid_data(
            "session consensus pending recovery state is invalid",
        ));
    }
    Ok(OperatorRecoveryState {
        recovery_epoch,
        last_plan_digest,
        pending_epoch,
        pending_plan_digest,
        watch_cursor_invalidation_floor: checked_u64(cursor_floor)?,
    })
}

pub(crate) fn read_watch_cursor_invalidation_floor_sync(conn: &Connection) -> io::Result<u64> {
    if !table_exists(conn, "consensus_operator_recovery").map_err(db_error)?
        || !operator_recovery_cursor_column_exists(conn)?
    {
        return Ok(0);
    }
    let floor: i64 = conn
        .query_row(
            "SELECT watch_cursor_invalidation_floor FROM consensus_operator_recovery WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    checked_u64(floor)
}

fn operator_recovery_cursor_column_exists(conn: &Connection) -> io::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_operator_recovery') WHERE name = 'watch_cursor_invalidation_floor')",
        [],
        |row| row.get(0),
    )
    .map_err(db_error)
}

pub(crate) fn mark_operator_recovery_pending_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    pending_epoch: u64,
    plan_digest: [u8; 32],
) -> io::Result<()> {
    ensure_operator_recovery_schema_sync(conn, identity)?;
    let current = read_operator_recovery_sync(conn, identity)?;
    match (current.pending_epoch, current.pending_plan_digest) {
        (Some(epoch), Some(digest)) if epoch == pending_epoch && digest == plan_digest => {
            return Ok(());
        }
        (Some(_), Some(_)) => {
            return Err(invalid_data(
                "a different session operator recovery workflow is already pending",
            ));
        }
        (None, None) => {}
        _ => {
            return Err(invalid_data(
                "session operator recovery pending state is incomplete",
            ));
        }
    }
    if pending_epoch <= current.recovery_epoch {
        return Err(invalid_data(
            "session consensus pending recovery epoch did not advance",
        ));
    }
    conn.execute(
        "UPDATE consensus_operator_recovery SET pending_epoch = ?1, pending_plan_digest = ?2 WHERE singleton = 1 AND configuration_epoch = ?3",
        params![
            checked_positive_i64(pending_epoch)?,
            plan_digest.as_slice(),
            epoch_i64(identity)?,
        ],
    )
    .map_err(db_error)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorRecoveryApply {
    Applied,
    Idempotent,
    Rejected,
}

pub(crate) fn finalize_operator_recovery_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    recovery_epoch: u64,
    plan_digest: [u8; 32],
    fence_high_water: u64,
    credential_high_water: u64,
) -> io::Result<OperatorRecoveryApply> {
    ensure_operator_recovery_schema_sync(conn, identity)?;
    let current = read_operator_recovery_sync(conn, identity)?;
    if let (Some(pending_epoch), Some(pending_digest)) =
        (current.pending_epoch, current.pending_plan_digest)
    {
        if pending_epoch != recovery_epoch || pending_digest != plan_digest {
            return Ok(OperatorRecoveryApply::Rejected);
        }
    }
    if current.recovery_epoch == recovery_epoch {
        return Ok(if current.last_plan_digest == plan_digest {
            OperatorRecoveryApply::Idempotent
        } else {
            OperatorRecoveryApply::Rejected
        });
    }
    if recovery_epoch <= current.recovery_epoch {
        return Ok(OperatorRecoveryApply::Rejected);
    }

    let observed_fence = observed_fence_high_water_sync(conn)?;
    let observed_credential = observed_credential_high_water_sync(conn)?;
    if fence_high_water < observed_fence || credential_high_water < observed_credential {
        return Ok(OperatorRecoveryApply::Rejected);
    }
    let next_fence = fence_high_water
        .checked_add(1)
        .ok_or_else(|| invalid_data("session recovery fence high-water exhausted"))?;
    let next_credential = credential_high_water
        .checked_add(1)
        .ok_or_else(|| invalid_data("session recovery credential high-water exhausted"))?;

    conn.execute("UPDATE leases SET active = 0", [])
        .map_err(db_error)?;
    conn.execute(
        "UPDATE lease_globals SET val = ?1 WHERE key = 'next_fence'",
        [checked_positive_i64(next_fence)?],
    )
    .map_err(db_error)?;
    conn.execute(
        "UPDATE lease_globals SET val = ?1 WHERE key = 'next_credential_id'",
        [checked_positive_i64(next_credential)?],
    )
    .map_err(db_error)?;
    let changed = conn
        .execute(
            "UPDATE consensus_operator_recovery SET recovery_epoch = ?1, last_plan_digest = ?2, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1 AND configuration_epoch = ?3",
            params![
                checked_positive_i64(recovery_epoch)?,
                plan_digest.as_slice(),
                epoch_i64(identity)?,
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data(
            "session consensus recovery state was not updated",
        ));
    }
    Ok(OperatorRecoveryApply::Applied)
}

pub(crate) fn observed_fence_high_water_sync(conn: &Connection) -> io::Result<u64> {
    let mut high = 0_u64;
    for sql in [
        "SELECT MAX(fence) FROM session_records",
        "SELECT MAX(fence) FROM leases",
        "SELECT MAX(fence) FROM key_fences",
    ] {
        let value: Option<i64> = conn
            .query_row(sql, [], |row| row.get(0))
            .map_err(db_error)?;
        if let Some(value) = value {
            high = high.max(checked_u64(value)?);
        }
    }
    let next: i64 = conn
        .query_row(
            "SELECT val FROM lease_globals WHERE key = 'next_fence'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let next = checked_positive_u64(next)?;
    Ok(high.max(next.saturating_sub(1)))
}

pub(crate) fn observed_credential_high_water_sync(conn: &Connection) -> io::Result<u64> {
    let mut high = conn
        .query_row("SELECT MAX(credential_id) FROM leases", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .map_err(db_error)?
        .map(checked_u64)
        .transpose()?
        .unwrap_or(0);
    let next: i64 = conn
        .query_row(
            "SELECT val FROM lease_globals WHERE key = 'next_credential_id'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let next = checked_positive_u64(next)?;
    high = high.max(next.saturating_sub(1));
    Ok(high)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn claim_legacy_checkpoint_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    checkpoint_digest: [u8; 32],
    pending_recovery_epoch: u64,
    plan_digest: [u8; 32],
    application_sequence_high_water: u64,
    watch_cursor_invalidation_floor: u64,
) -> io::Result<()> {
    validate_expected_members(expected_members)?;
    if table_exists(conn, "consensus_identity").map_err(db_error)? {
        return Err(invalid_data(
            "session recovery checkpoint is already consensus-owned",
        ));
    }
    validate_sealed_state_sync(conn)?;
    let logical_time: Option<String> = conn
        .query_row(
            "SELECT timestamp FROM session_replication_log ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    if let Some(value) = &logical_time {
        Timestamp::from_str(value)
            .map_err(|_| invalid_data("legacy checkpoint logical time is invalid"))?;
    }

    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    tx.execute_batch(CONSENSUS_SCHEMA).map_err(db_error)?;
    let epoch = epoch_i64(identity)?;
    tx.execute(
        "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
            identity.cluster_id().as_bytes().as_slice(),
            identity.configuration_id().as_bytes().as_slice(),
            epoch,
        ],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO consensus_membership (singleton, configuration_epoch, membership_json) VALUES (1, ?1, ?2)",
        params![
            epoch,
            encode_json(&StoredMembership::<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>::default())?,
        ],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO consensus_machine (singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            epoch,
            checked_i64(application_sequence_high_water)?,
            checkpoint_digest.as_slice(),
            logical_time,
            checked_i64(watch_cursor_invalidation_floor)?,
        ],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO consensus_operator_recovery (singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor) VALUES (1, ?1, 0, ?2, ?3, ?4, ?5)",
        params![
            epoch,
            [0_u8; 32].as_slice(),
            checked_positive_i64(pending_recovery_epoch)?,
            plan_digest.as_slice(),
            checked_i64(watch_cursor_invalidation_floor)?,
        ],
    )
    .map_err(db_error)?;
    tx.execute("DELETE FROM session_replication_log", [])
        .map_err(db_error)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn checked_i64(value: u64) -> io::Result<i64> {
    i64::try_from(value).map_err(|_| invalid_data("session consensus integer exceeds SQLite range"))
}

pub(crate) fn checked_positive_i64(value: u64) -> io::Result<i64> {
    if value == 0 {
        return Err(invalid_data("session consensus integer must be positive"));
    }
    checked_i64(value)
}

pub(crate) fn checked_u64(value: i64) -> io::Result<u64> {
    u64::try_from(value).map_err(|_| invalid_data("negative session consensus integer"))
}

pub(crate) fn checked_positive_u64(value: i64) -> io::Result<u64> {
    let value = checked_u64(value)?;
    if value == 0 {
        return Err(invalid_data("session consensus integer must be positive"));
    }
    Ok(value)
}

pub(crate) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn db_error(_: rusqlite::Error) -> io::Error {
    io::Error::other("session consensus SQLite operation failed")
}

fn encode_json<T: serde::Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid_data("session consensus encoding failed"))
}

fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(|_| invalid_data("session consensus decoding failed"))
}

fn epoch_i64(identity: SessionConsensusIdentity) -> io::Result<i64> {
    checked_positive_i64(identity.configuration_epoch().get())
}

fn validate_epoch(stored: i64, identity: SessionConsensusIdentity) -> io::Result<()> {
    if checked_positive_u64(stored)? != identity.configuration_epoch().get() {
        return Err(invalid_data(
            "session consensus configuration epoch mismatch",
        ));
    }
    Ok(())
}

fn validate_log_id(log_id: &LogId<SessionConsensusNodeId>) -> io::Result<(i64, i64)> {
    let term = checked_i64(log_id.leader_id.term)?;
    let index = checked_i64(log_id.index)?;
    Ok((term, index))
}

pub(crate) fn validate_command_for_log(
    command: &SessionConsensusCommand,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    if command.schema_version != SESSION_CONSENSUS_SCHEMA_VERSION {
        return Err(invalid_data("unsupported session consensus command schema"));
    }
    if command.identity != identity {
        return Err(invalid_data("session consensus command identity mismatch"));
    }
    if let SessionMutationIntent::FinalizeOperatorRecovery {
        recovery_epoch,
        plan_digest,
        fence_high_water,
        credential_high_water,
    } = &command.intent
    {
        if *recovery_epoch == 0
            || plan_digest.iter().all(|byte| *byte == 0)
            || *fence_high_water == u64::MAX
            || *credential_high_water == u64::MAX
        {
            return Err(invalid_data(
                "session consensus operator recovery command is invalid",
            ));
        }
    }
    if let SessionMutationIntent::CompareAndSet(op) = &command.intent {
        if op.new_record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
            return Err(invalid_data(
                "session consensus requires a sealed record payload",
            ));
        }
        op.new_record
            .payload
            .validate_envelope_for_record(&op.new_record)
            .map_err(|_| invalid_data("session consensus record envelope is invalid"))?;
    }
    Ok(())
}

fn validate_entry_for_fixed_membership(
    entry: &Entry<SessionRaftTypeConfig>,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    match &entry.payload {
        EntryPayload::Normal(command) => validate_command_for_log(command, identity),
        EntryPayload::Membership(membership) => validate_fixed_membership(
            &StoredMembership::new(Some(entry.log_id), membership.clone()),
            expected_members,
        ),
        EntryPayload::Blank => Ok(()),
    }
}

pub(crate) fn read_vote_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<Vote<SessionConsensusNodeId>>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, term, node_id, vote_json FROM consensus_vote WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, Vec<u8>>(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, term, node_id, encoded)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    let vote: Vote<SessionConsensusNodeId> = decode_json(&encoded)?;
    if checked_u64(term)? != vote.leader_id.term {
        return Err(invalid_data(
            "persisted session consensus vote term mismatch",
        ));
    }
    match (node_id, vote.leader_id.voted_for()) {
        (Some(stored), Some(voted_for)) if checked_positive_u64(stored)? == voted_for.get() => {}
        (None, None) => {}
        _ => {
            return Err(invalid_data(
                "persisted session consensus vote node mismatch",
            ))
        }
    }
    Ok(Some(vote))
}

pub(crate) fn save_vote_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    vote: &Vote<SessionConsensusNodeId>,
) -> io::Result<()> {
    if let Some(current) = read_vote_sync(conn, identity)? {
        if vote.partial_cmp(&current) != Some(std::cmp::Ordering::Greater) && vote != &current {
            return Err(invalid_data("session consensus vote did not advance"));
        }
    }
    let epoch = epoch_i64(identity)?;
    let term = checked_i64(vote.leader_id.term)?;
    let node_id = vote
        .leader_id
        .voted_for()
        .map(|node| checked_positive_i64(node.get()))
        .transpose()?;
    let encoded = encode_json(vote)?;
    conn.execute(
        "INSERT OR REPLACE INTO consensus_vote (singleton, configuration_epoch, term, node_id, vote_json) VALUES (1, ?1, ?2, ?3, ?4)",
        params![epoch, term, node_id, encoded],
    )
    .map_err(db_error)?;
    Ok(())
}

fn read_log_pointer(
    conn: &Connection,
    table: &'static str,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
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
    let log_id: LogId<SessionConsensusNodeId> = decode_json(&encoded)?;
    if checked_u64(term)? != log_id.leader_id.term || checked_u64(index)? != log_id.index {
        return Err(invalid_data(
            "persisted session consensus log pointer mismatch",
        ));
    }
    Ok(Some(log_id))
}

fn save_log_pointer(
    tx: &Transaction<'_>,
    table: &'static str,
    identity: SessionConsensusIdentity,
    log_id: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let (term, index) = validate_log_id(log_id)?;
    let sql = format!(
        "INSERT OR REPLACE INTO {table} (singleton, configuration_epoch, term, log_index, log_id_json) VALUES (1, ?1, ?2, ?3, ?4)"
    );
    tx.execute(
        &sql,
        params![epoch_i64(identity)?, term, index, encode_json(log_id)?],
    )
    .map_err(db_error)?;
    Ok(())
}

pub(crate) fn read_committed_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    read_log_pointer(conn, "consensus_committed", identity)
}

pub(crate) fn save_committed_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    committed: Option<LogId<SessionConsensusNodeId>>,
) -> io::Result<()> {
    let Some(committed) = committed else {
        if read_committed_sync(conn, identity)?.is_some() {
            return Err(invalid_data(
                "session consensus committed index cannot be cleared",
            ));
        }
        return Ok(());
    };
    if let Some(current) = read_committed_sync(conn, identity)? {
        if committed.index < current.index
            || (committed.index == current.index && committed != current)
        {
            return Err(invalid_data("session consensus committed index regressed"));
        }
    }
    let tx = conn.unchecked_transaction().map_err(db_error)?;
    save_log_pointer(&tx, "consensus_committed", identity, &committed)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn read_purged_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    read_log_pointer(conn, "consensus_purged", identity)
}

pub(crate) fn last_log_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log ORDER BY log_index DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, term, index, encoded)) = row else {
        return read_purged_sync(conn, identity);
    };
    validate_epoch(epoch, identity)?;
    let entry: Entry<SessionRaftTypeConfig> = decode_json(&encoded)?;
    if checked_u64(term)? != entry.log_id.leader_id.term
        || checked_u64(index)? != entry.log_id.index
    {
        return Err(invalid_data("persisted session consensus log row mismatch"));
    }
    Ok(Some(entry.log_id))
}

pub(crate) fn read_log_range_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    start: u64,
    end: Option<u64>,
    limit: Option<usize>,
) -> io::Result<Vec<Entry<SessionRaftTypeConfig>>> {
    let start = checked_i64(start)?;
    let end = end.map(checked_i64).transpose()?;
    let limit = limit
        .map(|value| {
            i64::try_from(value)
                .map_err(|_| invalid_data("session consensus log limit exceeds SQLite range"))
        })
        .transpose()?;
    let mut entries = Vec::new();
    let sql = match (end, limit) {
        (Some(_), Some(_)) => "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index ASC LIMIT ?3",
        (Some(_), None) => "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index ASC",
        (None, Some(_)) => "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 ORDER BY log_index ASC LIMIT ?3",
        (None, None) => "SELECT configuration_epoch, term, log_index, entry_json FROM consensus_log WHERE log_index >= ?1 ORDER BY log_index ASC",
    };
    let mut stmt = conn.prepare(sql).map_err(db_error)?;
    let mut rows = match (end, limit) {
        (Some(end), Some(limit)) => stmt.query(params![start, end, limit]),
        (Some(end), None) => stmt.query(params![start, end]),
        (None, Some(limit)) => stmt.query(params![start, limit]),
        (None, None) => stmt.query(params![start]),
    }
    .map_err(db_error)?;
    while let Some(row) = rows.next().map_err(db_error)? {
        let epoch: i64 = row.get(0).map_err(db_error)?;
        let term: i64 = row.get(1).map_err(db_error)?;
        let index: i64 = row.get(2).map_err(db_error)?;
        let encoded: Vec<u8> = row.get(3).map_err(db_error)?;
        validate_epoch(epoch, identity)?;
        let entry: Entry<SessionRaftTypeConfig> = decode_json(&encoded)?;
        if checked_u64(term)? != entry.log_id.leader_id.term
            || checked_u64(index)? != entry.log_id.index
        {
            return Err(invalid_data("persisted session consensus log row mismatch"));
        }
        validate_entry_for_fixed_membership(&entry, identity, expected_members)?;
        entries.push(entry);
    }
    for pair in entries.windows(2) {
        if pair[1].log_id.index != pair[0].log_id.index.saturating_add(1) {
            return Err(invalid_data(
                "persisted session consensus log contains a hole",
            ));
        }
    }
    Ok(entries)
}

pub(crate) fn append_logs_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let expected = last_log_sync(conn, identity)?
        .map(|log| {
            log.index
                .checked_add(1)
                .ok_or_else(|| invalid_data("session consensus log index exhausted"))
        })
        .transpose()?
        .unwrap_or(0);
    if entries[0].log_id.index != expected {
        return Err(invalid_data(
            "session consensus log append would create a hole",
        ));
    }
    for (offset, entry) in entries.iter().enumerate() {
        let offset = u64::try_from(offset)
            .map_err(|_| invalid_data("session consensus log batch exceeds integer range"))?;
        if entry.log_id.index
            != expected
                .checked_add(offset)
                .ok_or_else(|| invalid_data("session consensus log index exhausted"))?
        {
            return Err(invalid_data(
                "session consensus log batch is not contiguous",
            ));
        }
        validate_entry_for_fixed_membership(entry, identity, expected_members)?;
    }

    let tx = conn.unchecked_transaction().map_err(db_error)?;
    for entry in entries {
        let (term, index) = validate_log_id(&entry.log_id)?;
        let encoded = encode_json(entry)?;
        if encoded.len() > CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(invalid_data(
                "session consensus log entry exceeds storage limit",
            ));
        }
        tx.execute(
            "INSERT INTO consensus_log (log_index, configuration_epoch, term, entry_json) VALUES (?1, ?2, ?3, ?4)",
            params![index, epoch_i64(identity)?, term, encoded],
        )
        .map_err(db_error)?;
    }
    tx.commit().map_err(db_error)
}

pub(crate) fn truncate_logs_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    since: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let (_, index) = validate_log_id(since)?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    if let Some(committed) = read_committed_sync(&tx, identity)? {
        if since.index <= committed.index {
            return Err(invalid_data(
                "session consensus truncate crosses committed log",
            ));
        }
    }
    if let Some(applied) = read_applied_sync(&tx, identity)? {
        if since.index <= applied.index {
            return Err(invalid_data(
                "session consensus truncate crosses applied log",
            ));
        }
    }
    if let Some(purged) = read_purged_sync(&tx, identity)? {
        if since.index <= purged.index {
            return Err(invalid_data(
                "session consensus truncate crosses purged log",
            ));
        }
    }
    tx.execute("DELETE FROM consensus_log WHERE log_index >= ?1", [index])
        .map_err(db_error)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn purge_logs_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    through: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let (_, index) = validate_log_id(through)?;
    if let Some(current) = read_purged_sync(conn, identity)? {
        if through.index < current.index || (through.index == current.index && through != &current)
        {
            return Err(invalid_data("session consensus purged index regressed"));
        }
    }
    let applied = read_applied_sync(conn, identity)?
        .ok_or_else(|| invalid_data("session consensus cannot purge unapplied logs"))?;
    if through.index > applied.index {
        return Err(invalid_data(
            "session consensus cannot purge unapplied logs",
        ));
    }
    let tx = conn.unchecked_transaction().map_err(db_error)?;
    tx.execute("DELETE FROM consensus_log WHERE log_index <= ?1", [index])
        .map_err(db_error)?;
    save_log_pointer(&tx, "consensus_purged", identity, through)?;
    tx.commit().map_err(db_error)
}

pub(crate) fn read_applied_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    read_log_pointer(conn, "consensus_applied", identity)
}

fn validate_expected_members(
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    if expected_members.is_empty() {
        return Err(invalid_data(
            "session consensus expected membership must not be empty",
        ));
    }
    Ok(())
}

fn is_pristine_membership(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> bool {
    membership.log_id().is_none()
        && membership.membership().get_joint_config().is_empty()
        && membership.nodes().next().is_none()
}

fn validate_fixed_membership(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    validate_expected_members(expected_members)?;
    let config = membership.membership().get_joint_config();
    let nodes = membership
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    if config.len() != 1
        || config.first() != Some(expected_members)
        || nodes != *expected_members
        || membership.membership().learner_ids().next().is_some()
    {
        return Err(invalid_data(
            "session consensus membership does not match admitted topology",
        ));
    }
    Ok(())
}

fn validate_persisted_membership_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    let applied = read_applied_sync(conn, identity)?;
    let membership = read_membership_unchecked_sync(conn, identity)?;
    if is_pristine_membership(&membership) {
        if applied.is_none() {
            return Ok(());
        }
        return Err(invalid_data(
            "session consensus applied state has pristine membership",
        ));
    }
    validate_fixed_membership(&membership, expected_members)
}

fn read_membership_unchecked_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>> {
    let (epoch, encoded): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT configuration_epoch, membership_json FROM consensus_membership WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    decode_json(&encoded)
}

pub(crate) fn read_membership_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>> {
    let membership = read_membership_unchecked_sync(conn, identity)?;
    if is_pristine_membership(&membership) && read_applied_sync(conn, identity)?.is_none() {
        return Ok(membership);
    }
    validate_fixed_membership(&membership, expected_members)?;
    Ok(membership)
}

fn payload_digest(command: &SessionConsensusCommand) -> io::Result<[u8; 32]> {
    // Idempotency binds caller-owned semantics, not leader-owned sequence,
    // predecessor, or logical-time metadata. A retry after a committed
    // response is lost will be proposed by a new leader with new metadata but
    // must still recover the original durable outcome.
    let encoded = encode_json(&(command.schema_version, command.identity, &command.intent))?;
    let mut hasher = Sha256::new();
    hasher.update(OUTCOME_DIGEST_DOMAIN);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn request_id_hex(request_id: SessionConsensusRequestId) -> String {
    crate::hex::encode_lower(request_id.as_bytes())
}

fn lease_error_to_store(error: LeaseError) -> StoreError {
    match error {
        LeaseError::AlreadyHeld => StoreError::LeaseHeld,
        LeaseError::Expired => StoreError::LeaseExpired,
        LeaseError::StaleFence => StoreError::StaleFence,
        LeaseError::NotFound => StoreError::NotFound,
        LeaseError::InvalidSessionTtl => StoreError::InvalidSessionTtl,
        LeaseError::Backend(_) => {
            StoreError::BackendUnavailable("session consensus lease application failed".into())
        }
    }
}

/// Whether a state-machine rejection is a deterministic result of the
/// committed command and previously committed state.
///
/// Backend capability, persistence, serialization, crypto, and restore/log
/// errors describe a node-local fault or corrupt/incompatible state rather than
/// a caller-visible command outcome. Persisting one of those errors would let a
/// faulty replica advance its applied/application state while healthy replicas
/// apply the mutation, permanently diverging the deterministic state machine.
fn is_deterministic_intent_rejection(error: &StoreError) -> bool {
    match error {
        StoreError::NotFound
        | StoreError::StaleFence
        | StoreError::CasConflict
        | StoreError::InvalidKey(_)
        | StoreError::InvalidSessionTtl
        | StoreError::LeaseHeld
        | StoreError::LeaseExpired
        | StoreError::PayloadTooLarge { .. } => true,
        StoreError::CapabilityNotSupported(_)
        | StoreError::BackendUnavailable(_)
        | StoreError::InvalidReplicationSequence
        | StoreError::ReplicationOperationLimitExceeded
        | StoreError::Crypto(_)
        | StoreError::Serialization(_)
        | StoreError::InvalidRestoreScanRequest(_)
        | StoreError::InvalidRestoreScanResponse(_)
        | StoreError::RestoreScanPageTooLarge { .. }
        | StoreError::RestoreScanCursorStale
        | StoreError::RestoreScanWorkBudgetExceeded
        | StoreError::RestoreScanResponseTooLarge { .. } => false,
    }
}

fn state_machine_intent_fault() -> io::Error {
    io::Error::other("session consensus state-machine operation failed")
}

#[derive(Debug)]
pub(crate) struct AppliedBatch {
    pub(crate) responses: Vec<SessionConsensusResponse>,
    pub(crate) notifications: Vec<ReplicationEntry>,
}

fn read_machine_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<(u64, SessionConsensusEntryDigest, Option<Timestamp>, u64)> {
    let (epoch, sequence, digest, logical_time, watch_sequence): (
        i64,
        i64,
        Vec<u8>,
        Option<String>,
        i64,
    ) = conn
        .query_row(
            "SELECT configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence FROM consensus_machine WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(db_error)?;
    validate_epoch(epoch, identity)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| invalid_data("persisted session consensus digest has invalid length"))?;
    let logical_time = logical_time
        .map(|value| {
            Timestamp::from_str(&value)
                .map_err(|_| invalid_data("persisted session consensus logical time is invalid"))
        })
        .transpose()?;
    Ok((
        checked_u64(sequence)?,
        SessionConsensusEntryDigest::from_bytes(digest),
        logical_time,
        checked_u64(watch_sequence)?,
    ))
}

#[cfg(test)]
pub(crate) fn proposal_state_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<(u64, SessionConsensusEntryDigest, Option<Timestamp>)> {
    let (sequence, digest, logical_time, _) = read_machine_sync(conn, identity)?;
    Ok((sequence, digest, logical_time))
}

fn read_outcome_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    request_id: SessionConsensusRequestId,
) -> io::Result<Option<([u8; 32], SessionConsensusResponse)>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, payload_digest, response_json FROM consensus_request_outcomes WHERE request_id = ?1",
            [request_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, digest, response)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    let digest = digest.try_into().map_err(|_| {
        invalid_data("persisted session consensus request digest has invalid length")
    })?;
    Ok(Some((digest, decode_json(&response)?)))
}

fn validate_membership_ids(
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> io::Result<()> {
    if let Some(log_id) = membership.log_id() {
        validate_log_id(log_id)?;
    }
    for node_id in membership.voter_ids() {
        checked_positive_i64(node_id.get())?;
    }
    for (node_id, _) in membership.nodes() {
        checked_positive_i64(node_id.get())?;
    }
    Ok(())
}

fn store_membership_sync(
    tx: &Transaction<'_>,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> io::Result<()> {
    validate_membership_ids(membership)?;
    validate_fixed_membership(membership, expected_members)?;
    tx.execute(
        "UPDATE consensus_membership SET configuration_epoch = ?1, membership_json = ?2 WHERE singleton = 1",
        params![epoch_i64(identity)?, encode_json(membership)?],
    )
    .map_err(db_error)?;
    Ok(())
}

fn execute_intent_sync(
    conn: &Connection,
    intent: &SessionMutationIntent,
    caps: &BackendCapabilities,
    logical_time: Timestamp,
) -> Result<(SessionMutationOutcome, Option<ReplicationOp>), StoreError> {
    match intent {
        SessionMutationIntent::AdvanceLogicalTime => Ok((SessionMutationOutcome::Unit, None)),
        SessionMutationIntent::CompareAndSet(op) => {
            if op.new_record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
                return Err(StoreError::Serialization(
                    "session consensus requires a sealed record payload".into(),
                ));
            }
            let result = ops::compare_and_set_sync(conn, op.as_ref().clone(), caps, logical_time)?;
            let replication = matches!(result, CompareAndSetResult::Success).then(|| {
                ReplicationOp::CompareAndSet {
                    key: op.key.clone(),
                    expected_generation: op.expected_generation,
                    credential_id: op.lease.credential_id(),
                    guard_expires_at: op.lease.expires_at(),
                    new_record: op.new_record.clone(),
                }
            });
            Ok((SessionMutationOutcome::CompareAndSet(result), replication))
        }
        SessionMutationIntent::DeleteFenced(guard) => {
            ops::delete_fenced_sync(conn, guard, caps, logical_time)?;
            Ok((
                SessionMutationOutcome::Unit,
                Some(ReplicationOp::DeleteFenced {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                }),
            ))
        }
        SessionMutationIntent::RefreshTtl { lease: guard, ttl } => {
            ops::refresh_ttl_sync(conn, guard, *ttl, caps, logical_time)?;
            let expires_at = crate::ttl::checked_session_deadline(logical_time, *ttl)?;
            Ok((
                SessionMutationOutcome::Unit,
                Some(ReplicationOp::RefreshTtl {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                    ttl: *ttl,
                    expires_at,
                }),
            ))
        }
        SessionMutationIntent::AcquireLease { key, owner, ttl } => {
            let guard = lease::acquire_sync(conn, key, owner.clone(), *ttl, logical_time)
                .map_err(lease_error_to_store)?;
            Ok((
                SessionMutationOutcome::Lease(guard.clone()),
                Some(ReplicationOp::AcquireLease {
                    key: key.clone(),
                    owner: owner.clone(),
                    fence: guard.fence(),
                    credential_id: guard.credential_id(),
                    ttl: *ttl,
                    expires_at: guard.expires_at(),
                }),
            ))
        }
        SessionMutationIntent::RenewLease { lease: guard, ttl } => {
            let renewed =
                lease::renew_sync(conn, guard, *ttl, logical_time).map_err(lease_error_to_store)?;
            Ok((
                SessionMutationOutcome::Lease(renewed.clone()),
                Some(ReplicationOp::RenewLease {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                    credential_id: guard.credential_id(),
                    ttl: *ttl,
                    expires_at: renewed.expires_at(),
                }),
            ))
        }
        SessionMutationIntent::ReleaseLease(guard) => {
            lease::release_sync(conn, guard.clone(), logical_time).map_err(lease_error_to_store)?;
            Ok((
                SessionMutationOutcome::Unit,
                Some(ReplicationOp::ReleaseLease {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                    credential_id: guard.credential_id(),
                }),
            ))
        }
        SessionMutationIntent::FinalizeOperatorRecovery {
            recovery_epoch,
            plan_digest,
            fence_high_water,
            credential_high_water,
        } => match finalize_operator_recovery_sync(
            conn,
            // The identity is validated before this function and all state
            // machine writes use the same fixed configuration epoch.
            read_identity_for_recovery_sync(conn)?,
            *recovery_epoch,
            *plan_digest,
            *fence_high_water,
            *credential_high_water,
        )
        .map_err(|_| {
            StoreError::BackendUnavailable("session consensus recovery application failed".into())
        })? {
            OperatorRecoveryApply::Applied | OperatorRecoveryApply::Idempotent => {
                Ok((SessionMutationOutcome::Unit, None))
            }
            OperatorRecoveryApply::Rejected => Err(StoreError::InvalidKey(
                "operator_recovery_epoch_rejected".into(),
            )),
        },
    }
}

fn read_identity_for_recovery_sync(
    conn: &Connection,
) -> Result<SessionConsensusIdentity, StoreError> {
    let (cluster, configuration, epoch): (Vec<u8>, Vec<u8>, i64) = conn
        .query_row(
            "SELECT cluster_id, configuration_id, configuration_epoch FROM consensus_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| StoreError::BackendUnavailable(
            "session consensus recovery identity read failed".into(),
        ))?;
    let cluster: [u8; 32] = cluster.try_into().map_err(|_| {
        StoreError::BackendUnavailable("session consensus recovery identity is invalid".into())
    })?;
    let configuration: [u8; 32] = configuration.try_into().map_err(|_| {
        StoreError::BackendUnavailable("session consensus recovery identity is invalid".into())
    })?;
    let epoch = checked_positive_u64(epoch).map_err(|_| {
        StoreError::BackendUnavailable("session consensus recovery identity is invalid".into())
    })?;
    let epoch = crate::consensus::SessionConsensusConfigurationEpoch::new(epoch).map_err(|_| {
        StoreError::BackendUnavailable("session consensus recovery identity is invalid".into())
    })?;
    Ok(SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::from_bytes(cluster),
        crate::consensus::SessionConsensusConfigurationId::from_bytes(configuration),
        epoch,
    ))
}

fn store_replication_notification_sync(
    tx: &Transaction<'_>,
    identity: SessionConsensusIdentity,
    watch_sequence: u64,
    request_id: SessionConsensusRequestId,
    op: ReplicationOp,
    logical_time: Timestamp,
) -> io::Result<ReplicationEntry> {
    let entry = ReplicationEntry {
        sequence: watch_sequence,
        tx_id: request_id_hex(request_id),
        op,
        timestamp: logical_time,
    };
    entry
        .validate()
        .map_err(|_| invalid_data("committed session replication notification is invalid"))?;
    tx.execute(
        "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![
            checked_positive_i64(entry.sequence)?,
            entry.tx_id,
            serde_json::to_string(&entry).map_err(|_| invalid_data("session replication notification encoding failed"))?,
            ops::format_rfc3339_normalized(entry.timestamp),
        ],
    )
    .map_err(db_error)?;
    let epoch = epoch_i64(identity)?;
    let changed = tx
        .execute(
            "UPDATE consensus_machine SET watch_sequence = ?1 WHERE singleton = 1 AND configuration_epoch = ?2",
            params![checked_i64(watch_sequence)?, epoch],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data("session consensus machine state is missing"));
    }
    Ok(entry)
}

pub(crate) fn apply_entries_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    caps: &BackendCapabilities,
    entries: Vec<Entry<SessionRaftTypeConfig>>,
) -> io::Result<AppliedBatch> {
    if entries.is_empty() {
        return Ok(AppliedBatch {
            responses: Vec::new(),
            notifications: Vec::new(),
        });
    }
    for entry in &entries {
        validate_entry_for_fixed_membership(entry, identity, expected_members)?;
    }
    let mut tx = conn.unchecked_transaction().map_err(db_error)?;
    let mut last_applied = read_applied_sync(&tx, identity)?;
    let mut machine = read_machine_sync(&tx, identity)?;
    let mut responses = Vec::with_capacity(entries.len());
    let mut notifications = Vec::new();

    for entry in entries {
        let expected_index = last_applied
            .as_ref()
            .map(|log_id| {
                log_id
                    .index
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("session consensus applied index exhausted"))
            })
            .transpose()?
            .unwrap_or(0);
        if entry.log_id.index != expected_index {
            return Err(invalid_data("session consensus apply is not contiguous"));
        }

        let response = match entry.payload {
            EntryPayload::Blank => SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::Unit),
                sequence: 0,
                digest: None,
                logical_time: None,
                raft_log_index: entry.log_id.index,
            },
            EntryPayload::Membership(membership) => {
                let stored = StoredMembership::new(Some(entry.log_id), membership);
                store_membership_sync(&tx, identity, expected_members, &stored)?;
                SessionConsensusResponse {
                    result: Ok(SessionMutationOutcome::Unit),
                    sequence: 0,
                    digest: None,
                    logical_time: None,
                    raft_log_index: entry.log_id.index,
                }
            }
            EntryPayload::Normal(command) => {
                validate_command_for_log(&command, identity)?;
                let digest = payload_digest(&command)?;
                if let Some((persisted_digest, persisted_response)) =
                    read_outcome_sync(&tx, identity, command.request_id)?
                {
                    if persisted_digest != digest {
                        return Err(invalid_data(
                            "session consensus request ID was reused with another payload",
                        ));
                    }
                    persisted_response
                } else {
                    let sequence = machine.0.checked_add(1).ok_or_else(|| {
                        invalid_data("session consensus application sequence exhausted")
                    })?;
                    let logical_time = machine.2.map_or(command.logical_time, |last_time| {
                        last_time.max(command.logical_time)
                    });
                    let command_digest = command
                        .calculate_applied_digest(sequence, machine.1, logical_time)
                        .map_err(|_| invalid_data("session consensus command digest failed"))?;

                    let (result, replication) = {
                        let mut savepoint = tx.savepoint().map_err(db_error)?;
                        match execute_intent_sync(&savepoint, &command.intent, caps, logical_time) {
                            Ok((outcome, replication)) => {
                                savepoint.commit().map_err(db_error)?;
                                (Ok(outcome), replication)
                            }
                            Err(error) if is_deterministic_intent_rejection(&error) => {
                                savepoint.rollback().map_err(db_error)?;
                                (Err(error), None)
                            }
                            Err(_) => {
                                savepoint.rollback().map_err(db_error)?;
                                return Err(state_machine_intent_fault());
                            }
                        }
                    };

                    let response = SessionConsensusResponse {
                        result,
                        sequence,
                        digest: Some(command_digest),
                        logical_time: Some(logical_time),
                        raft_log_index: entry.log_id.index,
                    };
                    tx.execute(
                        "INSERT INTO consensus_request_outcomes (request_id, configuration_epoch, payload_digest, response_json) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            command.request_id.as_bytes().as_slice(),
                            epoch_i64(identity)?,
                            digest.as_slice(),
                            encode_json(&response)?,
                        ],
                    )
                    .map_err(db_error)?;
                    let changed = tx
                        .execute(
                            "UPDATE consensus_machine SET application_sequence = ?1, last_digest = ?2, logical_time = ?3 WHERE singleton = 1 AND configuration_epoch = ?4",
                            params![
                                checked_positive_i64(sequence)?,
                                command_digest.as_bytes().as_slice(),
                                ops::format_rfc3339_normalized(logical_time),
                                epoch_i64(identity)?,
                            ],
                        )
                        .map_err(db_error)?;
                    if changed != 1 {
                        return Err(invalid_data("session consensus machine state is missing"));
                    }
                    machine.0 = sequence;
                    machine.1 = command_digest;
                    machine.2 = Some(logical_time);
                    if let Some(replication) = replication {
                        machine.3 = machine.3.checked_add(1).ok_or_else(|| {
                            invalid_data("session consensus watch sequence exhausted")
                        })?;
                        notifications.push(store_replication_notification_sync(
                            &tx,
                            identity,
                            machine.3,
                            command.request_id,
                            replication,
                            logical_time,
                        )?);
                    }
                    response
                }
            }
        };

        save_log_pointer(&tx, "consensus_applied", identity, &entry.log_id)?;
        last_applied = Some(entry.log_id);
        responses.push(response);
    }

    validate_persisted_membership_sync(&tx, identity, expected_members)?;
    tx.commit().map_err(db_error)?;
    Ok(AppliedBatch {
        responses,
        notifications,
    })
}

pub(crate) fn validate_sealed_state_sync(conn: &Connection) -> io::Result<()> {
    let mut record_stmt = conn
        .prepare(
            r#"
            SELECT tenant, nf_kind, key_type, stable_id, generation, owner,
                   fence, state_class, state_type, expires_at, payload, encoding
            FROM session_records
            "#,
        )
        .map_err(db_error)?;
    let records = record_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, i64>(11)?,
            ))
        })
        .map_err(db_error)?;
    for row in records {
        let (
            tenant,
            nf_kind,
            key_type,
            stable_id,
            generation,
            owner,
            fence,
            state_class,
            state_type,
            expires_at,
            payload,
            encoding,
        ) = row.map_err(db_error)?;
        let record = ops::stored_record_from_row(
            tenant,
            nf_kind,
            key_type,
            stable_id,
            generation,
            owner,
            fence,
            state_class,
            state_type,
            expires_at,
            payload,
            encoding,
        )
        .map_err(|_| invalid_data("session consensus snapshot record is invalid"))?;
        if record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
            return Err(invalid_data(
                "session consensus snapshot contains an unsealed record payload",
            ));
        }
        record
            .payload
            .validate_envelope_for_record(&record)
            .map_err(|_| invalid_data("session consensus snapshot envelope is invalid"))?;
    }

    let mut stmt = conn
        .prepare("SELECT entry_json FROM session_replication_log ORDER BY sequence ASC")
        .map_err(db_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(db_error)?;
    let mut expected = read_watch_cursor_invalidation_floor_sync(conn)?
        .checked_add(1)
        .ok_or_else(|| invalid_data("session replication sequence exhausted"))?;
    for row in rows {
        let encoded = row.map_err(db_error)?;
        let entry: ReplicationEntry = serde_json::from_str(&encoded)
            .map_err(|_| invalid_data("persisted session replication entry is invalid"))?;
        if entry.sequence != expected {
            return Err(invalid_data(
                "persisted session replication log is not contiguous",
            ));
        }
        validate_sealed_replication_op(&entry.op)?;
        expected = expected
            .checked_add(1)
            .ok_or_else(|| invalid_data("session replication sequence exhausted"))?;
    }
    let observed_head = expected
        .checked_sub(1)
        .ok_or_else(|| invalid_data("session replication sequence underflow"))?;
    if table_exists(conn, "consensus_machine").map_err(db_error)? {
        let watch_sequence: i64 = conn
            .query_row(
                "SELECT watch_sequence FROM consensus_machine WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if checked_u64(watch_sequence)? != observed_head {
            return Err(invalid_data(
                "session replication cursor does not match the persisted log",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_sealed_replication_op(root: &ReplicationOp) -> io::Result<()> {
    let mut pending = vec![root];
    let mut visited = 0_usize;
    while let Some(op) = pending.pop() {
        visited = visited
            .checked_add(1)
            .ok_or_else(|| invalid_data("session replication operation count overflow"))?;
        if visited > crate::backend::MAX_REPLICATION_OPERATIONS_PER_ENTRY {
            return Err(invalid_data("session replication operation limit exceeded"));
        }
        match op {
            ReplicationOp::CompareAndSet { new_record, .. } => {
                if new_record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
                    return Err(invalid_data(
                        "session replication log contains an unsealed record payload",
                    ));
                }
                new_record
                    .payload
                    .validate_envelope_for_record(new_record)
                    .map_err(|_| {
                        invalid_data("session replication log contains an invalid envelope")
                    })?;
            }
            ReplicationOp::Batch { ops } => pending.extend(ops),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn build_snapshot_database_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    path: &std::path::Path,
) -> io::Result<ConsensusAppliedMembership> {
    validate_sealed_state_sync(conn)?;
    let applied = read_applied_sync(conn, identity)?;
    let membership = read_membership_sync(conn, identity, expected_members)?;
    validate_fixed_membership(&membership, expected_members)?;
    validate_membership_ids(&membership)?;

    let mut destination = Connection::open(path).map_err(db_error)?;
    {
        let backup = rusqlite::backup::Backup::new(conn, &mut destination).map_err(db_error)?;
        backup
            .run_to_completion(128, std::time::Duration::ZERO, None)
            .map_err(db_error)?;
    }
    destination
        .execute_batch(
            r#"
            DELETE FROM consensus_vote;
            DELETE FROM consensus_committed;
            DELETE FROM consensus_purged;
            DELETE FROM consensus_log;
            DELETE FROM consensus_snapshot;
            PRAGMA journal_mode = DELETE;
            VACUUM;
            "#,
        )
        .map_err(db_error)?;
    ops::rotate_restore_scan_epoch_sync(&destination)
        .map_err(|_| invalid_data("built session consensus snapshot restore metadata failed"))?;
    validate_existing_schema(&destination, identity, expected_members)
        .map_err(|_| invalid_data("built session consensus snapshot failed validation"))?;
    validate_sealed_state_sync(&destination)?;
    Ok((applied, membership))
}

fn validate_snapshot_database_sync(
    path: &std::path::Path,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
) -> io::Result<()> {
    validate_fixed_membership(&meta.last_membership, expected_members)?;
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(db_error)?;
    ensure_operator_recovery_schema_sync(&conn, identity)?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(db_error)?;
    if integrity != "ok" {
        return Err(invalid_data(
            "session consensus snapshot integrity check failed",
        ));
    }
    validate_existing_schema(&conn, identity, expected_members)
        .map_err(|_| invalid_data("session consensus snapshot identity is invalid"))?;
    ops::read_restore_scan_state_sync(&conn)
        .map_err(|_| invalid_data("session consensus snapshot restore metadata is invalid"))?;
    validate_sealed_state_sync(&conn)?;
    let applied = read_applied_sync(&conn, identity)?;
    let membership = read_membership_sync(&conn, identity, expected_members)?;
    validate_fixed_membership(&membership, expected_members)?;
    if applied != meta.last_log_id || membership != meta.last_membership {
        return Err(invalid_data("session consensus snapshot metadata mismatch"));
    }
    for table in [
        "consensus_vote",
        "consensus_committed",
        "consensus_purged",
        "consensus_log",
        "consensus_snapshot",
    ] {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = conn
            .query_row(&sql, [], |row| row.get(0))
            .map_err(db_error)?;
        if count != 0 {
            return Err(invalid_data(
                "session consensus snapshot contains log-store authority",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn install_snapshot_database_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    snapshot_db_path: &std::path::Path,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    final_file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    let incoming_last_log_id = meta.last_log_id.as_ref();
    validate_snapshot_floor(conn, identity, incoming_last_log_id)?;
    validate_snapshot_database_sync(snapshot_db_path, identity, expected_members, meta)?;
    if final_file_name.is_empty()
        || final_file_name.contains('/')
        || final_file_name.contains('\\')
        || final_file_name == "."
        || final_file_name == ".."
    {
        return Err(invalid_data("invalid session consensus snapshot file name"));
    }
    let byte_length = checked_positive_i64(byte_length)?;
    let snapshot_path = snapshot_db_path
        .to_str()
        .ok_or_else(|| invalid_data("session consensus snapshot path is not UTF-8"))?;
    conn.execute("ATTACH DATABASE ?1 AS consensus_incoming", [snapshot_path])
        .map_err(db_error)?;

    let result = (|| {
        let tx = conn.unchecked_transaction().map_err(db_error)?;
        // Re-check under the same transaction that swaps the state image. A
        // second process must not be able to advance the durable floor between
        // validation and replacement even though deployment admission already
        // requires one writer per backing store.
        validate_snapshot_floor(&tx, identity, incoming_last_log_id)?;
        for (table, columns) in [
            (
                "session_records",
                "tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, state_type, expires_at, payload, encoding",
            ),
            (
                "leases",
                "tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at",
            ),
            (
                "key_fences",
                "tenant, nf_kind, key_type, stable_id, fence",
            ),
            ("lease_globals", "key, val"),
            (
                "session_replication_log",
                "sequence, tx_id, entry_json, timestamp",
            ),
            (
                "consensus_request_outcomes",
                "request_id, configuration_epoch, payload_digest, response_json",
            ),
            (
                "consensus_machine",
                "singleton, configuration_epoch, application_sequence, last_digest, logical_time, watch_sequence",
            ),
            (
                "consensus_membership",
                "singleton, configuration_epoch, membership_json",
            ),
            (
                "consensus_applied",
                "singleton, configuration_epoch, term, log_index, log_id_json",
            ),
            (
                "consensus_operator_recovery",
                "singleton, configuration_epoch, recovery_epoch, last_plan_digest, pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor",
            ),
            (
                "restore_scan_state",
                "singleton, epoch, revision, cursor_key",
            ),
        ] {
            tx.execute(&format!("DELETE FROM {table}"), [])
                .map_err(db_error)?;
            tx.execute(
                &format!(
                    "INSERT INTO {table} ({columns}) SELECT {columns} FROM consensus_incoming.{table}"
                ),
                [],
            )
            .map_err(db_error)?;
        }
        // Restore cursors are local evidence, not replicated state-machine
        // authority. Every snapshot destination gets a fresh incarnation so
        // two nodes installing the same coherent snapshot cannot consume one
        // another's continuation token.
        ops::rotate_restore_scan_incarnation_sync(&tx)
            .map_err(|_| invalid_data("installed session snapshot restore metadata failed"))?;
        tx.execute(
            "INSERT OR REPLACE INTO consensus_snapshot (singleton, configuration_epoch, meta_json, file_name, checksum, byte_length) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                epoch_i64(identity)?,
                encode_json(meta)?,
                final_file_name,
                checksum.as_slice(),
                byte_length,
            ],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)
    })();

    let detach = conn
        .execute("DETACH DATABASE consensus_incoming", [])
        .map_err(db_error);
    result.and(detach.map(|_| ()))
}

fn validate_snapshot_floor(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    incoming_last_log_id: Option<&LogId<SessionConsensusNodeId>>,
) -> io::Result<()> {
    for floor in [
        read_committed_sync(conn, identity)?,
        read_applied_sync(conn, identity)?,
    ] {
        let Some(floor) = floor else {
            continue;
        };
        let Some(incoming) = incoming_last_log_id else {
            return Err(invalid_data(
                "session consensus snapshot regresses durable state",
            ));
        };
        if incoming.index < floor.index || (incoming.index == floor.index && incoming != &floor) {
            return Err(invalid_data(
                "session consensus snapshot regresses durable state",
            ));
        }
    }
    Ok(())
}

pub(crate) fn save_current_snapshot_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
) -> io::Result<()> {
    validate_fixed_membership(&meta.last_membership, expected_members)?;
    let changed = conn
        .execute(
            "INSERT OR REPLACE INTO consensus_snapshot (singleton, configuration_epoch, meta_json, file_name, checksum, byte_length) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                epoch_i64(identity)?,
                encode_json(meta)?,
                file_name,
                checksum.as_slice(),
                checked_positive_i64(byte_length)?,
            ],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data(
            "session consensus snapshot metadata was not saved",
        ));
    }
    Ok(())
}

pub(crate) type CurrentSnapshot = (
    opc_consensus::engine::SnapshotMeta<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    String,
    [u8; 32],
    u64,
);

pub(crate) fn read_current_snapshot_sync(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<Option<CurrentSnapshot>> {
    let row = conn
        .query_row(
            "SELECT configuration_epoch, meta_json, file_name, checksum, byte_length FROM consensus_snapshot WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?;
    let Some((epoch, encoded_meta, file_name, checksum, byte_length)) = row else {
        return Ok(None);
    };
    validate_epoch(epoch, identity)?;
    if file_name.is_empty()
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name == "."
        || file_name == ".."
    {
        return Err(invalid_data(
            "persisted session consensus snapshot file name is invalid",
        ));
    }
    let checksum = checksum
        .try_into()
        .map_err(|_| invalid_data("persisted session consensus snapshot checksum is invalid"))?;
    let meta: opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    > = decode_json(&encoded_meta)?;
    validate_fixed_membership(&meta.last_membership, expected_members)?;
    Ok(Some((
        meta,
        file_name,
        checksum,
        checked_positive_u64(byte_length)?,
    )))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId};
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    use super::*;
    use crate::model::{OwnerId, SessionKey, SessionKeyType};
    use crate::restore::{RestoreScanCursor, RestoreScanRequest, RestoreScanScope};

    fn identity() -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::new("state-machine-fault-tests")
                .expect("cluster ID"),
            crate::consensus::SessionConsensusConfigurationId::from_bytes([0x51; 32]),
            crate::consensus::SessionConsensusConfigurationEpoch::new(1)
                .expect("configuration epoch"),
        )
    }

    fn node_id() -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(7).expect("node ID")
    }

    fn expected_members() -> BTreeSet<SessionConsensusNodeId> {
        BTreeSet::from([node_id()])
    }

    fn member(value: u64) -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(value).expect("member ID")
    }

    fn stored_membership(
        configs: Vec<BTreeSet<SessionConsensusNodeId>>,
        nodes: BTreeSet<SessionConsensusNodeId>,
    ) -> StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode> {
        StoredMembership::new(
            Some(log_id(0)),
            opc_consensus::engine::Membership::new(configs, nodes),
        )
    }

    fn log_id(index: u64) -> LogId<SessionConsensusNodeId> {
        LogId::new(CommittedLeaderId::new(1, node_id()), index)
    }

    fn timestamp(second: u8) -> Timestamp {
        Timestamp::from_str(&format!("2026-07-12T00:00:{second:02}Z")).expect("timestamp")
    }

    fn key() -> crate::model::SessionKey {
        SessionKey {
            tenant: TenantId::from_static("state-machine-fault-tenant"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"state-machine-fault-session"),
        }
    }

    fn membership_entry() -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![expected_members()],
                expected_members(),
            )),
        }
    }

    fn acquire_entry(
        index: u64,
        request_id: [u8; 16],
        owner: &'static str,
    ) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: identity(),
                request_id: SessionConsensusRequestId::from_bytes(request_id),
                logical_time: timestamp(u8::try_from(index).expect("test index fits timestamp")),
                intent: SessionMutationIntent::AcquireLease {
                    key: key(),
                    owner: OwnerId::new(owner).expect("owner"),
                    ttl: Duration::from_secs(300),
                },
            }),
        }
    }

    #[test]
    fn only_deterministic_domain_rejections_are_committable() {
        for error in [
            StoreError::NotFound,
            StoreError::StaleFence,
            StoreError::CasConflict,
            StoreError::InvalidKey("SDK-owned validation reason".into()),
            StoreError::InvalidSessionTtl,
            StoreError::LeaseHeld,
            StoreError::LeaseExpired,
            StoreError::PayloadTooLarge { actual: 2, max: 1 },
        ] {
            assert!(is_deterministic_intent_rejection(&error));
        }

        for error in [
            StoreError::BackendUnavailable("node-local detail".into()),
            StoreError::Serialization("corrupt local row".into()),
            StoreError::CapabilityNotSupported("local capability".into()),
            StoreError::Crypto("invalid persisted envelope".into()),
        ] {
            assert!(!is_deterministic_intent_rejection(&error));
        }
    }

    #[test]
    fn fixed_membership_rejects_subset_joint_and_learner_shapes() {
        let expected = BTreeSet::from([member(7), member(8), member(9)]);
        let exact = stored_membership(vec![expected.clone()], expected.clone());
        validate_fixed_membership(&exact, &expected).expect("exact membership");

        let subset = BTreeSet::from([member(7), member(8)]);
        assert!(validate_fixed_membership(
            &stored_membership(vec![subset.clone()], subset),
            &expected
        )
        .is_err());
        assert!(validate_fixed_membership(
            &stored_membership(
                vec![expected.clone(), BTreeSet::from([member(7), member(8)])],
                expected.clone(),
            ),
            &expected,
        )
        .is_err());
        let mut nodes_with_learner = expected.clone();
        nodes_with_learner.insert(member(10));
        assert!(validate_fixed_membership(
            &stored_membership(vec![expected.clone()], nodes_with_learner),
            &expected,
        )
        .is_err());
    }

    #[tokio::test]
    async fn reopening_rejects_mismatched_persisted_membership() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let expected = expected_members();
        initialize_schema(&conn, identity, &expected).expect("consensus schema");
        let unexpected = stored_membership(
            vec![BTreeSet::from([member(8)])],
            BTreeSet::from([member(8)]),
        );
        conn.execute(
            "UPDATE consensus_membership SET membership_json = ?1 WHERE singleton = 1",
            [encode_json(&unexpected).expect("membership encoding")],
        )
        .expect("inject persisted mismatch");
        assert_eq!(
            SessionConsensusStorageError::CorruptState,
            initialize_schema(&conn, identity, &expected)
                .expect_err("mismatched persisted membership must reject startup")
        );
    }

    #[tokio::test]
    async fn snapshot_metadata_mismatch_is_rejected_before_persistence() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let expected = expected_members();
        initialize_schema(&conn, identity, &expected).expect("consensus schema");
        let unexpected = stored_membership(
            vec![BTreeSet::from([member(8)])],
            BTreeSet::from([member(8)]),
        );
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id: Some(log_id(0)),
            last_membership: unexpected,
            snapshot_id: "mismatched-membership".into(),
        };
        assert!(save_current_snapshot_sync(
            &conn,
            identity,
            &expected,
            &meta,
            "snapshot.opc",
            [0; 32],
            1,
        )
        .is_err());
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM consensus_snapshot", [], |row| {
                row.get(0)
            })
            .expect("snapshot count");
        assert_eq!(0, count);
    }

    #[tokio::test]
    async fn installed_snapshot_invalidates_source_cursor_and_first_page_restarts() {
        let source = SqliteSessionBackend::in_memory().expect("source backend");
        let source_conn = source.conn.lock().await;
        let identity = identity();
        let expected = expected_members();
        initialize_schema(&source_conn, identity, &expected).expect("source consensus schema");
        apply_entries_sync(
            &source_conn,
            identity,
            &expected,
            &source.caps,
            vec![membership_entry()],
        )
        .expect("apply admitted membership");
        let (source_epoch, source_revision, source_cursor_key) =
            ops::read_restore_scan_state_sync(&source_conn).expect("source cursor state");
        let scope = RestoreScanScope::all();
        let source_cursor = RestoreScanCursor::durable(
            &source_cursor_key,
            source_epoch,
            source_revision,
            timestamp(0),
            &scope,
            &key(),
            1,
        )
        .expect("source cursor");

        let directory = tempfile::tempdir().expect("snapshot directory");
        let snapshot_path = directory.path().join("installed.sqlite");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&source_conn, identity, &expected, &snapshot_path)
                .expect("build snapshot");
        drop(source_conn);
        let meta = opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "restore-cursor-incarnation".to_string(),
        };

        let target = SqliteSessionBackend::in_memory().expect("target backend");
        let target_conn = target.conn.lock().await;
        initialize_schema(&target_conn, identity, &expected).expect("target consensus schema");
        let byte_length = std::fs::metadata(&snapshot_path)
            .expect("snapshot metadata")
            .len();
        install_snapshot_database_sync(
            &target_conn,
            identity,
            &expected,
            &snapshot_path,
            &meta,
            "installed.opc",
            [0x5a; 32],
            byte_length,
        )
        .expect("install snapshot");

        let stale = ops::scan_restore_records_sync(
            &target_conn,
            RestoreScanRequest {
                scope: scope.clone(),
                cursor: Some(source_cursor),
                limit: 1,
            },
            timestamp(1),
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now() + Duration::from_secs(5),
            false,
        )
        .expect_err("snapshot install creates a new cursor incarnation");
        assert_eq!(stale, StoreError::RestoreScanCursorStale);
        let first_page = ops::scan_restore_records_sync(
            &target_conn,
            RestoreScanRequest {
                scope,
                cursor: None,
                limit: 1,
            },
            timestamp(1),
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now() + Duration::from_secs(5),
            false,
        )
        .expect("restart from first page");
        assert!(first_page.complete);
        assert!(first_page.records.is_empty());

        let (target_epoch, target_revision, target_cursor_key) =
            ops::read_restore_scan_state_sync(&target_conn).expect("target cursor state");
        let target_cursor = RestoreScanCursor::durable(
            &target_cursor_key,
            target_epoch,
            target_revision,
            timestamp(1),
            &RestoreScanScope::all(),
            &key(),
            1,
        )
        .expect("target-local cursor");

        let second_target = SqliteSessionBackend::in_memory().expect("second target backend");
        let second_target_conn = second_target.conn.lock().await;
        initialize_schema(&second_target_conn, identity, &expected)
            .expect("second target consensus schema");
        install_snapshot_database_sync(
            &second_target_conn,
            identity,
            &expected,
            &snapshot_path,
            &meta,
            "installed-second.opc",
            [0x6b; 32],
            byte_length,
        )
        .expect("install same snapshot on second target");
        let (second_epoch, _, second_cursor_key) =
            ops::read_restore_scan_state_sync(&second_target_conn)
                .expect("second-target cursor state");
        assert_ne!(target_epoch, second_epoch);
        assert_ne!(*target_cursor_key, *second_cursor_key);
        let cross_node = ops::scan_restore_records_sync(
            &second_target_conn,
            RestoreScanRequest {
                scope: RestoreScanScope::all(),
                cursor: Some(target_cursor),
                limit: 1,
            },
            timestamp(1),
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now() + Duration::from_secs(5),
            false,
        )
        .expect_err("same snapshot still yields node-local cursor incarnations");
        assert_eq!(cross_node, StoreError::RestoreScanCursorStale);
    }

    #[tokio::test]
    async fn node_local_intent_fault_aborts_apply_without_advancing_state() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let expected_members = expected_members();
        initialize_schema(&conn, identity, &expected_members).expect("consensus schema");

        apply_entries_sync(
            &conn,
            identity,
            &expected_members,
            &backend.caps,
            vec![membership_entry()],
        )
        .expect("initial membership entry");
        let baseline_applied = read_applied_sync(&conn, identity).expect("baseline applied");
        let baseline_machine = proposal_state_sync(&conn, identity).expect("baseline machine");
        let baseline_globals: Vec<(String, i64)> = conn
            .prepare("SELECT key, val FROM lease_globals ORDER BY key")
            .expect("prepare globals")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query globals")
            .collect::<rusqlite::Result<_>>()
            .expect("collect globals");

        // Fail after acquire has updated both lease-global allocators. The
        // trigger text is deliberately sensitive-looking so the assertion also
        // proves that the state-machine storage error remains coarse.
        conn.execute_batch(
            r#"
            CREATE TRIGGER fail_consensus_lease_insert
            BEFORE INSERT ON leases
            BEGIN
                SELECT RAISE(ABORT, 'node-local-secret-canary');
            END;
            "#,
        )
        .expect("install local SQLite fault");

        let request_id = [0xA5; 16];
        let error = apply_entries_sync(
            &conn,
            identity,
            &expected_members,
            &backend.caps,
            vec![acquire_entry(1, request_id, "fault-owner")],
        )
        .expect_err("node-local SQLite fault must fail Openraft apply");
        assert_eq!(io::ErrorKind::Other, error.kind());
        assert_eq!(
            "session consensus state-machine operation failed",
            error.to_string()
        );
        assert!(!error.to_string().contains("node-local-secret-canary"));

        assert_eq!(
            baseline_applied,
            read_applied_sync(&conn, identity).expect("applied after fault")
        );
        assert_eq!(
            baseline_machine,
            proposal_state_sync(&conn, identity).expect("machine after fault")
        );
        assert!(read_outcome_sync(
            &conn,
            identity,
            SessionConsensusRequestId::from_bytes(request_id)
        )
        .expect("outcome lookup")
        .is_none());
        for table in ["leases", "key_fences", "session_replication_log"] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("table count");
            assert_eq!(0, count, "{table} must remain unchanged");
        }
        let globals: Vec<(String, i64)> = conn
            .prepare("SELECT key, val FROM lease_globals ORDER BY key")
            .expect("prepare globals")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query globals")
            .collect::<rusqlite::Result<_>>()
            .expect("collect globals");
        assert_eq!(baseline_globals, globals);

        conn.execute("DROP TRIGGER fail_consensus_lease_insert", [])
            .expect("remove local fault");
        let recovered = apply_entries_sync(
            &conn,
            identity,
            &expected_members,
            &backend.caps,
            vec![acquire_entry(1, request_id, "fault-owner")],
        )
        .expect("same entry applies after local storage recovery");
        assert!(matches!(
            recovered.responses.as_slice(),
            [SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::Lease(_)),
                sequence: 1,
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn deterministic_lease_rejection_commits_as_an_outcome() {
        let backend = SqliteSessionBackend::in_memory().expect("backend");
        let conn = backend.conn.lock().await;
        let identity = identity();
        let expected_members = expected_members();
        initialize_schema(&conn, identity, &expected_members).expect("consensus schema");

        let rejected_id = [0xB2; 16];
        let applied = apply_entries_sync(
            &conn,
            identity,
            &expected_members,
            &backend.caps,
            vec![
                membership_entry(),
                acquire_entry(1, [0xB1; 16], "current-owner"),
                acquire_entry(2, rejected_id, "other-owner"),
            ],
        )
        .expect("deterministic rejection remains a committed response");

        assert!(matches!(
            applied.responses.as_slice(),
            [
                SessionConsensusResponse { result: Ok(_), .. },
                SessionConsensusResponse {
                    result: Ok(SessionMutationOutcome::Lease(_)),
                    sequence: 1,
                    ..
                },
                SessionConsensusResponse {
                    result: Err(StoreError::LeaseHeld),
                    sequence: 2,
                    ..
                }
            ]
        ));
        assert_eq!(Some(log_id(2)), read_applied_sync(&conn, identity).unwrap());
        assert_eq!(
            2,
            proposal_state_sync(&conn, identity)
                .expect("machine state")
                .0
        );
        assert!(matches!(
            read_outcome_sync(
                &conn,
                identity,
                SessionConsensusRequestId::from_bytes(rejected_id)
            )
            .expect("rejected outcome")
            .map(|(_, response)| response.result),
            Some(Err(StoreError::LeaseHeld))
        ));
    }
}
