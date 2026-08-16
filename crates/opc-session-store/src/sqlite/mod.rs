//! Durable SQLite implementation of the storage and lease APIs.
//!
//! Intended for single-node and edge/single-replica profiles: it provides
//! transactional fenced CAS, monotonic per-key fences, server-side lease
//! expiry, and per-key TTL on one local database file (WAL mode, full sync).
//! Application-journal replay and watch remain for standalone compatibility.
//! Once the durable consensus identity claims a database, every public raw
//! backend operation fails closed; Openraft's internal state-machine adapter
//! is the only mutation and read-authority path.

use std::ffi::OsStr;
use std::fs::{File, Metadata, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt as _;

use async_trait::async_trait;
use rusqlite::{
    params, Connection, InterruptHandle, OpenFlags, OptionalExtension, Transaction,
    TransactionBehavior,
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
    record::{SessionPayloadEncoding, StoredSessionRecord},
    replication_watch::{
        prepare_consumer_watch_registration, prepare_watch_registration, watch_backlog_query_limit,
        ConsumerReplicationWatcher, ReplicationWatcher,
    },
    restore::{RestoreScanPage, RestoreScanRequest},
    ttl::{
        checked_session_deadline, validate_session_ttl, validate_stored_record_expiry_at,
        validate_stored_record_expiry_profile,
    },
};

pub mod audit;
pub(crate) mod consensus;
pub(crate) mod lease;
pub(crate) mod ops;
pub(crate) mod replication;

/// Maximum encrypted payload bytes retained by the standalone SQLite store.
pub const SQLITE_SESSION_MAX_VALUE_BYTES: usize = 4 * 1024 * 1024 + 64 * 1024;
// Consensus retains its existing value profile until #683 raises the shared
// command/RPC and consumer-response ceilings together. Advertising the raw
// SQLite limit through that adapter would accept values its 2 MiB transport
// cannot propose and would disable every record-bearing consumer batch.
/// Maximum sealed payload bytes admitted by the SQLite consensus adapter.
pub const SQLITE_CONSENSUS_MAX_VALUE_BYTES: usize = 1_048_576;
const CONSENSUS_AUTHORITY_REQUIRED: &str = "consensus_authority_required";
const RESTORE_SCAN_BLOCKING_WORKERS: usize = 1;
const SQLITE_OPERATION_BLOCKING_WORKERS: usize = 1;
const SQLITE_OPERATION_MAX_WORK: Duration = Duration::from_secs(2);
const SQLITE_BUSY_TIMEOUT_MILLIS: u64 = 100;
const SQLITE_OPERATION_PROGRESS_INTERVAL: i32 = 1_000;

const SESSION_RECORDS_SCHEMA_SQL: &str = r#"
    CREATE TABLE session_records (
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
    )
"#;

const RESTORE_SCAN_STATE_SCHEMA_SQL: &str = r#"
    CREATE TABLE restore_scan_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        epoch BLOB NOT NULL CHECK (length(epoch) = 16),
        revision INTEGER NOT NULL CHECK (revision >= 0),
        cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32)
    )
"#;

// This is the single supported standalone predecessor. Every other table in
// that manifest is byte-for-byte the current frozen layout below; only this
// local, non-authoritative restore metadata table predates `cursor_key`.
const RESTORE_SCAN_STATE_PREDECESSOR_SCHEMA_SQL: &str = r#"
    CREATE TABLE restore_scan_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        epoch BLOB NOT NULL CHECK (length(epoch) = 16),
        revision INTEGER NOT NULL CHECK (revision >= 0)
    )
"#;

// SQLite's reviewed `ALTER TABLE ... ADD COLUMN` result cannot add `NOT NULL`
// without a default. A populated, nonzero key under this exact nullable DDL is
// therefore a current schema, including on every restart after migration.
const RESTORE_SCAN_STATE_MIGRATED_SCHEMA_SQL: &str = r#"
    CREATE TABLE restore_scan_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        epoch BLOB NOT NULL CHECK (length(epoch) = 16),
        revision INTEGER NOT NULL CHECK (revision >= 0),
        cursor_key BLOB CHECK (cursor_key IS NULL OR length(cursor_key) = 32)
    )
"#;

const LEASES_SCHEMA_SQL: &str = r#"
    CREATE TABLE leases (
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
    )
"#;

const KEY_FENCES_SCHEMA_SQL: &str = r#"
    CREATE TABLE key_fences (
        tenant TEXT NOT NULL,
        nf_kind TEXT NOT NULL,
        key_type TEXT NOT NULL,
        stable_id BLOB NOT NULL CHECK (
            typeof(stable_id) = 'blob' AND length(stable_id) BETWEEN 1 AND 64
        ),
        fence INTEGER NOT NULL,
        PRIMARY KEY (tenant, nf_kind, key_type, stable_id)
    )
"#;

const LEASE_GLOBALS_SCHEMA_SQL: &str = r#"
    CREATE TABLE lease_globals (
        key TEXT PRIMARY KEY,
        val INTEGER NOT NULL
    )
"#;

const SESSION_REPLICATION_LOG_SCHEMA_SQL: &str = r#"
    CREATE TABLE session_replication_log (
        sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
        tx_id TEXT NOT NULL CHECK (
            typeof(tx_id) = 'text'
            AND length(CAST(tx_id AS BLOB)) BETWEEN 1 AND 128
        ),
        entry_json TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
"#;

const CURRENT_LOCAL_SCHEMA_MANIFEST: &[(&str, &str)] = &[
    ("session_records", SESSION_RECORDS_SCHEMA_SQL),
    ("restore_scan_state", RESTORE_SCAN_STATE_SCHEMA_SQL),
    ("leases", LEASES_SCHEMA_SQL),
    ("key_fences", KEY_FENCES_SCHEMA_SQL),
    ("lease_globals", LEASE_GLOBALS_SCHEMA_SQL),
    (
        "session_replication_log",
        SESSION_REPLICATION_LOG_SCHEMA_SQL,
    ),
];

const MIGRATED_LOCAL_SCHEMA_MANIFEST: &[(&str, &str)] = &[
    ("session_records", SESSION_RECORDS_SCHEMA_SQL),
    ("restore_scan_state", RESTORE_SCAN_STATE_MIGRATED_SCHEMA_SQL),
    ("leases", LEASES_SCHEMA_SQL),
    ("key_fences", KEY_FENCES_SCHEMA_SQL),
    ("lease_globals", LEASE_GLOBALS_SCHEMA_SQL),
    (
        "session_replication_log",
        SESSION_REPLICATION_LOG_SCHEMA_SQL,
    ),
];

const PREDECESSOR_LOCAL_SCHEMA_MANIFEST: &[(&str, &str)] = &[
    ("session_records", SESSION_RECORDS_SCHEMA_SQL),
    (
        "restore_scan_state",
        RESTORE_SCAN_STATE_PREDECESSOR_SCHEMA_SQL,
    ),
    ("leases", LEASES_SCHEMA_SQL),
    ("key_fences", KEY_FENCES_SCHEMA_SQL),
    ("lease_globals", LEASE_GLOBALS_SCHEMA_SQL),
    (
        "session_replication_log",
        SESSION_REPLICATION_LOG_SCHEMA_SQL,
    ),
];

pub(crate) fn validate_consensus_record(record: &StoredSessionRecord) -> Result<(), StoreError> {
    let actual = record.payload.len();
    if actual > SQLITE_CONSENSUS_MAX_VALUE_BYTES {
        return Err(StoreError::PayloadTooLarge {
            actual,
            max: SQLITE_CONSENSUS_MAX_VALUE_BYTES,
        });
    }
    if record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
        return Err(StoreError::Crypto(
            "session consensus requires a sealed payload".into(),
        ));
    }
    record.payload.validate_envelope_for_record(record)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreScanValidationProfile {
    Standalone,
    Consensus,
}

impl RestoreScanValidationProfile {
    const fn is_standalone(self) -> bool {
        matches!(self, Self::Standalone)
    }

    const fn max_payload_bytes(self) -> usize {
        match self {
            Self::Standalone => crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES,
            Self::Consensus => SQLITE_CONSENSUS_MAX_VALUE_BYTES,
        }
    }

    fn validate_record(self, record: &StoredSessionRecord) -> Result<(), StoreError> {
        match self {
            Self::Standalone => Ok(()),
            Self::Consensus => validate_consensus_record(record),
        }
    }
}

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
    admission_state: Arc<AtomicU8>,
    caps: BackendCapabilities,
    clock: Arc<dyn Clock>,
    restore_scan_workers: Arc<tokio::sync::Semaphore>,
    operation_workers: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    pub(crate) consensus_apply_gate: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    consensus_operator_recovery_failure: Arc<AtomicBool>,
    watchers: Arc<tokio::sync::Mutex<Vec<ReplicationWatcher>>>,
    consumer_watchers: Arc<tokio::sync::Mutex<Vec<ConsumerReplicationWatcher>>>,
    #[cfg(test)]
    pub(crate) watch_registration_gate: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    pub(crate) watch_backlog_captured: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalSchemaProvenance {
    /// The caller created the in-memory database or this `open` call created
    /// the file after proving it did not previously exist.
    ProvenNew,
    /// An existing file is durable evidence, even when its rowsets are empty.
    Existing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalOpenStage {
    FileClaimed,
    SqliteConnectionOpened,
    ExistingValidatedBeforePersistentPragma,
    NormalStagedBeforeWal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExistingLocalSchema {
    Current,
    CursorKeyPredecessor,
    ConsensusOwned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum SqliteAdmissionState {
    StandaloneReady = 0,
    ConsensusPending = 1,
    ConsensusInitializing = 2,
    ConsensusReady = 3,
    FailedClosed = 4,
}

impl SqliteAdmissionState {
    fn load(state: &AtomicU8) -> Self {
        match state.load(Ordering::Acquire) {
            0 => Self::StandaloneReady,
            1 => Self::ConsensusPending,
            2 => Self::ConsensusInitializing,
            3 => Self::ConsensusReady,
            _ => Self::FailedClosed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SqliteWorkAuthority {
    Standalone,
    Consensus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SqliteProvisionalProbeAdmission {
    PristineStandalone,
    ConsensusOwned,
}

impl SqliteWorkAuthority {
    fn is_admitted(self, state: &AtomicU8) -> bool {
        let expected = match self {
            Self::Standalone => SqliteAdmissionState::StandaloneReady,
            Self::Consensus => SqliteAdmissionState::ConsensusReady,
        };
        SqliteAdmissionState::load(state) == expected
    }
}

struct FileBackedOpenClaim {
    database_path: PathBuf,
    guardian: File,
    provenance: LocalSchemaProvenance,
}

fn invalid_file_backed_namespace() -> StoreError {
    StoreError::BackendUnavailable("session SQLite database namespace is unsafe".into())
}

fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        // FILE_ATTRIBUTE_REPARSE_POINT. The stable standard-library metadata
        // API exposes attributes but not a portable hard-link/file-ID tuple.
        return metadata.file_attributes() & 0x0000_0400 != 0;
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn validate_database_parent(path: &Path) -> Result<PathBuf, StoreError> {
    let file_name = path.file_name().ok_or_else(invalid_file_backed_namespace)?;
    if file_name == OsStr::new(".") || file_name == OsStr::new("..") {
        return Err(invalid_file_backed_namespace());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        StoreError::BackendUnavailable(format!(
            "session SQLite database parent is unavailable: {error}"
        ))
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata)
    {
        return Err(invalid_file_backed_namespace());
    }
    let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
        StoreError::BackendUnavailable(format!(
            "session SQLite database parent is unavailable: {error}"
        ))
    })?;
    let canonical_metadata = std::fs::symlink_metadata(&canonical_parent).map_err(|error| {
        StoreError::BackendUnavailable(format!(
            "session SQLite database parent is unavailable: {error}"
        ))
    })?;
    if !canonical_metadata.is_dir()
        || canonical_metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&canonical_metadata)
    {
        return Err(invalid_file_backed_namespace());
    }
    Ok(canonical_parent.join(file_name))
}

fn guarded_database_open_options(create_new: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
    }
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
}

fn validate_guarded_database_file(database_path: &Path, guardian: &File) -> Result<(), StoreError> {
    let guarded = guardian.metadata().map_err(|error| {
        StoreError::BackendUnavailable(format!("session SQLite database is unavailable: {error}"))
    })?;
    let named = std::fs::symlink_metadata(database_path).map_err(|error| {
        StoreError::BackendUnavailable(format!("session SQLite database is unavailable: {error}"))
    })?;
    if !guarded.is_file()
        || !named.is_file()
        || named.file_type().is_symlink()
        || metadata_is_reparse_point(&named)
    {
        return Err(invalid_file_backed_namespace());
    }

    #[cfg(unix)]
    if guarded.nlink() != 1
        || named.nlink() != 1
        || guarded.dev() != named.dev()
        || guarded.ino() != named.ino()
    {
        return Err(invalid_file_backed_namespace());
    }

    Ok(())
}

fn claim_file_backed_database(path: &Path) -> Result<FileBackedOpenClaim, StoreError> {
    let database_path = validate_database_parent(path)?;
    let (guardian, provenance) = match guarded_database_open_options(true).open(&database_path) {
        Ok(file) => (file, LocalSchemaProvenance::ProvenNew),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(&database_path).map_err(|error| {
                StoreError::BackendUnavailable(format!(
                    "session SQLite database is unavailable: {error}"
                ))
            })?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata_is_reparse_point(&metadata)
            {
                return Err(invalid_file_backed_namespace());
            }
            let file = guarded_database_open_options(false)
                .open(&database_path)
                .map_err(|error| {
                    StoreError::BackendUnavailable(format!(
                        "session SQLite database is unavailable: {error}"
                    ))
                })?;
            (file, LocalSchemaProvenance::Existing)
        }
        Err(error) => return Err(StoreError::BackendUnavailable(error.to_string())),
    };
    validate_guarded_database_file(&database_path, &guardian)?;
    let canonical_database_path = std::fs::canonicalize(&database_path).map_err(|error| {
        StoreError::BackendUnavailable(format!("session SQLite database is unavailable: {error}"))
    })?;
    validate_guarded_database_file(&canonical_database_path, &guardian)?;
    Ok(FileBackedOpenClaim {
        database_path: canonical_database_path,
        guardian,
        provenance,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalSchemaColumn {
    cid: i64,
    name: String,
    declared_type: String,
    not_null: i64,
    default_value: Option<String>,
    primary_key: i64,
    hidden: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalSchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    normalized_sql: Option<String>,
    columns: Vec<LocalSchemaColumn>,
}

fn normalize_local_schema_sql(sql: &str) -> String {
    let mut normalized = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    let mut quote_end = None;
    while let Some(character) = characters.next() {
        if let Some(end) = quote_end {
            normalized.push(character);
            if character == end {
                if end != ']' && characters.peek() == Some(&end) {
                    normalized.push(characters.next().unwrap_or(end));
                } else {
                    quote_end = None;
                }
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                quote_end = Some(character);
                normalized.push(character);
            }
            '[' => {
                quote_end = Some(']');
                normalized.push(character);
            }
            character if character.is_ascii_whitespace() => {}
            character => normalized.push(character.to_ascii_lowercase()),
        }
    }
    normalized
}

fn local_schema_manifest(conn: &Connection) -> rusqlite::Result<Vec<LocalSchemaObject>> {
    let mut statement = conn.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE substr(name, 1, 7) != 'sqlite_' COLLATE NOCASE ORDER BY type, name",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    objects
        .into_iter()
        .map(|(object_type, name, table_name, sql)| {
            let columns = if object_type == "table" {
                let mut columns = conn.prepare(
                    r#"SELECT cid, name, type, "notnull", dflt_value, pk, hidden
                       FROM pragma_table_xinfo(?1) ORDER BY cid"#,
                )?;
                let observed = columns
                    .query_map([name.as_str()], |row| {
                        Ok(LocalSchemaColumn {
                            cid: row.get(0)?,
                            name: row.get(1)?,
                            declared_type: row.get(2)?,
                            not_null: row.get(3)?,
                            default_value: row.get(4)?,
                            primary_key: row.get(5)?,
                            hidden: row.get(6)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                observed
            } else {
                Vec::new()
            };
            Ok(LocalSchemaObject {
                object_type,
                name,
                table_name,
                normalized_sql: sql.map(|value| normalize_local_schema_sql(&value)),
                columns,
            })
        })
        .collect()
}

fn frozen_local_schema_manifest(
    definitions: &[(&str, &str)],
) -> Result<Vec<LocalSchemaObject>, StoreError> {
    let expected = Connection::open_in_memory().map_err(|_| {
        StoreError::BackendUnavailable("canonical session schema is invalid".into())
    })?;
    for (name, sql) in definitions {
        expected.execute_batch(sql).map_err(|_| {
            StoreError::BackendUnavailable("canonical session schema is invalid".into())
        })?;
        let exists = expected
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [*name],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| {
                StoreError::BackendUnavailable("canonical session schema is invalid".into())
            })?;
        if !exists {
            return Err(StoreError::BackendUnavailable(
                "canonical session schema is invalid".into(),
            ));
        }
    }
    local_schema_manifest(&expected)
        .map_err(|_| StoreError::BackendUnavailable("canonical session schema is invalid".into()))
}

fn classify_existing_local_schema(conn: &Connection) -> Result<ExistingLocalSchema, StoreError> {
    let observed = local_schema_manifest(conn)
        .map_err(|_| StoreError::Serialization("persisted session schema is invalid".into()))?;
    let current = frozen_local_schema_manifest(CURRENT_LOCAL_SCHEMA_MANIFEST)?;
    let migrated = frozen_local_schema_manifest(MIGRATED_LOCAL_SCHEMA_MANIFEST)?;
    if observed == current || observed == migrated {
        return Ok(ExistingLocalSchema::Current);
    }
    if observed == frozen_local_schema_manifest(PREDECESSOR_LOCAL_SCHEMA_MANIFEST)? {
        return Ok(ExistingLocalSchema::CursorKeyPredecessor);
    }

    // A consensus-owned database has a distinct complete manifest and is
    // authority-fenced from the standalone API. Admit only a current local
    // six-table subset plus a separately recognized consensus inventory;
    // arbitrary extensions cannot masquerade as consensus ownership.
    let local_names = CURRENT_LOCAL_SCHEMA_MANIFEST
        .iter()
        .map(|(name, _)| *name)
        .collect::<std::collections::BTreeSet<_>>();
    let local = observed
        .iter()
        .filter(|object| local_names.contains(object.name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let only_consensus_extensions = observed.iter().all(|object| {
        local_names.contains(object.name.as_str()) || object.name.starts_with("consensus_")
    });
    if only_consensus_extensions
        && (local == current || local == migrated)
        && consensus::validate_consensus_inventory_for_local_open(conn)
            .map_err(|_| StoreError::Serialization("persisted session schema is invalid".into()))?
    {
        return Ok(ExistingLocalSchema::ConsensusOwned);
    }
    Err(StoreError::Serialization(
        "persisted session schema is invalid".into(),
    ))
}

/// Revalidate the complete standalone schema when a previously released raw
/// backend is claimed for fresh consensus ownership. This catalog-only check
/// closes the constructor-to-initializer gap without repeating any authority
/// row scan.
pub(super) fn validate_local_schema_for_fresh_consensus_claim(
    conn: &Connection,
) -> Result<(), StoreError> {
    if classify_existing_local_schema(conn)? == ExistingLocalSchema::Current {
        Ok(())
    } else {
        Err(StoreError::Serialization(
            "persisted session schema is invalid".into(),
        ))
    }
}

fn validate_restore_scan_metadata_row(
    conn: &Connection,
    schema: ExistingLocalSchema,
) -> Result<(), StoreError> {
    let invalid: bool = match schema {
        ExistingLocalSchema::Current | ExistingLocalSchema::ConsensusOwned => conn.query_row(
            r#"
            SELECT COUNT(*) != 1 OR EXISTS(
                SELECT 1 FROM restore_scan_state
                WHERE typeof(singleton) != 'integer'
                   OR singleton != 1
                   OR typeof(epoch) != 'blob'
                   OR length(epoch) != 16
                   OR epoch = zeroblob(16)
                   OR typeof(revision) != 'integer'
                   OR revision < 0
                   OR typeof(cursor_key) != 'blob'
                   OR length(cursor_key) != 32
                   OR cursor_key = zeroblob(32)
            )
            FROM restore_scan_state
            "#,
            [],
            |row| row.get(0),
        ),
        ExistingLocalSchema::CursorKeyPredecessor => conn.query_row(
            r#"
            SELECT COUNT(*) != 1 OR EXISTS(
                SELECT 1 FROM restore_scan_state
                WHERE typeof(singleton) != 'integer'
                   OR singleton != 1
                   OR typeof(epoch) != 'blob'
                   OR length(epoch) != 16
                   OR epoch = zeroblob(16)
                   OR typeof(revision) != 'integer'
                   OR revision < 0
            )
            FROM restore_scan_state
            "#,
            [],
            |row| row.get(0),
        ),
    }
    .map_err(|_| {
        StoreError::Serialization("persisted session restore metadata is invalid".into())
    })?;
    if invalid {
        return Err(StoreError::Serialization(
            "persisted session restore metadata is invalid".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_consensus_restore_scan_metadata_row(
    conn: &Connection,
) -> Result<(), StoreError> {
    validate_restore_scan_metadata_row(conn, ExistingLocalSchema::ConsensusOwned)
}

fn invalid_standalone_persisted_state() -> StoreError {
    StoreError::Serialization("persisted standalone session state is invalid".into())
}

fn validate_standalone_session_rows(conn: &Connection) -> Result<(), StoreError> {
    let mut records = conn
        .prepare(
            r#"
            SELECT tenant, nf_kind, key_type, stable_id, generation, owner,
                   fence, state_class, state_type, expires_at, payload, encoding
            FROM session_records
            "#,
        )
        .map_err(|_| invalid_standalone_persisted_state())?;
    let rows = records
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
        .map_err(|_| invalid_standalone_persisted_state())?;
    for row in rows {
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
        ) = row.map_err(|_| invalid_standalone_persisted_state())?;
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
        .map_err(|_| invalid_standalone_persisted_state())?;
        if record.payload.len() > SQLITE_SESSION_MAX_VALUE_BYTES
            || validate_stored_record_expiry_profile(&record).is_err()
        {
            return Err(invalid_standalone_persisted_state());
        }
    }
    Ok(())
}

fn validate_standalone_replication_log(conn: &Connection) -> Result<(), StoreError> {
    let mut statement = conn
        .prepare(
            r#"
            SELECT sequence,
                   CASE
                       WHEN typeof(tx_id) = 'text'
                        AND length(CAST(tx_id AS BLOB)) BETWEEN ?1 AND ?2
                       THEN tx_id
                   END,
                   entry_json,
                   timestamp
            FROM session_replication_log
            ORDER BY sequence
            "#,
        )
        .map_err(|_| invalid_standalone_persisted_state())?;
    let rows = statement
        .query_map(
            params![REPLICATION_TX_ID_MIN_BYTES, REPLICATION_TX_ID_MAX_BYTES],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(|_| invalid_standalone_persisted_state())?;
    let mut expected_sequence = 1_u64;
    for row in rows {
        let (sequence, tx_id, entry_json, timestamp) =
            row.map_err(|_| invalid_standalone_persisted_state())?;
        let entry =
            replication::hydrate_replication_entry(sequence, tx_id, &entry_json, &timestamp)
                .map_err(|_| invalid_standalone_persisted_state())?;
        if entry.sequence != expected_sequence
            || replication::validate_replication_payloads(&entry.op, SQLITE_SESSION_MAX_VALUE_BYTES)
                .is_err()
        {
            return Err(invalid_standalone_persisted_state());
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(invalid_standalone_persisted_state)?;
    }
    Ok(())
}

fn validate_existing_local_state(
    conn: &Connection,
    schema: ExistingLocalSchema,
) -> Result<(), StoreError> {
    if schema == ExistingLocalSchema::ConsensusOwned {
        // The raw backend remains authority-fenced by `consensus_identity`.
        // Its initializer owns the one complete consensus state validation
        // (including restore metadata) and every supported migration while
        // this connection keeps the admission lock retained.
        return Ok(());
    }
    validate_restore_scan_metadata_row(conn, schema)?;
    validate_standalone_session_rows(conn)?;
    validate_standalone_replication_log(conn)?;
    consensus::validate_lease_state_sync(conn).map_err(|_| {
        StoreError::Serialization("persisted session lease authority is invalid".into())
    })
}

fn validate_existing_local_schema_with_hooks(
    conn: &Connection,
    after_migration: impl FnOnce(&Transaction<'_>) -> Result<(), StoreError>,
    mut before_full_state_validation: impl FnMut(),
) -> Result<ExistingLocalSchema, StoreError> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)
        .map_err(|_| StoreError::BackendUnavailable("session schema admission failed".into()))?;
    let schema = classify_existing_local_schema(&tx)?;
    if schema != ExistingLocalSchema::ConsensusOwned {
        before_full_state_validation();
    }
    validate_existing_local_state(&tx, schema)?;

    if schema == ExistingLocalSchema::CursorKeyPredecessor {
        ops::initialize_restore_scan_metadata_in_transaction_sync(&tx)?;
        after_migration(&tx)?;
        if classify_existing_local_schema(&tx)? != ExistingLocalSchema::Current {
            return Err(StoreError::Serialization(
                "persisted session schema is invalid".into(),
            ));
        }
        // The cursor migration changes only this bounded metadata table. The
        // complete record/log/lease authority scan above remains protected by
        // this same transaction, so validate the migrated table and key
        // directly instead of rescanning unchanged authority rowsets.
        validate_restore_scan_metadata_row(&tx, ExistingLocalSchema::Current)?;
    }

    tx.commit()
        .map_err(|_| StoreError::BackendUnavailable("session schema admission failed".into()))?;
    Ok(schema)
}

fn validate_existing_local_schema_with_migration_hook(
    conn: &Connection,
    after_migration: impl FnOnce(&Transaction<'_>) -> Result<(), StoreError>,
) -> Result<ExistingLocalSchema, StoreError> {
    validate_existing_local_schema_with_hooks(conn, after_migration, || {})
}

fn validate_existing_local_schema(conn: &Connection) -> Result<ExistingLocalSchema, StoreError> {
    validate_existing_local_schema_with_migration_hook(conn, |_| Ok(()))
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

fn configure_sqlite_busy_timeout(conn: &Connection) -> Result<(), StoreError> {
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MILLIS))
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))
}

fn verify_sqlite_locking_mode(conn: &Connection, expected: &str) -> Result<(), StoreError> {
    let observed: String = conn
        .query_row("PRAGMA locking_mode", [], |row| row.get(0))
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    if !observed.eq_ignore_ascii_case(expected) {
        return Err(StoreError::BackendUnavailable(format!(
            "failed to select SQLite {expected} locking mode: {observed}"
        )));
    }
    Ok(())
}

fn retain_sqlite_exclusive_locking_mode(conn: &Connection) -> Result<(), StoreError> {
    let observed: String = conn
        .query_row("PRAGMA locking_mode = EXCLUSIVE", [], |row| row.get(0))
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    if !observed.eq_ignore_ascii_case("exclusive") {
        return Err(StoreError::BackendUnavailable(format!(
            "failed to select SQLite exclusive locking mode: {observed}"
        )));
    }
    verify_sqlite_locking_mode(conn, "exclusive")
}

fn stage_sqlite_normal_locking_mode(conn: &Connection) -> Result<(), StoreError> {
    let observed: String = conn
        .query_row("PRAGMA locking_mode = NORMAL", [], |row| row.get(0))
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    if !observed.eq_ignore_ascii_case("normal") {
        return Err(StoreError::BackendUnavailable(format!(
            "failed to restore SQLite normal locking mode: {observed}"
        )));
    }
    Ok(())
}

fn release_sqlite_exclusive_locking_mode(conn: &Connection) -> Result<(), StoreError> {
    stage_sqlite_normal_locking_mode(conn)?;
    // SQLite releases a retained EXCLUSIVE lock on the next completed database
    // access after changing back to NORMAL. Make that boundary explicit rather
    // than relying on an autocommit PRAGMA/read statement's lifetime.
    let read_boundary = Transaction::new_unchecked(conn, TransactionBehavior::Deferred)
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    read_boundary
        .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    read_boundary
        .commit()
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    verify_sqlite_locking_mode(conn, "normal")
}

fn initialize_new_local_schema(conn: &Connection) -> Result<(), StoreError> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)
        .map_err(|_| StoreError::BackendUnavailable("session schema admission failed".into()))?;
    for (_, sql) in CURRENT_LOCAL_SCHEMA_MANIFEST {
        tx.execute_batch(sql)
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    }
    ops::initialize_restore_scan_metadata_in_transaction_sync(&tx)?;
    tx.execute(
        "INSERT INTO lease_globals (key, val) VALUES ('next_fence', 1)",
        [],
    )
    .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    tx.execute(
        "INSERT INTO lease_globals (key, val) VALUES ('next_credential_id', 1)",
        [],
    )
    .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    let schema = classify_existing_local_schema(&tx)?;
    if schema != ExistingLocalSchema::Current {
        return Err(StoreError::Serialization(
            "persisted session schema is invalid".into(),
        ));
    }
    validate_existing_local_state(&tx, schema)?;
    tx.commit()
        .map_err(|_| StoreError::BackendUnavailable("session schema admission failed".into()))
}

fn verify_sqlite_connection_pragma_profile(
    conn: &Connection,
    expected_journal_mode: Option<&str>,
) -> Result<(), StoreError> {
    let synchronous: i64 = conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    let temp_store: i64 = conn
        .query_row("PRAGMA temp_store", [], |row| row.get(0))
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    let busy_timeout: u64 = conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    if synchronous != 3
        || foreign_keys != 1
        || temp_store != 2
        || busy_timeout != SQLITE_BUSY_TIMEOUT_MILLIS
    {
        return Err(StoreError::BackendUnavailable(
            "failed to apply the SQLite connection pragma profile".into(),
        ));
    }
    if let Some(expected) = expected_journal_mode {
        let observed: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        if !observed.eq_ignore_ascii_case(expected) {
            return Err(StoreError::BackendUnavailable(format!(
                "failed to select SQLite {expected} journal mode: {observed}"
            )));
        }
    }
    Ok(())
}

fn apply_in_memory_pragma_profile(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        r#"
        PRAGMA synchronous = EXTRA;
        PRAGMA foreign_keys = ON;
        PRAGMA temp_store = MEMORY;
        "#,
    )
    .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
    configure_sqlite_busy_timeout(conn)?;
    verify_sqlite_connection_pragma_profile(conn, None)
}

fn apply_file_pragma_profile_and_release(conn: &Connection) -> Result<(), StoreError> {
    apply_file_pragma_profile_and_release_with_hook(conn, |_| {})
}

fn apply_file_pragma_profile_and_release_with_hook(
    conn: &Connection,
    mut hook: impl FnMut(LocalOpenStage),
) -> Result<(), StoreError> {
    let mut apply = || {
        // A reopened database may already persist WAL mode. SQLite cannot
        // leave EXCLUSIVE locking mode after this connection first accesses
        // that WAL, so checkpoint the already-validated image back to rollback
        // journaling while the physical admission lock is still retained.
        // Invalid images never reach this transition.
        let rollback_mode: String = conn
            .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        if !rollback_mode.eq_ignore_ascii_case("delete") {
            return Err(StoreError::BackendUnavailable(format!(
                "failed to normalize SQLite rollback journal mode: {rollback_mode}"
            )));
        }
        // Select NORMAL while the physical admission lock is still retained,
        // then make the WAL transition the immediate next database access.
        // That statement is the indivisible hand-off from the validated image
        // to its live WAL family.
        stage_sqlite_normal_locking_mode(conn)?;
        hook(LocalOpenStage::NormalStagedBeforeWal);
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::BackendUnavailable(format!(
                "failed to enable SQLite WAL journal mode: {journal_mode}"
            )));
        }
        conn.execute_batch(
            r#"
            PRAGMA synchronous = EXTRA;
            PRAGMA foreign_keys = ON;
            PRAGMA temp_store = MEMORY;
            "#,
        )
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        configure_sqlite_busy_timeout(conn)?;
        verify_sqlite_connection_pragma_profile(conn, Some("wal"))?;
        verify_sqlite_locking_mode(conn, "normal")?;
        // Force and finalize a read boundary so lock release remains explicit
        // for databases that were already in WAL before this admission.
        let read_boundary = Transaction::new_unchecked(conn, TransactionBehavior::Deferred)
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        read_boundary
            .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        read_boundary
            .commit()
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        verify_sqlite_locking_mode(conn, "normal")
    };
    let result = apply();
    if result.is_err() {
        // A failed post-validation profile must not leave an otherwise reusable
        // connection indefinitely holding the admission lock.
        let _ = release_sqlite_exclusive_locking_mode(conn);
    }
    result
}

impl SqliteSessionBackend {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_admission_hook(path.as_ref(), |_, _| {})
    }

    fn open_with_admission_hook(
        path: &Path,
        mut hook: impl FnMut(LocalOpenStage, &File),
    ) -> Result<Self, StoreError> {
        // The immediate parent is a deployment-owned namespace. Within that
        // boundary, atomically claim a new regular file (or open one exact
        // existing regular file) without following a final symlink. Retain the
        // guardian until SQLite has opened the same canonical pathname. SQLite
        // must keep that pathname—not a descriptor alias—so its WAL/SHM family
        // remains one portable namespace. The guardian supplies the leaf
        // no-follow check; `SQLITE_OPEN_NOFOLLOW` is deliberately omitted
        // because SQLite inherits it for ATTACH and would then reject the
        // Linux `/proc/self/fd` binding used only by journal-off snapshot
        // staging. The trusted-parent contract excludes a hostile rename in
        // the small guardian-to-SQLite-open interval.
        let claim = claim_file_backed_database(path)?;
        hook(LocalOpenStage::FileClaimed, &claim.guardian);
        let conn = Connection::open_with_flags(
            &claim.database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        hook(LocalOpenStage::SqliteConnectionOpened, &claim.guardian);
        validate_guarded_database_file(&claim.database_path, &claim.guardian)?;
        configure_sqlite_busy_timeout(&conn)?;
        if let Some(latch) = consensus::read_operator_recovery_latch_sync(&claim.database_path)
            .map_err(|_| {
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
        Self::new_with_conn_and_hook(
            conn,
            false,
            Some(claim.database_path),
            claim.provenance,
            |stage| hook(stage, &claim.guardian),
        )
    }

    /// Open an ephemeral in-memory SQLite database.
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Self::new_with_conn(conn, true, None, LocalSchemaProvenance::ProvenNew)
    }

    fn new_with_conn(
        conn: Connection,
        in_memory: bool,
        database_path: Option<PathBuf>,
        provenance: LocalSchemaProvenance,
    ) -> Result<Self, StoreError> {
        Self::new_with_conn_and_hook(conn, in_memory, database_path, provenance, |_| {})
    }

    fn new_with_conn_and_hook(
        conn: Connection,
        in_memory: bool,
        database_path: Option<PathBuf>,
        provenance: LocalSchemaProvenance,
        mut hook: impl FnMut(LocalOpenStage),
    ) -> Result<Self, StoreError> {
        let admission_state = if in_memory {
            initialize_new_local_schema(&conn)?;
            apply_in_memory_pragma_profile(&conn)?;
            SqliteAdmissionState::StandaloneReady
        } else {
            retain_sqlite_exclusive_locking_mode(&conn)?;
            let schema = if provenance == LocalSchemaProvenance::Existing {
                validate_existing_local_schema(&conn)?
            } else {
                initialize_new_local_schema(&conn)?;
                ExistingLocalSchema::Current
            };
            hook(LocalOpenStage::ExistingValidatedBeforePersistentPragma);
            if schema == ExistingLocalSchema::ConsensusOwned {
                // The consensus initializer owns its sole complete state scan
                // and any supported migration. Preserve SQLite's cooperating-
                // writer exclusion across that continuation, while the shared
                // logical state makes every raw operation on every clone fail
                // closed until initialization consumes the boundary.
                SqliteAdmissionState::ConsensusPending
            } else {
                apply_file_pragma_profile_and_release_with_hook(&conn, &mut hook)?;
                SqliteAdmissionState::StandaloneReady
            }
        };

        Ok(Self {
            conn: Arc::new(tokio::sync::Mutex::new(conn)),
            database_path: database_path.map(Arc::new),
            admission_state: Arc::new(AtomicU8::new(admission_state as u8)),
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
            #[cfg(test)]
            consensus_operator_recovery_failure: Arc::new(AtomicBool::new(false)),
            watchers: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            consumer_watchers: Arc::new(tokio::sync::Mutex::new(Vec::new())),
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
        self.run_store_sqlite_task_with_authority(SqliteWorkAuthority::Standalone, kind, operation)
            .await
    }

    async fn run_consensus_store_sqlite_task<T, F>(
        &self,
        kind: SqliteStoreWorkKind,
        operation: F,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    {
        self.run_store_sqlite_task_with_authority(SqliteWorkAuthority::Consensus, kind, operation)
            .await
    }

    async fn run_store_sqlite_task_with_authority<T, F>(
        &self,
        authority: SqliteWorkAuthority,
        kind: SqliteStoreWorkKind,
        operation: F,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    {
        if !authority.is_admitted(&self.admission_state) {
            return Err(StoreError::CapabilityNotSupported(
                CONSENSUS_AUTHORITY_REQUIRED.into(),
            ));
        }
        let admission_state = Arc::clone(&self.admission_state);
        match self
            .run_sqlite_task(move |conn| {
                // The first check avoids needless worker admission. This
                // second check runs while the connection mutex is held, so a
                // queued raw operation cannot cross a consensus ownership
                // transition while it was waiting.
                if !authority.is_admitted(&admission_state) {
                    return Err(StoreError::CapabilityNotSupported(
                        CONSENSUS_AUTHORITY_REQUIRED.into(),
                    ));
                }
                operation(conn)
            })
            .await
        {
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
        if !SqliteWorkAuthority::Standalone.is_admitted(&self.admission_state) {
            return Err(LeaseError::Backend(CONSENSUS_AUTHORITY_REQUIRED.into()));
        }
        let admission_state = Arc::clone(&self.admission_state);
        match self
            .run_sqlite_task(move |conn| {
                if !SqliteWorkAuthority::Standalone.is_admitted(&admission_state) {
                    return Err(LeaseError::Backend(CONSENSUS_AUTHORITY_REQUIRED.into()));
                }
                operation(conn)
            })
            .await
        {
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

    /// Enter the one consensus-owned schema/state admission boundary while the
    /// caller holds this backend's connection mutex. The prior logical state is
    /// returned so a pre-commit rejection can remain pending or standalone as
    /// appropriate without ever opening a raw authority path.
    fn begin_consensus_admission(
        &self,
        conn: &Connection,
        watchers: &mut Vec<ReplicationWatcher>,
    ) -> Result<SqliteAdmissionState, StoreError> {
        let prior = SqliteAdmissionState::load(&self.admission_state);
        if !matches!(
            prior,
            SqliteAdmissionState::StandaloneReady | SqliteAdmissionState::ConsensusPending
        ) {
            return Err(StoreError::BackendUnavailable(
                "session consensus admission is unavailable".into(),
            ));
        }
        // Fence every raw clone before the fallible physical-lock transition.
        // If SQLite changes the connection mode and a later verification
        // fails, no public standalone operation may resume on an ambiguously
        // retained connection.
        self.admission_state.store(
            SqliteAdmissionState::ConsensusInitializing as u8,
            Ordering::Release,
        );
        // The caller holds the raw watcher registry before the connection
        // mutex. Dropping its senders at the same fence prevents a standalone
        // stream captured before admission from observing consensus applies.
        watchers.clear();
        if self.is_file_backed() {
            let transition = if prior == SqliteAdmissionState::ConsensusPending {
                verify_sqlite_locking_mode(conn, "exclusive")
            } else {
                retain_sqlite_exclusive_locking_mode(conn)
            };
            if let Err(error) = transition {
                let released = release_sqlite_exclusive_locking_mode(conn).is_ok();
                let next = if prior == SqliteAdmissionState::StandaloneReady && released {
                    SqliteAdmissionState::StandaloneReady
                } else {
                    SqliteAdmissionState::FailedClosed
                };
                self.admission_state.store(next as u8, Ordering::Release);
                return Err(error);
            }
        }
        Ok(prior)
    }

    /// Finish consensus initialization before releasing the connection mutex.
    /// A committed image receives the verified WAL profile and lock-release
    /// boundary; a rejected image receives no persistent PRAGMA transition.
    fn finish_consensus_admission(
        &self,
        conn: &Connection,
        prior: SqliteAdmissionState,
        committed: bool,
    ) -> Result<(), StoreError> {
        let retain_pending = !committed && prior == SqliteAdmissionState::ConsensusPending;
        let result = if self.is_file_backed() {
            if committed {
                apply_file_pragma_profile_and_release(conn)
            } else if retain_pending {
                verify_sqlite_locking_mode(conn, "exclusive")
            } else {
                release_sqlite_exclusive_locking_mode(conn)
            }
        } else {
            Ok(())
        };
        let next = if committed && result.is_ok() {
            SqliteAdmissionState::ConsensusReady
        } else if !committed && result.is_ok() {
            prior
        } else {
            SqliteAdmissionState::FailedClosed
        };
        self.admission_state.store(next as u8, Ordering::Release);
        result
    }

    /// Capabilities consumed by the consensus adapter that owns this backend.
    pub(crate) const fn consensus_capabilities(&self) -> BackendCapabilities {
        let mut capabilities = self.caps;
        capabilities.max_value_bytes = SQLITE_CONSENSUS_MAX_VALUE_BYTES;
        capabilities
    }

    /// Direct consensus membership operations are permitted only after the
    /// consensus initializer commits its admission boundary.
    pub(super) fn consensus_admission_is_ready(&self) -> bool {
        SqliteWorkAuthority::Consensus.is_admitted(&self.admission_state)
    }

    /// Classify the logical boundary for the deny-only provisional-candidate
    /// cancellation probe. A standalone backend is only a candidate here: the
    /// caller must still prove its exact schema and empty authority rowsets
    /// while holding the connection mutex before treating it as pristine.
    pub(super) fn consensus_provisional_probe_admission(
        &self,
    ) -> Option<SqliteProvisionalProbeAdmission> {
        match SqliteAdmissionState::load(&self.admission_state) {
            SqliteAdmissionState::StandaloneReady => {
                Some(SqliteProvisionalProbeAdmission::PristineStandalone)
            }
            SqliteAdmissionState::ConsensusPending | SqliteAdmissionState::ConsensusReady => {
                Some(SqliteProvisionalProbeAdmission::ConsensusOwned)
            }
            SqliteAdmissionState::ConsensusInitializing | SqliteAdmissionState::FailedClosed => {
                None
            }
        }
    }

    /// Whether consensus state is backed by a filesystem database.
    ///
    /// Fixed durable quorums reject ephemeral in-memory stores. This is a
    /// durability-shape check, not a claim about physical failure domains or
    /// concrete volume identity.
    pub(crate) const fn is_file_backed(&self) -> bool {
        self.database_path.is_some()
    }

    /// Synchronously test a fixed-quorum authority record without waiting for
    /// a concurrent SQLite operation. Callers must treat lock contention or a
    /// malformed durable record as revoked authority.
    pub(crate) fn fixed_quorum_authority_is_exact_now(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        expected_members: &std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
        expected_bindings: &std::collections::BTreeMap<
            crate::consensus::SessionConsensusNodeId,
            crate::consensus::SessionTopologyMemberBinding,
        >,
        expected_placement_policy: crate::readiness::PlacementResiliencePolicy,
    ) -> bool {
        if !SqliteWorkAuthority::Consensus.is_admitted(&self.admission_state) {
            return false;
        }
        self.conn.try_lock().is_ok_and(|conn| {
            SqliteWorkAuthority::Consensus.is_admitted(&self.admission_state)
                && consensus::fixed_quorum_authority_is_exact_sync(
                    &conn,
                    identity,
                    expected_members,
                    expected_bindings,
                    expected_placement_policy,
                    false,
                )
                .unwrap_or(false)
        })
    }

    /// Read the immutable fixed-quorum authority record under the backend
    /// lock. Storage failure is intentionally indistinguishable from a
    /// revoked authority to inbound engine traffic.
    pub(crate) async fn fixed_quorum_authority_record_is_exact(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        expected_members: &std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
        expected_bindings: &std::collections::BTreeMap<
            crate::consensus::SessionConsensusNodeId,
            crate::consensus::SessionTopologyMemberBinding,
        >,
        expected_placement_policy: crate::readiness::PlacementResiliencePolicy,
        allow_pristine_membership: bool,
    ) -> bool {
        if !SqliteWorkAuthority::Consensus.is_admitted(&self.admission_state) {
            return false;
        }
        let conn = self.conn.lock().await;
        if !SqliteWorkAuthority::Consensus.is_admitted(&self.admission_state) {
            return false;
        }
        consensus::fixed_quorum_authority_is_exact_sync(
            &conn,
            identity,
            expected_members,
            expected_bindings,
            expected_placement_policy,
            allow_pristine_membership,
        )
        .unwrap_or(false)
    }

    /// Read the last committed state-machine logical time after a caller-owned
    /// Openraft linearizable barrier. This path is read-only and allocates no
    /// sequencing authority.
    pub(crate) async fn consensus_logical_time(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
    ) -> Result<Option<opc_types::Timestamp>, StoreError> {
        self.run_consensus_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::logical_time_sync(conn, identity).map_err(|_| {
                StoreError::BackendUnavailable(
                    "session consensus logical time is unavailable".into(),
                )
            })
        })
        .await
    }

    /// Return whether this replica has applied the replicated command-
    /// admission cutover. A `true` value is monotonic durable evidence; a
    /// stale `false` merely causes a safe fixed-request-ID marker retry.
    pub(crate) async fn consensus_command_admission_cutover_committed(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
    ) -> Result<bool, StoreError> {
        self.run_consensus_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::command_admission_cutover_committed_sync(conn, identity).map_err(|_| {
                StoreError::BackendUnavailable(
                    "session consensus command admission state is unavailable".into(),
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
        self.run_consensus_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let result = ops::get_sync(&tx, &key, logical_time)?;
            if let Some(record) = result.as_ref() {
                validate_consensus_record(record)?;
            }
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
        self.run_restore_scan(
            request,
            logical_time,
            deadline,
            RestoreScanValidationProfile::Consensus,
        )
        .await
    }

    async fn run_restore_scan(
        &self,
        request: RestoreScanRequest,
        logical_time: opc_types::Timestamp,
        deadline: tokio::time::Instant,
        profile: RestoreScanValidationProfile,
    ) -> Result<RestoreScanPage, StoreError> {
        let authority = if profile.is_standalone() {
            SqliteWorkAuthority::Standalone
        } else {
            SqliteWorkAuthority::Consensus
        };
        if !authority.is_admitted(&self.admission_state) {
            return Err(StoreError::CapabilityNotSupported(
                CONSENSUS_AUTHORITY_REQUIRED.into(),
            ));
        }
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
        // Admission may have changed while this scan waited for its bounded
        // worker/connection slots. Holding the connection mutex makes this
        // second check the final ownership boundary for the whole scan.
        if !authority.is_admitted(&self.admission_state) {
            return Err(StoreError::CapabilityNotSupported(
                CONSENSUS_AUTHORITY_REQUIRED.into(),
            ));
        }
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
            let tx = if profile.is_standalone() {
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
                profile,
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
        self.run_consensus_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
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
        #[cfg(test)]
        if self
            .consensus_operator_recovery_failure
            .load(Ordering::Acquire)
        {
            return Err(StoreError::BackendUnavailable(
                "injected session operator recovery check failure".into(),
            ));
        }
        let database_path = self.database_path.clone();
        self.run_consensus_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
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

    #[cfg(test)]
    pub(crate) fn inject_consensus_operator_recovery_failure(&self, enabled: bool) {
        self.consensus_operator_recovery_failure
            .store(enabled, Ordering::Release);
    }

    pub(crate) async fn consensus_operator_recovery_committed(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        recovery_epoch: u64,
        plan_digest: [u8; 32],
    ) -> Result<bool, StoreError> {
        self.run_consensus_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
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
        self.run_consensus_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
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
                       entry_json,
                       timestamp
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
                            row.get::<_, String>(3)?,
                        ))
                    },
                )
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let mut result = Vec::new();
            for item in entries {
                let (stored_sequence, stored_tx_id, json, timestamp) = item.map_err(|_| {
                    StoreError::BackendUnavailable("session store read failed".into())
                })?;
                let entry = replication::hydrate_replication_entry(
                    stored_sequence,
                    stored_tx_id,
                    &json,
                    &timestamp,
                )
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
                consensus::validate_sealed_replication_op(&entry.op).map_err(|_| {
                    StoreError::BackendUnavailable("session store read failed".into())
                })?;
                result.push(entry);
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

    /// Subscribe an authenticated consumer to redacted committed changes.
    ///
    /// The raw replication backlog is projected while the ordinary watch
    /// registration lock is held, which closes the capture/register race.
    /// Live consumers then receive only compact projection envelopes through
    /// their own byte-bounded registry; no raw replay entry is cloned per
    /// consumer connection.
    pub(crate) async fn consensus_consumer_watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<crate::SessionConsumerChange, StoreError>>,
        StoreError,
    > {
        let cursor = ReplicationWatchCursor::new(start_sequence);
        // The ordinary watcher mutex serializes raw append notification with
        // backlog capture. Keep it while adding the projected subscriber so a
        // committed entry can land in neither source.
        let _raw_watchers = self.watchers.lock().await;
        let existing = self
            .consensus_get_replication_log(
                cursor.first_sequence(),
                watch_backlog_query_limit(cursor),
            )
            .await?;
        let (stream, watcher) = prepare_consumer_watch_registration(cursor, existing)?;
        let mut consumer_watchers = self.consumer_watchers.lock().await;
        consumer_watchers.retain(|watcher| !watcher.is_closed());
        if let Some(watcher) = watcher {
            consumer_watchers.push(watcher);
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

#[cfg(test)]
#[test]
fn consensus_value_cap_stays_below_unexpanded_transport_contract() {
    let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite backend");
    assert_eq!(
        backend.consensus_capabilities().max_value_bytes,
        SQLITE_CONSENSUS_MAX_VALUE_BYTES
    );
    assert!(backend.consensus_capabilities().max_value_bytes < SQLITE_SESSION_MAX_VALUE_BYTES);
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
        if !SqliteWorkAuthority::Standalone.is_admitted(&self.admission_state) {
            let rejected = ops
                .into_iter()
                .map(|op| {
                    let error =
                        || StoreError::CapabilityNotSupported(CONSENSUS_AUTHORITY_REQUIRED.into());
                    match op {
                        SessionOp::Get { .. } => SessionOpResult::Get(Err(error())),
                        SessionOp::CompareAndSet(_) => SessionOpResult::CompareAndSet(Err(error())),
                        SessionOp::DeleteFenced { .. } => {
                            SessionOpResult::DeleteFenced(Err(error()))
                        }
                        SessionOp::RefreshTtl { .. } => SessionOpResult::RefreshTtl(Err(error())),
                    }
                })
                .collect();
            return Ok(rejected);
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
        self.run_restore_scan(
            request,
            now,
            deadline,
            RestoreScanValidationProfile::Standalone,
        )
        .await
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
                       entry_json,
                       timestamp
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
                                row.get::<_, String>(3)?,
                            ))
                        },
                    )
                    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

                let mut result = Vec::new();
                for item in entries {
                    let (stored_sequence, stored_tx_id, json, timestamp) =
                        item.map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                    result.push(replication::hydrate_replication_entry(
                        stored_sequence,
                        stored_tx_id,
                        &json,
                        &timestamp,
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
        replication::validate_replication_payloads(&entry.op, self.caps.max_value_bytes)?;
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
        for entry in &entries {
            replication::validate_replication_payloads(&entry.op, self.caps.max_value_bytes)?;
        }
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
        // The watcher registry and consensus initializer share this mutex.
        // Recheck while it remains held so a registration that waited behind
        // the consensus fence cannot become a raw authority escape.
        if !SqliteWorkAuthority::Standalone.is_admitted(&self.admission_state) {
            return Err(StoreError::CapabilityNotSupported(
                CONSENSUS_AUTHORITY_REQUIRED.into(),
            ));
        }
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
        backend::{ReplicationOp, ReplicationTxId},
        model::{FenceToken, Generation, SessionKeyType, StateClass, StateType},
        record::EncryptedSessionPayload,
    };
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    #[test]
    fn reopening_incomplete_file_does_not_bootstrap_authority_tables() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("incomplete.sqlite");
        let conn = Connection::open(&path).expect("pre-existing database");
        conn.execute_batch("CREATE TABLE unrelated_state (value INTEGER);")
            .expect("seed unrelated table");
        let journal_mode_before: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("read original journal mode");
        drop(conn);
        let bytes_before = std::fs::read(&path).expect("read original database image");

        assert!(SqliteSessionBackend::open(&path).is_err());
        assert_eq!(
            std::fs::read(&path).expect("read rejected database image"),
            bytes_before,
            "rejected admission must not mutate the database image"
        );
        let wal_path = PathBuf::from(format!("{}-wal", path.display()));
        let shm_path = PathBuf::from(format!("{}-shm", path.display()));
        assert!(!wal_path.exists(), "rejected admission must not create WAL");
        assert!(!shm_path.exists(), "rejected admission must not create SHM");

        let conn = Connection::open(&path).expect("inspect database");
        let journal_mode_after: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("read retained journal mode");
        assert_eq!(journal_mode_after, journal_mode_before);
        let tables = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .expect("list tables")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query tables")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect tables");
        assert_eq!(tables, vec!["unrelated_state"]);
    }

    #[test]
    fn reopening_invalid_complete_delete_image_preserves_bytes_and_journal_mode() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("invalid-state.sqlite");
        drop(SqliteSessionBackend::open(&path).expect("create complete database"));
        let conn = Connection::open(&path).expect("open invalid-state fixture");
        conn.execute_batch(
            r#"
            PRAGMA ignore_check_constraints = ON;
            UPDATE restore_scan_state
               SET cursor_key = zeroblob(32)
             WHERE singleton = 1;
            "#,
        )
        .expect("install invalid persisted restore key");
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
            .expect("return invalid fixture to rollback journal mode");
        assert!(journal_mode.eq_ignore_ascii_case("delete"));
        drop(conn);
        let bytes_before = std::fs::read(&path).expect("read invalid database image");

        assert!(SqliteSessionBackend::open(&path).is_err());
        assert_eq!(
            std::fs::read(&path).expect("read rejected invalid image"),
            bytes_before,
            "full-state rejection must not mutate the database image"
        );
        assert!(!PathBuf::from(format!("{}-wal", path.display())).exists());
        assert!(!PathBuf::from(format!("{}-shm", path.display())).exists());
        let conn = Connection::open(&path).expect("inspect rejected invalid image");
        let journal_mode_after: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("read retained journal mode");
        assert!(journal_mode_after.eq_ignore_ascii_case("delete"));
    }

    #[test]
    fn preexisting_zero_length_file_is_not_bootstrapped() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("empty.sqlite");
        File::create(&path).expect("create pre-existing empty file");

        assert!(SqliteSessionBackend::open(&path).is_err());
        assert_eq!(
            std::fs::metadata(&path).expect("empty file metadata").len(),
            0
        );
        assert!(!PathBuf::from(format!("{}-wal", path.display())).exists());
        assert!(!PathBuf::from(format!("{}-shm", path.display())).exists());
    }

    fn set_restore_revision_and_journal(
        path: &std::path::Path,
        revision: i64,
        initially_wal: bool,
    ) {
        let conn = Connection::open(path).expect("open revision fixture");
        conn.execute(
            "UPDATE restore_scan_state SET revision = ?1 WHERE singleton = 1",
            [revision],
        )
        .expect("set distinctive restore revision");
        let pragma = if initially_wal {
            "PRAGMA journal_mode = WAL"
        } else {
            "PRAGMA journal_mode = DELETE"
        };
        let journal_mode: String = conn
            .query_row(pragma, [], |row| row.get(0))
            .expect("select fixture journal mode");
        let expected = if initially_wal { "wal" } else { "delete" };
        assert!(journal_mode.eq_ignore_ascii_case(expected));
    }

    #[test]
    fn newly_created_open_retains_guardian_through_sqlite_open() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("new.sqlite");
        let mut observed_open_guardian = false;
        let backend = SqliteSessionBackend::open_with_admission_hook(&path, |stage, guardian| {
            if stage == LocalOpenStage::SqliteConnectionOpened {
                assert!(guardian.metadata().expect("guardian metadata").is_file());
                observed_open_guardian = true;
            }
        })
        .expect("open the atomically claimed file");
        assert!(observed_open_guardian);
        drop(backend);
    }

    #[test]
    fn existing_open_retains_guardian_through_sqlite_open() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("existing.sqlite");
        drop(SqliteSessionBackend::open(&path).expect("create authority database"));
        let mut observed_open_guardian = false;
        let backend = SqliteSessionBackend::open_with_admission_hook(&path, |stage, guardian| {
            if stage == LocalOpenStage::SqliteConnectionOpened {
                assert!(guardian.metadata().expect("guardian metadata").is_file());
                observed_open_guardian = true;
            }
        })
        .expect("reopen the guarded existing file");
        assert!(observed_open_guardian);
        drop(backend);
    }

    #[test]
    fn file_backed_open_rejects_non_regular_database() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("not-a-database");
        std::fs::create_dir(&path).expect("create non-regular target");
        assert!(SqliteSessionBackend::open(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_backed_open_rejects_symlink_database_and_parent() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("database directory");
        let target = directory.path().join("target.sqlite");
        std::fs::write(&target, b"unchanged").expect("create target");
        let alias = directory.path().join("alias.sqlite");
        symlink(&target, &alias).expect("create database symlink");
        assert!(SqliteSessionBackend::open(&alias).is_err());
        assert_eq!(std::fs::read(&target).expect("read target"), b"unchanged");

        let real_parent = directory.path().join("real-parent");
        std::fs::create_dir(&real_parent).expect("create real parent");
        let alias_parent = directory.path().join("alias-parent");
        symlink(&real_parent, &alias_parent).expect("create parent symlink");
        assert!(SqliteSessionBackend::open(alias_parent.join("database.sqlite")).is_err());
        assert!(!real_parent.join("database.sqlite").exists());
    }

    #[cfg(unix)]
    #[test]
    fn file_backed_open_rejects_hardlink_ambiguity() {
        let directory = tempfile::tempdir().expect("database directory");
        let target = directory.path().join("target.sqlite");
        std::fs::write(&target, b"unchanged").expect("create target");
        let alias = directory.path().join("alias.sqlite");
        std::fs::hard_link(&target, &alias).expect("create hardlink alias");
        assert!(SqliteSessionBackend::open(&alias).is_err());
        assert_eq!(std::fs::read(&target).expect("read target"), b"unchanged");
    }

    #[test]
    fn existing_validation_retains_writer_exclusion_through_wal_transition() {
        for initially_wal in [false, true] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join("authority.sqlite");
            drop(SqliteSessionBackend::open(&path).expect("create authority database"));
            set_restore_revision_and_journal(&path, 7, initially_wal);
            let mut competing_writes = Vec::new();

            let opened = SqliteSessionBackend::open_with_admission_hook(
                &path,
                |stage, _guardian| {
                    if matches!(
                        stage,
                        LocalOpenStage::ExistingValidatedBeforePersistentPragma
                            | LocalOpenStage::NormalStagedBeforeWal
                    ) {
                        let writer = Connection::open(&path).expect("open competing connection");
                        writer
                            .busy_timeout(Duration::ZERO)
                            .expect("disable competing busy wait");
                        writer
                            .execute_batch("PRAGMA ignore_check_constraints = ON")
                            .expect("permit invalid cursor fixture");
                        competing_writes.push((
                            stage,
                            writer.execute(
                                "UPDATE restore_scan_state SET cursor_key = zeroblob(32) WHERE singleton = 1",
                                [],
                            ),
                        ));
                    }
                },
            );

            assert_eq!(competing_writes.len(), 2);
            for (stage, competing_write) in competing_writes {
                assert!(
                    matches!(
                        competing_write,
                        Err(rusqlite::Error::SqliteFailure(error, _))
                            if matches!(
                                error.code,
                                rusqlite::ErrorCode::DatabaseBusy
                                    | rusqlite::ErrorCode::DatabaseLocked
                            )
                    ),
                    "the competing writer must remain excluded at {stage:?} (initially_wal={initially_wal})"
                );
            }
            let opened = opened.expect("the protected valid authority image reopens");
            let writer = Connection::open(&path).expect("open writer after admission");
            writer
                .busy_timeout(Duration::ZERO)
                .expect("disable post-admission busy wait");
            assert_eq!(
                writer
                    .execute(
                        "UPDATE restore_scan_state SET revision = 8 WHERE singleton = 1",
                        [],
                    )
                    .expect("writer enters after admission"),
                1
            );
            drop(writer);
            drop(opened);
            let conn = Connection::open(&path).expect("inspect reopened database");
            let cursor_key: Vec<u8> = conn
                .query_row(
                    "SELECT cursor_key FROM restore_scan_state WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("read retained cursor key");
            assert_ne!(cursor_key, vec![0_u8; 32]);
            let revision: i64 = conn
                .query_row(
                    "SELECT revision FROM restore_scan_state WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("read competing revision");
            assert_eq!(revision, 8);
            let journal_mode: String = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .expect("read resulting journal mode");
            assert!(journal_mode.eq_ignore_ascii_case("wal"));
        }
    }

    fn seed_file_backed_authority_fixture(path: &std::path::Path) {
        let backend = SqliteSessionBackend::open(path).expect("new file-backed backend");
        drop(backend);
        let conn = Connection::open(path).expect("seed database");
        conn.execute(
            "INSERT INTO leases (tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at) VALUES ('tenant', 'smf', 'pdu-session', X'6B6579', 1, 1, 'owner-a', 1, 0, '1970-01-01T00:00:00.000000000Z')",
            [],
        )
        .expect("seed lease");
        conn.execute(
            "INSERT INTO key_fences (tenant, nf_kind, key_type, stable_id, fence) VALUES ('tenant', 'smf', 'pdu-session', X'6B6579', 1)",
            [],
        )
        .expect("seed fence");
        conn.execute(
            "UPDATE lease_globals SET val = 2 WHERE key IN ('next_fence', 'next_credential_id')",
            [],
        )
        .expect("seed allocator high-water");
    }

    fn seed_complete_cursor_key_predecessor(path: &std::path::Path) -> (Vec<u8>, i64) {
        seed_file_backed_authority_fixture(path);
        let conn = Connection::open(path).expect("seed predecessor database");
        let key = key(b"key");
        let owner = OwnerId::new("owner-a").expect("owner");
        let fence = FenceToken::new(1);
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(4),
            owner: owner.clone(),
            fence,
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("cursor-migration"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([0x41, 0x42]),
        };
        conn.execute(
            "INSERT INTO session_records (tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, state_type, expires_at, payload, encoding) VALUES ('tenant', 'smf', 'pdu-session', X'6B6579', 4, 'owner-a', 1, 'authoritative-session', 'cursor-migration', NULL, X'4142', 0)",
            [],
        )
        .expect("seed predecessor record");
        let entry = ReplicationEntry {
            sequence: 1,
            tx_id: ReplicationTxId::new("cursor-migration-entry").expect("transaction ID"),
            op: ReplicationOp::CompareAndSet {
                key,
                expected_generation: None,
                credential_id: 1,
                guard_expires_at: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
                new_record: record,
            },
            timestamp: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
        };
        conn.execute(
            "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (1, ?1, ?2, '1970-01-01T00:00:00.000000000Z')",
            params![
                entry.tx_id.as_str(),
                serde_json::to_string(&entry).expect("serialize replication entry")
            ],
        )
        .expect("seed predecessor replication log");
        let epoch: Vec<u8> = conn
            .query_row(
                "SELECT epoch FROM restore_scan_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read predecessor epoch");
        let revision = 7_i64;
        conn.execute_batch(
            r#"
            DROP TABLE restore_scan_state;
            CREATE TABLE restore_scan_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                revision INTEGER NOT NULL CHECK (revision >= 0)
            );
            "#,
        )
        .expect("install exact predecessor restore schema");
        conn.execute(
            "INSERT INTO restore_scan_state (singleton, epoch, revision) VALUES (1, ?1, ?2)",
            params![epoch.as_slice(), revision],
        )
        .expect("seed predecessor restore metadata");
        (epoch, revision)
    }

    #[test]
    fn current_and_predecessor_admission_each_run_one_complete_state_pass() {
        let current_directory = tempfile::tempdir().expect("current database directory");
        let current_path = current_directory.path().join("current.sqlite");
        drop(SqliteSessionBackend::open(&current_path).expect("create current database"));
        let current = Connection::open(&current_path).expect("open current database");
        let current_full_passes = std::cell::Cell::new(0_u8);
        let current_migration_checks = std::cell::Cell::new(0_u8);
        let current_schema = validate_existing_local_schema_with_hooks(
            &current,
            |_| {
                current_migration_checks.set(current_migration_checks.get() + 1);
                Ok(())
            },
            || current_full_passes.set(current_full_passes.get() + 1),
        )
        .expect("validate current database");
        assert_eq!(current_schema, ExistingLocalSchema::Current);
        assert_eq!(current_full_passes.get(), 1);
        assert_eq!(current_migration_checks.get(), 0);

        let predecessor_directory = tempfile::tempdir().expect("predecessor database directory");
        let predecessor_path = predecessor_directory.path().join("predecessor.sqlite");
        seed_complete_cursor_key_predecessor(&predecessor_path);
        let predecessor = Connection::open(&predecessor_path).expect("open predecessor database");
        let predecessor_full_passes = std::cell::Cell::new(0_u8);
        let predecessor_migration_checks = std::cell::Cell::new(0_u8);
        let predecessor_schema = validate_existing_local_schema_with_hooks(
            &predecessor,
            |_| {
                predecessor_migration_checks.set(predecessor_migration_checks.get() + 1);
                Ok(())
            },
            || predecessor_full_passes.set(predecessor_full_passes.get() + 1),
        )
        .expect("validate and migrate predecessor database");
        assert_eq!(
            predecessor_schema,
            ExistingLocalSchema::CursorKeyPredecessor
        );
        assert_eq!(predecessor_full_passes.get(), 1);
        assert_eq!(predecessor_migration_checks.get(), 1);
        assert_eq!(
            classify_existing_local_schema(&predecessor).expect("reclassify migrated database"),
            ExistingLocalSchema::Current
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    struct StandaloneDatabaseEvidence {
        schema: Vec<(String, String, String, Option<String>)>,
        session_records: Vec<Vec<String>>,
        restore_scan_state: Vec<Vec<String>>,
        leases: Vec<Vec<String>>,
        key_fences: Vec<Vec<String>>,
        lease_globals: Vec<Vec<String>>,
        session_replication_log: Vec<Vec<String>>,
    }

    fn quoted_table_rows(conn: &Connection, table: &str, order_by: &str) -> Vec<Vec<String>> {
        let columns = conn
            .prepare("SELECT name FROM pragma_table_xinfo(?1) ORDER BY cid")
            .expect("prepare evidence column query")
            .query_map([table], |row| row.get::<_, String>(0))
            .expect("query evidence columns")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect evidence columns");
        let projections = columns
            .iter()
            .map(|column| format!("quote(\"{}\")", column.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(", ");
        let table = table.replace('"', "\"\"");
        let mut statement = conn
            .prepare(&format!(
                "SELECT {projections} FROM \"{table}\" ORDER BY {order_by}"
            ))
            .expect("prepare evidence query");
        let column_count = statement.column_count();
        statement
            .query_map([], move |row| {
                (0..column_count)
                    .map(|column| row.get::<_, String>(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .expect("query evidence")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect evidence")
    }

    fn standalone_database_evidence(path: &std::path::Path) -> StandaloneDatabaseEvidence {
        let conn = Connection::open(path).expect("inspect standalone database");
        let schema = conn
            .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
            .expect("prepare schema evidence")
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .expect("query schema evidence")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect schema evidence");
        StandaloneDatabaseEvidence {
            schema,
            session_records: quoted_table_rows(
                &conn,
                "session_records",
                "tenant, nf_kind, key_type, stable_id",
            ),
            restore_scan_state: quoted_table_rows(&conn, "restore_scan_state", "singleton"),
            leases: quoted_table_rows(&conn, "leases", "tenant, nf_kind, key_type, stable_id"),
            key_fences: quoted_table_rows(
                &conn,
                "key_fences",
                "tenant, nf_kind, key_type, stable_id",
            ),
            lease_globals: quoted_table_rows(&conn, "lease_globals", "key"),
            session_replication_log: quoted_table_rows(
                &conn,
                "session_replication_log",
                "sequence",
            ),
        }
    }

    fn recreate_restore_scan_state(conn: &Connection, schema: &str, cursor_key: Option<&[u8]>) {
        let (epoch, revision): (Vec<u8>, i64) = conn
            .query_row(
                "SELECT epoch, revision FROM restore_scan_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read restore metadata before fixture replacement");
        conn.execute_batch("DROP TABLE restore_scan_state")
            .expect("drop restore fixture table");
        conn.execute_batch(schema)
            .expect("create replacement restore fixture table");
        if let Some(cursor_key) = cursor_key {
            conn.execute(
                "INSERT INTO restore_scan_state (singleton, epoch, revision, cursor_key) VALUES (1, ?1, ?2, ?3)",
                params![epoch, revision, cursor_key],
            )
            .expect("insert replacement restore metadata");
        } else {
            conn.execute(
                "INSERT INTO restore_scan_state (singleton, epoch, revision) VALUES (1, ?1, ?2)",
                params![epoch, revision],
            )
            .expect("insert replacement restore metadata");
        }
    }

    fn assert_reopen_rejected_without_mutation(path: &std::path::Path, case: &str) {
        let before = standalone_database_evidence(path);
        assert!(
            SqliteSessionBackend::open(path).is_err(),
            "reopen must reject {case}"
        );
        assert_eq!(
            standalone_database_evidence(path),
            before,
            "failed reopen must preserve every schema definition and row for {case}"
        );
    }

    #[test]
    fn reopening_complete_cursor_key_predecessor_migrates_and_restarts() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("predecessor.sqlite");
        let (expected_epoch, expected_revision) = seed_complete_cursor_key_predecessor(&path);
        let predecessor = standalone_database_evidence(&path);

        let migrated = SqliteSessionBackend::open(&path)
            .expect("the exact complete cursor-key predecessor must migrate");
        drop(migrated);

        let migrated_evidence = standalone_database_evidence(&path);
        assert_eq!(
            migrated_evidence.session_records,
            predecessor.session_records
        );
        assert_eq!(migrated_evidence.leases, predecessor.leases);
        assert_eq!(migrated_evidence.key_fences, predecessor.key_fences);
        assert_eq!(migrated_evidence.lease_globals, predecessor.lease_globals);
        assert_eq!(
            migrated_evidence.session_replication_log,
            predecessor.session_replication_log
        );
        let conn = Connection::open(&path).expect("inspect migrated database");
        let (epoch, revision, cursor_key): (Vec<u8>, i64, Vec<u8>) = conn
            .query_row(
                "SELECT epoch, revision, cursor_key FROM restore_scan_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read migrated restore metadata");
        assert_eq!(epoch, expected_epoch);
        assert_eq!(revision, expected_revision);
        assert_eq!(cursor_key.len(), 32);
        assert_ne!(cursor_key, vec![0_u8; 32]);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM session_records", [], |row| row
                .get::<_, i64>(0))
                .expect("count retained records"),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM leases", [], |row| row
                .get::<_, i64>(0))
                .expect("count retained leases"),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM key_fences", [], |row| row
                .get::<_, i64>(0))
                .expect("count retained fences"),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM session_replication_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("count retained log rows"),
            1
        );
        drop(conn);

        let restarted = SqliteSessionBackend::open(&path)
            .expect("migrated database must restart without repair");
        drop(restarted);
        assert_eq!(
            standalone_database_evidence(&path),
            migrated_evidence,
            "restart must accept the reviewed nullable ALTER form without a second migration"
        );
    }

    #[test]
    fn predecessor_migration_rolls_back_on_injected_post_alter_failure() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("predecessor.sqlite");
        seed_complete_cursor_key_predecessor(&path);
        let before = standalone_database_evidence(&path);
        let conn = Connection::open(&path).expect("open predecessor database");

        let error = validate_existing_local_schema_with_migration_hook(&conn, |_| {
            Err(StoreError::BackendUnavailable(
                "injected cursor-key migration failure".into(),
            ))
        })
        .expect_err("injected failure must abort migration");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));
        drop(conn);

        assert_eq!(
            standalone_database_evidence(&path),
            before,
            "ALTER TABLE and cursor publication must roll back together"
        );
    }

    #[test]
    fn malformed_predecessor_authority_rejects_before_migration() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("predecessor.sqlite");
        seed_complete_cursor_key_predecessor(&path);
        let conn = Connection::open(&path).expect("mutate predecessor authority");
        conn.execute("UPDATE leases SET owner = 'owner-b'", [])
            .expect("create record/lease owner mismatch");
        drop(conn);

        assert_reopen_rejected_without_mutation(&path, "malformed predecessor lease authority");
    }

    #[test]
    fn malformed_predecessor_records_and_log_reject_before_migration() {
        for (case, mutation) in [
            (
                "negative persisted record generation",
                "UPDATE session_records SET generation = -1",
            ),
            (
                "noncontiguous replication log",
                "UPDATE session_replication_log SET sequence = 2",
            ),
        ] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join("predecessor.sqlite");
            seed_complete_cursor_key_predecessor(&path);
            let conn = Connection::open(&path).expect("mutate predecessor state");
            conn.execute_batch(mutation)
                .expect("apply malformed persisted-state fixture");
            drop(conn);

            assert_reopen_rejected_without_mutation(&path, case);
        }
    }

    #[test]
    fn unknown_and_hybrid_restore_layouts_reject_without_mutation() {
        for (case, schema, cursor_key) in [
            (
                "wrong predecessor restore DDL",
                r#"
                CREATE TABLE restore_scan_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                    revision INTEGER NOT NULL CHECK (revision >= 0),
                    legacy_marker INTEGER
                )
                "#,
                None,
            ),
            (
                "hybrid fresh/migrated restore DDL",
                r#"
                CREATE TABLE restore_scan_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                    revision INTEGER NOT NULL CHECK (revision >= 0),
                    cursor_key BLOB NOT NULL CHECK (
                        cursor_key IS NULL OR length(cursor_key) = 32
                    )
                )
                "#,
                Some([0x5a_u8; 32].as_slice()),
            ),
        ] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join("predecessor.sqlite");
            seed_complete_cursor_key_predecessor(&path);
            let conn = Connection::open(&path).expect("mutate restore schema");
            recreate_restore_scan_state(&conn, schema, cursor_key);
            drop(conn);

            assert_reopen_rejected_without_mutation(&path, case);
        }
    }

    #[test]
    fn malformed_current_cursor_keys_reject_without_mutation() {
        for (case, mutation) in [
            (
                "NULL cursor key",
                "UPDATE restore_scan_state SET cursor_key = NULL",
            ),
            (
                "zero cursor key",
                "UPDATE restore_scan_state SET cursor_key = zeroblob(32)",
            ),
            (
                "wrong-width cursor key",
                "UPDATE restore_scan_state SET cursor_key = randomblob(31)",
            ),
            (
                "non-BLOB cursor key",
                "UPDATE restore_scan_state SET cursor_key = '01234567890123456789012345678901'",
            ),
        ] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join("current.sqlite");
            seed_complete_cursor_key_predecessor(&path);
            let conn = Connection::open(&path).expect("prepare migrated restore schema");
            ops::initialize_restore_scan_metadata_sync(&conn)
                .expect("install reviewed nullable cursor-key schema");
            conn.execute_batch("PRAGMA ignore_check_constraints = ON")
                .expect("allow malformed cursor fixture");
            conn.execute_batch(mutation)
                .expect("apply malformed cursor fixture");
            drop(conn);

            assert_reopen_rejected_without_mutation(&path, case);
        }
    }

    type AuthoritySchemaEvidence = Vec<(String, String)>;
    type AuthorityTableCounts = Vec<(String, Option<i64>)>;
    type AuthorityLeaseGlobalValues = Vec<(String, i64)>;
    type AuthorityKeyFences = Vec<(Vec<u8>, i64)>;

    fn authority_reopen_evidence(
        path: &std::path::Path,
    ) -> (
        AuthoritySchemaEvidence,
        AuthorityTableCounts,
        AuthorityLeaseGlobalValues,
        AuthorityKeyFences,
    ) {
        let conn = Connection::open(path).expect("inspect database");
        let schema = conn
            .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .expect("list schema")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query schema")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect schema");
        let counts = [
            "session_records",
            "restore_scan_state",
            "leases",
            "key_fences",
            "lease_globals",
            "session_replication_log",
        ]
        .into_iter()
        .map(|table| {
            let exists = schema.iter().any(|(name, _)| name == table);
            let count = exists.then(|| {
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("count authority table")
            });
            (table.to_owned(), count)
        })
        .collect();
        let globals = conn
            .prepare("SELECT key, val FROM lease_globals ORDER BY key")
            .ok()
            .map(|mut statement| {
                statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .expect("query globals")
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .expect("collect globals")
            })
            .unwrap_or_default();
        let fences = conn
            .prepare("SELECT stable_id, fence FROM key_fences ORDER BY stable_id")
            .ok()
            .map(|mut statement| {
                statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .expect("query fences")
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .expect("collect fences")
            })
            .unwrap_or_default();
        (schema, counts, globals, fences)
    }

    #[test]
    fn reopening_existing_files_never_bootstraps_missing_authority_evidence() {
        for (case, mutation) in [
            ("leases", "DROP TABLE leases"),
            ("key-fences", "DROP TABLE key_fences"),
            ("lease-globals", "DROP TABLE lease_globals"),
            (
                "next-fence",
                "DELETE FROM lease_globals WHERE key = 'next_fence'",
            ),
            (
                "next-credential",
                "DELETE FROM lease_globals WHERE key = 'next_credential_id'",
            ),
            ("per-key-fence", "DELETE FROM key_fences"),
            (
                "extra-authority-table",
                "CREATE TABLE unexpected_authority (value INTEGER)",
            ),
            (
                "wildcard-shaped-extra-authority-table",
                "CREATE TABLE sqliteXauthority (value INTEGER)",
            ),
            (
                "extra-authority-row",
                "INSERT INTO lease_globals (key, val) VALUES ('unexpected_allocator', 3)",
            ),
        ] {
            let directory = tempfile::tempdir().expect("database directory");
            let path = directory.path().join("existing.sqlite");
            seed_file_backed_authority_fixture(&path);
            let conn = Connection::open(&path).expect("mutate fixture");
            conn.execute_batch(mutation)
                .expect("apply fixture mutation");
            drop(conn);
            let before = authority_reopen_evidence(&path);

            assert!(
                SqliteSessionBackend::open(&path).is_err(),
                "reopen must reject missing {case} authority evidence"
            );
            assert_eq!(
                authority_reopen_evidence(&path),
                before,
                "failed reopen must not bootstrap or repair {case}"
            );
        }
    }

    #[test]
    fn reopening_valid_existing_standalone_authority_succeeds() {
        let directory = tempfile::tempdir().expect("database directory");
        let path = directory.path().join("existing.sqlite");
        seed_file_backed_authority_fixture(&path);
        SqliteSessionBackend::open(&path).expect("valid existing standalone database reopens");
    }

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
                        RestoreScanValidationProfile::Standalone,
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
mod consensus_readiness_deadline_tests {
    use std::collections::BTreeMap;

    use opc_consensus::{
        derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    };

    use super::*;
    use crate::{
        consensus::ConsensusSessionStore,
        readiness::DurableReadinessState,
        topology::{
            QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
            ReplicaId, ReplicaTlsIdentity, ValidatedQuorumTopology,
        },
    };

    const OPERATION_TIMEOUT: Duration = Duration::from_secs(1);
    const RECOVERY_PREFLIGHT_HOLD: Duration = Duration::from_millis(600);
    const PROBE_ASSERTION_SLACK: Duration = Duration::from_millis(250);

    fn singleton_topology() -> ValidatedQuorumTopology {
        let replica_id = ReplicaId::new("readiness-deadline-singleton").expect("replica ID");
        let descriptor = QuorumReplicaDescriptor::new(
            replica_id.clone(),
            ReplicaEndpoint::new("readiness-deadline.invalid", 7443).expect("endpoint"),
            ReplicaTlsIdentity::new("spiffe://test/session/readiness-deadline")
                .expect("TLS identity"),
            ReplicaFailureDomain::new("readiness-deadline-zone").expect("failure domain"),
            ReplicaBackingIdentity::new("readiness-deadline-disk").expect("backing identity"),
        );
        let cluster_id =
            ConsensusClusterId::new("session-readiness-deadline-tests").expect("cluster ID");
        let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
        let configuration_id =
            derive_configuration_id(cluster_id, epoch, &[descriptor.configuration_fingerprint()]);
        ValidatedQuorumTopology::try_new_consensus_lab_singleton(
            replica_id,
            vec![descriptor],
            ConsensusIdentity::new(cluster_id, configuration_id, epoch),
        )
        .expect("singleton topology")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readiness_recovery_and_barrier_share_one_complete_operation_deadline() {
        let snapshots = tempfile::tempdir().expect("snapshot directory");
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_operation_timeout(
            singleton_topology(),
            backend.clone(),
            snapshots.path(),
            BTreeMap::new(),
            OPERATION_TIMEOUT,
        )
        .await
        .expect("open consensus singleton");
        store
            .initialize_cluster()
            .await
            .expect("initialize consensus singleton");
        assert!(store.probe_durable_readiness().await.is_ready());

        let held_apply = apply_gate
            .acquire_owned()
            .await
            .expect("hold state-machine apply");
        let status_before = store.status();
        let mutation_store = store.clone();
        let mutation = tokio::spawn(async move { mutation_store.max_replication_sequence().await });
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            loop {
                let status = store.status();
                if status.last_log_index.is_some_and(|last| {
                    last > status_before.last_log_index.unwrap_or_default()
                        && status.applied_index.is_none_or(|applied| applied < last)
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("mutation reaches the log while apply is held");

        let held_connection = backend.conn.lock().await;
        let probe_store = store.clone();
        let probe_started = tokio::time::Instant::now();
        let probe = tokio::spawn(async move { probe_store.probe_durable_readiness().await });
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            while backend.operation_workers.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("readiness recovery preflight waits on the held SQLite connection");
        tokio::time::sleep(RECOVERY_PREFLIGHT_HOLD).await;
        drop(held_connection);

        let report = tokio::time::timeout_at(
            probe_started + OPERATION_TIMEOUT + PROBE_ASSERTION_SLACK,
            probe,
        )
        .await
        .expect("readiness probe must not receive a second operation budget")
        .expect("readiness probe task");
        assert_eq!(report.state(), DurableReadinessState::NoQuorum);
        assert!(probe_started.elapsed() >= RECOVERY_PREFLIGHT_HOLD);

        drop(held_apply);
        let _ = tokio::time::timeout(Duration::from_secs(2), mutation)
            .await
            .expect("mutation task settles after apply resumes")
            .expect("mutation task");
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
                    RestoreScanValidationProfile::Standalone,
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
                RestoreScanValidationProfile::Standalone,
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
