//! Explicit provisioning and reopening of retained configuration authority.
//!
//! The SDK owns the admission record and lock beside the database. Neither is
//! a caller-created marker or an independent configuration writer. Local
//! authentication does not prove freshness against coherent storage rollback.

use std::fmt;
#[cfg(test)]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", all(test, unix)))]
use hmac::{Hmac, KeyInit, Mac};
#[cfg(any(target_os = "linux", all(test, unix)))]
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(unix)]
use crate::local_sqlite::FileAdmission;
use crate::local_sqlite::{completion_path, lock_path};
#[cfg(target_os = "linux")]
use crate::local_sqlite::{
    file_identity, identity_for_path, open_sqlite, reject_symlink_components,
};
#[cfg(any(target_os = "linux", all(test, unix)))]
use crate::local_sqlite::{open_file, AdmissionFileLock};
use crate::{AuditKey, ConfigConsensusTopology, SqliteBackend};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

mod operation;
mod provisioning;
pub use operation::{RetainedConfigOpen, RetainedConfigOpenRetirement};
pub use provisioning::RetainedConfigProvisionRequest;

#[cfg(any(target_os = "linux", all(test, unix)))]
const RECORD_MAGIC: &[u8; 8] = b"OPCRET01";
#[cfg(any(target_os = "linux", all(test, unix)))]
const RECORD_DOMAIN: &[u8] = b"openpacketcore/config-retained-admission/v1\0";
const BINDING_DOMAIN: &[u8] = b"openpacketcore/config-retained-scope/v1\0";
#[cfg(any(target_os = "linux", all(test, unix)))]
const RECORD_BYTES: usize = 8 + 32 + 32 + 1 + 6 * 8 + 32;
const MAX_VALIDATION_BYTES: u64 = 64 * 1024 * 1024 * 1024;
#[cfg(target_os = "linux")]
const COPY_BUFFER_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const BINDING_SCHEMA: &str = "CREATE TABLE consensus_retained_binding (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), record BLOB NOT NULL CHECK(length(record) = 153))";
// Bounds concurrent startup work, including cancelled blocking operations.
static ADMISSION_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

#[derive(Clone, Copy)]
enum OpenIntent {
    NewAuthority,
    RepairMember,
    ResumeAuthority,
    ResumeRepair,
    Reopen,
    Transaction(RetainedConfigProvisionRequest, provisioning::OpenMode),
}

/// Exact caller-admitted configuration authority and local storage/key scope.
///
/// The backing and key-scope inputs must come from the caller's independently
/// admitted storage and credential authorities, not from the database being
/// opened. They are opaque digests, never paths, credentials, or diagnostic IDs.
#[derive(Clone, PartialEq, Eq)]
pub struct RetainedConfigBinding {
    topology: ConfigConsensusTopology,
    backing_identity: [u8; 32],
    key_scope: [u8; 32],
}

impl RetainedConfigBinding {
    /// Bind exact topology, retained backing identity, and approved key scope.
    pub fn new(
        topology: ConfigConsensusTopology,
        backing_identity: [u8; 32],
        key_scope: [u8; 32],
    ) -> Result<Self, RetainedConfigError> {
        if backing_identity == [0; 32] || key_scope == [0; 32] {
            return Err(RetainedConfigError::InvalidRequest);
        }
        Ok(Self {
            topology,
            backing_identity,
            key_scope,
        })
    }

    pub(crate) fn topology(&self) -> &ConfigConsensusTopology {
        &self.topology
    }

    fn digest(&self, key: &AuditKey) -> [u8; 32] {
        let identity = self.topology.identity();
        let mut digest = Sha256::new();
        digest.update(BINDING_DOMAIN);
        digest.update(identity.cluster_id().as_bytes());
        digest.update(identity.configuration_id().as_bytes());
        digest.update(identity.configuration_epoch().get().to_be_bytes());
        digest.update(self.topology.local_node_id().get().to_be_bytes());
        digest.update((self.topology.members().len() as u64).to_be_bytes());
        for member in self.topology.members() {
            digest.update(member.get().to_be_bytes());
        }
        digest.update(self.backing_identity);
        digest.update(self.key_scope);
        digest.update(key.epoch().to_be_bytes());
        digest.update(key.fingerprint());
        digest.finalize().into()
    }
}

impl fmt::Debug for RetainedConfigBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetainedConfigBinding(<redacted>)")
    }
}

/// Explicit caller-selected durability profile; reopening never selects one.
#[derive(Clone, Copy, Debug)]
pub enum RetainedConfigDurability {
    /// Require the SDK's durable filesystem preflight and reserved free space.
    Durable {
        /// Minimum free bytes required by the admitted storage plan.
        min_free_bytes: u64,
    },
    /// Explicitly waive durable-filesystem qualification, without waiving
    /// identity, authentication, locking, or provision/reopen separation.
    Ephemeral,
}

/// Bounded retained-store admission options, with no automatic create fallback.
#[derive(Clone)]
// Keep the same public options on unsupported targets; only Linux executes them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct RetainedConfigOptions {
    path: PathBuf,
    binding: RetainedConfigBinding,
    durability: RetainedConfigDurability,
    max_validation_bytes: u64,
    operation_timeout: Duration,
}

impl RetainedConfigOptions {
    /// Select storage, authority, durability and explicit admission bounds.
    ///
    /// The byte budget covers the database and all recovery journals copied
    /// into SDK-owned private validation storage before ordinary reopening.
    pub fn new(
        path: impl Into<PathBuf>,
        binding: RetainedConfigBinding,
        durability: RetainedConfigDurability,
        max_validation_bytes: u64,
        operation_timeout: Duration,
    ) -> Result<Self, RetainedConfigError> {
        let path = path.into();
        if !path.is_absolute()
            || path.file_name().is_none()
            || max_validation_bytes == 0
            || max_validation_bytes > MAX_VALIDATION_BYTES
            || operation_timeout.is_zero()
            || operation_timeout > Duration::from_secs(3600)
        {
            return Err(RetainedConfigError::InvalidRequest);
        }
        Ok(Self {
            path,
            binding,
            durability,
            max_validation_bytes,
            operation_timeout,
        })
    }
}

impl fmt::Debug for RetainedConfigOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetainedConfigOptions(<redacted>)")
    }
}

/// Closed value-free retained-store admission outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RetainedConfigError {
    /// Invalid or unsupported caller-supplied scope, path or bounds.
    #[error("invalid retained configuration storage request")]
    InvalidRequest,
    /// This platform does not implement the required file-identity/lock profile.
    #[error("retained configuration storage profile is unsupported")]
    Unsupported,
    /// Provisioning found existing storage and did not adopt or overwrite it.
    #[error("retained configuration storage already exists")]
    AlreadyExists,
    /// Ordinary reopening found missing or incomplete established storage.
    #[error("retained configuration storage requires explicit recovery")]
    RecoveryRequired,
    /// Another admitted opener owns this exact retained store.
    #[error("retained configuration storage is already open")]
    InUse,
    /// Stored identity, key, schema or authenticated state did not match.
    #[error("retained configuration storage validation failed")]
    Rejected,
    /// Admission exceeded its byte, time or filesystem resource bound.
    #[error("retained configuration storage admission bound exceeded")]
    AdmissionBound,
    /// No retained-state mutation was authorized before this I/O failure.
    #[error("retained configuration storage is unavailable")]
    Unavailable,
    /// Provisioning or validated WAL recovery may have changed durable state.
    /// No capability is returned; retry only through explicit lifecycle readback.
    #[error("retained configuration storage admission outcome is indeterminate")]
    Indeterminate,
}

struct AdmissionWork {
    cancelled: AtomicBool,
    mutated: AtomicBool,
    deadline: Instant,
    #[cfg(test)]
    hook: Option<AdmissionTestHook>,
    #[cfg(test)]
    lock_hook: Option<AdmissionLockTestHook>,
    #[cfg(test)]
    completion_hook: Option<AdmissionCompletionTestHook>,
    #[cfg(test)]
    provision_fault: Option<AdmissionProvisionFault>,
}

#[cfg(test)]
type AdmissionTestHook = Arc<dyn Fn(&AdmissionWork, &str) + Send + Sync>;

#[cfg(test)]
type AdmissionLockTestHook = Arc<dyn Fn(&File) + Send + Sync>;

#[cfg(test)]
type AdmissionProvisionFault = Arc<dyn Fn(&str) -> bool + Send + Sync>;

#[cfg(test)]
type AdmissionCompletionTestHook = Arc<dyn Fn(&SqliteBackend) + Send + Sync>;

impl AdmissionWork {
    #[cfg(test)]
    fn stage(&self, name: &str) {
        if let Some(hook) = &self.hook {
            hook(self, name);
        }
    }

    fn check(&self) -> Result<(), RetainedConfigError> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            Err(RetainedConfigError::AdmissionBound)
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn mutation(&self) -> Result<(), RetainedConfigError> {
        self.check()?;
        self.mutated.store(true, Ordering::Release);
        Ok(())
    }
}

struct CancelOnDrop(Arc<AdmissionWork>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}

/// Returns only a denial predicate. Presence is never admission authority.
pub(crate) fn requires_retained_lifecycle(path: &Path) -> bool {
    std::fs::symlink_metadata(lock_path(path)).is_ok()
        || std::fs::symlink_metadata(completion_path(path)).is_ok()
        || std::fs::symlink_metadata(obsolete_intent_path(path)).is_ok()
}

// An earlier-format intent is only a denial signal, never recovery authority.
fn obsolete_intent_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".opc-retained.intent");
    PathBuf::from(name)
}

impl SqliteBackend {
    /// Explicitly provision conclusively new retained configuration storage.
    ///
    /// This is an operator-authorized provisioning operation, never a restart
    /// fallback. Existing or interrupted artifacts are preserved and rejected.
    /// Resume an interrupted request with `begin_resume_config_authority` and
    /// the same authorization; invoking provision again never overwrites it.
    pub async fn provision_config_authority(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
    ) -> Result<Self, RetainedConfigError> {
        open_authority(options, audit_key, OpenIntent::NewAuthority).await
    }

    /// Explicitly provision replacement storage for one existing voter.
    ///
    /// The replacement starts without local history and can only recover from
    /// the authenticated existing quorum. Its persisted repair disposition
    /// forbids local genesis, including after reopening. Loss of the complete
    /// quorum therefore requires a separately approved new authority, never
    /// repeated member repair. Existing artifacts are not overwritten. The
    /// consensus store restores a quorum-authorized snapshot before the empty
    /// replacement can vote or answer replication requests under its node ID.
    pub async fn provision_config_member_repair(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
    ) -> Result<Self, RetainedConfigError> {
        open_authority(options, audit_key, OpenIntent::RepairMember).await
    }

    /// Reopen established retained authority without creating or initializing it.
    ///
    /// Scope/authentication/schema validation runs on a bounded private copy so
    /// rejection cannot modify the retained SQLite database or recovery files.
    /// Once validated original WAL recovery starts, an I/O/cancellation failure
    /// is `Indeterminate`, never a claim that no mutation occurred. Coherent
    /// whole-store rollback still requires fresh external authority validation.
    pub async fn reopen_config_authority(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
    ) -> Result<Self, RetainedConfigError> {
        open_authority(options, audit_key, OpenIntent::Reopen).await
    }
}

async fn open_authority(
    options: RetainedConfigOptions,
    audit_key: AuditKey,
    intent: OpenIntent,
) -> Result<SqliteBackend, RetainedConfigError> {
    let mut operation = begin_open_authority(options, audit_key, intent)?;
    operation.wait().await
}

fn begin_open_authority(
    options: RetainedConfigOptions,
    audit_key: AuditKey,
    intent: OpenIntent,
) -> Result<RetainedConfigOpen, RetainedConfigError> {
    let work = Arc::new(AdmissionWork {
        cancelled: AtomicBool::new(false),
        mutated: AtomicBool::new(false),
        deadline: Instant::now()
            .checked_add(options.operation_timeout)
            .ok_or(RetainedConfigError::InvalidRequest)?,
        #[cfg(test)]
        hook: None,
        #[cfg(test)]
        lock_hook: None,
        #[cfg(test)]
        completion_hook: None,
        #[cfg(test)]
        provision_fault: None,
    });
    RetainedConfigOpen::start(options, audit_key, intent, work)
}

fn open_authority_sync(
    options: RetainedConfigOptions,
    audit_key: AuditKey,
    intent: OpenIntent,
    work: &Arc<AdmissionWork>,
) -> Result<SqliteBackend, RetainedConfigError> {
    use provisioning::OpenMode;
    let (request, mode) = match intent {
        OpenIntent::Transaction(request, mode) => (request, mode),
        OpenIntent::NewAuthority | OpenIntent::ResumeAuthority | OpenIntent::Reopen => (
            RetainedConfigProvisionRequest::new_authority(options.binding.digest(&audit_key))?,
            match intent {
                OpenIntent::NewAuthority => OpenMode::Provision,
                OpenIntent::ResumeAuthority => OpenMode::Resume,
                _ => OpenMode::ReopenImplicit,
            },
        ),
        OpenIntent::RepairMember | OpenIntent::ResumeRepair => (
            RetainedConfigProvisionRequest::member_repair(options.binding.digest(&audit_key))?,
            if matches!(intent, OpenIntent::RepairMember) {
                OpenMode::Provision
            } else {
                OpenMode::Resume
            },
        ),
    };
    provisioning::open(options, audit_key, request, mode, work)
}

#[cfg(target_os = "linux")]
fn finish_open(
    options: RetainedConfigOptions,
    audit_key: AuditKey,
    record: [u8; RECORD_BYTES],
    admission: Arc<FileAdmission>,
    work: &Arc<AdmissionWork>,
    caps: crate::PersistCapabilities,
) -> Result<SqliteBackend, RetainedConfigError> {
    let (ephemeral, min_free_bytes) = match options.durability {
        RetainedConfigDurability::Durable { min_free_bytes } => (false, min_free_bytes),
        RetainedConfigDurability::Ephemeral => (true, 0),
    };
    #[cfg(test)]
    work.stage("before_original_open");
    admission.read_back()?;
    work.mutation()?;
    let conn = open_sqlite(&options.path)?;
    crate::schema::apply_pragma_profile(&conn).map_err(|_| RetainedConfigError::Unavailable)?;
    validate_connection(&conn, &options, &record, &audit_key, work)?;
    admission.read_back()?;
    let connection_guard = Arc::clone(&admission);
    conn.authorizer(Some(move |_: rusqlite::hooks::AuthContext<'_>| {
        if connection_guard.read_back().is_ok() {
            rusqlite::hooks::Authorization::Allow
        } else {
            rusqlite::hooks::Authorization::Deny
        }
    }))
    .map_err(|_| RetainedConfigError::Unavailable)?;
    work.check()?;
    Ok(SqliteBackend::from_retained_connection(
        options.path,
        ephemeral,
        min_free_bytes,
        audit_key,
        conn,
        caps,
        options.binding,
        record[72] == 1,
        admission,
    ))
}

#[cfg(unix)]
pub(crate) fn retained_preflight(
    admission: &FileAdmission,
    ephemeral: bool,
    min_free_bytes: u64,
) -> crate::PersistCapabilities {
    // Use held files: the legacy preflight writes a probe file, which a
    // rejected retained reopen must not create or overwrite.
    let dir = admission.path.parent().unwrap_or(Path::new("/"));
    let safe_filesystem = !ephemeral && crate::schema::is_safe_filesystem(dir);
    crate::PersistCapabilities {
        ephemeral_mode: ephemeral,
        storage_path: admission.path.to_string_lossy().into_owned(),
        fsync_available: !ephemeral
            && admission.database.sync_all().is_ok()
            && admission.parent.sync_all().is_ok(),
        locking_compatible: safe_filesystem,
        same_filesystem: admission.identity[0] == admission.identity[4],
        safe_filesystem,
        free_bytes: crate::schema::get_free_bytes(dir).unwrap_or(0),
        min_free_bytes,
        directory_permissions_safe: crate::schema::is_directory_permissions_safe(dir),
        wal_autocheckpoint_pages: 1000,
        journal_mode: "wal".into(),
        synchronous_setting: "extra".into(),
        foreign_keys_on: true,
        wal_mode: true,
    }
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn make_record(
    binding: &RetainedConfigBinding,
    key: &AuditKey,
    identity: [u64; 6],
    nonce: [u8; 32],
    repair_only: bool,
) -> Result<[u8; RECORD_BYTES], RetainedConfigError> {
    let mut record = [0; RECORD_BYTES];
    record[..8].copy_from_slice(RECORD_MAGIC);
    record[8..40].copy_from_slice(&binding.digest(key));
    record[40..72].copy_from_slice(&nonce);
    record[72] = u8::from(repair_only);
    for (i, value) in identity.iter().enumerate() {
        record[73 + i * 8..81 + i * 8].copy_from_slice(&value.to_be_bytes());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| RetainedConfigError::Rejected)?;
    mac.update(RECORD_DOMAIN);
    mac.update(&record[..RECORD_BYTES - 32]);
    record[RECORD_BYTES - 32..].copy_from_slice(&mac.finalize().into_bytes());
    Ok(record)
}

#[cfg(target_os = "linux")]
fn validate_record(
    record: &[u8; RECORD_BYTES],
    binding: &RetainedConfigBinding,
    key: &AuditKey,
) -> Result<(), RetainedConfigError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| RetainedConfigError::Rejected)?;
    mac.update(RECORD_DOMAIN);
    mac.update(&record[..RECORD_BYTES - 32]);
    mac.verify_slice(&record[RECORD_BYTES - 32..])
        .map_err(|_| RetainedConfigError::Rejected)?;
    if &record[..8] != RECORD_MAGIC || record[8..40] != binding.digest(key) || record[72] > 1 {
        return Err(RetainedConfigError::Rejected);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn record_identity(record: &[u8; RECORD_BYTES]) -> Result<[u64; 6], RetainedConfigError> {
    let mut identity = [0; 6];
    for (i, value) in identity.iter_mut().enumerate() {
        *value = u64::from_be_bytes(
            record[73 + i * 8..81 + i * 8]
                .try_into()
                .map_err(|_| RetainedConfigError::Rejected)?,
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn validate_copy(
    options: &RetainedConfigOptions,
    record: &[u8; RECORD_BYTES],
    key: &AuditKey,
    admission: &FileAdmission,
    work: &Arc<AdmissionWork>,
) -> Result<(), RetainedConfigError> {
    let staging = tempfile::Builder::new()
        .prefix("opc-retained-validation-")
        .tempdir()
        .map_err(|_| RetainedConfigError::Unavailable)?;
    let staged_path = staging.path().join("config.sqlite");
    let mut remaining = options.max_validation_bytes;
    let mut buffer = [0; COPY_BUFFER_BYTES];
    for suffix in ["", "-wal", "-journal"] {
        work.check()?;
        let mut source_path = options.path.as_os_str().to_os_string();
        source_path.push(suffix);
        let source_path = PathBuf::from(source_path);
        if !suffix.is_empty() {
            match std::fs::symlink_metadata(&source_path) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(RetainedConfigError::Rejected),
            }
        }
        let mut source = open_file(&source_path, false, false)?;
        let length = source
            .metadata()
            .map_err(|_| RetainedConfigError::Unavailable)?
            .len();
        if length > remaining || (suffix.is_empty() && length == 0) {
            return Err(RetainedConfigError::AdmissionBound);
        }
        remaining -= length;
        let mut destination = staged_path.as_os_str().to_os_string();
        destination.push(suffix);
        let mut destination = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(PathBuf::from(destination))
            .map_err(|_| RetainedConfigError::Unavailable)?;
        let mut copied = 0u64;
        loop {
            work.check()?;
            let count = source
                .read(&mut buffer)
                .map_err(|_| RetainedConfigError::Unavailable)?;
            if count == 0 {
                break;
            }
            copied = copied
                .checked_add(count as u64)
                .ok_or(RetainedConfigError::AdmissionBound)?;
            if copied > length {
                return Err(RetainedConfigError::Rejected);
            }
            destination
                .write_all(&buffer[..count])
                .map_err(|_| RetainedConfigError::Unavailable)?;
        }
        if copied != length {
            return Err(RetainedConfigError::Rejected);
        }
    }
    admission.read_back()?;
    let conn = open_sqlite(&staged_path)?;
    validate_connection(&conn, options, record, key, work)?;
    admission.read_back()
}

#[cfg(target_os = "linux")]
fn validate_connection(
    conn: &Connection,
    options: &RetainedConfigOptions,
    record: &[u8; RECORD_BYTES],
    key: &AuditKey,
    work: &Arc<AdmissionWork>,
) -> Result<(), RetainedConfigError> {
    let progress = Arc::clone(work);
    conn.progress_handler(1000, Some(move || progress.check().is_err()))
        .map_err(|_| RetainedConfigError::Unavailable)?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| RetainedConfigError::Rejected)?;
    if integrity != "ok" {
        return Err(RetainedConfigError::Rejected);
    }
    // A digest supplied by the retained database is only a compatibility
    // check. The independent SDK catalog includes the exact replay index.
    crate::schema::validate_retained_base_schema(conn)
        .map_err(|_| RetainedConfigError::Rejected)?;
    let version =
        crate::schema::get_schema_version(conn).map_err(|_| RetainedConfigError::Rejected)?;
    let digest =
        crate::schema::get_schema_digest(conn).map_err(|_| RetainedConfigError::Rejected)?;
    if version.as_deref() != Some(crate::schema::SCHEMA_VERSION)
        || digest
            != Some(
                crate::schema::current_schema_digest(conn)
                    .map_err(|_| RetainedConfigError::Rejected)?,
            )
    {
        return Err(RetainedConfigError::Rejected);
    }
    let schema_matches: bool = conn.query_row(
        "SELECT COUNT(*) = 1 AND MIN(sql) = ?1 FROM sqlite_schema WHERE name GLOB 'consensus_retained_*' OR tbl_name = 'consensus_retained_binding'",
        [BINDING_SCHEMA], |row| row.get(0),
    ).map_err(|_| RetainedConfigError::Rejected)?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM consensus_retained_binding",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RetainedConfigError::Rejected)?;
    if !schema_matches || count != 1 {
        return Err(RetainedConfigError::Rejected);
    }
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT record FROM consensus_retained_binding WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RetainedConfigError::Rejected)?;
    let stored: &[u8; RECORD_BYTES] = stored
        .as_slice()
        .try_into()
        .map_err(|_| RetainedConfigError::Rejected)?;
    validate_record(stored, &options.binding, key)?;
    if record_identity(stored)? != record_identity(record)? || stored != record {
        return Err(RetainedConfigError::Rejected);
    }
    crate::consensus::validate_retained_schema(
        conn,
        options.binding.topology(),
        key,
        work.deadline,
    )
    .map_err(|_| RetainedConfigError::Rejected)?;
    conn.progress_handler(0, None::<fn() -> bool>)
        .map_err(|_| RetainedConfigError::Unavailable)?;
    work.check()
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod provisioning_tests;
