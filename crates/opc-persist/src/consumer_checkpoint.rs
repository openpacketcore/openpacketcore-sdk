//! Non-voting, non-authoritative configuration-consumer storage.
//!
//! This is a sealed local checkpoint, not a `ConfigStore`, authoring log or
//! consensus member. Callers must revalidate remote freshness and runtime effects.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opc_crypto::{decrypt_envelope, encrypt_envelope};
use opc_key::{ConsumerCheckpointAad, EnvelopeAad, KeyProvider};
use opc_types::{SchemaDigest, SpiffeId, TenantId};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::backend::BackendConnection;
use crate::{ConfigConsensusIdentity, RetainedConfigDurability, RetainedConfigError};

#[cfg(unix)]
use crate::local_sqlite::{
    file_identity, identity_for_path, lock_path, open_file, open_sqlite, reject_symlink_components,
    AdmissionFileLock, FileAdmission,
};
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MAGIC: &[u8; 8] = b"OPCCKP01";
const SCHEMA: &str = "CREATE TABLE consumer_checkpoint (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), generation INTEGER NOT NULL CHECK(generation > 0), envelope BLOB NOT NULL CHECK(length(envelope) > 0))";
const ENVELOPE_OVERHEAD_LIMIT: usize = 16 * 1024;
const SQLITE_PAGE_BYTES: u64 = 4096;
const STORAGE_RESERVE_BYTES: u64 = 65536;
static IO_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Exact externally configured consumer, schema, authority epoch and backing.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsumerCheckpointBinding {
    scope: ConfigConsensusIdentity,
    schema: SchemaDigest,
    consumer: SpiffeId,
    tenant: TenantId,
    backing: [u8; 32],
}

impl ConsumerCheckpointBinding {
    /// Bind storage to independently admitted identities. The nonzero backing
    /// digest must be supplied by storage authority, never learned from this file.
    pub fn new(
        scope: ConfigConsensusIdentity,
        schema: SchemaDigest,
        consumer: SpiffeId,
        tenant: TenantId,
        backing: [u8; 32],
    ) -> Result<Self, ConsumerCheckpointError> {
        if backing == [0; 32] {
            return Err(ConsumerCheckpointError::InvalidRequest);
        }
        Ok(Self {
            scope,
            schema,
            consumer,
            tenant,
            backing,
        })
    }

    /// Compare against the actual authenticated watch binding before transport
    /// recovery. This check does not authenticate a caller-constructed snapshot.
    pub fn matches_consumer(
        &self,
        scope: &ConfigConsensusIdentity,
        schema: SchemaDigest,
        consumer: &SpiffeId,
    ) -> bool {
        &self.scope == scope && self.schema == schema && &self.consumer == consumer
    }

    fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/config-consumer-binding/v1\0");
        hash.update(self.scope.cluster_id().as_bytes());
        hash.update(self.scope.configuration_id().as_bytes());
        hash.update(self.scope.configuration_epoch().get().to_be_bytes());
        hash.update(self.schema.as_bytes());
        for value in [self.consumer.as_str(), self.tenant.as_str()] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update(self.backing);
        hash.finalize().into()
    }
}

impl fmt::Debug for ConsumerCheckpointBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsumerCheckpointBinding(<redacted>)")
    }
}

/// Closed local resource bounds and explicit durability choice.
#[derive(Clone)]
pub struct ConsumerCheckpointOptions {
    path: PathBuf,
    binding: ConsumerCheckpointBinding,
    durability: RetainedConfigDurability,
    max_payload_bytes: usize,
    max_storage_bytes: u64,
    timeout: Duration,
}

impl ConsumerCheckpointOptions {
    /// Configure an absolute, exclusively owned file and bounded operations.
    ///
    /// Payload is limited to 16 MiB; the complete database and journals are
    /// limited to 1 GiB. Storage must admit the page-rounded maximum envelope,
    /// SQLite overflow pointers and root pages, plus journal and sidecar reserve.
    /// No queue exists: one operation per store can be outstanding.
    pub fn new(
        path: impl Into<PathBuf>,
        binding: ConsumerCheckpointBinding,
        durability: RetainedConfigDurability,
        max_payload_bytes: usize,
        max_storage_bytes: u64,
        timeout: Duration,
    ) -> Result<Self, ConsumerCheckpointError> {
        let path = path.into();
        if !path.is_absolute()
            || path.file_name().is_none()
            || !(1..=16 * 1024 * 1024).contains(&max_payload_bytes)
            || max_storage_bytes < minimum_storage_bytes(max_payload_bytes)
            || max_storage_bytes > 1024 * 1024 * 1024
            || timeout.is_zero()
            || timeout > Duration::from_secs(3600)
        {
            return Err(ConsumerCheckpointError::InvalidRequest);
        }
        Ok(Self {
            path,
            binding,
            durability,
            max_payload_bytes,
            max_storage_bytes,
            timeout,
        })
    }
}

// Called only after validating the payload range. Each overflow page spends
// four bytes on its next-page pointer. Reserve two more pages for sqlite_schema
// and the singleton table root; the row header fits in the root's local payload.
// Three database images plus fixed reserve cover the database, replacement WAL
// (including frame headers), shared memory and admission sidecar.
fn minimum_storage_bytes(max_payload_bytes: usize) -> u64 {
    let envelope_bytes = max_payload_bytes as u64 + ENVELOPE_OVERHEAD_LIMIT as u64;
    let database_pages = 2 + envelope_bytes.div_ceil(SQLITE_PAGE_BYTES - 4);
    3 * database_pages * SQLITE_PAGE_BYTES + STORAGE_RESERVE_BYTES
}

impl fmt::Debug for ConsumerCheckpointOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsumerCheckpointOptions(<redacted>)")
    }
}

/// Value-free storage outcomes. Possible mutations are always indeterminate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConsumerCheckpointError {
    /// Invalid caller-selected scope or resource bounds.
    #[error("invalid consumer checkpoint request")]
    InvalidRequest,
    /// Required local filesystem admission is unsupported.
    #[error("consumer checkpoint storage is unsupported")]
    Unsupported,
    /// Explicit provisioning found existing artifacts.
    #[error("consumer checkpoint already exists")]
    AlreadyExists,
    /// Established state is missing or incomplete; no create fallback is allowed.
    #[error("consumer checkpoint requires explicit recovery")]
    RecoveryRequired,
    /// Another SDK handle holds the exclusive local file admission.
    #[error("consumer checkpoint is already open")]
    InUse,
    /// Authentication, exact scope, schema or file identity did not match.
    #[error("consumer checkpoint validation failed")]
    Rejected,
    /// An explicit byte, task, generation or time bound was exhausted.
    #[error("consumer checkpoint bound exceeded")]
    Limit,
    /// Readback is required before a conflicting or uncertain write can proceed.
    #[error("consumer checkpoint requires readback")]
    Conflict,
    /// No mutation was started before this dependency failure.
    #[error("consumer checkpoint is unavailable")]
    Unavailable,
    /// A durable operation may have completed. Readback/reopen is mandatory.
    #[error("consumer checkpoint outcome is indeterminate")]
    Indeterminate,
    /// Owned shutdown completed and the handle admits no further work.
    #[error("consumer checkpoint is closed")]
    Closed,
}

impl From<RetainedConfigError> for ConsumerCheckpointError {
    fn from(error: RetainedConfigError) -> Self {
        match error {
            RetainedConfigError::InvalidRequest => Self::InvalidRequest,
            RetainedConfigError::Unsupported => Self::Unsupported,
            RetainedConfigError::AlreadyExists => Self::AlreadyExists,
            RetainedConfigError::RecoveryRequired => Self::RecoveryRequired,
            RetainedConfigError::InUse => Self::InUse,
            RetainedConfigError::Rejected => Self::Rejected,
            RetainedConfigError::AdmissionBound => Self::Limit,
            RetainedConfigError::Unavailable => Self::Unavailable,
            RetainedConfigError::Indeterminate => Self::Indeterminate,
        }
    }
}

/// One authenticated local readback. Its generation is a storage CAS fence,
/// never a newly allocated configuration version. Payload formatting is redacted.
pub struct ConsumerCheckpointReadback {
    generation: u64,
    payload: Zeroizing<Vec<u8>>,
}

impl ConsumerCheckpointReadback {
    /// Consume the sealed-state projection at the trusted consumer boundary.
    pub fn into_parts(self) -> (u64, Zeroizing<Vec<u8>>) {
        (self.generation, self.payload)
    }
}

impl fmt::Debug for ConsumerCheckpointReadback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsumerCheckpointReadback(<redacted>)")
    }
}

struct EncodedRow {
    generation: u64,
    envelope: Vec<u8>,
}

struct Work {
    deadline: Instant,
    cancelled: AtomicBool,
    mutated: AtomicBool,
}

impl Work {
    fn new(timeout: Duration) -> Result<Arc<Self>, ConsumerCheckpointError> {
        Ok(Arc::new(Self {
            deadline: Instant::now()
                .checked_add(timeout)
                .ok_or(ConsumerCheckpointError::InvalidRequest)?,
            cancelled: AtomicBool::new(false),
            mutated: AtomicBool::new(false),
        }))
    }
    fn check(&self) -> Result<(), ConsumerCheckpointError> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            Err(self.error(ConsumerCheckpointError::Limit))
        } else {
            Ok(())
        }
    }
    fn mutation(&self) -> Result<(), ConsumerCheckpointError> {
        self.check()?;
        self.mutated.store(true, Ordering::Release);
        Ok(())
    }
    fn error(&self, error: ConsumerCheckpointError) -> ConsumerCheckpointError {
        if self.mutated.load(Ordering::Acquire) {
            ConsumerCheckpointError::Indeterminate
        } else {
            error
        }
    }
}

struct CancelOnDrop(Arc<Work>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}

struct PendingIo {
    task: tokio::task::JoinHandle<Result<EncodedRow, ConsumerCheckpointError>>,
    work: Arc<Work>,
}

/// Single-owner SDK checkpoint storage. It has no authoring or voter methods.
///
/// Cancelling a write retains its task and uncertain disposition. Only explicit
/// readback can clear that disposition. Drop requests cancellation; a blocking
/// operation retains the file lock until it has actually stopped. Use `shutdown`
/// when positively proven completion and lock release are required.
pub struct ConsumerCheckpointStore {
    options: ConsumerCheckpointOptions,
    provider: Arc<dyn KeyProvider>,
    metadata: ConsumerCheckpointAad,
    connection: Arc<Mutex<Option<BackendConnection>>>,
    pending: Option<PendingIo>,
    uncertain: bool,
    verified: Option<(u64, [u8; 32])>,
    closed: bool,
}

impl fmt::Debug for ConsumerCheckpointStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsumerCheckpointStore(<redacted>)")
    }
}

impl ConsumerCheckpointStore {
    /// Explicitly create a never-used checkpoint. Existing artifacts are preserved.
    pub async fn provision(
        options: ConsumerCheckpointOptions,
        provider: Arc<dyn KeyProvider>,
    ) -> Result<Self, ConsumerCheckpointError> {
        Self::open(options, provider, true).await
    }

    /// Reopen exact established storage. Missing/corrupt state never becomes new.
    pub async fn reopen(
        options: ConsumerCheckpointOptions,
        provider: Arc<dyn KeyProvider>,
    ) -> Result<Self, ConsumerCheckpointError> {
        Self::open(options, provider, false).await
    }

    /// Exact binding used by the transport-owning consumer coordinator.
    pub fn binding(&self) -> &ConsumerCheckpointBinding {
        &self.options.binding
    }

    /// Hard aggregate plaintext limit, including all observed and applied facts.
    pub fn max_payload_bytes(&self) -> usize {
        self.options.max_payload_bytes
    }

    /// Authenticate current state after settling any abandoned operation. A
    /// successful result permits a subsequent CAS; it is not serving authority.
    pub async fn read_back(
        &mut self,
    ) -> Result<ConsumerCheckpointReadback, ConsumerCheckpointError> {
        if self.closed {
            return Err(ConsumerCheckpointError::Closed);
        }
        if self.pending.is_some() {
            // A failed possible write is resolved from actual storage, not replayed.
            let _ = self.settle().await?;
        }
        self.uncertain = true;
        self.start_io(None)?;
        let row = self.settle().await??;
        let payload = self.decrypt(&row).await?;
        self.verified = Some((row.generation, Sha256::digest(&row.envelope).into()));
        self.uncertain = false;
        Ok(ConsumerCheckpointReadback {
            generation: row.generation,
            payload,
        })
    }

    /// Atomically replace one complete checkpoint under the exact last-read CAS
    /// generation. Cancellation or failure after dispatch remains indeterminate;
    /// neither the old nor new payload may then authorize a product effect.
    pub async fn compare_and_set(
        &mut self,
        expected: u64,
        payload: Zeroizing<Vec<u8>>,
    ) -> Result<ConsumerCheckpointReadback, ConsumerCheckpointError> {
        if self.closed {
            return Err(ConsumerCheckpointError::Closed);
        }
        if self.uncertain || self.pending.is_some() {
            return Err(ConsumerCheckpointError::Conflict);
        }
        if payload.len() > self.options.max_payload_bytes
            || expected == 0
            || expected >= i64::MAX as u64
        {
            return Err(ConsumerCheckpointError::Limit);
        }
        let Some((verified_generation, verified_digest)) = self.verified else {
            return Err(ConsumerCheckpointError::Conflict);
        };
        if verified_generation != expected {
            return Err(ConsumerCheckpointError::Conflict);
        }
        let generation = expected + 1;
        let aad = EnvelopeAad::consumer_checkpoint(
            self.options.binding.tenant.clone(),
            generation,
            self.metadata.clone(),
        );
        let envelope = tokio::time::timeout(
            self.options.timeout,
            encrypt_envelope(self.provider.as_ref(), &aad, &payload),
        )
        .await
        .map_err(|_| ConsumerCheckpointError::Limit)?
        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        if envelope.len() > self.options.max_payload_bytes + ENVELOPE_OVERHEAD_LIMIT {
            return Err(ConsumerCheckpointError::Limit);
        }
        self.uncertain = true;
        self.start_io(Some((
            expected,
            verified_digest,
            EncodedRow {
                generation,
                envelope,
            },
        )))?;
        let row = self.settle().await??;
        let stored = self
            .decrypt(&row)
            .await
            .map_err(|_| ConsumerCheckpointError::Indeterminate)?;
        if row.generation != generation || *stored != *payload {
            return Err(ConsumerCheckpointError::Indeterminate);
        }
        self.verified = Some((row.generation, Sha256::digest(&row.envelope).into()));
        self.uncertain = false;
        Ok(ConsumerCheckpointReadback {
            generation,
            payload: stored,
        })
    }

    /// Stop new work, await the owned operation and close SQLite off the async
    /// executor. A timed-out shutdown returns indeterminate and never asserts
    /// that its still-owned file lock has already been released.
    pub async fn shutdown(mut self) -> Result<(), ConsumerCheckpointError> {
        self.closed = true;
        if let Some(pending) = &self.pending {
            pending.work.cancelled.store(true, Ordering::Release);
        }
        if self.pending.is_some() {
            let _ = self.settle().await?;
        }
        let connection = Arc::clone(&self.connection);
        let mut task = tokio::task::spawn_blocking(move || {
            let mut slot = connection
                .lock()
                .map_err(|_| ConsumerCheckpointError::Indeterminate)?;
            if let Some(conn) = slot.take() {
                conn.close()
                    .map_err(|_| ConsumerCheckpointError::Indeterminate)?;
            }
            Ok(())
        });
        tokio::time::timeout(self.options.timeout, &mut task)
            .await
            .map_err(|_| ConsumerCheckpointError::Indeterminate)?
            .map_err(|_| ConsumerCheckpointError::Indeterminate)?
    }

    async fn decrypt(
        &self,
        row: &EncodedRow,
    ) -> Result<Zeroizing<Vec<u8>>, ConsumerCheckpointError> {
        let aad = EnvelopeAad::consumer_checkpoint(
            self.options.binding.tenant.clone(),
            row.generation,
            self.metadata.clone(),
        );
        let payload = tokio::time::timeout(
            self.options.timeout,
            decrypt_envelope(self.provider.as_ref(), &aad, &row.envelope),
        )
        .await
        .map_err(|_| ConsumerCheckpointError::Limit)?
        .map_err(|_| ConsumerCheckpointError::Rejected)?;
        if payload.len() > self.options.max_payload_bytes {
            return Err(ConsumerCheckpointError::Limit);
        }
        Ok(payload)
    }

    fn start_io(
        &mut self,
        update: Option<(u64, [u8; 32], EncodedRow)>,
    ) -> Result<(), ConsumerCheckpointError> {
        let permit = IO_SLOTS
            .try_acquire()
            .map_err(|_| ConsumerCheckpointError::Limit)?;
        let connection = Arc::clone(&self.connection);
        let options = self.options.clone();
        let work = Work::new(options.timeout)?;
        let task_work = Arc::clone(&work);
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let result = (|| {
                task_work.check()?;
                let mut slot = connection
                    .lock()
                    .map_err(|_| ConsumerCheckpointError::Unavailable)?;
                let conn = slot.as_mut().ok_or(ConsumerCheckpointError::Closed)?;
                let progress = Arc::clone(&task_work);
                conn.progress_handler(1000, Some(move || progress.check().is_err()));
                check_storage_size(&options)?;
                if let Some((expected, verified_digest, row)) = update {
                    let current = read_row(conn, &options)?;
                    if current.generation != expected
                        || <[u8; 32]>::from(Sha256::digest(&current.envelope)) != verified_digest
                    {
                        return Err(ConsumerCheckpointError::Conflict);
                    }
                    // WAL is truncated between writes; reserve worst-case DB and
                    // journal growth before allocating a replacement transaction.
                    task_work.mutation()?;
                    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
                    let tx = conn
                        .transaction()
                        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
                    // Reclaim the old overflow pages inside the same atomic
                    // transaction before writing the replacement. An UPDATE
                    // can allocate a second full blob before freeing the old
                    // one, exceeding the admitted minimum database budget.
                    let changed = tx
                        .execute(
                            "DELETE FROM consumer_checkpoint WHERE singleton=1 AND generation=?1",
                            [expected as i64],
                        )
                        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
                    if changed != 1 {
                        return Err(ConsumerCheckpointError::Conflict);
                    }
                    tx.execute("INSERT INTO consumer_checkpoint (singleton, generation, envelope) VALUES (1, ?1, ?2)", rusqlite::params![row.generation as i64, row.envelope])
                        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
                    #[cfg(test)]
                    tests::crash_at("before-commit");
                    tx.commit()
                        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
                    #[cfg(test)]
                    tests::crash_at("after-commit");
                    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
                    #[cfg(test)]
                    tests::crash_at("after-checkpoint");
                }
                let row = read_row(conn, &options)?;
                check_storage_size(&options)?;
                task_work.check()?;
                Ok(row)
            })();
            result.map_err(|e| task_work.error(e))
        });
        self.pending = Some(PendingIo { task, work });
        Ok(())
    }

    async fn settle(
        &mut self,
    ) -> Result<Result<EncodedRow, ConsumerCheckpointError>, ConsumerCheckpointError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(ConsumerCheckpointError::Conflict)?;
        let _cancel = CancelOnDrop(Arc::clone(&pending.work));
        let result = tokio::time::timeout(self.options.timeout, &mut pending.task)
            .await
            .map_err(|_| ConsumerCheckpointError::Indeterminate)?
            .map_err(|_| ConsumerCheckpointError::Indeterminate)?;
        self.pending = None;
        Ok(result)
    }

    #[cfg(not(unix))]
    async fn open(
        _options: ConsumerCheckpointOptions,
        _provider: Arc<dyn KeyProvider>,
        _provision: bool,
    ) -> Result<Self, ConsumerCheckpointError> {
        Err(ConsumerCheckpointError::Unsupported)
    }

    #[cfg(unix)]
    async fn open(
        options: ConsumerCheckpointOptions,
        provider: Arc<dyn KeyProvider>,
        provision: bool,
    ) -> Result<Self, ConsumerCheckpointError> {
        let work = Work::new(options.timeout)?;
        let _cancel = CancelOnDrop(Arc::clone(&work));
        let result = async {
            let prepare_options = options.clone();
            let prepared = run_open_io(Arc::clone(&work), move |work| {
                prepare_files(&prepare_options, provision, work)
            })
            .await?;
            let metadata = prepared.metadata(&options.binding)?;
            let initial = if provision {
                let aad = EnvelopeAad::consumer_checkpoint(
                    options.binding.tenant.clone(),
                    1,
                    metadata.clone(),
                );
                let envelope = tokio::time::timeout_at(
                    tokio::time::Instant::from_std(work.deadline),
                    encrypt_envelope(provider.as_ref(), &aad, &[]),
                )
                .await
                .map_err(|_| ConsumerCheckpointError::Limit)?
                .map_err(|_| ConsumerCheckpointError::Unavailable)?;
                EncodedRow {
                    generation: 1,
                    envelope,
                }
            } else {
                let row = prepared
                    .row
                    .as_ref()
                    .ok_or(ConsumerCheckpointError::RecoveryRequired)?;
                let aad = EnvelopeAad::consumer_checkpoint(
                    options.binding.tenant.clone(),
                    row.generation,
                    metadata.clone(),
                );
                let payload = tokio::time::timeout_at(
                    tokio::time::Instant::from_std(work.deadline),
                    decrypt_envelope(provider.as_ref(), &aad, &row.envelope),
                )
                .await
                .map_err(|_| ConsumerCheckpointError::Limit)?
                .map_err(|_| ConsumerCheckpointError::Rejected)?;
                if payload.len() > options.max_payload_bytes {
                    return Err(ConsumerCheckpointError::Limit);
                }
                EncodedRow {
                    generation: row.generation,
                    envelope: row.envelope.clone(),
                }
            };
            let finish_options = options.clone();
            let conn = run_open_io(Arc::clone(&work), move |work| {
                finish_open(prepared, &finish_options, initial, provision, work)
            })
            .await?;
            Ok(Self {
                options,
                provider,
                metadata,
                connection: Arc::new(Mutex::new(Some(conn))),
                pending: None,
                uncertain: true,
                verified: None,
                closed: false,
            })
        }
        .await;
        result.map_err(|e| work.error(e))
    }
}

impl Drop for ConsumerCheckpointStore {
    fn drop(&mut self) {
        if let Some(pending) = &self.pending {
            pending.work.cancelled.store(true, Ordering::Release);
        }
    }
}

#[cfg(unix)]
async fn run_open_io<T: Send + 'static>(
    work: Arc<Work>,
    operation: impl FnOnce(&Arc<Work>) -> Result<T, ConsumerCheckpointError> + Send + 'static,
) -> Result<T, ConsumerCheckpointError> {
    let permit = IO_SLOTS
        .try_acquire()
        .map_err(|_| ConsumerCheckpointError::Limit)?;
    let deadline = work.deadline;
    let mut task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work.check()?;
        operation(&work)
    });
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut task)
        .await
        .map_err(|_| ConsumerCheckpointError::Indeterminate)?
        .map_err(|_| ConsumerCheckpointError::Indeterminate)?
}

#[cfg(unix)]
struct PreparedFiles {
    admission: Arc<FileAdmission>,
    record: [u8; 40],
    row: Option<EncodedRow>,
}

#[cfg(unix)]
impl PreparedFiles {
    fn metadata(
        &self,
        binding: &ConsumerCheckpointBinding,
    ) -> Result<ConsumerCheckpointAad, ConsumerCheckpointError> {
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/config-consumer-storage/v1\0");
        hash.update(self.record);
        for value in self.admission.identity {
            hash.update(value.to_be_bytes());
        }
        ConsumerCheckpointAad::new(binding.digest(), hash.finalize().into())
            .map_err(|_| ConsumerCheckpointError::Rejected)
    }
}

#[cfg(unix)]
fn prepare_files(
    options: &ConsumerCheckpointOptions,
    provision: bool,
    work: &Arc<Work>,
) -> Result<PreparedFiles, ConsumerCheckpointError> {
    reject_symlink_components(&options.path)?;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = suffixed(&options.path, suffix);
        match std::fs::symlink_metadata(&path) {
            Ok(_) if provision => return Err(ConsumerCheckpointError::AlreadyExists),
            Ok(_) => {
                open_file(&path, false, false)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ConsumerCheckpointError::Rejected),
        }
    }
    let parent_path = options
        .path
        .parent()
        .ok_or(ConsumerCheckpointError::InvalidRequest)?;
    let parent = open_file(parent_path, false, true)?;
    let before = identity_for_path(parent_path, true)?;
    let lock = if provision {
        let result = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(lock_path(&options.path));
        match result {
            Ok(file) => {
                work.mutated.store(true, Ordering::Release);
                file
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(ConsumerCheckpointError::AlreadyExists)
            }
            Err(_) => return Err(ConsumerCheckpointError::Unavailable),
        }
    } else {
        open_file(&lock_path(&options.path), true, false)?
    };
    let lock = AdmissionFileLock::acquire(lock)?;
    #[cfg(test)]
    if provision {
        tests::crash_at("provision-lock");
    }
    let mut record = [0; 40];
    if provision {
        use rand::{rngs::SysRng, TryRng};
        record[..8].copy_from_slice(MAGIC);
        SysRng
            .try_fill_bytes(&mut record[8..])
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
    } else {
        if lock
            .metadata()
            .map_err(|_| ConsumerCheckpointError::Unavailable)?
            .len()
            != record.len() as u64
        {
            return Err(ConsumerCheckpointError::RecoveryRequired);
        }
        (&*lock)
            .read_exact(&mut record)
            .map_err(|_| ConsumerCheckpointError::RecoveryRequired)?;
        if &record[..8] != MAGIC {
            return Err(ConsumerCheckpointError::Rejected);
        }
    }
    let database = if provision {
        work.mutation()?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&options.path)
            .map_err(|_| ConsumerCheckpointError::Unavailable)?
    } else {
        open_file(&options.path, false, false)?
    };
    let identity = file_identity(&parent, &lock, &database)?;
    #[cfg(test)]
    if provision {
        tests::crash_at("provision-database");
    }
    if before != identity[..2] {
        return Err(ConsumerCheckpointError::Rejected);
    }
    let admission = Arc::new(FileAdmission {
        path: options.path.clone(),
        parent,
        lock,
        database,
        identity,
    });
    admission.read_back()?;
    if let RetainedConfigDurability::Durable { min_free_bytes } = options.durability {
        let caps = crate::retained::retained_preflight(&admission, false, min_free_bytes);
        if !caps.is_safe_for_writes() {
            return Err(ConsumerCheckpointError::Rejected);
        }
    }
    let row = if provision {
        None
    } else {
        let staging = tempfile::Builder::new()
            .prefix("opc-checkpoint-")
            .tempdir()
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        let destination = staging.path().join("checkpoint.sqlite");
        copy_for_validation(options, &destination, work)?;
        let conn = open_sqlite(&destination)?;
        let progress = Arc::clone(work);
        conn.progress_handler(1000, Some(move || progress.check().is_err()));
        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(|_| ConsumerCheckpointError::Rejected)?;
        if integrity != "ok" {
            return Err(ConsumerCheckpointError::Rejected);
        }
        Some(read_row(&conn, options)?)
    };
    admission.read_back()?;
    work.check()?;
    Ok(PreparedFiles {
        admission,
        record,
        row,
    })
}

#[cfg(unix)]
fn finish_open(
    prepared: PreparedFiles,
    options: &ConsumerCheckpointOptions,
    initial: EncodedRow,
    provision: bool,
    work: &Arc<Work>,
) -> Result<BackendConnection, ConsumerCheckpointError> {
    prepared.admission.read_back()?;
    work.mutation()?;
    let conn = open_sqlite(&options.path)?;
    configure_connection(&conn, options, work)?;
    if provision {
        let tx = conn
            .unchecked_transaction()
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        tx.execute_batch(SCHEMA)
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        tx.execute(
            "INSERT INTO consumer_checkpoint (singleton, generation, envelope) VALUES (1, 1, ?1)",
            [initial.envelope.as_slice()],
        )
        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        tx.commit()
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        #[cfg(test)]
        tests::crash_at("provision-schema");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        prepared
            .admission
            .database
            .sync_all()
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        prepared
            .admission
            .parent
            .sync_all()
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        work.check()?;
        let mut lock = &*prepared.admission.lock;
        lock.write_all(&prepared.record)
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        lock.sync_all()
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        prepared
            .admission
            .parent
            .sync_all()
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        #[cfg(test)]
        tests::crash_at("provision-complete");
    }
    let read = read_row(&conn, options)?;
    if read.generation != initial.generation || read.envelope != initial.envelope {
        return Err(ConsumerCheckpointError::Rejected);
    }
    check_storage_size(options)?;
    prepared.admission.read_back()?;
    let guard = Arc::clone(&prepared.admission);
    conn.authorizer(Some(move |_: rusqlite::hooks::AuthContext<'_>| {
        if guard.read_back().is_ok() {
            rusqlite::hooks::Authorization::Allow
        } else {
            rusqlite::hooks::Authorization::Deny
        }
    }));
    conn.progress_handler(0, None::<fn() -> bool>);
    work.check()?;
    Ok(BackendConnection::retained(conn, prepared.admission))
}

fn configure_connection(
    conn: &Connection,
    options: &ConsumerCheckpointOptions,
    work: &Arc<Work>,
) -> Result<(), ConsumerCheckpointError> {
    let progress = Arc::clone(work);
    conn.progress_handler(1000, Some(move || progress.check().is_err()));
    crate::schema::apply_pragma_profile(conn).map_err(|_| ConsumerCheckpointError::Unavailable)?;
    let page_size: u64 = conn
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .map_err(|_| ConsumerCheckpointError::Rejected)?;
    if page_size != SQLITE_PAGE_BYTES {
        return Err(ConsumerCheckpointError::Rejected);
    }
    // Keep room for both the database and its replacement WAL. These are hard
    // backend limits in addition to admission/readback of actual file sizes.
    conn.pragma_update(
        None,
        "max_page_count",
        (options.max_storage_bytes - STORAGE_RESERVE_BYTES) / (3 * SQLITE_PAGE_BYTES),
    )
    .map_err(|_| ConsumerCheckpointError::Unavailable)?;
    let pages: u64 = conn
        .pragma_query_value(None, "max_page_count", |r| r.get(0))
        .map_err(|_| ConsumerCheckpointError::Rejected)?;
    if pages > (options.max_storage_bytes - STORAGE_RESERVE_BYTES) / (3 * SQLITE_PAGE_BYTES) {
        return Err(ConsumerCheckpointError::Limit);
    }
    conn.pragma_update(None, "journal_size_limit", options.max_storage_bytes / 2)
        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
    conn.pragma_update(None, "wal_autocheckpoint", 1)
        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
    conn.pragma_update(None, "trusted_schema", false)
        .map_err(|_| ConsumerCheckpointError::Unavailable)?;
    Ok(())
}

fn read_row(
    conn: &Connection,
    options: &ConsumerCheckpointOptions,
) -> Result<EncodedRow, ConsumerCheckpointError> {
    let schema_ok: bool = conn
        .query_row(
            "SELECT COUNT(*)=1 AND MIN(sql)=?1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
            [SCHEMA],
            |r| r.get(0),
        )
        .map_err(|_| ConsumerCheckpointError::Rejected)?;
    if !schema_ok {
        return Err(ConsumerCheckpointError::Rejected);
    }
    let (count, length, generation): (i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), MAX(length(envelope)), MAX(generation) FROM consumer_checkpoint",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| ConsumerCheckpointError::Rejected)?;
    if count != 1
        || generation <= 0
        || length <= 0
        || length as u64 > (options.max_payload_bytes + ENVELOPE_OVERHEAD_LIMIT) as u64
    {
        return Err(ConsumerCheckpointError::Rejected);
    }
    let envelope = conn
        .query_row(
            "SELECT envelope FROM consumer_checkpoint WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(|_| ConsumerCheckpointError::Rejected)?;
    Ok(EncodedRow {
        generation: generation as u64,
        envelope,
    })
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn check_storage_size(options: &ConsumerCheckpointOptions) -> Result<(), ConsumerCheckpointError> {
    let mut total = 0u64;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        match std::fs::symlink_metadata(suffixed(&options.path, suffix)) {
            Ok(meta) => {
                if !meta.is_file() || meta.file_type().is_symlink() {
                    return Err(ConsumerCheckpointError::Rejected);
                }
                total = total
                    .checked_add(meta.len())
                    .ok_or(ConsumerCheckpointError::Limit)?;
            }
            Err(e) if !suffix.is_empty() && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ConsumerCheckpointError::RecoveryRequired),
        }
    }
    if total > options.max_storage_bytes {
        return Err(ConsumerCheckpointError::Limit);
    }
    Ok(())
}

#[cfg(unix)]
fn copy_for_validation(
    options: &ConsumerCheckpointOptions,
    destination: &Path,
    work: &Arc<Work>,
) -> Result<(), ConsumerCheckpointError> {
    check_storage_size(options)?;
    let mut remaining = options.max_storage_bytes;
    let mut buffer = [0; 64 * 1024];
    for suffix in ["", "-wal", "-journal"] {
        let path = suffixed(&options.path, suffix);
        if !suffix.is_empty()
            && !path
                .try_exists()
                .map_err(|_| ConsumerCheckpointError::Unavailable)?
        {
            continue;
        }
        let mut source = open_file(&path, false, false)?;
        let length = source
            .metadata()
            .map_err(|_| ConsumerCheckpointError::Unavailable)?
            .len();
        remaining = remaining
            .checked_sub(length)
            .ok_or(ConsumerCheckpointError::Limit)?;
        let mut dest = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(suffixed(destination, suffix))
            .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        let mut copied = 0u64;
        loop {
            work.check()?;
            let n = source
                .read(&mut buffer)
                .map_err(|_| ConsumerCheckpointError::Unavailable)?;
            if n == 0 {
                break;
            }
            copied = copied
                .checked_add(n as u64)
                .ok_or(ConsumerCheckpointError::Limit)?;
            if copied > length {
                return Err(ConsumerCheckpointError::Rejected);
            }
            dest.write_all(&buffer[..n])
                .map_err(|_| ConsumerCheckpointError::Unavailable)?;
        }
        if copied != length {
            return Err(ConsumerCheckpointError::Rejected);
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
