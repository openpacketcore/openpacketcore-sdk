//! Request-bound, atomic publication of a new local configuration authority.

use super::*;

#[cfg(target_os = "linux")]
const INTENT_MAGIC: &[u8; 8] = b"OPCPRV01";
#[cfg(target_os = "linux")]
const INTENT_DOMAIN: &[u8] = b"openpacketcore/config-provision-intent/v1\0";
#[cfg(target_os = "linux")]
const INTENT_BYTES: usize = 8 + 32 + 32 + 1 + 4 * 8 + 32;

/// Independently authorized identity and disposition of one provisioning request.
///
/// Retain this value outside the destination database and repeat it unchanged
/// on resume. Identifiers are destination-local; this is not a distributed
/// uniqueness or storage-freshness authority. All-zero identifiers are refused.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RetainedConfigProvisionRequest {
    id: [u8; 32],
    repair_only: bool,
}

impl RetainedConfigProvisionRequest {
    /// Name a separately authorized, never-used configuration authority.
    pub fn new_authority(id: [u8; 32]) -> Result<Self, RetainedConfigError> {
        Self::new(id, false)
    }

    /// Name replacement storage that must recover from its existing quorum.
    ///
    /// The resulting backend retains the existing member-repair prohibition on
    /// local genesis. This does not authorize replacing an entire lost quorum.
    pub fn member_repair(id: [u8; 32]) -> Result<Self, RetainedConfigError> {
        Self::new(id, true)
    }

    fn new(id: [u8; 32], repair_only: bool) -> Result<Self, RetainedConfigError> {
        if id == [0; 32] {
            return Err(RetainedConfigError::InvalidRequest);
        }
        Ok(Self { id, repair_only })
    }
}

impl fmt::Debug for RetainedConfigProvisionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetainedConfigProvisionRequest(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OpenMode {
    Provision,
    Resume,
    Reopen,
    ReopenImplicit,
}

#[cfg(target_os = "linux")]
impl OpenMode {
    fn is_reopen(self) -> bool {
        matches!(self, Self::Reopen | Self::ReopenImplicit)
    }
}

impl SqliteBackend {
    /// Resume a provisioning request originally begun with
    /// `begin_provision_config_authority` or `provision_config_authority`.
    ///
    /// Those constructors name one request by the independently supplied binding
    /// and audit key. Retain that exact authorization across interruptions; this
    /// method must never be used as a new-authority fallback after storage loss.
    pub fn begin_resume_config_authority(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
    ) -> Result<RetainedConfigOpen, RetainedConfigError> {
        begin_open_authority(options, audit_key, OpenIntent::ResumeAuthority)
    }

    /// Resume the exact binding-based member-repair provisioning operation.
    /// The authenticated repair-only disposition cannot become new genesis.
    pub fn begin_resume_config_member_repair(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
    ) -> Result<RetainedConfigOpen, RetainedConfigError> {
        begin_open_authority(options, audit_key, OpenIntent::ResumeRepair)
    }

    /// Begin request-bound provisioning of unused retained configuration storage.
    ///
    /// The Linux filesystem must support unnamed temporary files, atomic link
    /// publication, file locks, and truthful file/directory synchronization.
    /// The SDK publishes only authenticated intent and a complete database.
    /// Retain the request and use `begin_resume_config_provision` after an
    /// interruption. Existing files are never adopted or overwritten.
    pub fn begin_provision_config_transaction(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
        request: RetainedConfigProvisionRequest,
    ) -> Result<RetainedConfigOpen, RetainedConfigError> {
        begin_open_authority(
            options,
            audit_key,
            OpenIntent::Transaction(request, OpenMode::Provision),
        )
    }

    /// Resume the exact authorized request, or read back its completed result.
    ///
    /// A crash before intent publication leaves no named artifact; the same
    /// request may start again. An authenticated intent without a database is
    /// resumed automatically. A published database is only validated, never
    /// initialized. Conflicting or unverifiable artifacts are left unchanged.
    /// This is an explicit provisioning operation, not a restart fallback.
    pub fn begin_resume_config_provision(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
        request: RetainedConfigProvisionRequest,
    ) -> Result<RetainedConfigOpen, RetainedConfigError> {
        begin_open_authority(
            options,
            audit_key,
            OpenIntent::Transaction(request, OpenMode::Resume),
        )
    }

    /// Reopen a completed request-based store without completing provisioning.
    ///
    /// Missing intent, completion record, or database returns `RecoveryRequired`. This profile
    /// refuses the older one-shot admission encoding; crossing profiles is a
    /// fresh installation. Cancellation and joining follow `RetainedConfigOpen`.
    pub fn begin_reopen_config_transaction(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
        request: RetainedConfigProvisionRequest,
    ) -> Result<RetainedConfigOpen, RetainedConfigError> {
        begin_open_authority(
            options,
            audit_key,
            OpenIntent::Transaction(request, OpenMode::Reopen),
        )
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open(
    _options: RetainedConfigOptions,
    _key: AuditKey,
    _request: RetainedConfigProvisionRequest,
    _mode: OpenMode,
    _work: &Arc<AdmissionWork>,
) -> Result<SqliteBackend, RetainedConfigError> {
    Err(RetainedConfigError::Unsupported)
}

#[cfg(target_os = "linux")]
pub(super) fn open(
    options: RetainedConfigOptions,
    key: AuditKey,
    mut request: RetainedConfigProvisionRequest,
    mode: OpenMode,
    work: &Arc<AdmissionWork>,
) -> Result<SqliteBackend, RetainedConfigError> {
    use std::os::unix::fs::MetadataExt;

    work.check()?;
    reject_symlink_components(&options.path)?;
    if exists(&obsolete_intent_path(&options.path))? {
        return Err(RetainedConfigError::RecoveryRequired);
    }
    let parent_path = options
        .path
        .parent()
        .ok_or(RetainedConfigError::InvalidRequest)?;
    let parent = open_file(parent_path, false, true)?;
    let parent_metadata = parent
        .metadata()
        .map_err(|_| RetainedConfigError::Unavailable)?;
    let parent_identity = [parent_metadata.dev(), parent_metadata.ino()];
    let marker_path = lock_path(&options.path);
    let completion_path = completion_path(&options.path);
    let marker_exists = exists(&marker_path)?;
    if mode == OpenMode::Provision
        && (marker_exists || exists(&options.path)? || exists(&completion_path)?)
    {
        return Err(RetainedConfigError::AlreadyExists);
    }
    if !marker_exists && (mode.is_reopen() || exists(&completion_path)?) {
        return Err(RetainedConfigError::RecoveryRequired);
    }
    let lock = if marker_exists {
        // Only the separate admission inode is opened before writer exclusion.
        // Opening/closing a SQLite main or SHM descriptor here could release
        // another connection's process-scoped POSIX locks.
        let lock = AdmissionFileLock::acquire(open_existing(&marker_path)?)?;
        #[cfg(test)]
        if let Some(hook) = &work.lock_hook {
            hook(&lock);
        }
        request = validate_intent(
            &lock,
            &parent,
            &options.binding,
            &key,
            request,
            mode == OpenMode::ReopenImplicit,
        )?;
        lock
    } else {
        require_absent_database(&options.path)?;
        let lock = AdmissionFileLock::acquire(unnamed(&parent)?)?;
        checkpoint(work, "intent_created")?;
        let record = intent_record(&lock, &parent, &options.binding, &key, request)?;
        (&*lock)
            .write_all(&record)
            .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "intent_written")?;
        lock.sync_all()
            .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "intent_synced")?;
        check_parent(parent_path, parent_identity)?;
        publish(&lock, &parent, &marker_path, work)?;
        checkpoint(work, "intent_published")?;
        parent
            .sync_all()
            .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "intent_directory_synced")?;
        checkpoint(work, "lock_created")?;
        #[cfg(test)]
        if let Some(hook) = &work.lock_hook {
            hook(&lock);
        }
        lock
    };
    check_parent(parent_path, parent_identity)?;
    if identity_for_path(&marker_path, false)? != descriptor_identity(&lock)? {
        return Err(RetainedConfigError::Rejected);
    }
    let database_exists = exists(&options.path)?;
    let completion_exists = exists(&completion_path)?;
    if (!database_exists && (mode.is_reopen() || completion_exists))
        || (mode.is_reopen() && !completion_exists)
    {
        return Err(RetainedConfigError::RecoveryRequired);
    }
    if marker_exists && mode == OpenMode::Resume && !database_exists {
        work.mutation()?;
        parent
            .sync_all()
            .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "intent_directory_synced")?;
    }
    let database = if database_exists {
        for suffix in ["-wal", "-shm", "-journal"] {
            let path = sidecar(&options.path, suffix);
            if exists(&path)? {
                identity_for_path(&path, false)?;
            }
        }
        open_existing(&options.path)?
    } else {
        require_absent_database(&options.path)?;
        let database = unnamed(&parent)?;
        checkpoint(work, "database_created")?;
        database
    };
    let identity = file_identity(&parent, &lock, &database)?;
    let mut admission = FileAdmission {
        path: options.path.clone(),
        parent,
        lock,
        database,
        completion: None,
        identity,
    };
    let record = make_record(
        &options.binding,
        &key,
        identity,
        request.id,
        request.repair_only,
    )?;
    if completion_exists {
        let mut completion = open_existing(&completion_path)?;
        if completion
            .metadata()
            .map_err(|_| RetainedConfigError::Unavailable)?
            .len()
            != RECORD_BYTES as u64
        {
            return Err(RetainedConfigError::RecoveryRequired);
        }
        let mut observed = [0; RECORD_BYTES];
        completion
            .read_exact(&mut observed)
            .map_err(|_| RetainedConfigError::Rejected)?;
        validate_record(&observed, &options.binding, &key)?;
        if record_identity(&observed)? != identity || observed != record {
            return Err(RetainedConfigError::Rejected);
        }
        admission.completion = Some((completion_path.clone(), completion));
    }
    let (ephemeral, min_free_bytes) = match options.durability {
        RetainedConfigDurability::Durable { min_free_bytes } => (false, min_free_bytes),
        RetainedConfigDurability::Ephemeral => (true, 0),
    };
    let caps = retained_preflight(&admission, ephemeral, min_free_bytes);
    if !ephemeral && !caps.is_safe_for_writes() {
        return Err(RetainedConfigError::Rejected);
    }
    if !database_exists {
        let conn = Connection::open_in_memory().map_err(|_| RetainedConfigError::Unavailable)?;
        let progress = Arc::clone(work);
        conn.progress_handler(1000, Some(move || progress.check().is_err()))
            .map_err(|_| RetainedConfigError::Unavailable)?;
        crate::schema::apply_pragma_profile(&conn).map_err(|_| RetainedConfigError::Unavailable)?;
        crate::schema::initialize_schema(&conn).map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "base_initialized")?;
        let digest = crate::schema::current_schema_digest(&conn)
            .map_err(|_| RetainedConfigError::Unavailable)?;
        let transaction = conn
            .unchecked_transaction()
            .map_err(|_| RetainedConfigError::Unavailable)?;
        crate::schema::set_schema_version(&transaction, &digest)
            .map_err(|_| RetainedConfigError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| RetainedConfigError::Unavailable)?;
        crate::consensus::provision_retained_schema(
            &conn,
            options.binding.topology(),
            &key,
            work.deadline,
        )
        .map_err(|_| RetainedConfigError::Rejected)?;
        checkpoint(work, "consensus_initialized")?;
        conn.execute_batch(BINDING_SCHEMA)
            .map_err(|_| RetainedConfigError::Unavailable)?;
        conn.execute(
            "INSERT INTO consensus_retained_binding (singleton, record) VALUES (1, ?1)",
            [record.as_slice()],
        )
        .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "binding_stored")?;
        validate_connection(&conn, &options, &record, &key, work)?;
        let serialized = conn
            .serialize(rusqlite::MAIN_DB)
            .map_err(|_| RetainedConfigError::Unavailable)?;
        if serialized.len() as u64 > options.max_validation_bytes {
            return Err(RetainedConfigError::AdmissionBound);
        }
        for chunk in serialized.chunks(COPY_BUFFER_BYTES) {
            work.check()?;
            (&admission.database)
                .write_all(chunk)
                .map_err(|_| RetainedConfigError::Unavailable)?;
        }
        checkpoint(work, "database_written")?;
        admission
            .database
            .sync_all()
            .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "database_synced")?;
        check_parent(parent_path, parent_identity)?;
        if identity_for_path(&marker_path, false)? != identity[2..4] {
            return Err(RetainedConfigError::Rejected);
        }
        require_absent_database(&options.path)?;
        publish(&admission.database, &admission.parent, &options.path, work)?;
        checkpoint(work, "database_published")?;
    }
    // A resume must sync the directory again even when the last process died
    // immediately after the successful link and before directory synchronization.
    if !mode.is_reopen() {
        work.mutation()?;
        admission
            .parent
            .sync_all()
            .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "database_directory_synced")?;
    }
    validate_copy(&options, &record, &key, &admission, work)?;
    if !completion_exists {
        // A separate completion witness distinguishes interrupted publication
        // from loss of an established database. Never recreate the latter.
        let mut completion = unnamed(&admission.parent)?;
        checkpoint(work, "completion_created")?;
        completion
            .write_all(&record)
            .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "completion_written")?;
        completion
            .sync_all()
            .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "completion_synced")?;
        admission.read_back()?;
        publish(&completion, &admission.parent, &completion_path, work)?;
        admission.completion = Some((completion_path, completion));
        checkpoint(work, "record_written")?;
    }
    if !mode.is_reopen() {
        admission
            .parent
            .sync_all()
            .map_err(|_| RetainedConfigError::Unavailable)?;
        checkpoint(work, "record_synced")?;
    }
    finish_open(options, key, record, Arc::new(admission), work, caps)
}

#[cfg(target_os = "linux")]
fn exists(path: &Path) -> Result<bool, RetainedConfigError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(RetainedConfigError::Unavailable),
    }
}

#[cfg(target_os = "linux")]
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(target_os = "linux")]
fn require_absent_database(path: &Path) -> Result<(), RetainedConfigError> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        if exists(&sidecar(path, suffix))? {
            return Err(RetainedConfigError::AlreadyExists);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn descriptor_identity(file: &std::fs::File) -> Result<[u64; 2], RetainedConfigError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|_| RetainedConfigError::Unavailable)?;
    Ok([metadata.dev(), metadata.ino()])
}

#[cfg(target_os = "linux")]
fn check_parent(path: &Path, expected: [u64; 2]) -> Result<(), RetainedConfigError> {
    reject_symlink_components(path)?;
    if identity_for_path(path, true)? != expected {
        return Err(RetainedConfigError::Rejected);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unnamed(parent: &std::fs::File) -> Result<std::fs::File, RetainedConfigError> {
    use rustix::fs::{openat, Mode, OFlags};
    openat(
        parent,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(std::fs::File::from)
    .map_err(|error| match error {
        rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::INVAL => RetainedConfigError::Unsupported,
        _ => RetainedConfigError::Unavailable,
    })
}

#[cfg(target_os = "linux")]
fn open_existing(path: &Path) -> Result<std::fs::File, RetainedConfigError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let pin = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| RetainedConfigError::Rejected)?;
    let metadata = pin
        .metadata()
        .map_err(|_| RetainedConfigError::Unavailable)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
        return Err(RetainedConfigError::Rejected);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(format!("/proc/self/fd/{}", pin.as_raw_fd()))
        .map_err(|_| RetainedConfigError::Rejected)?;
    if descriptor_identity(&file)? != [metadata.dev(), metadata.ino()] {
        return Err(RetainedConfigError::Rejected);
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn publish(
    file: &std::fs::File,
    parent: &std::fs::File,
    path: &Path,
    work: &AdmissionWork,
) -> Result<(), RetainedConfigError> {
    use std::os::fd::AsRawFd;
    let name = path
        .file_name()
        .ok_or(RetainedConfigError::InvalidRequest)?;
    work.mutation()?;
    // Following this procfs link publishes the held unnamed inode without
    // requiring CAP_DAC_READ_SEARCH (AT_EMPTY_PATH would require that capability).
    rustix::fs::linkat(
        rustix::fs::CWD,
        format!("/proc/self/fd/{}", file.as_raw_fd()),
        parent,
        name,
        rustix::fs::AtFlags::SYMLINK_FOLLOW,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            RetainedConfigError::AlreadyExists
        } else {
            RetainedConfigError::Unavailable
        }
    })
}

#[cfg(target_os = "linux")]
fn intent_record(
    lock: &std::fs::File,
    parent: &std::fs::File,
    binding: &RetainedConfigBinding,
    key: &AuditKey,
    request: RetainedConfigProvisionRequest,
) -> Result<[u8; INTENT_BYTES], RetainedConfigError> {
    let mut record = [0; INTENT_BYTES];
    record[..8].copy_from_slice(INTENT_MAGIC);
    record[8..40].copy_from_slice(&binding.digest(key));
    record[40..72].copy_from_slice(&request.id);
    record[72] = u8::from(request.repair_only);
    for (index, value) in descriptor_identity(parent)?
        .into_iter()
        .chain(descriptor_identity(lock)?)
        .enumerate()
    {
        record[73 + index * 8..81 + index * 8].copy_from_slice(&value.to_be_bytes());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| RetainedConfigError::Rejected)?;
    mac.update(INTENT_DOMAIN);
    mac.update(&record[..INTENT_BYTES - 32]);
    record[INTENT_BYTES - 32..].copy_from_slice(&mac.finalize().into_bytes());
    Ok(record)
}

#[cfg(target_os = "linux")]
fn validate_intent(
    lock: &std::fs::File,
    parent: &std::fs::File,
    binding: &RetainedConfigBinding,
    key: &AuditKey,
    mut request: RetainedConfigProvisionRequest,
    read_disposition: bool,
) -> Result<RetainedConfigProvisionRequest, RetainedConfigError> {
    if lock
        .metadata()
        .map_err(|_| RetainedConfigError::Unavailable)?
        .len()
        != INTENT_BYTES as u64
    {
        return Err(RetainedConfigError::RecoveryRequired);
    }
    let mut observed = [0; INTENT_BYTES];
    let mut input = lock;
    input
        .read_exact(&mut observed)
        .map_err(|_| RetainedConfigError::Rejected)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| RetainedConfigError::Rejected)?;
    mac.update(INTENT_DOMAIN);
    mac.update(&observed[..INTENT_BYTES - 32]);
    mac.verify_slice(&observed[INTENT_BYTES - 32..])
        .map_err(|_| RetainedConfigError::Rejected)?;
    if read_disposition {
        if observed[72] > 1 {
            return Err(RetainedConfigError::Rejected);
        }
        request.repair_only = observed[72] == 1;
    }
    if observed != intent_record(lock, parent, binding, key, request)? {
        return Err(RetainedConfigError::Rejected);
    }
    Ok(request)
}

#[cfg(target_os = "linux")]
fn checkpoint(work: &AdmissionWork, name: &str) -> Result<(), RetainedConfigError> {
    #[cfg(test)]
    {
        work.stage(name);
        if work
            .provision_fault
            .as_ref()
            .is_some_and(|fault| fault(name))
        {
            return Err(RetainedConfigError::Unavailable);
        }
    }
    #[cfg(not(test))]
    let _ = name;
    work.check()
}
