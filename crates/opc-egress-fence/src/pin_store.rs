//! Descriptor-anchored bpffs generation publication and recovery inventory.

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fmt, io,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, TryLockError},
};

use rand::{rngs::SysRng, TryRng};
use rustix::fs::{
    flock, fstat, fstatfs, fsync, mkdirat, open, openat, renameat_with, unlinkat, AtFlags, Dir,
    DirEntry, FileType, FlockOperation, Mode, OFlags, RenameFlags,
};

use crate::install_manifest::{InstallGenerationId, INSTALL_PIN_OBJECT_NAMES};

const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
const MAX_GENERATIONS: usize = 32;
const GENERATION_HEX_BYTES: usize = 32;
const CREATE_ATTEMPTS: usize = 4;

/// Trusted, existing bpffs directory dedicated to egress-fence generations.
pub(crate) struct FencePinStore {
    inner: Arc<PinStoreInner>,
}

struct PinStoreInner {
    visible_path: PathBuf,
    descriptor: OwnedFd,
    device: u64,
    inode: u64,
    owner_process_id: u32,
    process_lock: Mutex<()>,
}

impl FencePinStore {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(pin_store_error(io::ErrorKind::InvalidInput));
        }
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let filesystem = fstatfs(&descriptor).map_err(io::Error::from)?;
        let metadata = fstat(&descriptor).map_err(io::Error::from)?;
        validate_pin_root_metadata(
            filesystem.f_type as u64,
            metadata.st_uid,
            metadata.st_mode,
            FileType::from_raw_mode(metadata.st_mode).is_dir(),
        )?;
        let store = Self {
            inner: Arc::new(PinStoreInner {
                visible_path: path.to_path_buf(),
                descriptor,
                device: metadata.st_dev,
                inode: metadata.st_ino,
                owner_process_id: std::process::id(),
                process_lock: Mutex::new(()),
            }),
        };
        store.lock()?.scan()?;
        Ok(store)
    }

    /// Acquire the exclusive cross-process generation-operation guard.
    pub(crate) fn lock(&self) -> io::Result<FencePinStoreGuard<'_>> {
        verify_process_identity(self.inner.owner_process_id)?;
        let process_guard = self
            .inner
            .process_lock
            .try_lock()
            .map_err(|error| match error {
                TryLockError::WouldBlock => pin_store_error(io::ErrorKind::WouldBlock),
                TryLockError::Poisoned(_) => pin_store_error(io::ErrorKind::Other),
            })?;
        flock(
            &self.inner.descriptor,
            FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(redact_io)?;
        Ok(FencePinStoreGuard {
            store: &self.inner,
            _process_guard: process_guard,
        })
    }

    /// Prove that the originally admitted root path still names this root.
    pub(crate) fn verify_visible_identity(&self) -> io::Result<()> {
        verify_pin_root_visible_identity(&self.inner)
    }
}

/// Exclusive operation guard spanning scan, install, adoption, and cleanup.
pub(crate) struct FencePinStoreGuard<'a> {
    store: &'a Arc<PinStoreInner>,
    _process_guard: MutexGuard<'a, ()>,
}

impl FencePinStoreGuard<'_> {
    pub(crate) fn scan(&self) -> io::Result<Vec<GenerationInventoryEntry>> {
        verify_pin_root_visible_identity(self.store)?;
        scan_generation_entries(&self.store.descriptor, MAX_GENERATIONS, |entry| {
            let descriptor = open_generation_directory(self.store, entry.file_name())?;
            let metadata = fstat(&descriptor).map_err(redact_io)?;
            let root_metadata = fstat(&self.store.descriptor).map_err(redact_io)?;
            if metadata.st_dev != root_metadata.st_dev || metadata.st_ino != entry.ino() {
                return Err(pin_store_error(io::ErrorKind::InvalidData));
            }
            Ok(())
        })
    }

    /// Return a bounded conservative recovery classification.
    ///
    /// No directory is deleted here. Exactly one prepared or exactly one
    /// committed generation may be returned for higher-level identity-aware
    /// recovery. Multiple durable candidates, or prepared plus committed, are
    /// ambiguous and fail closed. Only inert staging entries are cleanup
    /// candidates.
    pub(crate) fn recovery_inventory(&self) -> io::Result<RecoveryInventory> {
        classify_recovery_entries(self.scan()?)
    }

    /// Open one exact descriptor-anchored generation discovered by `scan`.
    pub(crate) fn open_existing(
        &self,
        entry: GenerationInventoryEntry,
    ) -> io::Result<GenerationDirectory> {
        verify_pin_root_visible_identity(self.store)?;
        let name = generation_name(entry.phase, entry.generation_id);
        let descriptor = open_generation_directory(self.store, &name)?;
        let generation = GenerationDirectory {
            store: Arc::clone(self.store),
            generation_id: entry.generation_id,
            phase: entry.phase,
            name,
            descriptor,
        };
        generation.verify_visible_identity()?;
        Ok(generation)
    }

    pub(crate) fn create_staging(&self) -> io::Result<GenerationDirectory> {
        if self.scan()?.len() >= MAX_GENERATIONS {
            return Err(pin_store_error(io::ErrorKind::OutOfMemory));
        }
        for _ in 0..CREATE_ATTEMPTS {
            let generation_id = random_generation_id()?;
            let name = generation_name(GenerationPhase::Staging, generation_id);
            match mkdirat(
                self.store.descriptor.as_fd(),
                name.as_str(),
                Mode::from_bits_truncate(0o700),
            ) {
                Ok(()) => {
                    fsync(&self.store.descriptor).map_err(redact_io)?;
                    let directory = open_generation_directory(self.store, &name)?;
                    self.scan()?;
                    let generation = GenerationDirectory {
                        store: Arc::clone(self.store),
                        generation_id,
                        phase: GenerationPhase::Staging,
                        name,
                        descriptor: directory,
                    };
                    generation.verify_visible_identity()?;
                    return Ok(generation);
                }
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => return Err(redact_io(error)),
            }
        }
        Err(pin_store_error(io::ErrorKind::AlreadyExists))
    }

    /// Remove one exact inert staging generation containing only known pins.
    ///
    /// Prepared and committed generations are never accepted. Any unknown,
    /// duplicate, or over-bound child preserves the directory and fails closed.
    pub(crate) fn remove_staging(&self, generation: GenerationDirectory) -> io::Result<()> {
        if !Arc::ptr_eq(self.store, &generation.store)
            || generation.phase != GenerationPhase::Staging
        {
            return Err(pin_store_error(io::ErrorKind::InvalidInput));
        }
        generation.verify_visible_identity()?;
        let object_names = scan_known_object_names(&generation.descriptor)?;
        for name in &object_names {
            unlinkat(
                generation.descriptor.as_fd(),
                name.as_str(),
                AtFlags::empty(),
            )
            .map_err(redact_io)?;
        }
        fsync(&generation.descriptor).map_err(redact_io)?;
        if !scan_known_object_names(&generation.descriptor)?.is_empty() {
            return Err(pin_store_error(io::ErrorKind::InvalidData));
        }
        generation.verify_visible_identity()?;
        unlinkat(
            self.store.descriptor.as_fd(),
            generation.name.as_str(),
            AtFlags::REMOVEDIR,
        )
        .map_err(redact_io)?;
        fsync(&self.store.descriptor).map_err(redact_io)?;
        match openat(
            self.store.descriptor.as_fd(),
            generation.name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Ok(_) | Err(_) => Err(pin_store_error(io::ErrorKind::InvalidData)),
        }
    }
}

impl Drop for FencePinStoreGuard<'_> {
    fn drop(&mut self) {
        if process_identity_matches(self.store.owner_process_id) {
            let _ = flock(&self.store.descriptor, FlockOperation::Unlock);
        }
    }
}

impl fmt::Debug for FencePinStoreGuard<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencePinStoreGuard(<redacted>)")
    }
}

impl Clone for FencePinStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl fmt::Debug for FencePinStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencePinStore(<redacted>)")
    }
}

/// One opened generation directory in an exact publication phase.
pub(crate) struct GenerationDirectory {
    store: Arc<PinStoreInner>,
    generation_id: InstallGenerationId,
    phase: GenerationPhase,
    name: String,
    descriptor: OwnedFd,
}

impl GenerationDirectory {
    pub(crate) const fn generation_id(&self) -> InstallGenerationId {
        self.generation_id
    }

    pub(crate) const fn phase(&self) -> GenerationPhase {
        self.phase
    }

    pub(crate) fn object_path(&self, object_name: &str) -> io::Result<PathBuf> {
        validate_object_name(object_name)?;
        if !INSTALL_PIN_OBJECT_NAMES.contains(&object_name) {
            return Err(pin_store_error(io::ErrorKind::InvalidInput));
        }
        self.verify_visible_identity()?;
        Ok(descriptor_object_path(&self.descriptor, object_name))
    }

    pub(crate) fn verify_visible_identity(&self) -> io::Result<()> {
        verify_pin_root_visible_identity(&self.store)?;
        let reopened = open_generation_directory(&self.store, &self.name)?;
        verify_same_directory(&self.descriptor, &reopened)
    }

    pub(crate) fn verify_exact_object_set(&self) -> io::Result<()> {
        self.verify_visible_identity()?;
        let actual = scan_known_object_names(&self.descriptor)?;
        let mut expected = INSTALL_PIN_OBJECT_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        expected.sort_unstable();
        if actual != expected {
            return Err(pin_store_error(io::ErrorKind::InvalidData));
        }
        Ok(())
    }

    pub(crate) fn publish_prepared(self, guard: &FencePinStoreGuard<'_>) -> io::Result<Self> {
        self.publish(guard, GenerationPhase::Prepared)
    }

    pub(crate) fn publish_committed(self, guard: &FencePinStoreGuard<'_>) -> io::Result<Self> {
        self.publish(guard, GenerationPhase::Committed)
    }

    fn publish(
        mut self,
        guard: &FencePinStoreGuard<'_>,
        target: GenerationPhase,
    ) -> io::Result<Self> {
        if !Arc::ptr_eq(guard.store, &self.store) {
            return Err(pin_store_error(io::ErrorKind::InvalidInput));
        }
        if !matches!(
            (self.phase, target),
            (GenerationPhase::Staging, GenerationPhase::Prepared)
                | (GenerationPhase::Prepared, GenerationPhase::Committed)
        ) {
            return Err(pin_store_error(io::ErrorKind::InvalidInput));
        }
        self.verify_visible_identity()?;
        fsync(&self.descriptor).map_err(redact_io)?;
        let target_name = generation_name(target, self.generation_id);
        renameat_with(
            self.store.descriptor.as_fd(),
            self.name.as_str(),
            self.store.descriptor.as_fd(),
            target_name.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(redact_io)?;
        fsync(&self.store.descriptor).map_err(redact_io)?;

        let reopened = open_generation_directory(&self.store, &target_name)?;
        verify_same_directory(&self.descriptor, &reopened)?;
        require_name_absent(
            openat(
                self.store.descriptor.as_fd(),
                self.name.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(drop),
        )?;

        self.phase = target;
        self.name = target_name;
        self.descriptor = reopened;
        self.verify_visible_identity()?;
        Ok(self)
    }
}

impl fmt::Debug for GenerationDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationDirectory")
            .field("phase", &self.phase)
            .field("generation_present", &true)
            .finish()
    }
}

/// Durable external publication phase encoded in a generation directory name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GenerationPhase {
    Staging,
    Prepared,
    Committed,
}

impl GenerationPhase {
    const fn prefix(self) -> &'static str {
        match self {
            Self::Staging => "staging-",
            Self::Prepared => "prepared-",
            Self::Committed => "committed-",
        }
    }
}

/// One exact generation discovered during bounded recovery inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenerationInventoryEntry {
    pub(crate) phase: GenerationPhase,
    pub(crate) generation_id: InstallGenerationId,
}

/// Bounded recovery result. Cleanup candidates are never deleted implicitly.
pub(crate) struct RecoveryInventory {
    pub(crate) committed: Option<GenerationInventoryEntry>,
    pub(crate) prepared: Option<GenerationInventoryEntry>,
    pub(crate) cleanup_candidates: Vec<GenerationInventoryEntry>,
}

impl fmt::Debug for RecoveryInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryInventory")
            .field("committed_present", &self.committed.is_some())
            .field("prepared_present", &self.prepared.is_some())
            .field("cleanup_candidate_count", &self.cleanup_candidates.len())
            .finish()
    }
}

fn validate_pin_root_metadata(
    filesystem_type: u64,
    owner_uid: u32,
    mode: u32,
    is_directory: bool,
) -> io::Result<()> {
    let group_or_other_writable = mode & 0o022 != 0;
    if filesystem_type != BPF_FS_MAGIC || !is_directory || owner_uid != 0 || group_or_other_writable
    {
        return Err(pin_store_error(io::ErrorKind::InvalidData));
    }
    Ok(())
}

fn verify_pin_root_visible_identity(store: &PinStoreInner) -> io::Result<()> {
    verify_process_identity(store.owner_process_id)?;
    let visible = open(
        &store.visible_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(redact_io)?;
    let filesystem = fstatfs(&visible).map_err(redact_io)?;
    let metadata = fstat(&visible).map_err(redact_io)?;
    validate_pin_root_metadata(
        filesystem.f_type as u64,
        metadata.st_uid,
        metadata.st_mode,
        FileType::from_raw_mode(metadata.st_mode).is_dir(),
    )?;
    if metadata.st_dev != store.device || metadata.st_ino != store.inode {
        return Err(pin_store_error(io::ErrorKind::InvalidData));
    }
    verify_same_directory(&store.descriptor, &visible)
}

fn process_identity_matches(owner_process_id: u32) -> bool {
    owner_process_id != 0 && owner_process_id == std::process::id()
}

fn verify_process_identity(owner_process_id: u32) -> io::Result<()> {
    if !process_identity_matches(owner_process_id) {
        return Err(pin_store_error(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn require_name_absent(result: Result<(), rustix::io::Errno>) -> io::Result<()> {
    match result {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Ok(()) | Err(_) => Err(pin_store_error(io::ErrorKind::InvalidData)),
    }
}

fn verify_same_directory(left: &OwnedFd, right: &OwnedFd) -> io::Result<()> {
    let left = fstat(left).map_err(redact_io)?;
    let right = fstat(right).map_err(redact_io)?;
    if left.st_dev != right.st_dev
        || left.st_ino != right.st_ino
        || !FileType::from_raw_mode(left.st_mode).is_dir()
        || !FileType::from_raw_mode(right.st_mode).is_dir()
    {
        return Err(pin_store_error(io::ErrorKind::InvalidData));
    }
    Ok(())
}

fn validate_generation_metadata(
    filesystem_type: u64,
    root_device: u64,
    device: u64,
    owner_uid: u32,
    mode: u32,
    is_directory: bool,
) -> io::Result<()> {
    if filesystem_type != BPF_FS_MAGIC
        || device != root_device
        || !is_directory
        || owner_uid != 0
        || mode & 0o7777 != 0o700
    {
        return Err(pin_store_error(io::ErrorKind::InvalidData));
    }
    Ok(())
}

fn open_generation_directory<P: rustix::path::Arg>(
    store: &PinStoreInner,
    name: P,
) -> io::Result<OwnedFd> {
    let descriptor = openat(
        store.descriptor.as_fd(),
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(redact_io)?;
    let filesystem = fstatfs(&descriptor).map_err(io::Error::from)?;
    let metadata = fstat(&descriptor).map_err(io::Error::from)?;
    validate_generation_metadata(
        filesystem.f_type as u64,
        store.device,
        metadata.st_dev,
        metadata.st_uid,
        metadata.st_mode,
        FileType::from_raw_mode(metadata.st_mode).is_dir(),
    )?;
    Ok(descriptor)
}

fn scan_generation_entries<F>(
    descriptor: &OwnedFd,
    limit: usize,
    mut validate_entry: F,
) -> io::Result<Vec<GenerationInventoryEntry>>
where
    F: FnMut(&DirEntry) -> io::Result<()>,
{
    let mut entries = Vec::new();
    let directory = Dir::read_from(descriptor).map_err(redact_io)?;
    for entry in directory {
        let entry = entry.map_err(redact_io)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if entries.len() >= limit {
            return Err(pin_store_error(io::ErrorKind::InvalidData));
        }
        let parsed = parse_generation_name(OsStr::from_bytes(name))
            .ok_or_else(|| pin_store_error(io::ErrorKind::InvalidData))?;
        validate_entry(&entry)?;
        entries.push(parsed);
    }
    entries.sort_unstable_by_key(|entry| (entry.phase, entry.generation_id.bytes()));
    Ok(entries)
}

fn scan_known_object_names(descriptor: &OwnedFd) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    let mut unique = BTreeSet::new();
    let directory = Dir::read_from(descriptor).map_err(redact_io)?;
    for entry in directory {
        let entry = entry.map_err(redact_io)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() >= INSTALL_PIN_OBJECT_NAMES.len() {
            return Err(pin_store_error(io::ErrorKind::InvalidData));
        }
        if entry.ino() == 0 || !entry.file_type().is_file() {
            return Err(pin_store_error(io::ErrorKind::InvalidData));
        }
        let name =
            std::str::from_utf8(bytes).map_err(|_| pin_store_error(io::ErrorKind::InvalidData))?;
        if !INSTALL_PIN_OBJECT_NAMES.contains(&name) || !unique.insert(name.to_owned()) {
            return Err(pin_store_error(io::ErrorKind::InvalidData));
        }
        names.push(name.to_owned());
    }
    names.sort_unstable();
    Ok(names)
}

fn classify_recovery_entries(
    entries: Vec<GenerationInventoryEntry>,
) -> io::Result<RecoveryInventory> {
    if entries.len() > MAX_GENERATIONS {
        return Err(pin_store_error(io::ErrorKind::InvalidData));
    }
    let mut committed = None;
    let mut prepared = None;
    let mut cleanup_candidates = Vec::new();
    for entry in entries {
        match entry.phase {
            GenerationPhase::Staging => cleanup_candidates.push(entry),
            GenerationPhase::Prepared => {
                if prepared.replace(entry).is_some() {
                    return Err(pin_store_error(io::ErrorKind::InvalidData));
                }
            }
            GenerationPhase::Committed => {
                if committed.replace(entry).is_some() {
                    return Err(pin_store_error(io::ErrorKind::InvalidData));
                }
            }
        }
    }
    if prepared.is_some() && committed.is_some() {
        return Err(pin_store_error(io::ErrorKind::InvalidData));
    }
    Ok(RecoveryInventory {
        committed,
        prepared,
        cleanup_candidates,
    })
}

fn random_generation_id() -> io::Result<InstallGenerationId> {
    let mut bytes = [0_u8; 16];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| pin_store_error(io::ErrorKind::Other))?;
    InstallGenerationId::new(bytes).map_err(|_| pin_store_error(io::ErrorKind::Other))
}

fn generation_name(phase: GenerationPhase, generation_id: InstallGenerationId) -> String {
    let mut name = String::with_capacity(phase.prefix().len() + GENERATION_HEX_BYTES);
    name.push_str(phase.prefix());
    for byte in generation_id.bytes() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

fn parse_generation_name(name: &OsStr) -> Option<GenerationInventoryEntry> {
    let bytes = name.as_bytes();
    let phase = [
        GenerationPhase::Staging,
        GenerationPhase::Prepared,
        GenerationPhase::Committed,
    ]
    .into_iter()
    .find(|phase| bytes.starts_with(phase.prefix().as_bytes()))?;
    let hexadecimal = bytes.get(phase.prefix().len()..)?;
    if hexadecimal.len() != GENERATION_HEX_BYTES {
        return None;
    }
    let mut generation = [0_u8; 16];
    for (index, output) in generation.iter_mut().enumerate() {
        let high = decode_hex(*hexadecimal.get(index * 2)?)?;
        let low = decode_hex(*hexadecimal.get(index * 2 + 1)?)?;
        *output = (high << 4) | low;
    }
    Some(GenerationInventoryEntry {
        phase,
        generation_id: InstallGenerationId::new(generation).ok()?,
    })
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_object_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() >= 64
        || name == "."
        || name == ".."
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'_' && byte != b'-')
    {
        return Err(pin_store_error(io::ErrorKind::InvalidInput));
    }
    Ok(())
}

fn descriptor_object_path(descriptor: &OwnedFd, object_name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        descriptor.as_raw_fd(),
        object_name
    ))
}

fn redact_io(error: impl Into<io::Error>) -> io::Error {
    let error = error.into();
    pin_store_error(error.kind())
}

fn pin_store_error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "egress_fence_pin_store")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            for _ in 0..16 {
                let nonce = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "opc-egress-fence-pin-{label}-{}-{nonce}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create test directory: {error}"),
                }
            }
            panic!("test directory namespace exhausted");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn generation(index: u8) -> InstallGenerationId {
        let mut bytes = [0_u8; 16];
        bytes[15] = index;
        InstallGenerationId::new(bytes).expect("nonzero test generation")
    }

    fn test_store(path: &Path) -> FencePinStore {
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open test store");
        let metadata = fstat(&descriptor).expect("stat test store");
        FencePinStore {
            inner: Arc::new(PinStoreInner {
                visible_path: path.to_path_buf(),
                descriptor,
                device: metadata.st_dev,
                inode: metadata.st_ino,
                owner_process_id: std::process::id(),
                process_lock: Mutex::new(()),
            }),
        }
    }

    #[test]
    fn generation_names_are_exact_lowercase_and_round_trip() {
        let generation_id = InstallGenerationId::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
            0xdc, 0xfe,
        ])
        .expect("generation");
        for phase in [
            GenerationPhase::Staging,
            GenerationPhase::Prepared,
            GenerationPhase::Committed,
        ] {
            let name = generation_name(phase, generation_id);
            assert_eq!(
                parse_generation_name(OsStr::new(&name)),
                Some(GenerationInventoryEntry {
                    phase,
                    generation_id
                })
            );
        }
        for invalid in [
            "staging-",
            "prepared-0123456789abcdef0123456789abcde",
            "committed-0123456789abcdef0123456789abcdef0",
            "staging-0123456789ABCDEF0123456789ABCDEF",
            "unknown-0123456789abcdef0123456789abcdef",
            "staging-00000000000000000000000000000000",
        ] {
            assert_eq!(parse_generation_name(OsStr::new(invalid)), None);
        }
    }

    #[test]
    fn object_names_cannot_escape_the_generation() {
        for valid in INSTALL_PIN_OBJECT_NAMES {
            assert!(validate_object_name(valid).is_ok());
        }
        for invalid in ["", ".", "..", "../gate", "nested/gate", "gate.pin"] {
            let error = validate_object_name(invalid).expect_err("invalid name");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(error.to_string(), "egress_fence_pin_store");
        }
    }

    #[test]
    fn only_noent_proves_a_published_old_name_disappeared() {
        assert!(require_name_absent(Err(rustix::io::Errno::NOENT)).is_ok());
        assert_eq!(
            require_name_absent(Ok(()))
                .expect_err("an opened old name is foreign")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            require_name_absent(Err(rustix::io::Errno::ACCESS))
                .expect_err("an inaccessible old name is ambiguous")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            require_name_absent(Err(rustix::io::Errno::IO))
                .expect_err("an I/O failure is ambiguous")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn inherited_store_identity_is_rejected_before_locking() {
        let directory = TestDirectory::new("process-identity");
        let mut store = test_store(directory.path());
        let inherited_process_id = std::process::id().wrapping_add(1).max(1);
        Arc::get_mut(&mut store.inner)
            .expect("unique test store")
            .owner_process_id = inherited_process_id;

        assert_eq!(
            store
                .lock()
                .expect_err("a process may not use an inherited OFD lock")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            store
                .verify_visible_identity()
                .expect_err("all inherited descriptor operations fail closed")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn pin_root_requires_bpffs_root_ownership_and_nonwritable_trust_boundary() {
        let valid_mode = rustix::fs::FileType::Directory.as_raw_mode() | 0o755;
        assert!(validate_pin_root_metadata(BPF_FS_MAGIC, 0, valid_mode, true).is_ok());

        for (filesystem, uid, mode, is_directory) in [
            (0, 0, 0o755, true),
            (BPF_FS_MAGIC, 1, 0o755, true),
            (BPF_FS_MAGIC, 0, 0o775, true),
            (BPF_FS_MAGIC, 0, 0o755, false),
        ] {
            let mode = rustix::fs::FileType::Directory.as_raw_mode() | mode;
            let error = validate_pin_root_metadata(filesystem, uid, mode, is_directory)
                .expect_err("untrusted root");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn generation_requires_exact_root_owned_private_directory_on_root_bpffs() {
        let directory_mode = rustix::fs::FileType::Directory.as_raw_mode() | 0o700;
        assert!(validate_generation_metadata(BPF_FS_MAGIC, 7, 7, 0, directory_mode, true).is_ok());

        for (filesystem, root_device, device, uid, mode, is_directory) in [
            (0, 7, 7, 0, directory_mode, true),
            (BPF_FS_MAGIC, 7, 8, 0, directory_mode, true),
            (BPF_FS_MAGIC, 7, 7, 1, directory_mode, true),
            (BPF_FS_MAGIC, 7, 7, 0, directory_mode | 0o050, true),
            (BPF_FS_MAGIC, 7, 7, 0, directory_mode | 0o4000, true),
            (BPF_FS_MAGIC, 7, 7, 0, directory_mode, false),
        ] {
            assert_eq!(
                validate_generation_metadata(
                    filesystem,
                    root_device,
                    device,
                    uid,
                    mode,
                    is_directory,
                )
                .expect_err("untrusted generation")
                .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn scan_is_descriptor_anchored_across_visible_path_replacement() {
        let temporary = TestDirectory::new("replacement");
        let visible = temporary.path().join("visible");
        let moved = temporary.path().join("moved");
        fs::create_dir(&visible).expect("create visible directory");
        let original_name = generation_name(GenerationPhase::Staging, generation(1));
        fs::create_dir(visible.join(&original_name)).expect("create original generation");
        let descriptor = open(
            &visible,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open visible descriptor");

        fs::rename(&visible, &moved).expect("move descriptor target");
        fs::create_dir(&visible).expect("create replacement path");
        let replacement_name = generation_name(GenerationPhase::Committed, generation(2));
        fs::create_dir(visible.join(replacement_name)).expect("create replacement generation");

        let entries =
            scan_generation_entries(&descriptor, MAX_GENERATIONS, |_| Ok(())).expect("scan");
        assert_eq!(
            entries,
            vec![GenerationInventoryEntry {
                phase: GenerationPhase::Staging,
                generation_id: generation(1),
            }]
        );
    }

    #[test]
    fn scanning_and_cleanup_classification_are_hard_bounded() {
        let temporary = TestDirectory::new("bound");
        for index in 1..=u8::try_from(MAX_GENERATIONS + 1).expect("small bound") {
            let name = generation_name(GenerationPhase::Staging, generation(index));
            fs::create_dir(temporary.path().join(name)).expect("create generation");
        }
        let descriptor = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open test directory");
        let error = scan_generation_entries(&descriptor, MAX_GENERATIONS, |_| Ok(()))
            .expect_err("over-bound scan");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let bounded = (1..=u8::try_from(MAX_GENERATIONS).expect("small bound"))
            .map(|index| GenerationInventoryEntry {
                phase: GenerationPhase::Staging,
                generation_id: generation(index),
            })
            .collect();
        let recovery = classify_recovery_entries(bounded).expect("bounded cleanup inventory");
        assert!(recovery.committed.is_none());
        assert!(recovery.prepared.is_none());
        assert_eq!(recovery.cleanup_candidates.len(), MAX_GENERATIONS);

        let over_bound = (1..=u8::try_from(MAX_GENERATIONS + 1).expect("small bound"))
            .map(|index| GenerationInventoryEntry {
                phase: GenerationPhase::Prepared,
                generation_id: generation(index),
            })
            .collect();
        assert_eq!(
            classify_recovery_entries(over_bound)
                .expect_err("over-bound cleanup inventory")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn multiple_committed_generations_are_ambiguous() {
        let entries = vec![
            GenerationInventoryEntry {
                phase: GenerationPhase::Committed,
                generation_id: generation(1),
            },
            GenerationInventoryEntry {
                phase: GenerationPhase::Committed,
                generation_id: generation(2),
            },
        ];
        let error = classify_recovery_entries(entries).expect_err("ambiguous committed state");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "egress_fence_pin_store");
    }

    #[test]
    fn prepared_is_durable_recovery_evidence_and_never_cleanup() {
        let prepared = GenerationInventoryEntry {
            phase: GenerationPhase::Prepared,
            generation_id: generation(1),
        };
        let staging = GenerationInventoryEntry {
            phase: GenerationPhase::Staging,
            generation_id: generation(2),
        };
        let recovery =
            classify_recovery_entries(vec![prepared, staging]).expect("unambiguous prepared state");
        assert_eq!(recovery.prepared, Some(prepared));
        assert!(recovery.committed.is_none());
        assert_eq!(recovery.cleanup_candidates, vec![staging]);

        let second_prepared = GenerationInventoryEntry {
            phase: GenerationPhase::Prepared,
            generation_id: generation(3),
        };
        assert_eq!(
            classify_recovery_entries(vec![prepared, second_prepared])
                .expect_err("multiple prepared generations are ambiguous")
                .kind(),
            io::ErrorKind::InvalidData
        );
        let committed = GenerationInventoryEntry {
            phase: GenerationPhase::Committed,
            generation_id: generation(4),
        };
        assert_eq!(
            classify_recovery_entries(vec![prepared, committed])
                .expect_err("prepared plus committed is ambiguous")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn known_object_scan_is_exact_and_bounded_before_cleanup() {
        let temporary = TestDirectory::new("known-objects");
        for object_name in INSTALL_PIN_OBJECT_NAMES {
            fs::write(temporary.path().join(object_name), []).expect("create known object");
        }
        let descriptor = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open object directory");
        let names = scan_known_object_names(&descriptor).expect("exact known object inventory");
        assert_eq!(names.len(), INSTALL_PIN_OBJECT_NAMES.len());

        fs::write(temporary.path().join("foreign"), []).expect("create foreign object");
        assert_eq!(
            scan_known_object_names(&descriptor)
                .expect_err("foreign object must preserve directory")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(temporary.path().join("foreign").exists());
        for object_name in INSTALL_PIN_OBJECT_NAMES {
            assert!(temporary.path().join(object_name).exists());
        }
    }

    #[test]
    fn object_paths_are_generation_descriptor_anchored() {
        let generation_descriptor =
            open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
                .expect("open generation test descriptor");
        let object = descriptor_object_path(&generation_descriptor, "OPC_FENCE_CKS");
        assert!(object.starts_with("/proc/self/fd"));
        assert_eq!(
            object.file_name().and_then(OsStr::to_str),
            Some("OPC_FENCE_CKS")
        );
    }

    #[test]
    fn cross_process_descriptor_lock_is_exclusive_and_released() {
        let temporary = TestDirectory::new("lock");
        let first = test_store(temporary.path());
        let second = test_store(temporary.path());

        let first_guard = first.lock().expect("first exclusive lock");
        let error = second.lock().expect_err("second descriptor must not lock");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(first_guard);
        drop(second.lock().expect("lock released with guard"));
    }

    #[test]
    fn descriptor_identity_rejects_path_replacement() {
        let temporary = TestDirectory::new("identity");
        let original = temporary.path().join("original");
        let replacement = temporary.path().join("replacement");
        fs::create_dir(&original).expect("create original");
        fs::create_dir(&replacement).expect("create replacement");
        let original = open(
            &original,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open original");
        let replacement = open(
            &replacement,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open replacement");
        assert_eq!(
            verify_same_directory(&original, &replacement)
                .expect_err("replacement identity")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(verify_same_directory(&original, &original).is_ok());
    }

    #[test]
    fn debug_never_exposes_paths_or_generation_ids() {
        let temporary = TestDirectory::new("debug");
        let store = test_store(temporary.path());
        assert_eq!(format!("{store:?}"), "FencePinStore(<redacted>)");
        let guard = store.lock().expect("debug guard");
        assert_eq!(format!("{guard:?}"), "FencePinStoreGuard(<redacted>)");
    }
}
