//! Descriptor-anchored bpffs generation publication and recovery inventory.

use std::{
    ffi::OsStr,
    fmt, fs, io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    sync::Arc,
};

use rand::{rngs::SysRng, TryRng};
use rustix::fs::{
    fstat, fstatfs, fsync, mkdirat, open, openat, renameat_with, unlinkat, FileType, Mode, OFlags,
    RenameFlags, Stat, UnlinkatFlags,
};

use crate::install_manifest::InstallGenerationId;

const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
const MAX_GENERATIONS: usize = 32;
const GENERATION_HEX_BYTES: usize = 32;
const CREATE_ATTEMPTS: usize = 4;

/// Trusted, existing bpffs directory dedicated to egress-fence generations.
pub(crate) struct FencePinStore {
    inner: Arc<PinStoreInner>,
}

struct PinStoreInner {
    path: PathBuf,
    descriptor: OwnedFd,
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
            &metadata,
            FileType::from_raw_mode(metadata.st_mode).is_dir(),
        )?;
        let store = Self {
            inner: Arc::new(PinStoreInner {
                path: path.to_path_buf(),
                descriptor,
            }),
        };
        store.scan()?;
        Ok(store)
    }

    pub(crate) fn scan(&self) -> io::Result<Vec<GenerationInventoryEntry>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.inner.path).map_err(redact_io)? {
            if entries.len() >= MAX_GENERATIONS {
                return Err(pin_store_error(io::ErrorKind::InvalidData));
            }
            let entry = entry.map_err(redact_io)?;
            let file_type = entry.file_type().map_err(redact_io)?;
            if !file_type.is_dir() {
                return Err(pin_store_error(io::ErrorKind::InvalidData));
            }
            let name = entry.file_name();
            let parsed = parse_generation_name(&name)
                .ok_or_else(|| pin_store_error(io::ErrorKind::InvalidData))?;
            entries.push(parsed);
        }
        entries.sort_unstable_by_key(|entry| (entry.phase, entry.generation_id.bytes()));
        Ok(entries)
    }

    pub(crate) fn create_staging(&self) -> io::Result<GenerationDirectory> {
        if self.scan()?.len() >= MAX_GENERATIONS {
            return Err(pin_store_error(io::ErrorKind::OutOfMemory));
        }
        for _ in 0..CREATE_ATTEMPTS {
            let generation_id = random_generation_id()?;
            let name = generation_name(GenerationPhase::Staging, generation_id);
            match mkdirat(
                self.inner.descriptor.as_fd(),
                name.as_str(),
                Mode::from_bits_truncate(0o700),
            ) {
                Ok(()) => {
                    fsync(&self.inner.descriptor).map_err(redact_io)?;
                    let directory = open_generation_directory(&self.inner, &name)?;
                    if self.scan()?.len() > MAX_GENERATIONS {
                        drop(directory);
                        let _ = unlinkat(
                            self.inner.descriptor.as_fd(),
                            name.as_str(),
                            UnlinkatFlags::REMOVEDIR,
                        );
                        return Err(pin_store_error(io::ErrorKind::OutOfMemory));
                    }
                    return Ok(GenerationDirectory {
                        store: Arc::clone(&self.inner),
                        generation_id,
                        phase: GenerationPhase::Staging,
                        name,
                        descriptor: directory,
                    });
                }
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => return Err(redact_io(error)),
            }
        }
        Err(pin_store_error(io::ErrorKind::AlreadyExists))
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
        Ok(self.store.path.join(&self.name).join(object_name))
    }

    pub(crate) fn publish_prepared(self) -> io::Result<Self> {
        self.publish(GenerationPhase::Prepared)
    }

    pub(crate) fn publish_committed(self) -> io::Result<Self> {
        self.publish(GenerationPhase::Committed)
    }

    fn publish(mut self, target: GenerationPhase) -> io::Result<Self> {
        if !matches!(
            (self.phase, target),
            (GenerationPhase::Staging, GenerationPhase::Prepared)
                | (GenerationPhase::Prepared, GenerationPhase::Committed)
        ) {
            return Err(pin_store_error(io::ErrorKind::InvalidInput));
        }
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
        let before = fstat(&self.descriptor).map_err(io::Error::from)?;
        let after = fstat(&reopened).map_err(io::Error::from)?;
        if before.st_ino != after.st_ino || before.st_dev != after.st_dev {
            return Err(pin_store_error(io::ErrorKind::InvalidData));
        }
        if openat(
            self.store.descriptor.as_fd(),
            self.name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .is_ok()
        {
            return Err(pin_store_error(io::ErrorKind::InvalidData));
        }

        self.phase = target;
        self.name = target_name;
        self.descriptor = reopened;
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

fn validate_pin_root_metadata(
    filesystem_type: u64,
    metadata: &Stat,
    is_directory: bool,
) -> io::Result<()> {
    let group_or_other_writable = metadata.st_mode & 0o022 != 0;
    if filesystem_type != BPF_FS_MAGIC
        || !is_directory
        || metadata.st_uid != 0
        || group_or_other_writable
    {
        return Err(pin_store_error(io::ErrorKind::InvalidData));
    }
    Ok(())
}

fn open_generation_directory(store: &PinStoreInner, name: &str) -> io::Result<OwnedFd> {
    let descriptor = openat(
        store.descriptor.as_fd(),
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(redact_io)?;
    let filesystem = fstatfs(&descriptor).map_err(io::Error::from)?;
    let metadata = fstat(&descriptor).map_err(io::Error::from)?;
    if filesystem.f_type as u64 != BPF_FS_MAGIC
        || !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_uid != 0
        || metadata.st_mode & 0o077 != 0
    {
        return Err(pin_store_error(io::ErrorKind::InvalidData));
    }
    Ok(descriptor)
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

    #[test]
    fn generation_names_are_exact_lowercase_and_round_trip() {
        let generation_id = InstallGenerationId::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98,
            0xba, 0xdc, 0xfe,
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
        for valid in ["manifest", "opc_fence_gate", "OPC_FENCE_CKS"] {
            assert!(validate_object_name(valid).is_ok());
        }
        for invalid in ["", ".", "..", "../gate", "nested/gate", "gate.pin"] {
            let error = validate_object_name(invalid).expect_err("invalid name");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(error.to_string(), "egress_fence_pin_store");
        }
    }

    #[test]
    fn pin_root_requires_bpffs_root_ownership_and_nonwritable_trust_boundary() {
        let valid = Stat {
            st_uid: 0,
            st_mode: rustix::fs::FileType::Directory.as_raw_mode() | 0o755,
            ..unsafe { std::mem::zeroed() }
        };
        assert!(validate_pin_root_metadata(BPF_FS_MAGIC, &valid, true).is_ok());

        for (filesystem, uid, mode, is_directory) in [
            (0, 0, 0o755, true),
            (BPF_FS_MAGIC, 1, 0o755, true),
            (BPF_FS_MAGIC, 0, 0o775, true),
            (BPF_FS_MAGIC, 0, 0o755, false),
        ] {
            let mut mutated = valid;
            mutated.st_uid = uid;
            mutated.st_mode = rustix::fs::FileType::Directory.as_raw_mode() | mode;
            let error = validate_pin_root_metadata(filesystem, &mutated, is_directory)
                .expect_err("untrusted root");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn debug_never_exposes_paths_or_generation_ids() {
        let store = FencePinStore {
            inner: Arc::new(PinStoreInner {
                path: PathBuf::from("/secret/bpffs/path"),
                descriptor: open(
                    "/dev/null",
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .expect("open test descriptor"),
            }),
        };
        assert_eq!(format!("{store:?}"), "FencePinStore(<redacted>)");
    }
}
