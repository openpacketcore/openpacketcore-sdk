//! Ordinary fixed-store selection and descriptor-bound native reopen.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use super::super::{self as consensus, SqliteConsensusCore};
use super::{invalid_data, Binding, IoControl, Limits, Wal};

pub(super) const ROOT_BYTES: u64 = 168;
const ROOT_MAGIC: &[u8; 8] = b"OPCNR001";
const SELECTION_ATTRIBUTE: &str = "user.opc.native-root-v1";

fn read_selection(database: &File) -> io::Result<Option<[u8; ROOT_BYTES as usize]>> {
    let mut bytes = [0; ROOT_BYTES as usize];
    match rustix::fs::fgetxattr(database, SELECTION_ATTRIBUTE, &mut bytes[..]) {
        Ok(len) if len == bytes.len() => Ok(Some(bytes)),
        Ok(_) => Err(invalid_data("native database selection extent differs")),
        Err(rustix::io::Errno::NODATA) => Ok(None),
        // Ordinary SQLite may use a filesystem without user attributes.
        // Selecting native storage there still fails at the durable write.
        Err(rustix::io::Errno::OPNOTSUPP) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn open_directory(path: &Path) -> io::Result<Arc<File>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    if !file.metadata()?.is_dir() {
        return Err(invalid_data("native parent is not a directory"));
    }
    Ok(Arc::new(file))
}

pub(super) fn pin_directory(path: &Path) -> io::Result<Arc<File>> {
    let file = open_directory(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700 {
        return Err(invalid_data("native directory ownership or mode differs"));
    }
    Ok(file)
}

pub(super) fn directory_path(file: &File) -> PathBuf {
    // The final dot names the directory itself, allowing O_NOFOLLOW on each
    // child without resolving the consumer's mutable parent pathname again.
    PathBuf::from(format!("/proc/self/fd/{}/.", file.as_raw_fd()))
}

/// Clones share a sticky selection and the current live owner. An absent,
/// incomplete or closed selected owner cannot dispatch to the SQLite basis.
pub(crate) struct NativeOwner {
    parent: Arc<File>,
    database: File,
    database_name: OsString,
    database_identity: (u64, u64),
    native_name: OsString,
    selected: AtomicBool,
    current: Mutex<Weak<Wal>>,
}

impl NativeOwner {
    pub(crate) fn discover(path: &Path, conn: &Connection) -> io::Result<Self> {
        let parent = open_directory(
            path.parent()
                .ok_or_else(|| invalid_data("native database parent missing"))?,
        )?;
        let database_name = path
            .file_name()
            .ok_or_else(|| invalid_data("native database name missing"))?
            .to_os_string();
        let mut native_name = database_name.clone();
        native_name.push(".native-wal");
        let file = opc_sqlite_file_control_sys::main_file_descriptor(conn)
            .map_err(|_| invalid_data("native database descriptor unavailable"))?;
        let metadata = file.metadata()?;
        let named = fs::symlink_metadata(directory_path(&parent).join(&database_name))?;
        if !metadata.is_file() || !named.is_file() || identity(&metadata) != identity(&named) {
            return Err(invalid_data(
                "native database descriptor differs from namespace",
            ));
        }
        let namespace_exists =
            match fs::symlink_metadata(directory_path(&parent).join(&native_name)) {
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            };
        let selected = read_selection(&file)?.is_some() || namespace_exists;
        Ok(Self {
            parent,
            database: file,
            database_name,
            database_identity: identity(&metadata),
            native_name,
            selected: AtomicBool::new(selected),
            current: Mutex::new(Weak::new()),
        })
    }

    pub(crate) fn selected(&self) -> bool {
        if self.selected.load(Ordering::Acquire) {
            return true;
        }
        // Another ordinary backend may have selected this database since
        // this handle opened. Once discovered, selection stays irreversible.
        if !matches!(read_selection(&self.database), Ok(None)) {
            self.select();
            return true;
        }
        match fs::symlink_metadata(directory_path(&self.parent).join(&self.native_name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            _ => {
                self.select();
                true
            }
        }
    }

    pub(crate) fn select(&self) {
        self.selected.store(true, Ordering::Release);
    }

    pub(crate) fn current(&self) -> io::Result<Arc<Wal>> {
        self.current
            .lock()
            .map_err(|_| invalid_data("native owner slot poisoned"))?
            .upgrade()
            .ok_or_else(|| invalid_data("native owner unavailable"))
    }

    fn verify_database(&self, core: &SqliteConsensusCore) -> io::Result<()> {
        let database = core
            .database_file
            .as_ref()
            .ok_or_else(|| invalid_data("native database pin missing"))?;
        let metadata = database.file().metadata()?;
        let named = fs::symlink_metadata(directory_path(&self.parent).join(&self.database_name))?;
        if !named.is_file()
            || identity(&metadata) != self.database_identity
            || identity(&named) != self.database_identity
        {
            return Err(invalid_data("native database namespace changed"));
        }
        Ok(())
    }

    pub(crate) async fn attach_with_descriptors<V, F>(
        &self,
        core: &mut SqliteConsensusCore,
        validate: impl FnOnce(Vec<consensus::CurrentSnapshot>, Option<consensus::CurrentSnapshot>) -> F,
        verify: impl FnOnce(&V) -> io::Result<()>,
        install_source: impl FnOnce(&V) -> Option<&super::snapshot::InstallSource>,
    ) -> io::Result<()>
    where
        F: std::future::Future<Output = io::Result<V>>,
    {
        if !self.selected()
            || core.private_wal.is_some()
            || core.authority_profile != consensus::ConsensusAuthorityProfile::FixedImmutable
        {
            return Err(invalid_data("native fixed owner admission differs"));
        }
        self.verify_database(core)?;
        let conn = core.conn.lock().await;
        let path = directory_path(&self.parent).join(&self.native_name);
        let existing = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let wal = if existing {
            let pin = pin_directory(&path)?;
            let binding = self.read_root(&pin, core.storage_identity)?;
            let opening = super::native::Opening::new(
                &directory_path(&pin),
                binding,
                core.configured_roster_root.clone(),
                Limits::default(),
                IoControl::default(),
            )?;
            let descriptors = validate(opening.snapshots(), opening.install_candidate()).await?;
            opening
                .finish_with_install_source(install_source(&descriptors), || verify(&descriptors))?
        } else {
            if !core.fresh_native_basis || read_selection(&self.database)?.is_some() {
                return Err(invalid_data(
                    "existing fixed storage is missing its native root",
                ));
            }
            let descriptors = validate(Vec::new(), None).await?;
            verify(&descriptors)?;
            let mut generation = [0; 32];
            generation[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            generation[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            let wal = Wal::create_native_with_root(
                &path,
                &conn,
                core.storage_identity,
                generation,
                core.configured_roster_root.clone(),
                Limits::default(),
                IoControl::default(),
            )?;
            self.write_root(&wal)?;
            wal
        };
        self.verify_database(core)?;
        let placement = core
            .fixed_placement_policy
            .ok_or_else(|| invalid_data("native fixed placement missing"))?;
        wal.native_fixed_read(
            core.storage_identity,
            &core.expected_members,
            &core.expected_bindings,
            placement,
            true,
            None,
            |_, exact| {
                if exact {
                    Ok(())
                } else {
                    Err(invalid_data("native configured authority differs"))
                }
            },
        )?;
        core.applied_progress
            .send_replace(wal.with_native_read(|state| Ok(state.applied()))?);
        let wal = Arc::new(wal);
        *self
            .current
            .lock()
            .map_err(|_| invalid_data("native owner slot poisoned"))? = Arc::downgrade(&wal);
        core.private_wal = Some(wal);
        Ok(())
    }

    fn write_root(&self, wal: &Wal) -> io::Result<()> {
        let directory = wal
            .directory_pin
            .as_ref()
            .ok_or_else(|| invalid_data("native directory pin missing"))?;
        let directory_identity = identity(&directory.metadata()?);
        let mut bytes = [0; ROOT_BYTES as usize];
        bytes[..8].copy_from_slice(ROOT_MAGIC);
        for (chunk, value) in bytes[8..40].chunks_exact_mut(8).zip([
            self.database_identity.0,
            self.database_identity.1,
            directory_identity.0,
            directory_identity.1,
        ]) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        bytes[40..72].copy_from_slice(&wal.binding.generation);
        bytes[72..104].copy_from_slice(&wal.binding.basis);
        bytes[104..136].copy_from_slice(&wal.binding.digest()?);
        let checksum = Sha256::digest(&bytes[..136]);
        bytes[136..].copy_from_slice(&checksum);
        let mut file = super::file_create(&directory_path(directory).join("ROOT"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        directory.sync_all()?;
        self.parent.sync_all()?;
        // Retain the complete ROOT proof on the actual database inode,
        // independently of the removable native namespace and its spelling.
        // CREATE prevents replacing a prior selection. The inode sync must
        // finish before publishing a live owner or admitting any native work.
        rustix::fs::fsetxattr(
            &self.database,
            SELECTION_ATTRIBUTE,
            &bytes,
            rustix::fs::XattrFlags::CREATE,
        )?;
        self.database.sync_all()
    }

    fn read_root(
        &self,
        directory: &File,
        identity_expected: consensus::SessionConsensusIdentity,
    ) -> io::Result<Binding> {
        let mut file = super::file_read(&directory_path(directory).join("ROOT"))?;
        let metadata = file.metadata()?;
        if metadata.len() != ROOT_BYTES
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(invalid_data(
                "native root record extent or ownership differs",
            ));
        }
        let mut bytes = [0; ROOT_BYTES as usize];
        file.read_exact(&mut bytes)?;
        if read_selection(&self.database)? != Some(bytes) {
            return Err(invalid_data(
                "native root differs from durable database selection",
            ));
        }
        if &bytes[..8] != ROOT_MAGIC || Sha256::digest(&bytes[..136])[..] != bytes[136..] {
            return Err(invalid_data("native root record proof differs"));
        }
        let directory_identity = identity(&directory.metadata()?);
        for (chunk, expected) in bytes[8..40].chunks_exact(8).zip([
            self.database_identity.0,
            self.database_identity.1,
            directory_identity.0,
            directory_identity.1,
        ]) {
            if chunk != expected.to_be_bytes() {
                return Err(invalid_data("native root namespace identity differs"));
            }
        }
        let mut generation = [0; 32];
        let mut basis = [0; 32];
        generation.copy_from_slice(&bytes[40..72]);
        basis.copy_from_slice(&bytes[72..104]);
        let binding = Binding {
            identity: identity_expected,
            generation,
            basis,
            native: true,
        };
        if binding.digest()? != bytes[104..136] {
            return Err(invalid_data("native root authority binding differs"));
        }
        Ok(binding)
    }
}
