//! Shared local SQLite file admission for separate configuration authority and
//! consumer-checkpoint lifecycles. File presence is never protocol authority.

use crate::{RetainedConfigError, SqliteBackend};
use rusqlite::{Connection, OpenFlags};
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Own the admitted lock, rather than relying on the last OS descriptor close.
/// A concurrent preflight child can inherit this file description until exec.
/// Only the final SDK owner releases it; failed acquisition owns no unlock.
pub(crate) struct AdmissionFileLock(File);

impl AdmissionFileLock {
    #[cfg(unix)]
    pub(crate) fn acquire(file: File) -> Result<Self, RetainedConfigError> {
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |error| {
                if error == rustix::io::Errno::WOULDBLOCK {
                    RetainedConfigError::InUse
                } else {
                    RetainedConfigError::Unavailable
                }
            },
        )?;
        Ok(Self(file))
    }
}

impl std::ops::Deref for AdmissionFileLock {
    type Target = File;

    fn deref(&self) -> &File {
        &self.0
    }
}

impl Drop for AdmissionFileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
    }
}

/// The shared connection wrapper retains admission through SQLite close,
/// including when an outstanding blocking operation outlives its caller.
pub(crate) struct FileAdmission {
    pub(crate) path: PathBuf,
    pub(crate) parent: File,
    pub(crate) lock: AdmissionFileLock,
    pub(crate) database: File,
    pub(crate) identity: [u64; 6],
}

impl FileAdmission {
    #[cfg(unix)]
    pub(crate) fn read_back(&self) -> Result<(), RetainedConfigError> {
        reject_symlink_components(&self.path)?;
        let parent = self.path.parent().ok_or(RetainedConfigError::Rejected)?;
        let identity = file_identity(&self.parent, &self.lock, &self.database)?;
        if identity != self.identity
            || identity_for_path(parent, true)? != identity[0..2]
            || identity_for_path(&lock_path(&self.path), false)? != identity[2..4]
            || identity_for_path(&self.path, false)? != identity[4..6]
        {
            return Err(RetainedConfigError::Rejected);
        }
        Ok(())
    }
}

pub(crate) fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".opc-retained");
    PathBuf::from(name)
}

#[cfg(unix)]
pub(crate) fn open_file(
    path: &Path,
    writable: bool,
    directory: bool,
) -> Result<File, RetainedConfigError> {
    let mut flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                RetainedConfigError::RecoveryRequired
            } else {
                RetainedConfigError::Rejected
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|_| RetainedConfigError::Unavailable)?;
    if metadata.is_dir() != directory
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        || metadata.mode() & 0o022 != 0
    {
        return Err(RetainedConfigError::Rejected);
    }
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn identity_for_path(
    path: &Path,
    directory: bool,
) -> Result<[u64; 2], RetainedConfigError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| RetainedConfigError::Rejected)?;
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        || metadata.mode() & 0o022 != 0
    {
        return Err(RetainedConfigError::Rejected);
    }
    Ok([metadata.dev(), metadata.ino()])
}

#[cfg(unix)]
pub(crate) fn file_identity(
    parent: &File,
    lock: &File,
    database: &File,
) -> Result<[u64; 6], RetainedConfigError> {
    let parent = parent
        .metadata()
        .map_err(|_| RetainedConfigError::Unavailable)?;
    let lock = lock
        .metadata()
        .map_err(|_| RetainedConfigError::Unavailable)?;
    let database = database
        .metadata()
        .map_err(|_| RetainedConfigError::Unavailable)?;
    Ok([
        parent.dev(),
        parent.ino(),
        lock.dev(),
        lock.ino(),
        database.dev(),
        database.ino(),
    ])
}

pub(crate) fn reject_symlink_components(path: &Path) -> Result<(), RetainedConfigError> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        if matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        ) {
            return Err(RetainedConfigError::InvalidRequest);
        }
        prefix.push(component);
        match std::fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RetainedConfigError::Rejected)
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && prefix == path => {}
            Err(_) => return Err(RetainedConfigError::RecoveryRequired),
        }
    }
    Ok(())
}

pub(crate) fn open_sqlite(path: &Path) -> Result<Connection, RetainedConfigError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| RetainedConfigError::Rejected)?;
    if conn
        .is_readonly(rusqlite::MAIN_DB)
        .map_err(|_| RetainedConfigError::Rejected)?
    {
        return Err(RetainedConfigError::Rejected);
    }
    conn.busy_timeout(Duration::from_millis(u64::from(
        SqliteBackend::SQLITE_BUSY_TIMEOUT_MS,
    )))
    .map_err(|_| RetainedConfigError::Unavailable)?;
    Ok(conn)
}
