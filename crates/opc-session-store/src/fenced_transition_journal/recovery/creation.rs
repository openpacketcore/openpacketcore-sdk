//! Publish a complete recovery journal, retaining checked directory identity.

use super::*;
use std::{ffi::OsStr, ffi::OsString, fs::File, os::unix::ffi::OsStrExt};

use nix::{
    errno::Errno,
    fcntl::{AtFlags, Flock, FlockArg},
    sys::stat::fstatat,
    unistd::{unlinkat, UnlinkatFlags},
};

use super::super::{is_private_bounded_file, sqlite_descriptor_path, PreparedJournalPath};

pub(super) struct Creation {
    parent: File,
    staged: OsString,
    final_name: OsString,
    prefix: String,
    directory_lock: Option<Flock<File>>,
}

fn prefix(leaf: &OsStr) -> String {
    let digest = Sha256::digest(leaf.as_bytes());
    format!(".opc-v2-recovery-{}-", crate::hex::encode_lower(&digest))
}

fn lock_parent(parent: &File) -> Result<Flock<File>, StoreError> {
    #[cfg(test)]
    if REFUSE_DIRECTORY_LOCK.with(std::cell::Cell::get) {
        return Err(ownership::lock_error(Errno::EOPNOTSUPP));
    }
    Flock::lock(
        parent.try_clone().map_err(|_| recovery_unavailable())?,
        FlockArg::LockExclusiveNonblock,
    )
    .map_err(|(_, error)| ownership::lock_error(error))
}

#[cfg(test)]
thread_local! {
    pub(super) static REFUSE_DIRECTORY_LOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn remove_staging_file(parent: &File, name: &OsStr) -> Result<(), StoreError> {
    let metadata = match fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(Errno::ENOENT) => return Ok(()),
        Err(_) => return Err(recovery_unavailable()),
    };
    let bound = if name.as_bytes().ends_with(b"-wal") {
        RECOVERY_WAL_MAX_BYTES
    } else if name.as_bytes().ends_with(b"-shm") {
        RECOVERY_SHM_MAX_BYTES
    } else {
        RECOVERY_MAIN_MAX_BYTES
    };
    if !is_private_bounded_file(&metadata, nix::unistd::geteuid().as_raw(), bound) {
        return Err(recovery_unavailable());
    }
    unlinkat(parent, name, UnlinkatFlags::NoRemoveDir).map_err(|_| recovery_unavailable())
}

fn cleanup_stale(parent: &File, prefix: &str, keep: Option<&OsStr>) -> Result<(), StoreError> {
    let directory =
        sqlite_descriptor_path(parent, OsStr::new(".")).map_err(|_| recovery_unavailable())?;
    for entry in std::fs::read_dir(directory).map_err(|_| recovery_unavailable())? {
        let name = entry.map_err(|_| recovery_unavailable())?.file_name();
        if name.as_bytes().starts_with(prefix.as_bytes()) && keep != Some(name.as_os_str()) {
            remove_staging_file(parent, &name)?;
        }
    }
    parent.sync_all().map_err(|_| recovery_unavailable())
}

pub(super) fn prepare(
    final_path: &Path,
    bounds: SecureJournalFileBounds,
) -> Result<(PreparedJournalPath, Creation), StoreError> {
    let final_name = final_path.file_name().ok_or_else(recovery_unavailable)?;
    if [b"-wal".as_slice(), b"-shm", b"-journal"]
        .iter()
        .any(|suffix| final_name.as_bytes().ends_with(suffix))
    {
        return Err(recovery_unavailable());
    }
    let prefix = prefix(final_name);
    let staged = OsString::from(format!("{prefix}{}.stage", uuid::Uuid::new_v4()));
    let mut path = prepare_secure_journal_path_with_bounds(
        &final_path.with_file_name(&staged),
        JournalOpenMode::CreateNew,
        bounds,
    )
    .map_err(recovery_path_error)?;
    // Row authentication names the final checked path, never the transient
    // staging name. Both names share the same held private directory.
    path.binding_path.set_file_name(final_name);
    let mut creation = Creation {
        parent: path
            .path_guard
            .parent
            .try_clone()
            .map_err(|_| recovery_unavailable())?,
        staged,
        final_name: final_name.to_os_string(),
        prefix,
        directory_lock: None,
    };
    creation.directory_lock = Some(lock_parent(&creation.parent)?);
    match fstatat(&creation.parent, final_name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(Errno::ENOENT) => {}
        _ => return Err(recovery_unavailable()),
    }
    cleanup_stale(&creation.parent, &creation.prefix, Some(&creation.staged))?;
    path.path_guard
        .verify()
        .map_err(|_| recovery_unavailable())?;
    Ok((path, creation))
}

impl Creation {
    /// SQLite has checkpointed and closed before this method. The ownership
    /// descriptor and process-local inode lease remain held across rename.
    pub(super) fn publish(&self, path: &mut PreparedJournalPath) -> Result<(), StoreError> {
        use nix::{fcntl::openat, fcntl::OFlag, sys::stat::fstat, sys::stat::Mode};
        path.path_guard
            .verify()
            .map_err(|_| recovery_unavailable())?;
        let file = File::from(
            openat(
                &self.parent,
                self.staged.as_os_str(),
                OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| recovery_unavailable())?,
        );
        if !path
            .path_guard
            .leaf_identity
            .matches(&fstat(&file).map_err(|_| recovery_unavailable())?)
        {
            return Err(recovery_unavailable());
        }
        file.sync_all().map_err(|_| recovery_unavailable())?;
        drop(file);
        #[cfg(test)]
        creation_crash_point("synced");
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "redox"
        ))]
        rustix::fs::renameat_with(
            &self.parent,
            &self.staged,
            &self.parent,
            &self.final_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| recovery_unavailable())?;
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "redox"
        )))]
        {
            // All SDK recovery creators hold this directory lock. Other
            // writers are excluded by the private-directory contract.
            if !matches!(
                fstatat(
                    &self.parent,
                    self.final_name.as_os_str(),
                    AtFlags::AT_SYMLINK_NOFOLLOW
                ),
                Err(Errno::ENOENT)
            ) {
                return Err(recovery_unavailable());
            }
            rustix::fs::renameat(&self.parent, &self.staged, &self.parent, &self.final_name)
                .map_err(|_| recovery_unavailable())?;
        }
        path.path_guard.leaf_name.clone_from(&self.final_name);
        path.sqlite_path = sqlite_descriptor_path(&path.path_guard.parent, &self.final_name)
            .map_err(|_| recovery_unavailable())?;
        #[cfg(test)]
        creation_crash_point("published");
        path.path_guard
            .verify()
            .map_err(|_| recovery_unavailable())?;
        self.parent.sync_all().map_err(|_| recovery_unavailable())?;
        #[cfg(test)]
        creation_crash_point("directory_synced");
        Ok(())
    }
}

impl Drop for Creation {
    fn drop(&mut self) {
        // Initialization failures are also self-cleaning. An actual process
        // crash skips Drop; the next create/open cleans this exact namespace.
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut name = self.staged.clone();
            name.push(suffix);
            let _ = remove_staging_file(&self.parent, &name);
        }
        let _ = self.parent.sync_all();
    }
}

pub(super) fn cleanup_after_open(path: &PreparedJournalPath) -> Result<(), StoreError> {
    let parent = &path.path_guard.parent;
    let _lock = match lock_parent(parent) {
        Ok(lock) => lock,
        // A live creator owns its temporary files and will clean them itself.
        Err(error) if error == recovery_owner_locked() => return Ok(()),
        Err(error) => return Err(error),
    };
    let leaf = path
        .binding_path
        .file_name()
        .ok_or_else(recovery_unavailable)?;
    cleanup_stale(parent, &prefix(leaf), None)
}
