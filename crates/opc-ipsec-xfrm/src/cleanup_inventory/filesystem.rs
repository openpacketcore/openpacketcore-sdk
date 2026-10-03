use std::{
    io::Write,
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::{Component, Path, PathBuf},
};

use rustix::fs::{
    flock, fstat, fsync, mkdirat, open, openat, renameat, unlinkat, AtFlags, Dir, FileType,
    FlockOperation, Mode, OFlags,
};

use super::{
    node::ciphertext_digest,
    store::{resource_bounds, NodeName, SnapshotIo},
    tree::{FormatBudget, InventoryLimits},
    InventoryError,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OpenMode {
    CreateNew,
    Reopen,
}

pub(super) struct DirectoryIo {
    root: OwnedFd,
    path: PathBuf,
    device: u64,
    inode: u64,
    owner: u32,
    process: u32,
    limits: InventoryLimits,
    format: FormatBudget,
    temporary: Option<std::fs::File>,
}

impl Drop for DirectoryIo {
    fn drop(&mut self) {
        // A fork-before-exec descriptor can outlive the owning writer's FD.
        // Only the original process may release their shared flock.
        if self.process == std::process::id() {
            let _ = flock(&self.root, FlockOperation::Unlock);
        }
    }
}

pub(super) struct ReadHandle {
    file: std::fs::File,
    device: u64,
    inode: u64,
    maximum: usize,
}

trait IdentityValue {
    fn identity(self) -> Result<u64, InventoryError>;
}
impl IdentityValue for u64 {
    fn identity(self) -> Result<u64, InventoryError> {
        Ok(self)
    }
}
impl IdentityValue for u32 {
    fn identity(self) -> Result<u64, InventoryError> {
        Ok(u64::from(self))
    }
}
impl IdentityValue for i64 {
    fn identity(self) -> Result<u64, InventoryError> {
        u64::try_from(self).map_err(|_| InventoryError::InvalidRoot)
    }
}
impl IdentityValue for i32 {
    fn identity(self) -> Result<u64, InventoryError> {
        u64::try_from(self).map_err(|_| InventoryError::InvalidRoot)
    }
}

fn validate_directory(metadata: &rustix::fs::Stat) -> Result<(), InventoryError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o700
        || metadata.st_nlink == 0
    {
        return Err(InventoryError::InvalidRoot);
    }
    Ok(())
}

fn open_directory_path(path: &Path) -> Result<OwnedFd, InventoryError> {
    // NOFOLLOW applies to one open's final component. Walk from a held root
    // descriptor so an earlier component cannot redirect create or reopen.
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open("/", flags, Mode::empty()).map_err(|_| InventoryError::InvalidRoot)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty())
                    .map_err(|_| InventoryError::InvalidRoot)?;
            }
            _ => return Err(InventoryError::InvalidRoot),
        }
        let metadata = fstat(&directory).map_err(|_| InventoryError::Storage)?;
        if !FileType::from_raw_mode(metadata.st_mode).is_dir()
            || metadata.st_nlink == 0
            || (metadata.st_mode & 0o022 != 0 && metadata.st_mode & 0o1000 == 0)
        {
            return Err(InventoryError::InvalidRoot);
        }
    }
    Ok(directory)
}

fn validate_file(
    metadata: &rustix::fs::Stat,
    owner: u32,
    maximum: usize,
) -> Result<usize, InventoryError> {
    let length = usize::try_from(metadata.st_size).map_err(|_| InventoryError::Malformed)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || metadata.st_uid != owner
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 1
    {
        return Err(InventoryError::Malformed);
    }
    if length > maximum {
        return Err(InventoryError::Capacity);
    }
    Ok(length)
}

fn node_name(name: NodeName) -> String {
    match name {
        NodeName::Root => String::from("root"),
        NodeName::Branch(position, slot) => format!("branch-{position:02x}-{slot}"),
        NodeName::Leaf(position, slot) => format!("leaf-{position:04x}-{slot}"),
        NodeName::Temporary => String::from("pending"),
    }
}

fn parse_name(bytes: &[u8]) -> Result<NodeName, InventoryError> {
    let name = std::str::from_utf8(bytes).map_err(|_| InventoryError::Malformed)?;
    let value = if name == "root" {
        NodeName::Root
    } else if name == "pending" {
        NodeName::Temporary
    } else {
        let (prefix, remainder) = name.split_once('-').ok_or(InventoryError::Malformed)?;
        let (position, slot) = remainder.split_once('-').ok_or(InventoryError::Malformed)?;
        let position = u32::from_str_radix(position, 16).map_err(|_| InventoryError::Malformed)?;
        let slot = slot.parse::<u8>().map_err(|_| InventoryError::Malformed)?;
        match prefix {
            "branch" => NodeName::Branch(position, slot),
            "leaf" => NodeName::Leaf(position, slot),
            _ => return Err(InventoryError::Malformed),
        }
    };
    if node_name(value) != name {
        return Err(InventoryError::Malformed);
    }
    Ok(value)
}

impl DirectoryIo {
    pub(super) fn open(
        path: &Path,
        mode: OpenMode,
        limits: InventoryLimits,
        format: FormatBudget,
    ) -> Result<Self, InventoryError> {
        let required = resource_bounds(limits, format)?;
        if required.content_bytes > limits.storage_bytes
            || required.index_bytes > limits.index_bytes
            || required.working_bytes > limits.working_bytes
        {
            return Err(InventoryError::Capacity);
        }
        if !path.is_absolute()
            || path.as_os_str().as_bytes().len() > 4096
            || !path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(InventoryError::InvalidRoot);
        }
        let parent = path.parent().ok_or(InventoryError::InvalidRoot)?;
        let child = path.file_name().ok_or(InventoryError::InvalidRoot)?;
        let parent_descriptor = open_directory_path(parent)?;
        if mode == OpenMode::CreateNew {
            mkdirat(&parent_descriptor, child, Mode::from_bits_truncate(0o700))
                .map_err(|_| InventoryError::InvalidRoot)?;
        }
        let root = openat(
            &parent_descriptor,
            child,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| InventoryError::InvalidRoot)?;
        let metadata = fstat(&root).map_err(|_| InventoryError::Storage)?;
        validate_directory(&metadata)?;
        flock(&root, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                InventoryError::StoreBusy
            } else {
                InventoryError::Storage
            }
        })?;
        let result = Self {
            root,
            path: path.to_owned(),
            device: metadata.st_dev.identity()?,
            inode: metadata.st_ino.identity()?,
            owner: metadata.st_uid,
            process: std::process::id(),
            limits,
            format,
            temporary: None,
        };
        result.check_binding()?;
        if mode == OpenMode::CreateNew {
            // Persist the new directory's entry before publishing any root.
            fsync(&parent_descriptor).map_err(|_| InventoryError::Storage)?;
        }
        Ok(result)
    }

    pub(super) fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    fn maximum(&self, name: NodeName) -> Result<usize, InventoryError> {
        let required = resource_bounds(self.limits, self.format)?;
        match name {
            NodeName::Root => Ok(self.format.root_bytes),
            NodeName::Branch(position, slot)
                if u64::from(position) < required.branch_files && slot < 2 =>
            {
                Ok(self.format.manifest_bytes)
            }
            NodeName::Leaf(position, slot)
                if u64::from(position) < required.leaf_files && slot < 2 =>
            {
                self.format.leaf_frame_bytes()
            }
            NodeName::Temporary => Ok(self
                .format
                .root_bytes
                .max(self.format.manifest_bytes)
                .max(self.format.leaf_frame_bytes()?)),
            _ => Err(InventoryError::Malformed),
        }
    }

    fn open_file(&self, name: NodeName) -> Result<OwnedFd, InventoryError> {
        openat(
            &self.root,
            node_name(name).as_str(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| InventoryError::Storage)
    }

    fn read_file(&self, file: &std::fs::File, maximum: usize) -> Result<Vec<u8>, InventoryError> {
        let metadata = fstat(file).map_err(|_| InventoryError::Storage)?;
        let length = validate_file(&metadata, self.owner, maximum)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| InventoryError::Allocation)?;
        bytes.resize(length, 0);
        let mut offset = 0;
        while offset < length {
            let count = rustix::io::pread(
                file,
                &mut bytes[offset..],
                u64::try_from(offset).map_err(|_| InventoryError::Capacity)?,
            )
            .map_err(|_| InventoryError::Storage)?;
            if count == 0 {
                return Err(InventoryError::Malformed);
            }
            offset = offset.checked_add(count).ok_or(InventoryError::Capacity)?;
        }
        let mut extra = [0_u8; 1];
        if rustix::io::pread(
            file,
            &mut extra,
            u64::try_from(length).map_err(|_| InventoryError::Capacity)?,
        )
        .map_err(|_| InventoryError::Storage)?
            != 0
        {
            return Err(InventoryError::Malformed);
        }
        let after = fstat(file).map_err(|_| InventoryError::Storage)?;
        if validate_file(&after, self.owner, maximum)? != length
            || after.st_dev != metadata.st_dev
            || after.st_ino != metadata.st_ino
        {
            return Err(InventoryError::WrongBinding);
        }
        Ok(bytes)
    }

    fn verify_named_file(
        &self,
        file: &std::fs::File,
        name: NodeName,
    ) -> Result<(), InventoryError> {
        let held = fstat(file).map_err(|_| InventoryError::Storage)?;
        validate_file(&held, self.owner, self.maximum(name)?)?;
        let visible = self.open_file(name)?;
        let observed = fstat(&visible).map_err(|_| InventoryError::Storage)?;
        validate_file(&observed, self.owner, self.maximum(name)?)?;
        if held.st_dev != observed.st_dev || held.st_ino != observed.st_ino {
            return Err(InventoryError::WrongBinding);
        }
        Ok(())
    }
}

impl SnapshotIo for DirectoryIo {
    type Handle = ReadHandle;

    fn check_binding(&self) -> Result<(), InventoryError> {
        if self.process != std::process::id() {
            return Err(InventoryError::WrongBinding);
        }
        let held = fstat(&self.root).map_err(|_| InventoryError::Storage)?;
        validate_directory(&held)?;
        let visible = open_directory_path(&self.path)?;
        let observed = fstat(&visible).map_err(|_| InventoryError::Storage)?;
        validate_directory(&observed)?;
        if observed.st_dev.identity()? != self.device
            || observed.st_ino.identity()? != self.inode
            || held.st_dev != observed.st_dev
            || held.st_ino != observed.st_ino
            || observed.st_uid != self.owner
        {
            return Err(InventoryError::WrongBinding);
        }
        Ok(())
    }

    fn account(&self, limits: InventoryLimits, format: FormatBudget) -> Result<(), InventoryError> {
        self.check_binding()?;
        if limits != self.limits || format != self.format {
            return Err(InventoryError::WrongBinding);
        }
        let required = resource_bounds(limits, format)?;
        let mut count = 0_u64;
        let mut bytes = 0_u64;
        let directory = Dir::read_from(&self.root).map_err(|_| InventoryError::Storage)?;
        for entry in directory {
            let entry = entry.map_err(|_| InventoryError::Storage)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            count = count.checked_add(1).ok_or(InventoryError::Capacity)?;
            if count > required.file_count {
                return Err(InventoryError::Capacity);
            }
            let name = parse_name(name)?;
            let maximum = self.maximum(name)?;
            let file = self.open_file(name)?;
            let metadata = fstat(&file).map_err(|_| InventoryError::Storage)?;
            let length = validate_file(&metadata, self.owner, maximum)?;
            bytes = bytes
                .checked_add(u64::try_from(length).map_err(|_| InventoryError::Capacity)?)
                .ok_or(InventoryError::Capacity)?;
            if bytes > limits.storage_bytes {
                return Err(InventoryError::Capacity);
            }
        }
        Ok(())
    }

    fn read(
        &self,
        name: NodeName,
        maximum: usize,
    ) -> Result<(Self::Handle, Vec<u8>), InventoryError> {
        self.check_binding()?;
        let maximum = maximum.min(self.maximum(name)?);
        let file = std::fs::File::from(self.open_file(name)?);
        let metadata = fstat(&file).map_err(|_| InventoryError::Storage)?;
        let bytes = self.read_file(&file, maximum)?;
        let handle = ReadHandle {
            file,
            device: metadata.st_dev.identity()?,
            inode: metadata.st_ino.identity()?,
            maximum,
        };
        Ok((handle, bytes))
    }

    fn stabilize_root(
        &mut self,
        handle: &Self::Handle,
        digest: [u8; 32],
    ) -> Result<(), InventoryError> {
        self.check_binding()?;
        self.verify_named_file(&handle.file, NodeName::Root)?;
        let metadata = fstat(&handle.file).map_err(|_| InventoryError::Storage)?;
        if metadata.st_dev.identity()? != handle.device
            || metadata.st_ino.identity()? != handle.inode
            || ciphertext_digest(&self.read_file(&handle.file, handle.maximum)?) != digest
        {
            return Err(InventoryError::WrongBinding);
        }
        fsync(&handle.file).map_err(|_| InventoryError::Storage)
    }

    fn write_temporary(&mut self, bytes: &[u8]) -> Result<(), InventoryError> {
        self.check_binding()?;
        if self.temporary.is_some() || bytes.len() > self.maximum(NodeName::Temporary)? {
            return Err(InventoryError::Capacity);
        }
        let file = openat(
            &self.root,
            node_name(NodeName::Temporary).as_str(),
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| InventoryError::Storage)?;
        self.temporary = Some(std::fs::File::from(file));
        let file = self.temporary.as_mut().ok_or(InventoryError::Storage)?;
        file.write_all(bytes).map_err(|_| InventoryError::Storage)?;
        validate_file(
            &fstat(&*file).map_err(|_| InventoryError::Storage)?,
            self.owner,
            bytes.len(),
        )?;
        Ok(())
    }

    fn sync_temporary(&mut self) -> Result<(), InventoryError> {
        self.check_binding()?;
        let file = self.temporary.as_ref().ok_or(InventoryError::Storage)?;
        self.verify_named_file(file, NodeName::Temporary)?;
        fsync(file).map_err(|_| InventoryError::Storage)
    }

    fn rename_temporary(&mut self, destination: NodeName) -> Result<(), InventoryError> {
        self.check_binding()?;
        if destination == NodeName::Temporary {
            return Err(InventoryError::Malformed);
        }
        let file = self.temporary.as_ref().ok_or(InventoryError::Storage)?;
        self.verify_named_file(file, NodeName::Temporary)?;
        validate_file(
            &fstat(file).map_err(|_| InventoryError::Storage)?,
            self.owner,
            self.maximum(destination)?,
        )?;
        // A destination may be absent or a previously bounded regular slot.
        match openat(
            &self.root,
            node_name(destination).as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(existing) => {
                validate_file(
                    &fstat(&existing).map_err(|_| InventoryError::Storage)?,
                    self.owner,
                    self.maximum(destination)?,
                )?;
            }
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(_) => return Err(InventoryError::Storage),
        }
        renameat(
            &self.root,
            node_name(NodeName::Temporary).as_str(),
            &self.root,
            node_name(destination).as_str(),
        )
        .map_err(|_| InventoryError::Storage)?;
        self.temporary = None;
        Ok(())
    }

    fn sync_directory(&mut self) -> Result<(), InventoryError> {
        self.check_binding()?;
        fsync(&self.root).map_err(|_| InventoryError::Storage)
    }

    fn remove_temporary(&mut self) -> Result<(), InventoryError> {
        self.check_binding()?;
        if self.temporary.is_some() {
            return Err(InventoryError::Unavailable);
        }
        match openat(
            &self.root,
            node_name(NodeName::Temporary).as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => {
                validate_file(
                    &fstat(&file).map_err(|_| InventoryError::Storage)?,
                    self.owner,
                    self.maximum(NodeName::Temporary)?,
                )?;
            }
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
            Err(_) => return Err(InventoryError::Storage),
        }
        unlinkat(
            &self.root,
            node_name(NodeName::Temporary).as_str(),
            AtFlags::empty(),
        )
        .map_err(|_| InventoryError::Storage)
    }
}

#[cfg(test)]
mod tests;
