use super::*;
use crate::linux::bpf_observation::ObservedPin;
use crate::tc::PinnedIdentity;
use std::sync::Arc;

pub struct LocalPinDirectory {
    handles: Arc<LocalScopeHandles>,
    relative: PathBuf,
    file: File,
    identity: Identity,
}
pub struct LocalPin {
    directory: Arc<LocalPinDirectory>,
    name: String,
    inode: Identity,
    inode_file: File,
    object: ObservedPin,
    identity: PinnedIdentity,
}

fn directory_entries(file: &File) -> Result<Vec<String>, ScopeError> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path).map_err(ScopeError::from)? {
        let name = entry
            .map_err(ScopeError::from)?
            .file_name()
            .into_string()
            .map_err(|_| ScopeError::Conflict)?;
        if entries.len() == 256 || name.is_empty() {
            return Err(ScopeError::Conflict);
        }
        entries.push(name);
    }
    entries.sort();
    if entries.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ScopeError::Inspection);
    }
    Ok(entries)
}

impl LocalScopeHandles {
    pub fn root_entries(&self) -> Result<Vec<String>, ScopeError> {
        self.verify()?;
        let entries = directory_entries(&self.root)?;
        self.verify()?;
        Ok(entries)
    }
}

fn relative_components(path: &Path) -> Result<Vec<&std::ffi::OsStr>, ScopeError> {
    if path
        .as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(ScopeError::InvalidSpec);
    }
    let components = path
        .components()
        .map(|part| match part {
            std::path::Component::Normal(name) if !name.as_bytes().contains(&0) => Ok(name),
            _ => Err(ScopeError::InvalidSpec),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() || components.len() > 8 || path.as_os_str().as_bytes().len() > 1024 {
        return Err(ScopeError::InvalidSpec);
    }
    Ok(components)
}

fn open_relative(handles: &LocalScopeHandles, relative: &Path) -> Result<Option<File>, ScopeError> {
    let mut parent = handles.root.try_clone().map_err(ScopeError::from)?;
    for part in relative_components(relative)? {
        let name = CString::new(part.as_bytes()).map_err(|_| ScopeError::InvalidSpec)?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: 0x01 | 0x02 | 0x04 | 0x08, // NO_XDEV | NO_MAGICLINKS | NO_SYMLINKS | BENEATH
        };
        // SAFETY: parent is held and name/how are valid across openat2. No
        // symlink or mount crossing can escape the held private root.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent.as_raw_fd(),
                name.as_ptr(),
                &how as *const OpenHow,
                mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(ScopeError::from(error));
        }
        // SAFETY: openat2 returned this fresh owned descriptor.
        let child = unsafe { File::from_raw_fd(fd as i32) };
        let child_identity = identity(&child)?;
        if !child_identity.private_directory()
            || child_identity.mount != handles.root_identity.mount
        {
            return Err(ScopeError::Conflict);
        }
        parent = child;
    }
    Ok(Some(parent))
}

fn leaf_identity(parent: &File, name: &str) -> Result<Option<Identity>, ScopeError> {
    let name = CString::new(name).map_err(|_| ScopeError::InvalidSpec)?;
    // SAFETY: zero initializes the complete statx output object.
    let mut output: linux_raw_sys::general::statx = unsafe { mem::zeroed() };
    // SAFETY: parent, the leaf C string and complete Linux UAPI output buffer
    // stay alive. The direct syscall also works with musl's libc bindings.
    let result = unsafe {
        libc::syscall(
            libc::SYS_statx,
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | AT_STATX_DONT_SYNC,
            REQUIRED_STAT,
            &mut output as *mut linux_raw_sys::general::statx,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(ScopeError::from(error));
    }
    if output.stx_mask & REQUIRED_STAT != REQUIRED_STAT || output.stx_mnt_id == 0 {
        return Err(ScopeError::Unsupported);
    }
    Ok(Some(Identity {
        major: output.stx_dev_major,
        minor: output.stx_dev_minor,
        inode: output.stx_ino,
        mount: output.stx_mnt_id,
        mode: output.stx_mode,
        uid: output.stx_uid,
        links: output.stx_nlink,
    }))
}

impl LocalPinDirectory {
    pub fn create(
        handles: Arc<LocalScopeHandles>,
        relative: &Path,
    ) -> Result<Arc<Self>, ScopeError> {
        let components = relative_components(relative)?;
        handles.verify()?;
        let mut parent = handles.root.try_clone().map_err(ScopeError::from)?;
        let mut prefix = PathBuf::new();
        for component in components {
            handles.verify()?;
            if !prefix.as_os_str().is_empty() {
                let current = open_relative(&handles, &prefix)?.ok_or(ScopeError::Conflict)?;
                if !identity(&current)?.same_object(identity(&parent)?) {
                    return Err(ScopeError::Conflict);
                }
            }
            prefix.push(component);
            if let Some(child) = open_relative(&handles, &prefix)? {
                parent = child;
                continue;
            }
            let name = CString::new(component.as_bytes()).map_err(|_| ScopeError::InvalidSpec)?;
            // SAFETY: the bounded single component and retained directory FD
            // remain valid. No absolute path, symlink or mount crossing is
            // used. Existing objects are never chmodded or repaired.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(ScopeError::from(error));
                }
            }
            parent = open_relative(&handles, &prefix)?.ok_or(ScopeError::Conflict)?;
        }
        let result = Self::open(handles, relative)?.ok_or(ScopeError::Conflict)?;
        if !result.identity.same_object(identity(&parent)?) {
            return Err(ScopeError::Conflict);
        }
        result.verify()?;
        Ok(result)
    }
    pub fn descriptor_path(&self) -> Result<PathBuf, ScopeError> {
        self.verify()?;
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.file.as_raw_fd()
        )))
    }
    pub fn open(
        handles: Arc<LocalScopeHandles>,
        relative: &Path,
    ) -> Result<Option<Arc<Self>>, ScopeError> {
        handles.verify()?;
        let Some(file) = open_relative(&handles, relative)? else {
            handles.verify()?;
            return Ok(None);
        };
        let id = identity(&file)?;
        let result = Arc::new(Self {
            handles,
            relative: relative.to_owned(),
            file,
            identity: id,
        });
        result.verify()?;
        Ok(Some(result))
    }
    pub fn verify(&self) -> Result<(), ScopeError> {
        self.handles.verify()?;
        let current = open_relative(&self.handles, &self.relative)?.ok_or(ScopeError::Conflict)?;
        if !self.identity.same_object(identity(&current)?)
            || !self.identity.same_object(identity(&self.file)?)
        {
            return Err(ScopeError::Conflict);
        }
        Ok(())
    }
    pub fn entries(&self) -> Result<Vec<String>, ScopeError> {
        self.verify()?;
        let entries = directory_entries(&self.file)?;
        self.verify()?;
        Ok(entries)
    }
    pub fn inspect(self: &Arc<Self>, name: &str) -> Result<LocalPin, ScopeError> {
        if relative_components(Path::new(name))?.len() != 1 {
            return Err(ScopeError::InvalidSpec);
        }
        self.verify()?;
        let inode = leaf_identity(&self.file, name)?.ok_or(ScopeError::Conflict)?;
        if inode.mount != self.identity.mount
            || inode.uid != self.identity.uid
            || inode.mode as u32 != libc::S_IFREG | 0o600
            || inode.links != 1
        {
            return Err(ScopeError::Conflict);
        }
        let leaf = CString::new(name).map_err(|_| ScopeError::InvalidSpec)?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: 0x01 | 0x02 | 0x04 | 0x08,
        };
        // SAFETY: the relative leaf and open_how remain valid; O_PATH retains
        // the pin inode itself without opening it as a different BPF object.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.file.as_raw_fd(),
                leaf.as_ptr(),
                &how as *const OpenHow,
                mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(ScopeError::from(io::Error::last_os_error()));
        }
        // SAFETY: openat2 returned this fresh owned descriptor.
        let inode_file = unsafe { File::from_raw_fd(fd as i32) };
        if identity(&inode_file)? != inode {
            return Err(ScopeError::Conflict);
        }
        let path = PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd())).join(name);
        let object = ObservedPin::open(&path).map_err(ScopeError::from)?;
        let identity = object.identity().map_err(|_| ScopeError::Inspection)?;
        let pin = LocalPin {
            directory: Arc::clone(self),
            name: name.to_owned(),
            inode,
            inode_file,
            object,
            identity,
        };
        pin.verify()?;
        Ok(pin)
    }
}
impl LocalPin {
    pub fn program(&self) -> Result<crate::platform::ObservedProgram, ScopeError> {
        self.verify()?;
        self.object.program().map_err(|_| ScopeError::Inspection)
    }
    pub fn map(&self) -> Result<crate::platform::ObservedMap, ScopeError> {
        self.verify()?;
        self.object.map().map_err(|_| ScopeError::Inspection)
    }
    pub fn identity(&self) -> &PinnedIdentity {
        &self.identity
    }
    pub fn verify(&self) -> Result<(), ScopeError> {
        self.directory.verify()?;
        if leaf_identity(&self.directory.file, &self.name)? != Some(self.inode)
            || identity(&self.inode_file)? != self.inode
            || self.object.identity().map_err(|_| ScopeError::Inspection)? != self.identity
        {
            return Err(ScopeError::Conflict);
        }
        let path = PathBuf::from(format!("/proc/self/fd/{}", self.directory.file.as_raw_fd()))
            .join(&self.name);
        let current = ObservedPin::open(&path).map_err(ScopeError::from)?;
        if current.identity().map_err(|_| ScopeError::Inspection)? != self.identity {
            return Err(ScopeError::Conflict);
        }
        if leaf_identity(&self.directory.file, &self.name)? != Some(self.inode) {
            return Err(ScopeError::Conflict);
        }
        Ok(())
    }
    pub fn unlink(&self, handles: &Arc<LocalScopeHandles>) -> Result<(), ScopeError> {
        if !Arc::ptr_eq(handles, &self.directory.handles) {
            return Err(ScopeError::Conflict);
        }
        self.verify()?;
        let name = CString::new(self.name.as_str()).map_err(|_| ScopeError::InvalidSpec)?;
        // SAFETY: the validated one-component name is relative to the held
        // verified directory. The caller retains lifetime writer exclusion.
        if unsafe { libc::unlinkat(self.directory.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(ScopeError::from(io::Error::last_os_error()));
        }
        self.directory.verify()?;
        if leaf_identity(&self.directory.file, &self.name)?.is_some() {
            return Err(ScopeError::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pin_paths_are_bounded_normal_relative_components() {
        for bad in [
            "",
            ".",
            "..",
            "../map",
            "/root",
            "a/../map",
            "a/./map",
            "a\0b",
            "a/b/c/d/e/f/g/h/i",
        ] {
            assert!(relative_components(Path::new(bad)).is_err(), "{bad:?}");
        }
        assert_eq!(relative_components(Path::new("gtpu/lo")).unwrap().len(), 2);
    }
}
