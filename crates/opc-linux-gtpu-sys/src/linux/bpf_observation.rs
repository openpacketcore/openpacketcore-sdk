use super::*;
use crate::bpf::{InspectionCall, InspectionError, MapIdentity, ProgramIdentity};

const BPF_MAP_GET_FD_BY_ID: u32 = 14;
const MAX_MAPS: usize = 1024;

// Stable Linux UAPI prefix through netns_ino. Pointers stay zero unless their
// corresponding user buffers are supplied and alive for the complete syscall.
#[repr(C, align(8))]
#[derive(Default)]
struct ProgramInfo {
    kind: u32,
    id: u32,
    tag: [u8; 8],
    jited_len: u32,
    xlated_len: u32,
    jited: u64,
    xlated: u64,
    load_time: u64,
    uid: u32,
    map_count: u32,
    maps: u64,
    name: [u8; 16],
    ifindex: u32,
    flags: u32,
    netns_dev: u64,
    netns_ino: u64,
}
#[repr(C, align(8))]
#[derive(Default)]
struct MapInfo {
    kind: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
    name: [u8; 16],
    ifindex: u32,
    btf_vmlinux_value_type_id: u32,
    netns_dev: u64,
    netns_ino: u64,
    btf_id: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_id: u32,
    map_extra: u64,
}
const _: () = {
    assert!(mem::size_of::<ProgramInfo>() == 104);
    assert!(mem::offset_of!(ProgramInfo, load_time) == 40);
    assert!(mem::offset_of!(ProgramInfo, map_count) == 52);
    assert!(mem::offset_of!(ProgramInfo, maps) == 56);
    assert!(mem::offset_of!(ProgramInfo, name) == 64);
    assert!(mem::size_of::<MapInfo>() == 88);
    assert!(mem::offset_of!(MapInfo, name) == 24);
    assert!(mem::offset_of!(MapInfo, map_extra) == 80);
};

fn invalid(call: InspectionCall) -> InspectionError {
    InspectionError::new(call, io::ErrorKind::InvalidData.into())
}

// This private function is called only with initialized UAPI structs above.
fn read_info<T>(fd: &OwnedFd, value: &mut T, call: InspectionCall) -> Result<(), InspectionError> {
    let mut attr = BpfObjGetInfoByFdAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: mem::size_of::<T>() as u32,
        info: (value as *mut T) as usize as u64,
    };
    // SAFETY: attr points to the initialized writable UAPI object. Any nested
    // buffers remain alive in the caller. The syscall retains no user pointer.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &mut attr as *mut BpfObjGetInfoByFdAttr,
            mem::size_of::<BpfObjGetInfoByFdAttr>(),
        )
    };
    if result < 0 {
        return Err(InspectionError::new(call, io::Error::last_os_error()));
    }
    if attr.info_len < mem::size_of::<T>() as u32 {
        return Err(invalid(call));
    }
    Ok(())
}

pub struct ObservedProgram {
    fd: OwnedFd,
}
impl ObservedProgram {
    pub fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, InspectionError> {
        fd.try_clone_to_owned()
            .map(|fd| Self { fd })
            .map_err(|error| InspectionError::new(InspectionCall::ProgramInfo, error))
    }
    pub(crate) fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
    pub fn open(id: u32) -> Result<Self, InspectionError> {
        open_bpf_object_by_id(BPF_PROG_GET_FD_BY_ID, id)
            .map(|fd| Self { fd })
            .map_err(|error| InspectionError::new(InspectionCall::OpenProgram, error))
    }
    pub fn info(&self) -> Result<ProgramIdentity, InspectionError> {
        let mut raw = ProgramInfo::default();
        read_info(&self.fd, &mut raw, InspectionCall::ProgramInfo)?;
        let count = raw.map_count as usize;
        if count > MAX_MAPS || raw.id == 0 || raw.kind == 0 || raw.name[15] != 0 {
            return Err(invalid(InspectionCall::ProgramInfo));
        }
        let mut ids = vec![0; count];
        let mut complete = ProgramInfo {
            map_count: raw.map_count,
            maps: ids.as_mut_ptr() as usize as u64,
            ..ProgramInfo::default()
        };
        read_info(&self.fd, &mut complete, InspectionCall::ProgramInfo)?;
        if complete.map_count != raw.map_count
            || complete.id != raw.id
            || complete.kind != raw.kind
            || complete.tag != raw.tag
            || complete.name != raw.name
            || complete.load_time != raw.load_time
            || complete.ifindex != raw.ifindex
        {
            return Err(invalid(InspectionCall::ProgramInfo));
        }
        ids.sort_unstable();
        if ids.contains(&0) || ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid(InspectionCall::ProgramInfo));
        }
        Ok(ProgramIdentity {
            id: raw.id,
            program_type: raw.kind,
            tag: raw.tag,
            name: raw.name,
            load_time_ns: raw.load_time,
            map_ids: ids,
            ifindex: raw.ifindex,
        })
    }
}

pub struct ObservedMap {
    fd: OwnedFd,
}

pub enum ObservedPin {
    Program(ObservedProgram),
    Map(ObservedMap),
}
impl ObservedPin {
    pub fn program(&self) -> Result<ObservedProgram, InspectionError> {
        match self {
            Self::Program(program) => ObservedProgram::from_fd(program.fd.as_fd()),
            Self::Map(_) => Err(invalid(InspectionCall::ProgramInfo)),
        }
    }
    pub fn map(&self) -> Result<ObservedMap, InspectionError> {
        match self {
            Self::Map(map) => ObservedMap::from_fd(map.fd.as_fd()),
            Self::Program(_) => Err(invalid(InspectionCall::MapInfo)),
        }
    }
    pub fn open(path: &Path) -> io::Result<Self> {
        let fd = open_bpf_link_from_pin(path)?;
        let mut contents = Vec::new();
        std::fs::File::open(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?
            .take(MAX_BPF_FDINFO_BYTES + 1)
            .read_to_end(&mut contents)?;
        if contents.len() as u64 > MAX_BPF_FDINFO_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let contents = std::str::from_utf8(&contents).map_err(|_| io::ErrorKind::InvalidData)?;
        match pin_kind(contents)? {
            PinKind::Map => Ok(Self::Map(ObservedMap { fd })),
            PinKind::Program => Ok(Self::Program(ObservedProgram { fd })),
        }
    }

    pub fn identity(&self) -> Result<crate::tc::PinnedIdentity, InspectionError> {
        match self {
            Self::Map(map) => map.info().map(crate::tc::PinnedIdentity::Map),
            Self::Program(program) => program.info().map(crate::tc::PinnedIdentity::Program),
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
enum PinKind {
    Map,
    Program,
}
fn pin_kind(contents: &str) -> io::Result<PinKind> {
    let mut kinds = contents
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter_map(|(key, _)| match key {
            "map_id" => Some(0),
            "prog_id" => Some(1),
            "link_id" => Some(2),
            _ => None,
        });
    let kind = kinds.next().ok_or(io::ErrorKind::InvalidData)?;
    if kinds.next().is_some() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    match kind {
        0 => Ok(PinKind::Map),
        1 => Ok(PinKind::Program),
        _ => Err(io::ErrorKind::Unsupported.into()),
    }
}

impl ObservedMap {
    pub fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, InspectionError> {
        fd.try_clone_to_owned()
            .map(|fd| Self { fd })
            .map_err(|error| InspectionError::new(InspectionCall::MapInfo, error))
    }
    pub fn try_clone_fd(&self) -> io::Result<OwnedFd> {
        self.fd.try_clone()
    }
    pub fn open(id: u32) -> Result<Self, InspectionError> {
        open_bpf_object_by_id(BPF_MAP_GET_FD_BY_ID, id)
            .map(|fd| Self { fd })
            .map_err(|error| InspectionError::new(InspectionCall::OpenMap, error))
    }
    pub fn info(&self) -> Result<MapIdentity, InspectionError> {
        let mut raw = MapInfo::default();
        read_info(&self.fd, &mut raw, InspectionCall::MapInfo)?;
        if raw.id == 0 || raw.kind == 0 || raw.name[15] != 0 {
            return Err(invalid(InspectionCall::MapInfo));
        }
        Ok(MapIdentity {
            id: raw.id,
            map_type: raw.kind,
            key_size: raw.key_size,
            value_size: raw.value_size,
            max_entries: raw.max_entries,
            flags: raw.flags,
            name: raw.name,
            ifindex: raw.ifindex,
            btf_vmlinux_value_type_id: raw.btf_vmlinux_value_type_id,
            btf_id: raw.btf_id,
            btf_key_type_id: raw.btf_key_type_id,
            btf_value_type_id: raw.btf_value_type_id,
            btf_vmlinux_id: raw.btf_vmlinux_id,
            map_extra: raw.map_extra,
            netns_dev: raw.netns_dev,
            netns_ino: raw.netns_ino,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::{self, GlobalObjectDisposition as Disposition};

    #[test]
    fn pinned_links_and_ambiguous_object_kinds_never_authorize_unpin() {
        assert_eq!(pin_kind("map_id:\t7\n").unwrap(), PinKind::Map);
        assert_eq!(pin_kind("prog_id:\t8\n").unwrap(), PinKind::Program);
        assert_eq!(
            pin_kind("link_id:\t9\n").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        for input in [
            "",
            "btf_id:\t9\n",
            "map_id: 1\nprog_id: 2\n",
            "map_id: 1\nmap_id: 1\n",
            "prog_id: 1\nlink_id: 1\n",
        ] {
            assert!(pin_kind(input).is_err());
        }
    }

    #[repr(C, align(8))]
    #[derive(Default)]
    struct Load {
        kind: u32,
        count: u32,
        instructions: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log: u64,
        version: u32,
        flags: u32,
        name: [u8; 16],
        ifindex: u32,
        attach_type: u32,
    }

    #[test]
    #[ignore = "requires CAP_BPF and writable private bpffs"]
    fn native_pin_replacement_cannot_unlink_a_new_inode_for_the_same_object() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
        let root =
            std::path::PathBuf::from(format!("/sys/fs/bpf/opc-local-pin-{}", std::process::id()));
        let lock_dir =
            std::env::temp_dir().join(format!("opc-local-pin-lock-{}", std::process::id()));
        struct Cleanup(std::path::PathBuf, std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let _cleanup = Cleanup(root.clone(), lock_dir.clone());
        for path in [&root, &root.join("maps"), &lock_dir] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let handles =
            std::sync::Arc::new(LocalScopeHandles::open(&root, &lock_dir.join("lock")).unwrap());
        let directory = LocalPinDirectory::open(std::sync::Arc::clone(&handles), Path::new("maps"))
            .unwrap()
            .unwrap();
        assert!(
            LocalPinDirectory::open(std::sync::Arc::clone(&handles), Path::new("missing"))
                .unwrap()
                .is_none()
        );
        let create = [2_u32, 4, 8, 1, 0];
        let fd =
            // SAFETY: create is an initialized BPF_MAP_CREATE prefix with no pointers.
            unsafe { libc::syscall(libc::SYS_bpf, 0, create.as_ptr(), mem::size_of_val(&create)) };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        // SAFETY: BPF_MAP_CREATE returned this fresh descriptor.
        let map = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let pin = || {
            let path = CString::new(root.join("maps/map").as_os_str().as_bytes()).unwrap();
            let request = BpfObjPinAttr {
                pathname: path.as_ptr() as usize as u64,
                bpf_fd: map.as_raw_fd() as u32,
                ..BpfObjPinAttr::default()
            };
            assert_eq!(
                // SAFETY: request and its NUL-terminated pathname stay alive.
                unsafe {
                    libc::syscall(
                        libc::SYS_bpf,
                        BPF_OBJ_PIN,
                        &request as *const BpfObjPinAttr,
                        mem::size_of::<BpfObjPinAttr>(),
                    )
                },
                0,
                "{}",
                io::Error::last_os_error()
            );
        };
        pin();
        let prior = directory.inspect("map").unwrap();
        let prior_identity = prior.identity().clone();
        prior.verify().unwrap();
        std::fs::remove_file(root.join("maps/map")).unwrap();
        pin();
        let replacement = directory.inspect("map").unwrap();
        assert_eq!(replacement.identity(), &prior_identity);
        assert!(
            prior.unlink(&handles).is_err(),
            "same object does not authorize a replaced pin inode"
        );
        replacement.verify().unwrap();
        replacement.unlink(&handles).unwrap();
        assert!(directory.entries().unwrap().is_empty());
        drop(handles);
        assert!(
            matches!(
                LocalScopeHandles::open(&root, &lock_dir.join("lock")),
                Err(crate::tc::ScopeError::Busy)
            ),
            "retained pins keep exclusion alive"
        );
    }

    #[test]
    #[ignore = "requires CAP_BPF/CAP_SYS_ADMIN"]
    fn native_observation_holds_descriptors_and_distinguishes_external_residue() {
        assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
        let mut create = [0_u32; 18];
        create[..4].copy_from_slice(&[2, 4, 8, 1]);
        let fd =
            // SAFETY: create is the zero-initialized map-create UAPI prefix, with
            // no nested pointers. A successful result is a fresh owned descriptor.
            unsafe { libc::syscall(libc::SYS_bpf, 0, create.as_ptr(), mem::size_of_val(&create)) };
        assert!(fd >= 0, "map create: {}", io::Error::last_os_error());
        // SAFETY: this is the fresh successful BPF_MAP_CREATE descriptor.
        let map_fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let mut raw_map = MapInfo::default();
        read_info(&map_fd, &mut raw_map, InspectionCall::MapInfo).unwrap();
        let mut instructions = [[0_u8; 8]; 4];
        instructions[0][0] = 0x18; // BPF_LD | BPF_DW | BPF_IMM
        instructions[0][1] = 0x11; // dst R1, BPF_PSEUDO_MAP_FD
        instructions[0][4..].copy_from_slice(&map_fd.as_raw_fd().to_ne_bytes());
        instructions[2][0] = 0xb7; // R0 = 0
        instructions[3][0] = 0x95; // exit
        let license = b"GPL\0";
        let load = Load {
            kind: 1,
            count: 4,
            instructions: instructions.as_ptr() as usize as u64,
            license: license.as_ptr() as usize as u64,
            name: *b"obs_owned\0\0\0\0\0\0\0",
            ..Load::default()
        };
        // SAFETY: load and its instruction/license buffers remain alive. No
        // pointer is retained by BPF_PROG_LOAD after the synchronous syscall.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                5,
                &load as *const Load,
                mem::size_of::<Load>(),
            )
        };
        assert!(fd >= 0, "program load: {}", io::Error::last_os_error());
        // SAFETY: this is the fresh successful BPF_PROG_LOAD descriptor.
        let program_fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let mut raw_program = ProgramInfo::default();
        read_info(&program_fd, &mut raw_program, InspectionCall::ProgramInfo).unwrap();
        let owned = bpf::ProgramHandle::open(raw_program.id).unwrap();
        let map = bpf::MapHandle::open(raw_map.id).unwrap();
        assert_eq!(owned.identity().map_ids, [raw_map.id]);
        assert_eq!(map.identity().map_type, 2);
        assert_eq!(map.identity().value_size, 8);
        assert!(owned.identity().load_time_ns > 0);
        let old_program = owned.identity().clone();
        let old_map = map.identity().clone();
        drop(program_fd);
        drop(map_fd);
        owned.recheck().unwrap();
        map.recheck().unwrap();
        let scan = bpf::programs(&[old_program.id]).unwrap();
        assert!(scan
            .iter()
            .any(|program| program.identity() == &old_program));
        drop(scan);
        let outside_observer = bpf::ProgramHandle::open(old_program.id).unwrap();
        drop(owned);
        drop(map);
        assert_eq!(
            bpf::observe_global_release(
                std::slice::from_ref(&old_program),
                std::slice::from_ref(&old_map)
            ),
            Disposition::StillReferencedOrUnproven
        );
        outside_observer.recheck().unwrap();
        drop(outside_observer);
        loop {
            if bpf::observe_global_release(
                std::slice::from_ref(&old_program),
                std::slice::from_ref(&old_map),
            ) == Disposition::GoneObserved
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
