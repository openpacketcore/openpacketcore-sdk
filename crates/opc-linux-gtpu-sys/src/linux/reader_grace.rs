use std::io;
use std::mem;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};

const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_ARRAY_OF_MAPS: u32 = 12;

/// Stable BPF_MAP_CREATE prefix through inner_map_fd. The kernel zero-extends
/// omitted optional fields. Both maps are unnamed, unpinned, and one-entry.
#[repr(C, align(8))]
#[derive(Default)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
}

#[repr(C, align(8))]
#[derive(Default)]
struct MapElementAttr {
    map_fd: u32,
    reserved: u32,
    key: u64,
    value: u64,
    flags: u64,
}

const _: () = {
    assert!(mem::size_of::<MapCreateAttr>() == 24);
    assert!(mem::offset_of!(MapCreateAttr, inner_map_fd) == 20);
    assert!(mem::size_of::<MapElementAttr>() == 32);
    assert!(mem::offset_of!(MapElementAttr, key) == 8);
    assert!(mem::offset_of!(MapElementAttr, value) == 16);
    assert!(mem::offset_of!(MapElementAttr, flags) == 24);
};

pub struct BpfMapReaderGrace {
    outer: OwnedFd,
    inner: OwnedFd,
}

impl BpfMapReaderGrace {
    pub fn new() -> io::Result<Self> {
        let inner = create_map(BPF_MAP_TYPE_ARRAY, 4, 0)?;
        let outer = create_map(
            BPF_MAP_TYPE_ARRAY_OF_MAPS,
            4,
            super::fd_number(inner.as_fd())?,
        )?;
        Ok(Self { outer, inner })
    }

    pub fn synchronize(&self) -> io::Result<()> {
        let key = 0_u32;
        let inner_fd = super::fd_number(self.inner.as_fd())?;
        let attr = MapElementAttr {
            map_fd: super::fd_number(self.outer.as_fd())?,
            key: &key as *const u32 as u64,
            value: &inner_fd as *const u32 as u64,
            ..MapElementAttr::default()
        };
        // SAFETY: attr is the initialized BPF_MAP_UPDATE_ELEM layout. Its
        // aligned key/value pointers and both owned FDs remain live throughout
        // this synchronous syscall. ARRAY_OF_MAPS copies the inner FD value.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_UPDATE_ELEM,
                &attr as *const MapElementAttr,
                mem::size_of::<MapElementAttr>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn create_map(map_type: u32, value_size: u32, inner_map_fd: u32) -> io::Result<OwnedFd> {
    let attr = MapCreateAttr {
        map_type,
        key_size: 4,
        value_size,
        max_entries: 1,
        inner_map_fd,
        ..MapCreateAttr::default()
    };
    // SAFETY: attr is the initialized stable BPF_MAP_CREATE prefix, with all
    // optional fields omitted/zero. A negative result is checked before a
    // unique owner is constructed for the fresh descriptor.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const MapCreateAttr,
            mem::size_of::<MapCreateAttr>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: BPF_MAP_CREATE returned this fresh FD and it has no other owner.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

#[cfg(test)]
mod tests;
