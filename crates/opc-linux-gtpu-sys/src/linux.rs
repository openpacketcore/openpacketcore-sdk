use std::ffi::CString;
use std::io::{self, Read};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use crate::{BpfCgroupProgramAttachment, BpfXdpLinkInfo, GtpuIpAddress, GtpuUdpBind};

const BPF_OBJ_PIN: libc::c_uint = 6;
const BPF_OBJ_GET: libc::c_uint = 7;
const BPF_PROG_ATTACH: libc::c_uint = 8;
const BPF_PROG_DETACH: libc::c_uint = 9;
const BPF_PROG_GET_FD_BY_ID: libc::c_uint = 13;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_uint = 15;
const BPF_PROG_QUERY: libc::c_uint = 16;
const BPF_MAP_FREEZE: libc::c_uint = 22;
const BPF_LINK_UPDATE: libc::c_uint = 29;
const BPF_LINK_GET_FD_BY_ID: libc::c_uint = 30;
const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_LINK_TYPE_XDP: u32 = 6;
const BPF_CGROUP_INET_EGRESS: u32 = 1;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;
const BPF_F_REPLACE: u32 = 1 << 2;
const BPF_CGROUP_MAX_PROGS: usize = 64;
const CGROUP_REVISION_PROBE_SENTINEL: u64 = u64::MAX;
const NANOS_PER_SECOND: u64 = 1_000_000_000;
const MAX_BPF_FDINFO_BYTES: u64 = 16_384;

pub struct BootTimeTimer {
    fd: OwnedFd,
}

impl BootTimeTimer {
    pub fn new(duration: Duration) -> io::Result<Self> {
        let specification = relative_timer_specification(duration)?;
        // SAFETY: `timerfd_create` has no pointer arguments. The returned
        // descriptor is checked before ownership is constructed.
        let raw_fd = unsafe {
            libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `timerfd_create` returned this fresh descriptor and no other
        // owner has been constructed for it.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        set_relative_timer(fd.as_raw_fd(), &specification)?;
        Ok(Self { fd })
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }

    pub fn consume_expirations(&self) -> io::Result<u64> {
        read_timer_expirations(self.fd.as_raw_fd())
    }
}

#[repr(C)]
#[derive(Debug, Default)]
struct BpfGetFdByIdAttr {
    object_id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C, align(8))]
#[derive(Debug, Default)]
struct BpfObjPinAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    path_fd: i32,
    reserved: u32,
}

#[repr(C, align(8))]
#[derive(Debug, Default)]
struct BpfObjGetInfoByFdAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C, align(8))]
#[derive(Debug, Default)]
struct BpfLinkUpdateAttr {
    link_fd: u32,
    new_program_fd: u32,
    flags: u32,
    old_program_fd: u32,
}

#[repr(C, align(8))]
#[derive(Debug, Default)]
struct BpfProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
    relative_fd: u32,
    expected_revision: u64,
}

#[repr(C, align(8))]
#[derive(Debug, Default)]
struct BpfProgQueryAttr {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    program_ids: u64,
    program_count: u32,
    reserved: u32,
    program_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct BpfMapFreezeAttr {
    map_fd: u32,
}

#[derive(Debug)]
struct DirectCgroupProgramRequest {
    command: libc::c_uint,
    attr: BpfProgAttachAttr,
}

/// Stable prefix of `struct bpf_link_info` through `xdp.ifindex`.
#[repr(C, align(8))]
#[derive(Debug, Default)]
struct BpfXdpLinkInfoRaw {
    link_type: u32,
    link_id: u32,
    program_id: u32,
    _union_alignment_padding: u32,
    ifindex: u32,
    _tail_padding: u32,
}

/// Stable prefix of `struct bpf_prog_info` through `tag`.
#[repr(C)]
#[derive(Debug, Default)]
struct BpfProgramInfoRaw {
    program_type: u32,
    program_id: u32,
    tag: [u8; 8],
}

const _: () = {
    assert!(mem::size_of::<BpfGetFdByIdAttr>() == 12);
    assert!(mem::align_of::<BpfGetFdByIdAttr>() == 4);
    assert!(mem::offset_of!(BpfGetFdByIdAttr, object_id) == 0);
    assert!(mem::offset_of!(BpfGetFdByIdAttr, next_id) == 4);
    assert!(mem::offset_of!(BpfGetFdByIdAttr, open_flags) == 8);
    assert!(mem::size_of::<BpfObjPinAttr>() == 24);
    assert!(mem::align_of::<BpfObjPinAttr>() == 8);
    assert!(mem::offset_of!(BpfObjPinAttr, pathname) == 0);
    assert!(mem::offset_of!(BpfObjPinAttr, bpf_fd) == 8);
    assert!(mem::offset_of!(BpfObjPinAttr, file_flags) == 12);
    assert!(mem::offset_of!(BpfObjPinAttr, path_fd) == 16);
    assert!(mem::offset_of!(BpfObjPinAttr, reserved) == 20);
    assert!(mem::size_of::<BpfObjGetInfoByFdAttr>() == 16);
    assert!(mem::align_of::<BpfObjGetInfoByFdAttr>() == 8);
    assert!(mem::offset_of!(BpfObjGetInfoByFdAttr, bpf_fd) == 0);
    assert!(mem::offset_of!(BpfObjGetInfoByFdAttr, info_len) == 4);
    assert!(mem::offset_of!(BpfObjGetInfoByFdAttr, info) == 8);
    assert!(mem::size_of::<BpfLinkUpdateAttr>() == 16);
    assert!(mem::align_of::<BpfLinkUpdateAttr>() == 8);
    assert!(mem::offset_of!(BpfLinkUpdateAttr, link_fd) == 0);
    assert!(mem::offset_of!(BpfLinkUpdateAttr, new_program_fd) == 4);
    assert!(mem::offset_of!(BpfLinkUpdateAttr, flags) == 8);
    assert!(mem::offset_of!(BpfLinkUpdateAttr, old_program_fd) == 12);
    assert!(mem::size_of::<BpfProgAttachAttr>() == 32);
    assert!(mem::align_of::<BpfProgAttachAttr>() == 8);
    assert!(mem::offset_of!(BpfProgAttachAttr, target_fd) == 0);
    assert!(mem::offset_of!(BpfProgAttachAttr, attach_bpf_fd) == 4);
    assert!(mem::offset_of!(BpfProgAttachAttr, attach_type) == 8);
    assert!(mem::offset_of!(BpfProgAttachAttr, attach_flags) == 12);
    assert!(mem::offset_of!(BpfProgAttachAttr, replace_bpf_fd) == 16);
    assert!(mem::offset_of!(BpfProgAttachAttr, relative_fd) == 20);
    assert!(mem::offset_of!(BpfProgAttachAttr, expected_revision) == 24);
    assert!(mem::size_of::<BpfProgQueryAttr>() == 64);
    assert!(mem::align_of::<BpfProgQueryAttr>() == 8);
    assert!(mem::offset_of!(BpfProgQueryAttr, target_fd) == 0);
    assert!(mem::offset_of!(BpfProgQueryAttr, attach_type) == 4);
    assert!(mem::offset_of!(BpfProgQueryAttr, query_flags) == 8);
    assert!(mem::offset_of!(BpfProgQueryAttr, attach_flags) == 12);
    assert!(mem::offset_of!(BpfProgQueryAttr, program_ids) == 16);
    assert!(mem::offset_of!(BpfProgQueryAttr, program_count) == 24);
    assert!(mem::offset_of!(BpfProgQueryAttr, reserved) == 28);
    assert!(mem::offset_of!(BpfProgQueryAttr, program_attach_flags) == 32);
    assert!(mem::offset_of!(BpfProgQueryAttr, link_ids) == 40);
    assert!(mem::offset_of!(BpfProgQueryAttr, link_attach_flags) == 48);
    assert!(mem::offset_of!(BpfProgQueryAttr, revision) == 56);
    assert!(mem::size_of::<BpfMapFreezeAttr>() == 4);
    assert!(mem::align_of::<BpfMapFreezeAttr>() == 4);
    assert!(mem::offset_of!(BpfMapFreezeAttr, map_fd) == 0);
    assert!(mem::size_of::<BpfXdpLinkInfoRaw>() == 24);
    assert!(mem::align_of::<BpfXdpLinkInfoRaw>() == 8);
    assert!(mem::offset_of!(BpfXdpLinkInfoRaw, link_type) == 0);
    assert!(mem::offset_of!(BpfXdpLinkInfoRaw, link_id) == 4);
    assert!(mem::offset_of!(BpfXdpLinkInfoRaw, program_id) == 8);
    assert!(mem::offset_of!(BpfXdpLinkInfoRaw, _union_alignment_padding) == 12);
    assert!(mem::offset_of!(BpfXdpLinkInfoRaw, ifindex) == 16);
    assert!(mem::offset_of!(BpfXdpLinkInfoRaw, _tail_padding) == 20);
    assert!(mem::size_of::<BpfProgramInfoRaw>() == 16);
    assert!(mem::align_of::<BpfProgramInfoRaw>() == 4);
    assert!(mem::offset_of!(BpfProgramInfoRaw, program_type) == 0);
    assert!(mem::offset_of!(BpfProgramInfoRaw, program_id) == 4);
    assert!(mem::offset_of!(BpfProgramInfoRaw, tag) == 8);
};

#[derive(Debug)]
pub struct NetlinkSocket {
    fd: OwnedFd,
    port_id: u32,
}

impl NetlinkSocket {
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn port_id(&self) -> u32 {
        self.port_id
    }
}

pub fn socket_kernel_identity(socket: BorrowedFd<'_>) -> io::Result<u64> {
    socket_u64_option(socket, libc::SO_COOKIE)
}

pub fn verify_udp_fence_socket_options(socket: BorrowedFd<'_>, ipv6: bool) -> io::Result<()> {
    let (level, freebind, transparent) = if ipv6 {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_FREEBIND,
            libc::IPV6_TRANSPARENT,
        )
    } else {
        (libc::IPPROTO_IP, libc::IP_FREEBIND, libc::IP_TRANSPARENT)
    };
    let ipv6_only = ipv6
        .then(|| socket_i32_option(socket, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY))
        .transpose()?;
    validate_udp_fence_option_values(
        socket_i32_option(socket, level, freebind)?,
        socket_i32_option(socket, level, transparent)?,
        ipv6_only,
    )
}

fn validate_udp_fence_option_values(
    freebind: i32,
    transparent: i32,
    ipv6_only: Option<i32>,
) -> io::Result<()> {
    if freebind != 0 || transparent != 0 || ipv6_only.is_some_and(|value| value != 1) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "udp_fence_socket_options",
        ));
    }
    Ok(())
}

pub fn query_cgroup_skb_egress(
    cgroup: BorrowedFd<'_>,
) -> io::Result<(u32, u64, Vec<BpfCgroupProgramAttachment>)> {
    let mut program_ids = [0_u32; BPF_CGROUP_MAX_PROGS];
    let mut program_attach_flags = [0_u32; BPF_CGROUP_MAX_PROGS];
    let mut query = BpfProgQueryAttr {
        target_fd: fd_number(cgroup)?,
        attach_type: BPF_CGROUP_INET_EGRESS,
        program_ids: program_ids.as_mut_ptr() as usize as u64,
        program_count: u32::try_from(program_ids.len())
            .map_err(|_| io::Error::other("bpf_cgroup_query_capacity"))?,
        program_attach_flags: program_attach_flags.as_mut_ptr() as usize as u64,
        revision: CGROUP_REVISION_PROBE_SENTINEL,
        ..BpfProgQueryAttr::default()
    };
    // SAFETY: `query` is the exact BPF_PROG_QUERY UAPI structure and its
    // program-id pointer names a live, writable fixed array for the entire
    // syscall. The cgroup descriptor remains borrowed and live.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_QUERY,
            &mut query as *mut BpfProgQueryAttr,
            mem::size_of::<BpfProgQueryAttr>(),
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSPC)
            || usize::try_from(query.program_count).unwrap_or(usize::MAX) > program_ids.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bpf_cgroup_query_capacity",
            ));
        }
        return Err(error);
    }
    let count = usize::try_from(query.program_count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bpf_cgroup_query_count"))?;
    if count > program_ids.len()
        || program_ids[..count].contains(&0)
        || program_ids[count..]
            .iter()
            .any(|program_id| *program_id != 0)
        || program_attach_flags[count..]
            .iter()
            .any(|flags| *flags != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bpf_cgroup_query_inventory",
        ));
    }
    let attachments = (0..count)
        .map(|index| BpfCgroupProgramAttachment {
            program_id: program_ids[index],
            program_attach_flags: program_attach_flags[index],
        })
        .collect();
    validate_cgroup_revision_probe(query.revision)?;
    Ok((query.attach_flags, query.revision, attachments))
}

pub fn probe_cgroup_revision_uapi(cgroup: BorrowedFd<'_>) -> io::Result<()> {
    let mut query = cgroup_revision_probe_request(fd_number(cgroup)?);
    // SAFETY: `query` is the exact BPF_PROG_QUERY UAPI structure, contains no
    // user pointers for this count-only request, and the cgroup descriptor
    // remains borrowed and live for the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_QUERY,
            &mut query as *mut BpfProgQueryAttr,
            mem::size_of::<BpfProgQueryAttr>(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    validate_cgroup_revision_probe(query.revision)
}

pub fn attach_cgroup_skb_egress(
    cgroup: BorrowedFd<'_>,
    program: BorrowedFd<'_>,
    expected_revision: u64,
) -> io::Result<()> {
    probe_cgroup_revision_uapi(cgroup)?;
    let request = direct_cgroup_program_request(
        BPF_PROG_ATTACH,
        fd_number(cgroup)?,
        fd_number(program)?,
        expected_revision,
    );
    // SAFETY: `request.attr` is the exact fully initialized BPF_PROG_ATTACH
    // UAPI structure. Both descriptors remain borrowed and live for the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            request.command,
            &request.attr as *const BpfProgAttachAttr,
            mem::size_of::<BpfProgAttachAttr>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn detach_cgroup_skb_egress(
    cgroup: BorrowedFd<'_>,
    program: BorrowedFd<'_>,
    expected_revision: u64,
) -> io::Result<()> {
    if expected_revision == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bpf_cgroup_detach_revision",
        ));
    }
    probe_cgroup_revision_uapi(cgroup)?;
    let request = direct_cgroup_program_request(
        BPF_PROG_DETACH,
        fd_number(cgroup)?,
        fd_number(program)?,
        expected_revision,
    );
    // SAFETY: `request.attr` is the exact fully initialized BPF_PROG_DETACH
    // UAPI structure. Both descriptors remain borrowed and live for the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            request.command,
            &request.attr as *const BpfProgAttachAttr,
            mem::size_of::<BpfProgAttachAttr>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn direct_cgroup_program_request(
    command: libc::c_uint,
    target_fd: u32,
    program_fd: u32,
    expected_revision: u64,
) -> DirectCgroupProgramRequest {
    DirectCgroupProgramRequest {
        command,
        attr: BpfProgAttachAttr {
            target_fd,
            attach_bpf_fd: program_fd,
            attach_type: BPF_CGROUP_INET_EGRESS,
            attach_flags: if command == BPF_PROG_ATTACH {
                BPF_F_ALLOW_MULTI
            } else {
                0
            },
            expected_revision,
            ..BpfProgAttachAttr::default()
        },
    }
}

fn cgroup_revision_probe_request(target_fd: u32) -> BpfProgQueryAttr {
    BpfProgQueryAttr {
        target_fd,
        attach_type: BPF_CGROUP_INET_EGRESS,
        revision: CGROUP_REVISION_PROBE_SENTINEL,
        ..BpfProgQueryAttr::default()
    }
}

fn validate_cgroup_revision_probe(revision: u64) -> io::Result<()> {
    if revision == CGROUP_REVISION_PROBE_SENTINEL {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "bpf_cgroup_revision_uapi",
        ))
    } else {
        Ok(())
    }
}

pub fn clock_gettime_boottime_ns() -> io::Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` points to writable, correctly aligned `timespec`
    // storage for the duration of this read-only clock operation.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) };
    if result != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(error.kind(), "clock_gettime_boottime"));
    }
    timespec_to_nanoseconds(value.tv_sec, value.tv_nsec)
}

fn relative_timer_specification(duration: Duration) -> io::Result<libc::itimerspec> {
    if duration.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "timerfd_boottime",
        ));
    }
    let seconds = libc::time_t::try_from(duration.as_secs())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "timerfd_boottime"))?;
    // `Duration` guarantees this is below one billion, which fits every
    // supported Linux `c_long`.
    let nanoseconds = duration.subsec_nanos() as libc::c_long;
    Ok(libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: seconds,
            tv_nsec: nanoseconds,
        },
    })
}

fn set_relative_timer(
    raw_fd: std::os::fd::RawFd,
    specification: &libc::itimerspec,
) -> io::Result<()> {
    loop {
        let result = {
            // SAFETY: `specification` is a fully initialized relative one-shot
            // timer value, the old-value pointer is null, and callers keep the
            // descriptor live for the duration of the syscall.
            unsafe { libc::timerfd_settime(raw_fd, 0, specification, std::ptr::null_mut()) }
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn read_timer_expirations(raw_fd: std::os::fd::RawFd) -> io::Result<u64> {
    loop {
        let mut expirations = 0_u64;
        // SAFETY: `expirations` is writable and correctly aligned for exactly
        // one timerfd expiration counter, and callers keep the descriptor live
        // for the duration of the nonblocking read.
        let result = unsafe {
            libc::read(
                raw_fd,
                (&mut expirations as *mut u64).cast::<libc::c_void>(),
                mem::size_of_val(&expirations),
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result as usize != mem::size_of_val(&expirations) || expirations == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "timerfd_boottime",
            ));
        }
        return Ok(expirations);
    }
}

fn timespec_to_nanoseconds(seconds: libc::time_t, nanoseconds: libc::c_long) -> io::Result<u64> {
    let seconds = u64::try_from(seconds)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "clock_gettime_boottime"))?;
    let nanoseconds = u64::try_from(nanoseconds)
        .ok()
        .filter(|value| *value < NANOS_PER_SECOND)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "clock_gettime_boottime"))?;
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "clock_gettime_boottime"))
}

pub fn freeze_bpf_map(map: BorrowedFd<'_>) -> io::Result<()> {
    let freeze = BpfMapFreezeAttr {
        map_fd: fd_number(map)?,
    };
    // SAFETY: `freeze` is the exact initialized BPF_MAP_FREEZE UAPI prefix and
    // the map descriptor remains borrowed and live for the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_FREEZE,
            &freeze as *const BpfMapFreezeAttr,
            mem::size_of::<BpfMapFreezeAttr>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn verify_bpf_map_frozen(map: BorrowedFd<'_>) -> io::Result<()> {
    let raw_fd = fd_number(map)?;
    let path = format!("/proc/self/fdinfo/{raw_fd}");
    let file = std::fs::File::open(path)?;
    let mut contents = Vec::new();
    file.take(MAX_BPF_FDINFO_BYTES + 1)
        .read_to_end(&mut contents)?;
    if u64::try_from(contents.len())
        .ok()
        .is_none_or(|length| length > MAX_BPF_FDINFO_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bpf_map_fdinfo_bound",
        ));
    }
    validate_bpf_map_fdinfo(&contents)
}

fn validate_bpf_map_fdinfo(contents: &[u8]) -> io::Result<()> {
    let text = std::str::from_utf8(contents)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bpf_map_fdinfo_encoding"))?;
    let mut frozen = text
        .lines()
        .filter_map(|line| line.strip_prefix("frozen:\t"));
    if frozen.next() != Some("1") || frozen.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bpf_map_not_frozen",
        ));
    }
    Ok(())
}

fn socket_i32_option(
    socket: BorrowedFd<'_>,
    level: libc::c_int,
    option: libc::c_int,
) -> io::Result<i32> {
    let mut value = 0_i32;
    let mut length = libc::socklen_t::try_from(mem::size_of::<i32>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket_option_width"))?;
    // SAFETY: `socket` remains live and borrowed, while `value` and `length`
    // are exact writable objects for the entire `getsockopt` call.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(length).ok() != Some(mem::size_of::<i32>()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket_option_width",
        ));
    }
    Ok(value)
}

fn socket_u64_option(socket: BorrowedFd<'_>, option: libc::c_int) -> io::Result<u64> {
    let mut value = 0_u64;
    let mut length = libc::socklen_t::try_from(mem::size_of::<u64>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket_option_width"))?;
    // SAFETY: `socket` is a live borrowed descriptor, `value` and `length`
    // point to writable objects for the entire call, and both options return
    // exactly one `u64` on Linux.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut u64).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(length).ok() != Some(mem::size_of::<u64>()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket_option_width",
        ));
    }
    Ok(value)
}

#[derive(Debug)]
pub struct GtpuUdpSocket {
    fd: OwnedFd,
}

/// Owned descriptor for one exact XDP BPF-link object.
#[derive(Debug)]
pub struct BpfXdpLink {
    fd: OwnedFd,
}

/// Owned descriptor for one exact XDP BPF program.
#[derive(Debug)]
pub struct BpfXdpProgram {
    fd: OwnedFd,
}

impl BpfXdpProgram {
    pub fn program_id(&self) -> io::Result<u32> {
        xdp_program_id_from_fd(&self.fd)
    }
}

impl BpfXdpLink {
    pub fn info(&self) -> io::Result<BpfXdpLinkInfo> {
        xdp_link_info_from_fd(&self.fd)
    }

    pub fn pin_duplicate(&self, path: &Path) -> io::Result<()> {
        let path = validate_pin_path(path)?;
        pin_bpf_object(&self.fd, &path)
    }

    pub fn replace_program(
        &self,
        new_program_fd: BorrowedFd<'_>,
        expected_old_program: &BpfXdpProgram,
    ) -> io::Result<()> {
        let attr = BpfLinkUpdateAttr {
            link_fd: fd_number(self.fd.as_fd())?,
            new_program_fd: fd_number(new_program_fd)?,
            flags: BPF_F_REPLACE,
            old_program_fd: fd_number(expected_old_program.fd.as_fd())?,
        };
        // SAFETY: `attr` is the fully initialized BPF_LINK_UPDATE UAPI
        // structure. All descriptors remain borrowed and live for the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_LINK_UPDATE,
                &attr as *const BpfLinkUpdateAttr,
                mem::size_of::<BpfLinkUpdateAttr>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl GtpuUdpSocket {
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

pub fn open_netlink_socket(protocol: i32) -> io::Result<NetlinkSocket> {
    // SAFETY: `socket` is called with constant Linux netlink domain/type values
    // and a caller-selected netlink protocol. On success the descriptor is fresh
    // and transferred immediately into `OwnedFd`; on failure no descriptor is owned.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            protocol,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `fd` is a fresh descriptor returned by `socket` above and is not
    // owned anywhere else.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let addr = kernel_netlink_addr(0);
    // SAFETY: `addr` is a fully initialized sockaddr_nl with the matching
    // length, and `fd` is a live netlink descriptor owned by this function.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut local = kernel_netlink_addr(0);
    let mut local_len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: `local` and `local_len` are initialized writable address
    // outputs, and `fd` is a live bound netlink descriptor.
    let rc = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut local as *mut libc::sockaddr_nl).cast::<libc::sockaddr>(),
            &mut local_len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if local_len != mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t
        || i32::from(local.nl_family) != libc::AF_NETLINK
        || local.nl_pid == 0
        || local.nl_groups != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid local netlink socket identity",
        ));
    }
    Ok(NetlinkSocket {
        fd,
        port_id: local.nl_pid,
    })
}

pub fn open_gtpu_udp_socket(bind: GtpuUdpBind) -> io::Result<GtpuUdpSocket> {
    match bind.address {
        GtpuIpAddress::Ipv4(octets) => open_gtpu_udp_socket_v4(octets, bind.port),
        GtpuIpAddress::Ipv6(octets) => open_gtpu_udp_socket_v6(octets, bind.port),
    }
}

pub fn ifindex_by_name(name: &str) -> io::Result<u32> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    // SAFETY: `name` is a valid NUL-terminated C string for the duration of the
    // call. `if_nametoindex` does not retain the pointer.
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if ifindex == 0 {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "interface not found",
        ))
    } else {
        Ok(ifindex)
    }
}

fn validate_link_id(link_id: u32) -> io::Result<()> {
    if link_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BPF link id must be non-zero",
        ));
    }
    Ok(())
}

fn validate_pin_path(path: &Path) -> io::Result<CString> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BPF link pin path must be absolute",
        ));
    }
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "BPF link pin path contains NUL",
        )
    })
}

fn fd_number(fd: BorrowedFd<'_>) -> io::Result<u32> {
    u32::try_from(fd.as_raw_fd()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "BPF object descriptor must be non-negative",
        )
    })
}

fn open_bpf_object_by_id(command: libc::c_uint, object_id: u32) -> io::Result<OwnedFd> {
    if object_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BPF object id must be non-zero",
        ));
    }
    let get_attr = BpfGetFdByIdAttr {
        object_id,
        ..BpfGetFdByIdAttr::default()
    };
    // SAFETY: `get_attr` is the exact 12-byte *_GET_FD_BY_ID UAPI prefix. The
    // kernel copies it and retains no pointer.
    let object_fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            &get_attr as *const BpfGetFdByIdAttr,
            mem::size_of::<BpfGetFdByIdAttr>(),
        )
    };
    if object_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let object_fd = object_fd as libc::c_int;
    // SAFETY: `object_fd` is a fresh descriptor returned by bpf(2) and is
    // transferred immediately into `OwnedFd`.
    let object_fd = unsafe { OwnedFd::from_raw_fd(object_fd) };
    ensure_cloexec(&object_fd)?;
    Ok(object_fd)
}

fn open_bpf_link_by_id(link_id: u32) -> io::Result<OwnedFd> {
    validate_link_id(link_id)?;
    open_bpf_object_by_id(BPF_LINK_GET_FD_BY_ID, link_id)
}

fn open_bpf_link_from_pin(path: &Path) -> io::Result<OwnedFd> {
    let path = validate_pin_path(path)?;
    let get_attr = BpfObjPinAttr {
        pathname: path.as_ptr() as usize as u64,
        ..BpfObjPinAttr::default()
    };
    // SAFETY: `get_attr` has the exact BPF_OBJ_GET UAPI layout and points to a
    // live NUL-terminated path for the duration of the syscall.
    let link_fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET,
            &get_attr as *const BpfObjPinAttr,
            mem::size_of::<BpfObjPinAttr>(),
        )
    };
    if link_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let link_fd = link_fd as libc::c_int;
    // SAFETY: `link_fd` is a fresh descriptor returned by BPF_OBJ_GET and is
    // transferred immediately into `OwnedFd`.
    let link_fd = unsafe { OwnedFd::from_raw_fd(link_fd) };
    ensure_cloexec(&link_fd)?;
    Ok(link_fd)
}

fn ensure_cloexec(fd: &OwnedFd) -> io::Result<()> {
    // BPF object descriptors are returned close-on-exec by the kernel. Verify
    // and repair that property defensively before the descriptor can escape
    // this boundary.
    // SAFETY: `link_fd` is live, F_GETFD does not require a third argument,
    // and F_SETFD receives the integer flag word returned by F_GETFD.
    let descriptor_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if descriptor_flags & libc::FD_CLOEXEC == 0 {
        // SAFETY: `link_fd` is live and `descriptor_flags | FD_CLOEXEC` is a
        // valid F_SETFD flag word.
        let set_result = unsafe {
            libc::fcntl(
                fd.as_raw_fd(),
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        };
        if set_result < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn pin_bpf_object(fd: &OwnedFd, path: &CString) -> io::Result<()> {
    let pin_attr = BpfObjPinAttr {
        pathname: path.as_ptr() as usize as u64,
        bpf_fd: fd_number(fd.as_fd())?,
        ..BpfObjPinAttr::default()
    };
    // SAFETY: `pin_attr` has the exact BPF_OBJ_PIN UAPI prefix and points to a
    // live NUL-terminated path for the syscall duration. `fd` remains live.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_PIN,
            &pin_attr as *const BpfObjPinAttr,
            mem::size_of::<BpfObjPinAttr>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn xdp_link_info_from_fd(link_fd: &OwnedFd) -> io::Result<BpfXdpLinkInfo> {
    let mut info = BpfXdpLinkInfoRaw::default();
    let mut info_attr = BpfObjGetInfoByFdAttr {
        bpf_fd: link_fd.as_raw_fd() as u32,
        info_len: mem::size_of::<BpfXdpLinkInfoRaw>() as u32,
        info: (&mut info as *mut BpfXdpLinkInfoRaw) as usize as u64,
    };
    // SAFETY: `info_attr` is the exact BPF_OBJ_GET_INFO_BY_FD UAPI layout and
    // points to a live, writable `BpfXdpLinkInfoRaw` for the syscall duration.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &mut info_attr as *mut BpfObjGetInfoByFdAttr,
            mem::size_of::<BpfObjGetInfoByFdAttr>(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if info_attr.info_len < mem::size_of::<BpfXdpLinkInfoRaw>() as u32
        || info.link_type != BPF_LINK_TYPE_XDP
        || info.link_id == 0
        || info.program_id == 0
        || info.ifindex == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BPF link is not a complete XDP attachment",
        ));
    }
    Ok(BpfXdpLinkInfo {
        link_id: info.link_id,
        program_id: info.program_id,
        ifindex: info.ifindex,
    })
}

fn xdp_program_id_from_fd(program_fd: &OwnedFd) -> io::Result<u32> {
    let mut info = BpfProgramInfoRaw::default();
    let mut info_attr = BpfObjGetInfoByFdAttr {
        bpf_fd: fd_number(program_fd.as_fd())?,
        info_len: mem::size_of::<BpfProgramInfoRaw>() as u32,
        info: (&mut info as *mut BpfProgramInfoRaw) as usize as u64,
    };
    // SAFETY: `info_attr` is the exact BPF_OBJ_GET_INFO_BY_FD UAPI layout and
    // points to a live writable `BpfProgramInfoRaw` for the call duration.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &mut info_attr as *mut BpfObjGetInfoByFdAttr,
            mem::size_of::<BpfObjGetInfoByFdAttr>(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if info_attr.info_len < mem::size_of::<BpfProgramInfoRaw>() as u32
        || info.program_type != BPF_PROG_TYPE_XDP
        || info.program_id == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BPF object is not a complete XDP program",
        ));
    }
    Ok(info.program_id)
}

pub fn open_xdp_link_by_id(link_id: u32) -> io::Result<BpfXdpLink> {
    let link = BpfXdpLink {
        fd: open_bpf_link_by_id(link_id)?,
    };
    let identity = link.info()?;
    if identity.link_id != link_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened XDP link id does not match the requested object",
        ));
    }
    Ok(link)
}

pub fn open_xdp_link_from_pin(path: &Path) -> io::Result<BpfXdpLink> {
    let link = BpfXdpLink {
        fd: open_bpf_link_from_pin(path)?,
    };
    let _ = link.info()?;
    Ok(link)
}

pub fn open_xdp_program_by_id(program_id: u32) -> io::Result<BpfXdpProgram> {
    let program = BpfXdpProgram {
        fd: open_bpf_object_by_id(BPF_PROG_GET_FD_BY_ID, program_id)?,
    };
    if program.program_id()? != program_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened XDP program id does not match the requested object",
        ));
    }
    Ok(program)
}

fn open_gtpu_udp_socket_v4(octets: [u8; 4], port: u16) -> io::Result<GtpuUdpSocket> {
    // SAFETY: `socket` is called with Linux IPv4 datagram constants. On success
    // the descriptor is fresh and transferred immediately into `OwnedFd`.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `fd` is a fresh descriptor returned by `socket` above and is not
    // owned anywhere else.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let addr = sockaddr_in(octets, port);
    // SAFETY: `addr` is a fully initialized sockaddr_in with matching length,
    // and `fd` is a live UDP socket owned by this function.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(GtpuUdpSocket { fd })
    }
}

fn open_gtpu_udp_socket_v6(octets: [u8; 16], port: u16) -> io::Result<GtpuUdpSocket> {
    // SAFETY: `socket` is called with Linux IPv6 datagram constants. On success
    // the descriptor is fresh and transferred immediately into `OwnedFd`.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `fd` is a fresh descriptor returned by `socket` above and is not
    // owned anywhere else.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_ipv6_only(&fd)?;
    let addr = sockaddr_in6(octets, port);
    // SAFETY: `addr` is a fully initialized sockaddr_in6 with matching length,
    // and `fd` is a live UDP socket owned by this function.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_in6).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(GtpuUdpSocket { fd })
    }
}

fn set_ipv6_only(fd: &OwnedFd) -> io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `one` is a valid integer option value, the option length matches
    // its type, and `fd` is a live IPv6 socket.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&one as *const libc::c_int).cast::<libc::c_void>(),
            mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn send_message(socket: &NetlinkSocket, payload: &[u8]) -> io::Result<usize> {
    if payload.is_empty() {
        return Ok(0);
    }
    let peer = kernel_netlink_addr(0);
    // SAFETY: `payload` is a valid immutable buffer for its length, `peer` is a
    // valid sockaddr_nl designating the kernel endpoint, and the socket fd is live.
    let rc = unsafe {
        libc::sendto(
            socket.fd.as_raw_fd(),
            payload.as_ptr().cast::<libc::c_void>(),
            payload.len(),
            0,
            (&peer as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

pub fn receive_message(socket: &NetlinkSocket, buffer: &mut [u8]) -> io::Result<usize> {
    if buffer.is_empty() {
        return Ok(0);
    }
    // SAFETY: `buffer` is a valid writable byte slice for its length and the
    // socket fd is live. `MSG_TRUNC` causes the kernel to return the real
    // datagram length even when it exceeds the buffer.
    let rc = unsafe {
        libc::recv(
            socket.fd.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            libc::MSG_TRUNC,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        classify_recv(rc as usize, buffer.len())
    }
}

/// Receive one unicast netlink datagram and prove that the kernel sent it.
///
/// Netlink header fields are payload controlled and therefore do not
/// authenticate the sender. Callers making authoritative decisions from an
/// ACK, echo, or dump must also validate the `sockaddr_nl` returned by
/// `recvfrom`: kernel-originated unicast replies have port id and groups zero.
pub fn receive_kernel_message(socket: &NetlinkSocket, buffer: &mut [u8]) -> io::Result<usize> {
    if buffer.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "kernel netlink receive buffer is empty",
        ));
    }
    let mut sender = kernel_netlink_addr(0);
    let mut sender_len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: `buffer` is a valid writable byte slice, `sender` and
    // `sender_len` are initialized writable address outputs, and the socket fd
    // is live. MSG_TRUNC preserves the pending datagram's real length.
    let rc = unsafe {
        libc::recvfrom(
            socket.fd.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            libc::MSG_TRUNC,
            (&mut sender as *mut libc::sockaddr_nl).cast::<libc::sockaddr>(),
            &mut sender_len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if sender_len != mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t
        || i32::from(sender.nl_family) != libc::AF_NETLINK
        || sender.nl_pid != 0
        || sender.nl_groups != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink datagram was not sent by the kernel",
        ));
    }
    classify_recv(rc as usize, buffer.len())
}

fn classify_recv(received_len: usize, buf_len: usize) -> io::Result<usize> {
    if received_len > buf_len {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "netlink GTP-U datagram truncated: buffer is {} bytes but datagram is {} bytes",
                buf_len, received_len
            ),
        ))
    } else {
        Ok(received_len)
    }
}

fn kernel_netlink_addr(groups: u32) -> libc::sockaddr_nl {
    // SAFETY: All-zero `sockaddr_nl` is a valid base value; the public fields
    // required by Linux netlink are initialized immediately below.
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = 0;
    addr.nl_groups = groups;
    addr
}

fn sockaddr_in(octets: [u8; 4], port: u16) -> libc::sockaddr_in {
    // SAFETY: All-zero `sockaddr_in` is a valid base value; the public fields
    // required by IPv4 UDP bind are initialized immediately below.
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = port.to_be();
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(octets),
    };
    addr
}

fn sockaddr_in6(octets: [u8; 16], port: u16) -> libc::sockaddr_in6 {
    // SAFETY: All-zero `sockaddr_in6` is a valid base value; the public fields
    // required by IPv6 UDP bind are initialized immediately below.
    let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    addr.sin6_port = port.to_be();
    addr.sin6_addr = libc::in6_addr { s6_addr: octets };
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, OwnedFd};

    #[test]
    fn kernel_addr_is_netlink_family() {
        let addr = kernel_netlink_addr(0);
        assert_eq!(addr.nl_family, libc::AF_NETLINK as libc::sa_family_t);
        assert_eq!(addr.nl_pid, 0);
        assert_eq!(addr.nl_groups, 0);
    }

    #[test]
    fn cgroup_egress_attach_is_direct_revision_guarded_and_multi() {
        let revision = 0x0102_0304_0506_0708;
        let request = direct_cgroup_program_request(BPF_PROG_ATTACH, 17, 23, revision);

        assert_eq!(request.command, BPF_PROG_ATTACH);
        assert_eq!(request.attr.target_fd, 17);
        assert_eq!(request.attr.attach_bpf_fd, 23);
        assert_eq!(request.attr.attach_type, BPF_CGROUP_INET_EGRESS);
        assert_eq!(request.attr.attach_flags, BPF_F_ALLOW_MULTI);
        assert_eq!(request.attr.replace_bpf_fd, 0);
        assert_eq!(request.attr.relative_fd, 0);
        assert_eq!(request.attr.expected_revision, revision);
    }

    #[test]
    fn cgroup_egress_pristine_attach_preserves_explicit_zero_revision() {
        let request = direct_cgroup_program_request(BPF_PROG_ATTACH, 17, 23, 0);

        assert_eq!(request.attr.attach_flags, BPF_F_ALLOW_MULTI);
        assert_eq!(request.attr.expected_revision, 0);
    }

    #[test]
    fn cgroup_egress_detach_targets_one_exact_program_with_revision() {
        let request = direct_cgroup_program_request(BPF_PROG_DETACH, 17, 23, 41);

        assert_eq!(request.command, BPF_PROG_DETACH);
        assert_eq!(request.attr.target_fd, 17);
        assert_eq!(request.attr.attach_bpf_fd, 23);
        assert_eq!(request.attr.attach_type, BPF_CGROUP_INET_EGRESS);
        assert_eq!(request.attr.attach_flags, 0);
        assert_eq!(request.attr.replace_bpf_fd, 0);
        assert_eq!(request.attr.relative_fd, 0);
        assert_eq!(request.attr.expected_revision, 41);
    }

    #[test]
    fn cgroup_revision_probe_requires_kernel_overwrite() {
        let request = cgroup_revision_probe_request(17);
        assert_eq!(request.target_fd, 17);
        assert_eq!(request.attach_type, BPF_CGROUP_INET_EGRESS);
        assert_eq!(request.program_count, 0);
        assert_eq!(request.program_ids, 0);
        assert_eq!(request.revision, CGROUP_REVISION_PROBE_SENTINEL);

        let error = validate_cgroup_revision_probe(CGROUP_REVISION_PROBE_SENTINEL)
            .expect_err("unchanged sentinel");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(error.to_string(), "bpf_cgroup_revision_uapi");
        assert!(validate_cgroup_revision_probe(0).is_ok());
        assert!(validate_cgroup_revision_probe(41).is_ok());
    }

    #[test]
    fn boottime_timespec_conversion_is_checked() {
        assert_eq!(timespec_to_nanoseconds(0, 0).expect("epoch"), 0);
        assert_eq!(
            timespec_to_nanoseconds(7, 123).expect("ordinary time"),
            7_000_000_123
        );
        for (seconds, nanoseconds) in [(-1, 0), (0, -1), (0, 1_000_000_000)] {
            let error =
                timespec_to_nanoseconds(seconds, nanoseconds).expect_err("invalid timespec");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "clock_gettime_boottime");
        }
        if let Ok(seconds) = libc::time_t::try_from(u64::MAX / NANOS_PER_SECOND + 1) {
            let error = timespec_to_nanoseconds(seconds, 0).expect_err("overflowing timespec");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "clock_gettime_boottime");
        }
    }

    #[test]
    fn live_boottime_read_is_nonzero_and_fallible() {
        let now = clock_gettime_boottime_ns().expect("CLOCK_BOOTTIME is supported on Linux");
        assert_ne!(now, 0);
    }

    #[test]
    fn relative_boottime_timer_conversion_rejects_zero_and_overflow() {
        let specification =
            relative_timer_specification(Duration::new(7, 123)).expect("ordinary duration");
        assert_eq!(specification.it_interval.tv_sec, 0);
        assert_eq!(specification.it_interval.tv_nsec, 0);
        assert_eq!(specification.it_value.tv_sec, 7);
        assert_eq!(specification.it_value.tv_nsec, 123);

        let error = relative_timer_specification(Duration::ZERO).expect_err("zero disarms timerfd");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "timerfd_boottime");

        if libc::time_t::try_from(u64::MAX).is_err() {
            let error = relative_timer_specification(Duration::new(u64::MAX, 999_999_999))
                .expect_err("seconds exceed time_t");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(error.to_string(), "timerfd_boottime");
        }
    }

    #[test]
    fn fenced_udp_option_values_require_strict_family_safe_defaults() {
        assert!(validate_udp_fence_option_values(0, 0, None).is_ok());
        assert!(validate_udp_fence_option_values(0, 0, Some(1)).is_ok());
        for (freebind, transparent, ipv6_only) in [
            (1, 0, None),
            (0, 1, None),
            (1, 1, Some(1)),
            (0, 0, Some(0)),
            (0, 0, Some(2)),
        ] {
            let error = validate_udp_fence_option_values(freebind, transparent, ipv6_only)
                .expect_err("unsafe socket option");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), "udp_fence_socket_options");
        }
    }

    #[test]
    fn frozen_map_fdinfo_requires_one_exact_frozen_field() {
        assert!(
            validate_bpf_map_fdinfo(b"pos:\t0\nflags:\t02000002\nmap_type:\t2\nfrozen:\t1\n")
                .is_ok()
        );
        for invalid in [
            b"map_type:\t2\n".as_slice(),
            b"map_type:\t2\nfrozen:\t0\n".as_slice(),
            b"map_type:\t2\nfrozen:\t2\n".as_slice(),
            b"map_type:\t2\nfrozen:\t1\nfrozen:\t1\n".as_slice(),
            b"map_type:\t2\nfrozen: 1\n".as_slice(),
            &[0xff][..],
        ] {
            assert_eq!(
                validate_bpf_map_fdinfo(invalid)
                    .expect_err("ambiguous or unfrozen fdinfo")
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn invalid_timer_descriptor_errors_without_memory_unsafety() {
        let specification =
            relative_timer_specification(Duration::from_nanos(1)).expect("duration");
        let arm_error = set_relative_timer(-1, &specification).expect_err("invalid arm descriptor");
        assert_eq!(arm_error.raw_os_error(), Some(libc::EBADF));
        let read_error = read_timer_expirations(-1).expect_err("invalid read descriptor");
        assert_eq!(read_error.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn live_boottime_timer_is_nonblocking_close_on_exec_and_redacted() {
        let timer = match crate::BootTimeTimer::new(Duration::from_millis(1)) {
            Ok(timer) => timer,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
                ) =>
            {
                eprintln!("skipping: CLOCK_BOOTTIME timerfd unavailable");
                return;
            }
            Err(error) => panic!("unexpected boot-time timer error: {error}"),
        };
        assert_eq!(format!("{timer:?}"), "BootTimeTimer(<redacted>)");
        // SAFETY: `timer` owns a live descriptor and these `fcntl` commands do
        // not consume it or require pointer arguments.
        let status_flags = unsafe { libc::fcntl(timer.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: as above, `F_GETFD` only reads descriptor flags.
        let descriptor_flags = unsafe { libc::fcntl(timer.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(status_flags & libc::O_NONBLOCK, 0);
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);

        let mut poll_descriptor = libc::pollfd {
            fd: timer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll_descriptor` is one initialized element and remains
        // writable for the bounded call.
        let ready = unsafe { libc::poll(&mut poll_descriptor, 1, 1_000) };
        assert_eq!(ready, 1, "boot-time timer did not become readable");
        assert_ne!(poll_descriptor.revents & libc::POLLIN, 0);
        assert_eq!(timer.consume_expirations().expect("expiration"), 1);
        let error = timer
            .consume_expirations()
            .expect_err("one-shot timer was consumed");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(error.to_string(), "boot_time_timer");

        let zero = crate::BootTimeTimer::new(Duration::ZERO).expect_err("zero duration");
        assert_eq!(zero.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(zero.to_string(), "boot_time_timer");
    }

    #[test]
    fn route_socket_reports_kernel_assigned_port_id() {
        match open_netlink_socket(crate::NETLINK_ROUTE) {
            Ok(socket) => assert_ne!(socket.port_id(), 0),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: netlink socket creation denied by sandbox");
            }
            Err(error) => panic!("unexpected netlink socket error: {error}"),
        }
    }

    #[test]
    fn sockaddr_in_preserves_wire_octets_and_port() {
        let addr = sockaddr_in([192, 0, 2, 9], 2152);
        assert_eq!(addr.sin_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(addr.sin_port.to_be(), 2152);
        assert_eq!(addr.sin_addr.s_addr.to_ne_bytes(), [192, 0, 2, 9]);
    }

    #[test]
    fn sockaddr_in6_preserves_wire_octets_and_port() {
        let octets = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let addr = sockaddr_in6(octets, 2152);
        assert_eq!(addr.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        assert_eq!(addr.sin6_port.to_be(), 2152);
        assert_eq!(addr.sin6_addr.s6_addr, octets);
    }

    #[test]
    fn classify_recv_accepts_fits_and_exact_fit() {
        let cases: &[(usize, usize, usize)] = &[(0, 1, 0), (5, 10, 5), (10, 10, 10)];
        for &(received, buf_len, expected) in cases {
            assert_eq!(
                classify_recv(received, buf_len).unwrap(),
                expected,
                "received={received}, buf_len={buf_len}"
            );
        }
    }

    #[test]
    fn classify_recv_rejects_truncated_datagram() {
        let err = classify_recv(11, 10).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(msg.contains("truncated"), "{msg}");
        assert!(msg.contains("buffer is 10 bytes"), "{msg}");
        assert!(msg.contains("datagram is 11 bytes"), "{msg}");
    }

    #[test]
    fn ifindex_lookup_rejects_nul_name() {
        let err = ifindex_by_name("bad\0name").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn ifindex_lookup_reports_missing_interface() {
        let err = ifindex_by_name("opcnoif0").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn ifindex_lookup_finds_loopback_when_available() {
        match ifindex_by_name("lo") {
            Ok(ifindex) => assert_ne!(ifindex, 0),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!("skipping: loopback interface is not visible in this namespace");
            }
            Err(error) => panic!("unexpected loopback lookup error: {error}"),
        }
    }

    #[test]
    fn udp_socket_bind_port_zero_is_supported_when_sandbox_allows() {
        match open_gtpu_udp_socket(GtpuUdpBind {
            address: GtpuIpAddress::Ipv4([127, 0, 0, 1]),
            port: 0,
        }) {
            Ok(socket) => assert!(socket.raw_fd() >= 0),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: UDP socket creation denied by sandbox");
            }
            Err(error) => panic!("unexpected UDP bind error: {error}"),
        }
    }

    fn try_local_datagram_pair() -> Option<(NetlinkSocket, OwnedFd)> {
        let mut fds: [libc::c_int; 2] = [-1, -1];
        // SAFETY: `fds` is a valid two-element array and the call writes exactly
        // two descriptors into it on success.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::PermissionDenied {
                return None;
            }
            panic!("socketpair failed: {err}");
        }
        // SAFETY: On success `socketpair` returned two fresh, live descriptors.
        let local = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: `fds[1]` is the second fresh descriptor returned by
        // `socketpair` and is not owned anywhere else.
        let peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Some((
            NetlinkSocket {
                fd: local,
                port_id: 0,
            },
            peer,
        ))
    }

    fn try_send_all(peer: &OwnedFd, payload: &[u8]) -> Option<()> {
        // SAFETY: `payload` is a valid immutable buffer for its length and the
        // peer descriptor is live.
        let rc = unsafe {
            libc::send(
                peer.as_raw_fd(),
                payload.as_ptr().cast::<libc::c_void>(),
                payload.len(),
                0,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::PermissionDenied {
                return None;
            }
            panic!("send failed: {err}");
        }
        assert_eq!(rc, payload.len() as isize, "short send");
        Some(())
    }

    fn datagram_socket_with(payload: &[u8]) -> Option<NetlinkSocket> {
        let (sock, peer) = try_local_datagram_pair()?;
        try_send_all(&peer, payload)?;
        Some(sock)
    }

    macro_rules! skip_if_sandbox_denies {
        ($sock:expr) => {
            match $sock {
                Some(sock) => sock,
                None => {
                    eprintln!("skipping: local datagram IPC denied by sandbox");
                    return;
                }
            }
        };
    }

    #[test]
    fn receive_message_reads_fitting_datagram() {
        let payload = b"hello gtpu";
        let sock = skip_if_sandbox_denies!(datagram_socket_with(payload));

        let mut buf = [0_u8; 32];
        let n = receive_message(&sock, &mut buf).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn receive_message_rejects_truncated_datagram() {
        let payload = b"0123456789abcdef";
        let sock = skip_if_sandbox_denies!(datagram_socket_with(payload));

        let mut buf = [0_u8; 8];
        let err = receive_message(&sock, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn receive_kernel_message_rejects_forged_userspace_peer() {
        let open = || match open_netlink_socket(libc::NETLINK_USERSOCK) {
            Ok(socket) => Some(socket),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => None,
            Err(error) => panic!("open NETLINK_USERSOCK failed: {error}"),
        };
        let Some(victim) = open() else {
            eprintln!("skipping: user netlink IPC denied by sandbox");
            return;
        };
        let Some(attacker) = open() else {
            eprintln!("skipping: user netlink IPC denied by sandbox");
            return;
        };

        // Forge the header fields that higher-level parsers traditionally
        // validate. They remain attacker-controlled payload bytes; only the
        // recvfrom sockaddr can authenticate the kernel sender.
        let mut forged_ack = [0_u8; 20];
        let forged_ack_len = forged_ack.len() as u32;
        forged_ack[..4].copy_from_slice(&forged_ack_len.to_ne_bytes());
        forged_ack[4..6].copy_from_slice(&2_u16.to_ne_bytes()); // NLMSG_ERROR
        forged_ack[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        forged_ack[12..16].copy_from_slice(&victim.port_id().to_ne_bytes());
        let mut destination = kernel_netlink_addr(0);
        destination.nl_pid = victim.port_id();
        // SAFETY: `forged_ack` is a valid immutable buffer, `destination` is a
        // fully initialized sockaddr_nl for the live victim, and the attacker
        // descriptor remains owned for the duration of the call.
        let sent = unsafe {
            libc::sendto(
                attacker.fd.as_raw_fd(),
                forged_ack.as_ptr().cast::<libc::c_void>(),
                forged_ack.len(),
                0,
                (&destination as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::PermissionDenied {
                eprintln!("skipping: user netlink send denied by sandbox");
                return;
            }
            panic!("send forged netlink ACK failed: {error}");
        }
        assert_eq!(sent as usize, forged_ack.len());

        let mut buffer = [0_u8; 64];
        let error = receive_kernel_message(&victim, &mut buffer).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not sent by the kernel"));
    }

    #[test]
    fn receive_kernel_message_rejects_empty_buffer() {
        let socket = open_netlink_socket(libc::NETLINK_ROUTE).unwrap();
        let error = receive_kernel_message(&socket, &mut []).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
