use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::NETLINK_XFRM;

const BPF_FS_MAGIC: libc::c_long = 0xcafe_4a11;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Debug)]
pub struct NetlinkSocket {
    fd: OwnedFd,
}

#[derive(Debug)]
pub struct BpffsDirectory {
    fd: OwnedFd,
}

impl BpffsDirectory {
    pub fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
    }
}

pub fn open_or_create_bpffs_directory(relative: &Path) -> io::Result<BpffsDirectory> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bpffs path must contain only relative normal components",
        ));
    }

    let base = open_absolute_directory(c"/sys/fs/bpf")?;
    verify_bpffs(&base)?;
    let mut current = base;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            unreachable!("validated above")
        };
        let component = CString::new(component.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bpffs path contains NUL"))?;
        // SAFETY: `current` is a live directory descriptor and `component` is
        // a NUL-terminated single path component. The mode is used only when
        // creation succeeds.
        let result = unsafe { libc::mkdirat(current.as_raw_fd(), component.as_ptr(), 0o750) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error);
            }
        }
        current = open_child_directory(&current, &component)?;
    }
    verify_bpffs(&current)?;
    Ok(BpffsDirectory { fd: current })
}

fn open_absolute_directory(path: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: `path` is a valid NUL-terminated path. A successful fresh
    // descriptor is transferred immediately into `OwnedFd`.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_fd(fd)
}

fn open_child_directory(parent: &OwnedFd, component: &CStr) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `parent` is live, `component` is NUL terminated, and `how`
    // points to a fully initialized `open_how`-compatible value for its size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent.as_raw_fd(),
            component.as_ptr(),
            &how as *const OpenHow,
            mem::size_of::<OpenHow>(),
        ) as libc::c_int
    };
    owned_fd(fd)
}

fn owned_fd(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` is a fresh descriptor returned by a successful open.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn verify_bpffs(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: zero is a valid initial representation for `statfs`; the kernel
    // initializes it completely on success below.
    let mut status: libc::statfs = unsafe { mem::zeroed() };
    // SAFETY: `fd` is live and `status` is valid writable storage.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut status) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if status.f_type != BPF_FS_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pin directory is not on bpffs",
        ));
    }
    Ok(())
}

impl NetlinkSocket {
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

pub fn open_netlink_socket() -> io::Result<NetlinkSocket> {
    // SAFETY: `socket` is called with constant Linux netlink domain/type values
    // and the XFRM protocol number. On success the returned descriptor is fresh
    // and transferred immediately into `OwnedFd`; on failure no descriptor is owned.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            NETLINK_XFRM,
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
        Err(io::Error::last_os_error())
    } else {
        Ok(NetlinkSocket { fd })
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
    // socket fd is live. `recv` writes at most `buffer.len()` bytes.
    // `MSG_TRUNC` causes the kernel to return the real datagram length even
    // when it exceeds the buffer, which lets us detect silent truncation below.
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

/// Classify a successful `recv` return value against the caller buffer.
///
/// Returns the number of bytes available in the buffer when the datagram fits
/// (or exactly fits). Returns [`io::ErrorKind::InvalidData`] when the kernel
/// reported a real datagram length larger than the buffer, which can only
/// happen when `recv` was called with `MSG_TRUNC`.
fn classify_recv(received_len: usize, buf_len: usize) -> io::Result<usize> {
    if received_len > buf_len {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "netlink XFRM datagram truncated: buffer is {} bytes but datagram is {} bytes",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpffs_directory_rejects_non_normal_relative_paths() {
        for path in ["", "/absolute", "../escape", "nested/../escape"] {
            assert_eq!(
                open_or_create_bpffs_directory(Path::new(path))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "path={path}"
            );
        }
    }

    #[test]
    fn filesystem_verification_rejects_a_real_non_bpffs_mount() {
        let root = open_absolute_directory(c"/").expect("open root filesystem");
        assert_eq!(
            verify_bpffs(&root).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn kernel_addr_is_xfrm_netlink_family() {
        let addr = kernel_netlink_addr(0);
        assert_eq!(addr.nl_family, libc::AF_NETLINK as libc::sa_family_t);
        assert_eq!(addr.nl_pid, 0);
        assert_eq!(addr.nl_groups, 0);
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

    /// Build a connected pair of `AF_UNIX` `SOCK_DGRAM` sockets.
    ///
    /// Linux returns the real datagram length for `AF_UNIX` datagram sockets
    /// under `MSG_TRUNC`, the same behavior the netlink path relies on, so this
    /// fixture is a faithful stand-in for `NETLINK_XFRM` without requiring
    /// privileges or a live kernel endpoint.
    ///
    /// Returns `None` when the test environment denies socket creation (e.g.
    /// `EPERM` under a restricted sandbox). Callers should skip the test.
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
        // SAFETY: `fds[1]` is the second fresh descriptor returned by `socketpair`
        // and is not owned anywhere else.
        let peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Some((NetlinkSocket { fd: local }, peer))
    }

    /// Send a full datagram; returns `None` when the environment denies the
    /// send (e.g. `EPERM` under a restricted sandbox). Callers should skip the
    /// test rather than fail.
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

    /// Create a local datagram socket with `payload` already queued, or `None`
    /// if the environment denies socket IPC.
    fn datagram_socket_with(payload: &[u8]) -> Option<NetlinkSocket> {
        let (sock, peer) = try_local_datagram_pair()?;
        try_send_all(&peer, payload)?;
        Some(sock)
    }

    /// Unwrap a test fixture, or print a skip diagnostic and return from the
    /// calling test when the sandbox denies local datagram IPC.
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
        let payload = b"hello xfrm";
        let sock = skip_if_sandbox_denies!(datagram_socket_with(payload));

        let mut buf = [0_u8; 32];
        let n = receive_message(&sock, &mut buf).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn receive_message_reads_exact_fit_datagram() {
        let payload = b"exactfit";
        assert_eq!(payload.len(), 8);
        let sock = skip_if_sandbox_denies!(datagram_socket_with(payload));

        let mut buf = [0_u8; 8];
        let n = receive_message(&sock, &mut buf).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf, payload);
    }

    #[test]
    fn receive_message_rejects_truncated_datagram() {
        let payload = b"0123456789abcdef";
        assert_eq!(payload.len(), 16);
        let sock = skip_if_sandbox_denies!(datagram_socket_with(payload));

        let mut buf = [0_u8; 8];
        let err = receive_message(&sock, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("truncated"), "{err}");
    }
}
