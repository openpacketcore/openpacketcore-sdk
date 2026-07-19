use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

#[derive(Debug)]
pub struct NetlinkSocket {
    fd: OwnedFd,
}

impl NetlinkSocket {
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

pub fn open_netlink_socket() -> io::Result<NetlinkSocket> {
    // SAFETY: `socket` is called with constant Linux netlink domain/type values
    // and NETLINK_ROUTE. On success the descriptor is fresh and transferred
    // immediately into `OwnedFd`; on failure no descriptor is owned.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            crate::NETLINK_ROUTE,
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
    let mut peer = kernel_netlink_addr(0);
    let mut peer_len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: `buffer` is a valid writable byte slice for its length, `peer`
    // and `peer_len` are initialized writable address outputs, and the socket
    // fd is live. `MSG_TRUNC` returns the real datagram length when it exceeds
    // the buffer so truncation can be rejected below.
    let rc = unsafe {
        libc::recvfrom(
            socket.fd.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            libc::MSG_TRUNC,
            (&mut peer as *mut libc::sockaddr_nl).cast::<libc::sockaddr>(),
            &mut peer_len,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else if peer_len != mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t
        || i32::from(peer.nl_family) != libc::AF_NETLINK
        || peer.nl_pid != 0
        || peer.nl_groups != 0
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rtnetlink datagram did not originate from the kernel",
        ))
    } else if rc as usize > buffer.len() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rtnetlink datagram truncated",
        ))
    } else {
        Ok(rc as usize)
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
