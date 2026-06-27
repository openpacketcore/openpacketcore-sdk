use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::NETLINK_XFRM;

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

    #[test]
    fn receive_message_reads_fitting_datagram() {
        let payload = b"hello xfrm";
        let sock = match datagram_socket_with(payload) {
            Some(sock) => sock,
            None => return,
        };

        let mut buf = [0_u8; 32];
        let n = receive_message(&sock, &mut buf).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn receive_message_reads_exact_fit_datagram() {
        let payload = b"exactfit";
        assert_eq!(payload.len(), 8);
        let sock = match datagram_socket_with(payload) {
            Some(sock) => sock,
            None => return,
        };

        let mut buf = [0_u8; 8];
        let n = receive_message(&sock, &mut buf).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf, payload);
    }

    #[test]
    fn receive_message_rejects_truncated_datagram() {
        let payload = b"0123456789abcdef";
        assert_eq!(payload.len(), 16);
        let sock = match datagram_socket_with(payload) {
            Some(sock) => sock,
            None => return,
        };

        let mut buf = [0_u8; 8];
        let err = receive_message(&sock, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("truncated"), "{err}");
    }
}
