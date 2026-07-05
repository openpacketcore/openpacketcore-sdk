use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::{GtpuIpAddress, GtpuUdpBind};

#[derive(Debug)]
pub struct NetlinkSocket {
    fd: OwnedFd,
}

impl NetlinkSocket {
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[derive(Debug)]
pub struct GtpuUdpSocket {
    fd: OwnedFd,
}

impl GtpuUdpSocket {
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
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
        Err(io::Error::last_os_error())
    } else {
        Ok(NetlinkSocket { fd })
    }
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
        Some((NetlinkSocket { fd: local }, peer))
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
}
