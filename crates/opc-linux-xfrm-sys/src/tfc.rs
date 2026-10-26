//! Raw protocol-59 socket calls; capability and policy semantics live in the safe wrapper.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::{io, mem, net::IpAddr};

#[derive(Debug)]
pub struct TfcDummySocket {
    fd: OwnedFd,
}

pub fn open(source: IpAddr, destination: IpAddr, policy: &[u8]) -> io::Result<TfcDummySocket> {
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mixed socket families",
        ));
    }
    let family = if source.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: Constant socket parameters; the fresh descriptor is immediately owned.
    let raw = unsafe {
        libc::socket(
            family,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            59,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is the fresh descriptor returned above, with no other owner.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let (level, option) = if source.is_ipv4() {
        (libc::IPPROTO_IP, 17)
    } else {
        (libc::IPPROTO_IPV6, 35)
    };
    let len = libc::socklen_t::try_from(policy.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "policy too long"))?;
    // SAFETY: The policy slice remains valid for its checked length; setsockopt copies it.
    let result =
        unsafe { libc::setsockopt(fd.as_raw_fd(), level, option, policy.as_ptr().cast(), len) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    address_call(&fd, source, true)?;
    address_call(&fd, destination, false)?;
    Ok(TfcDummySocket { fd })
}

fn address_call(fd: &OwnedFd, ip: IpAddr, bind: bool) -> io::Result<()> {
    let call = |address: *const libc::sockaddr, len| {
        // SAFETY: Each caller supplies an initialized sockaddr of the stated family/size.
        unsafe {
            if bind {
                libc::bind(fd.as_raw_fd(), address, len)
            } else {
                libc::connect(fd.as_raw_fd(), address, len)
            }
        }
    };
    let result = match ip {
        IpAddr::V4(ip) => {
            let address = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(ip.octets()),
                },
                sin_zero: [0; 8],
            };
            call(
                (&address as *const libc::sockaddr_in).cast(),
                mem::size_of_val(&address) as _,
            )
        }
        IpAddr::V6(ip) => {
            let address = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as _,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: ip.octets(),
                },
                sin6_scope_id: 0,
            };
            call(
                (&address as *const libc::sockaddr_in6).cast(),
                mem::size_of_val(&address) as _,
            )
        }
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl TfcDummySocket {
    pub fn send(&self, payload: &[u8]) -> io::Result<usize> {
        // SAFETY: The live descriptor and immutable slice remain valid through send.
        let result = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                payload.as_ptr().cast(),
                payload.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }
}
