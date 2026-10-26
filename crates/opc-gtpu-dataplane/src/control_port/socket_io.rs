//! Packet-info I/O shared by retained kernel-GTP and sealed eBPF sockets.

use nix::sys::socket::{
    recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage,
};
use std::io::{self, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, BorrowedFd};

pub(crate) struct Received {
    pub length: usize,
    pub peer: SocketAddr,
    pub local: IpAddr,
    pub ifindex: u32,
    pub queue_drops: Option<u32>,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid GTP-U packet-info envelope",
    )
}

pub(crate) fn local_tuple(ip: IpAddr, port: u16, ifindex: u32) -> SocketAddr {
    match ip {
        IpAddr::V4(_) => SocketAddr::new(ip, port),
        IpAddr::V6(ip) => SocketAddrV6::new(
            ip,
            port,
            0,
            if ip.is_unicast_link_local() {
                ifindex
            } else {
                0
            },
        )
        .into(),
    }
}

pub(crate) fn set_packet_info(fd: BorrowedFd<'_>, ipv6: bool) -> io::Result<()> {
    use nix::sys::socket::{setsockopt, sockopt};
    if ipv6 {
        setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true)?;
    } else {
        setsockopt(&fd, sockopt::Ipv4PacketInfo, &true)?;
    }
    Ok(())
}

pub(crate) fn receive(
    fd: BorrowedFd<'_>,
    buffer: &mut [u8],
    flags: MsgFlags,
 ) -> io::Result<Option<Received>> {
    receive_tracked(fd, buffer, flags, &mut false)
}

pub(crate) fn receive_tracked(
    fd: BorrowedFd<'_>,
    buffer: &mut [u8],
    flags: MsgFlags,
    consumed: &mut bool,
) -> io::Result<Option<Received>> {
    let mut control_space = nix::cmsg_space!(nix::libc::in_pktinfo, nix::libc::in6_pktinfo, u32);
    let mut iov = [IoSliceMut::new(buffer)];
    let message =
        match recvmsg::<SockaddrStorage>(fd.as_raw_fd(), &mut iov, Some(&mut control_space), flags)
        {
            Ok(message) => message,
            Err(nix::errno::Errno::EAGAIN) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    *consumed = true;
    crate::reassembly::validate_reassembly_envelope_flags(message.flags)?;
    let address = message.address.ok_or_else(invalid)?;
    let peer: SocketAddr = if let Some(v4) = address.as_sockaddr_in() {
        (*v4).into()
    } else if let Some(v6) = address.as_sockaddr_in6() {
        (*v6).into()
    } else {
        return Err(invalid());
    };
    let mut packet_info = None;
    let mut queue_drops = None;
    for control in message.cmsgs().map_err(|_| invalid())? {
        let info = match control {
            ControlMessageOwned::Ipv4PacketInfo(info) => Some((
                IpAddr::V4(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes())),
                u32::try_from(info.ipi_ifindex).map_err(|_| invalid())?,
            )),
            ControlMessageOwned::Ipv6PacketInfo(info) => Some((
                IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                info.ipi6_ifindex,
            )),
            ControlMessageOwned::RxqOvfl(drops) => {
                queue_drops = Some(drops);
                None
            }
            _ => None,
        };
        if let Some(info) = info {
            if packet_info.replace(info).is_some() {
                return Err(invalid());
            }
        }
    }
    let (local, ifindex) = packet_info.ok_or_else(invalid)?;
    if local.is_unspecified() || local.is_ipv4() != peer.is_ipv4() {
        return Err(invalid());
    }
    Ok(Some(Received {
        length: message.bytes,
        peer,
        local,
        ifindex,
        queue_drops,
    }))
}

pub(crate) fn send(
    fd: BorrowedFd<'_>,
    source: SocketAddr,
    peer: SocketAddr,
    bytes: &[u8],
) -> io::Result<usize> {
    let v4_info;
    let v6_info;
    // Pin the chosen source even when the retained socket has a wildcard bind.
    let control = match (source, peer) {
        (SocketAddr::V4(source), SocketAddr::V4(_)) => {
            v4_info = nix::libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: nix::libc::in_addr {
                    s_addr: u32::from_ne_bytes(source.ip().octets()),
                },
                ipi_addr: nix::libc::in_addr { s_addr: 0 },
            };
            ControlMessage::Ipv4PacketInfo(&v4_info)
        }
        (SocketAddr::V6(source), SocketAddr::V6(_)) => {
            v6_info = nix::libc::in6_pktinfo {
                ipi6_addr: nix::libc::in6_addr {
                    s6_addr: source.ip().octets(),
                },
                ipi6_ifindex: source.scope_id(),
            };
            ControlMessage::Ipv6PacketInfo(&v6_info)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GTP-U address family mismatch",
            ))
        }
    };
    let written = sendmsg(
        fd.as_raw_fd(),
        &[IoSlice::new(bytes)],
        &[control],
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
        Some(&SockaddrStorage::from(peer)),
    )?;
    if written != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial GTP-U datagram send",
        ));
    }
    Ok(written)
}
