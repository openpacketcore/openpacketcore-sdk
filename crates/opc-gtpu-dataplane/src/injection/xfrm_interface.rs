//! Retained packet binding and bounded, notification-aware identity acquisition.

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use nix::sys::socket::{
    bind, recvmsg, send, sendto, setsockopt, socket, sockopt, AddressFamily, MsgFlags, NetlinkAddr,
    SockFlag, SockProtocol, SockType,
};

use super::{GtpBearerMark, GtpuDownlinkInjectionError as Error, Ipv4Sender};

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const NLMSG_ERROR: u16 = 2;
const NLMSG_OVERRUN: u16 = 4;
const RTMGRP_LINK: u32 = 1;
const IF_INFO_LEN: usize = 16;
const NL_HEADER_LEN: usize = 16;
const MAX_DATAGRAMS: usize = 256;
const IDENTITY_DEADLINE: Duration = Duration::from_secs(1);

pub(super) struct XfrmInterfaceSocket {
    fd: OwnedFd,
}

impl XfrmInterfaceSocket {
    #[cfg(test)]
    pub(super) fn assert_receive_queue_empty(&self) {
        assert_eq!(
            nix::sys::socket::recv(
                self.fd.as_raw_fd(),
                &mut [0_u8; 1],
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_PEEK,
            ),
            Err(nix::errno::Errno::EAGAIN),
            "the injection socket must not retain inbound packets"
        );
    }

    pub(super) fn open(ifindex: u32, if_id: u32) -> Result<Self, Error> {
        Self::open_checked(ifindex, if_id, || {})
    }

    // One hook provides a deterministic replacement window to the native
    // regression; production passes a no-op and never exposes the socket.
    pub(super) fn open_checked(
        ifindex: u32,
        if_id: u32,
        before_bind: impl FnOnce(),
    ) -> Result<Self, Error> {
        if ifindex == 0 || ifindex > i32::MAX as u32 || if_id == 0 {
            return Err(Error::InvalidInterface);
        }
        let mut monitor = LinkMonitor::open(ifindex)?;
        let before = monitor.query(1, if_id)?;
        before_bind();
        let fd =
            opc_linux_gtpu_sys::open_bound_ipv4_packet_socket(ifindex).map_err(socket_error)?;
        setsockopt(&fd, sockopt::Mark, &0_u32).map_err(socket_error)?;
        // GETLINK is handled under RTNL. On this subscribed socket its reply
        // follows earlier RTNL link notifications, including a delete/create
        // with the same ifindex, kind and if_id. ENOBUFS/truncation fail closed.
        let after = monitor.query(2, if_id)?;
        let bound =
            opc_linux_gtpu_sys::bound_ipv4_packet_ifindex(fd.as_fd()).map_err(socket_error)?;
        if before != after || bound != ifindex {
            return Err(Error::InterfaceIdentityMismatch);
        }
        Ok(Self { fd })
    }
}

impl Ipv4Sender for XfrmInterfaceSocket {
    fn send(&mut self, packet: &[u8], mark: Option<GtpBearerMark>) -> io::Result<usize> {
        setsockopt(&self.fd, sockopt::Mark, &mark.map_or(0, GtpBearerMark::get))?;
        // No sockaddr: packet_snd uses its retained cached_dev. Passing an
        // ifindex here would resolve a replacement and defeat this contract.
        send(self.fd.as_raw_fd(), packet, MsgFlags::MSG_DONTWAIT).map_err(io::Error::from)
    }
}

fn socket_error(error: impl Into<io::Error>) -> Error {
    let error = error.into();
    let kind = error.kind();
    if matches!(
        error.raw_os_error(),
        Some(nix::libc::ENODEV | nix::libc::ENXIO)
    ) || kind == io::ErrorKind::NotFound
    {
        Error::InterfaceUnavailable
    } else if kind == io::ErrorKind::Unsupported {
        Error::UnsupportedPlatform
    } else {
        Error::Socket { kind }
    }
}

fn malformed() -> Error {
    Error::Socket {
        kind: io::ErrorKind::InvalidData,
    }
}

fn timed_out() -> Error {
    Error::Socket {
        kind: io::ErrorKind::TimedOut,
    }
}

struct LinkMonitor {
    fd: OwnedFd,
    ifindex: u32,
    deadline: Instant,
    remaining_datagrams: usize,
}

impl LinkMonitor {
    fn open(ifindex: u32) -> Result<Self, Error> {
        let deadline = Instant::now() + IDENTITY_DEADLINE;
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            SockProtocol::NetlinkRoute,
        )
        .map_err(socket_error)?;
        // Subscribe before the first identity read. Do not suppress ENOBUFS:
        // the constructor requires continuity, not a best-effort snapshot.
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, RTMGRP_LINK)).map_err(socket_error)?;
        Ok(Self {
            fd,
            ifindex,
            deadline,
            remaining_datagrams: MAX_DATAGRAMS,
        })
    }

    fn query(&mut self, sequence: u32, if_id: u32) -> Result<LinkIdentity, Error> {
        let mut request = [0_u8; NL_HEADER_LEN + IF_INFO_LEN];
        request[..4].copy_from_slice(&((NL_HEADER_LEN + IF_INFO_LEN) as u32).to_ne_bytes());
        request[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
        request[6..8].copy_from_slice(&1_u16.to_ne_bytes()); // NLM_F_REQUEST
        request[8..12].copy_from_slice(&sequence.to_ne_bytes());
        request[20..24].copy_from_slice(&self.ifindex.to_ne_bytes());
        let sent = sendto(
            self.fd.as_raw_fd(),
            &request,
            &NetlinkAddr::new(0, 0),
            MsgFlags::MSG_DONTWAIT,
        )
        .map_err(socket_error)?;
        if sent != request.len() {
            return Err(socket_error(io::Error::from(io::ErrorKind::WriteZero)));
        }
        let mut buffer = vec![0_u8; 65_536];
        loop {
            if Instant::now() >= self.deadline || self.remaining_datagrams == 0 {
                return Err(timed_out());
            }
            let received = {
                let mut slices = [io::IoSliceMut::new(&mut buffer)];
                recvmsg::<NetlinkAddr>(
                    self.fd.as_raw_fd(),
                    &mut slices,
                    None,
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
                )
                .map(|message| (message.bytes, message.address, message.flags))
            };
            let (size, sender, flags) = match received {
                Ok(received) => received,
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => return Err(socket_error(error)),
            };
            self.remaining_datagrams -= 1;
            let sender = sender.ok_or_else(malformed)?;
            if sender.pid() != 0
                || !matches!(sender.groups(), 0 | RTMGRP_LINK)
                || size > buffer.len()
                || flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
            {
                return Err(malformed());
            }
            if let Some(identity) = parse_messages(
                &buffer[..size],
                sender.groups() == RTMGRP_LINK,
                sequence,
                self.ifindex,
                if_id,
            )? {
                if Instant::now() >= self.deadline {
                    return Err(timed_out());
                }
                return Ok(identity);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct LinkIdentity {
    underlying_link: u32,
    if_id: u32,
}

fn parse_messages(
    mut bytes: &[u8],
    multicast: bool,
    sequence: u32,
    ifindex: u32,
    if_id: u32,
) -> Result<Option<LinkIdentity>, Error> {
    let mut identity = None;
    while !bytes.is_empty() {
        if bytes.len() < NL_HEADER_LEN {
            return Err(malformed());
        }
        let length = usize::try_from(read_u32(&bytes[..4])?).map_err(|_| malformed())?;
        let kind = read_u16(&bytes[4..6])?;
        let flags = read_u16(&bytes[6..8])?;
        if !(NL_HEADER_LEN..=bytes.len()).contains(&length)
            || length.next_multiple_of(4) > bytes.len()
            || flags & 0x10 != 0 // NLM_F_DUMP_INTR
            || kind == NLMSG_OVERRUN
        {
            return Err(malformed());
        }
        let body = &bytes[NL_HEADER_LEN..length];
        if multicast {
            if !matches!(kind, RTM_NEWLINK | RTM_DELLINK) || body.len() < IF_INFO_LEN {
                return Err(malformed());
            }
            if read_u32(&body[4..8])? == ifindex {
                return Err(Error::InterfaceIdentityMismatch);
            }
        } else {
            if read_u32(&bytes[8..12])? != sequence {
                return Err(malformed());
            }
            if kind == NLMSG_ERROR {
                let errno = i32::from_ne_bytes(
                    body.get(..4)
                        .ok_or_else(malformed)?
                        .try_into()
                        .map_err(|_| malformed())?,
                );
                let positive = errno
                    .checked_neg()
                    .filter(|errno| *errno > 0)
                    .ok_or_else(malformed)?;
                return Err(socket_error(io::Error::from_raw_os_error(positive)));
            }
            if kind != RTM_NEWLINK || identity.is_some() {
                return Err(malformed());
            }
            identity = Some(parse_identity(body, ifindex, if_id)?);
        }
        bytes = &bytes[length.next_multiple_of(4)..];
    }
    Ok(identity)
}

fn parse_identity(body: &[u8], ifindex: u32, expected_if_id: u32) -> Result<LinkIdentity, Error> {
    if body.len() < IF_INFO_LEN || read_u32(&body[4..8])? != ifindex {
        return Err(Error::InterfaceIdentityMismatch);
    }
    let attrs = &body[IF_INFO_LEN..];
    // ARPHRD_NONE and no IFLA_LINK_NETNSID (cross-namespace device).
    if read_u16(&body[2..4])? != 0xfffe || attribute(attrs, 37)?.is_some() {
        return Err(Error::UnsupportedInterface);
    }
    let info = attribute(attrs, 18)?.ok_or(Error::UnsupportedInterface)?; // IFLA_LINKINFO
    if attribute(info, 1)? != Some(b"xfrm\0") {
        // IFLA_INFO_KIND
        return Err(Error::UnsupportedInterface);
    }
    let data = attribute(info, 2)?.ok_or_else(malformed)?; // IFLA_INFO_DATA
    if attribute(data, 3)?.is_some() {
        // IFLA_XFRM_COLLECT_METADATA
        return Err(Error::UnsupportedInterface);
    }
    let if_id = read_u32(attribute(data, 2)?.ok_or_else(malformed)?)?;
    if if_id == 0 || if_id != expected_if_id {
        return Err(Error::InterfaceIdentityMismatch);
    }
    Ok(LinkIdentity {
        underlying_link: read_u32(attribute(data, 1)?.ok_or_else(malformed)?)?,
        if_id,
    })
}

fn attribute(mut bytes: &[u8], wanted: u16) -> Result<Option<&[u8]>, Error> {
    let mut found = None;
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(malformed());
        }
        let length = usize::from(read_u16(&bytes[..2])?);
        let kind = read_u16(&bytes[2..4])?;
        if !(4..=bytes.len()).contains(&length) || length.next_multiple_of(4) > bytes.len() {
            return Err(malformed());
        }
        if kind & 0x3fff == wanted
            && (kind & 0x4000 != 0 || found.replace(&bytes[4..length]).is_some())
        {
            return Err(malformed());
        }
        bytes = &bytes[length.next_multiple_of(4)..];
    }
    Ok(found)
}

fn read_u32(bytes: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_ne_bytes(
        bytes.try_into().map_err(|_| malformed())?,
    ))
}

fn read_u16(bytes: &[u8]) -> Result<u16, Error> {
    Ok(u16::from_ne_bytes(
        bytes.try_into().map_err(|_| malformed())?,
    ))
}

#[cfg(test)]
mod tests;
