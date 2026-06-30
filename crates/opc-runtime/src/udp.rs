//! UDP receive helpers with local destination metadata.
//!
//! These helpers are intended for protocols such as IKEv2 NAT detection where a
//! datagram's concrete local destination address is part of protocol evidence.

use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
};

use tokio::net::UdpSocket;

/// Bind a UDP socket that can report local destination metadata on receive.
///
/// On Linux this enables packet-info ancillary metadata before converting the
/// socket into Tokio's nonblocking socket type. Other platforms fall back to
/// concrete `local_addr()` reporting when the socket was bound to a specific
/// address.
///
/// # Errors
///
/// Returns [`io::Error`] when binding, configuring, or converting the socket
/// fails.
pub fn bind_udp_socket_with_destination_metadata(
    bind_addr: SocketAddr,
) -> io::Result<UdpDestinationMetadataSocket> {
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    let support = platform::enable_destination_metadata(&socket)?;
    let socket = UdpSocket::from_std(socket)?;
    Ok(UdpDestinationMetadataSocket { socket, support })
}

/// Receive one UDP datagram and return source and local destination metadata.
///
/// Use [`bind_udp_socket_with_destination_metadata`] when binding a listener so
/// packet-info metadata is enabled before the first receive where the platform
/// supports it.
///
/// # Errors
///
/// Returns [`io::Error`] when the receive operation or socket metadata lookup
/// fails.
pub async fn recv_udp_datagram_with_destination(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> io::Result<UdpReceivedDatagram> {
    platform::recv_udp_datagram_with_destination(socket, buffer).await
}

/// UDP socket wrapper that receives datagrams with destination metadata.
#[derive(Debug)]
pub struct UdpDestinationMetadataSocket {
    socket: UdpSocket,
    support: UdpDestinationMetadataSupport,
}

impl UdpDestinationMetadataSocket {
    /// Return the local socket address.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the OS cannot report the socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Return the platform destination-metadata support mode.
    #[must_use]
    pub const fn destination_metadata_support(&self) -> UdpDestinationMetadataSupport {
        self.support
    }

    /// Return the wrapped Tokio UDP socket.
    #[must_use]
    pub const fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Receive one UDP datagram into `buffer`.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the receive operation or socket metadata
    /// lookup fails.
    pub async fn recv_from_with_destination(
        &self,
        buffer: &mut [u8],
    ) -> io::Result<UdpReceivedDatagram> {
        recv_udp_datagram_with_destination(&self.socket, buffer).await
    }
}

/// Platform mechanism available for UDP local destination metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpDestinationMetadataSupport {
    /// Packet-info ancillary data can provide per-datagram destination address.
    AncillaryPacketInfo,
    /// Destination can only be inferred from a concrete socket `local_addr()`.
    LocalAddrOnly,
    /// The current platform has no supported per-datagram destination helper.
    UnsupportedPlatform,
}

/// UDP receive result with source and local destination metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct UdpReceivedDatagram {
    bytes: usize,
    source: SocketAddr,
    local_destination: UdpLocalDestination,
}

impl UdpReceivedDatagram {
    /// Build a receive result.
    #[must_use]
    pub const fn new(
        bytes: usize,
        source: SocketAddr,
        local_destination: UdpLocalDestination,
    ) -> Self {
        Self {
            bytes,
            source,
            local_destination,
        }
    }

    /// Number of payload bytes written into the caller's buffer.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Source endpoint of the datagram.
    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    /// Local destination endpoint metadata.
    #[must_use]
    pub const fn local_destination(&self) -> UdpLocalDestination {
        self.local_destination
    }
}

impl fmt::Debug for UdpReceivedDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpReceivedDatagram")
            .field("bytes", &self.bytes)
            .field("has_source", &true)
            .field("local_destination", &self.local_destination)
            .finish()
    }
}

/// Local destination endpoint for a received UDP datagram.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UdpLocalDestination {
    /// Concrete local destination endpoint.
    SocketAddr(SocketAddr),
    /// Concrete local destination endpoint was unavailable.
    Unavailable(UdpLocalDestinationUnavailableReason),
}

impl UdpLocalDestination {
    /// Build a local destination from a socket address.
    #[must_use]
    pub const fn socket_addr(addr: SocketAddr) -> Self {
        Self::SocketAddr(addr)
    }

    /// Build an unavailable local destination status.
    #[must_use]
    pub const fn unavailable(reason: UdpLocalDestinationUnavailableReason) -> Self {
        Self::Unavailable(reason)
    }

    /// Return the concrete destination endpoint when available.
    #[must_use]
    pub const fn socket_addr_value(self) -> Option<SocketAddr> {
        match self {
            Self::SocketAddr(addr) => Some(addr),
            Self::Unavailable(_) => None,
        }
    }

    /// Return destination metadata availability.
    #[must_use]
    pub const fn status(self) -> UdpLocalDestinationStatus {
        match self {
            Self::SocketAddr(_) => UdpLocalDestinationStatus::Concrete,
            Self::Unavailable(reason) => UdpLocalDestinationStatus::Unavailable(reason),
        }
    }
}

impl fmt::Debug for UdpLocalDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketAddr(_) => f
                .debug_struct("SocketAddr")
                .field("status", &UdpLocalDestinationStatus::Concrete)
                .finish(),
            Self::Unavailable(reason) => f.debug_tuple("Unavailable").field(reason).finish(),
        }
    }
}

/// Local destination metadata status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpLocalDestinationStatus {
    /// A concrete local destination endpoint is available.
    Concrete,
    /// Destination endpoint is unavailable for a known reason.
    Unavailable(UdpLocalDestinationUnavailableReason),
}

/// Reason a concrete UDP local destination endpoint is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpLocalDestinationUnavailableReason {
    /// Current platform has no packet-info destination helper.
    UnsupportedPlatform,
    /// Packet-info ancillary data was not present on this datagram.
    AncillaryDataMissing,
    /// Packet-info ancillary data was truncated by the OS.
    AncillaryDataTruncated,
    /// The socket local address is a wildcard address.
    WildcardLocalAddr,
}

fn fallback_local_destination(
    local_addr: SocketAddr,
    reason: UdpLocalDestinationUnavailableReason,
) -> UdpLocalDestination {
    if is_concrete_ip(local_addr.ip()) {
        UdpLocalDestination::socket_addr(local_addr)
    } else {
        UdpLocalDestination::unavailable(reason)
    }
}

fn is_concrete_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
        os::fd::AsRawFd,
    };

    use nix::sys::socket::{
        recvmsg, setsockopt,
        sockopt::{Ipv4PacketInfo, Ipv6RecvPacketInfo},
        ControlMessageOwned, MsgFlags, SockaddrStorage,
    };
    use tokio::{io::Interest, net::UdpSocket};

    use super::{
        fallback_local_destination, UdpDestinationMetadataSupport, UdpLocalDestination,
        UdpLocalDestinationUnavailableReason, UdpReceivedDatagram,
    };

    pub(super) fn enable_destination_metadata(
        socket: &std::net::UdpSocket,
    ) -> io::Result<UdpDestinationMetadataSupport> {
        let local_addr = socket.local_addr()?;
        match local_addr {
            SocketAddr::V4(_) => {
                setsockopt(socket, Ipv4PacketInfo, &true).map_err(io::Error::from)?;
            }
            SocketAddr::V6(_) => {
                setsockopt(socket, Ipv6RecvPacketInfo, &true).map_err(io::Error::from)?;
            }
        }
        Ok(UdpDestinationMetadataSupport::AncillaryPacketInfo)
    }

    pub(super) async fn recv_udp_datagram_with_destination(
        socket: &UdpSocket,
        buffer: &mut [u8],
    ) -> io::Result<UdpReceivedDatagram> {
        socket
            .async_io(Interest::READABLE, || recv_packet_info(socket, buffer))
            .await
    }

    fn recv_packet_info(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<UdpReceivedDatagram> {
        let mut iov = [io::IoSliceMut::new(buffer)];
        let mut control = nix::cmsg_space!(nix::libc::in_pktinfo, nix::libc::in6_pktinfo);
        let msg = recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::empty(),
        )
        .map_err(io::Error::from)?;

        let source = msg
            .address
            .as_ref()
            .and_then(socket_addr_from_sockaddr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "udp_source_unavailable"))?;
        let local_addr = socket.local_addr()?;
        let local_port = local_addr.port();
        let local_destination = if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
            fallback_local_destination(
                local_addr,
                UdpLocalDestinationUnavailableReason::AncillaryDataTruncated,
            )
        } else {
            packet_info_destination(&msg, local_port).unwrap_or_else(|| {
                fallback_local_destination(
                    local_addr,
                    UdpLocalDestinationUnavailableReason::AncillaryDataMissing,
                )
            })
        };

        Ok(UdpReceivedDatagram::new(
            msg.bytes,
            source,
            local_destination,
        ))
    }

    fn packet_info_destination(
        msg: &nix::sys::socket::RecvMsg<'_, '_, SockaddrStorage>,
        local_port: u16,
    ) -> Option<UdpLocalDestination> {
        let mut cmsgs = msg.cmsgs().ok()?;
        for cmsg in &mut cmsgs {
            match cmsg {
                ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                    let ip = Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr));
                    return Some(UdpLocalDestination::socket_addr(SocketAddr::V4(
                        SocketAddrV4::new(ip, local_port),
                    )));
                }
                ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                    let ip = Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr);
                    return Some(UdpLocalDestination::socket_addr(SocketAddr::V6(
                        SocketAddrV6::new(ip, local_port, 0, pktinfo.ipi6_ifindex),
                    )));
                }
                _ => {}
            }
        }
        None
    }

    fn socket_addr_from_sockaddr(addr: &SockaddrStorage) -> Option<SocketAddr> {
        if let Some(addr) = addr.as_sockaddr_in() {
            return Some(SocketAddr::V4(SocketAddrV4::from(*addr)));
        }
        if let Some(addr) = addr.as_sockaddr_in6() {
            let addr = SocketAddrV6::from(*addr);
            return Some(SocketAddr::V6(addr));
        }
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod platform {
    use std::{io, net::SocketAddr};

    use tokio::net::UdpSocket;

    use super::{
        fallback_local_destination, UdpDestinationMetadataSupport,
        UdpLocalDestinationUnavailableReason, UdpReceivedDatagram,
    };

    pub(super) fn enable_destination_metadata(
        _socket: &std::net::UdpSocket,
    ) -> io::Result<UdpDestinationMetadataSupport> {
        Ok(UdpDestinationMetadataSupport::LocalAddrOnly)
    }

    pub(super) async fn recv_udp_datagram_with_destination(
        socket: &UdpSocket,
        buffer: &mut [u8],
    ) -> io::Result<UdpReceivedDatagram> {
        let (bytes, source) = socket.recv_from(buffer).await?;
        let local_addr = socket
            .local_addr()
            .unwrap_or_else(|_| unspecified_like(source));
        let local_destination = fallback_local_destination(
            local_addr,
            UdpLocalDestinationUnavailableReason::UnsupportedPlatform,
        );
        Ok(UdpReceivedDatagram::new(bytes, source, local_destination))
    }

    fn unspecified_like(source: SocketAddr) -> SocketAddr {
        match source {
            SocketAddr::V4(addr) => {
                SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), addr.port())
            }
            SocketAddr::V6(addr) => {
                SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), addr.port())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        fallback_local_destination, UdpLocalDestination, UdpLocalDestinationStatus,
        UdpLocalDestinationUnavailableReason, UdpReceivedDatagram,
    };

    #[test]
    fn concrete_local_addr_is_preserved_as_destination() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 500);

        let destination = fallback_local_destination(
            addr,
            UdpLocalDestinationUnavailableReason::UnsupportedPlatform,
        );

        assert_eq!(destination.socket_addr_value(), Some(addr));
        assert_eq!(destination.status(), UdpLocalDestinationStatus::Concrete);
    }

    #[test]
    fn wildcard_local_addr_is_not_concrete_destination_evidence() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 500);

        let destination = fallback_local_destination(
            addr,
            UdpLocalDestinationUnavailableReason::UnsupportedPlatform,
        );

        assert_eq!(destination.socket_addr_value(), None);
        assert_eq!(
            destination.status(),
            UdpLocalDestinationStatus::Unavailable(
                UdpLocalDestinationUnavailableReason::UnsupportedPlatform
            )
        );
    }

    #[test]
    fn debug_redacts_udp_endpoints() {
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 4500);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 500);
        let received =
            UdpReceivedDatagram::new(4, source, UdpLocalDestination::socket_addr(destination));

        let debug = format!("{received:?}");

        assert!(!debug.contains("192.0.2.10"));
        assert!(!debug.contains("198.51.100.20"));
        assert!(debug.contains("bytes"));
        assert!(debug.contains("local_destination"));
    }
}
