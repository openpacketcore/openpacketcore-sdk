//! UDP receive and exact-source reply helpers with local destination metadata.
//!
//! These helpers are intended for protocols such as IKEv2 NAT detection where a
//! datagram's concrete local destination address is part of protocol evidence
//! and must also be selected as the source of the corresponding reply.

use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
};

use tokio::net::UdpSocket;

const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

/// Longest accepted [`UdpSocketOptions::bind_device`] name in bytes: Linux
/// `IFNAMSIZ` (16) minus the trailing NUL byte.
const MAX_BIND_DEVICE_BYTES: usize = 15;

/// Typed options for binding a destination-metadata UDP socket.
///
/// The struct is `#[non_exhaustive]` so future socket options can be added
/// without breaking consumers: build it with [`UdpSocketOptions::default`] and
/// set only the options you need.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdpSocketOptions {
    /// Linux or Android network device name the socket is scoped to with
    /// `SO_BINDTODEVICE` before `bind(2)`, for example a VRF device carrying
    /// IKE/NAT-T traffic. Must be non-empty, at most 15 bytes
    /// (`IFNAMSIZ - 1`), and free of NUL bytes. On other platforms a
    /// configured device makes binding fail closed with
    /// [`io::ErrorKind::Unsupported`].
    pub bind_device: Option<String>,
}

impl UdpSocketOptions {
    /// Return these options with `bind_device` set to `device`.
    #[must_use]
    pub fn with_bind_device(mut self, device: impl Into<String>) -> Self {
        self.bind_device = Some(device.into());
        self
    }
}

/// Bind a UDP socket that can report local destination metadata on receive.
///
/// On Linux this enables packet-info ancillary metadata before converting the
/// socket into Tokio's nonblocking socket type. Other platforms fall back to
/// concrete `local_addr()` reporting when the socket was bound to a specific
/// address.
///
/// Equivalent to [`bind_udp_socket_with_destination_metadata_and_options`]
/// with default [`UdpSocketOptions`].
///
/// # Errors
///
/// Returns [`io::Error`] when binding, configuring, or converting the socket
/// fails.
pub fn bind_udp_socket_with_destination_metadata(
    bind_addr: SocketAddr,
) -> io::Result<UdpDestinationMetadataSocket> {
    bind_udp_socket_with_destination_metadata_and_options(bind_addr, &UdpSocketOptions::default())
}

/// Bind a UDP socket with destination metadata and typed socket options.
///
/// With [`UdpSocketOptions::bind_device`] set, the socket is created first and
/// `SO_BINDTODEVICE` is applied before `bind(2)`, scoping the socket to that
/// network device (for example a VRF) for the whole bind/receive/send
/// lifecycle. This requires `CAP_NET_RAW` on Linux. On platforms without
/// `SO_BINDTODEVICE` a configured device fails closed with
/// [`io::ErrorKind::Unsupported`]; it is never silently ignored. With
/// `bind_device` unset this behaves exactly like
/// [`bind_udp_socket_with_destination_metadata`].
///
/// # Errors
///
/// Returns [`io::ErrorKind::InvalidInput`] for an empty, over-long
/// (more than 15 bytes), or NUL-containing device name,
/// [`io::ErrorKind::Unsupported`] for a device on a platform without
/// `SO_BINDTODEVICE`, and any operating-system error from socket creation,
/// device binding, address binding, configuration, or conversion.
pub fn bind_udp_socket_with_destination_metadata_and_options(
    bind_addr: SocketAddr,
    options: &UdpSocketOptions,
) -> io::Result<UdpDestinationMetadataSocket> {
    if let Some(device) = options.bind_device.as_deref() {
        validate_bind_device(device)?;
    }
    let socket = match options.bind_device.as_deref() {
        Some(device) => platform::bind_udp_socket_to_device(bind_addr, device)?,
        None => std::net::UdpSocket::bind(bind_addr)?,
    };
    socket.set_nonblocking(true)?;
    let support = platform::enable_destination_metadata(&socket)?;
    let socket = UdpSocket::from_std(socket)?;
    Ok(UdpDestinationMetadataSocket {
        socket,
        support,
        bind_device: options.bind_device.clone(),
    })
}

fn validate_bind_device(device: &str) -> io::Result<()> {
    if device.is_empty() {
        return Err(udp_error(
            io::ErrorKind::InvalidInput,
            "udp_bind_device_empty",
        ));
    }
    if device.len() > MAX_BIND_DEVICE_BYTES {
        return Err(udp_error(
            io::ErrorKind::InvalidInput,
            "udp_bind_device_too_long",
        ));
    }
    if device.as_bytes().contains(&0) {
        return Err(udp_error(
            io::ErrorKind::InvalidInput,
            "udp_bind_device_nul",
        ));
    }
    Ok(())
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
    bind_device: Option<String>,
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

    /// Return the `SO_BINDTODEVICE` device name this socket is scoped to, when
    /// one was configured at bind time.
    #[must_use]
    pub fn bind_device(&self) -> Option<&str> {
        self.bind_device.as_deref()
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

    /// Send one UDP datagram to `peer` from the exact `local_source` endpoint.
    ///
    /// This is the symmetric reply operation for
    /// [`Self::recv_from_with_destination`]. On Linux and Android it selects
    /// the source address with packet-info ancillary data. Other platforms
    /// only send when this socket is concretely bound to `local_source`; they
    /// return [`io::ErrorKind::Unsupported`] when exact source selection cannot
    /// be guaranteed.
    ///
    /// Payloads larger than 65,507 bytes are rejected before touching the
    /// socket. `local_source` must use this socket's address family and bound
    /// port. It must be a concrete, unicast, locally available address. An IPv6
    /// link-local source must include its interface scope.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for an invalid payload or source
    /// selection, [`io::ErrorKind::AddrNotAvailable`] when the source is not
    /// local to this socket, [`io::ErrorKind::Unsupported`] when the platform
    /// cannot guarantee exact selection, or an operating-system send error.
    pub async fn send_to_from(
        &self,
        buffer: &[u8],
        peer: SocketAddr,
        local_source: SocketAddr,
    ) -> io::Result<usize> {
        let socket_local = self.socket.local_addr()?;
        validate_send_to_from(buffer.len(), socket_local, peer, local_source)?;
        platform::send_udp_datagram_from(
            &self.socket,
            buffer,
            peer,
            local_source,
            self.bind_device.as_deref(),
        )
        .await
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

fn validate_send_to_from(
    payload_len: usize,
    socket_local: SocketAddr,
    peer: SocketAddr,
    local_source: SocketAddr,
) -> io::Result<()> {
    if payload_len > MAX_UDP_PAYLOAD_BYTES {
        return Err(udp_error(
            io::ErrorKind::InvalidInput,
            "udp_payload_too_large",
        ));
    }
    if !same_address_family(socket_local, peer) || !same_address_family(peer, local_source) {
        return Err(udp_error(
            io::ErrorKind::InvalidInput,
            "udp_source_family_mismatch",
        ));
    }
    if local_source.port() != socket_local.port() {
        return Err(udp_error(
            io::ErrorKind::InvalidInput,
            "udp_source_port_mismatch",
        ));
    }
    validate_source_ip(local_source)?;
    if is_concrete_ip(socket_local.ip()) && socket_local.ip() != local_source.ip() {
        return Err(udp_error(
            io::ErrorKind::AddrNotAvailable,
            "udp_source_bound_address_mismatch",
        ));
    }
    if let (SocketAddr::V6(socket_local), SocketAddr::V6(local_source)) =
        (socket_local, local_source)
    {
        if socket_local.ip().is_unicast_link_local()
            && socket_local.scope_id() != 0
            && socket_local.scope_id() != local_source.scope_id()
        {
            return Err(udp_error(
                io::ErrorKind::AddrNotAvailable,
                "udp_source_bound_address_mismatch",
            ));
        }
    }
    Ok(())
}

fn validate_source_ip(local_source: SocketAddr) -> io::Result<()> {
    match local_source {
        SocketAddr::V4(source) => {
            let ip = *source.ip();
            if ip.is_unspecified() {
                return Err(udp_error(
                    io::ErrorKind::InvalidInput,
                    "udp_source_unspecified",
                ));
            }
            if ip.is_multicast() {
                return Err(udp_error(
                    io::ErrorKind::InvalidInput,
                    "udp_source_multicast",
                ));
            }
            if ip.is_broadcast() {
                return Err(udp_error(
                    io::ErrorKind::InvalidInput,
                    "udp_source_broadcast",
                ));
            }
        }
        SocketAddr::V6(source) => {
            let ip = *source.ip();
            if ip.is_unspecified() {
                return Err(udp_error(
                    io::ErrorKind::InvalidInput,
                    "udp_source_unspecified",
                ));
            }
            if ip.is_multicast() {
                return Err(udp_error(
                    io::ErrorKind::InvalidInput,
                    "udp_source_multicast",
                ));
            }
            if ip.is_unicast_link_local() && source.scope_id() == 0 {
                return Err(udp_error(
                    io::ErrorKind::InvalidInput,
                    "udp_source_scope_required",
                ));
            }
        }
    }
    Ok(())
}

const fn same_address_family(left: SocketAddr, right: SocketAddr) -> bool {
    matches!(
        (left, right),
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
    )
}

fn udp_error(kind: io::ErrorKind, code: &'static str) -> io::Error {
    io::Error::new(kind, code)
}

fn validate_complete_datagram(sent: usize, payload_len: usize) -> io::Result<usize> {
    if sent == payload_len {
        return Ok(sent);
    }
    if sent == 0 {
        return Err(udp_error(
            io::ErrorKind::WriteZero,
            "udp_datagram_write_zero",
        ));
    }
    Err(udp_error(io::ErrorKind::Other, "udp_datagram_partial_send"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use std::{
        ffi::OsString,
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
        os::fd::AsRawFd,
    };

    use nix::sys::socket::{
        bind, recvmsg, sendmsg, setsockopt, socket,
        sockopt::{BindToDevice, Ipv4PacketInfo, Ipv6RecvPacketInfo},
        AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
        SockaddrIn, SockaddrIn6, SockaddrStorage,
    };
    use tokio::{io::Interest, net::UdpSocket};

    use super::{
        fallback_local_destination, udp_error, validate_complete_datagram,
        UdpDestinationMetadataSupport, UdpLocalDestination, UdpLocalDestinationUnavailableReason,
        UdpReceivedDatagram,
    };

    /// Create a UDP socket scoped to `device` with `SO_BINDTODEVICE` applied
    /// before `bind(2)`, matching the option's pre-bind requirement.
    pub(super) fn bind_udp_socket_to_device(
        bind_addr: SocketAddr,
        device: &str,
    ) -> io::Result<std::net::UdpSocket> {
        let family = match bind_addr {
            SocketAddr::V4(_) => AddressFamily::Inet,
            SocketAddr::V6(_) => AddressFamily::Inet6,
        };
        let fd = socket(family, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None)
            .map_err(io::Error::from)?;
        setsockopt(&fd, BindToDevice, &OsString::from(device)).map_err(io::Error::from)?;
        match bind_addr {
            SocketAddr::V4(addr) => bind(fd.as_raw_fd(), &SockaddrIn::from(addr)),
            SocketAddr::V6(addr) => bind(fd.as_raw_fd(), &SockaddrIn6::from(addr)),
        }
        .map_err(io::Error::from)?;
        Ok(std::net::UdpSocket::from(fd))
    }

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

    pub(super) async fn send_udp_datagram_from(
        socket: &UdpSocket,
        buffer: &[u8],
        peer: SocketAddr,
        local_source: SocketAddr,
        bind_device: Option<&str>,
    ) -> io::Result<usize> {
        let interface_index = local_source_interface(local_source);
        let sent = socket
            .async_io(Interest::WRITABLE, || {
                send_packet_info(
                    socket,
                    buffer,
                    peer,
                    local_source,
                    interface_index,
                    bind_device,
                )
            })
            .await?;
        validate_complete_datagram(sent, buffer.len())
    }

    fn send_packet_info(
        socket: &UdpSocket,
        buffer: &[u8],
        peer: SocketAddr,
        local_source: SocketAddr,
        interface_index: u32,
        bind_device: Option<&str>,
    ) -> io::Result<usize> {
        let iov = [io::IoSlice::new(buffer)];
        match (peer, local_source) {
            (SocketAddr::V4(peer), SocketAddr::V4(source)) => {
                let interface_index = i32::try_from(interface_index).map_err(|_| {
                    udp_error(io::ErrorKind::InvalidInput, "udp_source_interface_invalid")
                })?;
                let packet_info = nix::libc::in_pktinfo {
                    ipi_ifindex: interface_index,
                    ipi_spec_dst: nix::libc::in_addr {
                        s_addr: u32::from_ne_bytes(source.ip().octets()),
                    },
                    ipi_addr: nix::libc::in_addr { s_addr: 0 },
                };
                let control = [ControlMessage::Ipv4PacketInfo(&packet_info)];
                let peer = SockaddrIn::from(peer);
                sendmsg(
                    socket.as_raw_fd(),
                    &iov,
                    &control,
                    MsgFlags::empty(),
                    Some(&peer),
                )
                .map_err(|error| map_send_error(error, local_source, bind_device))
            }
            (SocketAddr::V6(peer), SocketAddr::V6(source)) => {
                let packet_info = nix::libc::in6_pktinfo {
                    ipi6_addr: nix::libc::in6_addr {
                        s6_addr: source.ip().octets(),
                    },
                    ipi6_ifindex: interface_index,
                };
                let control = [ControlMessage::Ipv6PacketInfo(&packet_info)];
                let peer = SockaddrIn6::from(peer);
                sendmsg(
                    socket.as_raw_fd(),
                    &iov,
                    &control,
                    MsgFlags::empty(),
                    Some(&peer),
                )
                .map_err(|error| map_send_error(error, local_source, bind_device))
            }
            _ => Err(udp_error(
                io::ErrorKind::InvalidInput,
                "udp_source_family_mismatch",
            )),
        }
    }

    const fn local_source_interface(local_source: SocketAddr) -> u32 {
        match local_source {
            SocketAddr::V4(_) => 0,
            SocketAddr::V6(source) if source.ip().is_unicast_link_local() => source.scope_id(),
            SocketAddr::V6(_) => 0,
        }
    }

    fn map_send_error(
        error: nix::errno::Errno,
        local_source: SocketAddr,
        bind_device: Option<&str>,
    ) -> io::Error {
        match error {
            nix::errno::Errno::EADDRNOTAVAIL | nix::errno::Errno::ENODEV => {
                udp_error(io::ErrorKind::AddrNotAvailable, "udp_source_not_local")
            }
            nix::errno::Errno::EINVAL | nix::errno::Errno::ENETUNREACH
                if source_bind_probe(local_source, bind_device) == Some(false) =>
            {
                udp_error(io::ErrorKind::AddrNotAvailable, "udp_source_not_local")
            }
            nix::errno::Errno::ENOPROTOOPT
            | nix::errno::Errno::EPROTONOSUPPORT
            | nix::errno::Errno::EOPNOTSUPP => udp_error(
                io::ErrorKind::Unsupported,
                "udp_source_selection_unsupported",
            ),
            nix::errno::Errno::EMSGSIZE => {
                udp_error(io::ErrorKind::InvalidInput, "udp_payload_too_large")
            }
            other => io::Error::from(other),
        }
    }

    fn source_bind_probe(mut local_source: SocketAddr, bind_device: Option<&str>) -> Option<bool> {
        // Linux may report a non-local packet-info source as EINVAL or
        // ENETUNREACH, which are also valid peer/path errors. Probe only after
        // one of those failures so the success path remains one sendmsg and a
        // reachable peer is not misreported as a source-selection failure. The
        // probe inherits this socket's `SO_BINDTODEVICE` scope because a
        // VRF-local source is only bindable inside its VRF; probing the
        // default routing instance would misreport it as not local. A probe
        // that cannot re-apply the device (for example after privileges were
        // dropped post-bind) stays inconclusive.
        local_source.set_port(0);
        let probe = match bind_device {
            Some(device) => bind_udp_socket_to_device(local_source, device).map(drop),
            None => std::net::UdpSocket::bind(local_source).map(drop),
        };
        match probe {
            Ok(()) => Some(true),
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => Some(false),
            Err(_) => None,
        }
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

    #[cfg(test)]
    mod tests {
        use std::{io, net::SocketAddr};

        use nix::errno::Errno;

        use super::{map_send_error, source_bind_probe};

        fn local_source() -> SocketAddr {
            "127.0.0.1:500".parse().expect("fixed local source")
        }

        #[test]
        fn send_error_mapping_preserves_retry_and_normalizes_static_failures() {
            let would_block = map_send_error(Errno::EAGAIN, local_source(), None);
            assert_eq!(would_block.kind(), io::ErrorKind::WouldBlock);

            for errno in [
                Errno::ENOPROTOOPT,
                Errno::EPROTONOSUPPORT,
                Errno::EOPNOTSUPP,
            ] {
                let unsupported = map_send_error(errno, local_source(), None);
                assert_eq!(unsupported.kind(), io::ErrorKind::Unsupported);
                assert_eq!(unsupported.to_string(), "udp_source_selection_unsupported");
            }

            let unavailable = map_send_error(Errno::EADDRNOTAVAIL, local_source(), None);
            assert_eq!(unavailable.kind(), io::ErrorKind::AddrNotAvailable);
            assert_eq!(unavailable.to_string(), "udp_source_not_local");

            let oversized = map_send_error(Errno::EMSGSIZE, local_source(), None);
            assert_eq!(oversized.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(oversized.to_string(), "udp_payload_too_large");
        }

        #[test]
        fn source_bind_probe_without_device_matches_local_reality() {
            assert_eq!(source_bind_probe(local_source(), None), Some(true));

            // RFC 5737 TEST-NET-1 source is never locally assigned.
            let doc_source: SocketAddr = "192.0.2.10:500".parse().expect("doc source");
            assert_eq!(source_bind_probe(doc_source, None), Some(false));
        }

        #[test]
        fn source_bind_probe_with_unusable_device_is_inconclusive() {
            // The device cannot be applied to the probe socket (missing
            // device as root: ENODEV; without CAP_NET_RAW: EPERM). Neither
            // is evidence about source locality, so the probe must stay
            // inconclusive instead of misreporting `udp_source_not_local`.
            assert_eq!(source_bind_probe(local_source(), Some("opc-nodev0")), None);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod platform {
    use std::{io, net::SocketAddr};

    use tokio::net::UdpSocket;

    use super::{
        fallback_local_destination, udp_error, validate_complete_datagram,
        UdpDestinationMetadataSupport, UdpLocalDestinationUnavailableReason, UdpReceivedDatagram,
    };

    pub(super) fn bind_udp_socket_to_device(
        _bind_addr: SocketAddr,
        _device: &str,
    ) -> io::Result<std::net::UdpSocket> {
        // `SO_BINDTODEVICE` does not exist here. Fail closed instead of
        // binding in the default routing instance and silently dropping the
        // requested device scope.
        Err(udp_error(
            io::ErrorKind::Unsupported,
            "udp_bind_device_unsupported",
        ))
    }

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

    pub(super) async fn send_udp_datagram_from(
        socket: &UdpSocket,
        buffer: &[u8],
        peer: SocketAddr,
        local_source: SocketAddr,
        _bind_device: Option<&str>,
    ) -> io::Result<usize> {
        if socket.local_addr()? != local_source {
            return Err(udp_error(
                io::ErrorKind::Unsupported,
                "udp_source_selection_unsupported",
            ));
        }
        let sent = socket.send_to(buffer, peer).await?;
        validate_complete_datagram(sent, buffer.len())
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
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use super::{
        bind_udp_socket_with_destination_metadata,
        bind_udp_socket_with_destination_metadata_and_options, fallback_local_destination,
        validate_bind_device, validate_complete_datagram, UdpLocalDestination,
        UdpLocalDestinationStatus, UdpLocalDestinationUnavailableReason, UdpReceivedDatagram,
        UdpSocketOptions,
    };

    fn loopback_any_port() -> SocketAddr {
        "127.0.0.1:0".parse().expect("loopback bind addr")
    }

    #[test]
    fn bind_device_names_are_validated() {
        let empty = validate_bind_device("").unwrap_err();
        assert_eq!(empty.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(empty.to_string(), "udp_bind_device_empty");

        // 16 bytes: one over the Linux IFNAMSIZ - 1 limit.
        let too_long = validate_bind_device("eth-test-0123456").unwrap_err();
        assert_eq!(too_long.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(too_long.to_string(), "udp_bind_device_too_long");

        let interior_nul = validate_bind_device("eth\0test").unwrap_err();
        assert_eq!(interior_nul.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(interior_nul.to_string(), "udp_bind_device_nul");

        assert!(validate_bind_device("vrf-test").is_ok());
        // 15 bytes: the longest legal device name.
        assert!(validate_bind_device("eth-test-012345").is_ok());
    }

    #[tokio::test]
    async fn invalid_bind_device_is_rejected_before_any_bind() {
        let options = UdpSocketOptions::default().with_bind_device("");

        let error =
            bind_udp_socket_with_destination_metadata_and_options(loopback_any_port(), &options)
                .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "udp_bind_device_empty");
    }

    #[tokio::test]
    async fn default_options_bind_matches_legacy_bind() {
        let legacy =
            bind_udp_socket_with_destination_metadata(loopback_any_port()).expect("legacy bind");
        let with_options = bind_udp_socket_with_destination_metadata_and_options(
            loopback_any_port(),
            &UdpSocketOptions::default(),
        )
        .expect("default-options bind");

        assert_eq!(
            legacy.destination_metadata_support(),
            with_options.destination_metadata_support()
        );
        assert_eq!(legacy.bind_device(), None);
        assert_eq!(with_options.bind_device(), None);
        assert!(with_options
            .local_addr()
            .expect("bound local addr")
            .ip()
            .is_loopback());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn bind_device_missing_or_unprivileged_fails_closed() {
        // `SO_BINDTODEVICE` needs CAP_NET_RAW: without it the kernel returns
        // EPERM before it even looks the device up; with it a nonexistent
        // device is ENODEV. Either way the bind must fail instead of silently
        // falling back to the default routing instance.
        let options = UdpSocketOptions::default().with_bind_device("opc-nodev0");

        let error =
            bind_udp_socket_with_destination_metadata_and_options(loopback_any_port(), &options)
                .unwrap_err();

        let raw = error.raw_os_error();
        assert!(
            raw == Some(nix::libc::EPERM) || raw == Some(nix::libc::ENODEV),
            "expected EPERM or ENODEV from SO_BINDTODEVICE, got {error:?}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW; run: sudo -E $(command -v cargo) test -p opc-runtime --lib \
                udp::tests::bind_device_loopback_scopes_the_socket -- --ignored"]
    async fn bind_device_loopback_scopes_the_socket() {
        let options = UdpSocketOptions::default().with_bind_device("lo");

        let socket =
            bind_udp_socket_with_destination_metadata_and_options(loopback_any_port(), &options)
                .expect("SO_BINDTODEVICE lo before bind");

        assert_eq!(socket.bind_device(), Some("lo"));
        assert!(socket
            .local_addr()
            .expect("bound local addr")
            .ip()
            .is_loopback());
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[tokio::test]
    async fn bind_device_fails_closed_on_unsupported_platform() {
        let options = UdpSocketOptions::default().with_bind_device("eth-test");

        let error =
            bind_udp_socket_with_destination_metadata_and_options(loopback_any_port(), &options)
                .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(error.to_string(), "udp_bind_device_unsupported");
    }

    #[test]
    fn datagram_send_result_must_cover_the_complete_payload() {
        assert_eq!(validate_complete_datagram(4, 4).unwrap(), 4);

        let write_zero = validate_complete_datagram(0, 4).unwrap_err();
        assert_eq!(write_zero.kind(), std::io::ErrorKind::WriteZero);
        assert_eq!(write_zero.to_string(), "udp_datagram_write_zero");

        let partial = validate_complete_datagram(3, 4).unwrap_err();
        assert_eq!(partial.kind(), std::io::ErrorKind::Other);
        assert_eq!(partial.to_string(), "udp_datagram_partial_send");
    }

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
