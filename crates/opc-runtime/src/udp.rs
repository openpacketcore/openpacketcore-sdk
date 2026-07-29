//! UDP receive and exact-source reply helpers with local destination metadata.
//!
//! These helpers are intended for protocols such as IKEv2 NAT detection where a
//! datagram's concrete local destination address is part of protocol evidence
//! and must also be selected as the source of the corresponding reply.

#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
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
#[derive(Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdpSocketOptions {
    /// Linux or Android network device name the socket is scoped to with
    /// `SO_BINDTODEVICE` before `bind(2)`, for example a VRF device carrying
    /// IKE/NAT-T traffic. Must be non-empty, at most 15 bytes
    /// (`IFNAMSIZ - 1`), and free of NUL bytes. On other platforms a
    /// configured device makes binding fail closed with
    /// [`io::ErrorKind::Unsupported`].
    pub bind_device: Option<String>,
    /// Require `IPV6_V6ONLY` before binding an IPv6 socket.
    ///
    /// The default is false, preserving the ordinary runtime UDP surface.
    /// The egress-fence installer enables this option so an IPv4-mapped send
    /// cannot bypass an exact IPv6 protected endpoint. It has no effect for an
    /// IPv4 bind. Non-Linux platforms may reject an enabled value when they
    /// cannot prove the setting.
    pub ipv6_only: bool,
}

impl UdpSocketOptions {
    /// Return these options with `bind_device` set to `device`.
    #[must_use]
    pub fn with_bind_device(mut self, device: impl Into<String>) -> Self {
        self.bind_device = Some(device.into());
        self
    }

    /// Return these options with strict IPv6-only binding enabled.
    #[must_use]
    pub const fn with_ipv6_only(mut self) -> Self {
        self.ipv6_only = true;
        self
    }
}

impl fmt::Debug for UdpSocketOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpSocketOptions")
            .field("bind_device_present", &self.bind_device.is_some())
            .field("ipv6_only", &self.ipv6_only)
            .finish()
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
/// Returns [`io::Error`] when no Tokio runtime is entered, the entered runtime
/// has no I/O driver, or binding, configuring, or converting the socket fails.
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
/// lifecycle. On platforms without `SO_BINDTODEVICE` a configured device fails
/// closed with [`io::ErrorKind::Unsupported`]; it is never silently ignored.
/// With `bind_device` unset this behaves exactly like
/// [`bind_udp_socket_with_destination_metadata`].
///
/// # Linux capability contract
///
/// The Linux kernel's own check (`sock_bindtoindex_locked()` in
/// `net/core/sock.c`) is `sk->sk_bound_dev_if && !ns_capable(net->user_ns,
/// CAP_NET_RAW)`, so it applies only to a socket that is *already*
/// device-bound:
///
/// - A socket that is not yet device-bound is not capability-gated for its
///   first `SO_BINDTODEVICE`. This holds on upstream mainline since v5.7
///   (commit `c427bfec18f2`, "net: core: enable SO_BINDTODEVICE for non-root
///   users"); upstream mainline before v5.7 gates every device bind, in a
///   function then named `sock_setbindtodevice_locked()`.
/// - A socket that is already device-bound still needs `CAP_NET_RAW` — in the
///   user namespace that owns its network namespace, not merely in its network
///   namespace — to be re-bound, including to the *same* device, or unbound.
///   That state is reachable at socket creation: a `sock_create` cgroup hook
///   may write `sk_bound_dev_if` during `socket(2)` (`ip vrf exec` is one such
///   mechanism), so a freshly created socket is not guaranteed to be unbound.
/// - On upstream mainline since v5.1 an unknown device name is `ENODEV`
///   regardless of capabilities, because `sock_setbindtodevice()` resolves the
///   name before the capability is consulted. Upstream mainline before v5.1
///   tests the capability first and returns `EPERM` without resolving the name.
///
/// This describes the kernel's own capability check only; LSM (for example
/// SELinux) and seccomp policy are out of scope. The version scope above is a
/// statement about upstream mainline; distribution and Android kernels backport
/// independently and are not verified here.
///
/// # Errors
///
/// Returns [`io::ErrorKind::InvalidInput`] for an empty, over-long
/// (more than 15 bytes), or NUL-containing device name,
/// [`io::ErrorKind::Unsupported`] for a device on a platform without
/// `SO_BINDTODEVICE`, a value-free error when no Tokio runtime is entered or
/// the entered runtime has no I/O driver, and any operating-system error from
/// socket creation, device binding, address binding, configuration, or
/// conversion.
pub fn bind_udp_socket_with_destination_metadata_and_options(
    bind_addr: SocketAddr,
    options: &UdpSocketOptions,
) -> io::Result<UdpDestinationMetadataSocket> {
    if let Some(device) = options.bind_device.as_deref() {
        validate_bind_device(device)?;
    }
    // `tokio::net::UdpSocket::from_std` panics when no thread-local runtime is
    // entered, and also when a runtime is entered without its I/O driver.
    // `Handle::try_current` proves only the first property. Reject it before
    // binding when possible, then contain the second Tokio boundary so this
    // public Result-returning API never propagates either panic. If conversion
    // unwinds, the moved standard socket is naturally dropped by unwinding.
    tokio::runtime::Handle::try_current()
        .map_err(|_| udp_error(io::ErrorKind::Other, "udp_runtime_unavailable"))?;
    let socket =
        platform::bind_udp_socket(bind_addr, options.bind_device.as_deref(), options.ipv6_only)?;
    socket.set_nonblocking(true)?;
    let support = platform::enable_destination_metadata(&socket)?;
    let socket =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| UdpSocket::from_std(socket)))
            .map_err(|_| udp_error(io::ErrorKind::Other, "udp_runtime_io_unavailable"))??;
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
pub struct UdpDestinationMetadataSocket {
    socket: UdpSocket,
    support: UdpDestinationMetadataSupport,
    bind_device: Option<String>,
}

impl fmt::Debug for UdpDestinationMetadataSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpDestinationMetadataSocket")
            .field("support", &self.support)
            .field("bind_device_present", &self.bind_device.is_some())
            .field("socket", &"<redacted>")
            .finish()
    }
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
    ///
    /// This is the ordinary, unfenced runtime surface. Opting into
    /// `opc-egress-fence` consumes a socket created inside that crate before
    /// exposing its fenced guardian controls, so this accessor does not create
    /// an alternate path from a `FencedUdpSocket`.
    #[must_use]
    pub const fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Read the full-width Linux socket cookie without exposing a descriptor.
    ///
    /// # Errors
    ///
    /// Returns a value-free operating-system error when the cookie cannot be
    /// read exactly or is zero.
    #[cfg(target_os = "linux")]
    pub fn socket_kernel_identity(&self) -> io::Result<opc_linux_gtpu_sys::SocketKernelIdentity> {
        opc_linux_gtpu_sys::socket_kernel_identity(self.socket.as_fd())
    }

    /// Prove the socket is unconnected and neither address- nor port-reusable.
    ///
    /// This is a narrow admission readback for exclusive fenced ownership. It
    /// intentionally exposes no descriptor: a borrowed descriptor would let
    /// callers duplicate it or create an alternate send path.
    ///
    /// # Errors
    ///
    /// Returns a stable, value-free error when the peer state cannot be read,
    /// the socket is connected, a reuse option cannot be read, or either
    /// `SO_REUSEADDR` or `SO_REUSEPORT` is enabled.
    #[cfg(target_os = "linux")]
    pub fn verify_exclusive_unconnected(&self) -> io::Result<()> {
        use nix::sys::socket::{
            getsockopt,
            sockopt::{ReuseAddr, ReusePort},
        };

        match self.socket.peer_addr() {
            Err(error) if error.kind() == io::ErrorKind::NotConnected => {}
            Ok(_) => {
                return Err(udp_error(
                    io::ErrorKind::PermissionDenied,
                    "udp_socket_connected",
                ));
            }
            Err(_) => {
                return Err(udp_error(io::ErrorKind::Other, "udp_socket_peer_readback"));
            }
        }
        let reuse_addr = getsockopt(&self.socket, ReuseAddr)
            .map_err(|_| udp_error(io::ErrorKind::Other, "udp_reuse_addr_readback"))?;
        let reuse_port = getsockopt(&self.socket, ReusePort)
            .map_err(|_| udp_error(io::ErrorKind::Other, "udp_reuse_port_readback"))?;
        if reuse_addr || reuse_port {
            return Err(udp_error(
                io::ErrorKind::PermissionDenied,
                "udp_socket_reusable",
            ));
        }
        Ok(())
    }

    /// Prove all admission properties required by the Linux egress fence.
    ///
    /// This combines unconnected/exclusive ownership with exact readback of
    /// `FREEBIND`, `TRANSPARENT`, and (for IPv6) `IPV6_V6ONLY`. No descriptor
    /// is exposed.
    ///
    /// # Errors
    ///
    /// Returns a stable, value-free error when any readback fails or an unsafe
    /// option is enabled.
    #[cfg(target_os = "linux")]
    pub fn verify_fence_admission(&self) -> io::Result<()> {
        use nix::sys::socket::{getsockopt, sockopt::BindToDevice};

        self.verify_exclusive_unconnected()?;
        let bound_device = getsockopt(&self.socket, BindToDevice)
            .map_err(|_| udp_error(io::ErrorKind::Other, "udp_bind_device_readback"))?;
        if !bound_device.is_empty() {
            return Err(udp_error(
                io::ErrorKind::PermissionDenied,
                "udp_socket_device_bound",
            ));
        }
        let ipv6 = self
            .local_addr()
            .map_err(|_| udp_error(io::ErrorKind::Other, "udp_local_addr_readback"))?
            .is_ipv6();
        opc_linux_gtpu_sys::verify_udp_fence_socket_options(self.socket.as_fd(), ipv6)
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
        bind, getsockopt, recvmsg, sendmsg, setsockopt, socket,
        sockopt::{BindToDevice, Ipv4PacketInfo, Ipv6RecvPacketInfo, Ipv6V6Only},
        AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
        SockaddrIn, SockaddrIn6, SockaddrStorage,
    };
    use tokio::{io::Interest, net::UdpSocket};

    use super::{
        fallback_local_destination, udp_error, validate_complete_datagram,
        UdpDestinationMetadataSupport, UdpLocalDestination, UdpLocalDestinationUnavailableReason,
        UdpReceivedDatagram,
    };

    pub(super) fn bind_udp_socket(
        bind_addr: SocketAddr,
        device: Option<&str>,
        ipv6_only: bool,
    ) -> io::Result<std::net::UdpSocket> {
        let family = match bind_addr {
            SocketAddr::V4(_) => AddressFamily::Inet,
            SocketAddr::V6(_) => AddressFamily::Inet6,
        };
        let fd = socket(family, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None)
            .map_err(io::Error::from)?;
        if let Some(device) = device {
            let expected = OsString::from(device);
            setsockopt(&fd, BindToDevice, &expected).map_err(io::Error::from)?;
            if getsockopt(&fd, BindToDevice).map_err(io::Error::from)? != expected {
                return Err(udp_error(
                    io::ErrorKind::Other,
                    "udp_bind_device_readback_mismatch",
                ));
            }
        }
        if bind_addr.is_ipv6() && ipv6_only {
            setsockopt(&fd, Ipv6V6Only, &true).map_err(io::Error::from)?;
            if !getsockopt(&fd, Ipv6V6Only).map_err(io::Error::from)? {
                return Err(udp_error(
                    io::ErrorKind::Other,
                    "udp_ipv6_only_readback_mismatch",
                ));
            }
        }
        match bind_addr {
            SocketAddr::V4(addr) => bind(fd.as_raw_fd(), &SockaddrIn::from(addr)),
            SocketAddr::V6(addr) => bind(fd.as_raw_fd(), &SockaddrIn6::from(addr)),
        }
        .map_err(io::Error::from)?;
        Ok(std::net::UdpSocket::from(fd))
    }

    /// Create a UDP socket scoped to `device` with `SO_BINDTODEVICE` applied
    /// before `bind(2)`, matching the option's pre-bind requirement.
    pub(super) fn bind_udp_socket_to_device(
        bind_addr: SocketAddr,
        device: &str,
    ) -> io::Result<std::net::UdpSocket> {
        bind_udp_socket(bind_addr, Some(device), false)
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
        // that cannot re-apply the device (the device disappeared, or the
        // probe socket was itself device-bound at creation and re-binding it
        // needs `CAP_NET_RAW`) stays inconclusive.
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

        // Linux-specific: asserts how this kernel's `SO_BINDTODEVICE` errors
        // are classified. Android shares the code path but is not verified.
        #[cfg(target_os = "linux")]
        #[test]
        fn source_bind_probe_with_unusable_device_is_inconclusive() {
            // An unknown device fails whatever the caller's capabilities are:
            // ENODEV on upstream mainline since v5.1, which resolves the name
            // before it tests CAP_NET_RAW, and EPERM before that. Neither is
            // evidence about source locality, so the probe must stay
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

    pub(super) fn bind_udp_socket(
        bind_addr: SocketAddr,
        device: Option<&str>,
        ipv6_only: bool,
    ) -> io::Result<std::net::UdpSocket> {
        if device.is_some() || ipv6_only {
            return Err(udp_error(
                io::ErrorKind::Unsupported,
                "udp_bind_option_unsupported",
            ));
        }
        std::net::UdpSocket::bind(bind_addr)
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

    #[test]
    fn bind_without_an_entered_runtime_returns_a_value_free_error() {
        let error = bind_udp_socket_with_destination_metadata_and_options(
            loopback_any_port(),
            &UdpSocketOptions::default(),
        )
        .expect_err("a Tokio runtime is required");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "udp_runtime_unavailable");
    }

    #[test]
    fn entered_runtime_without_io_returns_an_error_and_drops_the_descriptor() {
        let probe = std::net::UdpSocket::bind(loopback_any_port()).expect("reserve endpoint");
        let endpoint = probe.local_addr().expect("reserved endpoint");
        drop(probe);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime without I/O");
        let _entered = runtime.enter();

        let error = bind_udp_socket_with_destination_metadata_and_options(
            endpoint,
            &UdpSocketOptions::default(),
        )
        .expect_err("an entered runtime without I/O must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "udp_runtime_io_unavailable");
        std::net::UdpSocket::bind(endpoint).expect("failed conversion must close its descriptor");
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

    // The next three cases depend on Linux `SO_BINDTODEVICE` behaviour.
    // Android shares the code path but is not verified, so they stay
    // Linux-only rather than claiming a result nobody has observed there.

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bind_device_unknown_device_fails_closed() {
        // On upstream mainline since v5.1 `sock_setbindtodevice()` resolves the
        // device name before the capability is consulted, so an unknown device
        // is ENODEV whether or not the caller holds CAP_NET_RAW. EPERM stays
        // admissible because upstream mainline before v5.1 tests
        // `ns_capable(net->user_ns, CAP_NET_RAW)` first and never reaches the
        // lookup. Either way the bind must fail instead of silently falling
        // back to the default routing instance.
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bind_device_loopback_scopes_the_socket() {
        // This case proves device scoping, not the capability rule. It holds
        // only while the socket this call creates is not already device-bound
        // -- a `sock_create` cgroup hook (`ip vrf exec` is one such mechanism)
        // can bind it during `socket(2)`, after which CAP_NET_RAW is required
        // and the outcome would say nothing about scoping. Read the
        // precondition back from the kernel instead of assuming it.
        if let Some(reason) = device_bound_at_creation() {
            skip(&format!(
                "{reason}, so the unbound-socket precondition of \
                 bind_device_loopback_scopes_the_socket does not hold"
            ));
            return;
        }

        let options = UdpSocketOptions::default().with_bind_device("lo");

        let socket =
            bind_udp_socket_with_destination_metadata_and_options(loopback_any_port(), &options)
                .expect("SO_BINDTODEVICE lo before bind");

        // `bind_device()` only echoes the configured name back, and the bind
        // address is already loopback, so neither observes the kernel. Read
        // `SO_BINDTODEVICE` off the socket itself: that is the only assertion
        // here a regression in `bind_udp_socket_to_device` could fail.
        let scope =
            nix::sys::socket::getsockopt(&socket.socket, nix::sys::socket::sockopt::BindToDevice)
                .expect("SO_BINDTODEVICE readback");
        assert_eq!(scope, std::ffi::OsString::from("lo"));

        assert_eq!(socket.bind_device(), Some("lo"));
        assert!(socket
            .local_addr()
            .expect("bound local addr")
            .ip()
            .is_loopback());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rebinding_an_already_device_bound_socket_needs_cap_net_raw() {
        // The other half of the documented contract.
        // `sock_bindtoindex_locked()` gates on `sk->sk_bound_dev_if &&
        // !ns_capable(net->user_ns, CAP_NET_RAW)`, so once a socket is
        // device-bound even a re-bind to the SAME device needs the capability.
        // Exercised on a bare socket because no SDK entry point re-binds one it
        // already created; this keeps the documented rule executable rather
        // than letting the prose drift.
        use nix::sys::socket::{
            setsockopt, socket, sockopt::BindToDevice, AddressFamily, SockFlag, SockType,
        };

        if let Some(reason) = device_bound_at_creation() {
            skip(&format!(
                "{reason}, so the socket below arrives already device-bound and neither \
                 setsockopt would be its first bind"
            ));
            return;
        }

        let sock = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .expect("probe socket");
        let loopback = std::ffi::OsString::from("lo");

        if let Err(errno) = setsockopt(&sock, BindToDevice, &loopback) {
            // Upstream mainline before v5.7 gates every device bind, so the
            // first bind can legitimately fail here and the second one would
            // prove nothing about the already-bound rule.
            skip(&format!("the first device bind failed with {errno}"));
            return;
        }

        match setsockopt(&sock, BindToDevice, &loopback) {
            Err(nix::errno::Errno::EPERM) => {}
            Ok(()) => skip(
                "re-binding an already device-bound socket succeeded, so this process holds \
                 CAP_NET_RAW in the user namespace owning its network namespace and the case \
                 cannot discriminate",
            ),
            Err(errno) => panic!("expected EPERM re-binding a device-bound socket, got {errno}"),
        }
    }

    /// Report an environmental skip on stderr.
    ///
    /// libtest captures `eprintln!` and discards it for a case that passes, so
    /// a skip announced that way is invisible in a default run and the case
    /// silently counts as proof. Writing to the process stderr the harness does
    /// not capture keeps it visible.
    #[cfg(target_os = "linux")]
    fn skip(reason: &str) {
        use std::io::Write;

        let _ = writeln!(io::stderr(), "skipping: {reason}");
    }

    /// Why a freshly created UDP socket cannot serve as an unbound-socket
    /// precondition, or `None` when it reads back unbound.
    ///
    /// A readback error is not a pass: `sock_getbindtodevice()` returns the
    /// `netdev_get_name()` error when `sk_bound_dev_if` is non-zero but no
    /// longer resolves, which is itself a device-bound socket.
    #[cfg(target_os = "linux")]
    fn device_bound_at_creation() -> Option<String> {
        use nix::sys::socket::{
            getsockopt, socket, sockopt::BindToDevice, AddressFamily, SockFlag, SockType,
        };

        let probe = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .expect("probe socket");
        match getsockopt(&probe, BindToDevice) {
            Ok(device) if device.is_empty() => None,
            Ok(_) => Some("sockets are device-bound at creation".to_owned()),
            Err(_) => Some("the SO_BINDTODEVICE readback failed".to_owned()),
        }
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

    #[tokio::test]
    async fn socket_debug_and_kernel_identity_are_redaction_safe() {
        let socket =
            bind_udp_socket_with_destination_metadata(loopback_any_port()).expect("runtime bind");
        let local = socket.local_addr().expect("bound local endpoint");
        let debug = format!("{socket:?}");

        assert!(debug.contains("socket: \"<redacted>\""));
        assert!(!debug.contains(&local.ip().to_string()));
        assert!(!debug.contains(&local.port().to_string()));
        #[cfg(target_os = "linux")]
        {
            socket
                .verify_exclusive_unconnected()
                .expect("exclusive socket readback");
            assert_eq!(
                format!(
                    "{:?}",
                    socket
                        .socket_kernel_identity()
                        .expect("full-width socket identity")
                ),
                "SocketKernelIdentity(<redacted>)"
            );
        }
    }
}
