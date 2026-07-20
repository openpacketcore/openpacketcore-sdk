//! Post-reassembly downlink consumer for the kernel outer-fragment handoff.
//!
//! The tc downlink program passes outer IPv4 fragments to the kernel stack
//! unchanged (`TC_ACT_OK`); the kernel reassembles them under its bounded
//! `ipfrag` accounting and delivers exactly one complete UDP/2152 datagram to
//! the socket bound on the concrete local S2b-U address (never `0.0.0.0`).
//! This module is the SDK consumer for that re-entry point:
//! [`GtpuReassemblyConsumer::process`] mirrors the tc fast path's PDR
//! resolution, endpoint-binding validation, complete Active commit-graph
//! authorization, and inner destination checks, and returns the decapsulated
//! inner packet with its output bearer mark. Non-G-PDU GTP-U (echo, error
//! indication) is handed back for the control plane, matching the fast
//! path's pass-through.
//!
//! Deliberate, documented divergences from the tc fast path:
//!
//! - Checksum verification is the kernel's: socket delivery implies the
//!   kernel accepted the reassembled datagram, so the consumer performs no
//!   checksum probes of its own.
//! - Envelope padding strictness differs: tc requires the UDP end to equal
//!   the IPv4 end and drops padded envelopes, while the kernel strips layer-2
//!   padding before socket delivery, so a padded envelope that tc would drop
//!   unfragmented is accepted here after reassembly.
//! - The ingress ifindex and local destination are taken from the kernel's
//!   `IP_PKTINFO` control message. A positive per-datagram ifindex must match
//!   the sealed [`GtpuReassemblySocket`]; kernels that report zero after
//!   reassembly use only that socket's kernel-enforced `SO_BINDTODEVICE`
//!   identity. The SDK never substitutes an unverified caller value.
//!
//! The consumer's counters are userspace-side and deliberately *not* part of
//! the eBPF backend's identity-bound `datapath_snapshot` counters: the
//! snapshot aggregates the tc datapath's per-CPU maps, while these count the
//! post-reassembly socket path. Operators should monitor both.
//!
//! Socket lifecycle guidance for the embedding ePDG: call
//! [`GtpuReassemblySocket::set_receive_buffer_size`] for the expected
//! reassembled burst (kernel UDP buffer overruns drop silently and are not
//! visible in these counters), and shut down in reverse order —
//! detach the tc datapath first or close the consumer socket last — because
//! fragments arriving after the socket closes are answered with ICMP port
//! unreachable toward the PGW. Reassembly itself stays in the kernel, so
//! fragment memory and time are bounded by `net.ipv4.ipfrag_*` rather than
//! by any SDK state; the SDK never holds a userspace fragment cache.
//! Delivery of the decapsulated inner packet (route/XFRM injection) is the
//! embedding ePDG's choice and is deliberately out of scope here.

use std::fmt;
use std::net::Ipv4Addr;

use opc_gtpu_ebpf_common::{
    parse_gtpu_tpdu, DownlinkBindingMismatch, DownlinkEndpointBinding, GtpuReassemblyBounds,
    MarkedBearerOwner, MarkedDownlinkPdr, PdpContextCommit, UplinkFar, UplinkFarKey,
    MAX_REASSEMBLED_GTPU_LEN,
};

use crate::model::{GtpBearerMark, GTPU_PORT};

/// Read the live per-netns IPv4 reassembly bounds for capability reporting.
///
/// Returns `None` when either sysctl is unreadable; the bounds are never
/// fabricated from defaults, so a capability report carrying `None` means
/// "kernel limits unknown", not "kernel defaults".
#[cfg(target_os = "linux")]
#[must_use]
pub fn linux_reassembly_bounds() -> Option<GtpuReassemblyBounds> {
    fn read_sysctl_u32(path: &str) -> Option<u32> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|value| value.trim().parse().ok())
    }
    Some(GtpuReassemblyBounds {
        max_inflight_bytes: read_sysctl_u32("/proc/sys/net/ipv4/ipfrag_high_thresh")?,
        timeout_seconds: read_sysctl_u32("/proc/sys/net/ipv4/ipfrag_time")?,
    })
}

/// Bounded Linux IPv4 fragment-reassembly counters from `/proc/net/snmp`.
///
/// Linux exposes timeout failures separately and all other failed fragment
/// sets (including conflicting overlaps and resource-pressure evictions) as
/// one aggregate. It does not expose stable per-cause overlap and resource
/// counters, so callers must not infer either individual cause from
/// [`failed`](Self::failed).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GtpuKernelIpv4ReassemblyStats {
    /// Received IPv4 fragments that required reassembly (`ReasmReqds`).
    pub fragments_requested: u64,
    /// Fragment sets successfully reassembled (`ReasmOKs`).
    pub succeeded: u64,
    /// Fragment sets evicted after their bounded timeout (`ReasmTimeout`).
    pub timed_out: u64,
    /// All failed fragment sets (`ReasmFails`), including conflicting
    /// overlaps, resource-pressure eviction, malformed sets, and timeouts.
    pub failed: u64,
}

/// Stable, redaction-safe failure reading Linux IPv4 reassembly counters.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GtpuKernelReassemblyStatsError {
    /// `/proc/net/snmp` could not be opened or read.
    Unavailable,
    /// The bounded input was oversized, non-UTF-8, incomplete, duplicated,
    /// non-numeric, or otherwise malformed.
    Malformed,
}

#[cfg(target_os = "linux")]
impl GtpuKernelReassemblyStatsError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "gtpu_kernel_reassembly_stats_unavailable",
            Self::Malformed => "gtpu_kernel_reassembly_stats_malformed",
        }
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for GtpuKernelReassemblyStatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for GtpuKernelReassemblyStatsError {}

#[cfg(target_os = "linux")]
const MAX_PROC_NET_SNMP_BYTES: usize = 64 * 1024;

#[cfg(target_os = "linux")]
fn parse_linux_ipv4_reassembly_stats(
    input: &str,
) -> Result<GtpuKernelIpv4ReassemblyStats, GtpuKernelReassemblyStatsError> {
    if input.len() > MAX_PROC_NET_SNMP_BYTES {
        return Err(GtpuKernelReassemblyStatsError::Malformed);
    }

    let mut parsed = None;
    let mut lines = input.lines();
    while let Some(header_line) = lines.next() {
        if header_line.split_whitespace().next() != Some("Ip:") {
            continue;
        }
        if parsed.is_some() {
            return Err(GtpuKernelReassemblyStatsError::Malformed);
        }
        let value_line = lines
            .next()
            .ok_or(GtpuKernelReassemblyStatsError::Malformed)?;
        let mut headers = header_line.split_whitespace();
        let mut values = value_line.split_whitespace();
        if headers.next() != Some("Ip:") || values.next() != Some("Ip:") {
            return Err(GtpuKernelReassemblyStatsError::Malformed);
        }
        let headers = headers.collect::<Vec<_>>();
        let values = values.collect::<Vec<_>>();
        if headers.len() != values.len() || headers.is_empty() {
            return Err(GtpuKernelReassemblyStatsError::Malformed);
        }

        let mut stats = GtpuKernelIpv4ReassemblyStats::default();
        let mut required_fields = 0_u8;
        for (header, value) in headers.into_iter().zip(values) {
            let (slot, bit) = match header {
                "ReasmReqds" => (&mut stats.fragments_requested, 1_u8),
                "ReasmOKs" => (&mut stats.succeeded, 2_u8),
                "ReasmTimeout" => (&mut stats.timed_out, 4_u8),
                "ReasmFails" => (&mut stats.failed, 8_u8),
                _ => continue,
            };
            if required_fields & bit != 0 {
                return Err(GtpuKernelReassemblyStatsError::Malformed);
            }
            *slot = value
                .parse::<u64>()
                .map_err(|_| GtpuKernelReassemblyStatsError::Malformed)?;
            required_fields |= bit;
        }
        if required_fields != 0b1111 {
            return Err(GtpuKernelReassemblyStatsError::Malformed);
        }
        parsed = Some(stats);
    }

    parsed.ok_or(GtpuKernelReassemblyStatsError::Malformed)
}

/// Read a bounded, typed snapshot of Linux IPv4 fragment-reassembly counters.
///
/// The reader consumes at most 64 KiB, validates the paired `Ip:` header/value
/// rows and exact required field cardinality, and never includes procfs input
/// or I/O details in its error surface.
///
/// # Errors
///
/// Returns a stable [`GtpuKernelReassemblyStatsError`] when procfs is
/// unavailable or malformed.
#[cfg(target_os = "linux")]
pub fn read_linux_ipv4_reassembly_stats(
) -> Result<GtpuKernelIpv4ReassemblyStats, GtpuKernelReassemblyStatsError> {
    use std::io::Read;

    let file = std::fs::File::open("/proc/net/snmp")
        .map_err(|_| GtpuKernelReassemblyStatsError::Unavailable)?;
    let mut bytes = Vec::with_capacity(4 * 1024);
    file.take((MAX_PROC_NET_SNMP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| GtpuKernelReassemblyStatsError::Unavailable)?;
    if bytes.len() > MAX_PROC_NET_SNMP_BYTES {
        return Err(GtpuKernelReassemblyStatsError::Malformed);
    }
    let input =
        std::str::from_utf8(&bytes).map_err(|_| GtpuKernelReassemblyStatsError::Malformed)?;
    parse_linux_ipv4_reassembly_stats(input)
}

#[cfg(target_os = "linux")]
fn authoritative_ingress_ifindex(
    reported_ifindex: i32,
    socket_ifindex: u32,
) -> std::io::Result<u32> {
    if socket_ifindex == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sealed reassembly socket ifindex must be positive",
        ));
    }
    let reported_ifindex = u32::try_from(reported_ifindex).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid kernel ingress ifindex",
        )
    })?;
    if reported_ifindex == 0 {
        return Ok(socket_ifindex);
    }
    if reported_ifindex != socket_ifindex {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "kernel ingress ifindex conflicts with the managed interface",
        ));
    }
    Ok(reported_ifindex)
}

#[cfg(target_os = "linux")]
fn validate_reassembly_socket_address(
    local: std::net::SocketAddr,
    expected_address: Ipv4Addr,
) -> std::io::Result<()> {
    if expected_address.is_unspecified() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reassembly socket must use a concrete IPv4 UDP/2152 bind",
        ));
    }
    match local {
        std::net::SocketAddr::V4(local)
            if *local.ip() == expected_address && local.port() == GTPU_PORT =>
        {
            Ok(())
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "reassembly socket local binding changed",
        )),
    }
}

#[cfg(target_os = "linux")]
fn validate_reassembly_interface_name(interface_name: &str) -> std::io::Result<()> {
    let bytes = interface_name.as_bytes();
    if bytes.is_empty() || bytes.len() >= nix::libc::IFNAMSIZ || bytes.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid reassembly interface name",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_bound_device_readback(
    expected_name: &std::ffi::OsStr,
    expected_ifindex: u32,
    observed_name: &std::ffi::OsStr,
    observed_ifindex: u32,
) -> std::io::Result<()> {
    if expected_name.is_empty()
        || expected_ifindex == 0
        || observed_name.is_empty()
        || observed_ifindex == 0
        || observed_name != expected_name
        || observed_ifindex != expected_ifindex
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "reassembly socket device binding is not authoritative",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_reassembly_envelope_flags(flags: nix::sys::socket::MsgFlags) -> std::io::Result<()> {
    if flags
        .intersects(nix::sys::socket::MsgFlags::MSG_TRUNC | nix::sys::socket::MsgFlags::MSG_CTRUNC)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "truncated reassembly datagram envelope",
        ));
    }
    Ok(())
}

/// Exact outer provenance of one reassembled downlink GTP-U datagram.
///
/// The consumer receives these values from the delivery socket: peer address
/// and source port from the datagram source and the local destination from
/// `IP_PKTINFO`. A positive packet-info ifindex must match the sealed socket;
/// a zero packet-info ifindex uses only the same socket's live, verified
/// `SO_BINDTODEVICE` identity. These values authorize the datagram against the
/// same canonical
/// [`DownlinkEndpointBinding`] as the tc fast path.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DownlinkOuterProvenance {
    peer_address: Ipv4Addr,
    local_address: Ipv4Addr,
    ingress_ifindex: u32,
    source_port: u16,
}

impl DownlinkOuterProvenance {
    /// Construct one canonical provenance. Unspecified addresses and a zero
    /// ifindex cannot authorize anything and return `None`.
    #[must_use]
    pub(crate) fn new(
        peer_address: Ipv4Addr,
        local_address: Ipv4Addr,
        ingress_ifindex: u32,
        source_port: u16,
    ) -> Option<Self> {
        if peer_address.is_unspecified() || local_address.is_unspecified() || ingress_ifindex == 0 {
            return None;
        }
        Some(Self {
            peer_address,
            local_address,
            ingress_ifindex,
            source_port,
        })
    }

    /// Return the outer peer (PGW) address.
    #[must_use]
    pub const fn peer_address(&self) -> Ipv4Addr {
        self.peer_address
    }

    /// Return the local outer destination address.
    #[must_use]
    pub const fn local_address(&self) -> Ipv4Addr {
        self.local_address
    }

    /// Return the ingress interface index the datagram arrived on.
    #[must_use]
    pub const fn ingress_ifindex(&self) -> u32 {
        self.ingress_ifindex
    }

    /// Return the outer UDP source port.
    #[must_use]
    pub const fn source_port(&self) -> u16 {
        self.source_port
    }
}

impl fmt::Debug for DownlinkOuterProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownlinkOuterProvenance")
            .field("peer_address", &"<redacted>")
            .field("local_address", &"<redacted>")
            .field("ingress_ifindex", &"<redacted>")
            .field("source_port", &"<redacted>")
            .finish()
    }
}

/// Sealed Linux UDP/2152 socket for authoritative post-reassembly delivery.
///
/// [`GtpuReassemblySocket::bind`] applies `SO_BINDTODEVICE` before `bind(2)`,
/// derives a positive ifindex from the interface name, binds a concrete local
/// IPv4 address, enables `IP_PKTINFO`, and verifies the kernel's device
/// readback before returning. Private fields and the absence of a wrapping
/// constructor prevent an ordinary unbound socket from becoming
/// authoritative.
#[cfg(target_os = "linux")]
pub struct GtpuReassemblySocket {
    socket: std::net::UdpSocket,
    interface_name: std::ffi::OsString,
    ingress_ifindex: u32,
    local_address: Ipv4Addr,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for GtpuReassemblySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuReassemblySocket")
            .field("interface_name", &"<redacted>")
            .field("ingress_ifindex", &"<redacted>")
            .field("local_address", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl GtpuReassemblySocket {
    /// Bind a sealed post-reassembly socket to `interface_name` and the
    /// concrete local S2b-U `local_address` on UDP/2152.
    ///
    /// `SO_BINDTODEVICE` is set before `bind(2)`. The returned identity comes
    /// from positive interface-name lookup plus exact kernel socket-option
    /// readback; no caller-provided ifindex is accepted.
    /// Setting `SO_BINDTODEVICE` requires the process to hold the applicable
    /// Linux network capability (normally `CAP_NET_RAW`) in this namespace.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe `InvalidInput` for an empty/unknown interface
    /// or unspecified address. Socket creation, device binding, address
    /// binding, packet-info setup, or mismatched kernel readback return stable
    /// operation labels without the interface name or address.
    pub fn bind(local_address: Ipv4Addr, interface_name: &str) -> std::io::Result<Self> {
        use nix::sys::socket::{
            bind, getsockopt, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType,
            SockaddrIn,
        };
        use std::ffi::OsString;
        use std::net::SocketAddrV4;
        use std::os::fd::AsRawFd;

        if local_address.is_unspecified() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid reassembly socket identity",
            ));
        }
        validate_reassembly_interface_name(interface_name)?;
        let interface_name = OsString::from(interface_name);
        let ingress_ifindex =
            nix::net::if_::if_nametoindex(interface_name.as_os_str()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "reassembly interface lookup failed",
                )
            })?;
        if ingress_ifindex == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "reassembly interface lookup returned zero",
            ));
        }

        let fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|error| {
            let error = std::io::Error::from(error);
            std::io::Error::new(error.kind(), "reassembly socket creation failed")
        })?;
        setsockopt(&fd, sockopt::BindToDevice, &interface_name).map_err(|error| {
            let error = std::io::Error::from(error);
            std::io::Error::new(error.kind(), "reassembly device binding failed")
        })?;
        let address = SocketAddrV4::new(local_address, GTPU_PORT);
        bind(fd.as_raw_fd(), &SockaddrIn::from(address)).map_err(|error| {
            let error = std::io::Error::from(error);
            std::io::Error::new(error.kind(), "reassembly address binding failed")
        })?;
        setsockopt(&fd, sockopt::Ipv4PacketInfo, &true).map_err(|error| {
            let error = std::io::Error::from(error);
            std::io::Error::new(error.kind(), "reassembly packet-info setup failed")
        })?;
        let socket = std::net::UdpSocket::from(fd);
        validate_reassembly_socket_address(
            socket.local_addr().map_err(|error| {
                std::io::Error::new(error.kind(), "reassembly local binding readback failed")
            })?,
            local_address,
        )?;
        let observed_name = getsockopt(&socket, sockopt::BindToDevice).map_err(|error| {
            let error = std::io::Error::from(error);
            std::io::Error::new(error.kind(), "reassembly device readback failed")
        })?;
        let observed_ifindex = if observed_name.is_empty() {
            0
        } else {
            nix::net::if_::if_nametoindex(observed_name.as_os_str()).map_err(|error| {
                let error = std::io::Error::from(error);
                std::io::Error::new(error.kind(), "reassembly device readback failed")
            })?
        };
        validate_bound_device_readback(
            interface_name.as_os_str(),
            ingress_ifindex,
            observed_name.as_os_str(),
            observed_ifindex,
        )?;
        Ok(Self {
            socket,
            interface_name,
            ingress_ifindex,
            local_address,
        })
    }

    /// Return the verified managed ingress ifindex without exposing the raw
    /// socket or interface name.
    #[must_use]
    pub const fn ingress_ifindex(&self) -> u32 {
        self.ingress_ifindex
    }

    /// Set the socket's receive timeout.
    ///
    /// # Errors
    ///
    /// Returns the underlying socket-option error.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Request a positive receive-buffer size and return the kernel's
    /// effective `SO_RCVBUF` readback.
    ///
    /// Linux may clamp or account the requested size according to namespace
    /// limits, so callers should use the returned value as operational
    /// evidence. Neither the requested nor effective size appears in errors.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for zero, or a stable redaction-safe socket
    /// option/readback error.
    pub fn set_receive_buffer_size(&self, bytes: usize) -> std::io::Result<usize> {
        use nix::sys::socket::{getsockopt, setsockopt, sockopt};

        if bytes == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "reassembly receive buffer must be positive",
            ));
        }
        setsockopt(&self.socket, sockopt::RcvBuf, &bytes).map_err(|error| {
            let error = std::io::Error::from(error);
            std::io::Error::new(error.kind(), "reassembly receive-buffer setup failed")
        })?;
        getsockopt(&self.socket, sockopt::RcvBuf).map_err(|error| {
            let error = std::io::Error::from(error);
            std::io::Error::new(error.kind(), "reassembly receive-buffer readback failed")
        })
    }

    fn verify_live_binding(&self) -> std::io::Result<()> {
        use nix::sys::socket::{getsockopt, sockopt};

        let local = self.socket.local_addr().map_err(|error| {
            std::io::Error::new(error.kind(), "reassembly local binding readback failed")
        })?;
        validate_reassembly_socket_address(local, self.local_address)?;
        let observed_name = getsockopt(&self.socket, sockopt::BindToDevice).map_err(|error| {
            let error = std::io::Error::from(error);
            std::io::Error::new(error.kind(), "reassembly device readback failed")
        })?;
        let observed_ifindex = if observed_name.is_empty() {
            0
        } else {
            nix::net::if_::if_nametoindex(observed_name.as_os_str()).map_err(|error| {
                let error = std::io::Error::from(error);
                std::io::Error::new(error.kind(), "reassembly device readback failed")
            })?
        };
        validate_bound_device_readback(
            self.interface_name.as_os_str(),
            self.ingress_ifindex,
            observed_name.as_os_str(),
            observed_ifindex,
        )
    }

    /// Receive one complete reassembled UDP/2152 datagram with authoritative
    /// outer provenance.
    ///
    /// Live local-address and `SO_BINDTODEVICE` readback are verified before
    /// every receive. A positive `IP_PKTINFO` ifindex must exactly match the
    /// sealed socket. Linux kernels that report zero for an already
    /// reassembled datagram use only the socket's kernel-enforced device
    /// identity. Payload/control truncation is rejected before provenance or
    /// GTP-U parsing.
    ///
    /// # Errors
    ///
    /// Returns stable, redaction-safe errors for lost socket identity,
    /// truncated envelopes, absent packet info, conflicting provenance, or
    /// the underlying receive operation.
    pub fn receive(&self, buffer: &mut [u8]) -> std::io::Result<(usize, DownlinkOuterProvenance)> {
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrIn};
        use std::os::fd::AsRawFd;

        self.verify_live_binding()?;
        let mut cmsg_space = nix::cmsg_space!(nix::libc::in_pktinfo);
        let mut iov = [std::io::IoSliceMut::new(buffer)];
        let message = recvmsg::<SockaddrIn>(
            self.socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        )?;
        validate_reassembly_envelope_flags(message.flags)?;
        // Close the blocking-receive race: an interface rename, deletion, or
        // replacement while waiting cannot make a zero-pktinfo datagram rely
        // on stale sealed identity.
        self.verify_live_binding()?;
        let from = std::net::SocketAddr::from(message.address.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing datagram source")
        })?);
        let std::net::IpAddr::V4(peer) = from.ip() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "non-IPv4 datagram source",
            ));
        };
        let packet_info = message
            .cmsgs()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid reassembly control-message envelope",
                )
            })?
            .find_map(|control| match control {
                ControlMessageOwned::Ipv4PacketInfo(info) => Some(info),
                _ => None,
            })
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing IP_PKTINFO control message",
                )
            })?;
        let ingress_ifindex =
            authoritative_ingress_ifindex(packet_info.ipi_ifindex, self.ingress_ifindex)?;
        let local = Ipv4Addr::from(u32::from_be(packet_info.ipi_addr.s_addr));
        if local != self.local_address {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "kernel local destination conflicts with the sealed socket",
            ));
        }
        let provenance = DownlinkOuterProvenance::new(peer, local, ingress_ifindex, from.port())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical provenance")
            })?;
        Ok((message.bytes, provenance))
    }
}

/// Typed resolution of the downlink PDR lookup for one G-PDU TEID.
///
/// The lookup closure must return [`GtpuReassemblyPdr::Corrupt`] for every
/// state the tc fast path drops as malformed: a TEID present in *both* the
/// legacy and marked PDR maps (externally corrupted duplicate ownership) and
/// a marked PDR carrying the reserved zero bearer mark. Returning
/// `Configured` for either would let the socket path deliver packets the tc
/// path drops fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuReassemblyPdr {
    /// One canonical PDR authorizes the TEID.
    Configured(MarkedDownlinkPdr),
    /// The persisted PDR state is corrupt; fail closed.
    Corrupt,
}

/// Redaction-safe selector used for every component-map read of one
/// post-reassembly PDP graph.
///
/// Construct it from the PDR once, then use this same value for the FAR,
/// DSCP, owner (when marked), and commit lookups. Binding it into a
/// [`GtpuReassemblyGraphIdentity`] before calling
/// [`reassembly_commit_authorizes_graph`] ties the observed graph to the
/// current PDR and prevents an old selector's commit from authorizing a new or
/// mixed PDR.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuReassemblySelector {
    key: UplinkFarKey,
}

impl fmt::Debug for GtpuReassemblySelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuReassemblySelector")
            .field("ue_ip", &"<redacted>")
            .field("bearer_mark", &"<redacted>")
            .finish()
    }
}

impl GtpuReassemblySelector {
    /// Derive the exact default/marked component-map selector from a PDR.
    /// An unspecified UE PAA is never a valid map selector and returns
    /// `None`.
    #[must_use]
    pub fn from_pdr(pdr: MarkedDownlinkPdr) -> Option<Self> {
        if pdr.ue_ip == [0; 4] {
            None
        } else {
            Some(Self {
                key: UplinkFarKey {
                    ue_ip: pdr.ue_ip,
                    bearer_mark: pdr.bearer_mark,
                },
            })
        }
    }

    /// UE PAA key used by the default maps.
    #[must_use]
    pub const fn ue_ip(self) -> [u8; 4] {
        self.key.ue_ip
    }

    /// Whether this selector uses the additive marked maps.
    #[must_use]
    pub fn is_marked(self) -> bool {
        self.key.bearer_mark != [0; 4]
    }

    /// Exact eight-byte key for the additive marked maps, or `None` for a
    /// default bearer.
    #[must_use]
    pub fn marked_map_key(self) -> Option<[u8; 8]> {
        if self.is_marked() {
            Some(self.key.encode())
        } else {
            None
        }
    }
}

/// Validated identity tying one observed component-map selector to the exact
/// PDR and local TEID being authorized.
///
/// Construction rejects an old-selector/new-PDR mix before any commit can be
/// evaluated. All forwarding identifiers stay redacted from `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuReassemblyGraphIdentity {
    selector: GtpuReassemblySelector,
    local_teid: [u8; 4],
    pdr: MarkedDownlinkPdr,
}

impl fmt::Debug for GtpuReassemblyGraphIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuReassemblyGraphIdentity")
            .field("selector", &"<redacted>")
            .field("local_teid", &"<redacted>")
            .field("pdr", &"<redacted>")
            .finish()
    }
}

impl GtpuReassemblyGraphIdentity {
    /// Bind the selector actually used for component-map reads to the current
    /// PDR and local TEID. A mismatched selector or zero TEID fails closed.
    #[must_use]
    pub fn new(
        observed_selector: GtpuReassemblySelector,
        local_teid: [u8; 4],
        pdr: MarkedDownlinkPdr,
    ) -> Option<Self> {
        (local_teid != [0; 4] && GtpuReassemblySelector::from_pdr(pdr) == Some(observed_selector))
            .then_some(Self {
                selector: observed_selector,
                local_teid,
                pdr,
            })
    }
}

/// Validate the complete authoritative graph for one post-reassembly
/// delivery.
///
/// The caller must derive the selector from the current PDR, use that same
/// value to read `far`, `dscp`, and `owner` from their live maps first, bind it
/// into `identity`, then read `commit` **last** and invoke this function. The
/// identity constructor rejects an old-selector/new-PDR mix. The read order
/// makes the Active commit the publication fence: a concurrent install,
/// replacement, or removal either leaves the old exact graph authorized or
/// exposes a Pending/Removing/mismatched graph that fails closed.
///
/// For a default bearer (`pdr.bearer_mark == 0`), `owner` is ignored because
/// the default schema has no owner-journal entry. For a marked bearer, an exact
/// Active owner matching the commit is mandatory.
#[must_use]
pub fn reassembly_commit_authorizes_graph(
    commit: &PdpContextCommit,
    identity: GtpuReassemblyGraphIdentity,
    binding: &DownlinkEndpointBinding,
    far: &UplinkFar,
    dscp: Option<u8>,
    owner: Option<&MarkedBearerOwner>,
) -> bool {
    GtpuReassemblySelector::from_pdr(identity.pdr) == Some(identity.selector)
        && commit.authorizes_graph(identity.local_teid, far, dscp, binding)
        && (identity.pdr.bearer_mark == [0; 4]
            || owner.is_some_and(|owner| *owner == commit.marked_owner()))
}

/// Stable, redaction-safe reason a reassembled datagram was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuReassemblyDrop {
    /// The reassembled message violates the GTP-U framing invariants, or the
    /// persisted PDR state is corrupt (dual-map TEID or reserved zero mark).
    Malformed,
    /// The datagram exceeds the bounded maximum reassembled length.
    Oversized,
    /// No PDR exists for the G-PDU TEID.
    UnknownTeid,
    /// The outer provenance failed the canonical endpoint binding, or the
    /// complete Active PDP commit graph did not authorize the delivery.
    BindingMismatch(DownlinkBindingMismatch),
    /// The inner destination does not match the session's UE PAA.
    DestinationMismatch,
}

/// Fixed-cardinality counters of the post-reassembly consumer, mirroring the
/// fixed-cardinality datapath counters of the tc fast path.
///
/// These are userspace counters for the socket re-entry path and are
/// intentionally separate from the eBPF backend's `datapath_snapshot`
/// per-CPU map aggregates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GtpuReassemblyCounters {
    /// Reassembled G-PDUs decapsulated and handed to the embedding ePDG.
    pub decapsulated: u64,
    /// Messages passed through for the control plane (non-G-PDU GTP-U).
    pub control_plane: u64,
    /// Reassembled messages dropped as malformed, including corrupt PDR
    /// state (dual-map TEID, reserved zero mark).
    pub malformed: u64,
    /// G-PDUs dropped for an unknown TEID.
    pub unknown_teid: u64,
    /// G-PDUs dropped by the outer-endpoint binding or the marked-bearer
    /// owner journal.
    pub binding_drops: u64,
    /// G-PDUs dropped because the inner destination is not the session's UE.
    pub destination_mismatches: u64,
    /// Datagrams rejected before parsing because they exceed the bounded
    /// maximum reassembled length.
    pub oversized: u64,
}

/// Outcome of processing one reassembled downlink datagram.
#[derive(Clone, PartialEq, Eq)]
pub enum GtpuReassemblyOutcome {
    /// The datagram was authorized and decapsulated exactly once.
    Decapsulated {
        /// The complete inner packet (bounded by the reassembled datagram).
        inner_packet: Vec<u8>,
        /// Output bearer mark for XFRM policy selection; `None` is the
        /// default bearer (mark zero), matching the fast path.
        bearer_mark: Option<GtpBearerMark>,
    },
    /// Not a G-PDU: hand the message to the GTP-U control plane.
    ControlPlane,
    /// Fail-closed drop with a bounded typed reason.
    Dropped(GtpuReassemblyDrop),
}

impl fmt::Debug for GtpuReassemblyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decapsulated {
                inner_packet,
                bearer_mark,
            } => f
                .debug_struct("Decapsulated")
                .field("inner_packet", &"<redacted>")
                .field("inner_packet_len", &inner_packet.len())
                .field(
                    "bearer_mark",
                    &bearer_mark.map(|_| "<redacted>").unwrap_or("default"),
                )
                .finish(),
            Self::ControlPlane => f.write_str("ControlPlane"),
            Self::Dropped(reason) => f.debug_tuple("Dropped").field(reason).finish(),
        }
    }
}

/// Post-reassembly downlink consumer: the SDK GTP-U consumer that kernel
/// reassembly re-enters, backed by the caller's authoritative PDR,
/// endpoint-binding, and complete commit-graph state.
///
/// The three closures are the integration seam:
///
/// - `lookup_pdr` resolves a TEID to a typed [`GtpuReassemblyPdr`]; it must
///   report `Corrupt` for dual-map TEIDs and reserved zero marks, exactly
///   the states the tc program drops as malformed.
/// - `lookup_binding` serves the canonical endpoint binding for the TEID.
/// - `authorize_complete_graph` is consulted for **every** bearer. Production
///   callers derive one [`GtpuReassemblySelector`] from the supplied PDR, use
///   that same selector for the FAR, DSCP, owner, and commit map reads, then
///   read the `PdpContextCommit` record last and return true only when
///   [`reassembly_commit_authorizes_graph`] accepts the exact
///   `(selector, teid, pdr, binding, FAR, DSCP, owner)` graph. Commit-last
///   observation is the publication fence: Pending/Removing, an absent commit,
///   an old-selector/new-PDR pair, or any mixed graph must return false. This
///   mirrors the tc path across install, replacement, removal, and
///   crash-recovery windows.
///
/// Keeping the state source caller-supplied makes the consumer
/// backend-neutral and lets the embedding ePDG decide how read-back state is
/// refreshed.
pub struct GtpuReassemblyConsumer<P, B, A> {
    lookup_pdr: P,
    lookup_binding: B,
    authorize_complete_graph: A,
    counters: GtpuReassemblyCounters,
}

impl<P, B, A> fmt::Debug for GtpuReassemblyConsumer<P, B, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuReassemblyConsumer")
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl<P, B, A> GtpuReassemblyConsumer<P, B, A>
where
    P: Fn([u8; 4]) -> Option<GtpuReassemblyPdr>,
    B: Fn([u8; 4]) -> Option<DownlinkEndpointBinding>,
    A: Fn([u8; 4], MarkedDownlinkPdr, &DownlinkEndpointBinding) -> bool,
{
    /// Construct a consumer over the PDR lookup, endpoint-binding lookup, and
    /// complete committed-graph authorization callback.
    pub fn new(lookup_pdr: P, lookup_binding: B, authorize_complete_graph: A) -> Self {
        Self {
            lookup_pdr,
            lookup_binding,
            authorize_complete_graph,
            counters: GtpuReassemblyCounters::default(),
        }
    }

    /// Return the bounded consumer counters.
    #[must_use]
    pub const fn counters(&self) -> GtpuReassemblyCounters {
        self.counters
    }

    /// Process one complete reassembled UDP/2152 datagram.
    ///
    /// `message` is the exact UDP payload delivered by the socket. It is
    /// bounded by [`MAX_REASSEMBLED_GTPU_LEN`]; larger inputs are dropped
    /// before parsing. Each call processes one complete socket datagram and
    /// yields at most one decapsulated packet. Fragment overlap and duplicate
    /// acceptance are kernel-version-dependent; this consumer does not claim
    /// to deduplicate separate socket deliveries.
    pub fn process(
        &mut self,
        message: &[u8],
        provenance: &DownlinkOuterProvenance,
    ) -> GtpuReassemblyOutcome {
        if message.len() > MAX_REASSEMBLED_GTPU_LEN {
            self.counters.oversized += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Oversized);
        }
        let tpdu = match parse_gtpu_tpdu(message) {
            Ok(Some(tpdu)) => tpdu,
            Ok(None) => {
                self.counters.control_plane += 1;
                return GtpuReassemblyOutcome::ControlPlane;
            }
            Err(_) => {
                self.counters.malformed += 1;
                return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed);
            }
        };
        let pdr = match (self.lookup_pdr)(tpdu.teid) {
            None => {
                self.counters.unknown_teid += 1;
                return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::UnknownTeid);
            }
            Some(GtpuReassemblyPdr::Corrupt) => {
                // Dual-map TEID or reserved zero mark: the tc program drops
                // these as malformed, and so does this path.
                self.counters.malformed += 1;
                return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed);
            }
            Some(GtpuReassemblyPdr::Configured(pdr)) => pdr,
        };
        let Some(binding) = (self.lookup_binding)(tpdu.teid) else {
            self.counters.binding_drops += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::Invalid,
            ));
        };
        if let Err(reason) = binding.validate_ipv4_packet(
            provenance.peer_address.octets(),
            provenance.local_address.octets(),
            provenance.ingress_ifindex,
            provenance.source_port,
        ) {
            self.counters.binding_drops += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(reason));
        }
        // The complete graph gate applies to default and marked bearers. Its
        // final read must be the authoritative Active PdpContextCommit.
        if !(self.authorize_complete_graph)(tpdu.teid, pdr, &binding) {
            self.counters.binding_drops += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::Invalid,
            ));
        }
        let output_mark = u32::from_be_bytes(pdr.bearer_mark);
        // Mirror the fast path: the T-PDU must be an inner IPv4 packet
        // addressed to the session's UE PAA. `parse_gtpu_tpdu` already
        // guarantees at least a minimum inner header.
        if tpdu.payload[0] >> 4 != 4 {
            self.counters.malformed += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed);
        }
        if tpdu.payload[16..20] != pdr.ue_ip {
            self.counters.destination_mismatches += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::DestinationMismatch);
        }
        let bearer_mark = GtpBearerMark::new(output_mark);
        self.counters.decapsulated += 1;
        GtpuReassemblyOutcome::Decapsulated {
            inner_packet: tpdu.payload.to_vec(),
            bearer_mark,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_gtpu_ebpf_common::{
        GtpuEndpointAddress, GtpuSourcePortPolicy, GtpuUplinkSourcePortPolicy,
        MarkedBearerOwnerPhase,
    };

    const UE: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 2);
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const TEID: [u8; 4] = [0x10, 0, 0, 1];

    fn provenance() -> DownlinkOuterProvenance {
        DownlinkOuterProvenance::new(PEER, LOCAL, 7, 2152).unwrap()
    }

    fn binding() -> DownlinkEndpointBinding {
        DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv4(PEER.octets()),
            GtpuEndpointAddress::Ipv4(LOCAL.octets()),
            7,
            GtpuSourcePortPolicy::Any,
        )
        .unwrap()
    }

    fn pdr(mark: [u8; 4]) -> MarkedDownlinkPdr {
        MarkedDownlinkPdr {
            ue_ip: UE.octets(),
            bearer_mark: mark,
        }
    }

    fn far() -> UplinkFar {
        UplinkFar {
            peer_ip: PEER.octets(),
            local_ip: LOCAL.octets(),
            o_teid: [0x20, 0, 0, 1],
        }
    }

    fn commit(phase: MarkedBearerOwnerPhase) -> PdpContextCommit {
        PdpContextCommit::new(
            TEID,
            far(),
            None,
            binding(),
            GtpuUplinkSourcePortPolicy::LegacyServicePort,
            phase,
        )
        .unwrap()
    }

    type PdrLookup = Box<dyn Fn([u8; 4]) -> Option<GtpuReassemblyPdr>>;
    type BindingLookup = Box<dyn Fn([u8; 4]) -> Option<DownlinkEndpointBinding>>;
    type GraphAuthorizer =
        Box<dyn Fn([u8; 4], MarkedDownlinkPdr, &DownlinkEndpointBinding) -> bool>;

    fn consumer(
        mark: [u8; 4],
    ) -> GtpuReassemblyConsumer<PdrLookup, BindingLookup, GraphAuthorizer> {
        consumer_with_authority(mark, true)
    }

    fn consumer_with_authority(
        mark: [u8; 4],
        graph_authorized: bool,
    ) -> GtpuReassemblyConsumer<PdrLookup, BindingLookup, GraphAuthorizer> {
        GtpuReassemblyConsumer::new(
            Box::new(move |teid| (teid == TEID).then(|| GtpuReassemblyPdr::Configured(pdr(mark)))),
            Box::new(move |teid| (teid == TEID).then(binding)),
            Box::new(
                move |_: [u8; 4], _: MarkedDownlinkPdr, _: &DownlinkEndpointBinding| {
                    graph_authorized
                },
            ),
        )
    }

    fn inner_packet(dst: Ipv4Addr) -> Vec<u8> {
        let mut inner = vec![
            0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 45, 0, 9, 0, 0, 0, 0,
        ];
        inner[16..20].copy_from_slice(&dst.octets());
        inner.extend_from_slice(b"data");
        inner
    }

    fn gpdu(teid: [u8; 4], inner: &[u8]) -> Vec<u8> {
        let mut message = vec![0x30, 0xFF, 0, 0, teid[0], teid[1], teid[2], teid[3]];
        let declared = u16::try_from(inner.len()).unwrap();
        message[2..4].copy_from_slice(&declared.to_be_bytes());
        message.extend_from_slice(inner);
        message
    }

    #[test]
    fn authorized_marked_datagram_decapsulates_with_output_mark() {
        let mut consumer = consumer(0x0102_0304_u32.to_be_bytes());
        let outcome = consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance());
        let GtpuReassemblyOutcome::Decapsulated {
            inner_packet: delivered,
            bearer_mark,
        } = outcome
        else {
            panic!("expected decapsulation, got {outcome:?}");
        };
        assert_eq!(delivered, inner_packet(UE));
        assert_eq!(bearer_mark, GtpBearerMark::new(0x0102_0304));
        assert_eq!(consumer.counters().decapsulated, 1);
    }

    #[test]
    fn decapsulation_outcome_debug_redacts_inner_packet_and_bearer_mark() {
        let mut consumer = consumer(0x0102_0304_u32.to_be_bytes());
        let outcome = consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance());
        let debug = format!("{outcome:?}");
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("inner_packet_len"));
        assert!(!debug.contains("10, 45"));
        assert!(!debug.contains("16909060"));
    }

    #[test]
    fn default_bearer_requires_complete_active_graph_authorization() {
        let mut rejected = consumer_with_authority([0; 4], false);
        assert_eq!(
            rejected.process(&gpdu(TEID, &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::Invalid
            ))
        );
        let mut authorized = consumer_with_authority([0; 4], true);
        assert!(matches!(
            authorized.process(&gpdu(TEID, &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Decapsulated {
                bearer_mark: None,
                ..
            }
        ));
    }

    #[test]
    fn commit_last_graph_validator_rejects_transaction_and_mixed_graph_states() {
        let active = commit(MarkedBearerOwnerPhase::Active);
        let default_pdr = pdr([0; 4]);
        let default_selector = GtpuReassemblySelector::from_pdr(default_pdr).unwrap();
        let selector_debug = format!("{default_selector:?}");
        assert!(selector_debug.contains("<redacted>"));
        assert!(!selector_debug.contains("10, 45"));
        let default_identity =
            GtpuReassemblyGraphIdentity::new(default_selector, TEID, default_pdr).unwrap();
        let identity_debug = format!("{default_identity:?}");
        assert!(identity_debug.contains("<redacted>"));
        assert!(!identity_debug.contains("10, 45"));
        assert!(reassembly_commit_authorizes_graph(
            &active,
            default_identity,
            &binding(),
            &far(),
            None,
            None,
        ));
        for phase in [
            MarkedBearerOwnerPhase::Pending,
            MarkedBearerOwnerPhase::Removing,
        ] {
            assert!(!reassembly_commit_authorizes_graph(
                &active.with_phase(phase),
                default_identity,
                &binding(),
                &far(),
                None,
                None,
            ));
        }
        let wrong_far = UplinkFar {
            peer_ip: [192, 0, 2, 99],
            ..far()
        };
        assert!(!reassembly_commit_authorizes_graph(
            &active,
            default_identity,
            &binding(),
            &wrong_far,
            None,
            None,
        ));

        let replacement_pdr = MarkedDownlinkPdr {
            ue_ip: [10, 45, 0, 3],
            bearer_mark: [0; 4],
        };
        assert!(
            GtpuReassemblyGraphIdentity::new(default_selector, TEID, replacement_pdr).is_none(),
            "an old selector must not bind to a replacement PDR"
        );

        let marked = pdr(0x0102_0304_u32.to_be_bytes());
        let marked_selector = GtpuReassemblySelector::from_pdr(marked).unwrap();
        let marked_identity =
            GtpuReassemblyGraphIdentity::new(marked_selector, TEID, marked).unwrap();
        assert!(!reassembly_commit_authorizes_graph(
            &active,
            marked_identity,
            &binding(),
            &far(),
            None,
            None,
        ));
        let owner = active.marked_owner();
        assert!(reassembly_commit_authorizes_graph(
            &active,
            marked_identity,
            &binding(),
            &far(),
            None,
            Some(&owner),
        ));
    }

    #[test]
    fn marked_bearer_without_owner_authorization_fails_closed() {
        let mut consumer = consumer_with_authority(0x0102_0304_u32.to_be_bytes(), false);
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::Invalid
            ))
        );
        let counters = consumer.counters();
        assert_eq!(counters.binding_drops, 1);
        assert_eq!(counters.decapsulated, 0);
    }

    #[test]
    fn corrupt_pdr_state_fails_closed_like_the_tc_path() {
        // Dual-map TEID or marked PDR with a reserved zero mark must surface
        // as Corrupt from the lookup; the consumer drops as malformed.
        let mut consumer = GtpuReassemblyConsumer::new(
            Box::new(|_teid| Some(GtpuReassemblyPdr::Corrupt)) as PdrLookup,
            Box::new(move |teid| (teid == TEID).then(binding)) as BindingLookup,
            Box::new(|_: [u8; 4], _: MarkedDownlinkPdr, _: &DownlinkEndpointBinding| true)
                as GraphAuthorizer,
        );
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed)
        );
        let counters = consumer.counters();
        assert_eq!(counters.malformed, 1);
        assert_eq!(counters.decapsulated, 0);
    }

    #[test]
    fn every_drop_reason_is_typed_and_counted() {
        let mut consumer = consumer([0; 4]);
        // Unknown TEID.
        assert_eq!(
            consumer.process(&gpdu([0x20, 0, 0, 9], &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::UnknownTeid)
        );
        // Wrong outer peer.
        let wrong_peer =
            DownlinkOuterProvenance::new(Ipv4Addr::new(192, 0, 2, 11), LOCAL, 7, 2152).unwrap();
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &wrong_peer),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::PeerAddress
            ))
        );
        // Wrong ingress ifindex.
        let wrong_ifindex = DownlinkOuterProvenance::new(PEER, LOCAL, 8, 2152).unwrap();
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &wrong_ifindex),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::IngressAttachment
            ))
        );
        // Inner destination mismatch.
        assert_eq!(
            consumer.process(
                &gpdu(TEID, &inner_packet(Ipv4Addr::new(10, 45, 0, 9))),
                &provenance()
            ),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::DestinationMismatch)
        );
        // Malformed framing.
        assert_eq!(
            consumer.process(&[0x30, 0xFF, 0, 1], &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed)
        );
        // Non-IPv4 inner.
        let mut v6_inner = vec![0x60; 40];
        v6_inner.extend_from_slice(&[0; 8]);
        assert_eq!(
            consumer.process(&gpdu(TEID, &v6_inner), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed)
        );
        let counters = consumer.counters();
        assert_eq!(counters.unknown_teid, 1);
        assert_eq!(counters.binding_drops, 2);
        assert_eq!(counters.destination_mismatches, 1);
        assert_eq!(counters.malformed, 2);
        assert_eq!(counters.decapsulated, 0);
    }

    #[test]
    fn non_gpdu_messages_pass_to_the_control_plane() {
        let mut consumer = consumer([0; 4]);
        let mut echo = vec![0x30, 0x01, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0];
        echo[0] = 0x32;
        assert_eq!(
            consumer.process(&echo, &provenance()),
            GtpuReassemblyOutcome::ControlPlane
        );
        assert_eq!(consumer.counters().control_plane, 1);
    }

    #[test]
    fn oversized_datagrams_are_dropped_before_parsing() {
        let mut consumer = consumer([0; 4]);
        let oversized = vec![0x30; MAX_REASSEMBLED_GTPU_LEN + 1];
        assert_eq!(
            consumer.process(&oversized, &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Oversized)
        );
        assert_eq!(consumer.counters().oversized, 1);
        // The exact bounded maximum is admitted to the parser.
        let mut maximum = vec![0x30, 0xFF, 0, 0, 0, 0, 0, 0];
        maximum.resize(MAX_REASSEMBLED_GTPU_LEN, 0);
        let _ = consumer.process(&maximum, &provenance());
        assert_eq!(consumer.counters().oversized, 1);
    }

    #[test]
    fn missing_binding_fails_closed() {
        let mut consumer = GtpuReassemblyConsumer::new(
            Box::new(move |teid| (teid == TEID).then(|| GtpuReassemblyPdr::Configured(pdr([0; 4]))))
                as PdrLookup,
            Box::new(|_teid| None) as BindingLookup,
            Box::new(|_: [u8; 4], _: MarkedDownlinkPdr, _: &DownlinkEndpointBinding| true)
                as GraphAuthorizer,
        );
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::Invalid
            ))
        );
    }

    #[test]
    fn provenance_rejects_noncanonical_identity_and_redacts_debug() {
        assert!(DownlinkOuterProvenance::new(Ipv4Addr::UNSPECIFIED, LOCAL, 7, 2152).is_none());
        assert!(DownlinkOuterProvenance::new(PEER, Ipv4Addr::UNSPECIFIED, 7, 2152).is_none());
        assert!(DownlinkOuterProvenance::new(PEER, LOCAL, 0, 2152).is_none());
        let debug = format!("{:?}", provenance());
        assert!(!debug.contains("192"));
        assert!(!debug.contains("2152"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_ipv4_reassembly_stats_parser_is_bounded_and_strict() {
        let stats = parse_linux_ipv4_reassembly_stats(
            "Tcp: RtoAlgorithm\nTcp: 1\n\
             Ip: ReasmFails ReasmOKs ReasmReqds ReasmTimeout\n\
             Ip: 4 5 9 3\n",
        )
        .unwrap();
        assert_eq!(
            stats,
            GtpuKernelIpv4ReassemblyStats {
                fragments_requested: 9,
                succeeded: 5,
                timed_out: 3,
                failed: 4,
            }
        );

        for malformed in [
            "",
            "Ip: ReasmFails ReasmOKs ReasmReqds ReasmTimeout\n",
            "Ip: ReasmFails ReasmOKs ReasmReqds ReasmTimeout\nTcp: 4 5 9 3\n",
            "Ip: ReasmFails ReasmOKs ReasmReqds\nIp: 4 5 9\n",
            "Ip: ReasmFails ReasmOKs ReasmReqds ReasmTimeout\nIp: 4 5 9\n",
            "Ip: ReasmFails ReasmOKs ReasmReqds ReasmTimeout\nIp: 4 5 9 invalid\n",
            "Ip: ReasmFails ReasmFails ReasmOKs ReasmReqds ReasmTimeout\nIp: 4 4 5 9 3\n",
            "Ip: ReasmFails ReasmOKs ReasmReqds ReasmTimeout\nIp: 4 5 9 3\nIp: ReasmFails ReasmOKs ReasmReqds ReasmTimeout\nIp: 4 5 9 3\n",
        ] {
            assert_eq!(
                parse_linux_ipv4_reassembly_stats(malformed),
                Err(GtpuKernelReassemblyStatsError::Malformed),
                "malformed SNMP input must fail closed"
            );
        }

        let oversized = "x".repeat(MAX_PROC_NET_SNMP_BYTES + 1);
        assert_eq!(
            parse_linux_ipv4_reassembly_stats(&oversized),
            Err(GtpuKernelReassemblyStatsError::Malformed)
        );
        assert_eq!(
            GtpuKernelReassemblyStatsError::Unavailable.code(),
            "gtpu_kernel_reassembly_stats_unavailable"
        );
        assert_eq!(
            GtpuKernelReassemblyStatsError::Malformed.to_string(),
            "gtpu_kernel_reassembly_stats_malformed"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_ipv4_reassembly_stats_live_read_is_typed() {
        let stats = read_linux_ipv4_reassembly_stats().unwrap();
        assert!(stats.fragments_requested >= stats.succeeded);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reassembly_receive_validators_reject_weak_or_truncated_identity() {
        use nix::sys::socket::MsgFlags;
        use std::ffi::OsStr;
        use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

        assert!(validate_reassembly_interface_name("123456789012345").is_ok());
        for invalid_name in ["", "1234567890123456", "s2b\0u"] {
            let error = validate_reassembly_interface_name(invalid_name).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert_eq!(error.to_string(), "invalid reassembly interface name");
        }

        let valid = SocketAddr::V4(SocketAddrV4::new(LOCAL, GTPU_PORT));
        assert!(validate_reassembly_socket_address(valid, LOCAL).is_ok());
        assert_eq!(
            validate_reassembly_socket_address(valid, Ipv4Addr::UNSPECIFIED)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        for invalid in [
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, GTPU_PORT)),
            SocketAddr::V4(SocketAddrV4::new(LOCAL, 0)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, GTPU_PORT, 0, 0)),
        ] {
            assert_eq!(
                validate_reassembly_socket_address(invalid, LOCAL)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
        }

        let device = OsStr::new("s2bu");
        assert!(validate_bound_device_readback(device, 7, device, 7).is_ok());
        for (expected_name, expected_ifindex, observed_name, observed_ifindex) in [
            (device, 7, OsStr::new(""), 0),
            (device, 7, OsStr::new("other"), 8),
            (device, 7, device, 8),
            (OsStr::new(""), 7, device, 7),
            (device, 0, device, 7),
        ] {
            let error = validate_bound_device_readback(
                expected_name,
                expected_ifindex,
                observed_name,
                observed_ifindex,
            )
            .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "reassembly socket device binding is not authoritative"
            );
        }

        assert!(validate_reassembly_envelope_flags(MsgFlags::empty()).is_ok());
        for truncated in [
            MsgFlags::MSG_TRUNC,
            MsgFlags::MSG_CTRUNC,
            MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC,
        ] {
            let error = validate_reassembly_envelope_flags(truncated).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "truncated reassembly datagram envelope");
        }

        assert_eq!(authoritative_ingress_ifindex(7, 7).unwrap(), 7);
        assert_eq!(authoritative_ingress_ifindex(0, 7).unwrap(), 7);
        assert_eq!(
            authoritative_ingress_ifindex(7, 0).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            authoritative_ingress_ifindex(-1, 7).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            authoritative_ingress_ifindex(8, 7).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }
}
