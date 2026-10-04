//! IPv4 downlink injection toward caller-managed XFRM policies.
//!
//! **The consumer owns containment.** Before opening the raw injector, install
//! a lower-priority outbound block policy covering the subscriber address pool
//! for every mark, source and protocol. Keep it for the entire lifetime of the
//! plaintext source, with `net.ipv4.conf.all.disable_xfrm=0` and
//! `net.ipv4.conf.<egress>.disable_xfrm=0`, and no higher-priority intersecting
//! plaintext bypass policy. A namespace default outbound block policy is an
//! alternative for non-loopback output, requiring explicit policies for all
//! other permitted non-loopback flows. A missing bearer policy otherwise
//! permits plaintext on the ordinary route. No read-only policy query is an
//! atomic containment receipt: removing protection between a query and any
//! packet's kernel lookup can leak that packet. That interval is unbounded;
//! leakage can continue until protection returns or sending stops.
//!
//! [`GtpuDownlinkInjector::raw_ipv4`] provides the Linux `IP_HDRINCL`,
//! `IP_NODEFRAG`, `SO_MARK` and `IP_PKTINFO` recipe for the control port's
//! [`GtpuDecapsulatedDownlink`] and [`GtpuFragmentedDownlink`] outcomes. It
//! neither installs nor diagnoses policies. Successful injection means only
//! that the local kernel accepted packets, not that they were protected or
//! delivered. See the crate's `docs/control-port.md` for deployment obligations
//! and the zero-Identification limit.
//!
//! [`GtpuDownlinkInjector::xfrm_interface_ipv4`] is an optional stronger send
//! contract for consumers whose policies and SAs use an XFRM interface ID.
//! Its retained packet-socket binding requires an interface-scoped transform
//! and preserves zero Identification, including separate fragment outcomes.
//! **The consumer must also contain generated ICMP errors:** missing policy/SA
//! and DF path-MTU failures can emit ordinarily routed destination-unreachable
//! messages quoting plaintext from the injected packet. The control-port guide
//! supplies a verified output-drop rule scoped to the quoted subscriber pool.
//! The injector installs neither that rule nor interfaces/policies. Privileged
//! redirects, mirroring and interface configuration remain consumer-owned.

use std::{fmt, io};

use bytes::Bytes;

use crate::{GtpAddressFamily, GtpBearerMark, GtpuDecapsulatedDownlink, GtpuFragmentedDownlink};

const DONT_FRAGMENT: u16 = 0x4000;
const MORE_FRAGMENTS: u16 = 0x2000;
const OFFSET: u16 = 0x1fff;

#[cfg(target_os = "linux")]
mod xfrm_interface;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectionContract {
    RawIpv4,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    XfrmInterfaceIpv4,
}

/// Borrow one control-port outcome that contains injectable inner packets.
///
/// This does not grant forwarding authority or re-authorize a retained
/// outcome. Inject promptly after receiving it; the consumer owns session
/// lifetime and the containment configuration described by this module.
/// `Debug` uses only the outcomes' existing redacted formatting.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum GtpuDownlinkInjection<'a> {
    /// One inner packet, possibly itself an IPv4 fragment.
    Decapsulated(&'a GtpuDecapsulatedDownlink),
    /// The fragment batch of one outcome; injection validates its ordering.
    Fragmented(&'a GtpuFragmentedDownlink),
}

impl<'a> From<&'a GtpuDecapsulatedDownlink> for GtpuDownlinkInjection<'a> {
    fn from(packet: &'a GtpuDecapsulatedDownlink) -> Self {
        Self::Decapsulated(packet)
    }
}

impl<'a> From<&'a GtpuFragmentedDownlink> for GtpuDownlinkInjection<'a> {
    fn from(packet: &'a GtpuFragmentedDownlink) -> Self {
        Self::Fragmented(packet)
    }
}

/// Value-free classes of local packet-send failure.
///
/// No operating-system diagnostic or traffic value is retained. Policy and
/// filter refusals cannot be distinguished from their shared kernel errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GtpuDownlinkSendFailure {
    /// The nonblocking send could not proceed immediately.
    WouldBlock,
    /// The packet exceeds a socket, device or path-MTU limit.
    MessageTooLarge,
    /// The kernel could not allocate or queue the packet.
    NoBufferSpace,
    /// XFRM or a packet filter refused output. Revoked send privileges can
    /// also report this class; required privileges must remain available.
    PolicyOrFilterRefused,
    /// Access was denied (Linux `EACCES`), for example by a prohibit route
    /// or a broadcast destination without broadcast permission.
    AccessDenied,
    /// The send device is missing or its retained binding has been retired.
    /// Reusing its name or index does not repair the old binding.
    InterfaceUnavailable,
    /// The retained send device is down, or the socket has a pending error
    /// from an earlier down notification even though it is now up.
    InterfaceDown,
    /// A datagram send reported fewer bytes than supplied.
    ShortWrite,
    /// Another local failure, without its possibly sensitive diagnostic.
    Other,
}

/// Value-free refusal or local send failure. No nested operating-system
/// error, address, mark, SPI or packet bytes are retained or formatted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GtpuDownlinkInjectionError {
    /// This platform cannot create the requested injection socket.
    #[error("downlink injection is unsupported on this platform")]
    UnsupportedPlatform,
    /// This constructor supports only inner IPv4 packets.
    #[error("unsupported downlink injection address family")]
    UnsupportedFamily,
    /// The interface index or XFRM interface identifier is invalid.
    #[error("invalid downlink injection interface parameters")]
    InvalidInterface,
    /// The device is not a local, fixed-identifier XFRM interface.
    #[error("unsupported downlink injection interface")]
    UnsupportedInterface,
    /// The requested device does not exist or disappeared during construction.
    #[error("downlink injection interface unavailable")]
    InterfaceUnavailable,
    /// Device identity did not match, or changed while the socket was bound.
    #[error("downlink injection interface identity mismatch")]
    InterfaceIdentityMismatch,
    /// The IPv4 header or fragment batch is inconsistent; nothing was sent.
    #[error("malformed downlink injection packet or fragment batch")]
    MalformedIpv4,
    /// Linux would replace an unspecified source instead of preserving it.
    #[error("unspecified downlink injection source")]
    UnspecifiedSource,
    /// A raw-mode non-DF fragment or fragment batch has Identification zero.
    /// Linux would renumber it independently of its siblings; nothing is sent.
    #[error("zero Identification on a fragment or fragment batch")]
    ZeroIdentificationFragment,
    /// Socket creation or configuration failed before any packet was sent.
    #[error("downlink injection socket unavailable ({kind:?})")]
    Socket {
        /// Value-free operating-system error class.
        kind: io::ErrorKind,
    },
    /// A send failed. Earlier packets of this outcome may already have left.
    #[error("downlink injection send failed ({class:?}; {packets_sent} packets accepted)")]
    Send {
        /// Value-free failure class, including kernel MTU and buffer limits.
        class: GtpuDownlinkSendFailure,
        /// Packets accepted before the failing send. After a partial send the
        /// datagram is lost: this API cannot resume or resend the remainder.
        packets_sent: usize,
    },
}

/// Saturating, value-free counters for one injector instance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GtpuDownlinkInjectionCounters {
    /// Individual packets accepted by the local kernel, including packets
    /// accepted before a later send of the same outcome failed.
    pub packets_accepted: u64,
    /// Raw-mode zero-ID non-DF outcomes refused without sending; one per
    /// independent fragment or batch, not one per inferred datagram.
    pub zero_identification_refusals: u64,
    /// Outcomes stopped by a local send failure.
    pub send_failures: u64,
}

/// Consumer-test seam for injecting either downlink outcome.
///
/// A consumer may implement this trait with a fake without opening a socket.
/// The [`crate::testkit`] provides structural inputs for that fake.
/// The real implementation requires exclusive mutable access across mark
/// selection and all fragment sends. Implementations must keep errors and
/// formatting value-free and document their own containment contract.
pub trait GtpuDownlinkInjectionPort: fmt::Debug + Send {
    /// Send one outcome; return the number of packets locally accepted.
    ///
    /// # Errors
    /// Returns a value-free refusal or send failure, which may report partial
    /// acceptance. Success is neither an XFRM receipt nor peer-delivery proof.
    fn inject(
        &mut self,
        outcome: GtpuDownlinkInjection<'_>,
    ) -> Result<usize, GtpuDownlinkInjectionError>;

    /// Return this instance's bounded, value-free counters.
    fn counters(&self) -> GtpuDownlinkInjectionCounters;
}

/// An opaque IPv4 downlink injector with an explicitly selected send contract.
///
/// Select [`Self::raw_ipv4`] with consumer-owned pool containment, or
/// [`Self::xfrm_interface_ipv4`] with consumer-managed interface-scoped
/// policies and SAs. The socket and send contract remain private and fixed
/// for this instance's lifetime.
pub struct GtpuDownlinkInjector {
    inner: Injector<InjectionSocket>,
}

impl fmt::Debug for GtpuDownlinkInjector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuDownlinkInjector")
            .field("contract", &self.inner.contract)
            .finish()
    }
}

impl GtpuDownlinkInjector {
    /// Open a nonblocking Linux raw IPv4 injector in the current network
    /// namespace. The socket stays in that namespace for its lifetime.
    ///
    /// **The consumer must first install and continuously retain an outbound
    /// pool-wide block policy below the bearer policies**, with both the
    /// egress-device and `all` `disable_xfrm` sysctls zero, and no
    /// higher-priority intersecting plaintext bypass. A namespace default
    /// outbound block is another option for non-loopback output, with the
    /// namespace-wide cost described in the [module contract](crate::injection).
    /// This constructor performs no policy query and grants no
    /// containment receipt. Without that configuration, loss of a bearer OUT
    /// policy can send plaintext. See the [module contract](crate::injection).
    ///
    /// Requires raw-socket and packet-mark privileges (`CAP_NET_RAW`, plus
    /// `CAP_NET_ADMIN` for `SO_MARK` on kernels before Linux 5.17). Probes
    /// `SO_MARK` before returning and sets `IP_HDRINCL` and `IP_NODEFRAG`;
    /// each send sets the exact bearer mark
    /// (zero for the default bearer) and the inner source via `IP_PKTINFO`.
    /// HDRINCL supplies `FLOWI_FLAG_ANYSRC`, so that source need not be local.
    /// OUT selectors must use addresses and marks, not inner ports/protocol:
    /// Linux builds this raw flow with protocol `IPPROTO_RAW` and zero ports.
    ///
    /// # Errors
    /// Returns a value-free platform, socket creation or configuration error.
    pub fn raw_ipv4() -> Result<Self, GtpuDownlinkInjectionError> {
        let sender = RawIpv4Socket::open()?;
        Ok(Self {
            inner: Injector {
                sender: InjectionSocket::Raw(sender),
                contract: InjectionContract::RawIpv4,
                counters: GtpuDownlinkInjectionCounters::default(),
            },
        })
    }

    /// Bind IPv4 injection to a caller-managed XFRM interface in the current
    /// network namespace, with a nonzero interface index and expected XFRM
    /// interface identifier (`if_id`).
    ///
    /// The consumer must scope its outbound policies and SAs to that identifier.
    /// The constructor validates a local, non-metadata XFRM device and binds an
    /// `AF_PACKET/SOCK_DGRAM` socket once. A bounded link-event subscription
    /// detects device changes between identity reads around the bind, including
    /// deletion and reuse of the same index with identical attributes. No
    /// packets are sent during construction. Subsequent sends provide no
    /// destination sockaddr and never resolve the interface again: unregister
    /// invalidates this socket even if the name and index are reused.
    ///
    /// This path requires an actual interface-scoped transform. Missing
    /// matching policy/SA, interface loss and ordinary FIB route changes cannot
    /// forward the original packet through a plaintext fallback. However,
    /// missing policy/SA and DF path-MTU failures can generate IPv4 ICMP errors
    /// quoting the original packet and routed toward its source. Before sending,
    /// the consumer must continuously retain output containment for those
    /// errors, for example the quoted-pool drop rule in `docs/control-port.md`.
    /// This constructor does not install or audit that rule. The consumer
    /// also owns privileged configuration: redirects/mirrors before XFRM,
    /// changes to the interface's identifier or namespace contract, and
    /// selection of an unrelated SA are outside this guarantee.
    ///
    /// All validated IPv4 bytes, including Identification zero, remain intact;
    /// separate fragment outcomes need no correlation cache. The inner packet
    /// enters device egress directly instead of inner IPv4 LOCAL_OUT, so raw
    /// `IP_NODEFRAG` is unnecessary. Device egress hooks, inner POST_ROUTING
    /// before the transform, and transformed-packet IP output hooks still
    /// apply. Inner packets have no conntrack entry there and match nftables
    /// `ct state invalid`; an invalid-drop postrouting rule drops them all.
    /// Sends may succeed when XFRM drops the packet, with or without ICMP;
    /// success is not delivery or encryption proof.
    ///
    /// A reject-all receive filter is installed before binding the packet
    /// socket. Its IPv4 receive hook still runs, but no inbound packet is queued.
    ///
    /// Requires `CAP_NET_RAW` and packet-mark privileges (also `CAP_NET_ADMIN`
    /// on kernels before Linux 5.17). The constructor probes `SO_MARK` before
    /// returning. Identity acquisition has a one-second deadline and bounded
    /// receive work; contention or notification loss refuses construction
    /// rather than assuming identity continuity.
    ///
    /// # Errors
    /// Returns a value-free platform, parameter, unsupported-device, identity,
    /// socket or netlink error. A missing device is
    /// [`GtpuDownlinkInjectionError::InterfaceUnavailable`]. Nothing is sent on
    /// constructor failure. A deferred link event just after device setup can
    /// refuse identity acquisition; callers may start a fresh attempt once
    /// configuration settles, before handing over any packets.
    pub fn xfrm_interface_ipv4(
        ifindex: u32,
        if_id: u32,
    ) -> Result<Self, GtpuDownlinkInjectionError> {
        #[cfg(target_os = "linux")]
        {
            let sender = xfrm_interface::XfrmInterfaceSocket::open(ifindex, if_id)?;
            Ok(Self {
                inner: Injector {
                    sender: InjectionSocket::XfrmInterface(sender),
                    contract: InjectionContract::XfrmInterfaceIpv4,
                    counters: GtpuDownlinkInjectionCounters::default(),
                },
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ifindex, if_id);
            Err(GtpuDownlinkInjectionError::UnsupportedPlatform)
        }
    }

    /// Inject one outcome in fragment order, returning the number of packets
    /// accepted by the local kernel. Requires the selected constructor's
    /// configuration obligations to remain satisfied throughout every send.
    ///
    /// Validates the whole batch before sending. Keeps the header (including
    /// TTL/options). Interface-bound mode preserves every validated byte,
    /// including zero Identification in separate outcomes and batches.
    /// The following zero-ID handling applies only to raw mode, where Linux
    /// recomputes the validated total length and header checksum.
    ///
    /// A [`GtpuDownlinkInjection::Fragmented`] batch or independently received
    /// [`GtpuDownlinkInjection::Decapsulated`] fragment with Identification
    /// zero and DF clear is refused and counted before sending anything.
    /// The crate fragments only DF sources: atomic sources already receive
    /// nonzero IDs, so a zero-ID batch is one piece of an origin-fragmented
    /// datagram. Rewriting that piece cannot agree with its separate siblings.
    /// The raw path therefore loses an origin-fragmented zero-ID datagram
    /// whenever a non-DF fragment must be injected; no ID allocation or
    /// cross-outcome cache is attempted. [`Self::xfrm_interface_ipv4`] does
    /// not have this raw-path limit.
    /// Keeping DF on pieces of a DF-fragment source would preserve zero on
    /// raw output, but changing fragment flags and MTU semantics belongs to
    /// the fragmenter, not this injector.
    /// For sources distributing IDs over all 65,536 values this affects about
    /// one fragmented datagram in 65,536; sources repeatedly using zero can
    /// lose every fragmented datagram. Zero is legal under RFC 6864; this is
    /// a send-path limitation. Zero on an unfragmented packet (which Linux
    /// may number) or with DF set is accepted. Raw mode refuses an unspecified
    /// source. Both constructors refuse IPv6.
    ///
    /// # Errors
    /// Validation refusals send nothing. A local send failure stops at the
    /// first failed fragment and reports earlier accepted packets. Never
    /// retry the entire batch: after partial acceptance the datagram is lost
    /// and this API cannot resume or resend its remainder. In raw mode a
    /// retained block or output filter normally returns
    /// [`GtpuDownlinkSendFailure::PolicyOrFilterRefused`]; that class does not
    /// identify which rule refused it. Interface-bound sends can succeed when
    /// XFRM drops the packet, including when it generates an ICMP error.
    /// No automatic retry,
    /// packet queue, XFRM lookup diagnostic or policy installation is provided.
    pub fn inject(
        &mut self,
        outcome: GtpuDownlinkInjection<'_>,
    ) -> Result<usize, GtpuDownlinkInjectionError> {
        self.inner.inject(outcome)
    }

    /// Return value-free counters for this injector instance.
    #[must_use]
    pub const fn counters(&self) -> GtpuDownlinkInjectionCounters {
        self.inner.counters
    }
}

impl GtpuDownlinkInjectionPort for GtpuDownlinkInjector {
    fn inject(
        &mut self,
        outcome: GtpuDownlinkInjection<'_>,
    ) -> Result<usize, GtpuDownlinkInjectionError> {
        self.inject(outcome)
    }

    fn counters(&self) -> GtpuDownlinkInjectionCounters {
        self.counters()
    }
}

trait Ipv4Sender {
    fn send(&mut self, packet: &[u8], mark: Option<GtpBearerMark>) -> io::Result<usize>;
}

struct Injector<S> {
    sender: S,
    contract: InjectionContract,
    counters: GtpuDownlinkInjectionCounters,
}

impl<S: Ipv4Sender> Injector<S> {
    fn inject(
        &mut self,
        outcome: GtpuDownlinkInjection<'_>,
    ) -> Result<usize, GtpuDownlinkInjectionError> {
        use GtpuDownlinkInjectionError as Error;
        let raw = self.contract == InjectionContract::RawIpv4;
        let (first, rest, mark): (&[u8], &[Bytes], _) = match outcome {
            GtpuDownlinkInjection::Decapsulated(packet) => {
                if packet.family() != GtpAddressFamily::Ipv4 {
                    return Err(Error::UnsupportedFamily);
                }
                let bytes = packet.inner_packet();
                let header = Header::parse(bytes, self.contract)?;
                if raw
                    && header.id == 0
                    && header.flags & DONT_FRAGMENT == 0
                    && header.flags & (MORE_FRAGMENTS | OFFSET) != 0
                {
                    self.counters.zero_identification_refusals =
                        self.counters.zero_identification_refusals.saturating_add(1);
                    return Err(Error::ZeroIdentificationFragment);
                }
                (bytes, &[], packet.bearer_mark())
            }
            GtpuDownlinkInjection::Fragmented(batch) => {
                let (first, rest) = batch
                    .fragments()
                    .split_first()
                    .ok_or(Error::MalformedIpv4)?;
                let header = Header::parse(first, self.contract)?;
                let mut previous = header;
                for packet in rest {
                    let current = Header::parse(packet, self.contract)?;
                    if packet[12..20] != first[12..20]
                        || packet[9] != first[9]
                        || current.id != header.id
                        || current.flags & DONT_FRAGMENT != header.flags & DONT_FRAGMENT
                        || previous.flags & MORE_FRAGMENTS == 0
                        || previous.payload_len % 8 != 0
                        || current.offset() != previous.offset() + previous.payload_len
                    {
                        return Err(Error::MalformedIpv4);
                    }
                    previous = current;
                }
                if raw && header.id == 0 && header.flags & DONT_FRAGMENT == 0 {
                    self.counters.zero_identification_refusals =
                        self.counters.zero_identification_refusals.saturating_add(1);
                    return Err(Error::ZeroIdentificationFragment);
                }
                (first, rest, batch.bearer_mark())
            }
        };
        let mut packets_sent = 0;
        for packet in std::iter::once(first).chain(rest.iter().map(Bytes::as_ref)) {
            let result = self.sender.send(packet, mark);
            let class = match result {
                Ok(length) if length == packet.len() => {
                    packets_sent += 1;
                    self.counters.packets_accepted =
                        self.counters.packets_accepted.saturating_add(1);
                    continue;
                }
                Ok(_) => GtpuDownlinkSendFailure::ShortWrite,
                Err(error) => classify_send_error(&error),
            };
            self.counters.send_failures = self.counters.send_failures.saturating_add(1);
            return Err(Error::Send {
                class,
                packets_sent,
            });
        }
        Ok(packets_sent)
    }
}

#[derive(Clone, Copy)]
struct Header {
    id: u16,
    flags: u16,
    payload_len: usize,
}

impl Header {
    fn parse(
        packet: &[u8],
        contract: InjectionContract,
    ) -> Result<Self, GtpuDownlinkInjectionError> {
        use GtpuDownlinkInjectionError as Error;
        let (header_len, total_len) =
            crate::inner_fragment::valid_ipv4_header(packet).ok_or(Error::MalformedIpv4)?;
        if total_len != packet.len() {
            return Err(Error::MalformedIpv4);
        }
        if contract == InjectionContract::RawIpv4 && packet[12..16] == [0; 4] {
            return Err(Error::UnspecifiedSource);
        }
        let header = Self {
            id: u16::from_be_bytes([packet[4], packet[5]]),
            flags: u16::from_be_bytes([packet[6], packet[7]]),
            payload_len: total_len - header_len,
        };
        if header.offset() + total_len > usize::from(u16::MAX) {
            return Err(Error::MalformedIpv4);
        }
        Ok(header)
    }

    fn offset(self) -> usize {
        usize::from(self.flags & OFFSET) * 8
    }
}

fn classify_send_error(error: &io::Error) -> GtpuDownlinkSendFailure {
    use GtpuDownlinkSendFailure as Class;
    #[cfg(target_os = "linux")]
    match error.raw_os_error() {
        Some(nix::libc::EMSGSIZE) => return Class::MessageTooLarge,
        Some(nix::libc::ENOBUFS) => return Class::NoBufferSpace,
        Some(nix::libc::EACCES) => return Class::AccessDenied,
        Some(nix::libc::ENXIO | nix::libc::ENODEV) => return Class::InterfaceUnavailable,
        Some(nix::libc::ENETDOWN) => return Class::InterfaceDown,
        _ => {}
    }
    match error.kind() {
        io::ErrorKind::WouldBlock => Class::WouldBlock,
        io::ErrorKind::PermissionDenied => Class::PolicyOrFilterRefused,
        _ => Class::Other,
    }
}

enum InjectionSocket {
    Raw(RawIpv4Socket),
    #[cfg(target_os = "linux")]
    XfrmInterface(xfrm_interface::XfrmInterfaceSocket),
}

impl Ipv4Sender for InjectionSocket {
    fn send(&mut self, packet: &[u8], mark: Option<GtpBearerMark>) -> io::Result<usize> {
        match self {
            Self::Raw(sender) => sender.send(packet, mark),
            #[cfg(target_os = "linux")]
            Self::XfrmInterface(sender) => sender.send(packet, mark),
        }
    }
}

struct RawIpv4Socket {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::OwnedFd,
}

impl RawIpv4Socket {
    fn open() -> Result<Self, GtpuDownlinkInjectionError> {
        #[cfg(target_os = "linux")]
        {
            use nix::sys::socket::{
                setsockopt, socket, sockopt, AddressFamily, SockFlag, SockProtocol, SockType,
            };
            use std::os::fd::AsFd;
            let fd = socket(
                AddressFamily::Inet,
                SockType::Raw,
                SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
                SockProtocol::Raw,
            )
            .map_err(|error| GtpuDownlinkInjectionError::Socket {
                kind: io::Error::from(error).kind(),
            })?;
            opc_linux_gtpu_sys::configure_raw_ipv4_injection_socket(fd.as_fd())
                .map_err(|error| GtpuDownlinkInjectionError::Socket { kind: error.kind() })?;
            setsockopt(&fd, sockopt::Mark, &0_u32).map_err(|error| {
                GtpuDownlinkInjectionError::Socket {
                    kind: io::Error::from(error).kind(),
                }
            })?;
            Ok(Self { fd })
        }
        #[cfg(not(target_os = "linux"))]
        Err(GtpuDownlinkInjectionError::UnsupportedPlatform)
    }
}

impl Ipv4Sender for RawIpv4Socket {
    fn send(&mut self, packet: &[u8], mark: Option<GtpBearerMark>) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            use nix::sys::socket::{
                sendmsg, setsockopt, sockopt, ControlMessage, MsgFlags, SockaddrIn,
            };
            use std::os::fd::AsRawFd;
            setsockopt(&self.fd, sockopt::Mark, &mark.map_or(0, GtpBearerMark::get))?;
            let source = [packet[12], packet[13], packet[14], packet[15]];
            let destination = SockaddrIn::new(packet[16], packet[17], packet[18], packet[19], 0);
            let info = nix::libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: nix::libc::in_addr {
                    s_addr: u32::from_ne_bytes(source),
                },
                ipi_addr: nix::libc::in_addr { s_addr: 0 },
            };
            sendmsg(
                self.fd.as_raw_fd(),
                &[io::IoSlice::new(packet)],
                &[ControlMessage::Ipv4PacketInfo(&info)],
                MsgFlags::MSG_DONTWAIT,
                Some(&destination),
            )
            .map_err(io::Error::from)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (packet, mark);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod native_tests;
