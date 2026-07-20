//! Shared GTP-U (TS 29.281) wire-format layouts for the eBPF tc datapath.
//!
//! This crate is the single source of truth for the byte layouts exchanged
//! between the `opc-gtpu-dataplane` eBPF backend (userspace loader) and the
//! `opc-gtpu-dataplane-ebpf` tc programs: BPF map key/value encodings and the
//! exact GTP-U/UDP/IPv4 encapsulation bytes stamped on uplink packets. It is
//! `no_std`, dependency-free, and fully deterministic so the wire format is
//! unit-testable in ordinary CI without a kernel.
//!
//! All multi-byte fields are big-endian (network byte order) unless noted.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod envelope;

pub use envelope::{
    classify_udp_checksum, internet_checksum, internet_checksum_sum_is_valid, udp_ipv4_checksum,
    udp_ipv4_checksum_is_valid, GtpuEnvelopeBounds, GtpuEnvelopeError, Ipv4EnvelopeBounds,
    UdpChecksumDisposition, UdpChecksumEvidence, UdpEnvelopeBounds, IPV4_MAX_HDR_LEN,
};

/// GTP-U UDP port (TS 29.281 §4.4.2).
pub const GTPU_UDP_PORT: u16 = 2152;

/// Ethernet header length on the attach interface.
pub const ETH_HDR_LEN: usize = 14;
/// EtherType for IPv4.
pub const ETH_P_IPV4: u16 = 0x0800;
/// Minimum (option-free) IPv4 header length.
pub const IPV4_MIN_HDR_LEN: usize = 20;
/// UDP header length.
pub const UDP_HDR_LEN: usize = 8;
/// Mandatory GTPv1-U header length (flags, type, length, TEID).
pub const GTPU_MANDATORY_HDR_LEN: usize = 8;
/// Optional GTPv1-U field block length (sequence, N-PDU, next-ext type),
/// present when any of the S/PN/E flags is set.
pub const GTPU_OPT_LEN: usize = 4;
/// Total uplink encapsulation prepended per packet: outer IPv4 + UDP + GTP-U.
pub const GTPU_ENCAP_LEN: usize = IPV4_MIN_HDR_LEN + UDP_HDR_LEN + GTPU_MANDATORY_HDR_LEN;

/// GTPv1-U flags octet sent on uplink: version=1, PT=1, E=S=PN=0.
pub const GTPU_FLAGS_V1_GPDU: u8 = 0x30;
/// Mask of the version bits within the GTP-U flags octet.
pub const GTPU_FLAGS_VERSION_MASK: u8 = 0xE0;
/// Version bits value for GTPv1.
pub const GTPU_FLAGS_VERSION_V1: u8 = 0x20;
/// Protocol-type bit (1 = GTP, 0 = GTP').
pub const GTPU_FLAG_PT: u8 = 0x10;
/// Extension-header flag.
pub const GTPU_FLAG_E: u8 = 0x04;
/// Sequence-number flag.
pub const GTPU_FLAG_S: u8 = 0x02;
/// N-PDU-number flag.
pub const GTPU_FLAG_PN: u8 = 0x01;
/// Message type for a G-PDU (T-PDU carrier).
pub const GTPU_MSG_TYPE_GPDU: u8 = 0xFF;
/// GTP-U "no more extension headers" type value.
pub const GTPU_EXT_NONE: u8 = 0x00;
/// Upper bound on chained GTP-U extension headers accepted on downlink.
pub const GTPU_MAX_EXT_HEADERS: usize = 4;

/// Byte length of an uplink FAR map value.
pub const UPLINK_FAR_VALUE_LEN: usize = 12;
/// Byte length of a marked uplink FAR/DSCP map key.
pub const UPLINK_MARK_KEY_LEN: usize = 8;
/// Byte length of an unmarked/default downlink PDR map value.
pub const DOWNLINK_PDR_VALUE_LEN: usize = 4;
/// Byte length of a marked downlink PDR map value.
pub const MARKED_DOWNLINK_PDR_VALUE_LEN: usize = 8;
/// Byte length of a canonical downlink outer-endpoint binding.
pub const DOWNLINK_ENDPOINT_BINDING_VALUE_LEN: usize = 44;
/// Byte length of a marked-bearer owner journal value.
pub const MARKED_BEARER_OWNER_VALUE_LEN: usize = 64;
/// Byte length of an optional uplink DSCP map value.
pub const UPLINK_DSCP_VALUE_LEN: usize = 1;
/// Byte length of an optional selected uplink UDP source-port map value.
pub const UPLINK_SOURCE_PORT_VALUE_LEN: usize = 2;

/// Reserved impossible UE-PAA key carrying durable DSCP-schema evidence in
/// the existing uplink FAR map.
///
/// Userspace rejects `0.0.0.0` as a PDP address, and the eBPF uplink program
/// explicitly bypasses this key before lookup. This keeps the FAR key/value
/// ABI unchanged while distinguishing a one-time pre-DSCP migration from loss
/// of the additive DSCP map after that migration completed.
pub const UPLINK_DSCP_SCHEMA_MARKER_KEY: [u8; 4] = [0; 4];
/// Magic FAR value stored at [`UPLINK_DSCP_SCHEMA_MARKER_KEY`].
pub const UPLINK_DSCP_SCHEMA_MARKER_VALUE: [u8; UPLINK_FAR_VALUE_LEN] = *b"OPC-DSCP-v1\0";
/// Historical v2 marker proving that every per-bearer-mark map was adopted.
///
/// The marker replaces [`UPLINK_DSCP_SCHEMA_MARKER_VALUE`] only after every
/// additive marked map has been opened, every named pin has been verified as
/// the exact map held by the loader, and both v2 tc hooks have been
/// attached and read back by program ID. A loader that observes this value
/// fails closed when any required map pin is missing. On restart, exact or
/// absent hooks are reconciled; a foreign occupant blocks adoption.
pub const UPLINK_BEARER_SCHEMA_MARKER_VALUE: [u8; UPLINK_FAR_VALUE_LEN] = *b"OPC-MARK-v2\0";
/// Current v3 schema marker proving that every downlink PDR has a canonical
/// outer-endpoint binding and the exact binding-drop counter map is pinned.
///
/// Userspace publishes this only after the complete pin graph is validated and
/// both exact current hooks are attached. A v2 marker is endpoint-unbound and
/// requires explicit drained reprovisioning rather than an implicit policy.
pub const UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE: [u8; UPLINK_FAR_VALUE_LEN] = *b"OPC-PEER-v3\0";
/// Current v4 schema marker proving that the additive uplink source-port maps
/// are pinned and available to the exact current uplink program.
///
/// The v3-to-v4 migration is purely additive: the source-port maps are empty
/// by default and an absent entry selects the legacy 2152 source port, so a
/// committed v3 pin set can be upgraded in place by creating the maps,
/// verifying the complete pin graph, attaching the exact current hooks, and
/// committing this marker. A live previous-generation (v3 object) tc hook
/// does not match the current artifact and fails closed without mutation; it
/// must be detached by its owning loader before adoption, exactly like the
/// pre-v1 object generations. A loader that observes this value fails closed
/// when either source-port map pin is missing.
pub const UPLINK_SOURCE_PORT_SCHEMA_MARKER_VALUE: [u8; UPLINK_FAR_VALUE_LEN] = *b"OPC-SPORT-v4";

/// BPF map name: uplink FAR, keyed by UE PAA (IPv4, network order).
pub const MAP_UPLINK_FAR: &str = "GTPU_UPLINK_FAR";
/// BPF map name: marked uplink FAR, keyed by `(UE PAA, packet mark)`.
pub const MAP_UPLINK_MARK_FAR: &str = "GTPU_ULM_FAR";
/// BPF map name: downlink PDR, keyed by local S2b-U TEID (network order).
pub const MAP_DOWNLINK_PDR: &str = "GTPU_DOWNLINK_PDR";
/// BPF map name: marked downlink PDR, keyed by local S2b-U TEID.
pub const MAP_DOWNLINK_MARK_PDR: &str = "GTPU_DLM_PDR";
/// BPF map name: downlink outer-endpoint binding, keyed by local TEID.
pub const MAP_DOWNLINK_ENDPOINT_BINDING: &str = "GTPU_DL_BIND";
/// BPF map name: optional uplink DSCP, keyed by UE PAA.
pub const MAP_UPLINK_DSCP: &str = "GTPU_UPLINK_DSCP";
/// BPF map name: optional uplink DSCP, keyed by `(UE PAA, packet mark)`.
pub const MAP_UPLINK_MARK_DSCP: &str = "GTPU_ULM_DSCP";
/// BPF map name: optional selected uplink UDP source port, keyed by UE PAA.
pub const MAP_UPLINK_SOURCE_PORT: &str = "GTPU_UL_SPORT";
/// BPF map name: optional selected uplink UDP source port, keyed by
/// `(UE PAA, packet mark)`.
pub const MAP_UPLINK_MARK_SOURCE_PORT: &str = "GTPU_ULM_SPORT";
/// BPF map name: marked-bearer owner journal, keyed by `(UE PAA, mark)`.
pub const MAP_MARKED_BEARER_OWNER: &str = "GTPU_M_OWNER";
/// BPF map name: per-CPU datapath counters.
pub const MAP_COUNTERS: &str = "GTPU_COUNTERS";
/// BPF map name: fixed-cardinality downlink binding-drop counters.
pub const MAP_DOWNLINK_BINDING_COUNTERS: &str = "GTPU_DL_DROP";
/// BPF map name: single-slot device configuration (local S2b-U IPv4).
pub const MAP_CONFIG: &str = "GTPU_CONFIG";

/// tc program name handling uplink (subscriber → PGW) encapsulation.
pub const PROG_UPLINK: &str = "opc_gtpu_uplink";
/// tc program name handling downlink (PGW → subscriber) decapsulation.
pub const PROG_DOWNLINK: &str = "opc_gtpu_downlink";

/// Counter index: uplink packets GTP-U encapsulated.
pub const COUNTER_UL_ENCAP: u32 = 0;
/// Counter index: uplink FAR lookup misses. Mark-zero misses pass through;
/// nonzero misses drop under the complete-mark ownership contract.
pub const COUNTER_UL_FAR_MISS: u32 = 1;
/// Counter index: downlink G-PDUs decapsulated.
pub const COUNTER_DL_DECAP: u32 = 2;
/// Counter index: downlink G-PDUs dropped for an unknown TEID.
pub const COUNTER_DL_UNKNOWN_TEID: u32 = 3;
/// Counter index: downlink GTP-U packets dropped as malformed.
pub const COUNTER_DL_MALFORMED: u32 = 4;
/// Counter index: downlink G-PDUs dropped because the inner destination does
/// not match the session's UE PAA.
pub const COUNTER_DL_DST_MISMATCH: u32 = 5;
/// Number of datapath counters.
pub const COUNTER_SLOTS: u32 = 6;

/// Binding-drop counter index: no canonical binding exists for the PDR.
pub const COUNTER_DL_BINDING_INVALID: u32 = 0;
/// Binding-drop counter index: packet and binding address families differ.
pub const COUNTER_DL_BINDING_FAMILY_MISMATCH: u32 = 1;
/// Binding-drop counter index: the outer source is not the authorized peer.
pub const COUNTER_DL_BINDING_PEER_MISMATCH: u32 = 2;
/// Binding-drop counter index: the outer destination is not the local endpoint.
pub const COUNTER_DL_BINDING_LOCAL_MISMATCH: u32 = 3;
/// Binding-drop counter index: the tc attachment does not match the binding.
pub const COUNTER_DL_BINDING_INGRESS_MISMATCH: u32 = 4;
/// Binding-drop counter index: the UDP source port is outside policy.
pub const COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH: u32 = 5;
/// Number of fixed-cardinality downlink binding-drop counters.
pub const DOWNLINK_BINDING_COUNTER_SLOTS: u32 = 6;

/// Decide whether an uplink non-encapsulation path must drop rather than pass.
///
/// The eBPF backend owns the complete mark: zero selects the default bearer
/// and nonzero selects a dedicated bearer. Every nonzero packet must either
/// encapsulate through its exact `(PAA, mark)` FAR or drop so inner subscriber
/// traffic cannot leak unencapsulated. Mark-zero behavior remains the exact
/// legacy pass-on-miss/error path.
#[must_use]
pub const fn uplink_non_encapsulation_drops(packet_mark: u32) -> bool {
    packet_mark != 0
}

/// Uplink FAR map value: forwarding state for one subscriber session.
///
/// Map key: the UE PAA (inner IPv4 source address), 4 bytes network order.
///
/// Value layout (12 bytes):
///
/// | offset | field    | meaning                                        |
/// |--------|----------|------------------------------------------------|
/// | 0..4   | peer_ip  | PGW S2b-U IPv4 (outer destination), BE         |
/// | 4..8   | local_ip | ePDG S2b-U IPv4 (outer source), BE             |
/// | 8..12  | o_teid   | PGW-assigned S2b-U TEID stamped on uplink, BE  |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UplinkFar {
    /// Outer IPv4 destination: PGW S2b-U address, network order.
    pub peer_ip: [u8; 4],
    /// Outer IPv4 source: ePDG S2b-U address, network order.
    pub local_ip: [u8; 4],
    /// GTP-U TEID stamped toward the PGW, network order.
    pub o_teid: [u8; 4],
}

impl UplinkFar {
    /// Encode into the fixed map-value byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; UPLINK_FAR_VALUE_LEN] {
        [
            self.peer_ip[0],
            self.peer_ip[1],
            self.peer_ip[2],
            self.peer_ip[3],
            self.local_ip[0],
            self.local_ip[1],
            self.local_ip[2],
            self.local_ip[3],
            self.o_teid[0],
            self.o_teid[1],
            self.o_teid[2],
            self.o_teid[3],
        ]
    }

    /// Decode from the fixed map-value byte layout.
    #[must_use]
    pub const fn decode(value: &[u8; UPLINK_FAR_VALUE_LEN]) -> Self {
        Self {
            peer_ip: [value[0], value[1], value[2], value[3]],
            local_ip: [value[4], value[5], value[6], value[7]],
            o_teid: [value[8], value[9], value[10], value[11]],
        }
    }
}

/// Marked uplink lookup key for one bearer sharing a UE PAA.
///
/// The first four bytes are the UE IPv4 address and the final four bytes are
/// the complete Linux packet mark. Both fields use network byte order. Mark
/// zero is reserved for the legacy/default-bearer map and is never written to
/// the additive marked map by the userspace backend.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UplinkFarKey {
    /// UE PAA carried as the inner IPv4 source address.
    pub ue_ip: [u8; 4],
    /// Per-bearer Linux packet mark in network byte order.
    pub bearer_mark: [u8; 4],
}

impl core::fmt::Debug for UplinkFarKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UplinkFarKey")
            .field("ue_ip", &"<redacted>")
            .field("bearer_mark", &"<redacted>")
            .finish()
    }
}

impl UplinkFarKey {
    /// Encode into the fixed marked-map key layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; UPLINK_MARK_KEY_LEN] {
        [
            self.ue_ip[0],
            self.ue_ip[1],
            self.ue_ip[2],
            self.ue_ip[3],
            self.bearer_mark[0],
            self.bearer_mark[1],
            self.bearer_mark[2],
            self.bearer_mark[3],
        ]
    }

    /// Decode from the fixed marked-map key layout.
    #[must_use]
    pub const fn decode(value: &[u8; UPLINK_MARK_KEY_LEN]) -> Self {
        Self {
            ue_ip: [value[0], value[1], value[2], value[3]],
            bearer_mark: [value[4], value[5], value[6], value[7]],
        }
    }
}

/// Product-neutral IP address used by a GTP-U outer-endpoint binding.
///
/// The semantic model supports both address families even though the current
/// tc datapath executes only IPv4 GTP-U. Address bytes are always network
/// ordered and are redacted from `Debug` output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GtpuEndpointAddress {
    /// IPv4 endpoint address.
    Ipv4([u8; 4]),
    /// IPv6 endpoint address.
    Ipv6([u8; 16]),
}

impl core::fmt::Debug for GtpuEndpointAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple(match self {
            Self::Ipv4(_) => "Ipv4",
            Self::Ipv6(_) => "Ipv6",
        })
        .field(&"<redacted>")
        .finish()
    }
}

impl GtpuEndpointAddress {
    /// Return whether this address is the all-zero unspecified address.
    #[must_use]
    pub fn is_unspecified(self) -> bool {
        match self {
            Self::Ipv4(value) => value == [0; 4],
            Self::Ipv6(value) => value == [0; 16],
        }
    }

    const fn family_wire(self) -> u8 {
        match self {
            Self::Ipv4(_) => 4,
            Self::Ipv6(_) => 6,
        }
    }

    const fn encode_bytes(self) -> [u8; 16] {
        match self {
            Self::Ipv4(value) => [
                value[0], value[1], value[2], value[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            Self::Ipv6(value) => value,
        }
    }
}

/// Inclusive, canonical UDP source-port range.
///
/// A range always contains at least two ports. Use
/// [`GtpuSourcePortPolicy::Exact`] for one port.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GtpuSourcePortRange {
    first: u16,
    last: u16,
}

impl core::fmt::Debug for GtpuSourcePortRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtpuSourcePortRange")
            .field("first", &"<redacted>")
            .field("last", &"<redacted>")
            .finish()
    }
}

impl GtpuSourcePortRange {
    /// Construct an inclusive range. Equal or descending endpoints are not a
    /// canonical range and return `None`.
    #[must_use]
    pub const fn new(first: u16, last: u16) -> Option<Self> {
        if first < last {
            Some(Self { first, last })
        } else {
            None
        }
    }

    /// Return the first permitted port.
    #[must_use]
    pub const fn first(self) -> u16 {
        self.first
    }

    /// Return the last permitted port.
    #[must_use]
    pub const fn last(self) -> u16 {
        self.last
    }
}

/// Explicit, fixed-size policy for an inbound GTP-U UDP source port.
///
/// `Any` is the explicit dynamic-source-port policy required for peers that
/// follow TS 29.281 section 4.4.2. It is never inferred from missing state.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpuSourcePortPolicy {
    /// Accept every UDP source-port value.
    #[default]
    Any,
    /// Accept one exact UDP source port.
    Exact(u16),
    /// Accept one canonical inclusive range.
    InclusiveRange(GtpuSourcePortRange),
}

impl core::fmt::Debug for GtpuSourcePortPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Any => f.write_str("Any"),
            Self::Exact(_) => f.debug_tuple("Exact").field(&"<redacted>").finish(),
            Self::InclusiveRange(_) => f
                .debug_tuple("InclusiveRange")
                .field(&"<redacted>")
                .finish(),
        }
    }
}

impl GtpuSourcePortPolicy {
    /// Construct an inclusive multi-port range.
    #[must_use]
    pub const fn inclusive_range(first: u16, last: u16) -> Option<Self> {
        match GtpuSourcePortRange::new(first, last) {
            Some(range) => Some(Self::InclusiveRange(range)),
            None => None,
        }
    }

    /// Return whether `port` is authorized by this policy.
    #[must_use]
    pub const fn permits(self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => port == expected,
            Self::InclusiveRange(range) => port >= range.first && port <= range.last,
        }
    }

    const fn encode(self) -> (u8, u16, u16) {
        match self {
            Self::Any => (0, 0, 0),
            Self::Exact(port) => (1, port, port),
            Self::InclusiveRange(range) => (2, range.first, range.last),
        }
    }
}

/// Explicit uplink GTP-U UDP source-port selection policy.
///
/// TS 29.281 section 4.4.2 fixes the destination service port at 2152 and
/// leaves the source port to be set dynamically. Every uplink PDP context
/// carries one explicit policy; the pre-feature fixed-2152 behavior remains
/// available only as [`GtpuUplinkSourcePortPolicy::LegacyServicePort`]. The
/// granularity is deliberately per PDP/bearer context; a deterministic
/// inner-flow-hashed mode is a possible future extension of this type.
///
/// The selected port is persisted in the additive per-context source-port
/// maps. An absent map entry encodes the legacy policy, so pre-feature
/// pinned state upgrades without rewriting session entries. Port zero is
/// reserved (RFC 768) and rejected at every construction and decode
/// boundary, so corrupt adopted state fails closed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpuUplinkSourcePortPolicy {
    /// Explicit legacy policy: the UDP source port is fixed to 2152, exactly
    /// the pre-feature behavior.
    #[default]
    LegacyServicePort,
    /// One selected per-PDP/bearer-context UDP source port, stable for every
    /// packet of the context and across restarts.
    Selected(u16),
}

impl core::fmt::Debug for GtpuUplinkSourcePortPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LegacyServicePort => f.write_str("LegacyServicePort"),
            Self::Selected(_) => f.debug_tuple("Selected").field(&"<redacted>").finish(),
        }
    }
}

impl GtpuUplinkSourcePortPolicy {
    /// Construct a per-context selected-port policy. The reserved port zero
    /// fails closed with `None`.
    #[must_use]
    pub const fn selected(port: u16) -> Option<Self> {
        if port == 0 {
            None
        } else {
            Some(Self::Selected(port))
        }
    }

    /// Return the UDP source port stamped on uplink encapsulation under this
    /// policy. The legacy policy yields [`GTPU_UDP_PORT`].
    #[must_use]
    pub const fn effective_source_port(self) -> u16 {
        match self {
            Self::LegacyServicePort => GTPU_UDP_PORT,
            Self::Selected(port) => port,
        }
    }

    /// Return the additive source-port map value for this policy.
    ///
    /// The legacy policy is encoded as map absence (`None`), keeping
    /// pre-feature pinned state valid without rewriting entries. A selected
    /// port is stored big endian.
    #[must_use]
    pub const fn map_value(self) -> Option<[u8; UPLINK_SOURCE_PORT_VALUE_LEN]> {
        match self {
            Self::LegacyServicePort => None,
            Self::Selected(port) => Some(port.to_be_bytes()),
        }
    }

    /// Decode an additive source-port map value into the corresponding
    /// selected-port policy. A reserved zero port is corrupt adopted state
    /// and fails closed with `None`.
    #[must_use]
    pub const fn from_map_value(value: [u8; UPLINK_SOURCE_PORT_VALUE_LEN]) -> Option<Self> {
        Self::selected(u16::from_be_bytes(value))
    }
}

/// Fixed-cardinality reason an outer packet failed a downlink binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownlinkBindingMismatch {
    /// The stored record is non-canonical or otherwise corrupt.
    Invalid,
    /// The packet and configured endpoint families differ.
    AddressFamily,
    /// The packet's outer source is not the configured peer.
    PeerAddress,
    /// The packet's outer destination is not the configured local endpoint.
    LocalAddress,
    /// The packet arrived through a different tc attachment.
    IngressAttachment,
    /// The packet's UDP source port is not authorized.
    SourcePort,
}

/// Canonical downlink GTP-U outer endpoint and ingress binding.
///
/// The fixed 44-byte map layout is:
///
/// | offset | field |
/// |---|---|
/// | 0 | format version (`1`) |
/// | 1 | address family (`4` or `6`) |
/// | 2 | source-port policy (`0` any, `1` exact, `2` range) |
/// | 3 | reserved zero |
/// | 4..20 | peer address (IPv4 followed by twelve zero bytes, or IPv6) |
/// | 20..36 | local address (same family/canonical form) |
/// | 36..40 | ingress ifindex, big endian |
/// | 40..42 | first source port, big endian |
/// | 42..44 | last source port, big endian |
///
/// Addresses, ports, and the attachment identifier are redacted from `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DownlinkEndpointBinding {
    peer_address: GtpuEndpointAddress,
    local_address: GtpuEndpointAddress,
    ingress_ifindex: u32,
    source_port_policy: GtpuSourcePortPolicy,
    format_valid: bool,
}

impl core::fmt::Debug for DownlinkEndpointBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DownlinkEndpointBinding")
            .field("peer_address", &"<redacted>")
            .field("local_address", &"<redacted>")
            .field("ingress_ifindex", &"<redacted>")
            .field("source_port_policy", &"<redacted>")
            .field("format_valid", &self.format_valid)
            .finish()
    }
}

impl DownlinkEndpointBinding {
    /// Construct one canonical binding.
    ///
    /// Unspecified addresses, a zero ingress ifindex, and mixed address
    /// families are rejected.
    #[must_use]
    pub fn new(
        peer_address: GtpuEndpointAddress,
        local_address: GtpuEndpointAddress,
        ingress_ifindex: u32,
        source_port_policy: GtpuSourcePortPolicy,
    ) -> Option<Self> {
        if peer_address.family_wire() != local_address.family_wire()
            || peer_address.is_unspecified()
            || local_address.is_unspecified()
            || ingress_ifindex == 0
        {
            None
        } else {
            Some(Self {
                peer_address,
                local_address,
                ingress_ifindex,
                source_port_policy,
                format_valid: true,
            })
        }
    }

    /// Return the peer endpoint address.
    #[must_use]
    pub const fn peer_address(self) -> GtpuEndpointAddress {
        self.peer_address
    }

    /// Return the local endpoint address.
    #[must_use]
    pub const fn local_address(self) -> GtpuEndpointAddress {
        self.local_address
    }

    /// Return the exact ingress attachment identifier.
    #[must_use]
    pub const fn ingress_ifindex(self) -> u32 {
        self.ingress_ifindex
    }

    /// Return the explicit UDP source-port policy.
    #[must_use]
    pub const fn source_port_policy(self) -> GtpuSourcePortPolicy {
        self.source_port_policy
    }

    /// Return whether every field uses the canonical bounded encoding.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.format_valid
            && self.peer_address.family_wire() == self.local_address.family_wire()
            && !self.peer_address.is_unspecified()
            && !self.local_address.is_unspecified()
            && self.ingress_ifindex != 0
    }

    /// Validate an IPv4 packet's outer provenance without exposing values.
    pub fn validate_ipv4_packet(
        self,
        peer_address: [u8; 4],
        local_address: [u8; 4],
        ingress_ifindex: u32,
        source_port: u16,
    ) -> Result<(), DownlinkBindingMismatch> {
        if !self.is_valid() {
            return Err(DownlinkBindingMismatch::Invalid);
        }
        let (expected_peer, expected_local) = match (self.peer_address, self.local_address) {
            (GtpuEndpointAddress::Ipv4(peer), GtpuEndpointAddress::Ipv4(local)) => (peer, local),
            _ => return Err(DownlinkBindingMismatch::AddressFamily),
        };
        if peer_address != expected_peer {
            return Err(DownlinkBindingMismatch::PeerAddress);
        }
        if local_address != expected_local {
            return Err(DownlinkBindingMismatch::LocalAddress);
        }
        if ingress_ifindex != self.ingress_ifindex {
            return Err(DownlinkBindingMismatch::IngressAttachment);
        }
        if !self.source_port_policy.permits(source_port) {
            return Err(DownlinkBindingMismatch::SourcePort);
        }
        Ok(())
    }

    /// Encode into the fixed canonical map-value layout.
    #[must_use]
    pub const fn encode(self) -> [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN] {
        let peer = self.peer_address.encode_bytes();
        let local = self.local_address.encode_bytes();
        let ifindex = self.ingress_ifindex.to_be_bytes();
        let (policy, first, last) = self.source_port_policy.encode();
        let first = first.to_be_bytes();
        let last = last.to_be_bytes();
        [
            1,
            self.peer_address.family_wire(),
            policy,
            0,
            peer[0],
            peer[1],
            peer[2],
            peer[3],
            peer[4],
            peer[5],
            peer[6],
            peer[7],
            peer[8],
            peer[9],
            peer[10],
            peer[11],
            peer[12],
            peer[13],
            peer[14],
            peer[15],
            local[0],
            local[1],
            local[2],
            local[3],
            local[4],
            local[5],
            local[6],
            local[7],
            local[8],
            local[9],
            local[10],
            local[11],
            local[12],
            local[13],
            local[14],
            local[15],
            ifindex[0],
            ifindex[1],
            ifindex[2],
            ifindex[3],
            first[0],
            first[1],
            last[0],
            last[1],
        ]
    }

    /// Decode a map value while retaining whether every byte was canonical.
    #[must_use]
    pub const fn decode(value: &[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]) -> Self {
        let mut peer = [0_u8; 16];
        let mut local = [0_u8; 16];
        let mut index = 0;
        while index < 16 {
            peer[index] = value[index + 4];
            local[index] = value[index + 20];
            index += 1;
        }
        let ipv4_tail_zero = peer[4] == 0
            && peer[5] == 0
            && peer[6] == 0
            && peer[7] == 0
            && peer[8] == 0
            && peer[9] == 0
            && peer[10] == 0
            && peer[11] == 0
            && peer[12] == 0
            && peer[13] == 0
            && peer[14] == 0
            && peer[15] == 0
            && local[4] == 0
            && local[5] == 0
            && local[6] == 0
            && local[7] == 0
            && local[8] == 0
            && local[9] == 0
            && local[10] == 0
            && local[11] == 0
            && local[12] == 0
            && local[13] == 0
            && local[14] == 0
            && local[15] == 0;
        let (peer_address, local_address, family_valid) = match value[1] {
            4 => (
                GtpuEndpointAddress::Ipv4([peer[0], peer[1], peer[2], peer[3]]),
                GtpuEndpointAddress::Ipv4([local[0], local[1], local[2], local[3]]),
                ipv4_tail_zero,
            ),
            6 => (
                GtpuEndpointAddress::Ipv6(peer),
                GtpuEndpointAddress::Ipv6(local),
                true,
            ),
            _ => (
                GtpuEndpointAddress::Ipv4([0; 4]),
                GtpuEndpointAddress::Ipv4([0; 4]),
                false,
            ),
        };
        let first = u16::from_be_bytes([value[40], value[41]]);
        let last = u16::from_be_bytes([value[42], value[43]]);
        let (source_port_policy, policy_valid) = match value[2] {
            0 => (GtpuSourcePortPolicy::Any, first == 0 && last == 0),
            1 => (GtpuSourcePortPolicy::Exact(first), first == last),
            2 if first < last => (
                GtpuSourcePortPolicy::InclusiveRange(GtpuSourcePortRange { first, last }),
                true,
            ),
            _ => (GtpuSourcePortPolicy::Any, false),
        };
        Self {
            peer_address,
            local_address,
            ingress_ifindex: u32::from_be_bytes([value[36], value[37], value[38], value[39]]),
            source_port_policy,
            format_valid: value[0] == 1 && value[3] == 0 && family_valid && policy_valid,
        }
    }
}

#[inline(always)]
fn wire_range_is_nonzero(value: &[u8], start: usize, length: usize) -> bool {
    let mut index = 0;
    while index < length {
        if value[start + index] != 0 {
            return true;
        }
        index += 1;
    }
    false
}

#[inline(always)]
fn wire_range_is_zero(value: &[u8], start: usize, length: usize) -> bool {
    !wire_range_is_nonzero(value, start, length)
}

#[inline(always)]
fn wire_ranges_equal(
    left: &[u8],
    left_start: usize,
    right: &[u8],
    right_start: usize,
    length: usize,
) -> bool {
    let mut index = 0;
    while index < length {
        if left[left_start + index] != right[right_start + index] {
            return false;
        }
        index += 1;
    }
    true
}

#[inline(always)]
fn binding_wire_is_valid(value: &[u8], base: usize) -> bool {
    let family_valid = match value[base + 1] {
        4 => {
            wire_range_is_nonzero(value, base + 4, 4)
                && wire_range_is_nonzero(value, base + 20, 4)
                && wire_range_is_zero(value, base + 8, 12)
                && wire_range_is_zero(value, base + 24, 12)
        }
        6 => {
            wire_range_is_nonzero(value, base + 4, 16)
                && wire_range_is_nonzero(value, base + 20, 16)
        }
        _ => false,
    };
    let first = u16::from_be_bytes([value[base + 40], value[base + 41]]);
    let last = u16::from_be_bytes([value[base + 42], value[base + 43]]);
    let policy_valid = match value[base + 2] {
        0 => first == 0 && last == 0,
        1 => first == last,
        2 => first < last,
        _ => false,
    };
    value[base] == 1
        && value[base + 3] == 0
        && family_valid
        && policy_valid
        && u32::from_be_bytes([
            value[base + 36],
            value[base + 37],
            value[base + 38],
            value[base + 39],
        ]) != 0
}

/// Validate an IPv4 packet against a canonical binding wire value.
///
/// This allocation-free boundary is equivalent to
/// [`DownlinkEndpointBinding::decode`] followed by
/// [`DownlinkEndpointBinding::validate_ipv4_packet`]. It exists so the eBPF
/// classifier does not materialize the full 44-byte typed value on its
/// verifier-limited stack.
pub fn validate_ipv4_downlink_binding_wire(
    value: &[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
    peer_address: [u8; 4],
    local_address: [u8; 4],
    ingress_ifindex: u32,
    source_port: u16,
) -> Result<(), DownlinkBindingMismatch> {
    if !binding_wire_is_valid(value, 0) {
        return Err(DownlinkBindingMismatch::Invalid);
    }
    if value[1] != 4 {
        return Err(DownlinkBindingMismatch::AddressFamily);
    }
    if !wire_ranges_equal(&peer_address, 0, value, 4, 4) {
        return Err(DownlinkBindingMismatch::PeerAddress);
    }
    if !wire_ranges_equal(&local_address, 0, value, 20, 4) {
        return Err(DownlinkBindingMismatch::LocalAddress);
    }
    if ingress_ifindex != u32::from_be_bytes([value[36], value[37], value[38], value[39]]) {
        return Err(DownlinkBindingMismatch::IngressAttachment);
    }
    let first = u16::from_be_bytes([value[40], value[41]]);
    let last = u16::from_be_bytes([value[42], value[43]]);
    let permitted = match value[2] {
        0 => true,
        1 => source_port == first,
        2 => source_port >= first && source_port <= last,
        _ => false,
    };
    if !permitted {
        return Err(DownlinkBindingMismatch::SourcePort);
    }
    Ok(())
}

/// Downlink PDR value used by an unmarked/default bearer.
///
/// This layout remains byte-for-byte compatible with pin sets created before
/// per-bearer packet marks were introduced. New marked bearers use
/// [`MarkedDownlinkPdr`] in a separate additive map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownlinkPdr {
    /// UE PAA the inner packet must be addressed to, network order.
    pub ue_ip: [u8; 4],
}

impl DownlinkPdr {
    /// Encode into the fixed legacy map-value byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; DOWNLINK_PDR_VALUE_LEN] {
        self.ue_ip
    }

    /// Decode from the fixed legacy map-value byte layout.
    #[must_use]
    pub const fn decode(value: &[u8; DOWNLINK_PDR_VALUE_LEN]) -> Self {
        Self { ue_ip: *value }
    }
}

/// Validate one complete default-bearer graph before restart adoption.
///
/// Default bearers do not have a durable owner journal, so the PDR key/value,
/// FAR, endpoint binding, managed local address, and ingress attachment must
/// form one canonical graph. This shared predicate keeps the production Aya
/// loader and its deterministic fake from accepting different persisted
/// state. It intentionally rejects zero TEIDs, zero peer TEIDs, unspecified UE
/// addresses, and a UE address equal to the managed local endpoint.
#[must_use]
pub fn default_bearer_graph_is_valid(
    local_teid: [u8; 4],
    pdr: DownlinkPdr,
    far: UplinkFar,
    binding: DownlinkEndpointBinding,
    managed_local_ip: [u8; 4],
    ingress_ifindex: u32,
) -> bool {
    local_teid != [0; 4]
        && pdr.ue_ip != [0; 4]
        && pdr.ue_ip != managed_local_ip
        && far.peer_ip != [0; 4]
        && far.local_ip == managed_local_ip
        && far.o_teid != [0; 4]
        && binding.is_valid()
        && binding.ingress_ifindex() == ingress_ifindex
        && binding.peer_address() == GtpuEndpointAddress::Ipv4(far.peer_ip)
        && binding.local_address() == GtpuEndpointAddress::Ipv4(managed_local_ip)
}

/// Marked downlink PDR map value: decapsulation and XFRM selection state.
///
/// Map key: the ePDG-assigned local S2b-U TEID, 4 bytes network order (the
/// TEID exactly as it appears in received G-PDUs).
///
/// Value layout (8 bytes): the UE PAA (inner IPv4 destination), followed by
/// the complete Linux packet mark, both in network byte order.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MarkedDownlinkPdr {
    /// UE PAA the inner packet must be addressed to, network order.
    pub ue_ip: [u8; 4],
    /// Mark stamped after decapsulation for XFRM OUT policy selection.
    pub bearer_mark: [u8; 4],
}

impl core::fmt::Debug for MarkedDownlinkPdr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MarkedDownlinkPdr")
            .field("ue_ip", &"<redacted>")
            .field("bearer_mark", &"<redacted>")
            .finish()
    }
}

impl MarkedDownlinkPdr {
    /// Encode into the fixed map-value byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; MARKED_DOWNLINK_PDR_VALUE_LEN] {
        [
            self.ue_ip[0],
            self.ue_ip[1],
            self.ue_ip[2],
            self.ue_ip[3],
            self.bearer_mark[0],
            self.bearer_mark[1],
            self.bearer_mark[2],
            self.bearer_mark[3],
        ]
    }

    /// Decode from the fixed map-value byte layout.
    #[must_use]
    pub const fn decode(value: &[u8; MARKED_DOWNLINK_PDR_VALUE_LEN]) -> Self {
        Self {
            ue_ip: [value[0], value[1], value[2], value[3]],
            bearer_mark: [value[4], value[5], value[6], value[7]],
        }
    }
}

/// Durable owner journal for one marked bearer.
///
/// Map key: [`UplinkFarKey`]. The value binds that selector to the local
/// TEID, complete uplink FAR, downlink endpoint binding, and requested DSCP
/// before any forwarding map is published, allowing exact crash retry and
/// conflict rejection in O(1).
///
/// Layout: local TEID (4), encoded [`UplinkFar`] (12), DSCP (`0xff` = absent,
/// otherwise 0..63), format version (`2`), [`MarkedBearerOwnerPhase`], one
/// zero reserved byte, and encoded [`DownlinkEndpointBinding`] (44).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MarkedBearerOwner {
    /// ePDG-assigned local S2b-U TEID, network order.
    pub local_teid: [u8; 4],
    /// Exact uplink FAR committed for this bearer.
    pub uplink_far: UplinkFar,
    /// Always-initialized wire byte (`0xff` means absent).
    egress_dscp_wire: u8,
    /// Durable publication/removal phase.
    pub phase: MarkedBearerOwnerPhase,
    /// Exact downlink outer endpoint and ingress identity.
    pub downlink_binding: DownlinkEndpointBinding,
    format_valid: bool,
}

impl core::fmt::Debug for MarkedBearerOwner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MarkedBearerOwner")
            .field("local_teid", &"<redacted>")
            .field("uplink_far", &"<redacted>")
            .field("egress_dscp", &self.egress_dscp())
            .field("phase", &self.phase)
            .field("downlink_binding", &self.downlink_binding)
            .field("format_valid", &self.format_valid)
            .finish()
    }
}

/// Durable state of one marked-bearer publication transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MarkedBearerOwnerPhase {
    /// Owner is reserved; forwarding resources may still be incomplete.
    Pending = 1,
    /// Every forwarding resource was published and may carry traffic.
    Active = 2,
    /// Removal was committed; forwarding resources must not be resurrected.
    Removing = 3,
}

impl MarkedBearerOwner {
    /// Construct a canonical owner journal value.
    #[must_use]
    pub const fn new(
        local_teid: [u8; 4],
        uplink_far: UplinkFar,
        egress_dscp: Option<u8>,
        downlink_binding: DownlinkEndpointBinding,
        phase: MarkedBearerOwnerPhase,
    ) -> Self {
        Self {
            local_teid,
            uplink_far,
            egress_dscp_wire: match egress_dscp {
                Some(value) => value,
                None => 0xff,
            },
            phase,
            downlink_binding,
            format_valid: true,
        }
    }

    /// Return the optional outer uplink DSCP requested by the owner.
    #[must_use]
    pub fn egress_dscp(&self) -> Option<u8> {
        if self.egress_dscp_wire == 0xff {
            None
        } else {
            Some(self.egress_dscp_wire)
        }
    }

    /// Return the canonical journal wire byte (`0xff` means absent).
    #[must_use]
    pub const fn egress_dscp_wire(&self) -> u8 {
        self.egress_dscp_wire
    }

    /// Return whether every bounded field and reserved byte is canonical.
    #[must_use]
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.format_valid
            && self.local_teid != [0; 4]
            && self.uplink_far.peer_ip != [0; 4]
            && self.uplink_far.local_ip != [0; 4]
            && self.uplink_far.o_teid != [0; 4]
            && (self.egress_dscp_wire <= 63 || self.egress_dscp_wire == 0xff)
            && self.downlink_binding.is_valid()
            && matches!(
                (
                    self.downlink_binding.peer_address(),
                    self.downlink_binding.local_address()
                ),
                (GtpuEndpointAddress::Ipv4(peer), GtpuEndpointAddress::Ipv4(local))
                    if peer == self.uplink_far.peer_ip && local == self.uplink_far.local_ip
            )
    }

    /// Return whether this journal permits the exact marked uplink state.
    #[must_use]
    #[inline(always)]
    pub fn authorizes_uplink(&self, far: &UplinkFar, dscp_wire: u8) -> bool {
        self.is_valid()
            && matches!(self.phase, MarkedBearerOwnerPhase::Active)
            && self.uplink_far.peer_ip == far.peer_ip
            && self.uplink_far.local_ip == far.local_ip
            && self.uplink_far.o_teid == far.o_teid
            && self.egress_dscp_wire == dscp_wire
    }

    /// Return whether this journal permits the exact marked downlink TEID.
    #[must_use]
    #[inline(always)]
    pub fn authorizes_downlink(
        &self,
        local_teid: [u8; 4],
        binding: &DownlinkEndpointBinding,
    ) -> bool {
        self.is_valid()
            && matches!(self.phase, MarkedBearerOwnerPhase::Active)
            && self.local_teid == local_teid
            && self.downlink_binding == *binding
    }

    /// Encode into the fixed journal-value layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; MARKED_BEARER_OWNER_VALUE_LEN] {
        let far = self.uplink_far.encode();
        let binding = self.downlink_binding.encode();
        [
            self.local_teid[0],
            self.local_teid[1],
            self.local_teid[2],
            self.local_teid[3],
            far[0],
            far[1],
            far[2],
            far[3],
            far[4],
            far[5],
            far[6],
            far[7],
            far[8],
            far[9],
            far[10],
            far[11],
            self.egress_dscp_wire,
            2,
            self.phase as u8,
            0,
            binding[0],
            binding[1],
            binding[2],
            binding[3],
            binding[4],
            binding[5],
            binding[6],
            binding[7],
            binding[8],
            binding[9],
            binding[10],
            binding[11],
            binding[12],
            binding[13],
            binding[14],
            binding[15],
            binding[16],
            binding[17],
            binding[18],
            binding[19],
            binding[20],
            binding[21],
            binding[22],
            binding[23],
            binding[24],
            binding[25],
            binding[26],
            binding[27],
            binding[28],
            binding[29],
            binding[30],
            binding[31],
            binding[32],
            binding[33],
            binding[34],
            binding[35],
            binding[36],
            binding[37],
            binding[38],
            binding[39],
            binding[40],
            binding[41],
            binding[42],
            binding[43],
        ]
    }

    /// Decode a journal value while retaining whether its format was valid.
    #[must_use]
    pub const fn decode(value: &[u8; MARKED_BEARER_OWNER_VALUE_LEN]) -> Self {
        let mut far = [0_u8; UPLINK_FAR_VALUE_LEN];
        let mut index = 0;
        while index < UPLINK_FAR_VALUE_LEN {
            far[index] = value[index + 4];
            index += 1;
        }
        let mut binding = [0_u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN];
        index = 0;
        while index < DOWNLINK_ENDPOINT_BINDING_VALUE_LEN {
            binding[index] = value[index + 20];
            index += 1;
        }
        let (phase, phase_valid) = match value[18] {
            1 => (MarkedBearerOwnerPhase::Pending, true),
            2 => (MarkedBearerOwnerPhase::Active, true),
            3 => (MarkedBearerOwnerPhase::Removing, true),
            _ => (MarkedBearerOwnerPhase::Pending, false),
        };
        Self {
            local_teid: [value[0], value[1], value[2], value[3]],
            uplink_far: UplinkFar::decode(&far),
            egress_dscp_wire: value[16],
            phase,
            downlink_binding: DownlinkEndpointBinding::decode(&binding),
            format_valid: value[17] == 2 && phase_valid && value[19] == 0,
        }
    }
}

#[inline(always)]
fn marked_owner_wire_is_valid(value: &[u8; MARKED_BEARER_OWNER_VALUE_LEN]) -> bool {
    value[17] == 2
        && matches!(value[18], 1..=3)
        && value[19] == 0
        && wire_range_is_nonzero(value, 0, 4)
        && wire_range_is_nonzero(value, 4, 4)
        && wire_range_is_nonzero(value, 8, 4)
        && wire_range_is_nonzero(value, 12, 4)
        && (value[16] <= 63 || value[16] == 0xff)
        && binding_wire_is_valid(value, 20)
        && value[21] == 4
        && wire_ranges_equal(value, 4, value, 24, 4)
        && wire_ranges_equal(value, 8, value, 40, 4)
}

/// Return whether an encoded owner journal authorizes exact marked uplink
/// state without materializing the 64-byte typed journal.
///
/// This is the allocation-free eBPF equivalent of
/// [`MarkedBearerOwner::decode`] followed by
/// [`MarkedBearerOwner::authorizes_uplink`].
#[must_use]
pub fn marked_owner_wire_authorizes_uplink(
    value: &[u8; MARKED_BEARER_OWNER_VALUE_LEN],
    far: &UplinkFar,
    dscp_wire: u8,
) -> bool {
    marked_owner_wire_is_valid(value)
        && value[18] == MarkedBearerOwnerPhase::Active as u8
        && wire_ranges_equal(value, 4, &far.peer_ip, 0, 4)
        && wire_ranges_equal(value, 8, &far.local_ip, 0, 4)
        && wire_ranges_equal(value, 12, &far.o_teid, 0, 4)
        && value[16] == dscp_wire
}

/// Return whether an encoded owner journal authorizes the exact local TEID
/// and encoded downlink endpoint binding.
///
/// This is the allocation-free eBPF equivalent of
/// [`MarkedBearerOwner::decode`] followed by
/// [`MarkedBearerOwner::authorizes_downlink`].
#[must_use]
pub fn marked_owner_wire_authorizes_downlink(
    value: &[u8; MARKED_BEARER_OWNER_VALUE_LEN],
    local_teid: [u8; 4],
    binding: &[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
) -> bool {
    marked_owner_wire_is_valid(value)
        && value[18] == MarkedBearerOwnerPhase::Active as u8
        && wire_ranges_equal(value, 0, &local_teid, 0, 4)
        && wire_ranges_equal(value, 20, binding, 0, DOWNLINK_ENDPOINT_BINDING_VALUE_LEN)
}

/// Compute the IPv4 header checksum over a 20-byte option-free header.
///
/// The checksum field (offset 10..12) is treated as zero regardless of its
/// current contents, so the result can be stamped directly.
#[must_use]
pub fn ipv4_header_checksum(header: &[u8; IPV4_MIN_HDR_LEN]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < IPV4_MIN_HDR_LEN {
        if i != 10 {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        }
        i += 2;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build the exact 36 encapsulation bytes prepended to an uplink inner IPv4
/// packet: `[outer IPv4][UDP][GTPv1-U]`, outermost first (TS 29.281 §5.1).
///
/// `inner_len` is the full inner IPv4 packet length (header + payload).
/// Returns `None` when the encapsulated packet would exceed the IPv4
/// total-length field.
///
/// - Outer IPv4: IHL=5, DSCP/ECN=0, ID=0, no fragmentation flags, TTL=64,
///   protocol=UDP, checksum computed.
/// - UDP: source and destination port 2152; checksum 0 (permitted for UDP
///   over IPv4 by RFC 768; TS 29.281 transports GTP-U over UDP unchanged).
/// - GTPv1-U: flags 0x30 (version 1, PT=1, E=S=PN=0), message type 0xFF
///   (G-PDU), length = `inner_len` (octets after the mandatory 8-byte
///   header), TEID from the FAR.
#[must_use]
pub fn build_uplink_encap(far: &UplinkFar, inner_len: u16) -> Option<[u8; GTPU_ENCAP_LEN]> {
    build_uplink_encap_with_dscp(far, inner_len, None)
}

/// Build uplink encapsulation with an optional fixed outer DSCP codepoint.
///
/// A present codepoint must be in `0..=63`. The DSCP occupies the high six
/// bits of the IPv4 ToS octet and the ECN bits remain zero for this newly
/// generated outer header. Invalid codepoints fail closed with `None`.
/// Passing `None` is byte-for-byte equivalent to [`build_uplink_encap`].
#[must_use]
pub fn build_uplink_encap_with_dscp(
    far: &UplinkFar,
    inner_len: u16,
    dscp: Option<u8>,
) -> Option<[u8; GTPU_ENCAP_LEN]> {
    build_uplink_encap_with_dscp_and_source_port(far, inner_len, dscp, GTPU_UDP_PORT)
}

/// Build uplink encapsulation with an optional fixed outer DSCP codepoint
/// and an explicit UDP source port.
///
/// The UDP destination port is always [`GTPU_UDP_PORT`] (TS 29.281 section
/// 4.4.2 fixes the destination service port). `source_port` selects the UDP
/// source port; the reserved port zero fails closed with `None`. Passing
/// [`GTPU_UDP_PORT`] is byte-for-byte equivalent to
/// [`build_uplink_encap_with_dscp`]. DSCP handling matches
/// [`build_uplink_encap_with_dscp`].
#[must_use]
pub fn build_uplink_encap_with_dscp_and_source_port(
    far: &UplinkFar,
    inner_len: u16,
    dscp: Option<u8>,
    source_port: u16,
) -> Option<[u8; GTPU_ENCAP_LEN]> {
    const ENCAP: u16 = GTPU_ENCAP_LEN as u16;
    if source_port == 0 {
        return None;
    }
    if dscp.is_some_and(|value| value > 63) {
        return None;
    }
    if inner_len > u16::MAX - ENCAP {
        return None;
    }
    let outer_total = inner_len + ENCAP;
    let udp_len = inner_len + (UDP_HDR_LEN + GTPU_MANDATORY_HDR_LEN) as u16;

    let mut out = [0_u8; GTPU_ENCAP_LEN];
    // Outer IPv4 header.
    out[0] = 0x45; // version 4, IHL 5
    out[1] = dscp.unwrap_or(0) << 2;
    out[2..4].copy_from_slice(&outer_total.to_be_bytes());
    out[8] = 64; // TTL
    out[9] = 17; // UDP
    out[12..16].copy_from_slice(&far.local_ip);
    out[16..20].copy_from_slice(&far.peer_ip);
    let mut ip_header = [0_u8; IPV4_MIN_HDR_LEN];
    ip_header.copy_from_slice(&out[..IPV4_MIN_HDR_LEN]);
    let checksum = ipv4_header_checksum(&ip_header);
    out[10..12].copy_from_slice(&checksum.to_be_bytes());
    // UDP header.
    out[20..22].copy_from_slice(&source_port.to_be_bytes());
    out[22..24].copy_from_slice(&GTPU_UDP_PORT.to_be_bytes());
    out[24..26].copy_from_slice(&udp_len.to_be_bytes());
    // out[26..28] UDP checksum stays 0.
    // GTPv1-U header.
    out[28] = GTPU_FLAGS_V1_GPDU;
    out[29] = GTPU_MSG_TYPE_GPDU;
    out[30..32].copy_from_slice(&inner_len.to_be_bytes());
    out[32..36].copy_from_slice(&far.o_teid);
    Some(out)
}

/// Classification of the first [`GTPU_MANDATORY_HDR_LEN`] bytes of a UDP/2152
/// payload on the downlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuClass {
    /// Not a GTPv1 PDU (wrong version or PT=0); pass through untouched.
    NotGtpV1,
    /// A GTPv1 message that is not a G-PDU (echo, error indication, ...);
    /// pass through so the control plane can consume it.
    NotGpdu,
    /// A G-PDU carrying a T-PDU.
    Gpdu {
        /// TEID exactly as on the wire, network order.
        teid: [u8; 4],
        /// Value of the GTP-U length field (octets after the mandatory 8).
        length: u16,
        /// Whether any of the S/PN/E flags is set, i.e. the 4-byte optional
        /// block follows the mandatory header.
        has_opt: bool,
        /// Whether the E flag is set, i.e. extension headers follow the
        /// optional block and must be walked.
        has_ext: bool,
    },
}

/// Classify the mandatory GTPv1-U header of a received UDP/2152 payload.
#[must_use]
pub fn classify_gtpu(header: &[u8; GTPU_MANDATORY_HDR_LEN]) -> GtpuClass {
    let flags = header[0];
    if flags & GTPU_FLAGS_VERSION_MASK != GTPU_FLAGS_VERSION_V1 || flags & GTPU_FLAG_PT == 0 {
        return GtpuClass::NotGtpV1;
    }
    if header[1] != GTPU_MSG_TYPE_GPDU {
        return GtpuClass::NotGpdu;
    }
    GtpuClass::Gpdu {
        teid: [header[4], header[5], header[6], header[7]],
        length: u16::from_be_bytes([header[2], header[3]]),
        has_opt: flags & (GTPU_FLAG_E | GTPU_FLAG_S | GTPU_FLAG_PN) != 0,
        has_ext: flags & GTPU_FLAG_E != 0,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn far() -> UplinkFar {
        UplinkFar {
            peer_ip: [192, 0, 2, 10],
            local_ip: [192, 0, 2, 1],
            o_teid: [0x20, 0x00, 0x00, 0x01],
        }
    }

    #[test]
    fn far_value_round_trips_and_matches_documented_layout() {
        let encoded = far().encode();
        assert_eq!(&encoded[0..4], &[192, 0, 2, 10]);
        assert_eq!(&encoded[4..8], &[192, 0, 2, 1]);
        assert_eq!(&encoded[8..12], &[0x20, 0x00, 0x00, 0x01]);
        assert_eq!(UplinkFar::decode(&encoded), far());
    }

    #[test]
    fn pdr_value_round_trips() {
        let pdr = MarkedDownlinkPdr {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: 0x0102_0304_u32.to_be_bytes(),
        };
        assert_eq!(pdr.encode(), [10, 45, 0, 2, 1, 2, 3, 4]);
        assert_eq!(MarkedDownlinkPdr::decode(&pdr.encode()), pdr);
    }

    #[test]
    fn legacy_pdr_value_remains_exactly_four_address_bytes() {
        let pdr = DownlinkPdr {
            ue_ip: [10, 45, 0, 2],
        };
        assert_eq!(pdr.encode(), [10, 45, 0, 2]);
        assert_eq!(DownlinkPdr::decode(&pdr.encode()), pdr);
    }

    #[test]
    fn marked_uplink_key_round_trips_and_is_network_ordered() {
        let key = UplinkFarKey {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: 0x1020_3040_u32.to_be_bytes(),
        };
        assert_eq!(key.encode(), [10, 45, 0, 2, 0x10, 0x20, 0x30, 0x40]);
        assert_eq!(UplinkFarKey::decode(&key.encode()), key);
        assert!(!std::format!("{key:?}").contains("10203040"));
    }

    #[test]
    fn marked_downlink_debug_redacts_address_and_mark() {
        let pdr = MarkedDownlinkPdr {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: 0x1020_3040_u32.to_be_bytes(),
        };
        let debug = std::format!("{pdr:?}");
        assert!(!debug.contains("10, 45"));
        assert!(!debug.contains("10203040"));
    }

    fn ipv4_binding(policy: GtpuSourcePortPolicy) -> DownlinkEndpointBinding {
        DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv4([192, 0, 2, 10]),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 1]),
            7,
            policy,
        )
        .unwrap()
    }

    #[test]
    fn endpoint_binding_round_trips_canonical_ipv4_and_ipv6_layouts() {
        let ipv4 = ipv4_binding(GtpuSourcePortPolicy::Exact(2152));
        let encoded = ipv4.encode();
        assert_eq!(&encoded[..4], &[1, 4, 1, 0]);
        assert_eq!(&encoded[4..8], &[192, 0, 2, 10]);
        assert_eq!(&encoded[8..20], &[0; 12]);
        assert_eq!(&encoded[20..24], &[192, 0, 2, 1]);
        assert_eq!(&encoded[24..36], &[0; 12]);
        assert_eq!(&encoded[36..40], &7_u32.to_be_bytes());
        assert_eq!(&encoded[40..44], &[0x08, 0x68, 0x08, 0x68]);
        assert_eq!(DownlinkEndpointBinding::decode(&encoded), ipv4);

        let ipv6 = DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            GtpuEndpointAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            9,
            GtpuSourcePortPolicy::inclusive_range(20_000, 30_000).unwrap(),
        )
        .unwrap();
        assert_eq!(DownlinkEndpointBinding::decode(&ipv6.encode()), ipv6);
        assert!(ipv6.is_valid());
    }

    #[test]
    fn default_bearer_graph_validation_rejects_noncanonical_session_identity() {
        let local_ip = [192, 0, 2, 1];
        let pdr = DownlinkPdr {
            ue_ip: [10, 45, 0, 2],
        };
        let canonical_far = far();
        let binding = ipv4_binding(GtpuSourcePortPolicy::Any);
        let local_teid = 0x1000_0001_u32.to_be_bytes();
        assert!(default_bearer_graph_is_valid(
            local_teid,
            pdr,
            canonical_far,
            binding,
            local_ip,
            7,
        ));

        assert!(!default_bearer_graph_is_valid(
            [0; 4],
            pdr,
            canonical_far,
            binding,
            local_ip,
            7,
        ));
        let mut zero_peer_teid = canonical_far;
        zero_peer_teid.o_teid = [0; 4];
        assert!(!default_bearer_graph_is_valid(
            local_teid,
            pdr,
            zero_peer_teid,
            binding,
            local_ip,
            7,
        ));
        assert!(!default_bearer_graph_is_valid(
            local_teid,
            DownlinkPdr { ue_ip: [0; 4] },
            canonical_far,
            binding,
            local_ip,
            7,
        ));
        assert!(!default_bearer_graph_is_valid(
            local_teid,
            DownlinkPdr { ue_ip: local_ip },
            canonical_far,
            binding,
            local_ip,
            7,
        ));
    }

    #[test]
    fn endpoint_binding_rejects_noncanonical_and_mixed_identity() {
        assert!(DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv4([192, 0, 2, 10]),
            GtpuEndpointAddress::Ipv6([1; 16]),
            7,
            GtpuSourcePortPolicy::Any,
        )
        .is_none());
        assert!(DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv4([0; 4]),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 1]),
            7,
            GtpuSourcePortPolicy::Any,
        )
        .is_none());
        assert!(DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv4([192, 0, 2, 10]),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 1]),
            0,
            GtpuSourcePortPolicy::Any,
        )
        .is_none());
        assert!(GtpuSourcePortPolicy::inclusive_range(2152, 2152).is_none());
        assert!(GtpuSourcePortPolicy::inclusive_range(3000, 2000).is_none());

        let canonical = ipv4_binding(GtpuSourcePortPolicy::Any).encode();
        for (offset, replacement) in [(0, 2), (1, 5), (2, 3), (3, 1), (8, 1), (40, 1)] {
            let mut malformed = canonical;
            malformed[offset] = replacement;
            assert!(!DownlinkEndpointBinding::decode(&malformed).is_valid());
        }
        let mut zero_ifindex = canonical;
        zero_ifindex[36..40].fill(0);
        assert!(!DownlinkEndpointBinding::decode(&zero_ifindex).is_valid());
    }

    #[test]
    fn endpoint_binding_classifies_every_bounded_mismatch() {
        let exact = ipv4_binding(GtpuSourcePortPolicy::Exact(2152));
        let exact_wire = exact.encode();
        assert_eq!(
            exact.validate_ipv4_packet([192, 0, 2, 10], [192, 0, 2, 1], 7, 2152),
            Ok(())
        );
        assert_eq!(
            validate_ipv4_downlink_binding_wire(
                &exact_wire,
                [192, 0, 2, 10],
                [192, 0, 2, 1],
                7,
                2152,
            ),
            Ok(())
        );
        assert_eq!(
            exact.validate_ipv4_packet([192, 0, 2, 11], [192, 0, 2, 1], 7, 2152),
            Err(DownlinkBindingMismatch::PeerAddress)
        );
        assert_eq!(
            exact.validate_ipv4_packet([192, 0, 2, 10], [192, 0, 2, 2], 7, 2152),
            Err(DownlinkBindingMismatch::LocalAddress)
        );
        assert_eq!(
            exact.validate_ipv4_packet([192, 0, 2, 10], [192, 0, 2, 1], 8, 2152),
            Err(DownlinkBindingMismatch::IngressAttachment)
        );
        assert_eq!(
            exact.validate_ipv4_packet([192, 0, 2, 10], [192, 0, 2, 1], 7, 2153),
            Err(DownlinkBindingMismatch::SourcePort)
        );
        assert_eq!(
            validate_ipv4_downlink_binding_wire(
                &exact_wire,
                [192, 0, 2, 10],
                [192, 0, 2, 1],
                7,
                2153,
            ),
            Err(DownlinkBindingMismatch::SourcePort)
        );
        let ipv6 = DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv6([1; 16]),
            GtpuEndpointAddress::Ipv6([2; 16]),
            7,
            GtpuSourcePortPolicy::Any,
        )
        .unwrap();
        assert_eq!(
            ipv6.validate_ipv4_packet([192, 0, 2, 10], [192, 0, 2, 1], 7, 2152),
            Err(DownlinkBindingMismatch::AddressFamily)
        );
        assert!(GtpuSourcePortPolicy::Any.permits(0));
        assert!(GtpuSourcePortPolicy::inclusive_range(20_000, 30_000)
            .unwrap()
            .permits(25_000));
    }

    #[test]
    fn endpoint_binding_debug_redacts_all_outer_identity() {
        let binding = ipv4_binding(GtpuSourcePortPolicy::Exact(2152));
        let debug = std::format!("{binding:?}");
        for forbidden in ["192", "2152", "7"] {
            assert!(!debug.contains(forbidden));
        }
    }

    #[test]
    fn marked_map_names_are_unique_within_kernel_visible_limit() {
        const BPF_OBJ_NAME_VISIBLE_LEN: usize = 15;
        let new_names = [
            MAP_UPLINK_MARK_FAR,
            MAP_UPLINK_MARK_DSCP,
            MAP_DOWNLINK_MARK_PDR,
            MAP_DOWNLINK_ENDPOINT_BINDING,
            MAP_DOWNLINK_BINDING_COUNTERS,
            MAP_MARKED_BEARER_OWNER,
            MAP_UPLINK_SOURCE_PORT,
            MAP_UPLINK_MARK_SOURCE_PORT,
        ];
        for name in new_names {
            assert!(name.len() <= BPF_OBJ_NAME_VISIBLE_LEN);
        }
        let all_names = [
            MAP_UPLINK_FAR,
            MAP_UPLINK_MARK_FAR,
            MAP_UPLINK_DSCP,
            MAP_UPLINK_MARK_DSCP,
            MAP_UPLINK_SOURCE_PORT,
            MAP_UPLINK_MARK_SOURCE_PORT,
            MAP_DOWNLINK_PDR,
            MAP_DOWNLINK_MARK_PDR,
            MAP_DOWNLINK_ENDPOINT_BINDING,
            MAP_DOWNLINK_BINDING_COUNTERS,
            MAP_MARKED_BEARER_OWNER,
            MAP_COUNTERS,
            MAP_CONFIG,
        ];
        for (index, name) in all_names.iter().enumerate() {
            let name = &name.as_bytes()[..name.len().min(BPF_OBJ_NAME_VISIBLE_LEN)];
            for other in &all_names[index + 1..] {
                let other = other.as_bytes();
                let other = &other[..other.len().min(BPF_OBJ_NAME_VISIBLE_LEN)];
                assert_ne!(name, other);
            }
        }
    }

    #[test]
    fn complete_mark_ownership_makes_every_nonzero_bypass_fail_closed() {
        assert!(!uplink_non_encapsulation_drops(0));
        assert!(uplink_non_encapsulation_drops(1));
        assert!(uplink_non_encapsulation_drops(u32::MAX));
    }

    fn canonical_owner(phase: MarkedBearerOwnerPhase) -> MarkedBearerOwner {
        MarkedBearerOwner::new(
            0x1000_0001_u32.to_be_bytes(),
            UplinkFar {
                peer_ip: [192, 0, 2, 10],
                local_ip: [192, 0, 2, 1],
                o_teid: 0x2000_0001_u32.to_be_bytes(),
            },
            Some(46),
            DownlinkEndpointBinding::new(
                GtpuEndpointAddress::Ipv4([192, 0, 2, 10]),
                GtpuEndpointAddress::Ipv4([192, 0, 2, 1]),
                7,
                GtpuSourcePortPolicy::Any,
            )
            .unwrap(),
            phase,
        )
    }

    #[test]
    fn marked_owner_round_trips_exact_layout_and_redacts_identifiers() {
        let owner = canonical_owner(MarkedBearerOwnerPhase::Active);
        let encoded = owner.encode();
        assert_eq!(
            &encoded[..20],
            &[0x10, 0, 0, 1, 192, 0, 2, 10, 192, 0, 2, 1, 0x20, 0, 0, 1, 46, 2, 2, 0]
        );
        assert_eq!(&encoded[20..], &owner.downlink_binding.encode());
        assert_eq!(MarkedBearerOwner::decode(&encoded), owner);
        assert!(owner.is_valid());
        let debug = std::format!("{owner:?}");
        assert!(!debug.contains("192"));
        assert!(!debug.contains("268435457"));
        assert!(!debug.contains("536870913"));
    }

    #[test]
    fn active_owner_uses_initialized_absent_dscp_wire_sentinel() {
        let with_dscp = canonical_owner(MarkedBearerOwnerPhase::Active);
        let owner = MarkedBearerOwner::new(
            with_dscp.local_teid,
            with_dscp.uplink_far,
            None,
            with_dscp.downlink_binding,
            MarkedBearerOwnerPhase::Active,
        );
        let encoded = owner.encode();
        assert_eq!(encoded[16], 0xff);
        let decoded = MarkedBearerOwner::decode(&encoded);
        assert!(decoded.is_valid());
        assert_eq!(decoded.egress_dscp(), None);
        assert_eq!(decoded.egress_dscp_wire(), 0xff);
        assert!(decoded.authorizes_uplink(&decoded.uplink_far, 0xff));
        assert!(!decoded.authorizes_uplink(&decoded.uplink_far, 0));
    }

    #[test]
    fn marked_owner_rejects_every_noncanonical_bounded_field() {
        let encoded = canonical_owner(MarkedBearerOwnerPhase::Active).encode();
        for (offset, replacement) in [
            (17, 1),  // version
            (18, 0),  // phase
            (19, 1),  // reserved
            (16, 64), // DSCP
        ] {
            let mut malformed = encoded;
            malformed[offset] = replacement;
            assert!(!MarkedBearerOwner::decode(&malformed).is_valid());
        }
        for range in [0..4, 4..8, 8..12, 12..16] {
            let mut malformed = encoded;
            malformed[range].fill(0);
            assert!(!MarkedBearerOwner::decode(&malformed).is_valid());
        }
    }

    #[test]
    fn only_active_exact_owner_authorizes_marked_forwarding() {
        let far = canonical_owner(MarkedBearerOwnerPhase::Active).uplink_far;
        for phase in [
            MarkedBearerOwnerPhase::Pending,
            MarkedBearerOwnerPhase::Removing,
        ] {
            let owner = canonical_owner(phase);
            assert!(!owner.authorizes_uplink(&far, 46));
            assert!(
                !owner.authorizes_downlink(0x1000_0001_u32.to_be_bytes(), &owner.downlink_binding)
            );
        }
        let active = canonical_owner(MarkedBearerOwnerPhase::Active);
        assert!(active.authorizes_uplink(&far, 46));
        assert!(active.authorizes_downlink(0x1000_0001_u32.to_be_bytes(), &active.downlink_binding));
        let active_wire = active.encode();
        let binding_wire = active.downlink_binding.encode();
        assert!(marked_owner_wire_authorizes_uplink(&active_wire, &far, 46));
        assert!(marked_owner_wire_authorizes_downlink(
            &active_wire,
            active.local_teid,
            &binding_wire,
        ));
        assert!(!active.authorizes_uplink(&far, 0xff));
        assert!(!active.authorizes_uplink(&far, 47));
        let mut other_far = far;
        other_far.o_teid = 0x2000_0002_u32.to_be_bytes();
        assert!(!active.authorizes_uplink(&other_far, 46));
        assert!(!marked_owner_wire_authorizes_uplink(
            &active_wire,
            &other_far,
            46,
        ));
        assert!(
            !active.authorizes_downlink(0x1000_0002_u32.to_be_bytes(), &active.downlink_binding)
        );
        let other_binding = DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv4([192, 0, 2, 11]),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 1]),
            7,
            GtpuSourcePortPolicy::Any,
        )
        .unwrap();
        assert!(!active.authorizes_downlink(active.local_teid, &other_binding));
        assert!(!marked_owner_wire_authorizes_downlink(
            &active_wire,
            active.local_teid,
            &other_binding.encode(),
        ));
    }

    #[test]
    fn ipv4_checksum_matches_rfc1071_example() {
        // Canonical example header used in checksum walkthroughs.
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ipv4_header_checksum(&header), 0xB861);
    }

    #[test]
    fn ipv4_checksum_ignores_existing_checksum_bytes() {
        let mut header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let clean = ipv4_header_checksum(&header);
        header[10] = 0xDE;
        header[11] = 0xAD;
        assert_eq!(ipv4_header_checksum(&header), clean);
    }

    #[test]
    fn uplink_encap_emits_exact_ts29281_bytes() {
        // 60-byte inner IPv4 packet.
        let encap = build_uplink_encap(&far(), 60).unwrap();

        // Outer IPv4.
        assert_eq!(encap[0], 0x45);
        assert_eq!(u16::from_be_bytes([encap[2], encap[3]]), 96); // 60 + 36
        assert_eq!(u16::from_be_bytes([encap[6], encap[7]]), 0); // no frag bits
        assert_eq!(encap[8], 64);
        assert_eq!(encap[9], 17);
        assert_eq!(&encap[12..16], &[192, 0, 2, 1]); // outer src = local
        assert_eq!(&encap[16..20], &[192, 0, 2, 10]); // outer dst = peer
        let mut header = [0_u8; 20];
        header.copy_from_slice(&encap[..20]);
        assert_eq!(
            u16::from_be_bytes([encap[10], encap[11]]),
            ipv4_header_checksum(&header)
        );

        // UDP: sport = dport = 2152, len = 8 + 8 + inner, checksum 0.
        assert_eq!(u16::from_be_bytes([encap[20], encap[21]]), 2152);
        assert_eq!(u16::from_be_bytes([encap[22], encap[23]]), 2152);
        assert_eq!(u16::from_be_bytes([encap[24], encap[25]]), 76);
        assert_eq!(&encap[26..28], &[0, 0]);

        // GTPv1-U: flags 0x30, type 0xFF, length = inner octets, TEID.
        assert_eq!(encap[28], 0x30);
        assert_eq!(encap[29], 0xFF);
        assert_eq!(u16::from_be_bytes([encap[30], encap[31]]), 60);
        assert_eq!(&encap[32..36], &[0x20, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn uplink_encap_rejects_oversized_inner() {
        assert!(build_uplink_encap(&far(), u16::MAX - 35).is_none());
        assert!(build_uplink_encap(&far(), u16::MAX - 36).is_some());
    }

    #[test]
    fn absent_dscp_preserves_exact_legacy_encapsulation() {
        assert_eq!(
            build_uplink_encap(&far(), 60),
            build_uplink_encap_with_dscp(&far(), 60, None)
        );
        assert_eq!(build_uplink_encap(&far(), 60).unwrap()[1], 0);
    }

    #[test]
    fn fixed_dscp_is_stamped_and_ipv4_checksum_is_updated() {
        let encap = build_uplink_encap_with_dscp(&far(), 60, Some(46)).unwrap();
        assert_eq!(encap[1], 46 << 2);
        let mut header = [0_u8; IPV4_MIN_HDR_LEN];
        header.copy_from_slice(&encap[..IPV4_MIN_HDR_LEN]);
        assert_eq!(
            u16::from_be_bytes([encap[10], encap[11]]),
            ipv4_header_checksum(&header)
        );
    }

    #[test]
    fn fixed_dscp_accepts_boundaries_and_rejects_out_of_range() {
        assert_eq!(
            build_uplink_encap_with_dscp(&far(), 60, Some(0)).unwrap()[1],
            0
        );
        assert_eq!(
            build_uplink_encap_with_dscp(&far(), 60, Some(63)).unwrap()[1],
            0xfc
        );
        assert!(build_uplink_encap_with_dscp(&far(), 60, Some(64)).is_none());
        assert!(build_uplink_encap_with_dscp(&far(), 60, Some(u8::MAX)).is_none());
    }

    #[test]
    fn legacy_service_port_policy_preserves_exact_legacy_encapsulation() {
        assert_eq!(
            GtpuUplinkSourcePortPolicy::LegacyServicePort.effective_source_port(),
            GTPU_UDP_PORT
        );
        assert_eq!(
            GtpuUplinkSourcePortPolicy::LegacyServicePort.map_value(),
            None
        );
        // Byte-for-byte regression: the legacy policy emits exactly the
        // pre-feature source/destination 2152 bytes.
        assert_eq!(
            build_uplink_encap(&far(), 60),
            build_uplink_encap_with_dscp_and_source_port(&far(), 60, None, GTPU_UDP_PORT)
        );
        assert_eq!(
            build_uplink_encap_with_dscp(&far(), 60, Some(46)),
            build_uplink_encap_with_dscp_and_source_port(&far(), 60, Some(46), GTPU_UDP_PORT)
        );
    }

    #[test]
    fn selected_source_port_is_stamped_and_destination_remains_2152() {
        let encap = build_uplink_encap_with_dscp_and_source_port(&far(), 60, None, 40_000).unwrap();
        assert_eq!(u16::from_be_bytes([encap[20], encap[21]]), 40_000);
        assert_eq!(u16::from_be_bytes([encap[22], encap[23]]), GTPU_UDP_PORT);
        // The IPv4 header checksum does not cover UDP ports and every other
        // byte matches the legacy encapsulation except the source port.
        let legacy = build_uplink_encap(&far(), 60).unwrap();
        assert_eq!(&encap[..20], &legacy[..20]);
        assert_eq!(&encap[22..], &legacy[22..]);
    }

    #[test]
    fn reserved_zero_source_port_fails_closed_everywhere() {
        assert!(GtpuUplinkSourcePortPolicy::selected(0).is_none());
        assert!(GtpuUplinkSourcePortPolicy::from_map_value([0, 0]).is_none());
        assert!(build_uplink_encap_with_dscp_and_source_port(&far(), 60, None, 0).is_none());
    }

    #[test]
    fn source_port_policy_map_value_round_trips_big_endian() {
        let policy = GtpuUplinkSourcePortPolicy::selected(49_152).unwrap();
        assert_eq!(policy.map_value(), Some([0xC0, 0x00]));
        assert_eq!(
            GtpuUplinkSourcePortPolicy::from_map_value([0xC0, 0x00]),
            Some(policy)
        );
        assert_eq!(policy.effective_source_port(), 49_152);
        assert_eq!(
            GtpuUplinkSourcePortPolicy::from_map_value(GTPU_UDP_PORT.to_be_bytes()),
            Some(GtpuUplinkSourcePortPolicy::Selected(GTPU_UDP_PORT))
        );
        assert!(!std::format!("{policy:?}").contains("49152"));
    }

    #[test]
    fn classify_rejects_non_v1_and_gtp_prime() {
        // GTPv2 flags.
        assert_eq!(
            classify_gtpu(&[0x48, 0xFF, 0, 0, 0, 0, 0, 1]),
            GtpuClass::NotGtpV1
        );
        // GTPv1 but PT=0 (GTP').
        assert_eq!(
            classify_gtpu(&[0x20, 0xFF, 0, 0, 0, 0, 0, 1]),
            GtpuClass::NotGtpV1
        );
    }

    #[test]
    fn classify_passes_echo_request_as_not_gpdu() {
        assert_eq!(
            classify_gtpu(&[0x32, 0x01, 0, 4, 0, 0, 0, 0]),
            GtpuClass::NotGpdu
        );
    }

    #[test]
    fn classify_gpdu_reports_teid_length_and_option_flags() {
        assert_eq!(
            classify_gtpu(&[0x30, 0xFF, 0x00, 0x3C, 0x10, 0x00, 0x00, 0x01]),
            GtpuClass::Gpdu {
                teid: [0x10, 0x00, 0x00, 0x01],
                length: 60,
                has_opt: false,
                has_ext: false,
            }
        );
        // S flag set: optional block present, no extension walk.
        assert_eq!(
            classify_gtpu(&[0x32, 0xFF, 0x00, 0x40, 0x10, 0x00, 0x00, 0x01]),
            GtpuClass::Gpdu {
                teid: [0x10, 0x00, 0x00, 0x01],
                length: 64,
                has_opt: true,
                has_ext: false,
            }
        );
        // E flag set: optional block present and extension headers follow.
        assert_eq!(
            classify_gtpu(&[0x34, 0xFF, 0x00, 0x40, 0x10, 0x00, 0x00, 0x01]),
            GtpuClass::Gpdu {
                teid: [0x10, 0x00, 0x00, 0x01],
                length: 64,
                has_opt: true,
                has_ext: true,
            }
        );
    }
}
