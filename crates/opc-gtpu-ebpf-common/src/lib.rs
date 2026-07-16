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
/// Byte length of a marked-bearer owner journal value.
pub const MARKED_BEARER_OWNER_VALUE_LEN: usize = 20;
/// Byte length of an optional uplink DSCP map value.
pub const UPLINK_DSCP_VALUE_LEN: usize = 1;

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
/// Current schema marker proving that every per-bearer-mark map was adopted.
///
/// The marker replaces [`UPLINK_DSCP_SCHEMA_MARKER_VALUE`] only after every
/// additive marked map has been opened, every named pin has been verified as
/// the exact map held by the loader, and both current v2 tc hooks have been
/// attached and read back by program ID. A loader that observes this value
/// fails closed when any required map pin is missing. On restart, exact or
/// absent hooks are reconciled; a foreign occupant blocks adoption.
pub const UPLINK_BEARER_SCHEMA_MARKER_VALUE: [u8; UPLINK_FAR_VALUE_LEN] = *b"OPC-MARK-v2\0";

/// BPF map name: uplink FAR, keyed by UE PAA (IPv4, network order).
pub const MAP_UPLINK_FAR: &str = "GTPU_UPLINK_FAR";
/// BPF map name: marked uplink FAR, keyed by `(UE PAA, packet mark)`.
pub const MAP_UPLINK_MARK_FAR: &str = "GTPU_ULM_FAR";
/// BPF map name: downlink PDR, keyed by local S2b-U TEID (network order).
pub const MAP_DOWNLINK_PDR: &str = "GTPU_DOWNLINK_PDR";
/// BPF map name: marked downlink PDR, keyed by local S2b-U TEID.
pub const MAP_DOWNLINK_MARK_PDR: &str = "GTPU_DLM_PDR";
/// BPF map name: optional uplink DSCP, keyed by UE PAA.
pub const MAP_UPLINK_DSCP: &str = "GTPU_UPLINK_DSCP";
/// BPF map name: optional uplink DSCP, keyed by `(UE PAA, packet mark)`.
pub const MAP_UPLINK_MARK_DSCP: &str = "GTPU_ULM_DSCP";
/// BPF map name: marked-bearer owner journal, keyed by `(UE PAA, mark)`.
pub const MAP_MARKED_BEARER_OWNER: &str = "GTPU_M_OWNER";
/// BPF map name: per-CPU datapath counters.
pub const MAP_COUNTERS: &str = "GTPU_COUNTERS";
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
/// TEID, complete uplink FAR and requested DSCP before any forwarding map is
/// published, allowing exact crash retry and conflict rejection in O(1).
///
/// Layout: local TEID (4), encoded [`UplinkFar`] (12), DSCP (`0xff` = absent,
/// otherwise 0..63), format version (`1`), [`MarkedBearerOwnerPhase`], and one
/// zero reserved byte.
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
    format_valid: bool,
}

impl core::fmt::Debug for MarkedBearerOwner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MarkedBearerOwner")
            .field("local_teid", &"<redacted>")
            .field("uplink_far", &"<redacted>")
            .field("egress_dscp", &self.egress_dscp())
            .field("phase", &self.phase)
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
    pub fn authorizes_downlink(&self, local_teid: [u8; 4]) -> bool {
        self.is_valid()
            && matches!(self.phase, MarkedBearerOwnerPhase::Active)
            && self.local_teid == local_teid
    }

    /// Encode into the fixed journal-value layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; MARKED_BEARER_OWNER_VALUE_LEN] {
        let far = self.uplink_far.encode();
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
            1,
            self.phase as u8,
            0,
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
            format_valid: value[17] == 1 && phase_valid && value[19] == 0,
        }
    }
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
    const ENCAP: u16 = GTPU_ENCAP_LEN as u16;
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
    out[20..22].copy_from_slice(&GTPU_UDP_PORT.to_be_bytes());
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

    #[test]
    fn marked_map_names_are_unique_within_kernel_visible_limit() {
        const BPF_OBJ_NAME_VISIBLE_LEN: usize = 15;
        let new_names = [
            MAP_UPLINK_MARK_FAR,
            MAP_UPLINK_MARK_DSCP,
            MAP_DOWNLINK_MARK_PDR,
            MAP_MARKED_BEARER_OWNER,
        ];
        for name in new_names {
            assert!(name.len() <= BPF_OBJ_NAME_VISIBLE_LEN);
        }
        let all_names = [
            MAP_UPLINK_FAR,
            MAP_UPLINK_MARK_FAR,
            MAP_UPLINK_DSCP,
            MAP_UPLINK_MARK_DSCP,
            MAP_DOWNLINK_PDR,
            MAP_DOWNLINK_MARK_PDR,
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
            phase,
        )
    }

    #[test]
    fn marked_owner_round_trips_exact_layout_and_redacts_identifiers() {
        let owner = canonical_owner(MarkedBearerOwnerPhase::Active);
        let encoded = owner.encode();
        assert_eq!(
            encoded,
            [0x10, 0, 0, 1, 192, 0, 2, 10, 192, 0, 2, 1, 0x20, 0, 0, 1, 46, 1, 2, 0,]
        );
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
            (17, 2),  // version
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
            assert!(!owner.authorizes_downlink(0x1000_0001_u32.to_be_bytes()));
        }
        let active = canonical_owner(MarkedBearerOwnerPhase::Active);
        assert!(active.authorizes_uplink(&far, 46));
        assert!(active.authorizes_downlink(0x1000_0001_u32.to_be_bytes()));
        assert!(!active.authorizes_uplink(&far, 0xff));
        assert!(!active.authorizes_uplink(&far, 47));
        let mut other_far = far;
        other_far.o_teid = 0x2000_0002_u32.to_be_bytes();
        assert!(!active.authorizes_uplink(&other_far, 46));
        assert!(!active.authorizes_downlink(0x1000_0002_u32.to_be_bytes()));
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
