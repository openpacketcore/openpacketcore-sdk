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
mod fragment;
mod pmtu;
mod session;

pub use envelope::{
    classify_ipv6_extension_step, classify_ipv6_gtpu_ingress, classify_udp_checksum,
    internet_checksum, internet_checksum_sum_is_valid, udp_ipv4_checksum,
    udp_ipv4_checksum_is_valid, udp_ipv6_checksum, udp_ipv6_checksum_is_valid,
    udp_ipv6_checksum_segments, validate_ipv6_options_header, validate_ipv6_routing_header,
    GtpuEnvelopeBounds, GtpuEnvelopeError, Ipv4EnvelopeBounds, Ipv6ExtensionError,
    Ipv6ExtensionStep, Ipv6GtpuIngress, Ipv6UdpEnvelopeBounds, UdpChecksumDisposition,
    UdpChecksumEvidence, UdpEnvelopeBounds, IPV4_MAX_HDR_LEN, IPV6_MAX_EXT_HEADERS,
    IPV6_MAX_OPTIONS_PER_HEADER, IPV6_NH_AUTHENTICATION, IPV6_NH_DESTINATION_OPTIONS, IPV6_NH_ESP,
    IPV6_NH_FRAGMENT, IPV6_NH_HOP_BY_HOP, IPV6_NH_NONE, IPV6_NH_ROUTING, IPV6_NH_UDP,
};
pub use fragment::{
    parse_gtpu_tpdu, GtpuDownlinkFragmentContract, GtpuReassemblyBounds, GtpuTpdu, GtpuTpduError,
    LINUX_DEFAULT_REASSEMBLY_BOUNDS, MAX_REASSEMBLED_GTPU_LEN,
};
pub use pmtu::{
    apply_uplink_mtu_policy, decide_uplink_encap, decide_uplink_pmtu, encap_overhead,
    stamp_ipv4_dont_fragment, GtpuOuterFragmentPolicy, GtpuPmtuProtocol, GtpuPmtuSignal,
    GtpuUplinkMtuPolicy, UplinkEncapOutcome, UplinkMtuMapState, UplinkPmtuDecision,
    ICMPV4_CODE_FRAGMENTATION_NEEDED_DF_SET, ICMPV4_TYPE_DESTINATION_UNREACHABLE,
    ICMPV6_TYPE_PACKET_TOO_BIG, MIN_UPLINK_LINK_MTU, UPLINK_PMTU_FLAG_OUTER_FRAGMENT_REQUIRED,
    UPLINK_PMTU_VALUE_LEN,
};
pub use session::{
    gtpu_session_group_authorizes_downlink, gtpu_session_group_authorizes_uplink,
    select_gtpu_session_entry_wire, GtpuSessionAuthorityHeader, GtpuSessionDeviceConfig,
    GtpuSessionDeviceId, GtpuSessionDownlinkKey, GtpuSessionEntry, GtpuSessionEntryWireView,
    GtpuSessionGeneration, GtpuSessionGroupId, GtpuSessionGroupPhase, GtpuSessionGroupRecord,
    GtpuSessionGroupRef, GtpuSessionIndexCandidate, GtpuSessionIpFamily, GtpuSessionPaa,
    GtpuSessionTransactionId, GtpuSessionTransactionPhase, GtpuSessionTransactionRecord,
    GtpuSessionUplinkKey, GTPU_SESSION_CONFIG_VALUE_LEN, GTPU_SESSION_DOWNLINK_KEY_LEN,
    GTPU_SESSION_ENTRY_LEN, GTPU_SESSION_GROUP_ID_LEN, GTPU_SESSION_GROUP_REF_LEN,
    GTPU_SESSION_GROUP_VALUE_LEN, GTPU_SESSION_IPV4_SLOT, GTPU_SESSION_IPV6_SLOT,
    GTPU_SESSION_TRANSACTION_VALUE_LEN, GTPU_SESSION_UPLINK_KEY_LEN,
};

/// GTP-U UDP port (TS 29.281 §4.4.2).
pub const GTPU_UDP_PORT: u16 = 2152;

/// Ethernet header length on the attach interface.
pub const ETH_HDR_LEN: usize = 14;
/// EtherType for IPv4.
pub const ETH_P_IPV4: u16 = 0x0800;
/// EtherType for IPv6.
pub const ETH_P_IPV6: u16 = 0x86dd;
/// Minimum (option-free) IPv4 header length.
pub const IPV4_MIN_HDR_LEN: usize = 20;
/// Fixed IPv6 base-header length.
pub const IPV6_HDR_LEN: usize = 40;
/// UDP header length.
pub const UDP_HDR_LEN: usize = 8;
/// Mandatory GTPv1-U header length (flags, type, length, TEID).
pub const GTPU_MANDATORY_HDR_LEN: usize = 8;
/// Optional GTPv1-U field block length (sequence, N-PDU, next-ext type),
/// present when any of the S/PN/E flags is set.
pub const GTPU_OPT_LEN: usize = 4;
/// Total uplink encapsulation prepended per packet: outer IPv4 + UDP + GTP-U.
pub const GTPU_ENCAP_LEN: usize = IPV4_MIN_HDR_LEN + UDP_HDR_LEN + GTPU_MANDATORY_HDR_LEN;
/// Explicit IPv4 alias for the legacy encapsulation size.
pub const GTPU_IPV4_ENCAP_LEN: usize = GTPU_ENCAP_LEN;
/// Total uplink encapsulation prepended for an outer IPv6/UDP/GTP-U packet.
pub const GTPU_IPV6_ENCAP_LEN: usize = IPV6_HDR_LEN + UDP_HDR_LEN + GTPU_MANDATORY_HDR_LEN;
/// Largest supported fixed outer encapsulation.
pub const GTPU_MAX_ENCAP_LEN: usize = GTPU_IPV6_ENCAP_LEN;

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

/// Pack the verifier-split downlink parser result passed between eBPF frames.
///
/// The high word carries the original IPv4 Total Length rather than the
/// absolute Ethernet-frame end. IPv4 permits a Total Length of 65,535 bytes,
/// whose frame end is 65,549 after the Ethernet header is included and cannot
/// be represented by a `u16`. The caller reconstructs that end with
/// [`downlink_frame_end`] only after returning to the classifier entry frame.
#[must_use]
#[inline(always)]
pub const fn pack_downlink_parse_result(
    ipv4_total_length: u16,
    payload_offset: u16,
    teid: [u8; 4],
) -> u64 {
    ((ipv4_total_length as u64) << 48)
        | ((payload_offset as u64) << 32)
        | (u32::from_be_bytes(teid) as u64)
}

/// Unpack the original IPv4 Total Length from a downlink parser result.
#[must_use]
#[inline(always)]
pub const fn downlink_parse_ipv4_total_length(parsed: u64) -> u16 {
    (parsed >> 48) as u16
}

/// Unpack the absolute inner-payload offset from a downlink parser result.
#[must_use]
#[inline(always)]
pub const fn downlink_parse_payload_offset(parsed: u64) -> u16 {
    ((parsed >> 32) & (u16::MAX as u64)) as u16
}

/// Unpack the network-order TEID from a downlink parser result.
#[must_use]
#[inline(always)]
pub const fn downlink_parse_teid(parsed: u64) -> [u8; 4] {
    (parsed as u32).to_be_bytes()
}

/// Reconstruct the exclusive Ethernet-frame end from IPv4 Total Length.
///
/// The checked addition is intentionally shared by host tests and the eBPF
/// classifier entry frame so the maximum IPv4 packet cannot be truncated at
/// the parser's compact return boundary.
#[must_use]
#[inline(always)]
pub const fn downlink_frame_end(ipv4_total_length: u16) -> Option<u32> {
    (ipv4_total_length as u32).checked_add(ETH_HDR_LEN as u32)
}

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
/// Byte length of one encoded uplink UDP source-port policy.
pub const UPLINK_SOURCE_PORT_POLICY_LEN: usize = 2;
/// Byte length of one durable PDP-context commit record stored in an uplink
/// source-port map.
///
/// The record extends the existing 64-byte marked-owner journal with the
/// canonical two-byte source-port policy and two reserved bytes. Keeping the
/// complete FAR, binding, DSCP, local TEID, phase, and source-port policy in
/// one atomically replaced value gives both tc directions one coherent commit
/// authority.
pub const UPLINK_SOURCE_PORT_VALUE_LEN: usize = 68;

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
/// contain one complete PDP-context commit record for every default and marked
/// bearer and are available to both exact current tc programs.
///
/// The v3-to-v4 migration is additive, but not absence-based: before the v4
/// program is attached or this marker is committed, userspace materializes an
/// `Active` complete-graph commit carrying explicit legacy 2152 for every
/// retained v3 bearer. A committed v4 pin set therefore treats a missing or
/// inconsistent record as corrupt state and drops rather than silently
/// changing policy. A live previous-generation (v3 object) tc
/// hook does not match the current artifact and fails closed without
/// mutation; it must be detached by its owning loader before adoption,
/// exactly like the pre-v1 object generations. A loader that observes this
/// value fails closed when either source-port map pin or any bearer's complete
/// commit record is missing or inconsistent with its live graph.
pub const UPLINK_SOURCE_PORT_SCHEMA_MARKER_VALUE: [u8; UPLINK_FAR_VALUE_LEN] = *b"OPC-SPORT-v4";
/// Current v5 schema marker proving that the additive uplink MTU policy maps
/// are pinned and available to the exact current uplink program.
///
/// The v4-to-v5 migration is purely additive: the single-slot policy map
/// starts zeroed (the explicit unset state selecting the legacy
/// total-length-only behavior) and the drop-counter map starts empty, so a
/// committed v4 pin set upgrades in place by creating the maps, verifying
/// the complete pin graph, attaching the exact current hooks, and committing
/// this marker. A loader that observes this value fails closed when either
/// MTU map pin is missing.
pub const UPLINK_PMTU_SCHEMA_MARKER_VALUE: [u8; UPLINK_FAR_VALUE_LEN] = *b"OPC-PMTU-v5\0";

/// Byte width of the independent family-tagged grouped-session schema marker.
pub const GTPU_SESSION_SCHEMA_MARKER_LEN: usize = 16;
/// Marker for the additive family-tagged grouped-session ABI.
///
/// This marker lives in the new schema map and never occupies or reinterprets
/// a legacy four-byte IPv4 selector.
pub const GTPU_SESSION_SCHEMA_MARKER_VALUE: [u8; GTPU_SESSION_SCHEMA_MARKER_LEN] =
    *b"OPC-GROUP-IP-v6\0";
/// Single-slot key for [`MAP_CONFIG_IPV6`].
pub const GTPU_SESSION_CONFIG_KEY: u32 = 0;

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
/// BPF map name: default PDP-context commit record, keyed by UE PAA.
pub const MAP_UPLINK_SOURCE_PORT: &str = "GTPU_UL_SPORT";
/// BPF map name: marked PDP-context commit record, keyed by
/// `(UE PAA, packet mark)`.
pub const MAP_UPLINK_MARK_SOURCE_PORT: &str = "GTPU_ULM_SPORT";
/// BPF map name: single-slot uplink MTU policy (effective link MTU and
/// outer-fragmentation flags).
pub const MAP_UPLINK_PMTU: &str = "GTPU_PMTU_CFG";
/// BPF map name: per-CPU counter of uplink packets rejected fail closed by
/// the MTU policy.
pub const MAP_UPLINK_PMTU_COUNTERS: &str = "GTPU_PMTU_DROP";
/// BPF map name: marked-bearer owner journal, keyed by `(UE PAA, mark)`.
pub const MAP_MARKED_BEARER_OWNER: &str = "GTPU_M_OWNER";
/// BPF map name: per-CPU datapath counters.
pub const MAP_COUNTERS: &str = "GTPU_COUNTERS";
/// BPF map name: fixed-cardinality downlink binding-drop counters.
pub const MAP_DOWNLINK_BINDING_COUNTERS: &str = "GTPU_DL_DROP";
/// BPF map name: single-slot device configuration (local S2b-U IPv4).
pub const MAP_CONFIG: &str = "GTPU_CONFIG";
/// BPF map name: family-tagged grouped-session authority.
///
/// This map must be a normal, non-per-CPU `BPF_MAP_TYPE_HASH`. Activation and
/// fencing are whole-value `BPF_MAP_UPDATE_ELEM` replacements; array,
/// per-CPU, and in-place mutation cannot implement the snapshot contract.
pub const MAP_SESSION_GROUPS: &str = "GTPU_SESSIONS";
/// BPF map name: family-tagged grouped uplink selector index.
pub const MAP_SESSION_UPLINK_INDEX: &str = "GTPU_UL_INDEX";
/// BPF map name: family-tagged grouped downlink selector index.
pub const MAP_SESSION_DOWNLINK_INDEX: &str = "GTPU_DL_INDEX";
/// BPF map name: durable userspace-only grouped-session transaction journal.
pub const MAP_SESSION_TRANSACTIONS: &str = "GTPU_SESS_TXN";
/// BPF map name: managed IPv6 local-endpoint/device configuration.
pub const MAP_CONFIG_IPV6: &str = "GTPU_CONFIG6";
/// BPF map name: independent grouped-session schema marker.
pub const MAP_SESSION_SCHEMA: &str = "GTPU_SCHEMA6";

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

/// MTU-drop counter index: uplink packets rejected fail closed because the
/// encapsulated packet exceeded the configured effective link MTU.
pub const COUNTER_UL_MTU_REJECT: u32 = 0;
/// MTU-drop counter index: uplink packets dropped because the persisted MTU
/// policy bytes were corrupt. This is a canary for external writers: a
/// nonzero value always means non-SDK mutation of adopted state.
pub const COUNTER_UL_PMTU_CORRUPT: u32 = 1;
/// Number of uplink MTU-drop counters.
pub const UPLINK_PMTU_COUNTER_SLOTS: u32 = 2;

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
/// The semantic model supports both address families. The legacy v5 tc schema
/// remains IPv4-only; the additive grouped v6 schema uses this type but does
/// not claim production availability until its separately reported
/// qualification contract is proven. Address bytes are network ordered and
/// redacted from `Debug` output.
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
/// Every policy, including the legacy policy, is persisted as the two-byte
/// source-port field of an additive per-context [`PdpContextCommit`]. The
/// legacy policy is encoded as the explicit big-endian value 2152. Port zero
/// is reserved (RFC 768), and the service port 2152 has the single canonical
/// meaning `LegacyServicePort`; callers that need that wire value use the
/// legacy variant rather than constructing a redundant `Selected(2152)`.
/// Invalid values are rejected at every construction and decode boundary,
/// while commit-record absence is corrupt committed-v4 state and is handled
/// fail closed by the host and tc boundaries.
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
    /// Construct a per-context selected-port policy.
    ///
    /// The reserved port zero and the canonical legacy service port 2152 fail
    /// closed with `None`. Use [`Self::LegacyServicePort`] for fixed 2152.
    #[must_use]
    pub const fn selected(port: u16) -> Option<Self> {
        if port == 0 || port == GTPU_UDP_PORT {
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

    /// Return the explicit two-byte commit-record field for this policy.
    ///
    /// Both variants are stored big endian. `None` is reserved for an enum
    /// value constructed outside the checked constructor with either port
    /// zero or the non-canonical `Selected(2152)` representation.
    #[must_use]
    pub const fn map_value(self) -> Option<[u8; UPLINK_SOURCE_PORT_POLICY_LEN]> {
        match self {
            Self::LegacyServicePort => Some(GTPU_UDP_PORT.to_be_bytes()),
            Self::Selected(port) if port != 0 && port != GTPU_UDP_PORT => Some(port.to_be_bytes()),
            Self::Selected(_) => None,
        }
    }

    /// Decode an explicit two-byte commit-record field into its canonical policy.
    /// A reserved zero port is corrupt adopted state and fails closed with
    /// `None`; the service-port value decodes as the explicit legacy policy.
    #[must_use]
    pub const fn from_map_value(value: [u8; UPLINK_SOURCE_PORT_POLICY_LEN]) -> Option<Self> {
        let port = u16::from_be_bytes(value);
        if port == GTPU_UDP_PORT {
            Some(Self::LegacyServicePort)
        } else {
            Self::selected(port)
        }
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
fn wire_u16<const N: usize>(value: &[u8; N], offset: usize) -> u16 {
    (u16::from(value[offset]) << 8) | u16::from(value[offset + 1])
}

#[inline(always)]
fn wire_u32<const N: usize>(value: &[u8; N], offset: usize) -> u32 {
    (u32::from(value[offset]) << 24)
        | (u32::from(value[offset + 1]) << 16)
        | (u32::from(value[offset + 2]) << 8)
        | u32::from(value[offset + 3])
}

#[inline(always)]
fn wire_ipv6_is_nonzero<const N: usize>(value: &[u8; N], offset: usize) -> bool {
    if wire_u32(value, offset) != 0 {
        return true;
    }
    if wire_u32(value, offset + 4) != 0 {
        return true;
    }
    if wire_u32(value, offset + 8) != 0 {
        return true;
    }
    wire_u32(value, offset + 12) != 0
}

#[inline(always)]
fn wire_ipv4_tail_is_zero<const N: usize>(value: &[u8; N], offset: usize) -> bool {
    if wire_u32(value, offset) != 0 {
        return false;
    }
    if wire_u32(value, offset + 4) != 0 {
        return false;
    }
    wire_u32(value, offset + 8) == 0
}

#[inline(always)]
fn binding_policy_wire_is_valid<const N: usize>(value: &[u8; N], base: usize) -> bool {
    let first = wire_u16(value, base + 40);
    let last = wire_u16(value, base + 42);
    match value[base + 2] {
        0 => first == 0 && last == 0,
        1 => first == last,
        2 => first < last,
        _ => false,
    }
}

#[inline(always)]
fn binding_ipv4_wire_is_valid<const N: usize>(value: &[u8; N], base: usize) -> bool {
    if value[base] != 1 || value[base + 1] != 4 || value[base + 3] != 0 {
        return false;
    }
    if wire_u32(value, base + 4) == 0 || wire_u32(value, base + 20) == 0 {
        return false;
    }
    if !wire_ipv4_tail_is_zero(value, base + 8) || !wire_ipv4_tail_is_zero(value, base + 24) {
        return false;
    }
    if wire_u32(value, base + 36) == 0 {
        return false;
    }
    binding_policy_wire_is_valid(value, base)
}

#[inline(always)]
fn binding_wire_is_valid<const N: usize>(value: &[u8; N], base: usize) -> bool {
    if value[base] != 1 || value[base + 3] != 0 || wire_u32(value, base + 36) == 0 {
        return false;
    }
    let family_valid = match value[base + 1] {
        4 => {
            wire_u32(value, base + 4) != 0
                && wire_u32(value, base + 20) != 0
                && wire_ipv4_tail_is_zero(value, base + 8)
                && wire_ipv4_tail_is_zero(value, base + 24)
        }
        6 => wire_ipv6_is_nonzero(value, base + 4) && wire_ipv6_is_nonzero(value, base + 20),
        _ => false,
    };
    family_valid && binding_policy_wire_is_valid(value, base)
}

#[inline(always)]
fn binding_wires_equal<const N: usize>(
    value: &[u8; N],
    base: usize,
    binding: &[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
) -> bool {
    if wire_u32(value, base) != wire_u32(binding, 0) {
        return false;
    }
    if wire_u32(value, base + 4) != wire_u32(binding, 4) {
        return false;
    }
    if wire_u32(value, base + 8) != wire_u32(binding, 8) {
        return false;
    }
    if wire_u32(value, base + 12) != wire_u32(binding, 12) {
        return false;
    }
    if wire_u32(value, base + 16) != wire_u32(binding, 16) {
        return false;
    }
    if wire_u32(value, base + 20) != wire_u32(binding, 20) {
        return false;
    }
    if wire_u32(value, base + 24) != wire_u32(binding, 24) {
        return false;
    }
    if wire_u32(value, base + 28) != wire_u32(binding, 28) {
        return false;
    }
    if wire_u32(value, base + 32) != wire_u32(binding, 32) {
        return false;
    }
    if wire_u32(value, base + 36) != wire_u32(binding, 36) {
        return false;
    }
    wire_u32(value, base + 40) == wire_u32(binding, 40)
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
    if wire_u32(&peer_address, 0) != wire_u32(value, 4) {
        return Err(DownlinkBindingMismatch::PeerAddress);
    }
    if wire_u32(&local_address, 0) != wire_u32(value, 20) {
        return Err(DownlinkBindingMismatch::LocalAddress);
    }
    if ingress_ifindex != wire_u32(value, 36) {
        return Err(DownlinkBindingMismatch::IngressAttachment);
    }
    let first = wire_u16(value, 40);
    let last = wire_u16(value, 42);
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

/// Durable commit authority for one complete PDP-context map graph.
///
/// The default and marked source-port maps store this value rather than a
/// standalone port. A `Pending` or `Removing` record gates both tc directions
/// fail closed while userspace mutates the component maps. `Active` is
/// published last and authorizes traffic only when the live FAR, DSCP, local
/// TEID, and endpoint binding match this same record exactly.
///
/// The first 64 bytes intentionally reuse the canonical
/// [`MarkedBearerOwner`] encoding. Bytes 64..66 contain the explicit big-endian
/// source port (including legacy 2152); bytes 66..68 are reserved zero. This is
/// an additive v4-map ABI: pre-v4 pin sets have no source-port maps and are
/// materialized from their already validated graph before v4 is committed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PdpContextCommit {
    owner: MarkedBearerOwner,
    uplink_source_port_policy: GtpuUplinkSourcePortPolicy,
    format_valid: bool,
}

impl core::fmt::Debug for PdpContextCommit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PdpContextCommit")
            .field("local_teid", &"<redacted>")
            .field("uplink_far", &"<redacted>")
            .field("egress_dscp", &self.egress_dscp())
            .field("phase", &self.phase())
            .field("downlink_binding", &"<redacted>")
            .field("uplink_source_port_policy", &"<redacted>")
            .field("format_valid", &self.format_valid)
            .finish()
    }
}

impl PdpContextCommit {
    /// Construct a canonical complete-graph commit record.
    #[must_use]
    pub fn new(
        local_teid: [u8; 4],
        uplink_far: UplinkFar,
        egress_dscp: Option<u8>,
        downlink_binding: DownlinkEndpointBinding,
        uplink_source_port_policy: GtpuUplinkSourcePortPolicy,
        phase: MarkedBearerOwnerPhase,
    ) -> Option<Self> {
        uplink_source_port_policy.map_value()?;
        let value = Self {
            owner: MarkedBearerOwner::new(
                local_teid,
                uplink_far,
                egress_dscp,
                downlink_binding,
                phase,
            ),
            uplink_source_port_policy,
            format_valid: true,
        };
        value.is_valid().then_some(value)
    }

    /// Return this record with a different durable transaction phase.
    #[must_use]
    pub fn with_phase(self, phase: MarkedBearerOwnerPhase) -> Self {
        let format_valid = self.is_valid();
        Self {
            owner: MarkedBearerOwner::new(
                self.owner.local_teid,
                self.owner.uplink_far,
                self.owner.egress_dscp(),
                self.owner.downlink_binding,
                phase,
            ),
            uplink_source_port_policy: self.uplink_source_port_policy,
            // A phase transition must never normalize malformed decoded
            // state into a record that can later become authoritative.
            format_valid,
        }
    }

    /// Return the local/downlink TEID owned by this transaction.
    #[must_use]
    pub const fn local_teid(self) -> [u8; 4] {
        self.owner.local_teid
    }

    /// Return the complete uplink FAR owned by this transaction.
    #[must_use]
    pub const fn uplink_far(self) -> UplinkFar {
        self.owner.uplink_far
    }

    /// Return the optional fixed uplink DSCP.
    #[must_use]
    pub fn egress_dscp(&self) -> Option<u8> {
        self.owner.egress_dscp()
    }

    /// Return the canonical DSCP wire byte (`0xff` means absent).
    #[must_use]
    pub const fn egress_dscp_wire(&self) -> u8 {
        self.owner.egress_dscp_wire()
    }

    /// Return the exact downlink endpoint binding owned by this transaction.
    #[must_use]
    pub const fn downlink_binding(self) -> DownlinkEndpointBinding {
        self.owner.downlink_binding
    }

    /// Return the explicit uplink source-port policy.
    #[must_use]
    pub const fn uplink_source_port_policy(self) -> GtpuUplinkSourcePortPolicy {
        self.uplink_source_port_policy
    }

    /// Return the durable transaction phase.
    #[must_use]
    pub const fn phase(self) -> MarkedBearerOwnerPhase {
        self.owner.phase
    }

    /// Return the corresponding marked-bearer owner journal value.
    #[must_use]
    pub const fn marked_owner(self) -> MarkedBearerOwner {
        self.owner
    }

    /// Return whether every field and reserved byte is canonical.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.format_valid
            && self.owner.is_valid()
            && self.uplink_source_port_policy.map_value().is_some()
    }

    /// Return whether this Active record matches a complete live default graph.
    #[must_use]
    pub fn authorizes_graph(
        &self,
        local_teid: [u8; 4],
        far: &UplinkFar,
        dscp: Option<u8>,
        binding: &DownlinkEndpointBinding,
    ) -> bool {
        self.is_valid()
            && self.phase() == MarkedBearerOwnerPhase::Active
            && self.local_teid() == local_teid
            && self.uplink_far() == *far
            && self.egress_dscp() == dscp
            && self.downlink_binding() == *binding
    }

    /// Encode into the fixed durable commit-record layout.
    #[must_use]
    pub const fn encode(self) -> [u8; UPLINK_SOURCE_PORT_VALUE_LEN] {
        let owner = self.owner.encode();
        let policy = match self.uplink_source_port_policy.map_value() {
            Some(value) => value,
            None => [0; UPLINK_SOURCE_PORT_POLICY_LEN],
        };
        let mut encoded = [0_u8; UPLINK_SOURCE_PORT_VALUE_LEN];
        let mut index = 0;
        while index < MARKED_BEARER_OWNER_VALUE_LEN {
            encoded[index] = owner[index];
            index += 1;
        }
        encoded[64] = policy[0];
        encoded[65] = policy[1];
        encoded
    }

    /// Decode a durable record while retaining canonical-format evidence.
    #[must_use]
    pub const fn decode(value: &[u8; UPLINK_SOURCE_PORT_VALUE_LEN]) -> Self {
        let mut owner = [0_u8; MARKED_BEARER_OWNER_VALUE_LEN];
        let mut index = 0;
        while index < MARKED_BEARER_OWNER_VALUE_LEN {
            owner[index] = value[index];
            index += 1;
        }
        let (uplink_source_port_policy, policy_valid) =
            match GtpuUplinkSourcePortPolicy::from_map_value([value[64], value[65]]) {
                Some(policy) => (policy, true),
                None => (GtpuUplinkSourcePortPolicy::LegacyServicePort, false),
            };
        Self {
            owner: MarkedBearerOwner::decode(&owner),
            uplink_source_port_policy,
            format_valid: policy_valid && value[66] == 0 && value[67] == 0,
        }
    }
}

#[inline(always)]
fn bearer_owner_ipv4_wire_is_valid<const N: usize>(value: &[u8; N]) -> bool {
    if value[17] != 2 || !matches!(value[18], 1..=3) || value[19] != 0 {
        return false;
    }
    if wire_u32(value, 0) == 0
        || wire_u32(value, 4) == 0
        || wire_u32(value, 8) == 0
        || wire_u32(value, 12) == 0
    {
        return false;
    }
    if value[16] > 63 && value[16] != 0xff {
        return false;
    }
    if !binding_ipv4_wire_is_valid(value, 20) {
        return false;
    }
    if wire_u32(value, 4) != wire_u32(value, 24) {
        return false;
    }
    wire_u32(value, 8) == wire_u32(value, 40)
}

#[inline(never)]
fn pdp_commit_wire_is_valid(value: &[u8; UPLINK_SOURCE_PORT_VALUE_LEN]) -> bool {
    if !bearer_owner_ipv4_wire_is_valid(value) {
        return false;
    }
    wire_u16(value, 64) != 0 && value[66] == 0 && value[67] == 0
}

/// Return the committed UDP source port when an encoded Active record
/// authorizes the exact live uplink FAR and DSCP state.
///
/// `None` means the record is malformed, transitional, or inconsistent and
/// the tc program must drop fail closed.
#[must_use]
pub fn pdp_commit_wire_authorized_source_port(
    value: &[u8; UPLINK_SOURCE_PORT_VALUE_LEN],
    far: &UplinkFar,
    dscp_wire: u8,
) -> Option<u16> {
    if !pdp_commit_wire_is_valid(value)
        || value[18] != MarkedBearerOwnerPhase::Active as u8
        || wire_u32(value, 4) != wire_u32(&far.peer_ip, 0)
        || wire_u32(value, 8) != wire_u32(&far.local_ip, 0)
        || wire_u32(value, 12) != wire_u32(&far.o_teid, 0)
        || value[16] != dscp_wire
    {
        return None;
    }
    Some(wire_u16(value, 64))
}

/// Return whether an encoded Active record authorizes the exact local TEID and
/// downlink endpoint binding.
#[must_use]
#[inline(never)]
pub fn pdp_commit_wire_authorizes_downlink(
    value: &[u8; UPLINK_SOURCE_PORT_VALUE_LEN],
    local_teid: [u8; 4],
    binding: &[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
) -> bool {
    pdp_commit_wire_is_valid(value)
        && value[18] == MarkedBearerOwnerPhase::Active as u8
        && wire_u32(value, 0) == wire_u32(&local_teid, 0)
        && binding_wires_equal(value, 20, binding)
}

/// Return whether an encoded Active record authorizes the complete live graph
/// observed by either tc direction.
///
/// This combines the exact FAR/DSCP check used for uplink encapsulation with
/// the exact local-TEID/binding check used before downlink decapsulation. It
/// prevents either hook from accepting one half of a crash-mixed graph.
#[must_use]
#[inline(never)]
pub fn pdp_commit_wire_authorizes_graph(
    value: &[u8; UPLINK_SOURCE_PORT_VALUE_LEN],
    local_teid: [u8; 4],
    far: &UplinkFar,
    dscp_wire: u8,
    binding: &[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
) -> bool {
    if !pdp_commit_wire_is_valid(value) || value[18] != MarkedBearerOwnerPhase::Active as u8 {
        return false;
    }
    if wire_u32(value, 0) != wire_u32(&local_teid, 0) {
        return false;
    }
    if wire_u32(value, 4) != wire_u32(&far.peer_ip, 0) {
        return false;
    }
    if wire_u32(value, 8) != wire_u32(&far.local_ip, 0) {
        return false;
    }
    if wire_u32(value, 12) != wire_u32(&far.o_teid, 0) || value[16] != dscp_wire {
        return false;
    }
    binding_wires_equal(value, 20, binding)
}

#[inline(always)]
fn marked_owner_wire_is_valid(value: &[u8; MARKED_BEARER_OWNER_VALUE_LEN]) -> bool {
    bearer_owner_ipv4_wire_is_valid(value)
}

/// Return whether an encoded owner journal authorizes exact marked uplink
/// state without materializing the 64-byte typed journal.
///
/// This is the allocation-free eBPF equivalent of
/// [`MarkedBearerOwner::decode`] followed by
/// [`MarkedBearerOwner::authorizes_uplink`].
#[must_use]
#[inline(never)]
pub fn marked_owner_wire_authorizes_uplink(
    value: &[u8; MARKED_BEARER_OWNER_VALUE_LEN],
    far: &UplinkFar,
    dscp_wire: u8,
) -> bool {
    if !marked_owner_wire_is_valid(value) || value[18] != MarkedBearerOwnerPhase::Active as u8 {
        return false;
    }
    if wire_u32(value, 4) != wire_u32(&far.peer_ip, 0) {
        return false;
    }
    if wire_u32(value, 8) != wire_u32(&far.local_ip, 0) {
        return false;
    }
    wire_u32(value, 12) == wire_u32(&far.o_teid, 0) && value[16] == dscp_wire
}

/// Return whether an encoded owner journal authorizes the exact local TEID
/// and encoded downlink endpoint binding.
///
/// This is the allocation-free eBPF equivalent of
/// [`MarkedBearerOwner::decode`] followed by
/// [`MarkedBearerOwner::authorizes_downlink`].
#[must_use]
#[inline(never)]
pub fn marked_owner_wire_authorizes_downlink(
    value: &[u8; MARKED_BEARER_OWNER_VALUE_LEN],
    local_teid: [u8; 4],
    binding: &[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
) -> bool {
    if !marked_owner_wire_is_valid(value) || value[18] != MarkedBearerOwnerPhase::Active as u8 {
        return false;
    }
    if wire_u32(value, 0) != wire_u32(&local_teid, 0) {
        return false;
    }
    binding_wires_equal(value, 20, binding)
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
    fn downlink_parse_result_preserves_maximum_ipv4_total_length() {
        let teid = 0x1020_3040_u32.to_be_bytes();
        for total_length in [65_521_u16, 65_522, u16::MAX] {
            let frame_end = downlink_frame_end(total_length).expect("u16 length plus Ethernet");
            let bounds = Ipv4EnvelopeBounds::parse(frame_end as usize, 0x45, total_length)
                .expect("boundary IPv4 envelope");
            let packed = pack_downlink_parse_result(total_length, 4_174, teid);
            assert_eq!(downlink_parse_ipv4_total_length(packed), total_length);
            assert_eq!(downlink_parse_payload_offset(packed), 4_174);
            assert_eq!(downlink_parse_teid(packed), teid);
            assert_eq!(bounds.ip_end(), frame_end as usize);
            assert_eq!(
                downlink_frame_end(downlink_parse_ipv4_total_length(packed)),
                Some(frame_end)
            );
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
            MAP_UPLINK_PMTU,
            MAP_UPLINK_PMTU_COUNTERS,
            MAP_SESSION_GROUPS,
            MAP_SESSION_UPLINK_INDEX,
            MAP_SESSION_DOWNLINK_INDEX,
            MAP_SESSION_TRANSACTIONS,
            MAP_CONFIG_IPV6,
            MAP_SESSION_SCHEMA,
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
            MAP_UPLINK_PMTU,
            MAP_UPLINK_PMTU_COUNTERS,
            MAP_DOWNLINK_PDR,
            MAP_DOWNLINK_MARK_PDR,
            MAP_DOWNLINK_ENDPOINT_BINDING,
            MAP_DOWNLINK_BINDING_COUNTERS,
            MAP_MARKED_BEARER_OWNER,
            MAP_COUNTERS,
            MAP_CONFIG,
            MAP_SESSION_GROUPS,
            MAP_SESSION_UPLINK_INDEX,
            MAP_SESSION_DOWNLINK_INDEX,
            MAP_SESSION_TRANSACTIONS,
            MAP_CONFIG_IPV6,
            MAP_SESSION_SCHEMA,
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

    fn canonical_commit(phase: MarkedBearerOwnerPhase) -> PdpContextCommit {
        let owner = canonical_owner(phase);
        PdpContextCommit::new(
            owner.local_teid,
            owner.uplink_far,
            owner.egress_dscp(),
            owner.downlink_binding,
            GtpuUplinkSourcePortPolicy::selected(40_000).unwrap(),
            phase,
        )
        .unwrap()
    }

    #[test]
    fn pdp_commit_round_trips_explicit_v4_layout_and_redacts_identity() {
        let commit = canonical_commit(MarkedBearerOwnerPhase::Active);
        let encoded = commit.encode();
        assert_eq!(
            &encoded[..MARKED_BEARER_OWNER_VALUE_LEN],
            &commit.marked_owner().encode()
        );
        assert_eq!(&encoded[64..], &[0x9c, 0x40, 0, 0]);
        assert_eq!(PdpContextCommit::decode(&encoded), commit);
        assert!(commit.is_valid());
        let debug = std::format!("{commit:?}");
        for forbidden in ["192", "40000", "268435457", "536870913"] {
            assert!(!debug.contains(forbidden));
        }
    }

    #[test]
    fn active_pdp_commit_authorizes_only_the_exact_complete_graph() {
        let commit = canonical_commit(MarkedBearerOwnerPhase::Active);
        let encoded = commit.encode();
        let owner = commit.marked_owner();
        let binding = owner.downlink_binding.encode();
        assert_eq!(
            pdp_commit_wire_authorized_source_port(&encoded, &owner.uplink_far, 46),
            Some(40_000)
        );
        assert!(pdp_commit_wire_authorizes_downlink(
            &encoded,
            owner.local_teid,
            &binding
        ));
        assert!(pdp_commit_wire_authorizes_graph(
            &encoded,
            owner.local_teid,
            &owner.uplink_far,
            46,
            &binding,
        ));

        let mut wrong_far = owner.uplink_far;
        wrong_far.o_teid = 0x2000_0002_u32.to_be_bytes();
        assert!(!pdp_commit_wire_authorizes_graph(
            &encoded,
            owner.local_teid,
            &wrong_far,
            46,
            &binding,
        ));
        assert!(!pdp_commit_wire_authorizes_graph(
            &encoded,
            owner.local_teid,
            &owner.uplink_far,
            10,
            &binding,
        ));
        let mut wrong_binding = binding;
        wrong_binding[4] ^= 1;
        assert!(!pdp_commit_wire_authorizes_graph(
            &encoded,
            owner.local_teid,
            &owner.uplink_far,
            46,
            &wrong_binding,
        ));
    }

    #[test]
    fn transitional_or_malformed_pdp_commit_gates_both_directions() {
        for phase in [
            MarkedBearerOwnerPhase::Pending,
            MarkedBearerOwnerPhase::Removing,
        ] {
            let commit = canonical_commit(phase);
            let owner = commit.marked_owner();
            let encoded = commit.encode();
            assert!(
                pdp_commit_wire_authorized_source_port(&encoded, &owner.uplink_far, 46).is_none()
            );
            assert!(!pdp_commit_wire_authorizes_downlink(
                &encoded,
                owner.local_teid,
                &owner.downlink_binding.encode(),
            ));
        }

        let commit = canonical_commit(MarkedBearerOwnerPhase::Active);
        let owner = commit.marked_owner();
        let mut malformed = commit.encode();
        malformed[64] = 0;
        malformed[65] = 0;
        assert!(!PdpContextCommit::decode(&malformed).is_valid());
        assert!(!pdp_commit_wire_authorizes_graph(
            &malformed,
            owner.local_teid,
            &owner.uplink_far,
            46,
            &owner.downlink_binding.encode(),
        ));
        for offset in [66, 67] {
            let mut malformed = commit.encode();
            malformed[offset] = 1;
            let decoded = PdpContextCommit::decode(&malformed);
            assert!(!decoded.is_valid());
            assert!(
                !decoded
                    .with_phase(MarkedBearerOwnerPhase::Pending)
                    .is_valid(),
                "a phase change must not canonicalize malformed input"
            );
            assert!(!pdp_commit_wire_authorizes_graph(
                &malformed,
                owner.local_teid,
                &owner.uplink_far,
                46,
                &owner.downlink_binding.encode(),
            ));
        }
        let mut malformed_owner = commit.encode();
        malformed_owner[19] = 1;
        let decoded = PdpContextCommit::decode(&malformed_owner);
        assert!(!decoded.is_valid());
        assert!(
            !decoded
                .with_phase(MarkedBearerOwnerPhase::Removing)
                .is_valid(),
            "a phase change must preserve malformed owner evidence"
        );
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
            Some(GTPU_UDP_PORT.to_be_bytes())
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
        assert!(GtpuUplinkSourcePortPolicy::selected(GTPU_UDP_PORT).is_none());
        assert_eq!(GtpuUplinkSourcePortPolicy::Selected(0).map_value(), None);
        assert_eq!(
            GtpuUplinkSourcePortPolicy::Selected(GTPU_UDP_PORT).map_value(),
            None
        );
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
            Some(GtpuUplinkSourcePortPolicy::LegacyServicePort)
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
