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
/// Byte length of a downlink PDR map value.
pub const DOWNLINK_PDR_VALUE_LEN: usize = 4;

/// BPF map name: uplink FAR, keyed by UE PAA (IPv4, network order).
pub const MAP_UPLINK_FAR: &str = "GTPU_UPLINK_FAR";
/// BPF map name: downlink PDR, keyed by local S2b-U TEID (network order).
pub const MAP_DOWNLINK_PDR: &str = "GTPU_DOWNLINK_PDR";
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
/// Counter index: uplink IPv4 packets passed through on FAR miss.
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

/// Downlink PDR map value: decapsulation state for one subscriber session.
///
/// Map key: the ePDG-assigned local S2b-U TEID, 4 bytes network order (the
/// TEID exactly as it appears in received G-PDUs).
///
/// Value layout (4 bytes): the UE PAA (inner IPv4 destination), network order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownlinkPdr {
    /// UE PAA the inner packet must be addressed to, network order.
    pub ue_ip: [u8; 4],
}

impl DownlinkPdr {
    /// Encode into the fixed map-value byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; DOWNLINK_PDR_VALUE_LEN] {
        self.ue_ip
    }

    /// Decode from the fixed map-value byte layout.
    #[must_use]
    pub const fn decode(value: &[u8; DOWNLINK_PDR_VALUE_LEN]) -> Self {
        Self { ue_ip: *value }
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
    const ENCAP: u16 = GTPU_ENCAP_LEN as u16;
    if inner_len > u16::MAX - ENCAP {
        return None;
    }
    let outer_total = inner_len + ENCAP;
    let udp_len = inner_len + (UDP_HDR_LEN + GTPU_MANDATORY_HDR_LEN) as u16;

    let mut out = [0_u8; GTPU_ENCAP_LEN];
    // Outer IPv4 header.
    out[0] = 0x45; // version 4, IHL 5
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
        let pdr = DownlinkPdr {
            ue_ip: [10, 45, 0, 2],
        };
        assert_eq!(pdr.encode(), [10, 45, 0, 2]);
        assert_eq!(DownlinkPdr::decode(&pdr.encode()), pdr);
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
