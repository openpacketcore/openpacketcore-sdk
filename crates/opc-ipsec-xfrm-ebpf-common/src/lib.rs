//! Shared layouts for the XFRM post-transform tc eBPF DSCP companion.
//!
//! Linux XFRM can set masked output `skb->mark` bits on an SA but has no UAPI
//! attribute for a fixed outer DSCP. The host backend encodes a presence bit
//! plus a six-bit DSCP into a caller-reserved seven-bit mark window. The tc
//! program validates that token, stamps the outer IPv4/IPv6 DS field while
//! preserving ECN, then clears only its reserved bits.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Number of contiguous skb-mark bits reserved by the companion.
pub const MARK_TOKEN_BITS: u8 = 7;
/// Largest valid starting bit for a seven-bit window in a `u32` mark.
pub const MAX_MARK_SHIFT: u8 = 32 - MARK_TOKEN_BITS;
/// Encoded companion configuration map value length.
pub const MARK_CONFIG_VALUE_LEN: usize = 8;

/// BPF single-slot configuration map name.
pub const MAP_MARK_CONFIG: &str = "XFRM_DSCP_CFG";
/// tc egress classifier program name.
pub const PROG_EGRESS_DSCP: &str = "opc_xfrm_dscp";

/// Ethernet header length at the tc attach point.
pub const ETH_HDR_LEN: usize = 14;
/// IPv4 EtherType.
pub const ETH_P_IPV4: u16 = 0x0800;
/// IPv6 EtherType.
pub const ETH_P_IPV6: u16 = 0x86dd;
/// Minimum IPv4 header length.
pub const IPV4_HEADER_LEN: usize = 20;
/// Fixed IPv6 base-header length.
pub const IPV6_HEADER_LEN: usize = 40;
/// IP protocol number for ESP.
pub const IPPROTO_ESP: u8 = 50;
/// IP protocol number for UDP (ESP-in-UDP/NAT-T).
pub const IPPROTO_UDP: u8 = 17;
/// UDP header length.
pub const UDP_HEADER_LEN: usize = 8;
/// ESP SPI length used to reject the NAT-T non-ESP marker.
pub const ESP_SPI_LEN: usize = 4;

/// Validated reserved skb-mark profile shared by host and datapath.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkProfile {
    /// Starting bit of the seven-bit token window.
    pub shift: u8,
    /// Exact mask for the seven contiguous reserved bits.
    pub mask: u32,
}

impl MarkProfile {
    /// Derive the exact seven-bit mask for `shift`.
    #[must_use]
    pub const fn mask_for_shift(shift: u8) -> Option<u32> {
        if shift > MAX_MARK_SHIFT {
            return None;
        }
        Some(0x7f_u32 << shift)
    }

    /// Validate an explicit shift and mask pair.
    #[must_use]
    pub const fn new(shift: u8, mask: u32) -> Option<Self> {
        match Self::mask_for_shift(shift) {
            Some(expected) if expected == mask => Some(Self { shift, mask }),
            _ => None,
        }
    }

    /// Return the presence bit within the reserved token window.
    #[must_use]
    pub const fn presence_bit(self) -> u32 {
        0x40_u32 << self.shift
    }

    /// Encode one validated DSCP as a masked XFRM output-mark token.
    #[must_use]
    pub const fn encode_token(self, dscp: u8) -> Option<u32> {
        if dscp > 63 {
            return None;
        }
        Some(((dscp as u32) | 0x40) << self.shift)
    }

    /// Decode the token from a packet mark.
    #[must_use]
    pub const fn decode_token(self, mark: u32) -> MarkToken {
        let reserved = mark & self.mask;
        if reserved == 0 {
            return MarkToken::Absent;
        }
        if reserved & self.presence_bit() == 0 {
            return MarkToken::Malformed;
        }
        MarkToken::Dscp(((reserved >> self.shift) & 0x3f) as u8)
    }

    /// Clear exactly the seven reserved bits and preserve every unrelated bit.
    #[must_use]
    pub const fn clear_token(self, mark: u32) -> u32 {
        mark & !self.mask
    }

    /// Encode this profile into the pinned config-map wire layout.
    #[must_use]
    pub const fn encode(self) -> [u8; MARK_CONFIG_VALUE_LEN] {
        let mask = self.mask.to_le_bytes();
        [self.shift, 0, 0, 0, mask[0], mask[1], mask[2], mask[3]]
    }

    /// Decode and validate the pinned config-map wire layout.
    #[must_use]
    pub const fn decode(value: &[u8; MARK_CONFIG_VALUE_LEN]) -> Option<Self> {
        if value[1] != 0 || value[2] != 0 || value[3] != 0 {
            return None;
        }
        let mask = u32::from_le_bytes([value[4], value[5], value[6], value[7]]);
        Self::new(value[0], mask)
    }
}

/// Classification of this companion's reserved mark bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkToken {
    /// All reserved bits are clear; the packet is unrelated and passes.
    Absent,
    /// Reserved bits are set without the required presence bit.
    Malformed,
    /// A valid six-bit DSCP token.
    Dscp(u8),
}

/// Valid ESP carrier selected from an outer IP protocol and UDP ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspCarrier {
    /// ESP begins immediately after the outer IP header.
    Direct,
    /// ESP follows one UDP header (RFC 3948 NAT traversal).
    UdpEncapsulated,
}

/// Classify the only outer carriers eligible for DSCP stamping.
///
/// Direct ESP ignores `udp_ports`. UDP requires non-zero source and
/// destination ports so malformed/non-socket traffic cannot consume a token.
#[must_use]
pub const fn classify_esp_carrier(protocol: u8, udp_ports: [u8; 4]) -> Option<EspCarrier> {
    match protocol {
        IPPROTO_ESP => Some(EspCarrier::Direct),
        IPPROTO_UDP
            if (udp_ports[0] != 0 || udp_ports[1] != 0)
                && (udp_ports[2] != 0 || udp_ports[3] != 0) =>
        {
            Some(EspCarrier::UdpEncapsulated)
        }
        _ => None,
    }
}

/// Return whether four bytes represent a non-zero ESP SPI.
///
/// A zero word after UDP is the RFC 3948 non-ESP marker used by IKE and must
/// never be treated as transformed data traffic.
#[must_use]
pub const fn valid_esp_spi(spi: [u8; ESP_SPI_LEN]) -> bool {
    spi[0] != 0 || spi[1] != 0 || spi[2] != 0 || spi[3] != 0
}

/// Rewrite an outer IPv4 header's DSCP while preserving ECN and checksum.
///
/// The function accepts the fixed 20-byte header produced by Linux XFRM
/// tunnel mode. It fails closed for a non-IPv4/IHL-5 header or invalid DSCP.
#[must_use]
pub fn rewrite_ipv4_dscp(header: &mut [u8; IPV4_HEADER_LEN], dscp: u8) -> bool {
    if header[0] != 0x45 || dscp > 63 {
        return false;
    }
    let ecn = header[1] & 0x03;
    header[1] = (dscp << 2) | ecn;
    header[10] = 0;
    header[11] = 0;
    let checksum = ipv4_checksum(header).to_be_bytes();
    header[10] = checksum[0];
    header[11] = checksum[1];
    true
}

/// Rewrite an outer IPv6 base header's DSCP while preserving ECN/flow label.
#[must_use]
pub fn rewrite_ipv6_dscp(header: &mut [u8; IPV6_HEADER_LEN], dscp: u8) -> bool {
    if header[0] >> 4 != 6 || dscp > 63 {
        return false;
    }
    let traffic_class = ((header[0] & 0x0f) << 4) | (header[1] >> 4);
    let updated = (dscp << 2) | (traffic_class & 0x03);
    header[0] = (header[0] & 0xf0) | (updated >> 4);
    header[1] = (updated << 4) | (header[1] & 0x0f);
    true
}

fn ipv4_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    let mut sum = 0_u32;
    let mut offset = 0;
    while offset < IPV4_HEADER_LEN {
        sum += u32::from(u16::from_be_bytes([header[offset], header[offset + 1]]));
        offset += 2;
    }
    // A fixed 20-byte header has ten words. Two carry folds are sufficient
    // for their maximum sum and keep the eBPF control-flow graph bounded.
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_profile_validates_shift_and_exact_mask() {
        assert_eq!(MarkProfile::mask_for_shift(0), Some(0x7f));
        assert_eq!(MarkProfile::mask_for_shift(25), Some(0xfe00_0000));
        assert_eq!(MarkProfile::mask_for_shift(26), None);
        assert!(MarkProfile::new(25, 0xfe00_0000).is_some());
        assert!(MarkProfile::new(25, 0xfc00_0000).is_none());
    }

    #[test]
    fn token_round_trip_and_clear_preserve_unrelated_bits() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let unrelated = 0x0101_2345;
        let marked = unrelated | profile.encode_token(46).unwrap();
        assert_eq!(profile.decode_token(marked), MarkToken::Dscp(46));
        assert_eq!(profile.clear_token(marked), unrelated & !profile.mask);
        assert_eq!(
            profile.decode_token(unrelated & !profile.mask),
            MarkToken::Absent
        );
        assert_eq!(
            profile.decode_token(1_u32 << profile.shift),
            MarkToken::Malformed
        );
        assert!(profile.encode_token(64).is_none());
    }

    #[test]
    fn config_wire_round_trips_and_rejects_reserved_bytes() {
        let profile = MarkProfile::new(7, 0x0000_3f80).unwrap();
        let encoded = profile.encode();
        assert_eq!(MarkProfile::decode(&encoded), Some(profile));
        let mut malformed = encoded;
        malformed[1] = 1;
        assert_eq!(MarkProfile::decode(&malformed), None);
    }

    #[test]
    fn esp_carrier_rejects_non_esp_malformed_udp_and_non_esp_markers() {
        assert_eq!(
            classify_esp_carrier(IPPROTO_ESP, [0; 4]),
            Some(EspCarrier::Direct)
        );
        assert_eq!(
            classify_esp_carrier(IPPROTO_UDP, [0x11, 0x94, 0x11, 0x94]),
            Some(EspCarrier::UdpEncapsulated)
        );
        assert_eq!(classify_esp_carrier(IPPROTO_UDP, [0, 0, 0x11, 0x94]), None);
        assert_eq!(classify_esp_carrier(IPPROTO_UDP, [0x11, 0x94, 0, 0]), None);
        assert_eq!(classify_esp_carrier(6, [0; 4]), None);
        assert!(!valid_esp_spi([0; ESP_SPI_LEN]));
        assert!(valid_esp_spi([0, 0, 0, 1]));
    }

    #[test]
    fn ipv4_rewrite_preserves_ecn_and_updates_checksum() {
        let mut header = [0_u8; IPV4_HEADER_LEN];
        header[0] = 0x45;
        header[1] = 0x03;
        header[2..4].copy_from_slice(&100_u16.to_be_bytes());
        header[8] = 64;
        header[9] = IPPROTO_ESP;
        header[12..16].copy_from_slice(&[192, 0, 2, 1]);
        header[16..20].copy_from_slice(&[192, 0, 2, 2]);
        assert!(rewrite_ipv4_dscp(&mut header, 46));
        assert_eq!(header[1], (46 << 2) | 3);
        assert_eq!(ipv4_checksum(&header), 0);
        assert!(!rewrite_ipv4_dscp(&mut header, 64));
    }

    #[test]
    fn ipv6_rewrite_preserves_ecn_and_flow_label() {
        let mut header = [0_u8; IPV6_HEADER_LEN];
        header[0] = 0x60;
        header[1] = 0x31;
        header[2] = 0x23;
        header[3] = 0x45;
        assert!(rewrite_ipv6_dscp(&mut header, 46));
        let traffic_class = ((header[0] & 0x0f) << 4) | (header[1] >> 4);
        assert_eq!(traffic_class, (46 << 2) | 3);
        assert_eq!(header[1] & 0x0f, 1);
        assert_eq!(header[2..4], [0x23, 0x45]);
    }
}
