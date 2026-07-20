//! Minimal ICMP Packet-Too-Big generation for host callers of
//! `decide_uplink_encap`.
//!
//! When a host-side encapsulator receives [`UplinkEncapOutcome::RejectTooBig`]
//! it can turn the typed [`GtpuPmtuSignal`] into a wire packet toward the
//! inner source here: RFC 792 type 3 code 4 with the RFC 1191 next-hop MTU
//! for IPv4, or RFC 8200 section 5 / RFC 8201 type 2 for IPv6. The eBPF tc
//! backend deliberately does not use this helper: its reject path is a
//! silent, counted drop, and operators of that backend must size the inner
//! MTU out of band (for example MSS clamping) unless they run a host
//! component that consumes the signal.

use std::net::{Ipv4Addr, Ipv6Addr};

use opc_gtpu_ebpf_common::{
    internet_checksum, GtpuPmtuSignal, ICMPV4_CODE_FRAGMENTATION_NEEDED_DF_SET,
    ICMPV4_TYPE_DESTINATION_UNREACHABLE, ICMPV6_TYPE_PACKET_TOO_BIG,
};

/// Maximum bytes of the invoking packet quoted inside one ICMPv6 Packet Too
/// Big message: the minimum IPv6 MTU minus the outer IPv6 and ICMP headers.
const ICMPV6_MAX_QUOTE: usize = 1280 - 40 - 8;

/// Build an ICMPv4 Destination Unreachable "fragmentation needed and DF set"
/// message (RFC 792 type 3 code 4) with the RFC 1191 next-hop MTU, quoting
/// the invoking IPv4 header and its first 64 bits as required by RFC 792.
///
/// `signal` must be [`GtpuPmtuSignal::Icmpv4FragmentationNeeded`] and
/// `invoking_packet` must start with a complete IPv4 header followed by at
/// least eight payload bytes; anything else returns `None`.
#[must_use]
pub fn build_icmpv4_packet_too_big(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    signal: GtpuPmtuSignal,
    invoking_packet: &[u8],
) -> Option<Vec<u8>> {
    let GtpuPmtuSignal::Icmpv4FragmentationNeeded { inner_mtu } = signal else {
        return None;
    };
    let version_ihl = *invoking_packet.first()?;
    let ihl = usize::from(version_ihl & 0x0f) * 4;
    if version_ihl >> 4 != 4 || ihl < 20 || invoking_packet.len() < ihl + 8 {
        return None;
    }
    let quote = &invoking_packet[..ihl + 8];

    let total_length = u16::try_from(20 + 8 + quote.len()).ok()?;
    let mut packet = Vec::with_capacity(usize::from(total_length));
    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&total_length.to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // identification
    packet.extend_from_slice(&[0, 0]); // flags/fragment offset
    packet.push(64); // TTL
    packet.push(1); // ICMPv4
    packet.extend_from_slice(&[0, 0]); // header checksum (filled below)
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    let header_checksum = internet_checksum(&packet);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let icmp_offset = packet.len();
    packet.push(ICMPV4_TYPE_DESTINATION_UNREACHABLE);
    packet.push(ICMPV4_CODE_FRAGMENTATION_NEEDED_DF_SET);
    packet.extend_from_slice(&[0, 0]); // checksum (filled below)
    packet.extend_from_slice(&[0, 0]); // unused
    packet.extend_from_slice(&inner_mtu.to_be_bytes()); // RFC 1191 next-hop MTU
    packet.extend_from_slice(quote);
    let icmp_checksum = internet_checksum(&packet[icmp_offset..]);
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Some(packet)
}

/// Build an ICMPv6 Packet Too Big message (RFC 8200 section 5, RFC 8201 type
/// 2) quoting as much of the invoking packet as fits within the minimum IPv6
/// MTU.
///
/// `signal` must be [`GtpuPmtuSignal::Icmpv6PacketTooBig`] and
/// `invoking_packet` must start with a complete 40-byte IPv6 header;
/// anything else returns `None`.
#[must_use]
pub fn build_icmpv6_packet_too_big(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    signal: GtpuPmtuSignal,
    invoking_packet: &[u8],
) -> Option<Vec<u8>> {
    let GtpuPmtuSignal::Icmpv6PacketTooBig { inner_mtu } = signal else {
        return None;
    };
    if invoking_packet.len() < 40 || invoking_packet[0] >> 4 != 6 {
        return None;
    }
    let quote_len = invoking_packet.len().min(ICMPV6_MAX_QUOTE);

    let mut packet = Vec::with_capacity(40 + 8 + quote_len);
    // Outer IPv6 header: version, payload length, next header 58, hop limit.
    packet.push(0x60);
    packet.extend_from_slice(&[0, 0, 0]);
    let payload_length = u16::try_from(8 + quote_len).ok()?;
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.push(58); // ICMPv6
    packet.push(64); // hop limit
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());

    let icmp_offset = packet.len();
    packet.push(ICMPV6_TYPE_PACKET_TOO_BIG);
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // checksum (filled below)
    packet.extend_from_slice(&u32::from(inner_mtu).to_be_bytes());
    packet.extend_from_slice(&invoking_packet[..quote_len]);

    // Pseudo-header checksum over source, destination, upper-layer length,
    // and next header, then the ICMPv6 message.
    let mut checksum_input = Vec::with_capacity(40 + packet.len() - icmp_offset);
    checksum_input.extend_from_slice(&source.octets());
    checksum_input.extend_from_slice(&destination.octets());
    checksum_input.extend_from_slice(&u32::from(payload_length).to_be_bytes());
    checksum_input.extend_from_slice(&[0, 0, 0, 58]);
    checksum_input.extend_from_slice(&packet[icmp_offset..]);
    let checksum = internet_checksum(&checksum_input);
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TUNNEL_LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const UE: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 2);

    fn invoking_ipv4(payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut packet = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 10, 45, 0, 2, 198, 51, 100, 7,
        ];
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn icmpv4_ptb_matches_rfc1191_layout_and_verifies_checksums() {
        let signal = GtpuPmtuSignal::Icmpv4FragmentationNeeded { inner_mtu: 1464 };
        let invoking = invoking_ipv4(b"0123456789abcdef");
        let packet = build_icmpv4_packet_too_big(TUNNEL_LOCAL, UE, signal, &invoking).unwrap();

        // IPv4 header.
        assert_eq!(packet[0], 0x45);
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 20 + 8 + 28);
        assert_eq!(packet[8], 64);
        assert_eq!(packet[9], 1);
        assert_eq!(&packet[12..16], &TUNNEL_LOCAL.octets());
        assert_eq!(&packet[16..20], &UE.octets());
        assert_eq!(internet_checksum(&packet[..20]), 0, "IPv4 header checksum");

        // ICMP header: type 3 code 4, zero unused, RFC 1191 MTU.
        assert_eq!(packet[20], 3);
        assert_eq!(packet[21], 4);
        assert_eq!(&packet[24..26], &[0, 0]);
        assert_eq!(u16::from_be_bytes([packet[26], packet[27]]), 1464);
        assert_eq!(internet_checksum(&packet[20..]), 0, "ICMP checksum");

        // Quote: the complete invoking IPv4 header plus its first 64 bits.
        assert_eq!(&packet[28..], &invoking[..28]);
    }

    #[test]
    fn icmpv4_ptb_rejects_wrong_signal_and_short_invoking_packet() {
        let v6_signal = GtpuPmtuSignal::Icmpv6PacketTooBig { inner_mtu: 1464 };
        assert!(build_icmpv4_packet_too_big(
            TUNNEL_LOCAL,
            UE,
            v6_signal,
            &invoking_ipv4(b"01234567")
        )
        .is_none());
        let signal = GtpuPmtuSignal::Icmpv4FragmentationNeeded { inner_mtu: 1464 };
        assert!(build_icmpv4_packet_too_big(TUNNEL_LOCAL, UE, signal, &[]).is_none());
        assert!(build_icmpv4_packet_too_big(TUNNEL_LOCAL, UE, signal, &[0x45; 27]).is_none());
        // IPv6-looking invoking packet is rejected on the IPv4 path.
        assert!(build_icmpv4_packet_too_big(TUNNEL_LOCAL, UE, signal, &[0x60; 48]).is_none());
    }

    #[test]
    fn icmpv6_ptb_matches_rfc8201_layout_and_verifies_checksum() {
        let signal = GtpuPmtuSignal::Icmpv6PacketTooBig { inner_mtu: 1464 };
        let mut invoking = vec![0x60; 48];
        invoking[6] = 6; // next header TCP
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let packet = build_icmpv6_packet_too_big(source, destination, signal, &invoking).unwrap();

        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 8 + 48);
        assert_eq!(packet[6], 58);
        assert_eq!(&packet[8..24], &source.octets());
        assert_eq!(&packet[24..40], &destination.octets());

        assert_eq!(packet[40], 2);
        assert_eq!(packet[41], 0);
        assert_eq!(
            u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]),
            1464
        );
        assert_eq!(&packet[48..], &invoking[..]);

        // Verify the pseudo-header checksum the same way the receiver does.
        let mut check = Vec::new();
        check.extend_from_slice(&source.octets());
        check.extend_from_slice(&destination.octets());
        check.extend_from_slice(&(8_u32 + 48).to_be_bytes());
        check.extend_from_slice(&[0, 0, 0, 58]);
        check.extend_from_slice(&packet[40..]);
        assert_eq!(internet_checksum(&check), 0, "ICMPv6 checksum");
    }

    #[test]
    fn icmpv6_ptb_bounds_the_quote_to_the_minimum_ipv6_mtu() {
        let signal = GtpuPmtuSignal::Icmpv6PacketTooBig { inner_mtu: 1280 };
        let invoking = vec![0x60; 9000];
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let packet = build_icmpv6_packet_too_big(source, destination, signal, &invoking).unwrap();
        assert_eq!(packet.len(), 1280);
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]),
            (1280 - 40) as u16
        );
    }

    #[test]
    fn icmpv6_ptb_rejects_wrong_signal_and_non_ipv6_invoking_packet() {
        let v4_signal = GtpuPmtuSignal::Icmpv4FragmentationNeeded { inner_mtu: 1464 };
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert!(build_icmpv6_packet_too_big(source, destination, v4_signal, &[0x60; 40]).is_none());
        let signal = GtpuPmtuSignal::Icmpv6PacketTooBig { inner_mtu: 1464 };
        assert!(build_icmpv6_packet_too_big(source, destination, signal, &[0x45; 40]).is_none());
        assert!(build_icmpv6_packet_too_big(source, destination, signal, &[0x60; 39]).is_none());
    }
}
