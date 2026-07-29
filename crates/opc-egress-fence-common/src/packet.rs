use crate::ProtectedEndpoint;

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_PROTOCOL_UDP: u8 = 17;
// The reserved flag, MF, and a nonzero fragment offset all make the UDP
// source tuple ambiguous. DF is the only permitted flag.
const IPV4_AMBIGUOUS_FRAGMENT_MASK: u16 = 0xbfff;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_HEADER_TCP: u8 = 6;
const IPV6_NEXT_HEADER_UDP: u8 = 17;
const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
const IPV6_NEXT_HEADER_ESP: u8 = 50;
const IPV6_NEXT_HEADER_AUTHENTICATION: u8 = 51;
const IPV6_NEXT_HEADER_ICMPV6: u8 = 58;
const IPV6_NEXT_HEADER_NONE: u8 = 59;
const IPV6_NEXT_HEADER_DESTINATION: u8 = 60;
const MAX_IPV6_EXTENSION_HEADERS: usize = 4;
const UDP_HEADER_LEN: usize = 8;

/// Result of independently parsing a packet's local UDP source endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEndpointDisposition {
    /// Packet is proven to use the configured protected UDP source.
    Protected,
    /// Packet is well enough understood to prove it is not that endpoint.
    Unrelated,
    /// Truncation, malformed input, or a bounded parser limit prevents proof.
    ///
    /// The root cgroup-skb classifier fails closed in this state.
    Indeterminate,
}

/// Classify a cgroup-skb egress packet beginning at its network header.
///
/// Linux presents `BPF_CGROUP_INET_EGRESS` with `skb->data` pushed to the L3
/// network header. Ethernet and VLAN bytes are therefore neither accepted nor
/// parsed. IPv4 options and at most four bounded IPv6 extension headers are
/// supported. A fragment whose UDP source cannot be proven is indeterminate
/// when its source address is protected.
#[must_use]
pub fn classify_l3_udp_source(
    packet: &[u8],
    endpoint: ProtectedEndpoint,
) -> PacketEndpointDisposition {
    let Some(version) = packet.first().map(|first| first >> 4) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    match version {
        4 => classify_ipv4(packet, endpoint),
        6 => classify_ipv6(packet, endpoint),
        _ => PacketEndpointDisposition::Indeterminate,
    }
}

fn classify_ipv4(packet: &[u8], endpoint: ProtectedEndpoint) -> PacketEndpointDisposition {
    let ProtectedEndpoint::Ipv4 {
        address: protected_address,
        port: protected_port,
    } = endpoint
    else {
        return PacketEndpointDisposition::Unrelated;
    };
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return PacketEndpointDisposition::Indeterminate;
    }
    let version_ihl = packet[0];
    let header_len = usize::from(version_ihl & 0x0f) * 4;
    if version_ihl >> 4 != 4 || header_len < IPV4_MIN_HEADER_LEN {
        return PacketEndpointDisposition::Indeterminate;
    }
    let source = [packet[12], packet[13], packet[14], packet[15]];
    if source != protected_address {
        return PacketEndpointDisposition::Unrelated;
    }
    let Some(total_len) = read_u16_be(packet, 2).map(usize::from) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if header_len > total_len || packet.len() < total_len {
        return PacketEndpointDisposition::Indeterminate;
    }
    if packet[9] != IPV4_PROTOCOL_UDP {
        return PacketEndpointDisposition::Unrelated;
    }
    let Some(fragment) = read_u16_be(packet, 6) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if fragment & IPV4_AMBIGUOUS_FRAGMENT_MASK != 0 {
        return PacketEndpointDisposition::Indeterminate;
    }
    if header_len.saturating_add(UDP_HEADER_LEN) > total_len {
        return PacketEndpointDisposition::Indeterminate;
    }
    match read_u16_be(packet, header_len) {
        Some(port) if port == protected_port => PacketEndpointDisposition::Protected,
        Some(_) => PacketEndpointDisposition::Unrelated,
        None => PacketEndpointDisposition::Indeterminate,
    }
}

fn classify_ipv6(packet: &[u8], endpoint: ProtectedEndpoint) -> PacketEndpointDisposition {
    let ProtectedEndpoint::Ipv6 {
        address: protected_address,
        port: protected_port,
    } = endpoint
    else {
        return PacketEndpointDisposition::Unrelated;
    };
    if packet.len() < IPV6_HEADER_LEN || packet[0] >> 4 != 6 {
        return PacketEndpointDisposition::Indeterminate;
    }
    let mut source = [0_u8; 16];
    source.copy_from_slice(&packet[8..24]);
    if source != protected_address {
        return PacketEndpointDisposition::Unrelated;
    }
    let Some(payload_len) = read_u16_be(packet, 4).map(usize::from) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if payload_len == 0 {
        return PacketEndpointDisposition::Indeterminate;
    }
    let Some(packet_end) = IPV6_HEADER_LEN.checked_add(payload_len) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if packet.len() < packet_end {
        return PacketEndpointDisposition::Indeterminate;
    }
    let mut next_header = packet[6];
    let mut cursor = IPV6_HEADER_LEN;
    let mut extension_count = 0;
    loop {
        match next_header {
            IPV6_NEXT_HEADER_UDP => {
                if cursor.saturating_add(UDP_HEADER_LEN) > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                return match read_u16_be(packet, cursor) {
                    Some(port) if port == protected_port => PacketEndpointDisposition::Protected,
                    Some(_) => PacketEndpointDisposition::Unrelated,
                    None => PacketEndpointDisposition::Indeterminate,
                };
            }
            IPV6_NEXT_HEADER_TCP
            | IPV6_NEXT_HEADER_ICMPV6
            | IPV6_NEXT_HEADER_NONE
            | IPV6_NEXT_HEADER_ESP => return PacketEndpointDisposition::Unrelated,
            IPV6_NEXT_HEADER_HOP_BY_HOP
            | IPV6_NEXT_HEADER_ROUTING
            | IPV6_NEXT_HEADER_DESTINATION => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS
                    || cursor.saturating_add(2) > packet_end
                {
                    return PacketEndpointDisposition::Indeterminate;
                }
                next_header = packet[cursor];
                let header_len = (usize::from(packet[cursor + 1]) + 1) * 8;
                if header_len < 8 || cursor.saturating_add(header_len) > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                cursor += header_len;
            }
            IPV6_NEXT_HEADER_FRAGMENT => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS
                    || cursor.saturating_add(8) > packet_end
                {
                    return PacketEndpointDisposition::Indeterminate;
                }
                next_header = packet[cursor];
                let Some(fragment) = read_u16_be(packet, cursor + 2) else {
                    return PacketEndpointDisposition::Indeterminate;
                };
                if fragment != 0 {
                    return PacketEndpointDisposition::Indeterminate;
                }
                cursor += 8;
            }
            IPV6_NEXT_HEADER_AUTHENTICATION => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS
                    || cursor.saturating_add(2) > packet_end
                {
                    return PacketEndpointDisposition::Indeterminate;
                }
                next_header = packet[cursor];
                let header_len = (usize::from(packet[cursor + 1]) + 2) * 4;
                if header_len < 8 || cursor.saturating_add(header_len) > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                cursor += header_len;
            }
            // Unknown values can denote future extension headers before UDP.
            _ => return PacketEndpointDisposition::Indeterminate,
        }
        extension_count += 1;
    }
}

fn read_u16_be(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;

    const IPV4_ENDPOINT: ProtectedEndpoint = ProtectedEndpoint::Ipv4 {
        address: [192, 0, 2, 37],
        port: 0x1235,
    };
    const IPV6_ENDPOINT: ProtectedEndpoint = ProtectedEndpoint::Ipv6 {
        address: [
            0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0x9a, 0xbc,
        ],
        port: 0x1235,
    };

    fn ipv4_udp(source: [u8; 4], port: u16, ihl: u8, fragment: u16) -> Vec<u8> {
        let header_len = usize::from(ihl) * 4;
        let total_len = header_len + UDP_HEADER_LEN;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x40 | ihl;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&fragment.to_be_bytes());
        packet[9] = IPV4_PROTOCOL_UDP;
        packet[12..16].copy_from_slice(&source);
        packet[header_len..header_len + 2].copy_from_slice(&port.to_be_bytes());
        packet
    }

    fn ipv6_packet(next_header: u8, extension: &[u8]) -> Vec<u8> {
        let payload_len = extension.len() + UDP_HEADER_LEN;
        let mut packet = vec![0_u8; IPV6_HEADER_LEN + payload_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = next_header;
        packet[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0x9a, 0xbc,
        ]);
        packet[IPV6_HEADER_LEN..IPV6_HEADER_LEN + extension.len()].copy_from_slice(extension);
        packet[IPV6_HEADER_LEN + extension.len()..IPV6_HEADER_LEN + extension.len() + 2]
            .copy_from_slice(&0x1235_u16.to_be_bytes());
        packet
    }

    #[test]
    fn ipv4_options_reach_the_exact_udp_source() {
        assert_eq!(
            classify_l3_udp_source(&ipv4_udp([192, 0, 2, 37], 0x1235, 6, 0), IPV4_ENDPOINT,),
            PacketEndpointDisposition::Protected
        );
    }

    #[test]
    fn protected_ipv4_fragments_are_indeterminate() {
        for fragment in [1, 0x2000, 0x8000] {
            assert_eq!(
                classify_l3_udp_source(
                    &ipv4_udp([192, 0, 2, 37], 0x1235, 5, fragment),
                    IPV4_ENDPOINT,
                ),
                PacketEndpointDisposition::Indeterminate
            );
        }
    }

    #[test]
    fn ipv4_dont_fragment_flag_preserves_exact_classification() {
        assert_eq!(
            classify_l3_udp_source(&ipv4_udp([192, 0, 2, 37], 0x1235, 5, 0x4000), IPV4_ENDPOINT,),
            PacketEndpointDisposition::Protected
        );
    }

    #[test]
    fn well_formed_ipv4_non_domain_traffic_is_unrelated() {
        assert_eq!(
            classify_l3_udp_source(&ipv4_udp([198, 51, 100, 91], 0x1235, 5, 0), IPV4_ENDPOINT,),
            PacketEndpointDisposition::Unrelated
        );
        assert_eq!(
            classify_l3_udp_source(&ipv4_udp([192, 0, 2, 37], 0x4567, 5, 0), IPV4_ENDPOINT,),
            PacketEndpointDisposition::Unrelated
        );
        let mut tcp = ipv4_udp([192, 0, 2, 37], 0x1235, 5, 0);
        tcp[9] = IPV6_NEXT_HEADER_TCP;
        assert_eq!(
            classify_l3_udp_source(&tcp, IPV4_ENDPOINT),
            PacketEndpointDisposition::Unrelated
        );
    }

    #[test]
    fn ipv6_destination_options_reach_the_exact_udp_source() {
        let mut extension = [0_u8; 8];
        extension[0] = IPV6_NEXT_HEADER_UDP;
        assert_eq!(
            classify_l3_udp_source(
                &ipv6_packet(IPV6_NEXT_HEADER_DESTINATION, &extension),
                IPV6_ENDPOINT,
            ),
            PacketEndpointDisposition::Protected
        );
    }

    #[test]
    fn malformed_protected_ipv6_extension_is_indeterminate() {
        let mut extension = [0_u8; 8];
        extension[0] = IPV6_NEXT_HEADER_UDP;
        extension[1] = u8::MAX;
        assert_eq!(
            classify_l3_udp_source(
                &ipv6_packet(IPV6_NEXT_HEADER_DESTINATION, &extension),
                IPV6_ENDPOINT,
            ),
            PacketEndpointDisposition::Indeterminate
        );
    }

    #[test]
    fn known_ipv6_non_udp_terminal_is_unrelated() {
        assert_eq!(
            classify_l3_udp_source(&ipv6_packet(IPV6_NEXT_HEADER_TCP, &[]), IPV6_ENDPOINT,),
            PacketEndpointDisposition::Unrelated
        );
    }

    #[test]
    fn parser_requires_raw_l3_at_byte_zero() {
        let mut link_framed = vec![0_u8; 14];
        link_framed.extend_from_slice(&ipv4_udp([198, 51, 100, 91], 0x4567, 5, 0));
        assert_eq!(
            classify_l3_udp_source(&link_framed, IPV4_ENDPOINT),
            PacketEndpointDisposition::Indeterminate
        );
    }
}
