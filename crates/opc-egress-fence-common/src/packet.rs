use crate::ProtectedEndpoint;

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_OFFSET: usize = 12;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN_8021Q: u16 = 0x8100;
const ETHERTYPE_VLAN_8021AD: u16 = 0x88a8;
const MAX_VLAN_HEADERS: usize = 2;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_PROTOCOL_UDP: u8 = 17;
const IPV4_FRAGMENT_OFFSET_MASK: u16 = 0x1fff;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
const IPV6_NEXT_HEADER_ESP: u8 = 50;
const IPV6_NEXT_HEADER_AUTHENTICATION: u8 = 51;
const IPV6_NEXT_HEADER_NONE: u8 = 59;
const IPV6_NEXT_HEADER_DESTINATION: u8 = 60;
const IPV6_NEXT_HEADER_UDP: u8 = 17;
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
    /// The tc classifier fails closed for unmarked packets in this state.
    Indeterminate,
}

/// Classify an Ethernet-framed tc egress packet against one protected source.
///
/// The parser accepts at most two VLAN headers, IPv4 options, and at most four
/// bounded IPv6 extension headers. A fragment whose transport header cannot be
/// proven is indeterminate when its source address is protected.
#[must_use]
pub fn classify_ethernet_udp_source(
    frame: &[u8],
    endpoint: ProtectedEndpoint,
) -> PacketEndpointDisposition {
    if frame.len() < ETHERNET_HEADER_LEN {
        return PacketEndpointDisposition::Indeterminate;
    }
    let mut ether_type = read_u16_be(frame, ETHERTYPE_OFFSET);
    let mut network_offset = ETHERNET_HEADER_LEN;
    let mut vlan_count = 0;
    while matches!(
        ether_type,
        Some(ETHERTYPE_VLAN_8021Q | ETHERTYPE_VLAN_8021AD)
    ) {
        if vlan_count >= MAX_VLAN_HEADERS || frame.len() < network_offset + 4 {
            return PacketEndpointDisposition::Indeterminate;
        }
        ether_type = read_u16_be(frame, network_offset + 2);
        network_offset += 4;
        vlan_count += 1;
    }
    match ether_type {
        Some(ETHERTYPE_IPV4) => classify_ipv4(frame, network_offset, endpoint),
        Some(ETHERTYPE_IPV6) => classify_ipv6(frame, network_offset, endpoint),
        Some(_) => PacketEndpointDisposition::Unrelated,
        None => PacketEndpointDisposition::Indeterminate,
    }
}

fn classify_ipv4(
    frame: &[u8],
    offset: usize,
    endpoint: ProtectedEndpoint,
) -> PacketEndpointDisposition {
    let ProtectedEndpoint::Ipv4 {
        address: protected_address,
        port: protected_port,
    } = endpoint
    else {
        return PacketEndpointDisposition::Unrelated;
    };
    if frame.len() < offset + IPV4_MIN_HEADER_LEN {
        return PacketEndpointDisposition::Indeterminate;
    }
    let version_ihl = frame[offset];
    let header_len = usize::from(version_ihl & 0x0f) * 4;
    if version_ihl >> 4 != 4 || header_len < IPV4_MIN_HEADER_LEN {
        return PacketEndpointDisposition::Indeterminate;
    }
    let source = [
        frame[offset + 12],
        frame[offset + 13],
        frame[offset + 14],
        frame[offset + 15],
    ];
    if source != protected_address {
        return PacketEndpointDisposition::Unrelated;
    }
    let Some(total_len) = read_u16_be(frame, offset + 2).map(usize::from) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    let Some(packet_end) = offset.checked_add(total_len) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if header_len > total_len || frame.len() < packet_end {
        return PacketEndpointDisposition::Indeterminate;
    }
    if frame[offset + 9] != IPV4_PROTOCOL_UDP {
        return PacketEndpointDisposition::Unrelated;
    }
    let Some(fragment) = read_u16_be(frame, offset + 6) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if fragment & IPV4_FRAGMENT_OFFSET_MASK != 0 {
        return PacketEndpointDisposition::Indeterminate;
    }
    let Some(udp_offset) = offset.checked_add(header_len) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if udp_offset + UDP_HEADER_LEN > packet_end {
        return PacketEndpointDisposition::Indeterminate;
    }
    match read_u16_be(frame, udp_offset) {
        Some(port) if port == protected_port => PacketEndpointDisposition::Protected,
        Some(_) => PacketEndpointDisposition::Unrelated,
        None => PacketEndpointDisposition::Indeterminate,
    }
}

fn classify_ipv6(
    frame: &[u8],
    offset: usize,
    endpoint: ProtectedEndpoint,
) -> PacketEndpointDisposition {
    let ProtectedEndpoint::Ipv6 {
        address: protected_address,
        port: protected_port,
    } = endpoint
    else {
        return PacketEndpointDisposition::Unrelated;
    };
    if frame.len() < offset + IPV6_HEADER_LEN || frame[offset] >> 4 != 6 {
        return PacketEndpointDisposition::Indeterminate;
    }
    let mut source = [0_u8; 16];
    source.copy_from_slice(&frame[offset + 8..offset + 24]);
    if source != protected_address {
        return PacketEndpointDisposition::Unrelated;
    }
    let Some(payload_len) = read_u16_be(frame, offset + 4).map(usize::from) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if payload_len == 0 {
        return PacketEndpointDisposition::Indeterminate;
    }
    let Some(packet_end) = offset
        .checked_add(IPV6_HEADER_LEN)
        .and_then(|base| base.checked_add(payload_len))
    else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if frame.len() < packet_end {
        return PacketEndpointDisposition::Indeterminate;
    }
    let mut next_header = frame[offset + 6];
    let mut cursor = offset + IPV6_HEADER_LEN;
    let mut extension_count = 0;
    loop {
        match next_header {
            IPV6_NEXT_HEADER_UDP => {
                if cursor + UDP_HEADER_LEN > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                return match read_u16_be(frame, cursor) {
                    Some(port) if port == protected_port => PacketEndpointDisposition::Protected,
                    Some(_) => PacketEndpointDisposition::Unrelated,
                    None => PacketEndpointDisposition::Indeterminate,
                };
            }
            IPV6_NEXT_HEADER_NONE | IPV6_NEXT_HEADER_ESP => {
                return PacketEndpointDisposition::Unrelated;
            }
            IPV6_NEXT_HEADER_HOP_BY_HOP
            | IPV6_NEXT_HEADER_ROUTING
            | IPV6_NEXT_HEADER_DESTINATION => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS || cursor + 2 > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                next_header = frame[cursor];
                let header_len = (usize::from(frame[cursor + 1]) + 1) * 8;
                if header_len < 8 || cursor + header_len > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                cursor += header_len;
            }
            IPV6_NEXT_HEADER_FRAGMENT => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS || cursor + 8 > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                next_header = frame[cursor];
                let Some(fragment) = read_u16_be(frame, cursor + 2) else {
                    return PacketEndpointDisposition::Indeterminate;
                };
                if fragment & 0xfff8 != 0 {
                    return PacketEndpointDisposition::Indeterminate;
                }
                cursor += 8;
            }
            IPV6_NEXT_HEADER_AUTHENTICATION => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS || cursor + 2 > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                next_header = frame[cursor];
                let header_len = (usize::from(frame[cursor + 1]) + 2) * 4;
                if header_len < 8 || cursor + header_len > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                cursor += header_len;
            }
            // An unrecognized IPv6 next-header value is not proof that the
            // protected UDP source is absent. Future extension headers can
            // precede UDP, so the safe disposition is indeterminate.
            _ => return PacketEndpointDisposition::Indeterminate,
        }
        extension_count += 1;
    }
}

fn read_u16_be(bytes: &[u8], offset: usize) -> Option<u16> {
    let high = *bytes.get(offset)?;
    let low = *bytes.get(offset + 1)?;
    Some(u16::from_be_bytes([high, low]))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;

    const IPV4_ENDPOINT: ProtectedEndpoint = ProtectedEndpoint::Ipv4 {
        address: [192, 0, 2, 10],
        port: 2123,
    };
    const IPV6_ENDPOINT: ProtectedEndpoint = ProtectedEndpoint::Ipv6 {
        address: [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ],
        port: 2123,
    };

    fn ipv4_udp_with_options(vlan_headers: usize) -> Vec<u8> {
        let network_offset = ETHERNET_HEADER_LEN + vlan_headers * 4;
        let mut frame = vec![0_u8; network_offset + 24 + UDP_HEADER_LEN];
        let mut type_offset = ETHERTYPE_OFFSET;
        for index in 0..vlan_headers {
            frame[type_offset..type_offset + 2]
                .copy_from_slice(&ETHERTYPE_VLAN_8021Q.to_be_bytes());
            type_offset = ETHERNET_HEADER_LEN + index * 4 + 2;
        }
        frame[type_offset..type_offset + 2].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame[network_offset] = 0x46;
        frame[network_offset + 2..network_offset + 4].copy_from_slice(&(32_u16).to_be_bytes());
        frame[network_offset + 9] = IPV4_PROTOCOL_UDP;
        frame[network_offset + 12..network_offset + 16].copy_from_slice(&[192, 0, 2, 10]);
        frame[network_offset + 24..network_offset + 26].copy_from_slice(&2123_u16.to_be_bytes());
        frame
    }

    #[test]
    fn vlan_and_ipv4_options_reach_the_exact_udp_source() {
        for vlan_headers in 0..=MAX_VLAN_HEADERS {
            assert_eq!(
                classify_ethernet_udp_source(&ipv4_udp_with_options(vlan_headers), IPV4_ENDPOINT),
                PacketEndpointDisposition::Protected
            );
        }
    }

    #[test]
    fn noninitial_protected_ipv4_fragment_is_indeterminate() {
        let mut frame = ipv4_udp_with_options(0);
        frame[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8]
            .copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            classify_ethernet_udp_source(&frame, IPV4_ENDPOINT),
            PacketEndpointDisposition::Indeterminate
        );
    }

    #[test]
    fn ipv6_destination_options_reach_the_exact_udp_source() {
        let mut frame = vec![0_u8; ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 8 + UDP_HEADER_LEN];
        frame[ETHERTYPE_OFFSET..ETHERTYPE_OFFSET + 2]
            .copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let offset = ETHERNET_HEADER_LEN;
        frame[offset] = 0x60;
        frame[offset + 4..offset + 6].copy_from_slice(&16_u16.to_be_bytes());
        frame[offset + 6] = IPV6_NEXT_HEADER_DESTINATION;
        frame[offset + 8..offset + 24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        let extension = offset + IPV6_HEADER_LEN;
        frame[extension] = IPV6_NEXT_HEADER_UDP;
        let udp = extension + 8;
        frame[udp..udp + 2].copy_from_slice(&2123_u16.to_be_bytes());

        assert_eq!(
            classify_ethernet_udp_source(&frame, IPV6_ENDPOINT),
            PacketEndpointDisposition::Protected
        );
    }

    #[test]
    fn malformed_protected_ipv6_extension_is_indeterminate() {
        let mut frame = vec![0_u8; ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 8];
        frame[ETHERTYPE_OFFSET..ETHERTYPE_OFFSET + 2]
            .copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let offset = ETHERNET_HEADER_LEN;
        frame[offset] = 0x60;
        frame[offset + 4..offset + 6].copy_from_slice(&8_u16.to_be_bytes());
        frame[offset + 6] = IPV6_NEXT_HEADER_DESTINATION;
        frame[offset + 8..offset + 24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        frame[offset + IPV6_HEADER_LEN + 1] = u8::MAX;

        assert_eq!(
            classify_ethernet_udp_source(&frame, IPV6_ENDPOINT),
            PacketEndpointDisposition::Indeterminate
        );
    }
}
