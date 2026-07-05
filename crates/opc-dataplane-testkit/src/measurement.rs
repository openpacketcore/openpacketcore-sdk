//! Deterministic measurement T-PDU construction and parsing.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::DataplaneTestkitError;

/// Magic tag at the start of every measurement UDP payload.
pub const MEASUREMENT_MAGIC: [u8; 8] = *b"OPCDPTK1";

/// Measurement header length in octets.
pub const MEASUREMENT_HEADER_LEN: usize = 24;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const UDP_PROTOCOL: u8 = 17;

/// Inner IP/UDP flow for generated test T-PDUs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InnerIpFlow {
    /// IPv4 UDP flow.
    Ipv4 {
        /// Source IPv4 address.
        src: Ipv4Addr,
        /// Destination IPv4 address.
        dst: Ipv4Addr,
        /// Source UDP port.
        src_port: u16,
        /// Destination UDP port.
        dst_port: u16,
    },
    /// IPv6 UDP flow.
    Ipv6 {
        /// Source IPv6 address.
        src: Ipv6Addr,
        /// Destination IPv6 address.
        dst: Ipv6Addr,
        /// Source UDP port.
        src_port: u16,
        /// Destination UDP port.
        dst_port: u16,
    },
}

impl fmt::Debug for InnerIpFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 {
                src_port, dst_port, ..
            } => f
                .debug_struct("Ipv4")
                .field("src", &"<redacted>")
                .field("dst", &"<redacted>")
                .field("src_port", src_port)
                .field("dst_port", dst_port)
                .finish(),
            Self::Ipv6 {
                src_port, dst_port, ..
            } => f
                .debug_struct("Ipv6")
                .field("src", &"<redacted>")
                .field("dst", &"<redacted>")
                .field("src_port", src_port)
                .field("dst_port", dst_port)
                .finish(),
        }
    }
}

impl InnerIpFlow {
    /// Return this flow with source and destination endpoints swapped.
    #[must_use]
    pub const fn reversed(self) -> Self {
        match self {
            Self::Ipv4 {
                src,
                dst,
                src_port,
                dst_port,
            } => Self::Ipv4 {
                src: dst,
                dst: src,
                src_port: dst_port,
                dst_port: src_port,
            },
            Self::Ipv6 {
                src,
                dst,
                src_port,
                dst_port,
            } => Self::Ipv6 {
                src: dst,
                dst: src,
                src_port: dst_port,
                dst_port: src_port,
            },
        }
    }
}

/// Fixed measurement payload header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasurementHeader {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Caller-injected send timestamp in nanoseconds.
    pub send_timestamp_ns: u64,
}

impl MeasurementHeader {
    /// Encode this measurement header.
    #[must_use]
    pub fn encode(self) -> [u8; MEASUREMENT_HEADER_LEN] {
        let mut out = [0u8; MEASUREMENT_HEADER_LEN];
        out[..8].copy_from_slice(&MEASUREMENT_MAGIC);
        out[8..16].copy_from_slice(&self.sequence.to_be_bytes());
        out[16..24].copy_from_slice(&self.send_timestamp_ns.to_be_bytes());
        out
    }

    /// Decode a measurement header from the start of a UDP payload.
    pub fn decode(input: &[u8]) -> Result<Self, DataplaneTestkitError> {
        if input.len() < MEASUREMENT_HEADER_LEN {
            return Err(DataplaneTestkitError::truncated("measurement header"));
        }
        if input[..8] != MEASUREMENT_MAGIC {
            return Err(DataplaneTestkitError::invalid_packet(
                "measurement magic mismatch",
            ));
        }
        let mut sequence = [0u8; 8];
        sequence.copy_from_slice(&input[8..16]);
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&input[16..24]);
        Ok(Self {
            sequence: u64::from_be_bytes(sequence),
            send_timestamp_ns: u64::from_be_bytes(timestamp),
        })
    }
}

/// Parsed measurement T-PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTpdu {
    /// Inner IP/UDP flow.
    pub flow: InnerIpFlow,
    /// Measurement header.
    pub measurement: MeasurementHeader,
}

/// Build a well-formed IPv4 or IPv6 UDP T-PDU carrying a measurement header.
pub fn build_measurement_tpdu(
    flow: InnerIpFlow,
    sequence: u64,
    send_timestamp_ns: u64,
) -> Result<Vec<u8>, DataplaneTestkitError> {
    let header = MeasurementHeader {
        sequence,
        send_timestamp_ns,
    };
    build_udp_tpdu(flow, &header.encode())
}

/// Decode a measurement T-PDU and validate basic IP/UDP structure.
pub fn decode_measurement_tpdu(tpdu: &[u8]) -> Result<DecodedTpdu, DataplaneTestkitError> {
    if tpdu.is_empty() {
        return Err(DataplaneTestkitError::truncated("IP header"));
    }
    match tpdu[0] >> 4 {
        4 => decode_ipv4_measurement(tpdu),
        6 => decode_ipv6_measurement(tpdu),
        version => Err(DataplaneTestkitError::UnsupportedIpVersion { version }),
    }
}

/// Return a T-PDU with inner source/destination IPs and ports swapped.
pub fn echo_tpdu(tpdu: &[u8]) -> Result<Vec<u8>, DataplaneTestkitError> {
    let decoded = decode_measurement_tpdu(tpdu)?;
    let header = decoded.measurement.encode();
    build_udp_tpdu(decoded.flow.reversed(), &header)
}

fn build_udp_tpdu(flow: InnerIpFlow, udp_payload: &[u8]) -> Result<Vec<u8>, DataplaneTestkitError> {
    match flow {
        InnerIpFlow::Ipv4 {
            src,
            dst,
            src_port,
            dst_port,
        } => build_ipv4_udp(src, dst, src_port, dst_port, udp_payload),
        InnerIpFlow::Ipv6 {
            src,
            dst,
            src_port,
            dst_port,
        } => build_ipv6_udp(src, dst, src_port, dst_port, udp_payload),
    }
}

fn build_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    udp_payload: &[u8],
) -> Result<Vec<u8>, DataplaneTestkitError> {
    let udp_len = UDP_HEADER_LEN
        .checked_add(udp_payload.len())
        .ok_or(DataplaneTestkitError::Overflow { field: "udp_len" })?;
    let udp_len_u16 =
        u16::try_from(udp_len).map_err(|_| DataplaneTestkitError::Overflow { field: "udp_len" })?;
    let total_len =
        IPV4_HEADER_LEN
            .checked_add(udp_len)
            .ok_or(DataplaneTestkitError::Overflow {
                field: "ipv4_total_len",
            })?;
    let total_len_u16 = u16::try_from(total_len).map_err(|_| DataplaneTestkitError::Overflow {
        field: "ipv4_total_len",
    })?;

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&0u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = UDP_PROTOCOL;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());

    let checksum = checksum(&[&packet[..IPV4_HEADER_LEN]]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    write_udp_segment(
        &mut packet[IPV4_HEADER_LEN..],
        src_port,
        dst_port,
        udp_len_u16,
        udp_payload,
    );
    let udp_checksum = udp_checksum_ipv4(src, dst, &packet[IPV4_HEADER_LEN..]);
    packet[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}

fn build_ipv6_udp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    udp_payload: &[u8],
) -> Result<Vec<u8>, DataplaneTestkitError> {
    let udp_len = UDP_HEADER_LEN
        .checked_add(udp_payload.len())
        .ok_or(DataplaneTestkitError::Overflow { field: "udp_len" })?;
    let udp_len_u16 =
        u16::try_from(udp_len).map_err(|_| DataplaneTestkitError::Overflow { field: "udp_len" })?;
    let total_len =
        IPV6_HEADER_LEN
            .checked_add(udp_len)
            .ok_or(DataplaneTestkitError::Overflow {
                field: "ipv6_total_len",
            })?;

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    packet[6] = UDP_PROTOCOL;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());

    write_udp_segment(
        &mut packet[IPV6_HEADER_LEN..],
        src_port,
        dst_port,
        udp_len_u16,
        udp_payload,
    );
    let udp_checksum = udp_checksum_ipv6(src, dst, &packet[IPV6_HEADER_LEN..]);
    packet[IPV6_HEADER_LEN + 6..IPV6_HEADER_LEN + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}

fn write_udp_segment(
    segment: &mut [u8],
    src_port: u16,
    dst_port: u16,
    udp_len: u16,
    udp_payload: &[u8],
) {
    segment[0..2].copy_from_slice(&src_port.to_be_bytes());
    segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
    segment[4..6].copy_from_slice(&udp_len.to_be_bytes());
    segment[6..8].copy_from_slice(&0u16.to_be_bytes());
    segment[8..].copy_from_slice(udp_payload);
}

fn decode_ipv4_measurement(tpdu: &[u8]) -> Result<DecodedTpdu, DataplaneTestkitError> {
    if tpdu.len() < IPV4_HEADER_LEN {
        return Err(DataplaneTestkitError::truncated("IPv4 header"));
    }
    let ihl = usize::from(tpdu[0] & 0x0f) * 4;
    if ihl < IPV4_HEADER_LEN || tpdu.len() < ihl + UDP_HEADER_LEN {
        return Err(DataplaneTestkitError::invalid_packet("invalid IPv4 IHL"));
    }
    let total_len = usize::from(u16::from_be_bytes([tpdu[2], tpdu[3]]));
    if total_len < ihl + UDP_HEADER_LEN || total_len > tpdu.len() {
        return Err(DataplaneTestkitError::invalid_packet(
            "invalid IPv4 total length",
        ));
    }
    if tpdu[9] != UDP_PROTOCOL {
        return Err(DataplaneTestkitError::invalid_packet(
            "IPv4 payload is not UDP",
        ));
    }
    if checksum(&[&tpdu[..ihl]]) != 0 {
        return Err(DataplaneTestkitError::invalid_packet(
            "invalid IPv4 header checksum",
        ));
    }

    let src = Ipv4Addr::new(tpdu[12], tpdu[13], tpdu[14], tpdu[15]);
    let dst = Ipv4Addr::new(tpdu[16], tpdu[17], tpdu[18], tpdu[19]);
    let udp = &tpdu[ihl..total_len];
    let (src_port, dst_port, payload) = parse_udp_segment(udp)?;
    let udp_checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if udp_checksum != 0 && checksum_udp_ipv4_including_checksum(src, dst, udp) != 0 {
        return Err(DataplaneTestkitError::invalid_packet(
            "invalid IPv4 UDP checksum",
        ));
    }
    Ok(DecodedTpdu {
        flow: InnerIpFlow::Ipv4 {
            src,
            dst,
            src_port,
            dst_port,
        },
        measurement: MeasurementHeader::decode(payload)?,
    })
}

fn decode_ipv6_measurement(tpdu: &[u8]) -> Result<DecodedTpdu, DataplaneTestkitError> {
    if tpdu.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN {
        return Err(DataplaneTestkitError::truncated("IPv6 UDP packet"));
    }
    if tpdu[6] != UDP_PROTOCOL {
        return Err(DataplaneTestkitError::invalid_packet(
            "IPv6 payload is not UDP",
        ));
    }
    let payload_len = usize::from(u16::from_be_bytes([tpdu[4], tpdu[5]]));
    let total_len =
        IPV6_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(DataplaneTestkitError::Overflow {
                field: "ipv6_total_len",
            })?;
    if total_len > tpdu.len() || payload_len < UDP_HEADER_LEN {
        return Err(DataplaneTestkitError::invalid_packet(
            "invalid IPv6 payload length",
        ));
    }

    let mut src_octets = [0u8; 16];
    src_octets.copy_from_slice(&tpdu[8..24]);
    let mut dst_octets = [0u8; 16];
    dst_octets.copy_from_slice(&tpdu[24..40]);
    let src = Ipv6Addr::from(src_octets);
    let dst = Ipv6Addr::from(dst_octets);
    let udp = &tpdu[IPV6_HEADER_LEN..total_len];
    if u16::from_be_bytes([udp[6], udp[7]]) == 0 {
        return Err(DataplaneTestkitError::invalid_packet(
            "IPv6 UDP checksum is zero",
        ));
    }
    if checksum_udp_ipv6_including_checksum(src, dst, udp) != 0 {
        return Err(DataplaneTestkitError::invalid_packet(
            "invalid IPv6 UDP checksum",
        ));
    }
    let (src_port, dst_port, payload) = parse_udp_segment(udp)?;
    Ok(DecodedTpdu {
        flow: InnerIpFlow::Ipv6 {
            src,
            dst,
            src_port,
            dst_port,
        },
        measurement: MeasurementHeader::decode(payload)?,
    })
}

fn parse_udp_segment(udp: &[u8]) -> Result<(u16, u16, &[u8]), DataplaneTestkitError> {
    if udp.len() < UDP_HEADER_LEN {
        return Err(DataplaneTestkitError::truncated("UDP header"));
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < UDP_HEADER_LEN || udp_len > udp.len() {
        return Err(DataplaneTestkitError::invalid_packet("invalid UDP length"));
    }
    Ok((src_port, dst_port, &udp[UDP_HEADER_LEN..udp_len]))
}

fn udp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(UDP_PROTOCOL);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    nonzero_checksum(&[&pseudo, udp])
}

fn udp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(UDP_PROTOCOL);
    nonzero_checksum(&[&pseudo, udp])
}

fn checksum_udp_ipv4_including_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(UDP_PROTOCOL);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    checksum(&[&pseudo, udp])
}

fn checksum_udp_ipv6_including_checksum(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(UDP_PROTOCOL);
    checksum(&[&pseudo, udp])
}

fn nonzero_checksum(parts: &[&[u8]]) -> u16 {
    match checksum(parts) {
        0 => 0xffff,
        value => value,
    }
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for chunk in &mut chunks {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
        }
        if let Some(last) = chunks.remainder().first() {
            sum = sum.wrapping_add(u32::from(*last) << 8);
        }
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
