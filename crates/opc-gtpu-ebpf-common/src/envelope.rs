//! Verifier-friendly bounds and checksum primitives for downlink GTP-U.

use crate::{
    ETH_HDR_LEN, ETH_P_IPV6, GTPU_MANDATORY_HDR_LEN, GTPU_UDP_PORT, IPV4_MIN_HDR_LEN, IPV6_HDR_LEN,
    UDP_HDR_LEN,
};

/// Maximum IPv4 header length, including options.
pub const IPV4_MAX_HDR_LEN: usize = 60;

/// Maximum number of IPv6 extension headers accepted before UDP.
///
/// RFC 8200 does not define a numeric chain limit. A fixed bound is required
/// for verifier-safe packet processing and keeps hostile chains from creating
/// unbounded work.
pub const IPV6_MAX_EXT_HEADERS: usize = 8;

/// Maximum TLVs accepted in one IPv6 options header.
///
/// Long runs of one-byte padding are legal on the wire but are not useful to
/// this GTP-U fast path. Bounding the option count keeps the shared parser
/// suitable for a verifier-bounded implementation.
pub const IPV6_MAX_OPTIONS_PER_HEADER: usize = 32;

/// IPv6 Next Header value for Hop-by-Hop Options.
pub const IPV6_NH_HOP_BY_HOP: u8 = 0;
/// IPv6 Next Header value for UDP.
pub const IPV6_NH_UDP: u8 = 17;
/// IPv6 Next Header value for Routing.
pub const IPV6_NH_ROUTING: u8 = 43;
/// IPv6 Next Header value for Fragment.
pub const IPV6_NH_FRAGMENT: u8 = 44;
/// IPv6 Next Header value for ESP.
pub const IPV6_NH_ESP: u8 = 50;
/// IPv6 Next Header value for AH.
pub const IPV6_NH_AUTHENTICATION: u8 = 51;
/// IPv6 Next Header value for No Next Header.
pub const IPV6_NH_NONE: u8 = 59;
/// IPv6 Next Header value for Destination Options.
pub const IPV6_NH_DESTINATION_OPTIONS: u8 = 60;

/// Stable, redaction-safe reason an outer GTP-U envelope was rejected.
///
/// Variants intentionally contain no addresses, TEIDs, payload bytes, lengths,
/// or checksum values. The eBPF datapath maps every variant to its single
/// bounded malformed-packet counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuEnvelopeError {
    /// The IPv4 version or IHL field is invalid.
    InvalidIpv4Header,
    /// IPv4 Total Length cannot contain its header, UDP, and mandatory GTP-U.
    InvalidIpv4TotalLength,
    /// IPv4 Total Length extends beyond the accessible packet.
    TruncatedIpv4Packet,
    /// The complete variable-IHL IPv4 header checksum is invalid.
    InvalidIpv4Checksum,
    /// UDP Length is smaller than the UDP header.
    InvalidUdpLength,
    /// UDP Length does not end exactly at IPv4 Total Length.
    InconsistentUdpBoundary,
    /// UDP checksum handling was neither proven omission, valid, nor verified.
    InvalidUdpChecksum,
    /// UDP Length cannot contain the mandatory GTP-U header.
    TruncatedGtpuHeader,
    /// GTP-U Length does not end exactly at the UDP payload boundary.
    InconsistentGtpuBoundary,
}

/// Stable, redaction-safe reason an IPv6 extension chain was rejected.
///
/// The variants intentionally carry no addresses, lengths, offsets, or packet
/// bytes, so they are safe for bounded diagnostics and counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6ExtensionError {
    /// The fixed IPv6 header is truncated or does not carry version 6.
    InvalidBaseHeader,
    /// Payload Length is zero; IPv6 jumbograms are outside this datapath.
    JumbogramUnsupported,
    /// The declared IPv6 payload extends beyond accessible packet bytes.
    TruncatedPacket,
    /// More than [`IPV6_MAX_EXT_HEADERS`] precede UDP.
    TooManyHeaders,
    /// A variable-length extension header is truncated or has an invalid size.
    MalformedHeader,
    /// An options header contains a truncated or malformed option TLV.
    MalformedOption,
    /// One options header exceeds [`IPV6_MAX_OPTIONS_PER_HEADER`].
    TooManyOptions,
    /// An unknown option has RFC 8200 discard action bits.
    DiscardRequiredOption,
    /// Hop-by-Hop Options appeared anywhere except immediately after IPv6.
    HopByHopNotFirst,
    /// Otherwise supported extension headers appeared in a non-canonical
    /// order that this fast path cannot safely process.
    InvalidHeaderOrder,
    /// More than one Routing header appeared.
    MultipleRoutingHeaders,
    /// More than one Fragment header appeared.
    MultipleFragmentHeaders,
    /// A non-atomic IPv6 fragment requires reassembly, which this fast path
    /// does not perform.
    FragmentUnsupported,
    /// A Routing header still has segments to visit and cannot be skipped.
    ActiveRoutingUnsupported,
    /// Deprecated Routing Type 0 cannot be processed or ignored.
    RoutingTypeZeroUnsupported,
    /// AH cannot be bypassed at a pre-IP-stack tc ingress hook.
    AuthenticationUnsupported,
    /// ESP prevents bounded discovery of the UDP header.
    EspUnsupported,
    /// No Next Header terminated the packet before UDP.
    NoNextHeader,
    /// A next-header protocol not supported by the GTP-U UDP path appeared.
    UnsupportedNextHeader,
    /// UDP Length is invalid or does not end at the IPv6 payload boundary.
    InvalidUdpBoundary,
    /// The mandatory IPv6 UDP checksum is zero or invalid.
    InvalidUdpChecksum,
    /// UDP cannot contain the mandatory GTP-U header.
    TruncatedGtpuHeader,
    /// GTP-U Length does not end exactly at the UDP payload boundary.
    InconsistentGtpuBoundary,
}

/// One verifier-friendly decision while walking an IPv6 extension chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6ExtensionStep {
    /// UDP begins at the current cursor.
    Udp,
    /// Skip one complete extension header and continue with `next_header`.
    Skip {
        /// Next Header value carried by the extension.
        next_header: u8,
        /// Exact extension-header length in bytes.
        header_len: u16,
        /// Whether the skipped header was an atomic Fragment header.
        atomic_fragment: bool,
    },
}

/// Classify one IPv6 extension-header step from its first eight bytes.
///
/// `available` is the number of bytes remaining in the declared IPv6 payload
/// at the current cursor. The caller owns ordering state: it must reject a
/// Hop-by-Hop header after the first step and a second Fragment header.
///
/// # Errors
///
/// Returns a fieldless [`Ipv6ExtensionError`] for malformed, unsupported, or
/// non-atomic fragment headers.
pub fn classify_ipv6_extension_step(
    next_header: u8,
    prefix: [u8; 8],
    available: usize,
) -> Result<Ipv6ExtensionStep, Ipv6ExtensionError> {
    if next_header == IPV6_NH_UDP {
        return Ok(Ipv6ExtensionStep::Udp);
    }
    match next_header {
        IPV6_NH_AUTHENTICATION => {
            return Err(Ipv6ExtensionError::AuthenticationUnsupported);
        }
        IPV6_NH_ESP => return Err(Ipv6ExtensionError::EspUnsupported),
        IPV6_NH_NONE => return Err(Ipv6ExtensionError::NoNextHeader),
        IPV6_NH_HOP_BY_HOP | IPV6_NH_ROUTING | IPV6_NH_FRAGMENT | IPV6_NH_DESTINATION_OPTIONS => {}
        _ => return Err(Ipv6ExtensionError::UnsupportedNextHeader),
    }
    if available < 8 {
        return Err(Ipv6ExtensionError::MalformedHeader);
    }
    let (header_len, atomic_fragment) = match next_header {
        IPV6_NH_HOP_BY_HOP | IPV6_NH_ROUTING | IPV6_NH_DESTINATION_OPTIONS => {
            let length = usize::from(prefix[1])
                .checked_add(1)
                .and_then(|units| units.checked_mul(8))
                .ok_or(Ipv6ExtensionError::MalformedHeader)?;
            (length, false)
        }
        IPV6_NH_FRAGMENT => {
            let fragment = u16::from_be_bytes([prefix[2], prefix[3]]);
            if fragment & 0xfff8 != 0 || fragment & 0x0001 != 0 {
                return Err(Ipv6ExtensionError::FragmentUnsupported);
            }
            (8, true)
        }
        _ => return Err(Ipv6ExtensionError::UnsupportedNextHeader),
    };
    if header_len > available {
        return Err(Ipv6ExtensionError::MalformedHeader);
    }
    let header_len = u16::try_from(header_len).map_err(|_| Ipv6ExtensionError::MalformedHeader)?;
    Ok(Ipv6ExtensionStep::Skip {
        next_header: prefix[0],
        header_len,
        atomic_fragment,
    })
}

/// Validate all bounded TLVs in a complete Hop-by-Hop or Destination Options
/// header.
///
/// Pad1 is one zero type octet. PadN data is ignored as RFC 8200 requires.
/// Unknown options with action bits `00` are safe to skip; every option requiring
/// discard or ICMP is rejected because decapsulation at tc ingress would
/// otherwise bypass the IPv6 stack's required action.
///
/// # Errors
///
/// Returns a fieldless [`Ipv6ExtensionError`] for non-canonical length,
/// truncated/malformed padding or TLVs, excessive option count, or a
/// discard-required unknown option.
pub fn validate_ipv6_options_header(header: &[u8]) -> Result<(), Ipv6ExtensionError> {
    if header.len() < 8 || !header.len().is_multiple_of(8) {
        return Err(Ipv6ExtensionError::MalformedHeader);
    }
    let expected = usize::from(header[1])
        .checked_add(1)
        .and_then(|units| units.checked_mul(8))
        .ok_or(Ipv6ExtensionError::MalformedHeader)?;
    if expected != header.len() {
        return Err(Ipv6ExtensionError::MalformedHeader);
    }

    let mut cursor = 2_usize;
    let mut options = 0_usize;
    while cursor < header.len() {
        if options == IPV6_MAX_OPTIONS_PER_HEADER {
            return Err(Ipv6ExtensionError::TooManyOptions);
        }
        let option_type = header[cursor];
        if option_type == 0 {
            cursor += 1;
            options += 1;
            continue;
        }
        let option_data_len = usize::from(
            *header
                .get(cursor + 1)
                .ok_or(Ipv6ExtensionError::MalformedOption)?,
        );
        let option_end = cursor
            .checked_add(2)
            .and_then(|start| start.checked_add(option_data_len))
            .ok_or(Ipv6ExtensionError::MalformedOption)?;
        let _option_data = header
            .get(cursor + 2..option_end)
            .ok_or(Ipv6ExtensionError::MalformedOption)?;
        if option_type != 1 && option_type >> 6 != 0 {
            return Err(Ipv6ExtensionError::DiscardRequiredOption);
        }
        cursor = option_end;
        options += 1;
    }
    Ok(())
}

/// Validate a complete Routing header that is safe to ignore at tc ingress.
///
/// Only headers with `Segments Left == 0` can be skipped. Routing Type 0 is
/// always rejected. The known Type 2 and Type 4 shapes receive additional
/// structural validation; unknown zero-segment types retain RFC 8200's
/// ignore-and-continue behavior after their declared boundary is validated.
///
/// # Errors
///
/// Returns a fieldless [`Ipv6ExtensionError`] for invalid length, active
/// routing, deprecated Type 0, or malformed known routing types.
pub fn validate_ipv6_routing_header(header: &[u8]) -> Result<(), Ipv6ExtensionError> {
    if header.len() < 8 || !header.len().is_multiple_of(8) {
        return Err(Ipv6ExtensionError::MalformedHeader);
    }
    let expected = usize::from(header[1])
        .checked_add(1)
        .and_then(|units| units.checked_mul(8))
        .ok_or(Ipv6ExtensionError::MalformedHeader)?;
    if expected != header.len() {
        return Err(Ipv6ExtensionError::MalformedHeader);
    }
    if header[3] != 0 {
        return Err(Ipv6ExtensionError::ActiveRoutingUnsupported);
    }
    match header[2] {
        0 => Err(Ipv6ExtensionError::RoutingTypeZeroUnsupported),
        // Mobile IPv6 Type 2: fixed four-byte reserved field plus one address.
        2 if header.len() != 24 || header[4..8].iter().any(|byte| *byte != 0) => {
            Err(Ipv6ExtensionError::MalformedHeader)
        }
        2 => Ok(()),
        // Segment Routing Type 4: the segment list must contain Last Entry + 1
        // complete IPv6 addresses. Optional TLVs may follow that list.
        4 => {
            let segment_bytes = usize::from(header[4])
                .checked_add(1)
                .and_then(|entries| entries.checked_mul(16))
                .ok_or(Ipv6ExtensionError::MalformedHeader)?;
            let minimum = 8_usize
                .checked_add(segment_bytes)
                .ok_or(Ipv6ExtensionError::MalformedHeader)?;
            if minimum > header.len() {
                Err(Ipv6ExtensionError::MalformedHeader)
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv6ExtensionChainBounds {
    ip_end: usize,
    udp_offset: usize,
    extension_headers: u8,
}

fn parse_ipv6_extension_chain(
    frame: &[u8],
) -> Result<Ipv6ExtensionChainBounds, Ipv6ExtensionError> {
    let base_end = ETH_HDR_LEN
        .checked_add(IPV6_HDR_LEN)
        .ok_or(Ipv6ExtensionError::InvalidBaseHeader)?;
    let ether_type = frame
        .get(12..14)
        .ok_or(Ipv6ExtensionError::InvalidBaseHeader)?;
    if ether_type != ETH_P_IPV6.to_be_bytes() {
        return Err(Ipv6ExtensionError::InvalidBaseHeader);
    }
    let base = frame
        .get(ETH_HDR_LEN..base_end)
        .ok_or(Ipv6ExtensionError::InvalidBaseHeader)?;
    if base[0] >> 4 != 6 {
        return Err(Ipv6ExtensionError::InvalidBaseHeader);
    }
    let payload_length = usize::from(u16::from_be_bytes([base[4], base[5]]));
    if payload_length == 0 {
        return Err(Ipv6ExtensionError::JumbogramUnsupported);
    }
    let ip_end = base_end
        .checked_add(payload_length)
        .ok_or(Ipv6ExtensionError::TruncatedPacket)?;
    if ip_end > frame.len() {
        return Err(Ipv6ExtensionError::TruncatedPacket);
    }

    let mut next_header = base[6];
    let mut cursor = base_end;
    let mut walked = 0_usize;
    let mut fragment_seen = false;
    let mut routing_seen = false;
    let mut pre_routing_destination_seen = false;
    let mut final_destination_seen = false;
    loop {
        if next_header == IPV6_NH_UDP {
            break;
        }
        if walked == IPV6_MAX_EXT_HEADERS {
            return Err(Ipv6ExtensionError::TooManyHeaders);
        }
        if next_header == IPV6_NH_HOP_BY_HOP && walked != 0 {
            return Err(Ipv6ExtensionError::HopByHopNotFirst);
        }
        if next_header == IPV6_NH_ROUTING && routing_seen {
            return Err(Ipv6ExtensionError::MultipleRoutingHeaders);
        }
        if next_header == IPV6_NH_FRAGMENT && fragment_seen {
            return Err(Ipv6ExtensionError::MultipleFragmentHeaders);
        }
        match next_header {
            IPV6_NH_ROUTING if fragment_seen || final_destination_seen => {
                return Err(Ipv6ExtensionError::InvalidHeaderOrder);
            }
            IPV6_NH_FRAGMENT
                if final_destination_seen || pre_routing_destination_seen && !routing_seen =>
            {
                return Err(Ipv6ExtensionError::InvalidHeaderOrder);
            }
            IPV6_NH_DESTINATION_OPTIONS if final_destination_seen => {
                return Err(Ipv6ExtensionError::InvalidHeaderOrder);
            }
            IPV6_NH_DESTINATION_OPTIONS if pre_routing_destination_seen && !routing_seen => {
                return Err(Ipv6ExtensionError::InvalidHeaderOrder);
            }
            _ => {}
        }
        let prefix_end = cursor
            .checked_add(8)
            .ok_or(Ipv6ExtensionError::MalformedHeader)?;
        let prefix: [u8; 8] = frame
            .get(cursor..prefix_end)
            .ok_or(Ipv6ExtensionError::MalformedHeader)?
            .try_into()
            .map_err(|_| Ipv6ExtensionError::MalformedHeader)?;
        let available = ip_end
            .checked_sub(cursor)
            .ok_or(Ipv6ExtensionError::MalformedHeader)?;
        match classify_ipv6_extension_step(next_header, prefix, available)? {
            Ipv6ExtensionStep::Udp => break,
            Ipv6ExtensionStep::Skip {
                next_header: following,
                header_len,
                atomic_fragment,
            } => {
                let header_end = cursor
                    .checked_add(usize::from(header_len))
                    .ok_or(Ipv6ExtensionError::MalformedHeader)?;
                let header = frame
                    .get(cursor..header_end)
                    .ok_or(Ipv6ExtensionError::MalformedHeader)?;
                match next_header {
                    IPV6_NH_HOP_BY_HOP | IPV6_NH_DESTINATION_OPTIONS => {
                        validate_ipv6_options_header(header)?;
                    }
                    IPV6_NH_ROUTING => validate_ipv6_routing_header(header)?,
                    _ => {}
                }
                match next_header {
                    IPV6_NH_ROUTING => routing_seen = true,
                    IPV6_NH_FRAGMENT => fragment_seen = true,
                    IPV6_NH_DESTINATION_OPTIONS if routing_seen || fragment_seen => {
                        final_destination_seen = true;
                    }
                    IPV6_NH_DESTINATION_OPTIONS => pre_routing_destination_seen = true,
                    _ => {}
                }
                cursor = header_end;
                next_header = following;
                fragment_seen |= atomic_fragment;
                walked += 1;
            }
        }
    }
    Ok(Ipv6ExtensionChainBounds {
        ip_end,
        udp_offset: cursor,
        extension_headers: u8::try_from(walked).map_err(|_| Ipv6ExtensionError::TooManyHeaders)?,
    })
}

/// Checked bounds of UDP nested after a bounded IPv6 extension chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6UdpEnvelopeBounds {
    ip_end: usize,
    udp_offset: usize,
    udp_end: usize,
    gtp_offset: usize,
    extension_headers: u8,
}

impl Ipv6UdpEnvelopeBounds {
    /// Parse an Ethernet-carried IPv6 packet through its exact UDP boundary.
    ///
    /// Legal layer-2 padding after the declared IPv6 payload is ignored.
    /// Atomic Fragment headers (`offset=0`, `M=0`) are accepted; every
    /// fragment requiring reassembly fails with
    /// [`Ipv6ExtensionError::FragmentUnsupported`].
    ///
    /// # Errors
    ///
    /// Returns a fieldless [`Ipv6ExtensionError`] for malformed declarations,
    /// unsupported chains, fragments requiring reassembly, or an inexact UDP
    /// boundary.
    pub fn parse(frame: &[u8]) -> Result<Self, Ipv6ExtensionError> {
        let chain = parse_ipv6_extension_chain(frame)?;
        let base_end = ETH_HDR_LEN + IPV6_HDR_LEN;
        let base = frame
            .get(ETH_HDR_LEN..base_end)
            .ok_or(Ipv6ExtensionError::InvalidBaseHeader)?;
        let udp_header_end = chain
            .udp_offset
            .checked_add(UDP_HDR_LEN)
            .ok_or(Ipv6ExtensionError::InvalidUdpBoundary)?;
        let udp_header = frame
            .get(chain.udp_offset..udp_header_end)
            .ok_or(Ipv6ExtensionError::InvalidUdpBoundary)?;
        let udp_length = usize::from(u16::from_be_bytes([udp_header[4], udp_header[5]]));
        let minimum = UDP_HDR_LEN
            .checked_add(GTPU_MANDATORY_HDR_LEN)
            .ok_or(Ipv6ExtensionError::TruncatedGtpuHeader)?;
        if udp_length < minimum {
            return Err(Ipv6ExtensionError::TruncatedGtpuHeader);
        }
        let udp_end = chain
            .udp_offset
            .checked_add(udp_length)
            .ok_or(Ipv6ExtensionError::InvalidUdpBoundary)?;
        if udp_end != chain.ip_end {
            return Err(Ipv6ExtensionError::InvalidUdpBoundary);
        }
        let udp = frame
            .get(chain.udp_offset..udp_end)
            .ok_or(Ipv6ExtensionError::InvalidUdpBoundary)?;
        let source: [u8; 16] = base[8..24]
            .try_into()
            .map_err(|_| Ipv6ExtensionError::InvalidBaseHeader)?;
        let destination: [u8; 16] = base[24..40]
            .try_into()
            .map_err(|_| Ipv6ExtensionError::InvalidBaseHeader)?;
        if !udp_ipv6_checksum_is_valid(source, destination, udp) {
            return Err(Ipv6ExtensionError::InvalidUdpChecksum);
        }
        let gtp_offset = chain
            .udp_offset
            .checked_add(UDP_HDR_LEN)
            .ok_or(Ipv6ExtensionError::TruncatedGtpuHeader)?;
        Ok(Self {
            ip_end: chain.ip_end,
            udp_offset: chain.udp_offset,
            udp_end,
            gtp_offset,
            extension_headers: chain.extension_headers,
        })
    }

    /// Exclusive IPv6 packet end derived from Payload Length.
    #[must_use]
    pub const fn ip_end(self) -> usize {
        self.ip_end
    }

    /// Offset of UDP after the complete extension chain.
    #[must_use]
    pub const fn udp_offset(self) -> usize {
        self.udp_offset
    }

    /// Exclusive UDP end, equal to the declared IPv6 end.
    #[must_use]
    pub const fn udp_end(self) -> usize {
        self.udp_end
    }

    /// Offset of the mandatory GTP-U header.
    #[must_use]
    pub const fn gtp_offset(self) -> usize {
        self.gtp_offset
    }

    /// Number of accepted extension headers before UDP.
    #[must_use]
    pub const fn extension_headers(self) -> u8 {
        self.extension_headers
    }

    /// Validate the exact nested GTP-U boundary.
    ///
    /// # Errors
    ///
    /// Returns [`Ipv6ExtensionError::InconsistentGtpuBoundary`] unless the
    /// declared GTP-U message ends exactly at UDP.
    pub fn validate_gtpu_length(self, gtpu_length: u16) -> Result<usize, Ipv6ExtensionError> {
        let gtp_end = self
            .gtp_offset
            .checked_add(GTPU_MANDATORY_HDR_LEN)
            .and_then(|end| end.checked_add(usize::from(gtpu_length)))
            .ok_or(Ipv6ExtensionError::InconsistentGtpuBoundary)?;
        if gtp_end != self.udp_end {
            return Err(Ipv6ExtensionError::InconsistentGtpuBoundary);
        }
        Ok(gtp_end)
    }
}

/// Shared-hook action after bounded IPv6 GTP-U envelope triage.
///
/// This prevents a GTP-U classifier attached to a shared interface from
/// becoming a general IPv6 firewall. Unsupported protocols, AH/ESP, packets
/// requiring IPv6 reassembly, and extension chains that cannot prove a UDP
/// destination port are passed to the host stack. Strict malformed handling
/// begins only after bounded parsing proves destination UDP/2152.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6GtpuIngress {
    /// The packet is unrelated or cannot safely be classified as GTP-U.
    PassToStack,
    /// UDP/2152 carries one exact, checksummed GTP-U envelope.
    Candidate(Ipv6UdpEnvelopeBounds),
    /// UDP/2152 was proven, but its UDP/GTP-U envelope is malformed.
    RejectCandidate(Ipv6ExtensionError),
}

/// Classify an IPv6 frame without dropping unrelated traffic on a shared hook.
#[must_use]
pub fn classify_ipv6_gtpu_ingress(frame: &[u8]) -> Ipv6GtpuIngress {
    let chain = match parse_ipv6_extension_chain(frame) {
        Ok(chain) => chain,
        Err(_) => return Ipv6GtpuIngress::PassToStack,
    };
    let destination_end = match chain.udp_offset.checked_add(4) {
        Some(end) => end,
        None => return Ipv6GtpuIngress::PassToStack,
    };
    if destination_end > chain.ip_end {
        return Ipv6GtpuIngress::PassToStack;
    }
    let Some(udp_prefix) = frame.get(chain.udp_offset..destination_end) else {
        return Ipv6GtpuIngress::PassToStack;
    };
    if u16::from_be_bytes([udp_prefix[2], udp_prefix[3]]) != GTPU_UDP_PORT {
        return Ipv6GtpuIngress::PassToStack;
    }
    let bounds = match Ipv6UdpEnvelopeBounds::parse(frame) {
        Ok(bounds) => bounds,
        Err(error) => return Ipv6GtpuIngress::RejectCandidate(error),
    };
    let length_end = match bounds.gtp_offset.checked_add(4) {
        Some(end) => end,
        None => {
            return Ipv6GtpuIngress::RejectCandidate(Ipv6ExtensionError::TruncatedGtpuHeader);
        }
    };
    let Some(gtpu_prefix) = frame.get(bounds.gtp_offset..length_end) else {
        return Ipv6GtpuIngress::RejectCandidate(Ipv6ExtensionError::TruncatedGtpuHeader);
    };
    let gtpu_length = u16::from_be_bytes([gtpu_prefix[2], gtpu_prefix[3]]);
    match bounds.validate_gtpu_length(gtpu_length) {
        Ok(_) => Ipv6GtpuIngress::Candidate(bounds),
        Err(error) => Ipv6GtpuIngress::RejectCandidate(error),
    }
}

/// Checked bounds of a complete outer IPv4 packet carrying UDP and GTP-U.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4EnvelopeBounds {
    ip_header_len: usize,
    ip_end: usize,
    udp_offset: usize,
}

impl Ipv4EnvelopeBounds {
    /// Validate IPv4 version, IHL, Total Length, and accessible-packet bounds.
    ///
    /// `skb_len` includes the Ethernet header and any legal layer-2 padding.
    /// The returned `ip_end` is derived only from IPv4 Total Length, so padding
    /// is never admitted to a later UDP or GTP-U boundary.
    ///
    /// # Errors
    ///
    /// Returns a fieldless [`GtpuEnvelopeError`] when the IPv4 declaration is
    /// malformed, too small for UDP plus mandatory GTP-U, or truncated.
    pub fn parse(
        skb_len: usize,
        version_ihl: u8,
        total_length: u16,
    ) -> Result<Self, GtpuEnvelopeError> {
        let ihl_words = usize::from(version_ihl & 0x0f);
        if version_ihl >> 4 != 4 || ihl_words < 5 {
            return Err(GtpuEnvelopeError::InvalidIpv4Header);
        }
        let ip_header_len = ihl_words
            .checked_mul(4)
            .ok_or(GtpuEnvelopeError::InvalidIpv4Header)?;
        if !(IPV4_MIN_HDR_LEN..=IPV4_MAX_HDR_LEN).contains(&ip_header_len) {
            return Err(GtpuEnvelopeError::InvalidIpv4Header);
        }
        let minimum_total_length = ip_header_len
            .checked_add(UDP_HDR_LEN)
            .and_then(|length| length.checked_add(GTPU_MANDATORY_HDR_LEN))
            .ok_or(GtpuEnvelopeError::InvalidIpv4TotalLength)?;
        let total_length = usize::from(total_length);
        if total_length < minimum_total_length {
            return Err(GtpuEnvelopeError::InvalidIpv4TotalLength);
        }
        let ip_end = ETH_HDR_LEN
            .checked_add(total_length)
            .ok_or(GtpuEnvelopeError::InvalidIpv4TotalLength)?;
        if ip_end > skb_len {
            return Err(GtpuEnvelopeError::TruncatedIpv4Packet);
        }
        let udp_offset = ETH_HDR_LEN
            .checked_add(ip_header_len)
            .ok_or(GtpuEnvelopeError::InvalidIpv4Header)?;
        Ok(Self {
            ip_header_len,
            ip_end,
            udp_offset,
        })
    }

    /// Complete IPv4 header length, including options.
    #[must_use]
    pub const fn ip_header_len(self) -> usize {
        self.ip_header_len
    }

    /// Exclusive IPv4 packet end derived from Total Length.
    #[must_use]
    pub const fn ip_end(self) -> usize {
        self.ip_end
    }

    /// Offset of the UDP header from the Ethernet frame start.
    #[must_use]
    pub const fn udp_offset(self) -> usize {
        self.udp_offset
    }
}

/// Checked bounds of UDP nested exactly inside an outer IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpEnvelopeBounds {
    ipv4: Ipv4EnvelopeBounds,
    udp_end: usize,
    gtp_offset: usize,
}

impl UdpEnvelopeBounds {
    /// Validate UDP Length and its exact relationship to IPv4 Total Length.
    ///
    /// # Errors
    ///
    /// Returns a fieldless [`GtpuEnvelopeError`] when UDP is shorter than its
    /// header, cannot contain mandatory GTP-U, overflows, or does not end at
    /// the declared IPv4 boundary.
    pub fn parse(ipv4: Ipv4EnvelopeBounds, udp_length: u16) -> Result<Self, GtpuEnvelopeError> {
        let udp_length = usize::from(udp_length);
        if udp_length < UDP_HDR_LEN {
            return Err(GtpuEnvelopeError::InvalidUdpLength);
        }
        let minimum_gtpu_length = UDP_HDR_LEN
            .checked_add(GTPU_MANDATORY_HDR_LEN)
            .ok_or(GtpuEnvelopeError::TruncatedGtpuHeader)?;
        if udp_length < minimum_gtpu_length {
            return Err(GtpuEnvelopeError::TruncatedGtpuHeader);
        }
        let udp_end = ipv4
            .udp_offset
            .checked_add(udp_length)
            .ok_or(GtpuEnvelopeError::InconsistentUdpBoundary)?;
        if udp_end != ipv4.ip_end {
            return Err(GtpuEnvelopeError::InconsistentUdpBoundary);
        }
        let gtp_offset = ipv4
            .udp_offset
            .checked_add(UDP_HDR_LEN)
            .ok_or(GtpuEnvelopeError::TruncatedGtpuHeader)?;
        Ok(Self {
            ipv4,
            udp_end,
            gtp_offset,
        })
    }

    /// Checked outer IPv4 bounds.
    #[must_use]
    pub const fn ipv4(self) -> Ipv4EnvelopeBounds {
        self.ipv4
    }

    /// Exclusive UDP end, equal to the declared IPv4 end.
    #[must_use]
    pub const fn udp_end(self) -> usize {
        self.udp_end
    }

    /// Offset of the mandatory GTP-U header.
    #[must_use]
    pub const fn gtp_offset(self) -> usize {
        self.gtp_offset
    }
}

/// Checked exact nesting of GTP-U inside UDP inside IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpuEnvelopeBounds {
    udp: UdpEnvelopeBounds,
    gtp_end: usize,
}

impl GtpuEnvelopeBounds {
    /// Validate the TS 29.281 GTP-U Length field against the UDP payload end.
    ///
    /// # Errors
    ///
    /// Returns [`GtpuEnvelopeError::InconsistentGtpuBoundary`] unless the
    /// mandatory eight-byte header plus the declared post-header length ends
    /// exactly at the UDP and IPv4 boundary.
    pub fn parse(udp: UdpEnvelopeBounds, gtpu_length: u16) -> Result<Self, GtpuEnvelopeError> {
        let gtp_end = udp
            .gtp_offset
            .checked_add(GTPU_MANDATORY_HDR_LEN)
            .and_then(|end| end.checked_add(usize::from(gtpu_length)))
            .ok_or(GtpuEnvelopeError::InconsistentGtpuBoundary)?;
        if gtp_end != udp.udp_end {
            return Err(GtpuEnvelopeError::InconsistentGtpuBoundary);
        }
        Ok(Self { udp, gtp_end })
    }

    /// Checked UDP bounds.
    #[must_use]
    pub const fn udp(self) -> UdpEnvelopeBounds {
        self.udp
    }

    /// Exclusive GTP-U end, equal to both the UDP and IPv4 ends.
    #[must_use]
    pub const fn gtp_end(self) -> usize {
        self.gtp_end
    }
}

/// How a received IPv4 UDP checksum must be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpChecksumDisposition {
    /// A zero IPv4 UDP checksum is legally omitted by RFC 768, and the caller
    /// has proved that no partial checksum operation remains pending.
    Omitted,
    /// The kernel positively reports `CHECKSUM_UNNECESSARY` for this skb.
    KernelVerified,
    /// Packet bytes must be validated in software before decapsulation.
    SoftwareRequired,
}

/// Evidence available for classifying one received UDP checksum field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpChecksumEvidence {
    /// The caller proved that no checksum offload operation remains pending.
    ///
    /// Byte-only parsers have this evidence inherently. A live skb caller must
    /// independently exclude `CHECKSUM_PARTIAL` before selecting this variant.
    NoPendingOffload,
    /// The kernel positively authenticated the current checksum layer.
    KernelVerified,
    /// The checksum bytes are not authenticated and offload state is unresolved.
    ///
    /// This includes helper errors and any live skb state that may still be
    /// `CHECKSUM_PARTIAL`.
    Unverified,
}

/// Classify an IPv4 UDP checksum from explicit checksum-state evidence.
///
/// A zero field is classified as legal omission only with
/// [`UdpChecksumEvidence::NoPendingOffload`]. In particular, callers must not
/// treat a failed `CHECKSUM_UNNECESSARY` query as proof of omission because it
/// does not distinguish `CHECKSUM_NONE` from `CHECKSUM_PARTIAL`.
#[must_use]
pub const fn classify_udp_checksum(
    checksum: u16,
    evidence: UdpChecksumEvidence,
) -> UdpChecksumDisposition {
    match evidence {
        UdpChecksumEvidence::KernelVerified => UdpChecksumDisposition::KernelVerified,
        UdpChecksumEvidence::NoPendingOffload if checksum == 0 => UdpChecksumDisposition::Omitted,
        UdpChecksumEvidence::NoPendingOffload | UdpChecksumEvidence::Unverified => {
            UdpChecksumDisposition::SoftwareRequired
        }
    }
}

/// Return whether a checksum-helper accumulator includes a valid checksum.
///
/// This folds the `u32` ones-complement sum returned by `bpf_csum_diff`.
#[must_use]
pub const fn internet_checksum_sum_is_valid(sum: u32) -> bool {
    let first = (sum & 0xffff) + (sum >> 16);
    let second = (first & 0xffff) + (first >> 16);
    second == 0xffff
}

fn add_checksum_word(sum: u32, word: u16) -> u32 {
    let expanded = sum + u32::from(word);
    (expanded & 0xffff) + (expanded >> 16)
}

fn add_checksum_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut offset = 0;
    while offset + 1 < bytes.len() {
        sum = add_checksum_word(sum, u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
        offset += 2;
    }
    if offset < bytes.len() {
        sum = add_checksum_word(sum, u16::from(bytes[offset]) << 8);
    }
    sum
}

fn add_checksum_contiguous_segments(mut sum: u32, first: &[u8], second: &[u8]) -> u32 {
    if first.len().is_multiple_of(2) {
        sum = add_checksum_bytes(sum, first);
        return add_checksum_bytes(sum, second);
    }

    let paired_end = first.len() - 1;
    sum = add_checksum_bytes(sum, &first[..paired_end]);
    if let Some((&next, remainder)) = second.split_first() {
        sum = add_checksum_word(sum, u16::from_be_bytes([first[paired_end], next]));
        add_checksum_bytes(sum, remainder)
    } else {
        add_checksum_word(sum, u16::from(first[paired_end]) << 8)
    }
}

fn checksum_from_sum(sum: u32) -> u16 {
    let folded = (sum & 0xffff) + (sum >> 16);
    !(folded as u16)
}

/// Compute an RFC 1071 Internet checksum over arbitrary bytes.
///
/// An odd final octet is padded on the right with zero. To verify a header,
/// call this function with its checksum field intact and require zero.
#[must_use]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    checksum_from_sum(add_checksum_bytes(0, bytes))
}

/// Compute the IPv4 UDP checksum for a UDP header and payload.
///
/// `udp` must contain exactly the UDP Length bytes and its checksum field must
/// be zero. The IPv4 pseudo-header is included. A computed zero is encoded as
/// `0xffff`, as required by RFC 768 to distinguish it from checksum omission.
/// Returns `None` when the slice cannot be represented by UDP Length.
#[must_use]
pub fn udp_ipv4_checksum(source: [u8; 4], destination: [u8; 4], udp: &[u8]) -> Option<u16> {
    let length = u16::try_from(udp.len()).ok()?;
    let mut sum = add_checksum_bytes(0, &source);
    sum = add_checksum_bytes(sum, &destination);
    sum = add_checksum_word(sum, u16::from(17_u8));
    sum = add_checksum_word(sum, length);
    sum = add_checksum_bytes(sum, udp);
    let checksum = checksum_from_sum(sum);
    Some(if checksum == 0 { 0xffff } else { checksum })
}

/// Verify a non-zero IPv4 UDP checksum over its exact declared bytes.
///
/// A zero checksum is not accepted here; callers must first classify it as
/// [`UdpChecksumDisposition::Omitted`]. Oversized slices fail closed.
#[must_use]
pub fn udp_ipv4_checksum_is_valid(source: [u8; 4], destination: [u8; 4], udp: &[u8]) -> bool {
    let Ok(length) = u16::try_from(udp.len()) else {
        return false;
    };
    if udp.len() < UDP_HDR_LEN || (udp[6] == 0 && udp[7] == 0) {
        return false;
    }
    let mut sum = add_checksum_bytes(0, &source);
    sum = add_checksum_bytes(sum, &destination);
    sum = add_checksum_word(sum, u16::from(17_u8));
    sum = add_checksum_word(sum, length);
    sum = add_checksum_bytes(sum, udp);
    internet_checksum_sum_is_valid(sum)
}

/// Compute the mandatory IPv6 UDP checksum over two contiguous segments.
///
/// `udp_prefix` starts with the complete eight-byte UDP header and has a zero
/// checksum field. `payload` immediately follows it. The two lengths together
/// must equal the UDP Length encoded in `udp_prefix`. A computed zero is
/// transmitted as `0xffff` per RFC 8200 section 8.1.
#[must_use]
pub fn udp_ipv6_checksum_segments(
    source: [u8; 16],
    destination: [u8; 16],
    udp_prefix: &[u8],
    payload: &[u8],
) -> Option<u16> {
    if udp_prefix.len() < UDP_HDR_LEN
        || udp_prefix.get(6..8) != Some(&[0, 0])
        || udp_prefix.len().checked_add(payload.len())? > usize::from(u16::MAX)
    {
        return None;
    }
    let length = udp_prefix.len().checked_add(payload.len())?;
    let declared = usize::from(u16::from_be_bytes([udp_prefix[4], udp_prefix[5]]));
    if length != declared {
        return None;
    }
    let length = u32::try_from(length).ok()?;
    let mut sum = add_checksum_bytes(0, &source);
    sum = add_checksum_bytes(sum, &destination);
    sum = add_checksum_word(sum, (length >> 16) as u16);
    sum = add_checksum_word(sum, length as u16);
    sum = add_checksum_word(sum, u16::from(IPV6_NH_UDP));
    sum = add_checksum_contiguous_segments(sum, udp_prefix, payload);
    let checksum = checksum_from_sum(sum);
    Some(if checksum == 0 { 0xffff } else { checksum })
}

/// Compute the mandatory IPv6 UDP checksum over one exact UDP datagram.
#[must_use]
pub fn udp_ipv6_checksum(source: [u8; 16], destination: [u8; 16], udp: &[u8]) -> Option<u16> {
    udp_ipv6_checksum_segments(source, destination, udp, &[])
}

/// Verify a mandatory non-zero IPv6 UDP checksum.
#[must_use]
pub fn udp_ipv6_checksum_is_valid(source: [u8; 16], destination: [u8; 16], udp: &[u8]) -> bool {
    if udp.len() < UDP_HDR_LEN
        || udp.get(6..8) == Some(&[0, 0])
        || udp.len() > usize::from(u16::MAX)
        || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len()
    {
        return false;
    }
    let length = udp.len() as u32;
    let mut sum = add_checksum_bytes(0, &source);
    sum = add_checksum_bytes(sum, &destination);
    sum = add_checksum_word(sum, (length >> 16) as u16);
    sum = add_checksum_word(sum, length as u16);
    sum = add_checksum_word(sum, u16::from(IPV6_NH_UDP));
    sum = add_checksum_bytes(sum, udp);
    internet_checksum_sum_is_valid(sum)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;

    const SOURCE: [u8; 4] = [192, 0, 2, 1];
    const DESTINATION: [u8; 4] = [198, 51, 100, 2];
    const SOURCE_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
    const DESTINATION_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2];

    fn read_u16(frame: &[u8], offset: usize) -> Result<u16, GtpuEnvelopeError> {
        let bytes = frame
            .get(offset..offset + 2)
            .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn validate_frame(
        frame: &[u8],
        kernel_verified_udp: bool,
    ) -> Result<GtpuEnvelopeBounds, GtpuEnvelopeError> {
        let version_ihl = *frame
            .get(ETH_HDR_LEN)
            .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
        let total_length = read_u16(frame, ETH_HDR_LEN + 2)?;
        let ipv4 = Ipv4EnvelopeBounds::parse(frame.len(), version_ihl, total_length)?;
        let header_end = ETH_HDR_LEN
            .checked_add(ipv4.ip_header_len())
            .ok_or(GtpuEnvelopeError::InvalidIpv4Header)?;
        let header = frame
            .get(ETH_HDR_LEN..header_end)
            .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
        if internet_checksum(header) != 0 {
            return Err(GtpuEnvelopeError::InvalidIpv4Checksum);
        }
        let udp_length = read_u16(frame, ipv4.udp_offset() + 4)?;
        let udp = UdpEnvelopeBounds::parse(ipv4, udp_length)?;
        let udp_checksum = read_u16(frame, ipv4.udp_offset() + 6)?;
        let checksum_evidence = if kernel_verified_udp {
            UdpChecksumEvidence::KernelVerified
        } else {
            // This parser owns complete frame bytes rather than a live skb, so
            // no pending kernel checksum operation exists.
            UdpChecksumEvidence::NoPendingOffload
        };
        if matches!(
            classify_udp_checksum(udp_checksum, checksum_evidence),
            UdpChecksumDisposition::SoftwareRequired
        ) {
            let udp_bytes = frame
                .get(ipv4.udp_offset()..udp.udp_end())
                .ok_or(GtpuEnvelopeError::InconsistentUdpBoundary)?;
            let source = frame
                .get(ETH_HDR_LEN + 12..ETH_HDR_LEN + 16)
                .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
            let destination = frame
                .get(ETH_HDR_LEN + 16..ETH_HDR_LEN + 20)
                .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
            if !udp_ipv4_checksum_is_valid(
                [source[0], source[1], source[2], source[3]],
                [
                    destination[0],
                    destination[1],
                    destination[2],
                    destination[3],
                ],
                udp_bytes,
            ) {
                return Err(GtpuEnvelopeError::InvalidUdpChecksum);
            }
        }
        let gtpu_length = read_u16(frame, udp.gtp_offset() + 2)?;
        GtpuEnvelopeBounds::parse(udp, gtpu_length)
    }

    fn build_frame(
        ip_options: &[u8],
        gtpu_body: &[u8],
        checksum_udp: bool,
        padding_len: usize,
    ) -> Vec<u8> {
        assert_eq!(ip_options.len() % 4, 0);
        assert!(ip_options.len() <= IPV4_MAX_HDR_LEN - IPV4_MIN_HDR_LEN);
        let ip_header_len = IPV4_MIN_HDR_LEN + ip_options.len();
        let gtpu_length = GTPU_MANDATORY_HDR_LEN + gtpu_body.len();
        let udp_length = UDP_HDR_LEN + gtpu_length;
        let ip_total_length = ip_header_len + udp_length;
        let mut frame = vec![0_u8; ETH_HDR_LEN + ip_total_length + padding_len];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = ETH_HDR_LEN;
        frame[ip] = 0x40 | u8::try_from(ip_header_len / 4).unwrap();
        frame[ip + 2..ip + 4]
            .copy_from_slice(&u16::try_from(ip_total_length).unwrap().to_be_bytes());
        frame[ip + 8] = 64;
        frame[ip + 9] = 17;
        frame[ip + 12..ip + 16].copy_from_slice(&SOURCE);
        frame[ip + 16..ip + 20].copy_from_slice(&DESTINATION);
        frame[ip + IPV4_MIN_HDR_LEN..ip + ip_header_len].copy_from_slice(ip_options);
        let udp = ip + ip_header_len;
        frame[udp..udp + 2].copy_from_slice(&2152_u16.to_be_bytes());
        frame[udp + 2..udp + 4].copy_from_slice(&2152_u16.to_be_bytes());
        frame[udp + 4..udp + 6].copy_from_slice(&u16::try_from(udp_length).unwrap().to_be_bytes());
        let gtpu = udp + UDP_HDR_LEN;
        frame[gtpu] = 0x30;
        frame[gtpu + 1] = 0xff;
        frame[gtpu + 2..gtpu + 4]
            .copy_from_slice(&u16::try_from(gtpu_body.len()).unwrap().to_be_bytes());
        frame[gtpu + 4..gtpu + 8].copy_from_slice(&0x1020_3040_u32.to_be_bytes());
        frame[gtpu + GTPU_MANDATORY_HDR_LEN..gtpu + gtpu_length].copy_from_slice(gtpu_body);

        let ip_checksum = internet_checksum(&frame[ip..udp]);
        frame[ip + 10..ip + 12].copy_from_slice(&ip_checksum.to_be_bytes());
        if checksum_udp {
            let checksum =
                udp_ipv4_checksum(SOURCE, DESTINATION, &frame[udp..udp + udp_length]).unwrap();
            frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
        }
        frame
    }

    fn refresh_ip_checksum(frame: &mut [u8]) {
        let ip = ETH_HDR_LEN;
        let header_len = usize::from(frame[ip] & 0x0f) * 4;
        frame[ip + 10..ip + 12].fill(0);
        let checksum = internet_checksum(&frame[ip..ip + header_len]);
        frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    }

    fn refresh_udp_checksum(frame: &mut [u8]) {
        let ip = ETH_HDR_LEN;
        let header_len = usize::from(frame[ip] & 0x0f) * 4;
        let udp = ip + header_len;
        let udp_length = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
        frame[udp + 6..udp + 8].fill(0);
        let checksum =
            udp_ipv4_checksum(SOURCE, DESTINATION, &frame[udp..udp + udp_length]).unwrap();
        frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
    }

    fn build_ipv6_frame(
        first_next_header: u8,
        extension_headers: &[u8],
        gtpu_body: &[u8],
        destination_port: u16,
        padding_len: usize,
    ) -> Vec<u8> {
        let gtpu_length = GTPU_MANDATORY_HDR_LEN + gtpu_body.len();
        let udp_length = UDP_HDR_LEN + gtpu_length;
        let payload_length = extension_headers.len() + udp_length;
        let mut frame = vec![0_u8; ETH_HDR_LEN + IPV6_HDR_LEN + payload_length + padding_len];
        frame[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        let ip = ETH_HDR_LEN;
        frame[ip] = 0x60;
        frame[ip + 4..ip + 6]
            .copy_from_slice(&u16::try_from(payload_length).unwrap().to_be_bytes());
        frame[ip + 6] = first_next_header;
        frame[ip + 7] = 64;
        frame[ip + 8..ip + 24].copy_from_slice(&SOURCE_V6);
        frame[ip + 24..ip + 40].copy_from_slice(&DESTINATION_V6);
        let extensions = ip + IPV6_HDR_LEN;
        frame[extensions..extensions + extension_headers.len()].copy_from_slice(extension_headers);
        let udp = extensions + extension_headers.len();
        frame[udp..udp + 2].copy_from_slice(&21_152_u16.to_be_bytes());
        frame[udp + 2..udp + 4].copy_from_slice(&destination_port.to_be_bytes());
        frame[udp + 4..udp + 6].copy_from_slice(&u16::try_from(udp_length).unwrap().to_be_bytes());
        let gtpu = udp + UDP_HDR_LEN;
        frame[gtpu] = 0x30;
        frame[gtpu + 1] = 0xff;
        frame[gtpu + 2..gtpu + 4]
            .copy_from_slice(&u16::try_from(gtpu_body.len()).unwrap().to_be_bytes());
        frame[gtpu + 4..gtpu + 8].copy_from_slice(&0x1020_3040_u32.to_be_bytes());
        frame[gtpu + GTPU_MANDATORY_HDR_LEN..gtpu + gtpu_length].copy_from_slice(gtpu_body);
        let checksum =
            udp_ipv6_checksum(SOURCE_V6, DESTINATION_V6, &frame[udp..udp + udp_length]).unwrap();
        frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn refresh_ipv6_udp_checksum(frame: &mut [u8]) {
        let chain = parse_ipv6_extension_chain(frame).unwrap();
        let udp_length = usize::from(u16::from_be_bytes([
            frame[chain.udp_offset + 4],
            frame[chain.udp_offset + 5],
        ]));
        frame[chain.udp_offset + 6..chain.udp_offset + 8].fill(0);
        let checksum = udp_ipv6_checksum(
            SOURCE_V6,
            DESTINATION_V6,
            &frame[chain.udp_offset..chain.udp_offset + udp_length],
        )
        .unwrap();
        frame[chain.udp_offset + 6..chain.udp_offset + 8].copy_from_slice(&checksum.to_be_bytes());
    }

    #[test]
    fn ipv6_minimum_and_safe_extension_chain_have_exact_checked_bounds() {
        let minimum = build_ipv6_frame(IPV6_NH_UDP, &[], &[0x60, 1, 2, 3], GTPU_UDP_PORT, 12);
        let minimum_bounds = Ipv6UdpEnvelopeBounds::parse(&minimum).unwrap();
        assert_eq!(minimum_bounds.extension_headers(), 0);
        assert_eq!(minimum_bounds.ip_end() + 12, minimum.len());
        assert_eq!(
            classify_ipv6_gtpu_ingress(&minimum),
            Ipv6GtpuIngress::Candidate(minimum_bounds)
        );

        let extensions = [
            // Hop-by-Hop: Router Alert plus a zero-length PadN.
            IPV6_NH_ROUTING,
            0,
            5,
            2,
            0,
            0,
            1,
            0,
            // Unknown Routing type with Segments Left zero.
            IPV6_NH_FRAGMENT,
            0,
            253,
            0,
            0,
            0,
            0,
            0,
            // Atomic Fragment. Reserved octet/bits are receiver-ignored.
            IPV6_NH_DESTINATION_OPTIONS,
            0xa5,
            0,
            0x06,
            0x10,
            0x20,
            0x30,
            0x40,
            // Final Destination Options: six Pad1 octets.
            IPV6_NH_UDP,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let extended = build_ipv6_frame(
            IPV6_NH_HOP_BY_HOP,
            &extensions,
            &[0x60, 4, 5, 6],
            GTPU_UDP_PORT,
            0,
        );
        let bounds = Ipv6UdpEnvelopeBounds::parse(&extended).unwrap();
        assert_eq!(bounds.extension_headers(), 4);
        assert_eq!(bounds.ip_end(), extended.len());
    }

    #[test]
    fn ipv6_parser_rejects_wrong_ether_type_and_real_fragments() {
        let mut wrong_ether_type = build_ipv6_frame(IPV6_NH_UDP, &[], &[0x60], GTPU_UDP_PORT, 0);
        wrong_ether_type[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        assert_eq!(
            Ipv6UdpEnvelopeBounds::parse(&wrong_ether_type),
            Err(Ipv6ExtensionError::InvalidBaseHeader)
        );

        for fragment_field in [[0_u8, 1], [0, 8]] {
            let fragment = [
                IPV6_NH_UDP,
                0xa5,
                fragment_field[0],
                fragment_field[1],
                0,
                0,
                0,
                1,
            ];
            let frame = build_ipv6_frame(IPV6_NH_FRAGMENT, &fragment, &[0x60], GTPU_UDP_PORT, 0);
            assert_eq!(
                Ipv6UdpEnvelopeBounds::parse(&frame),
                Err(Ipv6ExtensionError::FragmentUnsupported)
            );
            assert_eq!(
                classify_ipv6_gtpu_ingress(&frame),
                Ipv6GtpuIngress::PassToStack
            );
        }
    }

    #[test]
    fn ipv6_options_routing_and_authentication_never_bypass_required_processing() {
        let discard_option = [IPV6_NH_UDP, 0, 0x40, 0, 0, 0, 0, 0];
        let frame = build_ipv6_frame(
            IPV6_NH_HOP_BY_HOP,
            &discard_option,
            &[0x60],
            GTPU_UDP_PORT,
            0,
        );
        assert_eq!(
            Ipv6UdpEnvelopeBounds::parse(&frame),
            Err(Ipv6ExtensionError::DiscardRequiredOption)
        );
        assert_eq!(
            classify_ipv6_gtpu_ingress(&frame),
            Ipv6GtpuIngress::PassToStack
        );

        // RFC 8200 says receivers ignore PadN data rather than validating zero.
        let nonzero_padn = [IPV6_NH_UDP, 0, 1, 1, 0xff, 0, 0, 0];
        let frame = build_ipv6_frame(
            IPV6_NH_DESTINATION_OPTIONS,
            &nonzero_padn,
            &[0x60],
            GTPU_UDP_PORT,
            0,
        );
        assert!(Ipv6UdpEnvelopeBounds::parse(&frame).is_ok());

        let active_routing = [IPV6_NH_UDP, 0, 253, 1, 0, 0, 0, 0];
        let frame = build_ipv6_frame(IPV6_NH_ROUTING, &active_routing, &[0x60], GTPU_UDP_PORT, 0);
        assert_eq!(
            Ipv6UdpEnvelopeBounds::parse(&frame),
            Err(Ipv6ExtensionError::ActiveRoutingUnsupported)
        );

        let authentication = [IPV6_NH_UDP, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let frame = build_ipv6_frame(
            IPV6_NH_AUTHENTICATION,
            &authentication,
            &[0x60],
            GTPU_UDP_PORT,
            0,
        );
        assert_eq!(
            Ipv6UdpEnvelopeBounds::parse(&frame),
            Err(Ipv6ExtensionError::AuthenticationUnsupported)
        );
        assert_eq!(
            classify_ipv6_gtpu_ingress(&frame),
            Ipv6GtpuIngress::PassToStack
        );
        assert_eq!(
            classify_ipv6_extension_step(IPV6_NH_NONE, [0; 8], 0),
            Err(Ipv6ExtensionError::NoNextHeader)
        );
    }

    #[test]
    fn ipv6_gtpu_triage_passes_unrelated_traffic_and_rejects_proven_candidates() {
        let mut candidate = build_ipv6_frame(IPV6_NH_UDP, &[], &[0x60, 1, 2, 3], GTPU_UDP_PORT, 0);
        let bounds = Ipv6UdpEnvelopeBounds::parse(&candidate).unwrap();
        let body = bounds.gtp_offset() + GTPU_MANDATORY_HDR_LEN;
        candidate[body] ^= 1;
        assert_eq!(
            classify_ipv6_gtpu_ingress(&candidate),
            Ipv6GtpuIngress::RejectCandidate(Ipv6ExtensionError::InvalidUdpChecksum)
        );

        let mut unrelated = build_ipv6_frame(IPV6_NH_UDP, &[], &[0x60, 1], 9_999, 0);
        let unrelated_bounds = parse_ipv6_extension_chain(&unrelated).unwrap();
        unrelated[unrelated_bounds.udp_offset + UDP_HDR_LEN] ^= 1;
        assert_eq!(
            classify_ipv6_gtpu_ingress(&unrelated),
            Ipv6GtpuIngress::PassToStack
        );

        let mut padded_short_payload =
            build_ipv6_frame(IPV6_NH_UDP, &[], &[0x60], GTPU_UDP_PORT, 0);
        padded_short_payload[ETH_HDR_LEN + 4..ETH_HDR_LEN + 6]
            .copy_from_slice(&1_u16.to_be_bytes());
        let short_chain = parse_ipv6_extension_chain(&padded_short_payload).unwrap();
        assert!(short_chain.udp_offset + 4 <= padded_short_payload.len());
        assert!(short_chain.udp_offset + 4 > short_chain.ip_end);
        assert_eq!(
            classify_ipv6_gtpu_ingress(&padded_short_payload),
            Ipv6GtpuIngress::PassToStack,
            "Ethernet padding outside Payload Length cannot prove UDP/2152",
        );

        let mut bad_gtpu_length = build_ipv6_frame(IPV6_NH_UDP, &[], &[0x60, 1], GTPU_UDP_PORT, 0);
        let bad_bounds = Ipv6UdpEnvelopeBounds::parse(&bad_gtpu_length).unwrap();
        bad_gtpu_length[bad_bounds.gtp_offset() + 2..bad_bounds.gtp_offset() + 4]
            .copy_from_slice(&0_u16.to_be_bytes());
        refresh_ipv6_udp_checksum(&mut bad_gtpu_length);
        assert_eq!(
            classify_ipv6_gtpu_ingress(&bad_gtpu_length),
            Ipv6GtpuIngress::RejectCandidate(Ipv6ExtensionError::InconsistentGtpuBoundary)
        );
    }

    #[test]
    fn ipv6_udp_checksum_preserves_an_odd_segment_boundary() {
        let payload = b"odd-split";
        let mut udp = vec![0_u8; UDP_HDR_LEN + payload.len()];
        udp[0..2].copy_from_slice(&40_000_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&GTPU_UDP_PORT.to_be_bytes());
        let udp_length = u16::try_from(udp.len()).unwrap();
        udp[4..6].copy_from_slice(&udp_length.to_be_bytes());
        udp[UDP_HDR_LEN..].copy_from_slice(payload);

        let mut reference_bytes = Vec::new();
        reference_bytes.extend_from_slice(&SOURCE_V6);
        reference_bytes.extend_from_slice(&DESTINATION_V6);
        reference_bytes.extend_from_slice(&u32::try_from(udp.len()).unwrap().to_be_bytes());
        reference_bytes.extend_from_slice(&[0, 0, 0, IPV6_NH_UDP]);
        reference_bytes.extend_from_slice(&udp);
        let reference = match internet_checksum(&reference_bytes) {
            0 => 0xffff,
            checksum => checksum,
        };
        assert_eq!(
            udp_ipv6_checksum_segments(SOURCE_V6, DESTINATION_V6, &udp[..9], &udp[9..]),
            Some(reference)
        );
        assert_eq!(
            udp_ipv6_checksum(SOURCE_V6, DESTINATION_V6, &udp),
            Some(reference)
        );
        udp[6..8].copy_from_slice(&reference.to_be_bytes());
        assert!(udp_ipv6_checksum_is_valid(SOURCE_V6, DESTINATION_V6, &udp));
    }

    #[test]
    fn minimum_and_option_bearing_frames_have_exact_nested_bounds() {
        for (options, body, checksum_udp, padding) in [
            (&[][..], &[0x45, 0, 0, 20][..], false, 0),
            (&[1, 1, 0, 0][..], &[0x45, 1, 2, 3, 4][..], true, 18),
            (
                &[1, 1, 1, 1, 1, 1, 0, 0][..],
                &[0x45, 1, 2, 3, 4, 5][..],
                true,
                0,
            ),
        ] {
            let frame = build_frame(options, body, checksum_udp, padding);
            let bounds = validate_frame(&frame, false).unwrap();
            assert_eq!(bounds.gtp_end(), bounds.udp().udp_end());
            assert_eq!(bounds.gtp_end(), bounds.udp().ipv4().ip_end());
            assert!(bounds.gtp_end() <= frame.len());
            assert_eq!(frame.len() - bounds.gtp_end(), padding);
        }
    }

    #[test]
    fn ipv4_bounds_reject_bad_ihl_total_length_and_truncation() {
        assert_eq!(
            Ipv4EnvelopeBounds::parse(128, 0x44, 64),
            Err(GtpuEnvelopeError::InvalidIpv4Header)
        );
        assert_eq!(
            Ipv4EnvelopeBounds::parse(128, 0x65, 64),
            Err(GtpuEnvelopeError::InvalidIpv4Header)
        );
        assert_eq!(
            Ipv4EnvelopeBounds::parse(128, 0x45, 35),
            Err(GtpuEnvelopeError::InvalidIpv4TotalLength)
        );
        assert_eq!(
            Ipv4EnvelopeBounds::parse(49, 0x45, 36),
            Err(GtpuEnvelopeError::TruncatedIpv4Packet)
        );
        let padded = Ipv4EnvelopeBounds::parse(usize::MAX, 0x4f, u16::MAX).unwrap();
        assert_eq!(padded.ip_header_len(), IPV4_MAX_HDR_LEN);
        assert!(padded.ip_end() < usize::MAX);
    }

    #[test]
    fn udp_and_gtpu_bounds_reject_every_non_exact_nesting() {
        let ipv4 = Ipv4EnvelopeBounds::parse(256, 0x45, 100).unwrap();
        assert_eq!(
            UdpEnvelopeBounds::parse(ipv4, 7),
            Err(GtpuEnvelopeError::InvalidUdpLength)
        );
        assert_eq!(
            UdpEnvelopeBounds::parse(ipv4, 8),
            Err(GtpuEnvelopeError::TruncatedGtpuHeader)
        );
        for length in [79_u16, 81] {
            assert_eq!(
                UdpEnvelopeBounds::parse(ipv4, length),
                Err(GtpuEnvelopeError::InconsistentUdpBoundary)
            );
        }
        let udp = UdpEnvelopeBounds::parse(ipv4, 80).unwrap();
        for length in [63_u16, 65] {
            assert_eq!(
                GtpuEnvelopeBounds::parse(udp, length),
                Err(GtpuEnvelopeError::InconsistentGtpuBoundary)
            );
        }
        let exact = GtpuEnvelopeBounds::parse(udp, 64).unwrap();
        assert_eq!(exact.gtp_end(), exact.udp().udp_end());
        assert_eq!(exact.gtp_end(), exact.udp().ipv4().ip_end());
    }

    #[test]
    fn variable_ihl_ipv4_checksum_covers_options() {
        let mut frame = build_frame(&[0x94, 4, 0, 0], &[0x45, 1, 2, 3], false, 0);
        validate_frame(&frame, false).unwrap();
        frame[ETH_HDR_LEN + IPV4_MIN_HDR_LEN] ^= 1;
        assert_eq!(
            validate_frame(&frame, false),
            Err(GtpuEnvelopeError::InvalidIpv4Checksum)
        );
    }

    #[test]
    fn rfc768_style_udp_vectors_cover_odd_and_even_lengths() {
        for (payload, expected) in [(&b"odd"[..], 0x2f6c_u16), (&b"even"[..], 0x37ea)] {
            let mut udp = vec![0_u8; UDP_HDR_LEN + payload.len()];
            udp[0..2].copy_from_slice(&2152_u16.to_be_bytes());
            udp[2..4].copy_from_slice(&2152_u16.to_be_bytes());
            let udp_length = u16::try_from(udp.len()).unwrap();
            udp[4..6].copy_from_slice(&udp_length.to_be_bytes());
            udp[UDP_HDR_LEN..].copy_from_slice(payload);
            assert_eq!(udp_ipv4_checksum(SOURCE, DESTINATION, &udp), Some(expected));
            udp[6..8].copy_from_slice(&expected.to_be_bytes());
            assert!(udp_ipv4_checksum_is_valid(SOURCE, DESTINATION, &udp));
            udp[UDP_HDR_LEN] ^= 1;
            assert!(!udp_ipv4_checksum_is_valid(SOURCE, DESTINATION, &udp));
        }
    }

    #[test]
    fn udp_checksum_disposition_requires_explicit_no_pending_offload_evidence() {
        assert_eq!(
            classify_udp_checksum(0, UdpChecksumEvidence::NoPendingOffload),
            UdpChecksumDisposition::Omitted
        );
        assert_eq!(
            classify_udp_checksum(0, UdpChecksumEvidence::Unverified),
            UdpChecksumDisposition::SoftwareRequired
        );
        assert_eq!(
            classify_udp_checksum(0x1234, UdpChecksumEvidence::KernelVerified),
            UdpChecksumDisposition::KernelVerified
        );
        assert_eq!(
            classify_udp_checksum(0x1234, UdpChecksumEvidence::Unverified),
            UdpChecksumDisposition::SoftwareRequired
        );
    }

    #[test]
    fn frame_fixtures_reject_ip_udp_and_gtpu_boundary_disagreement() {
        let base = build_frame(&[1, 1, 0, 0], &[0x45; 32], true, 8);
        let ip = ETH_HDR_LEN;
        let udp = ip + 24;
        let gtpu = udp + UDP_HDR_LEN;

        let mut invalid_ip_checksum = base.clone();
        invalid_ip_checksum[ip + 8] ^= 1;
        assert_eq!(
            validate_frame(&invalid_ip_checksum, false),
            Err(GtpuEnvelopeError::InvalidIpv4Checksum)
        );

        let mut truncated = base.clone();
        truncated.truncate(base.len() - 9);
        assert_eq!(
            validate_frame(&truncated, false),
            Err(GtpuEnvelopeError::TruncatedIpv4Packet)
        );

        for adjustment in [-1_i16, 1] {
            let mut inconsistent_ip = base.clone();
            let current = read_u16(&inconsistent_ip, ip + 2).unwrap();
            inconsistent_ip[ip + 2..ip + 4]
                .copy_from_slice(&current.wrapping_add_signed(adjustment).to_be_bytes());
            refresh_ip_checksum(&mut inconsistent_ip);
            assert_eq!(
                validate_frame(&inconsistent_ip, false),
                Err(GtpuEnvelopeError::InconsistentUdpBoundary)
            );

            let mut inconsistent_udp = base.clone();
            let current = read_u16(&inconsistent_udp, udp + 4).unwrap();
            inconsistent_udp[udp + 4..udp + 6]
                .copy_from_slice(&current.wrapping_add_signed(adjustment).to_be_bytes());
            assert_eq!(
                validate_frame(&inconsistent_udp, false),
                Err(GtpuEnvelopeError::InconsistentUdpBoundary)
            );

            let mut inconsistent_gtpu = base.clone();
            let current = read_u16(&inconsistent_gtpu, gtpu + 2).unwrap();
            inconsistent_gtpu[gtpu + 2..gtpu + 4]
                .copy_from_slice(&current.wrapping_add_signed(adjustment).to_be_bytes());
            refresh_udp_checksum(&mut inconsistent_gtpu);
            assert_eq!(
                validate_frame(&inconsistent_gtpu, false),
                Err(GtpuEnvelopeError::InconsistentGtpuBoundary)
            );
        }

        let mut invalid_udp_checksum = base;
        invalid_udp_checksum[gtpu + GTPU_MANDATORY_HDR_LEN] ^= 1;
        assert_eq!(
            validate_frame(&invalid_udp_checksum, false),
            Err(GtpuEnvelopeError::InvalidUdpChecksum)
        );
    }

    #[test]
    fn property_every_accepted_envelope_has_exact_bounded_ends() {
        let edge_skb_lengths = [0, 1, ETH_HDR_LEN, usize::MAX - 1, usize::MAX];
        for skb_len in edge_skb_lengths {
            for version_ihl in [0_u8, 0x44, 0x45, 0x4f, 0x55, 0xff] {
                for total_length in [0_u16, 35, 36, 60, u16::MAX] {
                    let _ = Ipv4EnvelopeBounds::parse(skb_len, version_ihl, total_length);
                }
            }
        }

        let mut state = 0x9e37_79b9_u32;
        for _ in 0..50_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let version_ihl = (state >> 24) as u8;
            let total_length = state as u16;
            let skb_len = usize::from((state >> 8) as u16);
            let Ok(ipv4) = Ipv4EnvelopeBounds::parse(skb_len, version_ihl, total_length) else {
                continue;
            };
            state = state.rotate_left(13).wrapping_add(0xa5a5_5a5a);
            let Ok(udp) = UdpEnvelopeBounds::parse(ipv4, state as u16) else {
                continue;
            };
            state = state.rotate_right(7).wrapping_mul(2_654_435_761);
            let Ok(gtpu) = GtpuEnvelopeBounds::parse(udp, state as u16) else {
                continue;
            };
            assert_eq!(gtpu.gtp_end(), gtpu.udp().udp_end());
            assert_eq!(gtpu.gtp_end(), gtpu.udp().ipv4().ip_end());
            assert!(gtpu.gtp_end() <= skb_len);
        }

        for body_length in 0_u16..=1_024 {
            let udp_length = u32::from(body_length) + 16;
            let total_length = udp_length + 20;
            let skb_length = usize::try_from(total_length + ETH_HDR_LEN as u32 + 32).unwrap();
            let ipv4 =
                Ipv4EnvelopeBounds::parse(skb_length, 0x45, u16::try_from(total_length).unwrap())
                    .unwrap();
            let udp = UdpEnvelopeBounds::parse(ipv4, u16::try_from(udp_length).unwrap()).unwrap();
            let gtpu = GtpuEnvelopeBounds::parse(udp, body_length).unwrap();
            assert_eq!(gtpu.gtp_end(), gtpu.udp().udp_end());
            assert_eq!(gtpu.gtp_end(), gtpu.udp().ipv4().ip_end());
            assert!(gtpu.gtp_end() <= skb_length);
        }
    }
}
