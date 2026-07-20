//! Key-material-free SWu IKE/ESP packet classification.

use std::fmt;

use opc_ipsec_lb_ebpf_common::{
    bootstrap_tag, ESP_HEADER_PREFIX_LEN, IKEV2_EXCHANGE_IKE_SA_INIT as EXCHANGE_TYPE_IKE_SA_INIT,
    IKEV2_HDR_LEN as IKE_HEADER_LEN, IKEV2_MAJOR_VERSION, NAT_T_KEEPALIVE as NAT_T_KEEPALIVE_BYTE,
    NON_ESP_MARKER, UDP_PORT_IKE, UDP_PORT_IKE_NATT,
};
use thiserror::Error;

use crate::error::IpsecLbError;
use crate::model::{IpAddress, SteerKey};
use crate::ownership::{
    DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi, EstablishedIkeOwnershipKey,
    IkeSpi, InitialExchangeDiscriminator, InitialIkeOwnershipKey, OuterSourceTuple,
    RoutingDomainTag, SessionOwnershipKey,
};
use crate::selector::{RendezvousSelector, SelectionKey, ShardSet};

const NAT_T_KEEPALIVE: [u8; 1] = [NAT_T_KEEPALIVE_BYTE];
const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_ESP: u8 = 50;
const IP_PROTOCOL_AH: u8 = 51;
const IP_PROTOCOL_ICMPV6: u8 = 58;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const ICMP_ERROR_HEADER_LEN: usize = 8;

pub use opc_ipsec_lb_ebpf_common::MAX_INGRESS_IPV6_EXTENSION_HEADERS;

/// Why a raw ingress packet could not be classified without guessing.
///
/// Variants deliberately carry no packet bytes, addresses, ports, or SPI
/// values, so `Debug`, `Display`, and error telemetry are redaction-safe.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum IngressUnclassifiableReason {
    /// The first nibble did not identify IPv4 or IPv6.
    #[error("unsupported IP version")]
    UnsupportedIpVersion,
    /// The outer network packet ended before its declared header or payload.
    #[error("truncated IP packet")]
    TruncatedIpPacket,
    /// An IPv4 or IPv6 header carried inconsistent lengths or fields.
    #[error("malformed IP header")]
    MalformedIpHeader,
    /// A non-initial IP fragment does not carry the transport discriminator.
    #[error("non-initial IP fragment")]
    NonInitialIpFragment,
    /// The IPv6 extension-header chain exceeded the fixed inspection bound.
    #[error("IPv6 extension-header chain exceeds classifier bound")]
    Ipv6ExtensionChainTooLong,
    /// IPv6 extension headers were duplicated or appeared in an unsafe order.
    #[error("invalid IPv6 extension-header chain")]
    InvalidIpv6ExtensionChain,
    /// An IPv6 Authentication Header had an invalid fixed length or 8-octet alignment.
    #[error("malformed IPv6 Authentication Header")]
    MalformedIpv6AuthenticationHeader,
    /// The terminal IP protocol is not an IKE/ESP or supported ICMP error path.
    #[error("unsupported IP protocol")]
    UnsupportedIpProtocol,
    /// The UDP header was unavailable.
    #[error("truncated UDP header")]
    TruncatedUdpHeader,
    /// The UDP length was smaller than its header or inconsistent with the IP payload.
    #[error("malformed UDP length")]
    MalformedUdpLength,
    /// The selected UDP endpoint was neither port 500 nor port 4500.
    #[error("unsupported UDP port")]
    UnsupportedUdpPort,
    /// A UDP/4500 non-ESP marker did not have an IKE header after it.
    #[error("truncated UDP/4500 non-ESP payload")]
    TruncatedNatTraversalIke,
    /// The fixed IKEv2 header was unavailable.
    #[error("truncated IKEv2 header")]
    TruncatedIkeHeader,
    /// The IKEv2 length or fixed-header semantics were inconsistent.
    #[error("malformed IKEv2 header")]
    MalformedIkeHeader,
    /// The IKE header did not identify IKEv2.
    #[error("unsupported IKE version")]
    UnsupportedIkeVersion,
    /// An IKE initiator SPI was zero.
    #[error("invalid IKE SPI")]
    InvalidIkeSpi,
    /// A zero responder SPI appeared outside IKE_SA_INIT.
    #[error("invalid zero-responder-SPI IKE exchange")]
    InvalidInitialIkeExchange,
    /// The fixed ESP SPI and sequence-number prefix was unavailable.
    #[error("truncated ESP header")]
    TruncatedEspHeader,
    /// The ESP SPI was in the RFC 4303 reserved range.
    #[error("invalid ESP SPI")]
    InvalidEspSpi,
    /// The fixed ICMP error header was unavailable.
    #[error("truncated ICMP error header")]
    TruncatedIcmpHeader,
    /// The ICMP type does not carry an error quote supported by this classifier.
    #[error("unsupported ICMP error type")]
    UnsupportedIcmpError,
    /// The ICMP quote ended before a required fixed discriminator.
    #[error("truncated ICMP packet quote")]
    TruncatedIcmpQuote,
    /// The quoted packet was not sourced from the destination that received the error.
    #[error("ICMP quote does not match ingress destination")]
    IcmpQuoteAddressMismatch,
    /// The quoted packet did not contain a supported IKE/ESP transport identity.
    #[error("unsupported ICMP quoted protocol")]
    UnsupportedIcmpQuotedProtocol,
    /// A quoted initial exchange lacks the original peer source tuple required by its key.
    #[error("ICMP quote cannot reconstruct initial-IKE ownership")]
    QuotedInitialIke,
}

impl IngressUnclassifiableReason {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedIpVersion => "ingress_unsupported_ip_version",
            Self::TruncatedIpPacket => "ingress_truncated_ip_packet",
            Self::MalformedIpHeader => "ingress_malformed_ip_header",
            Self::NonInitialIpFragment => "ingress_non_initial_ip_fragment",
            Self::Ipv6ExtensionChainTooLong => "ingress_ipv6_extension_chain_too_long",
            Self::InvalidIpv6ExtensionChain => "ingress_invalid_ipv6_extension_chain",
            Self::MalformedIpv6AuthenticationHeader => "ingress_malformed_ipv6_ah",
            Self::UnsupportedIpProtocol => "ingress_unsupported_ip_protocol",
            Self::TruncatedUdpHeader => "ingress_truncated_udp_header",
            Self::MalformedUdpLength => "ingress_malformed_udp_length",
            Self::UnsupportedUdpPort => "ingress_unsupported_udp_port",
            Self::TruncatedNatTraversalIke => "ingress_truncated_natt_ike",
            Self::TruncatedIkeHeader => "ingress_truncated_ike_header",
            Self::MalformedIkeHeader => "ingress_malformed_ike_header",
            Self::UnsupportedIkeVersion => "ingress_unsupported_ike_version",
            Self::InvalidIkeSpi => "ingress_invalid_ike_spi",
            Self::InvalidInitialIkeExchange => "ingress_invalid_initial_ike_exchange",
            Self::TruncatedEspHeader => "ingress_truncated_esp_header",
            Self::InvalidEspSpi => "ingress_invalid_esp_spi",
            Self::TruncatedIcmpHeader => "ingress_truncated_icmp_header",
            Self::UnsupportedIcmpError => "ingress_unsupported_icmp_error",
            Self::TruncatedIcmpQuote => "ingress_truncated_icmp_quote",
            Self::IcmpQuoteAddressMismatch => "ingress_icmp_quote_address_mismatch",
            Self::UnsupportedIcmpQuotedProtocol => "ingress_unsupported_icmp_quoted_protocol",
            Self::QuotedInitialIke => "ingress_quoted_initial_ike",
        }
    }
}

/// IKE/ESP representation identified at the public ingress.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressEncapsulationKind {
    /// IKEv2 carried directly by UDP/500.
    IkeUdp500,
    /// IKEv2 carried after the RFC 3948 non-ESP marker on UDP/4500.
    IkeUdp4500,
    /// RFC 3948 UDP-encapsulated ESP on UDP/4500.
    EspUdp4500,
    /// Native ESP carried as IP protocol 50.
    NativeEsp,
}

/// Where the classified identity was observed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressIdentityProvenance {
    /// The outer packet itself carried IKE or ESP.
    Direct,
    /// An ICMPv4 error quoted the classified packet.
    IcmpV4Quote,
    /// An ICMPv6 error quoted the classified packet.
    IcmpV6Quote,
}

/// Source address and optional UDP source port observed on the outer packet.
///
/// Native ESP and ICMP errors have no UDP source port. Explicit accessors make
/// the observation available to ownership and telemetry code, while `Debug`
/// redacts both fields.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObservedOuterSource {
    address: IpAddress,
    udp_port: Option<u16>,
}

impl ObservedOuterSource {
    const fn ip(address: IpAddress) -> Self {
        Self {
            address,
            udp_port: None,
        }
    }

    const fn udp(address: IpAddress, port: u16) -> Self {
        Self {
            address,
            udp_port: Some(port),
        }
    }

    /// Return the source address observed on the outer packet.
    #[must_use]
    pub const fn address(self) -> IpAddress {
        self.address
    }

    /// Return the UDP source port, when the outer packet was UDP.
    #[must_use]
    pub const fn udp_port(self) -> Option<u16> {
        self.udp_port
    }

    /// Return the canonical ownership source tuple for a UDP observation.
    #[must_use]
    pub const fn udp_tuple(self) -> Option<OuterSourceTuple> {
        match self.udp_port {
            Some(port) => Some(OuterSourceTuple::new(self.address, port)),
            None => None,
        }
    }
}

impl fmt::Debug for ObservedOuterSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedOuterSource")
            .field("address", &"<redacted>")
            .field("udp_port_present", &self.udp_port.is_some())
            .finish()
    }
}

/// ESP discriminator extracted from an ICMP quote.
///
/// The quoted packet is normally outbound, so its SPI is peer-owned and must
/// not be represented as an [`EspOwnershipKey`], whose SPI is explicitly the
/// inbound SPI. Consumers can correlate this value against product session
/// state without accidentally installing it as an inbound ownership key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuotedEspIdentity {
    destination: DestinationContext,
    encapsulation: EspEncapsulationKind,
    spi: EspSpi,
}

impl QuotedEspIdentity {
    const fn new(
        destination: DestinationContext,
        encapsulation: EspEncapsulationKind,
        spi: EspSpi,
    ) -> Self {
        Self {
            destination,
            encapsulation,
            spi,
        }
    }

    /// Return the destination/routing-domain context that received the error.
    #[must_use]
    pub const fn destination(self) -> DestinationContext {
        self.destination
    }

    /// Return the encapsulation used by the quoted ESP packet.
    #[must_use]
    pub const fn encapsulation(self) -> EspEncapsulationKind {
        self.encapsulation
    }

    /// Return the quoted ESP SPI.
    #[must_use]
    pub const fn spi(self) -> EspSpi {
        self.spi
    }
}

impl fmt::Debug for QuotedEspIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuotedEspIdentity")
            .field("destination", &self.destination)
            .field("encapsulation", &self.encapsulation)
            .field("spi", &"<redacted>")
            .finish()
    }
}

/// Destination-scoped identity extracted without SA key material.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressPacketIdentity {
    /// A canonical ownership key from direct ingress, or a direction-neutral
    /// established-IKE key reconstructed from an ICMP quote.
    Ownership(SessionOwnershipKey),
    /// A direction-sensitive ESP identity reconstructed from an ICMP quote.
    QuotedEsp(QuotedEspIdentity),
}

impl IngressPacketIdentity {
    /// Return the destination/routing-domain context.
    #[must_use]
    pub const fn destination(self) -> DestinationContext {
        match self {
            Self::Ownership(key) => key.destination(),
            Self::QuotedEsp(identity) => identity.destination(),
        }
    }

    /// Return a canonical ownership key when direction makes that safe.
    #[must_use]
    pub const fn ownership_key(self) -> Option<SessionOwnershipKey> {
        match self {
            Self::Ownership(key) => Some(key),
            Self::QuotedEsp(_) => None,
        }
    }
}

impl fmt::Debug for IngressPacketIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ownership(key) => f.debug_tuple("Ownership").field(key).finish(),
            Self::QuotedEsp(identity) => f.debug_tuple("QuotedEsp").field(identity).finish(),
        }
    }
}

/// One successfully classified ingress packet.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeylessIngressMatch {
    identity: IngressPacketIdentity,
    encapsulation: IngressEncapsulationKind,
    outer_source: ObservedOuterSource,
    provenance: IngressIdentityProvenance,
}

impl KeylessIngressMatch {
    const fn new(
        identity: IngressPacketIdentity,
        encapsulation: IngressEncapsulationKind,
        outer_source: ObservedOuterSource,
        provenance: IngressIdentityProvenance,
    ) -> Self {
        Self {
            identity,
            encapsulation,
            outer_source,
            provenance,
        }
    }

    /// Return the destination-scoped session identity.
    #[must_use]
    pub const fn identity(self) -> IngressPacketIdentity {
        self.identity
    }

    /// Return the wire encapsulation that carried the discriminator.
    #[must_use]
    pub const fn encapsulation(self) -> IngressEncapsulationKind {
        self.encapsulation
    }

    /// Return the source observation from the outer packet.
    #[must_use]
    pub const fn outer_source(self) -> ObservedOuterSource {
        self.outer_source
    }

    /// Return whether the identity was direct or reconstructed from ICMP.
    #[must_use]
    pub const fn provenance(self) -> IngressIdentityProvenance {
        self.provenance
    }

    /// Return a canonical ownership key when direction makes that safe.
    #[must_use]
    pub const fn ownership_key(self) -> Option<SessionOwnershipKey> {
        self.identity.ownership_key()
    }

    /// Return the destination/routing-domain context.
    #[must_use]
    pub const fn destination(self) -> DestinationContext {
        self.identity.destination()
    }
}

impl fmt::Debug for KeylessIngressMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeylessIngressMatch")
            .field("identity", &self.identity)
            .field("encapsulation", &self.encapsulation)
            .field("outer_source", &self.outer_source)
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// Outcome of keyless classification over one raw network-layer packet.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeylessIngressClassification {
    /// A destination-scoped IKE or ESP discriminator was extracted.
    Classified(KeylessIngressMatch),
    /// An RFC 3948 one-octet NAT traversal keepalive was recognized.
    NatTraversalKeepalive {
        /// Destination/routing-domain context that received the keepalive.
        destination: DestinationContext,
        /// Source address and UDP port observed on the keepalive.
        outer_source: ObservedOuterSource,
    },
    /// The packet could not be classified safely and no identity was guessed.
    Unclassifiable {
        /// Redaction-safe typed reason.
        reason: IngressUnclassifiableReason,
    },
}

impl KeylessIngressClassification {
    /// Stable machine-readable outcome code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Classified(matched) => match matched.encapsulation() {
                IngressEncapsulationKind::IkeUdp500 => "ingress_ike_udp_500",
                IngressEncapsulationKind::IkeUdp4500 => "ingress_ike_udp_4500",
                IngressEncapsulationKind::EspUdp4500 => "ingress_esp_udp_4500",
                IngressEncapsulationKind::NativeEsp => "ingress_native_esp",
            },
            Self::NatTraversalKeepalive { .. } => "ingress_natt_keepalive",
            Self::Unclassifiable { reason } => reason.as_str(),
        }
    }

    /// Return the classified match, when present.
    #[must_use]
    pub const fn matched(self) -> Option<KeylessIngressMatch> {
        match self {
            Self::Classified(matched) => Some(matched),
            Self::NatTraversalKeepalive { .. } | Self::Unclassifiable { .. } => None,
        }
    }

    /// Return the unclassifiable reason, when classification failed closed.
    #[must_use]
    pub const fn unclassifiable_reason(self) -> Option<IngressUnclassifiableReason> {
        match self {
            Self::Unclassifiable { reason } => Some(reason),
            Self::Classified(_) | Self::NatTraversalKeepalive { .. } => None,
        }
    }
}

/// Classify one raw IPv4 or IPv6 ingress packet without any SA key material.
///
/// `packet` begins at the network-layer version/header octet; Ethernet and
/// other link-layer framing must already be removed. The destination address
/// is read from that header and combined with the caller's opaque routing
/// domain. Parsing is zero-copy, allocates nothing, inspects only fixed
/// protocol headers, and bounds IPv6 extension-header traversal. Malformed,
/// truncated, non-initially fragmented, or unsupported input returns
/// [`KeylessIngressClassification::Unclassifiable`] without a guessed key.
#[must_use]
pub fn classify_keyless_ingress_packet(
    packet: &[u8],
    routing_domain: RoutingDomainTag,
) -> KeylessIngressClassification {
    let outer = match parse_ip_packet(packet, PacketCompleteness::Complete) {
        Ok(outer) => outer,
        Err(reason) => return unclassifiable(reason),
    };
    let destination = DestinationContext::new(outer.destination, routing_domain);

    match outer.protocol {
        IP_PROTOCOL_UDP => classify_direct_udp(outer, destination),
        IP_PROTOCOL_ESP => classify_direct_esp(outer, destination),
        IP_PROTOCOL_ICMP if outer.source.is_ipv4() => {
            classify_icmp_error(outer, destination, IngressIdentityProvenance::IcmpV4Quote)
        }
        IP_PROTOCOL_ICMPV6 if !outer.source.is_ipv4() => {
            classify_icmp_error(outer, destination, IngressIdentityProvenance::IcmpV6Quote)
        }
        _ => unclassifiable(IngressUnclassifiableReason::UnsupportedIpProtocol),
    }
}

fn unclassifiable(reason: IngressUnclassifiableReason) -> KeylessIngressClassification {
    KeylessIngressClassification::Unclassifiable { reason }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketCompleteness {
    Complete,
    IcmpQuote,
}

impl PacketCompleteness {
    const fn permits_declared_truncation(self) -> bool {
        matches!(self, Self::IcmpQuote)
    }

    const fn truncation_reason(self) -> IngressUnclassifiableReason {
        match self {
            Self::Complete => IngressUnclassifiableReason::TruncatedIpPacket,
            Self::IcmpQuote => IngressUnclassifiableReason::TruncatedIcmpQuote,
        }
    }
}

#[derive(Clone, Copy)]
struct IpPacketView<'a> {
    source: IpAddress,
    destination: IpAddress,
    protocol: u8,
    payload: &'a [u8],
    declared_transport_len: usize,
    transport_quote_truncated: bool,
    more_fragments: bool,
}

fn parse_ip_packet(
    packet: &[u8],
    completeness: PacketCompleteness,
) -> Result<IpPacketView<'_>, IngressUnclassifiableReason> {
    let Some(first) = packet.first() else {
        return Err(completeness.truncation_reason());
    };
    match first >> 4 {
        4 => parse_ipv4_packet(packet, completeness),
        6 => parse_ipv6_packet(packet, completeness),
        _ => Err(IngressUnclassifiableReason::UnsupportedIpVersion),
    }
}

fn parse_ipv4_packet(
    packet: &[u8],
    completeness: PacketCompleteness,
) -> Result<IpPacketView<'_>, IngressUnclassifiableReason> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(completeness.truncation_reason());
    }
    let header_words = usize::from(packet[0] & 0x0f);
    if header_words < 5 {
        return Err(IngressUnclassifiableReason::MalformedIpHeader);
    }
    let header_len = header_words * 4;
    if packet.len() < header_len {
        return Err(completeness.truncation_reason());
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len {
        return Err(IngressUnclassifiableReason::MalformedIpHeader);
    }
    let declared_truncated = total_len > packet.len();
    if declared_truncated && !completeness.permits_declared_truncation() {
        return Err(IngressUnclassifiableReason::TruncatedIpPacket);
    }
    let packet_end = total_len.min(packet.len());
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x1fff != 0 {
        return Err(IngressUnclassifiableReason::NonInitialIpFragment);
    }
    let more_fragments = fragment & 0x2000 != 0;
    Ok(IpPacketView {
        source: IpAddress::V4([packet[12], packet[13], packet[14], packet[15]]),
        destination: IpAddress::V4([packet[16], packet[17], packet[18], packet[19]]),
        protocol: packet[9],
        payload: &packet[header_len..packet_end],
        declared_transport_len: total_len - header_len,
        transport_quote_truncated: declared_truncated,
        more_fragments,
    })
}

fn parse_ipv6_packet(
    packet: &[u8],
    completeness: PacketCompleteness,
) -> Result<IpPacketView<'_>, IngressUnclassifiableReason> {
    if packet.len() < IPV6_HEADER_LEN {
        return Err(completeness.truncation_reason());
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    let declared_truncated = total_len > packet.len();
    if declared_truncated && !completeness.permits_declared_truncation() {
        return Err(IngressUnclassifiableReason::TruncatedIpPacket);
    }
    let packet_end = total_len.min(packet.len());
    let source = IpAddress::V6([
        packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14],
        packet[15], packet[16], packet[17], packet[18], packet[19], packet[20], packet[21],
        packet[22], packet[23],
    ]);
    let destination = IpAddress::V6([
        packet[24], packet[25], packet[26], packet[27], packet[28], packet[29], packet[30],
        packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37],
        packet[38], packet[39],
    ]);
    let mut next_header = packet[6];
    let mut cursor = IPV6_HEADER_LEN;
    let mut extension_count = 0usize;
    let mut more_fragments = false;
    let mut extension_order = Ipv6ExtensionOrder::default();

    while is_ipv6_extension_header(next_header) {
        if extension_count == MAX_INGRESS_IPV6_EXTENSION_HEADERS {
            return Err(IngressUnclassifiableReason::Ipv6ExtensionChainTooLong);
        }
        let current_header = next_header;
        let (following_header, extension_len) = if current_header == 44 {
            if packet_end.saturating_sub(cursor) < 8 {
                return Err(ipv6_extension_overrun_reason(
                    completeness,
                    declared_truncated,
                    current_header,
                ));
            }
            if packet[cursor + 1] != 0 {
                return Err(IngressUnclassifiableReason::MalformedIpHeader);
            }
            let fragment = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
            if fragment & 0x0006 != 0 {
                return Err(IngressUnclassifiableReason::MalformedIpHeader);
            }
            if fragment & 0xfff8 != 0 {
                return Err(IngressUnclassifiableReason::NonInitialIpFragment);
            }
            more_fragments |= fragment & 1 != 0;
            (packet[cursor], 8)
        } else {
            if packet_end.saturating_sub(cursor) < 2 {
                return Err(ipv6_extension_overrun_reason(
                    completeness,
                    declared_truncated,
                    current_header,
                ));
            }
            let following_header = packet[cursor];
            if current_header == IP_PROTOCOL_AH {
                let payload_len = packet[cursor + 1];
                if payload_len < 1 {
                    return Err(IngressUnclassifiableReason::MalformedIpv6AuthenticationHeader);
                }
                let extension_len = (usize::from(payload_len) + 2) * 4;
                if extension_len < 12 || extension_len % 8 != 0 {
                    return Err(IngressUnclassifiableReason::MalformedIpv6AuthenticationHeader);
                }
                (following_header, extension_len)
            } else {
                (following_header, (usize::from(packet[cursor + 1]) + 1) * 8)
            }
        };
        if packet_end.saturating_sub(cursor) < extension_len {
            return Err(ipv6_extension_overrun_reason(
                completeness,
                declared_truncated,
                current_header,
            ));
        }
        if current_header == IP_PROTOCOL_AH && (packet[cursor + 2] != 0 || packet[cursor + 3] != 0)
        {
            return Err(IngressUnclassifiableReason::MalformedIpv6AuthenticationHeader);
        }
        extension_order.observe(current_header, following_header, extension_count)?;
        extension_count += 1;
        next_header = following_header;
        cursor += extension_len;
    }

    Ok(IpPacketView {
        source,
        destination,
        protocol: next_header,
        payload: &packet[cursor..packet_end],
        declared_transport_len: total_len - cursor,
        transport_quote_truncated: declared_truncated,
        more_fragments,
    })
}

const fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | IP_PROTOCOL_AH | 60)
}

const fn ipv6_extension_overrun_reason(
    completeness: PacketCompleteness,
    declared_truncated: bool,
    current_header: u8,
) -> IngressUnclassifiableReason {
    if declared_truncated {
        completeness.truncation_reason()
    } else if current_header == IP_PROTOCOL_AH {
        IngressUnclassifiableReason::MalformedIpv6AuthenticationHeader
    } else {
        IngressUnclassifiableReason::MalformedIpHeader
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Ipv6ExtensionOrder {
    last_stage: Option<u8>,
    seen_hop_by_hop: bool,
    seen_pre_routing_destination: bool,
    seen_routing: bool,
    seen_fragment: bool,
    seen_authentication: bool,
    seen_final_destination: bool,
}

impl Ipv6ExtensionOrder {
    fn observe(
        &mut self,
        current_header: u8,
        following_header: u8,
        extension_index: usize,
    ) -> Result<(), IngressUnclassifiableReason> {
        let invalid = || IngressUnclassifiableReason::InvalidIpv6ExtensionChain;
        let stage = match current_header {
            0 => {
                if extension_index != 0 || self.seen_hop_by_hop {
                    return Err(invalid());
                }
                self.seen_hop_by_hop = true;
                0
            }
            43 => {
                if self.seen_routing {
                    return Err(invalid());
                }
                self.seen_routing = true;
                2
            }
            44 => {
                if self.seen_fragment {
                    return Err(invalid());
                }
                self.seen_fragment = true;
                3
            }
            IP_PROTOCOL_AH => {
                if self.seen_authentication {
                    return Err(invalid());
                }
                self.seen_authentication = true;
                4
            }
            60 if following_header == 43 => {
                if self.seen_pre_routing_destination
                    || self.seen_routing
                    || self.seen_final_destination
                {
                    return Err(invalid());
                }
                self.seen_pre_routing_destination = true;
                1
            }
            60 => {
                if self.seen_final_destination || is_ipv6_extension_header(following_header) {
                    return Err(invalid());
                }
                self.seen_final_destination = true;
                5
            }
            _ => return Err(invalid()),
        };
        if self.last_stage.is_some_and(|previous| previous > stage) {
            return Err(invalid());
        }
        self.last_stage = Some(stage);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct UdpPacketView<'a> {
    source_port: u16,
    destination_port: u16,
    payload: &'a [u8],
    declared_payload_len: usize,
    payload_truncated: bool,
}

fn parse_udp_packet(
    payload: &[u8],
    declared_transport_len: usize,
    transport_quote_truncated: bool,
    more_fragments: bool,
) -> Result<UdpPacketView<'_>, IngressUnclassifiableReason> {
    if payload.len() < UDP_HEADER_LEN {
        return Err(IngressUnclassifiableReason::TruncatedUdpHeader);
    }
    let declared_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    if declared_len < UDP_HEADER_LEN {
        return Err(IngressUnclassifiableReason::MalformedUdpLength);
    }
    let matches_ip_envelope = if more_fragments {
        declared_len > declared_transport_len
    } else {
        declared_len == declared_transport_len
    };
    if !matches_ip_envelope {
        return Err(IngressUnclassifiableReason::MalformedUdpLength);
    }
    let payload_truncated = declared_len > payload.len();
    if payload_truncated != (transport_quote_truncated || more_fragments) {
        return Err(IngressUnclassifiableReason::MalformedUdpLength);
    }
    if declared_len < payload.len() {
        return Err(IngressUnclassifiableReason::MalformedUdpLength);
    }
    let available_len = declared_len.min(payload.len());
    Ok(UdpPacketView {
        source_port: u16::from_be_bytes([payload[0], payload[1]]),
        destination_port: u16::from_be_bytes([payload[2], payload[3]]),
        payload: &payload[UDP_HEADER_LEN..available_len],
        declared_payload_len: declared_len - UDP_HEADER_LEN,
        payload_truncated,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpEndpointRole {
    Destination,
    Source,
}

#[derive(Clone, Copy)]
enum ParsedTransport {
    Ike {
        initiator_spi: IkeSpi,
        responder_spi: Option<IkeSpi>,
    },
    Esp(EspSpi),
    NatTraversalKeepalive,
}

#[derive(Clone, Copy)]
struct ParsedIngressTransport {
    encapsulation: IngressEncapsulationKind,
    identity: ParsedTransport,
}

fn parse_udp_transport(
    udp: UdpPacketView<'_>,
    endpoint_role: UdpEndpointRole,
) -> Result<ParsedIngressTransport, IngressUnclassifiableReason> {
    let selected_port = match endpoint_role {
        UdpEndpointRole::Destination => udp.destination_port,
        UdpEndpointRole::Source => udp.source_port,
    };
    match selected_port {
        UDP_PORT_IKE => Ok(ParsedIngressTransport {
            encapsulation: IngressEncapsulationKind::IkeUdp500,
            identity: parse_ike_transport(
                udp.payload,
                udp.declared_payload_len,
                udp.payload_truncated,
            )?,
        }),
        UDP_PORT_IKE_NATT => {
            parse_udp_4500_transport(udp.payload, udp.declared_payload_len, udp.payload_truncated)
        }
        _ => Err(IngressUnclassifiableReason::UnsupportedUdpPort),
    }
}

fn parse_udp_4500_transport(
    payload: &[u8],
    declared_payload_len: usize,
    payload_truncated: bool,
) -> Result<ParsedIngressTransport, IngressUnclassifiableReason> {
    if payload == NAT_T_KEEPALIVE {
        if payload_truncated || declared_payload_len != NAT_T_KEEPALIVE.len() {
            return Err(IngressUnclassifiableReason::TruncatedEspHeader);
        }
        return Ok(ParsedIngressTransport {
            encapsulation: IngressEncapsulationKind::EspUdp4500,
            identity: ParsedTransport::NatTraversalKeepalive,
        });
    }
    if payload.starts_with(&NON_ESP_MARKER) {
        let Some(declared_ike_len) = declared_payload_len.checked_sub(NON_ESP_MARKER.len()) else {
            return Err(IngressUnclassifiableReason::MalformedUdpLength);
        };
        if declared_ike_len == 0 {
            return Err(IngressUnclassifiableReason::TruncatedNatTraversalIke);
        }
        return Ok(ParsedIngressTransport {
            encapsulation: IngressEncapsulationKind::IkeUdp4500,
            identity: parse_ike_transport(
                &payload[NON_ESP_MARKER.len()..],
                declared_ike_len,
                payload_truncated,
            )?,
        });
    }
    Ok(ParsedIngressTransport {
        encapsulation: IngressEncapsulationKind::EspUdp4500,
        identity: ParsedTransport::Esp(parse_esp_spi(payload)?),
    })
}

fn parse_ike_transport(
    payload: &[u8],
    declared_payload_len: usize,
    payload_truncated: bool,
) -> Result<ParsedTransport, IngressUnclassifiableReason> {
    if payload.len() < IKE_HEADER_LEN {
        return Err(IngressUnclassifiableReason::TruncatedIkeHeader);
    }
    if payload[17] >> 4 != IKEV2_MAJOR_VERSION {
        return Err(IngressUnclassifiableReason::UnsupportedIkeVersion);
    }
    let declared_len =
        u32::from_be_bytes([payload[24], payload[25], payload[26], payload[27]]) as usize;
    if declared_len < IKE_HEADER_LEN || declared_len != declared_payload_len {
        return Err(IngressUnclassifiableReason::MalformedIkeHeader);
    }
    if (payload_truncated && payload.len() >= declared_payload_len)
        || (!payload_truncated && payload.len() != declared_payload_len)
    {
        return Err(IngressUnclassifiableReason::MalformedIkeHeader);
    }
    let initiator_spi = IkeSpi::new(u64::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]))
    .map_err(|_| IngressUnclassifiableReason::InvalidIkeSpi)?;
    let responder_value = u64::from_be_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ]);
    let responder_spi = if responder_value == 0 {
        if payload[18] != EXCHANGE_TYPE_IKE_SA_INIT {
            return Err(IngressUnclassifiableReason::InvalidInitialIkeExchange);
        }
        None
    } else {
        Some(IkeSpi::new(responder_value).map_err(|_| IngressUnclassifiableReason::InvalidIkeSpi)?)
    };
    Ok(ParsedTransport::Ike {
        initiator_spi,
        responder_spi,
    })
}

fn parse_esp_spi(payload: &[u8]) -> Result<EspSpi, IngressUnclassifiableReason> {
    if payload.len() < ESP_HEADER_PREFIX_LEN {
        return Err(IngressUnclassifiableReason::TruncatedEspHeader);
    }
    EspSpi::new(u32::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
    .map_err(|_| IngressUnclassifiableReason::InvalidEspSpi)
}

fn classify_direct_udp(
    outer: IpPacketView<'_>,
    destination: DestinationContext,
) -> KeylessIngressClassification {
    let udp = match parse_udp_packet(
        outer.payload,
        outer.declared_transport_len,
        outer.transport_quote_truncated,
        outer.more_fragments,
    ) {
        Ok(udp) => udp,
        Err(reason) => return unclassifiable(reason),
    };
    let parsed = match parse_udp_transport(udp, UdpEndpointRole::Destination) {
        Ok(parsed) => parsed,
        Err(reason) => return unclassifiable(reason),
    };
    let source = ObservedOuterSource::udp(outer.source, udp.source_port);
    if matches!(parsed.identity, ParsedTransport::NatTraversalKeepalive) {
        return KeylessIngressClassification::NatTraversalKeepalive {
            destination,
            outer_source: source,
        };
    }
    match direct_identity(parsed, destination, source) {
        Ok(identity) => KeylessIngressClassification::Classified(KeylessIngressMatch::new(
            IngressPacketIdentity::Ownership(identity),
            parsed.encapsulation,
            source,
            IngressIdentityProvenance::Direct,
        )),
        Err(reason) => unclassifiable(reason),
    }
}

fn classify_direct_esp(
    outer: IpPacketView<'_>,
    destination: DestinationContext,
) -> KeylessIngressClassification {
    let spi = match parse_esp_spi(outer.payload) {
        Ok(spi) => spi,
        Err(reason) => return unclassifiable(reason),
    };
    let identity = SessionOwnershipKey::from(EspOwnershipKey::new(
        destination,
        EspEncapsulationKind::Native,
        spi,
    ));
    KeylessIngressClassification::Classified(KeylessIngressMatch::new(
        IngressPacketIdentity::Ownership(identity),
        IngressEncapsulationKind::NativeEsp,
        ObservedOuterSource::ip(outer.source),
        IngressIdentityProvenance::Direct,
    ))
}

fn direct_identity(
    parsed: ParsedIngressTransport,
    destination: DestinationContext,
    source: ObservedOuterSource,
) -> Result<SessionOwnershipKey, IngressUnclassifiableReason> {
    match parsed.identity {
        ParsedTransport::Ike {
            initiator_spi,
            responder_spi: Some(responder_spi),
        } => Ok(SessionOwnershipKey::from(EstablishedIkeOwnershipKey::new(
            destination,
            initiator_spi,
            responder_spi,
        ))),
        ParsedTransport::Ike {
            initiator_spi,
            responder_spi: None,
        } => {
            let Some(source) = source.udp_tuple() else {
                return Err(IngressUnclassifiableReason::InvalidInitialIkeExchange);
            };
            Ok(SessionOwnershipKey::from(InitialIkeOwnershipKey::new(
                destination,
                source,
                initiator_spi,
                InitialExchangeDiscriminator::IKE_SA_INIT,
            )))
        }
        ParsedTransport::Esp(spi) => Ok(SessionOwnershipKey::from(EspOwnershipKey::new(
            destination,
            EspEncapsulationKind::UdpEncapsulated,
            spi,
        ))),
        ParsedTransport::NatTraversalKeepalive => {
            Err(IngressUnclassifiableReason::UnsupportedIpProtocol)
        }
    }
}

fn classify_icmp_error(
    outer: IpPacketView<'_>,
    destination: DestinationContext,
    provenance: IngressIdentityProvenance,
) -> KeylessIngressClassification {
    if outer.payload.len() < ICMP_ERROR_HEADER_LEN {
        return unclassifiable(IngressUnclassifiableReason::TruncatedIcmpHeader);
    }
    if !is_supported_icmp_error(outer.source.is_ipv4(), outer.payload[0]) {
        return unclassifiable(IngressUnclassifiableReason::UnsupportedIcmpError);
    }
    let quoted = match parse_ip_packet(
        &outer.payload[ICMP_ERROR_HEADER_LEN..],
        PacketCompleteness::IcmpQuote,
    ) {
        Ok(quoted) => quoted,
        Err(reason) => return unclassifiable(reason),
    };
    if quoted.source != destination.address() {
        return unclassifiable(IngressUnclassifiableReason::IcmpQuoteAddressMismatch);
    }

    let source = ObservedOuterSource::ip(outer.source);
    match quoted.protocol {
        IP_PROTOCOL_ESP => {
            let spi = match parse_esp_spi(quoted.payload) {
                Ok(spi) => spi,
                Err(IngressUnclassifiableReason::TruncatedEspHeader) => {
                    return unclassifiable(IngressUnclassifiableReason::TruncatedIcmpQuote);
                }
                Err(reason) => return unclassifiable(reason),
            };
            let identity = QuotedEspIdentity::new(destination, EspEncapsulationKind::Native, spi);
            KeylessIngressClassification::Classified(KeylessIngressMatch::new(
                IngressPacketIdentity::QuotedEsp(identity),
                IngressEncapsulationKind::NativeEsp,
                source,
                provenance,
            ))
        }
        IP_PROTOCOL_UDP => classify_quoted_udp(quoted, destination, source, provenance),
        _ => unclassifiable(IngressUnclassifiableReason::UnsupportedIcmpQuotedProtocol),
    }
}

fn classify_quoted_udp(
    quoted: IpPacketView<'_>,
    destination: DestinationContext,
    source: ObservedOuterSource,
    provenance: IngressIdentityProvenance,
) -> KeylessIngressClassification {
    let udp = match parse_udp_packet(
        quoted.payload,
        quoted.declared_transport_len,
        quoted.transport_quote_truncated,
        quoted.more_fragments,
    ) {
        Ok(udp) => udp,
        Err(IngressUnclassifiableReason::TruncatedUdpHeader) => {
            return unclassifiable(IngressUnclassifiableReason::TruncatedIcmpQuote);
        }
        Err(reason) => return unclassifiable(reason),
    };
    let parsed = match parse_udp_transport(udp, UdpEndpointRole::Source) {
        Ok(parsed) => parsed,
        Err(IngressUnclassifiableReason::TruncatedIkeHeader)
        | Err(IngressUnclassifiableReason::TruncatedEspHeader)
        | Err(IngressUnclassifiableReason::TruncatedNatTraversalIke) => {
            return unclassifiable(IngressUnclassifiableReason::TruncatedIcmpQuote);
        }
        Err(IngressUnclassifiableReason::UnsupportedUdpPort) => {
            return unclassifiable(IngressUnclassifiableReason::UnsupportedIcmpQuotedProtocol);
        }
        Err(reason) => return unclassifiable(reason),
    };

    let identity = match parsed.identity {
        ParsedTransport::Ike {
            initiator_spi,
            responder_spi: Some(responder_spi),
        } => IngressPacketIdentity::Ownership(SessionOwnershipKey::from(
            EstablishedIkeOwnershipKey::new(destination, initiator_spi, responder_spi),
        )),
        ParsedTransport::Ike {
            responder_spi: None,
            ..
        } => return unclassifiable(IngressUnclassifiableReason::QuotedInitialIke),
        ParsedTransport::Esp(spi) => IngressPacketIdentity::QuotedEsp(QuotedEspIdentity::new(
            destination,
            EspEncapsulationKind::UdpEncapsulated,
            spi,
        )),
        ParsedTransport::NatTraversalKeepalive => {
            return unclassifiable(IngressUnclassifiableReason::UnsupportedIcmpQuotedProtocol);
        }
    };
    KeylessIngressClassification::Classified(KeylessIngressMatch::new(
        identity,
        parsed.encapsulation,
        source,
        provenance,
    ))
}

const fn is_supported_icmp_error(ipv4: bool, icmp_type: u8) -> bool {
    if ipv4 {
        matches!(icmp_type, 3 | 4 | 5 | 11 | 12)
    } else {
        matches!(icmp_type, 1..=4)
    }
}

/// ESP IP-fragmentation handling posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspFragmentPosture {
    /// Deployment prevents ESP IP fragmentation via MTU/DF posture.
    PreventIpFragmentation,
    /// Deployment reassembles fragments before steering.
    ReassembleBeforeSteer,
}

/// IP fragmentation metadata supplied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct IpFragment {
    /// Fragment offset in 8-octet units.
    pub offset: u16,
    /// More-fragments flag.
    pub more_fragments: bool,
}

impl IpFragment {
    /// True for a non-first fragment that lacks UDP/ESP headers.
    #[must_use]
    pub const fn is_non_first(self) -> bool {
        self.offset != 0
    }
}

/// Classifier configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwuClassifierConfig<'a> {
    /// Current shard set used for IKE_SA_INIT bootstrap.
    pub shards: &'a ShardSet,
    /// Number of high-order routing-tag bits used for IKE responder SPIs.
    /// Bootstrap tagging is a userspace slow-path decision; the XDP fast
    /// path looks initial exchanges up by their canonical ownership key and
    /// hands misses to this slow path.
    pub bootstrap_tag_bits: u8,
    /// ESP IP-fragment posture.
    pub esp_fragment_posture: EspFragmentPosture,
}

/// Ingress SWu packet view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwuPacket<'a> {
    /// UDP destination port.
    pub udp_destination_port: u16,
    /// Source IP observed at the edge.
    pub source_ip: IpAddress,
    /// UDP datagram payload.
    pub datagram: &'a [u8],
    /// Optional IP fragmentation metadata.
    pub fragment: Option<IpFragment>,
}

/// Packet classification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwuClassification {
    /// Accepted for steering.
    Steer {
        /// Key extracted from packet headers.
        key: SteerKey,
        /// Bootstrap shard selected for initial IKE_SA_INIT packets.
        bootstrap_shard: Option<crate::model::ShardId>,
    },
    /// NAT traversal keepalive consumed at the edge.
    NatKeepalive,
    /// Non-first fragment requires configured reassembly.
    NeedsReassembly,
    /// Rejected with a stable reason.
    Rejected {
        /// Stable rejection code.
        code: &'static str,
    },
}

impl SwuClassification {
    /// Stable classification code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Steer {
                key: SteerKey::IkeResponderSpi(_),
                ..
            } => "ike_responder_spi",
            Self::Steer {
                key: SteerKey::IkeInit { .. },
                ..
            } => "ike_sa_init_bootstrap",
            Self::Steer {
                key: SteerKey::EspSpi(_),
                ..
            } => "esp_in_udp",
            Self::NatKeepalive => "natt_keepalive",
            Self::NeedsReassembly => "ip_fragment_needs_reassembly",
            Self::Rejected { code } => code,
        }
    }

    /// Convert rejection into an error.
    pub fn accepted(self) -> Result<Self, IpsecLbError> {
        match self {
            Self::Rejected { code } => Err(IpsecLbError::packet_rejected(code)),
            _ => Ok(self),
        }
    }
}

/// Classify an ingress SWu packet.
#[must_use]
pub fn classify_swu_packet(
    packet: SwuPacket<'_>,
    config: SwuClassifierConfig<'_>,
) -> SwuClassification {
    if let Some(fragment) = packet.fragment {
        if fragment.is_non_first() {
            return match config.esp_fragment_posture {
                EspFragmentPosture::PreventIpFragmentation => SwuClassification::Rejected {
                    code: "unexpected_non_first_ip_fragment",
                },
                EspFragmentPosture::ReassembleBeforeSteer => SwuClassification::NeedsReassembly,
            };
        }
    }

    match packet.udp_destination_port {
        UDP_PORT_IKE => classify_ike(packet.datagram, packet.source_ip, config),
        UDP_PORT_IKE_NATT => classify_udp_4500(packet.datagram, packet.source_ip, config),
        _ => SwuClassification::Rejected {
            code: "unsupported_udp_port",
        },
    }
}

fn classify_udp_4500(
    datagram: &[u8],
    source_ip: IpAddress,
    config: SwuClassifierConfig<'_>,
) -> SwuClassification {
    if datagram == NAT_T_KEEPALIVE {
        return SwuClassification::NatKeepalive;
    }
    if datagram.starts_with(&NON_ESP_MARKER) {
        return classify_ike(&datagram[NON_ESP_MARKER.len()..], source_ip, config);
    }
    if datagram.len() < ESP_HEADER_PREFIX_LEN {
        return SwuClassification::Rejected {
            code: "runt_esp_in_udp",
        };
    }
    let spi = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    if spi == 0 {
        return SwuClassification::Rejected {
            code: "zero_esp_spi",
        };
    }
    SwuClassification::Steer {
        key: SteerKey::EspSpi(spi),
        bootstrap_shard: None,
    }
}

fn classify_ike(
    ike: &[u8],
    source_ip: IpAddress,
    config: SwuClassifierConfig<'_>,
) -> SwuClassification {
    let Some(header) = parse_ike_header(ike) else {
        return SwuClassification::Rejected {
            code: "malformed_ike_header",
        };
    };

    if header.responder_spi == 0 {
        if header.exchange_type != EXCHANGE_TYPE_IKE_SA_INIT {
            return SwuClassification::Rejected {
                code: "zero_responder_spi_outside_ike_sa_init",
            };
        }
        // Steer an initial IKE_SA_INIT (no allocated SPI yet) to the shard that
        // owns its bootstrap tag, using the shared FNV tag
        // (`ebpf_common::bootstrap_tag`) and the SAME rendezvous tag->shard
        // mapping the allocator's `decode` uses. This is a userspace slow-path
        // decision; the XDP fast path looks the exchange up by its canonical
        // ownership key and hands misses here.
        let tag = match source_ip {
            IpAddress::V4(octets) => {
                bootstrap_tag(header.initiator_spi, &octets, config.bootstrap_tag_bits)
            }
            IpAddress::V6(octets) => {
                bootstrap_tag(header.initiator_spi, &octets, config.bootstrap_tag_bits)
            }
        };
        let Some(tag) = tag else {
            return SwuClassification::Rejected {
                code: "invalid_bootstrap_tag_bits",
            };
        };
        let selector = RendezvousSelector;
        let Ok(bootstrap_shard) =
            selector.select(config.shards, &SelectionKey::Tag(u64::from(tag)))
        else {
            return SwuClassification::Rejected {
                code: "no_bootstrap_shard",
            };
        };
        return SwuClassification::Steer {
            key: SteerKey::IkeInit {
                initiator_spi: header.initiator_spi,
                source_ip,
            },
            bootstrap_shard: Some(bootstrap_shard),
        };
    }

    SwuClassification::Steer {
        key: SteerKey::IkeResponderSpi(header.responder_spi),
        bootstrap_shard: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IkeHeader {
    initiator_spi: u64,
    responder_spi: u64,
    exchange_type: u8,
}

fn parse_ike_header(input: &[u8]) -> Option<IkeHeader> {
    if input.len() < IKE_HEADER_LEN {
        return None;
    }
    let version = input[17];
    if (version >> 4) != IKEV2_MAJOR_VERSION {
        return None;
    }
    let declared_len = u32::from_be_bytes([input[24], input[25], input[26], input[27]]) as usize;
    if declared_len < IKE_HEADER_LEN || declared_len > input.len() {
        return None;
    }
    Some(IkeHeader {
        initiator_spi: u64::from_be_bytes(input[0..8].try_into().ok()?),
        responder_spi: u64::from_be_bytes(input[8..16].try_into().ok()?),
        exchange_type: input[18],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ShardId;

    fn shards() -> ShardSet {
        ShardSet::new(vec![ShardId::new(0), ShardId::new(1), ShardId::new(2)]).unwrap()
    }

    fn config(shards: &ShardSet) -> SwuClassifierConfig<'_> {
        SwuClassifierConfig {
            shards,
            bootstrap_tag_bits: 8,
            esp_fragment_posture: EspFragmentPosture::PreventIpFragmentation,
        }
    }

    fn ike_header(initiator_spi: u64, responder_spi: u64, exchange_type: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; IKE_HEADER_LEN];
        bytes[0..8].copy_from_slice(&initiator_spi.to_be_bytes());
        bytes[8..16].copy_from_slice(&responder_spi.to_be_bytes());
        bytes[17] = 0x20;
        bytes[18] = exchange_type;
        bytes[24..28].copy_from_slice(&(IKE_HEADER_LEN as u32).to_be_bytes());
        bytes
    }

    #[test]
    fn udp_500_initial_ike_sa_init_uses_bootstrap_key() {
        let shards = shards();
        let packet = SwuPacket {
            udp_destination_port: 500,
            source_ip: IpAddress::V4([198, 51, 100, 7]),
            datagram: &ike_header(0x1111, 0, EXCHANGE_TYPE_IKE_SA_INIT),
            fragment: None,
        };
        let classification = classify_swu_packet(packet, config(&shards));
        assert_eq!(classification.code(), "ike_sa_init_bootstrap");
        assert!(matches!(
            classification,
            SwuClassification::Steer {
                key: SteerKey::IkeInit { .. },
                bootstrap_shard: Some(_)
            }
        ));
    }

    #[test]
    fn udp_4500_non_esp_marker_classifies_ike_on_responder_spi() {
        let shards = shards();
        let mut datagram = NON_ESP_MARKER.to_vec();
        datagram.extend_from_slice(&ike_header(0x1111, 0x2222, 35));
        let classification = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: IpAddress::V4([203, 0, 113, 9]),
                datagram: &datagram,
                fragment: None,
            },
            config(&shards),
        );
        assert_eq!(classification.code(), "ike_responder_spi");
    }

    #[test]
    fn udp_4500_without_marker_classifies_esp_spi() {
        let shards = shards();
        let datagram = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1];
        let classification = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: IpAddress::V4([203, 0, 113, 9]),
                datagram: &datagram,
                fragment: None,
            },
            config(&shards),
        );
        assert!(matches!(
            classification,
            SwuClassification::Steer {
                key: SteerKey::EspSpi(0x1234_5678),
                ..
            }
        ));
    }

    #[test]
    fn mobike_source_change_does_not_change_nonzero_ike_steer_key() {
        let shards = shards();
        let ike = ike_header(0x1111, 0x2222, 37);
        let first = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 500,
                source_ip: IpAddress::V4([198, 51, 100, 1]),
                datagram: &ike,
                fragment: None,
            },
            config(&shards),
        );
        let second = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 500,
                source_ip: IpAddress::V4([198, 51, 100, 2]),
                datagram: &ike,
                fragment: None,
            },
            config(&shards),
        );
        assert_eq!(first, second);
    }

    #[test]
    fn malformed_and_runt_packets_fail_closed() {
        let shards = shards();
        assert_eq!(
            classify_swu_packet(
                SwuPacket {
                    udp_destination_port: 500,
                    source_ip: IpAddress::V4([1, 1, 1, 1]),
                    datagram: &[0u8; 8],
                    fragment: None,
                },
                config(&shards),
            )
            .code(),
            "malformed_ike_header"
        );
        assert_eq!(
            classify_swu_packet(
                SwuPacket {
                    udp_destination_port: 4500,
                    source_ip: IpAddress::V4([1, 1, 1, 1]),
                    datagram: &[1, 2, 3],
                    fragment: None,
                },
                config(&shards),
            )
            .code(),
            "runt_esp_in_udp"
        );
    }

    #[test]
    fn non_first_ip_fragment_is_not_silently_dropped() {
        let shards = shards();
        let classification = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: IpAddress::V4([1, 1, 1, 1]),
                datagram: &[],
                fragment: Some(IpFragment {
                    offset: 1,
                    more_fragments: false,
                }),
            },
            config(&shards),
        );
        assert_eq!(classification.code(), "unexpected_non_first_ip_fragment");

        let classification = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: IpAddress::V4([1, 1, 1, 1]),
                datagram: &[],
                fragment: Some(IpFragment {
                    offset: 1,
                    more_fragments: true,
                }),
            },
            SwuClassifierConfig {
                shards: &shards,
                bootstrap_tag_bits: 8,
                esp_fragment_posture: EspFragmentPosture::ReassembleBeforeSteer,
            },
        );
        assert_eq!(classification, SwuClassification::NeedsReassembly);
    }
}
