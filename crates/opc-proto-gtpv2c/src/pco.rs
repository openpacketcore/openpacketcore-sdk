//! TS 24.008 Protocol Configuration Options container helpers.
//!
//! GTPv2-C PCO and APCO Information Elements transport these bytes opaquely.
//! This module adds the bounded inner-container codec needed for DNS and
//! P-CSCF address relay without changing that raw-preserving transport layer.
//!
//! @spec 3GPP TS24008 10.5.6.3
//! @conformance boundary-only

use std::{error::Error, fmt};

/// PCO header with the extension bit set and configuration protocol `000`
/// (PPP for an IP PDP/PDN type).
pub const PCO_HEADER_PPP_FOR_IP_PDN: u8 = 0x80;

/// P-CSCF IPv6 Address container identifier.
pub const PCO_CONTAINER_P_CSCF_IPV6: u16 = 0x0001;

/// DNS Server IPv6 Address container identifier.
pub const PCO_CONTAINER_DNS_SERVER_IPV6: u16 = 0x0003;

/// P-CSCF IPv4 Address container identifier.
pub const PCO_CONTAINER_P_CSCF_IPV4: u16 = 0x000c;

/// DNS Server IPv4 Address container identifier.
pub const PCO_CONTAINER_DNS_SERVER_IPV4: u16 = 0x000d;

/// IPv4 Link MTU container identifier.
///
/// Direction-dependent, per TS 24.008 Table 10.5.154: MS to network this is
/// the zero-length IPv4 Link MTU *Request*; network to MS it carries the link
/// MTU itself as two octets.
pub const PCO_CONTAINER_IPV4_LINK_MTU: u16 = 0x0010;

/// P-CSCF reselection-support request container identifier.
///
/// In the MS-to-network direction this container has zero-length contents and
/// independently indicates support for P-CSCF reselection. It is not implied
/// by either P-CSCF address-family request.
pub const PCO_CONTAINER_P_CSCF_RESELECTION_SUPPORT: u16 = 0x0012;

/// IPCP configuration-protocol identifier (RFC 1332).
///
/// TS 24.008 10.5.6.3 requires support for this identifier, and places it in
/// the configuration protocol options list, which precedes the container-based
/// additional parameters list.
pub const PCO_PROTOCOL_IPCP: u16 = 0x8021;

/// Maximum number of length-delimited containers decoded from one PCO value.
///
/// This bounds parser work and address-vector growth independently of the
/// outer GTPv2-C IE length.
pub const PCO_MAX_CONTAINERS: usize = 64;

const PCO_CONTAINER_HEADER_LEN: usize = 3;

/// RFC 1661 configuration-packet header: Code, Identifier and a two-octet
/// Length that counts itself.
const IPCP_HEADER_LEN: u8 = 4;

/// RFC 1877 DNS option: Type, Length, and a four-octet address.
const IPCP_DNS_OPTION_LEN: u8 = 6;

const IPCP_CODE_CONFIGURE_REQUEST: u8 = 1;
const IPCP_CODE_CONFIGURE_NAK: u8 = 3;

/// Primary DNS Server Address option (RFC 1877 §1.1).
const IPCP_OPTION_PRIMARY_DNS: u8 = 129;

/// Secondary DNS Server Address option (RFC 1877 §1.2).
const IPCP_OPTION_SECONDARY_DNS: u8 = 131;

/// Request for DNS server addresses via an IPCP Configure-Request.
///
/// A peer may serve DNS through the IPCP option exchange instead of, or in
/// addition to, the `0x000d` container. RFC 1877 §1.1 has the requesting side
/// send the address as four zero octets, and the peer answer with a
/// Configure-Nak carrying the real address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcpDnsRequest {
    /// Request the Primary DNS Server Address option (RFC 1877 type 129).
    pub primary_dns: bool,
    /// Request the Secondary DNS Server Address option (RFC 1877 type 131).
    pub secondary_dns: bool,
    /// Identifier echoed by the peer in its reply, per RFC 1661 §5.
    ///
    /// This is opaque to the encoder; a caller that correlates replies is
    /// responsible for varying it.
    pub identifier: u8,
}

impl IpcpDnsRequest {
    /// Construct a request selecting no option.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            primary_dns: false,
            secondary_dns: false,
            identifier: 0,
        }
    }

    /// Return whether at least one DNS option is selected.
    ///
    /// [`Self::identifier`] alone never makes a request; without an option the
    /// unit would be a Configure-Request carrying nothing to negotiate.
    #[must_use]
    pub const fn is_requested(self) -> bool {
        self.primary_dns || self.secondary_dns
    }

    /// Length of the IPCP unit contents for the selected options.
    ///
    /// Bounded by construction at `4 + 6 + 6 = 16`, so it always fits the
    /// one-octet unit length that TS 24.008 10.5.6.3 defines.
    const fn contents_len(self) -> u8 {
        let mut len = IPCP_HEADER_LEN;
        if self.primary_dns {
            len += IPCP_DNS_OPTION_LEN;
        }
        if self.secondary_dns {
            len += IPCP_DNS_OPTION_LEN;
        }
        len
    }
}

/// Parameters requested in an MS-to-network PCO or APCO.
///
/// Container parameters are encoded as zero-length containers. [`Self::ipcp_dns`]
/// is instead a structured RFC 1332 unit and is emitted ahead of them, because
/// TS 24.008 10.5.6.3 places the configuration protocol options list before the
/// additional parameters list. An empty request encodes to an empty vector so a
/// caller can omit the outer PCO IE.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PcoRequest {
    /// Request P-CSCF IPv6 addresses.
    pub p_cscf_ipv6: bool,
    /// Request DNS Server IPv6 addresses.
    pub dns_server_ipv6: bool,
    /// Request P-CSCF IPv4 addresses.
    pub p_cscf_ipv4: bool,
    /// Request DNS Server IPv4 addresses.
    pub dns_server_ipv4: bool,
    /// Indicate support for P-CSCF reselection.
    ///
    /// This emits the independent empty container `0x0012`; the P-CSCF IPv4
    /// and IPv6 address request flags never imply it.
    pub p_cscf_reselection_support: bool,
    /// Request the network-supplied IPv4 Link MTU.
    ///
    /// On a tunnelled access the packet the UE emits is carried inside IPsec
    /// ESP and then GTP-U, so the UE cannot infer the usable MTU from its own
    /// link. Asking is the only way it learns.
    pub ipv4_link_mtu: bool,
    /// Request DNS server addresses through an IPCP Configure-Request.
    ///
    /// This is independent of [`Self::dns_server_ipv4`]: a peer may answer
    /// either mechanism, and asking both ways is what an interoperating
    /// gateway does.
    pub ipcp_dns: IpcpDnsRequest,
}

impl PcoRequest {
    /// Construct a request with no selected parameters.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            p_cscf_ipv6: false,
            dns_server_ipv6: false,
            p_cscf_ipv4: false,
            dns_server_ipv4: false,
            p_cscf_reselection_support: false,
            ipv4_link_mtu: false,
            ipcp_dns: IpcpDnsRequest::none(),
        }
    }

    /// Return whether at least one parameter is requested.
    #[must_use]
    pub const fn is_requested(self) -> bool {
        self.p_cscf_ipv6
            || self.dns_server_ipv6
            || self.p_cscf_ipv4
            || self.dns_server_ipv4
            || self.p_cscf_reselection_support
            || self.ipv4_link_mtu
            || self.ipcp_dns.is_requested()
    }

    /// Encode MS-to-network PCO contents.
    ///
    /// The IPCP unit comes first when selected, then the requested containers
    /// in ascending identifier order. Each container parameter is represented
    /// by its two-octet identifier and a zero contents length. When no
    /// parameter is selected, this returns an empty vector rather than a
    /// header-only PCO.
    #[must_use]
    pub fn encode_request_contents(self) -> Vec<u8> {
        if !self.is_requested() {
            return Vec::new();
        }

        let requested_count = [
            self.p_cscf_ipv6,
            self.dns_server_ipv6,
            self.p_cscf_ipv4,
            self.dns_server_ipv4,
            self.ipv4_link_mtu,
            self.p_cscf_reselection_support,
        ]
        .into_iter()
        .filter(|requested| *requested)
        .count();
        let ipcp_len = if self.ipcp_dns.is_requested() {
            PCO_CONTAINER_HEADER_LEN + usize::from(self.ipcp_dns.contents_len())
        } else {
            0
        };
        let mut encoded = Vec::with_capacity(
            1 + requested_count.saturating_mul(PCO_CONTAINER_HEADER_LEN) + ipcp_len,
        );
        encoded.push(PCO_HEADER_PPP_FOR_IP_PDN);
        // TS 24.008 10.5.6.3: the configuration protocol options list occupies
        // octets 4..w and the additional parameters list w+1..z, so the IPCP
        // unit is positionally ahead of every container.
        if self.ipcp_dns.is_requested() {
            encode_ipcp_configure_request(&mut encoded, self.ipcp_dns);
        }
        if self.p_cscf_ipv6 {
            encode_empty_request_container(&mut encoded, PCO_CONTAINER_P_CSCF_IPV6);
        }
        if self.dns_server_ipv6 {
            encode_empty_request_container(&mut encoded, PCO_CONTAINER_DNS_SERVER_IPV6);
        }
        if self.p_cscf_ipv4 {
            encode_empty_request_container(&mut encoded, PCO_CONTAINER_P_CSCF_IPV4);
        }
        if self.dns_server_ipv4 {
            encode_empty_request_container(&mut encoded, PCO_CONTAINER_DNS_SERVER_IPV4);
        }
        if self.ipv4_link_mtu {
            encode_empty_request_container(&mut encoded, PCO_CONTAINER_IPV4_LINK_MTU);
        }
        if self.p_cscf_reselection_support {
            encode_empty_request_container(&mut encoded, PCO_CONTAINER_P_CSCF_RESELECTION_SUPPORT);
        }
        encoded
    }
}

fn encode_empty_request_container(encoded: &mut Vec<u8>, identifier: u16) {
    encoded.extend_from_slice(&identifier.to_be_bytes());
    encoded.push(0);
}

/// Encode the `0x8021` unit carrying an IPCP Configure-Request.
///
/// The unit contents is an RFC 1661 packet stripped of its Protocol and
/// Padding octets, as TS 24.008 10.5.6.3 requires: Code, Identifier, and a
/// two-octet Length that counts the header plus every option.
fn encode_ipcp_configure_request(encoded: &mut Vec<u8>, request: IpcpDnsRequest) {
    let contents_len = request.contents_len();
    encoded.extend_from_slice(&PCO_PROTOCOL_IPCP.to_be_bytes());
    encoded.push(contents_len);
    encoded.push(IPCP_CODE_CONFIGURE_REQUEST);
    encoded.push(request.identifier);
    encoded.extend_from_slice(&u16::from(contents_len).to_be_bytes());
    if request.primary_dns {
        encode_ipcp_dns_option(encoded, IPCP_OPTION_PRIMARY_DNS);
    }
    if request.secondary_dns {
        encode_ipcp_dns_option(encoded, IPCP_OPTION_SECONDARY_DNS);
    }
}

/// Encode one RFC 1877 DNS option requesting a peer-supplied address.
///
/// The address is four zero octets: RFC 1877 §1.1 defines that as the signal
/// for the peer to answer with a Configure-Nak carrying the real address.
fn encode_ipcp_dns_option(encoded: &mut Vec<u8>, option_type: u8) {
    encoded.push(option_type);
    encoded.push(IPCP_DNS_OPTION_LEN);
    encoded.extend_from_slice(&[0; 4]);
}

/// DNS and P-CSCF addresses decoded from a network-to-MS PCO.
///
/// Repeated address containers are retained in wire order. Well-formed unknown
/// containers are skipped. `Debug` reports counts only so infrastructure
/// addresses are not copied into incidental diagnostics.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PcoAddressConfiguration {
    /// P-CSCF IPv6 addresses from container `0x0001`.
    pub p_cscf_ipv6: Vec<[u8; 16]>,
    /// DNS Server IPv6 addresses from container `0x0003`.
    pub dns_server_ipv6: Vec<[u8; 16]>,
    /// P-CSCF IPv4 addresses from container `0x000c`.
    pub p_cscf_ipv4: Vec<[u8; 4]>,
    /// DNS Server IPv4 addresses from container `0x000d`.
    pub dns_server_ipv4: Vec<[u8; 4]>,
    /// Primary DNS Server Address from an IPCP Configure-Nak (RFC 1877 §1.1).
    ///
    /// Held separately from [`Self::dns_server_ipv4`] so the answering
    /// mechanism stays visible; [`Self::dns_server_ipv4_all`] merges them.
    pub ipcp_primary_dns: Option<[u8; 4]>,
    /// Secondary DNS Server Address from an IPCP Configure-Nak (RFC 1877 §1.2).
    pub ipcp_secondary_dns: Option<[u8; 4]>,
    /// IPv4 link MTU in octets, from container `0x0010`.
    ///
    /// `Option` rather than a sentinel: TS 24.008 reserves no "absent" value,
    /// and zero is not one.
    pub ipv4_link_mtu: Option<u16>,
}

impl PcoAddressConfiguration {
    /// Return whether no supported address was present.
    ///
    /// This asks about *addresses* only. A value carrying just an IPv4 link
    /// MTU is still empty by this predicate, because the common caller uses it
    /// to decide whether to fall back to configured DNS; reporting non-empty
    /// for an MTU-only value would skip that fallback and establish a session
    /// with no usable DNS. Check [`Self::ipv4_link_mtu`] separately.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.p_cscf_ipv6.is_empty()
            && self.dns_server_ipv6.is_empty()
            && self.p_cscf_ipv4.is_empty()
            && self.dns_server_ipv4.is_empty()
            && self.ipcp_primary_dns.is_none()
            && self.ipcp_secondary_dns.is_none()
    }

    /// Every IPv4 DNS server address the peer supplied, by either mechanism.
    ///
    /// Container addresses come first in wire order, then the IPCP primary and
    /// secondary addresses, with duplicates dropped. A peer answers through
    /// whichever mechanism it implements, so a caller that reads only
    /// [`Self::dns_server_ipv4`] can end up with a session that established
    /// cleanly and has no usable DNS. Prefer this accessor.
    #[must_use]
    pub fn dns_server_ipv4_all(&self) -> Vec<[u8; 4]> {
        let mut all = self.dns_server_ipv4.clone();
        for address in [self.ipcp_primary_dns, self.ipcp_secondary_dns]
            .into_iter()
            .flatten()
        {
            if !all.contains(&address) {
                all.push(address);
            }
        }
        all
    }

    /// Decode network-to-MS PCO contents.
    ///
    /// Parsing is all-or-nothing: malformed framing or a known address
    /// container with the wrong fixed length rejects the complete value.
    /// Unknown, well-formed length-delimited containers are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`PcoDecodeError`] for an absent/unsupported header, truncated
    /// container framing, a declared length beyond the remaining input, an
    /// invalid fixed address length, or more than [`PCO_MAX_CONTAINERS`].
    pub fn decode_network_contents(value: &[u8]) -> Result<Self, PcoDecodeError> {
        let (&header, mut remaining) = value.split_first().ok_or(PcoDecodeError::Empty)?;
        if header != PCO_HEADER_PPP_FOR_IP_PDN {
            return Err(PcoDecodeError::UnsupportedHeader);
        }

        let mut decoded = Self::default();
        let mut container_count = 0usize;
        while !remaining.is_empty() {
            container_count = container_count
                .checked_add(1)
                .ok_or(PcoDecodeError::TooManyContainers)?;
            if container_count > PCO_MAX_CONTAINERS {
                return Err(PcoDecodeError::TooManyContainers);
            }
            if remaining.len() < PCO_CONTAINER_HEADER_LEN {
                return Err(PcoDecodeError::ContainerHeaderTruncated);
            }

            let identifier = u16::from_be_bytes([remaining[0], remaining[1]]);
            let contents_len = usize::from(remaining[2]);
            let contents_end = PCO_CONTAINER_HEADER_LEN
                .checked_add(contents_len)
                .ok_or(PcoDecodeError::ContainerLengthOverrun)?;
            if contents_end > remaining.len() {
                return Err(PcoDecodeError::ContainerLengthOverrun);
            }
            let contents = &remaining[PCO_CONTAINER_HEADER_LEN..contents_end];
            match identifier {
                PCO_CONTAINER_P_CSCF_IPV6 => {
                    decoded.p_cscf_ipv6.push(decode_ipv6_address(contents)?)
                }
                PCO_CONTAINER_DNS_SERVER_IPV6 => {
                    decoded.dns_server_ipv6.push(decode_ipv6_address(contents)?)
                }
                PCO_CONTAINER_P_CSCF_IPV4 => {
                    decoded.p_cscf_ipv4.push(decode_ipv4_address(contents)?)
                }
                PCO_CONTAINER_DNS_SERVER_IPV4 => {
                    decoded.dns_server_ipv4.push(decode_ipv4_address(contents)?)
                }
                PCO_CONTAINER_IPV4_LINK_MTU => decode_ipv4_link_mtu(contents, &mut decoded),
                PCO_PROTOCOL_IPCP => decode_ipcp_unit(contents, &mut decoded)?,
                _ => {}
            }
            remaining = &remaining[contents_end..];
        }
        Ok(decoded)
    }
}

impl fmt::Debug for PcoAddressConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PcoAddressConfiguration")
            .field("p_cscf_ipv6_count", &self.p_cscf_ipv6.len())
            .field("dns_server_ipv6_count", &self.dns_server_ipv6.len())
            .field("p_cscf_ipv4_count", &self.p_cscf_ipv4.len())
            .field("dns_server_ipv4_count", &self.dns_server_ipv4.len())
            .field("ipcp_primary_dns_present", &self.ipcp_primary_dns.is_some())
            .field(
                "ipcp_secondary_dns_present",
                &self.ipcp_secondary_dns.is_some(),
            )
            .field("ipv4_link_mtu", &self.ipv4_link_mtu)
            .finish()
    }
}

/// Decode a `0x8021` unit, recording any peer-supplied DNS address.
///
/// Only a Configure-Nak carries addresses: RFC 1661 §5.3 has a Configure-Ack
/// echo the request's options verbatim, and this crate always requests with
/// the RFC 1877 all-zero address, so an Ack conveys nothing. Other codes are
/// accepted and ignored rather than rejected.
fn decode_ipcp_unit(
    contents: &[u8],
    decoded: &mut PcoAddressConfiguration,
) -> Result<(), PcoDecodeError> {
    let header_len = usize::from(IPCP_HEADER_LEN);
    if contents.len() < header_len {
        return Err(PcoDecodeError::IpcpHeaderTruncated);
    }
    let code = contents[0];
    // contents[1] is the Identifier, which correlates a reply to a request and
    // carries nothing this decoder interprets.
    let declared = usize::from(u16::from_be_bytes([contents[2], contents[3]]));
    if declared < header_len || declared > contents.len() {
        return Err(PcoDecodeError::IpcpLengthInvalid);
    }
    if code != IPCP_CODE_CONFIGURE_NAK {
        return Ok(());
    }

    // Each iteration consumes at least two octets of a slice the one-octet
    // unit length already bounds to 255, so this terminates without a
    // separate option cap.
    let mut remaining = &contents[header_len..declared];
    while !remaining.is_empty() {
        let (&option_type, rest) = remaining
            .split_first()
            .ok_or(PcoDecodeError::IpcpOptionTruncated)?;
        let (&option_len, _) = rest
            .split_first()
            .ok_or(PcoDecodeError::IpcpOptionTruncated)?;
        let option_len = usize::from(option_len);
        // RFC 1661 §6: the option Length counts the Type and Length octets.
        if option_len < 2 || option_len > remaining.len() {
            return Err(PcoDecodeError::IpcpOptionLengthInvalid);
        }
        let data = &remaining[2..option_len];
        match option_type {
            IPCP_OPTION_PRIMARY_DNS => {
                decode_ipcp_dns_option(data, &mut decoded.ipcp_primary_dns)?;
            }
            IPCP_OPTION_SECONDARY_DNS => {
                decode_ipcp_dns_option(data, &mut decoded.ipcp_secondary_dns)?;
            }
            _ => {}
        }
        remaining = &remaining[option_len..];
    }
    Ok(())
}

/// Record one RFC 1877 DNS address, keeping the first of any duplicate.
///
/// An all-zero address is the RFC 1877 request encoding, not a server, so a
/// peer that echoes it back is treated as having supplied nothing.
fn decode_ipcp_dns_option(data: &[u8], slot: &mut Option<[u8; 4]>) -> Result<(), PcoDecodeError> {
    let address =
        <[u8; 4]>::try_from(data).map_err(|_| PcoDecodeError::IpcpDnsOptionLengthInvalid)?;
    if address != [0; 4] && slot.is_none() {
        *slot = Some(address);
    }
    Ok(())
}

/// Smallest MTU an IPv4 link can carry.
///
/// RFC 791 requires every internet module to forward a 68-octet datagram
/// without further fragmentation, so nothing below this is a usable link MTU.
const MIN_IPV4_LINK_MTU: u16 = 68;

/// Record the IPv4 link MTU, keeping the first of any repeat.
///
/// TS 24.008 10.5.6.3 is explicit that a container whose contents length is
/// not two "shall be ignored by the receiver", so a malformed instance is
/// skipped rather than rejecting the whole value. That is deliberately unlike
/// the address containers, for which the specification states no such rule and
/// this codec fails closed.
fn decode_ipv4_link_mtu(contents: &[u8], decoded: &mut PcoAddressConfiguration) {
    let Ok(octets) = <[u8; 2]>::try_from(contents) else {
        return;
    };
    let mtu = u16::from_be_bytes(octets);
    // A value below the RFC 791 minimum is not an MTU. Surfacing one lets a
    // caller that applies what it asked for blackhole the whole user plane on
    // two unvalidated octets, so it is skipped like a wrong-length instance --
    // the same reasoning the sibling DNS option uses for an all-zero address.
    if mtu < MIN_IPV4_LINK_MTU {
        return;
    }
    if decoded.ipv4_link_mtu.is_none() {
        decoded.ipv4_link_mtu = Some(mtu);
    }
}

fn decode_ipv4_address(contents: &[u8]) -> Result<[u8; 4], PcoDecodeError> {
    <[u8; 4]>::try_from(contents).map_err(|_| PcoDecodeError::InvalidIpv4AddressLength)
}

fn decode_ipv6_address(contents: &[u8]) -> Result<[u8; 16], PcoDecodeError> {
    <[u8; 16]>::try_from(contents).map_err(|_| PcoDecodeError::InvalidIpv6AddressLength)
}

/// Structural failure while decoding network-to-MS PCO contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcoDecodeError {
    /// The configuration-protocol header octet was absent.
    Empty,
    /// The header was not extension-bit plus configuration protocol `000`.
    UnsupportedHeader,
    /// Trailing input was shorter than a three-octet container header.
    ContainerHeaderTruncated,
    /// A container's declared contents extended beyond the remaining PCO.
    ContainerLengthOverrun,
    /// A known IPv4 address container did not contain exactly four octets.
    InvalidIpv4AddressLength,
    /// A known IPv6 address container did not contain exactly sixteen octets.
    InvalidIpv6AddressLength,
    /// The value exceeded [`PCO_MAX_CONTAINERS`].
    TooManyContainers,
    /// An IPCP unit was shorter than the RFC 1661 four-octet header.
    IpcpHeaderTruncated,
    /// An IPCP Length was below the header size or beyond the unit contents.
    IpcpLengthInvalid,
    /// An IPCP option header was truncated.
    IpcpOptionTruncated,
    /// An IPCP option Length was below two or beyond the remaining options.
    IpcpOptionLengthInvalid,
    /// An RFC 1877 DNS option did not carry exactly four address octets.
    IpcpDnsOptionLengthInvalid,
}

impl PcoDecodeError {
    /// Return a stable, payload-free diagnostic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "pco_empty",
            Self::UnsupportedHeader => "pco_unsupported_header",
            Self::ContainerHeaderTruncated => "pco_container_header_truncated",
            Self::ContainerLengthOverrun => "pco_container_length_overrun",
            Self::InvalidIpv4AddressLength => "pco_invalid_ipv4_address_length",
            Self::InvalidIpv6AddressLength => "pco_invalid_ipv6_address_length",
            Self::TooManyContainers => "pco_too_many_containers",
            Self::IpcpHeaderTruncated => "pco_ipcp_header_truncated",
            Self::IpcpLengthInvalid => "pco_ipcp_length_invalid",
            Self::IpcpOptionTruncated => "pco_ipcp_option_truncated",
            Self::IpcpOptionLengthInvalid => "pco_ipcp_option_length_invalid",
            Self::IpcpDnsOptionLengthInvalid => "pco_ipcp_dns_option_length_invalid",
        }
    }
}

impl fmt::Display for PcoDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for PcoDecodeError {}
