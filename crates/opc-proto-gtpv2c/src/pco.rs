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

/// Maximum number of length-delimited containers decoded from one PCO value.
///
/// This bounds parser work and address-vector growth independently of the
/// outer GTPv2-C IE length.
pub const PCO_MAX_CONTAINERS: usize = 64;

const PCO_CONTAINER_HEADER_LEN: usize = 3;

/// Address parameters requested in an MS-to-network PCO.
///
/// Every selected parameter is encoded as a zero-length container. An empty
/// request encodes to an empty vector so a caller can omit the outer PCO IE.
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
}

impl PcoRequest {
    /// Construct a request with no selected address parameters.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            p_cscf_ipv6: false,
            dns_server_ipv6: false,
            p_cscf_ipv4: false,
            dns_server_ipv4: false,
        }
    }

    /// Return whether at least one address parameter is requested.
    #[must_use]
    pub const fn is_requested(self) -> bool {
        self.p_cscf_ipv6 || self.dns_server_ipv6 || self.p_cscf_ipv4 || self.dns_server_ipv4
    }

    /// Encode MS-to-network PCO contents in ascending container-ID order.
    ///
    /// Each selected parameter is represented by its two-octet identifier and
    /// a zero contents length. When no parameter is selected, this returns an
    /// empty vector rather than a header-only PCO.
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
        ]
        .into_iter()
        .filter(|requested| *requested)
        .count();
        let mut encoded =
            Vec::with_capacity(1 + requested_count.saturating_mul(PCO_CONTAINER_HEADER_LEN));
        encoded.push(PCO_HEADER_PPP_FOR_IP_PDN);
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
        encoded
    }
}

fn encode_empty_request_container(encoded: &mut Vec<u8>, identifier: u16) {
    encoded.extend_from_slice(&identifier.to_be_bytes());
    encoded.push(0);
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
}

impl PcoAddressConfiguration {
    /// Return whether no supported address container was present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.p_cscf_ipv6.is_empty()
            && self.dns_server_ipv6.is_empty()
            && self.p_cscf_ipv4.is_empty()
            && self.dns_server_ipv4.is_empty()
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
            .finish()
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
        }
    }
}

impl fmt::Display for PcoDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for PcoDecodeError {}
