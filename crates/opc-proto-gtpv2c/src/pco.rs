//! TS 24.008 Protocol Configuration Options container helpers.
//!
//! GTPv2-C PCO and APCO Information Elements transport these bytes opaquely.
//! This module adds the bounded inner-container codec needed for DNS and
//! P-CSCF address relay without changing that raw-preserving transport layer.
//!
//! Clause references are to TS 24.008 V20.0.0. The 10.5.6.3 text this module
//! relies on is unchanged from V13.7.0 through that release, so a bare
//! `10.5.6.3` elsewhere in the crate resolves to the same wording.
//!
//! @spec 3GPP TS24008 V20.0.0 10.5.6.3
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
/// indicates support for P-CSCF reselection. It is not implied by either
/// P-CSCF address-family request, but neither is it independent of them: TS
/// 24.008 10.5.6.3 says of this container that "This PCO parameter may be
/// present only if a container with P-CSCF IPv4 Address Request or P-CSCF
/// IPv6 Address Request is present." [`PcscfRequest`] carries the two
/// together so an unaccompanied instance cannot be built.
///
/// The identifier is Reserved in the network-to-MS direction.
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

/// [`PcoIpcpDiscard::unit_index`] numbers units within one value, and the cap
/// above is what keeps that number inside one octet. Asserted rather than
/// commented so raising the cap past 255 is a compile error at the definition
/// instead of a silent truncation at the recording site.
const _: () = assert!(PCO_MAX_CONTAINERS <= u8::MAX as usize);

const PCO_CONTAINER_HEADER_LEN: usize = 3;

/// RFC 1661 configuration-packet header: Code, Identifier and a two-octet
/// Length that counts itself.
const IPCP_HEADER_LEN: u8 = 4;

/// RFC 1877 DNS option: Type, Length, and a four-octet address.
const IPCP_DNS_OPTION_LEN: u8 = 6;

const IPCP_CODE_CONFIGURE_REQUEST: u8 = 1;
const IPCP_CODE_CONFIGURE_ACK: u8 = 2;
const IPCP_CODE_CONFIGURE_NAK: u8 = 3;
const IPCP_CODE_CONFIGURE_REJECT: u8 = 4;

/// Primary DNS Server Address option (RFC 1877 §1.1).
const IPCP_OPTION_PRIMARY_DNS: u8 = 129;

/// Secondary DNS Server Address option (RFC 1877 §1.3).
const IPCP_OPTION_SECONDARY_DNS: u8 = 131;

/// Return whether a network-to-MS identifier belongs to the container list.
///
/// TS 24.008 V20.0.0 Table 10.5.154 assigns these ranges to additional
/// parameter containers, including table-reserved and operator-specific
/// values. An unsupported identifier inside the registry still establishes
/// the second logical list; otherwise a later IPCP unit could be adopted from
/// outside the configuration protocol options list. Identifiers not assigned
/// by that table remain ambiguous and do not establish a boundary.
const fn is_network_to_ms_container_identifier(identifier: u16) -> bool {
    matches!(
        identifier,
        0x0001..=0x002b
            | 0x0030..=0x0032
            | 0x0035..=0x0041
            | 0x0047..=0x004a
            | 0x0050..=0x0052
            | 0x0056..=0x0059
            | 0x0060..=0x0062
            | 0xff00..=0xffff
    )
}

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

/// The caller's position on outstanding IPCP Configure-Requests.
///
/// RFC 1661 §5.3: "On reception of a Configure-Nak, the Identifier field MUST
/// match that of the last transmitted Configure-Request. Invalid packets are
/// silently discarded." A decoder handed no Identifier cannot satisfy that, so
/// [`Self::default`] is [`Self::none`] and discards every Configure-Nak: the
/// fail-closed position is the one a caller reaches by accident.
///
/// An uncorrelated Nak yields no address rather than an error, following the
/// same sentence's "silently discarded"; the value around it still decodes and
/// the omission is reported through [`PcoDecoded::ipcp_discards`].
///
/// Only one Identifier is outstanding at a time. RFC 1661's automaton permits
/// retransmission under a fresh Identifier, so a Nak answering a superseded
/// request is discarded as [`PcoIpcpDiscardReason::IdentifierMismatch`] rather
/// than silently ignored, which is what makes that stricture observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IpcpNakCorrelation {
    /// Identifier of the last transmitted Configure-Request, when one is
    /// outstanding. `None` is what makes [`Default`] fail closed.
    expected_identifier: Option<u8>,
    /// Whether a Primary DNS Server Address option was solicited.
    primary_dns: bool,
    /// Whether a Secondary DNS Server Address option was solicited.
    secondary_dns: bool,
}

impl IpcpNakCorrelation {
    /// No Configure-Request is outstanding; discard every Configure-Nak.
    ///
    /// This is what [`Default`] produces.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            expected_identifier: None,
            primary_dns: false,
            secondary_dns: false,
        }
    }

    /// Correlate against the Identifier of a transmitted Configure-Request,
    /// accepting both RFC 1877 DNS options.
    ///
    /// This is the RFC-permissive constructor: RFC 1661 §5.3 lets a peer append
    /// Configuration Options that were not in the Configure-Request, so a Nak
    /// carrying an option this side did not ask for is not invalid.
    #[must_use]
    pub const fn expecting(identifier: u8) -> Self {
        Self {
            expected_identifier: Some(identifier),
            primary_dns: true,
            secondary_dns: true,
        }
    }

    /// Correlate against the request this SDK encoded, accepting only the
    /// options it actually solicited.
    ///
    /// Declining an unsolicited option is engineering judgement and not a
    /// specification requirement -- see [`Self::expecting`] for the permissive
    /// reading. It costs a peer nothing that RFC 1661 guarantees it, and it
    /// removes one way an off-path sender can place a DNS server in a session
    /// it never negotiated. It is not an on-path control: the Identifier is
    /// visible on the wire, and [`IpcpDnsRequest::identifier`] is documented as
    /// opaque with nothing obliging a caller to vary it.
    ///
    /// Returns [`Self::none`] for a request that selects no option, because
    /// [`IpcpDnsRequest::identifier`] alone never emits a unit; see
    /// [`IpcpDnsRequest::is_requested`].
    #[must_use]
    pub const fn for_request(request: IpcpDnsRequest) -> Self {
        if !request.is_requested() {
            return Self::none();
        }
        Self {
            expected_identifier: Some(request.identifier),
            primary_dns: request.primary_dns,
            secondary_dns: request.secondary_dns,
        }
    }

    /// Return whether a Configure-Nak carrying `identifier` is correlated.
    #[must_use]
    pub const fn accepts_identifier(self, identifier: u8) -> bool {
        match self.expected_identifier {
            Some(expected) => expected == identifier,
            None => false,
        }
    }

    /// Return whether any Configure-Request is outstanding.
    ///
    /// Held apart from [`Self::accepts_identifier`] so the two failure modes
    /// stay distinguishable in the discard evidence: "nobody asked" and "this
    /// is not the answer to what was asked" are different operator problems.
    const fn is_outstanding(self) -> bool {
        self.expected_identifier.is_some()
    }

    /// Return whether an RFC 1877 DNS option type was solicited.
    const fn accepts_option(self, option_type: u8) -> bool {
        match option_type {
            IPCP_OPTION_PRIMARY_DNS => self.primary_dns,
            IPCP_OPTION_SECONDARY_DNS => self.secondary_dns,
            _ => false,
        }
    }
}

/// P-CSCF address-request containers selected in an MS-to-network PCO.
///
/// Every variant selects at least one address-request container. There is
/// deliberately no "neither" variant, which is what makes an unaccompanied
/// [`PcscfRequest::reselection_support`] unrepresentable. Adding a variant is a
/// compile error in [`Self::includes_ipv4`] and [`Self::includes_ipv6`], so
/// that property cannot be lost by an edit that only touches this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcscfAddressRequest {
    /// Request P-CSCF IPv4 addresses only: container `0x000c`.
    Ipv4,
    /// Request P-CSCF IPv6 addresses only: container `0x0001`.
    Ipv6,
    /// Request both address families: containers `0x0001` and `0x000c`.
    Ipv4AndIpv6,
}

impl PcscfAddressRequest {
    /// Return whether container `0x000c` is selected.
    ///
    /// Written as an exhaustive `match` rather than a `matches!`, because
    /// `matches!` would answer `false` for a variant added later. A variant
    /// answering `false` here and in [`Self::includes_ipv6`] selects neither
    /// address container, which is what would let [`PcscfRequest`] emit an
    /// unaccompanied `0x0012` again. This way growing the enum is a compile
    /// error at both sites instead.
    #[must_use]
    pub const fn includes_ipv4(self) -> bool {
        match self {
            Self::Ipv4 => true,
            Self::Ipv6 => false,
            Self::Ipv4AndIpv6 => true,
        }
    }

    /// Return whether container `0x0001` is selected.
    ///
    /// Exhaustive for the reason given on [`Self::includes_ipv4`].
    #[must_use]
    pub const fn includes_ipv6(self) -> bool {
        match self {
            Self::Ipv4 => false,
            Self::Ipv6 => true,
            Self::Ipv4AndIpv6 => true,
        }
    }
}

/// P-CSCF parameters requested in an MS-to-network PCO or APCO.
///
/// TS 24.008 10.5.6.3 binds the re-selection support container to an address
/// request: "This PCO parameter may be present only if a container with P-CSCF
/// IPv4 Address Request or P-CSCF IPv6 Address Request is present." Carrying
/// both in one value is what enforces that rule, so the encoder cannot emit a
/// container the specification forbids and needs no runtime check to say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcscfRequest {
    /// Address-request containers to emit.
    pub addresses: PcscfAddressRequest,
    /// Also emit the empty P-CSCF Re-selection support container `0x0012`.
    ///
    /// The implication runs one way only. Selecting an address family never
    /// sets this: TS 24.008 10.5.6.3 has the container mean that the UE
    /// supports the TS 24.229 re-selection procedures, which is a separate
    /// capability from wanting an address. Selecting it without an address
    /// family is what the specification forbids, and [`Self::addresses`]
    /// cannot express that.
    pub reselection_support: bool,
}

impl PcscfRequest {
    /// Request P-CSCF addresses without declaring re-selection support.
    #[must_use]
    pub const fn addresses(addresses: PcscfAddressRequest) -> Self {
        Self {
            addresses,
            reselection_support: false,
        }
    }

    /// Request P-CSCF addresses and declare re-selection support alongside them.
    #[must_use]
    pub const fn with_reselection_support(addresses: PcscfAddressRequest) -> Self {
        Self {
            addresses,
            reselection_support: true,
        }
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
    /// P-CSCF address requests and any accompanying re-selection support.
    ///
    /// Grouped rather than flat because TS 24.008 10.5.6.3 makes the
    /// re-selection support container conditional on an address request; see
    /// [`PcscfRequest`].
    pub p_cscf: Option<PcscfRequest>,
    /// Request DNS Server IPv6 addresses.
    pub dns_server_ipv6: bool,
    /// Request DNS Server IPv4 addresses.
    pub dns_server_ipv4: bool,
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
            p_cscf: None,
            dns_server_ipv6: false,
            dns_server_ipv4: false,
            ipv4_link_mtu: false,
            ipcp_dns: IpcpDnsRequest::none(),
        }
    }

    /// Return whether at least one parameter is requested.
    #[must_use]
    pub const fn is_requested(self) -> bool {
        self.p_cscf.is_some()
            || self.dns_server_ipv6
            || self.dns_server_ipv4
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

        let p_cscf_container_count = self.p_cscf.map_or(0, |p_cscf| {
            usize::from(p_cscf.addresses.includes_ipv6())
                + usize::from(p_cscf.addresses.includes_ipv4())
                + usize::from(p_cscf.reselection_support)
        });
        let requested_count = p_cscf_container_count
            + usize::from(self.dns_server_ipv6)
            + usize::from(self.dns_server_ipv4)
            + usize::from(self.ipv4_link_mtu);
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
        // Every P-CSCF container is selected by destructuring `self.p_cscf` at
        // its own emission site. Flattening the option into booleans first
        // would move the TS 24.008 10.5.6.3 accompaniment rule out of the type
        // and into the flattening step, where one wrong token reintroduces an
        // unaccompanied `0x0012`.
        if let Some(p_cscf) = self.p_cscf {
            if p_cscf.addresses.includes_ipv6() {
                encode_empty_request_container(&mut encoded, PCO_CONTAINER_P_CSCF_IPV6);
            }
        }
        if self.dns_server_ipv6 {
            encode_empty_request_container(&mut encoded, PCO_CONTAINER_DNS_SERVER_IPV6);
        }
        if let Some(p_cscf) = self.p_cscf {
            if p_cscf.addresses.includes_ipv4() {
                encode_empty_request_container(&mut encoded, PCO_CONTAINER_P_CSCF_IPV4);
            }
        }
        if self.dns_server_ipv4 {
            encode_empty_request_container(&mut encoded, PCO_CONTAINER_DNS_SERVER_IPV4);
        }
        if self.ipv4_link_mtu {
            encode_empty_request_container(&mut encoded, PCO_CONTAINER_IPV4_LINK_MTU);
        }
        // TS 24.008 10.5.6.3 permits this container only alongside a P-CSCF
        // address request. Reaching this emission needs `self.p_cscf` to be
        // `Some`, and every `PcscfAddressRequest` variant made the same two
        // sites above emit at least one of `0x0001`/`0x000c`, so the
        // accompanying container is already in `encoded`. Nothing outside
        // `self.p_cscf` can select this identifier.
        if let Some(p_cscf) = self.p_cscf {
            if p_cscf.reselection_support {
                encode_empty_request_container(
                    &mut encoded,
                    PCO_CONTAINER_P_CSCF_RESELECTION_SUPPORT,
                );
            }
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
    /// Secondary DNS Server Address from an IPCP Configure-Nak (RFC 1877 §1.3).
    pub ipcp_secondary_dns: Option<[u8; 4]>,
    /// IPv4 link MTU in octets, from container `0x0010`.
    ///
    /// `Option` rather than a sentinel: TS 24.008 reserves no "absent" value.
    /// A value below the RFC 791 68-octet minimum is not a usable link MTU and
    /// is reported as absent rather than passed on, so a caller that applies
    /// what it asked for cannot blackhole the user plane on two peer-supplied
    /// octets.
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
    /// Container addresses come first, in wire order and with their
    /// multiplicity preserved; the IPCP primary and secondary addresses follow,
    /// each appended only if the list does not already contain it. The
    /// container list itself is never deduplicated -- a repeat is a thing the
    /// peer actually sent, and collapsing it would destroy that evidence.
    ///
    /// A peer answers through whichever mechanism it implements, so a caller
    /// that reads only [`Self::dns_server_ipv4`] can end up with a session that
    /// established cleanly and has no usable DNS. Prefer this accessor.
    ///
    /// Note that [`Self::decode_network_contents`] surfaces no IPCP address at
    /// all, so under that entry point this equals [`Self::dns_server_ipv4`].
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

    /// Decode network-to-MS PCO contents without correlating IPCP replies.
    ///
    /// Equivalent to [`Self::decode_network_contents_correlated`] with
    /// [`IpcpNakCorrelation::none`], so **no IPCP-supplied DNS address is
    /// surfaced**: holding no Identifier, this entry point cannot satisfy RFC
    /// 1661 §5.3 and answers with nothing rather than with an uncorrelated
    /// address. For a value whose only DNS source was the IPCP reply,
    /// [`Self::is_empty`] then reports empty and the caller's configured-DNS
    /// fallback fires, exactly as that predicate describes; a value that also
    /// carries an address container is of course not empty. A caller
    /// that sent an IPCP Configure-Request still holds the [`IpcpDnsRequest`]
    /// it sent, and should call [`Self::decode_network_contents_correlated`]
    /// with [`IpcpNakCorrelation::for_request`].
    ///
    /// Malformed container framing rejects the complete value, because with a
    /// bad container boundary no sibling boundary is recoverable. A known
    /// address container carrying the wrong fixed length also rejects the
    /// complete value; that is this codec's configuration-atomicity policy and
    /// not a specification requirement, since TS 24.008 states no receiver
    /// disposition for it and a half-applied DNS or P-CSCF set is worse than
    /// none. Unknown, well-formed length-delimited containers are skipped. A
    /// malformed `0x8021` unit is discarded unit-locally, as is an IPCP unit
    /// placed after a registered network-to-MS container: TS 24.008 defines
    /// the configuration protocol options list before the additional
    /// parameters list, and this decoder does not adopt protocol material after
    /// that boundary.
    ///
    /// # Errors
    ///
    /// Returns [`PcoDecodeError`] for an absent/unsupported header, truncated
    /// container framing, a declared length beyond the remaining input, an
    /// invalid fixed address length, or more than [`PCO_MAX_CONTAINERS`]. A
    /// malformed `0x8021` unit is not an error; use
    /// [`Self::decode_network_contents_correlated`] to see why one was dropped.
    pub fn decode_network_contents(value: &[u8]) -> Result<Self, PcoDecodeError> {
        Self::decode_network_contents_correlated(value, IpcpNakCorrelation::none())
            .map(PcoDecoded::into_configuration)
    }

    /// Decode network-to-MS PCO contents, correlating IPCP Configure-Naks.
    ///
    /// `correlation` is the caller's position on outstanding IPCP
    /// Configure-Requests; see [`IpcpNakCorrelation`] for what each constructor
    /// admits. Whole-value dispositions are as documented on
    /// [`Self::decode_network_contents`].
    ///
    /// # Errors
    ///
    /// Returns [`PcoDecodeError`] for an absent or unsupported header,
    /// truncated container framing, a declared length beyond the remaining
    /// input, an invalid fixed address length, or more than
    /// [`PCO_MAX_CONTAINERS`]. A malformed, uncorrelated, or out-of-order
    /// `0x8021` unit is *not* an error: it is discarded and reported through
    /// [`PcoDecoded::ipcp_discards`].
    pub fn decode_network_contents_correlated(
        value: &[u8],
        correlation: IpcpNakCorrelation,
    ) -> Result<PcoDecoded, PcoDecodeError> {
        let (&header, mut remaining) = value.split_first().ok_or(PcoDecodeError::Empty)?;
        if header != PCO_HEADER_PPP_FOR_IP_PDN {
            return Err(PcoDecodeError::UnsupportedHeader);
        }

        let mut decoded = Self::default();
        let mut discards: Vec<PcoIpcpDiscard> = Vec::new();
        let mut container_count = 0usize;
        let mut additional_parameters_started = false;
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
            if is_network_to_ms_container_identifier(identifier) {
                additional_parameters_started = true;
            }
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
                // RFC 1661 §5.3: "Invalid packets are silently discarded." TS
                // 24.008 10.5.6.3 maps one 0x8021 unit to one RFC 1661 packet,
                // and this unit's outer container boundary was already
                // validated above, so following containers are recoverable
                // and are kept. Contrast the address container arms above,
                // which fail the whole value under this codec's own
                // configuration-atomicity policy.
                PCO_PROTOCOL_IPCP => {
                    let outcome = if additional_parameters_started {
                        // TS 24.008 10.5.6.3 defines configuration protocol
                        // options in octets 4..w and additional parameters in
                        // w+1..z. Once a registered network-to-MS container
                        // establishes the second list, a later IPCP unit cannot
                        // be interpreted as part of the first list. The
                        // specification gives no receiver disposition for this
                        // send-side violation, so this codec keeps the
                        // recoverable containers but fails closed on the
                        // misplaced protocol material.
                        IpcpUnitOutcome::discarded(PcoIpcpDiscardReason::AfterAdditionalParameters)
                    } else {
                        decode_ipcp_unit(contents, correlation)
                    };
                    if let Some(unit) = outcome.merge {
                        // First writer across units wins, matching the
                        // within-unit rule in `decode_ipcp_unit`.
                        if decoded.ipcp_primary_dns.is_none() {
                            decoded.ipcp_primary_dns = unit.primary_dns;
                        }
                        if decoded.ipcp_secondary_dns.is_none() {
                            decoded.ipcp_secondary_dns = unit.secondary_dns;
                        }
                    }
                    if let Some(reason) = outcome.note {
                        // `container_count` is 1-based here and was bounded by
                        // PCO_MAX_CONTAINERS above, which the const assertion
                        // beside that constant pins to <= u8::MAX.
                        discards.push(PcoIpcpDiscard {
                            reason,
                            unit_index: (container_count - 1) as u8,
                        });
                    }
                }
                // Every other identifier, including an unaccompanied
                // `0x0012`. TS 24.008 10.5.6.3 lists `0012H` as Reserved in
                // the network-to-MS direction this function decodes, and
                // states: "If the additional parameters list contains a
                // container identifier that is not supported by the receiving
                // entity the corresponding unit shall be ignored." Its
                // conditional-presence rule constrains the sender and assigns
                // the receiver no behaviour, so rejecting here would discard
                // every address in the same value over a peer's send-side
                // violation.
                _ => {}
            }
            remaining = &remaining[contents_end..];
        }
        Ok(PcoDecoded {
            configuration: decoded,
            discards,
        })
    }
}

/// Result of a correlated network-to-MS PCO decode.
///
/// Held separately from [`PcoAddressConfiguration`], which has public fields,
/// derives `PartialEq` and is not `non_exhaustive`: a field added there would
/// break struct literals and silently change equality for every existing
/// caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PcoDecoded {
    /// Addresses and MTU accepted from the value.
    configuration: PcoAddressConfiguration,
    /// Bounded evidence for IPCP material that was not merged.
    discards: Vec<PcoIpcpDiscard>,
}

impl PcoDecoded {
    /// Return the addresses and MTU accepted from the value.
    #[must_use]
    pub fn configuration(&self) -> &PcoAddressConfiguration {
        &self.configuration
    }

    /// Take ownership of the accepted configuration.
    #[must_use]
    pub fn into_configuration(self) -> PcoAddressConfiguration {
        self.configuration
    }

    /// Return bounded, redaction-safe evidence for IPCP material not merged.
    ///
    /// At most one entry per length-delimited unit, so the length is bounded by
    /// [`PCO_MAX_CONTAINERS`].
    #[must_use]
    pub fn ipcp_discards(&self) -> &[PcoIpcpDiscard] {
        &self.discards
    }
}

/// One IPCP unit whose material was not merged, in whole or in part.
///
/// At most one entry exists per unit, so a unit carrying two skipped options
/// still yields one: this records that a unit lost material, not how much.
///
/// Carries no address octets and no Identifier value. `Debug` on this type is
/// reachable from operational logging, and the [`PcoAddressConfiguration`]
/// `Debug` contract already reports counts and presence only; this extends the
/// same contract to the evidence about what was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcoIpcpDiscard {
    /// Why the material was not merged.
    reason: PcoIpcpDiscardReason,
    /// Position of the unit among the value's length-delimited units.
    unit_index: u8,
}

impl PcoIpcpDiscard {
    /// Return why the material was not merged.
    #[must_use]
    pub const fn reason(self) -> PcoIpcpDiscardReason {
        self.reason
    }

    /// Return the zero-based position of the unit among the value's
    /// length-delimited units, counting every container and not only IPCP ones.
    #[must_use]
    pub const fn unit_index(self) -> u8 {
        self.unit_index
    }
}

/// Why IPCP material was not merged into the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PcoIpcpDiscardReason {
    /// Whole unit discarded: its Identifier did not match the outstanding
    /// Configure-Request (RFC 1661 §5.3).
    IdentifierMismatch,
    /// Whole unit discarded: no Configure-Request was outstanding, so no
    /// Configure-Nak could be correlated.
    NoOutstandingRequest,
    /// Whole unit discarded: it appeared after a registered network-to-MS
    /// container, outside the TS 24.008 configuration protocol options list.
    AfterAdditionalParameters,
    /// Whole unit discarded: malformed. The carried [`PcoDecodeError`] is the
    /// same value the decoder returned for this fault before the disposition
    /// became unit-local.
    Malformed(PcoDecodeError),
    /// Unit merged, but at least one DNS option carried an address for a server
    /// this side never solicited, and that option was skipped.
    UnsolicitedOption,
}

impl PcoIpcpDiscardReason {
    /// Return a stable, payload-free diagnostic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentifierMismatch => "pco_ipcp_identifier_mismatch",
            Self::NoOutstandingRequest => "pco_ipcp_no_outstanding_request",
            Self::AfterAdditionalParameters => "pco_ipcp_after_additional_parameters",
            Self::Malformed(error) => error.as_str(),
            Self::UnsolicitedOption => "pco_ipcp_unsolicited_option",
        }
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

/// Addresses one IPCP unit contributed, held apart from the accumulating
/// configuration until the whole unit has parsed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct IpcpUnitScratch {
    /// Primary DNS Server Address this unit supplied (RFC 1877 §1.1).
    primary_dns: Option<[u8; 4]>,
    /// Secondary DNS Server Address this unit supplied (RFC 1877 §1.3).
    secondary_dns: Option<[u8; 4]>,
}

/// What one `0x8021` unit contributed.
struct IpcpUnitOutcome {
    /// Addresses to merge. `None` when nothing is merged.
    merge: Option<IpcpUnitScratch>,
    /// At most one bounded diagnostic for this unit.
    note: Option<PcoIpcpDiscardReason>,
}

impl IpcpUnitOutcome {
    /// Discard the whole unit, naming why.
    const fn discarded(reason: PcoIpcpDiscardReason) -> Self {
        Self {
            merge: None,
            note: Some(reason),
        }
    }

    /// Contribute nothing and record nothing.
    const fn ignored() -> Self {
        Self {
            merge: None,
            note: None,
        }
    }
}

/// Decode one `0x8021` unit, reporting any peer-supplied DNS address.
///
/// Only a Configure-Nak carries addresses: RFC 1661 §5.2 has a Configure-Ack
/// echo the request's options verbatim, and this crate always requests with
/// the RFC 1877 all-zero address, so an Ack conveys nothing. Codes 1, 2 and 4
/// are option-framed configuration packets too, so their framing and the shape
/// of known DNS options are syntactically validated before their contents are
/// ignored. Codes outside 1 through 4 do not use the Configuration Options
/// packet shape this parser can validate and are ignored without applying
/// option framing.
///
/// Returns no `Result`: this decoder contains a syntactic fault to one IPCP
/// packet, and TS 24.008 10.5.6.3 maps one `0x8021` unit to one such packet, so
/// no IPCP fault reaches the enclosing PCO value. Choosing a PPP response for a
/// malformed Configure-Request remains outside this projection. Nothing is
/// written to the caller's accumulator either, so an option that parsed before
/// a later malformed one in the same packet cannot survive it.
fn decode_ipcp_unit(contents: &[u8], correlation: IpcpNakCorrelation) -> IpcpUnitOutcome {
    let header_len = usize::from(IPCP_HEADER_LEN);
    if contents.len() < header_len {
        return IpcpUnitOutcome::discarded(PcoIpcpDiscardReason::Malformed(
            PcoDecodeError::IpcpHeaderTruncated,
        ));
    }
    let code = contents[0];
    let identifier = contents[1];
    let declared = usize::from(u16::from_be_bytes([contents[2], contents[3]]));
    if declared < header_len || declared > contents.len() {
        return IpcpUnitOutcome::discarded(PcoIpcpDiscardReason::Malformed(
            PcoDecodeError::IpcpLengthInvalid,
        ));
    }
    if matches!(
        code,
        IPCP_CODE_CONFIGURE_REQUEST | IPCP_CODE_CONFIGURE_ACK | IPCP_CODE_CONFIGURE_REJECT
    ) {
        if let Err(error) = validate_ipcp_configuration_options(&contents[header_len..declared]) {
            return IpcpUnitOutcome::discarded(PcoIpcpDiscardReason::Malformed(error));
        }
        return IpcpUnitOutcome::ignored();
    }
    if code != IPCP_CODE_CONFIGURE_NAK {
        return IpcpUnitOutcome::ignored();
    }
    // RFC 1661 §5.3: "On reception of a Configure-Nak, the Identifier field
    // MUST match that of the last transmitted Configure-Request. Invalid
    // packets are silently discarded." Resolved before any option is parsed, so
    // an uncorrelated Nak's addresses never reach the scratch state at all.
    if !correlation.is_outstanding() {
        return IpcpUnitOutcome::discarded(PcoIpcpDiscardReason::NoOutstandingRequest);
    }
    if !correlation.accepts_identifier(identifier) {
        return IpcpUnitOutcome::discarded(PcoIpcpDiscardReason::IdentifierMismatch);
    }

    let mut scratch = IpcpUnitScratch::default();
    let mut note = None;
    // Each iteration consumes at least two octets of a slice the one-octet
    // unit length already bounds to 255, so this terminates without a
    // separate option cap.
    let mut remaining = &contents[header_len..declared];
    while !remaining.is_empty() {
        let (option_type, data, rest) = match split_ipcp_configuration_option(remaining) {
            Ok(option) => option,
            Err(error) => {
                return IpcpUnitOutcome::discarded(PcoIpcpDiscardReason::Malformed(error))
            }
        };
        match option_type {
            IPCP_OPTION_PRIMARY_DNS | IPCP_OPTION_SECONDARY_DNS => {
                // Whether the packet is invalid is a property of the packet,
                // not of what this side happened to solicit, so the option is
                // parsed before the solicited set is consulted. Validating only
                // a solicited option would make one Configure-Nak valid or
                // invalid depending on local state, and would let a malformed
                // option in an unsolicited slot leave an earlier valid option
                // standing -- exactly what RFC 1661 §5.3 forbids.
                let parsed = match parse_ipcp_dns_option(data) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        return IpcpUnitOutcome::discarded(PcoIpcpDiscardReason::Malformed(error))
                    }
                };
                if correlation.accepts_option(option_type) {
                    let slot = if option_type == IPCP_OPTION_PRIMARY_DNS {
                        &mut scratch.primary_dns
                    } else {
                        &mut scratch.secondary_dns
                    };
                    // First writer within the unit wins, matching the
                    // across-unit rule at the merge site.
                    if slot.is_none() {
                        *slot = parsed;
                    }
                } else {
                    // RFC 1661 §5.3 permits a Configure-Nak to append
                    // Configuration Options the peer desires that were not in
                    // the Configure-Request, so an unsolicited option does not
                    // make the packet invalid and the unit is kept. Declining
                    // to adopt the address is this codec's hardening judgement.
                    note = Some(PcoIpcpDiscardReason::UnsolicitedOption);
                }
            }
            _ => {}
        }
        remaining = rest;
    }
    IpcpUnitOutcome {
        merge: Some(scratch),
        note,
    }
}

/// Split one RFC 1661 Configuration Option from a packet.
///
/// The returned slices borrow the bounded IPCP unit, and each successful call
/// consumes at least two octets.
fn split_ipcp_configuration_option(remaining: &[u8]) -> Result<(u8, &[u8], &[u8]), PcoDecodeError> {
    let Some((&option_type, rest)) = remaining.split_first() else {
        return Err(PcoDecodeError::IpcpOptionTruncated);
    };
    let Some((&option_len, _)) = rest.split_first() else {
        return Err(PcoDecodeError::IpcpOptionTruncated);
    };
    let option_len = usize::from(option_len);
    // RFC 1661 §6: the option Length counts the Type and Length octets.
    if option_len < 2 || option_len > remaining.len() {
        return Err(PcoDecodeError::IpcpOptionLengthInvalid);
    }
    Ok((
        option_type,
        &remaining[2..option_len],
        &remaining[option_len..],
    ))
}

/// Validate the Configuration Options field of a non-Nak configuration packet.
///
/// DNS values are not adopted from these codes, but their option framing is
/// still checked so syntactically invalid input is reported rather than called
/// a well-formed ignored packet. Known RFC 1877 options retain their fixed
/// six-octet shape independent of which configuration code carried them. This
/// is syntax validation only: Identifier correlation, Configure-Ack equality,
/// Configure-Reject subset validation and PPP response policy remain outside
/// this decoder.
fn validate_ipcp_configuration_options(mut remaining: &[u8]) -> Result<(), PcoDecodeError> {
    while !remaining.is_empty() {
        let (option_type, data, rest) = split_ipcp_configuration_option(remaining)?;
        if matches!(
            option_type,
            IPCP_OPTION_PRIMARY_DNS | IPCP_OPTION_SECONDARY_DNS
        ) {
            parse_ipcp_dns_option(data)?;
        }
        remaining = rest;
    }
    Ok(())
}

/// Parse the data of one RFC 1877 DNS Server Address option.
///
/// `Ok(None)` means the option was well formed and supplied no server: an
/// all-zero address is the RFC 1877 request encoding, not a server, so a peer
/// that echoes it back is treated as having supplied nothing. The first-writer
/// rule lives at the call site, which owns the slot.
fn parse_ipcp_dns_option(data: &[u8]) -> Result<Option<[u8; 4]>, PcoDecodeError> {
    let address =
        <[u8; 4]>::try_from(data).map_err(|_| PcoDecodeError::IpcpDnsOptionLengthInvalid)?;
    Ok((address != [0; 4]).then_some(address))
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
