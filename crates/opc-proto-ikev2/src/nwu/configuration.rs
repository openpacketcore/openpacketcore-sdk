use super::{once, Address, Error, Limits, Notify};
use crate::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_configuration_payload,
    Ikev2ConfigurationAttributeBuild, Ikev2ConfigurationPayload, Ikev2ConfigurationPayloadBuild,
    Ikev2IkeAuthPayloadBuild, PayloadChain, PayloadType, RawPayload,
};
use bytes::Bytes;
use opc_protocol::DecodeContext;
use std::fmt;

/// Requested inner address families. At least one family is always requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamilies {
    /// IPv4 only.
    Ipv4,
    /// IPv6 only.
    Ipv6,
    /// Both families.
    Dual,
}
impl AddressFamilies {
    /// Whether IPv4 is requested.
    pub const fn ipv4(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Dual)
    }
    /// Whether IPv6 is requested.
    pub const fn ipv6(self) -> bool {
        matches!(self, Self::Ipv6 | Self::Dual)
    }
    fn from_presence(ipv4: bool, ipv6: bool) -> Result<Self, Error> {
        match (ipv4, ipv6) {
            (true, true) => Ok(Self::Dual),
            (true, false) => Ok(Self::Ipv4),
            (false, true) => Ok(Self::Ipv6),
            _ => Err(Error::Missing),
        }
    }
}

/// Configuration portion of the UE's IKE_AUTH request (TS 24.502 7.3.2.2).
/// AUTH, SA, and traffic-selector validation remain in their existing codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationRequest {
    /// Requested inner families, using empty CP attribute values.
    pub families: AddressFamilies,
    /// Whether the UE advertises RFC 4555 support. The N3IWF response includes
    /// MOBIKE_SUPPORTED only when IPv4 was requested as well.
    pub mobike_supported: bool,
}
impl ConfigurationRequest {
    /// Canonical configuration entries to combine with the caller's IKE_AUTH
    /// payloads before protecting the exchange.
    pub fn payloads(self) -> Result<Vec<Ikev2IkeAuthPayloadBuild>, Error> {
        let mut attributes = Vec::new();
        for (present, attribute_type) in [(self.families.ipv4(), 1), (self.families.ipv6(), 8)] {
            if present {
                attributes.push(Ikev2ConfigurationAttributeBuild {
                    attribute_type,
                    value: vec![],
                });
            }
        }
        let mut out = vec![cp_entry(1, attributes)?];
        if self.mobike_supported {
            out.push(notify_entry(Notify::MobikeSupported)?);
        }
        Ok(out)
    }
    /// Decode the configuration portion of an opened IKE_AUTH request.
    /// Bounds count every payload and CP attribute, including ignored entries.
    /// Unknown CP attributes and unrelated status notifies are ignored; callers
    /// handle their other protocol profiles separately. Duplicate known fields
    /// and additional CP payloads are rejected.
    pub fn decode(first: PayloadType, bytes: &[u8], limits: Limits) -> Result<Self, Error> {
        let mut families = None;
        let mut mobike = None;
        for raw in chain(first, bytes, limits)? {
            let raw = raw.map_err(|_| Error::Framing)?;
            match raw.payload_type {
                PayloadType::Configuration => {
                    let cp = cp_decode(raw.body, limits)?;
                    if cp.config_type != 1 {
                        return Err(Error::Incompatible);
                    }
                    let mut ipv4 = None;
                    let mut ipv6 = None;
                    for attr in cp.attributes {
                        match attr.attribute_type {
                            1 | 8 => {
                                if !attr.value.is_empty() {
                                    return Err(Error::InvalidValue);
                                }
                                once(
                                    if attr.attribute_type == 1 {
                                        &mut ipv4
                                    } else {
                                        &mut ipv6
                                    },
                                    (),
                                )?;
                            }
                            _ => (),
                        }
                    }
                    once(
                        &mut families,
                        AddressFamilies::from_presence(ipv4.is_some(), ipv6.is_some())?,
                    )?;
                }
                PayloadType::Notify => match profile_notify(raw.body)? {
                    Some(Notify::MobikeSupported) => once(&mut mobike, ())?,
                    Some(_) => return Err(Error::Incompatible),
                    None => (),
                },
                _ => (),
            }
        }
        Ok(Self {
            families: families.ok_or(Error::Missing)?,
            mobike_supported: mobike.is_some(),
        })
    }
}

/// NAS endpoint alternatives. The consumer chooses one address and keeps it
/// for the TCP session, as required by TS 24.502 section 8.2.3.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NasEndpoint {
    ipv4: Option<Address>,
    ipv6: Option<Address>,
    port: u16,
}
impl NasEndpoint {
    /// Construct at least one family with its shared NAS_TCP_PORT.
    pub fn new(ipv4: Option<Address>, ipv6: Option<Address>, port: u16) -> Result<Self, Error> {
        AddressFamilies::from_presence(ipv4.is_some(), ipv6.is_some())?;
        if ipv4.is_some_and(|a| !a.is_ipv4()) || ipv6.is_some_and(Address::is_ipv4) {
            return Err(Error::Incompatible);
        }
        Ok(Self { ipv4, ipv6, port })
    }
    /// Optional IPv4 endpoint.
    pub const fn ipv4(self) -> Option<Address> {
        self.ipv4
    }
    /// Optional IPv6 endpoint.
    pub const fn ipv6(self) -> Option<Address> {
        self.ipv6
    }
    /// Explicit port access. Reachability and local port policy are caller-owned.
    pub const fn port(self) -> u16 {
        self.port
    }
}
impl fmt::Debug for NasEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NasEndpoint([REDACTED])")
    }
}

/// Validated CFG_REPLY plus NAS transport configuration and conditional MOBIKE.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationReply {
    ipv4: Option<Address>,
    ipv6: Option<(Address, u8)>,
    nas: NasEndpoint,
    mobike: bool,
}
impl fmt::Debug for ConfigurationReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigurationReply([REDACTED])")
    }
}
impl ConfigurationReply {
    /// Construct a reply to an exact request. Assigned families must have been
    /// requested; each NAS endpoint needs its matching assigned family. IPv6
    /// attributes include a prefix length of 0..=128 (RFC 7296 section 3.15.1).
    pub fn new(
        request: ConfigurationRequest,
        ipv4: Option<Address>,
        ipv6: Option<(Address, u8)>,
        nas: NasEndpoint,
    ) -> Result<Self, Error> {
        AddressFamilies::from_presence(ipv4.is_some(), ipv6.is_some())?;
        if ipv4.is_some_and(|a| !a.is_ipv4())
            || ipv6.is_some_and(|(a, p)| a.is_ipv4() || p > 128)
            || (ipv4.is_some() && !request.families.ipv4())
            || (ipv6.is_some() && !request.families.ipv6())
            || (nas.ipv4.is_some() && ipv4.is_none())
            || (nas.ipv6.is_some() && ipv6.is_none())
        {
            return Err(Error::Incompatible);
        }
        Ok(Self {
            ipv4,
            ipv6,
            nas,
            mobike: request.mobike_supported && request.families.ipv4(),
        })
    }
    /// Assigned UE IPv4 address.
    pub const fn ipv4(self) -> Option<Address> {
        self.ipv4
    }
    /// Assigned UE IPv6 address and prefix length.
    pub const fn ipv6(self) -> Option<(Address, u8)> {
        self.ipv6
    }
    /// Offered NAS endpoint alternatives.
    pub const fn nas(self) -> NasEndpoint {
        self.nas
    }
    /// Whether the response advertises MOBIKE, conditional on the request.
    pub const fn mobike_supported(self) -> bool {
        self.mobike
    }
    /// Build the configuration entries for the final IKE_AUTH response.
    pub fn payloads(self) -> Result<Vec<Ikev2IkeAuthPayloadBuild>, Error> {
        let mut attributes = Vec::new();
        if let Some(a) = self.ipv4 {
            attributes.push(Ikev2ConfigurationAttributeBuild {
                attribute_type: 1,
                value: a.octets(),
            });
        }
        if let Some((a, p)) = self.ipv6 {
            let mut value = a.octets();
            value.push(p);
            attributes.push(Ikev2ConfigurationAttributeBuild {
                attribute_type: 8,
                value,
            });
        }
        let mut out = vec![cp_entry(2, attributes)?];
        for a in [self.nas.ipv4, self.nas.ipv6].into_iter().flatten() {
            out.push(notify_entry(Notify::NasAddress(a))?);
        }
        out.push(notify_entry(Notify::NasTcpPort(self.nas.port))?);
        if self.mobike {
            out.push(notify_entry(Notify::MobikeSupported)?);
        }
        Ok(out)
    }
    /// Decode the configuration portion of a final opened IKE_AUTH response
    /// against the original request. Payload order is unrestricted.
    pub fn decode(
        request: ConfigurationRequest,
        first: PayloadType,
        bytes: &[u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut cp_seen = None;
        let mut ipv4 = None;
        let mut ipv6 = None;
        let mut nas4 = None;
        let mut nas6 = None;
        let mut port = None;
        let mut mobike = None;
        for raw in chain(first, bytes, limits)? {
            let raw = raw.map_err(|_| Error::Framing)?;
            match raw.payload_type {
                PayloadType::Configuration => {
                    once(&mut cp_seen, ())?;
                    let cp = cp_decode(raw.body, limits)?;
                    if cp.config_type != 2 {
                        return Err(Error::Incompatible);
                    }
                    for attr in cp.attributes {
                        match attr.attribute_type {
                            1 => once(
                                &mut ipv4,
                                Address::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                                    <[u8; 4]>::try_from(attr.value)
                                        .map_err(|_| Error::InvalidValue)?,
                                ))),
                            )?,
                            8 => {
                                if attr.value.len() != 17 {
                                    return Err(Error::InvalidValue);
                                }
                                let addr =
                                    Address::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                                        <[u8; 16]>::try_from(&attr.value[..16])
                                            .map_err(|_| Error::InvalidValue)?,
                                    )));
                                once(&mut ipv6, (addr, attr.value[16]))?;
                            }
                            _ => (),
                        }
                    }
                }
                PayloadType::Notify => match profile_notify(raw.body)? {
                    Some(Notify::NasAddress(a)) => {
                        once(if a.is_ipv4() { &mut nas4 } else { &mut nas6 }, a)?
                    }
                    Some(Notify::NasTcpPort(p)) => once(&mut port, p)?,
                    Some(Notify::MobikeSupported) => once(&mut mobike, ())?,
                    Some(_) => return Err(Error::Incompatible),
                    None => (),
                },
                _ => (),
            }
        }
        cp_seen.ok_or(Error::Missing)?;
        let nas = NasEndpoint::new(nas4, nas6, port.ok_or(Error::Missing)?)?;
        let reply = Self::new(request, ipv4, ipv6, nas)?;
        if reply.mobike != mobike.is_some() {
            return Err(Error::Incompatible);
        }
        Ok(reply)
    }
}

pub(super) fn chain(
    first: PayloadType,
    bytes: &[u8],
    limits: Limits,
) -> Result<impl Iterator<Item = Result<RawPayload<'_>, opc_protocol::DecodeError>>, Error> {
    limits.check(bytes.len(), 0)?;
    Ok(
        PayloadChain::new(first, bytes).iter_with_context(DecodeContext {
            max_ies: limits.entries,
            max_message_len: limits.bytes,
            ..DecodeContext::default()
        }),
    )
}
pub(super) fn notify_entry(notify: Notify<'_>) -> Result<Ikev2IkeAuthPayloadBuild, Error> {
    Ok(Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body: notify.encode_body()?,
    })
}
fn cp_entry(
    config_type: u8,
    attributes: Vec<Ikev2ConfigurationAttributeBuild>,
) -> Result<Ikev2IkeAuthPayloadBuild, Error> {
    Ok(Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Configuration,
        body: build_ike_auth_configuration_payload(&Ikev2ConfigurationPayloadBuild {
            config_type,
            attributes,
        })
        .map_err(|_| Error::InvalidValue)?,
    })
}
fn cp_decode(body: &[u8], limits: Limits) -> Result<Ikev2ConfigurationPayload<'_>, Error> {
    limits.check(body.len(), 0)?;
    if body.len() > 65_531 {
        return Err(Error::Limit);
    }
    // Preflight count before the generic decoder allocates its attribute vector.
    let mut rest = body.get(4..).ok_or(Error::Framing)?;
    let mut count = 0;
    while !rest.is_empty() {
        let (&[_, _, a, b], tail) = rest.split_first_chunk::<4>().ok_or(Error::Framing)?;
        rest = tail
            .get(usize::from(u16::from_be_bytes([a, b]))..)
            .ok_or(Error::Framing)?;
        count += 1;
        limits.check(body.len(), count)?;
    }
    Ikev2ConfigurationPayload::decode_body(body).map_err(|_| Error::Framing)
}
fn profile_notify(body: &[u8]) -> Result<Option<Notify<'_>>, Error> {
    let value = crate::Ikev2NotifyPayload::decode_body(body).map_err(|_| Error::Framing)?;
    if value.notify_message_type < 16_384 {
        return Err(Error::Incompatible);
    }
    Notify::decode(value)
}

/// Chain profile payload entries with the existing generic IKE encoder.
/// Callers can append AUTH, SA and other entries before invoking this function.
pub fn encode_payloads(
    entries: &[Ikev2IkeAuthPayloadBuild],
) -> Result<(PayloadType, Bytes), Error> {
    build_ike_auth_cleartext_payload_chain(entries).map_err(|_| Error::Framing)
}
