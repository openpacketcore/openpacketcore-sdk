use super::super::{configuration::chain, once, Address, Error, Limits};
use crate::{Ikev2IkeAuthPayloadBuild, Ikev2NatDetectionPayloads, Ikev2NotifyPayload, PayloadType};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

/// Observed UDP source and destination, in packet direction. Socket metadata
/// is supplied by the transport; IKE integrity alone does not authenticate it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Path {
    source: SocketAddr,
    destination: SocketAddr,
}
impl Path {
    /// Require concrete unicast addresses of the same family and nonzero ports.
    /// Scoped IPv6/flow labels are outside this wire contract. Whether a pair
    /// is acceptable for deployment remains explicit caller address policy.
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Result<Self, Error> {
        for endpoint in [source, destination] {
            if endpoint.port() == 0
                || endpoint.ip().is_unspecified()
                || endpoint.ip().is_multicast()
                || matches!(endpoint.ip(), IpAddr::V4(ip) if ip.is_broadcast())
                || matches!(endpoint, SocketAddr::V6(v) if v.scope_id() != 0 || v.flowinfo() != 0)
            {
                return Err(Error::InvalidValue);
            }
        }
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(Error::Incompatible);
        }
        Ok(Self {
            source,
            destination,
        })
    }
    /// Explicit access to the source socket endpoint.
    pub const fn source(self) -> SocketAddr {
        self.source
    }
    /// Explicit access to the destination socket endpoint.
    pub const fn destination(self) -> SocketAddr {
        self.destination
    }
    /// Reverse packet direction, e.g. to send a response or a COOKIE2 probe.
    pub const fn reversed(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
        }
    }
    fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        for ip in [self.source.ip(), self.destination.ip()] {
            match ip {
                IpAddr::V4(v) => out.extend(v.octets()),
                IpAddr::V6(v) => out.extend(v.octets()),
            }
        }
        out.extend(self.source.port().to_be_bytes());
        out.extend(self.destination.port().to_be_bytes());
        out
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (source, destination, port_offset) = match bytes.len() {
            12 => (
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&bytes[..4]).map_err(|_| Error::InvalidValue)?,
                )),
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&bytes[4..8]).map_err(|_| Error::InvalidValue)?,
                )),
                8,
            ),
            36 => (
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&bytes[..16]).map_err(|_| Error::InvalidValue)?,
                )),
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&bytes[16..32]).map_err(|_| Error::InvalidValue)?,
                )),
                32,
            ),
            _ => return Err(Error::InvalidValue),
        };
        Self::new(
            SocketAddr::new(
                source,
                u16::from_be_bytes([bytes[port_offset], bytes[port_offset + 1]]),
            ),
            SocketAddr::new(
                destination,
                u16::from_be_bytes([bytes[port_offset + 2], bytes[port_offset + 3]]),
            ),
        )
    }
}
impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Path([REDACTED])")
    }
}

/// RFC 4555 mobility notifications and RFC 7296 NAT-D. This is a structural
/// borrowed view, never authentication or permission to update an SA.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Notify<'a> {
    /// Additional peer address (16397/16398).
    AdditionalAddress(Address),
    /// Replace the peer address list with only the packet source (16399).
    NoAdditionalAddresses,
    /// Original IKE initiator requests an address update (16400).
    UpdateSaAddresses,
    /// Eight through 64 unpredictable octets to echo exactly (16401).
    Cookie2(&'a [u8]),
    /// Integrity-protected source/destination addresses and ports (16402).
    NoNatsAllowed(Path),
    /// Source endpoint SHA-1 NAT-D hash (16388).
    NatSource(&'a [u8]),
    /// Destination endpoint SHA-1 NAT-D hash (16389).
    NatDestination(&'a [u8]),
    /// Address policy rejected an authenticated update (40).
    UnacceptableAddresses,
    /// NO_NATS_ALLOWED disagreed with observed addresses/ports (41).
    UnexpectedNatDetected,
}
impl fmt::Debug for Notify<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MobikeNotify([REDACTED])")
    }
}
impl<'a> Notify<'a> {
    /// Decode a complete Notify body; Protocol ID is ignored with zero SPI.
    /// Every known notification validates its exact data length.
    pub fn decode_body(bytes: &'a [u8]) -> Result<Option<Self>, Error> {
        if bytes.len() > 65_531 {
            return Err(Error::Limit);
        }
        let n = Ikev2NotifyPayload::decode_body(bytes).map_err(|_| Error::Framing)?;
        let t = n.notify_message_type;
        if !matches!(t, 40 | 41 | 16_388 | 16_389 | 16_397..=16_402) {
            return Ok(None);
        }
        if n.spi_size != 0 {
            return Err(Error::SpiShape);
        }
        let d = n.notification_data;
        Ok(Some(match t {
            16_397 | 16_398 => Self::AdditionalAddress(Address::from_wire(d, t == 16_397)?),
            16_399 if d.is_empty() => Self::NoAdditionalAddresses,
            16_400 if d.is_empty() => Self::UpdateSaAddresses,
            16_401 if (8..=64).contains(&d.len()) => Self::Cookie2(d),
            16_402 => Self::NoNatsAllowed(Path::decode(d)?),
            16_388 if d.len() == 20 => Self::NatSource(d),
            16_389 if d.len() == 20 => Self::NatDestination(d),
            40 if d.is_empty() => Self::UnacceptableAddresses,
            41 if d.is_empty() => Self::UnexpectedNatDetected,
            _ => return Err(Error::InvalidValue),
        }))
    }
    /// Build a canonical, zero-SPI Notify body, validating borrowed lengths.
    pub fn encode_body(self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Cookie2(v) if !(8..=64).contains(&v.len()) => return Err(Error::InvalidValue),
            Self::NatSource(v) | Self::NatDestination(v) if v.len() != 20 => {
                return Err(Error::InvalidValue)
            }
            _ => (),
        }
        let (t, data): (u16, Vec<u8>) = match self {
            Self::AdditionalAddress(a) => (if a.is_ipv4() { 16_397 } else { 16_398 }, a.octets()),
            Self::NoAdditionalAddresses => (16_399, vec![]),
            Self::UpdateSaAddresses => (16_400, vec![]),
            Self::Cookie2(v) => (16_401, v.to_vec()),
            Self::NoNatsAllowed(p) => (16_402, p.encode()),
            Self::NatSource(v) => (16_388, v.to_vec()),
            Self::NatDestination(v) => (16_389, v.to_vec()),
            Self::UnacceptableAddresses => (40, vec![]),
            Self::UnexpectedNatDetected => (41, vec![]),
        };
        let mut body = vec![0, 0];
        body.extend(t.to_be_bytes());
        body.extend(data);
        Ok(body)
    }
    /// One payload for the existing canonical payload-chain encoder/sealer.
    pub fn payload(self) -> Result<Ikev2IkeAuthPayloadBuild, Error> {
        Ok(Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: self.encode_body()?,
        })
    }
}

/// Bounded opened INFORMATIONAL request. Addresses are descriptive until the
/// authenticated responder validates policy and return routability.
#[derive(Clone)]
pub struct Request<'a> {
    pub(super) update: bool,
    pub(super) additional: Option<Vec<Address>>,
    pub(super) cookie: Option<&'a [u8]>,
    pub(super) no_nats: Option<Path>,
    pub(super) nat: Ikev2NatDetectionPayloads<'a>,
}
impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MobikeRequest([REDACTED])")
    }
}
impl<'a> Request<'a> {
    /// Decode singleton update/cookie/NAT prohibition and bounded additional
    /// addresses. Unknown status and noncritical payloads are ignored after
    /// framing. NAT-D permits multiple source hashes and one destination hash;
    /// a partial pair fails. Duplicate addresses and conflicting list forms
    /// are rejected as local admission policy. Empty DPD requests are allowed.
    pub fn decode(first: PayloadType, bytes: &'a [u8], limits: Limits) -> Result<Self, Error> {
        let mut update = None;
        let mut no_additional = None;
        let mut additional = Vec::new();
        let mut cookie = None;
        let mut no_nats = None;
        let mut nat = Ikev2NatDetectionPayloads::new();
        for raw in chain(first, bytes, limits)? {
            let raw = raw.map_err(|_| Error::Framing)?;
            match raw.payload_type {
                PayloadType::Unknown(_) | PayloadType::VendorId => continue,
                PayloadType::Notify => (),
                _ => return Err(Error::Incompatible),
            }
            let n = Ikev2NotifyPayload::decode(raw).map_err(|_| Error::Framing)?;
            if n.notify_message_type < 16_384 {
                return Err(Error::Incompatible);
            }
            match Notify::decode_body(raw.body)? {
                Some(Notify::UpdateSaAddresses) => once(&mut update, ())?,
                Some(Notify::NoAdditionalAddresses) => once(&mut no_additional, ())?,
                Some(Notify::AdditionalAddress(a)) => {
                    if additional.contains(&a) {
                        return Err(Error::Duplicate);
                    }
                    additional.push(a);
                }
                Some(Notify::Cookie2(v)) => once(&mut cookie, v)?,
                Some(Notify::NoNatsAllowed(p)) => once(&mut no_nats, p)?,
                Some(Notify::NatSource(_) | Notify::NatDestination(_)) => {
                    // RFC 7296 ignores Protocol ID with SPI size zero. The
                    // generic NAT-D collector takes canonical views.
                    nat.push_notify(Ikev2NotifyPayload {
                        protocol_id: 0,
                        ..n
                    })
                    .map_err(|_| Error::InvalidValue)?;
                }
                Some(_) => return Err(Error::Incompatible),
                None => (),
            }
        }
        if no_additional.is_some() && !additional.is_empty() {
            return Err(Error::Incompatible);
        }
        if nat.has_destination_hash() != (nat.source_hash_count() != 0) {
            return Err(Error::Missing);
        }
        Ok(Self {
            update: update.is_some(),
            additional: if no_additional.is_some() || !additional.is_empty() {
                Some(additional)
            } else {
                None
            },
            cookie,
            no_nats,
            nat,
        })
    }
    /// Whether the original IKE initiator requests an SA address change.
    pub const fn updates_addresses(&self) -> bool {
        self.update
    }
    /// Advertised alternatives, excluding the observed packet source. An empty
    /// list means NO_ADDITIONAL_ADDRESSES; None means leave the list unchanged.
    pub fn additional_addresses(&self) -> Option<&[Address]> {
        self.additional.as_deref()
    }
    /// COOKIE2 bytes for exact response echo; no diagnostic representation.
    pub const fn cookie2(&self) -> Option<&'a [u8]> {
        self.cookie
    }
}
