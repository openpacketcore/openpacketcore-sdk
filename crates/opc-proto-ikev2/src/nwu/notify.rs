use super::{Error, QosInfo};
use crate::{build_ike_auth_notify_payload, Ikev2NotifyPayload, Ikev2NotifyPayloadBuild};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// An inner NAS/UP address with redacted diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Address(IpAddr);
impl Address {
    /// Wrap a caller-owned address without logging it.
    pub const fn new(address: IpAddr) -> Self {
        Self(address)
    }
    /// Explicit access to the wire address.
    pub const fn value(self) -> IpAddr {
        self.0
    }
    /// Whether the address belongs to IPv4.
    pub const fn is_ipv4(self) -> bool {
        self.0.is_ipv4()
    }
    fn from_wire(data: &[u8], ipv4: bool) -> Result<Self, Error> {
        Ok(Self(if ipv4 {
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(data).map_err(|_| Error::InvalidValue)?,
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(data).map_err(|_| Error::InvalidValue)?,
            ))
        }))
    }
    pub(super) fn octets(self) -> Vec<u8> {
        match self.0 {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        }
    }
}
impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_ipv4() {
            "Address::Ipv4([REDACTED])"
        } else {
            "Address::Ipv6([REDACTED])"
        })
    }
}

/// Sender-owned inbound ESP SPI. Zero is not a usable ESP SPI.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspSpi([u8; 4]);
impl EspSpi {
    /// Construct a nonzero SPI. Allocation and ownership verification are caller-owned.
    pub fn new(value: [u8; 4]) -> Result<Self, Error> {
        if value == [0; 4] {
            Err(Error::InvalidValue)
        } else {
            Ok(Self(value))
        }
    }
    /// Explicit wire access.
    pub const fn octets(self) -> [u8; 4] {
        self.0
    }
}
impl fmt::Debug for EspSpi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EspSpi([REDACTED])")
    }
}

/// Typed TS 24.502 section 9.3.1 notifications and RFC 4555 capability.
/// Unknown Notify types return `None`; known unsupported types return an error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Notify<'a> {
    /// Complete association, including its optional additional QoS information.
    Qos(QosInfo<'a>),
    /// N3IWF NAS transport address (55502 or 55503).
    NasAddress(Address),
    /// N3IWF user-plane transport address (55504 or 55505).
    UpAddress(Address),
    /// NAS TCP destination port (55506). A wire value of zero is retained.
    NasTcpPort(u16),
    /// Sender-owned inbound ESP SPI (55508). Future extension data is ignored on receive.
    UpSaInfo(EspSpi),
    /// Empty MOBIKE_SUPPORTED status (16396).
    MobikeSupported,
}
impl fmt::Debug for Notify<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Qos(_) => "Notify::Qos([REDACTED])",
            Self::NasAddress(_) => "Notify::NasAddress([REDACTED])",
            Self::UpAddress(_) => "Notify::UpAddress([REDACTED])",
            Self::NasTcpPort(_) => "Notify::NasTcpPort([REDACTED])",
            Self::UpSaInfo(_) => "Notify::UpSaInfo([REDACTED])",
            Self::MobikeSupported => "Notify::MobikeSupported",
        })
    }
}
impl<'a> Notify<'a> {
    /// Decode a Notify body without its generic payload header.
    pub fn decode_body(body: &'a [u8]) -> Result<Option<Self>, Error> {
        if body.len() > 65_531 {
            return Err(Error::Limit);
        }
        Self::decode(Ikev2NotifyPayload::decode_body(body).map_err(|_| Error::Framing)?)
    }
    /// Validate a generic Notify view, including manually constructed views.
    /// Protocol ID is ignored when SPI Size is zero, per RFC 7296 section 3.10.
    pub fn decode(value: Ikev2NotifyPayload<'a>) -> Result<Option<Self>, Error> {
        let t = value.notify_message_type;
        if !(55_501..=55_508).contains(&t) && t != 16_396 {
            return Ok(None);
        }
        if value.spi.len() != usize::from(value.spi_size) {
            return Err(Error::SpiShape);
        }
        if value
            .spi
            .len()
            .saturating_add(value.notification_data.len())
            > 65_527
        {
            return Err(Error::Limit);
        }
        if t == 55_508 {
            if value.protocol_id != 3 || value.spi_size != 4 {
                return Err(Error::SpiShape);
            }
            return Ok(Some(Self::UpSaInfo(EspSpi::new(
                value.spi.try_into().map_err(|_| Error::SpiShape)?,
            )?)));
        }
        if value.spi_size != 0 {
            return Err(Error::SpiShape);
        }
        let data = value.notification_data;
        Ok(Some(match t {
            55_501 => Self::Qos(QosInfo::decode(data)?),
            55_502 | 55_503 => Self::NasAddress(Address::from_wire(data, t == 55_502)?),
            55_504 | 55_505 => Self::UpAddress(Address::from_wire(data, t == 55_504)?),
            55_506 => Self::NasTcpPort(u16::from_be_bytes(
                data.try_into().map_err(|_| Error::InvalidValue)?,
            )),
            55_507 => return Err(Error::Unsupported),
            16_396 if data.is_empty() => Self::MobikeSupported,
            _ => return Err(Error::InvalidValue),
        }))
    }
    /// Construct a canonical body through the generic IKE Notify builder.
    pub fn encode_body(self) -> Result<Vec<u8>, Error> {
        let (notify_message_type, protocol_id, spi, notification_data) = match self {
            Self::Qos(qos) => (55_501, 0, vec![], qos.encode()?),
            Self::NasAddress(address) => (
                if address.is_ipv4() { 55_502 } else { 55_503 },
                0,
                vec![],
                address.octets(),
            ),
            Self::UpAddress(address) => (
                if address.is_ipv4() { 55_504 } else { 55_505 },
                0,
                vec![],
                address.octets(),
            ),
            Self::NasTcpPort(port) => (55_506, 0, vec![], port.to_be_bytes().to_vec()),
            Self::UpSaInfo(spi) => (55_508, 3, spi.octets().to_vec(), vec![]),
            Self::MobikeSupported => (16_396, 0, vec![], vec![]),
        };
        build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
            protocol_id,
            spi,
            notify_message_type,
            notification_data,
        })
        .map_err(|_| Error::InvalidValue)
    }
}
