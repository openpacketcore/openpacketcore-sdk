//! Typed TS 29.281 §5.2.2 extension values; RAN payload semantics belong to their users.

use crate::{encode_extension_header, GtpuExtensionHeader, PduSessionContainer};
use bytes::Bytes;
use opc_protocol::{DecodeError, DecodeErrorCode, EncodeError, EncodeErrorCode};

/// Typed extension values. Opaque containers borrow their complete aligned content.
///
/// A known RAN container format does not establish comprehension of its inner
/// protocol, peer admission or permission to forward it. Consumers apply those
/// policies separately. PDCP interface-specific 12/15-bit limits are also caller
/// policy; the generic short number retains the UTRAN 16-bit wire value.
#[derive(Clone, PartialEq, Eq)]
pub enum GtpuTypedExtension<'a> {
    /// Triggering UDP source port (§5.2.2.1).
    UdpPort(u16),
    /// Short PDCP number (§5.2.2.2).
    PdcpPduNumber(u16),
    /// 18-bit PDCP number, current sender assignment 0x03 (§5.2.2.2A).
    LongPdcpPduNumber(u32),
    /// Earlier-release assignment 0x82; use only for explicit legacy interop.
    LegacyLongPdcpPduNumber(u32),
    /// SCI octet (§5.2.2.3); this release's send values are 0–15.
    ServiceClassIndicator(u8),
    /// Opaque TS 36.425 RAN container (§5.2.2.4).
    RanContainer(&'a [u8]),
    /// Opaque TS 36.465 Xw RAN container (§5.2.2.5).
    XwRanContainer(&'a [u8]),
    /// Opaque TS 38.425 NR RAN container (§5.2.2.6).
    NrRanContainer(&'a [u8]),
    /// Existing complete QFI/PPI/RQI subset (§5.2.2.7).
    PduSessionContainer(PduSessionContainer),
}

impl std::fmt::Debug for GtpuTypedExtension<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GtpuTypedExtension")
            .field("extension_type", &self.extension_type())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl<'a> GtpuTypedExtension<'a> {
    /// Decode known content; unknown types return `None` without implying comprehension.
    /// Receiver-ignored spare bits are omitted from the typed value.
    ///
    /// # Errors
    /// Rejects incorrect known lengths or an unsupported PDU Session Container value.
    pub fn decode(header: &GtpuExtensionHeader<'a>) -> Result<Option<Self>, DecodeError> {
        validate_fixed_length(header)?;
        let value = header.content;
        let typed = match header.ext_type {
            0x40 => Self::UdpPort(u16::from_be_bytes([value[0], value[1]])),
            0xc0 => Self::PdcpPduNumber(u16::from_be_bytes([value[0], value[1]])),
            0x03 | 0x82 => {
                let number = u32::from_be_bytes([0, value[0] & 3, value[1], value[2]]);
                if header.ext_type == 0x03 {
                    Self::LongPdcpPduNumber(number)
                } else {
                    Self::LegacyLongPdcpPduNumber(number)
                }
            }
            0x20 => Self::ServiceClassIndicator(value[0]),
            0x81 | 0x83 | 0x84 => {
                if value.len() < 2 || value.len() > 1018 || !(value.len() + 2).is_multiple_of(4) {
                    return Err(invalid_length());
                }
                match header.ext_type {
                    0x81 => Self::RanContainer(value),
                    0x83 => Self::XwRanContainer(value),
                    _ => Self::NrRanContainer(value),
                }
            }
            0x85 => Self::PduSessionContainer(PduSessionContainer::decode(header)?),
            _ => return Ok(None),
        };
        Ok(Some(typed))
    }

    /// Extension type stored in the preceding header's next-type field.
    #[must_use]
    pub const fn extension_type(&self) -> u8 {
        match self {
            Self::UdpPort(_) => 0x40,
            Self::PdcpPduNumber(_) => 0xc0,
            Self::LongPdcpPduNumber(_) => 0x03,
            Self::LegacyLongPdcpPduNumber(_) => 0x82,
            Self::ServiceClassIndicator(_) => 0x20,
            Self::RanContainer(_) => 0x81,
            Self::XwRanContainer(_) => 0x83,
            Self::NrRanContainer(_) => 0x84,
            Self::PduSessionContainer(_) => 0x85,
        }
    }

    /// Encode length, content and next-type octets, clearing sender spare bits.
    ///
    /// # Errors
    /// Refuses oversized 18-bit numbers, reserved SCI send values, invalid PSCs,
    /// and opaque containers outside the 4n−2 content width (2–1018 bytes).
    pub fn encode(&self, next_extension_type: u8) -> Result<Bytes, EncodeError> {
        let invalid = || {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "invalid typed GTP-U extension value",
            })
        };
        let content = match self {
            Self::UdpPort(value) | Self::PdcpPduNumber(value) => value.to_be_bytes().to_vec(),
            Self::LongPdcpPduNumber(value) | Self::LegacyLongPdcpPduNumber(value) => {
                if *value > 0x3ffff {
                    return Err(invalid());
                }
                let bytes = value.to_be_bytes();
                vec![bytes[1], bytes[2], bytes[3], 0, 0, 0]
            }
            Self::ServiceClassIndicator(value) => {
                if *value > 15 {
                    return Err(invalid());
                }
                vec![*value, 0]
            }
            Self::RanContainer(value)
            | Self::XwRanContainer(value)
            | Self::NrRanContainer(value) => {
                // Check before allocation: raw containers may be caller-constructed.
                if value.len() < 2 || value.len() > 1018 || !(value.len() + 2).is_multiple_of(4) {
                    return Err(invalid());
                }
                value.to_vec()
            }
            Self::PduSessionContainer(value) => value.encode().map_err(|_| invalid())?,
        };
        encode_extension_header(&content, next_extension_type)
            .map(Bytes::from)
            .map_err(|_| invalid())
    }
}

pub(crate) fn validate_fixed_length(header: &GtpuExtensionHeader<'_>) -> Result<(), DecodeError> {
    let expected = match header.ext_type {
        0x20 | 0x40 | 0xc0 => 2,
        0x03 | 0x82 => 6,
        _ => return Ok(()),
    };
    if header.content.len() != expected {
        Err(invalid_length())
    } else {
        Ok(())
    }
}

fn invalid_length() -> DecodeError {
    DecodeError::new(
        DecodeErrorCode::InvalidLength {
            reason: "invalid typed GTP-U extension length",
        },
        0,
    )
}
