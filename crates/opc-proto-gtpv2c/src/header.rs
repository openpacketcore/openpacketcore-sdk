//! GTPv2-C common-header parsing and encoding.
//!
//! @spec 3GPP TS29274 R18 5.1
//! @req REQ-3GPP-TS29274-R18-5.1-001

use bytes::{BufMut, BytesMut};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef, ValidationLevel,
};

/// GTPv2-C protocol version carried in the common-header flags octet.
pub const GTPV2C_VERSION: u8 = 2;

/// Length, in octets, of a GTPv2-C header with the TEID flag set.
pub const HEADER_LEN_WITH_TEID: usize = 12;

/// Length, in octets, of a GTPv2-C header without a TEID.
pub const HEADER_LEN_WITHOUT_TEID: usize = 8;

/// Maximum value of the 24-bit GTPv2-C sequence number field.
pub const MAX_SEQUENCE_NUMBER: u32 = 0x00ff_ffff;

fn is_strict(level: ValidationLevel) -> bool {
    matches!(
        level,
        ValidationLevel::Strict | ValidationLevel::ProcedureAware
    )
}

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS29274", "5.1")
}

/// GTPv2-C common header.
///
/// The length field follows TS 29.274 and excludes the first four octets of
/// the message. When [`Header::teid_flag`] is set, the length includes the
/// four-octet TEID plus sequence/spare fields and payload IEs.
///
/// @spec 3GPP TS29274 R18 5.1
/// @req REQ-3GPP-TS29274-R18-5.1-002
/// @conformance s2b-subset
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Protocol version from flags octet bits 8-6; valid GTPv2-C is `2`.
    pub version: u8,
    /// Piggybacking flag from the flags octet.
    pub piggybacking: bool,
    /// TEID-present flag from the flags octet.
    pub teid_flag: bool,
    /// Low three spare bits from the flags octet.
    pub spare: u8,
    /// GTPv2-C message type.
    pub message_type: u8,
    /// Message length, excluding the first four octets.
    pub length: u16,
    /// Tunnel Endpoint Identifier, present when [`Header::teid_flag`] is set.
    pub teid: Option<u32>,
    /// 24-bit GTPv2-C sequence number encoded in octets following the TEID
    /// or directly after the length field when no TEID is present.
    pub sequence_number: u32,
    /// Spare octet following the 24-bit sequence number.
    pub spare_octet: u8,
}

impl Header {
    /// Construct a canonical GTPv2-C header for a message without TEID.
    pub const fn without_teid(message_type: u8, sequence_number: u32) -> Self {
        Self {
            version: GTPV2C_VERSION,
            piggybacking: false,
            teid_flag: false,
            spare: 0,
            message_type,
            length: 0,
            teid: None,
            sequence_number,
            spare_octet: 0,
        }
    }

    /// Construct a canonical GTPv2-C header for a message with TEID.
    pub const fn with_teid(message_type: u8, teid: u32, sequence_number: u32) -> Self {
        Self {
            version: GTPV2C_VERSION,
            piggybacking: false,
            teid_flag: true,
            spare: 0,
            message_type,
            length: 0,
            teid: Some(teid),
            sequence_number,
            spare_octet: 0,
        }
    }

    /// Return the on-wire header size in octets.
    pub const fn wire_len(&self) -> usize {
        if self.teid_flag {
            HEADER_LEN_WITH_TEID
        } else {
            HEADER_LEN_WITHOUT_TEID
        }
    }

    /// Return the number of bytes declared by the header length field.
    pub const fn body_len(&self) -> usize {
        self.length as usize
    }
}

/// Decode a GTPv2-C common header from the front of `input`.
///
/// The returned slice starts immediately after the common header and before
/// any IE payload. Full message-boundary validation happens in
/// [`crate::Message`].
///
/// @spec 3GPP TS29274 R18 5.1
/// @req REQ-3GPP-TS29274-R18-5.1-003
/// @conformance s2b-subset
pub fn decode_header(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Header> {
    let spec = spec_ref();
    if input.len() < HEADER_LEN_WITHOUT_TEID {
        return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec));
    }

    let flags = input[0];
    let version = (flags >> 5) & 0x07;
    let piggybacking = (flags & 0x10) != 0;
    let teid_flag = (flags & 0x08) != 0;
    let spare = flags & 0x07;

    if version != GTPV2C_VERSION {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "version",
                value: version as u64,
            },
            0,
        )
        .with_spec_ref(spec));
    }

    if is_strict(ctx.validation_level) && spare != 0 {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "flags spare bits must be zero",
            },
            0,
        )
        .with_spec_ref(spec));
    }

    let message_type = input[1];
    let length = u16::from_be_bytes([input[2], input[3]]);
    let header_len = if teid_flag {
        HEADER_LEN_WITH_TEID
    } else {
        HEADER_LEN_WITHOUT_TEID
    };

    let total_declared_len = 4usize.checked_add(length as usize).ok_or_else(|| {
        DecodeError::new(DecodeErrorCode::LengthOverflow, 2).with_spec_ref(spec.clone())
    })?;
    if total_declared_len < header_len {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidLength {
                reason: "message length shorter than common header",
            },
            2,
        )
        .with_spec_ref(spec));
    }

    if input.len() < header_len {
        return Err(DecodeError::new(DecodeErrorCode::Truncated, input.len()).with_spec_ref(spec));
    }

    let (teid, sequence_offset) = if teid_flag {
        let teid = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
        (Some(teid), 8usize)
    } else {
        (None, 4usize)
    };

    let sequence_number = ((input[sequence_offset] as u32) << 16)
        | ((input[sequence_offset + 1] as u32) << 8)
        | (input[sequence_offset + 2] as u32);
    let spare_octet = input[sequence_offset + 3];

    if is_strict(ctx.validation_level) && spare_octet != 0 {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "sequence spare octet must be zero",
            },
            sequence_offset + 3,
        )
        .with_spec_ref(spec));
    }

    Ok((
        &input[header_len..],
        Header {
            version,
            piggybacking,
            teid_flag,
            spare,
            message_type,
            length,
            teid,
            sequence_number,
            spare_octet,
        },
    ))
}

/// Encode a GTPv2-C common header.
///
/// In raw-preserving mode this keeps version and spare bits from the supplied
/// header. In canonical mode it emits version 2, zero spare bits, and a zero
/// sequence spare octet.
///
/// @spec 3GPP TS29274 R18 5.1
/// @req REQ-3GPP-TS29274-R18-5.1-004
/// @conformance s2b-subset
pub fn encode_header(
    header: &Header,
    dst: &mut BytesMut,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let spec = spec_ref();
    if header.sequence_number > MAX_SEQUENCE_NUMBER {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "sequence number exceeds 24 bits",
        })
        .with_spec_ref(spec));
    }
    if header.teid_flag && header.teid.is_none() {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "TEID flag set without TEID value",
        })
        .with_spec_ref(spec));
    }
    if !header.teid_flag && header.teid.is_some() {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "TEID value present while TEID flag is clear",
        })
        .with_spec_ref(spec));
    }

    let version = if ctx.raw_preserving {
        header.version & 0x07
    } else {
        GTPV2C_VERSION
    };
    if version != GTPV2C_VERSION {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "GTPv2-C canonical version must be 2",
        })
        .with_spec_ref(spec));
    }

    let mut flags = version << 5;
    if header.piggybacking {
        flags |= 0x10;
    }
    if header.teid_flag {
        flags |= 0x08;
    }
    if ctx.raw_preserving {
        flags |= header.spare & 0x07;
    }

    dst.put_u8(flags);
    dst.put_u8(header.message_type);
    dst.put_u16(header.length);
    if header.teid_flag {
        let teid = header.teid.ok_or_else(|| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "TEID flag set without TEID value",
            })
            .with_spec_ref(spec.clone())
        })?;
        dst.put_u32(teid);
    }
    dst.put_u8(((header.sequence_number >> 16) & 0xff) as u8);
    dst.put_u8(((header.sequence_number >> 8) & 0xff) as u8);
    dst.put_u8((header.sequence_number & 0xff) as u8);
    dst.put_u8(if ctx.raw_preserving {
        header.spare_octet
    } else {
        0
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_echo_request_header_without_teid() {
        let bytes = [0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
        let decoded = decode_header(&bytes, DecodeContext::default());
        let (tail, header) = match decoded {
            Ok(value) => value,
            Err(error) => panic!("decode failed: {error:?}"),
        };
        assert!(tail.is_empty());
        assert_eq!(header.version, GTPV2C_VERSION);
        assert!(!header.teid_flag);
        assert_eq!(header.sequence_number, 1);
        assert_eq!(header.wire_len(), HEADER_LEN_WITHOUT_TEID);
    }

    #[test]
    fn strict_decode_rejects_spare_bits() {
        let bytes = [0x41, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
        let ctx = DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        };
        let decoded = decode_header(&bytes, ctx);
        assert!(decoded.is_err());
    }
}
