//! GTPv2-C common-header parsing and encoding.
//!
//! @spec 3GPP TS29274 R18 5.1, 5.4, 5.5.1
//! @req REQ-3GPP-TS29274-R18-5.1-001

use core::fmt;

use bytes::{BufMut, BytesMut};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef,
};

/// GTPv2-C protocol version carried in the common-header flags octet.
pub const GTPV2C_VERSION: u8 = 2;

/// Length, in octets, of a GTPv2-C header with the TEID flag set.
pub const HEADER_LEN_WITH_TEID: usize = 12;

/// Length, in octets, of a GTPv2-C header without a TEID.
pub const HEADER_LEN_WITHOUT_TEID: usize = 8;

/// Maximum value of the 24-bit GTPv2-C sequence number field.
pub const MAX_SEQUENCE_NUMBER: u32 = 0x00ff_ffff;

/// Maximum value of the four-bit GTPv2-C Message Priority field.
pub const MAX_MESSAGE_PRIORITY: u8 = 15;

/// Relative priority carried by an EPC-specific GTPv2-C header.
///
/// TS 29.274 encodes this value in bits 8 to 5 of octet 12 when the Message
/// Priority (MP) flag is set. Zero is the highest priority and 15 is the
/// lowest priority. This value is scheduling metadata and contains no
/// subscriber or peer identity.
///
/// @spec 3GPP TS29274 R18 5.4, 5.5.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessagePriority(u8);

impl MessagePriority {
    /// Highest relative message priority.
    pub const HIGHEST: Self = Self(0);

    /// Lowest relative message priority.
    pub const LOWEST: Self = Self(MAX_MESSAGE_PRIORITY);

    /// Validate and construct a four-bit message priority.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMessagePriority`] when `value` is greater than 15.
    pub const fn new(value: u8) -> Result<Self, InvalidMessagePriority> {
        if value <= MAX_MESSAGE_PRIORITY {
            Ok(Self(value))
        } else {
            Err(InvalidMessagePriority { value })
        }
    }

    /// Return the priority as an integer in `0..=15`.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    const fn from_wire(value: u8) -> Self {
        Self(value & MAX_MESSAGE_PRIORITY)
    }
}

impl TryFrom<u8> for MessagePriority {
    type Error = InvalidMessagePriority;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<MessagePriority> for u8 {
    fn from(value: MessagePriority) -> Self {
        value.get()
    }
}

/// Error returned when a GTPv2-C Message Priority does not fit four bits.
///
/// The value is protocol scheduling metadata, so diagnostics may safely
/// report it without exposing subscriber data, tunnel identifiers, or peer
/// addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMessagePriority {
    value: u8,
}

impl InvalidMessagePriority {
    /// Return the rejected value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.value
    }
}

impl fmt::Display for InvalidMessagePriority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GTPv2-C message priority must be between 0 and 15 inclusive")
    }
}

impl std::error::Error for InvalidMessagePriority {}

/// GTPv2-C message type values covered by the S2b typed subset.
///
/// Unsupported values remain available through [`MessageType::Unknown`] so
/// callers can use a typed API without losing raw message-type bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Echo Request (1).
    EchoRequest,
    /// Echo Response (2).
    EchoResponse,
    /// Create Session Request (32).
    CreateSessionRequest,
    /// Create Session Response (33).
    CreateSessionResponse,
    /// Modify Bearer Request (34), used by the S2b Modify Session view.
    ModifyBearerRequest,
    /// Modify Bearer Response (35), used by the S2b Modify Session view.
    ModifyBearerResponse,
    /// Delete Session Request (36).
    DeleteSessionRequest,
    /// Delete Session Response (37).
    DeleteSessionResponse,
    /// Create Bearer Request (95).
    CreateBearerRequest,
    /// Create Bearer Response (96).
    CreateBearerResponse,
    /// Update Bearer Request (97).
    UpdateBearerRequest,
    /// Update Bearer Response (98).
    UpdateBearerResponse,
    /// Delete Bearer Request (99).
    DeleteBearerRequest,
    /// Delete Bearer Response (100).
    DeleteBearerResponse,
    /// Unsupported or future GTPv2-C message type.
    Unknown(u8),
}

impl MessageType {
    /// Convert a raw GTPv2-C message type octet into the typed view.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::EchoRequest,
            2 => Self::EchoResponse,
            32 => Self::CreateSessionRequest,
            33 => Self::CreateSessionResponse,
            34 => Self::ModifyBearerRequest,
            35 => Self::ModifyBearerResponse,
            36 => Self::DeleteSessionRequest,
            37 => Self::DeleteSessionResponse,
            95 => Self::CreateBearerRequest,
            96 => Self::CreateBearerResponse,
            97 => Self::UpdateBearerRequest,
            98 => Self::UpdateBearerResponse,
            99 => Self::DeleteBearerRequest,
            100 => Self::DeleteBearerResponse,
            other => Self::Unknown(other),
        }
    }

    /// Return the raw GTPv2-C message type octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::EchoRequest => 1,
            Self::EchoResponse => 2,
            Self::CreateSessionRequest => 32,
            Self::CreateSessionResponse => 33,
            Self::ModifyBearerRequest => 34,
            Self::ModifyBearerResponse => 35,
            Self::DeleteSessionRequest => 36,
            Self::DeleteSessionResponse => 37,
            Self::CreateBearerRequest => 95,
            Self::CreateBearerResponse => 96,
            Self::UpdateBearerRequest => 97,
            Self::UpdateBearerResponse => 98,
            Self::DeleteBearerRequest => 99,
            Self::DeleteBearerResponse => 100,
            Self::Unknown(value) => value,
        }
    }

    /// Return `true` when this is one of the S2b typed subset message values.
    pub const fn is_s2b(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        Self::from_u8(value)
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        value.as_u8()
    }
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
/// @spec 3GPP TS29274 R18 5.1, 5.4, 5.5.1
/// @req REQ-3GPP-TS29274-R18-5.1-002
/// @conformance s2b-subset
///
/// # Safety for logging
///
/// `Debug` reports whether a TEID is present but never emits the tunnel
/// identifier itself. Message type, flags, relative priority, length, and
/// sequence metadata remain available for protocol diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    /// Protocol version from flags octet bits 8-6; valid GTPv2-C is `2`.
    pub version: u8,
    /// Piggybacking flag from the flags octet.
    pub piggybacking: bool,
    /// TEID-present flag from the flags octet.
    pub teid_flag: bool,
    /// Message Priority flag from bit 3 of a TEID-present EPC header.
    ///
    /// This flag must equal `message_priority.is_some()`. It is always false
    /// for no-TEID Echo and Version Not Supported headers, where bit 3 is
    /// spare instead.
    pub message_priority_flag: bool,
    /// Spare bits from the flags octet.
    ///
    /// For TEID-present EPC headers this contains bits 2 to 1 only. For a
    /// no-TEID header it contains all three low spare bits so raw-preserving
    /// forwarding can retain them. Strict decode requires the value to be zero.
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
    /// Optional relative Message Priority from octet 12.
    ///
    /// This is present exactly when [`Header::message_priority_flag`] is set.
    /// Priorities are available only on TEID-present EPC headers.
    pub message_priority: Option<MessagePriority>,
    /// Raw octet following the 24-bit sequence number.
    ///
    /// On a TEID-present header, its high nibble carries Message Priority when
    /// the MP flag is set and its low nibble is spare. When MP is clear, the
    /// high nibble is ignored by receivers. Keeping the decoded octet lets
    /// raw-preserving encode retain ignored and spare bits; canonical encode
    /// always emits the typed priority and zero spare bits.
    pub spare_octet: u8,
}

impl fmt::Debug for Header {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Header")
            .field("version", &self.version)
            .field("piggybacking", &self.piggybacking)
            .field("teid_flag", &self.teid_flag)
            .field("teid_present", &self.teid.is_some())
            .field("message_priority_flag", &self.message_priority_flag)
            .field("spare", &self.spare)
            .field("message_type", &self.message_type)
            .field("length", &self.length)
            .field("sequence_number", &self.sequence_number)
            .field("message_priority", &self.message_priority)
            .field("spare_octet", &self.spare_octet)
            .finish()
    }
}

impl Header {
    /// Construct a canonical GTPv2-C header for a message without TEID.
    pub const fn without_teid(message_type: u8, sequence_number: u32) -> Self {
        Self {
            version: GTPV2C_VERSION,
            piggybacking: false,
            teid_flag: false,
            message_priority_flag: false,
            spare: 0,
            message_type,
            length: 0,
            teid: None,
            sequence_number,
            message_priority: None,
            spare_octet: 0,
        }
    }

    /// Construct a canonical GTPv2-C header for a message with TEID.
    pub const fn with_teid(message_type: u8, teid: u32, sequence_number: u32) -> Self {
        Self {
            version: GTPV2C_VERSION,
            piggybacking: false,
            teid_flag: true,
            message_priority_flag: false,
            spare: 0,
            message_type,
            length: 0,
            teid: Some(teid),
            sequence_number,
            message_priority: None,
            spare_octet: 0,
        }
    }

    /// Set a typed Message Priority and its MP flag.
    ///
    /// The resulting header must remain TEID-present. Encoding rejects an MP
    /// flag on a no-TEID header.
    #[must_use]
    pub const fn with_message_priority(mut self, priority: MessagePriority) -> Self {
        self.message_priority_flag = true;
        self.message_priority = Some(priority);
        self.spare_octet = (priority.get() << 4) | (self.spare_octet & 0x0f);
        self
    }

    /// Set or clear a typed Message Priority in fluent builder code.
    ///
    /// This accepts an `Option` so a higher-level request or response builder
    /// can copy priority metadata without branching or constructing flag bits.
    #[must_use]
    pub const fn with_optional_message_priority(
        mut self,
        priority: Option<MessagePriority>,
    ) -> Self {
        self.set_message_priority(priority);
        self
    }

    /// Set or clear the typed Message Priority and keep the MP flag coherent.
    pub const fn set_message_priority(&mut self, priority: Option<MessagePriority>) {
        self.message_priority_flag = priority.is_some();
        self.message_priority = priority;
        self.spare_octet = match priority {
            Some(value) => (value.get() << 4) | (self.spare_octet & 0x0f),
            None => self.spare_octet & 0x0f,
        };
    }

    /// Return the typed relative Message Priority, when MP is enabled.
    #[must_use]
    pub const fn message_priority(&self) -> Option<MessagePriority> {
        self.message_priority
    }

    /// Return the on-wire header size in octets.
    pub const fn wire_len(&self) -> usize {
        if self.teid_flag {
            HEADER_LEN_WITH_TEID
        } else {
            HEADER_LEN_WITHOUT_TEID
        }
    }

    /// Return the typed GTPv2-C message type, with an unknown fallback.
    pub const fn typed_message_type(&self) -> MessageType {
        MessageType::from_u8(self.message_type)
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
/// @spec 3GPP TS29274 R18 5.1, 5.4, 5.5.1
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
    let raw_message_priority_flag = (flags & 0x04) != 0;
    let message_priority_flag = teid_flag && raw_message_priority_flag;
    let spare = if teid_flag {
        flags & 0x03
    } else {
        flags & 0x07
    };

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

    if crate::is_strict(ctx.validation_level) && spare != 0 {
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
    let message_priority = if message_priority_flag {
        Some(MessagePriority::from_wire(spare_octet >> 4))
    } else {
        None
    };

    if crate::is_strict(ctx.validation_level) {
        let invalid_spare_octet = if teid_flag {
            (spare_octet & 0x0f) != 0
        } else {
            spare_octet != 0
        };
        if invalid_spare_octet {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "sequence or message-priority spare bits must be zero",
                },
                sequence_offset + 3,
            )
            .with_spec_ref(spec));
        }
        if teid_flag && !message_priority_flag && (spare_octet & 0xf0) != 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "message priority value set while MP flag is clear",
                },
                sequence_offset + 3,
            )
            .with_spec_ref(spec));
        }
    }

    Ok((
        &input[header_len..],
        Header {
            version,
            piggybacking,
            teid_flag,
            message_priority_flag,
            spare,
            message_type,
            length,
            teid,
            sequence_number,
            message_priority,
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
/// @spec 3GPP TS29274 R18 5.1, 5.4, 5.5.1
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
    if !header.teid_flag && (header.message_priority_flag || header.message_priority.is_some()) {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "Message Priority requires a TEID-present EPC header",
        })
        .with_spec_ref(spec));
    }
    let message_priority = match (header.message_priority_flag, header.message_priority) {
        (true, Some(priority)) => Some(priority),
        (false, None) => None,
        _ => {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "MP flag and message priority value are inconsistent",
            })
            .with_spec_ref(spec));
        }
    };

    let version = if ctx.raw_preserving {
        header.version & 0x07
    } else {
        GTPV2C_VERSION
    };
    if version != GTPV2C_VERSION {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "GTPv2-C version must be 2",
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
    if header.message_priority_flag {
        flags |= 0x04;
    }
    if ctx.raw_preserving {
        flags |= header.spare & if header.teid_flag { 0x03 } else { 0x07 };
    }

    dst.put_u8(flags);
    dst.put_u8(header.message_type);
    dst.put_u16(header.length);
    if header.teid_flag {
        match header.teid {
            Some(teid) => dst.put_u32(teid),
            None => {
                return Err(EncodeError::new(EncodeErrorCode::Structural {
                    reason: "TEID flag set without TEID value",
                })
                .with_spec_ref(spec));
            }
        }
    }
    dst.put_u8(((header.sequence_number >> 16) & 0xff) as u8);
    dst.put_u8(((header.sequence_number >> 8) & 0xff) as u8);
    dst.put_u8((header.sequence_number & 0xff) as u8);
    let priority_octet = match message_priority {
        Some(priority) => {
            let spare = if ctx.raw_preserving {
                header.spare_octet & 0x0f
            } else {
                0
            };
            (priority.get() << 4) | spare
        }
        None if ctx.raw_preserving => header.spare_octet,
        None => 0,
    };
    dst.put_u8(priority_octet);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_protocol::ValidationLevel;

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
