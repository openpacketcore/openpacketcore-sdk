//! IKEv2 fixed-header parsing and encoding.
//!
//! @spec IETF RFC7296 3.1
//! @req REQ-IETF-RFC7296-3.1-001

use bytes::{BufMut, BytesMut};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef,
};

use crate::{payload::PayloadType, validation::Ikev2ValidationProfile};

/// IKEv2 fixed header length in octets.
pub const HEADER_LEN: usize = 28;

/// IKEv2 major version number carried in the version octet high nibble.
pub const IKEV2_MAJOR_VERSION: u8 = 2;

/// IKEv2 minor version number carried in the version octet low nibble.
pub const IKEV2_MINOR_VERSION: u8 = 0;

/// Canonical IKEv2 version octet, major 2 and minor 0.
pub const IKEV2_VERSION_OCTET: u8 = (IKEV2_MAJOR_VERSION << 4) | (IKEV2_MINOR_VERSION & 0x0f);

/// IKE_SA_INIT exchange type value.
pub const EXCHANGE_TYPE_IKE_SA_INIT: u8 = 34;

/// IKE_AUTH exchange type value.
pub const EXCHANGE_TYPE_IKE_AUTH: u8 = 35;

/// CREATE_CHILD_SA exchange type value.
pub const EXCHANGE_TYPE_CREATE_CHILD_SA: u8 = 36;

/// INFORMATIONAL exchange type value.
pub const EXCHANGE_TYPE_INFORMATIONAL: u8 = 37;

const FLAG_INITIATOR: u8 = 0x08;
const FLAG_VERSION: u8 = 0x10;
const FLAG_RESPONSE: u8 = 0x20;
const FLAG_KNOWN_MASK: u8 = FLAG_INITIATOR | FLAG_VERSION | FLAG_RESPONSE;

fn spec_ref() -> SpecRef {
    SpecRef::new("ietf", "RFC7296", "3.1")
}

fn truncated(spec: &SpecRef, offset: usize) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Truncated, offset).with_spec_ref(spec.clone())
}

fn read_array<const N: usize>(
    input: &[u8],
    offset: usize,
    spec: &SpecRef,
) -> Result<[u8; N], DecodeError> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| DecodeError::new(DecodeErrorCode::LengthOverflow, offset))?;
    let Some(slice) = input.get(offset..end) else {
        return Err(truncated(spec, offset));
    };
    let mut bytes = [0u8; N];
    bytes.copy_from_slice(slice);
    Ok(bytes)
}

/// Raw IKEv2 header flags octet with named bit helpers.
///
/// @spec IETF RFC7296 3.1
/// @req REQ-IETF-RFC7296-3.1-FLAGS-001
/// @conformance experimental-scaffold
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HeaderFlags {
    raw: u8,
}

impl HeaderFlags {
    /// Construct a flag wrapper from the raw on-wire octet.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Construct flags from individual named bits.
    pub const fn from_bits(initiator: bool, response: bool, version: bool) -> Self {
        let mut raw = 0u8;
        if initiator {
            raw |= FLAG_INITIATOR;
        }
        if response {
            raw |= FLAG_RESPONSE;
        }
        if version {
            raw |= FLAG_VERSION;
        }
        Self { raw }
    }

    /// Return the raw flags octet.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return `true` when the Initiator bit is set.
    pub const fn initiator(self) -> bool {
        (self.raw & FLAG_INITIATOR) != 0
    }

    /// Return `true` when the Response bit is set.
    pub const fn response(self) -> bool {
        (self.raw & FLAG_RESPONSE) != 0
    }

    /// Return `true` when the Version bit is set.
    ///
    /// This is the RFC 7296 §3.1 "higher major version supported" flag, not
    /// the IKE major-version field. IKEv2 senders clear it and receivers ignore
    /// it.
    pub const fn version(self) -> bool {
        (self.raw & FLAG_VERSION) != 0
    }

    /// Return reserved bits outside the I, V, and R flag positions.
    pub const fn reserved_bits(self) -> u8 {
        self.raw & !FLAG_KNOWN_MASK
    }

    /// Return a canonicalized send-side flags octet.
    ///
    /// RFC 7296 §3.1 requires the Version bit and reserved bits to be cleared
    /// when sending, so canonical output retains only the Initiator and
    /// Response bits.
    pub const fn canonical_raw(self) -> u8 {
        self.raw & (FLAG_INITIATOR | FLAG_RESPONSE)
    }
}

/// IKEv2 fixed header.
///
/// The `length` field is the complete message length in octets, including this
/// fixed header and all payload bytes.
///
/// @spec IETF RFC7296 3.1
/// @req REQ-IETF-RFC7296-3.1-HEADER-001
/// @conformance experimental-scaffold
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Initiator SPI.
    pub initiator_spi: u64,
    /// Responder SPI.
    pub responder_spi: u64,
    /// Payload type of the first payload, or 0 for no payload.
    pub next_payload: u8,
    /// Major version from the high nibble of the version octet.
    pub major_version: u8,
    /// Minor version from the low nibble of the version octet.
    pub minor_version: u8,
    /// IKEv2 exchange type value.
    pub exchange_type: u8,
    /// Raw and named header flags.
    pub flags: HeaderFlags,
    /// Message ID.
    pub message_id: u32,
    /// Complete IKE message length, including the fixed header.
    pub length: u32,
}

impl Header {
    /// Construct a canonical IKEv2 fixed header with no payload bytes yet.
    pub const fn new(
        initiator_spi: u64,
        responder_spi: u64,
        next_payload: PayloadType,
        exchange_type: u8,
        flags: HeaderFlags,
        message_id: u32,
    ) -> Self {
        Self {
            initiator_spi,
            responder_spi,
            next_payload: next_payload.as_u8(),
            major_version: IKEV2_MAJOR_VERSION,
            minor_version: IKEV2_MINOR_VERSION,
            exchange_type,
            flags,
            message_id,
            length: HEADER_LEN as u32,
        }
    }

    /// Return the encoded fixed-header length in octets.
    pub const fn wire_len(&self) -> usize {
        HEADER_LEN
    }

    /// Return the version octet represented by this header.
    pub const fn version_octet(&self) -> u8 {
        ((self.major_version & 0x0f) << 4) | (self.minor_version & 0x0f)
    }

    /// Return the declared body length after the fixed header.
    ///
    /// The value is derived from this header's stored Length field and does not
    /// allocate. Headers decoded with [`decode_header`] are checked against the
    /// supplied [`DecodeContext::max_message_len`]; manually constructed
    /// headers should be bounded by callers before using this value to size any
    /// allocation.
    pub fn body_len(&self) -> Result<usize, DecodeError> {
        let spec = spec_ref();
        let declared = usize::try_from(self.length).map_err(|_| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, 24).with_spec_ref(spec.clone())
        })?;
        declared.checked_sub(HEADER_LEN).ok_or_else(|| {
            DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "IKEv2 length shorter than fixed header",
                },
                24,
            )
            .with_spec_ref(spec)
        })
    }
}

/// Decode an IKEv2 fixed header from the front of `input`.
///
/// Full message-boundary slicing happens in [`crate::Message`], but this
/// header-only API still rejects declared lengths below [`HEADER_LEN`] or above
/// [`DecodeContext::max_message_len`] so callers do not accidentally allocate
/// from hostile length fields.
///
/// @spec IETF RFC7296 3.1
/// @req REQ-IETF-RFC7296-3.1-DECODE-001
/// @conformance experimental-scaffold
pub fn decode_header(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Header> {
    decode_header_with_profile(input, ctx, Ikev2ValidationProfile::NetworkReceive)
}

/// Decode an IKEv2 fixed header using an explicit validation profile.
///
/// [`Ikev2ValidationProfile::NetworkReceive`] follows RFC 7296 receiver
/// behavior and ignores higher minor versions and reserved flag bits while
/// preserving their raw values in [`Header`].
/// [`Ikev2ValidationProfile::SenderCanonical`] additionally diagnoses those
/// fields when validating generated outbound fixtures.
///
/// All profiles reject invalid major versions and malformed or hostile length
/// fields.
///
/// @spec IETF RFC7296 3.1
/// @req REQ-IETF-RFC7296-3.1-DECODE-002
/// @conformance experimental-scaffold
pub fn decode_header_with_profile(
    input: &[u8],
    ctx: DecodeContext,
    profile: Ikev2ValidationProfile,
) -> DecodeResult<'_, Header> {
    let spec = spec_ref();
    if input.len() < HEADER_LEN {
        return Err(truncated(&spec, input.len()));
    }

    let initiator_spi = u64::from_be_bytes(read_array::<8>(input, 0, &spec)?);
    let responder_spi = u64::from_be_bytes(read_array::<8>(input, 8, &spec)?);
    let next_payload = input[16];
    let version = input[17];
    let major_version = (version >> 4) & 0x0f;
    let minor_version = version & 0x0f;
    let exchange_type = input[18];
    let flags = HeaderFlags::new(input[19]);
    let message_id = u32::from_be_bytes(read_array::<4>(input, 20, &spec)?);
    let length = u32::from_be_bytes(read_array::<4>(input, 24, &spec)?);

    if major_version != IKEV2_MAJOR_VERSION {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "major_version",
                value: major_version as u64,
            },
            17,
        )
        .with_spec_ref(spec));
    }

    if profile.requires_sender_canonical_fields() && minor_version != IKEV2_MINOR_VERSION {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "minor_version",
                value: minor_version as u64,
            },
            17,
        )
        .with_spec_ref(spec));
    }

    if profile.requires_sender_canonical_fields() && (flags.version() || flags.reserved_bits() != 0)
    {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "IKEv2 Version and reserved header flag bits must be zero on send",
            },
            19,
        )
        .with_spec_ref(spec));
    }

    if length < HEADER_LEN as u32 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidLength {
                reason: "IKEv2 length shorter than fixed header",
            },
            24,
        )
        .with_spec_ref(spec));
    }

    let declared_len = usize::try_from(length).map_err(|_| {
        DecodeError::new(DecodeErrorCode::LengthOverflow, 24).with_spec_ref(spec.clone())
    })?;
    if declared_len > ctx.max_message_len {
        return Err(
            DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 24).with_spec_ref(spec)
        );
    }

    Ok((
        &input[HEADER_LEN..],
        Header {
            initiator_spi,
            responder_spi,
            next_payload,
            major_version,
            minor_version,
            exchange_type,
            flags,
            message_id,
            length,
        },
    ))
}

/// Encode an IKEv2 fixed header.
///
/// In raw-preserving mode this keeps the decoded minor version and reserved
/// flag bits. In canonical mode it emits version 2.0 and clears the RFC 7296
/// §3.1 Version bit plus reserved flag bits while retaining the I and R flags.
///
/// @spec IETF RFC7296 3.1
/// @req REQ-IETF-RFC7296-3.1-ENCODE-001
/// @conformance experimental-scaffold
pub fn encode_header(
    header: &Header,
    dst: &mut BytesMut,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let spec = spec_ref();
    if header.major_version != IKEV2_MAJOR_VERSION {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "IKEv2 major version must be 2",
        })
        .with_spec_ref(spec));
    }
    if header.length < HEADER_LEN as u32 {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "IKEv2 length shorter than fixed header",
        })
        .with_spec_ref(spec));
    }

    ctx.check_capacity(HEADER_LEN)?;

    dst.reserve(HEADER_LEN);
    dst.put_u64(header.initiator_spi);
    dst.put_u64(header.responder_spi);
    dst.put_u8(header.next_payload);
    let version = if ctx.raw_preserving {
        header.version_octet()
    } else {
        IKEV2_VERSION_OCTET
    };
    dst.put_u8(version);
    dst.put_u8(header.exchange_type);
    let flags = if ctx.raw_preserving {
        header.flags.raw()
    } else {
        header.flags.canonical_raw()
    };
    dst.put_u8(flags);
    dst.put_u32(header.message_id);
    dst.put_u32(header.length);
    Ok(())
}
