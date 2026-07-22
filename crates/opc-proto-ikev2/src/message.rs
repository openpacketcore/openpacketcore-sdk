//! IKEv2 raw message shell built on the OpenPacketCore protocol traits.
//!
//! @spec IETF RFC7296 3.1, 3.2
//! @req REQ-IETF-RFC7296-MESSAGE-001

use core::fmt;

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, OwnedDecode, SpecRef, ToOwnedPdu,
};

use crate::{
    header::{decode_header_with_profile, encode_header, Header, HEADER_LEN},
    payload::{
        validate_payload_chain_with_rejection_and_profile, Ikev2PayloadChainRejection,
        Ikev2UnknownCriticalPayload, PayloadChain, PayloadType, RawPayloadIterator,
    },
    validation::Ikev2ValidationProfile,
};

fn spec_ref() -> SpecRef {
    SpecRef::new("ietf", "RFC7296", "3.1")
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RejectedMessageHeader {
    initiator_spi: u64,
    responder_spi: u64,
    next_payload: u8,
    major_version: u8,
    minor_version: u8,
    exchange_type: u8,
    flags: crate::HeaderFlags,
    message_id: u32,
    length: u32,
}

impl RejectedMessageHeader {
    fn from_header(header: &Header) -> Self {
        Self {
            initiator_spi: header.initiator_spi,
            responder_spi: header.responder_spi,
            next_payload: header.next_payload,
            major_version: header.major_version,
            minor_version: header.minor_version,
            exchange_type: header.exchange_type,
            flags: header.flags,
            message_id: header.message_id,
            length: header.length,
        }
    }

    pub(crate) fn to_header(self) -> Header {
        Header {
            initiator_spi: self.initiator_spi,
            responder_spi: self.responder_spi,
            next_payload: self.next_payload,
            major_version: self.major_version,
            minor_version: self.minor_version,
            exchange_type: self.exchange_type,
            flags: self.flags,
            message_id: self.message_id,
            length: self.length,
        }
    }
}

/// Unknown-critical rejection attached to one structurally valid IKEv2
/// message header.
///
/// This type is a protocol fact, not authority to transmit a response. Its
/// retained header projection is private and its `Debug` output omits both
/// SPIs and all packet bytes. An IKE_SA_INIT response can be authorized only
/// by converting this fact through the request-shape boundary in [`crate::sa_init`].
///
/// @spec IETF RFC7296 2.5, 3.1, 3.2
/// @req REQ-IETF-RFC7296-MESSAGE-UNKNOWN-CRITICAL-001
/// @conformance boundary-only
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2UnknownCriticalPayloadMessage {
    header: RejectedMessageHeader,
    rejection: Ikev2UnknownCriticalPayload,
    has_trailing_bytes: bool,
}

impl Ikev2UnknownCriticalPayloadMessage {
    /// Stable machine-readable rejection code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.rejection.code()
    }

    /// Exact typed unsupported-payload fact.
    #[must_use]
    pub const fn rejection(self) -> Ikev2UnknownCriticalPayload {
        self.rejection
    }

    /// Return whether the received IKE header was a request.
    ///
    /// This is informational only. It does not validate the exchange-specific
    /// request shape and does not grant reply authority.
    #[must_use]
    pub const fn is_request(self) -> bool {
        !self.header.flags.response()
    }

    pub(crate) const fn has_trailing_bytes(self) -> bool {
        self.has_trailing_bytes
    }

    pub(crate) const fn declared_len(self) -> usize {
        self.header.length as usize
    }

    pub(crate) fn request_header(self) -> Header {
        self.header.to_header()
    }
}

impl fmt::Debug for Ikev2UnknownCriticalPayloadMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2UnknownCriticalPayloadMessage")
            .field("code", &self.code())
            .field("rejection", &self.rejection)
            .field("is_request", &self.is_request())
            .finish_non_exhaustive()
    }
}

/// Detailed IKEv2 message decode rejection.
///
/// Existing [`Message::decode_with_profile`] and [`BorrowDecode`] APIs retain
/// their source-compatible [`DecodeError`] surface. This additive boundary
/// preserves the exact unsupported payload type only when its complete generic
/// framing was validated; malformed offender framing remains malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2MessageRejection {
    /// The fixed header or payload chain was malformed or exceeded limits.
    Malformed(DecodeError),
    /// A fully framed unknown payload set the Critical bit.
    UnknownCriticalPayload(Ikev2UnknownCriticalPayloadMessage),
}

impl Ikev2MessageRejection {
    /// Stable machine-readable rejection code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "ike_message_malformed",
            Self::UnknownCriticalPayload(rejection) => rejection.code(),
        }
    }

    /// Return the typed unknown-critical message fact when present.
    #[must_use]
    pub const fn unknown_critical_payload(&self) -> Option<Ikev2UnknownCriticalPayloadMessage> {
        match self {
            Self::Malformed(_) => None,
            Self::UnknownCriticalPayload(rejection) => Some(*rejection),
        }
    }

    pub(crate) fn into_decode_error(self) -> DecodeError {
        match self {
            Self::Malformed(error) => error,
            Self::UnknownCriticalPayload(rejection) => rejection.rejection.decode_error(),
        }
    }
}

impl fmt::Display for Ikev2MessageRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "{}: {error}", self.code()),
            Self::UnknownCriticalPayload(rejection) => write!(
                f,
                "{}: type {} at payload offset {}",
                rejection.code(),
                rejection.rejection().payload_type(),
                rejection.rejection().payload_offset()
            ),
        }
    }
}

impl std::error::Error for Ikev2MessageRejection {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(error) => Some(error),
            Self::UnknownCriticalPayload(_) => None,
        }
    }
}

/// Borrowed IKEv2 message shell.
///
/// The raw payload-chain bytes are preserved byte-for-byte. Typed payload-body
/// parsing and protected-payload opening are intentionally layered outside this
/// initial scaffold.
///
/// @spec IETF RFC7296 3.1, 3.2
/// @req REQ-IETF-RFC7296-MESSAGE-002
/// @conformance experimental-scaffold
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// Decoded IKEv2 fixed header.
    pub header: Header,
    /// Raw payload chain declared by the header length field.
    pub payloads: PayloadChain<'a>,
    /// Bytes beyond the message boundary declared by the fixed header.
    pub tail: &'a [u8],
}

impl<'a> Message<'a> {
    /// Iterate over raw payloads with [`DecodeContext::default`].
    pub fn payloads(&self) -> RawPayloadIterator<'a> {
        self.payloads_with_context(DecodeContext::default())
    }

    /// Iterate over raw payloads with explicit decode limits.
    pub fn payloads_with_context(&self, ctx: DecodeContext) -> RawPayloadIterator<'a> {
        self.payloads.iter_with_context(ctx)
    }

    /// Iterate over raw payloads with explicit decode limits and IKEv2
    /// validation profile.
    pub fn payloads_with_profile(
        &self,
        ctx: DecodeContext,
        profile: Ikev2ValidationProfile,
    ) -> RawPayloadIterator<'a> {
        self.payloads.iter_with_profile(ctx, profile)
    }

    /// Decode a borrowed IKEv2 message with an explicit validation profile.
    ///
    /// Network receive mode follows RFC 7296 receiver behavior for ignored
    /// minor-version and reserved fields. Sender-canonical mode is intended for
    /// generated outbound fixture validation. Both modes enforce the same
    /// hostile-length, payload-chain, count, major-version, and unknown
    /// critical-payload checks.
    pub fn decode_with_profile(
        input: &'a [u8],
        ctx: DecodeContext,
        profile: Ikev2ValidationProfile,
    ) -> DecodeResult<'a, Self> {
        Self::decode_with_profile_and_rejection(input, ctx, profile)
            .map_err(Ikev2MessageRejection::into_decode_error)
    }

    /// Decode a borrowed IKEv2 message while preserving a typed
    /// unknown-critical rejection fact.
    ///
    /// Malformed lengths, truncation, payload-count bounds, and every failure
    /// before a complete offending payload is established remain ordinary
    /// non-reply-capable [`Ikev2MessageRejection::Malformed`] outcomes.
    pub fn decode_with_rejection(
        input: &'a [u8],
        ctx: DecodeContext,
    ) -> Result<(&'a [u8], Self), Ikev2MessageRejection> {
        Self::decode_with_profile_and_rejection(input, ctx, Ikev2ValidationProfile::NetworkReceive)
    }

    /// Decode a borrowed IKEv2 message with an explicit validation profile
    /// while preserving a typed unknown-critical rejection fact.
    pub fn decode_with_profile_and_rejection(
        input: &'a [u8],
        ctx: DecodeContext,
        profile: Ikev2ValidationProfile,
    ) -> Result<(&'a [u8], Self), Ikev2MessageRejection> {
        let spec = spec_ref();
        let (_, header) = decode_header_with_profile(input, ctx, profile)
            .map_err(Ikev2MessageRejection::Malformed)?;
        let msg_end = usize::try_from(header.length).map_err(|_| {
            Ikev2MessageRejection::Malformed(
                DecodeError::new(DecodeErrorCode::LengthOverflow, 24).with_spec_ref(spec.clone()),
            )
        })?;
        if msg_end > ctx.max_message_len {
            return Err(Ikev2MessageRejection::Malformed(
                DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 24).with_spec_ref(spec),
            ));
        }
        if msg_end < HEADER_LEN {
            return Err(Ikev2MessageRejection::Malformed(
                DecodeError::new(
                    DecodeErrorCode::InvalidLength {
                        reason: "IKEv2 length shorter than fixed header",
                    },
                    24,
                )
                .with_spec_ref(spec),
            ));
        }
        if input.len() < msg_end {
            return Err(Ikev2MessageRejection::Malformed(
                DecodeError::new(DecodeErrorCode::Truncated, input.len()).with_spec_ref(spec),
            ));
        }

        let payload_region = &input[HEADER_LEN..msg_end];
        let first_payload = PayloadType::from_u8(header.next_payload);
        match validate_payload_chain_with_rejection_and_profile(
            first_payload,
            payload_region,
            ctx,
            profile,
        ) {
            Ok(()) => {}
            Err(Ikev2PayloadChainRejection::Malformed(error)) => {
                return Err(Ikev2MessageRejection::Malformed(error));
            }
            Err(Ikev2PayloadChainRejection::UnknownCriticalPayload(rejection)) => {
                return Err(Ikev2MessageRejection::UnknownCriticalPayload(
                    Ikev2UnknownCriticalPayloadMessage {
                        header: RejectedMessageHeader::from_header(&header),
                        rejection,
                        has_trailing_bytes: input.len() != msg_end,
                    },
                ));
            }
        }
        let tail = &input[msg_end..];

        Ok((
            tail,
            Self {
                header,
                payloads: PayloadChain::new(first_payload, payload_region),
                tail,
            },
        ))
    }

    fn encoded_lens(&self) -> Result<(usize, u32), EncodeError> {
        let spec = spec_ref();
        let total_len = HEADER_LEN
            .checked_add(self.payloads.bytes().len())
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec.clone()))?;
        let total_len_u32 = u32::try_from(total_len)
            .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec))?;
        Ok((total_len, total_len_u32))
    }

    fn validate_encode_shape(&self) -> Result<(), EncodeError> {
        let spec = spec_ref();
        if self.payloads.is_empty() && self.payloads.first_payload() != PayloadType::NoNext {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "empty payload region requires No Next Payload",
            })
            .with_spec_ref(spec));
        }
        if !self.payloads.is_empty() && self.payloads.first_payload() == PayloadType::NoNext {
            return Err(EncodeError::new(EncodeErrorCode::Structural {
                reason: "payload bytes require a first payload type",
            })
            .with_spec_ref(spec));
        }
        Ok(())
    }
}

impl<'a> BorrowDecode<'a> for Message<'a> {
    /// Decode a borrowed IKEv2 message and validate the unencrypted payload chain.
    ///
    /// @spec IETF RFC7296 3.1, 3.2
    /// @req REQ-IETF-RFC7296-MESSAGE-DECODE-001
    /// @conformance experimental-scaffold
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        Self::decode_with_profile(input, ctx, Ikev2ValidationProfile::NetworkReceive)
    }
}

impl Encode for Message<'_> {
    /// Encode this message, recomputing the IKEv2 Length field.
    ///
    /// @spec IETF RFC7296 3.1
    /// @req REQ-IETF-RFC7296-MESSAGE-ENCODE-001
    /// @conformance experimental-scaffold
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        self.validate_encode_shape()?;
        let (total_len, total_len_u32) = self.encoded_lens()?;
        ctx.check_capacity(total_len)?;

        let mut header = self.header.clone();
        header.length = total_len_u32;
        header.next_payload = self.payloads.first_payload().as_u8();

        dst.reserve(total_len);
        encode_header(&header, dst, ctx)?;
        dst.put_slice(self.payloads.bytes());
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let (total_len, _) = self.encoded_lens()?;
        Ok(total_len)
    }
}

impl ToOwnedPdu for Message<'_> {
    type Owned = OwnedMessage;

    fn to_owned_pdu(&self) -> Self::Owned {
        OwnedMessage {
            header: self.header.clone(),
            raw_payloads: Bytes::copy_from_slice(self.payloads.bytes()),
        }
    }
}

/// Owned IKEv2 message shell.
///
/// @spec IETF RFC7296 3.1, 3.2
/// @req REQ-IETF-RFC7296-MESSAGE-OWNED-001
/// @conformance experimental-scaffold
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedMessage {
    /// Decoded IKEv2 fixed header.
    pub header: Header,
    /// Owned raw payload-chain bytes.
    pub raw_payloads: Bytes,
}

impl OwnedMessage {
    /// Borrow this owned message for encode and payload iteration.
    pub fn as_borrowed(&self) -> Message<'_> {
        Message {
            header: self.header.clone(),
            payloads: PayloadChain::new(
                PayloadType::from_u8(self.header.next_payload),
                &self.raw_payloads,
            ),
            tail: &[],
        }
    }

    /// Iterate over raw payloads with [`DecodeContext::default`].
    pub fn payloads(&self) -> RawPayloadIterator<'_> {
        self.as_borrowed().payloads()
    }
}

impl OwnedDecode for OwnedMessage {
    /// Decode an owned IKEv2 message.
    ///
    /// @spec IETF RFC7296 3.1, 3.2
    /// @req REQ-IETF-RFC7296-MESSAGE-OWNED-DECODE-001
    /// @conformance experimental-scaffold
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (header, raw_len) = {
            let (_, borrowed) = Message::decode(&input, ctx)?;
            (borrowed.header, borrowed.payloads.bytes().len())
        };
        let raw_end = HEADER_LEN
            .checked_add(raw_len)
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::LengthOverflow, HEADER_LEN))?;
        Ok(Self {
            header,
            raw_payloads: input.slice(HEADER_LEN..raw_end),
        })
    }
}

impl Encode for OwnedMessage {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        self.as_borrowed().encode(dst, ctx)
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        self.as_borrowed().wire_len(ctx)
    }
}
