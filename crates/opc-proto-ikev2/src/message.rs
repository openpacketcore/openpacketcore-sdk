//! IKEv2 raw message shell built on the OpenPacketCore protocol traits.
//!
//! @spec IETF RFC7296 3.1, 3.2
//! @req REQ-IETF-RFC7296-MESSAGE-001

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, OwnedDecode, SpecRef, ToOwnedPdu,
};

use crate::{
    header::{decode_header_with_profile, encode_header, Header, HEADER_LEN},
    payload::{validate_payload_chain_with_profile, PayloadChain, PayloadType, RawPayloadIterator},
    validation::Ikev2ValidationProfile,
};

fn spec_ref() -> SpecRef {
    SpecRef::new("ietf", "RFC7296", "3.1")
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
        let spec = spec_ref();
        let (_, header) = decode_header_with_profile(input, ctx, profile)?;
        let msg_end = usize::try_from(header.length).map_err(|_| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, 24).with_spec_ref(spec.clone())
        })?;
        if msg_end > ctx.max_message_len {
            return Err(
                DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 24).with_spec_ref(spec)
            );
        }
        if msg_end < HEADER_LEN {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "IKEv2 length shorter than fixed header",
                },
                24,
            )
            .with_spec_ref(spec));
        }
        if input.len() < msg_end {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, input.len()).with_spec_ref(spec)
            );
        }

        let payload_region = &input[HEADER_LEN..msg_end];
        let first_payload = PayloadType::from_u8(header.next_payload);
        validate_payload_chain_with_profile(first_payload, payload_region, ctx, profile)?;
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
