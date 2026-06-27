//! GTPv2-C message shell built on the OpenPacketCore protocol traits.
//!
//! @spec 3GPP TS29274 R18 5.1, 8.2
//! @req REQ-3GPP-TS29274-R18-MESSAGE-001

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, OwnedDecode, SpecRef, ToOwnedPdu,
};

use crate::header::{decode_header, encode_header, Header, MessageType};
use crate::ie::{validate_ie_region, RawIeIterator};

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS29274", "5.1")
}

/// A borrowed GTPv2-C message.
///
/// The raw message shell preserves the IE region byte-for-byte and exposes
/// a lazy raw IE iterator. Typed S2b procedure views are layered in
/// [`crate::s2b`] without removing this forwarding-safe representation.
///
/// @spec 3GPP TS29274 R18 5.1, 8.2
/// @req REQ-3GPP-TS29274-R18-MESSAGE-002
/// @conformance s2b-subset
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// Parsed common header.
    pub header: Header,
    /// Raw IE bytes after the common header and before the declared message
    /// boundary.
    pub raw_ies: &'a [u8],
    /// Bytes beyond the message boundary declared by the header Length field.
    pub tail: &'a [u8],
}

impl<'a> Message<'a> {
    /// Return the typed GTPv2-C message type, with an unknown fallback.
    pub fn message_type(&self) -> MessageType {
        self.header.typed_message_type()
    }

    /// Iterate over the raw IE region with a default decode context.
    pub fn ies(&self) -> RawIeIterator<'a> {
        self.ies_with_context(DecodeContext::default())
    }

    /// Iterate over the raw IE region with explicit decode limits.
    pub fn ies_with_context(&self, ctx: DecodeContext) -> RawIeIterator<'a> {
        RawIeIterator::new(self.raw_ies, ctx)
    }

    fn encoded_lens(&self) -> Result<(usize, u16), EncodeError> {
        let spec = spec_ref();
        let total_len = self
            .header
            .wire_len()
            .checked_add(self.raw_ies.len())
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec.clone()))?;
        let body_len = total_len.checked_sub(4).ok_or_else(|| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "message length underflow",
            })
            .with_spec_ref(spec.clone())
        })?;
        let body_len_u16 = u16::try_from(body_len)
            .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec))?;
        Ok((total_len, body_len_u16))
    }
}

impl<'a> BorrowDecode<'a> for Message<'a> {
    /// Decode a borrowed GTPv2-C message and validate its raw IE region.
    ///
    /// @spec 3GPP TS29274 R18 5.1, 8.2
    /// @req REQ-3GPP-TS29274-R18-MESSAGE-003
    /// @conformance s2b-subset
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let spec = spec_ref();
        let (_, header) = decode_header(input, ctx)?;
        let msg_end = 4usize.checked_add(header.length as usize).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, 2).with_spec_ref(spec.clone())
        })?;

        if msg_end > ctx.max_message_len {
            return Err(
                DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 2).with_spec_ref(spec)
            );
        }
        if input.len() < msg_end {
            return Err(
                DecodeError::new(DecodeErrorCode::Truncated, input.len()).with_spec_ref(spec)
            );
        }
        if msg_end < header.wire_len() {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "message length shorter than common header",
                },
                2,
            )
            .with_spec_ref(spec));
        }

        let raw_ies = &input[header.wire_len()..msg_end];
        validate_ie_region(raw_ies, ctx)?;
        let tail = &input[msg_end..];

        Ok((
            tail,
            Self {
                header,
                raw_ies,
                tail,
            },
        ))
    }
}

impl Encode for Message<'_> {
    /// Encode this message, recomputing the GTPv2-C Length field.
    ///
    /// @spec 3GPP TS29274 R18 5.1
    /// @req REQ-3GPP-TS29274-R18-MESSAGE-004
    /// @conformance s2b-subset
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let (total_len, body_len) = self.encoded_lens()?;
        ctx.check_capacity(total_len)?;
        let mut header = self.header.clone();
        header.length = body_len;

        dst.reserve(total_len);
        encode_header(&header, dst, ctx)?;
        dst.put_slice(self.raw_ies);
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
            raw_ies: Bytes::copy_from_slice(self.raw_ies),
        }
    }
}

/// An owned GTPv2-C message shell.
///
/// @spec 3GPP TS29274 R18 5.1, 8.2
/// @req REQ-3GPP-TS29274-R18-MESSAGE-005
/// @conformance s2b-subset
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedMessage {
    /// Parsed common header.
    pub header: Header,
    /// Owned raw IE bytes after the common header.
    pub raw_ies: Bytes,
}

impl OwnedMessage {
    /// Return the typed GTPv2-C message type, with an unknown fallback.
    pub fn message_type(&self) -> MessageType {
        self.header.typed_message_type()
    }

    /// Borrow this owned message for encode and IE iteration.
    pub fn as_borrowed(&self) -> Message<'_> {
        Message {
            header: self.header.clone(),
            raw_ies: &self.raw_ies,
            tail: &[],
        }
    }

    /// Iterate over the raw IE region with a default decode context.
    pub fn ies(&self) -> RawIeIterator<'_> {
        self.as_borrowed().ies()
    }
}

impl OwnedDecode for OwnedMessage {
    /// Decode an owned GTPv2-C message.
    ///
    /// @spec 3GPP TS29274 R18 5.1, 8.2
    /// @req REQ-3GPP-TS29274-R18-MESSAGE-006
    /// @conformance s2b-subset
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, borrowed) = Message::decode(&input, ctx)?;
        let raw_start = borrowed.header.wire_len();
        let raw_end = raw_start
            .checked_add(borrowed.raw_ies.len())
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::LengthOverflow, raw_start))?;
        Ok(Self {
            header: borrowed.header,
            raw_ies: input.slice(raw_start..raw_end),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s2b;
    use opc_protocol::{OwnedDecode, ValidationLevel};

    #[test]
    fn decodes_and_roundtrips_echo_request() {
        let bytes = [0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
        let decoded = Message::decode(&bytes, DecodeContext::default());
        let (tail, message) = match decoded {
            Ok(value) => value,
            Err(error) => panic!("decode failed: {error:?}"),
        };
        assert!(tail.is_empty());
        assert_eq!(message.header.message_type, 1);
        assert!(message.raw_ies.is_empty());

        let mut encoded = BytesMut::new();
        let ctx = EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        };
        let result = message.encode(&mut encoded, ctx);
        assert!(result.is_ok());
        assert_eq!(encoded.as_ref(), bytes.as_slice());
    }

    #[test]
    fn decodes_create_session_shell_with_raw_ie() {
        let bytes = [
            0x48,
            s2b::CREATE_SESSION_REQUEST,
            0x00,
            0x0d,
            0x01,
            0x02,
            0x03,
            0x04,
            0x00,
            0x00,
            0x02,
            0x00,
            0xff,
            0x00,
            0x01,
            0x00,
            0xaa,
        ];
        let decoded = Message::decode(&bytes, DecodeContext::default());
        let (_, message) = match decoded {
            Ok(value) => value,
            Err(error) => panic!("decode failed: {error:?}"),
        };
        assert_eq!(message.header.teid, Some(0x0102_0304));
        let mut count = 0usize;
        for item in message.ies() {
            let ie = match item {
                Ok(ie) => ie,
                Err(error) => panic!("IE decode failed: {error:?}"),
            };
            count += 1;
            assert_eq!(ie.ie_type, 0xff);
            assert_eq!(ie.value, [0xaa]);
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn owned_decode_keeps_raw_ie_slice() {
        let bytes = Bytes::from_static(&[
            0x48, 0x20, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02, 0x00, 0xff, 0x00,
            0x01, 0x00, 0xaa,
        ]);
        let decoded = OwnedMessage::decode_owned(bytes, DecodeContext::default());
        let message = match decoded {
            Ok(message) => message,
            Err(error) => panic!("decode failed: {error:?}"),
        };
        assert_eq!(message.raw_ies.as_ref(), &[0xff, 0x00, 0x01, 0x00, 0xaa]);
    }

    #[test]
    fn strict_decode_rejects_ie_spare_bits() {
        let bytes = [
            0x48, 0x20, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02, 0x00, 0xff, 0x00,
            0x01, 0xf0, 0xaa,
        ];
        let ctx = DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        };
        let decoded = Message::decode(&bytes, ctx);
        assert!(decoded.is_err());
    }
}
