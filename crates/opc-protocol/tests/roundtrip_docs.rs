//! Tests documenting canonical vs raw-preserving round-trip behavior.
//!
//! RFC 005 §12 defines three round-trip properties:
//! 1. Canonical: `decode(encode(model)) == model`
//! 2. Raw-Preserving: `encode_raw_preserving(decode_raw_preserving(input)) == input`
//! 3. Reject Stability: rejected inputs never panic, hang, or over-allocate.

use bytes::BytesMut;
use opc_protocol::{BorrowDecode, DecodeContext, DecodeResult, Encode, EncodeContext, EncodeError};

/// A tiny canonical PDU for demonstration.
#[derive(Debug, Clone, PartialEq)]
struct CanonicalPdu {
    value: u16,
}

impl<'a> BorrowDecode<'a> for CanonicalPdu {
    fn decode(input: &'a [u8], _ctx: DecodeContext) -> DecodeResult<'a, Self> {
        if input.len() < 2 {
            return Err(opc_protocol::DecodeError::new(
                opc_protocol::DecodeErrorCode::Truncated,
                0,
            ));
        }
        let value = u16::from_be_bytes([input[0], input[1]]);
        Ok((&input[2..], Self { value }))
    }
}

impl Encode for CanonicalPdu {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;
        dst.extend_from_slice(&self.value.to_be_bytes());
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        Ok(2)
    }
}

/// A raw-preserving PDU that stores the original bytes.
#[derive(Debug, Clone, PartialEq)]
struct RawPreservingPdu {
    raw: Vec<u8>,
}

impl<'a> BorrowDecode<'a> for RawPreservingPdu {
    fn decode(input: &'a [u8], _ctx: DecodeContext) -> DecodeResult<'a, Self> {
        // In raw-preserving mode we might accept the entire buffer as-is,
        // including unknown trailing bytes or padding.
        Ok((
            &[],
            Self {
                raw: input.to_vec(),
            },
        ))
    }
}

impl Encode for RawPreservingPdu {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;
        dst.extend_from_slice(&self.raw);
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        Ok(self.raw.len())
    }
}

#[test]
fn canonical_round_trip_decode_encode_model() {
    // Property: decode(encode(model)) == model
    let model = CanonicalPdu { value: 0xABCD };

    let mut buf = BytesMut::new();
    model.encode(&mut buf, EncodeContext::default()).unwrap();

    let (rest, decoded) = CanonicalPdu::decode(&buf, DecodeContext::default()).unwrap();
    assert!(rest.is_empty());
    assert_eq!(decoded, model);
}

#[test]
fn raw_preserving_round_trip_reproduces_input() {
    // Property: encode_raw_preserving(decode_raw_preserving(input)) == input
    let original = vec![0x01, 0x02, 0x03, 0xFF, 0xFF]; // includes unknown/padding

    let (_, decoded) = RawPreservingPdu::decode(&original, DecodeContext::default()).unwrap();
    assert_eq!(decoded.raw, original);

    let mut buf = BytesMut::new();
    decoded
        .encode(
            &mut buf,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        )
        .unwrap();

    assert_eq!(&buf[..], &original[..]);
}

#[test]
fn encode_context_raw_preserving_flag_is_readable() {
    let canonical = EncodeContext::default();
    assert!(!canonical.raw_preserving);

    let raw = EncodeContext {
        raw_preserving: true,
        ..EncodeContext::default()
    };
    assert!(raw.raw_preserving);
}

#[test]
fn reject_stability_no_panic_on_empty_input() {
    // Property: rejected inputs return structured errors, never panic.
    let empty: &[u8] = &[];
    let result = CanonicalPdu::decode(empty, DecodeContext::default());
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(matches!(
        err.code(),
        opc_protocol::DecodeErrorCode::Truncated
    ));
}
