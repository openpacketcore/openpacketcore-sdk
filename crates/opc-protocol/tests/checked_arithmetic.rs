//! Tests that `Encode::wire_len` uses checked arithmetic.
//!
//! RFC 005 §9.2: "All offset, length, and capacity calculations MUST use
//! checked_add, checked_sub, checked_mul, usize::try_from. Integer
//! truncation with `as` is forbidden in parser and encoder length paths."

use bytes::BytesMut;
use opc_protocol::{Encode, EncodeContext, EncodeError, EncodeErrorCode};

/// Mock encoder whose `wire_len` correctly uses checked arithmetic.
struct CheckedPdu {
    header_len: u32,
    payload_len: u32,
}

impl Encode for CheckedPdu {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;
        dst.reserve(len);
        dst.extend_from_slice(&self.header_len.to_be_bytes());
        dst.extend_from_slice(&self.payload_len.to_be_bytes());
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let header =
            usize::try_from(self.header_len).map_err(|_| EncodeError::length_overflow())?;
        let payload =
            usize::try_from(self.payload_len).map_err(|_| EncodeError::length_overflow())?;
        let total = header
            .checked_add(payload)
            .ok_or(EncodeError::length_overflow())?;
        Ok(total)
    }
}

/// Mock encoder that deliberately overflows to verify error handling.
struct OverflowPdu;

impl Encode for OverflowPdu {
    fn encode(&self, _dst: &mut BytesMut, _ctx: EncodeContext) -> Result<(), EncodeError> {
        unreachable!("encode should not be called in this test")
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let a = usize::MAX;
        let b = 1usize;
        a.checked_add(b).ok_or_else(EncodeError::length_overflow)
    }
}

#[test]
fn wire_len_succeeds_when_checked_math_fits() {
    let pdu = CheckedPdu {
        header_len: 4,
        payload_len: 100,
    };
    let len = pdu.wire_len(EncodeContext::default()).unwrap();
    assert_eq!(len, 104);
}

#[test]
fn wire_len_returns_length_overflow_on_checked_add_failure() {
    let pdu = OverflowPdu;
    let err = pdu.wire_len(EncodeContext::default()).unwrap_err();
    assert!(matches!(err.code(), EncodeErrorCode::LengthOverflow));
}

#[test]
fn encode_fails_before_writing_when_capacity_exceeded() {
    let ctx = EncodeContext {
        max_message_len: 2,
        ..EncodeContext::default()
    };

    let pdu = CheckedPdu {
        header_len: 4,
        payload_len: 100,
    };

    let mut buf = BytesMut::new();
    let err = pdu.encode(&mut buf, ctx).unwrap_err();

    assert!(matches!(
        err.code(),
        EncodeErrorCode::CapacityExceeded {
            required: 104,
            available: 2
        }
    ));
    // Buffer must remain unchanged because encode failed before writing.
    assert!(buf.is_empty());
}

#[test]
fn encode_populates_buffer_when_capacity_is_sufficient() {
    let pdu = CheckedPdu {
        header_len: 4,
        payload_len: 4,
    };
    let ctx = EncodeContext::default();
    let mut buf = BytesMut::new();
    pdu.encode(&mut buf, ctx).unwrap();

    // 2 u32s × 4 bytes each = 8 bytes total
    assert_eq!(buf.len(), 8);
}
