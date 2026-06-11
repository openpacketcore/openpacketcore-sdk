//! Compile-time lifetime fixture for BorrowDecode.
//!
//! This test proves that `BorrowDecode<'a>` correctly ties the decoded view
//! to the input buffer lifetime. The borrow checker prevents the view from
//! outliving the buffer.

use opc_protocol::{BorrowDecode, DecodeContext, DecodeResult};

/// A minimal borrowed PDU to exercise the lifetime contract.
#[derive(Debug, PartialEq)]
struct BorrowedPdu<'a> {
    data: &'a [u8],
}

impl<'a> BorrowDecode<'a> for BorrowedPdu<'a> {
    fn decode(input: &'a [u8], _ctx: DecodeContext) -> DecodeResult<'a, Self> {
        Ok((&[], Self { data: input }))
    }
}

/// Demonstrates that a borrowed view lives exactly as long as its input.
#[test]
fn borrowed_view_tied_to_input_lifetime() {
    let buffer = vec![0x01, 0x02, 0x03];
    let (rest, pdu) = BorrowedPdu::decode(&buffer, DecodeContext::default()).unwrap();

    assert!(rest.is_empty());
    assert_eq!(pdu.data, &[0x01, 0x02, 0x03]);

    // The borrow checker ensures `pdu` cannot outlive `buffer`.
    // If `BorrowedPdu` incorrectly used 'static or leaked the lifetime,
    // this test file would fail to compile.
}

/// Proves that multiple borrowed views from the same buffer have compatible
/// lifetimes.
#[test]
fn multiple_borrowed_views_from_same_buffer() {
    let buffer: Vec<u8> = (0..16).collect();

    let (tail, first) = BorrowedPdu::decode(&buffer[..4], DecodeContext::default()).unwrap();
    assert!(tail.is_empty());
    assert_eq!(first.data, &[0, 1, 2, 3]);

    let (tail, second) = BorrowedPdu::decode(&buffer[4..8], DecodeContext::default()).unwrap();
    assert!(tail.is_empty());
    assert_eq!(second.data, &[4, 5, 6, 7]);

    // Both views are valid as long as `buffer` is alive.
    assert_eq!(first.data.len() + second.data.len(), 8);
}
