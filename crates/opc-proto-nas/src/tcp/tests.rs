#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn no_payload_allocation_precedes_a_valid_complete_prefix() {
    for prefix in [&[0, 0][..], &[1, 1][..], &[255, 255][..]] {
        let mut decoder = NasTcpDecoder::new(NasTcpLimit::new(256).unwrap());
        let mut first = &prefix[..1];
        assert!(decoder.feed(&mut first).unwrap().is_none());
        assert_eq!(decoder.payload.capacity(), 0);
        let mut second = &prefix[1..];
        assert!(decoder.feed(&mut second).is_err());
        assert_eq!(decoder.payload.capacity(), 0);
        assert_eq!(decoder.prefix_len, 0);
        assert_eq!(decoder.expected, 0);
    }
}

#[test]
fn coalesced_input_allocates_only_the_current_declared_body() {
    let mut input = vec![0, 3, 0x7f, 0xff, 0x41];
    input.resize(1024 * 1024, 0x5a);
    let mut tail = input.as_slice();
    let mut decoder = NasTcpDecoder::new(NasTcpLimit::new(256).unwrap());
    let frame = decoder.feed(&mut tail).unwrap().unwrap();
    assert_eq!(frame.payload.len(), 3);
    assert_eq!(frame.payload.capacity(), 3);
    assert_eq!(tail.len(), input.len() - 5);
    assert_eq!(decoder.payload.capacity(), 0);
    assert_eq!(decoder.prefix_len, 0);
    decoder.finish().unwrap();
}

#[test]
fn incomplete_bodies_reserve_exactly_the_validated_limit() {
    for length in [1_u16, 255, 256, 257, u16::MAX] {
        let mut decoder = NasTcpDecoder::new(NasTcpLimit::new(usize::from(length)).unwrap());
        let bytes = length.to_be_bytes();
        let mut prefix = bytes.as_slice();
        assert!(decoder.feed(&mut prefix).unwrap().is_none());
        assert!(decoder.payload.is_empty());
        assert_eq!(decoder.payload.capacity(), usize::from(length));
        assert_eq!(decoder.finish(), Err(NasTcpError::Truncated));
        assert_eq!(decoder.payload.capacity(), 0);
        assert_eq!(decoder.prefix_len, 0);
        assert_eq!(decoder.expected, 0);
    }
}

#[test]
fn drop_releases_only_its_decoder_and_new_stream_has_no_stale_prefix() {
    let limit = NasTcpLimit::new(256).unwrap();
    let mut decoder = NasTcpDecoder::new(limit);
    let mut partial = &[0, 5, 0x7e][..];
    assert!(decoder.feed(&mut partial).unwrap().is_none());
    assert_eq!(decoder.payload.len(), 1);
    drop(decoder);
    let mut fresh = NasTcpDecoder::new(limit);
    let mut input = &[0, 1, 0xff][..];
    assert!(fresh.feed(&mut input).unwrap().unwrap().payload() == [0xff]);
    fresh.finish().unwrap();
}
