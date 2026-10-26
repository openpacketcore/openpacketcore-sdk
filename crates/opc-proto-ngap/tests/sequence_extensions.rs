use opc_proto_ngap::{decode, encode, Message, PduKind};
use opc_protocol::{DecodeContext, DecodeErrorCode, EncodeContext};

// X.691 11.9.3.4 and 19.7-19.9. One present, unknown BOOLEAN extension.
fn extension_wire(count: usize) -> Vec<u8> {
    wrap_body(&extension_body(count))
}

fn extension_body(count: usize) -> Vec<u8> {
    let mut body = vec![0x80, 0, 1, 0, 21, 0x40, 1, 0x20];
    if count <= 64 {
        let start = body.len();
        body.resize(start + (7 + count).div_ceil(8), 0);
        body[start] = ((count - 1) as u8) << 1;
        let bit = 7 + count - 1;
        body[start + bit / 8] |= 0x80 >> (bit % 8);
    } else {
        body.push(0x80); // Large normally-small marker, aligned for determinant.
        let mut remaining = count;
        while remaining >= 16384 {
            let blocks = (remaining / 16384).min(4);
            let bits = blocks * 16384;
            body.push(0xc0 | blocks as u8);
            let start = body.len();
            body.resize(start + bits / 8, 0);
            remaining -= bits;
            if remaining == 0 {
                *body.last_mut().unwrap() = 1;
            }
        }
        if remaining < 128 {
            body.push(remaining as u8);
        } else {
            body.extend_from_slice(&(0x8000 | remaining as u16).to_be_bytes());
        }
        if remaining > 0 {
            let start = body.len();
            body.resize(start + remaining.div_ceil(8), 0);
            let bit = remaining - 1;
            body[start + bit / 8] |= 0x80 >> (bit % 8);
        }
    }
    body.extend_from_slice(&[1, 0]); // Open-type length 1; BOOLEAN FALSE.
    body
}

fn wrap_body(body: &[u8]) -> Vec<u8> {
    let mut wire = vec![0, 21, 0];
    assert!(body.len() < 16384);
    if body.len() < 128 {
        wire.push(body.len() as u8);
    } else {
        wire.extend_from_slice(&(0x8000 | body.len() as u16).to_be_bytes());
    }
    wire.extend_from_slice(body);
    wire
}

fn check(count: usize) {
    let wire = extension_wire(count);
    check_wire(&wire, DecodeContext::default());
}

fn check_wire(wire: &[u8], ctx: DecodeContext) {
    let pdu = decode(wire, ctx).expect("valid SEQUENCE addition bitmap must decode");
    assert_eq!(&pdu.raw[..], wire);
    let PduKind::Initiating {
        message: Message::NgSetupRequest(request),
        ..
    } = &pdu.kind
    else {
        panic!("expected NGSetupRequest");
    };
    assert_eq!(request.protocol_ies.0.len(), 1);
    assert_eq!(request.protocol_ies.0[0].id, 21);
    assert_eq!(request.protocol_ies.0[0].criticality as u8, 1);
    assert_eq!(request.protocol_ies.0[0].value.as_bytes(), &[0x20]);
    assert_eq!(
        encode(
            &pdu,
            EncodeContext {
                raw_preserving: true,
                ..Default::default()
            }
        )
        .unwrap(),
        wire
    );
    assert_eq!(
        encode(&pdu, EncodeContext::default()).unwrap(),
        [0, 21, 0, 8, 0, 0, 1, 0, 21, 0x40, 1, 0x20]
    );
}

#[test]
fn small_bitmaps() {
    for count in [1, 2, 7, 8, 63, 64] {
        check(count);
    }
}
#[test]
fn large_unfragmented_bitmaps() {
    for count in [65, 127, 128, 16383] {
        check(count);
    }
}

#[test]
fn noncanonical_short_bitmap_lengths_are_rejected() {
    // X.691 11.9.3.6 requires one octet for lengths through 127, including
    // terminal lengths after a 16K fragment. The large-form marker is separate.
    for (count, determinant_offset) in [(65, 9), (127, 9), (16384, 2058), (16385, 2058)] {
        let mut body = extension_body(count);
        check_wire(&wrap_body(&body), DecodeContext::default());
        body.insert(determinant_offset, 0x80);
        assert_invalid_body(&body);
    }
}
#[test]
fn fragmented_bitmap_16384() {
    check(16384);
}
#[test]
fn fragmented_bitmap_16385() {
    check(16385);
}

#[test]
fn fragment_multipliers_and_terminal_lengths_preserve_the_root() {
    // X.691 11.9.3.8: all four fragment sizes, repeated determinants, and
    // empty tails and one-/two-octet terminal lengths. Only the final bit is set.
    for count in [
        32768, 49152, 65536, 65537, 65663, 65664, 81919, 81920, 98304,
    ] {
        check(count);
    }
}

#[test]
fn presence_bits_from_every_fragment_are_counted_before_open_types() {
    let mut body = extension_body(16385);
    body[10] = 0x80; // First addition in the first fragment.
    body[10 + 2047] = 1; // Last addition in the first fragment.

    // The existing terminal bitmap and open type now follow two present bits.
    body.extend_from_slice(&[2, 0xab, 0xcd, 1, 0xef]);
    check_wire(&wrap_body(&body), DecodeContext::default());
    assert_invalid_body(&body[..body.len() - 2]);

    // A complete bitmap may describe only absent additions.
    body[10] = 0;
    body[10 + 2047] = 0;
    body[10 + 2048 + 1] = 0;
    body.truncate(10 + 2048 + 2);
    check_wire(&wrap_body(&body), DecodeContext::default());
}

#[test]
fn fragmented_bitmap_obeys_exact_message_count_and_depth_limits() {
    for count in [16384, 16385, 81920] {
        let wire = extension_wire(count);
        let ctx = DecodeContext {
            max_message_len: wire.len(),
            max_ies: 1,
            max_depth: 5,
            ..DecodeContext::default()
        };
        check_wire(&wire, ctx);
        for (limited, expected) in [
            (
                DecodeContext {
                    max_message_len: wire.len() - 1,
                    ..ctx
                },
                DecodeErrorCode::MessageLengthExceeded,
            ),
            (
                DecodeContext { max_ies: 0, ..ctx },
                DecodeErrorCode::IeCountExceeded,
            ),
            (
                DecodeContext {
                    max_depth: 4,
                    ..ctx
                },
                DecodeErrorCode::DepthExceeded,
            ),
        ] {
            assert_eq!(decode(&wire, limited).unwrap_err().code(), &expected);
        }
    }
}

fn assert_invalid_body(body: &[u8]) {
    assert_eq!(
        decode(&wrap_body(body), DecodeContext::default())
            .unwrap_err()
            .code(),
        &DecodeErrorCode::Structural {
            reason: "ngap open type"
        }
    );
}

#[test]
fn truncated_fragmented_bitmaps_and_open_types_are_rejected() {
    for count in [16384, 16385, 16512] {
        let body = extension_body(count);
        for end in 8..body.len() {
            // Rebuild the outer length so failure exercises the SEQUENCE
            // framing, including the terminal determinant and open type.
            assert_invalid_body(&body[..end]);
        }
    }
}

#[test]
fn malformed_fragment_determinants_padding_and_trailing_values_are_rejected() {
    let body = extension_body(16385);
    for invalid in [0xc0].into_iter().chain(0xc5..=0xff) {
        for offset in [9, 10 + 2048] {
            let mut bad = body.clone();
            bad[offset] = invalid;
            assert_invalid_body(&bad);
        }
    }
    for offset in [8, 10 + 2048 + 1] {
        let mut bad = body.clone();
        bad[offset] |= 1; // Alignment before the determinant or after the bitmap.
        assert_invalid_body(&bad);
    }
    let mut bad = body.clone();
    bad.extend_from_slice(&[1, 0]); // No corresponding presence bit.
    assert_invalid_body(&bad);

    let mut bad = extension_body(16384);
    bad.remove(10 + 2048); // Omit the mandatory zero terminal determinant.
    assert_invalid_body(&bad);

    let mut bad = body[..8].to_vec();
    bad.extend_from_slice(&[0x80, 64]); // Long form requires more than 64 bits.
    bad.extend_from_slice(&[0; 8]);
    assert_invalid_body(&bad);
}
