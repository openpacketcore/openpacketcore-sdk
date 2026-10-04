//! Synthetic RFC 9260 DATA chunks exercise the public decoder and N2 boundary.

use bytes::Bytes;
use opc_sctp::n2::{N2Error, N2Inbound, UnprotectedN2Profile};
use opc_sctp::{
    DataChunk, DataChunkError, DataChunkFlags, DeliveryOrder, InboundMessage,
    PayloadProtocolIdentifier,
};

// Independently laid out network-order fields, five user octets (including a
// zero), and three alignment octets. I/B/E are set; U is clear.
const DATA: [u8; 24] = [
    0, 0x0b, 0, 21, 0x12, 0x34, 0x56, 0x78, 0x13, 0x57, 0x24, 0x68, 0x01, 0x23, 0x45, 0x67, 0xde,
    0xad, 0, 0xbe, 0xef, 0, 0, 0,
];

fn wire_with_payload(payload: &[u8]) -> Vec<u8> {
    let mut wire = DATA[..16].to_vec();
    let length = u16::try_from(16 + payload.len()).expect("synthetic DATA length");
    wire[2..4].copy_from_slice(&length.to_be_bytes());
    wire.extend_from_slice(payload);
    wire.resize(wire.len().next_multiple_of(4), 0);
    wire
}

#[test]
fn decodes_network_order_fields_and_borrows_only_user_data() {
    let wire = DATA;
    let chunk = DataChunk::decode(&wire).expect("DATA");
    assert_eq!(
        chunk.flags(),
        DataChunkFlags {
            immediate_sack: true,
            unordered: false,
            beginning: true,
            ending: true,
        }
    );
    assert_eq!(chunk.tsn(), 0x1234_5678);
    assert_eq!(chunk.stream_id(), 0x1357);
    assert_eq!(chunk.stream_sequence_number(), 0x2468);
    assert_eq!(chunk.ppid(), PayloadProtocolIdentifier::new(0x0123_4567));
    assert!(chunk.user_data() == &DATA[16..21], "user data changed");
    assert!(std::ptr::eq(
        chunk.user_data().as_ptr(),
        wire[16..].as_ptr()
    ));
}

#[test]
fn all_flag_combinations_preserve_iube_and_ignore_reserved_bits() {
    for flags in 0..=u8::MAX {
        let mut wire = DATA;
        wire[1] = flags;
        let chunk = DataChunk::decode(&wire).expect("reserved flags are ignored");
        assert_eq!(
            chunk.flags(),
            DataChunkFlags {
                immediate_sack: flags & 8 != 0,
                unordered: flags & 4 != 0,
                beginning: flags & 2 != 0,
                ending: flags & 1 != 0,
            }
        );
        let result = chunk.into_inbound_message(-17);
        if flags & 3 == 3 {
            let message = result.expect("complete record");
            let expected_order = if flags & 4 != 0 {
                DeliveryOrder::Unordered
            } else {
                DeliveryOrder::Ordered
            };
            assert_eq!(message.order, expected_order);
        } else {
            assert_eq!(result, Err(DataChunkError::Fragmented));
        }
    }
}

#[test]
fn mapping_owns_payload_and_preserves_only_record_metadata() {
    let mut wire = DATA;
    let message = DataChunk::decode(&wire)
        .expect("DATA")
        .into_inbound_message(-17)
        .expect("complete record");
    assert!(message.payload.as_ref() == &wire[16..21], "payload changed");
    assert!(!std::ptr::eq(message.payload.as_ptr(), wire[16..].as_ptr()));
    assert_eq!(message.stream_id, 0x1357);
    assert_eq!(message.ppid.get(), 0x0123_4567);
    assert_eq!(message.order, DeliveryOrder::Ordered);
    assert_eq!(message.assoc_id, -17);
    assert!(!message.notification);
    assert!(message.event.is_none());
    assert!(!message.truncated);
    assert!(!message.control_truncated);
    wire[16..21].fill(0);
    assert!(
        message.payload.as_ref() == &DATA[16..21],
        "copy was borrowed"
    );
}

#[test]
fn rejects_every_non_data_type() {
    for chunk_type in 1..=u8::MAX {
        let mut wire = DATA;
        wire[0] = chunk_type;
        assert_eq!(DataChunk::decode(&wire), Err(DataChunkError::WrongType));
    }
}

#[test]
fn rejects_short_headers_impossible_lengths_and_missing_user_data() {
    for end in 0..16 {
        assert_eq!(
            DataChunk::decode(&DATA[..end]),
            Err(DataChunkError::ShortHeader)
        );
    }
    for length in 0_u16..16 {
        let mut wire = DATA;
        wire[2..4].copy_from_slice(&length.to_be_bytes());
        assert_eq!(DataChunk::decode(&wire), Err(DataChunkError::InvalidLength));
    }
    let mut empty = DATA[..16].to_vec();
    empty[2..4].copy_from_slice(&16_u16.to_be_bytes());
    assert_eq!(DataChunk::decode(&empty), Err(DataChunkError::NoUserData));
    empty.extend_from_slice(&[0; 4]);
    assert_eq!(DataChunk::decode(&empty), Err(DataChunkError::NoUserData));
}

#[test]
fn rejects_truncated_data_and_missing_alignment_octets() {
    for end in 16..21 {
        assert_eq!(
            DataChunk::decode(&DATA[..end]),
            Err(DataChunkError::Truncated)
        );
    }
    for end in 21..24 {
        assert_eq!(
            DataChunk::decode(&DATA[..end]),
            Err(DataChunkError::InvalidPadding)
        );
    }
    let mut wire = DATA;
    wire[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(DataChunk::decode(&wire), Err(DataChunkError::Truncated));
}

#[test]
fn padding_is_exact_zero_alignment_and_never_payload_or_another_chunk() {
    for user_len in 1..=8 {
        let wire = wire_with_payload(&[0; 8][..user_len]);
        let declared = 16 + user_len;
        let chunk = DataChunk::decode(&wire).expect("zero payload is valid");
        assert_eq!(chunk.user_data().len(), user_len);
        for end in declared..wire.len() {
            assert_eq!(
                DataChunk::decode(&wire[..end]),
                Err(DataChunkError::InvalidPadding)
            );
        }
        for padding_index in declared..wire.len() {
            let mut nonzero = wire.clone();
            nonzero[padding_index] = 1;
            assert_eq!(
                DataChunk::decode(&nonzero),
                Err(DataChunkError::InvalidPadding)
            );
        }
        for extra in 1..=4 {
            let mut trailing = wire.clone();
            trailing.resize(wire.len() + extra, 0);
            assert_eq!(
                DataChunk::decode(&trailing),
                Err(DataChunkError::TrailingBytes)
            );
        }
        let mut bundled = wire;
        bundled.extend_from_slice(&DATA);
        assert_eq!(
            DataChunk::decode(&bundled),
            Err(DataChunkError::TrailingBytes)
        );
    }
}

#[test]
fn maximum_wire_length_includes_padding_without_u16_overflow() {
    let wire = wire_with_payload(&vec![0x5a; usize::from(u16::MAX) - 16]);
    assert_eq!(wire.len(), 65_536);
    let chunk = DataChunk::decode(&wire).expect("maximum DATA length");
    assert_eq!(chunk.user_data().len(), 65_519);
    assert!(chunk.user_data().iter().all(|octet| *octet == 0x5a));
}

#[test]
fn decoding_and_fragment_refusal_allocate_nothing() {
    let mut wrong_type = DATA;
    wrong_type[0] = 1;
    let mut invalid_length = DATA;
    invalid_length[3] = 15;
    let mut no_user_data = DATA;
    no_user_data[3] = 16;
    let mut nonzero_padding = DATA;
    nonzero_padding[23] = 1;
    let mut fragment = DATA;
    fragment[1] = 0;
    let trailing = [DATA.as_slice(), &[0]].concat();
    let cases: &[(&[u8], DataChunkError)] = &[
        (&[], DataChunkError::ShortHeader),
        (&wrong_type, DataChunkError::WrongType),
        (&invalid_length, DataChunkError::InvalidLength),
        (&no_user_data, DataChunkError::NoUserData),
        (&DATA[..20], DataChunkError::Truncated),
        (&DATA[..21], DataChunkError::InvalidPadding),
        (&nonzero_padding, DataChunkError::InvalidPadding),
        (&trailing, DataChunkError::TrailingBytes),
    ];
    let allocations = allocation_counter::measure(|| {
        let chunk = DataChunk::decode(std::hint::black_box(&DATA)).expect("DATA");
        std::hint::black_box(chunk);
        for (wire, expected) in cases {
            assert_eq!(
                DataChunk::decode(std::hint::black_box(wire)),
                Err(*expected)
            );
        }
        assert_eq!(
            DataChunk::decode(std::hint::black_box(&fragment))
                .expect("fragment")
                .into_inbound_message(0),
            Err(DataChunkError::Fragmented)
        );
    });
    assert_eq!(allocations.count_total, 0);
    assert_eq!(allocations.bytes_total, 0);
}

#[test]
fn data_chunk_and_message_debug_and_errors_never_render_user_data() {
    let payload = b"SYNTHETIC-PAYLOAD-MARKER!";
    let mut wire = wire_with_payload(payload);
    assert!(wire.len() > 16 + payload.len(), "padding must be present");
    let chunk = DataChunk::decode(&wire).expect("DATA");
    assert_eq!(format!("{chunk:?}"), "DataChunk { .. }");
    assert_eq!(format!("{chunk:#?}"), "DataChunk { .. }");
    let message = chunk.into_inbound_message(0).expect("complete record");
    for debug in [format!("{message:?}"), format!("{message:#?}")] {
        assert!(!debug.contains("SYNTHETIC-PAYLOAD-MARKER"));
        assert!(!debug.contains("83, 89, 78"));
        assert!(!debug.contains("53594e"));
    }
    let last = wire.len() - 1;
    wire[last] = 1;
    let error = DataChunk::decode(&wire).expect_err("padding");
    assert_eq!(format!("{error:?}"), "InvalidPadding");
    assert_eq!(error.to_string(), "sctp_data_chunk_invalid_padding");
}

#[test]
fn wire_and_kernel_metadata_use_identical_n2_admission() {
    let profile = UnprotectedN2Profile::new(3).expect("bound");
    for (flags, ppid, payload, expected) in [
        (3, 60, b"nas".as_slice(), None),
        (7, 60, b"nas".as_slice(), Some(N2Error::UnorderedData)),
        (3, 66, b"nas".as_slice(), Some(N2Error::WrongPpid)),
        (
            3,
            60_u32.swap_bytes(),
            b"nas".as_slice(),
            Some(N2Error::WrongPpid),
        ),
        (3, 60, b"over".as_slice(), Some(N2Error::MessageTooLarge)),
    ] {
        let mut wire = wire_with_payload(payload);
        wire[1] = flags;
        wire[12..16].copy_from_slice(&ppid.to_be_bytes());
        let decoded = DataChunk::decode(&wire)
            .expect("DATA")
            .into_inbound_message(41)
            .expect("complete record");
        let kernel = InboundMessage {
            payload: Bytes::copy_from_slice(payload),
            stream_id: 0x1357,
            ppid: PayloadProtocolIdentifier::new(ppid),
            order: if flags & 4 != 0 {
                DeliveryOrder::Unordered
            } else {
                DeliveryOrder::Ordered
            },
            assoc_id: 41,
            notification: false,
            event: None,
            truncated: false,
            control_truncated: false,
        };
        assert_eq!(decoded, kernel);
        for message in [decoded, kernel] {
            match (profile.admit(message), expected) {
                (Ok(N2Inbound::Payload(admitted)), None) => {
                    assert!(admitted.payload().as_ref() == payload, "payload changed");
                    assert_eq!(admitted.stream_id(), 0x1357);
                    assert_eq!(admitted.association_id(), 41);
                }
                (Err(actual), Some(expected)) => assert_eq!(actual, expected),
                _ => panic!("N2 admission diverged"),
            }
        }
    }
}
