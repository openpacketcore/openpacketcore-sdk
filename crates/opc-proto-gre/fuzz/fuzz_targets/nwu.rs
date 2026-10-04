#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use opc_proto_gre::{
    DefaultFallbackIntent as Fallback, Direction, FlowAssociation, FlowMapping, NwuGrePacket, Qfi,
    QfiSet, SelectionKind,
};
use opc_protocol::{DecodeContext, DecodeErrorCode, Encode, EncodeContext, ToOwnedPdu};

fuzz_target!(|input: &[u8]| {
    // Bound all work even when a caller supplies an oversized fuzzer seed.
    let data = &input[..input.len().min(4096)];
    for direction in [Direction::Uplink, Direction::Downlink] {
        for max in [0, data.first().copied().unwrap_or(0) as usize, 4096] {
            let ctx = DecodeContext {
                max_message_len: max,
                ..DecodeContext::default()
            };
            match NwuGrePacket::decode(data, direction, ctx) {
                Err(error) => {
                    if data.len() > max {
                        assert_eq!(error.code(), &DecodeErrorCode::MessageLengthExceeded);
                    }
                    // Error strings have only static reasons and fixed offsets.
                    assert!(error.to_string().len() < 100);
                    assert!(format!("{error:?}").len() < 300);
                }
                Ok(packet) => {
                    assert!(data.len() <= max && data.len() > 8);
                    assert_eq!(packet.payload(), &data[8..]);
                    assert_eq!(format!("{packet:?}"), "NwuGrePacket([REDACTED])");
                    assert_eq!(
                        format!("{:?}", packet.to_owned_pdu()),
                        "OwnedNwuGrePacket([REDACTED])"
                    );
                    let mut encoded = BytesMut::new();
                    packet
                        .encode(
                            &mut encoded,
                            EncodeContext {
                                max_message_len: data.len(),
                                ..EncodeContext::default()
                            },
                        )
                        .unwrap();
                    assert_eq!(&encoded[..4], &[0x20, 0, 0, 0]);
                    assert_eq!(encoded.len(), data.len());
                    assert_eq!(
                        NwuGrePacket::decode(&encoded, direction, ctx).unwrap(),
                        packet
                    );
                    for encode_ctx in [
                        EncodeContext {
                            max_message_len: data.len() - 1,
                            ..EncodeContext::default()
                        },
                        EncodeContext {
                            raw_preserving: true,
                            ..EncodeContext::default()
                        },
                    ] {
                        let mut dst = BytesMut::from(&b"prefix"[..]);
                        assert!(packet.encode(&mut dst, encode_ctx).is_err());
                        assert_eq!(dst.as_ref(), b"prefix");
                    }
                }
            }
        }
    }

    let entries: Vec<_> = data
        .chunks_exact(3)
        .take(64)
        .enumerate()
        .map(|(index, row)| {
            FlowAssociation::new(
                index,
                QfiSet::empty()
                    .with(Qfi::new(row[0] % 64).unwrap())
                    .with(Qfi::new(row[1] % 64).unwrap()),
                if row[2] & 1 == 0 {
                    Fallback::Ineligible
                } else {
                    Fallback::Eligible
                },
            )
        })
        .collect();
    let map = FlowMapping::new(&entries, 64).unwrap();
    if !entries.is_empty() {
        assert!(FlowMapping::new(&entries, entries.len() - 1).is_err());
    }
    for value in data.iter().take(64) {
        let value = value % 64;
        let qfi = Qfi::new(value).unwrap();
        let selected = map.select(qfi);
        // Direct comparison with the input tuples, independent of QfiSet.
        let exact: Vec<_> = data
            .chunks_exact(3)
            .take(64)
            .enumerate()
            .filter(|(_, row)| row[0] % 64 == value || row[1] % 64 == value)
            .map(|(index, _)| index)
            .collect();
        let default: Vec<_> = data
            .chunks_exact(3)
            .take(64)
            .enumerate()
            .filter(|(_, row)| row[2] & 1 != 0)
            .map(|(index, _)| index)
            .collect();
        let expected = if exact.is_empty() { &default } else { &exact };
        let kind = if !exact.is_empty() {
            SelectionKind::Exact
        } else if !default.is_empty() {
            SelectionKind::DefaultFallback
        } else {
            SelectionKind::Unmapped
        };
        assert_eq!(selected.kind(), kind);
        assert_eq!(
            selected
                .candidates()
                .map(|entry| *entry.association())
                .collect::<Vec<_>>(),
            *expected
        );
        assert_eq!(format!("{selected:?}"), "FlowSelection([REDACTED])");
        assert_eq!(
            format!("{:?}", selected.candidates()),
            "AssociationCandidates([REDACTED])"
        );
    }
});
