use bytes::{Bytes, BytesMut};
use opc_proto_gre::{
    DefaultFallbackIntent as Fallback, Direction, DirectionalQos, FlowAssociation, FlowMapping,
    NwuGrePacket, OwnedNwuGrePacket, Qfi, QfiSet, Rqi, SelectionKind,
};
use opc_protocol::{
    DecodeContext, DecodeErrorCode, Encode, EncodeContext, ProtocolVersion, ToOwnedPdu,
    ValidationLevel,
};

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return vec![];
    }
    let (pairs, tail) = s.as_bytes().as_chunks::<2>();
    assert!(tail.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex"))
        .collect()
}

fn qfi(value: u8) -> Qfi {
    Qfi::new(value).expect("test QFI")
}

fn uplink(value: u8) -> DirectionalQos {
    DirectionalQos::Uplink { qfi: qfi(value) }
}

#[test]
fn independent_directional_golden_packets_and_constructors() {
    let mut admitted = 0;
    let mut rejected = 0;
    for line in include_str!("fixtures/nwu.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let row: Vec<_> = line.split('\t').collect();
        assert_eq!(row.len(), 5);
        let direction = if row[0] == "U" {
            Direction::Uplink
        } else {
            Direction::Downlink
        };
        let input = hex(row[4]);
        let decoded = NwuGrePacket::decode(&input, direction, DecodeContext::default());
        if row[3] == "-" {
            assert!(decoded.is_err());
            assert!(OwnedNwuGrePacket::decode(
                Bytes::from(input),
                direction,
                DecodeContext::default()
            )
            .is_err());
            rejected += 1;
            continue;
        }
        let expected = hex(row[3]);
        let value: u8 = row[1].parse().expect("qfi");
        let qos = match direction {
            Direction::Uplink => uplink(value),
            Direction::Downlink => DirectionalQos::Downlink {
                qfi: qfi(value),
                rqi: if row[2] == "1" {
                    Rqi::Indicated
                } else {
                    Rqi::NotIndicated
                },
            },
        };
        let packet = decoded.expect("reference admission");
        assert_eq!(packet.qos(), qos);
        assert_eq!(packet.qos().direction(), direction);
        assert_eq!(packet.payload(), &input[8..]);
        let constructor =
            NwuGrePacket::new(qos, &expected[8..], EncodeContext::default()).expect("construct");
        let owned = OwnedNwuGrePacket::decode(
            Bytes::copy_from_slice(&input),
            direction,
            DecodeContext::default(),
        )
        .expect("owned");
        assert_eq!(packet, owned.as_borrowed());
        assert_eq!(packet.to_owned_pdu(), owned);
        let constructed_owned = OwnedNwuGrePacket::new(
            qos,
            Bytes::copy_from_slice(&expected[8..]),
            EncodeContext::default(),
        )
        .expect("owned construct");
        for view in [
            packet,
            constructor,
            owned.as_borrowed(),
            constructed_owned.as_borrowed(),
        ] {
            let mut out = BytesMut::new();
            view.encode(&mut out, EncodeContext::default())
                .expect("encode");
            assert_eq!(out.as_ref(), expected);
            assert_eq!(
                view.wire_len(EncodeContext::default()).expect("len"),
                expected.len()
            );
        }
        admitted += 1;
    }
    assert_eq!((admitted, rejected), (1113, 90));
}

#[test]
fn every_flags_word_obeys_rfc_bit_positions() {
    // Independent set construction: do not copy the production mask.
    let legal: Vec<u16> = (0..128u16)
        .map(|choice| {
            let mut flags = 1 << (15 - 2); // K, RFC bit 2
            for bit in 0..7 {
                if choice & (1 << bit) != 0 {
                    flags |= 1 << (15 - (6 + bit));
                }
            }
            flags
        })
        .collect();
    let mut count = 0;
    for flags in 0..=u16::MAX {
        let [first, second] = flags.to_be_bytes();
        let input = [first, second, 0, 0, 63, 0, 0, 0, 0x5a];
        for direction in [Direction::Uplink, Direction::Downlink] {
            let result = NwuGrePacket::decode(&input, direction, DecodeContext::default());
            assert_eq!(result.is_ok(), legal.contains(&flags));
            if let Ok(packet) = result {
                let mut canonical = BytesMut::new();
                packet
                    .encode(&mut canonical, EncodeContext::default())
                    .expect("encode");
                assert_eq!(&canonical[..2], &[0x20, 0]);
                count += 1;
            }
        }
    }
    assert_eq!(count, 256);
}

#[test]
fn every_received_protocol_type_is_ignored_and_transmit_is_zero() {
    for protocol in 0..=u16::MAX {
        let [high, low] = protocol.to_be_bytes();
        let input = [0x20, 0, high, low, 1, 0, 0, 0, 0x5a];
        let packet = NwuGrePacket::decode(&input, Direction::Uplink, DecodeContext::default())
            .expect("ignore protocol");
        let mut out = BytesMut::new();
        packet
            .encode(&mut out, EncodeContext::default())
            .expect("canonical");
        assert_eq!(out.as_ref(), [0x20, 0, 0, 0, 1, 0, 0, 0, 0x5a]);
    }
}

#[test]
fn every_qfi_constructor_input_is_checked_and_redacted() {
    for value in 0..=u8::MAX {
        let result = Qfi::try_from(value);
        assert_eq!(result.is_ok(), value < 64);
        if let Ok(qfi) = result {
            assert_eq!(qfi.value(), value);
            assert_eq!(format!("{qfi:?}"), "Qfi([REDACTED])");
        } else {
            assert_eq!(
                result.expect_err("range").to_string(),
                "QFI is outside the supported range"
            );
        }
    }
}

#[test]
fn receive_limits_precede_fields_and_all_validation_levels_keep_profile_checks() {
    let valid = [0x20, 0, 0, 0, 63, 0, 0, 0, 0x5a];
    for level in [
        ValidationLevel::HeaderOnly,
        ValidationLevel::Structural,
        ValidationLevel::Strict,
        ValidationLevel::ProcedureAware,
    ] {
        for max in 0..=10 {
            let ctx = DecodeContext {
                max_message_len: max,
                validation_level: level,
                ..DecodeContext::default()
            };
            let result = NwuGrePacket::decode(&valid, Direction::Uplink, ctx);
            assert_eq!(result.is_ok(), max >= valid.len());
            if max < valid.len() {
                assert_eq!(
                    result.expect_err("bound").code(),
                    &DecodeErrorCode::MessageLengthExceeded
                );
            }
        }
        for length in 0..=8 {
            assert!(NwuGrePacket::decode(
                &valid[..length],
                Direction::Uplink,
                DecodeContext {
                    validation_level: level,
                    ..DecodeContext::default()
                }
            )
            .is_err());
        }
        let mut illegal = valid;
        illegal[7] = 0x80;
        assert!(NwuGrePacket::decode(
            &illegal,
            Direction::Uplink,
            DecodeContext {
                validation_level: level,
                ..DecodeContext::default()
            }
        )
        .is_err());
    }
    let ctx = DecodeContext {
        max_ies: 0,
        max_depth: 0,
        protocol_version: ProtocolVersion(255),
        ..DecodeContext::default()
    };
    assert!(NwuGrePacket::decode(&valid, Direction::Uplink, ctx).is_ok());
}

#[test]
fn encode_failures_leave_destination_unchanged_including_owned_paths() {
    let packet = NwuGrePacket::new(
        uplink(63),
        b"synthetic-private-packet",
        EncodeContext::default(),
    )
    .expect("packet");
    let owned = packet.to_owned_pdu();
    let required = packet.wire_len(EncodeContext::default()).expect("size");
    for max in 0..required {
        let ctx = EncodeContext {
            max_message_len: max,
            ..EncodeContext::default()
        };
        for encoder in [&packet as &dyn Encode, &owned] {
            let mut out = BytesMut::from(&b"prefix"[..]);
            assert!(encoder.encode(&mut out, ctx).is_err());
            assert_eq!(&out[..], b"prefix");
            assert!(encoder.wire_len(ctx).is_err());
        }
        assert!(NwuGrePacket::new(packet.qos(), packet.payload(), ctx).is_err());
        assert!(OwnedNwuGrePacket::new(
            packet.qos(),
            Bytes::copy_from_slice(packet.payload()),
            ctx
        )
        .is_err());
    }
    let mut out = BytesMut::from(&b"prefix"[..]);
    packet
        .encode(
            &mut out,
            EncodeContext {
                max_message_len: required,
                ..EncodeContext::default()
            },
        )
        .expect("exact cap, prefix excluded");
    assert_eq!(out.len(), required + 6);
    let ctx = EncodeContext {
        raw_preserving: true,
        ..EncodeContext::default()
    };
    let before = out.clone();
    assert!(packet.encode(&mut out, ctx).is_err());
    assert_eq!(out, before);
    assert!(NwuGrePacket::new(uplink(1), &[], EncodeContext::default()).is_err());
    assert!(OwnedNwuGrePacket::new(uplink(1), Bytes::new(), EncodeContext::default()).is_err());
}

#[test]
fn key_spares_are_ignored_but_uplink_rqi_remains_invalid() {
    let mut wire = [0x23, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x5a];
    let packet =
        NwuGrePacket::decode(&wire, Direction::Uplink, DecodeContext::default()).expect("spares");
    assert_eq!(packet.qos(), uplink(63));
    let mut encoded = BytesMut::new();
    packet
        .encode(&mut encoded, EncodeContext::default())
        .expect("canonical");
    assert_eq!(encoded.as_ref(), [0x20, 0, 0, 0, 63, 0, 0, 0, 0x5a]);
    wire[7] = 0xff;
    assert!(NwuGrePacket::decode(&wire, Direction::Uplink, DecodeContext::default()).is_err());
    assert!(NwuGrePacket::decode(&wire, Direction::Downlink, DecodeContext::default()).is_ok());
}

#[test]
fn mapping_keeps_multiple_qfis_matches_defaults_and_no_implicit_preference() {
    let entries = [
        FlowAssociation::new("default-a", QfiSet::empty(), Fallback::Eligible),
        FlowAssociation::new(
            "sa-a",
            QfiSet::empty().with(qfi(0)).with(qfi(1)).with(qfi(63)),
            Fallback::Ineligible,
        ),
        FlowAssociation::new("sa-b", QfiSet::empty().with(qfi(1)), Fallback::Ineligible),
        FlowAssociation::new("default-b", QfiSet::empty(), Fallback::Eligible),
    ];
    let mapping = FlowMapping::new(&entries, entries.len()).expect("bound");
    for value in [0, 1, 63] {
        let selected = mapping.select(qfi(value));
        assert_eq!(selected.kind(), SelectionKind::Exact);
        let ids: Vec<_> = selected
            .candidates()
            .map(|entry| *entry.association())
            .collect();
        assert_eq!(
            ids,
            if value == 1 {
                vec!["sa-a", "sa-b"]
            } else {
                vec!["sa-a"]
            }
        );
    }
    let selected = mapping.select(qfi(2));
    assert_eq!(selected.kind(), SelectionKind::DefaultFallback);
    assert_eq!(
        selected
            .candidates()
            .map(|entry| *entry.association())
            .collect::<Vec<_>>(),
        ["default-a", "default-b"]
    );
    assert!(FlowMapping::new(&entries, entries.len() - 1).is_err());
    let no_default = FlowMapping::new(&entries[1..3], 2).expect("mapping");
    assert_eq!(no_default.select(qfi(2)).kind(), SelectionKind::Unmapped);
    assert_eq!(no_default.select(qfi(2)).candidates().count(), 0);
    let empty = FlowMapping::<()>::new(&[], 0).expect("empty");
    assert_eq!(empty.select(qfi(0)).kind(), SelectionKind::Unmapped);
}

#[test]
fn mapping_matches_independent_boolean_matrix_for_all_qfis() {
    for scenario in 0..256usize {
        let membership: Vec<Vec<bool>> = (0..8)
            .map(|entry| {
                (0..64)
                    .map(|qfi| (qfi + entry * 7 + scenario) % 11 == 0)
                    .collect()
            })
            .collect();
        let defaults: Vec<bool> = (0..8).map(|entry| scenario & (1 << entry) != 0).collect();
        let entries: Vec<_> = (0..8)
            .map(|entry| {
                let set = (0..64)
                    .filter(|q| membership[entry][*q])
                    .fold(QfiSet::empty(), |set, value| set.with(qfi(value as u8)));
                FlowAssociation::new(
                    entry,
                    set,
                    if defaults[entry] {
                        Fallback::Eligible
                    } else {
                        Fallback::Ineligible
                    },
                )
            })
            .collect();
        let mapping = FlowMapping::new(&entries, 8).expect("bounded");
        for selected_qfi in (0..64).map(qfi) {
            let value = usize::from(selected_qfi.value());
            let exact: Vec<_> = (0..8).filter(|entry| membership[*entry][value]).collect();
            let fallback: Vec<_> = (0..8).filter(|entry| defaults[*entry]).collect();
            let expected = if !exact.is_empty() { &exact } else { &fallback };
            let selected = mapping.select(selected_qfi);
            let kind = if !exact.is_empty() {
                SelectionKind::Exact
            } else if !fallback.is_empty() {
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
            let mut candidates = selected.candidates();
            assert_eq!(candidates.size_hint().1, Some(entries.len()));
            while candidates.next().is_some() {}
            assert!(candidates.next().is_none());
            assert_eq!(candidates.size_hint().1, Some(0));
        }
    }
}

#[test]
fn qfi_sets_cover_all_64_bits_and_duplicate_insertion() {
    let mut all = QfiSet::empty();
    for value in 0..64 {
        let one = QfiSet::empty().with(qfi(value));
        assert_eq!(one, one.with(qfi(value)));
        for other in 0..64 {
            assert_eq!(one.contains(qfi(other)), value == other);
        }
        all = all.with(qfi(value));
    }
    for value in 0..64 {
        assert!(all.contains(qfi(value)));
    }
}

#[test]
fn debug_and_errors_retain_no_packet_identifier_or_configuration_values() {
    struct PrivateId;
    impl std::fmt::Debug for PrivateId {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("identifier Debug must never run")
        }
    }
    let qos = DirectionalQos::Downlink {
        qfi: qfi(61),
        rqi: Rqi::Indicated,
    };
    let packet = NwuGrePacket::new(qos, b"synthetic-private-packet", EncodeContext::default())
        .expect("packet");
    let entries = [FlowAssociation::new(
        PrivateId,
        QfiSet::empty().with(qfi(61)),
        Fallback::Eligible,
    )];
    let map = FlowMapping::new(&entries, 1).expect("map");
    let selected = map.select(qfi(61));
    for (actual, expected) in [
        (format!("{packet:?}"), "NwuGrePacket([REDACTED])"),
        (
            format!("{:?}", packet.to_owned_pdu()),
            "OwnedNwuGrePacket([REDACTED])",
        ),
        (format!("{qos:?}"), "DirectionalQos([REDACTED])"),
        (format!("{:?}", Rqi::Indicated), "Rqi([REDACTED])"),
        (format!("{:?}", entries[0]), "FlowAssociation([REDACTED])"),
        (format!("{:?}", entries[0].qfis()), "QfiSet([REDACTED])"),
        (
            format!("{:?}", entries[0].fallback_intent()),
            "DefaultFallbackIntent([REDACTED])",
        ),
        (format!("{map:?}"), "FlowMapping([REDACTED])"),
        (format!("{selected:?}"), "FlowSelection([REDACTED])"),
        (
            format!("{:?}", selected.candidates()),
            "AssociationCandidates([REDACTED])",
        ),
    ] {
        assert_eq!(actual, expected);
    }
    let error = packet
        .wire_len(EncodeContext {
            max_message_len: 13,
            ..EncodeContext::default()
        })
        .expect_err("limit");
    for diagnostic in [format!("{error:?}"), error.to_string()] {
        for private in ["synthetic-private-packet", "61", "13"] {
            assert!(!diagnostic.contains(private));
        }
    }
    let error = FlowMapping::new(&entries, 0).expect_err("mapping limit");
    assert_eq!(error.to_string(), "association count exceeds limit");
}

#[test]
fn borrowed_decode_and_mapping_allocate_nothing() {
    let wire = [0x20, 0, 0, 0, 63, 0, 0, 0, 0x5a];
    let entries = [FlowAssociation::new(
        (),
        QfiSet::empty().with(qfi(63)),
        Fallback::Eligible,
    )];
    let allocations = allocation_counter::measure(|| {
        let packet = NwuGrePacket::decode(&wire, Direction::Uplink, DecodeContext::default())
            .expect("decode");
        assert_eq!(packet.payload().as_ptr(), wire[8..].as_ptr());
        let map = FlowMapping::new(&entries, 1).expect("map");
        assert_eq!(map.select(packet.qos().qfi()).candidates().count(), 1);
    });
    assert_eq!(allocations.count_total, 0);
    assert_eq!(allocations.bytes_total, 0);
}
