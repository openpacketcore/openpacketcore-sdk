//! Synthetic packet tests for the N3 intent boundary; no forwarding claim.

use bytes::BytesMut;
use opc_gtpu_dataplane::n3::{
    LocalN3DownlinkTnl, N3Direction, N3FlowMarking, N3ForwardingIntent, N3ForwardingRole,
    N3PacketError, N3PacketView, N3Qfi, N3UplinkEncapsulation, ReceivedN3UplinkTnl,
};
use opc_gtpu_dataplane::{
    EbpfGtpuDataplaneBackend, GtpBearerMark, GtpuCapability, GtpuDataplaneBackend,
    LinuxGtpuDataplaneBackend, MockGtpuDataplaneBackend, Teid, UnsupportedGtpuDataplaneBackend,
};
use opc_protocol::{DecodeContext, DuplicateIePolicy, UnknownIePolicy, ValidationLevel};
use sha2::{Digest, Sha256};

const REFERENCE: &str = include_str!("n3_reference.tsv");

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    let (pairs, tail) = text.as_bytes().as_chunks::<2>();
    assert!(tail.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn insertion(qfi: u8) -> N3UplinkEncapsulation {
    let tunnel = ReceivedN3UplinkTnl::new(
        "192.0.2.1".parse().unwrap(),
        Teid::new(0x1122_3344).unwrap(),
    )
    .unwrap();
    N3UplinkEncapsulation::new(tunnel, N3Qfi::new(qfi).unwrap())
}

#[test]
fn independent_reference_packets() {
    assert_eq!(
        &Sha256::digest(REFERENCE.as_bytes())[..],
        unhex("31da0a1658218432817bc181be4233fadd4fd1f36c36f3d29f087bc131b8424a")
    );
    let mut counts = [0, 0];
    for row in REFERENCE.lines().filter(|line| !line.starts_with('#')) {
        let columns: Vec<_> = row.split('\t').collect();
        assert_eq!(columns.len(), 8);
        let direction = match columns[1] {
            "ul" => N3Direction::Uplink,
            "dl" => N3Direction::Downlink,
            _ => panic!("invalid oracle direction"),
        };
        let wire = unhex(columns[7]);
        let result = N3PacketView::decode(&wire, direction, DecodeContext::default());
        if columns[2] == "accept" {
            counts[0] += 1;
            let view = result
                .unwrap_or_else(|reason| panic!("synthetic case {} refused: {reason}", columns[0]));
            assert_eq!(view.datagram(), wire);
            assert_eq!(view.datagram().as_ptr(), wire.as_ptr());
            assert_eq!(view.teid().get(), 0x1122_3344);
            assert_eq!(view.qos().direction(), direction);
            assert_eq!(view.qos().qfi().get(), columns[3].parse::<u8>().unwrap());
            assert_eq!(view.qos().rqi(), columns[4] == "1");
            assert_eq!(
                view.qos().ppi(),
                if columns[5] == "-" {
                    None
                } else {
                    Some(columns[5].parse::<u8>().unwrap())
                }
            );
            assert_eq!(view.payload(), unhex(columns[6]));
        } else {
            counts[1] += 1;
            assert!(result.is_err(), "synthetic case {} accepted", columns[0]);
        }
    }
    assert_eq!(counts, [1511, 1093]);
}

#[test]
fn n3_uplink_insertion_matches_independent_wire() {
    let tunnel = ReceivedN3UplinkTnl::new(
        "192.0.2.1".parse().unwrap(),
        Teid::new(0x1122_3344).unwrap(),
    )
    .unwrap();
    let insertion = N3UplinkEncapsulation::new(tunnel, N3Qfi::new(9).unwrap());
    let mut dst = BytesMut::from(&b"prefix"[..]);
    insertion.encode_gpdu(&[0xab], &mut dst, 17).unwrap();
    assert_eq!(
        &dst[6..],
        &[0x34, 0xff, 0, 9, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x85, 1, 0x10, 9, 0, 0xab]
    );
    let decoded =
        N3PacketView::decode(&dst[6..], N3Direction::Uplink, DecodeContext::default()).unwrap();
    assert_eq!(decoded.qos().qfi().get(), 9);
    assert_eq!(decoded.payload(), &[0xab]);
}

#[test]
fn n3_datagram_rejects_trailing_bytes_and_empty_inner_payload() {
    let wire = [
        0x36, 0xff, 0, 8, 0x11, 0x22, 0x33, 0x44, 0, 5, 0, 0x85, 1, 0, 9, 0,
    ];
    assert_eq!(
        N3PacketView::decode(&wire, N3Direction::Downlink, DecodeContext::default()).unwrap_err(),
        N3PacketError::EmptyPayload
    );
    let mut extra = wire.to_vec();
    extra.push(0xab);
    assert_eq!(
        N3PacketView::decode(&extra, N3Direction::Downlink, DecodeContext::default()).unwrap_err(),
        N3PacketError::InvalidFraming
    );
}

#[test]
fn reviewed_psc_only_fixtures_do_not_claim_forwarding_input() {
    use opc_proto_gtpu::{GtpuExtensionChain, GtpuMessage};
    use opc_protocol::BorrowDecode;
    let fixtures = [
        (
            N3Direction::Uplink,
            include_str!("../../opc-n3iwf-fixtures/fixtures/n3-gtpu/wire/positive-ul-psc.hex"),
        ),
        (
            N3Direction::Downlink,
            include_str!("../../opc-n3iwf-fixtures/fixtures/n3-gtpu/wire/positive-dl-psc.hex"),
        ),
    ];
    for (direction, fixture) in fixtures {
        let compact: String = fixture.split_whitespace().collect();
        let wire = unhex(&compact);
        let (tail, generic) = GtpuMessage::decode(&wire, DecodeContext::default()).unwrap();
        assert!(tail.is_empty());
        assert!(generic.payload.is_empty());
        assert!(GtpuExtensionChain::from_message(&generic)
            .unwrap()
            .pdu_session_container
            .is_some());
        assert_eq!(
            N3PacketView::decode(&wire, direction, DecodeContext::default()).unwrap_err(),
            N3PacketError::EmptyPayload
        );
    }
}

#[test]
fn all_qfis_construct_without_truncation() {
    for qfi in 0..=u8::MAX {
        let checked = N3Qfi::new(qfi);
        if qfi > 63 {
            assert_eq!(checked.unwrap_err(), N3PacketError::InvalidQfi);
            continue;
        }
        assert_eq!(checked.unwrap().get(), qfi);
        let mut wire = BytesMut::new();
        insertion(qfi)
            .encode_gpdu(&[0xca, 0xfe], &mut wire, 18)
            .unwrap();
        let expected = [
            0x34, 0xff, 0, 10, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x85, 1, 0x10, qfi, 0, 0xca, 0xfe,
        ];
        assert_eq!(&wire[..], expected);
    }
}

#[test]
fn receiver_limits_and_policies_cannot_weaken_profile() {
    let valid = unhex("3fff000911223344abcdff8501000900aa");
    let duplicate = unhex("34ff000d11223344000000850100098501000900aa");
    let required = unhex("34ff000d11223344000000c10112348501000900aa");
    let optional = unhex("34ff000d11223344000000200112348501000900aa");
    let malformed_psc = unhex("34ff0009112233440000008501020900aa");
    for validation_level in [
        ValidationLevel::HeaderOnly,
        ValidationLevel::Structural,
        ValidationLevel::Strict,
        ValidationLevel::ProcedureAware,
    ] {
        for unknown_ie_policy in [
            UnknownIePolicy::Drop,
            UnknownIePolicy::Preserve,
            UnknownIePolicy::Reject,
        ] {
            for duplicate_ie_policy in [
                DuplicateIePolicy::First,
                DuplicateIePolicy::Last,
                DuplicateIePolicy::Reject,
            ] {
                let ctx = DecodeContext {
                    validation_level,
                    unknown_ie_policy,
                    duplicate_ie_policy,
                    ..DecodeContext::default()
                };
                assert!(N3PacketView::decode(&valid, N3Direction::Downlink, ctx).is_ok());
                assert!(N3PacketView::decode(&optional, N3Direction::Downlink, ctx).is_ok());
                for (wire, expected) in [
                    (&duplicate, N3PacketError::DuplicatePsc),
                    (&required, N3PacketError::UnsupportedExtension),
                    (&malformed_psc, N3PacketError::InvalidPsc),
                ] {
                    assert_eq!(
                        N3PacketView::decode(wire, N3Direction::Downlink, ctx).unwrap_err(),
                        expected
                    );
                }
                for cap in 0..valid.len() {
                    assert_eq!(
                        N3PacketView::decode(
                            &valid,
                            N3Direction::Downlink,
                            DecodeContext {
                                max_message_len: cap,
                                ..ctx
                            }
                        )
                        .unwrap_err(),
                        N3PacketError::MessageTooLarge
                    );
                }
                for max_ies in [0, 1] {
                    assert_eq!(
                        N3PacketView::decode(
                            &optional,
                            N3Direction::Downlink,
                            DecodeContext { max_ies, ..ctx }
                        )
                        .unwrap_err(),
                        N3PacketError::ExtensionLimitExceeded
                    );
                }
                for max_depth in [0, 1] {
                    assert_eq!(
                        N3PacketView::decode(
                            &optional,
                            N3Direction::Downlink,
                            DecodeContext { max_depth, ..ctx }
                        )
                        .unwrap_err(),
                        N3PacketError::ExtensionLimitExceeded
                    );
                }
                assert!(N3PacketView::decode(
                    &optional,
                    N3Direction::Downlink,
                    DecodeContext {
                        max_message_len: optional.len(),
                        max_ies: 2,
                        max_depth: 2,
                        ..ctx
                    }
                )
                .is_ok());
            }
        }
    }
}

#[test]
fn construction_limits_are_atomic_and_exclude_output_prefix() {
    let insertion = insertion(63);
    for payload in [vec![], vec![0xaa], vec![0xbb; 65527], vec![0xcc; 65528]] {
        for cap in [0, 16, 17, 65535, 65543, usize::MAX] {
            let mut dst = BytesMut::from(&b"existing-prefix"[..]);
            let before = dst.clone();
            let expected = if payload.is_empty() {
                Err(N3PacketError::EmptyPayload)
            } else if payload.len() > 65527 {
                Err(N3PacketError::LengthOverflow)
            } else if payload.len() + 16 > cap {
                Err(N3PacketError::MessageTooLarge)
            } else {
                Ok(payload.len() + 16)
            };
            assert_eq!(insertion.wire_len(&payload, cap), expected);
            let result = insertion.encode_gpdu(&payload, &mut dst, cap);
            match expected {
                Err(reason) => {
                    assert_eq!(result.unwrap_err(), reason);
                    assert_eq!(dst, before);
                }
                Ok(len) => {
                    result.unwrap();
                    assert_eq!(&dst[..before.len()], &before[..]);
                    assert_eq!(dst.len() - before.len(), len);
                    let view = N3PacketView::decode(
                        &dst[before.len()..],
                        N3Direction::Uplink,
                        DecodeContext {
                            max_message_len: len,
                            ..DecodeContext::default()
                        },
                    )
                    .unwrap();
                    assert_eq!(view.payload(), payload);
                }
            }
        }
    }
}

#[test]
fn receive_is_borrowed_and_allocates_nothing() {
    let wire = unhex("34ff00111122334400000020011234850200c907a1b2c300aa");
    let stats = allocation_counter::measure(|| {
        let view =
            N3PacketView::decode(&wire, N3Direction::Downlink, DecodeContext::default()).unwrap();
        assert_eq!(view.payload(), &[0xaa]);
        assert_eq!(view.qos().qfi().get(), 9);
        assert_eq!(view.qos().ppi(), Some(7));
        assert!(view.qos().rqi());
        assert_eq!(view.datagram().as_ptr(), wire.as_ptr());
        std::hint::black_box(view);
    });
    assert_eq!(stats.count_total, 0);
    assert_eq!(stats.bytes_total, 0);
}

#[test]
fn directional_tunnel_and_marking_intent_is_explicit_and_redacted() {
    let uplink = ReceivedN3UplinkTnl::new(
        "192.0.2.1".parse().unwrap(),
        Teid::new(0x1122_3344).unwrap(),
    )
    .unwrap();
    let downlink = LocalN3DownlinkTnl::new(
        "2001:db8::2".parse().unwrap(),
        Teid::new(0x5566_7788).unwrap(),
    )
    .unwrap();
    let qfi = N3Qfi::new(9).unwrap();
    let mark = GtpBearerMark::new(0x1234_5678).unwrap();
    let flow = N3FlowMarking::new(qfi, Some(mark));
    let intent = N3ForwardingIntent::new(N3ForwardingRole::N3iwf, uplink, downlink, flow);
    assert_eq!(intent.role(), N3ForwardingRole::N3iwf);
    assert_eq!(intent.received_uplink(), uplink);
    assert_eq!(intent.local_downlink(), downlink);
    assert_eq!(intent.flow(), flow);
    assert_eq!(flow.qfi(), qfi);
    assert_eq!(flow.mark(), Some(mark));
    assert_eq!(N3FlowMarking::new(qfi, None).mark(), None);
    assert_eq!(
        uplink.destination(),
        "192.0.2.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(uplink.teid().get(), 0x1122_3344);
    assert_eq!(
        downlink.local_address(),
        "2001:db8::2".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(downlink.teid().get(), 0x5566_7788);
    let encapsulation = N3UplinkEncapsulation::new(uplink, qfi);
    assert_eq!(encapsulation.tunnel(), uplink);
    assert_eq!(encapsulation.qfi(), qfi);
    let wire = unhex("34ff0009112233440000008501000900aa");
    let view =
        N3PacketView::decode(&wire, N3Direction::Downlink, DecodeContext::default()).unwrap();
    let values: [(&dyn std::fmt::Debug, &str); 8] = [
        (&uplink, "ReceivedN3UplinkTnl"),
        (&downlink, "LocalN3DownlinkTnl"),
        (&qfi, "N3Qfi"),
        (&flow, "N3FlowMarking"),
        (&intent, "N3ForwardingIntent"),
        (&encapsulation, "N3UplinkEncapsulation"),
        (&view, "N3PacketView"),
        (view.qos(), "N3Qos"),
    ];
    for (value, name) in values {
        assert_eq!(format!("{value:?}"), format!("{name}(<redacted>)"));
    }
    for address in ["0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255"] {
        let address = address.parse().unwrap();
        assert_eq!(
            ReceivedN3UplinkTnl::new(address, uplink.teid()).unwrap_err(),
            N3PacketError::InvalidAddress
        );
        assert_eq!(
            LocalN3DownlinkTnl::new(address, downlink.teid()).unwrap_err(),
            N3PacketError::InvalidAddress
        );
    }
}

#[test]
fn every_shipped_backend_refuses_n3_forwarding_capability() {
    let backends: Vec<Box<dyn GtpuDataplaneBackend>> = vec![
        Box::new(MockGtpuDataplaneBackend::new()),
        Box::new(LinuxGtpuDataplaneBackend::new()),
        Box::new(EbpfGtpuDataplaneBackend::new()),
        Box::new(UnsupportedGtpuDataplaneBackend::new()),
    ];
    for backend in backends {
        assert_eq!(
            backend.n3_forwarding_capability(N3ForwardingRole::N3iwf),
            GtpuCapability::Missing
        );
    }
}
