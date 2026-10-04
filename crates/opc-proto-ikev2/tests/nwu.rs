use opc_proto_ikev2::nwu::{Notify, QosInfo};

#[test]
fn independent_qos_notify_vector() {
    let body = [0, 0, 0xd8, 0xcd, 4, 5, 1, 9, 0];
    let expected = Notify::Qos(must(QosInfo::new(5, &[9], false, None, None)));
    assert_eq!(must(Notify::decode_body(&body)), Some(expected));
    assert_eq!(must(expected.encode_body()), body);
}

fn must<T, E: std::fmt::Debug>(v: Result<T, E>) -> T {
    match v {
        Ok(v) => v,
        Err(e) => panic!("{e:?}"),
    }
}

use opc_proto_ikev2::{
    nwu::{
        encode_payloads, AdditionalQos, Address, AddressFamilies, ConfigurationReply,
        ConfigurationRequest, Error, EspSpi, Limits, NasEndpoint, QosParameter,
    },
    Ikev2IkeAuthPayloadBuild, PayloadChain, PayloadType,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../opc-n3iwf-fixtures/fixtures/nwu-ike/wire")
        .join(format!("{name}.hex"));
    must(std::fs::read_to_string(path))
        .split_whitespace()
        .map(|b| must(u8::from_str_radix(b, 16)))
        .collect()
}
fn v4(last: u8) -> Address {
    Address::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
}
fn v6(last: u16) -> Address {
    Address::new(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, last,
    )))
}
fn entries(values: &[(PayloadType, &[u8])]) -> Vec<Ikev2IkeAuthPayloadBuild> {
    values
        .iter()
        .map(|(payload_type, body)| Ikev2IkeAuthPayloadBuild {
            payload_type: *payload_type,
            body: body.to_vec(),
        })
        .collect()
}
fn independent_chain(values: &[(u8, &[u8])]) -> (PayloadType, Vec<u8>) {
    let mut out = Vec::new();
    for (i, (_, body)) in values.iter().enumerate() {
        out.extend_from_slice(&[values.get(i + 1).map_or(0, |v| v.0), 0]);
        out.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        out.extend_from_slice(body);
    }
    (PayloadType::from_u8(values.first().map_or(0, |v| v.0)), out)
}

#[test]
fn published_notify_vectors_and_receiver_protocol_id_rules() {
    let qos = must(QosInfo::new(5, &[9], false, None, None));
    let cases = [
        ("positive-nas-ip4", Notify::NasAddress(v4(10))),
        ("positive-nas-tcp-port", Notify::NasTcpPort(20000)),
        ("positive-5g-qos-info", Notify::Qos(qos)),
        ("positive-up-ip4", Notify::UpAddress(v4(11))),
        (
            "positive-up-sa-info",
            Notify::UpSaInfo(must(EspSpi::new([10, 11, 12, 13]))),
        ),
    ];
    for (name, expected) in cases {
        let wire = fixture(name);
        let raw = must(must(
            PayloadChain::new(PayloadType::Notify, &wire)
                .iter()
                .next()
                .ok_or(Error::Missing),
        ));
        assert_eq!(must(Notify::decode_body(raw.body)), Some(expected));
        let (first, encoded) = must(encode_payloads(&entries(&[(
            PayloadType::Notify,
            &must(expected.encode_body()),
        )])));
        assert_eq!(first, PayloadType::Notify);
        assert_eq!(encoded.as_ref(), wire);
        if !matches!(expected, Notify::UpSaInfo(_)) {
            let mut changed = raw.body.to_vec();
            changed[0] = 255;
            assert_eq!(must(Notify::decode_body(&changed)), Some(expected));
        }
    }
    let extended = [3, 4, 0xd8, 0xd4, 10, 11, 12, 13, 0xa5, 0x5a];
    assert_eq!(
        must(must(Notify::decode_body(&extended)).ok_or(Error::Missing)).encode_body(),
        Ok(extended[..8].to_vec())
    );
    let mut wrong = extended;
    wrong[0] = 0;
    assert_eq!(Notify::decode_body(&wrong), Err(Error::SpiShape));
    assert_eq!(EspSpi::new([0; 4]), Err(Error::InvalidValue));
    // RFC 4555 section 4.2.1: receiver-ignored capability extension bytes.
    let extended_capability = [0xff, 0, 0x40, 0x0c, 0xa5, 0x5a];
    assert_eq!(
        must(Notify::decode_body(&extended_capability)),
        Some(Notify::MobikeSupported)
    );
    assert_eq!(
        must(Notify::MobikeSupported.encode_body()),
        [0, 0, 0x40, 0x0c]
    );
}

#[test]
fn malformed_published_notify_and_critical_payload_vectors() {
    for name in [
        "malformed-spi-size",
        "bounded-spi-size-overflow",
        "truncated-nas-ip4",
    ] {
        let wire = fixture(name);
        let result = PayloadChain::new(PayloadType::Notify, &wire)
            .iter()
            .try_for_each(|p| {
                let raw = p.map_err(|_| Error::Framing)?;
                Notify::decode_body(raw.body).map(|_| ())
            });
        assert!(result.is_err(), "{name}");
    }
    let wire = fixture("unknown-critical-payload");
    assert!(PayloadChain::new(PayloadType::Unknown(250), &wire)
        .iter()
        .any(|p| p.is_err()));
    // This fixture proves only generic receipt; it does not establish a MOBIKE update.
    let wire = fixture("mobility-additional-addresses");
    let raw = must(must(
        PayloadChain::new(PayloadType::Notify, &wire)
            .iter()
            .next()
            .ok_or(Error::Missing),
    ));
    assert_eq!(must(Notify::decode_body(raw.body)), None);
}

#[test]
fn complete_qos_independent_parameters_and_full_replacement_values() {
    // TS 24.502 table 9.3.1.1-2: GBR characteristics, exact rate units,
    // both loss-rate directions. Authored directly, without the SDK encoder.
    let extra = [
        7, 1, 8, 0, 127, 3, 255, 9, 9, 15, 160, 2, 3, 1, 0, 10, 3, 3, 2, 0, 11, 4, 3, 3, 0, 12, 5,
        3, 255, 0, 13, 7, 2, 3, 232, 8, 2, 0, 1,
    ];
    let additional = must(AdditionalQos::new(&extra));
    assert_eq!(additional.parameters().count(), 7);
    assert_eq!(
        must(AdditionalQos::encode_parameters(
            &additional.parameters().collect::<Vec<_>>()
        )),
        extra
    );
    let qos = must(QosInfo::new(
        15,
        &[1, 9, 63],
        true,
        Some(46),
        Some(additional),
    ));
    let mut expected = vec![0, 0, 0xd8, 0xcd, 43, 15, 3, 1, 9, 63, 7, 46];
    expected.extend_from_slice(&extra);
    // Length covers only octets after itself.
    expected[4] = (expected.len() - 5) as u8;
    assert_eq!(must(Notify::Qos(qos).encode_body()), expected);
    assert_eq!(must(Notify::decode_body(&expected)), Some(Notify::Qos(qos)));
    let empty = must(QosInfo::new(15, &[], false, None, None));
    assert_eq!(must(empty.encode()), [3, 15, 0, 0]);
    let gbr = [0, 1, 0, 0, 0, 0, 15, 255];
    let critical = [1, 1, 0, 0, 0, 0, 15, 255, 15, 255];
    for data in [&gbr[..], &critical[..]] {
        let wire = must(AdditionalQos::encode_parameters(&[
            QosParameter::Characteristics(data),
        ]));
        assert_eq!(must(AdditionalQos::new(&wire)).parameters().count(), 1);
    }
}

#[test]
fn qos_bounds_duplicates_spares_and_independent_adverse_mutations() {
    let qfis: Vec<_> = (1..=63).collect();
    assert!(QosInfo::new(1, &qfis, false, Some(63), None).is_ok());
    for bad in [vec![0], vec![64], vec![9, 9]] {
        assert!(QosInfo::new(1, &bad, false, None, None).is_err());
    }
    for bad in [0, 16, 255] {
        assert!(QosInfo::new(bad, &[], false, None, None).is_err());
    }
    assert!(QosInfo::new(1, &[], false, Some(64), None).is_err());
    let reserved = [4, 5, 1, 0xc9, 0xfa];
    assert_eq!(
        must(must(QosInfo::decode(&reserved)).encode()),
        [4, 5, 1, 9, 2]
    );
    // An ignored TLV still needs complete framing and counts toward the wire bound.
    assert_eq!(
        must(AdditionalQos::new(&[2, 99, 2, 0xaa, 0xbb, 6, 1, 0xff]))
            .parameters()
            .count(),
        0
    );
    for wire in [
        vec![],
        vec![1],
        vec![1, 2, 3, 0, 0],
        vec![0, 2, 3, 0, 0, 0],
        vec![2, 7, 2, 0, 1, 7, 2, 0, 2],
        vec![1, 7, 2, 3, 233],
        vec![1, 1, 6, 2, 0, 0, 0, 0, 0],
        vec![2, 1, 6, 2, 1, 0, 0, 0, 0, 7, 2, 0, 1],
    ] {
        assert!(AdditionalQos::new(&wire).is_err());
    }
    let good = [4, 5, 1, 9, 0];
    for n in 0..good.len() {
        assert!(QosInfo::decode(&good[..n]).is_err());
    }
    for (index, value) in [(0, 3), (0, 5), (2, 2), (3, 0), (4, 1), (4, 4)] {
        let mut bad = good;
        bad[index] = value;
        assert!(QosInfo::decode(&bad).is_err(), "{index}");
    }
    let mut long = vec![1, 99, 187];
    long.extend(vec![0; 187]); // 190 bytes
    let extra = must(AdditionalQos::new(&long));
    // 3 fixed + 62 QFIs + 190 = 255 exactly; ignored fields do not erase input budgets.
    assert!(QosInfo::new(1, &qfis[..62], false, None, Some(extra)).is_ok());
    assert_eq!(
        QosInfo::new(1, &qfis, false, None, Some(extra)),
        Err(Error::Limit)
    );
    assert_eq!(
        QosInfo::new(1, &qfis[..62], false, Some(0), Some(extra)),
        Err(Error::Limit)
    );
}

#[test]
fn independent_configuration_request_and_reply_family_matrix() {
    for families in [
        AddressFamilies::Ipv4,
        AddressFamilies::Ipv6,
        AddressFamilies::Dual,
    ] {
        for mobike_supported in [false, true] {
            let request = ConfigurationRequest {
                families,
                mobike_supported,
            };
            let mut cp = vec![1, 0, 0, 0];
            if families.ipv4() {
                cp.extend([0, 1, 0, 0]);
            }
            if families.ipv6() {
                cp.extend([0, 8, 0, 0]);
            }
            let mut literal = vec![(47, &cp[..])];
            if mobike_supported {
                literal.push((41, &[0, 0, 0x40, 0x0c]));
            }
            let (first, bytes) = independent_chain(&literal);
            assert_eq!(
                must(ConfigurationRequest::decode(
                    first,
                    &bytes,
                    Limits::default()
                )),
                request
            );
            assert_eq!(
                must(encode_payloads(&must(request.payloads()))).1.as_ref(),
                bytes
            );
            let nas = must(NasEndpoint::new(
                families.ipv4().then(|| v4(10)),
                families.ipv6().then(|| v6(10)),
                20000,
            ));
            let reply = must(ConfigurationReply::new(
                request,
                families.ipv4().then(|| v4(1)),
                families.ipv6().then(|| (v6(1), 64)),
                nas,
            ));
            let mut cp = vec![2, 0, 0, 0];
            if families.ipv4() {
                cp.extend([0, 1, 0, 4, 192, 0, 2, 1]);
            }
            if families.ipv6() {
                cp.extend([
                    0, 8, 0, 17, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 64,
                ]);
            }
            let mut literal = vec![(47, &cp[..])];
            if families.ipv4() {
                literal.push((41, &[0, 0, 0xd8, 0xce, 192, 0, 2, 10]));
            }
            if families.ipv6() {
                literal.push((
                    41,
                    &[
                        0, 0, 0xd8, 0xcf, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10,
                    ],
                ));
            }
            literal.push((41, &[0, 0, 0xd8, 0xd2, 0x4e, 0x20]));
            if mobike_supported && families.ipv4() {
                literal.push((41, &[0, 0, 0x40, 0x0c]));
            }
            let (first, bytes) = independent_chain(&literal);
            assert_eq!(
                must(encode_payloads(&must(reply.payloads()))).1.as_ref(),
                bytes
            );
            assert_eq!(
                must(ConfigurationReply::decode(
                    request,
                    first,
                    &bytes,
                    Limits::default()
                )),
                reply
            );
            literal.reverse();
            let (first, bytes) = independent_chain(&literal);
            assert_eq!(
                must(ConfigurationReply::decode(
                    request,
                    first,
                    &bytes,
                    Limits::default()
                )),
                reply
            );
        }
    }
}

#[test]
fn configuration_duplicate_ordering_malformed_and_limit_contracts() {
    let request = ConfigurationRequest {
        families: AddressFamilies::Ipv4,
        mobike_supported: false,
    };
    let cp = [2, 0, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1];
    for name in ["duplicate-nas-ip4", "ordering-tcp-before-ip4"] {
        let mut bytes = vec![41, 0, 0, 16];
        bytes.extend(cp);
        bytes.extend(fixture(name));
        let result = ConfigurationReply::decode(
            request,
            PayloadType::Configuration,
            &bytes,
            Limits::default(),
        );
        if name.starts_with("duplicate") {
            assert_eq!(result, Err(Error::Duplicate));
        } else {
            assert_eq!(must(result).nas().port(), 20000);
        }
    }
    let reply = must(ConfigurationReply::new(
        request,
        Some(v4(1)),
        None,
        must(NasEndpoint::new(Some(v4(10)), None, 20000)),
    ));
    let payloads = must(reply.payloads());
    let (first, wire) = must(encode_payloads(&payloads));
    for length in 0..wire.len() {
        assert!(
            ConfigurationReply::decode(request, first, &wire[..length], Limits::default()).is_err()
        );
    }
    for i in 0..payloads.len() {
        let mut dup = payloads.clone();
        dup.push(payloads[i].clone());
        let (first, wire) = must(encode_payloads(&dup));
        assert_eq!(
            ConfigurationReply::decode(request, first, &wire, Limits::default()),
            Err(Error::Duplicate)
        );
    }
    assert!(ConfigurationReply::decode(
        request,
        first,
        &wire,
        Limits {
            bytes: wire.len() - 1,
            entries: 3
        }
    )
    .is_err());
    assert!(ConfigurationReply::decode(
        request,
        first,
        &wire,
        Limits {
            bytes: wire.len(),
            entries: 2
        }
    )
    .is_err());
    assert!(ConfigurationReply::decode(
        request,
        first,
        &wire,
        Limits {
            bytes: wire.len(),
            entries: 3
        }
    )
    .is_ok());
    // CP preflight bounds attributes before generic allocation; reserved bits are receive-only.
    let mut many = vec![1, 0, 0, 0, 0x80, 1, 0, 0];
    many.extend([0x7f, 0xff, 0, 0]);
    let (first, wire) = independent_chain(&[(47, &many)]);
    assert_eq!(
        ConfigurationRequest::decode(
            first,
            &wire,
            Limits {
                bytes: 128,
                entries: 1
            }
        ),
        Err(Error::Limit)
    );
    assert_eq!(
        must(ConfigurationRequest::decode(
            first,
            &wire,
            Limits {
                bytes: 128,
                entries: 2
            }
        )),
        request
    );
    let invalid = [1, 0, 0, 0, 0, 1, 0, 1, 0];
    let (first, wire) = independent_chain(&[(47, &invalid)]);
    assert_eq!(
        ConfigurationRequest::decode(first, &wire, Limits::default()),
        Err(Error::InvalidValue)
    );
    assert!(ConfigurationReply::new(
        request,
        None,
        Some((v6(1), 64)),
        must(NasEndpoint::new(None, Some(v6(10)), 20000))
    )
    .is_err());
}

#[test]
fn diagnostic_surfaces_redact_all_deployment_values() {
    let request = ConfigurationRequest {
        families: AddressFamilies::Ipv4,
        mobike_supported: false,
    };
    let reply = must(ConfigurationReply::new(
        request,
        Some(v4(1)),
        None,
        must(NasEndpoint::new(Some(v4(10)), None, 20000)),
    ));
    let values = [
        format!("{reply:?}"),
        format!("{:?}", reply.nas()),
        format!("{:?}", v4(10)),
        format!("{:?}", v6(10)),
        format!("{:?}", Notify::NasTcpPort(20000)),
        format!(
            "{:?}",
            Notify::Qos(must(QosInfo::new(5, &[9], true, Some(46), None)))
        ),
        format!("{:?}", must(EspSpi::new([0xaa, 0xbb, 0xcc, 0xdd]))),
    ];
    for value in values {
        for secret in ["192.0.2.", "2001:db8", "20000", "aabbccdd", "170, 187"] {
            assert!(!value.contains(secret));
        }
    }
}

use opc_proto_ikev2::{
    nwu::{
        ChildDelete, DeleteCollision, DeleteOutcome, Modification, ModificationOutcome, Peer,
        PendingChildDelete, PendingIkeDelete, PendingModification,
    },
    Header, HeaderFlags, EXCHANGE_TYPE_INFORMATIONAL,
};
fn header(sender: Peer, response: bool) -> Header {
    Header::new(
        1,
        2,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_INFORMATIONAL,
        HeaderFlags::from_bits(sender == Peer::Ue, response, false),
        7,
    )
}
#[test]
fn published_modification_complete_replacement_and_role_checks() {
    let wire = fixture("modify-child-sa");
    let request = header(Peer::Network, false);
    let (_, value) = must(Modification::decode(
        &request,
        PayloadType::Notify,
        &wire,
        Limits::default(),
    ));
    assert_eq!(value.inbound_spi, must(EspSpi::new([10, 11, 12, 13])));
    assert_eq!(value.replacement.session(), 5);
    assert_eq!(value.replacement.qfis().collect::<Vec<_>>(), [10]);
    assert!(!value.replacement.is_default());
    assert_eq!(value.replacement.dscp(), None);
    assert_eq!(value.replacement.additional(), None);
    assert_eq!(
        must(encode_payloads(&must(value.payloads()))).1.as_ref(),
        wire
    );
    let mut payloads = must(value.payloads());
    payloads.reverse();
    let (first, bytes) = must(encode_payloads(&payloads));
    assert_eq!(
        must(Modification::decode(
            &request,
            first,
            &bytes,
            Limits::default()
        ))
        .1,
        value
    );
    for wrong in [header(Peer::Ue, false), header(Peer::Network, true)] {
        assert!(Modification::decode(&wrong, first, &bytes, Limits::default()).is_err());
    }
    payloads.push(payloads[0].clone());
    let (first, bytes) = must(encode_payloads(&payloads));
    assert_eq!(
        Modification::decode(&request, first, &bytes, Limits::default()),
        Err(Error::Duplicate)
    );
}
#[test]
fn modification_acceptance_rejection_timeout_and_response_correlation_are_distinct() {
    let request = header(Peer::Network, false);
    let response = header(Peer::Ue, true);
    assert_eq!(
        must(must(PendingModification::new(&request)).response(
            &response,
            PayloadType::NoNext,
            &[],
            Limits::default()
        )),
        ModificationOutcome::Accepted
    );
    let (first, bytes) = independent_chain(&[(41, &[0, 0, 0, 14])]);
    let result = must(must(PendingModification::new(&request)).response(
        &response,
        first,
        &bytes,
        Limits::default(),
    ));
    match result {
        ModificationOutcome::Rejected(e) => assert_eq!(e.code(), 14),
        _ => panic!("wrong outcome"),
    }
    assert_eq!(
        must(PendingModification::new(&request)).timeout(),
        ModificationOutcome::AmbiguousTimeout
    );
    let mut wrong = response.clone();
    wrong.message_id += 1;
    assert!(must(PendingModification::new(&request))
        .response(&wrong, first, &bytes, Limits::default())
        .is_err());
    let (first, bytes) = independent_chain(&[(41, &[0, 0, 0x40, 0x0c])]);
    assert!(must(PendingModification::new(&request))
        .response(&response, first, &bytes, Limits::default())
        .is_err());
    assert!(must(PendingModification::new(&request))
        .response(&response, PayloadType::NoNext, &[0], Limits::default())
        .is_err());
}
#[test]
fn child_delete_echoes_all_inbound_spis_for_both_initiators_and_crossed_requests() {
    let spis = [
        must(EspSpi::new([10, 11, 12, 13])),
        must(EspSpi::new([10, 11, 12, 14])),
    ];
    let deletion = must(ChildDelete::new(&spis, Limits::default()));
    assert!(deletion.validate_complete(&[spis[1], spis[0]]).is_ok());
    assert!(deletion.validate_complete(&spis[..1]).is_err());
    assert!(deletion.validate_complete(&[spis[0], spis[0]]).is_err());
    let (first, bytes) = independent_chain(&[(42, &[3, 4, 0, 2, 10, 11, 12, 13, 10, 11, 12, 14])]);
    assert_eq!(
        must(encode_payloads(&must(deletion.payloads()))).1.as_ref(),
        bytes
    );
    for (sender, receiver) in [(Peer::Network, Peer::Ue), (Peer::Ue, Peer::Network)] {
        let request = header(sender, false);
        let response = header(receiver, true);
        let (_, received) = must(ChildDelete::decode(
            &request,
            sender,
            first,
            &bytes,
            Limits::default(),
        ));
        assert_eq!(received, deletion);
        for collision in [DeleteCollision::Ordinary, DeleteCollision::Crossed] {
            assert_eq!(
                must(encode_payloads(&must(
                    received.response_payloads(collision)
                )))
                .1
                .as_ref(),
                bytes
            );
        }
        assert_eq!(
            must(
                must(PendingChildDelete::new(&request, sender, deletion.clone())).response(
                    &response,
                    first,
                    &bytes,
                    Limits::default()
                )
            ),
            DeleteOutcome::Acknowledged
        );
        assert_eq!(
            must(PendingChildDelete::new(&request, sender, deletion.clone())).timeout(),
            DeleteOutcome::DiscardIkeAndAllChildren
        );
        let opposite = must(ChildDelete::new(
            &[must(EspSpi::new([0xff; 4]))],
            Limits::default(),
        ));
        let (wrong_first, wrong) = must(encode_payloads(&must(opposite.payloads())));
        assert!(
            must(PendingChildDelete::new(&request, sender, deletion.clone()))
                .response(&response, wrong_first, &wrong, Limits::default())
                .is_err()
        );
        assert!(
            must(PendingChildDelete::new(&request, sender, deletion.clone()))
                .response(&response, PayloadType::NoNext, &[], Limits::default())
                .is_err()
        );
    }
    let fixture = fixture("delete-esp");
    let (_, single) = must(ChildDelete::decode(
        &header(Peer::Network, false),
        Peer::Network,
        PayloadType::Delete,
        &fixture,
        Limits::default(),
    ));
    assert_eq!(single.inbound_spis(), &spis[..1]);
}
#[test]
fn child_delete_bounds_duplicates_and_ike_delete_have_separate_wire_contracts() {
    let spi = must(EspSpi::new([10, 11, 12, 13]));
    assert_eq!(
        ChildDelete::new(&[spi, spi], Limits::default()),
        Err(Error::Duplicate)
    );
    assert_eq!(
        ChildDelete::new(&[], Limits::default()),
        Err(Error::Missing)
    );
    assert_eq!(
        ChildDelete::new(
            &[spi],
            Limits {
                bytes: 11,
                entries: 1
            }
        ),
        Err(Error::Limit)
    );
    assert!(ChildDelete::new(
        &[spi],
        Limits {
            bytes: 12,
            entries: 1
        }
    )
    .is_ok());
    for body in [
        &[3, 0, 255, 255][..],
        &[3, 4, 0, 1, 0, 0, 0, 0],
        &[3, 4, 0, 0],
        &[1, 0, 0, 0],
    ] {
        let (first, bytes) = independent_chain(&[(42, body)]);
        assert!(ChildDelete::decode(
            &header(Peer::Network, false),
            Peer::Network,
            first,
            &bytes,
            Limits::default()
        )
        .is_err());
    }
    let (first, bytes) = independent_chain(&[(42, &[1, 0, 0, 0])]);
    assert_eq!(
        must(encode_payloads(&must(PendingIkeDelete::payloads())))
            .1
            .as_ref(),
        bytes
    );
    for (sender, receiver) in [(Peer::Network, Peer::Ue), (Peer::Ue, Peer::Network)] {
        let request = header(sender, false);
        let response = header(receiver, true);
        assert!(PendingIkeDelete::decode_request(
            &request,
            sender,
            first,
            &bytes,
            Limits::default()
        )
        .is_ok());
        assert_eq!(
            must(must(PendingIkeDelete::new(&request, sender)).response(
                &response,
                PayloadType::NoNext,
                &[]
            )),
            DeleteOutcome::Acknowledged
        );
        assert_eq!(
            must(PendingIkeDelete::new(&request, sender)).timeout(),
            DeleteOutcome::DiscardIkeAndAllChildren
        );
        assert!(must(PendingIkeDelete::new(&request, sender))
            .response(&response, first, &bytes)
            .is_err());
    }
}

use opc_proto_ikev2::{
    build_create_child_sa_rekey_response_payloads,
    nwu::{all_packet_selectors, AeadPolicy, AeadSuite, CreateRequest, CreateRequestBuild},
    Ikev2CreateChildSaRekeyResponseBuild, Ikev2EncryptionAlgorithm, Ikev2NoncePayloadBuild,
    Ikev2SaPayloadBuild, Ikev2SaProposalBuild, Ikev2SaTransformBuild, Ikev2TransformAttributeBuild,
    Ikev2TransformAttributeBuildValue, EXCHANGE_TYPE_CREATE_CHILD_SA,
};
fn encr(algorithm: Ikev2EncryptionAlgorithm) -> Ikev2SaTransformBuild {
    Ikev2SaTransformBuild {
        transform_type: 1,
        transform_id: algorithm.transform_id(),
        attributes: vec![Ikev2TransformAttributeBuild {
            attribute_type: 14,
            value: Ikev2TransformAttributeBuildValue::Tv(algorithm.key_bits()),
        }],
    }
}
fn create_input() -> CreateRequestBuild<'static> {
    CreateRequestBuild {
        security_association: Ikev2SaPayloadBuild {
            proposals: vec![Ikev2SaProposalBuild {
                proposal_number: 1,
                protocol_id: 3,
                spi: vec![10, 11, 12, 13],
                transforms: vec![
                    encr(Ikev2EncryptionAlgorithm::AesGcm16_128),
                    Ikev2SaTransformBuild {
                        transform_type: 5,
                        transform_id: 0,
                        attributes: vec![],
                    },
                ],
            }],
        },
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x55; 16],
        },
        key_exchange: None,
        inner_families: AddressFamilies::Ipv4,
        up_address: v4(11),
        qos: must(QosInfo::new(5, &[9], true, None, None)),
    }
}
fn create_header(sender: Peer, response: bool) -> Header {
    let mut h = header(sender, response);
    h.exchange_type = EXCHANGE_TYPE_CREATE_CHILD_SA;
    h
}
#[test]
fn independent_full_create_vector_uses_network_initiator_and_all_packet_selectors() {
    // Full synthetic SA/Nonce/TS bodies authored independently of SDK builders.
    let sa = [
        0, 0, 0, 32, 1, 3, 4, 2, 10, 11, 12, 13, 3, 0, 0, 12, 1, 0, 0, 20, 0x80, 14, 0, 128, 0, 0,
        0, 8, 5, 0, 0, 0,
    ];
    let nonce = [0x55; 16];
    let ts = [
        1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255,
    ];
    let (first, mut wire) = independent_chain(&[(33, &sa), (40, &nonce), (44, &ts), (45, &ts)]);
    // Link to the independently published payload-only CREATE notification pair.
    let last = 36 + 20 + 24;
    wire[last] = 41;
    wire.extend(fixture("create-child-sa"));
    let input = create_input();
    assert_eq!(
        must(encode_payloads(&must(input.payloads()))).1.as_ref(),
        wire
    );
    let request = must(CreateRequest::decode(
        &create_header(Peer::Network, false),
        first,
        &wire,
        AddressFamilies::Ipv4,
        Limits::default(),
    ));
    assert_eq!(request.up_address(), v4(11));
    assert_eq!(request.qos().qfis().collect::<Vec<_>>(), [9]);
    assert!(request.qos().is_default());
    assert!(CreateRequest::decode(
        &create_header(Peer::Ue, false),
        first,
        &wire,
        AddressFamilies::Ipv4,
        Limits::default()
    )
    .is_err());
    for len in 0..wire.len() {
        assert!(CreateRequest::decode(
            &create_header(Peer::Network, false),
            first,
            &wire[..len],
            AddressFamilies::Ipv4,
            Limits::default()
        )
        .is_err());
    }
    for families in [
        AddressFamilies::Ipv4,
        AddressFamilies::Ipv6,
        AddressFamilies::Dual,
    ] {
        let mut input = create_input();
        input.inner_families = families;
        input.up_address = if families == AddressFamilies::Ipv6 {
            v6(11)
        } else {
            v4(11)
        };
        let (first, wire) = must(encode_payloads(&must(input.payloads())));
        assert_eq!(
            must(CreateRequest::decode(
                &create_header(Peer::Network, false),
                first,
                &wire,
                families,
                Limits::default()
            ))
            .families(),
            families
        );
    }
}
#[test]
fn create_rejects_multiple_up_addresses_duplicates_missing_and_narrowed_selectors() {
    let input = create_input();
    let payloads = must(input.payloads());
    for i in 0..payloads.len() {
        let mut altered = payloads.clone();
        altered.remove(i);
        let (first, wire) = must(encode_payloads(&altered));
        assert!(CreateRequest::decode(
            &create_header(Peer::Network, false),
            first,
            &wire,
            AddressFamilies::Ipv4,
            Limits::default()
        )
        .is_err());
        altered = payloads.clone();
        altered.push(payloads[i].clone());
        let (first, wire) = must(encode_payloads(&altered));
        assert!(CreateRequest::decode(
            &create_header(Peer::Network, false),
            first,
            &wire,
            AddressFamilies::Ipv4,
            Limits::default()
        )
        .is_err());
    }
    let mut altered = payloads.clone();
    altered.push(Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body: must(Notify::UpAddress(v6(11)).encode_body()),
    });
    let (first, wire) = must(encode_payloads(&altered));
    assert!(CreateRequest::decode(
        &create_header(Peer::Network, false),
        first,
        &wire,
        AddressFamilies::Ipv4,
        Limits::default()
    )
    .is_err());
    let mut altered = payloads.clone();
    altered[2].body[12] = 1;
    let (first, wire) = must(encode_payloads(&altered));
    assert!(CreateRequest::decode(
        &create_header(Peer::Network, false),
        first,
        &wire,
        AddressFamilies::Ipv4,
        Limits::default()
    )
    .is_err());
    let mut altered = payloads;
    altered.push(Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body: vec![3, 4, 0x40, 9, 10, 11, 12, 13],
    });
    let (first, wire) = must(encode_payloads(&altered));
    assert!(CreateRequest::decode(
        &create_header(Peer::Network, false),
        first,
        &wire,
        AddressFamilies::Ipv4,
        Limits::default()
    )
    .is_err());
}
#[test]
fn aead_selection_follows_caller_order_without_integrity_or_fallback() {
    let mut input = create_input();
    let mut second = input.security_association.proposals[0].clone();
    second.proposal_number = 2;
    second.transforms[0] = encr(Ikev2EncryptionAlgorithm::AesGcm16_256);
    input.security_association.proposals.push(second);
    let (first, wire) = must(encode_payloads(&must(input.payloads())));
    let request = must(CreateRequest::decode(
        &create_header(Peer::Network, false),
        first,
        &wire,
        AddressFamilies::Ipv4,
        Limits::default(),
    ));
    let s128 = must(AeadSuite::new(
        Ikev2EncryptionAlgorithm::AesGcm16_128,
        None,
        false,
    ));
    let s256 = must(AeadSuite::new(
        Ikev2EncryptionAlgorithm::AesGcm16_256,
        None,
        false,
    ));
    for suites in [vec![s256, s128], vec![s128, s256]] {
        let selection = must(must(AeadPolicy::new(suites.clone())).select(&request));
        assert_eq!(selection.suite(), suites[0]);
        let sa = selection.response_sa(must(EspSpi::new([1, 2, 3, 4])));
        assert!(!sa.proposals[0]
            .transforms
            .iter()
            .any(|t| t.transform_type == 3));
        let response = must(build_create_child_sa_rekey_response_payloads(
            &Ikev2CreateChildSaRekeyResponseBuild {
                security_association: sa,
                nonce: Ikev2NoncePayloadBuild {
                    nonce: vec![0x66; 16],
                },
                key_exchange: None,
                traffic_selectors_initiator: all_packet_selectors(AddressFamilies::Ipv4),
                traffic_selectors_responder: all_packet_selectors(AddressFamilies::Ipv4),
            },
        ));
        let (first, wire) = must(encode_payloads(&response.into_payloads()));
        assert!(request
            .accepted_response(
                &create_header(Peer::Ue, true),
                first,
                &wire,
                Limits::default()
            )
            .is_ok());
        let mut wrong = create_header(Peer::Ue, true);
        wrong.message_id += 1;
        assert!(request
            .accepted_response(&wrong, first, &wire, Limits::default())
            .is_err());
    }
    let absent = must(AeadSuite::new(
        Ikev2EncryptionAlgorithm::AesGcm16_192,
        None,
        false,
    ));
    assert!(must(AeadPolicy::new(vec![absent]))
        .select(&request)
        .is_err());
    assert!(AeadSuite::new(Ikev2EncryptionAlgorithm::AesCbc128, None, false).is_err());
    assert!(AeadPolicy::new(vec![]).is_err());
    assert!(AeadPolicy::new(vec![s128, s128]).is_err());
    input.security_association.proposals.truncate(1);
    input.security_association.proposals[0].transforms[0] =
        encr(Ikev2EncryptionAlgorithm::AesCbc128);
    input.security_association.proposals[0]
        .transforms
        .push(Ikev2SaTransformBuild {
            transform_type: 3,
            transform_id: 2,
            attributes: vec![],
        });
    let (first, wire) = must(encode_payloads(&must(input.payloads())));
    let request = must(CreateRequest::decode(
        &create_header(Peer::Network, false),
        first,
        &wire,
        AddressFamilies::Ipv4,
        Limits::default(),
    ));
    assert!(must(AeadPolicy::new(vec![s128])).select(&request).is_err());
    // Separate integrity alongside AEAD is invalid even before policy selection.
    input.security_association.proposals[0].transforms[0] =
        encr(Ikev2EncryptionAlgorithm::AesGcm16_128);
    assert!(input.payloads().is_err());
}
