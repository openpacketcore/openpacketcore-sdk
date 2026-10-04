use opc_proto_eap::eap5g::{
    AnParameters, BootstrapRequirements, DuplicatePolicy, Error, EstablishmentCause, Guami,
    GuamiType, Limits, Message, NasPdu, Nid, Packet, PlmnId, Presence, RequestedNssai, HEADER_LEN,
};
use opc_proto_eap::EapCode;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../opc-n3iwf-fixtures/fixtures/eap5g/wire")
        .join(format!("{name}.hex"));
    std::fs::read_to_string(path)
        .expect("published synthetic fixture")
        .split_whitespace()
        .map(|part| u8::from_str_radix(part, 16).expect("fixture hex"))
        .collect()
}

#[test]
fn constructed_start_matches_independent_published_fixture() {
    let packet = Packet::new(1, Message::Start);
    assert!(packet.encode(Limits::default()).expect("encode") == fixture("positive-start"));
}

#[test]
fn bootstrap_preserves_opaque_nas_from_independent_fixture() {
    let wire = fixture("positive-nas-response");
    let packet = Packet::parse(&wire, Limits::default()).expect("parse");
    let Message::NasResponse { parameters, nas } = packet.message() else {
        panic!("wrong message kind");
    };
    assert!(parameters.selected_plmn.is_some());
    assert!(nas.as_bytes() == [0x7e, 0, 0x41]);
    assert!(packet.encode(Limits::default()).expect("encode") == wire);
}

// Independent test authoring: these helpers assemble the TS 24.502 fields
// directly, without calling the SDK encoder. Assertions never print raw bytes.
fn wire(code: u8, message: u8, body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(HEADER_LEN + body.len()).expect("synthetic length");
    let mut out = vec![code, 9, 0, 0, 254, 0, 0x28, 0xaf, 0, 0, 0, 3, message, 0];
    out[2..4].copy_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn response(an: &[u8], nas: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u16::try_from(an.len()).expect("AN length").to_be_bytes());
    body.extend_from_slice(an);
    body.extend_from_slice(&u16::try_from(nas.len()).expect("NAS length").to_be_bytes());
    body.extend_from_slice(nas);
    wire(2, 2, &body)
}

fn parameters(wire: &[u8], limits: Limits) -> AnParameters<'_> {
    let Message::NasResponse { parameters, .. } =
        Packet::parse(wire, limits).expect("parse").message()
    else {
        panic!("response expected");
    };
    parameters
}

fn rejects(wire: &[u8], error: Error) {
    assert_eq!(
        Packet::parse(wire, Limits::default()).expect_err("must reject"),
        error
    );
}

#[test]
fn all_published_eap5g_cases_have_explicit_dispositions() {
    for name in [
        "positive-start",
        "positive-nas-response",
        "positive-notification",
        "positive-stop",
        "ordering-an-parameters",
        "unknown-parameter-ignored",
    ] {
        assert!(
            Packet::parse(&fixture(name), Limits::default()).is_ok(),
            "case {name}"
        );
    }
    assert_eq!(
        parameters(&fixture("unknown-parameter-ignored"), Limits::default()).ignored_count(),
        1
    );
    rejects(&fixture("malformed-length"), Error::LengthMismatch);
    rejects(&fixture("unknown-message-id"), Error::UnsupportedMessage);
    rejects(&fixture("truncated-start"), Error::Truncated);
    rejects(&fixture("bounded-an-parameter-overflow"), Error::Truncated);
    rejects(
        &fixture("duplicate-selected-plmn"),
        Error::DuplicateParameter,
    );
    let duplicate = fixture("duplicate-selected-plmn");
    let p = parameters(
        &duplicate,
        Limits {
            duplicates: DuplicatePolicy::FirstWins,
            ..Limits::default()
        },
    );
    assert_eq!(p.duplicate_count(), 1);
}

#[test]
fn constructs_every_supported_direction_against_spec_authored_bytes() {
    let limits = Limits::default();
    let nas = NasPdu::new(&[0xde, 0xad, 0, 0xbe, 0xef]).expect("opaque synthetic NAS");
    for (message, expected) in [
        (Message::Start, wire(1, 1, &[])),
        (Message::Stop, wire(2, 4, &[])),
        (Message::NotificationRequest, wire(1, 3, &[0, 0])),
        (Message::NotificationResponse, wire(2, 3, &[])),
        (
            Message::NasRequest(nas),
            wire(1, 2, &[0, 5, 0xde, 0xad, 0, 0xbe, 0xef]),
        ),
        (
            Message::NasResponse {
                parameters: AnParameters::default(),
                nas,
            },
            response(&[], nas.as_bytes()),
        ),
    ] {
        let packet = Packet::new(9, message);
        assert!(packet.encode(limits).expect("encode") == expected);
        let parsed = Packet::parse(&expected, limits).expect("parse");
        assert_eq!(parsed.identifier(), 9);
        assert_eq!(
            parsed.code(),
            if expected[0] == 1 {
                EapCode::Request
            } else {
                EapCode::Response
            }
        );
    }
}

#[test]
fn typed_bootstrap_fields_match_independent_wire_in_every_parameter_order() {
    // Test PLMN 001/01; synthetic GUAMI, NID and slices. No captured traffic.
    let tlvs: &[&[u8]] = &[
        &[1, 6, 0, 0xf1, 0x10, 1, 2, 3],
        &[2, 3, 0, 0xf1, 0x10],
        &[3, 7, 1, 1, 4, 1, 2, 3, 4],
        &[4, 1, 3],
        &[5, 6, 0x10, 0x32, 0x54, 0x76, 0x98, 0x0a],
        &[7, 0],
        &[8, 1, 1],
    ];
    let mut p = AnParameters::default();
    p.guami = Some(Guami::from_octets([0, 0xf1, 0x10, 1, 2, 3]).expect("GUAMI"));
    p.selected_plmn = Some(PlmnId::from_octets([0, 0xf1, 0x10]).expect("PLMN"));
    p.requested_nssai = Some(RequestedNssai::from_value(&[1, 1, 4, 1, 2, 3, 4]).expect("NSSAI"));
    p.establishment_cause = Some(EstablishmentCause::MoSignalling);
    p.selected_nid = Some(Nid::from_octets([0x10, 0x32, 0x54, 0x76, 0x98, 0x0a]));
    p.onboarding = true;
    p.guami_type = Some(GuamiType::Native);
    let expected = response(&tlvs.concat(), &[0xff, 0, 0xff]);
    let constructed = Packet::new(
        9,
        Message::NasResponse {
            parameters: p,
            nas: NasPdu::new(&[0xff, 0, 0xff]).expect("NAS"),
        },
    );
    assert!(constructed.encode(Limits::default()).expect("encode") == expected);
    // Exhaust all 7! orders. Canonical sender order is not a receive restriction.
    fn permutations(parts: &mut [&[u8]], start: usize, expected: &[u8]) {
        if start == parts.len() {
            let data = response(&parts.concat(), &[0xff, 0, 0xff]);
            let packet = Packet::parse(&data, Limits::default()).expect("permuted parameters");
            assert!(packet.encode(Limits::default()).expect("canonical encode") == expected);
            return;
        }
        for i in start..parts.len() {
            parts.swap(start, i);
            permutations(parts, start + 1, expected);
            parts.swap(start, i);
        }
    }
    permutations(&mut tlvs.to_vec(), 0, &expected);
}

#[test]
fn bootstrap_presence_uses_explicit_context_without_reading_nas() {
    let data = fixture("positive-nas-response");
    let mut p = parameters(&data, Limits::default());
    p.validate_bootstrap(BootstrapRequirements::default())
        .expect("base profile");
    for requirements in [
        BootstrapRequirements {
            guami: Presence::Required,
            ..Default::default()
        },
        BootstrapRequirements {
            requested_nssai: Presence::Required,
            ..Default::default()
        },
        BootstrapRequirements {
            selected_nid: Presence::Required,
            ..Default::default()
        },
        BootstrapRequirements {
            onboarding: Presence::Required,
            ..Default::default()
        },
    ] {
        assert_eq!(
            p.validate_bootstrap(requirements),
            Err(Error::ParameterPresence)
        );
    }
    p.selected_nid = Some(Nid::from_octets([0; 6]));
    p.onboarding = true;
    p.validate_bootstrap(BootstrapRequirements {
        selected_nid: Presence::Required,
        onboarding: Presence::Required,
        ..Default::default()
    })
    .expect("SNPN onboarding profile");
    assert_eq!(
        p.validate_bootstrap(BootstrapRequirements {
            selected_nid: Presence::Absent,
            ..Default::default()
        }),
        Err(Error::ParameterPresence)
    );
    p.selected_plmn = None;
    assert_eq!(
        p.validate_bootstrap(BootstrapRequirements::default()),
        Err(Error::ParameterPresence)
    );
    p.selected_plmn = Some(PlmnId::from_octets([0, 0xf1, 0x10]).expect("PLMN"));
    p.establishment_cause = None;
    assert_eq!(
        p.validate_bootstrap(BootstrapRequirements::default()),
        Err(Error::ParameterPresence)
    );
    // Later NAS responses do not acquire initial-response requirements.
    assert!(Packet::parse(&response(&[], &[0]), Limits::default()).is_ok());
}

#[test]
fn ignores_spare_bits_extensions_and_spare_types_but_not_known_unsupported_types() {
    for (code, id, body) in [
        (1, 1, vec![]),
        (2, 4, vec![]),
        (2, 3, vec![]),
        (1, 3, vec![0, 0]),
        (1, 2, vec![0, 1, 0x80]),
    ] {
        let mut extended = body.clone();
        extended.extend_from_slice(&[0xfe, 0xdc, 0xba]);
        let mut data = wire(code, id, &extended);
        data[13] = 0xff;
        let parsed = Packet::parse(&data, Limits::default()).expect("receive spare bits");
        assert!(
            parsed.encode(Limits::default()).expect("canonical encode") == wire(code, id, &body)
        );
    }
    let mut data = response(&[0xff, 0, 0xfe, 2, 0xaa, 0xbb], &[0]);
    // Two-octet extended-AN block length, then type/u16 length/value, then spares.
    data.extend_from_slice(&[0, 4, 0xff, 0, 1, 0xee, 0xff, 0xff]);
    let length = data.len() as u16;
    data[2..4].copy_from_slice(&length.to_be_bytes());
    assert_eq!(parameters(&data, Limits::default()).ignored_count(), 3);
    rejects(&response(&[6, 1, 0], &[0]), Error::UnsupportedParameter);
    rejects(&wire(1, 3, &[0, 2, 1, 0]), Error::UnsupportedParameter);
    let mut data = response(&[], &[0]);
    data.extend_from_slice(&[0, 4, 6, 0, 1, 0]);
    let length = data.len() as u16;
    data[2..4].copy_from_slice(&length.to_be_bytes());
    rejects(&data, Error::UnsupportedParameter);
}

#[test]
fn duplicate_policy_validates_later_values_and_counts_spares_separately() {
    let an = [2, 3, 0, 0xf1, 0x10, 2, 3, 0, 0xf1, 0x20, 0xff, 0, 0xff, 0];
    let data = response(&an, &[1]);
    let limits = Limits {
        duplicates: DuplicatePolicy::FirstWins,
        ..Default::default()
    };
    let p = parameters(&data, limits);
    assert!(p.selected_plmn.expect("PLMN").to_octets() == [0, 0xf1, 0x10]);
    assert_eq!(p.duplicate_count(), 1);
    assert_eq!(p.ignored_count(), 2);
    rejects(&data, Error::DuplicateParameter);
    let data = response(&[2, 3, 0, 0xf1, 0x10, 2, 1, 0], &[1]);
    assert_eq!(
        Packet::parse(&data, limits).expect_err("malformed duplicate"),
        Error::InvalidParameter
    );
}

#[test]
fn validates_parameter_lengths_nested_nssai_bcd_and_spare_cause_behavior() {
    for an in [
        vec![1, 5, 0, 0xf1, 0x10, 0, 0],
        vec![2, 2, 0, 0xf1],
        vec![2, 3, 0xfa, 0xf1, 0x10],
        vec![3, 0],
        vec![3, 2, 3, 1],
        vec![4, 2, 0, 0],
        vec![5, 5, 0, 0, 0, 0, 0],
        vec![7, 1, 0],
        vec![8, 0],
    ] {
        rejects(&response(&an, &[1]), Error::InvalidParameter);
    }
    rejects(&response(&[8, 1, 1], &[1]), Error::ParameterPresence);
    assert!(Packet::parse(&response(&[8, 1, 0xff], &[1]), Limits::default()).is_ok());
    for (input, expected) in [
        (0xf3, EstablishmentCause::MoSignalling),
        (0xf2, EstablishmentCause::MoData),
        (0xff, EstablishmentCause::MoData),
    ] {
        let data = response(&[4, 1, input], &[1]);
        assert_eq!(
            parameters(&data, Limits::default()).establishment_cause,
            Some(expected)
        );
    }
    assert!(Nid::from_octets([0, 0, 0, 0, 0, 0xfa]).to_octets() == [0, 0, 0, 0, 0, 0x0a]);
    for size in [1, 2, 4, 5, 8] {
        let mut value = vec![size];
        value.resize(1 + usize::from(size), 1);
        assert_eq!(
            RequestedNssai::from_value(&value)
                .expect("S-NSSAI length")
                .count(),
            1
        );
    }
    assert_eq!(
        RequestedNssai::from_value(&[1, 1].repeat(8))
            .expect("eight slices")
            .count(),
        8
    );
    assert_eq!(
        RequestedNssai::from_value(&[1, 1].repeat(9)).expect_err("nine slices"),
        Error::InvalidParameter
    );
    for value in [
        &[0][..],
        &[3, 1, 2, 3],
        &[4, 1, 2, 3],
        &[9, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    ] {
        assert_eq!(
            RequestedNssai::from_value(value).expect_err("bad S-NSSAI"),
            Error::InvalidParameter
        );
    }
}

#[test]
fn malformed_lengths_directions_and_empty_nas_are_rejected() {
    for (code, id) in [(2, 1), (1, 4), (3, 1), (4, 2), (0, 3), (1, 0xff)] {
        rejects(&wire(code, id, &[]), Error::UnsupportedMessage);
    }
    rejects(&wire(1, 2, &[0, 0]), Error::EmptyNas);
    rejects(&response(&[], &[]), Error::EmptyNas);
    rejects(&wire(1, 2, &[0, 2, 0]), Error::Truncated);
    rejects(&wire(2, 2, &[0, 1, 0xff, 0, 1, 0]), Error::Truncated);
    let good = fixture("positive-nas-response");
    for cut in 0..good.len() {
        assert!(Packet::parse(&good[..cut], Limits::default()).is_err());
        if cut >= HEADER_LEN {
            let mut data = good[..cut].to_vec();
            data[2..4].copy_from_slice(&(cut as u16).to_be_bytes());
            assert!(Packet::parse(&data, Limits::default()).is_err());
        }
    }
    for field in [2, 3, 14, 15, 24, 25] {
        for octet in 0..=255 {
            if good[field] == octet {
                continue;
            }
            let mut altered = good.clone();
            altered[field] = octet;
            assert!(
                Packet::parse(&altered, Limits::default()).is_err(),
                "length field {field}"
            );
        }
    }
    for field in 4..12 {
        let mut data = good.clone();
        data[field] ^= 1;
        rejects(&data, Error::UnsupportedMethod);
    }
    for extra in [&[0][..], &[0, 1], &[0, 3, 0xff, 0, 0]] {
        let mut data = response(&[], &[1]);
        data.extend_from_slice(extra);
        let len = data.len() as u16;
        data[2..4].copy_from_slice(&len.to_be_bytes());
        assert!(Packet::parse(&data, Limits::default()).is_err());
    }
}

#[test]
fn eap_maximum_includes_exact_request_response_and_an_headers() {
    let limits = Limits::default();
    for (is_response, overhead) in [(false, 16), (true, 18)] {
        let bytes = vec![0x80; usize::from(u16::MAX) - overhead];
        let nas = NasPdu::new(&bytes).expect("bounded NAS");
        let message = if is_response {
            Message::NasResponse {
                parameters: AnParameters::default(),
                nas,
            }
        } else {
            Message::NasRequest(nas)
        };
        let packet = Packet::new(9, message);
        assert_eq!(packet.encoded_len(limits), Ok(65535));
        let encoded = packet.encode(limits).expect("maximum");
        assert!(encoded[2..4] == [255, 255]);
        let parsed = Packet::parse(&encoded, limits).expect("maximum receive");
        assert_eq!(parsed.encoded_len(limits), Ok(65535));
        let mut too_large = encoded;
        too_large.push(0);
        rejects(&too_large, Error::LimitExceeded);
    }
    let bytes = vec![0x80; 65518];
    let nas = NasPdu::new(&bytes).expect("fits request but not response");
    let response = Packet::new(
        1,
        Message::NasResponse {
            parameters: AnParameters::default(),
            nas,
        },
    );
    assert_eq!(response.encoded_len(limits), Err(Error::LimitExceeded));
    let mut untouched = [0xa5; 32];
    assert_eq!(
        response.encode_into(&mut untouched, limits),
        Err(Error::LimitExceeded)
    );
    assert!(untouched == [0xa5; 32]);
    let mut p = AnParameters::default();
    p.selected_plmn = Some(PlmnId::from_octets([0, 0xf1, 0x10]).expect("PLMN"));
    let bytes = vec![0x80; 65512];
    let packet = Packet::new(
        9,
        Message::NasResponse {
            parameters: p,
            nas: NasPdu::new(&bytes).expect("NAS"),
        },
    );
    assert_eq!(packet.encoded_len(limits), Ok(65535));
    let bytes = vec![0; 65520];
    assert_eq!(
        NasPdu::new(&bytes).expect_err("NAS cannot fit envelope"),
        Error::LimitExceeded
    );
}

#[test]
fn caller_bounds_are_inclusive_and_failed_encoding_does_not_touch_output() {
    let data = fixture("positive-nas-response");
    let limits = Limits {
        max_packet_len: 29,
        max_an_bytes: 8,
        max_parameters: 2,
        ..Default::default()
    };
    let packet = Packet::parse(&data, limits).expect("inclusive bounds");
    assert!(packet.encode(limits).is_ok());
    for smaller in [
        Limits {
            max_packet_len: 28,
            ..limits
        },
        Limits {
            max_an_bytes: 7,
            ..limits
        },
        Limits {
            max_parameters: 1,
            ..limits
        },
    ] {
        assert_eq!(
            Packet::parse(&data, smaller).expect_err("receive limit"),
            Error::LimitExceeded
        );
        let mut output = [0xa5; 30];
        assert_eq!(
            packet.encode_into(&mut output, smaller),
            Err(Error::LimitExceeded)
        );
        assert!(output == [0xa5; 30]);
    }
    let mut output = [0xa5; 28];
    assert_eq!(
        packet.encode_into(&mut output, limits),
        Err(Error::OutputTooSmall)
    );
    assert!(output == [0xa5; 28]);
    let data = response(&[0xff, 0, 0xff, 0], &[0]);
    let limits = Limits {
        max_parameters: 1,
        ..Default::default()
    };
    assert_eq!(
        Packet::parse(&data, limits).expect_err("spares also count"),
        Error::LimitExceeded
    );
    let mut data = response(&[0xff, 0], &[0]);
    data.extend_from_slice(&[0, 4, 0xff, 0, 1, 0]);
    let len = data.len() as u16;
    data[2..4].copy_from_slice(&len.to_be_bytes());
    assert_eq!(
        Packet::parse(&data, limits).expect_err("extended count"),
        Error::LimitExceeded
    );
    assert_eq!(
        Packet::parse(
            &data,
            Limits {
                max_an_bytes: 5,
                ..Default::default()
            }
        )
        .expect_err("combined AN bound"),
        Error::LimitExceeded
    );
}

#[test]
fn private_bytes_never_reach_debug_or_errors() {
    let marker = b"SYNTHETIC_PRIVATE_NAS_SENTINEL";
    let data = response(&[0xff, 4, b'H', b'I', b'D', b'E'], marker);
    let packet = Packet::parse(&data, Limits::default()).expect("opaque private NAS");
    let text = format!("{packet:?} {:?}", packet.message());
    for forbidden in [
        "SYNTHETIC_PRIVATE_NAS_SENTINEL",
        "HIDE",
        "83, 89, 78",
        "48, 49, 44, 45",
    ] {
        assert!(!text.contains(forbidden));
    }
    for cut in 0..data.len() {
        let error = Packet::parse(&data[..cut], Limits::default()).expect_err("truncated");
        assert!(!format!("{error:?} {error}").contains("SYNTHETIC_PRIVATE"));
    }
    assert_eq!(
        format!("{:?}", PlmnId::from_octets([0, 0xf1, 0x10]).expect("PLMN")),
        "PlmnId([REDACTED])"
    );
    assert_eq!(
        format!(
            "{:?}",
            Guami::from_octets([0, 0xf1, 0x10, 1, 2, 3]).expect("GUAMI")
        ),
        "Guami([REDACTED])"
    );
    assert_eq!(format!("{:?}", Nid::from_octets([0; 6])), "Nid([REDACTED])");
}
