use bytes::BytesMut;
use opc_proto_gtpv2c::n1_mode::{
    IndicationFlag, N1ModeApcoError, N1ModeApcoRequest, N1ModeApcoResponse, PduSessionId,
    PlmnIdentity, SnssaiValue, N1_MODE_APCO_MAX_CONTAINERS, N1_MODE_APCO_MAX_CONTENTS_LEN,
};
use opc_proto_gtpv2c::{AdditionalProtocolConfigurationOptions, Indication, TypedIe, TypedIeValue};
use opc_protocol::{DecodeContext, EncodeContext};

// TS 24.008 V20.0.0 §10.5.6.3: no nested NAS IEI/length around the slice.
const REQUEST: &[u8] = &[0x80, 0, 0x1a, 1, 7];
const RESPONSE: &[u8] = &[0x80, 0, 0x1b, 7, 1, 0x12, 0x34, 0x56, 0x00, 0xf1, 0x10];

fn apco(value: &[u8]) -> AdditionalProtocolConfigurationOptions {
    AdditionalProtocolConfigurationOptions {
        value: value.to_vec(),
    }
}

fn request() -> N1ModeApcoRequest {
    N1ModeApcoRequest::new(PduSessionId::new(7).unwrap())
}

fn response() -> N1ModeApcoResponse {
    N1ModeApcoResponse::new(
        SnssaiValue::from_bytes(&[1, 0x12, 0x34, 0x56]).unwrap(),
        PlmnIdentity::from_bytes([0, 0xf1, 0x10]).unwrap(),
    )
}

#[test]
fn directional_codecs_match_independent_apco_vectors() {
    assert_eq!(request().encode_apco().value, REQUEST);
    assert_eq!(response().encode_apco().value, RESPONSE);
    assert_eq!(
        N1ModeApcoRequest::decode(&apco(REQUEST)),
        Ok(Some(request()))
    );
    assert_eq!(
        N1ModeApcoResponse::decode(&apco(RESPONSE)),
        Ok(Some(response()))
    );
    assert_eq!(request().pdu_session_id().value(), 7);
    assert_eq!(response().snssai().as_bytes(), &RESPONSE[4..8]);
    assert_eq!(response().plmn_id().as_bytes(), &[0, 0xf1, 0x10]);
}

#[test]
fn opposite_direction_reserved_identifiers_are_ignored() {
    assert_eq!(N1ModeApcoRequest::decode(&apco(RESPONSE)), Ok(None));
    assert_eq!(N1ModeApcoResponse::decode(&apco(REQUEST)), Ok(None));
    let both = [REQUEST, &RESPONSE[1..]].concat();
    assert_eq!(N1ModeApcoRequest::decode(&apco(&both)), Ok(Some(request())));
    assert_eq!(
        N1ModeApcoResponse::decode(&apco(&both)),
        Ok(Some(response()))
    );
}

#[test]
fn all_slice_forms_keep_the_associated_plmn() {
    for slice in [
        &[1][..],
        &[1, 2],
        &[1, 2, 3, 4],
        &[1, 2, 3, 4, 5],
        &[1, 2, 3, 4, 5, 6, 7, 8],
    ] {
        for plmn in [[0, 0xf1, 0x10], [0x13, 0, 0x62]] {
            let typed = N1ModeApcoResponse::new(
                SnssaiValue::from_bytes(slice).unwrap(),
                PlmnIdentity::from_bytes(plmn).unwrap(),
            );
            let encoded = typed.encode_apco();
            assert_eq!(usize::from(encoded.value[3]), slice.len() + 3);
            assert_eq!(&encoded.value[4..4 + slice.len()], slice);
            assert_eq!(&encoded.value[4 + slice.len()..], plmn);
            assert_eq!(N1ModeApcoResponse::decode(&encoded), Ok(Some(typed)));
        }
    }
}

#[test]
fn s2b_encoding_uses_apco_163_instance_zero() {
    for (ie, value) in [
        (request().to_s2b_ie(), REQUEST),
        (response().to_s2b_ie(), RESPONSE),
    ] {
        assert_eq!(ie.instance, 0);
        let mut wire = BytesMut::new();
        ie.encode(&mut wire, EncodeContext::default()).unwrap();
        assert_eq!(&wire[..4], &[163, 0, value.len() as u8, 0]);
        assert_eq!(&wire[4..], value);
        let decoded = TypedIe::decode_sequence(&wire, DecodeContext::default()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(matches!(
            decoded[0].value,
            TypedIeValue::AdditionalProtocolConfigurationOptions(_)
        ));
    }
}

#[test]
fn append_preserves_existing_ipcp_dns_pcscf_and_unknown_units() {
    let existing = apco(&[
        0x80, 0x80, 0x21, 4, 1, 9, 0, 4, // opaque IPCP unit
        0, 0x0c, 0, 0, 0x0d, 0, // P-CSCF and DNS requests
        0xee, 0x01, 2, 0xaa, 0xbb, // unknown unit
    ]);
    let before = existing.value.clone();
    let extended = request().append_to(&existing).unwrap();
    assert_eq!(&extended.value[..before.len()], &before);
    assert_eq!(&extended.value[before.len()..], &REQUEST[1..]);
    assert_eq!(existing.value, before);
    assert_eq!(N1ModeApcoRequest::decode(&extended), Ok(Some(request())));
    assert_eq!(
        response().append_to(&apco(&[0x80])).unwrap().value,
        RESPONSE
    );
}

#[test]
fn receiver_accepts_configuration_protocol_fallback_and_spare_bits() {
    for header in 0x80..=0xff {
        let mut wire = REQUEST.to_vec();
        wire[0] = header;
        assert_eq!(N1ModeApcoRequest::decode(&apco(&wire)), Ok(Some(request())));
    }
}

#[test]
fn duplicate_n1_containers_are_rejected_even_when_identical() {
    for wire in [REQUEST, RESPONSE] {
        let duplicated = [wire, &wire[1..]].concat();
        let result = if wire == REQUEST {
            N1ModeApcoRequest::decode(&apco(&duplicated)).map(|_| ())
        } else {
            N1ModeApcoResponse::decode(&apco(&duplicated)).map(|_| ())
        };
        assert_eq!(result, Err(N1ModeApcoError::DuplicateContainer));
    }
    assert_eq!(
        request().append_to(&apco(REQUEST)),
        Err(N1ModeApcoError::DuplicateContainer)
    );
    assert_eq!(
        response().append_to(&apco(RESPONSE)),
        Err(N1ModeApcoError::DuplicateContainer)
    );
    let mut conflict = REQUEST.to_vec();
    conflict.extend_from_slice(&[0, 0x1a, 1, 8]);
    assert_eq!(
        N1ModeApcoRequest::decode(&apco(&conflict)),
        Err(N1ModeApcoError::DuplicateContainer)
    );
}

#[test]
fn invalid_n1_value_shapes_are_reported_without_values() {
    for wire in [
        &[0x80, 0, 0x1a, 0][..],
        &[0x80, 0, 0x1a, 2, 1, 2],
        &[0x80, 0, 0x1a, 1, 255],
    ] {
        assert_eq!(
            N1ModeApcoRequest::decode(&apco(wire)),
            Err(N1ModeApcoError::InvalidPduSessionId)
        );
    }
    for len in [0u8, 1, 2, 3, 6, 9, 10, 12] {
        let mut wire = vec![0x80, 0, 0x1b, len];
        wire.extend(std::iter::repeat_n(0, usize::from(len)));
        assert_eq!(
            N1ModeApcoResponse::decode(&apco(&wire)),
            Err(N1ModeApcoError::InvalidSnssai)
        );
    }
    let invalid_plmn = [0x80, 0, 0x1b, 4, 1, 0xfa, 0xff, 0xff];
    assert_eq!(
        N1ModeApcoResponse::decode(&apco(&invalid_plmn)),
        Err(N1ModeApcoError::InvalidPlmnIdentity)
    );
}

#[test]
fn framing_is_checked_through_the_end_including_unknown_units() {
    for wire in [
        &[][..],
        &[0],
        &[0x80, 0],
        &[0x80, 0, 0x1a],
        &[0x80, 0, 0x1a, 2, 7],
    ] {
        assert!(N1ModeApcoRequest::decode(&apco(wire)).is_err());
    }
    for tail in [&[0xff][..], &[0xee, 1, 3, 0]] {
        let wire = [REQUEST, tail].concat();
        assert!(N1ModeApcoRequest::decode(&apco(&wire)).is_err());
    }
}

#[test]
fn two_octet_length_units_cannot_hide_or_forge_n1_containers() {
    // 0x0041 has a two-octet length in BOTH directions. Embedded 0x001a is data.
    let mut wire = vec![0x80, 0, 0x41, 0, 4, 0, 0x1a, 1, 15];
    wire.extend_from_slice(&REQUEST[1..]);
    assert_eq!(N1ModeApcoRequest::decode(&apco(&wire)), Ok(Some(request())));
    // 0x0023 has a two-octet length in the network-to-MS direction only.
    let mut reply = vec![0x80, 0, 0x23, 0, 4, 0, 0x1b, 1, 15];
    reply.extend_from_slice(&RESPONSE[1..]);
    assert_eq!(
        N1ModeApcoResponse::decode(&apco(&reply)),
        Ok(Some(response()))
    );
    assert!(N1ModeApcoResponse::decode(&apco(&[0x80, 0, 0x23, 0])).is_err());
    assert!(N1ModeApcoRequest::decode(&apco(&[0x80, 0, 0x41, 1, 0])).is_err());
}

#[test]
fn nssaa_eap_cannot_forge_a_request_identity() {
    // TS 24.008 V20.0.0: 0061H encloses one opaque six-octet EAP message.
    let wire = [0x80, 0, 0x61, 0, 6, 0xee, 0, 0, 0x1a, 1, 15];
    assert_eq!(N1ModeApcoRequest::decode(&apco(&wire)), Ok(None));
}

#[test]
fn nssaa_eap_cannot_hide_a_request_identity() {
    let wire = [0x80, 0, 0x61, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0x1a, 1, 7];
    assert_eq!(N1ModeApcoRequest::decode(&apco(&wire)), Ok(Some(request())));
}

#[test]
fn nssaa_eap_cannot_forge_a_response_slice() {
    let wire = [
        0x80, 0, 0x61, 0, 12, 0xee, 0, 0, 0x1b, 7, 1, 0x12, 0x34, 0x56, 0, 0xf1, 0x10,
    ];
    assert_eq!(N1ModeApcoResponse::decode(&apco(&wire)), Ok(None));
}

#[test]
fn nssaa_eap_cannot_hide_a_response_slice() {
    let wire = [
        0x80, 0, 0x61, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0x1b, 7, 1, 0x12, 0x34, 0x56, 0, 0xf1, 0x10,
    ];
    assert_eq!(
        N1ModeApcoResponse::decode(&apco(&wire)),
        Ok(Some(response()))
    );
}

#[test]
fn nssaa_status_keeps_one_octet_request_length() {
    // TS 24.008 V20.0.0: 0062H is reserved in this direction and still uses
    // one-octet framing; it is NSSAA status from network to MS.
    let status = apco(&[0x80, 0, 0x62, 1, 1]);
    assert_eq!(N1ModeApcoRequest::decode(&status), Ok(None));
    let with_request = [status.value.as_slice(), &REQUEST[1..]].concat();
    assert_eq!(
        N1ModeApcoRequest::decode(&apco(&with_request)),
        Ok(Some(request()))
    );
    assert_eq!(request().append_to(&status).unwrap().value, with_request);
    assert_eq!(status.value, [0x80, 0, 0x62, 1, 1]);
}

#[test]
fn nssaa_status_keeps_one_octet_response_length() {
    let status = apco(&[0x80, 0, 0x62, 1, 1]);
    assert_eq!(N1ModeApcoResponse::decode(&status), Ok(None));
    let with_response = [status.value.as_slice(), &RESPONSE[1..]].concat();
    assert_eq!(
        N1ModeApcoResponse::decode(&apco(&with_response)),
        Ok(Some(response()))
    );
    assert_eq!(response().append_to(&status).unwrap().value, with_response);
    assert_eq!(status.value, [0x80, 0, 0x62, 1, 1]);
}

#[test]
fn every_two_octet_identifier_obeys_its_directional_length_rule() {
    fn opaque_unit(identifier: u16, length_octets: usize, payload: &[u8]) -> Vec<u8> {
        let mut wire = vec![0x80];
        wire.extend_from_slice(&identifier.to_be_bytes());
        if length_octets == 2 {
            wire.push(0);
        }
        wire.push(u8::try_from(payload.len()).unwrap());
        wire.extend_from_slice(payload);
        wire
    }

    // Independent TS 24.008 V20.0.0 table: all eight earlier identifiers and
    // NSSAA EAP (0061H). The second column is the MS-to-network length width;
    // all nine use two octets from network to MS. The prefix also forms an
    // empty unknown unit if a two-octet length is wrongly read as one octet.
    for (identifier, request_length_octets) in [
        (0x0023, 1),
        (0x0024, 1),
        (0x0030, 1),
        (0x0031, 1),
        (0x0032, 1),
        (0x0041, 2),
        (0x0051, 2),
        (0x0056, 2),
        (0x0061, 2),
    ] {
        let unknown_request = opaque_unit(
            identifier,
            request_length_octets,
            &[0xee, 0, 0, 0x1a, 1, 15],
        );
        assert_eq!(
            N1ModeApcoRequest::decode(&apco(&unknown_request)),
            Ok(None),
            "MS-to-network {identifier:#06x} cannot forge an identity"
        );
        let with_request = [unknown_request.as_slice(), &REQUEST[1..]].concat();
        assert_eq!(
            N1ModeApcoRequest::decode(&apco(&with_request)),
            Ok(Some(request())),
            "MS-to-network {identifier:#06x} cannot hide an identity"
        );
        assert_eq!(
            request().append_to(&apco(&unknown_request)).unwrap().value,
            with_request,
            "MS-to-network {identifier:#06x} is preserved by append"
        );

        let unknown_response = opaque_unit(identifier, 2, &[0xee, 0, 0, 0x1b, 4, 2, 0, 0xf1, 0x10]);
        assert_eq!(
            N1ModeApcoResponse::decode(&apco(&unknown_response)),
            Ok(None),
            "network-to-MS {identifier:#06x} cannot forge a slice"
        );
        let with_response = [unknown_response.as_slice(), &RESPONSE[1..]].concat();
        assert_eq!(
            N1ModeApcoResponse::decode(&apco(&with_response)),
            Ok(Some(response())),
            "network-to-MS {identifier:#06x} cannot hide a slice"
        );
        assert_eq!(
            response()
                .append_to(&apco(&unknown_response))
                .unwrap()
                .value,
            with_response,
            "network-to-MS {identifier:#06x} is preserved by append"
        );
    }
}

#[test]
fn container_and_ordinary_apco_byte_bounds_are_enforced_before_append() {
    let mut units = vec![0x80];
    for _ in 0..N1_MODE_APCO_MAX_CONTAINERS {
        units.extend_from_slice(&[0xee, 0, 0]);
    }
    assert_eq!(N1ModeApcoRequest::decode(&apco(&units)), Ok(None));
    assert_eq!(
        request().append_to(&apco(&units)),
        Err(N1ModeApcoError::TooManyContainers)
    );
    units.extend_from_slice(&[0xee, 0, 0]);
    assert_eq!(
        N1ModeApcoRequest::decode(&apco(&units)),
        Err(N1ModeApcoError::TooManyContainers)
    );
    assert_eq!(N1_MODE_APCO_MAX_CONTENTS_LEN, 251);
    let mut full = vec![0x80, 0xee, 0, 247];
    full.resize(251, 0);
    assert_eq!(N1ModeApcoRequest::decode(&apco(&full)), Ok(None));
    assert_eq!(
        request().append_to(&apco(&full)),
        Err(N1ModeApcoError::ContentsTooLong)
    );
    full.push(0);
    assert_eq!(
        N1ModeApcoRequest::decode(&apco(&full)),
        Err(N1ModeApcoError::ContentsTooLong)
    );
}

#[test]
fn indication_flags_use_ie_octets_eleven_and_twelve() {
    for bits in 0..8 {
        let mut indication = Indication { flags: vec![0] };
        for (index, flag) in [
            IndicationFlag::FiveGsInterworking,
            IndicationFlag::FiveGcNotRestrictedSupport,
            IndicationFlag::FiveGcNotRestricted,
        ]
        .into_iter()
        .enumerate()
        {
            indication.set_flag(flag, bits & (1 << index) != 0);
            assert_eq!(indication.flag(flag), bits & (1 << index) != 0);
        }
        let mut expected = vec![0; indication.flags.len()];
        if bits & 1 != 0 {
            expected[6] |= 0x20;
        }
        if bits & 2 != 0 {
            expected[7] |= 0x08;
        }
        if bits & 4 != 0 {
            expected[7] |= 0x04;
        }
        assert_eq!(indication.flags, expected);
    }
}

#[test]
fn indication_updates_preserve_all_unrelated_and_extension_bits() {
    let flags = [
        IndicationFlag::FiveGsInterworking,
        IndicationFlag::FiveGcNotRestrictedSupport,
        IndicationFlag::FiveGcNotRestricted,
    ];
    for (flag, index, mask) in [
        (flags[0], 6, 0x20),
        (flags[1], 7, 0x08),
        (flags[2], 7, 0x04),
    ] {
        let mut indication = Indication {
            flags: vec![0xff; 12],
        };
        indication.set_flag(flag, false);
        let mut expected = vec![0xff; 12];
        expected[index] &= !mask;
        assert_eq!(indication.flags, expected);
        indication.set_flag(flag, true);
        assert_eq!(indication.flags, vec![0xff; 12]);
    }
    for length in 0..=6 {
        let mut short = Indication {
            flags: vec![0xff; length],
        };
        for flag in flags {
            assert!(!short.flag(flag));
            short.set_flag(flag, false);
        }
        assert_eq!(short.flags, vec![0xff; length]);
    }
}

#[test]
fn n1_apco_diagnostics_are_value_free() {
    assert_eq!(
        format!("{:?}", request()),
        format!(
            "{:?}",
            N1ModeApcoRequest::new(PduSessionId::new(15).unwrap())
        )
    );
    let other = N1ModeApcoResponse::new(
        SnssaiValue::from_bytes(&[255]).unwrap(),
        PlmnIdentity::from_bytes([0x13, 0, 0x62]).unwrap(),
    );
    assert_eq!(format!("{:?}", response()), format!("{other:?}"));
    let a = N1ModeApcoRequest::decode(&apco(&[0x80, 0, 0x1a, 1, 16])).unwrap_err();
    let b = N1ModeApcoRequest::decode(&apco(&[0x80, 0, 0x1a, 1, 255])).unwrap_err();
    assert_eq!(format!("{a} {a:?}"), format!("{b} {b:?}"));
}
