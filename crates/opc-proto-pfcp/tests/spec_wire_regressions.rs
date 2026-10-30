//! Independent TS 29.244 V19.6.0 vectors for the specification audit.

use bytes::BytesMut;
use opc_proto_pfcp::ie::{Cause, CauseValue, FTeid, TypedIe, UeIpAddress};
use opc_protocol::{DecodeContext, DecodeErrorCode, EncodeContext, ValidationLevel};

#[test]
fn cause_values_match_table_8_2_1_1() {
    for (value, code) in [
        (CauseValue::MandatoryIeMissing, 66),
        (CauseValue::ConditionalIeMissing, 67),
        (CauseValue::InvalidLength, 68),
        (CauseValue::MandatoryIeIncorrect, 69),
        (CauseValue::InvalidForwardingPolicy, 70),
        (CauseValue::InvalidFTeidAllocationOption, 71),
        (CauseValue::NoEstablishedPfcpAssociation, 72),
        (CauseValue::RuleCreationModificationFailure, 73),
        (CauseValue::PfcpEntityInCongestion, 74),
        (CauseValue::NoResourcesAvailable, 75),
        (CauseValue::ServiceNotSupported, 76),
        (CauseValue::SystemFailure, 77),
        (CauseValue::RedirectionRequested, 78),
    ] {
        let wire = [0, 19, 0, 1, code];
        let expected = TypedIe::Cause(Cause { value });
        let (_, decoded) = TypedIe::decode(&wire, DecodeContext::default(), 0).unwrap();
        assert_eq!(decoded, expected);
        let mut encoded = BytesMut::new();
        expected
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(encoded.as_ref(), wire);
    }
    for code in (1..=3).chain(64..=92) {
        assert!(
            !matches!(CauseValue::from(code), CauseValue::Unknown(_)),
            "{code}"
        );
        assert_eq!(u8::from(CauseValue::from(code)), code);
    }
}

#[test]
fn fteid_choose_has_no_teid_or_address_octets() {
    for value in [
        &[0x05][..],
        &[0x06],
        &[0x07],
        &[0x0d, 7],
        &[0x0e, 7],
        &[0x0f, 7],
    ] {
        let mut wire = vec![0, 21, 0, value.len() as u8];
        wire.extend_from_slice(value);
        let (_, decoded) = TypedIe::decode(&wire, DecodeContext::default(), 0).unwrap();
        let TypedIe::FTeid(fteid) = &decoded else {
            panic!("F-TEID expected")
        };
        assert!(fteid.ch);
        assert_eq!(fteid.teid, None);
        assert_eq!(fteid.ipv4, None);
        assert_eq!(fteid.ipv6, None);
        assert_eq!(fteid.choose_id, value.get(1).copied());
        let mut encoded = BytesMut::new();
        decoded
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(encoded.as_ref(), wire);
    }
}

#[test]
fn ue_ipv4_uses_bit_two_and_ipv6_uses_bit_one() {
    let wire = [0, 93, 0, 5, 0x06, 10, 0, 0, 1];
    let (_, decoded) = TypedIe::decode(&wire, DecodeContext::default(), 0).unwrap();
    let TypedIe::UeIpAddress(address) = &decoded else {
        panic!("UE IP Address expected")
    };
    assert!(address.v4 && address.sd && !address.v6);
    assert_eq!(address.ipv4, Some([10, 0, 0, 1]));
    let mut encoded = BytesMut::new();
    decoded
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
    assert_eq!(encoded.as_ref(), wire);

    let mut wire = vec![0, 93, 0, 17, 0x01];
    wire.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let (_, decoded) = TypedIe::decode(&wire, DecodeContext::default(), 0).unwrap();
    let TypedIe::UeIpAddress(address) = &decoded else {
        panic!("UE IP Address expected")
    };
    assert!(address.v6 && !address.v4);
    assert_eq!(address.ipv4, None);
    assert_eq!(address.ipv6.as_ref().unwrap().as_slice(), &wire[5..]);
    let mut encoded = BytesMut::new();
    decoded
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
    assert_eq!(encoded.as_ref(), wire);
}

#[test]
fn unknown_causes_preserve_the_wire_value_and_acceptance_class() {
    for code in 0..=u8::MAX {
        let value = CauseValue::from(code);
        assert_eq!(u8::from(value), code);
        assert_eq!(value.is_acceptance(), (1..=63).contains(&code));
        assert_eq!(value.is_rejection(), code >= 64);
    }
    assert_eq!(CauseValue::from(10), CauseValue::Unknown(10));
    assert_eq!(CauseValue::from(200), CauseValue::Unknown(200));
}

#[test]
fn fteid_rejects_invalid_flags_lengths_and_encoder_fields() {
    let error = TypedIe::decode(&[0, 21, 0, 1, 0x01], DecodeContext::default(), 0).unwrap_err();
    assert_eq!(error.code(), &DecodeErrorCode::Truncated);
    assert_eq!(error.spec_ref().unwrap().section(), "8.2.3");
    for value in [
        &[0x00, 0, 0, 0, 1][..],              // no address family
        &[0x04],                              // CH without an address family
        &[0x0c, 7],                           // CH/CHID without an address family
        &[0x09, 0, 0, 0, 1, 127, 0, 0, 1, 7], // CHID without CH
        &[0x0d],                              // missing CHOOSE ID
        &[0x01, 0, 0, 0, 1, 127, 0, 0],       // truncated provided IPv4
    ] {
        let mut wire = vec![0, 21, 0, value.len() as u8];
        wire.extend_from_slice(value);
        for validation_level in [ValidationLevel::Structural, ValidationLevel::Strict] {
            let ctx = DecodeContext {
                validation_level,
                ..DecodeContext::default()
            };
            let err = TypedIe::decode(&wire, ctx, 0).unwrap_err();
            assert_eq!(err.spec_ref().unwrap().section(), "8.2.3");
        }
    }
    let choose = FTeid {
        v4: true,
        v6: false,
        ch: true,
        chid: false,
        teid: None,
        ipv4: None,
        ipv6: None,
        choose_id: None,
    };
    for invalid in [
        FTeid {
            teid: Some(7),
            ..choose.clone()
        },
        FTeid {
            ipv4: Some([127, 0, 0, 1]),
            ..choose.clone()
        },
        FTeid {
            ipv6: Some([0; 16]),
            ..choose.clone()
        },
        FTeid {
            choose_id: Some(7),
            ..choose.clone()
        },
        FTeid {
            chid: true,
            ..choose.clone()
        },
        FTeid {
            ch: false,
            ..choose.clone()
        },
        FTeid {
            v4: false,
            ..choose
        },
    ] {
        let mut encoded = BytesMut::from(&b"prefix"[..]);
        let error = TypedIe::FTeid(invalid)
            .encode(&mut encoded, EncodeContext::default())
            .unwrap_err();
        assert_eq!(error.spec_ref().unwrap().section(), "8.2.3");
        assert_eq!(encoded.as_ref(), b"prefix");
    }
}

fn decode_ue_address(value: &[u8]) -> UeIpAddress {
    let mut wire = vec![0, 93, 0, value.len() as u8];
    wire.extend_from_slice(value);
    let (_, decoded) = TypedIe::decode(&wire, DecodeContext::default(), 0).unwrap();
    let mut encoded = BytesMut::new();
    decoded
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
    assert_eq!(encoded.as_ref(), wire);
    let TypedIe::UeIpAddress(address) = decoded else {
        panic!("UE IP Address expected")
    };
    address
}

#[test]
fn ue_address_dual_stack_allocation_and_ipv6_prefixes_match_the_wire() {
    let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut dual_stack = vec![0x03, 10, 0, 0, 1];
    dual_stack.extend_from_slice(&ipv6);
    let address = decode_ue_address(&dual_stack);
    assert_eq!(address.ipv4, Some([10, 0, 0, 1]));
    assert_eq!(address.ipv6, Some(ipv6));

    for (flag, prefix, delegation, length) in [(0x09, 4, Some(4), None), (0x41, 56, None, Some(56))]
    {
        let mut value = vec![flag];
        value.extend_from_slice(&ipv6);
        value.push(prefix);
        let address = decode_ue_address(&value);
        assert_eq!(address.ipv6_prefix_delegation_bits, delegation);
        assert_eq!(address.ipv6_prefix_length, length);
        assert_eq!(address.ipv6d, delegation.is_some());
        assert_eq!(address.ip6pl, length.is_some());
    }
    for (value, v4, v6) in [
        (&[0x10][..], true, false),
        (&[0x20][..], false, true),
        (&[0x30][..], true, true),
    ] {
        let address = decode_ue_address(value);
        assert_eq!(address.chv4, v4);
        assert_eq!(address.chv6, v6);
        assert_eq!(address.ipv4, None);
        assert_eq!(address.ipv6, None);
    }
    assert_eq!(
        decode_ue_address(&[0x28, 4]).ipv6_prefix_delegation_bits,
        Some(4)
    );
    assert_eq!(decode_ue_address(&[0x60, 56]).ipv6_prefix_length, Some(56));
}

#[test]
fn ue_address_rejects_inconsistent_flags_and_lengths_at_all_validation_levels() {
    let mut conflicting_ipv6 = vec![0x21]; // V6 and CHV6
    conflicting_ipv6.extend_from_slice(&[0; 16]);
    for value in [
        &[0x02, 10, 0, 0][..], // short IPv4
        &[0x12, 10, 0, 0, 1],  // V4 and CHV4
        &conflicting_ipv6,
        &[0x08, 4],     // IPv6D without IPv6
        &[0x40, 56],    // IP6PL without IPv6
        &[0x68, 4, 56], // IPv6D and IP6PL together
    ] {
        let mut wire = vec![0, 93, 0, value.len() as u8];
        wire.extend_from_slice(value);
        for validation_level in [
            ValidationLevel::Structural,
            ValidationLevel::Strict,
            ValidationLevel::ProcedureAware,
        ] {
            let ctx = DecodeContext {
                validation_level,
                ..DecodeContext::default()
            };
            let error = TypedIe::decode(&wire, ctx, 0).unwrap_err();
            assert_eq!(error.spec_ref().unwrap().section(), "8.2.62");
        }
    }
    let address = decode_ue_address(&[0x02, 10, 0, 0, 1]);
    for invalid in [
        UeIpAddress {
            chv4: true,
            ..address.clone()
        },
        UeIpAddress {
            ipv4: None,
            ..address.clone()
        },
        UeIpAddress {
            v4: false,
            ..address.clone()
        },
        UeIpAddress {
            ipv6: Some([0; 16]),
            ..address.clone()
        },
        UeIpAddress {
            ipv6d: true,
            ..address.clone()
        },
        UeIpAddress {
            ipv6_prefix_delegation_bits: Some(4),
            ..address.clone()
        },
        UeIpAddress {
            ip6pl: true,
            ..address.clone()
        },
        UeIpAddress {
            ipv6_prefix_length: Some(56),
            ..address
        },
    ] {
        let mut encoded = BytesMut::from(&b"prefix"[..]);
        assert!(TypedIe::UeIpAddress(invalid)
            .encode(&mut encoded, EncodeContext::default())
            .is_err());
        assert_eq!(encoded.as_ref(), b"prefix");
    }
}

#[test]
fn extendable_address_ies_ignore_unknown_trailing_octets() {
    // Table 8.1.2-1 classifies both IEs as Extendable. Unknown octets must
    // not be mistaken for an address in CHOOSE mode or reject a future peer.
    for canonical in [
        &[0, 21, 0, 1, 0x05][..],
        &[0, 21, 0, 2, 0x0d, 7],
        &[0, 21, 0, 9, 0x01, 0, 0, 0, 1, 127, 0, 0, 1],
        &[0, 93, 0, 5, 0x02, 10, 0, 0, 1],
        &[0, 93, 0, 1, 0x30],
        &[0, 93, 0, 2, 0x60, 56],
    ] {
        let (_, expected) = TypedIe::decode(canonical, DecodeContext::default(), 0).unwrap();
        let mut wire = canonical.to_vec();
        wire[3] += 4;
        wire.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        for validation_level in [
            ValidationLevel::Structural,
            ValidationLevel::Strict,
            ValidationLevel::ProcedureAware,
        ] {
            let ctx = DecodeContext {
                validation_level,
                ..DecodeContext::default()
            };
            let (remaining, decoded) = TypedIe::decode(&wire, ctx, 0).unwrap();
            assert!(remaining.is_empty());
            assert_eq!(decoded, expected);
            let mut encoded = BytesMut::new();
            decoded
                .encode(&mut encoded, EncodeContext::default())
                .unwrap();
            assert_eq!(encoded.as_ref(), canonical);
        }
    }
}

#[test]
fn ue_address_spare_bit_is_ignored_on_receive_and_cleared_on_encode() {
    let wire = [0, 93, 0, 5, 0x82, 10, 0, 0, 1];
    let (_, decoded) = TypedIe::decode(&wire, DecodeContext::default(), 0).unwrap();
    let mut encoded = BytesMut::new();
    decoded
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
    assert_eq!(encoded.as_ref(), [0, 93, 0, 5, 0x02, 10, 0, 0, 1]);
}
