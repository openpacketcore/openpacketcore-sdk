use bytes::{Bytes, BytesMut};
use opc_proto_pfcp::{ie::TypedIe, Message, OwnedMessage};
use opc_protocol::{
    BorrowDecode, DecodeContext, Encode, EncodeContext, OwnedDecode, UnknownIePolicy,
    ValidationLevel,
};

fn tlv(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut wire = kind.to_be_bytes().to_vec();
    wire.extend_from_slice(&(value.len() as u16).to_be_bytes());
    wire.extend_from_slice(value);
    wire
}

fn message(kind: u8, session: bool, ies: &[Vec<u8>]) -> OwnedMessage {
    let mut wire = vec![0x20 | u8::from(session), kind, 0, 0];
    if session {
        wire.extend_from_slice(&1_u64.to_be_bytes());
    }
    wire.extend_from_slice(&[0, 0, 1, 0]);
    for ie in ies {
        wire.extend_from_slice(ie);
    }
    let length = (wire.len() - 4) as u16;
    wire[2..4].copy_from_slice(&length.to_be_bytes());
    OwnedMessage::decode_owned(Bytes::from(wire), DecodeContext::default()).unwrap()
}

#[test]
fn node_messages_enforce_their_own_mandatory_ies_and_seid_absence() {
    let node = tlv(60, &[0, 192, 0, 2, 1]);
    let cause = tlv(19, &[1]);
    for (kind, ies) in [
        (3, vec![]),
        (4, vec![cause.clone()]),
        (7, vec![node.clone()]),
        (8, vec![node.clone(), cause.clone()]),
        (11, vec![]),
        (12, vec![node.clone(), tlv(101, &[0])]),
        (13, vec![node.clone(), cause.clone()]),
        (14, vec![node.clone()]),
        (15, vec![node.clone(), cause.clone()]),
        (16, vec![node.clone(), tlv(290, &[])]),
        (17, vec![node, cause]),
    ] {
        assert!(
            message(kind, false, &ies)
                .validate_production_v1(DecodeContext::default())
                .is_ok(),
            "type {kind}"
        );
        for missing in 0..ies.len() {
            let mut incomplete = ies.clone();
            incomplete.remove(missing);
            assert!(
                matches!(
                    message(kind, false, &incomplete)
                        .validate_production_v1(DecodeContext::default()),
                    Err(opc_proto_pfcp::profile::ProfileValidationError::MissingIe { .. })
                ),
                "type {kind}, missing {missing}"
            );
        }
        assert!(matches!(
            message(kind, true, &ies).validate_production_v1(DecodeContext::default()),
            Err(opc_proto_pfcp::profile::ProfileValidationError::SeidPresence { .. })
        ));
    }
}

#[test]
fn session_modification_accepts_no_rule_operations() {
    for ies in [
        vec![],
        vec![tlv(117, &60_u32.to_be_bytes())],
        vec![tlv(57, &[2, 0, 0, 0, 0, 0, 0, 0, 7, 192, 0, 2, 1])],
    ] {
        let msg = message(52, true, &ies);
        assert!(msg.validate_production_v1(DecodeContext::default()).is_ok());
    }
    assert!(opc_proto_pfcp::session_modification_request_with_operations(1, 1, vec![]).is_ok());
}

#[test]
fn defined_unmodelled_ies_survive_reject_and_drop_policies() {
    for policy in [UnknownIePolicy::Reject, UnknownIePolicy::Drop] {
        let ctx = DecodeContext {
            unknown_ie_policy: policy,
            ..DecodeContext::default()
        };
        let wire = tlv(127, &[]);
        let decoded = opc_proto_pfcp::ie::decode_typed_ie_sequence(&wire, ctx, 0).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].ie_type(), 127);
    }
}

#[test]
fn strict_header_accepts_spares_and_walks_follow_on_messages() {
    for level in [ValidationLevel::Strict, ValidationLevel::ProcedureAware] {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        let mut wire = vec![0x3c, 1, 0, 12, 0, 0, 1, 0, 0, 96, 0, 4, 0, 0, 0, 1];
        wire.extend_from_slice(&[0x20, 1, 0, 12, 0, 0, 2, 0, 0, 96, 0, 4, 0, 0, 0, 1]);
        let (rest, first) = Message::decode(&wire, ctx).unwrap();
        assert!(first.header.fo);
        let (rest, second) = Message::decode(rest, ctx).unwrap();
        assert!(!second.header.fo);
        assert!(rest.is_empty());
        assert_eq!(second.header.sequence_number, 2);
        let owned = OwnedMessage::decode_owned(Bytes::copy_from_slice(&wire[..16]), ctx).unwrap();
        let mut encoded = BytesMut::new();
        owned
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(encoded[0], 0x24);
    }
}

#[test]
fn apply_action_multicast_bits_are_not_spares() {
    let wire = tlv(44, &[0, 0x18]);
    let (_, TypedIe::ApplyAction(action)) =
        TypedIe::decode(&wire, DecodeContext::default(), 0).unwrap()
    else {
        panic!()
    };
    assert_eq!(action.spare, 0);
    let mut encoded = BytesMut::new();
    TypedIe::ApplyAction(action)
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
    assert_eq!(encoded.as_ref(), wire);
}

fn establishment(pdi: &[u8]) -> OwnedMessage {
    let mut pdr = tlv(56, &[0, 1]);
    pdr.extend(tlv(29, &[0, 0, 0, 1]));
    pdr.extend(tlv(2, pdi));
    pdr.extend(tlv(108, &[0, 0, 0, 7]));
    let mut far = tlv(108, &[0, 0, 0, 7]);
    far.extend(tlv(44, &[1, 0]));
    message(
        50,
        true,
        &[
            tlv(60, &[0, 192, 0, 2, 1]),
            tlv(57, &[2, 0, 0, 0, 0, 0, 0, 0, 1, 192, 0, 2, 1]),
            tlv(1, &pdr),
            tlv(3, &far),
        ],
    )
}

#[test]
fn pdi_allows_source_interface_only_but_forbids_conflicting_endpoint_fields() {
    let source = tlv(20, &[0]);
    assert!(establishment(&source)
        .validate_production_v1(DecodeContext::default())
        .is_ok());
    assert!(establishment(&[])
        .validate_production_v1(DecodeContext::default())
        .is_err());
    let mut pdi = source;
    pdi.extend(tlv(21, &[5])); // CHOOSE IPv4.
    pdi.extend(tlv(131, &[1]));
    assert!(establishment(&pdi)
        .validate_production_v1(DecodeContext::default())
        .is_err());
}

#[test]
fn malformed_optional_pdi_addresses_remain_documented_profile_errors() {
    // The typed profile deliberately reports the value error. It does not
    // implement TS 29.244 §7.6.8's optional-IE discard; see CONFORMANCE.md.
    for validation_level in [
        ValidationLevel::HeaderOnly,
        ValidationLevel::Structural,
        ValidationLevel::Strict,
        ValidationLevel::ProcedureAware,
    ] {
        let ctx = DecodeContext {
            validation_level,
            ..DecodeContext::default()
        };
        let source = tlv(20, &[0]);
        assert!(establishment(&source).validate_production_v1(ctx).is_ok());
        for invalid in [tlv(21, &[0]), tlv(93, &[0x12, 192, 0, 2, 1])] {
            let mut pdi = source.clone();
            pdi.extend(invalid);
            assert!(matches!(
                establishment(&pdi).validate_production_v1(ctx),
                Err(opc_proto_pfcp::profile::ProfileValidationError::TypedDecode { .. })
            ));
        }
    }
}

#[test]
fn establishment_requires_node_id_and_modification_can_reference_existing_rules() {
    let mut pdi = tlv(20, &[0]);
    pdi.extend(tlv(22, b"internet"));
    let mut msg = establishment(&pdi);
    msg.ies.retain(|ie| ie.ie_type != 60);
    assert!(matches!(
        msg.validate_production_v1(DecodeContext::default()),
        Err(opc_proto_pfcp::profile::ProfileValidationError::MissingIe { ie: "Node ID", .. })
    ));
    let mut update = tlv(56, &[0, 1]);
    update.extend(tlv(108, &[0, 0, 0, 7]));
    update.extend(tlv(109, &[0, 0, 0, 8]));
    update.extend(tlv(81, &[0, 0, 0, 9]));
    assert!(message(52, true, &[tlv(9, &update)])
        .validate_production_v1(DecodeContext::default())
        .is_ok());
}

#[test]
fn apply_action_profile_enforces_primary_action_and_buffer_notifications() {
    for (bits, valid) in [
        ([6, 0], false),
        ([12, 0], true),
        ([10, 0], false),
        ([0, 0x18], true),
        ([2, 2], false),
        ([4, 2], true),
        ([0, 0], false),
    ] {
        let mut far = tlv(108, &[0, 0, 0, 7]);
        far.extend(tlv(44, &bits));
        far.extend(tlv(4, &tlv(42, &[0])));
        assert_eq!(
            message(52, true, &[tlv(3, &far)])
                .validate_production_v1(DecodeContext::default())
                .is_ok(),
            valid,
            "{bits:?}"
        );
    }
}

#[test]
fn every_assigned_ie_is_recognized_and_reserved_types_remain_unknown() {
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };
    assert_eq!(opc_proto_pfcp::ie::IE_DEFINITIONS.len(), 400);
    for &(kind, _) in opc_proto_pfcp::ie::IE_DEFINITIONS {
        // An empty typed value may be malformed, but must not be classified unknown.
        if let Err(error) = TypedIe::decode(&tlv(kind, &[]), ctx, 0) {
            assert_ne!(
                error.code(),
                &opc_protocol::DecodeErrorCode::UnknownCriticalIe,
                "{kind}"
            );
        }
    }
    for kind in [0, 116, 273, 381, 404, 65000] {
        let error = TypedIe::decode(&tlv(kind, &[0, 1]), ctx, 0).unwrap_err();
        assert_eq!(
            error.code(),
            &opc_protocol::DecodeErrorCode::UnknownCriticalIe,
            "{kind}"
        );
    }
    let wire = tlv(117, &60_u32.to_be_bytes());
    let (_, TypedIe::UserPlaneInactivityTimer(timer)) = TypedIe::decode(&wire, ctx, 0).unwrap()
    else {
        panic!()
    };
    assert_eq!(timer.seconds, 60);
    let mut encoded = BytesMut::new();
    TypedIe::UserPlaneInactivityTimer(timer)
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
    assert_eq!(encoded.as_ref(), wire);
}

#[test]
fn typed_ie_errors_identify_the_defining_clause() {
    for (kind, section) in [
        (21, "8.2.3"),
        (57, "8.2.37"),
        (56, "8.2.36"),
        (108, "8.2.74"),
        (95, "8.2.64"),
        (117, "8.2.83"),
    ] {
        for wire in [
            tlv(kind, &[]),
            [kind.to_be_bytes().as_slice(), &[0, 1]].concat(),
        ] {
            let error = TypedIe::decode(&wire, DecodeContext::default(), 0).unwrap_err();
            assert_eq!(error.spec_ref().unwrap().section(), section);
        }
    }
}

#[test]
fn release_and_establishment_builders_supply_mandatory_identity() {
    use opc_proto_pfcp::ie::{Cause, CauseValue, FSeid, NodeId, NodeIdType};
    let node = NodeId {
        node_id_type: NodeIdType::Ipv4,
        value: vec![192, 0, 2, 1],
    };
    let cause = Cause {
        value: CauseValue::RequestAccepted,
    };
    let fseid = FSeid {
        v4: true,
        v6: false,
        seid: 1,
        ipv4: Some([192, 0, 2, 1]),
        ipv6: None,
    };
    for msg in [
        opc_proto_pfcp::association_release_request(1, node.clone()).unwrap(),
        opc_proto_pfcp::association_release_response(1, node.clone(), cause).unwrap(),
        opc_proto_pfcp::session_establishment_response(1, 1, node.clone(), Some(fseid), cause)
            .unwrap(),
    ] {
        assert!(msg.ies.iter().any(|ie| ie.ie_type == 60));
        let mut missing = msg;
        missing.ies.retain(|ie| ie.ie_type != 60);
        assert!(missing
            .validate_production_v1(DecodeContext::default())
            .is_err());
    }
    assert!(opc_proto_pfcp::session_establishment_response(1, 1, node, None, cause).is_err());
}

#[test]
fn header_only_response_cannot_hide_body_ies_with_drop_policy() {
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..DecodeContext::default()
    };
    assert!(message(11, false, &[tlv(500, &[])])
        .validate_production_v1(ctx)
        .is_err());
}
