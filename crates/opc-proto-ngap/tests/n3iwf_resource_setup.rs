#![allow(clippy::unwrap_used)]
use bytes::Bytes;
use opc_proto_ngap::n3iwf::context_fields::{AllowedNssai, Guami, SecurityAlgorithmMasks};
use opc_proto_ngap::n3iwf::nas::UeAggregateBitRate;
use opc_proto_ngap::n3iwf::release::Cause;
use opc_proto_ngap::n3iwf::resource_setup::{
    InitialContextFailure, InitialContextRequest, InitialContextResponse, ResourceSetupMessage,
    SessionResourceRequest, SessionResourceResponse,
};
use opc_proto_ngap::n3iwf::session_lists::{
    FailedSessions, SessionResults, SessionSetupRequests, SuccessfulSessions,
};
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, NasPdu, RanUeId, SecurityKey};
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DecodeError, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy,
    ValidationLevel,
};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-resource-setup.json")).unwrap()
}
fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 200_000,
        max_ies: 256,
        max_depth: 24,
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    }
}
fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    }
}
fn kind(row: &Value) -> MessageType {
    match row["kind"].as_str().unwrap() {
        "InitialContextSetupRequest" => MessageType::InitialContextSetupRequest,
        "InitialContextSetupResponse" => MessageType::InitialContextSetupResponse,
        "InitialContextSetupFailure" => MessageType::InitialContextSetupFailure,
        "PDUSessionResourceSetupRequest" => MessageType::PduSessionResourceSetupRequest,
        "PDUSessionResourceSetupResponse" => MessageType::PduSessionResourceSetupResponse,
        _ => panic!("reference outcome"),
    }
}
fn criticality(value: &Value) -> Criticality {
    match value.as_str().unwrap() {
        "reject" => Criticality::reject,
        "ignore" => Criticality::ignore,
        "notify" => Criticality::notify,
        _ => panic!("reference criticality"),
    }
}
type Fields = Vec<(u16, Criticality, Vec<u8>)>;
fn fields(row: &Value, name: &str) -> Fields {
    row[name]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["id"].as_u64().unwrap() as u16,
                criticality(&v["criticality"]),
                bytes(v["wire_hex"].as_str().unwrap()),
            )
        })
        .collect()
}
fn field(values: &Fields, id: u16) -> Option<&[u8]> {
    values.iter().find(|v| v.0 == id).map(|v| v.2.as_slice())
}
fn masks(row: &Value) -> SecurityAlgorithmMasks {
    let v: Vec<_> = row["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u16)
        .collect();
    SecurityAlgorithmMasks::new(v[0], v[1], v[2], v[3])
}
fn results(values: &Fields, yes: u16, no: u16) -> SessionResults {
    SessionResults::new(
        field(values, yes).map(|v| SuccessfulSessions::decode(v, context()).unwrap()),
        field(values, no).map(|v| FailedSessions::decode(v, context()).unwrap()),
    )
    .unwrap()
}
// The individual leaf constructors have separate model-to-byte qualification.
// Here the independent leaf values exercise complete typed message construction,
// separately from whole-message receive and without an SDK-generated oracle.
fn construct_row(row: &Value, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
    let values = fields(row, "canonical_fields");
    let amf = AmfUeId::decode(field(&values, 10).unwrap(), context()).unwrap();
    let ran = RanUeId::decode(field(&values, 85).unwrap(), context()).unwrap();
    let nas = field(&values, 38).map(|v| NasPdu::decode(v, context()).unwrap());
    let aggregate_bit_rate =
        field(&values, 110).map(|v| UeAggregateBitRate::decode(v, context()).unwrap());
    match kind(row) {
        MessageType::InitialContextSetupRequest => InitialContextRequest {
            amf,
            ran,
            guami: Guami::decode(field(&values, 28).unwrap(), context()).unwrap(),
            allowed: AllowedNssai::decode(field(&values, 0).unwrap(), context()).unwrap(),
            key: SecurityKey::decode(field(&values, 94).unwrap(), context()).unwrap(),
            aggregate_bit_rate,
            nas,
            sessions: field(&values, 71)
                .map(|v| SessionSetupRequests::decode(v, context()).unwrap().requests),
        }
        .construct(masks(row), ctx),
        MessageType::InitialContextSetupResponse => InitialContextResponse {
            diagnostics: None,
            amf,
            ran,
            sessions: results(&values, 72, 55),
        }
        .construct(ctx),
        MessageType::InitialContextSetupFailure => InitialContextFailure {
            diagnostics: None,
            amf,
            ran,
            cause: Cause::decode(field(&values, 15).unwrap(), context()).unwrap(),
            failed: field(&values, 132).map(|v| FailedSessions::decode(v, context()).unwrap()),
        }
        .construct(ctx),
        MessageType::PduSessionResourceSetupRequest => SessionResourceRequest {
            amf,
            ran,
            nas,
            aggregate_bit_rate,
            sessions: SessionSetupRequests::decode(field(&values, 74).unwrap(), context())
                .unwrap()
                .requests,
        }
        .construct(ctx),
        MessageType::PduSessionResourceSetupResponse => SessionResourceResponse {
            diagnostics: None,
            amf,
            ran,
            sessions: results(&values, 75, 58),
            location: field(&values, 121).map(|v| N3iwfLocation::decode(v, context()).unwrap()),
        }
        .construct(ctx),
        _ => panic!("reference outcome"),
    }
}
fn reconstruct(
    message: &ResourceSetupMessage<'_>,
    row: &Value,
    ctx: DecodeContext,
) -> Result<Pdu, DecodeError> {
    match message {
        ResourceSetupMessage::InitialRequest(v) => v.construct(masks(row), ctx),
        ResourceSetupMessage::InitialResponse(v) => v.construct(ctx),
        ResourceSetupMessage::InitialFailure(v) => v.construct(ctx),
        ResourceSetupMessage::SessionRequest(v) => v.construct(ctx),
        ResourceSetupMessage::SessionResponse(v) => v.construct(ctx),
    }
}
fn amf(message: &ResourceSetupMessage<'_>) -> u64 {
    match message {
        ResourceSetupMessage::InitialRequest(v) => v.amf.value(),
        ResourceSetupMessage::InitialResponse(v) => v.amf.value(),
        ResourceSetupMessage::InitialFailure(v) => v.amf.value(),
        ResourceSetupMessage::SessionRequest(v) => v.amf.value(),
        ResourceSetupMessage::SessionResponse(v) => v.amf.value(),
    }
}
fn read(row: &Value, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
    Pdu::decode_owned(Bytes::from(bytes(row["wire_hex"].as_str().unwrap())), ctx)
}
fn row<'a>(reference: &'a Value, name: &str) -> &'a Value {
    reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
}
fn pdu_with_fields(row: &Value, fields: &Fields, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
    let values: Vec<_> = fields
        .iter()
        .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value))
        .collect();
    Pdu::from_protocol_ies(kind(row), &values, ctx)
}

#[test]
fn independent_messages_match_admission_and_canonical_construction() {
    let reference = oracle();
    let mut admitted_count = 0;
    for row in reference["cases"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let pdu = read(row, context());
        if !row["admitted"].as_bool().unwrap() {
            if let Ok(pdu) = pdu {
                assert!(
                    ResourceSetupMessage::from_pdu(&pdu, context()).is_err(),
                    "{name}"
                );
            }
            continue;
        }
        let pdu = pdu.unwrap_or_else(|e| panic!("{name}: container {e:?}"));
        let admitted = ResourceSetupMessage::from_pdu(&pdu, context())
            .unwrap_or_else(|e| panic!("{name}: admission {e:?}"));
        let expected = bytes(row["canonical_wire_hex"].as_str().unwrap());
        let construction =
            construct_row(row, context()).unwrap_or_else(|e| panic!("{name}: constructor {e:?}"));
        assert!(
            encode(&construction, output()).unwrap() == expected,
            "{name}: independent construction"
        );
        assert!(
            encode(
                &reconstruct(&admitted.message, row, context()).unwrap(),
                output()
            )
            .unwrap()
                == expected,
            "{name}: admitted canonical fields"
        );
        match row["nested_unknown"].as_str() {
            Some("request-notify" | "request-ignore") => {
                assert_eq!(admitted.transfer_diagnostics.len(), 1, "{name}");
                let diagnostics = &admitted.transfer_diagnostics[0];
                assert_eq!(diagnostics.session.value(), 2);
                if row["nested_unknown"] == "request-notify" {
                    assert_eq!(diagnostics.notify_ie_ids, vec![65535]);
                    assert_eq!(diagnostics.ignored_ie_count, 0);
                } else {
                    assert!(diagnostics.notify_ie_ids.is_empty());
                    assert_eq!(diagnostics.ignored_ie_count, 1);
                }
            }
            _ => assert!(admitted.transfer_diagnostics.is_empty(), "{name}"),
        }
        let unknown_ignore = usize::from(row["criticality"] == "ignore");
        let context_capability = usize::from(row["kind"] == "InitialContextSetupRequest");
        let extra_ignored = usize::from(row["mode"] == "ignored" && row["ignored_id"] != 119);
        assert_eq!(
            admitted.ignored_ie_count,
            unknown_ignore + context_capability + extra_ignored,
            "{name}"
        );
        assert_eq!(
            admitted.notify_ie_ids.len(),
            usize::from(row["criticality"] == "notify")
        );
        if row["criticality"] == "notify" {
            assert_eq!(admitted.notify_ie_ids, vec![65530]);
        }
        assert!(format!("{admitted:?}").contains("REDACTED"));
        admitted_count += 1;
    }
    assert_eq!(reference["cases"].as_array().unwrap().len(), 122);
    assert_eq!(admitted_count, 83);
}

#[test]
fn shared_unknown_and_duplicate_policies_remain_authoritative() {
    let reference = oracle();
    for row in reference["cases"].as_array().unwrap() {
        if row["mode"] == "duplicate" {
            let values = fields(row, "fields");
            let last = values.iter().rev().find(|v| v.0 == 10).unwrap();
            let last = AmfUeId::decode(&last.2, context()).unwrap().value();
            for (policy, expected) in [
                (DuplicateIePolicy::First, 7),
                (DuplicateIePolicy::Last, last),
            ] {
                let ctx = DecodeContext {
                    duplicate_ie_policy: policy,
                    ..context()
                };
                let pdu = read(row, ctx).unwrap();
                assert_eq!(
                    amf(&ResourceSetupMessage::from_pdu(&pdu, ctx).unwrap().message),
                    expected
                );
            }
        }
        if row["mode"] != "unknown" {
            continue;
        }
        let strict_drop = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..context()
        };
        if row["criticality"] == "reject" {
            assert!(read(row, strict_drop).is_err());
            let ctx = DecodeContext {
                validation_level: ValidationLevel::Structural,
                ..strict_drop
            };
            let pdu = read(row, ctx).unwrap();
            assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_ok());
        } else {
            let pdu = read(row, strict_drop).unwrap();
            let admitted = ResourceSetupMessage::from_pdu(&pdu, strict_drop).unwrap();
            assert!(admitted.notify_ie_ids.is_empty());
            assert_eq!(
                admitted.ignored_ie_count,
                usize::from(row["kind"] == "InitialContextSetupRequest")
            );
            assert!(read(
                row,
                DecodeContext {
                    unknown_ie_policy: UnknownIePolicy::Reject,
                    ..context()
                }
            )
            .is_err());
        }
    }
}

#[test]
fn nested_unknown_policies_reach_contained_transfers() {
    let reference = oracle();
    for row in reference["cases"].as_array().unwrap().iter().filter(|row| {
        matches!(
            row["nested_unknown"].as_str(),
            Some("request-notify" | "request-ignore" | "request-reject")
        )
    }) {
        let strict_drop = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..context()
        };
        let pdu = read(row, strict_drop).unwrap();
        if row["nested_unknown"] == "request-reject" {
            assert!(ResourceSetupMessage::from_pdu(&pdu, strict_drop).is_err());
            let ctx = DecodeContext {
                validation_level: ValidationLevel::Structural,
                ..strict_drop
            };
            assert!(ResourceSetupMessage::from_pdu(&pdu, ctx)
                .unwrap()
                .transfer_diagnostics
                .is_empty());
        } else {
            assert!(ResourceSetupMessage::from_pdu(&pdu, strict_drop)
                .unwrap()
                .transfer_diagnostics
                .is_empty());
        }
        let ctx = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..context()
        };
        assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_err());
    }
}

#[test]
fn conditional_presence_key_custody_and_constructor_guards_are_explicit() {
    let reference = oracle();
    let request = row(&reference, "base-InitialContextSetupRequest");
    let pdu = read(request, context()).unwrap();
    let admitted = ResourceSetupMessage::from_pdu(&pdu, context()).unwrap();
    let ResourceSetupMessage::InitialRequest(mut value) = admitted.message else {
        panic!("request");
    };
    let PduKind::Initiating {
        message: opc_proto_ngap::Message::InitialContextSetupRequest(raw),
        ..
    } = &pdu.kind
    else {
        panic!("request container");
    };
    let key = raw
        .protocol_ies
        .0
        .iter()
        .find(|v| v.id == 94)
        .unwrap()
        .value
        .as_bytes();
    assert!(std::ptr::eq(
        value.key.expose_bytes().as_ptr(),
        key.as_ptr()
    ));
    assert!(format!("{value:?}").contains("REDACTED"));
    value.aggregate_bit_rate = None;
    assert!(value.construct(masks(request), context()).is_err());
    value.sessions = None;
    assert!(value.construct(masks(request), context()).is_ok());

    for length in [0, 31, 33] {
        let mut values = fields(request, "fields");
        values.iter_mut().find(|v| v.0 == 94).unwrap().2 = vec![0; length];
        let changed = pdu_with_fields(request, &values, context()).unwrap();
        assert!(ResourceSetupMessage::from_pdu(&changed, context()).is_err());
    }
    // Capabilities are mandatory but their contents are receiver-ignored.
    let mut values = fields(request, "fields");
    values.iter_mut().find(|v| v.0 == 119).unwrap().2.clear();
    let changed = pdu_with_fields(request, &values, context()).unwrap();
    assert!(ResourceSetupMessage::from_pdu(&changed, context()).is_ok());
    values.retain(|v| v.0 != 119);
    let changed = pdu_with_fields(request, &values, context()).unwrap();
    assert!(ResourceSetupMessage::from_pdu(&changed, context()).is_err());

    let pdu = read(
        row(&reference, "base-PDUSessionResourceSetupResponse"),
        context(),
    )
    .unwrap();
    let ResourceSetupMessage::SessionResponse(mut value) =
        ResourceSetupMessage::from_pdu(&pdu, context())
            .unwrap()
            .message
    else {
        panic!("response");
    };
    value.sessions = SessionResults::new(None, None).unwrap();
    assert!(value.construct(context()).is_err());
    let empty = InitialContextResponse {
        diagnostics: None,
        amf: value.amf,
        ran: value.ran,
        sessions: SessionResults::new(None, None).unwrap(),
    };
    assert!(empty.construct(context()).is_ok());
}

#[test]
fn nested_failures_and_mutated_metadata_reject_the_complete_message() {
    let reference = oracle();
    for row in reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["name"].as_str().unwrap().starts_with("base-"))
    {
        let values = fields(row, "fields");
        for id in [71, 74, 72, 75, 55, 58, 132] {
            let Some(index) = values.iter().position(|v| v.0 == id) else {
                continue;
            };
            let mut changed = values.clone();
            // Count remains plausible; reject an extension on the first item.
            changed[index].2[1] |= 0x80;
            let pdu = pdu_with_fields(row, &changed, context()).unwrap();
            assert!(ResourceSetupMessage::from_pdu(&pdu, context()).is_err());
        }
        let mut wrong_criticality = values.clone();
        wrong_criticality[0].1 = Criticality::notify;
        assert!(pdu_with_fields(row, &wrong_criticality, context()).is_err());
        let mut pdu = read(row, context()).unwrap();
        match &mut pdu.kind {
            PduKind::Initiating { procedure_code, .. }
            | PduKind::Successful { procedure_code, .. }
            | PduKind::Unsuccessful { procedure_code, .. } => *procedure_code = 255,
        }
        assert!(ResourceSetupMessage::from_pdu(&pdu, context()).is_err());
    }
}

#[test]
fn message_capacity_depth_and_nested_counts_are_bounded() {
    let reference = oracle();
    for (name, depth) in [
        ("base-InitialContextSetupRequest", 17),
        ("base-InitialContextSetupResponse", 13),
        ("base-InitialContextSetupFailure", 10),
        ("base-PDUSessionResourceSetupRequest", 17),
        ("base-PDUSessionResourceSetupResponse", 13),
        ("context-without-resources", 8),
        ("omit-InitialContextSetupResponse-72-55", 5),
    ] {
        let row = row(&reference, name);
        let wire = bytes(row["canonical_wire_hex"].as_str().unwrap());
        let ctx = DecodeContext {
            max_depth: depth,
            max_message_len: wire.len(),
            ..context()
        };
        let pdu = construct_row(row, ctx).unwrap();
        assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_ok());
        for ctx in [
            DecodeContext {
                max_depth: depth - 1,
                ..ctx
            },
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..ctx
            },
        ] {
            assert!(construct_row(row, ctx).is_err(), "{name}");
            assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_err(), "{name}");
        }
        let ctx = DecodeContext {
            max_ies: 1,
            ..context()
        };
        assert!(read(row, ctx).is_err());
        assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_err());
    }
    for name in [
        "count-256-InitialContextSetupRequest",
        "count-256-PDUSessionResourceSetupRequest",
    ] {
        let row = row(&reference, name);
        let pdu = read(row, context()).unwrap();
        let ctx = DecodeContext {
            max_ies: 255,
            ..context()
        };
        assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_err());
        assert!(construct_row(row, ctx).is_err());
    }
}

#[test]
fn complete_message_truncations_and_bounded_mutations_never_panic() {
    let reference = oracle();
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let stride = (wire.len() / 256).max(1);
        for end in (0..wire.len()).step_by(stride).chain([wire.len() - 1]) {
            assert!(Pdu::decode_owned(Bytes::copy_from_slice(&wire[..end]), context()).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(Pdu::decode_owned(Bytes::from(trailing), context()).is_err());
        for index in (0..wire.len()).step_by(stride) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                if let Ok(pdu) = Pdu::decode_owned(Bytes::from(changed), context()) {
                    let _ = ResourceSetupMessage::from_pdu(&pdu, context());
                }
            }
        }
    }
}
