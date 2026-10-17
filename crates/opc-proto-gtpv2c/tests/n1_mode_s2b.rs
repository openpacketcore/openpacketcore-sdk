use bytes::BytesMut;
use opc_proto_gtpv2c::n1_mode::{N1ModeApcoError, N1ModeApcoRequest, N1ModeApcoResponse};
use opc_proto_gtpv2c::s2b::{MessageDirection, Procedure};
use opc_proto_gtpv2c::{
    AdditionalProtocolConfigurationOptions, BearerContext, ProtocolConfigurationOptions,
    S2bMessage, TypedIe, TypedIeValue,
};
use opc_protocol::{DecodeContext, EncodeContext, ValidationLevel};

const REQUEST_MESSAGE: &[u8] =
    include_bytes!("fixtures/spec/create_session_request_s2b_ipv4_dynamic.bin");
const RESPONSE_MESSAGE: &[u8] =
    include_bytes!("fixtures/spec/create_session_response_s2b_subset.bin");
const REQUEST_APCO: &[u8] = &[0x80, 0, 0x1a, 1, 7];
const RESPONSE_APCO: &[u8] = &[0x80, 0, 0x1b, 7, 1, 0x12, 0x34, 0x56, 0, 0xf1, 0x10];

fn context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

fn apco_ie(value: &[u8], instance: u8) -> TypedIe<'static> {
    TypedIe {
        instance,
        value: TypedIeValue::AdditionalProtocolConfigurationOptions(
            AdditionalProtocolConfigurationOptions {
                value: value.to_vec(),
            },
        ),
    }
}

fn append_ie(fixture: &[u8], ie: &TypedIe<'_>) -> Vec<u8> {
    let mut wire = BytesMut::from(fixture);
    ie.encode(&mut wire, EncodeContext::default()).unwrap();
    let length = u16::try_from(wire.len() - 4).unwrap();
    wire[2..4].copy_from_slice(&length.to_be_bytes());
    wire.to_vec()
}

#[test]
fn n1_values_survive_procedure_aware_create_session_decode() {
    let request_wire = append_ie(REQUEST_MESSAGE, &apco_ie(REQUEST_APCO, 0));
    let (tail, message) = S2bMessage::decode(&request_wire, context()).unwrap();
    assert!(tail.is_empty());
    let view = message.as_view().unwrap();
    let n1 = N1ModeApcoRequest::from_s2b(view).unwrap().unwrap();
    assert_eq!(n1.pdu_session_id().value(), 7);
    assert_eq!(
        view.create_session_context().unwrap().apco.unwrap().value,
        REQUEST_APCO
    );
    assert_eq!(
        n1.to_s2b_ie(),
        *view.ies.iter().find(|ie| ie.ie_type() == 163).unwrap()
    );

    let response_wire = append_ie(RESPONSE_MESSAGE, &apco_ie(RESPONSE_APCO, 0));
    let (tail, message) = S2bMessage::decode(&response_wire, context()).unwrap();
    assert!(tail.is_empty());
    let view = message.as_view().unwrap();
    let n1 = N1ModeApcoResponse::from_s2b(view).unwrap().unwrap();
    assert_eq!(n1.snssai().as_bytes(), &[1, 0x12, 0x34, 0x56]);
    assert_eq!(n1.plmn_id().as_bytes(), &[0, 0xf1, 0x10]);
    assert_eq!(
        n1.to_s2b_ie(),
        *view.ies.iter().find(|ie| ie.ie_type() == 163).unwrap()
    );
}

#[test]
fn projection_ignores_other_instances_pco_and_grouped_apco() {
    for fixture in [REQUEST_MESSAGE, RESPONSE_MESSAGE] {
        let (_, message) = S2bMessage::decode(fixture, context()).unwrap();
        let mut view = message.as_view().unwrap().clone();
        for value in [REQUEST_APCO, RESPONSE_APCO] {
            view.ies.push(apco_ie(value, 1));
            view.ies.push(TypedIe {
                instance: 0,
                value: TypedIeValue::ProtocolConfigurationOptions(ProtocolConfigurationOptions {
                    value: value.to_vec(),
                }),
            });
            view.ies.push(TypedIe {
                instance: 0,
                value: TypedIeValue::BearerContext(BearerContext {
                    members: vec![apco_ie(value, 0)],
                }),
            });
        }
        if fixture == REQUEST_MESSAGE {
            assert_eq!(N1ModeApcoRequest::from_s2b(&view), Ok(None));
        } else {
            assert_eq!(N1ModeApcoResponse::from_s2b(&view), Ok(None));
        }
    }
}

#[test]
fn projection_checks_procedure_direction_and_header_type() {
    let (_, request) = S2bMessage::decode(REQUEST_MESSAGE, context()).unwrap();
    let (_, response) = S2bMessage::decode(RESPONSE_MESSAGE, context()).unwrap();
    assert_eq!(
        N1ModeApcoRequest::from_s2b(response.as_view().unwrap()),
        Err(N1ModeApcoError::WrongS2bMessage)
    );
    assert_eq!(
        N1ModeApcoResponse::from_s2b(request.as_view().unwrap()),
        Err(N1ModeApcoError::WrongS2bMessage)
    );
    for fixture in [REQUEST_MESSAGE, RESPONSE_MESSAGE] {
        let (_, message) = S2bMessage::decode(fixture, context()).unwrap();
        for field in 0..3 {
            let mut view = message.as_view().unwrap().clone();
            match field {
                0 => view.procedure = Procedure::Echo,
                1 => {
                    view.direction = if view.direction == MessageDirection::Request {
                        MessageDirection::Response
                    } else {
                        MessageDirection::Request
                    }
                }
                _ => view.header.message_type = 1,
            }
            let result = if fixture == REQUEST_MESSAGE {
                N1ModeApcoRequest::from_s2b(&view).map(|_| ())
            } else {
                N1ModeApcoResponse::from_s2b(&view).map(|_| ())
            };
            assert_eq!(result, Err(N1ModeApcoError::WrongS2bMessage));
        }
    }
}

#[test]
fn malformed_n1_is_separate_from_absence_and_message_cause() {
    let wire = append_ie(RESPONSE_MESSAGE, &apco_ie(&[0x80, 0, 0x1b, 1, 1], 0));
    let (_, message) = S2bMessage::decode(&wire, context()).unwrap();
    let view = message.as_view().unwrap();
    assert_eq!(
        N1ModeApcoResponse::from_s2b(view),
        Err(N1ModeApcoError::InvalidSnssai)
    );
    // The optional N1 value codec does not rewrite the peer's Cause.
    assert!(view.ies.iter().any(|ie| matches!(&ie.value, TypedIeValue::Cause(cause) if cause.value == opc_proto_gtpv2c::CauseValue::RequestAccepted)));
}

#[test]
fn top_level_ie_duplicates_follow_existing_first_occurrence_receive_policy() {
    let once = append_ie(REQUEST_MESSAGE, &apco_ie(REQUEST_APCO, 0));
    let twice = append_ie(&once, &apco_ie(&[0x80, 0, 0x1a, 1, 15], 0));
    let (_, message) = S2bMessage::decode(&twice, context()).unwrap();
    let n1 = N1ModeApcoRequest::from_s2b(message.as_view().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(n1.pdu_session_id().value(), 7);
}

#[test]
fn malformed_first_top_level_apco_is_not_replaced_by_a_later_valid_one() {
    // This existing shell fixture's opaque APCO is 80 21 01: a truncated
    // ordinary PCO unit, valid only as opaque outer-IE data. Its first
    // occurrence must not be silently repaired by a later N1-bearing APCO.
    let fixture = include_bytes!("fixtures/spec/create_session_request_s2b_subset.bin");
    let wire = append_ie(fixture, &apco_ie(REQUEST_APCO, 0));
    let (_, message) = S2bMessage::decode(&wire, context()).unwrap();
    assert_eq!(
        N1ModeApcoRequest::from_s2b(message.as_view().unwrap()),
        Err(N1ModeApcoError::TruncatedContainer)
    );
}
