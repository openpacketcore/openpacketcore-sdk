#![no_main]

#[path = "../../tests/support/release_sessions.rs"]
mod release_sessions;

#[path = "../../tests/support/response_diagnostics.rs"]
mod response_diagnostics;

#[path = "../../tests/support/applicability.rs"]
mod applicability;

#[path = "../../tests/support/resource_release.rs"]
mod resource_release;
#[path = "../../tests/support/resource_setup.rs"]
mod resource_setup;

#[path = "../../tests/support/ue_requests.rs"]
mod ue_requests;

#[path = "../../tests/support/modify_fields.rs"]
mod modify_fields;

#[path = "../../tests/support/modify_request.rs"]
mod modify_request;

#[path = "../../tests/support/modify.rs"]
mod modify;
#[path = "../../tests/support/modify_results.rs"]
mod modify_results;

#[path = "../../tests/support/notify.rs"]
mod notify;

#[path = "../../tests/support/reset.rs"]
mod reset;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opc_proto_ngap::n3iwf::context_fields::{AllowedNssai, Guami, SecurityAlgorithmMasks};
use opc_proto_ngap::n3iwf::nas::{NasMessage, UeAggregateBitRate};
use opc_proto_ngap::n3iwf::release::{Cause, ReleaseMessage, UeIdentifiers};
use opc_proto_ngap::n3iwf::resource_fields::{
    DownlinkTransport, QosFlowSetupList, SessionAggregateBitRate, SessionType, UplinkTransport,
};
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_proto_ngap::n3iwf::resource_results::{SetupFailureTransfer, SetupResponseTransfer};
use opc_proto_ngap::n3iwf::session_lists::{
    FailedSessions, SessionResults, SessionSetupRequests, SuccessfulSessions,
};
use opc_proto_ngap::n3iwf::setup::{
    AmfName, GlobalN3iwfId, PagingDrx, PlmnSupportList, ServedGuamiList, SetupMessage,
    SupportedTaList,
};
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, NasPdu, RanUeId, SecurityKey, TrackingArea};
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, Encode, EncodeContext, OwnedDecode, ValidationLevel,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 131072 {
        return;
    }
    let decode = DecodeContext {
        max_message_len: 200_000,
        max_ies: 32,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let output = EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    };
    release_sessions::exercise(data, decode, output);
    response_diagnostics::exercise(data, decode, output);
    applicability::exercise(data, decode, output);
    modify_fields::exercise(data, decode, output);
    modify_request::exercise(data, decode, output);
    modify_results::exercise(data, decode, output);
    modify::exercise(data, decode, output);
    notify::exercise(data, decode, output);
    reset::exercise(data, decode, output);
    ue_requests::exercise(data, decode, output);
    resource_setup::exercise(data, decode, output);
    resource_release::exercise(data, decode, output);
    if let Ok(field) = AmfUeId::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(AmfUeId::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = RanUeId::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(RanUeId::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = TrackingArea::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(TrackingArea::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = N3iwfLocation::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(N3iwfLocation::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = SecurityKey::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(wire.as_bytes() == data);
    }
    if let Ok(field) = NasPdu::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(NasPdu::decode(wire.as_bytes(), decode).unwrap().as_bytes() == field.as_bytes());
    }
    let nas = NasPdu::new(data).encode(output).unwrap();
    assert!(NasPdu::decode(nas.as_bytes(), decode).unwrap().as_bytes() == data);
    if let Ok(field) = UeAggregateBitRate::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(UeAggregateBitRate::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = Cause::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(Cause::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = UeIdentifiers::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(UeIdentifiers::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = UplinkTransport::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(UplinkTransport::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = DownlinkTransport::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(DownlinkTransport::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = SessionAggregateBitRate::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(SessionAggregateBitRate::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = SessionType::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(SessionType::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = QosFlowSetupList::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(QosFlowSetupList::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(admitted) = SetupRequestTransfer::decode(data, decode) {
        let wire = admitted.transfer.encode(output).unwrap();
        let received = SetupRequestTransfer::decode(wire.as_bytes(), decode).unwrap();
        assert!(received.transfer == admitted.transfer);
        assert_eq!(received.ignored_ie_count, 0);
        assert!(received.notify_ie_ids.is_empty());
    }
    let result_ctx = DecodeContext {
        max_ies: 64,
        ..decode
    };
    if let Ok(value) = SetupResponseTransfer::decode(data, result_ctx) {
        let wire = value.encode(output).unwrap();
        assert!(SetupResponseTransfer::decode(wire.as_bytes(), result_ctx).unwrap() == value);
    }
    if let Ok(value) = SetupFailureTransfer::decode(data, result_ctx) {
        let wire = value.encode(output).unwrap();
        assert!(SetupFailureTransfer::decode(wire.as_bytes(), result_ctx).unwrap() == value);
    }
    let list_ctx = DecodeContext {
        max_ies: 256,
        ..decode
    };
    let list_output = EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    };
    if let Ok(value) = SessionSetupRequests::decode(data, list_ctx) {
        let wire = value.requests.encode(list_output).unwrap();
        let admitted = SessionSetupRequests::decode(wire.as_bytes(), list_ctx).unwrap();
        assert!(admitted.diagnostics.is_empty());
        assert_eq!(
            admitted.requests.values().len(),
            value.requests.values().len()
        );
        for (got, expected) in admitted
            .requests
            .values()
            .iter()
            .zip(value.requests.values())
        {
            assert_eq!(got.id.value(), expected.id.value());
            assert!(got.slice == expected.slice);
            assert!(got.transfer == expected.transfer);
            assert!(
                got.nas.as_ref().map(|v| v.as_bytes())
                    == expected.nas.as_ref().map(|v| v.as_bytes())
            );
        }
    }
    let successful = SuccessfulSessions::decode(data, list_ctx).ok();
    let failed = FailedSessions::decode(data, list_ctx).ok();
    if let Some(value) = &successful {
        let wire = value.encode(list_output).unwrap();
        assert!(SuccessfulSessions::decode(wire.as_bytes(), list_ctx).unwrap() == *value);
    }
    if let Some(value) = &failed {
        let wire = value.encode(list_output).unwrap();
        assert!(FailedSessions::decode(wire.as_bytes(), list_ctx).unwrap() == *value);
    }
    let _ = SessionResults::new(successful, failed);
    if let Ok(field) = Guami::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(Guami::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = AllowedNssai::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(AllowedNssai::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Some(bytes) = data.get(..8) {
        let masks = bytes.as_chunks::<2>().0;
        let value = SecurityAlgorithmMasks::new(
            u16::from_be_bytes(masks[0]),
            u16::from_be_bytes(masks[1]),
            u16::from_be_bytes(masks[2]),
            u16::from_be_bytes(masks[3]),
        );
        assert_eq!(value.encode(output).unwrap().as_bytes().len(), 9);
    }
    if let Ok(field) = GlobalN3iwfId::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(GlobalN3iwfId::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = ServedGuamiList::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(ServedGuamiList::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = PlmnSupportList::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(PlmnSupportList::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = SupportedTaList::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(SupportedTaList::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(field) = AmfName::decode(data, decode) {
        let wire = field.encode(output).unwrap();
        assert!(AmfName::decode(wire.as_bytes(), decode).unwrap() == field);
    }
    if let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), decode) {
        if let Ok(admitted) = SetupMessage::from_pdu(&pdu, decode) {
            let constructed = match &admitted.message {
                SetupMessage::Request(value) => value.construct(PagingDrx::v128, decode),
                SetupMessage::Response(value) => value.construct(decode),
                SetupMessage::Failure(value) => value.construct(decode),
            }
            .unwrap();
            let wire = encode(&constructed, output).unwrap();
            let received = Pdu::decode_owned(Bytes::from(wire), decode).unwrap();
            let readmitted = SetupMessage::from_pdu(&received, decode).unwrap();
            assert!(readmitted.message == admitted.message);
            assert!(readmitted.notify_ie_ids.is_empty());
        }
        if let Ok(admitted) = ReleaseMessage::from_pdu(&pdu, decode) {
            let constructed = admitted.message.construct(decode).unwrap();
            let wire = encode(&constructed, output).unwrap();
            let received = Pdu::decode_owned(Bytes::from(wire), decode).unwrap();
            let readmitted = ReleaseMessage::from_pdu(&received, decode).unwrap();
            assert_eq!(readmitted.ignored_ie_count, 0);
            assert!(readmitted.notify_ie_ids.is_empty());
        }
        if let Ok(admitted) = NasMessage::from_pdu(&pdu, decode) {
            let constructed = admitted.message.construct(decode).unwrap();
            let wire = encode(&constructed, output).unwrap();
            let received = Pdu::decode_owned(Bytes::from(wire), decode).unwrap();
            let readmitted = NasMessage::from_pdu(&received, decode).unwrap();
            assert_eq!(readmitted.ignored_ie_count, 0);
            assert!(readmitted.notify_ie_ids.is_empty());
        }
        if let Ok(wire) = encode(&pdu, output) {
            assert_eq!(pdu.wire_len(output).unwrap(), wire.len());
            let received = Pdu::decode_owned(Bytes::from(wire), decode).unwrap();
            assert!(received.kind == pdu.kind);
        }
    }
    // Independent construction input: bounded borrowed chunks, including
    // repeated/unknown identifiers and opaque, potentially invalid leaf values.
    let ies: Vec<_> = data
        .chunks(256)
        .take(32)
        .filter(|chunk| chunk.len() >= 3)
        .map(|chunk| {
            let crit = match chunk[2] % 3 {
                0 => Criticality::reject,
                1 => Criticality::ignore,
                _ => Criticality::notify,
            };
            ProtocolIe::new(u16::from_be_bytes([chunk[0], chunk[1]]), crit, &chunk[3..])
        })
        .collect();
    let kind = match data.first().copied().unwrap_or(0) % 3 {
        0 => MessageType::NgSetupRequest,
        1 => MessageType::NgSetupResponse,
        _ => MessageType::NgSetupFailure,
    };
    for duplicate_ie_policy in [
        DuplicateIePolicy::First,
        DuplicateIePolicy::Last,
        DuplicateIePolicy::Reject,
    ] {
        if let Ok(pdu) = Pdu::from_protocol_ies(
            kind,
            &ies,
            DecodeContext {
                duplicate_ie_policy,
                ..decode
            },
        ) {
            let wire = encode(&pdu, output).unwrap();
            assert_eq!(pdu.wire_len(output).unwrap(), wire.len());
            assert!(Pdu::decode_owned(Bytes::from(wire), decode).unwrap().kind == pdu.kind);
        }
    }
    let large = Pdu::from_protocol_ies(
        kind,
        &[ProtocolIe::new(65535, Criticality::ignore, data)],
        decode,
    )
    .unwrap();
    let wire = encode(&large, output).unwrap();
    assert!(Pdu::decode_owned(Bytes::from(wire), decode).unwrap().kind == large.kind);
});
