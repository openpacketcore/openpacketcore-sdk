#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opc_proto_ngap::n3iwf::nas::{NasMessage, UeAggregateBitRate};
use opc_proto_ngap::n3iwf::release::{Cause, ReleaseMessage, UeIdentifiers};
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
