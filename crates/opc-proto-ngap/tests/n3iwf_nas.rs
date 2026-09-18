//! Complete-message vectors from an independent Release 18 compiler.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use opc_proto_ngap::n3iwf::nas::{EstablishmentCause, NasMessage, UeAggregateBitRate};
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, NasPdu, RanUeId, TrackingArea};
use opc_proto_ngap::{decode, encode, Criticality, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, UnknownIePolicy, ValidationLevel,
};
use opc_types::PlmnId;
use serde_json::Value;

fn context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    }
}
fn octets(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-nas.json")).unwrap()
}
fn location() -> N3iwfLocation {
    N3iwfLocation::new(
        "192.0.2.1".parse().unwrap(),
        Some(4500),
        Some(TrackingArea::new(
            PlmnId::new("001", "01").unwrap(),
            [0, 0, 1],
        )),
    )
}
fn cause(value: &str) -> EstablishmentCause {
    match value {
        "emergency" => EstablishmentCause::emergency,
        "highPriorityAccess" => EstablishmentCause::highPriorityAccess,
        "mt-Access" => EstablishmentCause::mt_Access,
        "mo-Signalling" => EstablishmentCause::mo_Signalling,
        "mo-Data" => EstablishmentCause::mo_Data,
        "mo-VoiceCall" => EstablishmentCause::mo_VoiceCall,
        "mo-VideoCall" => EstablishmentCause::mo_VideoCall,
        "mo-SMS" => EstablishmentCause::mo_SMS,
        "mps-PriorityAccess" => EstablishmentCause::mps_PriorityAccess,
        "mcs-PriorityAccess" => EstablishmentCause::mcs_PriorityAccess,
        "notAvailable" => EstablishmentCause::notAvailable,
        "mo-ExceptionData" => EstablishmentCause::mo_ExceptionData,
        _ => panic!("reference cause name"),
    }
}

fn construct(row: &Value) -> NasMessage<'static> {
    let amf = AmfUeId::new(0x0102030405).unwrap();
    let ran = RanUeId::new(0x10203040);
    let nas = NasPdu::new(&[0x7e, 0, 0x64, 0x14]);
    match row["message"].as_str().unwrap() {
        "InitialUEMessage" => NasMessage::InitialUe {
            ran,
            nas,
            location: location(),
            cause: cause(row["cause"].as_str().unwrap_or("mo-Signalling")),
            selected_plmn: row["selected_plmn"]
                .as_bool()
                .unwrap_or(true)
                .then(|| PlmnId::new("001", "01").unwrap()),
            context_requested: row["context_requested"].as_bool().unwrap_or(false),
        },
        "DownlinkNASTransport" => NasMessage::Downlink {
            amf,
            ran,
            nas,
            aggregate_bit_rate: row["downlink"]
                .as_u64()
                .map(|dl| UeAggregateBitRate::new(dl, row["uplink"].as_u64().unwrap()).unwrap()),
        },
        "UplinkNASTransport" => NasMessage::Uplink {
            amf,
            ran,
            nas,
            location: location(),
        },
        _ => panic!("reference message"),
    }
}

#[test]
fn complete_constructed_and_received_messages_match_independent_reference() {
    let oracle = oracle();
    let mut count = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["construct"] == true)
    {
        count += 1;
        let expected = octets(row["wire_hex"].as_str().unwrap());
        let pdu = construct(row).construct(context()).unwrap();
        assert!(pdu.raw.is_empty());
        assert!(
            encode(&pdu, EncodeContext::default()).unwrap() == expected,
            "complete message differs from reference"
        );
        let received = decode(&expected, context()).unwrap();
        let admitted = NasMessage::from_pdu(&received, context()).unwrap();
        assert_eq!(admitted.ignored_ie_count, 0);
        assert!(admitted.notify_ie_ids.is_empty());
        match &admitted.message {
            NasMessage::InitialUe {
                ran,
                nas,
                location,
                cause: observed,
                selected_plmn,
                context_requested,
            } => {
                assert!(ran.value() == 0x10203040);
                assert!(nas.as_bytes() == [0x7e, 0, 0x64, 0x14]);
                assert!(location.port() == Some(4500));
                assert!(location.tai().unwrap().tac() == [0, 0, 1]);
                assert!(*observed == cause(row["cause"].as_str().unwrap_or("mo-Signalling")));
                assert_eq!(
                    selected_plmn.is_some(),
                    row["selected_plmn"].as_bool().unwrap_or(true)
                );
                assert_eq!(
                    *context_requested,
                    row["context_requested"].as_bool().unwrap_or(false)
                );
            }
            NasMessage::Downlink {
                amf,
                ran,
                nas,
                aggregate_bit_rate,
            } => {
                assert!(amf.value() == 0x0102030405);
                assert!(ran.value() == 0x10203040);
                assert!(nas.as_bytes() == [0x7e, 0, 0x64, 0x14]);
                assert!(
                    aggregate_bit_rate.map(UeAggregateBitRate::downlink)
                        == row["downlink"].as_u64()
                );
                assert!(
                    aggregate_bit_rate.map(UeAggregateBitRate::uplink) == row["uplink"].as_u64()
                );
            }
            NasMessage::Uplink {
                amf,
                ran,
                nas,
                location,
            } => {
                assert!(amf.value() == 0x0102030405);
                assert!(ran.value() == 0x10203040);
                assert!(nas.as_bytes() == [0x7e, 0, 0x64, 0x14]);
                assert!(location.port() == Some(4500));
            }
        }
        assert!(received.raw.as_ref() == expected);
    }
    assert_eq!(count, 21);
}

#[test]
fn every_missing_mandatory_field_fails_beyond_structural_decode() {
    let oracle = oracle();
    let mut count = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row.get("missing_id").is_some())
    {
        count += 1;
        assert_eq!(row["reference_error"], "missing-mandatory-ie");
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&wire, context()).unwrap();
        assert!(NasMessage::from_pdu(&pdu, context()).is_err());
        assert!(pdu.raw.as_ref() == wire);
    }
    assert_eq!(count, 11);
}

#[test]
fn outer_duplicate_selection_and_unknown_policy_remain_authoritative() {
    let oracle = oracle();
    for row in oracle["cases"].as_array().unwrap() {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        if row.get("duplicate_id").is_some() {
            assert!(decode(&wire, context()).is_err());
            for duplicate_ie_policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
                let ctx = DecodeContext {
                    duplicate_ie_policy,
                    ..context()
                };
                let pdu = decode(&wire, ctx).unwrap();
                let admitted = NasMessage::from_pdu(&pdu, ctx).unwrap();
                let (value, original) = match admitted.message {
                    NasMessage::InitialUe { ran, .. } => (u64::from(ran.value()), 0x10203040),
                    NasMessage::Downlink { amf, .. } | NasMessage::Uplink { amf, .. } => {
                        (amf.value(), 0x0102030405)
                    }
                };
                assert!(
                    value
                        == if duplicate_ie_policy == DuplicateIePolicy::First {
                            34
                        } else {
                            original
                        }
                );
                assert!(pdu.raw.as_ref() == wire);
            }
        }
        if let Some(crit) = row["unknown_criticality"].as_str() {
            if crit == "reject" {
                assert!(decode(&wire, context()).is_err());
                continue;
            }
            let pdu = decode(&wire, context()).unwrap();
            let admitted = NasMessage::from_pdu(&pdu, context()).unwrap();
            assert_eq!(admitted.ignored_ie_count, usize::from(crit == "ignore"));
            assert_eq!(
                admitted.notify_ie_ids,
                if crit == "notify" {
                    vec![65530]
                } else {
                    vec![]
                }
            );
            assert!(decode(
                &wire,
                DecodeContext {
                    unknown_ie_policy: UnknownIePolicy::Reject,
                    ..context()
                }
            )
            .is_err());
            let ctx = DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..context()
            };
            let dropped = decode(&wire, ctx).unwrap();
            let admitted = NasMessage::from_pdu(&dropped, ctx).unwrap();
            assert_eq!(admitted.ignored_ie_count, 0);
            assert!(admitted.notify_ie_ids.is_empty());
            assert!(dropped.raw.as_ref() == wire);
        }
    }
}

fn with_extra(base: &Pdu, id: u16, criticality: Criticality, value: &[u8]) -> Pdu {
    let PduKind::Initiating { message, .. } = &base.kind else {
        panic!("base outcome")
    };
    let (kind, mut fields): (MessageType, Vec<ProtocolIe<'_>>) = match message {
        Message::InitialUeMessage(m) => (
            MessageType::InitialUeMessage,
            m.protocol_ies
                .0
                .iter()
                .map(|ie| {
                    ProtocolIe::new(ie.id, crit_of(ie.criticality as u8), ie.value.as_bytes())
                })
                .collect(),
        ),
        Message::DownlinkNasTransport(m) => (
            MessageType::DownlinkNasTransport,
            m.protocol_ies
                .0
                .iter()
                .map(|ie| {
                    ProtocolIe::new(ie.id, crit_of(ie.criticality as u8), ie.value.as_bytes())
                })
                .collect(),
        ),
        Message::UplinkNasTransport(m) => (
            MessageType::UplinkNasTransport,
            m.protocol_ies
                .0
                .iter()
                .map(|ie| {
                    ProtocolIe::new(ie.id.0, crit_of(ie.criticality as u8), ie.value.as_bytes())
                })
                .collect(),
        ),
        _ => panic!("base message"),
    };
    fields.push(ProtocolIe::new(id, criticality, value));
    Pdu::from_protocol_ies(kind, &fields, context()).unwrap()
}

#[test]
fn n3iwf_ignored_fields_are_not_parsed_and_applicable_fields_do_not_disappear() {
    let oracle = oracle();
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["name"].as_str().unwrap().starts_with("base-"))
    {
        let base = construct(row).construct(context()).unwrap();
        let (ignored, unsupported): (&[(u16, Criticality)], u16) =
            match row["message"].as_str().unwrap() {
                "InitialUEMessage" => (
                    &[
                        (201, Criticality::reject),
                        (224, Criticality::reject),
                        (225, Criticality::ignore),
                        (227, Criticality::ignore),
                        (259, Criticality::reject),
                        (333, Criticality::ignore),
                        (402, Criticality::reject),
                        (427, Criticality::ignore),
                    ],
                    371,
                ),
                "DownlinkNASTransport" => (
                    &[
                        (83, Criticality::ignore),
                        (36, Criticality::ignore),
                        (31, Criticality::ignore),
                        (177, Criticality::ignore),
                        (205, Criticality::ignore),
                        (206, Criticality::ignore),
                        (209, Criticality::ignore),
                        (222, Criticality::ignore),
                        (117, Criticality::ignore),
                        (228, Criticality::ignore),
                        (226, Criticality::ignore),
                        (264, Criticality::reject),
                        (334, Criticality::ignore),
                        (400, Criticality::ignore),
                    ],
                    48,
                ),
                "UplinkNASTransport" => (&[], 239),
                _ => panic!("message"),
            };
        for &(id, crit) in ignored {
            let pdu = with_extra(&base, id, crit, &[0xff, 0xfe]);
            let admitted = NasMessage::from_pdu(&pdu, context()).unwrap();
            assert_eq!(admitted.ignored_ie_count, 1);
        }
        let pdu = with_extra(
            &base,
            unsupported,
            if unsupported == 371 {
                Criticality::ignore
            } else {
                Criticality::reject
            },
            &[0],
        );
        assert!(NasMessage::from_pdu(&pdu, context()).is_err());
        if row["message"] == "DownlinkNASTransport" {
            // TS 29.413's exception makes AMBR applicable to N3IWF. Malformed
            // AMBR must fail admission even though its criticality is ignore.
            let malformed = with_extra(&base, 110, Criticality::ignore, &[0xff]);
            assert!(NasMessage::from_pdu(&malformed, context()).is_err());
        }
    }
}

#[test]
fn capacity_depth_mutable_wrapper_and_redaction_are_enforced() {
    let row = serde_json::json!({"message":"UplinkNASTransport"});
    let message = construct(&row);
    let mut pdu = message.construct(context()).unwrap();
    let wire = encode(&pdu, EncodeContext::default()).unwrap();
    assert!(message
        .construct(DecodeContext {
            max_message_len: wire.len() - 1,
            ..context()
        })
        .is_err());
    assert!(NasMessage::from_pdu(
        &pdu,
        DecodeContext {
            max_depth: 7,
            ..context()
        }
    )
    .is_err());
    assert!(NasMessage::from_pdu(
        &pdu,
        DecodeContext {
            max_ies: 3,
            ..context()
        }
    )
    .is_err());
    assert!(UeAggregateBitRate::new(4_000_000_000_001, 1).is_err());
    let text = format!("{:?}", NasMessage::from_pdu(&pdu, context()).unwrap());
    for forbidden in [
        "192.0.2.1",
        "4500",
        "270544960",
        "4328719365",
        "126, 0, 100, 20",
    ] {
        assert!(!text.contains(forbidden));
    }
    if let PduKind::Initiating { procedure_code, .. } = &mut pdu.kind {
        *procedure_code = 4;
    }
    assert!(NasMessage::from_pdu(&pdu, context()).is_err());
}

fn crit_of(value: u8) -> Criticality {
    match value {
        0 => Criticality::reject,
        1 => Criticality::ignore,
        2 => Criticality::notify,
        _ => panic!("criticality"),
    }
}
