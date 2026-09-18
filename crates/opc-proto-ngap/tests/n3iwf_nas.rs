//! Complete-message vectors from an independent Release 18 compiler.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/nas.rs"]
mod shared;

use bytes::Bytes;
use opc_proto_ngap::n3iwf::context_fields::{AllowedNssai, PartiallyAllowedNssai};
use opc_proto_ngap::n3iwf::nas::{EstablishmentCause, NasMessage, SelectedNid, UeAggregateBitRate};
use opc_proto_ngap::n3iwf::setup_fields::AmfName;
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, NasPdu, RanUeId, TrackingArea};
use opc_proto_ngap::{decode, encode, Criticality, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    BorrowDecode, DecodeContext, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy,
    ValidationLevel,
};
use opc_types::{PlmnId, Snssai};
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

#[test]
fn independently_encoded_partial_slices_and_selected_nid_are_admitted() {
    let oracle = oracle();
    let mut accepted = 0;
    let mut rejected = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["slice_identity_fields"] == true && row["reference_error"].is_null())
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&wire, context()).unwrap();
        let admitted = NasMessage::from_pdu(&pdu, context());
        if row["semantic_error"].is_null() {
            assert!(
                admitted.is_ok(),
                "independent slice or identity field not admitted"
            );
            let admitted = admitted.unwrap();
            match &admitted.message {
                NasMessage::InitialUe {
                    allowed_nssai,
                    partially_allowed_nssai,
                    selected_nid,
                    ..
                } => {
                    assert!(*allowed_nssai == allowed(&row["allowed_nssai"]));
                    assert!(*partially_allowed_nssai == partial(&row["partially_allowed_nssai"]));
                    assert!(*selected_nid == nid(&row["selected_nid"]));
                }
                NasMessage::Downlink {
                    allowed_nssai,
                    partially_allowed_nssai,
                    ..
                } => {
                    assert!(*allowed_nssai == allowed(&row["allowed_nssai"]));
                    assert!(*partially_allowed_nssai == partial(&row["partially_allowed_nssai"]));
                }
                _ => panic!("slice/identity reference outcome"),
            }
            shared::reconstruct(&admitted.message, context(), EncodeContext::default());
            accepted += 1;
        } else {
            assert!(admitted.is_err(), "invalid slice-list combination admitted");
            assert!(
                construct(row).construct(context()).is_err(),
                "invalid constructed slice-list combination admitted"
            );
            rejected += 1;
        }
        assert!(pdu.raw.as_ref() == wire);
    }
    assert_eq!(accepted, 167);
    assert_eq!(rejected, 76);
}

#[test]
fn slice_identity_duplicates_and_criticality_preserve_policy_then_validate_semantics() {
    let oracle = oracle();
    let mut duplicates = 0;
    let mut criticalities = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["slice_identity_fields"] == true)
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        if row.get("invalid_slice_identity_id").is_some() {
            assert!(row["reference_error"] == "ie-criticality");
            assert!(decode(&wire, context()).is_err());
            criticalities += 1;
        }
        if row.get("slice_identity_duplicate_id").is_none() {
            continue;
        }
        duplicates += 1;
        assert!(row["reference_error"] == "duplicate-ie");
        assert!(decode(&wire, context()).is_err());
        for duplicate_ie_policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
            let ctx = DecodeContext {
                duplicate_ie_policy,
                ..context()
            };
            let prefix = if duplicate_ie_policy == DuplicateIePolicy::First {
                "first"
            } else {
                "last"
            };
            let pdu = decode(&wire, ctx).unwrap();
            let admitted = NasMessage::from_pdu(&pdu, ctx);
            if row[format!("{prefix}_admitted")] == false {
                assert!(
                    admitted.is_err(),
                    "duplicate selection bypassed slice-list semantics"
                );
            } else {
                let admitted = admitted.unwrap();
                match &admitted.message {
                    NasMessage::InitialUe {
                        partially_allowed_nssai,
                        selected_nid,
                        ..
                    } => {
                        assert!(
                            *partially_allowed_nssai
                                == partial(&row[format!("{prefix}_partially_allowed_nssai")])
                        );
                        assert!(*selected_nid == nid(&row[format!("{prefix}_selected_nid")]));
                    }
                    NasMessage::Downlink {
                        partially_allowed_nssai,
                        ..
                    } => {
                        assert!(
                            *partially_allowed_nssai
                                == partial(&row[format!("{prefix}_partially_allowed_nssai")])
                        );
                    }
                    _ => panic!("slice/identity reference outcome"),
                }
                shared::reconstruct(&admitted.message, ctx, EncodeContext::default());
            }
            assert!(pdu.raw.as_ref() == wire);
        }
    }
    assert_eq!(duplicates, 7);
    assert_eq!(criticalities, 6);
}

#[test]
fn partial_slice_and_selected_nid_roots_reject_malformed_extent_padding_and_limits() {
    assert!(PartiallyAllowedNssai::new(vec![]).is_err());
    assert!(PartiallyAllowedNssai::new(vec![Snssai::without_sd(1); 9]).is_err());
    assert!(SelectedNid::new(1 << 44).is_err());
    assert!(SelectedNid::new(u64::MAX).is_err());
    let oracle = oracle();
    let mut checked = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["slice_identity_fields"] == true && row["construct"] == true)
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&wire, context()).unwrap();
        let base = construct(&serde_json::json!({"message":row["message"]}))
            .construct(context())
            .unwrap();
        for id in [414, 371] {
            let Some(value) = field_value(&pdu, id) else {
                continue;
            };
            for end in 0..value.len() {
                let changed = with_extra(&base, id, Criticality::ignore, &value[..end]);
                assert!(
                    NasMessage::from_pdu(&changed, context()).is_err(),
                    "truncated slice/identity field admitted"
                );
            }
            let mut tail = value.to_vec();
            tail.push(0);
            assert!(NasMessage::from_pdu(
                &with_extra(&base, id, Criticality::ignore, &tail),
                context()
            )
            .is_err());
            let depth = if id == 414 { 4 } else { 1 };
            let count = if id == 414 {
                row["partially_allowed_nssai"].as_array().unwrap().len()
            } else {
                0
            };
            let exact = DecodeContext {
                max_message_len: value.len(),
                max_depth: depth,
                max_ies: count,
                ..context()
            };
            let admitted = |ctx| {
                if id == 414 {
                    PartiallyAllowedNssai::decode(value, ctx).is_ok()
                } else {
                    SelectedNid::decode(value, ctx).is_ok()
                }
            };
            assert!(admitted(exact));
            assert!(!admitted(DecodeContext {
                max_message_len: value.len() - 1,
                ..exact
            }));
            assert!(!admitted(DecodeContext {
                max_depth: depth - 1,
                ..exact
            }));
            if id == 414 {
                assert!(!admitted(DecodeContext {
                    max_ies: count - 1,
                    ..exact
                }));
                let leaf = partial(&row["partially_allowed_nssai"]).unwrap();
                assert!(leaf
                    .encode(EncodeContext {
                        max_message_len: value.len() - 1,
                        ..EncodeContext::default()
                    })
                    .is_err());
                // List count is three bits; the first item then has extension
                // and optional-extension-container flags. Both fail closed.
                for flag in [0x10, 0x08] {
                    let mut changed = value.to_vec();
                    changed[0] |= flag;
                    for unknown_ie_policy in [
                        UnknownIePolicy::Preserve,
                        UnknownIePolicy::Drop,
                        UnknownIePolicy::Reject,
                    ] {
                        assert!(NasMessage::from_pdu(
                            &with_extra(&base, id, Criticality::ignore, &changed),
                            DecodeContext {
                                unknown_ie_policy,
                                ..context()
                            }
                        )
                        .is_err());
                    }
                }
                assert_eq!(format!("{leaf:?}"), "PartiallyAllowedNssai([REDACTED])");
            } else {
                let leaf = nid(&row["selected_nid"]).unwrap();
                assert!(leaf
                    .encode(EncodeContext {
                        max_message_len: 5,
                        ..EncodeContext::default()
                    })
                    .is_err());
                for padding in 1..16 {
                    let mut changed = value.to_vec();
                    changed[5] |= padding;
                    assert!(
                        NasMessage::from_pdu(
                            &with_extra(&base, id, Criticality::ignore, &changed),
                            context()
                        )
                        .is_err(),
                        "nonzero NID padding admitted"
                    );
                }
                assert_eq!(format!("{leaf:?}"), "SelectedNid([REDACTED])");
            }
            checked += 1;
        }
        for end in 0..wire.len() {
            assert!(decode(&wire[..end], context()).is_err());
        }
        let mut tail = wire.clone();
        tail.push(0);
        let (rest, prefix) = Pdu::decode(&tail, context()).unwrap();
        assert!(rest == [0] && prefix.raw.as_ref() == wire);
        assert!(Pdu::decode_owned(Bytes::from(tail), context()).is_err());
    }
    assert_eq!(checked, 160);
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

fn allowed(value: &Value) -> Option<AllowedNssai> {
    value.as_array().map(|values| {
        AllowedNssai::new(
            values
                .iter()
                .map(|v| match v["sd"].as_str() {
                    Some(sd) => Snssai::with_sd(v["sst"].as_u64().unwrap() as u8, sd).unwrap(),
                    None => Snssai::without_sd(v["sst"].as_u64().unwrap() as u8),
                })
                .collect(),
        )
        .unwrap()
    })
}

fn partial(value: &Value) -> Option<PartiallyAllowedNssai> {
    allowed(value).map(|value| PartiallyAllowedNssai::new(value.values().to_vec()).unwrap())
}

fn nid(value: &Value) -> Option<SelectedNid> {
    value
        .as_str()
        .map(|v| SelectedNid::new(u64::from_str_radix(v, 16).unwrap()).unwrap())
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
            allowed_nssai: allowed(&row["allowed_nssai"]),
            partially_allowed_nssai: partial(&row["partially_allowed_nssai"]),
            selected_nid: nid(&row["selected_nid"]),
        },
        "DownlinkNASTransport" => NasMessage::Downlink {
            amf,
            ran,
            nas,
            aggregate_bit_rate: row["downlink"]
                .as_u64()
                .map(|dl| UeAggregateBitRate::new(dl, row["uplink"].as_u64().unwrap()).unwrap()),
            allowed_nssai: allowed(&row["allowed_nssai"]),
            old_amf: row["old_amf"]
                .as_str()
                .map(|name| AmfName::new(name).unwrap()),
            partially_allowed_nssai: partial(&row["partially_allowed_nssai"]),
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
fn independently_encoded_optional_fields_are_admitted() {
    let oracle = oracle();
    let mut checked = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["optional_fields"] == true && row["reference_error"].is_null())
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&wire, context()).unwrap();
        assert!(
            NasMessage::from_pdu(&pdu, context()).is_ok(),
            "independent applicable NAS optional field was not admitted"
        );
        let admitted = NasMessage::from_pdu(&pdu, context()).unwrap();
        match admitted.message {
            NasMessage::InitialUe { allowed_nssai, .. } => {
                assert!(allowed_nssai == allowed(&row["allowed_nssai"]));
            }
            NasMessage::Downlink {
                allowed_nssai,
                old_amf,
                ..
            } => {
                assert!(allowed_nssai == allowed(&row["allowed_nssai"]));
                assert!(old_amf.as_ref().map(AmfName::as_str) == row["old_amf"].as_str());
            }
            _ => panic!("optional field oracle outcome"),
        }
        assert!(pdu.raw.as_ref() == wire);
        checked += 1;
    }
    assert!(checked == 56, "optional field oracle coverage changed");
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
                allowed_nssai,
                partially_allowed_nssai,
                selected_nid,
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
                assert!(*allowed_nssai == allowed(&row["allowed_nssai"]));
                assert!(*partially_allowed_nssai == partial(&row["partially_allowed_nssai"]));
                assert!(*selected_nid == nid(&row["selected_nid"]));
            }
            NasMessage::Downlink {
                amf,
                ran,
                nas,
                aggregate_bit_rate,
                allowed_nssai,
                old_amf,
                partially_allowed_nssai,
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
                assert!(*allowed_nssai == allowed(&row["allowed_nssai"]));
                assert!(old_amf.as_ref().map(AmfName::as_str) == row["old_amf"].as_str());
                assert!(*partially_allowed_nssai == partial(&row["partially_allowed_nssai"]));
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
    assert_eq!(count, 235);
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
        if row.get("duplicate_id").is_some() && row["optional_fields"] != true {
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
                    3,
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
                    34,
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
            if [3, 34].contains(&unsupported) {
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

#[test]
fn optional_singleton_selection_and_criticality_follow_the_generic_policy() {
    let oracle = oracle();
    let mut duplicate_cases = 0;
    let mut wrong_criticality_cases = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["optional_fields"] == true)
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        if row.get("invalid_optional_id").is_some() {
            assert!(row["reference_error"] == "ie-criticality");
            assert!(decode(&wire, context()).is_err());
            wrong_criticality_cases += 1;
        }
        if row.get("duplicate_id").is_none() {
            continue;
        }
        duplicate_cases += 1;
        assert!(row["reference_error"] == "duplicate-ie");
        assert!(decode(&wire, context()).is_err());
        for duplicate_ie_policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
            let ctx = DecodeContext {
                duplicate_ie_policy,
                ..context()
            };
            let prefix = if duplicate_ie_policy == DuplicateIePolicy::First {
                "first"
            } else {
                "last"
            };
            let pdu = decode(&wire, ctx).unwrap();
            let admitted = NasMessage::from_pdu(&pdu, ctx).unwrap();
            match admitted.message {
                NasMessage::InitialUe { allowed_nssai, .. } => {
                    assert!(allowed_nssai == allowed(&row[format!("{prefix}_allowed_nssai")]));
                }
                NasMessage::Downlink {
                    allowed_nssai,
                    old_amf,
                    ..
                } => {
                    assert!(allowed_nssai == allowed(&row[format!("{prefix}_allowed_nssai")]));
                    assert!(
                        old_amf.as_ref().map(AmfName::as_str)
                            == row[format!("{prefix}_old_amf")].as_str()
                    );
                }
                _ => panic!("optional field oracle outcome"),
            }
            assert!(pdu.raw.as_ref() == wire);
        }
    }
    assert_eq!(duplicate_cases, 3);
    assert_eq!(wrong_criticality_cases, 6);
}

fn field_value(pdu: &Pdu, wanted: u16) -> Option<&[u8]> {
    let PduKind::Initiating { message, .. } = &pdu.kind else {
        panic!("NAS outcome")
    };
    match message {
        Message::InitialUeMessage(m) => m
            .protocol_ies
            .0
            .iter()
            .find(|ie| ie.id == wanted)
            .map(|ie| ie.value.as_bytes()),
        Message::DownlinkNasTransport(m) => m
            .protocol_ies
            .0
            .iter()
            .find(|ie| ie.id == wanted)
            .map(|ie| ie.value.as_bytes()),
        _ => panic!("optional field outcome"),
    }
}

#[test]
fn optional_nested_fields_reject_truncation_trailing_bytes_and_extensions() {
    let oracle = oracle();
    let mut checked = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["optional_fields"] == true && row["reference_error"].is_null())
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&wire, context()).unwrap();
        let base = construct(&serde_json::json!({"message": row["message"]}))
            .construct(context())
            .unwrap();
        for id in [0, 48] {
            let Some(value) = field_value(&pdu, id) else {
                continue;
            };
            for end in 0..value.len() {
                let changed = with_extra(&base, id, Criticality::reject, &value[..end]);
                assert!(
                    NasMessage::from_pdu(&changed, context()).is_err(),
                    "truncated optional field admitted"
                );
            }
            let mut trailing = value.to_vec();
            trailing.push(0);
            let changed = with_extra(&base, id, Criticality::reject, &trailing);
            assert!(
                NasMessage::from_pdu(&changed, context()).is_err(),
                "trailing optional field admitted"
            );
            // AllowedNSSAI: the three-bit list length is followed by item
            // extension/optional flags. AMFName: bit zero is the length extension.
            for flag in if id == 0 {
                &[0x10, 0x08][..]
            } else {
                &[0x80][..]
            } {
                let mut extension = value.to_vec();
                extension[0] |= flag;
                let changed = with_extra(&base, id, Criticality::reject, &extension);
                for unknown_ie_policy in [
                    UnknownIePolicy::Preserve,
                    UnknownIePolicy::Drop,
                    UnknownIePolicy::Reject,
                ] {
                    let ctx = DecodeContext {
                        unknown_ie_policy,
                        ..context()
                    };
                    assert!(
                        NasMessage::from_pdu(&changed, ctx).is_err(),
                        "unsupported nested extension admitted"
                    );
                }
            }
            checked += 1;
        }
        for end in 0..wire.len() {
            assert!(
                decode(&wire[..end], context()).is_err(),
                "truncated complete message decoded"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        // Borrowed decoding intentionally reports the following record. Owned
        // decoding is the complete-message boundary and must reject that tail.
        let (remainder, prefix) = Pdu::decode(&trailing, context()).unwrap();
        assert!(remainder == [0] && prefix.raw.as_ref() == wire);
        assert!(Pdu::decode_owned(Bytes::from(trailing), context()).is_err());
    }
    assert_eq!(checked, 58);
}

#[test]
fn optional_field_bounds_and_mutable_metadata_are_revalidated() {
    let oracle = oracle();
    for row in oracle["cases"].as_array().unwrap().iter().filter(|row| {
        (row["optional_fields"] == true || row["slice_identity_fields"] == true)
            && row["construct"] == true
    }) {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let message = construct(row);
        let pdu = decode(&wire, context()).unwrap();
        let depth = if row["allowed_nssai"].is_array()
            || row["partially_allowed_nssai"].is_array()
            || row["message"] == "InitialUEMessage"
        {
            8
        } else {
            5
        };
        let base_count = if row["message"] == "InitialUEMessage" {
            if row["selected_plmn"] == false {
                4
            } else {
                5
            }
        } else {
            3
        };
        let count = (base_count
            + usize::from(row["allowed_nssai"].is_array())
            + usize::from(row["old_amf"].is_string())
            + usize::from(row["partially_allowed_nssai"].is_array())
            + usize::from(row["selected_nid"].is_string()))
        .max(row["allowed_nssai"].as_array().map_or(0, Vec::len))
        .max(
            row["partially_allowed_nssai"]
                .as_array()
                .map_or(0, Vec::len),
        );
        let exact = DecodeContext {
            max_message_len: wire.len(),
            max_depth: depth,
            max_ies: count,
            ..context()
        };
        assert!(message.construct(exact).is_ok());
        assert!(NasMessage::from_pdu(&pdu, exact).is_ok());
        for short in [
            DecodeContext {
                max_depth: depth - 1,
                ..exact
            },
            DecodeContext {
                max_ies: count - 1,
                ..exact
            },
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..exact
            },
        ] {
            assert!(
                message.construct(short).is_err(),
                "optional constructor bound ignored"
            );
            assert!(
                NasMessage::from_pdu(&pdu, short).is_err(),
                "optional receive bound ignored"
            );
        }
        for id in [0, 48, 414, 371] {
            if field_value(&pdu, id).is_none() {
                continue;
            }
            let mut changed = decode(&wire, context()).unwrap();
            if let PduKind::Initiating { message, .. } = &mut changed.kind {
                match message {
                    Message::InitialUeMessage(m) => {
                        m.protocol_ies
                            .0
                            .iter_mut()
                            .find(|ie| ie.id == id)
                            .unwrap()
                            .criticality =
                            rasn::aper::decode(&[if id == 0 || id == 48 { 0x40 } else { 0 }])
                                .unwrap()
                    }
                    Message::DownlinkNasTransport(m) => {
                        m.protocol_ies
                            .0
                            .iter_mut()
                            .find(|ie| ie.id == id)
                            .unwrap()
                            .criticality =
                            rasn::aper::decode(&[if id == 0 || id == 48 { 0x40 } else { 0 }])
                                .unwrap()
                    }
                    _ => panic!("optional field outcome"),
                }
            }
            assert!(
                NasMessage::from_pdu(&changed, context()).is_err(),
                "mutated optional field metadata admitted"
            );
        }
        let text = format!(
            "{message:?} {:?}",
            NasMessage::from_pdu(&pdu, context()).unwrap()
        );
        for value in [
            "AMF-TEST",
            "192.0.2.1",
            "010203",
            "ffffff",
            "126, 0, 100, 20",
            "4328719365",
        ] {
            assert!(!text.contains(value), "NAS diagnostics revealed a value");
        }
        if let Some(name) = row["old_amf"].as_str().filter(|name| name.len() >= 4) {
            assert!(!text.contains(name), "NAS diagnostics revealed an AMF name");
        }
        assert!(pdu.raw.as_ref() == wire);
    }
}

#[test]
fn bounded_optional_message_mutations_replay_the_fuzz_boundary() {
    let oracle = oracle();
    let mut mutations = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["optional_fields"] == true || row["slice_identity_fields"] == true)
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        for index in 0..wire.len() {
            for bit in [1, 0x20, 0x80] {
                let mut changed = wire.clone();
                changed[index] ^= bit;
                for ctx in [
                    context(),
                    DecodeContext {
                        max_ies: 8,
                        max_depth: 8,
                        max_message_len: 256,
                        ..context()
                    },
                ] {
                    if let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(&changed), ctx) {
                        if let Ok(admitted) = NasMessage::from_pdu(&pdu, ctx) {
                            shared::reconstruct(&admitted.message, ctx, EncodeContext::default());
                        }
                    }
                }
                mutations += 1;
            }
        }
    }
    assert_eq!(mutations, 74_118);
}

fn crit_of(value: u8) -> Criticality {
    match value {
        0 => Criticality::reject,
        1 => Criticality::ignore,
        2 => Criticality::notify,
        _ => panic!("criticality"),
    }
}
