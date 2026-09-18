//! Complete NGAP messages need independent evidence for every admitted outcome.

use opc_n3iwf_fixtures::FixtureCatalog;
use opc_proto_ngap::{Criticality, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;

type Field = (u16, u8, Vec<u8>);

fn message_fields(message: &Message) -> (&'static str, Vec<Field>) {
    macro_rules! view {
        ($name:literal, $message:expr $(, $inner:tt)?) => {
            (
                $name,
                $message
                    .protocol_ies
                    .0
                    .iter()
                    .map(|ie| (ie.id$(.$inner)?, ie.criticality as u8, ie.value.as_bytes().to_vec()))
                    .collect(),
            )
        };
    }
    match message {
        Message::NgSetupRequest(value) => view!("NGSetupRequest", value),
        Message::NgSetupResponse(value) => view!("NGSetupResponse", value),
        Message::NgSetupFailure(value) => view!("NGSetupFailure", value),
        Message::InitialUeMessage(value) => view!("InitialUEMessage", value),
        Message::DownlinkNasTransport(value) => view!("DownlinkNASTransport", value),
        Message::UplinkNasTransport(value) => view!("UplinkNASTransport", value, 0),
        Message::PduSessionResourceModifyRequest(value) => {
            view!("PDUSessionResourceModifyRequest", value)
        }
        Message::PduSessionResourceModifyResponse(value) => {
            view!("PDUSessionResourceModifyResponse", value)
        }
        Message::PduSessionResourceNotify(value) => view!("PDUSessionResourceNotify", value),
        Message::NgReset(value) => view!("NGReset", value),
        Message::NgResetAcknowledge(value) => view!("NGResetAcknowledge", value),
        Message::ErrorIndication(value) => view!("ErrorIndication", value),
        Message::NasNonDeliveryIndication(value) => view!("NASNonDeliveryIndication", value),
        Message::UeContextReleaseRequest(value) => view!("UEContextReleaseRequest", value, 0),
        Message::InitialContextSetupRequest(value) => view!("InitialContextSetupRequest", value),
        Message::InitialContextSetupResponse(value) => view!("InitialContextSetupResponse", value),
        Message::InitialContextSetupFailure(value) => view!("InitialContextSetupFailure", value),
        Message::PduSessionResourceSetupRequest(value) => {
            view!("PDUSessionResourceSetupRequest", value)
        }
        Message::PduSessionResourceSetupResponse(value) => {
            view!("PDUSessionResourceSetupResponse", value)
        }
        Message::PduSessionResourceReleaseCommand(value) => {
            view!("PDUSessionResourceReleaseCommand", value)
        }
        Message::PduSessionResourceReleaseResponse(value) => {
            view!("PDUSessionResourceReleaseResponse", value)
        }
        Message::UeContextReleaseCommand(value) => view!("UEContextReleaseCommand", value, 0),
        Message::UeContextReleaseComplete(value) => view!("UEContextReleaseComplete", value, 0),
        Message::Paging(_) | Message::Unknown(_) => panic!("reference outcome not dispatched"),
    }
}

fn octets(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16).expect("hex"))
        .collect()
}

fn criticality(value: &Value) -> u8 {
    match value.as_str().expect("criticality") {
        "reject" => 0,
        "ignore" => 1,
        "notify" => 2,
        _ => panic!("reference criticality"),
    }
}

#[test]
fn every_admitted_ngap_outcome_has_an_independent_complete_message() {
    let catalog = FixtureCatalog::load_subset_from(&FixtureCatalog::fixture_root(), "ngap")
        .expect("reviewed catalog");
    for outcome in &catalog.completions()["ngap"].admitted_outcomes {
        assert!(
            catalog.manifests().any(|(manifest, _)| {
                manifest.validation_scope == "ngap-release18-message"
                    && manifest.case_class == "positive"
                    && manifest.context["message"] == outcome.as_str()
                    && manifest.context["independent_asn1_validation"] == true
            }),
            "complete independently validated message missing for {outcome}"
        );
    }
    for (manifest, _) in catalog.manifests() {
        assert!(matches!(
            manifest.validation_scope.as_str(),
            "aper-structural-dispatch" | "ngap-release18-message"
        ));
    }
}

#[test]
fn complete_reference_messages_exercise_every_sdk_typed_field() {
    let reference: Value =
        serde_json::from_str(include_str!("../oracles/ngap-rel18-messages.json")).expect("oracle");
    let cases = reference["cases"].as_array().expect("cases");
    let catalog = FixtureCatalog::load_subset_from(&FixtureCatalog::fixture_root(), "ngap")
        .expect("reviewed catalog");
    let mut count = 0;
    for (manifest, wire) in catalog
        .manifests()
        .filter(|(manifest, _)| manifest.validation_scope == "ngap-release18-message")
    {
        count += 1;
        let name = manifest.sdk_fixture_id.split(".v1.").nth(1).expect("name");
        let case = cases
            .iter()
            .find(|case| case["name"] == name)
            .expect("reference case");
        assert!(octets(case["wire_hex"].as_str().expect("wire")) == wire);
        assert_eq!(manifest.context["unknown_ie_policy"], "preserve");
        assert_eq!(manifest.context["duplicate_ie_policy"], "reject");
        assert_eq!(manifest.context["validation_level"], "strict");
        assert_eq!(
            manifest.context["sdk_structural_outcome"],
            case["sdk_structural_outcome"]
        );
        let result = opc_proto_ngap::decode(
            wire,
            DecodeContext {
                max_ies: case["max_ies"].as_u64().expect("bound") as usize,
                unknown_ie_policy: UnknownIePolicy::Preserve,
                duplicate_ie_policy: DuplicateIePolicy::Reject,
                validation_level: ValidationLevel::Strict,
                ..DecodeContext::default()
            },
        );
        if case["sdk_structural_outcome"] == "reject" {
            assert!(result.is_err(), "SDK must reject {name}");
            continue;
        }
        assert_eq!(case["sdk_structural_outcome"], "receive");
        let pdu = result.unwrap_or_else(|_| panic!("SDK must structurally decode {name}"));
        let (kind, code, crit, message) = match &pdu.kind {
            PduKind::Initiating {
                procedure_code,
                criticality,
                message,
            } => (
                "initiatingMessage",
                *procedure_code,
                *criticality as u8,
                message,
            ),
            PduKind::Successful {
                procedure_code,
                criticality,
                message,
            } => (
                "successfulOutcome",
                *procedure_code,
                *criticality as u8,
                message,
            ),
            PduKind::Unsuccessful {
                procedure_code,
                criticality,
                message,
            } => (
                "unsuccessfulOutcome",
                *procedure_code,
                *criticality as u8,
                message,
            ),
        };
        let outer = &case["pdu"]["value"];
        assert_eq!(kind, case["pdu"]["type"].as_str().expect("kind"));
        assert_eq!(
            u64::from(code),
            outer["procedureCode"].as_u64().expect("code")
        );
        assert_eq!(crit, criticality(&outer["criticality"]));
        let (message_name, observed) = message_fields(message);
        assert_eq!(message_name, case["message"].as_str().expect("message"));
        let expected: Vec<Field> = case["encoded_ies"]
            .as_array()
            .expect("IEs")
            .iter()
            .map(|field| {
                (
                    field["id"].as_u64().expect("IE id") as u16,
                    criticality(&field["criticality"]),
                    octets(field["value_hex"].as_str().expect("IE wire")),
                )
            })
            .collect();
        assert!(
            observed == expected,
            "SDK typed fields differ from reference for {name}"
        );
        let emitted = opc_proto_ngap::encode(
            &pdu,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        )
        .expect("raw preserving encode");
        assert!(emitted == wire, "raw preserving wire changed for {name}");
        // Canonical container output is distinct from semantic IE admission.
        // These received root containers have no sequence extension additions.
        assert!(opc_proto_ngap::encode(&pdu, EncodeContext::default()).expect("canonical") == wire);
    }
    assert_eq!(
        count,
        cases.len(),
        "every independent case exercises the SDK"
    );
}

#[test]
fn constructed_containers_match_every_independent_admitted_outcome() {
    let reference: Value =
        serde_json::from_str(include_str!("../oracles/ngap-rel18-messages.json")).expect("oracle");
    let mut outcomes = std::collections::BTreeSet::new();
    let mut compared = 0;
    for case in reference["cases"].as_array().expect("cases") {
        if case["case_class"] != "positive" && case["case_class"] != "ordering" {
            continue;
        }
        let name = case["message"].as_str().expect("message");
        let kind = match name {
            "NGSetupRequest" => MessageType::NgSetupRequest,
            "NGSetupResponse" => MessageType::NgSetupResponse,
            "NGSetupFailure" => MessageType::NgSetupFailure,
            "InitialUEMessage" => MessageType::InitialUeMessage,
            "DownlinkNASTransport" => MessageType::DownlinkNasTransport,
            "UplinkNASTransport" => MessageType::UplinkNasTransport,
            "NGReset" => MessageType::NgReset,
            "PDUSessionResourceNotify" => MessageType::PduSessionResourceNotify,
            "NGResetAcknowledge" => MessageType::NgResetAcknowledge,
            "ErrorIndication" => MessageType::ErrorIndication,
            "NASNonDeliveryIndication" => MessageType::NasNonDeliveryIndication,
            "UEContextReleaseRequest" => MessageType::UeContextReleaseRequest,
            "InitialContextSetupRequest" => MessageType::InitialContextSetupRequest,
            "InitialContextSetupResponse" => MessageType::InitialContextSetupResponse,
            "InitialContextSetupFailure" => MessageType::InitialContextSetupFailure,
            "PDUSessionResourceSetupRequest" => MessageType::PduSessionResourceSetupRequest,
            "PDUSessionResourceSetupResponse" => MessageType::PduSessionResourceSetupResponse,
            "PDUSessionResourceReleaseCommand" => MessageType::PduSessionResourceReleaseCommand,
            "PDUSessionResourceReleaseResponse" => MessageType::PduSessionResourceReleaseResponse,
            "UEContextReleaseCommand" => MessageType::UeContextReleaseCommand,
            "UEContextReleaseComplete" => MessageType::UeContextReleaseComplete,
            _ => panic!("unmapped independent outcome"),
        };
        // Each leaf was independently encoded, before the SDK constructor
        // existed. Do not decode the expected PDU to obtain constructor input.
        let fields: Vec<_> = case["encoded_ies"]
            .as_array()
            .expect("fields")
            .iter()
            .map(|field| {
                let crit = match criticality(&field["criticality"]) {
                    0 => Criticality::reject,
                    1 => Criticality::ignore,
                    2 => Criticality::notify,
                    _ => unreachable!(),
                };
                (
                    field["id"].as_u64().expect("id") as u16,
                    crit,
                    octets(field["value_hex"].as_str().expect("value")),
                )
            })
            .collect();
        let ies: Vec<_> = fields
            .iter()
            .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value))
            .collect();
        let pdu = Pdu::from_protocol_ies(kind, &ies, DecodeContext::default()).expect("construct");
        assert!(pdu.raw.is_empty());
        let expected = octets(case["wire_hex"].as_str().expect("wire"));
        assert!(
            opc_proto_ngap::encode(&pdu, EncodeContext::default()).expect("encode") == expected,
            "constructed wire differs for {}",
            case["name"].as_str().expect("case name")
        );
        outcomes.insert(name);
        compared += 1;
    }
    assert_eq!(outcomes.len(), 15);
    assert_eq!(compared, 21);
}

#[test]
fn every_complete_outcome_rejects_each_wrong_procedure_criticality() {
    let catalog = FixtureCatalog::load_subset_from(&FixtureCatalog::fixture_root(), "ngap")
        .expect("reviewed catalog");
    let mut seen = std::collections::BTreeSet::new();
    for (manifest, wire) in catalog.manifests().filter(|(manifest, _)| {
        manifest.validation_scope == "ngap-release18-message" && manifest.case_class == "positive"
    }) {
        seen.insert(manifest.context["message"].as_str().expect("message"));
        for criticality in [0, 0x40, 0x80] {
            if criticality == wire[2] {
                continue;
            }
            let mut changed = wire.to_vec();
            changed[2] = criticality;
            let result = opc_proto_ngap::decode(&changed, DecodeContext::default());
            assert!(
                result.is_err(),
                "incorrect procedure criticality was accepted"
            );
        }
    }
    assert_eq!(seen.len(), 15);
}
