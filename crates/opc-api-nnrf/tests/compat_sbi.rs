//! Compatibility test: hand-written `opc-sbi` NRF payloads can be normalized
//! into the generated `opc-api-nnrf` types.
//!
//! `opc-sbi` intentionally uses a minimal, discovery-focused profile with
//! snake-case JSON keys and lowercase NF-type/status enumerations. The
//! generated TS 29.510 types use camel-case keys and SCREAMING_SNAKE_CASE
//! extensible enums. This test proves the two representations describe the
//! same NRF object at the serde value level.

use opc_api_nnrf::{NfProfile, NfServiceStatus, NfStatus, NfType};
use opc_sbi::nrf::NfProfile as SbiNfProfile;
use opc_types::{NfInstanceId, NfType as SbiNfType, PlmnId, Snssai};
use serde_json::Value;

/// Convert an `opc-sbi` JSON value into the shape expected by `opc-api-nnrf`.
///
/// The two crates use different JSON conventions:
/// - field names: snake_case → camelCase
/// - NF type/status enums: lowercase/PascalCase → SCREAMING_SNAKE_CASE
fn sbi_value_to_generated(mut value: Value) -> Value {
    let Some(obj) = value.as_object_mut() else {
        return value;
    };

    let rename = [
        ("nf_instance_id", "nfInstanceId"),
        ("nf_type", "nfType"),
        ("nf_status", "nfStatus"),
        ("ipv4_addresses", "ipv4Addresses"),
        ("fqdn", "fqdn"),
        ("plmn_list", "plmnList"),
        ("s_nssais", "sNssais"),
        ("nf_services", "nfServices"),
        ("priority", "priority"),
        ("capacity", "capacity"),
    ];

    for (old, new) in rename {
        if let Some(v) = obj.remove(old) {
            obj.insert(new.to_string(), v);
        }
    }

    if let Some(Value::String(ty)) = obj.get_mut("nfType") {
        *ty = ty.to_uppercase();
    }
    if let Some(Value::String(status)) = obj.get_mut("nfStatus") {
        *status = status.to_uppercase().replace(' ', "_");
    }

    Value::Object(obj.clone())
}

fn sample_sbi_profile() -> SbiNfProfile {
    SbiNfProfile {
        nf_instance_id: NfInstanceId::new("amf-01").unwrap(),
        nf_type: SbiNfType::new("amf").unwrap(),
        nf_status: opc_sbi::nrf::NfStatus::Registered,
        ipv4_addresses: vec!["10.0.0.1".into(), "10.0.0.2".into()],
        fqdn: Some("amf01.example.com".into()),
        plmn_list: vec![PlmnId::new("001", "01").unwrap()],
        s_nssais: vec![Snssai::new(1, Some("000001")).unwrap()],
        nf_services: vec!["nnamf-comm".into(), "nnamf-mt".into()],
        priority: 10,
        capacity: 100,
    }
}

#[test]
fn sbi_nf_profile_deserializes_into_generated_type() {
    let sbi = sample_sbi_profile();
    let raw = serde_json::to_value(&sbi).expect("serialize opc-sbi profile");
    let generated_value = sbi_value_to_generated(raw);

    let generated: NfProfile = serde_json::from_value(generated_value)
        .expect("opc-sbi profile should deserialize into generated NfProfile");

    assert_eq!(generated.nf_instance_id, sbi.nf_instance_id);
    assert_eq!(generated.nf_type, NfType::Amf);
    assert_eq!(generated.nf_status, NfStatus::Registered);
    assert_eq!(generated.ipv4_addresses, Some(sbi.ipv4_addresses));
    assert_eq!(generated.fqdn, sbi.fqdn);
    assert_eq!(generated.plmn_list, Some(sbi.plmn_list));
    assert_eq!(generated.s_nssais, Some(sbi.s_nssais));
    assert_eq!(
        generated.nf_services,
        Some(
            sbi.nf_services
                .into_iter()
                .map(Value::String)
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(generated.priority, Some(sbi.priority));
    assert_eq!(generated.capacity, Some(sbi.capacity));
}

#[test]
fn sbi_nf_profile_round_trip_preserves_identity() {
    let sbi = sample_sbi_profile();
    let raw = serde_json::to_value(&sbi).unwrap();
    let generated_value = sbi_value_to_generated(raw);

    let generated: NfProfile = serde_json::from_value(generated_value).unwrap();
    let back = serde_json::to_value(&generated).unwrap();

    // The generated type emits the same camel-case, SCREAMING_SNAKE_CASE shape.
    assert_eq!(back["nfInstanceId"], "amf-01");
    assert_eq!(back["nfType"], "AMF");
    assert_eq!(back["nfStatus"], "REGISTERED");
    assert_eq!(
        back["ipv4Addresses"],
        serde_json::json!(["10.0.0.1", "10.0.0.2"])
    );
    assert_eq!(back["fqdn"], "amf01.example.com");
    assert_eq!(back["priority"], 10);
    assert_eq!(back["capacity"], 100);
}

#[test]
fn generated_nf_service_round_trip() {
    let json = serde_json::json!({
        "serviceInstanceId": "svc-01",
        "serviceName": "nnamf-comm",
        "versions": [
            {"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}
        ],
        "scheme": "https",
        "nfServiceStatus": "REGISTERED"
    });

    let service: opc_api_nnrf::NfService = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(service.service_instance_id, "svc-01");
    assert_eq!(service.service_name, "nnamf-comm");
    assert_eq!(service.scheme, "https");
    assert_eq!(service.nf_service_status, NfServiceStatus::Registered);
    assert_eq!(service.versions.len(), 1);

    // Optional fields are serialized as explicit nulls, so a full value
    // comparison requires the same shape. Round-trip through serde instead.
    let back = serde_json::to_value(&service).unwrap();
    let round_tripped: opc_api_nnrf::NfService = serde_json::from_value(back).unwrap();
    assert_eq!(service, round_tripped);
}
