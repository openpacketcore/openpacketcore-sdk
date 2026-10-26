//! SBI NRF payloads must conform directly to the generated TS 29.510 schema.

use opc_api_nnrf::{NfProfile, NfServiceStatus, NfStatus, NfType};
use opc_sbi::nrf::NfProfile as SbiNfProfile;
use opc_types::{NfInstanceId, NfType as SbiNfType, PlmnId, Snssai};

fn sample_sbi_profile() -> SbiNfProfile {
    SbiNfProfile {
        nf_instance_id: NfInstanceId::new("amf-01").unwrap(),
        nf_type: SbiNfType::new("amf").unwrap(),
        nf_status: opc_sbi::nrf::NfStatus::Registered,
        ipv4_addresses: vec!["10.0.0.1".into(), "10.0.0.2".into()],
        fqdn: Some("amf01.example.com".into()),
        plmn_list: vec![PlmnId::new("001", "01").unwrap().into()],
        s_nssais: vec![Snssai::new(1, Some("000001")).unwrap().into()],
        nf_services: vec![
            opc_sbi::testkit::nrf::test_service("namf-comm"),
            opc_sbi::testkit::nrf::test_service("namf-mt"),
        ],
        priority: 10,
        capacity: 100,
    }
}

#[test]
fn sbi_nf_profile_deserializes_into_generated_type() {
    let sbi = sample_sbi_profile();
    let raw = serde_json::to_value(&sbi).expect("serialize opc-sbi profile");
    let generated_value = raw;

    let generated: NfProfile = serde_json::from_value(generated_value)
        .expect("opc-sbi profile should deserialize into generated NfProfile");

    assert_eq!(generated.nf_instance_id, sbi.nf_instance_id);
    assert_eq!(generated.nf_type, NfType::Amf);
    assert_eq!(generated.nf_status, NfStatus::Registered);
    assert_eq!(generated.ipv4_addresses, Some(sbi.ipv4_addresses));
    assert_eq!(generated.fqdn, sbi.fqdn);
    assert_eq!(
        generated
            .plmn_list
            .map(|plmns| plmns.into_iter().map(Into::into).collect::<Vec<PlmnId>>()),
        Some(sbi.plmn_list.into_iter().map(Into::into).collect())
    );
    assert_eq!(
        generated
            .s_nssais
            .map(|snssais| snssais.into_iter().map(Into::into).collect::<Vec<Snssai>>()),
        Some(sbi.s_nssais.into_iter().map(Into::into).collect())
    );
    assert_eq!(generated.nf_services, Some(sbi.nf_services));
    assert_eq!(generated.priority, Some(sbi.priority));
    assert_eq!(generated.capacity, Some(sbi.capacity));
}

#[test]
fn sbi_nf_profile_round_trip_preserves_identity() {
    let sbi = sample_sbi_profile();
    let raw = serde_json::to_value(&sbi).unwrap();
    let generated_value = raw;

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
        "serviceName": "namf-comm",
        "versions": [
            {"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}
        ],
        "scheme": "https",
        "nfServiceStatus": "REGISTERED"
    });

    let service: opc_api_nnrf::NfService = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(service.service_instance_id, "svc-01");
    assert_eq!(service.service_name, "namf-comm");
    assert_eq!(service.scheme, "https");
    assert_eq!(service.nf_service_status, NfServiceStatus::Registered);
    assert_eq!(service.versions.len(), 1);

    let back = serde_json::to_value(&service).unwrap();
    assert_eq!(
        back, json,
        "absent optional attributes must not become null"
    );
    let round_tripped: opc_api_nnrf::NfService = serde_json::from_value(back).unwrap();
    assert_eq!(service, round_tripped);
}
