//! Generated Rust types for the 3GPP TS 29.510 NRF SBI interface.
//!
//! **Status: experimental** — this crate is a pilot for OpenAPI-to-Rust codegen.
//! Types are generated from the official 3GPP OpenAPI YAML specifications by
//! `scripts/generate-api-nnrf.py`.  Do not edit `types.rs` manually; re-run
//! `make generate-api` instead.
//!
//! See `CONFORMANCE.md` for coverage details.

#![forbid(unsafe_code)]

mod types;

pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use opc_types::NfInstanceId;

    #[test]
    fn nf_status_round_trip() {
        let status = NfStatus::Registered;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"REGISTERED\"");
        let decoded: NfStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, decoded);
    }

    #[test]
    fn nf_type_round_trip() {
        let ty = NfType::Amf;
        let json = serde_json::to_string(&ty).unwrap();
        assert_eq!(json, "\"AMF\"");
        let decoded: NfType = serde_json::from_str(&json).unwrap();
        assert_eq!(ty, decoded);
    }

    #[test]
    fn extensible_enum_unknown_variant() {
        let json = r#""UNKNOWN_STATUS""#;
        let status: NfStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status, NfStatus::Other("UNKNOWN_STATUS".into()));
    }

    #[test]
    fn nf_profile_deserialize_minimal() {
        let json = r#"{
            "nfInstanceId": "amf-01",
            "nfType": "AMF",
            "nfStatus": "REGISTERED",
            "priority": 1,
            "capacity": 100
        }"#;
        let profile: NfProfile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.nf_instance_id, NfInstanceId::new("amf-01").unwrap());
        assert_eq!(profile.nf_type, NfType::Amf);
        assert_eq!(profile.nf_status, NfStatus::Registered);
        assert_eq!(profile.priority, Some(1));
        assert_eq!(profile.capacity, Some(100));
        assert!(profile.fqdn.is_none());
    }

    #[test]
    fn nf_profile_deserialize_with_optional_fields() {
        let json = r#"{
            "nfInstanceId": "smf-01",
            "nfType": "SMF",
            "nfStatus": "SUSPENDED",
            "ipv4Addresses": ["10.0.0.1"],
            "fqdn": "smf.example.com",
            "nfServices": [{"serviceInstanceId":"svc-1","serviceName":"nsmf-pdusession","versions":[{"apiVersionInUri":"v1","apiFullVersion":"1.0.0"}],"scheme":"https","nfServiceStatus":"REGISTERED"}]
        }"#;
        let profile: NfProfile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.ipv4_addresses, Some(vec!["10.0.0.1".into()]));
        assert_eq!(profile.fqdn, Some("smf.example.com".into()));
        assert!(profile.nf_services.is_some());
    }

    #[test]
    fn nf_service_deserialize_minimal() {
        let json = r#"{
            "serviceInstanceId": "svc-01",
            "serviceName": "nnamf-comm",
            "versions": [{"apiVersionInUri":"v1","apiFullVersion":"1.0.0"}],
            "scheme": "https",
            "nfServiceStatus": "REGISTERED"
        }"#;
        let service: NfService = serde_json::from_str(json).unwrap();
        assert_eq!(service.service_instance_id, "svc-01");
        assert_eq!(service.service_name, "nnamf-comm");
        assert_eq!(service.scheme, "https");
        assert_eq!(service.nf_service_status, NfServiceStatus::Registered);
        assert_eq!(service.versions.len(), 1);
    }

    #[test]
    fn camel_case_serde() {
        let json =
            r#"{"nfInstanceId":"test-01","nfType":"AMF","nfStatus":"REGISTERED","priority":1}"#;
        let profile: NfProfile = serde_json::from_str(json).unwrap();
        assert_eq!(
            profile.nf_instance_id,
            NfInstanceId::new("test-01").unwrap()
        );
        assert_eq!(profile.priority, Some(1));
    }

    #[test]
    fn serialize_then_deserialize_nf_profile() {
        let json = r#"{
            "nfInstanceId": "upf-01",
            "nfType": "UPF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": ["192.168.1.1"],
            "priority": 5,
            "capacity": 200
        }"#;
        let profile: NfProfile = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&profile).unwrap();
        let round_tripped: NfProfile = serde_json::from_str(&serialized).unwrap();
        assert_eq!(profile.nf_instance_id, round_tripped.nf_instance_id);
        assert_eq!(profile.nf_type, round_tripped.nf_type);
        assert_eq!(profile.ipv4_addresses, round_tripped.ipv4_addresses);
    }
}
