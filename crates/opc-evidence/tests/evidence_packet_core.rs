//! Tests for packet-core evidence pack schemas and redaction validation.
//!
//! These tests are filtered by `cargo test -p opc-evidence --all-features packet_core`.

mod evidence_common;
use evidence_common::*;
use opc_evidence::{
    AttachProcedureEvidence, AttachProcedureResult, AttachStep, AttachStepResult,
    KernelDataplaneEvidence, PacketCoreEvidencePack, PacketCoreMessageDirection,
    PacketCoreProtocolEvidence, PACKET_CORE_SCHEMA_VERSION,
};
use time::OffsetDateTime;

fn sample_protocol_evidence() -> PacketCoreProtocolEvidence {
    PacketCoreProtocolEvidence {
        schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
        evidence_id: "epdg-ikev2-auth-request-001".into(),
        protocol: "IKEv2".into(),
        scenario: "IKE_AUTH exchange with EAP-AKA".into(),
        message_direction: PacketCoreMessageDirection::Uplink,
        payload_summary: "IKE_AUTH request carrying IDi and CP payload".into(),
        payload_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .into(),
        conformance_tags: vec!["@spec RFC 7296 §1.2".into()],
        requirements: vec!["REQ-IETF-RFC7296-R1-1.2-001".into()],
        fixture_source: "spec-authored from RFC 7296 §1.2".into(),
        fixture_provenance: "hand-authored from independent spec reading".into(),
        captured_at: Some(
            OffsetDateTime::parse(
                "2026-06-28T00:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap(),
        ),
        notes: Some("Experimental protocol evidence shape.".into()),
    }
}

fn sample_attach_evidence() -> AttachProcedureEvidence {
    AttachProcedureEvidence {
        schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
        evidence_id: "epdg-initial-attach-001".into(),
        procedure: "initial-attach".into(),
        result: AttachProcedureResult::Success,
        steps: vec![
            AttachStep {
                name: "IKE_SA_INIT".into(),
                result: AttachStepResult::Success,
                message_digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .into(),
                ),
                notes: None,
            },
            AttachStep {
                name: "IKE_AUTH_EAP_AKA".into(),
                result: AttachStepResult::Success,
                message_digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .into(),
                ),
                notes: None,
            },
        ],
        ue_identifier_redacted: "<supi-redacted>".into(),
        session_id_redacted: Some("<s2b-session-redacted>".into()),
        serving_node: "epdg-0".into(),
        timestamp: OffsetDateTime::parse(
            "2026-06-28T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap(),
        duration_ms: Some(120),
        requirements: vec!["REQ-3GPP-TS29274-R18-7.1-001".into()],
        notes: Some("Experimental attach procedure evidence shape.".into()),
    }
}

fn sample_kernel_dataplane_evidence() -> KernelDataplaneEvidence {
    KernelDataplaneEvidence {
        schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
        evidence_id: "epdg-kernel-dataplane-001".into(),
        interface_name: "eth0".into(),
        xfrm_state_count: 4,
        xfrm_policy_count: 4,
        routing_entries: 12,
        iptables_rules: 0,
        nftables_rules: 8,
        observed_packets: 1_000_000,
        dropped_packets: 0,
        counters: vec![
            opc_evidence::DataplaneCounter {
                name: "esp_packets".into(),
                value: 900_000,
            },
            opc_evidence::DataplaneCounter {
                name: "gtpu_packets".into(),
                value: 100_000,
            },
        ],
        xfrm_state_summary: vec!["spi=<spi-redacted> mode=tunnel".into()],
        timestamp: OffsetDateTime::parse(
            "2026-06-28T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap(),
        requirements: vec!["REQ-IETF-RFC7296-R1-1.2-001".into()],
        notes: Some("Experimental kernel dataplane evidence shape.".into()),
    }
}

fn sample_pack() -> PacketCoreEvidencePack {
    PacketCoreEvidencePack {
        schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
        pack_id: "epdg-smoke-2026-06-28".into(),
        generated_at: OffsetDateTime::parse(
            "2026-06-28T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap(),
        generated_by: "opc-evidence packet-core schema tests".into(),
        experimental: true,
        protocol_evidence: vec![sample_protocol_evidence()],
        attach_evidence: vec![sample_attach_evidence()],
        kernel_dataplane_evidence: vec![sample_kernel_dataplane_evidence()],
    }
}

#[test]
fn packet_core_protocol_evidence_roundtrips_deterministically() {
    let original = sample_protocol_evidence();
    let json = serde_json::to_string(&original).expect("serialize");
    let round: PacketCoreProtocolEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, round);

    let json2 = serde_json::to_string(&original).expect("serialize again");
    assert_eq!(json, json2, "serialization must be deterministic");
}

#[test]
fn packet_core_attach_evidence_roundtrips_deterministically() {
    let original = sample_attach_evidence();
    let json = serde_json::to_string(&original).expect("serialize");
    let round: AttachProcedureEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, round);

    let json2 = serde_json::to_string(&original).expect("serialize again");
    assert_eq!(json, json2, "serialization must be deterministic");
}

#[test]
fn packet_core_kernel_dataplane_evidence_roundtrips_deterministically() {
    let original = sample_kernel_dataplane_evidence();
    let json = serde_json::to_string(&original).expect("serialize");
    let round: KernelDataplaneEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, round);

    let json2 = serde_json::to_string(&original).expect("serialize again");
    assert_eq!(json, json2, "serialization must be deterministic");
}

#[test]
fn packet_core_evidence_pack_roundtrips_deterministically() {
    let original = sample_pack();
    let json = serde_json::to_string(&original).expect("serialize");
    let round: PacketCoreEvidencePack = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, round);

    let json2 = serde_json::to_string(&original).expect("serialize again");
    assert_eq!(json, json2, "serialization must be deterministic");
}

#[test]
fn packet_core_evidence_pack_fixture_roundtrips() {
    let raw = include_str!("fixtures/packet_core_evidence_pack.json");
    let pack: PacketCoreEvidencePack = serde_json::from_str(raw).expect("deserialize fixture");
    assert!(pack.experimental);
    assert_eq!(pack.protocol_evidence.len(), 1);
    assert_eq!(pack.attach_evidence.len(), 1);
    assert_eq!(pack.kernel_dataplane_evidence.len(), 1);

    let back = serde_json::to_string_pretty(&pack).unwrap();
    let round: PacketCoreEvidencePack = serde_json::from_str(&back).unwrap();
    assert_eq!(pack, round);
}

#[test]
fn packet_core_evidence_pack_validates_redaction() {
    let pack = sample_pack();
    pack.validate_redaction()
        .expect("sample pack must be redacted");
}

#[test]
fn packet_core_redaction_fails_on_raw_imsi() {
    let mut pack = sample_pack();
    pack.attach_evidence[0].ue_identifier_redacted = "208950000000001".into();
    let err = pack.validate_redaction().unwrap_err();
    assert!(err.to_string().contains("redaction violation"));
    assert!(err.to_string().contains("long digit run"));
}

#[test]
fn packet_core_redaction_fails_on_raw_msisdn() {
    let mut pack = sample_pack();
    pack.attach_evidence[0].ue_identifier_redacted = "+14155552671".into();
    let err = pack.validate_redaction().unwrap_err();
    assert!(err.to_string().contains("redaction violation"));
    assert!(err.to_string().contains("MSISDN"));
}

#[test]
fn packet_core_redaction_fails_on_raw_imei() {
    let mut pack = sample_pack();
    pack.protocol_evidence[0].notes = Some("device IMEI 490154203237518".into());
    let err = pack.validate_redaction().unwrap_err();
    assert!(err.to_string().contains("redaction violation"));
}

#[test]
fn packet_core_redaction_fails_on_nai() {
    let mut pack = sample_pack();
    pack.attach_evidence[0].session_id_redacted = Some("user@example.com".into());
    let err = pack.validate_redaction().unwrap_err();
    assert!(err.to_string().contains("redaction violation"));
    assert!(err.to_string().contains("NAI"));
}

#[test]
fn packet_core_redaction_fails_on_session_id_marker() {
    let mut pack = sample_pack();
    pack.attach_evidence[0].session_id_redacted = Some("Session-Id 12345".into());
    let err = pack.validate_redaction().unwrap_err();
    assert!(err.to_string().contains("redaction violation"));
    assert!(err.to_string().contains("marker"));
}

#[test]
fn packet_core_redaction_fails_on_li_identifier() {
    let mut pack = sample_pack();
    pack.kernel_dataplane_evidence[0].notes = Some("liid-12345 observed".into());
    let err = pack.validate_redaction().unwrap_err();
    assert!(err.to_string().contains("redaction violation"));
}

#[test]
fn packet_core_redaction_fails_on_key_material() {
    let mut pack = sample_pack();
    pack.protocol_evidence[0].notes = Some("-----BEGIN PRIVATE KEY-----".into());
    let err = pack.validate_redaction().unwrap_err();
    assert!(err.to_string().contains("redaction violation"));
    assert!(err.to_string().contains("key material"));
}

#[test]
fn packet_core_redaction_allows_sha256_digests() {
    let mut pack = sample_pack();
    pack.protocol_evidence[0].payload_digest =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into();
    pack.validate_redaction()
        .expect("sha256 digests must not be flagged");
}

#[test]
fn packet_core_redaction_allows_redacted_values() {
    let mut pack = sample_pack();
    pack.attach_evidence[0].ue_identifier_redacted = "<imsi-redacted>".into();
    pack.attach_evidence[0].session_id_redacted = Some("<session-redacted>".into());
    pack.protocol_evidence[0].notes = Some("no sensitive content".into());
    pack.validate_redaction()
        .expect("redacted placeholders must pass");
}

#[test]
fn packet_core_generated_protocol_evidence_matches_schema() {
    let schema: serde_json::Value =
        serde_json::from_str(PACKET_CORE_PROTOCOL_EVIDENCE_SCHEMA).unwrap();
    let value = serde_json::to_value(sample_protocol_evidence()).unwrap();
    schema_support::validate_value_against_schema(&schema, &value)
        .expect("generated protocol evidence must satisfy schema");
}

#[test]
fn packet_core_generated_attach_evidence_matches_schema() {
    let schema: serde_json::Value =
        serde_json::from_str(PACKET_CORE_ATTACH_EVIDENCE_SCHEMA).unwrap();
    let value = serde_json::to_value(sample_attach_evidence()).unwrap();
    schema_support::validate_value_against_schema(&schema, &value)
        .expect("generated attach evidence must satisfy schema");
}

#[test]
fn packet_core_generated_kernel_dataplane_evidence_matches_schema() {
    let schema: serde_json::Value =
        serde_json::from_str(PACKET_CORE_KERNEL_DATAPLANE_EVIDENCE_SCHEMA).unwrap();
    let value = serde_json::to_value(sample_kernel_dataplane_evidence()).unwrap();
    schema_support::validate_value_against_schema(&schema, &value)
        .expect("generated kernel dataplane evidence must satisfy schema");
}

#[test]
fn packet_core_generated_evidence_pack_matches_schema() {
    let schema: serde_json::Value = serde_json::from_str(PACKET_CORE_EVIDENCE_PACK_SCHEMA).unwrap();
    let value = serde_json::to_value(sample_pack()).unwrap();
    schema_support::validate_value_against_schema(&schema, &value)
        .expect("generated evidence pack must satisfy schema");
}
