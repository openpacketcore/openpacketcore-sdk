mod evidence_common;
use evidence_common::*;
use std::str::FromStr;

#[test]
fn rfc006_versioned_schemas_are_valid_json() {
    for schema in [
        EVIDENCE_RECORD_SCHEMA,
        GAP_RECORD_SCHEMA,
        BUNDLE_MANIFEST_SCHEMA,
        CONFORMANCE_REPORT_SCHEMA,
        REQUIREMENT_INVENTORY_SCHEMA,
        PERFORMANCE_BASELINE_SCHEMA,
        VEX_POLICY_RESULT_SCHEMA,
        PACKET_CORE_PROTOCOL_EVIDENCE_SCHEMA,
        PACKET_CORE_ATTACH_EVIDENCE_SCHEMA,
        PACKET_CORE_KERNEL_DATAPLANE_EVIDENCE_SCHEMA,
        PACKET_CORE_EVIDENCE_PACK_SCHEMA,
    ] {
        serde_json::from_str::<serde_json::Value>(schema)
            .expect("versioned RFC 006 schema file must be valid JSON");
    }
}

#[test]
fn evidence_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        EVIDENCE_RECORD_SCHEMA,
        include_str!("fixtures/evidence_record.json"),
    )
    .expect("evidence fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn gap_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        GAP_RECORD_SCHEMA,
        include_str!("fixtures/gap_record.json"),
    )
    .expect("gap fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn manifest_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        BUNDLE_MANIFEST_SCHEMA,
        include_str!("fixtures/manifest.json"),
    )
    .expect("manifest fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn conformance_report_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        CONFORMANCE_REPORT_SCHEMA,
        include_str!("fixtures/conformance_report.json"),
    )
    .expect("conformance report fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn requirement_inventory_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        REQUIREMENT_INVENTORY_SCHEMA,
        include_str!("fixtures/requirement_inventory.json"),
    )
    .expect("requirement inventory fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn performance_baseline_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        PERFORMANCE_BASELINE_SCHEMA,
        include_str!("fixtures/performance_baseline.json"),
    )
    .expect("performance baseline fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn vex_policy_result_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        VEX_POLICY_RESULT_SCHEMA,
        include_str!("fixtures/vex_policy_result.json"),
    )
    .expect("VEX policy result fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn generated_evidence_record_matches_versioned_schema() {
    let mut record = EvidenceRecord::new(
        RequirementId::from_str("REQ-3GPP-TS29281-R18-5.1-001").unwrap(),
        ConformanceStatus::Partial,
    );
    record
        .source_refs
        .push("crates/opc-proto-gtp/src/header.rs:Gtpv1uHeader".into());
    record
        .test_refs
        .push("crates/opc-proto-gtp/tests/roundtrip.rs:test_gtpu_header".into());
    record.gap_refs.push("GAP-000123".into());
    record
        .artifact_digests
        .push("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into());
    record.reviewed_by.push("standards-reviewer".into());
    record.last_updated = Some(
        time::OffsetDateTime::parse(
            "2026-05-19T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap(),
    );

    let schema: serde_json::Value = serde_json::from_str(EVIDENCE_RECORD_SCHEMA).unwrap();
    let value = serde_json::to_value(record).unwrap();
    schema_support::validate_value_against_schema(&schema, &value)
        .expect("generated EvidenceRecord must satisfy the committed RFC 006 schema");
}

#[test]
fn generated_gap_matches_versioned_schema() {
    let schema: serde_json::Value = serde_json::from_str(GAP_RECORD_SCHEMA).unwrap();
    let value = serde_json::to_value(valid_gap()).unwrap();
    schema_support::validate_value_against_schema(&schema, &value)
        .expect("generated Gap must satisfy the committed RFC 006 schema");
}

#[test]
fn generated_gap_with_no_owner_matches_versioned_schema() {
    let schema: serde_json::Value = serde_json::from_str(GAP_RECORD_SCHEMA).unwrap();
    let mut gap = valid_gap();
    gap.owner = None;
    let value = serde_json::to_value(gap).unwrap();
    schema_support::validate_value_against_schema(&schema, &value)
        .expect("generated Gap with no owner must satisfy the committed RFC 006 schema");
}

#[test]
fn packet_core_protocol_evidence_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        PACKET_CORE_PROTOCOL_EVIDENCE_SCHEMA,
        include_str!("fixtures/packet_core_protocol_evidence.json"),
    )
    .expect("packet-core protocol evidence fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn packet_core_attach_evidence_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        PACKET_CORE_ATTACH_EVIDENCE_SCHEMA,
        include_str!("fixtures/packet_core_attach_evidence.json"),
    )
    .expect("packet-core attach evidence fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn packet_core_kernel_dataplane_evidence_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        PACKET_CORE_KERNEL_DATAPLANE_EVIDENCE_SCHEMA,
        include_str!("fixtures/packet_core_kernel_dataplane_evidence.json"),
    )
    .expect(
        "packet-core kernel dataplane evidence fixture must satisfy the committed RFC 006 schema",
    );
}

#[test]
fn packet_core_evidence_pack_fixture_matches_versioned_schema() {
    schema_support::validate_json_str_against_schema(
        PACKET_CORE_EVIDENCE_PACK_SCHEMA,
        include_str!("fixtures/packet_core_evidence_pack.json"),
    )
    .expect("packet-core evidence pack fixture must satisfy the committed RFC 006 schema");
}

#[test]
fn packet_core_evidence_pack_schema_rejects_experimental_false() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/packet_core_evidence_pack.json")).unwrap();
    value["experimental"] = serde_json::Value::Bool(false);
    let schema: serde_json::Value = serde_json::from_str(PACKET_CORE_EVIDENCE_PACK_SCHEMA).unwrap();
    let err = schema_support::validate_value_against_schema(&schema, &value).unwrap_err();
    assert!(
        err.contains("experimental"),
        "error should mention experimental: {err}"
    );
}

#[test]
fn packet_core_evidence_pack_rejects_wrong_schema_version() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/packet_core_evidence_pack.json")).unwrap();
    value["schema_version"] = "rfc006/v1/wrong".into();
    let schema: serde_json::Value = serde_json::from_str(PACKET_CORE_EVIDENCE_PACK_SCHEMA).unwrap();
    let err = schema_support::validate_value_against_schema(&schema, &value).unwrap_err();
    assert!(
        err.contains("schema_version"),
        "error should mention schema_version: {err}"
    );
}

#[test]
fn packet_core_protocol_evidence_rejects_wrong_schema_version() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/packet_core_protocol_evidence.json")).unwrap();
    value["schema_version"] = "rfc006/v1/wrong".into();
    let schema: serde_json::Value =
        serde_json::from_str(PACKET_CORE_PROTOCOL_EVIDENCE_SCHEMA).unwrap();
    let err = schema_support::validate_value_against_schema(&schema, &value).unwrap_err();
    assert!(
        err.contains("schema_version"),
        "error should mention schema_version: {err}"
    );
}

#[test]
fn packet_core_attach_evidence_rejects_wrong_schema_version() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/packet_core_attach_evidence.json")).unwrap();
    value["schema_version"] = "rfc006/v1/wrong".into();
    let schema: serde_json::Value =
        serde_json::from_str(PACKET_CORE_ATTACH_EVIDENCE_SCHEMA).unwrap();
    let err = schema_support::validate_value_against_schema(&schema, &value).unwrap_err();
    assert!(
        err.contains("schema_version"),
        "error should mention schema_version: {err}"
    );
}

#[test]
fn packet_core_kernel_dataplane_evidence_rejects_wrong_schema_version() {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/packet_core_kernel_dataplane_evidence.json"
    ))
    .unwrap();
    value["schema_version"] = "rfc006/v1/wrong".into();
    let schema: serde_json::Value =
        serde_json::from_str(PACKET_CORE_KERNEL_DATAPLANE_EVIDENCE_SCHEMA).unwrap();
    let err = schema_support::validate_value_against_schema(&schema, &value).unwrap_err();
    assert!(
        err.contains("schema_version"),
        "error should mention schema_version: {err}"
    );
}

#[test]
fn packet_core_evidence_pack_inline_items_reject_wrong_schema_version() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/packet_core_evidence_pack.json")).unwrap();

    // protocol_evidence inline item.
    {
        let mut value = value.clone();
        value["protocol_evidence"][0]["schema_version"] = "rfc006/v1/wrong".into();
        let schema: serde_json::Value =
            serde_json::from_str(PACKET_CORE_EVIDENCE_PACK_SCHEMA).unwrap();
        let err = schema_support::validate_value_against_schema(&schema, &value).unwrap_err();
        assert!(
            err.contains("schema_version"),
            "error should mention schema_version: {err}"
        );
    }

    // attach_evidence inline item.
    {
        let mut value = value.clone();
        value["attach_evidence"][0]["schema_version"] = "rfc006/v1/wrong".into();
        let schema: serde_json::Value =
            serde_json::from_str(PACKET_CORE_EVIDENCE_PACK_SCHEMA).unwrap();
        let err = schema_support::validate_value_against_schema(&schema, &value).unwrap_err();
        assert!(
            err.contains("schema_version"),
            "error should mention schema_version: {err}"
        );
    }

    // kernel_dataplane_evidence inline item.
    {
        value["kernel_dataplane_evidence"][0]["schema_version"] = "rfc006/v1/wrong".into();
        let schema: serde_json::Value =
            serde_json::from_str(PACKET_CORE_EVIDENCE_PACK_SCHEMA).unwrap();
        let err = schema_support::validate_value_against_schema(&schema, &value).unwrap_err();
        assert!(
            err.contains("schema_version"),
            "error should mention schema_version: {err}"
        );
    }
}

#[test]
fn packet_core_schema_versions_match_constant() {
    fn assert_schema_version_const(schema: &serde_json::Value, pointer: &str, label: &str) {
        let actual = schema
            .pointer(pointer)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{label}: missing schema_version const at {pointer}"));
        assert_eq!(
            actual,
            opc_evidence::PACKET_CORE_SCHEMA_VERSION,
            "{label}: schema_version const drift"
        );
    }

    let pack_schema: serde_json::Value =
        serde_json::from_str(PACKET_CORE_EVIDENCE_PACK_SCHEMA).unwrap();
    assert_schema_version_const(&pack_schema, "/properties/schema_version/const", "pack");
    assert_schema_version_const(
        &pack_schema,
        "/properties/protocol_evidence/items/properties/schema_version/const",
        "pack/protocol_evidence",
    );
    assert_schema_version_const(
        &pack_schema,
        "/properties/attach_evidence/items/properties/schema_version/const",
        "pack/attach_evidence",
    );
    assert_schema_version_const(
        &pack_schema,
        "/properties/kernel_dataplane_evidence/items/properties/schema_version/const",
        "pack/kernel_dataplane_evidence",
    );

    let standalone_schemas = [
        ("protocol", PACKET_CORE_PROTOCOL_EVIDENCE_SCHEMA),
        ("attach", PACKET_CORE_ATTACH_EVIDENCE_SCHEMA),
        ("kernel_dataplane", PACKET_CORE_KERNEL_DATAPLANE_EVIDENCE_SCHEMA),
    ];
    for (label, raw) in standalone_schemas {
        let schema: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_schema_version_const(&schema, "/properties/schema_version/const", label);
    }
}
