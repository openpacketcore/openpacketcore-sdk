mod evidence_common;
use evidence_common::*;
use std::collections::HashMap;

#[test]
fn compute_digest_is_stable() {
    let d1 = compute_digest(b"hello world");
    let d2 = compute_digest(b"hello world");
    assert_eq!(d1, d2);
    assert!(d1.starts_with("sha256:"));
}

#[test]
fn compute_digest_changes_on_content() {
    let d1 = compute_digest(b"hello world");
    let d2 = compute_digest(b"hello world!");
    assert_ne!(d1, d2);
}

#[test]
fn manifest_verifies_matching_digests() {
    let data = b"conformance-report-contents";
    let digest = compute_digest(data);

    let mut expected = HashMap::new();
    expected.insert("conformance-report.json".into(), digest);

    let manifest = Manifest {
        schema_version: "1.0.0".into(),
        sdk_version: "0.1.0".into(),
        git_commit: "abc123".into(),
        artifact_digests: vec![],
        file_digests: vec![ManifestEntry {
            path: "conformance-report.json".into(),
            digest: expected.get("conformance-report.json").unwrap().clone(),
        }],
        signing_identity: "release-bot@openpacketcore.dev".into(),
        generation_tool: "opc-evidence".into(),
        generation_tool_version: "0.1.0".into(),
        generation_timestamp: "2026-05-27T17:25:13Z".into(),
        known_incomplete_sections: vec![],
        metadata: HashMap::new(),
    };

    manifest.verify_file_digests(&expected).unwrap();
}

#[test]
fn manifest_detects_tampered_digest() {
    let mut expected = HashMap::new();
    expected.insert(
        "conformance-report.json".into(),
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
    );

    let manifest = Manifest {
        schema_version: "1.0.0".into(),
        sdk_version: "0.1.0".into(),
        git_commit: "abc123".into(),
        artifact_digests: vec![],
        file_digests: vec![ManifestEntry {
            path: "conformance-report.json".into(),
            digest: "sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
                .into(),
        }],
        signing_identity: "release-bot@openpacketcore.dev".into(),
        generation_tool: "opc-evidence".into(),
        generation_tool_version: "0.1.0".into(),
        generation_timestamp: "2026-05-27T17:25:13Z".into(),
        known_incomplete_sections: vec![],
        metadata: HashMap::new(),
    };

    let err = manifest
        .verify_file_digests(&expected)
        .expect_err("should detect tamper");
    assert!(matches!(err, EvidenceError::ManifestTampered));
}

#[test]
fn manifest_detects_missing_artifact() {
    let manifest = Manifest {
        schema_version: "1.0.0".into(),
        sdk_version: "0.1.0".into(),
        git_commit: "abc123".into(),
        artifact_digests: vec![],
        file_digests: vec![ManifestEntry {
            path: "missing.json".into(),
            digest: "sha256:abc".into(),
        }],
        signing_identity: "release-bot@openpacketcore.dev".into(),
        generation_tool: "opc-evidence".into(),
        generation_tool_version: "0.1.0".into(),
        generation_timestamp: "2026-05-27T17:25:13Z".into(),
        known_incomplete_sections: vec![],
        metadata: HashMap::new(),
    };

    let err = manifest
        .verify_file_digests(&HashMap::new())
        .expect_err("should detect missing");
    assert!(matches!(err, EvidenceError::MissingArtifact(_)));
}

#[test]
fn manifest_fixture_roundtrips() {
    let raw = include_str!("fixtures/manifest.json");
    let manifest: Manifest = serde_json::from_str(raw).unwrap();
    assert_eq!(manifest.schema_version, "1.0.0");
    assert_eq!(manifest.file_digests.len(), 2);
    assert_eq!(manifest.artifact_digests.len(), 1);
    assert_eq!(manifest.artifact_digests[0].path, "target/release/opc-cnf");
    assert_eq!(manifest.generation_tool, "opc-evidence");
    assert_eq!(manifest.generation_tool_version, "0.1.0");
    assert_eq!(manifest.generation_timestamp, "2026-05-27T17:25:13Z");
    assert_eq!(
        manifest.known_incomplete_sections,
        vec!["5.3-gtp-v2-extension-headers"]
    );

    let back = serde_json::to_string_pretty(&manifest).unwrap();
    let round: Manifest = serde_json::from_str(&back).unwrap();
    assert_eq!(round.schema_version, manifest.schema_version);
    assert_eq!(round.file_digests.len(), manifest.file_digests.len());
    assert_eq!(
        round.artifact_digests.len(),
        manifest.artifact_digests.len()
    );
    assert_eq!(round.generation_tool, manifest.generation_tool);
    assert_eq!(
        round.generation_tool_version,
        manifest.generation_tool_version
    );
    assert_eq!(round.generation_timestamp, manifest.generation_timestamp);
    assert_eq!(
        round.known_incomplete_sections,
        manifest.known_incomplete_sections
    );
}

#[test]
fn generated_manifest_matches_versioned_schema() {
    let schema: serde_json::Value = serde_json::from_str(BUNDLE_MANIFEST_SCHEMA).unwrap();
    let manifest: Manifest = serde_json::from_str(include_str!("fixtures/manifest.json")).unwrap();
    let value = serde_json::to_value(manifest).unwrap();
    schema_support::validate_value_against_schema(&schema, &value)
        .expect("generated Manifest must satisfy the committed RFC 006 schema");
}

#[test]
fn schema_rejects_manifest_without_signing_identity() {
    let schema: serde_json::Value = serde_json::from_str(BUNDLE_MANIFEST_SCHEMA).unwrap();
    let mut manifest_val: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/manifest.json")).unwrap();
    if let Some(obj) = manifest_val.as_object_mut() {
        obj.remove("signing_identity");
    }
    let err = schema_support::validate_value_against_schema(&schema, &manifest_val)
        .expect_err("should reject manifest without signing_identity");
    assert!(err.contains("signing_identity"), "error was: {err}");
}
