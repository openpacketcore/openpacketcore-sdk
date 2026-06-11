mod evidence_common;
use evidence_common::*;

#[test]
fn test_gap_006_004_bundle_signing_and_verification() {
    let manifest = Manifest {
        schema_version: "1.0.0".to_string(),
        sdk_version: "0.1.0".to_string(),
        git_commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        artifact_digests: vec![ManifestEntry {
            path: "sbom.json".to_string(),
            digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
        }],
        file_digests: vec![ManifestEntry {
            path: "src/lib.rs".to_string(),
            digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
        }],
        signing_identity: "mock-identity-key123".to_string(),
        generation_tool: "opc-evidence".to_string(),
        generation_tool_version: "0.1.0".to_string(),
        generation_timestamp: "2026-06-08T12:00:00Z".to_string(),
        known_incomplete_sections: vec![],
        metadata: std::collections::HashMap::new(),
    };

    let signer = MockSigner::new("key123");
    let verifier = MockVerifier::new("key123");

    let manifest_bytes = manifest_signing_bytes(&manifest).unwrap();
    let signature = signer.sign(&manifest_bytes).unwrap();

    let mut bundle = EvidenceBundle {
        manifest: manifest.clone(),
        signature: signature.clone(),
        conformance_report: None,
        sbom: None,
        vex: None,
        provenance: None,
        performance_baseline: None,
        data_governance_report: None,
    };

    let mut files = std::collections::HashMap::new();
    files.insert("sbom.json".to_string(), vec![]);
    files.insert("src/lib.rs".to_string(), vec![]);

    // 1. Success verification
    assert!(verify_bundle(&bundle, &verifier, &files).is_ok());

    // 2. Reject missing signature
    bundle.signature = "".to_string();
    assert!(verify_bundle(&bundle, &verifier, &files).is_err());
    bundle.signature = signature.clone();

    // 3. Reject tampered signature/payload
    let wrong_verifier = MockVerifier::new("wrong-key");
    assert!(verify_bundle(&bundle, &wrong_verifier, &files).is_err());

    // 4. Reject unknown schema version
    bundle.manifest.schema_version = "2.0.0".to_string();
    let manifest_bytes_v2 = serde_json::to_vec(&bundle.manifest).unwrap();
    bundle.signature = signer.sign(&manifest_bytes_v2).unwrap();
    assert!(verify_bundle(&bundle, &verifier, &files).is_err());
    bundle.manifest.schema_version = "1.0.0".to_string();
    bundle.signature = signature.clone();

    // 5. Reject missing artifacts
    let mut missing_files = files.clone();
    missing_files.remove("sbom.json");
    assert!(verify_bundle(&bundle, &verifier, &missing_files).is_err());

    // 6. Reject digest mismatch
    let mut tampered_files = files.clone();
    tampered_files.insert("sbom.json".to_string(), b"tampered content".to_vec());
    assert!(verify_bundle(&bundle, &verifier, &tampered_files).is_err());
}
