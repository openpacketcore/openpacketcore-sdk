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

    let mut bundle = EvidenceBundle {
        manifest: manifest.clone(),
        signature: String::new(),
        conformance_report: None,
        sbom: None,
        vex: None,
        provenance: None,
        performance_baseline: None,
        data_governance_report: None,
    };
    sign_bundle(&mut bundle, &signer).unwrap();
    let signature = bundle.signature.clone();

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
    sign_bundle(&mut bundle, &signer).unwrap();
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

#[test]
fn tampering_an_embedded_blob_invalidates_the_signature() {
    let manifest = Manifest {
        schema_version: "1.0.0".to_string(),
        sdk_version: "0.1.0".to_string(),
        git_commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        artifact_digests: vec![],
        file_digests: vec![],
        signing_identity: "mock-identity-key123".to_string(),
        generation_tool: "opc-evidence".to_string(),
        generation_tool_version: "0.1.0".to_string(),
        generation_timestamp: "2026-06-08T12:00:00Z".to_string(),
        known_incomplete_sections: vec![],
        metadata: std::collections::HashMap::new(),
    };

    let signer = MockSigner::new("key123");
    let verifier = MockVerifier::new("key123");

    // Build a bundle carrying an embedded SBOM and sign over manifest + blobs.
    let mut bundle = EvidenceBundle {
        manifest,
        signature: String::new(),
        conformance_report: None,
        sbom: Some("{\"sbom\":\"original\"}".to_string()),
        vex: None,
        provenance: None,
        performance_baseline: None,
        data_governance_report: None,
    };
    sign_bundle(&mut bundle, &signer).unwrap();

    let files = std::collections::HashMap::new();
    assert!(verify_bundle(&bundle, &verifier, &files).is_ok());

    // Swapping the embedded SBOM must now invalidate the signature.
    bundle.sbom = Some("{\"sbom\":\"malicious\"}".to_string());
    assert!(
        verify_bundle(&bundle, &verifier, &files).is_err(),
        "a tampered embedded blob must fail verification"
    );
}

#[test]
fn signing_domains_and_manifest_order_are_deterministic() {
    let mut left = Manifest {
        schema_version: "1.0.0".to_string(),
        sdk_version: "0.2.0".to_string(),
        git_commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        artifact_digests: vec![
            ManifestEntry {
                path: "z/report.json".to_string(),
                digest: compute_digest(b"z"),
            },
            ManifestEntry {
                path: "a/report.json".to_string(),
                digest: compute_digest(b"a"),
            },
        ],
        file_digests: vec![],
        signing_identity: "mock-identity-key123".to_string(),
        generation_tool: "opc-evidence".to_string(),
        generation_tool_version: "0.2.0".to_string(),
        generation_timestamp: "2026-07-15T00:00:00Z".to_string(),
        known_incomplete_sections: vec![],
        metadata: std::collections::HashMap::from([
            ("z".to_string(), "last".to_string()),
            ("a".to_string(), "first".to_string()),
        ]),
    };
    let mut right = left.clone();
    right.artifact_digests.reverse();
    right.metadata = std::collections::HashMap::from([
        ("a".to_string(), "first".to_string()),
        ("z".to_string(), "last".to_string()),
    ]);

    let manifest_bytes = manifest_signing_bytes(&left).unwrap();
    assert_eq!(manifest_bytes, manifest_signing_bytes(&right).unwrap());
    assert_eq!(
        compute_digest(&manifest_bytes),
        "sha256:0e65d901d5c7809f39d361ffca766922eeb2238fca807524343c9cd382b1abf6"
    );

    let bundle = EvidenceBundle {
        manifest: left.clone(),
        signature: String::new(),
        conformance_report: None,
        sbom: None,
        vex: None,
        provenance: None,
        performance_baseline: None,
        data_governance_report: None,
    };
    let bundle_bytes = bundle_signing_bytes(&bundle).unwrap();
    assert_ne!(
        manifest_bytes, bundle_bytes,
        "manifest signatures must not replay as bundle signatures"
    );
    assert_eq!(
        compute_digest(&bundle_bytes),
        "sha256:9226d6bfd7edf871c7393227ce88920a0ac840d1c59d44d595e2bd2c9145edca"
    );

    left.artifact_digests[0].digest = compute_digest(b"changed");
    assert_ne!(
        manifest_signing_bytes(&left).unwrap(),
        manifest_signing_bytes(&right).unwrap()
    );
}

#[test]
fn signer_identity_is_bound_and_failed_resigning_retains_the_signature() {
    let mut bundle = EvidenceBundle {
        manifest: Manifest {
            schema_version: "1.0.0".to_string(),
            sdk_version: "0.2.0".to_string(),
            git_commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
            artifact_digests: vec![],
            file_digests: vec![],
            signing_identity: "mock-identity-key123".to_string(),
            generation_tool: "opc-evidence".to_string(),
            generation_tool_version: "0.2.0".to_string(),
            generation_timestamp: "2026-07-15T00:00:00Z".to_string(),
            known_incomplete_sections: vec![],
            metadata: std::collections::HashMap::new(),
        },
        signature: String::new(),
        conformance_report: None,
        sbom: None,
        vex: None,
        provenance: None,
        performance_baseline: None,
        data_governance_report: None,
    };
    sign_bundle(&mut bundle, &MockSigner::new("key123")).unwrap();
    let original = bundle.signature.clone();

    let err = sign_bundle(&mut bundle, &MockSigner::new("wrong-key"))
        .expect_err("a signer with a different identity must be rejected");
    assert_eq!(bundle.signature, original);
    assert!(!err.to_string().contains("key123"));
}

#[test]
fn unsafe_duplicate_and_malformed_manifest_entries_fail_closed() {
    let digest = compute_digest(b"artifact");
    let base = Manifest {
        schema_version: "1.0.0".to_string(),
        sdk_version: "0.2.0".to_string(),
        git_commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        artifact_digests: vec![ManifestEntry {
            path: "evidence/report.json".to_string(),
            digest: digest.clone(),
        }],
        file_digests: vec![],
        signing_identity: "mock-identity-key123".to_string(),
        generation_tool: "opc-evidence".to_string(),
        generation_tool_version: "0.2.0".to_string(),
        generation_timestamp: "2026-07-15T00:00:00Z".to_string(),
        known_incomplete_sections: vec![],
        metadata: std::collections::HashMap::new(),
    };

    for path in [
        "../token=do-not-log",
        "/absolute/report.json",
        "C:\\evidence\\report.json",
        "evidence//report.json",
    ] {
        let mut manifest = base.clone();
        manifest.artifact_digests[0].path = path.to_string();
        let err = validate_manifest_structure(&manifest)
            .expect_err("unsafe manifest paths must be rejected");
        assert!(!err.to_string().contains("do-not-log"));
        assert!(!err.to_string().contains(path));
    }

    let mut duplicate = base.clone();
    duplicate
        .artifact_digests
        .push(duplicate.artifact_digests[0].clone());
    assert!(validate_manifest_structure(&duplicate).is_err());

    let mut duplicate_across_sections = base.clone();
    duplicate_across_sections
        .file_digests
        .push(duplicate_across_sections.artifact_digests[0].clone());
    assert!(validate_manifest_structure(&duplicate_across_sections).is_err());

    let mut malformed_digest = base;
    malformed_digest.artifact_digests[0].digest = "sha256:ABC".to_string();
    assert!(validate_manifest_structure(&malformed_digest).is_err());

    let mut secret_named_manifest = malformed_digest;
    secret_named_manifest.artifact_digests[0].digest = digest;
    secret_named_manifest.artifact_digests[0].path = "token=do-not-log.json".to_string();
    let mut bundle = EvidenceBundle {
        manifest: secret_named_manifest,
        signature: String::new(),
        conformance_report: None,
        sbom: None,
        vex: None,
        provenance: None,
        performance_baseline: None,
        data_governance_report: None,
    };
    sign_bundle(&mut bundle, &MockSigner::new("key123")).unwrap();
    let err = verify_bundle(
        &bundle,
        &MockVerifier::new("key123"),
        &std::collections::HashMap::new(),
    )
    .expect_err("missing manifest entries must fail without echoing their path");
    assert!(!err.to_string().contains("do-not-log"));
}
