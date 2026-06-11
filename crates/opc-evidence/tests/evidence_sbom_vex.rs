mod evidence_common;
use evidence_common::*;

#[test]
fn test_gap_006_002_sbom_and_vex() {
    let workspace_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let sbom = generate_sbom(workspace_dir).unwrap();
    assert_eq!(sbom.bom_format, "CycloneDX");
    assert_eq!(sbom.spec_version, "1.4");
    assert!(!sbom.components.is_empty());

    let opc_evidence_comp = sbom.components.iter().find(|c| c.name == "opc-evidence");
    assert!(opc_evidence_comp.is_some());
    let comp = opc_evidence_comp.unwrap();
    assert_eq!(comp.component_type, "application");

    assert!(!comp.licenses.is_empty());
    assert_eq!(comp.licenses[0].license.id, Some("Apache-2.0".to_string()));

    assert!(comp.external_references.is_some());
    let refs = comp.external_references.as_ref().unwrap();
    assert_eq!(
        refs[0].url,
        "https://github.com/openpacketcore/openpacketcore-sdk"
    );

    let vex_res = VexPolicyResult::new(
        "CVE-2026-99999".to_string(),
        VexDecision::NotAffected,
        "The vulnerable dependency function is never imported or used.".to_string(),
        Some("No action needed".to_string()),
    )
    .unwrap();

    let record = VexRecord {
        package_name: "some-dep".to_string(),
        package_version: "1.0.0".to_string(),
        policy_result: vex_res.clone(),
        source_evidence: Some("Static code analysis verify".to_string()),
    };

    assert!(validate_vex_record(&record).is_ok());

    let bad_record = VexRecord {
        package_name: "".to_string(),
        package_version: "1.0.0".to_string(),
        policy_result: vex_res,
        source_evidence: None,
    };
    assert!(validate_vex_record(&bad_record).is_err());

    let bad_result = VexPolicyResult::new(
        "CVE-2026-99999".to_string(),
        VexDecision::NotAffected,
        "".to_string(),
        None,
    );
    assert!(bad_result.is_err());
}

#[test]
fn sbom_generation_is_deterministic_and_resolves_lock_dependency_specs() {
    let temp_dir = tempfile::tempdir().unwrap();
    let crates_dir = temp_dir.path().join("crates");
    let app_dir = crates_dir.join("app");
    let dep_dir = crates_dir.join("dep");
    std::fs::create_dir_all(&app_dir).unwrap();
    std::fs::create_dir_all(&dep_dir).unwrap();

    std::fs::write(
        temp_dir.path().join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/*"]

[workspace.package]
version = "0.1.0"
license = "Apache-2.0"
repository = "https://example.invalid/repo"
"#,
    )
    .unwrap();
    std::fs::write(
        app_dir.join("Cargo.toml"),
        r#"
[package]
name = "app"
version.workspace = true
license.workspace = true
repository.workspace = true
"#,
    )
    .unwrap();
    std::fs::write(
        dep_dir.join("Cargo.toml"),
        r#"
[package]
name = "dep"
version = "2.0.0"
"#,
    )
    .unwrap();
    std::fs::write(
        temp_dir.path().join("Cargo.lock"),
        r#"
version = 3

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "dep 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "dep"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
    )
    .unwrap();

    let ts = "2026-06-08T12:00:00Z";
    let first = generate_sbom_at(temp_dir.path(), ts).unwrap();
    let second = generate_sbom_at(temp_dir.path(), ts).unwrap();
    assert_eq!(first, second);
    assert!(first.serial_number.starts_with("urn:uuid:"));

    let app_ref = "pkg:cargo/app@0.1.0";
    let dep_ref = "pkg:cargo/dep@2.0.0";
    let app_dep = first
        .dependencies
        .iter()
        .find(|dep| dep.dependency_ref == app_ref)
        .expect("app dependency edge must exist");
    assert_eq!(app_dep.depends_on, vec![dep_ref]);
}
