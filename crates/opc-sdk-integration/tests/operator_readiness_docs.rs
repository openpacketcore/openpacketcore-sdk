#[test]
fn operator_readiness_doc_tracks_final_validation_boundaries() {
    let readme = include_str!("../../../README.md");
    let contributing = include_str!("../../../CONTRIBUTING.md");
    let readiness = include_str!("../../../docs/operator-readiness.md");
    let status = include_str!("../../../docs/implementation-status.md");

    for required in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo test --workspace",
        "T-a2ed9b0f",
        "T-01342432",
        "T-099afa77",
        "GAP-009-001",
        "GAP-009-008",
        "BootstrapConfig::apply_fail_closed",
        "EncryptingManagedDatastore",
        "EncryptingSessionBackend",
        "NrfDrainHook",
        "not Kubernetes-operator-ready",
        "T-8c57ecee",
        "ADR 0018",
        "opc-proto-diameter",
        "Experimental protocol crates",
        "operators/operator-sdk-go",
        "docs/refactoring/epdg-sdk-final-hardening-triage.md",
    ] {
        assert!(
            readiness.contains(required),
            "operator readiness doc must mention {required}"
        );
    }

    assert!(
        status.contains("docs/operator-readiness.md") || status.contains("operator-readiness.md"),
        "implementation status must link the operator readiness handoff"
    );
    assert!(
        status.contains("Historical foundation validation snapshot — T-9be95f92"),
        "implementation status must retain the scoped historical validation snapshot"
    );
    assert!(
        status.contains("Historical EPC/untrusted-access hardening snapshot — T-8c57ecee"),
        "implementation status must retain the scoped EPC/untrusted-access snapshot"
    );
    assert!(
        readme.contains("no workspace-wide production profile is currently approved"),
        "the root README must not turn scoped CI into production approval"
    );
    assert!(
        contributing.contains(
            "Cargo publication eligibility is release mechanics, not a production-maturity"
        ),
        "Cargo publication eligibility must remain distinct from maturity"
    );
    assert!(
        status.contains("it is not generated release evidence"),
        "the status matrix must not claim to be candidate release evidence"
    );
    assert!(
        status.contains(
            "| GAP-001-006 | 001 | Config-store carrier HA qualification | high (open) |"
        ),
        "config-store carrier HA qualification must remain explicitly open"
    );
    assert!(
        status.lines().any(|line| {
            line.starts_with("| 004-4 | Geo-replication") && line.contains("| **partial** |")
        }),
        "the in-process quorum proof must not claim complete geo-replication"
    );
    assert!(
        status.contains("not invoked by PR or release workflows"),
        "library policy evaluation must not imply workflow enforcement"
    );
}
