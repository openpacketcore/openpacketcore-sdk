#[test]
fn operator_readiness_doc_tracks_final_validation_boundaries() {
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
        status.contains("Final validation snapshot — T-9be95f92"),
        "implementation status must retain the final validation snapshot"
    );
    assert!(
        status.contains("Final hardening snapshot — T-8c57ecee"),
        "implementation status must retain the EPC/untrusted-access final hardening snapshot"
    );
}
