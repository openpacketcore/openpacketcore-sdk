#![allow(unused_imports)]
mod lifecycle_common;

use lifecycle_common::*;
use operator_lifecycle::{
    CompatibilityBlockReason, CompatibilityDecision, CompatibilityFeature, CompatibilityMatrix,
    CompatibilityRule, MigrationCompatibility,
};

#[test]
fn test_compatibility_exact_and_range_matches() {
    let matrix = create_test_compatibility_matrix();
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-1".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    let dec = matrix.evaluate_compatibility(
        &op,
        &nf,
        RuntimeMode::Production,
        "consensus",
        "quorum",
        true,
        true,
        true,
        &ev,
    );
    assert_eq!(dec, CompatibilityDecision::Allowed);
}

#[test]
fn test_compatibility_reject_unknown_nf() {
    let matrix = create_test_compatibility_matrix();
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf_unknown_kind = NfReleaseDescriptor {
        nf_kind: "unknown-nf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-1".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    let dec = matrix.evaluate_compatibility(
        &op,
        &nf_unknown_kind,
        RuntimeMode::Production,
        "consensus",
        "quorum",
        true,
        true,
        true,
        &ev,
    );
    assert!(matches!(
        dec,
        CompatibilityDecision::Blocked(CompatibilityBlockReason::UnsupportedNfKind { .. })
    ));

    let nf_unsupported_version = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "2.0.0".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let dec = matrix.evaluate_compatibility(
        &op,
        &nf_unsupported_version,
        RuntimeMode::Production,
        "consensus",
        "quorum",
        true,
        true,
        true,
        &ev,
    );
    assert!(matches!(
        dec,
        CompatibilityDecision::Blocked(CompatibilityBlockReason::UnsupportedNfVersion { .. })
    ));
}

#[test]
fn test_compatibility_reject_unsupported_operator_sdk() {
    let matrix = create_test_compatibility_matrix();
    let op_bad = OperatorReleaseDescriptor {
        operator_version: "2.0.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-1".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    let dec = matrix.evaluate_compatibility(
        &op_bad,
        &nf,
        RuntimeMode::Production,
        "consensus",
        "quorum",
        true,
        true,
        true,
        &ev,
    );
    assert!(matches!(
        dec,
        CompatibilityDecision::Blocked(CompatibilityBlockReason::UnsupportedOperatorVersion { .. })
    ));
}

#[test]
fn test_compatibility_reject_config_state_schema_mismatch() {
    let matrix = create_test_compatibility_matrix();
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf_bad_schema = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "0.9.0".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-1".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    let dec = matrix.evaluate_compatibility(
        &op,
        &nf_bad_schema,
        RuntimeMode::Production,
        "consensus",
        "quorum",
        true,
        true,
        true,
        &ev,
    );
    assert!(matches!(
        dec,
        CompatibilityDecision::Blocked(
            CompatibilityBlockReason::UnsupportedConfigSchemaVersion { .. }
        )
    ));
}

#[test]
fn test_compatibility_reject_missing_migration_path() {
    let matrix = create_test_compatibility_matrix();
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-1".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    let dec = matrix.evaluate_migration(&op, &nf, "1.0.0", "3.0.0", &ev);
    assert!(matches!(
        dec,
        CompatibilityDecision::Blocked(CompatibilityBlockReason::MigrationPathNotAllowed { .. })
    ));
}

#[test]
fn test_compatibility_rollback_constraints() {
    let matrix = create_test_compatibility_matrix();
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-1".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    // Rollback from 2.0.0 -> 1.0.0 is explicitly allowed
    let dec1 = matrix.evaluate_migration(&op, &nf, "2.0.0", "1.0.0", &ev);
    assert_eq!(dec1, CompatibilityDecision::Allowed);

    // Rollback from 3.0.0 -> 2.0.0 is blocked by allowed_rollback = false
    let dec2 = matrix.evaluate_migration(&op, &nf, "3.0.0", "2.0.0", &ev);
    assert!(matches!(
        dec2,
        CompatibilityDecision::Blocked(CompatibilityBlockReason::RollbackNotAllowed { .. })
    ));
}

#[test]
fn test_compatibility_feature_mismatch() {
    let matrix = create_test_compatibility_matrix();
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-1".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    // Missing consensus config backend
    let dec = matrix.evaluate_compatibility(
        &op,
        &nf,
        RuntimeMode::Production,
        "sqlite",
        "quorum",
        true,
        true,
        true,
        &ev,
    );
    assert!(matches!(
        dec,
        CompatibilityDecision::Blocked(CompatibilityBlockReason::MissingRequiredFeature(
            CompatibilityFeature::ConsensusConfigBackend
        ))
    ));
}

#[test]
fn test_compatibility_allows_policy_defined_nf_kind() {
    let matrix = CompatibilityMatrix {
        rules: vec![CompatibilityRule {
            rule_id: "vendor-rule".to_string(),
            operator_version_range: SupportedVersionRange(">=1.0.0, <2.0.0".to_string()),
            sdk_version_range: SupportedVersionRange(">=1.5.0".to_string()),
            nf_kind: "nwdaf".to_string(),
            nf_version_range: SupportedVersionRange(">=0.4.0, <1.0.0".to_string()),
            crd_api_version_range: SupportedVersionRange("openpacketcore.org/v1beta1".to_string()),
            config_schema_version_range: SupportedVersionRange(">=1.0.0".to_string()),
            state_schema_version_range: SupportedVersionRange(">=1.0.0".to_string()),
            required_features: vec![CompatibilityFeature::ResourceProfile],
            required_runtime_modes: vec![RuntimeMode::Production],
            required_persistence_profiles: vec![],
            allowed_migrations: vec![],
        }],
    };
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf = NfReleaseDescriptor {
        nf_kind: "nwdaf".to_string(),
        nf_version: "0.4.1".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-vendor".to_string(),
        approved_by: "release-board".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    let dec = matrix.evaluate_compatibility(
        &op,
        &nf,
        RuntimeMode::Production,
        "sqlite",
        "fake",
        true,
        true,
        true,
        &ev,
    );
    assert_eq!(dec, CompatibilityDecision::Allowed);
}

#[test]
fn test_compatibility_rejects_blank_evidence_fields() {
    let matrix = create_test_compatibility_matrix();
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: " ".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    let dec = matrix.evaluate_compatibility(
        &op,
        &nf,
        RuntimeMode::Production,
        "consensus",
        "quorum",
        true,
        true,
        true,
        &ev,
    );
    assert_eq!(
        dec,
        CompatibilityDecision::Blocked(CompatibilityBlockReason::MissingEvidence)
    );
}

#[test]
fn test_compatibility_requires_both_persistence_profiles_to_match() {
    let mut matrix = create_test_compatibility_matrix();
    matrix.rules[0].required_features.clear();
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-1".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    let dec = matrix.evaluate_compatibility(
        &op,
        &nf,
        RuntimeMode::Production,
        "consensus",
        "sqlite",
        true,
        true,
        true,
        &ev,
    );
    assert!(matches!(
        dec,
        CompatibilityDecision::Blocked(
            CompatibilityBlockReason::UnsupportedPersistenceProfile { .. }
        )
    ));
}
