use std::collections::BTreeMap;

use opc_evidence::{
    assert_packet_continuity_claim_allowed, assert_traffic_readiness_claim_allowed,
    DataplaneBearerSummary, DataplaneEvidenceError, DataplaneSessionSummary, DataplaneSnapshot,
    DataplaneSnapshotAsserter, DataplaneTrafficBlockReasonCode,
};

fn proven_snapshot() -> DataplaneSnapshot {
    DataplaneSnapshot {
        session_count: 2,
        bearer_count: 2,
        installed_object_count: 6,
        highest_fence: Some(30),
        highest_generation: Some(9),
        stale_mutation_counters: BTreeMap::from([("fence-rejected".to_string(), 3)]),
        sessions: vec![
            DataplaneSessionSummary {
                session_ref: "session-b".to_string(),
                bearer_count: 1,
                installed_object_count: 3,
                highest_generation: Some(5),
                highest_fence: Some(20),
            },
            DataplaneSessionSummary {
                session_ref: "session-a".to_string(),
                bearer_count: 1,
                installed_object_count: 3,
                highest_generation: Some(9),
                highest_fence: Some(30),
            },
        ],
        bearers: vec![
            DataplaneBearerSummary {
                session_ref: "session-b".to_string(),
                bearer_ref: "bearer-2".to_string(),
                installed_object_count: 3,
                highest_generation: Some(5),
                highest_fence: Some(20),
            },
            DataplaneBearerSummary {
                session_ref: "session-a".to_string(),
                bearer_ref: "bearer-1".to_string(),
                installed_object_count: 3,
                highest_generation: Some(9),
                highest_fence: Some(30),
            },
        ],
        forwarding_proven: Some(true),
        kernel_state_reconciled: Some(true),
        packet_continuity_proven: Some(true),
    }
}

#[test]
fn dataplane_snapshot_allows_claims_only_with_explicit_proofs() {
    let snapshot = proven_snapshot();

    assert_traffic_readiness_claim_allowed(&snapshot);
    assert_packet_continuity_claim_allowed(&snapshot);
    assert!(!snapshot.blocks_traffic_readiness());
    assert!(snapshot.traffic_readiness_blockers().is_empty());
    assert_eq!(snapshot.first_traffic_readiness_blocker(), None);
    DataplaneSnapshotAsserter::new(&snapshot)
        .traffic_readiness_claim_allowed()
        .packet_continuity_claim_allowed();
}

#[test]
fn dataplane_snapshot_rejects_absent_traffic_proof() {
    let mut snapshot = proven_snapshot();
    snapshot.forwarding_proven = None;

    let err = snapshot
        .validate_traffic_readiness_claim()
        .expect_err("missing forwarding proof should reject traffic readiness");
    assert!(matches!(
        err,
        DataplaneEvidenceError::MissingProofField {
            field: "forwarding_proven",
            ..
        }
    ));
    assert_eq!(
        err.traffic_block_reason_code(),
        Some(DataplaneTrafficBlockReasonCode::ForwardingNotProven)
    );
}

#[test]
fn dataplane_snapshot_rejects_false_continuity_proof() {
    let mut snapshot = proven_snapshot();
    snapshot.packet_continuity_proven = Some(false);

    assert!(matches!(
        snapshot.validate_packet_continuity_claim(),
        Err(DataplaneEvidenceError::FalseProofField {
            field: "packet_continuity_proven",
            ..
        })
    ));
}

#[test]
fn dataplane_snapshot_projects_traffic_blockers_in_stable_priority_order() {
    let mut snapshot = proven_snapshot();
    snapshot.forwarding_proven = None;
    snapshot.kernel_state_reconciled = Some(false);
    snapshot.packet_continuity_proven = None;

    assert!(snapshot.blocks_traffic_readiness());
    assert_eq!(
        snapshot.first_traffic_readiness_blocker(),
        Some(DataplaneTrafficBlockReasonCode::ForwardingNotProven)
    );
    assert_eq!(
        snapshot.traffic_readiness_blockers(),
        vec![
            DataplaneTrafficBlockReasonCode::ForwardingNotProven,
            DataplaneTrafficBlockReasonCode::KernelStateNotReconciled,
            DataplaneTrafficBlockReasonCode::PacketContinuityNotProven,
        ]
    );
}

#[test]
fn dataplane_traffic_block_reason_codes_are_stable_and_redaction_safe() {
    let code = DataplaneTrafficBlockReasonCode::KernelStateNotReconciled;

    assert_eq!(code.as_str(), "kernel_state_not_reconciled");
    assert_eq!(code.to_string(), "kernel_state_not_reconciled");
    assert_eq!(code.proof_field(), "kernel_state_reconciled");
    assert_eq!(
        code.message(),
        "traffic readiness blocked: kernel state is not reconciled"
    );
    assert_eq!(
        serde_json::to_value(code).expect("serialize reason code"),
        serde_json::json!("kernel_state_not_reconciled")
    );
    assert!(!code.message().contains("session-a"));
    assert!(!code.message().contains("bearer-1"));
}

#[test]
fn dataplane_snapshot_canonicalizes_and_summarizes_without_refs() {
    let snapshot = proven_snapshot().canonicalized();

    assert_eq!(snapshot.sessions[0].session_ref, "session-a");
    assert_eq!(snapshot.bearers[0].session_ref, "session-a");

    let summary = snapshot.redaction_safe_summary();
    assert!(summary.contains("sessions=2"));
    assert!(summary.contains("installed_objects=6"));
    assert!(!summary.contains("session-a"));
    assert!(!summary.contains("bearer-1"));
}
