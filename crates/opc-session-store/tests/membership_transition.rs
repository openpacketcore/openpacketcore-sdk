use std::time::Duration;

use opc_session_store::{
    QuorumReplicaDescriptor, QuorumTopologyError, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, SessionConsensusClusterId,
    SessionConsensusConfigurationEpoch, SessionTopologyTransitionError,
    SessionTopologyTransitionId, SessionTopologyTransitionLogIndexes,
    SessionTopologyTransitionOutcome, SessionTopologyTransitionPhase,
    SessionTopologyTransitionReason, SessionTopologyTransitionRequest,
    SessionTopologyTransitionStatus, QUORUM_TOPOLOGY_MAX_MEMBERS,
    SESSION_TOPOLOGY_TRANSITION_MAX_OPERATION_TIMEOUT,
};

fn epoch(value: u64) -> SessionConsensusConfigurationEpoch {
    SessionConsensusConfigurationEpoch::new(value).expect("test epoch")
}

fn cluster(label: &str) -> SessionConsensusClusterId {
    SessionConsensusClusterId::new(label).expect("test cluster")
}

fn descriptor(
    replica: usize,
    endpoint: usize,
    tls: usize,
    failure_domain: usize,
    backing: usize,
) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        ReplicaId::new(format!("replica-{replica}")).expect("test replica ID"),
        ReplicaEndpoint::new(format!("replica-{endpoint}.test.invalid"), 7443)
            .expect("test endpoint"),
        ReplicaTlsIdentity::new(format!("spiffe://test/session/replica/{tls}"))
            .expect("test TLS identity"),
        ReplicaFailureDomain::new(format!("failure-domain-{failure_domain}"))
            .expect("test failure domain"),
        ReplicaBackingIdentity::new(format!("backing-{backing}")).expect("test backing identity"),
    )
}

fn member(index: usize) -> QuorumReplicaDescriptor {
    descriptor(index, index, index, index, index)
}

fn members(count: usize) -> Vec<QuorumReplicaDescriptor> {
    (0..count).map(member).collect()
}

fn request(
    transition_byte: u8,
    cluster_label: &str,
    desired_members: Vec<QuorumReplicaDescriptor>,
    timeout: Duration,
) -> Result<SessionTopologyTransitionRequest, SessionTopologyTransitionError> {
    SessionTopologyTransitionRequest::try_new(
        SessionTopologyTransitionId::from_bytes([transition_byte; 16]),
        cluster(cluster_label),
        epoch(7),
        epoch(8),
        desired_members,
        timeout,
    )
}

fn invalid_topology(source: QuorumTopologyError) -> SessionTopologyTransitionError {
    SessionTopologyTransitionError::InvalidDesiredTopology { source }
}

#[test]
fn transition_identity_is_fixed_width_and_never_rendered_raw() {
    let raw = *b"secret-id-123456";
    let transition_id = SessionTopologyTransitionId::from_bytes(raw);

    assert_eq!(transition_id.as_bytes(), raw);
    assert_eq!(
        format!("{transition_id:?}"),
        "SessionTopologyTransitionId(<redacted>)"
    );
    assert!(!format!("{transition_id:?}").contains("secret-id"));
}

#[test]
fn request_accepts_bounded_odd_memberships_and_canonicalizes_order() {
    for count in [3, 5, QUORUM_TOPOLOGY_MAX_MEMBERS] {
        let mut reversed = members(count);
        reversed.reverse();
        let request = request(
            1,
            "membership-model-tests",
            reversed,
            SESSION_TOPOLOGY_TRANSITION_MAX_OPERATION_TIMEOUT,
        )
        .expect("valid odd membership request");

        assert_eq!(request.expected_epoch().get(), 7);
        assert_eq!(request.desired_epoch().get(), 8);
        assert_eq!(
            request.operation_timeout(),
            SESSION_TOPOLOGY_TRANSITION_MAX_OPERATION_TIMEOUT
        );
        assert_eq!(request.desired_members().len(), count);
        assert!(request
            .desired_members()
            .windows(2)
            .all(|pair| pair[0].replica_id() < pair[1].replica_id()));
    }
}

#[test]
fn request_rejects_nonsequential_and_overflowing_epochs() {
    let nonsequential = SessionTopologyTransitionRequest::try_new(
        SessionTopologyTransitionId::from_bytes([1; 16]),
        cluster("membership-model-tests"),
        epoch(7),
        epoch(9),
        members(3),
        Duration::from_secs(1),
    );
    assert_eq!(
        nonsequential,
        Err(SessionTopologyTransitionError::NonSequentialEpoch)
    );

    let overflowing = SessionTopologyTransitionRequest::try_new(
        SessionTopologyTransitionId::from_bytes([1; 16]),
        cluster("membership-model-tests"),
        epoch(u64::MAX),
        epoch(u64::MAX),
        members(3),
        Duration::from_secs(1),
    );
    assert_eq!(
        overflowing,
        Err(SessionTopologyTransitionError::EpochOverflow)
    );
}

#[test]
fn request_rejects_unbounded_timeout_and_invalid_member_counts() {
    for timeout in [
        Duration::ZERO,
        SESSION_TOPOLOGY_TRANSITION_MAX_OPERATION_TIMEOUT + Duration::from_nanos(1),
    ] {
        assert_eq!(
            request(1, "membership-model-tests", members(3), timeout),
            Err(SessionTopologyTransitionError::InvalidOperationTimeout)
        );
    }

    for (count, expected) in [
        (
            0,
            QuorumTopologyError::HaMemberCountTooSmall { configured: 0 },
        ),
        (
            2,
            QuorumTopologyError::HaMemberCountTooSmall { configured: 2 },
        ),
        (
            4,
            QuorumTopologyError::HaMemberCountMustBeOdd { configured: 4 },
        ),
        (
            QUORUM_TOPOLOGY_MAX_MEMBERS + 1,
            QuorumTopologyError::MemberCountTooLarge {
                configured: QUORUM_TOPOLOGY_MAX_MEMBERS + 1,
                max: QUORUM_TOPOLOGY_MAX_MEMBERS,
            },
        ),
    ] {
        assert_eq!(
            request(
                1,
                "membership-model-tests",
                members(count),
                Duration::from_secs(1)
            ),
            Err(invalid_topology(expected))
        );
    }
}

#[test]
fn request_reuses_every_existing_descriptor_uniqueness_invariant() {
    let cases = [
        (
            vec![member(0), member(1), descriptor(1, 2, 2, 2, 2)],
            QuorumTopologyError::DuplicateReplicaId,
        ),
        (
            vec![member(0), member(1), descriptor(2, 1, 2, 2, 2)],
            QuorumTopologyError::DuplicateEndpoint,
        ),
        (
            vec![member(0), member(1), descriptor(2, 2, 1, 2, 2)],
            QuorumTopologyError::DuplicateTlsIdentity,
        ),
        (
            vec![member(0), member(1), descriptor(2, 2, 2, 1, 2)],
            QuorumTopologyError::DuplicateFailureDomain,
        ),
        (
            vec![member(0), member(1), descriptor(2, 2, 2, 2, 1)],
            QuorumTopologyError::DuplicateBackingIdentity,
        ),
    ];

    for (desired_members, expected) in cases {
        assert_eq!(
            request(
                1,
                "membership-model-tests",
                desired_members,
                Duration::from_secs(1)
            ),
            Err(invalid_topology(expected))
        );
    }
}

#[test]
fn digest_and_idempotency_are_order_independent_cluster_bound_and_exact() {
    let forward = request(
        1,
        "membership-model-tests",
        members(5),
        Duration::from_secs(10),
    )
    .expect("forward request");
    let mut reversed_members = members(5);
    reversed_members.reverse();
    let reversed = request(
        1,
        "membership-model-tests",
        reversed_members,
        Duration::from_secs(10),
    )
    .expect("reversed request");
    let different_timeout = request(
        1,
        "membership-model-tests",
        members(5),
        Duration::from_secs(11),
    )
    .expect("different timeout");
    let different_id = request(
        2,
        "membership-model-tests",
        members(5),
        Duration::from_secs(10),
    )
    .expect("different transition ID");
    let different_cluster = request(
        1,
        "membership-model-tests-other",
        members(5),
        Duration::from_secs(10),
    )
    .expect("different cluster");
    let different_descriptor = request(
        1,
        "membership-model-tests",
        vec![
            member(0),
            member(1),
            descriptor(2, 22, 2, 2, 2),
            member(3),
            member(4),
        ],
        Duration::from_secs(10),
    )
    .expect("different descriptor");

    assert_eq!(forward, reversed);
    assert_eq!(forward.request_digest(), reversed.request_digest());
    assert!(forward.is_idempotent_retry(&reversed));
    assert_eq!(forward.validate_idempotent_retry(&reversed), Ok(()));
    for changed in [
        &different_timeout,
        &different_id,
        &different_cluster,
        &different_descriptor,
    ] {
        assert_ne!(forward.request_digest(), changed.request_digest());
        assert_eq!(
            forward.validate_idempotent_retry(changed),
            Err(SessionTopologyTransitionError::IdempotencyConflict)
        );
    }
}

#[test]
fn status_and_evidence_reject_epoch_or_terminal_state_contradictions() {
    let request = request(
        1,
        "membership-model-tests",
        members(5),
        Duration::from_secs(10),
    )
    .expect("request");
    let joint = SessionTopologyTransitionStatus::try_from_request(
        &request,
        3,
        epoch(7),
        SessionTopologyTransitionPhase::JointCommitted,
        SessionTopologyTransitionOutcome::RecoveryRequired,
        SessionTopologyTransitionReason::LeaderChanged,
        SessionTopologyTransitionLogIndexes::new(Some(100), None, None),
    )
    .expect("resumable joint evidence");
    assert_eq!(joint.transition_id(), request.transition_id());
    assert_eq!(
        joint.phase(),
        SessionTopologyTransitionPhase::JointCommitted
    );
    assert_eq!(joint.evidence().expected_epoch(), epoch(7));
    assert_eq!(joint.evidence().desired_epoch(), epoch(8));
    assert_eq!(joint.evidence().committed_epoch(), epoch(7));
    assert_eq!(joint.evidence().desired_member_count(), 5);
    assert_eq!(joint.evidence().desired_quorum(), 3);
    assert_eq!(joint.current_member_count(), 3);
    assert_eq!(joint.current_quorum(), 2);
    assert_eq!(joint.desired_member_count(), 5);
    assert_eq!(joint.desired_quorum(), 3);
    assert_eq!(joint.reason_code(), "leader_changed");
    assert_eq!(joint.log_indexes().joint(), Some(100));
    assert_eq!(joint.log_indexes().uniform(), None);
    assert_eq!(joint.log_indexes().finalization(), None);
    assert_eq!(
        joint.evidence().outcome(),
        SessionTopologyTransitionOutcome::RecoveryRequired
    );

    let completed = SessionTopologyTransitionStatus::try_from_request(
        &request,
        3,
        epoch(8),
        SessionTopologyTransitionPhase::Completed,
        SessionTopologyTransitionOutcome::Succeeded,
        SessionTopologyTransitionReason::Succeeded,
        SessionTopologyTransitionLogIndexes::new(Some(100), Some(101), Some(102)),
    )
    .expect("completed evidence");
    assert!(completed.phase().is_terminal());
    assert!(completed.outcome().is_terminal());
    assert_eq!(
        completed.evidence().request_digest(),
        request.request_digest()
    );
    assert_eq!(
        completed.evidence().desired_configuration_id(),
        request.desired_configuration_id()
    );

    for invalid in [
        SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            epoch(7),
            SessionTopologyTransitionPhase::Completed,
            SessionTopologyTransitionOutcome::Succeeded,
            SessionTopologyTransitionReason::Succeeded,
            SessionTopologyTransitionLogIndexes::new(Some(100), Some(101), Some(102)),
        ),
        SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            epoch(8),
            SessionTopologyTransitionPhase::Aborted,
            SessionTopologyTransitionOutcome::Aborted,
            SessionTopologyTransitionReason::AbortedByCaller,
            SessionTopologyTransitionLogIndexes::default(),
        ),
        SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            epoch(7),
            SessionTopologyTransitionPhase::Prepared,
            SessionTopologyTransitionOutcome::Succeeded,
            SessionTopologyTransitionReason::Succeeded,
            SessionTopologyTransitionLogIndexes::default(),
        ),
        SessionTopologyTransitionStatus::try_from_request(
            &request,
            4,
            epoch(7),
            SessionTopologyTransitionPhase::Prepared,
            SessionTopologyTransitionOutcome::InProgress,
            SessionTopologyTransitionReason::Progressing,
            SessionTopologyTransitionLogIndexes::default(),
        ),
        SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            epoch(8),
            SessionTopologyTransitionPhase::Completed,
            SessionTopologyTransitionOutcome::Succeeded,
            SessionTopologyTransitionReason::Succeeded,
            SessionTopologyTransitionLogIndexes::new(Some(101), Some(100), Some(102)),
        ),
        SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            epoch(7),
            SessionTopologyTransitionPhase::Prepared,
            SessionTopologyTransitionOutcome::InProgress,
            SessionTopologyTransitionReason::QuorumUnavailable,
            SessionTopologyTransitionLogIndexes::default(),
        ),
        SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            epoch(7),
            SessionTopologyTransitionPhase::Prepared,
            SessionTopologyTransitionOutcome::RecoveryRequired,
            SessionTopologyTransitionReason::CancellationTooLate,
            SessionTopologyTransitionLogIndexes::default(),
        ),
        SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            epoch(8),
            SessionTopologyTransitionPhase::Finalizing,
            SessionTopologyTransitionOutcome::InProgress,
            SessionTopologyTransitionReason::Progressing,
            SessionTopologyTransitionLogIndexes::new(Some(100), Some(101), Some(102)),
        ),
    ] {
        assert_eq!(
            invalid,
            Err(SessionTopologyTransitionError::InvalidEvidenceState)
        );
    }

    SessionTopologyTransitionStatus::try_from_request(
        &request,
        3,
        epoch(7),
        SessionTopologyTransitionPhase::JointCommitted,
        SessionTopologyTransitionOutcome::RecoveryRequired,
        SessionTopologyTransitionReason::CancellationTooLate,
        SessionTopologyTransitionLogIndexes::new(Some(100), None, None),
    )
    .expect("cancellation is too late after joint commit");
    SessionTopologyTransitionStatus::try_from_request(
        &request,
        3,
        epoch(8),
        SessionTopologyTransitionPhase::Finalizing,
        SessionTopologyTransitionOutcome::InProgress,
        SessionTopologyTransitionReason::Progressing,
        SessionTopologyTransitionLogIndexes::new(Some(100), Some(101), None),
    )
    .expect("finalization is pending while finalizing");
}

#[test]
fn runtime_facing_errors_have_stable_redaction_safe_codes() {
    let cases = [
        (
            SessionTopologyTransitionError::StaleEpoch,
            "session_topology_transition_stale_epoch",
        ),
        (
            SessionTopologyTransitionError::QuorumLosingChange,
            "session_topology_transition_quorum_losing_change",
        ),
        (
            SessionTopologyTransitionError::TransitionInProgress,
            "session_topology_transition_in_progress",
        ),
        (
            SessionTopologyTransitionError::DeadlineExceededResumable,
            "session_topology_transition_deadline_exceeded_resumable",
        ),
        (
            SessionTopologyTransitionError::CancellationTooLate,
            "session_topology_transition_cancellation_too_late",
        ),
        (
            SessionTopologyTransitionError::NotLeader,
            "session_topology_transition_not_leader",
        ),
        (
            SessionTopologyTransitionError::Unavailable,
            "session_topology_transition_unavailable",
        ),
    ];

    for (error, expected_code) in cases {
        assert_eq!(error.reason_code(), expected_code);
        assert!(!error.to_string().contains("replica"));
    }
}

#[test]
fn request_status_evidence_and_errors_do_not_render_descriptor_values() {
    let replica_canary = "private-replica-canary";
    let endpoint_canary = "private-endpoint-canary.test.invalid";
    let tls_canary = "spiffe://private/session/canary";
    let failure_canary = "private-failure-canary";
    let backing_canary = "private-backing-canary";
    let sensitive = QuorumReplicaDescriptor::new(
        ReplicaId::new(replica_canary).expect("replica ID"),
        ReplicaEndpoint::new(endpoint_canary, 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(tls_canary).expect("TLS identity"),
        ReplicaFailureDomain::new(failure_canary).expect("failure domain"),
        ReplicaBackingIdentity::new(backing_canary).expect("backing identity"),
    );
    let validated_request = request(
        1,
        "membership-model-tests",
        vec![member(0), member(1), sensitive],
        Duration::from_secs(10),
    )
    .expect("request");
    let status = SessionTopologyTransitionStatus::try_from_request(
        &validated_request,
        3,
        epoch(7),
        SessionTopologyTransitionPhase::Prepared,
        SessionTopologyTransitionOutcome::InProgress,
        SessionTopologyTransitionReason::Progressing,
        SessionTopologyTransitionLogIndexes::default(),
    )
    .expect("status");
    let rendered = format!("{validated_request:?} {status:?}");
    for canary in [
        replica_canary,
        endpoint_canary,
        tls_canary,
        failure_canary,
        backing_canary,
    ] {
        assert!(!rendered.contains(canary));
    }

    let error = request(
        1,
        "membership-model-tests",
        vec![member(0), member(1), member(1)],
        Duration::from_secs(10),
    )
    .expect_err("duplicate request");
    let error_rendered = format!("{error:?} {error}");
    assert!(!error_rendered.contains("replica-1"));
    assert_eq!(
        error.reason_code(),
        "session_topology_transition_invalid_desired_topology"
    );
}
