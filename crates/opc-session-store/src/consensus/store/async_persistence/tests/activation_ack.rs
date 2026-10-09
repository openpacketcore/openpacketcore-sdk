//! An activation reply must cover the certificate, even before Raft publishes metrics.

use super::*;
use crate::consensus::snapshot::SnapshotArtifactGate;

struct GateRelease(Arc<SnapshotArtifactGate>);

impl GateRelease {
    fn new(gate: Arc<SnapshotArtifactGate>) -> Self {
        gate.arm();
        Self(gate)
    }
}

impl Drop for GateRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn activation_request(
    activation: CapabilityActivationKind,
    scope: SessionConsensusIdentity,
) -> ForwardMutationRequest {
    let (request_id, intent) = match activation {
        CapabilityActivationKind::ScopeProfileV3 => (
            scope_profile::request_id(scope),
            SessionMutationIntent::PreflightScopeProfile,
        ),
        CapabilityActivationKind::FencedTransitionV1 => (
            fenced_transition_activation_request_id(scope),
            SessionMutationIntent::PreflightFencedTransitionCapability,
        ),
        CapabilityActivationKind::ProtectedRosterV1 => (
            protected_roster_profile_activation_request_id(scope),
            SessionMutationIntent::PreflightProtectedRosterProfile,
        ),
        CapabilityActivationKind::ProtectedRosterV2 => (
            protected_roster_profile_v2_activation_request_id(scope),
            SessionMutationIntent::PreflightProtectedRosterProfileV2,
        ),
    };
    ForwardMutationRequest {
        work_class: ForwardWorkClass::Inferred,
        request_id,
        intent,
        required_consumer_scope: ForwardConsumerScope::Internal,
    }
}

fn backend_activation(
    store: &ConsensusSessionStore,
    activation: CapabilityActivationKind,
) -> (bool, u64) {
    let (scope, voters) = store.current_scope().unwrap();
    store
        .inner
        .private_wal
        .as_ref()
        .unwrap()
        .native_public_scalar_read(|state| {
            let active = match activation {
                CapabilityActivationKind::ScopeProfileV3 => {
                    let key = crate::scope_storage::profile_key(scope.cluster_id()).unwrap();
                    let row = state.scope_record(store.inner.storage_identity, &key).unwrap();
                    matches!(row, Some(crate::scope_storage::ScopeRow::Activation(certificate))
                        if certificate.matches(scope, fenced_transition_voter_set_digest(scope, &voters)))
                }
                CapabilityActivationKind::FencedTransitionV1 => {
                    state.v1_activation_matches(scope, &voters)
                }
                CapabilityActivationKind::ProtectedRosterV1 => {
                    state.protected_roster_activation_matches(scope, &voters)
                }
                CapabilityActivationKind::ProtectedRosterV2 => {
                    state.protected_roster_v2_activation_matches(scope, &voters)
                }
            };
            Ok((active, state.applied().unwrap().index))
        })
        .unwrap()
}

async fn acknowledgment_covers_certificate_before_metrics(
    activation: CapabilityActivationKind,
    modes: &[SessionPersistenceMode],
) {
    let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
    for &mode in modes {
        let mut fleet = Fleet::new(3);
        for index in 0..3 {
            fleet.open(index, mode).await.unwrap();
        }
        fleet.form().await;
        let leader_index = fleet.leader();
        let follower_index = (leader_index + 1) % 3;
        let leader = fleet.store(leader_index).clone();
        let follower = fleet.store(follower_index).clone();
        let deadline = tokio::time::Instant::now() + OPERATION_BOUND;
        let before = leader
            .inner
            .raft
            .metrics()
            .borrow()
            .last_applied
            .unwrap()
            .index;
        follower
            .inner
            .read_barrier
            .wait_for_applied_index(before, deadline)
            .await
            .unwrap();
        let held_follower_apply = Arc::clone(&follower.inner.backend.consensus_apply_gate)
            .acquire_owned()
            .await
            .unwrap();

        // Admit the concurrent request before any certificate is proposed.
        // Only this task is paused: another activation can commit normally.
        let read_gate = GateRelease::new(Arc::new(SnapshotArtifactGate::new()));
        let request = activation_request(activation, leader.current_scope().unwrap().0);
        let admitted = tokio::spawn({
            let leader = leader.clone();
            let gate = Arc::clone(&read_gate.0);
            let origin = follower.inner.local_node_id;
            async move {
                activation_evidence::READ_ADMIT_GATE
                    .scope(gate, async move {
                        leader
                            .apply_on_local_leader(request, origin, deadline)
                            .await
                    })
                    .await
            }
        });
        tokio::time::timeout_at(deadline, read_gate.0.wait_started())
            .await
            .unwrap();

        // Keep the real applied certificate visible while Openraft's state-
        // machine completion notification and metrics publication are held.
        let apply_gate = GateRelease::new(Arc::clone(
            &leader.inner.backend.consensus_apply_publication_gate,
        ));
        let cold = tokio::spawn({
            let leader = leader.clone();
            async move {
                leader
                    .activate_capability_before(deadline, activation)
                    .await
            }
        });
        tokio::time::timeout_at(deadline, apply_gate.0.wait_started())
            .await
            .unwrap();
        let (active, certificate_index) = backend_activation(&leader, activation);
        assert!(active);
        assert_eq!(certificate_index, before + 1);
        assert_eq!(
            leader
                .inner
                .raft
                .metrics()
                .borrow()
                .last_applied
                .unwrap()
                .index,
            before
        );
        assert_eq!(backend_activation(&follower, activation), (false, before));

        drop(read_gate);
        let reply = tokio::time::timeout_at(deadline, admitted)
            .await
            .unwrap()
            .unwrap();
        let ForwardMutationReply::FencedTransitionActivation(Ok(reply)) = reply else {
            panic!("already-applied certificate must produce an activation acknowledgment");
        };
        assert_eq!(reply.applied_log_index, certificate_index,
            "activation acknowledgment must cover backend certificate while metrics still precede it");

        let wait = follower
            .inner
            .read_barrier
            .wait_for_applied_index(reply.applied_log_index, deadline);
        tokio::pin!(wait);
        assert!(
            wait.as_mut().now_or_never().is_none(),
            "the acknowledged index must keep the follower waiting for its missing certificate"
        );
        drop(held_follower_apply);
        drop(apply_gate);
        wait.await.unwrap();
        assert!(backend_activation(&follower, activation).0);
        tokio::time::timeout_at(deadline, cold)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            leader.inner.raft.metrics().borrow().last_log_index,
            Some(certificate_index),
            "the concurrent already-activated path must not append another marker"
        );
        fleet.close_all().await;
    }
}

#[tokio::test]
async fn fenced_activation_ack_covers_backend_before_metrics() {
    acknowledgment_covers_certificate_before_metrics(
        CapabilityActivationKind::FencedTransitionV1,
        &[
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ],
    )
    .await;
}

#[tokio::test]
async fn protected_roster_v1_activation_ack_covers_backend_before_metrics() {
    acknowledgment_covers_certificate_before_metrics(
        CapabilityActivationKind::ProtectedRosterV1,
        &[
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ],
    )
    .await;
}

#[tokio::test]
async fn protected_roster_v2_activation_ack_covers_backend_before_metrics() {
    acknowledgment_covers_certificate_before_metrics(
        CapabilityActivationKind::ProtectedRosterV2,
        &[
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ],
    )
    .await;
}

#[tokio::test]
async fn scope_profile_activation_ack_covers_backend_before_metrics() {
    acknowledgment_covers_certificate_before_metrics(
        CapabilityActivationKind::ScopeProfileV3,
        &[SessionPersistenceMode::Durable],
    )
    .await;
}
