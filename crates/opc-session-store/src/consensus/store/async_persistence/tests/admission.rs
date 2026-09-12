//! Actual certificate validation, conflicting suffix repair and activation.

use super::races::{until, wait_for_lease_expiry};
use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) enum CutMutation {
    Nonce,
    Identity,
    Requester(SessionConsensusNodeId),
    Voters,
    UncommittedVote,
    OtherLeader(SessionConsensusNodeId),
    LogLineage,
    Membership,
}

impl CutMutation {
    pub(super) fn alter(self, response: &mut SessionConsensusWireResponse) {
        let Ok(payload) = &response.result else {
            return;
        };
        let payload =
            persistence_protocol::unwrap_payload(SessionPersistenceMode::Async, payload).unwrap();
        let Ok(mut cut) = decode_bounded::<ColdQuorumCut>(payload) else {
            return;
        };
        match self {
            Self::Nonce => cut.request.nonce = SessionConsensusRequestId::new(),
            Self::Identity => {
                cut.identity = SessionConsensusIdentity::new(
                    cut.identity.cluster_id(),
                    cut.identity.configuration_id(),
                    ConsensusConfigurationEpoch::new(cut.identity.configuration_epoch().get() + 1)
                        .unwrap(),
                );
            }
            Self::Requester(node) => cut.requester = node,
            Self::Voters => cut.voters[0] ^= 1,
            Self::UncommittedVote => cut.vote.committed = false,
            Self::OtherLeader(node) => {
                cut.vote = Vote::new_committed(cut.vote.leader_id.term, node)
            }
            Self::LogLineage => {
                cut.barrier.leader_id = CommittedLeaderId::new(
                    cut.vote.leader_id.term + 1,
                    cut.vote.leader_id.voted_for().unwrap(),
                );
            }
            Self::Membership => {
                cut.membership = Some(LogId::new(cut.barrier.leader_id, cut.barrier.index + 1));
            }
        }
        *response = persistence_protocol::wrap_response(
            SessionPersistenceMode::Async,
            SessionConsensusWireResponse {
                result: Ok(encode_bounded(&cut).unwrap()),
            },
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_real_certificate_binds_request_scope_full_vote_and_membership() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let leader = fleet.leader();
        let recovering = (leader + 1) % 3;
        let other = (leader + 2) % 3;
        let live = fleet.store(leader).clone();
        let provider = provider();
        let first = create_request(&live, 1, &provider).await;
        let first_outcome = create(&live, &first).await;
        live.activate_fenced_transition_capability().await.unwrap();
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &first_outcome).await;
            store.drain_async_persistence().await.unwrap();
        }
        fleet.close(recovering).await;
        fleet
            .open(recovering, SessionPersistenceMode::Async)
            .await
            .unwrap();
        let cold = fleet.store(recovering).clone();
        wait_for_restored_cold_metrics(&cold).await;
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(!cold.status().admitted);
        let before = cold.inner.raft.metrics().borrow().clone();
        let mut previous_cut = None;
        for mutation in [
            CutMutation::Nonce,
            CutMutation::Identity,
            CutMutation::Requester(fleet.peers[leader].node),
            CutMutation::Voters,
            CutMutation::UncommittedVote,
            CutMutation::OtherLeader(fleet.peers[other].node),
            CutMutation::LogLineage,
            CutMutation::Membership,
        ] {
            *fleet.peers[leader].cut_mutation.lock().unwrap() = Some(mutation);
            assert!(
                matches!(
                    cold.initialize_cluster().await,
                    Err(ConsensusSessionStoreOpenError::RecoveryRequired)
                ),
                "altered certificate: {mutation:?}"
            );
            let actual = fleet.peers[leader].last_cut.lock().unwrap().unwrap();
            if let Some(previous) = previous_cut {
                let previous: ColdQuorumCut = previous;
                assert!(actual.barrier.index > previous.barrier.index);
                assert_ne!(actual.request.nonce, previous.request.nonce);
            }
            previous_cut = Some(actual);
            assert!(!cold.inner.persistence_protocol.is_active());
            assert!(!cold.status().admitted);
            assert_eq!(
                cold.probe_fixed_quorum_readiness()
                    .await
                    .traffic_authority(),
                FixedQuorumTrafficAuthority::RecoveryRequired
            );
            if matches!(mutation, CutMutation::Membership) {
                // An internally consistent leader/range still cannot supply
                // a different membership identity for final activation.
                assert!(cold
                    .inner
                    .raft
                    .metrics()
                    .borrow()
                    .last_applied
                    .is_some_and(|last| persistence_protocol::covers(last, actual.barrier)));
            } else {
                let metrics = cold.inner.raft.metrics();
                let current = metrics.borrow();
                assert_eq!(current.vote, before.vote);
                assert_eq!(current.last_log_index, before.last_log_index);
                assert_eq!(current.last_applied, before.last_applied);
            }
        }
        *fleet.peers[leader].cut_mutation.lock().unwrap() = None;
        let initialized = tokio::time::Instant::now();
        cold.initialize_cluster().await.unwrap();
        assert!(initialized.elapsed() < OPERATION_BOUND);
        let fresh = fleet.peers[leader].last_cut.lock().unwrap().unwrap();
        assert!(fresh.barrier.index > previous_cut.unwrap().barrier.index);
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &first_outcome).await;
        }
        let second = create_request(&live, 2, &provider).await;
        let second_outcome = create(&live, &second).await;
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &second, &second_outcome).await;
        }
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

struct ActivationRelease(Arc<persistence_protocol::ActivationHoldForTest>);

impl Drop for ActivationRelease {
    fn drop(&mut self) {
        self.0.release.notify_one();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_conflicting_suffix_and_cancelled_activation_require_a_fresh_attempt() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let old_leader = fleet.leader();
        let successor = (old_leader + 1) % 3;
        let other = (old_leader + 2) % 3;
        let old = fleet.store(old_leader).clone();
        let provider = provider();
        let first = create_request(&old, 1, &provider).await;
        let first_outcome = create(&old, &first).await;
        old.activate_fenced_transition_capability().await.unwrap();
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &first_outcome).await;
            store.inner.raft.runtime_config().elect(false);
        }
        let retained = old.inner.raft.metrics().borrow().last_applied.unwrap();
        let retained_vote = old.inner.raft.metrics().borrow().vote;
        until(
            || {
                fleet.stores.iter().flatten().all(|store| {
                    let metrics = store.inner.raft.metrics();
                    let current = metrics.borrow();
                    current.last_applied == Some(retained)
                        && current.last_log_index == Some(retained.index)
                })
            },
            "the initial committed prefix is identical before partition",
        )
        .await;
        for peer in [successor, other] {
            fleet.set_link(old_leader, peer, false);
            fleet.set_link(peer, old_leader, false);
        }
        // These are bounded real engine proposals and retain the original
        // admission slots until their actual receivers finish. No storage
        // row, LogId or vote is fabricated to construct the conflicting tail.
        let (authority_identity, _) = old.current_scope().unwrap();
        let deadline = tokio::time::Instant::now() + OPERATION_BOUND;
        let mut completions = Vec::new();
        for _ in 0..DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS {
            let command = SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: old.inner.storage_identity,
                request_id: SessionConsensusRequestId::new(),
                logical_time: old.inner.clock.now_utc(),
                intent: SessionMutationIntent::Authorized {
                    origin: old.inner.local_node_id,
                    authority_identity,
                    mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
                },
            };
            validate_consensus_command_preproposal(&command).unwrap();
            let permit = tokio::time::timeout_at(
                deadline,
                Arc::clone(&old.inner.proposal_admission).acquire_owned(),
            )
            .await
            .unwrap()
            .unwrap();
            let response =
                tokio::time::timeout_at(deadline, old.inner.raft.client_write_ff(command))
                    .await
                    .unwrap()
                    .unwrap();
            completions.push(tokio::spawn(async move {
                let result = response.await;
                drop(permit);
                result
            }));
        }
        let suffix_end = retained.index + DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS as u64;
        until(
            || old.inner.raft.metrics().borrow().last_log_index == Some(suffix_end),
            "the isolated real leader appends the full bounded incompatible suffix",
        )
        .await;
        assert!(completions
            .iter()
            .all(|completion| !completion.is_finished()));
        assert_eq!(
            old.inner.raft.metrics().borrow().last_applied,
            Some(retained)
        );
        assert_eq!(old.inner.raft.metrics().borrow().vote, retained_vote);
        old.drain_async_persistence().await.unwrap();
        fleet.close(old_leader).await;
        for completion in completions {
            assert!(!matches!(completion.await.unwrap(), Ok(Ok(_))));
        }
        drop(old);
        tokio::join!(
            wait_for_lease_expiry(fleet.store(successor)),
            wait_for_lease_expiry(fleet.store(other))
        );
        let next = fleet.store(successor).clone();
        next.inner.raft.trigger().elect().await.unwrap();
        until(
            || {
                let vote = next.inner.raft.metrics().borrow().vote;
                vote.is_committed()
                    && vote.leader_id.term > retained_vote.leader_id.term
                    && vote.leader_id.voted_for() == Some(fleet.peers[successor].node)
                    && fleet.store(other).inner.raft.metrics().borrow().vote == vote
            },
            "the surviving real quorum elects a successor without the incompatible tail",
        )
        .await;
        fleet
            .open(old_leader, SessionPersistenceMode::Async)
            .await
            .unwrap();
        let cold = fleet.store(old_leader).clone();
        // Raft::new returns after spawning the core. Its watch initially
        // contains a zero vote until startup publishes the restored state.
        until(
            || cold.inner.raft.metrics().borrow().vote == retained_vote,
            "startup publishes the exact retained committed vote",
        )
        .await;
        assert_eq!(cold.inner.raft.metrics().borrow().vote, retained_vote);
        assert_eq!(
            cold.inner.raft.metrics().borrow().last_log_index,
            Some(suffix_end)
        );
        assert_eq!(
            cold.inner.raft.metrics().borrow().last_applied,
            Some(retained)
        );
        assert!(!cold.inner.persistence_protocol.is_active());
        let applied = Arc::clone(&cold.inner.backend.consensus_apply_gate)
            .acquire_owned()
            .await
            .unwrap();
        let appends = fleet.peers[old_leader]
            .successful_appends
            .load(Ordering::Acquire);
        let activation =
            ActivationRelease(cold.inner.persistence_protocol.hold_activation_for_test());
        for peer in [successor, other] {
            fleet.set_link(old_leader, peer, true);
            fleet.set_link(peer, old_leader, true);
        }
        let initialized = {
            let cold = cold.clone();
            tokio::spawn(async move { cold.initialize_cluster().await })
        };
        until(
            || {
                cold.persistence_health().recovery == Some(SessionAsyncRecoveryState::CatchingUp)
                    && fleet.peers[old_leader]
                        .successful_appends
                        .load(Ordering::Acquire)
                        > appends
                    && fleet.peers[successor]
                        .last_cut
                        .lock()
                        .unwrap()
                        .is_some_and(|cut| {
                            cold.inner
                                .raft
                                .metrics()
                                .borrow()
                                .last_log_index
                                .is_some_and(|index| {
                                    index >= cut.barrier.index && index < suffix_end
                                })
                        })
            },
            "the real successor replaces the long conflicting tail while apply remains blocked",
        )
        .await;
        let cut = fleet.peers[successor].last_cut.lock().unwrap().unwrap();
        assert!(cut.barrier.index < suffix_end);
        assert!(cold
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .is_some_and(|index| index >= cut.barrier.index && index < suffix_end));
        assert_eq!(
            cold.inner.raft.metrics().borrow().last_applied,
            Some(retained)
        );
        assert!(!cold.inner.persistence_protocol.is_active() && !cold.status().admitted);
        drop(applied);
        tokio::time::timeout(OPERATION_BOUND, activation.0.entered.notified())
            .await
            .unwrap();
        assert!(cold
            .inner
            .raft
            .metrics()
            .borrow()
            .last_applied
            .is_some_and(|last| persistence_protocol::covers(last, cut.barrier)));
        assert!(!cold.inner.persistence_protocol.is_active() && !cold.status().admitted);
        // This pauses after the actual public activation predicate succeeded,
        // immediately before publication. Its exclusive fence prevents a new
        // attempt from being installed behind that successful old check.
        let replacement = cold
            .inner
            .persistence_protocol
            .quarantine_before(tokio::time::Instant::now() + OPERATION_BOUND);
        tokio::pin!(replacement);
        assert!(futures_util::poll!(replacement.as_mut()).is_pending());
        initialized.abort();
        assert!(initialized.await.unwrap_err().is_cancelled());
        let request = replacement.await.unwrap();
        assert!(
            request.attempt > cut.request.attempt && request.incarnation == cut.request.incarnation
        );
        activation.0.release.notify_one();
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(cold
            .inner
            .persistence_protocol
            .accept_cut_before(cut, tokio::time::Instant::now() + OPERATION_BOUND)
            .await
            .is_err());
        assert!(!cold.inner.persistence_protocol.is_active() && !cold.status().admitted);
        let start = tokio::time::Instant::now();
        cold.initialize_cluster().await.unwrap();
        assert!(start.elapsed() < OPERATION_BOUND);
        let fresh = fleet.peers[successor].last_cut.lock().unwrap().unwrap();
        assert!(fresh.request.attempt > request.attempt && fresh.barrier.index > cut.barrier.index);
        assert_ne!(fresh.request.nonce, cut.request.nonce);
        for store in fleet.stores.iter().flatten() {
            store.inner.raft.runtime_config().elect(true);
            assert_recorded(store, &first, &first_outcome).await;
        }
        let second = create_request(&next, 2, &provider).await;
        let second_outcome = create(&next, &second).await;
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &second, &second_outcome).await;
        }
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
