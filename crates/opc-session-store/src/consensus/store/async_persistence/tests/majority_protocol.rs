//! Recovery controls use actual authenticated member responses. Only negative
//! controls alter their copies; no synthetic vote or matching append is issued.

use super::*;
use crate::consensus::recovery_types::{Action, Prepared, Ready, Reply, Request, Round, Selection};

fn coordinator(fleet: &Fleet) -> SessionConsensusNodeId {
    fleet.peers.iter().map(|peer| peer.node).min().unwrap()
}

pub(super) fn index(fleet: &Fleet, node: SessionConsensusNodeId) -> usize {
    fleet
        .peers
        .iter()
        .position(|peer| peer.node == node)
        .unwrap()
}

pub(super) async fn control(
    fleet: &Fleet,
    target: usize,
    action: Action,
) -> Result<Reply, SessionConsensusPeerError> {
    let response = fleet.peers[target]
        .call(wire(
            fleet.store(target),
            coordinator(fleet),
            SessionPersistenceMode::Async,
            SessionConsensusRpcFamily::ReadBarrier,
            &Request::new(action),
        ))
        .await?;
    let payload = response.result?;
    let payload = persistence_protocol::unwrap_payload(SessionPersistenceMode::Async, &payload)?;
    decode_bounded(payload).map_err(|_| SessionConsensusPeerError::Protocol)
}

async fn round(fleet: &Fleet) -> Round {
    let mut participants = BTreeMap::new();
    for target in 0..fleet.stores.len() {
        let Reply::Status(status) = control(fleet, target, Action::Status).await.unwrap() else {
            panic!("expected actual recovery status");
        };
        participants.insert(status.node, status);
    }
    let store = fleet.store(0);
    Round {
        identity: store.inner.storage_identity,
        voters: fenced_transition_voter_set_digest(
            store.inner.storage_identity,
            &store.inner.bootstrap_members,
        ),
        era: participants
            .values()
            .map(|status| status.era)
            .max()
            .unwrap()
            + 1,
        nonce: SessionConsensusRequestId::new(),
        participants,
    }
}

pub(super) async fn prepare(fleet: &Fleet) -> Selection {
    let round = round(fleet).await;
    let prepared = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let replies = join_all(
                (0..fleet.stores.len())
                    .map(|target| control(fleet, target, Action::Prepare(round.clone()))),
            )
            .await;
            let mut prepared = BTreeMap::<SessionConsensusNodeId, Prepared>::new();
            for reply in replies {
                if let Ok(Reply::Prepared(value)) = reply {
                    prepared.insert(value.participant.node, *value);
                }
            }
            if prepared.len() == fleet.stores.len() {
                break prepared;
            }
        }
    })
    .await
    .expect("all actual preparations complete");
    let leader = *prepared
        .iter()
        .max_by(|(a, left), (b, right)| {
            left.retained
                .last
                .cmp(&right.retained.last)
                .then_with(|| b.cmp(a))
        })
        .unwrap()
        .0;
    let selection = Selection {
        round,
        prepared,
        leader,
    };
    for target in 0..fleet.stores.len() {
        assert!(matches!(
            control(fleet, target, Action::Select(selection.clone())).await,
            Ok(Reply::Selected)
        ));
    }
    selection
}

async fn committed_ready(
    fleet: &Fleet,
    selection: &Selection,
) -> BTreeMap<SessionConsensusNodeId, Ready> {
    let boundary = committed(fleet, selection).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let replies = join_all((0..fleet.stores.len()).map(|target| {
                control(
                    fleet,
                    target,
                    Action::Ready {
                        selection: selection.clone(),
                        boundary,
                    },
                )
            }))
            .await;
            let mut ready = BTreeMap::new();
            for reply in replies {
                if let Ok(Reply::Ready(value)) = reply {
                    ready.insert(value.node, value);
                }
            }
            if ready.len() == fleet.stores.len() {
                break ready;
            }
        }
    })
    .await
    .expect("all actual committed generations are persisted")
}

async fn committed(fleet: &Fleet, selection: &Selection) -> LogId<SessionConsensusNodeId> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Reply::Committed(boundary)) = control(
                fleet,
                index(fleet, selection.leader),
                Action::Commit(selection.clone()),
            )
            .await
            {
                break boundary;
            }
        }
    })
    .await
    .expect("actual boundary commit completes")
}

pub(super) async fn recover(fleet: &Fleet) {
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let _ = join_all(
                fleet
                    .stores
                    .iter()
                    .flatten()
                    .map(ConsensusSessionStore::initialize_cluster),
            )
            .await;
            let reports = join_all(
                fleet
                    .stores
                    .iter()
                    .flatten()
                    .map(ConsensusSessionStore::probe_fixed_quorum_readiness),
            )
            .await;
            if reports
                .iter()
                .all(|report| report.traffic_authority().is_granted())
            {
                break;
            }
        }
    })
    .await;
    if result.is_err() {
        for store in fleet.stores.iter().flatten() {
            eprintln!(
                "recovery_fixture_progress stage={:?} active={}",
                store.persistence_health().recovery,
                store.inner.persistence_protocol.is_active()
            );
        }
    }
    result.expect("complete recovery and usable application authority");
}

struct DiskHold {
    entered: tokio::sync::Notify,
    released: (Mutex<bool>, std::sync::Condvar),
}

impl DiskHold {
    fn release(&self) {
        *self.released.0.lock().unwrap() = true;
        self.released.1.notify_all();
    }
}

struct DiskRelease(Arc<DiskHold>);
impl Drop for DiskRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_recovery_cancelled_promise_owns_disk_until_shutdown_and_replacement() {
    exercise_cancelled_promise_owns_disk_until_shutdown_and_replacement(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_recovery_cancelled_promise_owns_disk_until_shutdown_and_replacement() {
    exercise_cancelled_promise_owns_disk_until_shutdown_and_replacement(true).await;
}

async fn exercise_cancelled_promise_owns_disk_until_shutdown_and_replacement(protected: bool) {
    use crate::sqlite::consensus::wal::Point;
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = if protected {
        Fleet::with_protected_recovery(3)
    } else {
        Fleet::new(3)
    };
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        cold(&mut fleet).await;
        fleet.close(0).await;
        let hold = Arc::new(DiskHold {
            entered: tokio::sync::Notify::new(),
            released: (Mutex::new(false), std::sync::Condvar::new()),
        });
        let _release = DiskRelease(Arc::clone(&hold));
        let hook = Arc::clone(&hold);
        fleet
            .open_with_io_hook(
                0,
                Arc::new(move |point| {
                    if point == Point::BeforeAsyncAuthorityWrite {
                        hook.entered.notify_one();
                        let mut released = hook.released.0.lock().unwrap();
                        while !*released {
                            released = hook.released.1.wait(released).unwrap();
                        }
                    }
                    Ok(())
                }),
            )
            .await
            .unwrap();
        let round = round(&fleet).await;
        let request = wire(
            fleet.store(0),
            coordinator(&fleet),
            SessionPersistenceMode::Async,
            SessionConsensusRpcFamily::ReadBarrier,
            &Request::new(Action::Prepare(round.clone())),
        );
        let peer = Arc::clone(&fleet.peers[0]);
        let request = tokio::spawn(async move { peer.call(request).await });
        tokio::time::timeout(OPERATION_BOUND, hold.entered.notified())
            .await
            .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        // Passive state remains observable while the accepted fsync is held.
        let observed = fleet.store(0).clone();
        let health = tokio::task::spawn_blocking(move || observed.persistence_health());
        assert!(!tokio::time::timeout(OPERATION_BOUND, health)
            .await
            .unwrap()
            .unwrap()
            .asynchronous
            .unwrap()
            .background_failure
            .is_some());
        let started = tokio::time::Instant::now();
        assert!(control(&fleet, 0, Action::Prepare(round.clone()))
            .await
            .is_err());
        assert!(started.elapsed() < OPERATION_BOUND * 2);
        assert!(!fleet.store(0).inner.persistence_protocol.is_active());

        *fleet.peers[0].handler.write().await = None;
        let store = fleet.stores[0].take().unwrap();
        let closed = tokio::spawn(async move { store.shutdown_with_closed_proof(false).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !closed.is_finished(),
            "shutdown must join the accepted disk owner"
        );
        assert!(
            fleet.open(0, SessionPersistenceMode::Async).await.is_err(),
            "replacement cannot acquire the still-owned root"
        );
        hold.release();
        tokio::time::timeout(OPERATION_BOUND * 2, closed)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        fleet.open(0, SessionPersistenceMode::Async).await.unwrap();
        assert!(control(&fleet, 0, Action::Prepare(round.clone()))
            .await
            .is_err());
        assert!(!fleet.store(0).inner.persistence_protocol.is_active());
        recover(&fleet).await;
        let store = fleet.store(fleet.leader());
        let request = create_request(store, 124, &provider()).await;
        let lease = store
            .acquire(
                request.lease().key(),
                OwnerId::new("cancel-successor").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        store.release(lease).await.unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_recovery_five_voters_repeat_boundary_and_sequential_rejoin() {
    exercise_five_voters_repeat_boundary_and_sequential_rejoin(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_recovery_five_voters_repeat_boundary_and_sequential_rejoin() {
    exercise_five_voters_repeat_boundary_and_sequential_rejoin(true).await;
}

async fn exercise_five_voters_repeat_boundary_and_sequential_rejoin(protected: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = if protected {
        Fleet::with_protected_recovery(5)
    } else {
        Fleet::new(5)
    };
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let mut prior_era = 1;
        for turn in 0..2 {
            cold(&mut fleet).await;
            recover(&fleet).await;
            let store = fleet.store(fleet.leader());
            let (_, bound) = store
                .inner
                .private_wal
                .as_ref()
                .unwrap()
                .async_authority()
                .unwrap()
                .unwrap();
            assert!(bound.era() > prior_era);
            prior_era = bound.era();
            let request = create_request(store, 125 + turn, &provider()).await;
            let lease = store
                .acquire(
                    request.lease().key(),
                    OwnerId::new("five-successor").unwrap(),
                    Duration::from_secs(60),
                )
                .await
                .unwrap();
            store.release(lease).await.unwrap();
            // Keep one peer unavailable: the remaining live majority still
            // suffices for ordinary single-voter rejoin after retirement.
            fleet.close(4).await;
            for target in 0..4 {
                fleet.close(target).await;
                fleet
                    .open(target, SessionPersistenceMode::Async)
                    .await
                    .unwrap();
                recover(&fleet).await;
                assert_eq!(
                    fleet
                        .store(target)
                        .inner
                        .private_wal
                        .as_ref()
                        .unwrap()
                        .async_authority()
                        .unwrap()
                        .unwrap()
                        .1
                        .era(),
                    prior_era
                );
            }
            fleet.open(4, SessionPersistenceMode::Async).await.unwrap();
            recover(&fleet).await;
        }
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

pub(super) async fn cold(fleet: &mut Fleet) {
    fleet.close_all().await;
    for target in 0..fleet.stores.len() {
        fleet
            .open(target, SessionPersistenceMode::Async)
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_recovery_activation_retry_survives_a_new_real_leader() {
    exercise_activation_retry_survives_a_new_real_leader(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_recovery_activation_retry_survives_a_new_real_leader() {
    exercise_activation_retry_survives_a_new_real_leader(true).await;
}

async fn exercise_activation_retry_survives_a_new_real_leader(protected: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = if protected {
        Fleet::with_protected_recovery(3)
    } else {
        Fleet::new(3)
    };
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        cold(&mut fleet).await;
        let selection = prepare(&fleet).await;
        let ready = committed_ready(&fleet, &selection).await;
        let leader = index(&fleet, selection.leader);
        let successor = (leader + 1) % 3;
        let pending = (leader + 2) % 3;
        for target in [leader, successor] {
            assert!(matches!(
                control(
                    &fleet,
                    target,
                    Action::Activate {
                        selection: selection.clone(),
                        ready: ready.clone(),
                    }
                )
                .await,
                Ok(Reply::Active)
            ));
        }
        // Only the activated majority changes term. The pending member keeps
        // its exact prepared vote until its activation message is retried.
        fleet
            .store(leader)
            .inner
            .raft
            .runtime_config()
            .heartbeat(false);
        fleet
            .store(successor)
            .inner
            .raft
            .runtime_config()
            .elect(false);
        races::wait_for_lease_expiry(fleet.store(leader)).await;
        races::wait_for_lease_expiry(fleet.store(successor)).await;
        fleet
            .store(successor)
            .inner
            .raft
            .trigger()
            .elect()
            .await
            .unwrap();
        races::until(
            || {
                let current = fleet.store(successor).inner.raft.metrics().borrow().clone();
                current.current_leader == Some(fleet.peers[successor].node)
                    && current.vote.is_committed()
                    && current.vote.leader_id.term > ready[&selection.leader].vote.leader_id.term
            },
            "actual successor election",
        )
        .await;
        assert!(!fleet.store(pending).inner.persistence_protocol.is_active());
        for target in [pending, leader, successor] {
            assert!(
                matches!(
                    control(
                        &fleet,
                        target,
                        Action::Activate {
                            selection: selection.clone(),
                            ready: ready.clone(),
                        }
                    )
                    .await,
                    Ok(Reply::Active)
                ),
                "activation retry retains the persisted boundary across an ordinary election"
            );
        }
        recover(&fleet).await;
        let provider = provider();
        let request = create_request(fleet.store(fleet.leader()), 121, &provider).await;
        let request = FencedTransitionV2Request::new(
            fleet
                .store(fleet.leader())
                .fenced_transition_v2_history_state()
                .await
                .unwrap()
                .active_epoch()
                .unwrap(),
            FencedTransitionV2CallerNonce::from_bytes(121u128.to_be_bytes()),
            request.lease().clone(),
            request.mutation().clone(),
        )
        .unwrap();
        let outcome = create(fleet.store(fleet.leader()), &request).await;
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &request, &outcome).await;
        }
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_recovery_retries_an_election_interrupted_after_preparation() {
    exercise_retries_an_election_interrupted_after_preparation(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_recovery_retries_an_election_interrupted_after_preparation() {
    exercise_retries_an_election_interrupted_after_preparation(true).await;
}

async fn exercise_retries_an_election_interrupted_after_preparation(protected: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = if protected {
        Fleet::with_protected_recovery(3)
    } else {
        Fleet::new(3)
    };
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        cold(&mut fleet).await;
        for peer in &fleet.peers {
            peer.blocked_votes.store(true, Ordering::Release);
        }
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let _ = join_all(
                    fleet
                        .stores
                        .iter()
                        .flatten()
                        .map(ConsensusSessionStore::initialize_cluster),
                )
                .await;
                if fleet.stores.iter().flatten().all(|store| {
                    store.persistence_health().recovery
                        == Some(SessionAsyncRecoveryState::ReformingQuorum)
                }) {
                    break;
                }
            }
        })
        .await
        .expect("prepared real election loses its vote replies");
        for store in fleet.stores.iter().flatten() {
            assert!(!store.inner.persistence_protocol.is_active());
        }
        for peer in &fleet.peers {
            peer.blocked_votes.store(false, Ordering::Release);
        }
        recover(&fleet).await;
        let store = fleet.store(fleet.leader());
        let request = create_request(store, 122, &provider()).await;
        let lease = store
            .acquire(
                request.lease().key(),
                OwnerId::new("recovered-election").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        store.release(lease).await.unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_recovery_old_ready_and_delayed_activation_cannot_admit_a_replacement() {
    exercise_old_ready_and_delayed_activation_cannot_admit_a_replacement(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_recovery_old_ready_and_delayed_activation_cannot_admit_a_replacement() {
    exercise_old_ready_and_delayed_activation_cannot_admit_a_replacement(true).await;
}

async fn exercise_old_ready_and_delayed_activation_cannot_admit_a_replacement(protected: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = if protected {
        Fleet::with_protected_recovery(3)
    } else {
        Fleet::new(3)
    };
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        cold(&mut fleet).await;
        let selection = prepare(&fleet).await;
        let ready = committed_ready(&fleet, &selection).await;
        let replacement = index(&fleet, selection.leader);
        fleet.close(replacement).await;
        fleet
            .open(replacement, SessionPersistenceMode::Async)
            .await
            .unwrap();
        assert!(matches!(
            control(
                &fleet,
                replacement,
                Action::Activate {
                    selection: selection.clone(),
                    ready: ready.clone(),
                }
            )
            .await,
            Err(SessionConsensusPeerError::Rejected)
        ));
        assert!(!fleet
            .store(replacement)
            .inner
            .persistence_protocol
            .is_active());
        recover(&fleet).await;
        for target in 0..3 {
            let before = fleet
                .store(target)
                .inner
                .private_wal
                .as_ref()
                .unwrap()
                .async_authority()
                .unwrap()
                .unwrap()
                .1;
            assert!(before.era() > selection.round.era);
            for action in [
                Action::Prepare(selection.round.clone()),
                Action::Select(selection.clone()),
                Action::Activate {
                    selection: selection.clone(),
                    ready: ready.clone(),
                },
            ] {
                assert!(control(&fleet, target, action).await.is_err());
            }
            assert!(
                fleet
                    .store(target)
                    .inner
                    .private_wal
                    .as_ref()
                    .unwrap()
                    .async_authority()
                    .unwrap()
                    .unwrap()
                    .1
                    == before
            );
            assert!(fleet.store(target).inner.persistence_protocol.is_active());
        }
        let store = fleet.store(fleet.leader());
        let request = create_request(store, 123, &provider()).await;
        let lease = store
            .acquire(
                request.lease().key(),
                OwnerId::new("replacement-owner").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        store.release(lease).await.unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_recovery_certificates_require_exact_roster_root_boot_vote_and_commit() {
    exercise_certificates_require_exact_roster_root_boot_vote_and_commit(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_recovery_certificates_require_exact_roster_root_boot_vote_and_commit() {
    exercise_certificates_require_exact_roster_root_boot_vote_and_commit(true).await;
}

async fn exercise_certificates_require_exact_roster_root_boot_vote_and_commit(protected: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = if protected {
        Fleet::with_protected_recovery(3)
    } else {
        Fleet::new(3)
    };
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        cold(&mut fleet).await;
        let selection = prepare(&fleet).await;
        if protected {
            let caller = coordinator(&fleet);
            let remote = fleet
                .peers
                .iter()
                .find(|peer| peer.node != caller && peer.node != selection.leader)
                .unwrap();
            let rejection = fleet
                .store(index(&fleet, caller))
                .recovery_call(
                    remote.node,
                    Action::Commit(selection.clone()),
                    tokio::time::Instant::now() + OPERATION_BOUND,
                )
                .await
                .err();
            assert_eq!(
                rejection,
                Some(SessionConsensusPeerError::Rejected),
                "an authenticated rejection must not become retryable owner progress"
            );
        }
        let own = fleet.peers[0].node;
        let mut invalid = Vec::new();
        let mut changed = selection.clone();
        changed.round.voters[0] ^= 1;
        invalid.push(changed);
        let mut changed = selection.clone();
        changed.round.participants.get_mut(&own).unwrap().root[0] ^= 1;
        invalid.push(changed);
        let mut changed = selection.clone();
        changed.round.participants.get_mut(&own).unwrap().boot = SessionConsensusRequestId::new();
        invalid.push(changed);
        let mut changed = selection.clone();
        changed.round.era -= 1;
        invalid.push(changed);
        let mut changed = selection.clone();
        changed.round.identity = SessionConsensusIdentity::new(
            selection.round.identity.cluster_id(),
            selection.round.identity.configuration_id(),
            ConsensusConfigurationEpoch::new(
                selection.round.identity.configuration_epoch().get() + 1,
            )
            .unwrap(),
        );
        invalid.push(changed);
        let mut changed = selection.clone();
        changed.prepared.remove(&own);
        invalid.push(changed);
        let mut changed = selection.clone();
        changed
            .prepared
            .get_mut(&own)
            .unwrap()
            .retained
            .vote
            .as_mut()
            .unwrap()
            .committed = true;
        invalid.push(changed);
        let mut changed = selection.clone();
        changed
            .prepared
            .get_mut(&own)
            .unwrap()
            .retained
            .last
            .as_mut()
            .unwrap()
            .leader_id
            .term += 1;
        invalid.push(changed);
        for changed in invalid {
            assert!(control(&fleet, 0, Action::Select(changed)).await.is_err());
            assert!(!fleet.store(0).inner.persistence_protocol.is_active());
        }
        let ready = committed_ready(&fleet, &selection).await;
        for alteration in 0..6 {
            let mut changed = ready.clone();
            match alteration {
                0 => {
                    changed.remove(&own);
                }
                1 => changed.get_mut(&own).unwrap().boot = SessionConsensusRequestId::new(),
                2 => changed.get_mut(&own).unwrap().root[0] ^= 1,
                3 => changed.get_mut(&own).unwrap().vote.committed = false,
                4 => changed.get_mut(&own).unwrap().boundary.leader_id.term += 1,
                5 => changed.get_mut(&own).unwrap().boundary.index += 1,
                _ => unreachable!(),
            }
            assert!(control(
                &fleet,
                0,
                Action::Activate {
                    selection: selection.clone(),
                    ready: changed,
                }
            )
            .await
            .is_err());
            assert!(!fleet.store(0).inner.persistence_protocol.is_active());
        }
        for target in 0..3 {
            assert!(matches!(
                control(
                    &fleet,
                    target,
                    Action::Activate {
                        selection: selection.clone(),
                        ready: ready.clone(),
                    }
                )
                .await,
                Ok(Reply::Active)
            ));
        }
        recover(&fleet).await;
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_recovery_snapshot_requires_complete_install_and_actual_matching_append() {
    exercise_snapshot_requires_complete_install_and_actual_matching_append(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protected_async_recovery_snapshot_requires_complete_install_and_actual_matching_append() {
    exercise_snapshot_requires_complete_install_and_actual_matching_append(true).await;
}

async fn exercise_snapshot_requires_complete_install_and_actual_matching_append(protected: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = if protected {
        Fleet::with_protected_recovery(3)
    } else {
        Fleet::new(3)
    };
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        cold(&mut fleet).await;
        let selection = prepare(&fleet).await;
        let leader = index(&fleet, selection.leader);
        let target = (leader + 1) % 3;
        *fleet.peers[target].blocked_append_above.lock().unwrap() = Some((selection.leader, 0));
        let boundary = committed(&fleet, &selection).await;
        let mut snapshot = snapshots::snapshot(fleet.store(leader)).await;
        assert!(persistence_protocol::covers(
            snapshot.meta.last_log_id.unwrap(),
            boundary
        ));
        let rest = snapshot.data.split_off(snapshot.data.len() / 2);
        let offset = snapshot.data.len() as u64;
        snapshot.done = false;
        snapshots::decode_snapshot(
            snapshots::send_snapshot(fleet.store(target), selection.leader, &snapshot).await,
            "recovery partial snapshot",
        )
        .unwrap();
        let ready = Action::Ready {
            selection: selection.clone(),
            boundary,
        };
        assert!(control(&fleet, target, ready.clone()).await.is_err());
        assert!(!fleet.store(target).inner.persistence_protocol.is_active());
        assert!(
            fleet
                .store(target)
                .inner
                .raft
                .metrics()
                .borrow()
                .last_applied
                .unwrap()
                .index
                < boundary.index
        );

        snapshot.offset = offset;
        snapshot.data = rest;
        snapshot.done = true;
        snapshots::decode_snapshot(
            snapshots::send_snapshot(fleet.store(target), selection.leader, &snapshot).await,
            "recovery complete snapshot",
        )
        .unwrap();
        assert!(persistence_protocol::covers(
            fleet
                .store(target)
                .inner
                .raft
                .metrics()
                .borrow()
                .last_applied
                .unwrap(),
            boundary
        ));
        assert!(
            control(&fleet, target, ready).await.is_err(),
            "snapshot alone cannot certify a current matching peer"
        );
        assert!(!fleet.store(target).inner.persistence_protocol.is_active());

        // Exercise the normal authenticated adapter and actual engine result;
        // a synthetic acknowledgement would not be a matching witness.
        let append = AppendEntriesRequest::<SessionRaftTypeConfig> {
            vote: snapshot.vote,
            prev_log_id: snapshot.meta.last_log_id,
            entries: vec![],
            leader_commit: snapshot.meta.last_log_id,
        };
        let response = fleet
            .store(target)
            .rpc_handler()
            .handle(
                selection.leader,
                wire(
                    fleet.store(target),
                    selection.leader,
                    SessionPersistenceMode::Async,
                    SessionConsensusRpcFamily::AppendEntries,
                    &append,
                ),
            )
            .await;
        let payload = response.result.unwrap();
        let decoded = decode_bounded::<
            Result<
                AppendEntriesResponse<SessionConsensusNodeId>,
                RaftError<SessionConsensusNodeId>,
            >,
        >(
            persistence_protocol::unwrap_payload(SessionPersistenceMode::Async, &payload).unwrap(),
        )
        .unwrap();
        assert!(matches!(decoded, Ok(AppendEntriesResponse::Success)));
        *fleet.peers[target].blocked_append_above.lock().unwrap() = None;
        let ready = committed_ready(&fleet, &selection).await;
        for target in 0..3 {
            assert!(matches!(
                control(
                    &fleet,
                    target,
                    Action::Activate {
                        selection: selection.clone(),
                        ready: ready.clone()
                    }
                )
                .await,
                Ok(Reply::Active)
            ));
        }
        recover(&fleet).await;
        let store = fleet.store(fleet.leader());
        let request = create_request(store, 129, &provider()).await;
        let lease = store
            .acquire(
                request.lease().key(),
                OwnerId::new("snapshot-successor").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        store.release(lease).await.unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_recovery_protected_trust_root_needs_authority_even_without_retained_activation() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let generator = [
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96,
    ];
    let root = crate::RosterAttestationTrustRootV1::new([0xC9; 32], generator).unwrap();
    let mut fleet = Fleet::with_roster_root(3, Some(root));
    let result = AssertUnwindSafe(async {
        for target in 0..3 {
            fleet
                .open(target, SessionPersistenceMode::Async)
                .await
                .unwrap();
        }
        let initialized = join_all(
            fleet
                .stores
                .iter()
                .flatten()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await;
        assert!(initialized.iter().all(Result::is_ok));
        for store in fleet.stores.iter().flatten() {
            store.drain_async_persistence().await.unwrap();
        }
        cold(&mut fleet).await;
        for store in fleet.stores.iter().flatten() {
            assert!(store.initialize_cluster().await.is_err());
            assert_eq!(
                store.persistence_health().recovery,
                Some(SessionAsyncRecoveryState::ProtectedAuthorityRequired)
            );
            assert!(!store.inner.persistence_protocol.is_active());
            assert_eq!(
                store
                    .inner
                    .private_wal
                    .as_ref()
                    .unwrap()
                    .async_authority()
                    .unwrap()
                    .unwrap()
                    .1
                    .era(),
                1
            );
            assert!(!store
                .probe_fixed_quorum_readiness()
                .await
                .traffic_authority()
                .is_granted());
        }
        // An unavailable participant must not hide the locally established
        // unsupported authority contract behind a generic retry reason.
        fleet.close(2).await;
        assert!(fleet.store(0).initialize_cluster().await.is_err());
        assert_eq!(
            fleet.store(0).persistence_health().recovery,
            Some(SessionAsyncRecoveryState::ProtectedAuthorityRequired)
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
