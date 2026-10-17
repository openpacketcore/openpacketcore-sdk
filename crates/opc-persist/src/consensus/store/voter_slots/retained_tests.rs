use super::*;
use crate::{RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};

fn retained_options(
    directory: &std::path::Path,
    initial: VoterSlotTable,
    local: ConsensusNodeId,
) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        directory.join("config.sqlite"),
        RetainedConfigBinding::for_voter_slots(initial, local, [41; 32], [42; 32])
            .expect("retained incarnation binding"),
        RetainedConfigDurability::Ephemeral,
        64 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .expect("retained options")
}

fn audit_key() -> crate::AuditKey {
    crate::AuditKey::new([42; 32]).unwrap()
}

#[tokio::test]
async fn retained_voter_profile_reopens_and_refuses_legacy_admission() {
    let directory = tempfile::tempdir().unwrap();
    let local = member(1, 1).identity.node_id();
    let options = retained_options(directory.path(), genesis(), local);
    let backend = SqliteBackend::provision_config_authority(options.clone(), audit_key())
        .await
        .expect("provision the admitted genesis incarnation");
    let legacy = ConsensusConfigStore::open(
        ConfigConsensusTopology::for_voter_slots(&genesis(), local).unwrap(),
        backend.clone(),
        directory.path().join("legacy-snapshots"),
        BTreeMap::new(),
    )
    .await;
    assert!(matches!(
        legacy,
        Err(ConfigConsensusOpenError::InvalidRuntimeConfiguration)
    ));
    let network = Arc::new(Network::default());
    let open = |backend| {
        ConsensusConfigStore::open_with_voter_slots(
            genesis(),
            local,
            backend,
            directory.path().join("snapshots"),
            Arc::new(Resolver(network.clone())),
        )
    };
    let store = open(backend)
        .await
        .expect("open retained incarnation profile");
    assert_eq!(store.voter_slot_state().await.unwrap().table(), &genesis());
    store.shutdown().await.unwrap();
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(options, audit_key())
        .await
        .expect("reopen exact retained incarnation binding");
    let store = open(backend)
        .await
        .expect("reopen retained incarnation profile");
    assert_eq!(store.voter_slot_state().await.unwrap().table(), &genesis());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn retained_replacement_candidate_preserves_nonvoting_admission_on_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let mut prepared = genesis();
    let request = verified_request(&prepared, 3).request().clone();
    prepared
        .apply_control(
            &VoterSlotControl::Begin(Box::new(request)),
            VoterSlotLogId { term: 1, index: 1 },
        )
        .expect("fixture models a committed Prepare");
    let local = member(3, 2).identity.node_id();
    assert_ne!(local, member(3, 1).identity.node_id());
    let options = retained_options(directory.path(), prepared.clone(), local);
    let backend = SqliteBackend::provision_config_member_repair(options.clone(), audit_key())
        .await
        .expect("provision selected candidate storage");
    assert!(backend.retained_repair_only);
    let network = Arc::new(Network::default());
    let open = |backend| {
        ConsensusConfigStore::open_with_voter_slots(
            prepared.clone(),
            local,
            backend,
            directory.path().join("snapshots"),
            Arc::new(Resolver(network.clone())),
        )
    };
    let store = open(backend).await.expect("open retained candidate");
    assert!(!store
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
    assert_eq!(store.voter_slot_state().await.unwrap().table(), &prepared);
    assert!(store.inner.raft.metrics().borrow().last_applied.is_none());
    store.shutdown().await.unwrap();
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(options, audit_key())
        .await
        .expect("reopen pending candidate without provisioning again");
    assert!(backend.retained_repair_only);
    let store = open(backend).await.expect("resume retained candidate");
    assert!(!store
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
    assert_eq!(store.voter_slot_state().await.unwrap().table(), &prepared);
    assert!(store.inner.raft.metrics().borrow().last_applied.is_none());
    store.shutdown().await.unwrap();
}

async fn retained_fleet(size: u16) -> (Fleet, VoterSlotTable) {
    let mut initial = genesis();
    initial.slots = (1..=size)
        .map(|slot| VoterSlotRecord {
            member: member(slot, 1),
            retired_through: 0,
            phase: VoterSlotPhase::Voting,
            last_result: None,
        })
        .collect();
    let network = Arc::new(Network::default());
    let mut nodes = Vec::new();
    let mut directories = Vec::new();
    for slot in 1..=size {
        let directory = tempfile::tempdir().unwrap();
        let local = member(slot, 1).identity.node_id();
        let backend = SqliteBackend::provision_config_authority(
            retained_options(directory.path(), initial.clone(), local),
            audit_key(),
        )
        .await
        .unwrap();
        let store = ConsensusConfigStore::open_with_voter_slots(
            initial.clone(),
            local,
            backend,
            directory.path().join("snapshots"),
            Arc::new(Resolver(network.clone())),
        )
        .await
        .unwrap();
        network
            .handlers
            .write()
            .unwrap()
            .insert(local, store.rpc_handler());
        nodes.push(store);
        directories.push(directory);
    }
    for initialized in
        futures_util::future::join_all(nodes.iter().map(ConsensusConfigStore::initialize_cluster))
            .await
    {
        initialized.unwrap();
    }
    nodes[0]
        .inner
        .raft
        .wait(Some(Duration::from_secs(5)))
        .current_leader(member(1, 1).identity.node_id(), "retained fixture leader")
        .await
        .unwrap();
    let prefix = nodes[0]
        .inner
        .raft
        .client_write(super::review_tests::probe_marker(&nodes[0], 0xD3, 1))
        .await
        .unwrap()
        .log_id;
    for node in &nodes {
        node.inner
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(prefix.index), "common retained prefix")
            .await
            .unwrap();
        node.inner.raft.runtime_config().elect(false);
    }
    (
        Fleet {
            nodes,
            network,
            directories,
        },
        initial,
    )
}

async fn durable_vote(store: &ConsensusConfigStore) -> Option<Vote<ConsensusNodeId>> {
    let core = store.inner.voter_profile.as_ref().unwrap().core.clone();
    let identity = core.identity;
    let members = core.expected_members.clone();
    core.run_sqlite(move |conn| crate::consensus::sqlite::read_vote_sync(conn, identity, &members))
        .await
        .unwrap()
}

async fn lease_expired(store: &ConsensusConfigStore) {
    let lease = Duration::from_millis(config_raft_config().unwrap().election_timeout_max);
    loop {
        let deadline = store
            .inner
            .raft
            .with_raft_state(move |state| {
                if state.vote_ref().is_committed() {
                    state.vote_last_modified().map(|at| at + lease)
                } else {
                    None
                }
            })
            .await
            .unwrap();
        let Some(deadline) = deadline else {
            return;
        };
        if tokio::time::Instant::now() > deadline {
            return;
        }
        tokio::time::sleep_until(deadline + Duration::from_nanos(1)).await;
    }
}

async fn wait_for_grant(
    network: &Network,
    target: ConsensusNodeId,
    vote: Vote<ConsensusNodeId>,
) -> RecordedVote {
    loop {
        let changed = network.vote_changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if let Some(recorded) = network
            .votes
            .lock()
            .unwrap()
            .iter()
            .find(|entry| {
                entry.target == target && entry.request.vote == vote && entry.response.vote_granted
            })
            .cloned()
        {
            return recorded;
        }
        changed.await;
    }
}

async fn selected_candidate(
    fleet: &Fleet,
    prepared: &VoterSlotTable,
    slot: u16,
) -> (
    ConsensusConfigStore,
    tempfile::TempDir,
    RetainedConfigOptions,
) {
    selected_candidate_with_timeout(
        fleet,
        prepared,
        slot,
        DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT,
    )
    .await
}

async fn selected_candidate_with_timeout(
    fleet: &Fleet,
    prepared: &VoterSlotTable,
    slot: u16,
    operation_timeout: Duration,
) -> (
    ConsensusConfigStore,
    tempfile::TempDir,
    RetainedConfigOptions,
) {
    let directory = tempfile::tempdir().unwrap();
    let local = member(slot, 2).identity.node_id();
    let options = retained_options(directory.path(), prepared.clone(), local);
    let backend = SqliteBackend::provision_config_member_repair(options.clone(), audit_key())
        .await
        .unwrap();
    let candidate = ConsensusConfigStore::open_with_voter_slots_and_operation_timeout(
        prepared.clone(),
        local,
        backend,
        directory.path().join("snapshots"),
        Arc::new(Resolver(fleet.network.clone())),
        operation_timeout,
    )
    .await
    .unwrap();
    assert_eq!(durable_vote(&candidate).await, None);
    assert!(!candidate
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
    (candidate, directory, options)
}

async fn wait_for_replacement(leader: &ConsensusConfigStore) -> VoterSlotDurableState {
    let mut changes = leader.inner.durable_progress.subscribe_applied();
    loop {
        let state = leader.voter_slot_state().await.unwrap();
        if state.table().replacement.is_none() {
            return state;
        }
        changes.changed().await.unwrap();
    }
}

async fn wait_for_admitted_candidate(candidate: &ConsensusConfigStore) {
    candidate
        .initialize_cluster()
        .await
        .expect("candidate becomes an admitted voter");
    assert!(candidate.status().admitted);
    assert!(candidate
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
}

async fn learner_refuses_vote(fleet: &Fleet, candidate: &ConsensusConfigStore, term: u64) {
    assert!(!candidate.status().admitted);
    let mut binding = fleet
        .network
        .learner_binding
        .lock()
        .unwrap()
        .clone()
        .expect("real learner marker RPC binding");
    assert_eq!(
        binding.destination.identity.node_id(),
        candidate.inner.local_node_id
    );
    let before = durable_vote(candidate).await;
    let request = ConsensusWireRequest::try_new(
        binding.configuration,
        binding.source.identity.node_id(),
        ConsensusRpcFamily::Vote,
        encode_config_wire(&VoteRequest {
            vote: Vote::new(term, binding.source.identity.node_id()),
            last_log_id: candidate.inner.raft.metrics().borrow().last_applied,
        })
        .unwrap(),
    )
    .unwrap();
    binding.payload_digest = voter_rpc_request_digest(&request).unwrap();
    let response = Peer {
        network: fleet.network.clone(),
        member: binding.destination.clone(),
    }
    .call_with_incarnation(request, binding, Duration::from_secs(3))
    .await
    .unwrap();
    assert_eq!(
        response.response.result,
        Err(ConsensusPeerError::ScopeMismatch)
    );
    assert_eq!(
        durable_vote(candidate).await,
        before,
        "learner refusal cannot update its durable vote"
    );
    let membership = candidate
        .inner
        .raft
        .metrics()
        .borrow()
        .membership_config
        .clone();
    assert!(membership
        .membership()
        .learner_ids()
        .any(|id| id == candidate.inner.local_node_id));
    assert!(!candidate
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_retained_voters_replace_lost_vote_identity_through_a_learner() {
    let (mut fleet, initial) = retained_fleet(5).await;
    let leader = fleet.nodes[0].clone();
    let old = member(5, 1).identity.node_id();
    let new = member(5, 2).identity.node_id();
    let term = leader.status().term;
    {
        let mut blocked = fleet.network.blocked_paths.lock().unwrap();
        for source in 1..=5 {
            for target in 1..=5 {
                if (source <= 3) != (target <= 3) {
                    blocked.insert((
                        member(source, 1).identity.node_id(),
                        member(target, 1).identity.node_id(),
                    ));
                }
            }
        }
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            lease_expired(&fleet.nodes[3]),
            lease_expired(&fleet.nodes[4])
        );
        fleet.nodes[3].inner.raft.trigger().elect().await.unwrap();
        let original = wait_for_grant(
            &fleet.network,
            old,
            Vote::new(term + 1, member(4, 1).identity.node_id()),
        )
        .await;
        assert_eq!(
            durable_vote(&fleet.nodes[4]).await,
            Some(original.request.vote)
        );
        leader.inner.raft.ensure_linearizable().await.unwrap();
        assert_eq!(
            leader.status().term,
            term,
            "the source quorum has not observed the lost vote"
        );
    })
    .await
    .expect("deterministic unfinished five-voter campaign");
    fleet.network.handlers.write().unwrap().remove(&old);
    fleet.nodes[4].shutdown().await.unwrap();

    tokio::time::timeout(Duration::from_secs(30), async {
        // This is the configured authenticated-loss observation window, not an
        // election schedule or a guessed lease delay.
        tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW).await;
        let prepared = leader
            .replace_voter(verified_request(&initial, 5))
            .await
            .unwrap();
        assert!(prepared.table().is_retired(old));
        // Finalization is deliberately withheld below, so initialize must
        // exhaust its own request budget. Use the same one-second attempt as
        // the bounded-download regressions; the 30-second outer bound still
        // includes the full authenticated-loss window and later vote lease.
        let (candidate, directory, _) =
            selected_candidate_with_timeout(&fleet, prepared.table(), 5, Duration::from_secs(1))
                .await;
        fleet
            .network
            .freeze_after_marker
            .store(new.get(), Ordering::SeqCst);
        fleet
            .network
            .handlers
            .write()
            .unwrap()
            .insert(new, candidate.rpc_handler());
        fleet.nodes.push(candidate.clone());
        fleet.directories.push(directory);
        let (finished, admission) = tokio::join!(
            wait_for_replacement(&leader),
            candidate.initialize_cluster()
        );
        assert!(
            admission.is_err(),
            "the candidate still awaits local finalization"
        );
        assert_eq!(finished.table().configuration_epoch.get(), 2);
        assert_eq!(
            fleet.network.paused_replication_to.load(Ordering::SeqCst),
            new.get()
        );
        learner_refuses_vote(&fleet, &candidate, term + 1).await;
        let membership = leader
            .inner
            .raft
            .metrics()
            .borrow()
            .membership_config
            .clone();
        assert_eq!(membership.membership().get_joint_config().len(), 1);
        assert_eq!(
            membership.membership().voter_ids().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                member(1, 1).identity.node_id(),
                member(2, 1).identity.node_id(),
                member(3, 1).identity.node_id(),
                member(4, 1).identity.node_id(),
                new
            ])
        );
        assert!(!membership.membership().voter_ids().any(|id| id == old));
        fleet
            .network
            .paused_replication_to
            .store(0, Ordering::SeqCst);
        wait_for_admitted_candidate(&candidate).await;
        assert!(candidate
            .voter_slot_state()
            .await
            .unwrap()
            .table()
            .is_retired(old));
        assert_eq!(candidate.status().node_id, new);
        // Recreate the conflicting candidate's real campaign after promotion.
        // Its term is the same one in which the lost identity voted for voter 4;
        // only the newly selected identity may grant this request now.
        let competing = member(3, 1).identity.node_id();
        fleet.nodes[2]
            .inner
            .raft
            .wait(Some(Duration::from_secs(3)))
            .applied_index_at_least(
                candidate.status().applied_index,
                "competing voter observes completed replacement",
            )
            .await
            .unwrap();
        {
            let mut blocked = fleet.network.blocked_paths.lock().unwrap();
            for peer in [
                member(1, 1).identity.node_id(),
                member(2, 1).identity.node_id(),
            ] {
                blocked.insert((peer, competing));
                blocked.insert((competing, peer));
                blocked.insert((peer, new));
                blocked.insert((new, peer));
            }
        }
        fleet.nodes[2].inner.raft.runtime_config().elect(false);
        candidate.inner.raft.runtime_config().elect(false);
        tokio::join!(lease_expired(&fleet.nodes[2]), lease_expired(&candidate));
        fleet.nodes[2].inner.raft.trigger().elect().await.unwrap();
        let successor_grant =
            wait_for_grant(&fleet.network, new, Vote::new(term + 1, competing)).await;
        assert_eq!(
            durable_vote(&candidate).await,
            Some(successor_grant.request.vote)
        );
        assert_ne!(successor_grant.target, old);
    })
    .await
    .expect("new-identity repair preserves the 30-second repair bound");

    let grants = fleet.network.votes.lock().unwrap().clone();
    let mut by_identity_and_term = BTreeMap::new();
    for grant in grants
        .into_iter()
        .filter(|grant| grant.response.vote_granted)
    {
        let key = (grant.target, grant.request.vote.leader_id.term);
        let previous = by_identity_and_term.insert(key, grant.request.vote);
        assert!(
            previous.is_none_or(|vote| vote == grant.request.vote),
            "one identity granted two candidates in a term"
        );
    }
    fleet.close().await;
}

#[tokio::test]
async fn retained_repair_cannot_reuse_a_voting_incarnation() {
    let directory = tempfile::tempdir().unwrap();
    let local = member(3, 1).identity.node_id();
    let options = retained_options(directory.path(), genesis(), local);
    let backend = SqliteBackend::provision_config_member_repair(options.clone(), audit_key())
        .await
        .unwrap();
    let network = Arc::new(Network::default());
    let open = |backend| {
        ConsensusConfigStore::open_with_voter_slots(
            genesis(),
            local,
            backend,
            directory.path().join("snapshots"),
            Arc::new(Resolver(network.clone())),
        )
    };
    assert!(matches!(
        open(backend).await,
        Err(ConfigConsensusOpenError::VoterIdentityReplacementRequired)
    ));
    let backend = SqliteBackend::reopen_config_authority(options, audit_key())
        .await
        .unwrap();
    assert!(matches!(
        open(backend).await,
        Err(ConfigConsensusOpenError::VoterIdentityReplacementRequired)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_retained_voters_resume_a_learner_after_cancellation_and_restart() {
    let (mut fleet, initial) = retained_fleet(3).await;
    let leader = fleet.nodes[0].clone();
    let old = member(3, 1).identity.node_id();
    let new = member(3, 2).identity.node_id();
    fleet.network.handlers.write().unwrap().remove(&old);
    fleet.nodes[2].shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW).await;
        let prepared = leader
            .replace_voter(verified_request(&initial, 3))
            .await
            .unwrap();
        let (candidate, directory, options) = selected_candidate(&fleet, prepared.table(), 3).await;
        fleet
            .network
            .freeze_after_marker
            .store(new.get(), Ordering::SeqCst);
        fleet
            .network
            .handlers
            .write()
            .unwrap()
            .insert(new, candidate.rpc_handler());
        let admitting = candidate.clone();
        let initialization = tokio::spawn(async move { admitting.initialize_cluster().await });
        wait_for_replacement(&leader).await;
        learner_refuses_vote(&fleet, &candidate, leader.status().term + 1).await;
        assert!(
            !initialization.is_finished(),
            "learner must still be awaiting promotion"
        );
        initialization.abort();
        assert!(initialization.await.unwrap_err().is_cancelled());
        fleet.network.handlers.write().unwrap().remove(&new);
        candidate.shutdown().await.unwrap();
        drop(candidate);
        let backend = SqliteBackend::reopen_config_authority(options, audit_key())
            .await
            .expect("restart the same admitted candidate backing");
        let resumed = ConsensusConfigStore::open_with_voter_slots(
            prepared.table().clone(),
            new,
            backend,
            directory.path().join("snapshots"),
            Arc::new(Resolver(fleet.network.clone())),
        )
        .await
        .expect("resume installed learner state");
        assert!(!resumed
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .local_voting_admitted());
        assert!(resumed.inner.raft.metrics().borrow().last_applied.is_some());
        fleet
            .network
            .handlers
            .write()
            .unwrap()
            .insert(new, resumed.rpc_handler());
        fleet
            .network
            .paused_replication_to
            .store(0, Ordering::SeqCst);
        wait_for_admitted_candidate(&resumed).await;
        assert_eq!(resumed.status().node_id, new);
        let state = resumed.voter_slot_state().await.unwrap();
        assert!(state.table().replacement.is_none());
        assert!(state.table().is_retired(old));
        assert_eq!(state.table().configuration_epoch.get(), 2);
        fleet.nodes.push(resumed);
        fleet.directories.push(directory);
    })
    .await
    .expect("three-voter restart and cancellation preserve the 30-second repair bound");
    fleet.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_replacement_resumes_after_the_leader_restarts() {
    let (mut fleet, initial) = retained_fleet(3).await;
    let old = member(3, 1).identity.node_id();
    let new = member(3, 2).identity.node_id();
    let leader_id = member(1, 1).identity.node_id();
    fleet.network.handlers.write().unwrap().remove(&old);
    fleet.nodes[2].shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW).await;
        let prepared = fleet.nodes[0]
            .replace_voter(verified_request(&initial, 3))
            .await
            .unwrap();
        let operation = prepared.table().replacement.as_ref().unwrap();
        assert_eq!(operation.phase, VoterReplacementPhase::Prepared);
        fleet.nodes[1]
            .inner
            .raft
            .wait(None)
            .applied_index_at_least(
                Some(operation.evidence.prepare.index),
                "survivor retains Prepare",
            )
            .await
            .unwrap();

        fleet.network.handlers.write().unwrap().remove(&leader_id);
        let leader = fleet.nodes.remove(0);
        let vote = durable_vote(&leader).await;
        let retired_owner = Arc::downgrade(&leader.inner);
        leader.shutdown().await.unwrap();
        drop(leader);
        // The in-process fixture must finish the stopped owner's work before
        // it models a new process opening the same exclusive retained backing.
        while retired_owner.strong_count() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let directory = fleet.directories[0].path();
        let backend = SqliteBackend::reopen_config_authority(
            retained_options(directory, initial.clone(), leader_id),
            audit_key(),
        )
        .await
        .expect("ordinary retained reopen of the stopped leader");
        let resumed = ConsensusConfigStore::open_with_voter_slots(
            initial.clone(),
            leader_id,
            backend,
            directory.join("snapshots"),
            Arc::new(Resolver(fleet.network.clone())),
        )
        .await
        .unwrap();
        assert_eq!(durable_vote(&resumed).await, vote);
        assert_eq!(resumed.voter_slot_state().await.unwrap(), prepared);
        fleet
            .network
            .handlers
            .write()
            .unwrap()
            .insert(leader_id, resumed.rpc_handler());

        let (candidate, directory, _) = selected_candidate(&fleet, prepared.table(), 3).await;
        fleet
            .network
            .handlers
            .write()
            .unwrap()
            .insert(new, candidate.rpc_handler());
        // Ordinary engine election and the store-owned coordinator recover the
        // accepted request. No election trigger or replacement resubmission.
        let (finished, ()) = tokio::join!(
            wait_for_replacement(&resumed),
            wait_for_admitted_candidate(&candidate)
        );
        assert!(finished.table().is_retired(old));
        assert_eq!(finished.table().configuration_epoch.get(), 2);
        assert_eq!(finished.table().slots[2].member.identity.node_id(), new);
        assert_eq!(candidate.voter_slot_state().await.unwrap(), finished);
        fleet.nodes.push(resumed);
        fleet.nodes.push(candidate);
        fleet.directories.push(directory);
    })
    .await
    .expect("retained leader restart preserves the thirty-second replacement bound");
    fleet.close().await;
}
