use super::*;
use opc_consensus::engine::{
    raft::{AppendEntriesRequest, AppendEntriesResponse},
    EntryPayload, RaftLogReader,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_remote_survivor_live_target_veto_has_no_effect() {
    let fleet = Fleet::open().await;
    for node in &fleet.nodes {
        node.inner.raft.runtime_config().elect(false);
    }
    let leader = fleet.nodes[0].clone();
    let old = member(3, 1).identity.node_id();
    fleet.network.handlers.write().unwrap().remove(&old);
    fleet.nodes[2].shutdown().await.unwrap();
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(100)).await;
    // Only B sees a fresh proof from C. C's own loss-probe route is unavailable,
    // and A's complete observation window still says the target is absent.
    let request = SessionConsensusWireRequest::try_new(
        leader.inner.storage_identity,
        old,
        SessionConsensusRpcFamily::Vote,
        encode_bounded(&VoteRequest {
            vote: Vote::new(0, old),
            last_log_id: None,
        })
        .unwrap(),
    )
    .unwrap();
    let response = fleet.nodes[2]
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .transport
        .peer(member(2, 1).identity.node_id())
        .call(request)
        .await
        .unwrap();
    assert!(response.result.is_ok());
    assert_eq!(
        leader
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .check_target_absent(old),
        Ok(())
    );
    assert_eq!(
        fleet.nodes[1]
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .check_target_absent(old),
        Err(VoterReplacementError::TargetStillLive)
    );
    let before = leader.voter_slot_state().await.unwrap();
    let log_before = leader.inner.raft.metrics().borrow().last_log_index;
    let result = leader
        .replace_voter(verified_request(before.table(), 3))
        .await;
    let after = leader.voter_slot_state().await.unwrap();
    let log_after = leader.inner.raft.metrics().borrow().last_log_index;
    let writable = tokio::time::timeout(
        leader.inner.operation_timeout,
        leader
            .inner
            .raft
            .client_write(probe_marker(&leader, 0xC1, 1)),
    )
    .await;
    fleet.close().await;
    assert_eq!(result, Err(VoterReplacementError::TargetStillLive));
    assert_eq!(after, before);
    assert_eq!(
        log_after, log_before,
        "a remote veto must precede the local Prepare append"
    );
    assert!(
        matches!(writable, Ok(Ok(_))),
        "survivors must still commit after the refusal"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_candidate_withholds_joint_append_success_until_durable_joint_apply() {
    let (mut fleet, leader, prepared) = super::progress_tests::prepared_fleet().await;
    let candidate_id = member(3, 2).identity.node_id();
    fleet
        .network
        .freeze_after_marker
        .store(candidate_id.get(), Ordering::SeqCst);
    let candidate = super::progress_tests::add_candidate(&mut fleet, &prepared).await;
    let selected = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(state) = published_voter_state(&leader) {
                if state.table().replacement.is_none() {
                    break state;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("survivors finish while the candidate is held at its learner Marker");
    assert_eq!(
        fleet.network.paused_replication_to.load(Ordering::SeqCst),
        candidate_id.get()
    );
    let profile = candidate.inner.voter_profile.as_ref().unwrap();
    assert!(!profile.admission.local_voting_admitted());
    let previous = candidate
        .inner
        .raft
        .metrics()
        .borrow()
        .last_applied
        .unwrap();
    let mut logs = leader
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .core
        .private_wal_log_store()
        .await
        .unwrap()
        .unwrap();
    let mut entries = logs
        .try_get_log_entries(previous.index + 1..)
        .await
        .unwrap();
    drop(logs);
    let position = entries.iter().position(|entry| matches!(&entry.payload, EntryPayload::Membership(membership) if membership.get_joint_config().len() == 2)).expect("real committed joint entry");
    let joint = entries[position].log_id;
    let before_joint = if position == 0 {
        previous
    } else {
        entries[position - 1].log_id
    };
    entries.truncate(position + 1);
    let vote = leader
        .inner
        .raft
        .with_raft_state(|state| *state.vote_ref())
        .await
        .unwrap();
    let wire_identity = selected
        .table()
        .current_configuration()
        .identity(
            selected.table().cluster_instance,
            selected.table().manifest_digest,
        )
        .unwrap();
    let make_wire = |rpc: &AppendEntriesRequest<SessionRaftTypeConfig>| {
        let wire = SessionConsensusWireRequest::try_new(
            wire_identity,
            leader.inner.local_node_id,
            SessionConsensusRpcFamily::AppendEntries,
            encode_bounded(rpc).unwrap(),
        )
        .unwrap();
        fleet
            .network
            .allow_paused_requests
            .lock()
            .unwrap()
            .insert(voter_rpc_request_digest(&wire).unwrap());
        wire
    };
    // Reproduce the effective-membership window using the leader's exact log
    // entries and genuine authenticated requests, while withholding joint commit.
    let wire = make_wire(&AppendEntriesRequest {
        vote,
        prev_log_id: Some(previous),
        entries,
        leader_commit: Some(before_joint),
    });
    let peer = leader
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .transport
        .peer(candidate_id);
    let mut pending = tokio::spawn(async move { peer.call(wire).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let observed = candidate
                .inner
                .raft
                .with_raft_state(move |state| {
                    state
                        .membership_state
                        .effective()
                        .membership()
                        .get_joint_config()
                        .len()
                        == 2
                        && state
                            .membership_state
                            .effective()
                            .membership()
                            .voter_ids()
                            .any(|id| id == candidate_id)
                })
                .await
                .unwrap();
            if observed
                && candidate
                    .inner
                    .raft
                    .metrics()
                    .borrow()
                    .last_applied
                    .is_some_and(|cut| cut.index >= before_joint.index)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("candidate observes joint without committing it");
    assert!(
        candidate
            .inner
            .raft
            .metrics()
            .borrow()
            .last_applied
            .unwrap()
            .index
            < joint.index
    );
    assert!(!profile.admission.local_voting_admitted());
    let early = tokio::time::timeout(Duration::from_millis(500), &mut pending)
        .await
        .ok();
    let released_early = early.is_some();
    let heartbeat = make_wire(&AppendEntriesRequest {
        vote,
        prev_log_id: Some(joint),
        entries: vec![],
        leader_commit: Some(joint),
    });
    let commit_reply = leader
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .transport
        .peer(candidate_id)
        .call(heartbeat)
        .await
        .unwrap();
    let reply = match early {
        Some(reply) => reply.unwrap().unwrap(),
        None => tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    };
    let success = |response: SessionConsensusWireResponse| {
        matches!(
            decode_bounded::<
                Result<
                    AppendEntriesResponse<SessionConsensusNodeId>,
                    opc_consensus::engine::error::RaftError<SessionConsensusNodeId>,
                >,
            >(&response.result.unwrap()),
            Ok(Ok(
                AppendEntriesResponse::Success | AppendEntriesResponse::PartialSuccess(_)
            ))
        )
    };
    assert!(success(commit_reply));
    assert!(success(reply));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !profile.admission.local_voting_admitted() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    fleet
        .network
        .paused_replication_to
        .store(0, Ordering::SeqCst);
    fleet.close().await;
    assert!(
        !released_early,
        "candidate emitted AppendEntries success before durable joint application"
    );
}
