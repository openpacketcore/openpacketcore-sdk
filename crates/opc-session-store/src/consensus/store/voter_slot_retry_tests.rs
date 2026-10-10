use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_retry_reports_pending_prepare_when_target_returns() {
    let fleet = Fleet::open().await;
    let leader = fleet.nodes[0].clone();
    let old = fleet.nodes[2].clone();
    let network = fleet.network.clone();
    let survivor = member(2, 1).identity.node_id();
    let target = member(3, 1).identity.node_id();
    for node in &fleet.nodes {
        node.inner.raft.runtime_config().elect(false);
    }
    network.handlers.write().unwrap().remove(&target);
    old.shutdown().await.unwrap();
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(100)).await;
    let result = tokio::spawn(async move {
        // Heartbeats can still prove a surviving quorum. Hold only Prepare so
        // the leader publishes its intent without committing it.
        network
            .paused_nonempty_append_to
            .store(survivor.get(), Ordering::SeqCst);
        let first = verified_request(&genesis(), 3);
        let expected = first.request().clone();
        let proposer = leader.clone();
        let proposal = tokio::spawn(async move { proposer.replace_voter(first).await });
        let provisional = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(state) = published_voter_state(&leader) {
                    if state.intent().is_some() {
                        break state;
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the original Prepare must be durable but not yet committed");
        assert_eq!(provisional.table(), &genesis());
        assert_eq!(&provisional.intent().unwrap().request, &expected);

        // A returning process can prove the old key even though its Raft call
        // is fenced. Deliver this evidence only to the leader, so the surviving
        // follower remains eligible to acknowledge the original Prepare.
        let vote = SessionConsensusWireRequest::try_new(
            leader.inner.storage_identity,
            target,
            SessionConsensusRpcFamily::Vote,
            encode_bounded(&VoteRequest {
                vote: Vote::new(0, target),
                last_log_id: None,
            })
            .unwrap(),
        )
        .unwrap();
        let response = old
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .transport
            .peer(member(1, 1).identity.node_id())
            .call(vote)
            .await
            .unwrap();
        assert!(
            response.result.is_err(),
            "the old incarnation remains fenced"
        );
        assert_eq!(
            leader
                .inner
                .voter_profile
                .as_ref()
                .unwrap()
                .admission
                .check_target_absent(target),
            Err(VoterReplacementError::TargetStillLive)
        );
        let retry = leader.replace_voter(verified_request(&genesis(), 3)).await;
        assert_eq!(leader.voter_slot_state().await.unwrap(), provisional);
        network.paused_nonempty_append_to.store(0, Ordering::SeqCst);
        let committed = tokio::time::timeout(Duration::from_secs(5), proposal)
            .await
            .expect("the original Prepare must still be able to commit")
            .unwrap()
            .unwrap();
        assert!(committed.intent().is_none());
        assert_eq!(
            committed.table().replacement.as_ref().unwrap().attestation,
            expected.attestation
        );
        assert_eq!(retry, Err(VoterReplacementError::ReplacementInProgress));
    })
    .await;
    fleet
        .network
        .paused_nonempty_append_to
        .store(0, Ordering::SeqCst);
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_retry_reports_an_attempt_waiting_for_peer_drain() {
    let fleet = Fleet::open().await;
    let leader = fleet.nodes[0].clone();
    let old = fleet.nodes[2].clone();
    let target = member(3, 1).identity.node_id();
    for node in &fleet.nodes {
        node.inner.raft.runtime_config().elect(false);
    }
    fleet.network.handlers.write().unwrap().remove(&target);
    old.shutdown().await.unwrap();
    tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(100)).await;
    let result = tokio::spawn(async move {
        let admission = leader
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .admission
            .clone();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let peer_admission = admission.clone();
        let accepted = tokio::spawn(async move {
            peer_admission
                .run_peer(
                    target,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                    move || async move {
                        entered.send(()).unwrap();
                        let _ = released.await;
                        Ok(())
                    },
                )
                .await
        });
        started.await.unwrap();
        let proposer = leader.clone();
        let proposal = tokio::spawn(async move {
            proposer
                .replace_voter(verified_request(&genesis(), 3))
                .await
        });
        // The original attempt has closed new calls and is draining the one
        // accepted above. It owns the replacement even before Prepare exists.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let probe = admission
                    .run_peer(
                        target,
                        tokio::time::Instant::now() + Duration::from_millis(50),
                        || async { Ok(()) },
                    )
                    .await;
                if probe == Err(VoterReplacementError::UnauthorizedReplacement) {
                    break;
                }
                assert!(probe.is_ok() || probe == Err(VoterReplacementError::Deadline));
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the first attempt must reach the peer-drain barrier");
        let before = leader.voter_slot_state().await.unwrap();
        assert!(before.intent().is_none());
        assert_eq!(before.table(), &genesis());
        let vote = SessionConsensusWireRequest::try_new(
            leader.inner.storage_identity,
            target,
            SessionConsensusRpcFamily::Vote,
            encode_bounded(&VoteRequest {
                vote: Vote::new(0, target),
                last_log_id: None,
            })
            .unwrap(),
        )
        .unwrap();
        let response = old
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .transport
            .peer(member(1, 1).identity.node_id())
            .call(vote)
            .await
            .unwrap();
        assert!(response.result.is_err());
        assert_eq!(
            admission.check_target_absent(target),
            Err(VoterReplacementError::TargetStillLive)
        );
        let retry = leader.replace_voter(verified_request(&genesis(), 3)).await;
        release.send(()).unwrap();
        accepted.await.unwrap().unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), proposal)
                .await
                .unwrap()
                .unwrap(),
            Err(VoterReplacementError::TargetStillLive)
        );
        assert_eq!(leader.voter_slot_state().await.unwrap(), before);
        assert_eq!(retry, Err(VoterReplacementError::ReplacementInProgress));
    })
    .await;
    fleet.close().await;
    result.unwrap();
}
