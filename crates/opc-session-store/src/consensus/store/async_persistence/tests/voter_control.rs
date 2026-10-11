use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarded_voter_control_is_refused_without_poisoning_a_native_store() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    for index in 0..3 {
        fleet
            .open(index, SessionPersistenceMode::Durable)
            .await
            .unwrap();
    }
    fleet.form().await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let follower = (leader + 1) % 3;
        let store = fleet.store(leader);
        assert!(store.inner.private_wal.is_some());
        assert!(store.inner.voter_profile.is_none());
        store.inner.raft.ensure_linearizable().await.unwrap();
        let before_log = store.inner.raft.metrics().borrow().last_log_index;
        let control = opc_consensus::voter_slots::VoterSlotControl::Marker {
            request_id: opc_consensus::ConsensusRequestId::from_bytes([9; 16]),
            request_digest: [7; 32],
        }
        .encode()
        .unwrap();
        let payload = encode_bounded(&ForwardRequest::Mutation(ForwardMutationRequest {
            work_class: ForwardWorkClass::Inferred,
            request_id: SessionConsensusRequestId::new(),
            intent: SessionMutationIntent::VoterSlotControl(control),
            required_consumer_scope: ForwardConsumerScope::Internal,
        }))
        .unwrap();
        let sender = fleet.peers[follower].node;
        let request = SessionConsensusWireRequest::try_new(
            store.inner.storage_identity,
            sender,
            SessionConsensusRpcFamily::ForwardMutation,
            payload,
        )
        .unwrap();
        let response = store.rpc_handler().handle(sender, request).await;
        response.validate().unwrap();
        let reply: ForwardMutationReply = decode_bounded(&response.result.unwrap()).unwrap();
        assert!(
            matches!(
                reply,
                ForwardMutationReply::Applied(response)
                    if matches!(
                        &response.result,
                        Err(StoreError::CapabilityNotSupported(reason))
                            if reason == "topology_transition_requires_local_coordinator_authority"
                    )
                        && response.sequence == 0
                        && response.digest.is_none()
                        && response.logical_time.is_none()
                        && response.raft_log_index == 0
            ),
            "forwarded voter control must be refused before proposal"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before_log,
            "a refused voter control must never enter the Raft log"
        );
        assert!(store.inner.raft.metrics().borrow().running_state.is_ok());
        store.inner.raft.ensure_linearizable().await.unwrap();

        fleet.close(leader).await;
        fleet
            .open(leader, SessionPersistenceMode::Durable)
            .await
            .expect("the native store must reopen without repair");
        clock::initialize(fleet.store(leader)).await.unwrap();
        fleet.ready().await;
        assert!(fleet
            .store(leader)
            .inner
            .raft
            .metrics()
            .borrow()
            .running_state
            .is_ok());
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap();
}
