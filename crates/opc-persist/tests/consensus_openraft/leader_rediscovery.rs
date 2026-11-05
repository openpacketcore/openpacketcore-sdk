//! Redirects and later refusals cannot rewrite a previous attempt's outcome.

use super::*;
use scripted_election::schedule;
use std::task::Poll;

#[derive(Debug)]
struct ApplicationReply {
    inner: Arc<dyn ConsensusRpcHandler>,
    family: ConsensusRpcFamily,
    payload: Vec<u8>,
    delay: Duration,
    completed: Arc<AtomicUsize>,
}

#[async_trait]
impl ConsensusRpcHandler for ApplicationReply {
    fn compatibility(&self) -> Option<opc_consensus::ConsensusCompatibility> {
        self.inner.compatibility()
    }

    async fn handle(
        &self,
        sender: ConfigConsensusNodeId,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse {
        self.handle_with_compatibility(sender, request, None).await
    }

    async fn handle_with_compatibility(
        &self,
        sender: ConfigConsensusNodeId,
        request: ConsensusWireRequest,
        compatibility: Option<opc_consensus::ConsensusCompatibility>,
    ) -> ConsensusWireResponse {
        if request.family == self.family {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            self.completed.fetch_add(1, Ordering::SeqCst);
            return ConsensusWireResponse {
                result: Ok(self.payload.clone()),
            };
        }
        self.inner
            .handle_with_compatibility(sender, request, compatibility)
            .await
    }
}

fn rejected_mutation() -> Vec<u8> {
    // Frozen postcard tags: ForwardMutationReply::Rejected (3),
    // ForwardMutationRejection::CommandTooLarge (0).
    opc_consensus::encode_bounded(&(opc_persist::CONFIG_CONSENSUS_WIRE_VERSION, 3_u8, 0_u8))
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn rejection_after_a_lost_commit_reply_retains_unknown_outcome() {
    refusal_after_a_lost_commit_reply_retains_unknown_outcome(rejected_mutation()).await;
}

async fn refusal_after_a_lost_commit_reply_retains_unknown_outcome(payload: Vec<u8>) {
    schedule::with_frozen_time(async {
        let cluster = ThreeNodeCluster::build([[0x55; 32]; 3]).await;
        let results = tokio::join!(
            cluster.stores[0].initialize_cluster(),
            cluster.stores[1].initialize_cluster(),
            cluster.stores[2].initialize_cluster(),
        );
        assert_eq!(results, (Ok(()), Ok(()), Ok(())));
        cluster.wait_ready().await;
        let leader = cluster.leader();
        let follower = (leader + 1) % 3;
        let path = &cluster.paths[&(follower, leader)];
        path.pause_forward_response.store(true, Ordering::SeqCst);
        path.drop_forward_responses(1);
        let tx_id = TxId::new();
        let write = cluster.stores[follower]
            .append_attested_commit(attested(commit(tx_id, None, 1, 31), audit(tx_id)));
        tokio::pin!(write);
        tokio::select! {
            result = &mut write => panic!("committed response must be held: {result:?}"),
            () = path.forward_response_ready.notified() => {}
        }
        let committed = cluster.stores[leader].load_latest().await.unwrap().unwrap();
        assert_eq!(committed.record.tx_id, tx_id);
        path.install(Arc::new(ApplicationReply {
            inner: cluster.stores[leader].rpc_handler(),
            family: ConsensusRpcFamily::ForwardMutation,
            payload,
            delay: Duration::ZERO,
            completed: Arc::new(AtomicUsize::new(0)),
        }))
        .await;
        path.pause_forward_response.store(false, Ordering::SeqCst);
        path.release_forward_response.notify_one();
        assert!(futures_util::poll!(&mut write).is_pending());
        tokio::time::advance(Duration::from_millis(50)).await;
        let result = write.await;
        let after = cluster.stores[leader].load_latest().await.unwrap().unwrap();
        path.install(cluster.stores[leader].rpc_handler()).await;
        cluster.shutdown().await;
        assert!(matches!(
            result.unwrap_err().kind(),
            PersistErrorKind::OutcomeUnknown
        ));
        assert_eq!(after.record, committed.record);
    })
    .await;
}

async fn redirected_call_retains_original_view(read: bool) {
    schedule::with_frozen_time(async {
        let cluster = ThreeNodeCluster::build([[0x55; 32]; 3]).await;
        let results = tokio::join!(
            cluster.stores[0].initialize_cluster(),
            cluster.stores[1].initialize_cluster(),
            cluster.stores[2].initialize_cluster(),
        );
        assert_eq!(results, (Ok(()), Ok(()), Ok(())));
        cluster.wait_ready().await;
        let leader = cluster.leader();
        let follower = (leader + 1) % 3;
        let redirected = (leader + 2) % 3;
        let old_view = cluster.stores[leader].status().node_id;
        let target = cluster.stores[redirected].status().node_id;
        let family = if read {
            ConsensusRpcFamily::ReadBarrier
        } else {
            ConsensusRpcFamily::ForwardMutation
        };
        // NotLeader is tag 2 for ReadBarrierReply and tag 1 for ForwardMutationReply.
        let hint = opc_consensus::encode_bounded(&(
            opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
            if read { 2_u8 } else { 1_u8 },
            Some(target),
        ))
        .unwrap();
        let reply = if read {
            // ReadBarrierReply::Ready(None): the fixture has no configuration.
            opc_consensus::encode_bounded(&(
                opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
                1_u8,
                None::<u64>,
            ))
            .unwrap()
        } else {
            rejected_mutation()
        };
        let old_path = &cluster.paths[&(follower, leader)];
        old_path
            .install(Arc::new(ApplicationReply {
                inner: cluster.stores[leader].rpc_handler(),
                family,
                payload: hint,
                delay: Duration::ZERO,
                completed: Arc::new(AtomicUsize::new(0)),
            }))
            .await;
        let new_path = &cluster.paths[&(follower, redirected)];
        let grace = opc_consensus::DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE;
        let reply_after_grace = Duration::from_millis(300);
        let reply_delay = grace + reply_after_grace;
        let completed = Arc::new(AtomicUsize::new(0));
        new_path
            .install(Arc::new(ApplicationReply {
                inner: cluster.stores[redirected].rpc_handler(),
                family,
                payload: reply,
                delay: reply_delay,
                completed: completed.clone(),
            }))
            .await;
        let started = tokio::time::Instant::now();
        let outcome = {
            let operation = async {
                if read {
                    cluster.stores[follower].load_latest().await
                } else {
                    let tx_id = TxId::new();
                    cluster.stores[follower]
                        .append_attested_commit(attested(commit(tx_id, None, 1, 32), audit(tx_id)))
                        .await
                        .map(|()| None)
                }
            };
            tokio::pin!(operation);
            assert!(futures_util::poll!(&mut operation).is_pending());
            // Poll at the declared retirement boundary before the reply is
            // ready, so a biased select cannot hide premature route retirement.
            tokio::time::advance(grace).await;
            assert!(futures_util::poll!(&mut operation).is_pending());
            tokio::time::advance(reply_after_grace).await;
            let outcome = futures_util::poll!(&mut operation);
            if outcome.is_pending() && completed.load(Ordering::SeqCst) == 1 {
                // The read still joins real SQLite I/O after the barrier reply.
                // Let that I/O finish without advancing the protocol clock.
                Poll::Ready(operation.await)
            } else {
                outcome
            }
        };
        assert_eq!(started.elapsed(), reply_delay);
        let view_after_reply = cluster.stores[follower].status().leader_id;
        old_path.install(cluster.stores[leader].rpc_handler()).await;
        new_path
            .install(cluster.stores[redirected].rpc_handler())
            .await;
        cluster.shutdown().await;
        assert_eq!(view_after_reply, Some(old_view));
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        let Poll::Ready(result) = outcome else {
            panic!("an unchanged stale local view must not retire a peer's fresher redirect");
        };
        if read {
            assert!(result.unwrap().is_none());
        } else {
            assert!(matches!(
                result.unwrap_err().kind(),
                PersistErrorKind::ConstraintViolation(_)
            ));
        }
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn redirected_write_ignores_the_unchanged_old_leader_view() {
    redirected_call_retains_original_view(false).await;
}

#[tokio::test(start_paused = true)]
async fn redirected_read_ignores_the_unchanged_old_leader_view() {
    redirected_call_retains_original_view(true).await;
}
