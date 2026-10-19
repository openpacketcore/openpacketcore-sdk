//! Seeding follows an actual committed leader change before recovery begins.

use super::*;
use std::cell::RefCell;
use tokio::sync::oneshot;

type BatchPause = (oneshot::Sender<u64>, oneshot::Receiver<()>);

tokio::task_local! {
    static AFTER_BATCH: RefCell<Option<BatchPause>>;
}

pub(super) async fn after_batch(last: u64) {
    if let Some((entered, released)) = AFTER_BATCH
        .try_with(|pause| pause.borrow_mut().take())
        .ok()
        .flatten()
    {
        entered.send(last).unwrap();
        released.await.unwrap();
    }
}

pub(super) async fn leader_before(
    fleet: &Fleet,
    hint: Option<SessionConsensusNodeId>,
    rejected: (SessionConsensusNodeId, u64),
    deadline: tokio::time::Instant,
) -> &ConsensusSessionStore {
    tokio::time::timeout_at(deadline, async {
        let mut metrics = fleet
            .stores
            .iter()
            .flatten()
            .map(|store| (store, store.inner.raft.metrics()))
            .collect::<Vec<_>>();
        loop {
            let leader = metrics
                .iter_mut()
                .filter_map(|(store, metrics)| {
                    let current = metrics.borrow_and_update();
                    (current.running_state.is_ok()
                        && current.state == opc_consensus::engine::ServerState::Leader
                        && current.vote.is_committed()
                        && current.current_leader == Some(store.inner.local_node_id)
                        && (store.inner.local_node_id != rejected.0
                            || current.current_term > rejected.1))
                        .then_some((*store, current.current_term))
                })
                .max_by_key(|(store, term)| (*term, hint == Some(store.inner.local_node_id)));
            if let Some((leader, _)) = leader {
                return leader;
            }
            futures_util::future::select_all(
                metrics
                    .iter_mut()
                    .map(|(_, metrics)| Box::pin(metrics.changed())),
            )
            .await
            .0
            .expect("seeding voters remain live while a leader commits");
        }
    })
    .await
    .expect("leader discovery retains the original seed batch deadline")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_seed_follows_leader_change() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let source = fleet.store(leader);
        let successor = fleet.store((leader + 1) % 3);
        let other = fleet.store((leader + 2) % 3);
        let command = repeated_command(source);
        let before = source.inner.raft.metrics().borrow().last_log_index.unwrap();
        let target = before + DURABLE_OPENRAFT_PROFILE.max_payload_entries + 4;
        let (entered, seeded) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let seeding = AFTER_BATCH.scope(
            RefCell::new(Some((entered, released))),
            seed_to(&fleet, source, &command, target),
        );
        tokio::pin!(seeding);
        let deadline = tokio::time::Instant::now() + WAIT;
        tokio::time::timeout_at(deadline, async {
            let last = tokio::select! {
                last = seeded => last.unwrap(),
                () = &mut seeding => panic!("seeding finished before the handoff"),
            };
            assert_eq!(last, before + DURABLE_OPENRAFT_PROFILE.max_payload_entries);
            assert!(last < target);
            // A successful batch is quorum-applied. The chosen successor must
            // apply that prefix too before it can accept the forced handoff.
            successor
                .inner
                .raft
                .metrics()
                .wait_for(|current| current.last_applied.is_some_and(|log| log.index >= last))
                .await
                .unwrap();
            let request = source
                .inner
                .raft
                .begin_leadership_transfer(successor.inner.local_node_id)
                .await
                .unwrap();
            for target in [other, successor] {
                let response: Result<
                    (),
                    RaftError<
                        SessionConsensusNodeId,
                        opc_consensus::engine::raft::TransferLeaderError,
                    >,
                > = source
                    .call_peer(
                        target.inner.local_node_id,
                        SessionConsensusRpcFamily::LeadershipTransfer,
                        &request,
                        deadline,
                    )
                    .await
                    .unwrap();
                response.unwrap();
            }
            for store in [source, successor, other] {
                let mut metrics = store.inner.raft.metrics();
                metrics
                    .wait_for(|current| {
                        current.vote.is_committed()
                            && current.current_leader == Some(successor.inner.local_node_id)
                            && current.vote.leader_id.term > request.from().leader_id.term
                    })
                    .await
                    .unwrap();
            }
            release.send(()).unwrap();
            seeding.await;
            for store in [source, successor] {
                let current = store.inner.raft.metrics().borrow().clone();
                assert_eq!(current.last_log_index, Some(target));
                assert!(current.last_applied.is_some_and(|log| log.index >= target));
                assert_eq!(current.current_leader, Some(successor.inner.local_node_id));
                assert!(current.vote.is_committed());
            }
        })
        .await
        .expect("seeding and the forced handoff retain their existing bound");
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
