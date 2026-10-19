//! Seeding follows an actual committed leader change before recovery begins.

use super::*;
use std::cell::{Cell, RefCell};
use tokio::sync::oneshot;

type BatchPause = (oneshot::Sender<u64>, oneshot::Receiver<()>);

tokio::task_local! {
    static AFTER_BATCH: RefCell<Option<BatchPause>>;
    static FORCE_FIRST_BATCH_HANDOFF: Cell<bool>;
    static FORCE_CONNECTED_HANDOFF: Cell<bool>;
    static TRACK_LAGGING_FOLLOWER: Cell<Option<usize>>;
}

pub(super) async fn after_batch(
    fleet: &Fleet,
    last: u64,
    target: u64,
    deadline: tokio::time::Instant,
) {
    let connected = FORCE_CONNECTED_HANDOFF
        .try_with(|force| force.replace(false))
        .unwrap_or(false);
    let ordinary = FORCE_FIRST_BATCH_HANDOFF
        .try_with(|force| force.replace(false))
        .unwrap_or(false);
    if connected || ordinary {
        let leader = fleet.leader();
        let offset = if connected { 2 } else { 1 };
        transfer_before(
            fleet,
            fleet.store(leader),
            fleet.store((leader + offset) % 3),
            deadline,
            !connected,
        )
        .await;
        if connected {
            TRACK_LAGGING_FOLLOWER.with(|tracked| tracked.set(Some((leader + 1) % 3)));
        }
        eprintln!("seed setup handoff committed after index {last}; connected={connected}");
    }
    if let Some((entered, released)) = AFTER_BATCH
        .try_with(|pause| pause.borrow_mut().take())
        .ok()
        .flatten()
    {
        entered.send(last).unwrap();
        released.await.unwrap();
    }
    if let Some(follower) = TRACK_LAGGING_FOLLOWER.try_with(Cell::get).ok().flatten() {
        let leader = leader_before(fleet, None, None, deadline).await;
        let seed_limit = *fleet.peers[follower].seed_prefix_limit.lock().unwrap();
        if let Some(limit) = seed_limit {
            assert!(
                fleet
                    .store(follower)
                    .inner
                    .raft
                    .metrics()
                    .borrow()
                    .last_log_index
                    .is_some_and(|last| last <= limit),
                "initial seed preserves the isolated follower prefix across handoff"
            );
        }
        let reachable = seed_limit.is_none()
            && !fleet.peers[follower]
                .blocked_senders
                .lock()
                .unwrap()
                .contains(&leader.inner.local_node_id);
        if reachable {
            // Exercise the allowed successor-to-follower route before setup
            // restores its original leader. Correct isolation leaves no route
            // that can advance the prefix.
            tokio::time::timeout_at(
                deadline,
                fleet
                    .store(follower)
                    .inner
                    .raft
                    .metrics()
                    .wait_for(|current| current.last_applied.is_some_and(|log| log.index >= last)),
            )
            .await
            .expect("follower observation retains the seed batch deadline")
            .unwrap();
        }
    }
    if last >= target {
        // Observe only initial seeding. Later seed calls intentionally retain
        // the follower behind the held snapshot transfer until recovery.
        let _ = TRACK_LAGGING_FOLLOWER.try_with(|tracked| tracked.set(None));
    }
}

#[cfg(feature = "test-control")]
pub(super) async fn force_seed_handoff(operation: impl std::future::Future<Output = ()>) {
    FORCE_FIRST_BATCH_HANDOFF
        .scope(Cell::new(true), async {
            operation.await;
            assert!(!FORCE_FIRST_BATCH_HANDOFF.with(Cell::get));
        })
        .await;
}

async fn transfer_before(
    fleet: &Fleet,
    source: &ConsensusSessionStore,
    successor: &ConsensusSessionStore,
    deadline: tokio::time::Instant,
    observe_all: bool,
) {
    tokio::time::timeout_at(deadline, async {
        let last = source.inner.raft.metrics().borrow().last_log_index.unwrap();
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
        for target in fleet
            .stores
            .iter()
            .flatten()
            .filter(|store| {
                observe_all
                    && store.inner.local_node_id != source.inner.local_node_id
                    && store.inner.local_node_id != successor.inner.local_node_id
            })
            .chain(std::iter::once(successor))
        {
            let response: Result<
                (),
                RaftError<SessionConsensusNodeId, opc_consensus::engine::raft::TransferLeaderError>,
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
        for store in fleet.stores.iter().flatten() {
            // Some pressure fixtures isolate the third voter's data link.
            // The old and new leader still observe the committed handoff;
            // deterministic injection additionally waits for every voter.
            if !observe_all
                && store.inner.local_node_id != source.inner.local_node_id
                && store.inner.local_node_id != successor.inner.local_node_id
            {
                continue;
            }
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
    })
    .await
    .expect("setup handoff retains its original deadline");
}

pub(super) async fn leader_before(
    fleet: &Fleet,
    hint: Option<SessionConsensusNodeId>,
    rejected: Option<(SessionConsensusNodeId, u64)>,
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
                        && rejected.is_none_or(|(node, term)| {
                            store.inner.local_node_id != node || current.current_term > term
                        }))
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

pub(super) async fn restore_owner_before(
    fleet: &Fleet,
    owner: &ConsensusSessionStore,
    deadline: tokio::time::Instant,
) {
    let leader = leader_before(fleet, Some(owner.inner.local_node_id), None, deadline).await;
    if leader.inner.local_node_id != owner.inner.local_node_id {
        transfer_before(fleet, leader, owner, deadline, false).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_seed_follows_leader_change() {
    let mut fleet = fleet(SessionPersistenceMode::Durable).await;
    let result = AssertUnwindSafe(async {
        let leader = fleet.leader();
        let source = fleet.store(leader);
        let successor = fleet.store((leader + 1) % 3);
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
            transfer_before(&fleet, source, successor, deadline, true).await;
            release.send(()).unwrap();
            seeding.await;
            for store in [source, successor] {
                // Write completion can precede metrics publication. Observe
                // application under the enclosing deadline before checking it.
                let mut metrics = store.inner.raft.metrics();
                let current = metrics
                    .wait_for(|current| current.last_applied.is_some_and(|log| log.index >= target))
                    .await
                    .unwrap()
                    .clone();
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

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_build_seed_handoff_preserves_owner() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    FORCE_FIRST_BATCH_HANDOFF
        .scope(Cell::new(true), async {
            blocked_build(SessionPersistenceMode::Durable, window, 1, false).await;
            assert!(!FORCE_FIRST_BATCH_HANDOFF.with(Cell::get));
        })
        .await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_blocked_transfer_seed_handoff_preserves_owner() {
    let window = DURABLE_OPENRAFT_PROFILE.retained_logs
        + 2 * DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
        + 64;
    FORCE_CONNECTED_HANDOFF
        .scope(
            Cell::new(true),
            TRACK_LAGGING_FOLLOWER.scope(Cell::new(None), async {
                blocked_transfer(SessionPersistenceMode::Durable, window, 1, false).await;
                assert!(!FORCE_CONNECTED_HANDOFF.with(Cell::get));
            }),
        )
        .await;
}
