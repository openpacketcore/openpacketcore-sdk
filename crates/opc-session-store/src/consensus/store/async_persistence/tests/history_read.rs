//! A fresh history classification needs a quorum read, not a native WAL flush.

use super::*;
use crate::sqlite::consensus::wal::{owner::IoHookForTest, Point};
use std::sync::Condvar;

const PHYSICAL_ATTEMPT_CAP: Duration = Duration::from_millis(250);

mod preparation;

/// Delay the ordinary durable data-sync boundary, after warm activation.
/// The hook is installed before each real native owner is constructed.
struct NativeSyncDelay {
    armed: Mutex<bool>,
    release: Condvar,
    entered: tokio::sync::watch::Sender<BTreeSet<usize>>,
}

impl NativeSyncDelay {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            armed: Mutex::new(false),
            release: Condvar::new(),
            entered: tokio::sync::watch::Sender::default(),
        })
    }

    fn hook(self: &Arc<Self>, voter: usize) -> IoHookForTest {
        let delay = Arc::clone(self);
        Arc::new(move |point| {
            if point != Point::BeforeDataSync {
                return Ok(());
            }
            let mut armed = delay.armed.lock().unwrap();
            if *armed {
                delay.entered.send_modify(|entered| {
                    entered.insert(voter);
                });
            }
            while *armed {
                let (next, watchdog) = delay
                    .release
                    .wait_timeout(armed, Duration::from_secs(30))
                    .unwrap();
                armed = next;
                if watchdog.timed_out() && *armed {
                    return Err(std::io::Error::other("native sync test release missing"));
                }
            }
            Ok(())
        })
    }

    fn arm(self: &Arc<Self>) -> NativeSyncRelease {
        let mut armed = self.armed.lock().unwrap();
        assert!(!*armed);
        self.entered.send_replace(BTreeSet::new());
        *armed = true;
        NativeSyncRelease(Arc::clone(self))
    }

    async fn wait_entered(&self, voter: usize) {
        let mut entered = self.entered.subscribe();
        clock::watchdog(
            entered.wait_for(|entered| entered.contains(&voter)),
            "ordinary mutation must reach the real native data-sync hook",
        )
        .await
        .unwrap();
    }
}

struct NativeSyncRelease(Arc<NativeSyncDelay>);

impl Drop for NativeSyncRelease {
    fn drop(&mut self) {
        *self.0.armed.lock().unwrap() = false;
        self.0.release.notify_all();
    }
}

/// Hold real inbound requests before dispatch, preserving cancellation.
pub(super) struct RequestHold {
    released: tokio::sync::watch::Sender<bool>,
    entered: tokio::sync::watch::Sender<bool>,
    after_commit: Option<u64>,
}

impl RequestHold {
    pub(super) async fn wait(&self, request: &SessionConsensusWireRequest) {
        if let Some(index) = self.after_commit {
            if request.family != SessionConsensusRpcFamily::AppendEntries {
                return;
            }
            let append: AppendEntriesRequest<SessionRaftTypeConfig> =
                decode_bounded(&request.payload).expect("ordinary durable AppendEntries");
            if !append
                .leader_commit
                .is_some_and(|log_id| log_id.index > index)
            {
                return;
            }
        }
        let mut released = self.released.subscribe();
        if !*released.borrow_and_update() {
            self.entered.send_replace(true);
            released.wait_for(|released| *released).await.unwrap();
        }
    }
}

struct RequestRelease {
    peer: Arc<Peer>,
    hold: Arc<RequestHold>,
}

impl RequestRelease {
    fn new(peer: &Arc<Peer>) -> Self {
        Self::after_commit(peer, None)
    }

    fn after_commit(peer: &Arc<Peer>, after_commit: Option<u64>) -> Self {
        let hold = Arc::new(RequestHold {
            released: tokio::sync::watch::Sender::new(false),
            entered: tokio::sync::watch::Sender::new(false),
            after_commit,
        });
        assert!(peer
            .held_requests
            .lock()
            .unwrap()
            .replace(Arc::clone(&hold))
            .is_none());
        Self {
            peer: Arc::clone(peer),
            hold,
        }
    }

    async fn wait_entered(&self) {
        let mut entered = self.hold.entered.subscribe();
        clock::watchdog(
            entered.wait_for(|entered| *entered),
            "the held minority must receive an actual quorum request",
        )
        .await
        .unwrap();
    }
}

impl Drop for RequestRelease {
    fn drop(&mut self) {
        self.hold.released.send_replace(true);
        self.peer.held_requests.lock().unwrap().take();
    }
}

async fn open_durable(fleet: &mut Fleet, delay: &Arc<NativeSyncDelay>) {
    for voter in 0..3 {
        fleet
            .open_with_all_hooks(
                voter,
                SessionPersistenceMode::Durable,
                None,
                None,
                Some(delay.hook(voter)),
            )
            .await
            .unwrap();
        assert_eq!(
            fleet.store(voter).persistence_mode(),
            SessionPersistenceMode::Durable
        );
        assert!(fleet.store(voter).inner.private_wal.is_some());
    }
    fleet.form().await;
    // Fault phases retain one elected leader. Prevent the isolated minority
    // from starting an unrelated election while its inbound RPCs are held.
    for store in fleet.stores.iter().flatten() {
        store.inner.raft.runtime_config().elect(false);
    }
}

async fn activate_and_warm(fleet: &Fleet) -> FencedTransitionV2HistoryState {
    let leader = fleet.leader();
    let request = create_request(fleet.store(leader), 1, &provider()).await;
    create(fleet.store(leader), &request).await;
    let mut expected = None;
    for voter in 0..3 {
        let store = fleet.store(voter).clone();
        let history = clock::complete(store.inner.operation_timeout, async move {
            store.fenced_transition_v2_history_state().await
        })
        .await
        .unwrap();
        assert_eq!(
            history.active_epoch(),
            Some(FencedTransitionV2HistoryEpoch::new(1).unwrap())
        );
        assert_eq!(history.bound_entries(), 1);
        if let Some(expected) = expected {
            assert_eq!(history, expected);
        }
        expected = Some(history);
        assert!(fleet
            .store(voter)
            .inner
            .backend
            .consensus_fenced_transition_v2_activation_matches_scope(
                fleet.store(voter).inner.storage_identity,
                fleet.store(voter).current_scope().unwrap().0,
                fleet.store(voter).current_scope().unwrap().1,
                fleet
                    .store(voter)
                    .inner
                    .backend
                    .fenced_transition_profile
                    .digest(),
            )
            .await
            .unwrap());
    }
    finish_mutation_preparation(fleet).await;
    expected.unwrap()
}

/// Fence every preparation command before any voter is denied durable sync.
/// Constructing a request observes a fence through a new logical-time command;
/// its local completion does not wait for the followers' commit persistence.
async fn finish_mutation_preparation(fleet: &Fleet) {
    let committed = fleet
        .store(fleet.leader())
        .inner
        .raft
        .metrics()
        .borrow()
        .last_log_index
        .unwrap();
    for store in fleet.stores.iter().flatten() {
        store
            .inner
            .read_barrier
            .wait_for_applied_index(committed, tokio::time::Instant::now() + OPERATION_BOUND)
            .await
            .unwrap();
    }
}

async fn arm_after_preparation(fleet: &Fleet, delay: &Arc<NativeSyncDelay>) -> NativeSyncRelease {
    finish_mutation_preparation(fleet).await;
    delay.arm()
}

async fn history_with_delayed_storage(hold_minority: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let delay = NativeSyncDelay::new();
    let result = AssertUnwindSafe(async {
        open_durable(&mut fleet, &delay).await;
        let expected = activate_and_warm(&fleet).await;
        let leader = fleet.leader();
        let minority = (leader + 1) % 3;
        let healthy_follower = (leader + 2) % 3;
        let held = hold_minority.then(|| RequestRelease::new(&fleet.peers[minority]));
        if !hold_minority {
            for other in [leader, healthy_follower] {
                fleet.set_link(other, minority, false);
                fleet.set_link(minority, other, false);
            }
        }
        let storage_release = delay.arm();
        let before = fleet.store(leader).inner.raft.metrics().borrow().last_log_index;
        // Both a local leader and a healthy follower must classify the same
        // applied scope without appending any new logical-time command.
        let started = std::time::Instant::now();
        let reads = tokio::time::timeout(
            PHYSICAL_ATTEMPT_CAP,
            join_all([leader, healthy_follower].into_iter().map(|voter| {
                fleet.store(voter).fenced_transition_v2_history_state()
            })),
        ).await;
        let elapsed = started.elapsed();
        let entered = delay.entered.borrow().clone();
        let after = fleet.store(leader).inner.raft.metrics().borrow().last_log_index;
        drop(storage_release);
        if let Some(held) = &held {
            held.wait_entered().await;
        }
        drop(held);
        assert!(
            matches!(&reads, Ok(reads) if reads.len() == 2 && reads.iter().all(|read| read.as_ref() == Ok(&expected))),
            "fresh history must fit the original {PHYSICAL_ATTEMPT_CAP:?} physical cap with one minority unavailable; held={hold_minority}, elapsed={elapsed:?}, native_sync_voters={entered:?}, reads={reads:?}",
        );
        assert!(elapsed < PHYSICAL_ATTEMPT_CAP);
        assert!(entered.is_empty(), "history classification must not reach durable sync");
        assert_eq!(after, before, "history classification must not append a consensus command");
    }).catch_unwind().await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_v2_history_read_avoids_native_sync_with_one_held_voter() {
    history_with_delayed_storage(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_v2_history_read_avoids_native_sync_with_one_unavailable_voter() {
    history_with_delayed_storage(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_mutation_waits_for_native_sync_and_completes_after_release() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let delay = NativeSyncDelay::new();
    let result = AssertUnwindSafe(async {
        open_durable(&mut fleet, &delay).await;
        activate_and_warm(&fleet).await;
        let leader = fleet.leader();
        let store = fleet.store(leader);
        let request = create_request(store, 2, &provider()).await;
        let storage_release = arm_after_preparation(&fleet, &delay).await;
        let mut mutation = Box::pin(store.fenced_transition_v2(request.clone()));
        tokio::select! {
            result = &mut mutation => panic!("ordinary durable mutation returned before native sync: {result:?}"),
            () = delay.wait_entered(leader) => {}
        }
        assert!(
            tokio::time::timeout(PHYSICAL_ATTEMPT_CAP, &mut mutation).await.is_err(),
            "the unchanged physical cap must expire while real durable sync is held",
        );
        assert!(delay.entered.borrow().contains(&leader));
        drop(storage_release);
        let outcome = clock::watchdog(mutation, "released native mutation must complete")
            .await.unwrap();
        assert!(outcome.matches_v2_request(&request));
        assert_eq!(outcome.mutation(), FencedTransitionMutationResult::Created);
        assert_eq!(outcome.committed_generation(), Generation::new(1));
        assert_recorded(store, &request, &outcome).await;
    }).catch_unwind().await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_v2_history_read_requires_fresh_quorum_after_cancellation() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let delay = NativeSyncDelay::new();
    let result = AssertUnwindSafe(async {
        open_durable(&mut fleet, &delay).await;
        let expected = activate_and_warm(&fleet).await;
        let leader = fleet.leader();
        let held = (0..3)
            .filter(|voter| *voter != leader)
            .map(|voter| RequestRelease::new(&fleet.peers[voter]))
            .collect::<Vec<_>>();
        let storage_release = delay.arm();
        let store = fleet.store(leader).clone();
        let before = store.inner.raft.metrics().borrow().last_log_index;
        clock::run(async move {
            {
                let read = store.fenced_transition_v2_history_state();
                tokio::pin!(read);
                assert!(futures_util::poll!(read.as_mut()).is_pending());
                tokio::time::advance(PHYSICAL_ATTEMPT_CAP).await;
                assert!(futures_util::poll!(read.as_mut()).is_pending());
                // Dropping this caller must not preserve a successful warm
                // quorum proof or start a detached logical-time proposal.
            }
            let started = tokio::time::Instant::now();
            let read = store.fenced_transition_v2_history_state();
            tokio::pin!(read);
            assert!(futures_util::poll!(read.as_mut()).is_pending());
            tokio::time::advance(OPERATION_BOUND).await;
            assert!(matches!(
                clock::watchdog(read, "history must respect its original deadline").await,
                Err(StoreError::BackendUnavailable(_))
            ));
            assert_eq!(started.elapsed(), OPERATION_BOUND);
        })
        .await;
        assert_eq!(
            fleet
                .store(leader)
                .inner
                .raft
                .metrics()
                .borrow()
                .last_log_index,
            before
        );
        assert!(delay.entered.borrow().is_empty());
        drop(held);
        assert_eq!(
            tokio::time::timeout(
                PHYSICAL_ATTEMPT_CAP,
                fleet.store(leader).fenced_transition_v2_history_state()
            )
            .await
            .unwrap()
            .unwrap(),
            expected
        );
        assert!(delay.entered.borrow().is_empty());
        drop(storage_release);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_v2_history_read_without_activation_requires_every_voter() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let delay = NativeSyncDelay::new();
    let result = AssertUnwindSafe(async {
        open_durable(&mut fleet, &delay).await;
        let leader = fleet.leader();
        let minority = (leader + 1) % 3;
        let store = fleet.store(leader);
        let (identity, members) = store.current_scope().unwrap();
        assert!(!store
            .inner
            .backend
            .consensus_fenced_transition_v2_activation_matches_scope(
                store.inner.storage_identity,
                identity,
                members,
                store.inner.backend.fenced_transition_profile.digest(),
            )
            .await
            .unwrap());
        for voter in 0..3 {
            if voter != minority {
                fleet.set_link(voter, minority, false);
                fleet.set_link(minority, voter, false);
            }
        }
        // A majority is still available for the read index, but a fresh V2
        // capability proof cannot replace the missing voter's acknowledgement.
        assert!(matches!(
            store.fenced_transition_v2_history_state().await,
            Err(StoreError::BackendUnavailable(_))
        ));
        for voter in 0..3 {
            if voter != minority {
                fleet.set_link(voter, minority, true);
                fleet.set_link(minority, voter, true);
            }
        }
        let before = store.inner.raft.metrics().borrow().last_log_index;
        let history = store.fenced_transition_v2_history_state().await.unwrap();
        assert_eq!(
            history.active_epoch(),
            Some(FencedTransitionV2HistoryEpoch::new(1).unwrap())
        );
        assert_eq!(history.bound_entries(), 0);
        assert_eq!(store.inner.raft.metrics().borrow().last_log_index, before);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_v2_history_read_rechecks_local_and_durable_authority() {
    use crate::sqlite::consensus::{ensure_operator_recovery_latch_sync, OperatorRecoveryLatch};

    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let delay = NativeSyncDelay::new();
    let result = AssertUnwindSafe(async {
        open_durable(&mut fleet, &delay).await;
        let expected = activate_and_warm(&fleet).await;
        let follower = (fleet.leader() + 1) % 3;
        let store = fleet.store(follower);
        let before = store.inner.raft.metrics().borrow().last_log_index;
        store.inner.admitted.store(false, Ordering::Release);
        let refused = store.fenced_transition_v2_history_state().await;
        store.inner.admitted.store(true, Ordering::Release);
        assert!(matches!(refused, Err(StoreError::BackendUnavailable(_))));
        assert_eq!(
            store.fenced_transition_v2_history_state().await.unwrap(),
            expected
        );

        ensure_operator_recovery_latch_sync(
            &fleet
                .directory
                .path()
                .join(format!("node-{follower}.sqlite")),
            OperatorRecoveryLatch {
                identity: store.inner.storage_identity,
                recovery_epoch: 1,
                plan_digest: [0x32; 32],
                audit_pending: false,
            },
        )
        .unwrap();
        assert!(matches!(
            store.fenced_transition_v2_history_state().await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert_eq!(store.inner.raft.metrics().borrow().last_log_index, before);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_v2_history_read_waits_for_the_followers_committed_history() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let delay = NativeSyncDelay::new();
    let result = AssertUnwindSafe(async {
        open_durable(&mut fleet, &delay).await;
        let previous = activate_and_warm(&fleet).await;
        let leader = fleet.leader();
        let follower = (leader + 1) % 3;
        let request = create_request(fleet.store(leader), 3, &provider()).await;
        let held = RequestRelease::new(&fleet.peers[follower]);
        create(fleet.store(leader), &request).await;
        let expected = fleet
            .store(leader)
            .fenced_transition_v2_history_state()
            .await
            .unwrap();
        assert_eq!(expected.bound_entries(), previous.bound_entries() + 1);
        let committed = fleet
            .store(leader)
            .inner
            .raft
            .metrics()
            .borrow()
            .last_applied
            .unwrap()
            .index;
        assert!(
            fleet
                .store(follower)
                .inner
                .raft
                .metrics()
                .borrow()
                .last_applied
                .unwrap()
                .index
                < committed
        );
        let before = fleet
            .store(leader)
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index;
        let read = fleet.store(follower).fenced_transition_v2_history_state();
        tokio::pin!(read);
        assert!(
            tokio::time::timeout(PHYSICAL_ATTEMPT_CAP, read.as_mut())
                .await
                .is_err(),
            "the follower must not expose its older history before applying the read index"
        );
        held.wait_entered().await;
        drop(held);
        assert_eq!(
            clock::watchdog(read, "released follower must apply committed history")
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            fleet
                .store(leader)
                .inner
                .raft
                .metrics()
                .borrow()
                .last_log_index,
            before
        );
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
