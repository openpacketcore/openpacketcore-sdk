//! Request construction must finish on all voters before holding native sync.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_preparation_commit_cannot_consume_the_mutations_sync_hold() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let delay = NativeSyncDelay::new();
    let result = AssertUnwindSafe(async {
        open_durable(&mut fleet, &delay).await;
        activate_and_warm(&fleet).await;
        let leader = fleet.leader();
        let store = fleet.store(leader);
        let before = store.inner.raft.metrics().borrow().clone();
        let warm_index = before.last_applied.unwrap().index;
        let followers = (0..3).filter(|voter| *voter != leader).collect::<Vec<_>>();
        // Allow the new entry to replicate, but pause the subsequent messages
        // advertising its commit. The leader can finish request construction
        // while both followers still owe that preparation entry's durable cut.
        let held = followers
            .iter()
            .map(|voter| RequestRelease::after_commit(&fleet.peers[*voter], Some(warm_index)))
            .collect::<Vec<_>>();
        let request = create_request(store, 2, &provider()).await;
        join_all(held.iter().map(RequestRelease::wait_entered)).await;
        let prepared_index = store.inner.raft.metrics().borrow().last_applied.unwrap().index;
        assert!(prepared_index > warm_index, "request construction appends logical time");
        for voter in &followers {
            assert_eq!(
                fleet.store(*voter).inner.raft.metrics().borrow().last_applied.unwrap().index,
                warm_index,
                "the controlled preparation commit has not reached a follower",
            );
        }

        let preparing = async {
            finish_mutation_preparation(&fleet).await;
            delay.arm()
        };
        tokio::pin!(preparing);
        // Poll the actual fixture boundary once. An unsafe immediate arm will
        // trap the old follower commits when their network hold is released.
        let first = futures_util::poll!(preparing.as_mut());
        drop(held);
        let storage_release = match first {
            std::task::Poll::Ready(release) => {
                join_all(followers.iter().map(|voter| delay.wait_entered(*voter))).await;
                release
            }
            std::task::Poll::Pending => preparing.await,
        };
        assert!(!delay.entered.borrow().contains(&leader));
        let mut mutation = Box::pin(store.fenced_transition_v2(request.clone()));
        tokio::select! {
            result = &mut mutation => {
                let after = store.inner.raft.metrics().borrow().clone();
                eprintln!(
                    "history_preparation leader_unchanged={} term_unchanged={} preparation_index={prepared_index} last_log_index={:?} native_sync_voters={:?} result={result:?}",
                    after.current_leader == before.current_leader,
                    after.current_term == before.current_term,
                    after.last_log_index,
                    *delay.entered.borrow(),
                );
                panic!("ordinary durable mutation returned before native sync: {result:?}");
            }
            () = delay.wait_entered(leader) => {}
        }
        assert!(
            tokio::time::timeout(PHYSICAL_ATTEMPT_CAP, &mut mutation).await.is_err(),
            "the unchanged physical cap must expire while real durable sync is held",
        );
        assert!(delay.entered.borrow().contains(&leader));
        drop(storage_release);
        let outcome = clock::watchdog(mutation, "released native mutation must complete")
            .await
            .unwrap();
        assert!(outcome.matches_v2_request(&request));
        assert_eq!(outcome.mutation(), FencedTransitionMutationResult::Created);
        assert_eq!(outcome.committed_generation(), Generation::new(1));
        assert_recorded(store, &request, &outcome).await;
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
