//! A forward stalled on a lost leader must reroute once a successor is known.
//!
//! A crashed process refuses connections, but a failed node or a partition
//! can black-hole an established connection instead. The follower's forward to
//! the lost leader then receives no answer at all, so only the follower's own
//! view of the elected successor can release it before the caller's deadline.

use super::*;

/// Far beyond the operation deadline: the black-holed route never answers
/// within one operation.
const BLACKHOLE: Duration = Duration::from_secs(60);

#[tokio::test]
async fn blackholed_leader_forward_reroutes_within_the_unplanned_loss_write_stall() {
    let _timing_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("qualification semaphore remains open");
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let (leader, leader_id, term) = cluster.observed_leader();
    let follower = (0..MEMBER_COUNT)
        .find(|index| *index != leader)
        .expect("a surviving follower");
    let other = (0..MEMBER_COUNT)
        .find(|index| *index != leader && *index != follower)
        .expect("a second survivor");

    // The follower's route to the leader accepts every call but never answers
    // within the operation. Every other path to or from the leader fails, so
    // the survivors stop hearing from it and elect a successor.
    cluster
        .paths
        .get(&(follower, leader))
        .expect("follower to leader path")
        .delay_calls(BLACKHOLE);
    for (source, target) in [(leader, follower), (leader, other), (other, leader)] {
        cluster
            .paths
            .get(&(source, target))
            .expect("leader path")
            .set_enabled(false);
    }

    let started = Instant::now();
    let key = session_key(b"blackholed-leader-forward");
    let acquired = tokio::time::timeout(
        DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT + Duration::from_secs(5),
        cluster.stores[follower].acquire(
            &key,
            owner("blackholed-leader-owner"),
            Duration::from_secs(30),
        ),
    )
    .await
    .expect("the store bounds the write by its own operation deadline");
    let elapsed = started.elapsed();
    let bound = DURABLE_CONSENSUS_TIMING_PROFILE.unplanned_leader_loss_write_stall();
    assert!(
        cluster
            .paths
            .get(&(follower, leader))
            .expect("follower to leader path")
            .forward_mutation_calls()
            > 0,
        "the write must first be forwarded into the black-holed leader route"
    );
    let lease = acquired.unwrap_or_else(|error| {
        panic!(
            "a write held on a black-holed lost leader must reroute to its successor; \
             it failed after {}ms: {error:?}",
            elapsed.as_millis()
        )
    });
    assert!(
        elapsed <= bound,
        "a write held on a black-holed lost leader took {}ms, above the documented \
         {}ms unplanned leader-loss write stall",
        elapsed.as_millis(),
        bound.as_millis()
    );

    let survivors = [follower, other];
    let statuses = survivors
        .iter()
        .map(|index| cluster.stores[*index].status())
        .collect::<Vec<_>>();
    assert!(
        statuses.iter().all(|status| status.term > term
            && status.leader_id.is_some_and(|leader| leader != leader_id)),
        "the surviving majority serves a successor in a later term: {statuses:?}"
    );
    let record = sealed_record(key.clone(), 1, &lease, b"sealed-after-reroute");
    assert_eq!(
        CompareAndSetResult::Success,
        cluster.stores[other]
            .compare_and_set(CompareAndSet {
                key,
                lease,
                expected_generation: None,
                new_record: record,
            })
            .await
            .expect("the lease admitted after the reroute fences a later write")
    );
}
