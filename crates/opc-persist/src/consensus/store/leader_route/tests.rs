use super::*;
use crate::PersistErrorKind;
use opc_consensus::engine::RaftMetrics;
use std::task::Poll;
use tokio::sync::watch;
use tokio::time::Instant;

fn node(value: u64) -> ConsensusNodeId {
    ConsensusNodeId::new(value).unwrap()
}

async fn observed_successor_does_not_renew_retirement(next: Option<ConsensusNodeId>) {
    let members = [node(1), node(2), node(3)].into_iter().collect();
    let mut initial = RaftMetrics::new_initial(node(3));
    initial.current_leader = Some(node(1));
    let (view, metrics) = watch::channel(initial);
    let deadline = Instant::now() + Duration::from_secs(3);
    let retirement = wait_for_retirement(
        metrics,
        &members,
        LeaderRoute::from_local_view(node(1)),
        deadline,
    );
    tokio::pin!(retirement);
    assert!(futures_util::poll!(&mut retirement).is_pending());
    view.send_modify(|metrics| metrics.current_leader = Some(node(2)));
    assert!(futures_util::poll!(&mut retirement).is_pending());
    tokio::time::advance(DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE / 2).await;
    view.send_modify(|metrics| metrics.current_leader = next);
    assert!(futures_util::poll!(&mut retirement).is_pending());
    tokio::time::advance(DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE / 2).await;
    let Poll::Ready(result) = futures_util::poll!(&mut retirement) else {
        panic!("the first observed successor fixes an absolute retirement deadline");
    };
    assert_eq!(result.unwrap(), next);
}

#[tokio::test(start_paused = true)]
async fn unknown_view_does_not_renew_an_observed_route_retirement() {
    observed_successor_does_not_renew_retirement(None).await;
}

#[tokio::test(start_paused = true)]
async fn another_successor_does_not_renew_an_observed_route_retirement() {
    observed_successor_does_not_renew_retirement(Some(node(3))).await;
}

#[test]
fn redirect_retains_its_old_view_until_local_confirmation() {
    let mut route = LeaderRoute::redirected(node(2), Some(node(1)));
    assert_eq!(route.observe(Some(node(1))), None);
    assert_eq!(route.observe(None), None);
    assert_eq!(route.observe(Some(node(2))), None);
    assert_eq!(route.observe(Some(node(1))), Some(node(1)));
}

#[tokio::test(start_paused = true)]
async fn retirement_cannot_extend_the_operation_deadline() {
    let members = [node(1), node(2), node(3)].into_iter().collect();
    let mut initial = RaftMetrics::new_initial(node(3));
    initial.current_leader = Some(node(2));
    let (_view, metrics) = watch::channel(initial);
    let remaining = DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE / 2;
    let deadline = Instant::now() + remaining;
    let result = wait_for_retirement(
        metrics,
        &members,
        LeaderRoute::from_local_view(node(1)),
        deadline,
    )
    .await;
    assert!(matches!(
        result.unwrap_err().kind(),
        PersistErrorKind::Unavailable
    ));
    assert_eq!(Instant::now(), deadline);
}
