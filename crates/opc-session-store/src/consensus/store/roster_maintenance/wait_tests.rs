use super::*;
use futures_util::poll;
use opc_consensus::engine::{RaftMetrics, Vote};
use std::task::Poll;

fn metrics() -> RaftMetrics<SessionConsensusNodeId, EmptyNode> {
    let node = SessionConsensusNodeId::new(1).unwrap();
    let mut metrics = RaftMetrics::new_initial(node);
    metrics.current_term = 1;
    metrics.vote = Vote::new_committed(1, node);
    metrics.current_leader = Some(node);
    metrics
}

#[tokio::test(start_paused = true)]
async fn production_wait_keeps_its_deadline_through_commits_and_heartbeats() {
    let (_stop, stop) = tokio::sync::watch::channel(false);
    let (publications, metrics) = tokio::sync::watch::channel(metrics());
    let leadership = std::sync::Mutex::new(None);
    let started = tokio::time::Instant::now();
    let mut wait = Box::pin(wait_roster_maintenance(
        Duration::from_secs(1),
        stop,
        metrics,
        &leadership,
    ));
    assert!(poll!(wait.as_mut()).is_pending());
    for step in 1..=10 {
        tokio::time::advance(Duration::from_millis(100)).await;
        publications.send_modify(|metrics| {
            metrics.last_log_index = Some(step);
            metrics.last_applied = Some(LogId::new(
                opc_consensus::engine::CommittedLeaderId::new(1, metrics.id),
                step,
            ));
            metrics.millis_since_quorum_ack = Some(step % 2);
        });
        if step < 10 {
            assert!(poll!(wait.as_mut()).is_pending());
        } else {
            assert_eq!(poll!(wait.as_mut()), Poll::Ready(true));
        }
    }
    assert_eq!(started.elapsed(), Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn production_wait_wakes_for_each_leader_or_term_change() {
    for change_term in [false, true] {
        let (_stop, stop) = tokio::sync::watch::channel(false);
        let (publications, metrics) = tokio::sync::watch::channel(metrics());
        let leadership = std::sync::Mutex::new(None);
        let started = tokio::time::Instant::now();
        let mut wait = Box::pin(wait_roster_maintenance(
            Duration::from_secs(1),
            stop,
            metrics,
            &leadership,
        ));
        assert!(poll!(wait.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(100)).await;
        publications.send_modify(|metrics| {
            if change_term {
                metrics.current_term = 2;
                metrics.vote = Vote::new_committed(2, metrics.id);
            } else {
                metrics.current_leader = Some(SessionConsensusNodeId::new(2).unwrap());
            }
        });
        assert_eq!(poll!(wait.as_mut()), Poll::Ready(true));
        assert_eq!(started.elapsed(), Duration::from_millis(100));
    }
}

#[tokio::test(start_paused = true)]
async fn production_wait_honors_zero_delay_and_stop_without_advancing_time() {
    let (shutdown, stop) = tokio::sync::watch::channel(false);
    let (_publications, metrics) = tokio::sync::watch::channel(metrics());
    let leadership = std::sync::Mutex::new(None);
    let started = tokio::time::Instant::now();
    assert!(
        wait_roster_maintenance(Duration::ZERO, stop.clone(), metrics.clone(), &leadership,).await
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    let mut wait = Box::pin(wait_roster_maintenance(
        Duration::from_secs(1),
        stop.clone(),
        metrics.clone(),
        &leadership,
    ));
    assert!(poll!(wait.as_mut()).is_pending());
    shutdown.send_replace(true);
    assert_eq!(poll!(wait.as_mut()), Poll::Ready(false));
    assert!(!wait_roster_maintenance(Duration::ZERO, stop, metrics, &leadership,).await);
    assert_eq!(started.elapsed(), Duration::ZERO);
}
