//! Bound stale application routes by the local engine leader view.

use super::*;
use opc_consensus::engine::RaftMetrics;
use tokio::sync::watch;
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(super) struct LeaderRoute {
    pub(super) target: ConsensusNodeId,
    chosen_under: Option<ConsensusNodeId>,
}

impl LeaderRoute {
    pub(super) fn from_local_view(target: ConsensusNodeId) -> Self {
        Self::redirected(target, Some(target))
    }

    pub(super) fn redirected(
        target: ConsensusNodeId,
        chosen_under: Option<ConsensusNodeId>,
    ) -> Self {
        Self {
            target,
            chosen_under,
        }
    }

    pub(super) fn observe(&mut self, leader: Option<ConsensusNodeId>) -> Option<ConsensusNodeId> {
        if leader == Some(self.target) {
            // Once the local view confirms a redirect, its previous leader
            // no longer exempts the route if that node later leads again.
            self.chosen_under = leader;
        }
        leader.filter(|leader| *leader != self.target && Some(*leader) != self.chosen_under)
    }
}

pub(super) async fn wait_for_retirement(
    mut metrics: watch::Receiver<RaftMetrics<ConsensusNodeId, EmptyNode>>,
    members: &BTreeSet<ConsensusNodeId>,
    mut route: LeaderRoute,
    deadline: Instant,
) -> Result<Option<ConsensusNodeId>, PersistError> {
    loop {
        let leader = metrics
            .borrow_and_update()
            .current_leader
            .filter(|leader| members.contains(leader));
        if route.observe(leader).is_some() {
            break;
        }
        match tokio::time::timeout_at(deadline, metrics.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                // A closed watch cannot establish a successor. The peer call
                // still owns its original absolute deadline.
                tokio::time::sleep_until(deadline).await;
                return Err(consensus_unavailable());
            }
            Err(_) => return Err(consensus_unavailable()),
        }
    }
    // The first observed successor fixes the deadline. Unknown views, leader
    // changes and unrelated metrics cannot renew an already superseded route.
    let grace_deadline = Instant::now()
        .checked_add(DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE)
        .map_or(deadline, |grace| grace.min(deadline));
    tokio::time::sleep_until(grace_deadline).await;
    if Instant::now() >= deadline {
        return Err(consensus_unavailable());
    }
    Ok(metrics
        .borrow()
        .current_leader
        .filter(|leader| members.contains(leader)))
}

#[cfg(test)]
mod tests;
