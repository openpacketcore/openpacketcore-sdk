use super::{ConsensusConfigStore, ConsensusOp, Role};
use crate::error::PersistError;
use std::sync::atomic::Ordering;
use tracing::debug;

impl ConsensusConfigStore {
    pub async fn add_node_as_non_voter(&self, peer_id: usize) -> Result<(), PersistError> {
        self.metrics
            .membership_change_attempts
            .fetch_add(1, Ordering::Relaxed);
        let res = self.add_node_as_non_voter_inner(peer_id).await;
        if res.is_ok() {
            self.metrics
                .membership_change_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .membership_change_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    async fn add_node_as_non_voter_inner(&self, peer_id: usize) -> Result<(), PersistError> {
        let state = self.state.lock().await;
        if state.role != Role::Leader {
            return Err(PersistError::inconsistent_state(
                "only the leader can change membership",
            ));
        }

        let mut membership = self
            .inner
            .consensus_get_active_membership()
            .await?
            .ok_or_else(|| PersistError::inconsistent_state("membership not found"))?;

        if membership.removed_members.contains(&peer_id) {
            return Err(PersistError::inconsistent_state(
                "cannot add a removed/tombstoned member",
            ));
        }

        if membership.voting_members.contains(&peer_id)
            || membership.non_voting_members.contains(&peer_id)
        {
            return Err(PersistError::inconsistent_state("node already in cluster"));
        }

        membership.non_voting_members.push(peer_id);
        membership.epoch += 1;

        drop(state);

        let op = ConsensusOp::ChangeMembership { membership };
        self.replicate_and_commit(op).await
    }

    pub async fn promote_node(&self, peer_id: usize) -> Result<(), PersistError> {
        self.metrics
            .membership_change_attempts
            .fetch_add(1, Ordering::Relaxed);
        let res = self.promote_node_inner(peer_id).await;
        if res.is_ok() {
            self.metrics
                .membership_change_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .membership_change_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    async fn promote_node_inner(&self, peer_id: usize) -> Result<(), PersistError> {
        let state = self.state.lock().await;
        if state.role != Role::Leader {
            return Err(PersistError::inconsistent_state(
                "only the leader can change membership",
            ));
        }

        let membership = self
            .inner
            .consensus_get_active_membership()
            .await?
            .ok_or_else(|| PersistError::inconsistent_state("membership not found"))?;

        if !membership.non_voting_members.contains(&peer_id) {
            return Err(PersistError::inconsistent_state("node is not a non-voter"));
        }

        let last_log_idx = self.inner.consensus_get_last_log().await?.0;
        let match_idx = state.match_index.get(&peer_id).cloned().unwrap_or(0);
        let lag = last_log_idx.saturating_sub(match_idx);
        if lag > 0 {
            return Err(PersistError::inconsistent_state("node is not caught up"));
        }

        // Phase 1: Joint configuration C_old,new
        let mut joint_membership = membership.clone();
        joint_membership.old_voting_members = Some(membership.voting_members.clone());
        joint_membership
            .non_voting_members
            .retain(|&id| id != peer_id);
        joint_membership.voting_members.push(peer_id);
        joint_membership.epoch += 1;

        drop(state);

        let op = ConsensusOp::ChangeMembership {
            membership: joint_membership.clone(),
        };
        self.replicate_and_commit(op).await
    }

    pub async fn remove_node(&self, peer_id: usize) -> Result<(), PersistError> {
        self.metrics
            .membership_change_attempts
            .fetch_add(1, Ordering::Relaxed);
        let res = self.remove_node_inner(peer_id).await;
        if res.is_ok() {
            self.metrics
                .membership_change_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .membership_change_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    async fn remove_node_inner(&self, peer_id: usize) -> Result<(), PersistError> {
        let state = self.state.lock().await;
        if state.role != Role::Leader {
            return Err(PersistError::inconsistent_state(
                "only the leader can change membership",
            ));
        }

        if peer_id == self.node_id {
            return Err(PersistError::inconsistent_state(
                "cannot remove the leader directly",
            ));
        }

        let mut membership = self
            .inner
            .consensus_get_active_membership()
            .await?
            .ok_or_else(|| PersistError::inconsistent_state("membership not found"))?;

        let is_voter = membership.voting_members.contains(&peer_id);
        let is_non_voter = membership.non_voting_members.contains(&peer_id);

        if !is_voter && !is_non_voter {
            return Err(PersistError::inconsistent_state("node not in cluster"));
        }

        if is_voter {
            let remaining_voters = membership
                .voting_members
                .iter()
                .filter(|&&id| id != peer_id)
                .count();
            if remaining_voters == 0 {
                return Err(PersistError::inconsistent_state(
                    "cannot remove all voting members",
                ));
            }
        }

        if is_voter {
            // Phase 1: Joint configuration C_old,new
            let mut joint_membership = membership.clone();
            joint_membership.old_voting_members = Some(membership.voting_members.clone());
            joint_membership.voting_members.retain(|&id| id != peer_id);
            joint_membership
                .non_voting_members
                .retain(|&id| id != peer_id);
            if !joint_membership.removed_members.contains(&peer_id) {
                joint_membership.removed_members.push(peer_id);
            }
            joint_membership.epoch += 1;

            drop(state);

            let op = ConsensusOp::ChangeMembership {
                membership: joint_membership.clone(),
            };
            self.replicate_and_commit(op).await
        } else {
            // Single-phase transition for non-voter removal
            membership.non_voting_members.retain(|&id| id != peer_id);
            if !membership.removed_members.contains(&peer_id) {
                membership.removed_members.push(peer_id);
            }
            membership.epoch += 1;

            drop(state);

            let op = ConsensusOp::ChangeMembership { membership };
            self.replicate_and_commit(op).await
        }
    }

    #[allow(dead_code)]
    async fn wait_for_membership_finalization(
        &self,
        expected_epoch: u64,
    ) -> Result<(), PersistError> {
        let start = std::time::Instant::now();
        loop {
            if let Ok(Some(current_m)) = self.inner.consensus_get_membership().await {
                debug!(
                    node_id = self.node_id,
                    epoch = current_m.epoch,
                    old_voting_members = ?current_m.old_voting_members,
                    expected_epoch,
                    "waiting for joint consensus finalization"
                );
                if current_m.old_voting_members.is_none() && current_m.epoch >= expected_epoch {
                    return Ok(());
                }
            }
            if start.elapsed() > std::time::Duration::from_secs(15) {
                return Err(PersistError::inconsistent_state(
                    "timeout waiting for joint consensus finalization",
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}
