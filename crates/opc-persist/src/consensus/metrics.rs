use super::{ClusterMembership, ConsensusConfigStore, ConsensusMetricsDump, PeerStatusDump};
use crate::error::PersistError;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

impl ConsensusConfigStore {
    pub async fn update_global_metrics(&self) -> Result<(), PersistError> {
        let state = self.state.lock().await;
        let applied_index = self.inner.consensus_get_applied_index().await?;
        let (last_log_index, _) = self.inner.consensus_get_last_log().await?;
        let membership = self
            .inner
            .consensus_get_active_membership()
            .await?
            .unwrap_or_else(|| ClusterMembership {
                cluster_id: "unknown".to_string(),
                node_id: self.node_id,
                voting_members: vec![],
                non_voting_members: vec![],
                old_voting_members: None,
                removed_members: vec![],
                epoch: 0,
            });

        opc_redaction::metrics::METRICS
            .persist_leader_term
            .store(state.current_term, Ordering::Relaxed);
        opc_redaction::metrics::METRICS
            .persist_commit_index
            .store(state.commit_index, Ordering::Relaxed);
        opc_redaction::metrics::METRICS
            .persist_applied_index
            .store(applied_index, Ordering::Relaxed);

        let snapshot_idx =
            if let Ok(Some((snap_idx, _, _))) = self.inner.consensus_get_snapshot().await {
                snap_idx
            } else {
                0
            };
        opc_redaction::metrics::METRICS
            .persist_snapshot_index
            .store(snapshot_idx, Ordering::Relaxed);

        opc_redaction::metrics::METRICS
            .persist_leader_changes
            .store(
                self.metrics.leader_changes.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        opc_redaction::metrics::METRICS
            .persist_rpc_auth_failures
            .store(
                self.metrics.auth_failures.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        opc_redaction::metrics::METRICS
            .persist_snapshot_install_failures
            .store(
                self.metrics.snapshot_failures.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );

        if let Ok(mut lag_map) = opc_redaction::metrics::METRICS
            .persist_peer_replication_lag
            .lock()
        {
            lag_map.clear();
            for &pid in &membership.voting_members {
                if pid == self.node_id {
                    continue;
                }
                let mat = state.match_index.get(&pid).cloned().unwrap_or(0);
                let lag = last_log_index.saturating_sub(mat);
                lag_map.insert(pid, lag);
            }
        }
        Ok(())
    }

    pub async fn dump_metrics(&self) -> Result<ConsensusMetricsDump, PersistError> {
        let _ = self.update_global_metrics().await;
        let state = self.state.lock().await;
        let applied_index = self.inner.consensus_get_applied_index().await?;
        let (last_log_index, _) = self.inner.consensus_get_last_log().await?;
        let membership = self
            .inner
            .consensus_get_active_membership()
            .await?
            .unwrap_or_else(|| ClusterMembership {
                cluster_id: "unknown".to_string(),
                node_id: self.node_id,
                voting_members: vec![],
                non_voting_members: vec![],
                old_voting_members: None,
                removed_members: vec![],
                epoch: 0,
            });

        let mut peer_status = HashMap::new();
        for &pid in &membership.voting_members {
            if pid == self.node_id {
                continue;
            }
            let next = state.next_index.get(&pid).cloned().unwrap_or(0);
            let mat = state.match_index.get(&pid).cloned().unwrap_or(0);
            let lag = last_log_index.saturating_sub(mat);
            peer_status.insert(
                pid,
                PeerStatusDump {
                    next_index: next,
                    match_index: mat,
                    lag,
                },
            );
        }

        Ok(ConsensusMetricsDump {
            node_id: self.node_id,
            role: format!("{:?}", state.role),
            term: state.current_term,
            commit_index: state.commit_index,
            applied_index,
            last_log_index,
            membership_epoch: membership.epoch,
            election_count: self.metrics.election_count.load(Ordering::Relaxed),
            leader_changes: self.metrics.leader_changes.load(Ordering::Relaxed),
            rpc_failures: self.metrics.rpc_failures.load(Ordering::Relaxed),
            rpc_timeouts: self.metrics.rpc_timeouts.load(Ordering::Relaxed),
            snapshot_installs: self.metrics.snapshot_installs.load(Ordering::Relaxed),
            snapshot_failures: self.metrics.snapshot_failures.load(Ordering::Relaxed),
            read_quorum_failures: self.metrics.read_quorum_failures.load(Ordering::Relaxed),
            write_quorum_failures: self.metrics.write_quorum_failures.load(Ordering::Relaxed),
            auth_failures: self.metrics.auth_failures.load(Ordering::Relaxed),
            membership_change_attempts: self
                .metrics
                .membership_change_attempts
                .load(Ordering::Relaxed),
            membership_change_success: self
                .metrics
                .membership_change_success
                .load(Ordering::Relaxed),
            membership_change_failures: self
                .metrics
                .membership_change_failures
                .load(Ordering::Relaxed),
            server_active_connections: self
                .metrics
                .server_active_connections
                .load(Ordering::Relaxed),
            server_rejected_connections: self
                .metrics
                .server_rejected_connections
                .load(Ordering::Relaxed),
            server_shutdown_failures: self
                .metrics
                .server_shutdown_failures
                .load(Ordering::Relaxed),
            server_start_failures: self.metrics.server_start_failures.load(Ordering::Relaxed),
            peer_status,
        })
    }
}
