use super::{AppendEntriesRequest, ConsensusConfigStore, ConsensusPeer, Role};
use crate::error::PersistError;
use std::sync::atomic::Ordering;
use std::sync::Arc;

impl ConsensusConfigStore {
    pub async fn verify_leadership(&self) -> Result<(), PersistError> {
        let res = self.verify_leadership_inner().await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .persist_quorum_read_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .persist_quorum_read_failure
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    async fn verify_leadership_inner(&self) -> Result<(), PersistError> {
        if let Err(e) = self.wait_for_no_op_commit().await {
            self.metrics
                .read_quorum_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        let (term, leader_commit) = {
            let state = self.state.lock().await;
            if state.role != Role::Leader {
                return Err(PersistError::inconsistent_state("not the leader"));
            }
            (state.current_term, state.commit_index)
        };

        let membership = self
            .inner
            .consensus_get_active_membership()
            .await?
            .ok_or_else(|| PersistError::inconsistent_state("membership not found"))?;

        let quorum = (membership.voting_members.len() / 2) + 1;
        let mut success_count = 0;
        if membership.voting_members.contains(&self.node_id) {
            success_count += 1;
        }

        if success_count >= quorum {
            return Ok(());
        }

        let peers = {
            let peers_guard = self.peers.read().await;
            peers_guard
                .values()
                .cloned()
                .collect::<Vec<Arc<dyn ConsensusPeer>>>()
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(peers.len() + 1);
        for peer in peers {
            let pid = peer.node_id();
            if !membership.voting_members.contains(&pid) {
                continue;
            }
            if self.is_partitioned(pid).await {
                continue;
            }

            let (last_log_idx, last_log_term) = self
                .inner
                .consensus_get_last_log()
                .await
                .unwrap_or_default();
            let req = AppendEntriesRequest {
                term,
                leader_id: self.node_id,
                prev_log_index: last_log_idx,
                prev_log_term: last_log_term,
                entries: vec![],
                leader_commit,
            };
            let peer = Arc::clone(&peer);
            let tx = tx.clone();
            tokio::spawn(async move {
                let res = peer.append_entries(req).await;
                let _ = tx.send((pid, res)).await;
            });
        }
        drop(tx);

        while let Some((_pid, res)) = rx.recv().await {
            if let Ok(resp) = res {
                if resp.term > term {
                    let mut s = self.state.lock().await;
                    if resp.term > s.current_term {
                        s.current_term = resp.term;
                        s.voted_for = None;
                        s.role = Role::Follower;
                        s.leader_id = None;
                        let _ = self
                            .inner
                            .consensus_set_state(s.current_term, s.voted_for)
                            .await;
                    }
                    self.metrics
                        .read_quorum_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(PersistError::inconsistent_state("peer has newer term"));
                }
                if resp.term == term && resp.success {
                    success_count += 1;
                    if success_count >= quorum {
                        return Ok(());
                    }
                }
            }
        }

        if success_count >= quorum {
            Ok(())
        } else {
            self.metrics
                .read_quorum_failures
                .fetch_add(1, Ordering::Relaxed);
            Err(PersistError::io("lost leader quorum"))
        }
    }
}
