use super::{
    ConsensusConfigStore, ConsensusMetrics, ConsensusNodeState, ConsensusOp, ConsensusPeer,
    LogEntry, RequestVoteRequest, RequestVoteResponse, Role, TimeoutNowRequest, TimeoutNowResponse,
};
use crate::backend::SqliteBackend;
use crate::error::PersistError;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

impl ConsensusConfigStore {
    pub async fn force_campaign(&self) -> Result<(), PersistError> {
        self.campaign().await
    }

    pub async fn campaign(&self) -> Result<(), PersistError> {
        Self::campaign_static(
            Arc::clone(&self.inner),
            Arc::clone(&self.peers),
            Arc::clone(&self.state),
            Arc::clone(&self.commit_notifier),
            self.node_id,
            Arc::clone(&self.metrics),
        )
        .await
    }

    pub async fn campaign_static(
        inner: Arc<SqliteBackend>,
        peers: Arc<RwLock<std::collections::HashMap<usize, Arc<dyn ConsensusPeer>>>>,
        state: Arc<Mutex<ConsensusNodeState>>,
        commit_notifier: Arc<tokio::sync::Notify>,
        node_id: usize,
        metrics: Arc<ConsensusMetrics>,
    ) -> Result<(), PersistError> {
        let membership = inner
            .consensus_get_active_membership()
            .await?
            .ok_or_else(|| PersistError::inconsistent_state("membership not found"))?;

        if !membership.voting_members.contains(&node_id) {
            return Err(PersistError::inconsistent_state(
                "Non-voting member cannot campaign",
            ));
        }

        metrics.election_count.fetch_add(1, Ordering::Relaxed);
        let (req, peer_list) = {
            let mut s = state.lock().await;
            if !s.online {
                return Err(PersistError::io("node offline"));
            }
            s.role = Role::Candidate;
            s.current_term += 1;
            s.voted_for = Some(node_id);
            s.leader_id = None;
            s.last_contact = Instant::now();

            inner
                .consensus_set_state(s.current_term, s.voted_for)
                .await?;

            let (last_index, last_term) = inner.consensus_get_last_log().await?;
            let req = RequestVoteRequest {
                term: s.current_term,
                candidate_id: node_id,
                last_log_index: last_index,
                last_log_term: last_term,
            };

            let peers_guard = peers.read().await;
            let peer_list: Vec<Arc<dyn ConsensusPeer>> = peers_guard.values().cloned().collect();
            (req, peer_list)
        };

        let quorum = (membership.voting_members.len() / 2) + 1;
        let mut votes = 0;
        if membership.voting_members.contains(&node_id) {
            votes += 1; // Vote for self
        }

        for peer in peer_list {
            let pid = peer.node_id();
            if !membership.voting_members.contains(&pid) {
                continue;
            }
            // If partitioned, skip sending vote request
            {
                let s = state.lock().await;
                if s.partitioned_peers.contains(&pid) {
                    continue;
                }
            }
            if let Ok(resp) = peer.request_vote(req.clone()).await {
                if resp.vote_granted {
                    votes += 1;
                } else {
                    let mut s = state.lock().await;
                    if resp.term > s.current_term {
                        s.current_term = resp.term;
                        s.voted_for = None;
                        s.role = Role::Follower;
                        s.leader_id = None;
                        inner
                            .consensus_set_state(s.current_term, s.voted_for)
                            .await?;
                        return Err(PersistError::inconsistent_state("peer has newer term"));
                    }
                }
            }
        }

        let mut s = state.lock().await;
        if s.role == Role::Candidate && s.current_term == req.term {
            if votes >= quorum {
                s.role = Role::Leader;
                s.leader_id = Some(node_id);
                metrics.leader_changes.fetch_add(1, Ordering::Relaxed);

                let (last_log_index, _) = inner.consensus_get_last_log().await?;
                let entry = LogEntry {
                    index: last_log_index + 1,
                    term: s.current_term,
                    op: ConsensusOp::NoOp,
                };
                inner
                    .consensus_append_logs(last_log_index, vec![entry.clone()])
                    .await?;

                let new_last_log_index = entry.index;
                s.next_index.clear();
                s.match_index.clear();
                let peer_ids = {
                    let guard = peers.read().await;
                    guard.keys().cloned().collect::<Vec<usize>>()
                };
                for pid in peer_ids {
                    s.next_index.insert(pid, new_last_log_index + 1);
                    s.match_index.insert(pid, 0);
                }

                debug!(node_id = node_id, term = s.current_term, "became leader");

                drop(s);

                let _ = Self::update_commit_index_static(&inner, &state, &commit_notifier, node_id)
                    .await;
                Self::trigger_replication_static(
                    inner,
                    peers,
                    state,
                    commit_notifier,
                    node_id,
                    Arc::clone(&metrics),
                );
                Ok(())
            } else {
                s.role = Role::Follower;
                s.voted_for = None;
                inner
                    .consensus_set_state(s.current_term, s.voted_for)
                    .await?;
                Err(PersistError::inconsistent_state(
                    "did not reach quorum of votes",
                ))
            }
        } else {
            Err(PersistError::inconsistent_state(
                "election aborted: term or role changed",
            ))
        }
    }

    pub async fn handle_request_vote(
        &self,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, PersistError> {
        let mut state = self.state.lock().await;
        if !state.online {
            return Err(PersistError::io("node offline"));
        }

        if req.term > state.current_term {
            state.current_term = req.term;
            state.voted_for = None;
            state.role = Role::Follower;
            state.leader_id = None;
            self.inner
                .consensus_set_state(state.current_term, state.voted_for)
                .await?;
        }

        if req.term >= state.current_term {
            state.last_contact = Instant::now();
        }

        let mut vote_granted = false;
        if req.term == state.current_term
            && (state.voted_for.is_none() || state.voted_for == Some(req.candidate_id))
        {
            let (last_index, last_term) = self.inner.consensus_get_last_log().await?;
            let log_ok = req.last_log_term > last_term
                || (req.last_log_term == last_term && req.last_log_index >= last_index);

            if log_ok {
                vote_granted = true;
                state.voted_for = Some(req.candidate_id);
                self.inner
                    .consensus_set_state(state.current_term, state.voted_for)
                    .await?;
            }
        }

        Ok(RequestVoteResponse {
            term: state.current_term,
            vote_granted,
        })
    }

    pub async fn handle_timeout_now(
        &self,
        req: TimeoutNowRequest,
    ) -> Result<TimeoutNowResponse, PersistError> {
        let mut state = self.state.lock().await;
        if state.current_term < req.term {
            state.current_term = req.term;
            state.voted_for = None;
            state.role = Role::Follower;
            state.leader_id = None;
            self.inner
                .consensus_set_state(state.current_term, None)
                .await?;
        }

        let store = self.clone();
        tokio::spawn(async move {
            let _ = store.campaign().await;
        });

        Ok(TimeoutNowResponse {
            term: state.current_term,
            success: true,
        })
    }

    pub async fn transfer_leadership(&self, target_node_id: usize) -> Result<(), PersistError> {
        let last_log_index = {
            let (idx, _) = self.inner.consensus_get_last_log().await?;
            idx
        };

        {
            let state = self.state.lock().await;
            if state.role != Role::Leader {
                return Err(PersistError::inconsistent_state("not the leader"));
            }
            let match_idx = state.match_index.get(&target_node_id).cloned().unwrap_or(0);
            if match_idx < last_log_index {
                return Err(PersistError::inconsistent_state(
                    "target node is not caught up",
                ));
            }
        }

        {
            let mut state = self.state.lock().await;
            state.role = Role::Follower;
            state.voted_for = None;
            state.leader_id = None;
            self.inner
                .consensus_set_state(state.current_term, None)
                .await?;
        }

        let peer = {
            let peers = self.peers.read().await;
            peers
                .get(&target_node_id)
                .cloned()
                .ok_or_else(|| PersistError::inconsistent_state("target peer not found"))?
        };

        let req = TimeoutNowRequest {
            term: self.state.lock().await.current_term,
            candidate_id: target_node_id,
        };
        let _ = peer.timeout_now(req).await?;

        Ok(())
    }
}
