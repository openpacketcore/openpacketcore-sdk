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
        let (last_log_idx, last_log_term) = self.inner.consensus_get_last_log().await?;

        // Keep ownership of every quorum probe. `JoinSet` aborts unfinished
        // requests when this function reaches quorum, observes a newer term,
        // or is itself cancelled. Detached probes can otherwise outlive the
        // read they were authorizing and consume the peer's RPC budget after
        // the caller has gone away.
        let mut requests = tokio::task::JoinSet::new();
        for peer in peers {
            let pid = peer.node_id();
            if !membership.voting_members.contains(&pid) {
                continue;
            }
            if self.is_partitioned(pid).await {
                continue;
            }

            let req = AppendEntriesRequest {
                term,
                leader_id: self.node_id,
                prev_log_index: last_log_idx,
                prev_log_term: last_log_term,
                entries: vec![],
                leader_commit,
            };
            let peer = Arc::clone(&peer);
            requests.spawn(async move {
                let res = peer.append_entries(req).await;
                (pid, res)
            });
        }

        while let Some(joined) = requests.join_next().await {
            let Ok((_pid, res)) = joined else {
                // A failed probe cannot contribute to quorum. Do not expose
                // task panic/cancellation text through the RPC metrics path.
                continue;
            };
            if let Err(error) = &res {
                self.metrics.record_rpc_failure(error);
            }
            if let Ok(resp) = res {
                if resp.term > term {
                    let mut s = self.state.lock().await;
                    if resp.term > s.current_term {
                        self.inner.consensus_set_state(resp.term, None).await?;
                        s.current_term = resp.term;
                        s.voted_for = None;
                        s.role = Role::Follower;
                        s.leader_id = None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AppendEntriesResponse, AuditKey, ClusterMembership, ConsensusClock, InstallSnapshotRequest,
        InstallSnapshotResponse, RequestVoteRequest, RequestVoteResponse, RollbackTarget,
        SqliteBackend, StoredConfig, TimeoutNowRequest, TimeoutNowResponse,
    };
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[derive(Debug)]
    enum ProbeBehavior {
        Pending {
            entered: Arc<tokio::sync::Semaphore>,
            dropped: Arc<AtomicBool>,
        },
        AckAfterPeerEntered(Arc<tokio::sync::Semaphore>),
    }

    #[derive(Debug)]
    struct ProbePeer {
        node_id: usize,
        behavior: ProbeBehavior,
    }

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl ConsensusPeer for ProbePeer {
        fn node_id(&self) -> usize {
            self.node_id
        }

        async fn request_vote(
            &self,
            _req: RequestVoteRequest,
        ) -> Result<RequestVoteResponse, PersistError> {
            Err(PersistError::io("unexpected vote probe"))
        }

        async fn append_entries(
            &self,
            req: AppendEntriesRequest,
        ) -> Result<AppendEntriesResponse, PersistError> {
            match &self.behavior {
                ProbeBehavior::Pending { entered, dropped } => {
                    let _drop_probe = DropProbe(Arc::clone(dropped));
                    entered.add_permits(1);
                    std::future::pending::<()>().await;
                    unreachable!("pending quorum probe completed")
                }
                ProbeBehavior::AckAfterPeerEntered(entered) => {
                    let permit = entered
                        .acquire()
                        .await
                        .map_err(|_| PersistError::inconsistent_state("test quorum gate closed"))?;
                    permit.forget();
                    Ok(AppendEntriesResponse {
                        term: req.term,
                        success: true,
                    })
                }
            }
        }

        async fn install_snapshot(
            &self,
            _req: InstallSnapshotRequest,
        ) -> Result<InstallSnapshotResponse, PersistError> {
            Err(PersistError::io("unexpected snapshot probe"))
        }

        async fn load_latest_consensus_rpc(&self) -> Result<Option<StoredConfig>, PersistError> {
            Err(PersistError::io("unexpected latest probe"))
        }

        async fn load_rollback_consensus_rpc(
            &self,
            _target: RollbackTarget,
        ) -> Result<StoredConfig, PersistError> {
            Err(PersistError::io("unexpected rollback probe"))
        }

        async fn timeout_now(
            &self,
            _req: TimeoutNowRequest,
        ) -> Result<TimeoutNowResponse, PersistError> {
            Err(PersistError::io("unexpected timeout-now probe"))
        }
    }

    async fn leader_store(
        temp_dir: &tempfile::TempDir,
        voting_members: Vec<usize>,
    ) -> Arc<ConsensusConfigStore> {
        let backend = Arc::new(
            SqliteBackend::open_with_audit_key(
                temp_dir.path().join("read-index-cancellation.db"),
                true,
                0,
                AuditKey::new([0x5C; 32]).unwrap(),
            )
            .await
            .unwrap(),
        );
        let store = Arc::new(
            ConsensusConfigStore::new(
                0,
                backend,
                Some(ClusterMembership {
                    cluster_id: "read-index-cancellation".to_string(),
                    node_id: 0,
                    voting_members,
                    non_voting_members: vec![],
                    old_voting_members: None,
                    removed_members: vec![],
                    epoch: 1,
                }),
                Some(ConsensusClock {
                    enable_timers: false,
                    ..ConsensusClock::default()
                }),
            )
            .await
            .unwrap(),
        );
        store.state.lock().await.role = Role::Leader;
        store
    }

    async fn wait_until_dropped(dropped: &AtomicBool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("outstanding quorum probe was not cancelled");
    }

    #[tokio::test]
    async fn reaching_read_quorum_aborts_outstanding_peer_probe() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = leader_store(&temp_dir, vec![0, 1, 2]).await;
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        store
            .add_peer(
                1,
                Arc::new(ProbePeer {
                    node_id: 1,
                    behavior: ProbeBehavior::Pending {
                        entered: Arc::clone(&entered),
                        dropped: Arc::clone(&dropped),
                    },
                }),
            )
            .await;
        store
            .add_peer(
                2,
                Arc::new(ProbePeer {
                    node_id: 2,
                    behavior: ProbeBehavior::AckAfterPeerEntered(Arc::clone(&entered)),
                }),
            )
            .await;

        tokio::time::timeout(Duration::from_secs(1), store.verify_leadership())
            .await
            .expect("read quorum did not complete")
            .unwrap();

        wait_until_dropped(&dropped).await;
    }

    #[tokio::test]
    async fn cancelling_read_quorum_aborts_outstanding_peer_probe() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = leader_store(&temp_dir, vec![0, 1]).await;
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        store
            .add_peer(
                1,
                Arc::new(ProbePeer {
                    node_id: 1,
                    behavior: ProbeBehavior::Pending {
                        entered: Arc::clone(&entered),
                        dropped: Arc::clone(&dropped),
                    },
                }),
            )
            .await;

        let task_store = Arc::clone(&store);
        let task = tokio::spawn(async move { task_store.verify_leadership().await });
        tokio::time::timeout(Duration::from_secs(1), entered.acquire())
            .await
            .expect("quorum probe did not start")
            .expect("quorum probe gate closed")
            .forget();

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        wait_until_dropped(&dropped).await;
    }
}
