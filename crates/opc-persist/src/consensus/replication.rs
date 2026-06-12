use super::{
    AppendEntriesRequest, AppendEntriesResponse, ConsensusClock, ConsensusConfigStore,
    ConsensusMetrics, ConsensusNodeState, ConsensusOp, ConsensusPeer, InstallSnapshotRequest,
    LogEntry, Role,
};
use crate::backend::SqliteBackend;
use crate::error::PersistError;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

impl ConsensusConfigStore {
    pub async fn handle_append_entries(
        &self,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, PersistError> {
        let mut state = self.state.lock().await;
        if !state.online {
            return Err(PersistError::io("node offline"));
        }

        if req.term > state.current_term {
            state.current_term = req.term;
            state.voted_for = None;
            state.role = Role::Follower;
            state.leader_id = Some(req.leader_id);
            self.inner
                .consensus_set_state(state.current_term, state.voted_for)
                .await?;
        }

        if req.term >= state.current_term {
            state.last_contact = Instant::now();
        }

        if req.term < state.current_term {
            opc_redaction::metrics::METRICS
                .persist_stale_leader_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Ok(AppendEntriesResponse {
                term: state.current_term,
                success: false,
            });
        }

        state.role = Role::Follower;
        state.leader_id = Some(req.leader_id);

        if req.prev_log_index > 0 {
            let local_term_opt = self
                .inner
                .consensus_get_log_term(req.prev_log_index)
                .await?;
            match local_term_opt {
                Some(local_term) if local_term == req.prev_log_term => {}
                _ => {
                    return Ok(AppendEntriesResponse {
                        term: state.current_term,
                        success: false,
                    });
                }
            }
        }

        if !req.entries.is_empty() {
            self.inner
                .consensus_append_logs(req.prev_log_index, req.entries)
                .await?;
        } else {
            let last_log = self.inner.consensus_get_last_log().await?.0;
            if last_log > req.prev_log_index {
                self.inner
                    .consensus_truncate_unapplied_after(req.prev_log_index)
                    .await?;
            }
        }

        let last_log = self.inner.consensus_get_last_log().await?.0;
        let commit_to = req.leader_commit.min(last_log);
        self.inner.consensus_apply_entries(commit_to).await?;

        state.commit_index = commit_to;
        state.last_applied = commit_to;

        Ok(AppendEntriesResponse {
            term: state.current_term,
            success: true,
        })
    }

    pub async fn replicate_to_peers_sync(&self) -> Result<(), PersistError> {
        let store_addr = Arc::as_ptr(&self.inner) as usize;
        static REPLICATION_LOCKS: std::sync::OnceLock<
            std::sync::Mutex<
                std::collections::HashMap<usize, std::sync::Arc<tokio::sync::Mutex<()>>>,
            >,
        > = std::sync::OnceLock::new();
        let lock = REPLICATION_LOCKS
            .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
            .lock()
            .unwrap()
            .entry(store_addr)
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        let peers = {
            let guard = self.peers.read().await;
            guard
                .values()
                .cloned()
                .collect::<Vec<Arc<dyn ConsensusPeer>>>()
        };

        for peer in peers {
            let peer_id = peer.node_id();
            if self.is_partitioned(peer_id).await {
                continue;
            }
            loop {
                let (term, leader_id, commit_index, next_idx) = {
                    let s = self.state.lock().await;
                    if s.role != Role::Leader {
                        return Ok(());
                    }
                    let next = s.next_index.get(&peer_id).cloned().unwrap_or(1);
                    (s.current_term, self.node_id, s.commit_index, next)
                };

                let snapshot_opt = self.inner.consensus_get_snapshot().await?;
                if let Some((snap_idx, snap_term, snap_data)) = snapshot_opt {
                    if next_idx <= snap_idx {
                        let req = InstallSnapshotRequest {
                            term,
                            leader_id,
                            last_included_index: snap_idx,
                            last_included_term: snap_term,
                            data: snap_data,
                        };
                        match peer.install_snapshot(req).await {
                            Ok(resp) => {
                                let mut s = self.state.lock().await;
                                if resp.term > s.current_term {
                                    s.current_term = resp.term;
                                    s.voted_for = None;
                                    s.role = Role::Follower;
                                    s.leader_id = None;
                                    let cur_term = s.current_term;
                                    let voted_for = s.voted_for;
                                    drop(s);
                                    let _ =
                                        self.inner.consensus_set_state(cur_term, voted_for).await;
                                    return Ok(());
                                }
                                if resp.success {
                                    s.next_index.insert(peer_id, snap_idx + 1);
                                    s.match_index.insert(peer_id, snap_idx);
                                    drop(s);
                                    let _ = self.update_commit_index().await;
                                    continue;
                                }
                            }
                            Err(e) => {
                                debug!(error = ?e, peer_id, "install_snapshot failed");
                                break;
                            }
                        }
                    }
                }

                let (last_log_index, _) = self.inner.consensus_get_last_log().await?;
                let is_heartbeat = last_log_index < next_idx;
                let entries = if is_heartbeat {
                    vec![]
                } else {
                    self.inner.consensus_get_entries(next_idx).await?
                };

                let (prev_log_index, prev_log_term) = if next_idx <= 1 {
                    (0, 0)
                } else {
                    let idx = next_idx - 1;
                    let t = self.inner.consensus_get_log_term(idx).await?.unwrap_or(0);
                    (idx, t)
                };

                let entries_len = entries.len();
                let req = AppendEntriesRequest {
                    term,
                    leader_id,
                    prev_log_index,
                    prev_log_term,
                    entries,
                    leader_commit: commit_index,
                };

                match peer.append_entries(req).await {
                    Ok(resp) => {
                        let mut s = self.state.lock().await;
                        if resp.term > s.current_term {
                            s.current_term = resp.term;
                            s.voted_for = None;
                            s.role = Role::Follower;
                            s.leader_id = None;
                            let cur_term = s.current_term;
                            let voted_for = s.voted_for;
                            drop(s);
                            let _ = self.inner.consensus_set_state(cur_term, voted_for).await;
                            return Ok(());
                        }
                        if s.role != Role::Leader {
                            return Ok(());
                        }
                        if resp.success {
                            let new_match = prev_log_index + entries_len as u64;
                            let current_match = s.match_index.get(&peer_id).cloned().unwrap_or(0);
                            if new_match > current_match {
                                s.match_index.insert(peer_id, new_match);
                                s.next_index.insert(peer_id, new_match + 1);
                                drop(s);
                                let _ = self.update_commit_index().await;
                            } else {
                                drop(s);
                            }
                            break;
                        } else if next_idx > 1 {
                            s.next_index.insert(peer_id, next_idx - 1);
                        } else {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        Ok(())
    }

    pub fn update_commit_index(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), PersistError>> + Send + 'static>,
    > {
        let store = self.clone();
        Box::pin(async move {
            Self::update_commit_index_static(
                &store.inner,
                &store.state,
                &store.commit_notifier,
                store.node_id,
            )
            .await?;

            let role = store.get_role().await;
            if role == Role::Leader {
                if let Ok(Some(mut membership)) = store.inner.consensus_get_membership().await {
                    if membership.old_voting_members.is_some() {
                        let mut s = store.state.lock().await;
                        if !s.finalization_in_progress
                            && s.last_finalized_epoch != Some(membership.epoch)
                        {
                            s.finalization_in_progress = true;
                            s.last_finalized_epoch = Some(membership.epoch);
                            drop(s);

                            let (last_idx, _) =
                                store.inner.consensus_get_last_log().await.unwrap_or((0, 0));
                            let mut already_appended = false;
                            if last_idx > 0 {
                                let start_search = last_idx.saturating_sub(100).max(1);
                                if let Ok(entries) =
                                    store.inner.consensus_get_entries(start_search).await
                                {
                                    for entry in &entries {
                                        if let ConsensusOp::ChangeMembership {
                                            membership: last_mem,
                                        } = &entry.op
                                        {
                                            if last_mem.old_voting_members.is_none()
                                                && last_mem.epoch > membership.epoch
                                            {
                                                already_appended = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                            if !already_appended {
                                membership.old_voting_members = None;
                                membership.epoch += 1;
                                let op = ConsensusOp::ChangeMembership { membership };
                                let store2 = store.clone();
                                let fut: std::pin::Pin<
                                    Box<dyn std::future::Future<Output = ()> + Send>,
                                > = Box::pin(async move {
                                    let res = store2.replicate_and_commit(op).await;
                                    let mut s = store2.state.lock().await;
                                    s.finalization_in_progress = false;
                                    if let Err(err) = res {
                                        s.last_finalized_epoch = None;
                                        debug!(
                                            error = ?err,
                                            "joint consensus finalization failed"
                                        );
                                    }
                                });
                                tokio::spawn(fut);
                            } else {
                                let mut s = store.state.lock().await;
                                s.finalization_in_progress = false;
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    }

    pub async fn sync(&self) -> Result<(), PersistError> {
        let role = self.get_role().await;
        if role == Role::Leader {
            self.replicate_to_peers_sync().await?;
        }
        Ok(())
    }

    pub fn replicate_and_commit(
        &self,
        op: ConsensusOp,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PersistError>> + Send + '_>>
    {
        let this = self.clone();
        Box::pin(async move {
            let res = this.replicate_and_commit_inner(op).await;
            if res.is_ok() {
                opc_redaction::metrics::METRICS
                    .persist_quorum_write_success
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                opc_redaction::metrics::METRICS
                    .persist_quorum_write_failure
                    .fetch_add(1, Ordering::Relaxed);
            }
            res
        })
    }

    fn replicate_and_commit_inner(
        &self,
        op: ConsensusOp,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PersistError>> + Send + '_>>
    {
        let this = self.clone();
        Box::pin(async move {
            if op != ConsensusOp::NoOp {
                if let Err(e) = this.wait_for_no_op_commit().await {
                    this.metrics
                        .write_quorum_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            }

            let (online, role, current_term) = {
                let state = this.state.lock().await;
                (state.online, state.role, state.current_term)
            };
            if !online {
                return Err(PersistError::io("node offline"));
            }
            if role != Role::Leader {
                return Err(PersistError::inconsistent_state(
                    "stale leader: not the leader",
                ));
            }

            if let ConsensusOp::ChangeMembership { membership } = &op {
                if let Ok(Some(active)) = this.inner.consensus_get_active_membership().await {
                    if active.epoch >= membership.epoch {
                        return Ok(());
                    }
                }
            }

            let (last_index, _) = this.inner.consensus_get_last_log().await?;
            let entry = LogEntry {
                index: last_index + 1,
                term: current_term,
                op,
            };
            this.inner
                .consensus_append_logs(last_index, vec![entry.clone()])
                .await?;
            let entry_index = entry.index;

            // Replicate to peers synchronously to see if we can commit immediately
            if let Err(err) = this.replicate_to_peers_sync().await {
                this.truncate_uncommitted_entry(entry_index).await;
                let _ = this.replicate_to_peers_sync().await; // Synchronously propagate truncation!
                Self::trigger_replication_static(
                    Arc::clone(&this.inner),
                    Arc::clone(&this.peers),
                    Arc::clone(&this.state),
                    Arc::clone(&this.commit_notifier),
                    this.node_id,
                    Arc::clone(&this.metrics),
                );
                this.metrics
                    .write_quorum_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(err);
            }

            if this.peers.read().await.is_empty() {
                let _ = this.update_commit_index().await;
            }

            let committed_res = {
                let state = this.state.lock().await;
                if state.role != Role::Leader {
                    Err(PersistError::inconsistent_state(
                        "stale leader: term/role changed during replication",
                    ))
                } else {
                    Ok(state.commit_index >= entry_index)
                }
            };

            let committed = match committed_res {
                Ok(c) => c,
                Err(e) => {
                    this.truncate_uncommitted_entry(entry_index).await;
                    let _ = this.replicate_to_peers_sync().await; // Synchronously propagate truncation!
                    Self::trigger_replication_static(
                        Arc::clone(&this.inner),
                        Arc::clone(&this.peers),
                        Arc::clone(&this.state),
                        Arc::clone(&this.commit_notifier),
                        this.node_id,
                        Arc::clone(&this.metrics),
                    );
                    this.metrics
                        .write_quorum_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            };

            if committed {
                // Also trigger background replication to let lagging followers know/catch up
                Self::trigger_replication_static(
                    Arc::clone(&this.inner),
                    Arc::clone(&this.peers),
                    Arc::clone(&this.state),
                    Arc::clone(&this.commit_notifier),
                    this.node_id,
                    Arc::clone(&this.metrics),
                );
                Ok(())
            } else {
                // Truncate the uncommitted log entry
                this.truncate_uncommitted_entry(entry_index).await;
                let _ = this.replicate_to_peers_sync().await; // Synchronously propagate truncation!
                Self::trigger_replication_static(
                    Arc::clone(&this.inner),
                    Arc::clone(&this.peers),
                    Arc::clone(&this.state),
                    Arc::clone(&this.commit_notifier),
                    this.node_id,
                    Arc::clone(&this.metrics),
                );
                this.metrics
                    .write_quorum_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(PersistError::inconsistent_state(
                    "majority consensus quorum not reached for write",
                ))
            }
        })
    }

    async fn truncate_uncommitted_entry(&self, entry_index: u64) {
        if let Ok((last_index, _)) = self.inner.consensus_get_last_log().await {
            if last_index >= entry_index {
                let _ = self
                    .inner
                    .consensus_truncate_unapplied_after(entry_index.saturating_sub(1))
                    .await;
            }
        }
        let mut state = self.state.lock().await;
        let truncated_last_index = entry_index.saturating_sub(1);
        for next in state.next_index.values_mut() {
            if *next > truncated_last_index + 1 {
                *next = truncated_last_index + 1;
            }
        }
        for match_idx in state.match_index.values_mut() {
            if *match_idx > truncated_last_index {
                *match_idx = truncated_last_index;
            }
        }
    }

    pub(crate) async fn wait_for_no_op_commit(&self) -> Result<(), PersistError> {
        let mut attempts = 0;
        let max_attempts = 15;
        loop {
            let (online, role, current_term) = self.get_online_role_term().await;
            if !online {
                return Err(PersistError::io("node offline"));
            }
            if role != Role::Leader {
                return Err(PersistError::inconsistent_state(
                    "stale leader: not the leader",
                ));
            }

            let last_applied_term = {
                let applied_idx = self.inner.consensus_get_applied_index().await?;
                self.inner
                    .consensus_get_log_term(applied_idx)
                    .await?
                    .unwrap_or(0)
            };

            if last_applied_term >= current_term {
                return Ok(());
            }

            let _ = self.replicate_to_peers_sync().await;
            let _ = self.update_commit_index().await;

            attempts += 1;
            if attempts >= max_attempts {
                return Err(PersistError::inconsistent_state(
                    "majority consensus quorum not reached: current-term no-op not committed",
                ));
            }

            let notified = self.commit_notifier.notified();
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
            }
        }
    }

    async fn get_online_role_term(&self) -> (bool, Role, u64) {
        let state = self.state.lock().await;
        (state.online, state.role, state.current_term)
    }

    pub fn start_timers(
        inner: Arc<SqliteBackend>,
        peers: Arc<RwLock<std::collections::HashMap<usize, Arc<dyn ConsensusPeer>>>>,
        state: Arc<Mutex<ConsensusNodeState>>,
        commit_notifier: Arc<tokio::sync::Notify>,
        clock: ConsensusClock,
        node_id: usize,
        metrics: Arc<ConsensusMetrics>,
    ) {
        if !clock.enable_timers {
            return;
        }

        let weak_state = Arc::downgrade(&state);
        drop(state);
        tokio::spawn(async move {
            let mut election_timeout = Self::get_random_timeout(&clock);
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_heartbeat = Instant::now();

            loop {
                interval.tick().await;

                let state = match weak_state.upgrade() {
                    Some(s) => s,
                    None => break,
                };

                let (online, role) = {
                    let s = state.lock().await;
                    (s.online, s.role)
                };

                if !online {
                    continue;
                }

                if role == Role::Leader {
                    if last_heartbeat.elapsed() >= clock.heartbeat_interval {
                        let _ = Self::send_heartbeats_static(
                            Arc::clone(&inner),
                            Arc::clone(&peers),
                            Arc::clone(&state),
                            Arc::clone(&commit_notifier),
                            node_id,
                            Arc::clone(&metrics),
                        )
                        .await;
                        let _ = Self::update_commit_index_static(
                            &inner,
                            &state,
                            &commit_notifier,
                            node_id,
                        )
                        .await;
                        last_heartbeat = Instant::now();
                    }
                } else {
                    let last_contact = {
                        let s = state.lock().await;
                        s.last_contact
                    };

                    if last_contact.elapsed() >= election_timeout {
                        debug!(node_id = node_id, "election timeout elapsed, campaigning");
                        {
                            let mut s = state.lock().await;
                            s.last_contact = Instant::now();
                        }
                        election_timeout = Self::get_random_timeout(&clock);
                        let _ = Self::campaign_static(
                            Arc::clone(&inner),
                            Arc::clone(&peers),
                            Arc::clone(&state),
                            Arc::clone(&commit_notifier),
                            node_id,
                            Arc::clone(&metrics),
                        )
                        .await;
                    }
                }
            }
        });
    }

    fn get_random_timeout(clock: &ConsensusClock) -> std::time::Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let min_ms = clock.election_timeout_min.as_millis() as u64;
        let max_ms = clock.election_timeout_max.as_millis() as u64;
        if min_ms >= max_ms {
            clock.election_timeout_min
        } else {
            let ms = rng.gen_range(min_ms..max_ms);
            std::time::Duration::from_millis(ms)
        }
    }

    async fn send_heartbeats_static(
        inner: Arc<SqliteBackend>,
        peers: Arc<RwLock<std::collections::HashMap<usize, Arc<dyn ConsensusPeer>>>>,
        state: Arc<Mutex<ConsensusNodeState>>,
        commit_notifier: Arc<tokio::sync::Notify>,
        node_id: usize,
        metrics: Arc<ConsensusMetrics>,
    ) -> Result<(), PersistError> {
        let (term, commit_index) = {
            let s = state.lock().await;
            if s.role != Role::Leader {
                return Ok(());
            }
            (s.current_term, s.commit_index)
        };

        let peer_list = {
            let guard = peers.read().await;
            guard
                .values()
                .cloned()
                .collect::<Vec<Arc<dyn ConsensusPeer>>>()
        };

        for peer in peer_list {
            let peer_id = peer.node_id();
            // Skip if partitioned
            {
                let s = state.lock().await;
                if s.partitioned_peers.contains(&peer_id) {
                    continue;
                }
            }

            let (last_log_idx, _) = inner.consensus_get_last_log().await.unwrap_or((0, 0));
            let next_idx = {
                let s = state.lock().await;
                s.next_index.get(&peer_id).cloned().unwrap_or(1)
            };

            if last_log_idx >= next_idx {
                // Peer is lagging, trigger active replication catch-up!
                Self::trigger_replication_static(
                    Arc::clone(&inner),
                    Arc::clone(&peers),
                    Arc::clone(&state),
                    Arc::clone(&commit_notifier),
                    node_id,
                    Arc::clone(&metrics),
                );
                continue;
            }
            let (prev_log_index, prev_log_term) = {
                let s = state.lock().await;
                let next = s.next_index.get(&peer_id).cloned().unwrap_or(1);
                let prev = next.saturating_sub(1);
                if prev == 0 {
                    (0, 0)
                } else {
                    let term = inner.consensus_get_log_term(prev).await?.unwrap_or(0);
                    (prev, term)
                }
            };

            let req = AppendEntriesRequest {
                term,
                leader_id: node_id,
                prev_log_index,
                prev_log_term,
                entries: vec![],
                leader_commit: commit_index,
            };

            let inner_c = Arc::clone(&inner);
            let state_c = Arc::clone(&state);
            let peer_c = Arc::clone(&peer);
            let metrics_c = Arc::clone(&metrics);
            let commit_notifier_c = Arc::clone(&commit_notifier);
            tokio::spawn(async move {
                match peer_c.append_entries(req).await {
                    Ok(resp) => {
                        let mut s = state_c.lock().await;
                        if resp.term > s.current_term {
                            s.current_term = resp.term;
                            s.voted_for = None;
                            s.role = Role::Follower;
                            s.leader_id = None;
                            let _ = inner_c
                                .consensus_set_state(s.current_term, s.voted_for)
                                .await;
                            return;
                        }
                        if s.role == Role::Leader {
                            if resp.success {
                                let old_match = s.match_index.get(&peer_id).cloned().unwrap_or(0);
                                if prev_log_index > old_match {
                                    s.match_index.insert(peer_id, prev_log_index);
                                    s.next_index.insert(peer_id, prev_log_index + 1);
                                    drop(s);
                                    let _ = Self::update_commit_index_static(
                                        &inner_c,
                                        &state_c,
                                        &commit_notifier_c,
                                        node_id,
                                    )
                                    .await;
                                }
                            } else {
                                let next = s.next_index.get(&peer_id).cloned().unwrap_or(1);
                                if next > 1 {
                                    s.next_index.insert(peer_id, next - 1);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        metrics_c.rpc_failures.fetch_add(1, Ordering::Relaxed);
                        if e.to_string().contains("timeout") {
                            metrics_c.rpc_timeouts.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
        Ok(())
    }

    pub fn trigger_replication_static(
        inner: Arc<SqliteBackend>,
        peers: Arc<RwLock<std::collections::HashMap<usize, Arc<dyn ConsensusPeer>>>>,
        state: Arc<Mutex<ConsensusNodeState>>,
        commit_notifier: Arc<tokio::sync::Notify>,
        node_id: usize,
        metrics: Arc<ConsensusMetrics>,
    ) {
        tokio::spawn(async move {
            let peers_guard = peers.read().await;
            let peer_list: Vec<Arc<dyn ConsensusPeer>> = peers_guard.values().cloned().collect();
            drop(peers_guard);

            for peer in peer_list {
                let peer_id = peer.node_id();
                // Check if partitioned
                {
                    let s = state.lock().await;
                    if s.partitioned_peers.contains(&peer_id) {
                        continue;
                    }
                }
                let inner = Arc::clone(&inner);
                let state = Arc::clone(&state);
                let commit_notifier = Arc::clone(&commit_notifier);
                let peer = Arc::clone(&peer);
                let metrics_c = Arc::clone(&metrics);

                tokio::spawn(async move {
                    loop {
                        let (term, leader_id, commit_index, next_idx, _match_idx) = {
                            let s = state.lock().await;
                            if s.role != Role::Leader {
                                return;
                            }
                            let next = s.next_index.get(&peer_id).cloned().unwrap_or(1);
                            let mat = s.match_index.get(&peer_id).cloned().unwrap_or(0);
                            (s.current_term, node_id, s.commit_index, next, mat)
                        };

                        let snapshot_opt = match inner.consensus_get_snapshot().await {
                            Ok(opt) => opt,
                            Err(_) => break,
                        };

                        if let Some((snap_idx, snap_term, snap_data)) = snapshot_opt {
                            if next_idx <= snap_idx {
                                let req = InstallSnapshotRequest {
                                    term,
                                    leader_id,
                                    last_included_index: snap_idx,
                                    last_included_term: snap_term,
                                    data: snap_data,
                                };
                                match peer.install_snapshot(req).await {
                                    Ok(resp) => {
                                        let mut s = state.lock().await;
                                        if resp.term > s.current_term {
                                            s.current_term = resp.term;
                                            s.voted_for = None;
                                            s.role = Role::Follower;
                                            s.leader_id = None;
                                            let _ = inner
                                                .consensus_set_state(s.current_term, s.voted_for)
                                                .await;
                                            return;
                                        }
                                        if resp.success {
                                            s.next_index.insert(peer_id, snap_idx + 1);
                                            s.match_index.insert(peer_id, snap_idx);
                                            drop(s);
                                            let _ = Self::update_commit_index_static(
                                                &inner,
                                                &state,
                                                &commit_notifier,
                                                node_id,
                                            )
                                            .await;
                                            continue;
                                        }
                                    }
                                    Err(e) => {
                                        metrics_c.rpc_failures.fetch_add(1, Ordering::Relaxed);
                                        if e.to_string().contains("timeout") {
                                            metrics_c.rpc_timeouts.fetch_add(1, Ordering::Relaxed);
                                        }
                                        break;
                                    }
                                }
                            }
                        }

                        let (last_log_index, _) = match inner.consensus_get_last_log().await {
                            Ok(res) => res,
                            Err(_) => break,
                        };

                        let is_heartbeat = last_log_index < next_idx;
                        let entries = if is_heartbeat {
                            vec![]
                        } else {
                            match inner.consensus_get_entries(next_idx).await {
                                Ok(ent) => ent,
                                Err(_) => break,
                            }
                        };

                        let (prev_log_index, prev_log_term) = if next_idx <= 1 {
                            (0, 0)
                        } else {
                            let idx = next_idx - 1;
                            let t = match inner.consensus_get_log_term(idx).await {
                                Ok(Some(term)) => term,
                                _ => 0,
                            };
                            (idx, t)
                        };

                        let req = AppendEntriesRequest {
                            term,
                            leader_id,
                            prev_log_index,
                            prev_log_term,
                            entries,
                            leader_commit: commit_index,
                        };

                        match peer.append_entries(req).await {
                            Ok(resp) => {
                                let mut s = state.lock().await;
                                if resp.term > s.current_term {
                                    s.current_term = resp.term;
                                    s.voted_for = None;
                                    s.role = Role::Follower;
                                    s.leader_id = None;
                                    let _ = inner
                                        .consensus_set_state(s.current_term, s.voted_for)
                                        .await;
                                    return;
                                }
                                if s.role != Role::Leader {
                                    return;
                                }
                                if resp.success {
                                    if !is_heartbeat {
                                        let new_match = prev_log_index
                                            + last_log_index.saturating_sub(prev_log_index);
                                        s.match_index.insert(peer_id, new_match);
                                        s.next_index.insert(peer_id, new_match + 1);
                                        drop(s);
                                        let _ = Self::update_commit_index_static(
                                            &inner,
                                            &state,
                                            &commit_notifier,
                                            node_id,
                                        )
                                        .await;
                                    }
                                    break;
                                } else if next_idx > 1 {
                                    s.next_index.insert(peer_id, next_idx - 1);
                                } else {
                                    break;
                                }
                            }
                            Err(e) => {
                                metrics_c.rpc_failures.fetch_add(1, Ordering::Relaxed);
                                if e.to_string().contains("timeout") {
                                    metrics_c.rpc_timeouts.fetch_add(1, Ordering::Relaxed);
                                }
                                break;
                            }
                        }
                    }
                });
            }
        });
    }

    pub(crate) async fn update_commit_index_static(
        inner: &SqliteBackend,
        state: &Mutex<ConsensusNodeState>,
        commit_notifier: &tokio::sync::Notify,
        node_id: usize,
    ) -> Result<(), PersistError> {
        let (role, current_term, commit_index, match_index_map) = {
            let s = state.lock().await;
            (
                s.role,
                s.current_term,
                s.commit_index,
                s.match_index.clone(),
            )
        };

        if role != Role::Leader {
            return Ok(());
        }

        let (last_log_index, _) = inner.consensus_get_last_log().await?;

        let mut n = commit_index;
        for candidate_n in (commit_index + 1..=last_log_index).rev() {
            let membership = inner
                .consensus_get_active_membership_at(candidate_n)
                .await?
                .ok_or_else(|| PersistError::inconsistent_state("membership not found"))?;

            let voting_count = membership
                .voting_members
                .iter()
                .filter(|&&voter_id| {
                    let m = if voter_id == node_id {
                        last_log_index
                    } else {
                        match_index_map.get(&voter_id).cloned().unwrap_or(0)
                    };
                    m >= candidate_n
                })
                .count();
            let voting_majority = voting_count > (membership.voting_members.len() / 2);

            let old_majority = match &membership.old_voting_members {
                None => true,
                Some(old_voters) => {
                    let old_count = old_voters
                        .iter()
                        .filter(|&&voter_id| {
                            let m = if voter_id == node_id {
                                last_log_index
                            } else {
                                match_index_map.get(&voter_id).cloned().unwrap_or(0)
                            };
                            m >= candidate_n
                        })
                        .count();
                    old_count > (old_voters.len() / 2)
                }
            };

            if voting_majority && old_majority {
                n = candidate_n;
                break;
            }
        }

        let mut apply_n = None;
        if n > commit_index {
            let term_opt = inner.consensus_get_log_term(n).await?;
            if let Some(term) = term_opt {
                if term == current_term {
                    let mut s = state.lock().await;
                    if s.role == Role::Leader
                        && s.current_term == current_term
                        && n > s.commit_index
                    {
                        s.commit_index = n;
                        s.last_applied = n;
                        apply_n = Some(n);
                    }
                }
            }
        }

        if let Some(n) = apply_n {
            inner.consensus_apply_entries(n).await?;
            commit_notifier.notify_waiters();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn random_election_timeout_stays_within_clock_bounds() {
        let clock = ConsensusClock::default();
        for _ in 0..100 {
            let timeout = ConsensusConfigStore::get_random_timeout(&clock);
            assert!(timeout >= clock.election_timeout_min);
            assert!(timeout < clock.election_timeout_max);
        }
    }

    #[test]
    fn random_election_timeout_returns_min_when_bounds_equal() {
        let clock = ConsensusClock {
            election_timeout_min: Duration::from_millis(200),
            election_timeout_max: Duration::from_millis(200),
            heartbeat_interval: Duration::from_millis(50),
            enable_timers: true,
        };
        assert_eq!(
            ConsensusConfigStore::get_random_timeout(&clock),
            Duration::from_millis(200)
        );
    }
}
