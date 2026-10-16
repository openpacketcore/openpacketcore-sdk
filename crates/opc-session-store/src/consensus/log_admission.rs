//! Backpressure on the live retained log, including work queued in the engine.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_consensus::engine::raft::AppendEntriesRequest;
use opc_consensus::engine::{EmptyNode, RaftMetrics, ServerState};
use tokio::sync::watch;

use super::persistence_protocol::PersistenceProtocol;
use super::{SessionConsensusNodeId, SessionRaft, SessionRaftTypeConfig};

/// Initial live-row window pending workload-specific build and transfer measurements.
/// This leaves three quarters of the native log's last-defence capacity unused.
pub const SESSION_CONSENSUS_LOG_HIGH_WATER_ROWS: u64 = 262_144;

/// Pressure relative to the live log window. These levels clear as work progresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConsensusLogPressureLevel {
    /// Below one half of the window.
    Normal,
    /// At least one half of the window.
    Elevated,
    /// At least three quarters of the window.
    High,
    /// At or above the window.
    AtWindow,
}

/// Current log gauges; no field is an operation or lifetime budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusLogPressureSnapshot {
    /// Rows above the published purge frontier.
    pub retained_rows: u64,
    /// Reserved growth not yet retired against engine observations.
    pub pending_entries: u64,
    /// Entries after the last selected snapshot.
    pub entries_since_snapshot: u64,
    /// The current live-row admission window.
    pub high_water_rows: u64,
    /// Pressure from retained rows and pending growth together.
    pub retained_level: ConsensusLogPressureLevel,
    /// Pressure from entries since the selected snapshot.
    pub snapshot_level: ConsensusLogPressureLevel,
}

type Metrics = RaftMetrics<SessionConsensusNodeId, EmptyNode>;

struct CompletedGrowth {
    entries: u64,
    through: u64,
    // Marked seen at completion, not at submission. A later publication must
    // include the completed operation or a subsequent truncation/purge.
    completed_at: watch::Receiver<Metrics>,
}

#[derive(Default)]
struct State {
    pending: u64,
    completed: Option<CompletedGrowth>,
    warning: Option<(ConsensusLogPressureLevel, ConsensusLogPressureLevel)>,
}

pub(super) struct LogAdmission {
    metrics: watch::Receiver<Metrics>,
    state: Mutex<State>,
    changed: watch::Sender<()>,
    window: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogAdmissionError {
    NotLeader(Option<SessionConsensusNodeId>),
    Unavailable,
}

impl LogAdmission {
    pub(super) fn for_raft(raft: SessionRaft, persistence: PersistenceProtocol) -> Arc<Self> {
        Self::with_metrics(raft.metrics(), Some(raft), persistence)
    }

    #[cfg(test)]
    pub(super) fn new(metrics: watch::Receiver<Metrics>) -> Arc<Self> {
        Self::with_metrics(metrics, None, PersistenceProtocol::default())
    }

    fn with_metrics(
        metrics: watch::Receiver<Metrics>,
        raft: Option<SessionRaft>,
        persistence: PersistenceProtocol,
    ) -> Arc<Self> {
        let (changed, mut changes) = watch::channel(());
        let admission = Arc::new(Self {
            metrics: metrics.clone(),
            state: Mutex::new(State::default()),
            changed,
            window: AtomicU64::new(SESSION_CONSENSUS_LOG_HIGH_WATER_ROWS),
        });
        let weak = Arc::downgrade(&admission);
        let mut active_changes = persistence.active_changes();
        tokio::spawn(async move {
            let mut metrics = metrics;
            let mut next_snapshot = tokio::time::Instant::now();
            loop {
                let Some(admission) = weak.upgrade() else {
                    return;
                };
                let pressure = admission.snapshot();
                let needs_snapshot = {
                    let metrics = metrics.borrow();
                    raft.is_some()
                        && persistence.is_active()
                        && metrics.running_state.is_ok()
                        && pressure
                            .retained_rows
                            .saturating_add(pressure.pending_entries)
                            >= pressure.high_water_rows
                        && distance(
                            metrics.last_applied.map(|id| id.index),
                            metrics.snapshot.map(|id| id.index),
                        ) >= opc_consensus::DURABLE_OPENRAFT_PROFILE.logs_per_snapshot
                };
                drop(admission);
                if needs_snapshot && tokio::time::Instant::now() >= next_snapshot {
                    // The engine normally schedules builds on commit progress.
                    // A stalled old build can finish after this gate has stopped
                    // all new commits, leaving no event to schedule its successor.
                    // Retry only under live pressure: an active build may ignore
                    // this request, including a build at an unchanged snapshot cut.
                    next_snapshot = tokio::time::Instant::now() + Duration::from_secs(1);
                    // Recheck under the recovery fence, keeping it through
                    // enqueue so a concurrent prepare cannot admit this work
                    // after closing the active incarnation.
                    if let Ok(_active) = persistence
                        .submission_before(persistence.operation_stamp(), next_snapshot)
                        .await
                    {
                        if raft
                            .as_ref()
                            .expect("snapshot engine")
                            .trigger()
                            .snapshot()
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                tokio::select! {
                    result = metrics.changed() => if result.is_err() { return; },
                    result = changes.changed() => if result.is_err() { return; },
                    result = active_changes.changed() => if result.is_err() { return; },
                    () = tokio::time::sleep_until(next_snapshot), if needs_snapshot => {},
                }
            }
        });
        admission
    }

    #[cfg(test)]
    pub(super) fn set_window_for_test(&self, window: u64) {
        assert!(window > 0);
        self.window.store(window, Ordering::Release);
        self.changed.send_replace(());
    }

    fn observe(&self, state: &mut State, metrics: &Metrics) -> ConsensusLogPressureSnapshot {
        if state.completed.as_ref().is_some_and(|completed| {
            metrics
                .last_log_index
                .is_some_and(|last| last >= completed.through)
                || metrics
                    .purged
                    .is_some_and(|purged| purged.index >= completed.through)
                || completed.completed_at.has_changed().unwrap_or(false)
        }) {
            state.pending -= state.completed.take().expect("observed completion").entries;
        }
        let retained_rows = distance(metrics.last_log_index, metrics.purged.map(|id| id.index));
        let entries_since_snapshot =
            distance(metrics.last_log_index, metrics.snapshot.map(|id| id.index));
        let high_water_rows = self.window.load(Ordering::Acquire);
        let snapshot = ConsensusLogPressureSnapshot {
            retained_rows,
            pending_entries: state.pending,
            entries_since_snapshot,
            high_water_rows,
            retained_level: level(retained_rows.saturating_add(state.pending), high_water_rows),
            snapshot_level: level(entries_since_snapshot, high_water_rows),
        };
        let warning = (snapshot.retained_level, snapshot.snapshot_level);
        if state.warning != Some(warning) {
            if warning.0 != ConsensusLogPressureLevel::Normal
                || warning.1 != ConsensusLogPressureLevel::Normal
            {
                tracing::warn!(
                    retained_rows,
                    pending_entries = state.pending,
                    entries_since_snapshot,
                    high_water_rows,
                    retained_level = ?warning.0,
                    snapshot_level = ?warning.1,
                    "consensus live log pressure"
                );
            } else if state.warning.is_some() {
                tracing::info!(
                    retained_rows,
                    entries_since_snapshot,
                    "consensus live log pressure cleared"
                );
            }
            state.warning = Some(warning);
        }
        snapshot
    }

    pub(super) fn snapshot(&self) -> ConsensusLogPressureSnapshot {
        let mut state = self.state.lock().expect("log admission state");
        // Keep the metrics read lock through debt retirement. Otherwise a new
        // watch version could retire debt against an older last-log value.
        let metrics = self.metrics.borrow();
        self.observe(&mut state, &metrics)
    }

    pub(super) fn has_capacity(&self) -> bool {
        let snapshot = self.snapshot();
        snapshot
            .retained_rows
            .saturating_add(snapshot.pending_entries)
            < snapshot.high_water_rows
    }

    /// Finish queued admission on a leadership change, including while waiting
    /// for a scheduler credit. No caller deadline or resident reservation is
    /// renewed by a redirect.
    pub(super) async fn while_leader<F: std::future::Future>(
        &self,
        operation: F,
    ) -> Result<F::Output, LogAdmissionError> {
        let mut metrics = self.metrics.clone();
        let vote = metrics.borrow().vote;
        tokio::pin!(operation);
        loop {
            {
                let current = metrics.borrow_and_update();
                if current.running_state.is_err() {
                    return Err(LogAdmissionError::Unavailable);
                }
                if current.current_leader != Some(current.id)
                    || current.state != ServerState::Leader
                    || current.vote != vote
                {
                    return Err(LogAdmissionError::NotLeader(current.current_leader));
                }
            }
            tokio::select! {
                biased;
                result = metrics.changed() => result.map_err(|_| LogAdmissionError::Unavailable)?,
                result = &mut operation => return Ok(result),
            }
        }
    }

    pub(super) async fn ready_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), LogAdmissionError> {
        let mut metrics = self.metrics.clone();
        let mut changed = self.changed.subscribe();
        tokio::time::timeout_at(deadline, self.while_leader(async {
            loop {
                if self.has_capacity() {
                    return Ok(());
                }
                tokio::select! {
                    result = metrics.changed() => result.map_err(|_| LogAdmissionError::Unavailable)?,
                    result = changed.changed() => result.map_err(|_| LogAdmissionError::Unavailable)?,
                }
            }
        }))
        .await
        .map_err(|_| LogAdmissionError::Unavailable)??
    }

    /// Called synchronously at the final enqueue boundary, after authority checks.
    pub(super) fn reserve_proposal(
        self: &Arc<Self>,
        reserved_headroom: bool,
    ) -> Result<GrowthReservation, LogAdmissionError> {
        let mut state = self.state.lock().expect("log admission state");
        let metrics = self.metrics.borrow();
        let snapshot = self.observe(&mut state, &metrics);
        if metrics.running_state.is_err() {
            return Err(LogAdmissionError::Unavailable);
        }
        if metrics.current_leader != Some(metrics.id) || metrics.state != ServerState::Leader {
            return Err(LogAdmissionError::NotLeader(metrics.current_leader));
        }
        if !reserved_headroom
            && snapshot.retained_rows.saturating_add(state.pending) >= snapshot.high_water_rows
        {
            return Err(LogAdmissionError::Unavailable);
        }
        state.pending += 1;
        self.changed.send_replace(());
        Ok(GrowthReservation {
            admission: self.clone(),
            entries: 1,
        })
    }

    /// Observe replicated growth without gating it. The leader already owns
    /// admission, and these data requests also carry Raft's heartbeats. A full
    /// follower must receive the complete batch, including any trailing control.
    pub(super) fn track_append(
        self: &Arc<Self>,
        rpc: &AppendEntriesRequest<SessionRaftTypeConfig>,
    ) -> Option<GrowthReservation> {
        let mut state = self.state.lock().expect("log admission state");
        let metrics = self.metrics.borrow();
        self.observe(&mut state, &metrics);
        let entries = rpc
            .entries
            .iter()
            .filter(|entry| {
                metrics
                    .last_log_index
                    .is_none_or(|last| entry.log_id.index > last)
            })
            .count() as u64;
        if entries == 0 {
            return None;
        }
        state.pending += entries;
        self.changed.send_replace(());
        Some(GrowthReservation {
            admission: self.clone(),
            entries,
        })
    }
}

/// The engine completion owner retains this reservation after caller cancellation.
pub(super) struct GrowthReservation {
    admission: Arc<LogAdmission>,
    entries: u64,
}

impl GrowthReservation {
    pub(super) fn complete(mut self, through: u64) {
        let mut state = self.admission.state.lock().expect("log admission state");
        let mut completed_at = self.admission.metrics.clone();
        let metrics = completed_at.borrow_and_update();
        self.admission.observe(&mut state, &metrics);
        // Any remaining debt belongs to this same publication version. Keep
        // one live cohort, so memory and lock work do not grow with completions.
        if let Some(completed) = state.completed.as_mut() {
            completed.entries += self.entries;
            completed.through = completed.through.max(through);
        } else {
            drop(metrics);
            state.completed = Some(CompletedGrowth {
                entries: self.entries,
                through,
                completed_at,
            });
        }
        self.entries = 0;
        self.admission.changed.send_replace(());
    }
}

impl Drop for GrowthReservation {
    fn drop(&mut self) {
        if self.entries != 0 {
            let mut state = self.admission.state.lock().expect("log admission state");
            state.pending -= self.entries;
            self.admission.changed.send_replace(());
        }
    }
}

fn distance(last: Option<u64>, frontier: Option<u64>) -> u64 {
    match (last, frontier) {
        (Some(last), Some(frontier)) => last.saturating_sub(frontier),
        (Some(last), None) => last.saturating_add(1),
        (None, _) => 0,
    }
}

fn level(rows: u64, window: u64) -> ConsensusLogPressureLevel {
    if rows >= window {
        ConsensusLogPressureLevel::AtWindow
    } else if rows >= window - window / 4 {
        ConsensusLogPressureLevel::High
    } else if rows >= window - window / 2 {
        ConsensusLogPressureLevel::Elevated
    } else {
        ConsensusLogPressureLevel::Normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        SessionConsensusClusterId, SessionConsensusCommand, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity, SessionConsensusRequestId,
        SessionMutationIntent, SESSION_CONSENSUS_SCHEMA_VERSION,
    };
    use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId, Vote};

    fn node() -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(1).unwrap()
    }

    fn log_id(index: u64) -> LogId<SessionConsensusNodeId> {
        LogId::new(CommittedLeaderId::new(1, node()), index)
    }

    fn fixture(last: u64, window: u64) -> (watch::Sender<Metrics>, Arc<LogAdmission>) {
        let mut metrics = Metrics::new_initial(node());
        metrics.last_log_index = Some(last);
        metrics.current_leader = Some(node());
        metrics.state = ServerState::Leader;
        metrics.vote = Vote::new_committed(1, node());
        let (send, receive) = watch::channel(metrics);
        let admission = LogAdmission::new(receive);
        admission.set_window_for_test(window);
        (send, admission)
    }

    fn append(
        indices: impl IntoIterator<Item = u64>,
    ) -> AppendEntriesRequest<SessionRaftTypeConfig> {
        AppendEntriesRequest {
            vote: Vote::new_committed(1, node()),
            prev_log_id: None,
            leader_commit: None,
            entries: indices
                .into_iter()
                .map(|index| Entry {
                    log_id: log_id(index),
                    payload: EntryPayload::Normal(SessionConsensusCommand {
                        schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                        identity: SessionConsensusIdentity::new(
                            SessionConsensusClusterId::from_bytes([1; 32]),
                            SessionConsensusConfigurationId::from_bytes([2; 32]),
                            SessionConsensusConfigurationEpoch::new(1).unwrap(),
                        ),
                        request_id: SessionConsensusRequestId::from_bytes([3; 16]),
                        logical_time: "2026-07-21T00:00:00Z".parse().unwrap(),
                        intent: SessionMutationIntent::AdvanceLogicalTime,
                    }),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn log_admission_counts_queued_growth_before_metrics_publish() {
        let (_send, admission) = fixture(1, 4);
        let first = admission.reserve_proposal(false).unwrap();
        let second = admission.reserve_proposal(false).unwrap();
        assert!(admission.reserve_proposal(false).is_err());
        assert_eq!(admission.snapshot().pending_entries, 2);
        assert_eq!(admission.snapshot().retained_rows, 2);
        drop(first);
        assert!(admission.has_capacity());
        drop(second);
        assert_eq!(admission.snapshot().pending_entries, 0);
    }

    #[tokio::test]
    async fn log_admission_completion_needs_a_later_metrics_publication() {
        let (send, admission) = fixture(1, 4);
        let growth = admission.reserve_proposal(false).unwrap();
        send.send_modify(|metrics| metrics.last_log_index = Some(2));
        growth.complete(3);
        assert_eq!(admission.snapshot().pending_entries, 1);
        assert!(!admission.has_capacity());
        send.send_modify(|metrics| {
            // A later conflicting suffix may remove the completed append.
            // Its live credit still retires; it is not an index watermark.
            metrics.last_log_index = Some(1);
            metrics.purged = Some(log_id(0));
        });
        assert_eq!(admission.snapshot().pending_entries, 0);
        assert_eq!(admission.snapshot().retained_rows, 1);
        assert!(admission.has_capacity());
    }

    #[tokio::test]
    async fn log_admission_observed_completion_does_not_need_another_write() {
        let (send, admission) = fixture(1, 4);
        let growth = admission.reserve_proposal(false).unwrap();
        send.send_modify(|metrics| metrics.last_log_index = Some(2));
        growth.complete(2);
        assert_eq!(admission.snapshot().pending_entries, 0);
        assert!(admission.has_capacity());
    }

    #[tokio::test]
    async fn log_admission_completion_cohorts_reuse_capacity_after_truncation() {
        let (send, admission) = fixture(0, 5);
        let first = admission.reserve_proposal(false).unwrap();
        let second = admission.reserve_proposal(false).unwrap();
        let cancelled = admission.reserve_proposal(false).unwrap();
        first.complete(1);
        second.complete(2);
        assert_eq!(admission.snapshot().pending_entries, 3);
        drop(cancelled);
        assert_eq!(admission.snapshot().pending_entries, 2);
        let in_flight = admission.reserve_proposal(false).unwrap();
        send.send_modify(|metrics| metrics.last_log_index = Some(1));
        assert_eq!(admission.snapshot().pending_entries, 1);
        in_flight.complete(2);
        assert_eq!(admission.snapshot().pending_entries, 1);
        send.send_modify(|metrics| metrics.last_log_index = Some(0));
        assert_eq!(admission.snapshot().pending_entries, 0);
        let reservations = (0..4)
            .map(|_| admission.reserve_proposal(false).unwrap())
            .collect::<Vec<_>>();
        assert!(!admission.has_capacity());
        drop(reservations);
        assert!(admission.has_capacity());
    }

    #[tokio::test]
    async fn log_admission_reuses_capacity_at_large_absolute_indices() {
        let (send, admission) = fixture(0, 4);
        for base in [1_u64 << 40, 1_u64 << 60, u64::MAX - 4] {
            send.send_modify(|metrics| {
                metrics.last_log_index = Some(base + 3);
                metrics.purged = Some(log_id(base));
                metrics.snapshot = Some(log_id(base + 1));
            });
            assert_eq!(admission.snapshot().retained_rows, 3);
            assert_eq!(admission.snapshot().entries_since_snapshot, 2);
            let growth = admission.reserve_proposal(false).unwrap();
            assert!(!admission.has_capacity());
            send.send_modify(|metrics| {
                metrics.last_log_index = Some(base + 4);
                metrics.purged = Some(log_id(base + 2));
            });
            growth.complete(base + 4);
            assert_eq!(admission.snapshot().retained_rows, 2);
            assert_eq!(admission.snapshot().pending_entries, 0);
            assert!(admission.has_capacity());
        }
    }

    #[tokio::test]
    async fn log_admission_wait_resumes_on_purge_and_obeys_deadline() {
        let (send, admission) = fixture(3, 4);
        let mut waiting = Box::pin(
            admission.ready_before(tokio::time::Instant::now() + std::time::Duration::from_secs(5)),
        );
        assert!(futures_util::poll!(&mut waiting).is_pending());
        assert_eq!(admission.snapshot().pending_entries, 0);
        send.send_modify(|metrics| metrics.purged = Some(log_id(1)));
        assert_eq!(waiting.await, Ok(()));
        send.send_modify(|metrics| metrics.purged = None);
        assert_eq!(
            admission.ready_before(tokio::time::Instant::now()).await,
            Err(LogAdmissionError::Unavailable)
        );
        assert_eq!(admission.snapshot().pending_entries, 0);
    }

    #[tokio::test]
    async fn log_admission_fixed_warning_fractions_clear_after_progress() {
        let (send, admission) = fixture(3, 8);
        assert_eq!(
            admission.snapshot().retained_level,
            ConsensusLogPressureLevel::Elevated
        );
        assert_eq!(
            admission.snapshot().snapshot_level,
            ConsensusLogPressureLevel::Elevated
        );
        send.send_modify(|metrics| metrics.last_log_index = Some(5));
        assert_eq!(
            admission.snapshot().retained_level,
            ConsensusLogPressureLevel::High
        );
        send.send_modify(|metrics| metrics.last_log_index = Some(7));
        assert_eq!(
            admission.snapshot().retained_level,
            ConsensusLogPressureLevel::AtWindow
        );
        send.send_modify(|metrics| {
            metrics.purged = Some(log_id(6));
            metrics.snapshot = Some(log_id(7));
        });
        assert_eq!(
            admission.snapshot().retained_level,
            ConsensusLogPressureLevel::Normal
        );
        assert_eq!(
            admission.snapshot().snapshot_level,
            ConsensusLogPressureLevel::Normal
        );
    }

    #[tokio::test]
    async fn log_admission_review_demotion_wakes_every_waiter() {
        let (send, admission) = fixture(3, 4);
        send.send_modify(|metrics| {
            metrics.current_leader = Some(node());
            metrics.state = opc_consensus::engine::ServerState::Leader;
            metrics.vote = Vote::new_committed(1, node());
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut waiters = (0..8)
            .map(|_| Box::pin(admission.ready_before(deadline)))
            .collect::<Vec<_>>();
        for waiter in &mut waiters {
            assert!(futures_util::poll!(waiter).is_pending());
        }
        let successor = SessionConsensusNodeId::new(2).unwrap();
        send.send_modify(|metrics| {
            metrics.current_leader = Some(successor);
            metrics.state = opc_consensus::engine::ServerState::Follower;
            metrics.vote = Vote::new_committed(2, successor);
        });
        for waiter in &mut waiters {
            assert!(
                matches!(futures_util::poll!(waiter), std::task::Poll::Ready(
                    Err(LogAdmissionError::NotLeader(Some(leader)))) if leader == successor),
                "demotion must wake every waiter without capacity or timer progress"
            );
        }
        assert_eq!(admission.snapshot().pending_entries, 0);
        assert_eq!(admission.snapshot().retained_rows, 4);
        assert!(tokio::time::Instant::now() < deadline);
    }

    #[tokio::test]
    async fn log_admission_follower_preserves_mixed_repair_prefix() {
        let (_send, admission) = fixture(3, 4);
        let mut mixed = append(2..6);
        // A trailing control must not be stranded behind ordinary data.
        mixed.entries[3].payload = EntryPayload::Blank;
        let tracked = admission.track_append(&mixed);
        assert!(tracked.is_some());
        assert_eq!(
            mixed
                .entries
                .iter()
                .map(|entry| entry.log_id.index)
                .collect::<Vec<_>>(),
            vec![2, 3, 4, 5]
        );
        assert_eq!(admission.snapshot().pending_entries, 2);
        drop(tracked);
        let growth = append(4..6);
        assert!(admission.track_append(&growth).is_some());
        assert_eq!(growth.entries.len(), 2);
        let heartbeat = append([]);
        assert!(admission.track_append(&heartbeat).is_none());
        let mut control = append([4]);
        control.entries[0].payload = EntryPayload::Blank;
        assert!(admission.track_append(&control).is_some());
        let mut priority = append([4]);
        let EntryPayload::Normal(command) = &mut priority.entries[0].payload else {
            unreachable!()
        };
        command.intent = SessionMutationIntent::PreflightScopeProfile;
        assert!(
            admission.track_append(&priority).is_some(),
            "all replicated growth passes the follower window regardless of class"
        );
        assert_eq!(admission.snapshot().pending_entries, 0);
    }

    #[tokio::test]
    async fn log_admission_follower_reserves_the_admitted_growth_prefix() {
        let (_send, admission) = fixture(1, 4);
        let rpc = append(2..5);
        let growth = admission.track_append(&rpc).unwrap();
        assert_eq!(rpc.entries.len(), 3);
        assert_eq!(admission.snapshot().pending_entries, 3);
        assert!(admission.reserve_proposal(false).is_err());
        drop(growth);
        assert!(admission.has_capacity());
    }

    #[tokio::test]
    async fn log_admission_recovery_and_topology_control_pass_the_full_window() {
        let (_send, admission) = fixture(3, 4);
        for intent in [
            SessionMutationIntent::AsyncRecoveryBoundary {
                era: 1,
                plan: [1; 32],
                protected: None,
            },
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id: [2; 16],
                request_digest: [3; 32],
            },
            SessionMutationIntent::FenceTopologyAuthority {
                transition_id: [2; 16],
                request_digest: [3; 32],
            },
            SessionMutationIntent::AbortTopologyTransition {
                transition_id: [2; 16],
                request_digest: [3; 32],
            },
            SessionMutationIntent::FinalizeTopologyTransition {
                transition_id: [2; 16],
                request_digest: [3; 32],
            },
        ] {
            let mut rpc = append([4]);
            let EntryPayload::Normal(command) = &mut rpc.entries[0].payload else {
                unreachable!()
            };
            command.intent = intent;
            let tracked = admission.track_append(&rpc);
            assert!(
                tracked.is_some(),
                "engine progress control retains its existing validation and authority"
            );
            assert_eq!(admission.snapshot().pending_entries, 1);
            assert_eq!(rpc.entries.len(), 1);
            drop(tracked);
            assert_eq!(admission.snapshot().pending_entries, 0);
        }
    }

    #[tokio::test]
    async fn log_admission_emergency_headroom_is_counted_without_ordinary_capacity() {
        let (_send, admission) = fixture(3, 4);
        assert!(admission.reserve_proposal(false).is_err());
        let emergency = admission.reserve_proposal(true).unwrap();
        assert_eq!(admission.snapshot().pending_entries, 1);
        assert!(!admission.has_capacity());
        let second = admission.reserve_proposal(true).unwrap();
        assert_eq!(admission.snapshot().pending_entries, 2);
        assert!(admission.reserve_proposal(false).is_err());
        drop(emergency);
        drop(second);
        assert_eq!(admission.snapshot().pending_entries, 0);
        assert!(!admission.has_capacity());
    }
}
