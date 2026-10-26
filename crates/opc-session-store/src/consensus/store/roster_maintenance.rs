//! Owned, bounded retention maintenance for a store receiving only roster work.
//!
//! Q1/Q2 never carry unrelated retention work. The local leader observes the
//! authenticated reclaim/retirement indexes and proposes an ordinary logical-time
//! command only when that existing bounded maintenance turn can do work. Young
//! rows do not create empty Raft entries. The original retention boundary and
//! mutation widths remain unchanged.

use super::*;

const ROSTER_MAINTENANCE_TICK: Duration = Duration::from_secs(1);
const ROSTER_MAINTENANCE_MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RosterMaintenanceBackoff {
    delay: Duration,
}

impl Default for RosterMaintenanceBackoff {
    fn default() -> Self {
        Self {
            delay: ROSTER_MAINTENANCE_TICK,
        }
    }
}

impl RosterMaintenanceBackoff {
    const fn delay(self) -> Duration {
        self.delay
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn grew(self) -> Self {
        Self {
            delay: self
                .delay
                .checked_mul(2)
                .unwrap_or(ROSTER_MAINTENANCE_MAX_BACKOFF)
                .min(ROSTER_MAINTENANCE_MAX_BACKOFF),
        }
    }
}

/// An invalid projection is unknown, so it requests a bounded authoritative
/// refresh. A valid empty/live-only ledger needs no maintenance observation.
const fn roster_maintenance_pending(snapshot: &ProtectedRosterConsensusDiagnosticSnapshot) -> bool {
    snapshot.occupancy_valid == 0
        || snapshot.retained_reservations > 0
        || snapshot.tombstone_reservations > 0
}

const fn roster_maintenance_progressed(
    before: &ProtectedRosterConsensusDiagnosticSnapshot,
    after: &ProtectedRosterConsensusDiagnosticSnapshot,
) -> bool {
    after.retained_reservations < before.retained_reservations
        || after.tombstone_reservations < before.tombstone_reservations
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RosterMaintenanceOutcome {
    Applied,
    Idle,
    Retry,
}

#[async_trait::async_trait]
trait RosterMaintenanceLane: Sync {
    fn occupancy(&self) -> Option<ProtectedRosterConsensusDiagnosticSnapshot>;
    async fn propose(&self) -> Option<RosterMaintenanceOutcome>;

    /// Returns false on shutdown or when the owning store disappears.
    async fn wait(&self, delay: Duration) -> bool {
        tokio::time::sleep(delay).await;
        true
    }
}

async fn run_roster_maintenance_lane<L: RosterMaintenanceLane>(lane: L) {
    let mut backoff = RosterMaintenanceBackoff::default();
    loop {
        if !lane.wait(backoff.delay()).await {
            return;
        }
        // Recheck once immediately after an applied turn leaves tombstones.
        // At steady arrivals, waiting a full tick would let the next due row
        // win reclaim again. Each proposal keeps the unchanged backend batch
        // bound, and even flat gauges can produce at most two turns per tick.
        for _ in 0..2 {
            let Some(before) = lane.occupancy() else {
                return;
            };
            if !roster_maintenance_pending(&before) {
                backoff.reset();
                break;
            }
            let Some(outcome) = lane.propose().await else {
                return;
            };
            let Some(after) = lane.occupancy() else {
                return;
            };
            // A successful due turn is progress even when concurrent Q2 completions
            // replace its reclaimed count. Gauges are only a fallback for an
            // indeterminate reply that nevertheless published a visible reduction.
            if outcome != RosterMaintenanceOutcome::Retry
                || roster_maintenance_progressed(&before, &after)
            {
                backoff.reset();
            } else {
                backoff = backoff.grew();
            }
            if outcome != RosterMaintenanceOutcome::Applied
                || after.occupancy_valid == 0
                || after.tombstone_reservations == 0
            {
                break;
            }
        }
    }
}

fn roster_maintenance_submission_outcome<T, E>(
    submission: Result<T, E>,
) -> Option<RosterMaintenanceOutcome> {
    Some(if submission.is_ok() {
        RosterMaintenanceOutcome::Applied
    } else {
        RosterMaintenanceOutcome::Retry
    })
}

struct ConsensusStoreRosterMaintenanceLane {
    inner: Weak<ConsensusSessionStoreInner>,
    stop: tokio::sync::watch::Receiver<bool>,
    leadership: std::sync::Mutex<Option<(Option<SessionConsensusNodeId>, u64)>>,
}

#[async_trait::async_trait]
impl RosterMaintenanceLane for ConsensusStoreRosterMaintenanceLane {
    fn occupancy(&self) -> Option<ProtectedRosterConsensusDiagnosticSnapshot> {
        Some(
            self.inner
                .upgrade()?
                .diagnostics
                .protected_roster_snapshot(),
        )
    }

    async fn wait(&self, delay: Duration) -> bool {
        let Some(inner) = self.inner.upgrade() else {
            return false;
        };
        if *self.stop.borrow() || inner.retirement.is_started() {
            return false;
        }
        let mut metrics = inner.raft.metrics();
        drop(inner);
        let mut stop = self.stop.clone();
        let deadline = tokio::time::Instant::now() + delay;
        loop {
            if *stop.borrow_and_update() {
                return false;
            }
            let changed = {
                let status = metrics.borrow_and_update();
                if status.running_state.is_err() {
                    return false;
                }
                let current = (status.current_leader, status.vote.leader_id.term);
                let mut previous = self
                    .leadership
                    .lock()
                    .expect("roster leadership observation");
                previous
                    .replace(current)
                    .is_some_and(|previous| previous != current)
            };
            if changed {
                return true;
            }
            tokio::select! {
                biased;
                _ = stop.changed() => return false,
                () = tokio::time::sleep_until(deadline) => return true,
                changed = metrics.changed() => if changed.is_err() { return false; },
            }
            // Commit/heartbeat publications do not restart the fixed sleep or
            // cause another observation. Only leadership or term wakes early.
        }
    }

    async fn propose(&self) -> Option<RosterMaintenanceOutcome> {
        let inner = self.inner.upgrade()?;
        if *self.stop.borrow() || inner.retirement.is_started() {
            return None;
        }
        if inner.raft.metrics().borrow().current_leader != Some(inner.local_node_id) {
            return Some(RosterMaintenanceOutcome::Idle);
        }
        let deadline = tokio::time::Instant::now().checked_add(inner.operation_timeout)?;
        let generation = inner
            .diagnostics
            .protected_roster_snapshot()
            .occupancy_generation;
        let due = tokio::time::timeout_at(
            deadline,
            inner.backend.consensus_protected_roster_maintenance_due(
                inner.storage_identity,
                inner.clock.now_utc(),
            ),
        )
        .await;
        let due = match due {
            Ok(Ok((occupancy, due))) => {
                inner
                    .diagnostics
                    .refresh_protected_roster_occupancy(generation, Some(occupancy));
                due
            }
            _ => {
                inner
                    .diagnostics
                    .refresh_protected_roster_occupancy(generation, None);
                return Some(RosterMaintenanceOutcome::Retry);
            }
        };
        if !due {
            return Some(RosterMaintenanceOutcome::Idle);
        }
        if *self.stop.borrow() || inner.retirement.is_started() {
            return None;
        }
        let local = inner.local_node_id;
        let store = ConsensusSessionStore { inner };
        // This path repeats local authority, retirement and deadline checks.
        // It cannot route a late maintenance proposal to another leader.
        let reply = store
            .apply_on_local_leader_inner(
                ForwardMutationRequest {
                    work_class: ForwardWorkClass::Inferred,
                    request_id: SessionConsensusRequestId::new(),
                    intent: SessionMutationIntent::AdvanceLogicalTime,
                    required_consumer_scope: ForwardConsumerScope::Internal,
                },
                local,
                deadline,
                false,
                None,
            )
            .await;
        let result = match reply {
            ForwardMutationReply::Applied(response) => match response.result {
                Ok(SessionMutationOutcome::Unit) => Ok(()),
                _ => Err(()),
            },
            _ => Err(()),
        };
        roster_maintenance_submission_outcome(result)
    }
}

pub(super) struct RosterMaintenanceTask {
    stop: tokio::sync::watch::Sender<bool>,
    worker: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl RosterMaintenanceTask {
    pub(super) async fn shutdown(&self) {
        self.stop.send_replace(true);
        let mut worker = self.worker.lock().await;
        // Keep the handle owned until joined if an observing shutdown is
        // cancelled. No proposal is abandoned after acceptance.
        if let Some(task) = worker.as_mut() {
            let _ = task.await;
        }
        worker.take();
    }
}

#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
impl RosterMaintenanceTask {
    pub(super) async fn is_finished_for_test(&self) -> bool {
        self.worker
            .lock()
            .await
            .as_ref()
            .is_none_or(|task| task.is_finished())
    }

    pub(super) async fn abort_for_test(&self) {
        if let Some(task) = self.worker.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

pub(super) fn start(inner: Weak<ConsensusSessionStoreInner>) -> RosterMaintenanceTask {
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let lane = ConsensusStoreRosterMaintenanceLane {
        inner,
        stop: stopped,
        leadership: std::sync::Mutex::new(None),
    };
    RosterMaintenanceTask {
        stop,
        worker: tokio::sync::Mutex::new(Some(tokio::spawn(run_roster_maintenance_lane(lane)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockObservation {
        snapshot: Mutex<ProtectedRosterConsensusDiagnosticSnapshot>,
        proposals: Mutex<usize>,
        proposal_delay: Option<std::time::Duration>,
        clears_on_proposal: bool,
        applies_without_count_reduction: std::sync::atomic::AtomicBool,
        retry_followups: std::sync::atomic::AtomicBool,
        /// Simulate the owning store disappearing immediately after this many
        /// proposals.
        drop_after: Mutex<Option<usize>>,
    }

    impl MockObservation {
        fn new(
            retained: u64,
            tombstone: u64,
            proposal_delay: Option<std::time::Duration>,
            clears_on_proposal: bool,
        ) -> Arc<Self> {
            let snapshot = ProtectedRosterConsensusDiagnosticSnapshot {
                occupancy_valid: 1,
                retained_reservations: retained,
                tombstone_reservations: tombstone,
                ..Default::default()
            };
            Arc::new(Self {
                snapshot: Mutex::new(snapshot),
                proposals: Mutex::new(0),
                proposal_delay,
                clears_on_proposal,
                applies_without_count_reduction: std::sync::atomic::AtomicBool::new(false),
                retry_followups: std::sync::atomic::AtomicBool::new(false),
                drop_after: Mutex::new(None),
            })
        }

        fn occupancy(&self) -> ProtectedRosterConsensusDiagnosticSnapshot {
            *self.snapshot.lock().unwrap()
        }
    }

    struct MockLane {
        observation: Arc<MockObservation>,
        alive: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RosterMaintenanceLane for MockLane {
        fn occupancy(&self) -> Option<ProtectedRosterConsensusDiagnosticSnapshot> {
            if !self.alive.load(Ordering::Relaxed) {
                return None;
            }
            Some(self.observation.occupancy())
        }

        async fn propose(&self) -> Option<RosterMaintenanceOutcome> {
            if !self.alive.load(Ordering::Relaxed) {
                return None;
            }
            *self.observation.proposals.lock().unwrap() += 1;
            if let Some(delay) = self.observation.proposal_delay {
                tokio::time::sleep(delay).await;
            }
            if self.observation.clears_on_proposal {
                *self.observation.snapshot.lock().unwrap() =
                    ProtectedRosterConsensusDiagnosticSnapshot {
                        occupancy_valid: 1,
                        ..Default::default()
                    };
            }
            let drop_now = self
                .observation
                .drop_after
                .lock()
                .unwrap()
                .is_some_and(|limit| *self.observation.proposals.lock().unwrap() >= limit);
            if drop_now {
                self.alive.store(false, Ordering::Relaxed);
            }
            if self.observation.retry_followups.load(Ordering::Relaxed)
                && *self.observation.proposals.lock().unwrap() % 2 == 0
            {
                return Some(RosterMaintenanceOutcome::Retry);
            }
            Some(
                if self.observation.clears_on_proposal
                    || self
                        .observation
                        .applies_without_count_reduction
                        .load(Ordering::Relaxed)
                {
                    RosterMaintenanceOutcome::Applied
                } else {
                    RosterMaintenanceOutcome::Retry
                },
            )
        }
    }

    fn spawn_mock(
        observation: Arc<MockObservation>,
    ) -> (
        Arc<std::sync::atomic::AtomicBool>,
        tokio::task::JoinHandle<()>,
    ) {
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let task = tokio::spawn(run_roster_maintenance_lane(MockLane {
            observation: Arc::clone(&observation),
            alive: Arc::clone(&alive),
        }));
        (alive, task)
    }

    fn proposals(observation: &MockObservation) -> usize {
        *observation.proposals.lock().unwrap()
    }

    #[test]
    fn backoff_is_bounded_and_only_resets_to_the_base_tick() {
        let mut backoff = RosterMaintenanceBackoff::default();
        assert_eq!(backoff.delay(), ROSTER_MAINTENANCE_TICK);
        for _ in 0..64 {
            backoff = backoff.grew();
        }
        assert_eq!(backoff.delay(), ROSTER_MAINTENANCE_MAX_BACKOFF);
        backoff.reset();
        assert_eq!(backoff.delay(), ROSTER_MAINTENANCE_TICK);
    }

    #[test]
    fn unknown_occupancy_requests_a_bounded_refresh() {
        assert!(
            roster_maintenance_pending(&ProtectedRosterConsensusDiagnosticSnapshot::default()),
            "an unknown projection must be refreshed instead of treated as an empty ledger"
        );
    }

    #[test]
    fn pending_trigger_requires_retained_or_tombstone_occupancy() {
        let mut snapshot = ProtectedRosterConsensusDiagnosticSnapshot {
            occupancy_valid: 1,
            ..Default::default()
        };
        assert!(!roster_maintenance_pending(&snapshot));
        snapshot.live_reservations = 5;
        assert!(
            !roster_maintenance_pending(&snapshot),
            "live reservations are never reclaimed by maintenance"
        );
        snapshot.retained_reservations = 1;
        assert!(roster_maintenance_pending(&snapshot));
        snapshot.retained_reservations = 0;
        snapshot.tombstone_reservations = 1;
        assert!(roster_maintenance_pending(&snapshot));
    }

    #[tokio::test(start_paused = true)]
    async fn no_occupancy_never_proposes() {
        let observation = MockObservation::new(0, 0, None, false);
        let (alive, task) = spawn_mock(Arc::clone(&observation));
        for _ in 0..16 {
            tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(proposals(&observation), 0);
        alive.store(false, Ordering::Relaxed);
        tokio::time::advance(ROSTER_MAINTENANCE_MAX_BACKOFF).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_retention_backs_off_instead_of_storming() {
        let observation = MockObservation::new(1, 0, None, false);
        let (alive, task) = spawn_mock(Arc::clone(&observation));
        // Drive 30 seconds of virtual time. The lane may propose at
        // t=1,3,7,15,31 and then at most once per minute of back-off, never
        // once per tick.
        for _ in 0..30 {
            tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
            tokio::task::yield_now().await;
        }
        let stalled = proposals(&observation);
        assert!(
            (1..=6).contains(&stalled),
            "no-progress turns must back off, got {stalled} proposals in 30 ticks"
        );
        alive.store(false, Ordering::Relaxed);
        tokio::time::advance(ROSTER_MAINTENANCE_MAX_BACKOFF).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;
    }

    #[test]
    fn transient_submission_errors_are_bounded_skips_not_teardown() {
        // A transient submission error (leadership
        // stepdown, no-quorum/operator-recovery gate, deadline expiry,
        // OutcomeUnknown, backend unavailability) must keep the lane alive.
        // `None` is reserved for store disappearance or shutdown.
        let rejected: Result<(), StoreError> = Err(StoreError::BackendUnavailable(
            "transient roster maintenance submission failure".into(),
        ));
        assert_eq!(
            roster_maintenance_submission_outcome(rejected),
            Some(RosterMaintenanceOutcome::Retry),
            "a transient submission error is a bounded skip, never teardown"
        );
        let accepted: Result<SessionConsensusResponse, StoreError> =
            Err(StoreError::BackendOperationOutcomeUnavailable);
        assert_eq!(
            roster_maintenance_submission_outcome(accepted),
            Some(RosterMaintenanceOutcome::Retry),
            "outcome-unknown also keeps the lane alive for a later bounded retry"
        );
    }

    #[test]
    fn reclaim_is_progress_even_when_the_retained_plus_tombstone_total_is_flat() {
        // Reclaim moves one retained terminal row into one tombstone, so the
        // total stays flat while real progress was made.
        let before = ProtectedRosterConsensusDiagnosticSnapshot {
            occupancy_valid: 1,
            retained_reservations: 1,
            ..Default::default()
        };
        let after = ProtectedRosterConsensusDiagnosticSnapshot {
            occupancy_valid: 1,
            tombstone_reservations: 1,
            ..Default::default()
        };
        assert!(
            roster_maintenance_progressed(&before, &after),
            "retained -> tombstone must reset the lane back-off"
        );
        assert!(!roster_maintenance_progressed(&before, &before));
        let cleared = ProtectedRosterConsensusDiagnosticSnapshot::default();
        assert!(
            roster_maintenance_progressed(&after, &cleared),
            "tombstone retirement is progress"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn applied_maintenance_keeps_its_tick_when_concurrent_q2_replaces_reclaimed_rows() {
        let observation = MockObservation::new(1, 0, None, false);
        observation
            .applies_without_count_reduction
            .store(true, Ordering::Relaxed);
        let (alive, task) = spawn_mock(Arc::clone(&observation));
        // Each due command succeeds, while another Q2 leaves both gauges flat.
        // The applied reply must keep the bounded drain at its base cadence.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        for _ in 0..8 {
            tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
        assert_eq!(proposals(&observation), 8);
        assert_eq!(observation.occupancy().retained_reservations, 1);
        alive.store(false, Ordering::Relaxed);
        tokio::time::advance(ROSTER_MAINTENANCE_MAX_BACKOFF).await;
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("dropped owner stops the lane")
            .expect("lane joins");
    }

    struct SteadyRosterLane {
        start: tokio::time::Instant,
        state: Arc<Mutex<(u64, u64, u64)>>,
        alive: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RosterMaintenanceLane for SteadyRosterLane {
        fn occupancy(&self) -> Option<ProtectedRosterConsensusDiagnosticSnapshot> {
            if !self.alive.load(Ordering::Relaxed) {
                return None;
            }
            let (reclaimed, retired, _) = *self.state.lock().unwrap();
            Some(ProtectedRosterConsensusDiagnosticSnapshot {
                occupancy_valid: 1,
                retained_reservations: 16 - reclaimed,
                tombstone_reservations: reclaimed - retired,
                ..Default::default()
            })
        }

        async fn propose(&self) -> Option<RosterMaintenanceOutcome> {
            // Model sixteen history completions at half-second intervals
            // become eligible exactly 24 hours later, at the same rate. Model
            // both backends' existing reclaim-first, one-action command seam.
            let due = (self.start.elapsed().as_millis() / 500).min(16) as u64;
            let mut state = self.state.lock().unwrap();
            state.2 += 1;
            if state.0 < due {
                state.0 = due;
            } else if state.1 < state.0 {
                state.1 = state.0;
            } else {
                return Some(RosterMaintenanceOutcome::Idle);
            }
            Some(RosterMaintenanceOutcome::Applied)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn roster_maintenance_retires_during_steady_half_second_arrivals() {
        let state = Arc::new(Mutex::new((0, 0, 0)));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let task = tokio::spawn(run_roster_maintenance_lane(SteadyRosterLane {
            start: tokio::time::Instant::now(),
            state: Arc::clone(&state),
            alive: Arc::clone(&alive),
        }));
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        for _ in 0..16 {
            tokio::time::advance(Duration::from_millis(500)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
        let (reclaimed, retired, proposals) = *state.lock().unwrap();
        alive.store(false, Ordering::Relaxed);
        tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
        task.await.unwrap();
        assert_eq!(reclaimed, 16, "reclaim retains its existing throughput");
        assert!(
            retired >= 14,
            "steady arrivals must not starve retirement: reclaimed={reclaimed}, retired={retired}"
        );
        assert!(
            proposals <= 16,
            "follow-up work is bounded to two commands per tick"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn roster_maintenance_bounds_followups_when_applied_gauges_stay_flat() {
        let observation = MockObservation::new(1, 1, None, false);
        observation
            .applies_without_count_reduction
            .store(true, Ordering::Relaxed);
        let (alive, task) = spawn_mock(Arc::clone(&observation));
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        for _ in 0..8 {
            tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
        assert!(
            (8..=16).contains(&proposals(&observation)),
            "concurrent arrivals or predicate mismatch cannot cause a proposal storm"
        );
        alive.store(false, Ordering::Relaxed);
        tokio::time::advance(ROSTER_MAINTENANCE_MAX_BACKOFF).await;
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn roster_maintenance_keeps_reclaim_cadence_after_followup_failure() {
        let observation = MockObservation::new(1, 1, None, false);
        observation
            .applies_without_count_reduction
            .store(true, Ordering::Relaxed);
        observation.retry_followups.store(true, Ordering::Relaxed);
        let (alive, task) = spawn_mock(Arc::clone(&observation));
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        for _ in 0..8 {
            tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
        let attempts = proposals(&observation);
        alive.store(false, Ordering::Relaxed);
        tokio::time::advance(ROSTER_MAINTENANCE_MAX_BACKOFF).await;
        task.await.unwrap();
        assert_eq!(
            attempts, 16,
            "a failed optional follow-up must not slow successful reclaim below one turn per tick"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_store_stops_the_lane() {
        let observation = MockObservation::new(1, 0, None, false);
        *observation.drop_after.lock().unwrap() = Some(1);
        let (_, task) = spawn_mock(Arc::clone(&observation));
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        for _ in 0..16 {
            tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(proposals(&observation), 1);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("the lane exits once Weak::upgrade fails")
            .expect("lane task does not panic");
    }

    #[tokio::test(start_paused = true)]
    async fn one_proposal_in_flight_and_progress_resets_the_tick() {
        let observation =
            MockObservation::new(1, 0, Some(std::time::Duration::from_secs(10)), true);
        let (alive, task) = spawn_mock(Arc::clone(&observation));
        // Let the spawned lane register its first timer before moving paused
        // virtual time.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
            if proposals(&observation) == 1 {
                break;
            }
        }
        assert_eq!(
            proposals(&observation),
            1,
            "the lane awaits its single in-flight proposal"
        );
        // Many base ticks elapse while the proposal is in flight; they must not
        // start another proposal.
        for _ in 0..9 {
            tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(
            proposals(&observation),
            1,
            "coalescing keeps at most one maintenance proposal in flight"
        );
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(proposals(&observation), 1);
        alive.store(false, Ordering::Relaxed);
        tokio::time::advance(ROSTER_MAINTENANCE_MAX_BACKOFF).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;
    }
}
