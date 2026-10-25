//! Bounded leader-owned maintenance lane for protected-roster retention.
//!
//! Protected-roster retention is reclaimed by the deterministic maintenance
//! turn folded into ordinary logical-time commands. The frozen Q1/Q2 roster
//! mutation profile must never carry unrelated retention work, so a store that
//! receives only protected-roster admissions has no ordinary command to carry
//! that turn. This lane supplies one: when the published authenticated
//! occupancy reports retained terminal or tombstone reservations, the local
//! leader proposes the existing `AdvanceLogicalTime` intent through the normal
//! authority/deadline path. That ordinary command runs the existing
//! deterministic reclaim/retire turn; retention semantics, the exact 24-hour
//! boundary, caps and the Q1/Q2 mutation width are unchanged.
//!
//! The lane is deliberately bounded: one observation per base tick, one
//! proposal in flight at a time (the loop awaits each proposal), and an
//! exponential back-off up to a fixed ceiling while a turn reclaims nothing.
//! It never reclaims before the existing retention boundary and never falls
//! back to a busy loop.

use super::*;

/// Base observation delay for the roster-maintenance lane.
const ROSTER_MAINTENANCE_TICK: Duration = Duration::from_secs(1);
/// Maximum back-off after consecutive turns that reclaimed no roster state.
const ROSTER_MAINTENANCE_MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Bounded exponential back-off used by the lane.
///
/// Every turn that frees roster occupancy resets the delay to the base tick;
/// a turn that frees nothing doubles it up to the fixed ceiling. The value is
/// bounded below by the base tick and above by the ceiling, so the lane cannot
/// busy-loop when nothing is eligible for reclamation.
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

/// Whether the published occupancy reports protected-roster retention that a
/// deterministic maintenance turn could reclaim or retire.
///
/// Only retained terminal rows (eligible at the exact retention boundary) and
/// compact tombstones (eligible for ordered retirement) are considered. Live
/// reservations are never reclaimed by maintenance and cannot trigger this
/// lane.
const fn roster_maintenance_pending(snapshot: &ProtectedRosterConsensusDiagnosticSnapshot) -> bool {
    snapshot.retained_reservations > 0 || snapshot.tombstone_reservations > 0
}

/// Total retention occupancy the lane uses to detect progress.
const fn roster_maintenance_occupancy(
    snapshot: &ProtectedRosterConsensusDiagnosticSnapshot,
) -> u64 {
    snapshot
        .retained_reservations
        .saturating_add(snapshot.tombstone_reservations)
}

/// The lane's only two interactions with the store.
///
/// Splitting them keeps the bounded scheduling logic independently testable and
/// makes the single-flight property explicit: the driver awaits `propose`
/// before it observes again, so at most one maintenance proposal is in flight.
#[async_trait::async_trait]
trait RosterMaintenanceLane {
    /// Read one coherent published occupancy projection, or `None` when the
    /// owning store has been dropped.
    fn occupancy(&self) -> Option<ProtectedRosterConsensusDiagnosticSnapshot>;

    /// Propose one ordinary logical-time advance, or `None` when the owning
    /// store has been dropped or the proposal could not be accepted through
    /// the leader/authority/deadline path. A returned `Some` does not imply
    /// that a maintenance turn reclaimed anything.
    async fn propose(&self) -> Option<()>;
}

/// Run the bounded lane until the owning store is dropped.
async fn run_roster_maintenance_lane<L>(lane: L)
where
    L: RosterMaintenanceLane,
{
    let mut backoff = RosterMaintenanceBackoff::default();
    loop {
        tokio::time::sleep(backoff.delay()).await;
        let Some(before) = lane.occupancy() else {
            return;
        };
        if !roster_maintenance_pending(&before) {
            backoff.reset();
            continue;
        }
        let Some(()) = lane.propose().await else {
            return;
        };
        let Some(after) = lane.occupancy() else {
            return;
        };
        if roster_maintenance_occupancy(&after) < roster_maintenance_occupancy(&before) {
            backoff.reset();
        } else {
            backoff = backoff.grew();
        }
    }
}

/// Production lane over one store. It holds only a weak reference so the last
/// store owner drops the lane instead of leaving an owner cycle or a task that
/// outlives the store.
#[cfg(not(test))]
struct ConsensusStoreRosterMaintenanceLane {
    inner: Weak<ConsensusSessionStoreInner>,
}

#[cfg(not(test))]
#[async_trait::async_trait]
impl RosterMaintenanceLane for ConsensusStoreRosterMaintenanceLane {
    fn occupancy(&self) -> Option<ProtectedRosterConsensusDiagnosticSnapshot> {
        let inner = self.inner.upgrade()?;
        Some(inner.diagnostics.protected_roster_snapshot())
    }

    async fn propose(&self) -> Option<()> {
        let inner = self.inner.upgrade()?;
        // Leadership can move between the occupancy observation and this
        // proposal. Re-check the local leader fence here; a lost lease simply
        // skips the turn, and the next tick retries. No capability, receipt or
        // mutation is lost because the maintenance command changes no business
        // state.
        if inner.raft.metrics().borrow().current_leader != Some(inner.local_node_id) {
            return Some(());
        }
        let deadline = tokio::time::Instant::now().checked_add(inner.operation_timeout)?;
        let store = ConsensusSessionStore {
            inner: Arc::clone(&inner),
        };
        // `AdvanceLogicalTime` is the existing ordinary logical-time intent.
        // Its committed response makes both native and SQLite state machines
        // run their bounded deterministic roster maintenance turn. This
        // proposal has no opaque payload, consumer scope, wire-format change,
        // Q1/Q2 command or caller-visible outcome.
        let _ = store
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::AdvanceLogicalTime,
                None,
                deadline,
            )
            .await
            .ok()?;
        Some(())
    }
}

/// Start the production roster-maintenance lane for `inner`.
#[cfg(not(test))]
pub(super) fn start(inner: Weak<ConsensusSessionStoreInner>) {
    tokio::spawn(run_roster_maintenance_lane(
        ConsensusStoreRosterMaintenanceLane { inner },
    ));
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
    }

    impl MockObservation {
        fn new(
            retained: u64,
            tombstone: u64,
            proposal_delay: Option<std::time::Duration>,
            clears_on_proposal: bool,
        ) -> Arc<Self> {
            let mut snapshot = ProtectedRosterConsensusDiagnosticSnapshot::default();
            snapshot.retained_reservations = retained;
            snapshot.tombstone_reservations = tombstone;
            Arc::new(Self {
                snapshot: Mutex::new(snapshot),
                proposals: Mutex::new(0),
                proposal_delay,
                clears_on_proposal,
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

        async fn propose(&self) -> Option<()> {
            if !self.alive.load(Ordering::Relaxed) {
                return None;
            }
            *self.observation.proposals.lock().unwrap() += 1;
            if let Some(delay) = self.observation.proposal_delay {
                tokio::time::sleep(delay).await;
            }
            if self.observation.clears_on_proposal {
                *self.observation.snapshot.lock().unwrap() =
                    ProtectedRosterConsensusDiagnosticSnapshot::default();
            }
            Some(())
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
    fn pending_trigger_requires_retained_or_tombstone_occupancy() {
        let mut snapshot = ProtectedRosterConsensusDiagnosticSnapshot::default();
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
        // t=1,2,4,8,16 and then at most once per minute of back-off, never
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
