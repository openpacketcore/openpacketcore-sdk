//! Conditional backlog proof using the production loop and its default sleep.
//!
//! Arrivals are ten rows at each independent one-second boundary for 180 seconds.
//! Assume a healthy lane, one partition, a distinct admission epoch per row,
//! two phases per turn, at most 1.25 seconds of service per phase, and at most
//! 0.25 seconds of dispatch jitter per turn. The 1,024-row phase cap is unchanged.
//! Every captured prefix is eligible: there are no retries, authority changes or
//! deferred-profile barriers. The one-second tick includes service; overruns coalesce without another idle
//! second. Consecutive reclaim snapshots are therefore at most
//! max(1 second, 2 * 1.25 seconds) + 0.25 seconds = 2.75 seconds apart.
//! A row arriving just after one snapshot waits at most another 1.25 seconds
//! for the next reclaim to commit: four seconds, or four ten-row buckets.
//! A retirement phase finishes before another reclaim, so at most the three
//! buckets between reclaim snapshots can coexist as tombstones. The initial
//! tick plus jitter plus service is also below four seconds. These are service
//! assumptions, not consequences of the store's ten-second operation deadline.

use super::*;
use std::sync::Mutex;
use tokio::sync::{mpsc, oneshot};

const RATE: u64 = 10;
const SECONDS: u64 = 180;
const ROWS: u64 = RATE * SECONDS;
const BOUND: u64 = 40;
const MAX_SERVICE: Duration = Duration::from_millis(1250);
const DISPATCH_JITTER: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
enum Phase {
    Reclaim(u64),
    Retire(u64),
}

#[derive(Debug, Default, Clone)]
struct Observations {
    peak_due: u64,
    peak_tombstones: u64,
    boundary_samples: u64,
    boundaries_in_flight: u64,
    completion_samples: u64,
    first_breach: Option<Duration>,
    maximum_dispatch: Duration,
    maximum_service: Duration,
    maximum_reclaim_gap: Duration,
}

impl Observations {
    fn within_bound(&self) -> bool {
        self.peak_due <= BOUND && self.peak_tombstones <= BOUND
    }
}

struct Ledger {
    start: tokio::time::Instant,
    alive: bool,
    arrived: u64,
    reclaimed: u64,
    retired: u64,
    in_flight: bool,
    last_reclaim: Option<tokio::time::Instant>,
    observations: Observations,
}

impl Ledger {
    fn sample(&mut self) {
        let due = self.arrived.checked_sub(self.reclaimed).unwrap();
        let tombstones = self.reclaimed.checked_sub(self.retired).unwrap();
        self.observations.peak_due = self.observations.peak_due.max(due);
        self.observations.peak_tombstones = self.observations.peak_tombstones.max(tombstones);
        if !self.observations.within_bound() {
            self.observations
                .first_breach
                .get_or_insert(self.start.elapsed());
        }
    }
}

#[derive(Debug)]
enum DelayKind {
    Dispatch,
    Service,
}

#[derive(Debug)]
struct ServiceGate {
    started: tokio::time::Instant,
    kind: DelayKind,
    release: oneshot::Sender<()>,
}

struct ArrivalLane {
    ledger: Arc<Mutex<Ledger>>,
    service: mpsc::UnboundedSender<ServiceGate>,
}

impl ArrivalLane {
    async fn delay(&self, kind: DelayKind) -> Duration {
        let started = tokio::time::Instant::now();
        let (release, completion) = oneshot::channel();
        self.service
            .send(ServiceGate {
                started,
                kind,
                release,
            })
            .expect("the independent clock owns the delay gate");
        completion.await.expect("the delay gate completes");
        started.elapsed()
    }
}

#[async_trait::async_trait]
impl RosterMaintenanceLane for ArrivalLane {
    // Deliberately inherit RosterMaintenanceLane::wait: the production
    // tokio::time::sleep(delay) and elapsed-service cadence are under test.
    fn occupancy(&self) -> Option<ProtectedRosterConsensusDiagnosticSnapshot> {
        let ledger = self.ledger.lock().unwrap();
        ledger
            .alive
            .then_some(ProtectedRosterConsensusDiagnosticSnapshot {
                occupancy_valid: 1,
                retained_reservations: ROWS - ledger.reclaimed,
                tombstone_reservations: ledger.reclaimed - ledger.retired,
                ..Default::default()
            })
    }

    async fn propose(&self) -> Option<RosterMaintenanceOutcome> {
        let needs_dispatch = {
            let ledger = self.ledger.lock().unwrap();
            ledger.retired == ledger.reclaimed && ledger.reclaimed < ledger.arrived
        };
        if needs_dispatch {
            // Exercise the full jitter allowance before each reclaim snapshot,
            // including immediate turns after an overrun. The production wait
            // is untouched and the arrival clock continues through this gate.
            let dispatch = self.delay(DelayKind::Dispatch).await;
            let mut ledger = self.ledger.lock().unwrap();
            ledger.observations.maximum_dispatch =
                ledger.observations.maximum_dispatch.max(dispatch);
        }
        let started = tokio::time::Instant::now();
        let phase = {
            let mut ledger = self.ledger.lock().unwrap();
            let batch = crate::fenced_mutation_roster::RECLAIM_BATCH as u64;
            // Ordinals represent distinct epochs in the one ordered partition.
            // Capture the eligible prefix before service, so arrivals during an
            // in-flight proposal cannot be silently included in its result.
            let phase = if ledger.retired < ledger.reclaimed {
                Phase::Retire((ledger.retired + batch).min(ledger.reclaimed))
            } else if ledger.reclaimed < ledger.arrived {
                if let Some(previous) = ledger.last_reclaim.replace(started) {
                    ledger.observations.maximum_reclaim_gap = ledger
                        .observations
                        .maximum_reclaim_gap
                        .max(started - previous);
                }
                Phase::Reclaim((ledger.reclaimed + batch).min(ledger.arrived))
            } else {
                return Some(RosterMaintenanceOutcome::Idle);
            };
            assert!(!ledger.in_flight, "only one proposal may be in flight");
            ledger.in_flight = true;
            phase
        };
        let service = self.delay(DelayKind::Service).await;
        let mut ledger = self.ledger.lock().unwrap();
        match phase {
            Phase::Reclaim(through) => {
                assert!(ledger.reclaimed < through && through <= ledger.arrived);
                ledger.reclaimed = through;
            }
            Phase::Retire(through) => {
                assert!(ledger.retired < through && through <= ledger.reclaimed);
                ledger.retired = through;
            }
        }
        ledger.in_flight = false;
        ledger.observations.maximum_service = ledger.observations.maximum_service.max(service);
        ledger.observations.completion_samples += 1;
        ledger.sample();
        Some(RosterMaintenanceOutcome::Applied)
    }
}

async fn independent_arrivals(service: Duration) -> Observations {
    assert_eq!(service.as_millis() % DISPATCH_JITTER.as_millis(), 0);
    let start = tokio::time::Instant::now();
    let ledger = Arc::new(Mutex::new(Ledger {
        start,
        alive: true,
        arrived: 0,
        reclaimed: 0,
        retired: 0,
        in_flight: false,
        last_reclaim: None,
        observations: Observations::default(),
    }));
    let (service_tx, mut service_rx) = mpsc::unbounded_channel();
    let mut worker = Box::pin(run_roster_maintenance_lane(ArrivalLane {
        ledger: Arc::clone(&ledger),
        service: service_tx,
    }));
    assert!(futures_util::poll!(&mut worker).is_pending());
    let mut gate: Option<ServiceGate> = None;
    // Advance time independently of the worker. Explicit gates inject the full
    // 250 ms dispatch jitter and the selected service time. Every gate duration
    // is a multiple of the step, so polling adds no unmeasured completion lag.
    // The production sleep, including zero-delay overrun coalescing, remains.
    // Neither dispatch nor completion gates control the arrival clock.
    // After arrivals end, two full turns suffice to finish an already captured
    // prefix and the final arrivals. This also joins the slow negative control.
    let end = Duration::from_secs(SECONDS) + 4 * service + 2 * ROSTER_MAINTENANCE_TICK;
    while start.elapsed() < end {
        tokio::time::advance(DISPATCH_JITTER).await;
        let elapsed = start.elapsed();
        if elapsed <= Duration::from_secs(SECONDS) && elapsed.subsec_nanos() == 0 {
            let mut state = ledger.lock().unwrap();
            state.arrived += RATE;
            assert_eq!(state.arrived, elapsed.as_secs() * RATE);
            state.observations.boundary_samples += 1;
            let in_flight = state.in_flight;
            state.observations.boundaries_in_flight += u64::from(in_flight);
            // Sample before releasing a coincident completion: this includes
            // the new bucket even when a service result is about to arrive.
            state.sample();
        }
        if gate.as_ref().is_some_and(|pending| {
            let delay = match pending.kind {
                DelayKind::Dispatch => DISPATCH_JITTER,
                DelayKind::Service => service,
            };
            pending.started.elapsed() >= delay
        }) {
            gate.take().unwrap().release.send(()).unwrap();
        }
        assert!(futures_util::poll!(&mut worker).is_pending());
        if let Ok(request) = service_rx.try_recv() {
            assert!(gate.replace(request).is_none(), "one owned service gate");
            assert!(service_rx.try_recv().is_err(), "no parallel proposal");
        }
        let state = ledger.lock().unwrap();
        if state.arrived == ROWS && state.retired == ROWS {
            break;
        }
    }
    let observations = {
        let mut state = ledger.lock().unwrap();
        assert_eq!(state.arrived, ROWS, "all 180 arrival boundaries execute");
        assert_eq!(state.reclaimed, ROWS, "every due row drains");
        assert_eq!(state.retired, ROWS, "every distinct epoch retires");
        assert!(!state.in_flight);
        assert!(gate.is_none());
        assert_eq!(state.observations.boundary_samples, SECONDS);
        assert!(state.observations.boundaries_in_flight > 0);
        assert!(state.observations.completion_samples > 0);
        state.alive = false;
        state.observations.clone()
    };
    tokio::time::advance(ROSTER_MAINTENANCE_TICK).await;
    assert!(
        futures_util::poll!(&mut worker).is_ready(),
        "the lane joins"
    );
    eprintln!("independent arrival model: service={service:?}, {observations:?}");
    observations
}

#[tokio::test(start_paused = true)]
async fn independent_arrivals_stay_within_four_buckets_under_service_assumptions() {
    for service in [Duration::from_millis(500), MAX_SERVICE] {
        let observations = independent_arrivals(service).await;
        assert!(
            observations.within_bound(),
            "independent arrivals must stay within {BOUND} rows: {observations:?}"
        );
        assert_eq!(observations.maximum_dispatch, DISPATCH_JITTER);
        assert!(observations.maximum_service <= MAX_SERVICE);
        assert!(
            observations.maximum_reclaim_gap
                <= ROSTER_MAINTENANCE_TICK.max(2 * MAX_SERVICE) + DISPATCH_JITTER
        );
    }
}

#[tokio::test(start_paused = true)]
async fn slow_service_breaches_the_independent_arrival_bound() {
    let observations = independent_arrivals(Duration::from_secs(6)).await;
    assert!(observations.maximum_service > MAX_SERVICE);
    assert!(
        !observations.within_bound(),
        "the same bound check must reject service outside its assumptions"
    );
    assert!(observations.peak_due > BOUND);
    assert!(
        observations.first_breach.unwrap() <= Duration::from_secs(6),
        "arrivals breach the bound before the first slow proposal completes"
    );
}
