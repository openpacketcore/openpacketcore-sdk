//! Declarative, lease-gated prefix advertisement service.
//!
//! The service owns the caller-facing reconcile semantics on top of a
//! [`RoutingStackAdapter`]: callers declare "this exact host-prefix set should
//! be advertised now" per routing domain, gated by a health lease whose
//! deadline is driven by an injected clock. The service computes the delta,
//! enforces the generation rules shared with
//! [`crate::vip::VipOwnershipCoordinator`], and emits the typed telemetry
//! stream the caller uses to act on routing health.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_session_store::{Clock, SystemClock};
use opc_types::Timestamp;
use tokio::sync::{broadcast, oneshot, watch, Notify};

use crate::error::IpsecLbError;
use crate::ownership::RoutingDomainTag;
use crate::routing::{
    AdvertisedPrefix, AdvertisementLease, AdvertisementSetDisposition, HostPrefix, LeaseGeneration,
    PathHealth, PeerIdentity, PeerSessionChangeReason, PeerSessionState, PrefixAdvertisementState,
    PrefixApplyOutcome, PrefixRejectReason, PrefixStatusSnapshot, PrefixWithdrawReason,
    RoutingEvent, RoutingEventKind, RoutingStackAdapter, MAX_ADVERTISED_PREFIXES_PER_DOMAIN,
    MAX_ADVERTISEMENT_ROUTING_DOMAINS, MAX_ROUTING_MUTATION_DURATION, MAX_ROUTING_PEERS_PER_DOMAIN,
    MAX_ROUTING_PEERS_TOTAL, MAX_ROUTING_PEER_NAME_LEN,
};

/// Default capacity of the broadcast event channel.
const EVENT_CHANNEL_CAPACITY: usize = 256;
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);
const MAX_PEER_RETENTION_SECS: u64 = 86_400;
const MAX_POSSIBLY_AFFECTED_PREFIXES_PER_DOMAIN: usize = MAX_ADVERTISED_PREFIXES_PER_DOMAIN * 2;

/// Service configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixAdvertiserConfig {
    /// Watchdog cadence. Lease expiry is detected within one interval and
    /// peer observations are polled once per interval. The complete
    /// enforcement bound also includes adapter mutation time; query
    /// [`PrefixAdvertiserService::lease_enforcement_bound`]. The bound applies
    /// only while [`PrefixAdvertiserService::run`] is independently supervised.
    pub poll_interval: Duration,
    /// Maximum prefixes admitted to one routing-domain reconcile.
    pub max_prefixes_per_domain: usize,
    /// How long a peer that vanished from stack observations is retained
    /// after its session-down transition, in seconds.
    pub peer_retention_secs: u64,
}

impl Default for PrefixAdvertiserConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            max_prefixes_per_domain: MAX_ADVERTISED_PREFIXES_PER_DOMAIN,
            peer_retention_secs: 600,
        }
    }
}

impl PrefixAdvertiserConfig {
    /// Validate the service configuration.
    pub fn validate(self) -> Result<(), IpsecLbError> {
        if self.poll_interval.is_zero() {
            return Err(IpsecLbError::invalid_config(
                "poll_interval",
                "poll interval must be non-zero",
            ));
        }
        if self.poll_interval > MAX_POLL_INTERVAL {
            return Err(IpsecLbError::invalid_config(
                "poll_interval",
                "poll interval exceeds the production bound",
            ));
        }
        if self.max_prefixes_per_domain == 0 {
            return Err(IpsecLbError::invalid_config(
                "max_prefixes_per_domain",
                "prefix bound must be non-zero",
            ));
        }
        if self.max_prefixes_per_domain > MAX_ADVERTISED_PREFIXES_PER_DOMAIN {
            return Err(IpsecLbError::invalid_config(
                "max_prefixes_per_domain",
                "prefix bound exceeds the hard production ceiling",
            ));
        }
        if self.peer_retention_secs > MAX_PEER_RETENTION_SECS {
            return Err(IpsecLbError::invalid_config(
                "peer_retention_secs",
                "peer retention exceeds the production bound",
            ));
        }
        Ok(())
    }
}

/// Disposition of one declarative reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReconcileDisposition {
    /// Every desired prefix was accepted into the routing stack's local
    /// originated set. Consult snapshots/events for exact peer-export state.
    Applied,
    /// The exact same intent was already in effect; no adapter mutation ran.
    Retained,
    /// At least one desired prefix was rejected or unreachable.
    PartiallyRejected,
    /// The intent carried no authorizing lease; the domain was withdrawn.
    Withdrawn,
    /// The intent carried a generation that cannot authorize advertisement;
    /// the domain was failed closed to withdrawn.
    StaleRejected,
}

impl ReconcileDisposition {
    /// Stable machine-readable disposition code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Retained => "retained",
            Self::PartiallyRejected => "partially_rejected",
            Self::Withdrawn => "withdrawn",
            Self::StaleRejected => "stale_rejected",
        }
    }
}

/// Typed result of one declarative reconcile.
#[derive(Debug, Clone)]
pub struct PrefixReconcileReport {
    /// Routing domain reconciled.
    pub domain: RoutingDomainTag,
    /// Overall reconcile disposition.
    pub disposition: ReconcileDisposition,
    /// Typed per-prefix outcomes for the desired set.
    pub outcomes: BTreeMap<HostPrefix, PrefixApplyOutcome>,
}

#[derive(Debug, Clone, Copy, Default)]
struct PrefixTrack {
    originated: bool,
    export_evidence_pending: bool,
    state: PrefixAdvertisementState,
    last_transition: Option<Timestamp>,
    last_withdraw_reason: Option<PrefixWithdrawReason>,
}

#[derive(Debug, Default)]
struct DomainState {
    highest_generation: Option<LeaseGeneration>,
    lease_deadline: Option<Timestamp>,
    advertised_generation: Option<LeaseGeneration>,
    desired: BTreeSet<HostPrefix>,
    prefixes: BTreeMap<HostPrefix, PrefixTrack>,
    intent_revision: u64,
    /// True from intent admission until the matching adapter mutation reaches
    /// a terminal outcome. Observations captured in this window predate the
    /// authoritative mutation result even when the intent revision matches.
    mutation_in_flight: bool,
    withdraw_pending: bool,
    withdraw_in_flight: bool,
    withdraw_reason: Option<PrefixWithdrawReason>,
    known_absent: bool,
    /// A prior possibly-effective mutation could not be authoritatively
    /// cleaned up. No advertisement may run until exact absence succeeds.
    quarantined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PeerKey {
    domain: RoutingDomainTag,
    name: String,
}

#[derive(Debug, Clone)]
struct PeerTrack {
    identity: PeerIdentity,
    session: PeerSessionState,
    path_health: PathHealth,
    advertised_prefixes: BTreeSet<HostPrefix>,
    last_seen: Timestamp,
}

#[derive(Debug, Default)]
struct ServiceState {
    domains: BTreeMap<RoutingDomainTag, DomainState>,
    peers: BTreeMap<PeerKey, PeerTrack>,
    sequence: u64,
    next_intent_revision: u64,
}

#[derive(Debug, Default)]
struct StartupState {
    attempt: u64,
    running: bool,
    complete: bool,
    last_error: Option<IpsecLbError>,
}

#[derive(Debug, Default)]
struct StartupControl {
    state: Mutex<StartupState>,
    changed: Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationPriority {
    Withdrawal,
    Apply,
}

struct PendingMutation {
    domains: BTreeSet<RoutingDomainTag>,
    priority: MutationPriority,
    ready: oneshot::Sender<()>,
}

#[derive(Default)]
struct MutationScheduleState {
    active: bool,
    pending: VecDeque<PendingMutation>,
}

/// Bounded, cancellation-safe mutation admission.
///
/// At most one queued request of each priority can cover a domain. A newer
/// overlapping request supersedes the older queued request, which wakes its
/// detached driver with a typed conflict. Withdrawals are always selected
/// before applies after the currently active adapter mutation completes.
#[derive(Default)]
struct MutationScheduler {
    state: Mutex<MutationScheduleState>,
}

struct MutationPermit {
    scheduler: Arc<MutationScheduler>,
}

impl Drop for MutationPermit {
    fn drop(&mut self) {
        self.scheduler.release();
    }
}

impl MutationScheduler {
    async fn acquire(
        self: &Arc<Self>,
        domains: BTreeSet<RoutingDomainTag>,
        priority: MutationPriority,
    ) -> Result<MutationPermit, IpsecLbError> {
        if domains.is_empty() {
            return Err(IpsecLbError::invalid_config(
                "mutation_domains",
                "mutation domain set must be non-empty",
            ));
        }
        let receiver = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !state.active {
                state.active = true;
                return Ok(MutationPermit {
                    scheduler: Arc::clone(self),
                });
            }

            let (ready, receiver) = oneshot::channel();
            let mut retained = VecDeque::with_capacity(state.pending.len().saturating_add(1));
            while let Some(mut pending) = state.pending.pop_front() {
                let overlaps = pending
                    .domains
                    .iter()
                    .any(|domain| domains.contains(domain));
                let superseded = overlaps
                    && (priority == MutationPriority::Withdrawal
                        || pending.priority == MutationPriority::Apply);
                if superseded {
                    // A batched withdrawal can overlap only partially. Keep
                    // its sender alive for every unaffected domain; its
                    // driver rechecks each original revision after waking.
                    // Dropping the complete pending entry here would strand
                    // the remainder in `withdraw_in_flight` forever.
                    pending.domains.retain(|domain| !domains.contains(domain));
                }
                if !pending.domains.is_empty() {
                    retained.push_back(pending);
                }
            }
            retained.push_back(PendingMutation {
                domains,
                priority,
                ready,
            });
            debug_assert!(
                retained.len() <= MAX_ADVERTISEMENT_ROUTING_DOMAINS.saturating_mul(2),
                "mutation scheduler admission must remain domain-bounded"
            );
            state.pending = retained;
            receiver
        };

        receiver.await.map_err(|_closed| {
            IpsecLbError::ownership_conflict("routing mutation was superseded while queued")
        })?;
        Ok(MutationPermit {
            scheduler: Arc::clone(self),
        })
    }

    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            let next = state
                .pending
                .iter()
                .position(|pending| pending.priority == MutationPriority::Withdrawal)
                .and_then(|index| state.pending.remove(index))
                .or_else(|| state.pending.pop_front());
            let Some(next) = next else {
                state.active = false;
                return;
            };
            if next.ready.send(()).is_ok() {
                // The active flag stays set while the awakened driver owns the
                // logical permit. Its guard releases the next waiter.
                return;
            }
        }
    }
}

/// Declarative, lease-gated prefix advertisement service.
///
/// Generation rules mirror [`crate::vip::VipOwnershipCoordinator`]:
///
/// - every supplied lease generation is recorded; history is never erased;
/// - advertising a new intent requires a generation strictly newer than
///   every generation previously observed;
/// - while a generation is current (the greatest observed) and its lease is
///   unexpired, repeating the identical intent is an idempotent no-op when
///   every desired prefix is advertised, and a safe declarative re-apply
///   when any desired track is unconfirmed or rejected — the same-generation
///   retry survives transient stack failures exactly like #254's retained
///   retry fence;
/// - a stale, equal-after-withdraw, expired, or missing lease fails closed:
///   the domain is withdrawn and a stale generation can never re-advertise
///   after a newer drain or fence loss;
/// - an ambiguous, refused, malformed-outcome, or failed adapter apply drives
///   an immediate whole-domain withdrawal. The generation is burned; only a
///   strictly newer epoch can advertise after this fail-closed cleanup.
///
/// Before the first advertisement, startup reconciliation withdraws every
/// adapter-declared managed domain to establish known absence across process
/// restarts. Advertising fails closed while that cleanup is unavailable.
///
/// Cancellation safety: adapter mutations totally order through the bounded
/// priority scheduler; applies and withdrawals are driven by detached tasks,
/// and the driver re-validates that its intent is still current (same
/// desired set, same generation, lease still armed) after winning the
/// lock — a stale queued driver bails without touching the adapter. A driver
/// superseded while its bounded adapter call is in flight cleans the complete
/// domain before releasing the lock. Deadlines are checked immediately before
/// and after mutation. Cancelling `reconcile` before the lock, during the
/// adapter call, or after an unobserved result therefore cannot cancel the
/// authoritative cleanup or leave phantom `Advertised` belief.
///
/// Retention: prefix tracks are kept while the prefix is in the current
/// desired set or in a non-terminal state (`Advertised`/`Unknown`); terminal
/// (`Withdrawn`/`Rejected`) tracks are pruned once the prefix leaves the
/// desired set. Peers that vanish from stack observations transition to
/// session-down immediately and are pruned after
/// [`PrefixAdvertiserConfig::peer_retention_secs`].
///
/// Mutating operations are serialized internally; callers may share one
/// service behind an [`Arc`].
pub struct PrefixAdvertiserService<A> {
    adapter: Arc<A>,
    clock: Arc<dyn Clock>,
    config: PrefixAdvertiserConfig,
    state: Arc<Mutex<ServiceState>>,
    op_lock: tokio::sync::Mutex<()>,
    observation_lock: tokio::sync::Mutex<()>,
    mutation_scheduler: Arc<MutationScheduler>,
    events: broadcast::Sender<RoutingEvent>,
    managed_domains: BTreeSet<RoutingDomainTag>,
    maximum_mutation_duration: Duration,
    startup: Arc<StartupControl>,
}

impl<A> fmt::Debug for PrefixAdvertiserService<A>
where
    A: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock_state(&self.state);
        f.debug_struct("PrefixAdvertiserService")
            .field("adapter", &self.adapter)
            .field("config", &self.config)
            .field("domains", &state.domains.len())
            .field("peers", &state.peers.len())
            .finish()
    }
}

impl<A> PrefixAdvertiserService<A>
where
    A: RoutingStackAdapter + 'static,
{
    /// Build a service on the system clock.
    pub fn new(adapter: A, config: PrefixAdvertiserConfig) -> Result<Self, IpsecLbError> {
        Self::with_clock(adapter, config, Arc::new(SystemClock))
    }

    /// Build a service on an injected clock for deterministic lease tests.
    pub fn with_clock(
        adapter: A,
        config: PrefixAdvertiserConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, IpsecLbError> {
        config.validate()?;
        let managed_domains = adapter.managed_domains();
        if managed_domains.is_empty() {
            return Err(IpsecLbError::invalid_config(
                "managed_domains",
                "at least one managed routing domain is required",
            ));
        }
        if managed_domains.len() > MAX_ADVERTISEMENT_ROUTING_DOMAINS {
            return Err(IpsecLbError::invalid_config(
                "managed_domains",
                "managed routing-domain count exceeds the production bound",
            ));
        }
        let maximum_mutation_duration = adapter.maximum_mutation_duration();
        if maximum_mutation_duration.is_zero()
            || maximum_mutation_duration > MAX_ROUTING_MUTATION_DURATION
        {
            return Err(IpsecLbError::invalid_config(
                "maximum_mutation_duration",
                "adapter mutation duration is zero or exceeds the production bound",
            ));
        }
        let process_supervision = adapter.process_supervision();
        let _production_supervision = process_supervision.is_production();
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let mut initial_state = ServiceState::default();
        for domain in &managed_domains {
            initial_state
                .domains
                .insert(*domain, DomainState::default());
        }
        Ok(Self {
            adapter: Arc::new(adapter),
            clock,
            config,
            state: Arc::new(Mutex::new(initial_state)),
            op_lock: tokio::sync::Mutex::new(()),
            observation_lock: tokio::sync::Mutex::new(()),
            mutation_scheduler: Arc::new(MutationScheduler::default()),
            events,
            managed_domains,
            maximum_mutation_duration,
            startup: Arc::new(StartupControl::default()),
        })
    }

    /// Establish known absence for every adapter-managed routing domain.
    ///
    /// The first call runs a cancellation-safe detached cleanup. Every
    /// reconcile also invokes this gate, so a new process incarnation cannot
    /// advertise until durable fragments/routes left by a previous process
    /// have been authoritatively withdrawn. A failed attempt is returned to
    /// all current waiters; a later call retries the complete domain set.
    pub async fn initialize(&self) -> Result<(), IpsecLbError> {
        let attempt = loop {
            let notified = self.startup.changed.notified();
            let action = {
                let mut startup = self
                    .startup
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if startup.complete {
                    return Ok(());
                }
                if startup.running {
                    None
                } else {
                    startup.last_error = None;
                    startup.attempt = startup.attempt.saturating_add(1);
                    startup.running = true;
                    Some(startup.attempt)
                }
            };
            if let Some(attempt) = action {
                break attempt;
            }
            notified.await;
        };

        let adapter = Arc::clone(&self.adapter);
        let mutation_scheduler = Arc::clone(&self.mutation_scheduler);
        let state = Arc::clone(&self.state);
        let managed_domains = self.managed_domains.clone();
        let startup = Arc::clone(&self.startup);
        tokio::spawn(async move {
            let result =
                drive_startup_cleanup(adapter, mutation_scheduler, state, &managed_domains).await;
            let mut control = startup
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if control.attempt == attempt {
                control.running = false;
                match result {
                    Ok(()) => control.complete = true,
                    Err(error) => control.last_error = Some(error),
                }
            }
            drop(control);
            startup.changed.notify_waiters();
        });

        loop {
            let notified = self.startup.changed.notified();
            {
                let startup = self
                    .startup
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if startup.complete {
                    return Ok(());
                }
                if !startup.running && startup.attempt == attempt {
                    return Err(startup.last_error.clone().unwrap_or_else(|| {
                        IpsecLbError::io(
                            "routing_startup_cleanup",
                            std::io::Error::other("startup cleanup did not complete"),
                        )
                    }));
                }
            }
            notified.await;
        }
    }

    /// Maximum elapsed time from lease expiry to either completed exact
    /// withdrawal or fail-stop of a production routing process.
    ///
    /// This contract applies only while [`Self::run`] remains alive in an
    /// independently supervised task (or the caller invokes
    /// [`Self::enforce_lease_once`] at the configured cadence). One poll
    /// interval detects expiry. An already-running apply can consume one
    /// adapter bound and then one cleanup bound before the expiry batch's own
    /// withdrawal consumes a third adapter bound. A mutation timeout first
    /// fail-stops the owned production routing process so late work cannot
    /// revive an advertisement.
    #[must_use]
    pub fn lease_enforcement_bound(&self) -> Duration {
        self.config.poll_interval + self.maximum_mutation_duration.saturating_mul(3)
    }

    /// Subscribe to the typed health/readiness event stream.
    ///
    /// Events carry strictly increasing sequence numbers. A lagging receiver
    /// observes [`broadcast::error::RecvError::Lagged`] and must resynchronize
    /// from [`Self::prefix_snapshots`].
    pub fn subscribe_events(&self) -> broadcast::Receiver<RoutingEvent> {
        self.events.subscribe()
    }

    /// Reconcile one routing domain to the exact desired host-prefix set.
    ///
    /// `lease` is the caller's current health evidence: `Some` authorizes
    /// origination of exactly `desired`, `None` drains the domain. The call
    /// is idempotent; the adapter is never asked to originate anything
    /// outside `desired`. The adapter mutation is driven to completion even
    /// if the returned future is dropped (see the type-level documentation).
    pub async fn reconcile(
        &self,
        domain: RoutingDomainTag,
        desired: BTreeSet<HostPrefix>,
        lease: Option<AdvertisementLease>,
    ) -> Result<PrefixReconcileReport, IpsecLbError> {
        self.initialize().await?;
        if !self.managed_domains.contains(&domain) {
            return Err(IpsecLbError::invalid_config(
                "routing_domain",
                "routing domain is not managed by this adapter",
            ));
        }
        if desired.len() > self.config.max_prefixes_per_domain {
            return Err(IpsecLbError::invalid_config(
                "desired_prefixes",
                "desired prefix set exceeds the production bound",
            ));
        }
        let _op = self.op_lock.lock().await;
        let now = self.clock.now_utc();

        enum Plan {
            Retained,
            Withdraw {
                reason: PrefixWithdrawReason,
                revision: u64,
            },
            Apply {
                generation: LeaseGeneration,
                revision: u64,
            },
        }

        let plan = {
            let mut state = lock_state(&self.state);
            let next_revision = state.next_intent_revision.checked_add(1).ok_or_else(|| {
                IpsecLbError::invalid_config("intent_revision", "routing intent revision exhausted")
            })?;
            // Consuming a revision for an idempotent retain is harmless and
            // avoids aliasing the global counter with the borrowed domain.
            state.next_intent_revision = next_revision;
            let domain_state = state.domains.get_mut(&domain).ok_or_else(|| {
                IpsecLbError::invalid_config(
                    "routing_domain",
                    "routing domain is not managed by this service",
                )
            })?;
            let previous_highest = domain_state.highest_generation;
            if let Some(lease) = lease {
                if domain_state
                    .highest_generation
                    .is_none_or(|highest| lease.generation() > highest)
                {
                    domain_state.highest_generation = Some(lease.generation());
                }
            }

            if lease.is_some() && domain_state.quarantined {
                revoke_domain_intent(
                    domain_state,
                    next_revision,
                    PrefixWithdrawReason::RoutingStackUnreachable,
                    now,
                );
                Plan::Withdraw {
                    reason: PrefixWithdrawReason::RoutingStackUnreachable,
                    revision: next_revision,
                }
            } else {
                match lease {
                    None => {
                        revoke_domain_intent(
                            domain_state,
                            next_revision,
                            PrefixWithdrawReason::CallerDrain,
                            now,
                        );
                        Plan::Withdraw {
                            reason: PrefixWithdrawReason::CallerDrain,
                            revision: next_revision,
                        }
                    }
                    Some(lease) => {
                        let deadline = lease_deadline(now, lease)?;
                        let generation = lease.generation();
                        let lease_expired = domain_state
                            .lease_deadline
                            .is_some_and(|deadline| now >= deadline);
                        let fresh_epoch =
                            previous_highest.is_none_or(|highest| generation > highest);
                        if fresh_epoch {
                            domain_state.lease_deadline = Some(deadline);
                            domain_state.desired.clone_from(&desired);
                            domain_state.intent_revision = next_revision;
                            domain_state.mutation_in_flight = true;
                            domain_state.withdraw_pending = false;
                            domain_state.withdraw_in_flight = false;
                            domain_state.withdraw_reason = None;
                            Plan::Apply {
                                generation,
                                revision: next_revision,
                            }
                        } else {
                            // Same-generation intents are valid only while the
                            // generation is current, its lease is unexpired, and
                            // the intent is byte-identical to the live epoch.
                            let epoch_live = domain_state.advertised_generation == Some(generation);
                            let epoch_ambiguous = domain_state.advertised_generation.is_none()
                                && domain_state.lease_deadline.is_some()
                                && domain_state.highest_generation == Some(generation);
                            let same_set = domain_state.desired == desired;
                            if lease_expired || !same_set || (!epoch_live && !epoch_ambiguous) {
                                revoke_domain_intent(
                                    domain_state,
                                    next_revision,
                                    PrefixWithdrawReason::StaleGeneration,
                                    now,
                                );
                                Plan::Withdraw {
                                    reason: PrefixWithdrawReason::StaleGeneration,
                                    revision: next_revision,
                                }
                            } else {
                                domain_state.lease_deadline = Some(deadline);
                                // Retention is decided against the desired set
                                // alone: historical tracks of prefixes that left
                                // the set must not poison renewal.
                                let all_originated = epoch_live
                                    && desired.iter().all(|prefix| {
                                        domain_state.prefixes.get(prefix).is_some_and(|track| {
                                            track.originated
                                                && track.state != PrefixAdvertisementState::Rejected
                                                && (track.state
                                                    != PrefixAdvertisementState::Unknown
                                                    || track.export_evidence_pending)
                                        })
                                    });
                                if all_originated {
                                    Plan::Retained
                                } else {
                                    // Same-generation declarative re-apply:
                                    // unconfirmed or rejected desired tracks get
                                    // a fresh outcome without a new generation.
                                    domain_state.intent_revision = next_revision;
                                    domain_state.mutation_in_flight = true;
                                    domain_state.withdraw_pending = false;
                                    domain_state.withdraw_in_flight = false;
                                    domain_state.withdraw_reason = None;
                                    Plan::Apply {
                                        generation,
                                        revision: next_revision,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };
        drop(_op);

        match plan {
            Plan::Retained => Ok(PrefixReconcileReport {
                domain,
                disposition: ReconcileDisposition::Retained,
                outcomes: desired
                    .iter()
                    .map(|prefix| (*prefix, PrefixApplyOutcome::Accepted))
                    .collect(),
            }),
            Plan::Withdraw { reason, revision } => {
                let disposition = if reason == PrefixWithdrawReason::StaleGeneration {
                    ReconcileDisposition::StaleRejected
                } else {
                    ReconcileDisposition::Withdrawn
                };
                self.withdraw_domain(domain, reason, revision).await?;
                let outcomes = if reason == PrefixWithdrawReason::StaleGeneration {
                    desired
                        .iter()
                        .map(|prefix| {
                            (
                                *prefix,
                                PrefixApplyOutcome::Rejected(PrefixRejectReason::StaleGeneration),
                            )
                        })
                        .collect()
                } else {
                    BTreeMap::new()
                };
                Ok(PrefixReconcileReport {
                    domain,
                    disposition,
                    outcomes,
                })
            }
            Plan::Apply {
                generation,
                revision,
            } => {
                self.apply_domain(domain, desired, generation, revision)
                    .await
            }
        }
    }

    async fn apply_domain(
        &self,
        domain: RoutingDomainTag,
        desired: BTreeSet<HostPrefix>,
        generation: LeaseGeneration,
        revision: u64,
    ) -> Result<PrefixReconcileReport, IpsecLbError> {
        // Drive the adapter mutation on a detached task. Cancelling the
        // caller's future only drops the join handle; the driver still
        // finishes the adapter call and applies the outcome, so belief can
        // never tear between "the stack was told" and "the service knows".
        let driver = tokio::spawn(drive_apply(
            Arc::clone(&self.adapter),
            Arc::clone(&self.mutation_scheduler),
            Arc::clone(&self.state),
            self.events.clone(),
            Arc::clone(&self.clock),
            domain,
            desired,
            generation,
            revision,
        ));
        driver.await.map_err(|error| {
            IpsecLbError::io(
                "apply_driver",
                std::io::Error::other(format!("apply driver failed: {error}")),
            )
        })?
    }

    async fn withdraw_domain(
        &self,
        domain: RoutingDomainTag,
        reason: PrefixWithdrawReason,
        revision: u64,
    ) -> Result<(), IpsecLbError> {
        let driver = tokio::spawn(drive_withdraw(
            Arc::clone(&self.adapter),
            Arc::clone(&self.mutation_scheduler),
            Arc::clone(&self.state),
            self.events.clone(),
            Arc::clone(&self.clock),
            domain,
            reason,
            revision,
        ));
        driver.await.map_err(|error| {
            IpsecLbError::io(
                "withdraw_driver",
                std::io::Error::other(format!("withdraw driver failed: {error}")),
            )
        })?
    }

    /// Enforce lease deadlines once.
    ///
    /// Every domain whose lease deadline has passed is withdrawn and its
    /// prefixes transition with [`PrefixWithdrawReason::LeaseExpired`]. A
    /// All currently expired domains are sent through one bounded adapter
    /// batch, so the withdrawal bound does not scale with domain count.
    pub async fn enforce_lease_once(&self) -> Result<(), IpsecLbError> {
        self.initialize().await?;
        let _op = self.op_lock.lock().await;
        let now = self.clock.now_utc();
        let withdrawals: Vec<(RoutingDomainTag, PrefixWithdrawReason, u64)> = {
            let mut state = lock_state(&self.state);
            let candidates: Vec<(RoutingDomainTag, PrefixWithdrawReason)> = state
                .domains
                .iter()
                .filter_map(|(domain, domain_state)| {
                    if domain_state.withdraw_pending && !domain_state.withdraw_in_flight {
                        Some((
                            *domain,
                            domain_state
                                .withdraw_reason
                                .unwrap_or(PrefixWithdrawReason::RoutingStackUnreachable),
                        ))
                    } else if domain_state
                        .lease_deadline
                        .is_some_and(|deadline| now >= deadline)
                    {
                        Some((*domain, PrefixWithdrawReason::LeaseExpired))
                    } else {
                        None
                    }
                })
                .collect();
            let mut planned = Vec::with_capacity(candidates.len());
            for (domain, reason) in candidates {
                let Some(revision) = state.next_intent_revision.checked_add(1) else {
                    continue;
                };
                state.next_intent_revision = revision;
                if let Some(domain_state) = state.domains.get_mut(&domain) {
                    revoke_domain_intent(domain_state, revision, reason, now);
                    planned.push((domain, reason, revision));
                }
            }
            planned
        };
        drop(_op);
        if withdrawals.is_empty() {
            return Ok(());
        }
        let driver = tokio::spawn(drive_withdrawals(
            Arc::clone(&self.adapter),
            Arc::clone(&self.mutation_scheduler),
            Arc::clone(&self.state),
            self.events.clone(),
            Arc::clone(&self.clock),
            withdrawals,
        ));
        match driver.await {
            Ok(result) => result,
            Err(error) => Err(IpsecLbError::io(
                "withdraw_driver",
                std::io::Error::other(format!("withdraw driver failed: {error}")),
            )),
        }
    }

    /// Poll the routing stack once and relay session and path-health
    /// transitions.
    ///
    /// Ordering guarantee: for one cause, the `PeerSessionChanged` event is
    /// always emitted before the prefix events it triggers. When the stack
    /// is unobservable, established sessions transition locally to `Down`
    /// and all paths transition to `Unknown`. Originated prefixes become
    /// unconfirmed — relayed as `PrefixUnconfirmed`, never as an upstream
    /// withdrawal the service did not observe.
    pub async fn observe_once(&self) -> Result<(), IpsecLbError> {
        self.initialize().await?;
        let _observation = self.observation_lock.lock().await;
        let intent_snapshots: BTreeMap<RoutingDomainTag, (u64, bool)> = {
            let state = lock_state(&self.state);
            state
                .domains
                .iter()
                .map(|(domain, domain_state)| {
                    (
                        *domain,
                        (
                            domain_state.intent_revision,
                            domain_state.mutation_in_flight,
                        ),
                    )
                })
                .collect()
        };
        let observation = tokio::time::timeout(
            self.maximum_mutation_duration,
            self.adapter.poll_observations(),
        )
        .await
        .map_err(|_elapsed| {
            IpsecLbError::io(
                "routing_observation_timeout",
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "routing observation exceeded the adapter bound",
                ),
            )
        });
        let now = self.clock.now_utc();
        match observation {
            Ok(Ok(observations)) => {
                if let Err(error) = validate_observations(&self.managed_domains, &observations) {
                    let mut state = lock_state(&self.state);
                    note_observation_loss_locked(&mut state, &self.events, now);
                    return Err(error);
                }
                let mut state = lock_state(&self.state);
                let stale_domains: BTreeSet<RoutingDomainTag> = state
                    .domains
                    .iter()
                    .filter_map(|(domain, domain_state)| {
                        let current = (domain_state.intent_revision, false);
                        (intent_snapshots.get(domain) != Some(&current)
                            || domain_state.mutation_in_flight)
                            .then_some(*domain)
                    })
                    .collect();
                let mut seen: BTreeMap<PeerKey, PeerTrack> = BTreeMap::new();
                for mut observation in observations {
                    if stale_domains.contains(&observation.domain) {
                        let key = PeerKey {
                            domain: observation.domain,
                            name: observation.peer.name().to_owned(),
                        };
                        observation.advertised_prefixes = state
                            .peers
                            .get(&key)
                            .map(|track| track.advertised_prefixes.clone())
                            .unwrap_or_default();
                    }
                    seen.insert(
                        PeerKey {
                            domain: observation.domain,
                            name: observation.peer.name().to_owned(),
                        },
                        PeerTrack {
                            identity: observation.peer,
                            session: observation.session,
                            path_health: observation.path_health,
                            advertised_prefixes: observation.advertised_prefixes,
                            last_seen: now,
                        },
                    );
                }
                let previous = state.peers.clone();
                for (key, previous_track) in &previous {
                    if !seen.contains_key(key) {
                        // Prune peers gone beyond the retention bound.
                        let expired = previous_track
                            .last_seen
                            .add_seconds(self.config.peer_retention_secs.cast_signed())
                            .is_some_and(|deadline| now >= deadline);
                        if !expired {
                            seen.insert(
                                key.clone(),
                                PeerTrack {
                                    identity: previous_track.identity.clone(),
                                    session: PeerSessionState::Down,
                                    path_health: PathHealth::Unknown,
                                    advertised_prefixes: BTreeSet::new(),
                                    last_seen: previous_track.last_seen,
                                },
                            );
                        }
                    }
                }
                apply_peer_observation_batch_locked(
                    &mut state,
                    &self.events,
                    now,
                    previous,
                    seen,
                    &stale_domains,
                );
                Ok(())
            }
            Ok(Err(_error)) | Err(_error) => {
                let mut state = lock_state(&self.state);
                note_observation_loss_locked(&mut state, &self.events, now);
                Ok(())
            }
        }
    }

    /// Run the watchdog loop until the shutdown signal flips to `true` or its
    /// sender drops.
    ///
    /// Each tick enforces lease deadlines and relays stack observations.
    /// Observation faults are retried on the next tick. A production adapter
    /// must fail-stop its owned routing process before an unconfirmed
    /// withdrawal error returns; the BIRD adapter enforces that contract for
    /// filesystem, configure-refusal, ambiguous, readback, and timeout paths.
    /// Upstream withdrawal remains separate peer-session or BFD evidence.
    ///
    /// Sending `true` or dropping every sender always runs the same bounded
    /// domain withdrawal path before this future returns. A watchdog-control
    /// task cannot disappear while silently leaving accepted intent live.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.config.poll_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = self.enforce_lease_once().await;
                    let _ = self.observe_once().await;
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        self.shutdown().await;
    }

    /// Withdraw every domain best-effort for process shutdown.
    ///
    /// The local lifecycle supervision still applies: loss of the SDK-owned
    /// supervisor/helper parent boundary kills and reaps the foreground BIRD
    /// child. This method does not infer upstream route withdrawal.
    pub async fn shutdown(&self) {
        let _ = self.initialize().await;
        let _op = self.op_lock.lock().await;
        let now = self.clock.now_utc();
        let domains: Vec<(RoutingDomainTag, u64)> = {
            let mut state = lock_state(&self.state);
            let domains: Vec<RoutingDomainTag> = state.domains.keys().copied().collect();
            let mut planned = Vec::with_capacity(domains.len());
            for domain in domains {
                let Some(revision) = state.next_intent_revision.checked_add(1) else {
                    continue;
                };
                state.next_intent_revision = revision;
                if let Some(domain_state) = state.domains.get_mut(&domain) {
                    revoke_domain_intent(
                        domain_state,
                        revision,
                        PrefixWithdrawReason::ServiceShutdown,
                        now,
                    );
                    planned.push((domain, revision));
                }
            }
            planned
        };
        drop(_op);
        if !domains.is_empty() {
            let withdrawals = domains
                .into_iter()
                .map(|(domain, revision)| (domain, PrefixWithdrawReason::ServiceShutdown, revision))
                .collect();
            let driver = tokio::spawn(drive_withdrawals(
                Arc::clone(&self.adapter),
                Arc::clone(&self.mutation_scheduler),
                Arc::clone(&self.state),
                self.events.clone(),
                Arc::clone(&self.clock),
                withdrawals,
            ));
            // Dropping `shutdown` must not cancel an already-authorized
            // withdrawal. The detached driver owns it to a terminal outcome.
            let _ = driver.await;
        }
    }

    /// Return the status snapshot for every tracked prefix in one domain.
    #[must_use]
    pub fn prefix_snapshots(&self, domain: RoutingDomainTag) -> Vec<PrefixStatusSnapshot> {
        let state = lock_state(&self.state);
        let advertised = advertised_prefixes_for_domain(&state.peers, domain);
        let Some(domain_state) = state.domains.get(&domain) else {
            return Vec::new();
        };
        domain_state
            .prefixes
            .iter()
            .map(|(prefix, track)| PrefixStatusSnapshot {
                prefix: AdvertisedPrefix::new(domain, *prefix),
                state: track.state,
                advertised_to: if track.originated
                    && track.state == PrefixAdvertisementState::Advertised
                {
                    advertised.get(prefix).cloned().unwrap_or_default()
                } else {
                    BTreeSet::new()
                },
                last_transition: track.last_transition,
                last_withdraw_reason: track.last_withdraw_reason,
            })
            .collect()
    }

    /// Return the status snapshot for one prefix, when tracked.
    #[must_use]
    pub fn prefix_snapshot(
        &self,
        domain: RoutingDomainTag,
        prefix: HostPrefix,
    ) -> Option<PrefixStatusSnapshot> {
        self.prefix_snapshots(domain)
            .into_iter()
            .find(|snapshot| snapshot.prefix.prefix() == prefix)
    }
}

/// Detached apply driver: performs the adapter mutation and applies the
/// outcome to service state as one serialized unit.
///
/// The scheduler serializes adapter mutations, prioritizes withdrawals, and
/// supersedes overlapping queued applies, so the last admitted driver is the
/// last adapter effect and belief —
/// a retried intent queued after a cancelled call can never be overwritten
/// by the stale driver.
///
/// Between being spawned and winning the lock the domain may have moved on
/// (a drain, or a newer intent): the driver re-validates intent currency
/// after acquiring the lock and bails without touching the adapter when its
/// intent is stale, so a cancelled-then-drained apply can never re-originate
/// a prefix the drain already withdrew.
#[allow(clippy::too_many_arguments)]
async fn drive_apply<A>(
    adapter: Arc<A>,
    mutation_scheduler: Arc<MutationScheduler>,
    state: Arc<Mutex<ServiceState>>,
    events: broadcast::Sender<RoutingEvent>,
    clock: Arc<dyn Clock>,
    domain: RoutingDomainTag,
    desired: BTreeSet<HostPrefix>,
    generation: LeaseGeneration,
    revision: u64,
) -> Result<PrefixReconcileReport, IpsecLbError>
where
    A: RoutingStackAdapter,
{
    let _permit = mutation_scheduler
        .acquire(BTreeSet::from([domain]), MutationPriority::Apply)
        .await?;
    if !intent_is_current(
        &state,
        domain,
        &desired,
        generation,
        revision,
        clock.now_utc(),
    ) {
        return Err(IpsecLbError::OwnershipConflict {
            reason: "advertisement intent superseded or expired before apply",
        });
    }
    let result = match adapter.apply_advertisement_set(domain, &desired).await {
        Ok(result) => result,
        Err(error) => {
            let _ = cleanup_uncertain_apply(
                &adapter, &state, &events, &clock, domain, &desired, revision,
            )
            .await;
            return Err(error);
        }
    };

    let outcome_keys: BTreeSet<HostPrefix> = result.outcomes.keys().copied().collect();
    let contract_violation = if outcome_keys != desired {
        Some("outcome_key_set_mismatch")
    } else if !result.outcomes.values().all(|outcome| {
        matches!(
            (result.disposition, outcome),
            (
                AdvertisementSetDisposition::Applied,
                PrefixApplyOutcome::Accepted | PrefixApplyOutcome::Rejected(_)
            ) | (
                AdvertisementSetDisposition::Refused,
                PrefixApplyOutcome::Rejected(_)
            ) | (
                AdvertisementSetDisposition::Ambiguous,
                PrefixApplyOutcome::Unreachable
            )
        )
    }) {
        Some("disposition_outcome_mismatch")
    } else {
        None
    };
    if let Some(code) = contract_violation {
        let _ = cleanup_uncertain_apply(
            &adapter, &state, &events, &clock, domain, &desired, revision,
        )
        .await;
        return Err(IpsecLbError::adapter_contract_violation(code));
    }

    if result.disposition != AdvertisementSetDisposition::Applied {
        cleanup_uncertain_apply(
            &adapter, &state, &events, &clock, domain, &desired, revision,
        )
        .await?;
        return Ok(PrefixReconcileReport {
            domain,
            disposition: ReconcileDisposition::PartiallyRejected,
            outcomes: result.outcomes,
        });
    }

    let now = clock.now_utc();
    let committed = (|| -> Result<bool, IpsecLbError> {
        let mut state = lock_state(&state);
        // An expiry/drain/newer generation may have superseded this mutation while
        // the adapter call was in flight. Revalidate while holding the same state
        // lock used for the result commit; an out-of-lock check would allow a
        // newer intent to arrive between validation and commit.
        let result_is_current = state.domains.get(&domain).is_some_and(|domain_state| {
            domain_intent_is_current(domain_state, &desired, generation, revision, now)
        });
        if !result_is_current {
            return Ok(false);
        }
        // Any peer export view predates this exact-set replacement. Invalidate it
        // for the affected domain; a subsequent complete observation is the only
        // authority that can publish `Advertised` again.
        for (key, peer) in &mut state.peers {
            if key.domain == domain {
                peer.advertised_prefixes.clear();
            }
        }
        let mut pending = Vec::new();
        {
            let domain_state = state.domains.get_mut(&domain).ok_or_else(|| {
                IpsecLbError::invalid_config(
                    "routing_domain",
                    "routing domain disappeared during apply",
                )
            })?;
            // This is the terminal authoritative point for the admitted intent.
            // Observations captured after intent admission but before this commit
            // carry `mutation_in_flight = true` and must remain stale even though
            // their intent revision matches this result.
            domain_state.mutation_in_flight = false;
            domain_state.advertised_generation = Some(generation);
            domain_state.known_absent = !result
                .outcomes
                .values()
                .any(|outcome| *outcome == PrefixApplyOutcome::Accepted);
            for (prefix, outcome) in &result.outcomes {
                let track = domain_state.prefixes.entry(*prefix).or_default();
                match outcome {
                    PrefixApplyOutcome::Accepted => {
                        let was_advertised = track.state == PrefixAdvertisementState::Advertised;
                        track.originated = true;
                        track.export_evidence_pending = true;
                        track.state = PrefixAdvertisementState::Unknown;
                        track.last_transition = Some(now);
                        track.last_withdraw_reason = None;
                        if was_advertised {
                            pending.push(RoutingEventKind::PrefixUnconfirmed {
                                prefix: AdvertisedPrefix::new(domain, *prefix),
                                reason: PrefixWithdrawReason::PeerExportUnconfirmed,
                            });
                        }
                    }
                    PrefixApplyOutcome::Rejected(reason) => {
                        track.originated = false;
                        track.export_evidence_pending = false;
                        if track.state == PrefixAdvertisementState::Advertised {
                            pending.push(RoutingEventKind::PrefixWithdrawn {
                                prefix: AdvertisedPrefix::new(domain, *prefix),
                                reason: PrefixWithdrawReason::AdapterRejected,
                            });
                        }
                        track.state = PrefixAdvertisementState::Rejected;
                        track.last_transition = Some(now);
                        track.last_withdraw_reason = Some(match reason {
                            PrefixRejectReason::StaleGeneration => {
                                PrefixWithdrawReason::StaleGeneration
                            }
                            _ => PrefixWithdrawReason::AdapterRejected,
                        });
                    }
                    PrefixApplyOutcome::Unreachable => {
                        track.export_evidence_pending = false;
                        if track.state == PrefixAdvertisementState::Advertised {
                            pending.push(RoutingEventKind::PrefixUnconfirmed {
                                prefix: AdvertisedPrefix::new(domain, *prefix),
                                reason: PrefixWithdrawReason::RoutingStackUnreachable,
                            });
                        }
                        track.state = PrefixAdvertisementState::Unknown;
                        track.last_transition = Some(now);
                        track.last_withdraw_reason =
                            Some(PrefixWithdrawReason::RoutingStackUnreachable);
                    }
                }
            }
            // Prefixes reconciled out of the desired set are withdrawn by the
            // adapter's declarative apply; reflect exactly that delta.
            let mut dropped = Vec::new();
            for (prefix, track) in &mut domain_state.prefixes {
                if track.originated && !desired.contains(prefix) {
                    let transitioned = matches!(
                        track.state,
                        PrefixAdvertisementState::Advertised | PrefixAdvertisementState::Unknown
                    );
                    track.originated = false;
                    track.export_evidence_pending = false;
                    track.state = PrefixAdvertisementState::Withdrawn;
                    if transitioned {
                        track.last_transition = Some(now);
                        dropped.push(*prefix);
                    }
                    track.last_withdraw_reason = Some(PrefixWithdrawReason::CallerDrain);
                }
            }
            for prefix in dropped {
                pending.push(RoutingEventKind::PrefixWithdrawn {
                    prefix: AdvertisedPrefix::new(domain, prefix),
                    reason: PrefixWithdrawReason::CallerDrain,
                });
            }
            prune_terminal_tracks(domain_state);
        }
        for kind in pending {
            emit_locked(&mut state, &events, now, kind);
        }
        Ok(true)
    })()?;
    if !committed {
        cleanup_uncertain_apply(
            &adapter, &state, &events, &clock, domain, &desired, revision,
        )
        .await?;
        return Err(IpsecLbError::OwnershipConflict {
            reason: "advertisement intent superseded or expired during apply",
        });
    }

    let disposition = if result
        .outcomes
        .values()
        .all(|outcome| *outcome == PrefixApplyOutcome::Accepted)
    {
        ReconcileDisposition::Applied
    } else {
        ReconcileDisposition::PartiallyRejected
    };
    Ok(PrefixReconcileReport {
        domain,
        disposition,
        outcomes: result.outcomes,
    })
}

async fn drive_startup_cleanup<A>(
    adapter: Arc<A>,
    mutation_scheduler: Arc<MutationScheduler>,
    state: Arc<Mutex<ServiceState>>,
    managed_domains: &BTreeSet<RoutingDomainTag>,
) -> Result<(), IpsecLbError>
where
    A: RoutingStackAdapter,
{
    let _permit = mutation_scheduler
        .acquire(managed_domains.clone(), MutationPriority::Withdrawal)
        .await?;
    adapter.establish_known_absence().await?;
    let mut state = lock_state(&state);
    for domain in managed_domains {
        let Some(domain_state) = state.domains.get_mut(domain) else {
            continue;
        };
        domain_state.known_absent = true;
        domain_state.withdraw_pending = false;
        domain_state.withdraw_in_flight = false;
        domain_state.withdraw_reason = None;
        domain_state.lease_deadline = None;
        domain_state.advertised_generation = None;
        domain_state.desired.clear();
        domain_state.prefixes.clear();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn drive_withdraw<A>(
    adapter: Arc<A>,
    mutation_scheduler: Arc<MutationScheduler>,
    state: Arc<Mutex<ServiceState>>,
    events: broadcast::Sender<RoutingEvent>,
    clock: Arc<dyn Clock>,
    domain: RoutingDomainTag,
    reason: PrefixWithdrawReason,
    revision: u64,
) -> Result<(), IpsecLbError>
where
    A: RoutingStackAdapter,
{
    drive_withdrawals(
        adapter,
        mutation_scheduler,
        state,
        events,
        clock,
        vec![(domain, reason, revision)],
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn drive_withdrawals<A>(
    adapter: Arc<A>,
    mutation_scheduler: Arc<MutationScheduler>,
    state: Arc<Mutex<ServiceState>>,
    events: broadcast::Sender<RoutingEvent>,
    clock: Arc<dyn Clock>,
    withdrawals: Vec<(RoutingDomainTag, PrefixWithdrawReason, u64)>,
) -> Result<(), IpsecLbError>
where
    A: RoutingStackAdapter,
{
    let requested_domains: BTreeSet<RoutingDomainTag> =
        withdrawals.iter().map(|(domain, _, _)| *domain).collect();
    let _permit = mutation_scheduler
        .acquire(requested_domains, MutationPriority::Withdrawal)
        .await?;
    let current: Vec<(RoutingDomainTag, PrefixWithdrawReason, u64)> = withdrawals
        .into_iter()
        .filter(|(domain, _, revision)| withdraw_is_current(&state, *domain, *revision))
        .collect();
    if current.is_empty() {
        return Err(IpsecLbError::ownership_conflict(
            "withdrawal intent was superseded before mutation",
        ));
    }
    let domains: BTreeSet<RoutingDomainTag> =
        current.iter().map(|(domain, _, _)| *domain).collect();
    if let Err(error) = adapter.withdraw_domains(&domains).await {
        let now = clock.now_utc();
        let mut state = lock_state(&state);
        let mut unconfirmed = Vec::new();
        for (domain, reason, revision) in &current {
            if let Some(domain_state) = state
                .domains
                .get_mut(domain)
                .filter(|domain_state| domain_state.intent_revision == *revision)
            {
                domain_state.withdraw_in_flight = false;
                domain_state.mutation_in_flight = false;
                // The adapter may have removed none, some, or all routes.
                // Preserve the complete possibly-live set and prohibit a new
                // advertisement until an exact-absence cleanup succeeds.
                domain_state.quarantined = true;
                unconfirmed.extend(
                    mark_domain_unknown(domain_state, now, *reason)
                        .into_iter()
                        .map(|prefix| (*domain, prefix, *reason)),
                );
            }
        }
        for (domain, prefix, reason) in unconfirmed {
            emit_locked(
                &mut state,
                &events,
                now,
                RoutingEventKind::PrefixUnconfirmed {
                    prefix: AdvertisedPrefix::new(domain, prefix),
                    reason,
                },
            );
        }
        return Err(error);
    }

    let now = clock.now_utc();
    let mut state = lock_state(&state);
    let mut pending_events = Vec::new();
    for (domain, reason, revision) in current {
        let mut withdrawn = Vec::new();
        if let Some(domain_state) = state
            .domains
            .get_mut(&domain)
            .filter(|domain_state| domain_state.intent_revision == revision)
        {
            finalize_domain_withdrawal(domain_state, now, reason, &mut withdrawn);
            pending_events.extend(withdrawn.into_iter().map(|prefix| (domain, prefix, reason)));
        }
    }
    for (domain, prefix, reason) in pending_events {
        emit_locked(
            &mut state,
            &events,
            now,
            RoutingEventKind::PrefixWithdrawn {
                prefix: AdvertisedPrefix::new(domain, prefix),
                reason,
            },
        );
    }
    Ok(())
}

async fn cleanup_uncertain_apply<A>(
    adapter: &Arc<A>,
    state: &Arc<Mutex<ServiceState>>,
    events: &broadcast::Sender<RoutingEvent>,
    clock: &Arc<dyn Clock>,
    domain: RoutingDomainTag,
    desired: &BTreeSet<HostPrefix>,
    revision: u64,
) -> Result<(), IpsecLbError>
where
    A: RoutingStackAdapter,
{
    let cleanup = adapter.withdraw_all(domain).await;
    let now = clock.now_utc();
    let mut state = lock_state(state);
    let current_revision = state
        .domains
        .get(&domain)
        .is_some_and(|domain_state| domain_state.intent_revision == revision);
    let mut withdrawn = Vec::new();
    match cleanup {
        Ok(()) => {
            if current_revision {
                if let Some(domain_state) = state.domains.get_mut(&domain) {
                    for prefix in desired {
                        domain_state.prefixes.entry(*prefix).or_default();
                    }
                    finalize_domain_withdrawal(
                        domain_state,
                        now,
                        PrefixWithdrawReason::RoutingStackUnreachable,
                        &mut withdrawn,
                    );
                }
            }
        }
        Err(error) => {
            quarantine_possibly_affected_locked(&mut state, events, now, domain, desired);
            return Err(error);
        }
    }
    for prefix in withdrawn {
        emit_locked(
            &mut state,
            events,
            now,
            RoutingEventKind::PrefixWithdrawn {
                prefix: AdvertisedPrefix::new(domain, prefix),
                reason: PrefixWithdrawReason::RoutingStackUnreachable,
            },
        );
    }
    Ok(())
}

/// Atomically replace one complete routing-stack observation.
///
/// Session transitions are emitted first, exact per-prefix export transitions
/// second, and path-health transitions last. Replacing the complete peer map
/// before deriving prefix visibility avoids a false withdraw/readvertise pair
/// when a route moves between peers in one poll.
fn apply_peer_observation_batch_locked(
    state: &mut ServiceState,
    events: &broadcast::Sender<RoutingEvent>,
    now: Timestamp,
    previous: BTreeMap<PeerKey, PeerTrack>,
    current: BTreeMap<PeerKey, PeerTrack>,
    stale_domains: &BTreeSet<RoutingDomainTag>,
) {
    let keys: BTreeSet<PeerKey> = previous.keys().chain(current.keys()).cloned().collect();
    let mut session_events = Vec::new();
    let mut path_events = Vec::new();
    for key in &keys {
        let before = previous.get(key);
        let after = current.get(key);
        let first_sighting = before.is_none();
        let identity = after
            .map(|track| track.identity.clone())
            .or_else(|| before.map(|track| track.identity.clone()));
        let Some(identity) = identity else {
            continue;
        };
        let session = after
            .map(|track| track.session)
            .unwrap_or(PeerSessionState::Down);
        let path_health = after
            .map(|track| track.path_health)
            .unwrap_or(PathHealth::Unknown);
        if before.is_none_or(|track| track.session != session) {
            let reason = match session {
                PeerSessionState::Established => PeerSessionChangeReason::SessionEstablished,
                PeerSessionState::Connecting => {
                    if first_sighting {
                        PeerSessionChangeReason::PeerObserved
                    } else {
                        PeerSessionChangeReason::SessionClosed
                    }
                }
                PeerSessionState::Down => {
                    if first_sighting {
                        PeerSessionChangeReason::PeerObserved
                    } else if before.is_some_and(|track| track.path_health == PathHealth::Up)
                        && path_health == PathHealth::Down
                    {
                        PeerSessionChangeReason::BfdPathDown
                    } else {
                        PeerSessionChangeReason::SessionClosed
                    }
                }
            };
            session_events.push(RoutingEventKind::PeerSessionChanged {
                domain: key.domain,
                peer: identity.clone(),
                state: session,
                reason,
            });
        }
        if before.is_none_or(|track| track.path_health != path_health)
            && (!first_sighting || path_health != PathHealth::Up)
        {
            path_events.push(RoutingEventKind::PathHealthChanged {
                domain: key.domain,
                peer: identity,
                health: path_health,
            });
        }
    }

    state.peers = current;
    for event in session_events {
        emit_locked(state, events, now, event);
    }

    let domains: Vec<RoutingDomainTag> = state.domains.keys().copied().collect();
    let mut prefix_events = Vec::new();
    for domain in domains {
        if stale_domains.contains(&domain) {
            continue;
        }
        let visible = advertised_prefixes_for_domain(&state.peers, domain);
        let previous_visible = advertised_prefixes_for_domain(&previous, domain);
        let Some(domain_state) = state.domains.get_mut(&domain) else {
            continue;
        };
        for (prefix, track) in &mut domain_state.prefixes {
            if !track.originated {
                continue;
            }
            let peers = visible.get(prefix).cloned().unwrap_or_default();
            if peers.is_empty() {
                let reason = if previous_visible.get(prefix).is_some_and(|peers| {
                    peers.iter().any(|peer| {
                        !state.peers.iter().any(|(key, track)| {
                            key.domain == domain
                                && track.identity == *peer
                                && track.session == PeerSessionState::Established
                        })
                    })
                }) {
                    PrefixWithdrawReason::PeerSessionDown
                } else {
                    PrefixWithdrawReason::PeerExportAbsent
                };
                if matches!(
                    track.state,
                    PrefixAdvertisementState::Advertised | PrefixAdvertisementState::Unknown
                ) {
                    track.export_evidence_pending = false;
                    track.state = PrefixAdvertisementState::Withdrawn;
                    track.last_transition = Some(now);
                    track.last_withdraw_reason = Some(reason);
                    prefix_events.push(RoutingEventKind::PrefixWithdrawn {
                        prefix: AdvertisedPrefix::new(domain, *prefix),
                        reason,
                    });
                } else if track.state == PrefixAdvertisementState::Withdrawn {
                    track.export_evidence_pending = false;
                    track.last_withdraw_reason = Some(reason);
                }
            } else if track.state != PrefixAdvertisementState::Advertised {
                track.export_evidence_pending = false;
                track.state = PrefixAdvertisementState::Advertised;
                track.last_transition = Some(now);
                track.last_withdraw_reason = None;
                prefix_events.push(RoutingEventKind::PrefixAdvertised {
                    prefix: AdvertisedPrefix::new(domain, *prefix),
                    peers: peers.len(),
                });
            } else {
                track.export_evidence_pending = false;
            }
        }
    }
    for event in prefix_events {
        emit_locked(state, events, now, event);
    }
    for event in path_events {
        emit_locked(state, events, now, event);
    }
}

fn advertised_prefixes_for_domain(
    peers: &BTreeMap<PeerKey, PeerTrack>,
    domain: RoutingDomainTag,
) -> BTreeMap<HostPrefix, BTreeSet<PeerIdentity>> {
    let mut advertised = BTreeMap::<HostPrefix, BTreeSet<PeerIdentity>>::new();
    for (key, track) in peers {
        if key.domain != domain || track.session != PeerSessionState::Established {
            continue;
        }
        for prefix in &track.advertised_prefixes {
            advertised
                .entry(*prefix)
                .or_default()
                .insert(track.identity.clone());
        }
    }
    advertised
}

fn note_observation_loss_locked(
    state: &mut ServiceState,
    events: &broadcast::Sender<RoutingEvent>,
    now: Timestamp,
) {
    let keys: Vec<PeerKey> = state.peers.keys().cloned().collect();
    for key in keys {
        let Some(previous) = state.peers.get(&key).cloned() else {
            continue;
        };
        let session = if previous.session == PeerSessionState::Established {
            PeerSessionState::Down
        } else {
            previous.session
        };
        if let Some(track) = state.peers.get_mut(&key) {
            track.session = session;
            track.path_health = PathHealth::Unknown;
            track.advertised_prefixes.clear();
        }
        if previous.session == PeerSessionState::Established {
            emit_locked(
                state,
                events,
                now,
                RoutingEventKind::PeerSessionChanged {
                    domain: key.domain,
                    peer: previous.identity.clone(),
                    state: PeerSessionState::Down,
                    reason: PeerSessionChangeReason::ObservationLost,
                },
            );
        }
        if previous.path_health != PathHealth::Unknown {
            emit_locked(
                state,
                events,
                now,
                RoutingEventKind::PathHealthChanged {
                    domain: key.domain,
                    peer: previous.identity,
                    health: PathHealth::Unknown,
                },
            );
        }
    }

    let domains: Vec<RoutingDomainTag> = state.domains.keys().copied().collect();
    for domain in domains {
        let unconfirmed = state
            .domains
            .get_mut(&domain)
            .map(|domain_state| {
                mark_domain_unknown(
                    domain_state,
                    now,
                    PrefixWithdrawReason::RoutingStackUnreachable,
                )
            })
            .unwrap_or_default();
        for prefix in unconfirmed {
            emit_locked(
                state,
                events,
                now,
                RoutingEventKind::PrefixUnconfirmed {
                    prefix: AdvertisedPrefix::new(domain, prefix),
                    reason: PrefixWithdrawReason::RoutingStackUnreachable,
                },
            );
        }
    }
}

/// Remove terminal tracks whose prefix left the desired set.
///
/// Retention rule: a track is kept while its prefix is in the current
/// desired set or in a non-terminal state (`Advertised`/`Unknown`, the
/// latter still possibly originated by the stack). Terminal
/// (`Withdrawn`/`Rejected`) tracks outside the desired set are pure history
/// and pruned here so state cannot grow unboundedly.
fn prune_terminal_tracks(domain_state: &mut DomainState) {
    let desired = &domain_state.desired;
    domain_state.prefixes.retain(|prefix, track| {
        desired.contains(prefix)
            || matches!(
                track.state,
                PrefixAdvertisementState::Advertised | PrefixAdvertisementState::Unknown
            )
    });
}

fn lock_state(state: &Arc<Mutex<ServiceState>>) -> std::sync::MutexGuard<'_, ServiceState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn emit_locked(
    state: &mut ServiceState,
    events: &broadcast::Sender<RoutingEvent>,
    now: Timestamp,
    kind: RoutingEventKind,
) {
    state.sequence = state.sequence.saturating_add(1);
    // No subscribers is not an error; telemetry must never block intent.
    let _ = events.send(RoutingEvent {
        sequence: state.sequence,
        at: now,
        kind,
    });
}

fn lease_deadline(now: Timestamp, lease: AdvertisementLease) -> Result<Timestamp, IpsecLbError> {
    now.add_seconds(i64::from(lease.ttl_secs())).ok_or_else(|| {
        IpsecLbError::invalid_config(
            "lease_ttl",
            "lease time-to-live overflows the timestamp range",
        )
    })
}

fn revoke_domain_intent(
    domain_state: &mut DomainState,
    revision: u64,
    reason: PrefixWithdrawReason,
    now: Timestamp,
) {
    domain_state.intent_revision = revision;
    domain_state.mutation_in_flight = true;
    domain_state.lease_deadline = None;
    domain_state.advertised_generation = None;
    domain_state.desired.clear();
    domain_state.withdraw_pending = true;
    domain_state.withdraw_in_flight = true;
    domain_state.withdraw_reason = Some(reason);
    domain_state.known_absent = false;
    let _ = mark_domain_unknown(domain_state, now, reason);
}

fn mark_domain_unknown(
    domain_state: &mut DomainState,
    now: Timestamp,
    reason: PrefixWithdrawReason,
) -> Vec<HostPrefix> {
    let mut changed = Vec::new();
    for (prefix, track) in &mut domain_state.prefixes {
        if track.originated
            || matches!(
                track.state,
                PrefixAdvertisementState::Advertised | PrefixAdvertisementState::Unknown
            )
        {
            if track.state != PrefixAdvertisementState::Unknown
                || track.last_withdraw_reason != Some(reason)
            {
                changed.push(*prefix);
            }
            track.state = PrefixAdvertisementState::Unknown;
            track.export_evidence_pending = false;
            track.last_transition = Some(now);
            track.last_withdraw_reason = Some(reason);
        }
    }
    changed
}

fn quarantine_possibly_affected_locked(
    state: &mut ServiceState,
    events: &broadcast::Sender<RoutingEvent>,
    now: Timestamp,
    domain: RoutingDomainTag,
    attempted: &BTreeSet<HostPrefix>,
) {
    let revision = state.next_intent_revision.saturating_add(1);
    state.next_intent_revision = revision;
    let mut unconfirmed = Vec::new();
    if let Some(domain_state) = state.domains.get_mut(&domain) {
        let mut affected: BTreeSet<HostPrefix> = domain_state
            .prefixes
            .iter()
            .filter_map(|(prefix, track)| {
                (track.originated || track.state == PrefixAdvertisementState::Unknown)
                    .then_some(*prefix)
            })
            .collect();
        affected.extend(attempted.iter().copied());
        debug_assert!(affected.len() <= MAX_POSSIBLY_AFFECTED_PREFIXES_PER_DOMAIN);
        domain_state.intent_revision = revision;
        domain_state.mutation_in_flight = false;
        domain_state.lease_deadline = None;
        domain_state.advertised_generation = None;
        domain_state.desired.clear();
        domain_state.withdraw_pending = true;
        domain_state.withdraw_in_flight = false;
        domain_state.withdraw_reason = Some(PrefixWithdrawReason::RoutingStackUnreachable);
        domain_state.known_absent = false;
        domain_state.quarantined = true;
        for prefix in affected {
            let track = domain_state.prefixes.entry(prefix).or_default();
            if track.state != PrefixAdvertisementState::Unknown
                || track.last_withdraw_reason != Some(PrefixWithdrawReason::RoutingStackUnreachable)
            {
                unconfirmed.push(prefix);
            }
            // `originated` means possibly live while state is Unknown. This
            // keeps the complete uncertainty set retained until exact absence.
            track.originated = true;
            track.export_evidence_pending = false;
            track.state = PrefixAdvertisementState::Unknown;
            track.last_transition = Some(now);
            track.last_withdraw_reason = Some(PrefixWithdrawReason::RoutingStackUnreachable);
        }
        prune_terminal_tracks(domain_state);
    }
    for prefix in unconfirmed {
        emit_locked(
            state,
            events,
            now,
            RoutingEventKind::PrefixUnconfirmed {
                prefix: AdvertisedPrefix::new(domain, prefix),
                reason: PrefixWithdrawReason::RoutingStackUnreachable,
            },
        );
    }
}

fn finalize_domain_withdrawal(
    domain_state: &mut DomainState,
    now: Timestamp,
    reason: PrefixWithdrawReason,
    withdrawn: &mut Vec<HostPrefix>,
) {
    domain_state.mutation_in_flight = false;
    domain_state.advertised_generation = None;
    domain_state.lease_deadline = None;
    domain_state.desired.clear();
    domain_state.withdraw_pending = false;
    domain_state.withdraw_in_flight = false;
    domain_state.withdraw_reason = None;
    domain_state.known_absent = true;
    domain_state.quarantined = false;
    for (prefix, track) in &mut domain_state.prefixes {
        if track.originated
            || matches!(
                track.state,
                PrefixAdvertisementState::Advertised | PrefixAdvertisementState::Unknown
            )
        {
            let transitioned = matches!(
                track.state,
                PrefixAdvertisementState::Advertised | PrefixAdvertisementState::Unknown
            );
            track.originated = false;
            track.export_evidence_pending = false;
            track.state = PrefixAdvertisementState::Withdrawn;
            if transitioned {
                track.last_transition = Some(now);
                withdrawn.push(*prefix);
            }
            track.last_withdraw_reason = Some(reason);
        }
    }
    prune_terminal_tracks(domain_state);
}

fn withdraw_is_current(
    state: &Arc<Mutex<ServiceState>>,
    domain: RoutingDomainTag,
    revision: u64,
) -> bool {
    let state = lock_state(state);
    state.domains.get(&domain).is_some_and(|domain_state| {
        domain_state.intent_revision == revision
            && domain_state.withdraw_pending
            && domain_state.withdraw_in_flight
            && domain_state.lease_deadline.is_none()
            && domain_state.desired.is_empty()
    })
}

fn validate_observations(
    managed_domains: &BTreeSet<RoutingDomainTag>,
    observations: &[crate::routing::PeerObservation],
) -> Result<(), IpsecLbError> {
    if observations.len() > MAX_ROUTING_PEERS_TOTAL {
        return Err(IpsecLbError::invalid_config(
            "routing_observations",
            "routing observation count exceeds the production bound",
        ));
    }
    let mut per_domain = BTreeMap::<RoutingDomainTag, usize>::new();
    let mut identities = BTreeSet::new();
    for observation in observations {
        if !managed_domains.contains(&observation.domain) {
            return Err(IpsecLbError::invalid_config(
                "routing_observations",
                "adapter reported an unmanaged routing domain",
            ));
        }
        if observation.peer.name().is_empty()
            || observation.peer.name().len() > MAX_ROUTING_PEER_NAME_LEN
            || !observation
                .peer
                .name()
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
        {
            return Err(IpsecLbError::invalid_config(
                "routing_observations",
                "routing peer name is empty, non-printable, or exceeds the production bound",
            ));
        }
        if !identities.insert((observation.domain, observation.peer.name())) {
            return Err(IpsecLbError::invalid_config(
                "routing_observations",
                "adapter reported a duplicate routing peer identity",
            ));
        }
        if observation.advertised_prefixes.len() > MAX_ADVERTISED_PREFIXES_PER_DOMAIN {
            return Err(IpsecLbError::invalid_config(
                "routing_observations",
                "per-peer advertised-prefix evidence exceeds the production bound",
            ));
        }
        if observation.session != PeerSessionState::Established
            && !observation.advertised_prefixes.is_empty()
        {
            return Err(IpsecLbError::invalid_config(
                "routing_observations",
                "non-established peer reported advertised-prefix evidence",
            ));
        }
        let count = per_domain.entry(observation.domain).or_default();
        *count = count.saturating_add(1);
        if *count > MAX_ROUTING_PEERS_PER_DOMAIN {
            return Err(IpsecLbError::invalid_config(
                "routing_observations",
                "routing peer count per domain exceeds the production bound",
            ));
        }
    }
    Ok(())
}

/// Check that a queued apply driver's intent is still the domain's current
/// intent: identical desired set, revision and generation, with a deadline
/// that is strictly in the future at the mutation boundary.
fn intent_is_current(
    state: &Arc<Mutex<ServiceState>>,
    domain: RoutingDomainTag,
    desired: &BTreeSet<HostPrefix>,
    generation: LeaseGeneration,
    revision: u64,
    now: Timestamp,
) -> bool {
    let state = lock_state(state);
    state.domains.get(&domain).is_some_and(|domain_state| {
        domain_intent_is_current(domain_state, desired, generation, revision, now)
    })
}

fn domain_intent_is_current(
    domain_state: &DomainState,
    desired: &BTreeSet<HostPrefix>,
    generation: LeaseGeneration,
    revision: u64,
    now: Timestamp,
) -> bool {
    domain_state.desired == *desired
        && domain_state.highest_generation == Some(generation)
        && domain_state.intent_revision == revision
        && domain_state.mutation_in_flight
        && !domain_state.withdraw_pending
        && domain_state
            .lease_deadline
            .is_some_and(|deadline| now < deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::IpAddress;
    use crate::routing::ConformanceFakeRoutingStack;

    fn prefix(last: u8) -> HostPrefix {
        HostPrefix::new(IpAddress::V4([203, 0, 113, last]))
    }

    async fn wait_for_pending_count(scheduler: &MutationScheduler, expected: usize) {
        for _ in 0..64 {
            if scheduler
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pending
                .len()
                == expected
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("mutation scheduler did not reach the expected pending count");
    }

    #[tokio::test]
    async fn partial_overlap_preserves_the_remainder_of_a_queued_withdrawal_batch() {
        let scheduler = Arc::new(MutationScheduler::default());
        let domain_a = RoutingDomainTag::new(64_512);
        let domain_b = RoutingDomainTag::new(64_513);
        let active_domain = RoutingDomainTag::new(64_514);
        let active = scheduler
            .acquire(BTreeSet::from([active_domain]), MutationPriority::Apply)
            .await
            .unwrap();
        let old_batch = tokio::spawn({
            let scheduler = Arc::clone(&scheduler);
            async move {
                scheduler
                    .acquire(
                        BTreeSet::from([domain_a, domain_b]),
                        MutationPriority::Withdrawal,
                    )
                    .await
            }
        });
        wait_for_pending_count(&scheduler, 1).await;
        let newer_overlap = tokio::spawn({
            let scheduler = Arc::clone(&scheduler);
            async move {
                scheduler
                    .acquire(BTreeSet::from([domain_a]), MutationPriority::Withdrawal)
                    .await
            }
        });
        wait_for_pending_count(&scheduler, 2).await;
        {
            let state = scheduler
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(state.pending[0].domains, BTreeSet::from([domain_b]));
            assert_eq!(state.pending[1].domains, BTreeSet::from([domain_a]));
        }

        drop(active);
        let old_permit = old_batch.await.unwrap().unwrap();
        assert!(!newer_overlap.is_finished());
        drop(old_permit);
        drop(newer_overlap.await.unwrap().unwrap());
        assert!(
            !scheduler
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active
        );
    }

    /// A driver that loses the race against a drain must bail before
    /// touching the adapter: no apply call, no adapter-side mutation.
    #[tokio::test]
    async fn stale_driver_bails_without_touching_the_adapter() {
        let domain = RoutingDomainTag::new(64512);
        let adapter = Arc::new(ConformanceFakeRoutingStack::with_domains([domain]));
        let mutation_scheduler = Arc::new(MutationScheduler::default());
        let state = Arc::new(Mutex::new(ServiceState::default()));
        let (events, _receiver) = broadcast::channel(8);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let generation = LeaseGeneration::new(1).unwrap();
        // Domain state exactly as a completed drain left it.
        {
            let mut state = lock_state(&state);
            let domain_state = state.domains.entry(domain).or_default();
            domain_state.highest_generation = Some(generation);
            domain_state.desired.clear();
            domain_state.lease_deadline = None;
        }

        let error = drive_apply(
            adapter.clone(),
            mutation_scheduler,
            state,
            events,
            clock,
            domain,
            [prefix(10)].into_iter().collect(),
            generation,
            1,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, IpsecLbError::OwnershipConflict { .. }));
        assert!(adapter.apply_calls().is_empty());
        assert!(adapter.mutation_log().is_empty());
        assert!(adapter.originated(domain).is_empty());
    }

    #[tokio::test]
    async fn failed_withdrawal_terminates_only_the_matching_mutation_epoch() {
        let domain = RoutingDomainTag::new(64_512);
        let adapter = Arc::new(ConformanceFakeRoutingStack::with_domains([domain]));
        adapter.set_unreachable(true);
        let mutation_scheduler = Arc::new(MutationScheduler::default());
        let state = Arc::new(Mutex::new(ServiceState::default()));
        let (events, _receiver) = broadcast::channel(8);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        {
            let mut state = lock_state(&state);
            let domain_state = state.domains.entry(domain).or_default();
            domain_state.intent_revision = 7;
            domain_state.mutation_in_flight = true;
            domain_state.withdraw_pending = true;
            domain_state.withdraw_in_flight = true;
            domain_state.withdraw_reason = Some(PrefixWithdrawReason::CallerDrain);
        }

        assert!(drive_withdrawals(
            adapter,
            mutation_scheduler,
            Arc::clone(&state),
            events,
            clock,
            vec![(domain, PrefixWithdrawReason::CallerDrain, 7)],
        )
        .await
        .is_err());

        let state = lock_state(&state);
        let domain_state = state.domains.get(&domain).unwrap();
        assert_eq!(domain_state.intent_revision, 7);
        assert!(domain_state.quarantined);
        assert!(!domain_state.mutation_in_flight);
        assert!(!domain_state.withdraw_in_flight);
    }
}
