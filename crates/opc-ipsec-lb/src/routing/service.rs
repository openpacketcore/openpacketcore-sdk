//! Declarative, lease-gated prefix advertisement service.
//!
//! The service owns the caller-facing reconcile semantics on top of a
//! [`RoutingStackAdapter`]: callers declare "this exact host-prefix set should
//! be advertised now" per routing domain, gated by a health lease whose
//! deadline is driven by an injected clock. The service computes the delta,
//! enforces the generation rules shared with
//! [`crate::vip::VipOwnershipCoordinator`], and emits the typed telemetry
//! stream the caller uses to act on routing health.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_session_store::{Clock, SystemClock};
use opc_types::Timestamp;
use tokio::sync::{broadcast, watch};

use crate::error::IpsecLbError;
use crate::ownership::RoutingDomainTag;
use crate::routing::{
    AdvertisedPrefix, AdvertisementLease, HostPrefix, LeaseGeneration, PathHealth, PeerIdentity,
    PeerSessionChangeReason, PeerSessionState, PrefixAdvertisementState, PrefixApplyOutcome,
    PrefixRejectReason, PrefixStatusSnapshot, PrefixWithdrawReason, RoutingEvent, RoutingEventKind,
    RoutingStackAdapter, MAX_ADVERTISED_PREFIXES_PER_DOMAIN,
};

/// Default capacity of the broadcast event channel.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Service configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixAdvertiserConfig {
    /// Watchdog cadence. Lease-expired prefixes are withdrawn within one
    /// interval of expiry, and peer observations are polled once per
    /// interval.
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
        if self.max_prefixes_per_domain == 0 {
            return Err(IpsecLbError::invalid_config(
                "max_prefixes_per_domain",
                "prefix bound must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Disposition of one declarative reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReconcileDisposition {
    /// Every desired prefix was accepted by the routing stack.
    Advertised,
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
            Self::Advertised => "advertised",
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
    last_seen: Timestamp,
}

#[derive(Debug, Default)]
struct ServiceState {
    domains: BTreeMap<RoutingDomainTag, DomainState>,
    peers: BTreeMap<PeerKey, PeerTrack>,
    sequence: u64,
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
/// - an ambiguous adapter apply leaves the lease deadline armed so the
///   watchdog withdraws any possibly-originated prefixes, and recovery uses
///   the same-generation retry above.
///
/// Cancellation safety: adapter applies are driven to completion by an
/// internal driver task detached from the caller's future, and mutations
/// serialize on an internal apply lock in intent order. Cancelling the
/// `reconcile` future can therefore never tear service belief: the driver
/// still applies the outcomes. Withdrawals instead pre-mark tracks as
/// unconfirmed before the adapter call, so a cancelled or failed withdraw
/// never leaves phantom `Advertised` state behind.
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
    apply_lock: Arc<tokio::sync::Mutex<()>>,
    events: broadcast::Sender<RoutingEvent>,
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
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Ok(Self {
            adapter: Arc::new(adapter),
            clock,
            config,
            state: Arc::new(Mutex::new(ServiceState::default())),
            op_lock: tokio::sync::Mutex::new(()),
            apply_lock: Arc::new(tokio::sync::Mutex::new(())),
            events,
        })
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
            Withdraw(PrefixWithdrawReason),
            Apply(LeaseGeneration),
        }

        let plan = {
            let mut state = lock_state(&self.state);
            let domain_state = state.domains.entry(domain).or_default();
            let previous_highest = domain_state.highest_generation;
            if let Some(lease) = lease {
                if domain_state
                    .highest_generation
                    .is_none_or(|highest| lease.generation() > highest)
                {
                    domain_state.highest_generation = Some(lease.generation());
                }
            }

            match lease {
                None => Plan::Withdraw(PrefixWithdrawReason::CallerDrain),
                Some(lease) => {
                    let deadline = lease_deadline(now, lease)?;
                    let generation = lease.generation();
                    let lease_expired = domain_state
                        .lease_deadline
                        .is_some_and(|deadline| now >= deadline);
                    let fresh_epoch = previous_highest.is_none_or(|highest| generation > highest);
                    if fresh_epoch {
                        domain_state.lease_deadline = Some(deadline);
                        domain_state.desired.clone_from(&desired);
                        Plan::Apply(generation)
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
                            Plan::Withdraw(PrefixWithdrawReason::StaleGeneration)
                        } else {
                            domain_state.lease_deadline = Some(deadline);
                            // Retention is decided against the desired set
                            // alone: historical tracks of prefixes that left
                            // the set must not poison renewal.
                            let all_advertised = epoch_live
                                && desired.iter().all(|prefix| {
                                    domain_state.prefixes.get(prefix).is_some_and(|track| {
                                        track.originated
                                            && track.state == PrefixAdvertisementState::Advertised
                                    })
                                });
                            if all_advertised {
                                Plan::Retained
                            } else {
                                // Same-generation declarative re-apply:
                                // unconfirmed or rejected desired tracks get
                                // a fresh outcome without a new generation.
                                Plan::Apply(generation)
                            }
                        }
                    }
                }
            }
        };

        match plan {
            Plan::Retained => Ok(PrefixReconcileReport {
                domain,
                disposition: ReconcileDisposition::Retained,
                outcomes: desired
                    .iter()
                    .map(|prefix| (*prefix, PrefixApplyOutcome::Accepted))
                    .collect(),
            }),
            Plan::Withdraw(reason) => {
                let disposition = if reason == PrefixWithdrawReason::StaleGeneration {
                    ReconcileDisposition::StaleRejected
                } else {
                    ReconcileDisposition::Withdrawn
                };
                self.withdraw_domain(domain, reason).await?;
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
            Plan::Apply(generation) => self.apply_domain(domain, desired, generation).await,
        }
    }

    async fn apply_domain(
        &self,
        domain: RoutingDomainTag,
        desired: BTreeSet<HostPrefix>,
        generation: LeaseGeneration,
    ) -> Result<PrefixReconcileReport, IpsecLbError> {
        // Drive the adapter mutation on a detached task. Cancelling the
        // caller's future only drops the join handle; the driver still
        // finishes the adapter call and applies the outcome, so belief can
        // never tear between "the stack was told" and "the service knows".
        let driver = tokio::spawn(drive_apply(
            Arc::clone(&self.adapter),
            Arc::clone(&self.apply_lock),
            Arc::clone(&self.state),
            self.events.clone(),
            Arc::clone(&self.clock),
            domain,
            desired,
            generation,
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
    ) -> Result<(), IpsecLbError> {
        // Pre-mark every originated or advertised track as unconfirmed so a
        // failed or cancelled withdraw can never leave phantom `Advertised`
        // belief behind. The lease deadline stays armed on error so the
        // watchdog retries the withdrawal on its next tick.
        let now = self.clock.now_utc();
        let mut pending = Vec::new();
        {
            let mut state = lock_state(&self.state);
            let domain_state = state.domains.entry(domain).or_default();
            for (prefix, track) in &mut domain_state.prefixes {
                // Unknown tracks are re-collected so a watchdog retry after
                // an ambiguous earlier attempt still converges them to a
                // terminal withdrawn state with its event.
                if track.originated
                    || matches!(
                        track.state,
                        PrefixAdvertisementState::Advertised | PrefixAdvertisementState::Unknown
                    )
                {
                    track.originated = false;
                    track.state = PrefixAdvertisementState::Unknown;
                    track.last_transition = Some(now);
                    pending.push(*prefix);
                }
            }
        }
        self.adapter.withdraw_all(domain).await?;

        let now = self.clock.now_utc();
        let mut state = lock_state(&self.state);
        {
            let domain_state = state.domains.entry(domain).or_default();
            domain_state.advertised_generation = None;
            domain_state.lease_deadline = None;
            domain_state.desired.clear();
            for prefix in &pending {
                if let Some(track) = domain_state.prefixes.get_mut(prefix) {
                    track.state = PrefixAdvertisementState::Withdrawn;
                    track.last_transition = Some(now);
                    track.last_withdraw_reason = Some(reason);
                }
            }
            prune_terminal_tracks(domain_state);
        }
        for prefix in pending {
            emit_locked(
                &mut state,
                &self.events,
                now,
                RoutingEventKind::PrefixWithdrawn {
                    prefix: AdvertisedPrefix::new(domain, prefix),
                    reason,
                },
            );
        }
        Ok(())
    }

    /// Enforce lease deadlines once.
    ///
    /// Every domain whose lease deadline has passed is withdrawn and its
    /// prefixes transition with [`PrefixWithdrawReason::LeaseExpired`]. A
    /// failing domain never blocks the others: errors are collected and the
    /// first one is returned after every expired domain was attempted, so
    /// the bounded-withdrawal guarantee is not head-of-line blocked.
    pub async fn enforce_lease_once(&self) -> Result<(), IpsecLbError> {
        let _op = self.op_lock.lock().await;
        let now = self.clock.now_utc();
        let expired: Vec<RoutingDomainTag> = {
            let state = lock_state(&self.state);
            state
                .domains
                .iter()
                .filter(|(_, domain_state)| {
                    domain_state
                        .lease_deadline
                        .is_some_and(|deadline| now >= deadline)
                })
                .map(|(domain, _)| *domain)
                .collect()
        };
        let mut first_error = None;
        for domain in expired {
            if let Err(error) = self
                .withdraw_domain(domain, PrefixWithdrawReason::LeaseExpired)
                .await
            {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Poll the routing stack once and relay session and path-health
    /// transitions.
    ///
    /// Ordering guarantee: for one cause, the `PeerSessionChanged` event is
    /// always emitted before the prefix events it triggers. When the stack
    /// is unobservable, established sessions are presumed closed (the
    /// routing component's death closes its BGP sessions, so upstream
    /// withdraws this instance's paths) and originated prefixes become
    /// unconfirmed — relayed as `PrefixUnconfirmed`, never as a withdrawal
    /// the service did not observe.
    pub async fn observe_once(&self) -> Result<(), IpsecLbError> {
        let _op = self.op_lock.lock().await;
        let now = self.clock.now_utc();
        match self.adapter.poll_observations().await {
            Ok(observations) => {
                let mut state = lock_state(&self.state);
                let mut seen: BTreeMap<PeerKey, PeerTrack> = BTreeMap::new();
                for observation in observations {
                    seen.insert(
                        PeerKey {
                            domain: observation.domain,
                            name: observation.peer.name().to_owned(),
                        },
                        PeerTrack {
                            identity: observation.peer,
                            session: observation.session,
                            path_health: observation.path_health,
                            last_seen: now,
                        },
                    );
                }
                let existing: Vec<PeerKey> = state.peers.keys().cloned().collect();
                for key in existing {
                    if !seen.contains_key(&key) {
                        let track = PeerTrack {
                            identity: state.peers[&key].identity.clone(),
                            session: PeerSessionState::Down,
                            path_health: state.peers[&key].path_health,
                            last_seen: state.peers[&key].last_seen,
                        };
                        note_peer_locked(
                            &mut state,
                            &self.events,
                            now,
                            key.clone(),
                            track,
                            PeerSessionChangeReason::SessionClosed,
                        );
                        // Prune peers gone beyond the retention bound.
                        let expired = state.peers.get(&key).is_some_and(|track| {
                            track
                                .last_seen
                                .add_seconds(self.config.peer_retention_secs.cast_signed())
                                .is_some_and(|deadline| now >= deadline)
                        });
                        if expired {
                            state.peers.remove(&key);
                        }
                    }
                }
                for (key, track) in seen {
                    note_peer_locked(
                        &mut state,
                        &self.events,
                        now,
                        key,
                        track,
                        PeerSessionChangeReason::SessionClosed,
                    );
                }
                Ok(())
            }
            Err(_error) => {
                let mut state = lock_state(&self.state);
                let keys: Vec<PeerKey> = state.peers.keys().cloned().collect();
                for key in keys {
                    let Some(track) = state.peers.get_mut(&key) else {
                        continue;
                    };
                    if track.session == PeerSessionState::Established {
                        track.session = PeerSessionState::Down;
                        track.path_health = PathHealth::Unknown;
                        let identity = track.identity.clone();
                        emit_locked(
                            &mut state,
                            &self.events,
                            now,
                            RoutingEventKind::PeerSessionChanged {
                                peer: identity,
                                state: PeerSessionState::Down,
                                reason: PeerSessionChangeReason::ObservationLost,
                            },
                        );
                    }
                }
                // Originated prefixes are unconfirmed while the stack is
                // unreachable; they are not reported as withdrawn because
                // the stack may still originate them.
                let domains: Vec<RoutingDomainTag> = state.domains.keys().copied().collect();
                for domain in domains {
                    let mut unconfirmed = Vec::new();
                    {
                        let domain_state = state.domains.entry(domain).or_default();
                        for (prefix, track) in &mut domain_state.prefixes {
                            if track.originated
                                && track.state == PrefixAdvertisementState::Advertised
                            {
                                track.state = PrefixAdvertisementState::Unknown;
                                track.last_transition = Some(now);
                                track.last_withdraw_reason =
                                    Some(PrefixWithdrawReason::RoutingStackUnreachable);
                                unconfirmed.push(*prefix);
                            }
                        }
                    }
                    for prefix in unconfirmed {
                        emit_locked(
                            &mut state,
                            &self.events,
                            now,
                            RoutingEventKind::PrefixUnconfirmed {
                                prefix: AdvertisedPrefix::new(domain, prefix),
                                reason: PrefixWithdrawReason::RoutingStackUnreachable,
                            },
                        );
                    }
                }
                Ok(())
            }
        }
    }

    /// Run the watchdog loop until the shutdown signal flips to `true` or its
    /// sender drops.
    ///
    /// Each tick enforces lease deadlines and relays stack observations.
    /// Adapter faults are retried on the next tick, so a transient failure
    /// delays but never cancels the bounded withdrawal guarantee.
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
    }

    /// Withdraw every domain best-effort for process shutdown.
    ///
    /// The stronger half of the failure pairing still applies: once this
    /// process exits, the routing component's death or session loss closes
    /// the BGP sessions and upstream withdraws this instance's paths.
    pub async fn shutdown(&self) {
        let _op = self.op_lock.lock().await;
        let domains: Vec<RoutingDomainTag> = {
            let state = lock_state(&self.state);
            state.domains.keys().copied().collect()
        };
        for domain in domains {
            let _ = self
                .withdraw_domain(domain, PrefixWithdrawReason::ServiceShutdown)
                .await;
        }
    }

    /// Return the status snapshot for every tracked prefix in one domain.
    #[must_use]
    pub fn prefix_snapshots(&self, domain: RoutingDomainTag) -> Vec<PrefixStatusSnapshot> {
        let state = lock_state(&self.state);
        let established = established_peers(&state, domain);
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
                    established.clone()
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
/// The apply lock serializes adapter mutations in intent order, so the last
/// driver to run is always the last adapter effect and the last belief —
/// a retried intent queued after a cancelled call can never be overwritten
/// by the stale driver.
#[allow(clippy::too_many_arguments)]
async fn drive_apply<A>(
    adapter: Arc<A>,
    apply_lock: Arc<tokio::sync::Mutex<()>>,
    state: Arc<Mutex<ServiceState>>,
    events: broadcast::Sender<RoutingEvent>,
    clock: Arc<dyn Clock>,
    domain: RoutingDomainTag,
    desired: BTreeSet<HostPrefix>,
    generation: LeaseGeneration,
) -> Result<PrefixReconcileReport, IpsecLbError>
where
    A: RoutingStackAdapter,
{
    let _apply = apply_lock.lock().await;
    let outcomes = match adapter.apply_advertisement_set(domain, &desired).await {
        Ok(outcomes) => outcomes,
        Err(error) => {
            // Ambiguous apply: the lease deadline stays armed so the
            // watchdog withdraws any possibly-originated prefixes, and
            // previously advertised prefixes become unconfirmed. The epoch
            // remains retryable with the same generation while the lease is
            // unexpired and the intent identical.
            let now = clock.now_utc();
            let mut state = lock_state(&state);
            let mut pending = Vec::new();
            {
                let domain_state = state.domains.entry(domain).or_default();
                domain_state.advertised_generation = None;
                for prefix in &desired {
                    let track = domain_state.prefixes.entry(*prefix).or_default();
                    if track.state == PrefixAdvertisementState::Advertised {
                        track.state = PrefixAdvertisementState::Unknown;
                        track.last_transition = Some(now);
                        track.last_withdraw_reason =
                            Some(PrefixWithdrawReason::RoutingStackUnreachable);
                        pending.push(RoutingEventKind::PrefixUnconfirmed {
                            prefix: AdvertisedPrefix::new(domain, *prefix),
                            reason: PrefixWithdrawReason::RoutingStackUnreachable,
                        });
                    }
                }
            }
            for kind in pending {
                emit_locked(&mut state, &events, now, kind);
            }
            return Err(error);
        }
    };

    let now = clock.now_utc();
    let mut state = lock_state(&state);
    let established = established_peers(&state, domain).len();
    let mut pending = Vec::new();
    {
        let domain_state = state.domains.entry(domain).or_default();
        domain_state.advertised_generation = Some(generation);
        for (prefix, outcome) in &outcomes {
            let track = domain_state.prefixes.entry(*prefix).or_default();
            match outcome {
                PrefixApplyOutcome::Accepted => {
                    track.originated = true;
                    if track.state != PrefixAdvertisementState::Advertised {
                        track.state = PrefixAdvertisementState::Advertised;
                        track.last_transition = Some(now);
                        track.last_withdraw_reason = None;
                        pending.push(RoutingEventKind::PrefixAdvertised {
                            prefix: AdvertisedPrefix::new(domain, *prefix),
                            peers: established,
                        });
                    }
                }
                PrefixApplyOutcome::Rejected(reason) => {
                    track.originated = false;
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
                track.originated = false;
                track.state = PrefixAdvertisementState::Withdrawn;
                track.last_transition = Some(now);
                track.last_withdraw_reason = Some(PrefixWithdrawReason::CallerDrain);
                dropped.push(*prefix);
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

    let disposition = if outcomes
        .values()
        .all(|outcome| *outcome == PrefixApplyOutcome::Accepted)
    {
        ReconcileDisposition::Advertised
    } else {
        ReconcileDisposition::PartiallyRejected
    };
    Ok(PrefixReconcileReport {
        domain,
        disposition,
        outcomes,
    })
}

/// Relay one peer observation: session transitions first, then the prefix
/// transitions they cause, then path-health transitions.
fn note_peer_locked(
    state: &mut ServiceState,
    events: &broadcast::Sender<RoutingEvent>,
    now: Timestamp,
    key: PeerKey,
    track: PeerTrack,
    down_reason: PeerSessionChangeReason,
) {
    let domain = key.domain;
    let previous = state.peers.get(&key).cloned();
    let first_sighting = previous.is_none();
    let session_changed = previous
        .as_ref()
        .is_none_or(|previous| previous.session != track.session);
    let health_changed = previous
        .as_ref()
        .is_none_or(|previous| previous.path_health != track.path_health);
    state.peers.insert(key, track.clone());

    if session_changed {
        let reason = match track.session {
            PeerSessionState::Established => PeerSessionChangeReason::SessionEstablished,
            PeerSessionState::Connecting => {
                if first_sighting {
                    PeerSessionChangeReason::PeerObserved
                } else {
                    down_reason
                }
            }
            PeerSessionState::Down => {
                if first_sighting {
                    PeerSessionChangeReason::PeerObserved
                } else if previous
                    .as_ref()
                    .is_some_and(|previous| previous.path_health == PathHealth::Up)
                    && track.path_health == PathHealth::Down
                {
                    PeerSessionChangeReason::BfdPathDown
                } else {
                    down_reason
                }
            }
        };
        // The session transition is always emitted before any
        // prefix-level event it causes.
        emit_locked(
            state,
            events,
            now,
            RoutingEventKind::PeerSessionChanged {
                peer: track.identity.clone(),
                state: track.session,
                reason,
            },
        );

        match track.session {
            PeerSessionState::Established => {
                let mut readvertised = Vec::new();
                {
                    let domain_state = state.domains.entry(domain).or_default();
                    for (prefix, prefix_track) in &mut domain_state.prefixes {
                        if prefix_track.originated
                            && prefix_track.state == PrefixAdvertisementState::Withdrawn
                            && prefix_track.last_withdraw_reason
                                == Some(PrefixWithdrawReason::PeerSessionDown)
                        {
                            prefix_track.state = PrefixAdvertisementState::Advertised;
                            prefix_track.last_transition = Some(now);
                            prefix_track.last_withdraw_reason = None;
                            readvertised.push(*prefix);
                        }
                    }
                }
                let peers = established_peers(state, domain).len();
                for prefix in readvertised {
                    emit_locked(
                        state,
                        events,
                        now,
                        RoutingEventKind::PrefixAdvertised {
                            prefix: AdvertisedPrefix::new(domain, prefix),
                            peers,
                        },
                    );
                }
            }
            PeerSessionState::Connecting | PeerSessionState::Down => {
                let was_established = previous
                    .as_ref()
                    .is_some_and(|previous| previous.session == PeerSessionState::Established);
                if was_established || (first_sighting && track.session == PeerSessionState::Down) {
                    let remaining = established_peers(state, domain).len();
                    if remaining == 0 {
                        let mut withdrawn = Vec::new();
                        {
                            let domain_state = state.domains.entry(domain).or_default();
                            for (prefix, prefix_track) in &mut domain_state.prefixes {
                                if prefix_track.originated
                                    && prefix_track.state == PrefixAdvertisementState::Advertised
                                {
                                    prefix_track.state = PrefixAdvertisementState::Withdrawn;
                                    prefix_track.last_transition = Some(now);
                                    prefix_track.last_withdraw_reason =
                                        Some(PrefixWithdrawReason::PeerSessionDown);
                                    withdrawn.push(*prefix);
                                }
                            }
                        }
                        for prefix in withdrawn {
                            emit_locked(
                                state,
                                events,
                                now,
                                RoutingEventKind::PrefixWithdrawn {
                                    prefix: AdvertisedPrefix::new(domain, prefix),
                                    reason: PrefixWithdrawReason::PeerSessionDown,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    if health_changed && (!first_sighting || track.path_health != PathHealth::Up) {
        emit_locked(
            state,
            events,
            now,
            RoutingEventKind::PathHealthChanged {
                peer: track.identity,
                health: track.path_health,
            },
        );
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

fn established_peers(state: &ServiceState, domain: RoutingDomainTag) -> BTreeSet<PeerIdentity> {
    state
        .peers
        .iter()
        .filter(|(key, track)| {
            key.domain == domain && track.session == PeerSessionState::Established
        })
        .map(|(_, track)| track.identity.clone())
        .collect()
}
